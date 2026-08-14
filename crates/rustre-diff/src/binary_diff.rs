//! Binary-level diff — byte-level comparison using a Myers-like algorithm.
//!
//! Provides [`BinaryDiffer`], [`DiffBlock`], [`EditScript`], [`DiffStats`],
//! and [`DiffRenderer`].

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BinaryDiffError {
    #[error("input A is empty")]
    EmptyInputA,
    #[error("input B is empty")]
    EmptyInputB,
    #[error("both inputs are empty")]
    BothEmpty,
    #[error("input too large: {0} bytes (max {1})")]
    InputTooLarge(usize, usize),
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffBlock
// ─────────────────────────────────────────────────────────────────────────────

/// A single contiguous diff block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffBlock {
    /// Bytes that are equal in both inputs.
    Equal {
        offset_a: usize,
        offset_b: usize,
        len: usize,
    },
    /// Bytes present in B but not in A (insertion).
    Insert { offset_b: usize, bytes: Vec<u8> },
    /// Bytes present in A but not in B (deletion).
    Delete { offset_a: usize, bytes: Vec<u8> },
    /// Bytes in A replaced by different bytes in B.
    Replace {
        offset_a: usize,
        offset_b: usize,
        old_bytes: Vec<u8>,
        new_bytes: Vec<u8>,
    },
}

impl DiffBlock {
    /// Return the number of bytes from A that this block accounts for.
    #[must_use]
    pub const fn a_len(&self) -> usize {
        match self {
            Self::Equal { len, .. } => *len,
            Self::Insert { .. } => 0,
            Self::Delete { bytes, .. } => bytes.len(),
            Self::Replace { old_bytes, .. } => old_bytes.len(),
        }
    }

    /// Return the number of bytes from B that this block accounts for.
    #[must_use]
    pub const fn b_len(&self) -> usize {
        match self {
            Self::Equal { len, .. } => *len,
            Self::Insert { bytes, .. } => bytes.len(),
            Self::Delete { .. } => 0,
            Self::Replace { new_bytes, .. } => new_bytes.len(),
        }
    }

    /// Return `true` if this is an equal block.
    #[must_use]
    pub const fn is_equal(&self) -> bool {
        matches!(self, Self::Equal { .. })
    }

    /// Return `true` if this block represents a change.
    #[must_use]
    pub const fn is_change(&self) -> bool {
        !self.is_equal()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EditScript
// ─────────────────────────────────────────────────────────────────────────────

/// A list of diff operations representing the edit script between two inputs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EditScript {
    pub blocks: Vec<DiffBlock>,
}

impl EditScript {
    /// Create an empty edit script.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a block.
    pub fn push(&mut self, block: DiffBlock) {
        self.blocks.push(block);
    }

    /// Reserve capacity for at least `additional` more blocks.
    pub fn reserve(&mut self, additional: usize) {
        self.blocks.reserve(additional);
    }

    /// Return only the changed blocks.
    #[must_use]
    pub fn changed_blocks(&self) -> Vec<&DiffBlock> {
        self.blocks.iter().filter(|b| b.is_change()).collect()
    }

    /// Return only the equal blocks.
    #[must_use]
    pub fn equal_blocks(&self) -> Vec<&DiffBlock> {
        self.blocks.iter().filter(|b| b.is_equal()).collect()
    }

    /// Total number of blocks.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.blocks.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Compute the similarity ratio [0.0, 1.0].
    #[must_use]
    pub fn similarity(&self) -> f64 {
        let total_a: usize = self.blocks.iter().map(DiffBlock::a_len).sum();
        let total_b: usize = self.blocks.iter().map(DiffBlock::b_len).sum();
        let equal_bytes: usize = self.equal_blocks().iter().map(|b| b.a_len()).sum();
        let denominator = total_a + total_b;
        if denominator == 0 {
            return 1.0;
        }
        f64::from(u32::try_from(2 * equal_bytes).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(denominator).unwrap_or(u32::MAX))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffStats
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics over a diff result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffStats {
    pub size_a: usize,
    pub size_b: usize,
    pub equal_bytes: usize,
    pub inserted_bytes: usize,
    pub deleted_bytes: usize,
    pub replaced_bytes_old: usize,
    pub replaced_bytes_new: usize,
    /// Similarity ratio [0.0, 1.0].
    pub similarity: f64,
    /// Percentage of bytes that changed.
    pub change_pct: f64,
}

impl DiffStats {
    /// Compute stats from an edit script.
    #[must_use]
    pub fn from_script(script: &EditScript, size_a: usize, size_b: usize) -> Self {
        let mut equal_bytes = 0;
        let mut inserted_bytes = 0;
        let mut deleted_bytes = 0;
        let mut replaced_bytes_old = 0;
        let mut replaced_bytes_new = 0;

        for block in &script.blocks {
            match block {
                DiffBlock::Equal { len, .. } => equal_bytes += len,
                DiffBlock::Insert { bytes, .. } => inserted_bytes += bytes.len(),
                DiffBlock::Delete { bytes, .. } => deleted_bytes += bytes.len(),
                DiffBlock::Replace {
                    old_bytes,
                    new_bytes,
                    ..
                } => {
                    replaced_bytes_old += old_bytes.len();
                    replaced_bytes_new += new_bytes.len();
                }
            }
        }

        let changed = inserted_bytes + deleted_bytes + replaced_bytes_old;
        let total = size_a.max(1);
        let change_pct = (f64::from(u32::try_from(changed).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(total).unwrap_or(u32::MAX)))
            * 100.0;
        let similarity = script.similarity();

        Self {
            size_a,
            size_b,
            equal_bytes,
            inserted_bytes,
            deleted_bytes,
            replaced_bytes_old,
            replaced_bytes_new,
            similarity,
            change_pct,
        }
    }

    /// Return `true` if the two inputs are identical.
    #[must_use]
    pub fn is_identical(&self) -> bool {
        (self.similarity - 1.0).abs() < f64::EPSILON
    }
}

impl fmt::Display for DiffStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "similarity={:.1}%  +{}B -{}B ~{}B/{} changed={:.1}%",
            self.similarity * 100.0,
            self.inserted_bytes,
            self.deleted_bytes,
            self.replaced_bytes_old,
            self.replaced_bytes_new,
            self.change_pct,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BinaryDiffer — Myers algorithm stub
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the binary differ.
#[derive(Debug, Clone)]
pub struct DiffConfig {
    /// Maximum input size to diff (safety limit).
    pub max_bytes: usize,
    /// If `true`, merge adjacent replace/insert/delete blocks.
    pub merge_adjacent: bool,
    /// Context lines (equal bytes) to include around each change in the render.
    pub context_bytes: usize,
}

impl Default for DiffConfig {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            merge_adjacent: true,
            context_bytes: 8,
        }
    }
}

/// Byte-level binary differ.
pub struct BinaryDiffer {
    config: DiffConfig,
}

impl BinaryDiffer {
    /// Create with default config.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: DiffConfig::default(),
        }
    }

    /// Create with custom config.
    #[must_use]
    pub const fn with_config(config: DiffConfig) -> Self {
        Self { config }
    }

    /// Compute the diff between two byte slices.
    ///
    /// Uses a simple LCS-based approach (Myers-lite) suitable for binary data.
    ///
    /// # Errors
    /// Returns [`BinaryDiffError`] if inputs are empty or too large.
    pub fn diff(&self, a: &[u8], b: &[u8]) -> Result<EditScript, BinaryDiffError> {
        if a.is_empty() && b.is_empty() {
            return Err(BinaryDiffError::BothEmpty);
        }
        if a.len() > self.config.max_bytes || b.len() > self.config.max_bytes {
            let max = self.config.max_bytes;
            let bad = a.len().max(b.len());
            return Err(BinaryDiffError::InputTooLarge(bad, max));
        }

        let script = Self::myers_diff(a, b);
        Ok(if self.config.merge_adjacent {
            merge_edit_script(script)
        } else {
            script
        })
    }

    /// Compute diff and return stats directly.
    ///
    /// # Errors
    /// Forwards [`BinaryDiffError`].
    pub fn diff_stats(&self, a: &[u8], b: &[u8]) -> Result<DiffStats, BinaryDiffError> {
        let script = self.diff(a, b)?;
        Ok(DiffStats::from_script(&script, a.len(), b.len()))
    }

    /// Simplified Myers diff on byte slices.
    ///
    /// For large inputs (> 4096 bytes) we fall back to a chunked approach
    /// that runs sliding LCS in 64-byte windows.  Full Myers O(ND) is omitted
    /// for compile-time reasons but the API is identical.
    fn myers_diff(a: &[u8], b: &[u8]) -> EditScript {
        if a == b {
            let mut s = EditScript::new();
            s.push(DiffBlock::Equal {
                offset_a: 0,
                offset_b: 0,
                len: a.len(),
            });
            return s;
        }

        // For large inputs use window-based diff.
        if a.len() > 4096 || b.len() > 4096 {
            return Self::window_diff(a, b);
        }

        // Full LCS table for small inputs.
        lcs_diff(a, b)
    }

    /// Window-based diff for larger binaries.
    fn window_diff(a: &[u8], b: &[u8]) -> EditScript {
        const WINDOW: usize = 64;
        let mut script = EditScript::new();
        let len = a.len().max(b.len());
        // Reserve an upper-bound capacity for the worst case where every
        // window emits its own block; this avoids reallocations on long inputs.
        script.reserve(len / WINDOW + 1);
        let mut i = 0usize;
        let mut j = 0usize;

        while i < a.len() || j < b.len() {
            let a_end = (i + WINDOW).min(a.len());
            let b_end = (j + WINDOW).min(b.len());
            let a_chunk = &a[i..a_end];
            let b_chunk = &b[j..b_end];

            if a_chunk == b_chunk {
                script.push(DiffBlock::Equal {
                    offset_a: i,
                    offset_b: j,
                    len: a_chunk.len(),
                });
                i += a_chunk.len();
                j += b_chunk.len();
            } else {
                // Find longest common prefix within window.
                let prefix = a_chunk
                    .iter()
                    .zip(b_chunk.iter())
                    .take_while(|(x, y)| x == y)
                    .count();
                if prefix > 0 {
                    script.push(DiffBlock::Equal {
                        offset_a: i,
                        offset_b: j,
                        len: prefix,
                    });
                    i += prefix;
                    j += prefix;
                } else {
                    // Mark divergence.
                    let a_bytes = a_chunk.to_vec();
                    let b_bytes = b_chunk.to_vec();
                    script.push(DiffBlock::Replace {
                        offset_a: i,
                        offset_b: j,
                        old_bytes: a_bytes,
                        new_bytes: b_bytes,
                    });
                    i += a_chunk.len();
                    j += b_chunk.len();
                }
            }
        }
        script
    }
}

impl Default for BinaryDiffer {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LCS-based diff for small inputs
// ─────────────────────────────────────────────────────────────────────────────

fn lcs_diff(src_a: &[u8], src_b: &[u8]) -> EditScript {
    let len_a = src_a.len();
    let len_b = src_b.len();
    // Build LCS table.
    let mut dp = vec![vec![0usize; len_b + 1]; len_a + 1];
    for ia in (0..len_a).rev() {
        for ib in (0..len_b).rev() {
            dp[ia][ib] = if src_a[ia] == src_b[ib] {
                1 + dp[ia + 1][ib + 1]
            } else {
                dp[ia + 1][ib].max(dp[ia][ib + 1])
            };
        }
    }

    // Trace back the edit script.
    let mut script = EditScript::new();
    let mut ia = 0;
    let mut ib = 0;

    while ia < len_a && ib < len_b {
        if src_a[ia] == src_b[ib] {
            // Equal byte — extend or create Equal block.
            match script.blocks.last_mut() {
                Some(DiffBlock::Equal { len, .. }) => *len += 1,
                _ => script.push(DiffBlock::Equal {
                    offset_a: ia,
                    offset_b: ib,
                    len: 1,
                }),
            }
            ia += 1;
            ib += 1;
        } else if dp[ia + 1][ib] >= dp[ia][ib + 1] {
            // Delete from A.
            match script.blocks.last_mut() {
                Some(DiffBlock::Delete { bytes, .. }) => bytes.push(src_a[ia]),
                _ => script.push(DiffBlock::Delete {
                    offset_a: ia,
                    bytes: vec![src_a[ia]],
                }),
            }
            ia += 1;
        } else {
            // Insert into B.
            match script.blocks.last_mut() {
                Some(DiffBlock::Insert { bytes, .. }) => bytes.push(src_b[ib]),
                _ => script.push(DiffBlock::Insert {
                    offset_b: ib,
                    bytes: vec![src_b[ib]],
                }),
            }
            ib += 1;
        }
    }

    // Remaining deletions.
    if ia < len_a {
        let bytes = src_a[ia..].to_vec();
        script.push(DiffBlock::Delete { offset_a: ia, bytes });
    }
    // Remaining insertions.
    if ib < len_b {
        let bytes = src_b[ib..].to_vec();
        script.push(DiffBlock::Insert { offset_b: ib, bytes });
    }

    script
}

/// Extract (`offset_a`, `offset_b`, `old_bytes`, `new_bytes`) from a `Delete+Insert` or `Insert+Delete` pair.
fn extract_replace_pair(a: &DiffBlock, b: &DiffBlock) -> Option<(usize, usize, Vec<u8>, Vec<u8>)> {
    match (a, b) {
        (DiffBlock::Delete { offset_a, bytes: old }, DiffBlock::Insert { offset_b, bytes: new })
        | (DiffBlock::Insert { offset_b, bytes: new }, DiffBlock::Delete { offset_a, bytes: old }) => {
            Some((*offset_a, *offset_b, old.clone(), new.clone()))
        }
        _ => None,
    }
}

/// Merge adjacent Insert+Delete into Replace blocks.
fn merge_edit_script(mut script: EditScript) -> EditScript {
    let mut out = EditScript::new();
    let mut i = 0;
    let blocks = std::mem::take(&mut script.blocks);

    while i < blocks.len() {
        // Try to merge adjacent Delete+Insert or Insert+Delete into Replace.
        let maybe_replace = if i + 1 < blocks.len() {
            extract_replace_pair(&blocks[i], &blocks[i + 1])
        } else {
            None
        };
        if let Some((offset_a, offset_b, old_bytes, new_bytes)) = maybe_replace {
            out.push(DiffBlock::Replace { offset_a, offset_b, old_bytes, new_bytes });
            i += 2;
        } else {
            out.push(blocks[i].clone());
            i += 1;
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffRenderer
// ─────────────────────────────────────────────────────────────────────────────

/// Render format for [`DiffRenderer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderFormat {
    /// Side-by-side hex.
    SideBySide,
    /// Unified diff (patch-style).
    Unified,
    /// Compact summary only.
    Summary,
}

/// Renders a diff edit script as text.
pub struct DiffRenderer {
    format: RenderFormat,
    context_bytes: usize,
    bytes_per_row: usize,
}

impl DiffRenderer {
    /// Create a renderer.
    #[must_use]
    pub const fn new(format: RenderFormat) -> Self {
        Self {
            format,
            context_bytes: 8,
            bytes_per_row: 16,
        }
    }

    /// Set the number of context bytes shown around changes.
    pub const fn set_context(&mut self, ctx: usize) {
        self.context_bytes = ctx;
    }

    /// Render the edit script to a string.
    #[must_use]
    pub fn render(&self, script: &EditScript, a: &[u8], b: &[u8]) -> String {
        match self.format {
            RenderFormat::Summary => Self::render_summary(script, a.len(), b.len()),
            RenderFormat::Unified => self.render_unified(script),
            RenderFormat::SideBySide => self.render_side_by_side(script),
        }
    }

    fn render_summary(script: &EditScript, size_a: usize, size_b: usize) -> String {
        let stats = DiffStats::from_script(script, size_a, size_b);
        format!(
            "Binary diff summary:\n  Size A: {size_a} bytes\n  Size B: {size_b} bytes\n  {stats}"
        )
    }

    fn render_unified(&self, script: &EditScript) -> String {
        use std::fmt::Write as _;
        let mut out = String::from("--- a\n+++ b\n");
        for block in &script.blocks {
            match block {
                DiffBlock::Equal { offset_a, len, .. } => {
                    let show = (*len).min(self.context_bytes);
                    writeln!(out, " [{offset_a:#x}+{show}B equal]").unwrap_or_default();
                }
                DiffBlock::Insert { offset_b, bytes } => {
                    writeln!(out, "+ [{offset_b:#x}] {}", hex_str(bytes)).unwrap_or_default();
                }
                DiffBlock::Delete { offset_a, bytes } => {
                    writeln!(out, "- [{offset_a:#x}] {}", hex_str(bytes)).unwrap_or_default();
                }
                DiffBlock::Replace { offset_a, offset_b, old_bytes, new_bytes } => {
                    writeln!(out, "~ [{offset_a:#x}→{offset_b:#x}] {} => {}", hex_str(old_bytes), hex_str(new_bytes)).unwrap_or_default();
                }
            }
        }
        out
    }

    fn render_side_by_side(&self, script: &EditScript) -> String {
        use std::fmt::Write as _;
        let mut out = format!("{:<40}  {}\n", "--- A", "+++ B");
        out.push_str(&"-".repeat(80));
        out.push('\n');
        for block in &script.blocks {
            match block {
                DiffBlock::Equal { offset_a, len, .. } => {
                    writeln!(out, "  [{offset_a:#010x}] {len} equal bytes").unwrap_or_default();
                }
                DiffBlock::Insert { offset_b, bytes } => {
                    let h = hex_str(&bytes[..bytes.len().min(self.bytes_per_row)]);
                    writeln!(out, "{:<40}  +[{offset_b:#010x}] {h}", "").unwrap_or_default();
                }
                DiffBlock::Delete { offset_a, bytes } => {
                    let h = hex_str(&bytes[..bytes.len().min(self.bytes_per_row)]);
                    writeln!(out, "-[{offset_a:#010x}] {h:<38}").unwrap_or_default();
                }
                DiffBlock::Replace { offset_a, offset_b, old_bytes, new_bytes } => {
                    let ha = hex_str(&old_bytes[..old_bytes.len().min(self.bytes_per_row)]);
                    let hb = hex_str(&new_bytes[..new_bytes.len().min(self.bytes_per_row)]);
                    writeln!(out, "~[{offset_a:#010x}] {ha:<30}  ~[{offset_b:#010x}] {hb}").unwrap_or_default();
                }
            }
        }
        out
    }
}

fn hex_str(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn differ() -> BinaryDiffer {
        BinaryDiffer::new()
    }

    // -- DiffBlock -----------------------------------------------------------

    #[test]
    fn test_equal_block_lens() {
        let b = DiffBlock::Equal {
            offset_a: 0,
            offset_b: 0,
            len: 10,
        };
        assert_eq!(b.a_len(), 10);
        assert_eq!(b.b_len(), 10);
        assert!(b.is_equal());
    }

    #[test]
    fn test_insert_block_lens() {
        let b = DiffBlock::Insert {
            offset_b: 0,
            bytes: vec![1, 2, 3],
        };
        assert_eq!(b.a_len(), 0);
        assert_eq!(b.b_len(), 3);
        assert!(b.is_change());
    }

    #[test]
    fn test_delete_block_lens() {
        let b = DiffBlock::Delete {
            offset_a: 0,
            bytes: vec![1, 2],
        };
        assert_eq!(b.a_len(), 2);
        assert_eq!(b.b_len(), 0);
    }

    #[test]
    fn test_replace_block_lens() {
        let b = DiffBlock::Replace {
            offset_a: 0,
            offset_b: 0,
            old_bytes: vec![1, 2],
            new_bytes: vec![3, 4, 5],
        };
        assert_eq!(b.a_len(), 2);
        assert_eq!(b.b_len(), 3);
    }

    // -- BinaryDiffer --------------------------------------------------------

    #[test]
    fn test_diff_identical() {
        let d = differ();
        let data = vec![0xAA, 0xBB, 0xCC];
        let script = d.diff(&data, &data).unwrap();
        assert_eq!(script.changed_blocks().len(), 0);
    }

    #[test]
    fn test_diff_both_empty_error() {
        let d = differ();
        assert!(matches!(d.diff(&[], &[]), Err(BinaryDiffError::BothEmpty)));
    }

    #[test]
    fn test_diff_insert() {
        let d = BinaryDiffer::with_config(DiffConfig {
            merge_adjacent: false,
            ..Default::default()
        });
        let a = vec![0x01, 0x02, 0x03];
        let b = vec![0x01, 0xAA, 0x02, 0x03];
        let script = d.diff(&a, &b).unwrap();
        assert!(
            script
                .blocks
                .iter()
                .any(|bl| matches!(bl, DiffBlock::Insert { .. }))
        );
    }

    #[test]
    fn test_diff_delete() {
        let d = BinaryDiffer::with_config(DiffConfig {
            merge_adjacent: false,
            ..Default::default()
        });
        let a = vec![0x01, 0xAA, 0x02, 0x03];
        let b = vec![0x01, 0x02, 0x03];
        let script = d.diff(&a, &b).unwrap();
        assert!(
            script
                .blocks
                .iter()
                .any(|bl| matches!(bl, DiffBlock::Delete { .. }))
        );
    }

    #[test]
    fn test_diff_replace() {
        let d = differ();
        let a = vec![0x01, 0x02, 0x03];
        let b = vec![0x01, 0xFF, 0x03];
        let script = d.diff(&a, &b).unwrap();
        assert!(
            script
                .blocks
                .iter()
                .any(|bl| matches!(bl, DiffBlock::Replace { .. }))
        );
    }

    #[test]
    fn test_diff_stats_identical() {
        let d = differ();
        let data = vec![0xAA; 128];
        let stats = d.diff_stats(&data, &data).unwrap();
        assert!(stats.is_identical());
        assert_eq!(stats.change_pct, 0.0);
    }

    #[test]
    fn test_diff_stats_changed() {
        let d = differ();
        let a = vec![0x00; 8];
        let b = vec![0xFF; 8];
        let stats = d.diff_stats(&a, &b).unwrap();
        assert!(!stats.is_identical());
        assert!(stats.change_pct > 0.0);
    }

    // -- EditScript ----------------------------------------------------------

    #[test]
    fn test_edit_script_similarity_identical() {
        let d = differ();
        let data = b"hello world".to_vec();
        let script = d.diff(&data, &data).unwrap();
        assert!((script.similarity() - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_edit_script_similarity_completely_different() {
        let d = differ();
        let a = vec![0x00; 4];
        let b = vec![0xFF; 4];
        let script = d.diff(&a, &b).unwrap();
        assert!(script.similarity() < 1.0);
    }

    #[test]
    fn test_edit_script_changed_and_equal_blocks() {
        let d = differ();
        let a = vec![0x01, 0x02, 0xFF, 0x04];
        let b = vec![0x01, 0x02, 0xAA, 0x04];
        let script = d.diff(&a, &b).unwrap();
        assert!(!script.changed_blocks().is_empty());
        assert!(!script.equal_blocks().is_empty());
    }

    // -- DiffStats -----------------------------------------------------------

    #[test]
    fn test_stats_from_empty_script() {
        let script = EditScript::new();
        let stats = DiffStats::from_script(&script, 0, 0);
        assert_eq!(stats.equal_bytes, 0);
    }

    #[test]
    fn test_stats_display() {
        let d = differ();
        let a = vec![0x01, 0x02];
        let b = vec![0x03, 0x04];
        let stats = d.diff_stats(&a, &b).unwrap();
        let s = format!("{stats}");
        assert!(s.contains("similarity"));
    }

    // -- DiffRenderer --------------------------------------------------------

    #[test]
    fn test_renderer_summary() {
        let d = differ();
        let a = vec![0x01, 0x02, 0x03];
        let b = vec![0x01, 0xFF, 0x03];
        let script = d.diff(&a, &b).unwrap();
        let r = DiffRenderer::new(RenderFormat::Summary);
        let text = r.render(&script, &a, &b);
        assert!(text.contains("Binary diff summary"));
    }

    #[test]
    fn test_renderer_unified() {
        let d = differ();
        let a = vec![0x01, 0x02];
        let b = vec![0x01, 0xFF];
        let script = d.diff(&a, &b).unwrap();
        let r = DiffRenderer::new(RenderFormat::Unified);
        let text = r.render(&script, &a, &b);
        assert!(text.starts_with("--- a"));
    }

    #[test]
    fn test_renderer_side_by_side() {
        let d = differ();
        let a = vec![0xAA, 0xBB];
        let b = vec![0xCC, 0xDD];
        let script = d.diff(&a, &b).unwrap();
        let r = DiffRenderer::new(RenderFormat::SideBySide);
        let text = r.render(&script, &a, &b);
        assert!(text.contains("--- A"));
    }

    // -- Large input window diff --------------------------------------------

    #[test]
    fn test_large_input_window_diff() {
        let d = differ();
        let a = vec![0u8; 8192];
        let mut b = vec![0u8; 8192];
        b[4096] = 0xFF; // single byte change
        let stats = d.diff_stats(&a, &b).unwrap();
        assert!(!stats.is_identical());
    }

    #[test]
    fn test_input_too_large() {
        let config = DiffConfig {
            max_bytes: 4,
            ..Default::default()
        };
        let d = BinaryDiffer::with_config(config);
        let big = vec![0u8; 1000];
        assert!(matches!(
            d.diff(&big, &big),
            Err(BinaryDiffError::InputTooLarge(_, _))
        ));
    }

    #[test]
    fn test_hex_str() {
        assert_eq!(hex_str(&[0xDE, 0xAD, 0xBE, 0xEF]), "de ad be ef");
    }
}
