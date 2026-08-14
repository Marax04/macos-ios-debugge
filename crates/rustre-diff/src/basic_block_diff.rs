//! Basic block-level binary diff.
//!
//! Compares two functions at the basic-block granularity, matching blocks by
//! their hash and content, and computing structural changes to the CFG.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// BasicBlock
// ---------------------------------------------------------------------------

/// A basic block for diffing purposes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Address of the first instruction in the block.
    pub start_addr: u64,
    /// Address past the last instruction in the block.
    pub end_addr: u64,
    /// Instruction count.
    pub instr_count: usize,
    /// FNV hash of the block's raw bytes.
    pub hash: u64,
    /// Raw bytes.
    pub bytes: Vec<u8>,
    /// Successor block addresses.
    pub successors: Vec<u64>,
}

impl BasicBlock {
    /// Create a new basic block.
    #[must_use]
    pub fn new(start_addr: u64, end_addr: u64, bytes: Vec<u8>, successors: Vec<u64>) -> Self {
        let hash = fnv1a(&bytes);
        let instr_count = bytes.len(); // simplified: 1 byte per instruction
        Self {
            start_addr,
            end_addr,
            instr_count,
            hash,
            bytes,
            successors,
        }
    }

    /// Size of this block in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        usize::try_from(self.end_addr - self.start_addr).unwrap_or(usize::MAX)
    }

    /// Return `true` if this is an entry block (address is a function entry point).
    #[must_use]
    pub const fn is_entry(&self, function_addr: u64) -> bool {
        self.start_addr == function_addr
    }

    /// Return `true` if this block has no successors (exit block).
    #[must_use]
    pub const fn is_exit(&self) -> bool {
        self.successors.is_empty()
    }

    /// Byte-level similarity to another block.
    #[must_use]
    pub fn similarity(&self, other: &Self) -> f64 {
        if self.hash == other.hash {
            return 1.0;
        }
        let (a, b) = (&self.bytes, &other.bytes);
        let common: usize = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
        let max_len = a.len().max(b.len());
        if max_len == 0 {
            1.0
        } else {
            f64::from(u32::try_from(common).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(max_len).unwrap_or(u32::MAX))
        }
    }
}

impl fmt::Display for BasicBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BB[{:#x}-{:#x}] instrs={} succs={}",
            self.start_addr,
            self.end_addr,
            self.instr_count,
            self.successors.len()
        )
    }
}

// ---------------------------------------------------------------------------
// BlockMatchKind
// ---------------------------------------------------------------------------

/// How a basic block changed between two versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockMatchKind {
    /// Byte-for-byte identical.
    Identical,
    /// Same control-flow successors but different content.
    ContentChanged,
    /// Successor edges changed (restructured flow).
    FlowChanged,
    /// Both content and flow changed.
    FullyChanged,
    /// Block added in new version.
    Added,
    /// Block removed from old version.
    Removed,
}

impl fmt::Display for BlockMatchKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// BlockMatch
// ---------------------------------------------------------------------------

/// Pairing of a basic block across two function versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMatch {
    /// Block from the old version, if present.
    pub old_block: Option<BasicBlock>,
    /// Block from the new version, if present.
    pub new_block: Option<BasicBlock>,
    /// How they relate.
    pub kind: BlockMatchKind,
    /// Byte-level similarity score [0.0, 1.0].
    pub similarity: f64,
}

impl BlockMatch {
    /// Create an identical match.
    #[must_use]
    pub const fn identical(a: BasicBlock, b: BasicBlock) -> Self {
        Self {
            similarity: 1.0,
            old_block: Some(a),
            new_block: Some(b),
            kind: BlockMatchKind::Identical,
        }
    }

    /// Create a content-changed match.
    #[must_use]
    pub fn content_changed(old: BasicBlock, new: BasicBlock) -> Self {
        let sim = old.similarity(&new);
        Self {
            similarity: sim,
            old_block: Some(old),
            new_block: Some(new),
            kind: BlockMatchKind::ContentChanged,
        }
    }

    /// Create a match for two blocks that differ, classifying HOW they differ.
    ///
    /// `ContentChanged` means "same successors, different content" — so the
    /// successor lists have to be compared to say it. When the edges moved the
    /// answer is [`BlockMatchKind::FlowChanged`], and when both moved it is
    /// [`BlockMatchKind::FullyChanged`]; those two are the interesting cases a
    /// patch analyst is looking for.
    #[must_use]
    pub fn changed(old: BasicBlock, new: BasicBlock) -> Self {
        let sim = old.similarity(&new);
        // Successor ORDER is an artefact of how blocks were enumerated, not a
        // property of the control flow; compare them as sets.
        let mut old_succ = old.successors.clone();
        let mut new_succ = new.successors.clone();
        old_succ.sort_unstable();
        old_succ.dedup();
        new_succ.sort_unstable();
        new_succ.dedup();
        let flow_changed = old_succ != new_succ;
        let content_changed = old.bytes != new.bytes;
        let kind = match (content_changed, flow_changed) {
            (true, true) => BlockMatchKind::FullyChanged,
            (false, true) => BlockMatchKind::FlowChanged,
            _ => BlockMatchKind::ContentChanged,
        };
        Self {
            similarity: sim,
            old_block: Some(old),
            new_block: Some(new),
            kind,
        }
    }

    /// Create an added entry.
    #[must_use]
    pub const fn added(block: BasicBlock) -> Self {
        Self {
            similarity: 0.0,
            old_block: None,
            new_block: Some(block),
            kind: BlockMatchKind::Added,
        }
    }

    /// Create a removed entry.
    #[must_use]
    pub const fn removed(block: BasicBlock) -> Self {
        Self {
            similarity: 0.0,
            old_block: Some(block),
            new_block: None,
            kind: BlockMatchKind::Removed,
        }
    }

    /// Return `true` if this is an unchanged match.
    #[must_use]
    pub fn is_unchanged(&self) -> bool {
        self.kind == BlockMatchKind::Identical
    }
}

impl fmt::Display for BlockMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let old_s = self
            .old_block
            .as_ref().map_or_else(|| "-".to_string(), |b| format!("{:#x}", b.start_addr));
        let new_s = self
            .new_block
            .as_ref().map_or_else(|| "-".to_string(), |b| format!("{:#x}", b.start_addr));
        write!(
            f,
            "{} ({old_s} → {new_s}) sim={:.0}%",
            self.kind,
            self.similarity * 100.0
        )
    }
}

// ---------------------------------------------------------------------------
// BlockDiff (full result)
// ---------------------------------------------------------------------------

/// Complete basic-block diff for one function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDiff {
    /// Function name.
    pub function_name: String,
    /// All block matches.
    pub matches: Vec<BlockMatch>,
}

impl BlockDiff {
    /// Count identical blocks.
    #[must_use]
    pub fn identical_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| m.kind == BlockMatchKind::Identical)
            .count()
    }

    /// Count added blocks.
    #[must_use]
    pub fn added_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| m.kind == BlockMatchKind::Added)
            .count()
    }

    /// Count removed blocks.
    #[must_use]
    pub fn removed_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| m.kind == BlockMatchKind::Removed)
            .count()
    }

    /// Count changed blocks (any non-identical paired blocks).
    #[must_use]
    pub fn changed_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| {
                !matches!(
                    m.kind,
                    BlockMatchKind::Identical | BlockMatchKind::Added | BlockMatchKind::Removed
                )
            })
            .count()
    }

    /// Average similarity across matched pairs.
    #[must_use]
    pub fn avg_similarity(&self) -> f64 {
        let paired: Vec<f64> = self
            .matches
            .iter()
            .filter(|m| m.old_block.is_some() && m.new_block.is_some())
            .map(|m| m.similarity)
            .collect();
        if paired.is_empty() {
            1.0
        } else {
            paired.iter().sum::<f64>()
                / f64::from(u32::try_from(paired.len()).unwrap_or(u32::MAX))
        }
    }
}

impl fmt::Display for BlockDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BlockDiff '{}': identical={} added={} removed={} changed={} avg_sim={:.0}%",
            self.function_name,
            self.identical_count(),
            self.added_count(),
            self.removed_count(),
            self.changed_count(),
            self.avg_similarity() * 100.0,
        )
    }
}

// ---------------------------------------------------------------------------
// BasicBlockDiffer
// ---------------------------------------------------------------------------

/// Computes a basic-block diff between two function bodies.
#[derive(Debug, Default)]
pub struct BasicBlockDiffer;

impl BasicBlockDiffer {
    /// Create a new differ.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compute a block-level diff between `old_blocks` and `new_blocks`.
    ///
    /// Matching is done by hash equality first, then by highest byte similarity.
    #[must_use]
    pub fn diff(
        &self,
        function_name: impl Into<String>,
        old_blocks: &[BasicBlock],
        new_blocks: &[BasicBlock],
    ) -> BlockDiff {
        let mut matches = Vec::with_capacity(old_blocks.len() + new_blocks.len());
        let mut matched_old: Vec<bool> = vec![false; old_blocks.len()];
        let mut matched_new: Vec<bool> = vec![false; new_blocks.len()];

        // First pass: exact hash matches.
        //
        // Indexed rather than scanned: the paired loop was quadratic in the
        // block count and kept walking the whole new-block list after a match.
        let mut new_by_hash: std::collections::HashMap<u64, Vec<usize>> =
            std::collections::HashMap::with_capacity(new_blocks.len());
        for (ni, nb) in new_blocks.iter().enumerate() {
            new_by_hash.entry(nb.hash).or_default().push(ni);
        }
        for (oi, ob) in old_blocks.iter().enumerate() {
            if let Some(candidates) = new_by_hash.get(&ob.hash)
                && let Some(&ni) = candidates.iter().find(|&&ni| !matched_new[ni])
            {
                matches.push(BlockMatch::identical(ob.clone(), new_blocks[ni].clone()));
                matched_old[oi] = true;
                matched_new[ni] = true;
            }
        }

        // Second pass: best similarity matches for unmatched blocks
        for (oi, ob) in old_blocks.iter().enumerate() {
            if matched_old[oi] {
                continue;
            }
            let best = new_blocks
                .iter()
                .enumerate()
                .filter(|(ni, _)| !matched_new[*ni])
                .map(|(ni, nb)| (ni, nb, ob.similarity(nb)))
                .max_by(|a, b| {
                    a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal)
                });
            if let Some((ni, nb, sim)) = best
                && sim > 0.3 {
                    matches.push(BlockMatch::changed(ob.clone(), nb.clone()));
                    matched_old[oi] = true;
                    matched_new[ni] = true;
                }
        }

        // Remaining unmatched: removed from old, added in new
        for (oi, ob) in old_blocks.iter().enumerate() {
            if !matched_old[oi] {
                matches.push(BlockMatch::removed(ob.clone()));
            }
        }
        for (ni, nb) in new_blocks.iter().enumerate() {
            if !matched_new[ni] {
                matches.push(BlockMatch::added(nb.clone()));
            }
        }

        BlockDiff {
            function_name: function_name.into(),
            matches,
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: FNV-1a hash
// ---------------------------------------------------------------------------

#[inline]
fn fnv1a(data: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 14_695_981_039_346_656_037;
    const PRIME: u64 = 1_099_511_628_211;
    data.iter().fold(OFFSET_BASIS, |acc, &b| {
        (acc ^ u64::from(b)).wrapping_mul(PRIME)
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn block(start: u64, bytes: &[u8]) -> BasicBlock {
        BasicBlock::new(start, start + bytes.len() as u64, bytes.to_vec(), vec![])
    }

    fn block_with_succ(start: u64, bytes: &[u8], succs: Vec<u64>) -> BasicBlock {
        BasicBlock::new(start, start + bytes.len() as u64, bytes.to_vec(), succs)
    }

    fn differ() -> BasicBlockDiffer {
        BasicBlockDiffer::new()
    }

    #[test]
    fn test_basic_block_size() {
        let b = block(0x1000, &[0x90, 0x90, 0x90]);
        assert_eq!(b.size(), 3);
    }

    #[test]
    fn test_basic_block_is_entry() {
        let b = block(0x1000, &[0x90]);
        assert!(b.is_entry(0x1000));
        assert!(!b.is_entry(0x2000));
    }

    #[test]
    fn test_basic_block_is_exit() {
        let b = block(0x1000, &[0xC3]);
        assert!(b.is_exit());
        let b2 = block_with_succ(0x1000, &[0xEB], vec![0x2000]);
        assert!(!b2.is_exit());
    }

    #[test]
    fn test_basic_block_similarity_identical() {
        let b1 = block(0x1000, &[0x90, 0x90]);
        let b2 = block(0x2000, &[0x90, 0x90]);
        assert!((b1.similarity(&b2) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_basic_block_similarity_different() {
        let b1 = block(0, &[0x90, 0x90, 0x90, 0x90]);
        let b2 = block(0, &[0xFF, 0xFF, 0xFF, 0xFF]);
        assert!((b1.similarity(&b2)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_basic_block_similarity_partial() {
        let b1 = block(0, &[0x90, 0x90, 0xFF, 0xFF]);
        let b2 = block(0, &[0x90, 0x90, 0x90, 0x90]);
        let sim = b1.similarity(&b2);
        assert!(sim > 0.0 && sim < 1.0);
    }

    #[test]
    fn test_basic_block_display() {
        let b = block_with_succ(0x1000, &[0x90], vec![0x2000]);
        let s = b.to_string();
        assert!(s.contains("0x1000"));
        assert!(s.contains("succs=1"));
    }

    #[test]
    fn test_block_match_identical() {
        let b1 = block(0x1000, &[0x90]);
        let b2 = block(0x1000, &[0x90]);
        let m = BlockMatch::identical(b1, b2);
        assert_eq!(m.kind, BlockMatchKind::Identical);
        assert!(m.is_unchanged());
        assert!((m.similarity - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_block_match_added() {
        let b = block(0x2000, &[0x90]);
        let m = BlockMatch::added(b);
        assert_eq!(m.kind, BlockMatchKind::Added);
        assert!(!m.is_unchanged());
        assert!(m.old_block.is_none());
    }

    #[test]
    fn test_block_match_removed() {
        let b = block(0x3000, &[0xC3]);
        let m = BlockMatch::removed(b);
        assert_eq!(m.kind, BlockMatchKind::Removed);
        assert!(m.new_block.is_none());
    }

    #[test]
    fn test_block_match_content_changed() {
        let old = block(0, &[0x90, 0x90]);
        let new = block(0, &[0x90, 0xFF]);
        let m = BlockMatch::content_changed(old, new);
        assert_eq!(m.kind, BlockMatchKind::ContentChanged);
        assert!(m.similarity > 0.0 && m.similarity < 1.0);
    }

    #[test]
    fn test_block_match_display() {
        let b = block(0x1000, &[0x90]);
        let m = BlockMatch::removed(b);
        let s = m.to_string();
        assert!(s.contains("Removed"));
    }

    #[test]
    fn test_differ_identical() {
        let blocks = vec![block(0x1000, &[0x90, 0x90])];
        let diff = differ().diff("fn", &blocks, &blocks);
        assert_eq!(diff.identical_count(), 1);
        assert_eq!(diff.added_count(), 0);
        assert_eq!(diff.removed_count(), 0);
    }

    #[test]
    fn test_differ_added_block() {
        let old = vec![block(0x1000, &[0x90])];
        let new = vec![block(0x1000, &[0x90]), block(0x2000, &[0xFF])];
        let diff = differ().diff("fn", &old, &new);
        assert_eq!(diff.added_count(), 1);
    }

    #[test]
    fn test_differ_removed_block() {
        let old = vec![block(0x1000, &[0x90]), block(0x2000, &[0xFF])];
        let new = vec![block(0x1000, &[0x90])];
        let diff = differ().diff("fn", &old, &new);
        assert_eq!(diff.removed_count(), 1);
    }

    #[test]
    fn test_differ_changed_block() {
        // Same start address but different content → content changed
        let old = vec![block(0x1000, &[0x90, 0x90, 0x90, 0x90])];
        let new = vec![block(0x1000, &[0x90, 0x90, 0xFF, 0xFF])];
        let diff = differ().diff("fn", &old, &new);
        assert_eq!(diff.changed_count(), 1);
    }

    #[test]
    fn test_differ_empty() {
        let diff = differ().diff("fn", &[], &[]);
        assert_eq!(diff.identical_count(), 0);
        assert!((diff.avg_similarity() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_block_diff_display() {
        let diff = BlockDiff {
            function_name: "test".to_string(),
            matches: vec![],
        };
        let s = diff.to_string();
        assert!(s.contains("test"));
    }

    #[test]
    fn test_block_diff_avg_similarity_no_pairs() {
        let diff = BlockDiff {
            function_name: "fn".to_string(),
            matches: vec![BlockMatch::added(block(0, &[0x90]))],
        };
        // No paired blocks → avg_similarity returns 1.0 (default)
        assert!((diff.avg_similarity() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_block_diff_serialization() {
        let diff = BlockDiff {
            function_name: "fn".to_string(),
            matches: vec![],
        };
        let json = serde_json::to_string(&diff).unwrap();
        let decoded: BlockDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.function_name, "fn");
    }

    #[test]
    fn test_block_match_kind_display() {
        assert_eq!(BlockMatchKind::Identical.to_string(), "Identical");
        assert_eq!(BlockMatchKind::Added.to_string(), "Added");
        assert_eq!(BlockMatchKind::Removed.to_string(), "Removed");
    }

    #[test]
    fn test_basic_block_serialization() {
        let b = block(0x1000, &[0x90, 0xC3]);
        let json = serde_json::to_string(&b).unwrap();
        let decoded: BasicBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.start_addr, 0x1000);
        assert_eq!(decoded.bytes.len(), 2);
    }

    #[test]
    fn test_fnv1a_empty() {
        let h = fnv1a(&[]);
        assert_ne!(h, 0);
    }

    #[test]
    fn test_fnv1a_deterministic() {
        assert_eq!(fnv1a(&[0x90, 0x90]), fnv1a(&[0x90, 0x90]));
    }

    #[test]
    fn test_fnv1a_different_bytes() {
        assert_ne!(fnv1a(&[0x90]), fnv1a(&[0x91]));
    }
}
