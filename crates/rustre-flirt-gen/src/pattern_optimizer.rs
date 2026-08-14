//! Pattern optimisation for FLIRT signature generation.
//!
//! Provides three major services:
//!
//! 1. **Trie grouping** — collects patterns with common byte-prefix into a
//!    radix / Patricia trie to expose shared structure for the serialiser.
//! 2. **Variable-byte detection** — automatically marks bytes as wildcards when
//!    they carry relocation targets, branch offsets, or displacement fields.
//! 3. **CRC window selection** — picks the optimal 2-to-32-byte window after the
//!    initial pattern such that the CRC-16 discriminates patterns maximally.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// PatternBytes
// ─────────────────────────────────────────────────────────────────────────────

/// A pattern as a sequence of optional (concrete or wildcard) bytes.
///
/// `None` means "wildcard" — the IDA FLIRT `.pat` `..` notation.
pub type PatternBytes = Vec<Option<u8>>;

// ─────────────────────────────────────────────────────────────────────────────
// OptimizedPattern
// ─────────────────────────────────────────────────────────────────────────────

/// A fully-optimised pattern ready for serialisation.
#[derive(Debug, Clone)]
pub struct OptimizedPattern {
    /// The masked pattern bytes (up to 32 bytes, `None` = wildcard).
    pub bytes: PatternBytes,
    /// Byte offset of the CRC window relative to the start of the pattern.
    pub crc_offset: u16,
    /// Number of bytes covered by the CRC window.
    pub crc_len: u8,
    /// Tail CRC over the CRC window bytes (concrete bytes only), via [`crc16`].
    pub crc: u16,
    /// The function name this pattern identifies.
    pub name: String,
    /// Byte offsets that were auto-detected as variable and masked.
    pub masked_offsets: Vec<u16>,
}

// ─────────────────────────────────────────────────────────────────────────────
// RelocationHint
// ─────────────────────────────────────────────────────────────────────────────

/// Describes a region within function bytes that should be masked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelocationHint {
    /// Start byte offset (relative to function start).
    pub offset: u16,
    /// Number of bytes to mask (1, 2, 4, or 8).
    pub size: u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternInput
// ─────────────────────────────────────────────────────────────────────────────

/// Input to the optimizer: raw bytes plus known relocations.
#[derive(Debug, Clone)]
pub struct PatternInput {
    /// Raw function bytes.
    pub bytes: Vec<u8>,
    /// Function name.
    pub name: String,
    /// Known relocation / variable-byte regions.
    pub relocations: Vec<RelocationHint>,
}

impl PatternInput {
    /// Construct a new input with no relocations.
    #[must_use]
    pub fn new(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            name: name.into(),
            relocations: Vec::new(),
        }
    }

    /// Add a relocation hint.
    pub fn add_reloc(&mut self, offset: u16, size: u8) {
        self.relocations.push(RelocationHint { offset, size });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tail CRC
// ─────────────────────────────────────────────────────────────────────────────

/// The FLIRT tail CRC, i.e. [`rustre_flirt::crc::flirt_tail`].
///
/// # Why this changed (T3b)
///
/// This used to be `rustre_flirt::crc::arc` and was documented as "CRC-16/ARC —
/// FLIRT standard". Both halves were wrong for this field: the tail CRC that
/// [`crate::PatternGenerator::generate`] actually stores, and that
/// `flirt-apply` recomputes when validating, is `flirt_tail` (MCRF4XX). ARC was
/// a third algorithm competing for one conceptual field, after the eleven
/// unified in T3.
///
/// It was left alone until it could be decided by measurement rather than
/// intuition, because it was not established that the value reached the same
/// field. It is now: [`OptimizedPattern`] carries exactly the leaf triple
/// `(crc_offset: u16, crc_len: u8, crc: u16)` that a `.sig` leaf stores, so it
/// is the same field by construction.
///
/// The switch is observably neutral **today** — see
/// `tests/pattern_optimizer_uses_the_canonical_crc.rs`: this module is declared
/// in `lib.rs` but imported by nothing in the workspace, so no `.sig` has ever
/// carried a value from here. The change matters for the first caller that
/// wires it up, who would otherwise get silently unverifiable CRCs.
#[must_use]
pub fn crc16(data: &[u8]) -> u16 {
    rustre_flirt::crc::flirt_tail(data)
}

// ─────────────────────────────────────────────────────────────────────────────
// VariableByteDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects variable (relocation-bearing) byte ranges from x86/x64 heuristics
/// in addition to explicit relocation tables.
pub struct VariableByteDetector {
    /// If `true`, also apply x86-specific opcode heuristics.
    pub heuristic_x86: bool,
    /// If `true`, also apply ARM32 branch-offset heuristics.
    pub heuristic_arm32: bool,
}

impl Default for VariableByteDetector {
    fn default() -> Self {
        Self {
            heuristic_x86: true,
            heuristic_arm32: false,
        }
    }
}

impl VariableByteDetector {
    /// Build a combined mask (bit-per-byte) of variable positions.
    ///
    /// Returns a `Vec<bool>` of length `bytes.len()` where `true` means the
    /// byte should be replaced with a wildcard.
    #[must_use]
    pub fn compute_mask(&self, bytes: &[u8], relocs: &[RelocationHint]) -> Vec<bool> {
        let len = bytes.len();
        let mut mask = vec![false; len];

        // Apply explicit relocations.
        for r in relocs {
            let start = r.offset as usize;
            let end = (start + r.size as usize).min(len);
            for m in mask.iter_mut().take(end).skip(start) {
                *m = true;
            }
        }

        // x86/x64 heuristics: near-call/jump displacement (E8/E9 xx xx xx xx).
        if self.heuristic_x86 {
            let mut i = 0usize;
            while i + 4 < len {
                match bytes[i] {
                    // CALL rel32 / JMP rel32
                    0xE8 | 0xE9 => {
                        for j in 1..=4 {
                            if i + j < len {
                                mask[i + j] = true;
                            }
                        }
                        i += 5;
                        continue;
                    }
                    // Short Jcc
                    0x70..=0x7F => {
                        if i + 1 < len {
                            mask[i + 1] = true;
                        }
                        i += 2;
                        continue;
                    }
                    // Near Jcc (0F 8x)
                    0x0F if i + 5 < len && matches!(bytes[i + 1], 0x80..=0x8F) => {
                        for j in 2..=5 {
                            mask[i + j] = true;
                        }
                        i += 6;
                        continue;
                    }
                    // MOV r/m, imm32 patterns — skip absolute address immediate
                    0xB8..=0xBF => {
                        // MOV reg, imm32: the immediate is usually an address
                        for j in 1..=4 {
                            if i + j < len {
                                mask[i + j] = true;
                            }
                        }
                        i += 5;
                        continue;
                    }
                    _ => {}
                }
                i += 1;
            }
        }

        // ARM32 heuristics: B/BL instructions (opcode[31:24] = 0xEB / 0xEA).
        if self.heuristic_arm32 && len >= 4 {
            let mut i = 0usize;
            while i + 3 < len {
                let word = u32::from_le_bytes([bytes[i], bytes[i+1], bytes[i+2], bytes[i+3]]);
                let cond = word >> 28;
                let op = (word >> 24) & 0xF;
                if cond != 0xF && (op == 0xA || op == 0xB) {
                    // Branch target in bits[23:0] — mask the lower 3 bytes.
                    mask[i] = true;
                    mask[i+1] = true;
                    mask[i+2] = true;
                }
                i += 4;
            }
        }

        mask
    }

    /// Apply the mask to raw bytes, producing a [`PatternBytes`].
    #[must_use]
    pub fn apply_mask(&self, bytes: &[u8], mask: &[bool]) -> PatternBytes {
        bytes.iter().zip(mask.iter())
            .map(|(&b, &m)| if m { None } else { Some(b) })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CrcWindowSelector
// ─────────────────────────────────────────────────────────────────────────────

/// Selects the best CRC window over a collection of patterns.
///
/// The "best" window is defined as the one that maximises the number of
/// distinct CRC values (i.e. maximises discrimination power) for a given
/// length constraint.
pub struct CrcWindowSelector {
    /// Minimum window length (bytes).
    pub min_len: u8,
    /// Maximum window length (bytes).
    pub max_len: u8,
    /// How many bytes after the initial 32-byte prefix to start the search.
    pub search_start: u16,
}

impl Default for CrcWindowSelector {
    fn default() -> Self {
        Self { min_len: 2, max_len: 32, search_start: 32 }
    }
}

impl CrcWindowSelector {
    /// Given a set of raw function byte slices, find the CRC offset and length
    /// that yields the most distinct CRC values (best discriminating power).
    ///
    /// Returns `(best_offset, best_len)`.  If the data is too short, returns
    /// `(search_start, min_len)` with whatever bytes are available.
    #[must_use]
    pub fn select(&self, samples: &[&[u8]]) -> (u16, u8) {
        if samples.is_empty() {
            return (self.search_start, self.min_len);
        }

        let min_sample_len = samples.iter().map(|s| s.len()).min().unwrap_or(0);
        let start = self.search_start as usize;

        if start >= min_sample_len {
            return (self.search_start, self.min_len);
        }

        let available = min_sample_len - start;
        let max_window = (self.max_len as usize).min(available);

        let mut best_offset = self.search_start;
        let mut best_len = self.min_len;
        let mut best_distinct = 0usize;

        for window_len in (self.min_len as usize)..=max_window {
            // Try a few offsets.
            let max_offset_search = (available - window_len).min(32);
            for offset_delta in 0..=max_offset_search {
                let abs_offset = start + offset_delta;
                let mut crcs: Vec<u16> = samples.iter()
                    .filter(|s| s.len() >= abs_offset + window_len)
                    .map(|s| crc16(&s[abs_offset..abs_offset + window_len]))
                    .collect();
                crcs.sort_unstable();
                crcs.dedup();
                let distinct = crcs.len();
                if distinct > best_distinct {
                    best_distinct = distinct;
                    best_offset = u16::try_from(abs_offset).unwrap_or(u16::MAX);
                    best_len = u8::try_from(window_len).unwrap_or(u8::MAX);
                }
            }
        }

        (best_offset, best_len)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TrieNode / PatternTrie
// ─────────────────────────────────────────────────────────────────────────────

/// A node in the pattern grouping trie.
#[derive(Debug, Default)]
pub struct TrieNode {
    /// Children keyed by the next concrete byte.
    pub children: HashMap<Option<u8>, Box<Self>>,
    /// Patterns that terminate at this node.
    pub terminals: Vec<OptimizedPattern>,
}

impl TrieNode {
    fn new() -> Self {
        Self::default()
    }

    /// Insert a pattern by its byte sequence.
    pub fn insert(&mut self, pattern: OptimizedPattern) {
        self.insert_at(&pattern.bytes.clone(), pattern);
    }

    fn insert_at(&mut self, remaining: &[Option<u8>], pattern: OptimizedPattern) {
        if remaining.is_empty() {
            self.terminals.push(pattern);
            return;
        }
        let key = remaining[0];
        let child = self.children.entry(key).or_insert_with(|| Box::new(Self::new()));
        child.insert_at(&remaining[1..], pattern);
    }

    /// Count total number of terminal patterns in this subtree.
    #[must_use]
    pub fn count_terminals(&self) -> usize {
        let here = self.terminals.len();
        let below: usize = self.children.values().map(|c| c.count_terminals()).sum();
        here + below
    }

    /// Depth of the deepest path in this subtree.
    #[must_use]
    pub fn depth(&self) -> usize {
        if self.children.is_empty() {
            return 0;
        }
        1 + self.children.values().map(|c| c.depth()).max().unwrap_or(0)
    }
}

/// A trie grouping patterns by shared byte prefix for efficient storage.
pub struct PatternTrie {
    root: TrieNode,
    total_inserted: usize,
}

impl PatternTrie {
    /// Create an empty trie.
    #[must_use]
    pub fn new() -> Self {
        Self { root: TrieNode::new(), total_inserted: 0 }
    }

    /// Insert an optimised pattern.
    pub fn insert(&mut self, p: OptimizedPattern) {
        self.root.insert(p);
        self.total_inserted += 1;
    }

    /// Number of patterns in the trie.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.total_inserted
    }

    /// `true` if no patterns have been inserted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total_inserted == 0
    }

    /// Borrow the root node for traversal.
    #[must_use]
    pub const fn root(&self) -> &TrieNode {
        &self.root
    }

    /// Collect all patterns in insertion order (BFS).
    #[must_use]
    pub fn collect_all(&self) -> Vec<&OptimizedPattern> {
        let mut out = Vec::new();
        let mut queue = vec![&self.root];
        while let Some(node) = queue.pop() {
            for t in &node.terminals {
                out.push(t);
            }
            for child in node.children.values() {
                queue.push(child.as_ref());
            }
        }
        out
    }
}

impl Default for PatternTrie {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternOptimizer
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level optimizer: combines variable-byte detection, CRC window selection,
/// and trie grouping.
pub struct PatternOptimizer {
    /// How many leading bytes to include in the initial pattern (default 32).
    pub initial_bytes: usize,
    pub var_detector: VariableByteDetector,
    pub crc_selector: CrcWindowSelector,
}

impl Default for PatternOptimizer {
    fn default() -> Self {
        Self {
            initial_bytes: 32,
            var_detector: VariableByteDetector::default(),
            crc_selector: CrcWindowSelector::default(),
        }
    }
}

impl PatternOptimizer {
    /// Optimise a single [`PatternInput`] using caller-supplied CRC params.
    ///
    /// `crc_offset` and `crc_len` should come from [`CrcWindowSelector::select`]
    /// after processing a batch.
    #[must_use]
    pub fn optimize_one(&self, input: &PatternInput, crc_offset: u16, crc_len: u8) -> OptimizedPattern {
        let initial = self.initial_bytes.min(input.bytes.len());
        let raw_slice = &input.bytes[..initial];

        let mask = self.var_detector.compute_mask(raw_slice, &input.relocations);
        let pattern_bytes = self.var_detector.apply_mask(raw_slice, &mask);

        // Collect masked offsets.
        let masked_offsets: Vec<u16> = mask.iter().enumerate()
            .filter(|(_, m)| **m)
            .map(|(i, _)| u16::try_from(i).unwrap_or(u16::MAX))
            .collect();

        // Compute CRC over the window in the raw bytes (not the initial slice).
        let crc_start = crc_offset as usize;
        let crc_end = crc_start + crc_len as usize;
        let crc = if crc_end <= input.bytes.len() {
            crc16(&input.bytes[crc_start..crc_end])
        } else {
            0
        };

        OptimizedPattern {
            bytes: pattern_bytes,
            crc_offset,
            crc_len,
            crc,
            name: input.name.clone(),
            masked_offsets,
        }
    }

    /// Optimise a batch of inputs, auto-selecting the CRC window, and return
    /// a populated [`PatternTrie`].
    #[must_use]
    pub fn optimize_batch(&self, inputs: &[PatternInput]) -> PatternTrie {
        // Collect raw slices for CRC window selection.
        let raw_refs: Vec<&[u8]> = inputs.iter().map(|i| i.bytes.as_slice()).collect();
        let (crc_off, crc_len) = self.crc_selector.select(&raw_refs);

        let mut trie = PatternTrie::new();
        for input in inputs {
            let opt = self.optimize_one(input, crc_off, crc_len);
            trie.insert(opt);
        }
        trie
    }

    /// Optimise a batch and return a flat `Vec` instead of a trie.
    #[must_use]
    pub fn optimize_flat(&self, inputs: &[PatternInput]) -> Vec<OptimizedPattern> {
        let raw_refs: Vec<&[u8]> = inputs.iter().map(|i| i.bytes.as_slice()).collect();
        let (crc_off, crc_len) = self.crc_selector.select(&raw_refs);
        inputs.iter().map(|inp| self.optimize_one(inp, crc_off, crc_len)).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OptimizerStats
// ─────────────────────────────────────────────────────────────────────────────

/// Summary statistics emitted after a batch optimisation run.
#[derive(Debug, Clone, Default)]
pub struct OptimizerStats {
    /// Total patterns processed.
    pub total: usize,
    /// Patterns that had at least one byte masked.
    pub partially_masked: usize,
    /// Patterns fully concrete (no wildcards).
    pub fully_concrete: usize,
    /// Patterns where >50% of bytes are wildcards.
    pub heavily_masked: usize,
    /// Selected CRC offset.
    pub crc_offset: u16,
    /// Selected CRC length.
    pub crc_len: u8,
}

impl OptimizerStats {
    /// Compute stats from a slice of optimised patterns.
    #[must_use]
    pub fn compute(patterns: &[OptimizedPattern]) -> Self {
        let mut s = Self { total: patterns.len(), ..Self::default() };
        for p in patterns {
            let wildcards = p.bytes.iter().filter(|b| b.is_none()).count();
            let total = p.bytes.len();
            if wildcards == 0 {
                s.fully_concrete += 1;
            } else {
                s.partially_masked += 1;
            }
            if total > 0 && wildcards * 2 > total {
                s.heavily_masked += 1;
            }
            s.crc_offset = p.crc_offset;
            s.crc_len = p.crc_len;
        }
        s
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc16_known() {
        // This test used to pin 0xBB3D, the catalogue check value for
        // CRC-16/ARC, and so it certified the very defect T3b removed: a third
        // algorithm competing for the tail CRC field. A constant pinned in a
        // test does not make the algorithm right, it makes the wrong one hard
        // to notice.
        //
        // Now pinned two ways that must agree: the catalogue check value for
        // MCRF4XX, and the canonical primitive itself. The constant alone would
        // drift silently if `crc16` were repointed again; the delegation alone
        // would pass even if the primitive were wrong.
        let data = b"123456789";
        assert_eq!(crc16(data), 0x6F91, "check value di CRC-16/MCRF4XX");
        assert_eq!(crc16(data), rustre_flirt::crc::flirt_tail(data));
    }

    #[test]
    fn test_variable_mask_x86_call() {
        let mut bytes = vec![0u8; 10];
        bytes[2] = 0xE8; // CALL rel32
        bytes[3] = 0x01;
        bytes[4] = 0x00;
        bytes[5] = 0x00;
        bytes[6] = 0x00;
        let detector = VariableByteDetector::default();
        let mask = detector.compute_mask(&bytes, &[]);
        assert!(mask[3] && mask[4] && mask[5] && mask[6]);
        assert!(!mask[0] && !mask[1]);
    }

    #[test]
    fn test_trie_insert_and_collect() {
        let mut trie = PatternTrie::new();
        let p = OptimizedPattern {
            bytes: vec![Some(0x55), Some(0x48), None, Some(0xEC)],
            crc_offset: 32,
            crc_len: 8,
            crc: 0xABCD,
            name: "foo".into(),
            masked_offsets: vec![2],
        };
        trie.insert(p);
        assert_eq!(trie.len(), 1);
        let all = trie.collect_all();
        assert_eq!(all[0].name, "foo");
    }

    #[test]
    fn test_optimizer_batch() {
        let inputs = vec![
            PatternInput::new("alpha", vec![0x55, 0x48, 0x89, 0xE5, 0xE8, 0x01, 0x00, 0x00, 0x00, 0x5D]),
            PatternInput::new("beta",  vec![0x55, 0x48, 0x89, 0xE5, 0xE8, 0x02, 0x00, 0x00, 0x00, 0x5D]),
        ];
        let opt = PatternOptimizer::default();
        let flat = opt.optimize_flat(&inputs);
        assert_eq!(flat.len(), 2);
        // Byte 5 (offset 5 inside E8 call) should be masked.
        // offset 4 is 0xE8, offsets 5..8 should be None.
        for p in &flat {
            assert!(p.bytes[5].is_none(), "call displacement should be masked");
        }
    }
}
