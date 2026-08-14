//! Pattern optimizer — merge adjacent wildcards, compute alignment hints,
//! and produce an [`OptimizedPattern`] from a raw [`Pattern`].

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{Pattern, PatternByte};

// ─────────────────────────────────────────────────────────────────────────────
// AlignmentHint
// ─────────────────────────────────────────────────────────────────────────────

/// A hint about the natural alignment of the first fixed byte in a pattern.
///
/// Many binary patterns (e.g. PE headers, RIFF chunks, ELF fields) are aligned
/// on 2-, 4-, or 8-byte boundaries. When the optimizer can prove this, the
/// scanner can advance by `alignment` bytes at a time instead of 1, giving a
/// significant speedup on large buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlignmentHint {
    /// Alignment in bytes (must be a power of two: 1, 2, 4, or 8).
    pub alignment: usize,
    /// Byte offset of the first exact byte within the (merged) pattern.
    pub anchor_offset: usize,
}

impl AlignmentHint {
    /// Construct a new alignment hint.
    ///
    /// # Panics
    /// Does not panic — clamps `alignment` to the nearest supported power-of-two
    /// (1, 2, 4, 8).
    #[must_use]
    pub fn new(alignment: usize, anchor_offset: usize) -> Self {
        let clamped = match alignment {
            0 | 1 => 1,
            2 | 3 => 2,
            4..=7 => 4,
            _ => 8,
        };
        Self {
            alignment: clamped,
            anchor_offset,
        }
    }

    /// Returns `true` if the alignment provides any speedup over byte-by-byte scan.
    #[must_use]
    pub const fn is_useful(&self) -> bool {
        self.alignment > 1
    }
}

impl Default for AlignmentHint {
    fn default() -> Self {
        Self {
            alignment: 1,
            anchor_offset: 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WildcardRun
// ─────────────────────────────────────────────────────────────────────────────

/// A run of consecutive wildcard bytes in a pattern after merging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WildcardRun {
    /// Index in the merged pattern's slot list.
    pub start: usize,
    /// Number of wildcard bytes.
    pub length: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// OptimizedPattern
// ─────────────────────────────────────────────────────────────────────────────

/// An optimized representation of a pattern after applying [`PatternOptimizer`].
///
/// Optimization passes applied:
/// 1. **Wildcard merging** — adjacent wildcard slots are coalesced into a single
///    conceptual "skip N bytes" run and recorded in `wildcard_runs`.
/// 2. **Anchor selection** — the longest run of consecutive exact bytes is chosen
///    as the primary anchor for Boyer-Moore-like skipping.
/// 3. **Alignment inference** — common alignment values (2, 4, 8) are inferred
///    from context hints stored in the optimizer.
/// 4. **Specificity score** — exact / total ratio for ranking patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizedPattern {
    /// Original byte slots (wildcards preserved).
    pub bytes: Vec<PatternByte>,
    /// Value bytes for masked comparison.
    pub values: Vec<u8>,
    /// Mask bytes (0xFF = exact, 0x00 = wildcard).
    pub masks: Vec<u8>,
    /// Merged wildcard runs within the pattern.
    pub wildcard_runs: Vec<WildcardRun>,
    /// Best anchor (offset, byte value) for pre-filtering.
    pub anchor: Option<(usize, u8)>,
    /// Alignment hint inferred by the optimizer.
    pub alignment: AlignmentHint,
    /// Specificity in [0.0, 1.0]: fraction of exact bytes.
    pub specificity: f64,
    /// Optional name carried over from the source pattern.
    pub name: Option<String>,
    /// Good-suffix skip table for Boyer-Moore-Horspool acceleration (anchor byte
    /// only; stores the maximum skip distance for each possible byte value).
    #[serde(with = "serde_big_array::BigArray")]
    pub bmh_skip: [usize; 256],
}

impl OptimizedPattern {
    /// Returns the length of the pattern in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the pattern is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns `true` if the pattern matches `data` at `offset`.
    #[must_use]
    pub fn matches(&self, data: &[u8], offset: usize) -> bool {
        let end = match offset.checked_add(self.bytes.len()) {
            Some(e) if e <= data.len() => e,
            _ => return false,
        };
        let window = &data[offset..end];
        for (i, &d) in window.iter().enumerate() {
            if d & self.masks[i] != self.values[i] & self.masks[i] {
                return false;
            }
        }
        true
    }

    /// Search `data` for all matches using the anchor and BMH skip table.
    #[must_use]
    pub fn search(&self, data: &[u8]) -> Vec<usize> {
        if self.is_empty() || data.len() < self.len() {
            return Vec::new();
        }
        let pat_len = self.len();
        if let Some((anchor_off, anchor_byte)) = self.anchor {
            // Boyer-Moore-Horspool style: align on anchor, use skip table.
            let mut results = Vec::new();
            // Start scanning from the anchor position inside the buffer.
            // Alignment is reported as metadata only; forcing it here would
            // miss legitimate matches at unaligned offsets.
            let mut i = anchor_off;
            while i < data.len() {
                let d = data[i];
                if d == anchor_byte {
                    let start = i.saturating_sub(anchor_off);
                    if start + pat_len <= data.len() && self.matches(data, start) {
                        results.push(start);
                        i += 1;
                        continue;
                    }
                }
                // Skip to the next occurrence of the ANCHOR byte.
                //
                // The previous version applied a Boyer-Moore-Horspool
                // bad-character skip keyed on the byte at the end of the
                // window. That rule is only sound for a wildcard-free pattern:
                // with trailing wildcards any byte may legitimately sit at the
                // window end, so the table carries no information and the skip
                // jumped clean over real matches. On "AA BB ?? ??" against
                // `11 AA BB 00 00` it skipped from i=1 to i=5 and never tested
                // offset 1, where the pattern does match.
                //
                // Advancing to the next anchor byte is sound for ANY pattern —
                // every match must carry the anchor byte at
                // `start + anchor_off` — and is still a single byte scan.
                match data[i + 1..].iter().position(|&b| b == anchor_byte) {
                    Some(delta) => i += delta + 1,
                    None => break,
                }
            }
            return results;
        }
        // Fallback: brute-force scan.
        (0..=(data.len() - pat_len))
            .filter(|&s| self.matches(data, s))
            .collect()
    }

    /// Return all wildcard-run lengths as a summary vector.
    #[must_use]
    pub fn wildcard_run_lengths(&self) -> Vec<usize> {
        self.wildcard_runs.iter().map(|r| r.length).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternOptimizer
// ─────────────────────────────────────────────────────────────────────────────

/// Optimizer configuration and state.
///
/// Call [`PatternOptimizer::optimize`] to transform a [`Pattern`] into an
/// [`OptimizedPattern`].  Optionally supply [`AlignmentHint`]s via
/// [`PatternOptimizer::with_hint`] to guide alignment inference.
#[derive(Debug, Default)]
pub struct PatternOptimizer {
    /// User-supplied alignment hints, keyed by the pattern name or empty string.
    hints: HashMap<String, AlignmentHint>,
    /// If `true`, the optimizer will compute a full BMH skip table.
    pub compute_bmh: bool,
    /// Minimum run of consecutive exact bytes required to use BMH acceleration.
    pub bmh_min_run: usize,
}

impl PatternOptimizer {
    /// Create a new optimizer with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hints: HashMap::new(),
            compute_bmh: true,
            bmh_min_run: 2,
        }
    }

    /// Register an alignment hint for a named pattern.
    pub fn with_hint(mut self, pattern_name: impl Into<String>, hint: AlignmentHint) -> Self {
        self.hints.insert(pattern_name.into(), hint);
        self
    }

    /// Disable BMH table computation (useful for very short patterns).
    #[must_use]
    pub const fn without_bmh(mut self) -> Self {
        self.compute_bmh = false;
        self
    }

    /// Optimize `pattern` and return the [`OptimizedPattern`].
    #[must_use]
    pub fn optimize(&self, pattern: &Pattern) -> OptimizedPattern {
        let bytes = pattern.bytes.clone();
        let (values, masks) = Self::build_value_mask(&bytes);
        let wildcard_runs = Self::find_wildcard_runs(&bytes);
        let anchor = Self::select_anchor(&bytes);
        let specificity = Self::compute_specificity(&bytes);
        let alignment = self.infer_alignment(pattern, &bytes);
        let bmh_skip = if self.compute_bmh {
            Self::build_bmh_skip(&bytes, self.bmh_min_run)
        } else {
            [1usize; 256]
        };

        OptimizedPattern {
            bytes,
            values,
            masks,
            wildcard_runs,
            anchor,
            alignment,
            specificity,
            name: pattern.name.clone(),
            bmh_skip,
        }
    }

    /// Optimize multiple patterns in parallel using rayon.
    #[must_use]
    pub fn optimize_many(&self, patterns: &[Pattern]) -> Vec<OptimizedPattern> {
        use rayon::prelude::*;
        patterns.par_iter().map(|p| self.optimize(p)).collect()
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn build_value_mask(bytes: &[PatternByte]) -> (Vec<u8>, Vec<u8>) {
        let values: Vec<u8> = bytes.iter().map(PatternByte::value_byte).collect();
        let masks: Vec<u8> = bytes.iter().map(PatternByte::mask_byte).collect();
        (values, masks)
    }

    fn find_wildcard_runs(bytes: &[PatternByte]) -> Vec<WildcardRun> {
        let mut runs = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_wildcard() {
                let start = i;
                while i < bytes.len() && bytes[i].is_wildcard() {
                    i += 1;
                }
                runs.push(WildcardRun {
                    start,
                    length: i - start,
                });
            } else {
                i += 1;
            }
        }
        runs
    }

    /// Select the best anchor: the longest run of consecutive exact bytes.
    /// Returns `(offset_of_run_end - 1, byte_at_that_offset)`.
    fn select_anchor(bytes: &[PatternByte]) -> Option<(usize, u8)> {
        let mut best_run_start = 0usize;
        let mut best_run_len = 0usize;
        let mut cur_start = 0usize;
        let mut cur_len = 0usize;

        for (i, pb) in bytes.iter().enumerate() {
            if matches!(pb, PatternByte::Exact(_)) {
                if cur_len == 0 {
                    cur_start = i;
                }
                cur_len += 1;
                if cur_len > best_run_len {
                    best_run_len = cur_len;
                    best_run_start = cur_start;
                }
            } else {
                cur_len = 0;
            }
        }

        if best_run_len == 0 {
            return None;
        }
        // Anchor on the middle of the best run (reduces false-positive rate).
        let anchor_off = best_run_start + best_run_len / 2;
        if let PatternByte::Exact(b) = bytes[anchor_off] {
            Some((anchor_off, b))
        } else {
            None
        }
    }

    fn compute_specificity(bytes: &[PatternByte]) -> f64 {
        if bytes.is_empty() {
            return 0.0;
        }
        let exact = bytes
            .iter()
            .filter(|b| matches!(b, PatternByte::Exact(_)))
            .count();
        exact as f64 / bytes.len() as f64
    }

    /// Infer alignment from user hints or from byte count divisibility.
    fn infer_alignment(&self, pattern: &Pattern, bytes: &[PatternByte]) -> AlignmentHint {
        // User hint takes priority.
        if let Some(name) = &pattern.name {
            if let Some(&hint) = self.hints.get(name.as_str()) {
                return hint;
            }
        }
        if let Some(&hint) = self.hints.get("") {
            return hint;
        }
        // Heuristic: if pattern length is divisible by 4 and specificity > 0.75,
        // guess 4-byte alignment.
        let spec = Self::compute_specificity(bytes);
        let anchor_off = Self::select_anchor(bytes).map_or(0, |(off, _)| off);
        if bytes.len() % 4 == 0 && spec >= 0.75 {
            return AlignmentHint::new(4, anchor_off);
        }
        if bytes.len() % 2 == 0 && spec >= 0.5 {
            return AlignmentHint::new(2, anchor_off);
        }
        AlignmentHint::new(1, anchor_off)
    }

    /// Build a Boyer-Moore-Horspool bad-character skip table.
    ///
    /// For each possible byte value `b`, the skip table stores the distance from
    /// the last occurrence of `b` in the exact bytes of the pattern to the end of
    /// the pattern.  Bytes not present in the pattern get `pat_len`.
    fn build_bmh_skip(bytes: &[PatternByte], min_run: usize) -> [usize; 256] {
        let pat_len = bytes.len();
        if pat_len == 0 {
            return [1usize; 256];
        }

        // Count the longest run of exact bytes.
        let max_run = {
            let mut best = 0usize;
            let mut cur = 0usize;
            for pb in bytes {
                if matches!(pb, PatternByte::Exact(_)) {
                    cur += 1;
                    if cur > best {
                        best = cur;
                    }
                } else {
                    cur = 0;
                }
            }
            best
        };

        if max_run < min_run {
            // Pattern has too few exact bytes for BMH to be useful.
            return [1usize; 256];
        }

        let mut skip = [pat_len; 256];
        // Only process exact bytes (wildcards do not contribute to the skip table).
        for (i, pb) in bytes[..pat_len.saturating_sub(1)].iter().enumerate() {
            if let PatternByte::Exact(b) = pb {
                let dist = pat_len - 1 - i;
                skip[*b as usize] = dist.min(skip[*b as usize]);
            }
        }
        // Last byte of pattern always gets skip = 1.
        if let PatternByte::Exact(b) = bytes[pat_len - 1] {
            skip[b as usize] = 1;
        }
        skip
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OptimizerStats
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics produced by a batch optimization pass.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct OptimizerStats {
    pub total_patterns: usize,
    pub patterns_with_anchor: usize,
    pub patterns_with_alignment: usize,
    pub patterns_with_bmh: usize,
    pub average_specificity: f64,
    pub total_wildcard_runs: usize,
}

impl OptimizerStats {
    /// Compute statistics from a slice of optimized patterns.
    #[must_use]
    pub fn from_optimized(patterns: &[OptimizedPattern]) -> Self {
        if patterns.is_empty() {
            return Self::default();
        }
        let total = patterns.len();
        let with_anchor = patterns.iter().filter(|p| p.anchor.is_some()).count();
        let with_alignment = patterns
            .iter()
            .filter(|p| p.alignment.is_useful())
            .count();
        let with_bmh = patterns
            .iter()
            .filter(|p| p.bmh_skip.iter().any(|&s| s > 1))
            .count();
        let avg_spec = patterns.iter().map(|p| p.specificity).sum::<f64>() / total as f64;
        let total_runs = patterns
            .iter()
            .map(|p| p.wildcard_runs.len())
            .sum::<usize>();
        Self {
            total_patterns: total,
            patterns_with_anchor: with_anchor,
            patterns_with_alignment: with_alignment,
            patterns_with_bmh: with_bmh,
            average_specificity: avg_spec,
            total_wildcard_runs: total_runs,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(s: &str) -> Pattern {
        Pattern::parse(s).unwrap()
    }

    #[test]
    fn test_alignment_hint_clamp() {
        assert_eq!(AlignmentHint::new(0, 0).alignment, 1);
        assert_eq!(AlignmentHint::new(3, 0).alignment, 2);
        assert_eq!(AlignmentHint::new(6, 0).alignment, 4);
        assert_eq!(AlignmentHint::new(100, 0).alignment, 8);
    }

    #[test]
    fn test_alignment_hint_useful() {
        assert!(!AlignmentHint::new(1, 0).is_useful());
        assert!(AlignmentHint::new(4, 0).is_useful());
    }

    #[test]
    fn test_wildcard_runs_none() {
        let p = pat("DE AD BE EF");
        let opt = PatternOptimizer::new().optimize(&p);
        assert!(opt.wildcard_runs.is_empty());
    }

    #[test]
    fn test_wildcard_runs_single() {
        let p = pat("DE ?? ?? BE EF");
        let opt = PatternOptimizer::new().optimize(&p);
        assert_eq!(opt.wildcard_runs.len(), 1);
        assert_eq!(opt.wildcard_runs[0].start, 1);
        assert_eq!(opt.wildcard_runs[0].length, 2);
    }

    #[test]
    fn test_wildcard_runs_multiple() {
        let p = pat("DE ?? BE ?? ?? EF");
        let opt = PatternOptimizer::new().optimize(&p);
        assert_eq!(opt.wildcard_runs.len(), 2);
        assert_eq!(opt.wildcard_runs[1].length, 2);
    }

    #[test]
    fn test_anchor_selection() {
        let p = pat("DE AD BE EF");
        let opt = PatternOptimizer::new().optimize(&p);
        assert!(opt.anchor.is_some());
        let (off, _byte) = opt.anchor.unwrap();
        assert!(off < 4);
    }

    #[test]
    fn test_anchor_all_wildcards() {
        let p = pat("?? ?? ??");
        let opt = PatternOptimizer::new().optimize(&p);
        assert!(opt.anchor.is_none());
    }

    #[test]
    fn test_specificity_all_exact() {
        let p = pat("DE AD BE EF");
        let opt = PatternOptimizer::new().optimize(&p);
        assert!((opt.specificity - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_specificity_half() {
        let p = pat("DE ?? BE ??");
        let opt = PatternOptimizer::new().optimize(&p);
        assert!((opt.specificity - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_matches_exact() {
        let p = pat("DE AD BE EF");
        let opt = PatternOptimizer::new().optimize(&p);
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        assert!(opt.matches(&data, 0));
        assert!(!opt.matches(&data, 1));
    }

    #[test]
    fn test_matches_with_wildcard() {
        let p = pat("DE ?? EF");
        let opt = PatternOptimizer::new().optimize(&p);
        let data = [0xDE, 0x99, 0xEF];
        assert!(opt.matches(&data, 0));
    }

    #[test]
    fn test_search_finds_matches() {
        let p = pat("AA BB");
        let opt = PatternOptimizer::new().optimize(&p);
        let data = [0x00, 0xAA, 0xBB, 0x00, 0xAA, 0xBB];
        let results = opt.search(&data);
        assert_eq!(results, vec![1, 4]);
    }

    #[test]
    fn test_search_empty_pattern() {
        let p = Pattern {
            bytes: vec![],
            name: None,
            tags: vec![],
            captures: vec![],
            comment: String::new(),
        };
        let opt = PatternOptimizer::new().optimize(&p);
        let data = [0xAA, 0xBB];
        assert!(opt.search(&data).is_empty());
    }

    #[test]
    fn test_optimize_many() {
        let patterns = vec![pat("AA BB"), pat("CC DD")];
        let opts = PatternOptimizer::new().optimize_many(&patterns);
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].len(), 2);
    }

    #[test]
    fn test_bmh_skip_table_computed() {
        let p = pat("DE AD BE EF 00 11 22 33");
        let opt = PatternOptimizer::new().optimize(&p);
        // At least one skip value should be > 1.
        assert!(opt.bmh_skip.iter().any(|&s| s > 1));
    }

    #[test]
    fn test_bmh_not_computed_for_short() {
        let p = pat("DE");
        let opt = PatternOptimizer::new().optimize(&p);
        // Single-byte pattern: skip table all 1s since max_run < min_run(2).
        assert!(opt.bmh_skip.iter().all(|&s| s == 1));
    }

    #[test]
    fn test_alignment_inference_4byte() {
        let p = pat("DE AD BE EF 00 11 22 33");
        let opt = PatternOptimizer::new().optimize(&p);
        // 8-byte pattern, specificity 1.0 >= 0.75 → should get 4-byte alignment.
        assert_eq!(opt.alignment.alignment, 4);
    }

    #[test]
    fn test_user_hint_overrides_inference() {
        let mut p = pat("DE AD BE EF");
        p.name = Some("my_pat".into());
        let hint = AlignmentHint::new(8, 0);
        let opt = PatternOptimizer::new()
            .with_hint("my_pat", hint)
            .optimize(&p);
        assert_eq!(opt.alignment.alignment, 8);
    }

    #[test]
    fn test_optimizer_stats() {
        let patterns = vec![pat("DE AD BE EF"), pat("?? ?? ?? ??")];
        let opts = PatternOptimizer::new().optimize_many(&patterns);
        let stats = OptimizerStats::from_optimized(&opts);
        assert_eq!(stats.total_patterns, 2);
        assert!(stats.average_specificity > 0.0);
    }

    #[test]
    fn test_wildcard_run_lengths_helper() {
        let p = pat("DE ?? ?? BE ?? EF");
        let opt = PatternOptimizer::new().optimize(&p);
        let lens = opt.wildcard_run_lengths();
        assert_eq!(lens, vec![2, 1]);
    }
}
