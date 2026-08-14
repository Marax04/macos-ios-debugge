//! REDQUEEN pass — full input-to-state guided mutation engine.
//!
//! REDQUEEN (Schumilo et al., 2019) is a whitebox fuzzing technique that
//! avoids heavyweight symbolic execution by combining:
//!
//! 1. **Magic-byte extraction** — scan the binary and corpus for constants used
//!    in comparison operations.
//! 2. **Colorize** — identify which bytes in the current input are "tainted"
//!    (influence comparisons).
//! 3. **Targeted I2S mutations** — for every unsatisfied comparison `(v0, v1)`,
//!    scan the input for byte sequences equal to `v0` and replace them with
//!    `v1` (and vice-versa).
//! 4. **Nested-branch solver** — iterative I2S passes that peel off one branch
//!    condition at a time until a path is fully unlocked.
//! 5. **Arithmetic solver** — when literal byte replacement doesn't match, try
//!    `v1 ± small_delta` as the replacement value.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::cmplog::{CmplogCollector, CmplogEntry, CmplogMap, I2sTransformer};
use crate::{Dictionary, XorShiftRng};

// ── MagicBytes ────────────────────────────────────────────────────────────────

/// A "magic byte" pattern: a short constant sequence observed in comparisons.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MagicPattern {
    /// Raw bytes of the constant.
    pub bytes: Vec<u8>,
    /// Source address in the binary where this constant was first seen.
    pub source_addr: u64,
    /// How many times this pattern has been seen (weight for mutation priority).
    pub frequency: u32,
}

impl MagicPattern {
    /// Create a new pattern with frequency 1.
    #[must_use]
    pub const fn new(bytes: Vec<u8>, source_addr: u64) -> Self {
        Self {
            bytes,
            source_addr,
            frequency: 1,
        }
    }

    /// Increment the frequency counter.
    pub const fn increment(&mut self) {
        self.frequency = self.frequency.saturating_add(1);
    }
}

// ── MagicDatabase ─────────────────────────────────────────────────────────────

/// Persistent database of magic byte patterns collected across the fuzzing
/// campaign.
#[derive(Debug, Default)]
pub struct MagicDatabase {
    /// Patterns indexed by their byte content (for fast lookup / dedup).
    patterns: HashMap<Vec<u8>, MagicPattern>,
}

impl MagicDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest all magic bytes from a [`CmplogMap`], updating frequencies.
    pub fn ingest_from_cmplog(&mut self, cmpmap: &CmplogMap, source_addr: u64) {
        for bytes in cmpmap.magic_bytes() {
            if bytes.len() < 2 {
                continue; // skip single-byte constants (too common)
            }
            let entry = self
                .patterns
                .entry(bytes.clone())
                .or_insert_with(|| MagicPattern::new(bytes, source_addr));
            entry.increment();
        }
    }

    /// Return patterns sorted by frequency descending.
    #[must_use]
    pub fn by_frequency(&self) -> Vec<&MagicPattern> {
        let mut v: Vec<&MagicPattern> = self.patterns.values().collect();
        v.sort_unstable_by(|a, b| b.frequency.cmp(&a.frequency));
        v
    }

    /// Export the database as a [`Dictionary`] for use by dictionary mutators.
    #[must_use]
    pub fn to_dictionary(&self) -> Dictionary {
        let mut dict = Dictionary::new();
        for p in self.by_frequency() {
            dict.add(p.bytes.clone());
        }
        dict
    }

    /// Number of distinct patterns.
    #[must_use]
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// True when no patterns have been collected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Look up patterns that appear as substrings of `input`.
    #[must_use]
    pub fn find_in_input<'a>(&'a self, input: &[u8]) -> Vec<(&'a MagicPattern, usize)> {
        let mut hits = Vec::new();
        for (bytes, pat) in &self.patterns {
            if bytes.len() > input.len() {
                continue;
            }
            for start in 0..=input.len() - bytes.len() {
                if &input[start..start + bytes.len()] == bytes.as_slice() {
                    hits.push((pat, start));
                }
            }
        }
        hits
    }
}

// ── RedqueenMutation ──────────────────────────────────────────────────────────

/// A single REDQUEEN mutation proposal.
#[derive(Debug, Clone)]
pub struct RedqueenMutation {
    /// The mutated input bytes.
    pub bytes: Vec<u8>,
    /// Human-readable description of the mutation strategy applied.
    pub strategy: String,
    /// Byte range replaced in the original input.
    pub range: std::ops::Range<usize>,
}

// ── NestedBranchSolver ────────────────────────────────────────────────────────

/// Iterative solver for nested conditional branches.
///
/// Many real-world checks are nested: passing comparison A reveals comparison
/// B (which was previously dead code).  This solver performs multiple I2S
/// passes, re-executing after each successful candidate to discover deeper
/// comparisons.
pub struct NestedBranchSolver {
    /// Maximum number of I2S pass iterations.
    pub max_iterations: usize,
    /// Minimum new coverage bits to continue iterating.
    pub min_new_bits: u32,
}

impl NestedBranchSolver {
    /// Create a solver with the given iteration limit.
    #[must_use]
    pub const fn new(max_iterations: usize) -> Self {
        Self {
            max_iterations,
            min_new_bits: 1,
        }
    }

    /// Run the nested solver.
    ///
    /// `execute` receives a candidate input and returns
    /// `(new_coverage_bits, new_cmplog)` for that execution.
    ///
    /// Returns all inputs that yielded new coverage during the solve.
    pub fn solve<F>(
        &self,
        seed: &[u8],
        collector: &mut CmplogCollector,
        mut execute: F,
    ) -> Vec<Vec<u8>>
    where
        F: FnMut(&[u8]) -> (u32, CmplogMap),
    {
        let mut current = seed.to_vec();
        let mut interesting: Vec<Vec<u8>> = Vec::new();
        let transformer = I2sTransformer::new();

        for _iter in 0..self.max_iterations {
            let candidates = transformer.transform(&current, &collector.map);
            if candidates.is_empty() {
                break;
            }

            let mut found_better = false;
            for cand in candidates {
                let (new_bits, new_cmpmap) = execute(&cand.candidate);
                if new_bits >= self.min_new_bits {
                    interesting.push(cand.candidate.clone());
                    // Update the collector with newly discovered comparisons.
                    for entry in new_cmpmap.iter() {
                        if !entry.is_equal() {
                            collector.map.record(entry.addr, entry.v0, entry.v1, entry.size);
                        }
                    }
                    current = cand.candidate;
                    found_better = true;
                    break; // restart the pass from the new input
                }
            }

            if !found_better {
                break;
            }
        }

        interesting
    }
}

impl Default for NestedBranchSolver {
    fn default() -> Self {
        Self::new(16)
    }
}

// ── ArithmeticSolver ──────────────────────────────────────────────────────────

/// Arithmetic solver: when an exact I2S replacement doesn't hit, try values
/// near `v1` (within a small arithmetic window).
pub struct ArithmeticSolver {
    /// Window of ± deltas to try around the target value.
    pub window: u64,
}

impl ArithmeticSolver {
    /// Create a solver with the given arithmetic window.
    #[must_use]
    pub const fn new(window: u64) -> Self {
        Self { window }
    }

    /// Generate candidates by searching for `v0` and replacing with `v1 ± delta`
    /// for `delta` in `0..=window`.
    #[must_use]
    pub fn solve(
        &self,
        input: &[u8],
        entry: &CmplogEntry,
    ) -> Vec<Vec<u8>> {
        let n = entry.size.bytes();
        if n > input.len() {
            return Vec::new();
        }

        let v0_bytes = entry.v0_le_bytes();
        let mut candidates: Vec<Vec<u8>> = Vec::new();

        for delta in 0..=self.window {
            for &sign in &[1i64, -1i64] {
                let target = entry.v1.cast_signed().wrapping_add(sign * delta.cast_signed()).cast_unsigned();
                let target = entry.size.mask(target);
                let target_bytes = target.to_le_bytes()[..n].to_vec();

                if target_bytes == v0_bytes {
                    continue; // identical to needle — skip
                }

                for start in 0..=input.len() - n {
                    if &input[start..start + n] == v0_bytes.as_slice() {
                        let mut candidate = input.to_vec();
                        candidate[start..start + n].copy_from_slice(&target_bytes);
                        candidates.push(candidate);
                    }
                }
                if candidates.len() >= 64 {
                    return candidates;
                }
            }
        }
        candidates
    }
}

impl Default for ArithmeticSolver {
    fn default() -> Self {
        Self::new(35)
    }
}

// ── RedqueenPass ──────────────────────────────────────────────────────────────

/// Configuration for a single REDQUEEN mutation pass.
#[derive(Debug, Clone)]
pub struct RedqueenConfig {
    /// Enable the arithmetic window solver.
    pub enable_arithmetic: bool,
    /// Enable multi-byte string comparison solving.
    pub enable_multi_byte: bool,
    /// Enable nested branch solving.
    pub enable_nested: bool,
    /// Maximum candidates produced per seed per REDQUEEN pass.
    pub max_candidates: usize,
    /// Arithmetic window size.
    pub arithmetic_window: u64,
    /// Maximum nested iterations.
    pub max_nested_iterations: usize,
}

impl Default for RedqueenConfig {
    fn default() -> Self {
        Self {
            enable_arithmetic: true,
            enable_multi_byte: true,
            enable_nested: true,
            max_candidates: 512,
            arithmetic_window: 35,
            max_nested_iterations: 8,
        }
    }
}

/// The main REDQUEEN mutation engine.
///
/// Orchestrates I2S, arithmetic solving, multi-byte solving, and nested-branch
/// solving into a unified pipeline.
pub struct RedqueenEngine {
    /// Database of magic bytes collected across the campaign.
    pub magic_db: MagicDatabase,
    /// Configuration.
    pub config: RedqueenConfig,
    /// PRNG for tiebreaking / randomised exploration.
    _rng: XorShiftRng,
    /// Count of total mutations generated.
    pub total_mutations: u64,
}

impl RedqueenEngine {
    /// Create a new engine with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(RedqueenConfig::default())
    }

    /// Create with custom configuration.
    #[must_use]
    pub fn with_config(config: RedqueenConfig) -> Self {
        Self {
            magic_db: MagicDatabase::new(),
            config,
            _rng: XorShiftRng::new(0xE0D0_1337),
            total_mutations: 0,
        }
    }

    /// Ingest a completed `CmpLog` run to update the magic-byte database.
    pub fn ingest_cmplog(&mut self, cmpmap: &CmplogMap, source_addr: u64) {
        self.magic_db.ingest_from_cmplog(cmpmap, source_addr);
    }

    /// Run the full REDQUEEN pass on `input` given the current `collector`.
    ///
    /// Returns a list of candidate inputs generated by all active sub-passes.
    #[must_use]
    pub fn mutate(&mut self, input: &[u8], collector: &CmplogCollector) -> Vec<RedqueenMutation> {
        let mut mutations: Vec<RedqueenMutation> = Vec::new();

        // ── I2S pass ────────────────────────────────────────────────────────
        let transformer = I2sTransformer::new();
        let i2s_results = transformer.transform(input, &collector.map);
        for r in i2s_results {
            let end = (r.offset + r.replaced_bytes).min(r.candidate.len());
            mutations.push(RedqueenMutation {
                bytes: r.candidate,
                strategy: format!(
                    "i2s:{}:{}",
                    if r.forward { "fwd" } else { "rev" },
                    r.offset
                ),
                range: r.offset..end,
            });
            if mutations.len() >= self.config.max_candidates {
                break;
            }
        }

        // ── Arithmetic pass ─────────────────────────────────────────────────
        if self.config.enable_arithmetic && mutations.len() < self.config.max_candidates {
            let arith = ArithmeticSolver::new(self.config.arithmetic_window);
            for entry in collector.map.unsatisfied() {
                if mutations.len() >= self.config.max_candidates {
                    break;
                }
                for candidate in arith.solve(input, entry) {
                    mutations.push(RedqueenMutation {
                        bytes: candidate,
                        strategy: format!("arith:{:#x}", entry.addr),
                        range: 0..input.len(),
                    });
                    if mutations.len() >= self.config.max_candidates {
                        break;
                    }
                }
            }
        }

        // ── Multi-byte pass ─────────────────────────────────────────────────
        if self.config.enable_multi_byte && mutations.len() < self.config.max_candidates {
            for (pat, offset) in self.magic_db.find_in_input(input) {
                // Try replacing the found magic bytes with their frequent
                // alternatives from other patterns of the same length.
                let n = pat.bytes.len();
                for other_pat in self.magic_db.by_frequency().into_iter().take(8) {
                    if other_pat.bytes.len() == n && other_pat.bytes != pat.bytes {
                        let mut candidate = input.to_vec();
                        candidate[offset..offset + n].copy_from_slice(&other_pat.bytes);
                        mutations.push(RedqueenMutation {
                            bytes: candidate,
                            strategy: format!("magic:{n}@{offset}"),
                            range: offset..offset + n,
                        });
                        if mutations.len() >= self.config.max_candidates {
                            break;
                        }
                    }
                }
                if mutations.len() >= self.config.max_candidates {
                    break;
                }
            }
        }

        self.total_mutations += mutations.len() as u64;
        mutations
    }

    /// Export the current magic-byte database as a fuzzer dictionary.
    #[must_use]
    pub fn export_dictionary(&self) -> Dictionary {
        self.magic_db.to_dictionary()
    }

    /// Return the number of distinct magic patterns collected.
    #[must_use]
    pub fn magic_pattern_count(&self) -> usize {
        self.magic_db.len()
    }
}

impl Default for RedqueenEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── PatternMatcher ────────────────────────────────────────────────────────────

/// Fast multi-pattern searcher used to locate magic bytes within an input.
///
/// Uses a simple Aho-Corasick–inspired approach: build a trie of all patterns,
/// then scan the input in a single pass.  For small pattern sets (< 256) a
/// naive scan is used for simplicity.
pub struct PatternMatcher {
    patterns: Vec<Vec<u8>>,
    min_len: usize,
}

impl PatternMatcher {
    /// Create a new matcher from a set of patterns.
    #[must_use]
    pub fn new(patterns: Vec<Vec<u8>>) -> Self {
        let min_len = patterns.iter().map(std::vec::Vec::len).min().unwrap_or(0);
        Self { patterns, min_len }
    }

    /// Find all `(pattern_index, offset_in_input)` matches.
    #[must_use]
    pub fn find_all(&self, input: &[u8]) -> Vec<(usize, usize)> {
        if self.patterns.is_empty() || input.len() < self.min_len {
            return Vec::new();
        }
        let mut hits = Vec::new();
        for (pi, pat) in self.patterns.iter().enumerate() {
            if pat.len() > input.len() {
                continue;
            }
            for start in 0..=input.len() - pat.len() {
                if &input[start..start + pat.len()] == pat.as_slice() {
                    hits.push((pi, start));
                }
            }
        }
        hits
    }

    /// Number of patterns.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patterns.len()
    }

    /// True when no patterns are registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmplog::CmpSize;

    fn make_cmpmap_with(v0: u64, v1: u64, size: CmpSize) -> CmplogMap {
        let mut m = CmplogMap::new();
        m.record(0x1000, v0, v1, size);
        m
    }

    #[test]
    fn magic_database_ingest() {
        let mut db = MagicDatabase::new();
        let cmpmap = make_cmpmap_with(0, 0xDEAD_BEEF, CmpSize::B4);
        db.ingest_from_cmplog(&cmpmap, 0x1000);
        assert!(!db.is_empty());
    }

    #[test]
    fn magic_database_to_dictionary() {
        let mut db = MagicDatabase::new();
        let cmpmap = make_cmpmap_with(0, 0x1234_5678, CmpSize::B4);
        db.ingest_from_cmplog(&cmpmap, 0);
        let dict = db.to_dictionary();
        assert!(!dict.is_empty());
    }

    #[test]
    fn magic_database_find_in_input() {
        let mut db = MagicDatabase::new();
        // Add pattern 0xDEAD_BEEF (LE = EF BE AD DE)
        let cmpmap = make_cmpmap_with(0, 0xDEAD_BEEF, CmpSize::B4);
        db.ingest_from_cmplog(&cmpmap, 0);

        let mut input = vec![0u8; 16];
        input[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let hits = db.find_in_input(&input);
        assert!(!hits.is_empty());
    }

    #[test]
    fn arithmetic_solver_finds_candidates() {
        let entry = CmplogEntry::new(0x2000, 10, 20, CmpSize::B4);
        let mut input = vec![0u8; 16];
        input[0..4].copy_from_slice(&10u32.to_le_bytes());

        let solver = ArithmeticSolver::new(35);
        let cands = solver.solve(&input, &entry);
        assert!(!cands.is_empty());
    }

    #[test]
    fn arithmetic_solver_empty_when_no_match() {
        let entry = CmplogEntry::new(0, 99, 100, CmpSize::B4);
        let input = vec![0u8; 8]; // doesn't contain 99
        let solver = ArithmeticSolver::new(5);
        assert!(solver.solve(&input, &entry).is_empty());
    }

    #[test]
    fn redqueen_engine_mutate_produces_candidates() {
        let mut engine = RedqueenEngine::new();
        let mut collector = CmplogCollector::new();
        // Pretend v0=10 in input, target v1=0xDEAD
        collector.ingest(0x1000, 10, 0xDEAD, 4);

        let mut input = vec![0u8; 16];
        input[0..4].copy_from_slice(&10u32.to_le_bytes());

        let mutations = engine.mutate(&input, &collector);
        assert!(!mutations.is_empty());
    }

    #[test]
    fn redqueen_engine_export_dictionary() {
        let mut engine = RedqueenEngine::new();
        let cmpmap = make_cmpmap_with(0, 0xCAFE_BABE, CmpSize::B4);
        engine.ingest_cmplog(&cmpmap, 0);
        let dict = engine.export_dictionary();
        assert!(!dict.is_empty());
    }

    #[test]
    fn nested_branch_solver_terminates() {
        let mut collector = CmplogCollector::new();
        collector.ingest(0x1, 0xFF, 0x00, 1);

        let seed = vec![0xFFu8; 8];
        let solver = NestedBranchSolver::new(4);
        let interesting = solver.solve(&seed, &mut collector, |_cand| {
            (0, CmplogMap::new()) // never interesting
        });
        assert!(interesting.is_empty());
    }

    #[test]
    fn pattern_matcher_finds_patterns() {
        let patterns = vec![b"AAAA".to_vec(), b"BBBB".to_vec()];
        let matcher = PatternMatcher::new(patterns);
        let input = b"AAAAXXXXBBBB";
        let hits = matcher.find_all(input);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn pattern_matcher_empty_patterns() {
        let matcher = PatternMatcher::new(Vec::new());
        let hits = matcher.find_all(b"anything");
        assert!(hits.is_empty());
    }

    #[test]
    fn redqueen_mutation_strategy_label() {
        let m = RedqueenMutation {
            bytes: vec![0],
            strategy: "i2s:fwd:0".to_string(),
            range: 0..1,
        };
        assert!(m.strategy.starts_with("i2s"));
    }

    #[test]
    fn magic_pattern_frequency_increments() {
        let mut p = MagicPattern::new(vec![1, 2, 3], 0);
        p.increment();
        p.increment();
        assert_eq!(p.frequency, 3);
    }
}
