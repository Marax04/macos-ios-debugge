//! `cff_pattern_matcher` — Pattern matching for CFF variants.
//!
//! Handles:
//! * OLLVM flat dispatch
//! * Conditional dispatcher
//! * Nested dispatchers
//! * Indirect dispatcher via lookup table
//! * Hikari obfuscator specifics


use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use rustre_core::address::Address;

// ─────────────────────────────────────────────────────────────────────────────
// CFF variant enumeration
// ─────────────────────────────────────────────────────────────────────────────

/// Known CFF obfuscation variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CffVariant {
    /// LLVM-based OLLVM: flat dispatch loop with dense switch.
    OllvmFlatDispatch,
    /// OLLVM with conditional (if/else) dispatcher.
    OllvmConditional,
    /// Multiple nested dispatchers (dispatcher selecting sub-dispatcher).
    NestedDispatchers,
    /// Dispatch through a computed address in a lookup table (indirect).
    IndirectLookupTable,
    /// Hikari obfuscator: switch-based CFF with bogus basic blocks.
    Hikari,
    /// Generic CFF: large switch, no specific protector identified.
    GenericSwitch,
    /// Unknown pattern.
    Unknown,
}

impl std::fmt::Display for CffVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::OllvmFlatDispatch => "OLLVM-FlatDispatch",
            Self::OllvmConditional => "OLLVM-Conditional",
            Self::NestedDispatchers => "NestedDispatchers",
            Self::IndirectLookupTable => "IndirectLookupTable",
            Self::Hikari => "Hikari",
            Self::GenericSwitch => "GenericSwitch",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Structural CFG metrics used for pattern matching
// ─────────────────────────────────────────────────────────────────────────────

/// Structural metrics about a function's CFG used for CFF classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgMetrics {
    /// Total number of basic blocks.
    pub block_count: usize,
    /// Number of blocks with exactly one successor (unconditional flow).
    pub single_successor_blocks: usize,
    /// Number of blocks with exactly two successors (conditional).
    pub two_successor_blocks: usize,
    /// Number of blocks with 3+ successors (switch / dispatch).
    pub multi_successor_blocks: usize,
    /// Maximum out-degree (max number of successors from any one block).
    pub max_out_degree: usize,
    /// Number of back-edges (loops).
    pub back_edges: usize,
    /// Mean basic block size in instructions.
    pub mean_block_size: f64,
    /// Standard deviation of block sizes.
    pub stddev_block_size: f64,
    /// Whether a single block dominates most of the other blocks.
    pub has_dominant_dispatcher: bool,
    /// Address of the most-likely dispatcher block.
    pub dispatcher_candidate: Option<Address>,
    /// Number of "predispatcher" blocks (blocks that only assign the state var).
    pub predispatcher_block_count: usize,
    /// Number of blocks whose only successor is the dispatcher.
    pub back_to_dispatcher_count: usize,
}

impl CfgMetrics {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            block_count: 0,
            single_successor_blocks: 0,
            two_successor_blocks: 0,
            multi_successor_blocks: 0,
            max_out_degree: 0,
            back_edges: 0,
            mean_block_size: 0.0,
            stddev_block_size: 0.0,
            has_dominant_dispatcher: false,
            dispatcher_candidate: None,
            predispatcher_block_count: 0,
            back_to_dispatcher_count: 0,
        }
    }
}

impl Default for CfgMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Match result
// ─────────────────────────────────────────────────────────────────────────────

/// Result of pattern matching against a single CFF variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatchResult {
    /// Which CFF variant was matched.
    pub variant: CffVariant,
    /// Confidence score (0.0–1.0).
    pub confidence: f32,
    /// Supporting evidence.
    pub evidence: Vec<String>,
    /// Addresses of sub-dispatcher blocks (for `NestedDispatchers`).
    pub sub_dispatchers: Vec<Address>,
    /// Address of the lookup table (for `IndirectLookupTable`).
    pub lookup_table_address: Option<Address>,
}

impl PatternMatchResult {
    #[must_use]
    pub const fn new(variant: CffVariant, confidence: f32) -> Self {
        Self {
            variant,
            confidence,
            evidence: Vec::new(),
            sub_dispatchers: Vec::new(),
            lookup_table_address: None,
        }
    }

    #[must_use]
    pub fn with_evidence(mut self, e: impl Into<String>) -> Self {
        self.evidence.push(e.into());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CffPatternMatcher
// ─────────────────────────────────────────────────────────────────────────────

/// Matches a CFG against known CFF obfuscation patterns.
pub struct CffPatternMatcher {
    pub min_confidence: f32,
}

impl Default for CffPatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert `usize` to `f64` for heuristic computations without precision-loss lint.
/// Values larger than `u32::MAX` are clamped, which is fine for block counts.
#[inline]
fn usize_to_f64(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

impl CffPatternMatcher {
    #[must_use]
    pub const fn new() -> Self {
        Self { min_confidence: 0.45 }
    }

    #[must_use]
    pub const fn with_min_confidence(mut self, t: f32) -> Self {
        self.min_confidence = t;
        self
    }

    // ── Metric computation ────────────────────────────────────────────────────

    /// Compute CFG metrics from a block adjacency list.
    ///
    /// `blocks` — `(address, block_size_insns, successors)` tuples.
    #[must_use]
    pub fn compute_metrics(
        &self,
        blocks: &[(Address, usize, Vec<Address>)],
    ) -> CfgMetrics {
        let mut metrics = CfgMetrics::new();
        metrics.block_count = blocks.len();

        let mut sizes: Vec<f64> = Vec::new();
        let mut max_out = 0usize;
        let mut max_succ_addr: Option<Address> = None;

        let all_addrs: HashSet<Address> = blocks.iter().map(|(a, _, _)| *a).collect();

        for (addr, size, succs) in blocks {
            sizes.push(usize_to_f64(*size));
            let out_deg = succs.len();
            match out_deg {
                0 => {}
                1 => metrics.single_successor_blocks += 1,
                2 => metrics.two_successor_blocks += 1,
                _ => metrics.multi_successor_blocks += 1,
            }
            if out_deg > max_out {
                max_out = out_deg;
                max_succ_addr = Some(*addr);
            }

            // Count back-edges (successor address ≤ own address within the function)
            for &succ in succs {
                if succ <= *addr && all_addrs.contains(&succ) {
                    metrics.back_edges += 1;
                }
            }
        }

        metrics.max_out_degree = max_out;
        metrics.dispatcher_candidate = max_succ_addr;
        metrics.has_dominant_dispatcher = max_out >= 4;

        // Stats
        if !sizes.is_empty() {
            let len_f64 = usize_to_f64(sizes.len());
            let mean = sizes.iter().sum::<f64>() / len_f64;
            let variance = sizes.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / len_f64;
            metrics.mean_block_size = mean;
            metrics.stddev_block_size = variance.sqrt();
        }

        // Count predispatcher blocks: blocks with exactly 1 successor = dispatcher
        if let Some(disp) = metrics.dispatcher_candidate {
            for (_, _, succs) in blocks {
                if succs.len() == 1 && succs[0] == disp {
                    metrics.back_to_dispatcher_count += 1;
                }
            }
            // Predispatchers: blocks with 1 successor (unconditional) going back to dispatcher
            metrics.predispatcher_block_count = metrics.back_to_dispatcher_count;
        }

        metrics
    }

    // ── Per-variant matchers ──────────────────────────────────────────────────

    /// Match against OLLVM flat dispatch pattern.
    #[must_use]
    pub fn match_ollvm_flat(&self, m: &CfgMetrics) -> PatternMatchResult {
        let mut conf = 0.0f32;
        let mut evidence = Vec::new();

        // Flat dispatch: one dominant dispatcher with many successors
        if m.max_out_degree >= 6 {
            conf += 0.35;
            evidence.push(format!("max out-degree = {} (>= 6)", m.max_out_degree));
        }

        // Most blocks return to dispatcher (back_to_dispatcher_count is high)
        if m.back_to_dispatcher_count >= 4 {
            conf += 0.25;
            evidence.push(format!(
                "{} blocks return to dispatcher",
                m.back_to_dispatcher_count
            ));
        }

        // Low branch ratio (OLLVM mostly avoids conditional splits in real blocks)
        let branch_ratio = usize_to_f64(m.two_successor_blocks) / usize_to_f64(m.block_count.max(1));
        if branch_ratio < 0.25 {
            conf += 0.15;
            evidence.push(format!("low branch ratio {branch_ratio:.2} (< 0.25)"));
        }

        // Back edges: typically one loop (the main dispatcher loop)
        if m.back_edges == 1 || m.back_edges == 2 {
            conf += 0.10;
            evidence.push(format!("{} back-edge(s)", m.back_edges));
        }

        // Small mean block size with high stddev → many tiny routing blocks
        if m.mean_block_size < 8.0 && m.stddev_block_size > 4.0 {
            conf += 0.15;
            evidence.push("small blocks with high stddev".into());
        }

        PatternMatchResult {
            variant: CffVariant::OllvmFlatDispatch,
            confidence: conf.min(1.0),
            evidence,
            sub_dispatchers: Vec::new(),
            lookup_table_address: None,
        }
    }

    /// Match against OLLVM conditional dispatcher.
    #[must_use]
    pub fn match_ollvm_conditional(&self, m: &CfgMetrics) -> PatternMatchResult {
        let mut conf = 0.0f32;
        let mut evidence = Vec::new();

        // Conditional dispatcher: high ratio of 2-successor blocks
        let branch_ratio = usize_to_f64(m.two_successor_blocks) / usize_to_f64(m.block_count.max(1));
        if branch_ratio >= 0.40 {
            conf += 0.35;
            evidence.push(format!("branch ratio {branch_ratio:.2} (>= 0.40)"));
        }

        // Moderate out-degree dispatcher (not as fan-out as flat)
        if m.max_out_degree >= 3 && m.max_out_degree < 8 {
            conf += 0.20;
            evidence.push(format!("out-degree = {} (3–7)", m.max_out_degree));
        }

        // Multiple back-edges (many conditional loops)
        if m.back_edges >= 2 {
            conf += 0.20;
            evidence.push(format!("{} back-edges", m.back_edges));
        }

        if m.has_dominant_dispatcher {
            conf += 0.15;
            evidence.push("has dominant dispatcher block".into());
        }

        PatternMatchResult {
            variant: CffVariant::OllvmConditional,
            confidence: conf.min(1.0),
            evidence,
            sub_dispatchers: Vec::new(),
            lookup_table_address: None,
        }
    }

    /// Match against nested dispatchers pattern.
    #[must_use]
    pub fn match_nested_dispatchers(
        &self,
        m: &CfgMetrics,
        blocks: &[(Address, usize, Vec<Address>)],
    ) -> PatternMatchResult {
        let mut conf = 0.0f32;
        let mut evidence = Vec::new();
        let mut sub_dispatchers = Vec::new();

        // Find multiple blocks with 4+ successors
        let big_dispatch_blocks: Vec<Address> = blocks
            .iter()
            .filter(|(_, _, succs)| succs.len() >= 4)
            .map(|(a, _, _)| *a)
            .collect();

        if big_dispatch_blocks.len() >= 2 {
            conf += 0.40;
            evidence.push(format!(
                "{} blocks with ≥4 successors",
                big_dispatch_blocks.len()
            ));
            sub_dispatchers = big_dispatch_blocks;
        }

        if m.block_count >= 10 && m.predispatcher_block_count >= 3 {
            conf += 0.25;
            evidence.push(format!(
                "{} predispatcher blocks",
                m.predispatcher_block_count
            ));
        }

        PatternMatchResult {
            variant: CffVariant::NestedDispatchers,
            confidence: conf.min(1.0),
            evidence,
            sub_dispatchers,
            lookup_table_address: None,
        }
    }

    /// Match against indirect lookup table dispatcher.
    #[must_use]
    pub fn match_indirect_lookup_table(
        &self,
        m: &CfgMetrics,
        bytes: &[u8],
        base_address: u64,
    ) -> PatternMatchResult {
        let mut conf = 0.0f32;
        let mut evidence = Vec::new();
        let mut lookup_table_address = None;

        // Indirect dispatch: jmp [reg + table_base + offset*8] pattern
        // Look for: jmp [rax*8 + disp32]  → FF 24 C5
        let indirect_jumps = bytes
            .windows(3)
            .filter(|w| w[0] == 0xFF && w[1] == 0x24 && w[2] == 0xC5)
            .count();

        if indirect_jumps >= 1 {
            conf += 0.50;
            evidence.push(format!("{indirect_jumps} indirect jmp [rax*8+table] patterns"));

            // Extract the table address from the first occurrence
            if let Some((idx, _)) = bytes.windows(3).enumerate().find(|(_, w)| {
                w[0] == 0xFF && w[1] == 0x24 && w[2] == 0xC5
            }) && idx + 7 <= bytes.len() {
                let disp = i32::from_le_bytes(bytes[idx + 3..idx + 7].try_into().unwrap_or_default());
                let rip = base_address + u64::try_from(idx + 7).unwrap_or(u64::MAX);
                lookup_table_address = Some(Address((rip.cast_signed() + i64::from(disp)).cast_unsigned()));
            }
        }

        // Low out-degree for individual blocks (dispatch is through table)
        if m.max_out_degree <= 2 && m.back_to_dispatcher_count >= 4 {
            conf += 0.30;
            evidence.push("low individual out-degree, many back-to-dispatcher".into());
        }

        PatternMatchResult {
            variant: CffVariant::IndirectLookupTable,
            confidence: conf.min(1.0),
            evidence,
            sub_dispatchers: Vec::new(),
            lookup_table_address,
        }
    }

    /// Match against Hikari obfuscator specifics.
    ///
    /// Hikari adds "bogus basic blocks" — unreachable blocks with random
    /// conditional branches.  Characteristic: many 2-successor blocks
    /// where one successor is unreachable.
    #[must_use]
    pub fn match_hikari(&self, m: &CfgMetrics) -> PatternMatchResult {
        let mut conf = 0.0f32;
        let mut evidence = Vec::new();

        // High number of conditional branches (bogus blocks use jcc heavily)
        let branch_ratio = usize_to_f64(m.two_successor_blocks) / usize_to_f64(m.block_count.max(1));
        if branch_ratio > 0.50 {
            conf += 0.30;
            evidence.push(format!("high branch ratio {branch_ratio:.2}"));
        }

        // Hikari's main loop: one back-edge to a dispatcher
        if m.back_edges == 1 && m.has_dominant_dispatcher {
            conf += 0.30;
            evidence.push("single back-edge with dominant dispatcher".into());
        }

        // High block count with small mean size → many bogus blocks
        if m.block_count > 20 && m.mean_block_size < 6.0 {
            conf += 0.20;
            evidence.push(format!(
                "{} blocks, mean size {:.1} insns",
                m.block_count, m.mean_block_size
            ));
        }

        // Hikari also has predispatcher blocks
        if m.predispatcher_block_count >= 2 {
            conf += 0.10;
            evidence.push(format!("{} predispatcher blocks", m.predispatcher_block_count));
        }

        PatternMatchResult {
            variant: CffVariant::Hikari,
            confidence: conf.min(1.0),
            evidence,
            sub_dispatchers: Vec::new(),
            lookup_table_address: None,
        }
    }

    /// Generic switch pattern: large switch, no specific protector.
    #[must_use]
    pub fn match_generic_switch(&self, m: &CfgMetrics) -> PatternMatchResult {
        let mut conf = 0.0f32;
        let mut evidence = Vec::new();

        if m.max_out_degree >= 4 && m.has_dominant_dispatcher {
            conf += 0.40;
            evidence.push(format!("max out-degree {}", m.max_out_degree));
        }

        if m.back_to_dispatcher_count >= 3 {
            conf += 0.30;
            evidence.push(format!("{} blocks returning to dispatcher", m.back_to_dispatcher_count));
        }

        if m.back_edges >= 1 {
            conf += 0.15;
        }

        PatternMatchResult {
            variant: CffVariant::GenericSwitch,
            confidence: conf.min(1.0),
            evidence,
            sub_dispatchers: Vec::new(),
            lookup_table_address: None,
        }
    }

    // ── Full match ────────────────────────────────────────────────────────────

    /// Match all patterns and return the best result.
    #[must_use]
    pub fn match_all(
        &self,
        blocks: &[(Address, usize, Vec<Address>)],
        bytes: &[u8],
        base_address: u64,
    ) -> Vec<PatternMatchResult> {
        let metrics = self.compute_metrics(blocks);

        let mut results = vec![
            self.match_ollvm_flat(&metrics),
            self.match_ollvm_conditional(&metrics),
            self.match_nested_dispatchers(&metrics, blocks),
            self.match_indirect_lookup_table(&metrics, bytes, base_address),
            self.match_hikari(&metrics),
            self.match_generic_switch(&metrics),
        ];

        results.retain(|r| r.confidence >= self.min_confidence);
        results.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        results
    }

    /// Return only the best-matching pattern.
    #[must_use]
    pub fn best_match(
        &self,
        blocks: &[(Address, usize, Vec<Address>)],
        bytes: &[u8],
        base_address: u64,
    ) -> Option<PatternMatchResult> {
        self.match_all(blocks, bytes, base_address).into_iter().next()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(v: u64) -> Address {
        Address(v)
    }

    fn build_ollvm_flat_blocks() -> Vec<(Address, usize, Vec<Address>)> {
        // Dispatcher with 8 successors, 8 real blocks returning to dispatcher
        let dispatcher_addr = addr(0x1000);
        let mut blocks = vec![
            (dispatcher_addr, 5, (0..8u64).map(|i| addr(0x2000 + i * 0x100)).collect()),
        ];
        for i in 0..8u64 {
            let a = addr(0x2000 + i * 0x100);
            blocks.push((a, 4, vec![dispatcher_addr])); // returns to dispatcher
        }
        blocks
    }

    #[test]
    fn test_match_ollvm_flat_dispatch() {
        let matcher = CffPatternMatcher::new();
        let blocks = build_ollvm_flat_blocks();
        let result = matcher.match_ollvm_flat(&matcher.compute_metrics(&blocks));
        assert!(result.confidence >= 0.40, "confidence={}", result.confidence);
        assert_eq!(result.variant, CffVariant::OllvmFlatDispatch);
    }

    #[test]
    fn test_compute_metrics_out_degree() {
        let matcher = CffPatternMatcher::new();
        let blocks = vec![
            (addr(0x100), 10, vec![addr(0x200), addr(0x300), addr(0x400), addr(0x500)]),
            (addr(0x200), 5, vec![addr(0x100)]),
            (addr(0x300), 5, vec![addr(0x100)]),
            (addr(0x400), 5, vec![addr(0x100)]),
            (addr(0x500), 5, vec![addr(0x100)]),
        ];
        let m = matcher.compute_metrics(&blocks);
        assert_eq!(m.max_out_degree, 4);
        assert_eq!(m.block_count, 5);
        assert_eq!(m.back_to_dispatcher_count, 4);
    }

    #[test]
    fn test_match_all_returns_sorted() {
        let matcher = CffPatternMatcher::new();
        let blocks = build_ollvm_flat_blocks();
        let results = matcher.match_all(&blocks, &[], 0x1000);
        // Results should be sorted by confidence descending
        for i in 1..results.len() {
            assert!(results[i - 1].confidence >= results[i].confidence);
        }
    }

    #[test]
    fn test_match_indirect_lookup_table_bytes() {
        let matcher = CffPatternMatcher::new();
        // FF 24 C5 = jmp [rax*8 + ...]  followed by disp32
        let bytes = vec![0xFFu8, 0x24, 0xC5, 0x00, 0x10, 0x40, 0x00, 0x90];
        let blocks = build_ollvm_flat_blocks();
        let m = matcher.compute_metrics(&blocks);
        let result = matcher.match_indirect_lookup_table(&m, &bytes, 0x0040_0000);
        assert!(result.confidence >= 0.40);
        assert_eq!(result.variant, CffVariant::IndirectLookupTable);
    }

    #[test]
    fn test_best_match_some() {
        let matcher = CffPatternMatcher::new();
        let blocks = build_ollvm_flat_blocks();
        let best = matcher.best_match(&blocks, &[], 0x1000);
        assert!(best.is_some());
    }
}
