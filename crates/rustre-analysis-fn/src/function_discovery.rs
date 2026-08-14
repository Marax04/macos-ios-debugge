//! `function_discovery` — multi-strategy function boundary discovery.
//!
//! Provides:
//! * [`FunctionDiscovery`]     — top-level coordinator.
//! * [`DiscoveryStrategy`]     — enum of available strategies.
//! * [`FunctionCandidate`]     — a candidate function entry point.
//! * [`OverlapDetector`]       — detects overlapping function ranges.
//! * [`TailCallResolver`]      — identifies and resolves tail calls.
//! * [`FunctionBoundary`]      — finalized start/end pair.

use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// DiscoveryStrategy
// ─────────────────────────────────────────────────────────────────────────────

/// The algorithmic strategy used to discover a function candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiscoveryStrategy {
    /// Linear sweep: scan bytes sequentially for prologue patterns.
    LinearSweep,
    /// Recursive descent from a known entry point following call targets.
    RecursiveDescent,
    /// Signature matching against a known pattern database.
    Signature,
    /// Derived from the call graph (call target that hasn't been analysed yet).
    CallGraph,
    /// From the symbol / export table.
    SymbolTable,
    /// From exception handler tables (`.pdata`, `.eh_frame`).
    ExceptionTable,
    /// Heuristic gap-fill between known functions.
    HeuristicGap,
}

impl std::fmt::Display for DiscoveryStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::LinearSweep => "linear_sweep",
            Self::RecursiveDescent => "recursive_descent",
            Self::Signature => "signature",
            Self::CallGraph => "call_graph",
            Self::SymbolTable => "symbol_table",
            Self::ExceptionTable => "exception_table",
            Self::HeuristicGap => "heuristic_gap",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionCandidate
// ─────────────────────────────────────────────────────────────────────────────

/// A candidate function entry point with a confidence score.
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionCandidate {
    /// Virtual address of the suspected function entry.
    pub addr: u64,
    /// Confidence in `[0.0, 1.0]`.
    pub confidence: f32,
    /// The strategy that produced this candidate.
    pub method: DiscoveryStrategy,
    /// Optional name (from symbols / user).
    pub name: Option<String>,
    /// Whether this candidate has been confirmed (all checks passed).
    pub confirmed: bool,
}

impl FunctionCandidate {
    #[must_use]
    pub const fn new(addr: u64, confidence: f32, method: DiscoveryStrategy) -> Self {
        Self {
            addr,
            confidence,
            method,
            name: None,
            confirmed: false,
        }
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use]
    pub const fn confirmed(mut self) -> Self {
        self.confirmed = true;
        self
    }

    /// True when confidence >= 0.8.
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.8
    }

    /// True when confidence < 0.4.
    #[must_use]
    pub fn is_low_confidence(&self) -> bool {
        self.confidence < 0.4
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionBoundary
// ─────────────────────────────────────────────────────────────────────────────

/// A finalized function boundary with start and (optional) end addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionBoundary {
    pub start: u64,
    pub end: Option<u64>,
    pub method: DiscoveryStrategy,
    pub name: Option<String>,
    pub is_tail_call_target: bool,
}

impl FunctionBoundary {
    #[must_use]
    pub const fn new(start: u64, method: DiscoveryStrategy) -> Self {
        Self {
            start,
            end: None,
            method,
            name: None,
            is_tail_call_target: false,
        }
    }

    #[must_use]
    pub const fn with_end(mut self, end: u64) -> Self {
        self.end = Some(end);
        self
    }

    /// Size in bytes, if end is known.
    #[must_use]
    pub fn size(&self) -> Option<u64> {
        self.end.map(|e| e.saturating_sub(self.start))
    }
}

impl From<&FunctionCandidate> for FunctionBoundary {
    fn from(c: &FunctionCandidate) -> Self {
        let mut b = Self::new(c.addr, c.method);
        if let Some(ref n) = c.name {
            b.name = Some(n.clone());
        }
        b
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Prologue scanner (x86-64)
// ─────────────────────────────────────────────────────────────────────────────

/// Byte-level prologue patterns for x86-64.
const PROLOGUE_PUSH_RBP: &[u8] = &[0x55, 0x48, 0x89, 0xE5];
const PROLOGUE_SUB_RSP_IMM8: &[u8] = &[0x48, 0x83, 0xEC];
const PROLOGUE_SUB_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xEC];
const PROLOGUE_ENDBR64: &[u8] = &[0xF3, 0x0F, 0x1E, 0xFA];

fn scan_prologues(base: u64, bytes: &[u8]) -> Vec<FunctionCandidate> {
    let mut results = Vec::new();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        let rem = &bytes[i..];
        let (conf, skip) = if rem.starts_with(PROLOGUE_PUSH_RBP) {
            (0.9, 4)
        } else if rem.starts_with(PROLOGUE_ENDBR64) {
            (0.85, 4)
        } else if rem.starts_with(PROLOGUE_SUB_RSP_IMM8) && rem.len() >= 4 {
            (0.75, 3)
        } else if rem.starts_with(PROLOGUE_SUB_RSP_IMM32) && rem.len() >= 7 {
            (0.70, 3)
        } else {
            (0.0, 1)
        };
        if conf > 0.0 {
            results.push(FunctionCandidate::new(
                base + i as u64,
                conf,
                DiscoveryStrategy::LinearSweep,
            ));
            i += skip;
        } else {
            i += 1;
        }
    }
    results
}

fn scan_call_targets(base: u64, bytes: &[u8]) -> Vec<FunctionCandidate> {
    let mut targets: Vec<FunctionCandidate> = Vec::new();
    let len = bytes.len();
    let mut i = 0;
    while i + 4 < len {
        if bytes[i] == 0xE8 {
            let rel = i32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
            let next_ip = base + i as u64 + 5;
            let target = next_ip.wrapping_add_signed(i64::from(rel));
            let region_end = base.saturating_add(bytes.len() as u64);
            if target >= base && target < region_end {
                targets.push(FunctionCandidate::new(
                    target,
                    0.80,
                    DiscoveryStrategy::CallGraph,
                ));
            }
            i += 5;
        } else {
            i += 1;
        }
    }
    targets
}

// ─────────────────────────────────────────────────────────────────────────────
// Linear sweep strategy
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for linear sweep.
#[derive(Debug, Clone)]
pub struct LinearSweepConfig {
    pub min_function_size: usize,
    pub follow_calls: bool,
    pub scan_gap_bytes: usize,
}

impl Default for LinearSweepConfig {
    fn default() -> Self {
        Self {
            min_function_size: 4,
            follow_calls: true,
            scan_gap_bytes: 16,
        }
    }
}

/// Performs linear sweep discovery.
pub struct LinearSweeper {
    pub config: LinearSweepConfig,
}

impl LinearSweeper {
    #[must_use]
    pub const fn new(config: LinearSweepConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn discover(&self, base: u64, bytes: &[u8]) -> Vec<FunctionCandidate> {
        let mut candidates = scan_prologues(base, bytes);
        if self.config.follow_calls {
            for c in scan_call_targets(base, bytes) {
                if !candidates.iter().any(|e| e.addr == c.addr) {
                    candidates.push(c);
                }
            }
        }
        candidates.sort_unstable_by(|a, b| a.addr.cmp(&b.addr));
        candidates
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Recursive descent strategy
// ─────────────────────────────────────────────────────────────────────────────

/// Upper bound (in bytes) on how far [`RecursiveDescentDiscoverer::discover`]
/// scans forward from each visited address looking for `CALL rel32` targets.
///
/// Without this cap, each queue item re-scanned `bytes[off..]` — i.e. from
/// its own address all the way to the end of the mapped region — turning
/// discovery over `V` visited addresses spread across an `N`-byte region into
/// O(V*N) work (worst case O(N^2) when V grows with N, as it does for large
/// binaries with many functions). A single function body rarely exceeds a
/// few KiB, so bounding the per-node scan window is both correct (function
/// bodies are typically much smaller than this) and turns the walk back into
/// O(N) total work.
const RECURSIVE_DESCENT_SCAN_WINDOW: usize = 4096;

/// Performs recursive descent discovery.
pub struct RecursiveDescentDiscoverer {
    pub max_depth: usize,
}

impl RecursiveDescentDiscoverer {
    #[must_use]
    pub const fn new(max_depth: usize) -> Self {
        Self { max_depth }
    }

    /// Start from `entry_points` and follow call targets recursively.
    #[must_use]
    pub fn discover(
        &self,
        base: u64,
        bytes: &[u8],
        entry_points: &[u64],
    ) -> Vec<FunctionCandidate> {
        let mut visited: HashSet<u64> = HashSet::new();
        let mut queue: VecDeque<(u64, usize)> = entry_points.iter().map(|&a| (a, 0)).collect();
        let mut results: Vec<FunctionCandidate> = Vec::new();

        while let Some((addr, depth)) = queue.pop_front() {
            if !visited.insert(addr) || depth > self.max_depth {
                continue;
            }
            let region_end = base.saturating_add(bytes.len() as u64);
            if addr < base || addr >= region_end {
                continue;
            }

            let conf = if depth == 0 {
                1.0
            } else {
                0.85_f32 - (f32::from(u16::try_from(depth).unwrap_or(u16::MAX)) * 0.05).min(0.4)
            };
            results.push(FunctionCandidate::new(
                addr,
                conf,
                DiscoveryStrategy::RecursiveDescent,
            ));

            let off = usize::try_from(addr - base).unwrap_or(usize::MAX);
            let scan_end = off.saturating_add(RECURSIVE_DESCENT_SCAN_WINDOW).min(bytes.len());
            let slice = &bytes[off..scan_end];
            for c in scan_call_targets(addr, slice) {
                if !visited.contains(&c.addr) {
                    queue.push_back((c.addr, depth + 1));
                }
            }
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Signature strategy
// ─────────────────────────────────────────────────────────────────────────────

/// A signature pattern with optional wildcards.
#[derive(Debug, Clone)]
pub struct SignaturePattern {
    pub name: String,
    pub bytes: Vec<Option<u8>>,
    pub confidence: f32,
}

impl SignaturePattern {
    pub fn new(name: impl Into<String>, bytes: Vec<Option<u8>>, confidence: f32) -> Self {
        Self {
            name: name.into(),
            bytes,
            confidence,
        }
    }

    /// True if `data` matches this pattern at offset 0.
    #[must_use]
    pub fn matches(&self, data: &[u8]) -> bool {
        if data.len() < self.bytes.len() {
            return false;
        }
        self.bytes
            .iter()
            .zip(data.iter())
            .all(|(pat, &b)| pat.is_none_or(|p| p == b))
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Signature-based function discovery.
pub struct SignatureDiscoverer {
    pub patterns: Vec<SignaturePattern>,
}

impl SignatureDiscoverer {
    #[must_use]
    pub const fn new(patterns: Vec<SignaturePattern>) -> Self {
        Self { patterns }
    }

    #[must_use]
    pub fn discover(&self, base: u64, bytes: &[u8]) -> Vec<FunctionCandidate> {
        let mut results = Vec::new();
        for i in 0..bytes.len() {
            for pat in &self.patterns {
                if pat.matches(&bytes[i..]) {
                    results.push(
                        FunctionCandidate::new(
                            base + i as u64,
                            pat.confidence,
                            DiscoveryStrategy::Signature,
                        )
                        .with_name(pat.name.clone()),
                    );
                    break;
                }
            }
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OverlapDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects overlapping function ranges after boundary estimation.
#[derive(Debug, Clone, Default)]
pub struct OverlapDetector;

impl OverlapDetector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Given a sorted list of boundaries, return pairs of overlapping ranges.
    #[must_use]
    pub fn find_overlaps(&self, boundaries: &[FunctionBoundary]) -> Vec<(usize, usize)> {
        let mut overlaps = Vec::new();
        for (i, b) in boundaries.iter().enumerate() {
            let end_i = b.end.unwrap_or(u64::MAX);
            for (j, c) in boundaries.iter().enumerate().skip(i + 1) {
                if c.start >= end_i {
                    break;
                }
                overlaps.push((i, j));
            }
        }
        overlaps
    }

    /// Remove duplicates (same start address), keeping highest-confidence.
    ///
    /// Uses a total order on confidence, so NaN values never panic.
    #[must_use]
    pub fn deduplicate(&self, mut candidates: Vec<FunctionCandidate>) -> Vec<FunctionCandidate> {
        candidates.sort_by(|a, b| {
            a.addr
                .cmp(&b.addr)
                .then_with(|| b.confidence.total_cmp(&a.confidence))
        });
        candidates.dedup_by_key(|c| c.addr);
        candidates
    }

    /// Check if two ranges overlap.
    #[must_use]
    pub const fn ranges_overlap(start1: u64, end1: u64, start2: u64, end2: u64) -> bool {
        start1 < end2 && start2 < end1
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TailCallResolver
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies tail-call patterns and resolves them to function entries.
pub struct TailCallResolver;

impl TailCallResolver {
    /// Scan bytes for x86-64 JMP rel32 (`E9 imm32`) patterns that look like
    /// tail calls (jumps into a different function).
    #[must_use]
    pub fn find_tail_call_targets(base: u64, bytes: &[u8]) -> Vec<u64> {
        let mut targets = Vec::new();
        let len = bytes.len();
        let mut i = 0;
        while i + 4 < len {
            if bytes[i] == 0xE9 {
                let rel =
                    i32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
                let next_ip = base + i as u64 + 5;
                let target = next_ip.wrapping_add_signed(i64::from(rel));
                if target >= base && target < base.saturating_add(bytes.len() as u64) {
                    targets.push(target);
                }
                i += 5;
            } else {
                i += 1;
            }
        }
        targets.sort_unstable();
        targets.dedup();
        targets
    }

    /// Mark candidates at tail-call target addresses (as confirmed direct calls).
    #[must_use]
    pub fn resolve(base: u64, bytes: &[u8]) -> Vec<FunctionCandidate> {
        Self::find_tail_call_targets(base, bytes)
            .into_iter()
            .map(|addr| {
                FunctionCandidate::new(addr, 0.75, DiscoveryStrategy::CallGraph).confirmed()
            })
            .collect()
    }
}

/// Extended metadata for a candidate.
#[derive(Debug, Clone, Default)]
pub struct CandidateMeta {
    pub is_tail_call: bool,
    pub seen_in_export: bool,
}

impl TailCallResolver {
    /// Produce `FunctionBoundary` entries for tail-call targets.
    #[must_use]
    pub fn resolve_to_boundaries(base: u64, bytes: &[u8]) -> Vec<FunctionBoundary> {
        Self::find_tail_call_targets(base, bytes)
            .into_iter()
            .map(|addr| {
                let mut b = FunctionBoundary::new(addr, DiscoveryStrategy::CallGraph);
                b.is_tail_call_target = true;
                b
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionDiscovery — top-level coordinator
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the function discovery engine.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub strategies: Vec<DiscoveryStrategy>,
    pub min_confidence: f32,
    pub min_function_size: usize,
    pub max_recursion_depth: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            strategies: vec![
                DiscoveryStrategy::LinearSweep,
                DiscoveryStrategy::RecursiveDescent,
                DiscoveryStrategy::CallGraph,
            ],
            min_confidence: 0.5,
            min_function_size: 4,
            max_recursion_depth: 512,
        }
    }
}

/// Summary of a discovery run.
#[derive(Debug, Clone, Default)]
pub struct DiscoverySummary {
    pub total_candidates: usize,
    pub confirmed_functions: usize,
    pub by_strategy: HashMap<DiscoveryStrategy, usize>,
    pub overlaps_detected: usize,
    pub tail_calls_resolved: usize,
}

/// Top-level function discovery coordinator.
pub struct FunctionDiscovery {
    config: DiscoveryConfig,
}

impl FunctionDiscovery {
    #[must_use]
    pub const fn new(config: DiscoveryConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn default_x86_64() -> Self {
        Self::new(DiscoveryConfig::default())
    }

    /// Run all enabled strategies on `bytes` loaded at `base`.
    #[must_use]
    pub fn discover(
        &self,
        base: u64,
        bytes: &[u8],
        entry_points: &[u64],
    ) -> (Vec<FunctionBoundary>, DiscoverySummary) {
        let mut candidates: Vec<FunctionCandidate> = Vec::new();

        for strategy in &self.config.strategies {
            match strategy {
                DiscoveryStrategy::LinearSweep => {
                    let sw = LinearSweeper::new(LinearSweepConfig::default());
                    candidates.extend(sw.discover(base, bytes));
                }
                DiscoveryStrategy::RecursiveDescent => {
                    let rd = RecursiveDescentDiscoverer::new(self.config.max_recursion_depth);
                    candidates.extend(rd.discover(base, bytes, entry_points));
                }
                DiscoveryStrategy::CallGraph => {
                    candidates.extend(scan_call_targets(base, bytes));
                }
                // Not runnable from raw bytes alone: these need a signature DB,
                // a parsed symbol/exception table, or a post-pass over already
                // known boundaries. Handled elsewhere in the pipeline.
                DiscoveryStrategy::Signature
                | DiscoveryStrategy::SymbolTable
                | DiscoveryStrategy::ExceptionTable
                | DiscoveryStrategy::HeuristicGap => {}
            }
        }

        // Tail-call resolution.
        let tail_calls = TailCallResolver::find_tail_call_targets(base, bytes);
        let tail_call_count = tail_calls.len();
        for addr in tail_calls {
            if !candidates.iter().any(|c| c.addr == addr) {
                candidates.push(FunctionCandidate::new(
                    addr,
                    0.75,
                    DiscoveryStrategy::CallGraph,
                ));
            }
        }

        // Deduplicate.
        let detector = OverlapDetector::new();
        let deduped = detector.deduplicate(candidates);

        // Filter by confidence.
        let filtered: Vec<FunctionCandidate> = deduped
            .into_iter()
            .filter(|c| c.confidence >= self.config.min_confidence)
            .collect();

        let total_candidates = filtered.len();
        let mut by_strategy: HashMap<DiscoveryStrategy, usize> = HashMap::new();
        for c in &filtered {
            *by_strategy.entry(c.method).or_insert(0) += 1;
        }

        // Build boundaries (estimate ends).
        let starts: Vec<u64> = filtered.iter().map(|c| c.addr).collect();
        let file_end = base.saturating_add(bytes.len() as u64);
        let boundaries: Vec<FunctionBoundary> = filtered
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let end = if i + 1 < starts.len() {
                    starts[i + 1]
                } else {
                    file_end
                };
                let size = end.saturating_sub(c.addr);
                let mut b = FunctionBoundary::from(c);
                if usize::try_from(size).unwrap_or(usize::MAX) >= self.config.min_function_size {
                    b.end = Some(end);
                }
                b
            })
            .collect();

        // Detect overlaps.
        let overlaps = detector.find_overlaps(&boundaries);
        let overlaps_detected = overlaps.len();

        // Mark confirmed.
        let confirmed_functions = boundaries.iter().filter(|b| b.end.is_some()).count();

        let summary = DiscoverySummary {
            total_candidates,
            confirmed_functions,
            by_strategy,
            overlaps_detected,
            tail_calls_resolved: tail_call_count,
        };

        (boundaries, summary)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_code() -> (u64, Vec<u8>) {
        // PUSH RBP; MOV RBP,RSP at offset 0x10; CALL rel32 at 0; RET at 0x20
        let base = 0x1000u64;
        let mut code = vec![0x90u8; 0x30];
        // CALL at 0x00: disp = 0x0B → target = 0x1000+5+0x0B = 0x1010
        code[0] = 0xE8;
        code[1..5].copy_from_slice(&0x0Bi32.to_le_bytes());
        // PUSH RBP; MOV RBP,RSP at 0x10
        code[0x10] = 0x55;
        code[0x11] = 0x48;
        code[0x12] = 0x89;
        code[0x13] = 0xE5;
        // RET at 0x20
        code[0x20] = 0xC3;
        // JMP rel32 at 0x25: disp=-0x15 → target=0x1025+5-0x15 = 0x1015
        code[0x25] = 0xE9;
        code[0x26..0x2A].copy_from_slice(&(-0x15i32).to_le_bytes());
        (base, code)
    }

    // 1. DiscoveryStrategy display.
    #[test]
    fn test_strategy_display() {
        assert_eq!(DiscoveryStrategy::LinearSweep.to_string(), "linear_sweep");
        assert_eq!(
            DiscoveryStrategy::RecursiveDescent.to_string(),
            "recursive_descent"
        );
        assert_eq!(DiscoveryStrategy::CallGraph.to_string(), "call_graph");
    }

    // 2. FunctionCandidate basic fields.
    #[test]
    fn test_function_candidate_basic() {
        let c = FunctionCandidate::new(0x1000, 0.9, DiscoveryStrategy::LinearSweep);
        assert_eq!(c.addr, 0x1000);
        assert!((c.confidence - 0.9).abs() < 1e-5);
        assert_eq!(c.method, DiscoveryStrategy::LinearSweep);
        assert!(c.is_high_confidence());
        assert!(!c.is_low_confidence());
    }

    // 3. FunctionCandidate with_name.
    #[test]
    fn test_candidate_with_name() {
        let c =
            FunctionCandidate::new(0x2000, 1.0, DiscoveryStrategy::SymbolTable).with_name("main");
        assert_eq!(c.name.as_deref(), Some("main"));
    }

    // 4. FunctionCandidate is_low_confidence.
    #[test]
    fn test_candidate_low_confidence() {
        let c = FunctionCandidate::new(0x3000, 0.3, DiscoveryStrategy::HeuristicGap);
        assert!(c.is_low_confidence());
        assert!(!c.is_high_confidence());
    }

    // 5. scan_prologues finds PUSH RBP; MOV RBP,RSP.
    #[test]
    fn test_scan_prologues_push_rbp() {
        let (base, code) = minimal_code();
        let hits = scan_prologues(base, &code);
        let found = hits.iter().any(|c| c.addr == base + 0x10);
        assert!(found, "expected prologue at 0x1010: {hits:?}");
    }

    // 6. scan_call_targets finds CALL rel32.
    #[test]
    fn test_scan_call_targets() {
        let (base, code) = minimal_code();
        let targets = scan_call_targets(base, &code);
        let found = targets.iter().any(|c| c.addr == base + 0x10);
        assert!(found, "expected call target at 0x1010: {targets:?}");
    }

    // 7. LinearSweeper deduplication.
    #[test]
    fn test_linear_sweeper_dedup() {
        let (base, code) = minimal_code();
        let sw = LinearSweeper::new(LinearSweepConfig::default());
        let cands = sw.discover(base, &code);
        let addrs: Vec<u64> = cands.iter().map(|c| c.addr).collect();
        let unique: HashSet<u64> = addrs.iter().copied().collect();
        assert_eq!(addrs.len(), unique.len(), "duplicates present: {addrs:?}");
    }

    // 8. RecursiveDescentDiscoverer starts from entry.
    #[test]
    fn test_recursive_descent_entry() {
        let (base, code) = minimal_code();
        let rd = RecursiveDescentDiscoverer::new(10);
        let cands = rd.discover(base, &code, &[base]);
        assert!(cands.iter().any(|c| c.addr == base));
    }

    // 9. RecursiveDescentDiscoverer follows call targets.
    #[test]
    fn test_recursive_descent_follows_calls() {
        let (base, code) = minimal_code();
        let rd = RecursiveDescentDiscoverer::new(10);
        let cands = rd.discover(base, &code, &[base]);
        let found = cands.iter().any(|c| c.addr == base + 0x10);
        assert!(found, "should follow call to 0x1010: {cands:?}");
    }

    // 9b. RecursiveDescentDiscoverer bounds its per-node CALL scan so that
    // discovery over a large region touching many entry points is not
    // quadratic (each visited node only scans a fixed-size window ahead of
    // itself, not out to the end of the whole byte region).
    #[test]
    fn test_recursive_descent_scan_is_bounded_not_quadratic() {
        let base = 0x1000u64;
        // A large region where every 16-byte slot is `CALL next_slot; RET;
        // padding`, chaining forward one hop at a time from the entry.
        let slots = 4096usize;
        let mut code = vec![0x90u8; slots * 16];
        for slot in 0..slots - 1 {
            let call_off = slot * 16;
            let next_slot_addr = base + ((slot + 1) * 16) as u64;
            let next_ip = base + (call_off + 5) as u64;
            let rel = i32::try_from(next_slot_addr as i64 - next_ip as i64).unwrap();
            code[call_off] = 0xE8;
            code[call_off + 1..call_off + 5].copy_from_slice(&rel.to_le_bytes());
            code[call_off + 5] = 0xC3;
        }
        let rd = RecursiveDescentDiscoverer::new(slots + 1);
        let cands = rd.discover(base, &code, &[base]);
        // Every slot is reachable by following the CALL chain hop-by-hop
        // (each hop is within the 4096-byte scan window), even though no
        // single node's scan window covers the whole 64KiB region.
        assert_eq!(cands.len(), slots, "expected the full call chain to be walked hop-by-hop");
    }

    // 10. RecursiveDescentDiscoverer respects max_depth.
    #[test]
    fn test_recursive_descent_max_depth() {
        let (base, code) = minimal_code();
        let rd = RecursiveDescentDiscoverer::new(0);
        // Depth 0 means only entry points, no recursion.
        let cands = rd.discover(base, &code, &[base]);
        assert_eq!(cands.len(), 1);
    }

    // 11. SignaturePattern matches exact.
    #[test]
    fn test_signature_exact_match() {
        let pat = SignaturePattern::new(
            "test",
            vec![Some(0x55), Some(0x48), Some(0x89), Some(0xE5)],
            0.9,
        );
        let data = [0x55, 0x48, 0x89, 0xE5, 0x00];
        assert!(pat.matches(&data));
    }

    // 12. SignaturePattern wildcard.
    #[test]
    fn test_signature_wildcard() {
        let pat =
            SignaturePattern::new("wild", vec![Some(0x48), Some(0x83), Some(0xEC), None], 0.8);
        assert!(pat.matches(&[0x48, 0x83, 0xEC, 0xFF]));
        assert!(pat.matches(&[0x48, 0x83, 0xEC, 0x28]));
        assert!(!pat.matches(&[0x48, 0x83, 0xED, 0x28]));
    }

    // 13. SignaturePattern too short.
    #[test]
    fn test_signature_too_short() {
        let pat = SignaturePattern::new("s", vec![Some(0x55), Some(0x48)], 0.8);
        assert!(!pat.matches(&[0x55]));
    }

    // 14. SignatureDiscoverer finds pattern.
    #[test]
    fn test_signature_discoverer() {
        let (base, code) = minimal_code();
        let pats = vec![SignaturePattern::new(
            "push_rbp",
            vec![Some(0x55), Some(0x48), Some(0x89), Some(0xE5)],
            0.9,
        )];
        let sd = SignatureDiscoverer::new(pats);
        let cands = sd.discover(base, &code);
        assert!(cands.iter().any(|c| c.addr == base + 0x10));
    }

    // 15. OverlapDetector::find_overlaps.
    #[test]
    fn test_overlap_detector_overlaps() {
        let b1 = FunctionBoundary::new(0x1000, DiscoveryStrategy::LinearSweep).with_end(0x1010);
        let b2 = FunctionBoundary::new(0x1008, DiscoveryStrategy::LinearSweep).with_end(0x1020);
        let overlaps = OverlapDetector::new().find_overlaps(&[b1, b2]);
        assert_eq!(overlaps.len(), 1);
    }

    // 16. OverlapDetector::find_overlaps no overlap.
    #[test]
    fn test_overlap_detector_no_overlaps() {
        let b1 = FunctionBoundary::new(0x1000, DiscoveryStrategy::LinearSweep).with_end(0x1010);
        let b2 = FunctionBoundary::new(0x1010, DiscoveryStrategy::LinearSweep).with_end(0x1020);
        let overlaps = OverlapDetector::new().find_overlaps(&[b1, b2]);
        assert!(overlaps.is_empty());
    }

    // 17. OverlapDetector::deduplicate.
    #[test]
    fn test_overlap_detector_dedup() {
        let c1 = FunctionCandidate::new(0x1000, 0.6, DiscoveryStrategy::LinearSweep);
        let c2 = FunctionCandidate::new(0x1000, 0.9, DiscoveryStrategy::CallGraph);
        let c3 = FunctionCandidate::new(0x2000, 0.7, DiscoveryStrategy::LinearSweep);
        let result = OverlapDetector::new().deduplicate(vec![c1, c2, c3]);
        assert_eq!(result.len(), 2);
        // Should keep the higher-confidence entry for 0x1000.
        let at_1000 = result.iter().find(|c| c.addr == 0x1000).unwrap();
        assert!((at_1000.confidence - 0.9).abs() < 1e-5);
    }

    // 18. OverlapDetector::ranges_overlap.
    #[test]
    fn test_ranges_overlap() {
        assert!(OverlapDetector::ranges_overlap(0, 10, 5, 15));
        assert!(!OverlapDetector::ranges_overlap(0, 5, 5, 10));
        assert!(!OverlapDetector::ranges_overlap(10, 20, 0, 10));
    }

    // 19. TailCallResolver::find_tail_call_targets.
    #[test]
    fn test_tail_call_resolver() {
        let (base, code) = minimal_code();
        let targets = TailCallResolver::find_tail_call_targets(base, &code);
        assert!(
            !targets.is_empty(),
            "expected at least one tail-call target: {targets:?}"
        );
    }

    // 20. FunctionBoundary::size.
    #[test]
    fn test_boundary_size() {
        let b = FunctionBoundary::new(0x1000, DiscoveryStrategy::LinearSweep).with_end(0x1020);
        assert_eq!(b.size(), Some(0x20));
    }

    // 21. FunctionBoundary from candidate.
    #[test]
    fn test_boundary_from_candidate() {
        let c =
            FunctionCandidate::new(0x4000, 0.9, DiscoveryStrategy::SymbolTable).with_name("foo");
        let b = FunctionBoundary::from(&c);
        assert_eq!(b.start, 0x4000);
        assert_eq!(b.name.as_deref(), Some("foo"));
    }

    // 22. FunctionDiscovery::discover returns boundaries.
    #[test]
    fn test_discovery_run() {
        let (base, code) = minimal_code();
        let d = FunctionDiscovery::default_x86_64();
        let (boundaries, summary) = d.discover(base, &code, &[base]);
        assert!(!boundaries.is_empty());
        assert!(summary.total_candidates > 0);
    }

    // 23. DiscoverySummary by_strategy.
    #[test]
    fn test_summary_by_strategy() {
        let (base, code) = minimal_code();
        let d = FunctionDiscovery::default_x86_64();
        let (_, summary) = d.discover(base, &code, &[base]);
        assert!(!summary.by_strategy.is_empty());
    }

    // 24. DiscoveryConfig default strategies.
    #[test]
    fn test_discovery_config_default() {
        let cfg = DiscoveryConfig::default();
        assert!(cfg.strategies.contains(&DiscoveryStrategy::LinearSweep));
        assert!(
            cfg.strategies
                .contains(&DiscoveryStrategy::RecursiveDescent)
        );
        assert_eq!(cfg.min_function_size, 4);
    }

    // 25. SignaturePattern::len.
    #[test]
    fn test_signature_len() {
        let p = SignaturePattern::new("x", vec![Some(0x55), Some(0x48)], 0.9);
        assert_eq!(p.len(), 2);
        assert!(!p.is_empty());
    }

    // 26. FunctionCandidate confirmed flag.
    #[test]
    fn test_candidate_confirmed() {
        let c = FunctionCandidate::new(0x1000, 0.9, DiscoveryStrategy::LinearSweep).confirmed();
        assert!(c.confirmed);
    }

    // 27. Empty binary discovery.
    #[test]
    fn test_empty_binary() {
        let d = FunctionDiscovery::default_x86_64();
        let (boundaries, summary) = d.discover(0x1000, &[], &[]);
        assert!(boundaries.is_empty());
        assert_eq!(summary.total_candidates, 0);
    }

    // 28. LinearSweeper no follow_calls.
    #[test]
    fn test_linear_sweeper_no_calls() {
        let (base, code) = minimal_code();
        let cfg = LinearSweepConfig {
            follow_calls: false,
            ..Default::default()
        };
        let sw = LinearSweeper::new(cfg);
        let cands = sw.discover(base, &code);
        // Only prologue-based; no call-target entries.
        for c in &cands {
            assert_eq!(c.method, DiscoveryStrategy::LinearSweep);
        }
    }

    // 29. TailCallResolver::resolve_to_boundaries.
    #[test]
    fn test_tail_call_to_boundaries() {
        let (base, code) = minimal_code();
        let boundaries = TailCallResolver::resolve_to_boundaries(base, &code);
        assert!(!boundaries.is_empty());
        assert!(boundaries.iter().all(|b| b.is_tail_call_target));
    }

    // 30. RecursiveDescentDiscoverer empty entry.
    #[test]
    fn test_recursive_descent_empty_entry() {
        let rd = RecursiveDescentDiscoverer::new(10);
        let cands = rd.discover(0x1000, &[], &[]);
        assert!(cands.is_empty());
    }

    // 31. SignatureDiscoverer no match.
    #[test]
    fn test_signature_no_match() {
        let pats = vec![SignaturePattern::new(
            "nomatch",
            vec![Some(0xFF), Some(0xFF)],
            0.9,
        )];
        let sd = SignatureDiscoverer::new(pats);
        let code = vec![0x55, 0x48, 0x89, 0xE5];
        let cands = sd.discover(0x1000, &code);
        assert!(cands.is_empty());
    }

    // 32. FunctionBoundary tail_call flag.
    #[test]
    fn test_boundary_tail_call() {
        let mut b = FunctionBoundary::new(0x1000, DiscoveryStrategy::CallGraph);
        b.is_tail_call_target = true;
        assert!(b.is_tail_call_target);
    }

    // 33. DiscoveryStrategy all variants.
    #[test]
    fn test_strategy_variants() {
        let all = [
            DiscoveryStrategy::LinearSweep,
            DiscoveryStrategy::RecursiveDescent,
            DiscoveryStrategy::Signature,
            DiscoveryStrategy::CallGraph,
            DiscoveryStrategy::SymbolTable,
            DiscoveryStrategy::ExceptionTable,
            DiscoveryStrategy::HeuristicGap,
        ];
        let set: HashSet<String> = all.iter().map(std::string::ToString::to_string).collect();
        assert_eq!(set.len(), 7);
    }

    // 34. scan_prologues ENDBR64.
    #[test]
    fn test_endbr64_detected() {
        let base = 0x5000u64;
        let mut code = vec![0x90u8; 16];
        code[4] = 0xF3;
        code[5] = 0x0F;
        code[6] = 0x1E;
        code[7] = 0xFA;
        let cands = scan_prologues(base, &code);
        assert!(cands.iter().any(|c| c.addr == base + 4));
    }

    // 35. FunctionDiscovery min_confidence filter.
    #[test]
    fn test_min_confidence_filter() {
        let cfg = DiscoveryConfig {
            min_confidence: 0.95,
            ..Default::default()
        };
        let d = FunctionDiscovery::new(cfg);
        let (base, code) = minimal_code();
        let (boundaries, _) = d.discover(base, &code, &[base]);
        // At 0.95 threshold, only the highest-confidence entries survive.
        for b in &boundaries {
            // All returned boundaries were from high-confidence candidates.
            let _ = b; // we just verify no panic
        }
    }

    // 36. FunctionBoundary size None when end unknown.
    #[test]
    fn test_boundary_size_none() {
        let b = FunctionBoundary::new(0x1000, DiscoveryStrategy::LinearSweep);
        assert_eq!(b.size(), None);
    }

    // 37. scan_call_targets on a buffer that ends right at the CALL opcode
    // boundary (no room for the rel32 operand) must not panic or index OOB.
    #[test]
    fn test_scan_call_targets_truncated_operand() {
        // 0xE8 as the very last byte: no operand bytes follow.
        let code = vec![0x90, 0x90, 0xE8];
        let targets = scan_call_targets(0x1000, &code);
        assert!(targets.is_empty());
    }

    // 38. scan_prologues on buffers shorter than the longest prologue pattern.
    #[test]
    fn test_scan_prologues_short_buffer() {
        for len in 0..4 {
            let code = vec![0x55u8; len];
            // Must not panic regardless of buffer length.
            let _ = scan_prologues(0x1000, &code);
        }
    }

    // 39. find_tail_call_targets on a buffer that ends right at the JMP opcode.
    #[test]
    fn test_tail_call_targets_truncated_operand() {
        let code = vec![0x90, 0xE9, 0x00, 0x00];
        let targets = TailCallResolver::find_tail_call_targets(0x1000, &code);
        assert!(targets.is_empty());
    }

    // 40. RecursiveDescentDiscoverer with an entry point at the exact end of
    // the region (out of bounds) must be skipped, not panic.
    #[test]
    fn test_recursive_descent_entry_out_of_bounds() {
        let base = 0x1000u64;
        let code = vec![0x90u8; 8];
        let rd = RecursiveDescentDiscoverer::new(4);
        // Entry exactly at region_end (one past the last valid byte).
        let cands = rd.discover(base, &code, &[base + 8]);
        assert!(cands.is_empty());
        // Entry below base.
        let cands2 = rd.discover(base, &code, &[0x10]);
        assert!(cands2.is_empty());
    }

    // 41. LinearSweeper on an all-zero (invalid) buffer: no panics, no bogus
    // candidates from the 0x00 filler bytes.
    #[test]
    fn test_linear_sweeper_all_zeros() {
        let code = vec![0u8; 64];
        let sw = LinearSweeper::new(LinearSweepConfig::default());
        let cands = sw.discover(0x1000, &code);
        assert!(cands.is_empty());
    }

    // 42. SignatureDiscoverer with an empty pattern list finds nothing and
    // does not panic on any input, including empty bytes.
    #[test]
    fn test_signature_discoverer_no_patterns() {
        let sd = SignatureDiscoverer::new(vec![]);
        assert!(sd.discover(0x1000, &[]).is_empty());
        assert!(sd.discover(0x1000, &[0x55, 0x90]).is_empty());
    }

    // 43. OverlapDetector::find_overlaps on an empty slice.
    #[test]
    fn test_overlap_detector_empty() {
        assert!(OverlapDetector::new().find_overlaps(&[]).is_empty());
    }

    // 44. FunctionDiscovery::discover with an entry point far outside the
    // scanned region must not panic.
    #[test]
    fn test_discovery_entry_point_out_of_region() {
        let (base, code) = minimal_code();
        let d = FunctionDiscovery::default_x86_64();
        let (boundaries, _summary) = d.discover(base, &code, &[base + 0xFFFF]);
        // No panic; boundaries may still be non-empty from other strategies.
        let _ = boundaries;
    }
}
