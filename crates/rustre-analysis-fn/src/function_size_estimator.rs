//! Heuristic function-size estimator.
//!
//! Provides fast, lightweight size estimates for function bodies without
//! performing full disassembly.  The estimates are used to pre-allocate data
//! structures, guide gap analysis, and filter obviously-tiny false positives
//! before expensive passes.
//!
//! The module offers three heuristic layers:
//! 1. **Linear scan** — walk bytes looking for the first RET/BX-LR/return-like
//!    opcode, capping at a configurable maximum.
//! 2. **Density heuristic** — count the density of branch/call opcodes in a
//!    sliding window to estimate where a function likely ends.
//! 3. **Alignment heuristic** — assume functions end at the next alignment
//!    boundary (e.g. 16-byte aligned) after the first observed RET-like byte.

use std::collections::HashMap;
use std::fmt;
use rustre_core::address::Address;

// ── Architecture ──────────────────────────────────────────────────────────────

/// Target architecture for the estimator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstimatorArch {
    /// AMD64 / x86-64.
    X86_64,
    /// IA-32 / x86-32.
    X86_32,
    /// `AArch64`.
    Arm64,
}

impl fmt::Display for EstimatorArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86_64 => write!(f, "x86_64"),
            Self::X86_32 => write!(f, "x86_32"),
            Self::Arm64 => write!(f, "arm64"),
        }
    }
}

// ── SizeHeuristic ─────────────────────────────────────────────────────────────

/// Which heuristic was used to produce the size estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeHeuristic {
    /// The first RET-like byte found in a linear scan.
    LinearScan,
    /// Alignment boundary after the first RET-like byte.
    AlignmentBoundary,
    /// Density-based window scan (branch instruction density).
    BranchDensity,
    /// Upper-bound cap was hit (no terminator found in scan range).
    MaxCapHit,
    /// The function body is empty or less than 4 bytes.
    TooSmall,
}

impl fmt::Display for SizeHeuristic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LinearScan => write!(f, "LinearScan"),
            Self::AlignmentBoundary => write!(f, "AlignmentBoundary"),
            Self::BranchDensity => write!(f, "BranchDensity"),
            Self::MaxCapHit => write!(f, "MaxCapHit"),
            Self::TooSmall => write!(f, "TooSmall"),
        }
    }
}

// ── EstimatedSize ─────────────────────────────────────────────────────────────

/// The result of a single size estimation.
#[derive(Debug, Clone)]
pub struct EstimatedSize {
    /// Start address of the function.
    pub start: Address,
    /// Estimated minimum size in bytes.
    pub min_bytes: u64,
    /// Estimated maximum size in bytes (upper bound).
    pub max_bytes: u64,
    /// Best single-point estimate.
    pub best_bytes: u64,
    /// Which heuristic produced this estimate.
    pub heuristic: SizeHeuristic,
    /// Confidence in `[0.0, 1.0]`.
    pub confidence: f32,
}

impl EstimatedSize {
    /// Returns `true` when `min == max` (exact result).
    #[must_use]
    pub const fn is_exact(&self) -> bool {
        self.min_bytes == self.max_bytes
    }

    /// Returns the span as an inclusive range: `[min, max]`.
    #[must_use]
    pub const fn range(&self) -> std::ops::RangeInclusive<u64> {
        self.min_bytes..=self.max_bytes
    }

    /// Compute the midpoint estimate.
    #[must_use]
    pub const fn midpoint(&self) -> u64 {
        // Avoid overflow: compute average without adding both values first.
        self.min_bytes / 2 + self.max_bytes / 2 + (self.min_bytes & self.max_bytes & 1)
    }
}

impl fmt::Display for EstimatedSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#x} size ~{} bytes ({}..{}) via {} conf={:.2}",
            self.start.as_u64(),
            self.best_bytes,
            self.min_bytes,
            self.max_bytes,
            self.heuristic,
            self.confidence
        )
    }
}

// ── Heuristic helpers ─────────────────────────────────────────────────────────

/// Scan `bytes` for the first x86 RET-like byte (`C3`, `CB`, `C2`, `CA`).
/// Returns the offset of the byte after the instruction (i.e. the exclusive end).
#[must_use]
pub fn linear_scan_x86(bytes: &[u8], max_scan: usize) -> Option<usize> {
    let limit = bytes.len().min(max_scan);
    let mut i = 0usize;
    while i < limit {
        match bytes[i] {
            0xC3 | 0xCB | 0xF4 => return Some(i + 1),  // RET/RETF/HLT
            0xC2 | 0xCA => return Some((i + 3).min(bytes.len())),
            0xEB => i += 2,           // JMP rel8 — may be inlined tail call; skip
            0xE9 => i += 5,           // JMP rel32
            0x0F if i + 1 < bytes.len() && bytes[i + 1] == 0x0B => return Some(i + 2), // UD2
            _ => i += 1,
        }
    }
    None
}

/// Scan `bytes` for the first ARM64 RET word (`0xD65F03C0`).
/// Returns the offset of the next instruction after the RET.
#[must_use]
pub fn linear_scan_arm64(bytes: &[u8], max_scan: usize) -> Option<usize> {
    let limit = bytes.len().min(max_scan);
    let mut i = 0usize;
    while i + 3 < limit {
        if !i.is_multiple_of(4) {
            i += 1;
            continue;
        }
        let word = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        match word {
            0xD65F_03C0 | 0xD65F_0BFF | 0xD65F_0FFF => return Some(i + 4),
            _ => {}
        }
        // B unconditional: bits [31:26] == 000101
        if (word >> 26) == 0b00_0101 {
            return Some(i + 4);
        }
        i += 4;
    }
    None
}

/// Find the next alignment boundary at or after `offset` for alignment `align`.
#[must_use]
pub const fn next_alignment(offset: usize, align: usize) -> usize {
    let align = if align < 1 { 1 } else { align };
    // Guard against `offset + align - 1` overflowing.
    offset.saturating_add(align - 1) & !(align - 1)
}

/// Branch-density window scan.
///
/// Slides a window of `window_size` bytes over `bytes` and counts branch /
/// call / ret opcodes.  The window with the highest density is presumed to be
/// the function epilogue.  Returns the approximate end offset.
#[must_use]
pub fn branch_density_scan_x86(bytes: &[u8], window_size: usize, max_scan: usize) -> Option<usize> {
    if bytes.len() < window_size {
        return None;
    }
    let limit = bytes.len().min(max_scan);
    let mut best_density = 0usize;
    let mut best_end = None;
    let windows = limit.saturating_sub(window_size);
    for start in 0..=windows {
        let window = &bytes[start..start + window_size];
        let density: usize = window
            .iter()
            .filter(|&&b| {
                matches!(
                    b,
                    0xC3 | 0xCB | 0xC2 | 0xCA | 0xE8 | 0xE9 | 0xEB | 0x74
                        | 0x75 | 0x7C | 0x7D | 0x7E | 0x7F | 0xFF
                )
            })
            .count();
        if density > best_density {
            best_density = density;
            best_end = Some(start + window_size);
        }
    }
    best_end
}

// ── FunctionSizeEstimator ─────────────────────────────────────────────────────

/// Configuration and entry point for function-size estimation.
pub struct FunctionSizeEstimator {
    /// Target architecture.
    pub arch: EstimatorArch,
    /// Maximum number of bytes to scan for a terminator.
    pub max_scan_bytes: usize,
    /// Code alignment in bytes (used by the alignment heuristic).
    pub alignment: usize,
    /// Window size for the branch-density scan.
    pub density_window: usize,
    /// Whether to enable the alignment heuristic as a fallback.
    pub use_alignment: bool,
    /// Whether to enable the density heuristic as a second fallback.
    pub use_density: bool,
}

impl Default for FunctionSizeEstimator {
    fn default() -> Self {
        Self {
            arch: EstimatorArch::X86_64,
            max_scan_bytes: 4096,
            alignment: 16,
            density_window: 32,
            use_alignment: true,
            use_density: true,
        }
    }
}

impl FunctionSizeEstimator {
    /// Create a new estimator with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the architecture.
    #[must_use]
    pub const fn with_arch(mut self, arch: EstimatorArch) -> Self {
        self.arch = arch;
        self
    }

    /// Set the maximum scan window.
    #[must_use]
    pub const fn with_max_scan(mut self, n: usize) -> Self {
        self.max_scan_bytes = n;
        self
    }

    /// Set the code alignment.
    #[must_use]
    pub const fn with_alignment(mut self, a: usize) -> Self {
        self.alignment = a;
        self
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Estimate the size of a function whose body starts at `start_addr` and
    /// whose raw bytes are given in `bytes` (starting at `start_addr`).
    #[must_use]
    pub fn estimate(&self, start: Address, bytes: &[u8]) -> EstimatedSize {
        if bytes.len() < 4 {
            return EstimatedSize {
                start,
                min_bytes: bytes.len() as u64,
                max_bytes: bytes.len() as u64,
                best_bytes: bytes.len() as u64,
                heuristic: SizeHeuristic::TooSmall,
                confidence: 0.30,
            };
        }

        // Pass 1: linear scan.
        let linear = match self.arch {
            EstimatorArch::X86_64 | EstimatorArch::X86_32 => {
                linear_scan_x86(bytes, self.max_scan_bytes)
            }
            EstimatorArch::Arm64 => linear_scan_arm64(bytes, self.max_scan_bytes),
        };

        if let Some(end_off) = linear {
            let best = end_off as u64;
            // Alignment upper bound.
            let aligned_end = next_alignment(end_off, self.alignment) as u64;
            return EstimatedSize {
                start,
                min_bytes: best,
                max_bytes: aligned_end,
                best_bytes: best,
                heuristic: SizeHeuristic::LinearScan,
                confidence: 0.85,
            };
        }

        // Pass 2: alignment boundary after a partial scan (no full ret found).
        if self.use_alignment {
            let cap = bytes.len().min(self.max_scan_bytes);
            let aligned = next_alignment(cap, self.alignment) as u64;
            // Try density scan for a better inner estimate.
            if self.use_density
                && let Some(density_end) = branch_density_scan_x86(bytes, self.density_window, cap)
            {
                return EstimatedSize {
                    start,
                    min_bytes: density_end as u64,
                    max_bytes: aligned,
                    best_bytes: density_end as u64,
                    heuristic: SizeHeuristic::BranchDensity,
                    confidence: 0.55,
                };
            }
            return EstimatedSize {
                start,
                min_bytes: cap as u64,
                max_bytes: aligned,
                best_bytes: cap as u64,
                heuristic: SizeHeuristic::AlignmentBoundary,
                confidence: 0.40,
            };
        }

        // Pass 3: cap hit.
        let cap = bytes.len().min(self.max_scan_bytes) as u64;
        EstimatedSize {
            start,
            min_bytes: cap,
            max_bytes: cap,
            best_bytes: cap,
            heuristic: SizeHeuristic::MaxCapHit,
            confidence: 0.20,
        }
    }

    /// Batch-estimate sizes for multiple functions.
    ///
    /// `functions` is a map from start address to raw bytes.
    #[must_use]
    pub fn estimate_all(
        &self,
        functions: &HashMap<u64, Vec<u8>>,
    ) -> HashMap<u64, EstimatedSize> {
        functions
            .iter()
            .map(|(&addr, bytes)| {
                let est = self.estimate(Address::new(addr), bytes);
                (addr, est)
            })
            .collect()
    }

    /// Classify an estimate as small/medium/large/huge based on the best-bytes
    /// value and configurable thresholds.
    #[must_use]
    pub const fn classify(estimated: &EstimatedSize) -> FunctionSizeClass {
        match estimated.best_bytes {
            0..=31 => FunctionSizeClass::Tiny,
            32..=127 => FunctionSizeClass::Small,
            128..=511 => FunctionSizeClass::Medium,
            512..=4095 => FunctionSizeClass::Large,
            _ => FunctionSizeClass::Huge,
        }
    }

    /// Filter out all estimates below `min_bytes` as likely false positives.
    #[must_use]
    pub fn filter_too_small(
        estimates: HashMap<u64, EstimatedSize>,
        min_bytes: u64,
    ) -> HashMap<u64, EstimatedSize> {
        estimates
            .into_iter()
            .filter(|(_, e)| e.best_bytes >= min_bytes)
            .collect()
    }

    /// Summarise a batch of estimates.
    #[must_use]
    pub fn summarise(estimates: &HashMap<u64, EstimatedSize>) -> BatchSummary {
        let count = estimates.len();
        if count == 0 {
            return BatchSummary::default();
        }
        let sizes: Vec<u64> = estimates.values().map(|e| e.best_bytes).collect();
        let total: u64 = sizes.iter().sum();
        let mean = total / count as u64;
        let mut sorted = sizes;
        sorted.sort_unstable();
        let median = sorted[count / 2];
        let min = *sorted.first().unwrap_or(&0);
        let max = *sorted.last().unwrap_or(&0);
        BatchSummary {
            count,
            total_bytes: total,
            mean_bytes: mean,
            median_bytes: median,
            min_bytes: min,
            max_bytes: max,
        }
    }
}

// ── FunctionSizeClass ─────────────────────────────────────────────────────────

/// Broad size category for a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionSizeClass {
    /// 0–31 bytes.
    Tiny,
    /// 32–127 bytes.
    Small,
    /// 128–511 bytes.
    Medium,
    /// 512–4095 bytes.
    Large,
    /// ≥ 4096 bytes.
    Huge,
}

impl fmt::Display for FunctionSizeClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tiny => write!(f, "Tiny"),
            Self::Small => write!(f, "Small"),
            Self::Medium => write!(f, "Medium"),
            Self::Large => write!(f, "Large"),
            Self::Huge => write!(f, "Huge"),
        }
    }
}

// ── BatchSummary ──────────────────────────────────────────────────────────────

/// Statistics over a batch of size estimates.
#[derive(Debug, Clone, Default)]
pub struct BatchSummary {
    /// Number of functions.
    pub count: usize,
    /// Total estimated bytes.
    pub total_bytes: u64,
    /// Mean estimated size.
    pub mean_bytes: u64,
    /// Median estimated size.
    pub median_bytes: u64,
    /// Smallest estimate.
    pub min_bytes: u64,
    /// Largest estimate.
    pub max_bytes: u64,
}

impl fmt::Display for BatchSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "count={} total={} mean={} median={} min={} max={}",
            self.count,
            self.total_bytes,
            self.mean_bytes,
            self.median_bytes,
            self.min_bytes,
            self.max_bytes
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn estimator() -> FunctionSizeEstimator {
        FunctionSizeEstimator::new().with_arch(EstimatorArch::X86_64)
    }

    // ── linear_scan_x86 ───────────────────────────────────────────────────────

    #[test]
    fn linear_scan_finds_ret() {
        let bytes = vec![0x55, 0x48, 0x89, 0xE5, 0xC3];
        assert_eq!(linear_scan_x86(&bytes, 32), Some(5));
    }

    #[test]
    fn linear_scan_finds_ud2() {
        let bytes = vec![0x90, 0x0F, 0x0B, 0x90];
        assert_eq!(linear_scan_x86(&bytes, 32), Some(3));
    }

    #[test]
    fn linear_scan_max_cap() {
        // No RET in a 100-byte NOP sled capped at 5 bytes.
        let bytes = vec![0x90u8; 100];
        assert_eq!(linear_scan_x86(&bytes, 5), None);
    }

    #[test]
    fn linear_scan_arm64_ret() {
        let word: u32 = 0xD65F_03C0;
        let bytes = word.to_le_bytes().to_vec();
        assert_eq!(linear_scan_arm64(&bytes, 32), Some(4));
    }

    // ── next_alignment ────────────────────────────────────────────────────────

    #[test]
    fn next_alignment_already_aligned() {
        assert_eq!(next_alignment(16, 16), 16);
    }

    #[test]
    fn next_alignment_partial() {
        assert_eq!(next_alignment(17, 16), 32);
    }

    #[test]
    fn next_alignment_zero() {
        assert_eq!(next_alignment(0, 16), 0);
    }

    // ── FunctionSizeEstimator::estimate ──────────────────────────────────────

    #[test]
    fn estimate_small_function() {
        let bytes = vec![0x55, 0x48, 0x89, 0xE5, 0xC3];
        let est = estimator().estimate(Address::new(0x1000), &bytes);
        assert_eq!(est.best_bytes, 5);
        assert_eq!(est.heuristic, SizeHeuristic::LinearScan);
        assert!(est.confidence > 0.8);
    }

    #[test]
    fn estimate_too_small() {
        let bytes = vec![0x90u8; 3];
        let est = estimator().estimate(Address::new(0x2000), &bytes);
        assert_eq!(est.heuristic, SizeHeuristic::TooSmall);
    }

    #[test]
    fn estimate_no_ret_uses_alignment() {
        let bytes = vec![0x90u8; 64];
        let est = estimator()
            .with_max_scan(32)
            .with_alignment(16)
            .estimate(Address::new(0x3000), &bytes);
        // Should use alignment boundary.
        assert!(matches!(
            est.heuristic,
            SizeHeuristic::AlignmentBoundary | SizeHeuristic::BranchDensity
        ));
    }

    #[test]
    fn estimate_max_cap_hit() {
        let bytes = vec![0x90u8; 100];
        let est = FunctionSizeEstimator {
            use_alignment: false,
            use_density: false,
            ..Default::default()
        }
        .with_max_scan(50)
        .estimate(Address::new(0x4000), &bytes);
        assert_eq!(est.heuristic, SizeHeuristic::MaxCapHit);
    }

    // ── classify ─────────────────────────────────────────────────────────────

    #[test]
    fn classify_tiny() {
        let est = EstimatedSize {
            start: Address::new(0),
            min_bytes: 4,
            max_bytes: 16,
            best_bytes: 10,
            heuristic: SizeHeuristic::LinearScan,
            confidence: 0.9,
        };
        assert_eq!(FunctionSizeEstimator::classify(&est), FunctionSizeClass::Tiny);
    }

    #[test]
    fn classify_large() {
        let est = EstimatedSize {
            start: Address::new(0),
            min_bytes: 512,
            max_bytes: 1024,
            best_bytes: 700,
            heuristic: SizeHeuristic::LinearScan,
            confidence: 0.8,
        };
        assert_eq!(FunctionSizeEstimator::classify(&est), FunctionSizeClass::Large);
    }

    // ── estimate_all ─────────────────────────────────────────────────────────

    #[test]
    fn estimate_all_two_functions() {
        let mut funcs: HashMap<u64, Vec<u8>> = HashMap::new();
        funcs.insert(0x1000, vec![0x55, 0xC3]);
        funcs.insert(0x2000, vec![0x90, 0x90, 0xC3]);
        let ests = estimator().estimate_all(&funcs);
        assert_eq!(ests.len(), 2);
    }

    // ── filter_too_small ─────────────────────────────────────────────────────

    #[test]
    fn filter_too_small_removes_tiny() {
        let mut map: HashMap<u64, EstimatedSize> = HashMap::new();
        map.insert(
            0x1000,
            EstimatedSize {
                start: Address::new(0x1000),
                min_bytes: 2,
                max_bytes: 2,
                best_bytes: 2,
                heuristic: SizeHeuristic::TooSmall,
                confidence: 0.3,
            },
        );
        map.insert(
            0x2000,
            EstimatedSize {
                start: Address::new(0x2000),
                min_bytes: 64,
                max_bytes: 80,
                best_bytes: 64,
                heuristic: SizeHeuristic::LinearScan,
                confidence: 0.9,
            },
        );
        let filtered = FunctionSizeEstimator::filter_too_small(map, 4);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains_key(&0x2000));
    }

    // ── summarise ────────────────────────────────────────────────────────────

    #[test]
    fn summarise_empty() {
        let empty: HashMap<u64, EstimatedSize> = HashMap::new();
        let s = FunctionSizeEstimator::summarise(&empty);
        assert_eq!(s.count, 0);
    }

    #[test]
    fn summarise_three_functions() {
        let mut funcs: HashMap<u64, Vec<u8>> = HashMap::new();
        // 5 bytes each with C3 at position 4.
        funcs.insert(0x1000, vec![0x90, 0x90, 0x90, 0x90, 0xC3]);
        funcs.insert(0x2000, vec![0x90, 0x90, 0x90, 0x90, 0xC3]);
        funcs.insert(0x3000, vec![0x90, 0x90, 0x90, 0x90, 0xC3]);
        let ests = estimator().estimate_all(&funcs);
        let s = FunctionSizeEstimator::summarise(&ests);
        assert_eq!(s.count, 3);
        assert_eq!(s.mean_bytes, 5);
    }

    // ── EstimatedSize helpers ─────────────────────────────────────────────────

    #[test]
    fn estimated_size_is_exact() {
        let e = EstimatedSize {
            start: Address::new(0),
            min_bytes: 10,
            max_bytes: 10,
            best_bytes: 10,
            heuristic: SizeHeuristic::LinearScan,
            confidence: 1.0,
        };
        assert!(e.is_exact());
    }

    #[test]
    fn estimated_size_range() {
        let e = EstimatedSize {
            start: Address::new(0),
            min_bytes: 5,
            max_bytes: 20,
            best_bytes: 10,
            heuristic: SizeHeuristic::AlignmentBoundary,
            confidence: 0.5,
        };
        assert!(e.range().contains(&10));
        assert!(!e.range().contains(&4));
    }

    #[test]
    fn estimated_size_display() {
        let e = EstimatedSize {
            start: Address::new(0x1000),
            min_bytes: 8,
            max_bytes: 16,
            best_bytes: 10,
            heuristic: SizeHeuristic::LinearScan,
            confidence: 0.85,
        };
        let s = e.to_string();
        assert!(s.contains("0x1000"));
        assert!(s.contains("10"));
    }

    #[test]
    fn batch_summary_display() {
        let s = BatchSummary {
            count: 10,
            total_bytes: 500,
            mean_bytes: 50,
            median_bytes: 48,
            min_bytes: 4,
            max_bytes: 200,
        };
        let out = s.to_string();
        assert!(out.contains("count=10"));
    }
}
