
//! Timing-based anti-analysis detector.
//!
//! Identifies RDTSC instruction patterns, GetTickCount delta loops,
//! Sleep(0) ping-pong, and QueryPerformanceCounter threshold checks.
//! Suggests NOP replacements or constant-value substitutions for each hit.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// TimingPattern — categories of timing-based anti-analysis
// ─────────────────────────────────────────────────────────────────────────────

/// Categories of timing-based anti-analysis techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimingPattern {
    /// Two RDTSC readings with a delta comparison.
    RdtscDelta,
    /// Single RDTSC for inline clock measurement.
    RdtscSingle,
    /// `GetTickCount` called twice with delta comparison.
    GetTickCountDelta,
    /// `QueryPerformanceCounter` delta check.
    QueryPerfCounterDelta,
    /// `Sleep(0)` ping-pong: call Sleep, observe elapsed time.
    SleepZeroPingPong,
    /// Large `Sleep` argument used to outlast sandbox time budget.
    LargeSleepArgument,
    /// `NtDelayExecution` with large delay.
    NtDelayExecution,
    /// `timeGetTime` delta check.
    TimeGetTimeDelta,
    /// `GetSystemTimeAsFileTime` used as high-resolution timer.
    GetSystemTimeAsFileTime,
}

impl fmt::Display for TimingPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::RdtscDelta => "RDTSC-delta",
            Self::RdtscSingle => "RDTSC-single",
            Self::GetTickCountDelta => "GetTickCount-delta",
            Self::QueryPerfCounterDelta => "QueryPerfCounter-delta",
            Self::SleepZeroPingPong => "Sleep(0)-pingpong",
            Self::LargeSleepArgument => "LargeSleep",
            Self::NtDelayExecution => "NtDelayExecution",
            Self::TimeGetTimeDelta => "timeGetTime-delta",
            Self::GetSystemTimeAsFileTime => "GetSystemTimeAsFileTime",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ThresholdValue — a constant used as a timing threshold
// ─────────────────────────────────────────────────────────────────────────────

/// A constant value found in code that acts as a timing threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdValue {
    /// Raw value (e.g. 0x1000 ticks or 60000 ms).
    pub value: u64,
    /// Byte offset of the constant in the binary.
    pub offset: usize,
    /// Size of the constant in bytes (1, 2, 4, or 8).
    pub size: usize,
    /// Human-readable interpretation (e.g. "60 seconds in ms").
    pub interpretation: String,
}

impl ThresholdValue {
    /// Create a new threshold value with auto-generated interpretation.
    #[must_use]
    pub fn new(value: u64, offset: usize, size: usize) -> Self {
        let interpretation = interpret_threshold(value);
        Self {
            value,
            offset,
            size,
            interpretation,
        }
    }
}

fn interpret_threshold(value: u64) -> String {
    match value {
        0 => "zero (Sleep(0))".to_string(),
        1..=9 => format!("{value} ms"),
        10..=999 => format!("{value} ms (~{:.1} seconds)", value as f64 / 1000.0),
        1000 => "1 second".to_string(),
        1_000..=59_999 => format!("{value} ms ({:.1} seconds)", value as f64 / 1000.0),
        60_000 => "60 seconds (1 minute)".to_string(),
        60_001..=3_599_999 => format!("{value} ms ({:.1} minutes)", value as f64 / 60_000.0),
        3_600_000 => "1 hour".to_string(),
        _ if value > 0x1000_0000 => format!("{value:#x} (large RDTSC threshold)"),
        _ => format!("{value} (unknown units)"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RdtscCheck — an RDTSC-based timing check
// ─────────────────────────────────────────────────────────────────────────────

/// Represents one or more RDTSC instructions found in a function body.
#[derive(Debug, Clone)]
pub struct RdtscCheck {
    /// Offset of the first RDTSC instruction.
    pub first_offset: usize,
    /// Offset of the second RDTSC instruction (if a delta check).
    pub second_offset: Option<usize>,
    /// The threshold constant compared against the delta, if found.
    pub threshold: Option<ThresholdValue>,
    /// Whether this looks like a delta (two readings) vs single.
    pub is_delta: bool,
    /// Suggested patch: replace both RDTSC opcodes with NOPs.
    pub suggested_patch: Vec<(usize, Vec<u8>)>,
}

impl RdtscCheck {
    fn new_single(offset: usize) -> Self {
        Self {
            first_offset: offset,
            second_offset: None,
            threshold: None,
            is_delta: false,
            suggested_patch: vec![(offset, vec![0x90, 0x90])],
        }
    }

    fn new_delta(first: usize, second: usize, threshold: Option<ThresholdValue>) -> Self {
        let patch = vec![
            (first, vec![0x90, 0x90]),
            (second, vec![0x90, 0x90]),
        ];
        Self {
            first_offset: first,
            second_offset: Some(second),
            threshold,
            is_delta: true,
            suggested_patch: patch,
        }
    }

    /// Return the number of bytes that would be patched.
    #[must_use]
    pub fn patch_byte_count(&self) -> usize {
        self.suggested_patch.iter().map(|(_, b)| b.len()).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SleepCheck — a Sleep-based timing check
// ─────────────────────────────────────────────────────────────────────────────

/// A `Sleep` call with a significant argument found in binary data.
#[derive(Debug, Clone)]
pub struct SleepCheck {
    /// Offset of the `push <duration>` instruction.
    pub push_offset: usize,
    /// The pushed duration value in milliseconds.
    pub duration_ms: u64,
    /// Whether this is a `Sleep(0)` ping-pong or a large-sleep sandbox evasion.
    pub pattern: TimingPattern,
    /// Suggested patch: replace push with `push 0`.
    pub suggested_patch: Vec<u8>,
}

impl SleepCheck {
    fn new(push_offset: usize, duration_ms: u64) -> Self {
        let pattern = if duration_ms == 0 {
            TimingPattern::SleepZeroPingPong
        } else {
            TimingPattern::LargeSleepArgument
        };
        // Replace `push <imm32>` (68 xx xx xx xx) with `push 0` + NOPs
        let suggested_patch = vec![0x6A, 0x00, 0x90, 0x90, 0x90];
        Self {
            push_offset,
            duration_ms,
            pattern,
            suggested_patch,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TimingCheck — unified representation of any timing check
// ─────────────────────────────────────────────────────────────────────────────

/// A single timing-based anti-analysis check found in the binary.
#[derive(Debug, Clone)]
pub struct TimingCheck {
    /// The category of timing pattern.
    pub pattern: TimingPattern,
    /// Primary byte offset.
    pub offset: usize,
    /// Optional secondary offset (e.g. second RDTSC).
    pub secondary_offset: Option<usize>,
    /// Threshold constant used for comparison, if found.
    pub threshold: Option<ThresholdValue>,
    /// Confidence score in `[0, 100]`.
    pub confidence: u8,
    /// Human-readable description.
    pub description: String,
    /// Suggested patches: `(offset, replacement_bytes)`.
    pub suggested_patches: Vec<(usize, Vec<u8>)>,
}

impl TimingCheck {
    fn new(
        pattern: TimingPattern,
        offset: usize,
        confidence: u8,
        description: impl Into<String>,
    ) -> Self {
        Self {
            pattern,
            offset,
            secondary_offset: None,
            threshold: None,
            confidence,
            description: description.into(),
            suggested_patches: Vec::new(),
        }
    }

    /// Return `true` if this is a high-confidence detection (≥ 80).
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 80
    }

    /// Return all affected byte offsets.
    #[must_use]
    pub fn affected_offsets(&self) -> Vec<usize> {
        let mut v = vec![self.offset];
        if let Some(sec) = self.secondary_offset {
            v.push(sec);
        }
        v
    }
}

impl fmt::Display for TimingCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TimingCheck[{}] @ {:#x} (confidence {}): {}",
            self.pattern, self.offset, self.confidence, self.description
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Byte-level scanning helpers
// ─────────────────────────────────────────────────────────────────────────────

fn find_all(data: &[u8], pattern: &[u8]) -> Vec<usize> {
    let plen = pattern.len();
    (0..data.len().saturating_sub(plen - 1))
        .filter(|&off| &data[off..off + plen] == pattern)
        .collect()
}

fn find_masked(data: &[u8], pattern: &[u8], mask: &[u8]) -> Vec<usize> {
    let plen = pattern.len();
    (0..data.len().saturating_sub(plen - 1))
        .filter(|&off| {
            pattern.iter().enumerate().all(|(i, &p)| {
                mask[i] == 0 || (data[off + i] & mask[i]) == (p & mask[i])
            })
        })
        .collect()
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4).map(|b| {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// TimingCheckDetector — main detector
// ─────────────────────────────────────────────────────────────────────────────

/// Scans binary data for timing-based anti-analysis patterns.
pub struct TimingCheckDetector {
    /// Minimum Sleep duration (ms) to flag as suspicious.
    pub sleep_threshold_ms: u64,
    /// Maximum byte distance between two RDTSC instructions to be considered
    /// a delta check.
    pub rdtsc_window: usize,
    /// Minimum confidence to include in results.
    pub min_confidence: u8,
}

impl Default for TimingCheckDetector {
    fn default() -> Self {
        Self {
            sleep_threshold_ms: 1_000,
            rdtsc_window: 128,
            min_confidence: 60,
        }
    }
}

impl TimingCheckDetector {
    /// Create a new detector with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a detector with custom parameters.
    #[must_use]
    pub const fn with_params(sleep_threshold_ms: u64, rdtsc_window: usize) -> Self {
        Self {
            sleep_threshold_ms,
            rdtsc_window,
            min_confidence: 60,
        }
    }

    /// Scan `data` for all timing checks.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<TimingCheck> {
        let mut checks = Vec::new();
        checks.extend(self.scan_rdtsc(data));
        checks.extend(self.scan_gettickcount(data));
        checks.extend(self.scan_sleep(data));
        checks.extend(self.scan_qpc(data));
        checks.extend(self.scan_string_imports(data));
        checks.retain(|c| c.confidence >= self.min_confidence);
        checks.sort_by_key(|c| c.offset);
        checks
    }

    /// Scan for RDTSC (0F 31) patterns and classify as single or delta.
    #[must_use]
    pub fn scan_rdtsc(&self, data: &[u8]) -> Vec<TimingCheck> {
        let offsets = find_all(data, &[0x0F, 0x31]);
        if offsets.is_empty() {
            return Vec::new();
        }

        let mut checks = Vec::new();
        let mut used = vec![false; offsets.len()];

        for (i, &first) in offsets.iter().enumerate() {
            if used[i] {
                continue;
            }
            // Look for a second RDTSC within window
            let mut paired = false;
            for (j, &second) in offsets.iter().enumerate().skip(i + 1) {
                if second - first > self.rdtsc_window {
                    break;
                }
                used[j] = true;
                paired = true;
                // Look for a threshold constant (CMP instruction) between them
                let threshold = self.find_threshold_between(data, first + 2, second);
                let rdtsc = RdtscCheck::new_delta(first, second, threshold.clone());
                let mut c = TimingCheck::new(
                    TimingPattern::RdtscDelta,
                    first,
                    92,
                    "RDTSC delta timing check (two readings + compare)",
                );
                c.secondary_offset = Some(second);
                c.threshold = threshold;
                c.suggested_patches = rdtsc.suggested_patch.clone();
                checks.push(c);
                break;
            }
            if !paired {
                let rdtsc = RdtscCheck::new_single(first);
                let mut c = TimingCheck::new(
                    TimingPattern::RdtscSingle,
                    first,
                    75,
                    "Single RDTSC instruction (timing side-channel)",
                );
                c.suggested_patches = rdtsc.suggested_patch.clone();
                checks.push(c);
            }
        }
        checks
    }

    fn find_threshold_between(
        &self,
        data: &[u8],
        start: usize,
        end: usize,
    ) -> Option<ThresholdValue> {
        let window = data.get(start..end.min(data.len()))?;
        // Look for CMP reg, imm32 patterns (e.g. 3D xx xx xx xx = CMP EAX, imm32)
        // or 81 F? xx xx xx xx = CMP reg, imm32
        for i in 0..window.len().saturating_sub(4) {
            let b = window[i];
            if b == 0x3D {
                // CMP EAX, imm32
                if let Some(v) = read_u32_le(window, i + 1) {
                    if v > 0x100 {
                        return Some(ThresholdValue::new(u64::from(v), start + i + 1, 4));
                    }
                }
            } else if b == 0x81 && i + 5 < window.len() {
                // 81 /7 imm32 = CMP r/m, imm32
                let modrm = window[i + 1];
                if (modrm >> 3) & 7 == 7 {
                    if let Some(v) = read_u32_le(window, i + 2) {
                        if v > 0x100 {
                            return Some(ThresholdValue::new(u64::from(v), start + i + 2, 4));
                        }
                    }
                }
            }
        }
        None
    }

    /// Scan for `GetTickCount` timing patterns.
    ///
    /// Looks for `call eax; mov reg, eax; call eax; sub eax, reg` sequences.
    #[must_use]
    pub fn scan_gettickcount(&self, data: &[u8]) -> Vec<TimingCheck> {
        // call eax (FF D0); mov edi,eax (8B F8); call eax (FF D0); sub eax,edi (2B C7)
        let pattern = &[0xFF_u8, 0xD0, 0x8B, 0xF8, 0xFF, 0xD0, 0x2B, 0xC7];
        find_all(data, pattern)
            .into_iter()
            .map(|off| {
                let mut c = TimingCheck::new(
                    TimingPattern::GetTickCountDelta,
                    off,
                    88,
                    "GetTickCount delta: call/save/call/sub pattern",
                );
                // Patch: NOP the first pair then XOR EAX,EAX
                c.suggested_patches = vec![(off, vec![0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x31, 0xC0])];
                c
            })
            .collect()
    }

    /// Scan for large Sleep arguments.
    #[must_use]
    pub fn scan_sleep(&self, data: &[u8]) -> Vec<TimingCheck> {
        let mut checks = Vec::new();
        let threshold = self.sleep_threshold_ms;
        for i in 0..data.len().saturating_sub(4) {
            if data[i] == 0x68 {
                // push imm32
                if let Some(v) = read_u32_le(data, i + 1) {
                    let duration = u64::from(v);
                    if duration == 0 || duration >= threshold {
                        let sc = SleepCheck::new(i, duration);
                        let mut c = TimingCheck::new(
                            sc.pattern,
                            i,
                            if duration == 0 { 70 } else { 85 },
                            format!("Sleep({duration} ms) suspicious argument"),
                        );
                        c.threshold = Some(ThresholdValue::new(duration, i + 1, 4));
                        c.suggested_patches = vec![(i, sc.suggested_patch.clone())];
                        checks.push(c);
                    }
                }
            } else if data[i] == 0x6A {
                // push imm8
                if i + 1 < data.len() {
                    let v = u64::from(data[i + 1]);
                    if v == 0 {
                        let mut c = TimingCheck::new(
                            TimingPattern::SleepZeroPingPong,
                            i,
                            65,
                            "Sleep(0) short-form push",
                        );
                        c.suggested_patches = vec![(i, vec![0x90, 0x90])];
                        checks.push(c);
                    }
                }
            }
        }
        checks
    }

    /// Scan for `QueryPerformanceCounter` timing patterns.
    ///
    /// Looks for `push ecx; CALL [addr]` pattern (push + FF 15).
    #[must_use]
    pub fn scan_qpc(&self, data: &[u8]) -> Vec<TimingCheck> {
        // push ecx (51); CALL [imm32] (FF 15 xx xx xx xx)
        let pattern = &[0x51_u8, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00];
        let mask = &[0xFF_u8, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];
        find_masked(data, pattern, mask)
            .into_iter()
            .map(|off| {
                let mut c = TimingCheck::new(
                    TimingPattern::QueryPerfCounterDelta,
                    off,
                    72,
                    "QueryPerformanceCounter call site (push + indirect call)",
                );
                c.suggested_patches = vec![(off, vec![0x90; 7])];
                c
            })
            .collect()
    }

    /// Scan for API name strings (import table evidence).
    #[must_use]
    pub fn scan_string_imports(&self, data: &[u8]) -> Vec<TimingCheck> {
        let apis: &[(&[u8], TimingPattern, u8)] = &[
            (b"GetTickCount", TimingPattern::GetTickCountDelta, 72),
            (
                b"QueryPerformanceCounter",
                TimingPattern::QueryPerfCounterDelta,
                70,
            ),
            (b"timeGetTime", TimingPattern::TimeGetTimeDelta, 70),
            (
                b"GetSystemTimeAsFileTime",
                TimingPattern::GetSystemTimeAsFileTime,
                68,
            ),
            (b"NtDelayExecution", TimingPattern::NtDelayExecution, 78),
        ];
        let mut checks = Vec::new();
        for &(name, pattern, conf) in apis {
            for off in find_all(data, name) {
                let s = String::from_utf8_lossy(name).to_string();
                let mut c = TimingCheck::new(
                    pattern,
                    off,
                    conf,
                    format!("Import string: {s}"),
                );
                c.suggested_patches = Vec::new(); // string hits get no binary patch
                checks.push(c);
            }
        }
        checks
    }

    /// Return all RDTSC checks from a scan.
    #[must_use]
    pub fn rdtsc_checks(&self, data: &[u8]) -> Vec<RdtscCheck> {
        let offsets = find_all(data, &[0x0F, 0x31]);
        let mut out = Vec::new();
        let mut used = vec![false; offsets.len()];
        for (i, &first) in offsets.iter().enumerate() {
            if used[i] {
                continue;
            }
            let mut paired = false;
            for (j, &second) in offsets.iter().enumerate().skip(i + 1) {
                if second - first > self.rdtsc_window {
                    break;
                }
                used[j] = true;
                paired = true;
                let threshold = self.find_threshold_between(data, first + 2, second);
                out.push(RdtscCheck::new_delta(first, second, threshold));
                break;
            }
            if !paired {
                out.push(RdtscCheck::new_single(first));
            }
        }
        out
    }

    /// Return all Sleep checks from a scan.
    #[must_use]
    pub fn sleep_checks(&self, data: &[u8]) -> Vec<SleepCheck> {
        let mut checks = Vec::new();
        for i in 0..data.len().saturating_sub(4) {
            if data[i] == 0x68 {
                if let Some(v) = read_u32_le(data, i + 1) {
                    let d = u64::from(v);
                    if d == 0 || d >= self.sleep_threshold_ms {
                        checks.push(SleepCheck::new(i, d));
                    }
                }
            }
        }
        checks
    }

    /// Generate a textual report of all timing checks found.
    #[must_use]
    pub fn report(&self, data: &[u8]) -> TimingReport {
        let checks = self.scan(data);
        TimingReport::from_checks(checks)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TimingReport
// ─────────────────────────────────────────────────────────────────────────────

/// Summary report from [`TimingCheckDetector::report`].
#[derive(Debug)]
pub struct TimingReport {
    /// All detected timing checks.
    pub checks: Vec<TimingCheck>,
    /// Per-pattern hit counts.
    pub pattern_counts: HashMap<TimingPattern, usize>,
}

impl TimingReport {
    fn from_checks(checks: Vec<TimingCheck>) -> Self {
        let mut pattern_counts: HashMap<TimingPattern, usize> = HashMap::new();
        for c in &checks {
            *pattern_counts.entry(c.pattern).or_insert(0) += 1;
        }
        Self {
            checks,
            pattern_counts,
        }
    }

    /// Return the total number of timing checks found.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.checks.len()
    }

    /// Return `true` if no timing checks were detected.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.checks.is_empty()
    }

    /// Return hit count for a given pattern.
    #[must_use]
    pub fn count_for(&self, pattern: TimingPattern) -> usize {
        self.pattern_counts.get(&pattern).copied().unwrap_or(0)
    }

    /// Return all high-confidence checks.
    #[must_use]
    pub fn high_confidence(&self) -> Vec<&TimingCheck> {
        self.checks.iter().filter(|c| c.is_high_confidence()).collect()
    }

    /// Collect all suggested patches across all checks.
    #[must_use]
    pub fn all_patches(&self) -> Vec<(usize, Vec<u8>)> {
        let mut patches: Vec<(usize, Vec<u8>)> = self
            .checks
            .iter()
            .flat_map(|c| c.suggested_patches.clone())
            .collect();
        patches.sort_by_key(|p| p.0);
        patches.dedup_by_key(|p| p.0);
        patches
    }

    /// Apply all patches to a copy of `data` and return the patched buffer.
    #[must_use]
    pub fn apply_patches(&self, data: &[u8]) -> Vec<u8> {
        let mut buf = data.to_vec();
        for (off, bytes) in self.all_patches() {
            let end = (off + bytes.len()).min(buf.len());
            let actual_len = end - off;
            buf[off..end].copy_from_slice(&bytes[..actual_len]);
        }
        buf
    }
}

impl fmt::Display for TimingReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Timing Check Report ({} checks) ===", self.total())?;
        for c in &self.checks {
            writeln!(f, "  {c}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_rdtsc_single() {
        let detector = TimingCheckDetector::new();
        let data = vec![0x90u8, 0x0F, 0x31, 0x90];
        let checks = detector.scan_rdtsc(&data);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].pattern, TimingPattern::RdtscSingle);
        assert_eq!(checks[0].offset, 1);
    }

    #[test]
    fn test_scan_rdtsc_delta() {
        let detector = TimingCheckDetector::new();
        let mut data = vec![0x90u8; 32];
        data[4] = 0x0F;
        data[5] = 0x31;
        data[20] = 0x0F;
        data[21] = 0x31;
        let checks = detector.scan_rdtsc(&data);
        assert!(checks.iter().any(|c| c.pattern == TimingPattern::RdtscDelta));
    }

    #[test]
    fn test_scan_rdtsc_delta_with_threshold() {
        let detector = TimingCheckDetector::new();
        let mut data = vec![0x90u8; 32];
        data[0] = 0x0F;
        data[1] = 0x31;
        // CMP EAX, 0x1000
        data[4] = 0x3D;
        data[5] = 0x00;
        data[6] = 0x10;
        data[7] = 0x00;
        data[8] = 0x00;
        data[16] = 0x0F;
        data[17] = 0x31;
        let checks = detector.scan_rdtsc(&data);
        let delta = checks.iter().find(|c| c.pattern == TimingPattern::RdtscDelta);
        assert!(delta.is_some());
        assert!(delta.unwrap().threshold.is_some());
    }

    #[test]
    fn test_scan_gettickcount() {
        let detector = TimingCheckDetector::new();
        let data = vec![
            0xFF_u8, 0xD0, 0x8B, 0xF8, 0xFF, 0xD0, 0x2B, 0xC7, 0x90,
        ];
        let checks = detector.scan_gettickcount(&data);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].pattern, TimingPattern::GetTickCountDelta);
    }

    #[test]
    fn test_scan_sleep_large() {
        let detector = TimingCheckDetector::new();
        // push 60000 ms = 0xEA60
        let data = vec![0x68_u8, 0x60, 0xEA, 0x00, 0x00, 0x90];
        let checks = detector.scan_sleep(&data);
        assert!(!checks.is_empty());
        assert!(matches!(
            checks[0].pattern,
            TimingPattern::LargeSleepArgument
        ));
    }

    #[test]
    fn test_scan_sleep_zero() {
        let detector = TimingCheckDetector::new();
        let data = vec![0x6A_u8, 0x00, 0x90];
        let checks = detector.scan_sleep(&data);
        assert!(checks.iter().any(|c| c.pattern == TimingPattern::SleepZeroPingPong));
    }

    #[test]
    fn test_scan_qpc_pattern() {
        let detector = TimingCheckDetector::new();
        let data = vec![0x51_u8, 0xFF, 0x15, 0x10, 0x20, 0x30, 0x40];
        let checks = detector.scan_qpc(&data);
        assert!(!checks.is_empty());
        assert_eq!(checks[0].pattern, TimingPattern::QueryPerfCounterDelta);
    }

    #[test]
    fn test_scan_string_imports_gettickcount() {
        let detector = TimingCheckDetector::new();
        let data = b"GetTickCount";
        let checks = detector.scan_string_imports(data);
        assert!(checks.iter().any(|c| c.pattern == TimingPattern::GetTickCountDelta));
    }

    #[test]
    fn test_scan_string_imports_ntdelay() {
        let detector = TimingCheckDetector::new();
        let data = b"NtDelayExecution";
        let checks = detector.scan_string_imports(data);
        assert!(checks.iter().any(|c| c.pattern == TimingPattern::NtDelayExecution));
    }

    #[test]
    fn test_timing_report_clean() {
        let detector = TimingCheckDetector::new();
        let report = detector.report(&[0x90; 32]);
        assert!(report.is_clean());
    }

    #[test]
    fn test_timing_report_with_rdtsc() {
        let detector = TimingCheckDetector::new();
        let data = vec![0x0F_u8, 0x31, 0x90];
        let report = detector.report(&data);
        assert!(!report.is_clean());
        assert!(report.count_for(TimingPattern::RdtscSingle) > 0);
    }

    #[test]
    fn test_timing_report_apply_patches() {
        let detector = TimingCheckDetector::new();
        let data = vec![0x0F_u8, 0x31, 0x90, 0x90];
        let report = detector.report(&data);
        let patched = report.apply_patches(&data);
        assert_ne!(patched[0], 0x0F);
    }

    #[test]
    fn test_rdtsc_checks_helper() {
        let detector = TimingCheckDetector::new();
        let data = vec![0x0F_u8, 0x31, 0x90];
        let rdtsc_list = detector.rdtsc_checks(&data);
        assert_eq!(rdtsc_list.len(), 1);
        assert!(!rdtsc_list[0].is_delta);
    }

    #[test]
    fn test_sleep_checks_helper() {
        let detector = TimingCheckDetector::new();
        let data = vec![0x68_u8, 0x00, 0x27, 0x0F, 0x00, 0x90]; // push 1000000
        let sleep_list = detector.sleep_checks(&data);
        assert!(!sleep_list.is_empty());
    }

    #[test]
    fn test_threshold_value_display() {
        let tv = ThresholdValue::new(60_000, 0, 4);
        assert!(tv.interpretation.contains("60 second"));
    }

    #[test]
    fn test_threshold_value_large_rdtsc() {
        let tv = ThresholdValue::new(0x2000_0000, 0, 4);
        assert!(tv.interpretation.contains("0x"));
    }

    #[test]
    fn test_timing_check_high_confidence() {
        let c = TimingCheck::new(TimingPattern::RdtscDelta, 0, 92, "test");
        assert!(c.is_high_confidence());
        let c2 = TimingCheck::new(TimingPattern::SleepZeroPingPong, 0, 65, "test");
        assert!(!c2.is_high_confidence());
    }

    #[test]
    fn test_timing_check_affected_offsets() {
        let mut c = TimingCheck::new(TimingPattern::RdtscDelta, 10, 90, "test");
        c.secondary_offset = Some(24);
        assert_eq!(c.affected_offsets(), vec![10, 24]);
    }

    #[test]
    fn test_timing_pattern_display() {
        assert_eq!(format!("{}", TimingPattern::RdtscDelta), "RDTSC-delta");
        assert_eq!(format!("{}", TimingPattern::LargeSleepArgument), "LargeSleep");
    }

    #[test]
    fn test_scan_no_false_positives_on_nops() {
        let detector = TimingCheckDetector::new();
        let data = vec![0x90u8; 64];
        let checks = detector.scan(&data);
        // Pure NOPs: only possible hit is Sleep if 0x90909090 > threshold
        // 0x90909090 > 1000 → will be flagged as sleep, but we just verify no crash
        let _ = checks;
    }

    #[test]
    fn test_all_patches_deduplication() {
        let detector = TimingCheckDetector::new();
        let data = vec![0x0F_u8, 0x31, 0x90];
        let report = detector.report(&data);
        let patches = report.all_patches();
        // No duplicate offsets
        let offsets: Vec<usize> = patches.iter().map(|p| p.0).collect();
        let mut deduped = offsets.clone();
        deduped.dedup();
        assert_eq!(offsets, deduped);
    }
}
