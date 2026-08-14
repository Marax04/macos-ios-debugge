//! `timing_bypass` — Detect and patch timing-based anti-debug checks.
//!
//! Malware and protected software frequently detect the presence of a debugger
//! by measuring elapsed time between two timer readings and comparing the delta
//! against a threshold.  Common approaches:
//!
//! * [`TimingCheck::Rdtsc`] — `RDTSC` / `RDTSCP` instructions.
//! * [`TimingCheck::GetTickCount`] — Win32 `kernel32!GetTickCount`.
//! * [`TimingCheck::QueryPerformanceCounter`] — Win32 `QueryPerformanceCounter`.
//!
//! This module provides:
//!
//! * [`TimingBypass`] — the main scanner and patcher.
//! * [`TimingPatch`] — patch strategies (NOP, force-zero, constant).
//! * [`TimingBypassReport`] — aggregated results for a binary.

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// TimingCheck — the kind of timer-based check
// ---------------------------------------------------------------------------

/// The category of timing-based anti-debug check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TimingCheck {
    /// `RDTSC` / `RDTSCP` instruction pair: reads the CPU timestamp counter.
    Rdtsc,
    /// `kernel32!GetTickCount` delta check.
    GetTickCount,
    /// `kernel32!QueryPerformanceCounter` delta check.
    QueryPerformanceCounter,
    /// Generic timing loop — detected by a combination of heuristics.
    Generic,
}

impl TimingCheck {
    /// Return a short human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rdtsc => "RDTSC",
            Self::GetTickCount => "GetTickCount",
            Self::QueryPerformanceCounter => "QueryPerformanceCounter",
            Self::Generic => "generic-timing",
        }
    }

    /// Return `true` if this check is based on a CPU instruction (not an API call).
    #[must_use]
    pub const fn is_instruction_based(self) -> bool {
        matches!(self, Self::Rdtsc)
    }
}

impl fmt::Display for TimingCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// TimingPatch — the patch strategy to apply
// ---------------------------------------------------------------------------

/// Strategy for patching out a timing-based check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimingPatch {
    /// Overwrite the check with `0x90` NOP bytes.
    Nop,
    /// Force the return / result register to zero, eliminating any delta.
    ForceZero,
    /// Replace the instruction(s) with a constant-value write so that delta
    /// checks always evaluate to a pre-set benign value.
    Constant(u64),
}

impl TimingPatch {
    /// Return a short label for display.
    #[must_use]
    pub fn label(self) -> String {
        match self {
            Self::Nop => "nop".to_string(),
            Self::ForceZero => "force-zero".to_string(),
            Self::Constant(c) => format!("constant({c:#x})"),
        }
    }
}

impl fmt::Display for TimingPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

// ---------------------------------------------------------------------------
// TimingHit — a single detected occurrence of a timing check
// ---------------------------------------------------------------------------

/// A single detected timing check within a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingHit {
    /// Type of timing check detected.
    pub check: TimingCheck,
    /// Byte offset of the check within the analysed buffer.
    pub offset: usize,
    /// Matched bytes at the detection site.
    pub bytes: Vec<u8>,
    /// Recommended patch strategy.
    pub recommended_patch: TimingPatch,
    /// Patch bytes to apply for the recommended strategy.
    pub patch_bytes: Vec<u8>,
    /// Confidence in `[0, 100]`.
    pub confidence: u32,
    /// Human-readable description.
    pub description: String,
}

impl TimingHit {
    /// Create a new timing hit.
    #[must_use]
    pub fn new(
        check: TimingCheck,
        offset: usize,
        bytes: Vec<u8>,
        recommended_patch: TimingPatch,
        patch_bytes: Vec<u8>,
        confidence: u32,
        description: impl Into<String>,
    ) -> Self {
        Self {
            check,
            offset,
            bytes,
            recommended_patch,
            patch_bytes,
            confidence: confidence.min(100),
            description: description.into(),
        }
    }

    /// Return `true` if confidence is high (≥ 75).
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 75
    }

    /// Return `true` if a binary patch can be applied (non-empty `patch_bytes`).
    #[must_use]
    pub const fn is_patchable(&self) -> bool {
        !self.patch_bytes.is_empty()
    }
}

impl fmt::Display for TimingHit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TimingHit[{}@{:#x}] {} conf={}%",
            self.check, self.offset, self.description, self.confidence
        )
    }
}

// ---------------------------------------------------------------------------
// TimingBypassReport — aggregated results
// ---------------------------------------------------------------------------

/// The complete report produced by [`TimingBypass::scan`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimingBypassReport {
    /// All individual timing hits found.
    pub hits: Vec<TimingHit>,
    /// Total number of patchable hits (non-empty `patch_bytes`).
    pub patchable_count: usize,
    /// Number of RDTSC-based hits.
    pub rdtsc_count: usize,
    /// Number of API-based timing hits (`GetTickCount`, QPC, …).
    pub api_count: usize,
    /// Summary string.
    pub summary: String,
}

impl TimingBypassReport {
    /// Build a report from a list of hits.
    #[must_use]
    pub fn from_hits(hits: Vec<TimingHit>) -> Self {
        let patchable_count = hits.iter().filter(|h| h.is_patchable()).count();
        let rdtsc_count = hits
            .iter()
            .filter(|h| h.check == TimingCheck::Rdtsc)
            .count();
        let api_count = hits
            .iter()
            .filter(|h| {
                matches!(
                    h.check,
                    TimingCheck::GetTickCount | TimingCheck::QueryPerformanceCounter
                )
            })
            .count();
        let summary = format!(
            "{} timing checks found ({} RDTSC, {} API, {} patchable)",
            hits.len(),
            rdtsc_count,
            api_count,
            patchable_count
        );
        Self {
            hits,
            patchable_count,
            rdtsc_count,
            api_count,
            summary,
        }
    }

    /// Return `true` if any timing check was found.
    #[must_use]
    pub const fn has_checks(&self) -> bool {
        !self.hits.is_empty()
    }

    /// Return only high-confidence hits (≥ 75).
    #[must_use]
    pub fn high_confidence_hits(&self) -> Vec<&TimingHit> {
        self.hits
            .iter()
            .filter(|h| h.is_high_confidence())
            .collect()
    }

    /// Return all patchable hits.
    #[must_use]
    pub fn patchable_hits(&self) -> Vec<&TimingHit> {
        self.hits.iter().filter(|h| h.is_patchable()).collect()
    }
}

impl fmt::Display for TimingBypassReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.summary)
    }
}

// ---------------------------------------------------------------------------
// TimingBypass — the main scanner / patcher
// ---------------------------------------------------------------------------

/// Scans binary data for timing-based anti-debug checks and computes patches.
///
/// # Usage
///
/// ```
/// use rustre_deobf_antianti::timing_bypass::TimingBypass;
/// let code = &[0x0F, 0x31_u8]; // RDTSC
/// let report = TimingBypass::new().scan(code);
/// assert!(report.rdtsc_count > 0);
/// ```
#[derive(Debug, Clone, Default)]
pub struct TimingBypass {
    /// When `true`, also scan for API name string literals.
    pub scan_strings: bool,
    /// Minimum confidence threshold (0–100) for including a hit.
    pub min_confidence: u32,
}

impl TimingBypass {
    /// Create a new [`TimingBypass`] with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            scan_strings: true,
            min_confidence: 0,
        }
    }

    /// Set whether to scan for API name string literals.
    #[must_use]
    pub const fn with_string_scan(mut self, enabled: bool) -> Self {
        self.scan_strings = enabled;
        self
    }

    /// Set the minimum confidence threshold.
    #[must_use]
    pub fn with_min_confidence(mut self, min: u32) -> Self {
        self.min_confidence = min.min(100);
        self
    }

    /// Scan `data` for all timing-based anti-debug checks and return a report.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> TimingBypassReport {
        let mut hits = Vec::new();

        // ── RDTSC (0F 31) ────────────────────────────────────────────────────
        self.scan_pattern(
            data,
            &[0x0F, 0x31],
            TimingCheck::Rdtsc,
            TimingPatch::Nop,
            &[0x90, 0x90],
            90,
            "RDTSC instruction",
            &mut hits,
        );

        // ── RDTSCP (0F 01 F9) ────────────────────────────────────────────────
        self.scan_pattern(
            data,
            &[0x0F, 0x01, 0xF9],
            TimingCheck::Rdtsc,
            TimingPatch::ForceZero,
            &[0x31, 0xC0, 0x31, 0xD2], // XOR eax,eax; XOR edx,edx + 1 extra padding byte not needed
            88,
            "RDTSCP instruction",
            &mut hits,
        );

        // ── GetTickCount timing pattern ───────────────────────────────────────
        // call eax (FF D0); mov edi, eax (8B F8); call eax (FF D0); sub eax, edi (2B C7)
        self.scan_pattern(
            data,
            &[0xFF, 0xD0, 0x8B, 0xF8, 0xFF, 0xD0, 0x2B, 0xC7],
            TimingCheck::GetTickCount,
            TimingPatch::ForceZero,
            &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x31, 0xC0],
            85,
            "GetTickCount delta timing check",
            &mut hits,
        );

        // ── QueryPerformanceCounter push/call pattern ─────────────────────────
        // push ecx; call [addr] — indirect call to QPC
        self.scan_pattern(
            data,
            &[0x51, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00],
            TimingCheck::QueryPerformanceCounter,
            TimingPatch::Nop,
            &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
            70,
            "QueryPerformanceCounter call site (push ecx; call [addr])",
            &mut hits,
        );

        // ── RDTSC delta: two RDTSC + sub ─────────────────────────────────────
        // 0F 31 ... 0F 31 ... 29/2B = a classic two-RDTSC delta check.
        self.scan_two_rdtsc_pattern(data, &mut hits);

        // ── String-literal API name hints ─────────────────────────────────────
        if self.scan_strings {
            self.scan_api_strings(data, &mut hits);
        }

        // Filter by minimum confidence.
        let hits: Vec<TimingHit> = hits
            .into_iter()
            .filter(|h| h.confidence >= self.min_confidence)
            .collect();

        TimingBypassReport::from_hits(hits)
    }

    /// Apply all patchable hits from a report to `data`.
    ///
    /// Returns the number of patches applied.
    ///
    /// # Errors
    ///
    /// Returns a `String` error if a patch offset is out of bounds.
    pub fn apply_patches(
        &self,
        data: &mut [u8],
        report: &TimingBypassReport,
    ) -> Result<usize, String> {
        let mut applied = 0;
        for hit in report.patchable_hits() {
            let end = hit.offset + hit.patch_bytes.len();
            if end > data.len() {
                return Err(format!(
                    "patch at offset {:#x} len {} exceeds buffer size {}",
                    hit.offset,
                    hit.patch_bytes.len(),
                    data.len()
                ));
            }
            data[hit.offset..end].copy_from_slice(&hit.patch_bytes);
            applied += 1;
        }
        Ok(applied)
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fn scan_pattern(
        &self,
        data: &[u8],
        pattern: &[u8],
        check: TimingCheck,
        patch_strategy: TimingPatch,
        patch_bytes: &[u8],
        confidence: u32,
        description: &str,
        out: &mut Vec<TimingHit>,
    ) {
        if pattern.len() > data.len() {
            return;
        }
        let mut pos = 0;
        while pos + pattern.len() <= data.len() {
            if &data[pos..pos + pattern.len()] == pattern {
                out.push(TimingHit::new(
                    check,
                    pos,
                    data[pos..pos + pattern.len()].to_vec(),
                    patch_strategy,
                    patch_bytes.to_vec(),
                    confidence,
                    description,
                ));
                pos += pattern.len();
            } else {
                pos += 1;
            }
        }
    }

    /// Detect two RDTSC instructions within 64 bytes of each other (classic delta pattern).
    fn scan_two_rdtsc_pattern(&self, data: &[u8], out: &mut Vec<TimingHit>) {
        if data.len() < 4 {
            return;
        }
        let window = 64usize;
        let mut first_rdtsc: Option<usize> = None;

        let mut i = 0;
        while i + 2 <= data.len() {
            if data[i] == 0x0F && data[i + 1] == 0x31 {
                if let Some(first) = first_rdtsc {
                    if i - first <= window {
                        // Confirm a SUB instruction follows within 8 bytes.
                        let region_end = (i + 10).min(data.len());
                        let region = &data[i..region_end];
                        let has_sub = region.windows(1).any(|w| w[0] == 0x29 || w[0] == 0x2B);
                        let confidence = if has_sub { 92 } else { 75 };
                        out.push(TimingHit::new(
                            TimingCheck::Rdtsc,
                            first,
                            data[first..i + 2].to_vec(),
                            TimingPatch::Nop,
                            vec![0x90; i + 2 - first],
                            confidence,
                            format!("two-RDTSC delta check ({} bytes apart)", i - first),
                        ));
                        first_rdtsc = Some(i);
                    } else {
                        first_rdtsc = Some(i);
                    }
                } else {
                    first_rdtsc = Some(i);
                }
                i += 2;
            } else {
                i += 1;
            }
        }
    }

    fn scan_api_strings(&self, data: &[u8], out: &mut Vec<TimingHit>) {
        let apis: &[(&[u8], TimingCheck, &str)] = &[
            (
                b"GetTickCount",
                TimingCheck::GetTickCount,
                "GetTickCount import string",
            ),
            (
                b"QueryPerformanceCounter",
                TimingCheck::QueryPerformanceCounter,
                "QueryPerformanceCounter import string",
            ),
            (
                b"QueryPerformanceFrequency",
                TimingCheck::QueryPerformanceCounter,
                "QueryPerformanceFrequency import string",
            ),
            (
                b"GetSystemTimeAsFileTime",
                TimingCheck::Generic,
                "GetSystemTimeAsFileTime import string",
            ),
            (
                b"timeGetTime",
                TimingCheck::GetTickCount,
                "timeGetTime import string",
            ),
            (
                b"GetTickCount64",
                TimingCheck::GetTickCount,
                "GetTickCount64 import string",
            ),
        ];
        for (needle, check, desc) in apis {
            let mut pos = 0;
            while pos + needle.len() <= data.len() {
                if &data[pos..pos + needle.len()] == *needle {
                    out.push(TimingHit::new(
                        *check,
                        pos,
                        needle.to_vec(),
                        TimingPatch::ForceZero,
                        vec![], // string-literal hit: no direct byte patch
                        65,
                        *desc,
                    ));
                    pos += needle.len();
                } else {
                    pos += 1;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── TimingCheck ───────────────────────────────────────────────────────────

    #[test]
    fn test_timing_check_names() {
        assert_eq!(TimingCheck::Rdtsc.name(), "RDTSC");
        assert_eq!(TimingCheck::GetTickCount.name(), "GetTickCount");
        assert_eq!(
            TimingCheck::QueryPerformanceCounter.name(),
            "QueryPerformanceCounter"
        );
        assert_eq!(TimingCheck::Generic.name(), "generic-timing");
    }

    #[test]
    fn test_timing_check_instruction_based() {
        assert!(TimingCheck::Rdtsc.is_instruction_based());
        assert!(!TimingCheck::GetTickCount.is_instruction_based());
        assert!(!TimingCheck::QueryPerformanceCounter.is_instruction_based());
    }

    // ── TimingPatch ───────────────────────────────────────────────────────────

    #[test]
    fn test_timing_patch_labels() {
        assert_eq!(TimingPatch::Nop.label(), "nop");
        assert_eq!(TimingPatch::ForceZero.label(), "force-zero");
        assert_eq!(TimingPatch::Constant(0xDEAD).label(), "constant(0xdead)");
    }

    // ── TimingBypass::scan — RDTSC ────────────────────────────────────────────

    #[test]
    fn test_scan_rdtsc_single() {
        let code = &[0x90u8, 0x0F, 0x31, 0x90];
        let report = TimingBypass::new().with_string_scan(false).scan(code);
        assert!(report.rdtsc_count >= 1, "expected RDTSC hit, got: {report}");
        assert!(report.has_checks());
    }

    #[test]
    fn test_scan_rdtsc_multiple() {
        let code = &[0x0Fu8, 0x31, 0x90, 0x0F, 0x31, 0x90];
        let report = TimingBypass::new().with_string_scan(false).scan(code);
        // At minimum 2 single-RDTSC hits.
        assert!(report.rdtsc_count >= 2, "got {}", report.rdtsc_count);
    }

    #[test]
    fn test_scan_gettickcount_pattern() {
        let code = &[0xFFu8, 0xD0, 0x8B, 0xF8, 0xFF, 0xD0, 0x2B, 0xC7];
        let report = TimingBypass::new().with_string_scan(false).scan(code);
        assert!(report.api_count >= 1, "expected API hit, got: {report}");
    }

    #[test]
    fn test_scan_qpc_call_pattern() {
        let code = &[0x51u8, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00];
        let report = TimingBypass::new().with_string_scan(false).scan(code);
        assert!(report.api_count >= 1, "expected QPC hit, got: {report}");
    }

    #[test]
    fn test_scan_api_string_gettickcount() {
        let data = b"GetTickCount";
        let report = TimingBypass::new().with_string_scan(true).scan(data);
        assert!(report.api_count >= 1, "expected string hit, got {report}");
    }

    #[test]
    fn test_scan_no_checks_in_nop_sled() {
        let code = vec![0x90u8; 32];
        let report = TimingBypass::new().with_string_scan(false).scan(&code);
        assert!(!report.has_checks(), "unexpected hits: {report}");
    }

    // ── apply_patches ─────────────────────────────────────────────────────────

    #[test]
    fn test_apply_patches_rdtsc_nop() {
        let mut code = vec![0x90u8, 0x0F, 0x31, 0x90, 0x90];
        let report = TimingBypass::new().with_string_scan(false).scan(&code);
        let applied = TimingBypass::new()
            .apply_patches(&mut code, &report)
            .unwrap();
        assert!(applied > 0, "expected at least one patch");
        // The RDTSC bytes should now be NOPs.
        assert_eq!(code[1], 0x90);
        assert_eq!(code[2], 0x90);
    }

    // ── TimingBypassReport ────────────────────────────────────────────────────

    #[test]
    fn test_report_high_confidence_filter() {
        let mut code = Vec::new();
        code.extend_from_slice(&[0x0F, 0x31]); // RDTSC (conf 90)
        let report = TimingBypass::new().with_string_scan(false).scan(&code);
        let hc = report.high_confidence_hits();
        assert!(!hc.is_empty());
        assert!(hc.iter().all(|h| h.confidence >= 75));
    }

    #[test]
    fn test_report_patchable_count() {
        let code = &[0x0Fu8, 0x31]; // RDTSC with a 2-byte patch
        let report = TimingBypass::new().with_string_scan(false).scan(code);
        assert!(report.patchable_count >= 1, "{report}");
    }
}
