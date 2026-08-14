//! `timing_attack_neutralizer` — Neutralise timing-based anti-debug checks.
//!
//! Detects and patches timing-based anti-debugging techniques including
//! RDTSC instruction sequences, `GetTickCount`/`QueryPerformanceCounter` delta
//! checks, and `NtQueryPerformanceCounter` patterns.  For each detected check,
//! produces a binary [`NeutralizePatch`] that makes the timing delta appear
//! constant and acceptable.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── TimingCheckKind ───────────────────────────────────────────────────────────

/// Specific timing mechanism used by a detected anti-debug check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TimingCheckKind {
    /// `RDTSC` instruction pair with delta comparison.
    Rdtsc,
    /// `GetTickCount()` delta check.
    GetTickCount,
    /// `QueryPerformanceCounter()` delta check.
    QueryPerformanceCounter,
    /// `NtQueryPerformanceCounter` syscall.
    NtQueryPerformanceCounter,
    /// `timeGetTime()` / multimedia timer delta.
    TimeGetTime,
    /// `GetSystemTimeAsFileTime()` delta.
    GetSystemTimeAsFileTime,
    /// `clock()` POSIX timer.
    Clock,
    /// Generic delay loop with a large constant.
    DelayLoop,
}

impl std::fmt::Display for TimingCheckKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl TimingCheckKind {
    /// Returns `true` for hardware-instruction-level timing (no API call).
    #[must_use]
    pub const fn is_hardware_level(self) -> bool {
        matches!(self, Self::Rdtsc)
    }

    /// Returns `true` for Windows API-based timing.
    #[must_use]
    pub const fn is_windows_api(self) -> bool {
        matches!(
            self,
            Self::GetTickCount
                | Self::QueryPerformanceCounter
                | Self::NtQueryPerformanceCounter
                | Self::TimeGetTime
                | Self::GetSystemTimeAsFileTime
        )
    }
}

// ── TimingCheck ───────────────────────────────────────────────────────────────

/// A detected timing-based anti-debug check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingCheck {
    /// What kind of timer is being used.
    pub kind: TimingCheckKind,
    /// Byte offset of the first timing instruction in the binary.
    pub offset: usize,
    /// Number of bytes the check spans (first read through comparison).
    pub span_bytes: usize,
    /// Confidence in [0, 100].
    pub confidence: u32,
    /// Human-readable description of what was found.
    pub description: String,
    /// Whether the check uses a comparison threshold (vs. just a single read).
    pub has_delta_comparison: bool,
}

impl TimingCheck {
    /// Create a new detection record.
    #[must_use]
    pub fn new(
        kind: TimingCheckKind,
        offset: usize,
        span_bytes: usize,
        confidence: u32,
        description: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            offset,
            span_bytes,
            confidence: confidence.min(100),
            description: description.into(),
            has_delta_comparison: true,
        }
    }

    /// Mark as a single-read (non-delta) check.
    #[must_use]
    pub const fn single_read(mut self) -> Self {
        self.has_delta_comparison = false;
        self
    }

    /// Returns `true` if confidence is ≥ 75.
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 75
    }
}

// ── NeutralizePatch ───────────────────────────────────────────────────────────

/// Strategy to use when patching a timing check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NeutralizeStrategy {
    /// Replace timing instructions with NOPs.
    Nop,
    /// Force the delta to always be zero (XOR result register with itself).
    ZeroDelta,
    /// Force the delta to a small constant (< typical debbuging overhead).
    SmallConstant,
    /// Replace the comparison so the branch is never taken.
    SkipBranch,
}

/// A binary patch that neutralises a detected timing check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeutralizePatch {
    /// The underlying timing check this patch targets.
    pub check: TimingCheck,
    /// Strategy applied.
    pub strategy: NeutralizeStrategy,
    /// Byte offset at which `patch_bytes` should be written.
    pub patch_offset: usize,
    /// Original bytes at that offset (for rollback / verification).
    pub original_bytes: Vec<u8>,
    /// Replacement bytes.
    pub patch_bytes: Vec<u8>,
    /// Human-readable description of what the patch does.
    pub description: String,
}

impl NeutralizePatch {
    /// Create a new neutralize patch.
    #[must_use]
    pub fn new(
        check: TimingCheck,
        strategy: NeutralizeStrategy,
        patch_offset: usize,
        original_bytes: Vec<u8>,
        patch_bytes: Vec<u8>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            check,
            strategy,
            patch_offset,
            original_bytes,
            patch_bytes,
            description: description.into(),
        }
    }

    /// Apply this patch to a binary buffer.  Returns `Ok(())` on success or an
    /// error string if the buffer is too short or original bytes don't match.
    pub fn apply(&self, binary: &mut Vec<u8>) -> Result<(), String> {
        // Guard: original_bytes and patch_bytes must be the same length so that
        // the verification window and the write window are consistent.  A
        // mismatch indicates a corrupted or tampered NeutralizePatch and must
        // be rejected before touching the binary.
        if !self.original_bytes.is_empty()
            && self.original_bytes.len() != self.patch_bytes.len()
        {
            return Err(format!(
                "patch at 0x{:X}: original_bytes length ({}) != patch_bytes length ({}); \
                 refusing to apply",
                self.patch_offset,
                self.original_bytes.len(),
                self.patch_bytes.len(),
            ));
        }
        let end = self.patch_offset + self.patch_bytes.len();
        if end > binary.len() {
            return Err(format!(
                "patch at 0x{:X}: buffer too short ({} < {end})",
                self.patch_offset,
                binary.len()
            ));
        }
        // Verify original bytes.
        if !self.original_bytes.is_empty() {
            let orig_end = self.patch_offset + self.original_bytes.len();
            if orig_end <= binary.len()
                && binary[self.patch_offset..orig_end] != self.original_bytes[..]
            {
                return Err(format!(
                    "patch at 0x{:X}: original bytes mismatch",
                    self.patch_offset
                ));
            }
        }
        binary[self.patch_offset..end].copy_from_slice(&self.patch_bytes);
        Ok(())
    }

    /// Roll back this patch, restoring `original_bytes`.
    pub fn rollback(&self, binary: &mut Vec<u8>) -> Result<(), String> {
        let end = self.patch_offset + self.original_bytes.len();
        if end > binary.len() {
            return Err(format!("rollback at 0x{:X}: buffer too short", self.patch_offset));
        }
        binary[self.patch_offset..end].copy_from_slice(&self.original_bytes);
        Ok(())
    }
}

// ── Signature database ────────────────────────────────────────────────────────

/// A byte-pattern + mask entry for a timing check.
struct TimingPattern {
    kind: TimingCheckKind,
    pattern: &'static [u8],
    mask: &'static [u8],
    confidence: u32,
    description: &'static str,
    patch_bytes: &'static [u8],
    strategy: NeutralizeStrategy,
}

fn timing_patterns() -> Vec<TimingPattern> {
    vec![
        // RDTSC (0F 31)
        TimingPattern {
            kind: TimingCheckKind::Rdtsc,
            pattern: &[0x0F, 0x31],
            mask: &[0xFF, 0xFF],
            confidence: 90,
            description: "RDTSC instruction — read time-stamp counter",
            patch_bytes: &[0x90, 0x90],
            strategy: NeutralizeStrategy::Nop,
        },
        // RDTSC x64 also via RDTSCP (0F 01 F9)
        TimingPattern {
            kind: TimingCheckKind::Rdtsc,
            pattern: &[0x0F, 0x01, 0xF9],
            mask: &[0xFF, 0xFF, 0xFF],
            confidence: 90,
            description: "RDTSCP instruction — serialising TSC read",
            patch_bytes: &[0x90, 0x90, 0x90],
            strategy: NeutralizeStrategy::Nop,
        },
        // GetTickCount delta: call eax; mov edi, eax; call eax; sub eax, edi
        TimingPattern {
            kind: TimingCheckKind::GetTickCount,
            pattern: &[0xFF, 0xD0, 0x8B, 0xF8, 0xFF, 0xD0, 0x2B, 0xC7],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            confidence: 85,
            description: "GetTickCount delta timing check (call/save/call/sub pattern)",
            patch_bytes: &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x31, 0xC0],
            strategy: NeutralizeStrategy::ZeroDelta,
        },
        // RDTSC + delta pattern: 0F 31; 8B D0 (mov edx,eax); 0F 31; 2B C2 (sub eax,edx)
        TimingPattern {
            kind: TimingCheckKind::Rdtsc,
            pattern: &[0x0F, 0x31, 0x8B, 0xD0, 0x0F, 0x31, 0x2B, 0xC2],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            confidence: 95,
            description: "RDTSC delta pattern (rdtsc; mov edx,eax; rdtsc; sub eax,edx)",
            patch_bytes: &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x31, 0xC0],
            strategy: NeutralizeStrategy::ZeroDelta,
        },
        // QueryPerformanceCounter: push ecx; call [addr] — partial match
        TimingPattern {
            kind: TimingCheckKind::QueryPerformanceCounter,
            pattern: &[0x51, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00],
            mask: &[0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
            confidence: 70,
            description: "QueryPerformanceCounter indirect call pattern",
            patch_bytes: &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
            strategy: NeutralizeStrategy::Nop,
        },
        // Large Sleep push (anti-sandbox — often pairs with timing)
        TimingPattern {
            kind: TimingCheckKind::DelayLoop,
            pattern: &[0x68, 0x00, 0x27, 0x09, 0x00], // push 0x92700 (600000 ms)
            mask: &[0xFF, 0x00, 0xFF, 0xFF, 0xFF],
            confidence: 75,
            description: "Large Sleep call — push delay arg > 600000 ms",
            patch_bytes: &[0x6A, 0x00, 0x90, 0x90, 0x90],
            strategy: NeutralizeStrategy::ZeroDelta,
        },
        // NtQueryPerformanceCounter string import
        // (detected as a string search rather than a binary pattern)
        // Handled separately in scan_strings().
    ]
}

// ── TimingAttackNeutralizer ───────────────────────────────────────────────────

/// Scans binary data for timing-based anti-debug patterns and generates
/// [`NeutralizePatch`] instances to defeat them.
pub struct TimingAttackNeutralizer {
    /// Minimum confidence threshold for reporting a detection.
    pub min_confidence: u32,
    /// Whether to include string-based API detections.
    pub scan_api_strings: bool,
}

impl Default for TimingAttackNeutralizer {
    fn default() -> Self {
        Self {
            min_confidence: 70,
            scan_api_strings: true,
        }
    }
}

impl TimingAttackNeutralizer {
    /// Create a new neutralizer with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the minimum confidence threshold.
    #[must_use]
    pub const fn with_min_confidence(mut self, min: u32) -> Self {
        self.min_confidence = min;
        self
    }

    /// Scan `binary` for timing checks and return all detections.
    #[must_use]
    pub fn scan(&self, binary: &[u8]) -> Vec<TimingCheck> {
        let mut checks: Vec<TimingCheck> = Vec::new();

        // Pattern-based scan.
        for tp in &timing_patterns() {
            if tp.confidence < self.min_confidence {
                continue;
            }
            let hits = masked_scan(binary, tp.pattern, tp.mask);
            for offset in hits {
                checks.push(TimingCheck::new(
                    tp.kind,
                    offset,
                    tp.pattern.len(),
                    tp.confidence,
                    tp.description,
                ));
            }
        }

        // String-based API scan.
        if self.scan_api_strings {
            checks.extend(self.scan_api_strings_internal(binary));
        }

        // Sort by offset.
        checks.sort_by_key(|c| c.offset);
        checks
    }

    /// Generate neutralize patches for all detected timing checks in `binary`.
    #[must_use]
    pub fn generate_patches(&self, binary: &[u8]) -> Vec<NeutralizePatch> {
        let checks = self.scan(binary);
        let patterns = timing_patterns();

        let mut patches: Vec<NeutralizePatch> = Vec::new();

        for check in checks {
            // Find a matching pattern entry.
            if let Some(tp) = patterns.iter().find(|tp| {
                tp.kind == check.kind
                    && tp.pattern.len() == check.span_bytes
                    && check.offset + tp.patch_bytes.len() <= binary.len()
            }) {
                let orig_end = check.offset + tp.patch_bytes.len();
                let original_bytes = binary[check.offset..orig_end].to_vec();
                patches.push(NeutralizePatch::new(
                    check.clone(),
                    tp.strategy,
                    check.offset,
                    original_bytes,
                    tp.patch_bytes.to_vec(),
                    format!("neutralised {} at 0x{:X}", check.kind, check.offset),
                ));
            } else {
                // Fallback: NOP the entire span.
                let end = (check.offset + check.span_bytes).min(binary.len());
                let span = end - check.offset;
                if span == 0 {
                    continue;
                }
                let original_bytes = binary[check.offset..end].to_vec();
                let patch_bytes = vec![0x90u8; span];
                patches.push(NeutralizePatch::new(
                    check.clone(),
                    NeutralizeStrategy::Nop,
                    check.offset,
                    original_bytes,
                    patch_bytes,
                    format!("NOP-patched {} at 0x{:X}", check.kind, check.offset),
                ));
            }
        }

        patches
    }

    /// Apply all generated patches to `binary`.
    ///
    /// Returns `(patches_applied, errors)`.
    ///
    /// If any patch fails the binary may already be partially modified.  To
    /// keep the binary in a consistent state we stop at the first failure and
    /// roll back all patches that were already applied.
    pub fn neutralize(&self, binary: &mut Vec<u8>) -> (usize, Vec<String>) {
        let patches = self.generate_patches(binary);
        let mut applied = 0usize;
        let mut errors: Vec<String> = Vec::new();
        for patch in &patches {
            match patch.apply(binary) {
                Ok(()) => applied += 1,
                Err(e) => {
                    // Roll back all previously applied patches so the binary
                    // is not left in a half-patched state.
                    for rollback_patch in patches[..applied].iter().rev() {
                        let _ = rollback_patch.rollback(binary);
                    }
                    applied = 0;
                    errors.push(e);
                    break;
                }
            }
        }
        (applied, errors)
    }

    /// Generate a Frida hook script that spoofs the timer APIs at runtime.
    #[must_use]
    pub fn frida_script(&self, checks: &[TimingCheck]) -> String {
        let mut script =
            String::from("// Frida timing-bypass script — generated by timing_attack_neutralizer\n\n");

        let has = |k: TimingCheckKind| checks.iter().any(|c| c.kind == k);

        if has(TimingCheckKind::GetTickCount) {
            script.push_str(
                "Interceptor.attach(Module.findExportByName(null, 'GetTickCount'), {\n\
                 \tonLeave(retval) { retval.replace(0x1234); }\n\
                 });\n\n",
            );
        }

        if has(TimingCheckKind::QueryPerformanceCounter) {
            script.push_str(
                "Interceptor.attach(Module.findExportByName(null, 'QueryPerformanceCounter'), {\n\
                 \tonLeave(retval) { this.buf && this.buf.writeU64(0x12345678); }\n\
                 \tonEnter(args) { this.buf = args[0]; }\n\
                 });\n\n",
            );
        }

        if has(TimingCheckKind::Rdtsc) {
            script.push_str(
                "// RDTSC: use Frida Stalker to replace RDTSC instructions with constant.\n\
                 // Refer to Stalker.follow with onReceive to intercept 0F 31 opcodes.\n\n",
            );
        }

        if has(TimingCheckKind::TimeGetTime) {
            script.push_str(
                "Interceptor.attach(Module.findExportByName(null, 'timeGetTime'), {\n\
                 \tonLeave(retval) { retval.replace(0x1234); }\n\
                 });\n\n",
            );
        }

        script
    }

    /// Summary statistics for a set of patches.
    #[must_use]
    pub fn patch_summary(patches: &[NeutralizePatch]) -> HashMap<TimingCheckKind, usize> {
        let mut map: HashMap<TimingCheckKind, usize> = HashMap::new();
        for p in patches {
            *map.entry(p.check.kind).or_insert(0) += 1;
        }
        map
    }

    fn scan_api_strings_internal(&self, binary: &[u8]) -> Vec<TimingCheck> {
        let apis: &[(&[u8], TimingCheckKind, &str)] = &[
            (b"GetTickCount", TimingCheckKind::GetTickCount, "GetTickCount import string"),
            (
                b"QueryPerformanceCounter",
                TimingCheckKind::QueryPerformanceCounter,
                "QueryPerformanceCounter import string",
            ),
            (
                b"NtQueryPerformanceCounter",
                TimingCheckKind::NtQueryPerformanceCounter,
                "NtQueryPerformanceCounter import string",
            ),
            (b"timeGetTime", TimingCheckKind::TimeGetTime, "timeGetTime import string"),
            (
                b"GetSystemTimeAsFileTime",
                TimingCheckKind::GetSystemTimeAsFileTime,
                "GetSystemTimeAsFileTime import string",
            ),
        ];

        let mut checks: Vec<TimingCheck> = Vec::new();
        for (sig, kind, desc) in apis {
            let mut pos = 0usize;
            while pos + sig.len() <= binary.len() {
                if &binary[pos..pos + sig.len()] == *sig {
                    let mut c = TimingCheck::new(*kind, pos, sig.len(), 72, *desc);
                    c.has_delta_comparison = false;
                    checks.push(c);
                    pos += sig.len();
                } else {
                    pos += 1;
                }
            }
        }
        checks
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn masked_scan(data: &[u8], pattern: &[u8], mask: &[u8]) -> Vec<usize> {
    let plen = pattern.len();
    if plen == 0 || plen > data.len() {
        return Vec::new();
    }
    let mut offsets = Vec::new();
    let limit = data.len() - plen;
    for pos in 0..=limit {
        let hit = pattern.iter().enumerate().all(|(i, &p)| {
            mask[i] == 0x00 || (data[pos + i] & mask[i]) == (p & mask[i])
        });
        if hit {
            offsets.push(pos);
        }
    }
    offsets
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_rdtsc() {
        let binary = vec![0x90, 0x0F, 0x31, 0x90];
        let neutralizer = TimingAttackNeutralizer::new();
        let checks = neutralizer.scan(&binary);
        assert!(checks.iter().any(|c| c.kind == TimingCheckKind::Rdtsc));
    }

    #[test]
    fn test_scan_rdtscp() {
        let binary = vec![0x0F, 0x01, 0xF9, 0x90];
        let neutralizer = TimingAttackNeutralizer::new();
        let checks = neutralizer.scan(&binary);
        assert!(checks.iter().any(|c| c.kind == TimingCheckKind::Rdtsc));
    }

    #[test]
    fn test_scan_gettickcount_delta() {
        let binary = vec![0xFF, 0xD0, 0x8B, 0xF8, 0xFF, 0xD0, 0x2B, 0xC7];
        let n = TimingAttackNeutralizer::new();
        let checks = n.scan(&binary);
        assert!(checks.iter().any(|c| c.kind == TimingCheckKind::GetTickCount));
    }

    #[test]
    fn test_scan_rdtsc_delta_pattern() {
        let binary = vec![0x0F, 0x31, 0x8B, 0xD0, 0x0F, 0x31, 0x2B, 0xC2];
        let n = TimingAttackNeutralizer::new();
        let checks = n.scan(&binary);
        assert!(checks.iter().any(|c| c.kind == TimingCheckKind::Rdtsc && c.span_bytes == 8));
    }

    #[test]
    fn test_scan_api_string() {
        let binary = b"GetTickCount\x00";
        let n = TimingAttackNeutralizer::new();
        let checks = n.scan(binary);
        assert!(checks.iter().any(|c| c.kind == TimingCheckKind::GetTickCount));
    }

    #[test]
    fn test_scan_no_false_positives_nop_sled() {
        let binary = vec![0x90u8; 32];
        let n = TimingAttackNeutralizer::new();
        let checks = n.scan(&binary);
        assert!(checks.iter().all(|c| c.kind != TimingCheckKind::Rdtsc));
    }

    #[test]
    fn test_generate_patches_rdtsc() {
        let binary = vec![0x90, 0x0F, 0x31, 0x90];
        let n = TimingAttackNeutralizer::new();
        let patches = n.generate_patches(&binary);
        assert!(!patches.is_empty());
        let rdtsc_patch = patches.iter().find(|p| p.check.kind == TimingCheckKind::Rdtsc).unwrap();
        assert_eq!(rdtsc_patch.patch_bytes, vec![0x90, 0x90]);
    }

    #[test]
    fn test_apply_patch() {
        let mut binary = vec![0x90, 0x0F, 0x31, 0x90];
        let n = TimingAttackNeutralizer::new();
        let patches = n.generate_patches(&binary);
        for p in &patches {
            p.apply(&mut binary).unwrap();
        }
        assert_eq!(binary[1], 0x90);
        assert_eq!(binary[2], 0x90);
    }

    #[test]
    fn test_neutralize_modifies_binary() {
        let mut binary = vec![0x90, 0x0F, 0x31, 0x90];
        let n = TimingAttackNeutralizer::new();
        let (applied, errors) = n.neutralize(&mut binary);
        assert!(applied > 0);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_rollback_patch() {
        let orig_binary = vec![0x90, 0x0F, 0x31, 0x90];
        let mut binary = orig_binary.clone();
        let n = TimingAttackNeutralizer::new();
        let patches = n.generate_patches(&binary);
        for p in &patches {
            p.apply(&mut binary).unwrap();
        }
        for p in patches.iter().rev() {
            p.rollback(&mut binary).unwrap();
        }
        assert_eq!(binary, orig_binary);
    }

    #[test]
    fn test_frida_script_gettickcount() {
        let checks = vec![TimingCheck::new(
            TimingCheckKind::GetTickCount,
            0,
            8,
            85,
            "test",
        )];
        let n = TimingAttackNeutralizer::new();
        let script = n.frida_script(&checks);
        assert!(script.contains("GetTickCount"));
        assert!(script.contains("retval.replace"));
    }

    #[test]
    fn test_frida_script_rdtsc() {
        let checks = vec![TimingCheck::new(TimingCheckKind::Rdtsc, 0, 2, 90, "rdtsc")];
        let n = TimingAttackNeutralizer::new();
        let script = n.frida_script(&checks);
        assert!(script.contains("RDTSC"));
    }

    #[test]
    fn test_patch_summary() {
        let binary = vec![0x90, 0x0F, 0x31, 0x90, 0x0F, 0x31, 0x90];
        let n = TimingAttackNeutralizer::new();
        let patches = n.generate_patches(&binary);
        let summary = TimingAttackNeutralizer::patch_summary(&patches);
        assert!(summary.get(&TimingCheckKind::Rdtsc).copied().unwrap_or(0) >= 2);
    }

    #[test]
    fn test_confidence_threshold() {
        let binary = vec![0x0F, 0x31]; // RDTSC — confidence 90
        let n = TimingAttackNeutralizer::new().with_min_confidence(95);
        let checks = n.scan(&binary);
        // RDTSC is 90 confidence, below threshold of 95.
        assert!(checks.iter().all(|c| c.kind != TimingCheckKind::Rdtsc));
    }

    #[test]
    fn test_timing_check_kind_predicates() {
        assert!(TimingCheckKind::Rdtsc.is_hardware_level());
        assert!(!TimingCheckKind::GetTickCount.is_hardware_level());
        assert!(TimingCheckKind::GetTickCount.is_windows_api());
        assert!(!TimingCheckKind::Rdtsc.is_windows_api());
        assert!(!TimingCheckKind::Clock.is_windows_api());
    }

    #[test]
    fn test_neutralize_patch_apply_too_short() {
        let check = TimingCheck::new(TimingCheckKind::Rdtsc, 100, 2, 90, "test");
        let patch = NeutralizePatch::new(
            check,
            NeutralizeStrategy::Nop,
            100,
            vec![0x0F, 0x31],
            vec![0x90, 0x90],
            "test",
        );
        let mut binary = vec![0u8; 10]; // too short
        assert!(patch.apply(&mut binary).is_err());
    }
}
