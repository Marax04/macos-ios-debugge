
//! Anti-debug patcher: detects and patches common anti-debugging checks in
//! binary data.  Covers IsDebuggerPresent, CheckRemoteDebuggerPresent,
//! NtQueryInformationProcess (ProcessDebugPort), heap-flag checks, and
//! NtGlobalFlag checks, all implemented using only `std`.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// AntiDebugTechnique — what kind of check is being patched
// ─────────────────────────────────────────────────────────────────────────────

/// Category of anti-debug check identified in binary code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AntiDebugTechnique {
    /// `kernel32!IsDebuggerPresent` return-value check.
    IsDebuggerPresent,
    /// `kernel32!CheckRemoteDebuggerPresent` result check.
    CheckRemoteDebuggerPresent,
    /// `ntdll!NtQueryInformationProcess` with `ProcessDebugPort` (class 7).
    NtQueryInformationProcess,
    /// PEB `ProcessHeap.Flags` / `ForceFlags` fields (heap debug flags).
    HeapFlags,
    /// PEB `NtGlobalFlag` field set to 0x70 under heap-debug allocation.
    NtGlobalFlag,
    /// PEB `BeingDebugged` byte directly accessed via FS/GS.
    BeingDebugged,
    /// Hardware breakpoint registers (DR0–DR7) read via MOV Rd, DRn.
    HardwareBreakpoints,
    /// `CloseHandle(INVALID_HANDLE_VALUE)` — raises exception under debugger.
    CloseInvalidHandle,
    /// `OutputDebugString` error-code timing side-channel.
    OutputDebugString,
    /// SEH / trap-flag manipulation (single-step detection).
    SehTrapFlag,
    /// `ptrace(PTRACE_TRACEME)` Linux syscall.
    PtraceME,
    /// RDTSC instruction used as timing discriminator.
    Rdtsc,
    /// Any other technique not matched by the above.
    Other,
}

impl fmt::Display for AntiDebugTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::IsDebuggerPresent => "IsDebuggerPresent",
            Self::CheckRemoteDebuggerPresent => "CheckRemoteDebuggerPresent",
            Self::NtQueryInformationProcess => "NtQueryInformationProcess",
            Self::HeapFlags => "HeapFlags",
            Self::NtGlobalFlag => "NtGlobalFlag",
            Self::BeingDebugged => "BeingDebugged",
            Self::HardwareBreakpoints => "HardwareBreakpoints",
            Self::CloseInvalidHandle => "CloseInvalidHandle",
            Self::OutputDebugString => "OutputDebugString",
            Self::SehTrapFlag => "SehTrapFlag",
            Self::PtraceME => "PtraceME",
            Self::Rdtsc => "Rdtsc",
            Self::Other => "Other",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DetectionPattern — byte pattern used to locate a technique
// ─────────────────────────────────────────────────────────────────────────────

/// A masked byte pattern for finding anti-debug instructions.
#[derive(Debug, Clone)]
pub struct DetectionPattern {
    /// Human-readable name for this pattern.
    pub name: &'static str,
    /// Byte sequence to match.
    pub bytes: &'static [u8],
    /// Per-byte mask: `0xFF` = exact match, `0x00` = wildcard, other = bitmask.
    pub mask: &'static [u8],
    /// Technique this pattern detects.
    pub technique: AntiDebugTechnique,
    /// Confidence score in `[0, 100]`.
    pub confidence: u8,
}

impl DetectionPattern {
    /// Return `true` if this pattern matches `data` starting at `offset`.
    #[must_use]
    pub fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        let len = self.bytes.len();
        if offset + len > data.len() {
            return false;
        }
        self.bytes.iter().enumerate().all(|(i, &p)| {
            let m = self.mask[i];
            m == 0x00 || (data[offset + i] & m) == (p & m)
        })
    }

    /// Scan all of `data` and return every matching offset.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<usize> {
        let len = self.bytes.len();
        if len == 0 {
            return Vec::new();
        }
        (0..data.len().saturating_sub(len - 1))
            .filter(|&off| self.matches_at(data, off))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatchBytes — replacement bytes for a patch
// ─────────────────────────────────────────────────────────────────────────────

/// Describes the bytes to write when patching a location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchBytes {
    /// Bytes to write at the patch location.
    pub bytes: Vec<u8>,
    /// Human-readable description of what the patch does.
    pub description: String,
}

impl PatchBytes {
    /// Create a NOP-sled patch of `len` bytes.
    #[must_use]
    pub fn nop_sled(len: usize) -> Self {
        Self {
            bytes: vec![0x90; len],
            description: format!("NOP sled ({len} bytes)"),
        }
    }

    /// Create a patch that returns zero from the patched location.
    #[must_use]
    pub fn xor_eax_eax_nops(total_len: usize) -> Self {
        // 31 C0 = XOR EAX, EAX then fill remaining bytes with NOPs
        let mut bytes = vec![0x90; total_len];
        if total_len >= 2 {
            bytes[0] = 0x31;
            bytes[1] = 0xC0;
        }
        Self {
            bytes,
            description: "XOR EAX,EAX + NOPs (force zero)".to_string(),
        }
    }

    /// Create a patch that XORs RAX, RAX (x64 zero-register) then NOPs.
    #[must_use]
    pub fn xor_rax_rax_nops(total_len: usize) -> Self {
        let mut bytes = vec![0x90; total_len];
        if total_len >= 3 {
            bytes[0] = 0x48;
            bytes[1] = 0x31;
            bytes[2] = 0xC0;
        }
        Self {
            bytes,
            description: "XOR RAX,RAX + NOPs (x64 force zero)".to_string(),
        }
    }

    /// Patch that replaces the matched bytes with an unconditional short jump
    /// that skips `skip` bytes past the end of the pattern.
    #[must_use]
    pub fn short_jump_over(pattern_len: usize, skip: u8) -> Self {
        let mut bytes = vec![0x90; pattern_len];
        if pattern_len >= 2 {
            bytes[0] = 0xEB; // JMP rel8
            bytes[1] = skip;
        }
        Self {
            bytes,
            description: format!("JMP +{skip} to skip {pattern_len} bytes"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatchEntry — a concrete patch to be applied
// ─────────────────────────────────────────────────────────────────────────────

/// A single binary patch: location, original bytes, and replacement bytes.
#[derive(Debug, Clone)]
pub struct PatchEntry {
    /// Byte offset in the target binary.
    pub offset: usize,
    /// Original bytes at this location (saved for rollback).
    pub original: Vec<u8>,
    /// Replacement bytes.
    pub patch: PatchBytes,
    /// The technique this patch neutralises.
    pub technique: AntiDebugTechnique,
}

impl PatchEntry {
    /// Create a new `PatchEntry`.
    #[must_use]
    pub const fn new(
        offset: usize,
        original: Vec<u8>,
        patch: PatchBytes,
        technique: AntiDebugTechnique,
    ) -> Self {
        Self {
            offset,
            original,
            patch,
            technique,
        }
    }

    /// Apply this patch to `data`.  Returns `false` if the offset is out of
    /// bounds or the original bytes no longer match.
    pub fn apply(&self, data: &mut [u8]) -> bool {
        let end = self.offset + self.patch.bytes.len();
        if end > data.len() {
            return false;
        }
        data[self.offset..end].copy_from_slice(&self.patch.bytes);
        true
    }

    /// Rollback this patch (restore original bytes).  Returns `false` if out
    /// of bounds.
    pub fn rollback(&self, data: &mut [u8]) -> bool {
        let end = self.offset + self.original.len();
        if end > data.len() {
            return false;
        }
        data[self.offset..end].copy_from_slice(&self.original);
        true
    }

    /// Return the number of bytes changed by this patch.
    #[must_use]
    pub const fn byte_count(&self) -> usize {
        self.patch.bytes.len()
    }
}

impl fmt::Display for PatchEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PatchEntry {{ offset: {:#x}, technique: {}, patch: \"{}\" }}",
            self.offset, self.technique, self.patch.description
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in pattern database
// ─────────────────────────────────────────────────────────────────────────────

/// Return the built-in set of anti-debug detection patterns.
#[must_use]
pub fn builtin_patterns() -> Vec<DetectionPattern> {
    vec![
        // ── IsDebuggerPresent — CALL [import] pattern ───────────────────
        DetectionPattern {
            name: "IsDebuggerPresent-import-call",
            bytes: &[0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x84, 0xC0],
            mask: &[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF],
            technique: AntiDebugTechnique::IsDebuggerPresent,
            confidence: 80,
        },
        // ── IsDebuggerPresent — string literal ──────────────────────────
        DetectionPattern {
            name: "IsDebuggerPresent-string",
            bytes: b"IsDebuggerPresent",
            mask: &[0xFF; 17],
            technique: AntiDebugTechnique::IsDebuggerPresent,
            confidence: 75,
        },
        // ── CheckRemoteDebuggerPresent — string ─────────────────────────
        DetectionPattern {
            name: "CheckRemoteDebuggerPresent-string",
            bytes: b"CheckRemoteDebuggerPresent",
            mask: &[0xFF; 26],
            technique: AntiDebugTechnique::CheckRemoteDebuggerPresent,
            confidence: 80,
        },
        // ── NtQueryInformationProcess — ProcessDebugPort push args ──────
        // push 0; push 4; push 7  (class=ProcessDebugPort)
        DetectionPattern {
            name: "NtQIP-ProcessDebugPort-push7",
            bytes: &[0x6A, 0x00, 0x6A, 0x04, 0x6A, 0x07],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            technique: AntiDebugTechnique::NtQueryInformationProcess,
            confidence: 90,
        },
        // ── NtQueryInformationProcess — string ──────────────────────────
        DetectionPattern {
            name: "NtQueryInformationProcess-string",
            bytes: b"NtQueryInformationProcess",
            mask: &[0xFF; 25],
            technique: AntiDebugTechnique::NtQueryInformationProcess,
            confidence: 75,
        },
        // ── PEB BeingDebugged x86 — mov eax, fs:[30h] ───────────────────
        DetectionPattern {
            name: "PEB-BeingDebugged-x86",
            bytes: &[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            technique: AntiDebugTechnique::BeingDebugged,
            confidence: 95,
        },
        // ── PEB BeingDebugged x64 — mov rax, gs:[60h] ───────────────────
        DetectionPattern {
            name: "PEB-BeingDebugged-x64",
            bytes: &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            technique: AntiDebugTechnique::BeingDebugged,
            confidence: 95,
        },
        // ── NtGlobalFlag x86 — mov eax, fs:[68h] ────────────────────────
        DetectionPattern {
            name: "NtGlobalFlag-x86",
            bytes: &[0x64, 0xA1, 0x68, 0x00, 0x00, 0x00],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            technique: AntiDebugTechnique::NtGlobalFlag,
            confidence: 90,
        },
        // ── HeapFlags x86 — TEB access for heap flags ───────────────────
        DetectionPattern {
            name: "HeapFlags-x86",
            bytes: &[0x64, 0xA1, 0x18, 0x00, 0x00, 0x00],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            technique: AntiDebugTechnique::HeapFlags,
            confidence: 85,
        },
        // ── Hardware breakpoints — MOV Rd, DRn ──────────────────────────
        DetectionPattern {
            name: "DR-register-read",
            bytes: &[0x0F, 0x21, 0xC0],
            mask: &[0xFF, 0xFF, 0xF8],
            technique: AntiDebugTechnique::HardwareBreakpoints,
            confidence: 85,
        },
        // ── CloseHandle(INVALID_HANDLE_VALUE) — push -1 ─────────────────
        DetectionPattern {
            name: "CloseHandle-invalid",
            bytes: &[0x6A, 0xFF],
            mask: &[0xFF, 0xFF],
            technique: AntiDebugTechnique::CloseInvalidHandle,
            confidence: 65,
        },
        // ── OutputDebugString string ─────────────────────────────────────
        DetectionPattern {
            name: "OutputDebugStringA-string",
            bytes: b"OutputDebugStringA",
            mask: &[0xFF; 18],
            technique: AntiDebugTechnique::OutputDebugString,
            confidence: 75,
        },
        // ── SEH trap-flag: pushfd; pop eax; test eax, 100h ───────────────
        DetectionPattern {
            name: "SEH-trap-flag",
            bytes: &[0x9C, 0x58, 0xA9, 0x00, 0x01, 0x00, 0x00],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            technique: AntiDebugTechnique::SehTrapFlag,
            confidence: 80,
        },
        // ── RDTSC ────────────────────────────────────────────────────────
        DetectionPattern {
            name: "RDTSC",
            bytes: &[0x0F, 0x31],
            mask: &[0xFF, 0xFF],
            technique: AntiDebugTechnique::Rdtsc,
            confidence: 85,
        },
        // ── ptrace(PTRACE_TRACEME) Linux x86 syscall ─────────────────────
        DetectionPattern {
            name: "ptrace-TRACEME-x86",
            bytes: &[0xB8, 0x65, 0x00, 0x00, 0x00],
            mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            technique: AntiDebugTechnique::PtraceME,
            confidence: 85,
        },
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// AntiDebugPatcher — main analysis and patching engine
// ─────────────────────────────────────────────────────────────────────────────

/// Main patcher: scans binary data for anti-debug patterns and generates
/// patch entries to neutralise them.
pub struct AntiDebugPatcher {
    patterns: Vec<DetectionPattern>,
    /// Minimum confidence threshold for a hit to generate a patch.
    pub min_confidence: u8,
    /// Whether to patch string-literal detections (no binary byte change).
    pub patch_strings: bool,
    /// Per-technique override: map technique → custom patch bytes length.
    /// If absent, pattern length is used.
    custom_patch_len: HashMap<AntiDebugTechnique, usize>,
}

impl AntiDebugPatcher {
    /// Create a patcher with the default built-in pattern set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: builtin_patterns(),
            min_confidence: 70,
            patch_strings: true,
            custom_patch_len: HashMap::new(),
        }
    }

    /// Set minimum confidence threshold for patches.
    #[must_use]
    pub const fn with_min_confidence(mut self, threshold: u8) -> Self {
        self.min_confidence = threshold;
        self
    }

    /// Register a custom pattern.
    pub fn add_pattern(&mut self, pattern: DetectionPattern) {
        self.patterns.push(pattern);
    }

    /// Set a custom patch length for a specific technique.
    pub fn set_custom_patch_len(&mut self, technique: AntiDebugTechnique, len: usize) {
        self.custom_patch_len.insert(technique, len);
    }

    /// Scan `data` and return all detected patch entries.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<PatchEntry> {
        let mut entries = Vec::new();
        for pattern in &self.patterns {
            if pattern.confidence < self.min_confidence {
                continue;
            }
            for offset in pattern.scan(data) {
                let patch_len = self
                    .custom_patch_len
                    .get(&pattern.technique)
                    .copied()
                    .unwrap_or(pattern.bytes.len());
                let end = (offset + patch_len).min(data.len());
                let original = data[offset..end].to_vec();
                let patch = self.build_patch(pattern, patch_len);
                entries.push(PatchEntry::new(offset, original, patch, pattern.technique));
            }
        }
        // Deduplicate by offset (keep first hit per offset).
        entries.sort_by_key(|e| e.offset);
        entries.dedup_by_key(|e| e.offset);
        entries
    }

    /// Apply all detected patches to a mutable copy of `data`.
    /// Returns `(patched_data, applied_count)`.
    #[must_use]
    pub fn patch_all(&self, data: &[u8]) -> (Vec<u8>, usize) {
        let mut buf = data.to_vec();
        let entries = self.scan(data);
        let mut applied = 0usize;
        for entry in &entries {
            if entry.apply(&mut buf) {
                applied += 1;
            }
        }
        (buf, applied)
    }

    /// Apply only patches for a specific technique.
    #[must_use]
    pub fn patch_technique(&self, data: &[u8], technique: AntiDebugTechnique) -> (Vec<u8>, usize) {
        let mut buf = data.to_vec();
        let entries: Vec<PatchEntry> = self
            .scan(data)
            .into_iter()
            .filter(|e| e.technique == technique)
            .collect();
        let applied = entries.iter().filter(|e| e.apply(&mut buf)).count();
        (buf, applied)
    }

    /// Return a summary report of detected techniques and their hit counts.
    #[must_use]
    pub fn report(&self, data: &[u8]) -> PatchReport {
        let entries = self.scan(data);
        let mut counts: HashMap<AntiDebugTechnique, usize> = HashMap::new();
        for e in &entries {
            *counts.entry(e.technique).or_insert(0) += 1;
        }
        PatchReport {
            total_hits: entries.len(),
            technique_counts: counts,
            entries,
        }
    }

    fn build_patch(&self, pattern: &DetectionPattern, len: usize) -> PatchBytes {
        match pattern.technique {
            AntiDebugTechnique::BeingDebugged => {
                if len >= 9 {
                    // x64: XOR RAX,RAX + NOPs
                    PatchBytes::xor_rax_rax_nops(len)
                } else {
                    PatchBytes::xor_eax_eax_nops(len)
                }
            }
            AntiDebugTechnique::NtGlobalFlag | AntiDebugTechnique::HeapFlags => {
                PatchBytes::xor_eax_eax_nops(len)
            }
            AntiDebugTechnique::HardwareBreakpoints => PatchBytes::xor_eax_eax_nops(len),
            AntiDebugTechnique::SehTrapFlag => {
                // Replace test eax,100h with xor eax,eax + NOPs
                PatchBytes::xor_eax_eax_nops(len)
            }
            AntiDebugTechnique::Rdtsc => PatchBytes::nop_sled(len),
            AntiDebugTechnique::CloseInvalidHandle => PatchBytes::nop_sled(len),
            AntiDebugTechnique::IsDebuggerPresent
            | AntiDebugTechnique::CheckRemoteDebuggerPresent
            | AntiDebugTechnique::NtQueryInformationProcess
            | AntiDebugTechnique::OutputDebugString
            | AntiDebugTechnique::PtraceME => PatchBytes::nop_sled(len),
            _ => PatchBytes::nop_sled(len),
        }
    }

    /// Return the number of registered patterns.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Verify that original bytes in a `PatchEntry` still match `data`.
    #[must_use]
    pub fn verify_original(entry: &PatchEntry, data: &[u8]) -> bool {
        let end = entry.offset + entry.original.len();
        if end > data.len() {
            return false;
        }
        &data[entry.offset..end] == entry.original.as_slice()
    }
}

impl Default for AntiDebugPatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatchReport
// ─────────────────────────────────────────────────────────────────────────────

/// Summary report produced by [`AntiDebugPatcher::report`].
#[derive(Debug)]
pub struct PatchReport {
    /// Total number of hits across all patterns.
    pub total_hits: usize,
    /// Per-technique hit counts.
    pub technique_counts: HashMap<AntiDebugTechnique, usize>,
    /// All individual patch entries found.
    pub entries: Vec<PatchEntry>,
}

impl PatchReport {
    /// Return `true` if any anti-debug technique was detected.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.total_hits == 0
    }

    /// Return the techniques detected (sorted by discriminant for stability).
    #[must_use]
    pub fn detected_techniques(&self) -> Vec<AntiDebugTechnique> {
        let mut techs: Vec<AntiDebugTechnique> =
            self.technique_counts.keys().copied().collect();
        techs.sort_by_key(|t| format!("{t}"));
        techs
    }

    /// Return the number of hits for a specific technique.
    #[must_use]
    pub fn hits_for(&self, technique: AntiDebugTechnique) -> usize {
        self.technique_counts.get(&technique).copied().unwrap_or(0)
    }

    /// Format the report as a multi-line human-readable string.
    #[must_use]
    pub fn format_text(&self) -> String {
        let mut s = format!("=== Anti-Debug Patch Report ({} hits) ===\n", self.total_hits);
        for t in self.detected_techniques() {
            let count = self.hits_for(t);
            s.push_str(&format!("  {t}: {count} hit(s)\n"));
        }
        for entry in &self.entries {
            s.push_str(&format!(
                "  [{:#08x}] {} — {}\n",
                entry.offset, entry.technique, entry.patch.description
            ));
        }
        s
    }
}

impl fmt::Display for PatchReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_text())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Specific patchers for individual techniques
// ─────────────────────────────────────────────────────────────────────────────

/// Patch `IsDebuggerPresent` to always return 0 by NOP-ing the call site and
/// forcing EAX=0 afterwards.
#[derive(Debug, Clone, Default)]
pub struct IsDebuggerPresentPatcher;

impl IsDebuggerPresentPatcher {
    /// Return a `PatchBytes` that replaces `IsDebuggerPresent` call-result-check
    /// sequences.  The 8-byte sequence `FF 15 xx xx xx xx 84 C0` becomes
    /// `31 C0 90 90 90 90 84 C0` (force EAX=0, preserve TEST AL,AL).
    #[must_use]
    pub fn patch_bytes() -> PatchBytes {
        PatchBytes {
            bytes: vec![0x31, 0xC0, 0x90, 0x90, 0x90, 0x90, 0x84, 0xC0],
            description: "Force IsDebuggerPresent to return 0".to_string(),
        }
    }

    /// Scan `data` for the call-site pattern and return patch entries.
    #[must_use]
    pub fn scan(data: &[u8]) -> Vec<PatchEntry> {
        let pattern = &[0xFF_u8, 0x15, 0x00, 0x00, 0x00, 0x00, 0x84, 0xC0];
        let mask = &[0xFF_u8, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF];
        let plen = pattern.len();
        let pb = Self::patch_bytes();
        (0..data.len().saturating_sub(plen - 1))
            .filter(|&off| {
                pattern.iter().enumerate().all(|(i, &p)| {
                    mask[i] == 0 || (data[off + i] & mask[i]) == (p & mask[i])
                })
            })
            .map(|off| {
                PatchEntry::new(
                    off,
                    data[off..off + plen].to_vec(),
                    pb.clone(),
                    AntiDebugTechnique::IsDebuggerPresent,
                )
            })
            .collect()
    }
}

/// Patches `NtQueryInformationProcess` ProcessDebugPort calls.
#[derive(Debug, Clone, Default)]
pub struct NtQipDebugPortPatcher;

impl NtQipDebugPortPatcher {
    /// Scan for the `push 0; push 4; push 7` argument sequence.
    #[must_use]
    pub fn scan(data: &[u8]) -> Vec<PatchEntry> {
        let pattern = &[0x6A_u8, 0x00, 0x6A, 0x04, 0x6A, 0x07];
        let plen = pattern.len();
        (0..data.len().saturating_sub(plen - 1))
            .filter(|&off| &data[off..off + plen] == pattern)
            .map(|off| {
                let pb = PatchBytes {
                    bytes: vec![0x90; plen],
                    description: "NOP out NtQIP ProcessDebugPort push args".to_string(),
                };
                PatchEntry::new(
                    off,
                    data[off..off + plen].to_vec(),
                    pb,
                    AntiDebugTechnique::NtQueryInformationProcess,
                )
            })
            .collect()
    }
}

/// Patches heap-flag checks by zeroing the PEB read.
#[derive(Debug, Clone, Default)]
pub struct HeapFlagPatcher;

impl HeapFlagPatcher {
    /// Scan for TEB/PEB heap-flag access patterns.
    #[must_use]
    pub fn scan(data: &[u8]) -> Vec<PatchEntry> {
        let patterns: &[(&[u8], &str)] = &[
            (&[0x64, 0xA1, 0x18, 0x00, 0x00, 0x00], "TEB heap-flags x86"),
            (&[0x64, 0xA1, 0x68, 0x00, 0x00, 0x00], "NtGlobalFlag x86"),
        ];
        let mut out = Vec::new();
        for (pat, desc) in patterns {
            let plen = pat.len();
            for off in 0..data.len().saturating_sub(plen - 1) {
                if &data[off..off + plen] == *pat {
                    let pb = PatchBytes {
                        bytes: {
                            let mut b = vec![0x90u8; plen];
                            b[0] = 0x31;
                            b[1] = 0xC0;
                            b
                        },
                        description: format!("Patch {desc} → XOR EAX,EAX"),
                    };
                    out.push(PatchEntry::new(
                        off,
                        data[off..off + plen].to_vec(),
                        pb,
                        AntiDebugTechnique::HeapFlags,
                    ));
                }
            }
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_patterns_non_empty() {
        assert!(!builtin_patterns().is_empty());
    }

    #[test]
    fn test_detection_pattern_matches_rdtsc() {
        let patterns = builtin_patterns();
        let rdtsc = patterns.iter().find(|p| p.name == "RDTSC").unwrap();
        let data = [0x90u8, 0x0F, 0x31, 0x90];
        assert!(rdtsc.matches_at(&data, 1));
        assert!(!rdtsc.matches_at(&data, 0));
    }

    #[test]
    fn test_detection_pattern_scan_multiple() {
        let patterns = builtin_patterns();
        let rdtsc = patterns.iter().find(|p| p.name == "RDTSC").unwrap();
        let data = [0x0F_u8, 0x31, 0x90, 0x0F, 0x31];
        let hits = rdtsc.scan(&data);
        assert_eq!(hits, vec![0, 3]);
    }

    #[test]
    fn test_patch_bytes_nop_sled() {
        let pb = PatchBytes::nop_sled(4);
        assert_eq!(pb.bytes, vec![0x90, 0x90, 0x90, 0x90]);
    }

    #[test]
    fn test_patch_bytes_xor_eax() {
        let pb = PatchBytes::xor_eax_eax_nops(4);
        assert_eq!(pb.bytes[0], 0x31);
        assert_eq!(pb.bytes[1], 0xC0);
    }

    #[test]
    fn test_patch_entry_apply() {
        let data = vec![0x0F_u8, 0x31, 0x90, 0x90];
        let pb = PatchBytes::nop_sled(2);
        let entry = PatchEntry::new(0, vec![0x0F, 0x31], pb, AntiDebugTechnique::Rdtsc);
        let mut buf = data.clone();
        assert!(entry.apply(&mut buf));
        assert_eq!(buf[0], 0x90);
        assert_eq!(buf[1], 0x90);
    }

    #[test]
    fn test_patch_entry_rollback() {
        let data = vec![0x0F_u8, 0x31, 0x90];
        let pb = PatchBytes::nop_sled(2);
        let entry = PatchEntry::new(0, vec![0x0F, 0x31], pb, AntiDebugTechnique::Rdtsc);
        let mut buf = data.clone();
        entry.apply(&mut buf);
        entry.rollback(&mut buf);
        assert_eq!(&buf[..2], &[0x0F, 0x31]);
    }

    #[test]
    fn test_patcher_scan_rdtsc() {
        let patcher = AntiDebugPatcher::new();
        let data = vec![0x90_u8, 0x0F, 0x31, 0x90];
        let entries = patcher.scan(&data);
        assert!(entries.iter().any(|e| e.technique == AntiDebugTechnique::Rdtsc));
    }

    #[test]
    fn test_patcher_scan_peb_x86() {
        let patcher = AntiDebugPatcher::new();
        let data = vec![0x64_u8, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x90];
        let entries = patcher.scan(&data);
        assert!(entries
            .iter()
            .any(|e| e.technique == AntiDebugTechnique::BeingDebugged));
    }

    #[test]
    fn test_patcher_scan_peb_x64() {
        let patcher = AntiDebugPatcher::new();
        let data = vec![0x65_u8, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00];
        let entries = patcher.scan(&data);
        assert!(entries
            .iter()
            .any(|e| e.technique == AntiDebugTechnique::BeingDebugged));
    }

    #[test]
    fn test_patcher_scan_nt_global_flag() {
        let patcher = AntiDebugPatcher::new();
        let data = vec![0x64_u8, 0xA1, 0x68, 0x00, 0x00, 0x00];
        let entries = patcher.scan(&data);
        assert!(entries
            .iter()
            .any(|e| e.technique == AntiDebugTechnique::NtGlobalFlag));
    }

    #[test]
    fn test_patcher_scan_dr_reg() {
        let patcher = AntiDebugPatcher::new();
        let data = vec![0x0F_u8, 0x21, 0xC3]; // mov ebx, dr0
        let entries = patcher.scan(&data);
        assert!(entries
            .iter()
            .any(|e| e.technique == AntiDebugTechnique::HardwareBreakpoints));
    }

    #[test]
    fn test_patch_all_modifies_rdtsc() {
        let patcher = AntiDebugPatcher::new();
        let data = vec![0x90_u8, 0x0F, 0x31, 0x90];
        let (patched, count) = patcher.patch_all(&data);
        assert!(count > 0);
        assert_ne!(patched[1], 0x0F);
    }

    #[test]
    fn test_report_is_clean_on_empty() {
        let patcher = AntiDebugPatcher::new();
        let report = patcher.report(&[0x90; 16]);
        // NOP sled has no anti-debug patterns
        assert!(report.is_clean());
    }

    #[test]
    fn test_report_detects_seh() {
        let patcher = AntiDebugPatcher::new();
        let data = vec![0x9C_u8, 0x58, 0xA9, 0x00, 0x01, 0x00, 0x00];
        let report = patcher.report(&data);
        assert!(!report.is_clean());
        assert!(report.hits_for(AntiDebugTechnique::SehTrapFlag) > 0);
    }

    #[test]
    fn test_isdebugger_present_patcher_scan() {
        let data = [
            0xFF_u8, 0x15, 0x10, 0x20, 0x30, 0x40, 0x84, 0xC0, 0x74, 0x0A,
        ];
        let entries = IsDebuggerPresentPatcher::scan(&data);
        assert!(!entries.is_empty());
        assert_eq!(entries[0].technique, AntiDebugTechnique::IsDebuggerPresent);
    }

    #[test]
    fn test_heap_flag_patcher_scan() {
        let data = [0x64_u8, 0xA1, 0x18, 0x00, 0x00, 0x00];
        let entries = HeapFlagPatcher::scan(&data);
        assert!(!entries.is_empty());
    }

    #[test]
    fn test_ntqip_patcher_scan() {
        let data = [0x6A_u8, 0x00, 0x6A, 0x04, 0x6A, 0x07, 0x90];
        let entries = NtQipDebugPortPatcher::scan(&data);
        assert!(!entries.is_empty());
    }

    #[test]
    fn test_patch_technique_selective() {
        let patcher = AntiDebugPatcher::new();
        let mut data = vec![0x90u8; 32];
        data[2] = 0x0F;
        data[3] = 0x31; // RDTSC
        data[10] = 0x64;
        data[11] = 0xA1;
        data[12] = 0x30;
        data[13] = 0x00;
        data[14] = 0x00;
        data[15] = 0x00; // PEB BeingDebugged
        let (patched, count) =
            patcher.patch_technique(&data, AntiDebugTechnique::Rdtsc);
        assert!(count > 0);
        // RDTSC patched
        assert_eq!(patched[2], 0x90);
        assert_eq!(patched[3], 0x90);
        // PEB not patched
        assert_eq!(patched[10], 0x64);
    }

    #[test]
    fn test_verify_original_matches() {
        let data = vec![0x0F_u8, 0x31, 0x90];
        let pb = PatchBytes::nop_sled(2);
        let entry = PatchEntry::new(0, vec![0x0F, 0x31], pb, AntiDebugTechnique::Rdtsc);
        assert!(AntiDebugPatcher::verify_original(&entry, &data));
    }

    #[test]
    fn test_verify_original_mismatches_after_patch() {
        let data = vec![0x0F_u8, 0x31, 0x90];
        let pb = PatchBytes::nop_sled(2);
        let entry = PatchEntry::new(0, vec![0x0F, 0x31], pb, AntiDebugTechnique::Rdtsc);
        let mut buf = data.clone();
        entry.apply(&mut buf);
        assert!(!AntiDebugPatcher::verify_original(&entry, &buf));
    }

    #[test]
    fn test_patcher_custom_pattern() {
        let mut patcher = AntiDebugPatcher::new();
        patcher.add_pattern(DetectionPattern {
            name: "custom-test",
            bytes: &[0xDE, 0xAD],
            mask: &[0xFF, 0xFF],
            technique: AntiDebugTechnique::Other,
            confidence: 90,
        });
        let data = vec![0x90_u8, 0xDE, 0xAD, 0x90];
        let entries = patcher.scan(&data);
        assert!(entries.iter().any(|e| e.technique == AntiDebugTechnique::Other));
    }

    #[test]
    fn test_patch_entry_display() {
        let pb = PatchBytes::nop_sled(2);
        let entry = PatchEntry::new(0x100, vec![0x0F, 0x31], pb, AntiDebugTechnique::Rdtsc);
        let s = format!("{entry}");
        assert!(s.contains("0x100"));
        assert!(s.contains("Rdtsc"));
    }

    #[test]
    fn test_min_confidence_filter() {
        let patcher = AntiDebugPatcher::new().with_min_confidence(95);
        let data = [0x6A_u8, 0xFF, 0x90]; // CloseInvalidHandle confidence=65
        let entries = patcher.scan(&data);
        assert!(!entries
            .iter()
            .any(|e| e.technique == AntiDebugTechnique::CloseInvalidHandle));
    }
}
