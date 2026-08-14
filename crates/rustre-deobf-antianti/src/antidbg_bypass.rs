//! Anti-debug bypass techniques.
//!
//! Provides [`AntiDebugTechnique`] enum, [`AntiDebugDetector`],
//! [`BypassPatch`], and [`PatchSet`].

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BypassError {
    #[error("binary too short at offset {0:#x}")]
    TooShort(usize),
    #[error("patch conflict at {0:#x}: another patch already covers this range")]
    Conflict(u64),
    #[error("unsupported technique: {0:?}")]
    Unsupported(AntiDebugTechnique),
    #[error("invalid patch data: {0}")]
    InvalidPatch(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// AntiDebugTechnique
// ─────────────────────────────────────────────────────────────────────────────

/// Taxonomy of anti-debugging techniques.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AntiDebugTechnique {
    // ── Windows API checks ───────────────────────────────────────────────────
    IsDebuggerPresent,
    CheckRemoteDebuggerPresent,
    NtQueryInformationProcess,
    DebugBreak,
    OutputDebugString,
    CloseInvalidHandle,
    // ── PEB / heap checks ────────────────────────────────────────────────────
    NtGlobalFlag,
    HeapFlags,
    ProcessHeap,
    BeingDebugged,
    // ── Timing checks ────────────────────────────────────────────────────────
    GetTickCount,
    QueryPerformanceCounter,
    Rdtsc,
    // ── Hardware breakpoint checks ───────────────────────────────────────────
    HardwareBreakpoints,
    // ── Exception-based ──────────────────────────────────────────────────────
    Int3Exception,
    Int1Exception,
    UnhandledExceptionFilter,
    // ── CPUID checks ─────────────────────────────────────────────────────────
    CpuidHypervisorBit,
    CpuidVmString,
    // ── Thread Local Storage ─────────────────────────────────────────────────
    TlsCallback,
    // ── Parent PID checks ────────────────────────────────────────────────────
    ParentPidCheck,
    // ── Self-debugging ───────────────────────────────────────────────────────
    SelfDebugging,
    // ── SeDebugPrivilege ─────────────────────────────────────────────────────
    SeDebugPrivilege,
    // ── Linux-specific ───────────────────────────────────────────────────────
    PtraceTraceme,
    ProcStatusTracerPid,
    // ── macOS-specific ───────────────────────────────────────────────────────
    SysctlKinfoProcFlag,
}

impl AntiDebugTechnique {
    /// Return a human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::IsDebuggerPresent => "IsDebuggerPresent",
            Self::CheckRemoteDebuggerPresent => "CheckRemoteDebuggerPresent",
            Self::NtQueryInformationProcess => "NtQueryInformationProcess",
            Self::DebugBreak => "DebugBreak",
            Self::OutputDebugString => "OutputDebugString",
            Self::CloseInvalidHandle => "CloseInvalidHandle",
            Self::NtGlobalFlag => "NtGlobalFlag",
            Self::HeapFlags => "HeapFlags",
            Self::ProcessHeap => "ProcessHeap",
            Self::BeingDebugged => "BeingDebugged",
            Self::GetTickCount => "GetTickCount",
            Self::QueryPerformanceCounter => "QueryPerformanceCounter",
            Self::Rdtsc => "RDTSC",
            Self::HardwareBreakpoints => "HardwareBreakpoints",
            Self::Int3Exception => "INT3Exception",
            Self::Int1Exception => "INT1Exception",
            Self::UnhandledExceptionFilter => "UnhandledExceptionFilter",
            Self::CpuidHypervisorBit => "CPUID-HypervisorBit",
            Self::CpuidVmString => "CPUID-VmString",
            Self::TlsCallback => "TLSCallback",
            Self::ParentPidCheck => "ParentPidCheck",
            Self::SelfDebugging => "SelfDebugging",
            Self::SeDebugPrivilege => "SeDebugPrivilege",
            Self::PtraceTraceme => "ptrace(TRACEME)",
            Self::ProcStatusTracerPid => "/proc/self/status:TracerPid",
            Self::SysctlKinfoProcFlag => "sysctl(P_TRACED)",
        }
    }

    /// Return `true` if this technique is Windows-specific.
    #[must_use]
    pub const fn is_windows(self) -> bool {
        matches!(
            self,
            Self::IsDebuggerPresent
                | Self::CheckRemoteDebuggerPresent
                | Self::NtQueryInformationProcess
                | Self::DebugBreak
                | Self::OutputDebugString
                | Self::CloseInvalidHandle
                | Self::NtGlobalFlag
                | Self::HeapFlags
                | Self::ProcessHeap
                | Self::BeingDebugged
                | Self::GetTickCount
                | Self::QueryPerformanceCounter
                | Self::HardwareBreakpoints
                | Self::TlsCallback
                | Self::ParentPidCheck
                | Self::SeDebugPrivilege
        )
    }

    /// Return `true` if this technique is Linux-specific.
    #[must_use]
    pub const fn is_linux(self) -> bool {
        matches!(self, Self::PtraceTraceme | Self::ProcStatusTracerPid)
    }

    /// Estimated difficulty to bypass (1=trivial, 5=hard).
    #[must_use]
    pub const fn bypass_difficulty(self) -> u8 {
        match self {
            Self::IsDebuggerPresent | Self::BeingDebugged => 1,
            Self::CheckRemoteDebuggerPresent | Self::NtGlobalFlag => 2,
            Self::HeapFlags | Self::ProcessHeap | Self::GetTickCount => 2,
            Self::NtQueryInformationProcess | Self::HardwareBreakpoints => 3,
            Self::Rdtsc | Self::QueryPerformanceCounter => 3,
            Self::Int3Exception | Self::Int1Exception => 2,
            Self::CpuidHypervisorBit | Self::CpuidVmString => 3,
            Self::TlsCallback | Self::SelfDebugging => 4,
            Self::SeDebugPrivilege => 3,
            _ => 2,
        }
    }
}

impl std::fmt::Display for AntiDebugTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Detection patterns
// ─────────────────────────────────────────────────────────────────────────────

/// A byte pattern used to detect an anti-debug technique.
#[derive(Debug, Clone)]
struct DetectionPattern {
    technique: AntiDebugTechnique,
    /// Byte sequence to scan for.
    bytes: Vec<u8>,
    /// Optional mask (0xFF = must match, 0x00 = wildcard).
    mask: Option<Vec<u8>>,
    /// Human-readable description.
    description: &'static str,
    /// Confidence 0–100.
    confidence: u8,
}

impl DetectionPattern {
    fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        let pat = &self.bytes;
        if offset + pat.len() > data.len() {
            return false;
        }
        let slice = &data[offset..offset + pat.len()];
        match &self.mask {
            Some(mask) => {
                for (i, (&d, &p)) in slice.iter().zip(pat.iter()).enumerate() {
                    let m = mask.get(i).copied().unwrap_or(0xFF);
                    if (d & m) != (p & m) {
                        return false;
                    }
                }
                true
            }
            None => slice == pat.as_slice(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DetectionHit
// ─────────────────────────────────────────────────────────────────────────────

/// A detected anti-debug check in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionHit {
    /// The technique detected.
    pub technique: AntiDebugTechnique,
    /// Virtual address (base + offset).
    pub address: u64,
    /// File offset.
    pub offset: usize,
    /// Confidence 0–100.
    pub confidence: u8,
    /// Description of what was matched.
    pub description: String,
    /// Matched bytes.
    pub matched_bytes: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// AntiDebugDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Scans binary data for anti-debug patterns.
pub struct AntiDebugDetector {
    patterns: Vec<DetectionPattern>,
    base_address: u64,
    min_confidence: u8,
}

impl AntiDebugDetector {
    /// Create a detector with the default pattern set.
    #[must_use]
    pub fn new() -> Self {
        let mut d = Self {
            patterns: Vec::new(),
            base_address: 0,
            min_confidence: 50,
        };
        d.populate();
        d
    }

    pub const fn set_base_address(&mut self, addr: u64) {
        self.base_address = addr;
    }

    pub const fn set_min_confidence(&mut self, c: u8) {
        self.min_confidence = c;
    }

    /// Scan `data` and return all detected hits.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> Vec<DetectionHit> {
        let mut hits = Vec::new();
        for pat in &self.patterns {
            if pat.confidence < self.min_confidence {
                continue;
            }
            for offset in 0..data.len().saturating_sub(pat.bytes.len().saturating_sub(1)) {
                if pat.matches_at(data, offset) {
                    hits.push(DetectionHit {
                        technique: pat.technique,
                        address: self.base_address + offset as u64,
                        offset,
                        confidence: pat.confidence,
                        description: pat.description.to_owned(),
                        matched_bytes: data[offset..offset + pat.bytes.len()].to_vec(),
                    });
                }
            }
        }
        hits.sort_by(|a, b| a.offset.cmp(&b.offset));
        hits
    }

    fn populate(&mut self) {
        // IsDebuggerPresent: CALL [IsDebuggerPresent] stub — look for known IAT call bytes.
        // Simplified: detect the string "IsDebuggerPresent" in import table.
        self.patterns.push(DetectionPattern {
            technique: AntiDebugTechnique::IsDebuggerPresent,
            bytes: b"IsDebuggerPresent".to_vec(),
            mask: None,
            description: "IsDebuggerPresent import string",
            confidence: 80,
        });
        // CheckRemoteDebuggerPresent
        self.patterns.push(DetectionPattern {
            technique: AntiDebugTechnique::CheckRemoteDebuggerPresent,
            bytes: b"CheckRemoteDebuggerPresent".to_vec(),
            mask: None,
            description: "CheckRemoteDebuggerPresent import string",
            confidence: 90,
        });
        // NtQueryInformationProcess
        self.patterns.push(DetectionPattern {
            technique: AntiDebugTechnique::NtQueryInformationProcess,
            bytes: b"NtQueryInformationProcess".to_vec(),
            mask: None,
            description: "NtQueryInformationProcess import string",
            confidence: 75,
        });
        // RDTSC instruction (0F 31)
        self.patterns.push(DetectionPattern {
            technique: AntiDebugTechnique::Rdtsc,
            bytes: vec![0x0F, 0x31],
            mask: None,
            description: "RDTSC instruction",
            confidence: 65,
        });
        // INT3 (0xCC)
        self.patterns.push(DetectionPattern {
            technique: AntiDebugTechnique::Int3Exception,
            bytes: vec![0xCC],
            mask: None,
            description: "INT3 software breakpoint instruction",
            confidence: 55,
        });
        // CPUID with EAX=1 check — look for CPUID (0F A2) followed by EBX shift
        self.patterns.push(DetectionPattern {
            technique: AntiDebugTechnique::CpuidHypervisorBit,
            bytes: vec![0x0F, 0xA2],
            mask: None,
            description: "CPUID instruction (may check hypervisor bit)",
            confidence: 50,
        });
        // PEB BeingDebugged: mov eax, fs:[30h]; movzx eax, byte ptr [eax+2]
        self.patterns.push(DetectionPattern {
            technique: AntiDebugTechnique::BeingDebugged,
            bytes: vec![0x64, 0xA1, 0x30, 0x00, 0x00, 0x00], // mov eax, fs:[30h]
            mask: None,
            description: "Access to PEB via fs:[0x30] (BeingDebugged check)",
            confidence: 75,
        });
        // 64-bit PEB access: mov rax, gs:[60h]
        self.patterns.push(DetectionPattern {
            technique: AntiDebugTechnique::BeingDebugged,
            bytes: vec![0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00],
            mask: None,
            description: "Access to PEB via gs:[0x60] (64-bit BeingDebugged check)",
            confidence: 78,
        });
        // GetTickCount
        self.patterns.push(DetectionPattern {
            technique: AntiDebugTechnique::GetTickCount,
            bytes: b"GetTickCount".to_vec(),
            mask: None,
            description: "GetTickCount timing check import",
            confidence: 70,
        });
        // QueryPerformanceCounter
        self.patterns.push(DetectionPattern {
            technique: AntiDebugTechnique::QueryPerformanceCounter,
            bytes: b"QueryPerformanceCounter".to_vec(),
            mask: None,
            description: "QueryPerformanceCounter timing check import",
            confidence: 70,
        });
        // OutputDebugString
        self.patterns.push(DetectionPattern {
            technique: AntiDebugTechnique::OutputDebugString,
            bytes: b"OutputDebugStringA".to_vec(),
            mask: None,
            description: "OutputDebugStringA — timing side-channel for debugger",
            confidence: 65,
        });
        // TLS callback marker
        self.patterns.push(DetectionPattern {
            technique: AntiDebugTechnique::TlsCallback,
            bytes: b".tls".to_vec(),
            mask: None,
            description: "TLS section name (may contain anti-debug callback)",
            confidence: 55,
        });
        // ptrace(PTRACE_TRACEME, 0, 0, 0) — Linux: syscall 101 / 0x65
        self.patterns.push(DetectionPattern {
            technique: AntiDebugTechnique::PtraceTraceme,
            bytes: b"ptrace".to_vec(),
            mask: None,
            description: "ptrace symbol reference (PTRACE_TRACEME anti-debug)",
            confidence: 70,
        });
        // /proc/self/status
        self.patterns.push(DetectionPattern {
            technique: AntiDebugTechnique::ProcStatusTracerPid,
            bytes: b"/proc/self/status".to_vec(),
            mask: None,
            description: "Read /proc/self/status to check TracerPid",
            confidence: 80,
        });
        // TracerPid string in /proc/self/status scan
        self.patterns.push(DetectionPattern {
            technique: AntiDebugTechnique::ProcStatusTracerPid,
            bytes: b"TracerPid".to_vec(),
            mask: None,
            description: "TracerPid field lookup in /proc/self/status",
            confidence: 85,
        });
        // NtGlobalFlag: check value 0x70
        self.patterns.push(DetectionPattern {
            technique: AntiDebugTechnique::NtGlobalFlag,
            bytes: vec![0x70, 0x00, 0x00, 0x00],
            mask: Some(vec![0xFF, 0x00, 0x00, 0x00]),
            description: "NtGlobalFlag debug value 0x70 byte",
            confidence: 60,
        });
        // DebugBreak import string
        self.patterns.push(DetectionPattern {
            technique: AntiDebugTechnique::DebugBreak,
            bytes: b"DebugBreak".to_vec(),
            mask: None,
            description: "DebugBreak import — raises exception under debugger",
            confidence: 72,
        });
        // SeDebugPrivilege
        self.patterns.push(DetectionPattern {
            technique: AntiDebugTechnique::SeDebugPrivilege,
            bytes: b"SeDebugPrivilege".to_vec(),
            mask: None,
            description: "SeDebugPrivilege string — privilege check",
            confidence: 65,
        });
    }
}

impl Default for AntiDebugDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BypassStrategy
// ─────────────────────────────────────────────────────────────────────────────

/// Strategy to use when generating a bypass patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BypassStrategy {
    /// Replace the check with NOP instructions.
    NopOut,
    /// Force the return value to indicate "not debugging" (e.g. return 0).
    ForceReturnFalse,
    /// Force the return value to indicate "not debugging" (return non-zero for inverse checks).
    ForceReturnTrue,
    /// Replace condition jump with unconditional jump.
    PatchJump,
    /// Inline a stub that always succeeds.
    InlineStub,
}

impl std::fmt::Display for BypassStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NopOut => write!(f, "NopOut"),
            Self::ForceReturnFalse => write!(f, "ForceReturn(false)"),
            Self::ForceReturnTrue => write!(f, "ForceReturn(true)"),
            Self::PatchJump => write!(f, "PatchJump"),
            Self::InlineStub => write!(f, "InlineStub"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BypassPatch
// ─────────────────────────────────────────────────────────────────────────────

/// A concrete patch that bypasses an anti-debug check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassPatch {
    /// Virtual address to patch.
    pub address: u64,
    /// File offset.
    pub offset: usize,
    /// Original bytes (for backup/restoration).
    pub original_bytes: Vec<u8>,
    /// Replacement bytes.
    pub patch_bytes: Vec<u8>,
    /// Strategy used.
    pub strategy: BypassStrategy,
    /// Which technique this patch targets.
    pub technique: AntiDebugTechnique,
    /// Human-readable description.
    pub description: String,
}

impl BypassPatch {
    /// Apply the patch to a mutable byte slice.
    ///
    /// # Errors
    /// Returns [`BypassError::TooShort`] if the slice is too short.
    pub fn apply(&self, data: &mut [u8]) -> Result<(), BypassError> {
        if self.offset + self.patch_bytes.len() > data.len() {
            return Err(BypassError::TooShort(self.offset));
        }
        data[self.offset..self.offset + self.patch_bytes.len()].copy_from_slice(&self.patch_bytes);
        Ok(())
    }

    /// Revert the patch (restore original bytes).
    ///
    /// # Errors
    /// Returns [`BypassError::TooShort`] if the slice is too short.
    pub fn revert(&self, data: &mut [u8]) -> Result<(), BypassError> {
        if self.offset + self.original_bytes.len() > data.len() {
            return Err(BypassError::TooShort(self.offset));
        }
        data[self.offset..self.offset + self.original_bytes.len()]
            .copy_from_slice(&self.original_bytes);
        Ok(())
    }

    /// Return `true` if the patch is currently applied to the given data.
    #[must_use]
    pub fn is_applied(&self, data: &[u8]) -> bool {
        if self.offset + self.patch_bytes.len() > data.len() {
            return false;
        }
        data[self.offset..self.offset + self.patch_bytes.len()] == *self.patch_bytes
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatchSet
// ─────────────────────────────────────────────────────────────────────────────

/// A collection of bypass patches.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatchSet {
    patches: Vec<BypassPatch>,
}

impl PatchSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a patch.
    ///
    /// # Errors
    /// Returns [`BypassError::Conflict`] if another patch already covers the same address.
    pub fn add(&mut self, patch: BypassPatch) -> Result<(), BypassError> {
        for existing in &self.patches {
            if existing.address == patch.address {
                return Err(BypassError::Conflict(patch.address));
            }
        }
        self.patches.push(patch);
        Ok(())
    }

    /// Add without conflict checking.
    pub fn add_unchecked(&mut self, patch: BypassPatch) {
        self.patches.push(patch);
    }

    /// Return all patches.
    #[must_use]
    pub fn patches(&self) -> &[BypassPatch] {
        &self.patches
    }

    /// Number of patches.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patches.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    /// Apply all patches to `data`.
    ///
    /// # Errors
    /// Returns the first error encountered.
    pub fn apply_all(&self, data: &mut [u8]) -> Result<(), BypassError> {
        for patch in &self.patches {
            patch.apply(data)?;
        }
        Ok(())
    }

    /// Revert all patches.
    ///
    /// # Errors
    /// Returns the first error encountered.
    pub fn revert_all(&self, data: &mut [u8]) -> Result<(), BypassError> {
        for patch in self.patches.iter().rev() {
            patch.revert(data)?;
        }
        Ok(())
    }

    /// Filter patches targeting a specific technique.
    #[must_use]
    pub fn for_technique(&self, t: AntiDebugTechnique) -> Vec<&BypassPatch> {
        self.patches.iter().filter(|p| p.technique == t).collect()
    }

    /// Generate a Frida script snippet to apply all patches at runtime.
    #[must_use]
    pub fn to_frida_script(&self) -> String {
        let mut lines = vec!["// Auto-generated Frida patch script".to_owned()];
        for patch in &self.patches {
            lines.push(format!("// {} @ {:#x}", patch.description, patch.address));
            let bytes: Vec<String> = patch
                .patch_bytes
                .iter()
                .map(|b| format!("{b:#04x}"))
                .collect();
            lines.push(format!(
                "Memory.writeByteArray(ptr('{:#x}'), [{}]);",
                patch.address,
                bytes.join(", ")
            ));
        }
        lines.join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BypassGenerator
// ─────────────────────────────────────────────────────────────────────────────

/// Generates [`BypassPatch`] instances for detected anti-debug hits.
pub struct BypassGenerator {
    preferred_strategy: HashMap<AntiDebugTechnique, BypassStrategy>,
    /// Alias of [`preferred_strategy`] used by callers that expect the
    /// shorter `preferred` field name. Kept in sync by all mutators.
    preferred: HashMap<AntiDebugTechnique, BypassStrategy>,
}

impl BypassGenerator {
    #[must_use]
    pub fn new() -> Self {
        let mut preferred = HashMap::new();
        preferred.insert(
            AntiDebugTechnique::IsDebuggerPresent,
            BypassStrategy::ForceReturnFalse,
        );
        preferred.insert(
            AntiDebugTechnique::CheckRemoteDebuggerPresent,
            BypassStrategy::ForceReturnFalse,
        );
        preferred.insert(AntiDebugTechnique::BeingDebugged, BypassStrategy::NopOut);
        preferred.insert(AntiDebugTechnique::Rdtsc, BypassStrategy::NopOut);
        preferred.insert(AntiDebugTechnique::Int3Exception, BypassStrategy::NopOut);
        preferred.insert(
            AntiDebugTechnique::CpuidHypervisorBit,
            BypassStrategy::NopOut,
        );
        preferred.insert(
            AntiDebugTechnique::HardwareBreakpoints,
            BypassStrategy::PatchJump,
        );
        preferred.insert(
            AntiDebugTechnique::NtQueryInformationProcess,
            BypassStrategy::ForceReturnFalse,
        );
        Self {
            preferred_strategy: preferred.clone(),
            preferred,
        }
    }

    /// Set the preferred bypass strategy for a technique.
    pub fn set_strategy(&mut self, technique: AntiDebugTechnique, strategy: BypassStrategy) {
        self.preferred.insert(technique, strategy);
        self.preferred_strategy.insert(technique, strategy);
    }

    /// Generate a bypass patch for a detection hit against `data`.
    ///
    /// # Errors
    /// Returns [`BypassError::TooShort`] if the data is too short.
    pub fn generate(&self, hit: &DetectionHit, data: &[u8]) -> Result<BypassPatch, BypassError> {
        let strategy = self
            .preferred
            .get(&hit.technique)
            .copied()
            .unwrap_or(BypassStrategy::NopOut);

        let original_len = hit.matched_bytes.len().max(1);
        if hit.offset + original_len > data.len() {
            return Err(BypassError::TooShort(hit.offset));
        }
        let original_bytes = data[hit.offset..hit.offset + original_len].to_vec();

        let patch_bytes = match strategy {
            BypassStrategy::NopOut => vec![0x90u8; original_len],
            BypassStrategy::ForceReturnFalse => {
                // xor eax, eax; ret  (2 bytes, pad with NOPs)
                let mut p = vec![0x31, 0xC0, 0xC3];
                while p.len() < original_len {
                    p.push(0x90);
                }
                p.truncate(original_len);
                p
            }
            BypassStrategy::ForceReturnTrue => {
                // mov eax, 1; ret
                let mut p = vec![0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];
                while p.len() < original_len {
                    p.push(0x90);
                }
                p.truncate(original_len);
                p
            }
            BypassStrategy::PatchJump => {
                // Replace a conditional jump (Jcc) with an unconditional jump (EB xx)
                // or simply NOP out the check.
                if original_len >= 2 {
                    let mut p = vec![0xEB, original_len as u8 - 2];
                    while p.len() < original_len {
                        p.push(0x90);
                    }
                    p.truncate(original_len);
                    p
                } else {
                    vec![0x90u8; original_len]
                }
            }
            BypassStrategy::InlineStub => {
                // Inline: xor eax, eax; nop...
                let mut p = vec![0x31, 0xC0];
                while p.len() < original_len {
                    p.push(0x90);
                }
                p.truncate(original_len);
                p
            }
        };

        Ok(BypassPatch {
            address: hit.address,
            offset: hit.offset,
            original_bytes,
            patch_bytes,
            strategy,
            technique: hit.technique,
            description: format!("Bypass {} via {}", hit.technique, strategy),
        })
    }

    /// Generate patches for all hits and return as a [`PatchSet`].
    #[must_use]
    pub fn generate_all(&self, hits: &[DetectionHit], data: &[u8]) -> PatchSet {
        let mut ps = PatchSet::new();
        for hit in hits {
            if let Ok(patch) = self.generate(hit, data) {
                ps.add_unchecked(patch);
            }
        }
        ps
    }
}

impl Default for BypassGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- AntiDebugTechnique --------------------------------------------------

    #[test]
    fn test_technique_name() {
        assert_eq!(
            AntiDebugTechnique::IsDebuggerPresent.name(),
            "IsDebuggerPresent"
        );
        assert_eq!(AntiDebugTechnique::Rdtsc.name(), "RDTSC");
    }

    #[test]
    fn test_technique_is_windows() {
        assert!(AntiDebugTechnique::IsDebuggerPresent.is_windows());
        assert!(!AntiDebugTechnique::PtraceTraceme.is_windows());
    }

    #[test]
    fn test_technique_is_linux() {
        assert!(AntiDebugTechnique::PtraceTraceme.is_linux());
        assert!(!AntiDebugTechnique::IsDebuggerPresent.is_linux());
    }

    #[test]
    fn test_technique_difficulty() {
        assert_eq!(AntiDebugTechnique::IsDebuggerPresent.bypass_difficulty(), 1);
        assert_eq!(AntiDebugTechnique::TlsCallback.bypass_difficulty(), 4);
    }

    #[test]
    fn test_technique_display() {
        assert_eq!(
            AntiDebugTechnique::BeingDebugged.to_string(),
            "BeingDebugged"
        );
    }

    // -- AntiDebugDetector ---------------------------------------------------

    #[test]
    fn test_detector_find_isdebugger_present() {
        let d = AntiDebugDetector::new();
        let data = b"XXXIsDebuggerPresentYYY".to_vec();
        let hits = d.detect(&data);
        assert!(
            hits.iter()
                .any(|h| h.technique == AntiDebugTechnique::IsDebuggerPresent)
        );
    }

    #[test]
    fn test_detector_find_rdtsc() {
        let d = AntiDebugDetector::new();
        let data = vec![0x90, 0x0F, 0x31, 0x90]; // NOP; RDTSC; NOP
        let hits = d.detect(&data);
        assert!(
            hits.iter()
                .any(|h| h.technique == AntiDebugTechnique::Rdtsc)
        );
    }

    #[test]
    fn test_detector_find_peb_64bit() {
        let d = AntiDebugDetector::new();
        let data = vec![0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00];
        let hits = d.detect(&data);
        assert!(
            hits.iter()
                .any(|h| h.technique == AntiDebugTechnique::BeingDebugged)
        );
    }

    #[test]
    fn test_detector_no_hits_empty() {
        let d = AntiDebugDetector::new();
        assert!(d.detect(&[]).is_empty());
    }

    #[test]
    fn test_detector_min_confidence() {
        let mut d = AntiDebugDetector::new();
        d.set_min_confidence(100);
        let data = b"IsDebuggerPresent".to_vec();
        // Confidence is 80, so should be filtered out.
        let hits = d.detect(&data);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_detector_tracerpid() {
        let d = AntiDebugDetector::new();
        let data = b"TracerPid:\t0\n".to_vec();
        let hits = d.detect(&data);
        assert!(
            hits.iter()
                .any(|h| h.technique == AntiDebugTechnique::ProcStatusTracerPid)
        );
    }

    // -- BypassPatch ---------------------------------------------------------

    #[test]
    fn test_patch_apply_and_revert() {
        let original = vec![0x0F, 0x31, 0x90];
        let patch = BypassPatch {
            address: 0x1000,
            offset: 0,
            original_bytes: original.clone(),
            patch_bytes: vec![0x90, 0x90, 0x90],
            strategy: BypassStrategy::NopOut,
            technique: AntiDebugTechnique::Rdtsc,
            description: "NOP RDTSC".into(),
        };
        let mut data = original.clone();
        patch.apply(&mut data).unwrap();
        assert_eq!(data, vec![0x90, 0x90, 0x90]);
        patch.revert(&mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn test_patch_is_applied() {
        let patch = BypassPatch {
            address: 0,
            offset: 0,
            original_bytes: vec![0x0F, 0x31],
            patch_bytes: vec![0x90, 0x90],
            strategy: BypassStrategy::NopOut,
            technique: AntiDebugTechnique::Rdtsc,
            description: "t".into(),
        };
        assert!(patch.is_applied(&[0x90, 0x90]));
        assert!(!patch.is_applied(&[0x0F, 0x31]));
    }

    #[test]
    fn test_patch_apply_too_short() {
        let patch = BypassPatch {
            address: 0,
            offset: 0,
            original_bytes: vec![0x90, 0x90, 0x90],
            patch_bytes: vec![0x90, 0x90, 0x90],
            strategy: BypassStrategy::NopOut,
            technique: AntiDebugTechnique::Int3Exception,
            description: "t".into(),
        };
        let mut data = vec![0x90u8; 2]; // too short for 3-byte patch
        assert!(patch.apply(&mut data).is_err());
    }

    // -- PatchSet ------------------------------------------------------------

    #[test]
    fn test_patchset_add_conflict() {
        let mut ps = PatchSet::new();
        let p1 = BypassPatch {
            address: 0x1000,
            offset: 0,
            original_bytes: vec![0x90],
            patch_bytes: vec![0x90],
            strategy: BypassStrategy::NopOut,
            technique: AntiDebugTechnique::Rdtsc,
            description: "p1".into(),
        };
        let p2 = p1.clone();
        ps.add(p1).unwrap();
        assert!(ps.add(p2).is_err());
    }

    #[test]
    fn test_patchset_apply_all() {
        let mut ps = PatchSet::new();
        ps.add_unchecked(BypassPatch {
            address: 0,
            offset: 0,
            original_bytes: vec![0x0F, 0x31],
            patch_bytes: vec![0x90, 0x90],
            strategy: BypassStrategy::NopOut,
            technique: AntiDebugTechnique::Rdtsc,
            description: "t".into(),
        });
        let mut data = vec![0x0F, 0x31, 0xFF];
        ps.apply_all(&mut data).unwrap();
        assert_eq!(data[0], 0x90);
    }

    #[test]
    fn test_patchset_frida_script() {
        let mut ps = PatchSet::new();
        ps.add_unchecked(BypassPatch {
            address: 0x401000,
            offset: 0,
            original_bytes: vec![0x0F],
            patch_bytes: vec![0x90],
            strategy: BypassStrategy::NopOut,
            technique: AntiDebugTechnique::Rdtsc,
            description: "NOP RDTSC".into(),
        });
        let script = ps.to_frida_script();
        assert!(script.contains("0x401000"));
        assert!(script.contains("Memory.writeByteArray"));
    }

    #[test]
    fn test_patchset_for_technique() {
        let mut ps = PatchSet::new();
        ps.add_unchecked(BypassPatch {
            address: 0x100,
            offset: 0,
            original_bytes: vec![0x90],
            patch_bytes: vec![0x90],
            strategy: BypassStrategy::NopOut,
            technique: AntiDebugTechnique::Rdtsc,
            description: "t".into(),
        });
        assert_eq!(ps.for_technique(AntiDebugTechnique::Rdtsc).len(), 1);
        assert!(
            ps.for_technique(AntiDebugTechnique::IsDebuggerPresent)
                .is_empty()
        );
    }

    // -- BypassGenerator -----------------------------------------------------

    #[test]
    fn test_generator_nop_strategy() {
        let r#gen = BypassGenerator::new();
        let hit = DetectionHit {
            technique: AntiDebugTechnique::Rdtsc,
            address: 0x1000,
            offset: 1,
            confidence: 65,
            description: "RDTSC".into(),
            matched_bytes: vec![0x0F, 0x31],
        };
        let data = vec![0x90, 0x0F, 0x31, 0x90];
        let patch = r#gen.generate(&hit, &data).unwrap();
        assert_eq!(patch.patch_bytes, vec![0x90, 0x90]);
    }

    #[test]
    fn test_generator_force_return_false() {
        let r#gen = BypassGenerator::new();
        let hit = DetectionHit {
            technique: AntiDebugTechnique::IsDebuggerPresent,
            address: 0x1000,
            offset: 0,
            confidence: 80,
            description: "test".into(),
            matched_bytes: vec![0x90; 6],
        };
        let data = vec![0x90u8; 64];
        let patch = r#gen.generate(&hit, &data).unwrap();
        // ForceReturnFalse starts with xor eax, eax = [0x31, 0xC0]
        assert_eq!(patch.patch_bytes[0], 0x31);
        assert_eq!(patch.patch_bytes[1], 0xC0);
    }

    #[test]
    fn test_generator_generate_all() {
        let r#gen = BypassGenerator::new();
        let data = b"IsDebuggerPresent\0TracerPid".to_vec();
        let detector = AntiDebugDetector::new();
        let hits = detector.detect(&data);
        let ps = r#gen.generate_all(&hits, &data);
        assert!(!ps.is_empty());
    }

    #[test]
    fn test_bypass_strategy_display() {
        assert_eq!(BypassStrategy::NopOut.to_string(), "NopOut");
        assert_eq!(
            BypassStrategy::ForceReturnFalse.to_string(),
            "ForceReturn(false)"
        );
    }
}
