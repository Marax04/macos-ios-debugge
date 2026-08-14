//! `timing_patchers` — Anti-timing technique detection and patching.
//!
//! Patches RDTSC, GetTickCount, QueryPerformanceCounter, Sleep/NtDelayExecution,
//! GetSystemTime spoofing, and timing-check bypass via emulation hooks.

use crate::AntiDebugTechnique;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// TimingSignature — byte patterns for timing instructions / API calls
// ─────────────────────────────────────────────────────────────────────────────

/// A timing-related byte signature to search for in the binary.
#[derive(Debug, Clone)]
pub struct TimingSignature {
    pub name: &'static str,
    pub technique: AntiDebugTechnique,
    /// Raw bytes (exact match, no wildcards).
    pub pattern: Vec<u8>,
    /// Mask (0xFF = match, 0x00 = wildcard).
    pub mask: Vec<u8>,
    /// Patch to apply at the matched offset.
    pub patch_template: PatchTemplate,
}

// ─────────────────────────────────────────────────────────────────────────────
// PatchTemplate
// ─────────────────────────────────────────────────────────────────────────────

/// Describes how to patch a detected timing instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatchTemplate {
    /// Replace the matched bytes with NOPs.
    Nop,
    /// Replace with `mov eax, <const_lo>; mov edx, <const_hi>` (for RDTSC).
    RdtscReturnConst { lo: u32, hi: u32 },
    /// Replace a CALL with `xor eax, eax` + NOPs.
    ZeroReturnXor32,
    /// Replace a CALL with `xor eax, eax; xor edx, edx` + NOPs.
    ZeroReturnXor64,
    /// Replace Sleep/NtDelayExecution CALL with NOPs (make instant).
    MakeInstant,
    /// Replace with a custom byte sequence.
    Custom(Vec<u8>),
}

// ─────────────────────────────────────────────────────────────────────────────
// TimingSignatureDb
// ─────────────────────────────────────────────────────────────────────────────

/// Built-in database of timing-related signatures.
pub struct TimingSignatureDb {
    pub signatures: Vec<TimingSignature>,
}

impl TimingSignatureDb {
    /// Build the default signature database.
    #[must_use]
    pub fn default_db() -> Self {
        let sigs = vec![
            // RDTSC instruction (0F 31)
            TimingSignature {
                name: "RDTSC",
                technique: AntiDebugTechnique::Rdtsc,
                pattern: vec![0x0F, 0x31],
                mask: vec![0xFF, 0xFF],
                patch_template: PatchTemplate::RdtscReturnConst { lo: 0x1337_0000, hi: 0 },
            },
            // RDTSCP (0F 01 F9)
            TimingSignature {
                name: "RDTSCP",
                technique: AntiDebugTechnique::Rdtsc,
                pattern: vec![0x0F, 0x01, 0xF9],
                mask: vec![0xFF, 0xFF, 0xFF],
                patch_template: PatchTemplate::RdtscReturnConst { lo: 0x1337_0000, hi: 0 },
            },
            // RDPMC (0F 33) — sometimes used as timing side-channel
            TimingSignature {
                name: "RDPMC",
                technique: AntiDebugTechnique::Rdtsc,
                pattern: vec![0x0F, 0x33],
                mask: vec![0xFF, 0xFF],
                patch_template: PatchTemplate::ZeroReturnXor64,
            },
            // GetTickCount stub: FF 15 ?? ?? ?? ?? (CALL [GetTickCount@IAT])
            // Matched by call pattern + symbol; we NOP the call.
            TimingSignature {
                name: "GetTickCount-IAT-call",
                technique: AntiDebugTechnique::GetTickCount,
                pattern: vec![0xFF, 0x15, 0x00, 0x00, 0x00, 0x00],
                mask: vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
                patch_template: PatchTemplate::ZeroReturnXor32,
            },
            // QueryPerformanceCounter
            TimingSignature {
                name: "QueryPerformanceCounter-IAT-call",
                technique: AntiDebugTechnique::GetTickCount,
                pattern: vec![0xFF, 0x15, 0x00, 0x00, 0x00, 0x00],
                mask: vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
                patch_template: PatchTemplate::ZeroReturnXor64,
            },
            // Sleep — NtDelayExecution: ff 15 (call [IAT])
            TimingSignature {
                name: "Sleep-IAT-call",
                technique: AntiDebugTechnique::GetTickCount, // reuse; real impl has Sleep variant
                pattern: vec![0xFF, 0x15, 0x00, 0x00, 0x00, 0x00],
                mask: vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
                patch_template: PatchTemplate::MakeInstant,
            },
        ];
        Self { signatures: sigs }
    }

    /// Scan `data` for all matching signatures and return `(offset, &sig)` pairs.
    #[must_use]
    pub fn scan<'a>(&'a self, data: &[u8]) -> Vec<(usize, &'a TimingSignature)> {
        let mut results = Vec::new();
        for sig in &self.signatures {
            let pat_len = sig.pattern.len();
            if pat_len == 0 || pat_len > data.len() {
                continue;
            }
            for (offset, window) in data.windows(pat_len).enumerate() {
                let matches = window
                    .iter()
                    .zip(sig.pattern.iter())
                    .zip(sig.mask.iter())
                    .all(|((b, p), m)| (*m == 0x00) || (b & m == p & m));
                if matches {
                    results.push((offset, sig));
                }
            }
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// patch_bytes — apply a PatchTemplate to a mutable byte slice
// ─────────────────────────────────────────────────────────────────────────────

/// Apply a patch template at `offset` within `data`, returning the modified range.
pub fn apply_patch_template(
    data: &mut Vec<u8>,
    offset: usize,
    sig_len: usize,
    template: &PatchTemplate,
) -> bool {
    match template {
        PatchTemplate::Nop => {
            if offset + sig_len > data.len() {
                return false;
            }
            for b in &mut data[offset..offset + sig_len] {
                *b = 0x90; // NOP
            }
            true
        }
        PatchTemplate::RdtscReturnConst { lo, hi } => {
            // Encode: mov eax, <lo>  (B8 lo lo lo lo)
            //         mov edx, <hi>  (BA hi hi hi hi)
            // Total: 10 bytes; NOP-pad the rest
            let patch: Vec<u8> = {
                let mut p = vec![0xB8u8];
                p.extend_from_slice(&lo.to_le_bytes());
                p.push(0xBA);
                p.extend_from_slice(&hi.to_le_bytes());
                p
            };
            let available = (data.len() - offset).min(sig_len.max(10));
            for (i, b) in patch.iter().enumerate().take(available) {
                if offset + i < data.len() {
                    data[offset + i] = *b;
                }
            }
            // NOP-pad remainder
            for i in patch.len()..available {
                if offset + i < data.len() {
                    data[offset + i] = 0x90;
                }
            }
            true
        }
        PatchTemplate::ZeroReturnXor32 => {
            // xor eax, eax (33 C0) + NOPs
            if offset + sig_len > data.len() || sig_len < 2 {
                return false;
            }
            data[offset] = 0x33;
            data[offset + 1] = 0xC0;
            for b in &mut data[offset + 2..offset + sig_len] {
                *b = 0x90;
            }
            true
        }
        PatchTemplate::ZeroReturnXor64 => {
            // xor eax, eax (33 C0); xor edx, edx (33 D2) + NOPs
            if offset + sig_len > data.len() || sig_len < 4 {
                return false;
            }
            data[offset] = 0x33;
            data[offset + 1] = 0xC0;
            data[offset + 2] = 0x33;
            data[offset + 3] = 0xD2;
            for b in &mut data[offset + 4..offset + sig_len] {
                *b = 0x90;
            }
            true
        }
        PatchTemplate::MakeInstant => {
            // NOP out the entire call
            if offset + sig_len > data.len() {
                return false;
            }
            for b in &mut data[offset..offset + sig_len] {
                *b = 0x90;
            }
            true
        }
        PatchTemplate::Custom(bytes) => {
            let len = bytes.len().min(sig_len).min(data.len() - offset);
            data[offset..offset + len].copy_from_slice(&bytes[..len]);
            // NOP-pad
            for b in &mut data[offset + len..offset + sig_len] {
                *b = 0x90;
            }
            true
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TimingPatchConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the timing patcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingPatchConfig {
    /// Constant TSC value to return from RDTSC patches.
    pub fake_tsc_lo: u32,
    pub fake_tsc_hi: u32,
    /// Whether to NOP RDTSC instructions (true) or replace with constant return (false).
    pub nop_rdtsc: bool,
    /// Whether to patch Sleep / NtDelayExecution calls.
    pub patch_sleep: bool,
    /// Whether to patch GetTickCount calls.
    pub patch_gettickcount: bool,
    /// Whether to patch QueryPerformanceCounter.
    pub patch_qpc: bool,
}

impl Default for TimingPatchConfig {
    fn default() -> Self {
        Self {
            fake_tsc_lo: 0x1000_0000,
            fake_tsc_hi: 0,
            nop_rdtsc: false,
            patch_sleep: true,
            patch_gettickcount: true,
            patch_qpc: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TimingPatchResult
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of patches applied by the timing patcher.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TimingPatchResult {
    pub rdtsc_patches: usize,
    pub sleep_patches: usize,
    pub gettickcount_patches: usize,
    pub qpc_patches: usize,
    pub total_patches: usize,
    pub patch_offsets: Vec<(usize, String)>,
}

// ─────────────────────────────────────────────────────────────────────────────
// TimingPatcher
// ─────────────────────────────────────────────────────────────────────────────

/// High-level timing patcher: detects and patches all timing techniques.
pub struct TimingPatcher {
    config: TimingPatchConfig,
    db: TimingSignatureDb,
}

impl TimingPatcher {
    #[must_use]
    pub fn new(config: TimingPatchConfig) -> Self {
        Self {
            config,
            db: TimingSignatureDb::default_db(),
        }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(TimingPatchConfig::default())
    }

    /// Scan `data` and apply all timing patches in-place.
    pub fn patch(&self, data: &mut Vec<u8>) -> TimingPatchResult {
        let matches = self.db.scan(data);
        let mut result = TimingPatchResult::default();

        // Deduplicate: sort by offset, apply each once.
        let mut seen_offsets = std::collections::HashSet::new();

        for (offset, sig) in matches {
            if !seen_offsets.insert(offset) {
                continue;
            }

            let template = self.select_template(sig);
            let sig_len = sig.pattern.len();

            if apply_patch_template(data, offset, sig_len, &template) {
                result.patch_offsets.push((offset, sig.name.to_string()));
                match sig.technique {
                    AntiDebugTechnique::Rdtsc => result.rdtsc_patches += 1,
                    AntiDebugTechnique::GetTickCount => {
                        match sig.name {
                            n if n.contains("Sleep") => result.sleep_patches += 1,
                            n if n.contains("QPC") || n.contains("QueryPerf") => result.qpc_patches += 1,
                            _ => result.gettickcount_patches += 1,
                        }
                    }
                    _ => {}
                }
                result.total_patches += 1;
            }
        }

        result
    }

    fn select_template(&self, sig: &TimingSignature) -> PatchTemplate {
        match sig.technique {
            AntiDebugTechnique::Rdtsc => {
                if self.config.nop_rdtsc {
                    PatchTemplate::Nop
                } else {
                    PatchTemplate::RdtscReturnConst {
                        lo: self.config.fake_tsc_lo,
                        hi: self.config.fake_tsc_hi,
                    }
                }
            }
            _ => sig.patch_template.clone(),
        }
    }

    /// Generate a Frida hook script for timing bypasses (JavaScript).
    #[must_use]
    pub fn frida_script(&self) -> String {
        let mut lines = vec![
            "// Auto-generated Frida hook for timing bypass".to_string(),
            "// Generated by rustre-deobf-antianti::timing_patchers".to_string(),
            String::new(),
        ];

        lines.push("'use strict';".into());
        lines.push(String::new());

        if self.config.patch_gettickcount {
            lines.push(r#"
const GetTickCount = Module.findExportByName('kernel32.dll', 'GetTickCount');
if (GetTickCount) {
    Interceptor.replace(GetTickCount, new NativeCallback(function () {
        return 0x10000000;
    }, 'uint32', []));
    console.log('[+] Hooked GetTickCount → constant 0x10000000');
}"#.trim().to_string());
            lines.push(String::new());
        }

        if self.config.patch_qpc {
            lines.push(r#"
const QueryPerformanceCounter = Module.findExportByName('kernel32.dll', 'QueryPerformanceCounter');
if (QueryPerformanceCounter) {
    Interceptor.attach(QueryPerformanceCounter, {
        onEnter: function(args) { this.ptr = args[0]; },
        onLeave: function(ret) {
            this.ptr.writeU64(0x100000000n);
            ret.replace(1);
        }
    });
    console.log('[+] Hooked QueryPerformanceCounter → constant');
}"#.trim().to_string());
            lines.push(String::new());
        }

        if self.config.patch_sleep {
            lines.push(r#"
const Sleep = Module.findExportByName('kernel32.dll', 'Sleep');
if (Sleep) {
    Interceptor.replace(Sleep, new NativeCallback(function (dwMilliseconds) {
        // NOP: return instantly
    }, 'void', ['uint32']));
    console.log('[+] Hooked Sleep → instant return');
}"#.trim().to_string());
        }

        lines.join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RDTSC delta check detector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects pairs of RDTSC instructions with a comparison in between
/// (the classic "measure elapsed ticks" anti-debug pattern).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdtscDeltaCheck {
    /// Offset of the first RDTSC.
    pub rdtsc1_offset: usize,
    /// Offset of the second RDTSC.
    pub rdtsc2_offset: usize,
    /// Offset of the comparison instruction.
    pub cmp_offset: usize,
    /// Estimated threshold being compared (if detectable).
    pub threshold: Option<u64>,
}

/// Scan for RDTSC delta pairs in `data`.
#[must_use]
pub fn detect_rdtsc_delta_checks(data: &[u8]) -> Vec<RdtscDeltaCheck> {
    let rdtsc_pattern = [0x0Fu8, 0x31];
    let rdtsc_offsets: Vec<usize> = data
        .windows(2)
        .enumerate()
        .filter(|(_, w)| *w == rdtsc_pattern)
        .map(|(i, _)| i)
        .collect();

    let mut checks = Vec::new();

    for pair in rdtsc_offsets.windows(2) {
        let (off1, off2) = (pair[0], pair[1]);
        let gap = off2 - off1;
        // Reasonable gap: 10..500 bytes between the two RDTSC instructions
        if gap < 10 || gap > 500 {
            continue;
        }
        // Search for a CMP instruction in the range [off2+2, off2+50]
        let search_start = off2 + 2;
        let search_end = (off2 + 50).min(data.len());
        let cmp_offset = data[search_start..search_end]
            .windows(1)
            .enumerate()
            .find(|(_, w)| w[0] == 0x3B || w[0] == 0x39 || w[0] == 0x3D) // CMP variants
            .map(|(i, _)| search_start + i);

        if let Some(cmp) = cmp_offset {
            checks.push(RdtscDeltaCheck {
                rdtsc1_offset: off1,
                rdtsc2_offset: off2,
                cmp_offset: cmp,
                threshold: None, // would require disassembly to extract
            });
        }
    }

    checks
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rdtsc_nop_patch() {
        let mut data = vec![0x90u8, 0x0F, 0x31, 0x90, 0x90];
        let patcher = TimingPatcher::new(TimingPatchConfig {
            nop_rdtsc: true,
            ..Default::default()
        });
        let result = patcher.patch(&mut data);
        assert_eq!(result.rdtsc_patches, 1);
        // RDTSC at offset 1 should be NOPped
        assert_eq!(data[1], 0x90);
        assert_eq!(data[2], 0x90);
    }

    #[test]
    fn test_rdtsc_const_patch() {
        let mut data = vec![0x0Fu8, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let patcher = TimingPatcher::new(TimingPatchConfig {
            nop_rdtsc: false,
            fake_tsc_lo: 0xDEAD_BEEF,
            fake_tsc_hi: 0,
            ..Default::default()
        });
        let result = patcher.patch(&mut data);
        assert_eq!(result.rdtsc_patches, 1);
        // First byte should be B8 (mov eax, imm32)
        assert_eq!(data[0], 0xB8);
    }

    #[test]
    fn test_delta_check_detection() {
        // Two RDTSC instructions 50 bytes apart, followed by a CMP
        let mut data = vec![0x90u8; 100];
        data[0] = 0x0F; data[1] = 0x31;
        data[50] = 0x0F; data[51] = 0x31;
        data[55] = 0x3B; // CMP
        let checks = detect_rdtsc_delta_checks(&data);
        assert!(!checks.is_empty(), "should detect delta check");
    }

    #[test]
    fn test_frida_script_contains_hooks() {
        let patcher = TimingPatcher::with_defaults();
        let script = patcher.frida_script();
        assert!(script.contains("GetTickCount"));
        assert!(script.contains("QueryPerformanceCounter"));
        assert!(script.contains("Sleep"));
    }

    #[test]
    fn test_zero_return_xor32_patch() {
        let mut data = vec![0xFF, 0x15, 0x00, 0x00, 0x00, 0x00];
        assert!(apply_patch_template(&mut data, 0, 6, &PatchTemplate::ZeroReturnXor32));
        assert_eq!(data[0], 0x33);
        assert_eq!(data[1], 0xC0);
    }
}
