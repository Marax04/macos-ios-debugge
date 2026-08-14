//! Full triage pipeline orchestration.
//!
//! Runs all analysis stages in order, collects their outputs, and
//! aggregates them into a single `TriageResult`. Each stage is a
//! `PipelineStage` that receives the raw file bytes plus the result
//! accumulated so far and appends its findings.

use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::{
    FileKind, ThreatLevel, TriageError, TriageIndicator, TriageResult,
    detect_file_kind,
};

// ─── StageOutput ──────────────────────────────────────────────────────────────

/// The output produced by a single pipeline stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageOutput {
    /// Name of the stage that produced this output.
    pub stage_name: String,
    /// Indicators discovered by this stage.
    pub indicators: Vec<TriageIndicator>,
    /// Whether this stage ran successfully.
    pub success: bool,
    /// Optional diagnostic message (e.g., skip reason or error description).
    pub message: Option<String>,
    /// Approximate execution time in microseconds.
    pub elapsed_us: u64,
}

impl StageOutput {
    /// Create a successful output with no indicators.
    #[must_use]
    pub fn empty(stage_name: impl Into<String>) -> Self {
        Self {
            stage_name: stage_name.into(),
            indicators: Vec::new(),
            success: true,
            message: None,
            elapsed_us: 0,
        }
    }

    /// Create an output that was skipped with a reason.
    #[must_use]
    pub fn skipped(stage_name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            stage_name: stage_name.into(),
            indicators: Vec::new(),
            success: true,
            message: Some(format!("skipped: {}", reason.into())),
            elapsed_us: 0,
        }
    }

    /// Create an output that failed with an error message.
    #[must_use]
    pub fn failed(stage_name: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            stage_name: stage_name.into(),
            indicators: Vec::new(),
            success: false,
            message: Some(format!("error: {}", error.into())),
            elapsed_us: 0,
        }
    }
}

// ─── PipelineStage trait ──────────────────────────────────────────────────────

/// A single stage in the triage pipeline.
///
/// Each stage receives the raw bytes and the mutable accumulated
/// `TriageResult`, appends any indicators it finds, and returns a
/// `StageOutput` describing what it did.
pub trait PipelineStage: Send + Sync {
    /// Short human-readable name for this stage.
    fn name(&self) -> &'static str;

    /// Run the stage against `data`, modifying `result` in place, and return
    /// the stage output.
    fn run(&self, data: &[u8], result: &mut TriageResult) -> StageOutput;

    /// Return `true` if this stage should run for the given file kind.
    /// Defaults to `true` (run for all file kinds).
    fn applicable(&self, _kind: FileKind) -> bool {
        true
    }
}

// ─── Built-in stages ──────────────────────────────────────────────────────────

/// Detects the file format and sets `result.file_kind`.
pub struct FileKindStage;

impl PipelineStage for FileKindStage {
    fn name(&self) -> &'static str {
        "file-kind"
    }

    fn run(&self, data: &[u8], result: &mut TriageResult) -> StageOutput {
        let kind = detect_file_kind(data);
        let mut output = StageOutput::empty(self.name());
        output.message = Some(format!("detected: {kind:?}"));
        // file_kind was already set in TriageResult::new; update it.
        result.file_kind = kind;
        output
    }
}

/// Checks whether the file entropy is suspiciously high (possible packing).
pub struct EntropyStage {
    /// Entropy threshold above which the file is flagged as possibly packed.
    pub threshold: f64,
}

impl EntropyStage {
    #[must_use]
    pub const fn new(threshold: f64) -> Self {
        Self { threshold }
    }
}

impl PipelineStage for EntropyStage {
    fn name(&self) -> &'static str {
        "entropy"
    }

    fn run(&self, _data: &[u8], result: &mut TriageResult) -> StageOutput {
        let mut out = StageOutput::empty(self.name());
        if result.entropy > self.threshold {
            let ind = TriageIndicator {
                name: "high-entropy".to_string(),
                description: format!("File entropy {:.3} exceeds threshold {:.1}", result.entropy, self.threshold),
                threat_level: ThreatLevel::Medium,
                category: "entropy".to_string(),
                evidence: format!("entropy={:.3}", result.entropy),
            };
            result.add_indicator(ind.clone());
            out.indicators.push(ind);
            out.message = Some(format!("entropy={:.3} (high)", result.entropy));
        } else {
            out.message = Some(format!("entropy={:.3} (normal)", result.entropy));
        }
        out
    }
}

/// Detects UPX packer signatures.
pub struct PackerDetectionStage;

impl PipelineStage for PackerDetectionStage {
    fn name(&self) -> &'static str {
        "packer-detection"
    }

    fn run(&self, data: &[u8], result: &mut TriageResult) -> StageOutput {
        let mut out = StageOutput::empty(self.name());
        let signatures: &[(&[u8], &str, ThreatLevel)] = &[
            (b"UPX!", "UPX packer", ThreatLevel::Medium),
            (b"MPRESS1", "MPRESS packer", ThreatLevel::Medium),
            (b"Themida", "Themida protector", ThreatLevel::High),
            (b"VMProtect", "VMProtect obfuscator", ThreatLevel::High),
            (b"ASPack", "ASPack packer", ThreatLevel::Medium),
            (b"PECompact", "PECompact packer", ThreatLevel::Medium),
            (b"PEPACK!!", "PEPACK packer", ThreatLevel::Medium),
            (b"ExeStealth", "ExeStealth protector", ThreatLevel::High),
            (b"ENIGMA", "Enigma protector", ThreatLevel::High),
        ];
        let scan_len = data.len().min(16384);
        for &(sig, name, lvl) in signatures {
            if data[..scan_len].windows(sig.len()).any(|w| w == sig) {
                let ind = TriageIndicator {
                    name: format!("packer:{name}"),
                    description: format!("{name} signature detected"),
                    threat_level: lvl,
                    category: "packing".to_string(),
                    evidence: format!("signature={}", std::str::from_utf8(sig).unwrap_or("?")),
                };
                result.is_packed = true;
                result.add_indicator(ind.clone());
                out.indicators.push(ind);
            }
        }
        out
    }
}

/// Detects suspicious strings (URLs, registry keys, crypto constants, etc.).
pub struct StringAnalysisStage {
    pub min_length: usize,
    pub max_scan_bytes: usize,
}

impl StringAnalysisStage {
    #[must_use]
    pub const fn new(min_length: usize, max_scan_bytes: usize) -> Self {
        Self { min_length, max_scan_bytes }
    }
}

impl PipelineStage for StringAnalysisStage {
    fn name(&self) -> &'static str {
        "string-analysis"
    }

    fn run(&self, data: &[u8], result: &mut TriageResult) -> StageOutput {
        let scan = &data[..data.len().min(self.max_scan_bytes)];
        let mut out = StageOutput::empty(self.name());

        // Network indicators.
        let url_patterns: &[&[u8]] = &[b"http://", b"https://", b"ftp://"];
        for &pat in url_patterns {
            if scan.windows(pat.len()).any(|w| w.eq_ignore_ascii_case(pat)) {
                let ind = TriageIndicator {
                    name: "network-url".to_string(),
                    description: format!("Network URL pattern: {}", std::str::from_utf8(pat).unwrap_or("?")),
                    threat_level: ThreatLevel::Low,
                    category: "network".to_string(),
                    evidence: std::str::from_utf8(pat).unwrap_or("?").to_string(),
                };
                result.add_indicator(ind.clone());
                out.indicators.push(ind);
                break;
            }
        }

        // Crypto constants in strings.
        let crypto_strings: &[(&[u8], &str, ThreatLevel)] = &[
            (b"-----BEGIN RSA PRIVATE KEY-----", "RSA private key embedded", ThreatLevel::Critical),
            (b"-----BEGIN PRIVATE KEY-----", "Private key embedded", ThreatLevel::Critical),
            (b"-----BEGIN CERTIFICATE-----", "Certificate embedded", ThreatLevel::Low),
        ];
        for &(pat, desc, lvl) in crypto_strings {
            if scan.windows(pat.len()).any(|w| w == pat) {
                let ind = TriageIndicator {
                    name: "embedded-key".to_string(),
                    description: desc.to_string(),
                    threat_level: lvl,
                    category: "crypto".to_string(),
                    evidence: std::str::from_utf8(pat).unwrap_or("?").chars().take(40).collect(),
                };
                result.add_indicator(ind.clone());
                out.indicators.push(ind);
            }
        }

        // Suspicious API strings.
        let api_strings: &[(&[u8], &str, ThreatLevel)] = &[
            (b"VirtualAlloc", "VirtualAlloc API reference", ThreatLevel::Low),
            (b"CreateRemoteThread", "CreateRemoteThread — injection", ThreatLevel::High),
            (b"WriteProcessMemory", "WriteProcessMemory — injection", ThreatLevel::High),
            (b"SetWindowsHookEx", "SetWindowsHookEx — keylogging", ThreatLevel::High),
            (b"RegSetValueEx", "RegSetValueEx — registry write", ThreatLevel::Medium),
            (b"InternetOpenUrl", "InternetOpenUrl — network", ThreatLevel::Low),
            (b"WinExec", "WinExec — shell execution", ThreatLevel::Medium),
        ];
        for &(pat, desc, lvl) in api_strings {
            if scan.windows(pat.len()).any(|w| w == pat) {
                let ind = TriageIndicator {
                    name: format!("api-string:{}", std::str::from_utf8(pat).unwrap_or("?")),
                    description: desc.to_string(),
                    threat_level: lvl,
                    category: "suspicious-api".to_string(),
                    evidence: std::str::from_utf8(pat).unwrap_or("?").to_string(),
                };
                result.add_indicator(ind.clone());
                out.indicators.push(ind);
            }
        }

        out.message = Some(format!("scanned {} bytes, {} indicators", scan.len(), out.indicators.len()));
        out
    }
}

/// Checks for anti-debug or anti-VM artefacts.
pub struct AntiAnalysisStage;

impl PipelineStage for AntiAnalysisStage {
    fn name(&self) -> &'static str {
        "anti-analysis"
    }

    fn run(&self, data: &[u8], result: &mut TriageResult) -> StageOutput {
        let scan_len = data.len().min(65536);
        let scan = &data[..scan_len];
        let mut out = StageOutput::empty(self.name());

        let patterns: &[(&[u8], &str, ThreatLevel)] = &[
            (b"IsDebuggerPresent", "IsDebuggerPresent anti-debug", ThreatLevel::Medium),
            (b"CheckRemoteDebuggerPresent", "CheckRemoteDebuggerPresent anti-debug", ThreatLevel::Medium),
            (b"NtQueryInformationProcess", "NtQueryInformationProcess anti-debug", ThreatLevel::Medium),
            (b"VBOX", "VirtualBox VM detection", ThreatLevel::Medium),
            (b"VMWARE", "VMware VM detection", ThreatLevel::Medium),
            (b"QEMU", "QEMU VM detection", ThreatLevel::Low),
            (b"SANDBOXIE", "Sandboxie anti-sandbox", ThreatLevel::High),
            (b"SbieDll", "Sandboxie DLL reference", ThreatLevel::High),
            (b"wine_get_version", "Wine environment detection", ThreatLevel::Low),
            (b"GetTickCount", "GetTickCount timing anti-debug", ThreatLevel::Low),
        ];

        for &(pat, desc, lvl) in patterns {
            if scan.windows(pat.len()).any(|w| w.eq_ignore_ascii_case(pat)) {
                result.is_obfuscated = true;
                let ind = TriageIndicator {
                    name: format!("anti-analysis:{}", std::str::from_utf8(pat).unwrap_or("?")),
                    description: desc.to_string(),
                    threat_level: lvl,
                    category: "anti-analysis".to_string(),
                    evidence: std::str::from_utf8(pat).unwrap_or("?").to_string(),
                };
                result.add_indicator(ind.clone());
                out.indicators.push(ind);
            }
        }
        out
    }
}

/// Detects shellcode-like characteristics.
pub struct ShellcodeDetectionStage;

impl ShellcodeDetectionStage {
    /// Check if a byte slice has a high proportion of executable instructions.
    fn shellcode_heuristic(data: &[u8]) -> bool {
        if data.len() < 64 {
            return false;
        }
        // Common shellcode opcode prefixes.
        let shellcode_opcodes: &[u8] = &[
            0x60, // PUSHAD
            0x61, // POPAD
            0xEB, // JMP short
            0xE9, // JMP near
            0xE8, // CALL near
            0x64, // FS: prefix
            0x31, // XOR
        ];
        let sample = &data[..data.len().min(256)];
        let shellcode_count = sample
            .iter()
            .filter(|&&b| shellcode_opcodes.contains(&b))
            .count();
        // If more than 15% of bytes are common shellcode opcodes, flag it.
        shellcode_count * 100 / sample.len() > 15
    }
}

impl PipelineStage for ShellcodeDetectionStage {
    fn name(&self) -> &'static str {
        "shellcode-detection"
    }

    fn run(&self, data: &[u8], result: &mut TriageResult) -> StageOutput {
        let mut out = StageOutput::empty(self.name());

        // Only flag if the file is not a valid PE/ELF.
        if matches!(result.file_kind, FileKind::Pe32 | FileKind::Pe64 | FileKind::Elf32 | FileKind::Elf64 | FileKind::MachO) {
            out.message = Some("skipped for known binary format".to_string());
            return out;
        }

        if Self::shellcode_heuristic(data) {
            let ind = TriageIndicator {
                name: "possible-shellcode".to_string(),
                description: "High proportion of shellcode-like opcodes detected".to_string(),
                threat_level: ThreatLevel::High,
                category: "shellcode".to_string(),
                evidence: format!("len={}", data.len()),
            };
            result.add_indicator(ind.clone());
            out.indicators.push(ind);
        }
        out
    }
}

// ─── CryptoConstantScanStage ──────────────────────────────────────────────────

/// Scan the binary for cryptographic constants using `rustre_crypto_id`.
///
/// Populates `TriageResult::crypto_hits`. Previously the pipeline never
/// called this scanner so downstream consumers always received zero hits even
/// though the scanner works correctly in isolation.
pub struct CryptoConstantScanStage;

impl PipelineStage for CryptoConstantScanStage {
    fn name(&self) -> &'static str {
        "crypto-constant-scan"
    }

    fn run(&self, data: &[u8], result: &mut TriageResult) -> StageOutput {
        let crypto_hits = rustre_crypto_id::scan_binary_for_crypto_constants(data);
        let count = crypto_hits.len();
        result.crypto_hits = crypto_hits;
        let mut out = StageOutput::empty(self.name());
        out.message = Some(format!("found {count} crypto constant hit(s)"));
        out
    }
}

// ─── AllStringExtractionStage ─────────────────────────────────────────────────

/// Populate `TriageResult::all_strings` with EVERY printable ASCII run from the image.
///
/// Not just the suspicious-pattern subset detected by `StringAnalysisStage`.
/// This is what the MCP tool consumer expects to see — the bug was: pipeline
/// returned `strings: []` while the standalone `triage_core_extract_strings`
/// tool found 3000+ strings.
///
/// Two defaults: `min_length=4` matches IDA/Ghidra; `max_scan_bytes` caps
/// extraction at 64 MiB so the stage stays bounded even on very large
/// binaries.
pub struct AllStringExtractionStage {
    /// Minimum printable run length. Strings shorter than this are dropped.
    pub min_length: usize,
    /// Cap on bytes scanned for strings.
    pub max_scan_bytes: usize,
}

impl AllStringExtractionStage {
    #[must_use]
    pub const fn new(min_length: usize, max_scan_bytes: usize) -> Self {
        Self {
            min_length,
            max_scan_bytes,
        }
    }
}

impl PipelineStage for AllStringExtractionStage {
    fn name(&self) -> &'static str {
        "all-string-extraction"
    }

    fn run(&self, data: &[u8], result: &mut TriageResult) -> StageOutput {
        let scan_len = data.len().min(self.max_scan_bytes);
        let strings = crate::StringHeuristics::extract_strings(&data[..scan_len], self.min_length);
        let count = strings.len();
        let mut out = StageOutput::empty(self.name());
        out.message = Some(format!("extracted {count} strings"));
        result.all_strings = strings;
        out
    }
}

// ─── CompilerDetectionStage ───────────────────────────────────────────────────

/// Populate `TriageResult::compiler_hint` by substring-fingerprinting the raw image.
///
/// Recognises Rust, Go, MinGW, Delphi, MSVC. Avoids pulling
/// `rustre-loader-pe` (and its PE parser) as a dependency by inlining the
/// pattern table — the detector only needs byte-level scanning. This was the
/// second half of the MCP triage bug: the loader-pe crate had
/// `detect_compiler` but the pipeline never called it.
pub struct CompilerDetectionStage;

/// Pattern → hint label. Order matters: the FIRST match wins, so the
/// strongest fingerprints (Rust's mangled-name prefix, Go's runtime
/// markers) come first.
///
/// Pattern set expanded after Rust release builds were observed to
/// strip the canonical `core::panicking` marker — instead we look at
/// build-system metadata (Cargo's `crates\` path prefix, `.rustc`
/// section name), runtime symbols (`rust_eh_personality`,
/// `rust_panic`), and mangled-name shapes that survive optimisation.
const COMPILER_FINGERPRINTS: &[(&[u8], &str)] = &[
    // ── Rust ── strong markers first
    (b"_RNvCs", "Rust"),                    // v0 mangling crate prefix
    (b"_RNvNtCs", "Rust"),                  // v0 mangling nested module
    (b"_RINvNtCs", "Rust"),                 // v0 mangling, generic instance
    (b"rust_eh_personality", "Rust"),
    (b"rust_panic", "Rust"),
    (b"rust_begin_unwind", "Rust"),
    (b"__rustc_debug_gdb", "Rust"),
    (b"core::panicking", "Rust"),
    (b"alloc::raw_vec", "Rust"),
    (b"alloc::vec::Vec", "Rust"),
    (b"core::result::unwrap_failed", "Rust"),
    (b"core::option::expect_failed", "Rust"),
    (b"std::sys::", "Rust"),
    (b"_ZN5alloc", "Rust"),                 // legacy mangling
    (b"_ZN4core", "Rust"),
    (b"_ZN3std", "Rust"),
    (b"\\src\\main.rs", "Rust"),            // Cargo path in panic messages
    (b"/src/main.rs", "Rust"),
    (b"\\.cargo\\registry", "Rust"),         // Cargo registry path
    (b"/.cargo/registry", "Rust"),
    (b"cargo:rustc", "Rust"),
    (b"-cgu.", "Rust"),                     // Rust codegen-unit naming
    // ── Go ──
    (b"runtime.main", "Go"),
    (b"go.buildid", "Go"),
    (b"go:itab.", "Go"),
    (b"runtime.goexit", "Go"),
    // ── Delphi ──
    (b"TObject", "Delphi"),
    (b"Forms.TApplication", "Delphi"),
    (b"Borland", "Delphi/BCB"),
    // ── MinGW (must come before GCC because MinGW IS GCC + winapi) ──
    (b"__mingw_", "MinGW (GCC)"),
    (b"libgcc_s_seh", "MinGW (GCC)"),
    // ── Generic GCC/Clang ──
    (b"_ZNSt", "GCC/Clang (libstdc++)"),
    (b"_ZNKSt", "GCC/Clang (libstdc++)"),
    (b"clang version", "Clang"),
    (b"GCC: (", "GCC"),
    // ── MSVC ──
    (b"Microsoft (R) Optimizing Compiler", "MSVC"),
    (b"vcruntime", "MSVC"),
    (b"msvcrt.dll", "MSVC"),
];

impl PipelineStage for CompilerDetectionStage {
    fn name(&self) -> &'static str {
        "compiler-detection"
    }

    fn run(&self, data: &[u8], result: &mut TriageResult) -> StageOutput {
        let mut out = StageOutput::empty(self.name());
        let scan_len = data.len().min(64 * 1024 * 1024);
        let scan = &data[..scan_len];

        // Pass 1: raw-byte substring scan (catches markers in any section,
        // including ones stripped from the extracted-string list because
        // they bordered non-printable bytes).
        for (pat, label) in COMPILER_FINGERPRINTS {
            if scan.windows(pat.len()).any(|w| w == *pat) {
                result.compiler_hint = Some((*label).to_string());
                out.message = Some(format!("matched (bytes): {label}"));
                return out;
            }
        }

        // Pass 2: scan the already-extracted printable string list. The
        // raw-byte pass can miss markers when the extractor coalesces
        // adjacent non-printable padding into the string boundary —
        // searching the extracted strings catches those. Cheap because
        // `all_strings` is a `Vec<ExtractedString>` already in memory.
        for s in &result.all_strings {
            let v = s.value.as_str();
            for (pat, label) in COMPILER_FINGERPRINTS {
                if let Ok(pat_str) = std::str::from_utf8(pat)
                    && v.contains(pat_str) {
                        result.compiler_hint = Some((*label).to_string());
                        out.message = Some(format!("matched (strings): {label}"));
                        return out;
                    }
            }
        }

        out.message = Some("no compiler fingerprint matched".to_string());
        out
    }
}

// ─── TriagePipeline ───────────────────────────────────────────────────────────

/// Orchestrates the full triage pipeline.
///
/// Stages are run in insertion order. Each stage receives the accumulated
/// `TriageResult` and can add indicators to it.
pub struct TriagePipeline {
    stages: Vec<Box<dyn PipelineStage>>,
    /// Maximum number of indicators to accumulate.
    pub max_indicators: usize,
    /// Stop after this threat level is reached.
    pub stop_at: Option<ThreatLevel>,
}

impl TriagePipeline {
    /// Create an empty pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stages: Vec::new(),
            max_indicators: 512,
            stop_at: None,
        }
    }

    /// Create a pipeline pre-loaded with the default stages.
    #[must_use]
    pub fn default_pipeline() -> Self {
        let mut p = Self::new();
        p.add_stage(Box::new(FileKindStage));
        p.add_stage(Box::new(EntropyStage::new(7.2)));
        p.add_stage(Box::new(PackerDetectionStage));
        p.add_stage(Box::new(StringAnalysisStage::new(6, 4 * 1024 * 1024)));
        // ── NEW: populate `all_strings` (full string table, like
        //         the standalone `triage_core_extract_strings` tool)
        //         and `compiler_hint` (Rust/Go/MSVC/MinGW/Delphi).
        //         Previously the pipeline returned both empty.
        p.add_stage(Box::new(AllStringExtractionStage::new(4, 64 * 1024 * 1024)));
        p.add_stage(Box::new(CompilerDetectionStage));
        p.add_stage(Box::new(AntiAnalysisStage));
        p.add_stage(Box::new(ShellcodeDetectionStage));
        p.add_stage(Box::new(CryptoConstantScanStage));
        p
    }

    /// Append a stage to the pipeline.
    pub fn add_stage(&mut self, stage: Box<dyn PipelineStage>) {
        self.stages.push(stage);
    }

    /// Set the early-exit threat level.
    pub const fn stop_at(&mut self, level: ThreatLevel) {
        self.stop_at = Some(level);
    }

    /// Run the pipeline against `data` and return a fully populated result
    /// along with the per-stage outputs.
    ///
    /// # Errors
    /// Returns `TriageError::TooSmall` if `data` is empty.
    pub fn run(&self, data: &[u8]) -> Result<PipelineRunResult, TriageError> {
        if data.is_empty() {
            return Err(TriageError::TooSmall(0));
        }

        let start = Instant::now();
        let file_kind = detect_file_kind(data);
        let mut result = TriageResult::new(file_kind, data);
        let mut stage_outputs = Vec::with_capacity(self.stages.len());

        for stage in &self.stages {
            if !stage.applicable(result.file_kind) {
                stage_outputs.push(StageOutput::skipped(
                    stage.name(),
                    format!("not applicable to {:?}", result.file_kind),
                ));
                continue;
            }
            if result.indicators.len() >= self.max_indicators {
                stage_outputs.push(StageOutput::skipped(
                    stage.name(),
                    "max indicators reached",
                ));
                continue;
            }

            let stage_start = Instant::now();
            let mut output = stage.run(data, &mut result);
            output.elapsed_us = u64::try_from(stage_start.elapsed().as_micros()).unwrap_or(u64::MAX);
            stage_outputs.push(output);

            // Early exit.
            if let Some(stop) = self.stop_at
                && result.threat_level >= stop {
                    break;
                }
        }

        result.analysis_time_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        Ok(PipelineRunResult {
            result,
            stage_outputs,
        })
    }
}

impl Default for TriagePipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TriagePipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TriagePipeline({} stages)", self.stages.len())
    }
}

// ─── PipelineRunResult ────────────────────────────────────────────────────────

/// The full output of a pipeline run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineRunResult {
    /// Aggregated triage result.
    pub result: TriageResult,
    /// Per-stage outputs in execution order.
    pub stage_outputs: Vec<StageOutput>,
}

impl PipelineRunResult {
    /// Total number of indicators found.
    #[must_use]
    pub const fn indicator_count(&self) -> usize {
        self.result.indicators.len()
    }

    /// Indicators from a specific stage.
    #[must_use]
    pub fn stage_indicators(&self, stage_name: &str) -> Vec<&TriageIndicator> {
        // Find the stage output.
        let stage_out = self
            .stage_outputs
            .iter()
            .find(|s| s.stage_name == stage_name);
        stage_out.map_or_else(Vec::new, |s| s.indicators.iter().collect())
    }

    /// Names of all stages that ran.
    #[must_use]
    pub fn ran_stages(&self) -> Vec<&str> {
        self.stage_outputs
            .iter()
            .filter(|s| s.success && s.message.as_deref().is_none_or(|m| !m.starts_with("skipped")))
            .map(|s| s.stage_name.as_str())
            .collect()
    }

    /// Total pipeline execution time in microseconds (sum of stage times).
    #[must_use]
    pub fn total_stage_time_us(&self) -> u64 {
        self.stage_outputs.iter().map(|s| s.elapsed_us).sum()
    }

    /// Format a concise summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} | threat={} score={}/100 indicators={} time={}ms",
            self.result.file_kind,
            self.result.threat_level,
            self.result.score,
            self.result.indicators.len(),
            self.result.analysis_time_ms,
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_data_returns_error() {
        let pipeline = TriagePipeline::default_pipeline();
        assert!(pipeline.run(&[]).is_err());
    }

    #[test]
    fn test_default_pipeline_runs() {
        let mut data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        data.resize(64, 0);
        let pipeline = TriagePipeline::default_pipeline();
        let run = pipeline.run(&data).unwrap();
        assert!(!run.stage_outputs.is_empty());
    }

    #[test]
    fn test_entropy_stage_flags_high() {
        // A buffer with very high entropy (random-ish).
        let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let stage = EntropyStage::new(4.0);
        let mut result = TriageResult::new(FileKind::Unknown, &data);
        result.entropy = 8.0;
        let out = stage.run(&data, &mut result);
        assert!(out.indicators.iter().any(|i| i.name == "high-entropy"));
    }

    #[test]
    fn test_entropy_stage_normal() {
        let data = vec![0u8; 128];
        let stage = EntropyStage::new(7.2);
        let mut result = TriageResult::new(FileKind::Unknown, &data);
        result.entropy = 1.0;
        let out = stage.run(&data, &mut result);
        assert!(out.indicators.is_empty());
    }

    #[test]
    fn test_packer_detection_upx() {
        let mut data = vec![0u8; 128];
        data[10..14].copy_from_slice(b"UPX!");
        let stage = PackerDetectionStage;
        let mut result = TriageResult::new(FileKind::Unknown, &data);
        let out = stage.run(&data, &mut result);
        assert!(!out.indicators.is_empty());
        assert!(result.is_packed);
    }

    #[test]
    fn test_string_analysis_network_url() {
        let data = b"GET http://evil.com/payload HTTP/1.1\x00";
        let stage = StringAnalysisStage::new(4, 65536);
        let mut result = TriageResult::new(FileKind::Unknown, data);
        let out = stage.run(data, &mut result);
        assert!(out.indicators.iter().any(|i| i.name == "network-url"));
    }

    #[test]
    fn test_anti_analysis_stage() {
        let data = b"IsDebuggerPresent\x00";
        let stage = AntiAnalysisStage;
        let mut result = TriageResult::new(FileKind::Unknown, data);
        let out = stage.run(data, &mut result);
        assert!(!out.indicators.is_empty());
    }

    #[test]
    fn test_pipeline_run_result_summary() {
        let data = vec![0u8; 128];
        let pipeline = TriagePipeline::default_pipeline();
        let run = pipeline.run(&data).unwrap();
        let summary = run.summary();
        assert!(summary.contains("score="));
    }

    #[test]
    fn test_stage_output_empty() {
        let out = StageOutput::empty("test");
        assert!(out.success);
        assert!(out.indicators.is_empty());
    }

    #[test]
    fn test_stage_output_skipped() {
        let out = StageOutput::skipped("test", "no data");
        assert!(out.success);
        assert!(out.message.as_deref().unwrap().contains("skipped"));
    }

    #[test]
    fn test_stage_output_failed() {
        let out = StageOutput::failed("test", "boom");
        assert!(!out.success);
        assert!(out.message.as_deref().unwrap().contains("error"));
    }

    #[test]
    fn test_add_custom_stage() {
        struct NoopStage;
        impl PipelineStage for NoopStage {
            fn name(&self) -> &'static str { "noop" }
            fn run(&self, _data: &[u8], _result: &mut TriageResult) -> StageOutput {
                StageOutput::empty("noop")
            }
        }
        let mut p = TriagePipeline::new();
        p.add_stage(Box::new(NoopStage));
        let run = p.run(&[0u8; 32]).unwrap();
        assert_eq!(run.stage_outputs.len(), 1);
    }
}
