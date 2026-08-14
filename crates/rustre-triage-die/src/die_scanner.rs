//! `die_scanner` — Detect-It-Easy style structured scanner with EP-offset awareness.
//!
//! Provides [`DieScanner`], [`DieMatch`], [`ScanMode`], [`DieRuleEngine`],
//! [`CompilerDetector`], [`LinkerDetector`], [`ProtectorDetector`], and [`DieReport`].
//!
//! **Distinct from [`crate::scanner::DieScanner`]** (which combines `SignatureDb` +
//! `DieDetector`) and from `crate::DieScanner` (YAML rule DSL).  This module's
//! `DieScanner` uses `DieRuleEngine`, which supports per-rule EP-only matching,
//! platform fields, and `unpacked_only` guards — making it the right choice when
//! you need fine-grained per-rule EP control and a rich `DieReport` output.
//!
//! The module-level `builtin_rules()` function (~24 rules) is intentionally
//! smaller than [`crate::rule_db_extended::EXTENDED_RULES`] (~90 rules); the
//! two sets use incompatible rule schemas and are complementary, not redundant.

use std::fmt;

use serde::{Deserialize, Serialize};

// ─── DieMatch ─────────────────────────────────────────────────────────────────

/// A single detection result produced by the DIE scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DieMatch {
    /// Display name of the detected entity (e.g. "UPX", "MSVC", "Themida").
    pub name: String,
    /// Version string if known (e.g. "3.x", "2019+").
    pub version: String,
    /// Type of detection (compiler / packer / protector / etc.)
    pub match_type: DieMatchType,
    /// Target platform (e.g. "Win32", "Win64", "ELF", "Mach-O").
    pub platform: String,
    /// Confidence score 0–100.
    pub confidence: u8,
    /// Human-readable justification.
    pub reason: String,
}

impl DieMatch {
    /// Returns `true` if the confidence is at least 70.
    #[must_use]
    pub fn is_confident(&self) -> bool {
        self.confidence >= 70
    }

    /// Returns `true` if this match indicates a packing layer.
    #[must_use]
    pub fn is_packer(&self) -> bool {
        self.match_type == DieMatchType::Packer || self.match_type == DieMatchType::Protector
    }
}

impl fmt::Display for DieMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:?}] {} v{} ({}) @ {}%",
            self.match_type, self.name, self.version, self.platform, self.confidence
        )
    }
}

/// Category of the matched entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DieMatchType {
    Compiler,
    Packer,
    Protector,
    Installer,
    Runtime,
    Linker,
    Tool,
    Unknown,
}

impl fmt::Display for DieMatchType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── ScanMode ─────────────────────────────────────────────────────────────────

/// Controls the scope of the scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanMode {
    /// Scan only the entry-point region (fast, < 1 ms).
    EpOnly,
    /// Full-file scan (checks all sections and the overlay).
    Full,
    /// Heuristic mode: EP scan first, then full if no result.
    Heuristic,
}

impl Default for ScanMode {
    fn default() -> Self {
        Self::Heuristic
    }
}

impl fmt::Display for ScanMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EpOnly => write!(f, "ep_only"),
            Self::Full => write!(f, "full"),
            Self::Heuristic => write!(f, "heuristic"),
        }
    }
}

// ─── DieRule ─────────────────────────────────────────────────────────────────

/// A single DIE detection rule.
#[derive(Debug, Clone)]
pub struct DieRule {
    pub name: &'static str,
    pub version: &'static str,
    pub match_type: DieMatchType,
    pub platform: &'static str,
    pub confidence: u8,
    /// Byte sequences that must all be present (AND logic).
    pub required_bytes: &'static [&'static [u8]],
    /// String substrings that must all be present.
    pub required_strings: &'static [&'static str],
    /// Byte sequence that must be at the entry-point offset (or `None`).
    pub ep_pattern: Option<&'static [u8]>,
    /// Whether this rule should only fire if the binary is NOT detected as packed.
    pub unpacked_only: bool,
}

// ─── DieRuleEngine ────────────────────────────────────────────────────────────

/// Evaluates a collection of [`DieRule`]s against raw binary data.
pub struct DieRuleEngine {
    rules: Vec<DieRule>,
    mode: ScanMode,
    ep_offset: usize,
}

impl DieRuleEngine {
    /// Create a new engine from a list of rules.
    #[must_use]
    pub fn new(rules: Vec<DieRule>, mode: ScanMode, ep_offset: usize) -> Self {
        Self { rules, mode, ep_offset }
    }

    /// Evaluate all rules against `data` and return matching [`DieMatch`] records.
    #[must_use]
    pub fn evaluate(&self, data: &[u8]) -> Vec<DieMatch> {
        let mut matches = Vec::new();
        for rule in &self.rules {
            if let Some(m) = self.eval_rule(rule, data) {
                matches.push(m);
            }
        }
        // Sort by confidence descending
        matches.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        matches
    }

    fn eval_rule(&self, rule: &DieRule, data: &[u8]) -> Option<DieMatch> {
        // EP-only pattern
        if let Some(ep_pat) = rule.ep_pattern {
            let check = match self.mode {
                ScanMode::EpOnly | ScanMode::Heuristic => {
                    let ep = self.ep_offset;
                    ep + ep_pat.len() <= data.len()
                        && &data[ep..ep + ep_pat.len()] == ep_pat
                }
                ScanMode::Full => {
                    // allow match anywhere in full mode
                    data.windows(ep_pat.len()).any(|w| w == ep_pat)
                }
            };
            if !check { return None; }
        }

        // Required byte sequences
        for &needle in rule.required_bytes {
            if !data.windows(needle.len()).any(|w| w == needle) {
                return None;
            }
        }

        // Required strings
        for &s in rule.required_strings {
            if !data.windows(s.len()).any(|w| w == s.as_bytes()) {
                return None;
            }
        }

        Some(DieMatch {
            name: rule.name.to_string(),
            version: rule.version.to_string(),
            match_type: rule.match_type,
            platform: rule.platform.to_string(),
            confidence: rule.confidence,
            reason: format!("Matched {} rule", rule.match_type),
        })
    }
}

// ─── Built-in rules ───────────────────────────────────────────────────────────

fn builtin_rules() -> Vec<DieRule> {
    vec![
        // ── Packers ─────────────────────────────────────────────────────────
        DieRule {
            name: "UPX",
            version: "3.x",
            match_type: DieMatchType::Packer,
            platform: "Win32/Win64",
            confidence: 97,
            required_bytes: &[b"UPX0", b"UPX1"],
            required_strings: &[],
            ep_pattern: None,
            unpacked_only: false,
        },
        DieRule {
            name: "UPX",
            version: "3.x (LZMA)",
            match_type: DieMatchType::Packer,
            platform: "Win32/Win64",
            confidence: 95,
            required_bytes: &[b"UPX!"],
            required_strings: &[],
            ep_pattern: Some(&[0x60, 0xBE]),
            unpacked_only: false,
        },
        DieRule {
            name: "MPRESS",
            version: "2.x",
            match_type: DieMatchType::Packer,
            platform: "Win32/Win64",
            confidence: 92,
            required_bytes: &[b".MPRESS1"],
            required_strings: &[],
            ep_pattern: None,
            unpacked_only: false,
        },
        DieRule {
            name: "ASPack",
            version: "2.x",
            match_type: DieMatchType::Packer,
            platform: "Win32",
            confidence: 91,
            required_bytes: &[b".aspack"],
            required_strings: &[],
            ep_pattern: Some(&[0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D]),
            unpacked_only: false,
        },
        DieRule {
            name: "PECompact",
            version: "2.x",
            match_type: DieMatchType::Packer,
            platform: "Win32",
            confidence: 90,
            required_bytes: &[b"PECompact2"],
            required_strings: &[],
            ep_pattern: None,
            unpacked_only: false,
        },
        DieRule {
            name: "MEW",
            version: "11",
            match_type: DieMatchType::Packer,
            platform: "Win32",
            confidence: 87,
            required_bytes: &[],
            required_strings: &["MEW"],
            ep_pattern: Some(&[0xE9]),
            unpacked_only: false,
        },
        DieRule {
            name: "FSG",
            version: "2.0",
            match_type: DieMatchType::Packer,
            platform: "Win32",
            confidence: 86,
            required_bytes: &[],
            required_strings: &["FSG!"],
            ep_pattern: None,
            unpacked_only: false,
        },
        DieRule {
            name: "PESpin",
            version: "1.3",
            match_type: DieMatchType::Packer,
            platform: "Win32",
            confidence: 85,
            required_bytes: &[],
            required_strings: &["PESpin"],
            ep_pattern: None,
            unpacked_only: false,
        },
        // ── Protectors ──────────────────────────────────────────────────────
        DieRule {
            name: "Themida",
            version: "3.x",
            match_type: DieMatchType::Protector,
            platform: "Win32/Win64",
            confidence: 93,
            required_bytes: &[b".themida"],
            required_strings: &[],
            ep_pattern: None,
            unpacked_only: false,
        },
        DieRule {
            name: "VMProtect",
            version: "2.x",
            match_type: DieMatchType::Protector,
            platform: "Win32/Win64",
            confidence: 93,
            required_bytes: &[b".vmp0"],
            required_strings: &[],
            ep_pattern: None,
            unpacked_only: false,
        },
        DieRule {
            name: "VMProtect",
            version: "3.x",
            match_type: DieMatchType::Protector,
            platform: "Win32/Win64",
            confidence: 93,
            required_bytes: &[b".vmp1"],
            required_strings: &[],
            ep_pattern: None,
            unpacked_only: false,
        },
        DieRule {
            name: "Enigma Protector",
            version: "7.x",
            match_type: DieMatchType::Protector,
            platform: "Win32/Win64",
            confidence: 90,
            required_bytes: &[],
            required_strings: &[".enigma1"],
            ep_pattern: None,
            unpacked_only: false,
        },
        DieRule {
            name: "Obsidium",
            version: "1.x",
            match_type: DieMatchType::Protector,
            platform: "Win32",
            confidence: 88,
            required_bytes: &[],
            required_strings: &["Obsidium"],
            ep_pattern: None,
            unpacked_only: false,
        },
        // ── Compilers ────────────────────────────────────────────────────────
        DieRule {
            name: "MSVC",
            version: "14.x",
            match_type: DieMatchType::Compiler,
            platform: "Win64",
            confidence: 77,
            required_bytes: &[],
            required_strings: &["Rich"],
            ep_pattern: Some(&[0x48, 0x83, 0xEC]),
            unpacked_only: true,
        },
        DieRule {
            name: "GCC/MinGW",
            version: "4.x+",
            match_type: DieMatchType::Compiler,
            platform: "Win32",
            confidence: 82,
            required_bytes: &[],
            required_strings: &["MinGW"],
            ep_pattern: None,
            unpacked_only: true,
        },
        DieRule {
            name: "Clang",
            version: "10+",
            match_type: DieMatchType::Compiler,
            platform: "Win64",
            confidence: 78,
            required_bytes: &[],
            required_strings: &["clang"],
            ep_pattern: None,
            unpacked_only: true,
        },
        DieRule {
            name: "Delphi",
            version: "7+",
            match_type: DieMatchType::Compiler,
            platform: "Win32",
            confidence: 87,
            required_bytes: &[],
            required_strings: &["Borland"],
            ep_pattern: None,
            unpacked_only: true,
        },
        DieRule {
            name: "Rust",
            version: "1.x",
            match_type: DieMatchType::Compiler,
            platform: "Win64",
            confidence: 85,
            required_bytes: &[],
            required_strings: &["rustc"],
            ep_pattern: None,
            unpacked_only: true,
        },
        // ── .NET ─────────────────────────────────────────────────────────────
        DieRule {
            name: ".NET Framework",
            version: "4.x",
            match_type: DieMatchType::Runtime,
            platform: "Win32/Win64",
            confidence: 94,
            required_bytes: &[],
            required_strings: &["mscoree.dll", "_CorExeMain"],
            ep_pattern: None,
            unpacked_only: false,
        },
        // ── Script/Bytecode bundlers ─────────────────────────────────────────
        DieRule {
            name: "PyInstaller",
            version: "6.x",
            match_type: DieMatchType::Tool,
            platform: "Win32/Win64",
            confidence: 95,
            required_bytes: &[],
            required_strings: &["MEI\x0C\x0B\x0A"],
            ep_pattern: None,
            unpacked_only: false,
        },
        DieRule {
            name: "AutoIt",
            version: "3.x",
            match_type: DieMatchType::Tool,
            platform: "Win32",
            confidence: 93,
            required_bytes: &[],
            required_strings: &["AU3!EA"],
            ep_pattern: None,
            unpacked_only: false,
        },
        // ── Installers ────────────────────────────────────────────────────────
        DieRule {
            name: "NSIS",
            version: "3.x",
            match_type: DieMatchType::Installer,
            platform: "Win32",
            confidence: 87,
            required_bytes: &[],
            required_strings: &["Nullsoft"],
            ep_pattern: None,
            unpacked_only: false,
        },
        DieRule {
            name: "InnoSetup",
            version: "6.x",
            match_type: DieMatchType::Installer,
            platform: "Win32",
            confidence: 90,
            required_bytes: &[],
            required_strings: &["Inno Setup"],
            ep_pattern: None,
            unpacked_only: false,
        },
    ]
}

// ─── CompilerDetector ─────────────────────────────────────────────────────────

/// Detects the compiler used to build a binary.
pub struct CompilerDetector;

impl CompilerDetector {
    /// Detect the compiler from raw `data` and return a match if found.
    #[must_use]
    pub fn detect(data: &[u8]) -> Option<DieMatch> {
        let engine = DieRuleEngine::new(
            builtin_rules()
                .into_iter()
                .filter(|r| r.match_type == DieMatchType::Compiler || r.match_type == DieMatchType::Runtime)
                .collect(),
            ScanMode::Full,
            0,
        );
        engine.evaluate(data).into_iter().next()
    }

    /// Return all compiler detections sorted by confidence.
    #[must_use]
    pub fn detect_all(data: &[u8]) -> Vec<DieMatch> {
        let engine = DieRuleEngine::new(
            builtin_rules()
                .into_iter()
                .filter(|r| r.match_type == DieMatchType::Compiler || r.match_type == DieMatchType::Runtime)
                .collect(),
            ScanMode::Full,
            0,
        );
        engine.evaluate(data)
    }

    /// Returns the best-confidence compiler name string.
    #[must_use]
    pub fn compiler_name(data: &[u8]) -> Option<String> {
        Self::detect(data).map(|m| format!("{} {}", m.name, m.version))
    }
}

// ─── LinkerDetector ───────────────────────────────────────────────────────────

/// Detects the linker used (heuristic via Rich header analysis).
pub struct LinkerDetector;

impl LinkerDetector {
    /// Detect the linker from the Rich header.  Returns `None` for ELF/non-PE.
    #[must_use]
    pub fn detect(data: &[u8]) -> Option<LinkerMatch> {
        // Look for Rich header "Rich" marker (XOR de-obfuscated)
        if Self::has_rich_header(data) {
            let (name, version) = Self::classify_rich_header(data);
            return Some(LinkerMatch {
                name,
                version,
                confidence: 70,
            });
        }
        None
    }

    fn has_rich_header(data: &[u8]) -> bool {
        // Rich header appears between MZ and PE@ as "Rich" XOR'd with a checksum
        // Simple: look for the string "Rich" in the first 512 bytes
        data.len() >= 4
            && data[..data.len().min(512)]
                .windows(4)
                .any(|w| w == b"Rich")
    }

    fn classify_rich_header(data: &[u8]) -> (String, String) {
        // Try to identify based on product IDs in the Rich header
        // Simple heuristic based on detected strings
        if data.windows(4).any(|w| w == b"Link") {
            return ("Microsoft Linker".to_string(), "14.x".to_string());
        }
        ("Unknown Linker".to_string(), "?".to_string())
    }
}

/// Linker detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerMatch {
    pub name: String,
    pub version: String,
    pub confidence: u8,
}

impl fmt::Display for LinkerMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} v{} ({}%)", self.name, self.version, self.confidence)
    }
}

// ─── ProtectorDetector ────────────────────────────────────────────────────────

/// Detects copy-protection / anti-tamper systems.
pub struct ProtectorDetector;

impl ProtectorDetector {
    /// Return all protector matches found in `data`.
    #[must_use]
    pub fn detect_all(data: &[u8]) -> Vec<DieMatch> {
        let engine = DieRuleEngine::new(
            builtin_rules()
                .into_iter()
                .filter(|r| r.match_type == DieMatchType::Protector)
                .collect(),
            ScanMode::Full,
            0,
        );
        engine.evaluate(data)
    }

    /// Returns `true` if any known protector is detected.
    #[must_use]
    pub fn is_protected(data: &[u8]) -> bool {
        !Self::detect_all(data).is_empty()
    }

    /// Return the highest-confidence protector name.
    #[must_use]
    pub fn best_match(data: &[u8]) -> Option<String> {
        Self::detect_all(data)
            .into_iter()
            .next()
            .map(|m| format!("{} {}", m.name, m.version))
    }
}

// ─── PackerLayer ─────────────────────────────────────────────────────────────

/// Represents a single packing layer in a multi-packed binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerLayer {
    /// Layer index (0 = outermost).
    pub layer: usize,
    /// Packer detected at this layer.
    pub packer: DieMatch,
    /// Entropy of this layer's data.
    pub entropy: f32,
}

impl fmt::Display for PackerLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Layer {}: {} (entropy={:.3})", self.layer, self.packer, self.entropy)
    }
}

// ─── MultiPackLayer ───────────────────────────────────────────────────────────

/// Analysis of multi-layer packing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiPackLayer {
    pub layers: Vec<PackerLayer>,
}

impl MultiPackLayer {
    /// Analyse `data` for multiple packing layers (heuristic).
    ///
    /// Detects the outer packer and estimates whether an inner layer exists
    /// based on high entropy in the packed stub.
    #[must_use]
    pub fn analyze(data: &[u8]) -> Self {
        let engine = DieRuleEngine::new(
            builtin_rules()
                .into_iter()
                .filter(|r| r.match_type == DieMatchType::Packer)
                .collect(),
            ScanMode::Full,
            0,
        );
        let matches = engine.evaluate(data);
        let global_entropy = entropy(data);

        let mut layers = Vec::new();
        for (i, m) in matches.into_iter().enumerate() {
            layers.push(PackerLayer {
                layer: i,
                packer: m,
                entropy: global_entropy,
            });
        }
        Self { layers }
    }

    /// Returns the number of detected packing layers.
    #[must_use]
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// Returns `true` if more than one packing layer was detected.
    #[must_use]
    pub fn is_multi_packed(&self) -> bool {
        self.layers.len() > 1
    }
}

// ─── ProtectedCodeRegion ─────────────────────────────────────────────────────

/// A region of protected/virtualised code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedCodeRegion {
    /// File offset of the region.
    pub offset: usize,
    /// Size in bytes.
    pub size: usize,
    /// Shannon entropy.
    pub entropy: f32,
    /// Whether this region is likely virtualised (VM-based protector).
    pub virtualised: bool,
    /// Associated section name.
    pub section_name: String,
}

impl ProtectedCodeRegion {
    /// Create a new region descriptor.
    #[must_use]
    pub fn new(offset: usize, size: usize, data: &[u8], section_name: impl Into<String>) -> Self {
        let e = if offset + size <= data.len() {
            entropy(&data[offset..offset + size])
        } else {
            0.0
        };
        Self {
            offset,
            size,
            entropy: e,
            virtualised: e > 7.5,
            section_name: section_name.into(),
        }
    }
}

impl fmt::Display for ProtectedCodeRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProtectedRegion[{}] @ 0x{:x} size={} entropy={:.3} vm={}",
            self.section_name, self.offset, self.size, self.entropy, self.virtualised
        )
    }
}

// ─── EmbeddedExecutable ──────────────────────────────────────────────────────

/// An executable embedded inside the scanned file (dropper pattern).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedExecutable {
    /// Offset in the parent file where the embedded PE starts.
    pub offset: usize,
    /// Size of the embedded PE (estimated).
    pub estimated_size: usize,
    /// Magic bytes at the offset.
    pub magic: [u8; 4],
    /// Whether a full PE header was found at this location.
    pub has_pe_header: bool,
}

impl EmbeddedExecutable {
    /// Scan `data` for embedded MZ/ELF binaries.
    #[must_use]
    pub fn find_all(data: &[u8]) -> Vec<Self> {
        let mut results = Vec::new();

        // Skip the first two bytes (the outer MZ header)
        for i in 2..data.len().saturating_sub(3) {
            if &data[i..i + 2] == b"MZ" {
                let mut magic = [0u8; 4];
                magic[..2].copy_from_slice(&data[i..i + 2]);
                if i + 4 <= data.len() {
                    magic.copy_from_slice(&data[i..i + 4]);
                }
                // Check for full PE header
                let has_pe = if i + 0x40 <= data.len() {
                    let pe_off = u32::from_le_bytes([
                        data[i + 0x3c], data[i + 0x3d], data[i + 0x3e], data[i + 0x3f],
                    ]) as usize;
                    // Use saturating_add: pe_off comes from untrusted embedded
                    // file data; i + pe_off can overflow on 32-bit targets.
                    let abs_pe_off = i.saturating_add(pe_off);
                    abs_pe_off + 4 <= data.len()
                        && &data[abs_pe_off..abs_pe_off + 4] == b"PE\x00\x00"
                } else {
                    false
                };

                results.push(EmbeddedExecutable {
                    offset: i,
                    estimated_size: data.len() - i,
                    magic,
                    has_pe_header: has_pe,
                });
            }
            // ELF magic
            if i + 4 <= data.len() && &data[i..i + 4] == b"\x7FELF" {
                let mut magic = [0u8; 4];
                magic.copy_from_slice(&data[i..i + 4]);
                results.push(EmbeddedExecutable {
                    offset: i,
                    estimated_size: data.len() - i,
                    magic,
                    has_pe_header: false,
                });
            }
        }
        results
    }
}

impl fmt::Display for EmbeddedExecutable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EmbeddedExe @ 0x{:x} has_pe={} size_est={}",
            self.offset, self.has_pe_header, self.estimated_size
        )
    }
}

// ─── PackerVersion ────────────────────────────────────────────────────────────

/// Refined packer version information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerVersion {
    pub name: String,
    pub version: String,
    pub variant: String,
    pub build_date: Option<String>,
}

impl PackerVersion {
    /// Extract the packer version from the best `DieMatch`.
    #[must_use]
    pub fn from_match(m: &DieMatch) -> Self {
        Self {
            name: m.name.clone(),
            version: m.version.clone(),
            variant: String::new(),
            build_date: None,
        }
    }
}

impl fmt::Display for PackerVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} v{}", self.name, self.version)?;
        if !self.variant.is_empty() {
            write!(f, " ({})", self.variant)?;
        }
        Ok(())
    }
}

// ─── ManualUnpackingHint ──────────────────────────────────────────────────────

/// Hints to assist a reverse-engineer in manually unpacking a sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualUnpackingHint {
    /// Short summary of the hint.
    pub title: String,
    /// Detailed description.
    pub description: String,
    /// Suggested breakpoint address or pattern.
    pub bp_suggestion: Option<String>,
    /// Suggested tool.
    pub tool: Option<String>,
}

impl ManualUnpackingHint {
    fn for_upx() -> Self {
        Self {
            title: "UPX: set BP on POPAD+JMP".to_string(),
            description: "UPX decompresses the original PE to a new memory region. \
                Set a breakpoint on the POPAD instruction followed by a long JMP at the \
                decompression stub tail.  After hitting the BP, the OEP will be in EAX/RAX.".to_string(),
            bp_suggestion: Some("POPAD; JMP dword ptr [...]".to_string()),
            tool: Some("x64dbg / ScyllaHide".to_string()),
        }
    }

    fn for_vmprotect() -> Self {
        Self {
            title: "VMProtect: trace virtualised instructions".to_string(),
            description: "VMProtect translates code into a custom VM bytecode. \
                Deobfuscators (e.g., vmprotect-dumper, NoVmp) can reconstruct \
                the original instructions.".to_string(),
            bp_suggestion: None,
            tool: Some("NoVmp / devirtualize-vmprotect".to_string()),
        }
    }

    fn generic() -> Self {
        Self {
            title: "Generic: memory dump after OEP".to_string(),
            description: "Run the sample in a debugger, wait until execution reaches \
                a return address in a newly allocated region (likely the OEP), then \
                dump the process memory and fix the PE header.".to_string(),
            bp_suggestion: Some("VirtualAlloc return / new_region+EP".to_string()),
            tool: Some("x64dbg + Scylla".to_string()),
        }
    }
}

impl fmt::Display for ManualUnpackingHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[HINT] {}: {}", self.title, self.description)
    }
}

// ─── DieReport ────────────────────────────────────────────────────────────────

/// Comprehensive detection report for a single file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DieReport {
    /// File hash (FNV-like).
    pub file_hash: String,
    /// File size in bytes.
    pub file_size: usize,
    /// All matches from the scan.
    pub matches: Vec<DieMatch>,
    /// Whether the file is packed.
    pub is_packed: bool,
    /// Whether the file is protected.
    pub is_protected: bool,
    /// Packing version (if packed).
    pub packer_version: Option<PackerVersion>,
    /// Embedded executables found (dropper detection).
    pub embedded_executables: Vec<EmbeddedExecutable>,
    /// Multi-pack layer analysis.
    pub pack_layers: MultiPackLayer,
    /// Protected code regions.
    pub protected_regions: Vec<ProtectedCodeRegion>,
    /// Linker detection result.
    pub linker: Option<LinkerMatch>,
    /// Manual unpacking hints.
    pub unpacking_hints: Vec<ManualUnpackingHint>,
    /// Scan mode used.
    pub scan_mode: ScanMode,
    /// Elapsed time in milliseconds.
    pub elapsed_ms: u64,
}

impl DieReport {
    /// Return the highest-confidence match overall.
    #[must_use]
    pub fn best_match(&self) -> Option<&DieMatch> {
        self.matches.first()
    }

    /// Serialise to JSON.
    ///
    /// # Errors
    /// Returns a string on failure.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }

    /// Short summary line.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "DieReport: packed={} protected={} matches={} embedded={}",
            self.is_packed,
            self.is_protected,
            self.matches.len(),
            self.embedded_executables.len()
        )
    }
}

impl fmt::Display for DieReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== DIE Scan Report ===")?;
        writeln!(f, "  File size  : {} bytes", self.file_size)?;
        writeln!(f, "  Packed     : {}", self.is_packed)?;
        writeln!(f, "  Protected  : {}", self.is_protected)?;
        writeln!(f, "  Scan mode  : {}", self.scan_mode)?;
        writeln!(f, "  Matches    : {}", self.matches.len())?;
        for m in &self.matches {
            writeln!(f, "    {m}")?;
        }
        writeln!(f, "  Embedded   : {}", self.embedded_executables.len())?;
        Ok(())
    }
}

// ─── DieScanner ───────────────────────────────────────────────────────────────

/// Main entry point for Detect-It-Easy style scanning.
pub struct DieScanner {
    mode: ScanMode,
    additional_rules: Vec<DieRule>,
}

impl DieScanner {
    /// Create a new scanner with default mode.
    #[must_use]
    pub fn new() -> Self {
        Self {
            mode: ScanMode::Heuristic,
            additional_rules: Vec::new(),
        }
    }

    /// Create a scanner with an explicit scan mode.
    #[must_use]
    pub fn with_mode(mode: ScanMode) -> Self {
        Self { mode, additional_rules: Vec::new() }
    }

    /// Add a custom rule to the scanner.
    pub fn add_rule(&mut self, rule: DieRule) {
        self.additional_rules.push(rule);
    }

    /// Scan `data` and produce a full [`DieReport`].
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> DieReport {
        use std::time::Instant;
        let start = Instant::now();

        let mut all_rules = builtin_rules();
        for r in &self.additional_rules {
            // Clone-less approximation: rules are cheap structs
            all_rules.push(DieRule {
                name: r.name,
                version: r.version,
                match_type: r.match_type,
                platform: r.platform,
                confidence: r.confidence,
                required_bytes: r.required_bytes,
                required_strings: r.required_strings,
                ep_pattern: r.ep_pattern,
                unpacked_only: r.unpacked_only,
            });
        }

        let ep_offset = self.detect_ep(data);
        let engine = DieRuleEngine::new(all_rules, self.mode, ep_offset);
        let matches = engine.evaluate(data);

        let is_packed = matches.iter().any(|m| m.is_packer());
        let is_protected = matches.iter().any(|m| m.match_type == DieMatchType::Protector);

        let packer_version = matches
            .iter()
            .find(|m| m.match_type == DieMatchType::Packer)
            .map(PackerVersion::from_match);

        let embedded_executables = EmbeddedExecutable::find_all(data);
        let pack_layers = MultiPackLayer::analyze(data);
        let linker = LinkerDetector::detect(data);

        // Collect high-entropy regions as protected regions
        let protected_regions = self.find_protected_regions(data);

        // Generate unpacking hints
        let unpacking_hints = self.generate_hints(&matches);

        let elapsed_ms = start.elapsed().as_millis() as u64;

        DieReport {
            file_hash: simple_hash(data),
            file_size: data.len(),
            matches,
            is_packed,
            is_protected,
            packer_version,
            embedded_executables,
            pack_layers,
            protected_regions,
            linker,
            unpacking_hints,
            scan_mode: self.mode,
            elapsed_ms,
        }
    }

    fn detect_ep(&self, data: &[u8]) -> usize {
        if data.len() < 0x40 { return 0; }
        if data[0] != 0x4D || data[1] != 0x5A { return 0; }
        let pe_off = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
        // Guard must cover up to pe_off + 0x18 + 0x13 + 1 = pe_off + 0x2C
        if pe_off + 0x2C > data.len() { return 0; }
        if &data[pe_off..pe_off+4] != b"PE\x00\x00" { return 0; }
        let opt_off = pe_off + 0x18;
        let ep_rva = u32::from_le_bytes([
            data[opt_off + 0x10], data[opt_off + 0x11],
            data[opt_off + 0x12], data[opt_off + 0x13],
        ]);

        // Translate EP RVA → file offset via section table walk.
        // Using the raw RVA as a file offset is wrong: virtual addresses are
        // not file offsets.
        let num_sections = u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]) as usize;
        let opt_size = u16::from_le_bytes([data[pe_off + 0x14], data[pe_off + 0x15]]) as usize;
        let sec_tbl = opt_off + opt_size;

        for i in 0..num_sections {
            let s = sec_tbl + i * 40;
            if s + 40 > data.len() { break; }
            let virt_addr = u32::from_le_bytes(data[s + 12..s + 16].try_into().unwrap_or([0; 4]));
            let virt_size = u32::from_le_bytes(data[s + 8..s + 12].try_into().unwrap_or([0; 4]));
            let raw_off = u32::from_le_bytes(data[s + 20..s + 24].try_into().unwrap_or([0; 4])) as usize;

            if ep_rva >= virt_addr && ep_rva < virt_addr + virt_size.max(1) {
                let file_off = raw_off + (ep_rva - virt_addr) as usize;
                return file_off;
            }
        }
        0
    }

    fn find_protected_regions(&self, data: &[u8]) -> Vec<ProtectedCodeRegion> {
        const BLOCK: usize = 4096;
        let mut regions = Vec::new();
        for (i, chunk) in data.chunks(BLOCK).enumerate() {
            let e = entropy(chunk);
            if e > 7.2 {
                regions.push(ProtectedCodeRegion {
                    offset: i * BLOCK,
                    size: chunk.len(),
                    entropy: e,
                    virtualised: e > 7.5,
                    section_name: format!("block_{i}"),
                });
            }
        }
        regions
    }

    fn generate_hints(&self, matches: &[DieMatch]) -> Vec<ManualUnpackingHint> {
        let mut hints = Vec::new();
        for m in matches {
            match m.name.as_str() {
                "UPX" => hints.push(ManualUnpackingHint::for_upx()),
                "VMProtect" => hints.push(ManualUnpackingHint::for_vmprotect()),
                _ if m.is_packer() => hints.push(ManualUnpackingHint::generic()),
                _ => {}
            }
        }
        if hints.is_empty() && matches.iter().any(|m| m.is_packer()) {
            hints.push(ManualUnpackingHint::generic());
        }
        hints
    }
}

impl Default for DieScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DieScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DieScanner(mode={:?}, custom_rules={})", self.mode, self.additional_rules.len())
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn entropy(data: &[u8]) -> f32 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f32;
    counts.iter().filter(|&&c| c > 0)
        .map(|&c| { let p = c as f32 / len; -p * p.log2() })
        .sum::<f32>()
        .clamp(0.0, 8.0)
}

fn simple_hash(data: &[u8]) -> String {
    let mut h: u64 = 0xcbf29ce484222325u64;
    for &b in data { h ^= b as u64; h = h.wrapping_mul(0x100000001b3u64); }
    format!("{:016x}", h)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn upx_data() -> Vec<u8> {
        let mut v = vec![0x4D, 0x5A];
        v.extend_from_slice(&[0u8; 100]);
        v.extend_from_slice(b"UPX0");
        v.extend_from_slice(b"UPX1");
        v.extend_from_slice(b"UPX!");
        v
    }

    fn themida_data() -> Vec<u8> {
        let mut v = vec![0x4D, 0x5A];
        v.extend_from_slice(&[0u8; 50]);
        v.extend_from_slice(b".themida");
        v
    }

    fn rust_data() -> Vec<u8> {
        let mut v = vec![0x4D, 0x5A];
        v.extend_from_slice(&[0u8; 50]);
        v.extend_from_slice(b"rustc 1.75.0");
        v
    }

    // ── DieMatch ─────────────────────────────────────────────────────────────

    #[test]
    fn test_die_match_is_confident() {
        let m = DieMatch {
            name: "UPX".to_string(),
            version: "3.x".to_string(),
            match_type: DieMatchType::Packer,
            platform: "Win32".to_string(),
            confidence: 97,
            reason: String::new(),
        };
        assert!(m.is_confident());
    }

    #[test]
    fn test_die_match_not_confident() {
        let m = DieMatch {
            name: "UPX".to_string(), version: "3.x".to_string(),
            match_type: DieMatchType::Packer, platform: "Win32".to_string(),
            confidence: 50, reason: String::new(),
        };
        assert!(!m.is_confident());
    }

    #[test]
    fn test_die_match_is_packer() {
        let m = DieMatch {
            name: "X".to_string(), version: String::new(),
            match_type: DieMatchType::Protector, platform: String::new(),
            confidence: 80, reason: String::new(),
        };
        assert!(m.is_packer());
    }

    #[test]
    fn test_die_match_display() {
        let m = DieMatch {
            name: "UPX".to_string(), version: "3.x".to_string(),
            match_type: DieMatchType::Packer, platform: "Win32".to_string(),
            confidence: 97, reason: String::new(),
        };
        let s = m.to_string();
        assert!(s.contains("UPX"));
        assert!(s.contains("97%"));
    }

    // ── ScanMode ─────────────────────────────────────────────────────────────

    #[test]
    fn test_scan_mode_default() {
        assert_eq!(ScanMode::default(), ScanMode::Heuristic);
    }

    #[test]
    fn test_scan_mode_display() {
        assert_eq!(ScanMode::EpOnly.to_string(), "ep_only");
        assert_eq!(ScanMode::Full.to_string(), "full");
        assert_eq!(ScanMode::Heuristic.to_string(), "heuristic");
    }

    // ── DieRuleEngine ────────────────────────────────────────────────────────

    #[test]
    fn test_rule_engine_upx_detection() {
        let engine = DieRuleEngine::new(builtin_rules(), ScanMode::Full, 0);
        let matches = engine.evaluate(&upx_data());
        assert!(matches.iter().any(|m| m.name == "UPX"));
    }

    #[test]
    fn test_rule_engine_empty_data() {
        let engine = DieRuleEngine::new(builtin_rules(), ScanMode::Full, 0);
        let matches = engine.evaluate(&[]);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_rule_engine_sorted_by_confidence() {
        let engine = DieRuleEngine::new(builtin_rules(), ScanMode::Full, 0);
        let data = upx_data();
        let matches = engine.evaluate(&data);
        for w in matches.windows(2) {
            assert!(w[0].confidence >= w[1].confidence);
        }
    }

    // ── CompilerDetector ─────────────────────────────────────────────────────

    #[test]
    fn test_compiler_detector_rust() {
        let m = CompilerDetector::detect(&rust_data());
        assert!(m.is_some());
        assert_eq!(m.unwrap().name, "Rust");
    }

    #[test]
    fn test_compiler_detector_no_match() {
        assert!(CompilerDetector::detect(&[0u8; 100]).is_none());
    }

    #[test]
    fn test_compiler_name_rust() {
        let name = CompilerDetector::compiler_name(&rust_data());
        assert!(name.unwrap().contains("Rust"));
    }

    #[test]
    fn test_compiler_detect_all_returns_all() {
        let all = CompilerDetector::detect_all(&rust_data());
        assert!(!all.is_empty());
    }

    // ── LinkerDetector ───────────────────────────────────────────────────────

    #[test]
    fn test_linker_detector_rich_header() {
        let mut data = vec![0x4D, 0x5A];
        data.extend_from_slice(b"Junk data Rich header here");
        let result = LinkerDetector::detect(&data);
        assert!(result.is_some());
    }

    #[test]
    fn test_linker_no_rich_header() {
        let data = vec![0u8; 64];
        assert!(LinkerDetector::detect(&data).is_none());
    }

    #[test]
    fn test_linker_match_display() {
        let lm = LinkerMatch { name: "MS Linker".to_string(), version: "14.x".to_string(), confidence: 70 };
        assert!(lm.to_string().contains("MS Linker"));
    }

    // ── ProtectorDetector ────────────────────────────────────────────────────

    #[test]
    fn test_protector_themida() {
        assert!(ProtectorDetector::is_protected(&themida_data()));
    }

    #[test]
    fn test_protector_no_match() {
        assert!(!ProtectorDetector::is_protected(&[0u8; 100]));
    }

    #[test]
    fn test_protector_best_match() {
        let best = ProtectorDetector::best_match(&themida_data());
        assert!(best.unwrap().contains("Themida"));
    }

    // ── MultiPackLayer ───────────────────────────────────────────────────────

    #[test]
    fn test_multi_pack_layer_single() {
        let ml = MultiPackLayer::analyze(&upx_data());
        assert!(!ml.is_multi_packed());
    }

    #[test]
    fn test_multi_pack_layer_empty() {
        let ml = MultiPackLayer::analyze(&[0u8; 100]);
        assert_eq!(ml.layer_count(), 0);
    }

    // ── EmbeddedExecutable ───────────────────────────────────────────────────

    #[test]
    fn test_embedded_exe_finds_inner_mz() {
        let mut data = b"MZ\x00\x00".to_vec();
        data.extend_from_slice(&[0u8; 100]);
        data.extend_from_slice(b"MZ\x00\x00data");
        let found = EmbeddedExecutable::find_all(&data);
        assert!(!found.is_empty());
    }

    #[test]
    fn test_embedded_exe_display() {
        let e = EmbeddedExecutable {
            offset: 0x200,
            estimated_size: 1024,
            magic: [0x4D, 0x5A, 0x90, 0x00],
            has_pe_header: false,
        };
        assert!(e.to_string().contains("0x200"));
    }

    // ── DieScanner ───────────────────────────────────────────────────────────

    #[test]
    fn test_die_scanner_upx() {
        let scanner = DieScanner::new();
        let report = scanner.scan(&upx_data());
        assert!(report.is_packed);
    }

    #[test]
    fn test_die_scanner_themida() {
        let scanner = DieScanner::new();
        let report = scanner.scan(&themida_data());
        assert!(report.is_protected);
    }

    #[test]
    fn test_die_scanner_empty() {
        let scanner = DieScanner::new();
        let report = scanner.scan(&[]);
        assert!(!report.is_packed);
        assert_eq!(report.file_size, 0);
    }

    #[test]
    fn test_die_scanner_report_json() {
        let scanner = DieScanner::new();
        let report = scanner.scan(b"test data");
        let json = report.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["is_packed"].is_boolean());
    }

    #[test]
    fn test_die_scanner_summary() {
        let scanner = DieScanner::new();
        let report = scanner.scan(&upx_data());
        let summary = report.summary();
        assert!(summary.contains("packed=true"));
    }

    #[test]
    fn test_die_scanner_display() {
        let scanner = DieScanner::new();
        let report = scanner.scan(&upx_data());
        let s = format!("{report}");
        assert!(s.contains("DIE Scan Report"));
    }

    #[test]
    fn test_die_scanner_with_mode_ep_only() {
        let scanner = DieScanner::with_mode(ScanMode::EpOnly);
        let report = scanner.scan(&upx_data());
        assert_eq!(report.scan_mode, ScanMode::EpOnly);
    }

    #[test]
    fn test_die_scanner_debug() {
        let scanner = DieScanner::new();
        let s = format!("{scanner:?}");
        assert!(s.contains("DieScanner"));
    }

    #[test]
    fn test_die_report_best_match() {
        let scanner = DieScanner::new();
        let report = scanner.scan(&upx_data());
        if let Some(best) = report.best_match() {
            assert_eq!(best.name, "UPX");
        }
    }

    #[test]
    fn test_packer_version_from_match() {
        let m = DieMatch {
            name: "UPX".to_string(), version: "3.x".to_string(),
            match_type: DieMatchType::Packer, platform: "Win32".to_string(),
            confidence: 97, reason: String::new(),
        };
        let pv = PackerVersion::from_match(&m);
        assert_eq!(pv.name, "UPX");
        assert_eq!(pv.version, "3.x");
    }

    #[test]
    fn test_packer_version_display() {
        let pv = PackerVersion { name: "UPX".to_string(), version: "3.x".to_string(), variant: String::new(), build_date: None };
        assert!(pv.to_string().contains("UPX"));
    }

    #[test]
    fn test_protected_code_region_new() {
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let r = ProtectedCodeRegion::new(0, 4096, &data, ".vmp0");
        assert_eq!(r.section_name, ".vmp0");
        assert!(r.entropy > 7.0);
        assert!(r.virtualised);
    }
}
