//! Packer and protector detection engine.
//!
//! Detects common packers and protectors using section name patterns, entropy
//! analysis, import table inspection, and byte signature matching.
//! Supported: UPX, Themida/WinLicense, VMProtect, Enigma, MPRESS, ASPack,
//! PECompact, NsPack, FSG, MEW, PESpin, Obsidium, ACProtect, ExeCryptor,
//! yodas Protector, ConfuserEx (.NET), and several compiler-embedded packers.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// PackerKind
// ---------------------------------------------------------------------------

/// The type of packing/protection applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PackerKind {
    /// Executable compression packer.
    Packer,
    /// Anti-tamper / code virtualisation protector.
    Protector,
    /// Copy-protection / DRM.
    Drm,
    /// .NET obfuscator.
    DotNetObfuscator,
    /// Generic crypter.
    Crypter,
}

impl fmt::Display for PackerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            PackerKind::Packer => "Packer",
            PackerKind::Protector => "Protector",
            PackerKind::Drm => "DRM",
            PackerKind::DotNetObfuscator => ".NET Obfuscator",
            PackerKind::Crypter => "Crypter",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// PackerHit
// ---------------------------------------------------------------------------

/// A single packer/protector detection hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerHit {
    /// Product name.
    pub name: String,
    /// Detected version, if determinable.
    pub version: Option<String>,
    /// Kind of protection.
    pub kind: PackerKind,
    /// Confidence score 0–100.
    pub confidence: u8,
    /// Human-readable evidence string.
    pub evidence: String,
    /// Which detection strategy fired.
    pub strategy: String,
}

impl fmt::Display for PackerHit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ver = self.version.as_deref().unwrap_or("?");
        write!(
            f,
            "{} {} v{} ({}%, via {}): {}",
            self.kind, self.name, ver, self.confidence, self.strategy, self.evidence
        )
    }
}

// ---------------------------------------------------------------------------
// PE header helpers
// ---------------------------------------------------------------------------

/// Minimal PE parsing context, sufficient for packer detection.
struct PeCtx<'a> {
    data: &'a [u8],
    pe_off: usize,
    is_64bit: bool,
}

impl<'a> PeCtx<'a> {
    /// Parse PE headers.  Returns `None` if not a valid PE.
    fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 64 || data[0] != 0x4D || data[1] != 0x5A {
            return None;
        }
        let pe_off = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
        if pe_off + 24 > data.len() || &data[pe_off..pe_off + 4] != b"PE\0\0" {
            return None;
        }
        let opt_off = pe_off + 24;
        if opt_off + 2 > data.len() {
            return None;
        }
        let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
        let is_64bit = magic == 0x020B;
        Some(Self {
            data,
            pe_off,
            is_64bit,
        })
    }

    fn section_count(&self) -> usize {
        u16::from_le_bytes([
            self.data[self.pe_off + 6],
            self.data[self.pe_off + 7],
        ]) as usize
    }

    fn opt_header_size(&self) -> usize {
        u16::from_le_bytes([
            self.data[self.pe_off + 20],
            self.data[self.pe_off + 21],
        ]) as usize
    }

    fn section_table_offset(&self) -> usize {
        self.pe_off + 24 + self.opt_header_size()
    }

    /// Returns iterator over (name, virtual_size, raw_offset, raw_size, characteristics, entropy).
    fn sections(&self) -> Vec<SectionInfo> {
        let n = self.section_count();
        let base = self.section_table_offset();
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let off = base + i * 40;
            if off + 40 > self.data.len() {
                break;
            }
            let name_bytes = &self.data[off..off + 8];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
            let virtual_size =
                u32::from_le_bytes(self.data[off + 8..off + 12].try_into().unwrap_or([0; 4]));
            let virtual_addr =
                u32::from_le_bytes(self.data[off + 12..off + 16].try_into().unwrap_or([0; 4]));
            let raw_size =
                u32::from_le_bytes(self.data[off + 16..off + 20].try_into().unwrap_or([0; 4]))
                    as usize;
            let raw_off =
                u32::from_le_bytes(self.data[off + 20..off + 24].try_into().unwrap_or([0; 4]))
                    as usize;
            let characteristics =
                u32::from_le_bytes(self.data[off + 36..off + 40].try_into().unwrap_or([0; 4]));

            let entropy = if raw_off + raw_size <= self.data.len() && raw_size > 0 {
                compute_entropy(&self.data[raw_off..raw_off + raw_size])
            } else {
                0.0
            };

            out.push(SectionInfo {
                name,
                virtual_size,
                virtual_address: virtual_addr,
                raw_offset: raw_off,
                raw_size,
                characteristics,
                entropy,
            });
        }
        out
    }

    fn entry_point_rva(&self) -> u32 {
        let opt_off = self.pe_off + 24;
        if opt_off + 0x14 > self.data.len() {
            return 0;
        }
        u32::from_le_bytes(
            self.data[opt_off + 0x10..opt_off + 0x14]
                .try_into()
                .unwrap_or([0; 4]),
        )
    }

    fn ep_bytes(&self) -> &[u8] {
        let ep_rva = self.entry_point_rva();
        for sec in self.sections() {
            if ep_rva >= sec.virtual_address
                && ep_rva < sec.virtual_address.saturating_add(sec.virtual_size.max(1))
            {
                let file_off = sec.raw_offset + (ep_rva - sec.virtual_address) as usize;
                if file_off < self.data.len() {
                    let end = (file_off + 32).min(self.data.len());
                    return &self.data[file_off..end];
                }
            }
        }
        &[]
    }

    fn import_table_rva(&self) -> u32 {
        let opt_off = self.pe_off + 24;
        let dd_base = if self.is_64bit {
            opt_off + 0x70
        } else {
            opt_off + 0x60
        };
        if dd_base + 16 > self.data.len() {
            return 0;
        }
        u32::from_le_bytes(self.data[dd_base + 8..dd_base + 12].try_into().unwrap_or([0; 4]))
    }

    /// Collect DLL names from import descriptor table.
    fn imported_dlls(&self) -> Vec<String> {
        let import_rva = self.import_table_rva();
        if import_rva == 0 {
            return Vec::new();
        }
        let Some(import_foff) = self.rva_to_file_off(import_rva) else {
            return Vec::new();
        };
        let mut dlls = Vec::new();
        let mut off = import_foff;
        while off + 20 <= self.data.len() {
            let name_rva = u32::from_le_bytes(
                self.data[off + 12..off + 16]
                    .try_into()
                    .unwrap_or([0; 4]),
            );
            let ilt_rva =
                u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap_or([0; 4]));
            if name_rva == 0 && ilt_rva == 0 {
                break;
            }
            if let Some(name_off) = self.rva_to_file_off(name_rva) {
                dlls.push(read_cstr(self.data, name_off).to_lowercase());
            }
            off += 20;
        }
        dlls
    }

    fn rva_to_file_off(&self, rva: u32) -> Option<usize> {
        if rva == 0 {
            return None;
        }
        for sec in self.sections() {
            if rva >= sec.virtual_address
                && rva < sec.virtual_address.saturating_add(sec.virtual_size.max(1))
            {
                let off = sec.raw_offset + (rva - sec.virtual_address) as usize;
                if off < self.data.len() {
                    return Some(off);
                }
            }
        }
        None
    }
}

fn read_cstr(data: &[u8], off: usize) -> String {
    let s = &data[off.min(data.len())..];
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len().min(256));
    String::from_utf8_lossy(&s[..end]).into_owned()
}

/// Information about one PE section.
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_offset: usize,
    pub raw_size: usize,
    pub characteristics: u32,
    pub entropy: f32,
}

impl SectionInfo {
    /// True if section has high entropy (likely packed/encrypted).
    pub fn is_high_entropy(&self) -> bool {
        self.entropy > 7.0
    }

    /// True if section is executable.
    pub fn is_executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }

    /// True if section is writable.
    pub fn is_writable(&self) -> bool {
        self.characteristics & 0x8000_0000 != 0
    }
}

/// Shannon entropy in bits per byte.
pub fn compute_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f32;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / len;
            -p * p.log2()
        })
        .sum()
}

// ---------------------------------------------------------------------------
// DetectionRule – the per-packer detection logic
// ---------------------------------------------------------------------------

/// Detection strategy identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    SectionName,
    EntryPointBytes,
    StringSearch,
    ImportTable,
    Entropy,
    OverlaySignature,
    SectionCount,
    Composite,
}

impl fmt::Display for Strategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Strategy::SectionName => "SectionName",
            Strategy::EntryPointBytes => "EntryPoint",
            Strategy::StringSearch => "String",
            Strategy::ImportTable => "ImportTable",
            Strategy::Entropy => "Entropy",
            Strategy::OverlaySignature => "Overlay",
            Strategy::SectionCount => "SectionCount",
            Strategy::Composite => "Composite",
        };
        f.write_str(s)
    }
}

/// A detection rule closure.
type RuleFn = Box<dyn Fn(&[u8], &PeCtx<'_>) -> Option<PackerHit> + Send + Sync>;

struct PackerRule {
    name: &'static str,
    strategy: Strategy,
    check: RuleFn,
}

// ---------------------------------------------------------------------------
// PackerDetector – main detection engine
// ---------------------------------------------------------------------------

/// The packer / protector detection engine.
///
/// Uses a layered strategy:
/// 1. Section name matching
/// 2. Entry-point byte pattern matching
/// 3. String search (DLL names, section content, embedded strings)
/// 4. Import table analysis (few imports = suspicious)
/// 5. Entropy analysis (packed sections have entropy > 7.0)
/// 6. Composite rules combining multiple evidence types
pub struct PackerDetector {
    rules: Vec<PackerRule>,
    /// Minimum confidence threshold for reported hits.
    min_confidence: u8,
    /// Whether to run all rules (false = stop at first confident hit).
    exhaustive: bool,
}

impl PackerDetector {
    /// Create a detector loaded with all built-in rules.
    pub fn new() -> Self {
        let mut detector = Self {
            rules: Vec::new(),
            min_confidence: 60,
            exhaustive: true,
        };
        detector.register_all_rules();
        detector
    }

    /// Set minimum confidence.
    pub fn set_min_confidence(&mut self, min: u8) {
        self.min_confidence = min;
    }

    /// Enable/disable exhaustive mode.
    pub fn set_exhaustive(&mut self, exhaustive: bool) {
        self.exhaustive = exhaustive;
    }

    /// Run detection on raw file bytes.  Returns all matching hits.
    pub fn detect(&self, data: &[u8]) -> Vec<PackerHit> {
        // Only PE for now.
        let pe = match PeCtx::parse(data) {
            Some(p) => p,
            None => return Vec::new(),
        };

        let mut hits: Vec<PackerHit> = Vec::new();
        for rule in &self.rules {
            if let Some(mut hit) = (rule.check)(data, &pe) {
                // If the closure produced an empty product name or strategy
                // label, fall back to the values declared on the registered
                // rule so every hit carries provenance.
                if hit.name.is_empty() {
                    hit.name = rule.name.to_string();
                }
                if hit.strategy.is_empty() {
                    hit.strategy = rule.strategy.to_string();
                }
                if hit.confidence >= self.min_confidence {
                    let confident = hit.confidence >= 90;
                    hits.push(hit);
                    if !self.exhaustive && confident {
                        break;
                    }
                }
            }
        }

        // Sort by confidence descending, then alphabetically.
        hits.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.name.cmp(&b.name))
        });
        hits
    }

    /// Run entropy analysis and return a summary.
    pub fn entropy_summary(&self, data: &[u8]) -> EntropyAnalysis {
        let pe = match PeCtx::parse(data) {
            Some(p) => p,
            None => {
                return EntropyAnalysis {
                    overall: compute_entropy(data),
                    sections: Vec::new(),
                    high_entropy_count: 0,
                    likely_packed: false,
                }
            }
        };
        let sections = pe.sections();
        let high_count = sections.iter().filter(|s| s.is_high_entropy()).count();
        let likely_packed = high_count > 0
            && (high_count as f32 / sections.len().max(1) as f32) > 0.4;

        EntropyAnalysis {
            overall: compute_entropy(data),
            sections: sections.into_iter().map(|s| (s.name, s.entropy)).collect(),
            high_entropy_count: high_count,
            likely_packed,
        }
    }

    // -----------------------------------------------------------------------
    // Rule registration
    // -----------------------------------------------------------------------

    fn rule(name: &'static str, strategy: Strategy, f: impl Fn(&[u8], &PeCtx<'_>) -> Option<PackerHit> + Send + Sync + 'static) -> PackerRule {
        PackerRule {
            name,
            strategy,
            check: Box::new(f),
        }
    }

    fn register_all_rules(&mut self) {
        // ---- UPX ----
        self.rules.push(Self::rule("UPX", Strategy::SectionName, |_data, pe| {
            let sections = pe.sections();
            let has_upx0 = sections.iter().any(|s| s.name == "UPX0");
            let has_upx1 = sections.iter().any(|s| s.name == "UPX1");
            if has_upx0 && has_upx1 {
                Some(PackerHit {
                    name: "UPX".to_string(),
                    version: None,
                    kind: PackerKind::Packer,
                    confidence: 95,
                    evidence: "Sections UPX0 and UPX1 found".to_string(),
                    strategy: "SectionName".to_string(),
                })
            } else {
                None
            }
        }));

        self.rules.push(Self::rule("UPX-string", Strategy::StringSearch, |data, _pe| {
            if data.windows(4).any(|w| w == b"UPX!") {
                Some(PackerHit {
                    name: "UPX".to_string(),
                    version: Some("3+".to_string()),
                    kind: PackerKind::Packer,
                    confidence: 90,
                    evidence: "String 'UPX!' found in binary".to_string(),
                    strategy: "String".to_string(),
                })
            } else {
                None
            }
        }));

        self.rules.push(Self::rule("UPX-EP", Strategy::EntryPointBytes, |_data, pe| {
            let ep = pe.ep_bytes();
            // Classic UPX entry: PUSHAD (60) / MOV ESI, addr (BE xx xx xx xx)
            if ep.len() >= 6 && ep[0] == 0x60 && ep[1] == 0xBE {
                Some(PackerHit {
                    name: "UPX".to_string(),
                    version: Some("3.x".to_string()),
                    kind: PackerKind::Packer,
                    confidence: 88,
                    evidence: "Entry point matches PUSHAD / MOV ESI UPX stub".to_string(),
                    strategy: "EntryPoint".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- MPRESS ----
        self.rules.push(Self::rule("MPRESS", Strategy::SectionName, |_data, pe| {
            if pe.sections().iter().any(|s| s.name.starts_with(".MPRESS")) {
                Some(PackerHit {
                    name: "MPRESS".to_string(),
                    version: Some("2.x".to_string()),
                    kind: PackerKind::Packer,
                    confidence: 90,
                    evidence: "Section .MPRESS1 found".to_string(),
                    strategy: "SectionName".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- ASPack ----
        self.rules.push(Self::rule("ASPack", Strategy::SectionName, |_data, pe| {
            if pe.sections().iter().any(|s| s.name == ".aspack") {
                Some(PackerHit {
                    name: "ASPack".to_string(),
                    version: Some("2.x".to_string()),
                    kind: PackerKind::Packer,
                    confidence: 92,
                    evidence: "Section .aspack found".to_string(),
                    strategy: "SectionName".to_string(),
                })
            } else {
                None
            }
        }));

        self.rules.push(Self::rule("ASPack-adata", Strategy::SectionName, |_data, pe| {
            if pe.sections().iter().any(|s| s.name == ".adata") {
                Some(PackerHit {
                    name: "ASPack".to_string(),
                    version: Some("2.12".to_string()),
                    kind: PackerKind::Packer,
                    confidence: 80,
                    evidence: "Section .adata found (ASPack signature)".to_string(),
                    strategy: "SectionName".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- PECompact ----
        self.rules.push(Self::rule("PECompact", Strategy::StringSearch, |data, _pe| {
            if data.windows(10).any(|w| w == b"PECompact2") {
                Some(PackerHit {
                    name: "PECompact".to_string(),
                    version: Some("2.x".to_string()),
                    kind: PackerKind::Packer,
                    confidence: 90,
                    evidence: "String 'PECompact2' found".to_string(),
                    strategy: "String".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- NsPack ----
        self.rules.push(Self::rule("NsPack", Strategy::SectionName, |_data, pe| {
            let secs = pe.sections();
            if secs.iter().any(|s| s.name == ".nsp0")
                || secs.iter().any(|s| s.name == ".nsp1")
                || secs.iter().any(|s| s.name == ".nsp2")
            {
                Some(PackerHit {
                    name: "NsPack".to_string(),
                    version: Some("3.7".to_string()),
                    kind: PackerKind::Packer,
                    confidence: 90,
                    evidence: "NsPack section (.nsp0/.nsp1/.nsp2) found".to_string(),
                    strategy: "SectionName".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- FSG ----
        self.rules.push(Self::rule("FSG", Strategy::StringSearch, |data, pe| {
            if data.windows(4).any(|w| w == b"FSG!") {
                let secs = pe.sections();
                Some(PackerHit {
                    name: "FSG".to_string(),
                    version: Some("2.0".to_string()),
                    kind: PackerKind::Packer,
                    confidence: 87,
                    evidence: format!("String 'FSG!' found; {} sections", secs.len()),
                    strategy: "String".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- MEW ----
        self.rules.push(Self::rule("MEW", Strategy::Composite, |data, pe| {
            let secs = pe.sections();
            let two_sections = secs.len() == 2;
            let has_mew = data.windows(3).any(|w| w == b"MEW");
            if two_sections && has_mew {
                Some(PackerHit {
                    name: "MEW".to_string(),
                    version: Some("1.1".to_string()),
                    kind: PackerKind::Packer,
                    confidence: 85,
                    evidence: "Exactly 2 sections + 'MEW' string".to_string(),
                    strategy: "Composite".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- PESpin ----
        self.rules.push(Self::rule("PESpin", Strategy::StringSearch, |data, _pe| {
            if data.windows(6).any(|w| w == b"PESpin") {
                Some(PackerHit {
                    name: "PESpin".to_string(),
                    version: Some("1.3".to_string()),
                    kind: PackerKind::Packer,
                    confidence: 86,
                    evidence: "String 'PESpin' found".to_string(),
                    strategy: "String".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- Themida / WinLicense ----
        self.rules.push(Self::rule("Themida", Strategy::SectionName, |_data, pe| {
            if pe.sections().iter().any(|s| s.name == ".themida") {
                Some(PackerHit {
                    name: "Themida/WinLicense".to_string(),
                    version: Some("3.x".to_string()),
                    kind: PackerKind::Protector,
                    confidence: 95,
                    evidence: "Section .themida found".to_string(),
                    strategy: "SectionName".to_string(),
                })
            } else {
                None
            }
        }));

        self.rules.push(Self::rule("Themida-string", Strategy::StringSearch, |data, _pe| {
            if data.windows(9).any(|w| w == b".winlice\0") || data.windows(9).any(|w| w == b"WinLicen") {
                Some(PackerHit {
                    name: "WinLicense".to_string(),
                    version: Some("3.x".to_string()),
                    kind: PackerKind::Drm,
                    confidence: 85,
                    evidence: "WinLicense string found".to_string(),
                    strategy: "String".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- VMProtect ----
        self.rules.push(Self::rule("VMProtect", Strategy::SectionName, |_data, pe| {
            let secs = pe.sections();
            let has_vmp0 = secs.iter().any(|s| s.name == ".vmp0");
            let has_vmp1 = secs.iter().any(|s| s.name == ".vmp1");
            if has_vmp0 || has_vmp1 {
                let ver = if has_vmp1 { "3.x" } else { "2.x" };
                Some(PackerHit {
                    name: "VMProtect".to_string(),
                    version: Some(ver.to_string()),
                    kind: PackerKind::Protector,
                    confidence: 95,
                    evidence: format!("VMProtect section found (.vmp0={}, .vmp1={})", has_vmp0, has_vmp1),
                    strategy: "SectionName".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- Enigma Protector ----
        self.rules.push(Self::rule("Enigma", Strategy::SectionName, |_data, pe| {
            let secs = pe.sections();
            if secs.iter().any(|s| s.name.starts_with(".enigma")) {
                Some(PackerHit {
                    name: "Enigma Protector".to_string(),
                    version: Some("7.x".to_string()),
                    kind: PackerKind::Protector,
                    confidence: 92,
                    evidence: "Enigma section (.enigma1/2) found".to_string(),
                    strategy: "SectionName".to_string(),
                })
            } else {
                None
            }
        }));

        self.rules.push(Self::rule("Enigma-string", Strategy::StringSearch, |data, _pe| {
            if data.windows(8).any(|w| w == b".enigma1") {
                Some(PackerHit {
                    name: "Enigma Protector".to_string(),
                    version: Some("7.x".to_string()),
                    kind: PackerKind::Protector,
                    confidence: 88,
                    evidence: "String '.enigma1' found in binary".to_string(),
                    strategy: "String".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- Obsidium ----
        self.rules.push(Self::rule("Obsidium", Strategy::StringSearch, |data, _pe| {
            if data.windows(8).any(|w| w == b"Obsidium") {
                Some(PackerHit {
                    name: "Obsidium".to_string(),
                    version: Some("1.x".to_string()),
                    kind: PackerKind::Protector,
                    confidence: 88,
                    evidence: "String 'Obsidium' found".to_string(),
                    strategy: "String".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- ACProtect ----
        self.rules.push(Self::rule("ACProtect", Strategy::StringSearch, |data, _pe| {
            if data.windows(9).any(|w| w == b"ACProtect") {
                Some(PackerHit {
                    name: "ACProtect".to_string(),
                    version: Some("2.x".to_string()),
                    kind: PackerKind::Protector,
                    confidence: 85,
                    evidence: "String 'ACProtect' found".to_string(),
                    strategy: "String".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- Entropy-based heuristic ----
        self.rules.push(Self::rule("Unknown-packer-entropy", Strategy::Entropy, |_data, pe| {
            let secs = pe.sections();
            if secs.is_empty() {
                return None;
            }
            let high_entropy_execs: Vec<&SectionInfo> = secs
                .iter()
                .filter(|s| s.is_executable() && s.is_high_entropy())
                .collect();

            if high_entropy_execs.len() >= 1 {
                let avg_ent: f32 =
                    high_entropy_execs.iter().map(|s| s.entropy).sum::<f32>()
                    / high_entropy_execs.len() as f32;
                Some(PackerHit {
                    name: "Unknown Packer (entropy)".to_string(),
                    version: None,
                    kind: PackerKind::Packer,
                    confidence: 65,
                    evidence: format!(
                        "{} high-entropy executable sections (avg entropy={:.2})",
                        high_entropy_execs.len(),
                        avg_ent
                    ),
                    strategy: "Entropy".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- Tiny import table heuristic ----
        self.rules.push(Self::rule("Suspicious-imports", Strategy::ImportTable, |_data, pe| {
            let dlls = pe.imported_dlls();
            if dlls.len() <= 1 && !dlls.is_empty() {
                Some(PackerHit {
                    name: "Thin Import Table".to_string(),
                    version: None,
                    kind: PackerKind::Packer,
                    confidence: 62,
                    evidence: format!(
                        "Only {} DLL(s) imported ({}): suspicious for packed binary",
                        dlls.len(),
                        dlls.join(", ")
                    ),
                    strategy: "ImportTable".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- ConfuserEx (.NET obfuscator) ----
        self.rules.push(Self::rule("ConfuserEx", Strategy::StringSearch, |data, _pe| {
            if data.windows(11).any(|w| w == b"ConfuserEx\0") || data.windows(9).any(|w| w == b"Confuser") {
                Some(PackerHit {
                    name: "ConfuserEx".to_string(),
                    version: Some("1.x".to_string()),
                    kind: PackerKind::DotNetObfuscator,
                    confidence: 87,
                    evidence: "ConfuserEx string found".to_string(),
                    strategy: "String".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- .NET Reactor ----
        self.rules.push(Self::rule("DotNetReactor", Strategy::StringSearch, |data, _pe| {
            if data.windows(12).any(|w| w == b".NET Reactor") {
                Some(PackerHit {
                    name: ".NET Reactor".to_string(),
                    version: Some("6.x".to_string()),
                    kind: PackerKind::DotNetObfuscator,
                    confidence: 90,
                    evidence: "String '.NET Reactor' found".to_string(),
                    strategy: "String".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- Dotfuscator ----
        self.rules.push(Self::rule("Dotfuscator", Strategy::StringSearch, |data, _pe| {
            if data.windows(11).any(|w| w == b"Dotfuscator") {
                Some(PackerHit {
                    name: "Dotfuscator".to_string(),
                    version: None,
                    kind: PackerKind::DotNetObfuscator,
                    confidence: 85,
                    evidence: "String 'Dotfuscator' found".to_string(),
                    strategy: "String".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- ExeCryptor ----
        self.rules.push(Self::rule("ExeCryptor", Strategy::StringSearch, |data, _pe| {
            if data.windows(10).any(|w| w == b"ExeCryptor") {
                Some(PackerHit {
                    name: "ExeCryptor".to_string(),
                    version: None,
                    kind: PackerKind::Crypter,
                    confidence: 88,
                    evidence: "String 'ExeCryptor' found".to_string(),
                    strategy: "String".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- yoda's Protector ----
        self.rules.push(Self::rule("YodasProtector", Strategy::StringSearch, |data, _pe| {
            if data.windows(6).any(|w| w == b"yP 1.0") || data.windows(12).any(|w| w == b"yoda's Crypt") {
                Some(PackerHit {
                    name: "yoda's Protector".to_string(),
                    version: Some("1.x".to_string()),
                    kind: PackerKind::Protector,
                    confidence: 82,
                    evidence: "yoda's Protector string found".to_string(),
                    strategy: "String".to_string(),
                })
            } else {
                None
            }
        }));

        // ---- CodeVirtualizer ----
        self.rules.push(Self::rule("CodeVirtualizer", Strategy::StringSearch, |data, _pe| {
            if data.windows(16).any(|w| w == b"CodeVirtualizer\0") {
                Some(PackerHit {
                    name: "Code Virtualizer".to_string(),
                    version: None,
                    kind: PackerKind::Protector,
                    confidence: 85,
                    evidence: "String 'CodeVirtualizer' found".to_string(),
                    strategy: "String".to_string(),
                })
            } else {
                None
            }
        }));
    }

    /// Number of registered rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Check if file is packed by any known packer (confidence ≥ min).
    pub fn is_packed(&self, data: &[u8]) -> bool {
        !self.detect(data).is_empty()
    }

    /// Return only packer hits (not protectors).
    pub fn detect_packers(&self, data: &[u8]) -> Vec<PackerHit> {
        self.detect(data)
            .into_iter()
            .filter(|h| h.kind == PackerKind::Packer)
            .collect()
    }

    /// Return only protector hits.
    pub fn detect_protectors(&self, data: &[u8]) -> Vec<PackerHit> {
        self.detect(data)
            .into_iter()
            .filter(|h| h.kind == PackerKind::Protector)
            .collect()
    }

    /// Collect section statistics from a PE file.
    pub fn section_stats(&self, data: &[u8]) -> Vec<SectionInfo> {
        let pe = match PeCtx::parse(data) {
            Some(p) => p,
            None => return Vec::new(),
        };
        pe.sections()
    }
}

impl Default for PackerDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PackerDetector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PackerDetector {{ rules={}, min_conf={}, exhaustive={} }}",
            self.rules.len(),
            self.min_confidence,
            self.exhaustive
        )
    }
}

// ---------------------------------------------------------------------------
// EntropyAnalysis
// ---------------------------------------------------------------------------

/// Summary of entropy analysis for a PE file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyAnalysis {
    /// Overall entropy of the whole file.
    pub overall: f32,
    /// Per-section entropy: `(section_name, entropy)`.
    pub sections: Vec<(String, f32)>,
    /// Number of high-entropy sections (> 7.0).
    pub high_entropy_count: usize,
    /// True when multiple high-entropy sections suggest packing.
    pub likely_packed: bool,
}

impl EntropyAnalysis {
    /// Maximum section entropy.
    pub fn max_entropy(&self) -> f32 {
        self.sections
            .iter()
            .map(|(_, e)| *e)
            .fold(0.0_f32, f32::max)
    }

    /// Average section entropy.
    pub fn avg_entropy(&self) -> f32 {
        if self.sections.is_empty() {
            return 0.0;
        }
        self.sections.iter().map(|(_, e)| e).sum::<f32>() / self.sections.len() as f32
    }
}

impl fmt::Display for EntropyAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EntropyAnalysis {{ overall={:.2}, sections={}, high_entropy={}, likely_packed={} }}",
            self.overall,
            self.sections.len(),
            self.high_entropy_count,
            self.likely_packed
        )
    }
}

// ---------------------------------------------------------------------------
// PackerReport – aggregate result
// ---------------------------------------------------------------------------

/// An aggregate packer detection report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerReport {
    /// All packer/protector hits.
    pub hits: Vec<PackerHit>,
    /// Entropy analysis.
    pub entropy: EntropyAnalysis,
    /// True if at least one packer was confirmed.
    pub is_packed: bool,
    /// True if at least one protector was confirmed.
    pub is_protected: bool,
    /// Unique set of detected packer names.
    pub detected_names: Vec<String>,
}

impl PackerReport {
    /// Build a report from raw hits + entropy.
    pub fn from_hits(hits: Vec<PackerHit>, entropy: EntropyAnalysis) -> Self {
        let is_packed = hits.iter().any(|h| h.kind == PackerKind::Packer);
        let is_protected = hits.iter().any(|h| h.kind == PackerKind::Protector);
        let mut names: Vec<String> = hits
            .iter()
            .map(|h| h.name.clone())
            .collect::<HashSet<String>>()
            .into_iter()
            .collect();
        names.sort();
        Self {
            hits,
            entropy,
            is_packed,
            is_protected,
            detected_names: names,
        }
    }

    /// Highest confidence across all hits.
    pub fn max_confidence(&self) -> u8 {
        self.hits.iter().map(|h| h.confidence).max().unwrap_or(0)
    }
}

impl fmt::Display for PackerReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PackerReport {{ packed={}, protected={}, hits={}, top_conf={} }}",
            self.is_packed,
            self.is_protected,
            self.hits.len(),
            self.max_confidence()
        )
    }
}

/// Convenience function: run all detection on `data` and return a full report.
pub fn full_analysis(data: &[u8]) -> PackerReport {
    let detector = PackerDetector::new();
    let hits = detector.detect(data);
    let entropy = detector.entropy_summary(data);
    PackerReport::from_hits(hits, entropy)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upx_stub() -> Vec<u8> {
        // Minimal PE with UPX0 / UPX1 sections in the section table
        let mut data = vec![0u8; 512];
        // MZ header
        data[0] = 0x4D;
        data[1] = 0x5A;
        // e_lfanew = 0x40
        data[0x3c] = 0x40;
        // PE signature at 0x40
        data[0x40] = b'P';
        data[0x41] = b'E';
        data[0x42] = 0;
        data[0x43] = 0;
        // Machine = x64
        data[0x44] = 0x64;
        data[0x45] = 0x86;
        // Section count = 2
        data[0x46] = 2;
        // Optional header size = 0xF0 (PE32+)
        data[0x54] = 0xF0;
        data[0x55] = 0x00;
        // Magic PE32+ at opt header (0x40 + 24 = 0x58)
        data[0x58] = 0x0B;
        data[0x59] = 0x02;
        // Section table starts at 0x40 + 24 + 0xF0 = 0x148
        let sec_off: usize = 0x40 + 24 + 0xF0;
        if sec_off + 80 <= data.len() {
            // Section 0: UPX0
            let name0 = b"UPX0\0\0\0\0";
            data[sec_off..sec_off + 8].copy_from_slice(name0);
            // Section 1: UPX1
            let name1 = b"UPX1\0\0\0\0";
            data[sec_off + 40..sec_off + 48].copy_from_slice(name1);
        }
        data
    }

    #[test]
    fn test_upx_detection_by_section() {
        let data = upx_stub();
        let detector = PackerDetector::new();
        let hits = detector.detect(&data);
        assert!(hits.iter().any(|h| h.name == "UPX"), "UPX should be detected");
    }

    #[test]
    fn test_upx_string_detection() {
        let detector = PackerDetector::new();
        let mut data = vec![0u8; 64];
        data[0] = 0x4D;
        data[1] = 0x5A;
        // Append UPX! string
        let mut full: Vec<u8> = data.clone();
        full.extend_from_slice(b"UPX! stub data here");
        // Without a full PE header this won't parse, but test the string rule independently.
        // We test via the PackerDetector which will not parse the PE.
        // Just ensure no panic.
        let _ = detector.detect(&full);
    }

    #[test]
    fn test_entropy_computation() {
        let zeros = vec![0u8; 256];
        assert_eq!(compute_entropy(&zeros), 0.0);
        let uniform: Vec<u8> = (0u8..=255).collect();
        let e = compute_entropy(&uniform);
        assert!((e - 8.0).abs() < 0.01, "uniform distribution = 8.0 bits");
    }

    #[test]
    fn test_entropy_summary_no_pe() {
        let detector = PackerDetector::new();
        let data = vec![0xAA_u8; 1024];
        let ea = detector.entropy_summary(&data);
        assert!(ea.sections.is_empty());
    }

    #[test]
    fn test_full_analysis_empty() {
        let report = full_analysis(&[]);
        assert!(!report.is_packed);
        assert!(!report.is_protected);
    }

    #[test]
    fn test_packer_report_display() {
        let report = full_analysis(&[]);
        let s = report.to_string();
        assert!(s.contains("PackerReport"));
    }

    #[test]
    fn test_rule_count() {
        let det = PackerDetector::new();
        assert!(det.rule_count() >= 10, "at least 10 built-in rules");
    }

    #[test]
    fn test_is_packed_false_for_garbage() {
        let det = PackerDetector::new();
        let data = vec![0xCC_u8; 256];
        assert!(!det.is_packed(&data));
    }

    #[test]
    fn test_packer_hit_display() {
        let h = PackerHit {
            name: "UPX".to_string(),
            version: Some("3.x".to_string()),
            kind: PackerKind::Packer,
            confidence: 95,
            evidence: "Section UPX0".to_string(),
            strategy: "SectionName".to_string(),
        };
        let s = h.to_string();
        assert!(s.contains("UPX"));
        assert!(s.contains("95%"));
    }
}
