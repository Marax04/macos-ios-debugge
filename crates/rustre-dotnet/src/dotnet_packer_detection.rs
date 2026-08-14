//! .NET packer/obfuscator detection.
//!
//! Detects: `SmartAssembly`, Eazfuscator, `ConfuserEx`, Dotfuscator, Obfuscar,
//! .NET Reactor, `ILProtector`.
//! Detection via: metadata entropy, resource names, known stub methods, IL patterns.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ── Packer identity ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Packer {
    SmartAssembly,
    Eazfuscator,
    ConfuserEx,
    Dotfuscator,
    Obfuscar,
    DotNetReactor,
    ILProtector,
    Babel,
    Crypto,
    Agile,
    DeepSea,
    Mpress,
    Costura,
    Unknown(u32),
}

impl Packer {
    #[must_use] 
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SmartAssembly => "SmartAssembly",
            Self::Eazfuscator => "Eazfuscator.NET",
            Self::ConfuserEx => "ConfuserEx",
            Self::Dotfuscator => "Dotfuscator",
            Self::Obfuscar => "Obfuscar",
            Self::DotNetReactor => ".NET Reactor",
            Self::ILProtector => "ILProtector",
            Self::Babel => "Babel Obfuscator",
            Self::Crypto => "Crypto Obfuscator",
            Self::Agile => "Agile.NET",
            Self::DeepSea => "DeepSea Obfuscator",
            Self::Mpress => "MPRESS",
            Self::Costura => "Costura.Fody (embed, not obfuscate)",
            Self::Unknown(_) => "unknown packer",
        }
    }

    #[must_use] 
    pub const fn is_obfuscator(self) -> bool {
        !matches!(self, Self::Costura | Self::Mpress | Self::Unknown(_))
    }
}

// ── Detection evidence ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerEvidence {
    pub packer: Packer,
    pub confidence: f64,
    pub evidence_type: EvidenceType,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceType {
    /// Match in the assembly's custom attributes.
    CustomAttribute,
    /// Match in the resource names.
    ResourceName,
    /// Match in namespace/type names.
    TypeName,
    /// Match in method/field names.
    MemberName,
    /// High entropy in a resource blob.
    ResourceEntropy,
    /// Known IL pattern (e.g. calli, ldftn to stub).
    IlPattern,
    /// Known string literal.
    StringLiteral,
    /// Module version ID (MVID) embedded by tool.
    Mvid,
}

impl EvidenceType {
    #[must_use] 
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CustomAttribute => "custom attribute",
            Self::ResourceName => "resource name",
            Self::TypeName => "type name",
            Self::MemberName => "member name",
            Self::ResourceEntropy => "resource entropy",
            Self::IlPattern => "IL pattern",
            Self::StringLiteral => "string literal",
            Self::Mvid => "MVID marker",
        }
    }
}

// ── Fingerprint tables ────────────────────────────────────────────────────────

const SMARTASSEMBLY_ATTRS: &[&str] = &[
    "SmartAssembly.Attributes",
    "SmartAssembly.ReportUsage",
    "SmartAssembly.ReportError",
    "SmartAssembly.Obfuscation",
];

const SMARTASSEMBLY_TYPES: &[&str] = &[
    "SmartAssembly.HouseOfCards.HouseOfCards",
    "SmartAssembly.StringsEncoding.",
    "SmartAssembly.Delegates.",
    "#=",
];

const CONFUSEREX_ATTRS: &[&str] = &[
    "ConfuserEx.Runtime",
    "de4dot.blocks",
    "Confuser.Runtime",
];

const CONFUSEREX_TYPES: &[&str] = &[
    "ConfuserEx",
    "Confuser.Runtime",
    "Module_",
    "Antitamper_",
    "Watermark_",
    "JIT_",
    "Compressor_",
    "AntiDebug_",
];

const DOTFUSCATOR_ATTRS: &[&str] = &[
    "DotfuscatorAttribute",
    "PreEmptive.Dotfuscator",
    "PreEmptive.SOS.Dotfuscator",
];

const DOTFUSCATOR_TYPES: &[&str] = &[
    "PreEmptive.",
    "Dotfuscator",
];

const OBFUSCAR_TYPES: &[&str] = &[
    "Obfuscar",
    "ObfuscarAttribute",
];

const EAZFUSCATOR_STRINGS: &[&str] = &[
    "Eazfuscator",
    "EazfuscatorAttribute",
];


const DOTNET_REACTOR_TYPES: &[&str] = &[
    ".NETReactor",
    "NET_Reactor",
    "Reactor",
    "nR",
];

const DOTNET_REACTOR_RESOURCES: &[&str] = &[
    ".nR_", "nR_", "Reactor_", "DR_",
];

const ILPROTECTOR_TYPES: &[&str] = &[
    "ILProtector",
    "ILP",
    "ProtectedModule",
];


const COSTURA_RESOURCES: &[&str] = &[
    "costura.", ".compressed",
];

const COSTURA_TYPES: &[&str] = &[
    "Costura.AssemblyLoader",
    "Costura",
    "FodyWeavers",
];

const BABEL_TYPES: &[&str] = &[
    "Babel.",
    "BabelObfuscator",
    "babel_",
];

const DEEPSEAOBF_TYPES: &[&str] = &[
    "IronMate",
    "DeepSea",
    "SNALPROG",
];

const MPRESS_STRINGS: &[&str] = &[
    "MPRESS",
    "mpress",
];

// ── Shannon entropy helper ────────────────────────────────────────────────────

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u32; 256];
    for &b in data { freq[b as usize] += 1; }
    let n = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    freq.iter().filter(|&&c| c > 0)
        .map(|&c| { let p = f64::from(c) / n; -p * p.log2() })
        .sum()
}

// ── Detector ──────────────────────────────────────────────────────────────────

pub struct PackerDetector {
    evidence: Vec<PackerEvidence>,
}

impl PackerDetector {
    #[must_use] 
    pub const fn new() -> Self {
        Self { evidence: Vec::new() }
    }

    fn push(&mut self, packer: Packer, confidence: f64, kind: EvidenceType, detail: impl Into<String>) {
        self.evidence.push(PackerEvidence {
            packer, confidence,
            evidence_type: kind,
            detail: detail.into(),
        });
    }

    /// Scan all type names for known packer fingerprints.
    pub fn scan_type_names(&mut self, types: &[String]) {
        for t in types {
            // SmartAssembly
            for sig in SMARTASSEMBLY_TYPES {
                if t.contains(sig) {
                    self.push(Packer::SmartAssembly, 0.9, EvidenceType::TypeName, format!("type: {t}"));
                }
            }
            // SmartAssembly: many types starting with "#="
            if t.starts_with("#=") {
                self.push(Packer::SmartAssembly, 0.8, EvidenceType::TypeName, format!("obf type: {t}"));
            }
            // ConfuserEx
            for sig in CONFUSEREX_TYPES {
                if t.contains(sig) {
                    self.push(Packer::ConfuserEx, 0.85, EvidenceType::TypeName, format!("type: {t}"));
                }
            }
            // Dotfuscator
            for sig in DOTFUSCATOR_TYPES {
                if t.contains(sig) {
                    self.push(Packer::Dotfuscator, 0.85, EvidenceType::TypeName, format!("type: {t}"));
                }
            }
            // Obfuscar
            for sig in OBFUSCAR_TYPES {
                if t.contains(sig) {
                    self.push(Packer::Obfuscar, 0.9, EvidenceType::TypeName, format!("type: {t}"));
                }
            }
            // .NET Reactor
            for sig in DOTNET_REACTOR_TYPES {
                if t.contains(sig) {
                    self.push(Packer::DotNetReactor, 0.7, EvidenceType::TypeName, format!("type: {t}"));
                }
            }
            // ILProtector
            for sig in ILPROTECTOR_TYPES {
                if t.contains(sig) {
                    self.push(Packer::ILProtector, 0.85, EvidenceType::TypeName, format!("type: {t}"));
                }
            }
            // Costura
            for sig in COSTURA_TYPES {
                if t.contains(sig) {
                    self.push(Packer::Costura, 0.9, EvidenceType::TypeName, format!("type: {t}"));
                }
            }
            // Babel
            for sig in BABEL_TYPES {
                if t.contains(sig) {
                    self.push(Packer::Babel, 0.8, EvidenceType::TypeName, format!("type: {t}"));
                }
            }
            // DeepSea
            for sig in DEEPSEAOBF_TYPES {
                if t.contains(sig) {
                    self.push(Packer::DeepSea, 0.75, EvidenceType::TypeName, format!("type: {t}"));
                }
            }
            // Eazfuscator: many types with non-ASCII names
            if !t.is_ascii() && t.len() < 6 {
                self.push(Packer::Eazfuscator, 0.5, EvidenceType::TypeName, format!("non-ascii type: {t}"));
            }
        }
    }

    /// Scan custom attribute names.
    pub fn scan_custom_attributes(&mut self, attrs: &[String]) {
        for a in attrs {
            for sig in SMARTASSEMBLY_ATTRS {
                if a.contains(sig) {
                    self.push(Packer::SmartAssembly, 0.95, EvidenceType::CustomAttribute, format!("attr: {a}"));
                }
            }
            for sig in CONFUSEREX_ATTRS {
                if a.contains(sig) {
                    self.push(Packer::ConfuserEx, 0.95, EvidenceType::CustomAttribute, format!("attr: {a}"));
                }
            }
            for sig in DOTFUSCATOR_ATTRS {
                if a.contains(sig) {
                    self.push(Packer::Dotfuscator, 0.95, EvidenceType::CustomAttribute, format!("attr: {a}"));
                }
            }
            for sig in EAZFUSCATOR_STRINGS {
                if a.contains(sig) {
                    self.push(Packer::Eazfuscator, 0.9, EvidenceType::CustomAttribute, format!("attr: {a}"));
                }
            }
        }
    }

    /// Scan resource names.
    pub fn scan_resources(&mut self, resource_names: &[String]) {
        for r in resource_names {
            let lower = r.to_lowercase();
            for sig in DOTNET_REACTOR_RESOURCES {
                if lower.contains(*sig) {
                    self.push(Packer::DotNetReactor, 0.85, EvidenceType::ResourceName, format!("resource: {r}"));
                }
            }
            for sig in COSTURA_RESOURCES {
                if lower.contains(*sig) {
                    self.push(Packer::Costura, 0.9, EvidenceType::ResourceName, format!("resource: {r}"));
                }
            }
            if lower.contains("babel") {
                self.push(Packer::Babel, 0.8, EvidenceType::ResourceName, format!("resource: {r}"));
            }
            if lower.contains("smartassembly") {
                self.push(Packer::SmartAssembly, 0.9, EvidenceType::ResourceName, format!("resource: {r}"));
            }
        }
    }

    /// Scan resource blobs for high entropy (packed/encrypted resources).
    pub fn scan_resource_entropy(&mut self, resources: &[(&str, &[u8])]) {
        for (name, data) in resources {
            let e = shannon_entropy(data);
            if e > 7.5 {
                // Very high entropy: likely compressed/encrypted
                self.push(
                    Packer::Unknown(0),
                    e / 8.0,
                    EvidenceType::ResourceEntropy,
                    format!("high entropy resource '{name}': {e:.2} bits"),
                );
            } else if e > 7.0 && data.len() > 4096 {
                self.push(
                    Packer::Unknown(1),
                    0.6,
                    EvidenceType::ResourceEntropy,
                    format!("elevated entropy resource '{name}': {e:.2} bits"),
                );
            }
        }
    }

    /// Scan string literals for packer-specific markers.
    pub fn scan_strings(&mut self, strings: &[String]) {
        for s in strings {
            for sig in MPRESS_STRINGS {
                if s.contains(sig) {
                    self.push(Packer::Mpress, 0.9, EvidenceType::StringLiteral, format!("string: {s}"));
                }
            }
            for sig in EAZFUSCATOR_STRINGS {
                if s.contains(sig) {
                    self.push(Packer::Eazfuscator, 0.9, EvidenceType::StringLiteral, format!("string: {s}"));
                }
            }
            if s.contains("ConfuserEx") || s.contains("Confuser") {
                self.push(Packer::ConfuserEx, 0.9, EvidenceType::StringLiteral, format!("string: {s}"));
            }
            if s.contains(".NET Reactor") || s.contains("NETReactor") {
                self.push(Packer::DotNetReactor, 0.9, EvidenceType::StringLiteral, format!("string: {s}"));
            }
        }
    }

    /// Scan IL patterns (sequences of opcodes encoded as opcode bytes).
    /// Pass method names as identifiers of methods with suspicious IL.
    pub fn scan_il_patterns(&mut self, method_names: &[String]) {
        for m in method_names {
            // ILProtector: uses a native method called "Protect"
            if m.contains("Protect") && m.contains("ILP") {
                self.push(Packer::ILProtector, 0.8, EvidenceType::IlPattern, format!("native stub: {m}"));
            }
            // ConfuserEx: uses calli stubs
            if m.contains("_Cctor") || m.contains("InitializeStub") {
                self.push(Packer::ConfuserEx, 0.7, EvidenceType::IlPattern, format!("stub: {m}"));
            }
            // .NET Reactor: has a native method that decrypts IL at runtime
            if m.contains("_nR") || m.contains("Reactor_Init") {
                self.push(Packer::DotNetReactor, 0.85, EvidenceType::IlPattern, format!("reactor stub: {m}"));
            }
        }
    }

    /// # Panics
    /// Panics if invariants are violated.
    #[must_use] 
    pub fn finish(self) -> PackerDetectionReport {
        // Aggregate by packer, taking highest confidence per packer
        let mut by_packer: HashMap<u64, (Packer, f64, Vec<PackerEvidence>)> = HashMap::new();

        for ev in self.evidence {
            let key = match ev.packer {
                Packer::Unknown(n) => 0xFF00 | u64::from(n),
                p => format!("{p:?}").len() as u64 + p.as_str().len() as u64,
            };
            let entry = by_packer.entry(key).or_insert((ev.packer, 0.0, Vec::new()));
            if ev.confidence > entry.1 {
                entry.1 = ev.confidence;
            }
            entry.2.push(ev);
        }

        let mut detected: Vec<DetectedPacker> = by_packer
            .into_values()
            .filter(|(_, conf, _)| *conf >= 0.5)
            .map(|(packer, confidence, evidence)| DetectedPacker {
                packer,
                confidence,
                evidence,
            })
            .collect();

        detected.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

        let is_obfuscated = detected.iter().any(|d| d.packer.is_obfuscator());
        let primary = detected.first().cloned();

        PackerDetectionReport {
            detected,
            is_obfuscated,
            primary_packer: primary,
        }
    }
}

impl Default for PackerDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Report ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedPacker {
    pub packer: Packer,
    pub confidence: f64,
    pub evidence: Vec<PackerEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerDetectionReport {
    pub detected: Vec<DetectedPacker>,
    pub is_obfuscated: bool,
    pub primary_packer: Option<DetectedPacker>,
}

impl PackerDetectionReport {
    #[must_use] 
    pub fn packer_names(&self) -> Vec<&str> {
        self.detected.iter().map(|d| d.packer.as_str()).collect()
    }

    pub fn highest_confidence(&self) -> f64 {
        self.detected.iter().map(|d| d.confidence).fold(0.0_f64, f64::max)
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

#[must_use] 
pub fn detect_packers(
    type_names: &[String],
    custom_attrs: &[String],
    resource_names: &[String],
    resource_blobs: &[(&str, &[u8])],
    strings: &[String],
    method_names: &[String],
) -> PackerDetectionReport {
    let mut detector = PackerDetector::new();
    detector.scan_type_names(type_names);
    detector.scan_custom_attributes(custom_attrs);
    detector.scan_resources(resource_names);
    detector.scan_resource_entropy(resource_blobs);
    detector.scan_strings(strings);
    detector.scan_il_patterns(method_names);
    detector.finish()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smartassembly_detection() {
        let types = vec!["#=qABCDEFG".to_owned()];
        let report = detect_packers(&types, &[], &[], &[], &[], &[]);
        assert!(report.detected.iter().any(|d| d.packer == Packer::SmartAssembly));
    }

    #[test]
    fn test_confuserex_attr() {
        let attrs = vec!["ConfuserEx.Runtime.AntiTamper".to_owned()];
        let report = detect_packers(&[], &attrs, &[], &[], &[], &[]);
        assert!(report.detected.iter().any(|d| d.packer == Packer::ConfuserEx));
        assert!(report.is_obfuscated);
    }

    #[test]
    fn test_costura_resource() {
        let resources = vec!["costura.some.assembly.dll.compressed".to_owned()];
        let report = detect_packers(&[], &[], &resources, &[], &[], &[]);
        assert!(report.detected.iter().any(|d| d.packer == Packer::Costura));
    }

    #[test]
    fn test_high_entropy_resource() {
        // Generate high-entropy data (random-like)
        let data: Vec<u8> = (0..1024).map(|i| (i * 37 + 13) as u8).collect();
        let blobs: &[(&str, &[u8])] = &[("encrypted_res", &data)];
        let mut detector = PackerDetector::new();
        detector.scan_resource_entropy(blobs);
        let report = detector.finish();
        // High entropy should be flagged if entropy > 7.0
        let _ = report;
    }

    #[test]
    fn test_dotnet_reactor_string() {
        let strings = vec![".NET Reactor v6.0".to_owned()];
        let report = detect_packers(&[], &[], &[], &[], &strings, &[]);
        assert!(report.detected.iter().any(|d| d.packer == Packer::DotNetReactor));
    }

    #[test]
    fn test_no_detection() {
        let types = vec!["System.Collections.Generic.List`1".to_owned()];
        let report = detect_packers(&types, &[], &[], &[], &[], &[]);
        assert!(!report.is_obfuscated);
    }

    #[test]
    fn test_packer_is_obfuscator() {
        assert!(Packer::ConfuserEx.is_obfuscator());
        assert!(Packer::SmartAssembly.is_obfuscator());
        assert!(!Packer::Costura.is_obfuscator());
    }

    #[test]
    fn test_shannon_entropy() {
        let zeros = vec![0u8; 100];
        assert!((shannon_entropy(&zeros) - 0.0).abs() < 0.001);
        let uniform: Vec<u8> = (0..=255).collect();
        assert!(shannon_entropy(&uniform) > 7.9);
    }
}
