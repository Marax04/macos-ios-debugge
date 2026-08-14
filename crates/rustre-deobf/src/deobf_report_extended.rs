//! Extended deobfuscation report for `rustre-deobf`.
//!
//! Provides `DeobfReportExtended` with per-technique timelines,
//! confidence matrices, and HTML/Markdown report generation.
//!
//! # Relation to `report` and `deobf_report`
//! This module is **technique-centric**: it carries a 50+ entry
//! `TechniqueUsed` taxonomy, before/after byte-level `DeobfTimeline`
//! snapshots, a `ConfidenceMatrix` (separate detection and removal
//! confidences per technique), and a `RecoveredAsset` inventory.
//! Use it when you need fine-grained attribution by obfuscation technique.
//!
//! [`report`](crate::report) is **pass-centric** with serde-backed
//! `Finding`/`Severity` classification and JSON/HTML export.
//!
//! [`deobf_report`](crate::deobf_report) is **statistics-centric** with
//! `ObfScore`, multi-format export (text/JSON/HTML/CSV/Markdown), and a
//! `ReportAggregator` for batch analysis.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write as _;
pub use std::time::{Duration, Instant};

// ── TechniqueUsed ─────────────────────────────────────────────────────────────

/// 50+ obfuscation techniques that can be detected/removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TechniqueUsed {
    // String obfuscation
    XorStringEncryption,
    Rc4StringEncryption,
    AesStringEncryption,
    Base64Encoding,
    HexEncoding,
    RotNEncoding,
    StackStrings,
    SplitStrings,
    // Control flow
    ControlFlowFlattening,
    OpaquePredicates,
    BogusControlFlow,
    DispatcherObfuscation,
    VirtualizedCode,
    SwitchObfuscation,
    // Data obfuscation
    MixedBooleanArithmetic,
    ConstantObfuscation,
    DataFlowObfuscation,
    DeadCodeInsertion,
    JunkCodeInsertion,
    NopSleds,
    // Anti-analysis
    AntiDebugging,
    AntiDisassembly,
    AntiVirtualMachine,
    AntiDumping,
    AntiEmulation,
    TimingChecks,
    ProcessEnvChecks,
    HardwareChecks,
    // Packing / protection
    Packing,
    EncryptedSections,
    SelfModifyingCode,
    PolyMorphicCode,
    MetaMorphicCode,
    VirtualMachineProtection,
    TamperDetection,
    // Import obfuscation
    ApiHashing,
    DynamicImportResolution,
    ImportObfuscation,
    HookDetection,
    // Code transformation
    InstructionSubstitution,
    RegisterRenaming,
    CodeTransposition,
    FunctionInlining,
    FunctionOutlining,
    CodeFragmentation,
    // Misc
    SignaturePatching,
    TimestampManipulation,
    ResourceObfuscation,
    PEHeaderManipulation,
    DebugInfoStripping,
    SymbolStripping,
    TlsCallbackHiding,
    ExceptionHandlerAbuse,
}

impl TechniqueUsed {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::XorStringEncryption => "XOR String Encryption",
            Self::Rc4StringEncryption => "RC4 String Encryption",
            Self::AesStringEncryption => "AES String Encryption",
            Self::Base64Encoding => "Base64 Encoding",
            Self::HexEncoding => "Hex Encoding",
            Self::RotNEncoding => "ROT-N Encoding",
            Self::StackStrings => "Stack Strings",
            Self::SplitStrings => "Split Strings",
            Self::ControlFlowFlattening => "Control Flow Flattening",
            Self::OpaquePredicates => "Opaque Predicates",
            Self::BogusControlFlow => "Bogus Control Flow",
            Self::DispatcherObfuscation => "Dispatcher Obfuscation",
            Self::VirtualizedCode => "Virtualized Code",
            Self::SwitchObfuscation => "Switch Obfuscation",
            Self::MixedBooleanArithmetic => "Mixed Boolean Arithmetic",
            Self::ConstantObfuscation => "Constant Obfuscation",
            Self::DataFlowObfuscation => "Data Flow Obfuscation",
            Self::DeadCodeInsertion => "Dead Code Insertion",
            Self::JunkCodeInsertion => "Junk Code Insertion",
            Self::NopSleds => "NOP Sleds",
            Self::AntiDebugging => "Anti-Debugging",
            Self::AntiDisassembly => "Anti-Disassembly",
            Self::AntiVirtualMachine => "Anti-VM",
            Self::AntiDumping => "Anti-Dumping",
            Self::AntiEmulation => "Anti-Emulation",
            Self::TimingChecks => "Timing Checks",
            Self::ProcessEnvChecks => "Process Environment Checks",
            Self::HardwareChecks => "Hardware Checks",
            Self::Packing => "Packing",
            Self::EncryptedSections => "Encrypted Sections",
            Self::SelfModifyingCode => "Self-Modifying Code",
            Self::PolyMorphicCode => "Polymorphic Code",
            Self::MetaMorphicCode => "Metamorphic Code",
            Self::VirtualMachineProtection => "VM Protection",
            Self::TamperDetection => "Tamper Detection",
            Self::ApiHashing => "API Hashing",
            Self::DynamicImportResolution => "Dynamic Import Resolution",
            Self::ImportObfuscation => "Import Obfuscation",
            Self::HookDetection => "Hook Detection",
            Self::InstructionSubstitution => "Instruction Substitution",
            Self::RegisterRenaming => "Register Renaming",
            Self::CodeTransposition => "Code Transposition",
            Self::FunctionInlining => "Function Inlining",
            Self::FunctionOutlining => "Function Outlining",
            Self::CodeFragmentation => "Code Fragmentation",
            Self::SignaturePatching => "Signature Patching",
            Self::TimestampManipulation => "Timestamp Manipulation",
            Self::ResourceObfuscation => "Resource Obfuscation",
            Self::PEHeaderManipulation => "PE Header Manipulation",
            Self::DebugInfoStripping => "Debug Info Stripping",
            Self::SymbolStripping => "Symbol Stripping",
            Self::TlsCallbackHiding => "TLS Callback Hiding",
            Self::ExceptionHandlerAbuse => "Exception Handler Abuse",
        }
    }

    /// Category grouping.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::XorStringEncryption
            | Self::Rc4StringEncryption
            | Self::AesStringEncryption
            | Self::Base64Encoding
            | Self::HexEncoding
            | Self::RotNEncoding
            | Self::StackStrings
            | Self::SplitStrings => "String Obfuscation",
            Self::ControlFlowFlattening
            | Self::OpaquePredicates
            | Self::BogusControlFlow
            | Self::DispatcherObfuscation
            | Self::VirtualizedCode
            | Self::SwitchObfuscation => "Control Flow",
            Self::MixedBooleanArithmetic
            | Self::ConstantObfuscation
            | Self::DataFlowObfuscation
            | Self::DeadCodeInsertion
            | Self::JunkCodeInsertion
            | Self::NopSleds => "Data Obfuscation",
            Self::AntiDebugging
            | Self::AntiDisassembly
            | Self::AntiVirtualMachine
            | Self::AntiDumping
            | Self::AntiEmulation
            | Self::TimingChecks
            | Self::ProcessEnvChecks
            | Self::HardwareChecks => "Anti-Analysis",
            Self::Packing
            | Self::EncryptedSections
            | Self::SelfModifyingCode
            | Self::PolyMorphicCode
            | Self::MetaMorphicCode
            | Self::VirtualMachineProtection
            | Self::TamperDetection => "Packing/Protection",
            Self::ApiHashing
            | Self::DynamicImportResolution
            | Self::ImportObfuscation
            | Self::HookDetection => "Import Obfuscation",
            _ => "Miscellaneous",
        }
    }
}

// ── DeobfTimeline ─────────────────────────────────────────────────────────────

/// Before/after snapshot for a single deobfuscation pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeobfTimeline {
    pub technique: TechniqueUsed,
    pub pass_name: String,
    pub before_bytes: Option<Vec<u8>>,
    pub after_bytes: Option<Vec<u8>>,
    pub patches_applied: usize,
    pub elapsed_ms: u64,
    pub notes: String,
}

impl DeobfTimeline {
    #[must_use]
    pub fn new(technique: TechniqueUsed, pass_name: impl Into<String>) -> Self {
        Self {
            technique,
            pass_name: pass_name.into(),
            before_bytes: None,
            after_bytes: None,
            patches_applied: 0,
            elapsed_ms: 0,
            notes: String::new(),
        }
    }

    /// Bytes changed by this pass.
    #[must_use]
    pub fn bytes_changed(&self) -> usize {
        match (&self.before_bytes, &self.after_bytes) {
            (Some(b), Some(a)) => b.iter().zip(a.iter()).filter(|(x, y)| x != y).count(),
            _ => 0,
        }
    }
}

// ── RecoveredAsset ────────────────────────────────────────────────────────────

/// Type of recovered asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetKind {
    String,
    Function,
    Type,
    ControlFlow,
    Import,
    Constant,
}

/// An asset recovered by the deobfuscation pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredAsset {
    pub kind: AssetKind,
    pub name: String,
    pub address: Option<u64>,
    pub confidence: f32,
    pub raw_value: Option<String>,
    pub technique: TechniqueUsed,
}

impl RecoveredAsset {
    #[must_use]
    pub fn new(
        kind: AssetKind,
        name: impl Into<String>,
        technique: TechniqueUsed,
        confidence: f32,
    ) -> Self {
        Self {
            kind,
            name: name.into(),
            address: None,
            confidence,
            raw_value: None,
            technique,
        }
    }

    #[must_use]
    pub const fn with_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    #[must_use]
    pub fn with_value(mut self, v: impl Into<String>) -> Self {
        self.raw_value = Some(v.into());
        self
    }
}

// ── ConfidenceMatrix ──────────────────────────────────────────────────────────

/// A matrix of per-technique confidence scores.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfidenceMatrix {
    /// Technique → detection confidence (0.0–1.0).
    pub detection: HashMap<String, f32>,
    /// Technique → removal success confidence (0.0–1.0).
    pub removal: HashMap<String, f32>,
}

impl ConfidenceMatrix {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_detection(&mut self, technique: TechniqueUsed, confidence: f32) {
        self.detection
            .insert(technique.name().to_string(), confidence.clamp(0.0, 1.0));
    }

    pub fn set_removal(&mut self, technique: TechniqueUsed, confidence: f32) {
        self.removal
            .insert(technique.name().to_string(), confidence.clamp(0.0, 1.0));
    }

    #[must_use]
    pub fn detection_for(&self, technique: TechniqueUsed) -> f32 {
        self.detection.get(technique.name()).copied().unwrap_or(0.0)
    }

    #[must_use]
    pub fn removal_for(&self, technique: TechniqueUsed) -> f32 {
        self.removal.get(technique.name()).copied().unwrap_or(0.0)
    }

    /// Average detection confidence across all techniques.
    #[must_use]
    pub fn avg_detection(&self) -> f32 {
        if self.detection.is_empty() {
            return 0.0;
        }
        self.detection.values().sum::<f32>() / f32::from(u16::try_from(self.detection.len()).unwrap_or(u16::MAX))
    }

    /// Average removal confidence.
    #[must_use]
    pub fn avg_removal(&self) -> f32 {
        if self.removal.is_empty() {
            return 0.0;
        }
        self.removal.values().sum::<f32>() / f32::from(u16::try_from(self.removal.len()).unwrap_or(u16::MAX))
    }
}

// ── DeobfReportExtended ───────────────────────────────────────────────────────

/// Extended deobfuscation report with full timeline, asset inventory, and rendering.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeobfReportExtended {
    pub binary_name: String,
    pub binary_size: usize,
    pub techniques: Vec<TechniqueUsed>,
    pub timeline: Vec<DeobfTimeline>,
    pub recovered_assets: Vec<RecoveredAsset>,
    pub confidence_matrix: ConfidenceMatrix,
    pub total_patches: usize,
    pub total_bytes_modified: usize,
    pub analysis_duration_ms: u64,
    pub overall_confidence: f32,
    pub notes: Vec<String>,
}

impl DeobfReportExtended {
    #[must_use]
    pub fn new(binary_name: impl Into<String>, binary_size: usize) -> Self {
        Self {
            binary_name: binary_name.into(),
            binary_size,
            ..Default::default()
        }
    }

    /// Record a detected technique.
    pub fn add_technique(&mut self, t: TechniqueUsed, detection_conf: f32, removal_conf: f32) {
        if !self.techniques.contains(&t) {
            self.techniques.push(t);
        }
        self.confidence_matrix.set_detection(t, detection_conf);
        self.confidence_matrix.set_removal(t, removal_conf);
    }

    /// Add a timeline entry.
    pub fn add_timeline(&mut self, entry: DeobfTimeline) {
        self.total_patches += entry.patches_applied;
        self.total_bytes_modified += entry.bytes_changed();
        self.timeline.push(entry);
    }

    /// Add a recovered asset.
    pub fn add_asset(&mut self, asset: RecoveredAsset) {
        self.recovered_assets.push(asset);
    }

    /// Compute overall confidence from the confidence matrix.
    pub fn compute_overall_confidence(&mut self) {
        let det = self.confidence_matrix.avg_detection();
        let rem = self.confidence_matrix.avg_removal();
        self.overall_confidence = det.mul_add(0.6, rem * 0.4).clamp(0.0, 1.0);
    }

    /// Count assets of a specific kind.
    #[must_use]
    pub fn asset_count(&self, kind: AssetKind) -> usize {
        self.recovered_assets
            .iter()
            .filter(|a| a.kind == kind)
            .count()
    }

    /// Techniques grouped by category.
    #[must_use]
    pub fn techniques_by_category(&self) -> HashMap<&'static str, Vec<TechniqueUsed>> {
        let mut map: HashMap<&'static str, Vec<TechniqueUsed>> = HashMap::new();
        for &t in &self.techniques {
            map.entry(t.category()).or_default().push(t);
        }
        map
    }
}

// ── HTMLReportGenerator ───────────────────────────────────────────────────────

/// Generates an HTML report from a `DeobfReportExtended`.
pub struct HTMLReportGenerator;

impl HTMLReportGenerator {
    /// Generate a self-contained HTML document.
    #[must_use]
    pub fn generate(report: &DeobfReportExtended) -> String {
        let mut html = String::new();
        html.push_str("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        html.push_str("<title>Deobfuscation Report</title>");
        html.push_str("<style>body{font-family:monospace;background:#1e1e1e;color:#d4d4d4}");
        let css1 = "h1,h2{".to_string() + "color:#569cd6}table{" + "border-collapse:collapse;width:100%}";
        html.push_str(&css1);
        html.push_str("th,td{border:1px solid #444;padding:4px 8px}th{background:#2d2d2d}");
        html.push_str("tr:hover{background:#2a2a2a}.badge{padding:2px 6px;border-radius:3px}");
        let css2 = ".high{".to_string() + "background:#c83232}.medium{" + "background:#b87c1e}.low{" + "background:#2d7a2d}</style></head><body>";
        html.push_str(&css2);

        let _ = write!(html, "<h1>Deobfuscation Report: {}</h1>", report.binary_name);
        let _ = write!(
            html,
            "<p>Binary size: {} bytes | Analysis: {}ms | Overall confidence: {:.0}%</p>",
            report.binary_size,
            report.analysis_duration_ms,
            report.overall_confidence * 100.0
        );

        // Techniques table
        html.push_str("<h2>Detected Techniques</h2><table><tr><th>Technique</th><th>Category</th><th>Detection</th><th>Removal</th></tr>");
        for &tech in &report.techniques {
            let det = report.confidence_matrix.detection_for(tech);
            let rem = report.confidence_matrix.removal_for(tech);
            let _ = write!(
                html,
                "<tr><td>{}</td><td>{}</td><td>{:.0}%</td><td>{:.0}%</td></tr>",
                tech.name(),
                tech.category(),
                det * 100.0,
                rem * 100.0
            );
        }
        html.push_str("</table>");

        // Timeline
        if !report.timeline.is_empty() {
            html.push_str("<h2>Pass Timeline</h2><table><tr><th>Pass</th><th>Technique</th><th>Patches</th><th>Bytes</th><th>Time(ms)</th></tr>");
            for entry in &report.timeline {
                let _ = write!(
                    html,
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    entry.pass_name,
                    entry.technique.name(),
                    entry.patches_applied,
                    entry.bytes_changed(),
                    entry.elapsed_ms
                );
            }
            html.push_str("</table>");
        }

        // Recovered assets
        if !report.recovered_assets.is_empty() {
            html.push_str("<h2>Recovered Assets</h2><table><tr><th>Kind</th><th>Name</th><th>Address</th><th>Confidence</th></tr>");
            for asset in &report.recovered_assets {
                let addr = asset
                    .address.map_or_else(|| "-".into(), |a| format!("0x{a:x}"));
                let _ = write!(
                    html,
                    "<tr><td>{:?}</td><td>{}</td><td>{}</td><td>{:.0}%</td></tr>",
                    asset.kind,
                    asset.name,
                    addr,
                    asset.confidence * 100.0
                );
            }
            html.push_str("</table>");
        }

        html.push_str("</body></html>");
        html
    }
}

// ── MarkdownReportGenerator ───────────────────────────────────────────────────

/// Generates a Markdown report from a `DeobfReportExtended`.
pub struct MarkdownReportGenerator;

impl MarkdownReportGenerator {
    /// Generate a Markdown string.
    #[must_use]
    pub fn generate(report: &DeobfReportExtended) -> String {
        let mut md = String::new();
        let _ = writeln!(md, "# Deobfuscation Report: {}\n", report.binary_name);
        let _ = writeln!(md, "- **Binary size**: {} bytes", report.binary_size);
        let _ = writeln!(md, "- **Analysis duration**: {}ms", report.analysis_duration_ms);
        let _ = writeln!(md, "- **Overall confidence**: {:.0}%", report.overall_confidence * 100.0);
        let _ = writeln!(md, "- **Total patches**: {}", report.total_patches);
        let _ = writeln!(md, "- **Bytes modified**: {}\n", report.total_bytes_modified);

        // Techniques
        md.push_str("## Detected Techniques\n\n");
        md.push_str("| Technique | Category | Detection | Removal |\n");
        md.push_str("|-----------|----------|-----------|--------|\n");
        for &tech in &report.techniques {
            let det = report.confidence_matrix.detection_for(tech);
            let rem = report.confidence_matrix.removal_for(tech);
            let _ = writeln!(
                md,
                "| {} | {} | {:.0}% | {:.0}% |",
                tech.name(),
                tech.category(),
                det * 100.0,
                rem * 100.0
            );
        }
        md.push('\n');

        // Timeline
        if !report.timeline.is_empty() {
            md.push_str("## Pass Timeline\n\n");
            md.push_str("| Pass | Technique | Patches | Bytes | Time (ms) |\n");
            md.push_str("|------|-----------|---------|-------|----------|\n");
            for entry in &report.timeline {
                let _ = writeln!(
                    md,
                    "| {} | {} | {} | {} | {} |",
                    entry.pass_name,
                    entry.technique.name(),
                    entry.patches_applied,
                    entry.bytes_changed(),
                    entry.elapsed_ms
                );
            }
            md.push('\n');
        }

        // Assets
        if !report.recovered_assets.is_empty() {
            md.push_str("## Recovered Assets\n\n");
            md.push_str("| Kind | Name | Address | Confidence |\n");
            md.push_str("|------|------|---------|------------|\n");
            for asset in &report.recovered_assets {
                let addr = asset
                    .address.map_or_else(|| "-".into(), |a| format!("0x{a:x}"));
                let _ = writeln!(
                    md,
                    "| {:?} | {} | {} | {:.0}% |",
                    asset.kind,
                    asset.name,
                    addr,
                    asset.confidence * 100.0
                );
            }
        }

        md
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TechniqueUsed ────────────────────────────────────────────────────────

    #[test]
    fn test_technique_name_nonempty() {
        assert!(!TechniqueUsed::XorStringEncryption.name().is_empty());
        assert!(!TechniqueUsed::VirtualMachineProtection.name().is_empty());
    }

    #[test]
    fn test_technique_category_string_obfuscation() {
        assert_eq!(
            TechniqueUsed::XorStringEncryption.category(),
            "String Obfuscation"
        );
    }

    #[test]
    fn test_technique_category_control_flow() {
        assert_eq!(
            TechniqueUsed::ControlFlowFlattening.category(),
            "Control Flow"
        );
    }

    #[test]
    fn test_technique_category_anti_analysis() {
        assert_eq!(TechniqueUsed::AntiDebugging.category(), "Anti-Analysis");
    }

    #[test]
    fn test_technique_total_count_at_least_50() {
        let techniques = [
            TechniqueUsed::XorStringEncryption,
            TechniqueUsed::Rc4StringEncryption,
            TechniqueUsed::AesStringEncryption,
            TechniqueUsed::Base64Encoding,
            TechniqueUsed::HexEncoding,
            TechniqueUsed::RotNEncoding,
            TechniqueUsed::StackStrings,
            TechniqueUsed::SplitStrings,
            TechniqueUsed::ControlFlowFlattening,
            TechniqueUsed::OpaquePredicates,
            TechniqueUsed::BogusControlFlow,
            TechniqueUsed::DispatcherObfuscation,
            TechniqueUsed::VirtualizedCode,
            TechniqueUsed::SwitchObfuscation,
            TechniqueUsed::MixedBooleanArithmetic,
            TechniqueUsed::ConstantObfuscation,
            TechniqueUsed::DataFlowObfuscation,
            TechniqueUsed::DeadCodeInsertion,
            TechniqueUsed::JunkCodeInsertion,
            TechniqueUsed::NopSleds,
            TechniqueUsed::AntiDebugging,
            TechniqueUsed::AntiDisassembly,
            TechniqueUsed::AntiVirtualMachine,
            TechniqueUsed::AntiDumping,
            TechniqueUsed::AntiEmulation,
            TechniqueUsed::TimingChecks,
            TechniqueUsed::ProcessEnvChecks,
            TechniqueUsed::HardwareChecks,
            TechniqueUsed::Packing,
            TechniqueUsed::EncryptedSections,
            TechniqueUsed::SelfModifyingCode,
            TechniqueUsed::PolyMorphicCode,
            TechniqueUsed::MetaMorphicCode,
            TechniqueUsed::VirtualMachineProtection,
            TechniqueUsed::TamperDetection,
            TechniqueUsed::ApiHashing,
            TechniqueUsed::DynamicImportResolution,
            TechniqueUsed::ImportObfuscation,
            TechniqueUsed::HookDetection,
            TechniqueUsed::InstructionSubstitution,
            TechniqueUsed::RegisterRenaming,
            TechniqueUsed::CodeTransposition,
            TechniqueUsed::FunctionInlining,
            TechniqueUsed::FunctionOutlining,
            TechniqueUsed::CodeFragmentation,
            TechniqueUsed::SignaturePatching,
            TechniqueUsed::TimestampManipulation,
            TechniqueUsed::ResourceObfuscation,
            TechniqueUsed::PEHeaderManipulation,
            TechniqueUsed::DebugInfoStripping,
            TechniqueUsed::SymbolStripping,
            TechniqueUsed::TlsCallbackHiding,
            TechniqueUsed::ExceptionHandlerAbuse,
        ];
        assert!(techniques.len() >= 50);
    }

    // ── DeobfTimeline ────────────────────────────────────────────────────────

    #[test]
    fn test_timeline_bytes_changed() {
        let mut entry = DeobfTimeline::new(TechniqueUsed::XorStringEncryption, "xor-pass");
        entry.before_bytes = Some(vec![0xAA, 0xBB, 0xCC]);
        entry.after_bytes = Some(vec![0xAA, 0x00, 0xCC]);
        assert_eq!(entry.bytes_changed(), 1);
    }

    #[test]
    fn test_timeline_bytes_changed_none() {
        let entry = DeobfTimeline::new(TechniqueUsed::NopSleds, "nop");
        assert_eq!(entry.bytes_changed(), 0);
    }

    // ── RecoveredAsset ────────────────────────────────────────────────────────

    #[test]
    fn test_recovered_asset_creation() {
        let a = RecoveredAsset::new(
            AssetKind::String,
            "http://evil.com",
            TechniqueUsed::XorStringEncryption,
            0.9,
        );
        assert_eq!(a.kind, AssetKind::String);
        assert!((a.confidence - 0.9).abs() < 0.001);
    }

    #[test]
    fn test_recovered_asset_with_address() {
        let a = RecoveredAsset::new(
            AssetKind::Function,
            "decrypt",
            TechniqueUsed::Rc4StringEncryption,
            0.7,
        )
        .with_address(0x401000);
        assert_eq!(a.address, Some(0x401000));
    }

    // ── ConfidenceMatrix ──────────────────────────────────────────────────────

    #[test]
    fn test_confidence_matrix_set_get() {
        let mut m = ConfidenceMatrix::new();
        m.set_detection(TechniqueUsed::Packing, 0.85);
        assert!((m.detection_for(TechniqueUsed::Packing) - 0.85).abs() < 0.001);
    }

    #[test]
    fn test_confidence_matrix_clamped() {
        let mut m = ConfidenceMatrix::new();
        m.set_detection(TechniqueUsed::NopSleds, 2.0);
        assert_eq!(m.detection_for(TechniqueUsed::NopSleds), 1.0);
    }

    #[test]
    fn test_confidence_matrix_avg() {
        let mut m = ConfidenceMatrix::new();
        m.set_detection(TechniqueUsed::Packing, 0.80);
        m.set_detection(TechniqueUsed::NopSleds, 0.60);
        let avg = m.avg_detection();
        assert!((avg - 0.70).abs() < 0.001);
    }

    #[test]
    fn test_confidence_matrix_empty_avg() {
        let m = ConfidenceMatrix::new();
        assert_eq!(m.avg_detection(), 0.0);
    }

    // ── DeobfReportExtended ───────────────────────────────────────────────────

    #[test]
    fn test_report_creation() {
        let r = DeobfReportExtended::new("sample.exe", 1024);
        assert_eq!(r.binary_name, "sample.exe");
        assert_eq!(r.binary_size, 1024);
    }

    #[test]
    fn test_report_add_technique() {
        let mut r = DeobfReportExtended::new("t", 0);
        r.add_technique(TechniqueUsed::XorStringEncryption, 0.9, 0.8);
        assert_eq!(r.techniques.len(), 1);
        assert!(
            (r.confidence_matrix
                .detection_for(TechniqueUsed::XorStringEncryption)
                - 0.9)
                .abs()
                < 0.001
        );
    }

    #[test]
    fn test_report_no_duplicate_technique() {
        let mut r = DeobfReportExtended::new("t", 0);
        r.add_technique(TechniqueUsed::Packing, 0.8, 0.7);
        r.add_technique(TechniqueUsed::Packing, 0.9, 0.8); // duplicate
        assert_eq!(r.techniques.len(), 1);
    }

    #[test]
    fn test_report_add_timeline_counts_patches() {
        let mut r = DeobfReportExtended::new("t", 100);
        let mut entry = DeobfTimeline::new(TechniqueUsed::NopSleds, "nop-pass");
        entry.patches_applied = 5;
        r.add_timeline(entry);
        assert_eq!(r.total_patches, 5);
    }

    #[test]
    fn test_report_asset_count() {
        let mut r = DeobfReportExtended::new("t", 0);
        r.add_asset(RecoveredAsset::new(
            AssetKind::String,
            "s1",
            TechniqueUsed::XorStringEncryption,
            0.8,
        ));
        r.add_asset(RecoveredAsset::new(
            AssetKind::String,
            "s2",
            TechniqueUsed::XorStringEncryption,
            0.7,
        ));
        r.add_asset(RecoveredAsset::new(
            AssetKind::Function,
            "f1",
            TechniqueUsed::ControlFlowFlattening,
            0.9,
        ));
        assert_eq!(r.asset_count(AssetKind::String), 2);
        assert_eq!(r.asset_count(AssetKind::Function), 1);
    }

    #[test]
    fn test_report_compute_confidence() {
        let mut r = DeobfReportExtended::new("t", 0);
        r.add_technique(TechniqueUsed::Packing, 0.8, 0.6);
        r.compute_overall_confidence();
        assert!(r.overall_confidence > 0.0 && r.overall_confidence <= 1.0);
    }

    #[test]
    fn test_report_techniques_by_category() {
        let mut r = DeobfReportExtended::new("t", 0);
        r.add_technique(TechniqueUsed::XorStringEncryption, 0.8, 0.7);
        r.add_technique(TechniqueUsed::ControlFlowFlattening, 0.9, 0.8);
        let by_cat = r.techniques_by_category();
        assert!(by_cat.contains_key("String Obfuscation"));
        assert!(by_cat.contains_key("Control Flow"));
    }

    // ── HTMLReportGenerator ───────────────────────────────────────────────────

    #[test]
    fn test_html_report_nonempty() {
        let r = DeobfReportExtended::new("test.exe", 512);
        let html = HTMLReportGenerator::generate(&r);
        assert!(!html.is_empty());
        assert!(html.contains("test.exe"));
    }

    #[test]
    fn test_html_report_contains_techniques() {
        let mut r = DeobfReportExtended::new("t", 0);
        r.add_technique(TechniqueUsed::Packing, 0.9, 0.8);
        let html = HTMLReportGenerator::generate(&r);
        assert!(html.contains("Packing"));
    }

    #[test]
    fn test_html_report_valid_doctype() {
        let r = DeobfReportExtended::new("t", 0);
        let html = HTMLReportGenerator::generate(&r);
        assert!(html.starts_with("<!DOCTYPE html>"));
    }

    // ── MarkdownReportGenerator ───────────────────────────────────────────────

    #[test]
    fn test_markdown_report_nonempty() {
        let r = DeobfReportExtended::new("binary.bin", 1024);
        let md = MarkdownReportGenerator::generate(&r);
        assert!(!md.is_empty());
        assert!(md.contains("binary.bin"));
    }

    #[test]
    fn test_markdown_report_contains_techniques_table() {
        let mut r = DeobfReportExtended::new("b", 0);
        r.add_technique(TechniqueUsed::NopSleds, 0.5, 0.5);
        let md = MarkdownReportGenerator::generate(&r);
        assert!(md.contains("NOP Sleds"));
    }

    #[test]
    fn test_markdown_report_contains_timeline() {
        let mut r = DeobfReportExtended::new("b", 0);
        let mut entry = DeobfTimeline::new(TechniqueUsed::NopSleds, "pass1");
        entry.patches_applied = 3;
        r.add_timeline(entry);
        let md = MarkdownReportGenerator::generate(&r);
        assert!(md.contains("pass1"));
    }

    #[test]
    fn test_markdown_report_starts_with_h1() {
        let r = DeobfReportExtended::new("t", 0);
        let md = MarkdownReportGenerator::generate(&r);
        assert!(md.starts_with("# Deobfuscation Report:"));
    }

    #[test]
    fn test_markdown_report_asset_table() {
        let mut r = DeobfReportExtended::new("b", 0);
        r.add_asset(RecoveredAsset::new(
            AssetKind::String,
            "evil.com",
            TechniqueUsed::XorStringEncryption,
            0.95,
        ));
        let md = MarkdownReportGenerator::generate(&r);
        assert!(md.contains("evil.com"));
    }
}
