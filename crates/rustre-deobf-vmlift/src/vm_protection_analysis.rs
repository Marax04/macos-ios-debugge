//! VM protection analysis for `rustre-deobf-vmlift`.

use crate::{HandlerSemantic, VmIsa, VmLifterPipeline};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Re-exported handler-semantic type used by VM protection scoring callers.
pub type VmHandlerSemantic = HandlerSemantic;

// ── VmComplexity ──────────────────────────────────────────────────────────────

/// Quantified complexity of a VM protection scheme.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VmComplexity {
    pub handler_diversity: f32,
    pub isa_size: usize,
    pub obfuscation_level: ObfuscationLevel,
    pub nested_vms: usize,
    pub estimated_handler_count: usize,
    pub dispatch_complexity: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ObfuscationLevel {
    #[default]
    None,
    Low,
    Medium,
    High,
    Extreme,
}

impl ObfuscationLevel {
    #[must_use]
    pub const fn score(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Low => 25,
            Self::Medium => 50,
            Self::High => 75,
            Self::Extreme => 100,
        }
    }

    #[must_use]
    pub const fn from_score(s: u8) -> Self {
        match s {
            0..=10 => Self::None,
            11..=35 => Self::Low,
            36..=60 => Self::Medium,
            61..=85 => Self::High,
            _ => Self::Extreme,
        }
    }
}

impl std::fmt::Display for ObfuscationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::None => "None",
                Self::Low => "Low",
                Self::Medium => "Medium",
                Self::High => "High",
                Self::Extreme => "Extreme",
            }
        )
    }
}

// ── ProtectedRegion ───────────────────────────────────────────────────────────

/// A region of code that is VM-protected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedRegion {
    pub original_address: u64,
    pub vm_entry_address: u64,
    pub vm_exit_address: Option<u64>,
    pub handler_count: usize,
    pub bytecode_size: usize,
    pub complexity: VmComplexity,
    pub protector_name: Option<String>,
}

impl ProtectedRegion {
    #[must_use]
    pub fn new(original_address: u64, vm_entry: u64) -> Self {
        Self {
            original_address,
            vm_entry_address: vm_entry,
            vm_exit_address: None,
            handler_count: 0,
            bytecode_size: 0,
            complexity: VmComplexity::default(),
            protector_name: None,
        }
    }

    #[must_use]
    pub const fn has_known_protector(&self) -> bool {
        self.protector_name.is_some()
    }

    #[must_use]
    pub const fn native_size_estimate(&self) -> usize {
        // Rough heuristic: 3-5 native instructions per VM bytecode byte.
        self.bytecode_size * 4
    }
}

// ── DeobfPriority ─────────────────────────────────────────────────────────────

/// Priority ranking for deobfuscation effort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[derive(Default)]
pub enum DeobfPriority {
    #[default]
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}


impl DeobfPriority {
    #[must_use]
    pub const fn from_complexity(c: &VmComplexity) -> Self {
        let score = c.obfuscation_level.score();
        match score {
            0..=25 => Self::Low,
            26..=50 => Self::Medium,
            51..=75 => Self::High,
            _ => Self::Critical,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

// ── EscapedCodeAnalysis ───────────────────────────────────────────────────────

/// Identifies native code that "escaped" from the VM and remains unprotected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscapedCodeRegion {
    pub address: u64,
    pub size: usize,
    pub confidence: f32,
    pub description: String,
}

pub struct EscapedCodeAnalyzer;

impl EscapedCodeAnalyzer {
    /// Find native code regions adjacent to VM-protected regions.
    #[must_use]
    pub fn find_escaped(
        protected: &[ProtectedRegion],
        all_code_size: usize,
    ) -> Vec<EscapedCodeRegion> {
        let mut escaped = Vec::new();
        // Regions between VM entries that are not accounted for.
        let mut sorted: Vec<u64> = protected.iter().map(|r| r.original_address).collect();
        sorted.sort_unstable();
        let mut prev = 0u64;
        for &addr in &sorted {
            if addr > prev + 0x100 {
                escaped.push(EscapedCodeRegion {
                    address: prev,
                    size: (addr - prev) as usize,
                    confidence: 0.6,
                    description: format!("Gap between protected regions: 0x{prev:x}–0x{addr:x}"),
                });
            }
            prev = addr + 0x100;
        }
        // Trailing region: anything between the last protected entry and the
        // end of the analysed code is also potentially escaped native code.
        let code_end = all_code_size as u64;
        if code_end > prev + 0x100 {
            escaped.push(EscapedCodeRegion {
                address: prev,
                size: (code_end - prev) as usize,
                confidence: 0.5,
                description: format!(
                    "Trailing native region after last protected entry: 0x{prev:x}–0x{code_end:x}"
                ),
            });
        }
        escaped
    }
}

// ── VmProtectionSummary ───────────────────────────────────────────────────────

/// Summary of the entire VM protection scheme for a binary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VmProtectionSummary {
    pub protected_regions: Vec<ProtectedRegion>,
    pub escaped_regions: Vec<EscapedCodeRegion>,
    pub total_protected_bytes: usize,
    pub total_native_estimate: usize,
    pub dominant_protector: Option<String>,
    pub overall_complexity: VmComplexity,
    pub deobf_priority: DeobfPriority,
    pub analysis_notes: Vec<String>,
}

impl VmProtectionSummary {
    #[must_use]
    pub fn new() -> Self {
        Self {
            deobf_priority: DeobfPriority::Low,
            ..Default::default()
        }
    }

    pub fn add_region(&mut self, region: ProtectedRegion) {
        self.total_protected_bytes += region.bytecode_size;
        self.total_native_estimate += region.native_size_estimate();
        self.protected_regions.push(region);
    }

    /// Compute aggregate stats.
    pub fn finalize(&mut self) {
        // Dominant protector = most common name.
        let mut name_count: HashMap<String, usize> = HashMap::new();
        for r in &self.protected_regions {
            if let Some(n) = &r.protector_name {
                *name_count.entry(n.clone()).or_insert(0) += 1;
            }
        }
        self.dominant_protector = name_count
            .into_iter()
            .max_by_key(|(_, c)| *c)
            .map(|(n, _)| n);

        // Overall complexity from max handler count.
        let max_handlers = self
            .protected_regions
            .iter()
            .map(|r| r.handler_count)
            .max()
            .unwrap_or(0);
        let obf_score = ((max_handlers as f32 / 256.0) * 100.0) as u8;
        self.overall_complexity.isa_size = self
            .protected_regions
            .iter()
            .map(|r| r.complexity.isa_size)
            .max()
            .unwrap_or(0);
        self.overall_complexity.obfuscation_level = ObfuscationLevel::from_score(obf_score);
        self.deobf_priority = DeobfPriority::from_complexity(&self.overall_complexity);
    }

    #[must_use]
    pub const fn region_count(&self) -> usize {
        self.protected_regions.len()
    }

    #[must_use]
    pub const fn is_vm_protected(&self) -> bool {
        !self.protected_regions.is_empty()
    }
}

// ── VmProtectionAnalysis ──────────────────────────────────────────────────────

/// Main VM protection analysis engine.
pub struct VmProtectionAnalysis {
    pub summary: VmProtectionSummary,
    pub isa: Option<VmIsa>,
}

impl Default for VmProtectionAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

impl VmProtectionAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self {
            summary: VmProtectionSummary::new(),
            isa: None,
        }
    }

    /// Analyse raw code bytes and return a full summary.
    #[must_use]
    pub fn analyze(code: &[u8], base_addr: u64) -> VmProtectionSummary {
        let report = VmLifterPipeline::detect_and_report(code, base_addr);
        let mut summary = VmProtectionSummary::new();
        summary.analysis_notes.clone_from(&report.analysis_notes);

        if report.dispatchers_found == 0 {
            summary
                .analysis_notes
                .push("No VM dispatchers detected".into());
            return summary;
        }

        // Create one ProtectedRegion per dispatcher found.
        for i in 0..report.dispatchers_found {
            let mut region = ProtectedRegion::new(base_addr, base_addr + i as u64 * 0x100);
            region.handler_count = report.total_handlers / report.dispatchers_found.max(1);
            region.bytecode_size = code.len() / report.dispatchers_found.max(1);
            region.complexity.isa_size = report.isa.len();
            region.complexity.handler_diversity = region.handler_count as f32 / 256.0;
            region.complexity.estimated_handler_count = region.handler_count;
            let obf = ((region.handler_count as f32 / 128.0).min(1.0) * 100.0) as u8;
            region.complexity.obfuscation_level = ObfuscationLevel::from_score(obf);
            summary.add_region(region);
        }

        let escaped = EscapedCodeAnalyzer::find_escaped(&summary.protected_regions, code.len());
        summary.escaped_regions = escaped;
        summary.finalize();
        summary
    }

    /// Rank regions by deobfuscation priority.
    #[must_use]
    pub fn prioritize(summary: &VmProtectionSummary) -> Vec<(&ProtectedRegion, DeobfPriority)> {
        let mut ranked: Vec<(&ProtectedRegion, DeobfPriority)> = summary
            .protected_regions
            .iter()
            .map(|r| (r, DeobfPriority::from_complexity(&r.complexity)))
            .collect();
        ranked.sort_by_key(|b| std::cmp::Reverse(b.1));
        ranked
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ObfuscationLevel ──────────────────────────────────────────────────────

    #[test]
    fn test_obfuscation_level_score() {
        assert_eq!(ObfuscationLevel::High.score(), 75);
        assert_eq!(ObfuscationLevel::None.score(), 0);
    }

    #[test]
    fn test_obfuscation_level_from_score() {
        assert_eq!(ObfuscationLevel::from_score(0), ObfuscationLevel::None);
        assert_eq!(ObfuscationLevel::from_score(80), ObfuscationLevel::High);
        assert_eq!(ObfuscationLevel::from_score(100), ObfuscationLevel::Extreme);
    }

    #[test]
    fn test_obfuscation_level_display() {
        assert_eq!(ObfuscationLevel::Medium.to_string(), "Medium");
    }

    // ── ProtectedRegion ───────────────────────────────────────────────────────

    #[test]
    fn test_protected_region_creation() {
        let r = ProtectedRegion::new(0x0040_1000, 0x0040_1080);
        assert_eq!(r.original_address, 0x0040_1000);
        assert!(!r.has_known_protector());
    }

    #[test]
    fn test_protected_region_native_size_estimate() {
        let mut r = ProtectedRegion::new(0, 0);
        r.bytecode_size = 100;
        assert_eq!(r.native_size_estimate(), 400);
    }

    #[test]
    fn test_protected_region_with_protector() {
        let mut r = ProtectedRegion::new(0, 0);
        r.protector_name = Some("VMProtect 3.x".into());
        assert!(r.has_known_protector());
    }

    // ── DeobfPriority ─────────────────────────────────────────────────────────

    #[test]
    fn test_deobf_priority_ordering() {
        assert!(DeobfPriority::Critical > DeobfPriority::High);
        assert!(DeobfPriority::High > DeobfPriority::Medium);
        assert!(DeobfPriority::Medium > DeobfPriority::Low);
    }

    #[test]
    fn test_deobf_priority_from_complexity_extreme() {
        let c = VmComplexity {
            obfuscation_level: ObfuscationLevel::Extreme,
            ..Default::default()
        };
        assert_eq!(DeobfPriority::from_complexity(&c), DeobfPriority::Critical);
    }

    #[test]
    fn test_deobf_priority_name() {
        assert_eq!(DeobfPriority::High.name(), "HIGH");
    }

    // ── EscapedCodeAnalyzer ───────────────────────────────────────────────────

    #[test]
    fn test_escaped_code_gap_detected() {
        let regions = vec![
            ProtectedRegion::new(0x0000, 0x0000),
            ProtectedRegion::new(0x1000, 0x1000),
        ];
        let escaped = EscapedCodeAnalyzer::find_escaped(&regions, 0x2000);
        assert!(!escaped.is_empty());
    }

    #[test]
    fn test_escaped_code_no_gap_adjacent() {
        let regions = vec![
            ProtectedRegion::new(0x0000, 0x0000),
            ProtectedRegion::new(0x0100, 0x0100),
        ];
        let escaped = EscapedCodeAnalyzer::find_escaped(&regions, 0x200);
        // gap of 0x100 should not trigger (≤ 0x100 threshold)
        assert!(escaped.is_empty());
    }

    // ── VmProtectionSummary ───────────────────────────────────────────────────

    #[test]
    fn test_summary_empty() {
        let s = VmProtectionSummary::new();
        assert!(!s.is_vm_protected());
        assert_eq!(s.region_count(), 0);
    }

    #[test]
    fn test_summary_add_region() {
        let mut s = VmProtectionSummary::new();
        let mut r = ProtectedRegion::new(0x1000, 0x1080);
        r.bytecode_size = 256;
        s.add_region(r);
        assert!(s.is_vm_protected());
        assert_eq!(s.total_protected_bytes, 256);
        assert_eq!(s.total_native_estimate, 1024);
    }

    #[test]
    fn test_summary_finalize_dominant_protector() {
        let mut s = VmProtectionSummary::new();
        let mut r1 = ProtectedRegion::new(0, 0);
        r1.protector_name = Some("VMP".into());
        s.add_region(r1);
        let mut r2 = ProtectedRegion::new(0, 0);
        r2.protector_name = Some("VMP".into());
        s.add_region(r2);
        let mut r3 = ProtectedRegion::new(0, 0);
        r3.protector_name = Some("Tigress".into());
        s.add_region(r3);
        s.finalize();
        assert_eq!(s.dominant_protector.as_deref(), Some("VMP"));
    }

    // ── VmProtectionAnalysis ──────────────────────────────────────────────────

    #[test]
    fn test_analysis_no_dispatcher() {
        let code = vec![0x90u8; 64]; // NOPs — no VM dispatcher
        let summary = VmProtectionAnalysis::analyze(&code, 0x1000);
        assert!(!summary.is_vm_protected());
    }

    #[test]
    fn test_analysis_with_jmp_table() {
        let mut code = vec![0x00u8; 16];
        code.extend_from_slice(&[0xFF, 0x24, 0xCD, 0x00, 0x00, 0x10, 0x00]);
        let summary = VmProtectionAnalysis::analyze(&code, 0x4000);
        // May detect one dispatcher; just no panic.
        let _ = summary.is_vm_protected();
    }

    #[test]
    fn test_analysis_prioritize_sorted() {
        let mut summary = VmProtectionSummary::new();
        let mut r1 = ProtectedRegion::new(0x1000, 0x1000);
        r1.complexity.obfuscation_level = ObfuscationLevel::High;
        r1.handler_count = 128;
        let mut r2 = ProtectedRegion::new(0x2000, 0x2000);
        r2.complexity.obfuscation_level = ObfuscationLevel::Low;
        r2.handler_count = 8;
        summary.add_region(r1);
        summary.add_region(r2);
        let ranked = VmProtectionAnalysis::prioritize(&summary);
        // Highest priority first
        assert!(ranked[0].1 >= ranked[1].1);
    }

    #[test]
    fn test_analysis_new() {
        let a = VmProtectionAnalysis::new();
        assert!(!a.summary.is_vm_protected());
        assert!(a.isa.is_none());
    }
}
