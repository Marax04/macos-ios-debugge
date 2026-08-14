//! `ios_jailbreak_detector` — Extended jailbreak detection analysis.
//!
//! The crate root already defines [`JailbreakIndicator`], [`JailbreakTechnique`],
//! [`JailbreakDetector`], [`JAILBREAK_PATHS`], and [`JAILBREAK_DYLIBS`].
//!
//! This module adds:
//!
//! * [`DetectionMethod`] — how the jailbreak was detected.
//! * [`IosJailbreakDetector`] — an extended detector with configurable methods,
//!   scoring, and confidence calculation.
//! * [`JailbreakReport`] — consolidated report with risk score and remediation hints.
//!
//! To avoid redefining existing crate types, all jailbreak-related base types
//! are imported from `crate::`.

pub use crate::{
    JailbreakDetector, JailbreakIndicator, JailbreakTechnique, JAILBREAK_DYLIBS, JAILBREAK_PATHS,
};

use serde::{Deserialize, Serialize};
use std::fmt;

// ─── DetectionMethod ─────────────────────────────────────────────────────────

/// The analysis method used to find a jailbreak indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectionMethod {
    /// Scanning string literals for known paths / dylib names.
    StringScan,
    /// Checking the Mach-O symbol table for jailbreak-related imports.
    SymbolTable,
    /// Checking load commands for injected dylibs.
    LoadCommands,
    /// Scanning imported selectors for jailbreak API usage.
    ObjcSelector,
    /// Scanning for runtime API calls (dlopen, fork, ptrace, etc.).
    RuntimeApiCall,
    /// Checking for URL scheme handlers (cydia://, sileo://).
    UrlScheme,
    /// Heuristic analysis of code patterns.
    Heuristic,
}

impl DetectionMethod {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::StringScan => "String scan",
            Self::SymbolTable => "Symbol table",
            Self::LoadCommands => "Load commands",
            Self::ObjcSelector => "ObjC selector scan",
            Self::RuntimeApiCall => "Runtime API call detection",
            Self::UrlScheme => "URL scheme handler check",
            Self::Heuristic => "Heuristic analysis",
        }
    }
}

impl fmt::Display for DetectionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ─── ExtendedIndicator ────────────────────────────────────────────────────────

/// An extended jailbreak indicator that includes the detection method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedIndicator {
    /// Core indicator (technique + pattern + address).
    pub indicator: JailbreakIndicator,
    /// The analysis method that found this indicator.
    pub method: DetectionMethod,
    /// Confidence [0, 100] that this is a genuine jailbreak indicator.
    pub confidence: u8,
}

impl ExtendedIndicator {
    /// Returns `true` when the confidence is high enough to be actionable.
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 75
    }
}

impl fmt::Display for ExtendedIndicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} — {} (confidence: {}%)",
            self.method,
            self.indicator.technique.description(),
            self.indicator.pattern,
            self.confidence,
        )
    }
}

// ─── JailbreakReport ──────────────────────────────────────────────────────────

/// Consolidated jailbreak detection report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JailbreakReport {
    /// Whether the binary shows jailbreak detection code.
    pub has_jailbreak_detection: bool,
    /// All extended indicators found.
    pub indicators: Vec<ExtendedIndicator>,
    /// Overall risk score [0, 100].
    pub risk_score: u8,
    /// Number of high-confidence indicators.
    pub high_confidence_count: usize,
    /// Human-readable summary.
    pub summary: String,
    /// Remediation hints.
    pub remediation: Vec<String>,
}

impl JailbreakReport {
    /// Returns high-confidence indicators.
    #[must_use]
    pub fn high_confidence_indicators(&self) -> Vec<&ExtendedIndicator> {
        self.indicators.iter().filter(|i| i.is_high_confidence()).collect()
    }

    /// Returns indicators found via a specific detection method.
    #[must_use]
    pub fn indicators_by_method(&self, method: DetectionMethod) -> Vec<&ExtendedIndicator> {
        self.indicators.iter().filter(|i| i.method == method).collect()
    }

    /// Returns `true` when the binary is likely jailbroken.
    #[must_use]
    pub const fn is_jailbroken(&self) -> bool {
        self.risk_score >= 70 && self.high_confidence_count >= 2
    }
}

// ─── IosJailbreakDetector ────────────────────────────────────────────────────

/// Extended jailbreak detection analyser.
///
/// Uses the base [`JailbreakDetector`] from the crate root for the initial
/// string/symbol scan, then enriches results with method attribution and
/// confidence scoring.
#[derive(Debug, Clone)]
pub struct IosJailbreakDetector {
    /// Whether to run the base string scan (default: true).
    pub run_string_scan: bool,
    /// Whether to scan the `Mach-O` symbol table (default: true).
    pub run_symbol_scan: bool,
    /// Whether to scan `ObjC` selectors (default: true).
    pub run_objc_scan: bool,
    /// Whether to scan load commands (default: true).
    pub run_load_cmd_scan: bool,
    /// Minimum confidence [0, 100] for an indicator to be included.
    pub min_confidence: u8,
}

impl Default for IosJailbreakDetector {
    fn default() -> Self {
        Self {
            run_string_scan: true,
            run_symbol_scan: true,
            run_objc_scan: true,
            run_load_cmd_scan: true,
            min_confidence: 50,
        }
    }
}

impl IosJailbreakDetector {
    /// Create a new detector with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the minimum confidence threshold.
    #[must_use]
    pub const fn with_min_confidence(mut self, c: u8) -> Self {
        self.min_confidence = c;
        self
    }

    /// Scan a Mach-O binary and return a [`JailbreakReport`].
    #[must_use]
    pub fn scan(&self, binary: &[u8]) -> JailbreakReport {
        if binary.is_empty() {
            return Self::empty_report();
        }

        let mut indicators: Vec<ExtendedIndicator> = Vec::new();

        // ── Base string scan via crate root JailbreakDetector ────────────
        if self.run_string_scan {
            for indicator in JailbreakDetector::scan(binary) {
                let confidence = Self::confidence_for_technique(indicator.technique, DetectionMethod::StringScan);
                if confidence >= self.min_confidence {
                    indicators.push(ExtendedIndicator {
                        indicator,
                        method: DetectionMethod::StringScan,
                        confidence,
                    });
                }
            }
        }

        // ── Symbol table scan ─────────────────────────────────────────────
        if self.run_symbol_scan && let Ok(macho) = goblin::mach::MachO::parse(binary, 0) {
            indicators.extend(self.scan_symbols(&macho));
        }

        // ── Load command scan ─────────────────────────────────────────────
        if self.run_load_cmd_scan && let Ok(macho) = goblin::mach::MachO::parse(binary, 0) {
            indicators.extend(self.scan_load_commands(&macho, binary));
        }

        // ── ObjC selector scan ────────────────────────────────────────────
        if self.run_objc_scan {
            indicators.extend(self.scan_objc_selectors(binary));
        }

        // Filter and deduplicate
        indicators.retain(|i| i.confidence >= self.min_confidence);
        indicators.sort_by_key(|i| std::cmp::Reverse(i.confidence));

        let risk_score = indicators.iter().map(|i| i.confidence).max().unwrap_or(0);
        let high_confidence_count = indicators.iter().filter(|i| i.is_high_confidence()).count();
        let has_jailbreak_detection = !indicators.is_empty();
        let summary = Self::build_summary(has_jailbreak_detection, &indicators);
        let remediation = Self::build_remediation(&indicators);

        JailbreakReport {
            has_jailbreak_detection,
            indicators,
            risk_score,
            high_confidence_count,
            summary,
            remediation,
        }
    }

    // ── private helpers ───────────────────────────────────────────────────────

    fn empty_report() -> JailbreakReport {
        JailbreakReport {
            has_jailbreak_detection: false,
            indicators: Vec::new(),
            risk_score: 0,
            high_confidence_count: 0,
            summary: "No binary provided.".to_string(),
            remediation: Vec::new(),
        }
    }

    fn confidence_for_technique(technique: JailbreakTechnique, method: DetectionMethod) -> u8 {
        let base: u8 = match technique {
            JailbreakTechnique::FileSystemCheck => 65,
            JailbreakTechnique::ForkCall | JailbreakTechnique::ShellExec => 80,
            JailbreakTechnique::PtraceAntiDebug => 85,
            JailbreakTechnique::DylibCheck | JailbreakTechnique::SandboxCheck => 75,
            JailbreakTechnique::UrlSchemeCheck | JailbreakTechnique::DlsymCheck => 70,
            JailbreakTechnique::WriteCheck => 60,
        };
        // Symbol table and load command detections are more reliable
        let bonus: u8 = match method {
            DetectionMethod::SymbolTable | DetectionMethod::LoadCommands => 10,
            DetectionMethod::ObjcSelector => 5,
            _ => 0,
        };
        base.saturating_add(bonus).min(100)
    }

    fn scan_symbols(&self, macho: &goblin::mach::MachO<'_>) -> Vec<ExtendedIndicator> {
        let mut out = Vec::new();
        let suspicious_symbols: &[(&str, JailbreakTechnique)] = &[
            ("fork", JailbreakTechnique::ForkCall),
            ("ptrace", JailbreakTechnique::PtraceAntiDebug),
            ("system", JailbreakTechnique::ShellExec),
            ("popen", JailbreakTechnique::ShellExec),
            ("sandbox_check", JailbreakTechnique::SandboxCheck),
            ("dlsym", JailbreakTechnique::DlsymCheck),
            ("_dyld_get_image_name", JailbreakTechnique::DylibCheck),
        ];
        for sym in macho.symbols().flatten() {
            let (name, _) = sym;
            for (pattern, technique) in suspicious_symbols {
                if name.contains(pattern) {
                    let confidence = Self::confidence_for_technique(*technique, DetectionMethod::SymbolTable);
                    if confidence >= self.min_confidence {
                        out.push(ExtendedIndicator {
                            indicator: JailbreakIndicator {
                                technique: *technique,
                                pattern: name.to_string(),
                                address: 0,
                            },
                            method: DetectionMethod::SymbolTable,
                            confidence,
                        });
                    }
                }
            }
        }
        out
    }

    fn scan_load_commands(&self, macho: &goblin::mach::MachO<'_>, binary: &[u8]) -> Vec<ExtendedIndicator> {
        use goblin::mach::load_command::CommandVariant;
        let mut out = Vec::new();
        for lc in &macho.load_commands {
            if let CommandVariant::LoadDylib(info) | CommandVariant::LoadWeakDylib(info) = &lc.command {
                let name_off = lc.offset + info.dylib.name as usize;
                let name_bytes = binary.get(name_off..).unwrap_or(b"");
                let nul_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
                let path = std::str::from_utf8(&name_bytes[..nul_end]).unwrap_or("").trim();
                for dylib in JAILBREAK_DYLIBS {
                    if path.contains(dylib) {
                        let confidence = Self::confidence_for_technique(
                            JailbreakTechnique::DylibCheck,
                            DetectionMethod::LoadCommands,
                        );
                        if confidence >= self.min_confidence {
                            out.push(ExtendedIndicator {
                                indicator: JailbreakIndicator {
                                    technique: JailbreakTechnique::DylibCheck,
                                    pattern: path.to_string(),
                                    address: 0,
                                },
                                method: DetectionMethod::LoadCommands,
                                confidence,
                            });
                        }
                    }
                }
            }
        }
        out
    }

    fn scan_objc_selectors(&self, binary: &[u8]) -> Vec<ExtendedIndicator> {
        let selectors = crate::scan_objc_selectors(binary);
        let mut out = Vec::new();
        let suspicious: &[(&str, JailbreakTechnique)] = &[
            ("cydia", JailbreakTechnique::UrlSchemeCheck),
            ("jailbreak", JailbreakTechnique::FileSystemCheck),
            ("mobilesubstrate", JailbreakTechnique::DylibCheck),
        ];
        for sel in &selectors {
            let lower = sel.to_ascii_lowercase();
            for (pattern, technique) in suspicious {
                if lower.contains(pattern) {
                    let confidence = Self::confidence_for_technique(*technique, DetectionMethod::ObjcSelector);
                    if confidence >= self.min_confidence {
                        out.push(ExtendedIndicator {
                            indicator: JailbreakIndicator {
                                technique: *technique,
                                pattern: sel.clone(),
                                address: 0,
                            },
                            method: DetectionMethod::ObjcSelector,
                            confidence,
                        });
                    }
                }
            }
        }
        out
    }

    fn build_summary(has_detection: bool, indicators: &[ExtendedIndicator]) -> String {
        if !has_detection {
            return "No jailbreak detection code found.".to_string();
        }
        let high = indicators.iter().filter(|i| i.is_high_confidence()).count();
        format!(
            "{} jailbreak indicator(s) detected ({} high-confidence).",
            indicators.len(),
            high
        )
    }

    fn build_remediation(indicators: &[ExtendedIndicator]) -> Vec<String> {
        let mut hints: std::collections::HashSet<&'static str> = std::collections::HashSet::new();
        for indicator in indicators {
            match indicator.indicator.technique {
                JailbreakTechnique::FileSystemCheck => {
                    hints.insert("Use NSURL fileExists for path checks instead of C stat/access.");
                }
                JailbreakTechnique::DylibCheck => {
                    hints.insert("Validate loaded dylibs against an allowlist at launch.");
                }
                JailbreakTechnique::ShellExec => {
                    hints.insert("Avoid system()/popen(); use NSTask with sandboxed paths.");
                }
                JailbreakTechnique::ForkCall => {
                    hints.insert("Consider replacing fork() with posix_spawn() where appropriate.");
                }
                JailbreakTechnique::PtraceAntiDebug => {
                    hints.insert("PT_DENY_ATTACH is blocked in production iOS — remove or guard.");
                }
                JailbreakTechnique::SandboxCheck => {
                    hints.insert("Combine sandbox_check() with multiple other detection heuristics.");
                }
                _ => {}
            }
        }
        let mut v: Vec<String> = hints.into_iter().map(str::to_string).collect();
        v.sort();
        v
    }
}

// ─── Free functions ───────────────────────────────────────────────────────────

/// Quick check: does the binary contain jailbreak detection code?
#[must_use]
pub fn has_jailbreak_detection(binary: &[u8]) -> bool {
    IosJailbreakDetector::new().scan(binary).has_jailbreak_detection
}

/// Return a risk score [0, 100] indicating how much jailbreak detection
/// code is present in the binary.
#[must_use]
pub fn jailbreak_risk_score(binary: &[u8]) -> u8 {
    IosJailbreakDetector::new().scan(binary).risk_score
}

/// Run the base jailbreak detector and return all [`JailbreakIndicator`]s.
#[must_use]
pub fn scan_indicators(binary: &[u8]) -> Vec<JailbreakIndicator> {
    JailbreakDetector::scan(binary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detection_method_name() {
        assert_eq!(DetectionMethod::StringScan.name(), "String scan");
        assert_eq!(DetectionMethod::SymbolTable.name(), "Symbol table");
    }

    #[test]
    fn test_detection_method_display() {
        assert_eq!(format!("{}", DetectionMethod::Heuristic), "Heuristic analysis");
    }

    #[test]
    fn test_scan_empty_binary_no_detection() {
        let detector = IosJailbreakDetector::new();
        let report = detector.scan(&[]);
        assert!(!report.has_jailbreak_detection);
        assert_eq!(report.risk_score, 0);
    }

    #[test]
    fn test_scan_cydia_path_string() {
        let mut binary = vec![0u8; 64];
        let needle = b"/Applications/Cydia.app";
        binary[5..5 + needle.len()].copy_from_slice(needle);
        let detector = IosJailbreakDetector::new();
        let report = detector.scan(&binary);
        assert!(report.has_jailbreak_detection);
    }

    #[test]
    fn test_jailbreak_report_is_not_jailbroken_empty() {
        let report = JailbreakReport {
            has_jailbreak_detection: false,
            indicators: Vec::new(),
            risk_score: 0,
            high_confidence_count: 0,
            summary: String::new(),
            remediation: Vec::new(),
        };
        assert!(!report.is_jailbroken());
    }

    #[test]
    fn test_jailbreak_report_is_jailbroken() {
        let indicator = ExtendedIndicator {
            indicator: JailbreakIndicator {
                technique: JailbreakTechnique::DylibCheck,
                pattern: "MobileSubstrate".to_string(),
                address: 0,
            },
            method: DetectionMethod::StringScan,
            confidence: 90,
        };
        let report = JailbreakReport {
            has_jailbreak_detection: true,
            indicators: vec![indicator.clone(), indicator],
            risk_score: 90,
            high_confidence_count: 2,
            summary: String::new(),
            remediation: Vec::new(),
        };
        assert!(report.is_jailbroken());
    }

    #[test]
    fn test_high_confidence_indicators() {
        let low = ExtendedIndicator {
            indicator: JailbreakIndicator {
                technique: JailbreakTechnique::WriteCheck,
                pattern: "/private/test".to_string(),
                address: 0,
            },
            method: DetectionMethod::StringScan,
            confidence: 40,
        };
        let high = ExtendedIndicator {
            indicator: JailbreakIndicator {
                technique: JailbreakTechnique::ForkCall,
                pattern: "fork".to_string(),
                address: 0,
            },
            method: DetectionMethod::SymbolTable,
            confidence: 85,
        };
        let report = JailbreakReport {
            has_jailbreak_detection: true,
            indicators: vec![low, high],
            risk_score: 85,
            high_confidence_count: 1,
            summary: String::new(),
            remediation: Vec::new(),
        };
        let hc = report.high_confidence_indicators();
        assert_eq!(hc.len(), 1);
        assert_eq!(hc[0].indicator.technique, JailbreakTechnique::ForkCall);
    }

    #[test]
    fn test_indicators_by_method() {
        let ind = ExtendedIndicator {
            indicator: JailbreakIndicator {
                technique: JailbreakTechnique::DylibCheck,
                pattern: "MobileSubstrate".to_string(),
                address: 0,
            },
            method: DetectionMethod::LoadCommands,
            confidence: 85,
        };
        let report = JailbreakReport {
            has_jailbreak_detection: true,
            indicators: vec![ind],
            risk_score: 85,
            high_confidence_count: 1,
            summary: String::new(),
            remediation: Vec::new(),
        };
        let by_method = report.indicators_by_method(DetectionMethod::LoadCommands);
        assert_eq!(by_method.len(), 1);
    }

    #[test]
    fn test_has_jailbreak_detection_empty() {
        assert!(!has_jailbreak_detection(&[]));
    }

    #[test]
    fn test_jailbreak_risk_score_empty() {
        assert_eq!(jailbreak_risk_score(&[]), 0);
    }

    #[test]
    fn test_scan_indicators_empty() {
        let indicators = scan_indicators(&[]);
        assert!(indicators.is_empty());
    }

    #[test]
    fn test_extended_indicator_is_high_confidence_true() {
        let i = ExtendedIndicator {
            indicator: JailbreakIndicator {
                technique: JailbreakTechnique::ForkCall,
                pattern: "fork".to_string(),
                address: 0,
            },
            method: DetectionMethod::SymbolTable,
            confidence: 80,
        };
        assert!(i.is_high_confidence());
    }

    #[test]
    fn test_extended_indicator_is_high_confidence_false() {
        let i = ExtendedIndicator {
            indicator: JailbreakIndicator {
                technique: JailbreakTechnique::WriteCheck,
                pattern: "/tmp/test".to_string(),
                address: 0,
            },
            method: DetectionMethod::StringScan,
            confidence: 50,
        };
        assert!(!i.is_high_confidence());
    }

    #[test]
    fn test_with_min_confidence_builder() {
        let d = IosJailbreakDetector::new().with_min_confidence(80);
        assert_eq!(d.min_confidence, 80);
    }

    #[test]
    fn test_dylib_scan_mobilesubstrate_string() {
        let mut binary = vec![0u8; 64];
        let needle = b"MobileSubstrate";
        binary[10..10 + needle.len()].copy_from_slice(needle);
        let detector = IosJailbreakDetector::new();
        let report = detector.scan(&binary);
        assert!(report.has_jailbreak_detection);
    }
}
