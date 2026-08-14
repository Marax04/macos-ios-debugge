//! `ios_dylib_injector_detector` — Detect dynamic library injection on iOS.
//!
//! Malicious actors and jailbreak tools inject dynamic libraries into iOS
//! processes using several techniques:
//!
//! * `DYLD_INSERT_LIBRARIES` — environment variable injection (blocked in iOS
//!   production, but present in jailbroken environments).
//! * `dlopen()` / `NSBundle` loading of arbitrary dylibs.
//! * Substrate / Substitute hooks that replace function pointers.
//! * fishhook-style GOT-slot patching.
//! * Overwriting `__DATA,__interpose` sections.
//!
//! This module scans a Mach-O binary for evidence of injection readiness and
//! already-injected libraries.

use crate::{IosError, IosFramework};
use serde::{Deserialize, Serialize};
use std::fmt;

// ─── InjectionTechnique ───────────────────────────────────────────────────────

/// How a dylib was (or could be) injected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InjectionTechnique {
    /// `DYLD_INSERT_LIBRARIES` environment-variable injection.
    DyldInsertLibraries,
    /// `dlopen()` call found in the binary.
    Dlopen,
    /// `MobileSubstrate` / `CydiaSubstrate` hook.
    Substrate,
    /// libsubstitute hook.
    Substitute,
    /// fishhook-style GOT rebinding.
    Fishhook,
    /// `__DATA,__interpose` section present.
    InterposeSection,
    /// `NSBundle` loading of a plugin/framework at runtime.
    NsBundle,
    /// Unknown / undetermined injection method.
    Unknown,
}

impl InjectionTechnique {
    /// Short human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::DyldInsertLibraries => "DYLD_INSERT_LIBRARIES",
            Self::Dlopen => "dlopen()",
            Self::Substrate => "MobileSubstrate",
            Self::Substitute => "libsubstitute",
            Self::Fishhook => "fishhook GOT rebinding",
            Self::InterposeSection => "__DATA,__interpose",
            Self::NsBundle => "NSBundle plugin loading",
            Self::Unknown => "Unknown",
        }
    }

    /// Returns a risk score in [0, 100].
    #[must_use]
    pub const fn risk_score(self) -> u8 {
        match self {
            Self::DyldInsertLibraries => 90,
            Self::Dlopen => 55,
            Self::Substrate | Self::Substitute => 95,
            Self::Fishhook => 80,
            Self::InterposeSection => 85,
            Self::NsBundle => 40,
            Self::Unknown => 50,
        }
    }
}

impl fmt::Display for InjectionTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ─── InjectedDylib ───────────────────────────────────────────────────────────

/// A dynamic library detected as injected into (or ready to be injected into)
/// a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectedDylib {
    /// Library name or path.
    pub name: String,
    /// Full path if known.
    pub path: Option<String>,
    /// The technique used (or inferred) for injection.
    pub technique: InjectionTechnique,
    /// Virtual address in the binary where this was found (0 if N/A).
    pub address: u64,
    /// Confidence [0, 100] that this represents an actual injection.
    pub confidence: u8,
    /// Whether the library is in a known trusted system path.
    pub is_system_library: bool,
}

impl InjectedDylib {
    /// Returns `true` when the library is likely malicious.
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        !self.is_system_library && self.confidence >= 60
    }

    /// Returns `true` when the library is from a jailbreak tool (Substrate etc.)
    #[must_use]
    pub const fn is_jailbreak_library(&self) -> bool {
        matches!(self.technique, InjectionTechnique::Substrate | InjectionTechnique::Substitute)
    }
}

impl fmt::Display for InjectedDylib {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} via {} (confidence: {}%)", self.name, self.technique, self.confidence)
    }
}

// ─── DetectionResult ─────────────────────────────────────────────────────────

/// The result of scanning a binary for dylib injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    /// Whether any injection evidence was found.
    pub has_injection: bool,
    /// All detected injected (or injectable) dylibs.
    pub injected_dylibs: Vec<InjectedDylib>,
    /// Whether `__DATA,__interpose` section was present.
    pub has_interpose_section: bool,
    /// Whether `dlopen` was imported.
    pub has_dlopen_import: bool,
    /// Whether Substrate/Substitute were found.
    pub has_hook_library: bool,
    /// Overall risk score [0, 100].
    pub risk_score: u8,
    /// Human-readable summary.
    pub summary: String,
}

impl DetectionResult {
    /// Returns only the suspicious dylibs.
    #[must_use]
    pub fn suspicious_dylibs(&self) -> Vec<&InjectedDylib> {
        self.injected_dylibs.iter().filter(|d| d.is_suspicious()).collect()
    }

    /// Returns the highest-risk dylib.
    #[must_use]
    pub fn highest_risk_dylib(&self) -> Option<&InjectedDylib> {
        self.injected_dylibs.iter().max_by_key(|d| d.confidence)
    }

    /// Returns `true` when the binary is clean (no injection evidence).
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        !self.has_injection && self.risk_score < 30
    }
}

// ─── IosDylibInjectorDetector ─────────────────────────────────────────────────

/// Scans Mach-O binaries for evidence of dylib injection.
#[derive(Debug, Clone, Default)]
pub struct IosDylibInjectorDetector {
    /// Whether to check for `DYLD_INSERT_LIBRARIES` in string literals.
    pub check_dyld_env: bool,
    /// Whether to scan the symbol table for `dlopen` imports.
    pub check_dlopen: bool,
    /// Whether to scan for known hook library names.
    pub check_hook_libraries: bool,
    /// Whether to scan for an `__interpose` section.
    pub check_interpose: bool,
    /// Minimum confidence [0, 100] to include a finding.
    pub min_confidence: u8,
}

impl IosDylibInjectorDetector {
    /// Create a detector with all checks enabled.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            check_dyld_env: true,
            check_dlopen: true,
            check_hook_libraries: true,
            check_interpose: true,
            min_confidence: 50,
        }
    }

    /// Enable all checks.
    #[must_use]
    pub const fn with_all_checks(mut self) -> Self {
        self.check_dyld_env = true;
        self.check_dlopen = true;
        self.check_hook_libraries = true;
        self.check_interpose = true;
        self
    }

    /// Set minimum confidence threshold.
    #[must_use]
    pub const fn with_min_confidence(mut self, threshold: u8) -> Self {
        self.min_confidence = threshold;
        self
    }

    /// Scan a raw Mach-O binary and return a [`DetectionResult`].
    ///
    /// # Errors
    /// Returns `IosError::ParseError` when the binary cannot be parsed.
    pub fn scan(&self, binary: &[u8]) -> Result<DetectionResult, IosError> {
        if binary.is_empty() {
            return Ok(Self::empty_result());
        }
        let mut injected: Vec<InjectedDylib> = Vec::new();
        let mut has_interpose = false;
        let mut has_dlopen = false;
        let mut has_hook_lib = false;

        // ── Parse Mach-O via goblin ───────────────────────────────────────
        let macho_opt = goblin::mach::MachO::parse(binary, 0).ok();

        // Check __DATA,__interpose section
        if self.check_interpose && let Some(ref macho) = macho_opt {
            has_interpose = Self::has_interpose_section(macho);
            if has_interpose {
                injected.push(InjectedDylib {
                    name: "__DATA,__interpose section".to_string(),
                    path: None,
                    technique: InjectionTechnique::InterposeSection,
                    address: 0,
                    confidence: 80,
                    is_system_library: false,
                });
            }
        }

        // Scan symbol imports
        if let Some(ref macho) = macho_opt {
            for sym in macho.symbols().flatten() {
                let (name, _) = sym;
                if self.check_dlopen && name.contains("dlopen") {
                    has_dlopen = true;
                    injected.push(InjectedDylib {
                        name: name.to_string(),
                        path: None,
                        technique: InjectionTechnique::Dlopen,
                        address: 0,
                        confidence: 65,
                        is_system_library: false,
                    });
                }
                if self.check_hook_libraries {
                    if name.contains("MSHookFunction") || name.contains("MobileSubstrate") {
                        has_hook_lib = true;
                        injected.push(InjectedDylib {
                            name: name.to_string(),
                            path: None,
                            technique: InjectionTechnique::Substrate,
                            address: 0,
                            confidence: 95,
                            is_system_library: false,
                        });
                    }
                    if name.contains("SubHookFunction") || name.contains("substitute") {
                        has_hook_lib = true;
                        injected.push(InjectedDylib {
                            name: name.to_string(),
                            path: None,
                            technique: InjectionTechnique::Substitute,
                            address: 0,
                            confidence: 95,
                            is_system_library: false,
                        });
                    }
                    if name.contains("rebind_symbols") || name.contains("fishhook") {
                        injected.push(InjectedDylib {
                            name: name.to_string(),
                            path: None,
                            technique: InjectionTechnique::Fishhook,
                            address: 0,
                            confidence: 75,
                            is_system_library: false,
                        });
                    }
                }
            }
        }

        // Scan dylib load commands
        if let Some(ref macho) = macho_opt {
            use goblin::mach::load_command::CommandVariant;
            for lc in &macho.load_commands {
                match &lc.command {
                    CommandVariant::LoadDylib(info) | CommandVariant::LoadWeakDylib(info) => {
                        let name_off = lc.offset + info.dylib.name as usize;
                        let name_bytes = binary.get(name_off..).unwrap_or(b"");
                        let nul_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
                        let path = std::str::from_utf8(&name_bytes[..nul_end]).unwrap_or("").trim();
                        let is_system = Self::is_system_path(path);
                        let technique = Self::classify_dylib_path(path);
                        let confidence = if is_system { 20 } else { Self::dylib_confidence(path) };
                        if confidence >= self.min_confidence {
                            injected.push(InjectedDylib {
                                name: path.rsplit('/').next().unwrap_or(path).to_string(),
                                path: Some(path.to_string()),
                                technique,
                                address: 0,
                                confidence,
                                is_system_library: is_system,
                            });
                        }
                    }
                    _ => {}
                }
            }
        }

        // Scan for DYLD_INSERT_LIBRARIES string
        if self.check_dyld_env && contains_bytes(binary, b"DYLD_INSERT_LIBRARIES") {
            injected.push(InjectedDylib {
                name: "DYLD_INSERT_LIBRARIES".to_string(),
                path: None,
                technique: InjectionTechnique::DyldInsertLibraries,
                address: 0,
                confidence: 85,
                is_system_library: false,
            });
        }

        // Filter by min_confidence
        injected.retain(|d| d.confidence >= self.min_confidence);

        let has_injection = !injected.is_empty();
        let risk_score = injected.iter().map(|d| d.confidence).max().unwrap_or(0);
        let summary = Self::build_summary(has_injection, &injected);

        Ok(DetectionResult {
            has_injection,
            injected_dylibs: injected,
            has_interpose_section: has_interpose,
            has_dlopen_import: has_dlopen,
            has_hook_library: has_hook_lib,
            risk_score,
            summary,
        })
    }

    /// Scan a list of [`IosFramework`]s (from IPA bundle analysis) for
    /// known injection-related libraries.
    #[must_use]
    pub fn scan_frameworks(&self, frameworks: &[IosFramework]) -> Vec<InjectedDylib> {
        frameworks
            .iter()
            .filter_map(|fw| {
                let technique = Self::classify_dylib_path(&fw.path);
                let is_system = fw.is_system;
                let confidence = if is_system { 10 } else { Self::dylib_confidence(&fw.path) };
                if confidence >= self.min_confidence {
                    Some(InjectedDylib {
                        name: fw.name.clone(),
                        path: Some(fw.path.clone()),
                        technique,
                        address: 0,
                        confidence,
                        is_system_library: is_system,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    // ── private helpers ───────────────────────────────────────────────────────

    fn empty_result() -> DetectionResult {
        DetectionResult {
            has_injection: false,
            injected_dylibs: Vec::new(),
            has_interpose_section: false,
            has_dlopen_import: false,
            has_hook_library: false,
            risk_score: 0,
            summary: "No binary provided.".to_string(),
        }
    }

    fn has_interpose_section(macho: &goblin::mach::MachO<'_>) -> bool {
        for sect in macho.segments.sections().flatten() {
            let Ok((hdr, _)) = sect else { continue };
            let sn = std::str::from_utf8(&hdr.sectname).unwrap_or("").trim_end_matches('\0');
            let sg = std::str::from_utf8(&hdr.segname).unwrap_or("").trim_end_matches('\0');
            if sg == "__DATA" && sn == "__interpose" {
                return true;
            }
        }
        false
    }

    fn is_system_path(path: &str) -> bool {
        path.starts_with("/System/Library/")
            || path.starts_with("/usr/lib/")
            || path.starts_with("/usr/local/lib/")
    }

    fn classify_dylib_path(path: &str) -> InjectionTechnique {
        let lower = path.to_ascii_lowercase();
        if lower.contains("substrate") || lower.contains("mobilesubstrate") {
            InjectionTechnique::Substrate
        } else if lower.contains("substitute") {
            InjectionTechnique::Substitute
        } else if lower.contains("fishhook") {
            InjectionTechnique::Fishhook
        } else if lower.contains("nsbundle") {
            InjectionTechnique::NsBundle
        } else {
            InjectionTechnique::Unknown
        }
    }

    fn dylib_confidence(path: &str) -> u8 {
        let lower = path.to_ascii_lowercase();
        if lower.contains("substrate") || lower.contains("substitute") {
            95
        } else if lower.contains("tweak") || lower.contains("inject") {
            80
        } else if lower.contains("hook") {
            75
        } else {
            30
        }
    }

    fn build_summary(has_injection: bool, dylibs: &[InjectedDylib]) -> String {
        if !has_injection {
            return "No dylib injection evidence detected.".to_string();
        }
        let suspicious: Vec<_> = dylibs.iter().filter(|d| d.is_suspicious()).collect();
        if suspicious.is_empty() {
            format!("{} dylib finding(s); all appear benign.", dylibs.len())
        } else {
            format!(
                "{} injection finding(s); {} suspicious: {}",
                dylibs.len(),
                suspicious.len(),
                suspicious
                    .iter()
                    .map(|d| d.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    }
}

// ─── Free functions ───────────────────────────────────────────────────────────

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Quick scan for dylib injection in a Mach-O byte slice.
///
/// Returns `true` if any injection evidence is found.
#[must_use]
pub fn has_injection_evidence(binary: &[u8]) -> bool {
    IosDylibInjectorDetector::new()
        .scan(binary)
        .is_ok_and(|r| r.has_injection)
}

/// Score the injection risk of a binary in [0, 100].
#[must_use]
pub fn injection_risk_score(binary: &[u8]) -> u8 {
    IosDylibInjectorDetector::new()
        .scan(binary)
        .map_or(0, |r| r.risk_score)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_injection_technique_name() {
        assert_eq!(InjectionTechnique::Substrate.name(), "MobileSubstrate");
        assert_eq!(InjectionTechnique::Dlopen.name(), "dlopen()");
    }

    #[test]
    fn test_injection_technique_risk() {
        assert!(InjectionTechnique::Substrate.risk_score() >= 90);
        assert!(InjectionTechnique::NsBundle.risk_score() < 60);
    }

    #[test]
    fn test_injection_technique_display() {
        assert_eq!(format!("{}", InjectionTechnique::Fishhook), "fishhook GOT rebinding");
    }

    #[test]
    fn test_scan_empty_binary() {
        let detector = IosDylibInjectorDetector::new();
        let result = detector.scan(&[]).unwrap();
        assert!(!result.has_injection);
        assert_eq!(result.risk_score, 0);
        assert!(result.is_clean());
    }

    #[test]
    fn test_scan_dyld_insert_libraries_string() {
        let mut binary = vec![0u8; 64];
        let needle = b"DYLD_INSERT_LIBRARIES";
        binary[10..10 + needle.len()].copy_from_slice(needle);
        let detector = IosDylibInjectorDetector::new();
        let result = detector.scan(&binary).unwrap();
        assert!(result.has_injection);
        let found = result
            .injected_dylibs
            .iter()
            .any(|d| d.technique == InjectionTechnique::DyldInsertLibraries);
        assert!(found);
    }

    #[test]
    fn test_injected_dylib_is_suspicious() {
        let d = InjectedDylib {
            name: "tweak.dylib".to_string(),
            path: None,
            technique: InjectionTechnique::Substrate,
            address: 0,
            confidence: 90,
            is_system_library: false,
        };
        assert!(d.is_suspicious());
    }

    #[test]
    fn test_injected_dylib_system_not_suspicious() {
        let d = InjectedDylib {
            name: "libSystem.dylib".to_string(),
            path: Some("/usr/lib/libSystem.dylib".to_string()),
            technique: InjectionTechnique::Unknown,
            address: 0,
            confidence: 90,
            is_system_library: true,
        };
        assert!(!d.is_suspicious());
    }

    #[test]
    fn test_injected_dylib_is_jailbreak() {
        let d = InjectedDylib {
            name: "CydiaSubstrate".to_string(),
            path: None,
            technique: InjectionTechnique::Substrate,
            address: 0,
            confidence: 95,
            is_system_library: false,
        };
        assert!(d.is_jailbreak_library());
    }

    #[test]
    fn test_detection_result_suspicious_dylibs() {
        let result = DetectionResult {
            has_injection: true,
            injected_dylibs: vec![
                InjectedDylib {
                    name: "tweak.dylib".to_string(),
                    path: None,
                    technique: InjectionTechnique::Substrate,
                    address: 0,
                    confidence: 95,
                    is_system_library: false,
                },
                InjectedDylib {
                    name: "libSystem.dylib".to_string(),
                    path: None,
                    technique: InjectionTechnique::Unknown,
                    address: 0,
                    confidence: 20,
                    is_system_library: true,
                },
            ],
            has_interpose_section: false,
            has_dlopen_import: false,
            has_hook_library: true,
            risk_score: 95,
            summary: "test".to_string(),
        };
        let suspicious = result.suspicious_dylibs();
        assert_eq!(suspicious.len(), 1);
    }

    #[test]
    fn test_scan_frameworks_substrate() {
        let detector = IosDylibInjectorDetector::new().with_min_confidence(50);
        let frameworks = vec![
            IosFramework {
                name: "MobileSubstrate".to_string(),
                path: "/Library/Frameworks/MobileSubstrate.framework".to_string(),
                is_system: false,
            },
            IosFramework {
                name: "UIKit".to_string(),
                path: "/System/Library/Frameworks/UIKit.framework".to_string(),
                is_system: true,
            },
        ];
        let found = detector.scan_frameworks(&frameworks);
        assert!(!found.is_empty());
        assert!(found.iter().all(|d| !d.is_system_library));
    }

    #[test]
    fn test_has_injection_evidence_clean() {
        assert!(!has_injection_evidence(&[]));
    }

    #[test]
    fn test_has_injection_evidence_dyld() {
        let mut binary = vec![0u8; 64];
        binary[5..26].copy_from_slice(b"DYLD_INSERT_LIBRARIES");
        assert!(has_injection_evidence(&binary));
    }

    #[test]
    fn test_injection_risk_score_clean() {
        assert_eq!(injection_risk_score(&[]), 0);
    }

    #[test]
    fn test_detection_result_is_clean() {
        let r = DetectionResult {
            has_injection: false,
            injected_dylibs: vec![],
            has_interpose_section: false,
            has_dlopen_import: false,
            has_hook_library: false,
            risk_score: 0,
            summary: String::new(),
        };
        assert!(r.is_clean());
    }

    #[test]
    fn test_with_min_confidence_builder() {
        let d = IosDylibInjectorDetector::new().with_min_confidence(80);
        assert_eq!(d.min_confidence, 80);
    }

    #[test]
    fn test_with_all_checks_builder() {
        let d = IosDylibInjectorDetector::default().with_all_checks();
        assert!(d.check_dyld_env);
        assert!(d.check_dlopen);
        assert!(d.check_hook_libraries);
        assert!(d.check_interpose);
    }
}
