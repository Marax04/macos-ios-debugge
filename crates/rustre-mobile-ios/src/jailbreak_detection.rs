//! Jailbreak detection analysis for iOS binaries.
//!
//! Identifies jailbreak checks in compiled code: file existence checks for
//! `Cydia`/`Sileo`, `fork()==0`, `sysctl` `KERN_PROC`, dylib injection detection.
//! Provides technique classification and bypass suggestions.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum JailbreakAnalysisError {
    #[error("binary too short")]
    TooShort,
    #[error("unsupported architecture")]
    UnsupportedArch,
}

pub type JailbreakResult<T> = Result<T, JailbreakAnalysisError>;

// ── Technique classification ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JailbreakTechniqueKind {
    /// File or directory existence check (`access`/`stat`/`fopen`).
    FileSystemCheck,
    /// Fork + exec trick (`fork()` returns 0 on jailbroken if debugger is present).
    ForkExec,
    /// `sysctl` with `KERN_PROC` to detect debuggers or injected processes.
    SysctlKernProc,
    /// Checking whether `ObjC` classes like `SBSApplicationDataDirectory` exist.
    ObjcClassCheck,
    /// Checking for injected dylibs (`DYLD_INSERT_LIBRARIES`, `MH_EXECUTE`).
    DylibInjection,
    /// URL scheme check (`cydia://`, `sileo://`).
    UrlSchemeCheck,
    /// Checking `/etc/apt`, `/bin/bash`, `/usr/sbin/sshd` existence.
    PathCheck,
    /// Sandbox escape attempt via writability check.
    SandboxEscape,
    /// Checking for Substrate/Substitute hooks.
    HookDetection,
    /// `PT_DENY_ATTACH` anti-debug.
    PtDenyAttach,
    /// `IOKit` / kernel interface checks.
    IOKitCheck,
    /// Dynamic library list scanning.
    DylibListScan,
    /// Checking for common jailbreak apps (Cydia, Sileo, Zebra, etc.).
    JailbreakAppCheck,
    /// Generic heuristic pattern.
    Generic,
}

impl JailbreakTechniqueKind {
    /// Return a short human-readable name for this technique kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileSystemCheck => "file system check",
            Self::ForkExec => "fork/exec trick",
            Self::SysctlKernProc => "sysctl KERN_PROC",
            Self::ObjcClassCheck => "ObjC class check",
            Self::DylibInjection => "dylib injection detection",
            Self::UrlSchemeCheck => "URL scheme check",
            Self::PathCheck => "path check (/etc/apt etc.)",
            Self::SandboxEscape => "sandbox escape check",
            Self::HookDetection => "hook detection (Substrate/Substitute)",
            Self::PtDenyAttach => "PT_DENY_ATTACH anti-debug",
            Self::IOKitCheck => "IOKit kernel check",
            Self::DylibListScan => "dylib list scan",
            Self::JailbreakAppCheck => "jailbreak app check",
            Self::Generic => "generic heuristic",
        }
    }

    /// Suggested bypass approach for Frida/hooks.
    #[must_use]
    pub const fn bypass_suggestion(self) -> &'static str {
        match self {
            Self::FileSystemCheck => {
                "Hook access(2)/stat(2)/fopen(3) to return ENOENT for jailbreak paths."
            }
            Self::ForkExec => {
                "Hook fork() to return -1 or 0 unconditionally; or hook waitpid to falsify result."
            }
            Self::SysctlKernProc => {
                "Hook sysctl() and zero out the kp_proc.p_flag P_TRACED bit in returned struct."
            }
            Self::ObjcClassCheck => {
                "Hook objc_lookUpClass / NSClassFromString to return nil for jailbreak class names."
            }
            Self::DylibInjection => {
                "Hook _dyld_get_image_name to skip jailbreak-related dylib names in enumeration."
            }
            Self::UrlSchemeCheck => {
                "Hook -[UIApplication canOpenURL:] to return NO for cydia:// and sileo:// schemes."
            }
            Self::PathCheck => {
                "Hook access/stat to return ENOENT for /etc/apt, /bin/bash, /usr/sbin/sshd."
            }
            Self::SandboxEscape => {
                "Hook open(2)/fopen(3) on paths outside the sandbox to return EPERM."
            }
            Self::HookDetection => {
                "Patch the MSHookFunction/SubHook detection routine; hook dlsym for substrate symbols."
            }
            Self::PtDenyAttach => {
                "Hook ptrace(2) and return 0 when request==PT_DENY_ATTACH."
            }
            Self::IOKitCheck => {
                "Hook IOServiceGetMatchingService / IOConnectCallScalarMethod calls."
            }
            Self::DylibListScan => {
                "Hook _dyld_image_count and _dyld_get_image_name to filter out jailbreak dylibs."
            }
            Self::JailbreakAppCheck => {
                "Hook LSApplicationWorkspace to hide jailbreak apps from the app list."
            }
            Self::Generic => {
                "Use Frida script to log all relevant calls and identify the check at runtime."
            }
        }
    }
}

// ── Known jailbreak paths ─────────────────────────────────────────────────────

pub const JAILBREAK_PATHS: &[(&str, JailbreakTechniqueKind)] = &[
    ("/Applications/Cydia.app", JailbreakTechniqueKind::JailbreakAppCheck),
    ("/Applications/Sileo.app", JailbreakTechniqueKind::JailbreakAppCheck),
    ("/Applications/Zebra.app", JailbreakTechniqueKind::JailbreakAppCheck),
    ("/Applications/Installer.app", JailbreakTechniqueKind::JailbreakAppCheck),
    ("/Applications/Filza.app", JailbreakTechniqueKind::JailbreakAppCheck),
    ("/Applications/unc0ver.app", JailbreakTechniqueKind::JailbreakAppCheck),
    ("/bin/bash", JailbreakTechniqueKind::PathCheck),
    ("/bin/sh", JailbreakTechniqueKind::PathCheck),
    ("/usr/sbin/sshd", JailbreakTechniqueKind::PathCheck),
    ("/usr/bin/ssh", JailbreakTechniqueKind::PathCheck),
    ("/etc/apt", JailbreakTechniqueKind::PathCheck),
    ("/var/lib/dpkg", JailbreakTechniqueKind::PathCheck),
    ("/var/lib/cydia", JailbreakTechniqueKind::PathCheck),
    ("/var/cache/apt", JailbreakTechniqueKind::PathCheck),
    ("/private/var/lib/apt", JailbreakTechniqueKind::PathCheck),
    ("/private/var/lib/cydia", JailbreakTechniqueKind::PathCheck),
    ("/private/var/stash", JailbreakTechniqueKind::PathCheck),
    ("/private/var/mobile/Library/SBSettings", JailbreakTechniqueKind::PathCheck),
    ("/Library/MobileSubstrate/MobileSubstrate.dylib", JailbreakTechniqueKind::HookDetection),
    ("/Library/MobileSubstrate/DynamicLibraries", JailbreakTechniqueKind::HookDetection),
    ("/usr/lib/TweakInject.dylib", JailbreakTechniqueKind::HookDetection),
    ("/usr/lib/substitute-inserter.dylib", JailbreakTechniqueKind::HookDetection),
    ("/usr/lib/libhooker.dylib", JailbreakTechniqueKind::HookDetection),
    ("/var/jb", JailbreakTechniqueKind::PathCheck),
    ("/var/containers/Bundle/.jailbreak", JailbreakTechniqueKind::PathCheck),
];

pub const JAILBREAK_DYLIBS: &[(&str, JailbreakTechniqueKind)] = &[
    ("MobileSubstrate", JailbreakTechniqueKind::HookDetection),
    ("SubstrateLoader", JailbreakTechniqueKind::HookDetection),
    ("substitute-inserter", JailbreakTechniqueKind::HookDetection),
    ("libhooker", JailbreakTechniqueKind::HookDetection),
    ("TweakInject", JailbreakTechniqueKind::HookDetection),
    ("RocketBootstrap", JailbreakTechniqueKind::HookDetection),
    ("CydiaSubstrate", JailbreakTechniqueKind::HookDetection),
];

pub const JAILBREAK_URL_SCHEMES: &[&str] = &[
    "cydia://",
    "sileo://",
    "zbra://",
    "filza://",
    "undecimus://",
];

pub const JAILBREAK_OBJC_CLASSES: &[&str] = &[
    "SBSApplicationDataDirectory",
    "SBPlatformController",
    "RBSProcessIdentity",
    "CydiaObject",
    "CYProduct",
];

pub const SYSCALL_NAMES_OF_INTEREST: &[(&str, JailbreakTechniqueKind)] = &[
    ("fork", JailbreakTechniqueKind::ForkExec),
    ("sysctl", JailbreakTechniqueKind::SysctlKernProc),
    ("ptrace", JailbreakTechniqueKind::PtDenyAttach),
    ("access", JailbreakTechniqueKind::FileSystemCheck),
    ("stat", JailbreakTechniqueKind::FileSystemCheck),
    ("lstat", JailbreakTechniqueKind::FileSystemCheck),
    ("fopen", JailbreakTechniqueKind::FileSystemCheck),
    ("open", JailbreakTechniqueKind::FileSystemCheck),
    ("dlopen", JailbreakTechniqueKind::DylibInjection),
    ("dlsym", JailbreakTechniqueKind::DylibInjection),
    ("_dyld_get_image_name", JailbreakTechniqueKind::DylibListScan),
    ("_dyld_image_count", JailbreakTechniqueKind::DylibListScan),
];

// ── Indicator ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JailbreakIndicator {
    pub technique: JailbreakTechniqueKind,
    pub evidence: String,
    pub location: Option<String>,
    pub confidence: IndicatorConfidence,
    pub bypass: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndicatorConfidence {
    Low,
    Medium,
    High,
}

impl IndicatorConfidence {
    /// Return the confidence level as a string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

// ── Detector ──────────────────────────────────────────────────────────────────

pub struct JailbreakDetector {
    indicators: Vec<JailbreakIndicator>,
}

impl JailbreakDetector {
    #[must_use]
    pub const fn new() -> Self {
        Self { indicators: Vec::new() }
    }

    fn add(&mut self, technique: JailbreakTechniqueKind, evidence: impl Into<String>, location: Option<String>, confidence: IndicatorConfidence) {
        let bypass = technique.bypass_suggestion().to_owned();
        self.indicators.push(JailbreakIndicator {
            technique,
            evidence: evidence.into(),
            location,
            confidence,
            bypass,
        });
    }

    /// Scan a list of strings (from the binary's string table) for jailbreak indicators.
    pub fn scan_strings(&mut self, strings: &[String]) {
        for s in strings {
            // File path checks
            for (path, kind) in JAILBREAK_PATHS {
                if s == path || s.starts_with(path) {
                    self.add(
                        *kind,
                        format!("string reference: {s}"),
                        None,
                        IndicatorConfidence::High,
                    );
                }
            }
            // URL schemes
            for scheme in JAILBREAK_URL_SCHEMES {
                if s.starts_with(scheme) {
                    self.add(
                        JailbreakTechniqueKind::UrlSchemeCheck,
                        format!("URL scheme: {s}"),
                        None,
                        IndicatorConfidence::High,
                    );
                }
            }
            // ObjC class names
            for cls in JAILBREAK_OBJC_CLASSES {
                if s == cls {
                    self.add(
                        JailbreakTechniqueKind::ObjcClassCheck,
                        format!("ObjC class reference: {s}"),
                        None,
                        IndicatorConfidence::High,
                    );
                }
            }
            // Dylib names
            for (dylib, kind) in JAILBREAK_DYLIBS {
                if s.contains(dylib) {
                    self.add(
                        *kind,
                        format!("dylib reference: {s}"),
                        None,
                        IndicatorConfidence::High,
                    );
                }
            }
            // Sandbox escape: attempt to write outside sandbox
            if s == "/private/var/mobile" || s == "/private" || s.contains("/.." ) {
                self.add(
                    JailbreakTechniqueKind::SandboxEscape,
                    format!("potential sandbox path: {s}"),
                    None,
                    IndicatorConfidence::Medium,
                );
            }
        }
    }

    /// Scan imported/exported symbol names.
    pub fn scan_symbols(&mut self, symbols: &[String]) {
        for sym in symbols {
            for (name, kind) in SYSCALL_NAMES_OF_INTEREST {
                let underscored = format!("_{name}");
                if sym == name || sym == &underscored {
                    self.add(
                        *kind,
                        format!("symbol import: {sym}"),
                        None,
                        IndicatorConfidence::Medium,
                    );
                }
            }
            // PT_DENY_ATTACH constant
            if sym.contains("PT_DENY_ATTACH") || sym == "_ptrace" {
                self.add(
                    JailbreakTechniqueKind::PtDenyAttach,
                    format!("ptrace symbol: {sym}"),
                    None,
                    IndicatorConfidence::High,
                );
            }
        }
    }

    /// Scan `ObjC` method names (selector list) for jailbreak detection patterns.
    pub fn scan_selectors(&mut self, selectors: &[String]) {
        // All keywords lowercased at compile time; we lowercase the selector once per selector.
        let jb_keywords = [
            "jailbreak", "jailbroken", "isJailbroken",
            "detectJailbreak", "checkJailbreak", "isDeviceJailbroken",
            "jailbreakCheck", "jbdetect",
        ];
        for sel in selectors {
            let lower_sel = sel.to_lowercase();
            for kw in &jb_keywords {
                if lower_sel.contains(*kw) {
                    self.add(
                        JailbreakTechniqueKind::Generic,
                        format!("jailbreak-related selector: {sel}"),
                        None,
                        IndicatorConfidence::High,
                    );
                }
            }
        }
    }

    /// Scan raw disassembly text for known jailbreak check patterns.
    pub fn scan_disassembly(&mut self, disasm: &str, function_name: &str) {
        let lines: Vec<&str> = disasm.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            // fork() followed by comparison to 0
            if line.contains("bl _fork") || line.contains("call _fork") {
                // Look for a CMP/CBZ within next 5 instructions
                let next: Vec<&str> = lines.get(i + 1..).unwrap_or(&[]).iter().take(5).copied().collect();
                if next.iter().any(|l| l.contains("cbz") || l.contains("cbnz") || l.contains("cmp")) {
                    self.add(
                        JailbreakTechniqueKind::ForkExec,
                        "fork() return value compared (fork trick)".to_string(),
                        Some(function_name.to_owned()),
                        IndicatorConfidence::High,
                    );
                }
            }

            // sysctl with KERN_PROC constant (0x0E = 14 = KERN_PROC)
            if (line.contains("bl _sysctl") || line.contains("call _sysctl"))
                && lines.iter().skip(i.saturating_sub(10)).take(15).any(|l| l.contains("0xe") || l.contains("#14"))
            {
                self.add(
                    JailbreakTechniqueKind::SysctlKernProc,
                    "sysctl(CTL_KERN, KERN_PROC, ...) call".to_string(),
                    Some(function_name.to_owned()),
                    IndicatorConfidence::High,
                );
            }

            // PT_DENY_ATTACH constant (31 = 0x1f)
            if (line.contains("bl _ptrace") || line.contains("call _ptrace"))
                && lines.iter().skip(i.saturating_sub(5)).take(8).any(|l| l.contains("0x1f") || l.contains("#31"))
            {
                self.add(
                    JailbreakTechniqueKind::PtDenyAttach,
                    "ptrace(PT_DENY_ATTACH, 0, 0, 0) call".to_string(),
                    Some(function_name.to_owned()),
                    IndicatorConfidence::High,
                );
            }

            // IOKit checks
            if line.contains("IOServiceGetMatchingService") || line.contains("IOServiceMatching") {
                self.add(
                    JailbreakTechniqueKind::IOKitCheck,
                    "IOKit service matching call".to_string(),
                    Some(function_name.to_owned()),
                    IndicatorConfidence::Medium,
                );
            }

            // dyld image enumeration
            if line.contains("_dyld_get_image_name") && line.contains("bl ") {
                self.add(
                    JailbreakTechniqueKind::DylibListScan,
                    "_dyld_get_image_name enumeration".to_string(),
                    Some(function_name.to_owned()),
                    IndicatorConfidence::High,
                );
            }
        }
    }

    /// Consume the detector and return the final [`JailbreakReport`].
    #[must_use]
    pub fn finish(self) -> JailbreakReport {
        let technique_counts: HashMap<String, usize> = {
            let mut m: HashMap<String, usize> = HashMap::with_capacity(self.indicators.len());
            for ind in &self.indicators {
                *m.entry(ind.technique.as_str().to_owned()).or_default() += 1;
            }
            m
        };
        let total = self.indicators.len();
        let high_confidence = self.indicators.iter().filter(|i| matches!(i.confidence, IndicatorConfidence::High)).count();
        let detected = total > 0;
        let obfuscated_checks = self.indicators.iter().filter(|i| matches!(i.technique, JailbreakTechniqueKind::Generic)).count() > 2;

        // Deduplicate bypass suggestions without extra clones
        let mut seen_bypass = std::collections::HashSet::new();
        let mut bypasses: Vec<String> = self.indicators
            .iter()
            .filter_map(|i| {
                if seen_bypass.insert(i.bypass.as_str()) {
                    Some(i.bypass.clone())
                } else {
                    None
                }
            })
            .collect();
        bypasses.sort();

        JailbreakReport {
            indicators: self.indicators,
            technique_counts,
            total_indicators: total,
            high_confidence_count: high_confidence,
            has_jailbreak_detection: detected,
            has_obfuscated_checks: obfuscated_checks,
            bypass_suggestions: bypasses,
        }
    }
}

impl Default for JailbreakDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Report ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JailbreakReport {
    pub indicators: Vec<JailbreakIndicator>,
    pub technique_counts: HashMap<String, usize>,
    pub total_indicators: usize,
    pub high_confidence_count: usize,
    pub has_jailbreak_detection: bool,
    pub has_obfuscated_checks: bool,
    pub bypass_suggestions: Vec<String>,
}

impl JailbreakReport {
    /// Classify the overall risk based on high-confidence indicator count.
    #[must_use]
    pub const fn risk_level(&self) -> &'static str {
        match self.high_confidence_count {
            0 => "none",
            1..=3 => "low",
            4..=8 => "medium",
            _ => "high",
        }
    }

    /// Return deduplicated technique names seen in the indicators.
    #[must_use]
    pub fn techniques_used(&self) -> Vec<&str> {
        let mut seen = std::collections::HashSet::new();
        self.indicators
            .iter()
            .filter_map(|i| {
                let s = i.technique.as_str();
                if seen.insert(s) { Some(s) } else { None }
            })
            .collect()
    }

    /// Generate a Frida script skeleton for bypassing detected checks.
    #[must_use]
    pub fn generate_frida_bypass(&self) -> String {
        let mut script = String::from("// Auto-generated Frida jailbreak bypass skeleton\n'use strict';\n\n");

        let techniques: std::collections::HashSet<JailbreakTechniqueKind> =
            self.indicators.iter().map(|i| i.technique).collect();

        if techniques.contains(&JailbreakTechniqueKind::FileSystemCheck)
            || techniques.contains(&JailbreakTechniqueKind::PathCheck)
        {
            script.push_str(r"
// Hook access(2) to block jailbreak path checks
const JAILBREAK_PATHS = [
  '/Applications/Cydia.app', '/bin/bash', '/etc/apt',
  '/Library/MobileSubstrate/MobileSubstrate.dylib',
  '/var/lib/cydia', '/private/var/stash',
];

const _access = Module.findExportByName(null, 'access');
if (_access) {
  Interceptor.attach(_access, {
    onEnter(args) {
      this.path = args[0].readUtf8String();
    },
    onLeave(retval) {
      if (JAILBREAK_PATHS.some(p => this.path && this.path.startsWith(p))) {
        retval.replace(-1);
      }
    }
  });
}
");
        }

        if techniques.contains(&JailbreakTechniqueKind::ForkExec) {
            script.push_str(r"
// Hook fork() to prevent jailbreak detection via fork trick
const _fork = Module.findExportByName(null, 'fork');
if (_fork) {
  Interceptor.attach(_fork, {
    onLeave(retval) {
      retval.replace(ptr(-1));
    }
  });
}
");
        }

        if techniques.contains(&JailbreakTechniqueKind::SysctlKernProc) {
            script.push_str(r"
// Hook sysctl to clear P_TRACED flag
const _sysctl = Module.findExportByName(null, 'sysctl');
if (_sysctl) {
  Interceptor.attach(_sysctl, {
    onEnter(args) {
      this.oldp = args[2];
    },
    onLeave(retval) {
      // Clear P_TRACED (bit 0x800) in kinfo_proc.kp_proc.p_flag at offset 32
      if (this.oldp && !this.oldp.isNull()) {
        try {
          const flags = this.oldp.add(32).readU32();
          this.oldp.add(32).writeU32(flags & ~0x800);
        } catch(_) {}
      }
    }
  });
}
");
        }

        if techniques.contains(&JailbreakTechniqueKind::PtDenyAttach) {
            script.push_str(r"
// Hook ptrace to nop PT_DENY_ATTACH
const _ptrace = Module.findExportByName(null, 'ptrace');
if (_ptrace) {
  Interceptor.attach(_ptrace, {
    onEnter(args) {
      if (args[0].toInt32() === 31) { // PT_DENY_ATTACH
        args[0] = ptr(0);
      }
    }
  });
}
");
        }

        if techniques.contains(&JailbreakTechniqueKind::UrlSchemeCheck) {
            script.push_str(r"
// Hook -[UIApplication canOpenURL:] for jailbreak schemes
const UIApplication = ObjC.classes.UIApplication;
if (UIApplication) {
  const canOpenURL = UIApplication['- canOpenURL:'];
  Interceptor.attach(canOpenURL.implementation, {
    onEnter(args) {
      const url = new ObjC.Object(args[2]).toString();
      if (['cydia://', 'sileo://', 'zbra://'].some(s => url.startsWith(s))) {
        this.block = true;
      }
    },
    onLeave(retval) {
      if (this.block) retval.replace(0);
    }
  });
}
");
        }

        if techniques.contains(&JailbreakTechniqueKind::DylibListScan) {
            script.push_str(r"
// Hook _dyld_get_image_name to hide jailbreak dylibs
const JB_DYLIBS = ['MobileSubstrate', 'substitute-inserter', 'libhooker', 'TweakInject'];
const dyld_get_image_name = Module.findExportByName(null, '_dyld_get_image_name');
if (dyld_get_image_name) {
  Interceptor.attach(dyld_get_image_name, {
    onLeave(retval) {
      if (!retval.isNull()) {
        const name = retval.readUtf8String() || '';
        if (JB_DYLIBS.some(jb => name.includes(jb))) {
          retval.replace(Memory.allocUtf8String('/usr/lib/libobjc.A.dylib'));
        }
      }
    }
  });
}
");
        }

        script.push_str("\nconsole.log('[JB bypass] Jailbreak detection hooks installed.');\n");
        script
    }
}

// ── Public analysis API ───────────────────────────────────────────────────────

/// Analyze strings extracted from a Mach-O binary for jailbreak detection.
#[must_use]
pub fn analyze_strings(strings: &[String]) -> JailbreakReport {
    let mut detector = JailbreakDetector::new();
    detector.scan_strings(strings);
    detector.finish()
}

/// Full analysis combining strings, symbols, and selectors.
#[must_use]
pub fn analyze_binary(
    strings: &[String],
    imported_symbols: &[String],
    objc_selectors: &[String],
) -> JailbreakReport {
    let mut detector = JailbreakDetector::new();
    detector.scan_strings(strings);
    detector.scan_symbols(imported_symbols);
    detector.scan_selectors(objc_selectors);
    detector.finish()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_detection() {
        let strings = vec![
            "/Applications/Cydia.app".to_owned(),
            "/bin/bash".to_owned(),
            "/usr/sbin/sshd".to_owned(),
            "Hello, World!".to_owned(),
        ];
        let report = analyze_strings(&strings);
        assert!(report.has_jailbreak_detection);
        assert!(report.total_indicators >= 3);
    }

    #[test]
    fn test_url_scheme_detection() {
        let strings = vec!["cydia://package/com.example".to_owned()];
        let report = analyze_strings(&strings);
        assert!(report.has_jailbreak_detection);
        let tech = report.techniques_used();
        assert!(tech.contains(&JailbreakTechniqueKind::UrlSchemeCheck.as_str()));
    }

    #[test]
    fn test_dylib_detection() {
        let strings = vec![
            "/Library/MobileSubstrate/MobileSubstrate.dylib".to_owned(),
        ];
        let report = analyze_strings(&strings);
        assert!(report.has_jailbreak_detection);
    }

    #[test]
    fn test_symbol_ptrace() {
        let mut detector = JailbreakDetector::new();
        detector.scan_symbols(&["_ptrace".to_owned(), "_fork".to_owned()]);
        let report = detector.finish();
        assert!(report.total_indicators >= 2);
        assert!(report.high_confidence_count >= 1);
    }

    #[test]
    fn test_selector_scan() {
        let mut detector = JailbreakDetector::new();
        detector.scan_selectors(&[
            "isJailbroken".to_owned(),
            "checkJailbreak".to_owned(),
            "init".to_owned(),
        ]);
        let report = detector.finish();
        assert!(report.total_indicators >= 2);
    }

    #[test]
    fn test_frida_bypass_generation() {
        let strings = vec![
            "/bin/bash".to_owned(),
            "cydia://".to_owned(),
        ];
        let report = analyze_strings(&strings);
        let script = report.generate_frida_bypass();
        assert!(script.contains("Interceptor.attach"));
        assert!(script.contains("canOpenURL"));
    }

    #[test]
    fn test_risk_level() {
        let report = analyze_strings(&[]);
        assert_eq!(report.risk_level(), "none");
    }

    #[test]
    fn test_technique_kind_bypass() {
        for kind in [
            JailbreakTechniqueKind::FileSystemCheck,
            JailbreakTechniqueKind::ForkExec,
            JailbreakTechniqueKind::SysctlKernProc,
            JailbreakTechniqueKind::PtDenyAttach,
        ] {
            assert!(!kind.bypass_suggestion().is_empty());
        }
    }
}
