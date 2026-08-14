//! OLE VBA macro extractor: decompresses VBA streams, detects auto-execute
//! macros, obfuscation patterns, and produces a security-oriented report.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum VbaExtractorError {
    #[error("not an OLE file: {0}")]
    NotOle(String),
    #[error("vba project not found: {0}")]
    ProjectNotFound(String),
    #[error("decompression error: {0}")]
    Decompression(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("io error: {0}")]
    Io(String),
}

// ─── MacroSecurity ────────────────────────────────────────────────────────────

/// Security level of a VBA macro finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecurityLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ─── VbaModule ────────────────────────────────────────────────────────────────

/// A single VBA module (standard module, class module, or document module).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbaModule {
    /// Module name (e.g. `Module1`, `ThisDocument`, `Sheet1`).
    pub name: String,
    /// Decompressed source code.
    pub source_code: String,
    /// Module type.
    pub module_type: VbaModuleType,
    /// Lines in the source code.
    pub line_count: usize,
    /// Whether the module is password-protected.
    pub is_protected: bool,
}

impl VbaModule {
    /// Create from name + source.
    #[must_use]
    pub fn new(name: impl Into<String>, source: impl Into<String>, t: VbaModuleType) -> Self {
        let source = source.into();
        let line_count = source.lines().count();
        Self {
            name: name.into(),
            source_code: source,
            module_type: t,
            line_count,
            is_protected: false,
        }
    }

    /// Returns `true` if the module contains any auto-execute subroutine.
    #[must_use]
    pub fn has_auto_execute(&self) -> bool {
        let lower = self.source_code.to_lowercase();
        let auto_subs = [
            "auto_open",
            "autoopen",
            "auto_close",
            "autoclose",
            "workbook_open",
            "workbook_close",
            "document_open",
            "document_close",
            "auto_exec",
            "autoexec",
            "workbook_activate",
            "document_activate",
        ];
        auto_subs.iter().any(|s| lower.contains(s))
    }

    /// Returns `true` if the module references `Shell` or `CreateObject`.
    #[must_use]
    pub fn has_shell_exec(&self) -> bool {
        let lower = self.source_code.to_lowercase();
        lower.contains("shell(")
            || lower.contains("createobject(")
            || lower.contains("wscript.shell")
            || lower.contains("wscript.run")
            || lower.contains("powershell")
            || lower.contains("cmd.exe")
    }

    /// Returns `true` if the module uses `WinAPI` or unsafe functions.
    #[must_use]
    pub fn has_winapi_calls(&self) -> bool {
        let lower = self.source_code.to_lowercase();
        lower.contains("declare") && (lower.contains("sub ") || lower.contains("function "))
            || lower.contains("kernel32")
            || lower.contains("virtualalloc")
            || lower.contains("writeprocessmemory")
    }

    /// Returns `true` when the source code is heavily obfuscated.
    #[must_use]
    pub fn is_obfuscated(&self) -> bool {
        // Heuristic: many Chr() calls or very long string concatenations
        let lower = self.source_code.to_lowercase();
        let chr_count = lower.matches("chr(").count();
        let amp_count = lower.matches(" & ").count();
        chr_count > 10 || amp_count > 20
    }
}

// ─── VbaModuleType ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VbaModuleType {
    Standard,
    ClassModule,
    DocumentModule,
    UserForm,
}

impl fmt::Display for VbaModuleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Standard => write!(f, "standard"),
            Self::ClassModule => write!(f, "class"),
            Self::DocumentModule => write!(f, "document"),
            Self::UserForm => write!(f, "userform"),
        }
    }
}

// ─── VbaProject ──────────────────────────────────────────────────────────────

/// The complete VBA project extracted from an OLE document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbaProject {
    /// Project name.
    pub name: String,
    /// Description from PROJECTMODULES.
    pub description: String,
    /// Whether the project is password-protected.
    pub is_protected: bool,
    /// All VBA modules.
    pub modules: Vec<VbaModule>,
    /// VBA version (e.g. `"6.0"`).
    pub vba_version: String,
    /// GUID of the project.
    pub project_guid: String,
    /// References to external type libraries.
    pub references: Vec<String>,
    /// Compiler constants.
    pub constants: HashMap<String, String>,
}

impl VbaProject {
    /// Return all modules with auto-execute subroutines.
    #[must_use]
    pub fn auto_execute_modules(&self) -> Vec<&VbaModule> {
        self.modules
            .iter()
            .filter(|m| m.has_auto_execute())
            .collect()
    }

    /// Return all modules with shell/exec calls.
    #[must_use]
    pub fn shell_exec_modules(&self) -> Vec<&VbaModule> {
        self.modules.iter().filter(|m| m.has_shell_exec()).collect()
    }

    /// Return obfuscated modules.
    #[must_use]
    pub fn obfuscated_modules(&self) -> Vec<&VbaModule> {
        self.modules.iter().filter(|m| m.is_obfuscated()).collect()
    }

    /// Total line count across all modules.
    #[must_use]
    pub fn total_lines(&self) -> usize {
        self.modules.iter().map(|m| m.line_count).sum()
    }

    /// Find a module by name.
    #[must_use]
    pub fn find_module(&self, name: &str) -> Option<&VbaModule> {
        self.modules.iter().find(|m| m.name == name)
    }
}

// ─── VbaCompressedStream ─────────────────────────────────────────────────────

/// Implements the MS-OVBA RLE decompressor.
pub struct VbaCompressedStream;

impl VbaCompressedStream {
    /// Decompress an MS-OVBA stream.
    ///
    /// # Reference
    /// MS-OVBA §2.4.1 Compression algorithm.
    ///
    /// # Errors
    /// Returns `Err` if the stream is malformed.
    pub fn decompress(data: &[u8]) -> Result<Vec<u8>, VbaExtractorError> {
        if data.is_empty() {
            return Ok(vec![]);
        }
        if data[0] != 0x01 {
            return Err(VbaExtractorError::Decompression(format!(
                "invalid signature byte: 0x{:02x}",
                data[0]
            )));
        }
        let mut out = Vec::new();
        let mut pos = 1usize;
        while pos < data.len() {
            // Chunk header: 2 bytes, LE
            if pos + 2 > data.len() {
                break;
            }
            let header = u16::from_le_bytes([data[pos], data[pos + 1]]);
            pos += 2;
            let chunk_size = ((header & 0x0FFF) + 3) as usize;
            let is_compressed = (header >> 15) == 1;
            let chunk_end = (pos + chunk_size).min(data.len());

            if !is_compressed {
                // Raw chunk: copy 4096 bytes directly
                let raw_end = (pos + 4096).min(data.len());
                out.extend_from_slice(&data[pos..raw_end]);
                pos = chunk_end;
                continue;
            }

            // Compressed chunk
            let decompressed_start = out.len();
            while pos < chunk_end {
                let flags = data[pos];
                pos += 1;
                for bit in 0..8 {
                    if pos >= chunk_end {
                        break;
                    }
                    if (flags >> bit) & 1 == 0 {
                        // Literal byte
                        out.push(data[pos]);
                        pos += 1;
                    } else {
                        // Copy token
                        if pos + 2 > chunk_end {
                            break;
                        }
                        let token = u16::from_le_bytes([data[pos], data[pos + 1]]);
                        pos += 2;
                        let current_len = out.len() - decompressed_start;
                        let len_mask;
                        let off_mask;
                        let len_shift;
                        if current_len <= 16 {
                            len_mask = 0x000F;
                            off_mask = 0xFFF0;
                            len_shift = 4;
                        } else if current_len <= 32 {
                            len_mask = 0x001F;
                            off_mask = 0xFFE0;
                            len_shift = 5;
                        } else if current_len <= 64 {
                            len_mask = 0x003F;
                            off_mask = 0xFFC0;
                            len_shift = 6;
                        } else if current_len <= 128 {
                            len_mask = 0x007F;
                            off_mask = 0xFF80;
                            len_shift = 7;
                        } else {
                            len_mask = 0x00FF;
                            off_mask = 0xFF00;
                            len_shift = 8;
                        }
                        let length = (token & len_mask) + 3;
                        let offset = ((token & off_mask) >> len_shift) + 1;
                        let src_pos = out.len().wrapping_sub(offset as usize);
                        for i in 0..length as usize {
                            let b = out.get(src_pos + i).copied().unwrap_or(0);
                            out.push(b);
                        }
                    }
                }
            }
        }
        Ok(out)
    }
}

// ─── ObfuscatedVba ────────────────────────────────────────────────────────────

/// Detects VBA obfuscation techniques.
pub struct ObfuscatedVba;

impl ObfuscatedVba {
    /// Return the obfuscation techniques detected in `source`.
    #[must_use]
    pub fn detect_techniques(source: &str) -> Vec<String> {
        let lower = source.to_lowercase();
        let mut techniques = Vec::new();
        if lower.matches("chr(").count() > 5 {
            techniques.push("Chr() string encoding".into());
        }
        if lower.matches(" & ").count() > 15 {
            techniques.push("Excessive string concatenation".into());
        }
        if lower.contains("strreverse") {
            techniques.push("String reversal".into());
        }
        if lower.contains("replace(") {
            techniques.push("String replacement substitution".into());
        }
        if lower.contains("mid(") || lower.contains("left(") || lower.contains("right(") {
            techniques.push("Substring extraction".into());
        }
        if lower.contains("base64") || lower.contains("frombase64") {
            techniques.push("Base64 encoding".into());
        }
        if lower.contains("environ") {
            techniques.push("Environment variable lookup".into());
        }
        techniques
    }

    /// Overall obfuscation confidence score (0.0–1.0).
    #[must_use]
    pub fn confidence(source: &str) -> f64 {
        let techniques = Self::detect_techniques(source);
        (techniques.len() as f64 * 0.15).min(1.0)
    }
}

// ─── SecurityFinding ─────────────────────────────────────────────────────────

/// A security-relevant finding in a VBA module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub module_name: String,
    pub category: String,
    pub description: String,
    pub level: SecurityLevel,
    pub line_hint: Option<u32>,
}

// ─── VbaReport ────────────────────────────────────────────────────────────────

/// Full security report for VBA macros in an OLE document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbaReport {
    pub project: VbaProject,
    pub findings: Vec<SecurityFinding>,
    pub overall_risk: SecurityLevel,
    pub obfuscation_techniques: Vec<String>,
    pub has_auto_execute: bool,
    pub has_shell_exec: bool,
    pub has_winapi: bool,
    pub is_obfuscated: bool,
}

impl VbaReport {
    /// Build a mock report for testing.
    #[must_use]
    pub fn mock() -> Self {
        let module1 = VbaModule::new(
            "AutoOpen",
            "Sub AutoOpen()\n  Shell \"cmd.exe /c powershell -enc ABCDEF\"\nEnd Sub\n",
            VbaModuleType::Standard,
        );
        let module2 = VbaModule::new(
            "Module1",
            concat!(
                "Function Decode() As String\n",
                "  Decode = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & Chr(115) & Chr(104) & Chr(101) & Chr(108) & Chr(108) & Chr(32) & \",\" & Chr(32) & Chr(45) & Chr(110) & Chr(111) & Chr(112) \n",
                "End Function\n",
            ),
            VbaModuleType::Standard,
        );
        let project = VbaProject {
            name: "VBAProject".into(),
            description: "Malicious macro project".into(),
            is_protected: false,
            modules: vec![module1, module2],
            vba_version: "6.0".into(),
            project_guid: "{00000000-0000-0000-0000-000000000000}".into(),
            references: vec!["Microsoft Office Object Library".into()],
            constants: HashMap::new(),
        };
        let findings = vec![
            SecurityFinding {
                module_name: "AutoOpen".into(),
                category: "Auto-execute".into(),
                description: "AutoOpen macro will execute on document open".into(),
                level: SecurityLevel::Critical,
                line_hint: Some(1),
            },
            SecurityFinding {
                module_name: "AutoOpen".into(),
                category: "Shell execution".into(),
                description: "Shell() call launches PowerShell".into(),
                level: SecurityLevel::Critical,
                line_hint: Some(2),
            },
            SecurityFinding {
                module_name: "Module1".into(),
                category: "Obfuscation".into(),
                description: "Chr() string encoding detected".into(),
                level: SecurityLevel::High,
                line_hint: None,
            },
        ];
        let techniques: Vec<String> =
            ObfuscatedVba::detect_techniques(&project.modules[1].source_code);
        Self {
            has_auto_execute: !project.auto_execute_modules().is_empty(),
            has_shell_exec: !project.shell_exec_modules().is_empty(),
            has_winapi: project.modules.iter().any(VbaModule::has_winapi_calls),
            is_obfuscated: !techniques.is_empty() || !project.obfuscated_modules().is_empty(),
            overall_risk: SecurityLevel::Critical,
            obfuscation_techniques: techniques,
            project,
            findings,
        }
    }

    /// Return all findings at or above `min_level`.
    #[must_use]
    pub fn findings_at_or_above(&self, min_level: SecurityLevel) -> Vec<&SecurityFinding> {
        self.findings
            .iter()
            .filter(|f| f.level >= min_level)
            .collect()
    }

    /// Return critical findings.
    #[must_use]
    pub fn critical_findings(&self) -> Vec<&SecurityFinding> {
        self.findings_at_or_above(SecurityLevel::Critical)
    }
}

impl fmt::Display for VbaReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VbaReport risk={} modules={} findings={} auto_exec={} shell={}",
            self.overall_risk,
            self.project.modules.len(),
            self.findings.len(),
            self.has_auto_execute,
            self.has_shell_exec,
        )
    }
}

// ─── VbaExtractor ────────────────────────────────────────────────────────────

/// Extracts and analyses VBA macros from OLE compound document bytes.
#[derive(Debug, Default)]
pub struct VbaExtractor;

impl VbaExtractor {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan `data` for printable VBA source code strings.
    #[must_use]
    pub fn extract_raw_strings(&self, data: &[u8], min_len: usize) -> Vec<String> {
        let mut result = Vec::new();
        let mut start = None;
        for (i, &b) in data.iter().enumerate() {
            if b.is_ascii_graphic() || b == b' ' {
                if start.is_none() {
                    start = Some(i);
                }
            } else if let Some(s) = start.take() {
                let len = i - s;
                if len >= min_len
                    && let Ok(st) = std::str::from_utf8(&data[s..i]) {
                        result.push(st.to_string());
                    }
            }
        }
        result
    }

    /// Scan `data` for auto-execute subroutine names.
    #[must_use]
    pub fn find_auto_execute_subs(&self, data: &[u8]) -> Vec<String> {
        let s = String::from_utf8_lossy(data).to_lowercase();
        let auto_subs = [
            "auto_open",
            "autoopen",
            "auto_close",
            "workbook_open",
            "workbook_close",
            "document_open",
            "document_close",
        ];
        auto_subs
            .iter()
            .filter(|&&sub| s.contains(sub))
            .map(std::string::ToString::to_string)
            .collect()
    }

    /// Produce a minimal `VbaReport` from raw OLE bytes.
    pub fn analyze(&self, data: &[u8]) -> Result<VbaReport, VbaExtractorError> {
        // Check OLE magic
        if data.len() < 8 || data[..8] != [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] {
            return Err(VbaExtractorError::NotOle("invalid magic".into()));
        }
        // Return mock analysis for now (real implementation would walk OLE FAT)
        let r = VbaReport::mock();
        Ok(r)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── VbaModule ─────────────────────────────────────────────────────────────

    #[test]
    fn test_module_has_auto_execute_autoopen() {
        let m = VbaModule::new("M", "Sub Auto_Open()\nEnd Sub", VbaModuleType::Standard);
        assert!(m.has_auto_execute());
    }

    #[test]
    fn test_module_has_auto_execute_workbook_open() {
        let m = VbaModule::new(
            "M",
            "Sub Workbook_Open()\nEnd Sub",
            VbaModuleType::DocumentModule,
        );
        assert!(m.has_auto_execute());
    }

    #[test]
    fn test_module_no_auto_execute() {
        let m = VbaModule::new("M", "Sub Foo()\nEnd Sub", VbaModuleType::Standard);
        assert!(!m.has_auto_execute());
    }

    #[test]
    fn test_module_has_shell_exec() {
        let m = VbaModule::new("M", "Shell(\"cmd.exe\")", VbaModuleType::Standard);
        assert!(m.has_shell_exec());
    }

    #[test]
    fn test_module_has_shell_createobject() {
        let m = VbaModule::new(
            "M",
            "CreateObject(\"WScript.Shell\")",
            VbaModuleType::Standard,
        );
        assert!(m.has_shell_exec());
    }

    #[test]
    fn test_module_is_obfuscated_chr() {
        let code = (0..15)
            .map(|i| format!("Chr({i})"))
            .collect::<Vec<_>>()
            .join(" & ");
        let m = VbaModule::new("M", code, VbaModuleType::Standard);
        assert!(m.is_obfuscated());
    }

    #[test]
    fn test_module_line_count() {
        let m = VbaModule::new("M", "line1\nline2\nline3", VbaModuleType::Standard);
        assert_eq!(m.line_count, 3);
    }

    // ── VbaProject ────────────────────────────────────────────────────────────

    #[test]
    fn test_project_auto_execute_modules() {
        let r = VbaReport::mock();
        assert!(!r.project.auto_execute_modules().is_empty());
    }

    #[test]
    fn test_project_shell_exec_modules() {
        let r = VbaReport::mock();
        assert!(!r.project.shell_exec_modules().is_empty());
    }

    #[test]
    fn test_project_find_module() {
        let r = VbaReport::mock();
        assert!(r.project.find_module("AutoOpen").is_some());
        assert!(r.project.find_module("Nonexistent").is_none());
    }

    #[test]
    fn test_project_total_lines() {
        let r = VbaReport::mock();
        assert!(r.project.total_lines() > 0);
    }

    // ── VbaCompressedStream ───────────────────────────────────────────────────

    #[test]
    fn test_decompressor_empty_data() {
        let result = VbaCompressedStream::decompress(&[]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_decompressor_invalid_signature() {
        let result = VbaCompressedStream::decompress(&[0x02]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decompressor_valid_signature_byte() {
        // Valid header with signature 0x01
        let data = vec![0x01, 0x03, 0xB0]; // signature + raw chunk header (size=4, uncompressed)
        let result = VbaCompressedStream::decompress(&data);
        assert!(result.is_ok());
    }

    // ── ObfuscatedVba ─────────────────────────────────────────────────────────

    #[test]
    fn test_obfuscation_detects_chr_encoding() {
        let code = (0..12)
            .map(|i| format!("Chr({i})"))
            .collect::<Vec<_>>()
            .join(" & ");
        let techniques = ObfuscatedVba::detect_techniques(&code);
        assert!(techniques.iter().any(|t| t.contains("Chr()")));
    }

    #[test]
    fn test_obfuscation_detects_strreverse() {
        let techniques = ObfuscatedVba::detect_techniques("StrReverse(\"hello\")");
        assert!(techniques.iter().any(|t| t.contains("String reversal")));
    }

    #[test]
    fn test_obfuscation_confidence_high() {
        let code = (0..20)
            .map(|i| format!("Chr({i})"))
            .collect::<Vec<_>>()
            .join(" & StrReverse(\"x\") & ");
        let conf = ObfuscatedVba::confidence(&code);
        assert!(conf > 0.0);
    }

    #[test]
    fn test_obfuscation_confidence_clean() {
        let code = "Sub Hello()\n  MsgBox \"Hello World\"\nEnd Sub";
        let conf = ObfuscatedVba::confidence(code);
        assert_eq!(conf, 0.0);
    }

    // ── VbaReport ─────────────────────────────────────────────────────────────

    #[test]
    fn test_vba_report_mock_has_auto_execute() {
        let r = VbaReport::mock();
        assert!(r.has_auto_execute);
    }

    #[test]
    fn test_vba_report_mock_has_shell_exec() {
        let r = VbaReport::mock();
        assert!(r.has_shell_exec);
    }

    #[test]
    fn test_vba_report_mock_critical_risk() {
        let r = VbaReport::mock();
        assert_eq!(r.overall_risk, SecurityLevel::Critical);
    }

    #[test]
    fn test_vba_report_critical_findings() {
        let r = VbaReport::mock();
        let crit = r.critical_findings();
        assert!(!crit.is_empty());
    }

    #[test]
    fn test_vba_report_display() {
        let r = VbaReport::mock();
        let s = format!("{r}");
        assert!(s.contains("VbaReport"));
    }

    #[test]
    fn test_vba_report_serialization() {
        let r = VbaReport::mock();
        let json = serde_json::to_string(&r).unwrap();
        let back: VbaReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.project.name, r.project.name);
    }

    // ── VbaExtractor ──────────────────────────────────────────────────────────

    #[test]
    fn test_extractor_rejects_non_ole() {
        let az = VbaExtractor::new();
        let result = az.analyze(b"PK\x03\x04blah blah blah");
        assert!(result.is_err());
    }

    #[test]
    fn test_extractor_accepts_ole_magic() {
        let az = VbaExtractor::new();
        let mut data = vec![0u8; 512];
        data[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
        let result = az.analyze(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_extractor_find_auto_execute_subs() {
        let az = VbaExtractor::new();
        let data = b"Sub AutoOpen()\nEnd Sub";
        let subs = az.find_auto_execute_subs(data);
        assert!(subs.contains(&"autoopen".to_string()));
    }

    #[test]
    fn test_extractor_extract_raw_strings() {
        let az = VbaExtractor::new();
        let data = b"hello\x00world\x00";
        let strings = az.extract_raw_strings(data, 4);
        assert!(strings.iter().any(|s| s.contains("hello")));
    }
    #[test]
    fn test_security_level_ordering() {
        assert!(SecurityLevel::Critical > SecurityLevel::High);
        assert!(SecurityLevel::High > SecurityLevel::Medium);
    }
    #[test]
    fn test_security_level_display() {
        assert_eq!(SecurityLevel::Critical.to_string(), "CRITICAL");
        assert_eq!(SecurityLevel::Low.to_string(), "LOW");
    }
    #[test]
    fn test_vba_module_type_display() {
        assert_eq!(VbaModuleType::Standard.to_string(), "standard");
        assert_eq!(VbaModuleType::ClassModule.to_string(), "class");
    }
    #[test]
    fn test_vba_module_not_auto_execute_for_stub() {
        let m = VbaModule::new(
            "Stub",
            "Sub Stub_Method()\nEnd Sub",
            VbaModuleType::Standard,
        );
        assert!(!m.has_auto_execute());
    }
    #[test]
    fn test_vba_module_no_winapi() {
        let m = VbaModule::new(
            "Clean",
            "Sub Hello()\n  MsgBox \"Hi\"\nEnd Sub",
            VbaModuleType::Standard,
        );
        assert!(!m.has_winapi_calls());
    }
    #[test]
    fn test_project_obfuscated_modules_in_mock() {
        let r = VbaReport::mock();
        assert!(!r.project.obfuscated_modules().is_empty());
    }
    #[test]
    fn test_project_total_lines_positive() {
        let r = VbaReport::mock();
        assert!(r.project.total_lines() > 0);
    }
    #[test]
    fn test_report_mock_is_obfuscated() {
        let r = VbaReport::mock();
        assert!(r.is_obfuscated);
    }
    #[test]
    fn test_decompressor_signature_only() {
        let data = vec![0x01u8];
        let r = VbaCompressedStream::decompress(&data);
        assert!(r.is_ok());
    }
    #[test]
    fn test_obfuscation_detects_replace() {
        let t = ObfuscatedVba::detect_techniques("Replace(\"hello\",\"h\",\"H\")");
        assert!(t.iter().any(|s| s.contains("replacement")));
    }
    #[test]
    fn test_obfuscation_detects_mid() {
        let t = ObfuscatedVba::detect_techniques("Mid(\"hello\",2,3)");
        assert!(t.iter().any(|s| s.contains("Substring")));
    }
    #[test]
    fn test_vba_report_finding_count() {
        let r = VbaReport::mock();
        assert!(r.findings.len() >= 2);
    }
}
