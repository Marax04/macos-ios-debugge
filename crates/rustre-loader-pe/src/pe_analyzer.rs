//! Deep PE analysis: import API groups, export analysis, resource tree,
//! debug info (PDB GUID), relocation table, bound imports, TLS callbacks,
//! manifest XML, Authenticode.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::casts::usize_to_f64;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum PeAnalyzerError {
    #[error("not a PE file: {0}")]
    NotPe(String),
    #[error("truncated at offset {0:#x}")]
    Truncated(usize),
    #[error("parse error: {0}")]
    Parse(String),
}

// ─── ImportGroup ─────────────────────────────────────────────────────────────

/// Category of API calls imported from a DLL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiGroup {
    FileIo,
    Registry,
    Network,
    Process,
    Thread,
    Memory,
    Crypto,
    Ui,
    AntiDebug,
    Injection,
    Persistence,
    Unknown,
}

impl fmt::Display for ApiGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::FileIo => "File I/O",
            Self::Registry => "Registry",
            Self::Network => "Network",
            Self::Process => "Process",
            Self::Thread => "Thread",
            Self::Memory => "Memory",
            Self::Crypto => "Cryptography",
            Self::Ui => "UI",
            Self::AntiDebug => "Anti-Debug",
            Self::Injection => "Code Injection",
            Self::Persistence => "Persistence",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

impl ApiGroup {
    /// Classify an API function name into a group.
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        let lower = name.to_lowercase();
        if lower.contains("createfile")
            || lower.contains("readfile")
            || lower.contains("writefile")
            || lower.contains("deletefile")
            || lower.contains("copyfile")
            || lower.contains("openfile")
        {
            return Self::FileIo;
        }
        if lower.contains("regopen")
            || lower.contains("regcreate")
            || lower.contains("regquery")
            || lower.contains("regset")
            || lower.contains("regdelete")
        {
            return Self::Registry;
        }
        if lower.contains("internet")
            || lower.contains("http")
            || lower.contains("ftp")
            || lower.contains("winsock")
            || lower == "send"
            || lower == "recv"
            || lower == "connect"
            || lower.contains("socket")
            || lower == "bind"
            || lower.contains("wsa")
        {
            return Self::Network;
        }
        if lower.contains("createprocess")
            || lower.contains("openprocess")
            || lower.contains("terminateprocess")
            || lower.contains("shellexecute")
            || lower == "system"
            || lower.contains("winexec")
        {
            return Self::Process;
        }
        if lower.contains("createthread")
            || lower.contains("suspendthread")
            || lower.contains("resumethread")
            || lower.contains("setthreadcontext")
        {
            return Self::Thread;
        }
        if lower.contains("virtualalloc")
            || lower.contains("virtualfree")
            || lower.contains("heapalloc")
            || lower.contains("writeprocessmemory")
            || lower.contains("readprocessmemory")
        {
            return Self::Memory;
        }
        if lower.contains("crypt")
            || lower.contains("hash")
            || lower.contains("rand")
            || lower.contains("bcrypt")
            || lower.contains("ncrypt")
        {
            return Self::Crypto;
        }
        if lower.contains("isdebuggerpresent")
            || lower.contains("checkremotedebugger")
            || lower.contains("outputdebugstring")
            || lower.contains("ntqueryin")
        {
            return Self::AntiDebug;
        }
        if lower.contains("queueuserapc")
            || lower.contains("ntmapviewofsection")
            || lower.contains("setwindowshook")
            || lower.contains("injection")
        {
            return Self::Injection;
        }
        if lower.contains("schtask")
            || lower.contains("services")
            || lower.contains("runonce")
            || lower.contains("startup")
        {
            return Self::Persistence;
        }
        Self::Unknown
    }

    /// Threat weight of this API group (0–10).
    #[must_use]
    pub const fn threat_weight(self) -> f64 {
        match self {
            Self::Injection => 9.0,
            Self::AntiDebug => 8.0,
            Self::Persistence => 7.0,
            Self::Memory | Self::Process => 5.0,
            Self::Network | Self::Thread => 4.0,
            Self::Crypto | Self::Registry => 3.0,
            Self::FileIo => 2.0,
            Self::Ui => 1.0,
            Self::Unknown => 0.5,
        }
    }
}

// ─── ImportAnalysis ──────────────────────────────────────────────────────────

/// Analysis of a PE import table.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImportAnalysis {
    /// All imported functions by DLL.
    pub by_dll: HashMap<String, Vec<String>>,
    /// API group counts.
    pub group_counts: HashMap<String, usize>,
    /// Total import count.
    pub total_imports: usize,
    /// Risk score from import APIs (0–100).
    pub risk_score: f64,
    /// Whether `IsDebuggerPresent` or similar is imported.
    pub has_anti_debug: bool,
    /// Whether `VirtualAlloc` + `WriteProcessMemory` both appear (injection pattern).
    pub has_injection_pattern: bool,
    /// Whether any network API is imported.
    pub has_network: bool,
}

impl ImportAnalysis {
    /// Build from a flat list of `(dll, function_name)` pairs.
    #[must_use]
    pub fn from_imports(imports: &[(String, String)]) -> Self {
        let mut by_dll: HashMap<String, Vec<String>> = HashMap::with_capacity(imports.len());
        let mut group_counts: HashMap<String, usize> = HashMap::with_capacity(12); // bounded by ApiGroup variants
        let mut has_anti_debug = false;
        let mut has_virtual_alloc = false;
        let mut has_write_process_mem = false;
        let mut has_network = false;
        let mut total_risk = 0.0_f64;

        for (dll, func) in imports {
            by_dll.entry(dll.clone()).or_default().push(func.clone());
            let group = ApiGroup::from_name(func);
            *group_counts.entry(group.to_string()).or_insert(0) += 1;
            total_risk += group.threat_weight();
            if group == ApiGroup::AntiDebug {
                has_anti_debug = true;
            }
            if group == ApiGroup::Network {
                has_network = true;
            }
            let lower = func.to_lowercase();
            if lower.contains("virtualalloc") {
                has_virtual_alloc = true;
            }
            if lower.contains("writeprocessmemory") {
                has_write_process_mem = true;
            }
        }

        let total = imports.len();
        let risk_score = (total_risk / usize_to_f64(total.max(1)) * 10.0).min(100.0);
        let has_injection_pattern = has_virtual_alloc && has_write_process_mem;

        Self {
            by_dll,
            group_counts,
            total_imports: total,
            risk_score,
            has_anti_debug,
            has_injection_pattern,
            has_network,
        }
    }
}

// ─── ExportAnalysis ───────────────────────────────────────────────────────────

/// Analysis of PE exports.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExportAnalysis {
    pub exported_names: Vec<String>,
    pub forwarded: Vec<(String, String)>, // (name, forwarder)
    pub ordinal_only: Vec<u16>,
    pub dll_name: Option<String>,
    pub total_exports: usize,
}

impl ExportAnalysis {
    /// Returns `true` if the binary has exports (i.e., is a DLL).
    #[must_use]
    pub const fn has_exports(&self) -> bool {
        self.total_exports > 0
    }

    /// Returns `true` if any exports are forwarded.
    #[must_use]
    pub const fn has_forwards(&self) -> bool {
        !self.forwarded.is_empty()
    }
}

// ─── ResourceTree ─────────────────────────────────────────────────────────────

/// Simplified PE resource tree summary.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourceTree {
    pub type_counts: HashMap<String, usize>,
    pub manifest_xml: Option<String>,
    pub version_info: Option<VersionInfo>,
    pub icon_count: usize,
    pub total_leaves: usize,
    pub total_size: u64,
}

/// Parsed `VS_VERSION_INFO`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub file_version: String,
    pub product_version: String,
    pub company_name: String,
    pub product_name: String,
    pub original_filename: String,
}

impl VersionInfo {
    #[must_use]
    pub fn mock() -> Self {
        Self {
            file_version: "1.0.0.0".into(),
            product_version: "1.0".into(),
            company_name: "Example Corp".into(),
            product_name: "ExampleApp".into(),
            original_filename: "app.exe".into(),
        }
    }
}

// ─── DebugInfo ────────────────────────────────────────────────────────────────

/// Debug directory information including PDB GUID.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DebugInfo {
    pub pdb_path: Option<String>,
    pub pdb_guid: Option<String>,
    pub pdb_age: Option<u32>,
    pub debug_types: Vec<String>,
    pub compiler_info: Option<String>,
}

impl DebugInfo {
    /// Returns `true` if full PDB info is available (path + GUID).
    #[must_use]
    pub const fn has_pdb_info(&self) -> bool {
        self.pdb_path.is_some() && self.pdb_guid.is_some()
    }
}

// ─── RelocationTable ─────────────────────────────────────────────────────────

/// Summary of the PE base relocation table.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelocationTable {
    pub block_count: usize,
    pub total_relocations: usize,
    pub type_counts: HashMap<String, usize>,
    pub has_high_entropy_relocs: bool,
}

// ─── BoundImports ─────────────────────────────────────────────────────────────

/// Bound import directory information.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BoundImports {
    pub entries: Vec<BoundImportEntry>,
    pub is_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundImportEntry {
    pub dll_name: String,
    pub timestamp: u32,
    pub forwarder_refs: u16,
}

// ─── TlsCallbacks ─────────────────────────────────────────────────────────────

/// TLS callback addresses.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsCallbacks {
    pub callbacks: Vec<u64>,
    pub data_start: u64,
    pub data_end: u64,
    pub index_va: u64,
}

impl TlsCallbacks {
    /// Returns `true` if any TLS callbacks are registered.
    #[must_use]
    pub const fn has_callbacks(&self) -> bool {
        !self.callbacks.is_empty()
    }
}

// ─── ManifestXml ─────────────────────────────────────────────────────────────

/// PE application manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestXml {
    pub raw_xml: String,
    pub requested_execution_level: Option<String>,
    pub ui_access: bool,
    pub dpi_aware: bool,
    pub supports_long_paths: bool,
}

impl ManifestXml {
    /// Parse from raw XML bytes.
    #[must_use]
    pub fn from_xml(xml: &str) -> Self {
        let raw_xml = xml.to_string();
        let lower = xml.to_lowercase();
        let level = if lower.contains("requireadministrator") {
            Some("requireAdministrator".into())
        } else if lower.contains("highestAvailable".to_lowercase().as_str()) {
            Some("highestAvailable".into())
        } else if lower.contains("asinvoker") {
            Some("asInvoker".into())
        } else {
            None
        };
        let ui_access = lower.contains("uiaccess=\"true\"");
        let dpi_aware = lower.contains("dpiawareness") || lower.contains("dpiaware");
        let supports_long_paths = lower.contains("longpathawarenesscompatibility");
        Self {
            raw_xml,
            requested_execution_level: level,
            ui_access,
            dpi_aware,
            supports_long_paths,
        }
    }

    /// Returns `true` if admin privileges are requested.
    #[must_use]
    pub fn requires_admin(&self) -> bool {
        self.requested_execution_level.as_deref() == Some("requireAdministrator")
    }
}

// ─── AuthentiCode ─────────────────────────────────────────────────────────────

/// Authenticode signature information from the security directory.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthentiCode {
    pub is_signed: bool,
    pub cert_chain_length: usize,
    pub signer_cn: Option<String>,
    pub timestamp_cn: Option<String>,
    pub algorithm: Option<String>,
    pub is_timestamp_valid: bool,
}

impl AuthentiCode {
    /// Returns `true` if the binary is timestamped.
    #[must_use]
    pub const fn has_timestamp(&self) -> bool {
        self.timestamp_cn.is_some()
    }
}

// ─── PeAnalysisReport ────────────────────────────────────────────────────────

/// Full deep-analysis report for a PE binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeAnalysisReport {
    pub machine: String,
    pub subsystem: String,
    pub image_base: u64,
    pub entry_point: u64,
    pub is_64bit: bool,
    pub is_dll: bool,
    pub is_dotnet: bool,
    pub timestamp: u32,
    pub imports: ImportAnalysis,
    pub exports: ExportAnalysis,
    pub resources: ResourceTree,
    pub debug_info: DebugInfo,
    pub relocations: RelocationTable,
    pub bound_imports: BoundImports,
    pub tls: TlsCallbacks,
    pub manifest: Option<ManifestXml>,
    pub authenticode: AuthentiCode,
    pub overall_threat: f64,
}

impl PeAnalysisReport {
    /// Build a mock report for testing.
    #[must_use]
    pub fn mock() -> Self {
        let raw_imports = vec![
            ("KERNEL32.dll".into(), "CreateProcess".into()),
            ("KERNEL32.dll".into(), "VirtualAlloc".into()),
            ("KERNEL32.dll".into(), "WriteProcessMemory".into()),
            ("KERNEL32.dll".into(), "IsDebuggerPresent".into()),
            ("WS2_32.dll".into(), "connect".into()),
            ("WS2_32.dll".into(), "send".into()),
            ("ADVAPI32.dll".into(), "RegOpenKeyEx".into()),
            ("ADVAPI32.dll".into(), "CryptEncrypt".into()),
        ];
        let imports = ImportAnalysis::from_imports(&raw_imports);
        let exports = ExportAnalysis {
            exported_names: vec![],
            forwarded: vec![],
            ordinal_only: vec![],
            dll_name: None,
            total_exports: 0,
        };
        let resources = ResourceTree {
            type_counts: HashMap::from([("RT_VERSION".into(), 1usize), ("RT_MANIFEST".into(), 1)]),
            manifest_xml: Some(
                "<assembly><requestedExecutionLevel level=\"asInvoker\"/></assembly>".into(),
            ),
            version_info: Some(VersionInfo::mock()),
            icon_count: 1,
            total_leaves: 3,
            total_size: 4096,
        };
        let debug = DebugInfo {
            pdb_path: Some("C:\\build\\app.pdb".into()),
            pdb_guid: Some("AABBCCDD-EEFF-0011-2233-445566778899".into()),
            pdb_age: Some(1),
            debug_types: vec!["CodeView".into()],
            compiler_info: Some("Microsoft (R) C/C++ Optimizing Compiler".into()),
        };
        let relocs = RelocationTable {
            block_count: 10,
            total_relocations: 512,
            type_counts: HashMap::from([("DIR64".into(), 512usize)]),
            has_high_entropy_relocs: false,
        };
        let tls = TlsCallbacks {
            callbacks: vec![0x1_4000_1000],
            data_start: 0x1_4001_0000,
            data_end: 0x1_4001_0010,
            index_va: 0x1_4001_F000,
        };
        let manifest = ManifestXml::from_xml(
            "<assembly><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></assembly>",
        );
        let auth = AuthentiCode {
            is_signed: false,
            cert_chain_length: 0,
            signer_cn: None,
            timestamp_cn: None,
            algorithm: None,
            is_timestamp_valid: false,
        };
        let overall_threat = imports.risk_score;
        Self {
            machine: "x86_64".into(),
            subsystem: "Console".into(),
            image_base: 0x1400_0000,
            entry_point: 0x1400_1000,
            is_64bit: true,
            is_dll: false,
            is_dotnet: false,
            timestamp: 0xDEAD_BEEF,
            imports,
            exports,
            resources,
            debug_info: debug,
            relocations: relocs,
            bound_imports: BoundImports::default(),
            tls,
            manifest: Some(manifest),
            authenticode: auth,
            overall_threat,
        }
    }

    /// Returns `true` when the binary has anti-debug imports.
    #[must_use]
    pub const fn has_anti_debug(&self) -> bool {
        self.imports.has_anti_debug
    }

    /// Returns `true` when injection patterns are present.
    #[must_use]
    pub const fn has_injection_pattern(&self) -> bool {
        self.imports.has_injection_pattern
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "PE {} {} threat={:.1} imports={} tls_callbacks={} signed={}",
            self.machine,
            self.subsystem,
            self.overall_threat,
            self.imports.total_imports,
            self.tls.callbacks.len(),
            self.authenticode.is_signed,
        )
    }
}

impl fmt::Display for PeAnalysisReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ─── PeAnalyzer ───────────────────────────────────────────────────────────────

/// Deep PE analysis engine.
#[derive(Debug, Default)]
pub struct PeAnalyzer;

impl PeAnalyzer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns `true` if `data` starts with `MZ` and has `PE\0\0` at the offset.
    #[must_use]
    pub fn is_pe(data: &[u8]) -> bool {
        if data.len() < 0x40 {
            return false;
        }
        if data[0] != 0x4D || data[1] != 0x5A {
            return false;
        }
        let pe_off = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;
        if pe_off + 4 > data.len() {
            return false;
        }
        data[pe_off..pe_off + 4] == [0x50, 0x45, 0x00, 0x00]
    }

    /// Classify an API name.
    #[must_use]
    pub fn classify_api(name: &str) -> ApiGroup {
        ApiGroup::from_name(name)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ApiGroup ──────────────────────────────────────────────────────────────

    #[test]
    fn test_api_group_create_process() {
        assert_eq!(ApiGroup::from_name("CreateProcessW"), ApiGroup::Process);
    }

    #[test]
    fn test_api_group_virtual_alloc() {
        assert_eq!(ApiGroup::from_name("VirtualAllocEx"), ApiGroup::Memory);
    }

    #[test]
    fn test_api_group_is_debugger_present() {
        assert_eq!(
            ApiGroup::from_name("IsDebuggerPresent"),
            ApiGroup::AntiDebug
        );
    }

    #[test]
    fn test_api_group_winsock_connect() {
        assert_eq!(ApiGroup::from_name("connect"), ApiGroup::Network);
    }

    #[test]
    fn test_api_group_reg_open() {
        assert_eq!(ApiGroup::from_name("RegOpenKeyExA"), ApiGroup::Registry);
    }

    #[test]
    fn test_api_group_threat_weight_ordering() {
        assert!(ApiGroup::Injection.threat_weight() > ApiGroup::FileIo.threat_weight());
    }

    #[test]
    fn test_api_group_display() {
        assert_eq!(ApiGroup::Injection.to_string(), "Code Injection");
    }

    // ── ImportAnalysis ────────────────────────────────────────────────────────

    #[test]
    fn test_import_analysis_mock_has_anti_debug() {
        let r = PeAnalysisReport::mock();
        assert!(r.imports.has_anti_debug);
    }

    #[test]
    fn test_import_analysis_mock_has_injection() {
        let r = PeAnalysisReport::mock();
        assert!(r.imports.has_injection_pattern);
    }

    #[test]
    fn test_import_analysis_mock_has_network() {
        let r = PeAnalysisReport::mock();
        assert!(r.imports.has_network);
    }

    #[test]
    fn test_import_analysis_total_imports() {
        let r = PeAnalysisReport::mock();
        assert_eq!(r.imports.total_imports, 8);
    }

    #[test]
    fn test_import_analysis_risk_positive() {
        let r = PeAnalysisReport::mock();
        assert!(r.imports.risk_score > 0.0);
    }

    // ── DebugInfo ─────────────────────────────────────────────────────────────

    #[test]
    fn test_debug_info_has_pdb() {
        let r = PeAnalysisReport::mock();
        assert!(r.debug_info.has_pdb_info());
    }

    #[test]
    fn test_debug_info_pdb_path() {
        let r = PeAnalysisReport::mock();
        assert!(r.debug_info.pdb_path.is_some());
    }

    // ── TlsCallbacks ──────────────────────────────────────────────────────────

    #[test]
    fn test_tls_has_callbacks() {
        let r = PeAnalysisReport::mock();
        assert!(r.tls.has_callbacks());
    }

    #[test]
    fn test_tls_callback_count() {
        let r = PeAnalysisReport::mock();
        assert_eq!(r.tls.callbacks.len(), 1);
    }

    // ── ManifestXml ───────────────────────────────────────────────────────────

    #[test]
    fn test_manifest_requires_admin_true() {
        let m = ManifestXml::from_xml(
            "<assembly><requestedExecutionLevel level=\"requireAdministrator\"/></assembly>",
        );
        assert!(m.requires_admin());
    }

    #[test]
    fn test_manifest_requires_admin_false() {
        let m = ManifestXml::from_xml(
            "<assembly><requestedExecutionLevel level=\"asInvoker\"/></assembly>",
        );
        assert!(!m.requires_admin());
    }

    #[test]
    fn test_manifest_dpi_aware() {
        let m =
            ManifestXml::from_xml("<assembly><dpiAwareness>PerMonitorV2</dpiAwareness></assembly>");
        assert!(m.dpi_aware);
    }

    // ── AuthentiCode ──────────────────────────────────────────────────────────

    #[test]
    fn test_authenticode_not_signed() {
        let r = PeAnalysisReport::mock();
        assert!(!r.authenticode.is_signed);
    }

    #[test]
    fn test_authenticode_no_timestamp() {
        let r = PeAnalysisReport::mock();
        assert!(!r.authenticode.has_timestamp());
    }

    // ── PeAnalyzer ────────────────────────────────────────────────────────────

    #[test]
    fn test_is_pe_valid() {
        let mut data = vec![0u8; 256];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert!(PeAnalyzer::is_pe(&data));
    }

    #[test]
    fn test_is_pe_not_mz() {
        assert!(!PeAnalyzer::is_pe(b"ELF"));
    }

    #[test]
    fn test_classify_api() {
        assert_eq!(PeAnalyzer::classify_api("VirtualAllocEx"), ApiGroup::Memory);
    }

    // ── PeAnalysisReport ──────────────────────────────────────────────────────

    #[test]
    fn test_report_mock_machine() {
        let r = PeAnalysisReport::mock();
        assert_eq!(r.machine, "x86_64");
    }

    #[test]
    fn test_report_mock_has_anti_debug() {
        let r = PeAnalysisReport::mock();
        assert!(r.has_anti_debug());
    }

    #[test]
    fn test_report_mock_has_injection() {
        let r = PeAnalysisReport::mock();
        assert!(r.has_injection_pattern());
    }

    #[test]
    fn test_report_mock_overall_threat_positive() {
        let r = PeAnalysisReport::mock();
        assert!(r.overall_threat > 0.0);
    }

    #[test]
    fn test_report_mock_not_signed() {
        let r = PeAnalysisReport::mock();
        assert!(!r.authenticode.is_signed);
    }

    #[test]
    fn test_report_display() {
        let r = PeAnalysisReport::mock();
        let s = format!("{r}");
        assert!(s.contains("PE"));
    }

    #[test]
    fn test_report_serialization() {
        let r = PeAnalysisReport::mock();
        let json = serde_json::to_string(&r).unwrap();
        let back: PeAnalysisReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.machine, r.machine);
    }
    #[test]
    fn test_api_group_file_io() {
        assert_eq!(ApiGroup::from_name("CreateFileA"), ApiGroup::FileIo);
    }
    #[test]
    fn test_api_group_thread() {
        assert_eq!(ApiGroup::from_name("CreateThread"), ApiGroup::Thread);
    }
    #[test]
    fn test_api_group_crypto() {
        assert_eq!(ApiGroup::from_name("CryptEncrypt"), ApiGroup::Crypto);
    }
    #[test]
    fn test_import_analysis_empty() {
        let ia = ImportAnalysis::from_imports(&[]);
        assert_eq!(ia.total_imports, 0);
        assert_eq!(ia.risk_score, 0.0);
    }
    #[test]
    fn test_export_analysis_no_exports() {
        let r = PeAnalysisReport::mock();
        assert!(!r.exports.has_exports());
    }
    #[test]
    fn test_export_analysis_no_forwards() {
        let r = PeAnalysisReport::mock();
        assert!(!r.exports.has_forwards());
    }
    #[test]
    fn test_debug_info_pdb_path_ends_with_pdb() {
        let r = PeAnalysisReport::mock();
        assert!(std::path::Path::new(r.debug_info.pdb_path.as_deref().unwrap()).extension().is_some_and(|e| e.eq_ignore_ascii_case("pdb")));
    }
    #[test]
    fn test_version_info_mock_product() {
        let v = VersionInfo::mock();
        assert_eq!(v.product_name, "ExampleApp");
    }
    #[test]
    fn test_tls_data_start() {
        let r = PeAnalysisReport::mock();
        assert_ne!(r.tls.data_start, 0);
    }
    #[test]
    fn test_manifest_execution_level() {
        let r = PeAnalysisReport::mock();
        let m = r.manifest.as_ref().unwrap();
        assert!(m.requested_execution_level.is_some());
    }
}
