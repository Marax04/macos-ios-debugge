//! `import_analysis` — Deep PE import table analysis.
//!
//! Provides `ImportAnalyzer`, `ImportEntry`, `ImportCategory`,
//! `ImportProfile`, `ImportsTimeline`, `ApiCallGraph`.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors from import analysis.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ImportError {
    #[error("no imports found")]
    NoImports,
    #[error("DLL not found: '{0}'")]
    DllNotFound(String),
    #[error("function not found: '{0}!{1}'")]
    FunctionNotFound(String, String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("invalid import table")]
    InvalidTable,
}

// ─── ImportCategory ───────────────────────────────────────────────────────────

/// Semantic category of a Windows API import.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ImportCategory {
    Crypto,
    Network,
    Process,
    Thread,
    File,
    Registry,
    Memory,
    Debug,
    AntiAnalysis,
    UI,
    Service,
    Driver,
    COM,
    Sync,
    Token,
    Persistence,
    Injection,
    InfoGathering,
    Print,
    Unknown,
}

impl ImportCategory {
    /// Return a human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Crypto => "Cryptography",
            Self::Network => "Networking",
            Self::Process => "Process Management",
            Self::Thread => "Thread Management",
            Self::File => "File I/O",
            Self::Registry => "Registry",
            Self::Memory => "Memory Management",
            Self::Debug => "Debugging",
            Self::AntiAnalysis => "Anti-Analysis",
            Self::UI => "User Interface",
            Self::Service => "Services",
            Self::Driver => "Drivers",
            Self::COM => "COM/OLE",
            Self::Sync => "Synchronization",
            Self::Token => "Security Tokens",
            Self::Persistence => "Persistence",
            Self::Injection => "Code Injection",
            Self::InfoGathering => "Information Gathering",
            Self::Print => "Printing",
            Self::Unknown => "Unknown",
        }
    }

    /// Threat weight for this category (0 = benign, 10 = very suspicious).
    #[must_use]
    pub const fn threat_weight(self) -> u8 {
        match self {
            Self::Injection => 10,
            Self::AntiAnalysis => 9,
            Self::Crypto | Self::Driver => 7,
            Self::Token | Self::Persistence => 6,
            Self::Debug => 5,
            Self::Process | Self::Thread => 4,
            Self::Network | Self::Registry | Self::Memory | Self::InfoGathering => 3,
            Self::Service | Self::COM => 2,
            Self::File | Self::Sync => 1,
            Self::UI | Self::Print | Self::Unknown => 0,
        }
    }
}

impl fmt::Display for ImportCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ─── ImportEntry ──────────────────────────────────────────────────────────────

/// A single imported function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    /// DLL name (normalised to lowercase).
    pub dll: String,
    /// Function name (may be empty for ordinal-only imports).
    pub function: String,
    /// Import ordinal (0 if named import).
    pub ordinal: u16,
    /// IAT virtual address.
    pub address: u64,
    /// Resolved category.
    pub category: ImportCategory,
    /// Risk score 0–100 for this specific import.
    pub risk_score: u8,
    /// Short description.
    pub description: String,
}

impl ImportEntry {
    /// Create a new import entry.
    #[must_use]
    pub fn new(
        dll: impl Into<String>,
        function: impl Into<String>,
        ordinal: u16,
        address: u64,
    ) -> Self {
        let dll_s: String = dll.into();
        let func_s: String = function.into();
        let (category, risk, desc) = categorize_import(&dll_s, &func_s);
        Self {
            dll: dll_s.to_ascii_lowercase(),
            function: func_s,
            ordinal, address, category, risk_score: risk,
            description: desc.to_string(),
        }
    }

    /// Return `true` if this is an ordinal-only import.
    #[must_use]
    pub const fn is_ordinal(&self) -> bool { self.function.is_empty() }

    /// Return a display name `"dll.dll!FunctionName"`.
    #[must_use]
    pub fn qualified_name(&self) -> String {
        if self.is_ordinal() {
            format!("{}!ord#{}", self.dll, self.ordinal)
        } else {
            format!("{}!{}", self.dll, self.function)
        }
    }

    /// Return `true` if this import is considered high-risk.
    #[must_use]
    pub const fn is_high_risk(&self) -> bool { self.risk_score >= 70 }
}

impl fmt::Display for ImportEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}] risk={}", self.qualified_name(), self.category, self.risk_score)
    }
}

// ─── ImportProfile ────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Detected capability flags for a PE import profile.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
    pub struct ImportCapabilities: u8 {
        /// Code injection capability (VirtualAlloc, WriteProcessMemory, etc.).
        const INJECTION     = 1 << 0;
        /// Network access capability (connect, send, recv, etc.).
        const NETWORK       = 1 << 1;
        /// Anti-analysis techniques (IsDebuggerPresent, etc.).
        const ANTI_ANALYSIS = 1 << 2;
        /// Cryptographic operations (CryptEncrypt, etc.).
        const CRYPTO        = 1 << 3;
        /// Registry access (RegOpenKey, etc.).
        const REGISTRY      = 1 << 4;
    }
}

/// Categorised import profile for a PE file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportProfile {
    /// All imported functions.
    pub imports: Vec<ImportEntry>,
    /// Imports grouped by category.
    pub by_category: HashMap<String, Vec<String>>,
    /// Overall risk score 0–100.
    pub risk_score: u8,
    /// Number of unique DLLs.
    pub dll_count: usize,
    /// Detected capability flags (injection, network, anti-analysis, crypto, registry).
    pub capabilities: ImportCapabilities,
    /// Notable imports (high-risk).
    pub notable: Vec<String>,
}

impl ImportProfile {
    /// Whether the binary likely has code injection capability.
    #[must_use]
    pub const fn has_injection(&self) -> bool {
        self.capabilities.contains(ImportCapabilities::INJECTION)
    }
    /// Whether the binary has network capability.
    #[must_use]
    pub const fn has_network(&self) -> bool {
        self.capabilities.contains(ImportCapabilities::NETWORK)
    }
    /// Whether the binary has anti-analysis techniques.
    #[must_use]
    pub const fn has_anti_analysis(&self) -> bool {
        self.capabilities.contains(ImportCapabilities::ANTI_ANALYSIS)
    }
    /// Whether the binary has cryptographic operations.
    #[must_use]
    pub const fn has_crypto(&self) -> bool {
        self.capabilities.contains(ImportCapabilities::CRYPTO)
    }
    /// Whether the binary accesses the registry.
    #[must_use]
    pub const fn has_registry(&self) -> bool {
        self.capabilities.contains(ImportCapabilities::REGISTRY)
    }
}

impl ImportProfile {
    /// Build a profile from a list of import entries.
    #[must_use]
    pub fn from_entries(imports: Vec<ImportEntry>) -> Self {
        let mut by_category: HashMap<String, Vec<String>> = HashMap::new();
        let mut notable = Vec::new();

        for entry in &imports {
            by_category
                .entry(entry.category.to_string())
                .or_default()
                .push(entry.qualified_name());
            if entry.is_high_risk() {
                notable.push(entry.qualified_name());
            }
        }

        let dll_count = {
            let mut dlls = std::collections::HashSet::new();
            for e in &imports { dlls.insert(&e.dll); }
            dlls.len()
        };

        let mut capabilities = ImportCapabilities::empty();
        if imports.iter().any(|e| e.category == ImportCategory::Injection) {
            capabilities |= ImportCapabilities::INJECTION;
        }
        if imports.iter().any(|e| e.category == ImportCategory::Network) {
            capabilities |= ImportCapabilities::NETWORK;
        }
        if imports.iter().any(|e| e.category == ImportCategory::AntiAnalysis) {
            capabilities |= ImportCapabilities::ANTI_ANALYSIS;
        }
        if imports.iter().any(|e| e.category == ImportCategory::Crypto) {
            capabilities |= ImportCapabilities::CRYPTO;
        }
        if imports.iter().any(|e| e.category == ImportCategory::Registry) {
            capabilities |= ImportCapabilities::REGISTRY;
        }

        // Aggregate risk score
        let risk_score = if imports.is_empty() { 0 } else {
            let total: u32 = imports.iter().map(|e| u32::from(e.risk_score)).sum();
            let avg = total / u32::try_from(imports.len()).unwrap_or(u32::MAX);
            let max = imports.iter().map(|e| u32::from(e.risk_score)).max().unwrap_or(0);
            ((avg * 2 + max) / 3).min(100) as u8
        };

        Self {
            imports, by_category, risk_score, dll_count, capabilities, notable,
        }
    }

    /// Return `true` if this profile indicates malicious intent.
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        self.risk_score >= 60
            || self.capabilities.contains(ImportCapabilities::INJECTION)
            || self.capabilities.contains(ImportCapabilities::ANTI_ANALYSIS)
    }

    /// Total number of imports.
    #[must_use]
    pub const fn import_count(&self) -> usize { self.imports.len() }

    /// Imports for a specific DLL.
    #[must_use]
    pub fn imports_from(&self, dll: &str) -> Vec<&ImportEntry> {
        let lower = dll.to_ascii_lowercase();
        self.imports.iter().filter(|e| e.dll == lower).collect()
    }

    /// Imports in a specific category.
    #[must_use]
    pub fn imports_in_category(&self, cat: ImportCategory) -> Vec<&ImportEntry> {
        self.imports.iter().filter(|e| e.category == cat).collect()
    }
}

// ─── ImportsTimeline ─────────────────────────────────────────────────────────

/// Suspicious API call sequences / patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportsTimeline {
    /// Detected API sequences (`pattern_name`, [`api_calls`]).
    pub sequences: Vec<ApiSequence>,
}

/// A named API call sequence pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSequence {
    pub name: String,
    pub description: String,
    pub apis: Vec<String>,
    pub severity: u8,
}

impl ImportsTimeline {
    /// Build from a profile by searching for known patterns.
    #[must_use]
    pub fn detect(profile: &ImportProfile) -> Self {
        let api_names: std::collections::HashSet<String> = profile
            .imports.iter()
            .map(|e| e.function.to_ascii_lowercase())
            .collect();

        let mut sequences = Vec::new();

        // Pattern: Classic remote thread injection
        let injection_apis = &["virtualallocex", "writeprocessmemory", "createremotethread"];
        if injection_apis.iter().all(|a| api_names.contains(*a)) {
            sequences.push(ApiSequence {
                name: "Remote Thread Injection".into(),
                description: "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread injection chain".into(),
                apis: injection_apis.iter().map(|s| (*s).to_string()).collect(),
                severity: 95,
            });
        }

        // Pattern: Process hollowing
        let hollow_apis = &["createprocessa", "zwunmapviewofsection", "virtualallocex"];
        if hollow_apis.iter().all(|a| api_names.contains(*a)) {
            sequences.push(ApiSequence {
                name: "Process Hollowing".into(),
                description: "Process hollowing / RunPE technique".into(),
                apis: hollow_apis.iter().map(|s| (*s).to_string()).collect(),
                severity: 90,
            });
        }

        // Pattern: Download and execute
        let download_apis = &["internetopenurla", "internetreadfile", "createfilea"];
        if download_apis.iter().all(|a| api_names.contains(*a)) {
            sequences.push(ApiSequence {
                name: "Download and Execute".into(),
                description: "Downloads a file over HTTP and executes it".into(),
                apis: download_apis.iter().map(|s| (*s).to_string()).collect(),
                severity: 80,
            });
        }

        // Pattern: Credential dump
        let cred_apis = &["openprocess", "readprocessmemory"];
        if cred_apis.iter().all(|a| api_names.contains(*a)) && api_names.contains("adjusttokenprivileges") {
            sequences.push(ApiSequence {
                name: "Credential Harvesting".into(),
                description: "Opens processes and reads their memory for credential extraction".into(),
                apis: vec!["OpenProcess".into(), "ReadProcessMemory".into(), "AdjustTokenPrivileges".into()],
                severity: 85,
            });
        }

        // Pattern: Registry persistence
        let reg_persist_apis = &["regcreatekeya", "regsetvalueexa"];
        if reg_persist_apis.iter().all(|a| api_names.contains(*a)) {
            sequences.push(ApiSequence {
                name: "Registry Persistence".into(),
                description: "Writes to registry for persistence".into(),
                apis: reg_persist_apis.iter().map(|s| (*s).to_string()).collect(),
                severity: 70,
            });
        }

        // Pattern: Anti-debug
        let anti_debug = &["isdebuggerpresent", "checkremotedebuggerpresent"];
        if anti_debug.iter().any(|a| api_names.contains(*a)) {
            let found: Vec<String> = anti_debug.iter().filter(|a| api_names.contains(**a)).map(|s| (*s).to_string()).collect();
            sequences.push(ApiSequence {
                name: "Anti-Debug".into(),
                description: "Checks for debugger presence".into(),
                apis: found,
                severity: 60,
            });
        }

        Self { sequences }
    }

    /// Return sequences above a severity threshold.
    #[must_use]
    pub fn above_severity(&self, threshold: u8) -> Vec<&ApiSequence> {
        self.sequences.iter().filter(|s| s.severity >= threshold).collect()
    }

    /// Return `true` if any sequences were detected.
    #[must_use]
    pub const fn has_sequences(&self) -> bool { !self.sequences.is_empty() }
}

// ─── ApiCallGraph ─────────────────────────────────────────────────────────────

/// A simplified API call graph: nodes are DLLs, edges are inter-DLL calls.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiCallGraph {
    /// For each DLL: the APIs it exports that are used.
    pub dll_nodes: HashMap<String, Vec<String>>,
    /// Edges: (`caller_dll`, `callee_dll`, count).
    pub edges: Vec<(String, String, usize)>,
}

impl ApiCallGraph {
    /// Build from an import profile.
    #[must_use]
    pub fn build(profile: &ImportProfile) -> Self {
        let mut dll_nodes: HashMap<String, Vec<String>> = HashMap::new();
        for entry in &profile.imports {
            dll_nodes
                .entry(entry.dll.clone())
                .or_default()
                .push(entry.function.clone());
        }
        // Edges: pairs of DLLs that share at least one import category.
        // The edge weight is the number of import categories that both DLLs
        // contribute to, which is a meaningful coupling metric.
        let mut edges = Vec::new();
        let dlls: Vec<String> = dll_nodes.keys().cloned().collect();
        for i in 0..dlls.len() {
            for j in (i + 1)..dlls.len() {
                let cats_i: std::collections::HashSet<_> = profile
                    .imports_from(&dlls[i])
                    .iter()
                    .map(|imp| imp.category)
                    .collect();
                let cats_j: std::collections::HashSet<_> = profile
                    .imports_from(&dlls[j])
                    .iter()
                    .map(|imp| imp.category)
                    .collect();
                let shared = cats_i.intersection(&cats_j).count();
                if shared > 0 {
                    edges.push((dlls[i].clone(), dlls[j].clone(), shared));
                }
            }
        }
        Self { dll_nodes, edges }
    }

    /// Number of DLL nodes.
    #[must_use]
    pub fn node_count(&self) -> usize { self.dll_nodes.len() }

    /// Number of edges.
    #[must_use]
    pub const fn edge_count(&self) -> usize { self.edges.len() }

    /// Return the most-used DLL.
    #[must_use]
    pub fn most_used_dll(&self) -> Option<&str> {
        self.dll_nodes.iter()
            .max_by_key(|(_, fns)| fns.len())
            .map(|(dll, _)| dll.as_str())
    }
}

// ─── ImportAnalyzer ───────────────────────────────────────────────────────────

/// Deep PE import table analyser.
pub struct ImportAnalyzer {
    entries: Vec<ImportEntry>,
}

impl ImportAnalyzer {
    /// Create a new analyser.
    #[must_use]
    pub const fn new() -> Self { Self { entries: vec![] } }

    /// Add an import entry.
    pub fn add(&mut self, entry: ImportEntry) { self.entries.push(entry); }

    /// Add from raw (dll, function, ordinal, address) tuples.
    pub fn add_raw(&mut self, items: impl IntoIterator<Item = (String, String, u16, u64)>) {
        for (dll, func, ord, addr) in items {
            self.entries.push(ImportEntry::new(dll, func, ord, addr));
        }
    }

    /// Build a profile from the current entries.
    #[must_use]
    pub fn build_profile(&self) -> ImportProfile {
        ImportProfile::from_entries(self.entries.clone())
    }

    /// Detect API sequence patterns.
    #[must_use]
    pub fn detect_sequences(&self) -> ImportsTimeline {
        ImportsTimeline::detect(&self.build_profile())
    }

    /// Build an API call graph.
    #[must_use]
    pub fn build_call_graph(&self) -> ApiCallGraph {
        ApiCallGraph::build(&self.build_profile())
    }

    /// Return entries matching a predicate.
    #[must_use]
    pub fn filter<F: Fn(&ImportEntry) -> bool>(&self, f: F) -> Vec<&ImportEntry> {
        self.entries.iter().filter(|e| f(e)).collect()
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize { self.entries.len() }

    /// Return `true` if no imports have been added.
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.entries.is_empty() }

    /// Return a reference to all entries.
    #[must_use]
    pub fn entries(&self) -> &[ImportEntry] { &self.entries }

    /// Find all imports containing a substring (case-insensitive).
    #[must_use]
    pub fn find(&self, query: &str) -> Vec<&ImportEntry> {
        let lower = query.to_ascii_lowercase();
        self.entries.iter().filter(|e|
            e.function.to_ascii_lowercase().contains(&lower)
            || e.dll.contains(&lower)
        ).collect()
    }
}

impl Default for ImportAnalyzer {
    fn default() -> Self { Self::new() }
}

// ─── Categorization logic ─────────────────────────────────────────────────────

/// Returns `(category, risk_score, description)` for a DLL + function pair.
fn categorize_import(dll: &str, func: &str) -> (ImportCategory, u8, &'static str) {
    let d = dll.to_ascii_lowercase();
    let f = func.to_ascii_lowercase();

    // Injection APIs
    let injection: &[&str] = &[
        "virtualallocex", "writeprocessmemory", "createremotethread",
        "ntwritevirtualmemory", "ntcreatethreadex", "ntmapviewofsection",
        "queueuserapc", "zwmapviewofsection",
    ];
    if injection.iter().any(|&a| f.contains(a)) {
        return (ImportCategory::Injection, 90, "Code injection API");
    }

    // Anti-analysis
    let anti: &[&str] = &[
        "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
        "ntsetinformationthread", "outputdebugstring",
    ];
    if anti.iter().any(|&a| f.contains(a)) {
        return (ImportCategory::AntiAnalysis, 80, "Anti-debug/analysis API");
    }

    // Crypto
    if d.contains("crypt") || d.contains("bcrypt") || d.contains("ncrypt") {
        return (ImportCategory::Crypto, 70, "Cryptographic API");
    }
    let crypto_funcs: &[&str] = &["cryptencrypt", "cryptdecrypt", "cryptgenkey", "bcryptencrypt", "bcryptdecrypt"];
    if crypto_funcs.iter().any(|&a| f.contains(a)) {
        return (ImportCategory::Crypto, 70, "Cryptographic API");
    }

    // Network
    if d.contains("wininet") || d.contains("winhttp") || d.contains("ws2_32") || d.contains("wsock") {
        return (ImportCategory::Network, 50, "Networking API");
    }
    let net_funcs: &[&str] = &["connect", "send", "recv", "socket", "wsastartup", "internetopen", "httpsendrequest"];
    if net_funcs.iter().any(|&a| f.contains(a)) {
        return (ImportCategory::Network, 50, "Networking API");
    }

    // Registry
    if d.contains("advapi32") {
        let reg_funcs: &[&str] = &["regopen", "regcreate", "regset", "regquery", "regdelete"];
        if reg_funcs.iter().any(|&a| f.contains(a)) {
            return (ImportCategory::Registry, 40, "Registry API");
        }
    }

    // Token / privilege
    let token_funcs: &[&str] = &["openprocesstoken", "adjusttokenprivileges", "duplicatetokenex", "impersonateloggedonuser"];
    if token_funcs.iter().any(|&a| f.contains(a)) {
        return (ImportCategory::Token, 70, "Token/privilege API");
    }

    // Process
    let proc_funcs: &[&str] = &["createprocess", "openprocess", "terminateprocess", "readprocessmemory"];
    if proc_funcs.iter().any(|&a| f.contains(a)) {
        return (ImportCategory::Process, 50, "Process management API");
    }

    // Thread
    let thread_funcs: &[&str] = &["createthread", "suspendthread", "resumethread", "terminatethread"];
    if thread_funcs.iter().any(|&a| f.contains(a)) {
        return (ImportCategory::Thread, 30, "Thread management API");
    }

    // Memory
    let mem_funcs: &[&str] = &["virtualalloc", "virtualfree", "virtualprotect", "heapalloc"];
    if mem_funcs.iter().any(|&a| f.contains(a)) {
        return (ImportCategory::Memory, 30, "Memory management API");
    }

    // Service
    let svc_funcs: &[&str] = &["openscmanager", "createservice", "startservice", "controlservice"];
    if svc_funcs.iter().any(|&a| f.contains(a)) {
        return (ImportCategory::Service, 50, "Service management API");
    }

    // Driver
    let drv_funcs: &[&str] = &["ntloaddriver", "ntunloaddriver", "deviceiocontrol"];
    if drv_funcs.iter().any(|&a| f.contains(a)) {
        return (ImportCategory::Driver, 60, "Driver API");
    }

    // File I/O
    let file_funcs: &[&str] = &["createfile", "readfile", "writefile", "deletefile", "movefile"];
    if file_funcs.iter().any(|&a| f.contains(a)) {
        return (ImportCategory::File, 10, "File I/O API");
    }

    // Debug
    let debug_funcs: &[&str] = &["debugactiveprocess", "waitfordebugevent", "continuedebugevent"];
    if debug_funcs.iter().any(|&a| f.contains(a)) {
        return (ImportCategory::Debug, 40, "Debugging API");
    }

    // Persistence
    let persist_funcs: &[&str] = &["installservice", "registerappid", "regsetvalue"];
    if persist_funcs.iter().any(|&a| f.contains(a)) {
        return (ImportCategory::Persistence, 55, "Persistence API");
    }

    // Information gathering
    let info_funcs: &[&str] = &["getsysteminfo", "getcomputername", "getusername", "getadaptersinfo"];
    if info_funcs.iter().any(|&a| f.contains(a)) {
        return (ImportCategory::InfoGathering, 20, "System information API");
    }

    // COM
    if d.contains("ole32") || d.contains("oleaut32") {
        return (ImportCategory::COM, 15, "COM/OLE API");
    }
    let com_funcs: &[&str] = &["coinitialize", "cocreateinstance", "cogetclassobject"];
    if com_funcs.iter().any(|&a| f.contains(a)) {
        return (ImportCategory::COM, 15, "COM API");
    }

    // UI
    if d.contains("user32") || d.contains("gdi32") {
        return (ImportCategory::UI, 0, "UI API");
    }

    (ImportCategory::Unknown, 0, "Unknown API")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(dll: &str, func: &str) -> ImportEntry {
        ImportEntry::new(dll, func, 0, 0)
    }

    fn analyzer_with_samples() -> ImportAnalyzer {
        let mut a = ImportAnalyzer::new();
        a.add(make_entry("kernel32.dll", "CreateProcessA"));
        a.add(make_entry("kernel32.dll", "VirtualAllocEx"));
        a.add(make_entry("kernel32.dll", "WriteProcessMemory"));
        a.add(make_entry("kernel32.dll", "CreateRemoteThread"));
        a.add(make_entry("ws2_32.dll", "connect"));
        a.add(make_entry("ws2_32.dll", "send"));
        a.add(make_entry("advapi32.dll", "RegSetValueExA"));
        a.add(make_entry("kernel32.dll", "IsDebuggerPresent"));
        a.add(make_entry("advapi32.dll", "CryptEncrypt"));
        a.add(make_entry("kernel32.dll", "CreateFileA"));
        a
    }

    // ── ImportCategory ────────────────────────────────────────────────────────

    #[test]
    fn test_category_names_unique() {
        use std::collections::HashSet;
        let cats = [
            ImportCategory::Crypto, ImportCategory::Network, ImportCategory::Process,
            ImportCategory::Thread, ImportCategory::File, ImportCategory::Registry,
            ImportCategory::Memory, ImportCategory::Debug, ImportCategory::AntiAnalysis,
            ImportCategory::UI,
        ];
        let names: HashSet<&str> = cats.iter().map(|c| c.name()).collect();
        assert_eq!(names.len(), cats.len());
    }

    #[test]
    fn test_injection_weight() {
        assert!(ImportCategory::Injection.threat_weight() >= 8);
    }

    #[test]
    fn test_ui_weight_zero() {
        assert_eq!(ImportCategory::UI.threat_weight(), 0);
    }

    #[test]
    fn test_category_display() {
        assert!(ImportCategory::Crypto.to_string().contains("Crypto"));
    }

    // ── ImportEntry ───────────────────────────────────────────────────────────

    #[test]
    fn test_entry_injection_category() {
        let e = make_entry("kernel32.dll", "VirtualAllocEx");
        assert_eq!(e.category, ImportCategory::Injection);
        assert!(e.is_high_risk());
    }

    #[test]
    fn test_entry_crypto_category() {
        let e = make_entry("advapi32.dll", "CryptEncrypt");
        assert_eq!(e.category, ImportCategory::Crypto);
    }

    #[test]
    fn test_entry_network_category() {
        let e = make_entry("ws2_32.dll", "connect");
        assert_eq!(e.category, ImportCategory::Network);
    }

    #[test]
    fn test_entry_file_category() {
        let e = make_entry("kernel32.dll", "CreateFileA");
        assert_eq!(e.category, ImportCategory::File);
    }

    #[test]
    fn test_entry_ordinal_import() {
        let e = ImportEntry::new("kernel32.dll", "", 100, 0x1000);
        assert!(e.is_ordinal());
        assert!(e.qualified_name().contains("ord#100"));
    }

    #[test]
    fn test_entry_qualified_name() {
        let e = make_entry("kernel32.dll", "CreateFileA");
        assert!(e.qualified_name().contains("kernel32.dll"));
        assert!(e.qualified_name().contains("CreateFileA"));
    }

    #[test]
    fn test_entry_display() {
        let e = make_entry("ws2_32.dll", "connect");
        assert!(e.to_string().contains("connect"));
    }

    // ── ImportProfile ─────────────────────────────────────────────────────────

    #[test]
    fn test_profile_has_injection() {
        let a = analyzer_with_samples();
        let p = a.build_profile();
        assert!(p.has_injection());
    }

    #[test]
    fn test_profile_has_network() {
        let a = analyzer_with_samples();
        let p = a.build_profile();
        assert!(p.has_network());
    }

    #[test]
    fn test_profile_has_anti_analysis() {
        let a = analyzer_with_samples();
        let p = a.build_profile();
        assert!(p.has_anti_analysis());
    }

    #[test]
    fn test_profile_dll_count() {
        let a = analyzer_with_samples();
        let p = a.build_profile();
        assert_eq!(p.dll_count, 3); // kernel32, ws2_32, advapi32
    }

    #[test]
    fn test_profile_risk_score_high() {
        let a = analyzer_with_samples();
        let p = a.build_profile();
        assert!(p.risk_score > 0);
    }

    #[test]
    fn test_profile_imports_from() {
        let a = analyzer_with_samples();
        let p = a.build_profile();
        let ws2 = p.imports_from("ws2_32.dll");
        assert_eq!(ws2.len(), 2);
    }

    #[test]
    fn test_profile_imports_in_category() {
        let a = analyzer_with_samples();
        let p = a.build_profile();
        let net = p.imports_in_category(ImportCategory::Network);
        assert!(!net.is_empty());
    }

    #[test]
    fn test_profile_notable_imports() {
        let a = analyzer_with_samples();
        let p = a.build_profile();
        assert!(!p.notable.is_empty());
    }

    #[test]
    fn test_profile_is_suspicious() {
        let a = analyzer_with_samples();
        let p = a.build_profile();
        assert!(p.is_suspicious());
    }

    #[test]
    fn test_profile_empty() {
        let p = ImportProfile::from_entries(vec![]);
        assert_eq!(p.risk_score, 0);
        assert_eq!(p.import_count(), 0);
        assert!(!p.is_suspicious());
    }

    // ── ImportsTimeline ───────────────────────────────────────────────────────

    #[test]
    fn test_timeline_detects_injection() {
        let a = analyzer_with_samples();
        let profile = a.build_profile();
        let timeline = ImportsTimeline::detect(&profile);
        assert!(timeline.has_sequences());
        let high = timeline.above_severity(80);
        assert!(!high.is_empty(), "Expected injection pattern");
    }

    #[test]
    fn test_timeline_empty_no_sequences() {
        let p = ImportProfile::from_entries(vec![]);
        let t = ImportsTimeline::detect(&p);
        assert!(!t.has_sequences());
    }

    #[test]
    fn test_timeline_anti_debug() {
        let mut a = ImportAnalyzer::new();
        a.add(make_entry("kernel32.dll", "IsDebuggerPresent"));
        let profile = a.build_profile();
        let timeline = ImportsTimeline::detect(&profile);
        assert!(timeline.sequences.iter().any(|s| s.name.contains("Anti-Debug")));
    }

    // ── ApiCallGraph ──────────────────────────────────────────────────────────

    #[test]
    fn test_call_graph_node_count() {
        let a = analyzer_with_samples();
        let profile = a.build_profile();
        let g = ApiCallGraph::build(&profile);
        assert_eq!(g.node_count(), 3);
    }

    #[test]
    fn test_call_graph_most_used_dll() {
        let a = analyzer_with_samples();
        let profile = a.build_profile();
        let g = ApiCallGraph::build(&profile);
        let most = g.most_used_dll().unwrap();
        assert_eq!(most, "kernel32.dll");
    }

    // ── ImportAnalyzer ────────────────────────────────────────────────────────

    #[test]
    fn test_analyzer_len() {
        let a = analyzer_with_samples();
        assert_eq!(a.len(), 10);
        assert!(!a.is_empty());
    }

    #[test]
    fn test_analyzer_find() {
        let a = analyzer_with_samples();
        let hits = a.find("VirtualAlloc");
        assert!(!hits.is_empty());
    }

    #[test]
    fn test_analyzer_filter() {
        let a = analyzer_with_samples();
        let high_risk = a.filter(super::ImportEntry::is_high_risk);
        assert!(!high_risk.is_empty());
    }

    #[test]
    fn test_analyzer_add_raw() {
        let mut a = ImportAnalyzer::new();
        a.add_raw(vec![
            ("ws2_32.dll".into(), "socket".into(), 0, 0x1000),
            ("ws2_32.dll".into(), "connect".into(), 0, 0x1004),
        ]);
        assert_eq!(a.len(), 2);
    }

    #[test]
    fn test_analyzer_entries() {
        let a = analyzer_with_samples();
        assert_eq!(a.entries().len(), 10);
    }
}
