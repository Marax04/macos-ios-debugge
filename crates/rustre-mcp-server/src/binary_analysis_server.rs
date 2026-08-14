//! `binary_analysis_server` —  MCP server for binary analysis operations.
//!
//! Provides [`BinaryAnalysisServer`] and its request/response types:
//! [`AnalyzeRequest`], [`DecompileRequest`], [`YaraRequest`], [`DiffRequest`],
//! [`SearchRequest`], and [`MitreRequest`].

use std::collections::HashMap;
pub use std::path::PathBuf;
pub use std::sync::Arc;

pub use async_trait::async_trait;
pub use parking_lot::Mutex;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use crate::ToolResult;
use crate::{McpError, ToolDefinition};

// â"€â"€â"€ Error â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Errors produced by the binary analysis server.
#[derive(Debug, Error, Clone)]
pub enum BinaryAnalysisError {
    #[error("binary not found: {0}")]
    BinaryNotFound(String),

    #[error("unsupported architecture: {0}")]
    UnsupportedArch(String),

    #[error("decompilation failed at 0x{0:x}: {1}")]
    DecompileFailed(u64, String),

    #[error("YARA error: {0}")]
    YaraError(String),

    #[error("diff failed: {0}")]
    DiffFailed(String),

    #[error("search failed: {0}")]
    SearchFailed(String),

    #[error("MITRE lookup failed: {0}")]
    MitreFailed(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("server not initialised")]
    NotInitialised,
}

impl From<BinaryAnalysisError> for McpError {
    fn from(e: BinaryAnalysisError) -> Self {
        Self::InternalError(e.to_string())
    }
}

// â"€â"€â"€ AnalyzeRequest â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Request to perform full binary analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzeRequest {
    pub binary_path: String,
    pub architecture: String,
    pub os: String,
    pub analysis_level: AnalysisLevel,
    pub run_yara: bool,
    pub build_cfg: bool,
    pub timeout_ms: u64,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Depth of analysis to perform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalysisLevel {
    Quick,
    Standard,
    Deep,
    Exhaustive,
}

impl std::fmt::Display for AnalysisLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Default for AnalyzeRequest {
    fn default() -> Self {
        Self {
            binary_path: String::new(),
            architecture: "x86_64".to_string(),
            os: "linux".to_string(),
            analysis_level: AnalysisLevel::Standard,
            run_yara: true,
            build_cfg: false,
            timeout_ms: 60_000,
            metadata: HashMap::new(),
        }
    }
}

impl AnalyzeRequest {
    #[must_use]
    pub fn new(binary_path: impl Into<String>) -> Self {
        Self {
            binary_path: binary_path.into(),
            ..Default::default()
        }
    }

    #[must_use]
    pub fn with_arch(mut self, arch: impl Into<String>) -> Self {
        self.architecture = arch.into();
        self
    }

    #[must_use]
    pub const fn with_level(mut self, level: AnalysisLevel) -> Self {
        self.analysis_level = level;
        self
    }
}

/// Response to an analysis request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzeResponse {
    pub binary_path: String,
    pub architecture: String,
    pub file_type: String,
    pub entry_point: u64,
    pub function_count: u32,
    pub import_count: u32,
    pub export_count: u32,
    pub string_count: u32,
    pub entropy: f64,
    pub yara_matches: Vec<String>,
    pub summary: String,
    pub duration_ms: u64,
}

impl AnalyzeResponse {
    /// Analyse the binary named by `req` and report what was actually found.
    ///
    /// Every number here is computed from the file's bytes. Before 2026-07-29
    /// the only entry point was [`Self::stub`], which returned `ELF64`,
    /// `entry_point 0x401000`, `function_count 42`, `import_count 15`,
    /// `export_count 3`, `string_count 128` and `entropy 6.2` for **any**
    /// input — including a path that does not exist — under a summary saying
    /// "complete". None of that capability was missing: `rustre-loader-pe`,
    /// `rustre-triage-entropy`, `rustre-analysis-string` and
    /// `rustre-analysis-fn` were already dependencies of this crate and this
    /// module imported none of them.
    ///
    /// Where a value genuinely cannot be determined it is reported as zero and
    /// the reason is stated in `summary` — a count of zero here means "none
    /// found", never "not looked for".
    ///
    /// # Errors
    /// [`BinaryAnalysisError::InvalidRequest`] if the file cannot be read; an
    /// unreadable binary is an honest failure, not an analysis result.
    pub fn analyze(req: &AnalyzeRequest) -> Result<Self, BinaryAnalysisError> {
        let start = std::time::Instant::now();
        let data = std::fs::read(&req.binary_path).map_err(|e| {
            BinaryAnalysisError::InvalidRequest(format!(
                "cannot read '{}': {e}",
                req.binary_path
            ))
        })?;

        let entropy = rustre_triage_entropy::shannon_entropy(&data);

        let scanner = rustre_analysis_string::StringScanner::default();
        let string_count =
            u32::try_from(scanner.scan(rustre_core::Address::new(0), &data).len())
                .unwrap_or(u32::MAX);

        // PE metadata when the image parses; otherwise the magic tells us the
        // container and the PE-specific counts stay zero, which is true.
        let pe = rustre_loader_pe::PeInfo::parse(&data).ok();
        let (file_type, entry_point, import_count, export_count, note) = match &pe {
            Some(p) => (
                "PE".to_string(),
                p.entry_point,
                u32::try_from(p.imports.len()).unwrap_or(u32::MAX),
                u32::try_from(p.exports.len()).unwrap_or(u32::MAX),
                String::new(),
            ),
            None => {
                let (kind, why): (&str, &str) = if data.starts_with(b"\x7FELF") {
                    ("ELF", "ELF image: PE import/export tables do not apply")
                } else if data.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
                    || data.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
                {
                    ("Mach-O", "Mach-O image: PE import/export tables do not apply")
                } else if data.starts_with(b"MZ") {
                    ("PE (unparsed)", "MZ magic present but the PE headers did not parse")
                } else {
                    ("unknown", "no recognised container magic")
                };
                (kind.to_string(), 0, 0, 0, format!(" {why}."))
            }
        };

        // Function detection needs an architecture; an unrecognised one yields
        // no functions rather than a guess.
        let arch = match req.architecture.as_str() {
            "x86_64" | "amd64" | "x86-64" => rustre_analysis_fn::DetectedArch::X86_64,
            "x86" | "i386" | "i686" => rustre_analysis_fn::DetectedArch::X86_32,
            "arm64" | "aarch64" => rustre_analysis_fn::DetectedArch::Arm64,
            _ => rustre_analysis_fn::DetectedArch::Unknown,
        };
        let mem = rustre_analysis_fn::MemorySlice::new(rustre_core::Address::new(0), &data);
        let function_count =
            u32::try_from(rustre_analysis_fn::detect_functions(arch, &mem).functions.len())
                .unwrap_or(u32::MAX);

        let summary = format!(
            "Analysed '{}': {} bytes, {file_type}, {function_count} functions, \
             {string_count} strings, entropy {entropy:.2}.{note}",
            req.binary_path,
            data.len()
        );

        Ok(Self {
            binary_path: req.binary_path.clone(),
            architecture: req.architecture.clone(),
            file_type,
            entry_point,
            function_count,
            import_count,
            export_count,
            string_count,
            entropy,
            yara_matches: Vec::new(),
            summary,
            duration_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }

    /// A fixed placeholder response. **Not an analysis** — see [`Self::analyze`].
    ///
    /// Retained deliberately: it is useful for tests and for exercising the
    /// response shape without touching the filesystem. What changed on
    /// 2026-07-29 is that no handler presents its output as a result.
    #[must_use]
    pub fn stub(req: &AnalyzeRequest) -> Self {
        Self {
            binary_path: req.binary_path.clone(),
            architecture: req.architecture.clone(),
            file_type: "ELF64".to_string(),
            entry_point: 0x0040_1000,
            function_count: 42,
            import_count: 15,
            export_count: 3,
            string_count: 128,
            entropy: 6.2,
            yara_matches: Vec::new(),
            summary: format!("Analysis of '{}' complete.", req.binary_path),
            duration_ms: 0,
        }
    }
}

// â"€â"€â"€ DecompileRequest â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Request to decompile a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileRequest {
    pub binary_path: String,
    pub function_address: u64,
    pub backend: String,
    pub include_disasm: bool,
    pub simplify: bool,
}

impl DecompileRequest {
    #[must_use]
    pub fn new(binary_path: impl Into<String>, function_address: u64) -> Self {
        Self {
            binary_path: binary_path.into(),
            function_address,
            backend: "ghidra".to_string(),
            include_disasm: false,
            simplify: true,
        }
    }

    /// Function address as a hex string.
    #[must_use]
    pub fn address_hex(&self) -> String {
        format!("0x{:x}", self.function_address)
    }
}

/// Response to a decompile request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileResponse {
    pub binary_path: String,
    pub address: u64,
    pub pseudo_c: String,
    pub disassembly: Option<String>,
    pub function_name: String,
    pub duration_ms: u64,
    /// HLIL pseudo-code from the experimental HLIL pass, when available.
    pub hlil_pseudo: Option<String>,
    /// Pipeline confidence score (0–100).
    pub confidence: u8,
}

impl DecompileResponse {
    /// Decompile the requested function with the real `rustre-decompiler`
    /// pipeline (structured control flow, recovered types, forwarded copies).
    ///
    /// # Errors
    ///
    /// Returns [`BinaryAnalysisError::DecompileFailed`] when the binary cannot be
    /// loaded or the address is not a mapped function.
    ///
    /// This used to fall back to [`Self::stub`] "so the handler never fails
    /// hard" — which meant a failed request came back as pseudo-C for an empty
    /// `sub_…()` plus two disassembly lines (`push rbp` / `mov rbp, rsp`) that
    /// were never read from the file. A caller could not tell that apart from a
    /// real function, so a failure was reported as an analysis. `handle_analyze`
    /// was already repaired the same way; this is its sibling.
    pub fn decompile(req: &DecompileRequest) -> Result<Self, BinaryAnalysisError> {
        let start = std::time::Instant::now();
        match rustre_decompiler::decompile_function_from_binary(
            std::path::Path::new(&req.binary_path),
            req.function_address,
            rustre_decompiler::DecompOptions::default(),
        ) {
            Ok(func) => Ok(Self {
                binary_path: req.binary_path.clone(),
                address: req.function_address,
                pseudo_c: func.pseudo_code,
                disassembly: None,
                function_name: func.name,
                duration_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
                hlil_pseudo: func.hlil_pseudo_code,
                confidence: func.confidence,
            }),
            // The underlying error is not forwarded verbatim: its type belongs to
            // `rustre-decompiler`, which this campaign must not review, so the
            // message states what failed without claiming to know why.
            Err(_) => Err(BinaryAnalysisError::DecompileFailed(
                req.function_address,
                format!(
                    "could not decompile '{}' at the requested address",
                    req.binary_path
                ),
            )),
        }
    }

    #[must_use]
    pub fn stub(req: &DecompileRequest) -> Self {
        Self {
            binary_path: req.binary_path.clone(),
            address: req.function_address,
            pseudo_c: format!(
                "// Decompiled function at {}\nvoid sub_{:x}() {{\n  // ...\n}}\n",
                req.address_hex(),
                req.function_address
            ),
            disassembly: if req.include_disasm {
                Some(format!(
                    "{}: push rbp\n0x{:x}: mov rbp, rsp",
                    req.address_hex(),
                    req.function_address + 1
                ))
            } else {
                None
            },
            function_name: format!("sub_{:x}", req.function_address),
            duration_ms: 0,
            hlil_pseudo: None,
            confidence: 0,
        }
    }
}

// â"€â"€â"€ YaraRequest â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Request to scan a binary with YARA rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRequest {
    pub binary_path: String,
    pub rules: Vec<String>,
    pub rule_files: Vec<String>,
    pub fast_mode: bool,
    pub timeout_ms: u64,
    pub namespace: String,
}

impl YaraRequest {
    #[must_use]
    pub fn new(binary_path: impl Into<String>) -> Self {
        Self {
            binary_path: binary_path.into(),
            rules: Vec::new(),
            rule_files: Vec::new(),
            fast_mode: false,
            timeout_ms: 30_000,
            namespace: "default".to_string(),
        }
    }

    #[must_use]
    pub fn with_rule(mut self, rule: impl Into<String>) -> Self {
        self.rules.push(rule.into());
        self
    }

    #[must_use]
    pub const fn fast(mut self) -> Self {
        self.fast_mode = true;
        self
    }

    /// Validate that at least one rule source is present.
    ///
    /// # Errors
    /// Returns [`BinaryAnalysisError::YaraError`] if no rules are provided.
    pub fn validate(&self) -> Result<(), BinaryAnalysisError> {
        if self.rules.is_empty() && self.rule_files.is_empty() {
            Err(BinaryAnalysisError::YaraError(
                "no rules provided".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}

/// A single YARA match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatchResult {
    pub rule_name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub offset: u64,
    pub matched_data: String,
}

/// Response to a YARA scan request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraResponse {
    pub binary_path: String,
    pub matches: Vec<YaraMatchResult>,
    pub total_rules_evaluated: u32,
    pub scan_duration_ms: u64,
    pub matched: bool,
}

impl YaraResponse {
    #[must_use]
    pub fn empty(binary_path: impl Into<String>) -> Self {
        Self {
            binary_path: binary_path.into(),
            matches: Vec::new(),
            total_rules_evaluated: 0,
            scan_duration_ms: 0,
            matched: false,
        }
    }
}

// â"€â"€â"€ DiffRequest â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Request to diff two binaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffRequest {
    pub binary_a: String,
    pub binary_b: String,
    pub diff_mode: DiffMode,
    pub similarity_threshold: f32,
    pub max_results: usize,
}

/// Diff comparison mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffMode {
    Bytewise,
    Decompiled,
    Signatures,
    Functions,
}

impl std::fmt::Display for DiffMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl DiffRequest {
    #[must_use]
    pub fn new(binary_a: impl Into<String>, binary_b: impl Into<String>) -> Self {
        Self {
            binary_a: binary_a.into(),
            binary_b: binary_b.into(),
            diff_mode: DiffMode::Functions,
            similarity_threshold: 0.8,
            max_results: 100,
        }
    }

    #[must_use]
    pub const fn with_mode(mut self, mode: DiffMode) -> Self {
        self.diff_mode = mode;
        self
    }

    #[must_use]
    pub const fn with_threshold(mut self, t: f32) -> Self {
        self.similarity_threshold = t.clamp(0.0, 1.0);
        self
    }
}

/// A single diff entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub function_name_a: String,
    pub function_name_b: String,
    pub address_a: u64,
    pub address_b: u64,
    pub similarity: f32,
    pub change_type: String,
}

/// Response to a diff request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResponse {
    pub binary_a: String,
    pub binary_b: String,
    pub changed: Vec<DiffEntry>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub total_functions_a: u32,
    pub total_functions_b: u32,
    pub duration_ms: u64,
}

impl DiffResponse {
    #[must_use]
    pub fn empty(req: &DiffRequest) -> Self {
        Self {
            binary_a: req.binary_a.clone(),
            binary_b: req.binary_b.clone(),
            changed: Vec::new(),
            added: Vec::new(),
            removed: Vec::new(),
            total_functions_a: 0,
            total_functions_b: 0,
            duration_ms: 0,
        }
    }
}

// â"€â"€â"€ SearchRequest â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Request to search within a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchRequest {
    pub binary_path: String,
    pub query: String,
    pub search_type: SearchType,
    pub case_sensitive: bool,
    pub max_results: usize,
    pub context_bytes: usize,
}

/// Kind of search to perform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SearchType {
    String,
    Bytes,
    Regex,
    Symbol,
    Function,
    Import,
}

impl std::fmt::Display for SearchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl SearchRequest {
    #[must_use]
    pub fn new(
        binary_path: impl Into<String>,
        query: impl Into<String>,
        search_type: SearchType,
    ) -> Self {
        Self {
            binary_path: binary_path.into(),
            query: query.into(),
            search_type,
            case_sensitive: false,
            max_results: 100,
            context_bytes: 16,
        }
    }
}

/// A single search hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub offset: u64,
    pub section: String,
    pub match_text: String,
    pub context: Vec<u8>,
}

/// Response to a search request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResponse {
    pub binary_path: String,
    pub query: String,
    pub hits: Vec<SearchHit>,
    pub total_hits: usize,
    pub truncated: bool,
    pub duration_ms: u64,
}

// â"€â"€â"€ MitreRequest â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Request to map findings to MITRE ATT&CK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreRequest {
    pub binary_path: String,
    pub analysis_summary: String,
    pub iocs: Vec<String>,
    pub capabilities: Vec<String>,
    pub include_sub_techniques: bool,
}

impl MitreRequest {
    #[must_use]
    pub fn new(binary_path: impl Into<String>, analysis_summary: impl Into<String>) -> Self {
        Self {
            binary_path: binary_path.into(),
            analysis_summary: analysis_summary.into(),
            iocs: Vec::new(),
            capabilities: Vec::new(),
            include_sub_techniques: true,
        }
    }
}

/// A MITRE technique match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub technique_id: String,
    pub name: String,
    pub tactic: String,
    pub description: String,
    pub confidence: f32,
}

impl MitreTechnique {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        tactic: impl Into<String>,
        confidence: f32,
    ) -> Self {
        Self {
            technique_id: id.into(),
            name: name.into(),
            tactic: tactic.into(),
            description: String::new(),
            confidence: confidence.clamp(0.0, 1.0),
        }
    }
}

/// Response to a MITRE mapping request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreResponse {
    pub binary_path: String,
    pub techniques: Vec<MitreTechnique>,
    pub top_tactic: Option<String>,
    pub total_mapped: usize,
    pub duration_ms: u64,
}

// â"€â"€â"€ BinaryAnalysisServer â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Server state.
#[derive(Default)]
struct ServerState {
    request_count: u64,
    error_count: u64,
}

/// MCP-compatible server for binary analysis operations.
pub struct BinaryAnalysisServer {
    state: RwLock<ServerState>,
    tool_definitions: Vec<ToolDefinition>,
}

impl BinaryAnalysisServer {
    /// Create a new server instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: RwLock::new(ServerState::default()),
            tool_definitions: builtin_tool_definitions(),
        }
    }

    /// Handle an analysis request.
    ///
    /// # Errors
    /// Returns [`BinaryAnalysisError::InvalidRequest`] if `binary_path` is empty.
    pub fn handle_analyze(
        &self,
        req: AnalyzeRequest,
    ) -> Result<AnalyzeResponse, BinaryAnalysisError> {
        if req.binary_path.is_empty() {
            self.state.write().error_count += 1;
            return Err(BinaryAnalysisError::InvalidRequest(
                "binary_path is empty".to_string(),
            ));
        }
        self.state.write().request_count += 1;
        // Real analysis. This used to be `Ok(AnalyzeResponse::stub(&req))`,
        // which answered every request with the same invented numbers without
        // ever opening the file.
        let resp = AnalyzeResponse::analyze(&req);
        if resp.is_err() {
            self.state.write().error_count += 1;
        }
        resp
    }

    /// Handle a decompile request.
    ///
    /// # Errors
    /// Returns [`BinaryAnalysisError::InvalidRequest`] if `binary_path` is empty.
    pub fn handle_decompile(
        &self,
        req: DecompileRequest,
    ) -> Result<DecompileResponse, BinaryAnalysisError> {
        if req.binary_path.is_empty() {
            self.state.write().error_count += 1;
            return Err(BinaryAnalysisError::InvalidRequest(
                "binary_path is empty".to_string(),
            ));
        }
        self.state.write().request_count += 1;
        let resp = DecompileResponse::decompile(&req);
        if resp.is_err() {
            self.state.write().error_count += 1;
        }
        resp
    }

    /// Handle a YARA scan request.
    ///
    /// # Errors
    /// Returns [`BinaryAnalysisError::YaraError`] if the request has no rules.
    pub fn handle_yara(&self, req: YaraRequest) -> Result<YaraResponse, BinaryAnalysisError> {
        req.validate()?;
        self.state.write().request_count += 1;
        Ok(YaraResponse::empty(&req.binary_path))
    }

    /// Handle a diff request.
    ///
    /// # Errors
    /// Returns [`BinaryAnalysisError::DiffFailed`] if `binary_a` and `binary_b` are the same.
    pub fn handle_diff(&self, req: DiffRequest) -> Result<DiffResponse, BinaryAnalysisError> {
        if req.binary_a == req.binary_b {
            return Err(BinaryAnalysisError::DiffFailed(
                "binary_a and binary_b are the same".to_string(),
            ));
        }
        self.state.write().request_count += 1;
        Ok(DiffResponse::empty(&req))
    }

    /// Handle a search request.
    ///
    /// # Errors
    /// Returns [`BinaryAnalysisError::InvalidRequest`] if the query is empty.
    pub fn handle_search(
        &self,
        req: SearchRequest,
    ) -> Result<SearchResponse, BinaryAnalysisError> {
        if req.query.is_empty() {
            return Err(BinaryAnalysisError::InvalidRequest(
                "query is empty".to_string(),
            ));
        }
        self.state.write().request_count += 1;
        Ok(SearchResponse {
            binary_path: req.binary_path,
            query: req.query,
            hits: Vec::new(),
            total_hits: 0,
            truncated: false,
            duration_ms: 0,
        })
    }

    /// Handle a MITRE mapping request.
    ///
    /// # Errors
    /// This function currently does not return errors.
    pub fn handle_mitre(
        &self,
        req: MitreRequest,
    ) -> Result<MitreResponse, BinaryAnalysisError> {
        self.state.write().request_count += 1;
        let techniques = infer_techniques(&req);
        let top_tactic = techniques.first().map(|t| t.tactic.clone());
        let total = techniques.len();
        Ok(MitreResponse {
            binary_path: req.binary_path,
            techniques,
            top_tactic,
            total_mapped: total,
            duration_ms: 0,
        })
    }

    /// Total requests handled.
    #[must_use]
    pub fn request_count(&self) -> u64 {
        self.state.read().request_count
    }

    /// Total errors recorded.
    #[must_use]
    pub fn error_count(&self) -> u64 {
        self.state.read().error_count
    }

    /// Return all tool definitions.
    #[must_use]
    pub fn tool_definitions(&self) -> &[ToolDefinition] {
        &self.tool_definitions
    }
}

impl Default for BinaryAnalysisServer {
    fn default() -> Self {
        Self::new()
    }
}

// â"€â"€â"€ Helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

fn infer_techniques(req: &MitreRequest) -> Vec<MitreTechnique> {
    let mut techniques = Vec::new();
    let summary = req.analysis_summary.to_lowercase();
    if summary.contains("inject") || summary.contains("shellcode") {
        techniques.push(MitreTechnique::new(
            "T1055",
            "Process Injection",
            "Defense Evasion",
            0.85,
        ));
    }
    if summary.contains("network") || summary.contains("socket") || summary.contains("http") {
        techniques.push(MitreTechnique::new(
            "T1071",
            "Application Layer Protocol",
            "Command and Control",
            0.75,
        ));
    }
    if summary.contains("registry") || summary.contains("persist") {
        techniques.push(MitreTechnique::new(
            "T1547",
            "Boot or Logon Autostart Execution",
            "Persistence",
            0.70,
        ));
    }
    if summary.contains("encrypt") || summary.contains("crypto") {
        techniques.push(MitreTechnique::new(
            "T1486",
            "Data Encrypted for Impact",
            "Impact",
            0.80,
        ));
    }
    techniques
}

fn builtin_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "analyze_binary".to_string(),
            description: "Perform full binary analysis".to_string(),
            input_schema: serde_json::Value::Null,
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "binary_path": { "type": "string" },
                    "architecture": { "type": "string" }
                },
                "required": ["binary_path"]
            }),
        },
        ToolDefinition {
            name: "decompile_function".to_string(),
            description: "Decompile a single function. Response includes source (pseudo-C), function_name, duration_ms, confidence, hlil_pseudo_code (HLIL output, null if unavailable).".to_string(),
            input_schema: serde_json::Value::Null,
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "binary_path": { "type": "string" },
                    "function_address": { "type": "integer" }
                },
                "required": ["binary_path", "function_address"]
            }),
        },
        ToolDefinition {
            name: "yara_scan".to_string(),
            description: "Scan a binary with YARA rules".to_string(),
            input_schema: serde_json::Value::Null,
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "binary_path": { "type": "string" },
                    "rules": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["binary_path"]
            }),
        },
        ToolDefinition {
            name: "diff_binaries".to_string(),
            description: "Diff two binary versions".to_string(),
            input_schema: serde_json::Value::Null,
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "binary_a": { "type": "string" },
                    "binary_b": { "type": "string" }
                },
                "required": ["binary_a", "binary_b"]
            }),
        },
        ToolDefinition {
            name: "search_binary".to_string(),
            description: "Search within a binary".to_string(),
            input_schema: serde_json::Value::Null,
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "binary_path": { "type": "string" },
                    "query": { "type": "string" }
                },
                "required": ["binary_path", "query"]
            }),
        },
        ToolDefinition {
            name: "mitre_mapping".to_string(),
            description: "Map findings to MITRE ATT&CK techniques".to_string(),
            input_schema: serde_json::Value::Null,
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "binary_path": { "type": "string" },
                    "analysis_summary": { "type": "string" }
                },
                "required": ["analysis_summary"]
            }),
        },
    ]
}

// â"€â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    fn srv() -> BinaryAnalysisServer {
        BinaryAnalysisServer::new()
    }

    // â"€â"€ AnalyzeRequest â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_analyze_request_new() {
        let req = AnalyzeRequest::new("/bin/ls");
        assert_eq!(req.binary_path, "/bin/ls");
        assert_eq!(req.analysis_level, AnalysisLevel::Standard);
        assert!(req.run_yara);
    }

    #[test]
    fn test_analyze_request_builder() {
        let req = AnalyzeRequest::new("/a")
            .with_arch("arm64")
            .with_level(AnalysisLevel::Deep);
        assert_eq!(req.architecture, "arm64");
        assert_eq!(req.analysis_level, AnalysisLevel::Deep);
    }

    #[test]
    fn test_analysis_level_display() {
        assert_eq!(AnalysisLevel::Quick.to_string(), "Quick");
        assert_eq!(AnalysisLevel::Exhaustive.to_string(), "Exhaustive");
    }

    /// Analysing a real file reports values measured from that file.
    ///
    /// This test used to pass `"/bin/ls"` — a path that does not exist on the
    /// machine this suite runs on — and assert `function_count > 0`. It passed
    /// **only because `handle_analyze` returned a stub inventing 42 functions
    /// without opening anything**, so it was pinning the fabrication in place:
    /// making the handler honest would have read as a regression. Rewritten
    /// 2026-07-29 to use a file that genuinely exists.
    #[tokio::test]
    async fn test_handle_analyze_ok() {
        let s = srv();
        let exe = std::env::current_exe().expect("current exe path");
        let path = exe.to_string_lossy().to_string();
        let resp = s.handle_analyze(AnalyzeRequest::new(&path)).unwrap();

        assert_eq!(resp.binary_path, path);
        // Entropy is computed from the bytes, so it must be a real figure in
        // range — 6.2 for everything was the tell that nothing was measured.
        assert!(
            resp.entropy > 0.0 && resp.entropy <= 8.0,
            "entropy must be measured from the file, got {}",
            resp.entropy
        );
        // A real executable contains printable strings.
        assert!(resp.string_count > 0, "a real binary has strings");
        assert!(
            resp.summary.contains("Analysed"),
            "the summary must describe what was measured: {}",
            resp.summary
        );
        assert_eq!(s.request_count(), 1);
    }

    /// A path that does not exist is an error, not an analysis.
    ///
    /// The negative control for the test above: before 2026-07-29 this case
    /// returned `Ok` with `ELF64 / 42 functions / entropy 6.2 / "complete"`.
    #[tokio::test]
    async fn test_handle_analyze_missing_file_is_an_error() {
        let s = srv();
        let err = s
            .handle_analyze(AnalyzeRequest::new("/definitely/not/here.bin"))
            .unwrap_err();
        assert!(
            matches!(err, BinaryAnalysisError::InvalidRequest(_)),
            "an unreadable binary must not produce an analysis result"
        );
        assert_eq!(s.error_count(), 1, "the failure must be counted");
    }

    #[tokio::test]
    async fn test_handle_analyze_empty_path() {
        let s = srv();
        let req = AnalyzeRequest::new("");
        let err = s.handle_analyze(req).unwrap_err();
        assert!(matches!(err, BinaryAnalysisError::InvalidRequest(_)));
        assert_eq!(s.error_count(), 1);
    }

    // â"€â"€ DecompileRequest â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_decompile_request_address_hex() {
        let req = DecompileRequest::new("/bin/ls", 0x401000);
        assert_eq!(req.address_hex(), "0x401000");
    }

    /// A path the process cannot read must come back as a FAILURE.
    ///
    /// This test used to `unwrap()` and assert that the pseudo-C mentioned the
    /// address — which passed only because `decompile` answered an unloadable
    /// binary with a manufactured `void sub_401000()` body. The address appeared
    /// in the output because the stub formatted it, not because anything was
    /// decompiled. `/bin/ls` does not exist on every machine that runs this
    /// suite, so the old assertion was green for the wrong reason.
    #[tokio::test]
    async fn test_handle_decompile_reports_failure_for_an_unreadable_binary() {
        let s = srv();
        let req = DecompileRequest::new("/definitely/not/a/binary", 0x401000);
        let err = s
            .handle_decompile(req)
            .expect_err("an unreadable path must not produce a decompilation");
        assert!(
            matches!(err, BinaryAnalysisError::DecompileFailed(addr, _) if addr == 0x401000),
            "expected DecompileFailed for the requested address, got {err:?}"
        );
        // The failure must be counted, like `handle_analyze` does.
        assert_eq!(s.error_count(), 1);
    }

    #[tokio::test]
    async fn test_handle_decompile_with_disasm() {
        // `include_disasm` must NOT resurrect a manufactured answer: this used to
        // assert that an unreadable path (`/b`) still produced `Some(disassembly)`,
        // which passed only because the stub invented two instructions.
        let s = srv();
        let req = DecompileRequest {
            include_disasm: true,
            ..DecompileRequest::new("/b", 0x100)
        };
        let err = s
            .handle_decompile(req)
            .expect_err("include_disasm must not turn a failure into a result");
        assert!(matches!(err, BinaryAnalysisError::DecompileFailed(..)));

        // What `include_disasm` does on SUCCESS is deliberately NOT asserted here:
        // it needs a real binary with a decompilable function at a known address,
        // and this suite has none. Asserting it against a fabricated response is
        // exactly what made this test green while the code was wrong.
    }

    #[tokio::test]
    async fn test_handle_decompile_empty_path() {
        let s = srv();
        let req = DecompileRequest::new("", 0);
        // Rejected before any decompilation is attempted, and with the specific
        // variant: `is_err()` alone would also accept a DecompileFailed, which
        // would mean the empty path had reached the pipeline.
        let err = s.handle_decompile(req).expect_err("empty path must be rejected");
        assert!(matches!(err, BinaryAnalysisError::InvalidRequest(_)));
    }

    // â"€â"€ YaraRequest â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_yara_request_validate_ok() {
        let req = YaraRequest::new("/a").with_rule("rule x {}");
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_yara_request_validate_no_rules() {
        let req = YaraRequest::new("/a");
        assert!(req.validate().is_err());
    }

    #[tokio::test]
    async fn test_handle_yara_ok() {
        let s = srv();
        let req = YaraRequest::new("/bin/ls").with_rule("rule x {}");
        let resp = s.handle_yara(req).unwrap();
        assert!(!resp.matched);
    }

    #[tokio::test]
    async fn test_handle_yara_no_rules_error() {
        let s = srv();
        let req = YaraRequest::new("/a");
        assert!(s.handle_yara(req).is_err());
    }

    // â"€â"€ DiffRequest â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_diff_request_new() {
        let req = DiffRequest::new("/a", "/b");
        assert_eq!(req.diff_mode, DiffMode::Functions);
        assert!((req.similarity_threshold - 0.8).abs() < f32::EPSILON);
    }

    #[tokio::test]
    async fn test_handle_diff_ok() {
        let s = srv();
        let req = DiffRequest::new("/a", "/b");
        let resp = s.handle_diff(req).unwrap();
        assert_eq!(resp.binary_a, "/a");
    }

    #[tokio::test]
    async fn test_handle_diff_same_binary() {
        let s = srv();
        let req = DiffRequest::new("/a", "/a");
        let err = s.handle_diff(req).unwrap_err();
        assert!(matches!(err, BinaryAnalysisError::DiffFailed(_)));
    }

    #[test]
    fn test_diff_mode_display() {
        assert_eq!(DiffMode::Bytewise.to_string(), "Bytewise");
        assert_eq!(DiffMode::Decompiled.to_string(), "Decompiled");
    }

    // â"€â"€ SearchRequest â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_search_type_display() {
        assert_eq!(SearchType::String.to_string(), "String");
        assert_eq!(SearchType::Import.to_string(), "Import");
    }

    #[tokio::test]
    async fn test_handle_search_ok() {
        let s = srv();
        let req = SearchRequest::new("/a", "CreateProcess", SearchType::Import);
        let resp = s.handle_search(req).unwrap();
        assert_eq!(resp.query, "CreateProcess");
        assert_eq!(resp.total_hits, 0);
    }

    #[tokio::test]
    async fn test_handle_search_empty_query() {
        let s = srv();
        let req = SearchRequest::new("/a", "", SearchType::String);
        assert!(s.handle_search(req).is_err());
    }

    // â"€â"€ MitreRequest â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_mitre_technique_new() {
        let t = MitreTechnique::new("T1055", "Process Injection", "Defense Evasion", 0.9);
        assert_eq!(t.technique_id, "T1055");
        assert!((t.confidence - 0.9).abs() < f32::EPSILON);
    }

    #[tokio::test]
    async fn test_handle_mitre_injection() {
        let s = srv();
        let req = MitreRequest::new("/a", "code performs process injection via shellcode");
        let resp = s.handle_mitre(req).unwrap();
        assert!(!resp.techniques.is_empty());
        
        assert!(resp
            .techniques
            .iter()
            .map(|t| t.technique_id.as_str()).any(|x| x == "T1055"));
    }

    #[tokio::test]
    async fn test_handle_mitre_empty_summary() {
        let s = srv();
        let req = MitreRequest::new("/a", "");
        let resp = s.handle_mitre(req).unwrap();
        // No techniques inferred from empty summary
        assert!(resp.techniques.is_empty());
    }

    // â"€â"€ Server stats â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[tokio::test]
    async fn test_server_request_count() {
        let s = srv();
        s.handle_analyze(AnalyzeRequest::new("/a")).ok();
        s.handle_analyze(AnalyzeRequest::new("/b")).ok();
        assert_eq!(s.request_count(), 2);
    }

    #[test]
    fn test_tool_definitions_non_empty() {
        let s = srv();
        assert!(!s.tool_definitions().is_empty());
        let names: Vec<&str> = s
            .tool_definitions()
            .iter()
            .map(|t| t.name.as_str())
            .collect();
        assert!(names.contains(&"analyze_binary"));
        assert!(names.contains(&"yara_scan"));
    }

    // â"€â"€ Error display â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_error_display() {
        let e = BinaryAnalysisError::BinaryNotFound("/missing".into());
        assert!(e.to_string().contains("missing"));
        let e2 = BinaryAnalysisError::DecompileFailed(0x1000, "timeout".into());
        assert!(e2.to_string().contains("0x1000"));
    }
}
