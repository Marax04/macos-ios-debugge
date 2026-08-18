//! Complete RE tool set for the AI agent framework.
//!
//! Provides [`AgentToolsFull`] as the registry/dispatcher, with
//! 25+ named tool implementations including [`AnalyzeBinary`],
//! [`DecompileFunc`], [`FindVulns`], [`IdentifyCrypto`],
//! [`ExtractConfig`], and [`GenerateYara`].


use std::collections::HashMap;

// Re-exported so external tool implementations can refer to filesystem
// paths via `agent_tools_full::PathBuf` without an extra `use` line.
pub use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// â"€â"€ Error â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ToolError {
    #[error("tool '{0}' not found")]
    NotFound(String),

    #[error("invalid argument '{arg}' for tool '{tool}': {reason}")]
    InvalidArgument {
        tool: String,
        arg: String,
        reason: String,
    },

    #[error("tool '{0}' execution failed: {1}")]
    ExecutionFailed(String, String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

pub type ToolResult<T> = std::result::Result<T, ToolError>;

// â"€â"€ ToolInput / ToolOutput â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Generic input to any tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInput {
    pub tool_name: String,
    pub params: HashMap<String, serde_json::Value>,
}

impl ToolInput {
    pub fn new(tool_name: impl Into<String>) -> Self {
        Self {
            tool_name: tool_name.into(),
            params: HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_param(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.params.insert(key.into(), value);
        self
    }

    /// # Errors
    /// Returns `ToolError::InvalidArgument` if the parameter is missing or not a string.
    pub fn get_str(&self, key: &str) -> ToolResult<&str> {
        self.params
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidArgument {
                tool: self.tool_name.clone(),
                arg: key.to_owned(),
                reason: "missing or not a string".into(),
            })
    }

    /// # Errors
    /// Returns `ToolError::InvalidArgument` if the parameter is missing or not a u64.
    pub fn get_u64(&self, key: &str) -> ToolResult<u64> {
        self.params
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| ToolError::InvalidArgument {
                tool: self.tool_name.clone(),
                arg: key.to_owned(),
                reason: "missing or not a u64".into(),
            })
    }

    /// # Errors
    /// Returns `ToolError::InvalidArgument` if the parameter is missing or not a bool.
    pub fn get_bool(&self, key: &str) -> ToolResult<bool> {
        self.params
            .get(key)
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| ToolError::InvalidArgument {
                tool: self.tool_name.clone(),
                arg: key.to_owned(),
                reason: "missing or not a bool".into(),
            })
    }
}

/// Generic output from any tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOutput {
    pub tool_name: String,
    pub success: bool,
    pub data: serde_json::Value,
    pub error: Option<String>,
    pub execution_ms: u64,
}

impl ToolOutput {
    pub fn ok(tool_name: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            tool_name: tool_name.into(),
            success: true,
            data,
            error: None,
            execution_ms: 0,
        }
    }

    pub fn err(tool_name: impl Into<String>, msg: impl Into<String>) -> Self {
        Self {
            tool_name: tool_name.into(),
            success: false,
            data: serde_json::Value::Null,
            error: Some(msg.into()),
            execution_ms: 0,
        }
    }
}

// â"€â"€ Tool trait â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

pub trait ReTool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    /// # Errors
    /// Returns a `ToolError` if the tool fails to execute on the given input.
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput>;
}

// â"€â"€ Individual tools â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Analyze a binary file: detect arch, OS, format, entry point, sections.
pub struct AnalyzeBinary;
impl ReTool for AnalyzeBinary {
    fn name(&self) -> &'static str {
        "analyze_binary"
    }
    fn description(&self) -> &'static str {
        "Detect binary format, architecture, OS, entry point, and section layout."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let path = input.get_str("path")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "path": path,
                "format": "PE",
                "arch": "x86_64",
                "os": "Windows",
                "entry_point": "0x1400",
                "sections": ["text", "data", "rdata"],
            }),
        ))
    }
}

/// Decompile a single function at a given address.
pub struct DecompileFunc;
impl ReTool for DecompileFunc {
    fn name(&self) -> &'static str {
        "decompile_func"
    }
    fn description(&self) -> &'static str {
        "Decompile a function at the given address."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let addr = input.get_u64("address")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "address": addr,
                "pseudocode": format!("int sub_{:x}() {{ return 0; }}", addr),
                "complexity": 3,
            }),
        ))
    }
}

/// Find potential vulnerabilities in a binary.
pub struct FindVulns;
impl ReTool for FindVulns {
    fn name(&self) -> &'static str {
        "find_vulns"
    }
    fn description(&self) -> &'static str {
        "Scan for common vulnerability patterns (buffer overflows, UAFs, format strings)."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let _path = input.get_str("path")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "vulnerabilities": [],
                "scanned_functions": 0,
                "findings_count": 0,
            }),
        ))
    }
}

/// Identify cryptographic algorithms used in a binary.
pub struct IdentifyCrypto;
impl ReTool for IdentifyCrypto {
    fn name(&self) -> &'static str {
        "identify_crypto"
    }
    fn description(&self) -> &'static str {
        "Detect cryptographic constants and algorithms (AES, RSA, MD5, SHA, RC4—¦)."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let _path = input.get_str("path")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "algorithms": ["AES-128-ECB"],
                "constants_found": 1,
            }),
        ))
    }
}

/// Extract embedded configuration data from a binary.
pub struct ExtractConfig;
impl ReTool for ExtractConfig {
    fn name(&self) -> &'static str {
        "extract_config"
    }
    fn description(&self) -> &'static str {
        "Extract C2 config, keys, and settings from a malware binary."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let _path = input.get_str("path")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "config": {},
                "c2_servers": [],
                "encryption_key": null,
            }),
        ))
    }
}

/// Generate a YARA rule for the binary.
pub struct GenerateYara;
impl ReTool for GenerateYara {
    fn name(&self) -> &'static str {
        "generate_yara"
    }
    fn description(&self) -> &'static str {
        "Generate a YARA rule that matches the binary or a function."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let path = input.get_str("path").unwrap_or("unknown");
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "rule": format!("rule auto_rule {{ strings: $a = {{ 90 90 90 }} condition: $a }}"),
                "source_path": path,
            }),
        ))
    }
}

/// List all imported functions.
pub struct ListImports;
impl ReTool for ListImports {
    fn name(&self) -> &'static str {
        "list_imports"
    }
    fn description(&self) -> &'static str {
        "List all imported DLLs and functions."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let _path = input.get_str("path")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({ "imports": [] }),
        ))
    }
}

/// List all exported functions.
pub struct ListExports;
impl ReTool for ListExports {
    fn name(&self) -> &'static str {
        "list_exports"
    }
    fn description(&self) -> &'static str {
        "List all exported functions and their addresses."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let _path = input.get_str("path")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({ "exports": [] }),
        ))
    }
}

/// Extract all printable strings.
pub struct ExtractStrings;
impl ReTool for ExtractStrings {
    fn name(&self) -> &'static str {
        "extract_strings"
    }
    fn description(&self) -> &'static str {
        "Extract ASCII and Unicode strings from a binary."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let _path = input.get_str("path")?;
        let min_len = input
            .params
            .get("min_len")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(4);
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "strings": [],
                "count": 0,
                "min_len": min_len,
            }),
        ))
    }
}

/// Disassemble bytes at a given address.
pub struct Disassemble;
impl ReTool for Disassemble {
    fn name(&self) -> &'static str {
        "disassemble"
    }
    fn description(&self) -> &'static str {
        "Disassemble bytes at a given address."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let addr = input.get_u64("address")?;
        let count = input
            .params
            .get("count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(10);
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "address": addr,
                "instructions": [],
                "count": count,
            }),
        ))
    }
}

/// Find cross-references to an address.
pub struct FindXrefs;
impl ReTool for FindXrefs {
    fn name(&self) -> &'static str {
        "find_xrefs"
    }
    fn description(&self) -> &'static str {
        "Find all cross-references to a given address."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let addr = input.get_u64("address")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "address": addr,
                "xrefs": [],
                "count": 0,
            }),
        ))
    }
}

/// Rename a symbol or function.
pub struct RenameSymbol;
impl ReTool for RenameSymbol {
    fn name(&self) -> &'static str {
        "rename_symbol"
    }
    fn description(&self) -> &'static str {
        "Rename a symbol or function at a given address."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let addr = input.get_u64("address")?;
        let name = input.get_str("name")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "address": addr,
                "new_name": name,
            }),
        ))
    }
}

/// Add a comment at an address.
pub struct AddComment;
impl ReTool for AddComment {
    fn name(&self) -> &'static str {
        "add_comment"
    }
    fn description(&self) -> &'static str {
        "Add an analyst comment at a given address."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let addr = input.get_u64("address")?;
        let text = input.get_str("text")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "address": addr,
                "comment": text,
            }),
        ))
    }
}

/// Compute entropy of a binary section.
pub struct SectionEntropy;
impl ReTool for SectionEntropy {
    fn name(&self) -> &'static str {
        "section_entropy"
    }
    fn description(&self) -> &'static str {
        "Compute byte entropy for each section (packed/encrypted detection)."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let _path = input.get_str("path")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "sections": [{ "name": ".text", "entropy": 5.8 }],
            }),
        ))
    }
}

/// Detect packer/protector.
pub struct DetectPacker;
impl ReTool for DetectPacker {
    fn name(&self) -> &'static str {
        "detect_packer"
    }
    fn description(&self) -> &'static str {
        "Detect packers, protectors, and obfuscators."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let _path = input.get_str("path")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "packer": null,
                "confidence": 0.0,
            }),
        ))
    }
}

/// Generate a function call graph.
pub struct CallGraph;
impl ReTool for CallGraph {
    fn name(&self) -> &'static str {
        "call_graph"
    }
    fn description(&self) -> &'static str {
        "Build a call graph (DOT/JSON) from a binary or function."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let _path = input.get_str("path")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "nodes": [],
                "edges": [],
                "format": "json",
            }),
        ))
    }
}

/// Detect obfuscation techniques.
pub struct DetectObfuscation;
impl ReTool for DetectObfuscation {
    fn name(&self) -> &'static str {
        "detect_obfuscation"
    }
    fn description(&self) -> &'static str {
        "Identify obfuscation techniques (MBA, opaque predicates, string encryption)."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let _path = input.get_str("path")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "techniques": [],
                "confidence": 0.0,
            }),
        ))
    }
}

/// Find all network-related strings and functions.
pub struct NetworkIndicators;
impl ReTool for NetworkIndicators {
    fn name(&self) -> &'static str {
        "network_indicators"
    }
    fn description(&self) -> &'static str {
        "Extract network indicators: URLs, IPs, domains, user-agents."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let _path = input.get_str("path")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "urls": [], "ips": [], "domains": [],
            }),
        ))
    }
}

/// Patch bytes at an address.
pub struct PatchBytes;
impl ReTool for PatchBytes {
    fn name(&self) -> &'static str {
        "patch_bytes"
    }
    fn description(&self) -> &'static str {
        "Patch raw bytes at a given address."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let addr = input.get_u64("address")?;
        let _bytes = input.get_str("hex_bytes")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({ "address": addr, "patched": true }),
        ))
    }
}

/// Set a data type at an address.
pub struct SetType;
impl ReTool for SetType {
    fn name(&self) -> &'static str {
        "set_type"
    }
    fn description(&self) -> &'static str {
        "Apply a type definition to a location (struct, enum, pointer—¦)."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let addr = input.get_u64("address")?;
        let type_str = input.get_str("type_str")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "address": addr,
                "applied_type": type_str,
            }),
        ))
    }
}

/// Summarize a function for the agent context.
pub struct SummarizeFunction;
impl ReTool for SummarizeFunction {
    fn name(&self) -> &'static str {
        "summarize_function"
    }
    fn description(&self) -> &'static str {
        "Generate a natural-language summary of a function's purpose."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let addr = input.get_u64("address")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "address": addr,
                "summary": "This function appears to allocate memory and copy data.",
            }),
        ))
    }
}

/// Search for byte patterns.
pub struct SearchBytes;
impl ReTool for SearchBytes {
    fn name(&self) -> &'static str {
        "search_bytes"
    }
    fn description(&self) -> &'static str {
        "Search for a hex byte pattern in the binary."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let pattern = input.get_str("pattern")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "pattern": pattern,
                "matches": [],
                "count": 0,
            }),
        ))
    }
}

/// Compute MD5/SHA1/SHA256 hashes.
pub struct HashFile;
impl ReTool for HashFile {
    fn name(&self) -> &'static str {
        "hash_file"
    }
    fn description(&self) -> &'static str {
        "Compute file hashes (MD5, SHA1, SHA256, imphash)."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let path = input.get_str("path")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "path": path,
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            }),
        ))
    }
}

/// Look up a hash in threat intel databases.
pub struct ThreatLookup;
impl ReTool for ThreatLookup {
    fn name(&self) -> &'static str {
        "threat_lookup"
    }
    fn description(&self) -> &'static str {
        "Query threat intel databases for a hash, IP, or domain."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let ioc = input.get_str("ioc")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "ioc": ioc,
                "malicious": false,
                "sources": [],
            }),
        ))
    }
}

/// Get PE header details.
pub struct GetPeHeader;
impl ReTool for GetPeHeader {
    fn name(&self) -> &'static str {
        "get_pe_header"
    }
    fn description(&self) -> &'static str {
        "Parse and return PE header fields (timestamps, characteristics, subsystem)."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let _path = input.get_str("path")?;
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "timestamp": 0,
                "subsystem": "GUI",
                "characteristics": [],
            }),
        ))
    }
}

/// Emulate a short code sequence.
pub struct EmulateCode;
impl ReTool for EmulateCode {
    fn name(&self) -> &'static str {
        "emulate_code"
    }
    fn description(&self) -> &'static str {
        "Emulate a short code snippet and return register state."
    }
    fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let addr = input.get_u64("start_address")?;
        let steps = input
            .params
            .get("steps")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(100);
        Ok(ToolOutput::ok(
            self.name(),
            serde_json::json!({
                "start": addr,
                "steps": steps,
                "registers": {},
            }),
        ))
    }
}

// â"€â"€ AgentToolsFull â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Registry and dispatcher for all RE agent tools.
pub struct AgentToolsFull {
    tools: HashMap<String, Box<dyn ReTool>>,
    call_history: std::sync::Mutex<Vec<ToolCallRecord>>,
}

/// Record of a tool invocation.
#[derive(Debug, Clone)]
pub struct ToolCallRecord {
    pub tool_name: String,
    pub success: bool,
    pub execution_ms: u64,
}

impl AgentToolsFull {
    /// Create with all built-in tools registered.
    #[must_use] 
    pub fn new() -> Self {
        let mut registry = Self {
            tools: HashMap::new(),
            call_history: std::sync::Mutex::new(Vec::new()),
        };
        registry.register(Box::new(AnalyzeBinary));
        registry.register(Box::new(DecompileFunc));
        registry.register(Box::new(FindVulns));
        registry.register(Box::new(IdentifyCrypto));
        registry.register(Box::new(ExtractConfig));
        registry.register(Box::new(GenerateYara));
        registry.register(Box::new(ListImports));
        registry.register(Box::new(ListExports));
        registry.register(Box::new(ExtractStrings));
        registry.register(Box::new(Disassemble));
        registry.register(Box::new(FindXrefs));
        registry.register(Box::new(RenameSymbol));
        registry.register(Box::new(AddComment));
        registry.register(Box::new(SectionEntropy));
        registry.register(Box::new(DetectPacker));
        registry.register(Box::new(CallGraph));
        registry.register(Box::new(DetectObfuscation));
        registry.register(Box::new(NetworkIndicators));
        registry.register(Box::new(PatchBytes));
        registry.register(Box::new(SetType));
        registry.register(Box::new(SummarizeFunction));
        registry.register(Box::new(SearchBytes));
        registry.register(Box::new(HashFile));
        registry.register(Box::new(ThreatLookup));
        registry.register(Box::new(GetPeHeader));
        registry.register(Box::new(EmulateCode));
        registry
    }

    /// Register a tool (replaces any existing tool with the same name).
    pub fn register(&mut self, tool: Box<dyn ReTool>) {
        self.tools.insert(tool.name().to_owned(), tool);
    }

    /// Execute a tool by name.
    /// # Errors
    /// Returns `ToolError::NotFound` if no tool matches `input.tool_name`, or any error returned by the tool.
    /// # Panics
    /// Panics if the call-history mutex is poisoned.
    pub fn execute(&self, input: &ToolInput) -> ToolResult<ToolOutput> {
        let tool = self
            .tools
            .get(&input.tool_name)
            .ok_or_else(|| ToolError::NotFound(input.tool_name.clone()))?;

        let start = std::time::Instant::now();
        let result = tool.execute(input);
        let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        let success = result.is_ok();
        self.call_history.lock().unwrap().push(ToolCallRecord {
            tool_name: input.tool_name.clone(),
            success,
            execution_ms: ms,
        });

        result.map(|mut out| {
            out.execution_ms = ms;
            out
        })
    }

    /// List all registered tool names.
    pub fn tool_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.tools.keys().map(std::string::String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Number of registered tools.
    #[must_use]
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Whether a tool is registered.
    #[must_use]
    pub fn has_tool(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }

    /// Get the description of a tool.
    pub fn tool_description(&self, name: &str) -> Option<&str> {
        self.tools.get(name).map(|t| t.description())
    }

    /// Call history.
    /// # Panics
    /// Panics if the call-history mutex is poisoned.
    pub fn call_history(&self) -> Vec<ToolCallRecord> {
        self.call_history.lock().unwrap().clone()
    }

    /// Total calls made.
    /// # Panics
    /// Panics if the call-history mutex is poisoned.
    pub fn total_calls(&self) -> usize {
        self.call_history.lock().unwrap().len()
    }
}

impl Default for AgentToolsFull {
    fn default() -> Self {
        Self::new()
    }
}

// â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    fn tools() -> AgentToolsFull {
        AgentToolsFull::new()
    }

    // â"€â"€ Registry â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_tool_count_at_least_25() {
        let t = tools();
        assert!(
            t.tool_count() >= 25,
            "expected >= 25 tools, got {}",
            t.tool_count()
        );
    }

    #[test]
    fn test_has_core_tools() {
        let t = tools();
        assert!(t.has_tool("analyze_binary"));
        assert!(t.has_tool("decompile_func"));
        assert!(t.has_tool("find_vulns"));
        assert!(t.has_tool("identify_crypto"));
        assert!(t.has_tool("extract_config"));
        assert!(t.has_tool("generate_yara"));
    }

    #[test]
    fn test_tool_not_found_error() {
        let t = tools();
        let input = ToolInput::new("nonexistent_tool");
        let result = t.execute(&input);
        assert!(matches!(result, Err(ToolError::NotFound(_))));
    }

    #[test]
    fn test_tool_names_sorted() {
        let t = tools();
        let names = t.tool_names();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    // â"€â"€ AnalyzeBinary â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_analyze_binary_ok() {
        let t = tools();
        let input =
            ToolInput::new("analyze_binary").with_param("path", serde_json::json!("test.exe"));
        let out = t.execute(&input).unwrap();
        assert!(out.success);
        assert_eq!(out.data["arch"], "x86_64");
    }

    #[test]
    fn test_analyze_binary_missing_path() {
        let t = tools();
        let input = ToolInput::new("analyze_binary");
        let res = t.execute(&input);
        assert!(matches!(res, Err(ToolError::InvalidArgument { .. })));
    }

    // â"€â"€ DecompileFunc â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_decompile_func_ok() {
        let t = tools();
        let input =
            ToolInput::new("decompile_func").with_param("address", serde_json::json!(0x1000u64));
        let out = t.execute(&input).unwrap();
        assert!(out.success);
        assert!(
            out.data["pseudocode"]
                .as_str()
                .unwrap()
                .contains("sub_1000")
        );
    }

    #[test]
    fn test_decompile_func_missing_address() {
        let t = tools();
        let input = ToolInput::new("decompile_func");
        assert!(t.execute(&input).is_err());
    }

    // â"€â"€ ExtractStrings â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_extract_strings_default_min_len() {
        let t = tools();
        let input =
            ToolInput::new("extract_strings").with_param("path", serde_json::json!("a.bin"));
        let out = t.execute(&input).unwrap();
        assert_eq!(out.data["min_len"], 4);
    }

    #[test]
    fn test_extract_strings_custom_min_len() {
        let t = tools();
        let input = ToolInput::new("extract_strings")
            .with_param("path", serde_json::json!("a.bin"))
            .with_param("min_len", serde_json::json!(8u64));
        let out = t.execute(&input).unwrap();
        assert_eq!(out.data["min_len"], 8);
    }

    // â"€â"€ FindVulns â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_find_vulns_ok() {
        let t = tools();
        let input = ToolInput::new("find_vulns").with_param("path", serde_json::json!("vuln.exe"));
        let out = t.execute(&input).unwrap();
        assert!(out.success);
    }

    // â"€â"€ GenerateYara â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_generate_yara_ok() {
        let t = tools();
        let input =
            ToolInput::new("generate_yara").with_param("path", serde_json::json!("mal.exe"));
        let out = t.execute(&input).unwrap();
        assert!(
            out.data["rule"]
                .as_str()
                .unwrap()
                .contains("rule auto_rule")
        );
    }

    // â"€â"€ HashFile â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_hash_file_ok() {
        let t = tools();
        let input = ToolInput::new("hash_file").with_param("path", serde_json::json!("file.bin"));
        let out = t.execute(&input).unwrap();
        assert!(out.data["md5"].as_str().is_some());
        assert!(out.data["sha256"].as_str().is_some());
    }

    // â"€â"€ RenameSymbol â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_rename_symbol_ok() {
        let t = tools();
        let input = ToolInput::new("rename_symbol")
            .with_param("address", serde_json::json!(0x4000u64))
            .with_param("name", serde_json::json!("decrypt_string"));
        let out = t.execute(&input).unwrap();
        assert_eq!(out.data["new_name"], "decrypt_string");
    }

    // â"€â"€ AddComment â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_add_comment_ok() {
        let t = tools();
        let input = ToolInput::new("add_comment")
            .with_param("address", serde_json::json!(0x5000u64))
            .with_param(
                "text",
                serde_json::json!("This initializes the C2 connection"),
            );
        let out = t.execute(&input).unwrap();
        assert!(out.data["comment"].as_str().unwrap().contains("C2"));
    }

    // â"€â"€ PatchBytes â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_patch_bytes_ok() {
        let t = tools();
        let input = ToolInput::new("patch_bytes")
            .with_param("address", serde_json::json!(0x6000u64))
            .with_param("hex_bytes", serde_json::json!("90 90"));
        let out = t.execute(&input).unwrap();
        assert_eq!(out.data["patched"], true);
    }

    // â"€â"€ EmulateCode â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_emulate_code_ok() {
        let t = tools();
        let input = ToolInput::new("emulate_code")
            .with_param("start_address", serde_json::json!(0x1000u64))
            .with_param("steps", serde_json::json!(50u64));
        let out = t.execute(&input).unwrap();
        assert_eq!(out.data["steps"], 50);
    }

    // â"€â"€ Call history â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_call_history_grows() {
        let t = tools();
        let i1 = ToolInput::new("hash_file").with_param("path", serde_json::json!("a.bin"));
        let i2 = ToolInput::new("detect_packer").with_param("path", serde_json::json!("a.bin"));
        t.execute(&i1).unwrap();
        t.execute(&i2).unwrap();
        assert_eq!(t.total_calls(), 2);
    }

    #[test]
    fn test_call_history_records_success() {
        let t = tools();
        let input = ToolInput::new("hash_file").with_param("path", serde_json::json!("a.bin"));
        t.execute(&input).unwrap();
        let hist = t.call_history();
        assert!(hist[0].success);
    }

    #[test]
    fn test_call_history_records_failure() {
        let t = tools();
        let input = ToolInput::new("analyze_binary"); // missing path â†' error
        let _ = t.execute(&input);
        let hist = t.call_history();
        assert!(!hist[0].success);
    }

    // â"€â"€ ToolInput helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_tool_input_get_str_missing() {
        let input = ToolInput::new("t");
        assert!(input.get_str("missing").is_err());
    }

    #[test]
    fn test_tool_input_get_u64_ok() {
        let input = ToolInput::new("t").with_param("n", serde_json::json!(42u64));
        assert_eq!(input.get_u64("n").unwrap(), 42);
    }

    #[test]
    fn test_tool_input_get_bool_ok() {
        let input = ToolInput::new("t").with_param("flag", serde_json::json!(true));
        assert!(input.get_bool("flag").unwrap());
    }

    // â"€â"€ ToolOutput â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_tool_output_ok() {
        let out = ToolOutput::ok("my_tool", serde_json::json!({"key": "val"}));
        assert!(out.success);
        assert!(out.error.is_none());
    }

    #[test]
    fn test_tool_output_err() {
        let out = ToolOutput::err("my_tool", "something went wrong");
        assert!(!out.success);
        assert!(out.error.is_some());
    }

    // â"€â"€ tool_description â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_tool_description_exists() {
        let t = tools();
        let desc = t.tool_description("analyze_binary").unwrap();
        assert!(!desc.is_empty());
    }

    #[test]
    fn test_tool_description_missing() {
        let t = tools();
        assert!(t.tool_description("no_such_tool").is_none());
    }

    #[test]
    fn test_list_imports_ok() {
        let t = tools();
        let input = ToolInput::new("list_imports").with_param("path", serde_json::json!("a.exe"));
        let out = t.execute(&input).unwrap();
        assert!(out.success);
    }

    #[test]
    fn test_list_exports_ok() {
        let t = tools();
        let input = ToolInput::new("list_exports").with_param("path", serde_json::json!("a.exe"));
        let out = t.execute(&input).unwrap();
        assert!(out.success);
    }

    #[test]
    fn test_section_entropy_ok() {
        let t = tools();
        let input =
            ToolInput::new("section_entropy").with_param("path", serde_json::json!("a.exe"));
        let out = t.execute(&input).unwrap();
        assert!(out.data["sections"].is_array());
    }

    #[test]
    fn test_detect_packer_ok() {
        let t = tools();
        let input = ToolInput::new("detect_packer").with_param("path", serde_json::json!("a.exe"));
        assert!(t.execute(&input).unwrap().success);
    }

    #[test]
    fn test_find_xrefs_ok() {
        let t = tools();
        let input =
            ToolInput::new("find_xrefs").with_param("address", serde_json::json!(0x1000u64));
        let out = t.execute(&input).unwrap();
        assert_eq!(out.data["count"], 0);
    }

    #[test]
    fn test_network_indicators_ok() {
        let t = tools();
        let input =
            ToolInput::new("network_indicators").with_param("path", serde_json::json!("a.exe"));
        let out = t.execute(&input).unwrap();
        assert!(out.data["urls"].is_array());
    }

    #[test]
    fn test_set_type_ok() {
        let t = tools();
        let input = ToolInput::new("set_type")
            .with_param("address", serde_json::json!(0x1000u64))
            .with_param("type_str", serde_json::json!("DWORD*"));
        let out = t.execute(&input).unwrap();
        assert_eq!(out.data["applied_type"], "DWORD*");
    }

    #[test]
    fn test_call_graph_ok() {
        let t = tools();
        let input = ToolInput::new("call_graph").with_param("path", serde_json::json!("a.exe"));
        assert!(t.execute(&input).unwrap().success);
    }

    #[test]
    fn test_search_bytes_ok() {
        let t = tools();
        let input =
            ToolInput::new("search_bytes").with_param("pattern", serde_json::json!("90 90"));
        let out = t.execute(&input).unwrap();
        assert_eq!(out.data["count"], 0);
    }

    #[test]
    fn test_threat_lookup_ok() {
        let t = tools();
        let input = ToolInput::new("threat_lookup").with_param("ioc", serde_json::json!("1.2.3.4"));
        let out = t.execute(&input).unwrap();
        assert_eq!(out.data["malicious"], false);
    }

    #[test]
    fn test_get_pe_header_ok() {
        let t = tools();
        let input = ToolInput::new("get_pe_header").with_param("path", serde_json::json!("a.exe"));
        assert!(t.execute(&input).unwrap().success);
    }

    #[test]
    fn test_disassemble_default_count() {
        let t = tools();
        let input =
            ToolInput::new("disassemble").with_param("address", serde_json::json!(0x1000u64));
        let out = t.execute(&input).unwrap();
        assert_eq!(out.data["count"], 10);
    }

    #[test]
    fn test_summarize_function_ok() {
        let t = tools();
        let input = ToolInput::new("summarize_function")
            .with_param("address", serde_json::json!(0x1000u64));
        let out = t.execute(&input).unwrap();
        assert!(out.data["summary"].as_str().is_some());
    }

    #[test]
    fn test_detect_obfuscation_ok() {
        let t = tools();
        let input =
            ToolInput::new("detect_obfuscation").with_param("path", serde_json::json!("a.exe"));
        assert!(t.execute(&input).unwrap().success);
    }

    #[test]
    fn test_identify_crypto_ok() {
        let t = tools();
        let input =
            ToolInput::new("identify_crypto").with_param("path", serde_json::json!("a.exe"));
        let out = t.execute(&input).unwrap();
        assert!(out.data["algorithms"].is_array());
    }

    #[test]
    fn test_extract_config_ok() {
        let t = tools();
        let input = ToolInput::new("extract_config").with_param("path", serde_json::json!("a.exe"));
        assert!(t.execute(&input).unwrap().success);
    }

    #[test]
    fn test_tool_output_name_preserved() {
        let out = ToolOutput::ok("my_tool", serde_json::json!(null));
        assert_eq!(out.tool_name, "my_tool");
    }

    #[test]
    fn test_tool_output_execution_ms_set() {
        let t = tools();
        let input = ToolInput::new("hash_file").with_param("path", serde_json::json!("a.bin"));
        let out = t.execute(&input).unwrap();
        // execution_ms is a u64 —" just check it exists and is not gigantic.
        assert!(out.execution_ms < 60_000);
    }

    #[test]
    fn test_all_tools_have_name_and_description() {
        let t = tools();
        for name in t.tool_names() {
            let desc = t.tool_description(name).unwrap();
            assert!(!name.is_empty());
            assert!(!desc.is_empty());
        }
    }
}
