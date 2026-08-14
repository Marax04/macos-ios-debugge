//! `re_workflows` — Built-in RE workflow template library.
//!
//! Provides [`ReWorkflows`], 20+ named workflow templates for common RE tasks,
//! [`WorkflowStep`], [`WorkflowParam`], and helpers to list, search, and
//! instantiate named templates.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ───────────────────────────────────────────────────────────────────

/// Errors produced by the RE workflow template subsystem.
#[derive(Debug, Error)]
pub enum ReWorkflowError {
    #[error("workflow template '{0}' not found")]
    NotFound(String),

    #[error("missing required parameter '{0}' for template '{1}'")]
    MissingParam(String, String),

    #[error("invalid parameter value '{param}' = '{value}': {reason}")]
    InvalidParam {
        param: String,
        value: String,
        reason: String,
    },

    #[error("template instantiation failed: {0}")]
    Instantiation(String),
}

// ─── WorkflowParam ────────────────────────────────────────────────────────────

/// Parameter type for a workflow template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParamType {
    String,
    Integer,
    Boolean,
    FilePath,
    Address,
    YaraRule,
    Custom(String),
}

impl std::fmt::Display for ParamType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "custom:{s}"),
            _ => write!(f, "{self:?}"),
        }
    }
}

/// A declared parameter for a workflow template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowParam {
    pub name: String,
    pub param_type: ParamType,
    pub required: bool,
    pub default_value: Option<serde_json::Value>,
    pub description: String,
}

impl WorkflowParam {
    #[must_use]
    pub fn required(
        name: impl Into<String>,
        param_type: ParamType,
        desc: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            param_type,
            required: true,
            default_value: None,
            description: desc.into(),
        }
    }

    #[must_use]
    pub fn optional(
        name: impl Into<String>,
        param_type: ParamType,
        default: serde_json::Value,
        desc: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            param_type,
            required: false,
            default_value: Some(default),
            description: desc.into(),
        }
    }
}

// ─── WorkflowStep ────────────────────────────────────────────────────────────

/// A single step within a workflow template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub step_id: String,
    pub agent: String,
    pub description: String,
    /// Input parameter bindings: `{ agent_key: "{{param_name}}" }`.
    pub inputs: HashMap<String, String>,
    /// Output bindings: `{ output_key: variable_name }`.
    pub outputs: HashMap<String, String>,
    /// Step is optional — failure does not abort the workflow.
    pub optional: bool,
    pub max_retries: u32,
}

impl WorkflowStep {
    #[must_use]
    pub fn new(
        step_id: impl Into<String>,
        agent: impl Into<String>,
        desc: impl Into<String>,
    ) -> Self {
        Self {
            step_id: step_id.into(),
            agent: agent.into(),
            description: desc.into(),
            inputs: HashMap::new(),
            outputs: HashMap::new(),
            optional: false,
            max_retries: 1,
        }
    }

    #[must_use]
    pub fn with_input(mut self, key: impl Into<String>, binding: impl Into<String>) -> Self {
        self.inputs.insert(key.into(), binding.into());
        self
    }

    #[must_use]
    pub fn with_output(mut self, key: impl Into<String>, var: impl Into<String>) -> Self {
        self.outputs.insert(key.into(), var.into());
        self
    }

    #[must_use]
    pub const fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    #[must_use]
    pub const fn with_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }
}

// ─── WorkflowTemplate ────────────────────────────────────────────────────────

/// A named, parameterised workflow template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowTemplate {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub category: String,
    pub params: Vec<WorkflowParam>,
    pub steps: Vec<WorkflowStep>,
    pub tags: Vec<String>,
    pub version: String,
    pub estimated_minutes: u32,
}

impl WorkflowTemplate {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        display_name: impl Into<String>,
        description: impl Into<String>,
        category: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            display_name: display_name.into(),
            description: description.into(),
            category: category.into(),
            params: Vec::new(),
            steps: Vec::new(),
            tags: Vec::new(),
            version: "1.0.0".to_string(),
            estimated_minutes: 5,
        }
    }

    #[must_use]
    pub fn with_param(mut self, p: WorkflowParam) -> Self {
        self.params.push(p);
        self
    }

    #[must_use]
    pub fn with_step(mut self, s: WorkflowStep) -> Self {
        self.steps.push(s);
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    #[must_use]
    pub const fn with_est(mut self, minutes: u32) -> Self {
        self.estimated_minutes = minutes;
        self
    }

    /// Validate that all required params are provided.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn validate_params(
        &self,
        params: &HashMap<String, serde_json::Value>,
    ) -> Result<(), ReWorkflowError> {
        for p in &self.params {
            if p.required && !params.contains_key(&p.name) {
                return Err(ReWorkflowError::MissingParam(
                    p.name.clone(),
                    self.name.clone(),
                ));
            }
        }
        Ok(())
    }

    /// Instantiate the template with `params`, returning a filled variable map.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn instantiate(
        &self,
        params: HashMap<String, serde_json::Value>,
    ) -> Result<HashMap<String, serde_json::Value>, ReWorkflowError> {
        self.validate_params(&params)?;
        let mut vars = HashMap::new();
        for p in &self.params {
            if let Some(v) = params.get(&p.name) {
                vars.insert(p.name.clone(), v.clone());
            } else if let Some(def) = &p.default_value {
                vars.insert(p.name.clone(), def.clone());
            }
        }
        // Merge any extra provided values
        for (k, v) in params {
            vars.entry(k).or_insert(v);
        }
        Ok(vars)
    }
}

// ─── ReWorkflows ─────────────────────────────────────────────────────────────

/// Registry and factory for all built-in RE workflow templates.
pub struct ReWorkflows {
    templates: HashMap<String, WorkflowTemplate>,
}

impl ReWorkflows {
    /// Create and populate the registry with all built-in templates.
    #[must_use]
    pub fn new() -> Self {
        let mut wf = Self {
            templates: HashMap::new(),
        };
        for t in builtin_templates() {
            wf.templates.insert(t.name.clone(), t);
        }
        wf
    }

    /// Total number of registered templates.
    #[must_use]
    pub fn count(&self) -> usize {
        self.templates.len()
    }

    /// Look up a template by its short name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&WorkflowTemplate> {
        self.templates.get(name)
    }

    /// List all template names.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.templates.keys().cloned().collect();
        names.sort();
        names
    }

    /// List templates in a given category.
    #[must_use]
    pub fn by_category(&self, category: &str) -> Vec<&WorkflowTemplate> {
        self.templates
            .values()
            .filter(|t| t.category == category)
            .collect()
    }

    /// Search templates by keyword in name, description, or tags.
    #[must_use]
    pub fn search(&self, keyword: &str) -> Vec<&WorkflowTemplate> {
        let kw = keyword.to_lowercase();
        self.templates
            .values()
            .filter(|t| {
                t.name.to_lowercase().contains(&kw)
                    || t.description.to_lowercase().contains(&kw)
                    || t.tags.iter().any(|tag| tag.to_lowercase().contains(&kw))
            })
            .collect()
    }

    /// Register a custom template.
    pub fn register(&mut self, template: WorkflowTemplate) {
        self.templates.insert(template.name.clone(), template);
    }

    /// Instantiate a named template with provided parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn instantiate(
        &self,
        name: &str,
        params: HashMap<String, serde_json::Value>,
    ) -> Result<HashMap<String, serde_json::Value>, ReWorkflowError> {
        let template = self
            .templates
            .get(name)
            .ok_or_else(|| ReWorkflowError::NotFound(name.to_string()))?;
        template.instantiate(params)
    }

    /// Return all available category names.
    #[must_use]
    pub fn categories(&self) -> Vec<String> {
        let mut cats: Vec<String> = self
            .templates
            .values()
            .map(|t| t.category.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        cats.sort();
        cats
    }
}

impl Default for ReWorkflows {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Built-in templates ───────────────────────────────────────────────────────

/// Returns all 20+ built-in RE workflow templates.
fn builtin_templates() -> Vec<WorkflowTemplate> {
    vec![
        // 1
        WorkflowTemplate::new(
            "analyze_malware",
            "Analyze Malware",
            "Full malware analysis: load, triage, YARA, TI lookup, decompile key functions.",
            "malware",
        )
        .with_param(WorkflowParam::required(
            "binary_path",
            ParamType::FilePath,
            "Path to the malware sample",
        ))
        .with_param(WorkflowParam::optional(
            "yara_rules_dir",
            ParamType::FilePath,
            serde_json::json!("/opt/yara-rules"),
            "YARA rules directory",
        ))
        .with_step(
            WorkflowStep::new("load", "loader-agent", "Load binary")
                .with_input("binary_path", "{{binary_path}}")
                .with_output("result", "load_result"),
        )
        .with_step(
            WorkflowStep::new("triage", "triage-agent", "Run triage analysis")
                .with_output("result", "triage_result"),
        )
        .with_step(
            WorkflowStep::new("yara", "yara-agent", "YARA scan")
                .with_input("rules_dir", "{{yara_rules_dir}}")
                .with_output("result", "yara_matches")
                .with_retries(2),
        )
        .with_step(
            WorkflowStep::new("ti_lookup", "ti-agent", "Threat intel lookup")
                .with_input("iocs", "yara_matches")
                .with_output("result", "ti_result")
                .optional()
                .with_retries(3),
        )
        .with_step(
            WorkflowStep::new("decompile", "decomp-agent", "Decompile key functions")
                .with_output("result", "decompiled"),
        )
        .with_step(
            WorkflowStep::new("report", "report-agent", "Generate malware report")
                .with_output("result", "final_report"),
        )
        .with_tag("malware")
        .with_tag("triage")
        .with_est(15),
        // 2
        WorkflowTemplate::new(
            "reverse_function",
            "Reverse Single Function",
            "Decompile a single function and generate rename suggestions.",
            "decompilation",
        )
        .with_param(WorkflowParam::required(
            "binary_path",
            ParamType::FilePath,
            "Binary path",
        ))
        .with_param(WorkflowParam::required(
            "address",
            ParamType::Address,
            "Function address (hex)",
        ))
        .with_step(
            WorkflowStep::new("decompile", "decomp-agent", "Decompile function")
                .with_input("binary_path", "{{binary_path}}")
                .with_input("address", "{{address}}")
                .with_output("result", "decompiled"),
        )
        .with_step(
            WorkflowStep::new("rename", "rename-agent", "Suggest renames")
                .with_input("code", "decompiled")
                .with_output("result", "rename_suggestions"),
        )
        .with_step(
            WorkflowStep::new("comment", "comment-agent", "Add inline comments")
                .with_input("code", "decompiled")
                .with_output("result", "commented_code")
                .optional(),
        )
        .with_tag("decompile")
        .with_tag("rename")
        .with_est(3),
        // 3
        WorkflowTemplate::new(
            "identify_crypto",
            "Identify Cryptographic Primitives",
            "Scan a binary for known cryptographic constants and algorithms.",
            "crypto",
        )
        .with_param(WorkflowParam::required(
            "binary_path",
            ParamType::FilePath,
            "Binary to analyse",
        ))
        .with_step(
            WorkflowStep::new("load", "loader-agent", "Load binary")
                .with_input("binary_path", "{{binary_path}}")
                .with_output("result", "load_result"),
        )
        .with_step(
            WorkflowStep::new("crypto_scan", "crypto-agent", "Scan for crypto constants")
                .with_output("result", "crypto_hits"),
        )
        .with_step(
            WorkflowStep::new("entropy", "entropy-agent", "Entropy analysis")
                .with_output("result", "entropy_map")
                .optional(),
        )
        .with_step(
            WorkflowStep::new("report", "report-agent", "Report crypto findings")
                .with_input("crypto", "crypto_hits")
                .with_output("result", "crypto_report"),
        )
        .with_tag("crypto")
        .with_tag("constants")
        .with_est(5),
        // 4
        WorkflowTemplate::new(
            "find_vulns",
            "Find Vulnerabilities",
            "Systematic vulnerability hunt: decompile all functions, run pattern matching.",
            "vulnerability",
        )
        .with_param(WorkflowParam::required(
            "binary_path",
            ParamType::FilePath,
            "Binary to scan",
        ))
        .with_param(WorkflowParam::optional(
            "severity_threshold",
            ParamType::String,
            serde_json::json!("medium"),
            "Minimum severity to report",
        ))
        .with_step(
            WorkflowStep::new("load", "loader-agent", "Load")
                .with_input("binary_path", "{{binary_path}}")
                .with_output("result", "load_result"),
        )
        .with_step(
            WorkflowStep::new("decompile_all", "decomp-agent", "Decompile all functions")
                .with_output("result", "all_code"),
        )
        .with_step(
            WorkflowStep::new(
                "vuln_patterns",
                "vuln-agent",
                "Pattern matching for vulnerabilities",
            )
            .with_input("code", "all_code")
            .with_output("result", "vuln_findings")
            .with_retries(2),
        )
        .with_step(
            WorkflowStep::new("malfind", "forensics-agent", "Forensics malfind")
                .with_output("result", "malfind_result")
                .optional(),
        )
        .with_step(
            WorkflowStep::new("report", "report-agent", "Vulnerability report")
                .with_output("result", "vuln_report"),
        )
        .with_tag("vulnerability")
        .with_tag("security")
        .with_est(20),
        // 5
        WorkflowTemplate::new(
            "unpack_binary",
            "Unpack Packed Binary",
            "Detect packers, emulate unpack stub, dump unpacked image.",
            "unpacking",
        )
        .with_param(WorkflowParam::required(
            "binary_path",
            ParamType::FilePath,
            "Packed binary",
        ))
        .with_param(WorkflowParam::optional(
            "output_dir",
            ParamType::FilePath,
            serde_json::json!("/tmp/unpacked"),
            "Output directory",
        ))
        .with_step(
            WorkflowStep::new("detect_packer", "packer-agent", "Detect packer")
                .with_input("binary_path", "{{binary_path}}")
                .with_output("result", "packer_info"),
        )
        .with_step(
            WorkflowStep::new("emulate", "emu-agent", "Emulate unpack stub")
                .with_input("binary_path", "{{binary_path}}")
                .with_output("result", "emulation_log"),
        )
        .with_step(
            WorkflowStep::new("dump", "dumper-agent", "Dump unpacked image")
                .with_input("output_dir", "{{output_dir}}")
                .with_output("result", "dump_path"),
        )
        .with_step(
            WorkflowStep::new("reload", "loader-agent", "Reload unpacked binary")
                .with_input("binary_path", "dump_path")
                .with_output("result", "reload_result"),
        )
        .with_tag("packer")
        .with_tag("unpack")
        .with_est(10),
        // 6
        WorkflowTemplate::new(
            "document_api",
            "Document Public API",
            "Generate documentation for all exported functions.",
            "documentation",
        )
        .with_param(WorkflowParam::required(
            "binary_path",
            ParamType::FilePath,
            "Binary with exports",
        ))
        .with_step(
            WorkflowStep::new("load", "loader-agent", "Load binary")
                .with_input("binary_path", "{{binary_path}}")
                .with_output("result", "load_result"),
        )
        .with_step(
            WorkflowStep::new("list_exports", "symbols-agent", "List exports")
                .with_output("result", "export_list"),
        )
        .with_step(
            WorkflowStep::new("decompile_exports", "decomp-agent", "Decompile exports")
                .with_input("functions", "export_list")
                .with_output("result", "decompiled_exports"),
        )
        .with_step(
            WorkflowStep::new("generate_docs", "doc-agent", "Generate documentation")
                .with_input("code", "decompiled_exports")
                .with_output("result", "api_docs"),
        )
        .with_tag("documentation")
        .with_tag("api")
        .with_est(12),
        // 7
        WorkflowTemplate::new(
            "binary_diff",
            "Binary Diff",
            "Diff two binary versions and highlight changes.",
            "diff",
        )
        .with_param(WorkflowParam::required(
            "binary_a",
            ParamType::FilePath,
            "First binary",
        ))
        .with_param(WorkflowParam::required(
            "binary_b",
            ParamType::FilePath,
            "Second binary",
        ))
        .with_param(WorkflowParam::optional(
            "threshold",
            ParamType::String,
            serde_json::json!("0.8"),
            "Similarity threshold",
        ))
        .with_step(
            WorkflowStep::new("load_a", "loader-agent", "Load binary A")
                .with_input("binary_path", "{{binary_a}}")
                .with_output("result", "load_a"),
        )
        .with_step(
            WorkflowStep::new("load_b", "loader-agent", "Load binary B")
                .with_input("binary_path", "{{binary_b}}")
                .with_output("result", "load_b"),
        )
        .with_step(
            WorkflowStep::new("diff", "diff-agent", "Compute diff")
                .with_input("threshold", "{{threshold}}")
                .with_output("result", "diff_result"),
        )
        .with_step(
            WorkflowStep::new("report", "report-agent", "Diff report")
                .with_output("result", "diff_report"),
        )
        .with_tag("diff")
        .with_est(8),
        // 8
        WorkflowTemplate::new(
            "firmware_analysis",
            "Firmware Analysis",
            "Extract and analyse embedded firmware: strings, functions, crypto, vulns.",
            "firmware",
        )
        .with_param(WorkflowParam::required(
            "firmware_path",
            ParamType::FilePath,
            "Firmware image",
        ))
        .with_step(
            WorkflowStep::new("extract", "firmware-agent", "Extract filesystem")
                .with_input("binary_path", "{{firmware_path}}")
                .with_output("result", "extracted_path"),
        )
        .with_step(
            WorkflowStep::new("strings", "strings-agent", "Extract strings")
                .with_output("result", "strings_result"),
        )
        .with_step(
            WorkflowStep::new("crypto", "crypto-agent", "Identify crypto")
                .with_output("result", "crypto_findings"),
        )
        .with_step(
            WorkflowStep::new("vuln_scan", "vuln-agent", "Vulnerability scan")
                .with_output("result", "vuln_findings")
                .with_retries(2),
        )
        .with_step(
            WorkflowStep::new("report", "report-agent", "Firmware report")
                .with_output("result", "fw_report"),
        )
        .with_tag("firmware")
        .with_tag("iot")
        .with_est(25),
        // 9
        WorkflowTemplate::new(
            "detect_obfuscation",
            "Detect Obfuscation",
            "Identify obfuscation techniques: MBA, opaque predicates, string encryption.",
            "obfuscation",
        )
        .with_param(WorkflowParam::required(
            "binary_path",
            ParamType::FilePath,
            "Binary to analyse",
        ))
        .with_step(
            WorkflowStep::new("load", "loader-agent", "Load binary")
                .with_input("binary_path", "{{binary_path}}")
                .with_output("result", "load_result"),
        )
        .with_step(
            WorkflowStep::new("mba_detect", "deobf-agent", "Detect MBA")
                .with_output("result", "mba_findings")
                .optional(),
        )
        .with_step(
            WorkflowStep::new("opaque_detect", "deobf-agent", "Detect opaque predicates")
                .with_output("result", "opaque_findings")
                .optional(),
        )
        .with_step(
            WorkflowStep::new("string_deobf", "deobf-agent", "Decrypt strings")
                .with_output("result", "decrypted_strings")
                .optional(),
        )
        .with_step(
            WorkflowStep::new("report", "report-agent", "Obfuscation report")
                .with_output("result", "deobf_report"),
        )
        .with_tag("obfuscation")
        .with_tag("deobf")
        .with_est(15),
        // 10
        WorkflowTemplate::new(
            "ctf_challenge",
            "CTF Challenge Solver",
            "Quick workflow for CTF binary challenges: flags, crypto, ROP chains.",
            "ctf",
        )
        .with_param(WorkflowParam::required(
            "binary_path",
            ParamType::FilePath,
            "CTF binary",
        ))
        .with_param(WorkflowParam::optional(
            "hint",
            ParamType::String,
            serde_json::json!(""),
            "Optional hint",
        ))
        .with_step(
            WorkflowStep::new("load", "loader-agent", "Load binary")
                .with_input("binary_path", "{{binary_path}}")
                .with_output("result", "load_result"),
        )
        .with_step(
            WorkflowStep::new("strings", "strings-agent", "Extract strings for flags")
                .with_output("result", "strings_result"),
        )
        .with_step(
            WorkflowStep::new("rop_gadgets", "rop-agent", "Find ROP gadgets")
                .with_output("result", "rop_chain")
                .optional(),
        )
        .with_step(
            WorkflowStep::new("decompile", "decomp-agent", "Decompile main")
                .with_output("result", "main_code"),
        )
        .with_step(
            WorkflowStep::new("solve", "ctf-agent", "Attempt flag recovery")
                .with_input("hint", "{{hint}}")
                .with_output("result", "flag_candidates"),
        )
        .with_tag("ctf")
        .with_tag("pwn")
        .with_est(5),
        // 11
        WorkflowTemplate::new(
            "shellcode_analysis",
            "Shellcode Analysis",
            "Disassemble and emulate shellcode, extract IOCs.",
            "shellcode",
        )
        .with_param(WorkflowParam::required(
            "shellcode_path",
            ParamType::FilePath,
            "Raw shellcode file",
        ))
        .with_param(WorkflowParam::optional(
            "arch",
            ParamType::String,
            serde_json::json!("x86_64"),
            "Target architecture",
        ))
        .with_step(
            WorkflowStep::new("disasm", "disasm-agent", "Disassemble shellcode")
                .with_input("binary_path", "{{shellcode_path}}")
                .with_input("arch", "{{arch}}")
                .with_output("result", "disassembly"),
        )
        .with_step(
            WorkflowStep::new("emulate", "emu-agent", "Emulate shellcode")
                .with_output("result", "emulation_log"),
        )
        .with_step(
            WorkflowStep::new("ioc_extract", "ioc-agent", "Extract IOCs")
                .with_output("result", "iocs"),
        )
        .with_step(
            WorkflowStep::new("report", "report-agent", "Shellcode report")
                .with_output("result", "sc_report"),
        )
        .with_tag("shellcode")
        .with_tag("exploit")
        .with_est(5),
        // 12
        WorkflowTemplate::new(
            "string_deobfuscation",
            "String Deobfuscation",
            "Identify and decrypt obfuscated strings in a binary.",
            "obfuscation",
        )
        .with_param(WorkflowParam::required(
            "binary_path",
            ParamType::FilePath,
            "Binary",
        ))
        .with_step(
            WorkflowStep::new("detect", "deobf-agent", "Detect string encryption")
                .with_input("binary_path", "{{binary_path}}")
                .with_output("result", "encrypted_strings"),
        )
        .with_step(
            WorkflowStep::new("decrypt", "deobf-agent", "Decrypt strings")
                .with_input("strings", "encrypted_strings")
                .with_output("result", "decrypted"),
        )
        .with_step(
            WorkflowStep::new(
                "patch",
                "patcher-agent",
                "Patch binary with decrypted strings",
            )
            .with_input("strings", "decrypted")
            .with_output("result", "patched_path")
            .optional(),
        )
        .with_tag("strings")
        .with_tag("obfuscation")
        .with_est(7),
        // 13
        WorkflowTemplate::new(
            "type_recovery",
            "Type Recovery",
            "Recover data types and structures from binary.",
            "type-analysis",
        )
        .with_param(WorkflowParam::required(
            "binary_path",
            ParamType::FilePath,
            "Binary",
        ))
        .with_step(
            WorkflowStep::new("load", "loader-agent", "Load binary")
                .with_input("binary_path", "{{binary_path}}")
                .with_output("result", "load_result"),
        )
        .with_step(
            WorkflowStep::new("type_recover", "type-agent", "Recover types")
                .with_output("result", "type_defs"),
        )
        .with_step(
            WorkflowStep::new("propagate", "type-agent", "Propagate type info")
                .with_input("types", "type_defs")
                .with_output("result", "propagated_types"),
        )
        .with_step(
            WorkflowStep::new("export_headers", "export-agent", "Export as C headers")
                .with_output("result", "header_file")
                .optional(),
        )
        .with_tag("types")
        .with_tag("struct")
        .with_est(8),
        // 14
        WorkflowTemplate::new(
            "network_protocol_re",
            "Network Protocol RE",
            "Reverse engineer a network protocol from a binary.",
            "network",
        )
        .with_param(WorkflowParam::required(
            "binary_path",
            ParamType::FilePath,
            "Binary",
        ))
        .with_param(WorkflowParam::optional(
            "pcap_path",
            ParamType::FilePath,
            serde_json::json!(""),
            "Optional PCAP for correlation",
        ))
        .with_step(
            WorkflowStep::new("load", "loader-agent", "Load binary")
                .with_input("binary_path", "{{binary_path}}")
                .with_output("result", "load_result"),
        )
        .with_step(
            WorkflowStep::new("find_parsers", "net-agent", "Find protocol parsers")
                .with_output("result", "parsers"),
        )
        .with_step(
            WorkflowStep::new("decompile_parsers", "decomp-agent", "Decompile parsers")
                .with_input("functions", "parsers")
                .with_output("result", "parser_code"),
        )
        .with_step(
            WorkflowStep::new("correlate_pcap", "net-agent", "Correlate with PCAP")
                .with_input("pcap", "{{pcap_path}}")
                .with_output("result", "pcap_correlation")
                .optional(),
        )
        .with_step(
            WorkflowStep::new("document_proto", "doc-agent", "Document protocol")
                .with_output("result", "proto_doc"),
        )
        .with_tag("network")
        .with_tag("protocol")
        .with_est(20),
        // 15
        WorkflowTemplate::new(
            "exploit_dev",
            "Exploit Development Assistance",
            "Identify exploitable conditions and assist with PoC development.",
            "exploit",
        )
        .with_param(WorkflowParam::required(
            "binary_path",
            ParamType::FilePath,
            "Vulnerable binary",
        ))
        .with_step(
            WorkflowStep::new("vuln_find", "vuln-agent", "Find vulnerabilities")
                .with_input("binary_path", "{{binary_path}}")
                .with_output("result", "vulns"),
        )
        .with_step(
            WorkflowStep::new("rop_gadgets", "rop-agent", "Find ROP gadgets")
                .with_output("result", "rop_chain"),
        )
        .with_step(
            WorkflowStep::new(
                "exploit_template",
                "exploit-agent",
                "Generate exploit template",
            )
            .with_input("vulns", "vulns")
            .with_input("rop", "rop_chain")
            .with_output("result", "exploit_template"),
        )
        .with_step(
            WorkflowStep::new("test_exploit", "fuzz-agent", "Validate exploit template")
                .with_output("result", "exploit_result")
                .optional(),
        )
        .with_tag("exploit")
        .with_tag("vulnerability")
        .with_est(30),
        // 16
        WorkflowTemplate::new(
            "android_apk_analysis",
            "Android APK Analysis",
            "Decompile APK, analyse manifest, find sensitive data.",
            "mobile",
        )
        .with_param(WorkflowParam::required(
            "apk_path",
            ParamType::FilePath,
            "APK file",
        ))
        .with_step(
            WorkflowStep::new("extract", "apktool-agent", "Extract APK")
                .with_input("binary_path", "{{apk_path}}")
                .with_output("result", "extracted"),
        )
        .with_step(
            WorkflowStep::new("decompile", "jadx-agent", "Decompile to Java")
                .with_output("result", "java_source"),
        )
        .with_step(
            WorkflowStep::new("manifest", "android-agent", "Parse manifest")
                .with_output("result", "manifest_findings"),
        )
        .with_step(
            WorkflowStep::new("sensitive_data", "strings-agent", "Find sensitive data")
                .with_output("result", "sensitive_strings"),
        )
        .with_step(
            WorkflowStep::new("report", "report-agent", "APK report")
                .with_output("result", "apk_report"),
        )
        .with_tag("android")
        .with_tag("mobile")
        .with_tag("apk")
        .with_est(10),
        // 17
        WorkflowTemplate::new(
            "ios_ipa_analysis",
            "iOS IPA Analysis",
            "Analyse iOS IPA: dyld, entitlements, sensitive data.",
            "mobile",
        )
        .with_param(WorkflowParam::required(
            "ipa_path",
            ParamType::FilePath,
            "IPA file",
        ))
        .with_step(
            WorkflowStep::new("extract", "ipa-agent", "Extract IPA")
                .with_input("binary_path", "{{ipa_path}}")
                .with_output("result", "extracted"),
        )
        .with_step(
            WorkflowStep::new("entitlements", "ios-agent", "Parse entitlements")
                .with_output("result", "entitlements"),
        )
        .with_step(
            WorkflowStep::new("decompile", "decomp-agent", "Decompile ObjC/Swift")
                .with_output("result", "decompiled"),
        )
        .with_step(
            WorkflowStep::new("report", "report-agent", "IPA report")
                .with_output("result", "ipa_report"),
        )
        .with_tag("ios")
        .with_tag("mobile")
        .with_tag("ipa")
        .with_est(10),
        // 18
        WorkflowTemplate::new(
            "kernel_module_analysis",
            "Kernel Module Analysis",
            "Analyse a kernel module/driver for vulnerabilities.",
            "kernel",
        )
        .with_param(WorkflowParam::required(
            "module_path",
            ParamType::FilePath,
            "Kernel module (.ko/.sys)",
        ))
        .with_step(
            WorkflowStep::new("load", "loader-agent", "Load module")
                .with_input("binary_path", "{{module_path}}")
                .with_output("result", "load_result"),
        )
        .with_step(
            WorkflowStep::new("find_ioctls", "kernel-agent", "Find IOCTL handlers")
                .with_output("result", "ioctls"),
        )
        .with_step(
            WorkflowStep::new(
                "decompile_ioctls",
                "decomp-agent",
                "Decompile IOCTL handlers",
            )
            .with_input("functions", "ioctls")
            .with_output("result", "ioctl_code"),
        )
        .with_step(
            WorkflowStep::new("vuln_scan", "vuln-agent", "Scan for kernel vulns")
                .with_input("code", "ioctl_code")
                .with_output("result", "kernel_vulns")
                .with_retries(2),
        )
        .with_step(
            WorkflowStep::new("report", "report-agent", "Kernel vulnerability report")
                .with_output("result", "kernel_report"),
        )
        .with_tag("kernel")
        .with_tag("driver")
        .with_tag("vulnerability")
        .with_est(20),
        // 19
        WorkflowTemplate::new(
            "ransomware_analysis",
            "Ransomware Analysis",
            "Identify encryption keys, file targeting, and C2 of ransomware.",
            "malware",
        )
        .with_param(WorkflowParam::required(
            "binary_path",
            ParamType::FilePath,
            "Ransomware sample",
        ))
        .with_step(
            WorkflowStep::new("load", "loader-agent", "Load sample")
                .with_input("binary_path", "{{binary_path}}")
                .with_output("result", "load_result"),
        )
        .with_step(
            WorkflowStep::new("crypto_id", "crypto-agent", "Identify encryption")
                .with_output("result", "crypto_info"),
        )
        .with_step(
            WorkflowStep::new("c2_extract", "net-agent", "Extract C2 indicators")
                .with_output("result", "c2_iocs"),
        )
        .with_step(
            WorkflowStep::new(
                "file_target",
                "strings-agent",
                "Find targeted file extensions",
            )
            .with_output("result", "targeted_exts"),
        )
        .with_step(
            WorkflowStep::new("key_material", "crypto-agent", "Extract key material")
                .with_output("result", "key_material")
                .optional(),
        )
        .with_step(
            WorkflowStep::new("report", "report-agent", "Ransomware report")
                .with_output("result", "ransomware_report"),
        )
        .with_tag("ransomware")
        .with_tag("malware")
        .with_tag("crypto")
        .with_est(20),
        // 20
        WorkflowTemplate::new(
            "signature_generation",
            "YARA Signature Generation",
            "Generate YARA signatures from malware characteristics.",
            "signatures",
        )
        .with_param(WorkflowParam::required(
            "binary_path",
            ParamType::FilePath,
            "Binary to generate signatures for",
        ))
        .with_param(WorkflowParam::optional(
            "output_path",
            ParamType::FilePath,
            serde_json::json!("/tmp/signatures.yar"),
            "Output YARA file",
        ))
        .with_step(
            WorkflowStep::new("strings", "strings-agent", "Extract unique strings")
                .with_input("binary_path", "{{binary_path}}")
                .with_output("result", "unique_strings"),
        )
        .with_step(
            WorkflowStep::new("flirt", "flirt-agent", "Generate FLIRT signatures")
                .with_output("result", "flirt_sigs")
                .optional(),
        )
        .with_step(
            WorkflowStep::new("generate_yara", "yara-gen-agent", "Generate YARA rules")
                .with_input("strings", "unique_strings")
                .with_output("result", "yara_rules"),
        )
        .with_step(
            WorkflowStep::new("validate_yara", "yara-agent", "Validate YARA rules")
                .with_input("rules", "yara_rules")
                .with_output("result", "validation_result"),
        )
        .with_step(
            WorkflowStep::new("save", "file-agent", "Save signatures")
                .with_input("path", "{{output_path}}")
                .with_input("content", "yara_rules")
                .with_output("result", "save_result"),
        )
        .with_tag("yara")
        .with_tag("signature")
        .with_tag("detection")
        .with_est(8),
        // 21
        WorkflowTemplate::new(
            "dotnet_analysis",
            ".NET Assembly Analysis",
            "Decompile and analyse .NET assemblies.",
            "dotnet",
        )
        .with_param(WorkflowParam::required(
            "assembly_path",
            ParamType::FilePath,
            ".NET assembly (.exe/.dll)",
        ))
        .with_step(
            WorkflowStep::new("load", "loader-agent", "Load assembly")
                .with_input("binary_path", "{{assembly_path}}")
                .with_output("result", "load_result"),
        )
        .with_step(
            WorkflowStep::new("metadata", "dotnet-agent", "Parse .NET metadata")
                .with_output("result", "metadata"),
        )
        .with_step(
            WorkflowStep::new("decompile_il", "dotnet-decomp-agent", "Decompile IL to C#")
                .with_output("result", "csharp_source"),
        )
        .with_step(
            WorkflowStep::new("vuln_scan", "vuln-agent", "Scan for vulnerabilities")
                .with_input("code", "csharp_source")
                .with_output("result", "dotnet_vulns"),
        )
        .with_step(
            WorkflowStep::new("report", "report-agent", ".NET analysis report")
                .with_output("result", "dotnet_report"),
        )
        .with_tag("dotnet")
        .with_tag("csharp")
        .with_tag("il")
        .with_est(10),
    ]
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn wf() -> ReWorkflows {
        ReWorkflows::new()
    }

    // ── ReWorkflows count/names ───────────────────────────────────────────────

    #[test]
    fn test_re_workflows_count_ge_20() {
        assert!(
            wf().count() >= 20,
            "expected at least 20 templates, got {}",
            wf().count()
        );
    }

    #[test]
    fn test_re_workflows_names_sorted() {
        let names = wf().names();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    // ── Template lookup ───────────────────────────────────────────────────────

    #[test]
    fn test_get_analyze_malware() {
        let w = wf();
        let t = w.get("analyze_malware").unwrap();
        assert_eq!(t.category, "malware");
        assert!(!t.steps.is_empty());
    }

    #[test]
    fn test_get_reverse_function() {
        let w = wf();
        let t = w.get("reverse_function").unwrap();
        assert_eq!(t.name, "reverse_function");
        assert!(t.params.iter().any(|p| p.name == "address"));
    }

    #[test]
    fn test_get_identify_crypto() {
        let w = wf();
        let t = w.get("identify_crypto").unwrap();
        assert!(t.tags.contains(&"crypto".to_string()));
    }

    #[test]
    fn test_get_find_vulns() {
        let w = wf();
        let t = w.get("find_vulns").unwrap();
        assert!(t.steps.iter().any(|s| s.step_id == "vuln_patterns"));
    }

    #[test]
    fn test_get_unpack_binary() {
        assert!(wf().get("unpack_binary").is_some());
    }

    #[test]
    fn test_get_document_api() {
        assert!(wf().get("document_api").is_some());
    }

    #[test]
    fn test_get_not_found() {
        assert!(wf().get("nonexistent").is_none());
    }

    // ── Category search ───────────────────────────────────────────────────────

    #[test]
    fn test_by_category_malware() {
        let w = wf();
        let templates = w.by_category("malware");
        assert!(templates.len() >= 2);
    }

    #[test]
    fn test_by_category_mobile() {
        let w = wf();
        let templates = w.by_category("mobile");
        assert!(templates.len() >= 2);
    }

    #[test]
    fn test_categories_non_empty() {
        let cats = wf().categories();
        assert!(!cats.is_empty());
        assert!(cats.contains(&"malware".to_string()));
    }

    // ── Keyword search ────────────────────────────────────────────────────────

    #[test]
    fn test_search_yara() {
        let w = wf();
        let results = w.search("yara");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_search_mobile() {
        let w = wf();
        let results = w.search("mobile");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_search_no_match() {
        let w = wf();
        let results = w.search("xyzzy_nonexistent_xyz");
        assert!(results.is_empty());
    }

    // ── Param validation ──────────────────────────────────────────────────────

    #[test]
    fn test_validate_params_ok() {
        let w = wf();
        let t = w.get("reverse_function").unwrap();
        let mut params = HashMap::new();
        params.insert("binary_path".to_string(), serde_json::json!("/bin/ls"));
        params.insert("address".to_string(), serde_json::json!("0x401000"));
        assert!(t.validate_params(&params).is_ok());
    }

    #[test]
    fn test_validate_params_missing_required() {
        let w = wf();
        let t = w.get("reverse_function").unwrap();
        let params = HashMap::new();
        let err = t.validate_params(&params).unwrap_err();
        assert!(matches!(err, ReWorkflowError::MissingParam(_, _)));
    }

    // ── Instantiation ─────────────────────────────────────────────────────────

    #[test]
    fn test_instantiate_with_required_params() {
        let mut params = HashMap::new();
        params.insert("binary_path".to_string(), serde_json::json!("/bin/ls"));
        params.insert("address".to_string(), serde_json::json!("0x401000"));
        let vars = wf().instantiate("reverse_function", params).unwrap();
        assert_eq!(
            vars.get("binary_path").unwrap(),
            &serde_json::json!("/bin/ls")
        );
    }

    #[test]
    fn test_instantiate_uses_defaults() {
        let mut params = HashMap::new();
        params.insert("binary_path".to_string(), serde_json::json!("/a.out"));
        let vars = wf().instantiate("analyze_malware", params).unwrap();
        // yara_rules_dir should have default
        assert!(vars.contains_key("yara_rules_dir"));
    }

    #[test]
    fn test_instantiate_not_found() {
        let err = wf().instantiate("ghost", HashMap::new()).unwrap_err();
        assert!(matches!(err, ReWorkflowError::NotFound(_)));
    }

    // ── WorkflowStep ──────────────────────────────────────────────────────────

    #[test]
    fn test_workflow_step_builder() {
        let s = WorkflowStep::new("s1", "agent-x", "desc")
            .with_input("key", "val")
            .with_output("out", "var")
            .optional()
            .with_retries(3);
        assert_eq!(s.step_id, "s1");
        assert!(s.optional);
        assert_eq!(s.max_retries, 3);
        assert_eq!(s.inputs.get("key").map(std::string::String::as_str), Some("val"));
        assert_eq!(s.outputs.get("out").map(std::string::String::as_str), Some("var"));
    }

    // ── WorkflowParam ─────────────────────────────────────────────────────────

    #[test]
    fn test_workflow_param_required() {
        let p = WorkflowParam::required("path", ParamType::FilePath, "desc");
        assert!(p.required);
        assert!(p.default_value.is_none());
    }

    #[test]
    fn test_workflow_param_optional() {
        let p = WorkflowParam::optional(
            "arch",
            ParamType::String,
            serde_json::json!("x86_64"),
            "architecture",
        );
        assert!(!p.required);
        assert_eq!(
            p.default_value.as_ref().unwrap(),
            &serde_json::json!("x86_64")
        );
    }

    #[test]
    fn test_param_type_display() {
        assert_eq!(ParamType::String.to_string(), "String");
        assert_eq!(ParamType::Custom("x".into()).to_string(), "custom:x");
    }

    // ── Custom template registration ──────────────────────────────────────────

    #[test]
    fn test_register_custom_template() {
        let mut wf = ReWorkflows::new();
        let prev = wf.count();
        let t = WorkflowTemplate::new("my_custom", "My Custom", "desc", "custom");
        wf.register(t);
        assert_eq!(wf.count(), prev + 1);
        assert!(wf.get("my_custom").is_some());
    }

    // ── All built-in workflow names present ───────────────────────────────────

    #[test]
    fn test_all_builtin_names_present() {
        let expected = [
            "analyze_malware",
            "reverse_function",
            "identify_crypto",
            "find_vulns",
            "unpack_binary",
            "document_api",
            "binary_diff",
            "firmware_analysis",
            "detect_obfuscation",
            "ctf_challenge",
            "shellcode_analysis",
            "string_deobfuscation",
            "type_recovery",
            "network_protocol_re",
            "exploit_dev",
            "android_apk_analysis",
            "ios_ipa_analysis",
            "kernel_module_analysis",
            "ransomware_analysis",
            "signature_generation",
            "dotnet_analysis",
        ];
        let wf = wf();
        for name in &expected {
            assert!(wf.get(name).is_some(), "missing template: {name}");
        }
    }

    // ── ReWorkflowError display ───────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let e = ReWorkflowError::NotFound("x".into());
        assert!(e.to_string().contains('x'));
        let e2 = ReWorkflowError::MissingParam("p".into(), "t".into());
        assert!(e2.to_string().contains('p'));
        let e3 = ReWorkflowError::InvalidParam {
            param: "p".into(),
            value: "v".into(),
            reason: "r".into(),
        };
        assert!(e3.to_string().contains('r'));
    }
}
