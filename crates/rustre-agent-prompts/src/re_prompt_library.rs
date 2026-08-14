//! `re_prompt_library` — RE-specific prompt library.
//!
//! Provides [`RePromptLibrary`] with 50+ curated prompts,
//! [`PromptCategory`], [`PromptTemplate`], [`ExamplePair`], and
//! [`ContextualPrompt`] for contextual prompt selection during analysis.
//!
//! # Distinct from `prompt_library`
//!
//! `re_prompt_library` is **domain-oriented**: categories map to analysis
//! modalities (`Disassembly`, `DotNet`, `Yara`, `Shellcode`, …), and
//! templates carry token estimates, an `expects_json` flag, and the
//! [`ContextualPrompt`] helper for budget-aware rendering.
//!
//! `prompt_library` is **schema-oriented**: every template carries a
//! JSON Schema for its expected output and categories map to structured
//! RE tasks (`FunctionAnalysis`, `MalwareClassification`, …).
//! Keep both — they serve different consumers.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ───────────────────────────────────────────────────────────────────

/// Errors from the prompt library.
#[derive(Debug, Error)]
pub enum PromptLibraryError {
    #[error("prompt '{0}' not found")]
    NotFound(String),

    #[error("missing variable '{0}' in template")]
    MissingVariable(String),

    #[error("category '{0}' is unknown")]
    UnknownCategory(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

// ─── PromptCategory ───────────────────────────────────────────────────────────

/// High-level category grouping for RE prompts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PromptCategory {
    Disassembly,
    Decompilation,
    Vulnerability,
    Malware,
    Crypto,
    Obfuscation,
    TypeRecovery,
    Naming,
    Documentation,
    Shellcode,
    Firmware,
    Mobile,
    DotNet,
    Diff,
    Triage,
    Yara,
    ChainOfThought,
    Explanation,
    Custom(String),
}

impl std::fmt::Display for PromptCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "custom:{s}"),
            _ => write!(f, "{self:?}"),
        }
    }
}

impl PromptCategory {
    /// Parse a category from a string slice (case-insensitive).
    #[must_use]
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "disassembly" | "disasm" => Self::Disassembly,
            "decompilation" | "decompile" => Self::Decompilation,
            "vulnerability" | "vuln" => Self::Vulnerability,
            "malware" => Self::Malware,
            "crypto" | "cryptography" => Self::Crypto,
            "obfuscation" | "deobfuscation" => Self::Obfuscation,
            "types" | "type_recovery" => Self::TypeRecovery,
            "naming" | "rename" => Self::Naming,
            "documentation" | "docs" => Self::Documentation,
            "shellcode" => Self::Shellcode,
            "firmware" => Self::Firmware,
            "mobile" | "android" | "ios" => Self::Mobile,
            "dotnet" | ".net" => Self::DotNet,
            "diff" => Self::Diff,
            "triage" => Self::Triage,
            "yara" | "signature" => Self::Yara,
            "chain_of_thought" | "cot" => Self::ChainOfThought,
            "explanation" | "explain" => Self::Explanation,
            other => Self::Custom(other.to_string()),
        }
    }
}

// ─── ExamplePair ──────────────────────────────────────────────────────────────

/// A few-shot example: input + expected output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExamplePair {
    pub input: String,
    pub output: String,
    pub note: String,
}

impl ExamplePair {
    #[must_use]
    pub fn new(input: impl Into<String>, output: impl Into<String>) -> Self {
        Self {
            input: input.into(),
            output: output.into(),
            note: String::new(),
        }
    }

    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = note.into();
        self
    }
}

// ─── PromptTemplate ───────────────────────────────────────────────────────────

/// A single prompt template with metadata and few-shot examples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptTemplate {
    /// Unique slug (`snake_case`).
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// Template body — use `{{variable}}` placeholders.
    pub body: String,
    pub category: PromptCategory,
    pub system_prompt: String,
    pub examples: Vec<ExamplePair>,
    pub tags: Vec<String>,
    /// Estimated token cost.
    pub estimated_tokens: u32,
    /// Whether the prompt expects a JSON output.
    pub expects_json: bool,
}

impl PromptTemplate {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        body: impl Into<String>,
        category: PromptCategory,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            body: body.into(),
            category,
            system_prompt: String::new(),
            examples: Vec::new(),
            tags: Vec::new(),
            estimated_tokens: 500,
            expects_json: false,
        }
    }

    #[must_use]
    pub fn with_system(mut self, sys: impl Into<String>) -> Self {
        self.system_prompt = sys.into();
        self
    }

    #[must_use]
    pub fn with_example(mut self, ex: ExamplePair) -> Self {
        self.examples.push(ex);
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    #[must_use]
    pub const fn expecting_json(mut self) -> Self {
        self.expects_json = true;
        self
    }

    #[must_use]
    pub const fn with_tokens(mut self, n: u32) -> Self {
        self.estimated_tokens = n;
        self
    }

    /// Render the prompt body by substituting `{{key}}` with values.
    pub fn render(&self, vars: &HashMap<String, String>) -> Result<String, PromptLibraryError> {
        let mut result = self.body.clone();
        // Extract required variables from the template
        let mut start = 0;
        while let Some(i) = result[start..].find("{{") {
            let open = start + i;
            let Some(end_rel) = result[open..].find("}}") else {
                break;
            };
            let close = open + end_rel;
            let key = result[open + 2..close].trim().to_string();
            let value = vars
                .get(&key)
                .cloned()
                .ok_or_else(|| PromptLibraryError::MissingVariable(key.clone()))?;
            result.replace_range(open..close + 2, &value);
            start = open + value.len();
        }
        Ok(result)
    }

    /// Render — missing variables use empty string instead of erroring.
    #[must_use]
    pub fn render_lenient(&self, vars: &HashMap<String, String>) -> String {
        let mut result = self.body.clone();
        for (k, v) in vars {
            result = result.replace(&format!("{{{{{k}}}}}"), v);
        }
        // Remove any remaining unresolved placeholders
        loop {
            if let Some(open) = result.find("{{")
                && let Some(rel_close) = result[open..].find("}}") {
                    result.replace_range(open..=open + rel_close + 1, "");
                    continue;
                }
            break;
        }
        result
    }

    /// Build a full prompt including system message and examples.
    #[must_use]
    pub fn build_full(&self, vars: &HashMap<String, String>) -> String {
        let body = self.render_lenient(vars);
        let mut out = String::new();
        if !self.system_prompt.is_empty() {
            out.push_str("[SYSTEM]\n");
            out.push_str(&self.system_prompt);
            out.push_str("\n\n");
        }
        for ex in &self.examples {
            out.push_str("[EXAMPLE INPUT]\n");
            out.push_str(&ex.input);
            out.push_str("\n[EXAMPLE OUTPUT]\n");
            out.push_str(&ex.output);
            out.push_str("\n\n");
        }
        out.push_str("[USER]\n");
        out.push_str(&body);
        out
    }
}

// ─── ContextualPrompt ────────────────────────────────────────────────────────

/// A contextually enriched prompt: template + auto-filled context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextualPrompt {
    pub template_id: String,
    pub vars: HashMap<String, String>,
    pub rendered: String,
    pub context_tokens: u32,
}

impl ContextualPrompt {
    /// Create a contextual prompt from a template and variable map.
    pub fn from_template(
        template: &PromptTemplate,
        vars: HashMap<String, String>,
    ) -> Result<Self, PromptLibraryError> {
        let rendered = template.render(&vars)?;
        let context_tokens = (rendered.chars().count() as u32).div_ceil(4);
        Ok(Self {
            template_id: template.id.clone(),
            vars,
            rendered,
            context_tokens,
        })
    }

    #[must_use]
    pub fn from_template_lenient(template: &PromptTemplate, vars: HashMap<String, String>) -> Self {
        let rendered = template.render_lenient(&vars);
        let context_tokens = (rendered.chars().count() as u32).div_ceil(4);
        Self {
            template_id: template.id.clone(),
            vars,
            rendered,
            context_tokens,
        }
    }

    #[must_use]
    pub const fn is_over_budget(&self, budget: u32) -> bool {
        self.context_tokens > budget
    }
}

// ─── RePromptLibrary ──────────────────────────────────────────────────────────

/// Central registry of all RE-specific prompts.
pub struct RePromptLibrary {
    prompts: HashMap<String, PromptTemplate>,
}

impl RePromptLibrary {
    /// Create the library and populate it with all built-in prompts.
    #[must_use]
    pub fn new() -> Self {
        let mut lib = Self {
            prompts: HashMap::new(),
        };
        for p in builtin_prompts() {
            lib.prompts.insert(p.id.clone(), p);
        }
        lib
    }

    /// Total number of prompts.
    #[must_use]
    pub fn count(&self) -> usize {
        self.prompts.len()
    }

    /// Get a prompt by its id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&PromptTemplate> {
        self.prompts.get(id)
    }

    /// All prompt ids.
    #[must_use]
    pub fn ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.prompts.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Prompts in a given category.
    #[must_use]
    pub fn by_category(&self, category: &PromptCategory) -> Vec<&PromptTemplate> {
        self.prompts
            .values()
            .filter(|p| &p.category == category)
            .collect()
    }

    /// Search prompts by keyword.
    #[must_use]
    pub fn search(&self, keyword: &str) -> Vec<&PromptTemplate> {
        let kw = keyword.to_lowercase();
        self.prompts
            .values()
            .filter(|p| {
                p.id.to_lowercase().contains(&kw)
                    || p.title.to_lowercase().contains(&kw)
                    || p.tags.iter().any(|t| t.to_lowercase().contains(&kw))
            })
            .collect()
    }

    /// Render a prompt by id with variables.
    pub fn render(
        &self,
        id: &str,
        vars: &HashMap<String, String>,
    ) -> Result<String, PromptLibraryError> {
        let tmpl = self
            .prompts
            .get(id)
            .ok_or_else(|| PromptLibraryError::NotFound(id.to_string()))?;
        tmpl.render(vars)
    }

    /// Register a custom prompt.
    pub fn register(&mut self, prompt: PromptTemplate) {
        self.prompts.insert(prompt.id.clone(), prompt);
    }

    /// Return all prompts expecting JSON output.
    #[must_use]
    pub fn json_prompts(&self) -> Vec<&PromptTemplate> {
        self.prompts.values().filter(|p| p.expects_json).collect()
    }

    /// Return the prompt(s) best suited for a given context.
    /// Currently returns prompts matching all provided category strings.
    #[must_use]
    pub fn suggest(&self, categories: &[PromptCategory]) -> Vec<&PromptTemplate> {
        self.prompts
            .values()
            .filter(|p| categories.contains(&p.category))
            .collect()
    }
}

impl Default for RePromptLibrary {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Built-in prompts ─────────────────────────────────────────────────────────

fn sys_re() -> String {
    "You are an expert reverse engineer. Be precise, concise, and technical.".to_string()
}

fn builtin_prompts() -> Vec<PromptTemplate> {
    vec![
        // ── Disassembly ───────────────────────────────────────────────────────
        PromptTemplate::new("explain_disasm", "Explain Disassembly",
            "Explain what the following {{arch}} disassembly does:\n\n```\n{{disassembly}}\n```\n\nProvide a concise English explanation.",
            PromptCategory::Disassembly)
            .with_system(sys_re())
            .with_example(ExamplePair::new("push rbp\nmov rbp, rsp", "Function prologue: saves caller's frame pointer and sets up a new stack frame."))
            .with_tag("explain").with_tag("disasm"),

        PromptTemplate::new("identify_pattern", "Identify Assembly Pattern",
            "Identify any well-known patterns (loops, syscalls, string ops) in:\n\n```\n{{disassembly}}\n```",
            PromptCategory::Disassembly)
            .with_system(sys_re())
            .with_tag("pattern"),

        PromptTemplate::new("trace_data_flow", "Trace Data Flow",
            "Trace the data flow for register {{register}} through the following code:\n\n```\n{{disassembly}}\n```",
            PromptCategory::Disassembly)
            .with_system(sys_re())
            .with_tag("dataflow"),

        // ── Decompilation ─────────────────────────────────────────────────────
        PromptTemplate::new("explain_decompiled", "Explain Decompiled Code",
            "Explain what this decompiled function does:\n\n```c\n{{code}}\n```\n\nInclude: purpose, input/output, side effects.",
            PromptCategory::Decompilation)
            .with_system(sys_re())
            .with_tag("explain").with_tag("decompile"),

        PromptTemplate::new("improve_pseudocode", "Improve Pseudo-code",
            "Rewrite the following pseudo-code to be cleaner and more readable:\n\n```c\n{{code}}\n```",
            PromptCategory::Decompilation)
            .with_system(sys_re())
            .with_tag("cleanup"),

        PromptTemplate::new("identify_algorithm", "Identify Algorithm",
            "Identify the algorithm implemented in:\n\n```c\n{{code}}\n```\n\nBe specific about variant if applicable.",
            PromptCategory::Decompilation)
            .with_system(sys_re())
            .with_tag("algorithm"),

        // ── Naming ────────────────────────────────────────────────────────────
        PromptTemplate::new("suggest_function_names", "Suggest Function Names",
            "Suggest meaningful names for the following functions. Return JSON: {\"sub_ADDR\": \"suggested_name\"}.\n\n{{functions}}",
            PromptCategory::Naming)
            .with_system(sys_re())
            .expecting_json()
            .with_tag("rename").with_tag("json"),

        PromptTemplate::new("suggest_variable_names", "Suggest Variable Names",
            "Suggest better names for local variables in:\n\n```c\n{{code}}\n```\nReturn JSON: {\"var_name\": \"new_name\"}.",
            PromptCategory::Naming)
            .with_system(sys_re())
            .expecting_json()
            .with_tag("rename").with_tag("json"),

        PromptTemplate::new("name_struct_fields", "Name Struct Fields",
            "Suggest names for the fields of this structure:\n\n```c\n{{struct_def}}\n```",
            PromptCategory::Naming)
            .with_system(sys_re())
            .with_tag("struct").with_tag("rename"),

        // ── Vulnerability ─────────────────────────────────────────────────────
        PromptTemplate::new("find_bugs", "Find Security Bugs",
            "Identify security vulnerabilities in:\n\n```c\n{{code}}\n```\n\nFor each: type, severity (critical/high/medium/low), location, and brief description.",
            PromptCategory::Vulnerability)
            .with_system(sys_re())
            .with_tag("security").with_tag("bugs"),

        PromptTemplate::new("check_buffer_overflow", "Check Buffer Overflow",
            "Does the following code contain buffer overflow vulnerabilities?\n\n```c\n{{code}}\n```\nExplain any findings.",
            PromptCategory::Vulnerability)
            .with_system(sys_re())
            .with_tag("overflow").with_tag("security"),

        PromptTemplate::new("check_use_after_free", "Check Use-After-Free",
            "Identify use-after-free vulnerabilities in:\n\n```c\n{{code}}\n```",
            PromptCategory::Vulnerability)
            .with_system(sys_re())
            .with_tag("uaf"),

        PromptTemplate::new("check_integer_overflow", "Check Integer Overflow",
            "Find integer overflow vulnerabilities in:\n\n```c\n{{code}}\n```\nInclude arithmetic operations that could wrap.",
            PromptCategory::Vulnerability)
            .with_system(sys_re())
            .with_tag("integer_overflow"),

        PromptTemplate::new("check_format_string", "Check Format String",
            "Check for format string vulnerabilities in:\n\n```c\n{{code}}\n```",
            PromptCategory::Vulnerability)
            .with_system(sys_re())
            .with_tag("format_string"),

        // ── Malware ───────────────────────────────────────────────────────────
        PromptTemplate::new("classify_malware", "Classify Malware",
            "Classify this malware based on its behaviour:\n\n{{behavior}}\n\nProvide: family, type, capabilities, and confidence.",
            PromptCategory::Malware)
            .with_system(sys_re())
            .with_tag("classification"),

        PromptTemplate::new("extract_iocs", "Extract IOCs",
            "Extract all indicators of compromise from:\n\n{{analysis}}\n\nReturn JSON: {\"domains\":[], \"ips\":[], \"hashes\":[], \"mutex\":[], \"registry\":[]}.",
            PromptCategory::Malware)
            .with_system(sys_re())
            .expecting_json()
            .with_tag("ioc").with_tag("json"),

        PromptTemplate::new("c2_analysis", "C2 Communication Analysis",
            "Analyse this network-related code for C2 behaviour:\n\n```c\n{{code}}\n```\nDescribe protocol, encoding, and beaconing pattern.",
            PromptCategory::Malware)
            .with_system(sys_re())
            .with_tag("c2").with_tag("network"),

        PromptTemplate::new("persistence_analysis", "Persistence Mechanism Analysis",
            "Identify persistence mechanisms in:\n\n```c\n{{code}}\n```\nMap to MITRE ATT&CK if possible.",
            PromptCategory::Malware)
            .with_system(sys_re())
            .with_tag("persistence").with_tag("mitre"),

        PromptTemplate::new("sandbox_evasion", "Sandbox Evasion Detection",
            "Identify sandbox/AV evasion techniques in:\n\n```c\n{{code}}\n```",
            PromptCategory::Malware)
            .with_system(sys_re())
            .with_tag("evasion").with_tag("sandbox"),

        // ── Crypto ────────────────────────────────────────────────────────────
        PromptTemplate::new("identify_crypto_algo", "Identify Crypto Algorithm",
            "Identify the cryptographic algorithm in:\n\n```c\n{{code}}\n```\nInclude variant, key size, and mode if applicable.",
            PromptCategory::Crypto)
            .with_system(sys_re())
            .with_tag("algorithm").with_tag("crypto"),

        PromptTemplate::new("analyze_crypto_usage", "Analyze Crypto Usage",
            "Is the cryptographic usage in the following code correct and secure?\n\n```c\n{{code}}\n```",
            PromptCategory::Crypto)
            .with_system(sys_re())
            .with_tag("crypto").with_tag("security"),

        PromptTemplate::new("extract_crypto_keys", "Extract Crypto Keys",
            "Identify any hardcoded keys, IVs, or seeds in:\n\n```c\n{{code}}\n```",
            PromptCategory::Crypto)
            .with_system(sys_re())
            .with_tag("keys").with_tag("hardcoded"),

        // ── Obfuscation ───────────────────────────────────────────────────────
        PromptTemplate::new("detect_obfuscation", "Detect Obfuscation",
            "What obfuscation techniques are present in:\n\n```c\n{{code}}\n```\nList each technique.",
            PromptCategory::Obfuscation)
            .with_system(sys_re())
            .with_tag("obfuscation"),

        PromptTemplate::new("deobfuscate_mba", "Deobfuscate MBA Expression",
            "Simplify this Mixed Boolean-Arithmetic expression: {{expression}}\nProvide the simplified form.",
            PromptCategory::Obfuscation)
            .with_system(sys_re())
            .with_tag("mba"),

        PromptTemplate::new("decrypt_strings", "Decrypt Obfuscated Strings",
            "The following code decrypts strings. Identify the algorithm and decrypt:\n\n```c\n{{code}}\n```",
            PromptCategory::Obfuscation)
            .with_system(sys_re())
            .with_tag("strings").with_tag("decrypt"),

        // ── TypeRecovery ──────────────────────────────────────────────────────
        PromptTemplate::new("recover_struct", "Recover Struct Layout",
            "Recover the data structure accessed via these field offsets:\n\n{{offsets}}\n\nWrite a C struct definition.",
            PromptCategory::TypeRecovery)
            .with_system(sys_re())
            .with_tag("struct").with_tag("types"),

        PromptTemplate::new("infer_function_signature", "Infer Function Signature",
            "Infer the C function signature for:\n\n```c\n{{code}}\n```",
            PromptCategory::TypeRecovery)
            .with_system(sys_re())
            .with_tag("signature").with_tag("types"),

        PromptTemplate::new("recover_vtable", "Recover vtable",
            "Recover the vtable structure from the following access pattern:\n\n{{accesses}}",
            PromptCategory::TypeRecovery)
            .with_system(sys_re())
            .with_tag("vtable").with_tag("c++"),

        // ── Documentation ─────────────────────────────────────────────────────
        PromptTemplate::new("document_function", "Document Function",
            "Write Doxygen documentation for:\n\n```c\n{{code}}\n```\nInclude @brief, @param, @return, @note.",
            PromptCategory::Documentation)
            .with_system(sys_re())
            .with_tag("doxygen").with_tag("docs"),

        PromptTemplate::new("summarize_binary", "Summarize Binary",
            "Write a concise summary of the binary based on:\n\nArchitecture: {{arch}}\nStrings: {{strings}}\nImports: {{imports}}\nExports: {{exports}}",
            PromptCategory::Documentation)
            .with_system(sys_re())
            .with_tag("summary"),

        // ── Shellcode ─────────────────────────────────────────────────────────
        PromptTemplate::new("analyze_shellcode", "Analyze Shellcode",
            "Analyze this {{arch}} shellcode:\n\n```\n{{disassembly}}\n```\nDescribe: purpose, syscalls, payload.",
            PromptCategory::Shellcode)
            .with_system(sys_re())
            .with_tag("shellcode").with_tag("exploit"),

        PromptTemplate::new("detect_shellcode_technique", "Detect Shellcode Technique",
            "Identify the shellcode technique used (e.g. egg-hunting, staged, self-modifying) in:\n\n```\n{{disassembly}}\n```",
            PromptCategory::Shellcode)
            .with_system(sys_re())
            .with_tag("technique").with_tag("shellcode"),

        // ── Firmware ──────────────────────────────────────────────────────────
        PromptTemplate::new("analyze_firmware_header", "Analyze Firmware Header",
            "Analyze this firmware header:\n\n```\n{{header_hex}}\n```\nIdentify format, version, offsets.",
            PromptCategory::Firmware)
            .with_system(sys_re())
            .with_tag("firmware").with_tag("header"),

        PromptTemplate::new("find_hardcoded_credentials", "Find Hardcoded Credentials",
            "Search for hardcoded credentials in these strings:\n\n{{strings}}\n\nReturn any found credentials.",
            PromptCategory::Firmware)
            .with_system(sys_re())
            .with_tag("credentials").with_tag("firmware"),

        // ── Mobile ────────────────────────────────────────────────────────────
        PromptTemplate::new("analyze_android_permission", "Analyze Android Permissions",
            "Analyse the security implications of these Android permissions:\n\n{{permissions}}",
            PromptCategory::Mobile)
            .with_system(sys_re())
            .with_tag("android").with_tag("permissions"),

        PromptTemplate::new("analyze_ios_entitlements", "Analyze iOS Entitlements",
            "Assess the security of these iOS entitlements:\n\n{{entitlements}}",
            PromptCategory::Mobile)
            .with_system(sys_re())
            .with_tag("ios").with_tag("entitlements"),

        // ── .NET ──────────────────────────────────────────────────────────────
        PromptTemplate::new("explain_dotnet_il", "Explain .NET IL",
            "Explain this .NET IL bytecode:\n\n```\n{{il_code}}\n```",
            PromptCategory::DotNet)
            .with_system(sys_re())
            .with_tag("il").with_tag("dotnet"),

        PromptTemplate::new("decompile_csharp", "Decompile C# from IL",
            "Convert this IL to readable C#:\n\n```\n{{il_code}}\n```",
            PromptCategory::DotNet)
            .with_system(sys_re())
            .with_tag("csharp").with_tag("dotnet"),

        // ── Diff ──────────────────────────────────────────────────────────────
        PromptTemplate::new("describe_patch_diff", "Describe Patch Diff",
            "Describe the changes between these two function versions and their security impact:\n\n[OLD]\n```c\n{{old_code}}\n```\n\n[NEW]\n```c\n{{new_code}}\n```",
            PromptCategory::Diff)
            .with_system(sys_re())
            .with_tag("diff").with_tag("patch"),

        PromptTemplate::new("identify_n_day", "Identify N-Day",
            "Given these changes, identify which CVE this patch addresses:\n\n{{diff}}\nSearch known vulnerabilities.",
            PromptCategory::Diff)
            .with_system(sys_re())
            .with_tag("nday").with_tag("cve"),

        // ── Triage ────────────────────────────────────────────────────────────
        PromptTemplate::new("quick_triage", "Quick Binary Triage",
            "Quickly triage this binary based on:\nFile type: {{file_type}}\nStrings: {{strings}}\nImports: {{imports}}\nEntropy: {{entropy}}\n\nProvide: verdict, confidence, next steps.",
            PromptCategory::Triage)
            .with_system(sys_re())
            .with_tag("triage"),

        PromptTemplate::new("packer_detection", "Packer Detection",
            "What packer or protector was used based on:\nSection names: {{sections}}\nEntry point bytes: {{ep_bytes}}\nImports: {{imports}}",
            PromptCategory::Triage)
            .with_system(sys_re())
            .with_tag("packer").with_tag("triage"),

        // ── YARA ──────────────────────────────────────────────────────────────
        PromptTemplate::new("generate_yara_rule", "Generate YARA Rule",
            "Generate a YARA rule to detect similar samples based on:\nStrings: {{strings}}\nByte patterns: {{patterns}}\nMalware family: {{family}}",
            PromptCategory::Yara)
            .with_system(sys_re())
            .with_tag("yara").with_tag("detection"),

        PromptTemplate::new("explain_yara_match", "Explain YARA Match",
            "Explain why this YARA rule matched and what it means:\n\nRule: {{rule}}\nMatched at: {{offset}}\nContext: {{context}}",
            PromptCategory::Yara)
            .with_system(sys_re())
            .with_tag("yara").with_tag("explain"),

        // ── Chain of Thought ──────────────────────────────────────────────────
        PromptTemplate::new("cot_analyze", "Chain-of-Thought Analysis",
            "Think step-by-step to analyze:\n\n```c\n{{code}}\n```\n\nStep 1: Identify the inputs and outputs.\nStep 2: Trace the control flow.\nStep 3: Identify side effects.\nStep 4: State the function's purpose.",
            PromptCategory::ChainOfThought)
            .with_system(sys_re())
            .with_tag("cot").with_tag("reasoning"),

        PromptTemplate::new("cot_vuln_hunt", "Chain-of-Thought Vulnerability Hunt",
            "Think step-by-step to find vulnerabilities in:\n\n```c\n{{code}}\n```\n\nStep 1: Identify all user-controlled inputs.\nStep 2: Trace inputs to dangerous sinks.\nStep 3: Evaluate memory safety.\nStep 4: State findings.",
            PromptCategory::ChainOfThought)
            .with_system(sys_re())
            .with_tag("cot").with_tag("vulnerability"),

        // ── Explanation ───────────────────────────────────────────────────────
        PromptTemplate::new("explain_for_beginner", "Explain for Beginner",
            "Explain what this code does in simple terms (assume the reader is not a programmer):\n\n```c\n{{code}}\n```",
            PromptCategory::Explanation)
            .with_system(sys_re())
            .with_tag("explain").with_tag("beginner"),

        PromptTemplate::new("explain_mitre_technique", "Explain MITRE Technique",
            "Explain how the following code implements MITRE technique {{technique_id}}:\n\n```c\n{{code}}\n```",
            PromptCategory::Explanation)
            .with_system(sys_re())
            .with_tag("mitre").with_tag("explain"),

        PromptTemplate::new("explain_api_call", "Explain API Call",
            "Explain the purpose and security implications of this API call: {{api_name}}({{args}}).",
            PromptCategory::Explanation)
            .with_system(sys_re())
            .with_tag("api").with_tag("explain"),

        PromptTemplate::new("explain_syscall", "Explain System Call",
            "Explain what this system call does and its typical use cases: {{syscall}}({{args}}). Include OS, calling convention, and security relevance.",
            PromptCategory::Explanation)
            .with_system(sys_re())
            .with_tag("syscall").with_tag("explain"),
    ]
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn lib() -> &'static RePromptLibrary {
        use std::sync::OnceLock;
        static L: OnceLock<RePromptLibrary> = OnceLock::new();
        L.get_or_init(RePromptLibrary::new)
    }

    // ── Library count ─────────────────────────────────────────────────────────

    #[test]
    fn test_library_count_ge_50() {
        assert!(
            lib().count() >= 50,
            "expected 50+ prompts, got {}",
            lib().count()
        );
    }

    #[test]
    fn test_library_ids_sorted() {
        let ids = lib().ids();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }

    // ── Lookup ────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_existing_prompt() {
        assert!(lib().get("explain_disasm").is_some());
        assert!(lib().get("find_bugs").is_some());
        assert!(lib().get("generate_yara_rule").is_some());
    }

    #[test]
    fn test_get_missing_prompt() {
        assert!(lib().get("nonexistent_prompt").is_none());
    }

    // ── Category ──────────────────────────────────────────────────────────────

    #[test]
    fn test_by_category_disassembly() {
        let results = lib().by_category(&PromptCategory::Disassembly);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_by_category_vulnerability() {
        let results = lib().by_category(&PromptCategory::Vulnerability);
        assert!(results.len() >= 4);
    }

    #[test]
    fn test_by_category_malware() {
        let results = lib().by_category(&PromptCategory::Malware);
        assert!(results.len() >= 4);
    }

    // ── Search ────────────────────────────────────────────────────────────────

    #[test]
    fn test_search_yara() {
        let results = lib().search("yara");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_search_no_match() {
        assert!(lib().search("xyzzy_impossible_match_zz").is_empty());
    }

    // ── Render ────────────────────────────────────────────────────────────────

    #[test]
    fn test_render_ok() {
        let mut vars = HashMap::new();
        vars.insert("arch".to_string(), "x86_64".to_string());
        vars.insert(
            "disassembly".to_string(),
            "push rbp\nmov rbp, rsp".to_string(),
        );
        let rendered = lib().render("explain_disasm", &vars).unwrap();
        assert!(rendered.contains("x86_64"));
        assert!(rendered.contains("push rbp"));
    }

    #[test]
    fn test_render_missing_var() {
        let vars = HashMap::new();
        let err = lib().render("explain_disasm", &vars).unwrap_err();
        assert!(matches!(err, PromptLibraryError::MissingVariable(_)));
    }

    #[test]
    fn test_render_not_found() {
        let vars = HashMap::new();
        let err = lib().render("ghost", &vars).unwrap_err();
        assert!(matches!(err, PromptLibraryError::NotFound(_)));
    }

    // ── PromptTemplate render_lenient ─────────────────────────────────────────

    #[test]
    fn test_render_lenient_partial() {
        let t = lib().get("explain_disasm").unwrap();
        let mut vars = HashMap::new();
        vars.insert("arch".to_string(), "arm64".to_string());
        // disassembly is missing — should render without panic
        let rendered = t.render_lenient(&vars);
        assert!(rendered.contains("arm64"));
    }

    // ── PromptTemplate build_full ─────────────────────────────────────────────

    #[test]
    fn test_build_full_includes_system() {
        let t = lib().get("explain_disasm").unwrap();
        let mut vars = HashMap::new();
        vars.insert("arch".to_string(), "x86_64".to_string());
        vars.insert("disassembly".to_string(), "nop".to_string());
        let full = t.build_full(&vars);
        assert!(full.contains("[SYSTEM]"));
        assert!(full.contains("[USER]"));
    }

    #[test]
    fn test_build_full_includes_examples() {
        let t = lib().get("explain_disasm").unwrap();
        let mut vars = HashMap::new();
        vars.insert("arch".to_string(), "x86_64".to_string());
        vars.insert("disassembly".to_string(), "nop".to_string());
        let full = t.build_full(&vars);
        // explain_disasm has an example
        assert!(full.contains("[EXAMPLE"));
    }

    // ── ContextualPrompt ──────────────────────────────────────────────────────

    #[test]
    fn test_contextual_prompt_ok() {
        let t = lib().get("explain_disasm").unwrap();
        let mut vars = HashMap::new();
        vars.insert("arch".to_string(), "x86_64".to_string());
        vars.insert("disassembly".to_string(), "xor eax, eax".to_string());
        let cp = ContextualPrompt::from_template(t, vars).unwrap();
        assert!(!cp.rendered.is_empty());
        assert!(cp.context_tokens > 0);
    }

    #[test]
    fn test_contextual_prompt_over_budget() {
        let t = lib().get("explain_disasm").unwrap();
        let mut vars = HashMap::new();
        vars.insert("arch".to_string(), "x86_64".to_string());
        vars.insert("disassembly".to_string(), "nop".to_string());
        let cp = ContextualPrompt::from_template_lenient(t, vars);
        assert!(!cp.is_over_budget(100_000));
        assert!(cp.is_over_budget(0));
    }

    // ── JSON prompts ──────────────────────────────────────────────────────────

    #[test]
    fn test_json_prompts_non_empty() {
        let json_prompts = lib().json_prompts();
        assert!(!json_prompts.is_empty());
        assert!(json_prompts.iter().all(|p| p.expects_json));
    }

    // ── Suggest ───────────────────────────────────────────────────────────────

    #[test]
    fn test_suggest_categories() {
        let suggestions = lib().suggest(&[PromptCategory::Malware, PromptCategory::Yara]);
        assert!(!suggestions.is_empty());
    }

    // ── PromptCategory ────────────────────────────────────────────────────────

    #[test]
    fn test_category_display() {
        assert_eq!(PromptCategory::Disassembly.to_string(), "Disassembly");
        assert_eq!(PromptCategory::Custom("x".into()).to_string(), "custom:x");
    }

    #[test]
    fn test_category_from_str_loose() {
        assert_eq!(
            PromptCategory::from_str_loose("disasm"),
            PromptCategory::Disassembly
        );
        assert_eq!(
            PromptCategory::from_str_loose("malware"),
            PromptCategory::Malware
        );
        assert_eq!(PromptCategory::from_str_loose("YARA"), PromptCategory::Yara);
        assert!(matches!(
            PromptCategory::from_str_loose("custom_thing"),
            PromptCategory::Custom(_)
        ));
    }

    // ── ExamplePair ───────────────────────────────────────────────────────────

    #[test]
    fn test_example_pair() {
        let ex = ExamplePair::new("input", "output").with_note("note");
        assert_eq!(ex.input, "input");
        assert_eq!(ex.note, "note");
    }

    // ── Custom registration ───────────────────────────────────────────────────

    #[test]
    fn test_register_custom_prompt() {
        let mut lib = RePromptLibrary::new();
        let prev = lib.count();
        let t = PromptTemplate::new(
            "my_custom",
            "My Prompt",
            "Do {{thing}}",
            PromptCategory::Custom("custom".into()),
        );
        lib.register(t);
        assert_eq!(lib.count(), prev + 1);
        assert!(lib.get("my_custom").is_some());
    }

    // ── All builtin prompts present ───────────────────────────────────────────

    #[test]
    fn test_all_builtin_ids_present() {
        let expected = [
            "explain_disasm",
            "identify_pattern",
            "trace_data_flow",
            "explain_decompiled",
            "improve_pseudocode",
            "identify_algorithm",
            "suggest_function_names",
            "suggest_variable_names",
            "name_struct_fields",
            "find_bugs",
            "check_buffer_overflow",
            "check_use_after_free",
            "check_integer_overflow",
            "check_format_string",
            "classify_malware",
            "extract_iocs",
            "c2_analysis",
            "persistence_analysis",
            "sandbox_evasion",
            "identify_crypto_algo",
            "analyze_crypto_usage",
            "extract_crypto_keys",
            "detect_obfuscation",
            "deobfuscate_mba",
            "decrypt_strings",
            "recover_struct",
            "infer_function_signature",
            "recover_vtable",
            "document_function",
            "summarize_binary",
            "analyze_shellcode",
            "detect_shellcode_technique",
            "analyze_firmware_header",
            "find_hardcoded_credentials",
            "analyze_android_permission",
            "analyze_ios_entitlements",
            "explain_dotnet_il",
            "decompile_csharp",
            "describe_patch_diff",
            "identify_n_day",
            "quick_triage",
            "packer_detection",
            "generate_yara_rule",
            "explain_yara_match",
            "cot_analyze",
            "cot_vuln_hunt",
            "explain_for_beginner",
            "explain_mitre_technique",
            "explain_api_call",
        ];
        let lib = lib();
        for id in &expected {
            assert!(lib.get(id).is_some(), "missing prompt: {id}");
        }
    }

    // ── WorkflowParam type ────────────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let e = PromptLibraryError::NotFound("x".into());
        assert!(e.to_string().contains('x'));
        let e2 = PromptLibraryError::MissingVariable("v".into());
        assert!(e2.to_string().contains('v'));
    }
}
