// prompt_templates.rs — Domain-specific RE prompt templates.
//
// Malware / vulnerability / diff / protocol / exploit templates.
// Template substitution, versioning, chain composition, output format.
//
// Distinct from `prompt_template_engine`:
//   `prompt_templates` owns the **content** — 10 builtin domain templates
//   (malware-analyze, vuln-analyze, binary-diff, …), a `TemplateRegistry`,
//   and a `PromptChain` / `ChainStep` / `ChainResult` execution model.
//
//   `prompt_template_engine` owns the **rendering engine** — `{{#if}}`,
//   `{{#each}}`, `{{escape_json}}` / `upper` / `lower` / `trim` filters,
//   template validation, JSON loading, and per-template render statistics.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Output format
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    PlainText,
    Json,
    Markdown,
    StructuredList,
    TableCsv,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputFormat::PlainText => write!(f, "plain text"),
            OutputFormat::Json => write!(f, "JSON"),
            OutputFormat::Markdown => write!(f, "Markdown"),
            OutputFormat::StructuredList => write!(f, "structured list"),
            OutputFormat::TableCsv => write!(f, "CSV table"),
        }
    }
}

// ---------------------------------------------------------------------------
// Template variable
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TemplateVar {
    pub name: String,
    pub description: String,
    pub required: bool,
    pub default: Option<String>,
}

impl TemplateVar {
    pub fn required(name: impl Into<String>, description: impl Into<String>) -> Self {
        TemplateVar {
            name: name.into(),
            description: description.into(),
            required: true,
            default: None,
        }
    }

    pub fn optional(name: impl Into<String>, description: impl Into<String>, default: impl Into<String>) -> Self {
        TemplateVar {
            name: name.into(),
            description: description.into(),
            required: false,
            default: Some(default.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Template version
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TemplateVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl TemplateVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        TemplateVersion { major, minor, patch }
    }

    pub fn v1() -> Self {
        Self::new(1, 0, 0)
    }
}

impl fmt::Display for TemplateVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ---------------------------------------------------------------------------
// Template category
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TemplateCategory {
    MalwareAnalysis,
    VulnerabilityAnalysis,
    BinaryDiff,
    ProtocolReversal,
    ExploitDevelopment,
    FunctionRenaming,
    StructureRecovery,
    CryptoIdentification,
    StringDecryption,
    BehaviorSummary,
    General,
}

impl fmt::Display for TemplateCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TemplateCategory::MalwareAnalysis => write!(f, "malware-analysis"),
            TemplateCategory::VulnerabilityAnalysis => write!(f, "vulnerability-analysis"),
            TemplateCategory::BinaryDiff => write!(f, "binary-diff"),
            TemplateCategory::ProtocolReversal => write!(f, "protocol-reversal"),
            TemplateCategory::ExploitDevelopment => write!(f, "exploit-development"),
            TemplateCategory::FunctionRenaming => write!(f, "function-renaming"),
            TemplateCategory::StructureRecovery => write!(f, "structure-recovery"),
            TemplateCategory::CryptoIdentification => write!(f, "crypto-identification"),
            TemplateCategory::StringDecryption => write!(f, "string-decryption"),
            TemplateCategory::BehaviorSummary => write!(f, "behavior-summary"),
            TemplateCategory::General => write!(f, "general"),
        }
    }
}

// ---------------------------------------------------------------------------
// PromptTemplate
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PromptTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: TemplateCategory,
    pub version: TemplateVersion,
    pub system_prompt: String,
    pub user_template: String,
    pub variables: Vec<TemplateVar>,
    pub output_format: OutputFormat,
    pub max_tokens: u32,
    pub tags: Vec<String>,
}

impl PromptTemplate {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        category: TemplateCategory,
        system_prompt: impl Into<String>,
        user_template: impl Into<String>,
    ) -> Self {
        PromptTemplate {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            category,
            version: TemplateVersion::v1(),
            system_prompt: system_prompt.into(),
            user_template: user_template.into(),
            variables: Vec::new(),
            output_format: OutputFormat::Markdown,
            max_tokens: 2048,
            tags: Vec::new(),
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_var(mut self, var: TemplateVar) -> Self {
        self.variables.push(var);
        self
    }

    pub fn with_output_format(mut self, fmt: OutputFormat) -> Self {
        self.output_format = fmt;
        self
    }

    pub fn with_max_tokens(mut self, tokens: u32) -> Self {
        self.max_tokens = tokens;
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Substitute variables in the user template
    pub fn render(&self, vars: &HashMap<String, String>) -> Result<RenderedPrompt, TemplateError> {
        // Check required vars
        for var in &self.variables {
            if var.required && !vars.contains_key(&var.name) {
                if var.default.is_none() {
                    return Err(TemplateError::MissingVariable(var.name.clone()));
                }
            }
        }

        let mut merged = HashMap::new();
        // Apply defaults
        for var in &self.variables {
            if let Some(ref default) = var.default {
                merged.insert(var.name.clone(), default.clone());
            }
        }
        // Override with provided
        for (k, v) in vars {
            merged.insert(k.clone(), v.clone());
        }

        let user = substitute(&self.user_template, &merged)?;
        let system = substitute(&self.system_prompt, &merged)?;

        let format_instruction = match self.output_format {
            OutputFormat::PlainText => String::new(),
            OutputFormat::Json => "\n\nRespond with valid JSON only.".to_string(),
            OutputFormat::Markdown => "\n\nFormat your response as Markdown.".to_string(),
            OutputFormat::StructuredList => "\n\nFormat your response as a structured list with bullet points.".to_string(),
            OutputFormat::TableCsv => "\n\nFormat your response as a CSV table.".to_string(),
        };

        Ok(RenderedPrompt {
            template_id: self.id.clone(),
            system_prompt: system,
            user_prompt: user + &format_instruction,
            max_tokens: self.max_tokens,
            output_format: self.output_format,
        })
    }

    pub fn variable_names(&self) -> Vec<&str> {
        self.variables.iter().map(|v| v.name.as_str()).collect()
    }

    pub fn required_variables(&self) -> Vec<&str> {
        self.variables.iter()
            .filter(|v| v.required)
            .map(|v| v.name.as_str())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// RenderedPrompt
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RenderedPrompt {
    pub template_id: String,
    pub system_prompt: String,
    pub user_prompt: String,
    pub max_tokens: u32,
    pub output_format: OutputFormat,
}

impl RenderedPrompt {
    pub fn estimated_tokens(&self) -> u32 {
        // Rough estimate: 1 token ≈ 4 chars
        ((self.system_prompt.len() + self.user_prompt.len()) / 4) as u32
    }

    pub fn fits_in_context(&self, context_limit: u32) -> bool {
        self.estimated_tokens() + self.max_tokens <= context_limit
    }
}

// ---------------------------------------------------------------------------
// PromptChain
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ChainStep {
    pub step_name: String,
    pub template_id: String,
    pub vars: HashMap<String, String>,
    /// If true, output of this step is fed as a var to the next step
    pub pipe_output: bool,
    pub pipe_var_name: Option<String>,
}

impl ChainStep {
    pub fn new(step_name: impl Into<String>, template_id: impl Into<String>) -> Self {
        ChainStep {
            step_name: step_name.into(),
            template_id: template_id.into(),
            vars: HashMap::new(),
            pipe_output: false,
            pipe_var_name: None,
        }
    }

    pub fn with_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.vars.insert(key.into(), value.into());
        self
    }

    pub fn pipe_to(mut self, var_name: impl Into<String>) -> Self {
        self.pipe_output = true;
        self.pipe_var_name = Some(var_name.into());
        self
    }
}

#[derive(Debug, Clone)]
pub struct PromptChain {
    pub chain_id: String,
    pub description: String,
    pub steps: Vec<ChainStep>,
}

impl PromptChain {
    pub fn new(chain_id: impl Into<String>) -> Self {
        PromptChain {
            chain_id: chain_id.into(),
            description: String::new(),
            steps: Vec::new(),
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn step(mut self, step: ChainStep) -> Self {
        self.steps.push(step);
        self
    }

    pub fn add_step(&mut self, step: ChainStep) {
        self.steps.push(step);
    }

    pub fn len(&self) -> usize {
        self.steps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Execute the chain using a render function
    pub fn execute<F>(&self, registry: &TemplateRegistry, mut step_fn: F) -> Vec<ChainResult>
    where
        F: FnMut(&RenderedPrompt) -> String,
    {
        let mut results = Vec::new();
        let mut accumulated_vars: HashMap<String, String> = HashMap::new();

        for step in &self.steps {
            let mut vars = step.vars.clone();
            // Inject piped vars from accumulated context
            for (k, v) in &accumulated_vars {
                vars.entry(k.clone()).or_insert_with(|| v.clone());
            }

            match registry.get(&step.template_id) {
                None => {
                    results.push(ChainResult {
                        step_name: step.step_name.clone(),
                        template_id: step.template_id.clone(),
                        output: String::new(),
                        error: Some(format!("template '{}' not found", step.template_id)),
                        skipped: true,
                    });
                }
                Some(tmpl) => {
                    match tmpl.render(&vars) {
                        Err(e) => {
                            results.push(ChainResult {
                                step_name: step.step_name.clone(),
                                template_id: step.template_id.clone(),
                                output: String::new(),
                                error: Some(format!("{:?}", e)),
                                skipped: false,
                            });
                        }
                        Ok(rendered) => {
                            let output = step_fn(&rendered);
                            if step.pipe_output {
                                if let Some(ref var_name) = step.pipe_var_name {
                                    accumulated_vars.insert(var_name.clone(), output.clone());
                                }
                            }
                            results.push(ChainResult {
                                step_name: step.step_name.clone(),
                                template_id: step.template_id.clone(),
                                output,
                                error: None,
                                skipped: false,
                            });
                        }
                    }
                }
            }
        }

        results
    }
}

#[derive(Debug, Clone)]
pub struct ChainResult {
    pub step_name: String,
    pub template_id: String,
    pub output: String,
    pub error: Option<String>,
    pub skipped: bool,
}

// ---------------------------------------------------------------------------
// TemplateRegistry
// ---------------------------------------------------------------------------

pub struct TemplateRegistry {
    templates: HashMap<String, PromptTemplate>,
    chains: HashMap<String, PromptChain>,
}

impl TemplateRegistry {
    pub fn new() -> Self {
        TemplateRegistry {
            templates: HashMap::new(),
            chains: HashMap::new(),
        }
    }

    pub fn with_builtins() -> Self {
        let mut reg = Self::new();
        reg.register(builtin_malware_analysis());
        reg.register(builtin_vuln_analysis());
        reg.register(builtin_binary_diff());
        reg.register(builtin_protocol_reversal());
        reg.register(builtin_exploit_dev());
        reg.register(builtin_function_rename());
        reg.register(builtin_structure_recovery());
        reg.register(builtin_crypto_id());
        reg.register(builtin_string_decrypt());
        reg.register(builtin_behavior_summary());
        reg
    }

    pub fn register(&mut self, template: PromptTemplate) {
        self.templates.insert(template.id.clone(), template);
    }

    pub fn register_chain(&mut self, chain: PromptChain) {
        self.chains.insert(chain.chain_id.clone(), chain);
    }

    pub fn get(&self, id: &str) -> Option<&PromptTemplate> {
        self.templates.get(id)
    }

    pub fn get_chain(&self, id: &str) -> Option<&PromptChain> {
        self.chains.get(id)
    }

    pub fn by_category(&self, cat: TemplateCategory) -> Vec<&PromptTemplate> {
        self.templates.values().filter(|t| t.category == cat).collect()
    }

    pub fn by_tag(&self, tag: &str) -> Vec<&PromptTemplate> {
        self.templates.values()
            .filter(|t| t.tags.iter().any(|tt| tt == tag))
            .collect()
    }

    pub fn all_ids(&self) -> Vec<&str> {
        self.templates.keys().map(|s| s.as_str()).collect()
    }

    pub fn count(&self) -> usize {
        self.templates.len()
    }
}

impl Default for TemplateRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Template error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum TemplateError {
    MissingVariable(String),
    UnclosedPlaceholder(String),
    UnknownTemplate(String),
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TemplateError::MissingVariable(v) => write!(f, "missing variable: {}", v),
            TemplateError::UnclosedPlaceholder(s) => write!(f, "unclosed placeholder: {}", s),
            TemplateError::UnknownTemplate(id) => write!(f, "unknown template: {}", id),
        }
    }
}

// ---------------------------------------------------------------------------
// Variable substitution engine
// ---------------------------------------------------------------------------

/// Replace {{VAR_NAME}} with values from vars map
fn substitute(template: &str, vars: &HashMap<String, String>) -> Result<String, TemplateError> {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '{' && chars.peek() == Some(&'{') {
            chars.next(); // consume second '{'
            let mut var_name = String::new();
            let mut closed = false;
            while let Some(nc) = chars.next() {
                if nc == '}' && chars.peek() == Some(&'}') {
                    chars.next(); // consume second '}'
                    closed = true;
                    break;
                }
                var_name.push(nc);
            }
            if !closed {
                return Err(TemplateError::UnclosedPlaceholder(var_name));
            }
            let var_name = var_name.trim().to_string();
            match vars.get(&var_name) {
                Some(val) => out.push_str(val),
                None => out.push_str(&format!("[MISSING:{}]", var_name)),
            }
        } else {
            out.push(c);
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Built-in templates
// ---------------------------------------------------------------------------

fn builtin_malware_analysis() -> PromptTemplate {
    PromptTemplate::new(
        "malware-analyze",
        "Malware Behavior Analysis",
        TemplateCategory::MalwareAnalysis,
        "You are an expert malware analyst. Analyze the provided disassembly or pseudocode. \
         Identify malicious behaviors, persistence mechanisms, C2 communication, and evasion techniques. \
         Map findings to MITRE ATT&CK techniques where applicable.",
        "Analyze the following {{arch}} binary function:\n\n```\n{{code}}\n```\n\n\
         Identified strings: {{strings}}\n\
         Imports: {{imports}}\n\n\
         Provide: (1) behavior summary, (2) ATT&CK techniques, (3) IOCs, (4) suggested function name.",
    )
    .with_var(TemplateVar::required("code", "Disassembly or decompiled pseudocode"))
    .with_var(TemplateVar::optional("arch", "Target architecture", "x86-64"))
    .with_var(TemplateVar::optional("strings", "Decrypted or visible strings", "none"))
    .with_var(TemplateVar::optional("imports", "Import table entries", "none"))
    .with_description("Analyze a function for malware behaviors and ATT&CK mapping")
    .with_output_format(OutputFormat::Markdown)
    .with_max_tokens(1500)
    .with_tag("malware")
    .with_tag("mitre")
}

fn builtin_vuln_analysis() -> PromptTemplate {
    PromptTemplate::new(
        "vuln-analyze",
        "Vulnerability Analysis",
        TemplateCategory::VulnerabilityAnalysis,
        "You are a security vulnerability researcher. Analyze the provided code for security vulnerabilities. \
         Focus on memory safety issues, integer overflows, use-after-free, format string bugs, and logic flaws.",
        "Analyze for vulnerabilities:\n\n```{{lang}}\n{{code}}\n```\n\n\
         Context: {{context}}\n\n\
         Identify: (1) vulnerability type, (2) affected location, (3) exploitability, (4) suggested fix.",
    )
    .with_var(TemplateVar::required("code", "Code to analyze"))
    .with_var(TemplateVar::optional("lang", "Language or disassembly type", "C"))
    .with_var(TemplateVar::optional("context", "Surrounding context", "standalone function"))
    .with_description("Find security vulnerabilities in code")
    .with_output_format(OutputFormat::Markdown)
    .with_max_tokens(1024)
    .with_tag("vulnerability")
    .with_tag("security")
}

fn builtin_binary_diff() -> PromptTemplate {
    PromptTemplate::new(
        "binary-diff",
        "Binary Patch Diff Analysis",
        TemplateCategory::BinaryDiff,
        "You are a binary patch analyst. Compare two versions of a function and explain what changed. \
         Identify if the patch fixes a bug, adds functionality, or is a security fix.",
        "Compare these two versions of function `{{func_name}}`:\n\n\
         ## Version A\n```\n{{code_a}}\n```\n\n\
         ## Version B\n```\n{{code_b}}\n```\n\n\
         Explain: (1) what changed, (2) why (bug fix / security / feature), (3) security implications.",
    )
    .with_var(TemplateVar::required("code_a", "Original version disassembly"))
    .with_var(TemplateVar::required("code_b", "Patched version disassembly"))
    .with_var(TemplateVar::optional("func_name", "Function name", "unknown"))
    .with_description("Analyze differences between two binary function versions")
    .with_output_format(OutputFormat::Markdown)
    .with_max_tokens(1024)
    .with_tag("diff")
    .with_tag("patch")
}

fn builtin_protocol_reversal() -> PromptTemplate {
    PromptTemplate::new(
        "protocol-reverse",
        "Network Protocol Reversal",
        TemplateCategory::ProtocolReversal,
        "You are a network protocol reverse engineer. Analyze network-related code or packet captures \
         to reconstruct the protocol specification.",
        "Reverse engineer the protocol from this code:\n\n```\n{{code}}\n```\n\n\
         Sample data (hex): {{sample_hex}}\n\n\
         Identify: (1) packet structure, (2) field types/sizes, (3) encoding, (4) protocol diagram.",
    )
    .with_var(TemplateVar::required("code", "Network handling code"))
    .with_var(TemplateVar::optional("sample_hex", "Sample packet hex bytes", "none"))
    .with_description("Reverse engineer a network protocol from code")
    .with_output_format(OutputFormat::Markdown)
    .with_max_tokens(2048)
    .with_tag("network")
    .with_tag("protocol")
}

fn builtin_exploit_dev() -> PromptTemplate {
    PromptTemplate::new(
        "exploit-dev",
        "Exploit Development Assistance",
        TemplateCategory::ExploitDevelopment,
        "You are an exploit development expert. Analyze the vulnerability and help develop a proof-of-concept exploit. \
         Focus on exploitation techniques appropriate for the target.",
        "Vulnerability: {{vuln_type}} at {{location}}\n\n\
         Code context:\n```\n{{code}}\n```\n\n\
         Target: {{target}}\n\
         Mitigations: {{mitigations}}\n\n\
         Suggest: (1) exploitation approach, (2) constraints, (3) PoC sketch.",
    )
    .with_var(TemplateVar::required("vuln_type", "Vulnerability type (e.g. stack overflow)"))
    .with_var(TemplateVar::required("code", "Vulnerable code"))
    .with_var(TemplateVar::optional("location", "Offset or function", "unknown"))
    .with_var(TemplateVar::optional("target", "OS/arch/version", "Linux x86-64"))
    .with_var(TemplateVar::optional("mitigations", "Active mitigations", "ASLR, NX"))
    .with_description("Assist with exploit development for a known vulnerability")
    .with_output_format(OutputFormat::Markdown)
    .with_max_tokens(2048)
    .with_tag("exploit")
}

fn builtin_function_rename() -> PromptTemplate {
    PromptTemplate::new(
        "function-rename",
        "Function Naming",
        TemplateCategory::FunctionRenaming,
        "You are a binary analysis expert. Suggest meaningful names for unnamed functions based on their behavior.",
        "Suggest a name for this function:\n\n```\n{{code}}\n```\n\n\
         Callers: {{callers}}\n\
         Callees: {{callees}}\n\n\
         Respond with: (1) suggested_name (snake_case), (2) confidence (0-100), (3) one-line description.",
    )
    .with_var(TemplateVar::required("code", "Function disassembly or pseudocode"))
    .with_var(TemplateVar::optional("callers", "List of calling functions", "unknown"))
    .with_var(TemplateVar::optional("callees", "List of called functions", "unknown"))
    .with_output_format(OutputFormat::Json)
    .with_max_tokens(256)
    .with_tag("rename")
}

fn builtin_structure_recovery() -> PromptTemplate {
    PromptTemplate::new(
        "struct-recover",
        "Data Structure Recovery",
        TemplateCategory::StructureRecovery,
        "You are a reverse engineering expert specializing in data structure recovery.",
        "Recover the data structure accessed in this code:\n\n```\n{{code}}\n```\n\n\
         Known offsets: {{offsets}}\n\n\
         Produce a C struct definition with field names, types, and sizes.",
    )
    .with_var(TemplateVar::required("code", "Code accessing the structure"))
    .with_var(TemplateVar::optional("offsets", "Known field offsets", "none"))
    .with_output_format(OutputFormat::PlainText)
    .with_max_tokens(512)
    .with_tag("struct")
    .with_tag("types")
}

fn builtin_crypto_id() -> PromptTemplate {
    PromptTemplate::new(
        "crypto-identify",
        "Cryptographic Algorithm Identification",
        TemplateCategory::CryptoIdentification,
        "You are a cryptographic algorithm expert. Identify cryptographic algorithms from code patterns.",
        "Identify the cryptographic algorithm in this code:\n\n```\n{{code}}\n```\n\n\
         Constants found: {{constants}}\n\n\
         Identify: (1) algorithm name, (2) mode of operation, (3) key size, (4) confidence.",
    )
    .with_var(TemplateVar::required("code", "Cryptographic function code"))
    .with_var(TemplateVar::optional("constants", "Observed constants", "none"))
    .with_output_format(OutputFormat::Json)
    .with_max_tokens(512)
    .with_tag("crypto")
}

fn builtin_string_decrypt() -> PromptTemplate {
    PromptTemplate::new(
        "string-decrypt",
        "Obfuscated String Decryption",
        TemplateCategory::StringDecryption,
        "You are a malware analyst expert in string obfuscation techniques.",
        "Analyze this string decryption routine:\n\n```\n{{code}}\n```\n\n\
         Encrypted data (hex): {{data_hex}}\n\n\
         Determine: (1) algorithm, (2) key, (3) decrypted strings if possible.",
    )
    .with_var(TemplateVar::required("code", "Decryption routine code"))
    .with_var(TemplateVar::optional("data_hex", "Encrypted data as hex", "unknown"))
    .with_output_format(OutputFormat::Markdown)
    .with_max_tokens(1024)
    .with_tag("strings")
    .with_tag("deobfuscation")
}

fn builtin_behavior_summary() -> PromptTemplate {
    PromptTemplate::new(
        "behavior-summary",
        "Function Behavior Summary",
        TemplateCategory::BehaviorSummary,
        "You are a reverse engineer. Provide a concise behavior summary of the given function.",
        "Summarize the behavior of this function in 2-4 sentences:\n\n```\n{{code}}\n```",
    )
    .with_var(TemplateVar::required("code", "Function code"))
    .with_output_format(OutputFormat::PlainText)
    .with_max_tokens(256)
    .with_tag("summary")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_substitute_basic() {
        let mut vars = HashMap::new();
        vars.insert("name".to_string(), "world".to_string());
        let result = substitute("Hello {{name}}!", &vars).unwrap();
        assert_eq!(result, "Hello world!");
    }

    #[test]
    fn test_substitute_missing() {
        let vars = HashMap::new();
        let result = substitute("Hello {{name}}!", &vars).unwrap();
        assert!(result.contains("[MISSING:name]"));
    }

    #[test]
    fn test_template_render_required_missing() {
        let reg = TemplateRegistry::with_builtins();
        let tmpl = reg.get("malware-analyze").unwrap();
        let vars = HashMap::new();
        // Missing 'code' (required)
        let result = tmpl.render(&vars);
        assert!(matches!(result, Err(TemplateError::MissingVariable(_))));
    }

    #[test]
    fn test_template_render_ok() {
        let reg = TemplateRegistry::with_builtins();
        let tmpl = reg.get("malware-analyze").unwrap();
        let mut vars = HashMap::new();
        vars.insert("code".to_string(), "mov rax, rbx\nret".to_string());
        let rendered = tmpl.render(&vars).unwrap();
        assert!(!rendered.user_prompt.is_empty());
        assert!(rendered.user_prompt.contains("mov rax, rbx"));
    }

    #[test]
    fn test_registry_builtins() {
        let reg = TemplateRegistry::with_builtins();
        assert!(reg.count() >= 10);
        assert!(reg.get("binary-diff").is_some());
        assert!(reg.get("nonexistent").is_none());
    }

    #[test]
    fn test_by_category() {
        let reg = TemplateRegistry::with_builtins();
        let malware = reg.by_category(TemplateCategory::MalwareAnalysis);
        assert!(!malware.is_empty());
    }

    #[test]
    fn test_prompt_chain() {
        let reg = TemplateRegistry::with_builtins();
        let chain = PromptChain::new("test-chain")
            .step(
                ChainStep::new("summarize", "behavior-summary")
                    .with_var("code", "mov rax, 1\nret")
                    .pipe_to("summary"),
            );
        let results = chain.execute(&reg, |rendered| {
            format!("MOCK RESPONSE for {}", rendered.template_id)
        });
        assert_eq!(results.len(), 1);
        assert!(results[0].output.contains("MOCK"));
    }

    #[test]
    fn test_template_version_ordering() {
        let v1 = TemplateVersion::new(1, 0, 0);
        let v2 = TemplateVersion::new(1, 1, 0);
        assert!(v2 > v1);
    }
}
