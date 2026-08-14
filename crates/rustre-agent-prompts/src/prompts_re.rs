//! RE-specific prompt templates for the `RustRE` agent framework.
//!
//! Provides the [`RePrompt`] enum, a [`PromptTemplate`] registry with variable
//! substitution, and built-in multi-paragraph prompt texts for common reverse
//! engineering analysis tasks.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::PromptError;

// ─── RePrompt ────────────────────────────────────────────────────────────────

/// All built-in RE prompt types.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RePrompt {
    /// Deep analysis of a single function.
    AnalyzeFunction,
    /// Human-readable explanation of raw assembly.
    ExplainAssembly,
    /// Vulnerability discovery in decompiled code.
    FindVulnerabilities,
    /// Identify crypto / hash / compression algorithms.
    IdentifyAlgorithm,
    /// Reverse engineer a network or file protocol.
    DescribeProtocol,
    /// Undo obfuscation and explain original intent.
    ReverseObfuscation,
    /// Malware family classification.
    ClassifyMalware,
    /// Explain observable runtime behaviour.
    ExplainBehavior,
    /// Detect persistence mechanisms in a binary.
    FindPersistence,
    /// Reconstruct an API surface from binary artefacts.
    DocumentAPI,
}

impl RePrompt {
    /// Return the canonical string key for this prompt type.
    #[must_use]
    pub const fn key(&self) -> &'static str {
        match self {
            Self::AnalyzeFunction => "analyze_function",
            Self::ExplainAssembly => "explain_assembly",
            Self::FindVulnerabilities => "find_vulnerabilities",
            Self::IdentifyAlgorithm => "identify_algorithm",
            Self::DescribeProtocol => "describe_protocol",
            Self::ReverseObfuscation => "reverse_obfuscation",
            Self::ClassifyMalware => "classify_malware",
            Self::ExplainBehavior => "explain_behavior",
            Self::FindPersistence => "find_persistence",
            Self::DocumentAPI => "document_api",
        }
    }

    /// Human-readable display name.
    #[must_use]
    pub const fn display_name(&self) -> &'static str {
        match self {
            Self::AnalyzeFunction => "Analyze Function",
            Self::ExplainAssembly => "Explain Assembly",
            Self::FindVulnerabilities => "Find Vulnerabilities",
            Self::IdentifyAlgorithm => "Identify Algorithm",
            Self::DescribeProtocol => "Describe Protocol",
            Self::ReverseObfuscation => "Reverse Obfuscation",
            Self::ClassifyMalware => "Classify Malware",
            Self::ExplainBehavior => "Explain Behavior",
            Self::FindPersistence => "Find Persistence",
            Self::DocumentAPI => "Document API",
        }
    }

    /// Return the list of required template variables for this prompt type.
    #[must_use]
    pub const fn required_variables(&self) -> &'static [&'static str] {
        match self {
            Self::AnalyzeFunction => &["function_name", "decompiled_code", "arch"],
            Self::ExplainAssembly => &["assembly_listing", "arch"],
            Self::FindVulnerabilities => &["decompiled_code", "function_name"],
            Self::IdentifyAlgorithm => &["code_snippet", "context_hint"],
            Self::DescribeProtocol => &["packet_bytes", "context"],
            Self::ReverseObfuscation => &["obfuscated_code"],
            Self::ClassifyMalware => &["binary_summary", "strings_excerpt", "imports_excerpt"],
            Self::ExplainBehavior => &["trace_summary"],
            Self::FindPersistence => &["behavior_log"],
            Self::DocumentAPI => &["binary_name", "export_list"],
        }
    }

    /// Return all built-in prompt types in definition order.
    #[must_use]
    pub fn all() -> Vec<Self> {
        vec![
            Self::AnalyzeFunction,
            Self::ExplainAssembly,
            Self::FindVulnerabilities,
            Self::IdentifyAlgorithm,
            Self::DescribeProtocol,
            Self::ReverseObfuscation,
            Self::ClassifyMalware,
            Self::ExplainBehavior,
            Self::FindPersistence,
            Self::DocumentAPI,
        ]
    }
}

// ─── BuiltinPromptText ───────────────────────────────────────────────────────

/// Raw (un-rendered) prompt text for every built-in RE prompt.
///
/// Variables use the `{{name}}` syntax consumed by [`crate::PromptTemplate::render`].
pub struct BuiltinPromptText;

impl BuiltinPromptText {
    /// Return the system prompt for the given type.
    #[must_use]
    pub const fn system(prompt: &RePrompt) -> &'static str {
        match prompt {
            RePrompt::AnalyzeFunction => {
                "You are an expert reverse engineer and vulnerability researcher. \
                 You specialise in static analysis of compiled binaries, decompiled C/C++, \
                 and assembly code. Provide thorough, accurate, and structured analysis."
            }
            RePrompt::ExplainAssembly => {
                "You are a low-level systems expert fluent in x86/x86_64, ARM, and MIPS \
                 assembly. Explain machine code clearly to a security researcher audience."
            }
            RePrompt::FindVulnerabilities => {
                "You are a security auditor specialising in binary vulnerability research. \
                 Identify memory safety issues, logic bugs, integer overflows, use-after-free, \
                 format string bugs, and other exploitable conditions."
            }
            RePrompt::IdentifyAlgorithm => {
                "You are a cryptography and algorithms expert. Identify cryptographic \
                 primitives, hash functions, compression schemes, and custom algorithms \
                 from code patterns."
            }
            RePrompt::DescribeProtocol => {
                "You are a network protocol reverse engineer. Reconstruct wire formats, \
                 field semantics, and message flows from packet captures and code."
            }
            RePrompt::ReverseObfuscation => {
                "You are a malware analyst and deobfuscation expert. Identify and undo \
                 obfuscation layers, packing, and anti-analysis tricks."
            }
            RePrompt::ClassifyMalware => {
                "You are a threat intelligence analyst. Classify malware families, \
                 identify TTPs aligned to MITRE ATT&CK, and attribute samples where \
                 evidence supports it."
            }
            RePrompt::ExplainBehavior => {
                "You are a dynamic analysis expert. Interpret execution traces, system \
                 call logs, and API call sequences to reconstruct program behaviour."
            }
            RePrompt::FindPersistence => {
                "You are a malware analyst specialising in persistence mechanisms. \
                 Identify registry keys, scheduled tasks, service installations, \
                 and other techniques used to survive reboots."
            }
            RePrompt::DocumentAPI => {
                "You are a reverse engineer specialising in API reconstruction. \
                 From binary exports and call patterns, produce developer-quality \
                 API documentation."
            }
        }
    }

    /// Return the user prompt template for the given type.
    #[must_use]
    pub const fn template(prompt: &RePrompt) -> &'static str {
        match prompt {
            RePrompt::AnalyzeFunction => {
                r"## Function Analysis Request

**Target binary architecture:** {{arch}}
**Function name:** `{{function_name}}`

### Decompiled code
```c
{{decompiled_code}}
```

### Analysis tasks
1. **Purpose** – Summarise what this function does in one paragraph.
2. **Algorithm** – Describe the algorithm or data transformation step-by-step.
3. **Arguments** – List each parameter with inferred type, role, and valid value range.
4. **Return value** – Describe what is returned and under what conditions.
5. **Side effects** – Document all memory writes, system calls, and global state mutations.
6. **Control flow** – Describe loops, conditional branches, and early-exit paths.
7. **Called functions** – Explain the role of each callee.
8. **Security observations** – Note any potentially dangerous patterns (buffer accesses, unchecked arithmetic, taint sinks).
9. **Suggested rename** – Propose a descriptive name for this function.
10. **Confidence** – Rate your confidence 1-10 and explain any uncertainties.

Provide your answer in structured markdown."
            }
            RePrompt::ExplainAssembly => {
                r"## Assembly Explanation Request

**Architecture:** {{arch}}

### Assembly listing
```asm
{{assembly_listing}}
```

### Tasks
1. **Overview** – Summarise the purpose of this code block in 2-3 sentences.
2. **Line-by-line** – Walk through each instruction group, explaining what it does in plain English.
3. **Register usage** – Map each used register to its logical role.
4. **Stack layout** – Describe any local variables and saved registers visible on the stack.
5. **Calling convention** – Identify the calling convention and map argument/return registers.
6. **Notable patterns** – Call out instruction patterns that indicate specific operations (e.g., CPUID, RDTSC, SIMD).
7. **Equivalent C pseudocode** – Write equivalent C-like pseudocode.

Use clear language suitable for a security researcher learning assembly."
            }
            RePrompt::FindVulnerabilities => {
                r"## Vulnerability Analysis Request

**Function:** `{{function_name}}`

### Decompiled code
```c
{{decompiled_code}}
```

### Analysis tasks
1. **Vulnerability summary** – List all identified vulnerabilities as a bulleted list with CWE IDs.
2. **For each vulnerability:**
   a. **Type** – Vulnerability class (buffer overflow, UAF, integer overflow, etc.)
   b. **Location** – Describe the exact lines/variables involved.
   c. **Root cause** – Explain why the bug exists.
   d. **Exploitability** – Assess difficulty and impact (local/remote, DoS/EoP/RCE).
   e. **CVSS estimate** – Provide a rough CVSS v3.1 base score.
   f. **Remediation** – Describe the fix.
3. **Attack surface** – Which function inputs are attacker-controlled?
4. **Missing mitigations** – Note absent checks (bounds checks, NULL checks, integer overflow guards).
5. **Safe functions audit** – List all unsafe function calls (strcpy, sprintf, memcpy) and their risk.
6. **Overall risk rating** – Critical / High / Medium / Low with justification.

Structure your answer in markdown with clear headings."
            }
            RePrompt::IdentifyAlgorithm => {
                r"## Algorithm Identification Request

**Context hint:** {{context_hint}}

### Code snippet
```c
{{code_snippet}}
```

### Tasks
1. **Algorithm identification** – Name the algorithm(s) present with confidence level.
2. **Evidence** – Point to the specific constants, operations, or code patterns that identify the algorithm.
3. **Variant** – If applicable, identify the specific variant (e.g., AES-128-CBC, SHA-256, zlib deflate level 6).
4. **Key schedule / initialisation** – Describe how keys or seeds are derived.
5. **Mode of operation** – For block ciphers, identify the mode of operation.
6. **Standard reference** – Cite the relevant RFC, FIPS publication, or academic paper.
7. **Custom modifications** – Note any deviations from the standard.
8. **Security assessment** – Comment on the security of this algorithm choice.
9. **Implementation quality** – Note any implementation weaknesses (timing side-channels, constant-time violations)."
            }
            RePrompt::DescribeProtocol => {
                r#"## Protocol Reverse Engineering Request

**Context:** {{context}}

### Packet bytes (hex)
```
{{packet_bytes}}
```

### Tasks
1. **Protocol identification** – Name the protocol if recognised; otherwise label it "unknown".
2. **Message type** – Identify the type/command of this message.
3. **Field breakdown** – Table with columns: Offset | Length | Field Name | Type | Value | Interpretation.
4. **Length fields** – Identify any length-prefixed fields and their scope.
5. **Header structure** – Describe the fixed header layout.
6. **Payload structure** – Describe variable-length payload sections.
7. **Framing** – Describe message boundaries, delimiters, or length-prefixed framing.
8. **Encoding** – Note any encoding (TLV, ASN.1, protobuf, custom).
9. **Checksums / MACs** – Identify integrity fields and their algorithms.
10. **Inferred C struct** – Write a C struct definition for this message.
11. **Wireshark dissector sketch** – Outline the Lua dissector logic."#
            }
            RePrompt::ReverseObfuscation => {
                r"## Deobfuscation Request

### Obfuscated code
```c
{{obfuscated_code}}
```

### Tasks
1. **Obfuscation techniques** – Enumerate all obfuscation techniques present.
2. **Deobfuscation steps** – Describe, step-by-step, how to undo each technique.
3. **Deobfuscated code** – Provide the clean, deobfuscated version.
4. **Original intent** – Explain what the code does after deobfuscation.
5. **Anti-analysis tricks** – List any anti-disassembly, anti-debugging, or anti-VM techniques.
6. **String decryption** – If string encryption is present, reconstruct the decryption routine.
7. **Control flow reconstruction** – If control flow is flattened or opaque, describe the true flow.
8. **Confidence** – Rate your confidence in the deobfuscation (1-10)."
            }
            RePrompt::ClassifyMalware => {
                r"## Malware Classification Request

### Binary summary
{{binary_summary}}

### Strings excerpt
```
{{strings_excerpt}}
```

### Imports excerpt
```
{{imports_excerpt}}
```

### Tasks
1. **Malware family** – Name the suspected family with confidence (High/Medium/Low).
2. **Evidence** – List the specific IOCs (strings, import patterns, hashes) that led to classification.
3. **Malware type** – Classify (RAT, ransomware, banker, dropper, stealer, botnet agent, etc.).
4. **MITRE ATT&CK TTPs** – List all applicable techniques with IDs (e.g., T1059.001).
5. **Capabilities summary** – Enumerate functional capabilities observed.
6. **C2 indicators** – Any hardcoded C2 addresses, URLs, or DGAs.
7. **Attribution hints** – Any language, pdb paths, compile-time artifacts, or tooling overlaps.
8. **Defensive recommendations** – YARA rules, network signatures, or registry/filesystem IOCs.
9. **Confidence assessment** – Explain limitations and alternative hypotheses."
            }
            RePrompt::ExplainBehavior => {
                r"## Behavior Explanation Request

### Trace summary
```
{{trace_summary}}
```

### Tasks
1. **High-level summary** – Describe in 2-3 sentences what the program is doing.
2. **Key operations** – List the most significant operations in chronological order.
3. **File system activity** – Describe all file reads, writes, creates, deletes.
4. **Network activity** – Describe all socket operations, DNS queries, HTTP requests.
5. **Registry activity** – Describe all registry key reads and writes.
6. **Process activity** – Describe process creation, injection, and termination.
7. **Memory operations** – Describe notable memory allocations, mappings, or protections.
8. **Synchronisation** – Describe mutex/event creation and usage.
9. **Anti-analysis behaviour** – Note any environment checks or sandbox evasion.
10. **Timeline reconstruction** – Build a chronological timeline of key events.
11. **IOC extraction** – Extract all observable IOCs (hashes, IPs, URLs, mutexes, registry keys)."
            }
            RePrompt::FindPersistence => {
                r"## Persistence Mechanism Analysis Request

### Behavior log
```
{{behavior_log}}
```

### Tasks
1. **Persistence mechanisms found** – List all identified persistence mechanisms.
2. **For each mechanism:**
   a. **Technique** – MITRE ATT&CK technique ID and name.
   b. **Location** – Exact registry key, file path, service name, or task name.
   c. **Trigger** – When is this mechanism activated (boot, logon, scheduled, etc.)?
   d. **Payload** – What is executed?
   e. **Privileges required** – What privilege level is needed to install?
   f. **Removal steps** – How to remove this persistence.
3. **Stealth assessment** – How hidden are these mechanisms from standard AV/EDR?
4. **Redundancy** – Are there multiple persistence mechanisms (failsafe)?
5. **Lateral movement hooks** – Any mechanisms that spread to other systems?
6. **Detection signatures** – Write detection rules (pseudo-YARA or Sigma) for each mechanism."
            }
            RePrompt::DocumentAPI => {
                r"## API Documentation Request

**Binary:** `{{binary_name}}`

### Export list
```
{{export_list}}
```

### Tasks
1. **API overview** – Describe the purpose and audience for this API.
2. **For each export:**
   a. **Prototype** – Reconstruct the function signature (return type, parameter types, names).
   b. **Description** – One-paragraph description of what the function does.
   c. **Parameters** – Document each parameter (type, role, valid values, ownership).
   d. **Return value** – Document the return value and error codes.
   e. **Thread safety** – Assess whether the function is thread-safe.
   f. **Calling convention** – Identify the calling convention.
   g. **Usage example** – Provide a short C/C++ usage example.
3. **Dependency graph** – Describe internal dependencies between exported functions.
4. **Error handling** – Describe the overall error reporting strategy.
5. **Versioning** – Note any version-tagged or ordinal-only exports.
6. **Security considerations** – Note any dangerous patterns in the exported API.
7. **Header file** – Generate a compilable C header declaring all exports."
            }
        }
    }
}

// ─── RePromptRegistry ────────────────────────────────────────────────────────

/// Registry of all RE prompt templates, keyed by [`RePrompt`].
///
/// Provides named-variable substitution and supports user-supplied overrides.
pub struct RePromptRegistry {
    templates: HashMap<RePrompt, crate::PromptTemplate>,
}

impl RePromptRegistry {
    /// Create a registry pre-populated with all built-in prompts.
    #[must_use]
    pub fn with_builtins() -> Self {
        let all = RePrompt::all();
        let mut registry = Self {
            templates: HashMap::with_capacity(all.len()),
        };
        for prompt in all {
            let raw_vars = RePrompt::required_variables(&prompt);
            let mut vars: Vec<String> = Vec::with_capacity(raw_vars.len());
            vars.extend(raw_vars.iter().map(|s| (*s).to_owned()));
            let t = crate::PromptTemplate::new(
                prompt.key(),
                BuiltinPromptText::template(&prompt),
                vars,
                BuiltinPromptText::system(&prompt),
            );
            registry.templates.insert(prompt, t);
        }
        registry
    }

    /// Render a built-in prompt with the supplied variable map.
    pub fn render(
        &self,
        prompt: &RePrompt,
        vars: &HashMap<String, String>,
    ) -> Result<String, PromptError> {
        match self.templates.get(prompt) {
            Some(t) => t.render(vars),
            None => Err(PromptError::TemplateNotFound(prompt.key().to_owned())),
        }
    }

    /// Override a built-in template with a custom one.
    pub fn override_template(&mut self, prompt: RePrompt, template: crate::PromptTemplate) {
        self.templates.insert(prompt, template);
    }

    /// Return the system prompt for a given type.
    #[must_use] 
    pub fn system_prompt(&self, prompt: &RePrompt) -> Option<&str> {
        self.templates.get(prompt).map(|t| t.system_prompt.as_str())
    }

    /// Return the template body for a given type.
    #[must_use] 
    pub fn template_body(&self, prompt: &RePrompt) -> Option<&str> {
        self.templates.get(prompt).map(|t| t.template.as_str())
    }

    /// Return the required variables for a given type.
    #[must_use] 
    pub fn variables(&self, prompt: &RePrompt) -> Option<&[String]> {
        self.templates.get(prompt).map(|t| t.variables.as_slice())
    }
}

// ─── PromptVariableBuilder ────────────────────────────────────────────────────

/// Fluent builder for assembling variable maps used with [`RePromptRegistry`].
#[derive(Default)]
pub struct PromptVariableBuilder {
    vars: HashMap<String, String>,
}

impl PromptVariableBuilder {
    /// Create a new empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a variable.
    #[must_use]
    pub fn set(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.vars.insert(key.into(), value.into());
        self
    }

    /// Build the variable map.
    #[must_use]
    pub fn build(self) -> HashMap<String, String> {
        self.vars
    }
}

// ─── PromptMetadata ──────────────────────────────────────────────────────────

/// Metadata about a rendered prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptMetadata {
    /// Which RE prompt type was rendered.
    pub prompt_type: String,
    /// Number of characters in the rendered prompt.
    pub char_count: usize,
    /// Approximate token count (chars / 4).
    pub approx_tokens: usize,
    /// Variables that were supplied.
    pub supplied_vars: Vec<String>,
}

impl PromptMetadata {
    /// Compute metadata from a rendered prompt string and its source type.
    #[must_use]
    pub fn compute(prompt_type: &RePrompt, rendered: &str, vars: &HashMap<String, String>) -> Self {
        let char_count = rendered.len();
        Self {
            prompt_type: prompt_type.key().to_owned(),
            char_count,
            approx_tokens: char_count / 4,
            supplied_vars: vars.keys().cloned().collect(),
        }
    }
}

// ─── RenderedPrompt ──────────────────────────────────────────────────────────

/// A fully rendered prompt ready to send to an LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedPrompt {
    /// System prompt.
    pub system: String,
    /// User prompt body.
    pub user: String,
    /// Metadata.
    pub metadata: PromptMetadata,
}

impl RenderedPrompt {
    /// Render a prompt from the registry.
    pub fn render(
        registry: &RePromptRegistry,
        prompt: &RePrompt,
        vars: HashMap<String, String>,
    ) -> Result<Self, PromptError> {
        let user = registry.render(prompt, &vars)?;
        let system = registry.system_prompt(prompt).unwrap_or("").to_owned();
        let metadata = PromptMetadata::compute(prompt, &user, &vars);
        Ok(Self {
            system,
            user,
            metadata,
        })
    }

    /// Return the total estimated token count (system + user combined).
    #[must_use]
    pub const fn total_tokens(&self) -> usize {
        (self.system.len() + self.user.len()) / 4
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> RePromptRegistry {
        RePromptRegistry::with_builtins()
    }

    #[test]
    fn test_all_prompts_registered() {
        let reg = make_registry();
        for p in RePrompt::all() {
            assert!(
                reg.template_body(&p).is_some(),
                "missing template for {p:?}"
            );
        }
    }

    #[test]
    fn test_analyze_function_render() {
        let reg = make_registry();
        let vars = PromptVariableBuilder::new()
            .set("function_name", "sub_401000")
            .set(
                "decompiled_code",
                "int sub_401000(char *buf, int len) { return len; }",
            )
            .set("arch", "x86_64")
            .build();
        let rendered = reg.render(&RePrompt::AnalyzeFunction, &vars).unwrap();
        assert!(rendered.contains("sub_401000"));
        assert!(rendered.contains("x86_64"));
    }

    #[test]
    fn test_missing_variable_error() {
        let reg = make_registry();
        let vars = HashMap::new();
        let result = reg.render(&RePrompt::AnalyzeFunction, &vars);
        assert!(result.is_err());
    }

    #[test]
    fn test_explain_assembly_render() {
        let reg = make_registry();
        let vars = PromptVariableBuilder::new()
            .set("assembly_listing", "push rbp\nmov rbp, rsp\nret")
            .set("arch", "x86_64")
            .build();
        let rendered = reg.render(&RePrompt::ExplainAssembly, &vars).unwrap();
        assert!(rendered.contains("push rbp"));
    }

    #[test]
    fn test_find_vulnerabilities_render() {
        let reg = make_registry();
        let vars = PromptVariableBuilder::new()
            .set("decompiled_code", "strcpy(buf, input);")
            .set("function_name", "parse_input")
            .build();
        let rendered = reg.render(&RePrompt::FindVulnerabilities, &vars).unwrap();
        assert!(rendered.contains("parse_input"));
    }

    #[test]
    fn test_identify_algorithm_render() {
        let reg = make_registry();
        let vars = PromptVariableBuilder::new()
            .set("code_snippet", "state[0] = 0x67452301;")
            .set("context_hint", "hash function")
            .build();
        let rendered = reg.render(&RePrompt::IdentifyAlgorithm, &vars).unwrap();
        assert!(rendered.contains("hash function"));
    }

    #[test]
    fn test_describe_protocol_render() {
        let reg = make_registry();
        let vars = PromptVariableBuilder::new()
            .set("packet_bytes", "00 01 02 03")
            .set("context", "TCP stream")
            .build();
        let rendered = reg.render(&RePrompt::DescribeProtocol, &vars).unwrap();
        assert!(rendered.contains("00 01 02 03"));
    }

    #[test]
    fn test_reverse_obfuscation_render() {
        let reg = make_registry();
        let vars = PromptVariableBuilder::new()
            .set("obfuscated_code", "x = (a ^ 0xDEAD) + b;")
            .build();
        let rendered = reg.render(&RePrompt::ReverseObfuscation, &vars).unwrap();
        assert!(rendered.contains("0xDEAD"));
    }

    #[test]
    fn test_classify_malware_render() {
        let reg = make_registry();
        let vars = PromptVariableBuilder::new()
            .set("binary_summary", "PE32+, 512KB, signed")
            .set("strings_excerpt", "cmd.exe\nhttp://evil.example.com")
            .set("imports_excerpt", "VirtualAlloc\nWriteProcessMemory")
            .build();
        let rendered = reg.render(&RePrompt::ClassifyMalware, &vars).unwrap();
        assert!(rendered.contains("VirtualAlloc"));
    }

    #[test]
    fn test_explain_behavior_render() {
        let reg = make_registry();
        let vars = PromptVariableBuilder::new()
            .set(
                "trace_summary",
                "CreateFile(config.ini)\nRegOpenKey(HKLM\\Software)",
            )
            .build();
        let rendered = reg.render(&RePrompt::ExplainBehavior, &vars).unwrap();
        assert!(rendered.contains("config.ini"));
    }

    #[test]
    fn test_find_persistence_render() {
        let reg = make_registry();
        let vars = PromptVariableBuilder::new()
            .set("behavior_log", "RegSetValue(Run\\malware.exe)")
            .build();
        let rendered = reg.render(&RePrompt::FindPersistence, &vars).unwrap();
        assert!(rendered.contains("malware.exe"));
    }

    #[test]
    fn test_document_api_render() {
        let reg = make_registry();
        let vars = PromptVariableBuilder::new()
            .set("binary_name", "target.dll")
            .set("export_list", "Initialize\nProcess\nCleanup")
            .build();
        let rendered = reg.render(&RePrompt::DocumentAPI, &vars).unwrap();
        assert!(rendered.contains("target.dll"));
    }

    #[test]
    fn test_prompt_keys_unique() {
        let keys: Vec<_> = RePrompt::all().iter().map(super::RePrompt::key).collect();
        let unique: std::collections::HashSet<_> = keys.iter().collect();
        assert_eq!(keys.len(), unique.len());
    }

    #[test]
    fn test_required_variables_non_empty() {
        for p in RePrompt::all() {
            assert!(
                !p.required_variables().is_empty(),
                "{p:?} has no required vars"
            );
        }
    }

    #[test]
    fn test_variable_builder_chain() {
        let vars = PromptVariableBuilder::new()
            .set("a", "1")
            .set("b", "2")
            .set("c", "3")
            .build();
        assert_eq!(vars.len(), 3);
        assert_eq!(vars["a"], "1");
    }

    #[test]
    fn test_prompt_metadata_compute() {
        let text = "Hello world";
        let mut vars = HashMap::new();
        vars.insert("x".to_owned(), "y".to_owned());
        let meta = PromptMetadata::compute(&RePrompt::ExplainAssembly, text, &vars);
        assert_eq!(meta.char_count, text.len());
        assert_eq!(meta.approx_tokens, text.len() / 4);
        assert_eq!(meta.prompt_type, "explain_assembly");
    }

    #[test]
    fn test_rendered_prompt_total_tokens() {
        let rp = RenderedPrompt {
            system: "sys".to_owned(),
            user: "usr".to_owned(),
            metadata: PromptMetadata {
                prompt_type: "test".to_owned(),
                char_count: 3,
                approx_tokens: 0,
                supplied_vars: vec![],
            },
        };
        assert_eq!(rp.total_tokens(), 3_usize.div_ceil(4));
    }

    #[test]
    fn test_system_prompt_non_empty() {
        let reg = make_registry();
        for p in RePrompt::all() {
            let sys = reg.system_prompt(&p).unwrap();
            assert!(!sys.is_empty(), "{p:?} system prompt is empty");
        }
    }

    #[test]
    fn test_override_template() {
        let mut reg = make_registry();
        let custom = crate::PromptTemplate::new(
            "explain_assembly",
            "Custom: {{arch}}",
            vec!["arch".to_owned()],
            "Custom system",
        );
        reg.override_template(RePrompt::ExplainAssembly, custom);
        let mut vars = HashMap::new();
        vars.insert("arch".to_owned(), "ARM64".to_owned());
        let result = reg.render(&RePrompt::ExplainAssembly, &vars).unwrap();
        assert_eq!(result, "Custom: ARM64");
    }

    #[test]
    fn test_display_names_non_empty() {
        for p in RePrompt::all() {
            assert!(!p.display_name().is_empty());
        }
    }

    #[test]
    fn test_rendered_prompt_from_registry() {
        let reg = make_registry();
        let vars: HashMap<String, String> = [
            ("arch", "x86_64"),
            ("function_name", "fn_test"),
            ("decompiled_code", "return 0;"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let rp = RenderedPrompt::render(&reg, &RePrompt::AnalyzeFunction, vars).unwrap();
        assert!(!rp.system.is_empty());
        assert!(rp.user.contains("fn_test"));
        assert_eq!(rp.metadata.prompt_type, "analyze_function");
    }

    #[test]
    fn test_all_prompts_count() {
        assert_eq!(RePrompt::all().len(), 10);
    }

    #[test]
    fn test_builtin_system_text_not_empty() {
        for p in RePrompt::all() {
            assert!(!BuiltinPromptText::system(&p).is_empty());
        }
    }

    #[test]
    fn test_builtin_template_text_not_empty() {
        for p in RePrompt::all() {
            assert!(!BuiltinPromptText::template(&p).is_empty());
        }
    }

    #[test]
    fn test_find_persistence_mitre_reference() {
        let reg = make_registry();
        let vars = PromptVariableBuilder::new()
            .set("behavior_log", "NtCreateKey(HKLM\\Run)")
            .build();
        let rendered = reg.render(&RePrompt::FindPersistence, &vars).unwrap();
        assert!(rendered.contains("MITRE"));
    }
}
