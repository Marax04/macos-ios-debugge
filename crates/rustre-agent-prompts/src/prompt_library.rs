// rustre-agent-prompts/src/prompt_library.rs
//
// Prompt library: 50+ prompt templates across all RE analysis categories.
// Each template has:
//   - system prompt
//   - user prompt template ({{variable}} placeholders)
//   - expected_output_schema (JSON Schema)
//   - few_shot examples (inline)
//   - category tag
//
// Intentionally distinct from `re_prompt_library`: this module is
// **schema-oriented** — every template carries a JSON Schema describing
// expected output, and categories map to structured RE tasks
// (FunctionAnalysis, MalwareClassification, …).
// `re_prompt_library` is **domain-oriented** — categories map to analysis
// modalities (Disassembly, DotNet, Yara, …) and templates carry token
// estimates, `expects_json` flags, and `ContextualPrompt` helpers.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────── Error ───────────────────────────────────────

#[derive(Debug, Error)]
pub enum LibraryError {
    #[error("template '{0}' not found")]
    NotFound(String),
    #[error("render error: missing variable '{0}'")]
    MissingVar(String),
    #[error("serialization error: {0}")]
    Serialize(String),
}

pub type LibResult<T> = Result<T, LibraryError>;

// ─────────────────────────────── Category ────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    FunctionAnalysis,
    MalwareClassification,
    VulnerabilityHunting,
    ProtocolReversal,
    CryptoIdentification,
    PackerAnalysis,
    CtfSolving,
    CodeSimilarity,
    StringAnalysis,
    TypeRecovery,
    Obfuscation,
    BehaviorAnalysis,
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self).ok()
            .and_then(|v| v.as_str().map(|s| s.to_owned()))
            .unwrap_or_default();
        write!(f, "{s}")
    }
}

// ─────────────────────────────── FewShotExample ──────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FewShotExample {
    pub input: String,
    pub output: String,
    pub description: String,
}

impl FewShotExample {
    pub fn new(input: impl Into<String>, output: impl Into<String>, description: impl Into<String>) -> Self {
        Self { input: input.into(), output: output.into(), description: description.into() }
    }
}

// ─────────────────────────────── PromptTemplate ──────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptTemplate {
    pub id: String,
    pub name: String,
    pub category: Category,
    pub description: String,
    pub system: String,
    pub user: String, // may contain {{var}} placeholders
    pub expected_output_schema: serde_json::Value,
    pub few_shots: Vec<FewShotExample>,
    pub variables: Vec<String>, // documented required variables
    pub tags: Vec<String>,
    pub version: String,
}

impl PromptTemplate {
    /// Render the user template by substituting {{variables}}.
    pub fn render_user(&self, vars: &HashMap<String, String>) -> LibResult<String> {
        render_template(&self.user, vars)
    }

    /// Render system + user into (system, user) pair.
    pub fn render(&self, vars: &HashMap<String, String>) -> LibResult<(String, String)> {
        let system = render_template(&self.system, vars)?;
        let user = render_template(&self.user, vars)?;
        Ok((system, user))
    }

    /// Build a few-shot block for prepending to the user prompt.
    pub fn few_shot_block(&self) -> String {
        if self.few_shots.is_empty() {
            return String::new();
        }
        let mut out = String::from("### Examples\n");
        for ex in &self.few_shots {
            out.push_str(&format!("**Input**: {}\n**Output**: {}\n\n", ex.input, ex.output));
        }
        out
    }

    pub fn render_with_few_shots(&self, vars: &HashMap<String, String>) -> LibResult<(String, String)> {
        let (sys, usr) = self.render(vars)?;
        let few = self.few_shot_block();
        Ok((sys, format!("{few}{usr}")))
    }
}

fn render_template(template: &str, vars: &HashMap<String, String>) -> LibResult<String> {
    let mut out = template.to_owned();
    let mut search_from = 0;
    loop {
        let start = match out[search_from..].find("{{") {
            Some(i) => search_from + i,
            None => break,
        };
        let end = match out[start..].find("}}") {
            Some(i) => start + i + 2,
            None => break,
        };
        let key = &out[start + 2..end - 2].trim().to_owned();
        let key = key.as_str();
        match vars.get(key) {
            Some(val) => {
                let replacement = val.clone();
                out.replace_range(start..end, &replacement);
                search_from = start + replacement.len();
            }
            None => {
                return Err(LibraryError::MissingVar(key.to_owned()));
            }
        }
    }
    Ok(out)
}

// ─────────────────────────────── PromptLibrary ───────────────────────────────

pub struct PromptLibrary {
    templates: HashMap<String, PromptTemplate>,
}

impl PromptLibrary {
    pub fn new() -> Self { Self { templates: HashMap::new() } }

    pub fn with_builtins() -> Self {
        let mut lib = Self::new();
        for t in builtin_templates() {
            lib.add(t);
        }
        lib
    }

    pub fn add(&mut self, t: PromptTemplate) {
        self.templates.insert(t.id.clone(), t);
    }

    pub fn get(&self, id: &str) -> LibResult<&PromptTemplate> {
        self.templates.get(id).ok_or_else(|| LibraryError::NotFound(id.to_owned()))
    }

    pub fn by_category(&self, cat: &Category) -> Vec<&PromptTemplate> {
        self.templates.values().filter(|t| &t.category == cat).collect()
    }

    pub fn by_tag(&self, tag: &str) -> Vec<&PromptTemplate> {
        self.templates.values().filter(|t| t.tags.iter().any(|tg| tg == tag)).collect()
    }

    pub fn all_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.templates.keys().cloned().collect();
        ids.sort();
        ids
    }

    pub fn count(&self) -> usize { self.templates.len() }

    pub fn render(&self, id: &str, vars: &HashMap<String, String>) -> LibResult<(String, String)> {
        self.get(id)?.render(vars)
    }

    pub fn render_with_few_shots(&self, id: &str, vars: &HashMap<String, String>) -> LibResult<(String, String)> {
        self.get(id)?.render_with_few_shots(vars)
    }
}

impl Default for PromptLibrary {
    fn default() -> Self { Self::with_builtins() }
}

// ─────────────────────────────── Builder ─────────────────────────────────────

struct TemplateBuilder {
    t: PromptTemplate,
}

impl TemplateBuilder {
    fn new(id: &str, name: &str, category: Category) -> Self {
        Self {
            t: PromptTemplate {
                id: id.to_owned(),
                name: name.to_owned(),
                category,
                description: String::new(),
                system: String::new(),
                user: String::new(),
                expected_output_schema: serde_json::json!({}),
                few_shots: Vec::new(),
                variables: Vec::new(),
                tags: Vec::new(),
                version: "1.0".to_owned(),
            },
        }
    }
    fn desc(mut self, d: &str) -> Self { self.t.description = d.to_owned(); self }
    fn system(mut self, s: &str) -> Self { self.t.system = s.to_owned(); self }
    fn user(mut self, u: &str) -> Self { self.t.user = u.to_owned(); self }
    fn schema(mut self, s: serde_json::Value) -> Self { self.t.expected_output_schema = s; self }
    fn vars(mut self, v: &[&str]) -> Self { self.t.variables = v.iter().map(|s| s.to_string()).collect(); self }
    fn tags(mut self, v: &[&str]) -> Self { self.t.tags = v.iter().map(|s| s.to_string()).collect(); self }
    fn shot(mut self, input: &str, output: &str, desc: &str) -> Self {
        self.t.few_shots.push(FewShotExample::new(input, output, desc));
        self
    }
    fn build(self) -> PromptTemplate { self.t }
}

// ─────────────────────────────── Built-in templates ──────────────────────────

const RE_SYSTEM: &str = "You are an expert reverse engineering assistant. \
Be precise, cite evidence, and always return well-formed JSON when requested.";

fn builtin_templates() -> Vec<PromptTemplate> {
    vec![
        // ── Function Analysis ─────────────────────────────────────────────────

        TemplateBuilder::new("fa_rename", "Rename Function", Category::FunctionAnalysis)
            .desc("Suggest a descriptive name for a function based on disassembly and pseudocode")
            .system(RE_SYSTEM)
            .user("Function at 0x{{address}} (currently '{{current_name}}'):\n\n```asm\n{{disasm}}\n```\n\nSuggest a snake_case name and brief description.")
            .schema(serde_json::json!({"type":"object","properties":{"new_name":{"type":"string"},"description":{"type":"string"},"confidence":{"type":"number"}}}))
            .vars(&["address","current_name","disasm"])
            .tags(&["rename","function","quick"])
            .shot("int sub_1000(int a, int b) { return a + b; }", r#"{"new_name":"add_integers","description":"Adds two integers","confidence":0.99}"#, "simple add")
            .shot("char* sub_2000(char* s) { while(*s++) {} return s-1; }", r#"{"new_name":"find_string_end","description":"Returns pointer past end of string","confidence":0.95}"#, "strlen variant")
            .build(),

        TemplateBuilder::new("fa_classify", "Classify Function", Category::FunctionAnalysis)
            .desc("Classify a function by its role (crypto, network, anti-debug, etc.)")
            .system(RE_SYSTEM)
            .user("Classify the following function:\n\n```c\n{{pseudocode}}\n```\n\nReturn JSON with: class (one of: crypto/network/anti_debug/string_op/math/io/ui/unknown), sub_class, confidence.")
            .schema(serde_json::json!({"type":"object","properties":{"class":{"type":"string"},"sub_class":{"type":"string"},"confidence":{"type":"number"}}}))
            .vars(&["pseudocode"])
            .tags(&["classify","function"])
            .build(),

        TemplateBuilder::new("fa_parameters", "Recover Parameters", Category::FunctionAnalysis)
            .desc("Recover parameter names and types for a function")
            .system(RE_SYSTEM)
            .user("Recover parameter names and types for the function at 0x{{address}}:\n\n```c\n{{pseudocode}}\n```\n\nReturn JSON array of parameters.")
            .schema(serde_json::json!({"type":"array","items":{"type":"object","properties":{"index":{"type":"integer"},"name":{"type":"string"},"type":{"type":"string"},"description":{"type":"string"}}}}))
            .vars(&["address","pseudocode"])
            .tags(&["parameters","types"])
            .build(),

        TemplateBuilder::new("fa_purpose", "Explain Function Purpose", Category::FunctionAnalysis)
            .desc("Write a detailed explanation of what a function does")
            .system(RE_SYSTEM)
            .user("Explain in detail what the following function does:\n\n```c\n{{pseudocode}}\n```")
            .schema(serde_json::json!({"type":"object","properties":{"summary":{"type":"string"},"details":{"type":"string"},"side_effects":{"type":"array","items":{"type":"string"}}}}))
            .vars(&["pseudocode"])
            .tags(&["explain","function"])
            .build(),

        TemplateBuilder::new("fa_calltree", "Analyse Call Tree", Category::FunctionAnalysis)
            .desc("Summarise the behaviour implied by a function's call tree")
            .system(RE_SYSTEM)
            .user("The function '{{name}}' calls: {{callees}}.\nBased on these callees, infer the function's high-level purpose.")
            .schema(serde_json::json!({"type":"object","properties":{"purpose":{"type":"string"},"category":{"type":"string"}}}))
            .vars(&["name","callees"])
            .tags(&["calltree","function"])
            .build(),

        // ── Malware Classification ─────────────────────────────────────────────

        TemplateBuilder::new("mc_triage", "Malware Triage", Category::MalwareClassification)
            .desc("Quick triage: classify malware family and capabilities")
            .system(RE_SYSTEM)
            .user("Triage this binary:\nImports: {{imports}}\nStrings: {{strings}}\nEntropy of .text: {{entropy}}\n\nClassify: family, capabilities, threat level.")
            .schema(serde_json::json!({"type":"object","properties":{"family":{"type":"string"},"capabilities":{"type":"array","items":{"type":"string"}},"threat_level":{"type":"string"},"confidence":{"type":"number"}}}))
            .vars(&["imports","strings","entropy"])
            .tags(&["malware","triage"])
            .shot("imports: VirtualAlloc,WriteProcessMemory,CreateRemoteThread / strings: 'inject'", r#"{"family":"injector","capabilities":["process_injection"],"threat_level":"high","confidence":0.85}"#, "classic injector")
            .build(),

        TemplateBuilder::new("mc_ioc", "Extract IoCs", Category::MalwareClassification)
            .desc("Extract Indicators of Compromise from strings and imports")
            .system(RE_SYSTEM)
            .user("Extract IoCs from:\nStrings: {{strings}}\nNetwork calls: {{network_calls}}\n\nReturn IPs, domains, registry keys, mutex names, file paths.")
            .schema(serde_json::json!({"type":"object","properties":{"ips":{"type":"array"},"domains":{"type":"array"},"registry_keys":{"type":"array"},"mutexes":{"type":"array"},"file_paths":{"type":"array"}}}))
            .vars(&["strings","network_calls"])
            .tags(&["ioc","malware"])
            .build(),

        TemplateBuilder::new("mc_persistence", "Identify Persistence", Category::MalwareClassification)
            .desc("Identify persistence mechanisms used by malware")
            .system(RE_SYSTEM)
            .user("Based on registry calls and file operations below, identify persistence mechanisms:\n{{api_calls}}")
            .schema(serde_json::json!({"type":"array","items":{"type":"object","properties":{"mechanism":{"type":"string"},"location":{"type":"string"},"confidence":{"type":"number"}}}}))
            .vars(&["api_calls"])
            .tags(&["persistence","malware"])
            .build(),

        TemplateBuilder::new("mc_network", "Network Behaviour", Category::MalwareClassification)
            .desc("Characterise the binary's network behaviour")
            .system(RE_SYSTEM)
            .user("Characterise network behaviour from:\nSocket APIs: {{socket_apis}}\nStrings: {{network_strings}}\nPacket structure hints: {{packet_hints}}")
            .schema(serde_json::json!({"type":"object","properties":{"protocol":{"type":"string"},"c2_indicators":{"type":"array"},"encryption":{"type":"string"},"beaconing_interval_hint":{"type":"string"}}}))
            .vars(&["socket_apis","network_strings","packet_hints"])
            .tags(&["network","malware","c2"])
            .build(),

        TemplateBuilder::new("mc_evasion", "Evasion Techniques", Category::MalwareClassification)
            .desc("Identify anti-analysis and evasion techniques")
            .system(RE_SYSTEM)
            .user("Identify evasion techniques from:\nAPIs: {{api_calls}}\nCode patterns: {{code_notes}}")
            .schema(serde_json::json!({"type":"array","items":{"type":"object","properties":{"technique":{"type":"string"},"description":{"type":"string"},"address":{"type":"integer"}}}}))
            .vars(&["api_calls","code_notes"])
            .tags(&["evasion","anti-debug","malware"])
            .build(),

        // ── Vulnerability Hunting ──────────────────────────────────────────────

        TemplateBuilder::new("vh_overflow", "Buffer Overflow Hunt", Category::VulnerabilityHunting)
            .desc("Hunt for buffer overflow vulnerabilities")
            .system(RE_SYSTEM)
            .user("Audit for buffer overflows in:\n```c\n{{pseudocode}}\n```\nFocus on: unbounded copies, stack buffers, length checks.")
            .schema(serde_json::json!({"type":"array","items":{"type":"object","properties":{"type":{"type":"string"},"location":{"type":"string"},"exploitability":{"type":"string"},"poc":{"type":"string"}}}}))
            .vars(&["pseudocode"])
            .tags(&["overflow","vulnerability"])
            .build(),

        TemplateBuilder::new("vh_uaf", "Use-After-Free Hunt", Category::VulnerabilityHunting)
            .desc("Hunt for use-after-free vulnerabilities")
            .system(RE_SYSTEM)
            .user("Audit for use-after-free in:\n```c\n{{pseudocode}}\n```")
            .schema(serde_json::json!({"type":"array","items":{"type":"object","properties":{"description":{"type":"string"},"free_site":{"type":"string"},"use_site":{"type":"string"},"exploitability":{"type":"string"}}}}))
            .vars(&["pseudocode"])
            .tags(&["uaf","vulnerability"])
            .build(),

        TemplateBuilder::new("vh_integer", "Integer Overflow Hunt", Category::VulnerabilityHunting)
            .desc("Hunt for integer overflow and underflow vulnerabilities")
            .system(RE_SYSTEM)
            .user("Audit for integer overflows in:\n```c\n{{pseudocode}}\n```")
            .schema(serde_json::json!({"type":"array","items":{"type":"object","properties":{"expression":{"type":"string"},"type":{"type":"string"},"impact":{"type":"string"}}}}))
            .vars(&["pseudocode"])
            .tags(&["integer","vulnerability"])
            .build(),

        TemplateBuilder::new("vh_format", "Format String Hunt", Category::VulnerabilityHunting)
            .desc("Hunt for format string vulnerabilities")
            .system(RE_SYSTEM)
            .user("Audit for format string bugs in:\n```c\n{{pseudocode}}\n```")
            .schema(serde_json::json!({"type":"array","items":{"type":"object","properties":{"call_site":{"type":"string"},"format_arg":{"type":"string"},"exploitability":{"type":"string"}}}}))
            .vars(&["pseudocode"])
            .tags(&["format-string","vulnerability"])
            .build(),

        TemplateBuilder::new("vh_toctou", "TOCTOU Hunt", Category::VulnerabilityHunting)
            .desc("Hunt for TOCTOU race conditions")
            .system(RE_SYSTEM)
            .user("Audit for TOCTOU conditions in:\n```c\n{{pseudocode}}\n```\nLook for: check then use patterns on files/resources.")
            .schema(serde_json::json!({"type":"array","items":{"type":"object","properties":{"description":{"type":"string"},"check_site":{"type":"string"},"use_site":{"type":"string"}}}}))
            .vars(&["pseudocode"])
            .tags(&["toctou","race","vulnerability"])
            .build(),

        TemplateBuilder::new("vh_cmd_injection", "Command Injection Hunt", Category::VulnerabilityHunting)
            .desc("Hunt for command/shell injection vulnerabilities")
            .system(RE_SYSTEM)
            .user("Audit for command injection in:\n```c\n{{pseudocode}}\n```")
            .schema(serde_json::json!({"type":"array","items":{"type":"object","properties":{"sink":{"type":"string"},"source":{"type":"string"},"exploitability":{"type":"string"}}}}))
            .vars(&["pseudocode"])
            .tags(&["command-injection","vulnerability"])
            .build(),

        // ── Protocol Reversal ─────────────────────────────────────────────────

        TemplateBuilder::new("pr_message_format", "Parse Message Format", Category::ProtocolReversal)
            .desc("Reverse-engineer a network message format from packet handling code")
            .system(RE_SYSTEM)
            .user("Reverse the message format from:\n```c\n{{pseudocode}}\n```\nStrings: {{network_strings}}")
            .schema(serde_json::json!({"type":"object","properties":{"header_fields":{"type":"array"},"payload_fields":{"type":"array"},"framing":{"type":"string"},"endianness":{"type":"string"}}}))
            .vars(&["pseudocode","network_strings"])
            .tags(&["protocol","network","format"])
            .build(),

        TemplateBuilder::new("pr_commands", "Extract Command IDs", Category::ProtocolReversal)
            .desc("Extract command/opcode IDs from protocol dispatch code")
            .system(RE_SYSTEM)
            .user("Extract command IDs from dispatch code:\n```c\n{{pseudocode}}\n```")
            .schema(serde_json::json!({"type":"array","items":{"type":"object","properties":{"id":{"type":"integer"},"name":{"type":"string"},"description":{"type":"string"}}}}))
            .vars(&["pseudocode"])
            .tags(&["protocol","commands"])
            .build(),

        TemplateBuilder::new("pr_encryption", "Identify Protocol Encryption", Category::ProtocolReversal)
            .desc("Identify encryption used in a network protocol")
            .system(RE_SYSTEM)
            .user("Identify protocol encryption from:\n```c\n{{pseudocode}}\n```\nKey material hints: {{key_hints}}")
            .schema(serde_json::json!({"type":"object","properties":{"algorithm":{"type":"string"},"key_exchange":{"type":"string"},"iv_handling":{"type":"string"},"confidence":{"type":"number"}}}))
            .vars(&["pseudocode","key_hints"])
            .tags(&["protocol","encryption","crypto"])
            .build(),

        // ── Crypto Identification ─────────────────────────────────────────────

        TemplateBuilder::new("ci_aes", "AES Identification", Category::CryptoIdentification)
            .desc("Identify AES implementation and parameters")
            .system(RE_SYSTEM)
            .user("Identify AES usage in:\n```c\n{{pseudocode}}\n```\nLook for S-box (0x63 first entry), key schedule, round count.")
            .schema(serde_json::json!({"type":"object","properties":{"is_aes":{"type":"boolean"},"key_size_bits":{"type":"integer"},"mode":{"type":"string"},"role":{"type":"string"},"confidence":{"type":"number"}}}))
            .vars(&["pseudocode"])
            .tags(&["aes","crypto","identify"])
            .build(),

        TemplateBuilder::new("ci_hash", "Hash Algorithm Identification", Category::CryptoIdentification)
            .desc("Identify hash algorithm from magic constants and structure")
            .system(RE_SYSTEM)
            .user("Identify the hash algorithm:\n```c\n{{pseudocode}}\n```\nConstants seen: {{constants}}")
            .schema(serde_json::json!({"type":"object","properties":{"algorithm":{"type":"string"},"variant":{"type":"string"},"confidence":{"type":"number"}}}))
            .vars(&["pseudocode","constants"])
            .tags(&["hash","crypto","identify"])
            .shot("constants: 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476", r#"{"algorithm":"MD5","variant":"standard","confidence":0.98}"#, "MD5 init constants")
            .shot("constants: 0x6a09e667, 0xbb67ae85", r#"{"algorithm":"SHA-256","variant":"standard","confidence":0.97}"#, "SHA-256 init")
            .build(),

        TemplateBuilder::new("ci_rsa", "RSA Identification", Category::CryptoIdentification)
            .desc("Identify RSA usage and key parameters")
            .system(RE_SYSTEM)
            .user("Identify RSA in:\n```c\n{{pseudocode}}\n```")
            .schema(serde_json::json!({"type":"object","properties":{"is_rsa":{"type":"boolean"},"operation":{"type":"string"},"key_size_hint":{"type":"integer"},"confidence":{"type":"number"}}}))
            .vars(&["pseudocode"])
            .tags(&["rsa","crypto","identify"])
            .build(),

        TemplateBuilder::new("ci_custom", "Custom Crypto Identification", Category::CryptoIdentification)
            .desc("Identify custom or non-standard cryptographic algorithms")
            .system(RE_SYSTEM)
            .user("Identify the custom crypto algorithm:\n```c\n{{pseudocode}}\n```\nDescribe structure, key usage, and any weaknesses.")
            .schema(serde_json::json!({"type":"object","properties":{"description":{"type":"string"},"weaknesses":{"type":"array"},"break_strategy":{"type":"string"}}}))
            .vars(&["pseudocode"])
            .tags(&["custom-crypto","crypto","weakness"])
            .build(),

        // ── Packer Analysis ───────────────────────────────────────────────────

        TemplateBuilder::new("pa_identify", "Identify Packer", Category::PackerAnalysis)
            .desc("Identify the packer/protector used")
            .system(RE_SYSTEM)
            .user("Identify packer:\nSection entropy: {{entropy}}\nEntry point bytes: {{ep_bytes}}\nStrings: {{strings}}")
            .schema(serde_json::json!({"type":"object","properties":{"packer":{"type":"string"},"version":{"type":"string"},"confidence":{"type":"number"}}}))
            .vars(&["entropy","ep_bytes","strings"])
            .tags(&["packer","identify"])
            .shot("entropy:.text=7.9 / ep_bytes:60 E8 00 00 00 00 58 83 E8 06", r#"{"packer":"UPX","version":"3.x","confidence":0.92}"#, "UPX signature")
            .build(),

        TemplateBuilder::new("pa_oep", "Find OEP", Category::PackerAnalysis)
            .desc("Identify the Original Entry Point after unpacking")
            .system(RE_SYSTEM)
            .user("Locate the OEP in this unpacking stub:\n```c\n{{pseudocode}}\n```\nLook for: tail jump, pushad/popad pair, call-then-jmp pattern.")
            .schema(serde_json::json!({"type":"object","properties":{"oep_address":{"type":"integer"},"method":{"type":"string"},"confidence":{"type":"number"}}}))
            .vars(&["pseudocode"])
            .tags(&["packer","oep","unpack"])
            .build(),

        // ── CTF Solving ───────────────────────────────────────────────────────

        TemplateBuilder::new("ctf_flag_check", "CTF Flag Checker", Category::CtfSolving)
            .desc("Reverse a CTF flag checking function")
            .system(RE_SYSTEM)
            .user("Reverse this flag checker:\n```c\n{{pseudocode}}\n```\nChallenge: {{description}}\n\nReturn the flag or a script to compute it.")
            .schema(serde_json::json!({"type":"object","properties":{"flag":{"type":"string"},"approach":{"type":"string"},"script":{"type":"string"},"confidence":{"type":"number"}}}))
            .vars(&["pseudocode","description"])
            .tags(&["ctf","flag","reverse"])
            .build(),

        TemplateBuilder::new("ctf_pwn", "CTF Pwn Exploit", Category::CtfSolving)
            .desc("Develop an exploit for a CTF pwn challenge")
            .system(RE_SYSTEM)
            .user("Pwn challenge: {{description}}\nVulnerability: {{vulnerability}}\nBinary info: {{binary_info}}\n\nDevelop an exploit strategy and pwntools script.")
            .schema(serde_json::json!({"type":"object","properties":{"strategy":{"type":"string"},"exploit_script":{"type":"string"},"mitigations_bypassed":{"type":"array"}}}))
            .vars(&["description","vulnerability","binary_info"])
            .tags(&["ctf","pwn","exploit"])
            .build(),

        TemplateBuilder::new("ctf_crypto", "CTF Crypto Challenge", Category::CtfSolving)
            .desc("Solve a CTF cryptography challenge")
            .system(RE_SYSTEM)
            .user("Crypto CTF: {{description}}\nAlgorithm code:\n```python\n{{code}}\n```\nCiphertext: {{ciphertext}}")
            .schema(serde_json::json!({"type":"object","properties":{"plaintext":{"type":"string"},"approach":{"type":"string"},"script":{"type":"string"}}}))
            .vars(&["description","code","ciphertext"])
            .tags(&["ctf","crypto","solve"])
            .build(),

        // ── Code Similarity ───────────────────────────────────────────────────

        TemplateBuilder::new("cs_match", "Code Similarity Match", Category::CodeSimilarity)
            .desc("Determine if two code snippets implement the same algorithm")
            .system(RE_SYSTEM)
            .user("Are these two functions equivalent?\n\nA:\n```c\n{{code_a}}\n```\n\nB:\n```c\n{{code_b}}\n```")
            .schema(serde_json::json!({"type":"object","properties":{"equivalent":{"type":"boolean"},"similarity_score":{"type":"number"},"differences":{"type":"string"}}}))
            .vars(&["code_a","code_b"])
            .tags(&["similarity","matching"])
            .build(),

        TemplateBuilder::new("cs_library", "Library Function Match", Category::CodeSimilarity)
            .desc("Identify if a function is from a known library")
            .system(RE_SYSTEM)
            .user("Is this function from a known library?\n```c\n{{pseudocode}}\n```\nCandidates: {{candidates}}")
            .schema(serde_json::json!({"type":"object","properties":{"library":{"type":"string"},"function":{"type":"string"},"version_hint":{"type":"string"},"confidence":{"type":"number"}}}))
            .vars(&["pseudocode","candidates"])
            .tags(&["library","similarity","match"])
            .build(),

        // ── String Analysis ───────────────────────────────────────────────────

        TemplateBuilder::new("sa_classify", "Classify Strings", Category::StringAnalysis)
            .desc("Classify strings found in a binary by category")
            .system(RE_SYSTEM)
            .user("Classify these strings:\n{{strings}}\n\nCategories: url/ip/domain/path/registry/mutex/error/debug/crypto_key/unknown.")
            .schema(serde_json::json!({"type":"array","items":{"type":"object","properties":{"string":{"type":"string"},"category":{"type":"string"},"notable":{"type":"boolean"}}}}))
            .vars(&["strings"])
            .tags(&["strings","classify"])
            .build(),

        TemplateBuilder::new("sa_decrypt", "Decrypt Obfuscated Strings", Category::StringAnalysis)
            .desc("Recover the decryption algorithm for obfuscated strings")
            .system(RE_SYSTEM)
            .user("Recover string decryption from:\n```c\n{{pseudocode}}\n```\nEncrypted blobs: {{blobs}}")
            .schema(serde_json::json!({"type":"object","properties":{"algorithm":{"type":"string"},"key":{"type":"string"},"decrypted_strings":{"type":"array"},"script":{"type":"string"}}}))
            .vars(&["pseudocode","blobs"])
            .tags(&["strings","decrypt","obfuscation"])
            .build(),

        // ── Type Recovery ─────────────────────────────────────────────────────

        TemplateBuilder::new("tr_struct", "Recover Struct Layout", Category::TypeRecovery)
            .desc("Recover struct layout from field access patterns")
            .system(RE_SYSTEM)
            .user("Recover struct layout from:\n```c\n{{pseudocode}}\n```")
            .schema(serde_json::json!({"type":"object","properties":{"struct_name":{"type":"string"},"fields":{"type":"array","items":{"type":"object","properties":{"offset":{"type":"integer"},"name":{"type":"string"},"type":{"type":"string"},"size":{"type":"integer"}}}}}}))
            .vars(&["pseudocode"])
            .tags(&["struct","type-recovery"])
            .build(),

        TemplateBuilder::new("tr_enum", "Recover Enum Values", Category::TypeRecovery)
            .desc("Recover enum constant values from switch/compare patterns")
            .system(RE_SYSTEM)
            .user("Recover enum from:\n```c\n{{pseudocode}}\n```")
            .schema(serde_json::json!({"type":"object","properties":{"enum_name":{"type":"string"},"values":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"value":{"type":"integer"}}}}}}))
            .vars(&["pseudocode"])
            .tags(&["enum","type-recovery"])
            .build(),

        // ── Obfuscation ───────────────────────────────────────────────────────

        TemplateBuilder::new("ob_detect", "Detect Obfuscation", Category::Obfuscation)
            .desc("Detect obfuscation techniques used in the binary")
            .system(RE_SYSTEM)
            .user("Detect obfuscation in:\n```c\n{{pseudocode}}\n```\nSection notes: {{section_notes}}")
            .schema(serde_json::json!({"type":"array","items":{"type":"object","properties":{"technique":{"type":"string"},"description":{"type":"string"},"deobfuscation_strategy":{"type":"string"}}}}))
            .vars(&["pseudocode","section_notes"])
            .tags(&["obfuscation","detect"])
            .build(),

        TemplateBuilder::new("ob_vmprotect", "VMProtect Analysis", Category::Obfuscation)
            .desc("Analyse VMProtect-protected code and suggest devirtualization approach")
            .system(RE_SYSTEM)
            .user("VMProtect handler at 0x{{address}}:\n```asm\n{{disasm}}\n```\n\nIdentify handler type and propose devirtualization approach.")
            .schema(serde_json::json!({"type":"object","properties":{"handler_type":{"type":"string"},"semantics":{"type":"string"},"devirt_approach":{"type":"string"}}}))
            .vars(&["address","disasm"])
            .tags(&["vmprotect","obfuscation","devirt"])
            .build(),

        // ── Behavior Analysis ──────────────────────────────────────────────────

        TemplateBuilder::new("ba_api_sequence", "API Sequence Analysis", Category::BehaviorAnalysis)
            .desc("Infer high-level behaviour from an API call sequence")
            .system(RE_SYSTEM)
            .user("Infer behaviour from this API sequence:\n{{api_sequence}}")
            .schema(serde_json::json!({"type":"object","properties":{"behavior":{"type":"string"},"category":{"type":"string"},"intent":{"type":"string"},"confidence":{"type":"number"}}}))
            .vars(&["api_sequence"])
            .tags(&["behavior","api"])
            .shot("VirtualAlloc → WriteProcessMemory → CreateRemoteThread", r#"{"behavior":"process injection","category":"malware","intent":"execute shellcode in remote process","confidence":0.92}"#, "classic injection")
            .build(),

        TemplateBuilder::new("ba_sandbox_evasion", "Sandbox Evasion Detection", Category::BehaviorAnalysis)
            .desc("Detect sandbox evasion techniques")
            .system(RE_SYSTEM)
            .user("Detect sandbox evasion in:\nAPIs: {{apis}}\nCode patterns: {{patterns}}")
            .schema(serde_json::json!({"type":"array","items":{"type":"object","properties":{"technique":{"type":"string"},"description":{"type":"string"},"bypass_strategy":{"type":"string"}}}}))
            .vars(&["apis","patterns"])
            .tags(&["sandbox","evasion","behavior"])
            .build(),

        TemplateBuilder::new("ba_lateral_movement", "Lateral Movement Analysis", Category::BehaviorAnalysis)
            .desc("Identify lateral movement techniques")
            .system(RE_SYSTEM)
            .user("Identify lateral movement in:\nAPIs: {{apis}}\nStrings: {{strings}}")
            .schema(serde_json::json!({"type":"array","items":{"type":"object","properties":{"technique":{"type":"string"},"target":{"type":"string"},"confidence":{"type":"number"}}}}))
            .vars(&["apis","strings"])
            .tags(&["lateral-movement","behavior"])
            .build(),
    ]
}

// ─────────────────────────────── unit tests ──────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn library_loads_builtins() {
        let lib = PromptLibrary::with_builtins();
        assert!(lib.count() >= 30);
    }

    #[test]
    fn get_template_by_id() {
        let lib = PromptLibrary::with_builtins();
        let t = lib.get("fa_rename").unwrap();
        assert_eq!(t.category, Category::FunctionAnalysis);
        assert!(!t.few_shots.is_empty());
    }

    #[test]
    fn render_substitutes_vars() {
        let lib = PromptLibrary::with_builtins();
        let v = vars(&[
            ("address", "0x1000"),
            ("current_name", "sub_1000"),
            ("disasm", "push rbp"),
        ]);
        let (_, user) = lib.render("fa_rename", &v).unwrap();
        assert!(user.contains("0x1000"));
        assert!(user.contains("sub_1000"));
    }

    #[test]
    fn render_missing_var_error() {
        let lib = PromptLibrary::with_builtins();
        let err = lib.render("fa_rename", &HashMap::new()).unwrap_err();
        assert!(matches!(err, LibraryError::MissingVar(_)));
    }

    #[test]
    fn unknown_template_error() {
        let lib = PromptLibrary::with_builtins();
        assert!(matches!(lib.get("nonexistent"), Err(LibraryError::NotFound(_))));
    }

    #[test]
    fn by_category_malware() {
        let lib = PromptLibrary::with_builtins();
        let mc = lib.by_category(&Category::MalwareClassification);
        assert!(!mc.is_empty());
        assert!(mc.iter().all(|t| t.category == Category::MalwareClassification));
    }

    #[test]
    fn few_shot_block_non_empty() {
        let lib = PromptLibrary::with_builtins();
        let t = lib.get("fa_rename").unwrap();
        let block = t.few_shot_block();
        assert!(block.contains("**Input**"));
    }

    #[test]
    fn all_ids_sorted() {
        let lib = PromptLibrary::with_builtins();
        let ids = lib.all_ids();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn category_display() {
        assert_eq!(Category::MalwareClassification.to_string(), "malware_classification");
    }

    #[test]
    fn render_with_few_shots_prepends_examples() {
        let lib = PromptLibrary::with_builtins();
        let v = vars(&[("address","0x1000"),("current_name","sub_1000"),("disasm","nop")]);
        let (_, user) = lib.render_with_few_shots("fa_rename", &v).unwrap();
        assert!(user.contains("### Examples"));
    }
}
