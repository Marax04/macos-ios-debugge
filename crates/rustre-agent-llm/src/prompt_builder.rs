// rustre-agent-llm/src/prompt_builder.rs
//
// RE-specific prompt construction:
//   - System prompt for the RE agent (rustre capabilities + RE domain knowledge)
//   - Function analysis prompt (disasm + pseudocode → rename/classify/describe)
//   - Malware analysis prompt
//   - CTF challenge prompt
//   - Vulnerability hunting prompt

use std::fmt::Write as FmtWrite;

use serde::{Deserialize, Serialize};

// ─────────────────────────────── PromptPart ──────────────────────────────────

/// A named section of a prompt, useful for composing complex system prompts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptSection {
    pub title: String,
    pub content: String,
    pub weight: u32, // higher weight = keep longer when trimming
}

impl PromptSection {
    pub fn new(title: impl Into<String>, content: impl Into<String>) -> Self {
        Self { title: title.into(), content: content.into(), weight: 10 }
    }

    #[must_use] 
    pub const fn with_weight(mut self, w: u32) -> Self { self.weight = w; self }

    #[must_use] 
    pub fn render(&self) -> String {
        format!("## {}\n{}\n", self.title, self.content)
    }
}

// ─────────────────────────────── BuiltinSections ────────────────────────────

pub struct BuiltinSections;

impl BuiltinSections {
    /// Core RE agent identity and mission.
    #[must_use] 
    pub fn agent_identity() -> PromptSection {
        PromptSection::new(
            "Identity",
            "You are RustRE-Agent, an expert reverse engineering assistant. \
You specialise in binary analysis, malware research, vulnerability research, \
and CTF challenges. You are systematic, precise, and cite evidence from the binary \
when making claims.",
        ).with_weight(100)
    }

    /// Description of rustre API tools available to the agent.
    #[must_use] 
    pub fn rustre_capabilities() -> PromptSection {
        PromptSection::new(
            "Available Tools (rustre API)",
            r"You have access to the following tools via function calls:

**Binary View**
- `binary_view.open(path)` — load a binary for analysis
- `binary_view.analyze()` — run auto-analysis on the loaded binary
- `binary_view.info()` — get metadata (arch, platform, entry point, size)

**Function Table**
- `function_table.list()` — enumerate all functions
- `function_table.get(address)` — get function details
- `function_table.rename(address, new_name)` — rename a function
- `function_table.set_type(address, prototype)` — set function prototype

**Disassembler / Decompiler**
- `disassemble_function(address)` — get disassembly listing
- `decompile_function(address)` — get decompiled pseudocode

**Cross References**
- `xref_engine.query_forward(address)` — get calls/jumps FROM this address
- `xref_engine.query_backward(address)` — get callers TO this address

**Symbol & String Search**
- `symbol_table.lookup(name)` — find symbol by name
- `search_strings(pattern)` — search strings in the binary

**Patch Set**
- `patch_set.apply(address, bytes_hex)` — patch bytes
- `patch_set.undo()` — revert last patch

**Memory**
- `memory_provider.read(address, size)` — read raw bytes

**Type System**
- `type_system.define_struct(name, fields)` — define a struct
- `type_system.resolve(name)` — look up a type definition

Always prefer using tools over making assumptions. Verify hypotheses with evidence.",
        ).with_weight(90)
    }

    /// RE domain knowledge: architectures, calling conventions, common patterns.
    #[must_use] 
    pub fn re_domain_knowledge() -> PromptSection {
        PromptSection::new(
            "RE Domain Knowledge",
            r"Key RE concepts to apply:

**Architectures**: x86-32/64 (cdecl, stdcall, fastcall, x64 Microsoft ABI), ARM32 (AAPCS), ARM64 (AAPCS64), MIPS, RISC-V.

**Common patterns**:
- Prologue: `push rbp; mov rbp, rsp` (x86-64) or `stp x29, x30, [sp, -N]!` (ARM64)
- PIC/GOT: `call __x86.get_pc_thunk.*` followed by GOT-relative offsets
- String obfuscation: XOR loops, stack-built strings, RC4/custom streams
- Anti-debug: `IsDebuggerPresent`, `NtQueryInformationProcess`, RDTSC delta checks
- Packer stubs: single-section PE with high entropy, self-modifying code, VirtualAlloc+WriteProcessMemory+CreateThread chains
- Crypto: S-box tables (AES), key schedule loops (DES), modular exponentiation (RSA)

**Naming conventions**: use snake_case for functions/variables, CamelCase for struct types. Prefix unknown functions `sub_ADDR` → rename to `verb_noun` (e.g., `decrypt_config`).

**Confidence levels**: always state your confidence (high/medium/low) and cite the address/instruction that supports each claim.",
        ).with_weight(80)
    }

    /// Output format instructions.
    #[must_use] 
    pub fn output_format() -> PromptSection {
        PromptSection::new(
            "Output Format",
            r#"Structure all analysis reports as JSON with these top-level keys:
{
  "summary": "one-paragraph executive summary",
  "findings": [{ "kind": "...", "title": "...", "description": "...", "address": 0, "confidence": 0.9 }],
  "renamed_functions": [{ "address": 0, "old_name": "...", "new_name": "..." }],
  "iocs": ["..."],
  "recommended_next_steps": ["..."]
}
For conversational answers, use clear markdown with code blocks for assembly/pseudocode."#,
        ).with_weight(70)
    }
}

// ─────────────────────────────── SystemPromptBuilder ─────────────────────────

/// Builder for composing multi-section system prompts.
#[derive(Default)]
pub struct SystemPromptBuilder {
    sections: Vec<PromptSection>,
    max_tokens: usize,
}

impl SystemPromptBuilder {
    #[must_use] 
    pub const fn new() -> Self { Self { sections: Vec::new(), max_tokens: 8000 } }

    #[must_use] 
    pub const fn max_tokens(mut self, n: usize) -> Self { self.max_tokens = n; self }

    /// Add a section (also available via `+` operator).
    #[must_use]
    pub fn push_section(mut self, section: PromptSection) -> Self {
        self.sections.push(section);
        self
    }


    /// Standard RE agent system prompt.
    #[must_use] 
    pub fn re_agent() -> Self {
        Self::new()
            .push_section(BuiltinSections::agent_identity())
            .push_section(BuiltinSections::rustre_capabilities())
            .push_section(BuiltinSections::re_domain_knowledge())
            .push_section(BuiltinSections::output_format())
    }

    #[must_use] 
    pub fn build(mut self) -> String {
        // Sort by descending weight so highest-priority sections come first.
        self.sections.sort_by(|a, b| b.weight.cmp(&a.weight));

        let mut out = String::new();
        let mut token_budget = self.max_tokens;

        for section in &self.sections {
            let rendered = section.render();
            let tok = rendered.len() / 4; // rough estimate
            if tok > token_budget {
                break;
            }
            token_budget -= tok;
            out.push_str(&rendered);
            out.push('\n');
        }
        out
    }
}

impl std::ops::Add<PromptSection> for SystemPromptBuilder {
    type Output = Self;
    fn add(self, section: PromptSection) -> Self {
        self.push_section(section)
    }
}

// ─────────────────────────────── UserPromptBuilder ───────────────────────────

/// Fluent builder for user-facing analysis prompts.
#[derive(Default)]
pub struct UserPromptBuilder {
    sections: Vec<(String, String)>, // (header, body)
}

impl UserPromptBuilder {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    #[must_use]
    pub fn section(mut self, header: impl Into<String>, body: impl Into<String>) -> Self {
        self.sections.push((header.into(), body.into()));
        self
    }

    #[must_use] 
    pub fn build(self) -> String {
        self.sections
            .into_iter()
            .map(|(h, b)| format!("### {h}\n{b}\n"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ─────────────────────────────── Prompt templates ────────────────────────────

/// All built-in RE prompt templates.
pub struct PromptTemplates;

impl PromptTemplates {
    // ── Function analysis ────────────────────────────────────────────────────

    #[must_use]
    pub fn analyze_function(
        address: u64,
        name: &str,
        disasm: &str,
        pseudocode: Option<&str>,
        callers: &[u64],
        call_targets: &[u64],
    ) -> String {
        let mut b = UserPromptBuilder::new()
            .section("Task", format!(
                "Analyse the function at address `0x{address:016x}` (currently named `{name}`). \
Provide: (1) a descriptive name, (2) inferred purpose, (3) key algorithms or data structures, \
(4) security-relevant behaviour, (5) suggested parameter names and types."
            ))
            .section("Disassembly", format!("```asm\n{disasm}\n```"))
            ;

        if let Some(pc) = pseudocode {
            b = b.section("Pseudocode", format!("```c\n{pc}\n```"));
        }

        if !callers.is_empty() {
            let caller_list: Vec<String> = callers.iter().map(|a| format!("0x{a:016x}")).collect();
            b = b.section("Callers", caller_list.join(", "));
        }

        if !call_targets.is_empty() {
            let callee_list: Vec<String> = call_targets.iter().map(|a| format!("0x{a:016x}")).collect();
            b = b.section("Callees", callee_list.join(", "));
        }

        b.section(
            "Output",
            "Return JSON: { \"new_name\": \"...\", \"description\": \"...\", \
\"parameters\": [{\"name\": \"...\", \"type\": \"...\"}], \
\"confidence\": 0.0-1.0, \"notes\": \"...\" }",
        ).build()
    }

    // ── Malware analysis ─────────────────────────────────────────────────────

    #[must_use] 
    pub fn analyze_malware(
        binary_info: &BinaryInfo,
        strings: &[String],
        imports: &[String],
        suspicious_functions: &[(u64, String)],
    ) -> String {
        let strings_block = if strings.is_empty() {
            "(none found)".to_owned()
        } else {
            strings.iter().take(100).map(|s| format!("  - {s:?}")).collect::<Vec<_>>().join("\n")
        };

        let imports_block = if imports.is_empty() {
            "(none)".to_owned()
        } else {
            imports.iter().take(50).map(|i| format!("  - {i}")).collect::<Vec<_>>().join("\n")
        };

        let suspicious_block = suspicious_functions
            .iter()
            .take(20)
            .map(|(addr, name)| format!("  - 0x{addr:016x}: {name}"))
            .collect::<Vec<_>>()
            .join("\n");

        UserPromptBuilder::new()
            .section("Task", "Perform malware triage on the following binary. \
Classify the malware family, identify key capabilities, extract IoCs, \
describe network behaviour, and list persistence mechanisms.")
            .section("Binary Metadata", binary_info.render())
            .section("Imported APIs", imports_block)
            .section("Strings (sample)", strings_block)
            .section("Suspicious Functions", if suspicious_block.is_empty() { "(none identified yet)".to_owned() } else { suspicious_block })
            .section("Output", "Return JSON with keys: family, capabilities (list), iocs (list), \
network_indicators (list), persistence (list), confidence, next_steps (list).")
            .build()
    }

    // ── Vulnerability hunting ────────────────────────────────────────────────

    #[must_use] 
    pub fn hunt_vulnerability(
        address: u64,
        function_name: &str,
        pseudocode: &str,
        vuln_hints: &[&str],
    ) -> String {
        let hints = if vuln_hints.is_empty() {
            "No specific hints provided — check for all common classes.".to_owned()
        } else {
            vuln_hints.iter().map(|h| format!("  - {h}")).collect::<Vec<_>>().join("\n")
        };

        UserPromptBuilder::new()
            .section("Task", format!(
                "Audit function `{function_name}` at `0x{address:016x}` for vulnerabilities. \
Check for: buffer overflows, integer overflows/underflows, use-after-free, \
format string bugs, off-by-one, TOCTOU, command injection, path traversal."
            ))
            .section("Pseudocode", format!("```c\n{pseudocode}\n```"))
            .section("Hints / Suspected Classes", hints)
            .section("Output", "Return JSON: { \"vulnerabilities\": [{ \"class\": \"...\", \
\"description\": \"...\", \"address\": 0, \"exploitability\": \"high|medium|low\", \
\"poc_sketch\": \"...\" }], \"overall_risk\": \"high|medium|low|none\" }")
            .build()
    }

    // ── CTF challenge ────────────────────────────────────────────────────────

    #[must_use] 
    pub fn solve_ctf(
        challenge_name: &str,
        binary_info: &BinaryInfo,
        description: &str,
        target_function: Option<(u64, &str)>,
        pseudocode: Option<&str>,
    ) -> String {
        let mut b = UserPromptBuilder::new()
            .section("Task", format!(
                "Solve the CTF challenge `{challenge_name}`. \
Identify the flag validation logic, reverse the algorithm, and provide the flag or a script to derive it."
            ))
            .section("Challenge Description", description)
            .section("Binary Metadata", binary_info.render());

        if let Some((addr, name)) = target_function {
            b = b.section("Target Function", format!("`{name}` @ `0x{addr:016x}`"));
        }

        if let Some(pc) = pseudocode {
            b = b.section("Pseudocode", format!("```c\n{pc}\n```"));
        }

        b.section("Output", "Return JSON: { \"approach\": \"...\", \"algorithm\": \"...\", \
\"flag\": \"CTF{...}\" or null, \"solve_script\": \"python code or null\", \"confidence\": 0.0-1.0 }")
            .build()
    }

    // ── Protocol reversal ────────────────────────────────────────────────────

    #[must_use] 
    pub fn reverse_protocol(
        binary_info: &BinaryInfo,
        network_strings: &[String],
        packet_structures: &[PacketHint],
    ) -> String {
        let nets = network_strings.iter().take(50)
            .map(|s| format!("  - {s:?}")).collect::<Vec<_>>().join("\n");

        let packets = packet_structures.iter()
            .map(|p| format!("  - {} (offset {}, len {}): {:?}", p.field_name, p.offset, p.size, p.notes))
            .collect::<Vec<_>>().join("\n");

        UserPromptBuilder::new()
            .section("Task", "Reverse-engineer the binary's network protocol. \
Identify: message format (header, TLV, fixed-length), framing, encryption/obfuscation, \
authentication scheme, command IDs and their semantics, error handling.")
            .section("Binary Metadata", binary_info.render())
            .section("Network-related Strings", if nets.is_empty() { "(none found)".to_owned() } else { nets })
            .section("Observed Packet Field Hints", if packets.is_empty() { "(none)".to_owned() } else { packets })
            .section("Output", "Return JSON: { \"protocol_name\": \"...\", \
\"transport\": \"TCP|UDP|...\", \"framing\": \"...\", \
\"message_format\": [{\"field\": \"...\", \"type\": \"...\", \"offset\": 0, \"size\": 0}], \
\"commands\": [{\"id\": 0, \"name\": \"...\", \"description\": \"...\"}], \
\"encryption\": \"...\", \"confidence\": 0.0-1.0 }")
            .build()
    }

    // ── Crypto identification ────────────────────────────────────────────────

    #[must_use] 
    pub fn identify_crypto(address: u64, function_name: &str, pseudocode: &str, byte_patterns: &[String]) -> String {
        let patterns = byte_patterns.iter()
            .map(|p| format!("  - {p}")).collect::<Vec<_>>().join("\n");

        UserPromptBuilder::new()
            .section("Task", format!(
                "Identify the cryptographic algorithm used in function `{function_name}` @ `0x{address:016x}`. \
Check for: AES (S-boxes, MixColumns), DES/3DES, RSA (modular exponentiation), \
ChaCha20/Salsa20 (quarter-round), MD5/SHA (magic constants), RC4 (KSA/PRGA), \
and custom/obfuscated algorithms."
            ))
            .section("Pseudocode", format!("```c\n{pseudocode}\n```"))
            .section("Observed Byte Patterns / Constants", if patterns.is_empty() { "(none detected)".to_owned() } else { patterns })
            .section("Output", "Return JSON: { \"algorithm\": \"AES|RSA|...|custom\", \
\"variant\": \"AES-128-CBC|...\", \"role\": \"encrypt|decrypt|hash|kdf\", \
\"key_material_address\": 0, \"confidence\": 0.0-1.0, \"evidence\": \"...\" }")
            .build()
    }

    // ── Rename variables ─────────────────────────────────────────────────────

    #[must_use] 
    pub fn rename_variables(address: u64, function_name: &str, pseudocode: &str) -> String {
        UserPromptBuilder::new()
            .section("Task", format!(
                "Rename the variables and parameters in function `{function_name}` @ `0x{address:016x}` \
to meaningful names based on their usage patterns."
            ))
            .section("Pseudocode (before renaming)", format!("```c\n{pseudocode}\n```"))
            .section("Output", "Return JSON: { \"renames\": [{\"original\": \"var_10\", \
\"suggested\": \"key_buffer\", \"reason\": \"...\"}], \
\"rewritten_pseudocode\": \"```c\\n...\\n```\" }")
            .build()
    }

    // ── Packer analysis ──────────────────────────────────────────────────────

    #[must_use] 
    pub fn analyze_packer(
        binary_info: &BinaryInfo,
        entropy_sections: &[(String, f64)],
        stub_pseudocode: Option<&str>,
    ) -> String {
        let entropy_block = entropy_sections
            .iter()
            .map(|(name, e)| format!("  - {name}: {e:.2}"))
            .collect::<Vec<_>>().join("\n");

        let mut b = UserPromptBuilder::new()
            .section("Task", "Identify the packer or protector used in this binary. \
Check for: UPX, MPRESS, Themida, VMProtect, Enigma, custom packers. \
Describe the unpacking stub, OEP recovery, and any anti-analysis tricks.")
            .section("Binary Metadata", binary_info.render())
            .section("Section Entropy", if entropy_block.is_empty() { "(not computed)".to_owned() } else { entropy_block });

        if let Some(pc) = stub_pseudocode {
            b = b.section("Unpacking Stub (decompiled)", format!("```c\n{pc}\n```"));
        }

        b.section("Output", "Return JSON: { \"packer\": \"upx|themida|...|unknown\", \
\"version\": \"...\", \"oep_address\": 0, \"unpacking_method\": \"...\", \
\"anti_analysis\": [\"...\"], \"confidence\": 0.0-1.0 }")
            .build()
    }
}

// ─────────────────────────────── Helper types ────────────────────────────────

/// Binary metadata for inclusion in prompts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BinaryInfo {
    pub path: String,
    pub arch: String,
    pub platform: String,
    pub file_type: String,
    pub entry_point: u64,
    pub base_address: u64,
    pub size_bytes: u64,
    pub sections: Vec<SectionInfo>,
    pub compiler: Option<String>,
    pub timestamp: Option<String>,
    pub sha256: Option<String>,
}

impl BinaryInfo {
    #[must_use] 
    pub fn render(&self) -> String {
        let mut out = format!(
            "Path: {}\nArch: {} | Platform: {} | Type: {}\n\
Entry: 0x{:016x} | Base: 0x{:016x} | Size: {} bytes",
            self.path, self.arch, self.platform, self.file_type,
            self.entry_point, self.base_address, self.size_bytes
        );
        if let Some(c) = &self.compiler { let _ = write!(out, "\nCompiler: {c}"); }
        if let Some(ts) = &self.timestamp { let _ = write!(out, "\nTimestamp: {ts}"); }
        if let Some(h) = &self.sha256 { let _ = write!(out, "\nSHA256: {h}"); }
        if !self.sections.is_empty() {
            out.push_str("\nSections:");
            for s in &self.sections {
                let _ = write!(out, "\n  {} vaddr=0x{:x} size={} entropy={:.2}",
                    s.name, s.virtual_address, s.size, s.entropy);
            }
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub size: u64,
    pub entropy: f64,
    pub permissions: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketHint {
    pub field_name: String,
    pub offset: u32,
    pub size: u32,
    pub notes: String,
}

// ─────────────────────────────── unit tests ──────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_prompt_re_agent_non_empty() {
        let prompt = SystemPromptBuilder::re_agent().build();
        assert!(prompt.contains("RustRE-Agent"));
        assert!(prompt.contains("binary_view.open"));
        assert!(prompt.contains("Architectures"));
    }

    #[test]
    fn system_prompt_respects_max_tokens() {
        // Very small budget — should truncate
        let prompt = SystemPromptBuilder::re_agent().max_tokens(50).build();
        // Should have at most ~200 chars for 50 tokens
        assert!(prompt.len() < 500);
    }

    #[test]
    fn analyze_function_prompt_contains_key_fields() {
        let p = PromptTemplates::analyze_function(
            0xDEAD_BEEF,
            "sub_DEADBEEF",
            "push rbp\nmov rbp, rsp",
            Some("void* fn(int a){}"),
            &[0x1000],
            &[0x2000],
        );
        assert!(p.contains("0x00000000deadbeef"));
        assert!(p.contains("sub_DEADBEEF"));
        assert!(p.contains("push rbp"));
        assert!(p.contains("void* fn"));
        assert!(p.contains("0x0000000000001000"));
    }

    #[test]
    fn analyze_malware_prompt_contains_metadata() {
        let info = BinaryInfo {
            path: "evil.exe".to_owned(),
            arch: "x86-64".to_owned(),
            platform: "Windows".to_owned(),
            file_type: "PE".to_owned(),
            ..Default::default()
        };
        let p = PromptTemplates::analyze_malware(
            &info,
            &["http://malicious.com".to_owned()],
            &["CreateRemoteThread".to_owned()],
            &[(0x1234, "decrypt_payload".to_owned())],
        );
        assert!(p.contains("evil.exe"));
        assert!(p.contains("malicious.com"));
        assert!(p.contains("CreateRemoteThread"));
    }

    #[test]
    fn hunt_vulnerability_prompt() {
        let p = PromptTemplates::hunt_vulnerability(
            0x4000,
            "handle_request",
            "strcpy(buf, input);",
            &["buffer overflow"],
        );
        assert!(p.contains("handle_request"));
        assert!(p.contains("strcpy"));
        assert!(p.contains("buffer overflow"));
    }

    #[test]
    fn ctf_prompt() {
        let info = BinaryInfo { path: "flag.elf".to_owned(), ..Default::default() };
        let p = PromptTemplates::solve_ctf(
            "rev100",
            &info,
            "Reverse the flag checker",
            Some((0x5000, "check_flag")),
            Some("if (input == expected) win();"),
        );
        assert!(p.contains("rev100"));
        assert!(p.contains("check_flag"));
    }

    #[test]
    fn identify_crypto_prompt() {
        let p = PromptTemplates::identify_crypto(
            0x6000,
            "enc_fn",
            "state ^= key;",
            &["63 7c 77 7b".to_owned()], // AES S-box start
        );
        assert!(p.contains("enc_fn"));
        assert!(p.contains("63 7c 77 7b"));
    }

    #[test]
    fn binary_info_render_no_panic() {
        let info = BinaryInfo {
            path: "test.bin".to_owned(),
            arch: "ARM64".to_owned(),
            sections: vec![SectionInfo {
                name: ".text".to_owned(),
                virtual_address: 0x1000,
                size: 4096,
                entropy: 7.2,
                permissions: "r-x".to_owned(),
            }],
            sha256: Some("abc123".to_owned()),
            ..Default::default()
        };
        let r = info.render();
        assert!(r.contains(".text"));
        assert!(r.contains("7.20"));
        assert!(r.contains("abc123"));
    }

    #[test]
    fn prompt_section_render() {
        let s = PromptSection::new("Foo", "Bar content");
        let r = s.render();
        assert!(r.starts_with("## Foo"));
        assert!(r.contains("Bar content"));
    }

    #[test]
    fn user_prompt_builder_multi_section() {
        let p = UserPromptBuilder::new()
            .section("A", "aaa")
            .section("B", "bbb")
            .build();
        assert!(p.contains("### A"));
        assert!(p.contains("### B"));
        assert!(p.contains("aaa"));
        assert!(p.contains("bbb"));
    }
}
