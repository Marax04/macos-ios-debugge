//! Domain-specific prompt builder for reverse-engineering analysis tasks.
//!
//! Constructs structured, context-rich prompts for each `AnalysisTask` variant
//! with binary context injection, hex-dump formatting, and disassembly snippets.

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;

// ─── AnalysisTask ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AnalysisTask {
    DecompilationReview,
    MalwareClassification,
    VulnerabilityHunting,
    CryptoIdentification,
    ProtocolReverse,
    ObfuscationAnalysis,
    BehaviorSummary,
    ExploitDevelopment,
    PatchAnalysis,
    FirmwareAnalysis,
}

impl AnalysisTask {
    pub fn title(&self) -> &'static str {
        match self {
            Self::DecompilationReview => "Decompilation Review",
            Self::MalwareClassification => "Malware Classification",
            Self::VulnerabilityHunting => "Vulnerability Hunting",
            Self::CryptoIdentification => "Cryptographic Primitive Identification",
            Self::ProtocolReverse => "Protocol Reverse Engineering",
            Self::ObfuscationAnalysis => "Obfuscation Analysis",
            Self::BehaviorSummary => "Behavioral Summary",
            Self::ExploitDevelopment => "Exploit Development Assistance",
            Self::PatchAnalysis => "Patch Differencing Analysis",
            Self::FirmwareAnalysis => "Firmware Analysis",
        }
    }

    pub fn system_instruction(&self) -> &'static str {
        match self {
            Self::DecompilationReview => {
                "You are an expert reverse engineer reviewing decompiled pseudocode. \
                 Identify logical errors, recover types, rename variables, and produce \
                 clean, idiomatic C/C++ equivalent code."
            }
            Self::MalwareClassification => {
                "You are a malware analyst. Classify the provided binary artefacts into \
                 malware families. Identify capabilities: persistence, C2, lateral movement, \
                 exfiltration, evasion. Provide confidence percentages."
            }
            Self::VulnerabilityHunting => {
                "You are a vulnerability researcher. Audit the provided code for memory \
                 corruption, integer overflow, use-after-free, format string, injection, \
                 and logic bugs. Rate each finding by CVSS v3 severity."
            }
            Self::CryptoIdentification => {
                "You are a cryptanalyst. Identify cryptographic algorithms, key schedules, \
                 S-boxes, and weaknesses in the provided code. Note non-standard or \
                 custom crypto implementations."
            }
            Self::ProtocolReverse => {
                "You are a network protocol analyst. Reverse engineer the binary protocol \
                 from captured traffic or parser code. Define field types, lengths, \
                 command codes, and state machine transitions."
            }
            Self::ObfuscationAnalysis => {
                "You are a deobfuscation expert. Identify obfuscation techniques \
                 (control-flow flattening, opaque predicates, string encryption, VM-based \
                 protection) and describe the deobfuscation strategy."
            }
            Self::BehaviorSummary => {
                "You are a binary analyst. Summarise the observable behavior of the \
                 provided function or binary: file I/O, registry, network, process \
                 creation, cryptography, and UI interactions."
            }
            Self::ExploitDevelopment => {
                "You are an offensive security researcher assisting with controlled \
                 exploit development in an authorised lab environment. Analyse the \
                 provided vulnerability and suggest exploitation primitives."
            }
            Self::PatchAnalysis => {
                "You are a patch analyst. Compare the before and after versions of the \
                 provided binary or source. Identify the vulnerability that was fixed, \
                 determine if a patch bypass is possible, and assess completeness."
            }
            Self::FirmwareAnalysis => {
                "You are a firmware security analyst. Analyse the extracted firmware \
                 for hardcoded credentials, insecure boot chains, unauthenticated update \
                 mechanisms, and RTOS-specific attack surfaces."
            }
        }
    }

    pub fn output_format(&self) -> &'static str {
        match self {
            Self::DecompilationReview => {
                "Provide cleaned pseudocode in a fenced ```c block, followed by a bullet \
                 list of issues found and renaming rationale."
            }
            Self::MalwareClassification => {
                "Respond with JSON: {\"family\": \"...\", \"confidence\": 0-100, \
                 \"capabilities\": [...], \"indicators\": [...]}."
            }
            Self::VulnerabilityHunting => {
                "List each finding as: [SEVERITY] Title — Description — Location — \
                 Recommendation."
            }
            Self::CryptoIdentification => {
                "List each primitive as: Algorithm | Key size | Mode | Weakness | Line ref."
            }
            Self::ProtocolReverse => {
                "Define the protocol as a Kaitai Struct YAML schema, then describe each \
                 message type in a table."
            }
            Self::ObfuscationAnalysis => {
                "Enumerate each technique with: Name | Evidence | Deobfuscation Strategy | \
                 Estimated effort."
            }
            Self::BehaviorSummary => {
                "Provide a structured markdown report with sections: Overview, File I/O, \
                 Network, Registry, Process, Crypto, Anomalies."
            }
            Self::ExploitDevelopment => {
                "Describe: root cause, affected offset/register, exploit primitive, \
                 suggested payload structure, and mitigations to bypass."
            }
            Self::PatchAnalysis => {
                "Provide: Changed functions, vulnerability description, patch adequacy \
                 (complete/partial/bypassed), CVE if known."
            }
            Self::FirmwareAnalysis => {
                "Provide: Firmware version, architecture, OS, hardcoded secrets, \
                 insecure functions, attack surface summary."
            }
        }
    }
}

// ─── PromptSection ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PromptSection {
    SystemInstructions,
    Context,
    Task,
    Examples,
    OutputFormat,
    Constraints,
}

// ─── TaskContext ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct TaskContext {
    pub binary_type: String,
    pub arch: String,
    pub os: String,
    pub function_count: u32,
    pub string_samples: Vec<String>,
    pub import_samples: Vec<String>,
    /// (start_addr, end_addr, entropy_value)
    pub entropy_regions: Vec<(u64, u64, f64)>,
    pub hex_bytes: Vec<u8>,
    pub disasm_lines: Vec<(u64, String, String)>, // (addr, bytes, mnemonic)
    pub additional_context: HashMap<String, String>,
}

impl TaskContext {
    pub fn new(arch: impl Into<String>, os: impl Into<String>) -> Self {
        Self {
            arch: arch.into(),
            os: os.into(),
            ..Default::default()
        }
    }

    pub fn binary_type(mut self, bt: impl Into<String>) -> Self {
        self.binary_type = bt.into();
        self
    }

    pub fn with_strings(mut self, strings: Vec<String>) -> Self {
        self.string_samples = strings;
        self
    }

    pub fn with_imports(mut self, imports: Vec<String>) -> Self {
        self.import_samples = imports;
        self
    }
}

// ─── PromptQuality ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PromptQuality {
    pub estimated_tokens: u32,
    pub relevance_score: f64,
    pub completeness_score: f64,
}

impl PromptQuality {
    fn compute(prompt: &str, context: &TaskContext, task: &AnalysisTask) -> Self {
        let estimated_tokens = (prompt.len() as f64 / 3.8).ceil() as u32;

        let relevance = {
            let mut score = 0.5f64;
            if !context.arch.is_empty() {
                score += 0.1;
            }
            if !context.import_samples.is_empty() {
                score += 0.1;
            }
            if !context.string_samples.is_empty() {
                score += 0.1;
            }
            if !context.hex_bytes.is_empty() {
                score += 0.1;
            }
            if !context.entropy_regions.is_empty() {
                score += 0.1;
            }
            score.min(1.0)
        };

        let completeness = {
            let required = match task {
                AnalysisTask::DecompilationReview => 3u32,
                AnalysisTask::MalwareClassification => 4,
                AnalysisTask::VulnerabilityHunting => 3,
                _ => 2,
            };
            let mut present = 1u32; // system instructions always present
            if !context.arch.is_empty() {
                present += 1;
            }
            if !context.import_samples.is_empty() {
                present += 1;
            }
            if !context.string_samples.is_empty() {
                present += 1;
            }
            (present as f64 / required as f64).min(1.0)
        };

        Self { estimated_tokens, relevance_score: relevance, completeness_score: completeness }
    }
}

// ─── AnalysisPromptBuilder ────────────────────────────────────────────────────

pub struct AnalysisPromptBuilder {
    include_hex_dump: bool,
    include_disasm: bool,
    max_string_samples: usize,
    max_import_samples: usize,
    max_hex_bytes: usize,
    section_order: Vec<PromptSection>,
}

impl Default for AnalysisPromptBuilder {
    fn default() -> Self {
        Self {
            include_hex_dump: true,
            include_disasm: true,
            max_string_samples: 20,
            max_import_samples: 30,
            max_hex_bytes: 256,
            section_order: vec![
                PromptSection::SystemInstructions,
                PromptSection::Context,
                PromptSection::Task,
                PromptSection::Examples,
                PromptSection::OutputFormat,
                PromptSection::Constraints,
            ],
        }
    }
}

impl AnalysisPromptBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn without_hex_dump(mut self) -> Self {
        self.include_hex_dump = false;
        self
    }

    pub fn without_disasm(mut self) -> Self {
        self.include_disasm = false;
        self
    }

    pub fn max_strings(mut self, n: usize) -> Self {
        self.max_string_samples = n;
        self
    }

    /// Build a complete prompt for the given task and context.
    /// Returns the prompt text and quality metrics.
    pub fn build_prompt(
        &self,
        task: &AnalysisTask,
        context: &TaskContext,
    ) -> (String, PromptQuality) {
        let mut prompt = String::new();

        for section in &self.section_order {
            match section {
                PromptSection::SystemInstructions => {
                    self.append_system(&mut prompt, task);
                }
                PromptSection::Context => {
                    self.append_context(&mut prompt, context);
                }
                PromptSection::Task => {
                    self.append_task(&mut prompt, task, context);
                }
                PromptSection::Examples => {
                    self.append_examples(&mut prompt, task);
                }
                PromptSection::OutputFormat => {
                    self.append_output_format(&mut prompt, task);
                }
                PromptSection::Constraints => {
                    self.append_constraints(&mut prompt, task);
                }
            }
        }

        let quality = PromptQuality::compute(&prompt, context, task);
        (prompt, quality)
    }

    fn append_system(&self, out: &mut String, task: &AnalysisTask) {
        let _ = writeln!(out, "## SYSTEM");
        let _ = writeln!(out, "{}", task.system_instruction());
        let _ = writeln!(out);
    }

    fn append_context(&self, out: &mut String, ctx: &TaskContext) {
        let _ = writeln!(out, "## BINARY CONTEXT");
        if !ctx.binary_type.is_empty() {
            let _ = writeln!(out, "- **Type**: {}", ctx.binary_type);
        }
        if !ctx.arch.is_empty() {
            let _ = writeln!(out, "- **Architecture**: {}", ctx.arch);
        }
        if !ctx.os.is_empty() {
            let _ = writeln!(out, "- **OS**: {}", ctx.os);
        }
        if ctx.function_count > 0 {
            let _ = writeln!(out, "- **Functions**: {}", ctx.function_count);
        }

        if !ctx.import_samples.is_empty() {
            let _ = writeln!(out, "\n### Imported Symbols (sample)");
            for imp in ctx.import_samples.iter().take(self.max_import_samples) {
                let _ = writeln!(out, "  - `{imp}`");
            }
        }

        if !ctx.string_samples.is_empty() {
            let _ = writeln!(out, "\n### String Constants (sample)");
            for s in ctx.string_samples.iter().take(self.max_string_samples) {
                let escaped = s.replace('`', "'");
                let _ = writeln!(out, "  - `{escaped}`");
            }
        }

        if !ctx.entropy_regions.is_empty() {
            let _ = writeln!(out, "\n### High-Entropy Regions");
            for (start, end, ent) in &ctx.entropy_regions {
                let _ = writeln!(out, "  - `0x{start:08x}` – `0x{end:08x}`: entropy = {ent:.3}");
            }
        }

        if self.include_hex_dump && !ctx.hex_bytes.is_empty() {
            let _ = writeln!(out, "\n### Hex Dump");
            let _ = writeln!(out, "```");
            out.push_str(&format_hex_dump(
                &ctx.hex_bytes[..ctx.hex_bytes.len().min(self.max_hex_bytes)],
                0x0000,
            ));
            let _ = writeln!(out, "```");
        }

        if self.include_disasm && !ctx.disasm_lines.is_empty() {
            let _ = writeln!(out, "\n### Disassembly");
            let _ = writeln!(out, "```asm");
            out.push_str(&format_disasm_snippet(&ctx.disasm_lines));
            let _ = writeln!(out, "```");
        }

        // Additional freeform context
        if !ctx.additional_context.is_empty() {
            let _ = writeln!(out, "\n### Additional Context");
            for (k, v) in &ctx.additional_context {
                let _ = writeln!(out, "- **{k}**: {v}");
            }
        }

        let _ = writeln!(out);
    }

    fn append_task(&self, out: &mut String, task: &AnalysisTask, ctx: &TaskContext) {
        let _ = writeln!(out, "## TASK: {}", task.title());
        match task {
            AnalysisTask::MalwareClassification => {
                let _ = writeln!(
                    out,
                    "Classify the binary artefacts described above. \
                     Focus on: file-system persistence, process injection, C2 communication \
                     patterns, and anti-analysis techniques."
                );
            }
            AnalysisTask::VulnerabilityHunting => {
                let _ = writeln!(
                    out,
                    "Audit the {} {} binary for exploitable vulnerabilities. \
                     Pay special attention to: memory-safety issues, integer arithmetic, \
                     untrusted input handling, and authentication bypasses.",
                    ctx.arch, ctx.os
                );
            }
            AnalysisTask::CryptoIdentification => {
                let _ = writeln!(
                    out,
                    "Identify every cryptographic primitive in the binary. \
                     Flag weak key lengths, ECB mode, reused nonces, or home-grown crypto."
                );
            }
            AnalysisTask::DecompilationReview => {
                let _ = writeln!(
                    out,
                    "Review the decompiled output. Recover struct layouts, clean up \
                     variable names, and annotate each function with its likely purpose."
                );
            }
            AnalysisTask::ProtocolReverse => {
                let _ = writeln!(
                    out,
                    "Reverse engineer the wire protocol. Define message framing, \
                     command codes, length fields, checksums, and authentication handshake."
                );
            }
            AnalysisTask::ObfuscationAnalysis => {
                let _ = writeln!(
                    out,
                    "Catalogue every obfuscation layer. For control-flow flattening, \
                     identify the dispatcher block and state variable. \
                     For string encryption, locate the decryption routine."
                );
            }
            AnalysisTask::BehaviorSummary => {
                let _ = writeln!(
                    out,
                    "Summarise all observable behaviours of the analysed code. \
                     Include API call chains and data-flow between components."
                );
            }
            AnalysisTask::ExploitDevelopment => {
                let _ = writeln!(
                    out,
                    "Analyse the vulnerability and propose an exploitation strategy \
                     for the described controlled lab environment."
                );
            }
            AnalysisTask::PatchAnalysis => {
                let _ = writeln!(
                    out,
                    "Compare before/after versions. Identify the root-cause vulnerability \
                     patched, and assess whether the fix is complete."
                );
            }
            AnalysisTask::FirmwareAnalysis => {
                let _ = writeln!(
                    out,
                    "Analyse the firmware image. Identify hardcoded credentials, \
                     insecure boot path, and network-exposed attack surface."
                );
            }
        }
        let _ = writeln!(out);
    }

    fn append_examples(&self, out: &mut String, task: &AnalysisTask) {
        match task {
            AnalysisTask::VulnerabilityHunting => {
                let _ = writeln!(out, "## EXAMPLES");
                let _ = writeln!(
                    out,
                    "**Example finding:**\n\
                     [HIGH] Stack Buffer Overflow — `strcpy(buf, user_input)` at 0x4012a0 \
                     with a 64-byte stack buffer and unchecked input length — \
                     Recommendation: use `strncpy` and validate length."
                );
                let _ = writeln!(out);
            }
            AnalysisTask::MalwareClassification => {
                let _ = writeln!(out, "## EXAMPLES");
                let _ = writeln!(
                    out,
                    "**Example output:**\n\
                     ```json\n\
                     {{\"family\": \"Emotet\", \"confidence\": 87, \
                     \"capabilities\": [\"C2\", \"persistence\", \"downloader\"], \
                     \"indicators\": [\"RegKey: HKCU\\\\Software\\\\Run\", \"HTTP POST /gate.php\"]}}\n\
                     ```"
                );
                let _ = writeln!(out);
            }
            _ => {} // No canned examples for other tasks
        }
    }

    fn append_output_format(&self, out: &mut String, task: &AnalysisTask) {
        let _ = writeln!(out, "## OUTPUT FORMAT");
        let _ = writeln!(out, "{}", task.output_format());
        let _ = writeln!(out);
    }

    fn append_constraints(&self, out: &mut String, task: &AnalysisTask) {
        let _ = writeln!(out, "## CONSTRAINTS");
        let _ = writeln!(out, "- Be concise but technically precise.");
        let _ = writeln!(out, "- Do not speculate beyond what the evidence supports.");
        let _ = writeln!(out, "- Reference specific addresses or offsets when available.");
        match task {
            AnalysisTask::ExploitDevelopment => {
                let _ = writeln!(
                    out,
                    "- This analysis is performed in an authorised security research context."
                );
            }
            AnalysisTask::MalwareClassification => {
                let _ = writeln!(out, "- Include confidence level for each capability claim.");
            }
            _ => {}
        }
        let _ = writeln!(out);
    }
}

// ─── Formatting helpers ───────────────────────────────────────────────────────

/// Format raw bytes as a classic hex dump with ASCII sidebar.
/// 16 bytes per line, prefixed with the address.
pub fn format_hex_dump(bytes: &[u8], base_addr: u64) -> String {
    let mut out = String::new();
    for (line_idx, chunk) in bytes.chunks(16).enumerate() {
        let addr = base_addr + (line_idx * 16) as u64;
        let _ = write!(out, "{addr:08x}  ");

        // Hex columns
        for (i, b) in chunk.iter().enumerate() {
            let _ = write!(out, "{b:02x} ");
            if i == 7 {
                out.push(' ');
            }
        }
        // Pad short last line
        if chunk.len() < 16 {
            let missing = 16 - chunk.len();
            for i in 0..missing {
                out.push_str("   ");
                if chunk.len() + i == 7 {
                    out.push(' ');
                }
            }
        }
        out.push_str(" |");

        // ASCII sidebar
        for &b in chunk {
            if b.is_ascii_graphic() || b == b' ' {
                out.push(b as char);
            } else {
                out.push('.');
            }
        }
        out.push_str("|\n");
    }
    out
}

/// Format disassembly as numbered lines with address prefix.
/// Input: `(address, raw_bytes_hex, mnemonic_and_operands)`
pub fn format_disasm_snippet(lines: &[(u64, String, String)]) -> String {
    let mut out = String::new();
    for (i, (addr, bytes_hex, mnemonic)) in lines.iter().enumerate() {
        let _ = writeln!(out, "{:4}  {:016x}  {:24}  {}", i + 1, addr, bytes_hex, mnemonic);
    }
    out
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_ctx() -> TaskContext {
        TaskContext::new("x86_64", "Linux").binary_type("ELF64")
    }

    // 1. build_prompt produces non-empty output
    #[test]
    fn test_build_prompt_non_empty() {
        let builder = AnalysisPromptBuilder::new();
        let (prompt, _) = builder.build_prompt(&AnalysisTask::MalwareClassification, &basic_ctx());
        assert!(!prompt.is_empty());
    }

    // 2. System instructions appear for each task
    #[test]
    fn test_system_instructions_present() {
        for task in [
            AnalysisTask::MalwareClassification,
            AnalysisTask::VulnerabilityHunting,
            AnalysisTask::CryptoIdentification,
        ] {
            let builder = AnalysisPromptBuilder::new();
            let (prompt, _) = builder.build_prompt(&task, &basic_ctx());
            assert!(
                prompt.contains("## SYSTEM"),
                "Missing SYSTEM section for {:?}",
                task
            );
        }
    }

    // 3. Context section includes architecture
    #[test]
    fn test_context_arch_present() {
        let builder = AnalysisPromptBuilder::new();
        let (prompt, _) = builder.build_prompt(&AnalysisTask::BehaviorSummary, &basic_ctx());
        assert!(prompt.contains("x86_64"));
    }

    // 4. Import samples appear in context
    #[test]
    fn test_import_samples() {
        let mut ctx = basic_ctx();
        ctx.import_samples = vec!["CreateRemoteThread".into(), "VirtualAlloc".into()];
        let builder = AnalysisPromptBuilder::new();
        let (prompt, _) = builder.build_prompt(&AnalysisTask::MalwareClassification, &ctx);
        assert!(prompt.contains("CreateRemoteThread"));
        assert!(prompt.contains("VirtualAlloc"));
    }

    // 5. String samples appear in context
    #[test]
    fn test_string_samples() {
        let mut ctx = basic_ctx();
        ctx.string_samples = vec!["http://evil.com/gate.php".into()];
        let builder = AnalysisPromptBuilder::new();
        let (prompt, _) = builder.build_prompt(&AnalysisTask::MalwareClassification, &ctx);
        assert!(prompt.contains("evil.com"));
    }

    // 6. Hex dump included when bytes provided
    #[test]
    fn test_hex_dump_included() {
        let mut ctx = basic_ctx();
        ctx.hex_bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let builder = AnalysisPromptBuilder::new();
        let (prompt, _) = builder.build_prompt(&AnalysisTask::ObfuscationAnalysis, &ctx);
        assert!(prompt.contains("de ad be ef"));
    }

    // 7. Hex dump excluded when without_hex_dump()
    #[test]
    fn test_hex_dump_excluded() {
        let mut ctx = basic_ctx();
        ctx.hex_bytes = vec![0xff, 0x00];
        let builder = AnalysisPromptBuilder::new().without_hex_dump();
        let (prompt, _) = builder.build_prompt(&AnalysisTask::ObfuscationAnalysis, &ctx);
        assert!(!prompt.contains("ff 00"));
    }

    // 8. Disassembly lines appear
    #[test]
    fn test_disasm_lines() {
        let mut ctx = basic_ctx();
        ctx.disasm_lines = vec![(0x401000, "55".into(), "push rbp".into())];
        let builder = AnalysisPromptBuilder::new();
        let (prompt, _) = builder.build_prompt(&AnalysisTask::DecompilationReview, &ctx);
        assert!(prompt.contains("push rbp"));
    }

    // 9. Output format section present
    #[test]
    fn test_output_format_section() {
        let builder = AnalysisPromptBuilder::new();
        let (prompt, _) = builder.build_prompt(&AnalysisTask::MalwareClassification, &basic_ctx());
        assert!(prompt.contains("## OUTPUT FORMAT"));
    }

    // 10. Constraints section present
    #[test]
    fn test_constraints_section() {
        let builder = AnalysisPromptBuilder::new();
        let (prompt, _) = builder.build_prompt(&AnalysisTask::VulnerabilityHunting, &basic_ctx());
        assert!(prompt.contains("## CONSTRAINTS"));
    }

    // 11. format_hex_dump 16-byte line
    #[test]
    fn test_format_hex_dump_line_length() {
        let bytes: Vec<u8> = (0..16).collect();
        let dump = format_hex_dump(&bytes, 0);
        let first_line = dump.lines().next().unwrap();
        assert!(first_line.starts_with("00000000  "));
        assert!(first_line.contains("|"));
    }

    // 12. format_hex_dump ASCII sidebar
    #[test]
    fn test_format_hex_dump_ascii() {
        let bytes = b"ABCD";
        let dump = format_hex_dump(bytes, 0);
        assert!(dump.contains("|ABCD"));
    }

    // 13. format_hex_dump non-printable shown as dot
    #[test]
    fn test_format_hex_dump_dots() {
        let bytes = &[0x01u8, 0x02, 0x03];
        let dump = format_hex_dump(bytes, 0);
        assert!(dump.contains("|..."));
    }

    // 14. format_disasm_snippet line numbering
    #[test]
    fn test_format_disasm_numbering() {
        let lines = vec![
            (0x1000u64, "48 89 e5".into(), "mov rbp, rsp".into()),
            (0x1003u64, "c3".into(), "ret".into()),
        ];
        let out = format_disasm_snippet(&lines);
        assert!(out.contains("   1  "));
        assert!(out.contains("   2  "));
        assert!(out.contains("mov rbp, rsp"));
        assert!(out.contains("ret"));
    }

    // 15. Quality estimated_tokens proportional to length
    #[test]
    fn test_quality_tokens_proportional() {
        let builder = AnalysisPromptBuilder::new();
        let short = basic_ctx();
        let mut long = basic_ctx();
        long.string_samples = (0..50).map(|i| format!("string_{i}")).collect();
        let (_, q_short) = builder.build_prompt(&AnalysisTask::BehaviorSummary, &short);
        let (_, q_long) = builder.build_prompt(&AnalysisTask::BehaviorSummary, &long);
        assert!(q_long.estimated_tokens > q_short.estimated_tokens);
    }

    // 16. Relevance score increases with more context
    #[test]
    fn test_relevance_score_increases_with_context() {
        let builder = AnalysisPromptBuilder::new();
        let minimal = basic_ctx();
        let mut rich = basic_ctx();
        rich.import_samples = vec!["malloc".into()];
        rich.string_samples = vec!["password".into()];
        rich.hex_bytes = vec![0xcc];
        let (_, q1) = builder.build_prompt(&AnalysisTask::MalwareClassification, &minimal);
        let (_, q2) = builder.build_prompt(&AnalysisTask::MalwareClassification, &rich);
        assert!(q2.relevance_score >= q1.relevance_score);
    }

    // 17. Entropy regions appear in output
    #[test]
    fn test_entropy_regions() {
        let mut ctx = basic_ctx();
        ctx.entropy_regions = vec![(0x1000, 0x2000, 7.8)];
        let builder = AnalysisPromptBuilder::new();
        let (prompt, _) = builder.build_prompt(&AnalysisTask::CryptoIdentification, &ctx);
        assert!(prompt.contains("7.800"));
    }

    // 18. Task title appears in TASK section
    #[test]
    fn test_task_title_in_prompt() {
        let builder = AnalysisPromptBuilder::new();
        let (prompt, _) = builder.build_prompt(&AnalysisTask::FirmwareAnalysis, &basic_ctx());
        assert!(prompt.contains("Firmware Analysis"));
    }

    // 19. ExploitDevelopment adds authorised context constraint
    #[test]
    fn test_exploit_authorised_constraint() {
        let builder = AnalysisPromptBuilder::new();
        let (prompt, _) =
            builder.build_prompt(&AnalysisTask::ExploitDevelopment, &basic_ctx());
        assert!(prompt.contains("authorised"));
    }

    // 20. max_strings limits string output
    #[test]
    fn test_max_strings_limit() {
        let mut ctx = basic_ctx();
        ctx.string_samples = (0..100).map(|i| format!("str_{i}")).collect();
        let builder = AnalysisPromptBuilder::new().max_strings(5);
        let (prompt, _) = builder.build_prompt(&AnalysisTask::MalwareClassification, &ctx);
        // Should contain str_4 but not str_5
        assert!(prompt.contains("str_4"));
        assert!(!prompt.contains("str_5"));
    }
}
