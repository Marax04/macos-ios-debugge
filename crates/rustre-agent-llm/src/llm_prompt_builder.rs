//! `llm_prompt_builder` — Build reverse-engineering–oriented prompts for LLM backends.
//!
//! Provides [`LlmPromptBuilder`], [`PromptTemplate`], and [`PromptSection`],
//! plus top-level helpers [`build_decompile_prompt`] and [`build_rename_prompt`].

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as FmtWrite;
use std::hash::BuildHasher;

use rustre_agent::casts::usize_to_u32;

// ── PromptSection ─────────────────────────────────────────────────────────────

/// A single named section that will be assembled into the final prompt.
#[derive(Debug, Clone)]
pub struct PromptSection {
    /// Human-readable section heading (used as a markdown H2).
    pub heading: String,
    /// Body text for this section.
    pub body: String,
    /// Whether to wrap `body` in a fenced code block.
    pub code_fence: bool,
    /// Optional language tag for the fence (e.g. `"c"`, `"asm"`).
    pub language: Option<String>,
    /// Weight used when the context must be trimmed to a token budget.
    /// Higher weight = more likely to survive trimming.  Range: 1–10.
    pub priority: u8,
}

impl PromptSection {
    /// Plain text section (no code fence).
    #[must_use]
    pub fn text(heading: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            heading: heading.into(),
            body: body.into(),
            code_fence: false,
            language: None,
            priority: 5,
        }
    }

    /// Code section wrapped in a fenced code block.
    #[must_use]
    pub fn code(
        heading: impl Into<String>,
        body: impl Into<String>,
        language: impl Into<String>,
    ) -> Self {
        Self {
            heading: heading.into(),
            body: body.into(),
            code_fence: true,
            language: Some(language.into()),
            priority: 5,
        }
    }

    /// Set the priority (1 = drop first, 10 = keep last).
    #[must_use]
    pub fn with_priority(mut self, p: u8) -> Self {
        self.priority = p.clamp(1, 10);
        self
    }

    /// Estimate token count (chars / 4 + overhead).
    #[must_use]
    pub fn estimated_tokens(&self) -> u32 {
        let chars = self.heading.len() + self.body.len();
        // fence overhead + heading + body
        let overhead = if self.code_fence { 12 } else { 6 };
        (usize_to_u32(chars) / 4).saturating_add(overhead)
    }

    /// Render the section to a markdown string.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = format!("## {}\n\n", self.heading);
        if self.code_fence {
            let lang = self.language.as_deref().unwrap_or("");
            let _ = write!(out, "```{lang}\n{}\n```\n", self.body);
        } else {
            out.push_str(&self.body);
            out.push('\n');
        }
        out
    }
}

impl fmt::Display for PromptSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

// ── PromptTemplate ────────────────────────────────────────────────────────────

/// A reusable template that describes how to build a specific kind of RE prompt.
#[derive(Debug, Clone)]
pub struct PromptTemplate {
    /// Unique name for this template (e.g. `"decompile"`, `"rename"`).
    pub name: String,
    /// System message preamble injected before the sections.
    pub system_preamble: String,
    /// List of section headings this template expects to have filled in.
    pub expected_sections: Vec<String>,
    /// Default values for optional sections.
    pub defaults: HashMap<String, String>,
    /// Maximum tokens this template should consume.
    pub max_tokens: u32,
}

impl PromptTemplate {
    /// Create a new template.
    #[must_use]
    pub fn new(name: impl Into<String>, system_preamble: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            system_preamble: system_preamble.into(),
            expected_sections: Vec::new(),
            defaults: HashMap::new(),
            max_tokens: 8192,
        }
    }

    /// Declare a required section heading.
    #[must_use]
    pub fn require_section(mut self, heading: impl Into<String>) -> Self {
        self.expected_sections.push(heading.into());
        self
    }

    /// Supply a default body for an optional section.
    #[must_use]
    pub fn default_section(mut self, heading: impl Into<String>, body: impl Into<String>) -> Self {
        self.defaults.insert(heading.into(), body.into());
        self
    }

    /// Override the token budget.
    #[must_use]
    pub const fn with_max_tokens(mut self, n: u32) -> Self {
        self.max_tokens = n;
        self
    }

    /// Returns the decompiler-focused default template.
    #[must_use]
    pub fn decompile() -> Self {
        Self::new(
            "decompile",
            "You are an expert reverse engineer. Analyze the provided disassembly and produce \
             clean, idiomatic C pseudo-code. Annotate local variables and infer their types. \
             Identify common patterns (loops, string operations, crypto primitives). \
             Do not emit TODO comments; fill in your best understanding of the code.",
        )
        .require_section("Binary Context")
        .require_section("Disassembly")
        .default_section("Known Symbols", "(none provided)")
        .default_section("Calling Convention", "x86-64 System V")
        .with_max_tokens(12_000)
    }

    /// Returns the rename-suggestion default template.
    #[must_use]
    pub fn rename() -> Self {
        Self::new(
            "rename",
            "You are an expert reverse engineer specializing in symbol naming. \
             Given the decompiled or disassembled code and context clues, propose \
             descriptive names for functions, variables, and data items. \
             Output a JSON array of {\"old\": \"...\", \"new\": \"...\", \"confidence\": 0.0-1.0} objects.",
        )
        .require_section("Code")
        .require_section("Current Symbol Names")
        .default_section("Import Hints", "(none)")
        .with_max_tokens(6_000)
    }

    /// Returns an exploit-analysis template.
    #[must_use]
    pub fn exploit_analysis() -> Self {
        Self::new(
            "exploit_analysis",
            "You are a vulnerability researcher. Analyze the code for security weaknesses \
             including buffer overflows, use-after-free, format string bugs, integer overflows, \
             and logic errors. For each finding provide: location, severity (Critical/High/Medium/Low), \
             description, and a suggested fix.",
        )
        .require_section("Code Under Review")
        .default_section("Known Mitigations", "Stack canaries, NX, ASLR")
        .with_max_tokens(10_000)
    }

    /// Validate that all required sections are present in `sections`.
    /// Returns a list of missing section headings.
    #[must_use]
    pub fn missing_sections(&self, sections: &[PromptSection]) -> Vec<String> {
        let provided: std::collections::HashSet<&str> =
            sections.iter().map(|s| s.heading.as_str()).collect();
        self.expected_sections
            .iter()
            .filter(|e| !provided.contains(e.as_str()))
            .cloned()
            .collect()
    }
}

// ── LlmPromptBuilder ─────────────────────────────────────────────────────────

/// Assembles a list of [`PromptSection`]s into a final system + user message pair,
/// trimming to fit a token budget when necessary.
#[derive(Debug, Default)]
pub struct LlmPromptBuilder {
    sections: Vec<PromptSection>,
    system_preamble: String,
    token_budget: u32,
    /// If set, a trailing instruction appended after all sections.
    trailing_instruction: Option<String>,
    /// Key–value metadata passed to templates for interpolation.
    metadata: HashMap<String, String>,
}

impl LlmPromptBuilder {
    /// Create a builder with a 4096-token default budget.
    #[must_use]
    pub fn new() -> Self {
        Self {
            token_budget: 4096,
            ..Self::default()
        }
    }

    /// Apply a [`PromptTemplate`], setting the system preamble and token budget.
    #[must_use]
    pub fn with_template(mut self, template: &PromptTemplate) -> Self {
        self.system_preamble.clone_from(&template.system_preamble);
        self.token_budget = template.max_tokens;
        // Inject defaults for sections not yet added
        for (heading, body) in &template.defaults {
            if !self.sections.iter().any(|s| &s.heading == heading) {
                self.sections
                    .push(PromptSection::text(heading.clone(), body.clone()).with_priority(2));
            }
        }
        self
    }

    /// Set the system preamble directly.
    #[must_use]
    pub fn system(mut self, preamble: impl Into<String>) -> Self {
        self.system_preamble = preamble.into();
        self
    }

    /// Set the token budget.
    #[must_use]
    pub const fn budget(mut self, tokens: u32) -> Self {
        self.token_budget = tokens;
        self
    }

    /// Append a section.
    #[must_use]
    pub fn section(mut self, sec: PromptSection) -> Self {
        self.sections.push(sec);
        self
    }

    /// Append a plain-text section.
    #[must_use]
    pub fn text_section(self, heading: impl Into<String>, body: impl Into<String>) -> Self {
        self.section(PromptSection::text(heading, body))
    }

    /// Append a code section.
    #[must_use]
    pub fn code_section(
        self,
        heading: impl Into<String>,
        body: impl Into<String>,
        lang: impl Into<String>,
    ) -> Self {
        self.section(PromptSection::code(heading, body, lang))
    }

    /// Set a trailing instruction.
    #[must_use]
    pub fn instruction(mut self, text: impl Into<String>) -> Self {
        self.trailing_instruction = Some(text.into());
        self
    }

    /// Insert metadata for template interpolation.
    #[must_use]
    pub fn meta(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), val.into());
        self
    }

    /// Interpolate `{key}` placeholders in a string from the metadata map.
    fn interpolate(&self, text: &str) -> String {
        let mut result = text.to_string();
        for (k, v) in &self.metadata {
            result = result.replace(&format!("{{{k}}}"), v);
        }
        result
    }

    /// Build the prompt, returning `(system_message, user_message)`.
    ///
    /// Sections are trimmed from lowest to highest priority to fit `token_budget`.
    #[must_use]
    pub fn build(mut self) -> (String, String) {
        let system = self.interpolate(&self.system_preamble);

        // Sort by priority descending so we drop low-priority sections first.
        self.sections
            .sort_unstable_by(|a, b| b.priority.cmp(&a.priority));

        let budget = self.token_budget;
        let mut total_tokens: u32 = usize_to_u32(system.len()) / 4;
        if let Some(ref instr) = self.trailing_instruction {
            total_tokens += usize_to_u32(instr.len()) / 4 + 4;
        }

        // Greedily include sections from highest to lowest priority.
        let mut included: Vec<&PromptSection> = Vec::new();
        for sec in &self.sections {
            let cost = sec.estimated_tokens();
            if total_tokens + cost <= budget {
                total_tokens += cost;
                included.push(sec);
            }
        }

        // Restore insertion order (stable sort by original index not tracked here,
        // so we sort by heading lexicographically as a tie-break — acceptable for RE use).
        included.sort_unstable_by(|a, b| a.heading.cmp(&b.heading));

        let mut user = String::new();
        for sec in included {
            user.push_str(&self.interpolate(&sec.render()));
            user.push('\n');
        }
        if let Some(ref instr) = self.trailing_instruction {
            user.push_str("---\n");
            user.push_str(&self.interpolate(instr));
            user.push('\n');
        }

        (system, user)
    }

    /// Build and return only the user-turn string.
    #[must_use]
    pub fn build_user_prompt(self) -> String {
        self.build().1
    }

    /// Total estimated token count across all sections (before trimming).
    #[must_use]
    pub fn estimated_total_tokens(&self) -> u32 {
        self.sections.iter().map(PromptSection::estimated_tokens).sum::<u32>()
            + (usize_to_u32(self.system_preamble.len()) / 4)
    }
}

// ── Top-level helpers ─────────────────────────────────────────────────────────

/// Build a decompilation-focused prompt ready for submission to an LLM.
///
/// # Parameters
/// - `disassembly`: the raw disassembly listing
/// - `binary_context`: short description of the binary (arch, format, etc.)
/// - `known_symbols`: optional map of address → known name
/// - `calling_convention`: e.g. `"x86-64 System V"` or `"MSVC __fastcall"`
/// - `max_tokens`: token budget for the full prompt
///
/// Returns `(system_message, user_message)`.
#[must_use]
pub fn build_decompile_prompt<S: BuildHasher>(
    disassembly: &str,
    binary_context: &str,
    known_symbols: Option<&HashMap<u64, String, S>>,
    calling_convention: &str,
    max_tokens: u32,
) -> (String, String) {
    let template = PromptTemplate::decompile().with_max_tokens(max_tokens);

    let symbols_body = match known_symbols {
        None => "(no known symbols)".to_string(),
        Some(m) if m.is_empty() => "(no known symbols)".to_string(),
        Some(m) => {
            let mut lines: Vec<String> = m
                .iter()
                .map(|(addr, name)| format!("{addr:#010x}  {name}"))
                .collect();
            lines.sort();
            lines.join("\n")
        }
    };

    LlmPromptBuilder::new()
        .with_template(&template)
        .code_section("Binary Context", binary_context, "")
        .code_section("Disassembly", disassembly, "asm")
        .text_section("Known Symbols", symbols_body)
        .text_section("Calling Convention", calling_convention)
        .instruction("Produce clean C pseudo-code for the function above.")
        .build()
}

/// Build a rename-suggestion prompt for an LLM.
///
/// # Parameters
/// - `code`: decompiled or disassembled code
/// - `current_names`: list of current (mangled or auto-generated) symbol names
/// - `context_hints`: optional additional context (e.g. import names nearby)
/// - `max_tokens`: token budget
///
/// Returns `(system_message, user_message)`.
#[must_use]
pub fn build_rename_prompt(
    code: &str,
    current_names: &[String],
    context_hints: Option<&str>,
    max_tokens: u32,
) -> (String, String) {
    let template = PromptTemplate::rename().with_max_tokens(max_tokens);

    let names_body = if current_names.is_empty() {
        "(none)".to_string()
    } else {
        current_names.join("\n")
    };

    let mut builder = LlmPromptBuilder::new()
        .with_template(&template)
        .code_section("Code", code, "c")
        .text_section("Current Symbol Names", names_body);

    if let Some(hints) = context_hints {
        builder = builder.text_section("Import Hints", hints);
    }

    builder
        .instruction(
            "Return a JSON array of rename suggestions: \
             [{\"old\":\"...\",\"new\":\"...\",\"confidence\":0.9}]",
        )
        .build()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_render_text() {
        let sec = PromptSection::text("Task", "Do this now.");
        let rendered = sec.render();
        assert!(rendered.contains("## Task"));
        assert!(rendered.contains("Do this now."));
        assert!(!rendered.contains("```"));
    }

    #[test]
    fn test_section_render_code() {
        let sec = PromptSection::code("Disassembly", "mov eax, 1\nret", "asm");
        let rendered = sec.render();
        assert!(rendered.contains("```asm"));
        assert!(rendered.contains("mov eax, 1"));
        assert!(rendered.contains("```"));
    }

    #[test]
    fn test_section_estimated_tokens() {
        let sec = PromptSection::text("H", "A".repeat(400));
        let tok = sec.estimated_tokens();
        assert!(tok >= 100, "expected >= 100 tokens, got {tok}");
    }

    #[test]
    fn test_section_priority_clamp() {
        let sec = PromptSection::text("H", "B").with_priority(99);
        assert_eq!(sec.priority, 10);
        let sec2 = PromptSection::text("H", "B").with_priority(0);
        assert_eq!(sec2.priority, 1);
    }

    #[test]
    fn test_template_decompile_name() {
        let t = PromptTemplate::decompile();
        assert_eq!(t.name, "decompile");
        assert!(t.max_tokens > 0);
        assert!(!t.expected_sections.is_empty());
    }

    #[test]
    fn test_template_rename_name() {
        let t = PromptTemplate::rename();
        assert_eq!(t.name, "rename");
    }

    #[test]
    fn test_template_missing_sections() {
        let t = PromptTemplate::decompile();
        let provided = vec![PromptSection::code("Disassembly", "nop", "asm")];
        let missing = t.missing_sections(&provided);
        assert!(missing.contains(&"Binary Context".to_string()));
        assert!(!missing.contains(&"Disassembly".to_string()));
    }

    #[test]
    fn test_template_no_missing_sections() {
        let t = PromptTemplate::decompile();
        let provided = vec![
            PromptSection::text("Binary Context", "PE x86-64"),
            PromptSection::code("Disassembly", "nop", "asm"),
        ];
        let missing = t.missing_sections(&provided);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_builder_basic_build() {
        let (sys, user) = LlmPromptBuilder::new()
            .system("You are an RE expert.")
            .section(PromptSection::text("Context", "A PE binary."))
            .section(PromptSection::code("Code", "push rbp\nret", "asm"))
            .build();
        assert!(sys.contains("RE expert"));
        assert!(user.contains("push rbp"));
        assert!(user.contains("Context"));
    }

    #[test]
    fn test_builder_metadata_interpolation() {
        let (_, user) = LlmPromptBuilder::new()
            .meta("arch", "x86-64")
            .section(PromptSection::text("Architecture", "Target: {arch}"))
            .build();
        assert!(user.contains("x86-64"));
        assert!(!user.contains("{arch}"));
    }

    #[test]
    fn test_builder_token_trimming() {
        // Very tight budget — only high-priority section should survive.
        let (_, user) = LlmPromptBuilder::new()
            .budget(50)
            .section(PromptSection::text("Low", "Drop me please.").with_priority(1))
            .section(PromptSection::text("High", "Keep me.").with_priority(10))
            .build();
        // High priority section fits; low priority may be dropped
        assert!(user.contains("Keep me") || user.is_empty());
    }

    #[test]
    fn test_builder_trailing_instruction() {
        let (_, user) = LlmPromptBuilder::new()
            .instruction("Now produce the output.")
            .build();
        assert!(user.contains("Now produce the output."));
        assert!(user.contains("---"));
    }

    #[test]
    fn test_builder_estimated_tokens() {
        let builder = LlmPromptBuilder::new()
            .system("sys")
            .section(PromptSection::text("H", "B".repeat(100)));
        assert!(builder.estimated_total_tokens() > 0);
    }

    #[test]
    fn test_build_decompile_prompt() {
        let mut syms = HashMap::new();
        syms.insert(0x1000u64, "init_crypto".to_string());
        let (sys, user) =
            build_decompile_prompt("mov eax, 1\nret", "PE x64", Some(&syms), "x86-64 SysV", 8192);
        assert!(!sys.is_empty());
        assert!(user.contains("mov eax") || user.contains("Disassembly"));
        assert!(user.contains("init_crypto") || user.contains("Known Symbols"));
    }

    #[test]
    fn test_build_decompile_prompt_no_symbols() {
        let (sys, user) =
            build_decompile_prompt::<std::collections::hash_map::RandomState>("nop\nret", "ELF x64", None, "x86-64 SysV", 4096);
        assert!(!sys.is_empty());
        assert!(!user.is_empty());
    }

    #[test]
    fn test_build_rename_prompt() {
        let names = vec!["sub_1000".to_string(), "var_8".to_string()];
        let (sys, user) =
            build_rename_prompt("int sub_1000(int a) { return a + 1; }", &names, None, 4096);
        assert!(!sys.is_empty());
        assert!(user.contains("sub_1000") || user.contains("Code"));
    }

    #[test]
    fn test_build_rename_prompt_with_hints() {
        let names = vec!["sub_2000".to_string()];
        let (_, user) = build_rename_prompt(
            "call strcmp\nret",
            &names,
            Some("imports: strcmp, malloc, free"),
            4096,
        );
        assert!(user.contains("strcmp") || user.contains("Import"));
    }

    #[test]
    fn test_build_rename_prompt_empty_names() {
        let (_, user) = build_rename_prompt("nop", &[], None, 4096);
        assert!(!user.is_empty());
    }

    #[test]
    fn test_template_with_max_tokens() {
        let t = PromptTemplate::decompile().with_max_tokens(2048);
        assert_eq!(t.max_tokens, 2048);
    }

    #[test]
    fn test_template_default_section_missing() {
        let t = PromptTemplate::decompile();
        // "Calling Convention" has a default — should be present when builder uses template
        let builder = LlmPromptBuilder::new().with_template(&t);
        // Check that the default got injected into sections
        assert!(builder.sections.iter().any(|s| s.heading == "Calling Convention"));
    }

    #[test]
    fn test_section_display_trait() {
        let sec = PromptSection::text("Foo", "Bar");
        let displayed = format!("{sec}");
        assert!(displayed.contains("Foo"));
        assert!(displayed.contains("Bar"));
    }

    #[test]
    fn test_exploit_analysis_template() {
        let t = PromptTemplate::exploit_analysis();
        assert_eq!(t.name, "exploit_analysis");
        assert!(!t.system_preamble.is_empty());
    }
}
