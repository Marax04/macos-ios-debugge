// context_assembler.rs — Budget-aware context assembly for LLM prompts.
//
// Disassembly, strings, imports, CFG, symbols → structured prompt context.
// Token budget management, context compression, context diff.
//
// Distinct from `context_builder`:
//   `context_assembler` is the **priority + budget** layer — it accepts raw
//   text blobs, wraps them as `ContextSection` with `ContextPriority`, tracks
//   a `TokenBudget`, drops or compresses low-priority sections when over budget,
//   and supports diff-ing two `AssembledContext` values.
//
//   `context_builder` is the **typed data-model** layer — it owns strongly-typed
//   structs (BinaryInfo, FunctionEntry, XrefEntry, …), serialises them to text,
//   and offers iterative compression based on section size.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Priority
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContextPriority {
    Critical = 4,
    High = 3,
    Medium = 2,
    Low = 1,
    Optional = 0,
}

impl fmt::Display for ContextPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContextPriority::Critical => write!(f, "critical"),
            ContextPriority::High => write!(f, "high"),
            ContextPriority::Medium => write!(f, "medium"),
            ContextPriority::Low => write!(f, "low"),
            ContextPriority::Optional => write!(f, "optional"),
        }
    }
}

// ---------------------------------------------------------------------------
// ContextSection — one piece of context
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionKind {
    Disassembly,
    Pseudocode,
    Strings,
    Imports,
    Exports,
    ControlFlowGraph,
    Symbols,
    CrossReferences,
    DataStructures,
    Entropy,
    Comments,
    Custom,
}

impl fmt::Display for SectionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SectionKind::Disassembly => "disassembly",
            SectionKind::Pseudocode => "pseudocode",
            SectionKind::Strings => "strings",
            SectionKind::Imports => "imports",
            SectionKind::Exports => "exports",
            SectionKind::ControlFlowGraph => "cfg",
            SectionKind::Symbols => "symbols",
            SectionKind::CrossReferences => "xrefs",
            SectionKind::DataStructures => "structs",
            SectionKind::Entropy => "entropy",
            SectionKind::Comments => "comments",
            SectionKind::Custom => "custom",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone)]
pub struct ContextSection {
    pub kind: SectionKind,
    pub label: String,
    pub content: String,
    pub priority: ContextPriority,
    pub token_estimate: u32,
    pub compressed: bool,
    pub metadata: HashMap<String, String>,
}

impl ContextSection {
    pub fn new(kind: SectionKind, label: impl Into<String>, content: impl Into<String>) -> Self {
        let content = content.into();
        let tok = estimate_tokens(&content);
        ContextSection {
            kind,
            label: label.into(),
            content,
            priority: ContextPriority::Medium,
            token_estimate: tok,
            compressed: false,
            metadata: HashMap::new(),
        }
    }

    pub fn with_priority(mut self, priority: ContextPriority) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn compress(&self, max_lines: usize) -> ContextSection {
        let lines: Vec<&str> = self.content.lines().collect();
        if lines.len() <= max_lines {
            return self.clone();
        }
        let keep = max_lines / 2;
        let mut compressed = lines[..keep].join("\n");
        compressed.push_str(&format!("\n... ({} lines omitted) ...\n", lines.len() - max_lines));
        compressed.push_str(&lines[lines.len() - keep..].join("\n"));
        let tok = estimate_tokens(&compressed);
        ContextSection {
            kind: self.kind,
            label: self.label.clone(),
            content: compressed,
            priority: self.priority,
            token_estimate: tok,
            compressed: true,
            metadata: self.metadata.clone(),
        }
    }

    pub fn format_for_prompt(&self) -> String {
        format!("### {}\n{}\n", self.label, self.content)
    }
}

// ---------------------------------------------------------------------------
// TokenBudget
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TokenBudget {
    pub total: u32,
    pub reserved_for_response: u32,
    pub reserved_for_system: u32,
    pub used: u32,
}

impl TokenBudget {
    pub fn new(total: u32, response_reserve: u32, system_reserve: u32) -> Self {
        TokenBudget {
            total,
            reserved_for_response: response_reserve,
            reserved_for_system: system_reserve,
            used: 0,
        }
    }

    pub fn available(&self) -> u32 {
        self.total
            .saturating_sub(self.reserved_for_response)
            .saturating_sub(self.reserved_for_system)
            .saturating_sub(self.used)
    }

    pub fn consume(&mut self, tokens: u32) -> bool {
        if tokens <= self.available() {
            self.used += tokens;
            true
        } else {
            false
        }
    }

    pub fn utilization_pct(&self) -> f64 {
        let cap = self.total
            .saturating_sub(self.reserved_for_response)
            .saturating_sub(self.reserved_for_system)
            .max(1);
        (self.used as f64 / cap as f64) * 100.0
    }

    pub fn is_exhausted(&self) -> bool {
        self.available() == 0
    }
}

// ---------------------------------------------------------------------------
// AssembledContext
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AssembledContext {
    pub sections: Vec<ContextSection>,
    pub total_tokens: u32,
    pub dropped_sections: Vec<String>,
    pub metadata: HashMap<String, String>,
}

impl AssembledContext {
    pub fn format_for_prompt(&self) -> String {
        self.sections.iter().map(|s| s.format_for_prompt()).collect::<Vec<_>>().join("\n")
    }

    pub fn section_count(&self) -> usize {
        self.sections.len()
    }

    pub fn find_section(&self, kind: SectionKind) -> Option<&ContextSection> {
        self.sections.iter().find(|s| s.kind == kind)
    }

    pub fn summary(&self) -> String {
        format!(
            "Context: {} sections, {} tokens, {} dropped",
            self.sections.len(),
            self.total_tokens,
            self.dropped_sections.len()
        )
    }
}

// ---------------------------------------------------------------------------
// ContextDiff
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ContextDiff {
    pub added_sections: Vec<SectionKind>,
    pub removed_sections: Vec<SectionKind>,
    pub changed_sections: Vec<(SectionKind, u32, u32)>, // kind, old_tokens, new_tokens
}

impl ContextDiff {
    pub fn compute(old: &AssembledContext, new: &AssembledContext) -> Self {
        let old_kinds: HashMap<SectionKind, &ContextSection> =
            old.sections.iter().map(|s| (s.kind, s)).collect();
        let new_kinds: HashMap<SectionKind, &ContextSection> =
            new.sections.iter().map(|s| (s.kind, s)).collect();

        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut changed = Vec::new();

        for (&kind, new_sec) in &new_kinds {
            if let Some(old_sec) = old_kinds.get(&kind) {
                if old_sec.content != new_sec.content {
                    changed.push((kind, old_sec.token_estimate, new_sec.token_estimate));
                }
            } else {
                added.push(kind);
            }
        }
        for &kind in old_kinds.keys() {
            if !new_kinds.contains_key(&kind) {
                removed.push(kind);
            }
        }

        ContextDiff { added_sections: added, removed_sections: removed, changed_sections: changed }
    }

    pub fn is_empty(&self) -> bool {
        self.added_sections.is_empty()
            && self.removed_sections.is_empty()
            && self.changed_sections.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ContextAssembler
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AssemblerConfig {
    pub max_disasm_lines: usize,
    pub max_string_count: usize,
    pub max_import_count: usize,
    pub max_xref_count: usize,
    pub compress_if_over: u32,
    pub include_entropy: bool,
    pub include_comments: bool,
    pub include_cfg: bool,
}

impl Default for AssemblerConfig {
    fn default() -> Self {
        AssemblerConfig {
            max_disasm_lines: 200,
            max_string_count: 50,
            max_import_count: 100,
            max_xref_count: 30,
            compress_if_over: 400,
            include_entropy: true,
            include_comments: true,
            include_cfg: false,
        }
    }
}

pub struct ContextAssembler {
    config: AssemblerConfig,
    sections: Vec<ContextSection>,
    budget: TokenBudget,
}

impl ContextAssembler {
    pub fn new(budget: TokenBudget) -> Self {
        ContextAssembler {
            config: AssemblerConfig::default(),
            sections: Vec::new(),
            budget,
        }
    }

    pub fn with_config(mut self, config: AssemblerConfig) -> Self {
        self.config = config;
        self
    }

    pub fn add_disassembly(&mut self, address: u64, disasm: impl Into<String>) {
        let raw = disasm.into();
        let content = format!("Function @ 0x{:x}\n{}", address, raw);
        let mut section = ContextSection::new(
            SectionKind::Disassembly,
            format!("Disassembly @ 0x{:x}", address),
            content,
        )
        .with_priority(ContextPriority::Critical)
        .with_meta("address", format!("0x{:x}", address));

        if section.token_estimate > self.config.compress_if_over {
            section = section.compress(self.config.max_disasm_lines);
        }
        self.sections.push(section);
    }

    pub fn add_pseudocode(&mut self, func_name: impl Into<String>, code: impl Into<String>) {
        let fname = func_name.into();
        let section = ContextSection::new(
            SectionKind::Pseudocode,
            format!("Pseudocode: {}", fname),
            code.into(),
        )
        .with_priority(ContextPriority::Critical)
        .with_meta("function", fname);
        self.sections.push(section);
    }

    pub fn add_strings(&mut self, strings: &[String]) {
        let limited: Vec<&String> = strings.iter().take(self.config.max_string_count).collect();
        if limited.is_empty() {
            return;
        }
        let content = limited.iter().enumerate()
            .map(|(i, s)| format!("[{}] {:?}", i, s))
            .collect::<Vec<_>>()
            .join("\n");
        let section = ContextSection::new(
            SectionKind::Strings,
            format!("Strings ({} shown)", limited.len()),
            content,
        )
        .with_priority(ContextPriority::High);
        self.sections.push(section);
    }

    pub fn add_imports(&mut self, imports: &[(String, String)]) {
        let limited: Vec<&(String, String)> = imports.iter().take(self.config.max_import_count).collect();
        if limited.is_empty() {
            return;
        }
        let content = limited.iter()
            .map(|(dll, func)| format!("{} -> {}", dll, func))
            .collect::<Vec<_>>()
            .join("\n");
        let section = ContextSection::new(
            SectionKind::Imports,
            format!("Imports ({} shown)", limited.len()),
            content,
        )
        .with_priority(ContextPriority::High);
        self.sections.push(section);
    }

    pub fn add_symbols(&mut self, symbols: &[(u64, String)]) {
        let content = symbols.iter()
            .map(|(addr, name)| format!("0x{:x}: {}", addr, name))
            .collect::<Vec<_>>()
            .join("\n");
        let section = ContextSection::new(
            SectionKind::Symbols,
            "Symbols".to_string(),
            content,
        )
        .with_priority(ContextPriority::Medium);
        self.sections.push(section);
    }

    pub fn add_xrefs(&mut self, xrefs_to: &[u64], xrefs_from: &[u64]) {
        let limited_to: Vec<&u64> = xrefs_to.iter().take(self.config.max_xref_count).collect();
        let limited_from: Vec<&u64> = xrefs_from.iter().take(self.config.max_xref_count).collect();
        let mut content = String::new();
        if !limited_to.is_empty() {
            content.push_str("Called from:\n");
            for addr in &limited_to {
                content.push_str(&format!("  0x{:x}\n", addr));
            }
        }
        if !limited_from.is_empty() {
            content.push_str("Calls to:\n");
            for addr in &limited_from {
                content.push_str(&format!("  0x{:x}\n", addr));
            }
        }
        if content.is_empty() {
            return;
        }
        let section = ContextSection::new(
            SectionKind::CrossReferences,
            "Cross References".to_string(),
            content,
        )
        .with_priority(ContextPriority::Low);
        self.sections.push(section);
    }

    pub fn add_cfg_summary(&mut self, blocks: &[(u64, usize)]) {
        if !self.config.include_cfg || blocks.is_empty() {
            return;
        }
        let content = blocks.iter()
            .map(|(addr, insn_count)| format!("BB @ 0x{:x}: {} instructions", addr, insn_count))
            .collect::<Vec<_>>()
            .join("\n");
        let section = ContextSection::new(
            SectionKind::ControlFlowGraph,
            format!("CFG ({} basic blocks)", blocks.len()),
            content,
        )
        .with_priority(ContextPriority::Medium);
        self.sections.push(section);
    }

    pub fn add_entropy_info(&mut self, section_name: &str, entropy: f64) {
        if !self.config.include_entropy {
            return;
        }
        let content = format!("Section '{}': entropy = {:.2} bits/byte", section_name, entropy);
        let section = ContextSection::new(
            SectionKind::Entropy,
            "Entropy Analysis".to_string(),
            content,
        )
        .with_priority(ContextPriority::Low);
        self.sections.push(section);
    }

    pub fn add_comment(&mut self, address: u64, comment: impl Into<String>) {
        if !self.config.include_comments {
            return;
        }
        let content = format!("0x{:x}: {}", address, comment.into());
        let section = ContextSection::new(
            SectionKind::Comments,
            "Analyst Comments".to_string(),
            content,
        )
        .with_priority(ContextPriority::Medium);
        self.sections.push(section);
    }

    pub fn add_section(&mut self, section: ContextSection) {
        self.sections.push(section);
    }

    /// Assemble the context, respecting token budget and priorities
    pub fn assemble(mut self) -> AssembledContext {
        // Sort by priority descending
        self.sections.sort_by(|a, b| b.priority.cmp(&a.priority));

        let mut included = Vec::new();
        let mut dropped = Vec::new();
        let mut total_tokens = 0u32;

        for section in self.sections {
            if self.budget.consume(section.token_estimate) {
                total_tokens += section.token_estimate;
                included.push(section);
            } else {
                // Try compressed version
                let compressed = section.compress(30);
                if self.budget.consume(compressed.token_estimate) {
                    total_tokens += compressed.token_estimate;
                    included.push(compressed);
                } else {
                    dropped.push(section.label.clone());
                }
            }
        }

        // Re-sort included by a natural order for readability
        included.sort_by_key(|s| match s.kind {
            SectionKind::Pseudocode => 0,
            SectionKind::Disassembly => 1,
            SectionKind::Strings => 2,
            SectionKind::Imports => 3,
            SectionKind::Exports => 4,
            SectionKind::Symbols => 5,
            SectionKind::CrossReferences => 6,
            SectionKind::ControlFlowGraph => 7,
            SectionKind::DataStructures => 8,
            SectionKind::Entropy => 9,
            SectionKind::Comments => 10,
            SectionKind::Custom => 11,
        });

        AssembledContext {
            sections: included,
            total_tokens,
            dropped_sections: dropped,
            metadata: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn estimate_tokens(text: &str) -> u32 {
    // Rough: 1 token ≈ 4 chars
    ((text.len() / 4).max(1).min(u32::MAX as usize)) as u32
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_assembly() {
        let budget = TokenBudget::new(8192, 1024, 256);
        let mut asm = ContextAssembler::new(budget);
        asm.add_disassembly(0x401000, "mov rax, 1\nxor rbx, rbx\nret");
        asm.add_strings(&["Hello".to_string(), "World".to_string()]);
        let ctx = asm.assemble();
        assert!(ctx.section_count() >= 2);
        assert!(ctx.total_tokens > 0);
    }

    #[test]
    fn test_token_budget() {
        let mut budget = TokenBudget::new(100, 20, 10);
        assert_eq!(budget.available(), 70);
        assert!(budget.consume(50));
        assert_eq!(budget.available(), 20);
        assert!(!budget.consume(30));
    }

    #[test]
    fn test_section_compress() {
        let lines: Vec<String> = (0..100).map(|i| format!("line {}", i)).collect();
        let content = lines.join("\n");
        let section = ContextSection::new(SectionKind::Disassembly, "test", content);
        let compressed = section.compress(20);
        assert!(compressed.compressed);
        assert!(compressed.content.contains("omitted"));
    }

    #[test]
    fn test_context_diff() {
        let budget1 = TokenBudget::new(8192, 1024, 256);
        let budget2 = TokenBudget::new(8192, 1024, 256);
        let mut asm1 = ContextAssembler::new(budget1);
        asm1.add_disassembly(0x1000, "mov rax, 1");
        let ctx1 = asm1.assemble();

        let mut asm2 = ContextAssembler::new(budget2);
        asm2.add_disassembly(0x1000, "mov rbx, 2");
        asm2.add_strings(&["new_string".to_string()]);
        let ctx2 = asm2.assemble();

        let diff = ContextDiff::compute(&ctx1, &ctx2);
        assert!(!diff.is_empty());
    }

    #[test]
    fn test_format_for_prompt() {
        let budget = TokenBudget::new(8192, 1024, 256);
        let mut asm = ContextAssembler::new(budget);
        asm.add_disassembly(0x401000, "nop");
        let ctx = asm.assemble();
        let formatted = ctx.format_for_prompt();
        assert!(formatted.contains("###"));
    }

    #[test]
    fn test_drop_low_priority_when_budget_tight() {
        // Tight budget that can only fit a few tokens
        let budget = TokenBudget::new(50, 10, 5);
        let mut asm = ContextAssembler::new(budget);
        // Add a large optional section
        let big_content: String = (0..200).map(|_| "a").collect();
        let section = ContextSection::new(SectionKind::Custom, "big", big_content)
            .with_priority(ContextPriority::Optional);
        asm.add_section(section);
        let ctx = asm.assemble();
        // The big optional section should be dropped or compressed
        assert!(ctx.dropped_sections.len() > 0 || ctx.sections.iter().any(|s| s.compressed));
    }

    #[test]
    fn test_add_imports() {
        let budget = TokenBudget::new(8192, 1024, 256);
        let mut asm = ContextAssembler::new(budget);
        let imports = vec![
            ("kernel32.dll".to_string(), "VirtualAlloc".to_string()),
            ("ntdll.dll".to_string(), "NtWriteVirtualMemory".to_string()),
        ];
        asm.add_imports(&imports);
        let ctx = asm.assemble();
        assert!(ctx.find_section(SectionKind::Imports).is_some());
    }
}
