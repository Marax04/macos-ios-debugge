//! Analysis context builder for LLM prompts — **data-model layer**.
//!
//! Provides [`AnalysisContext`], [`ContextSerializer`], and [`ContextCompressor`]
//! for assembling rich binary analysis contexts that fit within LLM token budgets.
//!
//! # Distinct from `context_assembler`
//!
//! `context_builder` is the **data-model** layer: it defines strongly-typed
//! structs (`BinaryInfo`, `FunctionEntry`, `XrefEntry`, `ImportEntry`, …),
//! serialises the full context into a text block, and compresses it by
//! iteratively trimming the most expensive sections.
//!
//! `context_assembler` is the **budget-aware assembly** layer: it accepts raw
//! text blobs (`add_disassembly`, `add_strings`, …), wraps them in
//! [`ContextSection`] with [`ContextPriority`] and [`TokenBudget`] tracking,
//! supports diff-ing two assembled contexts, and drops or compresses sections
//! according to priority when the token budget is exceeded.

use std::collections::HashMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

// ─── BinaryInfo ──────────────────────────────────────────────────────────────

/// Summary information about the target binary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BinaryInfo {
    /// File name without path.
    pub file_name: String,
    /// File format (PE, ELF, Mach-O, raw, etc.).
    pub format: String,
    /// CPU architecture (`x86_64`, ARM64, etc.).
    pub architecture: String,
    /// Bitness (32 or 64).
    pub bitness: u8,
    /// SHA-256 hash.
    pub sha256: String,
    /// File size in bytes.
    pub file_size: u64,
    /// Image base address in hex.
    pub image_base: u64,
    /// Compiler/linker hints.
    pub compiler_hint: String,
    /// Packer or protector name if detected.
    pub packer: Option<String>,
}

impl BinaryInfo {
    /// Format as a compact text block.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = format!(
            "Binary: {} | Format: {} | Arch: {} | {}bit | Size: {} bytes\n",
            self.file_name, self.format, self.architecture, self.bitness, self.file_size
        );
        if !self.sha256.is_empty() {
            let _ = writeln!(out, "SHA256: {}", self.sha256);
        }
        let _ = writeln!(out, "ImageBase: {:#018x}", self.image_base);
        if !self.compiler_hint.is_empty() {
            let _ = writeln!(out, "Compiler: {}", self.compiler_hint);
        }
        if let Some(ref p) = self.packer {
            let _ = writeln!(out, "Packer: {p}");
        }
        out
    }
}

// ─── FunctionEntry ───────────────────────────────────────────────────────────

/// A function entry for context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionEntry {
    /// Function start address.
    pub address: u64,
    /// Function name (may be auto-generated).
    pub name: String,
    /// Function size in bytes.
    pub size: u32,
    /// Number of basic blocks.
    pub block_count: u32,
    /// Number of outgoing calls.
    pub call_count: u32,
    /// Whether the function is a library function.
    pub is_library: bool,
    /// Decompiled code snippet (first N lines).
    pub decompiled_snippet: Option<String>,
}

impl FunctionEntry {
    /// Create a minimal function entry.
    #[must_use]
    pub fn new(address: u64, name: impl Into<String>, size: u32) -> Self {
        Self {
            address,
            name: name.into(),
            size,
            block_count: 0,
            call_count: 0,
            is_library: false,
            decompiled_snippet: None,
        }
    }

    /// Format as a single text line.
    #[must_use]
    pub fn to_line(&self) -> String {
        format!(
            "{:#018x} {:40} size={:<6} blocks={:<4} calls={:<4} {}",
            self.address,
            self.name,
            self.size,
            self.block_count,
            self.call_count,
            if self.is_library { "[lib]" } else { "" }
        )
    }
}

// ─── XrefEntry ───────────────────────────────────────────────────────────────

/// A cross-reference entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrefEntry {
    /// Source address.
    pub from_addr: u64,
    /// Target address.
    pub to_addr: u64,
    /// Source function name.
    pub from_name: String,
    /// Target function name.
    pub to_name: String,
    /// Cross-reference type.
    pub xref_type: XrefType,
}

/// Type of cross-reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum XrefType {
    /// Direct call instruction.
    Call,
    /// Jump instruction.
    Jump,
    /// Data reference (read).
    DataRead,
    /// Data reference (write).
    DataWrite,
    /// Offset reference (address taken).
    Offset,
}

impl XrefType {
    #[must_use]
    const fn label(&self) -> &'static str {
        match self {
            Self::Call => "CALL",
            Self::Jump => "JMP",
            Self::DataRead => "R",
            Self::DataWrite => "W",
            Self::Offset => "OFF",
        }
    }
}

// ─── ImportEntry ─────────────────────────────────────────────────────────────

/// An imported function entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    /// DLL or library name.
    pub dll_name: String,
    /// Function name or ordinal string.
    pub function_name: String,
    /// Import address table address.
    pub iat_address: u64,
}

impl ImportEntry {
    /// Format as a single line.
    #[must_use]
    pub fn to_line(&self) -> String {
        format!(
            "{:#018x} {}!{}",
            self.iat_address, self.dll_name, self.function_name
        )
    }
}

// ─── StringEntry ─────────────────────────────────────────────────────────────

/// An extracted string from the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEntry {
    /// File offset.
    pub offset: u64,
    /// The string value.
    pub value: String,
    /// String encoding.
    pub encoding: StringEncoding,
    /// Whether this string is referenced by code.
    pub is_referenced: bool,
}

/// String encoding type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
    Utf16Be,
    Utf8,
}

// ─── AnalysisContext ─────────────────────────────────────────────────────────

/// Full analysis context for an LLM prompt.
///
/// Build with [`AnalysisContextBuilder`] for a fluent API.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisContext {
    /// Binary file information.
    pub binary_info: BinaryInfo,
    /// Function list.
    pub functions: Vec<FunctionEntry>,
    /// Cross-references.
    pub xrefs: Vec<XrefEntry>,
    /// Extracted strings.
    pub strings: Vec<StringEntry>,
    /// Imported functions.
    pub imports: Vec<ImportEntry>,
    /// Free-form analyst notes.
    pub analyst_notes: Vec<String>,
    /// Custom key-value metadata.
    pub metadata: HashMap<String, String>,
}

impl AnalysisContext {
    /// Create an empty context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the number of non-library functions.
    #[must_use]
    pub fn user_function_count(&self) -> usize {
        self.functions.iter().filter(|f| !f.is_library).count()
    }
}

// ─── AnalysisContextBuilder ──────────────────────────────────────────────────

/// Fluent builder for [`AnalysisContext`].
#[derive(Default)]
pub struct AnalysisContextBuilder {
    ctx: AnalysisContext,
}

impl AnalysisContextBuilder {
    /// Create a new empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set binary information.
    #[must_use]
    pub fn binary_info(mut self, info: BinaryInfo) -> Self {
        self.ctx.binary_info = info;
        self
    }

    /// Add a function.
    #[must_use]
    pub fn function(mut self, f: FunctionEntry) -> Self {
        self.ctx.functions.push(f);
        self
    }

    /// Add multiple functions.
    #[must_use]
    pub fn functions(mut self, fns: impl IntoIterator<Item = FunctionEntry>) -> Self {
        self.ctx.functions.extend(fns);
        self
    }

    /// Add a cross-reference.
    #[must_use]
    pub fn xref(mut self, x: XrefEntry) -> Self {
        self.ctx.xrefs.push(x);
        self
    }

    /// Add an import.
    #[must_use]
    pub fn import(mut self, imp: ImportEntry) -> Self {
        self.ctx.imports.push(imp);
        self
    }

    /// Add a string.
    #[must_use]
    pub fn string_entry(mut self, s: StringEntry) -> Self {
        self.ctx.strings.push(s);
        self
    }

    /// Add an analyst note.
    #[must_use]
    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.ctx.analyst_notes.push(note.into());
        self
    }

    /// Add metadata.
    #[must_use]
    pub fn meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.ctx.metadata.insert(key.into(), value.into());
        self
    }

    /// Build the context.
    #[must_use]
    pub fn build(self) -> AnalysisContext {
        self.ctx
    }
}

// ─── ContextSerializer ───────────────────────────────────────────────────────

/// Serializes an [`AnalysisContext`] into compact text representations suitable
/// for inclusion in LLM prompts.
pub struct ContextSerializer {
    /// Maximum number of functions to include.
    pub max_functions: usize,
    /// Maximum number of strings to include.
    pub max_strings: usize,
    /// Maximum number of imports to include.
    pub max_imports: usize,
    /// Maximum number of xrefs to include.
    pub max_xrefs: usize,
    /// Whether to include decompiled snippets.
    pub include_snippets: bool,
}

impl Default for ContextSerializer {
    fn default() -> Self {
        Self {
            max_functions: 50,
            max_strings: 100,
            max_imports: 100,
            max_xrefs: 50,
            include_snippets: true,
        }
    }
}

impl ContextSerializer {
    /// Create a serializer with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Serialize an [`AnalysisContext`] to a compact text string.
    #[must_use]
    pub fn serialize(&self, ctx: &AnalysisContext) -> String {
        let mut out = String::with_capacity(4096);

        // Binary info section
        out.push_str("=== BINARY INFO ===\n");
        out.push_str(&ctx.binary_info.to_text());
        out.push('\n');

        // Functions section
        if !ctx.functions.is_empty() {
            out.push_str("=== FUNCTIONS ===\n");
            let shown = ctx.functions.len().min(self.max_functions);
            for f in ctx.functions.iter().take(shown) {
                out.push_str(&f.to_line());
                out.push('\n');
                if self.include_snippets
                    && let Some(ref snip) = f.decompiled_snippet {
                        out.push_str("  Decompiled:\n");
                        for line in snip.lines().take(5) {
                            let _ = writeln!(out, "    {line}");
                        }
                    }
            }
            if ctx.functions.len() > shown {
                let _ = writeln!(
                    out,
                    "  ... and {} more functions",
                    ctx.functions.len() - shown
                );
            }
            out.push('\n');
        }

        // Imports section
        if !ctx.imports.is_empty() {
            out.push_str("=== IMPORTS ===\n");
            for imp in ctx.imports.iter().take(self.max_imports) {
                out.push_str(&imp.to_line());
                out.push('\n');
            }
            if ctx.imports.len() > self.max_imports {
                let _ = writeln!(
                    out,
                    "  ... and {} more imports",
                    ctx.imports.len() - self.max_imports
                );
            }
            out.push('\n');
        }

        // Strings section
        if !ctx.strings.is_empty() {
            out.push_str("=== STRINGS ===\n");
            for s in ctx.strings.iter().take(self.max_strings) {
                let ref_mark = if s.is_referenced { "[ref]" } else { "" };
                let _ = writeln!(out, "{:#018x} {:<60} {}", s.offset, s.value, ref_mark);
            }
            if ctx.strings.len() > self.max_strings {
                let _ = writeln!(
                    out,
                    "  ... and {} more strings",
                    ctx.strings.len() - self.max_strings
                );
            }
            out.push('\n');
        }

        // XRefs section
        if !ctx.xrefs.is_empty() {
            out.push_str("=== XREFS ===\n");
            for x in ctx.xrefs.iter().take(self.max_xrefs) {
                let _ = writeln!(
                    out,
                    "{:#018x} {} -> {:#018x} {} [{}]",
                    x.from_addr,
                    x.from_name,
                    x.to_addr,
                    x.to_name,
                    x.xref_type.label()
                );
            }
            out.push('\n');
        }

        // Analyst notes
        if !ctx.analyst_notes.is_empty() {
            out.push_str("=== ANALYST NOTES ===\n");
            for note in &ctx.analyst_notes {
                let _ = writeln!(out, "- {note}");
            }
            out.push('\n');
        }

        // Metadata
        if !ctx.metadata.is_empty() {
            out.push_str("=== METADATA ===\n");
            for (k, v) in &ctx.metadata {
                let _ = writeln!(out, "{k}: {v}");
            }
            out.push('\n');
        }

        out
    }

    /// Estimate the token count of a serialized context.
    #[must_use]
    pub fn estimate_tokens(&self, ctx: &AnalysisContext) -> usize {
        self.serialize(ctx).len() / 4
    }
}

// ─── ContextCompressor ───────────────────────────────────────────────────────

/// Trims an [`AnalysisContext`] to fit within a token budget.
pub struct ContextCompressor {
    /// Target token budget.
    pub token_budget: usize,
    /// Characters per token estimate.
    pub chars_per_token: usize,
}

impl Default for ContextCompressor {
    fn default() -> Self {
        Self {
            token_budget: 4000,
            chars_per_token: 4,
        }
    }
}

impl ContextCompressor {
    /// Create a compressor with the given token budget.
    #[must_use]
    pub fn with_budget(token_budget: usize) -> Self {
        Self {
            token_budget,
            ..Self::default()
        }
    }

    /// Compress the context to fit within the token budget.
    /// Returns a trimmed clone of the context and the serialized text.
    #[must_use]
    pub fn compress(&self, ctx: &AnalysisContext) -> (AnalysisContext, String) {
        let budget_chars = self.token_budget * self.chars_per_token;
        let serializer = ContextSerializer::new();

        // Start with full context
        let mut trimmed = ctx.clone();

        // Iteratively reduce until it fits
        loop {
            let text = serializer.serialize(&trimmed);
            if text.len() <= budget_chars {
                return (trimmed, text);
            }

            // Try to trim the most expensive sections first
            if trimmed.strings.len() > 10 {
                let new_len = (trimmed.strings.len() * 3) / 4;
                trimmed.strings.truncate(new_len.max(10));
                continue;
            }
            if trimmed.functions.len() > 10 {
                let new_len = (trimmed.functions.len() * 3) / 4;
                // Remove decompiled snippets first
                for f in &mut trimmed.functions {
                    f.decompiled_snippet = None;
                }
                trimmed.functions.truncate(new_len.max(10));
                continue;
            }
            if trimmed.xrefs.len() > 5 {
                let new_len = (trimmed.xrefs.len() * 3) / 4;
                trimmed.xrefs.truncate(new_len.max(5));
                continue;
            }
            if trimmed.imports.len() > 5 {
                let new_len = (trimmed.imports.len() * 3) / 4;
                trimmed.imports.truncate(new_len.max(5));
                continue;
            }
            // Nothing more to trim
            let text = serializer.serialize(&trimmed);
            return (trimmed, text);
        }
    }

    /// Return the character budget.
    #[must_use]
    pub const fn char_budget(&self) -> usize {
        self.token_budget * self.chars_per_token
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_binary_info() -> BinaryInfo {
        BinaryInfo {
            file_name: "malware.exe".to_owned(),
            format: "PE32+".to_owned(),
            architecture: "x86_64".to_owned(),
            bitness: 64,
            sha256: "abc123".to_owned(),
            file_size: 524_288,
            image_base: 0x0000_0001_4000_0000,
            compiler_hint: "MSVC 19.x".to_owned(),
            packer: Some("UPX".to_owned()),
        }
    }

    fn sample_function(addr: u64, name: &str) -> FunctionEntry {
        FunctionEntry {
            address: addr,
            name: name.to_owned(),
            size: 256,
            block_count: 8,
            call_count: 3,
            is_library: false,
            decompiled_snippet: Some("int foo(void) {\n  return 0;\n}".to_owned()),
        }
    }

    #[test]
    fn test_binary_info_to_text() {
        let info = sample_binary_info();
        let text = info.to_text();
        assert!(text.contains("malware.exe"));
        assert!(text.contains("PE32+"));
        assert!(text.contains("x86_64"));
        assert!(text.contains("UPX"));
    }

    #[test]
    fn test_function_entry_to_line() {
        let f = sample_function(0x0001_4000_1000, "main");
        let line = f.to_line();
        assert!(line.contains("main"));
        assert!(line.contains("0x0000000140001000"));
    }

    #[test]
    fn test_import_entry_to_line() {
        let imp = ImportEntry {
            dll_name: "kernel32.dll".to_owned(),
            function_name: "VirtualAlloc".to_owned(),
            iat_address: 0x0001_4001_0000,
        };
        let line = imp.to_line();
        assert!(line.contains("kernel32.dll"));
        assert!(line.contains("VirtualAlloc"));
    }

    #[test]
    fn test_analysis_context_builder() {
        let ctx = AnalysisContextBuilder::new()
            .binary_info(sample_binary_info())
            .function(sample_function(0x1000, "init"))
            .function(sample_function(0x2000, "main"))
            .import(ImportEntry {
                dll_name: "ntdll.dll".to_owned(),
                function_name: "NtCreateFile".to_owned(),
                iat_address: 0x5000,
            })
            .note("Suspicious packed binary")
            .meta("analyst", "Alice")
            .build();

        assert_eq!(ctx.functions.len(), 2);
        assert_eq!(ctx.imports.len(), 1);
        assert_eq!(ctx.analyst_notes.len(), 1);
        assert_eq!(ctx.metadata["analyst"], "Alice");
    }

    #[test]
    fn test_context_serializer_output() {
        let ctx = AnalysisContextBuilder::new()
            .binary_info(sample_binary_info())
            .function(sample_function(0x1000, "start"))
            .build();
        let ser = ContextSerializer::new();
        let text = ser.serialize(&ctx);
        assert!(text.contains("BINARY INFO"));
        assert!(text.contains("FUNCTIONS"));
        assert!(text.contains("malware.exe"));
        assert!(text.contains("start"));
    }

    #[test]
    fn test_context_serializer_max_functions() {
        let mut builder = AnalysisContextBuilder::new().binary_info(sample_binary_info());
        for i in 0..100u64 {
            builder = builder.function(sample_function(0x1000 + i * 0x100, &format!("fn_{i}")));
        }
        let ctx = builder.build();
        let mut ser = ContextSerializer::new();
        ser.max_functions = 10;
        let text = ser.serialize(&ctx);
        assert!(text.contains("90 more functions"));
    }

    #[test]
    fn test_estimate_tokens() {
        let ctx = AnalysisContextBuilder::new()
            .binary_info(sample_binary_info())
            .build();
        let ser = ContextSerializer::new();
        let tokens = ser.estimate_tokens(&ctx);
        assert!(tokens > 0);
    }

    #[test]
    fn test_context_compressor_fits_budget() {
        let mut builder = AnalysisContextBuilder::new().binary_info(sample_binary_info());
        for i in 0..200u64 {
            builder = builder.string_entry(StringEntry {
                offset: i * 8,
                value: format!("very_long_string_value_that_takes_up_space_{i}"),
                encoding: StringEncoding::Ascii,
                is_referenced: false,
            });
        }
        let ctx = builder.build();
        let compressor = ContextCompressor::with_budget(500);
        let (_, text) = compressor.compress(&ctx);
        assert!(text.len() <= compressor.char_budget() * 2); // allow some slack
    }

    #[test]
    fn test_user_function_count() {
        let f1 = sample_function(0x1000, "user_fn");
        let mut f2 = sample_function(0x2000, "lib_fn");
        f2.is_library = true;
        let ctx = AnalysisContextBuilder::new()
            .binary_info(sample_binary_info())
            .function(f1)
            .function(f2)
            .build();
        assert_eq!(ctx.user_function_count(), 1);
    }

    #[test]
    fn test_context_with_xrefs() {
        let xref = XrefEntry {
            from_addr: 0x1000,
            to_addr: 0x2000,
            from_name: "caller".to_owned(),
            to_name: "callee".to_owned(),
            xref_type: XrefType::Call,
        };
        let ctx = AnalysisContextBuilder::new()
            .binary_info(sample_binary_info())
            .xref(xref)
            .build();
        let ser = ContextSerializer::new();
        let text = ser.serialize(&ctx);
        assert!(text.contains("XREFS"));
        assert!(text.contains("caller"));
        assert!(text.contains("CALL"));
    }

    #[test]
    fn test_context_with_strings() {
        let s = StringEntry {
            offset: 0x5000,
            value: "http://c2.evil.example.com".to_owned(),
            encoding: StringEncoding::Ascii,
            is_referenced: true,
        };
        let ctx = AnalysisContextBuilder::new()
            .binary_info(sample_binary_info())
            .string_entry(s)
            .build();
        let ser = ContextSerializer::new();
        let text = ser.serialize(&ctx);
        assert!(text.contains("http://c2.evil.example.com"));
        assert!(text.contains("[ref]"));
    }

    #[test]
    fn test_context_metadata_in_output() {
        let ctx = AnalysisContextBuilder::new()
            .binary_info(sample_binary_info())
            .meta("campaign", "operation_lazarus")
            .build();
        let ser = ContextSerializer::new();
        let text = ser.serialize(&ctx);
        assert!(text.contains("campaign"));
        assert!(text.contains("operation_lazarus"));
    }

    #[test]
    fn test_analyst_notes_in_output() {
        let ctx = AnalysisContextBuilder::new()
            .binary_info(sample_binary_info())
            .note("Uses DGA for C2 rotation")
            .build();
        let ser = ContextSerializer::new();
        let text = ser.serialize(&ctx);
        assert!(text.contains("ANALYST NOTES"));
        assert!(text.contains("DGA"));
    }

    #[test]
    fn test_compressor_default_budget() {
        let c = ContextCompressor::default();
        assert_eq!(c.token_budget, 4000);
        assert_eq!(c.char_budget(), 16000);
    }

    #[test]
    fn test_string_encoding_variants() {
        let encodings = [
            StringEncoding::Ascii,
            StringEncoding::Utf16Le,
            StringEncoding::Utf16Be,
            StringEncoding::Utf8,
        ];
        assert_eq!(encodings.len(), 4);
    }

    #[test]
    fn test_xref_type_labels() {
        assert_eq!(XrefType::Call.label(), "CALL");
        assert_eq!(XrefType::Jump.label(), "JMP");
        assert_eq!(XrefType::DataRead.label(), "R");
        assert_eq!(XrefType::DataWrite.label(), "W");
        assert_eq!(XrefType::Offset.label(), "OFF");
    }

    #[test]
    fn test_packer_none_not_in_output() {
        let mut info = sample_binary_info();
        info.packer = None;
        let text = info.to_text();
        assert!(!text.contains("Packer:"));
    }
}
