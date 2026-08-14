//! Full pseudocode generator for `rustre-decompiler`.
//!
//! # Overview
//!
//! [`PseudocodeGenerator`] is the final stage of the decompilation pipeline.
//! It consumes a structured AST (a list of [`PseudoStmt`] nodes) and emits a
//! human-readable C-like listing.
//!
//! ## Pseudo-AST
//!
//! [`PseudoStmt`] is a superset of C statement forms:
//!
//! | Variant        | Emitted as                     |
//! |---------------|-------------------------------|
//! | `Assign`       | `lhs = rhs;`                  |
//! | `VarDecl`      | `type name;` or `= init;`     |
//! | `Return`       | `return expr;`                |
//! | `If`           | `if (cond) { … } else { … }` |
//! | `While`        | `while (cond) { … }`          |
//! | `DoWhile`      | `do { … } while (cond);`     |
//! | `For`          | `for (…;…;…) { … }`          |
//! | `Switch`       | `switch (val) { case …: }`   |
//! | `Break`        | `break;`                      |
//! | `Continue`     | `continue;`                   |
//! | `Goto`         | `goto label;`                 |
//! | `Label`        | `label:`                      |
//! | `Expr`         | `expr;`                       |
//! | `Comment`      | `/* … */`                     |
//! | `Nop`          | (omitted)                     |
//!
//! ## Configuration
//!
//! [`CodeStyle`] controls formatting:
//!
//! * `indent` — per-level indentation string.
//! * `brace_same_line` — `if (c) {` vs `if (c)\n{`.
//! * `rust_types` — emit `u32`/`i64` rather than `uint32_t`/`int64_t`.
//! * `max_columns` — soft column limit (0 = unlimited).
//! * `blank_lines` — insert blank lines after block statements.
//!
//! ## Symbol Resolution
//!
//! [`SymbolResolver`] maps numeric variable ids to human-readable names.
//! Unknown ids fall back to `v{id}`.
//!
//! ## Post-Processing
//!
//! [`PseudocodeFormatter`] provides utilities for trimming trailing whitespace
//! and collapsing consecutive blank lines in the generated output.
//!
//! [`PseudocodeStats`] accumulates metrics across multiple decompilation runs.
//!
//! [`PseudocodeGenerator`] is the final stage of the decompilation pipeline.
//! It accepts a structured AST (sequences of [`PseudoStmt`]s) and emits a
//! human-readable, C-like text representation.
//!
//! Sub-components:
//! * [`CodeStyle`] — style parameters (braces, pointer notation, …).
//! * [`IndentManager`] — tracks and emits indentation.
//! * [`TypeAnnotation`] — carries type information for variables.
//! * [`SymbolResolver`] — maps raw variable ids to human names.
//! * [`CommentInserter`] — attaches address / analysis comments.

use std::collections::HashMap;
use std::fmt::{self, Write as _};

// ---------------------------------------------------------------------------
// Well-known output constants
// ---------------------------------------------------------------------------

/// Default indentation string (four spaces).
pub const DEFAULT_INDENT: &str = "    ";

/// Two-space indentation alternative.
pub const TWO_SPACE_INDENT: &str = "  ";

/// Maximum supported nesting depth.
pub const MAX_NESTING_DEPTH: usize = 64;

/// Null pointer expression.
pub const NULL_EXPR: &str = "NULL";

/// C preprocessor guard pattern.
pub const INCLUDE_GUARD: &str = "#pragma once";

/// Opening brace for Allman style (on its own line).
pub const ALLMAN_OPEN: &str = "\n{";

/// Opening brace for K&R style (same line).
pub const KR_OPEN: &str = " {";

/// Closing brace string.
pub const CLOSE_BRACE: &str = "}";

/// Semicolon suffix.
pub const SEMI: &str = ";";

// ---------------------------------------------------------------------------
// TypeWidth — bit-width utilities for C types
// ---------------------------------------------------------------------------

/// Bit width for common C integer types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TypeWidth {
    W8 = 8,
    W16 = 16,
    W32 = 32,
    W64 = 64,
    W128 = 128,
}

impl TypeWidth {
    /// Byte width.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self as usize / 8
    }

    /// C type string for unsigned variants.
    #[must_use]
    pub const fn c_unsigned(self) -> &'static str {
        match self {
            Self::W8 => "uint8_t",
            Self::W16 => "uint16_t",
            Self::W32 => "uint32_t",
            Self::W64 => "uint64_t",
            Self::W128 => "__uint128_t",
        }
    }

    /// C type string for signed variants.
    #[must_use]
    pub const fn c_signed(self) -> &'static str {
        match self {
            Self::W8 => "int8_t",
            Self::W16 => "int16_t",
            Self::W32 => "int32_t",
            Self::W64 => "int64_t",
            Self::W128 => "__int128_t",
        }
    }
}

/// Tab character.
pub const TAB_INDENT: &str = "\t";

/// Maximum recommended line length.
pub const RECOMMENDED_MAX_LINE: usize = 100;

// ---------------------------------------------------------------------------
// C keyword set — used by VariableNameSanitizer
// ---------------------------------------------------------------------------

/// Set of C keywords that must not be used as variable names.
pub const C_KEYWORDS: &[&str] = &[
    "auto",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "register",
    "restrict",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
    // C11 additions
    "_Alignas",
    "_Alignof",
    "_Atomic",
    "_Bool",
    "_Complex",
    "_Generic",
    "_Imaginary",
    "_Noreturn",
    "_Static_assert",
    "_Thread_local",
];

/// Returns `true` if `name` is a C keyword.
#[must_use]
pub fn is_c_keyword(name: &str) -> bool {
    C_KEYWORDS.contains(&name)
}

// ---------------------------------------------------------------------------
// StatementBuilder — convenience builder for PseudoStmt trees
// ---------------------------------------------------------------------------

/// Fluent builder for constructing [`PseudoStmt`] trees in tests or transforms.
#[derive(Debug, Default)]
pub struct StatementBuilder {
    stmts: Vec<PseudoStmt>,
}

impl StatementBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn assign(mut self, dest: &str, src: &str) -> Self {
        self.stmts.push(PseudoStmt::Assign {
            dest: dest.into(),
            src: src.into(),
        });
        self
    }

    #[must_use]
    pub fn ret(mut self) -> Self {
        self.stmts.push(PseudoStmt::Return(None));
        self
    }

    #[must_use]
    pub fn ret_expr(mut self, expr: &str) -> Self {
        self.stmts.push(PseudoStmt::Return(Some(expr.into())));
        self
    }

    #[must_use]
    pub fn if_stmt(mut self, cond: &str, then_body: Vec<PseudoStmt>) -> Self {
        self.stmts.push(PseudoStmt::If {
            cond: cond.into(),
            then_body,
            else_body: None,
        });
        self
    }

    #[must_use]
    pub fn while_stmt(mut self, cond: &str, body: Vec<PseudoStmt>) -> Self {
        self.stmts.push(PseudoStmt::While {
            cond: cond.into(),
            body,
        });
        self
    }

    #[must_use]
    pub fn build(self) -> Vec<PseudoStmt> {
        self.stmts
    }
}

// ---------------------------------------------------------------------------
// EmitContext — tracks the full state of an emission
// ---------------------------------------------------------------------------

/// Tracks the full state of a code-emission run, combining
/// [`IndentManager`], a symbol table, and comment metadata.
#[derive(Debug)]
pub struct EmitContext {
    pub indent: IndentManager,
    pub symbols: SymbolResolver,
    pub comments: CommentInserter,
    pub style: CodeStyle,
}

impl EmitContext {
    /// Create a fresh context with default style.
    #[must_use]
    pub fn new() -> Self {
        let style = CodeStyle::default();
        let unit = style.indent.clone();
        Self {
            indent: IndentManager::new(unit),
            symbols: SymbolResolver::default(),
            comments: CommentInserter::default(),
            style,
        }
    }

    /// Create with a custom style.
    #[must_use]
    pub fn with_style(style: CodeStyle) -> Self {
        let unit = style.indent.clone();
        Self {
            indent: IndentManager::new(unit),
            symbols: SymbolResolver::default(),
            comments: CommentInserter::default(),
            style,
        }
    }

    /// Current indentation prefix.
    #[must_use]
    pub fn prefix(&self) -> String {
        self.indent.prefix()
    }
}

impl Default for EmitContext {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PseudocodeConfig — unified alias
// ---------------------------------------------------------------------------

/// Alias for [`CodeStyle`] used in public API contexts.
pub type PseudocodeConfig = CodeStyle;

// ---------------------------------------------------------------------------
// BlockBodyEmitter — emits the body of a block-structured statement
// ---------------------------------------------------------------------------

/// Helper that emits a block body (open brace, indented stmts, close brace).
#[derive(Debug)]
pub struct BlockBodyEmitter<'a> {
    r#gen: &'a mut PseudocodeGenerator,
}

impl<'a> BlockBodyEmitter<'a> {
    /// Create an emitter.
    pub const fn new(r#gen: &'a mut PseudocodeGenerator) -> Self {
        Self { r#gen }
    }

    /// Emit `stmts` in a braced block.
    pub fn emit(&mut self, stmts: &[PseudoStmt]) {
        self.r#gen.indent.push();
        for stmt in stmts {
            self.r#gen.emit_stmt(stmt);
        }
        self.r#gen.indent.pop();
    }
}

// ---------------------------------------------------------------------------
// IndentString — wraps a configurable indentation unit
// ---------------------------------------------------------------------------

/// A helper that builds indented lines.
#[derive(Debug, Clone)]
pub struct IndentString {
    unit: String,
    depth: usize,
}

impl IndentString {
    #[must_use]
    pub fn new(unit: impl Into<String>, depth: usize) -> Self {
        Self {
            unit: unit.into(),
            depth,
        }
    }

    #[must_use]
    pub fn prefix(&self) -> String {
        self.unit.repeat(self.depth)
    }

    pub const fn increase(&mut self) {
        self.depth += 1;
    }
    pub const fn decrease(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    #[must_use]
    pub fn with_line(&self, text: &str) -> String {
        format!("{}{text}", self.prefix())
    }
}

// ---------------------------------------------------------------------------
// CodeStyle
// ---------------------------------------------------------------------------

/// Type-name formatting options for the pseudocode emitter.
#[derive(Debug, Clone, Default)]
pub struct CodeStyleTyping {
    /// Emit `u32`, `i64`-style type names.
    pub rust_types: bool,
    /// Emit `nullptr` rather than `NULL` / `0`.
    pub cpp_nullptr: bool,
}

/// Style configuration for the pseudocode emitter.
#[derive(Debug, Clone)]
pub struct CodeStyle {
    /// Indentation string (default `"    "`).
    pub indent: String,
    /// Place opening brace on the same line as `if`/`while`.
    pub brace_same_line: bool,
    /// Type-name formatting options.
    pub typing: CodeStyleTyping,
    /// Maximum output columns (0 = no limit).
    pub max_columns: usize,
    /// Insert a blank line after each top-level statement.
    pub blank_lines: bool,
}

impl Default for CodeStyle {
    fn default() -> Self {
        Self {
            indent: "    ".into(),
            brace_same_line: true,
            typing: CodeStyleTyping::default(),
            max_columns: 0,
            blank_lines: false,
        }
    }
}

// ---------------------------------------------------------------------------
// IndentManager
// ---------------------------------------------------------------------------

/// Tracks the current indentation depth.
#[derive(Debug, Clone)]
pub struct IndentManager {
    depth: usize,
    unit: String,
}

impl IndentManager {
    /// Create an [`IndentManager`] using `unit` per level.
    #[must_use]
    pub fn new(unit: impl Into<String>) -> Self {
        Self {
            depth: 0,
            unit: unit.into(),
        }
    }

    /// Increase depth by one.
    pub const fn push(&mut self) {
        self.depth += 1;
    }

    /// Decrease depth (saturating).
    pub const fn pop(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Current depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.depth
    }

    /// Current indentation prefix.
    #[must_use]
    pub fn prefix(&self) -> String {
        self.unit.repeat(self.depth)
    }
}

// ---------------------------------------------------------------------------
// TypeAnnotation
// ---------------------------------------------------------------------------

/// Type annotation for a variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeAnnotation {
    pub var_name: String,
    pub type_str: String,
    pub is_pointer: bool,
    pub is_const: bool,
}

impl TypeAnnotation {
    #[must_use]
    pub fn new(var_name: impl Into<String>, type_str: impl Into<String>) -> Self {
        Self {
            var_name: var_name.into(),
            type_str: type_str.into(),
            is_pointer: false,
            is_const: false,
        }
    }

    #[must_use]
    pub fn pointer(var_name: impl Into<String>, pointee: impl Into<String>) -> Self {
        Self {
            is_pointer: true,
            ..Self::new(var_name, format!("{} *", pointee.into()))
        }
    }

    /// C-style declaration string: `"uint32_t x"`.
    #[must_use]
    pub fn decl(&self) -> String {
        let prefix = if self.is_const { "const " } else { "" };
        format!("{prefix}{} {}", self.type_str, self.var_name)
    }
}

// ---------------------------------------------------------------------------
// SymbolResolver
// ---------------------------------------------------------------------------

/// Maps raw variable ids (usize) to human-readable names.
#[derive(Debug, Clone, Default)]
pub struct SymbolResolver {
    map: HashMap<usize, String>,
    next_auto: usize,
}

impl SymbolResolver {
    /// Register `name` for `id`.
    pub fn register(&mut self, id: usize, name: impl Into<String>) {
        self.map.insert(id, name.into());
    }

    /// Resolve `id` → name, generating `"v{id}"` if unknown.
    #[must_use]
    pub fn resolve(&self, id: usize) -> String {
        self.map
            .get(&id)
            .cloned()
            .unwrap_or_else(|| format!("v{id}"))
    }

    /// Generate a fresh unique name.
    pub fn fresh(&mut self) -> String {
        let n = self.next_auto;
        self.next_auto += 1;
        format!("tmp_{n}")
    }
}

// ---------------------------------------------------------------------------
// CommentInserter
// ---------------------------------------------------------------------------

/// Inserts analysis-derived or address-based comments at specific points.
#[derive(Debug, Clone, Default)]
pub struct CommentInserter {
    /// Maps source address → comment string.
    address_comments: HashMap<u64, String>,
    /// Ordered comment list (address, comment) for sequential emission.
    inline: Vec<(u64, String)>,
}

impl CommentInserter {
    /// Register a comment for address `addr`.
    pub fn add(&mut self, addr: u64, comment: impl Into<String>) {
        self.address_comments.insert(addr, comment.into());
        self.inline
            .push((addr, self.address_comments[&addr].clone()));
    }

    /// Retrieve the comment for `addr`, if any.
    #[must_use]
    pub fn get(&self, addr: u64) -> Option<&str> {
        self.address_comments.get(&addr).map(String::as_str)
    }

    /// Format a comment line `"/* … */"`.
    #[must_use]
    pub fn format(comment: &str) -> String {
        format!("/* {comment} */")
    }
}

// ---------------------------------------------------------------------------
// Pseudo-AST
// ---------------------------------------------------------------------------

/// A literal pseudocode expression string.
pub type Expr = String;

/// A pseudocode statement.
#[derive(Debug, Clone)]
pub enum PseudoStmt {
    /// `<dest> = <src>;`
    Assign { dest: Expr, src: Expr },
    /// `<type> <name>;` or `<type> <name> = <init>;`
    VarDecl {
        ty: String,
        name: String,
        init: Option<Expr>,
    },
    /// `return <expr>;` or `return;`
    Return(Option<Expr>),
    /// `if (<cond>) { … } else { … }`
    If {
        cond: Expr,
        then_body: Vec<Self>,
        else_body: Option<Vec<Self>>,
    },
    /// `while (<cond>) { … }`
    While { cond: Expr, body: Vec<Self> },
    /// `do { … } while (<cond>);`
    DoWhile { body: Vec<Self>, cond: Expr },
    /// `for (<init>; <cond>; <step>) { … }`
    For {
        init: Option<Expr>,
        cond: Option<Expr>,
        step: Option<Expr>,
        body: Vec<Self>,
    },
    /// `switch (<value>) { case <k>: <stmts>… }`
    Switch {
        value: Expr,
        cases: Vec<(i64, Vec<Self>)>,
        default: Option<Vec<Self>>,
    },
    /// `break;`
    Break,
    /// `continue;`
    Continue,
    /// `goto <label>;`
    Goto(String),
    /// `<label>:`
    Label(String),
    /// Bare expression statement `<expr>;`
    Expr(Expr),
    /// A `/* comment */` line.
    Comment(String),
    /// No-op.
    Nop,
}

/// Whether a statement sequence already ends in a control-flow terminator,
/// so no synthetic `break;` should be appended after it in a `switch` case.
fn ends_in_terminator(body: &[PseudoStmt]) -> bool {
    matches!(
        body.last(),
        Some(PseudoStmt::Return(_) | PseudoStmt::Goto(_) | PseudoStmt::Break | PseudoStmt::Continue)
    )
}

// ---------------------------------------------------------------------------
// PseudocodeOutput
// ---------------------------------------------------------------------------

/// The fully-generated pseudocode string and metadata.
#[derive(Debug, Clone)]
pub struct PseudocodeOutput {
    pub code: String,
    pub line_count: usize,
    pub stmt_count: usize,
    pub warnings: Vec<String>,
}

impl fmt::Display for PseudocodeOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.code)
    }
}

// ---------------------------------------------------------------------------
// PseudocodeGenerator
// ---------------------------------------------------------------------------

/// Emits a complete pseudocode listing from a function body ([`PseudoStmt`] slice).
#[derive(Debug)]
pub struct PseudocodeGenerator {
    pub style: CodeStyle,
    pub symbols: SymbolResolver,
    pub comments: CommentInserter,
    indent: IndentManager,
    output: String,
    line_count: usize,
    stmt_count: usize,
    warnings: Vec<String>,
}

impl PseudocodeGenerator {
    /// Construct a generator with the given style.
    #[must_use]
    pub fn new(style: CodeStyle) -> Self {
        let unit = style.indent.clone();
        Self {
            style,
            symbols: SymbolResolver::default(),
            comments: CommentInserter::default(),
            indent: IndentManager::new(unit),
            output: String::new(),
            line_count: 0,
            stmt_count: 0,
            warnings: Vec::new(),
        }
    }

    /// Emit a function with `signature` and `body` statements.
    pub fn emit_function(
        &mut self,
        signature: &str,
        locals: &[TypeAnnotation],
        body: &[PseudoStmt],
    ) -> PseudocodeOutput {
        self.output.clear();
        self.line_count = 0;
        self.stmt_count = 0;
        self.warnings.clear();

        // Signature + opening brace.
        if self.style.brace_same_line {
            self.emit_line(&format!("{signature} {{"));
        } else {
            self.emit_line(signature);
            self.emit_line("{");
        }
        self.indent.push();

        // Local variable declarations.
        for ann in locals {
            self.emit_line(&format!("{};", ann.decl()));
        }
        // Separating the declaration block from the body is structural (IDA
        // always does it), not a stylistic blank-line preference.
        if !locals.is_empty() {
            self.emit_blank();
        }

        // Body statements.
        self.emit_stmts(body);

        self.indent.pop();
        self.emit_line("}");

        PseudocodeOutput {
            code: std::mem::take(&mut self.output),
            line_count: self.line_count,
            stmt_count: self.stmt_count,
            warnings: std::mem::take(&mut self.warnings),
        }
    }

    // -- internal helpers --

    fn emit_line(&mut self, text: &str) {
        let _ = writeln!(self.output, "{}{text}", self.indent.prefix());
        self.line_count += 1;
    }

    fn emit_blank(&mut self) {
        let _ = writeln!(self.output);
        self.line_count += 1;
    }

    /// Emit a separating blank line after a block, but only at function-body
    /// level — nested blocks would otherwise shred bodies with gaps before
    /// their parent's closing brace.
    fn maybe_blank(&mut self) {
        if self.style.blank_lines && self.indent.depth() == 1 {
            self.emit_blank();
        }
    }

    fn emit_stmts(&mut self, stmts: &[PseudoStmt]) {
        for stmt in stmts {
            self.emit_stmt(stmt);
        }
    }

    fn emit_if(&mut self, cond: &str, then_body: &[PseudoStmt], else_body: Option<&[PseudoStmt]>) {
        let open = if self.style.brace_same_line { format!("if ({cond}) {{") } else { format!("if ({cond})") };
        self.emit_line(&open);
        if !self.style.brace_same_line { self.emit_line("{"); }
        self.indent.push();
        self.emit_stmts(then_body);
        self.indent.pop();
        if let Some(else_stmts) = else_body {
            if self.style.brace_same_line {
                self.emit_line("} else {");
            } else {
                self.emit_line("}");
                self.emit_line("else");
                self.emit_line("{");
            }
            self.indent.push();
            self.emit_stmts(else_stmts);
            self.indent.pop();
        }
        self.emit_line("}");
        self.maybe_blank();
    }

    fn emit_while(&mut self, cond: &str, body: &[PseudoStmt]) {
        let open = if self.style.brace_same_line { format!("while ({cond}) {{") } else { format!("while ({cond})") };
        self.emit_line(&open);
        if !self.style.brace_same_line { self.emit_line("{"); }
        self.indent.push();
        self.emit_stmts(body);
        self.indent.pop();
        self.emit_line("}");
        self.maybe_blank();
    }

    fn emit_for(&mut self, init: Option<&str>, cond: Option<&str>, step: Option<&str>, body: &[PseudoStmt]) {
        let i = init.unwrap_or("");
        let c = cond.unwrap_or("");
        let s = step.unwrap_or("");
        let header = if i.is_empty() && c.is_empty() && s.is_empty() {
            "for (;;)".to_string()
        } else {
            format!("for ({i}; {c}; {s})")
        };
        let open = if self.style.brace_same_line { format!("{header} {{") } else { header };
        self.emit_line(&open);
        if !self.style.brace_same_line { self.emit_line("{"); }
        self.indent.push();
        self.emit_stmts(body);
        self.indent.pop();
        self.emit_line("}");
        self.maybe_blank();
    }

    fn emit_switch(&mut self, value: &str, cases: &[(i64, Vec<PseudoStmt>)], default: Option<&[PseudoStmt]>) {
        let open = if self.style.brace_same_line { format!("switch ({value}) {{") } else { format!("switch ({value})") };
        self.emit_line(&open);
        if !self.style.brace_same_line { self.emit_line("{"); }
        // Cases sit one level in from `switch`, bodies one level deeper again,
        // matching IDA / clang-format rather than a flat jump-table listing.
        self.indent.push();
        for (k, body) in cases {
            self.emit_line(&format!("case {k}:"));
            self.indent.push();
            self.emit_stmts(body);
            // Only add a synthetic break when the body does not already end in
            // its own terminator — a dead `break;` after `return`/`goto` is a
            // machine-generated tell no hand-written C has.
            if !ends_in_terminator(body) {
                self.emit_line("break;");
            }
            self.indent.pop();
        }
        if let Some(def) = default {
            self.emit_line("default:");
            self.indent.push();
            self.emit_stmts(def);
            self.indent.pop();
        }
        self.indent.pop();
        self.emit_line("}");
        self.maybe_blank();
    }

    fn emit_stmt(&mut self, stmt: &PseudoStmt) {
        self.stmt_count += 1;
        match stmt {
            PseudoStmt::Nop => {
                self.stmt_count -= 1;
            }

            PseudoStmt::Comment(c) => {
                self.emit_line(&CommentInserter::format(c));
            }

            PseudoStmt::Assign { dest, src } => {
                self.emit_line(&format!("{dest} = {src};"));
            }

            PseudoStmt::VarDecl { ty, name, init } => {
                if let Some(val) = init {
                    self.emit_line(&format!("{ty} {name} = {val};"));
                } else {
                    self.emit_line(&format!("{ty} {name};"));
                }
            }

            PseudoStmt::Return(expr) => {
                if let Some(e) = expr {
                    self.emit_line(&format!("return {e};"));
                } else {
                    self.emit_line("return;");
                }
            }

            PseudoStmt::Expr(e) => {
                self.emit_line(&format!("{e};"));
            }

            PseudoStmt::If { cond, then_body, else_body } => {
                self.emit_if(cond, then_body, else_body.as_deref());
            }
            PseudoStmt::While { cond, body } => {
                self.emit_while(cond, body);
            }
            PseudoStmt::DoWhile { body, cond } => {
                if self.style.brace_same_line {
                    self.emit_line("do {");
                } else {
                    self.emit_line("do");
                    self.emit_line("{");
                }
                self.indent.push();
                self.emit_stmts(body);
                self.indent.pop();
                self.emit_line(&format!("}} while ({cond});"));
                self.maybe_blank();
            }
            PseudoStmt::For { init, cond, step, body } => {
                self.emit_for(init.as_deref(), cond.as_deref(), step.as_deref(), body);
            }
            PseudoStmt::Switch { value, cases, default } => {
                self.emit_switch(value, cases, default.as_deref());
            }
            PseudoStmt::Break => self.emit_line("break;"),
            PseudoStmt::Continue => self.emit_line("continue;"),
            PseudoStmt::Goto(l) => self.emit_line(&format!("goto {l};")),
            PseudoStmt::Label(l) => {
                // Labels are emitted one level out from the surrounding
                // statements (IDA convention) instead of snapping to column 0
                // like a disassembly listing.
                self.indent.pop();
                self.emit_line(&format!("{l}:"));
                self.indent.push();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PseudocodeFormatter — post-process output text
// ---------------------------------------------------------------------------

/// Post-processes generated pseudocode (strip trailing whitespace, normalise
/// blank lines, adjust line endings).
#[derive(Debug, Default)]
pub struct PseudocodeFormatter;

impl PseudocodeFormatter {
    /// Strip trailing whitespace from every line.
    #[must_use]
    pub fn strip_trailing_whitespace(code: &str) -> String {
        code.lines()
            .map(str::trim_end)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }

    /// Collapse consecutive blank lines into a single blank line.
    #[must_use]
    pub fn collapse_blank_lines(code: &str) -> String {
        let mut result = String::new();
        let mut last_blank = false;
        for line in code.lines() {
            if line.trim().is_empty() {
                if !last_blank {
                    result.push('\n');
                }
                last_blank = true;
            } else {
                result.push_str(line);
                result.push('\n');
                last_blank = false;
            }
        }
        result
    }

    /// Count non-blank, non-comment lines in `code`.
    #[must_use]
    pub fn count_code_lines(code: &str) -> usize {
        code.lines()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with("/*") && !t.starts_with("//")
            })
            .count()
    }
}

// ---------------------------------------------------------------------------
// VariableNameSanitizer
// ---------------------------------------------------------------------------

/// Sanitizes generated variable names to be valid C identifiers.
#[derive(Debug, Default)]
pub struct VariableNameSanitizer;

impl VariableNameSanitizer {
    /// Ensure `name` is a valid C identifier; replace invalid chars with `_`.
    #[must_use]
    pub fn sanitize(name: &str) -> String {
        if name.is_empty() {
            return "_".into();
        }
        let mut s = String::with_capacity(name.len());
        for (i, c) in name.chars().enumerate() {
            if c.is_ascii_alphabetic() || c == '_' || (i > 0 && c.is_ascii_digit()) {
                s.push(c);
            } else {
                s.push('_');
            }
        }
        // Avoid C reserved words.
        if matches!(
            s.as_str(),
            "int" | "for" | "while" | "if" | "return" | "void" | "switch"
        ) {
            s.push('_');
        }
        s
    }
}

// ---------------------------------------------------------------------------
// PseudocodeStats — metrics from the generator
// ---------------------------------------------------------------------------

/// Aggregate metrics collected from one or more decompilation runs.
#[derive(Debug, Clone, Default)]
pub struct PseudocodeStats {
    pub total_functions: usize,
    pub total_lines: usize,
    pub total_stmts: usize,
    pub functions_warnings: usize,
}

impl PseudocodeStats {
    /// Accumulate stats from a single [`PseudocodeOutput`].
    pub const fn add(&mut self, out: &PseudocodeOutput) {
        self.total_functions += 1;
        self.total_lines += out.line_count;
        self.total_stmts += out.stmt_count;
        if !out.warnings.is_empty() {
            self.functions_warnings += 1;
        }
    }

    /// Average lines per function.
    #[must_use]
    pub fn avg_lines(&self) -> f64 {
        if self.total_functions == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.total_lines).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.total_functions).unwrap_or(u32::MAX))
        }
    }
}

// ---------------------------------------------------------------------------
// CStyleGuard — validates that generated code follows basic C style rules
// ---------------------------------------------------------------------------

/// Validates a generated code string for basic C style compliance.
#[derive(Debug, Default)]
pub struct CStyleGuard;

/// Issues found by [`CStyleGuard`].
#[derive(Debug, Clone)]
pub struct StyleIssue {
    pub line: usize,
    pub description: String,
}

impl CStyleGuard {
    /// Check `code` for common issues.
    #[must_use] 
    pub fn check(code: &str) -> Vec<StyleIssue> {
        let mut issues = Vec::new();
        for (i, line) in code.lines().enumerate() {
            if line.len() > 200 {
                issues.push(StyleIssue {
                    line: i + 1,
                    description: "line too long".into(),
                });
            }
            if line.contains('\t') {
                issues.push(StyleIssue {
                    line: i + 1,
                    description: "tab character in output".into(),
                });
            }
        }
        issues
    }

    /// True if `code` passes all style checks.
    #[must_use]
    pub fn is_valid(code: &str) -> bool {
        Self::check(code).is_empty()
    }
}

// ---------------------------------------------------------------------------
// SignatureBuilder — builds C function signatures
// ---------------------------------------------------------------------------

/// Builds a C function signature string from components.
#[derive(Debug, Default)]
pub struct SignatureBuilder {
    pub return_type: String,
    pub name: String,
    pub params: Vec<(String, String)>, // (type, name)
}

impl SignatureBuilder {
    /// Create a builder for a void function.
    #[must_use]
    pub fn void(name: impl Into<String>) -> Self {
        Self {
            return_type: "void".into(),
            name: name.into(),
            params: Vec::new(),
        }
    }

    /// Set return type.
    #[must_use]
    pub fn returns(mut self, ty: impl Into<String>) -> Self {
        self.return_type = ty.into();
        self
    }

    /// Add a parameter.
    #[must_use]
    pub fn param(mut self, ty: impl Into<String>, name: impl Into<String>) -> Self {
        self.params.push((ty.into(), name.into()));
        self
    }

    /// Build the signature string.
    #[must_use]
    pub fn build(&self) -> String {
        if self.params.is_empty() {
            format!("{} {}(void)", self.return_type, self.name)
        } else {
            let params = self.params
                .iter()
                .map(|(t, n)| format!("{t} {n}"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{} {}({params})", self.return_type, self.name)
        }
    }
}

// ---------------------------------------------------------------------------
// ExpressionFormatter — formats expressions to C-style strings
// ---------------------------------------------------------------------------

/// Formats a [`PseudoStmt`] expression-like structure to a C string with
/// configurable precedence and parenthesisation.
#[derive(Debug, Default)]
pub struct ExpressionFormatter {
    /// Whether to add extra parentheses around every binary operation.
    pub paranoid_parens: bool,
}

impl ExpressionFormatter {
    /// Format a raw expression string, optionally adding parens.
    #[must_use]
    pub fn format(&self, expr: &str) -> String {
        if self.paranoid_parens {
            format!("({expr})")
        } else {
            expr.to_owned()
        }
    }
}

// ---------------------------------------------------------------------------
// OutputBuffer — accumulates lines with metadata
// ---------------------------------------------------------------------------

/// An output buffer that tracks both the code string and per-line metadata.
#[derive(Debug, Default)]
pub struct OutputBuffer {
    lines: Vec<String>,
    /// Source address per line (0 if unknown).
    addresses: Vec<u64>,
}

impl OutputBuffer {
    /// Append a line with an optional source address.
    pub fn push(&mut self, line: impl Into<String>, addr: u64) {
        self.lines.push(line.into());
        self.addresses.push(addr);
    }

    /// Total number of lines.
    #[must_use]
    pub const fn line_count(&self) -> usize {
        self.lines.len()
    }

}

/// Drain to a single string.
impl fmt::Display for OutputBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.lines.join("\n"))
    }
}

impl OutputBuffer {

    /// Clear the buffer.
    pub fn clear(&mut self) {
        self.lines.clear();
        self.addresses.clear();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_gen() -> PseudocodeGenerator {
        PseudocodeGenerator::new(CodeStyle::default())
    }

    fn emit(stmts: Vec<PseudoStmt>) -> String {
        let mut r#gen = default_gen();
        r#gen.emit_function("void f()", &[], &stmts).code
    }

    // --- IndentManager ---

    #[test]
    fn indent_push_pop() {
        let mut im = IndentManager::new("  ");
        im.push();
        assert_eq!(im.prefix(), "  ");
        im.pop();
        assert_eq!(im.prefix(), "");
    }

    #[test]
    fn indent_depth_tracks() {
        let mut im = IndentManager::new("    ");
        im.push();
        im.push();
        assert_eq!(im.depth(), 2);
    }

    #[test]
    fn indent_underflow_safe() {
        let mut im = IndentManager::new("  ");
        im.pop(); // should not panic
        assert_eq!(im.depth(), 0);
    }

    // --- TypeAnnotation ---

    #[test]
    fn type_annotation_decl() {
        let a = TypeAnnotation::new("x", "uint32_t");
        assert_eq!(a.decl(), "uint32_t x");
    }

    #[test]
    fn type_annotation_const() {
        let mut a = TypeAnnotation::new("c", "int");
        a.is_const = true;
        assert!(a.decl().starts_with("const "));
    }

    #[test]
    fn type_annotation_pointer() {
        let a = TypeAnnotation::pointer("p", "char");
        assert!(a.type_str.contains('*'));
        assert!(a.is_pointer);
    }

    // --- SymbolResolver ---

    #[test]
    fn resolver_register_resolve() {
        let mut r = SymbolResolver::default();
        r.register(5, "counter");
        assert_eq!(r.resolve(5), "counter");
    }

    #[test]
    fn resolver_unknown_default() {
        let r = SymbolResolver::default();
        assert_eq!(r.resolve(99), "v99");
    }

    #[test]
    fn resolver_fresh_unique() {
        let mut r = SymbolResolver::default();
        assert_eq!(r.fresh(), "tmp_0");
        assert_eq!(r.fresh(), "tmp_1");
    }

    // --- CommentInserter ---

    #[test]
    fn comment_inserter_add_get() {
        let mut ci = CommentInserter::default();
        ci.add(0x1000, "some comment");
        assert_eq!(ci.get(0x1000), Some("some comment"));
    }

    #[test]
    fn comment_inserter_format() {
        assert_eq!(CommentInserter::format("hello"), "/* hello */");
    }

    #[test]
    fn comment_inserter_missing_none() {
        let ci = CommentInserter::default();
        assert!(ci.get(0xDEAD).is_none());
    }

    // --- PseudocodeGenerator statements ---

    #[test]
    fn gen_return_expr() {
        let out = emit(vec![PseudoStmt::Return(Some("42".into()))]);
        assert!(out.contains("return 42;"));
    }

    #[test]
    fn gen_return_void() {
        let out = emit(vec![PseudoStmt::Return(None)]);
        assert!(out.contains("return;"));
    }

    #[test]
    fn gen_assign() {
        let out = emit(vec![PseudoStmt::Assign {
            dest: "x".into(),
            src: "0".into(),
        }]);
        assert!(out.contains("x = 0;"));
    }

    #[test]
    fn gen_var_decl_no_init() {
        let out = emit(vec![PseudoStmt::VarDecl {
            ty: "int".into(),
            name: "y".into(),
            init: None,
        }]);
        assert!(out.contains("int y;"));
    }

    #[test]
    fn gen_var_decl_with_init() {
        let out = emit(vec![PseudoStmt::VarDecl {
            ty: "int".into(),
            name: "y".into(),
            init: Some("5".into()),
        }]);
        assert!(out.contains("int y = 5;"));
    }

    #[test]
    fn gen_if_no_else() {
        let out = emit(vec![PseudoStmt::If {
            cond: "x > 0".into(),
            then_body: vec![PseudoStmt::Return(Some("x".into()))],
            else_body: None,
        }]);
        assert!(out.contains("if (x > 0)"));
        assert!(!out.contains("else"));
    }

    #[test]
    fn gen_if_with_else() {
        let out = emit(vec![PseudoStmt::If {
            cond: "c".into(),
            then_body: vec![PseudoStmt::Return(Some("1".into()))],
            else_body: Some(vec![PseudoStmt::Return(Some("0".into()))]),
        }]);
        assert!(out.contains("else"));
    }

    #[test]
    fn gen_while_loop() {
        let out = emit(vec![PseudoStmt::While {
            cond: "running".into(),
            body: vec![PseudoStmt::Break],
        }]);
        assert!(out.contains("while (running)"));
        assert!(out.contains("break;"));
    }

    #[test]
    fn gen_do_while() {
        let out = emit(vec![PseudoStmt::DoWhile {
            body: vec![PseudoStmt::Continue],
            cond: "running".into(),
        }]);
        assert!(out.contains("do {"));
        assert!(out.contains("} while (running)"));
    }

    #[test]
    fn gen_for_loop() {
        let out = emit(vec![PseudoStmt::For {
            init: Some("int i = 0".into()),
            cond: Some("i < 10".into()),
            step: Some("i++".into()),
            body: vec![PseudoStmt::Nop],
        }]);
        assert!(out.contains("for (int i = 0; i < 10; i++)"));
    }

    #[test]
    fn gen_switch() {
        let out = emit(vec![PseudoStmt::Switch {
            value: "x".into(),
            cases: vec![(1, vec![PseudoStmt::Return(Some("1".into()))])],
            default: Some(vec![PseudoStmt::Return(Some("0".into()))]),
        }]);
        assert!(out.contains("switch (x)"));
        assert!(out.contains("case 1:"));
        assert!(out.contains("default:"));
    }

    #[test]
    fn gen_goto_label() {
        let out = emit(vec![
            PseudoStmt::Label("loop:".into()),
            PseudoStmt::Goto("loop:".into()),
        ]);
        assert!(out.contains("loop:"));
        assert!(out.contains("goto loop:"));
    }

    #[test]
    fn gen_comment() {
        let out = emit(vec![PseudoStmt::Comment("hello world".into())]);
        assert!(out.contains("/* hello world */"));
    }

    #[test]
    fn gen_expr_stmt() {
        let out = emit(vec![PseudoStmt::Expr("printf(\"hi\")".into())]);
        assert!(out.contains("printf(\"hi\");"));
    }

    #[test]
    fn gen_function_signature() {
        let mut r#gen = default_gen();
        let out = r#gen.emit_function(
            "int add(int a, int b)",
            &[],
            &[PseudoStmt::Return(Some("a + b".into()))],
        );
        assert!(out.code.contains("int add(int a, int b)"));
    }

    #[test]
    fn gen_local_decls_emitted() {
        let mut r#gen = default_gen();
        let locals = vec![TypeAnnotation::new("x", "int")];
        let out = r#gen.emit_function("void f()", &locals, &[]);
        assert!(out.code.contains("int x;"));
    }

    #[test]
    fn gen_line_count() {
        let mut r#gen = default_gen();
        let out = r#gen.emit_function("void f()", &[], &[PseudoStmt::Return(None)]);
        assert!(out.line_count >= 3); // signature + return + closing brace
    }

    #[test]
    fn gen_stmt_count() {
        let mut r#gen = default_gen();
        let out = r#gen.emit_function(
            "void f()",
            &[],
            &[PseudoStmt::Nop, PseudoStmt::Return(None)],
        );
        // Nop doesn't count.
        assert_eq!(out.stmt_count, 1);
    }

    #[test]
    fn gen_display_output() {
        let out = PseudocodeOutput {
            code: "void f() {}".into(),
            line_count: 1,
            stmt_count: 0,
            warnings: vec![],
        };
        assert!(format!("{out}").contains("void f()"));
    }

    #[test]
    fn gen_brace_separate_line() {
        let style = CodeStyle {
            brace_same_line: false,
            ..Default::default()
        };
        let mut r#gen = PseudocodeGenerator::new(style);
        let out = r#gen.emit_function("void f()", &[], &[PseudoStmt::Return(None)]);
        // Opening brace should be on its own line.
        let lines: Vec<&str> = out.code.lines().collect();
        assert!(lines.iter().any(|l| l.trim() == "{"));
    }

    #[test]
    fn gen_indent_level_in_body() {
        let out = emit(vec![PseudoStmt::Return(Some("0".into()))]);
        // The return inside the function body should be indented.
        let ret_line = out.lines().find(|l| l.contains("return")).unwrap();
        assert!(ret_line.starts_with("    ")); // 4-space default
    }

    // --- CodeStyle tests ---

    #[test]
    fn code_style_default_values() {
        let s = CodeStyle::default();
        assert!(s.brace_same_line);
        assert!(!s.typing.rust_types);
    }

    #[test]
    fn indent_manager_four_space_default() {
        let im = IndentManager::new("    ");
        assert_eq!(im.prefix(), "");
    }

    #[test]
    fn indent_manager_two_level_prefix() {
        let mut im = IndentManager::new("  ");
        im.push();
        im.push();
        assert_eq!(im.prefix(), "    ");
    }

    // --- TypeAnnotation additional ---

    #[test]
    fn type_annotation_not_pointer_by_default() {
        let a = TypeAnnotation::new("x", "int");
        assert!(!a.is_pointer);
    }

    #[test]
    fn type_annotation_not_const_by_default() {
        let a = TypeAnnotation::new("x", "int");
        assert!(!a.is_const);
    }

    // --- SymbolResolver additional ---

    #[test]
    fn symbol_resolver_overwrite() {
        let mut r = SymbolResolver::default();
        r.register(1, "first");
        r.register(1, "second");
        assert_eq!(r.resolve(1), "second");
    }

    #[test]
    fn symbol_resolver_multiple_fresh() {
        let mut r = SymbolResolver::default();
        let names: Vec<_> = (0..5).map(|_| r.fresh()).collect();
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(unique.len(), 5);
    }

    // --- CommentInserter additional ---

    #[test]
    fn comment_inserter_multiple_addrs() {
        let mut ci = CommentInserter::default();
        ci.add(0x100, "first");
        ci.add(0x200, "second");
        assert_eq!(ci.get(0x100), Some("first"));
        assert_eq!(ci.get(0x200), Some("second"));
    }

    // --- PseudocodeGenerator additional ---

    #[test]
    fn gen_nop_not_counted() {
        let mut r#gen = default_gen();
        let out = r#gen.emit_function("void f()", &[], &[PseudoStmt::Nop, PseudoStmt::Nop]);
        assert_eq!(out.stmt_count, 0);
    }

    #[test]
    fn gen_nested_if() {
        let inner = PseudoStmt::If {
            cond: "y".into(),
            then_body: vec![PseudoStmt::Return(Some("1".into()))],
            else_body: None,
        };
        let outer = PseudoStmt::If {
            cond: "x".into(),
            then_body: vec![inner],
            else_body: None,
        };
        let out = emit(vec![outer]);
        assert!(out.contains("if (x)"));
        assert!(out.contains("if (y)"));
    }

    #[test]
    fn gen_switch_no_default() {
        let out = emit(vec![PseudoStmt::Switch {
            value: "n".into(),
            cases: vec![(0, vec![PseudoStmt::Break])],
            default: None,
        }]);
        assert!(!out.contains("default:"));
    }

    #[test]
    fn gen_for_empty_parts() {
        let out = emit(vec![PseudoStmt::For {
            init: None,
            cond: None,
            step: None,
            body: vec![PseudoStmt::Break],
        }]);
        assert!(out.contains("for (;;)") || out.contains("for ( ; ; )") || out.contains("for (;"));
    }

    #[test]
    fn gen_blank_lines_between_stmts() {
        let style = CodeStyle {
            blank_lines: true,
            ..Default::default()
        };
        let mut r#gen = PseudocodeGenerator::new(style);
        let out = r#gen.emit_function(
            "void f()",
            &[],
            &[
                PseudoStmt::If {
                    cond: "c".into(),
                    then_body: vec![],
                    else_body: None,
                },
                PseudoStmt::Return(None),
            ],
        );
        // With blank_lines=true, there should be blank lines.
        assert!(out.code.contains("\n\n"));
    }

    #[test]
    fn gen_multiple_local_decls() {
        let mut r#gen = default_gen();
        let locals = vec![
            TypeAnnotation::new("a", "int"),
            TypeAnnotation::new("b", "float"),
        ];
        let out = r#gen.emit_function("void f()", &locals, &[]);
        assert!(out.code.contains("int a;"));
        assert!(out.code.contains("float b;"));
    }

    // --- PseudocodeFormatter tests ---

    #[test]
    fn formatter_strip_trailing_whitespace() {
        let code = "int x;   \nreturn 0;  \n";
        let out = PseudocodeFormatter::strip_trailing_whitespace(code);
        assert!(!out.contains("   \n"));
    }

    #[test]
    fn formatter_collapse_blank_lines() {
        let code = "int x;\n\n\nreturn 0;\n";
        let out = PseudocodeFormatter::collapse_blank_lines(code);
        assert!(!out.contains("\n\n\n"));
    }

    #[test]
    fn formatter_count_code_lines() {
        let code = "int x;\n/* comment */\n\nreturn 0;\n";
        assert_eq!(PseudocodeFormatter::count_code_lines(code), 2);
    }

    #[test]
    fn formatter_count_empty() {
        assert_eq!(PseudocodeFormatter::count_code_lines(""), 0);
    }

    // --- VariableNameSanitizer tests ---

    #[test]
    fn sanitizer_valid_name() {
        assert_eq!(VariableNameSanitizer::sanitize("my_var"), "my_var");
    }

    #[test]
    fn sanitizer_replaces_invalid() {
        let s = VariableNameSanitizer::sanitize("my-var");
        assert!(s.contains('_'));
        assert!(!s.contains('-'));
    }

    #[test]
    fn sanitizer_digit_at_start() {
        let s = VariableNameSanitizer::sanitize("3foo");
        assert!(!s.starts_with('3'));
    }

    #[test]
    fn sanitizer_empty_input() {
        assert_eq!(VariableNameSanitizer::sanitize(""), "_");
    }

    #[test]
    fn sanitizer_reserved_word() {
        let s = VariableNameSanitizer::sanitize("int");
        assert!(s.ends_with('_'));
    }

    // --- PseudocodeStats tests ---

    #[test]
    fn pseudocode_stats_empty() {
        let s = PseudocodeStats::default();
        assert_eq!(s.avg_lines(), 0.0);
    }

    #[test]
    fn pseudocode_stats_add_single() {
        let mut s = PseudocodeStats::default();
        let out = PseudocodeOutput {
            code: String::new(),
            line_count: 10,
            stmt_count: 3,
            warnings: vec![],
        };
        s.add(&out);
        assert_eq!(s.total_functions, 1);
        assert_eq!(s.total_lines, 10);
        assert!((s.avg_lines() - 10.0).abs() < 1e-9);
    }

    #[test]
    fn pseudocode_stats_warning_counted() {
        let mut s = PseudocodeStats::default();
        let out = PseudocodeOutput {
            code: String::new(),
            line_count: 0,
            stmt_count: 0,
            warnings: vec!["warn".into()],
        };
        s.add(&out);
        assert_eq!(s.functions_warnings, 1);
    }

    // --- PseudoStmt variants ---

    #[test]
    fn gen_break_continue_loop() {
        let out = emit(vec![PseudoStmt::While {
            cond: "cond".into(),
            body: vec![PseudoStmt::Break, PseudoStmt::Continue],
        }]);
        assert!(out.contains("break;"));
        assert!(out.contains("continue;"));
    }

    #[test]
    fn gen_nested_while() {
        let inner = PseudoStmt::While {
            cond: "inner".into(),
            body: vec![PseudoStmt::Break],
        };
        let outer = PseudoStmt::While {
            cond: "outer".into(),
            body: vec![inner],
        };
        let out = emit(vec![outer]);
        assert!(out.contains("while (outer)"));
        assert!(out.contains("while (inner)"));
    }

    #[test]
    fn gen_for_no_step() {
        let out = emit(vec![PseudoStmt::For {
            init: Some("int i = 0".into()),
            cond: Some("i < n".into()),
            step: None,
            body: vec![PseudoStmt::Expr("i++".into())],
        }]);
        assert!(out.contains("for (int i = 0;"));
    }

    // --- CStyleGuard tests ---

    #[test]
    fn style_guard_valid_code() {
        let code = "int x;\nreturn 0;\n";
        assert!(CStyleGuard::is_valid(code));
    }

    #[test]
    fn style_guard_long_line() {
        let code = format!("{}\n", "x".repeat(201));
        let issues = CStyleGuard::check(&code);
        assert!(!issues.is_empty());
    }

    #[test]
    fn style_guard_tab_character() {
        let code = "\tint x;\n";
        let issues = CStyleGuard::check(code);
        assert!(!issues.is_empty());
    }

    // --- SignatureBuilder tests ---

    #[test]
    fn signature_void_no_params() {
        let s = SignatureBuilder::void("cleanup").build();
        assert!(s.contains("void cleanup(void)"));
    }

    #[test]
    fn signature_with_return_and_params() {
        let s = SignatureBuilder::void("add")
            .returns("int")
            .param("int", "a")
            .param("int", "b")
            .build();
        assert!(s.contains("int add("));
        assert!(s.contains("int a"));
        assert!(s.contains("int b"));
    }

    #[test]
    fn signature_empty_params_defaults_to_void() {
        let s = SignatureBuilder::void("f").build();
        assert!(s.contains("void"));
    }

    // --- ExpressionFormatter tests ---

    #[test]
    fn expression_formatter_no_parens() {
        let f = ExpressionFormatter {
            paranoid_parens: false,
        };
        assert_eq!(f.format("x + 1"), "x + 1");
    }

    #[test]
    fn expression_formatter_paranoid() {
        let f = ExpressionFormatter {
            paranoid_parens: true,
        };
        assert_eq!(f.format("x + 1"), "(x + 1)");
    }

    // --- OutputBuffer tests ---

    #[test]
    fn output_buffer_push_and_count() {
        let mut b = OutputBuffer::default();
        b.push("int x;", 0x1000);
        b.push("return 0;", 0x1004);
        assert_eq!(b.line_count(), 2);
    }

    #[test]
    fn output_buffer_to_string() {
        let mut b = OutputBuffer::default();
        b.push("void f()", 0);
        let s = b.to_string();
        assert!(s.contains("void f()"));
    }

    #[test]
    fn output_buffer_clear() {
        let mut b = OutputBuffer::default();
        b.push("x", 0);
        b.clear();
        assert_eq!(b.line_count(), 0);
    }

    // --- CodeStyle fields ---

    #[test]
    fn code_style_max_columns_default_zero() {
        let s = CodeStyle::default();
        assert_eq!(s.max_columns, 0);
    }

    #[test]
    fn code_style_not_blank_lines_by_default() {
        let s = CodeStyle::default();
        assert!(!s.blank_lines);
    }

    // --- SymbolResolver bulk registration ---

    #[test]
    fn symbol_resolver_bulk() {
        let mut r = SymbolResolver::default();
        for i in 0..10 {
            r.register(i, format!("var_{i}"));
        }
        for i in 0..10 {
            assert_eq!(r.resolve(i), format!("var_{i}"));
        }
    }
}
