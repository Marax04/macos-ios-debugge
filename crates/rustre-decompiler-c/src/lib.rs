//! `rustre-decompiler-c`
//!
//! C-like pseudocode emitter: the final output stage of the decompiler
//! pipeline.
//!
//! # Key components
//!
//! * [`CFormat`] — configuration (indent style, brace style, constant
//!   notation, …).
//! * [`CPrinter`] — takes a [`StructuredAst`] (from `rustre-decompiler-cfs`)
//!   and a [`TypeEnvironment`] (from `rustre-decompiler-type`) and emits
//!   well-formatted C pseudocode.
//! * [`DecompiledFunction`] — the result: source text plus statistics.

pub mod c_annotation;
pub mod c_comment_gen;
pub mod c_diff_emit;
pub mod c_goto_removal;
pub mod c_macro_detection;
pub mod c_output_full;
pub mod c_postprocess;
pub mod c_printer;
pub mod c_quality;
pub mod c_recovery;
pub mod c_simplifier;
pub mod c_typeinfer;
pub mod type_formatter;

use std::fmt::Write as FmtWrite;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use rustre_decompiler_cfs::{LoopKind, Statement, StructuredNode, SwitchCase};
use rustre_decompiler_expr::{Expr, IntWidth};
use rustre_decompiler_type::{DecompType, TypeEnvironment, TypedExprEmitter};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// How to indent the emitted code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndentStyle {
    /// N spaces per level.
    Spaces(u8),
    /// A tab character per level.
    Tabs,
}

/// Maximum indentation level emitted by [`IndentStyle::make`].  An unbounded
/// level passed from deep recursion would allocate an arbitrarily large string.
const MAX_INDENT_LEVEL: usize = 256;

impl IndentStyle {
    fn make(&self, level: usize) -> String {
        let level = level.min(MAX_INDENT_LEVEL);
        match self {
            Self::Spaces(n) => " ".repeat(*n as usize * level),
            Self::Tabs => "\t".repeat(level),
        }
    }
}

impl Default for IndentStyle {
    fn default() -> Self {
        Self::Spaces(4)
    }
}

/// Brace placement style.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum BraceStyle {
    /// `{` on same line as control keyword (K&R / 1TBS).
    #[default]
    KAndR,
    /// `{` on a new line (Allman).
    Allman,
}

/// How to print integer constants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ConstNotation {
    /// Prefer decimal; use hex for values ≥ 1000.
    #[default]
    Auto,
    /// Always decimal.
    Decimal,
    /// Always hexadecimal.
    Hex,
    /// Always hexadecimal with `0x` prefix.
    HexPrefixed,
}

/// Variable naming mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum VarNaming {
    /// Use the names from the type-aware renamer.
    #[default]
    TypeBased,
    /// Use the raw SSA/IL names.
    Raw,
    /// Use `var0`, `var1`, … sequential scheme.
    Sequential,
}

/// Complete formatting configuration for [`CPrinter`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CFormat {
    pub indent: IndentStyle,
    pub braces: BraceStyle,
    pub const_notation: ConstNotation,
    pub var_naming: VarNaming,
    /// Emit `/* block_id */` comments before each basic-block.
    pub emit_block_comments: bool,
    /// Emit a function prototype before the body.
    pub emit_prototype: bool,
}

impl Default for CFormat {
    fn default() -> Self {
        Self {
            indent: IndentStyle::default(),
            braces: BraceStyle::default(),
            const_notation: ConstNotation::default(),
            var_naming: VarNaming::default(),
            emit_block_comments: false,
            emit_prototype: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Output type
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics collected during emission.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmitStats {
    /// Number of `goto` statements emitted.
    pub goto_count: usize,
    /// Number of variables declared.
    pub variable_count: usize,
    /// Total lines of emitted source (including blank lines).
    pub lines: usize,
    /// Number of if/if-else constructs.
    pub if_count: usize,
    /// Number of loop constructs.
    pub loop_count: usize,
    /// Number of switch constructs.
    pub switch_count: usize,
}

/// The complete decompiled output for a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompiledFunction {
    pub name: String,
    pub source_code: String,
    pub stats: EmitStats,
}

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum EmitError {
    #[error("formatting error: {0}")]
    Fmt(#[from] std::fmt::Error),
    #[error("type emitter error: {0}")]
    Type(#[from] rustre_decompiler_type::TypeError),
    #[error("empty function body")]
    EmptyBody,
}

// ─────────────────────────────────────────────────────────────────────────────
// Function signature
// ─────────────────────────────────────────────────────────────────────────────

/// Describes one parameter of a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionParam {
    pub name: String,
    pub ty: DecompType,
}

impl FunctionParam {
    #[must_use]
    pub fn new(name: impl Into<String>, ty: DecompType) -> Self {
        Self {
            name: name.into(),
            ty,
        }
    }
}

/// A function signature used for prototype emission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub name: String,
    pub return_type: DecompType,
    pub params: Vec<FunctionParam>,
    pub is_variadic: bool,
}

impl FunctionSignature {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        return_type: DecompType,
        params: Vec<FunctionParam>,
    ) -> Self {
        Self {
            name: name.into(),
            return_type,
            params,
            is_variadic: false,
        }
    }

    /// Emit the signature as a C declaration line (no semicolon).
    #[must_use]
    pub fn as_c_declaration(&self) -> String {
        let params: Vec<String> = self
            .params
            .iter()
            .map(|p| format!("{} {}", p.ty.c_name(), p.name))
            .collect();
        let variadic = if self.is_variadic { ", ..." } else { "" };
        format!(
            "{} {}({}{})",
            self.return_type.c_name(),
            self.name,
            params.join(", "),
            variadic
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Variable declaration
// ─────────────────────────────────────────────────────────────────────────────

/// A local variable declaration: `type name [= init];`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarDecl {
    pub name: String,
    pub ty: DecompType,
    pub initializer: Option<String>,
}

impl VarDecl {
    #[must_use]
    pub fn new(name: impl Into<String>, ty: DecompType) -> Self {
        Self {
            name: name.into(),
            ty,
            initializer: None,
        }
    }

    #[must_use]
    pub fn with_init(mut self, init: impl Into<String>) -> Self {
        self.initializer = Some(init.into());
        self
    }

    #[must_use]
    pub fn as_c_declaration(&self) -> String {
        self.initializer.as_ref().map_or_else(|| format!("{} {}", self.ty.c_name(), self.name), |init| format!("{} {} = {}", self.ty.c_name(), self.name, init))
    }
}

/// Format the `init; cond; step` header for a C `for` loop.
///
/// The CFS post-pass encodes for-loops by stashing all three header pieces
/// into the loop's `condition` string separated by `;`.  This helper splits
/// that string back into three parts; when only the condition is present
/// (no `;`), it returns `; cond;` so the emitted code is still valid C.
#[must_use]
pub fn format_for_header(condition: &str) -> String {
    let parts: Vec<&str> = condition.splitn(3, ';').collect();
    if parts.len() == 3 {
        let init = parts[0].trim();
        let cond = parts[1].trim();
        let step = parts[2].trim();
        format!("{init}; {cond}; {step}")
    } else {
        format!("; {}; ", condition.trim())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CPrinter
// ─────────────────────────────────────────────────────────────────────────────

/// The main C pseudocode emitter.
pub struct CPrinter<'a> {
    fmt: CFormat,
    /// Retained so callers can re-extract the environment if needed.
    _env: &'a TypeEnvironment,
    type_emitter: TypedExprEmitter<'a>,
}

impl<'a> CPrinter<'a> {
    /// Create a printer with the given format and type environment.
    #[must_use]
    pub const fn new(fmt: CFormat, env: &'a TypeEnvironment) -> Self {
        let type_emitter = TypedExprEmitter::new(env, 8);
        Self {
            fmt,
            _env: env,
            type_emitter,
        }
    }

    /// Emit a complete function.
    ///
    /// # Errors
    /// Returns `EmitError` on formatting failures or missing type info.
    pub fn emit_function(
        &self,
        sig: &FunctionSignature,
        local_vars: &[VarDecl],
        body: &StructuredNode,
    ) -> Result<DecompiledFunction, EmitError> {
        let mut out = String::new();
        let mut stats = EmitStats {
            variable_count: local_vars.len(),
            ..EmitStats::default()
        };

        // ── Prototype ────────────────────────────────────────────────────────
        if self.fmt.emit_prototype {
            writeln!(out, "{};", sig.as_c_declaration())?;
            writeln!(out)?;
        }

        // ── Opening brace ────────────────────────────────────────────────────
        match self.fmt.braces {
            BraceStyle::KAndR => writeln!(out, "{} {{", sig.as_c_declaration())?,
            BraceStyle::Allman => {
                writeln!(out, "{}", sig.as_c_declaration())?;
                writeln!(out, "{{")?;
            }
        }

        // ── Local variable declarations ───────────────────────────────────────
        if !local_vars.is_empty() {
            let indent = self.fmt.indent.make(1);
            for v in local_vars {
                writeln!(out, "{indent}{};", v.as_c_declaration())?;
            }
            writeln!(out)?;
        }

        // ── Body ─────────────────────────────────────────────────────────────
        self.emit_node(&mut out, body, 1, &mut stats)?;

        writeln!(out, "}}")?;

        stats.lines = out.lines().count();
        stats.goto_count = body.goto_count();

        Ok(DecompiledFunction {
            name: sig.name.clone(),
            source_code: out,
            stats,
        })
    }

    /// Emit a single `StructuredNode` at the given indent level.
    fn emit_node(
        &self,
        out: &mut String,
        node: &StructuredNode,
        indent: usize,
        stats: &mut EmitStats,
    ) -> Result<(), EmitError> {
        let ind = self.fmt.indent.make(indent);
        match node {
            StructuredNode::BasicBlock { id, stmts } => {
                if self.fmt.emit_block_comments {
                    writeln!(out, "{ind}/* {id} */")?;
                }
                for s in stmts {
                    self.emit_statement(out, s, indent)?;
                }
            }

            StructuredNode::Sequence(nodes) => {
                for n in nodes {
                    self.emit_node(out, n, indent, stats)?;
                }
            }

            StructuredNode::If {
                condition,
                then_branch,
            } => {
                stats.if_count += 1;
                self.emit_if_header(out, condition, indent)?;
                self.emit_node(out, then_branch, indent + 1, stats)?;
                writeln!(out, "{ind}}}")?;
            }

            StructuredNode::IfElse {
                condition,
                then_branch,
                else_branch,
            } => {
                stats.if_count += 1;
                self.emit_if_header(out, condition, indent)?;
                self.emit_node(out, then_branch, indent + 1, stats)?;
                match self.fmt.braces {
                    BraceStyle::KAndR => writeln!(out, "{ind}}} else {{")?,
                    BraceStyle::Allman => {
                        writeln!(out, "{ind}}}")?;
                        writeln!(out, "{ind}else")?;
                        writeln!(out, "{ind}{{")?;
                    }
                }
                self.emit_node(out, else_branch, indent + 1, stats)?;
                writeln!(out, "{ind}}}")?;
            }

            StructuredNode::Loop {
                kind,
                condition,
                body,
            } => {
                stats.loop_count += 1;
                self.emit_loop(out, kind, condition, body, indent, stats)?;
            }

            StructuredNode::Switch { expr, cases } => {
                stats.switch_count += 1;
                self.emit_switch(out, expr, cases, indent, stats)?;
            }

            StructuredNode::Goto(target) => {
                writeln!(out, "{ind}goto label_{};", target.0)?;
            }

            StructuredNode::Break => {
                writeln!(out, "{ind}break;")?;
            }

            StructuredNode::Continue => {
                writeln!(out, "{ind}continue;")?;
            }

            StructuredNode::Return(val) => match val {
                Some(v) => writeln!(out, "{ind}return {v};")?,
                None => writeln!(out, "{ind}return;")?,
            },
        }
        Ok(())
    }

    fn emit_statement(
        &self,
        out: &mut String,
        stmt: &Statement,
        indent: usize,
    ) -> Result<(), EmitError> {
        let ind = self.fmt.indent.make(indent);
        match stmt {
            Statement::Raw(s) => writeln!(out, "{ind}{};", s.trim_end_matches(';'))?,
            Statement::Assign { lhs, rhs } => writeln!(out, "{ind}{lhs} = {rhs};")?,
            Statement::Return(v) => match v {
                Some(val) => writeln!(out, "{ind}return {val};")?,
                None => writeln!(out, "{ind}return;")?,
            },
            Statement::Branch(_) => {} // consumed by the structuring layer
        }
        Ok(())
    }

    fn emit_if_header(
        &self,
        out: &mut String,
        condition: &str,
        indent: usize,
    ) -> Result<(), EmitError> {
        let ind = self.fmt.indent.make(indent);
        match self.fmt.braces {
            BraceStyle::KAndR => writeln!(out, "{ind}if ({condition}) {{")?,
            BraceStyle::Allman => {
                writeln!(out, "{ind}if ({condition})")?;
                writeln!(out, "{ind}{{")?;
            }
        }
        Ok(())
    }

    fn emit_loop(
        &self,
        out: &mut String,
        kind: &LoopKind,
        condition: &str,
        body: &StructuredNode,
        indent: usize,
        stats: &mut EmitStats,
    ) -> Result<(), EmitError> {
        let ind = self.fmt.indent.make(indent);
        match kind {
            LoopKind::While => {
                match self.fmt.braces {
                    BraceStyle::KAndR => writeln!(out, "{ind}while ({condition}) {{")?,
                    BraceStyle::Allman => {
                        writeln!(out, "{ind}while ({condition})")?;
                        writeln!(out, "{ind}{{")?;
                    }
                }
                self.emit_node(out, body, indent + 1, stats)?;
                writeln!(out, "{ind}}}")?;
            }
            LoopKind::DoWhile => {
                match self.fmt.braces {
                    BraceStyle::KAndR => writeln!(out, "{ind}do {{")?,
                    BraceStyle::Allman => {
                        writeln!(out, "{ind}do")?;
                        writeln!(out, "{ind}{{")?;
                    }
                }
                self.emit_node(out, body, indent + 1, stats)?;
                writeln!(out, "{ind}}} while ({condition});")?;
            }
            LoopKind::For => {
                // The CFS post-pass encodes for-loops as `init; cond; step`
                // inside the `condition` string.  If the condition does not
                // already contain two `;` separators, fall back to a header
                // with only the condition populated.
                let header = format_for_header(condition);
                match self.fmt.braces {
                    BraceStyle::KAndR => writeln!(out, "{ind}for ({header}) {{")?,
                    BraceStyle::Allman => {
                        writeln!(out, "{ind}for ({header})")?;
                        writeln!(out, "{ind}{{")?;
                    }
                }
                self.emit_node(out, body, indent + 1, stats)?;
                writeln!(out, "{ind}}}")?;
            }
        }
        Ok(())
    }

    fn emit_switch(
        &self,
        out: &mut String,
        expr: &str,
        cases: &[SwitchCase],
        indent: usize,
        stats: &mut EmitStats,
    ) -> Result<(), EmitError> {
        let ind = self.fmt.indent.make(indent);
        let ind1 = self.fmt.indent.make(indent + 1);
        let ind2 = self.fmt.indent.make(indent + 2);
        match self.fmt.braces {
            BraceStyle::KAndR => writeln!(out, "{ind}switch ({expr}) {{")?,
            BraceStyle::Allman => {
                writeln!(out, "{ind}switch ({expr})")?;
                writeln!(out, "{ind}{{")?;
            }
        }
        // Present cases in ascending value order (default last), matching IDA /
        // Hex-Rays. The CFG hands successors to the structurer in petgraph's
        // reverse-insertion order, so without this they read `5,4,3,…`. Ordering
        // is purely cosmetic here: every case body ends in a terminator or gets
        // an explicit `break;` below, so there is no fallthrough to preserve.
        let mut order: Vec<usize> = (0..cases.len()).collect();
        order.sort_by_key(|&i| (cases[i].value.is_none(), cases[i].value.unwrap_or(i64::MAX)));
        for &ci in &order {
            let case = &cases[ci];
            match case.value {
                Some(v) => writeln!(out, "{ind1}case {v}:")?,
                None => writeln!(out, "{ind1}default:")?,
            }
            // Emit the body separately so a trailing `break;` can be suppressed
            // when the case already ends in a terminator (`return`/`goto`/
            // `break`/`continue`) — a `break;` after those is dead code.
            let mut body = String::new();
            self.emit_node(&mut body, &case.body, indent + 2, stats)?;
            out.push_str(&body);
            if !Self::body_ends_in_terminator(&body) {
                writeln!(out, "{ind2}break;")?;
            }
        }
        writeln!(out, "{ind}}}")?;
        Ok(())
    }

    /// True when an emitted case body's last non-empty line is already a
    /// control-transfer statement, so a following `break;` would be dead code.
    fn body_ends_in_terminator(body: &str) -> bool {
        let Some(last) = body.lines().rev().find(|l| !l.trim().is_empty()) else {
            return false;
        };
        let t = last.trim();
        (t.starts_with("return") || t.starts_with("goto ") || t == "break;" || t == "continue;")
            && t.ends_with(';')
    }

    /// Emit an expression using the type emitter, falling back to a raw string
    /// on error.
    #[must_use]
    pub fn emit_expr(&self, expr: &Expr) -> String {
        self.type_emitter
            .emit(expr)
            .unwrap_or_else(|_| "<expr>".to_string())
    }

    /// Emit a constant value according to the configured notation.
    #[must_use]
    pub fn emit_const(&self, value: i64, width: IntWidth) -> String {
        match self.fmt.const_notation {
            ConstNotation::Decimal => format!("{value}"),
            ConstNotation::Hex | ConstNotation::HexPrefixed => {
                format!("0x{value:X}")
            }
            ConstNotation::Auto => {
                if (0..1000).contains(&value) {
                    format!("{value}")
                } else {
                    match width {
                        IntWidth::U8 | IntWidth::I8 => {
                            let repr = u8::try_from(value).unwrap_or(u8::MAX);
                            format!("0x{repr:X}U")
                        }
                        IntWidth::U16 | IntWidth::I16 => {
                            let repr = u16::try_from(value).unwrap_or(u16::MAX);
                            format!("0x{repr:X}U")
                        }
                        IntWidth::U32 | IntWidth::I32 => {
                            // Truncate to 32-bit representation; negative i64 wraps correctly.
                            let repr = u32::try_from(value).unwrap_or(u32::MAX);
                            format!("0x{repr:X}U")
                        }
                        IntWidth::U64 | IntWidth::I64 => {
                            // Negatives wrap to their unsigned bit pattern, the
                            // same convention the narrower widths above use.
                            format!("0x{:X}U", value.cast_unsigned())
                        }
                    }
                }
            }
        }
    }

    /// Emit a struct definition.
    ///
    /// # Errors
    /// Returns `EmitError` on write failure.
    pub fn emit_struct_def(
        &self,
        st: &rustre_decompiler_type::StructType,
    ) -> Result<String, EmitError> {
        let mut out = String::new();
        writeln!(out, "struct {} {{", st.name)?;
        for f in &st.fields {
            writeln!(
                out,
                "    {} {};  /* offset: 0x{:x} */",
                f.ty.c_name(),
                f.name,
                f.offset
            )?;
        }
        writeln!(out, "}};")?;
        Ok(out)
    }

    /// Emit variable declarations for a list of [`VarDecl`]s at indent level 1.
    #[must_use]
    pub fn emit_var_decls(&self, vars: &[VarDecl]) -> String {
        let mut out = String::new();
        let ind = self.fmt.indent.make(1);
        for v in vars {
            let _ = writeln!(out, "{ind}{};", v.as_c_declaration());
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience builder
// ─────────────────────────────────────────────────────────────────────────────

/// A builder for constructing a [`DecompiledFunction`] step by step.
#[derive(Debug, Default)]
pub struct DecompFunctionBuilder {
    name: String,
    return_type: Option<DecompType>,
    params: Vec<FunctionParam>,
    local_vars: Vec<VarDecl>,
    fmt: CFormat,
}

impl DecompFunctionBuilder {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn return_type(mut self, ty: DecompType) -> Self {
        self.return_type = Some(ty);
        self
    }

    #[must_use]
    pub fn param(mut self, p: FunctionParam) -> Self {
        self.params.push(p);
        self
    }

    #[must_use]
    pub fn local(mut self, v: VarDecl) -> Self {
        self.local_vars.push(v);
        self
    }

    #[must_use]
    pub const fn format(mut self, fmt: CFormat) -> Self {
        self.fmt = fmt;
        self
    }

    /// Emit the function body using the provided structured AST.
    ///
    /// # Errors
    /// Returns `EmitError` on formatting failure.
    pub fn emit(
        self,
        body: &StructuredNode,
        env: &TypeEnvironment,
    ) -> Result<DecompiledFunction, EmitError> {
        let sig = FunctionSignature::new(
            self.name,
            self.return_type.unwrap_or(DecompType::Void),
            self.params,
        );
        let printer = CPrinter::new(self.fmt, env);
        printer.emit_function(&sig, &self.local_vars, body)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_decompiler_cfs::{BasicBlock, BlockId, ControlFlowStructurer, Statement as CfsStmt};
    use rustre_decompiler_type::StructField;

    fn make_env() -> TypeEnvironment {
        TypeEnvironment::new()
    }

    fn default_printer(env: &TypeEnvironment) -> CPrinter<'_> {
        CPrinter::new(CFormat::default(), env)
    }

    fn tabs_printer(env: &TypeEnvironment) -> CPrinter<'_> {
        CPrinter::new(
            CFormat {
                indent: IndentStyle::Tabs,
                ..CFormat::default()
            },
            env,
        )
    }

    fn allman_printer(env: &TypeEnvironment) -> CPrinter<'_> {
        CPrinter::new(
            CFormat {
                braces: BraceStyle::Allman,
                ..CFormat::default()
            },
            env,
        )
    }

    fn simple_sig() -> FunctionSignature {
        FunctionSignature::new("test_fn", DecompType::Void, vec![])
    }

    fn int_sig() -> FunctionSignature {
        FunctionSignature::new(
            "add",
            DecompType::Int(IntWidth::I32),
            vec![
                FunctionParam::new("a", DecompType::Int(IntWidth::I32)),
                FunctionParam::new("b", DecompType::Int(IntWidth::I32)),
            ],
        )
    }

    // ── Prototype / signature ─────────────────────────────────────────────

    #[test]
    fn test_signature_void_no_params() {
        let sig = simple_sig();
        assert_eq!(sig.as_c_declaration(), "void test_fn()");
    }

    #[test]
    fn test_signature_int_two_params() {
        let sig = int_sig();
        let decl = sig.as_c_declaration();
        assert!(decl.contains("int32_t"));
        assert!(decl.contains("add"));
        assert!(decl.contains('a'));
        assert!(decl.contains('b'));
    }

    #[test]
    fn test_variadic_signature() {
        let mut sig = simple_sig();
        sig.is_variadic = true;
        assert!(sig.as_c_declaration().contains("..."));
    }

    // ── VarDecl ───────────────────────────────────────────────────────────

    #[test]
    fn test_var_decl_no_init() {
        let v = VarDecl::new("count", DecompType::Int(IntWidth::I32));
        assert_eq!(v.as_c_declaration(), "int32_t count");
    }

    #[test]
    fn test_var_decl_with_init() {
        let v = VarDecl::new("x", DecompType::Int(IntWidth::I32)).with_init("0");
        assert_eq!(v.as_c_declaration(), "int32_t x = 0");
    }

    // ── Return node ───────────────────────────────────────────────────────

    #[test]
    fn test_emit_return_void() {
        let env = make_env();
        let p = default_printer(&env);
        let body = StructuredNode::Return(None);
        let result = p.emit_function(&simple_sig(), &[], &body).unwrap();
        assert!(result.source_code.contains("return;"));
        assert_eq!(result.stats.goto_count, 0);
    }

    #[test]
    fn test_emit_return_value() {
        let env = make_env();
        let p = default_printer(&env);
        let body = StructuredNode::Return(Some("42".to_string()));
        let result = p.emit_function(&simple_sig(), &[], &body).unwrap();
        assert!(result.source_code.contains("return 42;"));
    }

    // ── If / IfElse ───────────────────────────────────────────────────────

    #[test]
    fn test_emit_if() {
        let env = make_env();
        let p = default_printer(&env);
        let body = StructuredNode::If {
            condition: "x > 0".to_string(),
            then_branch: Box::new(StructuredNode::Return(None)),
        };
        let result = p.emit_function(&simple_sig(), &[], &body).unwrap();
        let src = &result.source_code;
        assert!(src.contains("if (x > 0)"));
        assert!(src.contains("return;"));
        assert_eq!(result.stats.if_count, 1);
    }

    #[test]
    fn test_emit_if_else() {
        let env = make_env();
        let p = default_printer(&env);
        let body = StructuredNode::IfElse {
            condition: "flag".to_string(),
            then_branch: Box::new(StructuredNode::Return(Some("1".to_string()))),
            else_branch: Box::new(StructuredNode::Return(Some("0".to_string()))),
        };
        let result = p.emit_function(&simple_sig(), &[], &body).unwrap();
        let src = &result.source_code;
        assert!(src.contains("if (flag)"));
        assert!(src.contains("} else {") || src.contains("else"));
        assert_eq!(result.stats.if_count, 1);
    }

    // ── Loops ─────────────────────────────────────────────────────────────

    #[test]
    fn test_emit_while_loop() {
        let env = make_env();
        let p = default_printer(&env);
        let body = StructuredNode::Loop {
            kind: LoopKind::While,
            condition: "i < 10".to_string(),
            body: Box::new(StructuredNode::Continue),
        };
        let result = p.emit_function(&simple_sig(), &[], &body).unwrap();
        let src = &result.source_code;
        assert!(src.contains("while (i < 10)"));
        assert!(src.contains("continue;"));
        assert_eq!(result.stats.loop_count, 1);
    }

    #[test]
    fn test_emit_do_while_loop() {
        let env = make_env();
        let p = default_printer(&env);
        let body = StructuredNode::Loop {
            kind: LoopKind::DoWhile,
            condition: "running".to_string(),
            body: Box::new(StructuredNode::Return(None)),
        };
        let result = p.emit_function(&simple_sig(), &[], &body).unwrap();
        let src = &result.source_code;
        assert!(src.contains("do {") || src.contains("do\n"));
        assert!(src.contains("} while (running)") || src.contains("while (running)"));
    }

    #[test]
    fn test_emit_for_loop() {
        let env = make_env();
        let p = default_printer(&env);
        let body = StructuredNode::Loop {
            kind: LoopKind::For,
            condition: "i < n".to_string(),
            body: Box::new(StructuredNode::Break),
        };
        let result = p.emit_function(&simple_sig(), &[], &body).unwrap();
        let src = &result.source_code;
        assert!(src.contains("for"));
        assert!(src.contains("i < n"));
    }

    // ── Switch ────────────────────────────────────────────────────────────

    #[test]
    fn test_emit_switch() {
        let env = make_env();
        let p = default_printer(&env);
        let body = StructuredNode::Switch {
            expr: "op".to_string(),
            cases: vec![
                SwitchCase {
                    value: Some(0),
                    body: Box::new(StructuredNode::Return(Some("0".to_string()))),
                },
                SwitchCase {
                    value: None,
                    body: Box::new(StructuredNode::Return(None)),
                },
            ],
        };
        let result = p.emit_function(&simple_sig(), &[], &body).unwrap();
        let src = &result.source_code;
        assert!(src.contains("switch (op)"));
        assert!(src.contains("case 0:"));
        assert!(src.contains("default:"));
        assert_eq!(result.stats.switch_count, 1);
    }

    #[test]
    fn switch_cases_render_in_ascending_value_order() {
        let env = make_env();
        let p = default_printer(&env);
        // Supply cases out of order (2, 0, default, 1) — output must be 0,1,2,default.
        let mk = |v: Option<i64>, r: &str| SwitchCase {
            value: v,
            body: Box::new(StructuredNode::Return(Some(r.to_string()))),
        };
        let body = StructuredNode::Switch {
            expr: "op".to_string(),
            cases: vec![mk(Some(2), "2"), mk(Some(0), "0"), mk(None, "9"), mk(Some(1), "1")],
        };
        let src = p.emit_function(&simple_sig(), &[], &body).unwrap().source_code;
        let order: Vec<&str> = src
            .lines()
            .filter_map(|l| {
                let t = l.trim();
                t.strip_prefix("case ").and_then(|x| x.strip_suffix(':')).or_else(|| {
                    (t == "default:").then_some("default")
                })
            })
            .collect();
        assert_eq!(order, vec!["0", "1", "2", "default"], "{src}");
    }

    #[test]
    fn switch_suppresses_dead_break_after_terminator() {
        let env = make_env();
        let p = default_printer(&env);
        // case 0 ends in `return` → no dead `break;`; the assignment case gets
        // a real `break;`.
        let body = StructuredNode::Switch {
            expr: "op".to_string(),
            cases: vec![
                SwitchCase {
                    value: Some(0),
                    body: Box::new(StructuredNode::Return(Some("1".to_string()))),
                },
                SwitchCase {
                    value: Some(1),
                    body: Box::new(StructuredNode::BasicBlock {
                        id: rustre_decompiler_cfs::BlockId::new(1),
                        stmts: vec![Statement::Assign { lhs: "x".to_string(), rhs: "2".to_string() }],
                    }),
                },
            ],
        };
        let src = p.emit_function(&simple_sig(), &[], &body).unwrap().source_code;
        // No `break;` on the line right after a `return ...;`.
        let lines: Vec<&str> = src.lines().collect();
        for w in lines.windows(2) {
            if w[0].trim().starts_with("return") {
                assert_ne!(w[1].trim(), "break;", "dead break after return:\n{src}");
            }
        }
        // The non-terminating case still breaks.
        assert!(src.contains("x = 2;"), "{src}");
        assert!(src.contains("break;"), "non-terminating case keeps its break: {src}");
    }

    // ── Goto ──────────────────────────────────────────────────────────────

    #[test]
    fn test_emit_goto() {
        let env = make_env();
        let p = default_printer(&env);
        let body = StructuredNode::Goto(BlockId::new(7));
        let result = p.emit_function(&simple_sig(), &[], &body).unwrap();
        assert!(result.source_code.contains("goto label_7;"));
        assert_eq!(result.stats.goto_count, 1);
    }

    // ── Brace / indent styles ─────────────────────────────────────────────

    #[test]
    fn test_allman_braces() {
        let env = make_env();
        let p = allman_printer(&env);
        let body = StructuredNode::If {
            condition: "x".to_string(),
            then_branch: Box::new(StructuredNode::Break),
        };
        let result = p.emit_function(&simple_sig(), &[], &body).unwrap();
        // In Allman style the `{` should appear on its own line.
        let lines: Vec<&str> = result.source_code.lines().collect();
        
        assert!(lines.iter().filter(|l| l.trim() == "{").copied().next().is_some());
    }

    #[test]
    fn test_tab_indentation() {
        let env = make_env();
        let p = tabs_printer(&env);
        let body = StructuredNode::Return(None);
        let result = p.emit_function(&simple_sig(), &[], &body).unwrap();
        assert!(result.source_code.contains('\t'));
    }

    // ── Local variable declarations ───────────────────────────────────────

    #[test]
    fn test_emit_local_vars() {
        let env = make_env();
        let p = default_printer(&env);
        let vars = vec![
            VarDecl::new("i", DecompType::Int(IntWidth::I32)).with_init("0"),
            VarDecl::new("ptr", DecompType::Ptr(Box::new(DecompType::Void))),
        ];
        let result = p
            .emit_function(&simple_sig(), &vars, &StructuredNode::Return(None))
            .unwrap();
        let src = &result.source_code;
        assert!(src.contains("int32_t i = 0;"));
        assert!(src.contains("void * ptr;"));
        assert_eq!(result.stats.variable_count, 2);
    }

    // ── Round-trip via CFG structurer ─────────────────────────────────────

    #[test]
    fn test_roundtrip_linear_function() {
        use rustre_decompiler_cfs::BasicBlock;

        let blocks = vec![
            BasicBlock::new(BlockId::new(0))
                .with_stmts(vec![CfsStmt::Assign {
                    lhs: "x".to_string(),
                    rhs: "1".to_string(),
                }])
                .with_successors(vec![BlockId::new(1)]),
            BasicBlock::new(BlockId::new(1))
                .with_stmts(vec![CfsStmt::Return(Some("x".to_string()))])
                .with_successors(vec![]),
        ];

        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();

        let env = make_env();
        let result = DecompFunctionBuilder::new("linear")
            .return_type(DecompType::Int(IntWidth::I32))
            .emit(&ast.root, &env)
            .unwrap();

        assert!(result.source_code.contains("x = 1"));
        assert_eq!(result.stats.goto_count, 0);
    }

    #[test]
    fn test_roundtrip_if_function() {
        let blocks = vec![
            BasicBlock::new(BlockId::new(0))
                .with_stmts(vec![CfsStmt::Branch("n > 0".to_string())])
                .with_successors(vec![BlockId::new(1), BlockId::new(2)]),
            BasicBlock::new(BlockId::new(1))
                .with_stmts(vec![CfsStmt::Return(Some("1".to_string()))])
                .with_successors(vec![]),
            BasicBlock::new(BlockId::new(2))
                .with_stmts(vec![CfsStmt::Return(Some("0".to_string()))])
                .with_successors(vec![]),
        ];

        let ast = ControlFlowStructurer::new(blocks)
            .structure(BlockId::new(0))
            .unwrap();

        let env = make_env();
        let result = DecompFunctionBuilder::new("sign")
            .return_type(DecompType::Int(IntWidth::I32))
            .emit(&ast.root, &env)
            .unwrap();

        assert!(result.source_code.contains("if"));
        assert!(result.stats.lines > 3);
    }

    // ── Constant notation ─────────────────────────────────────────────────

    #[test]
    fn test_const_notation_decimal() {
        let env = make_env();
        let p = CPrinter::new(
            CFormat {
                const_notation: ConstNotation::Decimal,
                ..CFormat::default()
            },
            &env,
        );
        assert_eq!(p.emit_const(4096, IntWidth::I32), "4096");
    }

    #[test]
    fn test_const_notation_hex() {
        let env = make_env();
        let p = CPrinter::new(
            CFormat {
                const_notation: ConstNotation::Hex,
                ..CFormat::default()
            },
            &env,
        );
        assert_eq!(p.emit_const(255, IntWidth::I32), "0xFF");
    }

    #[test]
    fn test_const_notation_auto_small() {
        let env = make_env();
        let p = default_printer(&env);
        assert_eq!(p.emit_const(42, IntWidth::I32), "42");
    }

    #[test]
    fn test_const_notation_auto_large() {
        let env = make_env();
        let p = default_printer(&env);
        let s = p.emit_const(0x1000, IntWidth::I64);
        assert!(s.starts_with("0x"));
    }

    // ── Struct definition emission ────────────────────────────────────────

    #[test]
    fn test_emit_struct_def() {
        let env = make_env();
        let p = default_printer(&env);
        let st = rustre_decompiler_type::StructType::new(
            "Foo",
            vec![
                StructField::new(0, "x", DecompType::Int(IntWidth::I32)),
                StructField::new(4, "y", DecompType::Float32),
            ],
            8,
        );
        let def = p.emit_struct_def(&st).unwrap();
        assert!(def.contains("struct Foo {"));
        assert!(def.contains("int32_t x"));
        assert!(def.contains("float y"));
    }

    // ── Stats ─────────────────────────────────────────────────────────────

    #[test]
    fn test_stats_lines_nonzero() {
        let env = make_env();
        let p = default_printer(&env);
        let body = StructuredNode::Sequence(vec![StructuredNode::Return(Some("0".to_string()))]);
        let result = p.emit_function(&int_sig(), &[], &body).unwrap();
        assert!(result.stats.lines > 0);
    }

    #[test]
    fn test_function_name_in_output() {
        let env = make_env();
        let p = default_printer(&env);
        let result = p
            .emit_function(&int_sig(), &[], &StructuredNode::Return(None))
            .unwrap();
        assert_eq!(result.name, "add");
        assert!(result.source_code.contains("add"));
    }

    // ── DecompFunctionBuilder ─────────────────────────────────────────────

    #[test]
    fn test_builder_basic() {
        let env = make_env();
        let result = DecompFunctionBuilder::new("foo")
            .return_type(DecompType::Void)
            .emit(&StructuredNode::Return(None), &env)
            .unwrap();
        assert!(result.source_code.contains("foo"));
        assert!(result.source_code.contains("void"));
    }

    #[test]
    fn test_builder_with_params() {
        let env = make_env();
        let result = DecompFunctionBuilder::new("bar")
            .return_type(DecompType::Int(IntWidth::I32))
            .param(FunctionParam::new("n", DecompType::Int(IntWidth::I32)))
            .emit(&StructuredNode::Return(Some("n".to_string())), &env)
            .unwrap();
        assert!(result.source_code.contains('n'));
        assert!(result.source_code.contains("return"));
    }

    // ── Block comments ────────────────────────────────────────────────────

    #[test]
    fn test_block_comment_emission() {
        let env = make_env();
        let p = CPrinter::new(
            CFormat {
                emit_block_comments: true,
                ..CFormat::default()
            },
            &env,
        );
        let body = StructuredNode::BasicBlock {
            id: BlockId::new(3),
            stmts: vec![CfsStmt::Raw("nop()".to_string())],
        };
        let result = p.emit_function(&simple_sig(), &[], &body).unwrap();
        assert!(result.source_code.contains("/* bb3 */"));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CStyle configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Bitfield of boolean style flags for C output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CStyleFlags(u8);

impl CStyleFlags {
    const BLANK_LINES_BETWEEN_DECLS: u8 = 0b0001;
    const ANNOTATE_UNKNOWN_CALLS: u8    = 0b0010;
    const USE_ARROW_FOR_PTR: u8         = 0b0100;
    const EXPLICIT_VOID_PARAMS: u8      = 0b1000;
    const TRAILING_NEWLINE: u8          = 0b0001_0000;

    #[must_use] pub const fn blank_lines_between_decls(self) -> bool { self.0 & Self::BLANK_LINES_BETWEEN_DECLS != 0 }
    #[must_use] pub const fn annotate_unknown_calls(self) -> bool { self.0 & Self::ANNOTATE_UNKNOWN_CALLS != 0 }
    #[must_use] pub const fn use_arrow_for_ptr(self) -> bool { self.0 & Self::USE_ARROW_FOR_PTR != 0 }
    #[must_use] pub const fn explicit_void_params(self) -> bool { self.0 & Self::EXPLICIT_VOID_PARAMS != 0 }
    #[must_use] pub const fn trailing_newline(self) -> bool { self.0 & Self::TRAILING_NEWLINE != 0 }
}

impl Default for CStyleFlags {
    fn default() -> Self {
        // blank_lines=true, annotate=true, use_arrow=true, explicit_void=false, trailing=true
        Self(Self::BLANK_LINES_BETWEEN_DECLS | Self::ANNOTATE_UNKNOWN_CALLS | Self::USE_ARROW_FOR_PTR | Self::TRAILING_NEWLINE)
    }
}

/// Additional style settings for C output.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CStyle {
    /// Style flags (`blank_lines_between_decls`, `annotate_unknown_calls`, `use_arrow_for_ptr`,
    /// `explicit_void_params`, `trailing_newline`).
    pub flags: CStyleFlags,
    /// Maximum line length before wrapping argument lists.
    pub max_line_length: usize,
}

impl Default for CStyle {
    fn default() -> Self {
        Self {
            flags: CStyleFlags::default(),
            max_line_length: 80,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CStatement — structured statement representation
// ─────────────────────────────────────────────────────────────────────────────

/// High-level C statement kinds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CStatement {
    /// `lhs = rhs;`
    Assign { lhs: String, rhs: String },
    /// `type name = init;`
    DeclAssign {
        ty: String,
        name: String,
        init: String,
    },
    /// `return expr;` or `return;`
    Return(Option<String>),
    /// `expr;`
    ExprStmt(String),
    /// `break;`
    Break,
    /// `continue;`
    Continue,
    /// `goto label;`
    Goto(String),
    /// `label:`
    Label(String),
    /// A block `{ stmts }`
    Block(Vec<Self>),
    /// `if (cond) { then } [else { else }]`
    If {
        cond: String,
        then_stmts: Vec<Self>,
        else_stmts: Vec<Self>,
    },
    /// `while (cond) { body }`
    While { cond: String, body: Vec<Self> },
    /// `do { body } while (cond);`
    DoWhile { body: Vec<Self>, cond: String },
    /// `for (init; cond; step) { body }`
    For {
        init: String,
        cond: String,
        step: String,
        body: Vec<Self>,
    },
    /// `switch (expr) { cases }`
    Switch {
        expr: String,
        cases: Vec<CSwitchCase>,
    },
    /// Raw text (pre-formatted).
    Raw(String),
}

/// A single case in a switch statement.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CSwitchCase {
    /// `None` = `default:`, `Some(v)` = `case v:`
    pub value: Option<i64>,
    pub body: Vec<CStatement>,
}

/// Maximum nesting depth for `CStatement::render`.  An adversarially deep
/// `Block(Block(…))` would otherwise cause unbounded recursion and ever-growing
/// indentation strings.  Beyond this depth we emit a placeholder instead.
const MAX_RENDER_DEPTH: usize = 256;

impl CStatement {
    /// Render the statement to a string with indentation.
    #[must_use]
    pub fn render(&self, indent: usize) -> String {
        use std::fmt::Write as _;
        if indent > MAX_RENDER_DEPTH {
            return format!("{}/* <max nesting depth exceeded> */", "    ".repeat(MAX_RENDER_DEPTH));
        }
        let pad = "    ".repeat(indent);
        match self {
            Self::Assign { lhs, rhs } => format!("{pad}{lhs} = {rhs};"),
            Self::DeclAssign { ty, name, init } => format!("{pad}{ty} {name} = {init};"),
            Self::Return(Some(e)) => format!("{pad}return {e};"),
            Self::Return(None) => format!("{pad}return;"),
            Self::ExprStmt(e) => format!("{pad}{e};"),
            Self::Break => format!("{pad}break;"),
            Self::Continue => format!("{pad}continue;"),
            Self::Goto(lbl) => format!("{pad}goto {lbl};"),
            Self::Label(lbl) => format!("{lbl}:"),
            Self::Raw(s) => format!("{pad}{s}"),
            Self::Block(stmts) => {
                let inner: Vec<String> = stmts.iter().map(|s| s.render(indent + 1)).collect();
                format!("{pad}{{\n{}\n{pad}}}", inner.join("\n"))
            }
            Self::If {
                cond,
                then_stmts,
                else_stmts,
            } => {
                let then_inner: Vec<String> =
                    then_stmts.iter().map(|s| s.render(indent + 1)).collect();
                let mut out = format!("{pad}if ({cond}) {{\n{}\n{pad}}}", then_inner.join("\n"));
                if !else_stmts.is_empty() {
                    let else_inner: Vec<String> =
                        else_stmts.iter().map(|s| s.render(indent + 1)).collect();
                    let _ = write!(out, " else {{\n{}\n{pad}}}", else_inner.join("\n"));
                }
                out
            }
            Self::While { cond, body } => {
                let inner: Vec<String> = body.iter().map(|s| s.render(indent + 1)).collect();
                format!("{pad}while ({cond}) {{\n{}\n{pad}}}", inner.join("\n"))
            }
            Self::DoWhile { body, cond } => {
                let inner: Vec<String> = body.iter().map(|s| s.render(indent + 1)).collect();
                format!("{pad}do {{\n{}\n{pad}}} while ({cond});", inner.join("\n"))
            }
            Self::For {
                init,
                cond,
                step,
                body,
            } => {
                let inner: Vec<String> = body.iter().map(|s| s.render(indent + 1)).collect();
                format!(
                    "{pad}for ({init}; {cond}; {step}) {{\n{}\n{pad}}}",
                    inner.join("\n")
                )
            }
            Self::Switch { expr, cases } => {
                let mut out = format!("{pad}switch ({expr}) {{\n");
                for case in cases {
                    let lbl = case.value.map_or_else(|| format!("{pad}    default:"), |v| format!("{pad}    case {v}:"));
                    out.push_str(&lbl);
                    out.push('\n');
                    for s in &case.body {
                        out.push_str(&s.render(indent + 2));
                        out.push('\n');
                    }
                }
                let _ = write!(out, "{pad}}}");
                out
            }
        }
    }

    /// Collect all variable names referenced.
    #[must_use]
    pub fn referenced_vars(&self) -> Vec<String> {
        let mut vars = Vec::new();
        if let Self::Assign { lhs, rhs } = self {
            vars.push(lhs.clone());
            // Simple heuristic: words in rhs.
            for w in rhs.split_whitespace() {
                if w.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    vars.push(w.to_string());
                }
            }
        }
        vars
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CPrecedence table
// ─────────────────────────────────────────────────────────────────────────────

/// C operator precedence levels (higher = tighter binding).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CPrecedence(pub u8);

impl CPrecedence {
    pub const COMMA: Self = Self(1);
    pub const ASSIGN: Self = Self(2);
    pub const TERNARY: Self = Self(3);
    pub const LOGICAL_OR: Self = Self(4);
    pub const LOGICAL_AND: Self = Self(5);
    pub const BITWISE_OR: Self = Self(6);
    pub const BITWISE_XOR: Self = Self(7);
    pub const BITWISE_AND: Self = Self(8);
    pub const EQUALITY: Self = Self(9);
    pub const RELATIONAL: Self = Self(10);
    pub const SHIFT: Self = Self(11);
    pub const ADDITIVE: Self = Self(12);
    pub const MULTIPLICATIVE: Self = Self(13);
    pub const UNARY: Self = Self(14);
    pub const POSTFIX: Self = Self(15);
    pub const PRIMARY: Self = Self(16);

    #[must_use]
    pub fn needs_parens(self, outer: Self) -> bool {
        self < outer
    }
}

/// Return the C precedence for a binary operator string.
#[must_use]
pub fn c_precedence_for_op(op: &str) -> CPrecedence {
    match op {
        "||" => CPrecedence::LOGICAL_OR,
        "&&" => CPrecedence::LOGICAL_AND,
        "|" => CPrecedence::BITWISE_OR,
        "^" => CPrecedence::BITWISE_XOR,
        "&" => CPrecedence::BITWISE_AND,
        "==" | "!=" => CPrecedence::EQUALITY,
        "<" | ">" | "<=" | ">=" => CPrecedence::RELATIONAL,
        "<<" | ">>" => CPrecedence::SHIFT,
        "+" | "-" => CPrecedence::ADDITIVE,
        "*" | "/" | "%" => CPrecedence::MULTIPLICATIVE,
        _ => CPrecedence::PRIMARY,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CTypeDeclaration
// ─────────────────────────────────────────────────────────────────────────────

/// Emits C type declarations from type objects.
#[derive(Debug, Default)]
pub struct CTypeDeclaration;

impl CTypeDeclaration {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn emit_struct(name: &str, fields: &[(&str, &str)]) -> String {
        use std::fmt::Write as _;
        let mut out = format!("struct {name} {{\n");
        for (ty, fname) in fields {
            let _ = writeln!(out, "    {ty} {fname};");
        }
        out.push_str("};");
        out
    }

    #[must_use]
    pub fn emit_typedef(alias: &str, ty: &str) -> String {
        format!("typedef {ty} {alias};")
    }

    #[must_use]
    pub fn emit_enum(name: &str, variants: &[(&str, i64)]) -> String {
        use std::fmt::Write as _;
        let mut out = format!("enum {name} {{\n");
        for (vname, val) in variants {
            let _ = writeln!(out, "    {vname} = {val},");
        }
        out.push_str("};");
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CFlowEmitter
// ─────────────────────────────────────────────────────────────────────────────

/// Emits control-flow constructs.
#[derive(Debug, Default)]
pub struct CFlowEmitter {
    indent: usize,
}

impl CFlowEmitter {
    #[must_use]
    pub const fn new(indent: usize) -> Self {
        Self { indent }
    }

    fn pad(&self) -> String {
        "    ".repeat(self.indent)
    }

    #[must_use]
    pub fn emit_if(&self, cond: &str, then_body: &str) -> String {
        format!(
            "{}if ({cond}) {{\n{then_body}\n{}}}",
            self.pad(),
            self.pad()
        )
    }

    #[must_use]
    pub fn emit_if_else(&self, cond: &str, then_body: &str, else_body: &str) -> String {
        format!(
            "{}if ({cond}) {{\n{then_body}\n{}}} else {{\n{else_body}\n{}}}",
            self.pad(),
            self.pad(),
            self.pad()
        )
    }

    #[must_use]
    pub fn emit_while(&self, cond: &str, body: &str) -> String {
        format!("{}while ({cond}) {{\n{body}\n{}}}", self.pad(), self.pad())
    }

    #[must_use]
    pub fn emit_do_while(&self, body: &str, cond: &str) -> String {
        format!(
            "{}do {{\n{body}\n{}}} while ({cond});",
            self.pad(),
            self.pad()
        )
    }

    #[must_use]
    pub fn emit_for(&self, init: &str, cond: &str, step: &str, body: &str) -> String {
        format!(
            "{}for ({init}; {cond}; {step}) {{\n{body}\n{}}}",
            self.pad(),
            self.pad()
        )
    }

    #[must_use]
    pub fn emit_switch(&self, expr: &str, cases: &[(Option<i64>, String)]) -> String {
        use std::fmt::Write as _;
        let pad = self.pad();
        let mut out = format!("{pad}switch ({expr}) {{\n");
        for (val, body) in cases {
            match val {
                Some(v) => { let _ = write!(out, "{pad}    case {v}:\n{body}\n{pad}        break;\n"); }
                None => { let _ = write!(out, "{pad}    default:\n{body}\n{pad}        break;\n"); }
            }
        }
        let _ = write!(out, "{pad}}}");
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CMacroExpander
// ─────────────────────────────────────────────────────────────────────────────

/// Expands macro-like patterns in emitted code.
#[derive(Debug, Default)]
pub struct CMacroExpander {
    macros: std::collections::HashMap<String, String>,
}

impl CMacroExpander {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn define(&mut self, name: impl Into<String>, expansion: impl Into<String>) {
        self.macros.insert(name.into(), expansion.into());
    }

    #[must_use]
    pub fn expand(&self, code: &str) -> String {
        let mut result = code.to_string();
        for (name, expansion) in &self.macros {
            result = result.replace(name.as_str(), expansion.as_str());
        }
        result
    }

    #[must_use]
    pub fn macro_count(&self) -> usize {
        self.macros.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CIncludeManager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages `#include` directives for emitted C code.
#[derive(Debug, Default)]
pub struct CIncludeManager {
    system_includes: Vec<String>,
    local_includes: Vec<String>,
}

impl CIncludeManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_system(&mut self, header: impl Into<String>) {
        let h = header.into();
        if !self.system_includes.contains(&h) {
            self.system_includes.push(h);
        }
    }

    pub fn add_local(&mut self, header: impl Into<String>) {
        let h = header.into();
        if !self.local_includes.contains(&h) {
            self.local_includes.push(h);
        }
    }

    #[must_use]
    pub fn emit(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        for inc in &self.system_includes {
            let _ = writeln!(out, "#include <{inc}>");
        }
        for inc in &self.local_includes {
            let _ = writeln!(out, "#include \"{inc}\"");
        }
        out
    }

    #[must_use]
    pub const fn count(&self) -> usize {
        self.system_includes.len() + self.local_includes.len()
    }

    /// Add common system headers based on function usage.
    pub fn add_for_function(&mut self, func_name: &str) {
        match func_name {
            "malloc" | "free" | "realloc" | "calloc" => self.add_system("stdlib.h"),
            "printf" | "fprintf" | "sprintf" | "sscanf" | "fopen" | "fclose" | "fread" | "fwrite" => self.add_system("stdio.h"),
            "strlen" | "strcpy" | "strcat" | "strcmp" | "memcpy" | "memset" => {
                self.add_system("string.h");
            }
            "open" | "close" | "read" | "write" => self.add_system("unistd.h"),
            _ => {}
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// COutputFormatter
// ─────────────────────────────────────────────────────────────────────────────

/// Post-processes emitted C code for formatting.
#[derive(Debug, Default)]
pub struct COutputFormatter {
    pub max_line_len: usize,
    pub normalize_whitespace: bool,
    pub strip_trailing_spaces: bool,
}

impl COutputFormatter {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_line_len: 80,
            normalize_whitespace: true,
            strip_trailing_spaces: true,
        }
    }

    #[must_use] 
    pub fn format(&self, code: &str) -> String {
        code.lines()
            .map(|line| {
                let line = if self.strip_trailing_spaces {
                    line.trim_end()
                } else {
                    line
                };
                if self.normalize_whitespace {
                    // Collapse multiple spaces (but preserve indentation).
                    let trimmed_start = line.len() - line.trim_start().len();
                    let indent = &line[..trimmed_start];
                    let rest = line[trimmed_start..]
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ");
                    format!("{indent}{rest}")
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CDecompileContext
// ─────────────────────────────────────────────────────────────────────────────

/// Context object accumulating state during C code emission.
#[derive(Debug, Default)]
pub struct CDecompileContext {
    pub function_name: String,
    pub locals: Vec<(String, String)>, // (type, name)
    pub temp_counter: usize,
    pub label_counter: usize,
    pub call_targets: Vec<String>,
}

impl CDecompileContext {
    #[must_use]
    pub fn new(function_name: impl Into<String>) -> Self {
        Self {
            function_name: function_name.into(),
            ..Default::default()
        }
    }

    pub fn add_local(&mut self, ty: impl Into<String>, name: impl Into<String>) {
        self.locals.push((ty.into(), name.into()));
    }

    pub fn fresh_temp(&mut self) -> String {
        let t = format!("t{}", self.temp_counter);
        self.temp_counter += 1;
        t
    }

    pub fn fresh_label(&mut self) -> String {
        let l = format!("lbl_{}", self.label_counter);
        self.label_counter += 1;
        l
    }

    pub fn record_call(&mut self, target: impl Into<String>) {
        self.call_targets.push(target.into());
    }

    #[must_use]
    pub fn emit_locals(&self) -> String {
        self.locals
            .iter()
            .map(|(ty, name)| format!("    {ty} {name};"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// COutputValidator
// ─────────────────────────────────────────────────────────────────────────────

/// Validates emitted C code for common issues.
#[derive(Debug, Default)]
pub struct COutputValidator {
    pub issues: Vec<String>,
}

impl COutputValidator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate(&mut self, code: &str) -> bool {
        self.issues.clear();
        // Check brace balance, skipping characters inside string and char literals.
        let (opens, closes) = {
            let mut opens = 0usize;
            let mut closes = 0usize;
            let mut chars = code.chars();
            while let Some(c) = chars.next() {
                match c {
                    '"' => {
                        // Skip everything inside a double-quoted string literal,
                        // respecting backslash escapes.
                        loop {
                            match chars.next() {
                                None | Some('"') => break,
                                Some('\\') => { chars.next(); } // skip escaped char
                                _ => {}
                            }
                        }
                    }
                    '\'' => {
                        // Skip everything inside a char literal, respecting escapes.
                        loop {
                            match chars.next() {
                                None | Some('\'') => break,
                                Some('\\') => { chars.next(); }
                                _ => {}
                            }
                        }
                    }
                    '{' => opens += 1,
                    '}' => closes += 1,
                    _ => {}
                }
            }
            (opens, closes)
        };
        if opens != closes {
            self.issues
                .push(format!("brace mismatch: {opens} open, {closes} close"));
        }
        // Check for double semicolons.
        if code.contains(";;") {
            self.issues.push("double semicolon found".to_string());
        }
        // Check for empty function body.
        if code.contains("{}") {
            self.issues.push("empty function body".to_string());
        }
        self.issues.is_empty()
    }

    #[must_use]
    pub const fn issue_count(&self) -> usize {
        self.issues.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CTryCatchEmitter
// ─────────────────────────────────────────────────────────────────────────────

/// Emits SEH / C++ try-catch constructs.
#[derive(Debug, Default)]
pub struct CTryCatchEmitter {
    indent: usize,
}

impl CTryCatchEmitter {
    #[must_use]
    pub const fn new(indent: usize) -> Self {
        Self { indent }
    }

    fn pad(&self) -> String {
        "    ".repeat(self.indent)
    }

    #[must_use]
    pub fn emit_try_except(
        &self,
        try_body: &str,
        except_filter: &str,
        except_body: &str,
    ) -> String {
        let pad = self.pad();
        format!(
            "{pad}__try {{\n{try_body}\n{pad}}} __except ({except_filter}) {{\n{except_body}\n{pad}}}"
        )
    }

    #[must_use]
    pub fn emit_try_finally(&self, try_body: &str, finally_body: &str) -> String {
        let pad = self.pad();
        format!("{pad}__try {{\n{try_body}\n{pad}}} __finally {{\n{finally_body}\n{pad}}}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_c_tests {
    use super::*;

    // ── CStyle ───────────────────────────────────────────────────────────────

    #[test]
    fn test_cstyle_defaults() {
        let s = CStyle::default();
        assert!(s.flags.use_arrow_for_ptr());
        assert!(s.flags.trailing_newline());
        assert_eq!(s.max_line_length, 80);
    }

    // ── CStatement rendering ──────────────────────────────────────────────────

    #[test]
    fn test_cstatement_assign() {
        let s = CStatement::Assign {
            lhs: "x".to_string(),
            rhs: "42".to_string(),
        };
        assert_eq!(s.render(0), "x = 42;");
    }

    #[test]
    fn test_cstatement_return_value() {
        let s = CStatement::Return(Some("x + y".to_string()));
        assert!(s.render(0).contains("return"));
    }

    #[test]
    fn test_cstatement_while() {
        let s = CStatement::While {
            cond: "i < 10".to_string(),
            body: vec![CStatement::Assign {
                lhs: "i".to_string(),
                rhs: "i + 1".to_string(),
            }],
        };
        let r = s.render(0);
        assert!(r.contains("while"));
        assert!(r.contains("i < 10"));
    }

    #[test]
    fn test_cstatement_for() {
        let s = CStatement::For {
            init: "int i = 0".to_string(),
            cond: "i < n".to_string(),
            step: "i++".to_string(),
            body: vec![CStatement::Break],
        };
        let r = s.render(0);
        assert!(r.contains("for"));
        assert!(r.contains("break"));
    }

    #[test]
    fn test_cstatement_if_else() {
        let s = CStatement::If {
            cond: "x > 0".to_string(),
            then_stmts: vec![CStatement::Return(Some("1".to_string()))],
            else_stmts: vec![CStatement::Return(Some("0".to_string()))],
        };
        let r = s.render(0);
        assert!(r.contains("if"));
        assert!(r.contains("else"));
    }

    #[test]
    fn test_cstatement_switch() {
        let s = CStatement::Switch {
            expr: "mode".to_string(),
            cases: vec![
                CSwitchCase {
                    value: Some(1),
                    body: vec![CStatement::Break],
                },
                CSwitchCase {
                    value: None,
                    body: vec![CStatement::Break],
                },
            ],
        };
        let r = s.render(0);
        assert!(r.contains("switch"));
        assert!(r.contains("case 1"));
        assert!(r.contains("default"));
    }

    // ── CPrecedence ───────────────────────────────────────────────────────────

    #[test]
    fn test_precedence_ordering() {
        assert!(CPrecedence::PRIMARY > CPrecedence::ADDITIVE);
        assert!(CPrecedence::ADDITIVE > CPrecedence::LOGICAL_OR);
    }

    #[test]
    fn test_precedence_needs_parens() {
        let add = CPrecedence::ADDITIVE;
        let mul = CPrecedence::MULTIPLICATIVE;
        assert!(add.needs_parens(mul));
        assert!(!mul.needs_parens(add));
    }

    #[test]
    fn test_c_precedence_for_op() {
        assert_eq!(c_precedence_for_op("+"), CPrecedence::ADDITIVE);
        assert_eq!(c_precedence_for_op("*"), CPrecedence::MULTIPLICATIVE);
        assert_eq!(c_precedence_for_op("=="), CPrecedence::EQUALITY);
    }

    // ── CTypeDeclaration ──────────────────────────────────────────────────────

    #[test]
    fn test_emit_struct() {
        let out = CTypeDeclaration::emit_struct("Point", &[("int", "x"), ("int", "y")]);
        assert!(out.contains("struct Point"));
        assert!(out.contains("int x"));
        assert!(out.contains("int y"));
    }

    #[test]
    fn test_emit_typedef() {
        let out = CTypeDeclaration::emit_typedef("DWORD", "unsigned int");
        assert_eq!(out, "typedef unsigned int DWORD;");
    }

    #[test]
    fn test_emit_enum() {
        let out = CTypeDeclaration::emit_enum("Color", &[("RED", 0), ("GREEN", 1), ("BLUE", 2)]);
        assert!(out.contains("enum Color"));
        assert!(out.contains("RED = 0"));
    }

    // ── CFlowEmitter ─────────────────────────────────────────────────────────

    #[test]
    fn test_flow_emitter_if() {
        let fe = CFlowEmitter::new(0);
        let out = fe.emit_if("x > 0", "    return 1;");
        assert!(out.contains("if (x > 0)"));
        assert!(out.contains("return 1"));
    }

    #[test]
    fn test_flow_emitter_while() {
        let fe = CFlowEmitter::new(0);
        let out = fe.emit_while("i < 10", "    i++;");
        assert!(out.contains("while (i < 10)"));
    }

    #[test]
    fn test_flow_emitter_for() {
        let fe = CFlowEmitter::new(0);
        let out = fe.emit_for("int i = 0", "i < 10", "i++", "    arr[i] = 0;");
        assert!(out.contains("for (int i = 0; i < 10; i++)"));
    }

    #[test]
    fn test_flow_emitter_switch() {
        let fe = CFlowEmitter::new(0);
        let cases = vec![
            (Some(1i64), "    x = 1;".to_string()),
            (None, "    x = 0;".to_string()),
        ];
        let out = fe.emit_switch("mode", &cases);
        assert!(out.contains("switch (mode)"));
        assert!(out.contains("case 1:"));
        assert!(out.contains("default:"));
    }

    // ── CMacroExpander ────────────────────────────────────────────────────────

    #[test]
    fn test_macro_expander_simple() {
        let mut me = CMacroExpander::new();
        me.define("NULL", "((void *)0)");
        let out = me.expand("ptr = NULL;");
        assert_eq!(out, "ptr = ((void *)0);");
    }

    // ── CIncludeManager ───────────────────────────────────────────────────────

    #[test]
    fn test_include_manager_system() {
        let mut im = CIncludeManager::new();
        im.add_system("stdio.h");
        im.add_system("stdlib.h");
        assert_eq!(im.count(), 2);
        assert!(im.emit().contains("#include <stdio.h>"));
    }

    #[test]
    fn test_include_manager_dedup() {
        let mut im = CIncludeManager::new();
        im.add_system("stdio.h");
        im.add_system("stdio.h");
        assert_eq!(im.count(), 1);
    }

    #[test]
    fn test_include_manager_auto() {
        let mut im = CIncludeManager::new();
        im.add_for_function("malloc");
        assert!(im.emit().contains("stdlib.h"));
    }

    // ── COutputFormatter ─────────────────────────────────────────────────────

    #[test]
    fn test_formatter_strip_trailing_spaces() {
        let f = COutputFormatter::new();
        let out = f.format("int x;   ");
        assert!(!out.ends_with(' '));
    }

    // ── CDecompileContext ─────────────────────────────────────────────────────

    #[test]
    fn test_decomp_context_fresh_temp() {
        let mut ctx = CDecompileContext::new("fn");
        let t0 = ctx.fresh_temp();
        let t1 = ctx.fresh_temp();
        assert_ne!(t0, t1);
    }

    #[test]
    fn test_decomp_context_locals() {
        let mut ctx = CDecompileContext::new("fn");
        ctx.add_local("int", "x");
        ctx.add_local("uint64_t", "y");
        let decls = ctx.emit_locals();
        assert!(decls.contains("int x"));
        assert!(decls.contains("uint64_t y"));
    }

    // ── COutputValidator ─────────────────────────────────────────────────────

    #[test]
    fn test_output_validator_valid() {
        let mut v = COutputValidator::new();
        assert!(v.validate("void foo() { return; }"));
    }

    #[test]
    fn test_output_validator_brace_mismatch() {
        let mut v = COutputValidator::new();
        assert!(!v.validate("void foo() { return; "));
        assert!(!v.issues.is_empty());
    }

    // ── CTryCatchEmitter ──────────────────────────────────────────────────────

    #[test]
    fn test_try_except_emission() {
        let e = CTryCatchEmitter::new(0);
        let out = e.emit_try_except(
            "    do_work();",
            "EXCEPTION_EXECUTE_HANDLER",
            "    handle_error();",
        );
        assert!(out.contains("__try"));
        assert!(out.contains("__except"));
        assert!(out.contains("EXCEPTION_EXECUTE_HANDLER"));
    }

    #[test]
    fn test_try_finally_emission() {
        let e = CTryCatchEmitter::new(0);
        let out = e.emit_try_finally("    do_work();", "    cleanup();");
        assert!(out.contains("__try"));
        assert!(out.contains("__finally"));
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Expression-aware structured C pretty-printer.
//
// `CodeGenerator` renders a `StructuredNode` tree to syntactically-valid C with
// full configuration (indent width/char, brace style, hex/dec constants, cast
// verbosity, variable naming). It collapses redundant blocks, balances braces,
// and produces deterministic output. Purely additive.
// ═════════════════════════════════════════════════════════════════════════════

use rustre_decompiler_expr::{BinOp, CExprRebuilder};

/// Verbosity of cast emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CastVerbosity {
    /// Emit every cast the IR carries.
    #[default]
    All,
    /// Only emit casts that change the byte width.
    Widening,
    /// Suppress casts entirely.
    None,
}

/// Full configuration for the [`CodeGenerator`].
#[derive(Debug, Clone)]
pub struct CodeGenOptions {
    /// Indentation.
    pub indent: IndentStyle,
    /// Brace placement.
    pub braces: BraceStyle,
    /// Integer constant rendering.
    pub const_notation: ConstNotation,
    /// Cast verbosity.
    pub casts: CastVerbosity,
    /// Emit a `/* bbN */` comment before each basic block.
    pub block_comments: bool,
    /// Emit a label before every block that is a goto target.
    pub emit_labels: bool,
    /// Collapse single-statement bodies onto one line where legal.
    pub compact_single_stmt: bool,
}

impl Default for CodeGenOptions {
    fn default() -> Self {
        Self {
            indent: IndentStyle::Spaces(4),
            braces: BraceStyle::KAndR,
            const_notation: ConstNotation::Auto,
            casts: CastVerbosity::All,
            block_comments: false,
            emit_labels: true,
            compact_single_stmt: false,
        }
    }
}

/// Emits a `StructuredNode` tree as formatted C source.
#[derive(Debug, Clone)]
pub struct CodeGenerator {
    opts: CodeGenOptions,
    rebuilder: CExprRebuilder,
}

impl Default for CodeGenerator {
    fn default() -> Self {
        Self::new(CodeGenOptions::default())
    }
}

impl CodeGenerator {
    /// New generator with options.
    #[must_use]
    pub fn new(opts: CodeGenOptions) -> Self {
        let rebuilder = CExprRebuilder::new();
        Self { opts, rebuilder }
    }

    /// Render an expression to C using the configured rebuilder.
    #[must_use]
    pub fn expr(&self, e: &Expr) -> String {
        self.rebuilder.rebuild(e)
    }

    /// Render a whole node tree (no surrounding function) at the given indent.
    #[must_use]
    pub fn render(&self, node: &StructuredNode, indent: usize) -> String {
        let mut out = String::new();
        self.node(&mut out, node, indent);
        out
    }

    /// Render a complete function: signature, locals, body, with balanced
    /// braces. The result is intended to be syntactically valid C.
    #[must_use]
    pub fn render_function(
        &self,
        sig: &FunctionSignature,
        locals: &[VarDecl],
        body: &StructuredNode,
    ) -> String {
        let mut out = String::new();
        let decl = sig.as_c_declaration();
        match self.opts.braces {
            BraceStyle::KAndR => {
                let _ = writeln!(out, "{decl} {{");
            }
            BraceStyle::Allman => {
                let _ = writeln!(out, "{decl}");
                let _ = writeln!(out, "{{");
            }
        }
        let ind = self.opts.indent.make(1);
        for v in locals {
            let _ = writeln!(out, "{ind}{};", v.as_c_declaration());
        }
        if !locals.is_empty() {
            out.push('\n');
        }
        self.node(&mut out, body, 1);
        let _ = writeln!(out, "}}");
        out
    }

    fn pad(&self, level: usize) -> String {
        self.opts.indent.make(level)
    }

    fn open_brace(&self, out: &mut String, level: usize, header: &str) {
        let ind = self.pad(level);
        match self.opts.braces {
            BraceStyle::KAndR => {
                let _ = writeln!(out, "{ind}{header} {{");
            }
            BraceStyle::Allman => {
                let _ = writeln!(out, "{ind}{header}");
                let _ = writeln!(out, "{ind}{{");
            }
        }
    }

    fn node(&self, out: &mut String, node: &StructuredNode, level: usize) {
        let ind = self.pad(level);
        match node {
            StructuredNode::BasicBlock { id, stmts } => {
                if self.opts.block_comments {
                    let _ = writeln!(out, "{ind}/* {id} */");
                }
                for s in stmts {
                    self.statement(out, s, level);
                }
            }
            StructuredNode::Sequence(children) => {
                for c in children {
                    self.node(out, c, level);
                }
            }
            StructuredNode::If {
                condition,
                then_branch,
            } => {
                self.open_brace(out, level, &format!("if ({condition})"));
                self.node(out, then_branch, level + 1);
                let _ = writeln!(out, "{ind}}}");
            }
            StructuredNode::IfElse {
                condition,
                then_branch,
                else_branch,
            } => {
                self.open_brace(out, level, &format!("if ({condition})"));
                self.node(out, then_branch, level + 1);
                match self.opts.braces {
                    BraceStyle::KAndR => {
                        let _ = writeln!(out, "{ind}}} else {{");
                    }
                    BraceStyle::Allman => {
                        let _ = writeln!(out, "{ind}}}");
                        let _ = writeln!(out, "{ind}else");
                        let _ = writeln!(out, "{ind}{{");
                    }
                }
                self.node(out, else_branch, level + 1);
                let _ = writeln!(out, "{ind}}}");
            }
            StructuredNode::Loop {
                kind,
                condition,
                body,
            } => {
                self.loop_node(out, kind, condition, body, level);
            }
            StructuredNode::Switch { expr, cases } => {
                self.switch_node(out, expr, cases, level);
            }
            StructuredNode::Goto(target) => {
                let _ = writeln!(out, "{ind}goto label_{};", target.0);
            }
            StructuredNode::Break => {
                let _ = writeln!(out, "{ind}break;");
            }
            StructuredNode::Continue => {
                let _ = writeln!(out, "{ind}continue;");
            }
            StructuredNode::Return(v) => match v {
                Some(e) => {
                    let _ = writeln!(out, "{ind}return {e};");
                }
                None => {
                    let _ = writeln!(out, "{ind}return;");
                }
            },
        }
    }

    fn loop_node(
        &self,
        out: &mut String,
        kind: &LoopKind,
        condition: &str,
        body: &StructuredNode,
        level: usize,
    ) {
        let ind = self.pad(level);
        match kind {
            LoopKind::While => {
                self.open_brace(out, level, &format!("while ({condition})"));
                self.node(out, body, level + 1);
                let _ = writeln!(out, "{ind}}}");
            }
            LoopKind::DoWhile => {
                self.open_brace(out, level, "do");
                self.node(out, body, level + 1);
                let _ = writeln!(out, "{ind}}} while ({condition});");
            }
            LoopKind::For => {
                self.open_brace(out, level, &format!("for (; {condition}; )"));
                self.node(out, body, level + 1);
                let _ = writeln!(out, "{ind}}}");
            }
        }
    }

    fn switch_node(&self, out: &mut String, expr: &str, cases: &[SwitchCase], level: usize) {
        let ind = self.pad(level);
        let ind1 = self.pad(level + 1);
        self.open_brace(out, level, &format!("switch ({expr})"));
        for case in cases {
            match case.value {
                Some(v) => {
                    let _ = writeln!(out, "{ind1}case {v}:");
                }
                None => {
                    let _ = writeln!(out, "{ind1}default:");
                }
            }
            self.node(out, &case.body, level + 2);
            let ind2 = self.pad(level + 2);
            // Only add a break if the body did not already end in a terminator.
            if !ends_with_terminator(&case.body) {
                let _ = writeln!(out, "{ind2}break;");
            }
        }
        let _ = writeln!(out, "{ind}}}");
    }

    fn statement(&self, out: &mut String, stmt: &Statement, level: usize) {
        let ind = self.pad(level);
        match stmt {
            Statement::Raw(s) => {
                let _ = writeln!(out, "{ind}{s};");
            }
            Statement::Assign { lhs, rhs } => {
                let _ = writeln!(out, "{ind}{lhs} = {rhs};");
            }
            Statement::Return(v) => match v {
                Some(e) => {
                    let _ = writeln!(out, "{ind}return {e};");
                }
                None => {
                    let _ = writeln!(out, "{ind}return;");
                }
            },
            // Branch statements are consumed by the structuring layer.
            Statement::Branch(_) => {}
        }
    }

    /// Render a constant according to the configured notation. Useful for
    /// callers that build statement strings themselves.
    #[must_use]
    pub fn constant(&self, value: i64, width: IntWidth) -> String {
        match self.opts.const_notation {
            ConstNotation::Decimal => format!("{value}"),
            ConstNotation::Hex => format!("{value:X}"),
            ConstNotation::HexPrefixed => format!("0x{value:X}"),
            ConstNotation::Auto => {
                if (0..1000).contains(&value) {
                    format!("{value}")
                } else {
                    let suffix = match width {
                        IntWidth::U32 => "U",
                        IntWidth::U64 => "ULL",
                        _ => "",
                    };
                    if value < 0 {
                        format!("-0x{:X}{suffix}", value.unsigned_abs())
                    } else {
                        format!("0x{value:X}{suffix}")
                    }
                }
            }
        }
    }
}

/// Does a node tree end with a control-flow terminator (return/break/continue/
/// goto)?
#[must_use]
fn ends_with_terminator(node: &StructuredNode) -> bool {
    match node {
        StructuredNode::Return(_)
        | StructuredNode::Break
        | StructuredNode::Continue
        | StructuredNode::Goto(_) => true,
        StructuredNode::Sequence(children) => children.last().is_some_and(ends_with_terminator),
        StructuredNode::BasicBlock { stmts, .. } => {
            matches!(stmts.last(), Some(Statement::Return(_)))
        }
        _ => false,
    }
}

/// Map a `BinOp` to its C operator string (re-exported convenience).
#[must_use]
pub const fn binop_c_str(op: BinOp) -> &'static str {
    op.as_str()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for the structured code generator
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod codegen_tests {
    use super::*;
    use rustre_decompiler_cfs::{BlockId, Statement as CfsStmt};
    use rustre_decompiler_expr::{BinOp as EBin, Expr, IntWidth, UnOp};

    fn cg() -> CodeGenerator {
        CodeGenerator::default()
    }

    fn raw(s: &str) -> CfsStmt {
        CfsStmt::Raw(s.to_string())
    }

    fn block(id: u32, stmts: Vec<CfsStmt>) -> StructuredNode {
        StructuredNode::BasicBlock {
            id: BlockId::new(id),
            stmts,
        }
    }

    fn balanced(s: &str) -> bool {
        let open = s.chars().filter(|&c| c == '{').count();
        let close = s.chars().filter(|&c| c == '}').count();
        open == close
    }

    // ── Expression rendering ───────────────────────────────────────────────

    #[test]
    fn test_codegen_expr_precedence() {
        let g = cg();
        let e = Expr::BinOp(
            EBin::Mul,
            Box::new(Expr::BinOp(
                EBin::Add,
                Box::new(Expr::Var("a".into())),
                Box::new(Expr::Var("b".into())),
            )),
            Box::new(Expr::Var("c".into())),
        );
        assert_eq!(g.expr(&e), "(a + b) * c");
    }

    #[test]
    fn test_codegen_expr_deref() {
        let g = cg();
        let e = Expr::UnOp(UnOp::Deref, Box::new(Expr::Var("p".into())));
        assert_eq!(g.expr(&e), "*p");
    }

    // ── If / IfElse ─────────────────────────────────────────────────────────

    #[test]
    fn test_codegen_if() {
        let g = cg();
        let node = StructuredNode::If {
            condition: "x > 0".into(),
            then_branch: Box::new(StructuredNode::Return(Some("1".into()))),
        };
        let s = g.render(&node, 0);
        assert!(s.contains("if (x > 0) {"));
        assert!(s.contains("return 1;"));
        assert!(balanced(&s));
    }

    #[test]
    fn test_codegen_if_else() {
        let g = cg();
        let node = StructuredNode::IfElse {
            condition: "flag".into(),
            then_branch: Box::new(StructuredNode::Return(Some("1".into()))),
            else_branch: Box::new(StructuredNode::Return(Some("0".into()))),
        };
        let s = g.render(&node, 0);
        assert!(s.contains("if (flag) {"));
        assert!(s.contains("} else {"));
        assert!(balanced(&s));
    }

    // ── Loops ───────────────────────────────────────────────────────────────

    #[test]
    fn test_codegen_while() {
        let g = cg();
        let node = StructuredNode::Loop {
            kind: LoopKind::While,
            condition: "i < n".into(),
            body: Box::new(block(1, vec![raw("i++")])),
        };
        let s = g.render(&node, 0);
        assert!(s.contains("while (i < n) {"));
        assert!(s.contains("i++;"));
        assert!(balanced(&s));
    }

    #[test]
    fn test_codegen_do_while() {
        let g = cg();
        let node = StructuredNode::Loop {
            kind: LoopKind::DoWhile,
            condition: "running".into(),
            body: Box::new(block(1, vec![raw("work()")])),
        };
        let s = g.render(&node, 0);
        assert!(s.contains("do {"));
        assert!(s.contains("} while (running);"));
        assert!(balanced(&s));
    }

    #[test]
    fn test_codegen_for() {
        let g = cg();
        let node = StructuredNode::Loop {
            kind: LoopKind::For,
            condition: "i < 10".into(),
            body: Box::new(StructuredNode::Break),
        };
        let s = g.render(&node, 0);
        assert!(s.contains("for (; i < 10; )"));
        assert!(s.contains("break;"));
    }

    // ── Switch ────────────────────────────────────────────────────────────

    #[test]
    fn test_codegen_switch_break_inserted() {
        let g = cg();
        let node = StructuredNode::Switch {
            expr: "op".into(),
            cases: vec![
                SwitchCase {
                    value: Some(0),
                    body: Box::new(block(1, vec![raw("a()")])),
                },
                SwitchCase {
                    value: None,
                    body: Box::new(block(2, vec![raw("b()")])),
                },
            ],
        };
        let s = g.render(&node, 0);
        assert!(s.contains("switch (op) {"));
        assert!(s.contains("case 0:"));
        assert!(s.contains("default:"));
        assert!(s.contains("break;"));
        assert!(balanced(&s));
    }

    #[test]
    fn test_codegen_switch_no_double_break() {
        let g = cg();
        // A case ending in return should NOT get an extra break.
        let node = StructuredNode::Switch {
            expr: "op".into(),
            cases: vec![SwitchCase {
                value: Some(1),
                body: Box::new(StructuredNode::Return(Some("1".into()))),
            }],
        };
        let s = g.render(&node, 0);
        let breaks = s.matches("break;").count();
        assert_eq!(breaks, 0);
    }

    // ── Goto / labels ─────────────────────────────────────────────────────

    #[test]
    fn test_codegen_goto() {
        let g = cg();
        let node = StructuredNode::Goto(BlockId::new(5));
        let s = g.render(&node, 0);
        assert!(s.contains("goto label_5;"));
    }

    // ── Function rendering ──────────────────────────────────────────────────

    #[test]
    fn test_codegen_function_balanced() {
        let g = cg();
        let sig = FunctionSignature::new("f", DecompType::Int(IntWidth::I32), vec![]);
        let body = StructuredNode::If {
            condition: "x".into(),
            then_branch: Box::new(StructuredNode::Return(Some("1".into()))),
        };
        let s = g.render_function(&sig, &[], &body);
        assert!(s.contains("f() {"));
        assert!(balanced(&s));
    }

    #[test]
    fn test_codegen_function_with_locals() {
        let g = cg();
        let sig = FunctionSignature::new("g", DecompType::Void, vec![]);
        let locals = vec![VarDecl::new("i", DecompType::Int(IntWidth::I32)).with_init("0")];
        let s = g.render_function(&sig, &locals, &StructuredNode::Return(None));
        assert!(s.contains("int32_t i = 0;"));
        assert!(s.contains("return;"));
        assert!(balanced(&s));
    }

    // ── Brace / indent styles ─────────────────────────────────────────────

    #[test]
    fn test_codegen_allman() {
        let g = CodeGenerator::new(CodeGenOptions {
            braces: BraceStyle::Allman,
            ..CodeGenOptions::default()
        });
        let node = StructuredNode::If {
            condition: "x".into(),
            then_branch: Box::new(StructuredNode::Break),
        };
        let s = g.render(&node, 0);
        // brace appears on its own line
        assert!(s.lines().any(|l| l.trim() == "{"));
        assert!(balanced(&s));
    }

    #[test]
    fn test_codegen_tabs() {
        let g = CodeGenerator::new(CodeGenOptions {
            indent: IndentStyle::Tabs,
            ..CodeGenOptions::default()
        });
        let node = StructuredNode::If {
            condition: "x".into(),
            then_branch: Box::new(StructuredNode::Return(None)),
        };
        let s = g.render(&node, 0);
        assert!(s.contains('\t'));
    }

    // ── Constant rendering ─────────────────────────────────────────────────

    #[test]
    fn test_codegen_const_decimal() {
        let g = CodeGenerator::new(CodeGenOptions {
            const_notation: ConstNotation::Decimal,
            ..CodeGenOptions::default()
        });
        assert_eq!(g.constant(4096, IntWidth::I32), "4096");
    }

    #[test]
    fn test_codegen_const_hex_prefixed() {
        let g = CodeGenerator::new(CodeGenOptions {
            const_notation: ConstNotation::HexPrefixed,
            ..CodeGenOptions::default()
        });
        assert_eq!(g.constant(255, IntWidth::I32), "0xFF");
    }

    #[test]
    fn test_codegen_const_auto_small_large() {
        let g = cg();
        assert_eq!(g.constant(42, IntWidth::I32), "42");
        assert!(g.constant(0x5000, IntWidth::U32).starts_with("0x"));
    }

    // ── Block comments ────────────────────────────────────────────────────

    #[test]
    fn test_codegen_block_comments() {
        let g = CodeGenerator::new(CodeGenOptions {
            block_comments: true,
            ..CodeGenOptions::default()
        });
        let s = g.render(&block(7, vec![raw("nop()")]), 0);
        assert!(s.contains("/* bb7 */"));
    }

    // ── ends_with_terminator helper ────────────────────────────────────────

    #[test]
    fn test_ends_with_terminator() {
        assert!(ends_with_terminator(&StructuredNode::Return(None)));
        assert!(ends_with_terminator(&StructuredNode::Break));
        assert!(!ends_with_terminator(&block(1, vec![raw("x = 1")])));
        let seq = StructuredNode::Sequence(vec![
            block(1, vec![raw("x = 1")]),
            StructuredNode::Return(None),
        ]);
        assert!(ends_with_terminator(&seq));
    }

    #[test]
    fn test_binop_c_str() {
        assert_eq!(binop_c_str(EBin::Add), "+");
        assert_eq!(binop_c_str(EBin::LAnd), "&&");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CStyleGuide — formatting options for C output
// ─────────────────────────────────────────────────────────────────────────────

/// How opening braces should be placed relative to the control keyword.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum BraceStyleGuide {
    /// Allman: `{` on its own line.
    Allman,
    /// K&R: `{` on the same line as the keyword.
    #[default]
    KAndR,
    /// Stroustrup: like K&R but `else` goes on a new line.
    Stroustrup,
}

/// Formatting preferences applied by [`CPrettifier`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CStyleGuide {
    /// Number of spaces per indentation level (ignored when `use_spaces` is
    /// false).
    pub indent_size: u8,
    /// Opening brace placement.
    pub brace_style: BraceStyleGuide,
    /// Lines longer than this will be wrapped (0 = disabled).
    pub max_line_length: u32,
    /// Use spaces for indentation; `false` means use a tab character.
    pub use_spaces: bool,
}

impl Default for CStyleGuide {
    fn default() -> Self {
        Self {
            indent_size: 4,
            brace_style: BraceStyleGuide::KAndR,
            max_line_length: 120,
            use_spaces: true,
        }
    }
}

impl CStyleGuide {
    /// Return the indentation string for one level.
    #[must_use]
    pub fn one_level(&self) -> String {
        if self.use_spaces {
            " ".repeat(self.indent_size as usize)
        } else {
            "\t".to_string()
        }
    }

    /// Return the indentation string for `level` levels.
    #[must_use]
    pub fn indent(&self, level: usize) -> String {
        self.one_level().repeat(level)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CPrettifier — re-indents and wraps raw C text according to a CStyleGuide
// ─────────────────────────────────────────────────────────────────────────────

/// Applies a [`CStyleGuide`] to raw C output, producing consistently indented
/// and optionally line-wrapped source text.
///
/// The prettifier is designed for post-processing output from [`CPrinter`] /
/// [`CodeGenerator`] when callers want to impose their own formatting on the
/// already-syntactically-valid text.  It uses brace depth counting to rebuild
/// indentation and a simple tokeniser to respect string literals when counting
/// braces.
#[derive(Debug, Default, Clone)]
pub struct CPrettifier;

impl CPrettifier {
    /// Create a new prettifier.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Apply `style` to `raw_c` and return the reformatted string.
    #[must_use]
    pub fn prettify(&self, raw_c: &str, style: &CStyleGuide) -> String {
        let mut out = String::new();
        let mut depth: usize = 0;

        for line in raw_c.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                out.push('\n');
                continue;
            }

            // Decide the indent for this line *before* accounting for a
            // leading `}`.  A line that starts with `}` (or `} else`) should
            // be dedented first.
            let leading_close = trimmed.starts_with('}');
            if leading_close && depth > 0 {
                depth -= 1;
            }

            let indent = style.indent(depth);
            let indented = format!("{indent}{trimmed}");

            // Wrap long lines.
            let result_line =
                if style.max_line_length > 0 && u32::try_from(indented.len()).unwrap_or(u32::MAX) > style.max_line_length {
                    Self::wrap_line(&indented, style)
                } else {
                    indented
                };

            out.push_str(&result_line);
            out.push('\n');

            // Adjust depth based on net brace balance for subsequent lines.
            let opens = Self::count_unquoted(trimmed, '{');
            let closes = if leading_close {
                // The leading `}` was already accounted for; count the rest.
                Self::count_unquoted(trimmed, '}').saturating_sub(1)
            } else {
                Self::count_unquoted(trimmed, '}')
            };

            depth = depth.saturating_add(opens).saturating_sub(closes);
        }

        // Remove a trailing newline added by the loop for a cleaner output.
        if out.ends_with('\n') {
            out.pop();
        }
        out
    }

    /// Wrap a long line by breaking after commas or before binary operators.
    /// The continuation is indented by one extra level.
    fn wrap_line(line: &str, style: &CStyleGuide) -> String {
        let max = style.max_line_length as usize;
        if line.len() <= max {
            return line.to_string();
        }

        // Determine the leading whitespace of the line (used for continuation).
        let leading_len = line.len() - line.trim_start().len();
        let cont_indent = format!("{}{}", &line[..leading_len], style.one_level());

        let mut result = String::new();
        let mut current = line.to_string();
        // Safety limit: never loop more times than there are characters, which
        // prevents an infinite loop when the continuation indent itself exceeds
        // max_line_length.
        let mut budget = current.len() + 1;

        while current.len() > max && budget > 0 {
            budget -= 1;
            // Find the last comma, `&&`, `||`, or space before the limit.
            let slice_end = max.min(current.len());
            let candidate = &current[..slice_end];
            let break_pos = candidate
                .rfind(", ")
                .or_else(|| candidate.rfind(" && "))
                .or_else(|| candidate.rfind(" || "))
                .or_else(|| candidate.rfind(' '));

            match break_pos {
                Some(pos) => {
                    // Include the delimiter on the first part.
                    let end = (pos + 1).min(current.len());
                    let tail = current[end..].trim_start().to_string();
                    result.push_str(current[..end].trim_end());
                    result.push('\n');
                    let next = format!("{cont_indent}{tail}");
                    // If the continuation would be no shorter, just emit it and stop.
                    if next.len() >= current.len() {
                        current = next;
                        break;
                    }
                    current = next;
                }
                None => break,
            }
        }
        result.push_str(&current);
        result
    }

    /// Count occurrences of `ch` in `s` that are not inside string literals.
    fn count_unquoted(s: &str, ch: char) -> usize {
        let mut count = 0;
        let mut in_string = false;
        let mut escaped = false;
        for c in s.chars() {
            if escaped {
                escaped = false;
                continue;
            }
            if c == '\\' && in_string {
                escaped = true;
                continue;
            }
            if c == '"' {
                in_string = !in_string;
                continue;
            }
            if !in_string && c == ch {
                count += 1;
            }
        }
        count
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CTypeAnnotator — inserts `/* type */` comments before typed variable uses
// ─────────────────────────────────────────────────────────────────────────────

/// Inserts `/* type */` comments into C source text before the first
/// occurrence of each variable whose type is provided in `type_map`.
///
/// The annotator scans each line for whole-word matches of known variable
/// names and prepends the corresponding type comment on first encounter so
/// that readers can quickly understand the type of each variable.
#[derive(Debug, Default, Clone)]
pub struct CTypeAnnotator;

impl CTypeAnnotator {
    /// Create a new annotator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Return a copy of `c_code` with `/* type */` comments inserted before
    /// the first use of each variable in `type_map`.
    #[must_use]
    pub fn annotate(
        &self,
        c_code: &str,
        type_map: &std::collections::HashMap<String, String>,
    ) -> String {
        // Track which variables have already been annotated so we only insert
        // the comment once per variable.
        let mut annotated: std::collections::HashSet<String> = std::collections::HashSet::new();

        let mut output = String::new();
        for line in c_code.lines() {
            let mut new_line = line.to_string();
            // Walk the type_map in a deterministic order for reproducibility.
            let mut entries: Vec<(&String, &String)> = type_map.iter().collect();
            entries.sort_by_key(|(k, _)| k.as_str());

            for (var, ty) in &entries {
                if annotated.contains(*var) {
                    continue;
                }
                if Self::contains_word(&new_line, var) {
                    // Replace only the first occurrence on this line.
                    let comment = format!("/* {ty} */ ");
                    new_line = Self::insert_before_word(&new_line, var, &comment);
                    annotated.insert((*var).clone());
                }
            }
            output.push_str(&new_line);
            output.push('\n');
        }
        // Remove trailing newline if the source did not end with one.
        if !c_code.ends_with('\n') && output.ends_with('\n') {
            output.pop();
        }
        output
    }

    /// Return `true` when `word` occurs as a whole word in `text`.
    fn contains_word(text: &str, word: &str) -> bool {
        Self::find_word(text, word).is_some()
    }

    /// Find the byte offset of the first whole-word occurrence of `word` in
    /// `text`, or `None` if absent.
    fn find_word(text: &str, word: &str) -> Option<usize> {
        let mut start = 0;
        while let Some(pos) = text[start..].find(word) {
            let abs = start + pos;
            let before_ok = abs == 0 || !Self::is_ident_char(text.as_bytes()[abs - 1] as char);
            let after = abs + word.len();
            let after_ok =
                after >= text.len() || !Self::is_ident_char(text.as_bytes()[after] as char);
            if before_ok && after_ok {
                return Some(abs);
            }
            start = abs + 1;
        }
        None
    }

    /// Insert `comment` immediately before the first whole-word occurrence of
    /// `word` in `text`.  Returns the original string unchanged if not found.
    fn insert_before_word(text: &str, word: &str, comment: &str) -> String {
        Self::find_word(text, word).map_or_else(|| text.to_string(), |pos| {
                let mut s = String::with_capacity(text.len() + comment.len());
                s.push_str(&text[..pos]);
                s.push_str(comment);
                s.push_str(&text[pos..]);
                s
            })
    }

    fn is_ident_char(c: char) -> bool {
        c.is_alphanumeric() || c == '_'
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for CStyleGuide, CPrettifier, CTypeAnnotator
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod new_c_tests {
    use super::*;
    use std::collections::HashMap;

    // ── CStyleGuide ───────────────────────────────────────────────────────────

    #[test]
    fn test_style_guide_defaults() {
        let s = CStyleGuide::default();
        assert_eq!(s.indent_size, 4);
        assert_eq!(s.brace_style, BraceStyleGuide::KAndR);
        assert_eq!(s.max_line_length, 120);
        assert!(s.use_spaces);
    }

    #[test]
    fn test_style_guide_indent_spaces() {
        let s = CStyleGuide {
            indent_size: 4,
            use_spaces: true,
            ..CStyleGuide::default()
        };
        assert_eq!(s.indent(2), "        "); // 8 spaces
    }

    #[test]
    fn test_style_guide_indent_tabs() {
        let s = CStyleGuide {
            use_spaces: false,
            ..CStyleGuide::default()
        };
        assert_eq!(s.indent(3), "\t\t\t");
    }

    #[test]
    fn test_style_guide_one_level_spaces() {
        let s = CStyleGuide {
            indent_size: 2,
            use_spaces: true,
            ..CStyleGuide::default()
        };
        assert_eq!(s.one_level(), "  ");
    }

    #[test]
    fn test_style_guide_brace_styles() {
        let allman = CStyleGuide {
            brace_style: BraceStyleGuide::Allman,
            ..CStyleGuide::default()
        };
        let kandr = CStyleGuide {
            brace_style: BraceStyleGuide::KAndR,
            ..CStyleGuide::default()
        };
        let stroup = CStyleGuide {
            brace_style: BraceStyleGuide::Stroustrup,
            ..CStyleGuide::default()
        };
        assert_eq!(allman.brace_style, BraceStyleGuide::Allman);
        assert_eq!(kandr.brace_style, BraceStyleGuide::KAndR);
        assert_eq!(stroup.brace_style, BraceStyleGuide::Stroustrup);
    }

    // ── CPrettifier ───────────────────────────────────────────────────────────

    fn default_style() -> CStyleGuide {
        CStyleGuide::default()
    }

    #[test]
    fn test_prettifier_basic_indentation() {
        let p = CPrettifier::new();
        let raw = "void foo() {\nreturn;\n}";
        let style = default_style();
        let out = p.prettify(raw, &style);
        // "return;" should be indented inside the braces.
        assert!(out.contains("    return;"), "got: {out:?}");
    }

    #[test]
    fn test_prettifier_nested_braces() {
        let p = CPrettifier::new();
        let raw = "void foo() {\nif (x) {\nreturn;\n}\n}";
        let out = p.prettify(raw, &default_style());
        // The inner return should be indented 8 spaces.
        assert!(out.contains("        return;"), "got: {out:?}");
    }

    #[test]
    fn test_prettifier_closing_brace_dedented() {
        let p = CPrettifier::new();
        let raw = "void foo() {\nx = 1;\n}";
        let out = p.prettify(raw, &default_style());
        // Closing brace should be at indent 0.
        let last_brace_line = out.lines().rev().find(|l| l.contains('}')).unwrap();
        assert_eq!(last_brace_line, "}");
    }

    #[test]
    fn test_prettifier_tabs() {
        let p = CPrettifier::new();
        let raw = "void foo() {\nreturn;\n}";
        let style = CStyleGuide {
            use_spaces: false,
            ..CStyleGuide::default()
        };
        let out = p.prettify(raw, &style);
        assert!(out.contains('\t'));
    }

    #[test]
    fn test_prettifier_empty_lines_preserved() {
        let p = CPrettifier::new();
        let raw = "void foo() {\n\nreturn;\n}";
        let out = p.prettify(raw, &default_style());
        // There should be a blank line inside the body.
        let blank_count = out.lines().filter(|l| l.trim().is_empty()).count();
        assert!(blank_count >= 1);
    }

    #[test]
    fn test_prettifier_no_wrap_when_short() {
        let p = CPrettifier::new();
        let raw = "int x = 1;";
        let style = CStyleGuide {
            max_line_length: 120,
            ..CStyleGuide::default()
        };
        let out = p.prettify(raw, &style);
        // A short line should be a single line.
        assert_eq!(out.lines().count(), 1);
    }

    #[test]
    fn test_prettifier_wraps_long_line() {
        let p = CPrettifier::new();
        // Construct a line clearly over 20 chars to test wrapping at max=20.
        let raw = "int very_long_var_name = some_function_call(arg1, arg2, arg3);";
        let style = CStyleGuide {
            max_line_length: 20,
            ..CStyleGuide::default()
        };
        let out = p.prettify(raw, &style);
        // The output should span multiple lines.
        assert!(out.lines().count() > 1, "expected wrap, got: {out:?}");
    }

    #[test]
    fn test_prettifier_brace_balance_preserved() {
        let p = CPrettifier::new();
        let raw = "void foo() {\nif (a) {\nx++;\n}\nif (b) {\ny++;\n}\n}";
        let out = p.prettify(raw, &default_style());
        let opens = out.chars().filter(|&c| c == '{').count();
        let closes = out.chars().filter(|&c| c == '}').count();
        assert_eq!(opens, closes);
    }

    #[test]
    fn test_prettifier_string_literal_braces_ignored() {
        let p = CPrettifier::new();
        // Braces inside string literals must not affect indentation depth.
        let raw = "const char *s = \"{ not a brace }\";\nreturn;";
        let out = p.prettify(raw, &default_style());
        // "return;" should remain at depth 0 — no spurious indentation.
        let return_line = out.lines().find(|l| l.contains("return")).unwrap();
        assert!(!return_line.starts_with("    "), "got: {return_line:?}");
    }

    // ── CTypeAnnotator ────────────────────────────────────────────────────────

    #[test]
    fn test_annotator_inserts_comment() {
        let ann = CTypeAnnotator::new();
        let code = "x = 1;";
        let mut map = HashMap::new();
        map.insert("x".to_string(), "int32_t".to_string());
        let out = ann.annotate(code, &map);
        assert!(out.contains("/* int32_t */"), "got: {out:?}");
        assert!(out.contains('x'), "got: {out:?}");
    }

    #[test]
    fn test_annotator_only_first_occurrence() {
        let ann = CTypeAnnotator::new();
        let code = "x = x + 1;";
        let mut map = HashMap::new();
        map.insert("x".to_string(), "int32_t".to_string());
        let out = ann.annotate(code, &map);
        // Comment should appear exactly once across the whole output.
        assert_eq!(out.matches("/* int32_t */").count(), 1, "got: {out:?}");
    }

    #[test]
    fn test_annotator_multiple_vars() {
        let ann = CTypeAnnotator::new();
        let code = "result = a + b;";
        let mut map = HashMap::new();
        map.insert("a".to_string(), "uint64_t".to_string());
        map.insert("b".to_string(), "uint64_t".to_string());
        let out = ann.annotate(code, &map);
        assert!(out.contains("/* uint64_t */"));
    }

    #[test]
    fn test_annotator_no_partial_word_match() {
        let ann = CTypeAnnotator::new();
        // "ab" should not match inside "abc".
        let code = "abc = 1;";
        let mut map = HashMap::new();
        map.insert("ab".to_string(), "int32_t".to_string());
        let out = ann.annotate(code, &map);
        assert!(!out.contains("/* int32_t */"), "got: {out:?}");
    }

    #[test]
    fn test_annotator_unknown_var_unchanged() {
        let ann = CTypeAnnotator::new();
        let code = "x = 1;";
        let map = HashMap::new(); // empty map
        let out = ann.annotate(code, &map);
        assert!(!out.contains("/*"), "got: {out:?}");
        assert!(out.contains("x = 1;"));
    }

    #[test]
    fn test_annotator_multiline_first_occurrence_per_var() {
        let ann = CTypeAnnotator::new();
        let code = "x = 0;\ny = x + 1;\nz = x * 2;";
        let mut map = HashMap::new();
        map.insert("x".to_string(), "int32_t".to_string());
        let out = ann.annotate(code, &map);
        // Comment should appear exactly once for "x".
        assert_eq!(out.matches("/* int32_t */").count(), 1, "got: {out:?}");
        // First line should have the comment; subsequent uses of "x" should not.
        let first_line = out.lines().next().unwrap();
        assert!(first_line.contains("/* int32_t */"), "got: {first_line:?}");
    }

    #[test]
    fn test_annotator_preserves_line_count() {
        let ann = CTypeAnnotator::new();
        let code = "a = 1;\nb = 2;\nc = 3;";
        let mut map = HashMap::new();
        map.insert("a".to_string(), "int".to_string());
        let out = ann.annotate(code, &map);
        assert_eq!(code.lines().count(), out.lines().count());
    }
}

// Additional utilities
#[must_use] 
pub const fn decompiler_c_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
#[must_use] 
pub fn supported_languages() -> Vec<&'static str> {
    vec!["c", "c++"]
}
#[must_use] 
pub const fn max_decompile_depth() -> usize {
    32
}

/// Language dialect for C decompilation output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CDialect {
    C89,
    C99,
    C11,
    C17,
    Cpp11,
    Cpp14,
    Cpp17,
    Cpp20,
}
impl CDialect {
    #[must_use] 
    pub const fn is_cpp(self) -> bool {
        matches!(self, Self::Cpp11 | Self::Cpp14 | Self::Cpp17 | Self::Cpp20)
    }
    #[must_use] 
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::C89 => "c89",
            Self::C99 => "c99",
            Self::C11 => "c11",
            Self::C17 => "c17",
            Self::Cpp11 => "c++11",
            Self::Cpp14 => "c++14",
            Self::Cpp17 => "c++17",
            Self::Cpp20 => "c++20",
        }
    }
}

/// Whether to emit comments in decompiled output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentMode {
    None,
    Minimal,
    Full,
}

/// Indentation style for C output.
#[derive(Debug, Clone)]
pub struct IndentStyleSimple {
    pub spaces: usize,
    pub use_tabs: bool,
}
impl Default for IndentStyleSimple {
    fn default() -> Self {
        Self {
            spaces: 4,
            use_tabs: false,
        }
    }
}
impl IndentStyleSimple {
    #[must_use] 
    pub const fn tabs() -> Self {
        Self {
            spaces: 1,
            use_tabs: true,
        }
    }
    #[must_use] 
    pub const fn spaces(n: usize) -> Self {
        Self {
            spaces: n,
            use_tabs: false,
        }
    }
    #[must_use] 
    pub fn indent_str(&self) -> String {
        if self.use_tabs {
            "\t".to_string()
        } else {
            " ".repeat(self.spaces)
        }
    }
}

#[cfg(test)]
mod utils_tests {
    use super::*;
    #[test]
    fn test_dialect_cpp() {
        assert!(CDialect::Cpp17.is_cpp());
        assert!(!CDialect::C99.is_cpp());
    }
    #[test]
    fn test_dialect_str() {
        assert_eq!(CDialect::C11.as_str(), "c11");
    }
    #[test]
    fn test_indent_default() {
        assert_eq!(IndentStyleSimple::default().indent_str(), "    ");
    }
    #[test]
    fn test_indent_tabs() {
        assert_eq!(IndentStyleSimple::tabs().indent_str(), "\t");
    }
    #[test]
    fn test_indent_2() {
        assert_eq!(IndentStyleSimple::spaces(2).indent_str(), "  ");
    }
    #[test]
    fn test_version() {
        let v = decompiler_c_version();
        assert!(!v.is_empty());
    }
    #[test]
    fn test_languages() {
        let langs = supported_languages();
        assert!(langs.contains(&"c"));
    }
}
