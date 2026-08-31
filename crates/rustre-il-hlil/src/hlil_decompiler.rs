//! HLIL → C pseudocode decompiler for `rustre-il-hlil`.
//!
//! [`HlilDecompiler`] orchestrates conversion of a [`HlilFunction`] to a
//! human-readable C-like string.  The pipeline is:
//!
//! 1. [`TypePrinter`] — emits type strings from [`HlilType`].
//! 2. [`ExprPrinter`] — emits expressions from [`HlilExpr`].
//! 3. [`StmtPrinter`] — emits statements from [`HlilStmt`].
//!
//! # Architecture
//!
//! The decompiler is structured as a set of composable printers:
//!
//! ```text
//! HlilFunction
//!     └── body: Vec<HlilStmt>
//!             └── HlilStmt variants
//!                     └── HlilExpr sub-trees
//! ```
//!
//! [`TypePrinter`] handles type-to-string conversion independently of statements,
//! so it can be reused for variable declarations, cast expressions, and function
//! signatures.
//!
//! [`ExprPrinter`] recursively descends the expression tree, applying operator
//! precedence rules to minimise redundant parentheses.
//!
//! [`StmtPrinter`] manages the indentation level and delegates to [`ExprPrinter`]
//! for expression sub-trees.
//!
//! # Configuration
//!
//! All output formatting is controlled by [`DecompilerConfig`]:
//! * `indent_str` — the per-level indentation string (default: four spaces).
//! * `annotate_types` — emit local variable type declarations.
//! * `address_comments` — emit `/* 0x… */` comments before statements.
//! * `blank_lines` — insert a blank line after block-structured statements.
//! * `max_line_len` — soft line-length limit (0 = no limit).
//! * `stdint_names` — use `uint32_t` rather than `unsigned int`.
//! * `banner` — prepend a `/* Decompiled by RustRE */` comment.
//!
//! # Extending the Decompiler
//!
//! Implement additional [`HlilExpr`] or [`HlilStmt`] variants by adding arms to
//! the `match` statements in [`ExprPrinter::print`] and [`StmtPrinter::emit_stmt`].
//! The pattern is deliberately exhaustive so the compiler will flag missed cases.
//! 4. [`CodegenContext`] — carries indent level, symbol table, and config.

use std::collections::HashMap;
use std::fmt::{self, Write as _};

use crate::{HlilExpr, HlilFunction, HlilStatement as HlilStmt, HlilType};

pub use crate::HlilVar;

// ---------------------------------------------------------------------------
// Well-known C type strings
// ---------------------------------------------------------------------------

/// Common C type name strings used throughout the decompiler output.
pub mod c_types {
    pub const VOID: &str = "void";
    pub const BOOL: &str = "bool";
    pub const CHAR: &str = "char";
    pub const INT: &str = "int";
    pub const UINT: &str = "unsigned int";
    pub const INT8: &str = "int8_t";
    pub const INT16: &str = "int16_t";
    pub const INT32: &str = "int32_t";
    pub const INT64: &str = "int64_t";
    pub const UINT8: &str = "uint8_t";
    pub const UINT16: &str = "uint16_t";
    pub const UINT32: &str = "uint32_t";
    pub const UINT64: &str = "uint64_t";
    pub const FLOAT: &str = "float";
    pub const DOUBLE: &str = "double";
    pub const VOIDPTR: &str = "void *";
}

// ---------------------------------------------------------------------------
// Operator precedence constants
// ---------------------------------------------------------------------------

/// C operator precedence levels (higher = tighter binding).
///
/// These are used by [`ExprPrinter`] to decide when to add parentheses.
pub mod precedence {
    pub const COMMA: u8 = 1;
    pub const ASSIGN: u8 = 2;
    pub const TERNARY: u8 = 3;
    pub const LOGICAL_OR: u8 = 4;
    pub const LOGICAL_AND: u8 = 5;
    pub const BITWISE_OR: u8 = 6;
    pub const BITWISE_XOR: u8 = 7;
    pub const BITWISE_AND: u8 = 8;
    pub const EQUALITY: u8 = 9;
    pub const RELATIONAL: u8 = 10;
    pub const SHIFT: u8 = 11;
    pub const ADDITIVE: u8 = 12;
    pub const MULTIPLICATIVE: u8 = 13;
    pub const UNARY: u8 = 14;
    pub const POSTFIX: u8 = 15;
}

// ---------------------------------------------------------------------------
// DecompilerConfig
// ---------------------------------------------------------------------------

/// Configuration knobs for the decompiler output.
#[derive(Debug, Clone)]
pub struct DecompilerConfig {
    /// Indentation string (default: four spaces).
    pub indent_str: String,
    /// Emit type annotations on variable declarations.
    pub annotate_types: bool,
    /// Emit source-address comments before statements.
    pub address_comments: bool,
    /// Emit blank lines between top-level statements.
    pub blank_lines: bool,
    /// Maximum line length before wrapping long expressions (0 = no limit).
    pub max_line_len: usize,
    /// Use `uint32_t` / `int64_t` style names rather than `unsigned int`.
    pub stdint_names: bool,
    /// Whether to add a `/* decompiled */` banner at the top.
    pub banner: bool,
}

impl Default for DecompilerConfig {
    fn default() -> Self {
        Self {
            indent_str: "    ".into(),
            annotate_types: true,
            address_comments: false,
            blank_lines: true,
            max_line_len: 0,
            stdint_names: true,
            banner: false,
        }
    }
}

// ---------------------------------------------------------------------------
// IndentLevel
// ---------------------------------------------------------------------------

/// Tracks the current indentation depth and converts it to a string prefix.
#[derive(Debug, Clone, Default)]
pub struct IndentLevel {
    depth: usize,
    unit: String,
}

impl IndentLevel {
    /// Create an [`IndentLevel`] using `unit` as the per-level string.
    #[must_use]
    pub fn new(unit: impl Into<String>) -> Self {
        Self {
            depth: 0,
            unit: unit.into(),
        }
    }

    /// Increase indentation by one level.
    pub const fn push(&mut self) {
        self.depth += 1;
    }

    /// Decrease indentation by one level (saturating).
    pub const fn pop(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Current depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.depth
    }

    /// Return the full indentation prefix for the current depth.
    #[must_use]
    pub fn prefix(&self) -> String {
        self.unit.repeat(self.depth)
    }

    /// Execute `f` at one greater indentation level.
    pub fn indented<R>(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        self.push();
        let r = f(self);
        self.pop();
        r
    }
}

// ---------------------------------------------------------------------------
// TypePrinter
// ---------------------------------------------------------------------------

/// Converts [`HlilType`] values to C type-declaration strings.
#[derive(Debug, Default, Clone)]
pub struct TypePrinter {
    use_stdint: bool,
}

impl TypePrinter {
    /// Create a [`TypePrinter`] that emits `uint32_t`-style names.
    #[must_use]
    pub const fn stdint() -> Self {
        Self { use_stdint: true }
    }

    /// Create a [`TypePrinter`] that emits `unsigned int`-style names.
    #[must_use]
    pub const fn traditional() -> Self {
        Self { use_stdint: false }
    }

    /// Convert `ty` to a C type string.
    #[must_use]
    pub fn print(&self, ty: &HlilType) -> String {
        match ty {
            HlilType::Unknown => "/* ? */".into(),
            HlilType::Void => "void".into(),
            HlilType::Bool => "bool".into(),
            HlilType::Int { signed, bits } => self.int_name(*signed, *bits),
            HlilType::Float { bits } => match bits {
                32 => "float".into(),
                64 => "double".into(),
                _ => format!("float{bits}"),
            },
            HlilType::Pointer { pointee, bits } => {
                let inner = self.print(pointee);
                let _ = bits;
                format!("{inner} *")
            }
            HlilType::Array { elem, count } => {
                let inner = self.print(elem);
                let count_str = count.map_or("".to_string(), |c| c.to_string());
                format!("{inner}[{count_str}]")
            }
            HlilType::Struct { name } => format!("struct {name}"),
            HlilType::Enum { name } => format!("enum {name}"),
            HlilType::Function { ret, params } => {
                let ret_s = self.print(ret);
                let params_s: Vec<String> = params.iter().map(|p| self.print(p)).collect();
                format!("{ret_s} (*)( {} )", params_s.join(", "))
            }
        }
    }

    fn int_name(&self, signed: bool, bits: u32) -> String {
        if self.use_stdint {
            let prefix = if signed { "int" } else { "uint" };
            format!("{prefix}{bits}_t")
        } else {
            match (signed, bits) {
                (true, 8) => "char".into(),
                (false, 8) => "unsigned char".into(),
                (true, 16) => "short".into(),
                (false, 16) => "unsigned short".into(),
                (true, 32) => "int".into(),
                (false, 32) => "unsigned int".into(),
                (true, 64) => "long long".into(),
                (false, 64) => "unsigned long long".into(),
                (s, b) => format!("{}{b}", if s { "i" } else { "u" }),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ExprPrinter
// ---------------------------------------------------------------------------

/// Converts [`HlilExpr`] values to C expression strings.
#[derive(Debug, Default)]
pub struct ExprPrinter {
    type_printer: TypePrinter,
}

impl ExprPrinter {
    /// Create an [`ExprPrinter`] with the given type printer.
    #[must_use]
    pub const fn new(type_printer: TypePrinter) -> Self {
        Self { type_printer }
    }

    /// Emit `expr` as a C expression string.
    #[must_use]
    pub fn print(&self, expr: &HlilExpr) -> String {
        match expr {
            HlilExpr::Const { value, .. } => format!("{value}"),
            HlilExpr::Float { value, .. } => format!("{value}"),
            HlilExpr::ConstFloat(f) => format!("{f}"),
            HlilExpr::Var { var: v } => v.name.clone(),
            HlilExpr::AddressOf { var } => format!("&{}", var.name),
            HlilExpr::AddrOf(inner) => format!("&{}", self.print(inner)),
            HlilExpr::Deref { addr, .. } => format!("*{}", self.print_parens(addr)),

            HlilExpr::Add(l, r, ..) => self.binop(l, "+", r),
            HlilExpr::Sub(l, r, ..) => self.binop(l, "-", r),
            HlilExpr::Mul(l, r, ..) => self.binop(l, "*", r),
            // #7150 — la divisione CON SEGNO non e una variante, e un TIPO.
            // Il lift lo dichiara: "Signed division: carry signedness in the
            // attached type so the distinction is not erased" (lib.rs:3159,
            // `MlilExpr::DivS -> HlilExpr::Div(.., from_mlil_size_signed)`).
            // Il tipo c era, nessuno lo leggeva: su operandi `uint64_t` il `/`
            // nudo e una divisione SENZA segno.
            HlilExpr::Div(l, r, ty) if matches!(ty, HlilType::Int { signed: true, .. }) => {
                format!("((int64_t){} / (int64_t){})", self.print_parens(l), self.print_parens(r))
            }
            HlilExpr::DivS(l, r) => {
                format!("((int64_t){} / (int64_t){})", self.print_parens(l), self.print_parens(r))
            }
            HlilExpr::Div(l, r, ..) | HlilExpr::DivU(l, r) => self.binop(l, "/", r),
            // #7150 — completamento della famiglia sensibile al segno.
            // ⚠ INERTE sul corpus attuale: i moduli emessi sono **0** (contro
            // 6603 shift e 259 divisioni). Aggiunto per coerenza, cosi la
            // famiglia e chiusa e nessuno deve tornarci; NON va contato fra i
            // guadagni, come il ramo gemello di `DivS` (§151).
            HlilExpr::Mod(l, r, ty) if matches!(ty, HlilType::Int { signed: true, .. }) => {
                format!("((int64_t){} % (int64_t){})", self.print_parens(l), self.print_parens(r))
            }
            HlilExpr::ModS(l, r) => {
                format!("((int64_t){} % (int64_t){})", self.print_parens(l), self.print_parens(r))
            }
            HlilExpr::Mod(l, r, ..) | HlilExpr::ModU(l, r) => self.binop(l, "%", r),
            HlilExpr::Or(l, r, ..) | HlilExpr::BitOr(l, r) => self.binop(l, "|", r),
            HlilExpr::And(l, r, ..) | HlilExpr::BitAnd(l, r) => self.binop(l, "&", r),
            HlilExpr::Xor(l, r, ..) | HlilExpr::BitXor(l, r) => self.binop(l, "^", r),
            HlilExpr::Shl(l, r, ..) => self.binop(l, "<<", r),
            // #7150 — `Sar` e lo shift ARITMETICO: conserva il bit di segno.
            // Su un operando dichiarato `uint64_t` un `>>` nudo e uno shift
            // LOGICO, e su un valore negativo non da un risultato "un po
            // diverso": ne da uno enorme e positivo. E lo stesso difetto delle
            // `CmpS*` (#7140), nella famiglia piu numerosa — misurati **6603**
            // shift destri nel corpus contro 259 divisioni.
            //
            // Il cast va SOLO a sinistra: e l operando di cui conta il segno.
            // La quantita di shift e non negativa per costruzione.
            HlilExpr::Sar(l, r) => format!("((int64_t){} >> {})", self.print_parens(l), self.print(r)),
            HlilExpr::Shr(l, r, ..) => self.binop(l, ">>", r),
            HlilExpr::BoolAnd(l, r) | HlilExpr::LogicalAnd(l, r) => self.binop(l, "&&", r),
            HlilExpr::BoolOr(l, r) | HlilExpr::LogicalOr(l, r) => self.binop(l, "||", r),
            HlilExpr::Not(e, ..) => format!("(~{})", self.print(e)),
            HlilExpr::BoolNot(e) | HlilExpr::LogicalNot(e) => format!("(!{})", self.print(e)),
            HlilExpr::Neg(e, ..) => format!("(-{})", self.print(e)),
            HlilExpr::CmpEq(l, r) => self.binop(l, "==", r),
            HlilExpr::CmpNe(l, r) => self.binop(l, "!=", r),
            // #7140 — le varianti CON SEGNO vanno stampate con i cast: gli
            // operandi sono dichiarati `uint64_t`, quindi un `<` nudo e' un
            // confronto SENZA segno e i valori negativi si comportano da grandi
            // positivi. Le `CmpU*` e le canoniche restano come prima.
            HlilExpr::CmpSlt(l, r) => self.binop_con_segno(l, "<", r),
            HlilExpr::CmpLt(l, r) | HlilExpr::CmpUlt(l, r) => self.binop(l, "<", r),
            HlilExpr::CmpSgt(l, r) => self.binop_con_segno(l, ">", r),
            HlilExpr::CmpSle(l, r) => self.binop_con_segno(l, "<=", r),
            HlilExpr::CmpSge(l, r) => self.binop_con_segno(l, ">=", r),
            HlilExpr::CmpGt(l, r) | HlilExpr::CmpUgt(l, r) => self.binop(l, ">", r),
            HlilExpr::CmpLe(l, r) | HlilExpr::CmpUle(l, r) => self.binop(l, "<=", r),
            HlilExpr::CmpGe(l, r) | HlilExpr::CmpUge(l, r) => self.binop(l, ">=", r),
            HlilExpr::Cast { expr, to, .. } => format!("(({}){})", self.type_printer.print(to), self.print(expr)),
            HlilExpr::FieldAccess { base, field, .. } => format!("{}.{field}", self.print_parens(base)),
            HlilExpr::Index { base, idx, .. } => format!("{}[{}]", self.print(base), self.print(idx)),
            HlilExpr::Call { func, args, .. } => {
                let args_s: Vec<String> = args.iter().map(|a| self.print(a)).collect();
                // #8090 - PRECEDENZA C: il callee va parentesizzato quando non e'
                // un nome semplice.
                //
                // `Call { func: Deref(X) }` nasce da `call [X]` e stampava
                // `*sub_X(args)`, che in C si legge `*(sub_X(args))` — chiama X e
                // dereferenzia il RISULTATO. L'AST significa `(*sub_X)(args)`:
                // carica il puntatore da X e chiamalo.
                //
                // L'AST era corretto a tutti i livelli a monte, verificati uno per
                // uno: x86 → LLIL emette `Call(Load(X))` (`read_operand` su
                // memoria restituisce `LlilExpr::Load`), LLIL → MLIL e MLIL → HLIL
                // traducono fedelmente. **Sbagliava solo la stampa.**
                //
                // Il difetto era coperto da `strip_star_before_named_call`, che
                // toglieva l'asterisco producendo `sub_X()` — una forma che
                // compila e sembra una chiamata normale. Misurato su `post8070`:
                // **975 siti** chiamano cosi' un indirizzo che sta in `.data`.
                //
                // `print_parens` avvolge tutto tranne `Var`/`Const`, quindi le
                // chiamate per nome restano BYTE-IDENTICHE: cambia solo il caso
                // in cui il callee e' un'espressione.
                //
                // ⚠ Verificato che `strip_star_before_named_call` NON interferisce:
                // pretende una `(` IMMEDIATAMENTE dopo l'identificatore, e nella
                // forma corretta `(*sub_X)(…)` dopo il nome viene `)`. Avevo
                // dichiarato che servisse un secondo intervento coordinato:
                // controllato, non serve.
                format!("{}({})", self.print_parens(func), args_s.join(", "))
            }
            HlilExpr::Ternary {
                cond, then, else_, ..
            } => {
                format!(
                    "({} ? {} : {})",
                    self.print(cond),
                    self.print(then),
                    self.print(else_)
                )
            }
            HlilExpr::SizeOf { ty } => format!("sizeof({})", self.type_printer.print(ty)),
            HlilExpr::ArrayIndex { array, index } => {
                format!("{}[{}]", self.print(array), self.print(index))
            }
            HlilExpr::Undefined(..) => "/* undefined */".into(),
            HlilExpr::If {
                cond,
                then_branch,
                else_branch,
            } => {
                format!(
                    "({} ? {} : {})",
                    self.print(cond),
                    self.print(then_branch),
                    self.print(else_branch)
                )
            }
        }
    }

    fn binop(&self, l: &HlilExpr, op: &str, r: &HlilExpr) -> String {
        format!("({} {} {})", self.print(l), op, self.print(r))
    }

    /// Come [`Self::binop`], ma forza il confronto CON SEGNO.
    ///
    /// #7140 — necessario perche le variabili di path B sono dichiarate
    /// `uint64_t`: un `<` nudo fra due di esse e un confronto SENZA segno, e un
    /// valore negativo si comporta da grande positivo. Il cast a `int64_t` e la
    /// sola forma che esprime in C il `cmovl`/`jl` dell originale.
    fn binop_con_segno(&self, l: &HlilExpr, op: &str, r: &HlilExpr) -> String {
        // ⚠ Una COSTANTE non ha bisogno del cast: `5` e gia un intero con
        // segno, e `(int64_t)5` aggiunge solo rumore. Castare il lato
        // variabile basta a rendere con segno l intero confronto, perche le
        // conversioni aritmetiche usuali promuovono l altro operando.
        // Il test `hlil_folds_flag_combo_idioms_into_comparisons` asserisce
        // `"< 5"`, e ha fatto notare proprio questo.
        let cast = |e: &HlilExpr| -> String {
            if matches!(e, HlilExpr::Const { .. }) {
                self.print(e)
            } else {
                format!("(int64_t){}", self.print_parens(e))
            }
        };
        format!("({} {} {})", cast(l), op, cast(r))
    }

    /// Emit `expr`, wrapping in parentheses when needed for unary prefix ops.
    fn print_parens(&self, expr: &HlilExpr) -> String {
        let s = self.print(expr);
        if matches!(expr, HlilExpr::Var { .. } | HlilExpr::Const { .. }) {
            s
        } else {
            format!("({s})")
        }
    }
}

// ---------------------------------------------------------------------------
// StmtPrinter
// ---------------------------------------------------------------------------

/// Converts [`HlilStmt`] values to C statement strings, managing indentation.
#[derive(Debug)]
pub struct StmtPrinter {
    expr_printer: ExprPrinter,
    type_printer: TypePrinter,
    indent: IndentLevel,
    config: DecompilerConfig,
    output: String,
}

impl StmtPrinter {
    /// Create a [`StmtPrinter`] with the given config.
    #[must_use]
    pub fn new(config: DecompilerConfig) -> Self {
        let tp = if config.stdint_names {
            TypePrinter::stdint()
        } else {
            TypePrinter::traditional()
        };
        Self {
            expr_printer: ExprPrinter::new(tp.clone()),
            type_printer: tp,
            indent: IndentLevel::new(config.indent_str.clone()),
            config,
            output: String::new(),
        }
    }

    /// Emit all statements in `stmts` into the output buffer.
    pub fn emit_stmts(&mut self, stmts: &[HlilStmt]) {
        for stmt in stmts {
            self.emit_stmt(stmt);
        }
    }

    /// Drain the output buffer and return the accumulated string.
    pub fn take_output(&mut self) -> String {
        std::mem::take(&mut self.output)
    }

    fn line(&mut self, s: &str) {
        let _ = writeln!(self.output, "{}{s}", self.indent.prefix());
    }

    pub fn emit_stmt(&mut self, stmt: &HlilStmt) {
        match stmt {
            HlilStmt::Assign { dest, src } => {
                let lhs = self.expr_printer.print(dest);
                let rhs = self.expr_printer.print(src);
                self.line(&format!("{lhs} = {rhs};"));
            }

            HlilStmt::AssignUnpack { dests, src } => {
                let rhs = self.expr_printer.print(src);
                let lhs: Vec<String> = dests
                    .iter()
                    .map(|d| self.expr_printer.print(&HlilExpr::Var { var: d.clone() }))
                    .collect();
                self.line(&format!("({}) = {rhs};", lhs.join(", ")));
            }

            HlilStmt::VarDecl { var, ty, init } => {
                let ty_s = self.type_printer.print(ty);
                if let Some(init_expr) = init {
                    let val = self.expr_printer.print(init_expr);
                    self.line(&format!("{ty_s} {} = {val};", var.name));
                } else {
                    self.line(&format!("{ty_s} {};", var.name));
                }
            }

            HlilStmt::VarDeclare { var, init } => {
                let ty_s = self.type_printer.print(&var.ty);
                if let Some(init_expr) = init {
                    let val = self.expr_printer.print(init_expr);
                    self.line(&format!("{ty_s} {} = {val};", var.name));
                } else {
                    self.line(&format!("{ty_s} {};", var.name));
                }
            }

            HlilStmt::Return(exprs) => {
                if exprs.is_empty() {
                    self.line("return;");
                } else {
                    let s = exprs
                        .iter()
                        .map(|e| self.expr_printer.print(e))
                        .collect::<Vec<_>>()
                        .join(", ");
                    self.line(&format!("return {s};"));
                }
            }

            HlilStmt::If {
                cond,
                then_body,
                else_body,
            } => {
                let cond_s = self.expr_printer.print(cond);
                self.line(&format!("if ({cond_s}) {{"));
                self.indent.push();
                self.emit_stmts(then_body);
                self.indent.pop();
                if !else_body.is_empty() {
                    self.line("} else {");
                    self.indent.push();
                    self.emit_stmts(else_body);
                    self.indent.pop();
                }
                self.line("}");
                if self.config.blank_lines {
                    let _ = writeln!(self.output);
                }
            }

            HlilStmt::While { cond, body } => {
                let cond_s = self.expr_printer.print(cond);
                self.line(&format!("while ({cond_s}) {{"));
                self.indent.push();
                self.emit_stmts(body);
                self.indent.pop();
                self.line("}");
                if self.config.blank_lines {
                    let _ = writeln!(self.output);
                }
            }

            HlilStmt::DoWhile { body, cond } => {
                self.line("do {");
                self.indent.push();
                self.emit_stmts(body);
                self.indent.pop();
                let cond_s = self.expr_printer.print(cond);
                self.line(&format!("}} while ({cond_s});"));
                if self.config.blank_lines {
                    let _ = writeln!(self.output);
                }
            }

            HlilStmt::For {
                init,
                cond,
                step,
                body,
            } => {
                let init_s = init.as_ref().map(|s| format!("{s}")).unwrap_or_default();
                let cond_s = cond
                    .as_ref()
                    .map(|e| self.expr_printer.print(e))
                    .unwrap_or_default();
                let update_s = step
                    .as_ref()
                    .map(|e| self.expr_printer.print(e))
                    .unwrap_or_default();
                self.line(&format!("for ({init_s}; {cond_s}; {update_s}) {{"));
                self.indent.push();
                self.emit_stmts(body);
                self.indent.pop();
                self.line("}");
                if self.config.blank_lines {
                    let _ = writeln!(self.output);
                }
            }

            HlilStmt::Switch { value,
                cases,
                default,
            } => {
                let val_s = self.expr_printer.print(value);
                self.line(&format!("switch ({val_s}) {{"));
                for case in cases {
                    for v in &case.values {
                        self.line(&format!("case {v}:"));
                    }
                    self.indent.push();
                    self.emit_stmts(&case.body);
                    self.line("break;");
                    self.indent.pop();
                }
                if !default.is_empty() {
                    self.line("default:");
                    self.indent.push();
                    self.emit_stmts(default);
                    self.indent.pop();
                }
                self.line("}");
                if self.config.blank_lines {
                    let _ = writeln!(self.output);
                }
            }

            HlilStmt::Break => self.line("break;"),
            HlilStmt::Continue => self.line("continue;"),
            HlilStmt::Goto(lbl) => self.line(&format!("goto {lbl};")),
            HlilStmt::Label(lbl) => {
                // Labels are unindented.
                let _ = writeln!(self.output, "{lbl}:");
            }

            HlilStmt::Expr(e) | HlilStmt::Expression(e) => {
                let s = self.expr_printer.print(e);
                self.line(&format!("{s};"));
            }

            HlilStmt::Block(stmts) => {
                self.line("{");
                self.indent.push();
                self.emit_stmts(stmts);
                self.indent.pop();
                self.line("}");
            }

            HlilStmt::Nop => {}
        }
    }
}

// ---------------------------------------------------------------------------
// CodegenContext
// ---------------------------------------------------------------------------

/// Context shared across the code generation phase.
#[derive(Debug)]
pub struct CodegenContext {
    /// Symbol id → C name.
    pub symbols: HashMap<u32, String>,
    /// Config for this run.
    pub config: DecompilerConfig,
    /// Counter for fresh temporaries.
    pub temp_counter: usize,
}

impl CodegenContext {
    #[must_use]
    pub fn new(config: DecompilerConfig) -> Self {
        Self {
            symbols: HashMap::new(),
            config,
            temp_counter: 0,
        }
    }

    /// Allocate a fresh temporary name (`tmp_0`, `tmp_1`, …).
    pub fn fresh_temp(&mut self) -> String {
        let n = self.temp_counter;
        self.temp_counter += 1;
        format!("tmp_{n}")
    }

    /// Register a name for `var_id`.
    pub fn register_name(&mut self, var_id: u32, name: String) {
        self.symbols.insert(var_id, name);
    }

    /// Look up the C name for `var_id`, returning a default if unregistered.
    #[must_use]
    pub fn name_of(&self, var_id: u32) -> String {
        self.symbols
            .get(&var_id)
            .cloned()
            .unwrap_or_else(|| format!("v{var_id}"))
    }
}

// ---------------------------------------------------------------------------
// PseudocodeOutput
// ---------------------------------------------------------------------------

/// The result of a decompilation run.
#[derive(Debug, Clone)]
pub struct PseudocodeOutput {
    /// The generated C pseudocode string.
    pub code: String,
    /// Warnings emitted during decompilation.
    pub warnings: Vec<String>,
    /// Number of statements emitted.
    pub stmt_count: usize,
}

impl fmt::Display for PseudocodeOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.code)
    }
}

// ---------------------------------------------------------------------------
// HlilDecompiler
// ---------------------------------------------------------------------------

/// Main decompiler: converts an [`HlilFunction`] to a [`PseudocodeOutput`].
#[derive(Debug)]
pub struct HlilDecompiler {
    pub config: DecompilerConfig,
}

impl HlilDecompiler {
    /// Create a decompiler with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: DecompilerConfig::default(),
        }
    }

    /// Create a decompiler with custom configuration.
    #[must_use]
    pub const fn with_config(config: DecompilerConfig) -> Self {
        Self { config }
    }

    /// Decompile `func` to pseudocode.
    #[must_use] 
    pub fn decompile(&self, func: &HlilFunction) -> PseudocodeOutput {
        let mut warnings = Vec::new();
        let mut output = String::new();

        // Banner.
        if self.config.banner {
            let _ = writeln!(output, "/* Decompiled by RustRE */");
        }

        // Function signature.
        let tp = if self.config.stdint_names {
            TypePrinter::stdint()
        } else {
            TypePrinter::traditional()
        };
        let ret_s = tp.print(&func.prototype.return_type);
        let params_s = func
            .prototype
            .params
            .iter()
            .map(|p| format!("{} {}", tp.print(&p.ty), p.name))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            output,
            "{ret_s} {name}({params_s}) {{",
            name = func.prototype.name
        );

        // Local variable declarations.
        if self.config.annotate_types {
            for local in &func.locals {
                let ty_s = tp.print(&local.ty);
                let _ = writeln!(output, "    {ty_s} {};", local.name);
            }
            if !func.locals.is_empty() && self.config.blank_lines {
                let _ = writeln!(output);
            }
        }

        // Body statements.
        let mut stmt_printer = StmtPrinter::new(self.config.clone());
        stmt_printer.indent.push(); // inside function body
        stmt_printer.emit_stmts(&func.body);
        let body_text = stmt_printer.take_output();

        if body_text.trim().is_empty() {
            warnings.push("function body is empty".into());
        }
        output.push_str(&body_text);

        let _ = writeln!(output, "}}");

        let stmt_count = func.body.len();
        PseudocodeOutput {
            code: output,
            warnings,
            stmt_count,
        }
    }
}

impl Default for HlilDecompiler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DecompilerPipeline — multi-function batch decompiler
// ---------------------------------------------------------------------------

/// Decompiles multiple functions and collects the combined output.
#[derive(Debug)]
pub struct DecompilerPipeline {
    decompiler: HlilDecompiler,
    outputs: Vec<(String, PseudocodeOutput)>,
}

impl DecompilerPipeline {
    /// Create a pipeline with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            decompiler: HlilDecompiler::new(),
            outputs: Vec::new(),
        }
    }

    /// Create a pipeline with a custom configuration.
    #[must_use]
    pub const fn with_config(config: DecompilerConfig) -> Self {
        Self {
            decompiler: HlilDecompiler::with_config(config),
            outputs: Vec::new(),
        }
    }

    /// Decompile `func` and add the output to the pipeline's output buffer.
    pub fn add(&mut self, func: &HlilFunction) {
        let out = self.decompiler.decompile(func);
        self.outputs.push((func.prototype.name.clone(), out));
    }

    /// Total number of decompiled functions.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.outputs.len()
    }

    /// Combine all outputs into one string, separated by blank lines.
    #[must_use]
    pub fn combined_output(&self) -> String {
        self.outputs
            .iter()
            .map(|(_, o)| o.code.clone())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Functions that produced warnings.
    #[must_use]
    pub fn functions_with_warnings(&self) -> Vec<&str> {
        self.outputs
            .iter()
            .filter(|(_, o)| !o.warnings.is_empty())
            .map(|(name, _)| name.as_str())
            .collect()
    }
}

impl Default for DecompilerPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TypePrinterConfig — alternate constructor pattern
// ---------------------------------------------------------------------------

impl TypePrinter {
    /// Create a [`TypePrinter`] from a [`DecompilerConfig`].
    #[must_use]
    pub const fn from_config(config: &DecompilerConfig) -> Self {
        if config.stdint_names {
            Self::stdint()
        } else {
            Self::traditional()
        }
    }
}

// ---------------------------------------------------------------------------
// ExprComplexity — metrics on expression complexity
// ---------------------------------------------------------------------------

/// Measures complexity metrics of an [`HlilExpr`] tree.
pub struct ExprComplexity;

impl ExprComplexity {
    /// Depth of the expression tree (leaf = 1).
    #[must_use]
    pub fn depth(expr: &HlilExpr) -> usize {
        match expr {
            HlilExpr::Const { .. }
            | HlilExpr::ConstFloat(_)
            | HlilExpr::Float { .. }
            | HlilExpr::Var { .. }
            | HlilExpr::AddressOf { .. }
            | HlilExpr::SizeOf { .. }
            | HlilExpr::Undefined(..) => 1,

            HlilExpr::Add(l, r, ..)
            | HlilExpr::Sub(l, r, ..)
            | HlilExpr::Mul(l, r, ..)
            | HlilExpr::Div(l, r, ..)
            | HlilExpr::Mod(l, r, ..)
            | HlilExpr::DivU(l, r)
            | HlilExpr::DivS(l, r)
            | HlilExpr::ModU(l, r)
            | HlilExpr::ModS(l, r)
            | HlilExpr::And(l, r, ..)
            | HlilExpr::Or(l, r, ..)
            | HlilExpr::Xor(l, r, ..)
            | HlilExpr::BitAnd(l, r)
            | HlilExpr::BitOr(l, r)
            | HlilExpr::BitXor(l, r)
            | HlilExpr::Shl(l, r, ..)
            | HlilExpr::Shr(l, r, ..)
            | HlilExpr::Sar(l, r)
            | HlilExpr::BoolAnd(l, r)
            | HlilExpr::BoolOr(l, r)
            | HlilExpr::LogicalAnd(l, r)
            | HlilExpr::LogicalOr(l, r)
            | HlilExpr::CmpEq(l, r)
            | HlilExpr::CmpNe(l, r)
            | HlilExpr::CmpLt(l, r)
            | HlilExpr::CmpGt(l, r)
            | HlilExpr::CmpLe(l, r)
            | HlilExpr::CmpGe(l, r)
            | HlilExpr::CmpSlt(l, r)
            | HlilExpr::CmpUlt(l, r)
            | HlilExpr::CmpSle(l, r)
            | HlilExpr::CmpUle(l, r)
            | HlilExpr::CmpSgt(l, r)
            | HlilExpr::CmpUgt(l, r)
            | HlilExpr::CmpSge(l, r)
            | HlilExpr::CmpUge(l, r) => 1 + Self::depth(l).max(Self::depth(r)),

            HlilExpr::Neg(e, ..)
            | HlilExpr::Not(e, ..)
            | HlilExpr::BoolNot(e)
            | HlilExpr::LogicalNot(e)
            | HlilExpr::AddrOf(e)
            | HlilExpr::Deref { addr: e, .. } | HlilExpr::Cast { expr: e, .. } | HlilExpr::FieldAccess { base: e, .. }
            | HlilExpr::ArrayIndex { array: e, .. }
            | HlilExpr::Index { base: e, .. } => 1 + Self::depth(e),

            HlilExpr::Call { func, args, .. } => {
                let arg_depth = args.iter().map(Self::depth).max().unwrap_or(0);
                1 + Self::depth(func).max(arg_depth)
            }

            HlilExpr::Ternary {
                cond, then, else_, ..
            } => {
                1 + Self::depth(cond)
                    .max(Self::depth(then))
                    .max(Self::depth(else_))
            }

            HlilExpr::If {
                cond,
                then_branch,
                else_branch,
            } => {
                1 + Self::depth(cond)
                    .max(Self::depth(then_branch))
                    .max(Self::depth(else_branch))
            }
        }
    }

    /// Total node count of the expression tree.
    #[must_use]
    pub fn node_count(expr: &HlilExpr) -> usize {
        match expr {
            HlilExpr::Const { .. }
            | HlilExpr::ConstFloat(_)
            | HlilExpr::Float { .. }
            | HlilExpr::Var { .. }
            | HlilExpr::AddressOf { .. }
            | HlilExpr::SizeOf { .. }
            | HlilExpr::Undefined(..) => 1,

            HlilExpr::Add(l, r, ..)
            | HlilExpr::Sub(l, r, ..)
            | HlilExpr::Mul(l, r, ..)
            | HlilExpr::Div(l, r, ..)
            | HlilExpr::Mod(l, r, ..)
            | HlilExpr::DivU(l, r)
            | HlilExpr::DivS(l, r)
            | HlilExpr::ModU(l, r)
            | HlilExpr::ModS(l, r)
            | HlilExpr::And(l, r, ..)
            | HlilExpr::Or(l, r, ..)
            | HlilExpr::Xor(l, r, ..)
            | HlilExpr::BitAnd(l, r)
            | HlilExpr::BitOr(l, r)
            | HlilExpr::BitXor(l, r)
            | HlilExpr::Shl(l, r, ..)
            | HlilExpr::Shr(l, r, ..)
            | HlilExpr::Sar(l, r)
            | HlilExpr::BoolAnd(l, r)
            | HlilExpr::BoolOr(l, r)
            | HlilExpr::LogicalAnd(l, r)
            | HlilExpr::LogicalOr(l, r)
            | HlilExpr::CmpEq(l, r)
            | HlilExpr::CmpNe(l, r)
            | HlilExpr::CmpLt(l, r)
            | HlilExpr::CmpGt(l, r)
            | HlilExpr::CmpLe(l, r)
            | HlilExpr::CmpGe(l, r)
            | HlilExpr::CmpSlt(l, r)
            | HlilExpr::CmpUlt(l, r)
            | HlilExpr::CmpSle(l, r)
            | HlilExpr::CmpUle(l, r)
            | HlilExpr::CmpSgt(l, r)
            | HlilExpr::CmpUgt(l, r)
            | HlilExpr::CmpSge(l, r)
            | HlilExpr::CmpUge(l, r) => 1 + Self::node_count(l) + Self::node_count(r),

            HlilExpr::Neg(e, ..)
            | HlilExpr::Not(e, ..)
            | HlilExpr::BoolNot(e)
            | HlilExpr::LogicalNot(e)
            | HlilExpr::AddrOf(e)
            | HlilExpr::Deref { addr: e, .. } | HlilExpr::Cast { expr: e, .. } | HlilExpr::FieldAccess { base: e, .. }
            | HlilExpr::ArrayIndex { array: e, .. }
            | HlilExpr::Index { base: e, .. } => 1 + Self::node_count(e),

            HlilExpr::Call { func, args, .. } => {
                1 + Self::node_count(func) + args.iter().map(Self::node_count).sum::<usize>()
            }

            HlilExpr::Ternary {
                cond, then, else_, ..
            } => 1 + Self::node_count(cond) + Self::node_count(then) + Self::node_count(else_),

            HlilExpr::If {
                cond,
                then_branch,
                else_branch,
            } => {
                1 + Self::node_count(cond)
                    + Self::node_count(then_branch)
                    + Self::node_count(else_branch)
            }
        }
    }
}

/// Counts statement kinds in an HLIL body.
#[derive(Debug, Clone, Default)]
pub struct StatementCounter {
    pub assignments: usize,
    pub conditionals: usize,
    pub loops: usize,
    pub returns: usize,
    pub calls: usize,
    pub gotos: usize,
}

impl StatementCounter {
    /// Count statement categories in `stmts`.
    #[must_use] 
    pub fn count(stmts: &[HlilStmt]) -> Self {
        let mut c = Self::default();
        for stmt in stmts {
            c.count_stmt(stmt);
        }
        c
    }

    fn count_stmt(&mut self, stmt: &HlilStmt) {
        match stmt {
            HlilStmt::Assign { .. } | HlilStmt::VarDecl { .. } | HlilStmt::AssignUnpack { .. } => {
                self.assignments += 1;
            }
            HlilStmt::Return(_) => self.returns += 1,
            HlilStmt::If {
                then_body,
                else_body,
                ..
            } => {
                self.conditionals += 1;
                for s in then_body {
                    self.count_stmt(s);
                }
                for s in else_body {
                    self.count_stmt(s);
                }
            }
            HlilStmt::While { body, .. } | HlilStmt::DoWhile { body, .. } | HlilStmt::For { body, .. } => {
                self.loops += 1;
                for s in body {
                    self.count_stmt(s);
                }
            }
            HlilStmt::Expr(HlilExpr::Call { .. }) => self.calls += 1,
            HlilStmt::Goto(_) => self.gotos += 1,
            _ => {}
        }
    }

    /// Total counted statements.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.assignments + self.conditionals + self.loops + self.returns + self.calls + self.gotos
    }
}

// ---------------------------------------------------------------------------
// DecompilerCache — caches decompiled outputs to avoid recomputation
// ---------------------------------------------------------------------------

/// A simple cache keyed by function address.
#[derive(Debug, Default)]
pub struct DecompilerCache {
    cache: std::collections::HashMap<u64, PseudocodeOutput>,
}

impl DecompilerCache {
    #[must_use]
    pub fn get(&self, addr: u64) -> Option<&PseudocodeOutput> {
        self.cache.get(&addr)
    }

    /// Store a decompiled output.
    pub fn put(&mut self, addr: u64, output: PseudocodeOutput) {
        self.cache.insert(addr, output);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Invalidate a cached entry.
    pub fn invalidate(&mut self, addr: u64) {
        self.cache.remove(&addr);
    }
}

// ---------------------------------------------------------------------------
// NameDemangler — demangles C++ names for display
// ---------------------------------------------------------------------------

/// A trivial name demangler (placeholder for a real implementation).
#[derive(Debug, Default)]
pub struct NameDemangler;

impl NameDemangler {
    /// Attempt to demangle `name`; returns `name` unchanged if not mangled.
    #[must_use]
    pub fn demangle(name: &str) -> String {
        // Detect obvious C++ mangling prefix.
        if name.starts_with("_Z") {
            format!("/* demangled */ {name}")
        } else {
            name.to_owned()
        }
    }
}

// ---------------------------------------------------------------------------
// CodeMetrics — lines / statements / complexity from pseudocode
// ---------------------------------------------------------------------------

/// Computes simple metrics from a [`PseudocodeOutput`].
#[derive(Debug, Clone, Default)]
pub struct CodeMetrics {
    pub total_lines: usize,
    pub blank_lines: usize,
    pub comment_lines: usize,
    pub code_lines: usize,
    pub stmt_count: usize,
}

impl CodeMetrics {
    /// Compute metrics from `output`.
    #[must_use]
    pub fn from_output(output: &PseudocodeOutput) -> Self {
        let mut m = Self {
            total_lines: output.code.lines().count(),
            stmt_count: output.stmt_count,
            ..Self::default()
        };
        for line in output.code.lines() {
            let t = line.trim();
            if t.is_empty() {
                m.blank_lines += 1;
            } else if t.starts_with("/*") || t.starts_with("//") {
                m.comment_lines += 1;
            } else {
                m.code_lines += 1;
            }
        }
        m
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HlilExpr, HlilFunction, HlilPrototype, HlilStatement as HlilStmt, HlilType, HlilVar, SwitchCase};
    use rustre_core::Address;

    /// #7140/#7150 — le varianti CON SEGNO si stampano coi cast, quelle SENZA
    /// segno no.
    ///
    /// Il difetto che questo test blocca: le famiglie erano appiattite sulla
    /// forma canonica (`CmpLt|CmpSlt|CmpUlt => "<"`, `Shr|Sar => ">>"`), quindi
    /// il segno lo decideva il TIPO delle variabili — che in path B e'
    /// `uint64_t`. Su `find_max` il binario fa `cmovl` (con segno) e l'emesso
    /// confrontava senza segno: con valori negativi il massimo non veniva mai
    /// aggiornato. Misurati 573 shift aritmetici resi logici e ~6700 confronti
    /// resi senza segno.
    #[test]
    fn confronti_e_shift_con_segno_portano_il_cast() {
        let p = ExprPrinter::new(TypePrinter::stdint());
        let a = var("a");
        let b = var("b");
        let cinque = HlilExpr::Const { value: 5, ty: HlilType::i64() };

        // CON segno → cast su entrambi i lati variabili.
        assert_eq!(
            p.print(&HlilExpr::CmpSlt(Box::new(a.clone()), Box::new(b.clone()))),
            "((int64_t)a < (int64_t)b)"
        );
        // SENZA segno → nessun cast.
        assert_eq!(
            p.print(&HlilExpr::CmpUlt(Box::new(a.clone()), Box::new(b.clone()))),
            "(a < b)"
        );
        // Canonica → invariata, cosi' un cambio di numeri non puo' venire da qui.
        assert_eq!(
            p.print(&HlilExpr::CmpLt(Box::new(a.clone()), Box::new(b.clone()))),
            "(a < b)"
        );

        // ⚠ Una COSTANTE non si casta: `(int64_t)5` sarebbe solo rumore, e le
        // conversioni aritmetiche usuali promuovono comunque l'altro operando.
        assert_eq!(
            p.print(&HlilExpr::CmpSlt(Box::new(a.clone()), Box::new(cinque))),
            "((int64_t)a < 5)"
        );

        // #7160 — la LARGHEZZA decide il cast. `(int64_t)(uint32_t)v` NON
        // ripristina il segno: il troncamento a 32 bit e gia avvenuto e per
        // v = -1 da 4294967295. Serve `(int32_t)`, che reinterpreta gli stessi
        // bit con segno. La larghezza si legge dalla variante `Cast { to }`.
        let a32 = HlilExpr::Cast {
            expr: Box::new(a.clone()),
            to: HlilType::Int { signed: false, bits: 32 },
        };
        assert_eq!(
            format!("{}", HlilExpr::CmpSlt(Box::new(a32.clone()), Box::new(a32))),
            "((int32_t)(uint32_t)a < (int32_t)(uint32_t)a)"
        );

        // `Sar` e' lo shift ARITMETICO: cast SOLO a sinistra, perche' la
        // quantita' di shift e' non negativa per costruzione.
        assert_eq!(
            p.print(&HlilExpr::Sar(Box::new(a.clone()), Box::new(HlilExpr::Const {
                value: 5,
                ty: HlilType::i64()
            }))),
            "((int64_t)a >> 5)"
        );
        // `Shr` e' LOGICO e deve restare senza cast: e' la meta' del corpus.
        assert_eq!(
            p.print(&HlilExpr::Shr(
                Box::new(a.clone()),
                Box::new(HlilExpr::Const { value: 5, ty: HlilType::i64() }),
                HlilType::i64()
            )),
            "(a >> 5)"
        );

        // ⚠ E il percorso `Display`, che e una SECONDA stampa.
        //
        // Il test copriva solo `ExprPrinter` e passava, mentre `Display`
        // castava un lato solo: `(int64_t)v1 < a1`. In C NON basta — con
        // l altro operando `uint64_t` le conversioni usuali riportano il
        // confronto a senza segno. Difetto trovato leggendo l emesso di
        // `find_max`, non dai test: e la stessa forma del difetto originale,
        // dove il segno cadeva in DUE punti e sistemarne uno non serviva.
        assert_eq!(
            format!("{}", HlilExpr::CmpSlt(Box::new(a.clone()), Box::new(b.clone()))),
            "((int64_t)a < (int64_t)b)"
        );
        assert_eq!(
            format!("{}", HlilExpr::CmpUlt(Box::new(a.clone()), Box::new(b))),
            "(a < b)"
        );
        assert_eq!(
            format!("{}", HlilExpr::Sar(Box::new(a), Box::new(HlilExpr::Const {
                value: 5,
                ty: HlilType::i64()
            }))),
            "((int64_t)a >> 5)"
        );
    }

    fn var(name: &str) -> HlilExpr {
        HlilExpr::Var {
            var: HlilVar {
                name: name.into(),
                ty: HlilType::Unknown,
                is_param: false,
                stack_offset: None,
                version: 0,
                is_ssa: false,
            },
        }
    }

    fn konst(v: i64) -> HlilExpr {
        HlilExpr::Const {
            value: v,
            ty: HlilType::i32(),
        }
    }

    fn make_func(name: &str, body: Vec<HlilStmt>) -> HlilFunction {
        HlilFunction {
            address: Address(0),
            prototype: HlilPrototype {
                name: name.into(),
                return_type: HlilType::Void,
                params: vec![],
                is_variadic: false,
                calling_convention: None,
            },
            return_type: HlilType::Void,
            locals: vec![],
            body,
            lifted_from: None,
        }
    }

    // --- IndentLevel tests ---

    #[test]
    fn indent_level_push_pop() {
        let mut lvl = IndentLevel::new("  ");
        assert_eq!(lvl.depth(), 0);
        lvl.push();
        assert_eq!(lvl.depth(), 1);
        assert_eq!(lvl.prefix(), "  ");
        lvl.pop();
        assert_eq!(lvl.depth(), 0);
    }

    #[test]
    fn indent_level_underflow() {
        let mut lvl = IndentLevel::new("    ");
        lvl.pop(); // should not panic
        assert_eq!(lvl.depth(), 0);
    }

    #[test]
    fn indent_level_indented_closure() {
        let mut lvl = IndentLevel::new("  ");
        lvl.indented(|l| {
            assert_eq!(l.depth(), 1);
        });
        assert_eq!(lvl.depth(), 0);
    }

    #[test]
    fn indent_level_triple_depth() {
        let mut lvl = IndentLevel::new("\t");
        lvl.push();
        lvl.push();
        lvl.push();
        assert_eq!(lvl.prefix(), "\t\t\t");
    }

    // --- TypePrinter tests ---

    #[test]
    fn type_printer_void() {
        let tp = TypePrinter::stdint();
        assert_eq!(tp.print(&HlilType::Void), "void");
    }

    #[test]
    fn type_printer_bool() {
        let tp = TypePrinter::stdint();
        assert_eq!(tp.print(&HlilType::Bool), "bool");
    }

    #[test]
    fn type_printer_i32_stdint() {
        let tp = TypePrinter::stdint();
        assert_eq!(tp.print(&HlilType::i32()), "int32_t");
    }

    #[test]
    fn type_printer_u64_stdint() {
        let tp = TypePrinter::stdint();
        assert_eq!(tp.print(&HlilType::u64()), "uint64_t");
    }

    #[test]
    fn type_printer_i32_traditional() {
        let tp = TypePrinter::traditional();
        assert_eq!(tp.print(&HlilType::i32()), "int");
    }

    #[test]
    fn type_printer_pointer() {
        let tp = TypePrinter::stdint();
        let ty = HlilType::ptr(HlilType::i32(), 64);
        assert!(tp.print(&ty).contains('*'));
    }

    #[test]
    fn type_printer_array_fixed() {
        let tp = TypePrinter::stdint();
        let ty = HlilType::Array {
            elem: Box::new(HlilType::i32()),
            count: Some(10),
        };
        let s = tp.print(&ty);
        assert!(s.contains("[10]"));
    }

    #[test]
    fn type_printer_struct() {
        let tp = TypePrinter::stdint();
        let ty = HlilType::Struct { name: "Foo".into() };
        assert_eq!(tp.print(&ty), "struct Foo");
    }

    #[test]
    fn type_printer_float32() {
        let tp = TypePrinter::stdint();
        assert_eq!(tp.print(&HlilType::Float { bits: 32 }), "float");
    }

    #[test]
    fn type_printer_double() {
        let tp = TypePrinter::stdint();
        assert_eq!(tp.print(&HlilType::Float { bits: 64 }), "double");
    }

    // --- ExprPrinter tests ---

    #[test]
    fn expr_printer_const() {
        let ep = ExprPrinter::default();
        assert_eq!(ep.print(&konst(42)), "42");
    }

    #[test]
    fn expr_printer_var() {
        let ep = ExprPrinter::default();
        assert_eq!(ep.print(&var("x")), "x");
    }

    #[test]
    fn expr_printer_add() {
        let ep = ExprPrinter::default();
        let e = HlilExpr::Add(Box::new(var("a")), Box::new(var("b")), HlilType::i32());
        assert_eq!(ep.print(&e), "(a + b)");
    }

    #[test]
    fn expr_printer_cmp_eq() {
        let ep = ExprPrinter::default();
        let e = HlilExpr::CmpEq(Box::new(var("x")), Box::new(konst(0)));
        assert_eq!(ep.print(&e), "(x == 0)");
    }

    #[test]
    fn expr_printer_ternary() {
        let ep = ExprPrinter::default();
        let e = HlilExpr::Ternary {
            cond: Box::new(var("c")),
            then: Box::new(konst(1)),
            else_: Box::new(konst(0)),
            ty: HlilType::i32(),
        };
        let s = ep.print(&e);
        assert!(s.contains('?') && s.contains(':'));
    }

    #[test]
    fn expr_printer_call_no_args() {
        let ep = ExprPrinter::default();
        let e = HlilExpr::Call {
            func: Box::new(var("foo")),
            args: vec![],
            ret_ty: HlilType::Void,
        };
        assert_eq!(ep.print(&e), "foo()");
    }

    #[test]
    fn expr_printer_call_with_args() {
        let ep = ExprPrinter::default();
        let e = HlilExpr::Call {
            func: Box::new(var("bar")),
            args: vec![var("x"), konst(1)],
            ret_ty: HlilType::Void,
        };
        let s = ep.print(&e);
        assert!(s.contains("bar(") && s.contains('x') && s.contains('1'));
    }

    #[test]
    fn expr_printer_field_access() {
        let ep = ExprPrinter::default();
        let e = HlilExpr::FieldAccess {
            base: Box::new(var("obj")),
            field: "member".into(),
            ty: HlilType::Unknown,
        };
        assert!(ep.print(&e).contains(".member"));
    }

    #[test]
    fn expr_printer_array_index() {
        let ep = ExprPrinter::default();
        let e = HlilExpr::ArrayIndex {
            array: Box::new(var("arr")),
            index: Box::new(konst(3)),
        };
        assert!(ep.print(&e).contains("[3]"));
    }

    #[test]
    fn expr_printer_cast() {
        let ep = ExprPrinter::new(TypePrinter::stdint());
        let e = HlilExpr::Cast {
            to: HlilType::i32(),
            expr: Box::new(var("x")),
        };
        let s = ep.print(&e);
        assert!(s.contains("int32_t"));
    }

    #[test]
    fn expr_printer_bool_not() {
        let ep = ExprPrinter::default();
        let e = HlilExpr::BoolNot(Box::new(var("flag")));
        assert!(ep.print(&e).contains('!'));
    }

    // --- StmtPrinter tests ---

    #[test]
    fn stmt_return_expr() {
        let mut sp = StmtPrinter::new(DecompilerConfig::default());
        sp.emit_stmt(&HlilStmt::Return(vec![konst(0)]));
        let s = sp.take_output();
        assert!(s.contains("return 0;"));
    }

    #[test]
    fn stmt_return_void() {
        let mut sp = StmtPrinter::new(DecompilerConfig::default());
        sp.emit_stmt(&HlilStmt::Return(vec![]));
        let s = sp.take_output();
        assert!(s.contains("return;"));
    }

    #[test]
    fn stmt_assign() {
        let mut sp = StmtPrinter::new(DecompilerConfig::default());
        sp.emit_stmt(&HlilStmt::Assign {
            dest: var("x"),
            src: konst(5),
        });
        let s = sp.take_output();
        assert!(s.contains("x = 5;"));
    }

    #[test]
    fn stmt_if_no_else() {
        let mut sp = StmtPrinter::new(DecompilerConfig::default());
        sp.emit_stmt(&HlilStmt::If {
            cond: var("flag"),
            then_body: vec![HlilStmt::Return(vec![])],
            else_body: vec![],
        });
        let s = sp.take_output();
        assert!(s.contains("if (flag)"));
        assert!(!s.contains("else"));
    }

    #[test]
    fn stmt_if_with_else() {
        let mut sp = StmtPrinter::new(DecompilerConfig::default());
        sp.emit_stmt(&HlilStmt::If {
            cond: var("flag"),
            then_body: vec![HlilStmt::Return(vec![konst(1)])],
            else_body: vec![HlilStmt::Return(vec![konst(0)])],
        });
        let s = sp.take_output();
        assert!(s.contains("else"));
    }

    #[test]
    fn stmt_while_loop() {
        let mut sp = StmtPrinter::new(DecompilerConfig::default());
        sp.emit_stmt(&HlilStmt::While {
            cond: var("cond"),
            body: vec![HlilStmt::Continue],
        });
        let s = sp.take_output();
        assert!(s.contains("while (cond)"));
        assert!(s.contains("continue;"));
    }

    #[test]
    fn stmt_break_continue() {
        let mut sp = StmtPrinter::new(DecompilerConfig::default());
        sp.emit_stmt(&HlilStmt::Break);
        sp.emit_stmt(&HlilStmt::Continue);
        let s = sp.take_output();
        assert!(s.contains("break;"));
        assert!(s.contains("continue;"));
    }

    #[test]
    fn stmt_goto_label() {
        let mut sp = StmtPrinter::new(DecompilerConfig::default());
        sp.emit_stmt(&HlilStmt::Label("loop_head".into()));
        sp.emit_stmt(&HlilStmt::Goto(Address(0x1000)));
        let s = sp.take_output();
        assert!(s.contains("loop_head:"));
        assert!(s.contains("goto "));
    }

    // --- CodegenContext tests ---

    #[test]
    fn codegen_context_fresh_temp() {
        let mut ctx = CodegenContext::new(DecompilerConfig::default());
        assert_eq!(ctx.fresh_temp(), "tmp_0");
        assert_eq!(ctx.fresh_temp(), "tmp_1");
    }

    #[test]
    fn codegen_context_register_name() {
        let mut ctx = CodegenContext::new(DecompilerConfig::default());
        ctx.register_name(3, "my_var".into());
        assert_eq!(ctx.name_of(3), "my_var");
    }

    #[test]
    fn codegen_context_default_name() {
        let ctx = CodegenContext::new(DecompilerConfig::default());
        assert_eq!(ctx.name_of(99), "v99");
    }

    // --- HlilDecompiler tests ---

    #[test]
    fn decompiler_empty_body_warning() {
        let func = make_func("empty_fn", vec![]);
        let dec = HlilDecompiler::new();
        let out = dec.decompile(&func);
        assert!(!out.warnings.is_empty());
    }

    #[test]
    fn decompiler_simple_return() {
        let func = make_func("ret_fn", vec![HlilStmt::Return(vec![konst(42)])]);
        let dec = HlilDecompiler::new();
        let out = dec.decompile(&func);
        assert!(out.code.contains("return 42;"));
    }

    #[test]
    fn decompiler_function_signature() {
        let func = HlilFunction {
            address: Address(0),
            prototype: HlilPrototype {
                name: "compute".into(),
                return_type: HlilType::i32(),
                params: vec![HlilVar::param("n", HlilType::i32())],
                is_variadic: false,
                calling_convention: None,
            },
            return_type: HlilType::i32(),
            locals: vec![],
            body: vec![HlilStmt::Return(vec![var("n")])],
            lifted_from: None,
        };
        let dec = HlilDecompiler::new();
        let out = dec.decompile(&func);
        assert!(out.code.contains("compute"));
        assert!(out.code.contains("return n;"));
    }

    #[test]
    fn decompiler_local_decls() {
        let func = HlilFunction {
            address: Address(0),
            prototype: HlilPrototype {
                name: "with_locals".into(),
                return_type: HlilType::Void,
                params: vec![],
                is_variadic: false,
                calling_convention: None,
            },
            return_type: HlilType::Void,
            locals: vec![HlilVar::new("x", HlilType::i32())],
            body: vec![HlilStmt::Return(vec![])],
            lifted_from: None,
        };
        let dec = HlilDecompiler::new();
        let out = dec.decompile(&func);
        assert!(out.code.contains('x'));
    }

    #[test]
    fn decompiler_banner() {
        let func = make_func("f", vec![]);
        let cfg = DecompilerConfig {
            banner: true,
            ..Default::default()
        };
        let out = HlilDecompiler::with_config(cfg).decompile(&func);
        assert!(out.code.contains("Decompiled"));
    }

    #[test]
    fn decompiler_stmt_count() {
        let func = make_func("cnt", vec![HlilStmt::Nop, HlilStmt::Return(vec![])]);
        let out = HlilDecompiler::new().decompile(&func);
        assert_eq!(out.stmt_count, 2);
    }

    #[test]
    fn pseudocode_output_display() {
        let out = PseudocodeOutput {
            code: "void f() {}".into(),
            warnings: vec![],
            stmt_count: 0,
        };
        assert!(format!("{out}").contains("void f()"));
    }

    #[test]
    fn decompiler_switch() {
        let body = vec![HlilStmt::Switch {
            value: konst(1),
            cases: vec![SwitchCase {
                values: vec![1],
                body: vec![HlilStmt::Break],
            }],
            default: vec![],
        }];
        let func = make_func("sw", body);
        let out = HlilDecompiler::new().decompile(&func);
        assert!(out.code.contains("switch"));
        assert!(out.code.contains("case 1:"));
    }

    #[test]
    fn decompiler_do_while() {
        let body = vec![HlilStmt::DoWhile {
            body: vec![HlilStmt::Nop],
            cond: var("running"),
        }];
        let func = make_func("dw", body);
        let out = HlilDecompiler::new().decompile(&func);
        assert!(out.code.contains("do {"));
        assert!(out.code.contains("} while (running)"));
    }

    // --- DecompilerPipeline tests ---

    #[test]
    fn pipeline_empty() {
        let p = DecompilerPipeline::new();
        assert_eq!(p.count(), 0);
    }

    #[test]
    fn pipeline_add_and_count() {
        let mut p = DecompilerPipeline::new();
        p.add(&make_func("f1", vec![]));
        p.add(&make_func("f2", vec![]));
        assert_eq!(p.count(), 2);
    }

    #[test]
    fn pipeline_combined_output() {
        let mut p = DecompilerPipeline::new();
        p.add(&make_func("f1", vec![HlilStmt::Return(vec![])]));
        let out = p.combined_output();
        assert!(out.contains("f1"));
    }

    #[test]
    fn pipeline_functions_with_warnings() {
        let mut p = DecompilerPipeline::new();
        p.add(&make_func("empty", vec![])); // empty body → warning
        assert_eq!(p.functions_with_warnings().len(), 1);
    }

    // --- TypePrinter::from_config ---

    #[test]
    fn type_printer_from_config_stdint() {
        let cfg = DecompilerConfig {
            stdint_names: true,
            ..Default::default()
        };
        let tp = TypePrinter::from_config(&cfg);
        assert_eq!(tp.print(&HlilType::i32()), "int32_t");
    }

    #[test]
    fn type_printer_from_config_traditional() {
        let cfg = DecompilerConfig {
            stdint_names: false,
            ..Default::default()
        };
        let tp = TypePrinter::from_config(&cfg);
        assert_eq!(tp.print(&HlilType::i32()), "int");
    }

    // --- ExprComplexity tests ---

    #[test]
    fn expr_complexity_leaf_depth() {
        assert_eq!(ExprComplexity::depth(&konst(0)), 1);
        assert_eq!(ExprComplexity::depth(&var("x")), 1);
    }

    #[test]
    fn expr_complexity_add_depth() {
        let e = HlilExpr::Add(Box::new(var("a")), Box::new(var("b")), HlilType::i32());
        assert_eq!(ExprComplexity::depth(&e), 2);
    }

    #[test]
    fn expr_complexity_node_count_leaf() {
        assert_eq!(ExprComplexity::node_count(&konst(0)), 1);
    }

    #[test]
    fn expr_complexity_node_count_add() {
        let e = HlilExpr::Add(Box::new(var("a")), Box::new(var("b")), HlilType::i32());
        assert_eq!(ExprComplexity::node_count(&e), 3);
    }

    #[test]
    fn expr_complexity_ternary_nodes() {
        let e = HlilExpr::Ternary {
            cond: Box::new(var("c")),
            then: Box::new(konst(1)),
            else_: Box::new(konst(0)),
            ty: HlilType::i32(),
        };
        assert_eq!(ExprComplexity::node_count(&e), 4);
    }

    // --- StatementCounter tests ---

    #[test]
    fn stmt_counter_empty() {
        let c = StatementCounter::count(&[]);
        assert_eq!(c.total(), 0);
    }

    #[test]
    fn stmt_counter_assign() {
        let stmts = vec![HlilStmt::Assign {
            dest: var("x"),
            src: konst(0),
        }];
        let c = StatementCounter::count(&stmts);
        assert_eq!(c.assignments, 1);
    }

    #[test]
    fn stmt_counter_conditional() {
        let stmts = vec![HlilStmt::If {
            cond: var("c"),
            then_body: vec![],
            else_body: vec![],
        }];
        let c = StatementCounter::count(&stmts);
        assert_eq!(c.conditionals, 1);
    }

    #[test]
    fn stmt_counter_loop() {
        let stmts = vec![HlilStmt::While {
            cond: var("c"),
            body: vec![],
        }];
        let c = StatementCounter::count(&stmts);
        assert_eq!(c.loops, 1);
    }

    #[test]
    fn stmt_counter_return() {
        let stmts = vec![HlilStmt::Return(vec![])];
        let c = StatementCounter::count(&stmts);
        assert_eq!(c.returns, 1);
    }

    // --- StmtPrinter for-loop ---

    #[test]
    fn stmt_for_loop_emitted() {
        let mut sp = StmtPrinter::new(DecompilerConfig::default());
        sp.emit_stmt(&HlilStmt::For {
            init: None,
            cond: None,
            step: None,
            body: vec![],
        });
        let s = sp.take_output();
        assert!(s.contains("for"));
    }

    // --- DecompilerCache tests ---

    #[test]
    fn cache_empty_initially() {
        let c = DecompilerCache::default();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn cache_put_get() {
        let mut c = DecompilerCache::default();
        let out = PseudocodeOutput {
            code: "void f(){}".into(),
            stmt_count: 0,
            warnings: vec![],
        };
        c.put(0x1000, out);
        assert!(c.get(0x1000).is_some());
        assert!(c.get(0x2000).is_none());
    }

    #[test]
    fn cache_invalidate() {
        let mut c = DecompilerCache::default();
        let out = PseudocodeOutput {
            code: String::new(),
            stmt_count: 0,
            warnings: vec![],
        };
        c.put(0x1000, out);
        c.invalidate(0x1000);
        assert!(c.get(0x1000).is_none());
    }

    // --- NameDemangler tests ---

    #[test]
    fn demangler_plain_name() {
        assert_eq!(NameDemangler::demangle("main"), "main");
    }

    #[test]
    fn demangler_cpp_prefix() {
        let r = NameDemangler::demangle("_Zfoo");
        assert!(r.contains("_Zfoo"));
    }

    // --- CodeMetrics tests ---

    #[test]
    fn code_metrics_empty_output() {
        let out = PseudocodeOutput {
            code: String::new(),
            stmt_count: 0,
            warnings: vec![],
        };
        let m = CodeMetrics::from_output(&out);
        assert_eq!(m.total_lines, 0);
    }

    #[test]
    fn code_metrics_counts_blanks() {
        let out = PseudocodeOutput {
            code: "int x;\n\nreturn 0;\n".into(),
            stmt_count: 2,
            warnings: vec![],
        };
        let m = CodeMetrics::from_output(&out);
        assert_eq!(m.blank_lines, 1);
    }

    // --- ExprPrinter additional ---

    #[test]
    fn expr_printer_neg() {
        let ep = ExprPrinter::default();
        let e = HlilExpr::Neg(Box::new(var("x")), HlilType::i32());
        assert!(ep.print(&e).contains("-x") || ep.print(&e).contains("(-x)"));
    }

    #[test]
    fn expr_printer_deref() {
        let ep = ExprPrinter::default();
        let e = HlilExpr::Deref {
            addr: Box::new(var("p")),
            ty: HlilType::Unknown,
        };
        assert!(ep.print(&e).contains('*'));
    }

    #[test]
    fn expr_printer_addr_of() {
        let ep = ExprPrinter::default();
        let e = HlilExpr::AddrOf(Box::new(var("x")));
        assert!(ep.print(&e).contains('&'));
    }

    // --- TypePrinter enum ---

    #[test]
    fn type_printer_enum() {
        let tp = TypePrinter::stdint();
        let ty = HlilType::Enum {
            name: "Status".into(),
        };
        assert_eq!(tp.print(&ty), "enum Status");
    }

    // --- HlilDecompiler for loop ---

    #[test]
    fn decompiler_for_loop() {
        let body = vec![HlilStmt::For {
            init: None,
            cond: None,
            step: None,
            body: vec![HlilStmt::Break],
        }];
        let func = make_func("for_fn", body);
        let out = HlilDecompiler::new().decompile(&func);
        assert!(out.code.contains("for"));
    }

    // --- IndentLevel::default ---

    #[test]
    fn indent_default_depth_zero() {
        let il = IndentLevel::default();
        assert_eq!(il.depth(), 0);
    }
}


#[cfg(test)]
mod test_precedenza_callee {
    use super::ExprPrinter;
    use crate::{HlilExpr, HlilType, HlilVar};

    fn var(n: &str) -> HlilExpr {
        HlilExpr::Var {
            var: HlilVar {
                name: n.to_string(),
                ty: HlilType::Int { signed: false, bits: 64 },
                is_param: false,
                stack_offset: None,
                version: 0,
                is_ssa: false,
            },
        }
    }

    #[test]
    fn chiamata_per_nome_resta_identica() {
        // Il caso dominante non deve cambiare di un byte: `print_parens`
        // avvolge tutto TRANNE `Var`/`Const`.
        let e = HlilExpr::Call {
            func: Box::new(var("sub_140001000")),
            args: vec![],
            ret_ty: HlilType::Void,
        };
        assert_eq!(ExprPrinter::default().print(&e), "sub_140001000()");
    }

    #[test]
    fn callee_dereferenziato_viene_parentesizzato() {
        // `call [X]`: senza parentesi `*sub_X()` si legge in C `*(sub_X())`,
        // cioe' «chiama lo slot e dereferenzia il risultato» — l'opposto di
        // «carica il puntatore dallo slot e chiamalo».
        let e = HlilExpr::Call {
            func: Box::new(HlilExpr::Deref {
                addr: Box::new(var("sub_14002D100")),
                ty: HlilType::Int { signed: false, bits: 64 },
            }),
            args: vec![],
            ret_ty: HlilType::Void,
        };
        assert_eq!(ExprPrinter::default().print(&e), "(*sub_14002D100)()");
    }
}
