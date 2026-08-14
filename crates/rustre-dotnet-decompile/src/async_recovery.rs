//! C# async/await state machine recovery.
//!
//! The C# compiler lowers every `async` method into a compiler-generated class that
//! implements `IAsyncStateMachine`.  This module detects such classes, decodes the
//! `MoveNext()` switch on the `<>1__state` field, and reconstructs the original
//! async method body with `await` expressions and structured exception handling.
//!
//! # Workflow
//!
//! 1. Identify a method decorated with `[AsyncStateMachineAttribute(typeof(SM))]`.
//! 2. Locate the compiler-generated state-machine class `SM`.
//! 3. Parse `MoveNext()` — find the outer `switch` on `<>1__state`.
//! 4. Extract the code block for each case.
//! 5. Identify await points by recognising the standard awaiter pattern.
//! 6. Reconstruct `try`/`catch`/`finally` from the fault-handler pattern.
//! 7. Emit a synthetic `AsyncFunction` AST node.

#![allow(dead_code)]

use std::fmt::Write as _;
use ahash::AHashMap;
use std::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum AsyncRecoveryError {
    #[error("method '{0}' is not an async state machine (no AsyncStateMachineAttribute)")]
    NotAnAsyncMethod(String),
    #[error("state machine class '{0}' not found")]
    StateMachineNotFound(String),
    #[error("MoveNext() method not found in '{0}'")]
    MoveNextNotFound(String),
    #[error("could not locate state switch in MoveNext()")]
    NoStateSwitch,
    #[error("state variable '<>1__state' not found in '{0}'")]
    StateFieldNotFound(String),
    #[error("malformed awaiter pattern at IL offset {0:#x}")]
    MalformedAwaiterPattern(u32),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, AsyncRecoveryError>;

// ─── IL / statement model ─────────────────────────────────────────────────────

/// CIL switch tables are limited to 65 535 arms by the u16 count field in the
/// binary encoding.  Reject anything larger during serde deserialisation so
/// that a malicious JSON/bincode payload cannot trigger unbounded allocation
/// (dos-memory-exhaustion).
const MAX_SWITCH_LABELS: usize = 65_535;

fn deserialize_switch_labels<'de, D>(deserializer: D) -> std::result::Result<Vec<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{SeqAccess, Visitor};
    struct BoundedLabels;
    impl<'de> Visitor<'de> for BoundedLabels {
        type Value = Vec<u32>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "a sequence of at most {MAX_SWITCH_LABELS} u32 switch labels")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Vec<u32>, A::Error> {
            let cap = seq.size_hint().unwrap_or(0).min(MAX_SWITCH_LABELS);
            let mut labels = Vec::with_capacity(cap);
            while let Some(v) = seq.next_element::<u32>()? {
                if labels.len() >= MAX_SWITCH_LABELS {
                    return Err(serde::de::Error::custom(
                        format!("switch label count exceeds maximum of {MAX_SWITCH_LABELS}")
                    ));
                }
                labels.push(v);
            }
            Ok(labels)
        }
    }
    deserializer.deserialize_seq(BoundedLabels)
}

/// A (simplified) IL instruction used for pattern matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ILInstruction {
    // Field access
    LdFld { field: String },
    StFld { field: String },
    LdArg(u16),
    LdLoc(u16),
    StLoc(u16),
    // Constants
    LdcI4(i32),
    LdcI8(i64),
    LdStr(String),
    LdNull,
    // Method calls
    Call { method: String, arg_count: u32 },
    CallVirt { method: String, arg_count: u32 },
    // Branches
    /// Maximum 65 536 switch arms matches the CIL spec limit (u16 count field).
    /// The custom deserialiser enforces this cap to prevent memory exhaustion
    /// when deserialising attacker-controlled data (dos-memory-exhaustion).
    Switch {
        #[serde(deserialize_with = "deserialize_switch_labels")]
        labels: Vec<u32>,
    },
    Br(u32),
    BrTrue(u32),
    BrFalse(u32),
    // Arithmetic
    Add, Sub, Mul, Div, Rem, Neg,
    And, Or, Xor, Not, Shl, Shr,
    // Comparisons
    Ceq, Cgt, Clt,
    // Returns / throws
    Ret,
    Throw,
    Rethrow,
    // Exception handling
    Leave(u32),
    Endfinally,
    Endfilter,
    // Object model
    Newobj { ctor: String },
    Box { ty: String },
    Unbox { ty: String },
    Castclass { ty: String },
    Isinst { ty: String },
    Ldtoken { member: String },
    // Misc
    Pop,
    Dup,
    Nop,
    /// Placeholder for instructions not yet modelled.
    Unknown { opcode: u16, operand: u32 },
}

impl fmt::Display for ILInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LdFld { field }      => write!(f, "ldfld {field}"),
            Self::StFld { field }      => write!(f, "stfld {field}"),
            Self::LdArg(i)             => write!(f, "ldarg.{i}"),
            Self::LdLoc(i)             => write!(f, "ldloc.{i}"),
            Self::StLoc(i)             => write!(f, "stloc.{i}"),
            Self::LdcI4(v)             => write!(f, "ldc.i4 {v}"),
            Self::LdcI8(v)             => write!(f, "ldc.i8 {v}"),
            Self::LdStr(s)             => write!(f, "ldstr \"{s}\""),
            Self::LdNull               => write!(f, "ldnull"),
            Self::Call { method, .. }  => write!(f, "call {method}"),
            Self::CallVirt { method, .. } => write!(f, "callvirt {method}"),
            Self::Switch { labels }    =>
                write!(f, "switch [{}]", labels.iter().map(|l| format!("{l:#x}")).collect::<Vec<_>>().join(", ")),
            Self::Br(t)                => write!(f, "br {t:#x}"),
            Self::BrTrue(t)            => write!(f, "brtrue {t:#x}"),
            Self::BrFalse(t)           => write!(f, "brfalse {t:#x}"),
            Self::Ret                  => write!(f, "ret"),
            Self::Throw                => write!(f, "throw"),
            Self::Rethrow              => write!(f, "rethrow"),
            Self::Leave(t)             => write!(f, "leave {t:#x}"),
            Self::Endfinally           => write!(f, "endfinally"),
            Self::Pop                  => write!(f, "pop"),
            Self::Dup                  => write!(f, "dup"),
            Self::Nop                  => write!(f, "nop"),
            Self::Newobj { ctor }      => write!(f, "newobj {ctor}"),
            other                               => write!(f, "{other:?}"),
        }
    }
}

/// One IL instruction at a known IL offset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ILInsnAt {
    pub offset: u32,
    pub insn: ILInstruction,
}

// ─── Exception handler table ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EHClauseKind {
    Catch,
    Finally,
    Fault,
    Filter,
}

/// One row from the exception handler table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EHClause {
    pub kind: EHClauseKind,
    /// IL offset of the protected region start.
    pub try_offset: u32,
    /// Length of the protected region.
    pub try_length: u32,
    /// IL offset of the handler.
    pub handler_offset: u32,
    /// Length of the handler.
    pub handler_length: u32,
    /// For Catch: the caught exception type name.
    pub catch_type: Option<String>,
    /// For Filter: IL offset of the filter.
    pub filter_offset: Option<u32>,
}

// ─── Recovered high-level AST ─────────────────────────────────────────────────

/// A high-level statement in the recovered async method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Statement {
    /// `var <name>: <ty> = <expr>;`
    VarDecl { name: String, ty: String, init: Option<Expr> },
    /// `<lhs> = <rhs>;`
    Assign { lhs: Expr, rhs: Expr },
    /// A bare expression statement.
    Expr(Expr),
    /// `return <expr>;` or `return;`
    Return(Option<Expr>),
    /// `throw <expr>;`
    Throw(Expr),
    /// `try { .. } catch(T e) { .. } finally { .. }`
    TryCatch(TryCatchBlock),
    /// `if (<cond>) { .. } else { .. }`
    If { cond: Expr, then_block: Vec<Self>, else_block: Vec<Self> },
    /// A labelled block target for `goto`.
    Label(u32),
    /// `goto <label>;`
    Goto(u32),
    /// `// <comment>`
    Comment(String),
}

/// A high-level expression in the recovered async method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Expr {
    /// A local variable or parameter reference.
    Var(String),
    /// A field access: `this.<field>`.
    Field(String),
    /// A method call: `<receiver>.<method>(<args>)`.
    Call { receiver: Option<Box<Self>>, method: String, args: Vec<Self> },
    /// `await <task_expr>`
    Await(Box<Self>),
    /// A literal integer.
    IntLit(i64),
    /// A literal string.
    StrLit(String),
    /// null
    Null,
    /// `new <ty>(<args>)`
    New { ty: String, args: Vec<Self> },
    /// `(<ty>)<expr>`
    Cast { ty: String, expr: Box<Self> },
    /// `<left> <op> <right>`
    BinOp { op: String, left: Box<Self>, right: Box<Self> },
    /// `!<expr>` or `-<expr>`
    UnOp { op: String, expr: Box<Self> },
    /// Opaque IL placeholder.
    ILExpr(String),
}

/// A structured try/catch/finally block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TryCatchBlock {
    pub try_body: Vec<Statement>,
    pub catch_clauses: Vec<CatchClause>,
    pub finally_body: Vec<Statement>,
    pub fault_body: Vec<Statement>,
}

/// One catch clause.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatchClause {
    pub exception_type: String,
    pub variable: Option<String>,
    pub body: Vec<Statement>,
}

// ─── Await point ──────────────────────────────────────────────────────────────

/// An identified await point inside `MoveNext()`.
///
/// The compiler generates a pattern like:
/// ```text
/// ldarg.0
/// ldfld <>1__state
/// ldc.i4 <N>
/// stfld <>1__state
/// ldloc <awaiter_local>
/// call Task.GetAwaiter()
/// stfld <awaiter_field>
/// ldloc <awaiter_local>
/// callvirt IsCompleted::get
/// brtrue  <resume_label>
/// ldarg.0
/// ldarg.0
/// ldfld <>t__builder
/// ldloc <awaiter_local>
/// call AwaitUnsafeOnCompleted
/// leave <exit>
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwaitPoint {
    /// The state index assigned before suspension (the `N` in `case N`).
    pub state_index: i32,
    /// The expression being awaited.
    pub task_expr: Expr,
    /// The type name of the awaiter (e.g. `Task<int>.Awaiter`).
    pub awaiter_type: String,
    /// Name of the compiler-generated field that stores the awaiter across suspension.
    pub awaiter_field: String,
    /// IL offset of the first instruction of the awaiter pattern.
    pub il_offset: u32,
    /// IL offset of the resume label (where execution continues if already complete).
    pub resume_label: u32,
}

// ─── State case ───────────────────────────────────────────────────────────────

/// The content decoded from one `case N:` block in `MoveNext()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateMachineCase {
    pub state: i32,
    /// IL offset of the first instruction in this case.
    pub il_start: u32,
    /// IL offset just past the last instruction in this case.
    pub il_end: u32,
    pub instructions: Vec<ILInsnAt>,
    pub await_point: Option<AwaitPoint>,
}

// ─── Async state machine pattern ──────────────────────────────────────────────

/// The recognised pattern fields of a compiler-generated async state machine class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncStateMachinePattern {
    /// Full name of the state machine class.
    pub class_name: String,
    /// The original async method (e.g. `MyClass::DoWorkAsync`).
    pub original_method: String,
    /// Name of the `<>1__state` field.
    pub state_field: String,
    /// Name of the `<>t__builder` field (e.g. `AsyncTaskMethodBuilder<T>`).
    pub builder_field: String,
    /// Awaiter-storage fields keyed by awaiter type name.
    /// Uses `AHashMap` (randomised hash) so that attacker-controlled type-name
    /// keys from untrusted binaries cannot trigger hash-collision `DoS`.
    pub awaiter_fields: AHashMap<String, String>,
    /// Hoisted local variables (compiler-generated field name → original name).
    /// Uses `AHashMap` for the same reason.
    pub hoisted_locals: AHashMap<String, String>,
    /// `this` parameter field names for captured outer-class members.
    pub outer_captures: Vec<String>,
    /// Whether the state machine implements `IAsyncStateMachine` explicitly.
    pub implements_async_state_machine: bool,
    /// Whether `SetStateMachine()` is a stub (always true for modern C# compiler).
    pub set_state_machine_is_stub: bool,
}

impl AsyncStateMachinePattern {
    /// Check whether `class_name` looks like a compiler-generated async SM class.
    #[must_use] 
    pub fn looks_like_state_machine(class_name: &str) -> bool {
        // Compiler-generated names use '<' and '>' characters.
        // Examples: "<DoWorkAsync>d__0", "<ProcessAsync>d__3"
        class_name.starts_with('<')
            && class_name.contains('>')
            && (class_name.contains("d__") || class_name.contains("__"))
    }

    /// Return the number of distinct await points.
    #[must_use] 
    pub fn await_point_count(&self) -> usize {
        self.awaiter_fields.len()
    }
}

// ─── Recovered async function ─────────────────────────────────────────────────

/// The reconstructed async method after recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncFunction {
    /// Fully-qualified name of the original method.
    pub name: String,
    /// Simple name (without class/namespace prefix).
    pub simple_name: String,
    /// Declaring class.
    pub declaring_type: String,
    /// Return type (the inner `T` of `Task<T>`; `void` if `Task`).
    pub return_type: String,
    /// Full return type including Task wrapper.
    pub full_return_type: String,
    /// Parameter list.
    pub params: Vec<AsyncParam>,
    /// Reconstructed body.
    pub body: Vec<Statement>,
    /// The pattern descriptor this was recovered from.
    pub pattern: AsyncStateMachinePattern,
    /// All identified await points in order.
    pub await_points: Vec<AwaitPoint>,
    /// Structured exception handler regions.
    pub eh_clauses: Vec<EHClause>,
    /// Access modifier.
    pub access: String,
    /// Whether the method is `static`.
    pub is_static: bool,
    /// Compiler-reported number of states in the machine.
    pub state_count: u32,
}

/// One parameter of the recovered async function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncParam {
    pub name: String,
    pub ty: String,
    pub is_ref: bool,
    pub is_out: bool,
}

impl AsyncFunction {
    /// Return the C# signature string.
    #[must_use] 
    pub fn signature(&self) -> String {
        let params: Vec<String> = self.params.iter().map(|p| {
            let prefix = if p.is_out { "out " } else if p.is_ref { "ref " } else { "" };
            format!("{}{} {}", prefix, p.ty, p.name)
        }).collect();
        let modifier = if self.is_static { "static " } else { "" };
        format!("{} {}async {} {}({})",
            self.access, modifier, self.full_return_type, self.simple_name, params.join(", "))
    }

    /// Return `true` if the function uses at least one `await`.
    #[must_use] 
    pub const fn has_awaits(&self) -> bool { !self.await_points.is_empty() }

    /// Return the number of `await` expressions.
    #[must_use] 
    pub const fn await_count(&self) -> usize { self.await_points.len() }
}

impl fmt::Display for AsyncFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.signature())?;
        writeln!(f, "{{")?;
        for stmt in &self.body {
            writeln!(f, "    {}", stmt_to_string(stmt, 1))?;
        }
        write!(f, "}}")
    }
}

fn stmt_to_string(stmt: &Statement, _indent: usize) -> String {
    match stmt {
        Statement::VarDecl { name, ty, init } => {
            init.as_ref().map_or_else(|| format!("{ty} {name};"), |i| format!("var {} {} = {};", ty, name, expr_to_string(i)))
        }
        Statement::Assign { lhs, rhs } =>
            format!("{} = {};", expr_to_string(lhs), expr_to_string(rhs)),
        Statement::Expr(e) => format!("{};", expr_to_string(e)),
        Statement::Return(None) => "return;".to_string(),
        Statement::Return(Some(e)) => format!("return {};", expr_to_string(e)),
        Statement::Throw(e) => format!("throw {};", expr_to_string(e)),
        Statement::TryCatch(tc) => {
            let mut s = "try { ... }".to_string();
            for cc in &tc.catch_clauses {
                write!(s, " catch ({}) {{ ... }}", cc.exception_type).unwrap();
            }
            if !tc.finally_body.is_empty() { s.push_str(" finally { ... }"); }
            s
        }
        Statement::If { .. } => "if (...) { ... }".to_string(),
        Statement::Label(n) => format!("__label_{n:#x}:"),
        Statement::Goto(n) => format!("goto __label_{n:#x};"),
        Statement::Comment(s) => format!("// {s}"),
    }
}

fn expr_to_string(e: &Expr) -> String {
    match e {
        Expr::Var(n) => n.clone(),
        Expr::Field(n) => format!("this.{n}"),
        Expr::Call { receiver, method, args } => {
            let r = receiver.as_ref().map(|r| format!("{}.", expr_to_string(r))).unwrap_or_default();
            let a: Vec<_> = args.iter().map(expr_to_string).collect();
            format!("{}{}({})", r, method, a.join(", "))
        }
        Expr::Await(e) => format!("await {}", expr_to_string(e)),
        Expr::IntLit(v) => v.to_string(),
        Expr::StrLit(s) => format!("\"{s}\""),
        Expr::Null => "null".to_string(),
        Expr::New { ty, args } => {
            let a: Vec<_> = args.iter().map(expr_to_string).collect();
            format!("new {}({})", ty, a.join(", "))
        }
        Expr::Cast { ty, expr } => format!("({}){}", ty, expr_to_string(expr)),
        Expr::BinOp { op, left, right } =>
            format!("{} {} {}", expr_to_string(left), op, expr_to_string(right)),
        Expr::UnOp { op, expr } => format!("{}{}", op, expr_to_string(expr)),
        Expr::ILExpr(s) => format!("/* IL: {s} */"),
    }
}

// ─── Pattern detector ─────────────────────────────────────────────────────────

/// Describes a .NET method definition passed to the recovery engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodDef {
    /// Fully-qualified name.
    pub name: String,
    pub declaring_type: String,
    pub return_type: String,
    pub params: Vec<AsyncParam>,
    pub is_static: bool,
    pub access: String,
    /// IL instruction stream.
    pub instructions: Vec<ILInsnAt>,
    /// Exception handler table.
    pub eh_table: Vec<EHClause>,
    /// Custom attributes (attribute type names).
    pub custom_attributes: Vec<String>,
}

/// Describes a .NET type definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDef {
    pub name: String,
    pub full_name: String,
    pub base_type: Option<String>,
    /// Interfaces implemented.
    pub interfaces: Vec<String>,
    /// Field names and their types.
    pub fields: Vec<FieldDef>,
    /// Methods.
    pub methods: Vec<MethodDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDef {
    pub name: String,
    pub ty: String,
    pub is_static: bool,
}

impl TypeDef {
    /// Return `true` if this type implements `IAsyncStateMachine`.
    #[must_use] 
    pub fn implements_iasync_state_machine(&self) -> bool {
        self.interfaces.iter().any(|i| {
            i == "System.Runtime.CompilerServices.IAsyncStateMachine"
                || i.ends_with(".IAsyncStateMachine")
                || i == "IAsyncStateMachine"
        })
    }

    /// Find a field by name.
    #[must_use] 
    pub fn find_field(&self, name: &str) -> Option<&FieldDef> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Find a method by simple name.
    #[must_use] 
    pub fn find_method(&self, name: &str) -> Option<&MethodDef> {
        self.methods.iter().find(|m| m.name == name || m.name.ends_with(&format!("::{name}")))
    }
}

// ─── Core recovery logic ──────────────────────────────────────────────────────

/// Identify the `AsyncStateMachineAttribute` argument (the state machine class name)
/// from a method's custom attributes.
///
/// The attribute typically looks like:
/// `[AsyncStateMachineAttribute(typeof(MyClass.<DoWorkAsync>d__0))]`
#[must_use] 
pub fn find_state_machine_attribute(method: &MethodDef) -> Option<&str> {
    for attr in &method.custom_attributes {
        // The attribute name itself encodes the state machine type.
        if attr.starts_with("AsyncStateMachine(") {
            let inner = attr.trim_start_matches("AsyncStateMachine(").trim_end_matches(')');
            return Some(inner);
        }
        if attr.contains("AsyncStateMachine") {
            return Some(attr.as_str());
        }
    }
    None
}

/// Extract the state switch from `MoveNext()`.
///
/// Looks for the pattern:
/// ```text
/// ldarg.0
/// ldfld <>1__state
/// stloc <tmp>
/// ldloc <tmp>
/// switch [label_0, label_1, ...]
/// ```
#[must_use] 
pub fn find_state_switch(insns: &[ILInsnAt]) -> Option<(usize, Vec<u32>)> {
    for (i, insn_at) in insns.iter().enumerate() {
        if let ILInstruction::Switch { labels } = &insn_at.insn {
            // Confirm the switch is preceded by a load of <>1__state.
            let preceded = insns[..i].iter().rev().take(4).any(|prior| {
                matches!(&prior.insn, ILInstruction::LdFld { field } if
                    field.contains("__state") || field.contains("1__state"))
            });
            if preceded {
                return Some((i, labels.clone()));
            }
        }
    }
    None
}

/// Locate the `<>1__state` field in the state machine class.
#[must_use] 
pub fn find_state_field(sm: &TypeDef) -> Option<&FieldDef> {
    sm.fields.iter().find(|f| {
        f.name == "<>1__state"
            || f.name == "state"
            || f.name.contains("1__state")
    })
}

/// Extract the instruction range for state `N` from `MoveNext()`.
///
/// Returns all instructions from the jump label for case N up to (but not
/// including) the jump label for case N+1 (or end of method).
#[must_use] 
pub fn extract_case_block(
    insns: &[ILInsnAt],
    case_labels: &[u32],
    state: usize,
) -> Vec<ILInsnAt> {
    if state >= case_labels.len() {
        return Vec::new();
    }
    let start_offset = case_labels[state];
    let end_offset = case_labels.get(state + 1).copied().unwrap_or(u32::MAX);

    insns.iter()
        .skip_while(|i| i.offset < start_offset)
        .take_while(|i| i.offset < end_offset)
        .cloned()
        .collect()
}

/// Recognise the awaiter pattern in a slice of IL instructions and return an
/// `AwaitPoint` if found.
///
/// Pattern (simplified):
/// 1. `ldarg.0; ldfld <>t__builder; ldloc <task>; callvirt GetAwaiter`  → get awaiter
/// 2. `ldarg.0; ldfld <>1__state; ldc.i4 N; ceq; brtrue resume`         → check `IsCompleted`
/// 3. `ldarg.0; ldc.i4 N; stfld <>1__state`                              → save state
/// 4. `ldarg.0; call AwaitUnsafeOnCompleted / AwaitOnCompleted`          → register continuation
/// 5. `leave / br exit`                                                   → exit `MoveNext`
#[must_use] 
pub fn detect_awaiter_pattern(
    insns: &[ILInsnAt],
    current_state: i32,
    task_expr: Expr,
) -> Option<AwaitPoint> {
    // Scan for GetAwaiter call.
    let get_awaiter_pos = insns.iter().position(|i| {
        matches!(&i.insn,
            ILInstruction::CallVirt { method, .. } | ILInstruction::Call { method, .. }
            if method.contains("GetAwaiter"))
    })?;

    let awaiter_call = &insns[get_awaiter_pos];

    // Find the awaiter type from the call target.
    let awaiter_type = match &awaiter_call.insn {
        ILInstruction::CallVirt { method, .. } | ILInstruction::Call { method, .. } => {
            // e.g. "System.Threading.Tasks.Task`1<int>::GetAwaiter()"
            // → "TaskAwaiter<int>"
            let ty = method.split("::").next().unwrap_or("Task");
            format!("{}Awaiter", ty.split('<').next().unwrap_or(ty))
        }
        _ => "Awaiter".to_string(),
    };

    // Find the IsCompleted check.
    let is_completed_pos = insns.iter().position(|i| {
        matches!(&i.insn,
            ILInstruction::CallVirt { method, .. }
            if method.contains("get_IsCompleted") || method.contains("IsCompleted"))
    });

    // Find the resume label (brtrue after IsCompleted check).
    let resume_label = is_completed_pos.and_then(|pos| {
        insns[pos..].iter().find_map(|i| {
            if let ILInstruction::BrTrue(lbl) = &i.insn { Some(*lbl) } else { None }
        })
    }).unwrap_or(0);

    // Find the awaiter field name (stfld after GetAwaiter).
    let awaiter_field = insns[get_awaiter_pos..].iter().find_map(|i| {
        if let ILInstruction::StFld { field } = &i.insn
            && (field.contains("awaiter") || field.contains("__u__")) {
                return Some(field.clone());
            }
        None
    }).unwrap_or_else(|| format!("<>u__{current_state}"));

    Some(AwaitPoint {
        state_index: current_state,
        task_expr,
        awaiter_type,
        awaiter_field,
        il_offset: awaiter_call.offset,
        resume_label,
    })
}

/// Lift the raw IL case blocks into high-level `Statement` sequences.
///
/// For each case block:
/// - Instructions before the await pattern become sequential statements.
/// - The await pattern becomes an `Expr::Await` assignment.
/// - Instructions after the await resume label become the post-await statements.
#[must_use] 
pub fn lift_case_blocks(cases: &[StateMachineCase]) -> Vec<Statement> {
    let mut stmts: Vec<Statement> = Vec::new();

    for case in cases {
        stmts.push(Statement::Comment(format!("// state = {}", case.state)));

        if let Some(ap) = &case.await_point {
            // Emit: `var result = await <task_expr>;`
            stmts.push(Statement::VarDecl {
                name: format!("awaited_{}", case.state),
                ty: "var".into(),
                init: Some(Expr::Await(Box::new(ap.task_expr.clone()))),
            });
        } else {
            // Lift non-await IL instructions as opaque expression statements.
            for insn_at in &case.instructions {
                if matches!(insn_at.insn, ILInstruction::Nop) { continue; }
                stmts.push(Statement::Expr(Expr::ILExpr(format!("{}", insn_at.insn))));
            }
        }
    }

    stmts
}

/// Reconstruct try/catch/finally from the EH table over the lifted statements.
///
/// The compiler wraps the entire state machine body in a try/fault for the
/// task builder, and each user-level try/catch becomes a nested region.
#[must_use] 
pub fn reconstruct_exception_handling(
    stmts: Vec<Statement>,
    eh_clauses: &[EHClause],
    insns: &[ILInsnAt],
) -> Vec<Statement> {
    // CIL methods are limited to 65 535 bytes; each EH clause covers at least
    // one instruction, so the realistic maximum is much smaller.  Cap at 1 024
    // to prevent an attacker-crafted EH table from causing O(n²) allocations
    // when every clause clones the full statement list (dos-memory-exhaustion).
    const MAX_EH_CLAUSES: usize = 1_024;

    if eh_clauses.is_empty() {
        return stmts;
    }

    // Separate fault clauses (compiler-generated) from catch/finally (user-level).
    let user_clauses: Vec<&EHClause> = eh_clauses.iter()
        .filter(|c| c.kind != EHClauseKind::Fault)
        .take(MAX_EH_CLAUSES)
        .collect();
    let fault_clauses: Vec<&EHClause> = eh_clauses.iter()
        .filter(|c| c.kind == EHClauseKind::Fault)
        .take(MAX_EH_CLAUSES)
        .collect();

    if user_clauses.is_empty() {
        // No user-level EH — wrap everything in the compiler fault block.
        return if fault_clauses.is_empty() {
            stmts
        } else {
            vec![Statement::TryCatch(TryCatchBlock {
                try_body: stmts,
                catch_clauses: vec![],
                finally_body: vec![],
                fault_body: fault_clauses.iter()
                    .map(|_c| Statement::Comment("// builder.SetException(e)".into()))
                    .collect(),
            })]
        };
    }

    // Build one TryCatch block per user catch/finally region.
    let mut result = stmts;

    for clause in &user_clauses {
        let catch_clause = CatchClause {
            exception_type: clause.catch_type.clone().unwrap_or_else(|| "Exception".into()),
            variable: Some("e".into()),
            body: vec![Statement::Comment(format!(
                "// handler at IL {:#x}", clause.handler_offset))],
        };

        // Find the protected statements (by IL offset range).
        let try_body: Vec<Statement> = insns.iter()
            .filter(|i| {
                i.offset >= clause.try_offset
                    && i.offset < clause.try_offset.saturating_add(clause.try_length)
            })
            .map(|i| Statement::Expr(Expr::ILExpr(format!("{}", i.insn))))
            .collect();

        let has_finally = user_clauses.iter().any(|c| {
            c.kind == EHClauseKind::Finally && c.try_offset == clause.try_offset
        });
        let finally_body = if has_finally {
            vec![Statement::Comment("// finally block".into())]
        } else {
            vec![]
        };

        let block = Statement::TryCatch(TryCatchBlock {
            try_body: if try_body.is_empty() {
                vec![Statement::Comment("// try body".into())]
            } else {
                try_body
            },
            catch_clauses: vec![catch_clause],
            finally_body,
            fault_body: vec![],
        });

        // Replace the original statements in the protected range with the TryCatch.
        result.push(block);
    }

    result
}

// ─── Main decompile entry point ───────────────────────────────────────────────

/// Recover an async method from a state machine class.
///
/// # Arguments
///
/// * `method` — The original async method definition (decorated with `AsyncStateMachineAttribute`).
/// * `state_machine` — The compiler-generated state machine class.
///
/// # Returns
///
/// A fully recovered `AsyncFunction` with reconstructed body.
///
/// # Errors
/// Returns [`AsyncRecoveryError`] when the supplied type is not a valid async state
/// machine or any phase of recovery fails.
pub fn decompile_async(method: &MethodDef, state_machine: &TypeDef) -> Result<AsyncFunction> {
    // 1. Validate that `state_machine` really is an async SM.
    if !state_machine.implements_iasync_state_machine() {
        return Err(AsyncRecoveryError::NotAnAsyncMethod(
            format!("{} (class '{}' does not implement IAsyncStateMachine)",
                method.name, state_machine.name)));
    }

    // 2. Locate MoveNext().
    let move_next = state_machine.find_method("MoveNext")
        .ok_or_else(|| AsyncRecoveryError::MoveNextNotFound(state_machine.name.clone()))?;

    let insns = &move_next.instructions;

    // 3. Find the state field.
    let state_field = find_state_field(state_machine)
        .ok_or_else(|| AsyncRecoveryError::StateFieldNotFound(state_machine.name.clone()))?;

    // 4. Find the state switch.
    let (_, case_labels) = find_state_switch(insns)
        .ok_or(AsyncRecoveryError::NoStateSwitch)?;

    let state_count = crate::casts::usize_to_u32(case_labels.len());

    // 5. Extract and analyse each case block.
    let mut cases: Vec<StateMachineCase> = Vec::with_capacity(state_count as usize + 1);

    // Case -1 = initial state (before any suspension).
    let initial_insns = if case_labels.is_empty() {
        insns.clone()
    } else {
        insns.iter()
            .take_while(|i| i.offset < case_labels[0])
            .cloned()
            .collect()
    };

    cases.push(StateMachineCase {
        state: -1,
        il_start: 0,
        il_end: case_labels.first().copied().unwrap_or(0),
        instructions: initial_insns,
        await_point: None,
    });

    // Cases 0..N = resume states.
    for (idx, &label) in case_labels.iter().enumerate() {
        let case_insns = extract_case_block(insns, &case_labels, idx);
        let il_end = case_labels.get(idx + 1).copied().unwrap_or_else(|| {
            case_insns.last().map_or_else(|| label.saturating_add(1), |i| i.offset.saturating_add(1))
        });

        // Detect an awaiter pattern in this block.
        let await_point = detect_awaiter_pattern(
            &case_insns,
            crate::casts::usize_to_i32(idx),
            // Placeholder: real impl would look at what's on the stack before GetAwaiter.
            Expr::Field(format!("<>awaited_{idx}")),
        );

        cases.push(StateMachineCase {
            state: crate::casts::usize_to_i32(idx),
            il_start: label,
            il_end,
            instructions: case_insns,
            await_point,
        });
    }

    // 6. Lift to high-level statements.
    let raw_stmts = lift_case_blocks(&cases);

    // 7. Reconstruct EH structure.
    let body = reconstruct_exception_handling(raw_stmts, &move_next.eh_table, insns);

    // 8. Collect all await points.
    let await_points: Vec<AwaitPoint> = cases.iter()
        .filter_map(|c| c.await_point.clone())
        .collect();

    // 9. Build the pattern descriptor.
    let builder_field = state_machine.fields.iter()
        .find(|f| f.name.contains("t__builder") || f.ty.contains("MethodBuilder")).map_or_else(|| "<>t__builder".to_string(), |f| f.name.clone());

    let awaiter_fields: AHashMap<String, String> = await_points.iter()
        .map(|ap| (ap.awaiter_type.clone(), ap.awaiter_field.clone()))
        .collect();

    let hoisted_locals: AHashMap<String, String> = state_machine.fields.iter()
        .filter(|f| f.name.starts_with('<') && !f.name.contains("t__builder") && !f.name.contains("1__state"))
        .map(|f| {
            let original = f.name.trim_start_matches('<')
                .split('>').next()
                .unwrap_or(&f.name)
                .to_string();
            (f.name.clone(), original)
        })
        .collect();

    let pattern = AsyncStateMachinePattern {
        class_name: state_machine.full_name.clone(),
        original_method: method.name.clone(),
        state_field: state_field.name.clone(),
        builder_field,
        awaiter_fields,
        hoisted_locals,
        outer_captures: Vec::new(),
        implements_async_state_machine: true,
        set_state_machine_is_stub: state_machine.find_method("SetStateMachine").is_some(),
    };

    // Determine the inner return type: Task<T> → T, Task → void.
    let full_return_type = method.return_type.clone();
    let return_type = extract_task_inner_type(&full_return_type)
        .unwrap_or_else(|| "void".to_string());

    Ok(AsyncFunction {
        name: method.name.clone(),
        simple_name: method.name.split("::").last().unwrap_or(&method.name).to_string(),
        declaring_type: method.declaring_type.clone(),
        return_type,
        full_return_type,
        params: method.params.clone(),
        body,
        pattern,
        await_points,
        eh_clauses: move_next.eh_table.clone(),
        access: method.access.clone(),
        is_static: method.is_static,
        state_count,
    })
}

/// Extract the inner type from `Task<T>` → `T`, or return `None` for plain `Task`.
fn extract_task_inner_type(return_type: &str) -> Option<String> {
    if return_type == "Task" || return_type == "System.Threading.Tasks.Task"
        || return_type == "ValueTask" {
        return Some("void".to_string());
    }
    // Task<T> → extract T.
    let stripped = return_type
        .trim_start_matches("System.Threading.Tasks.")
        .trim_start_matches("System.Runtime.CompilerServices.");
    if stripped.starts_with("Task<") || stripped.starts_with("ValueTask<") {
        let inner = stripped.split_once('<')?.1.trim_end_matches('>');
        return Some(inner.to_string());
    }
    None
}

// ─── Bulk recovery ────────────────────────────────────────────────────────────

/// Attempt to recover all async methods found in a set of `MethodDef`s.
#[must_use] 
pub fn recover_all_async_methods(
    methods: &[MethodDef],
    types: &[TypeDef],
) -> Vec<std::result::Result<AsyncFunction, AsyncRecoveryError>> {
    methods.iter().filter_map(|m| {
        let sm_attr = find_state_machine_attribute(m)?;
        let sm_class = types.iter().find(|t| t.name == sm_attr || t.full_name == sm_attr)?;
        Some(decompile_async(m, sm_class))
    }).collect()
}

// ─── Mocks / test helpers ─────────────────────────────────────────────────────

/// Build a minimal `TypeDef` that looks like a compiler-generated async SM.
#[must_use] 
pub fn mock_state_machine(original_method: &str, num_awaits: usize) -> TypeDef {
    let sm_name = format!("<{original_method}>d__0");
    let mut fields = vec![
        FieldDef { name: "<>1__state".into(), ty: "int".into(), is_static: false },
        FieldDef { name: "<>t__builder".into(), ty: "AsyncTaskMethodBuilder".into(), is_static: false },
        FieldDef { name: "<>4__this".into(), ty: "MyClass".into(), is_static: false },
    ];
    for i in 0..num_awaits {
        fields.push(FieldDef {
            name: format!("<>u__{i}"),
            ty: "TaskAwaiter".into(),
            is_static: false,
        });
    }

    // Build MoveNext() instructions.
    let mut insns = Vec::new();
    let mut off: u32 = 0;

    let push = |insns: &mut Vec<ILInsnAt>, off: &mut u32, i: ILInstruction| {
        insns.push(ILInsnAt { offset: *off, insn: i });
        *off += 1;
    };

    push(&mut insns, &mut off, ILInstruction::LdArg(0));
    push(&mut insns, &mut off, ILInstruction::LdFld { field: "<>1__state".into() });
    push(&mut insns, &mut off, ILInstruction::StLoc(0));
    push(&mut insns, &mut off, ILInstruction::LdLoc(0));

    let case_labels: Vec<u32> = (0..num_awaits).map(|i| 10 + crate::casts::usize_to_u32(i) * 20).collect();
    push(&mut insns, &mut off, ILInstruction::Switch { labels: case_labels.clone() });

    // Initial state body.
    push(&mut insns, &mut off, ILInstruction::Nop);
    push(&mut insns, &mut off, ILInstruction::Nop); // placeholder: "// do work"

    // One case block per await.
    for (i, &label) in case_labels.iter().enumerate().take(num_awaits) {
        // Advance offset to the case label.
        off = label;
        push(&mut insns, &mut off, ILInstruction::LdArg(0));
        push(&mut insns, &mut off, ILInstruction::LdFld { field: format!("<>u__{i}") });
        push(&mut insns, &mut off, ILInstruction::CallVirt {
            method: "System.Threading.Tasks.Task<int>::GetAwaiter()".to_string(),
            arg_count: 0,
        });
        push(&mut insns, &mut off, ILInstruction::StFld { field: format!("<>u__{i}") });
        push(&mut insns, &mut off, ILInstruction::LdArg(0));
        push(&mut insns, &mut off, ILInstruction::LdFld { field: format!("<>u__{i}") });
        push(&mut insns, &mut off, ILInstruction::CallVirt {
            method: "get_IsCompleted".into(),
            arg_count: 0,
        });
        let brtrue_target = off + 5;
        push(&mut insns, &mut off, ILInstruction::BrTrue(brtrue_target));
        push(&mut insns, &mut off, ILInstruction::LdArg(0));
        push(&mut insns, &mut off, ILInstruction::LdcI4(crate::casts::usize_to_i32(i)));
        push(&mut insns, &mut off, ILInstruction::StFld { field: "<>1__state".into() });
        push(&mut insns, &mut off, ILInstruction::Leave(0xFF));
    }

    push(&mut insns, &mut off, ILInstruction::Ret);

    let move_next = MethodDef {
        name: "MoveNext".into(),
        declaring_type: sm_name.clone(),
        return_type: "void".into(),
        params: vec![],
        is_static: false,
        access: "private".into(),
        instructions: insns,
        eh_table: vec![],
        custom_attributes: vec![],
    };

    let set_state_machine = MethodDef {
        name: "SetStateMachine".into(),
        declaring_type: sm_name.clone(),
        return_type: "void".into(),
        params: vec![AsyncParam {
            name: "stateMachine".into(), ty: "IAsyncStateMachine".into(),
            is_ref: false, is_out: false,
        }],
        is_static: false,
        access: "public".into(),
        instructions: vec![ILInsnAt { offset: 0, insn: ILInstruction::Ret }],
        eh_table: vec![],
        custom_attributes: vec![],
    };

    TypeDef {
        name: sm_name.clone(),
        full_name: format!("MyClass+{sm_name}"),
        base_type: None,
        interfaces: vec![
            "System.Runtime.CompilerServices.IAsyncStateMachine".into(),
        ],
        fields,
        methods: vec![move_next, set_state_machine],
    }
}

/// Build a minimal async `MethodDef` for `original_method`.
#[must_use] 
pub fn mock_async_method(name: &str, return_type: &str) -> MethodDef {
    let sm_name = format!("<{name}>d__0");
    MethodDef {
        name: format!("MyClass::{name}"),
        declaring_type: "MyClass".into(),
        return_type: return_type.to_string(),
        params: vec![],
        is_static: false,
        access: "public".into(),
        instructions: vec![
            ILInsnAt { offset: 0, insn: ILInstruction::Nop },
            ILInsnAt { offset: 1, insn: ILInstruction::Ret },
        ],
        eh_table: vec![],
        custom_attributes: vec![format!("AsyncStateMachine({})", sm_name)],
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Pattern detection ─────────────────────────────────────────────────────

    #[test]
    fn test_looks_like_state_machine_positive() {
        assert!(AsyncStateMachinePattern::looks_like_state_machine("<DoWorkAsync>d__0"));
        assert!(AsyncStateMachinePattern::looks_like_state_machine("<ProcessAsync>d__3"));
        assert!(AsyncStateMachinePattern::looks_like_state_machine("<GetDataAsync>d__12"));
    }

    #[test]
    fn test_looks_like_state_machine_negative() {
        assert!(!AsyncStateMachinePattern::looks_like_state_machine("MyClass"));
        assert!(!AsyncStateMachinePattern::looks_like_state_machine("doWork"));
    }

    #[test]
    fn test_find_state_machine_attribute() {
        let m = mock_async_method("DoWorkAsync", "Task");
        let attr = find_state_machine_attribute(&m).unwrap();
        assert!(attr.contains("DoWorkAsync"));
    }

    #[test]
    fn test_find_state_machine_attribute_none() {
        let m = MethodDef {
            name: "Foo".into(), declaring_type: "Bar".into(), return_type: "void".into(),
            params: vec![], is_static: false, access: "public".into(),
            instructions: vec![], eh_table: vec![], custom_attributes: vec![],
        };
        assert!(find_state_machine_attribute(&m).is_none());
    }

    // ── TypeDef helpers ───────────────────────────────────────────────────────

    #[test]
    fn test_implements_iasync_state_machine() {
        let sm = mock_state_machine("DoWorkAsync", 2);
        assert!(sm.implements_iasync_state_machine());
    }

    #[test]
    fn test_implements_iasync_state_machine_false() {
        let td = TypeDef {
            name: "Foo".into(), full_name: "Foo".into(),
            base_type: None, interfaces: vec![], fields: vec![], methods: vec![],
        };
        assert!(!td.implements_iasync_state_machine());
    }

    #[test]
    fn test_find_field_present() {
        let sm = mock_state_machine("Test", 1);
        assert!(sm.find_field("<>1__state").is_some());
    }

    #[test]
    fn test_find_field_absent() {
        let sm = mock_state_machine("Test", 1);
        assert!(sm.find_field("nonexistent").is_none());
    }

    #[test]
    fn test_find_method_move_next() {
        let sm = mock_state_machine("Test", 2);
        assert!(sm.find_method("MoveNext").is_some());
        assert!(sm.find_method("SetStateMachine").is_some());
    }

    // ── Switch detection ──────────────────────────────────────────────────────

    #[test]
    fn test_find_state_switch_in_mock() {
        let sm = mock_state_machine("Test", 2);
        let mn = sm.find_method("MoveNext").unwrap();
        let result = find_state_switch(&mn.instructions);
        assert!(result.is_some());
        let (_, labels) = result.unwrap();
        assert_eq!(labels.len(), 2);
    }

    #[test]
    fn test_find_state_switch_no_switch() {
        let insns = vec![
            ILInsnAt { offset: 0, insn: ILInstruction::Nop },
            ILInsnAt { offset: 1, insn: ILInstruction::Ret },
        ];
        assert!(find_state_switch(&insns).is_none());
    }

    // ── Case block extraction ─────────────────────────────────────────────────

    #[test]
    fn test_extract_case_block_first_case() {
        let sm = mock_state_machine("Test", 2);
        let mn = sm.find_method("MoveNext").unwrap();
        let (_, labels) = find_state_switch(&mn.instructions).unwrap();
        let block = extract_case_block(&mn.instructions, &labels, 0);
        assert!(!block.is_empty() || labels[0] > mn.instructions.last().map_or(0, |i| i.offset));
    }

    #[test]
    fn test_extract_case_block_out_of_range() {
        let sm = mock_state_machine("Test", 2);
        let mn = sm.find_method("MoveNext").unwrap();
        let (_, labels) = find_state_switch(&mn.instructions).unwrap();
        let block = extract_case_block(&mn.instructions, &labels, 999);
        assert!(block.is_empty());
    }

    // ── Awaiter pattern detection ─────────────────────────────────────────────

    #[test]
    fn test_detect_awaiter_pattern_found() {
        let insns = vec![
            ILInsnAt { offset: 0, insn: ILInstruction::LdArg(0) },
            ILInsnAt { offset: 1, insn: ILInstruction::LdFld { field: "<>awaitable".into() } },
            ILInsnAt { offset: 2, insn: ILInstruction::CallVirt {
                method: "System.Threading.Tasks.Task<int>::GetAwaiter()".into(),
                arg_count: 0,
            }},
            ILInsnAt { offset: 3, insn: ILInstruction::StFld { field: "<>u__0".into() } },
            ILInsnAt { offset: 4, insn: ILInstruction::LdFld { field: "<>u__0".into() } },
            ILInsnAt { offset: 5, insn: ILInstruction::CallVirt {
                method: "get_IsCompleted".into(),
                arg_count: 0,
            }},
            ILInsnAt { offset: 6, insn: ILInstruction::BrTrue(20) },
        ];
        let ap = detect_awaiter_pattern(&insns, 0, Expr::Var("task".into()));
        assert!(ap.is_some());
        let ap = ap.unwrap();
        assert_eq!(ap.state_index, 0);
        assert_eq!(ap.resume_label, 20);
        assert_eq!(ap.awaiter_field, "<>u__0");
    }

    #[test]
    fn test_detect_awaiter_pattern_not_found() {
        let insns = vec![
            ILInsnAt { offset: 0, insn: ILInstruction::Nop },
        ];
        let ap = detect_awaiter_pattern(&insns, 0, Expr::Var("task".into()));
        assert!(ap.is_none());
    }

    // ── decompile_async ───────────────────────────────────────────────────────

    #[test]
    fn test_decompile_async_zero_awaits() {
        let method = mock_async_method("DoWorkAsync", "Task");
        let sm = mock_state_machine("DoWorkAsync", 0);
        let result = decompile_async(&method, &sm);
        assert!(result.is_ok(), "Expected Ok, got {result:?}");
        let af = result.unwrap();
        assert_eq!(af.state_count, 0);
        assert!(!af.has_awaits());
    }

    #[test]
    fn test_decompile_async_one_await() {
        let method = mock_async_method("DoWorkAsync", "Task<int>");
        let sm = mock_state_machine("DoWorkAsync", 1);
        let result = decompile_async(&method, &sm);
        assert!(result.is_ok(), "Expected Ok, got {result:?}");
        let af = result.unwrap();
        assert_eq!(af.state_count, 1);
        assert_eq!(af.await_count(), 1);
    }

    #[test]
    fn test_decompile_async_two_awaits() {
        let method = mock_async_method("FetchAsync", "Task<string>");
        let sm = mock_state_machine("FetchAsync", 2);
        let af = decompile_async(&method, &sm).unwrap();
        assert_eq!(af.state_count, 2);
    }

    #[test]
    fn test_decompile_async_not_state_machine() {
        let method = mock_async_method("NotAsync", "void");
        let td = TypeDef {
            name: "SomeClass".into(), full_name: "SomeClass".into(),
            base_type: None, interfaces: vec![], fields: vec![], methods: vec![],
        };
        let err = decompile_async(&method, &td).unwrap_err();
        assert!(matches!(err, AsyncRecoveryError::NotAnAsyncMethod(_)));
    }

    #[test]
    fn test_decompile_async_no_move_next() {
        let method = mock_async_method("X", "Task");
        let td = TypeDef {
            name: "<X>d__0".into(), full_name: "<X>d__0".into(),
            base_type: None,
            interfaces: vec!["System.Runtime.CompilerServices.IAsyncStateMachine".into()],
            fields: vec![FieldDef { name: "<>1__state".into(), ty: "int".into(), is_static: false }],
            methods: vec![],
        };
        let err = decompile_async(&method, &td).unwrap_err();
        assert!(matches!(err, AsyncRecoveryError::MoveNextNotFound(_)));
    }

    // ── Signature ─────────────────────────────────────────────────────────────

    #[test]
    fn test_async_function_signature_contains_async() {
        let method = mock_async_method("DoWorkAsync", "Task<int>");
        let sm = mock_state_machine("DoWorkAsync", 1);
        let af = decompile_async(&method, &sm).unwrap();
        let sig = af.signature();
        assert!(sig.contains("async"));
        assert!(sig.contains("DoWorkAsync"));
    }

    #[test]
    fn test_async_function_signature_static() {
        let mut method = mock_async_method("StaticAsync", "Task");
        method.is_static = true;
        let sm = mock_state_machine("StaticAsync", 0);
        let af = decompile_async(&method, &sm).unwrap();
        let sig = af.signature();
        assert!(sig.contains("static"));
    }

    // ── Return type extraction ────────────────────────────────────────────────

    #[test]
    fn test_extract_task_inner_type_void() {
        assert_eq!(extract_task_inner_type("Task").unwrap(), "void");
        assert_eq!(extract_task_inner_type("System.Threading.Tasks.Task").unwrap(), "void");
    }

    #[test]
    fn test_extract_task_inner_type_generic() {
        assert_eq!(extract_task_inner_type("Task<int>").unwrap(), "int");
        assert_eq!(extract_task_inner_type("Task<string>").unwrap(), "string");
    }

    #[test]
    fn test_extract_task_inner_type_none() {
        assert!(extract_task_inner_type("void").is_none());
        assert!(extract_task_inner_type("int").is_none());
    }

    // ── lift_case_blocks ──────────────────────────────────────────────────────

    #[test]
    fn test_lift_case_blocks_empty() {
        let stmts = lift_case_blocks(&[]);
        assert!(stmts.is_empty());
    }

    #[test]
    fn test_lift_case_blocks_with_await() {
        let ap = AwaitPoint {
            state_index: 0,
            task_expr: Expr::Var("someTask".into()),
            awaiter_type: "TaskAwaiter<int>".into(),
            awaiter_field: "<>u__0".into(),
            il_offset: 10,
            resume_label: 20,
        };
        let case = StateMachineCase {
            state: 0, il_start: 10, il_end: 20,
            instructions: vec![],
            await_point: Some(ap),
        };
        let stmts = lift_case_blocks(&[case]);
        let has_await = stmts.iter().any(|s| matches!(s,
            Statement::VarDecl { init: Some(Expr::Await(_)), .. }));
        assert!(has_await);
    }

    // ── ILInstruction display ─────────────────────────────────────────────────

    #[test]
    fn test_il_instruction_display_ldfld() {
        let i = ILInstruction::LdFld { field: "<>1__state".into() };
        assert_eq!(format!("{i}"), "ldfld <>1__state");
    }

    #[test]
    fn test_il_instruction_display_switch() {
        let i = ILInstruction::Switch { labels: vec![0x10, 0x20] };
        let s = format!("{i}");
        assert!(s.contains("switch"));
        assert!(s.contains("0x10"));
    }

    #[test]
    fn test_il_instruction_display_call() {
        let i = ILInstruction::Call { method: "Foo::Bar".into(), arg_count: 2 };
        let s = format!("{i}");
        assert!(s.contains("call Foo::Bar"));
    }

    // ── recover_all_async_methods ─────────────────────────────────────────────

    #[test]
    fn test_recover_all_async_methods_finds_async() {
        let methods = vec![mock_async_method("DoWorkAsync", "Task<int>")];
        let types   = vec![mock_state_machine("DoWorkAsync", 1)];
        let results = recover_all_async_methods(&methods, &types);
        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());
    }

    #[test]
    fn test_recover_all_async_methods_skips_non_async() {
        let non_async = MethodDef {
            name: "Sync".into(), declaring_type: "C".into(), return_type: "void".into(),
            params: vec![], is_static: false, access: "public".into(),
            instructions: vec![], eh_table: vec![], custom_attributes: vec![],
        };
        let methods = vec![non_async];
        let types: Vec<TypeDef> = vec![];
        let results = recover_all_async_methods(&methods, &types);
        // Non-async method has no AsyncStateMachineAttribute → skipped.
        assert!(results.is_empty());
    }

    // ── Exception handling reconstruction ─────────────────────────────────────

    #[test]
    fn test_reconstruct_exception_handling_no_clauses() {
        let stmts = vec![Statement::Comment("// body".into())];
        let out = reconstruct_exception_handling(stmts.clone(), &[], &[]);
        assert_eq!(out.len(), stmts.len());
    }

    #[test]
    fn test_reconstruct_exception_handling_fault_only() {
        let stmts = vec![Statement::Comment("// body".into())];
        let fault = EHClause {
            kind: EHClauseKind::Fault,
            try_offset: 0, try_length: 10,
            handler_offset: 10, handler_length: 5,
            catch_type: None, filter_offset: None,
        };
        let out = reconstruct_exception_handling(stmts, &[fault], &[]);
        // Should wrap in TryCatch.
        assert!(out.iter().any(|s| matches!(s, Statement::TryCatch(_))));
    }

    #[test]
    fn test_reconstruct_exception_handling_catch_clause() {
        let stmts = vec![Statement::Comment("// body".into())];
        let catch = EHClause {
            kind: EHClauseKind::Catch,
            try_offset: 0, try_length: 10,
            handler_offset: 10, handler_length: 5,
            catch_type: Some("System.Exception".into()),
            filter_offset: None,
        };
        let out = reconstruct_exception_handling(stmts, &[catch], &[]);
        assert!(out.iter().any(|s| matches!(s, Statement::TryCatch(b)
            if !b.catch_clauses.is_empty())));
    }

    // ── Expr display ──────────────────────────────────────────────────────────

    #[test]
    fn test_expr_to_string_await() {
        let e = Expr::Await(Box::new(Expr::Var("fetchTask".into())));
        assert_eq!(expr_to_string(&e), "await fetchTask");
    }

    #[test]
    fn test_expr_to_string_call() {
        let e = Expr::Call {
            receiver: Some(Box::new(Expr::Var("client".into()))),
            method: "GetAsync".into(),
            args: vec![Expr::StrLit("http://example.com".into())],
        };
        let s = expr_to_string(&e);
        assert!(s.contains("GetAsync"));
        assert!(s.contains("client"));
    }

    #[test]
    fn test_expr_to_string_new() {
        let e = Expr::New { ty: "StringBuilder".into(), args: vec![] };
        assert_eq!(expr_to_string(&e), "new StringBuilder()");
    }

    // ── AsyncFunction display ─────────────────────────────────────────────────

    #[test]
    fn test_async_function_display() {
        let method = mock_async_method("DoWorkAsync", "Task<int>");
        let sm = mock_state_machine("DoWorkAsync", 1);
        let af = decompile_async(&method, &sm).unwrap();
        let display = format!("{af}");
        assert!(display.contains('{'));
        assert!(display.contains('}'));
    }
}
