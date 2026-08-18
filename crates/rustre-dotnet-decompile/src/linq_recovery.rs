//! LINQ and lambda expression recovery for C# decompilation.
//!
//! The C# compiler lowers LINQ queries and lambda expressions into:
//!
//! 1. **Lambda closures** — compiler-generated classes with names like `<>c` or
//!    `<>c__DisplayClass_N`, whose fields are the captured variables.
//! 2. **LINQ method chains** — sequences of calls to `Where()`, `Select()`,
//!    `OrderBy()`, `GroupBy()`, etc. on `IEnumerable<T>`.
//! 3. **LINQ query expressions** — `from x in … where … select …` syntax that
//!    the compiler turns into `SelectMany`/`Where`/`Select` chains.
//! 4. **`foreach` loops** — `GetEnumerator()` + `MoveNext()` + `Current` patterns.
//! 5. **Delegate calls** — `Action<T>`, `Func<T,R>`, `Predicate<T>` inferred from usage.


use ahash::AHashMap;
use std::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum LinqRecoveryError {
    #[error("type '{0}' is not a compiler-generated closure class")]
    NotAClosureClass(String),
    #[error("lambda class '{0}' has no Invoke method")]
    NoInvokeMethod(String),
    #[error("could not infer delegate type for lambda '{0}'")]
    DelegateInferenceFailed(String),
    #[error("LINQ chain is empty")]
    EmptyChain,
    #[error("unrecognised LINQ operator: '{0}'")]
    UnknownOperator(String),
    #[error("foreach pattern not matched at IL offset {0:#x}")]
    ForeachPatternNotMatched(u32),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, LinqRecoveryError>;

// ─── Lambda / delegate model ──────────────────────────────────────────────────

/// How a delegate type was inferred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelegateInferenceSource {
    /// The variable holding the lambda has a known delegate type.
    ExplicitVariable { ty: String },
    /// The lambda was passed directly as an argument to a typed parameter.
    MethodArgument { method: String, param_index: usize, ty: String },
    /// The lambda was stored in a field with a known type.
    FieldType { field: String, ty: String },
    /// Inferred from call-site usage (the delegate is invoked).
    CallSiteInference { return_type: String, param_types: Vec<String> },
    /// Unknown — could not determine the delegate type.
    Unknown,
}

/// One captured variable from a closure class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedVar {
    /// Compiler-generated field name in the closure class (e.g. `x`, `<>8__1`).
    pub field_name: String,
    /// Recovered original variable name.
    pub original_name: String,
    /// Type of the captured variable.
    pub ty: String,
    /// Whether the variable was captured by reference (ref-capture in C# is rare but possible).
    pub by_ref: bool,
}

/// A recovered lambda expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LambdaExpr {
    /// Name of the compiler-generated closure class (e.g. `<>c__DisplayClass_0`).
    pub class_name: String,
    /// Parameter list of the lambda.
    pub params: Vec<LambdaParam>,
    /// Return type of the lambda body.
    pub return_type: String,
    /// Recovered body (as a list of statements or a single expression).
    pub body: LambdaBody,
    /// Variables captured from the outer scope.
    pub captures: Vec<CapturedVar>,
    /// Inferred delegate type.
    pub delegate_type: Option<String>,
    pub inference_source: DelegateInferenceSource,
    /// Whether this lambda is a static lambda (no captures, emitted on `<>c`).
    pub is_static_lambda: bool,
}

impl LambdaExpr {
    /// Return a C# source representation.
    #[must_use] 
    pub fn to_csharp(&self) -> String {
        let params: Vec<String> = if self.params.len() == 1 && !self.params[0].has_explicit_type {
            vec![self.params[0].name.clone()]
        } else {
            self.params.iter()
                .map(|p| if p.has_explicit_type { format!("{} {}", p.ty, p.name) } else { p.name.clone() })
                .collect()
        };
        let param_str = if self.params.len() == 1 {
            params[0].clone()
        } else {
            format!("({})", params.join(", "))
        };
        let body_str = self.body.to_csharp();
        format!("{param_str} => {body_str}")
    }
}

impl fmt::Display for LambdaExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_csharp())
    }
}

/// One parameter of a lambda.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LambdaParam {
    pub name: String,
    pub ty: String,
    /// `true` if the type should be shown explicitly (inferred otherwise).
    pub has_explicit_type: bool,
}

/// The body of a lambda — either a single expression or a block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LambdaBody {
    /// Expression lambda: `x => x + 1`
    Expression(LambdaExprNode),
    /// Statement lambda: `x => { return x + 1; }`
    Block(Vec<LambdaStatement>),
}

impl LambdaBody {
    #[must_use] 
    pub fn to_csharp(&self) -> String {
        match self {
            Self::Expression(e) => e.to_csharp(),
            Self::Block(stmts) => {
                let inner: Vec<_> = stmts.iter().map(|s| format!("    {};", s.to_csharp())).collect();
                format!("{{ {} }}", inner.join(" "))
            }
        }
    }
}

/// A node in a lambda expression (simplified expression tree).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LambdaExprNode {
    Var(String),
    Field { receiver: Box<Self>, name: String },
    Call { receiver: Option<Box<Self>>, method: String, args: Vec<Self> },
    BinOp { op: String, left: Box<Self>, right: Box<Self> },
    UnOp { op: String, expr: Box<Self> },
    IntLit(i64),
    StrLit(String),
    BoolLit(bool),
    Null,
    New { ty: String, args: Vec<Self> },
    Cast { ty: String, expr: Box<Self> },
    AnonymousNew(Vec<(String, Self)>),
    Opaque(String),
}

impl LambdaExprNode {
    #[must_use] 
    pub fn to_csharp(&self) -> String {
        match self {
            Self::Var(n) => n.clone(),
            Self::Field { receiver, name } =>
                format!("{}.{}", receiver.to_csharp(), name),
            Self::Call { receiver, method, args } => {
                let r = receiver.as_ref().map(|r| format!("{}.", r.to_csharp())).unwrap_or_default();
                let a: Vec<_> = args.iter().map(Self::to_csharp).collect();
                format!("{}{}({})", r, method, a.join(", "))
            }
            Self::BinOp { op, left, right } =>
                format!("{} {} {}", left.to_csharp(), op, right.to_csharp()),
            Self::UnOp { op, expr } =>
                format!("{}{}", op, expr.to_csharp()),
            Self::IntLit(v) => v.to_string(),
            Self::StrLit(s) => format!("\"{s}\""),
            Self::BoolLit(b) => if *b { "true".to_string() } else { "false".to_string() },
            Self::Null => "null".to_string(),
            Self::New { ty, args } => {
                let a: Vec<_> = args.iter().map(Self::to_csharp).collect();
                format!("new {}({})", ty, a.join(", "))
            }
            Self::Cast { ty, expr } => format!("({}){}", ty, expr.to_csharp()),
            Self::AnonymousNew(fields) => {
                let f: Vec<_> = fields.iter()
                    .map(|(n, e)| format!("{} = {}", n, e.to_csharp()))
                    .collect();
                format!("new {{ {} }}", f.join(", "))
            }
            Self::Opaque(s) => s.clone(),
        }
    }
}

/// A statement inside a statement-lambda body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LambdaStatement {
    Return(Option<LambdaExprNode>),
    Assign { target: String, value: LambdaExprNode },
    Expr(LambdaExprNode),
    If { cond: LambdaExprNode, then: Box<Self>, else_: Option<Box<Self>> },
}

impl LambdaStatement {
    #[must_use] 
    pub fn to_csharp(&self) -> String {
        match self {
            Self::Return(None) => "return".to_string(),
            Self::Return(Some(e)) => format!("return {}", e.to_csharp()),
            Self::Assign { target, value } =>
                format!("{} = {}", target, value.to_csharp()),
            Self::Expr(e) => e.to_csharp(),
            Self::If { cond, then, else_ } => {
                let e = else_.as_ref().map(|e| format!(" else {}", e.to_csharp())).unwrap_or_default();
                format!("if ({}) {}{}", cond.to_csharp(), then.to_csharp(), e)
            }
        }
    }
}

// ─── LINQ operator model ──────────────────────────────────────────────────────

/// A single LINQ operator call in a method chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinqOperator {
    Where,
    Select,
    SelectMany,
    OrderBy,
    OrderByDescending,
    ThenBy,
    ThenByDescending,
    GroupBy,
    GroupJoin,
    Join,
    Distinct,
    DistinctBy,
    Take,
    TakeWhile,
    Skip,
    SkipWhile,
    First,
    FirstOrDefault,
    Last,
    LastOrDefault,
    Single,
    SingleOrDefault,
    Any,
    All,
    Count,
    LongCount,
    Sum,
    Min,
    Max,
    MinBy,
    MaxBy,
    Average,
    Aggregate,
    ToList,
    ToArray,
    ToDictionary,
    ToHashSet,
    ToLookup,
    AsEnumerable,
    AsQueryable,
    Cast,
    OfType,
    Zip,
    Concat,
    Union,
    Intersect,
    Except,
    Reverse,
    Contains,
    ElementAt,
    ElementAtOrDefault,
    DefaultIfEmpty,
    Append,
    Prepend,
    /// Extension method not in the standard set.
    Custom(String),
}

impl LinqOperator {
    /// Parse from a method name string (ignoring generics and arity suffixes).
    #[must_use] 
    pub fn from_method_name(name: &str) -> Option<Self> {
        let bare = name.split("::").last().unwrap_or(name)
            .split('<').next().unwrap_or(name)
            .trim_end_matches("()");
        match bare {
            "Where"               => Some(Self::Where),
            "Select"              => Some(Self::Select),
            "SelectMany"          => Some(Self::SelectMany),
            "OrderBy"             => Some(Self::OrderBy),
            "OrderByDescending"   => Some(Self::OrderByDescending),
            "ThenBy"              => Some(Self::ThenBy),
            "ThenByDescending"    => Some(Self::ThenByDescending),
            "GroupBy"             => Some(Self::GroupBy),
            "GroupJoin"           => Some(Self::GroupJoin),
            "Join"                => Some(Self::Join),
            "Distinct"            => Some(Self::Distinct),
            "DistinctBy"          => Some(Self::DistinctBy),
            "Take"                => Some(Self::Take),
            "TakeWhile"           => Some(Self::TakeWhile),
            "Skip"                => Some(Self::Skip),
            "SkipWhile"           => Some(Self::SkipWhile),
            "First"               => Some(Self::First),
            "FirstOrDefault"      => Some(Self::FirstOrDefault),
            "Last"                => Some(Self::Last),
            "LastOrDefault"       => Some(Self::LastOrDefault),
            "Single"              => Some(Self::Single),
            "SingleOrDefault"     => Some(Self::SingleOrDefault),
            "Any"                 => Some(Self::Any),
            "All"                 => Some(Self::All),
            "Count"               => Some(Self::Count),
            "LongCount"           => Some(Self::LongCount),
            "Sum"                 => Some(Self::Sum),
            "Min"                 => Some(Self::Min),
            "Max"                 => Some(Self::Max),
            "MinBy"               => Some(Self::MinBy),
            "MaxBy"               => Some(Self::MaxBy),
            "Average"             => Some(Self::Average),
            "Aggregate"           => Some(Self::Aggregate),
            "ToList"              => Some(Self::ToList),
            "ToArray"             => Some(Self::ToArray),
            "ToDictionary"        => Some(Self::ToDictionary),
            "ToHashSet"           => Some(Self::ToHashSet),
            "ToLookup"            => Some(Self::ToLookup),
            "AsEnumerable"        => Some(Self::AsEnumerable),
            "AsQueryable"         => Some(Self::AsQueryable),
            "Cast"                => Some(Self::Cast),
            "OfType"              => Some(Self::OfType),
            "Zip"                 => Some(Self::Zip),
            "Concat"              => Some(Self::Concat),
            "Union"               => Some(Self::Union),
            "Intersect"           => Some(Self::Intersect),
            "Except"              => Some(Self::Except),
            "Reverse"             => Some(Self::Reverse),
            "Contains"            => Some(Self::Contains),
            "ElementAt"           => Some(Self::ElementAt),
            "ElementAtOrDefault"  => Some(Self::ElementAtOrDefault),
            "DefaultIfEmpty"      => Some(Self::DefaultIfEmpty),
            "Append"              => Some(Self::Append),
            "Prepend"             => Some(Self::Prepend),
            _                     => None,
        }
    }

    #[must_use] 
    pub const fn is_terminal(&self) -> bool {
        matches!(self,
            Self::ToList | Self::ToArray | Self::ToDictionary | Self::ToHashSet
            | Self::ToLookup | Self::First | Self::FirstOrDefault | Self::Last
            | Self::LastOrDefault | Self::Single | Self::SingleOrDefault
            | Self::Any | Self::All | Self::Count | Self::LongCount
            | Self::Sum | Self::Min | Self::Max | Self::Average | Self::Aggregate
            | Self::Contains | Self::ElementAt | Self::ElementAtOrDefault)
    }
}

impl fmt::Display for LinqOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "{s}"),
            other => write!(f, "{other:?}"),
        }
    }
}

/// One step in a LINQ chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinqStep {
    pub operator: LinqOperator,
    pub lambdas: Vec<LambdaExpr>,
    /// For non-lambda args (e.g. `Take(10)`).
    pub scalar_args: Vec<String>,
    pub return_type: String,
    pub element_type: String,
}

impl LinqStep {
    #[must_use] 
    pub fn to_csharp(&self) -> String {
        let op = format!("{}", self.operator);
        let args: Vec<String> = self.lambdas.iter().map(LambdaExpr::to_csharp)
            .chain(self.scalar_args.iter().cloned())
            .collect();
        format!(".{}({})", op, args.join(", "))
    }
}

/// A complete LINQ method chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinqChain {
    /// The source expression (e.g. `customers`, `db.Orders`).
    pub source: String,
    /// The element type of the source.
    pub source_element_type: String,
    pub steps: Vec<LinqStep>,
    /// Final result type.
    pub result_type: String,
}

impl LinqChain {
    #[must_use] 
    pub fn to_method_chain(&self) -> String {
        let steps: Vec<_> = self.steps.iter().map(LinqStep::to_csharp).collect();
        format!("{}{}", self.source, steps.join(""))
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool { self.steps.is_empty() }
    #[must_use] 
    pub const fn len(&self) -> usize { self.steps.len() }
}

impl fmt::Display for LinqChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_method_chain())
    }
}

// ─── LINQ query expression ────────────────────────────────────────────────────

/// A query clause in a LINQ query expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryClause {
    /// `from <var> in <source>`
    From { var: String, source: String, ty: Option<String> },
    /// `where <predicate>`
    Where { predicate: LambdaExprNode },
    /// `orderby <key> [ascending | descending]`
    OrderBy { key: LambdaExprNode, descending: bool },
    /// `thenby <key> [ascending | descending]`
    ThenBy { key: LambdaExprNode, descending: bool },
    /// `select <projection>`
    Select { projection: LambdaExprNode },
    /// `group <element> by <key>`
    Group { element: LambdaExprNode, key: LambdaExprNode, into_var: Option<String> },
    /// `join <inner> on <outer_key> equals <inner_key> [into <var>]`
    Join { inner: String, outer_key: LambdaExprNode, inner_key: LambdaExprNode, result_var: String, into_var: Option<String> },
    /// `let <var> = <expr>`
    Let { var: String, expr: LambdaExprNode },
    /// `into <var>` continuation.
    Into { var: String },
}

impl QueryClause {
    #[must_use] 
    pub fn to_csharp(&self) -> String {
        match self {
            Self::From { var, source, ty } => {
                let ty_str = ty.as_deref().map(|t| format!("{t} ")).unwrap_or_default();
                format!("from {ty_str}{var} in {source}")
            }
            Self::Where { predicate } => format!("where {}", predicate.to_csharp()),
            Self::OrderBy { key, descending } => {
                let dir = if *descending { " descending" } else { "" };
                format!("orderby {}{}", key.to_csharp(), dir)
            }
            Self::ThenBy { key, descending } => {
                let dir = if *descending { " descending" } else { "" };
                format!("    , {}{}", key.to_csharp(), dir)
            }
            Self::Select { projection } => format!("select {}", projection.to_csharp()),
            Self::Group { element, key, into_var } => {
                let into = into_var.as_deref().map(|v| format!(" into {v}")).unwrap_or_default();
                format!("group {} by {}{}", element.to_csharp(), key.to_csharp(), into)
            }
            Self::Join { inner, outer_key, inner_key, result_var, into_var } => {
                let into = into_var.as_deref().map(|v| format!(" into {v}")).unwrap_or_default();
                format!("join {} on {} equals {} let {} = default{}",
                    inner, outer_key.to_csharp(), inner_key.to_csharp(), result_var, into)
            }
            Self::Let { var, expr } => format!("let {} = {}", var, expr.to_csharp()),
            Self::Into { var } => format!("into {var}"),
        }
    }
}

/// A full LINQ query expression (query syntax).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinqQuery {
    pub clauses: Vec<QueryClause>,
    pub result_type: String,
}

impl LinqQuery {
    #[must_use] 
    pub fn to_csharp(&self) -> String {
        self.clauses.iter().map(QueryClause::to_csharp).collect::<Vec<_>>().join("\n")
    }
}

impl fmt::Display for LinqQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_csharp())
    }
}

// ─── foreach recovery ─────────────────────────────────────────────────────────

/// Pattern for a compiler-generated `foreach` loop.
///
/// The compiler emits:
/// ```text
/// call GetEnumerator()    → stloc <enum>
/// try {
///   loop:
///     ldloc <enum>; callvirt MoveNext(); brfalse exit
///     ldloc <enum>; callvirt get_Current(); stloc <element>
///     <loop body using <element>>
///     br loop
/// } finally {
///   ldloc <enum>; callvirt Dispose()
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForeachPattern {
    /// IL offset of the `call GetEnumerator()`.
    pub get_enumerator_offset: u32,
    /// IL offset of the `callvirt MoveNext()`.
    pub move_next_offset: u32,
    /// IL offset of the `callvirt get_Current()`.
    pub get_current_offset: u32,
    /// Local variable slot holding the enumerator.
    pub enumerator_local: u16,
    /// Local variable slot holding the current element.
    pub element_local: u16,
    /// Type of the element (from `get_Current` return type).
    pub element_type: String,
    /// Recovered loop variable name.
    pub loop_var_name: String,
    /// IL offset range of the loop body.
    pub body_start: u32,
    pub body_end: u32,
}

// ─── Closure class detector ───────────────────────────────────────────────────

/// Whether a class name indicates a compiler-generated closure.
#[must_use] 
pub fn is_closure_class(class_name: &str) -> bool {
    // Static lambda holder: "<>c"
    // Display class: "<>c__DisplayClass_N" or "<Method>b__N" nested class
    class_name == "<>c"
        || class_name.starts_with("<>c__DisplayClass")
        || class_name.starts_with("<>c__")
        || (class_name.starts_with('<') && class_name.contains(">b__"))
        || (class_name.starts_with('<') && class_name.contains(">c__"))
}

/// Extract captured variables from a display class.
///
/// Every field of the display class that is not a compiler artefact represents
/// a captured variable.  For `<>c` (static lambda holder) there are no captures.
#[must_use] 
pub fn extract_captures(fields: &[ClosureField]) -> Vec<CapturedVar> {
    fields.iter()
        .filter(|f| !f.name.starts_with("CS$"))       // IL toolchain artefact
        .filter(|f| !f.name.contains("__instance"))   // <>c singleton
        .map(|f| {
            let original = recover_capture_name(&f.name);
            CapturedVar {
                field_name: f.name.clone(),
                original_name: original,
                ty: f.ty.clone(),
                by_ref: f.ty.starts_with("ref "),
            }
        })
        .collect()
}

/// Recover the programmer-visible name of a captured variable from its field name.
fn recover_capture_name(field_name: &str) -> String {
    // Common patterns:
    //   "<>3__x"       → "x"
    //   "x"            → "x" (already clean)
    //   "<>8__1"       → "local_1"  (unnamed, hoisted)
    field_name.strip_prefix("<>").map_or_else(|| field_name.to_string(), |rest| {
        let after_digits = rest.trim_start_matches(|c: char| c.is_ascii_digit());
        let after_dunder = after_digits.trim_start_matches("__");
        if after_dunder.is_empty() {
            format!("local_{field_name}")
        } else {
            after_dunder.to_string()
        }
    })
}

/// A field in a closure class (simplified).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosureField {
    pub name: String,
    pub ty: String,
}

/// Infer the delegate type for a lambda from usage context.
#[must_use] 
pub fn infer_delegate_type(
    param_types: &[String],
    return_type: &str,
) -> String {
    if return_type == "void" || return_type == "System.Void" {
        match param_types.len() {
            0 => "Action".to_string(),
            1 => format!("Action<{}>", param_types[0]),
            2 => format!("Action<{}, {}>", param_types[0], param_types[1]),
            n => format!("Action<{}>", param_types[..n.min(16)].join(", ")),
        }
    } else {
        let all_types: Vec<String> = param_types.iter().cloned()
            .chain(std::iter::once(return_type.to_string()))
            .collect();
        match param_types.len() {
            0 => format!("Func<{return_type}>"),
            _ => format!("Func<{}>", all_types.join(", ")),
        }
    }
}

// ─── LINQ chain recovery from IL ─────────────────────────────────────────────

/// A simplified IL call-site used for LINQ detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    pub il_offset: u32,
    /// Fully-qualified method name.
    pub method: String,
    /// Number of arguments (including `this` for extension methods).
    pub arg_count: u32,
    /// Return type.
    pub return_type: String,
    /// Lambda arguments (if any lambdas were passed).
    pub lambda_args: Vec<LambdaExpr>,
    /// Scalar arguments.
    pub scalar_args: Vec<String>,
}

/// Detect LINQ call sequences in a flat list of call sites.
///
/// Returns all chains found.  A chain ends when the next call is not a
/// recognised LINQ operator or when a terminal operator (`ToList`, Count, etc.) is reached.
#[must_use] 
pub fn detect_linq_chains(call_sites: &[CallSite]) -> Vec<LinqChain> {
    let mut chains = Vec::new();
    let mut i = 0;

    while i < call_sites.len() {
        let site = &call_sites[i];
        if let Some(op) = LinqOperator::from_method_name(&site.method) {
            // Start of a new chain.  Scan forward.
            // A chain that begins on a terminal operator (e.g. Count(), First())
            // collapses to a single step — there is nothing to chain into it.
            let starts_on_terminal = op.is_terminal();
            let source = derive_source_from_call(site);
            let source_element_type = derive_element_type(&site.return_type);

            let mut steps = Vec::new();
            let mut result_type = site.return_type.clone();
            let mut j = i;

            while j < call_sites.len() {
                let s = &call_sites[j];
                if let Some(linq_op) = LinqOperator::from_method_name(&s.method) {
                    let element_type = derive_element_type(&s.return_type);
                    result_type.clone_from(&s.return_type);
                    let is_terminal = linq_op.is_terminal();
                    steps.push(LinqStep {
                        operator: linq_op,
                        lambdas: s.lambda_args.clone(),
                        scalar_args: s.scalar_args.clone(),
                        return_type: s.return_type.clone(),
                        element_type,
                    });
                    j += 1;
                    if is_terminal { break; }
                } else {
                    break;
                }
            }

            if !steps.is_empty() {
                chains.push(LinqChain {
                    source,
                    source_element_type,
                    steps,
                    result_type,
                });
            }
            // If the opening operator was terminal we must not keep scanning
            // past it for more chains; advance one step explicitly.
            if starts_on_terminal && j == i {
                i += 1;
            } else {
                i = j;
            }
        } else {
            i += 1;
        }
    }

    chains
}

fn derive_source_from_call(site: &CallSite) -> String {
    if site.scalar_args.is_empty() {
        "source".to_string()
    } else {
        site.scalar_args[0].clone()
    }
}

fn derive_element_type(return_type: &str) -> String {
    // IEnumerable<T> → T, List<T> → T, etc.
    if let Some(inner) = extract_generic_arg(return_type, "IEnumerable") {
        return inner;
    }
    if let Some(inner) = extract_generic_arg(return_type, "IOrderedEnumerable") {
        return inner;
    }
    if let Some(inner) = extract_generic_arg(return_type, "IGrouping") {
        return inner;
    }
    if let Some(inner) = extract_generic_arg(return_type, "List") {
        return inner;
    }
    "object".to_string()
}

fn extract_generic_arg(ty: &str, outer: &str) -> Option<String> {
    let prefix = format!("{outer}<");
    if ty.starts_with(&prefix) || ty.contains(&prefix) {
        let start = ty.find('<')? + 1;
        let end = ty.rfind('>')?;
        Some(ty[start..end].to_string())
    } else {
        None
    }
}

// ─── foreach pattern detector ─────────────────────────────────────────────────

/// Detect the foreach pattern in a list of call sites.
///
/// Looks for the sequence: `GetEnumerator → MoveNext → get_Current`.
#[must_use] 
pub fn detect_foreach_patterns(call_sites: &[CallSite]) -> Vec<ForeachPattern> {
    let mut patterns = Vec::new();
    let mut i = 0;

    while i < call_sites.len() {
        if call_sites[i].method.contains("GetEnumerator") {
            let enum_site = &call_sites[i];

            // Find MoveNext after GetEnumerator.
            let move_next_pos = call_sites[i+1..].iter().position(|s| s.method.contains("MoveNext"));
            let get_current_pos = call_sites[i+1..].iter().position(|s| s.method.contains("get_Current"));

            if let (Some(mn), Some(gc)) = (move_next_pos, get_current_pos) {
                // MoveNext must appear before get_Current in the instruction
                // stream; if the positions are swapped the offsets would produce
                // body_end < body_start, corrupting downstream range operations.
                if mn < gc {
                    let mn_site = &call_sites[i + 1 + mn];
                    let gc_site = &call_sites[i + 1 + gc];

                    // `get_Current` returns the element type `T` directly,
                    // not an enumerable wrapper, so use it as-is.
                    let element_type = gc_site.return_type.clone();

                    patterns.push(ForeachPattern {
                        get_enumerator_offset: enum_site.il_offset,
                        move_next_offset: mn_site.il_offset,
                        get_current_offset: gc_site.il_offset,
                        enumerator_local: 0,
                        element_local: 1,
                        element_type: element_type.clone(),
                        loop_var_name: infer_foreach_var_name(&element_type),
                        body_start: gc_site.il_offset + 1,
                        body_end: mn_site.il_offset,
                    });
                    i += gc + 2;
                } else {
                    // Unexpected ordering — skip past GetEnumerator and retry.
                    i += 1;
                }
                continue;
            }
        }
        i += 1;
    }

    patterns
}

fn infer_foreach_var_name(element_type: &str) -> String {
    // Heuristic: use the lower-cased simple type name.
    let simple = element_type.split('.').next_back().unwrap_or(element_type);
    let simple = simple.split('<').next().unwrap_or(simple);
    if simple.is_empty() || simple == "object" {
        return "item".to_string();
    }
    let mut name = simple.to_string();
    if let Some(c) = name.chars().next() {
        let lower = c.to_lowercase().to_string();
        name = lower + &name[c.len_utf8()..];
    }
    name
}

// ─── LINQ method-chain → query-syntax conversion ──────────────────────────────

/// Convert a `LinqChain` into LINQ query syntax where possible.
///
/// Not all chains can be expressed as query syntax — those are returned as-is.
#[must_use] 
pub fn chain_to_query(chain: &LinqChain) -> Option<LinqQuery> {
    // Must start with at least a Where or Select.
    let has_where  = chain.steps.iter().any(|s| s.operator == LinqOperator::Where);
    let has_select = chain.steps.iter().any(|s| s.operator == LinqOperator::Select);
    if !has_where && !has_select {
        return None;
    }

    let mut clauses = Vec::new();
    let range_var = infer_foreach_var_name(&chain.source_element_type);

    // Initial `from` clause.
    clauses.push(QueryClause::From {
        var: range_var.clone(),
        source: chain.source.clone(),
        ty: None,
    });

    for step in &chain.steps {
        match &step.operator {
            LinqOperator::Where => {
                if let Some(lambda) = step.lambdas.first() {
                    let pred = lambda_to_expr_node(lambda);
                    clauses.push(QueryClause::Where { predicate: pred });
                }
            }
            LinqOperator::Select => {
                if let Some(lambda) = step.lambdas.first() {
                    let proj = lambda_to_expr_node(lambda);
                    clauses.push(QueryClause::Select { projection: proj });
                }
            }
            LinqOperator::OrderBy | LinqOperator::OrderByDescending => {
                if let Some(lambda) = step.lambdas.first() {
                    let key = lambda_to_expr_node(lambda);
                    clauses.push(QueryClause::OrderBy {
                        key,
                        descending: step.operator == LinqOperator::OrderByDescending,
                    });
                }
            }
            LinqOperator::ThenBy | LinqOperator::ThenByDescending => {
                if let Some(lambda) = step.lambdas.first() {
                    let key = lambda_to_expr_node(lambda);
                    clauses.push(QueryClause::ThenBy {
                        key,
                        descending: step.operator == LinqOperator::ThenByDescending,
                    });
                }
            }
            LinqOperator::GroupBy => {
                if let Some(key_lambda) = step.lambdas.first() {
                    let key = lambda_to_expr_node(key_lambda);
                    let elem = if step.lambdas.len() > 1 {
                        lambda_to_expr_node(&step.lambdas[1])
                    } else {
                        LambdaExprNode::Var(range_var.clone())
                    };
                    clauses.push(QueryClause::Group { element: elem, key, into_var: None });
                }
            }
            LinqOperator::SelectMany => {
                // `from x in source from y in x.collection select ...`
                if let Some(lambda) = step.lambdas.first() {
                    let inner = lambda_body_to_string(lambda);
                    clauses.push(QueryClause::From {
                        var: "inner".to_string(),
                        source: inner,
                        ty: None,
                    });
                }
            }
            // Terminal operators don't map to query syntax clauses.
            _ => {}
        }
    }

    // Ensure there is a select clause at the end.
    let has_select_clause = clauses.iter().any(|c| matches!(c, QueryClause::Select { .. } | QueryClause::Group { .. }));
    if !has_select_clause {
        clauses.push(QueryClause::Select {
            projection: LambdaExprNode::Var(range_var),
        });
    }

    Some(LinqQuery {
        clauses,
        result_type: chain.result_type.clone(),
    })
}

fn lambda_to_expr_node(lambda: &LambdaExpr) -> LambdaExprNode {
    match &lambda.body {
        LambdaBody::Expression(e) => e.clone(),
        LambdaBody::Block(stmts) => {
            // Use the return value of the first return statement.
            stmts.iter().find_map(|s| {
                if let LambdaStatement::Return(Some(e)) = s { Some(e.clone()) } else { None }
            }).unwrap_or_else(|| LambdaExprNode::Opaque("{...}".into()))
        }
    }
}

fn lambda_body_to_string(lambda: &LambdaExpr) -> String {
    lambda_to_expr_node(lambda).to_csharp()
}

// ─── Delegate inference ───────────────────────────────────────────────────────

/// Infer the delegate type for a lambda from the enclosing method's parameter list.
///
/// `method_name`  — the method that receives the lambda (e.g. `Where`, `Select`).
/// `param_index`  — which argument position the lambda occupies.
/// `element_type` — the element type `T` of the `IEnumerable<T>`.
#[must_use] 
pub fn infer_linq_lambda_delegate(
    method_name: &str,
    param_index: usize,
    element_type: &str,
    result_element_type: Option<&str>,
) -> String {
    let op = LinqOperator::from_method_name(method_name);
    match op {
        Some(LinqOperator::Where | LinqOperator::Any | LinqOperator::All | LinqOperator::Count) =>
            format!("Func<{element_type}, bool>"),
        Some(LinqOperator::Select | LinqOperator::GroupBy) => {
            let r = result_element_type.unwrap_or("object");
            format!("Func<{element_type}, {r}>")
        }
        Some(LinqOperator::SelectMany) => {
            let r = result_element_type.unwrap_or("object");
            if param_index == 0 {
                format!("Func<{element_type}, IEnumerable<{r}>>")
            } else {
                format!("Func<{element_type}, {r}, {r}>")
            }
        }
        Some(LinqOperator::OrderBy | LinqOperator::OrderByDescending |
LinqOperator::ThenBy | LinqOperator::ThenByDescending) => {
            let key = result_element_type.unwrap_or("int");
            format!("Func<{element_type}, {key}>")
        }
        Some(LinqOperator::Aggregate) => {
            let r = result_element_type.unwrap_or(element_type);
            format!("Func<{r}, {element_type}, {r}>")
        }
        _ => infer_delegate_type(&[element_type.to_string()], result_element_type.unwrap_or("object")),
    }
}

// ─── Bulk recovery ────────────────────────────────────────────────────────────

/// Summary of all LINQ/lambda patterns found in a method.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MethodLinqSummary {
    pub method_name: String,
    pub lambdas: Vec<LambdaExpr>,
    pub chains: Vec<LinqChain>,
    pub foreach_patterns: Vec<ForeachPattern>,
    pub query_expressions: Vec<LinqQuery>,
    /// Captured variables grouped by their owning closure class.
    #[serde(default)]
    pub captures_by_closure: Vec<(String, Vec<CapturedVar>)>,
}

impl MethodLinqSummary {
    #[must_use] 
    pub const fn has_linq(&self) -> bool {
        !self.lambdas.is_empty() || !self.chains.is_empty() || !self.foreach_patterns.is_empty()
    }
}

/// Recover all LINQ patterns from a list of call sites.
///
/// `closure_fields` is keyed by class names that originate from untrusted binary
/// input.  Accepting it as an `AHashMap` (randomised hash) prevents hash-collision
/// `DoS` where an attacker crafts many class names with identical `std` hash values.
#[must_use] 
pub fn recover_linq_summary(
    method_name: &str,
    call_sites: &[CallSite],
    closure_fields: &AHashMap<String, Vec<ClosureField>>,
) -> MethodLinqSummary {
    let chains = detect_linq_chains(call_sites);
    let foreach_patterns = detect_foreach_patterns(call_sites);

    // Convert chains to query syntax where possible.
    let query_expressions: Vec<LinqQuery> = chains.iter()
        .filter_map(chain_to_query)
        .collect();

    // Recover lambdas from all LINQ steps.
    let lambdas: Vec<LambdaExpr> = chains.iter()
        .flat_map(|c| c.steps.iter().flat_map(|s| s.lambdas.iter().cloned()))
        .collect();

    // Resolve captured variables for every closure class the method references.
    let mut captures_by_closure: Vec<(String, Vec<CapturedVar>)> = closure_fields
        .iter()
        .map(|(class_name, fields)| (class_name.clone(), extract_captures(fields)))
        .collect();
    captures_by_closure.sort_by(|a, b| a.0.cmp(&b.0));

    MethodLinqSummary {
        method_name: method_name.to_string(),
        lambdas,
        chains,
        foreach_patterns,
        query_expressions,
        captures_by_closure,
    }
}

// ─── Mock helpers ─────────────────────────────────────────────────────────────

/// Build a simple lambda `x => <body>` for tests.
#[must_use] 
pub fn mock_lambda(param: &str, body_expr: LambdaExprNode, return_type: &str) -> LambdaExpr {
    LambdaExpr {
        class_name: "<>c".to_string(),
        params: vec![LambdaParam {
            name: param.to_string(),
            ty: "var".to_string(),
            has_explicit_type: false,
        }],
        return_type: return_type.to_string(),
        body: LambdaBody::Expression(body_expr),
        captures: vec![],
        delegate_type: None,
        inference_source: DelegateInferenceSource::Unknown,
        is_static_lambda: true,
    }
}

/// Build a mock call site for a LINQ operator.
#[must_use] 
pub fn mock_linq_call(method: &str, lambda: LambdaExpr, return_type: &str) -> CallSite {
    CallSite {
        il_offset: 0,
        method: method.to_string(),
        arg_count: 2,
        return_type: return_type.to_string(),
        lambda_args: vec![lambda],
        scalar_args: vec!["source".to_string()],
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_closure_class ──────────────────────────────────────────────────────

    #[test]
    fn test_is_closure_class_static_holder() {
        assert!(is_closure_class("<>c"));
    }

    #[test]
    fn test_is_closure_class_display_class() {
        assert!(is_closure_class("<>c__DisplayClass_0"));
        assert!(is_closure_class("<>c__DisplayClass_12"));
    }

    #[test]
    fn test_is_closure_class_method_closure() {
        assert!(is_closure_class("<DoWork>b__0"));
        assert!(is_closure_class("<ProcessItems>c__0"));
    }

    #[test]
    fn test_is_closure_class_negative() {
        assert!(!is_closure_class("MyClass"));
        assert!(!is_closure_class("Program"));
        assert!(!is_closure_class("IEnumerable"));
    }

    // ── extract_captures ──────────────────────────────────────────────────────

    #[test]
    fn test_extract_captures_simple() {
        let fields = vec![
            ClosureField { name: "x".into(), ty: "int".into() },
            ClosureField { name: "prefix".into(), ty: "string".into() },
        ];
        let caps = extract_captures(&fields);
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0].original_name, "x");
        assert_eq!(caps[1].original_name, "prefix");
    }

    #[test]
    fn test_extract_captures_filters_cs_dollar() {
        let fields = vec![
            ClosureField { name: "CS$<>8__locals1".into(), ty: "object".into() },
            ClosureField { name: "realVar".into(), ty: "int".into() },
        ];
        let caps = extract_captures(&fields);
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].original_name, "realVar");
    }

    #[test]
    fn test_extract_captures_filters_instance_field() {
        let fields = vec![
            ClosureField { name: "<>__instance".into(), ty: "MyClass".into() },
            ClosureField { name: "y".into(), ty: "double".into() },
        ];
        let caps = extract_captures(&fields);
        assert_eq!(caps.len(), 1);
    }

    // ── recover_capture_name ──────────────────────────────────────────────────

    #[test]
    fn test_recover_capture_name_plain() {
        assert_eq!(recover_capture_name("x"), "x");
        assert_eq!(recover_capture_name("counter"), "counter");
    }

    #[test]
    fn test_recover_capture_name_compiler_generated() {
        // "<>3__x" → "x"
        let name = recover_capture_name("<>3__x");
        assert_eq!(name, "x");
    }

    // ── infer_delegate_type ───────────────────────────────────────────────────

    #[test]
    fn test_infer_delegate_type_action_no_params() {
        assert_eq!(infer_delegate_type(&[], "void"), "Action");
    }

    #[test]
    fn test_infer_delegate_type_action_one_param() {
        assert_eq!(infer_delegate_type(&["int".into()], "void"), "Action<int>");
    }

    #[test]
    fn test_infer_delegate_type_func_no_params() {
        assert_eq!(infer_delegate_type(&[], "bool"), "Func<bool>");
    }

    #[test]
    fn test_infer_delegate_type_func_one_param() {
        assert_eq!(infer_delegate_type(&["int".into()], "bool"), "Func<int, bool>");
    }

    #[test]
    fn test_infer_delegate_type_func_two_params() {
        assert_eq!(infer_delegate_type(&["int".into(), "string".into()], "bool"), "Func<int, string, bool>");
    }

    // ── LinqOperator ─────────────────────────────────────────────────────────

    #[test]
    fn test_linq_operator_from_method_name() {
        assert_eq!(LinqOperator::from_method_name("Where"), Some(LinqOperator::Where));
        assert_eq!(LinqOperator::from_method_name("Select"), Some(LinqOperator::Select));
        assert_eq!(LinqOperator::from_method_name("ToList"), Some(LinqOperator::ToList));
        assert_eq!(LinqOperator::from_method_name("Count"), Some(LinqOperator::Count));
        assert_eq!(LinqOperator::from_method_name("OrderBy"), Some(LinqOperator::OrderBy));
    }

    #[test]
    fn test_linq_operator_from_fqn() {
        let name = "System.Linq.Enumerable::Where<Customer>()";
        assert_eq!(LinqOperator::from_method_name(name), Some(LinqOperator::Where));
    }

    #[test]
    fn test_linq_operator_from_unknown() {
        assert!(LinqOperator::from_method_name("GetHashCode").is_none());
        assert!(LinqOperator::from_method_name("ToString").is_none());
    }

    #[test]
    fn test_linq_operator_is_terminal() {
        assert!(LinqOperator::ToList.is_terminal());
        assert!(LinqOperator::Count.is_terminal());
        assert!(LinqOperator::FirstOrDefault.is_terminal());
        assert!(!LinqOperator::Where.is_terminal());
        assert!(!LinqOperator::Select.is_terminal());
    }

    // ── detect_linq_chains ────────────────────────────────────────────────────

    #[test]
    fn test_detect_linq_chains_single_operator() {
        let lambda = mock_lambda("x", LambdaExprNode::BinOp {
            op: ">".into(),
            left: Box::new(LambdaExprNode::Var("x".into())),
            right: Box::new(LambdaExprNode::IntLit(0)),
        }, "bool");
        let sites = vec![mock_linq_call("Where", lambda, "IEnumerable<int>")];
        let chains = detect_linq_chains(&sites);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].steps.len(), 1);
        assert_eq!(chains[0].steps[0].operator, LinqOperator::Where);
    }

    #[test]
    fn test_detect_linq_chains_where_then_select_then_tolist() {
        let where_l = mock_lambda("x", LambdaExprNode::BoolLit(true), "bool");
        let select_l = mock_lambda("x", LambdaExprNode::Var("x".into()), "int");
        let sites = vec![
            mock_linq_call("Where",  where_l,  "IEnumerable<int>"),
            mock_linq_call("Select", select_l, "IEnumerable<int>"),
            CallSite {
                il_offset: 2, method: "ToList".into(), arg_count: 1,
                return_type: "List<int>".into(), lambda_args: vec![], scalar_args: vec![],
            },
        ];
        let chains = detect_linq_chains(&sites);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].len(), 3);
        assert_eq!(chains[0].steps[2].operator, LinqOperator::ToList);
    }

    #[test]
    fn test_detect_linq_chains_empty() {
        let chains = detect_linq_chains(&[]);
        assert!(chains.is_empty());
    }

    #[test]
    fn test_detect_linq_chains_non_linq() {
        let sites = vec![CallSite {
            il_offset: 0, method: "Console::WriteLine".into(), arg_count: 1,
            return_type: "void".into(), lambda_args: vec![], scalar_args: vec![],
        }];
        let chains = detect_linq_chains(&sites);
        assert!(chains.is_empty());
    }

    // ── LinqChain display ─────────────────────────────────────────────────────

    #[test]
    fn test_linq_chain_to_method_chain() {
        let lambda = mock_lambda("x", LambdaExprNode::BoolLit(true), "bool");
        let chain = LinqChain {
            source: "items".into(),
            source_element_type: "int".into(),
            steps: vec![LinqStep {
                operator: LinqOperator::Where,
                lambdas: vec![lambda],
                scalar_args: vec![],
                return_type: "IEnumerable<int>".into(),
                element_type: "int".into(),
            }],
            result_type: "IEnumerable<int>".into(),
        };
        let s = chain.to_method_chain();
        assert!(s.starts_with("items"));
        assert!(s.contains(".Where("));
    }

    // ── chain_to_query ────────────────────────────────────────────────────────

    #[test]
    fn test_chain_to_query_where_select() {
        let where_l = mock_lambda("x", LambdaExprNode::BoolLit(true), "bool");
        let select_l = mock_lambda("x", LambdaExprNode::Var("x".into()), "int");
        let chain = LinqChain {
            source: "numbers".into(),
            source_element_type: "int".into(),
            steps: vec![
                LinqStep { operator: LinqOperator::Where,  lambdas: vec![where_l],  scalar_args: vec![], return_type: "IEnumerable<int>".into(), element_type: "int".into() },
                LinqStep { operator: LinqOperator::Select, lambdas: vec![select_l], scalar_args: vec![], return_type: "IEnumerable<int>".into(), element_type: "int".into() },
            ],
            result_type: "IEnumerable<int>".into(),
        };
        let query = chain_to_query(&chain);
        assert!(query.is_some());
        let q = query.unwrap();
        let s = q.to_csharp();
        assert!(s.contains("from"));
        assert!(s.contains("where"));
        assert!(s.contains("select"));
    }

    #[test]
    fn test_chain_to_query_no_where_no_select() {
        let chain = LinqChain {
            source: "items".into(),
            source_element_type: "int".into(),
            steps: vec![LinqStep {
                operator: LinqOperator::OrderBy,
                lambdas: vec![mock_lambda("x", LambdaExprNode::Var("x".into()), "int")],
                scalar_args: vec![], return_type: "IOrderedEnumerable<int>".into(),
                element_type: "int".into(),
            }],
            result_type: "IOrderedEnumerable<int>".into(),
        };
        // No where or select → cannot convert to query syntax.
        assert!(chain_to_query(&chain).is_none());
    }

    // ── detect_foreach_patterns ───────────────────────────────────────────────

    #[test]
    fn test_detect_foreach_patterns_basic() {
        let sites = vec![
            CallSite { il_offset: 0, method: "GetEnumerator".into(), arg_count: 1,
                return_type: "IEnumerator<string>".into(), lambda_args: vec![], scalar_args: vec![] },
            CallSite { il_offset: 1, method: "MoveNext".into(), arg_count: 1,
                return_type: "bool".into(), lambda_args: vec![], scalar_args: vec![] },
            CallSite { il_offset: 2, method: "get_Current".into(), arg_count: 1,
                return_type: "string".into(), lambda_args: vec![], scalar_args: vec![] },
        ];
        let patterns = detect_foreach_patterns(&sites);
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].element_type, "string");
        assert_eq!(patterns[0].loop_var_name, "string");
    }

    #[test]
    fn test_detect_foreach_no_enumerator() {
        let sites = vec![
            CallSite { il_offset: 0, method: "Console::WriteLine".into(), arg_count: 1,
                return_type: "void".into(), lambda_args: vec![], scalar_args: vec![] },
        ];
        assert!(detect_foreach_patterns(&sites).is_empty());
    }

    // ── infer_foreach_var_name ────────────────────────────────────────────────

    #[test]
    fn test_infer_foreach_var_name_simple_types() {
        assert_eq!(infer_foreach_var_name("string"), "string");
        assert_eq!(infer_foreach_var_name("Customer"), "customer");
        assert_eq!(infer_foreach_var_name("OrderItem"), "orderItem");
    }

    #[test]
    fn test_infer_foreach_var_name_fqn() {
        assert_eq!(infer_foreach_var_name("System.String"), "string");
        assert_eq!(infer_foreach_var_name("System.Int32"), "int32");
    }

    #[test]
    fn test_infer_foreach_var_name_generic() {
        assert_eq!(infer_foreach_var_name("List<int>"), "list");
    }

    #[test]
    fn test_infer_foreach_var_name_empty() {
        assert_eq!(infer_foreach_var_name(""), "item");
        assert_eq!(infer_foreach_var_name("object"), "item");
    }

    // ── LambdaExpr display ────────────────────────────────────────────────────

    #[test]
    fn test_lambda_to_csharp_single_param() {
        let l = mock_lambda("x", LambdaExprNode::BinOp {
            op: ">".into(),
            left: Box::new(LambdaExprNode::Var("x".into())),
            right: Box::new(LambdaExprNode::IntLit(0)),
        }, "bool");
        let s = l.to_csharp();
        assert_eq!(s, "x => x > 0");
    }

    #[test]
    fn test_lambda_to_csharp_null_check() {
        let l = mock_lambda("item", LambdaExprNode::BinOp {
            op: "!=".into(),
            left: Box::new(LambdaExprNode::Var("item".into())),
            right: Box::new(LambdaExprNode::Null),
        }, "bool");
        assert!(l.to_csharp().contains("!= null"));
    }

    #[test]
    fn test_lambda_with_captures() {
        let mut l = mock_lambda("x", LambdaExprNode::Var("x".into()), "int");
        l.captures.push(CapturedVar {
            field_name: "threshold".into(),
            original_name: "threshold".into(),
            ty: "int".into(),
            by_ref: false,
        });
        l.is_static_lambda = false;
        assert!(!l.captures.is_empty());
    }

    // ── QueryClause display ───────────────────────────────────────────────────

    #[test]
    fn test_query_clause_from() {
        let c = QueryClause::From { var: "x".into(), source: "items".into(), ty: None };
        assert_eq!(c.to_csharp(), "from x in items");
    }

    #[test]
    fn test_query_clause_where() {
        let c = QueryClause::Where { predicate: LambdaExprNode::BoolLit(true) };
        assert_eq!(c.to_csharp(), "where true");
    }

    #[test]
    fn test_query_clause_select() {
        let c = QueryClause::Select { projection: LambdaExprNode::Var("x".into()) };
        assert_eq!(c.to_csharp(), "select x");
    }

    #[test]
    fn test_query_clause_orderby_ascending() {
        let c = QueryClause::OrderBy { key: LambdaExprNode::Var("name".into()), descending: false };
        let s = c.to_csharp();
        assert!(s.contains("orderby"));
        assert!(!s.contains("descending"));
    }

    #[test]
    fn test_query_clause_orderby_descending() {
        let c = QueryClause::OrderBy { key: LambdaExprNode::Var("age".into()), descending: true };
        assert!(c.to_csharp().contains("descending"));
    }

    // ── extract_generic_arg ───────────────────────────────────────────────────

    #[test]
    fn test_extract_generic_arg_ienumerable() {
        assert_eq!(extract_generic_arg("IEnumerable<Customer>", "IEnumerable"), Some("Customer".into()));
    }

    #[test]
    fn test_extract_generic_arg_list() {
        assert_eq!(extract_generic_arg("List<int>", "List"), Some("int".into()));
    }

    #[test]
    fn test_extract_generic_arg_not_found() {
        assert!(extract_generic_arg("IEnumerable<int>", "IQueryable").is_none());
    }

    // ── infer_linq_lambda_delegate ────────────────────────────────────────────

    #[test]
    fn test_infer_linq_lambda_delegate_where() {
        let d = infer_linq_lambda_delegate("Where", 0, "Customer", None);
        assert_eq!(d, "Func<Customer, bool>");
    }

    #[test]
    fn test_infer_linq_lambda_delegate_select() {
        let d = infer_linq_lambda_delegate("Select", 0, "Customer", Some("string"));
        assert_eq!(d, "Func<Customer, string>");
    }

    #[test]
    fn test_infer_linq_lambda_delegate_orderby() {
        let d = infer_linq_lambda_delegate("OrderBy", 0, "Customer", Some("string"));
        assert_eq!(d, "Func<Customer, string>");
    }

    #[test]
    fn test_infer_linq_lambda_delegate_any() {
        let d = infer_linq_lambda_delegate("Any", 0, "int", None);
        assert_eq!(d, "Func<int, bool>");
    }

    // ── recover_linq_summary ──────────────────────────────────────────────────

    #[test]
    fn test_recover_linq_summary_no_linq() {
        let sites = vec![CallSite {
            il_offset: 0, method: "ToString".into(), arg_count: 1,
            return_type: "string".into(), lambda_args: vec![], scalar_args: vec![],
        }];
        let summary = recover_linq_summary("Foo::Bar", &sites, &AHashMap::new());
        assert!(!summary.has_linq());
    }

    #[test]
    fn test_recover_linq_summary_with_where() {
        let lambda = mock_lambda("x", LambdaExprNode::BoolLit(true), "bool");
        let sites = vec![mock_linq_call("Where", lambda, "IEnumerable<int>")];
        let summary = recover_linq_summary("Foo::Bar", &sites, &AHashMap::new());
        assert!(summary.has_linq());
        assert_eq!(summary.chains.len(), 1);
    }

    // ── LambdaExprNode display ────────────────────────────────────────────────

    #[test]
    fn test_lambda_expr_node_anonymous_new() {
        let n = LambdaExprNode::AnonymousNew(vec![
            ("Name".into(), LambdaExprNode::Var("x".into())),
            ("Age".into(), LambdaExprNode::IntLit(30)),
        ]);
        let s = n.to_csharp();
        assert!(s.contains("new {"));
        assert!(s.contains("Name = x"));
        assert!(s.contains("Age = 30"));
    }

    #[test]
    fn test_lambda_expr_node_cast() {
        let n = LambdaExprNode::Cast { ty: "int".into(), expr: Box::new(LambdaExprNode::Var("x".into())) };
        assert_eq!(n.to_csharp(), "(int)x");
    }

    #[test]
    fn test_lambda_expr_node_new() {
        let n = LambdaExprNode::New { ty: "StringBuilder".into(), args: vec![] };
        assert_eq!(n.to_csharp(), "new StringBuilder()");
    }

    // ── LambdaBody display ────────────────────────────────────────────────────

    #[test]
    fn test_lambda_body_block() {
        let body = LambdaBody::Block(vec![
            LambdaStatement::Return(Some(LambdaExprNode::IntLit(42))),
        ]);
        let s = body.to_csharp();
        assert!(s.contains("return 42"));
    }

    #[test]
    fn test_lambda_body_expression() {
        let body = LambdaBody::Expression(LambdaExprNode::IntLit(1));
        assert_eq!(body.to_csharp(), "1");
    }

    // ── derive_element_type ───────────────────────────────────────────────────

    #[test]
    fn test_derive_element_type_ienumerable() {
        assert_eq!(derive_element_type("IEnumerable<string>"), "string");
    }

    #[test]
    fn test_derive_element_type_list() {
        assert_eq!(derive_element_type("List<Customer>"), "Customer");
    }

    #[test]
    fn test_derive_element_type_unknown() {
        assert_eq!(derive_element_type("void"), "object");
    }
}
