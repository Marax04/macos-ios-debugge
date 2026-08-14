//! Lua pattern matching for decompilation.
//!
//! Detects common Lua patterns (for-in loops, numeric for loops, method calls,
//! metatables, coroutines, pcall/xpcall patterns) and matches them against
//! an AST structure.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// LuaPattern
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies a recognisable Lua code pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LuaPattern {
    /// Numeric for loop: `for i = start, limit, step do`
    NumericFor,
    /// Generic for-in loop: `for k, v in iter do`
    GenericFor,
    /// Method call: `obj:method(args)`
    MethodCall,
    /// Metatable set: `setmetatable(t, mt)`
    SetMetatable,
    /// Metatable get: `getmetatable(t)`
    GetMetatable,
    /// Protected call: `pcall(f, ...)`
    Pcall,
    /// Extended protected call: `xpcall(f, handler, ...)`
    Xpcall,
    /// Coroutine creation: `coroutine.create(f)`
    CoroutineCreate,
    /// Coroutine resume: `coroutine.resume(co, ...)`
    CoroutineResume,
    /// Coroutine yield: `coroutine.yield(...)`
    CoroutineYield,
    /// Table constructor with mixed array/hash parts.
    TableConstructor,
    /// OOP class definition pattern: `ClassName = {}; ClassName.__index = ClassName`
    ClassDefinition,
    /// Mixin / module require: `local M = require("module")`
    RequireCall,
    /// String format: `string.format(fmt, ...)`
    StringFormat,
    /// Error propagation: `error(msg, level)`
    ErrorCall,
    /// Assert pattern: `assert(cond, msg)`
    AssertCall,
    /// Pairs iteration: `for k, v in pairs(t) do`
    PairsLoop,
    /// Ipairs iteration: `for i, v in ipairs(t) do`
    IpairsLoop,
    /// Metamethod definition: `mt.__index = function(t, k) ... end`
    MetamethodDef(MetamethodKind),
    /// Vararg forwarding: `local args = {...}`
    VarargCapture,
    /// String concatenation chain.
    StringConcat,
    /// Closure capturing upvalue.
    UpvalueClosure,
    /// User-defined or unrecognised pattern.
    Custom(String),
}

impl fmt::Display for LuaPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NumericFor => write!(f, "numeric-for"),
            Self::GenericFor => write!(f, "generic-for"),
            Self::MethodCall => write!(f, "method-call"),
            Self::SetMetatable => write!(f, "setmetatable"),
            Self::GetMetatable => write!(f, "getmetatable"),
            Self::Pcall => write!(f, "pcall"),
            Self::Xpcall => write!(f, "xpcall"),
            Self::CoroutineCreate => write!(f, "coroutine.create"),
            Self::CoroutineResume => write!(f, "coroutine.resume"),
            Self::CoroutineYield => write!(f, "coroutine.yield"),
            Self::TableConstructor => write!(f, "table-constructor"),
            Self::ClassDefinition => write!(f, "class-definition"),
            Self::RequireCall => write!(f, "require"),
            Self::StringFormat => write!(f, "string.format"),
            Self::ErrorCall => write!(f, "error"),
            Self::AssertCall => write!(f, "assert"),
            Self::PairsLoop => write!(f, "pairs-loop"),
            Self::IpairsLoop => write!(f, "ipairs-loop"),
            Self::MetamethodDef(k) => write!(f, "metamethod:{k}"),
            Self::VarargCapture => write!(f, "vararg-capture"),
            Self::StringConcat => write!(f, "string-concat"),
            Self::UpvalueClosure => write!(f, "upvalue-closure"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MetamethodKind
// ─────────────────────────────────────────────────────────────────────────────

/// Lua metamethod tag.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MetamethodKind {
    Index,
    NewIndex,
    Call,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    Unm,
    Idiv,
    Band,
    Bor,
    Bxor,
    Shl,
    Shr,
    Bnot,
    Concat,
    Len,
    Eq,
    Lt,
    Le,
    Tostring,
    Gc,
    Other(String),
}

impl fmt::Display for MetamethodKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Index => write!(f, "__index"),
            Self::NewIndex => write!(f, "__newindex"),
            Self::Call => write!(f, "__call"),
            Self::Add => write!(f, "__add"),
            Self::Sub => write!(f, "__sub"),
            Self::Mul => write!(f, "__mul"),
            Self::Div => write!(f, "__div"),
            Self::Mod => write!(f, "__mod"),
            Self::Pow => write!(f, "__pow"),
            Self::Unm => write!(f, "__unm"),
            Self::Idiv => write!(f, "__idiv"),
            Self::Band => write!(f, "__band"),
            Self::Bor => write!(f, "__bor"),
            Self::Bxor => write!(f, "__bxor"),
            Self::Shl => write!(f, "__shl"),
            Self::Shr => write!(f, "__shr"),
            Self::Bnot => write!(f, "__bnot"),
            Self::Concat => write!(f, "__concat"),
            Self::Len => write!(f, "__len"),
            Self::Eq => write!(f, "__eq"),
            Self::Lt => write!(f, "__lt"),
            Self::Le => write!(f, "__le"),
            Self::Tostring => write!(f, "__tostring"),
            Self::Gc => write!(f, "__gc"),
            Self::Other(s) => write!(f, "__{s}"),
        }
    }
}

impl MetamethodKind {
    /// Parse a metamethod name from a string key (with or without `__` prefix).
    #[must_use] 
    pub fn from_str(s: &str) -> Self {
        let key = s.trim_start_matches("__");
        match key {
            "index" => Self::Index,
            "newindex" => Self::NewIndex,
            "call" => Self::Call,
            "add" => Self::Add,
            "sub" => Self::Sub,
            "mul" => Self::Mul,
            "div" => Self::Div,
            "mod" => Self::Mod,
            "pow" => Self::Pow,
            "unm" => Self::Unm,
            "idiv" => Self::Idiv,
            "band" => Self::Band,
            "bor" => Self::Bor,
            "bxor" => Self::Bxor,
            "shl" => Self::Shl,
            "shr" => Self::Shr,
            "bnot" => Self::Bnot,
            "concat" => Self::Concat,
            "len" => Self::Len,
            "eq" => Self::Eq,
            "lt" => Self::Lt,
            "le" => Self::Le,
            "tostring" => Self::Tostring,
            "gc" => Self::Gc,
            other => Self::Other(other.to_string()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AST node types
// ─────────────────────────────────────────────────────────────────────────────

/// Simplified AST node for pattern matching.
#[derive(Debug, Clone, PartialEq)]
pub enum AstNode {
    /// Nil literal.
    Nil,
    /// Boolean literal.
    Bool(bool),
    /// Integer literal.
    Int(i64),
    /// Float literal.
    Float(f64),
    /// String literal.
    Str(String),
    /// Variable reference.
    Var(String),
    /// Function call: `func(args)`.
    Call { func: Box<Self>, args: Vec<Self> },
    /// Method call: `obj:method(args)`.
    MethodCall { obj: Box<Self>, method: String, args: Vec<Self> },
    /// Field access: `obj.field`.
    Field { obj: Box<Self>, field: String },
    /// Index access: `obj[key]`.
    Index { obj: Box<Self>, key: Box<Self> },
    /// Table constructor.
    Table(Vec<TableField>),
    /// Binary operation.
    Binop { op: String, lhs: Box<Self>, rhs: Box<Self> },
    /// Unary operation.
    Unop { op: String, operand: Box<Self> },
    /// Vararg `...`.
    Vararg,
    /// Closure.
    Closure { params: Vec<String>, body: Vec<Stmt> },
}

/// A field in a table constructor.
#[derive(Debug, Clone, PartialEq)]
pub enum TableField {
    /// `[key] = value`.
    Index { key: AstNode, value: AstNode },
    /// `name = value`.
    Named { name: String, value: AstNode },
    /// Positional value.
    Value(AstNode),
}

/// A Lua statement.
#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    /// Local assignment: `local a, b = ...`.
    Local { names: Vec<String>, values: Vec<AstNode> },
    /// Assignment: `a, b = ...`.
    Assign { targets: Vec<AstNode>, values: Vec<AstNode> },
    /// Expression statement (function call).
    Expr(AstNode),
    /// Do block.
    Do(Vec<Self>),
    /// While loop.
    While { cond: AstNode, body: Vec<Self> },
    /// Repeat loop.
    Repeat { cond: AstNode, body: Vec<Self> },
    /// If statement.
    If { cond: AstNode, then_body: Vec<Self>, else_body: Vec<Self> },
    /// Numeric for loop.
    NumericFor { var: String, start: AstNode, limit: AstNode, step: Option<AstNode>, body: Vec<Self> },
    /// Generic for loop.
    GenericFor { vars: Vec<String>, iterators: Vec<AstNode>, body: Vec<Self> },
    /// Function definition.
    Function { name: AstNode, params: Vec<String>, body: Vec<Self> },
    /// Return statement.
    Return(Vec<AstNode>),
    /// Break statement.
    Break,
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternMatch
// ─────────────────────────────────────────────────────────────────────────────

/// A successful match of a `LuaPattern` against AST content.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// Which pattern was matched.
    pub pattern: LuaPattern,
    /// The index of the statement in the parent block.
    pub stmt_idx: usize,
    /// Captures extracted by the match (keyed by capture name).
    pub captures: HashMap<String, String>,
    /// Confidence score (0–100).
    pub confidence: u8,
}

impl PatternMatch {
    /// Create a new match with full confidence.
    #[must_use] 
    pub fn new(pattern: LuaPattern, stmt_idx: usize) -> Self {
        Self {
            pattern,
            stmt_idx,
            captures: HashMap::new(),
            confidence: 100,
        }
    }

    /// Add a named capture.
    pub fn with_capture(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.captures.insert(name.into(), value.into());
        self
    }

    /// Set the confidence score.
    #[must_use] 
    pub const fn with_confidence(mut self, conf: u8) -> Self {
        self.confidence = conf;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopPattern
// ─────────────────────────────────────────────────────────────────────────────

/// Detailed information about a recognised loop pattern.
#[derive(Debug, Clone)]
pub struct LoopPattern {
    /// Loop kind.
    pub kind: LoopKind,
    /// The iteration variable names.
    pub vars: Vec<String>,
    /// Whether the loop is a pairs/ipairs sugar form.
    pub is_sugar: bool,
    /// Number of statements in the loop body.
    pub body_size: usize,
}

/// Loop kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopKind {
    NumericFor,
    PairsFor,
    IpairsFor,
    CustomIterFor,
    While,
    Repeat,
}

impl fmt::Display for LoopKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NumericFor => write!(f, "numeric-for"),
            Self::PairsFor => write!(f, "pairs-for"),
            Self::IpairsFor => write!(f, "ipairs-for"),
            Self::CustomIterFor => write!(f, "custom-iter-for"),
            Self::While => write!(f, "while"),
            Self::Repeat => write!(f, "repeat"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MethodCall
// ─────────────────────────────────────────────────────────────────────────────

/// Represents a detected method call pattern.
#[derive(Debug, Clone)]
pub struct MethodCallPattern {
    /// The object expression (as a string representation).
    pub object: String,
    /// The method name.
    pub method: String,
    /// Number of arguments.
    pub arg_count: usize,
    /// Whether this might be a constructor (name starts with `new` or is upper-case).
    pub is_constructor: bool,
}

impl MethodCallPattern {
    /// Create from a method-call AST node.
    #[must_use] 
    pub fn from_call(obj: &str, method: &str, arg_count: usize) -> Self {
        let is_constructor = method.starts_with("new")
            || method.chars().next().is_some_and(char::is_uppercase);
        Self {
            object: obj.to_string(),
            method: method.to_string(),
            arg_count,
            is_constructor,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternMatcher
// ─────────────────────────────────────────────────────────────────────────────

/// Matches Lua code patterns against statement sequences.
pub struct PatternMatcher {
    /// Whether to detect OOP class patterns.
    detect_oop: bool,
    /// Whether to detect coroutine patterns.
    detect_coroutines: bool,
    /// Whether to detect metatable patterns.
    detect_metatables: bool,
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self {
            detect_oop: true,
            detect_coroutines: true,
            detect_metatables: true,
        }
    }
}

impl PatternMatcher {
    /// Create a new matcher with all detectors enabled.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub const fn with_oop(mut self, enable: bool) -> Self {
        self.detect_oop = enable;
        self
    }

    #[must_use] 
    pub const fn with_coroutines(mut self, enable: bool) -> Self {
        self.detect_coroutines = enable;
        self
    }

    #[must_use] 
    pub const fn with_metatables(mut self, enable: bool) -> Self {
        self.detect_metatables = enable;
        self
    }

    /// Scan a block of statements and return all pattern matches found.
    #[must_use] 
    pub fn match_block(&self, stmts: &[Stmt]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        for (idx, stmt) in stmts.iter().enumerate() {
            matches.extend(self.match_stmt(stmt, idx));
        }
        // Also detect multi-statement patterns (OOP class definition).
        if self.detect_oop {
            matches.extend(self.detect_class_definitions(stmts));
        }
        matches
    }

    /// Match patterns against a single statement.
    fn match_stmt(&self, stmt: &Stmt, idx: usize) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        match stmt {
            Stmt::NumericFor { var, .. } => {
                matches.push(
                    PatternMatch::new(LuaPattern::NumericFor, idx)
                        .with_capture("var", var),
                );
                matches.extend(self.detect_loop_pattern(stmt, idx));
            }
            Stmt::GenericFor { vars, iterators, .. } => {
                let pat = self.classify_generic_for(iterators);
                matches.push(
                    PatternMatch::new(pat, idx)
                        .with_capture("vars", vars.join(",")),
                );
                matches.extend(self.detect_loop_pattern(stmt, idx));
            }
            Stmt::Expr(expr) => {
                matches.extend(self.match_expr(expr, idx));
            }
            Stmt::Assign { targets, values } => {
                matches.extend(self.match_assignment(targets, values, idx));
            }
            Stmt::Local { names, values } => {
                matches.extend(self.match_local(names, values, idx));
            }
            Stmt::Function { name, .. } => {
                matches.extend(self.match_function_def(name, idx));
            }
            _ => {}
        }
        matches
    }

    /// Classify a generic for iterator list.
    fn classify_generic_for(&self, iterators: &[AstNode]) -> LuaPattern {
        if let Some(AstNode::Call { func, .. }) = iterators.first()
            && let AstNode::Var(name) = func.as_ref() {
                return match name.as_str() {
                    "pairs" => LuaPattern::PairsLoop,
                    "ipairs" => LuaPattern::IpairsLoop,
                    _ => LuaPattern::GenericFor,
                };
            }
        LuaPattern::GenericFor
    }

    /// Match expression-level patterns.
    fn match_expr(&self, expr: &AstNode, idx: usize) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        match expr {
            AstNode::Call { func, args } => {
                if let AstNode::Var(name) = func.as_ref() {
                    match name.as_str() {
                        "pcall" => matches.push(
                            PatternMatch::new(LuaPattern::Pcall, idx)
                                .with_capture("argc", args.len().to_string()),
                        ),
                        "xpcall" => matches.push(
                            PatternMatch::new(LuaPattern::Xpcall, idx)
                                .with_capture("argc", args.len().to_string()),
                        ),
                        "setmetatable" => {
                            if self.detect_metatables {
                                matches.push(PatternMatch::new(LuaPattern::SetMetatable, idx));
                            }
                        }
                        "getmetatable" => {
                            if self.detect_metatables {
                                matches.push(PatternMatch::new(LuaPattern::GetMetatable, idx));
                            }
                        }
                        "require" => {
                            let module = args
                                .first()
                                .and_then(|a| if let AstNode::Str(s) = a { Some(s.as_str()) } else { None })
                                .unwrap_or("");
                            matches.push(
                                PatternMatch::new(LuaPattern::RequireCall, idx)
                                    .with_capture("module", module),
                            );
                        }
                        "error" => matches.push(PatternMatch::new(LuaPattern::ErrorCall, idx)),
                        "assert" => matches.push(PatternMatch::new(LuaPattern::AssertCall, idx)),
                        _ => {}
                    }
                } else if let AstNode::Field { obj, field } = func.as_ref() {
                    matches.extend(self.match_field_call(obj, field, args, idx));
                }
            }
            AstNode::MethodCall { obj, method, args } => {
                let obj_str = node_to_string(obj);
                matches.push(
                    PatternMatch::new(LuaPattern::MethodCall, idx)
                        .with_capture("obj", &obj_str)
                        .with_capture("method", method)
                        .with_capture("argc", args.len().to_string()),
                );
            }
            AstNode::Binop { op, .. } if op == ".." => {
                matches.push(PatternMatch::new(LuaPattern::StringConcat, idx));
            }
            AstNode::Vararg => {
                matches.push(PatternMatch::new(LuaPattern::VarargCapture, idx));
            }
            _ => {}
        }
        matches
    }

    /// Match field-access function calls (e.g. `coroutine.create`, `string.format`).
    fn match_field_call(
        &self,
        obj: &AstNode,
        field: &str,
        args: &[AstNode],
        idx: usize,
    ) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let obj_str = node_to_string(obj);
        match (obj_str.as_str(), field) {
            ("coroutine", "create") => {
                if self.detect_coroutines {
                    matches.push(PatternMatch::new(LuaPattern::CoroutineCreate, idx));
                }
            }
            ("coroutine", "resume") => {
                if self.detect_coroutines {
                    matches.push(
                        PatternMatch::new(LuaPattern::CoroutineResume, idx)
                            .with_capture("argc", args.len().to_string()),
                    );
                }
            }
            ("coroutine", "yield") => {
                if self.detect_coroutines {
                    matches.push(PatternMatch::new(LuaPattern::CoroutineYield, idx));
                }
            }
            ("string", "format") => {
                matches.push(
                    PatternMatch::new(LuaPattern::StringFormat, idx)
                        .with_capture("argc", args.len().to_string()),
                );
            }
            _ => {}
        }
        matches
    }

    /// Match assignment-level patterns.
    fn match_assignment(
        &self,
        targets: &[AstNode],
        values: &[AstNode],
        idx: usize,
    ) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        // Detect table constructor assignment.
        for val in values {
            if let AstNode::Table(_) = val {
                matches.push(PatternMatch::new(LuaPattern::TableConstructor, idx));
            }
        }
        // Detect metamethod definition: `mt.__index = function`
        if self.detect_metatables {
            for (target, value) in targets.iter().zip(values.iter()) {
                if let AstNode::Field { obj: _, field } = target
                    && field.starts_with("__") {
                        let kind = MetamethodKind::from_str(field);
                        matches.push(
                            PatternMatch::new(LuaPattern::MetamethodDef(kind), idx)
                                .with_capture("field", field),
                        );
                    }
                // Also detect: `ClassName.__index = ClassName`
                if let AstNode::Field { obj, field } = target
                    && field == "__index" {
                        if let AstNode::Var(cls) = value {
                            matches.push(
                                PatternMatch::new(LuaPattern::ClassDefinition, idx)
                                    .with_confidence(70)
                                    .with_capture("class", cls),
                            );
                        }
                        let _ = obj;
                    }
            }
        }
        // Detect closure capturing upvalue.
        for val in values {
            if let AstNode::Closure { .. } = val {
                matches.push(PatternMatch::new(LuaPattern::UpvalueClosure, idx));
            }
        }
        matches
    }

    /// Match local assignment patterns.
    fn match_local(
        &self,
        names: &[String],
        values: &[AstNode],
        idx: usize,
    ) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        for val in values {
            match val {
                AstNode::Table(_) => {
                    matches.push(PatternMatch::new(LuaPattern::TableConstructor, idx));
                }
                AstNode::Vararg => {
                    matches.push(PatternMatch::new(LuaPattern::VarargCapture, idx)
                        .with_capture("names", names.join(",")));
                }
                AstNode::Call { func, args } => {
                    if let AstNode::Var(name) = func.as_ref()
                        && name == "require" {
                            let module = args
                                .first()
                                .and_then(|a| if let AstNode::Str(s) = a { Some(s.as_str()) } else { None })
                                .unwrap_or("");
                            matches.push(
                                PatternMatch::new(LuaPattern::RequireCall, idx)
                                    .with_capture("module", module),
                            );
                        }
                }
                _ => {}
            }
        }
        matches
    }

    /// Match function definition patterns.
    fn match_function_def(&self, name: &AstNode, idx: usize) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        if let AstNode::Field { obj: _, field } = name
            && self.detect_metatables && field.starts_with("__") {
                let kind = MetamethodKind::from_str(field);
                matches.push(
                    PatternMatch::new(LuaPattern::MetamethodDef(kind), idx)
                        .with_capture("field", field),
                );
            }
        matches
    }

    /// Detect class definition patterns across multiple statements.
    fn detect_class_definitions(&self, stmts: &[Stmt]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        for (idx, stmt) in stmts.iter().enumerate() {
            // Pattern: `ClassName = {}` followed later by `ClassName.__index = ClassName`
            if let Stmt::Assign { targets, values } = stmt
                && let (Some(AstNode::Var(cls)), Some(AstNode::Table(_))) =
                    (targets.first(), values.first())
                {
                    // Check if a later statement sets __index.
                    let cls_clone = cls.clone();
                    let has_index_assign = stmts[idx + 1..].iter().any(|s| {
                        if let Stmt::Assign { targets: t2, values: v2 } = s
                            && let Some(AstNode::Field { obj, field }) = t2.first()
                                && field == "__index" && node_to_string(obj) == cls_clone
                                    && let Some(AstNode::Var(v)) = v2.first() {
                                        return *v == cls_clone;
                                    }
                        false
                    });
                    if has_index_assign {
                        matches.push(
                            PatternMatch::new(LuaPattern::ClassDefinition, idx)
                                .with_confidence(90)
                                .with_capture("class", cls),
                        );
                    }
                }
        }
        matches
    }

    /// Detect loop patterns and return `LoopPattern` descriptors embedded in
    /// `PatternMatch` captures.
    fn detect_loop_pattern(&self, stmt: &Stmt, idx: usize) -> Vec<PatternMatch> {
        let mut out = Vec::new();
        match stmt {
            Stmt::NumericFor { var, body, .. } => {
                out.push(
                    PatternMatch::new(LuaPattern::NumericFor, idx)
                        .with_capture("var", var)
                        .with_capture("body_size", body.len().to_string()),
                );
            }
            Stmt::GenericFor { vars, iterators, body } => {
                let kind = self.classify_generic_for(iterators);
                out.push(
                    PatternMatch::new(kind, idx)
                        .with_capture("vars", vars.join(","))
                        .with_capture("body_size", body.len().to_string()),
                );
            }
            _ => {}
        }
        out
    }

    /// Collect all method calls from an expression tree.
    #[must_use] 
    pub fn collect_method_calls(&self, stmts: &[Stmt]) -> Vec<MethodCallPattern> {
        let mut results = Vec::new();
        for stmt in stmts {
            collect_method_calls_from_stmt(stmt, &mut results);
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper functions
// ─────────────────────────────────────────────────────────────────────────────

/// Convert an AST node to a string representation (for captures).
fn node_to_string(node: &AstNode) -> String {
    match node {
        AstNode::Var(s) => s.clone(),
        AstNode::Field { obj, field } => format!("{}.{}", node_to_string(obj), field),
        AstNode::Str(s) => format!("\"{s}\""),
        AstNode::Int(n) => n.to_string(),
        AstNode::Float(f) => f.to_string(),
        AstNode::Bool(b) => b.to_string(),
        AstNode::Nil => "nil".to_string(),
        AstNode::Vararg => "...".to_string(),
        _ => "<expr>".to_string(),
    }
}

/// Recursively collect method calls from a statement.
fn collect_method_calls_from_stmt(stmt: &Stmt, out: &mut Vec<MethodCallPattern>) {
    match stmt {
        Stmt::Expr(e) => {
            collect_method_calls_from_expr(e, out);
        }
        Stmt::Return(exprs) => {
            for e in exprs {
                collect_method_calls_from_expr(e, out);
            }
        }
        Stmt::Local { values, .. } => {
            for v in values { collect_method_calls_from_expr(v, out); }
        }
        Stmt::Assign { values, .. } => {
            for v in values { collect_method_calls_from_expr(v, out); }
        }
        Stmt::NumericFor { body, .. }
        | Stmt::While { body, .. }
        | Stmt::Repeat { body, .. } => {
            for s in body { collect_method_calls_from_stmt(s, out); }
        }
        Stmt::GenericFor { body, .. } => {
            for s in body { collect_method_calls_from_stmt(s, out); }
        }
        Stmt::If { then_body, else_body, .. } => {
            for s in then_body { collect_method_calls_from_stmt(s, out); }
            for s in else_body { collect_method_calls_from_stmt(s, out); }
        }
        _ => {}
    }
}

fn collect_method_calls_from_expr(expr: &AstNode, out: &mut Vec<MethodCallPattern>) {
    if let AstNode::MethodCall { obj, method, args } = expr {
        out.push(MethodCallPattern::from_call(&node_to_string(obj), method, args.len()));
        for arg in args { collect_method_calls_from_expr(arg, out); }
    }
    if let AstNode::Call { func, args } = expr {
        collect_method_calls_from_expr(func, out);
        for arg in args { collect_method_calls_from_expr(arg, out); }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics over a set of pattern matches.
#[derive(Debug, Default)]
pub struct PatternStats {
    pub total: usize,
    pub by_pattern: HashMap<String, usize>,
}

impl PatternStats {
    #[must_use] 
    pub fn from_matches(matches: &[PatternMatch]) -> Self {
        let mut stats = Self { total: matches.len(), ..Default::default() };
        for m in matches {
            *stats.by_pattern.entry(m.pattern.to_string()).or_insert(0) += 1;
        }
        stats
    }

    #[must_use] 
    pub fn top_patterns(&self, n: usize) -> Vec<(&str, usize)> {
        let mut v: Vec<(&str, usize)> = self
            .by_pattern
            .iter()
            .map(|(k, &c)| (k.as_str(), c))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pcall_stmt() -> Stmt {
        Stmt::Expr(AstNode::Call {
            func: Box::new(AstNode::Var("pcall".into())),
            args: vec![AstNode::Var("f".into())],
        })
    }

    fn make_require_stmt(module: &str) -> Stmt {
        Stmt::Local {
            names: vec!["M".into()],
            values: vec![AstNode::Call {
                func: Box::new(AstNode::Var("require".into())),
                args: vec![AstNode::Str(module.into())],
            }],
        }
    }

    #[test]
    fn test_pcall_detection() {
        let matcher = PatternMatcher::new();
        let stmts = vec![make_pcall_stmt()];
        let matches = matcher.match_block(&stmts);
        assert!(matches.iter().any(|m| m.pattern == LuaPattern::Pcall));
    }

    #[test]
    fn test_require_detection() {
        let matcher = PatternMatcher::new();
        let stmts = vec![make_require_stmt("json")];
        let matches = matcher.match_block(&stmts);
        assert!(matches.iter().any(|m| m.pattern == LuaPattern::RequireCall));
        let req = matches.iter().find(|m| m.pattern == LuaPattern::RequireCall).unwrap();
        assert_eq!(req.captures.get("module").map(std::string::String::as_str), Some("json"));
    }

    #[test]
    fn test_numeric_for_detection() {
        let matcher = PatternMatcher::new();
        let stmts = vec![Stmt::NumericFor {
            var: "i".into(),
            start: AstNode::Int(1),
            limit: AstNode::Int(10),
            step: None,
            body: vec![],
        }];
        let matches = matcher.match_block(&stmts);
        assert!(matches.iter().any(|m| m.pattern == LuaPattern::NumericFor));
    }

    #[test]
    fn test_pairs_loop_detection() {
        let matcher = PatternMatcher::new();
        let stmts = vec![Stmt::GenericFor {
            vars: vec!["k".into(), "v".into()],
            iterators: vec![AstNode::Call {
                func: Box::new(AstNode::Var("pairs".into())),
                args: vec![AstNode::Var("t".into())],
            }],
            body: vec![],
        }];
        let matches = matcher.match_block(&stmts);
        assert!(matches.iter().any(|m| m.pattern == LuaPattern::PairsLoop));
    }

    #[test]
    fn test_method_call_detection() {
        let matcher = PatternMatcher::new();
        let stmts = vec![Stmt::Expr(AstNode::MethodCall {
            obj: Box::new(AstNode::Var("obj".into())),
            method: "doThing".into(),
            args: vec![],
        })];
        let matches = matcher.match_block(&stmts);
        assert!(matches.iter().any(|m| m.pattern == LuaPattern::MethodCall));
    }

    #[test]
    fn test_setmetatable_detection() {
        let matcher = PatternMatcher::new();
        let stmts = vec![Stmt::Expr(AstNode::Call {
            func: Box::new(AstNode::Var("setmetatable".into())),
            args: vec![AstNode::Var("t".into()), AstNode::Var("mt".into())],
        })];
        let matches = matcher.match_block(&stmts);
        assert!(matches.iter().any(|m| m.pattern == LuaPattern::SetMetatable));
    }

    #[test]
    fn test_metamethod_from_str() {
        assert_eq!(MetamethodKind::from_str("__index"), MetamethodKind::Index);
        assert_eq!(MetamethodKind::from_str("index"), MetamethodKind::Index);
        assert_eq!(MetamethodKind::from_str("__add"), MetamethodKind::Add);
    }

    #[test]
    fn test_pattern_stats() {
        let matches = vec![
            PatternMatch::new(LuaPattern::Pcall, 0),
            PatternMatch::new(LuaPattern::Pcall, 1),
            PatternMatch::new(LuaPattern::RequireCall, 2),
        ];
        let stats = PatternStats::from_matches(&matches);
        assert_eq!(stats.total, 3);
        let top = stats.top_patterns(2);
        assert_eq!(top[0].1, 2); // pcall appears twice
    }

    #[test]
    fn test_coroutine_create_detection() {
        let matcher = PatternMatcher::new();
        let stmts = vec![Stmt::Expr(AstNode::Call {
            func: Box::new(AstNode::Field {
                obj: Box::new(AstNode::Var("coroutine".into())),
                field: "create".into(),
            }),
            args: vec![AstNode::Var("f".into())],
        })];
        let matches = matcher.match_block(&stmts);
        assert!(matches.iter().any(|m| m.pattern == LuaPattern::CoroutineCreate));
    }

    #[test]
    fn test_table_constructor_in_assign() {
        let matcher = PatternMatcher::new();
        let stmts = vec![Stmt::Assign {
            targets: vec![AstNode::Var("t".into())],
            values: vec![AstNode::Table(vec![])],
        }];
        let matches = matcher.match_block(&stmts);
        assert!(matches.iter().any(|m| m.pattern == LuaPattern::TableConstructor));
    }

    #[test]
    fn test_node_to_string_field() {
        let node = AstNode::Field {
            obj: Box::new(AstNode::Var("a".into())),
            field: "b".into(),
        };
        assert_eq!(node_to_string(&node), "a.b");
    }
}
