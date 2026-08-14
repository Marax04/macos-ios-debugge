//! C# high-level pattern recognition for decompiled IL.
//!
//! Detects compiler-generated patterns such as async/await state machines,
//! LINQ comprehensions, delegate closures, anonymous classes, nullable
//! patterns, switch expressions, and pattern-matching constructs.

use ahash::AHashMap;
use std::collections::HashMap;
use std::fmt;

// ─── PatternConfidence ────────────────────────────────────────────────────────

/// Confidence level of a detected pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PatternConfidence {
    /// Weak heuristic match.
    Low,
    /// Likely but not definitive.
    Medium,
    /// Strong structural evidence.
    High,
}

impl fmt::Display for PatternConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
        }
    }
}

// ─── PatternLocation ──────────────────────────────────────────────────────────

/// The location (IL offset range) where a pattern was detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternLocation {
    pub start_offset: u32,
    pub end_offset: u32,
    pub containing_type: Option<String>,
    pub containing_method: Option<String>,
}

impl PatternLocation {
    #[must_use]
    pub const fn new(start_offset: u32, end_offset: u32) -> Self {
        Self { start_offset, end_offset, containing_type: None, containing_method: None }
    }

    #[must_use]
    pub fn with_context(mut self, type_name: impl Into<String>, method_name: impl Into<String>) -> Self {
        self.containing_type = Some(type_name.into());
        self.containing_method = Some(method_name.into());
        self
    }

    #[must_use]
    pub const fn span(&self) -> u32 {
        self.end_offset.saturating_sub(self.start_offset)
    }
}

// ─── AsyncAwaitPattern ───────────────────────────────────────────────────────

/// A detected async/await state machine.
///
/// The C# compiler transforms `async` methods into state machine types that
/// implement `IAsyncStateMachine`.  This struct captures the relevant
/// structural fields.
#[derive(Debug, Clone)]
pub struct AsyncAwaitPattern {
    /// Name of the compiler-generated state machine type.
    pub state_machine_type: String,
    /// The IL field holding the current state index.
    pub state_field: String,
    /// The `MoveNext` method that drives the state machine.
    pub move_next_method: String,
    /// Awaitable expressions discovered in the state machine.
    pub awaited_expressions: Vec<String>,
    /// Number of states (await points + 1).
    pub state_count: u32,
    /// Whether the async method is a value-returning method (`Task<T>`).
    pub is_generic: bool,
    /// Return type of the async method.
    pub return_type: String,
    pub confidence: PatternConfidence,
    pub location: PatternLocation,
}

impl AsyncAwaitPattern {
    #[must_use]
    pub fn new(state_machine_type: impl Into<String>, location: PatternLocation) -> Self {
        Self {
            state_machine_type: state_machine_type.into(),
            state_field: "<>1__state".into(),
            move_next_method: "MoveNext".into(),
            awaited_expressions: Vec::new(),
            state_count: 0,
            is_generic: false,
            return_type: "Task".into(),
            confidence: PatternConfidence::High,
            location,
        }
    }

    /// Format a human-readable description of this async pattern.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "async {} ({} await points, confidence={})",
            self.state_machine_type,
            self.state_count,
            self.confidence,
        )
    }
}

// ─── LinqPattern ─────────────────────────────────────────────────────────────

/// A detected LINQ query expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinqOperator {
    Where,
    Select,
    SelectMany,
    OrderBy,
    OrderByDescending,
    GroupBy,
    Join,
    First,
    FirstOrDefault,
    Single,
    SingleOrDefault,
    Any,
    All,
    Count,
    Sum,
    ToList,
    ToArray,
    ToDictionary,
    Aggregate,
}

impl fmt::Display for LinqOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Where => "Where",
            Self::Select => "Select",
            Self::SelectMany => "SelectMany",
            Self::OrderBy => "OrderBy",
            Self::OrderByDescending => "OrderByDescending",
            Self::GroupBy => "GroupBy",
            Self::Join => "Join",
            Self::First => "First",
            Self::FirstOrDefault => "FirstOrDefault",
            Self::Single => "Single",
            Self::SingleOrDefault => "SingleOrDefault",
            Self::Any => "Any",
            Self::All => "All",
            Self::Count => "Count",
            Self::Sum => "Sum",
            Self::ToList => "ToList",
            Self::ToArray => "ToArray",
            Self::ToDictionary => "ToDictionary",
            Self::Aggregate => "Aggregate",
        };
        write!(f, "{name}")
    }
}

/// A detected LINQ comprehension chain.
#[derive(Debug, Clone)]
pub struct LinqPattern {
    /// Source expression type (what the query is over).
    pub source_type: String,
    /// Sequence of LINQ operators applied.
    pub operators: Vec<LinqOperator>,
    /// Whether this LINQ chain uses query syntax (`from x in ...`).
    pub is_query_syntax: bool,
    /// Element type being projected (if known).
    pub element_type: Option<String>,
    pub confidence: PatternConfidence,
    pub location: PatternLocation,
}

impl LinqPattern {
    #[must_use]
    pub fn new(source_type: impl Into<String>, location: PatternLocation) -> Self {
        Self {
            source_type: source_type.into(),
            operators: Vec::new(),
            is_query_syntax: false,
            element_type: None,
            confidence: PatternConfidence::Medium,
            location,
        }
    }

    /// Format the LINQ chain as a C#-like expression.
    #[must_use]
    pub fn format_chain(&self) -> String {
        let ops: Vec<String> = self.operators.iter().map(std::string::ToString::to_string).collect();
        format!("{}.{}", self.source_type, ops.join("."))
    }

    /// Returns `true` if this LINQ chain is a terminal (materialisation) operator.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.operators.last().is_some_and(|o| {
            matches!(o, LinqOperator::ToList | LinqOperator::ToArray | LinqOperator::ToDictionary
                     | LinqOperator::First | LinqOperator::FirstOrDefault
                     | LinqOperator::Single | LinqOperator::SingleOrDefault
                     | LinqOperator::Count | LinqOperator::Sum | LinqOperator::Any | LinqOperator::All)
        })
    }
}

// ─── DelegatePattern ─────────────────────────────────────────────────────────

/// A detected delegate, anonymous method, or lambda expression.
#[derive(Debug, Clone)]
pub struct DelegatePattern {
    /// Delegate type (e.g. `Action<int>`, `Func<string, bool>`).
    pub delegate_type: String,
    /// The compiler-generated method backing the lambda/anonymous method.
    pub backing_method: Option<String>,
    /// Captured variables in the closure.
    pub captured_variables: Vec<(String, String)>, // (name, type)
    /// Whether this is a multicast delegate.
    pub is_multicast: bool,
    /// Whether this is a lambda (anonymous function).
    pub is_lambda: bool,
    pub confidence: PatternConfidence,
    pub location: PatternLocation,
}

impl DelegatePattern {
    #[must_use]
    pub fn new(delegate_type: impl Into<String>, location: PatternLocation) -> Self {
        Self {
            delegate_type: delegate_type.into(),
            backing_method: None,
            captured_variables: Vec::new(),
            is_multicast: false,
            is_lambda: false,
            confidence: PatternConfidence::High,
            location,
        }
    }

    /// Returns `true` if this delegate captures any variables.
    #[must_use]
    pub const fn is_closure(&self) -> bool {
        !self.captured_variables.is_empty()
    }
}

// ─── AnonymousClass ──────────────────────────────────────────────────────────

/// A compiler-generated anonymous type (from `new { ... }` expressions).
#[derive(Debug, Clone)]
pub struct AnonymousClass {
    /// Compiler-generated type name.
    pub generated_name: String,
    /// Property names and their inferred types.
    pub properties: Vec<(String, String)>,
    /// Whether this is a record struct (C# 10+).
    pub is_record_struct: bool,
    pub confidence: PatternConfidence,
    pub location: PatternLocation,
}

impl AnonymousClass {
    #[must_use]
    pub fn new(generated_name: impl Into<String>, location: PatternLocation) -> Self {
        Self {
            generated_name: generated_name.into(),
            properties: Vec::new(),
            is_record_struct: false,
            confidence: PatternConfidence::High,
            location,
        }
    }

    /// Format as a C# anonymous type initializer string.
    #[must_use]
    pub fn format(&self) -> String {
        let props: Vec<String> = self.properties.iter()
            .map(|(name, ty)| format!("{name}: {ty}"))
            .collect();
        format!("new {{ {} }}", props.join(", "))
    }
}

// ─── NullablePattern ─────────────────────────────────────────────────────────

/// A detected nullable value pattern (`T?`).
#[derive(Debug, Clone)]
pub enum NullableKind {
    /// `Nullable<T>` struct wrapping a value type.
    ValueType(String),
    /// Nullable reference type annotation (`T?` on a reference type).
    ReferenceType(String),
    /// Null-conditional (`?.`) operator usage.
    NullConditional,
    /// Null-coalescing (`??`) operator usage.
    NullCoalescing,
    /// Null-coalescing assignment (`??=`) usage.
    NullCoalescingAssignment,
    /// `is null` / `is not null` pattern test.
    NullCheck,
}

#[derive(Debug, Clone)]
pub struct NullablePattern {
    pub kind: NullableKind,
    pub inner_type: String,
    pub has_value_check: bool,
    pub confidence: PatternConfidence,
    pub location: PatternLocation,
}

impl NullablePattern {
    #[must_use]
    pub fn new(kind: NullableKind, inner_type: impl Into<String>, location: PatternLocation) -> Self {
        Self {
            kind,
            inner_type: inner_type.into(),
            has_value_check: false,
            confidence: PatternConfidence::High,
            location,
        }
    }
}

// ─── SwitchExpression ─────────────────────────────────────────────────────────

/// An arm of a switch expression.
#[derive(Debug, Clone)]
pub struct SwitchArm {
    /// The pattern in the arm (e.g. `> 0`, `string s`, `null`).
    pub pattern: String,
    /// Optional guard (`when` clause).
    pub guard: Option<String>,
    /// The expression this arm evaluates to.
    pub result_expr: String,
    /// IL offset of this arm.
    pub offset: u32,
}

/// A C# 8+ switch expression (`expr switch { ... }`).
#[derive(Debug, Clone)]
pub struct SwitchExpression {
    /// The input expression being switched over.
    pub input_expression: String,
    /// Type of the input.
    pub input_type: String,
    /// All arms in the switch expression.
    pub arms: Vec<SwitchArm>,
    /// Whether the switch has a discard arm (`_ => ...`).
    pub has_discard: bool,
    /// Return type of the switch expression.
    pub result_type: String,
    pub confidence: PatternConfidence,
    pub location: PatternLocation,
}

impl SwitchExpression {
    #[must_use]
    pub fn new(input_expression: impl Into<String>, input_type: impl Into<String>, location: PatternLocation) -> Self {
        Self {
            input_expression: input_expression.into(),
            input_type: input_type.into(),
            arms: Vec::new(),
            has_discard: false,
            result_type: "var".into(),
            confidence: PatternConfidence::Medium,
            location,
        }
    }

    /// Add a switch arm.
    pub fn add_arm(&mut self, arm: SwitchArm) {
        if arm.pattern == "_" {
            self.has_discard = true;
        }
        self.arms.push(arm);
    }

    /// Returns `true` if the switch expression is exhaustive.
    #[must_use]
    pub const fn is_exhaustive(&self) -> bool {
        self.has_discard || !self.arms.is_empty()
    }
}

// ─── PatternMatching ──────────────────────────────────────────────────────────

/// Kind of C# pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchPatternKind {
    /// `is SomeType`
    TypePattern(String),
    /// `is SomeType name`
    DeclarationPattern { type_name: String, variable: String },
    /// `is { Prop: value }`
    PropertyPattern { type_name: String, properties: Vec<(String, String)> },
    /// `is (a, b)`
    PositionalPattern { type_name: String, subpatterns: Vec<String> },
    /// `is > 0`, `is < 100`
    RelationalPattern { operator: String, constant: String },
    /// `is not null`
    NegationPattern(Box<Self>),
    /// `is p1 and p2`
    ConjunctivePattern,
    /// `is p1 or p2`
    DisjunctivePattern,
    /// `is null`
    NullPattern,
    /// `is _`
    DiscardPattern,
    /// Constant value pattern (`is 42`)
    ConstantPattern(String),
}

/// A C# pattern-matching construct.
#[derive(Debug, Clone)]
pub struct PatternMatching {
    /// The expression being tested.
    pub subject_expression: String,
    /// The type of the subject.
    pub subject_type: String,
    /// The pattern being matched.
    pub pattern: MatchPatternKind,
    /// Whether this is an `is` expression or a `when` guard.
    pub is_guard: bool,
    /// Variable bound by the pattern, if any.
    pub bound_variable: Option<String>,
    pub confidence: PatternConfidence,
    pub location: PatternLocation,
}

impl PatternMatching {
    #[must_use]
    pub fn new(
        subject: impl Into<String>,
        subject_type: impl Into<String>,
        pattern: MatchPatternKind,
        location: PatternLocation,
    ) -> Self {
        Self {
            subject_expression: subject.into(),
            subject_type: subject_type.into(),
            pattern,
            is_guard: false,
            bound_variable: None,
            confidence: PatternConfidence::High,
            location,
        }
    }
}

// ─── CsharpPattern (union) ────────────────────────────────────────────────────

/// Any detected C# high-level pattern.
#[derive(Debug, Clone)]
pub enum CsharpPattern {
    AsyncAwait(AsyncAwaitPattern),
    Linq(LinqPattern),
    Delegate(DelegatePattern),
    Anonymous(AnonymousClass),
    Nullable(NullablePattern),
    Switch(SwitchExpression),
    PatternMatch(PatternMatching),
}

impl CsharpPattern {
    /// Return the confidence of this pattern.
    #[must_use]
    pub const fn confidence(&self) -> PatternConfidence {
        match self {
            Self::AsyncAwait(p) => p.confidence,
            Self::Linq(p) => p.confidence,
            Self::Delegate(p) => p.confidence,
            Self::Anonymous(p) => p.confidence,
            Self::Nullable(p) => p.confidence,
            Self::Switch(p) => p.confidence,
            Self::PatternMatch(p) => p.confidence,
        }
    }

    /// Return the location of this pattern.
    #[must_use]
    pub const fn location(&self) -> &PatternLocation {
        match self {
            Self::AsyncAwait(p) => &p.location,
            Self::Linq(p) => &p.location,
            Self::Delegate(p) => &p.location,
            Self::Anonymous(p) => &p.location,
            Self::Nullable(p) => &p.location,
            Self::Switch(p) => &p.location,
            Self::PatternMatch(p) => &p.location,
        }
    }

    /// Return a short name for this pattern kind.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::AsyncAwait(_) => "AsyncAwait",
            Self::Linq(_) => "Linq",
            Self::Delegate(_) => "Delegate",
            Self::Anonymous(_) => "AnonymousClass",
            Self::Nullable(_) => "Nullable",
            Self::Switch(_) => "SwitchExpression",
            Self::PatternMatch(_) => "PatternMatching",
        }
    }
}

// ─── CsharpPatterns ───────────────────────────────────────────────────────────

/// Central registry of all detected C# patterns in a decompiled assembly.
#[derive(Debug, Default)]
pub struct CsharpPatterns {
    /// All detected patterns, keyed by their start IL offset.
    patterns: Vec<CsharpPattern>,
    /// Per-method pattern counts.
    /// Uses `AHashMap` (randomised hash) so that attacker-controlled method names
    /// from untrusted binaries cannot trigger hash-collision `DoS`.
    method_counts: AHashMap<String, usize>,
}

impl CsharpPatterns {
    /// Create an empty `CsharpPatterns` registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a detected pattern.
    pub fn add(&mut self, pattern: CsharpPattern) {
        if let Some(method) = pattern.location().containing_method.clone() {
            *self.method_counts.entry(method).or_insert(0) += 1;
        }
        self.patterns.push(pattern);
    }

    /// Total number of detected patterns.
    #[must_use]
    pub const fn total_count(&self) -> usize {
        self.patterns.len()
    }

    /// Return all patterns of a given kind.
    #[must_use]
    pub fn of_kind(&self, kind: &str) -> Vec<&CsharpPattern> {
        self.patterns.iter().filter(|p| p.kind_name() == kind).collect()
    }

    /// Return all patterns with at least `min_confidence`.
    #[must_use]
    pub fn with_min_confidence(&self, min: PatternConfidence) -> Vec<&CsharpPattern> {
        self.patterns.iter().filter(|p| p.confidence() >= min).collect()
    }

    /// Return all async/await patterns.
    #[must_use]
    pub fn async_patterns(&self) -> Vec<&AsyncAwaitPattern> {
        self.patterns.iter().filter_map(|p| {
            if let CsharpPattern::AsyncAwait(a) = p { Some(a) } else { None }
        }).collect()
    }

    /// Return all LINQ patterns.
    #[must_use]
    pub fn linq_patterns(&self) -> Vec<&LinqPattern> {
        self.patterns.iter().filter_map(|p| {
            if let CsharpPattern::Linq(l) = p { Some(l) } else { None }
        }).collect()
    }

    /// Return all delegate patterns.
    #[must_use]
    pub fn delegate_patterns(&self) -> Vec<&DelegatePattern> {
        self.patterns.iter().filter_map(|p| {
            if let CsharpPattern::Delegate(d) = p { Some(d) } else { None }
        }).collect()
    }

    /// Return all anonymous class patterns.
    #[must_use]
    pub fn anonymous_classes(&self) -> Vec<&AnonymousClass> {
        self.patterns.iter().filter_map(|p| {
            if let CsharpPattern::Anonymous(a) = p { Some(a) } else { None }
        }).collect()
    }

    /// Return all switch expression patterns.
    #[must_use]
    pub fn switch_expressions(&self) -> Vec<&SwitchExpression> {
        self.patterns.iter().filter_map(|p| {
            if let CsharpPattern::Switch(s) = p { Some(s) } else { None }
        }).collect()
    }

    /// Return all pattern-matching patterns.
    #[must_use]
    pub fn pattern_matches(&self) -> Vec<&PatternMatching> {
        self.patterns.iter().filter_map(|p| {
            if let CsharpPattern::PatternMatch(m) = p { Some(m) } else { None }
        }).collect()
    }

    /// Return the method name with the most patterns detected.
    #[must_use]
    pub fn busiest_method(&self) -> Option<(&str, usize)> {
        // `method_counts` is an `AHashMap` — a hash map, so iteration order is
        // not reproducible. Equal pattern counts must be broken on the method
        // name, or the reported busiest method changes between runs.
        self.method_counts
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(k, v)| (k.as_str(), *v))
    }

    /// Clear all detected patterns.
    pub fn clear(&mut self) {
        self.patterns.clear();
        self.method_counts.clear();
    }

    /// Return a summary of pattern counts by kind.
    #[must_use]
    pub fn count_by_kind(&self) -> HashMap<&str, usize> {
        let mut map: HashMap<&str, usize> = HashMap::new();
        for p in &self.patterns {
            *map.entry(p.kind_name()).or_insert(0) += 1;
        }
        map
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(start: u32, end: u32) -> PatternLocation {
        PatternLocation::new(start, end)
    }

    // ── PatternConfidence ─────────────────────────────────────────────────────

    #[test]
    fn confidence_ordering() {
        assert!(PatternConfidence::High > PatternConfidence::Medium);
        assert!(PatternConfidence::Medium > PatternConfidence::Low);
    }

    #[test]
    fn confidence_display() {
        assert_eq!(PatternConfidence::High.to_string(), "high");
        assert_eq!(PatternConfidence::Low.to_string(), "low");
    }

    // ── PatternLocation ───────────────────────────────────────────────────────

    #[test]
    fn location_span() {
        let l = loc(10, 30);
        assert_eq!(l.span(), 20);
    }

    #[test]
    fn location_with_context() {
        let l = loc(0, 10).with_context("MyType", "MyMethod");
        assert_eq!(l.containing_type.as_deref(), Some("MyType"));
        assert_eq!(l.containing_method.as_deref(), Some("MyMethod"));
    }

    // ── AsyncAwaitPattern ─────────────────────────────────────────────────────

    #[test]
    fn async_pattern_describe() {
        let mut a = AsyncAwaitPattern::new("Program+<DoWorkAsync>d__0", loc(0, 100));
        a.state_count = 3;
        let desc = a.describe();
        assert!(desc.contains('3'));
        assert!(desc.contains("high"));
    }

    #[test]
    fn async_pattern_defaults() {
        let a = AsyncAwaitPattern::new("SM", loc(0, 50));
        assert_eq!(a.state_field, "<>1__state");
        assert_eq!(a.move_next_method, "MoveNext");
        assert!(!a.is_generic);
    }

    #[test]
    fn async_pattern_awaited_expressions() {
        let mut a = AsyncAwaitPattern::new("SM", loc(0, 100));
        a.awaited_expressions.push("httpClient.GetAsync(url)".into());
        a.awaited_expressions.push("File.ReadAllTextAsync(path)".into());
        assert_eq!(a.awaited_expressions.len(), 2);
    }

    // ── LinqPattern ───────────────────────────────────────────────────────────

    #[test]
    fn linq_format_chain() {
        let mut l = LinqPattern::new("items", loc(0, 50));
        l.operators.push(LinqOperator::Where);
        l.operators.push(LinqOperator::Select);
        l.operators.push(LinqOperator::ToList);
        let chain = l.format_chain();
        assert_eq!(chain, "items.Where.Select.ToList");
    }

    #[test]
    fn linq_is_terminal_tolist() {
        let mut l = LinqPattern::new("items", loc(0, 50));
        l.operators.push(LinqOperator::ToList);
        assert!(l.is_terminal());
    }

    #[test]
    fn linq_is_terminal_orderby() {
        let mut l = LinqPattern::new("items", loc(0, 50));
        l.operators.push(LinqOperator::OrderBy);
        assert!(!l.is_terminal());
    }

    #[test]
    fn linq_operator_display() {
        assert_eq!(LinqOperator::Where.to_string(), "Where");
        assert_eq!(LinqOperator::ToDictionary.to_string(), "ToDictionary");
    }

    #[test]
    fn linq_is_query_syntax() {
        let mut l = LinqPattern::new("source", loc(0, 100));
        l.is_query_syntax = true;
        assert!(l.is_query_syntax);
    }

    // ── DelegatePattern ───────────────────────────────────────────────────────

    #[test]
    fn delegate_is_closure_empty() {
        let d = DelegatePattern::new("Func<int, bool>", loc(0, 20));
        assert!(!d.is_closure());
    }

    #[test]
    fn delegate_is_closure_with_captures() {
        let mut d = DelegatePattern::new("Func<string>", loc(0, 20));
        d.captured_variables.push(("x".into(), "int".into()));
        assert!(d.is_closure());
    }

    #[test]
    fn delegate_multicast() {
        let mut d = DelegatePattern::new("Action", loc(0, 10));
        d.is_multicast = true;
        assert!(d.is_multicast);
    }

    // ── AnonymousClass ────────────────────────────────────────────────────────

    #[test]
    fn anonymous_class_format_empty() {
        let a = AnonymousClass::new("<>f__AnonymousType0", loc(0, 10));
        let s = a.format();
        assert_eq!(s, "new {  }");
    }

    #[test]
    fn anonymous_class_format_with_props() {
        let mut a = AnonymousClass::new("AnonType", loc(0, 20));
        a.properties.push(("Name".into(), "string".into()));
        a.properties.push(("Age".into(), "int".into()));
        let s = a.format();
        assert!(s.contains("Name: string"));
        assert!(s.contains("Age: int"));
    }

    // ── NullablePattern ───────────────────────────────────────────────────────

    #[test]
    fn nullable_value_type() {
        let n = NullablePattern::new(
            NullableKind::ValueType("int".into()),
            "int",
            loc(0, 10),
        );
        assert!(matches!(n.kind, NullableKind::ValueType(_)));
    }

    #[test]
    fn nullable_null_check() {
        let n = NullablePattern::new(NullableKind::NullCheck, "string", loc(0, 5));
        assert!(matches!(n.kind, NullableKind::NullCheck));
    }

    // ── SwitchExpression ──────────────────────────────────────────────────────

    #[test]
    fn switch_add_arm() {
        let mut sw = SwitchExpression::new("shape", "Shape", loc(0, 100));
        sw.add_arm(SwitchArm {
            pattern: "Circle c".into(),
            guard: None,
            result_expr: "Math.PI * c.Radius * c.Radius".into(),
            offset: 0,
        });
        assert_eq!(sw.arms.len(), 1);
        assert!(!sw.has_discard);
    }

    #[test]
    fn switch_add_discard_arm() {
        let mut sw = SwitchExpression::new("x", "int", loc(0, 50));
        sw.add_arm(SwitchArm {
            pattern: "_".into(),
            guard: None,
            result_expr: "throw new InvalidOperationException()".into(),
            offset: 40,
        });
        assert!(sw.has_discard);
        assert!(sw.is_exhaustive());
    }

    #[test]
    fn switch_is_exhaustive_empty() {
        let sw = SwitchExpression::new("x", "int", loc(0, 10));
        assert!(!sw.is_exhaustive());
    }

    // ── PatternMatching ───────────────────────────────────────────────────────

    #[test]
    fn pattern_type_match() {
        let pm = PatternMatching::new(
            "obj",
            "object",
            MatchPatternKind::TypePattern("string".into()),
            loc(0, 10),
        );
        assert!(matches!(pm.pattern, MatchPatternKind::TypePattern(_)));
    }

    #[test]
    fn pattern_declaration() {
        let pm = PatternMatching::new(
            "obj",
            "object",
            MatchPatternKind::DeclarationPattern { type_name: "string".into(), variable: "s".into() },
            loc(0, 15),
        );
        if let MatchPatternKind::DeclarationPattern { variable, .. } = &pm.pattern {
            assert_eq!(variable, "s");
        } else {
            panic!("expected DeclarationPattern");
        }
    }

    #[test]
    fn pattern_negation() {
        let inner = MatchPatternKind::NullPattern;
        let negated = MatchPatternKind::NegationPattern(Box::new(inner));
        let pm = PatternMatching::new("x", "string", negated, loc(0, 10));
        assert!(matches!(pm.pattern, MatchPatternKind::NegationPattern(_)));
    }

    // ── CsharpPatterns (registry) ─────────────────────────────────────────────

    #[test]
    fn registry_add_and_count() {
        let mut r = CsharpPatterns::new();
        r.add(CsharpPattern::AsyncAwait(AsyncAwaitPattern::new("SM", loc(0, 100))));
        r.add(CsharpPattern::Linq(LinqPattern::new("items", loc(200, 250))));
        assert_eq!(r.total_count(), 2);
    }

    #[test]
    fn registry_of_kind() {
        let mut r = CsharpPatterns::new();
        r.add(CsharpPattern::AsyncAwait(AsyncAwaitPattern::new("SM1", loc(0, 100))));
        r.add(CsharpPattern::AsyncAwait(AsyncAwaitPattern::new("SM2", loc(100, 200))));
        r.add(CsharpPattern::Linq(LinqPattern::new("x", loc(200, 210))));
        assert_eq!(r.of_kind("AsyncAwait").len(), 2);
        assert_eq!(r.of_kind("Linq").len(), 1);
        assert_eq!(r.of_kind("Delegate").len(), 0);
    }

    #[test]
    fn registry_with_min_confidence() {
        let mut r = CsharpPatterns::new();
        let mut low = LinqPattern::new("x", loc(0, 10));
        low.confidence = PatternConfidence::Low;
        r.add(CsharpPattern::Linq(low));
        let high = AsyncAwaitPattern::new("SM", loc(10, 100));
        r.add(CsharpPattern::AsyncAwait(high));
        let high_only = r.with_min_confidence(PatternConfidence::High);
        assert_eq!(high_only.len(), 1);
    }

    #[test]
    fn registry_async_patterns() {
        let mut r = CsharpPatterns::new();
        r.add(CsharpPattern::AsyncAwait(AsyncAwaitPattern::new("SM", loc(0, 100))));
        assert_eq!(r.async_patterns().len(), 1);
    }

    #[test]
    fn registry_linq_patterns() {
        let mut r = CsharpPatterns::new();
        r.add(CsharpPattern::Linq(LinqPattern::new("src", loc(0, 50))));
        assert_eq!(r.linq_patterns().len(), 1);
    }

    #[test]
    fn registry_delegate_patterns() {
        let mut r = CsharpPatterns::new();
        r.add(CsharpPattern::Delegate(DelegatePattern::new("Action", loc(0, 10))));
        assert_eq!(r.delegate_patterns().len(), 1);
    }

    #[test]
    fn registry_anonymous_classes() {
        let mut r = CsharpPatterns::new();
        r.add(CsharpPattern::Anonymous(AnonymousClass::new("AnonType0", loc(0, 10))));
        assert_eq!(r.anonymous_classes().len(), 1);
    }

    #[test]
    fn registry_switch_expressions() {
        let mut r = CsharpPatterns::new();
        r.add(CsharpPattern::Switch(SwitchExpression::new("x", "int", loc(0, 100))));
        assert_eq!(r.switch_expressions().len(), 1);
    }

    #[test]
    fn registry_pattern_matches() {
        let mut r = CsharpPatterns::new();
        r.add(CsharpPattern::PatternMatch(PatternMatching::new(
            "obj", "object", MatchPatternKind::NullPattern, loc(0, 10),
        )));
        assert_eq!(r.pattern_matches().len(), 1);
    }

    #[test]
    fn registry_busiest_method() {
        let mut r = CsharpPatterns::new();
        let mut l1 = loc(0, 10);
        l1.containing_method = Some("MethodA".into());
        let mut l2 = loc(10, 20);
        l2.containing_method = Some("MethodA".into());
        let mut l3 = loc(20, 30);
        l3.containing_method = Some("MethodB".into());
        r.add(CsharpPattern::Linq(LinqPattern::new("x", l1)));
        r.add(CsharpPattern::Linq(LinqPattern::new("y", l2)));
        r.add(CsharpPattern::Linq(LinqPattern::new("z", l3)));
        let (method, count) = r.busiest_method().unwrap();
        assert_eq!(method, "MethodA");
        assert_eq!(count, 2);
    }

    #[test]
    fn registry_count_by_kind() {
        let mut r = CsharpPatterns::new();
        r.add(CsharpPattern::Linq(LinqPattern::new("a", loc(0, 10))));
        r.add(CsharpPattern::Linq(LinqPattern::new("b", loc(10, 20))));
        r.add(CsharpPattern::AsyncAwait(AsyncAwaitPattern::new("SM", loc(20, 100))));
        let counts = r.count_by_kind();
        assert_eq!(*counts.get("Linq").unwrap(), 2);
        assert_eq!(*counts.get("AsyncAwait").unwrap(), 1);
    }

    #[test]
    fn registry_clear() {
        let mut r = CsharpPatterns::new();
        r.add(CsharpPattern::Linq(LinqPattern::new("x", loc(0, 10))));
        r.clear();
        assert_eq!(r.total_count(), 0);
    }
}
