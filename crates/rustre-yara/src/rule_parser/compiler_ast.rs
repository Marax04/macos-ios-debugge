// compiler_ast.rs — compiler-facing parsed AST.
//
// `rule_compiler` consumes a normalized AST (`ParsedRule` et al.). The types
// below adapt the parser's `YaraRule` AST into that shape.

use std::collections::HashMap;

use super::{
    parse_rules, Condition, HexByte, StringSet, YaraMetaValue, YaraRule, YaraString,
    YaraStringKind,
};
use crate::YaraError;

/// Metadata literal as consumed by the compiler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaLiteral {
    String(String),
    Integer(i64),
    Boolean(bool),
}

/// Pattern modifiers in compiler-facing form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedModifiers {
    /// Encoding options: nocase, wide, ascii.
    pub encoding: crate::StringEncodingOpts,
    /// Output options: fullword, private, base64.
    pub output: crate::StringOutputOpts,
    /// XOR key range, if the `xor` modifier is present.
    pub xor: Option<(u8, u8)>,
    /// Whether the `base64wide` modifier is present.
    pub base64wide: bool,
}

impl Default for ParsedModifiers {
    fn default() -> Self {
        Self {
            encoding: crate::StringEncodingOpts { nocase: false, wide: false, ascii: false },
            output: crate::StringOutputOpts::default(),
            xor: None,
            base64wide: false,
        }
    }
}

/// One token of a hex pattern in compiler-facing form.
#[derive(Debug, Clone, PartialEq)]
pub enum HexToken {
    Byte(u8),
    Wildcard,
    Nibble { high: Option<u8>, low: Option<u8> },
    Jump { min: u32, max: Option<u32> },
    Alt(Vec<Vec<Self>>),
}

/// Pattern body kind in compiler-facing form.
#[derive(Debug, Clone, PartialEq)]
pub enum ParsedPatternKind {
    Text(String),
    Hex(Vec<HexToken>),
    Regex(String),
}

/// A single pattern (`$id = ...`) in compiler-facing form.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedPattern {
    pub id: String,
    pub kind: ParsedPatternKind,
    pub modifiers: ParsedModifiers,
}

/// Quantifier of an `of` / `for` expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Quantifier {
    All,
    Any,
    N(u64),
    Expr(Box<ConditionExpr>),
}

/// A set of patterns referenced by an `of` / `for` expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternSet {
    All,
    Named(Vec<String>),
    Wildcard(String),
}

/// Condition expression tree in compiler-facing form.
#[derive(Debug, Clone, PartialEq)]
pub enum ConditionExpr {
    True,
    False,
    Integer(i64),
    Float(f64),
    StringLit(String),
    Identifier(String),
    FileSize,
    EntryPoint,
    PatternMatch(String),
    PatternCount(String),
    Not(Box<Self>),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Eq(Box<Self>, Box<Self>),
    Ne(Box<Self>, Box<Self>),
    Lt(Box<Self>, Box<Self>),
    Le(Box<Self>, Box<Self>),
    Gt(Box<Self>, Box<Self>),
    Ge(Box<Self>, Box<Self>),
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    Div(Box<Self>, Box<Self>),
    Mod(Box<Self>, Box<Self>),
    Contains(Box<Self>, Box<Self>),
    IContains(Box<Self>, Box<Self>),
    StartsWith(Box<Self>, Box<Self>),
    EndsWith(Box<Self>, Box<Self>),
    Matches(Box<Self>, Box<Self>),
    Of { quantifier: Quantifier, set: PatternSet },
    For { quantifier: Quantifier, set: PatternSet, body: Box<Self> },
    At(String, Box<Self>),
    In(String, Box<Self>, Box<Self>),
}

/// A fully parsed rule in compiler-facing form.
#[derive(Debug, Clone)]
pub struct ParsedRule {
    pub name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, MetaLiteral>,
    pub patterns: Vec<ParsedPattern>,
    pub condition: ConditionExpr,
    pub source_text: String,
    pub is_global: bool,
    pub is_private: bool,
}

/// Parser facade that yields compiler-facing [`ParsedRule`]s.
#[derive(Debug, Default)]
pub struct RuleParser {
    /// Namespace assigned to parsed rules.
    pub namespace: String,
}

impl RuleParser {
    #[must_use]
    pub fn new() -> Self {
        Self { namespace: "default".to_string() }
    }

    /// Parse YARA source into compiler-facing rules.
    ///
    /// # Errors
    ///
    /// Returns a [`YaraError`] when the source fails to parse.
    pub fn parse(&mut self, src: &str) -> Result<Vec<ParsedRule>, YaraError> {
        let rules = parse_rules(src)?;
        Ok(rules
            .into_iter()
            .map(|r| convert_rule(r, &self.namespace))
            .collect())
    }
}

fn convert_rule(rule: YaraRule, namespace: &str) -> ParsedRule {
    let source_text = format!("{rule:?}");
    let metadata = rule
        .metadata
        .iter()
        .map(|(k, v)| (k.clone(), convert_meta(v)))
        .collect();
    let patterns = rule.strings.iter().map(convert_string).collect();
    let condition = convert_condition(&rule.condition);
    ParsedRule {
        name: rule.name,
        namespace: namespace.to_string(),
        tags: rule.tags,
        metadata,
        patterns,
        condition,
        source_text,
        is_global: rule.global,
        is_private: rule.private,
    }
}

fn convert_meta(v: &YaraMetaValue) -> MetaLiteral {
    match v {
        YaraMetaValue::Str(s) => MetaLiteral::String(s.clone()),
        YaraMetaValue::Int(i) => MetaLiteral::Integer(*i),
        YaraMetaValue::Bool(b) => MetaLiteral::Boolean(*b),
    }
}

fn convert_string(s: &YaraString) -> ParsedPattern {
    let kind = match &s.kind {
        YaraStringKind::Text(t) => ParsedPatternKind::Text(t.clone()),
        YaraStringKind::Hex(bytes) => {
            ParsedPatternKind::Hex(bytes.iter().map(convert_hex_byte).collect())
        }
        YaraStringKind::Regex(re, _flags) => ParsedPatternKind::Regex(re.clone()),
    };
    let m = &s.modifiers;
    ParsedPattern {
        id: s.identifier.clone(),
        kind,
        modifiers: ParsedModifiers {
            encoding: crate::StringEncodingOpts {
                nocase: m.encoding.nocase,
                wide: m.encoding.wide,
                ascii: m.encoding.ascii,
            },
            output: crate::StringOutputOpts {
                fullword: m.output.fullword,
                private: m.output.private,
                base64: m.output.base64,
            },
            xor: if m.xor { Some((0x00, 0xFF)) } else { None },
            base64wide: false,
        },
    }
}

const fn convert_hex_byte(b: &HexByte) -> HexToken {
    match *b {
        HexByte::Fixed(v) => HexToken::Byte(v),
        HexByte::Wildcard => HexToken::Wildcard,
        HexByte::NibbleHi(h) => HexToken::Nibble { high: Some(h), low: None },
        HexByte::NibbleLo(l) => HexToken::Nibble { high: None, low: Some(l) },
        HexByte::Jump(min, max) => HexToken::Jump { min, max: Some(max) },
    }
}

fn convert_set(s: &StringSet) -> PatternSet {
    match s {
        StringSet::Them => PatternSet::All,
        StringSet::List(names) => PatternSet::Named(names.clone()),
        StringSet::Wildcard(prefix) => PatternSet::Wildcard(prefix.clone()),
    }
}

/// Convert an `of`/`for` count expression to a quantifier.
/// The parser encodes `all` as `-1`, `none` as `0`, and `any` as `1`.
fn convert_quantifier(count: &Condition) -> Quantifier {
    match count {
        Condition::Int(-1) => Quantifier::All,
        Condition::Int(1) => Quantifier::Any,
        Condition::Int(n) if *n >= 0 => Quantifier::N(u64::try_from(*n).unwrap_or(0)),
        other => Quantifier::Expr(Box::new(convert_condition(other))),
    }
}

/// Extract the pattern identifier from a condition operand (e.g. the `$a`
/// in `$a at 0x100`). Falls back to `"$"` for non-reference operands.
fn pattern_id_of(c: &Condition) -> String {
    match c {
        Condition::StringRef(id) | Condition::StringWildcard(id) => id.clone(),
        _ => "$".to_string(),
    }
}

fn convert_condition(c: &Condition) -> ConditionExpr {
    let bx = |c: &Condition| Box::new(convert_condition(c));
    match c {
        Condition::Bool(true) => ConditionExpr::True,
        Condition::Bool(false) => ConditionExpr::False,
        Condition::Int(i) => ConditionExpr::Integer(*i),
        Condition::Str(s) => ConditionExpr::StringLit(s.clone()),
        Condition::StringRef(id) => ConditionExpr::PatternMatch(id.clone()),
        Condition::StringWildcard(prefix) => ConditionExpr::Of {
            quantifier: Quantifier::Any,
            set: PatternSet::Wildcard(prefix.clone()),
        },
        Condition::Filesize => ConditionExpr::FileSize,
        Condition::Entrypoint => ConditionExpr::EntryPoint,
        Condition::Not(e) => ConditionExpr::Not(bx(e)),
        Condition::And(a, b) => ConditionExpr::And(bx(a), bx(b)),
        Condition::Or(a, b) => ConditionExpr::Or(bx(a), bx(b)),
        Condition::Eq(a, b) => ConditionExpr::Eq(bx(a), bx(b)),
        Condition::Ne(a, b) => ConditionExpr::Ne(bx(a), bx(b)),
        Condition::Lt(a, b) => ConditionExpr::Lt(bx(a), bx(b)),
        Condition::Le(a, b) => ConditionExpr::Le(bx(a), bx(b)),
        Condition::Gt(a, b) => ConditionExpr::Gt(bx(a), bx(b)),
        Condition::Ge(a, b) => ConditionExpr::Ge(bx(a), bx(b)),
        Condition::Add(a, b) => ConditionExpr::Add(bx(a), bx(b)),
        Condition::Sub(a, b) => ConditionExpr::Sub(bx(a), bx(b)),
        Condition::Mul(a, b) => ConditionExpr::Mul(bx(a), bx(b)),
        Condition::Div(a, b) => ConditionExpr::Div(bx(a), bx(b)),
        Condition::Mod(a, b) => ConditionExpr::Mod(bx(a), bx(b)),
        Condition::Of { count, set } => ConditionExpr::Of {
            quantifier: convert_quantifier(count),
            set: convert_set(set),
        },
        Condition::At(pat, offset) => ConditionExpr::At(pattern_id_of(pat), bx(offset)),
        Condition::In(pat, from, to) => {
            ConditionExpr::In(pattern_id_of(pat), bx(from), bx(to))
        }
        Condition::Matches(e, re) => ConditionExpr::Matches(
            bx(e),
            Box::new(ConditionExpr::StringLit(re.clone())),
        ),
        Condition::For { count, set, body } => ConditionExpr::For {
            quantifier: convert_quantifier(count),
            set: convert_set(set),
            body: bx(body),
        },
        Condition::ModuleField(module, field) => {
            ConditionExpr::Identifier(format!("{module}.{field}"))
        }
        Condition::ModuleCall(module, func, _args) => {
            ConditionExpr::Identifier(format!("{module}.{func}"))
        }
        Condition::Defined(e) => convert_condition(e),
    }
}
