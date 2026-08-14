//! TTD Query Language — `FIND memory_write WHERE address=0x1234`.
//! Tokenizer, parser, semantics, and result types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueryLangError {
    #[error("unexpected token '{0}' at position {1}")]
    UnexpectedToken(String, usize),
    #[error("expected token '{0}', got '{1}'")]
    Expected(String, String),
    #[error("unknown field '{0}' for entity '{1}'")]
    UnknownField(String, String),
    #[error("invalid value for field '{0}': {1}")]
    InvalidValue(String, String),
    #[error("empty query")]
    EmptyQuery,
    #[error("unmatched parenthesis")]
    UnmatchedParen,
    #[error("division by zero in expression")]
    DivisionByZero,
}

// ─── QueryToken ───────────────────────────────────────────────────────────────

/// Lexical tokens for the TTD query language.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueryToken {
    /// `FIND`, `WHERE`, `AND`, `OR`, `NOT`, `LIMIT`, `ORDER`, `BY`, `ASC`, `DESC`
    Keyword(String),
    /// Entity names: `memory_write`, `memory_read`, `call`, `thread`, `module`
    Identifier(String),
    /// Integer literal (decimal or 0x hex).
    Integer(u64),
    /// String literal in double quotes.
    StringLit(String),
    /// Operators: `=`, `!=`, `<`, `>`, `<=`, `>=`, `~=` (regex)
    Operator(String),
    /// Comma.
    Comma,
    /// `(` or `)`.
    Paren(char),
    /// End of input.
    Eof,
}

impl QueryToken {
    #[must_use]
    pub fn is_keyword(&self, kw: &str) -> bool {
        matches!(self, Self::Keyword(k) if k.eq_ignore_ascii_case(kw))
    }
}

// ─── Lexer ────────────────────────────────────────────────────────────────────

/// Tokenizes a TTD query string.
pub struct QueryLexer<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> QueryLexer<'a> {
    #[must_use]
    pub const fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.as_bytes().get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    /// Tokenize the full input.
    pub fn tokenize(&mut self) -> Result<Vec<(QueryToken, usize)>, QueryLangError> {
        let mut tokens = Vec::new();
        loop {
            self.skip_ws();
            let start = self.pos;
            match self.peek() {
                None => {
                    tokens.push((QueryToken::Eof, start));
                    break;
                }
                Some(b',') => {
                    self.advance();
                    tokens.push((QueryToken::Comma, start));
                }
                Some(b'(' | b')') => {
                    let c = self.advance().unwrap() as char;
                    tokens.push((QueryToken::Paren(c), start));
                }
                Some(b'"') => {
                    self.advance();
                    let s = self.read_string()?;
                    tokens.push((QueryToken::StringLit(s), start));
                }
                Some(b'0'..=b'9') => {
                    let n = self.read_number()?;
                    tokens.push((QueryToken::Integer(n), start));
                }
                Some(b'=' | b'!' | b'<' | b'>' | b'~') => {
                    let op = self.read_operator();
                    tokens.push((QueryToken::Operator(op), start));
                }
                Some(b'a'..=b'z' | b'A'..=b'Z' | b'_') => {
                    let ident = self.read_ident();
                    let tok = if Self::is_keyword(&ident) {
                        QueryToken::Keyword(ident.to_uppercase())
                    } else {
                        QueryToken::Identifier(ident)
                    };
                    tokens.push((tok, start));
                }
                Some(c) => {
                    return Err(QueryLangError::UnexpectedToken(
                        (c as char).to_string(),
                        start,
                    ));
                }
            }
        }
        Ok(tokens)
    }

    fn read_string(&mut self) -> Result<String, QueryLangError> {
        let mut s = String::new();
        loop {
            match self.advance() {
                None => return Err(QueryLangError::UnmatchedParen),
                Some(b'"') => return Ok(s),
                Some(b) => s.push(b as char),
            }
        }
    }

    fn read_number(&mut self) -> Result<u64, QueryLangError> {
        // Check for 0x prefix.
        if self.peek() == Some(b'0') {
            let saved = self.pos;
            self.advance(); // consume '0'
            if self.peek() == Some(b'x') || self.peek() == Some(b'X') {
                self.advance(); // consume 'x'
                let hex: String = std::iter::from_fn(|| {
                    self.peek().filter(u8::is_ascii_hexdigit).map(|b| {
                        self.advance();
                        b as char
                    })
                })
                .collect();
                return u64::from_str_radix(&hex, 16)
                    .map_err(|e| QueryLangError::InvalidValue("hex".into(), e.to_string()));
            }
            // Not 0x — backtrack and parse as decimal.
            self.pos = saved;
        }
        let digits: String = std::iter::from_fn(|| {
            self.peek().filter(u8::is_ascii_digit).map(|b| {
                self.advance();
                b as char
            })
        })
        .collect();
        digits
            .parse::<u64>()
            .map_err(|e| QueryLangError::InvalidValue("integer".into(), e.to_string()))
    }

    fn read_ident(&mut self) -> String {
        std::iter::from_fn(|| {
            self.peek()
                .filter(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .map(|b| {
                    self.advance();
                    b as char
                })
        })
        .collect()
    }

    fn read_operator(&mut self) -> String {
        let first = self.advance().unwrap() as char;
        if self.peek() == Some(b'=') {
            self.advance();
            return format!("{first}=");
        }
        first.to_string()
    }

    fn is_keyword(s: &str) -> bool {
        matches!(
            s.to_uppercase().as_str(),
            "FIND"
                | "WHERE"
                | "AND"
                | "OR"
                | "NOT"
                | "LIMIT"
                | "ORDER"
                | "BY"
                | "ASC"
                | "DESC"
                | "BETWEEN"
                | "IN"
                | "LIKE"
        )
    }
}

// ─── AST Types ────────────────────────────────────────────────────────────────

/// Comparison operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompOp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    Regex,
}

impl CompOp {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "=" => Some(Self::Eq),
            "!=" => Some(Self::Ne),
            "<" => Some(Self::Lt),
            ">" => Some(Self::Gt),
            "<=" => Some(Self::Le),
            ">=" => Some(Self::Ge),
            "~=" => Some(Self::Regex),
            _ => None,
        }
    }
}

/// A value in a WHERE clause.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueryValue {
    Integer(u64),
    Str(String),
}

impl QueryValue {
    #[must_use]
    pub const fn as_u64(&self) -> Option<u64> {
        if let Self::Integer(n) = self {
            Some(*n)
        } else {
            None
        }
    }
}

/// A single WHERE predicate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Predicate {
    pub field: String,
    pub op: CompOp,
    pub value: QueryValue,
}

/// Logical combination of predicates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WhereClause {
    Single(Predicate),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Not(Box<Self>),
}

/// Sort order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortOrder {
    Asc,
    Desc,
}

/// A fully parsed TTD query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtdQuery {
    pub entity: String,
    pub clause: Option<WhereClause>,
    pub limit: Option<u64>,
    pub order_by: Option<(String, SortOrder)>,
}

// ─── QueryParser ─────────────────────────────────────────────────────────────

/// Recursive-descent parser for TTD queries.
pub struct QueryParser {
    tokens: Vec<(QueryToken, usize)>,
    pos: usize,
}

impl QueryParser {
    /// Create from pre-tokenized input.
    #[must_use]
    pub const fn new(tokens: Vec<(QueryToken, usize)>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> &QueryToken {
        self.tokens
            .get(self.pos)
            .map_or(&QueryToken::Eof, |(t, _)| t)
    }

    fn peek_pos(&self) -> usize {
        self.tokens.get(self.pos).map_or(0, |(_, p)| *p)
    }

    fn advance(&mut self) -> &QueryToken {
        let t = self
            .tokens
            .get(self.pos)
            .map_or(&QueryToken::Eof, |(t, _)| t);
        self.pos += 1;
        t
    }

    fn expect_keyword(&mut self, kw: &str) -> Result<(), QueryLangError> {
        if self.peek().is_keyword(kw) {
            self.advance();
            Ok(())
        } else {
            Err(QueryLangError::Expected(
                kw.to_string(),
                format!("{:?}", self.peek()),
            ))
        }
    }

    fn parse_ident(&mut self) -> Result<String, QueryLangError> {
        match self.advance().clone() {
            QueryToken::Identifier(s) => Ok(s),
            other => Err(QueryLangError::UnexpectedToken(
                format!("{other:?}"),
                self.peek_pos(),
            )),
        }
    }

    fn parse_value(&mut self) -> Result<QueryValue, QueryLangError> {
        match self.advance().clone() {
            QueryToken::Integer(n) => Ok(QueryValue::Integer(n)),
            QueryToken::StringLit(s) => Ok(QueryValue::Str(s)),
            other => Err(QueryLangError::UnexpectedToken(
                format!("{other:?}"),
                self.peek_pos(),
            )),
        }
    }

    fn parse_predicate(&mut self) -> Result<Predicate, QueryLangError> {
        let field = self.parse_ident()?;
        let op_str = match self.advance().clone() {
            QueryToken::Operator(s) => s,
            other => {
                return Err(QueryLangError::UnexpectedToken(
                    format!("{other:?}"),
                    self.peek_pos(),
                ));
            }
        };
        let op = CompOp::from_str(&op_str)
            .ok_or_else(|| QueryLangError::UnexpectedToken(op_str, self.peek_pos()))?;
        let value = self.parse_value()?;
        Ok(Predicate { field, op, value })
    }

    fn parse_where_clause(&mut self) -> Result<WhereClause, QueryLangError> {
        let mut left = if self.peek().is_keyword("NOT") {
            self.advance();
            WhereClause::Not(Box::new(self.parse_where_clause()?))
        } else {
            WhereClause::Single(self.parse_predicate()?)
        };
        loop {
            if self.peek().is_keyword("AND") {
                self.advance();
                let right = if self.peek().is_keyword("NOT") {
                    self.advance();
                    WhereClause::Not(Box::new(self.parse_where_clause()?))
                } else {
                    WhereClause::Single(self.parse_predicate()?)
                };
                left = WhereClause::And(Box::new(left), Box::new(right));
            } else if self.peek().is_keyword("OR") {
                self.advance();
                let right = WhereClause::Single(self.parse_predicate()?);
                left = WhereClause::Or(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    /// Parse a full query.
    pub fn parse(&mut self) -> Result<TtdQuery, QueryLangError> {
        if matches!(self.peek(), QueryToken::Eof) {
            return Err(QueryLangError::EmptyQuery);
        }
        self.expect_keyword("FIND")?;
        let entity = self.parse_ident()?;

        let clause = if self.peek().is_keyword("WHERE") {
            self.advance();
            Some(self.parse_where_clause()?)
        } else {
            None
        };

        let order_by = if self.peek().is_keyword("ORDER") {
            self.advance();
            self.expect_keyword("BY")?;
            let field = self.parse_ident()?;
            let dir = if self.peek().is_keyword("DESC") {
                self.advance();
                SortOrder::Desc
            } else {
                if self.peek().is_keyword("ASC") {
                    self.advance();
                }
                SortOrder::Asc
            };
            Some((field, dir))
        } else {
            None
        };

        let limit = if self.peek().is_keyword("LIMIT") {
            self.advance();
            match self.advance().clone() {
                QueryToken::Integer(n) => Some(n),
                other => {
                    return Err(QueryLangError::UnexpectedToken(
                        format!("{other:?}"),
                        self.peek_pos(),
                    ));
                }
            }
        } else {
            None
        };

        Ok(TtdQuery {
            entity,
            clause,
            limit,
            order_by,
        })
    }
}

// ─── QuerySemantics ───────────────────────────────────────────────────────────

/// Known fields per entity.
fn entity_fields(entity: &str) -> Option<&'static [&'static str]> {
    match entity {
        "memory_write" => Some(&["address", "size", "value", "pid", "tid", "time"]),
        "memory_read" => Some(&["address", "size", "value", "pid", "tid", "time"]),
        "call" => Some(&["address", "callee", "pid", "tid", "time", "depth"]),
        "thread" => Some(&["tid", "pid", "state", "time"]),
        "module" => Some(&["name", "base", "size", "time"]),
        "exception" => Some(&["code", "address", "pid", "tid", "time"]),
        _ => None,
    }
}

/// Validates semantics of a parsed query.
pub struct QuerySemantics;

impl QuerySemantics {
    /// Validate entity and fields.
    pub fn validate(query: &TtdQuery) -> Result<(), QueryLangError> {
        let fields = entity_fields(&query.entity)
            .ok_or_else(|| QueryLangError::UnknownField(query.entity.clone(), "<root>".into()))?;

        if let Some(clause) = &query.clause {
            Self::validate_clause(clause, &query.entity, fields)?;
        }
        if let Some((field, _)) = &query.order_by
            && !fields.contains(&field.as_str())
        {
            return Err(QueryLangError::UnknownField(
                field.clone(),
                query.entity.clone(),
            ));
        }
        Ok(())
    }

    fn validate_clause(
        clause: &WhereClause,
        entity: &str,
        fields: &[&str],
    ) -> Result<(), QueryLangError> {
        match clause {
            WhereClause::Single(p) => {
                if !fields.contains(&p.field.as_str()) {
                    return Err(QueryLangError::UnknownField(
                        p.field.clone(),
                        entity.to_string(),
                    ));
                }
                Ok(())
            }
            WhereClause::And(a, b) | WhereClause::Or(a, b) => {
                Self::validate_clause(a, entity, fields)?;
                Self::validate_clause(b, entity, fields)
            }
            WhereClause::Not(inner) => Self::validate_clause(inner, entity, fields),
        }
    }
}

// ─── QueryResult ──────────────────────────────────────────────────────────────

/// A single row in a query result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResultRow {
    pub fields: HashMap<String, QueryValue>,
}

impl QueryResultRow {
    #[must_use]
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
        }
    }

    pub fn set(&mut self, field: impl Into<String>, value: QueryValue) {
        self.fields.insert(field.into(), value);
    }

    #[must_use]
    pub fn get_int(&self, field: &str) -> Option<u64> {
        self.fields.get(field).and_then(QueryValue::as_u64)
    }
}

impl Default for QueryResultRow {
    fn default() -> Self {
        Self::new()
    }
}

/// Full result set from a query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueryResult {
    pub rows: Vec<QueryResultRow>,
    pub total_scanned: u64,
    pub entity: String,
}

impl QueryResult {
    #[must_use]
    pub const fn row_count(&self) -> usize {
        self.rows.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

// ─── TtdQueryLanguage ────────────────────────────────────────────────────────

/// High-level entry point: parse and validate a query string.
pub struct TtdQueryLanguage;

impl TtdQueryLanguage {
    /// Parse a query string into a `TtdQuery`.
    pub fn parse(input: &str) -> Result<TtdQuery, QueryLangError> {
        let mut lexer = QueryLexer::new(input);
        let tokens = lexer.tokenize()?;
        let mut parser = QueryParser::new(tokens);
        parser.parse()
    }

    /// Parse and validate.
    pub fn parse_and_validate(input: &str) -> Result<TtdQuery, QueryLangError> {
        let q = Self::parse(input)?;
        QuerySemantics::validate(&q)?;
        Ok(q)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Lexer ────────────────────────────────────────────────────────────────

    #[test]
    fn test_lex_basic() {
        let mut l = QueryLexer::new("FIND memory_write WHERE address=0x1234");
        let toks = l.tokenize().unwrap();
        assert!(matches!(&toks[0].0, QueryToken::Keyword(k) if k == "FIND"));
        assert!(matches!(&toks[1].0, QueryToken::Identifier(s) if s == "memory_write"));
    }

    #[test]
    fn test_lex_hex_literal() {
        let mut l = QueryLexer::new("0x1234");
        let toks = l.tokenize().unwrap();
        assert_eq!(toks[0].0, QueryToken::Integer(0x1234));
    }

    #[test]
    fn test_lex_decimal() {
        let mut l = QueryLexer::new("42");
        let toks = l.tokenize().unwrap();
        assert_eq!(toks[0].0, QueryToken::Integer(42));
    }

    #[test]
    fn test_lex_string_literal() {
        let mut l = QueryLexer::new(r#""hello""#);
        let toks = l.tokenize().unwrap();
        assert_eq!(toks[0].0, QueryToken::StringLit("hello".into()));
    }

    #[test]
    fn test_lex_operators() {
        let ops = ["=", "!=", "<", ">", "<=", ">=", "~="];
        for op in ops {
            let mut l = QueryLexer::new(op);
            let toks = l.tokenize().unwrap();
            assert!(matches!(&toks[0].0, QueryToken::Operator(s) if s == op));
        }
    }

    #[test]
    fn test_lex_keywords_case_insensitive() {
        let mut l = QueryLexer::new("find memory_write where");
        let toks = l.tokenize().unwrap();
        assert!(matches!(&toks[0].0, QueryToken::Keyword(k) if k == "FIND"));
        assert!(matches!(&toks[2].0, QueryToken::Keyword(k) if k == "WHERE"));
    }

    // ── Parser ───────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_simple_find() {
        let q = TtdQueryLanguage::parse("FIND memory_write").unwrap();
        assert_eq!(q.entity, "memory_write");
        assert!(q.clause.is_none());
    }

    #[test]
    fn test_parse_with_where() {
        let q = TtdQueryLanguage::parse("FIND memory_write WHERE address=0x1000").unwrap();
        assert!(q.clause.is_some());
    }

    #[test]
    fn test_parse_and_clause() {
        let q =
            TtdQueryLanguage::parse("FIND memory_write WHERE address=0x1000 AND size=4").unwrap();
        assert!(matches!(q.clause, Some(WhereClause::And(_, _))));
    }

    #[test]
    fn test_parse_or_clause() {
        let q =
            TtdQueryLanguage::parse("FIND call WHERE address=0x1000 OR address=0x2000").unwrap();
        assert!(matches!(q.clause, Some(WhereClause::Or(_, _))));
    }

    #[test]
    fn test_parse_with_limit() {
        let q = TtdQueryLanguage::parse("FIND thread LIMIT 100").unwrap();
        assert_eq!(q.limit, Some(100));
    }

    #[test]
    fn test_parse_with_order_asc() {
        let q = TtdQueryLanguage::parse("FIND thread ORDER BY tid ASC").unwrap();
        assert_eq!(q.order_by, Some(("tid".into(), SortOrder::Asc)));
    }

    #[test]
    fn test_parse_with_order_desc() {
        let q = TtdQueryLanguage::parse("FIND exception ORDER BY time DESC").unwrap();
        assert_eq!(q.order_by, Some(("time".into(), SortOrder::Desc)));
    }

    #[test]
    fn test_parse_empty_error() {
        assert!(TtdQueryLanguage::parse("").is_err());
    }

    #[test]
    fn test_parse_missing_find_error() {
        assert!(TtdQueryLanguage::parse("memory_write WHERE address=0x1").is_err());
    }

    #[test]
    fn test_parse_not_clause() {
        let q = TtdQueryLanguage::parse("FIND memory_write WHERE NOT address=0x0").unwrap();
        assert!(matches!(q.clause, Some(WhereClause::Not(_))));
    }

    // ── Semantics ─────────────────────────────────────────────────────────────

    #[test]
    fn test_semantics_valid_query() {
        let r = TtdQueryLanguage::parse_and_validate(
            "FIND memory_write WHERE address=0x1234 AND size=4 LIMIT 10",
        );
        assert!(r.is_ok());
    }

    #[test]
    fn test_semantics_unknown_entity() {
        let q = TtdQuery {
            entity: "unknown_entity".into(),
            clause: None,
            limit: None,
            order_by: None,
        };
        assert!(QuerySemantics::validate(&q).is_err());
    }

    #[test]
    fn test_semantics_unknown_field() {
        let r = TtdQueryLanguage::parse_and_validate("FIND memory_write WHERE nonexistent_field=1");
        assert!(r.is_err());
    }

    #[test]
    fn test_semantics_order_by_valid_field() {
        let r = TtdQueryLanguage::parse_and_validate("FIND call ORDER BY time ASC");
        assert!(r.is_ok());
    }

    #[test]
    fn test_semantics_order_by_invalid_field() {
        let r = TtdQueryLanguage::parse_and_validate("FIND call ORDER BY bogus_field ASC");
        assert!(r.is_err());
    }

    // ── QueryResult ──────────────────────────────────────────────────────────

    #[test]
    fn test_result_row_set_get() {
        let mut row = QueryResultRow::new();
        row.set("address", QueryValue::Integer(0x1234));
        assert_eq!(row.get_int("address"), Some(0x1234));
    }

    #[test]
    fn test_result_empty() {
        let r = QueryResult::default();
        assert!(r.is_empty());
        assert_eq!(r.row_count(), 0);
    }

    #[test]
    fn test_result_with_rows() {
        let mut r = QueryResult::default();
        r.rows.push(QueryResultRow::new());
        r.rows.push(QueryResultRow::new());
        assert_eq!(r.row_count(), 2);
    }

    // ── CompOp ────────────────────────────────────────────────────────────────

    #[test]
    fn test_compop_from_str() {
        assert_eq!(CompOp::from_str("="), Some(CompOp::Eq));
        assert_eq!(CompOp::from_str("!="), Some(CompOp::Ne));
        assert_eq!(CompOp::from_str("~="), Some(CompOp::Regex));
        assert_eq!(CompOp::from_str("??"), None);
    }

    // ── Additional coverage ─────────────────────────────────────────────────

    #[test]
    fn test_parse_memory_read_entity() {
        let q = TtdQueryLanguage::parse("FIND memory_read WHERE address=0x5000").unwrap();
        assert_eq!(q.entity, "memory_read");
    }

    #[test]
    fn test_parse_module_entity() {
        let q = TtdQueryLanguage::parse("FIND module").unwrap();
        assert_eq!(q.entity, "module");
    }

    #[test]
    fn test_parse_call_entity_with_pid() {
        let r = TtdQueryLanguage::parse_and_validate("FIND call WHERE pid=4").unwrap();
        assert_eq!(r.entity, "call");
    }

    #[test]
    fn test_parse_limit_large() {
        let q = TtdQueryLanguage::parse("FIND thread LIMIT 10000").unwrap();
        assert_eq!(q.limit, Some(10000));
    }

    #[test]
    fn test_result_row_missing_field_is_none() {
        let row = QueryResultRow::new();
        assert_eq!(row.get_int("nonexistent"), None);
    }

    #[test]
    fn test_query_value_str_as_u64_none() {
        let v = QueryValue::Str("hello".into());
        assert_eq!(v.as_u64(), None);
    }
}
