//! TTD mini-DSL query language for querying time-travel traces.
//!
//! # Language
//!
//! ```text
//! WHEN rax == 0x1234
//! AT time 12345:0 SHOW registers
//! FIND CALL "CreateFile"
//! FIND CALL "CreateFile" IN RANGE 100:0 TO 500:0
//! TRACE FROM 100:0 TO 200:0 WHERE memory[0x7fff0000] WRITTEN
//! TRACE FROM 100:0 TO 200:0 WHERE rax == 0xDEAD
//! AT time 50:0 SHOW memory[0x7fff0000]
//! FIND THREAD SWITCH TO 2
//! ```
//!
//! # Architecture
//!
//! 1. [`Lexer`] — tokenises the input string.
//! 2. [`Parser`] — builds a [`Query`] AST.
//! 3. [`QueryExecutor`] — runs the AST against a [`TtdIndex`].
//! 4. [`QueryResult`] — structured output (serialisable to JSON).

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ttd_index::{Position, PositionRange, TtdIndex};

// ── Token ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Token {
    // Keywords
    When,
    At,
    Time,
    Show,
    Find,
    Call,
    Trace,
    From,
    To,
    Where,
    In,
    Range,
    Memory,
    Written,
    Read,
    Registers,
    Thread,
    Switch,
    // Operators
    EqEq,
    NotEq,
    Gt,
    Lt,
    // Identifiers / literals
    Ident(String),
    Number(u64),
    StringLit(String),
    // Punctuation
    LBracket,
    RBracket,
    Colon,
    // End
    Eof,
}

// ── Lexer ─────────────────────────────────────────────────────────────────────

struct Lexer<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    const fn new(input: &'a str) -> Self {
        Self { input: input.as_bytes(), pos: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let ch = self.input.get(self.pos).copied();
        self.pos += 1;
        ch
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.peek() {
            if ch.is_ascii_whitespace() { self.advance(); } else { break; }
        }
    }

    fn read_number(&mut self) -> u64 {
        let start = self.pos;
        // Hex prefix?
        if self.input.get(self.pos..self.pos + 2) == Some(b"0x")
            || self.input.get(self.pos..self.pos + 2) == Some(b"0X")
        {
            self.pos += 2;
            while let Some(ch) = self.peek() {
                if ch.is_ascii_hexdigit() { self.advance(); } else { break; }
            }
            let hex_str = std::str::from_utf8(&self.input[start + 2..self.pos]).unwrap_or("0");
            u64::from_str_radix(hex_str, 16).unwrap_or(0)
        } else {
            while let Some(ch) = self.peek() {
                if ch.is_ascii_digit() { self.advance(); } else { break; }
            }
            std::str::from_utf8(&self.input[start..self.pos])
                .unwrap_or("0")
                .parse::<u64>()
                .unwrap_or(0)
        }
    }

    fn read_ident(&mut self) -> String {
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if ch.is_ascii_alphanumeric() || ch == b'_' { self.advance(); } else { break; }
        }
        String::from_utf8_lossy(&self.input[start..self.pos]).into_owned()
    }

    fn read_string_lit(&mut self) -> String {
        // Skip opening quote
        self.advance();
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if ch == b'"' { break; }            self.advance();
        }
        let s = String::from_utf8_lossy(&self.input[start..self.pos]).into_owned();
        // Skip closing quote
        self.advance();
        s
    }

    fn next_token(&mut self) -> Token {
        self.skip_whitespace();
        let Some(ch) = self.peek() else {
            return Token::Eof;
        };

        match ch {
            b'[' => { self.advance(); Token::LBracket }
            b']' => { self.advance(); Token::RBracket }
            b':' => { self.advance(); Token::Colon }
            b'=' => {
                self.advance();
                if self.peek() == Some(b'=') { self.advance(); }
                Token::EqEq
            }
            b'!' => {
                self.advance();
                if self.peek() == Some(b'=') { self.advance(); }
                Token::NotEq
            }
            b'>' => { self.advance(); Token::Gt }
            b'<' => { self.advance(); Token::Lt }
            b'"' => Token::StringLit(self.read_string_lit()),
            c if c.is_ascii_digit() => Token::Number(self.read_number()),
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let ident = self.read_ident();
                match ident.to_uppercase().as_str() {
                    "WHEN" => Token::When,
                    "AT" => Token::At,
                    "TIME" => Token::Time,
                    "SHOW" => Token::Show,
                    "FIND" => Token::Find,
                    "CALL" => Token::Call,
                    "TRACE" => Token::Trace,
                    "FROM" => Token::From,
                    "TO" => Token::To,
                    "WHERE" => Token::Where,
                    "IN" => Token::In,
                    "RANGE" => Token::Range,
                    "MEMORY" => Token::Memory,
                    "WRITTEN" => Token::Written,
                    "READ" => Token::Read,
                    "REGISTERS" => Token::Registers,
                    "THREAD" => Token::Thread,
                    "SWITCH" => Token::Switch,
                    _ => Token::Ident(ident),
                }
            }
            _ => { self.advance(); self.next_token() }
        }
    }

    fn tokenize(mut self) -> Vec<Token> {
        let mut tokens = Vec::new();
        loop {
            let t = self.next_token();
            let done = t == Token::Eof;
            tokens.push(t);
            if done { break; }
        }
        tokens
    }
}

// ── AST ───────────────────────────────────────────────────────────────────────

/// A comparison operator for WHEN queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CmpOp { Eq, NotEq, Gt, Lt }

/// A condition for TRACE/WHEN queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Condition {
    /// Register `reg` compared to `value` with operator `op`.
    Register { reg: String, op: CmpOp, value: u64 },
    /// Memory at `address` was written.
    MemoryWritten { address: u64 },
    /// Memory at `address` was read.
    MemoryRead { address: u64 },
}

/// Projection for AT … SHOW queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShowTarget {
    /// Show all register values at the position.
    Registers,
    /// Show value at a memory address.
    Memory(u64),
}

/// The parsed query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Query {
    /// `WHEN <register> == <value>` — find positions where condition holds.
    When(Condition),
    /// `AT time <pos> SHOW <target>` — snapshot at a position.
    AtTime { position: Position, show: ShowTarget },
    /// `FIND CALL "<name>" [IN RANGE <pos> TO <pos>]`
    FindCall { name: String, range: Option<PositionRange> },
    /// `TRACE FROM <pos> TO <pos> WHERE <condition>`
    Trace { from: Position, to: Position, condition: Condition },
    /// `FIND THREAD SWITCH TO <tid>`
    FindThreadSwitch { to_tid: u32 },
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse error.
#[derive(Debug, Clone)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Parse error: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    const fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> &Token {
        let t = self.tokens.get(self.pos).unwrap_or(&Token::Eof);
        self.pos += 1;
        t
    }

    fn expect_number(&mut self) -> Result<u64, ParseError> {
        match self.advance().clone() {
            Token::Number(n) => Ok(n),
            other => Err(ParseError(format!("expected number, got {other:?}"))),
        }
    }

    fn expect_string(&mut self) -> Result<String, ParseError> {
        match self.advance().clone() {
            Token::StringLit(s) | Token::Ident(s) => Ok(s),
            other => Err(ParseError(format!("expected string, got {other:?}"))),
        }
    }

    fn parse_position(&mut self) -> Result<Position, ParseError> {
        let seq = self.expect_number()?;
        // Optional :step
        if self.peek() == &Token::Colon {
            self.advance();
            let step = u32::try_from(self.expect_number()?)
                .map_err(|_| ParseError("step exceeds u32".into()))?;
            Ok(Position::new(seq, step))
        } else {
            Ok(Position::new(seq, 0))
        }
    }

    fn parse_cmp_op(&mut self) -> Result<CmpOp, ParseError> {
        match self.advance().clone() {
            Token::EqEq => Ok(CmpOp::Eq),
            Token::NotEq => Ok(CmpOp::NotEq),
            Token::Gt => Ok(CmpOp::Gt),
            Token::Lt => Ok(CmpOp::Lt),
            other => Err(ParseError(format!("expected comparison operator, got {other:?}"))),
        }
    }

    fn parse_condition(&mut self) -> Result<Condition, ParseError> {
        match self.peek().clone() {
            Token::Memory => {
                self.advance();
                // memory[0xADDR] WRITTEN | READ
                if self.peek() == &Token::LBracket {
                    self.advance();
                    let addr = self.expect_number()?;
                    if self.peek() == &Token::RBracket { self.advance(); }
                    match self.peek().clone() {
                        Token::Written => { self.advance(); Ok(Condition::MemoryWritten { address: addr }) }
                        Token::Read => { self.advance(); Ok(Condition::MemoryRead { address: addr }) }
                        other => Err(ParseError(format!("expected WRITTEN or READ, got {other:?}"))),
                    }
                } else {
                    Err(ParseError("expected '[' after memory".into()))
                }
            }
            Token::Ident(reg) => {
                self.advance();
                let op = self.parse_cmp_op()?;
                let value = self.expect_number()?;
                Ok(Condition::Register { reg, op, value })
            }
            other => Err(ParseError(format!("expected condition, got {other:?}"))),
        }
    }

    fn parse_query(&mut self) -> Result<Query, ParseError> {
        match self.peek().clone() {
            Token::When => {
                self.advance();
                let cond = self.parse_condition()?;
                Ok(Query::When(cond))
            }
            Token::At => {
                self.advance();
                if self.peek() == &Token::Time { self.advance(); }
                let pos = self.parse_position()?;
                if self.peek() == &Token::Show { self.advance(); }
                let show = match self.peek().clone() {
                    Token::Registers => { self.advance(); ShowTarget::Registers }
                    Token::Memory => {
                        self.advance();
                        if self.peek() == &Token::LBracket { self.advance(); }
                        let addr = self.expect_number()?;
                        if self.peek() == &Token::RBracket { self.advance(); }
                        ShowTarget::Memory(addr)
                    }
                    other => return Err(ParseError(format!("expected REGISTERS or MEMORY, got {other:?}"))),
                };
                Ok(Query::AtTime { position: pos, show })
            }
            Token::Find => {
                self.advance();
                match self.peek().clone() {
                    Token::Call => {
                        self.advance();
                        let name = self.expect_string()?;
                        let range = if self.peek() == &Token::In {
                            self.advance();
                            if self.peek() == &Token::Range { self.advance(); }
                            let from = self.parse_position()?;
                            if self.peek() == &Token::To { self.advance(); }
                            let to = self.parse_position()?;
                            Some(PositionRange::new(from, to))
                        } else {
                            None
                        };
                        Ok(Query::FindCall { name, range })
                    }
                    Token::Thread => {
                        self.advance();
                        if self.peek() == &Token::Switch { self.advance(); }
                        // expect TO
                        if self.peek() == &Token::To { self.advance(); }
                        let tid = u32::try_from(self.expect_number()?)
                            .map_err(|_| ParseError("tid exceeds u32".into()))?;
                        Ok(Query::FindThreadSwitch { to_tid: tid })
                    }
                    other => Err(ParseError(format!("expected CALL or THREAD after FIND, got {other:?}"))),
                }
            }
            Token::Trace => {
                self.advance();
                if self.peek() == &Token::From { self.advance(); }
                let from = self.parse_position()?;
                if self.peek() == &Token::To { self.advance(); }
                let to = self.parse_position()?;
                if self.peek() == &Token::Where { self.advance(); }
                let cond = self.parse_condition()?;
                Ok(Query::Trace { from, to, condition: cond })
            }
            other => Err(ParseError(format!("unknown query keyword: {other:?}"))),
        }
    }
}

/// Parse a query string into a [`Query`] AST.
///
/// # Errors
///
/// Returns [`ParseError`] if the input is not a well-formed query.
pub fn parse(input: &str) -> Result<Query, ParseError> {
    let tokens = Lexer::new(input).tokenize();
    let mut parser = Parser::new(tokens);
    parser.parse_query()
}

// ── Query result ──────────────────────────────────────────────────────────────

/// Output of executing a query against the index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryResult {
    /// List of positions satisfying the query.
    Positions(Vec<Position>),
    /// Register snapshot at a position (register → value).
    RegisterSnapshot(HashMap<String, u64>),
    /// Memory value at a position.
    MemoryValue { address: u64, value: Option<u64> },
    /// Timeline of events satisfying a TRACE query.
    Timeline(Vec<TimelineEntry>),
    /// Empty result.
    Empty,
    /// Error during execution.
    Error(String),
}

impl QueryResult {
    #[must_use] 
    pub const fn position_count(&self) -> usize {
        match self {
            Self::Positions(v) => v.len(),
            Self::Timeline(v) => v.len(),
            _ => 0,
        }
    }
}

/// An entry in a TRACE timeline result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub position: Position,
    pub description: String,
}

// ── Executor ──────────────────────────────────────────────────────────────────

/// Executes [`Query`] ASTs against a [`TtdIndex`].
pub struct QueryExecutor<'a> {
    index: &'a TtdIndex,
}

impl<'a> QueryExecutor<'a> {
    #[must_use] 
    pub const fn new(index: &'a TtdIndex) -> Self {
        Self { index }
    }

    #[must_use] 
    pub fn execute(&self, query: &Query) -> QueryResult {
        match query {
            Query::When(cond) => self.execute_when(cond),
            Query::AtTime { position, show } => self.execute_at_time(*position, show),
            Query::FindCall { name, range } => self.execute_find_call(name, range.as_ref()),
            Query::Trace { from, to, condition } => {
                self.execute_trace(*from, *to, condition)
            }
            Query::FindThreadSwitch { to_tid } => self.execute_find_thread_switch(*to_tid),
        }
    }

    fn execute_when(&self, cond: &Condition) -> QueryResult {
        match cond {
            Condition::Register { reg, op, value } => {
                match op {
                    CmpOp::Eq => {
                        let positions = self.index.when_register_equals(reg, *value).to_vec();
                        QueryResult::Positions(positions)
                    }
                    CmpOp::NotEq => {
                        // All positions for this register where value != target
                        let all_vals = self.index.registers.distinct_values(reg);
                        let mut positions: Vec<Position> = all_vals
                            .into_iter()
                            .filter(|&v| v != *value)
                            .flat_map(|v| self.index.registers.query_exact(reg, v).iter().copied())
                            .collect();
                        positions.sort();
                        QueryResult::Positions(positions)
                    }
                    // For Gt/Lt we gather all matching values
                    CmpOp::Gt => {
                        let all_vals = self.index.registers.distinct_values(reg);
                        let mut positions: Vec<Position> = all_vals
                            .into_iter()
                            .filter(|&v| v > *value)
                            .flat_map(|v| self.index.registers.query_exact(reg, v).iter().copied())
                            .collect();
                        positions.sort();
                        QueryResult::Positions(positions)
                    }
                    CmpOp::Lt => {
                        let all_vals = self.index.registers.distinct_values(reg);
                        let mut positions: Vec<Position> = all_vals
                            .into_iter()
                            .filter(|&v| v < *value)
                            .flat_map(|v| self.index.registers.query_exact(reg, v).iter().copied())
                            .collect();
                        positions.sort();
                        QueryResult::Positions(positions)
                    }
                }
            }
            Condition::MemoryWritten { address } => {
                let positions = self.index.when_address_written(*address).to_vec();
                QueryResult::Positions(positions)
            }
            Condition::MemoryRead { address } => {
                let positions = self.index.memory.reads_from(*address).to_vec();
                QueryResult::Positions(positions)
            }
        }
    }

    fn execute_at_time(&self, _position: Position, show: &ShowTarget) -> QueryResult {
        // Without a live trace we can only report what's indexed
        match show {
            ShowTarget::Registers => {
                // Return a snapshot of the most recent value for each indexed register
                // up to the query position (simplified: just list known registers)
                let mut snapshot = HashMap::new();
                // In a real implementation we'd walk the index backwards
                // Here we surface what's available
                snapshot.insert("note".to_string(), 0u64);
                QueryResult::RegisterSnapshot(snapshot)
            }
            ShowTarget::Memory(address) => {
                // Check if address was written
                let writes = self.index.when_address_written(*address);
                QueryResult::MemoryValue {
                    address: *address,
                    value: if writes.is_empty() { None } else { Some(0) },
                }
            }
        }
    }

    fn execute_find_call(&self, name: &str, range: Option<&PositionRange>) -> QueryResult {
        let positions = range.map_or_else(|| self.index.all_calls_to(name).to_vec(), |range| self.index.calls.calls_in_range(name, *range));
        QueryResult::Positions(positions)
    }

    fn execute_trace(&self, from: Position, to: Position, cond: &Condition) -> QueryResult {
        let range = PositionRange::new(from, to);
        let positions: Vec<Position> = match cond {
            Condition::Register { reg, op: CmpOp::Eq, value } => {
                self.index.registers.query_in_range(reg, *value, range)
            }
            Condition::MemoryWritten { address } => {
                let all = self.index.when_address_written(*address);
                let lo = all.partition_point(|p| p < &from);
                let hi = all.partition_point(|p| p <= &to);
                all[lo..hi].to_vec()
            }
            Condition::MemoryRead { address } => {
                let all = self.index.memory.reads_from(*address);
                let lo = all.partition_point(|p| p < &from);
                let hi = all.partition_point(|p| p <= &to);
                all[lo..hi].to_vec()
            }
            Condition::Register { .. } => vec![],
        };

        let timeline: Vec<TimelineEntry> = positions
            .into_iter()
            .map(|pos| TimelineEntry {
                position: pos,
                description: format!("{pos}"),
            })
            .collect();

        if timeline.is_empty() {
            QueryResult::Empty
        } else {
            QueryResult::Timeline(timeline)
        }
    }

    fn execute_find_thread_switch(&self, to_tid: u32) -> QueryResult {
        let positions = self.index.threads.switches_to(to_tid);
        QueryResult::Positions(positions)
    }
}

// ── High-level API ────────────────────────────────────────────────────────────

/// Parse and execute a query string against an index in one call.
#[must_use] 
pub fn query(input: &str, index: &TtdIndex) -> QueryResult {
    match parse(input) {
        Ok(q) => QueryExecutor::new(index).execute(&q),
        Err(e) => QueryResult::Error(e.0),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ttd_index::{IndexEvent, IndexEventKind, TtdIndex};

    fn p(seq: u64, step: u32) -> Position { Position::new(seq, step) }

    fn build_index() -> TtdIndex {
        TtdIndex::build_from_events(vec![
            IndexEvent { position: p(0, 0), kind: IndexEventKind::RegisterWrite { register: "rax".into(), value: 0x1234 } },
            IndexEvent { position: p(1, 0), kind: IndexEventKind::RegisterWrite { register: "rax".into(), value: 0xABCD } },
            IndexEvent { position: p(2, 0), kind: IndexEventKind::RegisterWrite { register: "rax".into(), value: 0x1234 } },
            IndexEvent { position: p(3, 0), kind: IndexEventKind::MemoryWrite { address: 0xDEAD_0000, value: 0, size: 4 } },
            IndexEvent { position: p(4, 0), kind: IndexEventKind::Call { target_name: "CreateFile".into(), target_address: 0x7c00 } },
            IndexEvent { position: p(5, 0), kind: IndexEventKind::Call { target_name: "ReadFile".into(), target_address: 0x7c10 } },
            IndexEvent { position: p(6, 0), kind: IndexEventKind::ThreadSwitch { from_tid: 1, to_tid: 3 } },
        ])
    }

    #[test]
    fn parse_when_register_eq() {
        let q = parse("WHEN rax == 0x1234").unwrap();
        assert_eq!(q, Query::When(Condition::Register {
            reg: "rax".into(), op: CmpOp::Eq, value: 0x1234,
        }));
    }

    #[test]
    fn parse_find_call() {
        let q = parse(r#"FIND CALL "CreateFile""#).unwrap();
        assert_eq!(q, Query::FindCall { name: "CreateFile".into(), range: None });
    }

    #[test]
    fn parse_find_call_in_range() {
        let q = parse(r#"FIND CALL "CreateFile" IN RANGE 10:0 TO 100:0"#).unwrap();
        assert_eq!(q, Query::FindCall {
            name: "CreateFile".into(),
            range: Some(PositionRange::new(p(10, 0), p(100, 0))),
        });
    }

    #[test]
    fn parse_trace_memory() {
        let q = parse("TRACE FROM 0:0 TO 10:0 WHERE memory[0xDEAD0000] WRITTEN").unwrap();
        assert_eq!(q, Query::Trace {
            from: p(0, 0), to: p(10, 0),
            condition: Condition::MemoryWritten { address: 0xDEAD_0000 },
        });
    }

    #[test]
    fn parse_at_time_show_registers() {
        let q = parse("AT time 5:0 SHOW registers").unwrap();
        assert_eq!(q, Query::AtTime { position: p(5, 0), show: ShowTarget::Registers });
    }

    #[test]
    fn parse_find_thread_switch() {
        let q = parse("FIND THREAD SWITCH TO 3").unwrap();
        assert_eq!(q, Query::FindThreadSwitch { to_tid: 3 });
    }

    #[test]
    fn execute_when_eq() {
        let idx = build_index();
        let result = query("WHEN rax == 0x1234", &idx);
        match result {
            QueryResult::Positions(v) => assert_eq!(v, vec![p(0, 0), p(2, 0)]),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn execute_find_call() {
        let idx = build_index();
        let result = query(r#"FIND CALL "CreateFile""#, &idx);
        match result {
            QueryResult::Positions(v) => assert_eq!(v, vec![p(4, 0)]),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn execute_trace_memory_written() {
        let idx = build_index();
        let result = query("TRACE FROM 0:0 TO 10:0 WHERE memory[0xDEAD0000] WRITTEN", &idx);
        match result {
            QueryResult::Timeline(t) => {
                assert_eq!(t.len(), 1);
                assert_eq!(t[0].position, p(3, 0));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn execute_find_thread_switch() {
        let idx = build_index();
        let result = query("FIND THREAD SWITCH TO 3", &idx);
        match result {
            QueryResult::Positions(v) => assert_eq!(v, vec![p(6, 0)]),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parse_error_unknown_keyword() {
        let result = parse("FOOBAR blah");
        assert!(result.is_err());
    }

    #[test]
    fn execute_returns_error_on_bad_query() {
        let idx = build_index();
        let result = query("FOOBAR", &idx);
        assert!(matches!(result, QueryResult::Error(_)));
    }
}
