//! Declarative dataflow query DSL (original-IP track, addendum item 4 of
//! `rustre_debug_enhancement_plan.md`).
//!
//! Pernosco is UI-click-only, GDB is imperative-command-only; this is a small
//! declarative query language over the Tier-1 omniscient index
//! ([`crate::omniscient_query::OmniscientIndex`]), in the spirit of the plan's
//! examples:
//! - `TRACE 0xdeadbeef BACKWARD` — walk the writer chain for an address (wraps
//!   [`crate::omniscient_query::OmniscientIndex::trace_origin`]).
//! - `TRACE 0xdeadbeef BACKWARD UNTIL PC 0x401000` — same, but stop as soon as a
//!   hop's writer PC matches (e.g. "stop once you reach the network-read call").
//! - `TRACE 0xdeadbeef BACKWARD AT 500` — trace the chain as of sequence 500
//!   rather than from the end of the recording. Combines with `UNTIL PC`, in
//!   either order.
//! - `FIND WRITES TO 0x2000 BEFORE 100` — every write to an address at or before a
//!   sequence number (wraps [`crate::omniscient_query::OmniscientIndex::who_wrote`]).
//!
//! This is a minimal, hand-rolled flat parser over a whitespace/hex grammar —
//! not a general-purpose language — sized to the plan's own examples. (It is
//! not recursive despite an earlier comment here saying "recursive-descent":
//! every production is parsed inline from a single token iterator.)
//! Extending the grammar (e.g. `WHERE origin != baseline`, `SINCE last_breakpoint`)
//! is a natural next step once a caller needs it.

use rustre_core::address::Address;

use crate::omniscient_query::{MemoryWrite, OmniscientIndex, OriginHop};

/// A parsed DSL command, ready to execute against an [`crate::omniscient_query::OmniscientIndex`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DslCommand {
    /// `TRACE <addr> BACKWARD [AT <seq>] [UNTIL PC <addr>]`
    ///
    /// `at_time` defaults to `u64::MAX` (trace from the end of the recording).
    TraceBackward { address: Address, at_time: u64, until_pc: Option<Address> },
    /// `FIND WRITES TO <addr> BEFORE <seq>`
    FindWrites { address: Address, before: u64 },
}

/// A parse or execution error, with a human-readable message for display in a
/// REPL/tool-call context.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DslError {
    #[error("empty query")]
    Empty,
    #[error("unknown command {0:?} — expected TRACE or FIND")]
    UnknownCommand(String),
    #[error("expected token {expected:?} at position {position}, found {found:?}")]
    ExpectedToken { expected: String, position: usize, found: String },
    #[error("invalid address literal {0:?} — expected 0x-prefixed hex")]
    InvalidAddress(String),
    #[error("invalid sequence number {0:?} — expected a decimal integer")]
    InvalidSequence(String),
    #[error("unexpected trailing tokens: {0}")]
    TrailingTokens(String),
}

fn parse_address(tok: &str) -> Result<Address, DslError> {
    let hex = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X"));
    let Some(hex) = hex else {
        return Err(DslError::InvalidAddress(tok.to_string()));
    };
    u64::from_str_radix(hex, 16)
        .map(Address)
        .map_err(|_| DslError::InvalidAddress(tok.to_string()))
}

fn parse_seq(tok: &str) -> Result<u64, DslError> {
    tok.parse::<u64>().map_err(|_| DslError::InvalidSequence(tok.to_string()))
}

fn expect<'a>(tokens: &mut std::slice::Iter<'a, &'a str>, expected: &str, position: usize) -> Result<&'a str, DslError> {
    match tokens.next() {
        Some(&tok) if tok.eq_ignore_ascii_case(expected) => Ok(tok),
        Some(&tok) => Err(DslError::ExpectedToken { expected: expected.to_string(), position, found: tok.to_string() }),
        None => Err(DslError::ExpectedToken { expected: expected.to_string(), position, found: "<end>".to_string() }),
    }
}

/// Parse a single DSL query string into a [`DslCommand`].
pub fn parse(query: &str) -> Result<DslCommand, DslError> {
    let tokens: Vec<&str> = query.split_whitespace().collect();
    if tokens.is_empty() {
        return Err(DslError::Empty);
    }
    let mut it = tokens.iter();
    let head = *it.next().unwrap();

    match head.to_ascii_uppercase().as_str() {
        "TRACE" => {
            let addr_tok = it.next().ok_or_else(|| DslError::ExpectedToken {
                expected: "<address>".into(),
                position: 1,
                found: "<end>".into(),
            })?;
            let address = parse_address(addr_tok)?;
            expect(&mut it, "BACKWARD", 2)?;

            // Optional clauses, in any order: `AT <seq>` and `UNTIL PC <addr>`.
            // `AT` scopes the trace to a point in the recording —
            // `trace_origin` has always honoured its `at_time` argument, but
            // the grammar had no way to express one and hardcoded `u64::MAX`,
            // leaving that engine capability unreachable from the DSL.
            let mut at_time = u64::MAX;
            let mut until_pc = None;
            let mut position = 3;
            while let Some(&tok) = it.next() {
                if tok.eq_ignore_ascii_case("AT") {
                    let seq_tok = it.next().ok_or_else(|| DslError::ExpectedToken {
                        expected: "<sequence>".into(),
                        position: position + 1,
                        found: "<end>".into(),
                    })?;
                    at_time = parse_seq(seq_tok)?;
                    position += 2;
                } else if tok.eq_ignore_ascii_case("UNTIL") {
                    expect(&mut it, "PC", position + 1)?;
                    let pc_tok = it.next().ok_or_else(|| DslError::ExpectedToken {
                        expected: "<address>".into(),
                        position: position + 2,
                        found: "<end>".into(),
                    })?;
                    until_pc = Some(parse_address(pc_tok)?);
                    position += 3;
                } else {
                    return Err(DslError::TrailingTokens(tok.to_string()));
                }
            }
            Ok(DslCommand::TraceBackward { address, at_time, until_pc })
        }
        "FIND" => {
            expect(&mut it, "WRITES", 1)?;
            expect(&mut it, "TO", 2)?;
            let addr_tok = it.next().ok_or_else(|| DslError::ExpectedToken {
                expected: "<address>".into(),
                position: 3,
                found: "<end>".into(),
            })?;
            let address = parse_address(addr_tok)?;
            expect(&mut it, "BEFORE", 4)?;
            let seq_tok = it.next().ok_or_else(|| DslError::ExpectedToken {
                expected: "<sequence>".into(),
                position: 5,
                found: "<end>".into(),
            })?;
            let before = parse_seq(seq_tok)?;
            if let Some(&trailing) = it.next() {
                return Err(DslError::TrailingTokens(trailing.to_string()));
            }
            Ok(DslCommand::FindWrites { address, before })
        }
        other => Err(DslError::UnknownCommand(other.to_string())),
    }
}

/// Result of executing a [`DslCommand`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DslResult {
    Origin(Vec<OriginHop>),
    Writes(Vec<MemoryWrite>),
}

/// Execute a parsed DSL command against an omniscient index.
#[must_use]
pub fn execute(command: &DslCommand, index: &OmniscientIndex) -> DslResult {
    match command {
        DslCommand::TraceBackward { address, at_time, until_pc } => {
            let mut hops = index.trace_origin(*address, *at_time);
            if let Some(pc) = until_pc
                && let Some(cut) = hops.iter().position(|h| h.write.writer_pc == Some(*pc)) {
                    hops.truncate(cut + 1);
                }
            DslResult::Origin(hops)
        }
        DslCommand::FindWrites { address, before } => {
            let writes = index.who_wrote(*address, *before).into_iter().cloned().collect();
            DslResult::Writes(writes)
        }
    }
}

/// Parse and execute a query in one call — convenience for tool-calling/REPL
/// callers that don't need the intermediate [`DslCommand`].
pub fn run(query: &str, index: &OmniscientIndex) -> Result<DslResult, DslError> {
    parse(query).map(|cmd| execute(&cmd, index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ThreadId;

    fn write(seq: u64, addr: u64, pc: u64, source: Option<u64>) -> MemoryWrite {
        MemoryWrite {
            sequence: seq,
            address: Address(addr),
            size: 4,
            tid: ThreadId(1),
            writer_pc: Some(Address(pc)),
            source_address: source.map(Address),
        }
    }

    #[test]
    fn parses_trace_backward() {
        let cmd = parse("TRACE 0x2000 BACKWARD").unwrap();
        assert_eq!(cmd, DslCommand::TraceBackward { address: Address(0x2000), at_time: u64::MAX, until_pc: None });
    }

    #[test]
    fn parses_trace_backward_until_pc_case_insensitively() {
        let cmd = parse("trace 0x2000 backward until pc 0x401000").unwrap();
        assert_eq!(
            cmd,
            DslCommand::TraceBackward { address: Address(0x2000), at_time: u64::MAX, until_pc: Some(Address(0x0040_1000)) }
        );
    }

    /// `OmniscientIndex::trace_origin` has always taken an `at_time` cutoff
    /// and honoured it, and `DslCommand::TraceBackward` has always carried the
    /// field — but the grammar hardcoded `u64::MAX`, so the capability was
    /// unreachable from the query language and `AT` parsed as a trailing-token
    /// error. Same shape as a backend that is implemented but never wired up.
    #[test]
    fn trace_backward_accepts_an_at_time_cutoff() {
        let cmd = parse("TRACE 0x1000 BACKWARD AT 5").unwrap();
        assert_eq!(
            cmd,
            DslCommand::TraceBackward {
                address: Address(0x1000),
                at_time: 5,
                until_pc: None
            }
        );

        // Combines with UNTIL PC, in either order.
        let a = parse("trace 0x1000 backward at 7 until pc 0x401000").unwrap();
        let b = parse("trace 0x1000 backward until pc 0x401000 at 7").unwrap();
        assert_eq!(a, b);
        assert_eq!(
            a,
            DslCommand::TraceBackward {
                address: Address(0x1000),
                at_time: 7,
                until_pc: Some(Address(0x0040_1000))
            }
        );

        // Omitting it still means "from the end of the recording".
        assert_eq!(
            parse("TRACE 0x1000 BACKWARD").unwrap(),
            DslCommand::TraceBackward { address: Address(0x1000), at_time: u64::MAX, until_pc: None }
        );

        // Malformed clauses stay errors rather than being silently accepted.
        assert!(matches!(parse("TRACE 0x1000 BACKWARD AT"), Err(DslError::ExpectedToken { .. })));
        assert!(matches!(parse("TRACE 0x1000 BACKWARD AT zz"), Err(DslError::InvalidSequence(_))));
        assert!(matches!(parse("TRACE 0x1000 BACKWARD NONSENSE"), Err(DslError::TrailingTokens(_))));
    }

    /// End-to-end: the cutoff must actually change the answer, not just parse.
    #[test]
    fn at_time_cutoff_changes_the_traced_chain() {
        // 0x1000 is written at seq 2 (copy of 0x2000) and again at seq 8.
        let idx = OmniscientIndex::from_writes(vec![
            write(0, 0x2000, 0x0040_1000, None),
            write(2, 0x1000, 0x0040_1010, Some(0x2000)),
            write(8, 0x1000, 0x0040_1020, None),
        ]);

        // Without a cutoff the newest write (seq 8) is the origin.
        let DslResult::Origin(latest) = run("TRACE 0x1000 BACKWARD", &idx).unwrap() else {
            panic!("expected an origin result");
        };
        assert_eq!(latest[0].write.sequence, 8);

        // As of seq 5 the seq-8 write has not happened yet, so the chain
        // starts at seq 2 and follows the copy back to 0x2000.
        let DslResult::Origin(earlier) = run("TRACE 0x1000 BACKWARD AT 5", &idx).unwrap() else {
            panic!("expected an origin result");
        };
        assert_eq!(earlier[0].write.sequence, 2);
        assert_eq!(earlier.last().unwrap().write.sequence, 0);
    }

    #[test]
    fn parses_find_writes() {
        let cmd = parse("FIND WRITES TO 0x3000 BEFORE 42").unwrap();
        assert_eq!(cmd, DslCommand::FindWrites { address: Address(0x3000), before: 42 });
    }

    #[test]
    fn rejects_empty_query() {
        assert_eq!(parse(""), Err(DslError::Empty));
        assert_eq!(parse("   "), Err(DslError::Empty));
    }

    #[test]
    fn rejects_unknown_command() {
        assert!(matches!(parse("DELETE 0x1000"), Err(DslError::UnknownCommand(_))));
    }

    #[test]
    fn rejects_bad_address_literal() {
        assert!(matches!(parse("TRACE 1234 BACKWARD"), Err(DslError::InvalidAddress(_))));
    }

    #[test]
    fn rejects_bad_sequence_literal() {
        assert!(matches!(parse("FIND WRITES TO 0x1000 BEFORE abc"), Err(DslError::InvalidSequence(_))));
    }

    #[test]
    fn rejects_trailing_tokens() {
        assert!(matches!(parse("TRACE 0x1000 BACKWARD extra"), Err(DslError::TrailingTokens(_))));
    }

    #[test]
    fn executes_find_writes_query() {
        let index = OmniscientIndex::from_writes(vec![write(0, 0x1000, 0x100, None), write(1, 0x1000, 0x200, None)]);
        let result = run("FIND WRITES TO 0x1000 BEFORE 5", &index).unwrap();
        let DslResult::Writes(writes) = result else { panic!("wrong variant") };
        assert_eq!(writes.len(), 2);
    }

    #[test]
    fn executes_trace_backward_query() {
        let mut index = OmniscientIndex::new();
        index.push(write(0, 0x2000, 0x50, None));
        index.push(write(1, 0x3000, 0x60, Some(0x2000)));
        let result = run("TRACE 0x3000 BACKWARD", &index).unwrap();
        let DslResult::Origin(hops) = result else { panic!("wrong variant") };
        assert_eq!(hops.len(), 2);
    }

    #[test]
    fn trace_backward_until_pc_truncates_chain() {
        let mut index = OmniscientIndex::new();
        index.push(write(0, 0x2000, 0x50, None));
        index.push(write(1, 0x3000, 0x60, Some(0x2000)));
        let result = run("TRACE 0x3000 BACKWARD UNTIL PC 0x60", &index).unwrap();
        let DslResult::Origin(hops) = result else { panic!("wrong variant") };
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].write.writer_pc, Some(Address(0x60)));
    }
}
