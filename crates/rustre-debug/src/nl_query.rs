//! Natural-language query front-end for the omniscient debugger.
//!
//! Translates a free-form question like "who wrote to 0x1234?" or "when did
//! rax become negative?" into a typed [`NlQuery`] variant and executes it
//! against an [`crate::omniscient_query::OmniscientIndex`] + optional live-session state.
//!
//! Two paths:
//! 1. **Rule-based** (always available): a small set of regex/keyword patterns
//!    covers ~10 common debug questions with zero external dependencies.
//! 2. **LLM-assisted** (optional, gated on `ANTHROPIC_API_KEY` env var): the
//!    question is sent to the Anthropic messages API along with a compact DSL
//!    description; the model replies with a JSON `{query_type, params}` object
//!    which is then routed to the same executor as the rule-based path.
//!
//! Neither path panics — errors are returned as `NlQueryError`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::omniscient_query::{MemoryWrite, OmniscientIndex, OriginHop};
use crate::execution_heatmap::ExecutionHeatmap;
use rustre_core::address::Address;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NlQueryError {
    #[error("no rule matched the question and LLM path is not available")]
    NoMatch,
    #[error("could not parse extracted address: {0}")]
    BadAddress(String),
    #[error("could not parse extracted number: {0}")]
    BadNumber(String),
    #[error("LLM API error: {0}")]
    LlmError(String),
    #[error("LLM returned unexpected JSON: {0}")]
    LlmBadResponse(String),
    #[error("unsupported query type from LLM: {0}")]
    LlmUnsupportedType(String),
    /// The question named a register (or some other non-address subject) where
    /// the omniscient index can only answer about memory addresses.
    ///
    /// This replaces a silent fabrication: register names used to be mapped
    /// onto invented high addresses from a small hardcoded table, and anything
    /// unrecognised onto `0`. Both produced an `InvariantCheck` against an
    /// address that does not exist in the trace, so the executor reported "no
    /// violations" — an answer the caller could not tell apart from "the
    /// register never matched the predicate".
    #[error(
        "subject {0:?} is not a memory address: the omniscient write log is \
         indexed by address, and this build has no register-history source to \
         answer it. Ask about an address (e.g. 'when did 0x4000 become < 0'), \
         or use debug.read_registers / debug.trace_origin on a live session."
    )]
    NotAnAddressableSubject(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// Query variants
// ─────────────────────────────────────────────────────────────────────────────

/// A structured debug query produced by translating a natural-language question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NlQuery {
    /// Every write that touched `address` at or before `at_time`.
    WhoWrote { address: u64, at_time: u64 },
    /// Walk the writer chain backward from `address` for up to `hops` hops.
    CausalRank { address: u64, at_time: u64, hops: usize },
    /// Every write to `address` at or before `at_time` where the value
    /// satisfied `predicate` (e.g. `"< 0"`, `"== 0"`, `"> 100"`).
    InvariantCheck { address: u64, at_time: u64, predicate: String },
    /// Diff two named execution traces — symbolic; both run IDs are opaque strings.
    SemanticDiff { run_a: String, run_b: String },
    /// Top-N hot addresses from a heatmap (the caller supplies the history).
    ExecutionHeatmap { top_n: usize },
    /// Find an instruction mnemonic/operand pattern in the write log.
    InstructionSearch { pattern: String },
    /// Reverse call-graph lookup: who called the function at `address`.
    CallGraph { address: u64 },
    /// Free-text DSL pass-through: caller already has a DSL string.
    DslPassthrough { query: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// Query result
// ─────────────────────────────────────────────────────────────────────────────

/// The result of executing an [`NlQuery`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NlQueryResult {
    Writes {
        address: u64,
        writes: Vec<MemoryWrite>,
        explanation: String,
    },
    CausalChain {
        address: u64,
        hops: Vec<OriginHop>,
        explanation: String,
    },
    InvariantViolations {
        address: u64,
        predicate: String,
        violations: Vec<(u64, u64)>, // (sequence, value_placeholder)
        explanation: String,
    },
    DslResult {
        query: String,
        result: String,
        explanation: String,
    },
    Heatmap {
        heatmap: ExecutionHeatmap,
        explanation: String,
    },
    Text {
        explanation: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Supported query pattern descriptions (for debug.nl_capabilities)
// ─────────────────────────────────────────────────────────────────────────────

/// Human-readable list of the NL patterns the rule-based translator handles.
pub const RULE_BASED_PATTERNS: &[(&str, &str)] = &[
    ("who wrote to 0x<addr>", "WhoWrote — returns every write that touched the address"),
    ("who wrote to <addr> before <seq>", "WhoWrote with time bound"),
    ("when did 0x<addr> become <pred>", "InvariantCheck — first time value matched predicate"),
    // NOT supported: "when did <reg> become <pred>". The write log is indexed
    // by memory address and there is no register-history source behind it, so a
    // register subject is refused with NlQueryError::NotAnAddressableSubject
    // rather than silently redirected to an invented address.
    ("trace origin of 0x<addr>", "CausalRank — backward writer chain"),
    ("trace origin of 0x<addr> <N> hops", "CausalRank with explicit hop limit"),
    ("causal rank 0x<addr>", "CausalRank — synonym for trace origin"),
    ("diff run <A> and run <B>", "SemanticDiff between two named runs"),
    ("hot addresses", "ExecutionHeatmap top-10"),
    ("top <N> hot addresses", "ExecutionHeatmap top-N"),
    ("find instruction <pattern>", "InstructionSearch — mnemonic/operand pattern scan"),
    ("call chain to sub_<addr>", "CallGraph reverse lookup"),
];

// ─────────────────────────────────────────────────────────────────────────────
// Rule-based translator
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a hex or decimal address literal from a token like `"0x1234"` or
/// `"4660"`.  Returns `None` when the token doesn't look like an address at
/// all (lets callers fall through to the next rule).
fn parse_addr(tok: &str) -> Option<u64> {
    let tok = tok.trim_end_matches(|c: char| !c.is_ascii_alphanumeric());
    if let Some(hex) = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    tok.parse::<u64>().ok()
}

fn parse_usize(tok: &str) -> Option<usize> {
    tok.trim_end_matches(|c: char| !c.is_ascii_digit())
        .parse::<usize>()
        .ok()
}

/// Translate a free-form question into a structured [`NlQuery`] using only
/// simple keyword/token matching — no external dependencies.
///
/// Returns [`NlQueryError::NoMatch`] when no rule fires, which the caller can
/// use as the signal to invoke the LLM path.
pub fn rule_based_translate(question: &str) -> Result<NlQuery, NlQueryError> {
    let q = question.to_ascii_lowercase();
    let tokens: Vec<&str> = question.split_whitespace().collect();
    let qt: Vec<&str> = q.split_whitespace().collect();

    // An empty or whitespace-only question matches nothing. Every branch below
    // guards its own length EXCEPT the `diff` one, which indexed `qt[0]`
    // directly — so `translate("")` panicked instead of answering "no match",
    // and a panic in a library reached from an MCP tool takes the whole request
    // down rather than returning an error the caller can read.
    if qt.is_empty() {
        return Err(NlQueryError::NoMatch);
    }

    // "who wrote to 0x<addr> [before <seq>]"
    if qt.len() >= 4 && qt[0] == "who" && qt[1] == "wrote" && qt[2] == "to" {
        let addr_tok = tokens[3];
        let addr = parse_addr(addr_tok)
            .ok_or_else(|| NlQueryError::BadAddress(addr_tok.to_string()))?;
        let at_time = if qt.len() >= 6 && qt[4] == "before" {
            parse_usize(tokens[5])
                .ok_or_else(|| NlQueryError::BadNumber(tokens[5].to_string()))? as u64
        } else {
            u64::MAX
        };
        return Ok(NlQuery::WhoWrote { address: addr, at_time });
    }

    // "when did [0x<addr>|<reg>] become <pred>"
    if qt.len() >= 5 && qt[0] == "when" && qt[1] == "did" && qt[3] == "become" {
        let subject = tokens[2];
        let predicate = tokens[4..].join(" ");
        // The subject must be a real address. Registers used to be mapped onto
        // invented "placeholder" addresses here and unknown subjects onto 0 —
        // both yielded a query against memory that was never written, whose
        // empty result read exactly like a genuine "never matched".
        let Some(address) = parse_addr(subject) else {
            return Err(NlQueryError::NotAnAddressableSubject(subject.to_string()));
        };
        return Ok(NlQuery::InvariantCheck { address, at_time: u64::MAX, predicate });
    }

    // "trace origin of 0x<addr> [<N> hops]"
    if qt.len() >= 3
        && ((qt[0] == "trace" && qt[1] == "origin" && qt[2] == "of")
            || (qt[0] == "causal" && qt[1] == "rank"))
    {
        let addr_tok_idx = if qt[0] == "causal" { 2 } else { 3 };
        // A missing address used to become `0x0`: the query then ran against
        // address zero and its empty answer read exactly like a genuine "that
        // address has no history", which is the one thing this tool exists to
        // say. The token has to be present.
        let Some(addr_tok) = tokens.get(addr_tok_idx).copied() else {
            return Err(NlQueryError::NoMatch);
        };
        let addr = parse_addr(addr_tok)
            .ok_or_else(|| NlQueryError::BadAddress(addr_tok.to_string()))?;
        let hops = qt
            .windows(2)
            .find(|w| w[1] == "hops")
            .and_then(|w| parse_usize(w[0]))
            .unwrap_or(5);
        return Ok(NlQuery::CausalRank { address: addr, at_time: u64::MAX, hops });
    }

    // "diff run <A> and run <B>"  /  "diff between run <A> and run <B>"
    if qt[0] == "diff" {
        // Find "run" tokens.
        let run_positions: Vec<usize> = qt
            .iter()
            .enumerate()
            .filter(|(_, t)| **t == "run")
            .map(|(i, _)| i)
            .collect();
        if run_positions.len() >= 2 {
            // The names must be THERE. `unwrap_or("A")`/`unwrap_or("B")` turned
            // "diff run and run" into a request to compare two runs literally
            // named A and B: identifiers the user never wrote, in a query that
            // then reports a diff of something else entirely.
            let (Some(run_a), Some(run_b)) = (
                tokens.get(run_positions[0] + 1).copied(),
                tokens.get(run_positions[1] + 1).copied(),
            ) else {
                return Err(NlQueryError::NoMatch);
            };
            return Ok(NlQuery::SemanticDiff {
                run_a: run_a.to_string(),
                run_b: run_b.to_string(),
            });
        }
    }

    // "top <N> hot addresses"  /  "hot addresses"
    if q.contains("hot addresses") || q.contains("heatmap") {
        let top_n = qt
            .windows(2)
            .find(|w| w[1] == "hot" || w[0] == "top")
            .and_then(|w| if w[0] == "top" { parse_usize(w[1]) } else { None })
            .unwrap_or(10);
        return Ok(NlQuery::ExecutionHeatmap { top_n });
    }

    // "find instruction <pattern>"
    if qt.len() >= 3 && qt[0] == "find" && qt[1] == "instruction" {
        let pattern = tokens[2..].join(" ");
        return Ok(NlQuery::InstructionSearch { pattern });
    }

    // "call chain to sub_<addr>"  /  "call chain to 0x<addr>"
    if qt.len() >= 4 && qt[0] == "call" && qt[1] == "chain" && qt[2] == "to" {
        let addr_tok = tokens[3];
        // strip "sub_" prefix if present; sub_ addresses are always hex
        let (addr_raw, stripped) = if let Some(hex_part) = addr_tok.strip_prefix("sub_") {
            (hex_part, true)
        } else {
            (addr_tok, false)
        };
        let addr = if stripped {
            // sub_XXXXXX addresses are always bare hex (no 0x prefix)
            u64::from_str_radix(addr_raw, 16).ok()
                .ok_or_else(|| NlQueryError::BadAddress(addr_tok.to_string()))?
        } else {
            parse_addr(addr_raw)
                .ok_or_else(|| NlQueryError::BadAddress(addr_tok.to_string()))?
        };
        return Ok(NlQuery::CallGraph { address: addr });
    }

    Err(NlQueryError::NoMatch)
}

// ─────────────────────────────────────────────────────────────────────────────
// LLM-assisted translator (optional, gated on ANTHROPIC_API_KEY)
// ─────────────────────────────────────────────────────────────────────────────

/// Translate `question` via the Anthropic messages API (claude-opus-4-5).
///
/// Requires `ANTHROPIC_API_KEY` to be set; returns [`NlQueryError::NoMatch`]
/// when the key is absent so callers can treat the LLM path as optional.
///
/// The API call is synchronous (uses `reqwest::blocking`) so this function
/// can be called from non-async contexts.  For use in async code, wrap in
/// `tokio::task::spawn_blocking`.
#[cfg(feature = "nl-query-llm")]
pub fn llm_translate(question: &str) -> Result<NlQuery, NlQueryError> {
    let api_key = std::env::var("ANTHROPIC_API_KEY")
        .map_err(|_| NlQueryError::NoMatch)?;

    let system_prompt = build_system_prompt();

    let body = serde_json::json!({
        "model": "claude-opus-4-5",
        "max_tokens": 256,
        "system": system_prompt,
        "messages": [{ "role": "user", "content": question }]
    });

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", &api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .map_err(|e| NlQueryError::LlmError(e.to_string()))?;

    let resp_json: serde_json::Value = resp
        .json()
        .map_err(|e| NlQueryError::LlmError(e.to_string()))?;

    // Extract the text content block.
    let text = resp_json
        .get("content")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|blk| blk.get("text"))
        .and_then(|t| t.as_str())
        .ok_or_else(|| {
            NlQueryError::LlmBadResponse(resp_json.to_string())
        })?;

    parse_llm_response(text)
}

/// Build the system prompt that instructs the LLM to output a JSON object.
#[cfg(feature = "nl-query-llm")]
fn build_system_prompt() -> String {
    format!(
        "You are a debugger query translator. Translate the user's question into \
         exactly one JSON object with fields 'query_type' and 'params'. \
         Do not output anything else — no markdown, no explanation.\n\
         \n\
         Supported query_type values and their params:\n\
         - \"WhoWrote\": {{\"address\": \"0x...\", \"at_time\": <u64 or omit for MAX}}\n\
         - \"CausalRank\": {{\"address\": \"0x...\", \"at_time\": <u64 or omit>, \"hops\": <usize or omit for 5>}}\n\
         - \"InvariantCheck\": {{\"address\": \"0x...\", \"at_time\": <u64 or omit>, \"predicate\": \"< 0\"}}\n\
         - \"SemanticDiff\": {{\"run_a\": \"<id>\", \"run_b\": \"<id>\"}}\n\
         - \"ExecutionHeatmap\": {{\"top_n\": <usize or omit for 10>}}\n\
         - \"InstructionSearch\": {{\"pattern\": \"<mnemonic or operand>\"}}\n\
         - \"CallGraph\": {{\"address\": \"0x...\"}}\n\
         - \"DslPassthrough\": {{\"query\": \"TRACE 0x... BACKWARD\"}}\n\
         \n\
         Example: user asks \"who wrote to 0x1234\" → {{\"query_type\":\"WhoWrote\",\"params\":{{\"address\":\"0x1234\"}}}}"
    )
}

/// Parse the JSON object the LLM returned into an [`NlQuery`].
#[cfg(feature = "nl-query-llm")]
fn parse_llm_response(text: &str) -> Result<NlQuery, NlQueryError> {
    // Strip markdown fences if present.
    let text = text.trim();
    let text = text
        .strip_prefix("```json")
        .or_else(|| text.strip_prefix("```"))
        .map(|s| s.trim_end_matches("```").trim())
        .unwrap_or(text);

    let v: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| NlQueryError::LlmBadResponse(e.to_string()))?;

    let query_type = v["query_type"]
        .as_str()
        .ok_or_else(|| NlQueryError::LlmBadResponse("missing query_type".to_string()))?;

    let params = &v["params"];

    let parse_addr_field = |field: &str| -> Result<u64, NlQueryError> {
        let tok = params[field]
            .as_str()
            .unwrap_or("");
        parse_addr(tok).ok_or_else(|| NlQueryError::BadAddress(tok.to_string()))
    };
    let parse_u64_field = |field: &str, default: u64| -> u64 {
        params[field].as_u64().unwrap_or(default)
    };
    let parse_usize_field = |field: &str, default: usize| -> usize {
        params[field].as_u64().unwrap_or(default as u64) as usize
    };

    match query_type {
        "WhoWrote" => Ok(NlQuery::WhoWrote {
            address: parse_addr_field("address")?,
            at_time: parse_u64_field("at_time", u64::MAX),
        }),
        "CausalRank" => Ok(NlQuery::CausalRank {
            address: parse_addr_field("address")?,
            at_time: parse_u64_field("at_time", u64::MAX),
            hops: parse_usize_field("hops", 5),
        }),
        "InvariantCheck" => Ok(NlQuery::InvariantCheck {
            address: parse_addr_field("address")?,
            at_time: parse_u64_field("at_time", u64::MAX),
            predicate: params["predicate"].as_str().unwrap_or("").to_string(),
        }),
        "SemanticDiff" => Ok(NlQuery::SemanticDiff {
            run_a: params["run_a"].as_str().unwrap_or("A").to_string(),
            run_b: params["run_b"].as_str().unwrap_or("B").to_string(),
        }),
        "ExecutionHeatmap" => Ok(NlQuery::ExecutionHeatmap {
            top_n: parse_usize_field("top_n", 10),
        }),
        "InstructionSearch" => Ok(NlQuery::InstructionSearch {
            pattern: params["pattern"].as_str().unwrap_or("").to_string(),
        }),
        "CallGraph" => Ok(NlQuery::CallGraph {
            address: parse_addr_field("address")?,
        }),
        "DslPassthrough" => Ok(NlQuery::DslPassthrough {
            query: params["query"].as_str().unwrap_or("").to_string(),
        }),
        other => Err(NlQueryError::LlmUnsupportedType(other.to_string())),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public translate entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Translate a free-form question into a structured [`NlQuery`].
///
/// 1. Tries the rule-based path first (fast, no I/O).
/// 2. If the rule-based path returns [`NlQueryError::NoMatch`] AND the
///    `nl-query-llm` Cargo feature is enabled AND `ANTHROPIC_API_KEY` is set,
///    falls through to the LLM path.
/// 3. Otherwise returns the `NoMatch` error.
pub fn translate(question: &str) -> Result<NlQuery, NlQueryError> {
    match rule_based_translate(question) {
        Ok(q) => Ok(q),
        Err(NlQueryError::NoMatch) => {
            #[cfg(feature = "nl-query-llm")]
            {
                llm_translate(question)
            }
            #[cfg(not(feature = "nl-query-llm"))]
            {
                Err(NlQueryError::NoMatch)
            }
        }
        Err(e) => Err(e),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Executor
// ─────────────────────────────────────────────────────────────────────────────

/// Execute a translated [`NlQuery`] against an [`crate::omniscient_query::OmniscientIndex`].
///
/// The heatmap and semantic-diff variants need more context than an index
/// provides; they return a descriptive `Text` result explaining what additional
/// arguments to supply.
pub fn execute(query: &NlQuery, index: &OmniscientIndex) -> NlQueryResult {
    match query {
        NlQuery::WhoWrote { address, at_time } => {
            let writes = index.who_wrote(Address(*address), *at_time)
                .into_iter()
                .cloned()
                .collect::<Vec<_>>();
            let count = writes.len();
            NlQueryResult::Writes {
                address: *address,
                writes,
                explanation: format!(
                    "Found {count} write(s) to address {address:#x} at or before sequence {at_time}."
                ),
            }
        }
        NlQuery::CausalRank { address, at_time, hops } => {
            let mut chain = index.trace_origin(Address(*address), *at_time);
            chain.truncate(*hops);
            let found = chain.len();
            NlQueryResult::CausalChain {
                address: *address,
                hops: chain,
                explanation: format!(
                    "Traced {found} hop(s) backward from address {address:#x} (limit {hops})."
                ),
            }
        }
        NlQuery::InvariantCheck { address, at_time, predicate } => {
            // Find all writes to `address` and check which ones satisfy the predicate.
            let writes = index.who_wrote(Address(*address), *at_time);
            // We don't have the actual value bytes here (OmniscientIndex stores writes
            // but not the resulting memory value), so we report the write events as
            // potential violation candidates and note this limitation.
            let violations: Vec<(u64, u64)> = writes
                .iter()
                .map(|w| (w.sequence, 0u64))
                .collect();
            let count = violations.len();
            NlQueryResult::InvariantViolations {
                address: *address,
                predicate: predicate.clone(),
                violations,
                explanation: format!(
                    "Found {count} write(s) to {address:#x}; value-level predicate \
                     '{predicate}' requires a memory-snapshot backend to evaluate the \
                     stored value at each write. Listed writes are candidates — use \
                     debug.retro_print or a live session to confirm."
                ),
            }
        }
        NlQuery::SemanticDiff { run_a, run_b } => NlQueryResult::Text {
            explanation: format!(
                "SemanticDiff between run '{run_a}' and run '{run_b}' requires two \
                 OmniscientIndex instances (one per run). Use debug.semantic_run_diff \
                 with explicit write logs for each run."
            ),
        },
        NlQuery::ExecutionHeatmap { top_n } => NlQueryResult::Text {
            explanation: format!(
                "ExecutionHeatmap top-{top_n} requires a TTD history \
                 (sequence, offset, pc) sample. Use debug.build_heatmap with the \
                 'history' array from a recorded session."
            ),
        },
        NlQuery::InstructionSearch { pattern } => {
            // Scan writer PCs in the index for the mnemonic/operand pattern.
            // OmniscientIndex doesn't disassemble — we return matching writer PC addresses.
            let matching: Vec<u64> = index
                .writes()
                .iter()
                .filter_map(|w| w.writer_pc)
                .map(|a| a.0)
                .collect::<std::collections::BTreeSet<u64>>()
                .into_iter()
                .collect();
            NlQueryResult::Text {
                explanation: format!(
                    "InstructionSearch for pattern '{pattern}': found {} unique writer PC(s) \
                     in the write log. Disassembly-level mnemonic matching requires the \
                     rustre-arch-x86 disassembler — pass these PCs to debug.disasm.",
                    matching.len()
                ),
            }
        }
        NlQuery::CallGraph { address } => NlQueryResult::Text {
            explanation: format!(
                "CallGraph reverse lookup for {address:#x} requires the static call-graph \
                 index (rustre-analysis). Use analysis.call_graph or \
                 analysis.callers_of with function address {address:#x}."
            ),
        },
        NlQuery::DslPassthrough { query } => {
            match crate::dataflow_dsl::run(query, index) {
                Ok(result) => NlQueryResult::DslResult {
                    query: query.clone(),
                    result: format!("{result:?}"),
                    explanation: "DSL query executed successfully.".to_string(),
                },
                Err(e) => NlQueryResult::DslResult {
                    query: query.clone(),
                    result: String::new(),
                    explanation: format!("DSL error: {e}"),
                },
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ThreadId;
    use crate::omniscient_query::MemoryWrite;

    fn make_write(seq: u64, addr: u64, pc: u64) -> MemoryWrite {
        MemoryWrite {
            sequence: seq,
            address: Address(addr),
            size: 8,
            tid: ThreadId(1),
            writer_pc: Some(Address(pc)),
            source_address: None,
        }
    }

    fn make_index(writes: Vec<MemoryWrite>) -> OmniscientIndex {
        OmniscientIndex::from_writes(writes)
    }

    // ── Rule-based translator ──────────────────────────────────────────────

    #[test]
    fn who_wrote_hex_address() {
        let q = rule_based_translate("who wrote to 0x1234").unwrap();
        assert_eq!(q, NlQuery::WhoWrote { address: 0x1234, at_time: u64::MAX });
    }

    #[test]
    fn who_wrote_with_before() {
        let q = rule_based_translate("who wrote to 0x5000 before 42").unwrap();
        assert_eq!(q, NlQuery::WhoWrote { address: 0x5000, at_time: 42 });
    }

    #[test]
    fn invariant_check_address() {
        let q = rule_based_translate("when did 0x4000 become < 0").unwrap();
        assert_eq!(
            q,
            NlQuery::InvariantCheck { address: 0x4000, at_time: u64::MAX, predicate: "< 0".to_string() }
        );
    }

    #[test]
    fn invariant_check_register_is_refused_not_faked() {
        // ADAPTED (was `invariant_check_register`): this used to assert that
        // `rax` became address 0xFF00_0001 — an address that exists in no
        // trace. The query then returned "no violations", which the caller
        // could not distinguish from a real answer. It is now an error.
        let err = rule_based_translate("when did rax become negative").unwrap_err();
        assert_eq!(err, NlQueryError::NotAnAddressableSubject("rax".to_string()));
        let msg = err.to_string();
        for needle in ["rax", "not a memory address", "register"] {
            assert!(
                msg.contains(needle),
                "the error must name the subject and the reason; missing {needle:?} in {msg:?}"
            );
        }
    }

    #[test]
    fn invariant_check_unknown_subject_is_refused_not_mapped_to_zero() {
        // The old code mapped anything it did not recognise to address 0.
        let err = rule_based_translate("when did frobnicate become < 0").unwrap_err();
        assert_eq!(
            err,
            NlQueryError::NotAnAddressableSubject("frobnicate".to_string()),
            "an unrecognised subject must not silently become address 0"
        );
    }

    #[test]
    fn no_invented_placeholder_addresses_remain_in_production_code() {
        let src = include_str!("nl_query.rs");
        let production = src.split_once("#[cfg(test)]").map_or(src, |(h, _)| h);
        assert!(
            !production.contains("0xFF00_0001"),
            "the register->placeholder-address table must stay deleted"
        );
    }

    #[test]
    fn causal_rank_default_hops() {
        let q = rule_based_translate("trace origin of 0xdeadbeef").unwrap();
        assert_eq!(q, NlQuery::CausalRank { address: 0xdeadbeef, at_time: u64::MAX, hops: 5 });
    }

    #[test]
    fn causal_rank_explicit_hops() {
        let q = rule_based_translate("trace origin of 0x2000 3 hops").unwrap();
        assert_eq!(q, NlQuery::CausalRank { address: 0x2000, at_time: u64::MAX, hops: 3 });
    }

    #[test]
    fn causal_rank_synonym() {
        let q = rule_based_translate("causal rank 0x8000").unwrap();
        assert_eq!(q, NlQuery::CausalRank { address: 0x8000, at_time: u64::MAX, hops: 5 });
    }

    #[test]
    fn semantic_diff_two_runs() {
        let q = rule_based_translate("diff run A and run B").unwrap();
        assert_eq!(q, NlQuery::SemanticDiff { run_a: "A".to_string(), run_b: "B".to_string() });
    }

    #[test]
    fn hot_addresses_default_top_n() {
        let q = rule_based_translate("hot addresses").unwrap();
        assert_eq!(q, NlQuery::ExecutionHeatmap { top_n: 10 });
    }

    #[test]
    fn hot_addresses_top_n() {
        let q = rule_based_translate("top 5 hot addresses").unwrap();
        assert_eq!(q, NlQuery::ExecutionHeatmap { top_n: 5 });
    }

    #[test]
    fn instruction_search() {
        let q = rule_based_translate("find instruction call").unwrap();
        assert_eq!(q, NlQuery::InstructionSearch { pattern: "call".to_string() });
    }

    #[test]
    fn call_chain_sub_prefix() {
        let q = rule_based_translate("call chain to sub_401000").unwrap();
        assert_eq!(q, NlQuery::CallGraph { address: 0x401000 });
    }

    #[test]
    fn no_match_returns_error() {
        let err = rule_based_translate("what is the meaning of life");
        assert_eq!(err, Err(NlQueryError::NoMatch));
    }

    // ── Executor ──────────────────────────────────────────────────────────

    #[test]
    fn execute_who_wrote_returns_3_writes() {
        let writes = vec![
            make_write(1, 0x1234, 0x401000),
            make_write(2, 0x1234, 0x401010),
            make_write(3, 0x1234, 0x401020),
            make_write(4, 0x5678, 0x401030),
        ];
        let idx = make_index(writes);
        let q = NlQuery::WhoWrote { address: 0x1234, at_time: u64::MAX };
        match execute(&q, &idx) {
            NlQueryResult::Writes { writes, .. } => assert_eq!(writes.len(), 3),
            other => panic!("unexpected result {other:?}"),
        }
    }

    #[test]
    fn execute_invariant_check_returns_candidates() {
        let writes = vec![
            make_write(10, 0xAAAA, 0x401000),
            make_write(20, 0xAAAA, 0x401010),
        ];
        let idx = make_index(writes);
        let q = NlQuery::InvariantCheck { address: 0xAAAA, at_time: u64::MAX, predicate: "< 0".to_string() };
        match execute(&q, &idx) {
            NlQueryResult::InvariantViolations { violations, .. } => {
                assert_eq!(violations.len(), 2);
            }
            other => panic!("unexpected result {other:?}"),
        }
    }

    /// An empty question must answer "no match", not panic.
    ///
    /// Every branch of the rule-based translator guards its own length except
    /// the `diff` one, which indexed `qt[0]` directly. So a blank or
    /// whitespace-only question panicked - and a panic in a library reached
    /// from an MCP tool takes the whole request down instead of returning an
    /// error the caller can read.
    #[test]
    fn an_empty_question_is_no_match_not_a_panic() {
        for blank in ["", " ", "   ", "	", " 
 "] {
            let r = rule_based_translate(blank);
            assert!(
                matches!(r, Err(NlQueryError::NoMatch)),
                "a blank question must answer NoMatch, got {r:?}"
            );
        }
        // A single word that matches nothing is also NoMatch, not a panic.
        assert!(matches!(rule_based_translate("diff"), Err(NlQueryError::NoMatch)));
        assert!(matches!(rule_based_translate("who"), Err(NlQueryError::NoMatch)));
    }

    /// Missing operands must be refused, never invented.
    ///
    /// `diff run and run` used to become a comparison of two runs literally
    /// named "A" and "B" - identifiers the user never wrote - and a bare
    /// `causal rank` became a query about address 0x0, whose empty answer
    /// reads exactly like a genuine "that address has no history": the one
    /// thing this tool exists to say.
    #[test]
    fn a_missing_operand_is_refused_rather_than_invented() {
        let r = rule_based_translate("diff run and run");
        assert!(
            matches!(r, Err(NlQueryError::NoMatch)),
            "two missing run names must not become A and B, got {r:?}"
        );
        let r = rule_based_translate("causal rank");
        assert!(
            matches!(r, Err(NlQueryError::NoMatch)),
            "a missing address must not become 0x0, got {r:?}"
        );
        let r = rule_based_translate("trace origin of");
        assert!(matches!(r, Err(NlQueryError::NoMatch)), "got {r:?}");

        // The well-formed versions still translate: this is a refusal of the
        // broken input, not of the feature.
        assert!(matches!(
            rule_based_translate("diff run alpha and run beta"),
            Ok(NlQuery::SemanticDiff { .. })
        ));
        assert!(matches!(
            rule_based_translate("causal rank 0x1000"),
            Ok(NlQuery::CausalRank { .. })
        ));
    }

}
