//! LLM streaming response infrastructure.
//!
//! Provides `StreamEvent`, `TokenBuffer`, `StreamingParser` (SSE/JSON),
//! `StreamingResponse`, and `CostTracker`.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rustre_agent::casts::u64_to_f64;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, Serialize, Deserialize)]
pub enum StreamError {
    #[error("stream closed unexpectedly")]
    Closed,
    #[error("parse error: {0}")]
    Parse(String),
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("buffer overflow: capacity {capacity} exceeded")]
    BufferOverflow { capacity: usize },
}

// ─── StreamEvent ──────────────────────────────────────────────────────────────

/// An event in a streaming LLM response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamEvent {
    /// A text delta from the model.
    Delta {
        /// Text chunk.
        text: String,
        /// Index of the choice (for multi-completion APIs).
        choice_index: u32,
    },
    /// The stream has finished.
    Done {
        /// Finish reason (e.g. `"stop"`, `"length"`, `"tool_calls"`).
        finish_reason: String,
        /// Final token usage, if provided.
        usage: Option<StreamUsage>,
    },
    /// An error occurred during streaming.
    Error(StreamError),
    /// A tool call was requested by the model.
    ToolCall {
        /// Tool call identifier.
        id: String,
        /// Tool name.
        name: String,
        /// Accumulated arguments (may arrive in fragments).
        arguments: String,
    },
    /// Server-sent ping / keep-alive.
    Ping,
    /// A model switch occurred (for routing proxies).
    ModelSwitch { model: String },
}

impl StreamEvent {
    /// Returns the text of a `Delta` event, or `None` for other variants.
    #[must_use]
    pub const fn delta_text(&self) -> Option<&str> {
        if let Self::Delta { text, .. } = self {
            Some(text.as_str())
        } else {
            None
        }
    }

    /// Returns `true` if this is a `Done` event.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        matches!(self, Self::Done { .. })
    }

    /// Returns `true` if this is an `Error` event.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::Error(_))
    }

    /// Returns `true` if this is a `ToolCall` event.
    #[must_use]
    pub const fn is_tool_call(&self) -> bool {
        matches!(self, Self::ToolCall { .. })
    }
}

impl fmt::Display for StreamEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delta { text, choice_index } => write!(f, "delta[{choice_index}]: {text:?}"),
            Self::Done { finish_reason, .. } => write!(f, "done:{finish_reason}"),
            Self::Error(e) => write!(f, "error:{e}"),
            Self::ToolCall { name, .. } => write!(f, "tool_call:{name}"),
            Self::Ping => write!(f, "ping"),
            Self::ModelSwitch { model } => write!(f, "model_switch:{model}"),
        }
    }
}

/// Token usage reported at stream end.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

impl StreamUsage {
    #[must_use]
    pub const fn new(prompt: u32, completion: u32) -> Self {
        Self {
            prompt_tokens: prompt,
            completion_tokens: completion,
            total_tokens: prompt.saturating_add(completion),
        }
    }
}

// ─── TokenBuffer ─────────────────────────────────────────────────────────────

/// Accumulates streaming token deltas and flushes them at configurable intervals.
pub struct TokenBuffer {
    inner: VecDeque<String>,
    capacity: usize,
    flush_threshold: usize,
    total_chars: usize,
}

impl TokenBuffer {
    /// Maximum pre-allocation for `TokenBuffer::with_capacity`.
    ///
    /// Prevents a caller-supplied huge `capacity` from exhausting memory
    /// before any tokens arrive.  Actual logical capacity is still honoured
    /// by the `push()` guard; only the eager heap reservation is capped.
    const MAX_PREALLOC: usize = 65_536;

    #[must_use]
    pub fn new(capacity: usize) -> Self {
        // Cap the initial heap reservation so a caller-supplied huge value
        // does not cause immediate OOM.  The push() bound is enforced
        // separately and still respects the full `capacity` limit.
        let prealloc = capacity.min(Self::MAX_PREALLOC);
        Self {
            inner: VecDeque::with_capacity(prealloc),
            capacity,
            flush_threshold: 10,
            total_chars: 0,
        }
    }

    /// Set the number of tokens to accumulate before `should_flush` returns `true`.
    #[must_use]
    pub const fn with_flush_threshold(mut self, n: usize) -> Self {
        self.flush_threshold = n;
        self
    }

    /// Push a new token delta.  Returns `Err` if the buffer is at capacity.
    ///
    /// # Errors
    ///
    /// Returns [`StreamError::BufferOverflow`] if the buffer is already at capacity.
    pub fn push(&mut self, token: impl Into<String>) -> Result<(), StreamError> {
        if self.inner.len() >= self.capacity {
            return Err(StreamError::BufferOverflow {
                capacity: self.capacity,
            });
        }
        let s = token.into();
        self.total_chars += s.len();
        self.inner.push_back(s);
        Ok(())
    }

    /// Returns `true` if the buffer has at least `flush_threshold` tokens.
    #[must_use]
    pub fn should_flush(&self) -> bool {
        self.inner.len() >= self.flush_threshold
    }

    /// Drain all buffered tokens as a single concatenated string.
    #[must_use]
    pub fn flush(&mut self) -> String {
        let cap: usize = self.inner.iter().map(String::len).sum();
        let mut out = String::with_capacity(cap);
        while let Some(t) = self.inner.pop_front() {
            out.push_str(&t);
        }
        out
    }

    /// Drain up to `n` tokens.
    #[must_use]
    pub fn flush_n(&mut self, n: usize) -> Vec<String> {
        let mut out = Vec::with_capacity(n.min(self.inner.len()));
        for _ in 0..n {
            match self.inner.pop_front() {
                Some(t) => out.push(t),
                None => break,
            }
        }
        out
    }

    /// Number of tokens currently buffered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if no tokens are buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Total number of characters pushed (not flushed).
    #[must_use]
    pub const fn total_chars(&self) -> usize {
        self.total_chars
    }

    /// Peek at all tokens without consuming.
    #[must_use]
    pub fn peek(&self) -> Vec<&str> {
        self.inner.iter().map(std::string::String::as_str).collect()
    }

    /// Concatenate all buffered tokens without consuming.
    #[must_use]
    pub fn peek_all(&self) -> String {
        self.inner.iter().map(std::string::String::as_str).collect()
    }

    /// Clear the buffer.
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

// ─── StreamingParser ─────────────────────────────────────────────────────────

/// Parses SSE (Server-Sent Events) or newline-delimited JSON streams into
/// `StreamEvent`s.
pub struct StreamingParser {
    format: StreamFormat,
    partial_line: String,
}

/// The format of an LLM streaming response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamFormat {
    /// OpenAI-style SSE: `data: {...}\n\n` or `data: [DONE]\n\n`
    OpenAiSse,
    /// Anthropic-style SSE: `event: ...\ndata: {...}\n\n`
    AnthropicSse,
    /// Plain newline-delimited JSON (one JSON object per line).
    NdJson,
}

impl StreamingParser {
    #[must_use]
    pub const fn new(format: StreamFormat) -> Self {
        Self {
            format,
            partial_line: String::new(),
        }
    }

    /// Feed a raw chunk of text and extract all complete events.
    pub fn feed(&mut self, chunk: &str) -> Vec<Result<StreamEvent, StreamError>> {
        self.partial_line.push_str(chunk);
        let mut events = Vec::new();

        while let Some(p) = self.partial_line.find('\n') {
            let pos = p;
            let line: String = self.partial_line.drain(..=pos).collect();
            let line = line.trim_end_matches('\n').trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            match self.format {
                StreamFormat::OpenAiSse => {
                    if let Some(ev) = Self::parse_openai_sse_line(line) {
                        events.push(ev);
                    }
                }
                StreamFormat::AnthropicSse => {
                    if let Some(ev) = Self::parse_anthropic_sse_line(line) {
                        events.push(ev);
                    }
                }
                StreamFormat::NdJson => {
                    events.push(Self::parse_ndjson_line(line));
                }
            }
        }
        events
    }

    fn parse_openai_sse_line(line: &str) -> Option<Result<StreamEvent, StreamError>> {
        if line.is_empty() || line.starts_with(':') {
            return None;
        }
        let data = line.strip_prefix("data: ")?;
        if data == "[DONE]" {
            return Some(Ok(StreamEvent::Done {
                finish_reason: "stop".into(),
                usage: None,
            }));
        }
        let json: serde_json::Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(e) => return Some(Err(StreamError::Parse(e.to_string()))),
        };

        // Check for error
        if let Some(err) = json.get("error") {
            return Some(Err(StreamError::Upstream(err.to_string())));
        }

        // Extract delta text
        let text = json["choices"][0]["delta"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let finish = json["choices"][0]["finish_reason"]
            .as_str()
            .map(str::to_string);

        if let Some(reason) = finish
            && reason != "null" {
                let usage = json.get("usage").map(|u| {
                    let pt = u32::try_from(u["prompt_tokens"].as_u64().unwrap_or(0)).unwrap_or(u32::MAX);
                    let ct = u32::try_from(u["completion_tokens"].as_u64().unwrap_or(0)).unwrap_or(u32::MAX);
                    StreamUsage::new(pt, ct)
                });
                return Some(Ok(StreamEvent::Done {
                    finish_reason: reason,
                    usage,
                }));
            }

        // Check for tool calls
        if let Some(tc) = json["choices"][0]["delta"]["tool_calls"][0].as_object() {
            let id = tc
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let name = tc
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let arguments = tc
                .get("function")
                .and_then(|f| f.get("arguments"))
                .and_then(|a| a.as_str())
                .unwrap_or("")
                .to_string();
            return Some(Ok(StreamEvent::ToolCall {
                id,
                name,
                arguments,
            }));
        }

        if !text.is_empty() {
            return Some(Ok(StreamEvent::Delta {
                text,
                choice_index: 0,
            }));
        }
        None
    }

    fn parse_anthropic_sse_line(line: &str) -> Option<Result<StreamEvent, StreamError>> {
        let data = line.strip_prefix("data: ")?;
        let json: serde_json::Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(e) => return Some(Err(StreamError::Parse(e.to_string()))),
        };
        match json["type"].as_str()? {
            "content_block_delta" => {
                let text = json["delta"]["text"].as_str().unwrap_or("").to_string();
                if text.is_empty() {
                    return None;
                }
                Some(Ok(StreamEvent::Delta {
                    text,
                    choice_index: 0,
                }))
            }
            "message_stop" => Some(Ok(StreamEvent::Done {
                finish_reason: "end_turn".into(),
                usage: None,
            })),
            "message_delta" => {
                let reason = json["delta"]["stop_reason"]
                    .as_str()
                    .unwrap_or("end_turn")
                    .to_string();
                let usage = json.get("usage").map(|u| {
                    let pt = u32::try_from(u["input_tokens"].as_u64().unwrap_or(0)).unwrap_or(u32::MAX);
                    let ct = u32::try_from(u["output_tokens"].as_u64().unwrap_or(0)).unwrap_or(u32::MAX);
                    StreamUsage::new(pt, ct)
                });
                Some(Ok(StreamEvent::Done {
                    finish_reason: reason,
                    usage,
                }))
            }
            "ping" => Some(Ok(StreamEvent::Ping)),
            "error" => Some(Err(StreamError::Upstream(
                json["error"]["message"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string(),
            ))),
            _ => None,
        }
    }

    fn parse_ndjson_line(line: &str) -> Result<StreamEvent, StreamError> {
        let json: serde_json::Value =
            serde_json::from_str(line).map_err(|e| StreamError::Parse(e.to_string()))?;
        // Ollama style
        if let Some(text) = json["message"]["content"].as_str() {
            let done = json["done"].as_bool().unwrap_or(false);
            if done {
                return Ok(StreamEvent::Done {
                    finish_reason: "stop".into(),
                    usage: None,
                });
            }
            return Ok(StreamEvent::Delta {
                text: text.to_string(),
                choice_index: 0,
            });
        }
        Err(StreamError::Parse("unrecognized ndjson structure".into()))
    }
}

// ─── CostTracker ─────────────────────────────────────────────────────────────

/// Cost-per-1k-token rates for a model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCostRates {
    /// Model identifier.
    pub model: String,
    /// Cost per 1 000 input/prompt tokens (USD).
    pub prompt_cost_per_1k: f64,
    /// Cost per 1 000 output/completion tokens (USD).
    pub completion_cost_per_1k: f64,
}

impl ModelCostRates {
    #[must_use]
    pub fn new(model: impl Into<String>, prompt: f64, completion: f64) -> Self {
        Self {
            model: model.into(),
            prompt_cost_per_1k: prompt,
            completion_cost_per_1k: completion,
        }
    }

    /// Well-known rates (approximate, subject to change).
    #[must_use]
    pub fn gpt4o() -> Self {
        Self::new("gpt-4o", 0.005, 0.015)
    }

    #[must_use]
    pub fn gpt4() -> Self {
        Self::new("gpt-4", 0.03, 0.06)
    }

    #[must_use]
    pub fn claude_opus() -> Self {
        Self::new("claude-opus-4-5", 0.015, 0.075)
    }

    #[must_use]
    pub fn claude_sonnet() -> Self {
        Self::new("claude-sonnet-4-5", 0.003, 0.015)
    }

    #[must_use]
    pub fn claude_haiku() -> Self {
        Self::new("claude-haiku-3-5", 0.0008, 0.004)
    }

    /// Calculate cost for the given token counts (USD).
    #[must_use]
    pub fn calculate_cost(&self, prompt_tokens: u64, completion_tokens: u64) -> f64 {
        (u64_to_f64(prompt_tokens) / 1000.0).mul_add(self.prompt_cost_per_1k, (u64_to_f64(completion_tokens) / 1000.0) * self.completion_cost_per_1k)
    }
}

/// Tracks cumulative token usage and cost across multiple LLM calls.
pub struct CostTracker {
    rates: ModelCostRates,
    total_prompt_tokens: AtomicU64,
    total_completion_tokens: AtomicU64,
    call_count: AtomicU64,
    /// Log of individual call costs.
    call_log: Arc<Mutex<Vec<CallCostEntry>>>,
}

/// A single logged call cost entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallCostEntry {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cost_usd: f64,
}

impl CostTracker {
    #[must_use]
    pub fn new(rates: ModelCostRates) -> Self {
        Self {
            rates,
            total_prompt_tokens: AtomicU64::new(0),
            total_completion_tokens: AtomicU64::new(0),
            call_count: AtomicU64::new(0),
            call_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Record a completed call.
    pub fn record(&self, prompt_tokens: u64, completion_tokens: u64) {
        self.total_prompt_tokens
            .fetch_add(prompt_tokens, Ordering::Relaxed);
        self.total_completion_tokens
            .fetch_add(completion_tokens, Ordering::Relaxed);
        self.call_count.fetch_add(1, Ordering::Relaxed);
        let cost = self.rates.calculate_cost(prompt_tokens, completion_tokens);
        self.call_log.lock().push(CallCostEntry {
            prompt_tokens,
            completion_tokens,
            cost_usd: cost,
        });
    }

    /// Record from a `StreamUsage`.
    pub fn record_usage(&self, usage: &StreamUsage) {
        self.record(u64::from(usage.prompt_tokens), u64::from(usage.completion_tokens));
    }

    /// Total prompt tokens across all recorded calls.
    #[must_use]
    pub fn total_prompt_tokens(&self) -> u64 {
        self.total_prompt_tokens.load(Ordering::Relaxed)
    }

    /// Total completion tokens across all recorded calls.
    #[must_use]
    pub fn total_completion_tokens(&self) -> u64 {
        self.total_completion_tokens.load(Ordering::Relaxed)
    }

    /// Total tokens (prompt + completion).
    #[must_use]
    pub fn total_tokens(&self) -> u64 {
        self.total_prompt_tokens() + self.total_completion_tokens()
    }

    /// Total cost in USD.
    #[must_use]
    pub fn total_cost_usd(&self) -> f64 {
        self.rates
            .calculate_cost(self.total_prompt_tokens(), self.total_completion_tokens())
    }

    /// Number of calls recorded.
    #[must_use]
    pub fn call_count(&self) -> u64 {
        self.call_count.load(Ordering::Relaxed)
    }

    /// Average cost per call (USD).
    #[must_use]
    pub fn average_cost_per_call(&self) -> f64 {
        let n = u64_to_f64(self.call_count());
        if n == 0.0 {
            return 0.0;
        }
        self.total_cost_usd() / n
    }

    /// Clone the call log.
    #[must_use]
    pub fn call_log(&self) -> Vec<CallCostEntry> {
        self.call_log.lock().clone()
    }

    /// Reset all counters.
    pub fn reset(&self) {
        self.total_prompt_tokens.store(0, Ordering::Relaxed);
        self.total_completion_tokens.store(0, Ordering::Relaxed);
        self.call_count.store(0, Ordering::Relaxed);
        self.call_log.lock().clear();
    }
}

// ─── StreamingResponse ────────────────────────────────────────────────────────

/// An accumulated streaming response.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StreamingResponse {
    /// Full text assembled from all `Delta` events.
    pub text: String,
    /// Finish reason from the `Done` event.
    pub finish_reason: Option<String>,
    /// Final usage statistics.
    pub usage: Option<StreamUsage>,
    /// Tool calls collected during the stream.
    pub tool_calls: Vec<StreamEvent>,
    /// Total events processed.
    pub event_count: usize,
    /// Whether the stream completed normally.
    pub completed: bool,
    /// Error, if the stream was terminated by an error.
    pub error: Option<StreamError>,
}

impl StreamingResponse {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a `StreamEvent` into this response accumulator.
    pub fn feed(&mut self, event: StreamEvent) {
        self.event_count += 1;
        match event {
            StreamEvent::Delta { text, .. } => self.text.push_str(&text),
            StreamEvent::Done {
                finish_reason,
                usage,
            } => {
                self.finish_reason = Some(finish_reason);
                self.usage = usage;
                self.completed = true;
            }
            StreamEvent::Error(e) => self.error = Some(e),
            ev @ StreamEvent::ToolCall { .. } => self.tool_calls.push(ev),
            _ => {}
        }
    }

    /// Feed all events from a slice.
    pub fn feed_all(&mut self, events: impl IntoIterator<Item = StreamEvent>) {
        for ev in events {
            self.feed(ev);
        }
    }

    /// Returns `true` if the response has text content.
    #[must_use]
    pub const fn has_text(&self) -> bool {
        !self.text.is_empty()
    }

    /// Returns `true` if the response completed without error.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.completed && self.error.is_none()
    }

    /// Word count of accumulated text.
    #[must_use]
    pub fn word_count(&self) -> usize {
        self.text.split_whitespace().count()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── StreamEvent ───────────────────────────────────────────────────────────

    #[test]
    fn stream_event_delta_text() {
        let ev = StreamEvent::Delta {
            text: "hello".into(),
            choice_index: 0,
        };
        assert_eq!(ev.delta_text(), Some("hello"));
    }

    #[test]
    fn stream_event_is_done() {
        let ev = StreamEvent::Done {
            finish_reason: "stop".into(),
            usage: None,
        };
        assert!(ev.is_done());
        assert!(!ev.is_error());
    }

    #[test]
    fn stream_event_is_error() {
        let ev = StreamEvent::Error(StreamError::Closed);
        assert!(ev.is_error());
    }

    #[test]
    fn stream_event_is_tool_call() {
        let ev = StreamEvent::ToolCall {
            id: "c1".into(),
            name: "fn".into(),
            arguments: "{}".into(),
        };
        assert!(ev.is_tool_call());
    }

    #[test]
    fn stream_event_display() {
        let ev = StreamEvent::Ping;
        assert_eq!(ev.to_string(), "ping");
    }

    // ── TokenBuffer ───────────────────────────────────────────────────────────

    #[test]
    fn token_buffer_push_flush() {
        let mut buf = TokenBuffer::new(100);
        buf.push("hello ").unwrap();
        buf.push("world").unwrap();
        let out = buf.flush();
        assert_eq!(out, "hello world");
        assert!(buf.is_empty());
    }

    #[test]
    fn token_buffer_overflow() {
        let mut buf = TokenBuffer::new(2);
        buf.push("a").unwrap();
        buf.push("b").unwrap();
        let r = buf.push("c");
        assert!(r.is_err());
    }

    #[test]
    fn token_buffer_should_flush() {
        let mut buf = TokenBuffer::new(100).with_flush_threshold(3);
        assert!(!buf.should_flush());
        buf.push("a").unwrap();
        buf.push("b").unwrap();
        buf.push("c").unwrap();
        assert!(buf.should_flush());
    }

    #[test]
    fn token_buffer_flush_n() {
        let mut buf = TokenBuffer::new(100);
        buf.push("a").unwrap();
        buf.push("b").unwrap();
        buf.push("c").unwrap();
        let out = buf.flush_n(2);
        assert_eq!(out, vec!["a", "b"]);
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn token_buffer_peek_all() {
        let mut buf = TokenBuffer::new(100);
        buf.push("x").unwrap();
        buf.push("y").unwrap();
        assert_eq!(buf.peek_all(), "xy");
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn token_buffer_total_chars() {
        let mut buf = TokenBuffer::new(100);
        buf.push("hello ").unwrap();
        buf.push("world").unwrap();
        assert_eq!(buf.total_chars(), 11);
    }

    // ── StreamingParser — OpenAI SSE ──────────────────────────────────────────

    #[test]
    fn parser_openai_done() {
        let mut parser = StreamingParser::new(StreamFormat::OpenAiSse);
        let events = parser.feed("data: [DONE]\n");
        assert_eq!(events.len(), 1);
        assert!(events[0].as_ref().unwrap().is_done());
    }

    #[test]
    fn parser_openai_delta() {
        let mut parser = StreamingParser::new(StreamFormat::OpenAiSse);
        let json = r#"{"choices":[{"delta":{"content":"hi"},"finish_reason":null}]}"#;
        let line = format!("data: {json}\n");
        let events = parser.feed(&line);
        assert_eq!(events.len(), 1);
        let ev = events[0].as_ref().unwrap();
        assert_eq!(ev.delta_text(), Some("hi"));
    }

    #[test]
    fn parser_openai_empty_lines_ignored() {
        let mut parser = StreamingParser::new(StreamFormat::OpenAiSse);
        let events = parser.feed("\n\n");
        assert!(events.is_empty());
    }

    // ── StreamingParser — Anthropic SSE ──────────────────────────────────────

    #[test]
    fn parser_anthropic_delta() {
        let mut parser = StreamingParser::new(StreamFormat::AnthropicSse);
        let json = r#"{"type":"content_block_delta","delta":{"text":"hello"}}"#;
        let line = format!("data: {json}\n");
        let events = parser.feed(&line);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].as_ref().unwrap().delta_text(), Some("hello"));
    }

    #[test]
    fn parser_anthropic_message_stop() {
        let mut parser = StreamingParser::new(StreamFormat::AnthropicSse);
        let json = r#"{"type":"message_stop"}"#;
        let line = format!("data: {json}\n");
        let events = parser.feed(&line);
        assert_eq!(events.len(), 1);
        assert!(events[0].as_ref().unwrap().is_done());
    }

    #[test]
    fn parser_anthropic_ping() {
        let mut parser = StreamingParser::new(StreamFormat::AnthropicSse);
        let json = r#"{"type":"ping"}"#;
        let line = format!("data: {json}\n");
        let events = parser.feed(&line);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0].as_ref().unwrap(), StreamEvent::Ping));
    }

    // ── StreamingParser — NDJSON ──────────────────────────────────────────────

    #[test]
    fn parser_ndjson_ollama() {
        let mut parser = StreamingParser::new(StreamFormat::NdJson);
        let json = r#"{"message":{"content":"world"},"done":false}"#;
        let line = format!("{json}\n");
        let events = parser.feed(&line);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].as_ref().unwrap().delta_text(), Some("world"));
    }

    #[test]
    fn parser_ndjson_done() {
        let mut parser = StreamingParser::new(StreamFormat::NdJson);
        let json = r#"{"message":{"content":""},"done":true}"#;
        let line = format!("{json}\n");
        let events = parser.feed(&line);
        assert_eq!(events.len(), 1);
        assert!(events[0].as_ref().unwrap().is_done());
    }

    // ── CostTracker ───────────────────────────────────────────────────────────

    #[test]
    fn cost_tracker_record() {
        let tracker = CostTracker::new(ModelCostRates::gpt4o());
        tracker.record(1000, 500);
        assert_eq!(tracker.total_prompt_tokens(), 1000);
        assert_eq!(tracker.total_completion_tokens(), 500);
        assert_eq!(tracker.total_tokens(), 1500);
        assert_eq!(tracker.call_count(), 1);
    }

    #[test]
    fn cost_tracker_cost_calculation() {
        let rates = ModelCostRates::new("test", 1.0, 2.0); // $1/1k prompt, $2/1k completion
        let tracker = CostTracker::new(rates);
        tracker.record(1000, 1000);
        let cost = tracker.total_cost_usd();
        assert!((cost - 3.0).abs() < 1e-9);
    }

    #[test]
    fn cost_tracker_average_cost_per_call() {
        let tracker = CostTracker::new(ModelCostRates::claude_haiku());
        tracker.record(1000, 500);
        tracker.record(2000, 1000);
        assert!(tracker.average_cost_per_call() > 0.0);
    }

    #[test]
    fn cost_tracker_reset() {
        let tracker = CostTracker::new(ModelCostRates::gpt4o());
        tracker.record(1000, 500);
        tracker.reset();
        assert_eq!(tracker.total_tokens(), 0);
        assert_eq!(tracker.call_count(), 0);
    }

    #[test]
    fn model_cost_rates_known() {
        let r = ModelCostRates::gpt4();
        assert!(r.calculate_cost(1000, 1000) > 0.0);
    }

    // ── StreamingResponse ─────────────────────────────────────────────────────

    #[test]
    fn streaming_response_accumulate() {
        let mut resp = StreamingResponse::new();
        resp.feed(StreamEvent::Delta {
            text: "Hello".into(),
            choice_index: 0,
        });
        resp.feed(StreamEvent::Delta {
            text: " World".into(),
            choice_index: 0,
        });
        resp.feed(StreamEvent::Done {
            finish_reason: "stop".into(),
            usage: None,
        });
        assert_eq!(resp.text, "Hello World");
        assert!(resp.is_ok());
        assert!(resp.has_text());
    }

    #[test]
    fn streaming_response_word_count() {
        let mut resp = StreamingResponse::new();
        resp.feed(StreamEvent::Delta {
            text: "one two three".into(),
            choice_index: 0,
        });
        assert_eq!(resp.word_count(), 3);
    }

    #[test]
    fn streaming_response_error() {
        let mut resp = StreamingResponse::new();
        resp.feed(StreamEvent::Error(StreamError::Closed));
        assert!(!resp.is_ok());
        assert!(resp.error.is_some());
    }

    #[test]
    fn streaming_response_tool_call() {
        let mut resp = StreamingResponse::new();
        resp.feed(StreamEvent::ToolCall {
            id: "c1".into(),
            name: "f".into(),
            arguments: "{}".into(),
        });
        assert_eq!(resp.tool_calls.len(), 1);
    }
}
