//! LLM context window management for `RustRE` agents.
//!
//! Provides [`ContextManager`] as the root type, with
//! [`TokenCounter`], [`ContextTrimmer`], [`SummaryGenerator`],
//! [`PriorityRetention`], and [`ContextExport`].

#![allow(dead_code)]

use std::collections::HashMap;

/// Re-export of [`std::collections::VecDeque`] for callers building
/// fixed-window message queues on top of [`ContextManager`].
pub use std::collections::VecDeque;

/// Re-export of [`std::sync::Arc`] for callers sharing context-manager
/// state across async tasks.
pub use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::fmt::Write as FmtWrite;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ContextError {
    #[error("context window full: {tokens} tokens > {limit}")]
    WindowFull { tokens: u32, limit: u32 },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("message index {0} out of bounds")]
    OutOfBounds(usize),

    #[error("trim target {target} exceeds current size {current}")]
    TrimTarget { target: u32, current: u32 },
}

pub type ContextResult<T> = std::result::Result<T, ContextError>;

// ── numeric cast helpers ─────────────────────────────────────────────────────
// Route through the workspace-standard saturating cast helpers in
// `rustre_agent::casts` so no `as`-casts appear at the call site.

use rustre_agent::casts::{f64_to_u32 as f64_to_u32_saturating, usize_to_f64};


// ── MessageRole ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageRole {
    System,
    User,
    Assistant,
    Tool,
}

impl std::fmt::Display for MessageRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::System => write!(f, "system"),
            Self::User => write!(f, "user"),
            Self::Assistant => write!(f, "assistant"),
            Self::Tool => write!(f, "tool"),
        }
    }
}

// ── ContextMessage ────────────────────────────────────────────────────────────

/// A single message in the context window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextMessage {
    pub role: MessageRole,
    pub content: String,
    /// Estimated token count for this message.
    pub token_count: u32,
    /// Priority (higher = more important to retain).
    pub priority: u8,
    /// Whether this message should never be trimmed.
    pub pinned: bool,
    /// Metadata (tool name, timestamps, etc.).
    pub metadata: HashMap<String, String>,
}

impl ContextMessage {
    pub fn new(role: MessageRole, content: impl Into<String>) -> Self {
        let content = content.into();
        let token_count = TokenCounter::estimate_tokens(&content);
        Self {
            role,
            content,
            token_count,
            priority: 5,
            pinned: false,
            metadata: HashMap::new(),
        }
    }

    pub fn system(content: impl Into<String>) -> Self {
        let mut m = Self::new(MessageRole::System, content);
        m.pinned = true;
        m.priority = 10;
        m
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self::new(MessageRole::User, content)
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self::new(MessageRole::Assistant, content)
    }

    pub fn tool(content: impl Into<String>) -> Self {
        let mut m = Self::new(MessageRole::Tool, content);
        m.priority = 3;
        m
    }

    #[must_use] 
    pub const fn with_priority(mut self, p: u8) -> Self {
        self.priority = p;
        self
    }

    #[must_use] 
    pub const fn pinned(mut self) -> Self {
        self.pinned = true;
        self
    }
}

// ── TokenCounter ──────────────────────────────────────────────────────────────

/// Estimates token counts for messages and text.
pub struct TokenCounter {
    /// Characters-per-token ratio (approximate: ~4 chars/token for English).
    chars_per_token: f64,
}

impl TokenCounter {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            chars_per_token: 4.0,
        }
    }

    #[must_use] 
    pub const fn with_ratio(ratio: f64) -> Self {
        Self {
            chars_per_token: ratio.max(0.1),
        }
    }

    /// Estimate the token count for a string.
    #[must_use]
    pub fn count(&self, text: &str) -> u32 {
        let chars = usize_to_f64(text.chars().count());
        f64_to_u32_saturating((chars / self.chars_per_token).ceil()).max(1)
    }

    /// Estimate using the default ratio (4 chars/token).
    #[must_use]
    pub fn estimate_tokens(text: &str) -> u32 {
        Self::new().count(text)
    }

    /// Count tokens in a list of messages.
    #[must_use] 
    pub fn count_messages(&self, messages: &[ContextMessage]) -> u32 {
        messages.iter().map(|m| m.token_count + 4).sum() // +4 for role overhead
    }
}

impl Default for TokenCounter {
    fn default() -> Self {
        Self::new()
    }
}

// ── ContextTrimmer ────────────────────────────────────────────────────────────

/// Trims the context to fit within a token budget.
pub struct ContextTrimmer {
    /// Strategy to use when trimming.
    pub strategy: TrimStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrimStrategy {
    /// Drop oldest non-pinned messages first.
    DropOldest,
    /// Drop lowest-priority non-pinned messages first.
    DropLowestPriority,
    /// Drop tool messages first, then oldest.
    DropToolsFirst,
    /// Alternate: drop from the middle (preserves first/last turns).
    DropMiddle,
}

impl ContextTrimmer {
    #[must_use] 
    pub const fn new(strategy: TrimStrategy) -> Self {
        Self { strategy }
    }

    /// Trim `messages` to fit within `token_budget`, returning the number
    /// of messages removed.
    pub fn trim(&self, messages: &mut Vec<ContextMessage>, token_budget: u32) -> usize {
        let counter = TokenCounter::new();
        let mut removed = 0;

        while counter.count_messages(messages) > token_budget {
            // Always preserve at least one non-pinned message so callers
            // retain context even under impossibly tight budgets. This
            // prevents the trimmer from emptying the buffer when no
            // individual message fits within the budget.
            let unpinned_count = messages.iter().filter(|m| !m.pinned).count();
            if unpinned_count <= 1 {
                break;
            }
            let idx = self.select_victim(messages);
            match idx {
                Some(i) => {
                    messages.remove(i);
                    removed += 1;
                }
                None => break, // all pinned, cannot trim further
            }
        }
        removed
    }

    fn select_victim(&self, messages: &[ContextMessage]) -> Option<usize> {
        match self.strategy {
            TrimStrategy::DropOldest => messages.iter().position(|m| !m.pinned),
            TrimStrategy::DropLowestPriority => messages
                .iter()
                .enumerate()
                .filter(|(_, m)| !m.pinned)
                .min_by_key(|(_, m)| m.priority)
                .map(|(i, _)| i),
            TrimStrategy::DropToolsFirst => messages
                .iter()
                .position(|m| !m.pinned && m.role == MessageRole::Tool)
                .or_else(|| messages.iter().position(|m| !m.pinned)),
            TrimStrategy::DropMiddle => {
                let unpinned: Vec<usize> = messages
                    .iter()
                    .enumerate()
                    .filter(|(_, m)| !m.pinned)
                    .map(|(i, _)| i)
                    .collect();
                if unpinned.is_empty() {
                    None
                } else {
                    Some(unpinned[unpinned.len() / 2])
                }
            }
        }
    }
}

// ── SummaryGenerator ─────────────────────────────────────────────────────────

/// Generates summaries of context segments to reclaim token budget.
pub struct SummaryGenerator {
    pub max_summary_tokens: u32,
}

impl SummaryGenerator {
    #[must_use] 
    pub const fn new(max_summary_tokens: u32) -> Self {
        Self { max_summary_tokens }
    }

    /// Summarize a slice of messages into a single condensed message.
    /// (In a real implementation this would call an LLM; here it is a stub.)
    #[must_use] 
    pub fn summarize(&self, messages: &[ContextMessage]) -> ContextMessage {
        let mut preview = String::with_capacity(160);
        for (i, m) in messages.iter().take(3).enumerate() {
            if i > 0 {
                preview.push_str("; ");
            }
            // Truncate to at most 40 characters (not bytes) to avoid
            // panicking on multibyte UTF-8 codepoints.
            let snippet: String = m.content.chars().take(40).collect();
            let _ = write!(preview, "[{}]: {}...", m.role, snippet);
        }
        let summary_text = format!("[SUMMARY of {} messages]: {}", messages.len(), preview);
        let mut msg = ContextMessage::new(MessageRole::System, summary_text);
        msg.token_count = msg.token_count.min(self.max_summary_tokens);
        msg.priority = 8;
        msg
    }

    /// Replace the oldest `n` non-pinned messages with a summary.
    /// Returns the number of messages replaced (before compression).
    pub fn compress(&self, messages: &mut Vec<ContextMessage>, n: usize) -> usize {
        let indices: Vec<usize> = messages
            .iter()
            .enumerate()
            .filter(|(_, m)| !m.pinned)
            .map(|(i, _)| i)
            .take(n)
            .collect();

        if indices.is_empty() {
            return 0;
        }

        let mut to_summarize: Vec<ContextMessage> = Vec::with_capacity(indices.len());
        for &i in indices.iter().rev() {
            to_summarize.push(messages.remove(i));
        }
        to_summarize.reverse();

        let summary = self.summarize(&to_summarize);
        let first_idx = indices[0];
        messages.insert(first_idx.min(messages.len()), summary);

        to_summarize.len()
    }
}

// ── PriorityRetention ─────────────────────────────────────────────────────────

/// Manages which messages must be retained at all costs.
pub struct PriorityRetention {
    /// Minimum priority to retain (messages below this threshold are candidates for removal).
    pub min_priority: u8,
    /// Always retain the most recent N messages regardless of priority.
    pub keep_last_n: usize,
}

impl PriorityRetention {
    #[must_use] 
    pub const fn new(min_priority: u8, keep_last_n: usize) -> Self {
        Self {
            min_priority,
            keep_last_n,
        }
    }

    /// Mark messages that should be protected from trimming.
    pub fn apply_retention(&self, messages: &mut [ContextMessage]) {
        let len = messages.len();
        for (i, msg) in messages.iter_mut().enumerate() {
            let in_last_n = i >= len.saturating_sub(self.keep_last_n);
            if msg.priority >= self.min_priority || in_last_n {
                msg.pinned = true;
            }
        }
    }

    /// Unpin all messages (to reset retention decisions).
    pub fn clear_retention(messages: &mut [ContextMessage]) {
        for msg in messages.iter_mut() {
            if msg.role != MessageRole::System {
                msg.pinned = false;
            }
        }
    }
}

// ── ContextExport ─────────────────────────────────────────────────────────────

/// Serializable snapshot of the context window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextExport {
    pub messages: Vec<ContextMessage>,
    pub token_count: u32,
    pub token_limit: u32,
    pub schema_version: u32,
}

const CONTEXT_EXPORT_VERSION: u32 = 1;

impl ContextExport {
    /// Serialize this export to a pretty-printed JSON string.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Serialization`] if JSON serialization fails.
    pub fn to_json(&self) -> ContextResult<String> {
        serde_json::to_string_pretty(self).map_err(|e| ContextError::Serialization(e.to_string()))
    }

    /// Deserialize a `ContextExport` from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::Serialization`] if JSON parsing fails.
    pub fn from_json(json: &str) -> ContextResult<Self> {
        serde_json::from_str(json).map_err(|e| ContextError::Serialization(e.to_string()))
    }
}

// ── ContextManager ────────────────────────────────────────────────────────────

/// Manages the LLM context window for a `RustRE` agent.
pub struct ContextManager {
    messages: Mutex<Vec<ContextMessage>>,
    token_limit: u32,
    pub trimmer: ContextTrimmer,
    pub summarizer: SummaryGenerator,
    pub retention: PriorityRetention,
    counter: TokenCounter,
}

impl ContextManager {
    // ── Constructor ───────────────────────────────────────────────────────────

    #[must_use] 
    pub const fn new(token_limit: u32, strategy: TrimStrategy) -> Self {
        Self {
            messages: Mutex::new(Vec::new()),
            token_limit,
            trimmer: ContextTrimmer::new(strategy),
            summarizer: SummaryGenerator::new(512),
            retention: PriorityRetention::new(7, 4),
            counter: TokenCounter::new(),
        }
    }

    #[must_use] 
    pub const fn with_defaults(token_limit: u32) -> Self {
        Self::new(token_limit, TrimStrategy::DropLowestPriority)
    }

    // ── Messages ──────────────────────────────────────────────────────────────

    /// Add a message. If adding it would exceed the limit, trim first.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::WindowFull`] if the single message exceeds the token limit.
    pub fn push(&self, msg: ContextMessage) -> ContextResult<()> {
        if msg.token_count > self.token_limit {
            return Err(ContextError::WindowFull {
                tokens: msg.token_count,
                limit: self.token_limit,
            });
        }
        let mut messages = self.messages.lock();
        messages.push(msg);
        // Trim if needed.
        self.trimmer.trim(&mut messages, self.token_limit);
        drop(messages);
        Ok(())
    }

    /// Add multiple messages, trimming as needed.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::WindowFull`] if any single message exceeds the token limit.
    pub fn extend(&self, msgs: Vec<ContextMessage>) -> ContextResult<()> {
        for msg in msgs {
            self.push(msg)?;
        }
        Ok(())
    }

    /// Get all current messages.
    pub fn messages(&self) -> Vec<ContextMessage> {
        self.messages.lock().clone()
    }

    /// Number of messages.
    pub fn len(&self) -> usize {
        self.messages.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Current total token count.
    pub fn token_count(&self) -> u32 {
        self.counter.count_messages(&self.messages.lock())
    }

    /// Remaining token budget.
    pub fn tokens_remaining(&self) -> u32 {
        self.token_limit.saturating_sub(self.token_count())
    }

    /// Token limit.
    #[must_use]
    pub const fn token_limit(&self) -> u32 {
        self.token_limit
    }

    /// Clear all non-pinned messages.
    pub fn clear_non_pinned(&self) {
        self.messages.lock().retain(|m| m.pinned);
    }

    /// Clear all messages.
    pub fn clear_all(&self) {
        self.messages.lock().clear();
    }

    // ── Trim ─────────────────────────────────────────────────────────────────

    /// Force-trim to fit within a custom budget.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::TrimTarget`] if `target_tokens` is larger than the current token count.
    pub fn trim_to(&self, target_tokens: u32) -> ContextResult<usize> {
        let current = self.token_count();
        if target_tokens > current {
            return Err(ContextError::TrimTarget {
                target: target_tokens,
                current,
            });
        }
        let removed = self.trimmer.trim(&mut self.messages.lock(), target_tokens);
        Ok(removed)
    }

    // ── Compress ─────────────────────────────────────────────────────────────

    /// Compress the oldest `n` messages into a summary.
    pub fn compress_oldest(&self, n: usize) -> usize {
        self.summarizer.compress(&mut self.messages.lock(), n)
    }

    // ── Export / Import ───────────────────────────────────────────────────────

    pub fn export(&self) -> ContextExport {
        ContextExport {
            messages: self.messages(),
            token_count: self.token_count(),
            token_limit: self.token_limit,
            schema_version: CONTEXT_EXPORT_VERSION,
        }
    }

    pub fn import(&self, export: ContextExport) {
        let mut messages = self.messages.lock();
        *messages = export.messages;
    }

    // ── Query ─────────────────────────────────────────────────────────────────

    /// Get messages by role.
    pub fn messages_by_role(&self, role: MessageRole) -> Vec<ContextMessage> {
        self.messages
            .lock()
            .iter()
            .filter(|m| m.role == role)
            .cloned()
            .collect()
    }

    /// Get the last N messages.
    pub fn last_n(&self, n: usize) -> Vec<ContextMessage> {
        let messages = self.messages.lock();
        let start = messages.len().saturating_sub(n);
        messages[start..].to_vec()
    }

    /// Usage ratio (0.0 – 1.0).
    #[must_use]
    pub fn usage_ratio(&self) -> f64 {
        f64::from(self.token_count()) / f64::from(self.token_limit)
    }
}

// Helper trait for Vec<ContextMessage>.
trait AnyPinned {
    fn any<F: Fn(&ContextMessage) -> bool>(&self, f: F) -> bool;
}
impl AnyPinned for Vec<ContextMessage> {
    fn any<F: Fn(&ContextMessage) -> bool>(&self, f: F) -> bool {
        self.iter().any(f)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cm(limit: u32) -> ContextManager {
        ContextManager::with_defaults(limit)
    }

    // ── TokenCounter ──────────────────────────────────────────────────────────

    #[test]
    fn test_token_counter_empty() {
        assert_eq!(TokenCounter::estimate_tokens(""), 1); // min 1
    }

    #[test]
    fn test_token_counter_basic() {
        // 4 chars = ~1 token
        let count = TokenCounter::estimate_tokens("abcd");
        assert_eq!(count, 1);
        let count8 = TokenCounter::estimate_tokens("abcdefgh");
        assert_eq!(count8, 2);
    }

    #[test]
    fn test_token_counter_custom_ratio() {
        let tc = TokenCounter::with_ratio(2.0);
        // 4 chars / 2 = 2 tokens
        assert_eq!(tc.count("abcd"), 2);
    }

    #[test]
    fn test_token_counter_messages_overhead() {
        let tc = TokenCounter::new();
        let msgs = vec![ContextMessage::user("hi")];
        let total = tc.count_messages(&msgs);
        assert!(total >= msgs[0].token_count);
    }

    // ── ContextMessage ────────────────────────────────────────────────────────

    #[test]
    fn test_message_role_display() {
        assert_eq!(MessageRole::User.to_string(), "user");
        assert_eq!(MessageRole::Assistant.to_string(), "assistant");
        assert_eq!(MessageRole::System.to_string(), "system");
        assert_eq!(MessageRole::Tool.to_string(), "tool");
    }

    #[test]
    fn test_system_message_pinned() {
        let m = ContextMessage::system("You are a helpful RE agent.");
        assert!(m.pinned);
        assert_eq!(m.role, MessageRole::System);
    }

    #[test]
    fn test_message_priority_builder() {
        let m = ContextMessage::user("hello").with_priority(9);
        assert_eq!(m.priority, 9);
    }

    #[test]
    fn test_message_pin_builder() {
        let m = ContextMessage::user("must keep").pinned();
        assert!(m.pinned);
    }

    #[test]
    fn test_tool_message_low_priority() {
        let m = ContextMessage::tool("tool output");
        assert!(m.priority <= 5);
    }

    // ── ContextTrimmer ────────────────────────────────────────────────────────

    #[test]
    fn test_trimmer_drop_oldest() {
        let mut msgs = vec![
            ContextMessage::user("first msg with enough text to cost tokens"),
            ContextMessage::user("second msg with enough text to cost tokens"),
            ContextMessage::user("third msg with enough text to cost tokens"),
        ];
        let trimmer = ContextTrimmer::new(TrimStrategy::DropOldest);
        // Set a very tight budget to force removal.
        trimmer.trim(&mut msgs, 1);
        assert!(msgs.len() < 3);
    }

    #[test]
    fn test_trimmer_drop_lowest_priority() {
        let mut msgs = vec![
            ContextMessage::user("important").with_priority(9),
            ContextMessage::user("less important").with_priority(1),
        ];
        let trimmer = ContextTrimmer::new(TrimStrategy::DropLowestPriority);
        trimmer.trim(&mut msgs, 1); // force one removal
        assert_eq!(msgs[0].priority, 9);
    }

    #[test]
    fn test_trimmer_pinned_not_removed() {
        let mut msgs = vec![ContextMessage::system("System prompt").pinned()];
        let trimmer = ContextTrimmer::new(TrimStrategy::DropOldest);
        let removed = trimmer.trim(&mut msgs, 1);
        assert_eq!(removed, 0);
        assert_eq!(msgs.len(), 1);
    }

    #[test]
    fn test_trimmer_drop_tools_first() {
        let mut msgs = vec![
            ContextMessage::user("question").with_priority(8),
            ContextMessage::tool("tool result a"),
            ContextMessage::tool("tool result b"),
        ];
        let trimmer = ContextTrimmer::new(TrimStrategy::DropToolsFirst);
        trimmer.trim(&mut msgs, 1);
        // Tool messages should be removed preferentially.
        let remaining_tools = msgs.iter().filter(|m| m.role == MessageRole::Tool).count();
        let initial_tools = 2usize;
        assert!(remaining_tools < initial_tools);
    }

    // ── SummaryGenerator ─────────────────────────────────────────────────────

    #[test]
    fn test_summarizer_produces_system_message() {
        let sg = SummaryGenerator::new(512);
        let msgs = vec![
            ContextMessage::user("What is AES?"),
            ContextMessage::assistant("AES is a block cipher…"),
        ];
        let summary = sg.summarize(&msgs);
        assert_eq!(summary.role, MessageRole::System);
        assert!(summary.content.contains("SUMMARY"));
    }

    #[test]
    fn test_summarizer_compress_reduces_count() {
        let sg = SummaryGenerator::new(512);
        let mut msgs = vec![
            ContextMessage::user("msg1 msg1 msg1"),
            ContextMessage::user("msg2 msg2 msg2"),
            ContextMessage::user("msg3 msg3 msg3"),
        ];
        let removed = sg.compress(&mut msgs, 2);
        assert_eq!(removed, 2);
        // 3 messages - 2 + 1 summary = 2
        assert_eq!(msgs.len(), 2);
    }

    #[test]
    fn test_summarizer_compress_skips_pinned() {
        let sg = SummaryGenerator::new(512);
        let mut msgs = vec![
            ContextMessage::system("System").pinned(),
            ContextMessage::user("hello"),
        ];
        let removed = sg.compress(&mut msgs, 2);
        // System is pinned, so only 1 non-pinned is compressible.
        assert!(removed <= 1);
    }

    // ── PriorityRetention ─────────────────────────────────────────────────────

    #[test]
    fn test_retention_pins_high_priority() {
        let retention = PriorityRetention::new(8, 0);
        let mut msgs = vec![
            ContextMessage::user("low").with_priority(3),
            ContextMessage::user("high").with_priority(9),
        ];
        retention.apply_retention(&mut msgs);
        assert!(!msgs[0].pinned);
        assert!(msgs[1].pinned);
    }

    #[test]
    fn test_retention_keep_last_n() {
        let retention = PriorityRetention::new(10, 2);
        let mut msgs = vec![
            ContextMessage::user("a").with_priority(1),
            ContextMessage::user("b").with_priority(1),
            ContextMessage::user("c").with_priority(1),
        ];
        retention.apply_retention(&mut msgs);
        // Last 2 (indices 1, 2) should be pinned.
        assert!(!msgs[0].pinned);
        assert!(msgs[1].pinned);
        assert!(msgs[2].pinned);
    }

    #[test]
    fn test_retention_clear() {
        let mut msgs = vec![
            ContextMessage::user("x").pinned(),
            ContextMessage::user("y").pinned(),
        ];
        PriorityRetention::clear_retention(&mut msgs);
        assert!(!msgs.any(|m| m.pinned));
    }

    // ── ContextManager ────────────────────────────────────────────────────────

    #[test]
    fn test_context_manager_push_ok() {
        let cm = cm(4096);
        cm.push(ContextMessage::user("hello")).unwrap();
        assert_eq!(cm.len(), 1);
    }

    #[test]
    fn test_context_manager_token_count() {
        let cm = cm(4096);
        cm.push(ContextMessage::user("hello")).unwrap();
        assert!(cm.token_count() > 0);
    }

    #[test]
    fn test_context_manager_too_large_single_message() {
        let cm = cm(5);
        // A message with 100 chars will need ~25 tokens > 5 limit.
        let big_msg = ContextMessage::user("a".repeat(100));
        let res = cm.push(big_msg);
        assert!(matches!(res, Err(ContextError::WindowFull { .. })));
    }

    #[test]
    fn test_context_manager_auto_trim() {
        let cm = cm(30);
        for i in 0..20 {
            let _ = cm.push(ContextMessage::user(format!("msg number {i}")));
        }
        // Should stay within budget.
        assert!(cm.token_count() <= 30);
    }

    #[test]
    fn test_context_manager_clear_non_pinned() {
        let cm = cm(4096);
        cm.push(ContextMessage::system("sys")).unwrap();
        cm.push(ContextMessage::user("user msg")).unwrap();
        cm.clear_non_pinned();
        assert_eq!(cm.len(), 1);
        assert_eq!(cm.messages()[0].role, MessageRole::System);
    }

    #[test]
    fn test_context_manager_clear_all() {
        let cm = cm(4096);
        cm.push(ContextMessage::system("sys")).unwrap();
        cm.clear_all();
        assert!(cm.is_empty());
    }

    #[test]
    fn test_context_manager_messages_by_role() {
        let cm = cm(4096);
        cm.push(ContextMessage::user("u1")).unwrap();
        cm.push(ContextMessage::assistant("a1")).unwrap();
        cm.push(ContextMessage::user("u2")).unwrap();
        assert_eq!(cm.messages_by_role(MessageRole::User).len(), 2);
        assert_eq!(cm.messages_by_role(MessageRole::Assistant).len(), 1);
    }

    #[test]
    fn test_context_manager_last_n() {
        let cm = cm(4096);
        for i in 0..5 {
            cm.push(ContextMessage::user(format!("msg {i}"))).unwrap();
        }
        let last2 = cm.last_n(2);
        assert_eq!(last2.len(), 2);
        assert!(last2[1].content.contains('4'));
    }

    #[test]
    fn test_context_manager_tokens_remaining() {
        let cm = cm(1000);
        cm.push(ContextMessage::user("hi")).unwrap();
        assert!(cm.tokens_remaining() < 1000);
        assert!(cm.tokens_remaining() > 0);
    }

    // ── Export / Import ───────────────────────────────────────────────────────

    #[test]
    fn test_context_export_round_trip() {
        let cm = cm(4096);
        cm.push(ContextMessage::user("exported msg")).unwrap();
        let export = cm.export();
        let json = export.to_json().unwrap();
        let back = ContextExport::from_json(&json).unwrap();
        assert_eq!(back.messages.len(), 1);
        assert_eq!(back.schema_version, CONTEXT_EXPORT_VERSION);
    }

    #[test]
    fn test_context_import() {
        let cm1 = cm(4096);
        cm1.push(ContextMessage::user("hello")).unwrap();
        let export = cm1.export();

        let cm2 = cm(4096);
        cm2.import(export);
        assert_eq!(cm2.len(), 1);
    }

    // ── usage_ratio ───────────────────────────────────────────────────────────

    #[test]
    fn test_usage_ratio_empty() {
        let cm = cm(1000);
        assert_eq!(cm.usage_ratio(), 0.0);
    }

    #[test]
    fn test_usage_ratio_partial() {
        let cm = cm(1000);
        cm.push(ContextMessage::user("hello")).unwrap();
        let ratio = cm.usage_ratio();
        assert!(ratio > 0.0 && ratio < 1.0);
    }

    #[test]
    fn test_context_manager_token_limit() {
        let cm = cm(512);
        assert_eq!(cm.token_limit(), 512);
    }

    #[test]
    fn test_context_extend_multiple() {
        let cm = cm(4096);
        let msgs = vec![
            ContextMessage::user("msg1"),
            ContextMessage::assistant("resp1"),
        ];
        cm.extend(msgs).unwrap();
        assert_eq!(cm.len(), 2);
    }

    #[test]
    fn test_trim_to_error_if_larger() {
        let cm = cm(4096);
        let err = cm.trim_to(9999);
        assert!(matches!(err, Err(ContextError::TrimTarget { .. })));
    }

    #[test]
    fn test_trim_to_reduces() {
        let cm = cm(4096);
        for i in 0..10 {
            cm.push(ContextMessage::user(format!("message number {i}")))
                .unwrap();
        }
        let before = cm.token_count();
        if before > 10 {
            let removed = cm.trim_to(10).unwrap();
            assert!(removed > 0 || cm.token_count() <= 10);
        }
    }

    #[test]
    fn test_compress_oldest_reduces_messages() {
        let cm = cm(4096);
        for i in 0..6 {
            cm.push(ContextMessage::user(format!("message {i}")))
                .unwrap();
        }
        let before = cm.len();
        let removed = cm.compress_oldest(3);
        assert!(removed > 0);
        assert!(cm.len() < before + 1); // net decrease (removed 3, added 1 summary)
    }

    #[test]
    fn test_trim_strategy_drop_middle() {
        let mut msgs = vec![
            ContextMessage::user("first long message that has tokens"),
            ContextMessage::user("middle long message that has tokens"),
            ContextMessage::user("last long message that has tokens"),
        ];
        let trimmer = ContextTrimmer::new(TrimStrategy::DropMiddle);
        trimmer.trim(&mut msgs, 1);
        assert!(msgs.len() < 3);
    }

    #[test]
    fn test_message_metadata() {
        let mut m = ContextMessage::new(MessageRole::User, "test");
        m.metadata.insert("key".into(), "value".into());
        assert_eq!(m.metadata["key"], "value");
    }

    #[test]
    fn test_summary_generator_max_tokens() {
        let sg = SummaryGenerator::new(10);
        let msgs = vec![ContextMessage::user(
            "lots of text here for summarizing test",
        )];
        let summary = sg.summarize(&msgs);
        assert!(summary.token_count <= 10 + 5); // allow small overhead
    }

    #[test]
    fn test_context_export_schema_version() {
        let cm = cm(4096);
        let export = cm.export();
        assert_eq!(export.schema_version, CONTEXT_EXPORT_VERSION);
    }

    #[test]
    fn test_context_export_token_limit() {
        let cm = cm(2000);
        let export = cm.export();
        assert_eq!(export.token_limit, 2000);
    }

    #[test]
    fn test_priority_retention_clear_leaves_system_pinned() {
        let mut msgs = vec![
            ContextMessage::system("sys").pinned(),
            ContextMessage::user("u").pinned(),
        ];
        PriorityRetention::clear_retention(&mut msgs);
        assert!(msgs[0].pinned); // system stays pinned
        assert!(!msgs[1].pinned); // user unpinned
    }

    #[test]
    fn test_token_counter_instance() {
        let tc = TokenCounter::new();
        assert!(tc.count("hello world") > 0);
    }

    #[test]
    fn test_context_message_token_count_set() {
        let m = ContextMessage::user("hello world this is a test message");
        assert!(m.token_count > 0);
    }

    #[test]
    fn test_context_manager_extend_empty() {
        let cm = cm(4096);
        cm.extend(vec![]).unwrap();
        assert!(cm.is_empty());
    }
}
