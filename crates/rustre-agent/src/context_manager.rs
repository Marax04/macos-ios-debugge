//! Context window management: `ContextManager`, token-limit trimming,
//! history summarization, and priority-based message retention.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{AgentMessage, MessageRole};

// ─── TokenEstimator ───────────────────────────────────────────────────────────

/// Estimates token counts for messages using a simple heuristic.
pub struct TokenEstimator {
    /// Average characters per token (GPT-style ≈ 4).
    chars_per_token: f64,
    /// Overhead tokens per message (role + separators).
    message_overhead: u32,
}

impl TokenEstimator {
    /// Create a default estimator (GPT-style).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            chars_per_token: 4.0,
            message_overhead: 4,
        }
    }

    /// Create a Claude-style estimator (slightly different ratios).
    #[must_use]
    pub const fn claude() -> Self {
        Self {
            chars_per_token: 3.8,
            message_overhead: 3,
        }
    }

    /// Estimate the number of tokens in a single string.
    #[must_use]
    pub fn estimate_str(&self, s: &str) -> u32 {
        crate::casts::f64_to_u32((crate::casts::usize_to_f64(s.len()) / self.chars_per_token).ceil())
    }

    /// Estimate the number of tokens in a message.
    #[must_use]
    pub fn estimate_message(&self, msg: &AgentMessage) -> u32 {
        self.estimate_str(&msg.content) + self.message_overhead
    }

    /// Estimate the total tokens in a slice of messages.
    #[must_use]
    pub fn estimate_messages(&self, messages: &[AgentMessage]) -> u32 {
        messages.iter().map(|m| self.estimate_message(m)).sum()
    }
}

impl Default for TokenEstimator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── MessagePriority ─────────────────────────────────────────────────────────

/// Priority for retaining a message when trimming the context window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MessagePriority {
    /// Always keep (e.g. system prompt, initial task).
    Critical = 3,
    /// Keep if possible (e.g. tool results with important data).
    High = 2,
    /// Keep normally (e.g. regular assistant messages).
    Normal = 1,
    /// Drop first if needed (e.g. verbose intermediate thoughts).
    Low = 0,
}

impl MessagePriority {
    /// Infer priority from a message's role and content.
    #[must_use]
    pub fn from_message(msg: &AgentMessage) -> Self {
        match msg.role {
            MessageRole::System => Self::Critical,
            MessageRole::User => {
                // First user message (task) is critical; others are normal.
                if msg.content.len() > 50 {
                    Self::High
                } else {
                    Self::Normal
                }
            }
            MessageRole::Tool => Self::High,
            MessageRole::Assistant => {
                // Verbose thinking messages are lower priority.
                if msg.content.contains("FINAL_ANSWER") {
                    Self::Critical
                } else if msg.content.starts_with("I'll") || msg.content.starts_with("Let me") {
                    Self::Low
                } else {
                    Self::Normal
                }
            }
        }
    }
}

// ─── SummarizationConfig ──────────────────────────────────────────────────────

/// Configuration for the history summarization step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummarizationConfig {
    /// How many of the most recent messages to preserve verbatim.
    pub recent_messages_to_keep: usize,
    /// Whether to include tool-call results in the summary.
    pub include_tool_results: bool,
    /// Maximum characters in the generated summary.
    pub max_summary_chars: usize,
}

impl Default for SummarizationConfig {
    fn default() -> Self {
        Self {
            recent_messages_to_keep: 4,
            include_tool_results: true,
            max_summary_chars: 2048,
        }
    }
}

// ─── ContextWindow ────────────────────────────────────────────────────────────

/// Current state of the context window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextWindow {
    /// Messages currently in the window.
    pub messages: Vec<AgentMessage>,
    /// Estimated token count.
    pub estimated_tokens: u32,
    /// Token limit for this window.
    pub token_limit: u32,
    /// Whether the window has been trimmed in this session.
    pub was_trimmed: bool,
    /// Number of messages dropped since the last trim.
    pub messages_dropped: u32,
}

impl ContextWindow {
    #[must_use]
    pub const fn new(token_limit: u32) -> Self {
        Self {
            messages: Vec::new(),
            estimated_tokens: 0,
            token_limit,
            was_trimmed: false,
            messages_dropped: 0,
        }
    }

    /// Returns `true` if the window is above 90% capacity.
    #[must_use]
    pub fn is_near_limit(&self) -> bool {
        self.estimated_tokens >= crate::casts::f64_to_u32(f64::from(self.token_limit) * 0.9)
    }

    /// Returns the remaining token budget.
    #[must_use]
    pub const fn remaining_tokens(&self) -> u32 {
        self.token_limit.saturating_sub(self.estimated_tokens)
    }

    /// Utilization fraction (0.0 – 1.0).
    #[must_use]
    pub fn utilization(&self) -> f64 {
        if self.token_limit == 0 {
            return 1.0;
        }
        f64::from(self.estimated_tokens) / f64::from(self.token_limit)
    }
}

// ─── ContextManager ──────────────────────────────────────────────────────────

/// Manages the agent's context window: appending messages, trimming when full,
/// and summarizing older history to reclaim space.
pub struct ContextManager {
    token_limit: u32,
    estimator: TokenEstimator,
    summarization_config: SummarizationConfig,
    /// Priority overrides for specific message indices.
    priority_overrides: HashMap<usize, MessagePriority>,
    /// Accumulated summary of dropped history.
    history_summary: String,
}

impl ContextManager {
    /// Create a new manager with the given token limit.
    #[must_use]
    pub fn new(token_limit: u32) -> Self {
        Self {
            token_limit,
            estimator: TokenEstimator::new(),
            summarization_config: SummarizationConfig::default(),
            priority_overrides: HashMap::new(),
            history_summary: String::new(),
        }
    }

    /// Create a manager with a custom token estimator.
    #[must_use]
    pub const fn with_estimator(mut self, estimator: TokenEstimator) -> Self {
        self.estimator = estimator;
        self
    }

    /// Override the summarization config.
    #[must_use]
    pub const fn with_summarization(mut self, config: SummarizationConfig) -> Self {
        self.summarization_config = config;
        self
    }

    /// Set a priority override for a specific message index.
    pub fn set_priority(&mut self, idx: usize, priority: MessagePriority) {
        self.priority_overrides.insert(idx, priority);
    }

    // ── Core API ─────────────────────────────────────────────────────────────

    /// Build a `ContextWindow` from the given message history, trimming if needed.
    ///
    /// Returns the trimmed window and the number of messages that were dropped.
    #[must_use]
    pub fn build_window(&self, messages: &[AgentMessage]) -> ContextWindow {
        let total = self.estimator.estimate_messages(messages);
        let mut window = ContextWindow::new(self.token_limit);
        window.estimated_tokens = total;

        if total <= self.token_limit {
            window.messages = messages.to_vec();
            return window;
        }

        // Need to trim.
        let trimmed = self.trim_to_token_limit(messages);
        window.messages_dropped = crate::casts::usize_to_u32(messages.len() - trimmed.len());
        window.estimated_tokens = self.estimator.estimate_messages(&trimmed);
        window.was_trimmed = true;
        window.messages = trimmed;
        window
    }

    /// Trim a message slice to fit within the token limit using priority-based eviction.
    ///
    /// The algorithm:
    /// 1. Keep all `Critical` messages.
    /// 2. Keep the N most recent messages regardless of priority.
    /// 3. Fill remaining budget greedily by priority (High → Normal → Low).
    #[must_use]
    pub fn trim_to_token_limit(&self, messages: &[AgentMessage]) -> Vec<AgentMessage> {
        if messages.is_empty() {
            return Vec::new();
        }

        let keep_recent = self.summarization_config.recent_messages_to_keep;

        // Partition into "always keep" (critical + recent) and "candidates".
        let mut always_keep: Vec<(usize, &AgentMessage)> = Vec::new();
        let mut candidates: Vec<(usize, &AgentMessage, MessagePriority)> = Vec::new();

        for (i, msg) in messages.iter().enumerate() {
            let prio = self
                .priority_overrides
                .get(&i)
                .copied()
                .unwrap_or_else(|| MessagePriority::from_message(msg));

            let is_recent = i >= messages.len().saturating_sub(keep_recent);

            if prio == MessagePriority::Critical || is_recent {
                always_keep.push((i, msg));
            } else {
                candidates.push((i, msg, prio));
            }
        }

        // Calculate budget consumed by always-keep set.
        let mut always_tokens: u32 = always_keep
            .iter()
            .map(|(_, m)| self.estimator.estimate_message(m))
            .sum();

        // If the always-keep set itself exceeds the token limit, evict the
        // oldest entries (lowest index) until it fits. Critical messages and
        // the most-recent message are preserved last.
        while always_tokens > self.token_limit && always_keep.len() > 1 {
            // Find oldest non-critical, non-last entry to drop.
            let last_idx = always_keep.last().map_or(usize::MAX, |(i, _)| *i);
            let drop_pos = always_keep.iter().position(|(i, m)| {
                let prio = self
                    .priority_overrides
                    .get(i)
                    .copied()
                    .unwrap_or_else(|| MessagePriority::from_message(m));
                prio != MessagePriority::Critical && *i != last_idx
            });
            match drop_pos {
                Some(p) => {
                    let (_, m) = always_keep.remove(p);
                    always_tokens = always_tokens
                        .saturating_sub(self.estimator.estimate_message(m));
                }
                None => break,
            }
        }

        let mut remaining_budget = self.token_limit.saturating_sub(always_tokens);

        // Sort candidates by priority (high first), then by recency (newest first).
        let mut sorted_candidates = candidates;
        sorted_candidates.sort_by(|a, b| b.2.cmp(&a.2).then(b.0.cmp(&a.0)));

        let mut selected_indices: std::collections::HashSet<usize> =
            always_keep.iter().map(|(i, _)| *i).collect();

        for (i, msg, _) in &sorted_candidates {
            let tokens = self.estimator.estimate_message(msg);
            if tokens <= remaining_budget {
                selected_indices.insert(*i);
                remaining_budget -= tokens;
            }
        }

        // Reconstruct in original order.
        messages
            .iter()
            .enumerate()
            .filter(|(i, _)| selected_indices.contains(i))
            .map(|(_, m)| m.clone())
            .collect()
    }

    /// Produce a textual summary of the messages that would be dropped.
    ///
    /// The summary is appended to `self.history_summary`.
    pub fn summarize_history(&mut self, dropped: &[AgentMessage]) -> String {
        use std::fmt::Write as _;
        if dropped.is_empty() {
            return String::new();
        }

        let mut summary = String::new();
        let _ = writeln!(summary, "[Summary of {} earlier messages]", dropped.len());

        let mut tool_calls: Vec<&str> = Vec::new();
        let mut assistant_points: Vec<&str> = Vec::new();

        for msg in dropped {
            match msg.role {
                MessageRole::Tool => {
                    if self.summarization_config.include_tool_results {
                        tool_calls.push(&msg.content);
                    }
                }
                MessageRole::Assistant => {
                    assistant_points.push(&msg.content);
                }
                _ => {}
            }
        }

        if !tool_calls.is_empty() {
            summary.push_str("Tool results:\n");
            for tc in tool_calls.iter().take(5) {
                let excerpt = &tc[..tc.len().min(120)];
                let _ = writeln!(summary, "  - {excerpt}");
            }
        }
        if !assistant_points.is_empty() {
            summary.push_str("Assistant observations:\n");
            for ap in assistant_points.iter().take(3) {
                let excerpt = &ap[..ap.len().min(200)];
                let _ = writeln!(summary, "  - {excerpt}");
            }
        }

        // Truncate to max summary chars.
        if summary.len() > self.summarization_config.max_summary_chars {
            summary.truncate(self.summarization_config.max_summary_chars);
            summary.push_str("...[truncated]");
        }

        self.history_summary.push_str(&summary);
        summary
    }

    /// Return the accumulated history summary.
    #[must_use]
    pub fn history_summary(&self) -> &str {
        &self.history_summary
    }

    /// Clear the accumulated history summary.
    pub fn clear_summary(&mut self) {
        self.history_summary.clear();
    }

    /// Estimate tokens for a single string without building a window.
    #[must_use]
    pub fn estimate_tokens(&self, s: &str) -> u32 {
        self.estimator.estimate_str(s)
    }

    /// Estimate tokens for a message slice.
    #[must_use]
    pub fn estimate_message_tokens(&self, messages: &[AgentMessage]) -> u32 {
        self.estimator.estimate_messages(messages)
    }

    /// The configured token limit.
    #[must_use]
    pub const fn token_limit(&self) -> u32 {
        self.token_limit
    }

    /// Update the token limit (e.g. after model switch).
    pub const fn set_token_limit(&mut self, limit: u32) {
        self.token_limit = limit;
    }

    /// Perform a full context-window compaction: trim + summarize dropped messages.
    ///
    /// Returns `(compacted_messages, summary_of_dropped)`.
    pub fn compact(&mut self, messages: &[AgentMessage]) -> (Vec<AgentMessage>, String) {
        let total = self.estimator.estimate_messages(messages);
        if total <= self.token_limit {
            return (messages.to_vec(), String::new());
        }

        let kept = self.trim_to_token_limit(messages);
        // parser-ambiguity / dangling-reference guard: raw content pointer
        // comparison is unreliable — two distinct AgentMessage values can have
        // the same heap address after one is dropped, and String clones always
        // allocate a new buffer.  Use index-based set membership instead.
        let kept_set: std::collections::HashSet<usize> = {
            // Build the same index set that trim_to_token_limit would select.
            // We re-derive it by matching content equality with original order.
            let mut indices = std::collections::HashSet::new();
            let mut remaining: Vec<(usize, &AgentMessage)> = messages
                .iter()
                .enumerate()
                .collect();
            'outer: for k in &kept {
                for i in 0..remaining.len() {
                    if remaining[i].1.content == k.content
                        && remaining[i].1.role == k.role
                        && remaining[i].1.timestamp == k.timestamp
                    {
                        indices.insert(remaining[i].0);
                        remaining.remove(i);
                        continue 'outer;
                    }
                }
            }
            indices
        };

        let dropped: Vec<&AgentMessage> = messages
            .iter()
            .enumerate()
            .filter(|(i, _)| !kept_set.contains(i))
            .map(|(_, m)| m)
            .collect();

        let owned_dropped: Vec<AgentMessage> = dropped.iter().map(|m| (*m).clone()).collect();
        let summary = self.summarize_history(&owned_dropped);
        (kept, summary)
    }

    /// Insert a synthetic "summary" message into a message list, representing
    /// compacted history.
    #[must_use]
    pub fn inject_summary_message(
        messages: &[AgentMessage],
        summary: &str,
    ) -> Vec<AgentMessage> {
        let mut result = Vec::with_capacity(messages.len() + 1);
        // Keep system messages at the front.
        result.extend(
            messages
                .iter()
                .filter(|m| m.role == MessageRole::System)
                .cloned(),
        );
        if !summary.is_empty() {
            result.push(AgentMessage::new(
                MessageRole::System,
                format!("[CONTEXT SUMMARY]\n{summary}"),
            ));
        }
        result.extend(
            messages
                .iter()
                .filter(|m| m.role != MessageRole::System)
                .cloned(),
        );
        result
    }

    /// Partition messages into priority buckets.
    #[must_use]
    pub fn partition_by_priority(
        &self,
        messages: &[AgentMessage],
    ) -> HashMap<String, Vec<AgentMessage>> {
        let mut map: HashMap<String, Vec<AgentMessage>> = HashMap::new();
        for (i, msg) in messages.iter().enumerate() {
            let prio = self
                .priority_overrides
                .get(&i)
                .copied()
                .unwrap_or_else(|| MessagePriority::from_message(msg));
            let key = format!("{prio:?}").to_ascii_lowercase();
            map.entry(key).or_default().push(msg.clone());
        }
        map
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sys_msg(content: &str) -> AgentMessage {
        AgentMessage::new(MessageRole::System, content)
    }

    fn user_msg(content: &str) -> AgentMessage {
        AgentMessage::new(MessageRole::User, content)
    }

    fn asst_msg(content: &str) -> AgentMessage {
        AgentMessage::new(MessageRole::Assistant, content)
    }

    fn tool_msg(content: &str) -> AgentMessage {
        AgentMessage::new(MessageRole::Tool, content)
    }

    // ── TokenEstimator ───────────────────────────────────────────────────────

    #[test]
    fn test_estimator_str() {
        let est = TokenEstimator::new();
        // 40 chars / 4 = 10 tokens (ceil)
        assert_eq!(est.estimate_str(&"a".repeat(40)), 10);
    }

    #[test]
    fn test_estimator_message_overhead() {
        let est = TokenEstimator::new();
        let msg = user_msg("hi"); // 2 chars → 1 token + 4 overhead = 5
        assert_eq!(est.estimate_message(&msg), 5);
    }

    #[test]
    fn test_estimator_multiple_messages() {
        let est = TokenEstimator::new();
        let msgs = vec![sys_msg("system"), user_msg("task")];
        let total = est.estimate_messages(&msgs);
        assert!(total > 0);
    }

    // ── MessagePriority ─────────────────────────────────────────────────────

    #[test]
    fn test_priority_system() {
        let msg = sys_msg("you are an agent");
        assert_eq!(MessagePriority::from_message(&msg), MessagePriority::Critical);
    }

    #[test]
    fn test_priority_tool() {
        let msg = tool_msg("[tool:result]");
        assert_eq!(MessagePriority::from_message(&msg), MessagePriority::High);
    }

    #[test]
    fn test_priority_final_answer() {
        let msg = asst_msg("FINAL_ANSWER: done");
        assert_eq!(MessagePriority::from_message(&msg), MessagePriority::Critical);
    }

    #[test]
    fn test_priority_thinking() {
        let msg = asst_msg("I'll now analyze the function.");
        assert_eq!(MessagePriority::from_message(&msg), MessagePriority::Low);
    }

    // ── ContextWindow ────────────────────────────────────────────────────────

    #[test]
    fn test_context_window_near_limit() {
        let mut w = ContextWindow::new(100);
        w.estimated_tokens = 91;
        assert!(w.is_near_limit());
    }

    #[test]
    fn test_context_window_remaining() {
        let mut w = ContextWindow::new(1000);
        w.estimated_tokens = 400;
        assert_eq!(w.remaining_tokens(), 600);
    }

    #[test]
    fn test_context_window_utilization() {
        let mut w = ContextWindow::new(200);
        w.estimated_tokens = 100;
        assert!((w.utilization() - 0.5).abs() < 1e-9);
    }

    // ── ContextManager ───────────────────────────────────────────────────────

    #[test]
    fn test_build_window_fits() {
        let mgr = ContextManager::new(10_000);
        let msgs = vec![sys_msg("system"), user_msg("hello")];
        let window = mgr.build_window(&msgs);
        assert!(!window.was_trimmed);
        assert_eq!(window.messages.len(), 2);
    }

    #[test]
    fn test_build_window_needs_trim() {
        // Very tight limit — 50 tokens.
        let mgr = ContextManager::new(50);
        let msgs: Vec<AgentMessage> = (0..20)
            .map(|i| asst_msg(&format!("Thinking about step {i} in detail...")))
            .collect();
        let window = mgr.build_window(&msgs);
        assert!(window.was_trimmed);
        assert!(window.messages.len() < 20);
        assert!(window.estimated_tokens <= 50);
    }

    #[test]
    fn test_trim_keeps_system_and_recent() {
        let mgr = ContextManager::new(200);
        let mut msgs = vec![sys_msg("You are an agent.")];
        for i in 0..15 {
            msgs.push(asst_msg(&format!("Thought {i}")));
        }
        let trimmed = mgr.trim_to_token_limit(&msgs);
        // System message must be retained.
        assert!(trimmed
            .iter()
            .any(|m| m.role == MessageRole::System));
        // Most recent messages must be retained.
        let last_content = &msgs.last().unwrap().content;
        assert!(trimmed.iter().any(|m| &m.content == last_content));
    }

    #[test]
    fn test_summarize_history() {
        let mut mgr = ContextManager::new(10_000);
        let dropped = vec![
            tool_msg("[tool:search] {\"count\": 3}"),
            asst_msg("I'll look at the results."),
        ];
        let summary = mgr.summarize_history(&dropped);
        assert!(!summary.is_empty());
        assert!(mgr.history_summary().contains("Summary"));
    }

    #[test]
    fn test_clear_summary() {
        let mut mgr = ContextManager::new(10_000);
        let _ = mgr.summarize_history(&[asst_msg("old thought")]);
        assert!(!mgr.history_summary().is_empty());
        mgr.clear_summary();
        assert!(mgr.history_summary().is_empty());
    }

    #[test]
    fn test_inject_summary_message() {
        let msgs = vec![
            sys_msg("system"),
            user_msg("task"),
            asst_msg("thinking"),
        ];
        let result = ContextManager::inject_summary_message(&msgs, "Earlier: found 3 functions.");
        // System messages come first.
        assert_eq!(result[0].role, MessageRole::System);
        // Summary message is injected after system messages.
        let has_summary = result.iter().any(|m| m.content.contains("CONTEXT SUMMARY"));
        assert!(has_summary);
    }

    #[test]
    fn test_inject_summary_empty_skips() {
        let msgs = vec![user_msg("hello")];
        let result = ContextManager::inject_summary_message(&msgs, "");
        // No extra message added.
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_estimate_tokens() {
        let mgr = ContextManager::new(10_000);
        assert_eq!(mgr.estimate_tokens("hello world"), 3); // 11 chars / 4 = 2.75 → ceil = 3
    }

    #[test]
    fn test_set_token_limit() {
        let mut mgr = ContextManager::new(1000);
        assert_eq!(mgr.token_limit(), 1000);
        mgr.set_token_limit(4096);
        assert_eq!(mgr.token_limit(), 4096);
    }

    #[test]
    fn test_priority_override() {
        let mut mgr = ContextManager::new(100);
        // Force index 0 (which would normally be critical) to Low.
        mgr.set_priority(0, MessagePriority::Low);
        let msgs = vec![
            sys_msg("system"), // overridden to Low
            user_msg("task"),
        ];
        // Just ensure no panic.
        let window = mgr.build_window(&msgs);
        assert!(window.messages.len() <= 2);
    }

    #[test]
    fn test_partition_by_priority() {
        let mgr = ContextManager::new(10_000);
        let msgs = vec![
            sys_msg("system"),
            user_msg("hi"),
            tool_msg("[result]"),
        ];
        let partitions = mgr.partition_by_priority(&msgs);
        assert!(!partitions.is_empty());
    }

    #[test]
    fn test_compact_no_overflow() {
        let mut mgr = ContextManager::new(10_000);
        let msgs = vec![user_msg("hello"), asst_msg("hi there")];
        let (kept, summary) = mgr.compact(&msgs);
        assert_eq!(kept.len(), 2);
        assert!(summary.is_empty());
    }
}
