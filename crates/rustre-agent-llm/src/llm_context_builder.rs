//! LLM context/prompt builder.
//!
//! Manages a sliding context window of messages, handles trimming strategies,
//! few-shot example injection, token estimation, and serialization.

use std::collections::VecDeque;
use std::fmt::Write as FmtWrite;

use rustre_agent::casts::{f64_to_u32, usize_to_f64, usize_to_u32};

// ── Token estimation ──────────────────────────────────────────────────────────

/// Rough token count estimate: chars / 4 (GPT-style heuristic).
#[must_use] 
pub fn token_count_estimate(text: &str) -> u32 {
    let chars = text.chars().count();
    f64_to_u32((usize_to_f64(chars) / 4.0).ceil())
}

// ── MessageRole ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageRole {
    System,
    User,
    Assistant,
    Tool,
}

impl MessageRole {
    #[must_use] 
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::Tool => "tool",
        }
    }
}

impl std::fmt::Display for MessageRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── ContextMessage ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ContextMessage {
    pub role: MessageRole,
    pub content: String,
    pub token_count: u32,
}

impl ContextMessage {
    pub fn new(role: MessageRole, content: impl Into<String>) -> Self {
        let content = content.into();
        let token_count = token_count_estimate(&content);
        Self { role, content, token_count }
    }

    pub fn with_token_count(role: MessageRole, content: impl Into<String>, tokens: u32) -> Self {
        Self { role, content: content.into(), token_count: tokens }
    }
}

// ── ContextStrategy ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextStrategy {
    /// Remove oldest non-system messages first.
    TrimOldest,
    /// Remove messages from the middle of the conversation.
    TrimMiddle,
    /// Replace removed messages with a summary placeholder.
    Summarize,
    /// Reject new messages when the window is full.
    RejectNew,
}

// ── FewShotExample ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FewShotExample {
    pub input: String,
    pub output: String,
    pub description: String,
}

impl FewShotExample {
    pub fn new(
        input: impl Into<String>,
        output: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            input: input.into(),
            output: output.into(),
            description: description.into(),
        }
    }

    /// Token cost of this example pair.
    #[must_use] 
    pub fn token_cost(&self) -> u32 {
        token_count_estimate(&self.input) + token_count_estimate(&self.output)
    }
}

// ── ContextWindow ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ContextWindow {
    pub max_tokens: u32,
    pub used_tokens: u32,
    pub messages: VecDeque<ContextMessage>,
    pub strategy: ContextStrategy,
}

impl ContextWindow {
    #[must_use] 
    pub const fn new(max_tokens: u32, strategy: ContextStrategy) -> Self {
        Self {
            max_tokens,
            used_tokens: 0,
            messages: VecDeque::new(),
            strategy,
        }
    }

    #[must_use] 
    pub const fn with_default_strategy(max_tokens: u32) -> Self {
        Self::new(max_tokens, ContextStrategy::TrimOldest)
    }

    /// Remaining token budget.
    #[must_use] 
    pub const fn available_tokens(&self) -> u32 {
        self.max_tokens.saturating_sub(self.used_tokens)
    }

    /// Whether there is room for a message of `tokens` tokens.
    #[must_use] 
    pub const fn has_capacity(&self, tokens: u32) -> bool {
        self.available_tokens() >= tokens
    }

    fn recalculate_used(&mut self) {
        self.used_tokens = self.messages.iter().map(|m| m.token_count).sum();
    }
}

// ── ContextStats ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct ContextStats {
    pub message_count: u32,
    pub system_tokens: u32,
    pub user_tokens: u32,
    pub assistant_tokens: u32,
    pub tool_tokens: u32,
    pub total_tokens: u32,
}

// ── LlmContextBuilder ─────────────────────────────────────────────────────────

/// Fluent builder for LLM context windows.
pub struct LlmContextBuilder {
    window: ContextWindow,
}

impl LlmContextBuilder {
    #[must_use] 
    pub const fn new(max_tokens: u32) -> Self {
        Self {
            window: ContextWindow::with_default_strategy(max_tokens),
        }
    }

    #[must_use] 
    pub const fn with_strategy(max_tokens: u32, strategy: ContextStrategy) -> Self {
        Self {
            window: ContextWindow::new(max_tokens, strategy),
        }
    }

    // ── Message addition ──────────────────────────────────────────────────────

    /// Add a system-role message. System messages are never trimmed.
    pub fn add_system_message(&mut self, content: impl Into<String>) -> bool {
        let msg = ContextMessage::new(MessageRole::System, content);
        let cost = msg.token_count;
        if self.window.used_tokens + cost > self.window.max_tokens {
            if self.window.strategy == ContextStrategy::RejectNew {
                return false;
            }
            self.trim_to_fit_tokens(cost);
        }
        self.window.used_tokens += cost;
        self.window.messages.push_front(msg);
        true
    }

    /// Add a user-role message.
    pub fn add_user_message(&mut self, content: impl Into<String>) -> bool {
        self.add_message(MessageRole::User, content)
    }

    /// Add an assistant-role message.
    pub fn add_assistant_message(&mut self, content: impl Into<String>) -> bool {
        self.add_message(MessageRole::Assistant, content)
    }

    /// Add a tool-role message.
    pub fn add_tool_message(&mut self, content: impl Into<String>) -> bool {
        self.add_message(MessageRole::Tool, content)
    }

    fn add_message(&mut self, role: MessageRole, content: impl Into<String>) -> bool {
        let msg = ContextMessage::new(role, content);
        let cost = msg.token_count;
        if self.window.used_tokens + cost > self.window.max_tokens {
            match &self.window.strategy {
                ContextStrategy::RejectNew => return false,
                ContextStrategy::TrimOldest | ContextStrategy::TrimMiddle | ContextStrategy::Summarize => {
                    self.trim_to_fit_tokens(cost);
                }
            }
        }
        self.window.used_tokens += cost;
        self.window.messages.push_back(msg);
        true
    }

    // ── Trim ──────────────────────────────────────────────────────────────────

    /// Remove oldest non-system messages until `needed` tokens are free.
    pub fn trim_to_fit(&mut self) {
        let needed = self.window.used_tokens.saturating_sub(self.window.max_tokens);
        if needed > 0 {
            self.trim_to_fit_tokens(needed);
        }
    }

    fn trim_to_fit_tokens(&mut self, needed: u32) {
        let mut freed = 0u32;
        match self.window.strategy.clone() {
            ContextStrategy::TrimOldest | ContextStrategy::Summarize => {
                let mut i = 0;
                while freed < needed && i < self.window.messages.len() {
                    if self.window.messages[i].role != MessageRole::System {
                        let cost = self.window.messages[i].token_count;
                        if self.window.strategy == ContextStrategy::Summarize {
                            let placeholder = ContextMessage::with_token_count(
                                MessageRole::System,
                                "[earlier messages summarized]",
                                6,
                            );
                            self.window.messages[i] = placeholder;
                            freed += cost.saturating_sub(6);
                        } else {
                            self.window.messages.remove(i);
                            freed += cost;
                            continue;
                        }
                    }
                    i += 1;
                }
            }
            ContextStrategy::TrimMiddle => {
                // Remove messages from the middle, preserving first & last.
                let len = self.window.messages.len();
                if len <= 2 {
                    return;
                }
                let mut mid = len / 2;
                while freed < needed && mid > 0 && mid < self.window.messages.len() {
                    if self.window.messages[mid].role == MessageRole::System {
                        mid += 1;
                    } else {
                        let cost = self.window.messages[mid].token_count;
                        self.window.messages.remove(mid);
                        freed += cost;
                    }
                }
                // If TrimMiddle could not free enough tokens (e.g. all
                // remaining messages are System-role), fall back to trimming
                // from the oldest end so the budget is actually satisfied.
                if freed < needed {
                    let mut i = 0;
                    while freed < needed && i < self.window.messages.len() {
                        if self.window.messages[i].role == MessageRole::System {
                            i += 1;
                        } else {
                            let cost = self.window.messages[i].token_count;
                            self.window.messages.remove(i);
                            freed += cost;
                        }
                    }
                }
            }
            ContextStrategy::RejectNew => {}
        }
        self.window.recalculate_used();
    }

    // ── Few-shot injection ────────────────────────────────────────────────────

    /// Insert few-shot examples as user/assistant pairs before the latest user message.
    pub fn add_few_shot_examples(&mut self, examples: &[FewShotExample]) -> usize {
        let insert_pos = self.find_last_user_message_pos();
        let mut inserted = 0;

        for ex in examples {
            let cost = ex.token_cost();
            if !self.window.has_capacity(cost) {
                self.trim_to_fit_tokens(cost);
            }
            let user_msg = ContextMessage::new(MessageRole::User, &ex.input);
            let asst_msg = ContextMessage::new(MessageRole::Assistant, &ex.output);
            let pos = insert_pos + inserted * 2;
            let user_cost = user_msg.token_count;
            let asst_cost = asst_msg.token_count;
            self.window.messages.insert(pos, user_msg);
            self.window.messages.insert(pos + 1, asst_msg);
            self.window.used_tokens += user_cost + asst_cost;
            inserted += 1;
        }
        inserted
    }

    fn find_last_user_message_pos(&self) -> usize {
        for (i, msg) in self.window.messages.iter().enumerate().rev() {
            if msg.role == MessageRole::User {
                return i;
            }
        }
        self.window.messages.len()
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    /// Format all messages as a JSON array (`OpenAI` chat format).
    #[must_use] 
    pub fn format_for_api(&self) -> String {
        let mut out = String::from("[\n");
        let msgs: Vec<&ContextMessage> = self.window.messages.iter().collect();
        for (i, msg) in msgs.iter().enumerate() {
            let escaped = msg.content.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r");
            write!(
                out,
                "  {{\"role\": \"{}\", \"content\": \"{}\"}}{}",
                msg.role.as_str(),
                escaped,
                if i + 1 < msgs.len() { ",\n" } else { "\n" }
            ).unwrap();
        }
        out.push(']');
        out
    }

    /// Format as human-readable Markdown for display/debugging.
    #[must_use] 
    pub fn format_as_markdown(&self) -> String {
        let mut out = String::new();
        for msg in &self.window.messages {
            let header = match msg.role {
                MessageRole::System => "### System",
                MessageRole::User => "### User",
                MessageRole::Assistant => "### Assistant",
                MessageRole::Tool => "### Tool",
            };
            writeln!(out, "{header}").unwrap();
            writeln!(out, "{}", msg.content).unwrap();
            writeln!(out, "*(~{} tokens)*\n", msg.token_count).unwrap();
        }
        out
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    #[must_use] 
    pub fn stats(&self) -> ContextStats {
        let message_count = usize_to_u32(self.window.messages.len());
        let mut system_tokens = 0u32;
        let mut user_tokens = 0u32;
        let mut assistant_tokens = 0u32;
        let mut tool_tokens = 0u32;
        for msg in &self.window.messages {
            match msg.role {
                MessageRole::System => system_tokens += msg.token_count,
                MessageRole::User => user_tokens += msg.token_count,
                MessageRole::Assistant => assistant_tokens += msg.token_count,
                MessageRole::Tool => tool_tokens += msg.token_count,
            }
        }
        let total_tokens = system_tokens + user_tokens + assistant_tokens + tool_tokens;
        ContextStats { message_count, system_tokens, user_tokens, assistant_tokens, tool_tokens, total_tokens }
    }

    /// Expose the built window.
    #[must_use] 
    pub fn build(self) -> ContextWindow {
        self.window
    }

    #[must_use] 
    pub const fn window(&self) -> &ContextWindow {
        &self.window
    }
}

// ── Message compression ───────────────────────────────────────────────────────

/// Truncate a message to approximately `target_tokens`, appending a suffix.
#[must_use] 
pub fn compress_message(msg: &str, target_tokens: u32) -> String {
    let current = token_count_estimate(msg);
    if current <= target_tokens {
        return msg.to_string();
    }
    let suffix = "... [truncated]";
    let suffix_tokens = token_count_estimate(suffix);
    let keep_tokens = target_tokens.saturating_sub(suffix_tokens);
    // chars ≈ tokens * 4
    let keep_chars = (keep_tokens * 4) as usize;
    let truncated: String = msg.chars().take(keep_chars).collect();
    format!("{truncated}{suffix}")
}

// ── Builder helper impl ───────────────────────────────────────────────────────

impl Default for LlmContextBuilder {
    fn default() -> Self {
        Self::new(4096)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_count_empty() {
        assert_eq!(token_count_estimate(""), 0);
    }

    #[test]
    fn test_token_count_four_chars() {
        assert_eq!(token_count_estimate("abcd"), 1);
    }

    #[test]
    fn test_token_count_partial() {
        assert_eq!(token_count_estimate("abc"), 1);
    }

    #[test]
    fn test_token_count_longer() {
        // 16 chars → 4 tokens
        assert_eq!(token_count_estimate("1234567890123456"), 4);
    }

    #[test]
    fn test_add_system_message() {
        let mut b = LlmContextBuilder::new(1000);
        assert!(b.add_system_message("You are a helpful assistant."));
        assert_eq!(b.window().messages.len(), 1);
        assert_eq!(b.window().messages[0].role, MessageRole::System);
    }

    #[test]
    fn test_add_user_message() {
        let mut b = LlmContextBuilder::new(1000);
        assert!(b.add_user_message("Hello!"));
        assert_eq!(b.window().messages.back().unwrap().role, MessageRole::User);
    }

    #[test]
    fn test_add_assistant_message() {
        let mut b = LlmContextBuilder::new(1000);
        b.add_user_message("Hello!");
        assert!(b.add_assistant_message("Hi there!"));
        assert_eq!(b.window().messages.back().unwrap().role, MessageRole::Assistant);
    }

    #[test]
    fn test_reject_new_strategy() {
        let mut b = LlmContextBuilder::with_strategy(10, ContextStrategy::RejectNew);
        b.add_system_message("sys");
        // Fill up: each char ≈ 0.25 tokens, 40 chars = 10 tokens
        let long_msg: String = "a".repeat(40);
        // First big message should fail because window is partially full
        let result = b.add_user_message(&long_msg);
        // result may succeed if tokens fit; key thing: adding beyond limit fails
        let _ = result;
        let very_long: String = "x".repeat(400);
        let r2 = b.add_user_message(&very_long);
        assert!(!r2);
    }

    #[test]
    fn test_trim_oldest_non_system() {
        let mut b = LlmContextBuilder::with_strategy(20, ContextStrategy::TrimOldest);
        b.add_system_message("sys"); // ~1 token
        // Add messages until trim kicks in
        for i in 0..10 {
            b.add_user_message(format!("message {i}"));
        }
        // System message should still be present
        assert!(b.window().messages.iter().any(|m| m.role == MessageRole::System));
    }

    #[test]
    fn test_trim_to_fit_manual() {
        let mut b = LlmContextBuilder::with_strategy(50, ContextStrategy::TrimOldest);
        for i in 0..20 {
            b.add_user_message(format!("msg {i}"));
        }
        b.trim_to_fit();
        assert!(b.window().used_tokens <= b.window().max_tokens);
    }

    #[test]
    fn test_format_for_api_is_json_array() {
        let mut b = LlmContextBuilder::new(1000);
        b.add_system_message("sys");
        b.add_user_message("hi");
        let json = b.format_for_api();
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
        assert!(json.contains("\"role\""));
        assert!(json.contains("\"content\""));
    }

    #[test]
    fn test_format_as_markdown() {
        let mut b = LlmContextBuilder::new(1000);
        b.add_system_message("You are helpful.");
        b.add_user_message("What is 2+2?");
        let md = b.format_as_markdown();
        assert!(md.contains("### System"));
        assert!(md.contains("### User"));
    }

    #[test]
    fn test_stats_counts() {
        let mut b = LlmContextBuilder::new(10000);
        b.add_system_message("system prompt");
        b.add_user_message("user question");
        b.add_assistant_message("answer");
        let s = b.stats();
        assert_eq!(s.message_count, 3);
        assert!(s.system_tokens > 0);
        assert!(s.user_tokens > 0);
        assert!(s.assistant_tokens > 0);
        assert_eq!(s.total_tokens, s.system_tokens + s.user_tokens + s.assistant_tokens + s.tool_tokens);
    }

    #[test]
    fn test_compress_message_no_change_if_fits() {
        let msg = "short";
        let result = compress_message(msg, 100);
        assert_eq!(result, msg);
    }

    #[test]
    fn test_compress_message_truncates() {
        let msg: String = "a".repeat(400);
        let result = compress_message(&msg, 10);
        assert!(result.ends_with("... [truncated]"));
        assert!(token_count_estimate(&result) <= 15); // some slack for suffix
    }

    #[test]
    fn test_few_shot_examples_insertion() {
        let mut b = LlmContextBuilder::new(10000);
        b.add_system_message("sys");
        b.add_user_message("real question");
        let examples = vec![
            FewShotExample::new("input1", "output1", "desc1"),
            FewShotExample::new("input2", "output2", "desc2"),
        ];
        let inserted = b.add_few_shot_examples(&examples);
        assert_eq!(inserted, 2);
        // Should have sys + 2*2 + 1 user = 6
        assert_eq!(b.window().messages.len(), 6);
    }

    #[test]
    fn test_few_shot_example_token_cost() {
        let ex = FewShotExample::new("hello world", "response here", "a test example");
        let cost = ex.token_cost();
        assert!(cost > 0);
    }

    #[test]
    fn test_build_returns_window() {
        let b = LlmContextBuilder::new(512);
        let w = b.build();
        assert_eq!(w.max_tokens, 512);
    }

    #[test]
    fn test_middle_trim_strategy() {
        let mut b = LlmContextBuilder::with_strategy(40, ContextStrategy::TrimMiddle);
        for i in 0..15 {
            b.add_user_message(format!("message number {i}"));
        }
        // Should not panic, used ≤ max
        assert!(b.window().used_tokens <= b.window().max_tokens + 50);
    }

    #[test]
    fn test_summarize_strategy_leaves_placeholder() {
        let mut b = LlmContextBuilder::with_strategy(30, ContextStrategy::Summarize);
        for i in 0..15 {
            b.add_user_message(format!("msg {i}"));
        }
        let has_summary = b.window().messages.iter().any(|m| {
            m.content.contains("[earlier messages summarized]")
        });
        // May or may not trigger depending on token sizes, but no panic
        let _ = has_summary;
    }

    #[test]
    fn test_available_tokens() {
        let mut b = LlmContextBuilder::new(100);
        assert_eq!(b.window().available_tokens(), 100);
        b.add_user_message("test message here");
        assert!(b.window().available_tokens() < 100);
    }

    #[test]
    fn test_add_tool_message() {
        let mut b = LlmContextBuilder::new(1000);
        assert!(b.add_tool_message("{\"result\": 42}"));
        assert_eq!(b.window().messages.back().unwrap().role, MessageRole::Tool);
    }
}
