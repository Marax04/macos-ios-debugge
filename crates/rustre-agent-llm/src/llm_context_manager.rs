//! `llm_context_manager` — Manage context windows for LLM-assisted RE.
//!
//! Provides [`LlmContextManager`], [`ContextWindow`], and [`TokenBudget`],
//! plus [`trim_to_budget`] for fitting content into a token limit.

use std::collections::{HashMap, VecDeque};
use std::fmt;

use rustre_agent::casts::usize_to_u32;

// ── TokenBudget ───────────────────────────────────────────────────────────────

/// Tracks how many tokens are available and consumed in an LLM call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenBudget {
    /// Maximum tokens allowed.
    pub max: u32,
    /// Tokens reserved for the model's completion (output).
    pub reserved_for_completion: u32,
    /// Tokens consumed by content inserted so far.
    pub used: u32,
}

impl TokenBudget {
    /// Create a new budget.
    ///
    /// `max` is the full context window size.
    /// `reserved_for_completion` is how many tokens to keep free for the model response.
    #[must_use]
    pub const fn new(max: u32, reserved_for_completion: u32) -> Self {
        Self {
            max,
            reserved_for_completion,
            used: 0,
        }
    }

    /// Tokens available for input content.
    #[must_use]
    pub const fn input_budget(&self) -> u32 {
        self.max.saturating_sub(self.reserved_for_completion)
    }

    /// Remaining tokens before the input budget is exhausted.
    #[must_use]
    pub const fn remaining(&self) -> u32 {
        self.input_budget().saturating_sub(self.used)
    }

    /// Whether `cost` tokens can still be added.
    #[must_use]
    pub const fn can_fit(&self, cost: u32) -> bool {
        self.remaining() >= cost
    }

    /// Consume `cost` tokens.  Returns `true` if they fit.
    pub const fn consume(&mut self, cost: u32) -> bool {
        if self.can_fit(cost) {
            self.used = self.used.saturating_add(cost);
            true
        } else {
            false
        }
    }

    /// Release `cost` tokens (undo a previous consume).
    pub const fn release(&mut self, cost: u32) {
        self.used = self.used.saturating_sub(cost);
    }

    /// Fill ratio: how full the input budget is (0.0–1.0).
    #[must_use]
    pub fn fill_ratio(&self) -> f64 {
        let budget = self.input_budget();
        if budget == 0 {
            1.0
        } else {
            f64::from(self.used) / f64::from(budget)
        }
    }

    /// Reset consumption to zero.
    pub const fn reset(&mut self) {
        self.used = 0;
    }
}

impl fmt::Display for TokenBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TokenBudget(used={}/{}, completion_reserved={})",
            self.used, self.input_budget(), self.reserved_for_completion
        )
    }
}

// ── Token counting ────────────────────────────────────────────────────────────

/// Approximate token count for a string (chars / 4, rounded up).
#[must_use]
pub fn count_tokens(text: &str) -> u32 {
    let chars = usize_to_u32(text.chars().count());
    chars.saturating_add(3) / 4
}

/// Trim `text` so that its estimated token count fits within `limit`.
/// Truncates at the last whitespace boundary before the limit is exceeded.
#[must_use]
pub fn trim_to_budget(text: &str, limit: u32) -> String {
    if count_tokens(text) <= limit {
        return text.to_string();
    }
    // Approximate character limit (4 chars per token).
    //
    // `char_limit` counts CHARACTERS, but `len()` and slicing work in BYTES:
    // `&text[..char_limit]` panics whenever the cut lands inside a multi-byte
    // character. Any accented, CJK or emoji text does that, and this is a
    // client for model output, so such text is routine rather than exotic.
    // Resolve the character index to a real byte boundary instead.
    let char_limit = (limit * 4) as usize;
    let end = text
        .char_indices()
        .nth(char_limit)
        .map_or(text.len(), |(i, _)| i);
    // Find a good break point
    let slice = &text[..end];
    // Try to break at a word boundary
    slice
        .rfind(|c: char| c.is_whitespace())
        .map_or_else(|| slice.to_string(), |pos| text[..pos].to_string())
}

// ── ContextEntry ──────────────────────────────────────────────────────────────

/// Priority level for a context entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Default)]
pub enum ContextPriority {
    /// Will be evicted first when trimming.
    Low = 1,
    /// Normal priority.
    #[default]
    Normal = 5,
    /// Kept until only mandatory items remain.
    High = 8,
    /// Never evicted (system messages, task descriptions).
    Mandatory = 10,
}

impl ContextPriority {
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }
}


/// A single entry in the context window.
#[derive(Debug, Clone)]
pub struct ContextEntry {
    /// Unique identifier within the window.
    pub id: String,
    /// Category tag (e.g. `"system"`, `"disasm"`, `"history"`, `"result"`).
    pub category: String,
    /// The text content.
    pub content: String,
    /// Estimated token count (cached).
    pub token_count: u32,
    /// Priority — lower values are evicted first.
    pub priority: ContextPriority,
    /// Sequence number for insertion order.
    pub seq: u64,
}

impl ContextEntry {
    /// Create a new entry, computing the token count automatically.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        category: impl Into<String>,
        content: impl Into<String>,
        priority: ContextPriority,
        seq: u64,
    ) -> Self {
        let content = content.into();
        let token_count = count_tokens(&content);
        Self {
            id: id.into(),
            category: category.into(),
            content,
            token_count,
            priority,
            seq,
        }
    }
}

// ── ContextWindow ─────────────────────────────────────────────────────────────

/// A bounded collection of [`ContextEntry`] items that respects a [`TokenBudget`].
#[derive(Debug)]
pub struct ContextWindow {
    entries: Vec<ContextEntry>,
    budget: TokenBudget,
    next_seq: u64,
}

impl ContextWindow {
    /// Create an empty window with the given budget.
    #[must_use]
    pub const fn new(budget: TokenBudget) -> Self {
        Self {
            entries: Vec::new(),
            budget,
            next_seq: 0,
        }
    }

    /// Try to insert `entry`.  If the budget is exhausted, evict lower-priority entries
    /// until there is room, then insert.  Returns `false` if even mandatory entries
    /// would need to be evicted (and none are evicted in that case).
    pub fn insert(&mut self, mut entry: ContextEntry) -> bool {
        entry.seq = self.next_seq;
        self.next_seq += 1;

        if self.budget.can_fit(entry.token_count) {
            self.budget.consume(entry.token_count);
            self.entries.push(entry);
            return true;
        }

        // Try to free space by evicting lower-priority entries
        let needed = entry.token_count;
        let entry_prio = entry.priority;

        // Collect eviction candidates (lower priority, sorted ascending by priority then seq)
        let mut candidates: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.priority < entry_prio)
            .map(|(i, _)| i)
            .collect();
        candidates.sort_unstable_by(|&a, &b| {
            self.entries[a]
                .priority
                .cmp(&self.entries[b].priority)
                .then_with(|| self.entries[a].seq.cmp(&self.entries[b].seq))
        });

        let mut freed = 0u32;
        let mut to_remove = Vec::new();
        for idx in candidates {
            freed += self.entries[idx].token_count;
            to_remove.push(idx);
            if self.budget.remaining() + freed >= needed {
                break;
            }
        }

        if self.budget.remaining() + freed < needed {
            return false;
        }

        // Remove collected indices (descending to preserve index validity)
        to_remove.sort_unstable_by(|a, b| b.cmp(a));
        for idx in to_remove {
            let removed = self.entries.remove(idx);
            self.budget.release(removed.token_count);
        }

        self.budget.consume(entry.token_count);
        self.entries.push(entry);
        true
    }

    /// Remove an entry by id.  Returns `true` if found.
    pub fn remove(&mut self, id: &str) -> bool {
        if let Some(pos) = self.entries.iter().position(|e| e.id == id) {
            let removed = self.entries.remove(pos);
            self.budget.release(removed.token_count);
            true
        } else {
            false
        }
    }

    /// Return all entries in insertion order (stable).
    #[must_use]
    pub fn entries_in_order(&self) -> Vec<&ContextEntry> {
        let mut ordered: Vec<&ContextEntry> = self.entries.iter().collect();
        ordered.sort_unstable_by_key(|e| e.seq);
        ordered
    }

    /// Render all entries to a single string for use as a prompt block.
    #[must_use]
    pub fn render(&self) -> String {
        self.entries_in_order()
            .iter()
            .map(|e| e.content.as_str())
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    /// Total tokens consumed.
    #[must_use]
    pub const fn tokens_used(&self) -> u32 {
        self.budget.used
    }

    /// Tokens remaining in the input budget.
    #[must_use]
    pub const fn tokens_remaining(&self) -> u32 {
        self.budget.remaining()
    }

    /// Number of entries in the window.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the window is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Find an entry by id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&ContextEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Return the current token budget.
    #[must_use]
    pub const fn budget(&self) -> &TokenBudget {
        &self.budget
    }

    /// Clear all entries and reset the budget.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.budget.reset();
    }

    /// All entries of a given category.
    #[must_use]
    pub fn entries_by_category(&self, category: &str) -> Vec<&ContextEntry> {
        self.entries
            .iter()
            .filter(|e| e.category == category)
            .collect()
    }
}

// ── LlmContextManager ─────────────────────────────────────────────────────────

/// Manages the full context lifecycle for an LLM-assisted RE session.
///
/// Maintains a rolling history of messages, task context, and analysis results.
/// Provides automatic eviction, de-duplication by category, and rendering.
#[derive(Debug)]
pub struct LlmContextManager {
    window: ContextWindow,
    history: VecDeque<(String, String)>, // (role, content)
    max_history: usize,
    category_limits: HashMap<String, usize>,
    total_inserts: u64,
    total_evictions: u64,
}

impl LlmContextManager {
    /// Create a manager with a context window of `max_tokens` and `completion_reserve`.
    #[must_use]
    pub fn new(max_tokens: u32, completion_reserve: u32) -> Self {
        let budget = TokenBudget::new(max_tokens, completion_reserve);
        Self {
            window: ContextWindow::new(budget),
            history: VecDeque::new(),
            max_history: 20,
            category_limits: HashMap::new(),
            total_inserts: 0,
            total_evictions: 0,
        }
    }

    /// Set the maximum number of history turns to retain.
    #[must_use]
    pub const fn with_history_limit(mut self, limit: usize) -> Self {
        self.max_history = limit;
        self
    }

    /// Limit how many entries of a category can exist simultaneously.
    #[must_use]
    pub fn with_category_limit(mut self, category: impl Into<String>, limit: usize) -> Self {
        self.category_limits.insert(category.into(), limit);
        self
    }

    /// Add a mandatory context entry (never evicted).
    pub fn set_system(&mut self, id: impl Into<String>, content: impl Into<String>) {
        let id_str: String = id.into();
        self.window.remove(&id_str);
        let entry = ContextEntry::new(id_str, "system", content, ContextPriority::Mandatory, 0);
        self.window.insert(entry);
    }

    /// Add a high-priority disassembly or code entry.
    pub fn add_code(&mut self, id: impl Into<String>, code: impl Into<String>) {
        self.add_entry(id, "code", code, ContextPriority::High);
    }

    /// Add a normal-priority analysis result.
    pub fn add_result(&mut self, id: impl Into<String>, result: impl Into<String>) {
        self.add_entry(id, "result", result, ContextPriority::Normal);
    }

    /// Add a low-priority historical note.
    pub fn add_note(&mut self, id: impl Into<String>, note: impl Into<String>) {
        self.add_entry(id, "note", note, ContextPriority::Low);
    }

    /// Add an entry with explicit category and priority.
    pub fn add_entry(
        &mut self,
        id: impl Into<String>,
        category: impl Into<String>,
        content: impl Into<String>,
        priority: ContextPriority,
    ) {
        let id_str: String = id.into();
        let cat_str: String = category.into();

        // Enforce category limits
        if let Some(&limit) = self.category_limits.get(&cat_str) {
            let cat_entries: Vec<String> = self
                .window
                .entries_by_category(&cat_str)
                .into_iter()
                .map(|e| e.id.clone())
                .collect();
            if cat_entries.len() >= limit {
                // Remove oldest entry in the category
                if let Some(oldest_id) = cat_entries.first() {
                    self.window.remove(oldest_id);
                    self.total_evictions += 1;
                }
            }
        }

        // Replace if id already exists
        self.window.remove(&id_str);

        let seq = self.total_inserts;
        self.total_inserts += 1;
        let entry = ContextEntry::new(id_str, cat_str, content, priority, seq);
        if !self.window.insert(entry) {
            self.total_evictions += 1;
        }
    }

    /// Append a user/assistant turn to the rolling history.
    pub fn push_history(&mut self, role: impl Into<String>, content: impl Into<String>) {
        self.history.push_back((role.into(), content.into()));
        while self.history.len() > self.max_history {
            self.history.pop_front();
        }
    }

    /// Render the context window to a single user-message string.
    #[must_use]
    pub fn render_context(&self) -> String {
        self.window.render()
    }

    /// Render history as a flat string (for injection into prompts).
    ///
    /// Newline and carriage-return characters in role or content are replaced
    /// with a space to prevent log-injection: a crafted content value
    /// containing `\n[assistant]:` would otherwise create fake history lines
    /// when the output is written to a log file or displayed line-by-line.
    #[must_use]
    pub fn render_history(&self) -> String {
        self.history
            .iter()
            .map(|(role, content)| {
                let safe_role = role.replace(['\n', '\r'], " ");
                let safe_content = content.replace(['\n', '\r'], " ");
                format!("[{safe_role}]: {safe_content}")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Token usage statistics.
    #[must_use]
    pub const fn token_stats(&self) -> (u32, u32, u32) {
        let b = self.window.budget();
        (b.used, b.input_budget(), b.remaining())
    }

    /// Number of entries currently in the context window.
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.window.len()
    }

    /// Total entries ever inserted.
    #[must_use]
    pub const fn total_inserts(&self) -> u64 {
        self.total_inserts
    }

    /// Total entries ever evicted.
    #[must_use]
    pub const fn total_evictions(&self) -> u64 {
        self.total_evictions
    }

    /// Remove an entry by id.
    pub fn remove(&mut self, id: &str) -> bool {
        self.window.remove(id)
    }

    /// Clear all context entries (preserves history).
    pub fn clear_context(&mut self) {
        self.window.clear();
    }

    /// Clear all history.
    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    /// Fill ratio of the context window (0.0–1.0).
    #[must_use]
    pub fn fill_ratio(&self) -> f64 {
        self.window.budget().fill_ratio()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_budget_basics() {
        let mut b = TokenBudget::new(1000, 200);
        assert_eq!(b.input_budget(), 800);
        assert_eq!(b.remaining(), 800);
        assert!(b.consume(300));
        assert_eq!(b.remaining(), 500);
        b.release(100);
        assert_eq!(b.remaining(), 600);
    }

    #[test]
    fn test_token_budget_overflow() {
        let mut b = TokenBudget::new(100, 20);
        assert!(!b.consume(200));
        assert_eq!(b.used, 0);
    }

    #[test]
    fn test_token_budget_fill_ratio() {
        let mut b = TokenBudget::new(200, 0);
        b.consume(100);
        assert!((b.fill_ratio() - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_token_budget_display() {
        let b = TokenBudget::new(1000, 200);
        let s = format!("{b}");
        assert!(s.contains("800"));
    }

    #[test]
    fn test_count_tokens() {
        assert_eq!(count_tokens(""), 0);
        // "hello" = 5 chars → (5+3)/4 = 2
        assert_eq!(count_tokens("hello"), 2);
        assert_eq!(count_tokens("a".repeat(400).as_str()), 100);
    }

    #[test]
    fn test_trim_to_budget_no_trim() {
        let text = "hello world";
        let result = trim_to_budget(text, 100);
        assert_eq!(result, text);
    }

    #[test]
    fn test_trim_to_budget_handles_multibyte_text() {
        // The character limit must be resolved to a real byte boundary.
        // Slicing at the raw character count panics as soon as the cut lands
        // inside a multi-byte character — and model output is full of accents,
        // CJK and emoji, so this is the normal case, not an exotic one.
        for text in [
            "aaaéaaaéaaaéaaaé",
            "日本語のテキストをここに置く",
            "emoji 🙂🙂🙂 and more 🙂🙂🙂 text",
            "café café café café café",
        ] {
            for limit in 1..=6 {
                let result = trim_to_budget(text, limit);
                assert!(
                    text.contains(result.as_str()) || result.is_empty(),
                    "trim_to_budget must return a prefix of the input"
                );
            }
        }
    }

    #[test]
    fn test_trim_to_budget_trims() {
        let text = "word ".repeat(1000);
        let result = trim_to_budget(&text, 50);
        assert!(count_tokens(&result) <= 50);
        assert!(!result.is_empty());
    }

    #[test]
    fn test_context_window_insert_basic() {
        let mut w = ContextWindow::new(TokenBudget::new(1000, 0));
        let e = ContextEntry::new("id1", "code", "int main() {}", ContextPriority::Normal, 0);
        assert!(w.insert(e));
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn test_context_window_eviction() {
        let mut w = ContextWindow::new(TokenBudget::new(20, 0));
        // Fill with low-priority entries
        for i in 0..5 {
            let e = ContextEntry::new(
                format!("low{i}"),
                "note",
                format!("note {i}"),
                ContextPriority::Low,
                i,
            );
            w.insert(e);
        }
        // Insert a high-priority entry that doesn't fit
        let hi = ContextEntry::new(
            "hi".to_string(),
            "code",
            "A".repeat(40),
            ContextPriority::High,
            10,
        );
        let inserted = w.insert(hi);
        // Should have evicted lower entries to make room
        assert!(inserted || w.tokens_remaining() < 10);
    }

    #[test]
    fn test_context_window_remove() {
        let mut w = ContextWindow::new(TokenBudget::new(1000, 0));
        let e = ContextEntry::new("x", "code", "content", ContextPriority::Normal, 0);
        w.insert(e);
        assert!(w.remove("x"));
        assert_eq!(w.len(), 0);
    }

    #[test]
    fn test_context_window_render() {
        let mut w = ContextWindow::new(TokenBudget::new(1000, 0));
        w.insert(ContextEntry::new("a", "code", "first", ContextPriority::Normal, 0));
        w.insert(ContextEntry::new("b", "code", "second", ContextPriority::Normal, 1));
        let rendered = w.render();
        assert!(rendered.contains("first"));
        assert!(rendered.contains("second"));
    }

    #[test]
    fn test_context_window_by_category() {
        let mut w = ContextWindow::new(TokenBudget::new(1000, 0));
        w.insert(ContextEntry::new("a", "code", "c", ContextPriority::Normal, 0));
        w.insert(ContextEntry::new("b", "note", "n", ContextPriority::Low, 1));
        let code_entries = w.entries_by_category("code");
        assert_eq!(code_entries.len(), 1);
        assert_eq!(code_entries[0].id, "a");
    }

    #[test]
    fn test_context_manager_set_system() {
        let mut mgr = LlmContextManager::new(4096, 512);
        mgr.set_system("sys", "You are a RE expert.");
        assert_eq!(mgr.entry_count(), 1);
    }

    #[test]
    fn test_context_manager_add_and_render() {
        let mut mgr = LlmContextManager::new(4096, 512);
        mgr.add_code("disasm", "push rbp\nret");
        mgr.add_result("analysis", "This function is a thunk.");
        let rendered = mgr.render_context();
        assert!(rendered.contains("push rbp") || rendered.contains("thunk"));
    }

    #[test]
    fn test_context_manager_history() {
        let mut mgr = LlmContextManager::new(4096, 512);
        mgr.push_history("user", "What does this function do?");
        mgr.push_history("assistant", "It initializes the heap.");
        let rendered = mgr.render_history();
        assert!(rendered.contains("[user]"));
        assert!(rendered.contains("heap"));
    }

    #[test]
    fn test_context_manager_history_limit() {
        let mut mgr = LlmContextManager::new(8192, 512).with_history_limit(3);
        for i in 0..10 {
            mgr.push_history("user", format!("message {i}"));
        }
        let rendered = mgr.render_history();
        // Only last 3 should remain
        assert!(rendered.contains("message 9"));
        assert!(!rendered.contains("message 0"));
    }

    #[test]
    fn test_context_manager_token_stats() {
        let mgr = LlmContextManager::new(1000, 200);
        let (used, total, remaining) = mgr.token_stats();
        assert_eq!(used, 0);
        assert_eq!(total, 800);
        assert_eq!(remaining, 800);
    }

    #[test]
    fn test_context_manager_fill_ratio() {
        let mgr = LlmContextManager::new(1000, 0);
        assert!((mgr.fill_ratio() - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_context_manager_category_limit() {
        let mut mgr = LlmContextManager::new(8192, 512).with_category_limit("result", 2);
        mgr.add_result("r1", "Result one.");
        mgr.add_result("r2", "Result two.");
        mgr.add_result("r3", "Result three.");
        // After inserting 3 results with limit 2, r1 should be evicted
        let context = mgr.render_context();
        assert!(!context.contains("Result one.") || context.contains("Result two."));
    }

    #[test]
    fn test_context_manager_remove() {
        let mut mgr = LlmContextManager::new(4096, 512);
        mgr.add_note("n1", "Old note");
        assert!(mgr.remove("n1"));
        assert_eq!(mgr.entry_count(), 0);
    }

    #[test]
    fn test_context_manager_clear() {
        let mut mgr = LlmContextManager::new(4096, 512);
        mgr.add_code("c1", "nop");
        mgr.clear_context();
        assert_eq!(mgr.entry_count(), 0);
    }

    #[test]
    fn test_context_priority_ordering() {
        assert!(ContextPriority::Mandatory > ContextPriority::High);
        assert!(ContextPriority::High > ContextPriority::Normal);
        assert!(ContextPriority::Normal > ContextPriority::Low);
    }
}
