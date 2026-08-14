// rustre-agent/src/memory_store.rs
//
// Agent memory: conversation history, structured analysis findings
// (functions, strings, IoCs, behaviours), cross-session SQLite persistence,
// cosine-similarity search on findings, and context-window management with
// summarisation.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ Error â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("database error: {0}")]
    Database(String),
    #[error("serialization error: {0}")]
    Serialize(String),
    #[error("finding not found: {0}")]
    NotFound(String),
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("embedding dimension mismatch: expected {expected}, got {got}")]
    DimMismatch { expected: usize, got: usize },
}

pub type MemoryResult<T> = Result<T, MemoryError>;

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ Helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

fn now_ms() -> u64 {
    u64::try_from(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()).unwrap_or(u64::MAX)
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 { 0.0 } else { dot / (na * nb) }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ MessageRole â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    User,
    Assistant,
    System,
    Tool,
}

impl std::fmt::Display for MessageRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::System => "system",
            Self::Tool => "tool",
        };
        write!(f, "{s}")
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ ConversationMessage â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationMessage {
    pub id: u64,
    pub role: MessageRole,
    pub content: String,
    pub timestamp_ms: u64,
    /// Estimated token count.
    pub tokens: usize,
    /// Optional tool call/result metadata.
    pub metadata: Option<serde_json::Value>,
}

impl ConversationMessage {
    pub fn new(role: MessageRole, content: impl Into<String>) -> Self {
        let content = content.into();
        let tokens = estimate_tokens(&content);
        Self {
            id: 0,
            role,
            content,
            timestamp_ms: now_ms(),
            tokens,
            metadata: None,
        }
    }

    #[must_use] 
    pub fn with_metadata(mut self, meta: serde_json::Value) -> Self {
        self.metadata = Some(meta);
        self
    }
}

fn estimate_tokens(text: &str) -> usize {
    // Rough GPT-style estimate: ~4 chars per token.
    (text.len() / 4).max(1)
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ ConversationHistory â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// In-memory conversation history with token-limit trimming.
#[derive(Default)]
pub struct ConversationHistory {
    messages: Vec<ConversationMessage>,
    next_id: u64,
    max_tokens: usize,
}

impl ConversationHistory {
    #[must_use] 
    pub const fn new(max_tokens: usize) -> Self {
        Self { messages: Vec::new(), next_id: 1, max_tokens }
    }

    pub fn push(&mut self, mut msg: ConversationMessage) -> u64 {
        msg.id = self.next_id;
        self.next_id += 1;
        self.messages.push(msg);
        // Trim to fit window
        self.trim();
        self.next_id - 1
    }

    #[must_use] 
    pub fn messages(&self) -> &[ConversationMessage] {
        &self.messages
    }

    #[must_use] 
    pub fn total_tokens(&self) -> usize {
        self.messages.iter().map(|m| m.tokens).sum()
    }

    /// Remove oldest messages (never removing system role) until under limit.
    fn trim(&mut self) {
        if self.max_tokens == 0 {
            return;
        }
        while self.total_tokens() > self.max_tokens && self.messages.len() > 1 {
            if let Some(idx) = self.messages.iter().position(|m| m.role != MessageRole::System) {
                self.messages.remove(idx);
            } else {
                break;
            }
        }
    }

    #[must_use] 
    pub fn last_n(&self, n: usize) -> &[ConversationMessage] {
        let start = self.messages.len().saturating_sub(n);
        &self.messages[start..]
    }

    pub fn clear(&mut self) {
        self.messages.retain(|m| m.role == MessageRole::System);
    }

    /// Summarise the history to a single placeholder message.
    pub fn summarise(&mut self, summary: &str) {
        self.messages.retain(|m| m.role == MessageRole::System);
        let mut s = ConversationMessage::new(MessageRole::System, format!("[Summary]: {summary}"));
        s.id = self.next_id;
        self.next_id += 1;
        self.messages.push(s);
    }

    /// # Errors
    /// Returns `MemoryError::Serialize` when serde JSON serialization fails.
    pub fn to_json(&self) -> MemoryResult<String> {
        serde_json::to_string_pretty(&self.messages)
            .map_err(|e| MemoryError::Serialize(e.to_string()))
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ Finding kinds â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Function,
    String,
    Ioc,
    Behaviour,
    Vulnerability,
    Crypto,
    Network,
    Registry,
    File,
    Mutex,
    Custom(String),
}

impl std::fmt::Display for FindingKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "custom:{s}"),
            other => write!(f, "{other:?}"),
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ Finding â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub session_id: String,
    pub kind: FindingKind,
    pub title: String,
    pub description: String,
    pub address: Option<u64>,
    pub confidence: f32, // 0.0— 1.0
    pub tags: Vec<String>,
    pub attributes: HashMap<String, serde_json::Value>,
    pub timestamp_ms: u64,
    /// Embedding vector for similarity search (optional).
    #[serde(skip)]
    pub embedding: Option<Vec<f32>>,
}

impl Finding {
    pub fn new(
        session_id: impl Into<String>,
        kind: FindingKind,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let title = title.into();
        let id = format!("f-{}-{}", now_ms(), fastrand_u32());
        Self {
            id,
            session_id: session_id.into(),
            kind,
            title,
            description: description.into(),
            address: None,
            confidence: 1.0,
            tags: Vec::new(),
            attributes: HashMap::new(),
            timestamp_ms: now_ms(),
            embedding: None,
        }
    }

    #[must_use] 
    pub const fn with_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    #[must_use] 
    pub const fn with_confidence(mut self, c: f32) -> Self {
        self.confidence = c.clamp(0.0, 1.0);
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    #[must_use]
    pub fn with_attr(mut self, key: impl Into<String>, val: serde_json::Value) -> Self {
        self.attributes.insert(key.into(), val);
        self
    }

    #[must_use] 
    pub fn with_embedding(mut self, emb: Vec<f32>) -> Self {
        self.embedding = Some(emb);
        self
    }

    #[must_use] 
    pub fn summary(&self) -> String {
        format!("[{}] {} \u{2014} {}", self.kind, self.title, self.description)
    }
}

fn fastrand_u32() -> u32 {
    // Simple LCG as a dependency-free fallback.
    static SEED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0x517c_c1b7_2722_0a95);
    let s = SEED.fetch_add(0x9e37_79b9_7f4a_7c15, std::sync::atomic::Ordering::Relaxed);
    u32::try_from(((s >> 33) ^ s) & 0xFFFF_FFFF).unwrap_or(u32::MAX)
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ FindingsStore â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// In-memory index of Findings with cosine-similarity search.
#[derive(Default)]
pub struct FindingsStore {
    findings: Vec<Finding>,
}

impl FindingsStore {
    pub fn add(&mut self, f: Finding) {
        self.findings.push(f);
    }

    #[must_use] 
    pub fn get(&self, id: &str) -> Option<&Finding> {
        self.findings.iter().find(|f| f.id == id)
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.findings.len();
        self.findings.retain(|f| f.id != id);
        self.findings.len() < before
    }

    #[must_use] 
    pub fn by_kind(&self, kind: &FindingKind) -> Vec<&Finding> {
        self.findings.iter().filter(|f| &f.kind == kind).collect()
    }

    #[must_use] 
    pub fn by_tag(&self, tag: &str) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.tags.iter().any(|t| t == tag)).collect()
    }

    #[must_use] 
    pub fn by_session(&self, session_id: &str) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.session_id == session_id).collect()
    }

    #[must_use] 
    pub fn all(&self) -> &[Finding] {
        &self.findings
    }

    /// Cosine similarity search.  Requires all findings to have embeddings.
    #[must_use] 
    pub fn search_by_embedding(&self, query: &[f32], top_k: usize) -> Vec<(&Finding, f32)> {
        let mut scored: Vec<(&Finding, f32)> = self
            .findings
            .iter()
            .filter_map(|f| {
                f.embedding.as_ref().map(|emb| (f, cosine_similarity(query, emb)))
            })
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(top_k);
        scored
    }

    /// Keyword search over title + description.
    #[must_use] 
    pub fn search_text(&self, query: &str, top_k: usize) -> Vec<&Finding> {
        let q = query.to_lowercase();
        let mut matches: Vec<&Finding> = self
            .findings
            .iter()
            .filter(|f| {
                f.title.to_lowercase().contains(&q) || f.description.to_lowercase().contains(&q)
            })
            .collect();
        matches.truncate(top_k);
        matches
    }

    #[must_use] 
    pub const fn count(&self) -> usize {
        self.findings.len()
    }

    /// # Errors
    /// Returns `MemoryError::Serialize` when serde JSON serialization fails.
    pub fn to_json(&self) -> MemoryResult<String> {
        serde_json::to_string_pretty(&self.findings)
            .map_err(|e| MemoryError::Serialize(e.to_string()))
    }

    #[must_use] 
    pub fn summary_report(&self) -> String {
        let mut by_kind: HashMap<String, usize> = HashMap::new();
        for f in &self.findings {
            *by_kind.entry(f.kind.to_string()).or_insert(0) += 1;
        }
        let mut lines: Vec<String> = by_kind
            .iter()
            .map(|(k, n)| format!("  {k}: {n}"))
            .collect();
        lines.sort();
        format!("Findings ({} total):\n{}", self.findings.len(), lines.join("\n"))
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ Session â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub binary_path: Option<String>,
    pub created_ms: u64,
    pub updated_ms: u64,
    pub tags: Vec<String>,
    pub notes: String,
}

impl Session {
    pub fn new(id: impl Into<String>) -> Self {
        let ts = now_ms();
        Self {
            id: id.into(),
            binary_path: None,
            created_ms: ts,
            updated_ms: ts,
            tags: Vec::new(),
            notes: String::new(),
        }
    }

    #[must_use]
    pub fn with_binary(mut self, path: impl Into<String>) -> Self {
        self.binary_path = Some(path.into());
        self
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ MemoryStore â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Top-level memory store.  Holds conversation history, findings, and session
/// metadata, with optional `SQLite` persistence.
pub struct MemoryStore {
    session: Mutex<Session>,
    history: Mutex<ConversationHistory>,
    findings: Mutex<FindingsStore>,
    db_path: Option<PathBuf>,
    // Cached summaries for context building
    summaries: RwLock<Vec<String>>,
}

impl MemoryStore {
    pub fn new(session_id: impl Into<String>, max_history_tokens: usize) -> Self {
        Self {
            session: Mutex::new(Session::new(session_id)),
            history: Mutex::new(ConversationHistory::new(max_history_tokens)),
            findings: Mutex::new(FindingsStore::default()),
            db_path: None,
            summaries: RwLock::new(Vec::new()),
        }
    }

    /// # Errors
    /// Returns an error if loading existing data from the database fails.
    pub fn with_db(mut self, path: impl Into<PathBuf>) -> MemoryResult<Self> {
        let path = path.into();
        self.db_path = Some(path.clone());
        // Attempt to load existing data
        if path.exists() {
            self.load_from_db(&path)?;
        }
        Ok(self)
    }

    // â"€â"€ Session â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    pub fn session_id(&self) -> String {
        self.session.lock().id.clone()
    }

    pub fn set_binary(&self, path: impl Into<String>) {
        self.session.lock().binary_path = Some(path.into());
    }

    // â"€â"€ History â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    pub fn add_message(&self, msg: ConversationMessage) -> u64 {
        let id = self.history.lock().push(msg);
        self.persist_if_needed();
        id
    }

    pub fn add_user(&self, content: impl Into<String>) -> u64 {
        self.add_message(ConversationMessage::new(MessageRole::User, content))
    }

    pub fn add_assistant(&self, content: impl Into<String>) -> u64 {
        self.add_message(ConversationMessage::new(MessageRole::Assistant, content))
    }

    pub fn add_system(&self, content: impl Into<String>) -> u64 {
        self.add_message(ConversationMessage::new(MessageRole::System, content))
    }

    pub fn history_messages(&self) -> Vec<ConversationMessage> {
        self.history.lock().messages().to_vec()
    }

    pub fn last_n_messages(&self, n: usize) -> Vec<ConversationMessage> {
        self.history.lock().last_n(n).to_vec()
    }

    pub fn total_history_tokens(&self) -> usize {
        self.history.lock().total_tokens()
    }

    pub fn summarise_history(&self, summary: String) {
        self.history.lock().summarise(&summary);
        self.summaries.write().push(summary);
        self.persist_if_needed();
    }

    pub fn clear_history(&self) {
        self.history.lock().clear();
    }

    // â"€â"€ Findings â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    pub fn add_finding(&self, f: Finding) -> String {
        let id = f.id.clone();
        self.findings.lock().add(f);
        self.persist_if_needed();
        id
    }

    pub fn get_finding(&self, id: &str) -> Option<Finding> {
        self.findings.lock().get(id).cloned()
    }

    pub fn remove_finding(&self, id: &str) -> bool {
        self.findings.lock().remove(id)
    }

    pub fn findings_by_kind(&self, kind: &FindingKind) -> Vec<Finding> {
        self.findings.lock().by_kind(kind).into_iter().cloned().collect()
    }

    pub fn findings_by_tag(&self, tag: &str) -> Vec<Finding> {
        self.findings.lock().by_tag(tag).into_iter().cloned().collect()
    }

    pub fn search_findings_text(&self, query: &str, top_k: usize) -> Vec<Finding> {
        self.findings
            .lock()
            .search_text(query, top_k)
            .into_iter()
            .cloned()
            .collect()
    }

    pub fn search_findings_embedding(&self, query: &[f32], top_k: usize) -> Vec<(Finding, f32)> {
        self.findings
            .lock()
            .search_by_embedding(query, top_k)
            .into_iter()
            .map(|(f, score)| (f.clone(), score))
            .collect()
    }

    pub fn all_findings(&self) -> Vec<Finding> {
        self.findings.lock().all().to_vec()
    }

    pub fn findings_count(&self) -> usize {
        self.findings.lock().count()
    }

    pub fn findings_summary(&self) -> String {
        self.findings.lock().summary_report()
    }

    // â"€â"€ Context building â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Build a compact context string for injection into an LLM prompt,
    /// including key findings and recent conversation summary.
    pub fn build_context(&self, max_tokens: usize) -> String {
        let mut out = String::new();
        let session = self.session.lock();

        out.push_str("=== Analysis Session ===\n");
        if let Some(bin) = &session.binary_path {
            use std::fmt::Write;
            let _ = writeln!(out, "Binary: {bin}");
        }
        {
            use std::fmt::Write;
            let _ = writeln!(out, "Session: {}\n", session.id);
        }
        drop(session);

        // Findings summary
        let findings = self.all_findings();
        if !findings.is_empty() {
            out.push_str("=== Key Findings ===\n");
            let mut budget = max_tokens.saturating_sub(estimate_tokens(&out));
            for f in &findings {
                let line = format!("\u{2022} [{}][{:.0}%] {} \u{2014} {}\n",
                    f.kind, f.confidence * 100.0, f.title, f.description);
                if estimate_tokens(&line) > budget {
                    break;
                }
                budget = budget.saturating_sub(estimate_tokens(&line));
                out.push_str(&line);
            }
            out.push('\n');
        }

        // Recent summaries
        let summaries = self.summaries.read();
        if !summaries.is_empty() {
            out.push_str("=== Analysis Summary ===\n");
            if let Some(last) = summaries.last() {
                out.push_str(last);
                out.push('\n');
            }
        }

        out
    }

    // â"€â"€ Persistence â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn persist_if_needed(&self) {
        if let Some(path) = &self.db_path {
            // Best-effort; ignore errors in persistence
            let _ = self.save_to_db(path);
        }
    }

    /// Save state to a JSON file (`SQLite` would require rusqlite feature).
    fn save_to_db(&self, path: &Path) -> MemoryResult<()> {
        let state = self.export()?;
        std::fs::write(path, state.as_bytes())
            .map_err(|e| MemoryError::Database(e.to_string()))
    }

    fn load_from_db(&self, path: &Path) -> MemoryResult<()> {
        let bytes = std::fs::read(path)
            .map_err(|e| MemoryError::Database(e.to_string()))?;
        let state: PersistedState = serde_json::from_slice(&bytes)
            .map_err(|e| MemoryError::Serialize(e.to_string()))?;

        // Restore findings
        {
            let mut store = self.findings.lock();
            for f in state.findings {
                store.add(f);
            }
        }

        // Restore history
        {
            let mut hist = self.history.lock();
            for msg in state.history {
                hist.push(msg);
            }
        }

        // Restore session
        *self.session.lock() = state.session;

        Ok(())
    }

    /// # Errors
    /// Returns `MemoryError::Serialize` when serde JSON serialization fails.
    pub fn export(&self) -> MemoryResult<String> {
        let state = PersistedState {
            session: self.session.lock().clone(),
            history: self.history.lock().messages().to_vec(),
            findings: self.findings.lock().all().to_vec(),
            summaries: self.summaries.read().clone(),
        };
        serde_json::to_string_pretty(&state)
            .map_err(|e| MemoryError::Serialize(e.to_string()))
    }
}

#[derive(Serialize, Deserialize)]
struct PersistedState {
    session: Session,
    history: Vec<ConversationMessage>,
    findings: Vec<Finding>,
    summaries: Vec<String>,
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ GlobalMemory â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Registry of all active `MemoryStore` instances, keyed by session ID.
pub struct GlobalMemory {
    stores: RwLock<HashMap<String, Arc<MemoryStore>>>,
}

impl GlobalMemory {
    #[must_use] 
    pub fn new() -> Self {
        Self { stores: RwLock::new(HashMap::new()) }
    }

    pub fn create_session(&self, id: impl Into<String>, max_tokens: usize) -> Arc<MemoryStore> {
        let id = id.into();
        let store = Arc::new(MemoryStore::new(id.clone(), max_tokens));
        self.stores.write().insert(id, Arc::clone(&store));
        store
    }

    pub fn get_session(&self, id: &str) -> Option<Arc<MemoryStore>> {
        self.stores.read().get(id).cloned()
    }

    pub fn remove_session(&self, id: &str) {
        self.stores.write().remove(id);
    }

    pub fn session_ids(&self) -> Vec<String> {
        self.stores.read().keys().cloned().collect()
    }
}

impl Default for GlobalMemory {
    fn default() -> Self {
        Self::new()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€ unit tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> MemoryStore {
        MemoryStore::new("test-session", 10_000)
    }

    #[test]
    fn add_and_retrieve_message() {
        let m = mem();
        m.add_user("hello");
        m.add_assistant("world");
        let msgs = m.history_messages();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].role, MessageRole::User);
        assert_eq!(msgs[1].content, "world");
    }

    #[test]
    fn history_trim() {
        // max 5 tokens —" each message has at least 1 token estimate
        let mut h = ConversationHistory::new(5);
        for i in 0..20 {
            h.push(ConversationMessage::new(MessageRole::User, i.to_string()));
        }
        assert!(h.total_tokens() <= 5 || h.messages().len() == 1);
    }

    #[test]
    fn findings_add_search_text() {
        let m = mem();
        let f = Finding::new("test-session", FindingKind::Function, "decrypt_data", "Decrypts AES data");
        m.add_finding(f);
        let results = m.search_findings_text("AES", 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "decrypt_data");
    }

    #[test]
    fn findings_by_kind() {
        let m = mem();
        m.add_finding(Finding::new("s", FindingKind::Ioc, "bad.com", "C2 domain"));
        m.add_finding(Finding::new("s", FindingKind::Function, "main", "entry"));
        let iocs = m.findings_by_kind(&FindingKind::Ioc);
        assert_eq!(iocs.len(), 1);
        assert_eq!(iocs[0].kind, FindingKind::Ioc);
    }

    #[test]
    fn findings_embedding_search() {
        let m = mem();
        let f1 = Finding::new("s", FindingKind::Crypto, "aes_enc", "AES encrypt")
            .with_embedding(vec![1.0, 0.0, 0.0]);
        let f2 = Finding::new("s", FindingKind::Crypto, "rsa_enc", "RSA encrypt")
            .with_embedding(vec![0.0, 1.0, 0.0]);
        m.add_finding(f1);
        m.add_finding(f2);
        let results = m.search_findings_embedding(&[1.0, 0.0, 0.0], 1);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.title, "aes_enc");
        assert!((results[0].1 - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_sim_orthogonal() {
        assert!(cosine_similarity(&[1.0, 0.0], &[0.0, 1.0]).abs() < 1e-6);
    }

    #[test]
    fn cosine_sim_identical() {
        let v = vec![0.6, 0.8];
        let s = cosine_similarity(&v, &v);
        assert!((s - 1.0).abs() < 1e-6);
    }

    #[test]
    fn summarise_clears_non_system() {
        let mut h = ConversationHistory::new(100_000);
        h.push(ConversationMessage::new(MessageRole::System, "sys"));
        h.push(ConversationMessage::new(MessageRole::User, "q"));
        h.push(ConversationMessage::new(MessageRole::Assistant, "a"));
        h.summarise("Summary here");
        // Should have system + summary only
        assert!(h.messages().iter().all(|m| m.role == MessageRole::System));
    }

    #[test]
    fn build_context_contains_finding() {
        let m = mem();
        m.add_finding(Finding::new("test-session", FindingKind::Ioc, "evil.exe", "Ransomware dropper"));
        let ctx = m.build_context(10_000);
        assert!(ctx.contains("evil.exe"));
        assert!(ctx.contains("Ransomware dropper"));
    }

    #[test]
    fn global_memory_session_lifecycle() {
        let gm = GlobalMemory::new();
        gm.create_session("s1", 1000);
        assert!(gm.get_session("s1").is_some());
        gm.remove_session("s1");
        assert!(gm.get_session("s1").is_none());
    }

    #[test]
    fn export_roundtrip() {
        let m = mem();
        m.add_user("hello");
        m.add_finding(Finding::new("test-session", FindingKind::String, "url", "http://x.com"));
        let json = m.export().unwrap();
        assert!(json.contains("hello"));
        assert!(json.contains("url"));
    }
}
