//! CLI session state: current file, analysis cache, command history,
//! user preferences, environment variables, and persistence to
//! `~/.rustre/session.json`.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialize(String),
    #[error("no file currently open")]
    NoFileOpen,
    #[error("key not found: {0}")]
    KeyNotFound(String),
    #[error("invalid value: {0}")]
    InvalidValue(String),
    #[error("history full")]
    HistoryFull,
}

pub type SessionResult<T> = Result<T, SessionError>;

// ─── Preferences ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preferences {
    pub output_format: String,
    pub color_mode: String,
    pub auto_analyze: bool,
    pub max_history: usize,
    pub default_arch: String,
    pub show_addresses: bool,
    pub hex_uppercase: bool,
    pub page_size: usize,
    pub prompt: String,
    pub custom: HashMap<String, String>,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            output_format: "table".to_string(),
            color_mode: "auto".to_string(),
            auto_analyze: true,
            max_history: 1000,
            default_arch: "x86_64".to_string(),
            show_addresses: true,
            hex_uppercase: false,
            page_size: 40,
            prompt: "rustre> ".to_string(),
            custom: HashMap::new(),
        }
    }
}

impl Preferences {
    pub fn set(&mut self, key: &str, value: &str) -> SessionResult<()> {
        match key {
            "output_format" => self.output_format = value.to_string(),
            "color_mode" => self.color_mode = value.to_string(),
            "auto_analyze" => self.auto_analyze = parse_bool(value)
                .ok_or_else(|| SessionError::InvalidValue(format!("'{value}' is not a bool")))?,
            "max_history" => self.max_history = value.parse()
                .map_err(|_| SessionError::InvalidValue(format!("'{value}' is not an integer")))?,
            "default_arch" => self.default_arch = value.to_string(),
            "show_addresses" => self.show_addresses = parse_bool(value)
                .ok_or_else(|| SessionError::InvalidValue(format!("'{value}' is not a bool")))?,
            "hex_uppercase" => self.hex_uppercase = parse_bool(value)
                .ok_or_else(|| SessionError::InvalidValue(format!("'{value}' is not a bool")))?,
            "page_size" => self.page_size = value.parse()
                .map_err(|_| SessionError::InvalidValue(format!("'{value}' is not an integer")))?,
            "prompt" => self.prompt = value.to_string(),
            other => { self.custom.insert(other.to_string(), value.to_string()); }
        }
        Ok(())
    }

    #[must_use] 
    pub fn get(&self, key: &str) -> Option<String> {
        match key {
            "output_format" => Some(self.output_format.clone()),
            "color_mode" => Some(self.color_mode.clone()),
            "auto_analyze" => Some(self.auto_analyze.to_string()),
            "max_history" => Some(self.max_history.to_string()),
            "default_arch" => Some(self.default_arch.clone()),
            "show_addresses" => Some(self.show_addresses.to_string()),
            "hex_uppercase" => Some(self.hex_uppercase.to_string()),
            "page_size" => Some(self.page_size.to_string()),
            "prompt" => Some(self.prompt.clone()),
            other => self.custom.get(other).cloned(),
        }
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.to_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

// ─── History Entry ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub command: String,
    pub timestamp: u64,
    pub duration_ms: u64,
    pub success: bool,
}

impl HistoryEntry {
    pub fn new(command: impl Into<String>, success: bool, duration: Duration) -> Self {
        // as_millis() returns u128; clamp to u64::MAX to avoid silent truncation
        // for absurdly long-running commands.
        let duration_ms = duration.as_millis().min(u128::from(u64::MAX)) as u64;
        Self {
            command: command.into(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            duration_ms,
            success,
        }
    }
}

// ─── Command History ─────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CommandHistory {
    entries: VecDeque<HistoryEntry>,
    pub max_size: usize,
    cursor: Option<usize>,
}

impl CommandHistory {
    #[must_use] 
    pub const fn new(max_size: usize) -> Self {
        Self { entries: VecDeque::new(), max_size, cursor: None }
    }

    pub fn push(&mut self, entry: HistoryEntry) {
        if self.entries.len() >= self.max_size {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
        self.cursor = None;
    }

    pub fn push_cmd(&mut self, cmd: &str, success: bool, duration: Duration) {
        // Don't add duplicates of the last entry.
        if self.entries.back().map(|e| e.command.as_str()) == Some(cmd) {
            return;
        }
        self.push(HistoryEntry::new(cmd, success, duration));
    }

    #[must_use] 
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use] 
    pub fn get(&self, index: usize) -> Option<&HistoryEntry> {
        self.entries.get(index)
    }

    #[must_use] 
    pub fn search(&self, query: &str) -> Vec<&HistoryEntry> {
        self.entries.iter().filter(|e| e.command.contains(query)).collect()
    }

    pub fn navigate_up(&mut self) -> Option<&str> {
        if self.entries.is_empty() { return None; }
        self.cursor = Some(match self.cursor {
            None => self.entries.len() - 1,
            Some(0) => 0,
            Some(n) => n - 1,
        });
        self.cursor.and_then(|i| self.entries.get(i)).map(|e| e.command.as_str())
    }

    pub fn navigate_down(&mut self) -> Option<&str> {
        match self.cursor {
            None => None,
            Some(n) if n + 1 >= self.entries.len() => {
                self.cursor = None;
                None
            }
            Some(n) => {
                self.cursor = Some(n + 1);
                self.entries.get(n + 1).map(|e| e.command.as_str())
            }
        }
    }

    pub const fn reset_cursor(&mut self) {
        self.cursor = None;
    }

    #[must_use] 
    pub fn recent(&self, n: usize) -> Vec<&HistoryEntry> {
        let skip = self.entries.len().saturating_sub(n);
        self.entries.iter().skip(skip).collect()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.cursor = None;
    }
}

// ─── Analysis Cache ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedAnalysis {
    pub key: String,
    pub value: serde_json::Value,
    pub created_at: u64,
    pub ttl_secs: Option<u64>,
}

impl CachedAnalysis {
    #[must_use] 
    pub fn is_expired(&self) -> bool {
        if let Some(ttl) = self.ttl_secs {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // Use saturating_add to avoid overflow when ttl is very large.
            return now > self.created_at.saturating_add(ttl);
        }
        false
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AnalysisCache {
    entries: HashMap<String, CachedAnalysis>,
}

impl AnalysisCache {
    pub fn set(&mut self, key: impl Into<String>, value: serde_json::Value, ttl: Option<u64>) {
        let key = key.into();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.entries.insert(key.clone(), CachedAnalysis {
            key,
            value,
            created_at: now,
            ttl_secs: ttl,
        });
    }

    #[must_use] 
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.entries.get(key)
            .filter(|e| !e.is_expired())
            .map(|e| &e.value)
    }

    #[must_use] 
    pub fn contains(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn remove(&mut self, key: &str) -> bool {
        self.entries.remove(key).is_some()
    }

    pub fn evict_expired(&mut self) {
        self.entries.retain(|_, v| !v.is_expired());
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    #[must_use] 
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

// ─── Open File Info ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenFileInfo {
    pub path: PathBuf,
    pub arch: String,
    pub bits: u32,
    pub format: String,
    pub size_bytes: u64,
    pub md5: String,
    pub sha256: String,
    pub base_addr: u64,
    pub entry_point: u64,
    pub opened_at: u64,
    pub analyzed: bool,
}

impl OpenFileInfo {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            path,
            arch: String::new(),
            bits: 64,
            format: String::new(),
            size_bytes: 0,
            md5: String::new(),
            sha256: String::new(),
            base_addr: 0,
            entry_point: 0,
            opened_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            analyzed: false,
        }
    }
}

impl fmt::Display for OpenFileInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({} {}-bit, {:#x})", self.path.display(), self.arch, self.bits, self.base_addr)
    }
}

// ─── Environment ─────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SessionEnv {
    vars: HashMap<String, String>,
}

impl SessionEnv {
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.vars.insert(key.into(), value.into());
    }

    #[must_use] 
    pub fn get(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(std::string::String::as_str)
    }

    pub fn unset(&mut self, key: &str) -> bool {
        self.vars.remove(key).is_some()
    }

    #[must_use] 
    pub fn expand(&self, template: &str) -> String {
        let mut out = template.to_string();
        for (k, v) in &self.vars {
            out = out.replace(&format!("${k}"), v);
            out = out.replace(&format!("${{{k}}}"), v);
        }
        out
    }

    #[must_use] 
    pub const fn all(&self) -> &HashMap<String, String> {
        &self.vars
    }
}

// ─── Session State ────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub current_file: Option<OpenFileInfo>,
    pub history: CommandHistory,
    pub cache: AnalysisCache,
    pub prefs: Preferences,
    pub env: SessionEnv,
    pub bookmarks: HashMap<String, u64>,
    pub comments: HashMap<u64, String>,
    pub tags: HashMap<u64, Vec<String>>,
    pub session_id: String,
    pub created_at: u64,
    pub modified_at: u64,
}

impl SessionState {
    #[must_use] 
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Build a session ID that is hard to predict or collide.  The previous
        // implementation used only `now ^ constant`, which was fully predictable
        // for any observer who knew the start time.  We now mix in the process
        // ID and the address of a stack variable (ASLR-derived) so that two
        // sessions started in the same second with the same PID still differ.
        // This is NOT a cryptographic nonce — use a CSPRNG if the session ID
        // is ever used in a security-critical context.
        let pid = u64::from(std::process::id());
        let stack_addr = {
            let x: u8 = 0;
            &raw const x as u64
        };
        let session_id = format!(
            "{:016x}",
            now.wrapping_mul(0x9e37_79b9_7f4a_7c15)
                ^ pid.wrapping_mul(0x6c62_272e_07bb_0142)
                ^ stack_addr
        );
        Self {
            history: CommandHistory::new(1000),
            session_id,
            created_at: now,
            modified_at: now,
            ..Default::default()
        }
    }

    pub fn touch(&mut self) {
        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    // ── File ────────────────────────────────────────────────────────────────

    pub fn open_file(&mut self, info: OpenFileInfo) {
        self.cache.clear();
        self.current_file = Some(info);
        self.touch();
    }

    pub fn close_file(&mut self) {
        self.current_file = None;
        self.cache.clear();
        self.touch();
    }

    pub fn current_file(&self) -> SessionResult<&OpenFileInfo> {
        self.current_file.as_ref().ok_or(SessionError::NoFileOpen)
    }

    // ── History ─────────────────────────────────────────────────────────────

    pub fn record_command(&mut self, cmd: &str, success: bool, duration: Duration) {
        self.history.push_cmd(cmd, success, duration);
        self.touch();
    }

    // ── Bookmarks ────────────────────────────────────────────────────────────

    pub fn bookmark(&mut self, name: impl Into<String>, addr: u64) {
        self.bookmarks.insert(name.into(), addr);
        self.touch();
    }

    #[must_use] 
    pub fn lookup_bookmark(&self, name: &str) -> Option<u64> {
        self.bookmarks.get(name).copied()
    }

    pub fn remove_bookmark(&mut self, name: &str) -> bool {
        let removed = self.bookmarks.remove(name).is_some();
        if removed { self.touch(); }
        removed
    }

    // ── Comments ─────────────────────────────────────────────────────────────

    pub fn set_comment(&mut self, addr: u64, comment: impl Into<String>) {
        self.comments.insert(addr, comment.into());
        self.touch();
    }

    #[must_use] 
    pub fn get_comment(&self, addr: u64) -> Option<&str> {
        self.comments.get(&addr).map(std::string::String::as_str)
    }

    pub fn clear_comment(&mut self, addr: u64) -> bool {
        let removed = self.comments.remove(&addr).is_some();
        if removed { self.touch(); }
        removed
    }

    // ── Tags ─────────────────────────────────────────────────────────────────

    pub fn add_tag(&mut self, addr: u64, tag: impl Into<String>) {
        self.tags.entry(addr).or_default().push(tag.into());
        self.touch();
    }

    #[must_use] 
    pub fn get_tags(&self, addr: u64) -> &[String] {
        self.tags.get(&addr).map_or(&[], std::vec::Vec::as_slice)
    }

    pub fn remove_tag(&mut self, addr: u64, tag: &str) {
        if let Some(tags) = self.tags.get_mut(&addr) {
            tags.retain(|t| t != tag);
        }
    }

    #[must_use] 
    pub fn addresses_with_tag(&self, tag: &str) -> Vec<u64> {
        self.tags.iter()
            .filter(|(_, tags)| tags.iter().any(|t| t == tag))
            .map(|(addr, _)| *addr)
            .collect()
    }

    // ── Persistence ──────────────────────────────────────────────────────────

    /// Compute the default session file path: `~/.rustre/session.json`.
    #[must_use] 
    pub fn default_path() -> PathBuf {
        dirs_home()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".rustre")
            .join("session.json")
    }

    /// Save session to a JSON file.
    ///
    /// Uses a write-to-temp-then-rename strategy so that an interrupted write
    /// (e.g. process killed, disk full) leaves the previous session file intact
    /// rather than producing a half-written / corrupted file (state-machine-on-error).
    pub fn save(&self, path: &Path) -> SessionResult<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| SessionError::Serialize(e.to_string()))?;
        // Write to a sibling temp file first, then atomically rename.
        let tmp_path = path.with_extension("json.tmp");
        fs::write(&tmp_path, &json)?;
        fs::rename(&tmp_path, path).map_err(|e| {
            // Best-effort cleanup of the temp file; ignore secondary error.
            let _ = fs::remove_file(&tmp_path);
            SessionError::Io(e)
        })?;
        Ok(())
    }

    /// Load session from a JSON file. Returns `None` if the file does not exist.
    /// Maximum session file size accepted (16 MiB) to bound memory use.
    const MAX_SESSION_FILE_BYTES: u64 = 16 * 1024 * 1024;

    pub fn load(path: &Path) -> SessionResult<Option<Self>> {
        // Use open() directly to avoid a TOCTOU race between exists() + open().
        let file = match fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(SessionError::Io(e)),
        };
        // Reject absurdly large session files before reading into memory.
        let meta = file.metadata()?;
        if meta.len() > Self::MAX_SESSION_FILE_BYTES {
            return Err(SessionError::InvalidValue(format!(
                "session file too large ({} bytes, limit {})",
                meta.len(),
                Self::MAX_SESSION_FILE_BYTES
            )));
        }
        let content = fs::read_to_string(path)?;
        let state: Self = serde_json::from_str(&content)
            .map_err(|e| SessionError::Serialize(e.to_string()))?;
        Ok(Some(state))
    }

    /// Save to the default path.
    pub fn save_default(&self) -> SessionResult<()> {
        self.save(&Self::default_path())
    }

    /// Load from the default path.
    pub fn load_default() -> SessionResult<Option<Self>> {
        Self::load(&Self::default_path())
    }

    #[must_use] 
    pub fn age(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Duration::from_secs(now.saturating_sub(self.created_at))
    }
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

// ─── Session Manager ─────────────────────────────────────────────────────────

/// Manages multiple named sessions.
pub struct SessionManager {
    sessions: HashMap<String, SessionState>,
    active: String,
    pub base_dir: PathBuf,
}

impl SessionManager {
    #[must_use] 
    pub fn new(base_dir: PathBuf) -> Self {
        let default_name = "default".to_string();
        let mut sessions = HashMap::new();
        sessions.insert(default_name.clone(), SessionState::new());
        Self { sessions, active: default_name, base_dir }
    }

    #[must_use] 
    pub fn default_manager() -> Self {
        let base = dirs_home()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".rustre")
            .join("sessions");
        Self::new(base)
    }

    #[must_use] 
    pub fn active(&self) -> &SessionState {
        self.sessions.get(&self.active).expect("active session missing")
    }

    pub fn active_mut(&mut self) -> &mut SessionState {
        self.sessions.get_mut(&self.active).expect("active session missing")
    }

    pub fn create(&mut self, name: impl Into<String>) -> &mut SessionState {
        let name = name.into();
        self.sessions.entry(name.clone()).or_default();
        self.sessions.get_mut(&name).unwrap()
    }

    pub fn switch(&mut self, name: &str) -> SessionResult<()> {
        if !self.sessions.contains_key(name) {
            return Err(SessionError::KeyNotFound(name.to_string()));
        }
        self.active = name.to_string();
        Ok(())
    }

    #[must_use] 
    pub fn list_names(&self) -> Vec<&str> {
        self.sessions.keys().map(std::string::String::as_str).collect()
    }

    pub fn remove(&mut self, name: &str) -> SessionResult<()> {
        if name == self.active {
            return Err(SessionError::InvalidValue("cannot remove active session".into()));
        }
        self.sessions.remove(name)
            .ok_or_else(|| SessionError::KeyNotFound(name.to_string()))?;
        Ok(())
    }

    pub fn save_active(&self) -> SessionResult<()> {
        let path = self.base_dir.join(format!("{}.json", self.active));
        self.active().save(&path)
    }

    pub fn load_session(&mut self, name: &str) -> SessionResult<()> {
        // Reject session names that contain path separators or ".." components
        // to prevent a caller-controlled `name` from escaping `self.base_dir`
        // via path traversal (e.g. name = "../../../etc/passwd").
        if name.contains(['/', '\\']) || name == ".." || name.starts_with("../") || name.starts_with("..\\") {
            return Err(SessionError::InvalidValue(format!(
                "invalid session name '{name}': must not contain path separators"
            )));
        }
        let path = self.base_dir.join(format!("{name}.json"));
        if let Some(state) = SessionState::load(&path)? {
            self.sessions.insert(name.to_string(), state);
        }
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_new() {
        let sess = SessionState::new();
        assert!(sess.current_file.is_none());
        assert!(!sess.session_id.is_empty());
    }

    #[test]
    fn test_open_close_file() {
        let mut sess = SessionState::new();
        assert!(sess.current_file().is_err());
        let info = OpenFileInfo::new("/tmp/test.exe");
        sess.open_file(info);
        assert!(sess.current_file().is_ok());
        sess.close_file();
        assert!(sess.current_file().is_err());
    }

    #[test]
    fn test_bookmarks() {
        let mut sess = SessionState::new();
        sess.bookmark("main", 0x401000);
        sess.bookmark("init", 0x401200);
        assert_eq!(sess.lookup_bookmark("main"), Some(0x401000));
        assert_eq!(sess.lookup_bookmark("missing"), None);
        sess.remove_bookmark("init");
        assert_eq!(sess.lookup_bookmark("init"), None);
    }

    #[test]
    fn test_comments() {
        let mut sess = SessionState::new();
        sess.set_comment(0x401000, "entry point");
        assert_eq!(sess.get_comment(0x401000), Some("entry point"));
        sess.clear_comment(0x401000);
        assert_eq!(sess.get_comment(0x401000), None);
    }

    #[test]
    fn test_tags() {
        let mut sess = SessionState::new();
        sess.add_tag(0x401000, "malware");
        sess.add_tag(0x401000, "entry");
        sess.add_tag(0x402000, "malware");
        assert_eq!(sess.get_tags(0x401000).len(), 2);
        let addrs = sess.addresses_with_tag("malware");
        assert!(addrs.contains(&0x401000));
        assert!(addrs.contains(&0x402000));
    }

    #[test]
    fn test_history_push_and_navigate() {
        let mut hist = CommandHistory::new(100);
        for i in 0..5 {
            hist.push_cmd(&format!("cmd{}", i), true, Duration::ZERO);
        }
        assert_eq!(hist.len(), 5);
        let last = hist.navigate_up().unwrap();
        assert_eq!(last, "cmd4");
        let prev = hist.navigate_up().unwrap();
        assert_eq!(prev, "cmd3");
    }

    #[test]
    fn test_history_dedup() {
        let mut hist = CommandHistory::new(100);
        hist.push_cmd("ls", true, Duration::ZERO);
        hist.push_cmd("ls", true, Duration::ZERO);
        assert_eq!(hist.len(), 1);
    }

    #[test]
    fn test_history_search() {
        let mut hist = CommandHistory::new(100);
        hist.push_cmd("open /tmp/malware.exe", true, Duration::ZERO);
        hist.push_cmd("strings", true, Duration::ZERO);
        hist.push_cmd("open /tmp/benign.dll", true, Duration::ZERO);
        let hits = hist.search("open");
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn test_analysis_cache() {
        let mut cache = AnalysisCache::default();
        cache.set("strings", serde_json::json!(["hello", "world"]), None);
        assert!(cache.contains("strings"));
        assert!(!cache.contains("other"));
        cache.remove("strings");
        assert!(!cache.contains("strings"));
    }

    #[test]
    fn test_preferences_set_get() {
        let mut prefs = Preferences::default();
        prefs.set("output_format", "json").unwrap();
        assert_eq!(prefs.get("output_format").as_deref(), Some("json"));
        prefs.set("page_size", "80").unwrap();
        assert_eq!(prefs.get("page_size").as_deref(), Some("80"));
    }

    #[test]
    fn test_preferences_invalid() {
        let mut prefs = Preferences::default();
        let result = prefs.set("auto_analyze", "maybe");
        assert!(result.is_err());
    }

    #[test]
    fn test_env_expand() {
        let mut env = SessionEnv::default();
        env.set("FILE", "/tmp/test.exe");
        let expanded = env.expand("open $FILE");
        assert_eq!(expanded, "open /tmp/test.exe");
        let expanded2 = env.expand("open ${FILE}");
        assert_eq!(expanded2, "open /tmp/test.exe");
    }

    #[test]
    fn test_session_serialize_roundtrip() {
        let mut sess = SessionState::new();
        sess.bookmark("test", 0xDEAD);
        sess.set_comment(0x1000, "comment");
        let json = serde_json::to_string(&sess).unwrap();
        let restored: SessionState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.lookup_bookmark("test"), Some(0xDEAD));
        assert_eq!(restored.get_comment(0x1000), Some("comment"));
    }

    #[test]
    fn test_session_manager_switch() {
        let tmp = std::env::temp_dir().join("rustre_test_sessions");
        let mut mgr = SessionManager::new(tmp);
        mgr.create("work");
        mgr.switch("work").unwrap();
        assert_eq!(mgr.active, "work");
        assert!(mgr.switch("nonexistent").is_err());
    }

    #[test]
    fn test_history_max_size() {
        let mut hist = CommandHistory::new(3);
        for i in 0..5 {
            hist.push(HistoryEntry::new(format!("cmd{}", i), true, Duration::ZERO));
        }
        assert_eq!(hist.len(), 3);
        // Oldest entries should be gone.
        assert_eq!(hist.get(0).unwrap().command, "cmd2");
    }
}
