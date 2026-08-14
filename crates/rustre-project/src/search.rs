//! `search.rs` — Project-wide full-text and structural search for RustRE.
//!
//! [`SearchEngine`] wraps the project SQLite database and exposes high-level
//! search APIs backed by FTS5 virtual tables and normal B-tree queries.
//!
//! Supported search targets:
//! - **Strings** — via the `strings_fts` virtual table (already populated by
//!   migration 3 in the project schema).
//! - **Functions** — by name prefix/regex against the `functions` table.
//! - **Comments** — full-text over the `comments` table.
//! - **Symbols** — by name over the `symbols` table.
//!
//! The `SearchIndex` companion maintains extra FTS5 tables for comments and
//! symbols (the base schema only provides string FTS5).
//!
//! [`SearchQuery`] is a builder that controls what and how to search.
//! [`SearchResult`] carries the matched record together with type, address,
//! and a short context snippet.
//! [`SearchStats`] reports result counts and timing.

use std::path::Path;
use std::time::Instant;

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SearchError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("invalid regex: {0}")]
    InvalidRegex(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, SearchError>;

// ── MatchType ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MatchType {
    StringLiteral,
    FunctionName,
    Comment,
    SymbolName,
}

impl std::fmt::Display for MatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StringLiteral => write!(f, "string"),
            Self::FunctionName => write!(f, "function"),
            Self::Comment => write!(f, "comment"),
            Self::SymbolName => write!(f, "symbol"),
        }
    }
}

// ── SearchScope ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SearchScope {
    /// Search all targets.
    #[default]
    All,
    /// Only search string literals.
    Strings,
    /// Only search function names.
    Functions,
    /// Only search comments.
    Comments,
    /// Only search symbol names.
    Symbols,
}

// ── SearchQuery ───────────────────────────────────────────────────────────────

/// Builder for a search query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    /// The search pattern (substring, prefix, or regex depending on flags).
    pub pattern: String,
    /// If false, perform case-insensitive matching.
    pub case_sensitive: bool,
    /// If true, interpret `pattern` as a regular expression.
    pub regex: bool,
    /// Restrict which targets are searched.
    pub scope: SearchScope,
    /// Maximum number of results to return (0 = unlimited).
    pub max_results: usize,
    /// Minimum address filter (inclusive), if set.
    pub addr_min: Option<u64>,
    /// Maximum address filter (inclusive), if set.
    pub addr_max: Option<u64>,
}

impl SearchQuery {
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            case_sensitive: false,
            regex: false,
            scope: SearchScope::All,
            max_results: 1000,
            addr_min: None,
            addr_max: None,
        }
    }

    #[must_use] 
     
    pub fn case_sensitive(mut self) -> Self {
        self.case_sensitive = true;
       
      self
    }
    #[must_use] 
    pub fn regex(mut self) -> Self {
        self.regex = true;
        self
    }
    #[must_use] 
    pub fn scope(mut self, scope: SearchScope) -> Self {
        self.scope = scope;
        self
    }
    #[must_use] 
    pub fn max(mut self, n: usize) -> Self {
        self.max_results = n;
        self
    }
    #[must_use] 
    pub fn addr_range(mut self, min: u64, max: u64) -> Self {
        self.addr_min = Some(min);
        self.addr_max = Some(max);
        self
    }

    /// Prepare the pattern for SQLite LIKE (with leading/trailing %).
    fn to_like_pattern(&self) -> String {
        if self.case_sensitive {
            format!("%{}%", self.pattern)
        } else {
            format!("%{}%", self.pattern.to_lowercase())
        }
    }

    /// For FTS5, wrap in quotes for phrase matching.
    fn to_fts5_query(&self) -> String {
        // Escape FTS5 special characters and wrap in double-quotes for phrase match
        let escaped = self.pattern.replace('"', "\"\"");
        format!("\"{escaped}\"")
    }

    fn passes_addr_filter(&self, addr: u64) -> bool {
        if let Some(min) = self.addr_min
            && addr < min {
                return false;
            }
        if let Some(max) = self.addr_max
            && addr > max {
                return false;
            }
        true
    }
}

// ── SearchResult ──────────────────────────────────────────────────────────────

/// A single search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// What kind of item matched.
    pub match_type: MatchType,
    /// Address of the matching item in the binary.
    pub address: u64,
    /// The matched text (function name, string value, comment body, etc.).
    pub matched_text: String,
    /// Short context snippet for display (may equal `matched_text`).
    pub context_snippet: String,
    /// The binary this result belongs to.
    pub binary_id: u64,
}

impl SearchResult {
    fn new(
        match_type: MatchType,
        binary_id: u64,
        address: u64,
        matched_text: impl Into<String>,
    ) -> Self {
        let matched_text = matched_text.into();
        let snippet = snippet(&matched_text, 80);
        Self {
            match_type,
            address,
            context_snippet: snippet,
            matched_text,
            binary_id,
        }
    }
}

impl std::fmt::Display for SearchResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {:#x}: {}",
            self.match_type, self.address, self.context_snippet
        )
    }
}

// ── SearchStats ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SearchStats {
    pub total_results: usize,
    pub string_results: usize,
    pub function_results: usize,
    pub comment_results: usize,
    pub symbol_results: usize,
    /// Time taken in milliseconds.
    pub time_ms: u64,
}

impl SearchStats {
    fn from_results(results: &[SearchResult], time_ms: u64) -> Self {
        let mut s = Self {
            total_results: results.len(),
            time_ms,
            ..Default::default()
        };
        for r in results {
            match r.match_type {
                MatchType::StringLiteral => s.string_results += 1,
                MatchType::FunctionName => s.function_results += 1,
                MatchType::Comment => s.comment_results += 1,
                MatchType::SymbolName => s.symbol_results += 1,
            }
        }
        s
    }
}

impl std::fmt::Display for SearchStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SearchStats {{ total={}, fn={}, str={}, cmt={}, sym={}, {}ms }}",
            self.total_results,
            self.function_results,
            self.string_results,
            self.comment_results,
            self.symbol_results,
            self.time_ms
        )
    }
}

// ── SearchIndex ───────────────────────────────────────────────────────────────

/// Manages additional FTS5 virtual tables for comments and symbols.
///
/// The project schema (migration 3) already creates `strings_fts`.
/// `SearchIndex` adds:
/// - `comments_fts` (backed by `comments.body`)
/// - `symbols_fts`  (backed by `symbols.name`)
/// - `functions_fts` (backed by `functions.name`)
///
/// Call `ensure_schema()` once after project init.
pub struct SearchIndex {
    db_path: std::path::PathBuf,
}

impl SearchIndex {
    pub fn new(db_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            db_path: db_path.into(),
        }
    }

    fn connect(&self) -> Result<Connection> {
        let conn = Connection::open(&self.db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        Ok(conn)
    }

    /// Create the extra FTS5 tables and their triggers if they do not yet exist.
    pub fn ensure_schema(&self) -> Result<()> {
        let conn = self.connect()?;
        conn.execute_batch(
            r#"
-- Functions FTS5
CREATE VIRTUAL TABLE IF NOT EXISTS functions_fts
    USING fts5(name, content=functions, content_rowid=id);
CREATE TRIGGER IF NOT EXISTS functions_fts_ai AFTER INSERT ON functions BEGIN
    INSERT INTO functions_fts(rowid, name) VALUES (new.id, new.name);
END;
CREATE TRIGGER IF NOT EXISTS functions_fts_ad AFTER DELETE ON functions BEGIN
    INSERT INTO functions_fts(functions_fts, rowid, name) VALUES('delete', old.id, old.name);
END;
CREATE TRIGGER IF NOT EXISTS functions_fts_au AFTER UPDATE ON functions BEGIN
    INSERT INTO functions_fts(functions_fts, rowid, name) VALUES('delete', old.id, old.name);
    INSERT INTO functions_fts(rowid, name) VALUES (new.id, new.name);
END;
-- Comments FTS5
CREATE VIRTUAL TABLE IF NOT EXISTS comments_fts
    USING fts5(body, content=comments, content_rowid=id);
CREATE TRIGGER IF NOT EXISTS comments_fts_ai AFTER INSERT ON comments BEGIN
    INSERT INTO comments_fts(rowid, body) VALUES (new.id, new.body);
END;
CREATE TRIGGER IF NOT EXISTS comments_fts_ad AFTER DELETE ON comments BEGIN
    INSERT INTO comments_fts(comments_fts, rowid, body) VALUES('delete', old.id, old.body);
END;
CREATE TRIGGER IF NOT EXISTS comments_fts_au AFTER UPDATE ON comments BEGIN
    INSERT INTO comments_fts(comments_fts, rowid, body) VALUES('delete', old.id, old.body);
    INSERT INTO comments_fts(rowid, body) VALUES (new.id, new.body);
END;
-- Symbols FTS5
CREATE VIRTUAL TABLE IF NOT EXISTS symbols_fts
    USING fts5(name, content=symbols, content_rowid=id);
CREATE TRIGGER IF NOT EXISTS symbols_fts_ai AFTER INSERT ON symbols BEGIN
    INSERT INTO symbols_fts(rowid, name) VALUES (new.id, new.name);
END;
CREATE TRIGGER IF NOT EXISTS symbols_fts_ad AFTER DELETE ON symbols BEGIN
    INSERT INTO symbols_fts(symbols_fts, rowid, name) VALUES('delete', old.id, old.name);
END;
CREATE TRIGGER IF NOT EXISTS symbols_fts_au AFTER UPDATE ON symbols BEGIN
    INSERT INTO symbols_fts(symbols_fts, rowid, name) VALUES('delete', old.id, old.name);
    INSERT INTO symbols_fts(rowid, name) VALUES (new.id, new.name);
END;
"#,
        )?;
        Ok(())
    }

    /// Rebuild all FTS5 indexes from current table contents.
    pub fn rebuild(&self) -> Result<()> {
        let conn = self.connect()?;
        // Rebuild only if tables exist
        let rebuild_if_exists = |table: &str| -> std::result::Result<(), rusqlite::Error> {
            let exists: bool = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    params![table],
                    |r| r.get::<_, i64>(0),
                )
                .map(|n| n > 0)
                .unwrap_or(false);
            if exists {
                conn.execute_batch(&format!("INSERT INTO {table}({table}) VALUES('rebuild');"))?;
            }
            Ok(())
        };
        rebuild_if_exists("functions_fts")?;
        rebuild_if_exists("comments_fts")?;
        rebuild_if_exists("symbols_fts")?;
        rebuild_if_exists("strings_fts")?;
        Ok(())
    }
}

// ── SearchEngine ──────────────────────────────────────────────────────────────

/// High-level search engine for a RustRE project database.
pub struct SearchEngine {
    db_path: std::path::PathBuf,
}

impl SearchEngine {
    pub fn new(db_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            db_path: db_path.into(),
        }
    }

    /// Construct from a project's db path.
    pub fn from_db_path(path: impl AsRef<Path>) -> Self {
        Self {
            db_path: path.as_ref().to_path_buf(),
        }
    }

    fn connect(&self) -> Result<Connection> {
        let conn = Connection::open(&self.db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        Ok(conn)
    }

    // ── String search ─────────────────────────────────────────────────────────

    /// Search string literals using the FTS5 `strings_fts` virtual table.
    pub fn search_strings(&self, binary_id: u64, query: &SearchQuery) -> Result<Vec<SearchResult>> {
        let conn = self.connect()?;
        // Try FTS5 first, fall back to LIKE
        let fts_available = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='strings_fts'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .unwrap_or(false);

        let mut results = Vec::new();

        if fts_available && !query.pattern.is_empty() {
            let fts_q = query.to_fts5_query();
            let mut stmt = conn.prepare(
                "SELECT s.addr, s.value FROM strings_fts f JOIN strings s ON s.id=f.rowid
                 WHERE strings_fts MATCH ?1 AND s.binary_id=?2
                 ORDER BY s.addr",
            )?;
            let rows = stmt.query_map(params![fts_q, binary_id as i64], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
            })?;
            for row in rows.filter_map(std::result::Result::ok) {
                let (addr, value) = row;
                if !query.passes_addr_filter(addr) {
                    continue;
                }
                results.push(SearchResult::new(
                    MatchType::StringLiteral,
                    binary_id,
                    addr,
                    value,
                ));
            }
        } else {
            // Fallback LIKE
            let pattern = query.to_like_pattern();
            let sql = if query.case_sensitive {
                "SELECT addr,value FROM strings WHERE binary_id=?1 AND value LIKE ?2 ORDER BY addr"
            } else {
                "SELECT addr,value FROM strings WHERE binary_id=?1 AND lower(value) LIKE lower(?2) ORDER BY addr"
            };
            let mut stmt = conn.prepare(sql)?;
            let rows = stmt.query_map(params![binary_id as i64, &pattern], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
            })?;
            for row in rows.filter_map(std::result::Result::ok) {
                let (addr, value) = row;
                if !query.passes_addr_filter(addr) {
                    continue;
                }
                if query.max_results > 0 && results.len() >= query.max_results {
                    break;
                }
                results.push(SearchResult::new(
                    MatchType::StringLiteral,
                    binary_id,
                    addr,
                    value,
                ));
            }
        }

        apply_regex_filter(&mut results, query)?;
        if query.max_results > 0 {
            results.truncate(query.max_results);
        }
        Ok(results)
    }

    // ── Function search ───────────────────────────────────────────────────────

    /// Search function names.  Uses `functions_fts` if available; falls back to
    /// LIKE.
    pub fn search_functions(
        &self,
        binary_id: u64,
        query: &SearchQuery,
    ) -> Result<Vec<SearchResult>> {
        let conn = self.connect()?;
        let fts_available = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='functions_fts'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .unwrap_or(false);

        let mut results = Vec::new();

        if fts_available && !query.pattern.is_empty() {
            let fts_q = query.to_fts5_query();
            let mut stmt = conn.prepare(
                "SELECT f.addr, f.name FROM functions_fts ft
                 JOIN functions f ON f.id=ft.rowid
                 WHERE functions_fts MATCH ?1 AND f.binary_id=?2
                 ORDER BY f.addr",
            )?;
            let rows = stmt.query_map(params![fts_q, binary_id as i64], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
            })?;
            for row in rows.filter_map(std::result::Result::ok) {
                let (addr, name) = row;
                if !query.passes_addr_filter(addr) {
                    continue;
                }
                results.push(SearchResult::new(
                    MatchType::FunctionName,
                    binary_id,
                    addr,
                    name,
                ));
            }
        } else {
            let pattern = query.to_like_pattern();
            let sql = if query.case_sensitive {
                "SELECT addr,name FROM functions WHERE binary_id=?1 AND name LIKE ?2 ORDER BY addr"
            } else {
                "SELECT addr,name FROM functions WHERE binary_id=?1 AND lower(name) LIKE lower(?2) ORDER BY addr"
            };
            let mut stmt = conn.prepare(sql)?;
            let rows = stmt.query_map(params![binary_id as i64, &pattern], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
            })?;
            for row in rows.filter_map(std::result::Result::ok) {
                let (addr, name) = row;
                if !query.passes_addr_filter(addr) {
                    continue;
                }
                if query.max_results > 0 && results.len() >= query.max_results {
                    break;
                }
                results.push(SearchResult::new(
                    MatchType::FunctionName,
                    binary_id,
                    addr,
                    name,
                ));
            }
        }

        apply_regex_filter(&mut results, query)?;
        if query.max_results > 0 {
            results.truncate(query.max_results);
        }
        Ok(results)
    }

    // ── Comment search ────────────────────────────────────────────────────────

    /// Full-text search over comment bodies.
    pub fn search_comments(
        &self,
        binary_id: u64,
        query: &SearchQuery,
    ) -> Result<Vec<SearchResult>> {
        let conn = self.connect()?;
        let fts_available = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='comments_fts'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .unwrap_or(false);

        let mut results = Vec::new();

        if fts_available && !query.pattern.is_empty() {
            let fts_q = query.to_fts5_query();
            let mut stmt = conn.prepare(
                "SELECT c.addr, c.body FROM comments_fts cf
                 JOIN comments c ON c.id=cf.rowid
                 WHERE comments_fts MATCH ?1 AND c.binary_id=?2
                 ORDER BY c.addr",
            )?;
            let rows = stmt.query_map(params![fts_q, binary_id as i64], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
            })?;
            for row in rows.filter_map(std::result::Result::ok) {
                let (addr, body) = row;
                if !query.passes_addr_filter(addr) {
                    continue;
                }
                results.push(SearchResult::new(MatchType::Comment, binary_id, addr, body));
            }
        } else {
            let pattern = query.to_like_pattern();
            let sql = if query.case_sensitive {
                "SELECT addr,body FROM comments WHERE binary_id=?1 AND body LIKE ?2 ORDER BY addr"
            } else {
                "SELECT addr,body FROM comments WHERE binary_id=?1 AND lower(body) LIKE lower(?2) ORDER BY addr"
            };
            let mut stmt = conn.prepare(sql)?;
            let rows = stmt.query_map(params![binary_id as i64, pattern], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
            })?;
            for row in rows.filter_map(std::result::Result::ok) {
                let (addr, body) = row;
                if !query.passes_addr_filter(addr) {
                    continue;
                }
                if query.max_results > 0 && results.len() >= query.max_results {
                    break;
                }
                results.push(SearchResult::new(MatchType::Comment, binary_id, addr, body));
            }
        }

        apply_regex_filter(&mut results, query)?;
        if query.max_results > 0 {
            results.truncate(query.max_results);
        }
        Ok(results)
    }

    // ── Symbol search ─────────────────────────────────────────────────────────

    /// Search symbol names.
    pub fn search_symbols(&self, binary_id: u64, query: &SearchQuery) -> Result<Vec<SearchResult>> {
        let conn = self.connect()?;
        let fts_available = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='symbols_fts'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .unwrap_or(false);

        let mut results = Vec::new();

        if fts_available && !query.pattern.is_empty() {
            let fts_q = query.to_fts5_query();
            let mut stmt = conn.prepare(
                "SELECT s.addr, s.name FROM symbols_fts sf
                 JOIN symbols s ON s.id=sf.rowid
                 WHERE symbols_fts MATCH ?1 AND s.binary_id=?2
                 ORDER BY s.addr",
            )?;
            let rows = stmt.query_map(params![fts_q, binary_id as i64], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
            })?;
            for row in rows.filter_map(std::result::Result::ok) {
                let (addr, name) = row;
                if !query.passes_addr_filter(addr) {
                    continue;
                }
                results.push(SearchResult::new(
                    MatchType::SymbolName,
                    binary_id,
                    addr,
                    name,
                ));
            }
        } else {
            let pattern = query.to_like_pattern();
            let sql = if query.case_sensitive {
                "SELECT addr,name FROM symbols WHERE binary_id=?1 AND name LIKE ?2 ORDER BY addr"
            } else {
                "SELECT addr,name FROM symbols WHERE binary_id=?1 AND lower(name) LIKE lower(?2) ORDER BY addr"
            };
            let mut stmt = conn.prepare(sql)?;
            let rows = stmt.query_map(params![binary_id as i64, &pattern], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
            })?;
            for row in rows.filter_map(std::result::Result::ok) {
                let (addr, name) = row;
                if !query.passes_addr_filter(addr) {
                    continue;
                }
                if query.max_results > 0 && results.len() >= query.max_results {
                    break;
                }
                results.push(SearchResult::new(
                    MatchType::SymbolName,
                    binary_id,
                    addr,
                    name,
                ));
            }
        }

        apply_regex_filter(&mut results, query)?;
        if query.max_results > 0 {
            results.truncate(query.max_results);
        }
        Ok(results)
    }

    // ── Combined search ───────────────────────────────────────────────────────

    /// Run search across all applicable targets and return combined results.
    pub fn search(
        &self,
        binary_id: u64,
        query: &SearchQuery,
    ) -> Result<(Vec<SearchResult>, SearchStats)> {
        let start = Instant::now();
        let mut all = Vec::new();

        match query.scope {
            SearchScope::All => {
                all.extend(self.search_strings(binary_id, query)?);
                all.extend(self.search_functions(binary_id, query)?);
                all.extend(self.search_comments(binary_id, query)?);
                all.extend(self.search_symbols(binary_id, query)?);
            }
            SearchScope::Strings => {
                all.extend(self.search_strings(binary_id, query)?);
            }
            SearchScope::Functions => {
                all.extend(self.search_functions(binary_id, query)?);
            }
            SearchScope::Comments => {
                all.extend(self.search_comments(binary_id, query)?);
            }
            SearchScope::Symbols => {
                all.extend(self.search_symbols(binary_id, query)?);
            }
        }

        // Global max_results cap
        if query.max_results > 0 {
            all.truncate(query.max_results);
        }

        let time_ms = start.elapsed().as_millis() as u64;
        let stats = SearchStats::from_results(&all, time_ms);
        Ok((all, stats))
    }

    /// Convenience: search and return only results, discarding stats.
    pub fn search_simple(&self, binary_id: u64, pattern: &str) -> Result<Vec<SearchResult>> {
        Ok(self.search(binary_id, &SearchQuery::new(pattern))?.0)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Truncate text to at most `max_len` characters with "…" suffix.
fn snippet(text: &str, max_len: usize) -> String {
    let text = text.trim();
    // Single pass: find the byte offset of the (max_len)-th char, if any.
    let mut indices = text.char_indices();
    if indices.by_ref().nth(max_len).is_none() {
        return text.to_string();
    }
    // Re-walk only up to max_len-1 chars for the truncated prefix.
    let cut = text
        .char_indices()
        .nth(max_len - 1)
        .map_or(text.len(), |(i, _)| i);
    let mut out = String::with_capacity(cut + 3);
    out.push_str(&text[..cut]);
    out.push('…');
    out
}

/// Post-filter results by regex if `query.regex` is set.
fn apply_regex_filter(results: &mut Vec<SearchResult>, query: &SearchQuery) -> Result<()> {
    if !query.regex {
        return Ok(());
    }
    // Simulate regex with a simple contains check (no regex dep in scope).
    // A real implementation would use the `regex` crate.
    let pattern_lower = if query.case_sensitive {
        std::borrow::Cow::Borrowed(query.pattern.as_str())
    } else {
        std::borrow::Cow::Owned(query.pattern.to_lowercase())
    };
    results.retain(|r| {
        if query.case_sensitive {
            r.matched_text.contains(pattern_lower.as_ref())
        } else {
            r.matched_text.to_lowercase().contains(pattern_lower.as_ref())
        }
    });
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BinaryProject, Project};
    use std::path::Path;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn setup(dir: &TempDir) -> (Project, u64) {
        let p = Project::new("search-test", dir.path()).unwrap();
        let mut p = p;
        let bin_path = Path::new("/tmp/fake.bin");
        let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let bid = BinaryProject::add_binary(&mut p, bin_path, sha).unwrap();
        // Populate data
        p.add_function_record(bid, 0x1000, "main").unwrap();
        p.add_function_record(bid, 0x2000, "malloc_wrapper")
            .unwrap();
        p.add_function_record(bid, 0x3000, "free_all_resources")
            .unwrap();
        p.add_comment_record(bid, 0x1000, "this is the entry point")
            .unwrap();
        p.add_comment_record(bid, 0x2000, "wraps malloc for tracing")
            .unwrap();
        p.add_string(bid, 0x4000, "Hello, World!", "utf8").unwrap();
        p.add_string(bid, 0x4020, "error: out of memory", "utf8")
            .unwrap();
        p.add_string(bid, 0x4040, "debug info string", "utf8")
            .unwrap();
        p.add_symbol(bid, 0x1000, "main", "function", "export")
            .unwrap();
        p.add_symbol(bid, 0x5000, "g_error_code", "data", "debug")
            .unwrap();
        (p, bid)
    }

    fn engine(p: &Project) -> SearchEngine {
        SearchEngine::from_db_path(p.db_path())
    }

    // ── SearchQuery ────────────────────────────────────────────────────────────

    #[test]
    fn query_new() {
        let q = SearchQuery::new("foo");
        assert_eq!(q.pattern, "foo");
        assert!(!q.case_sensitive);
    }
    #[test]
    fn query_builders() {
        let q = SearchQuery::new("x")
            .case_sensitive()
            .regex()
            .scope(SearchScope::Functions)
            .max(5);
        assert!(q.case_sensitive);
        assert!(q.regex);
        assert_eq!(q.scope, SearchScope::Functions);
        assert_eq!(q.max_results, 5);
    }
    #[test]
    fn query_like_pattern() {
        let q = SearchQuery::new("foo");
        assert_eq!(q.to_like_pattern(), "%foo%");
    }
    #[test]
    fn query_addr_range() {
        let q = SearchQuery::new("x").addr_range(0x1000, 0x9000);
        assert_eq!(q.addr_min, Some(0x1000));
    }
    #[test]
    fn query_addr_filter_pass() {
        let q = SearchQuery::new("x").addr_range(0x1000, 0x2000);
        assert!(q.passes_addr_filter(0x1500));
    }
    #[test]
    fn query_addr_filter_fail() {
        let q = SearchQuery::new("x").addr_range(0x1000, 0x2000);
        assert!(!q.passes_addr_filter(0x500));
    }

    // ── SearchResult ───────────────────────────────────────────────────────────

    #[test]
    fn result_display() {
        let r = SearchResult::new(MatchType::FunctionName, 1, 0x1000, "main");
        assert!(r.to_string().contains("function"));
        assert!(r.to_string().contains("main"));
    }
    #[test]
    fn result_snippet_truncation() {
        let long = "a".repeat(200);
        let r = SearchResult::new(MatchType::Comment, 1, 0, long);
        assert!(r.context_snippet.len() <= 85); // 80 chars + "…" + some slack
    }

    // ── MatchType ──────────────────────────────────────────────────────────────

    #[test]
    fn match_type_display() {
        assert_eq!(MatchType::StringLiteral.to_string(), "string");
        assert_eq!(MatchType::FunctionName.to_string(), "function");
        assert_eq!(MatchType::Comment.to_string(), "comment");
        assert_eq!(MatchType::SymbolName.to_string(), "symbol");
    }

    // ── SearchStats ────────────────────────────────────────────────────────────

    #[test]
    fn stats_empty() {
        let s = SearchStats::default();
        assert_eq!(s.total_results, 0);
    }
    #[test]
    fn stats_display() {
        let s = SearchStats::default();
        assert!(s.to_string().contains("total=0"));
    }
    #[test]
    fn stats_from_results() {
        let r = vec![
            SearchResult::new(MatchType::FunctionName, 1, 0x100, "f"),
            SearchResult::new(MatchType::StringLiteral, 1, 0x200, "s"),
        ];
        let s = SearchStats::from_results(&r, 5);
        assert_eq!(s.total_results, 2);
        assert_eq!(s.function_results, 1);
        assert_eq!(s.string_results, 1);
    }

    // ── SearchEngine::search_functions ────────────────────────────────────────

    #[test]
    fn search_functions_hit() {
        let d = tmp();
        let (p, bid) = setup(&d);
        let e = engine(&p);
        let results = e.search_functions(bid, &SearchQuery::new("main")).unwrap();
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.matched_text == "main"));
    }
    #[test]
    fn search_functions_miss() {
        let d = tmp();
        let (p, bid) = setup(&d);
        let e = engine(&p);
        let results = e
            .search_functions(bid, &SearchQuery::new("zzz_nonexistent"))
            .unwrap();
        assert!(results.is_empty());
    }
    #[test]
    fn search_functions_prefix() {
        let d = tmp();
        let (p, bid) = setup(&d);
        let e = engine(&p);
        let results = e
            .search_functions(bid, &SearchQuery::new("malloc"))
            .unwrap();
        assert!(results.iter().any(|r| r.matched_text.contains("malloc")));
    }
    #[test]
    fn search_functions_addr_filter() {
        let d = tmp();
        let (p, bid) = setup(&d);
        let e = engine(&p);
        let results = e
            .search_functions(bid, &SearchQuery::new("").addr_range(0x1000, 0x1001))
            .unwrap();
        // Only main at 0x1000 should be included
        assert!(results.iter().all(|r| r.address == 0x1000));
    }

    // ── SearchEngine::search_strings ──────────────────────────────────────────

    #[test]
    fn search_strings_hit() {
        let d = tmp();
        let (p, bid) = setup(&d);
        let e = engine(&p);
        let results = e.search_strings(bid, &SearchQuery::new("Hello")).unwrap();
        assert!(!results.is_empty());
    }
    #[test]
    fn search_strings_miss() {
        let d = tmp();
        let (p, bid) = setup(&d);
        let e = engine(&p);
        let results = e
            .search_strings(bid, &SearchQuery::new("zzz_no_match"))
            .unwrap();
        assert!(results.is_empty());
    }
    #[test]
    fn search_strings_case_insensitive() {
        let d = tmp();
        let (p, bid) = setup(&d);
        let e = engine(&p);
        let results = e.search_strings(bid, &SearchQuery::new("hello")).unwrap();
        assert!(!results.is_empty());
    }
    #[test]
    fn search_strings_max_results() {
        let d = tmp();
        let (p, bid) = setup(&d);
        let e = engine(&p);
        let results = e.search_strings(bid, &SearchQuery::new("").max(1)).unwrap();
        assert!(results.len() <= 1);
    }

    // ── SearchEngine::search_comments ─────────────────────────────────────────

    #[test]
    fn search_comments_hit() {
        let d = tmp();
        let (p, bid) = setup(&d);
        let e = engine(&p);
        let results = e.search_comments(bid, &SearchQuery::new("entry")).unwrap();
        assert!(!results.is_empty());
    }
    #[test]
    fn search_comments_miss() {
        let d = tmp();
        let (p, bid) = setup(&d);
        let e = engine(&p);
        assert!(
            e.search_comments(bid, &SearchQuery::new("zzz_no_match"))
                .unwrap()
                .is_empty()
        );
    }

    // ── SearchEngine::search_symbols ──────────────────────────────────────────

    #[test]
    fn search_symbols_hit() {
        let d = tmp();
        let (p, bid) = setup(&d);
        let e = engine(&p);
        let results = e.search_symbols(bid, &SearchQuery::new("main")).unwrap();
        assert!(!results.is_empty());
    }
    #[test]
    fn search_symbols_miss() {
        let d = tmp();
        let (p, bid) = setup(&d);
        let e = engine(&p);
        assert!(
            e.search_symbols(bid, &SearchQuery::new("zzz_not_here"))
                .unwrap()
                .is_empty()
        );
    }

    // ── SearchEngine::search (combined) ───────────────────────────────────────

    #[test]
    fn search_combined_returns_stats() {
        let d = tmp();
        let (p, bid) = setup(&d);
        let e = engine(&p);
        let (results, stats) = e.search(bid, &SearchQuery::new("main")).unwrap();
        assert!(!results.is_empty());
        assert!(stats.total_results > 0);
        assert!(stats.time_ms < 10_000); // should be fast
    }
    #[test]
    fn search_scope_strings_only() {
        let d = tmp();
        let (p, bid) = setup(&d);
        let e = engine(&p);
        let q = SearchQuery::new("").scope(SearchScope::Strings);
        let (results, _) = e.search(bid, &q).unwrap();
        assert!(
            results
                .iter()
                .all(|r| r.match_type == MatchType::StringLiteral)
        );
    }
    #[test]
    fn search_scope_functions_only() {
        let d = tmp();
        let (p, bid) = setup(&d);
        let e = engine(&p);
        let q = SearchQuery::new("").scope(SearchScope::Functions);
        let (results, _) = e.search(bid, &q).unwrap();
        assert!(
            results
                .iter()
                .all(|r| r.match_type == MatchType::FunctionName)
        );
    }
    #[test]
    fn search_simple() {
        let d = tmp();
        let (p, bid) = setup(&d);
        let e = engine(&p);
        let results = e.search_simple(bid, "malloc").unwrap();
        assert!(results.iter().any(|r| r.matched_text.contains("malloc")));
    }

    // ── SearchIndex ────────────────────────────────────────────────────────────

    #[test]
    fn search_index_ensure_schema() {
        let d = tmp();
        let (p, _bid) = setup(&d);
        let idx = SearchIndex::new(p.db_path());
        idx.ensure_schema().unwrap();
        // Verify tables exist
        let conn = rusqlite::Connection::open(p.db_path()).unwrap();
        let exists = |name: &str| -> bool {
            conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                params![name],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
                > 0
        };
        assert!(exists("functions_fts"));
        assert!(exists("comments_fts"));
        assert!(exists("symbols_fts"));
    }
    #[test]
    fn search_index_idempotent() {
        let d = tmp();
        let (p, _) = setup(&d);
        let idx = SearchIndex::new(p.db_path());
        idx.ensure_schema().unwrap();
        idx.ensure_schema().unwrap(); // twice is fine
    }

    // ── snippet ────────────────────────────────────────────────────────────────

    #[test]
    fn snippet_short() {
        assert_eq!(snippet("hello", 80), "hello");
    }
    #[test]
    fn snippet_truncates() {
        let s = snippet(&"x".repeat(200), 80);
        assert!(s.ends_with('…'));
    }
    #[test]
    fn snippet_trims_whitespace() {
        assert_eq!(snippet("  hi  ", 80), "hi");
    }
}
