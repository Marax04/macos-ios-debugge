//! `VirusTotal` Intelligence search module.
//!
//! Provides `VtIntelSearch`, `SearchQuery`, `VtQueryBuilder`, and helpers
//! to parse `VirusTotal` Intelligence search responses.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Sort field
// ---------------------------------------------------------------------------

/// Sort order for `VirusTotal` Intelligence search results.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SortField {
    /// Sort by relevance descending (default).
    RelevanceDesc,
    /// Sort by file size ascending.
    SizeAsc,
    /// Sort by file size descending.
    SizeDesc,
    /// Sort by first-seen date ascending.
    DateAsc,
    /// Sort by first-seen date descending.
    DateDesc,
    /// Sort by AV positive count ascending.
    PositivesAsc,
    /// Sort by AV positive count descending.
    PositivesDesc,
}

impl SortField {
    /// Returns the string token used in the `VirusTotal` Intelligence API.
    #[must_use] 
    pub const fn as_api_str(&self) -> &'static str {
        match self {
            Self::RelevanceDesc => "relevance-",
            Self::SizeAsc => "size+",
            Self::SizeDesc => "size-",
            Self::DateAsc => "date+",
            Self::DateDesc => "date-",
            Self::PositivesAsc => "positives+",
            Self::PositivesDesc => "positives-",
        }
    }
}

impl fmt::Display for SortField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_api_str())
    }
}

// ---------------------------------------------------------------------------
// SearchQuery
// ---------------------------------------------------------------------------

/// A fully constructed `VirusTotal` Intelligence search query ready to send.
#[derive(Debug, Clone)]
pub struct SearchQuery {
    /// The VT intelligence query string (e.g. `type:peexe tag:packed positives:5+`).
    pub query_string: String,
    /// Pagination cursor returned by a previous search.
    pub cursor: Option<String>,
    /// Maximum number of results to return (1–300).
    pub limit: u32,
    /// Sort order.
    pub sort_by: SortField,
}

impl Default for SearchQuery {
    fn default() -> Self {
        Self {
            query_string: String::new(),
            cursor: None,
            limit: 20,
            sort_by: SortField::RelevanceDesc,
        }
    }
}

impl SearchQuery {
    /// Create a new `SearchQuery` with all fields specified.
    pub fn new(
        query_string: impl Into<String>,
        cursor: Option<String>,
        limit: u32,
        sort_by: SortField,
    ) -> Self {
        let limit = limit.clamp(1, 300);
        Self {
            query_string: query_string.into(),
            cursor,
            limit,
            sort_by,
        }
    }

    /// Convert to a URL query-parameter map.
    #[must_use] 
    pub fn to_params(&self) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("query".into(), self.query_string.clone());
        m.insert("limit".into(), self.limit.to_string());
        m.insert("order".into(), self.sort_by.as_api_str().to_owned());
        if let Some(c) = &self.cursor {
            m.insert("cursor".into(), c.clone());
        }
        m
    }

    /// Returns `true` if the query string is non-empty.
    #[must_use] 
    pub fn is_valid(&self) -> bool {
        !self.query_string.trim().is_empty()
    }
}

// ---------------------------------------------------------------------------
// SearchResult / SearchResponse
// ---------------------------------------------------------------------------

/// A single file entry returned from a `VirusTotal` Intelligence search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResult {
    /// SHA-256 hash of the file.
    pub sha256: String,
    /// `VirusTotal` file type label (e.g. `"PE32 executable"`).
    pub file_type: String,
    /// File size in bytes.
    pub size: u64,
    /// Number of AV engines that flagged this file.
    pub positives: u32,
    /// Unix timestamp of first submission.
    pub first_seen: u64,
    /// Unix timestamp of last submission.
    pub last_seen: u64,
    /// Known file names.
    pub names: Vec<String>,
    /// VT tags (e.g. `"packed"`, `"overlay"`, `"signed"`).
    pub tags: Vec<String>,
}

impl SearchResult {
    /// Returns `true` if the file is considered malicious (positives ≥ 5).
    #[must_use] 
    pub const fn is_malicious(&self) -> bool {
        self.positives >= 5
    }

    /// Returns the primary name or falls back to the truncated SHA-256.
    #[must_use] 
    pub fn display_name(&self) -> &str {
        self.names.first().map_or(&self.sha256[..16], std::string::String::as_str)
    }

    /// Returns the age of the file's first submission in seconds relative to `now`.
    #[must_use] 
    pub const fn age_seconds(&self, now: u64) -> u64 {
        now.saturating_sub(self.first_seen)
    }
}

/// A page of `VirusTotal` Intelligence search results.
#[derive(Debug, Clone)]
pub struct SearchResponse {
    /// File results in this page.
    pub results: Vec<SearchResult>,
    /// Cursor for the next page (absent when there are no more results).
    pub cursor: Option<String>,
    /// Total number of matching files (may be an estimate).
    pub total_hits: u64,
}

impl SearchResponse {
    /// Returns `true` if there is a next page.
    #[must_use] 
    pub const fn has_next_page(&self) -> bool {
        self.cursor.is_some()
    }

    /// Returns the number of results in this page.
    #[must_use] 
    pub const fn page_size(&self) -> usize {
        self.results.len()
    }

    /// Returns a slice of results that match the given predicate.
    pub fn filter<F>(&self, predicate: F) -> Vec<&SearchResult>
    where
        F: Fn(&SearchResult) -> bool,
    {
        self.results.iter().filter(|r| predicate(r)).collect()
    }

    /// Returns only malicious results.
    #[must_use] 
    pub fn malicious_only(&self) -> Vec<&SearchResult> {
        self.filter(SearchResult::is_malicious)
    }
}

// ---------------------------------------------------------------------------
// JSON parsing helpers
// ---------------------------------------------------------------------------

/// Parse a raw JSON string (from the VT API) into a `SearchResponse`.
///
/// Expected shape (VT v3):
/// ```json
/// {
///   "data": [ { "id": "<sha256>", "attributes": { ... } } ],
///   "meta": { "cursor": "...", "total_hits": 12345 }
/// }
/// ```
#[must_use] 
pub fn parse_search_response(json: &str) -> SearchResponse {
    parse_search_response_impl(json)
}

fn parse_search_response_impl(json: &str) -> SearchResponse {
    let mut results = Vec::new();
    let mut cursor: Option<String> = None;
    let mut total_hits: u64 = 0;

    // ── locate the "data" array ──────────────────────────────────────────────
    if let Some(data_start) = find_key_array(json, "\"data\"") {
        let items = split_json_array(&json[data_start..]);
        for item in &items {
            if let Some(result) = parse_search_item(item) {
                results.push(result);
            }
        }
    }

    // ── locate the "meta" object ─────────────────────────────────────────────
    if let Some(meta_str) = extract_object(json, "\"meta\"") {
        cursor = extract_string_field(&meta_str, "cursor");
        if let Some(th) = extract_number_field(&meta_str, "total_hits") {
            total_hits = th;
        }
    }

    SearchResponse {
        results,
        cursor,
        total_hits,
    }
}

fn parse_search_item(item: &str) -> Option<SearchResult> {
    let sha256 = extract_string_field(item, "id")?;
    let attrs = extract_object(item, "\"attributes\"")?;

    let file_type = extract_string_field(&attrs, "type_description").unwrap_or_default();
    let size = extract_number_field(&attrs, "size").unwrap_or(0);
    let positives = extract_number_field(&attrs, "last_analysis_stats.malicious")
        .or_else(|| extract_number_field(&attrs, "positives"))
        .unwrap_or(0) as u32;
    let first_seen = extract_number_field(&attrs, "first_submission_date").unwrap_or(0);
    let last_seen = extract_number_field(&attrs, "last_submission_date").unwrap_or(0);
    let names = extract_string_array(&attrs, "names");
    let tags = extract_string_array(&attrs, "tags");

    Some(SearchResult {
        sha256,
        file_type,
        size,
        positives,
        first_seen,
        last_seen,
        names,
        tags,
    })
}

// ---------------------------------------------------------------------------
// Minimal JSON extraction helpers (no external deps)
// ---------------------------------------------------------------------------

/// Find the byte offset of the opening `[` for the named key.
fn find_key_array(json: &str, key: &str) -> Option<usize> {
    let pos = json.find(key)?;
    let after_key = &json[pos + key.len()..];
    let colon_pos = after_key.find(':')?;
    let after_colon = &after_key[colon_pos + 1..];
    let bracket_pos = after_colon.find('[')?;
    Some(pos + key.len() + colon_pos + 1 + bracket_pos)
}

/// Extract the string value for a JSON field by key name.
fn extract_string_field(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let pos = json.find(&needle)?;
    let after = &json[pos + needle.len()..];
    let colon = after.find(':')?;
    let after_colon = after[colon + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let inner = &after_colon[1..];
    let end = find_unescaped_quote(inner)?;
    Some(inner[..end].replace("\\\"", "\"").replace("\\\\", "\\"))
}

/// Extract a numeric value for a JSON field.
fn extract_number_field(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\"");
    let pos = json.find(&needle)?;
    let after = &json[pos + needle.len()..];
    let colon = after.find(':')?;
    let after_colon = after[colon + 1..].trim_start();
    let num_str: String = after_colon
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    num_str.parse().ok()
}

/// Extract a JSON object value for the given key.
fn extract_object(json: &str, key: &str) -> Option<String> {
    let pos = json.find(key)?;
    let after = &json[pos + key.len()..];
    let colon = after.find(':')?;
    let after_colon = after[colon + 1..].trim_start();
    if !after_colon.starts_with('{') {
        return None;
    }
    let end = find_matching_brace(after_colon)?;
    Some(after_colon[..=end].to_owned())
}

/// Extract a JSON array of strings for the given key.
fn extract_string_array(json: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{key}\"");
    let pos = match json.find(&needle) {
        Some(p) => p,
        None => return Vec::new(),
    };
    let after = &json[pos + needle.len()..];
    let colon = match after.find(':') {
        Some(c) => c,
        None => return Vec::new(),
    };
    let after_colon = after[colon + 1..].trim_start();
    if !after_colon.starts_with('[') {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut rest = &after_colon[1..];
    while let Some(q) = rest.find('"') {
        rest = &rest[q + 1..];
        if let Some(end) = find_unescaped_quote(rest) {
            result.push(rest[..end].to_owned());
            rest = &rest[end + 1..];
        } else {
            break;
        }
        if let Some(next) = rest.find(|c: char| !c.is_whitespace())
            && rest.as_bytes()[next] == b']' {
                break;
            }
    }
    result
}

/// Split a `[...]` JSON array into its top-level item strings.
fn split_json_array(json: &str) -> Vec<String> {
    let start = match json.find('[') {
        Some(p) => p + 1,
        None => return Vec::new(),
    };
    let mut items = Vec::new();
    let bytes = json.as_bytes();
    let mut depth = 0i32;
    let mut item_start = start;
    let mut in_string = false;
    let mut escape = false;
    for (i, &b) in bytes[start..].iter().enumerate() {
        let i = i + start;
        if escape {
            escape = false;
            continue;
        }
        if in_string {
            if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
                if depth == 0 {
                    items.push(json[item_start..=i].trim().to_owned());
                    item_start = i + 1;
                }
            }
            b',' if depth == 0 => {
                let seg = json[item_start..i].trim();
                if !seg.is_empty() && seg != "," {
                    // we'll catch it on depth==0 close brace
                }
                item_start = i + 1;
            }
            _ => {}
        }
    }
    items
}

fn find_unescaped_quote(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
        } else if bytes[i] == b'"' {
            return Some(i);
        } else {
            i += 1;
        }
    }
    None
}

fn find_matching_brace(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    for (i, &b) in bytes.iter().enumerate() {
        if escape {
            escape = false;
            continue;
        }
        if in_string {
            if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

// ---------------------------------------------------------------------------
// VtQueryBuilder — fluent query construction
// ---------------------------------------------------------------------------

/// Fluent builder that constructs a `VirusTotal` Intelligence query string.
///
/// # Example
/// ```rust
/// use rustre_ti_vt::vt_intelligence_search::VtQueryBuilder;
///
/// let query = VtQueryBuilder::new()
///     .with_type("peexe")
///     .with_tag("packed")
///     .with_positives_gte(5)
///     .from_date(1_700_000_000)
///     .build();
/// assert!(query.contains("type:peexe"));
/// assert!(query.contains("tag:packed"));
/// assert!(query.contains("positives:5+"));
/// ```
#[derive(Debug, Default, Clone)]
pub struct VtQueryBuilder {
    clauses: Vec<String>,
}

impl VtQueryBuilder {
    /// Create a new, empty query builder.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict to a specific file type (e.g. `"peexe"`, `"pdf"`, `"zip"`).
    #[must_use] 
    pub fn with_type(mut self, file_type: &str) -> Self {
        self.clauses.push(format!("type:{file_type}"));
        self
    }

    /// Restrict to files that carry the given VT tag.
    #[must_use] 
    pub fn with_tag(mut self, tag: &str) -> Self {
        self.clauses.push(format!("tag:{tag}"));
        self
    }

    /// Restrict to files with at least `n` AV positives.
    #[must_use] 
    pub fn with_positives_gte(mut self, n: u32) -> Self {
        self.clauses.push(format!("positives:{n}+"));
        self
    }

    /// Restrict to files whose size is within `[min_bytes, max_bytes]`.
    #[must_use] 
    pub fn with_size_range(mut self, min_bytes: u64, max_bytes: u64) -> Self {
        self.clauses.push(format!("size:{min_bytes}+"));
        self.clauses.push(format!("size:{max_bytes}-"));
        self
    }

    /// Restrict to files with the given import hash.
    #[must_use] 
    pub fn with_imphash(mut self, imphash: &str) -> Self {
        self.clauses.push(format!("imphash:{imphash}"));
        self
    }

    /// Restrict to files similar to the given SHA-256 (VT similarity search).
    #[must_use] 
    pub fn with_similarity(mut self, sha256: &str) -> Self {
        self.clauses.push(format!("similar-to:{sha256}"));
        self
    }

    /// Restrict to files with a particular behavioural signature (sandbox tag).
    #[must_use] 
    pub fn with_behavior(mut self, behavior: &str) -> Self {
        self.clauses.push(format!("behavior:{behavior}"));
        self
    }

    /// Restrict to files first seen after the given Unix timestamp.
    #[must_use] 
    pub fn from_date(mut self, unix_ts: u64) -> Self {
        self.clauses.push(format!("fs:{unix_ts}+"));
        self
    }

    /// Restrict to files first seen before the given Unix timestamp.
    #[must_use] 
    pub fn to_date(mut self, unix_ts: u64) -> Self {
        self.clauses.push(format!("fs:{unix_ts}-"));
        self
    }

    /// Restrict to files matching the given PE export function name.
    #[must_use] 
    pub fn with_export(mut self, export_name: &str) -> Self {
        self.clauses.push(format!("exports:{export_name}"));
        self
    }

    /// Restrict to files whose main PE section name contains `section_name`.
    #[must_use] 
    pub fn with_section(mut self, section_name: &str) -> Self {
        self.clauses.push(format!("section:{section_name}"));
        self
    }

    /// Restrict to files submitted from the given country code (ISO 3166-1 alpha-2).
    #[must_use] 
    pub fn from_country(mut self, country: &str) -> Self {
        self.clauses
            .push(format!("submitter:country:{}", country.to_uppercase()));
        self
    }

    /// Restrict to files with the given SSDEEP cluster.
    #[must_use] 
    pub fn with_ssdeep(mut self, ssdeep: &str) -> Self {
        self.clauses.push(format!("ssdeep:{ssdeep}"));
        self
    }

    /// Append a raw clause verbatim (for advanced users).
    #[must_use] 
    pub fn raw(mut self, clause: &str) -> Self {
        self.clauses.push(clause.to_owned());
        self
    }

    /// Returns `true` if at least one clause has been added.
    #[must_use] 
    pub const fn has_clauses(&self) -> bool {
        !self.clauses.is_empty()
    }

    /// Returns the number of clauses currently in the builder.
    #[must_use] 
    pub const fn clause_count(&self) -> usize {
        self.clauses.len()
    }

    /// Build the final VT Intelligence query string.
    ///
    /// Clauses are joined with a single space, which is the VT AND operator.
    #[must_use] 
    pub fn build(&self) -> String {
        self.clauses.join(" ")
    }

    /// Build a `SearchQuery` with the given pagination and sort parameters.
    #[must_use] 
    pub fn build_query(
        &self,
        limit: u32,
        sort_by: SortField,
        cursor: Option<String>,
    ) -> SearchQuery {
        SearchQuery::new(self.build(), cursor, limit, sort_by)
    }
}

// ---------------------------------------------------------------------------
// VtIntelSearch — high-level search facade
// ---------------------------------------------------------------------------

/// High-level `VirusTotal` Intelligence search facade.
///
/// Wraps `SearchQuery` construction, response parsing, and result pagination
/// into a single cohesive API.
pub struct VtIntelSearch {
    /// API key used for authentication.
    pub api_key: String,
    /// Base URL (overridable for testing).
    pub base_url: String,
    /// Active search query (if any).
    current_query: Option<SearchQuery>,
    /// Accumulates all pages retrieved so far.
    collected_results: Vec<SearchResult>,
}

impl VtIntelSearch {
    /// Create a new `VtIntelSearch` instance.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: "https://www.virustotal.com/api/v3".to_owned(),
            current_query: None,
            collected_results: Vec::new(),
        }
    }

    /// Configure the search using a `VtQueryBuilder`.
    #[must_use] 
    pub fn with_query_builder(mut self, builder: &VtQueryBuilder, limit: u32) -> Self {
        self.current_query = Some(builder.build_query(limit, SortField::RelevanceDesc, None));
        self
    }

    /// Configure the search with a raw query string.
    #[must_use] 
    pub fn with_raw_query(mut self, query: &str, limit: u32) -> Self {
        self.current_query = Some(SearchQuery::new(
            query,
            None,
            limit,
            SortField::RelevanceDesc,
        ));
        self
    }

    /// Set the sort order for the search.
    #[must_use] 
    pub const fn sort_by(mut self, sort: SortField) -> Self {
        if let Some(q) = self.current_query.as_mut() {
            q.sort_by = sort;
        }
        self
    }

    /// Return the current query string (for inspection/debugging).
    #[must_use] 
    pub fn query_string(&self) -> Option<&str> {
        self.current_query.as_ref().map(|q| q.query_string.as_str())
    }

    /// Parse a raw JSON search response and store the results.
    ///
    /// Returns `true` if there may be a next page (cursor present).
    pub fn ingest_response(&mut self, raw_json: &str) -> bool {
        let resp = parse_search_response(raw_json);
        let has_next = resp.has_next_page();
        if let Some(q) = self.current_query.as_mut() {
            q.cursor = resp.cursor.clone();
        }
        self.collected_results.extend(resp.results);
        has_next
    }

    /// Returns a reference to all collected results so far.
    #[must_use] 
    pub fn results(&self) -> &[SearchResult] {
        &self.collected_results
    }

    /// Clears all collected results and resets the cursor.
    pub fn reset(&mut self) {
        self.collected_results.clear();
        if let Some(q) = self.current_query.as_mut() {
            q.cursor = None;
        }
    }

    /// Returns the current query, if any.
    #[must_use] 
    pub const fn current_query(&self) -> Option<&SearchQuery> {
        self.current_query.as_ref()
    }

    /// Returns `true` if the current query is valid (non-empty).
    #[must_use] 
    pub fn is_ready(&self) -> bool {
        self.current_query
            .as_ref()
            .is_some_and(SearchQuery::is_valid)
    }

    /// Summarise the collected results: counts, malicious fraction, etc.
    #[must_use] 
    pub fn summary(&self) -> SearchSummary {
        let total = self.collected_results.len() as u64;
        let malicious = self
            .collected_results
            .iter()
            .filter(|r| r.is_malicious())
            .count() as u64;
        let avg_positives = if total > 0 {
            self.collected_results.iter().map(|r| u64::from(r.positives)).sum::<u64>() as f64
                / total as f64
        } else {
            0.0
        };
        SearchSummary {
            total_collected: total,
            malicious_count: malicious,
            avg_positives,
        }
    }
}

/// Summary statistics over the collected search results.
#[derive(Debug, Clone)]
pub struct SearchSummary {
    /// Total number of results collected so far.
    pub total_collected: u64,
    /// Number of results with ≥ 5 positives.
    pub malicious_count: u64,
    /// Average number of AV positives.
    pub avg_positives: f64,
}

// ---------------------------------------------------------------------------
// Utility: build a VT intelligence search URL
// ---------------------------------------------------------------------------

/// Build a complete `VirusTotal` Intelligence search URL for the given query.
#[must_use] 
pub fn build_search_url(base: &str, query: &SearchQuery) -> String {
    let params = query.to_params();
    let mut parts: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, url_encode(v)))
        .collect();
    parts.sort(); // deterministic for tests
    format!("{}/intelligence/search?{}", base, parts.join("&"))
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(char::from_digit(u32::from(b >> 4), 16).unwrap());
                out.push(char::from_digit(u32::from(b & 0xf), 16).unwrap());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sort_field_api_str() {
        assert_eq!(SortField::RelevanceDesc.as_api_str(), "relevance-");
        assert_eq!(SortField::SizeAsc.as_api_str(), "size+");
        assert_eq!(SortField::PositivesDesc.as_api_str(), "positives-");
    }

    #[test]
    fn test_query_builder_basic() {
        let q = VtQueryBuilder::new()
            .with_type("peexe")
            .with_tag("packed")
            .with_positives_gte(5)
            .build();
        assert!(q.contains("type:peexe"));
        assert!(q.contains("tag:packed"));
        assert!(q.contains("positives:5+"));
    }

    #[test]
    fn test_query_builder_size_range() {
        let q = VtQueryBuilder::new().with_size_range(1024, 102_400).build();
        assert!(q.contains("size:1024+"));
        assert!(q.contains("size:102400-"));
    }

    #[test]
    fn test_query_builder_date_range() {
        let q = VtQueryBuilder::new()
            .from_date(1_700_000_000)
            .to_date(1_710_000_000)
            .build();
        assert!(q.contains("fs:1700000000+"));
        assert!(q.contains("fs:1710000000-"));
    }

    #[test]
    fn test_query_builder_similarity() {
        let sha = "abc123def456abc123def456abc123def456abc123def456abc123def456abc1";
        let q = VtQueryBuilder::new().with_similarity(sha).build();
        assert!(q.contains("similar-to:"));
    }

    #[test]
    fn test_query_builder_imphash() {
        let q = VtQueryBuilder::new()
            .with_imphash("d41d8cd98f00b204e9800998ecf8427e")
            .build();
        assert!(q.contains("imphash:d41d8cd98f00b204e9800998ecf8427e"));
    }

    #[test]
    fn test_query_builder_raw() {
        let q = VtQueryBuilder::new().raw("magic:\"MZ\"").build();
        assert_eq!(q, "magic:\"MZ\"");
    }

    #[test]
    fn test_search_query_clamp_limit() {
        let sq = SearchQuery::new("type:peexe", None, 999, SortField::SizeAsc);
        assert_eq!(sq.limit, 300);
        let sq2 = SearchQuery::new("type:peexe", None, 0, SortField::SizeAsc);
        assert_eq!(sq2.limit, 1);
    }

    #[test]
    fn test_search_query_params() {
        let sq = SearchQuery::new("type:pdf", None, 10, SortField::DateDesc);
        let p = sq.to_params();
        assert_eq!(p["query"], "type:pdf");
        assert_eq!(p["limit"], "10");
        assert_eq!(p["order"], "date-");
        assert!(!p.contains_key("cursor"));
    }

    #[test]
    fn test_search_query_is_valid() {
        assert!(!SearchQuery::default().is_valid());
        let sq = SearchQuery::new("type:peexe", None, 10, SortField::RelevanceDesc);
        assert!(sq.is_valid());
    }

    #[test]
    fn test_search_result_is_malicious() {
        let r = make_result(0);
        assert!(!r.is_malicious());
        let r2 = make_result(5);
        assert!(r2.is_malicious());
        let r3 = make_result(10);
        assert!(r3.is_malicious());
    }

    #[test]
    fn test_search_result_display_name() {
        let mut r = make_result(1);
        r.names = vec!["evil.exe".to_owned()];
        assert_eq!(r.display_name(), "evil.exe");

        let r2 = make_result(1);
        assert_eq!(r2.display_name().len(), 16);
    }

    #[test]
    fn test_search_response_has_next_page() {
        let resp = SearchResponse {
            results: vec![],
            cursor: Some("abc".to_owned()),
            total_hits: 100,
        };
        assert!(resp.has_next_page());

        let resp2 = SearchResponse {
            results: vec![],
            cursor: None,
            total_hits: 0,
        };
        assert!(!resp2.has_next_page());
    }

    #[test]
    fn test_search_response_malicious_only() {
        let results = vec![make_result(0), make_result(5), make_result(3), make_result(7)];
        let resp = SearchResponse {
            results,
            cursor: None,
            total_hits: 4,
        };
        let mal = resp.malicious_only();
        assert_eq!(mal.len(), 2);
        assert!(mal.iter().all(|r| r.is_malicious()));
    }

    #[test]
    fn test_parse_search_response_empty() {
        let json = r#"{"data":[],"meta":{"total_hits":0}}"#;
        let resp = parse_search_response(json);
        assert_eq!(resp.total_hits, 0);
        assert!(resp.results.is_empty());
    }

    #[test]
    fn test_vt_intel_search_summary() {
        let mut search = VtIntelSearch::new("test_key");
        search.collected_results = vec![make_result(0), make_result(10), make_result(6)];
        let summary = search.summary();
        assert_eq!(summary.total_collected, 3);
        assert_eq!(summary.malicious_count, 2);
        assert!((summary.avg_positives - (0.0 + 10.0 + 6.0) / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_vt_intel_search_reset() {
        let mut search = VtIntelSearch::new("k").with_raw_query("type:peexe", 20);
        search.collected_results = vec![make_result(1)];
        search.reset();
        assert!(search.collected_results.is_empty());
    }

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("type:peexe"), "type%3apeexe");
        assert_eq!(url_encode("hello world"), "hello+world");
        assert_eq!(url_encode("abc"), "abc");
    }

    #[test]
    fn test_build_search_url_contains_base() {
        let sq = SearchQuery::new("type:peexe", None, 10, SortField::RelevanceDesc);
        let url = build_search_url("https://www.virustotal.com/api/v3", &sq);
        assert!(url.starts_with("https://www.virustotal.com/api/v3/intelligence/search?"));
        assert!(url.contains("limit=10"));
    }

    // ── helpers ────────────────────────────────────────────────────────────────

    fn make_result(positives: u32) -> SearchResult {
        SearchResult {
            sha256: "a".repeat(64),
            file_type: "PE32".to_owned(),
            size: 12345,
            positives,
            first_seen: 1_700_000_000,
            last_seen: 1_710_000_000,
            names: Vec::new(),
            tags: Vec::new(),
        }
    }
}
