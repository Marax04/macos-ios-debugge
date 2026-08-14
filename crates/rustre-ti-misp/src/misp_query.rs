//! `misp_query.rs` — MISP event/attribute search and export pipeline.
//!
//! Provides:
//!   - [`MispQuery`] — fluent query builder for MISP REST API
//!   - [`EventFilter`] — filter by tag / date / org / threat level
//!   - [`AttributeFilter`] — filter by type / category / value
//!   - [`MispSearch`] — composite search combining both filters
//!   - [`SearchResult`] — paginated search results
//!   - [`ExportFormat`] — JSON / XML / CSV / STIX export
//!   - [`MispPagination`] — cursor-based pagination

use serde::{Deserialize, Serialize};

// ─── ExportFormat ─────────────────────────────────────────────────────────────

/// Supported export formats for MISP search results.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExportFormat {
    Json,
    Xml,
    Csv,
    Stix,
    Snort,
    Yara,
    Rpz,
    Text,
}

impl ExportFormat {
    /// Return the MIME type for this format.
    #[must_use]
    pub const fn mime_type(&self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Xml => "application/xml",
            Self::Csv => "text/csv",
            Self::Stix => "application/json",
            Self::Snort => "text/plain",
            Self::Yara => "text/plain",
            Self::Rpz => "text/plain",
            Self::Text => "text/plain",
        }
    }

    /// Return the file extension for this format.
    #[must_use]
    pub const fn extension(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Xml => "xml",
            Self::Csv => "csv",
            Self::Stix => "stix.json",
            Self::Snort => "rules",
            Self::Yara => "yar",
            Self::Rpz => "rpz",
            Self::Text => "txt",
        }
    }

    /// Return the MISP API endpoint segment for this format.
    #[must_use]
    pub const fn api_segment(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Xml => "xml",
            Self::Csv => "csv",
            Self::Stix => "stix2",
            Self::Snort => "snort",
            Self::Yara => "yara",
            Self::Rpz => "rpz",
            Self::Text => "text",
        }
    }
}

impl std::fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.api_segment())
    }
}

// ─── MispPagination ──────────────────────────────────────────────────────────

/// Cursor-based pagination parameters for MISP search requests.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MispPagination {
    /// Maximum number of items per page.
    pub page_size: usize,
    /// Current page number (1-based).
    pub page: usize,
    /// Cursor token returned by the server for the next page.
    pub cursor: Option<String>,
    /// Whether there are more pages available.
    pub has_next: bool,
    /// Total number of matching items (may be approximate).
    pub total: Option<usize>,
}

impl MispPagination {
    /// Create pagination for the first page with `page_size` items.
    #[must_use]
    pub const fn first_page(page_size: usize) -> Self {
        Self {
            page_size,
            page: 1,
            cursor: None,
            has_next: false,
            total: None,
        }
    }

    /// Advance to the next page using the given cursor.
    #[must_use]
    pub fn next(mut self, cursor: String) -> Self {
        self.page += 1;
        self.cursor = Some(cursor);
        self.has_next = true;
        self
    }

    /// Return the byte offset for limit/offset-style APIs.
    #[must_use]
    pub const fn offset(&self) -> usize {
        (self.page.saturating_sub(1)) * self.page_size
    }
}

// ─── EventFilter ─────────────────────────────────────────────────────────────

/// Filters for MISP event search.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventFilter {
    /// Filter by one or more tag names (all must match if multiple given).
    pub tags: Vec<String>,
    /// Exclude events with these tags.
    pub not_tags: Vec<String>,
    /// From date (`YYYY-MM-DD`).
    pub date_from: Option<String>,
    /// To date (`YYYY-MM-DD`).
    pub date_to: Option<String>,
    /// Filter by creator organisation name.
    pub org: Option<String>,
    /// Filter by threat level ID (1=High, 2=Medium, 3=Low, 4=Undefined).
    pub threat_level_id: Option<u8>,
    /// Filter by analysis status (0=Initial, 1=Ongoing, 2=Completed).
    pub analysis: Option<u8>,
    /// Restrict to these event IDs.
    pub event_ids: Vec<u64>,
    /// Filter by distribution level [0–5].
    pub distribution: Option<u8>,
    /// Whether to include only published events.
    pub published: Option<bool>,
    /// Free-text search on event info field.
    pub info_contains: Option<String>,
}

impl EventFilter {
    /// Create an empty filter (matches all events).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by a single tag.
    #[must_use]
    pub fn by_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Exclude a tag.
    #[must_use]
    pub fn not_tag(mut self, tag: impl Into<String>) -> Self {
        self.not_tags.push(tag.into());
        self
    }

    /// Filter by date range (inclusive).
    #[must_use]
    pub fn by_date(mut self, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.date_from = Some(from.into());
        self.date_to = Some(to.into());
        self
    }

    /// Filter by organisation.
    #[must_use]
    pub fn by_org(mut self, org: impl Into<String>) -> Self {
        self.org = Some(org.into());
        self
    }

    /// Filter by threat level.
    #[must_use]
    pub const fn by_threat_level(mut self, level: u8) -> Self {
        self.threat_level_id = Some(level);
        self
    }

    /// Filter to published events only.
    #[must_use]
    pub const fn published_only(mut self) -> Self {
        self.published = Some(true);
        self
    }

    /// Filter by free-text on the info field.
    #[must_use]
    pub fn info_contains(mut self, text: impl Into<String>) -> Self {
        self.info_contains = Some(text.into());
        self
    }

    /// Return `true` if this filter has no constraints (matches everything).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.tags.is_empty()
            && self.not_tags.is_empty()
            && self.date_from.is_none()
            && self.date_to.is_none()
            && self.org.is_none()
            && self.threat_level_id.is_none()
            && self.analysis.is_none()
            && self.event_ids.is_empty()
            && self.distribution.is_none()
            && self.published.is_none()
            && self.info_contains.is_none()
    }
}

// ─── AttributeFilter ─────────────────────────────────────────────────────────

/// Filters for MISP attribute search.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttributeFilter {
    /// Filter by attribute type (e.g. `"md5"`, `"ip-dst"`).
    pub type_: Option<String>,
    /// Filter by category (e.g. `"Payload delivery"`).
    pub category: Option<String>,
    /// Exact attribute value match.
    pub value: Option<String>,
    /// Partial value match.
    pub value_like: Option<String>,
    /// Only return `to_ids` attributes.
    pub to_ids: Option<bool>,
    /// Only return attributes with sightings.
    pub with_sightings: bool,
    /// Distribution level filter.
    pub distribution: Option<u8>,
    /// Tags on the attribute.
    pub tags: Vec<String>,
}

impl AttributeFilter {
    /// Create an empty attribute filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by type.
    #[must_use]
    pub fn by_type(mut self, t: impl Into<String>) -> Self {
        self.type_ = Some(t.into());
        self
    }

    /// Filter by category.
    #[must_use]
    pub fn by_category(mut self, cat: impl Into<String>) -> Self {
        self.category = Some(cat.into());
        self
    }

    /// Filter by exact value.
    #[must_use]
    pub fn by_value(mut self, v: impl Into<String>) -> Self {
        self.value = Some(v.into());
        self
    }

    /// Filter by partial value.
    #[must_use]
    pub fn value_like(mut self, pattern: impl Into<String>) -> Self {
        self.value_like = Some(pattern.into());
        self
    }

    /// Only return IDS-flagged attributes.
    #[must_use]
    pub const fn to_ids_only(mut self) -> Self {
        self.to_ids = Some(true);
        self
    }

    /// Require at least one sighting.
    #[must_use]
    pub const fn sighted(mut self) -> Self {
        self.with_sightings = true;
        self
    }
}

// ─── MispSearch ──────────────────────────────────────────────────────────────

/// Composite MISP search combining event and attribute filters.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MispSearch {
    /// Event-level filters.
    pub event_filter: EventFilter,
    /// Attribute-level filters.
    pub attribute_filter: AttributeFilter,
    /// Return format.
    pub format: Option<ExportFormat>,
    /// Pagination settings.
    pub pagination: MispPagination,
    /// Whether to include related events.
    pub include_related: bool,
    /// Whether to include galaxy clusters.
    pub include_galaxies: bool,
    /// Whether to include object attributes.
    pub include_objects: bool,
}

impl MispSearch {
    /// Create an empty search.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pagination: MispPagination::first_page(25),
            ..Default::default()
        }
    }

    /// Set the event filter.
    #[must_use]
    pub fn with_event_filter(mut self, ef: EventFilter) -> Self {
        self.event_filter = ef;
        self
    }

    /// Set the attribute filter.
    #[must_use]
    pub fn with_attribute_filter(mut self, af: AttributeFilter) -> Self {
        self.attribute_filter = af;
        self
    }

    /// Set the export format.
    #[must_use]
    pub const fn with_format(mut self, fmt: ExportFormat) -> Self {
        self.format = Some(fmt);
        self
    }

    /// Set pagination.
    #[must_use]
    pub fn with_pagination(mut self, pagination: MispPagination) -> Self {
        self.pagination = pagination;
        self
    }

    /// Include object attributes in the results.
    #[must_use]
    pub const fn include_objects(mut self) -> Self {
        self.include_objects = true;
        self
    }

    /// Include galaxy clusters.
    #[must_use]
    pub const fn include_galaxies(mut self) -> Self {
        self.include_galaxies = true;
        self
    }

    /// Convert this search to a MISP REST API query body (simplified JSON).
    #[must_use]
    pub fn to_query_body(&self) -> serde_json::Value {
        let mut body = serde_json::json!({});
        if !self.event_filter.tags.is_empty() {
            body["tags"] = serde_json::json!(self.event_filter.tags);
        }
        if let Some(ref dt) = self.event_filter.date_from {
            body["from"] = serde_json::json!(dt);
        }
        if let Some(ref dt) = self.event_filter.date_to {
            body["to"] = serde_json::json!(dt);
        }
        if let Some(ref org) = self.event_filter.org {
            body["org"] = serde_json::json!(org);
        }
        if let Some(tl) = self.event_filter.threat_level_id {
            body["threat_level_id"] = serde_json::json!(tl);
        }
        if let Some(ref t) = self.attribute_filter.type_ {
            body["type"] = serde_json::json!(t);
        }
        if let Some(ref v) = self.attribute_filter.value {
            body["value"] = serde_json::json!(v);
        }
        body["page"] = serde_json::json!(self.pagination.page);
        body["limit"] = serde_json::json!(self.pagination.page_size);
        body
    }
}

// ─── SearchResult ─────────────────────────────────────────────────────────────

/// A single MISP event returned by a search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchEventResult {
    /// Event numeric ID.
    pub id: u64,
    /// Event UUID.
    pub uuid: String,
    /// Event title.
    pub info: String,
    /// Date string.
    pub date: String,
    /// Threat level (1–4).
    pub threat_level_id: u8,
    /// Number of attributes.
    pub attribute_count: usize,
    /// Tags.
    pub tags: Vec<String>,
    /// Org name.
    pub org: String,
}

impl SearchEventResult {
    /// Return `true` if this event has a High threat level.
    #[must_use]
    pub const fn is_high_threat(&self) -> bool {
        self.threat_level_id == 1
    }

    /// Return `true` if this event has any of the given tags.
    #[must_use]
    pub fn has_any_tag(&self, tags: &[&str]) -> bool {
        tags.iter().any(|t| self.tags.iter().any(|tag| tag == t))
    }
}

/// Paginated container for search results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// Matching events.
    pub events: Vec<SearchEventResult>,
    /// Pagination metadata for the next page.
    pub pagination: MispPagination,
    /// The query that produced this result.
    pub query_info: String,
}

impl SearchResult {
    /// Return `true` if there are no results.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Return the number of results.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }

    /// Return all high-threat events.
    #[must_use]
    pub fn high_threat_events(&self) -> Vec<&SearchEventResult> {
        self.events.iter().filter(|e| e.is_high_threat()).collect()
    }

    /// Return the event with the most attributes.
    #[must_use]
    pub fn most_attributed(&self) -> Option<&SearchEventResult> {
        self.events.iter().max_by_key(|e| e.attribute_count)
    }
}

// ─── MispQuery ────────────────────────────────────────────────────────────────

/// Fluent MISP query builder and executor.
#[derive(Debug)]
pub struct MispQuery {
    /// Server base URL.
    pub server_url: String,
    /// API key.
    pub api_key: String,
    /// Verify TLS certificates.
    pub verify_ssl: bool,
    /// HTTP timeout.
    pub timeout_secs: u64,
}

impl MispQuery {
    /// Create a new query builder.
    #[must_use]
    pub fn new(server_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            api_key: api_key.into(),
            verify_ssl: true,
            timeout_secs: 30,
        }
    }

    /// Disable TLS certificate verification.
    #[must_use]
    pub const fn without_ssl_verify(mut self) -> Self {
        self.verify_ssl = false;
        self
    }

    /// Set the request timeout.
    #[must_use]
    pub const fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Execute a search (mock implementation).
    pub async fn execute(&self, search: &MispSearch) -> Result<SearchResult, String> {
        let count = search.pagination.page_size.min(3);
        let events: Vec<SearchEventResult> = (1..=count as u64)
            .map(|i| {
                let is_high_threat = search.event_filter.threat_level_id == Some(1);
                SearchEventResult {
                    id: i,
                    uuid: format!("00000000-0000-0000-0000-{i:012x}"),
                    info: format!("Mock Event {i}"),
                    date: "2024-01-15".to_string(),
                    threat_level_id: if is_high_threat { 1 } else { 4 },
                    attribute_count: (i as usize) * 3,
                    tags: search.event_filter.tags.clone(),
                    org: search
                        .event_filter
                        .org
                        .clone()
                        .unwrap_or_else(|| "TestOrg".to_string()),
                }
            })
            .collect();

        let mut pagination = search.pagination.clone();
        pagination.has_next = count > 0;

        Ok(SearchResult {
            events,
            pagination,
            query_info: format!("page={}", search.pagination.page),
        })
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Execute a search and export the results in the given format.
    pub async fn export(
        &self,
        search: &MispSearch,
        format: ExportFormat,
    ) -> Result<String, String> {
        let result = self.execute(search).await?;
        match format {
            ExportFormat::Json => {
                serde_json::to_string_pretty(&result.events)
                    .map_err(|e| e.to_string())
            }
            ExportFormat::Csv => {
                let mut csv = "id,uuid,info,date,threat_level_id,attribute_count\n".to_string();
                for ev in &result.events {
                    csv.push_str(&format!(
                        "{},{},{},{},{},{}\n",
                        ev.id,
                        ev.uuid,
                        ev.info,
                        ev.date,
                        ev.threat_level_id,
                        ev.attribute_count,
                    ));
                }
                Ok(csv)
            }
            ExportFormat::Text => {
                let mut text = String::new();
                for ev in &result.events {
                    text.push_str(&format!("[{}] {} ({})\n", ev.id, ev.info, ev.date));
                }
                Ok(text)
            }
            _ => Ok(format!("Export as {format} not implemented in mock")),
        }
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Quick lookup: find the first event that references the given value.
    pub async fn lookup_value(&self, value: &str) -> Result<Option<SearchEventResult>, String> {
        let search = MispSearch::new().with_attribute_filter(
            AttributeFilter::new().by_value(value),
        );
        let result = self.execute(&search).await?;
        Ok(result.events.into_iter().next())
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Get all events tagged with `tlp:red` or `tlp:amber` (sensitive intel).
    pub async fn sensitive_events(&self) -> Result<Vec<SearchEventResult>, String> {
        let ef = EventFilter::new()
            .by_tag("tlp:red")
            .by_threat_level(1);
        let search = MispSearch::new().with_event_filter(ef);
        let result = self.execute(&search).await?;
        Ok(result.events)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> MispQuery {
        MispQuery::new("https://misp.example.com", "test-key")
    }

    // ── ExportFormat ────────────────────────────────────────────────────────

    #[test]
    fn test_export_format_mime_json() {
        assert_eq!(ExportFormat::Json.mime_type(), "application/json");
    }

    #[test]
    fn test_export_format_mime_csv() {
        assert_eq!(ExportFormat::Csv.mime_type(), "text/csv");
    }

    #[test]
    fn test_export_format_extension() {
        assert_eq!(ExportFormat::Json.extension(), "json");
        assert_eq!(ExportFormat::Csv.extension(), "csv");
        assert_eq!(ExportFormat::Stix.extension(), "stix.json");
        assert_eq!(ExportFormat::Yara.extension(), "yar");
    }

    #[test]
    fn test_export_format_api_segment() {
        assert_eq!(ExportFormat::Snort.api_segment(), "snort");
        assert_eq!(ExportFormat::Stix.api_segment(), "stix2");
    }

    #[test]
    fn test_export_format_display() {
        assert_eq!(ExportFormat::Json.to_string(), "json");
        assert_eq!(ExportFormat::Xml.to_string(), "xml");
    }

    // ── MispPagination ──────────────────────────────────────────────────────

    #[test]
    fn test_pagination_first_page() {
        let p = MispPagination::first_page(25);
        assert_eq!(p.page, 1);
        assert_eq!(p.page_size, 25);
        assert!(!p.has_next);
    }

    #[test]
    fn test_pagination_offset() {
        let p = MispPagination::first_page(10);
        assert_eq!(p.offset(), 0);
        let p2 = p.next("cursor1".to_string());
        assert_eq!(p2.offset(), 10);
    }

    #[test]
    fn test_pagination_next() {
        let p = MispPagination::first_page(10).next("abc".to_string());
        assert_eq!(p.page, 2);
        assert_eq!(p.cursor.as_deref(), Some("abc"));
    }

    // ── EventFilter ─────────────────────────────────────────────────────────

    #[test]
    fn test_event_filter_empty() {
        let f = EventFilter::new();
        assert!(f.is_empty());
    }

    #[test]
    fn test_event_filter_by_tag() {
        let f = EventFilter::new().by_tag("malware");
        assert!(!f.is_empty());
        assert!(f.tags.contains(&"malware".to_string()));
    }

    #[test]
    fn test_event_filter_not_tag() {
        let f = EventFilter::new().not_tag("false-positive");
        assert!(f.not_tags.contains(&"false-positive".to_string()));
    }

    #[test]
    fn test_event_filter_by_date() {
        let f = EventFilter::new().by_date("2024-01-01", "2024-12-31");
        assert_eq!(f.date_from.as_deref(), Some("2024-01-01"));
        assert_eq!(f.date_to.as_deref(), Some("2024-12-31"));
    }

    #[test]
    fn test_event_filter_by_org() {
        let f = EventFilter::new().by_org("ACME");
        assert_eq!(f.org.as_deref(), Some("ACME"));
    }

    #[test]
    fn test_event_filter_by_threat_level() {
        let f = EventFilter::new().by_threat_level(1);
        assert_eq!(f.threat_level_id, Some(1));
    }

    #[test]
    fn test_event_filter_published_only() {
        let f = EventFilter::new().published_only();
        assert_eq!(f.published, Some(true));
    }

    #[test]
    fn test_event_filter_info_contains() {
        let f = EventFilter::new().info_contains("ransomware");
        assert_eq!(f.info_contains.as_deref(), Some("ransomware"));
    }

    // ── AttributeFilter ─────────────────────────────────────────────────────

    #[test]
    fn test_attribute_filter_by_type() {
        let f = AttributeFilter::new().by_type("md5");
        assert_eq!(f.type_.as_deref(), Some("md5"));
    }

    #[test]
    fn test_attribute_filter_by_category() {
        let f = AttributeFilter::new().by_category("Payload delivery");
        assert_eq!(f.category.as_deref(), Some("Payload delivery"));
    }

    #[test]
    fn test_attribute_filter_by_value() {
        let f = AttributeFilter::new().by_value("deadbeef");
        assert_eq!(f.value.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn test_attribute_filter_value_like() {
        let f = AttributeFilter::new().value_like("192.168.");
        assert_eq!(f.value_like.as_deref(), Some("192.168."));
    }

    #[test]
    fn test_attribute_filter_to_ids_only() {
        let f = AttributeFilter::new().to_ids_only();
        assert_eq!(f.to_ids, Some(true));
    }

    #[test]
    fn test_attribute_filter_sighted() {
        let f = AttributeFilter::new().sighted();
        assert!(f.with_sightings);
    }

    // ── MispSearch ──────────────────────────────────────────────────────────

    #[test]
    fn test_search_new_defaults() {
        let s = MispSearch::new();
        assert_eq!(s.pagination.page, 1);
        assert_eq!(s.pagination.page_size, 25);
        assert!(!s.include_objects);
    }

    #[test]
    fn test_search_with_format() {
        let s = MispSearch::new().with_format(ExportFormat::Stix);
        assert_eq!(s.format, Some(ExportFormat::Stix));
    }

    #[test]
    fn test_search_include_objects() {
        let s = MispSearch::new().include_objects();
        assert!(s.include_objects);
    }

    #[test]
    fn test_search_include_galaxies() {
        let s = MispSearch::new().include_galaxies();
        assert!(s.include_galaxies);
    }

    #[test]
    fn test_search_to_query_body_has_page() {
        let s = MispSearch::new();
        let body = s.to_query_body();
        assert!(body["page"].is_number());
    }

    #[test]
    fn test_search_to_query_body_tags() {
        let s = MispSearch::new()
            .with_event_filter(EventFilter::new().by_tag("ransomware"));
        let body = s.to_query_body();
        assert!(body["tags"].is_array());
    }

    // ── SearchResult ────────────────────────────────────────────────────────

    #[test]
    fn test_search_result_is_empty() {
        let r = SearchResult {
            events: vec![],
            pagination: MispPagination::first_page(10),
            query_info: "test".to_string(),
        };
        assert!(r.is_empty());
    }

    #[test]
    fn test_search_result_high_threat() {
        let r = SearchResult {
            events: vec![
                SearchEventResult {
                    id: 1,
                    uuid: "uuid".to_string(),
                    info: "high threat".to_string(),
                    date: "2024-01-01".to_string(),
                    threat_level_id: 1,
                    attribute_count: 5,
                    tags: vec![],
                    org: "Org".to_string(),
                },
                SearchEventResult {
                    id: 2,
                    uuid: "uuid2".to_string(),
                    info: "low threat".to_string(),
                    date: "2024-01-01".to_string(),
                    threat_level_id: 3,
                    attribute_count: 2,
                    tags: vec![],
                    org: "Org".to_string(),
                },
            ],
            pagination: MispPagination::first_page(10),
            query_info: "test".to_string(),
        };
        assert_eq!(r.high_threat_events().len(), 1);
    }

    #[test]
    fn test_search_result_most_attributed() {
        let r = SearchResult {
            events: vec![
                SearchEventResult {
                    id: 1,
                    uuid: "u1".to_string(),
                    info: "e1".to_string(),
                    date: "2024-01-01".to_string(),
                    threat_level_id: 4,
                    attribute_count: 10,
                    tags: vec![],
                    org: "Org".to_string(),
                },
                SearchEventResult {
                    id: 2,
                    uuid: "u2".to_string(),
                    info: "e2".to_string(),
                    date: "2024-01-01".to_string(),
                    threat_level_id: 4,
                    attribute_count: 30,
                    tags: vec![],
                    org: "Org".to_string(),
                },
            ],
            pagination: MispPagination::first_page(10),
            query_info: String::new(),
        };
        assert_eq!(r.most_attributed().unwrap().id, 2);
    }

    // ── MispQuery ───────────────────────────────────────────────────────────

    #[test]
    fn test_query_new() {
        let q = query();
        assert!(q.server_url.contains("misp"));
        assert!(q.verify_ssl);
    }

    #[test]
    fn test_query_without_ssl() {
        let q = query().without_ssl_verify();
        assert!(!q.verify_ssl);
    }

    #[test]
    fn test_query_with_timeout() {
        let q = query().with_timeout(60);
        assert_eq!(q.timeout_secs, 60);
    }

    #[tokio::test]
    async fn test_execute_returns_events() {
        let search = MispSearch::new();
        let result = query().execute(&search).await.unwrap();
        assert!(!result.is_empty());
    }

    #[tokio::test]
    async fn test_execute_threat_level_filter() {
        let search = MispSearch::new()
            .with_event_filter(EventFilter::new().by_threat_level(1));
        let result = query().execute(&search).await.unwrap();
        assert!(result.events.iter().all(|e| e.threat_level_id == 1));
    }

    #[tokio::test]
    async fn test_export_csv() {
        let search = MispSearch::new();
        let csv = query().export(&search, ExportFormat::Csv).await.unwrap();
        assert!(csv.contains("id,uuid,info"));
    }

    #[tokio::test]
    async fn test_export_json() {
        let search = MispSearch::new();
        let json = query().export(&search, ExportFormat::Json).await.unwrap();
        assert!(json.starts_with('['));
    }

    #[tokio::test]
    async fn test_export_text() {
        let search = MispSearch::new();
        let text = query().export(&search, ExportFormat::Text).await.unwrap();
        assert!(text.contains("Mock Event"));
    }

    #[tokio::test]
    async fn test_lookup_value() {
        let result = query().lookup_value("deadbeef1234").await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_sensitive_events() {
        let events = query().sensitive_events().await.unwrap();
        assert!(!events.is_empty());
        assert!(events.iter().all(|e| e.threat_level_id == 1));
    }
}
