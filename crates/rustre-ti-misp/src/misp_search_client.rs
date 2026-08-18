//! MISP restSearch client: typed request/response builder, pagination support,
//! attribute-level and event-level search, and batch lookups.
//!
//! Provides `MispSearchClient`, `SearchRequest`, `SearchResponse`, and the
//! `search_by_value()` convenience function.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

// ── SearchFormat ──────────────────────────────────────────────────────────────

/// Output format requested from the MISP restSearch endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum SearchFormat {
    /// Full JSON output (default).
    #[default]
    Json,
    /// Lightweight attribute CSV.
    Csv,
    /// MISP XML export.
    Xml,
    /// `OpenIOC` format.
    Openioc,
    /// STIX 2.x JSON.
    Stix2,
    /// Plain text list of `IoC` values.
    Text,
    /// MISP native binary blob.
    Cache,
}


impl SearchFormat {
    /// Return the string accepted by the MISP API.
    #[must_use]
    pub const fn as_api_str(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Xml => "xml",
            Self::Openioc => "openioc",
            Self::Stix2 => "stix2",
            Self::Text => "text",
            Self::Cache => "cache",
        }
    }
}

// ── SearchController ──────────────────────────────────────────────────────────

/// Whether to search events or attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum SearchController {
    /// Search MISP events.
    Events,
    /// Search MISP attributes.
    #[default]
    Attributes,
    /// Search MISP objects.
    Objects,
}


// ── SearchRequest ─────────────────────────────────────────────────────────────

/// A typed request for the MISP `/events/restSearch` or
/// `/attributes/restSearch` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SearchRequest {
    /// Free-text value search. Supports `%` wildcard.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Second value for composite attribute search (e.g. `filename|sha256`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value2: Option<String>,
    /// Filter by attribute type string.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_attribute: Option<String>,
    /// Filter by attribute category.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Organisation name or ID filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// Tags that must all match (AND logic).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tags: Vec<String>,
    /// Tags to exclude.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub not_tags: Vec<String>,
    /// Event IDs to limit the search to.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub event_id: Vec<u64>,
    /// Search from this date (YYYY-MM-DD or relative, e.g. `"7d"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Search until this date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Only return IDS-flagged attributes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_ids: Option<bool>,
    /// Filter by threat level (1=High … 4=Undefined).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_level_id: Option<u8>,
    /// Filter by analysis status (0=Initial, 1=Ongoing, 2=Completed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis: Option<u8>,
    /// Whether to include soft-deleted attributes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
    /// Include event context in attribute results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_event_meta: Option<bool>,
    /// Maximum number of results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    /// Pagination page number (1-based).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<usize>,
    /// Output format (default: `"json"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_format: Option<String>,
    /// UUID of events to restrict search to.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub event_uuid: Vec<String>,
    /// Include related attributes in the result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_correlations: Option<bool>,
    /// Enforce a specific distribution level minimum.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distribution: Option<u8>,
    /// Additional key=value parameters forwarded verbatim.
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl SearchRequest {
    /// Create a blank search request.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by a single attribute value.
    #[must_use]
    pub fn with_value(mut self, v: impl Into<String>) -> Self {
        self.value = Some(v.into());
        self
    }

    /// Filter by attribute type.
    #[must_use]
    pub fn with_type(mut self, t: impl Into<String>) -> Self {
        self.type_attribute = Some(t.into());
        self
    }

    /// Filter by category.
    #[must_use]
    pub fn with_category(mut self, c: impl Into<String>) -> Self {
        self.category = Some(c.into());
        self
    }

    /// Add a required tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Add an excluded tag.
    #[must_use]
    pub fn without_tag(mut self, tag: impl Into<String>) -> Self {
        self.not_tags.push(tag.into());
        self
    }

    /// Set a date range.
    #[must_use]
    pub fn with_date_range(mut self, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.from = Some(from.into());
        self.to = Some(to.into());
        self
    }

    /// Set a relative time window (e.g. `"7d"`, `"1h"`).
    #[must_use]
    pub fn within_last(mut self, interval: impl Into<String>) -> Self {
        self.from = Some(interval.into());
        self
    }

    /// Set the result limit.
    #[must_use]
    pub const fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set the page number.
    #[must_use]
    pub const fn with_page(mut self, page: usize) -> Self {
        self.page = Some(page);
        self
    }

    /// Request only IDS-enabled attributes.
    #[must_use]
    pub const fn ids_only(mut self) -> Self {
        self.to_ids = Some(true);
        self
    }

    /// Filter by threat level.
    #[must_use]
    pub const fn with_threat_level(mut self, level: u8) -> Self {
        self.threat_level_id = Some(level);
        self
    }

    /// Set the output format.
    #[must_use]
    pub fn with_format(mut self, fmt: SearchFormat) -> Self {
        self.return_format = Some(fmt.as_api_str().to_string());
        self
    }

    /// Include event metadata in attribute results.
    #[must_use]
    pub const fn include_event_meta(mut self) -> Self {
        self.include_event_meta = Some(true);
        self
    }

    /// Include event metadata and correlations.
    #[must_use]
    pub const fn include_correlations(mut self) -> Self {
        self.include_correlations = Some(true);
        self
    }

    /// Restrict to specific event IDs.
    #[must_use]
    pub fn for_events(mut self, ids: impl IntoIterator<Item = u64>) -> Self {
        self.event_id.extend(ids);
        self
    }

    /// Restrict to specific event UUIDs.
    #[must_use]
    pub fn for_event_uuids(mut self, uuids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.event_uuid.extend(uuids.into_iter().map(Into::into));
        self
    }

    /// Convert to the JSON body expected by MISP's `POST /attributes/restSearch`.
    ///
    /// Wraps in the `{"request": {...}}` envelope.
    #[must_use]
    pub fn to_json_body(&self) -> serde_json::Value {
        let inner = serde_json::to_value(self).unwrap_or_default();
        serde_json::json!({ "request": inner })
    }

    /// Validate the request and return the first error found.
    #[must_use]
    pub fn validate(&self) -> Option<String> {
        if let Some(tl) = self.threat_level_id
            && !(1..=4).contains(&tl) {
                return Some(format!("threat_level_id must be 1-4, got {tl}"));
            }
        if let Some(a) = self.analysis
            && a > 2 {
                return Some(format!("analysis must be 0-2, got {a}"));
            }
        if let Some(lim) = self.limit
            && lim == 0 {
                return Some("limit must be > 0".to_string());
            }
        None
    }
}

// ── AttributeResult ───────────────────────────────────────────────────────────

/// A single attribute returned by the MISP search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeResult {
    /// Numeric attribute ID.
    pub id: u64,
    /// UUID.
    pub uuid: String,
    /// Attribute type string.
    #[serde(rename = "type")]
    pub type_: String,
    /// Attribute value.
    pub value: String,
    /// Category.
    pub category: String,
    /// Whether this attribute is IDS-flagged.
    pub to_ids: bool,
    /// Event ID this attribute belongs to.
    pub event_id: u64,
    /// Timestamp.
    pub timestamp: u64,
    /// Optional comment.
    pub comment: Option<String>,
    /// MISP tags on this attribute.
    #[serde(default)]
    pub tags: Vec<TagResult>,
    /// Correlation count.
    #[serde(default)]
    pub correlation_count: u32,
}

impl AttributeResult {
    /// Return whether this attribute has correlations.
    #[must_use]
    pub const fn has_correlations(&self) -> bool {
        self.correlation_count > 0
    }

    /// Return the first tag that starts with `prefix`.
    #[must_use]
    pub fn first_tag_with_prefix(&self, prefix: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|t| t.name.starts_with(prefix))
            .map(|t| t.name.as_str())
    }
}

/// A tag record inside a search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagResult {
    /// Tag name.
    pub name: String,
    /// Colour (hex string).
    pub colour: String,
    /// Whether this tag is exportable.
    pub exportable: bool,
}

// ── EventResult ───────────────────────────────────────────────────────────────

/// A lightweight event record returned by an event-level search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventResult {
    /// Numeric event ID.
    pub id: u64,
    /// UUID.
    pub uuid: String,
    /// Event title.
    pub info: String,
    /// Date string.
    pub date: String,
    /// Threat level ID.
    pub threat_level_id: u8,
    /// Analysis status.
    pub analysis: u8,
    /// Distribution level.
    pub distribution: u8,
    /// Attribute count.
    #[serde(default)]
    pub attribute_count: u32,
    /// Tags on this event.
    #[serde(default)]
    pub tags: Vec<TagResult>,
    /// Timestamp.
    pub timestamp: u64,
}

impl EventResult {
    /// Return `true` if the event has a high or medium threat level.
    #[must_use]
    pub const fn is_high_threat(&self) -> bool {
        self.threat_level_id <= 2
    }

    /// Return `true` if the analysis is complete.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.analysis == 2
    }
}

// ── SearchResponse ────────────────────────────────────────────────────────────

/// The deserialized response from a MISP restSearch query.
#[derive(Debug, Clone)]
pub struct SearchResponse {
    /// Attribute-level results (for attribute searches).
    pub attributes: Vec<AttributeResult>,
    /// Event-level results (for event searches).
    pub events: Vec<EventResult>,
    /// Total results matching the query (may exceed page size).
    pub total_count: usize,
    /// Whether more pages of results are available.
    pub has_more: bool,
    /// The page number of this response.
    pub page: usize,
    /// Raw response body for formats other than JSON.
    pub raw: Option<String>,
}

impl SearchResponse {
    /// Create an empty response.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            attributes: Vec::new(),
            events: Vec::new(),
            total_count: 0,
            has_more: false,
            page: 1,
            raw: None,
        }
    }

    /// Return all unique values from the attribute results.
    #[must_use]
    pub fn unique_values(&self) -> Vec<&str> {
        let mut seen = std::collections::HashSet::new();
        self.attributes
            .iter()
            .filter_map(|a| {
                if seen.insert(a.value.as_str()) {
                    Some(a.value.as_str())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return only IDS-flagged attributes.
    #[must_use]
    pub fn ids_attributes(&self) -> Vec<&AttributeResult> {
        self.attributes.iter().filter(|a| a.to_ids).collect()
    }

    /// Group attributes by their event ID.
    #[must_use]
    pub fn group_by_event(&self) -> HashMap<u64, Vec<&AttributeResult>> {
        let mut map: HashMap<u64, Vec<&AttributeResult>> = HashMap::new();
        for attr in &self.attributes {
            map.entry(attr.event_id).or_default().push(attr);
        }
        map
    }

    /// Return all tag names seen across all attribute results.
    #[must_use]
    pub fn all_tags(&self) -> Vec<&str> {
        let mut tags: Vec<&str> = self
            .attributes
            .iter()
            .flat_map(|a| a.tags.iter().map(|t| t.name.as_str()))
            .collect();
        tags.sort_unstable();
        tags.dedup();
        tags
    }

    /// Return the count of attributes with correlations.
    #[must_use]
    pub fn correlated_count(&self) -> usize {
        self.attributes.iter().filter(|a| a.has_correlations()).count()
    }
}

// ── SearchPager ───────────────────────────────────────────────────────────────

/// Pagination helper for iterating through large result sets.
pub struct SearchPager {
    request: SearchRequest,
    page: usize,
    page_size: usize,
    exhausted: bool,
}

impl SearchPager {
    /// Create a pager over the given request.
    #[must_use]
    pub const fn new(mut request: SearchRequest, page_size: usize) -> Self {
        request.limit = Some(page_size);
        request.page = Some(1);
        Self {
            request,
            page: 1,
            page_size,
            exhausted: false,
        }
    }

    /// Return the next page request, or `None` if all pages have been fetched.
    #[must_use]
    pub fn next_request(&mut self) -> Option<SearchRequest> {
        if self.exhausted {
            return None;
        }
        let mut req = self.request.clone();
        req.page = Some(self.page);
        self.page += 1;
        Some(req)
    }

    /// Mark the pager as exhausted (no more pages).
    pub const fn mark_exhausted(&mut self) {
        self.exhausted = true;
    }

    #[must_use]
    pub const fn current_page(&self) -> usize {
        let p = self.page.saturating_sub(1);
        if p > 1 { p } else { 1 }
    }

    /// Return the page size.
    #[must_use]
    pub const fn page_size(&self) -> usize {
        self.page_size
    }

    /// Return whether more pages are available.
    #[must_use]
    pub const fn has_more(&self) -> bool {
        !self.exhausted
    }
}

// ── MispSearchClient ──────────────────────────────────────────────────────────

/// High-level MISP search client wrapping the restSearch API.
///
/// Provides typed request construction, pagination, and mock responses
/// for testing without a live MISP instance.
pub struct MispSearchClient {
    /// Base URL of the MISP instance.
    pub base_url: String,
    /// Authentication key.
    pub api_key: String,
    /// HTTP timeout.
    pub timeout: Duration,
    /// Whether to verify TLS certificates.
    pub verify_tls: bool,
    /// Default page size for paginated searches.
    pub default_page_size: usize,
}

impl MispSearchClient {
    /// Create a new client.
    #[must_use]
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: api_key.into(),
            timeout: Duration::from_secs(30),
            verify_tls: true,
            default_page_size: 100,
        }
    }

    /// Disable TLS verification (development/self-signed certs).
    #[must_use]
    pub const fn without_tls_verify(mut self) -> Self {
        self.verify_tls = false;
        self
    }

    /// Set the HTTP timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the default page size for paginated searches.
    #[must_use]
    pub const fn with_page_size(mut self, size: usize) -> Self {
        self.default_page_size = size;
        self
    }

    /// Build the URL for a restSearch request.
    #[must_use]
    pub fn search_url(&self, controller: SearchController) -> String {
        let ctl = match controller {
            SearchController::Events => "events",
            SearchController::Attributes => "attributes",
            SearchController::Objects => "objects",
        };
        format!("{}/{}/restSearch", self.base_url.trim_end_matches('/'), ctl)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Execute a search against the configured MISP instance.
    ///
    /// This type builds and validates the request but has no HTTP transport of
    /// its own, so a search cannot be answered here.  It used to return
    /// deterministic sample attributes/events — complete with `to_ids` flags,
    /// `tlp:red` tags and correlation counts — as if they had matched.
    ///
    /// The real search is [`crate::client::MispClient::search_by_ioc`].
    ///
    /// # Errors
    ///
    /// Returns the validation error for a malformed request, otherwise a
    /// message naming the required network lookup.
    pub async fn search(
        &self,
        request: &SearchRequest,
        controller: SearchController,
    ) -> Result<SearchResponse, String> {
        if let Some(err) = request.validate() {
            return Err(err);
        }
        let _ = controller;
        Err(format!(
            "network lookup required: MispSearchClient builds requests for {} but has no \
             HTTP transport; no results were produced and none were invented. Use \
             crate::client::MispClient against a reachable instance.",
            self.search_url(controller)
        ))
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Convenience function: search attributes by a single value.
    ///
    /// Returns all attributes matching `value` (across all types).
    pub async fn search_by_value(&self, value: &str) -> Result<SearchResponse, String> {
        let req = SearchRequest::new().with_value(value).with_limit(100);
        self.search(&req, SearchController::Attributes).await
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Convenience function: search by value and type.
    pub async fn search_by_value_and_type(
        &self,
        value: &str,
        type_str: &str,
    ) -> Result<SearchResponse, String> {
        let req = SearchRequest::new()
            .with_value(value)
            .with_type(type_str)
            .with_limit(100);
        self.search(&req, SearchController::Attributes).await
    }

    /// Batch-search multiple values, returning one response per value.
    pub async fn batch_search_by_values(
        &self,
        values: &[&str],
    ) -> Vec<Result<SearchResponse, String>> {
        let mut results = Vec::with_capacity(values.len());
        for &v in values {
            results.push(self.search_by_value(v).await);
        }
        results
    }

    /// Return a pager for iterating over large attribute search results.
    #[must_use]
    pub const fn paginate(&self, request: SearchRequest) -> SearchPager {
        SearchPager::new(request, self.default_page_size)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Fetch all pages for the given request, accumulating results.
    pub async fn search_all(
        &self,
        request: SearchRequest,
        controller: SearchController,
    ) -> Result<SearchResponse, String> {
        let mut pager = self.paginate(request);
        let mut combined = SearchResponse::empty();

        while let Some(page_req) = pager.next_request() {
            let resp = self.search(&page_req, controller).await?;
            let page_len = resp.attributes.len() + resp.events.len();
            combined.attributes.extend(resp.attributes);
            combined.events.extend(resp.events);
            combined.total_count += page_len;
            if page_len < pager.page_size() {
                pager.mark_exhausted();
            }
        }

        Ok(combined)
    }

    // ── Synthetic response builder (fixtures, never a search result) ─────────

    /// Build a SYNTHETIC [`SearchResponse`] shaped like a MISP reply.
    ///
    /// Every field is generated from the request and an index counter; it
    /// matches nothing and describes nothing.  It exists so the pagination and
    /// response-handling code can be tested without a MISP instance, and is
    /// deliberately no longer reachable from [`Self::search`].
    #[must_use]
    pub fn mock_response(&self, req: &SearchRequest, controller: SearchController) -> SearchResponse {
        let limit = req.limit.unwrap_or(10).min(20);
        match controller {
            SearchController::Attributes => {
                let value = req.value.clone().unwrap_or_else(|| "test-value".to_string());
                let type_str = req
                    .type_attribute
                    .clone()
                    .unwrap_or_else(|| "sha256".to_string());
                let attrs: Vec<AttributeResult> = (1..=limit as u64)
                    .map(|i| AttributeResult {
                        id: i,
                        uuid: format!("attr-uuid-{i:04x}"),
                        type_: type_str.clone(),
                        value: format!("{value}-{i}"),
                        category: "Payload delivery".to_string(),
                        to_ids: i % 2 == 0,
                        event_id: (i % 5) + 1,
                        timestamp: 1_700_000_000 + i * 3600,
                        comment: (i % 3 == 0).then(|| format!("Mock comment {i}")),
                        tags: if i % 4 == 0 {
                            vec![TagResult {
                                name: "tlp:red".to_string(),
                                colour: "#FF0000".to_string(),
                                exportable: false,
                            }]
                        } else {
                            vec![]
                        },
                        correlation_count: (i % 3) as u32,
                    })
                    .collect();
                let total = attrs.len();
                SearchResponse {
                    attributes: attrs,
                    events: vec![],
                    total_count: total,
                    has_more: total >= limit,
                    page: req.page.unwrap_or(1),
                    raw: None,
                }
            }
            SearchController::Events => {
                let events: Vec<EventResult> = (1..=limit as u64)
                    .map(|i| EventResult {
                        id: i,
                        uuid: format!("event-uuid-{i:04x}"),
                        info: format!("Mock Event {i}"),
                        date: "2024-01-15".to_string(),
                        threat_level_id: ((i % 4) + 1) as u8,
                        analysis: (i % 3) as u8,
                        distribution: 1,
                        attribute_count: (i * 5) as u32,
                        tags: vec![],
                        timestamp: 1_700_000_000 + i * 86400,
                    })
                    .collect();
                let total = events.len();
                SearchResponse {
                    attributes: vec![],
                    events,
                    total_count: total,
                    has_more: total >= limit,
                    page: req.page.unwrap_or(1),
                    raw: None,
                }
            }
            SearchController::Objects => SearchResponse::empty(),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> MispSearchClient {
        MispSearchClient::new("https://misp.example.com", "test-key")
    }

    #[test]
    fn test_client_new() {
        let c = client();
        assert_eq!(c.base_url, "https://misp.example.com");
        assert_eq!(c.api_key, "test-key");
        assert!(c.verify_tls);
    }

    #[test]
    fn test_client_without_tls() {
        let c = client().without_tls_verify();
        assert!(!c.verify_tls);
    }

    #[test]
    fn test_search_url_attributes() {
        let c = client();
        let url = c.search_url(SearchController::Attributes);
        assert!(url.ends_with("/attributes/restSearch"));
    }

    #[test]
    fn test_search_url_events() {
        let c = client();
        let url = c.search_url(SearchController::Events);
        assert!(url.ends_with("/events/restSearch"));
    }

    #[tokio::test]
    async fn test_search_by_value_reports_network_lookup() {
        let c = client();
        let err = c.search_by_value("evil.com").await.unwrap_err();
        assert!(err.contains("network lookup required"), "{err}");
        assert!(err.contains("none were invented"), "{err}");
    }

    #[test]
    fn test_synthetic_response_still_available_for_tests() {
        let c = client();
        let req = SearchRequest::new().with_value("evil.com").with_limit(4);
        let resp = c.mock_response(&req, SearchController::Attributes);
        assert_eq!(resp.attributes.len(), 4);
        for attr in &resp.attributes {
            assert!(attr.value.contains("evil.com"));
        }
    }

    #[tokio::test]
    async fn test_search_event_controller() {
        let c = client();
        let req = SearchRequest::new().with_limit(5);
        assert!(c.search(&req, SearchController::Events).await.is_err());
        let resp = c.mock_response(&req, SearchController::Events);
        assert!(!resp.events.is_empty());
        assert!(resp.attributes.is_empty());
    }

    #[tokio::test]
    async fn test_search_respects_limit() {
        let c = client();
        let req = SearchRequest::new().with_limit(3);
        let resp = c.mock_response(&req, SearchController::Attributes);
        assert!(resp.attributes.len() <= 3);
    }

    #[tokio::test]
    async fn test_search_by_value_and_type() {
        let c = client();
        assert!(c.search_by_value_and_type("abc123", "sha256").await.is_err());
        let req = SearchRequest::new().with_value("abc123").with_type("sha256");
        for attr in &c.mock_response(&req, SearchController::Attributes).attributes {
            assert_eq!(attr.type_, "sha256");
        }
    }

    #[tokio::test]
    async fn test_batch_search_fails_per_value_not_silently() {
        let c = client();
        let results = c.batch_search_by_values(&["hash1", "hash2", "domain.com"]).await;
        assert_eq!(results.len(), 3);
        // Each entry carries its own honest failure rather than empty results
        // that would read as "no threat intelligence for this value".
        for r in &results {
            assert!(r.is_err());
        }
    }

    #[test]
    fn test_request_validation_valid() {
        let req = SearchRequest::new().with_limit(10).with_threat_level(2);
        assert!(req.validate().is_none());
    }

    #[test]
    fn test_request_validation_invalid_threat_level() {
        let req = SearchRequest::new().with_threat_level(5);
        assert!(req.validate().is_some());
    }

    #[test]
    fn test_request_validation_zero_limit() {
        let mut req = SearchRequest::new();
        req.limit = Some(0);
        assert!(req.validate().is_some());
    }

    #[test]
    fn test_request_validation_invalid_analysis() {
        let mut req = SearchRequest::new();
        req.analysis = Some(3);
        assert!(req.validate().is_some());
    }

    #[test]
    fn test_request_json_body() {
        let req = SearchRequest::new().with_value("1.2.3.4").with_type("ip-dst");
        let body = req.to_json_body();
        assert!(body.get("request").is_some());
    }

    #[test]
    fn test_response_unique_values() {
        let resp = SearchResponse {
            attributes: vec![
                AttributeResult {
                    id: 1,
                    uuid: "u1".to_string(),
                    type_: "sha256".to_string(),
                    value: "abc".to_string(),
                    category: "Payload delivery".to_string(),
                    to_ids: true,
                    event_id: 1,
                    timestamp: 0,
                    comment: None,
                    tags: vec![],
                    correlation_count: 0,
                },
                AttributeResult {
                    id: 2,
                    uuid: "u2".to_string(),
                    type_: "sha256".to_string(),
                    value: "abc".to_string(), // duplicate
                    category: "Payload delivery".to_string(),
                    to_ids: true,
                    event_id: 2,
                    timestamp: 0,
                    comment: None,
                    tags: vec![],
                    correlation_count: 0,
                },
            ],
            events: vec![],
            total_count: 2,
            has_more: false,
            page: 1,
            raw: None,
        };
        let unique = resp.unique_values();
        assert_eq!(unique.len(), 1);
        assert_eq!(unique[0], "abc");
    }

    #[test]
    fn test_response_ids_attributes() {
        let client = client();
        let req = SearchRequest::new().with_limit(10);
        let resp = client.mock_response(&req, SearchController::Attributes);
        let ids = resp.ids_attributes();
        for attr in ids {
            assert!(attr.to_ids);
        }
    }

    #[test]
    fn test_response_group_by_event() {
        let client = client();
        let req = SearchRequest::new().with_limit(10);
        let resp = client.mock_response(&req, SearchController::Attributes);
        let by_event = resp.group_by_event();
        assert!(!by_event.is_empty());
        for (eid, attrs) in &by_event {
            for attr in attrs {
                assert_eq!(attr.event_id, *eid);
            }
        }
    }

    #[test]
    fn test_search_pager_next_request() {
        let req = SearchRequest::new();
        let mut pager = SearchPager::new(req, 10);
        let first = pager.next_request().unwrap();
        assert_eq!(first.page, Some(1));
        let second = pager.next_request().unwrap();
        assert_eq!(second.page, Some(2));
    }

    #[test]
    fn test_search_pager_exhausted() {
        let req = SearchRequest::new();
        let mut pager = SearchPager::new(req, 10);
        pager.mark_exhausted();
        assert!(pager.next_request().is_none());
    }

    #[test]
    fn test_search_format_api_str() {
        assert_eq!(SearchFormat::Json.as_api_str(), "json");
        assert_eq!(SearchFormat::Stix2.as_api_str(), "stix2");
        assert_eq!(SearchFormat::Csv.as_api_str(), "csv");
    }

    #[test]
    fn test_event_result_is_high_threat() {
        let evt = EventResult {
            id: 1,
            uuid: "u".to_string(),
            info: "Test".to_string(),
            date: "2024-01-01".to_string(),
            threat_level_id: 1,
            analysis: 2,
            distribution: 1,
            attribute_count: 5,
            tags: vec![],
            timestamp: 0,
        };
        assert!(evt.is_high_threat());
        assert!(evt.is_complete());
    }

    #[test]
    fn test_event_result_not_high_threat() {
        let mut evt = EventResult {
            id: 1,
            uuid: "u".to_string(),
            info: "Test".to_string(),
            date: "2024-01-01".to_string(),
            threat_level_id: 4,
            analysis: 0,
            distribution: 1,
            attribute_count: 0,
            tags: vec![],
            timestamp: 0,
        };
        assert!(!evt.is_high_threat());
        evt.analysis = 2;
        assert!(evt.is_complete());
    }

    #[test]
    fn test_attribute_result_first_tag_with_prefix() {
        let attr = AttributeResult {
            id: 1,
            uuid: "u".to_string(),
            type_: "sha256".to_string(),
            value: "abc".to_string(),
            category: "Payload delivery".to_string(),
            to_ids: true,
            event_id: 1,
            timestamp: 0,
            comment: None,
            tags: vec![
                TagResult {
                    name: "tlp:red".to_string(),
                    colour: "#FF0000".to_string(),
                    exportable: false,
                },
                TagResult {
                    name: "mitre:T1055".to_string(),
                    colour: "#000000".to_string(),
                    exportable: true,
                },
            ],
            correlation_count: 0,
        };
        assert_eq!(attr.first_tag_with_prefix("tlp:"), Some("tlp:red"));
        assert_eq!(attr.first_tag_with_prefix("mitre:"), Some("mitre:T1055"));
        assert!(attr.first_tag_with_prefix("galaxy:").is_none());
    }

    #[test]
    fn test_response_all_tags() {
        let client = client();
        let req = SearchRequest::new().with_limit(10);
        let resp = client.mock_response(&req, SearchController::Attributes);
        let tags = resp.all_tags();
        // Tags are sorted and deduped.
        if !tags.is_empty() {
            let mut prev = "";
            for tag in &tags {
                assert!(*tag >= prev);
                prev = tag;
            }
        }
    }
}
