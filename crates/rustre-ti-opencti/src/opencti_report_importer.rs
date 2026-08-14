//! `OpenCTI` report importer.
//!
//! Fetches CTI reports from an `OpenCTI` `GraphQL` endpoint, parses them, and
//! produces a structured `ImportResult` ready for downstream processing.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{Confidence, OpenCtiConfig, OpenCtiError};

// ─── CtiReport ────────────────────────────────────────────────────────────────

/// A CTI report as returned by the `OpenCTI` `GraphQL` API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtiReport {
    /// `OpenCTI` internal ID.
    pub id: String,
    /// Report name / title.
    pub name: String,
    /// Free-text description or executive summary.
    pub description: Option<String>,
    /// Publication date (RFC 3339).
    pub published: String,
    /// `OpenCTI` report type (e.g. `"Threat-Report"`, `"Malware-Analysis"`).
    pub report_types: Vec<String>,
    /// Confidence level.
    pub confidence: Option<Confidence>,
    /// Labels applied to the report.
    pub labels: Vec<String>,
    /// IDs of `OpenCTI` objects that are part of this report.
    pub object_refs: Vec<String>,
    /// Author / creator identity.
    pub author: Option<String>,
    /// External references (source name, url).
    pub external_references: Vec<(String, Option<String>)>,
    /// TLP marking.
    pub tlp: Option<String>,
    /// When this report was created in `OpenCTI` (RFC 3339).
    pub created_at: String,
    /// When this report was last updated (RFC 3339).
    pub updated_at: String,
    /// Arbitrary metadata from the platform.
    pub metadata: HashMap<String, serde_json::Value>,
}

impl CtiReport {
    /// Create a sample report for unit tests.
    #[must_use]
    pub fn sample() -> Self {
        Self {
            id: "report-001".to_string(),
            name: "Emotet Q1 2024 Campaign".to_string(),
            description: Some(
                "Analysis of the Q1 2024 Emotet spam campaign targeting European banks.".to_string(),
            ),
            published: "2024-01-15T00:00:00Z".to_string(),
            report_types: vec!["Threat-Report".to_string()],
            confidence: Some(Confidence::HIGH),
            labels: vec!["emotet".to_string(), "banking-trojan".to_string()],
            object_refs: vec!["indicator-001".to_string(), "malware-001".to_string()],
            author: Some("ACME TI Team".to_string()),
            external_references: vec![(
                "ACME Blog".to_string(),
                Some("https://blog.acme.com/emotet-q1-2024".to_string()),
            )],
            tlp: Some("TLP:AMBER".to_string()),
            created_at: "2024-01-15T08:00:00Z".to_string(),
            updated_at: "2024-01-16T09:00:00Z".to_string(),
            metadata: HashMap::new(),
        }
    }

    /// Returns `true` if this is a malware analysis report.
    #[must_use]
    pub fn is_malware_analysis(&self) -> bool {
        self.report_types
            .iter()
            .any(|t| t == "Malware-Analysis" || t == "malware-analysis")
    }

    /// Returns `true` if this is a threat report.
    #[must_use]
    pub fn is_threat_report(&self) -> bool {
        self.report_types
            .iter()
            .any(|t| t == "Threat-Report" || t == "threat-report")
    }

    /// Returns the number of referenced objects.
    #[must_use]
    pub const fn object_count(&self) -> usize {
        self.object_refs.len()
    }
}

// ─── ReportFilter ─────────────────────────────────────────────────────────────

/// Criteria used to filter reports during import.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportFilter {
    /// Only import reports published on or after this date (RFC 3339).
    pub published_after: Option<String>,
    /// Only import reports published on or before this date (RFC 3339).
    pub published_before: Option<String>,
    /// Only import reports with at least one of these labels.
    pub labels: Vec<String>,
    /// Only import reports with at least one of these report types.
    pub report_types: Vec<String>,
    /// Minimum confidence level.
    pub min_confidence: Option<Confidence>,
    /// Maximum number of reports to import.
    pub limit: Option<usize>,
}

impl ReportFilter {
    /// Returns `true` if the given report matches all filter criteria.
    #[must_use]
    pub fn matches(&self, report: &CtiReport) -> bool {
        // Date range
        if self.published_after.as_deref().is_some_and(|after| report.published.as_str() < after) {
            return false;
        }
        if self.published_before.as_deref().is_some_and(|before| report.published.as_str() > before) {
            return false;
        }
        // Labels (OR)
        if !self.labels.is_empty() {
            let hit = self
                .labels
                .iter()
                .any(|l| report.labels.iter().any(|rl| rl == l));
            if !hit {
                return false;
            }
        }
        // Report types (OR)
        if !self.report_types.is_empty() {
            let hit = self
                .report_types
                .iter()
                .any(|rt| report.report_types.iter().any(|rrt| rrt == rt));
            if !hit {
                return false;
            }
        }
        // Confidence
        if let Some(min_conf) = self.min_confidence {
            match report.confidence {
                None => return false,
                Some(c) if c < min_conf => return false,
                _ => {}
            }
        }
        true
    }
}

// ─── ImportError ─────────────────────────────────────────────────────────────

/// Describes a single import failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportError {
    /// Report ID (if known).
    pub report_id: Option<String>,
    /// Human-readable error message.
    pub message: String,
    /// Whether the error is transient (worth retrying).
    pub transient: bool,
}

impl ImportError {
    /// Create a transient error.
    #[must_use]
    pub fn transient(report_id: impl Into<String>, msg: impl Into<String>) -> Self {
        Self {
            report_id: Some(report_id.into()),
            message: msg.into(),
            transient: true,
        }
    }

    /// Create a permanent error.
    #[must_use]
    pub fn permanent(msg: impl Into<String>) -> Self {
        Self {
            report_id: None,
            message: msg.into(),
            transient: false,
        }
    }
}

// ─── ImportResult ─────────────────────────────────────────────────────────────

/// Result of a report import operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    /// Total reports retrieved from the API before filtering.
    pub total_fetched: usize,
    /// Reports that passed all filters.
    pub imported: Vec<CtiReport>,
    /// Reports that were skipped (did not match filters).
    pub skipped_count: usize,
    /// Per-report errors encountered during import.
    pub errors: Vec<ImportError>,
    /// Whether the import was truncated by a `limit` filter.
    pub truncated: bool,
    /// Duration of the import in milliseconds.
    pub duration_ms: u64,
}

impl ImportResult {
    /// Create an empty result.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            total_fetched: 0,
            imported: vec![],
            skipped_count: 0,
            errors: vec![],
            truncated: false,
            duration_ms: 0,
        }
    }

    /// Number of successfully imported reports.
    #[must_use]
    pub const fn imported_count(&self) -> usize {
        self.imported.len()
    }

    /// Number of errors encountered.
    #[must_use]
    pub const fn error_count(&self) -> usize {
        self.errors.len()
    }

    /// Returns `true` if all reports were imported without errors.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }

    /// All transient errors (worth retrying).
    #[must_use]
    pub fn transient_errors(&self) -> Vec<&ImportError> {
        self.errors.iter().filter(|e| e.transient).collect()
    }

    /// Total number of object references across all imported reports.
    #[must_use]
    pub fn total_object_refs(&self) -> usize {
        self.imported.iter().map(CtiReport::object_count).sum()
    }

    /// Collect all unique labels from imported reports.
    #[must_use]
    pub fn all_labels(&self) -> Vec<String> {
        let mut labels: Vec<String> = self
            .imported
            .iter()
            .flat_map(|r| r.labels.iter().cloned())
            .collect();
        labels.sort();
        labels.dedup();
        labels
    }

    /// Add a successfully imported report.
    pub fn push_report(&mut self, report: CtiReport) {
        self.imported.push(report);
    }

    /// Record a skip.
    pub const fn inc_skip(&mut self) {
        self.skipped_count += 1;
    }

    /// Record an error.
    pub fn push_error(&mut self, err: ImportError) {
        self.errors.push(err);
    }
}

// ─── GraphQL helpers ─────────────────────────────────────────────────────────

/// Minimal representation of a GraphQL response envelope.
#[derive(Debug, Deserialize)]
struct GraphQLResponse<T> {
    data: Option<T>,
    errors: Option<Vec<GraphQLError>>,
}

#[derive(Debug, Deserialize)]
struct GraphQLError {
    message: String,
}

/// Parse a raw GraphQL JSON response into the inner `data` type.
///
/// # Errors
/// Returns `OpenCtiError::GraphQL` if the response contains errors.
/// Returns `OpenCtiError::Serialization` if the JSON cannot be parsed.
fn parse_graphql<T: for<'de> Deserialize<'de>>(
    json: &str,
) -> Result<T, OpenCtiError> {
    let resp: GraphQLResponse<T> = serde_json::from_str(json)
        .map_err(|e| OpenCtiError::Serialization(e.to_string()))?;

    if let Some(errors) = resp.errors {
        let msg = errors
            .iter()
            .map(|e| e.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(OpenCtiError::GraphQL(msg));
    }

    resp.data
        .ok_or_else(|| OpenCtiError::GraphQL("response has no data field".into()))
}

/// Build the GraphQL query for fetching reports.
fn build_reports_query(limit: usize, offset: usize) -> String {
    format!(
        r"{{
  reports(first: {limit}, offset: {offset}) {{
    edges {{
      node {{
        id
        name
        description
        published
        report_types
        confidence
        labels {{ value }}
        objectRefs {{ id }}
        createdBy {{ name }}
        externalReferences {{ source_name url }}
        objectMarking {{ definition }}
        created_at
        updated_at
      }}
    }}
  }}
}}"
    )
}

// ─── OpenCtiReportImporter ────────────────────────────────────────────────────

/// Imports CTI reports from an `OpenCTI` platform instance.
///
/// Uses a synchronous HTTP client abstraction so the module does not require
/// async without a runtime.
pub struct OpenCtiReportImporter {
    /// Configuration retained for downstream HTTP clients.
    config: OpenCtiConfig,
    filter: ReportFilter,
    /// Simulate HTTP (set to `true` for unit-test mode — no real HTTP calls).
    dry_run: bool,
}

impl OpenCtiReportImporter {
    /// Create a new importer with the given config and filter.
    #[must_use]
    pub const fn new(config: OpenCtiConfig, filter: ReportFilter) -> Self {
        Self {
            config,
            filter,
            dry_run: false,
        }
    }

    /// Enable dry-run mode (no real HTTP, returns sample data).
    #[must_use]
    pub const fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    /// Reference to the configuration.
    #[must_use]
    pub const fn config(&self) -> &OpenCtiConfig {
        &self.config
    }

    /// Perform the import.
    ///
    /// # Errors
    /// Returns `OpenCtiError` if the HTTP request or GraphQL parsing fails.
    pub fn import(&self) -> Result<ImportResult, OpenCtiError> {
        let start = std::time::Instant::now();
        let mut result = ImportResult::empty();

        if self.dry_run {
            // Return sample data without hitting the network.
            let samples = vec![CtiReport::sample(), {
                let mut r = CtiReport::sample();
                r.id = "report-002".to_string();
                r.name = "Cobalt Strike Beacon Analysis".to_string();
                r.report_types = vec!["Malware-Analysis".to_string()];
                r.labels = vec!["cobalt-strike".to_string()];
                r
            }];
            result.total_fetched = samples.len();
            for report in samples {
                if self.filter.matches(&report) {
                    result.push_report(report);
                } else {
                    result.inc_skip();
                }
                if self.filter.limit.is_some_and(|limit| result.imported_count() >= limit) {
                    result.truncated = true;
                    break;
                }
            }
            result.duration_ms = u64::try_from(start.elapsed().as_millis().min(u128::from(u64::MAX))).unwrap_or(u64::MAX);
            return Ok(result);
        }

        // Real-mode HTTP import lives in `opencti_client::OpenCtiClient`, which
        // owns the async reqwest runtime. The sync importer surface here
        // intentionally requires `dry_run()` so callers without a Tokio
        // runtime cannot accidentally block.
        let _ = build_reports_query(50, 0);
        Err(OpenCtiError::Http(
            "synchronous import requires dry_run(); use opencti_client::OpenCtiClient \
             for real network calls"
                .into(),
        ))
    }

    /// Merge two import results (useful for combining paginated fetches).
    #[must_use]
    pub fn merge_results(mut base: ImportResult, other: ImportResult) -> ImportResult {
        base.total_fetched += other.total_fetched;
        base.skipped_count += other.skipped_count;
        base.imported.extend(other.imported);
        base.errors.extend(other.errors);
        if other.truncated {
            base.truncated = true;
        }
        base.duration_ms += other.duration_ms;
        base
    }

    /// Maximum byte length accepted by [`Self::parse_raw_response`].
    ///
    /// A 64 MiB cap prevents OOM when the caller passes an untrusted or
    /// unexpectedly large network response.
    const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

    /// Parse a raw API response JSON into a list of reports.
    ///
    /// Used for testing with pre-recorded API responses.
    ///
    /// # Errors
    /// Returns `OpenCtiError::InvalidInput` if the response exceeds
    /// [`Self::MAX_RESPONSE_BYTES`].
    /// Returns `OpenCtiError` if the JSON is malformed.
    pub fn parse_raw_response(&self, json: &str) -> Result<Vec<CtiReport>, OpenCtiError> {
        #[derive(Deserialize)]
        struct ReportNode {
            id: String,
            name: String,
            description: Option<String>,
            published: String,
            report_types: Option<Vec<String>>,
            confidence: Option<u8>,
            created_at: String,
            updated_at: String,
        }

        #[derive(Deserialize)]
        struct Edge {
            node: ReportNode,
        }

        #[derive(Deserialize)]
        struct ReportsPage {
            edges: Vec<Edge>,
        }

        #[derive(Deserialize)]
        struct Data {
            reports: ReportsPage,
        }

        if json.len() > Self::MAX_RESPONSE_BYTES {
            return Err(OpenCtiError::InvalidInput(format!(
                "response too large: {} bytes (max {})",
                json.len(),
                Self::MAX_RESPONSE_BYTES
            )));
        }

        let data: Data = parse_graphql(json)?;
        Ok(data
            .reports
            .edges
            .into_iter()
            .map(|e| {
                let n = e.node;
                CtiReport {
                    id: n.id,
                    name: n.name,
                    description: n.description,
                    published: n.published,
                    report_types: n.report_types.unwrap_or_default(),
                    confidence: n.confidence.map(Confidence::new),
                    labels: vec![],
                    object_refs: vec![],
                    author: None,
                    external_references: vec![],
                    tlp: None,
                    created_at: n.created_at,
                    updated_at: n.updated_at,
                    metadata: HashMap::new(),
                }
            })
            .collect())
    }
}

// ─── ReportSummary ────────────────────────────────────────────────────────────

/// A lightweight summary of a CTI report suitable for display or logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub id: String,
    pub name: String,
    pub published: String,
    pub report_types: Vec<String>,
    pub label_count: usize,
    pub object_count: usize,
    pub confidence: Option<u8>,
}

impl From<&CtiReport> for ReportSummary {
    fn from(r: &CtiReport) -> Self {
        Self {
            id: r.id.clone(),
            name: r.name.clone(),
            published: r.published.clone(),
            report_types: r.report_types.clone(),
            label_count: r.labels.len(),
            object_count: r.object_refs.len(),
            confidence: r.confidence.map(Confidence::value),
        }
    }
}

impl std::fmt::Display for ReportSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} ({}) — {} objects, {} labels",
            self.id,
            self.name,
            self.published,
            self.object_count,
            self.label_count
        )
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> OpenCtiConfig {
        OpenCtiConfig::new("https://opencti.example.com", "test-token")
    }

    #[test]
    fn test_sample_report_fields() {
        let r = CtiReport::sample();
        assert!(!r.id.is_empty());
        assert!(r.is_threat_report());
        assert!(!r.is_malware_analysis());
        assert_eq!(r.object_count(), 2);
    }

    #[test]
    fn test_filter_by_label() {
        let filter = ReportFilter {
            labels: vec!["emotet".to_string()],
            ..Default::default()
        };
        let r = CtiReport::sample();
        assert!(filter.matches(&r));

        let mut r2 = CtiReport::sample();
        r2.labels = vec!["apt28".to_string()];
        assert!(!filter.matches(&r2));
    }

    #[test]
    fn test_filter_by_report_type() {
        let filter = ReportFilter {
            report_types: vec!["Malware-Analysis".to_string()],
            ..Default::default()
        };
        let r = CtiReport::sample();
        assert!(!filter.matches(&r));
    }

    #[test]
    fn test_filter_min_confidence() {
        let filter = ReportFilter {
            min_confidence: Some(Confidence::HIGH),
            ..Default::default()
        };
        let r = CtiReport::sample();
        assert!(filter.matches(&r)); // HIGH = 85

        let mut r2 = CtiReport::sample();
        r2.confidence = Some(Confidence::LOW);
        assert!(!filter.matches(&r2));
    }

    #[test]
    fn test_dry_run_import() {
        let importer = OpenCtiReportImporter::new(make_config(), ReportFilter::default())
            .dry_run();
        let result = importer.import().expect("dry run should succeed");
        assert_eq!(result.imported_count(), 2);
        assert!(result.is_clean());
    }

    #[test]
    fn test_dry_run_import_with_label_filter() {
        let filter = ReportFilter {
            labels: vec!["cobalt-strike".to_string()],
            ..Default::default()
        };
        let importer =
            OpenCtiReportImporter::new(make_config(), filter).dry_run();
        let result = importer.import().expect("should succeed");
        assert_eq!(result.imported_count(), 1);
        assert_eq!(result.imported[0].name, "Cobalt Strike Beacon Analysis");
    }

    #[test]
    fn test_dry_run_with_limit() {
        let filter = ReportFilter {
            limit: Some(1),
            ..Default::default()
        };
        let importer = OpenCtiReportImporter::new(make_config(), filter).dry_run();
        let result = importer.import().expect("should succeed");
        assert_eq!(result.imported_count(), 1);
        assert!(result.truncated);
    }

    #[test]
    fn test_import_result_all_labels() {
        let mut res = ImportResult::empty();
        res.push_report(CtiReport::sample());
        let labels = res.all_labels();
        assert!(labels.contains(&"emotet".to_string()));
    }

    #[test]
    fn test_report_summary() {
        let r = CtiReport::sample();
        let summary = ReportSummary::from(&r);
        assert_eq!(summary.object_count, 2);
        let display = format!("{summary}");
        assert!(display.contains("Emotet"));
    }

    #[test]
    fn test_merge_results() {
        let mut r1 = ImportResult::empty();
        r1.push_report(CtiReport::sample());
        r1.total_fetched = 1;

        let mut r2 = ImportResult::empty();
        r2.push_report(CtiReport::sample());
        r2.total_fetched = 1;

        let merged = OpenCtiReportImporter::merge_results(r1, r2);
        assert_eq!(merged.imported_count(), 2);
        assert_eq!(merged.total_fetched, 2);
    }
}
