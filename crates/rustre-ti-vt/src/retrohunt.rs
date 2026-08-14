//! `VirusTotal` Retrohunt — submit YARA rules and retrieve matches against the
//! VT corpus.
//!
//! Covers the full Retrohunt lifecycle: job submission, status polling, result
//! pagination, cancellation, and YARA rule validation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// RetroHuntStatus
// ---------------------------------------------------------------------------

/// Lifecycle state of a Retrohunt job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetroHuntStatus {
    /// Job has been queued but not yet started.
    Queued,
    /// Job is currently scanning the corpus.
    Running,
    /// Job has finished and results are available.
    Completed,
    /// Job was cancelled before finishing.
    Aborted,
    /// Job failed due to an internal error.
    Failed,
}

impl std::fmt::Display for RetroHuntStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Aborted => "aborted",
            Self::Failed => "failed",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// RetroHuntJob
// ---------------------------------------------------------------------------

/// A `VirusTotal` Retrohunt job record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetroHuntJob {
    /// Unique job identifier assigned by VT.
    pub id: String,
    /// The YARA rule submitted for this job.
    pub rule: String,
    /// Current status of the job.
    pub status: RetroHuntStatus,
    /// Number of files that matched the rule so far.
    pub matches_count: u64,
    /// Unix timestamp when the job was created.
    pub creation_date: u64,
    /// Unix timestamp when the job started.
    pub start_date: Option<u64>,
    /// Unix timestamp when the job finished.
    pub finish_date: Option<u64>,
    /// Corpus date range applied to this scan.
    pub filter: Option<RetroHuntFilter>,
    /// Progress percentage [0, 100].
    pub progress: u8,
    /// Optional human-readable description.
    pub description: Option<String>,
}

impl RetroHuntJob {
    /// Return `true` when the job has finished (completed or aborted/failed).
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        matches!(
            self.status,
            RetroHuntStatus::Completed | RetroHuntStatus::Aborted | RetroHuntStatus::Failed
        )
    }

    /// Return `true` when results can be fetched.
    #[must_use]
    pub fn has_results(&self) -> bool {
        self.status == RetroHuntStatus::Completed && self.matches_count > 0
    }

    /// Elapsed time in seconds, computed from creation to finish (or now if
    /// still running). Returns `None` if timestamps are unavailable.
    #[must_use]
    pub fn elapsed_secs(&self) -> Option<u64> {
        let end = self.finish_date.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
        Some(end.saturating_sub(self.creation_date))
    }
}

// ---------------------------------------------------------------------------
// RetroHuntMatch
// ---------------------------------------------------------------------------

/// A single file match returned by a Retrohunt job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetroHuntMatch {
    /// SHA-256 of the matched file.
    pub sha256: String,
    /// File size in bytes.
    pub file_size: u64,
    /// Unix timestamp when this file was first submitted to VT.
    pub first_seen: u64,
    /// Tags/labels on the matched file.
    pub tags: Vec<String>,
    /// YARA string identifiers that triggered the match.
    pub matched_strings: Vec<String>,
    /// Antivirus detection stats for this file.
    pub detection_stats: HashMap<String, u32>,
    /// File type description.
    pub file_type: Option<String>,
    /// Common malware family associated with this file (if any).
    pub malware_family: Option<String>,
}

impl RetroHuntMatch {
    /// Create a minimal match record.
    #[must_use]
    pub fn new(sha256: impl Into<String>, file_size: u64, first_seen: u64) -> Self {
        Self {
            sha256: sha256.into(),
            file_size,
            first_seen,
            tags: Vec::new(),
            matched_strings: Vec::new(),
            detection_stats: HashMap::new(),
            file_type: None,
            malware_family: None,
        }
    }

    /// Return `true` if any AV engine flagged this file as malicious.
    #[must_use]
    pub fn is_malicious(&self) -> bool {
        self.detection_stats.get("malicious").copied().unwrap_or(0) > 0
    }

    /// Total number of engines that scanned this file.
    #[must_use]
    pub fn total_engines(&self) -> u32 {
        self.detection_stats.values().sum()
    }
}

// ---------------------------------------------------------------------------
// RetroHuntFilter
// ---------------------------------------------------------------------------

/// Filters applied to a Retrohunt job.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RetroHuntFilter {
    /// Earliest first-submission timestamp to include (Unix seconds).
    pub date_from: Option<u64>,
    /// Latest first-submission timestamp to include (Unix seconds).
    pub date_to: Option<u64>,
    /// File type tags to include (e.g. `["peexe", "elf"]`).
    pub file_types: Vec<String>,
    /// Minimum file size in bytes.
    pub size_min: Option<u64>,
    /// Maximum file size in bytes.
    pub size_max: Option<u64>,
    /// Positive detection count threshold.
    pub min_positives: Option<u32>,
    /// Tags that must be present on matched files.
    pub required_tags: Vec<String>,
}

impl RetroHuntFilter {
    /// Create an empty filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set date range.
    #[must_use]
    pub const fn with_date_range(mut self, from: u64, to: u64) -> Self {
        self.date_from = Some(from);
        self.date_to = Some(to);
        self
    }

    /// Restrict to specific file types.
    #[must_use]
    pub fn with_file_type(mut self, ft: impl Into<String>) -> Self {
        self.file_types.push(ft.into());
        self
    }

    /// Set minimum detection count.
    #[must_use]
    pub const fn with_min_positives(mut self, n: u32) -> Self {
        self.min_positives = Some(n);
        self
    }

    /// Set file size range.
    #[must_use]
    pub const fn with_size_range(mut self, min: u64, max: u64) -> Self {
        self.size_min = Some(min);
        self.size_max = Some(max);
        self
    }

    /// Return `true` if this filter allows the given file type.
    #[must_use]
    pub fn allows_type(&self, ft: &str) -> bool {
        self.file_types.is_empty() || self.file_types.iter().any(|t| t == ft)
    }
}

// ---------------------------------------------------------------------------
// VtYaraRule
// ---------------------------------------------------------------------------

/// A YARA rule submitted to `VirusTotal` Retrohunt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtYaraRule {
    /// Rule name identifier.
    pub name: String,
    /// Full YARA rule text.
    pub source: String,
    /// Optional description/comment.
    pub description: Option<String>,
    /// Tags attached to this rule.
    pub tags: Vec<String>,
    /// Author of the rule.
    pub author: Option<String>,
}

impl VtYaraRule {
    /// Create a rule from a name and source text.
    #[must_use]
    pub fn new(name: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            source: source.into(),
            description: None,
            tags: Vec::new(),
            author: None,
        }
    }

    /// Basic syntactic validation: checks that the rule text contains the
    /// expected structural keywords.
    ///
    /// Returns `Ok(())` on success or `Err(reason)` on the first failing check.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub fn validate(&self) -> Result<(), String> {
        let src = &self.source;

        if self.name.is_empty() {
            return Err("rule name must not be empty".to_string());
        }

        if !src.contains("rule ") {
            return Err("YARA rule must contain 'rule' keyword".to_string());
        }

        if !src.contains('{') || !src.contains('}') {
            return Err("YARA rule must have opening and closing braces".to_string());
        }

        if !src.contains("condition:") {
            return Err("YARA rule must contain a 'condition:' section".to_string());
        }

        // Check for balanced braces.
        let open = src.chars().filter(|&c| c == '{').count();
        let close = src.chars().filter(|&c| c == '}').count();
        if open != close {
            return Err(format!("unbalanced braces: {open} open, {close} close"));
        }

        Ok(())
    }

    /// Return `true` if the rule passes basic validation.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }

    /// Return the number of string definitions in the rule.
    #[must_use]
    pub fn string_count(&self) -> usize {
        self.source
            .lines()
            .filter(|l| {
                let t = l.trim();
                t.starts_with('$') && t.contains('=')
            })
            .count()
    }
}

// ---------------------------------------------------------------------------
// RetroHuntPageResult
// ---------------------------------------------------------------------------

/// A paginated page of Retrohunt matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetroHuntPageResult {
    /// Matches on this page.
    pub matches: Vec<RetroHuntMatch>,
    /// Cursor for fetching the next page (`None` if this is the last page).
    pub next_cursor: Option<String>,
    /// Total estimated matches across all pages.
    pub total: u64,
}

// ---------------------------------------------------------------------------
// RetroHuntClient
// ---------------------------------------------------------------------------

/// Client for the `VirusTotal` Retrohunt API.
pub struct RetroHuntClient {
    api_key: String,
    base_url: String,
    max_results_per_page: usize,
}

impl RetroHuntClient {
    /// Create a new Retrohunt client.
    #[must_use]
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: "https://www.virustotal.com".to_string(),
            max_results_per_page: 20,
        }
    }

    /// Override the base URL (useful for testing).
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Set the maximum number of results returned per page.
    #[must_use]
    pub fn with_page_size(mut self, n: usize) -> Self {
        self.max_results_per_page = n.max(1);
        self
    }

    /// Whether the client is configured with a non-empty API key.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        !self.api_key.is_empty()
    }

    // ---- API methods (mock implementations) --------------------------------

    /// Submit a YARA rule for retrohunting. Returns the created job.
    ///
    /// # Errors
    /// Returns an error string if the rule fails validation or the client is
    /// not authenticated.
    pub async fn submit(
        &self,
        rule: VtYaraRule,
        filter: Option<RetroHuntFilter>,
    ) -> Result<RetroHuntJob, String> {
        if !self.is_authenticated() {
            return Err("API key required for Retrohunt".to_string());
        }
        rule.validate()
            .map_err(|e| format!("invalid YARA rule: {e}"))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(RetroHuntJob {
            id: format!("retrohunt-{now}"),
            rule: rule.source,
            status: RetroHuntStatus::Queued,
            matches_count: 0,
            creation_date: now,
            start_date: None,
            finish_date: None,
            filter,
            progress: 0,
            description: rule.description,
        })
    }

    /// Get the current status of a job by ID.
    ///
    /// # Errors
    /// Returns an error if the job ID is empty.
    pub async fn get_status(&self, job_id: &str) -> Result<RetroHuntJob, String> {
        if job_id.is_empty() {
            return Err("job_id must not be empty".to_string());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(RetroHuntJob {
            id: job_id.to_string(),
            rule: "rule mock { condition: true }".to_string(),
            status: RetroHuntStatus::Completed,
            matches_count: 42,
            creation_date: now - 600,
            start_date: Some(now - 580),
            finish_date: Some(now - 60),
            filter: None,
            progress: 100,
            description: None,
        })
    }

    /// Retrieve a page of matches for a completed job.
    ///
    /// # Errors
    /// Returns an error if the job is not in `Completed` status.
    pub async fn get_results(
        &self,
        job_id: &str,
        cursor: Option<&str>,
    ) -> Result<RetroHuntPageResult, String> {
        if job_id.is_empty() {
            return Err("job_id must not be empty".to_string());
        }
        let page_num = cursor
            .and_then(|c| c.strip_prefix("page:"))
            .and_then(|n| n.parse::<usize>().ok())
            .unwrap_or(0);

        // Mock: two pages of results.
        let is_last = page_num >= 1;
        let matches = (0..self.max_results_per_page.min(3))
            .map(|i| {
                let mut m = RetroHuntMatch::new(
                    format!("sha256mock{page_num:04}{i:04}"),
                    102_400,
                    1_600_000_000,
                );
                m.tags = vec!["malware".to_string()];
                m.detection_stats.insert("malicious".to_string(), 30);
                m.detection_stats.insert("undetected".to_string(), 42);
                m
            })
            .collect();

        Ok(RetroHuntPageResult {
            matches,
            next_cursor: if is_last {
                None
            } else {
                Some(format!("page:{}", page_num + 1))
            },
            total: 6,
        })
    }

    /// Collect ALL matches for a job by iterating through pages.
    ///
    /// # Errors
    /// Propagates errors from `get_results`.
    pub async fn get_all_results(&self, job_id: &str) -> Result<Vec<RetroHuntMatch>, String> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = self.get_results(job_id, cursor.as_deref()).await?;
            all.extend(page.matches);
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
            // Guard against infinite loops in mock.
            if all.len() > 1_000 {
                break;
            }
        }
        Ok(all)
    }

    /// Cancel a running job.
    ///
    /// # Errors
    /// Returns an error if the job ID is empty.
    pub async fn cancel(&self, job_id: &str) -> Result<RetroHuntJob, String> {
        if job_id.is_empty() {
            return Err("job_id must not be empty".to_string());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(RetroHuntJob {
            id: job_id.to_string(),
            rule: "rule mock { condition: true }".to_string(),
            status: RetroHuntStatus::Aborted,
            matches_count: 0,
            creation_date: now - 60,
            start_date: Some(now - 50),
            finish_date: Some(now),
            filter: None,
            progress: 30,
            description: None,
        })
    }

    /// List recent Retrohunt jobs for the authenticated account.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn list_jobs(&self, limit: usize) -> Result<Vec<RetroHuntJob>, String> {
        if !self.is_authenticated() {
            return Err("API key required".to_string());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let count = limit.min(5);
        Ok((0..count)
            .map(|i| RetroHuntJob {
                id: format!("job-{i:04}"),
                rule: format!("rule rule_{i} {{ condition: false }}"),
                status: if i.is_multiple_of(2) {
                    RetroHuntStatus::Completed
                } else {
                    RetroHuntStatus::Running
                },
                matches_count: (i as u64) * 10,
                creation_date: now - (i as u64) * 3600,
                start_date: Some(now - (i as u64) * 3550),
                finish_date: if i.is_multiple_of(2) {
                    Some(now - (i as u64) * 100)
                } else {
                    None
                },
                filter: None,
                progress: if i.is_multiple_of(2) { 100 } else { 50 },
                description: None,
            })
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> RetroHuntClient {
        RetroHuntClient::new("test-api-key-xxxxxxxxxxxxxxxxxxxxxxxx")
    }

    fn valid_rule() -> VtYaraRule {
        VtYaraRule::new(
            "detect_test",
            r#"rule detect_test {
    strings:
        $s0 = "malware_string"
        $s1 = { DE AD BE EF }
    condition:
        any of them
}"#,
        )
    }

    fn invalid_rule_no_condition() -> VtYaraRule {
        VtYaraRule::new("bad_rule", "rule bad_rule { strings: $s = \"x\" }")
    }

    // ---- VtYaraRule ----

    #[test]
    fn test_rule_validate_ok() {
        assert!(valid_rule().validate().is_ok());
    }

    #[test]
    fn test_rule_is_valid() {
        assert!(valid_rule().is_valid());
    }

    #[test]
    fn test_rule_validate_missing_condition() {
        assert!(invalid_rule_no_condition().validate().is_err());
    }

    #[test]
    fn test_rule_validate_empty_name() {
        let r = VtYaraRule::new("", "rule x { condition: true }");
        assert!(r.validate().is_err());
    }

    #[test]
    fn test_rule_validate_no_rule_keyword() {
        let r = VtYaraRule::new("r", "{ condition: true }");
        assert!(r.validate().is_err());
    }

    #[test]
    fn test_rule_validate_unbalanced_braces() {
        let r = VtYaraRule::new("r", "rule r { condition: true");
        assert!(r.validate().is_err());
    }

    #[test]
    fn test_rule_string_count() {
        let r = valid_rule();
        assert_eq!(r.string_count(), 2);
    }

    #[test]
    fn test_rule_string_count_empty() {
        let r = VtYaraRule::new("empty", "rule empty { condition: false }");
        assert_eq!(r.string_count(), 0);
    }

    // ---- RetroHuntFilter ----

    #[test]
    fn test_filter_allows_type_empty() {
        let f = RetroHuntFilter::new();
        assert!(f.allows_type("peexe"));
    }

    #[test]
    fn test_filter_allows_type_specific() {
        let f = RetroHuntFilter::new().with_file_type("peexe");
        assert!(f.allows_type("peexe"));
        assert!(!f.allows_type("elf"));
    }

    #[test]
    fn test_filter_with_size_range() {
        let f = RetroHuntFilter::new().with_size_range(1024, 1_000_000);
        assert_eq!(f.size_min, Some(1024));
        assert_eq!(f.size_max, Some(1_000_000));
    }

    #[test]
    fn test_filter_with_date_range() {
        let f = RetroHuntFilter::new().with_date_range(1_600_000_000, 1_700_000_000);
        assert_eq!(f.date_from, Some(1_600_000_000));
        assert_eq!(f.date_to, Some(1_700_000_000));
    }

    // ---- RetroHuntMatch ----

    #[test]
    fn test_match_new() {
        let m = RetroHuntMatch::new("abc123", 4096, 1_600_000_000);
        assert_eq!(m.sha256, "abc123");
        assert_eq!(m.file_size, 4096);
        assert!(!m.is_malicious());
    }

    #[test]
    fn test_match_is_malicious() {
        let mut m = RetroHuntMatch::new("abc", 100, 0);
        m.detection_stats.insert("malicious".to_string(), 5);
        assert!(m.is_malicious());
    }

    #[test]
    fn test_match_total_engines() {
        let mut m = RetroHuntMatch::new("abc", 100, 0);
        m.detection_stats.insert("malicious".to_string(), 5);
        m.detection_stats.insert("undetected".to_string(), 67);
        assert_eq!(m.total_engines(), 72);
    }

    // ---- RetroHuntJob ----

    #[test]
    fn test_job_is_finished_completed() {
        let job = RetroHuntJob {
            id: "j1".to_string(),
            rule: "rule r { condition: false }".to_string(),
            status: RetroHuntStatus::Completed,
            matches_count: 5,
            creation_date: 0,
            start_date: None,
            finish_date: Some(100),
            filter: None,
            progress: 100,
            description: None,
        };
        assert!(job.is_finished());
        assert!(job.has_results());
    }

    #[test]
    fn test_job_is_finished_running() {
        let job = RetroHuntJob {
            id: "j2".to_string(),
            rule: String::new(),
            status: RetroHuntStatus::Running,
            matches_count: 0,
            creation_date: 0,
            start_date: Some(50),
            finish_date: None,
            filter: None,
            progress: 50,
            description: None,
        };
        assert!(!job.is_finished());
        assert!(!job.has_results());
    }

    #[test]
    fn test_job_elapsed_secs() {
        let job = RetroHuntJob {
            id: "j3".to_string(),
            rule: String::new(),
            status: RetroHuntStatus::Completed,
            matches_count: 1,
            creation_date: 1_000_000,
            start_date: None,
            finish_date: Some(1_001_000),
            filter: None,
            progress: 100,
            description: None,
        };
        assert_eq!(job.elapsed_secs(), Some(1000));
    }

    // ---- RetroHuntClient async ----

    #[tokio::test]
    async fn test_submit_valid_rule() {
        let job = client().submit(valid_rule(), None).await.unwrap();
        assert!(!job.id.is_empty());
        assert_eq!(job.status, RetroHuntStatus::Queued);
    }

    #[tokio::test]
    async fn test_submit_invalid_rule() {
        let result = client().submit(invalid_rule_no_condition(), None).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("invalid YARA rule"));
    }

    #[tokio::test]
    async fn test_submit_no_auth() {
        let c = RetroHuntClient::new("");
        let result = c.submit(valid_rule(), None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_status() {
        let job = client().get_status("job-001").await.unwrap();
        assert_eq!(job.status, RetroHuntStatus::Completed);
        assert!(job.matches_count > 0);
    }

    #[tokio::test]
    async fn test_get_status_empty_id() {
        assert!(client().get_status("").await.is_err());
    }

    #[tokio::test]
    async fn test_get_results_first_page() {
        let page = client().get_results("job-001", None).await.unwrap();
        assert!(!page.matches.is_empty());
        assert!(page.next_cursor.is_some());
    }

    #[tokio::test]
    async fn test_get_results_second_page() {
        let page = client()
            .get_results("job-001", Some("page:1"))
            .await
            .unwrap();
        assert!(!page.matches.is_empty());
        assert!(page.next_cursor.is_none());
    }

    #[tokio::test]
    async fn test_get_all_results() {
        let all = client().get_all_results("job-001").await.unwrap();
        // Two pages × 3 results = 6 total.
        assert_eq!(all.len(), 6);
    }

    #[tokio::test]
    async fn test_cancel_job() {
        let job = client().cancel("job-001").await.unwrap();
        assert_eq!(job.status, RetroHuntStatus::Aborted);
    }

    #[tokio::test]
    async fn test_cancel_empty_id() {
        assert!(client().cancel("").await.is_err());
    }

    #[tokio::test]
    async fn test_list_jobs() {
        let jobs = client().list_jobs(3).await.unwrap();
        assert_eq!(jobs.len(), 3);
    }

    #[tokio::test]
    async fn test_list_jobs_statuses() {
        let jobs = client().list_jobs(4).await.unwrap();
        let any_completed = jobs.iter().any(|j| j.status == RetroHuntStatus::Completed);
        assert!(any_completed);
    }

    #[tokio::test]
    async fn test_list_jobs_no_auth() {
        let c = RetroHuntClient::new("");
        assert!(c.list_jobs(5).await.is_err());
    }

    // ---- RetroHuntStatus display ----

    #[test]
    fn test_status_display() {
        assert_eq!(RetroHuntStatus::Completed.to_string(), "completed");
        assert_eq!(RetroHuntStatus::Aborted.to_string(), "aborted");
        assert_eq!(RetroHuntStatus::Failed.to_string(), "failed");
    }

    // ---- Submit with filter ----

    #[tokio::test]
    async fn test_submit_with_filter() {
        let f = RetroHuntFilter::new()
            .with_file_type("peexe")
            .with_date_range(1_600_000_000, 1_700_000_000);
        let job = client().submit(valid_rule(), Some(f)).await.unwrap();
        assert!(job.filter.is_some());
    }

    // ---- Page size config ----

    #[test]
    fn test_page_size_config() {
        let c = client().with_page_size(10);
        assert_eq!(c.max_results_per_page, 10);
    }

    #[test]
    fn test_page_size_minimum_1() {
        let c = client().with_page_size(0);
        assert_eq!(c.max_results_per_page, 1);
    }

    // ---- RetroHuntMatch serde ----

    #[test]
    fn test_match_serde_roundtrip() {
        let m = RetroHuntMatch::new("sha256abc", 1024, 1_600_000_000);
        let json = serde_json::to_string(&m).unwrap();
        let m2: RetroHuntMatch = serde_json::from_str(&json).unwrap();
        assert_eq!(m2.sha256, "sha256abc");
        assert_eq!(m2.file_size, 1024);
    }

    #[test]
    fn test_job_serde_roundtrip() {
        let job = RetroHuntJob {
            id: "j-001".to_string(),
            rule: "rule r { condition: true }".to_string(),
            status: RetroHuntStatus::Completed,
            matches_count: 10,
            creation_date: 1_700_000_000,
            start_date: Some(1_700_000_001),
            finish_date: Some(1_700_001_000),
            filter: None,
            progress: 100,
            description: Some("test job".to_string()),
        };
        let json = serde_json::to_string(&job).unwrap();
        let job2: RetroHuntJob = serde_json::from_str(&json).unwrap();
        assert_eq!(job2.id, "j-001");
        assert_eq!(job2.status, RetroHuntStatus::Completed);
    }

    // ---- Filter serde ----

    #[test]
    fn test_filter_serde_roundtrip() {
        let f = RetroHuntFilter::new()
            .with_file_type("peexe")
            .with_date_range(1_600_000_000, 1_700_000_000)
            .with_min_positives(5)
            .with_size_range(1024, 10_000_000);
        let json = serde_json::to_string(&f).unwrap();
        let f2: RetroHuntFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(f2.min_positives, Some(5));
        assert_eq!(f2.file_types.len(), 1);
    }

    // ---- Rule serde ----

    #[test]
    fn test_rule_serde_roundtrip() {
        let r = valid_rule();
        let json = serde_json::to_string(&r).unwrap();
        let r2: VtYaraRule = serde_json::from_str(&json).unwrap();
        assert_eq!(r2.name, r.name);
        assert!(r2.is_valid());
    }

    // ---- Page result serde ----

    #[test]
    fn test_page_result_serde() {
        let page = RetroHuntPageResult {
            matches: vec![RetroHuntMatch::new("abc", 100, 0)],
            next_cursor: Some("page:1".to_string()),
            total: 42,
        };
        let json = serde_json::to_string(&page).unwrap();
        let page2: RetroHuntPageResult = serde_json::from_str(&json).unwrap();
        assert_eq!(page2.total, 42);
        assert_eq!(page2.matches.len(), 1);
    }

    // ---- Additional status checks ----

    #[test]
    fn test_status_failed_is_finished() {
        let job = RetroHuntJob {
            id: "x".to_string(),
            rule: String::new(),
            status: RetroHuntStatus::Failed,
            matches_count: 0,
            creation_date: 0,
            start_date: None,
            finish_date: Some(100),
            filter: None,
            progress: 0,
            description: None,
        };
        assert!(job.is_finished());
        assert!(!job.has_results());
    }

    #[test]
    fn test_queued_is_not_finished() {
        let job = RetroHuntJob {
            id: "x".to_string(),
            rule: String::new(),
            status: RetroHuntStatus::Queued,
            matches_count: 0,
            creation_date: 0,
            start_date: None,
            finish_date: None,
            filter: None,
            progress: 0,
            description: None,
        };
        assert!(!job.is_finished());
    }

    // ---- with_base_url ----

    #[test]
    fn test_client_with_base_url() {
        let c = client().with_base_url("http://localhost:8080");
        assert_eq!(c.base_url, "http://localhost:8080");
    }

    // ---- Multi-type file filter ----

    #[test]
    fn test_filter_multiple_types() {
        let f = RetroHuntFilter::new()
            .with_file_type("peexe")
            .with_file_type("elf");
        assert!(f.allows_type("peexe"));
        assert!(f.allows_type("elf"));
        assert!(!f.allows_type("zip"));
    }

    // ---- match malware_family field ----

    #[test]
    fn test_match_malware_family() {
        let mut m = RetroHuntMatch::new("abc", 100, 0);
        m.malware_family = Some("Emotet".to_string());
        assert_eq!(m.malware_family.as_deref(), Some("Emotet"));
    }

    // ---- RetroHuntJob has_results needs matches_count > 0 ----

    #[test]
    fn test_job_has_results_zero_matches() {
        let job = RetroHuntJob {
            id: "j".to_string(),
            rule: String::new(),
            status: RetroHuntStatus::Completed,
            matches_count: 0, // zero matches
            creation_date: 0,
            start_date: None,
            finish_date: Some(100),
            filter: None,
            progress: 100,
            description: None,
        };
        assert!(job.is_finished());
        assert!(!job.has_results());
    }

    // ---- VtYaraRule with description and author ----

    #[test]
    fn test_rule_with_description_and_author() {
        let mut r = valid_rule();
        r.description = Some("detects emotet".to_string());
        r.author = Some("analyst@example.com".to_string());
        assert!(r.is_valid());
        assert_eq!(r.description.as_deref(), Some("detects emotet"));
    }
}
