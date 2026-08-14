//! `OpenCTI` alert creation.
//!
//! Builds structured `CtiAlert` objects from raw threat signals and publishes
//! them to the `OpenCTI` platform via the `GraphQL` mutation API.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Confidence, OpenCtiConfig, OpenCtiError};

// ─── AlertSeverity ────────────────────────────────────────────────────────────

/// Severity of a CTI alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Informational => write!(f, "informational"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

impl AlertSeverity {
    /// Numeric weight (1–5) for scoring.
    #[must_use]
    pub const fn weight(self) -> u8 {
        match self {
            Self::Informational => 1,
            Self::Low => 2,
            Self::Medium => 3,
            Self::High => 4,
            Self::Critical => 5,
        }
    }

    /// Derive severity from a numeric score (0–100).
    #[must_use]
    pub const fn from_score(score: u8) -> Self {
        match score {
            0..=19 => Self::Informational,
            20..=39 => Self::Low,
            40..=59 => Self::Medium,
            60..=79 => Self::High,
            _ => Self::Critical,
        }
    }
}

// ─── AlertStatus ─────────────────────────────────────────────────────────────

/// Lifecycle status of a CTI alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertStatus {
    New,
    InProgress,
    Resolved,
    FalsePositive,
    Escalated,
}

impl fmt::Display for AlertStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::New => write!(f, "new"),
            Self::InProgress => write!(f, "in_progress"),
            Self::Resolved => write!(f, "resolved"),
            Self::FalsePositive => write!(f, "false_positive"),
            Self::Escalated => write!(f, "escalated"),
        }
    }
}

// ─── AlertSource ─────────────────────────────────────────────────────────────

/// The origin system or feed that triggered a CTI alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSource {
    /// Short identifier for the source system (e.g. `"virustotal"`, `"shodan"`).
    pub system: String,
    /// Feed name within the source system.
    pub feed: Option<String>,
    /// URL of the originating indicator or report.
    pub url: Option<String>,
    /// Raw signal data from the source (arbitrary JSON).
    pub raw: Option<serde_json::Value>,
}

impl AlertSource {
    /// Create a minimal alert source.
    #[must_use]
    pub fn new(system: impl Into<String>) -> Self {
        Self {
            system: system.into(),
            feed: None,
            url: None,
            raw: None,
        }
    }

    /// Set the feed name.
    #[must_use]
    pub fn with_feed(mut self, feed: impl Into<String>) -> Self {
        self.feed = Some(feed.into());
        self
    }

    /// Set the originating URL.
    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }
}

// ─── CtiAlert ─────────────────────────────────────────────────────────────────

/// A structured CTI alert ready to be published to `OpenCTI`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtiAlert {
    /// Client-side ID generated before publication.
    pub local_id: String,
    /// `OpenCTI` ID after successful publication (empty until published).
    pub opencti_id: Option<String>,
    /// Alert title.
    pub title: String,
    /// Detailed description.
    pub description: Option<String>,
    /// Severity of this alert.
    pub severity: AlertSeverity,
    /// Current lifecycle status.
    pub status: AlertStatus,
    /// Source that triggered the alert.
    pub source: AlertSource,
    /// Affected indicators / observables (STIX patterns or raw values).
    pub indicators: Vec<String>,
    /// Affected assets (hostnames, IPs, user accounts).
    pub affected_assets: Vec<String>,
    /// MITRE ATT&CK technique IDs.
    pub attack_techniques: Vec<String>,
    /// Confidence.
    pub confidence: Option<Confidence>,
    /// Labels.
    pub labels: Vec<String>,
    /// When the alert was first detected (RFC 3339).
    pub detected_at: String,
    /// Analyst notes.
    pub notes: Vec<String>,
    /// Arbitrary metadata.
    pub metadata: HashMap<String, serde_json::Value>,
}

impl CtiAlert {
    /// Create a new alert with default status `New`.
    #[must_use]
    pub fn new(
        local_id: impl Into<String>,
        title: impl Into<String>,
        severity: AlertSeverity,
        source: AlertSource,
    ) -> Self {
        Self {
            local_id: local_id.into(),
            opencti_id: None,
            title: title.into(),
            description: None,
            severity,
            status: AlertStatus::New,
            source,
            indicators: vec![],
            affected_assets: vec![],
            attack_techniques: vec![],
            confidence: None,
            labels: vec![],
            detected_at: "2024-01-01T00:00:00Z".to_string(),
            notes: vec![],
            metadata: HashMap::new(),
        }
    }

    /// Add an affected indicator.
    pub fn add_indicator(&mut self, indicator: impl Into<String>) {
        self.indicators.push(indicator.into());
    }

    /// Add an affected asset.
    pub fn add_asset(&mut self, asset: impl Into<String>) {
        self.affected_assets.push(asset.into());
    }

    /// Add a MITRE ATT&CK technique.
    pub fn add_technique(&mut self, technique: impl Into<String>) {
        self.attack_techniques.push(technique.into());
    }

    /// Add a label.
    pub fn add_label(&mut self, label: impl Into<String>) {
        self.labels.push(label.into());
    }

    /// Add a note.
    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    /// Escalate the alert to `Escalated` status.
    pub const fn escalate(&mut self) {
        self.status = AlertStatus::Escalated;
    }

    /// Resolve the alert.
    pub const fn resolve(&mut self) {
        self.status = AlertStatus::Resolved;
    }

    /// Mark as false positive.
    pub const fn mark_false_positive(&mut self) {
        self.status = AlertStatus::FalsePositive;
    }

    /// Returns `true` if the alert is still actionable.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(
            self.status,
            AlertStatus::New | AlertStatus::InProgress | AlertStatus::Escalated
        )
    }

    /// Returns `true` if the alert was published to `OpenCTI`.
    #[must_use]
    pub const fn is_published(&self) -> bool {
        self.opencti_id.is_some()
    }

    /// Build the GraphQL mutation input for this alert.
    #[must_use]
    pub fn to_graphql_input(&self) -> HashMap<String, serde_json::Value> {
        let mut input = HashMap::new();
        input.insert(
            "name".to_string(),
            serde_json::Value::String(self.title.clone()),
        );
        if let Some(desc) = &self.description {
            input.insert(
                "description".to_string(),
                serde_json::Value::String(desc.clone()),
            );
        }
        input.insert(
            "severity".to_string(),
            serde_json::Value::String(self.severity.to_string()),
        );
        input.insert(
            "x_opencti_workflow_id".to_string(),
            serde_json::Value::String(self.status.to_string()),
        );
        if let Some(c) = self.confidence {
            input.insert(
                "confidence".to_string(),
                serde_json::Value::Number(serde_json::Number::from(c.value())),
            );
        }
        input.insert(
            "labels".to_string(),
            serde_json::Value::Array(
                self.labels
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
        input
    }

    /// Create a sample alert for unit tests.
    #[must_use]
    pub fn sample() -> Self {
        let source = AlertSource::new("rustre-sandbox")
            .with_feed("dynamic-analysis")
            .with_url("https://sandbox.example.com/jobs/job-00000001");

        let mut alert = Self::new(
            "alert-local-001",
            "Suspected Emotet dropper executed on WORKSTATION-01",
            AlertSeverity::High,
            source,
        );
        alert.description = Some(
            "Dynamic analysis detected process injection and C2 beacon behaviour.".to_string(),
        );
        alert.add_indicator("[ipv4-addr:value = '185.220.101.1']");
        alert.add_asset("WORKSTATION-01");
        alert.add_technique("T1055");
        alert.add_technique("T1071");
        alert.add_label("emotet");
        alert.add_label("c2");
        alert.confidence = Some(Confidence::HIGH);
        alert
    }
}

// ─── AlertBuilder ─────────────────────────────────────────────────────────────

/// Fluent builder for `CtiAlert` objects.
pub struct AlertBuilder {
    inner: CtiAlert,
}

impl AlertBuilder {
    /// Start building an alert.
    #[must_use]
    pub fn new(
        local_id: impl Into<String>,
        title: impl Into<String>,
        severity: AlertSeverity,
        source: AlertSource,
    ) -> Self {
        Self {
            inner: CtiAlert::new(local_id, title, severity, source),
        }
    }

    /// Set description.
    #[must_use]
    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.inner.description = Some(d.into());
        self
    }

    /// Set confidence.
    #[must_use]
    pub const fn confidence(mut self, c: Confidence) -> Self {
        self.inner.confidence = Some(c);
        self
    }

    /// Add an indicator.
    #[must_use]
    pub fn indicator(mut self, ind: impl Into<String>) -> Self {
        self.inner.add_indicator(ind);
        self
    }

    /// Add an affected asset.
    #[must_use]
    pub fn asset(mut self, asset: impl Into<String>) -> Self {
        self.inner.add_asset(asset);
        self
    }

    /// Add an ATT&CK technique.
    #[must_use]
    pub fn technique(mut self, t: impl Into<String>) -> Self {
        self.inner.add_technique(t);
        self
    }

    /// Add a label.
    #[must_use]
    pub fn label(mut self, l: impl Into<String>) -> Self {
        self.inner.add_label(l);
        self
    }

    /// Set the detection timestamp.
    #[must_use]
    pub fn detected_at(mut self, ts: impl Into<String>) -> Self {
        self.inner.detected_at = ts.into();
        self
    }

    /// Finish building and return the `CtiAlert`.
    #[must_use]
    pub fn build(self) -> CtiAlert {
        self.inner
    }
}

// ─── PublishResult ────────────────────────────────────────────────────────────

/// Result of publishing an alert to `OpenCTI`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishResult {
    /// The local ID of the alert.
    pub local_id: String,
    /// The `OpenCTI` ID assigned after publication.
    pub opencti_id: Option<String>,
    /// Whether the publication succeeded.
    pub success: bool,
    /// Error message if publication failed.
    pub error: Option<String>,
    /// Round-trip time in milliseconds.
    pub rtt_ms: u64,
}

impl PublishResult {
    /// Create a successful result.
    #[must_use]
    pub fn ok(local_id: impl Into<String>, opencti_id: impl Into<String>, rtt_ms: u64) -> Self {
        Self {
            local_id: local_id.into(),
            opencti_id: Some(opencti_id.into()),
            success: true,
            error: None,
            rtt_ms,
        }
    }

    /// Create a failure result.
    #[must_use]
    pub fn err(local_id: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            local_id: local_id.into(),
            opencti_id: None,
            success: false,
            error: Some(error.into()),
            rtt_ms: 0,
        }
    }
}

// ─── OpenCtiAlertCreator ──────────────────────────────────────────────────────

/// Creates and publishes CTI alerts to an `OpenCTI` platform.
pub struct OpenCtiAlertCreator {
    config: OpenCtiConfig,
    /// When `true`, mutations are built but not sent.
    dry_run: bool,
}

impl OpenCtiAlertCreator {
    /// Create a new alert creator.
    #[must_use]
    pub const fn new(config: OpenCtiConfig) -> Self {
        Self {
            config,
            dry_run: false,
        }
    }

    /// Enable dry-run mode (build the mutation but do not publish it).
    #[must_use]
    pub const fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    /// Escape a string value for safe inline embedding in a GraphQL literal.
    ///
    /// GraphQL string literals use the same escape sequences as JSON, so we
    /// re-serialise the value through `serde_json` to get a properly-escaped
    /// double-quoted string.  This prevents injection via titles or descriptions
    /// that contain `"`, `\`, or newline characters.
    fn graphql_string_literal(s: &str) -> String {
        // serde_json::to_string on a &str produces a JSON-quoted string which
        // is also valid as a GraphQL string literal.
        serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
    }

    /// Build a GraphQL mutation for creating a note / alert-like object.
    ///
    /// Fields are sorted alphabetically for deterministic output.
    /// String values are re-serialised through `serde_json` to ensure all
    /// special characters are properly escaped before inline embedding.
    fn build_mutation(alert: &CtiAlert) -> String {
        use std::collections::BTreeMap;

        let input = alert.to_graphql_input();
        // Sort keys for reproducible output (HashMap iteration order is random).
        let sorted: BTreeMap<_, _> = input.iter().collect();
        let fields: Vec<String> = sorted
            .iter()
            .map(|(k, v)| {
                // Emit each value as a GraphQL literal:
                //   JSON strings  → re-escaped GraphQL string (safe against injection)
                //   JSON numbers  → GraphQL Int/Float (unquoted)
                //   JSON arrays   → GraphQL list literal (string elements re-escaped)
                //   other         → JSON representation (safe fallback)
                let literal = match v {
                    serde_json::Value::String(s) => Self::graphql_string_literal(s),
                    serde_json::Value::Array(arr) => {
                        let items: Vec<String> = arr
                            .iter()
                            .map(|item| match item {
                                serde_json::Value::String(s) => Self::graphql_string_literal(s),
                                other => other.to_string(),
                            })
                            .collect();
                        format!("[{}]", items.join(", "))
                    }
                    other => other.to_string(),
                };
                format!("{k}: {literal}")
            })
            .collect();
        format!(
            "mutation {{ noteAdd(input: {{ {} }}) {{ id standard_id }} }}",
            fields.join(", ")
        )
    }

    /// Create and publish a single alert.
    ///
    /// In dry-run mode, the mutation is returned as a string without being sent.
    ///
    /// # Errors
    /// Returns `OpenCtiError::Http` if the request fails in non-dry-run mode.
    pub fn create_alert(&self, alert: &mut CtiAlert) -> Result<PublishResult, OpenCtiError> {
        let start = std::time::Instant::now();
        let mutation = Self::build_mutation(alert);

        if self.dry_run {
            // Simulate a successful publication.
            let fake_id = format!("opencti-{}", alert.local_id);
            alert.opencti_id = Some(fake_id.clone());
            return Ok(PublishResult::ok(
                alert.local_id.clone(),
                fake_id,
                u64::try_from(start.elapsed().as_millis().min(u128::from(u64::MAX))).unwrap_or(u64::MAX),
            ));
        }

        // Real HTTP: POST mutation to GraphQL endpoint.
        // Without an async runtime or reqwest in scope, we return an error.
        let _ = mutation;
        Err(OpenCtiError::Http(
            "real HTTP not supported without runtime; use dry_run()".into(),
        ))
    }

    /// Publish a batch of alerts.
    ///
    /// Returns one `PublishResult` per alert, in the same order.
    /// Failures in individual alerts do not abort the batch.
    pub fn create_alerts_batch(&self, alerts: &mut [CtiAlert]) -> Vec<PublishResult> {
        alerts
            .iter_mut()
            .map(|alert| {
                self.create_alert(alert)
                    .unwrap_or_else(|e| PublishResult::err(alert.local_id.clone(), e.to_string()))
            })
            .collect()
    }

    /// Validate an alert before publishing.
    ///
    /// # Errors
    /// Returns `OpenCtiError::InvalidInput` if the alert is missing required fields.
    pub fn validate(&self, alert: &CtiAlert) -> Result<(), OpenCtiError> {
        if alert.title.is_empty() {
            return Err(OpenCtiError::InvalidInput("alert title is empty".into()));
        }
        if alert.source.system.is_empty() {
            return Err(OpenCtiError::InvalidInput(
                "alert source system is empty".into(),
            ));
        }
        if alert.local_id.is_empty() {
            return Err(OpenCtiError::InvalidInput("alert local_id is empty".into()));
        }
        Ok(())
    }

    /// Derive an alert severity from a numeric threat score (0–100).
    #[must_use]
    pub const fn severity_from_score(score: u8) -> AlertSeverity {
        AlertSeverity::from_score(score)
    }

    /// Build and validate an alert from a sandbox threat score and IOC list.
    ///
    /// # Errors
    /// Returns `OpenCtiError::InvalidInput` if the generated alert is invalid.
    pub fn alert_from_sandbox_score(
        &self,
        job_id: &str,
        threat_score: u8,
        iocs: &[String],
        assets: &[String],
    ) -> Result<CtiAlert, OpenCtiError> {
        let severity = Self::severity_from_score(threat_score);
        let source = AlertSource::new("rustre-sandbox")
            .with_feed("dynamic-analysis")
            .with_url(format!("{}/jobs/{job_id}", self.config.base_url));

        let mut alert = AlertBuilder::new(
            format!("sandbox-{job_id}"),
            format!("Sandbox alert — threat score {threat_score}"),
            severity,
            source,
        )
        .confidence(Confidence::new(threat_score))
        .description(format!(
            "Automated alert from RustRE sandbox job {job_id} (threat score: {threat_score}/100)."
        ))
        .build();

        for ioc in iocs {
            alert.add_indicator(ioc);
        }
        for asset in assets {
            alert.add_asset(asset);
        }
        if threat_score >= 60 {
            alert.add_label("high-threat");
        }
        if threat_score >= 80 {
            alert.add_label("critical");
        }

        self.validate(&alert)?;
        Ok(alert)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_creator() -> OpenCtiAlertCreator {
        let cfg = OpenCtiConfig::new("https://opencti.example.com", "token");
        OpenCtiAlertCreator::new(cfg).dry_run()
    }

    #[test]
    fn test_alert_sample_fields() {
        let alert = CtiAlert::sample();
        assert!(alert.is_active());
        assert!(!alert.is_published());
        assert_eq!(alert.severity, AlertSeverity::High);
        assert_eq!(alert.indicators.len(), 1);
        assert_eq!(alert.attack_techniques.len(), 2);
    }

    #[test]
    fn test_alert_lifecycle() {
        let mut alert = CtiAlert::sample();
        assert_eq!(alert.status, AlertStatus::New);
        alert.escalate();
        assert_eq!(alert.status, AlertStatus::Escalated);
        assert!(alert.is_active());
        alert.resolve();
        assert_eq!(alert.status, AlertStatus::Resolved);
        assert!(!alert.is_active());
    }

    #[test]
    fn test_severity_from_score() {
        assert_eq!(AlertSeverity::from_score(10), AlertSeverity::Informational);
        assert_eq!(AlertSeverity::from_score(50), AlertSeverity::Medium);
        assert_eq!(AlertSeverity::from_score(90), AlertSeverity::Critical);
    }

    #[test]
    fn test_create_alert_dry_run() {
        let creator = make_creator();
        let mut alert = CtiAlert::sample();
        let result = creator.create_alert(&mut alert).expect("dry run should succeed");
        assert!(result.success);
        assert!(result.opencti_id.is_some());
        assert!(alert.is_published());
    }

    #[test]
    fn test_validate_empty_title() {
        let creator = make_creator();
        let mut alert = CtiAlert::sample();
        alert.title = String::new();
        let result = creator.validate(&alert);
        assert!(result.is_err());
    }

    #[test]
    fn test_alert_from_sandbox_score_high() {
        let creator = make_creator();
        let iocs = vec!["185.220.101.1".to_string()];
        let assets = vec!["WORKSTATION-01".to_string()];
        let alert = creator
            .alert_from_sandbox_score("job-00000001", 85, &iocs, &assets)
            .expect("should build");
        assert_eq!(alert.severity, AlertSeverity::Critical);
        assert!(alert.labels.contains(&"critical".to_string()));
    }

    #[test]
    fn test_alert_from_sandbox_score_low() {
        let creator = make_creator();
        let alert = creator
            .alert_from_sandbox_score("job-00000002", 15, &[], &[])
            .expect("should build");
        assert_eq!(alert.severity, AlertSeverity::Informational);
    }

    #[test]
    fn test_batch_publish() {
        let creator = make_creator();
        let mut alerts = vec![CtiAlert::sample(), CtiAlert::sample()];
        alerts[1].local_id = "alert-local-002".to_string();
        let results = creator.create_alerts_batch(&mut alerts);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.success));
    }

    #[test]
    fn test_alert_builder() {
        let source = AlertSource::new("test-system");
        let alert = AlertBuilder::new("ab-001", "Test alert", AlertSeverity::Medium, source)
            .description("A test")
            .confidence(Confidence::MEDIUM)
            .indicator("[domain-name:value = 'evil.com']")
            .asset("SERVER-01")
            .technique("T1190")
            .label("test")
            .detected_at("2024-06-01T12:00:00Z")
            .build();

        assert_eq!(alert.severity, AlertSeverity::Medium);
        assert_eq!(alert.indicators.len(), 1);
        assert_eq!(alert.affected_assets.len(), 1);
        assert_eq!(alert.attack_techniques.len(), 1);
    }

    #[test]
    fn test_graphql_input_has_required_fields() {
        let alert = CtiAlert::sample();
        let input = alert.to_graphql_input();
        assert!(input.contains_key("name"));
        assert!(input.contains_key("severity"));
    }
}
