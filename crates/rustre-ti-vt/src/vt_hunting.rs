//! `vt_hunting` — `VirusTotal` retrohunt and livehunt integration:
//! hunt job management, rule CRUD, match streaming, and statistics.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// HuntRule
// ---------------------------------------------------------------------------

/// Status of a hunt rule or job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HuntStatus {
    Active,
    Paused,
    Completed,
    Failed(String),
    Pending,
    Queued,
}

impl fmt::Display for HuntStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Paused => write!(f, "paused"),
            Self::Completed => write!(f, "completed"),
            Self::Failed(reason) => write!(f, "failed: {reason}"),
            Self::Pending => write!(f, "pending"),
            Self::Queued => write!(f, "queued"),
        }
    }
}

/// A YARA hunting rule (livehunt or retrohunt).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntRule {
    pub id: String,
    pub name: String,
    pub yara_source: String,
    pub enabled: bool,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub created_at: u64,
    pub modified_at: u64,
    pub notification_emails: Vec<String>,
    pub match_limit: Option<u64>,
}

impl HuntRule {
    /// Create a new rule.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        yara_source: impl Into<String>,
    ) -> Self {
        let now = current_timestamp();
        Self {
            id: id.into(),
            name: name.into(),
            yara_source: yara_source.into(),
            enabled: true,
            tags: Vec::new(),
            metadata: HashMap::new(),
            created_at: now,
            modified_at: now,
            notification_emails: Vec::new(),
            match_limit: None,
        }
    }

    /// Whether this rule contains valid (non-empty) YARA source.
    #[must_use]
    pub fn has_valid_source(&self) -> bool {
        !self.yara_source.trim().is_empty() && self.yara_source.contains("rule ")
    }

    /// Add a tag.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }
}

impl fmt::Display for HuntRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HuntRule({}, enabled={}, tags=[{}])",
            self.name,
            self.enabled,
            self.tags.join(", ")
        )
    }
}

// ---------------------------------------------------------------------------
// HuntMatch
// ---------------------------------------------------------------------------

/// A single file match produced by a hunt rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub file_sha256: String,
    pub file_name: Option<String>,
    pub file_size: Option<u64>,
    pub file_type: Option<String>,
    pub detection_ratio: Option<String>,
    pub matched_at: u64,
    pub matched_tags: Vec<String>,
    pub matched_rule_names: Vec<String>,
    pub attributes: HashMap<String, String>,
}

impl HuntMatch {
    /// Create a minimal match.
    #[must_use]
    pub fn new(rule_id: impl Into<String>, sha256: impl Into<String>) -> Self {
        Self {
            rule_id: rule_id.into(),
            rule_name: String::new(),
            file_sha256: sha256.into(),
            file_name: None,
            file_size: None,
            file_type: None,
            detection_ratio: None,
            matched_at: current_timestamp(),
            matched_tags: Vec::new(),
            matched_rule_names: Vec::new(),
            attributes: HashMap::new(),
        }
    }

    /// Whether this match has a high detection ratio.
    #[must_use]
    pub fn is_highly_detected(&self) -> bool {
        if let Some(ratio) = &self.detection_ratio {
            let parts: Vec<&str> = ratio.split('/').collect();
            if parts.len() == 2 {
                let detected: u32 = parts[0].parse().unwrap_or(0);
                let total: u32 = parts[1].parse().unwrap_or(1);
                return detected as f32 / total as f32 > 0.5;
            }
        }
        false
    }
}

impl fmt::Display for HuntMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HuntMatch({}: {})", self.rule_id, self.file_sha256)
    }
}

// ---------------------------------------------------------------------------
// HuntStatistics
// ---------------------------------------------------------------------------

/// Aggregate statistics for a hunt.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HuntStatistics {
    pub total_matches: u64,
    pub unique_files: u64,
    pub total_files_scanned: u64,
    pub match_rate: f64,
    pub top_file_types: HashMap<String, u64>,
    pub top_detection_ratios: Vec<String>,
    pub matches_by_day: HashMap<String, u64>,
    pub total_malicious: u64,
    pub total_benign: u64,
}

impl HuntStatistics {
    /// Record a new match.
    pub fn record_match(&mut self, m: &HuntMatch) {
        self.total_matches += 1;
        if let Some(ftype) = &m.file_type {
            *self.top_file_types.entry(ftype.clone()).or_insert(0) += 1;
        }
        if m.is_highly_detected() {
            self.total_malicious += 1;
        } else {
            self.total_benign += 1;
        }
    }

    /// Compute the match rate.
    pub fn update_match_rate(&mut self) {
        self.match_rate = if self.total_files_scanned > 0 {
            self.total_matches as f64 / self.total_files_scanned as f64
        } else {
            0.0
        };
    }
}

impl fmt::Display for HuntStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HuntStats: {} matches, {} files, {:.2}% match rate",
            self.total_matches,
            self.total_files_scanned,
            self.match_rate * 100.0
        )
    }
}

// ---------------------------------------------------------------------------
// RetroHuntJob
// ---------------------------------------------------------------------------

/// A `VirusTotal` retrohunt job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetroHuntJob {
    pub job_id: String,
    pub rule: HuntRule,
    pub status: HuntStatus,
    pub creation_date: u64,
    pub start_date: Option<u64>,
    pub finish_date: Option<u64>,
    pub corpus: String,
    pub time_range_start: Option<u64>,
    pub time_range_end: Option<u64>,
    pub progress: f32,
    pub total_matches: u64,
    pub estimated_completion_secs: Option<u64>,
    pub matches: Vec<HuntMatch>,
    pub statistics: HuntStatistics,
}

impl RetroHuntJob {
    /// Create a new retrohunt job.
    #[must_use]
    pub fn new(job_id: impl Into<String>, rule: HuntRule) -> Self {
        Self {
            job_id: job_id.into(),
            rule,
            status: HuntStatus::Pending,
            creation_date: current_timestamp(),
            start_date: None,
            finish_date: None,
            corpus: "main".to_string(),
            time_range_start: None,
            time_range_end: None,
            progress: 0.0,
            total_matches: 0,
            estimated_completion_secs: None,
            matches: Vec::new(),
            statistics: HuntStatistics::default(),
        }
    }

    /// Mark the job as started.
    pub fn start(&mut self) {
        self.status = HuntStatus::Active;
        self.start_date = Some(current_timestamp());
    }

    /// Mark the job as complete.
    pub fn complete(&mut self) {
        self.status = HuntStatus::Completed;
        self.finish_date = Some(current_timestamp());
        self.progress = 1.0;
        self.statistics.update_match_rate();
    }

    /// Add a match to this job.
    pub fn add_match(&mut self, m: HuntMatch) {
        self.statistics.record_match(&m);
        self.total_matches += 1;
        self.matches.push(m);
    }

    /// Whether the job is still in progress.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(
            self.status,
            HuntStatus::Active | HuntStatus::Queued | HuntStatus::Pending
        )
    }

    /// Elapsed time since creation (in seconds).
    #[must_use]
    pub fn elapsed_secs(&self) -> u64 {
        current_timestamp().saturating_sub(self.creation_date)
    }
}

impl fmt::Display for RetroHuntJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RetroHuntJob({}: {} matches, status={})",
            self.job_id, self.total_matches, self.status
        )
    }
}

// ---------------------------------------------------------------------------
// LiveHunt
// ---------------------------------------------------------------------------

/// A livehunt notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveHuntNotification {
    pub notification_id: String,
    pub rule_id: String,
    pub file_match: HuntMatch,
    pub received_at: u64,
    pub acknowledged: bool,
}

/// A `VirusTotal` livehunt subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveHunt {
    pub subscription_id: String,
    pub rules: Vec<HuntRule>,
    pub status: HuntStatus,
    pub created_at: u64,
    pub total_notifications: u64,
    pub pending_notifications: Vec<LiveHuntNotification>,
    pub statistics: HuntStatistics,
    pub filter: Option<LiveHuntFilter>,
}

/// Filters for a livehunt subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveHuntFilter {
    pub file_types: Vec<String>,
    pub min_detection_ratio: Option<f32>,
    pub max_detection_ratio: Option<f32>,
    pub required_tags: Vec<String>,
    pub excluded_tags: Vec<String>,
}

impl LiveHunt {
    /// Create a new livehunt.
    #[must_use]
    pub fn new(subscription_id: impl Into<String>) -> Self {
        Self {
            subscription_id: subscription_id.into(),
            rules: Vec::new(),
            status: HuntStatus::Active,
            created_at: current_timestamp(),
            total_notifications: 0,
            pending_notifications: Vec::new(),
            statistics: HuntStatistics::default(),
            filter: None,
        }
    }

    /// Add a rule to this livehunt.
    pub fn add_rule(&mut self, rule: HuntRule) {
        self.rules.push(rule);
    }

    /// Process a new notification.
    pub fn receive_notification(&mut self, notif: LiveHuntNotification) {
        self.statistics.record_match(&notif.file_match);
        self.total_notifications += 1;
        self.pending_notifications.push(notif);
    }

    /// Acknowledge all pending notifications.
    pub fn acknowledge_all(&mut self) {
        for n in &mut self.pending_notifications {
            n.acknowledged = true;
        }
    }

    /// Number of unacknowledged notifications.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending_notifications
            .iter()
            .filter(|n| !n.acknowledged)
            .count()
    }
}

impl fmt::Display for LiveHunt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LiveHunt({}: {} rules, {} notifications)",
            self.subscription_id,
            self.rules.len(),
            self.total_notifications
        )
    }
}

// ---------------------------------------------------------------------------
// VtHunting — the main facade
// ---------------------------------------------------------------------------

/// `VirusTotal` hunting manager.
pub struct VtHunting {
    pub retrohunt_jobs: Vec<RetroHuntJob>,
    pub livehunts: Vec<LiveHunt>,
    pub rules: Vec<HuntRule>,
}

impl VtHunting {
    /// Create a new hunting manager.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            retrohunt_jobs: Vec::new(),
            livehunts: Vec::new(),
            rules: Vec::new(),
        }
    }

    /// Add a rule to the rule library.
    pub fn add_rule(&mut self, rule: HuntRule) {
        self.rules.push(rule);
    }

    /// Find a rule by ID.
    #[must_use]
    pub fn rule_by_id(&self, id: &str) -> Option<&HuntRule> {
        self.rules.iter().find(|r| r.id == id)
    }

    /// Create and register a new retrohunt job.
    pub fn submit_retrohunt(&mut self, rule: HuntRule) -> String {
        let job_id = format!("retrohunt-{}", current_timestamp());
        let mut job = RetroHuntJob::new(job_id.clone(), rule);
        job.start();
        self.retrohunt_jobs.push(job);
        job_id
    }

    /// Get a retrohunt job by ID.
    #[must_use]
    pub fn retrohunt_by_id(&self, id: &str) -> Option<&RetroHuntJob> {
        self.retrohunt_jobs.iter().find(|j| j.job_id == id)
    }

    /// Get a mutable retrohunt job by ID.
    #[must_use]
    pub fn retrohunt_by_id_mut(&mut self, id: &str) -> Option<&mut RetroHuntJob> {
        self.retrohunt_jobs.iter_mut().find(|j| j.job_id == id)
    }

    /// Create a new livehunt.
    pub fn create_livehunt(&mut self, rules: Vec<HuntRule>) -> String {
        let sub_id = format!("livehunt-{}", current_timestamp());
        let mut lh = LiveHunt::new(sub_id.clone());
        for r in rules {
            lh.add_rule(r);
        }
        self.livehunts.push(lh);
        sub_id
    }

    /// Total matches across all retrohunt jobs.
    #[must_use]
    pub fn total_retrohunt_matches(&self) -> u64 {
        self.retrohunt_jobs.iter().map(|j| j.total_matches).sum()
    }

    /// Active livehunts.
    #[must_use]
    pub fn active_livehunts(&self) -> Vec<&LiveHunt> {
        self.livehunts
            .iter()
            .filter(|lh| matches!(lh.status, HuntStatus::Active))
            .collect()
    }
}

impl Default for VtHunting {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for VtHunting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VtHunting({} jobs, {} livehunts, {} rules)",
            self.retrohunt_jobs.len(),
            self.livehunts.len(),
            self.rules.len()
        )
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(id: &str) -> HuntRule {
        HuntRule::new(id, "TestRule", r"rule TestRule { condition: true }")
    }

    #[test]
    fn test_hunt_rule_new() {
        let r = make_rule("R1");
        assert_eq!(r.id, "R1");
        assert!(r.enabled);
        assert!(r.tags.is_empty());
    }

    #[test]
    fn test_hunt_rule_has_valid_source() {
        let r = make_rule("R1");
        assert!(r.has_valid_source());
    }

    #[test]
    fn test_hunt_rule_invalid_source() {
        let r = HuntRule::new("R2", "Empty", "");
        assert!(!r.has_valid_source());
    }

    #[test]
    fn test_hunt_rule_add_tag() {
        let mut r = make_rule("R1");
        r.add_tag("malware");
        assert!(r.tags.contains(&"malware".to_string()));
    }

    #[test]
    fn test_hunt_rule_display() {
        let r = make_rule("R1");
        let s = r.to_string();
        assert!(s.contains("TestRule"));
    }

    #[test]
    fn test_hunt_match_new() {
        let m = HuntMatch::new("R1", "abc123");
        assert_eq!(m.rule_id, "R1");
        assert_eq!(m.file_sha256, "abc123");
        assert!(!m.is_highly_detected());
    }

    #[test]
    fn test_hunt_match_highly_detected() {
        let mut m = HuntMatch::new("R1", "abc");
        m.detection_ratio = Some("55/70".to_string());
        assert!(m.is_highly_detected());
    }

    #[test]
    fn test_hunt_match_not_highly_detected() {
        let mut m = HuntMatch::new("R1", "abc");
        m.detection_ratio = Some("2/70".to_string());
        assert!(!m.is_highly_detected());
    }

    #[test]
    fn test_hunt_match_display() {
        let m = HuntMatch::new("R1", "abc123");
        let s = m.to_string();
        assert!(s.contains("R1"));
        assert!(s.contains("abc123"));
    }

    #[test]
    fn test_retrohunt_job_new() {
        let r = make_rule("R1");
        let job = RetroHuntJob::new("J1", r);
        assert_eq!(job.job_id, "J1");
        assert_eq!(job.total_matches, 0);
        assert!(job.is_running());
    }

    #[test]
    fn test_retrohunt_job_start() {
        let r = make_rule("R1");
        let mut job = RetroHuntJob::new("J1", r);
        job.start();
        assert_eq!(job.status, HuntStatus::Active);
        assert!(job.start_date.is_some());
    }

    #[test]
    fn test_retrohunt_job_complete() {
        let r = make_rule("R1");
        let mut job = RetroHuntJob::new("J1", r);
        job.start();
        job.complete();
        assert_eq!(job.status, HuntStatus::Completed);
        assert!(!job.is_running());
    }

    #[test]
    fn test_retrohunt_job_add_match() {
        let r = make_rule("R1");
        let mut job = RetroHuntJob::new("J1", r);
        job.add_match(HuntMatch::new("R1", "sha256_abc"));
        assert_eq!(job.total_matches, 1);
        assert_eq!(job.matches.len(), 1);
    }

    #[test]
    fn test_retrohunt_job_display() {
        let r = make_rule("R1");
        let job = RetroHuntJob::new("J1", r);
        let s = job.to_string();
        assert!(s.contains("J1"));
    }

    #[test]
    fn test_hunt_statistics_record() {
        let mut stats = HuntStatistics::default();
        let mut m = HuntMatch::new("R1", "abc");
        m.detection_ratio = Some("40/70".to_string());
        m.file_type = Some("PE".to_string());
        stats.record_match(&m);
        assert_eq!(stats.total_matches, 1);
        assert_eq!(stats.top_file_types["PE"], 1);
    }

    #[test]
    fn test_hunt_statistics_match_rate() {
        let mut stats = HuntStatistics {
            total_matches: 10,
            total_files_scanned: 100,
            ..HuntStatistics::default()
        };
        stats.update_match_rate();
        assert!((stats.match_rate - 0.1).abs() < 0.001);
    }

    #[test]
    fn test_hunt_status_display() {
        assert_eq!(HuntStatus::Active.to_string(), "active");
        assert_eq!(HuntStatus::Completed.to_string(), "completed");
    }

    #[test]
    fn test_livehunt_new() {
        let lh = LiveHunt::new("LH1");
        assert_eq!(lh.subscription_id, "LH1");
        assert_eq!(lh.pending_count(), 0);
    }

    #[test]
    fn test_livehunt_add_rule() {
        let mut lh = LiveHunt::new("LH1");
        lh.add_rule(make_rule("R1"));
        assert_eq!(lh.rules.len(), 1);
    }

    #[test]
    fn test_livehunt_receive_notification() {
        let mut lh = LiveHunt::new("LH1");
        let notif = LiveHuntNotification {
            notification_id: "N1".to_string(),
            rule_id: "R1".to_string(),
            file_match: HuntMatch::new("R1", "abc"),
            received_at: current_timestamp(),
            acknowledged: false,
        };
        lh.receive_notification(notif);
        assert_eq!(lh.pending_count(), 1);
    }

    #[test]
    fn test_livehunt_acknowledge_all() {
        let mut lh = LiveHunt::new("LH1");
        let notif = LiveHuntNotification {
            notification_id: "N1".to_string(),
            rule_id: "R1".to_string(),
            file_match: HuntMatch::new("R1", "abc"),
            received_at: current_timestamp(),
            acknowledged: false,
        };
        lh.receive_notification(notif);
        lh.acknowledge_all();
        assert_eq!(lh.pending_count(), 0);
    }

    #[test]
    fn test_livehunt_display() {
        let lh = LiveHunt::new("LH1");
        let s = lh.to_string();
        assert!(s.contains("LH1"));
    }

    #[test]
    fn test_vt_hunting_submit_retrohunt() {
        let mut vt = VtHunting::new();
        let rule = make_rule("R1");
        let job_id = vt.submit_retrohunt(rule);
        assert!(!job_id.is_empty());
        assert!(vt.retrohunt_by_id(&job_id).is_some());
    }

    #[test]
    fn test_vt_hunting_create_livehunt() {
        let mut vt = VtHunting::new();
        let rules = vec![make_rule("R1"), make_rule("R2")];
        let sub_id = vt.create_livehunt(rules);
        assert!(!sub_id.is_empty());
        assert_eq!(vt.livehunts.len(), 1);
    }

    #[test]
    fn test_vt_hunting_total_matches() {
        let mut vt = VtHunting::new();
        let job_id = vt.submit_retrohunt(make_rule("R1"));
        {
            let job = vt.retrohunt_by_id_mut(&job_id).unwrap();
            job.add_match(HuntMatch::new("R1", "a"));
            job.add_match(HuntMatch::new("R1", "b"));
        }
        assert_eq!(vt.total_retrohunt_matches(), 2);
    }

    #[test]
    fn test_vt_hunting_active_livehunts() {
        let mut vt = VtHunting::new();
        vt.create_livehunt(vec![]);
        assert_eq!(vt.active_livehunts().len(), 1);
    }

    #[test]
    fn test_vt_hunting_add_rule() {
        let mut vt = VtHunting::new();
        vt.add_rule(make_rule("R1"));
        assert_eq!(vt.rules.len(), 1);
    }

    #[test]
    fn test_vt_hunting_rule_by_id() {
        let mut vt = VtHunting::new();
        vt.add_rule(make_rule("R1"));
        assert!(vt.rule_by_id("R1").is_some());
        assert!(vt.rule_by_id("R999").is_none());
    }
}
