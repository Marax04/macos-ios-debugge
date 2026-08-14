//! `alert_correlator` — Time-window alert correlation and grouping.
//!
//! Provides [`AlertCorrelator`], [`Alert`], [`AlertGroup`], and
//! [`correlate_alerts`] for collapsing burst alerts into correlated groups.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────────────────────────────
// Severity
// ─────────────────────────────────────────────────────────────────────────────

/// Alert severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    /// Convert a numeric level (0–4) to a `Severity`.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Info,
            1 => Self::Low,
            2 => Self::Medium,
            3 => Self::High,
            _ => Self::Critical,
        }
    }

    /// Convert to a numeric level.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AlertStatus
// ─────────────────────────────────────────────────────────────────────────────

/// Lifecycle state of an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertStatus {
    New,
    Acknowledged,
    InProgress,
    Resolved,
    FalsePositive,
}

impl fmt::Display for AlertStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::New => write!(f, "new"),
            Self::Acknowledged => write!(f, "acknowledged"),
            Self::InProgress => write!(f, "in_progress"),
            Self::Resolved => write!(f, "resolved"),
            Self::FalsePositive => write!(f, "false_positive"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Alert
// ─────────────────────────────────────────────────────────────────────────────

/// A single network detection alert.
#[derive(Debug, Clone)]
pub struct Alert {
    /// Unique alert identifier.
    pub id: u64,
    /// The rule or signature that generated this alert.
    pub rule_id: u32,
    /// Human-readable alert message.
    pub message: String,
    /// Severity level.
    pub severity: Severity,
    /// Unix timestamp (seconds) when the alert was generated.
    pub timestamp: u64,
    /// Source IP address.
    pub src_ip: IpAddr,
    /// Destination IP address.
    pub dst_ip: IpAddr,
    /// Source port (0 if not applicable).
    pub src_port: u16,
    /// Destination port (0 if not applicable).
    pub dst_port: u16,
    /// IP protocol number.
    pub proto: u8,
    /// Optional classification string.
    pub classification: Option<String>,
    /// Current lifecycle status.
    pub status: AlertStatus,
    /// Optional payload snippet (first N bytes).
    pub payload_snippet: Option<Vec<u8>>,
}

impl Alert {
    /// Create a minimal alert.
    #[must_use]
    pub fn new(
        id: u64,
        rule_id: u32,
        message: impl Into<String>,
        severity: Severity,
        src_ip: IpAddr,
        dst_ip: IpAddr,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Self {
            id,
            rule_id,
            message: message.into(),
            severity,
            timestamp,
            src_ip,
            dst_ip,
            src_port: 0,
            dst_port: 0,
            proto: 6,
            classification: None,
            status: AlertStatus::New,
            payload_snippet: None,
        }
    }

    /// Create with explicit timestamp (useful for deterministic tests).
    #[must_use]
    pub fn new_with_ts(
        id: u64,
        rule_id: u32,
        message: impl Into<String>,
        severity: Severity,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        timestamp: u64,
    ) -> Self {
        let mut a = Self::new(id, rule_id, message, severity, src_ip, dst_ip);
        a.timestamp = timestamp;
        a
    }

    /// Return `true` if this alert's `(src_ip, dst_ip, rule_id)` matches `other`.
    #[must_use]
    pub fn same_flow_and_rule(&self, other: &Self) -> bool {
        self.rule_id == other.rule_id
            && self.src_ip == other.src_ip
            && self.dst_ip == other.dst_ip
    }

    /// Return `true` if this alert falls within `window` seconds of `ts`.
    #[must_use]
    pub const fn within_window(&self, ts: u64, window_secs: u64) -> bool {
        let (lo, hi) = if ts >= window_secs {
            (ts - window_secs, ts + window_secs)
        } else {
            (0, ts + window_secs)
        };
        self.timestamp >= lo && self.timestamp <= hi
    }
}

impl fmt::Display for Alert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] [{}] {} → {}: {} (sid:{})",
            self.severity, self.status, self.src_ip, self.dst_ip, self.message, self.rule_id
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AlertGroup
// ─────────────────────────────────────────────────────────────────────────────

/// A group of correlated alerts.
#[derive(Debug, Clone)]
pub struct AlertGroup {
    /// Group identifier.
    pub id: u64,
    /// The alerts in this group (by ID).
    pub alert_ids: Vec<u64>,
    /// The rule ID shared by all grouped alerts.
    pub rule_id: u32,
    /// Dominant source IP.
    pub src_ip: IpAddr,
    /// Dominant destination IP.
    pub dst_ip: IpAddr,
    /// Maximum severity in this group.
    pub max_severity: Severity,
    /// Earliest timestamp in the group.
    pub first_seen: u64,
    /// Latest timestamp in the group.
    pub last_seen: u64,
    /// Human-readable summary.
    pub summary: String,
}

impl AlertGroup {
    /// Return the number of alerts in this group.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.alert_ids.len()
    }

    /// Return the duration spanned by this group.
    #[must_use]
    pub const fn span(&self) -> Duration {
        Duration::from_secs(self.last_seen.saturating_sub(self.first_seen))
    }

    /// Return `true` if this group is ongoing (last seen within `window_secs`).
    #[must_use]
    pub const fn is_active(&self, now: u64, window_secs: u64) -> bool {
        now.saturating_sub(self.last_seen) <= window_secs
    }
}

impl fmt::Display for AlertGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Group#{} [{}×{}] {} → {}: {}",
            self.id,
            self.alert_ids.len(),
            self.max_severity,
            self.src_ip,
            self.dst_ip,
            self.summary
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// correlate_alerts
// ─────────────────────────────────────────────────────────────────────────────

/// Correlate a slice of alerts into groups.
///
/// Two alerts are grouped together when they share the same
/// `(rule_id, src_ip, dst_ip)` triple and their timestamps fall within
/// `window_secs` of the earliest alert in the candidate group.
///
/// # Panics
/// Panics if internal grouping invariants are violated; this should not occur in practice.
#[must_use]
pub fn correlate_alerts(alerts: &[Alert], window_secs: u64) -> Vec<AlertGroup> {
    // Each group: (rule_id, src_ip, dst_ip) → accumulated alert indices.
    let mut key_to_group: HashMap<(u32, String, String), Vec<usize>> = HashMap::new();

    // Sort alerts by timestamp before grouping.
    let mut indexed: Vec<(usize, &Alert)> = alerts.iter().enumerate().collect();
    indexed.sort_by_key(|(_, a)| a.timestamp);

    // Assign each alert to a group based on the key and window.
    // We store the first_seen timestamp per group key to determine if a new
    // alert should start a new group instead.
    let mut group_first_seen: HashMap<(u32, String, String), u64> = HashMap::new();
    let mut group_counter: HashMap<(u32, String, String), u64> = HashMap::new();
    // group_id → alert indices
    let mut groups_by_id: HashMap<u64, Vec<usize>> = HashMap::new();
    let mut key_to_gid: HashMap<(u32, String, String), u64> = HashMap::new();
    let mut next_gid: u64 = 1;

    for (idx, alert) in &indexed {
        let key = (
            alert.rule_id,
            alert.src_ip.to_string(),
            alert.dst_ip.to_string(),
        );
        let first = group_first_seen.entry(key.clone()).or_insert(alert.timestamp);
        let within = alert.timestamp.saturating_sub(*first) <= window_secs;

        if within {
            // Belongs to existing group for this key.
            let gid = key_to_gid.entry(key.clone()).or_insert_with(|| {
                let g = next_gid;
                next_gid += 1;
                groups_by_id.insert(g, Vec::new());
                g
            });
            groups_by_id.get_mut(gid).unwrap().push(*idx);
            *group_counter.entry(key.clone()).or_insert(0) += 1;
        } else {
            // Starts a new group for this key.
            *first = alert.timestamp;
            let gid = next_gid;
            next_gid += 1;
            groups_by_id.insert(gid, vec![*idx]);
            key_to_gid.insert(key.clone(), gid);
            key_to_group.entry(key.clone()).or_default();
            *group_counter.entry(key.clone()).or_insert(0) = 1;
        }
    }

    // Build AlertGroup structs.
    let mut out = Vec::new();
    for (gid, indices) in groups_by_id {
        if indices.is_empty() {
            continue;
        }
        let group_alerts: Vec<&Alert> = indices.iter().map(|&i| &alerts[i]).collect();
        let first_seen = group_alerts.iter().map(|a| a.timestamp).min().unwrap_or(0);
        let last_seen = group_alerts.iter().map(|a| a.timestamp).max().unwrap_or(0);
        let max_severity = group_alerts
            .iter()
            .map(|a| a.severity)
            .max()
            .unwrap_or(Severity::Info);
        let representative = group_alerts[0];
        let alert_ids: Vec<u64> = group_alerts.iter().map(|a| a.id).collect();
        let summary = format!(
            "{} × '{}' ({}..{}s)",
            alert_ids.len(),
            representative.message,
            first_seen,
            last_seen
        );
        out.push(AlertGroup {
            id: gid,
            alert_ids,
            rule_id: representative.rule_id,
            src_ip: representative.src_ip,
            dst_ip: representative.dst_ip,
            max_severity,
            first_seen,
            last_seen,
            summary,
        });
    }
    out.sort_by_key(|g| g.id);
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// AlertCorrelator
// ─────────────────────────────────────────────────────────────────────────────

/// Stateful correlator that ingests alerts over time.
pub struct AlertCorrelator {
    /// Pending alerts not yet grouped.
    pending: Vec<Alert>,
    /// Finalised groups.
    groups: Vec<AlertGroup>,
    /// Correlation window in seconds.
    window_secs: u64,
    /// Total alerts ingested.
    total_ingested: u64,
    /// Suppressed alert counter (alerts dropped due to threshold).
    suppressed_count: u64,
    /// Max burst: if more than this many alerts share the same key within the
    /// window, further ones are suppressed.
    burst_threshold: u64,
    /// Per-key burst counter.
    burst_counts: HashMap<(u32, String, String), u64>,
}

impl AlertCorrelator {
    /// Create a new correlator with a correlation window and burst threshold.
    #[must_use]
    pub fn new(window_secs: u64, burst_threshold: u64) -> Self {
        Self {
            pending: Vec::new(),
            groups: Vec::new(),
            window_secs,
            total_ingested: 0,
            suppressed_count: 0,
            burst_threshold,
            burst_counts: HashMap::new(),
        }
    }

    /// Ingest a single alert.  Returns `false` if suppressed by burst limit.
    pub fn ingest(&mut self, alert: Alert) -> bool {
        self.total_ingested += 1;
        let key = (
            alert.rule_id,
            alert.src_ip.to_string(),
            alert.dst_ip.to_string(),
        );
        let count = self.burst_counts.entry(key).or_insert(0);
        if *count >= self.burst_threshold {
            self.suppressed_count += 1;
            return false;
        }
        *count += 1;
        self.pending.push(alert);
        true
    }

    /// Flush pending alerts: correlate them and append to `self.groups`.
    pub fn flush(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let new_groups = correlate_alerts(&self.pending, self.window_secs);
        self.groups.extend(new_groups);
        self.pending.clear();
        self.burst_counts.clear();
    }

    /// Ingest and immediately flush.
    pub fn ingest_and_flush(&mut self, alert: Alert) -> bool {
        let accepted = self.ingest(alert);
        self.flush();
        accepted
    }

    /// Return all finalised groups.
    #[must_use]
    pub fn groups(&self) -> &[AlertGroup] {
        &self.groups
    }

    /// Return groups with at least the given severity.
    #[must_use]
    pub fn groups_at_least(&self, sev: Severity) -> Vec<&AlertGroup> {
        self.groups
            .iter()
            .filter(|g| g.max_severity >= sev)
            .collect()
    }

    /// Return groups that are still active (last seen within `window_secs` of `now`).
    #[must_use]
    pub fn active_groups(&self, now: u64) -> Vec<&AlertGroup> {
        self.groups
            .iter()
            .filter(|g| g.is_active(now, self.window_secs))
            .collect()
    }

    /// Return total alerts ingested.
    #[must_use]
    pub const fn total_ingested(&self) -> u64 {
        self.total_ingested
    }

    /// Return number of suppressed alerts.
    #[must_use]
    pub const fn suppressed_count(&self) -> u64 {
        self.suppressed_count
    }

    /// Return the number of finalised groups.
    #[must_use]
    pub const fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Return pending (not yet flushed) alerts.
    #[must_use]
    pub fn pending(&self) -> &[Alert] {
        &self.pending
    }

    /// Clear all state.
    pub fn reset(&mut self) {
        self.pending.clear();
        self.groups.clear();
        self.burst_counts.clear();
        self.total_ingested = 0;
        self.suppressed_count = 0;
    }
}

impl Default for AlertCorrelator {
    fn default() -> Self {
        Self::new(60, 100)
    }
}

impl fmt::Debug for AlertCorrelator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AlertCorrelator")
            .field("window_secs", &self.window_secs)
            .field("pending", &self.pending.len())
            .field("groups", &self.groups.len())
            .field("total_ingested", &self.total_ingested)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    fn make_alert(id: u64, rule: u32, src: &str, dst: &str, ts: u64) -> Alert {
        Alert::new_with_ts(id, rule, "test alert", Severity::Medium, ip(src), ip(dst), ts)
    }

    #[test]
    fn alert_display() {
        let a = make_alert(1, 42, "10.0.0.1", "10.0.0.2", 0);
        let s = a.to_string();
        assert!(s.contains("10.0.0.1"));
        assert!(s.contains("sid:42"));
    }

    #[test]
    fn alert_same_flow_and_rule() {
        let a = make_alert(1, 1, "1.1.1.1", "2.2.2.2", 0);
        let b = make_alert(2, 1, "1.1.1.1", "2.2.2.2", 5);
        let c = make_alert(3, 2, "1.1.1.1", "2.2.2.2", 5);
        assert!(a.same_flow_and_rule(&b));
        assert!(!a.same_flow_and_rule(&c));
    }

    #[test]
    fn alert_within_window() {
        let a = make_alert(1, 1, "1.1.1.1", "2.2.2.2", 100);
        assert!(a.within_window(90, 15));
        assert!(!a.within_window(50, 10));
    }

    #[test]
    fn correlate_groups_same_flow() {
        let alerts = vec![
            make_alert(1, 1, "1.1.1.1", "2.2.2.2", 0),
            make_alert(2, 1, "1.1.1.1", "2.2.2.2", 5),
            make_alert(3, 1, "1.1.1.1", "2.2.2.2", 10),
        ];
        let groups = correlate_alerts(&alerts, 30);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].count(), 3);
    }

    #[test]
    fn correlate_splits_by_rule() {
        let alerts = vec![
            make_alert(1, 1, "1.1.1.1", "2.2.2.2", 0),
            make_alert(2, 2, "1.1.1.1", "2.2.2.2", 5),
        ];
        let groups = correlate_alerts(&alerts, 60);
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn correlate_splits_by_window_expiry() {
        let alerts = vec![
            make_alert(1, 1, "1.1.1.1", "2.2.2.2", 0),
            make_alert(2, 1, "1.1.1.1", "2.2.2.2", 200), // far outside 30s window
        ];
        let groups = correlate_alerts(&alerts, 30);
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn correlate_max_severity() {
        let mut high = make_alert(1, 1, "1.1.1.1", "2.2.2.2", 0);
        high.severity = Severity::High;
        let mut low = make_alert(2, 1, "1.1.1.1", "2.2.2.2", 5);
        low.severity = Severity::Low;
        let groups = correlate_alerts(&[high, low], 60);
        assert_eq!(groups[0].max_severity, Severity::High);
    }

    #[test]
    fn correlate_empty_input() {
        let groups = correlate_alerts(&[], 60);
        assert!(groups.is_empty());
    }

    #[test]
    fn correlator_ingest_and_flush() {
        let mut c = AlertCorrelator::new(30, 100);
        c.ingest(make_alert(1, 1, "1.1.1.1", "2.2.2.2", 0));
        c.ingest(make_alert(2, 1, "1.1.1.1", "2.2.2.2", 5));
        c.flush();
        assert_eq!(c.group_count(), 1);
        assert_eq!(c.total_ingested(), 2);
    }

    #[test]
    fn correlator_burst_suppression() {
        let mut c = AlertCorrelator::new(60, 2);
        c.ingest(make_alert(1, 1, "1.1.1.1", "2.2.2.2", 0));
        c.ingest(make_alert(2, 1, "1.1.1.1", "2.2.2.2", 1));
        let suppressed = !c.ingest(make_alert(3, 1, "1.1.1.1", "2.2.2.2", 2));
        assert!(suppressed);
        assert_eq!(c.suppressed_count(), 1);
    }

    #[test]
    fn correlator_reset() {
        let mut c = AlertCorrelator::new(30, 100);
        c.ingest(make_alert(1, 1, "1.1.1.1", "2.2.2.2", 0));
        c.flush();
        c.reset();
        assert_eq!(c.group_count(), 0);
        assert_eq!(c.total_ingested(), 0);
    }

    #[test]
    fn correlator_groups_at_least() {
        let mut c = AlertCorrelator::new(60, 100);
        let mut high = make_alert(1, 1, "1.1.1.1", "2.2.2.2", 0);
        high.severity = Severity::High;
        let mut info = make_alert(2, 2, "1.1.1.1", "2.2.2.2", 0);
        info.severity = Severity::Info;
        c.ingest(high);
        c.ingest(info);
        c.flush();
        let high_groups = c.groups_at_least(Severity::High);
        assert_eq!(high_groups.len(), 1);
    }

    #[test]
    fn alert_group_span() {
        let g = AlertGroup {
            id: 1,
            alert_ids: vec![1, 2, 3],
            rule_id: 1,
            src_ip: ip("1.1.1.1"),
            dst_ip: ip("2.2.2.2"),
            max_severity: Severity::Medium,
            first_seen: 100,
            last_seen: 160,
            summary: "test".into(),
        };
        assert_eq!(g.span(), Duration::from_secs(60));
    }

    #[test]
    fn alert_group_active() {
        let g = AlertGroup {
            id: 1,
            alert_ids: vec![1],
            rule_id: 1,
            src_ip: ip("1.1.1.1"),
            dst_ip: ip("2.2.2.2"),
            max_severity: Severity::Low,
            first_seen: 100,
            last_seen: 150,
            summary: "test".into(),
        };
        assert!(g.is_active(160, 30));
        assert!(!g.is_active(300, 30));
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn severity_from_u8() {
        assert_eq!(Severity::from_u8(0), Severity::Info);
        assert_eq!(Severity::from_u8(3), Severity::High);
        assert_eq!(Severity::from_u8(99), Severity::Critical);
    }

    #[test]
    fn correlator_active_groups() {
        let mut c = AlertCorrelator::new(60, 100);
        c.ingest(make_alert(1, 1, "1.1.1.1", "2.2.2.2", 1000));
        c.flush();
        let active = c.active_groups(1020);
        assert_eq!(active.len(), 1);
        let stale = c.active_groups(2000);
        assert!(stale.is_empty());
    }

    #[test]
    fn alert_group_display() {
        let g = AlertGroup {
            id: 7,
            alert_ids: vec![1, 2],
            rule_id: 42,
            src_ip: ip("10.0.0.1"),
            dst_ip: ip("10.0.0.2"),
            max_severity: Severity::High,
            first_seen: 0,
            last_seen: 10,
            summary: "summary text".into(),
        };
        let s = g.to_string();
        assert!(s.contains("Group#7"));
        assert!(s.contains("HIGH"));
    }

    #[test]
    fn correlate_single_alert() {
        let alerts = vec![make_alert(1, 1, "1.1.1.1", "2.2.2.2", 100)];
        let groups = correlate_alerts(&alerts, 60);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].count(), 1);
    }
}
