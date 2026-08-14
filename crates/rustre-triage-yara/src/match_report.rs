// rustre-triage-yara/src/match_report.rs
//! YARA match reporting: JSON/HTML export with highlighted regions.

use crate::scanner::ScanHits;
pub use crate::verdict::{FamilyAttribution, VerdictResult, YaraVerdict};
use crate::{EnhancedYaraMatch, YaraTriageMatch};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Match offset ─────────────────────────────────────────────────────────────

/// A single byte-range match location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchOffset {
    /// Rule that produced this match.
    pub rule_name: String,
    /// String identifier (e.g. `$s1`).
    pub string_id: String,
    /// Start offset in the original data.
    pub offset: u64,
    /// Length of the matched region.
    pub length: usize,
    /// Up to 32 bytes of the matched content (hex + ascii).
    pub preview_hex: String,
    pub preview_ascii: String,
}

impl MatchOffset {
    pub fn new(
        rule_name: impl Into<String>,
        string_id: impl Into<String>,
        offset: u64,
        data: &[u8],
    ) -> Self {
        let preview_bytes = &data[..data.len().min(32)];
        let preview_hex = preview_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let preview_ascii: String = preview_bytes
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        Self {
            rule_name: rule_name.into(),
            string_id: string_id.into(),
            offset,
            length: data.len(),
            preview_hex,
            preview_ascii,
        }
    }
}

// ─── Highlighted region ───────────────────────────────────────────────────────

/// A highlighted byte region for display in a hex viewer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighlightedRegion {
    pub offset: u64,
    pub length: usize,
    pub rule_name: String,
    pub string_id: String,
    pub severity: String,
    pub color: String,
}

impl HighlightedRegion {
    pub fn new(
        offset: u64,
        length: usize,
        rule_name: impl Into<String>,
        string_id: impl Into<String>,
        severity: &str,
    ) -> Self {
        let color = match severity.to_lowercase().as_str() {
            "critical" => "#ff0000",
            "high" => "#ff6600",
            "medium" => "#ffaa00",
            "low" => "#ffff00",
            "info" => "#aaaaff",
            _ => "#888888",
        }
        .to_string();
        Self {
            offset,
            length,
            rule_name: rule_name.into(),
            string_id: string_id.into(),
            severity: severity.to_string(),
            color,
        }
    }
}

// ─── Family cluster ────────────────────────────────────────────────────────────

/// Cluster of matches attributed to a single malware family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyCluster {
    pub family_name: String,
    pub rules_matched: Vec<String>,
    pub total_hits: usize,
    pub confidence: u8,
    pub severity: String,
}

// ─── Yara match report ────────────────────────────────────────────────────────

/// Complete match report for one file scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatchReport {
    pub file_hash: String,
    pub file_size: usize,
    pub scan_time_ms: u64,
    /// Overall verdict.
    pub verdict: String,
    /// Composite threat score (0–100).
    pub threat_score: u8,
    /// Individual match offsets.
    pub offsets: Vec<MatchOffset>,
    /// Highlighted regions for display.
    pub highlights: Vec<HighlightedRegion>,
    /// Family clusters derived from matches.
    pub family_clusters: Vec<FamilyCluster>,
    /// All matched rule names.
    pub matched_rules: Vec<String>,
    /// Raw enhanced YARA matches.
    pub enhanced_matches: Vec<EnhancedYaraMatch>,
    /// Raw triage matches.
    pub triage_matches: Vec<YaraTriageMatch>,
    /// Metadata key/value pairs.
    pub metadata: HashMap<String, String>,
}

impl YaraMatchReport {
    /// Build a report from scan hits.
    pub fn from_hits(hits: &ScanHits, file_hash: impl Into<String>, file_size: usize) -> Self {
        let threat_score = hits.threat_score();
        let verdict_str = if threat_score == 0 {
            "clean"
        } else if threat_score < 20 {
            "informational"
        } else if threat_score < 40 {
            "low"
        } else if threat_score < 60 {
            "suspicious"
        } else if threat_score < 80 {
            "high"
        } else {
            "malicious"
        }
        .to_string();

        let mut offsets = Vec::new();
        let mut highlights = Vec::new();
        let mut family_map: HashMap<String, FamilyCluster> = HashMap::new();
        let mut matched_rules = Vec::new();

        // Process enhanced matches
        for m in &hits.enhanced_matches {
            matched_rules.push(m.rule_name.clone());
            let sev = m
                .meta
                .get("severity")
                .map_or("medium", |s| s.as_str());
            let family = m
                .tags
                .first()
                .cloned()
                .unwrap_or_else(|| "Unknown".to_string());

            let cluster = family_map
                .entry(family.clone())
                .or_insert_with(|| FamilyCluster {
                    family_name: family.clone(),
                    rules_matched: Vec::new(),
                    total_hits: 0,
                    confidence: 0,
                    severity: "info".to_string(),
                });
            cluster.rules_matched.push(m.rule_name.clone());
            cluster.total_hits += 1;
            cluster.confidence = u8::try_from((cluster.rules_matched.len() * 20).min(95)).unwrap_or(95);
            if severity_rank(sev) > severity_rank(&cluster.severity) {
                cluster.severity = sev.to_string();
            }

            for sh in &m.string_matches {
                for (i, &off) in sh.offsets.iter().enumerate() {
                    let data = sh.matched_bytes.get(i).map_or(&[][..], Vec::as_slice);
                    offsets.push(MatchOffset::new(&m.rule_name, &sh.pattern_id, off, data));
                    highlights.push(HighlightedRegion::new(
                        off,
                        data.len(),
                        &m.rule_name,
                        &sh.pattern_id,
                        sev,
                    ));
                }
            }
        }

        // Process triage matches
        for m in &hits.triage_matches {
            matched_rules.push(m.rule_name.clone());
            let family = extract_family_name(&m.description);

            let cluster = family_map
                .entry(family.clone())
                .or_insert_with(|| FamilyCluster {
                    family_name: family.clone(),
                    rules_matched: Vec::new(),
                    total_hits: 0,
                    confidence: 0,
                    severity: "info".to_string(),
                });
            cluster.rules_matched.push(m.rule_name.clone());
            cluster.total_hits += m.matched_strings.len().max(1);
            cluster.confidence = u8::try_from((cluster.rules_matched.len() * 20).min(95)).unwrap_or(95);
            if severity_rank(&m.severity) > severity_rank(&cluster.severity) {
                cluster.severity.clone_from(&m.severity);
            }

            for (id, off) in &m.matched_strings {
                offsets.push(MatchOffset {
                    rule_name: m.rule_name.clone(),
                    string_id: id.clone(),
                    offset: *off,
                    length: 0,
                    preview_hex: String::new(),
                    preview_ascii: String::new(),
                });
                highlights.push(HighlightedRegion::new(
                    *off,
                    0,
                    &m.rule_name,
                    id,
                    &m.severity,
                ));
            }
        }

        matched_rules.sort_unstable();
        matched_rules.dedup();

        let mut family_clusters: Vec<FamilyCluster> = family_map.into_values().collect();
        family_clusters.sort_by(|a, b| b.total_hits.cmp(&a.total_hits));

        Self {
            file_hash: file_hash.into(),
            file_size,
            scan_time_ms: hits.scan_time_ms,
            verdict: verdict_str,
            threat_score,
            offsets,
            highlights,
            family_clusters,
            matched_rules,
            enhanced_matches: hits.enhanced_matches.clone(),
            triage_matches: hits.triage_matches.clone(),
            metadata: HashMap::new(),
        }
    }

    /// Add metadata key/value pair.
    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Export report to JSON string.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    #[must_use = "check or propagate the serialization result"]
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Export report to HTML string.
    #[must_use]
    pub fn to_html(&self) -> String {
        use std::fmt::Write as _;
        let mut html = String::new();
        html.push_str("<!DOCTYPE html><html><head><meta charset=\"utf-8\">");
        html.push_str("<title>YARA Match Report</title>");
        html.push_str(
            r"<style>
body { font-family: monospace; background: #1e1e1e; color: #d4d4d4; margin: 20px; }
h1 { color: #569cd6; }
h2 { color: #9cdcfe; border-bottom: 1px solid #333; }
.clean { color: #4ec9b0; }
.suspicious { color: #dcdcaa; }
.malicious { color: #f44747; }
.high { color: #ff6600; }
.medium { color: #ffaa00; }
.low { color: #ffff00; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #333; padding: 4px 8px; text-align: left; }
th { background: #252526; }
.hex { font-family: monospace; font-size: 12px; }
</style></head><body>",
        );

        html.push_str("<h1>YARA Match Report</h1>");
        let _ = write!(html, "<p><b>Hash:</b> {}</p>", self.file_hash);
        let _ = write!(html, "<p><b>Size:</b> {} bytes</p>", self.file_size);
        let _ = write!(html, "<p><b>Scan time:</b> {}ms</p>", self.scan_time_ms);
        let _ = write!(
            html,
            "<p><b>Verdict:</b> <span class=\"{}\">{}</span> (score {})</p>",
            self.verdict,
            self.verdict.to_uppercase(),
            self.threat_score
        );

        if !self.family_clusters.is_empty() {
            html.push_str("<h2>Family Attribution</h2><table>");
            html.push_str(
                "<tr><th>Family</th><th>Severity</th><th>Confidence</th><th>Hits</th></tr>",
            );
            for cluster in &self.family_clusters {
                let _ = write!(
                    html,
                    "<tr><td>{}</td><td class=\"{}\">{}</td><td>{}%</td><td>{}</td></tr>",
                    cluster.family_name,
                    cluster.severity,
                    cluster.severity,
                    cluster.confidence,
                    cluster.total_hits
                );
            }
            html.push_str("</table>");
        }

        if !self.matched_rules.is_empty() {
            html.push_str("<h2>Matched Rules</h2><ul>");
            for rule in &self.matched_rules {
                let _ = write!(html, "<li><code>{rule}</code></li>");
            }
            html.push_str("</ul>");
        }

        if !self.offsets.is_empty() {
            html.push_str("<h2>Match Offsets</h2><table>");
            html.push_str("<tr><th>Rule</th><th>String</th><th>Offset</th><th>Preview</th></tr>");
            for off in &self.offsets {
                let _ = write!(
                    html,
                    "<tr><td>{}</td><td>{}</td><td>0x{:x}</td><td class=\"hex\">{}</td></tr>",
                    off.rule_name, off.string_id, off.offset, off.preview_ascii
                );
            }
            html.push_str("</table>");
        }

        html.push_str("</body></html>");
        html
    }

    /// Export a condensed text summary.
    #[must_use]
    pub fn to_text(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        out.push_str("=== YARA Match Report ===\n");
        let _ = writeln!(out, "Hash:       {}", self.file_hash);
        let _ = writeln!(out, "Size:       {} bytes", self.file_size);
        let _ = writeln!(
            out,
            "Verdict:    {} (score {})",
            self.verdict.to_uppercase(),
            self.threat_score
        );
        let _ = writeln!(out, "Scan time:  {}ms", self.scan_time_ms);
        let _ = writeln!(out, "Matches:    {}", self.matched_rules.len());
        if !self.family_clusters.is_empty() {
            out.push_str("\n-- Families --\n");
            for c in &self.family_clusters {
                let _ = writeln!(
                    out,
                    "  {:30} sev={} conf={}%",
                    c.family_name, c.severity, c.confidence
                );
            }
        }
        if !self.matched_rules.is_empty() {
            out.push_str("\n-- Rules --\n");
            for r in &self.matched_rules {
                let _ = writeln!(out, "  {r}");
            }
        }
        if !self.offsets.is_empty() {
            out.push_str("\n-- Match Offsets --\n");
            for o in self.offsets.iter().take(20) {
                let _ = writeln!(
                    out,
                    "  [{:6}] {:20} {} = {:?}",
                    format!("0x{:04x}", o.offset),
                    o.rule_name,
                    o.string_id,
                    o.preview_ascii
                );
            }
            if self.offsets.len() > 20 {
                let _ = writeln!(out, "  ... and {} more", self.offsets.len() - 20);
            }
        }
        out
    }

    /// Number of total match offsets.
    #[must_use]
    pub const fn offset_count(&self) -> usize {
        self.offsets.len()
    }

    /// Whether the report has any matches.
    #[must_use]
    pub const fn has_matches(&self) -> bool {
        !self.matched_rules.is_empty()
    }
}

fn severity_rank(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

fn extract_family_name(desc: &str) -> String {
    desc.split_whitespace()
        .next()
        .unwrap_or("Unknown")
        .trim_end_matches(&[',', '.', ';', ':'][..])
        .to_string()
}

// ─── Report builder ───────────────────────────────────────────────────────────

/// Fluent builder for `YaraMatchReport`.
pub struct ReportBuilder {
    hits: ScanHits,
    hash: String,
    file_size: usize,
    metadata: HashMap<String, String>,
}

impl ReportBuilder {
    #[must_use]
    pub fn new(hits: ScanHits) -> Self {
        let file_size = hits.bytes_scanned;
        Self {
            hits,
            hash: String::new(),
            file_size,
            metadata: HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_hash(mut self, hash: impl Into<String>) -> Self {
        self.hash = hash.into();
        self
    }

    #[must_use]
    pub fn with_file_size(mut self, size: usize) -> Self {
        self.file_size = size;
        self
    }

    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), val.into());
        self
    }

    #[must_use]
    pub fn build(self) -> YaraMatchReport {
        let mut report = YaraMatchReport::from_hits(&self.hits, &self.hash, self.file_size);
        report.metadata.extend(self.metadata);
        report
    }
}

// ─── Report comparator ───────────────────────────────────────────────────────

/// Diff two reports, reporting newly-appeared or disappeared rule matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportDiff {
    pub new_rules: Vec<String>,
    pub removed_rules: Vec<String>,
    pub score_delta: i16,
    pub verdict_changed: bool,
}

impl ReportDiff {
    #[must_use]
    pub fn compare(before: &YaraMatchReport, after: &YaraMatchReport) -> Self {
        let before_set: std::collections::HashSet<&str> =
            before.matched_rules.iter().map(String::as_str).collect();
        let after_set: std::collections::HashSet<&str> =
            after.matched_rules.iter().map(String::as_str).collect();

        let new_rules = after_set
            .difference(&before_set)
            .map(ToString::to_string)
            .collect();
        let removed_rules = before_set
            .difference(&after_set)
            .map(ToString::to_string)
            .collect();

        Self {
            new_rules,
            removed_rules,
            score_delta: i16::from(after.threat_score) - i16::from(before.threat_score),
            verdict_changed: before.verdict != after.verdict,
        }
    }
}

// ─── Bulk report ──────────────────────────────────────────────────────────────

/// Aggregated stats from a set of reports (e.g. batch scan).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BulkReportStats {
    pub total_files: usize,
    pub malicious_count: usize,
    pub suspicious_count: usize,
    pub clean_count: usize,
    pub avg_score: f64,
    pub max_score: u8,
    pub top_families: Vec<(String, usize)>,
    pub top_rules: Vec<(String, usize)>,
}

impl BulkReportStats {
    #[must_use]
    pub fn from_reports(reports: &[YaraMatchReport]) -> Self {
        let mut stats = Self {
            total_files: reports.len(),
            ..Default::default()
        };
        let mut score_sum: u64 = 0;
        let mut family_counts: HashMap<String, usize> = HashMap::new();
        let mut rule_counts: HashMap<String, usize> = HashMap::new();

        for r in reports {
            match r.verdict.as_str() {
                "malicious" | "high" => stats.malicious_count += 1,
                "suspicious" | "low" | "informational" => stats.suspicious_count += 1,
                _ => stats.clean_count += 1,
            }
            score_sum += u64::from(r.threat_score);
            if r.threat_score > stats.max_score {
                stats.max_score = r.threat_score;
            }
            for c in &r.family_clusters {
                *family_counts.entry(c.family_name.clone()).or_insert(0) += 1;
            }
            for rule in &r.matched_rules {
                *rule_counts.entry(rule.clone()).or_insert(0) += 1;
            }
        }

        if stats.total_files > 0 {
            let avg = score_sum / u64::try_from(stats.total_files).unwrap_or(1);
            let rem = score_sum % u64::try_from(stats.total_files).unwrap_or(1);
            stats.avg_score = f64::from(u32::try_from(avg).unwrap_or(u32::MAX))
                + f64::from(u32::try_from(rem).unwrap_or(0))
                    / f64::from(u32::try_from(stats.total_files).unwrap_or(u32::MAX));
        }

        let mut families: Vec<(String, usize)> = family_counts.into_iter().collect();
        families.sort_by(|a, b| b.1.cmp(&a.1));
        families.truncate(10);
        stats.top_families = families;

        let mut rules: Vec<(String, usize)> = rule_counts.into_iter().collect();
        rules.sort_by(|a, b| b.1.cmp(&a.1));
        rules.truncate(10);
        stats.top_rules = rules;

        stats
    }

    #[must_use]
    pub fn malicious_rate(&self) -> f64 {
        if self.total_files == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.malicious_count).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.total_files).unwrap_or(u32::MAX))
    }
}

// ─── Report cache ─────────────────────────────────────────────────────────────

/// In-memory cache for match reports keyed by file hash.
pub struct ReportCache {
    cache: HashMap<String, YaraMatchReport>,
    max_entries: usize,
}

impl ReportCache {
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            cache: HashMap::new(),
            max_entries: max.max(1),
        }
    }

    pub fn insert(&mut self, hash: String, report: YaraMatchReport) {
        if self.cache.len() >= self.max_entries && let Some(key) = self.cache.keys().next().cloned() {
            // Remove the first entry (basic eviction)
            self.cache.remove(&key);
        }
        self.cache.insert(hash, report);
    }

    #[must_use]
    pub fn get(&self, hash: &str) -> Option<&YaraMatchReport> {
        self.cache.get(hash)
    }

    #[must_use]
    pub fn contains(&self, hash: &str) -> bool {
        self.cache.contains_key(hash)
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
    pub fn clear(&mut self) {
        self.cache.clear();
    }
}

// ─── Report filter ────────────────────────────────────────────────────────────

/// Filter criteria for report selection.
#[derive(Debug, Clone, Default)]
pub struct ReportFilter {
    pub min_score: Option<u8>,
    pub verdict: Option<String>,
    pub family: Option<String>,
    pub rule_name: Option<String>,
}

impl ReportFilter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn min_score(mut self, s: u8) -> Self {
        self.min_score = Some(s);
        self
    }
    #[must_use]
    pub fn verdict(mut self, v: impl Into<String>) -> Self {
        self.verdict = Some(v.into());
        self
    }
    #[must_use]
    pub fn family(mut self, f: impl Into<String>) -> Self {
        self.family = Some(f.into());
        self
    }
    #[must_use]
    pub fn rule(mut self, r: impl Into<String>) -> Self {
        self.rule_name = Some(r.into());
        self
    }

    /// Test whether a report passes this filter.
    #[must_use]
    pub fn matches(&self, r: &YaraMatchReport) -> bool {
        if let Some(min) = self.min_score && r.threat_score < min {
            return false;
        }
        if let Some(ref v) = self.verdict && r.verdict != *v {
            return false;
        }
        if let Some(ref f) = self.family {
            let lower = f.to_lowercase();
            if !r
                .family_clusters
                .iter()
                .any(|c| c.family_name.to_lowercase().contains(&lower))
            {
                return false;
            }
        }
        if let Some(ref rule) = self.rule_name && !r.matched_rules.iter().any(|n| n.contains(rule.as_str())) {
            return false;
        }
        true
    }

    /// Filter a slice of reports.
    #[must_use]
    pub fn apply<'a>(&self, reports: &'a [YaraMatchReport]) -> Vec<&'a YaraMatchReport> {
        reports.iter().filter(|r| self.matches(r)).collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::ScanHits;

    fn empty_hits() -> ScanHits {
        ScanHits {
            enhanced_matches: Vec::new(),
            triage_matches: Vec::new(),
            scan_time_ms: 5,
            bytes_scanned: 100,
        }
    }

    #[test]
    fn report_from_empty_hits() {
        let hits = empty_hits();
        let report = YaraMatchReport::from_hits(&hits, "deadbeef", 100);
        assert_eq!(report.verdict, "clean");
        assert_eq!(report.threat_score, 0);
        assert!(!report.has_matches());
    }

    #[test]
    fn report_with_triage_match() {
        let hits = ScanHits {
            enhanced_matches: Vec::new(),
            triage_matches: vec![YaraTriageMatch {
                rule_name: "Mimikatz".into(),
                matched_strings: vec![("s0".into(), 0x100)],
                description: "Mimikatz credential dump".into(),
                severity: "critical".into(),
            }],
            scan_time_ms: 10,
            bytes_scanned: 1024,
        };
        let report = YaraMatchReport::from_hits(&hits, "aabbccdd", 1024);
        assert!(report.has_matches());
        assert!(!report.family_clusters.is_empty());
        assert!(!report.offsets.is_empty());
    }

    #[test]
    fn report_to_json() {
        let hits = empty_hits();
        let report = YaraMatchReport::from_hits(&hits, "00000000", 0);
        let json = report.to_json().unwrap();
        assert!(json.contains("clean"));
        assert!(json.contains("00000000"));
    }

    #[test]
    fn report_to_html() {
        let hits = empty_hits();
        let report = YaraMatchReport::from_hits(&hits, "11111111", 100);
        let html = report.to_html();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("YARA Match Report"));
    }

    #[test]
    fn report_to_text() {
        let hits = empty_hits();
        let report = YaraMatchReport::from_hits(&hits, "22222222", 100);
        let text = report.to_text();
        assert!(text.contains("Verdict"));
        assert!(text.contains("22222222"));
    }

    #[test]
    fn report_builder() {
        let hits = empty_hits();
        let report = ReportBuilder::new(hits)
            .with_hash("cafebabe")
            .with_file_size(512)
            .with_meta("filename", "test.exe")
            .build();
        assert_eq!(report.file_hash, "cafebabe");
        assert_eq!(report.file_size, 512);
        assert_eq!(
            report.metadata.get("filename").map(|s| s.as_str()),
            Some("test.exe")
        );
    }

    #[test]
    fn match_offset_preview() {
        let off = MatchOffset::new("TestRule", "$s1", 0x1000, b"MZHello\x00");
        assert!(!off.preview_hex.is_empty());
        assert!(off.preview_ascii.contains("MZHello"));
    }

    #[test]
    fn highlighted_region_color_critical() {
        let r = HighlightedRegion::new(0, 4, "R", "$s", "critical");
        assert_eq!(r.color, "#ff0000");
    }

    #[test]
    fn family_cluster_severity_escalation() {
        let hits = ScanHits {
            enhanced_matches: Vec::new(),
            triage_matches: vec![
                YaraTriageMatch {
                    rule_name: "R1".into(),
                    matched_strings: Vec::new(),
                    description: "FamilyA malware".into(),
                    severity: "low".into(),
                },
                YaraTriageMatch {
                    rule_name: "R2".into(),
                    matched_strings: Vec::new(),
                    description: "FamilyA critical".into(),
                    severity: "critical".into(),
                },
            ],
            scan_time_ms: 1,
            bytes_scanned: 100,
        };
        let report = YaraMatchReport::from_hits(&hits, "hash", 100);
        // Both rules produce FamilyA and FamilyA clusters
        assert!(!report.family_clusters.is_empty());
    }
}
