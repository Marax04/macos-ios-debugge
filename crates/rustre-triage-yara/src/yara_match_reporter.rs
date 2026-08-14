//! YARA match reporter.
//!
//! [`YaraMatchReporter`] aggregates raw scan hits from the triage engine into
//! structured [`YaraMatchResult`] records and formats them for human and
//! machine consumption.  Each result carries per-pattern detail, enriched
//! severity labeling, and optional de-duplication.
//!
//! The reporter is intentionally decoupled from the scan engine so it can be
//! driven by any upstream scanner that produces byte-offset match data.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// MatchDetail
// ─────────────────────────────────────────────────────────────────────────────

/// Detail about a single pattern that fired inside a [`YaraMatchResult`].
#[derive(Debug, Clone)]
pub struct MatchDetail {
    /// Pattern identifier (e.g. `"$s0"`, `"$mz"`).
    pub pattern_id: String,
    /// File offsets at which the pattern matched.
    pub offsets: Vec<u64>,
    /// The first 16 bytes at the first match offset (for quick preview).
    pub preview_bytes: Vec<u8>,
    /// Length of the matched byte string.
    pub pattern_len: usize,
}

impl MatchDetail {
    /// Create a new `MatchDetail`.
    #[must_use]
    pub fn new(
        pattern_id: impl Into<String>,
        offsets: Vec<u64>,
        preview_bytes: Vec<u8>,
        pattern_len: usize,
    ) -> Self {
        Self {
            pattern_id: pattern_id.into(),
            offsets,
            preview_bytes,
            pattern_len,
        }
    }

    /// Total number of times the pattern matched.
    #[must_use]
    pub const fn match_count(&self) -> usize {
        self.offsets.len()
    }

    /// First offset, or `None` if there are no matches.
    #[must_use]
    pub fn first_offset(&self) -> Option<u64> {
        self.offsets.first().copied()
    }

    /// Return the preview bytes as a hex string (space-separated).
    #[must_use]
    pub fn preview_hex(&self) -> String {
        self.preview_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl fmt::Display for MatchDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({} hits, first @ {:#x})",
            self.pattern_id,
            self.offsets.len(),
            self.first_offset().unwrap_or(0)
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Severity
// ─────────────────────────────────────────────────────────────────────────────

/// Standardised severity level for a match result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl std::str::FromStr for Severity {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(s))
    }
}

impl Severity {
    /// Parse a severity string (case-insensitive).
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            _ => Self::Info,
        }
    }

    /// Canonical lower-case string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// YaraMatchResult
// ─────────────────────────────────────────────────────────────────────────────

/// A fully-enriched result for one rule that fired during a scan.
#[derive(Debug, Clone)]
pub struct YaraMatchResult {
    /// Name of the rule that fired.
    pub rule_name: String,
    /// Human-readable description.
    pub description: String,
    /// Parsed severity level.
    pub severity: Severity,
    /// Classification tags from the rule.
    pub tags: Vec<String>,
    /// Per-pattern match details.
    pub details: Vec<MatchDetail>,
    /// Arbitrary metadata from the rule.
    pub metadata: HashMap<String, String>,
    /// The file or data URI that was scanned.
    pub source_uri: String,
    /// Size of the scanned buffer in bytes.
    pub scanned_bytes: u64,
}

impl YaraMatchResult {
    /// Create a new result.
    #[must_use]
    pub fn new(
        rule_name: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
    ) -> Self {
        Self {
            rule_name: rule_name.into(),
            description: description.into(),
            severity,
            tags: Vec::new(),
            details: Vec::new(),
            metadata: HashMap::new(),
            source_uri: String::new(),
            scanned_bytes: 0,
        }
    }

    /// Total pattern hits across all details.
    #[must_use]
    pub fn total_hits(&self) -> usize {
        self.details.iter().map(MatchDetail::match_count).sum()
    }

    /// Return the first file offset at which any pattern matched.
    #[must_use]
    pub fn first_match_offset(&self) -> Option<u64> {
        self.details
            .iter()
            .flat_map(|d| d.offsets.iter().copied())
            .min()
    }

    /// Return `true` if any pattern matched at offset 0 (file-header match).
    #[must_use]
    pub fn matches_at_header(&self) -> bool {
        self.details
            .iter()
            .any(|d| d.offsets.contains(&0))
    }

    /// Number of distinct patterns that fired.
    #[must_use]
    pub const fn matched_pattern_count(&self) -> usize {
        self.details.len()
    }
}

impl fmt::Display for YaraMatchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} — {} ({} patterns, {} total hits)",
            self.severity.as_str().to_uppercase(),
            self.rule_name,
            self.description,
            self.matched_pattern_count(),
            self.total_hits()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScanReport
// ─────────────────────────────────────────────────────────────────────────────

/// A full scan report produced by [`YaraMatchReporter::generate_report`].
#[derive(Debug, Clone)]
pub struct ScanReport {
    /// URI or label for the scanned data.
    pub source_uri: String,
    /// Total bytes scanned.
    pub scanned_bytes: u64,
    /// Wall-clock time to scan.
    pub scan_duration: Duration,
    /// All match results in severity-descending order.
    pub results: Vec<YaraMatchResult>,
    /// Summary statistics.
    pub stats: ReportStats,
}

/// Per-severity match statistics.
#[derive(Debug, Clone, Default)]
pub struct ReportStats {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total_rules_matched: usize,
    pub total_pattern_hits: usize,
}

impl ReportStats {
    fn from_results(results: &[YaraMatchResult]) -> Self {
        let mut s = Self {
            total_rules_matched: results.len(),
            ..Default::default()
        };
        for r in results {
            s.total_pattern_hits += r.total_hits();
            match r.severity {
                Severity::Critical => s.critical += 1,
                Severity::High => s.high += 1,
                Severity::Medium => s.medium += 1,
                Severity::Low => s.low += 1,
                Severity::Info => s.info += 1,
            }
        }
        s
    }
}

impl ScanReport {
    /// Return `true` if any critical-severity rule fired.
    #[must_use]
    pub const fn has_critical(&self) -> bool {
        self.stats.critical > 0
    }

    /// Return `true` if any rule at or above `min_severity` fired.
    #[must_use]
    pub fn has_severity_gte(&self, min_severity: Severity) -> bool {
        self.results.iter().any(|r| r.severity >= min_severity)
    }

    /// Return all results at exactly `severity`.
    #[must_use]
    pub fn by_severity(&self, severity: Severity) -> Vec<&YaraMatchResult> {
        self.results.iter().filter(|r| r.severity == severity).collect()
    }

    /// Return all results carrying `tag`.
    #[must_use]
    pub fn by_tag(&self, tag: &str) -> Vec<&YaraMatchResult> {
        self.results
            .iter()
            .filter(|r| r.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// One-line human-readable verdict.
    #[must_use]
    pub const fn verdict(&self) -> &'static str {
        if self.stats.critical > 0 {
            "MALICIOUS"
        } else if self.stats.high > 0 {
            "SUSPICIOUS"
        } else if self.stats.medium > 0 {
            "POTENTIALLY_UNWANTED"
        } else if self.stats.total_rules_matched > 0 {
            "NOTEWORTHY"
        } else {
            "CLEAN"
        }
    }

    /// Format the report as a plain-text summary.
    #[must_use]
    pub fn to_text(&self) -> String {
        use std::fmt::Write as _;
        let mut out = "=== YARA Scan Report ===\n".to_string();
        let _ = writeln!(out, "Source  : {}", self.source_uri);
        let _ = writeln!(out, "Bytes   : {}", self.scanned_bytes);
        let _ = writeln!(out, "Duration: {:.2?}", self.scan_duration);
        let _ = writeln!(out, "Verdict : {}", self.verdict());
        let _ = writeln!(
            out,
            "Matches : {} rules ({} critical, {} high, {} medium, {} low, {} info)",
            self.stats.total_rules_matched,
            self.stats.critical,
            self.stats.high,
            self.stats.medium,
            self.stats.low,
            self.stats.info
        );
        if self.results.is_empty() {
            out.push_str("(no matches)\n");
        } else {
            out.push_str("\nDetailed Matches:\n");
            for r in &self.results {
                let _ = writeln!(out, "  {r}");
                for d in &r.details {
                    let _ = writeln!(
                        out,
                        "    {} hits @ {:?}",
                        d.pattern_id,
                        &d.offsets[..d.offsets.len().min(5)]
                    );
                }
            }
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RawHit — input from upstream scanner
// ─────────────────────────────────────────────────────────────────────────────

/// A single pattern match produced by an upstream scanner.
#[derive(Debug, Clone)]
pub struct RawHit {
    /// Rule name.
    pub rule_name: String,
    /// Rule description.
    pub description: String,
    /// Severity string from the rule's metadata.
    pub severity_str: String,
    /// Rule classification tags.
    pub tags: Vec<String>,
    /// Pattern identifier.
    pub pattern_id: String,
    /// File offset of the match.
    pub offset: u64,
    /// Matched bytes (up to 16 bytes for the preview).
    pub matched_bytes: Vec<u8>,
    /// Length of the original pattern.
    pub pattern_len: usize,
    /// Arbitrary rule metadata.
    pub metadata: HashMap<String, String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// ReporterConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for [`YaraMatchReporter`].
#[derive(Debug, Clone)]
pub struct ReporterConfig {
    /// If `true`, collapse multiple hits of the same rule into one result entry.
    pub deduplicate: bool,
    /// Minimum severity to include in the report.
    pub min_severity: Severity,
    /// Maximum preview bytes stored per match detail.
    pub max_preview_bytes: usize,
    /// Sort results by severity descending.
    pub sort_by_severity: bool,
}

impl Default for ReporterConfig {
    fn default() -> Self {
        Self {
            deduplicate: true,
            min_severity: Severity::Info,
            max_preview_bytes: 16,
            sort_by_severity: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// YaraMatchReporter
// ─────────────────────────────────────────────────────────────────────────────

/// Tuple type for a scan pattern: `(rule_name, description, severity_str, tags, pattern_bytes)`.
pub type ScanPattern<'a> = (&'a str, &'a str, &'a str, Vec<&'a str>, &'a [u8]);

/// Aggregates raw scan hits and produces structured [`YaraMatchResult`]s.
#[derive(Debug)]
pub struct YaraMatchReporter {
    config: ReporterConfig,
}

impl YaraMatchReporter {
    /// Create a reporter with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: ReporterConfig::default(),
        }
    }

    /// Create a reporter with a custom configuration.
    #[must_use]
    pub const fn with_config(config: ReporterConfig) -> Self {
        Self { config }
    }

    /// Process a slice of [`RawHit`]s and produce [`YaraMatchResult`]s.
    ///
    /// Hits are grouped by rule name.  Each group becomes one
    /// [`YaraMatchResult`] containing per-pattern [`MatchDetail`]s.
    #[must_use]
    pub fn process_hits(
        &self,
        hits: &[RawHit],
        source_uri: &str,
        scanned_bytes: u64,
    ) -> Vec<YaraMatchResult> {
        // Group hits by rule name
        let mut groups: HashMap<String, Vec<&RawHit>> = HashMap::new();
        for hit in hits {
            groups.entry(hit.rule_name.clone()).or_default().push(hit);
        }

        let mut results: Vec<YaraMatchResult> = groups
            .into_values()
            .filter_map(|rule_hits| {
                let first = rule_hits[0];
                let severity = Severity::parse(&first.severity_str);
                if severity < self.config.min_severity {
                    return None;
                }

                let mut result = YaraMatchResult::new(
                    &first.rule_name,
                    &first.description,
                    severity,
                );
                result.tags.clone_from(&first.tags);
                result.metadata.clone_from(&first.metadata);
                result.source_uri = source_uri.to_string();
                result.scanned_bytes = scanned_bytes;

                // Group by pattern_id within this rule
                let mut pat_groups: HashMap<String, Vec<&RawHit>> = HashMap::new();
                for hit in &rule_hits {
                    pat_groups
                        .entry(hit.pattern_id.clone())
                        .or_default()
                        .push(hit);
                }

                for (pat_id, pat_hits) in pat_groups {
                    let mut offsets: Vec<u64> = pat_hits.iter().map(|h| h.offset).collect();
                    offsets.sort_unstable();
                    if self.config.deduplicate {
                        offsets.dedup();
                    }
                    let preview = pat_hits[0]
                        .matched_bytes
                        .iter()
                        .take(self.config.max_preview_bytes)
                        .copied()
                        .collect();
                    let pattern_len = pat_hits[0].pattern_len;
                    result
                        .details
                        .push(MatchDetail::new(pat_id, offsets, preview, pattern_len));
                }

                // Sort details by pattern_id for determinism
                result.details.sort_unstable_by(|a, b| a.pattern_id.cmp(&b.pattern_id));

                Some(result)
            })
            .collect();

        if self.config.sort_by_severity {
            results.sort_unstable_by(|a, b| b.severity.cmp(&a.severity));
        }

        results
    }

    /// Build a full [`ScanReport`] from raw hits, measuring elapsed time.
    #[must_use]
    pub fn generate_report(
        &self,
        hits: &[RawHit],
        source_uri: &str,
        scanned_bytes: u64,
        scan_duration: Duration,
    ) -> ScanReport {
        let results = self.process_hits(hits, source_uri, scanned_bytes);
        let stats = ReportStats::from_results(&results);
        ScanReport {
            source_uri: source_uri.to_string(),
            scanned_bytes,
            scan_duration,
            results,
            stats,
        }
    }

    /// Convenience: scan `data` against `patterns` and generate a report.
    ///
    /// `patterns` is a slice of `(rule_name, description, severity_str, tags, pattern_bytes)`.
    #[must_use]
    pub fn scan_and_report(
        &self,
        data: &[u8],
        patterns: &[ScanPattern<'_>],
        source_uri: &str,
    ) -> ScanReport {
        let start = Instant::now();
        let mut hits: Vec<RawHit> = Vec::new();

        for (rule_name, description, severity_str, tags, needle) in patterns {
            if needle.is_empty() {
                continue;
            }
            let limit = data.len().saturating_sub(needle.len()) + 1;
            for i in 0..limit {
                if &data[i..i + needle.len()] == *needle {
                    let preview: Vec<u8> = data[i..]
                        .iter()
                        .take(self.config.max_preview_bytes)
                        .copied()
                        .collect();
                    hits.push(RawHit {
                        rule_name: rule_name.to_string(),
                        description: description.to_string(),
                        severity_str: severity_str.to_string(),
                        tags: tags.iter().map(ToString::to_string).collect(),
                        pattern_id: "$p".to_string(),
                        offset: u64::try_from(i).unwrap_or(u64::MAX),
                        matched_bytes: preview,
                        pattern_len: needle.len(),
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        self.generate_report(&hits, source_uri, u64::try_from(data.len()).unwrap_or(u64::MAX), start.elapsed())
    }
}

impl Default for YaraMatchReporter {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MatchSummaryLine
// ─────────────────────────────────────────────────────────────────────────────

/// A condensed single-line summary of a match result, suitable for log output.
#[derive(Debug, Clone)]
pub struct MatchSummaryLine {
    pub rule_name: String,
    pub severity: Severity,
    pub first_offset: u64,
    pub tag_summary: String,
}

impl MatchSummaryLine {
    /// Build from a [`YaraMatchResult`].
    #[must_use]
    pub fn from_result(r: &YaraMatchResult) -> Self {
        Self {
            rule_name: r.rule_name.clone(),
            severity: r.severity,
            first_offset: r.first_match_offset().unwrap_or(0),
            tag_summary: r.tags.join(", "),
        }
    }
}

impl fmt::Display for MatchSummaryLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} @ 0x{:x} ({})",
            self.severity.as_str().to_uppercase(),
            self.rule_name,
            self.first_offset,
            self.tag_summary
        )
    }
}

/// Produce a sorted summary-line list from a scan report.
#[must_use]
pub fn summarise_report(report: &ScanReport) -> Vec<MatchSummaryLine> {
    let mut lines: Vec<MatchSummaryLine> = report
        .results
        .iter()
        .map(MatchSummaryLine::from_result)
        .collect();
    lines.sort_unstable_by(|a, b| b.severity.cmp(&a.severity));
    lines
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hit(rule: &str, pat: &str, sev: &str, offset: u64, tags: &[&str]) -> RawHit {
        RawHit {
            rule_name: rule.to_string(),
            description: "desc".to_string(),
            severity_str: sev.to_string(),
            tags: tags.iter().map(|t| t.to_string()).collect(),
            pattern_id: pat.to_string(),
            offset,
            matched_bytes: vec![0x4d, 0x5a],
            pattern_len: 2,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_process_hits_groups_by_rule() {
        let reporter = YaraMatchReporter::new();
        let hits = vec![
            make_hit("RuleA", "$s0", "high", 0, &["malware"]),
            make_hit("RuleA", "$s0", "high", 100, &["malware"]),
            make_hit("RuleB", "$s1", "medium", 50, &[]),
        ];
        let results = reporter.process_hits(&hits, "test.bin", 200);
        assert_eq!(results.len(), 2);
        let rule_a = results.iter().find(|r| r.rule_name == "RuleA").unwrap();
        // With dedup, two same-offset-different hits → both offsets kept (0 and 100)
        assert_eq!(rule_a.details[0].offsets.len(), 2);
    }

    #[test]
    fn test_severity_ordering() {
        let reporter = YaraMatchReporter::new();
        let hits = vec![
            make_hit("Low", "$s0", "low", 0, &[]),
            make_hit("Critical", "$s0", "critical", 0, &[]),
            make_hit("Medium", "$s0", "medium", 0, &[]),
        ];
        let results = reporter.process_hits(&hits, "file", 100);
        assert_eq!(results[0].severity, Severity::Critical);
        assert_eq!(results[1].severity, Severity::Medium);
        assert_eq!(results[2].severity, Severity::Low);
    }

    #[test]
    fn test_min_severity_filter() {
        let config = ReporterConfig {
            min_severity: Severity::High,
            ..Default::default()
        };
        let reporter = YaraMatchReporter::with_config(config);
        let hits = vec![
            make_hit("Low", "$s0", "low", 0, &[]),
            make_hit("High", "$s0", "high", 0, &[]),
        ];
        let results = reporter.process_hits(&hits, "file", 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::High);
    }

    #[test]
    fn test_generate_report_verdict_clean() {
        let reporter = YaraMatchReporter::new();
        let report = reporter.generate_report(&[], "empty.bin", 0, Duration::ZERO);
        assert_eq!(report.verdict(), "CLEAN");
        assert!(!report.has_critical());
    }

    #[test]
    fn test_generate_report_verdict_malicious() {
        let reporter = YaraMatchReporter::new();
        let hits = vec![make_hit("Malware", "$s0", "critical", 0, &[])];
        let report = reporter.generate_report(&hits, "mal.bin", 100, Duration::ZERO);
        assert_eq!(report.verdict(), "MALICIOUS");
        assert!(report.has_critical());
    }

    #[test]
    fn test_scan_and_report() {
        let reporter = YaraMatchReporter::new();
        let data = b"MZheader...rest of pe file";
        let patterns = vec![("PE_Magic", "PE magic", "info", vec!["format"], b"MZ".as_ref())];
        let report = reporter.scan_and_report(data, &patterns, "test.exe");
        assert_eq!(report.stats.total_rules_matched, 1);
        assert_eq!(report.verdict(), "NOTEWORTHY");
    }

    #[test]
    fn test_report_by_tag() {
        let reporter = YaraMatchReporter::new();
        let hits = vec![
            make_hit("R1", "$s0", "high", 0, &["malware"]),
            make_hit("R2", "$s0", "medium", 0, &["packer"]),
        ];
        let report = reporter.generate_report(&hits, "f", 100, Duration::ZERO);
        let malware = report.by_tag("malware");
        assert_eq!(malware.len(), 1);
        assert_eq!(malware[0].rule_name, "R1");
    }

    #[test]
    fn test_match_detail_preview_hex() {
        let detail = MatchDetail::new("$s0", vec![0], vec![0x4d, 0x5a], 2);
        assert_eq!(detail.preview_hex(), "4d 5a");
    }

    #[test]
    fn test_severity_ordering_enum() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_severity_from_str() {
        assert_eq!(Severity::parse("critical"), Severity::Critical);
        assert_eq!(Severity::parse("CRITICAL"), Severity::Critical);
        assert_eq!(Severity::parse("unknown"), Severity::Info);
    }

    #[test]
    fn test_match_summary_line_display() {
        let hit = make_hit("TestRule", "$s0", "high", 0x100, &["malware"]);
        let reporter = YaraMatchReporter::new();
        let results = reporter.process_hits(&[hit], "test.bin", 200);
        let lines = summarise_report(&reporter.generate_report(
            &[make_hit("TestRule", "$s0", "high", 0x100, &["malware"])],
            "test.bin",
            200,
            Duration::ZERO,
        ));
        assert!(!lines.is_empty());
        let s = lines[0].to_string();
        assert!(s.contains("TestRule"));
        assert!(s.contains("HIGH") || s.contains("high"));
        let _ = results;
    }

    #[test]
    fn test_report_text_output() {
        let reporter = YaraMatchReporter::new();
        let hits = vec![make_hit("UPX", "$s0", "medium", 0, &["packer"])];
        let report = reporter.generate_report(&hits, "packed.exe", 1024, Duration::from_millis(5));
        let text = report.to_text();
        assert!(text.contains("packed.exe"));
        assert!(text.contains("UPX"));
    }
}
