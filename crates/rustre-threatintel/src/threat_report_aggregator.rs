//! `threat_report_aggregator` — Aggregate threat reports and extract `IoCs`.
//!
//! Provides [`ThreatReportAggregator`] which collects [`ThreatReport`] objects
//! from multiple sources, deduplicates `IoCs` across reports, computes coverage
//! statistics, and exposes a unified enriched view of all indicators.

use std::collections::{HashMap, HashSet};

use crate::ioc::{IoC, IoCType, Severity};
use crate::report::{ThreatReport, TlpLevel};

// ─────────────────────────────────────────────────────────────────────────────
// ReportSource
// ─────────────────────────────────────────────────────────────────────────────

/// Origin of an ingested threat report.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReportSource {
    /// Internal analyst report.
    Internal,
    /// MISP sharing community.
    Misp(String),
    /// `VirusTotal` feed.
    VirusTotal,
    /// `MalwareBazaar` feed.
    MalwareBazaar,
    /// Open-source intelligence (OSINT).
    Osint(String),
    /// Information Sharing and Analysis Center (ISAC).
    Isac(String),
    /// Vendor threat intelligence feed.
    Vendor(String),
    /// Custom / unknown source.
    Other(String),
}

impl std::fmt::Display for ReportSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal => write!(f, "Internal"),
            Self::Misp(s) => write!(f, "MISP({s})"),
            Self::VirusTotal => write!(f, "VirusTotal"),
            Self::MalwareBazaar => write!(f, "MalwareBazaar"),
            Self::Osint(s) => write!(f, "OSINT({s})"),
            Self::Isac(s) => write!(f, "ISAC({s})"),
            Self::Vendor(s) => write!(f, "Vendor({s})"),
            Self::Other(s) => write!(f, "Other({s})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AggregatedIoC
// ─────────────────────────────────────────────────────────────────────────────

/// An `IoC` that has been seen in one or more ingested reports.
#[derive(Debug, Clone)]
pub struct AggregatedIoC {
    /// The underlying indicator.
    pub ioc: IoC,
    /// Number of distinct reports that reference this `IoC`.
    pub report_count: usize,
    /// Sources that have contributed this `IoC`.
    pub sources: Vec<String>,
    /// Highest severity observed across all contributing reports.
    pub max_severity: Option<Severity>,
    /// Whether any contributing report was TLP:RED or TLP:AMBER.
    pub sensitive: bool,
}

impl AggregatedIoC {
    #[must_use]
    pub const fn new(ioc: IoC) -> Self {
        Self {
            ioc,
            report_count: 0,
            sources: Vec::new(),
            max_severity: None,
            sensitive: false,
        }
    }

    /// Add evidence from a report.
    fn absorb(&mut self, source: &str, severity: Option<Severity>, tlp: TlpLevel) {
        self.report_count += 1;
        if !self.sources.contains(&source.to_string()) {
            self.sources.push(source.to_string());
        }
        if let Some(sev) = severity {
            self.max_severity = Some(self.max_severity.map_or(sev, |existing| {
                if sev > existing { sev } else { existing }
            }));
        }
        if matches!(tlp, TlpLevel::Red | TlpLevel::Amber) {
            self.sensitive = true;
        }
    }

    /// Confidence score: 0.0–1.0, based on how many sources corroborate.
    #[must_use]
    pub fn corroboration_score(&self) -> f64 {
        let s = crate::casts::usize_to_f64(self.report_count);
        1.0 - (-s * 0.3).exp()
    }
}

impl std::fmt::Display for AggregatedIoC {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} (reports={}, sources={})",
            self.ioc.ioc_type,
            self.ioc.value,
            self.report_count,
            self.sources.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AggregationStats
// ─────────────────────────────────────────────────────────────────────────────

/// Summary statistics produced by the aggregator.
#[derive(Debug, Clone)]
pub struct AggregationStats {
    /// Total reports ingested.
    pub total_reports: usize,
    /// Total raw `IoCs` (before dedup).
    pub total_raw_iocs: usize,
    /// Unique `IoC` values after deduplication.
    pub unique_iocs: usize,
    /// `IoCs` seen in more than one report (corroborated).
    pub corroborated_iocs: usize,
    /// Sensitive `IoCs` (from TLP:RED or TLP:AMBER sources).
    pub sensitive_iocs: usize,
    /// Breakdown by `IoC` type.
    pub by_type: HashMap<String, usize>,
    /// Reports per source.
    pub by_source: HashMap<String, usize>,
}

impl std::fmt::Display for AggregationStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Aggregation Statistics ===")?;
        writeln!(f, "Reports:         {}", self.total_reports)?;
        writeln!(f, "Raw IoCs:        {}", self.total_raw_iocs)?;
        writeln!(f, "Unique IoCs:     {}", self.unique_iocs)?;
        writeln!(f, "Corroborated:    {}", self.corroborated_iocs)?;
        writeln!(f, "Sensitive:       {}", self.sensitive_iocs)?;
        writeln!(f, "By type:")?;
        let mut type_entries: Vec<(&String, &usize)> = self.by_type.iter().collect();
        type_entries.sort_by_key(|(k, _)| k.as_str());
        for (t, c) in type_entries {
            writeln!(f, "  {t}: {c}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ThreatReportAggregator
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregates threat reports from multiple sources and deduplicates their `IoCs`.
pub struct ThreatReportAggregator {
    /// All ingested reports.
    reports: Vec<(ThreatReport, ReportSource)>,
    /// Deduplicated `IoC` map: value → `AggregatedIoC`.
    ioc_map: HashMap<String, AggregatedIoC>,
    /// Total raw `IoC` count (before dedup).
    total_raw: usize,
    /// Names of all ingested reports, for quick lookup.
    report_titles: HashSet<String>,
}

impl ThreatReportAggregator {
    /// Create an empty aggregator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            reports: Vec::new(),
            ioc_map: HashMap::new(),
            total_raw: 0,
            report_titles: HashSet::new(),
        }
    }

    /// Ingest a threat report and index all of its `IoCs`.
    pub fn ingest(&mut self, report: ThreatReport, source: ReportSource) {
        let source_name = source.to_string();
        let tlp = report.tlp;
        // ThreatReport has no severity field; derive the maximum from its IoCs.
        let severity: Option<Severity> = report.iocs.iter().map(|ioc| ioc.severity).max();
        for ioc in &report.iocs {
            self.total_raw += 1;
            let key = ioc_key(ioc);
            let entry = self.ioc_map.entry(key).or_insert_with(|| AggregatedIoC::new(ioc.clone()));
            entry.absorb(&source_name, severity, tlp);
        }
        self.report_titles.insert(report.title.clone());
        self.reports.push((report, source));
    }

    /// Ingest multiple reports from the same source.
    pub fn ingest_all(&mut self, reports: Vec<ThreatReport>, source: &ReportSource) {
        for r in reports {
            self.ingest(r, source.clone());
        }
    }

    /// Return all aggregated `IoCs`.
    #[must_use]
    pub fn all_iocs(&self) -> Vec<&AggregatedIoC> {
        self.ioc_map.values().collect()
    }

    /// Return the unified `IoC` list, extracted from all ingested reports.
    ///
    /// Deduplicates by `IoC` value; only the first-seen instance is returned.
    #[must_use]
    pub fn aggregate_iocs(&self) -> Vec<&AggregatedIoC> {
        let mut v: Vec<&AggregatedIoC> = self.ioc_map.values().collect();
        v.sort_by(|a, b| {
            b.report_count
                .cmp(&a.report_count)
                .then(a.ioc.value.cmp(&b.ioc.value))
        });
        v
    }

    /// Return `IoCs` corroborated by at least `min_reports` distinct reports.
    #[must_use]
    pub fn corroborated_iocs(&self, min_reports: usize) -> Vec<&AggregatedIoC> {
        self.ioc_map
            .values()
            .filter(|a| a.report_count >= min_reports)
            .collect()
    }

    /// Return `IoCs` of a specific type.
    #[must_use]
    pub fn iocs_of_type(&self, ioc_type: &IoCType) -> Vec<&AggregatedIoC> {
        self.ioc_map
            .values()
            .filter(|a| &a.ioc.ioc_type == ioc_type)
            .collect()
    }

    /// Look up an `IoC` by its value.
    #[must_use]
    pub fn find_ioc(&self, value: &str) -> Option<&AggregatedIoC> {
        self.ioc_map.values().find(|a| a.ioc.value == value)
    }

    /// Return all sensitive `IoCs` (from TLP:RED or TLP:AMBER reports).
    #[must_use]
    pub fn sensitive_iocs(&self) -> Vec<&AggregatedIoC> {
        self.ioc_map.values().filter(|a| a.sensitive).collect()
    }

    /// Number of reports ingested.
    #[must_use]
    pub const fn report_count(&self) -> usize {
        self.reports.len()
    }

    /// Number of unique `IoC` values.
    #[must_use]
    pub fn unique_ioc_count(&self) -> usize {
        self.ioc_map.len()
    }

    /// Compute aggregation statistics.
    #[must_use]
    pub fn statistics(&self) -> AggregationStats {
        let mut by_type: HashMap<String, usize> = HashMap::new();
        let mut by_source: HashMap<String, usize> = HashMap::new();
        let mut corroborated = 0usize;
        let mut sensitive = 0usize;

        for (report, source) in &self.reports {
            *by_source.entry(source.to_string()).or_insert(0) += 1;
            for ioc in &report.iocs {
                *by_source.entry(source.to_string()).or_insert(0) += 1;
                *by_type.entry(ioc.ioc_type.to_string()).or_insert(0) += 1;
            }
        }

        for a in self.ioc_map.values() {
            if a.report_count > 1 { corroborated += 1; }
            if a.sensitive { sensitive += 1; }
        }

        AggregationStats {
            total_reports: self.reports.len(),
            total_raw_iocs: self.total_raw,
            unique_iocs: self.ioc_map.len(),
            corroborated_iocs: corroborated,
            sensitive_iocs: sensitive,
            by_type,
            by_source,
        }
    }

    /// Return all ingested reports, without source metadata.
    #[must_use]
    pub fn reports(&self) -> Vec<&ThreatReport> {
        self.reports.iter().map(|(r, _)| r).collect()
    }
}

impl Default for ThreatReportAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ThreatReportAggregator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreatReportAggregator")
            .field("reports", &self.reports.len())
            .field("unique_iocs", &self.ioc_map.len())
            .finish_non_exhaustive()
    }
}

fn ioc_key(ioc: &IoC) -> String {
    format!("{}:{}", ioc.ioc_type, ioc.value)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::TlpLevel;

    fn make_report(title: &str, ioc_values: &[(&str, IoCType)]) -> ThreatReport {
        let mut r = ThreatReport::new(title.to_string(), "tester".to_string());
        for (val, ty) in ioc_values {
            r.add_ioc(IoC::new(ty.clone(), val.to_string(), "test".to_string()));
        }
        r
    }

    #[test]
    fn test_ingest_single_report() {
        let mut agg = ThreatReportAggregator::new();
        let r = make_report("R1", &[("1.2.3.4", IoCType::Ip), ("evil.com", IoCType::Domain)]);
        agg.ingest(r, ReportSource::Internal);
        assert_eq!(agg.report_count(), 1);
        assert_eq!(agg.unique_ioc_count(), 2);
    }

    #[test]
    fn test_deduplication_across_reports() {
        let mut agg = ThreatReportAggregator::new();
        let r1 = make_report("R1", &[("1.2.3.4", IoCType::Ip)]);
        let r2 = make_report("R2", &[("1.2.3.4", IoCType::Ip), ("bad.io", IoCType::Domain)]);
        agg.ingest(r1, ReportSource::Internal);
        agg.ingest(r2, ReportSource::MalwareBazaar);
        assert_eq!(agg.unique_ioc_count(), 2);
        let ip = agg.find_ioc("1.2.3.4").unwrap();
        assert_eq!(ip.report_count, 2);
    }

    #[test]
    fn test_corroborated_iocs() {
        let mut agg = ThreatReportAggregator::new();
        agg.ingest(
            make_report("R1", &[("hash1", IoCType::Sha256), ("domain1", IoCType::Domain)]),
            ReportSource::Internal,
        );
        agg.ingest(
            make_report("R2", &[("hash1", IoCType::Sha256)]),
            ReportSource::VirusTotal,
        );
        let corr = agg.corroborated_iocs(2);
        assert_eq!(corr.len(), 1);
        assert_eq!(corr[0].ioc.value, "hash1");
    }

    #[test]
    fn test_iocs_of_type() {
        let mut agg = ThreatReportAggregator::new();
        agg.ingest(
            make_report("R1", &[("1.2.3.4", IoCType::Ip), ("bad.com", IoCType::Domain)]),
            ReportSource::Internal,
        );
        let ips = agg.iocs_of_type(&IoCType::Ip);
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn test_sensitive_iocs() {
        let mut agg = ThreatReportAggregator::new();
        let mut r = make_report("R1", &[("evil.com", IoCType::Domain)]);
        r.tlp = TlpLevel::Red;
        agg.ingest(r, ReportSource::Internal);
        assert_eq!(agg.sensitive_iocs().len(), 1);
    }

    #[test]
    fn test_aggregate_iocs_sorted_by_report_count() {
        let mut agg = ThreatReportAggregator::new();
        agg.ingest(make_report("R1", &[("a.com", IoCType::Domain), ("b.com", IoCType::Domain)]),
                   ReportSource::Internal);
        agg.ingest(make_report("R2", &[("a.com", IoCType::Domain)]),
                   ReportSource::VirusTotal);
        let v = agg.aggregate_iocs();
        assert_eq!(v[0].ioc.value, "a.com");
    }

    #[test]
    fn test_statistics() {
        let mut agg = ThreatReportAggregator::new();
        agg.ingest(
            make_report("R1", &[("1.1.1.1", IoCType::Ip)]),
            ReportSource::Internal,
        );
        agg.ingest(
            make_report("R2", &[("2.2.2.2", IoCType::Ip), ("1.1.1.1", IoCType::Ip)]),
            ReportSource::MalwareBazaar,
        );
        let stats = agg.statistics();
        assert_eq!(stats.total_reports, 2);
        assert_eq!(stats.unique_iocs, 2);
        assert_eq!(stats.corroborated_iocs, 1);
    }

    #[test]
    fn test_statistics_display() {
        let mut agg = ThreatReportAggregator::new();
        agg.ingest(make_report("R1", &[("x.com", IoCType::Domain)]), ReportSource::Internal);
        let s = agg.statistics().to_string();
        assert!(s.contains("Aggregation Statistics"));
    }

    #[test]
    fn test_report_source_display() {
        assert_eq!(ReportSource::Internal.to_string(), "Internal");
        assert_eq!(ReportSource::VirusTotal.to_string(), "VirusTotal");
        assert_eq!(ReportSource::Vendor("FooIntel".into()).to_string(), "Vendor(FooIntel)");
    }

    #[test]
    fn test_aggregated_ioc_display() {
        let ioc = IoC::new(IoCType::Ip, "1.2.3.4".to_string(), "test".to_string());
        let mut a = AggregatedIoC::new(ioc);
        a.report_count = 2;
        let s = a.to_string();
        assert!(s.contains("1.2.3.4"));
        assert!(s.contains("reports=2"));
    }

    #[test]
    fn test_corroboration_score() {
        let ioc = IoC::new(IoCType::Domain, "evil.io".into(), "test".into());
        let mut a = AggregatedIoC::new(ioc);
        a.report_count = 0;
        let s0 = a.corroboration_score();
        a.report_count = 5;
        let s5 = a.corroboration_score();
        assert!(s5 > s0);
        assert!(s5 <= 1.0);
    }

    #[test]
    fn test_ingest_all() {
        let mut agg = ThreatReportAggregator::new();
        let reports = vec![
            make_report("A", &[("h1", IoCType::Sha256)]),
            make_report("B", &[("h2", IoCType::Sha256)]),
        ];
        agg.ingest_all(reports, &ReportSource::Internal);
        assert_eq!(agg.report_count(), 2);
        assert_eq!(agg.unique_ioc_count(), 2);
    }

    #[test]
    fn test_find_ioc_not_found() {
        let agg = ThreatReportAggregator::new();
        assert!(agg.find_ioc("nothere").is_none());
    }

    #[test]
    fn test_reports_accessor() {
        let mut agg = ThreatReportAggregator::new();
        agg.ingest(make_report("R1", &[]), ReportSource::Internal);
        assert_eq!(agg.reports().len(), 1);
    }

    #[test]
    fn test_debug_format() {
        let agg = ThreatReportAggregator::new();
        let s = format!("{agg:?}");
        assert!(s.contains("ThreatReportAggregator"));
    }
}
