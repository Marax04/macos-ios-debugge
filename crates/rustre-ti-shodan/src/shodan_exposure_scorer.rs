//! Exposure scorer — combines a [`HostBannerAnalysis`] with the host's
//! port list and high-risk service categories to produce an exposure
//! score in `0..=100`.

use serde::{Deserialize, Serialize};

use crate::PortCategory;
use crate::shodan_banner_analyzer::HostBannerAnalysis;
use crate::shodan_host_enricher::ShodanHost;

/// Exposure score and its breakdown.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExposureScore {
    /// Final score `0..=100`.
    pub score: u32,
    /// Contribution per port category.
    pub by_category: Vec<(PortCategory, u32)>,
    /// Number of known CVEs found.
    pub cve_count: usize,
    /// Severity rating derived from `score`.
    pub severity: ExposureSeverity,
}

/// Coarse severity bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ExposureSeverity {
    #[default]
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl ExposureSeverity {
    /// Bucket a numeric score.
    #[must_use]
    pub const fn from_score(score: u32) -> Self {
        match score {
            0 => Self::None,
            1..=24 => Self::Low,
            25..=49 => Self::Medium,
            50..=74 => Self::High,
            _ => Self::Critical,
        }
    }
}

/// Exposure scorer.
pub struct ExposureScorer;

impl ExposureScorer {
    /// Score a host given its banner analysis.
    #[must_use]
    pub fn score(host: &ShodanHost, analysis: &HostBannerAnalysis) -> ExposureScore {
        let mut by_cat: Vec<(PortCategory, u32)> = Vec::new();
        let mut sum: u32 = 0;

        for port in &host.ports {
            let cat = PortCategory::from_port(*port);
            let w = cat.risk_weight();
            sum = sum.saturating_add(w);
            by_cat.push((cat, w));
        }

        // CVE contribution: each CVE adds 5, capped at 40.
        let cve_count = analysis.all_cves.len();
        let cve_pts = u32::try_from(cve_count).unwrap_or(u32::MAX).saturating_mul(5).min(40);
        sum = sum.saturating_add(cve_pts);

        let score = sum.min(100);
        ExposureScore {
            score,
            by_category: by_cat,
            cve_count,
            severity: ExposureSeverity::from_score(score),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shodan_banner_analyzer::BannerAnalyzer;
    use crate::shodan_host_enricher::{ShodanBanner, ShodanHost};

    /// Build a host with a CVE-bearing SSH banner in `data`, plus the given
    /// top-level ports/vulns. Used by tests that need realistic banner data.
    fn host_with_banner(ports: Vec<u16>, vulns: Vec<String>) -> ShodanHost {
        ShodanHost {
            ip: "1.2.3.4".into(),
            hostnames: vec![],
            domains: vec![],
            country_code: None,
            country_name: None,
            city: None,
            asn: None,
            isp: None,
            org: None,
            os: None,
            ports,
            tags: vec![],
            vulns,
            data: vec![ShodanBanner {
                ip: Some("1.2.3.4".into()),
                port: 22,
                transport: Some("tcp".into()),
                product: Some("OpenSSH".into()),
                version: None,
                cpe: vec![],
                cpe23: vec![],
                hostnames: vec![],
                data: Some("SSH-2.0".into()),
                timestamp: None,
                asn: None,
                org: None,
                vulns: Some(serde_json::json!({"CVE-2024-9999": {}})),
            }],
            last_update: None,
        }
    }

    /// Build a host with no banner data, no ports, and no vulns.
    fn host_empty() -> ShodanHost {
        ShodanHost {
            ip: "1.2.3.4".into(),
            hostnames: vec![],
            domains: vec![],
            country_code: None,
            country_name: None,
            city: None,
            asn: None,
            isp: None,
            org: None,
            os: None,
            ports: vec![],
            tags: vec![],
            vulns: vec![],
            data: vec![],
            last_update: None,
        }
    }

    #[test]
    fn high_risk_ports_dominate() {
        let h = host_with_banner(vec![22, 3389, 1433, 80], vec!["CVE-2024-0001".into()]);
        let a = BannerAnalyzer::analyze_host(&h);
        let s = ExposureScorer::score(&h, &a);
        assert!(s.score > 0);
        assert!(s.cve_count >= 1);
        assert!(matches!(
            s.severity,
            ExposureSeverity::Medium | ExposureSeverity::High | ExposureSeverity::Critical
        ));
    }

    #[test]
    fn empty_host_zero_score() {
        // A truly empty host (no banners, no ports, no vulns) must score 0.
        let h = host_empty();
        let a = BannerAnalyzer::analyze_host(&h);
        let s = ExposureScorer::score(&h, &a);
        assert_eq!(s.score, 0);
        assert_eq!(s.severity, ExposureSeverity::None);
    }
}
