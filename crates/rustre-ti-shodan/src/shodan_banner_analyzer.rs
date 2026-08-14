//! Banner analyzer — extracts product/version/vuln signals from a
//! [`ShodanBanner`] or [`ShodanHost`].

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::shodan_host_enricher::{ShodanBanner, ShodanHost};
use crate::{PortCategory, ShodanError};

/// Summary of a banner.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BannerSummary {
    /// Port number.
    pub port: u16,
    /// Port category.
    pub category: Option<PortCategory>,
    /// Detected product (e.g. `nginx`, `OpenSSH`).
    pub product: Option<String>,
    /// Detected version.
    pub version: Option<String>,
    /// Distinct CPE strings.
    pub cpes: BTreeSet<String>,
    /// Distinct CVE strings referenced by the banner.
    pub cves: BTreeSet<String>,
    /// `true` if the banner suggests TLS service.
    pub tls: bool,
}

impl BannerSummary {
    /// Build a summary from a single banner.
    #[must_use]
    pub fn from_banner(b: &ShodanBanner) -> Self {
        let category = if b.port == 0 {
            None
        } else {
            Some(PortCategory::from_port(b.port))
        };
        let mut cpes: BTreeSet<String> = BTreeSet::new();
        cpes.extend(b.cpe.iter().cloned());
        cpes.extend(b.cpe23.iter().cloned());
        let cve_set = extract_cves(b);
        let tls = b
            .data
            .as_deref()
            .is_some_and(|d| d.contains("TLS") || d.contains("ssl"));

        Self {
            port: b.port,
            category,
            product: b.product.clone(),
            version: b.version.clone(),
            cpes,
            cves: cve_set,
            tls,
        }
    }
}

/// Result of analysing all banners attached to a host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostBannerAnalysis {
    /// Per-port summaries (sorted by port).
    pub per_port: BTreeMap<u16, BannerSummary>,
    /// Distinct CVEs across all banners.
    pub all_cves: BTreeSet<String>,
    /// Distinct CPEs across all banners.
    pub all_cpes: BTreeSet<String>,
    /// Detected products, deduplicated.
    pub products: BTreeSet<String>,
}

impl HostBannerAnalysis {
    /// Count of unique vulnerable ports (any port with at least one CVE).
    #[must_use]
    pub fn vulnerable_port_count(&self) -> usize {
        self.per_port.values().filter(|s| !s.cves.is_empty()).count()
    }

    /// `true` if no banner reports a CVE.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.all_cves.is_empty()
    }
}

/// Banner analyzer.
pub struct BannerAnalyzer;

impl BannerAnalyzer {
    /// Analyze a list of banners.
    #[must_use]
    pub fn analyze_banners(banners: &[ShodanBanner]) -> HostBannerAnalysis {
        let mut out = HostBannerAnalysis::default();
        for b in banners {
            let summary = BannerSummary::from_banner(b);
            out.all_cves.extend(summary.cves.iter().cloned());
            out.all_cpes.extend(summary.cpes.iter().cloned());
            if let Some(p) = summary.product.clone() {
                out.products.insert(p);
            }
            // Merge into any existing entry for the same port (e.g. TCP + UDP
            // banners on the same port number) instead of silently overwriting,
            // which would discard CVEs/CPEs collected from the earlier banner.
            let port = summary.port;
            if let Some(existing) = out.per_port.get_mut(&port) {
                existing.cves.extend(summary.cves);
                existing.cpes.extend(summary.cpes);
                // Later banners override product/version so the most recent
                // observation wins (matches Shodan's own latest-banner
                // semantics). Earlier products are still retained in
                // `out.products`.
                if summary.product.is_some() {
                    existing.product = summary.product;
                }
                if summary.version.is_some() {
                    existing.version = summary.version;
                }
                existing.tls |= summary.tls;
            } else {
                out.per_port.insert(port, summary);
            }
        }
        out
    }

    /// Analyze the banners attached to a host record.
    #[must_use]
    pub fn analyze_host(host: &ShodanHost) -> HostBannerAnalysis {
        let mut analysis = Self::analyze_banners(&host.data);
        // Merge `host.vulns` (top-level CVE list) into the global set.
        analysis.all_cves.extend(host.vulns.iter().cloned());
        analysis
    }

    /// Validate that a banner is structurally usable (has a port and
    /// at least one identifying field).
    ///
    /// # Errors
    /// [`ShodanError::Json`] with a human-readable reason.
    pub fn validate(b: &ShodanBanner) -> Result<(), ShodanError> {
        if b.port == 0 {
            return Err(ShodanError::Json("banner missing port".to_owned()));
        }
        if b.product.is_none() && b.data.is_none() && b.cpe.is_empty() {
            return Err(ShodanError::Json(
                "banner has no product/data/cpe".to_owned(),
            ));
        }
        Ok(())
    }
}

fn extract_cves(b: &ShodanBanner) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    if let Some(vulns) = b.vulns.as_ref() {
        match vulns {
            serde_json::Value::Object(map) => {
                for key in map.keys() {
                    if key.starts_with("CVE-") {
                        out.insert(key.clone());
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    if let Some(s) = v.as_str()
                        && s.starts_with("CVE-")
                    {
                        out.insert(s.to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn banner(port: u16, product: Option<&str>) -> ShodanBanner {
        ShodanBanner {
            ip: Some("1.2.3.4".into()),
            port,
            transport: Some("tcp".into()),
            product: product.map(str::to_string),
            version: None,
            cpe: vec![],
            cpe23: vec![],
            hostnames: vec![],
            data: Some("hello".into()),
            timestamp: None,
            asn: None,
            org: None,
            vulns: Some(serde_json::json!({"CVE-2024-0001": {}})),
        }
    }

    #[test]
    fn analyze_collects_cves() {
        let a = BannerAnalyzer::analyze_banners(&[banner(22, Some("OpenSSH")), banner(80, None)]);
        assert_eq!(a.per_port.len(), 2);
        assert!(a.all_cves.contains("CVE-2024-0001"));
        assert!(!a.is_clean());
        assert_eq!(a.vulnerable_port_count(), 2);
    }

    #[test]
    fn validate_rejects_empty() {
        let mut b = banner(0, None);
        b.data = None;
        b.vulns = None;
        assert!(BannerAnalyzer::validate(&b).is_err());
    }
}
