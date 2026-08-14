//! `IoC` enrichment pipeline.
//!
//! Provides a composable enrichment pipeline that can apply multiple
//! enrichers to an [`IoC`] in sequence, accumulating context such as
//! geo-IP information, WHOIS data, passive DNS records, and abuse scores.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::ioc::{IoC, IoCType};

// ---------------------------------------------------------------------------
// GeoIP enrichment
// ---------------------------------------------------------------------------

/// Geographic location enrichment for an IP address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpInfo {
    /// ISO-3166-1 alpha-2 country code (e.g. `US`).
    pub country_code: String,
    /// Country display name.
    pub country_name: String,
    /// Autonomous System Number.
    pub asn: u32,
    /// ASN organisation name.
    pub asn_org: String,
    /// City name, if available.
    pub city: Option<String>,
    /// Latitude in decimal degrees.
    pub latitude: Option<f64>,
    /// Longitude in decimal degrees.
    pub longitude: Option<f64>,
    /// Whether the IP belongs to a known hosting provider.
    pub is_hosting: bool,
    /// Whether the IP belongs to a known VPN service.
    pub is_vpn: bool,
    /// Whether the IP belongs to a known Tor exit node.
    pub is_tor: bool,
}

impl GeoIpInfo {
    /// Return `true` if this IP is from infrastructure that hides true origin.
    #[must_use]
    pub const fn is_anonymising(&self) -> bool {
        self.is_vpn || self.is_tor
    }
}

impl fmt::Display for GeoIpInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (AS{} {} — {})",
            self.country_code, self.asn, self.asn_org, self.country_name
        )
    }
}

// ---------------------------------------------------------------------------
// WHOIS enrichment
// ---------------------------------------------------------------------------

/// WHOIS registration data for a domain or IP block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisRecord {
    /// Domain or IP queried.
    pub query: String,
    /// Registrar name.
    pub registrar: Option<String>,
    /// Registration date (ISO 8601 string).
    pub created: Option<String>,
    /// Expiry date (ISO 8601 string).
    pub expires: Option<String>,
    /// Registrant name / organisation.
    pub registrant: Option<String>,
    /// Registrant country.
    pub registrant_country: Option<String>,
    /// Name servers.
    pub name_servers: Vec<String>,
    /// Whether the registration is privacy-protected.
    pub privacy_protected: bool,
}

impl WhoisRecord {
    /// Return the age of the domain in days given a current Unix timestamp.
    ///
    /// Returns `None` if the creation date cannot be parsed.
    #[must_use]
    pub const fn age_days(&self, _now_unix: u64) -> Option<u64> {
        // Simplified: in a real implementation parse `self.created` as RFC 3339.
        None
    }
}

// ---------------------------------------------------------------------------
// Passive DNS
// ---------------------------------------------------------------------------

/// A single passive-DNS resolution record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdnsRecord {
    /// Hostname queried.
    pub hostname: String,
    /// Resolved IP address.
    pub ip: String,
    /// First observed (Unix timestamp).
    pub first_seen: u64,
    /// Last observed (Unix timestamp).
    pub last_seen: u64,
    /// Number of observations.
    pub count: u32,
    /// Data source that collected this record.
    pub source: String,
}

/// Set of passive-DNS records for a host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PdnsData {
    /// All resolution records collected.
    pub records: Vec<PdnsRecord>,
}

impl PdnsData {
    /// Create an empty passive-DNS record set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Collect all unique resolved IPs.
    #[must_use]
    pub fn unique_ips(&self) -> Vec<&str> {
        let mut seen: Vec<&str> = Vec::new();
        for r in &self.records {
            if !seen.contains(&r.ip.as_str()) {
                seen.push(&r.ip);
            }
        }
        seen
    }

    /// Return the most recently observed record.
    #[must_use]
    pub fn latest(&self) -> Option<&PdnsRecord> {
        self.records.iter().max_by_key(|r| r.last_seen)
    }
}

// ---------------------------------------------------------------------------
// Abuse confidence
// ---------------------------------------------------------------------------

/// Aggregated abuse confidence data for an IP or domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseConfidence {
    /// Abuse confidence percentage in [0, 100].
    pub score: u8,
    /// Number of reports seen.
    pub report_count: u32,
    /// Categories of abuse detected (e.g. `ssh_brute_force`, `malware_c2`).
    pub categories: Vec<String>,
    /// Most recent report timestamp (Unix).
    pub last_reported: Option<u64>,
    /// Data source.
    pub source: String,
}

impl AbuseConfidence {
    /// Return `true` if this indicator should be considered abusive.
    #[must_use]
    pub const fn is_abusive(&self) -> bool {
        self.score >= 50
    }
}

// ---------------------------------------------------------------------------
// EnrichedIoC
// ---------------------------------------------------------------------------

/// An `IoC` with all available enrichment data attached.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedIoC {
    /// The base indicator.
    pub ioc: IoC,
    /// Geo-IP data (IP-type indicators only).
    pub geo_ip: Option<GeoIpInfo>,
    /// WHOIS record (domain/IP indicators).
    pub whois: Option<WhoisRecord>,
    /// Passive DNS records (domain indicators).
    pub pdns: Option<PdnsData>,
    /// Abuse confidence data.
    pub abuse: Option<AbuseConfidence>,
    /// Arbitrary key-value enrichment metadata.
    pub metadata: HashMap<String, String>,
    /// Enrichment data age in seconds since the data was fetched.
    pub cache_age_secs: u64,
}

impl EnrichedIoC {
    /// Wrap a plain `IoC` with no enrichment data.
    #[must_use]
    pub fn new(ioc: IoC) -> Self {
        Self {
            ioc,
            geo_ip: None,
            whois: None,
            pdns: None,
            abuse: None,
            metadata: HashMap::new(),
            cache_age_secs: 0,
        }
    }

    /// Return `true` if any enrichment source marks this `IoC` as malicious.
    #[must_use]
    pub const fn is_high_risk(&self) -> bool {
        if let Some(ref abuse) = self.abuse
            && abuse.is_abusive() {
                return true;
            }
        if let Some(ref geo) = self.geo_ip
            && geo.is_anonymising() {
                return true;
            }
        false
    }

    /// Compute an overall enrichment risk score [0, 100].
    ///
    /// Factors:
    /// - Abuse confidence score (weighted 60 %)
    /// - Geo-IP anonymisation (+20 if VPN/Tor)
    /// - `IoC` base confidence (weighted 20 %)
    #[must_use]
    pub fn risk_score(&self) -> u8 {
        let mut score = 0.0f32;

        if let Some(ref abuse) = self.abuse {
            score = f32::from(abuse.score).mul_add(0.6, score);
        }
        if let Some(ref geo) = self.geo_ip
            && geo.is_anonymising() {
                score += 20.0;
            }
        score = f32::from(self.ioc.confidence).mul_add(0.2, score);

        crate::casts::f32_to_u8_sat(score.min(100.0).round())
    }

    /// Add an arbitrary metadata key-value pair.
    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }
}

impl fmt::Display for EnrichedIoC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EnrichedIoC [{ioc}] risk_score={score}",
            ioc = self.ioc,
            score = self.risk_score(),
        )
    }
}

// ---------------------------------------------------------------------------
// Enrichment pipeline
// ---------------------------------------------------------------------------

/// Trait implemented by each enrichment stage.
pub trait IoCEnricher: Send + Sync {
    /// Name of this enricher.
    fn name(&self) -> &str;

    /// `IoC` types this enricher can handle.
    fn supported_types(&self) -> Vec<IoCType>;

    /// Apply enrichment in-place to an [`EnrichedIoC`].
    ///
    /// # Errors
    ///
    /// Returns a boxed error if the enrichment fails.
    fn enrich(&self, target: &mut EnrichedIoC) -> Result<(), Box<dyn std::error::Error>>;
}

/// Sequential enrichment pipeline.
///
/// Each registered enricher is applied in insertion order.
/// Failures are collected and reported but do not abort the pipeline.
#[derive(Default)]
pub struct EnrichmentPipeline {
    enrichers: Vec<Box<dyn IoCEnricher>>,
}

impl EnrichmentPipeline {
    /// Create an empty pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an additional enricher stage.
    pub fn add_enricher(&mut self, enricher: Box<dyn IoCEnricher>) {
        self.enrichers.push(enricher);
    }

    /// Run all enrichers against `target`, collecting any errors.
    ///
    /// Returns a `Vec` of `(enricher_name, error_message)` for any stages that
    /// failed.
    pub fn run(&self, target: &mut EnrichedIoC) -> Vec<(String, String)> {
        let mut errors = Vec::new();
        for enricher in &self.enrichers {
            let supported = enricher.supported_types();
            if !supported.contains(&target.ioc.ioc_type) {
                continue;
            }
            if let Err(e) = enricher.enrich(target) {
                errors.push((enricher.name().to_string(), e.to_string()));
            }
        }
        errors
    }

    /// Return the number of registered enrichers.
    #[must_use]
    pub fn enricher_count(&self) -> usize {
        self.enrichers.len()
    }
}

impl fmt::Debug for EnrichmentPipeline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrichmentPipeline")
            .field("enricher_count", &self.enrichers.len())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Built-in mock enrichers
// ---------------------------------------------------------------------------

/// A no-op enricher used for testing.
#[derive(Debug)]
pub struct NullEnricher {
    name: String,
    types: Vec<IoCType>,
}

impl NullEnricher {
    /// Create a null enricher that claims to handle `types`.
    #[must_use]
    pub fn new(name: impl Into<String>, types: Vec<IoCType>) -> Self {
        Self {
            name: name.into(),
            types,
        }
    }
}

impl IoCEnricher for NullEnricher {
    fn name(&self) -> &str {
        &self.name
    }

    fn supported_types(&self) -> Vec<IoCType> {
        self.types.clone()
    }

    fn enrich(&self, _target: &mut EnrichedIoC) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

/// A metadata-tagging enricher that stamps a fixed key-value pair.
#[derive(Debug)]
pub struct MetadataEnricher {
    key: String,
    value: String,
    types: Vec<IoCType>,
}

impl MetadataEnricher {
    /// Create a new metadata stamper.
    #[must_use]
    pub fn new(key: impl Into<String>, value: impl Into<String>, types: Vec<IoCType>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            types,
        }
    }
}

impl IoCEnricher for MetadataEnricher {
    fn name(&self) -> &'static str {
        "metadata"
    }

    fn supported_types(&self) -> Vec<IoCType> {
        self.types.clone()
    }

    fn enrich(&self, target: &mut EnrichedIoC) -> Result<(), Box<dyn std::error::Error>> {
        target.set_metadata(self.key.clone(), self.value.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::Severity;

    fn make_ip_ioc() -> IoC {
        let mut ioc = IoC::new(IoCType::Ip, "1.2.3.4".to_string(), "test".to_string());
        ioc.confidence = 80;
        ioc
    }

    fn make_domain_ioc() -> IoC {
        IoC::new(
            IoCType::Domain,
            "evil.example.com".to_string(),
            "test".to_string(),
        )
    }

    fn make_geo() -> GeoIpInfo {
        GeoIpInfo {
            country_code: "RU".to_string(),
            country_name: "Russia".to_string(),
            asn: 12389,
            asn_org: "Rostelecom".to_string(),
            city: Some("Moscow".to_string()),
            latitude: Some(55.75),
            longitude: Some(37.62),
            is_hosting: false,
            is_vpn: false,
            is_tor: false,
        }
    }

    fn make_abuse(score: u8) -> AbuseConfidence {
        AbuseConfidence {
            score,
            report_count: 42,
            categories: vec!["malware_c2".to_string()],
            last_reported: Some(1_700_000_000),
            source: "abuseipdb".to_string(),
        }
    }

    #[test]
    fn test_enriched_ioc_new() {
        let e = EnrichedIoC::new(make_ip_ioc());
        assert!(e.geo_ip.is_none());
        assert!(e.whois.is_none());
        assert!(!e.is_high_risk());
        assert_eq!(e.risk_score(), crate::casts::f32_to_u8_sat((80_f32 * 0.2).round()));
    }

    #[test]
    fn test_enriched_ioc_high_risk_abuse() {
        let mut e = EnrichedIoC::new(make_ip_ioc());
        e.abuse = Some(make_abuse(90));
        assert!(e.is_high_risk());
    }

    #[test]
    fn test_enriched_ioc_high_risk_tor() {
        let mut e = EnrichedIoC::new(make_ip_ioc());
        let mut geo = make_geo();
        geo.is_tor = true;
        e.geo_ip = Some(geo);
        assert!(e.is_high_risk());
    }

    #[test]
    fn test_enriched_ioc_risk_score_combined() {
        let mut e = EnrichedIoC::new(make_ip_ioc());
        e.abuse = Some(make_abuse(80));
        let score = e.risk_score();
        assert!(score > 0);
        assert!(score <= 100);
    }

    #[test]
    fn test_enriched_ioc_set_metadata() {
        let mut e = EnrichedIoC::new(make_ip_ioc());
        e.set_metadata("source_feed", "threatfox");
        assert_eq!(
            e.metadata.get("source_feed").map(String::as_str),
            Some("threatfox")
        );
    }

    #[test]
    fn test_enriched_ioc_display() {
        let e = EnrichedIoC::new(make_ip_ioc());
        let s = e.to_string();
        assert!(s.contains("EnrichedIoC"));
        assert!(s.contains("1.2.3.4"));
    }

    #[test]
    fn test_geo_ip_anonymising_false() {
        let geo = make_geo();
        assert!(!geo.is_anonymising());
    }

    #[test]
    fn test_geo_ip_anonymising_vpn() {
        let mut geo = make_geo();
        geo.is_vpn = true;
        assert!(geo.is_anonymising());
    }

    #[test]
    fn test_geo_ip_display() {
        let geo = make_geo();
        let s = geo.to_string();
        assert!(s.contains("RU"));
        assert!(s.contains("12389"));
    }

    #[test]
    fn test_abuse_confidence_abusive_threshold() {
        assert!(!make_abuse(49).is_abusive());
        assert!(make_abuse(50).is_abusive());
        assert!(make_abuse(100).is_abusive());
    }

    #[test]
    fn test_pdns_unique_ips() {
        let mut pdns = PdnsData::new();
        pdns.records.push(PdnsRecord {
            hostname: "evil.com".to_string(),
            ip: "1.2.3.4".to_string(),
            first_seen: 0,
            last_seen: 100,
            count: 5,
            source: "vt".to_string(),
        });
        pdns.records.push(PdnsRecord {
            hostname: "evil.com".to_string(),
            ip: "1.2.3.4".to_string(),
            first_seen: 200,
            last_seen: 300,
            count: 3,
            source: "pdns".to_string(),
        });
        pdns.records.push(PdnsRecord {
            hostname: "evil.com".to_string(),
            ip: "5.6.7.8".to_string(),
            first_seen: 0,
            last_seen: 50,
            count: 1,
            source: "vt".to_string(),
        });
        assert_eq!(pdns.unique_ips().len(), 2);
    }

    #[test]
    fn test_pdns_latest() {
        let mut pdns = PdnsData::new();
        pdns.records.push(PdnsRecord {
            hostname: "h".to_string(),
            ip: "1.1.1.1".to_string(),
            first_seen: 0,
            last_seen: 100,
            count: 1,
            source: "s".to_string(),
        });
        pdns.records.push(PdnsRecord {
            hostname: "h".to_string(),
            ip: "2.2.2.2".to_string(),
            first_seen: 0,
            last_seen: 999,
            count: 1,
            source: "s".to_string(),
        });
        let latest = pdns.latest().unwrap();
        assert_eq!(latest.ip, "2.2.2.2");
    }

    #[test]
    fn test_pdns_empty_latest_is_none() {
        let pdns = PdnsData::new();
        assert!(pdns.latest().is_none());
    }

    #[test]
    fn test_pipeline_null_enricher() {
        let mut pipeline = EnrichmentPipeline::new();
        pipeline.add_enricher(Box::new(NullEnricher::new("null", vec![IoCType::Ip])));
        let mut e = EnrichedIoC::new(make_ip_ioc());
        let errors = pipeline.run(&mut e);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_pipeline_metadata_enricher() {
        let mut pipeline = EnrichmentPipeline::new();
        pipeline.add_enricher(Box::new(MetadataEnricher::new(
            "feed",
            "threatfox",
            vec![IoCType::Ip],
        )));
        let mut e = EnrichedIoC::new(make_ip_ioc());
        let errors = pipeline.run(&mut e);
        assert!(errors.is_empty());
        assert_eq!(
            e.metadata.get("feed").map(String::as_str),
            Some("threatfox")
        );
    }

    #[test]
    fn test_pipeline_skips_unsupported_type() {
        let mut pipeline = EnrichmentPipeline::new();
        // Enricher only handles Domain, but we feed it an IP
        pipeline.add_enricher(Box::new(MetadataEnricher::new(
            "k",
            "v",
            vec![IoCType::Domain],
        )));
        let mut e = EnrichedIoC::new(make_ip_ioc());
        pipeline.run(&mut e);
        assert!(e.metadata.is_empty());
    }

    #[test]
    fn test_pipeline_enricher_count() {
        let mut pipeline = EnrichmentPipeline::new();
        assert_eq!(pipeline.enricher_count(), 0);
        pipeline.add_enricher(Box::new(NullEnricher::new("a", vec![])));
        pipeline.add_enricher(Box::new(NullEnricher::new("b", vec![])));
        assert_eq!(pipeline.enricher_count(), 2);
    }

    #[test]
    fn test_pipeline_debug() {
        let pipeline = EnrichmentPipeline::new();
        let s = format!("{pipeline:?}");
        assert!(s.contains("EnrichmentPipeline"));
    }

    #[test]
    fn test_enriched_ioc_severity_preserved() {
        let mut ioc = make_ip_ioc();
        ioc.severity = Severity::Critical;
        let e = EnrichedIoC::new(ioc);
        assert_eq!(e.ioc.severity, Severity::Critical);
    }

    #[test]
    fn test_whois_record_fields() {
        let w = WhoisRecord {
            query: "evil.com".to_string(),
            registrar: Some("GoDaddy".to_string()),
            created: Some("2020-01-01".to_string()),
            expires: Some("2025-01-01".to_string()),
            registrant: None,
            registrant_country: Some("US".to_string()),
            name_servers: vec!["ns1.evil.com".to_string()],
            privacy_protected: true,
        };
        assert!(w.privacy_protected);
        assert_eq!(w.name_servers.len(), 1);
        assert!(w.age_days(1_700_000_000).is_none());
    }

    #[test]
    fn test_enriched_ioc_serialization() {
        let mut e = EnrichedIoC::new(make_domain_ioc());
        e.set_metadata("k", "v");
        let json = serde_json::to_string(&e).unwrap();
        let decoded: EnrichedIoC = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.ioc.value, "evil.example.com");
        assert_eq!(decoded.metadata.get("k").map(String::as_str), Some("v"));
    }
}
