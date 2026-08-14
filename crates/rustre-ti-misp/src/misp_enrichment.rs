//! `misp_enrichment` — MISP enrichment pipeline: `IoC` enrichment, attribute
//! enrichment, event enrichment, and an enrichment report.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// EnrichmentSource
// ---------------------------------------------------------------------------

/// Where enrichment data comes from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnrichmentSource {
    VirusTotal,
    Shodan,
    AbuseIPDB,
    AlienVaultOTX,
    MalwareBazaar,
    URLHaus,
    PhishTank,
    ThreatFox,
    Malpedia,
    InternalTi,
    Passive,
    Custom(String),
}

impl fmt::Display for EnrichmentSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "Custom({s})"),
            _ => write!(f, "{self:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// IoC_Enrichment — enriched indicator of compromise
// ---------------------------------------------------------------------------

/// The type of an `IoC`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IoCKind {
    Md5,
    Sha1,
    Sha256,
    IpAddress,
    Domain,
    Url,
    Email,
    RegistryKey,
    MutexName,
    FilePath,
    CertificateSerial,
    JarmHash,
}

impl fmt::Display for IoCKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A raw `IoC` value with its kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoC {
    pub kind: IoCKind,
    pub value: String,
}

impl IoC {
    /// Create a new `IoC`.
    #[must_use]
    pub fn new(kind: IoCKind, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }

    /// Whether this `IoC` looks well-formed for its type.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        match &self.kind {
            IoCKind::Md5 => {
                self.value.len() == 32 && self.value.chars().all(|c| c.is_ascii_hexdigit())
            }
            IoCKind::Sha1 => {
                self.value.len() == 40 && self.value.chars().all(|c| c.is_ascii_hexdigit())
            }
            IoCKind::Sha256 => {
                self.value.len() == 64 && self.value.chars().all(|c| c.is_ascii_hexdigit())
            }
            IoCKind::IpAddress => is_valid_ipv4(&self.value) || is_valid_ipv6(&self.value),
            IoCKind::Domain => !self.value.is_empty() && self.value.contains('.'),
            IoCKind::Url => self.value.starts_with("http://") || self.value.starts_with("https://"),
            _ => !self.value.is_empty(),
        }
    }
}

impl fmt::Display for IoC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.kind, self.value)
    }
}

/// An enriched `IoC` with data from one or more sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoCEnrichment {
    pub ioc: IoC,
    pub source: EnrichmentSource,
    pub malicious_detections: Option<u32>,
    pub total_detections: Option<u32>,
    pub first_seen: Option<u64>,
    pub last_seen: Option<u64>,
    pub tags: Vec<String>,
    pub threat_families: Vec<String>,
    pub country: Option<String>,
    pub asn: Option<String>,
    pub confidence: f32,
    pub notes: String,
    pub extra: HashMap<String, String>,
}

impl IoCEnrichment {
    /// Create a minimal enrichment.
    #[must_use]
    pub fn new(ioc: IoC, source: EnrichmentSource) -> Self {
        Self {
            ioc,
            source,
            malicious_detections: None,
            total_detections: None,
            first_seen: None,
            last_seen: None,
            tags: Vec::new(),
            threat_families: Vec::new(),
            country: None,
            asn: None,
            confidence: 0.0,
            notes: String::new(),
            extra: HashMap::new(),
        }
    }

    /// Whether this `IoC` is considered malicious.
    #[must_use]
    pub fn is_malicious(&self) -> bool {
        match (self.malicious_detections, self.total_detections) {
            (Some(m), Some(t)) if t > 0 => (m as f32 / t as f32) > 0.3,
            (Some(m), None) => m > 0,
            _ => false,
        }
    }

    /// Detection ratio as a string.
    #[must_use]
    pub fn detection_ratio(&self) -> String {
        match (self.malicious_detections, self.total_detections) {
            (Some(m), Some(t)) => format!("{m}/{t}"),
            (Some(m), None) => format!("{m}/?"),
            _ => "unknown".to_string(),
        }
    }
}

impl fmt::Display for IoCEnrichment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} — {} (malicious={})",
            self.source,
            self.ioc,
            self.detection_ratio(),
            self.is_malicious()
        )
    }
}

// ---------------------------------------------------------------------------
// AttributeEnrich
// ---------------------------------------------------------------------------

/// Enrichment data for a MISP attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeEnrich {
    pub attribute_uuid: String,
    pub attribute_type: String,
    pub attribute_value: String,
    pub enrichments: Vec<IoCEnrichment>,
    pub merged_tags: Vec<String>,
    pub risk_score: f32,
    pub enriched_at: u64,
}

impl AttributeEnrich {
    /// Create a new attribute enrichment.
    #[must_use]
    pub fn new(
        uuid: impl Into<String>,
        attr_type: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            attribute_uuid: uuid.into(),
            attribute_type: attr_type.into(),
            attribute_value: value.into(),
            enrichments: Vec::new(),
            merged_tags: Vec::new(),
            risk_score: 0.0,
            enriched_at: current_timestamp(),
        }
    }

    /// Add an enrichment.
    pub fn add_enrichment(&mut self, enr: IoCEnrichment) {
        // Merge tags
        for tag in &enr.tags {
            if !self.merged_tags.contains(tag) {
                self.merged_tags.push(tag.clone());
            }
        }
        // Compute risk score as max of confidence
        if enr.confidence > self.risk_score {
            self.risk_score = enr.confidence;
        }
        self.enrichments.push(enr);
    }

    /// Whether any enrichment source flagged this as malicious.
    #[must_use]
    pub fn is_flagged_malicious(&self) -> bool {
        self.enrichments.iter().any(IoCEnrichment::is_malicious)
    }
}

impl fmt::Display for AttributeEnrich {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AttributeEnrich({}: {} — {} enrichments, risk={:.1})",
            self.attribute_uuid,
            self.attribute_value,
            self.enrichments.len(),
            self.risk_score
        )
    }
}

// ---------------------------------------------------------------------------
// EventEnrich
// ---------------------------------------------------------------------------

/// Enrichment data for a complete MISP event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnrich {
    pub event_uuid: String,
    pub event_id: Option<u64>,
    pub event_info: String,
    pub attribute_enrichments: Vec<AttributeEnrich>,
    pub new_tags: Vec<String>,
    pub new_galaxy_clusters: Vec<String>,
    pub threat_level_change: Option<String>,
    pub enriched_at: u64,
    pub sources_used: Vec<EnrichmentSource>,
}

impl EventEnrich {
    /// Create a new event enrichment.
    #[must_use]
    pub fn new(uuid: impl Into<String>, info: impl Into<String>) -> Self {
        Self {
            event_uuid: uuid.into(),
            event_id: None,
            event_info: info.into(),
            attribute_enrichments: Vec::new(),
            new_tags: Vec::new(),
            new_galaxy_clusters: Vec::new(),
            threat_level_change: None,
            enriched_at: current_timestamp(),
            sources_used: Vec::new(),
        }
    }

    /// Add an attribute enrichment.
    pub fn add_attribute_enrichment(&mut self, ae: AttributeEnrich) {
        // Collect unique sources
        for enr in &ae.enrichments {
            if !self.sources_used.contains(&enr.source) {
                self.sources_used.push(enr.source.clone());
            }
        }
        self.attribute_enrichments.push(ae);
    }

    /// Count attributes flagged as malicious.
    #[must_use]
    pub fn malicious_count(&self) -> usize {
        self.attribute_enrichments
            .iter()
            .filter(|ae| ae.is_flagged_malicious())
            .count()
    }

    /// Average risk score across all attribute enrichments.
    #[must_use]
    pub fn average_risk(&self) -> f32 {
        if self.attribute_enrichments.is_empty() {
            return 0.0;
        }
        let total: f32 = self
            .attribute_enrichments
            .iter()
            .map(|ae| ae.risk_score)
            .sum();
        total / self.attribute_enrichments.len() as f32
    }
}

impl fmt::Display for EventEnrich {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EventEnrich({}: {} attributes, {} malicious, avg_risk={:.2})",
            self.event_uuid,
            self.attribute_enrichments.len(),
            self.malicious_count(),
            self.average_risk()
        )
    }
}

// ---------------------------------------------------------------------------
// EnrichmentReport
// ---------------------------------------------------------------------------

/// The complete enrichment report for a batch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentReport {
    pub report_id: String,
    pub events_enriched: Vec<EventEnrich>,
    pub total_attributes_enriched: usize,
    pub total_malicious_attributes: usize,
    pub enrichment_sources: Vec<EnrichmentSource>,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub errors: Vec<String>,
    pub summary: HashMap<String, String>,
}

impl EnrichmentReport {
    /// Create a new report.
    #[must_use]
    pub fn new(report_id: impl Into<String>) -> Self {
        Self {
            report_id: report_id.into(),
            events_enriched: Vec::new(),
            total_attributes_enriched: 0,
            total_malicious_attributes: 0,
            enrichment_sources: Vec::new(),
            started_at: current_timestamp(),
            finished_at: None,
            errors: Vec::new(),
            summary: HashMap::new(),
        }
    }

    /// Finalise the report.
    pub fn finalize(&mut self) {
        self.finished_at = Some(current_timestamp());
        let total_attrs: usize = self
            .events_enriched
            .iter()
            .map(|e| e.attribute_enrichments.len())
            .sum();
        let malicious: usize = self
            .events_enriched
            .iter()
            .map(EventEnrich::malicious_count)
            .sum();
        self.total_attributes_enriched = total_attrs;
        self.total_malicious_attributes = malicious;
        self.summary.insert(
            "total_events".to_string(),
            self.events_enriched.len().to_string(),
        );
        self.summary
            .insert("total_attributes".to_string(), total_attrs.to_string());
        self.summary
            .insert("malicious_attributes".to_string(), malicious.to_string());
    }

    /// Duration in seconds (if finished).
    #[must_use]
    pub fn duration_secs(&self) -> Option<u64> {
        self.finished_at.map(|f| f.saturating_sub(self.started_at))
    }

    /// Add an event enrichment.
    pub fn add_event(&mut self, ee: EventEnrich) {
        for src in &ee.sources_used {
            if !self.enrichment_sources.contains(src) {
                self.enrichment_sources.push(src.clone());
            }
        }
        self.events_enriched.push(ee);
    }
}

impl fmt::Display for EnrichmentReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EnrichmentReport({}: {} events, {} malicious attrs)",
            self.report_id,
            self.events_enriched.len(),
            self.total_malicious_attributes
        )
    }
}

// ---------------------------------------------------------------------------
// MispEnrichment — main coordinator
// ---------------------------------------------------------------------------

/// MISP enrichment coordinator.
pub struct MispEnrichment {
    pub sources: Vec<EnrichmentSource>,
    pub vt_api_key: Option<String>,
    pub timeout_secs: u64,
}

impl MispEnrichment {
    /// Create a new enrichment coordinator.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sources: Vec::new(),
            vt_api_key: None,
            timeout_secs: 30,
        }
    }

    /// Add an enrichment source.
    pub fn add_source(&mut self, source: EnrichmentSource) {
        if !self.sources.contains(&source) {
            self.sources.push(source);
        }
    }

    /// Enrich a single `IoC` with all configured sources (simulated).
    #[must_use]
    pub fn enrich_ioc(&self, ioc: IoC) -> Vec<IoCEnrichment> {
        let mut enrichments = Vec::with_capacity(self.sources.len());
        for src in &self.sources {
            let mut enr = IoCEnrichment::new(ioc.clone(), src.clone());
            // Simulate enrichment based on known malicious values
            if ioc.value.contains("malware") || ioc.value.contains("evil") {
                enr.malicious_detections = Some(45);
                enr.total_detections = Some(70);
                enr.confidence = 0.8;
                enr.tags.push("malicious".to_string());
            } else {
                enr.malicious_detections = Some(0);
                enr.total_detections = Some(70);
                enr.confidence = 0.1;
            }
            enrichments.push(enr);
        }
        enrichments
    }

    /// Enrich all attributes in an event (simulated).
    #[must_use]
    pub fn enrich_event(
        &self,
        event_uuid: impl Into<String>,
        event_info: impl Into<String>,
        iocs: Vec<IoC>,
    ) -> EventEnrich {
        let mut event_enr = EventEnrich::new(event_uuid, event_info);
        for ioc in iocs {
            let value = ioc.value.clone();
            let attr_type = ioc.kind.to_string();
            let mut ae = AttributeEnrich::new(format!("attr-{value}"), attr_type, value);
            for enr in self.enrich_ioc(ioc) {
                ae.add_enrichment(enr);
            }
            event_enr.add_attribute_enrichment(ae);
        }
        event_enr
    }

    /// Run a full enrichment batch and produce a report.
    #[must_use]
    pub fn run_batch(&self, events: Vec<(String, String, Vec<IoC>)>) -> EnrichmentReport {
        let mut report = EnrichmentReport::new(format!("report-{}", current_timestamp()));
        for (uuid, info, iocs) in events {
            let ee = self.enrich_event(uuid, info, iocs);
            report.add_event(ee);
        }
        report.finalize();
        report
    }
}

impl Default for MispEnrichment {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn is_valid_ipv4(s: &str) -> bool {
    let mut count = 0usize;
    for p in s.split('.') {
        if p.parse::<u8>().is_err() {
            return false;
        }
        count += 1;
        if count > 4 {
            return false;
        }
    }
    count == 4
}

fn is_valid_ipv6(s: &str) -> bool {
    s.contains(':') && s.len() >= 2
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

    #[test]
    fn test_ioc_valid_md5() {
        let ioc = IoC::new(IoCKind::Md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert!(ioc.is_valid());
    }

    #[test]
    fn test_ioc_invalid_md5() {
        let ioc = IoC::new(IoCKind::Md5, "short");
        assert!(!ioc.is_valid());
    }

    #[test]
    fn test_ioc_valid_ipv4() {
        let ioc = IoC::new(IoCKind::IpAddress, "192.168.1.1");
        assert!(ioc.is_valid());
    }

    #[test]
    fn test_ioc_invalid_ipv4() {
        let ioc = IoC::new(IoCKind::IpAddress, "999.1.1.1");
        assert!(!ioc.is_valid());
    }

    #[test]
    fn test_ioc_valid_url() {
        let ioc = IoC::new(IoCKind::Url, "https://example.com/malware");
        assert!(ioc.is_valid());
    }

    #[test]
    fn test_ioc_display() {
        let ioc = IoC::new(IoCKind::Domain, "evil.com");
        let s = ioc.to_string();
        assert!(s.contains("evil.com"));
    }

    #[test]
    fn test_ioc_enrichment_new() {
        let ioc = IoC::new(IoCKind::Sha256, "abc".repeat(21) + "ab");
        let enr = IoCEnrichment::new(ioc, EnrichmentSource::VirusTotal);
        assert_eq!(enr.source, EnrichmentSource::VirusTotal);
        assert!(!enr.is_malicious());
    }

    #[test]
    fn test_ioc_enrichment_malicious() {
        let ioc = IoC::new(IoCKind::Md5, "d41d8cd98f00b204e9800998ecf8427e");
        let mut enr = IoCEnrichment::new(ioc, EnrichmentSource::VirusTotal);
        enr.malicious_detections = Some(40);
        enr.total_detections = Some(70);
        assert!(enr.is_malicious());
    }

    #[test]
    fn test_ioc_enrichment_detection_ratio() {
        let ioc = IoC::new(IoCKind::Md5, "d41d8cd98f00b204e9800998ecf8427e");
        let mut enr = IoCEnrichment::new(ioc, EnrichmentSource::VirusTotal);
        enr.malicious_detections = Some(20);
        enr.total_detections = Some(70);
        assert_eq!(enr.detection_ratio(), "20/70");
    }

    #[test]
    fn test_enrichment_source_display() {
        assert_eq!(EnrichmentSource::VirusTotal.to_string(), "VirusTotal");
        let c = EnrichmentSource::Custom("MyFeed".to_string());
        assert!(c.to_string().contains("MyFeed"));
    }

    #[test]
    fn test_attribute_enrich_new() {
        let ae = AttributeEnrich::new("uuid-1", "sha256", "abc");
        assert_eq!(ae.attribute_uuid, "uuid-1");
        assert_eq!(ae.risk_score, 0.0);
    }

    #[test]
    fn test_attribute_enrich_add_enrichment() {
        let mut ae = AttributeEnrich::new("uuid-1", "sha256", "abc");
        let ioc = IoC::new(IoCKind::Sha256, "abc");
        let mut enr = IoCEnrichment::new(ioc, EnrichmentSource::VirusTotal);
        enr.confidence = 0.9;
        enr.tags.push("malware".to_string());
        ae.add_enrichment(enr);
        assert_eq!(ae.enrichments.len(), 1);
        assert!(ae.merged_tags.contains(&"malware".to_string()));
        assert!((ae.risk_score - 0.9).abs() < 0.001);
    }

    #[test]
    fn test_attribute_enrich_flagged_malicious() {
        let mut ae = AttributeEnrich::new("uuid-1", "sha256", "abc");
        let ioc = IoC::new(IoCKind::Sha256, "abc");
        let mut enr = IoCEnrichment::new(ioc, EnrichmentSource::VirusTotal);
        enr.malicious_detections = Some(45);
        enr.total_detections = Some(70);
        ae.add_enrichment(enr);
        assert!(ae.is_flagged_malicious());
    }

    #[test]
    fn test_event_enrich_malicious_count() {
        let mut event = EventEnrich::new("evt-1", "test event");
        let mut ae = AttributeEnrich::new("attr-1", "sha256", "test");
        let ioc = IoC::new(IoCKind::Sha256, "test");
        let mut enr = IoCEnrichment::new(ioc, EnrichmentSource::VirusTotal);
        enr.malicious_detections = Some(40);
        enr.total_detections = Some(60);
        ae.add_enrichment(enr);
        event.add_attribute_enrichment(ae);
        assert_eq!(event.malicious_count(), 1);
    }

    #[test]
    fn test_event_enrich_average_risk_zero() {
        let event = EventEnrich::new("evt-1", "empty");
        assert_eq!(event.average_risk(), 0.0);
    }

    #[test]
    fn test_event_enrich_display() {
        let event = EventEnrich::new("evt-1", "test event");
        let s = event.to_string();
        assert!(s.contains("evt-1"));
    }

    #[test]
    fn test_enrichment_report_new() {
        let r = EnrichmentReport::new("R1");
        assert_eq!(r.report_id, "R1");
        assert!(r.finished_at.is_none());
    }

    #[test]
    fn test_enrichment_report_finalize() {
        let mut r = EnrichmentReport::new("R1");
        r.finalize();
        assert!(r.finished_at.is_some());
    }

    #[test]
    fn test_enrichment_report_display() {
        let r = EnrichmentReport::new("R1");
        let s = r.to_string();
        assert!(s.contains("R1"));
    }

    #[test]
    fn test_misp_enrichment_sources() {
        let mut enr = MispEnrichment::new();
        enr.add_source(EnrichmentSource::VirusTotal);
        enr.add_source(EnrichmentSource::Shodan);
        enr.add_source(EnrichmentSource::VirusTotal); // duplicate
        assert_eq!(enr.sources.len(), 2);
    }

    #[test]
    fn test_misp_enrichment_enrich_ioc_malicious() {
        let mut me = MispEnrichment::new();
        me.add_source(EnrichmentSource::VirusTotal);
        let ioc = IoC::new(IoCKind::Domain, "evil-malware.com");
        let enrichments = me.enrich_ioc(ioc);
        assert_eq!(enrichments.len(), 1);
        assert!(enrichments[0].is_malicious());
    }

    #[test]
    fn test_misp_enrichment_enrich_ioc_clean() {
        let mut me = MispEnrichment::new();
        me.add_source(EnrichmentSource::VirusTotal);
        let ioc = IoC::new(IoCKind::Domain, "legitimate.com");
        let enrichments = me.enrich_ioc(ioc);
        assert!(!enrichments[0].is_malicious());
    }

    #[test]
    fn test_misp_enrichment_run_batch() {
        let mut me = MispEnrichment::new();
        me.add_source(EnrichmentSource::VirusTotal);
        let events = vec![(
            "evt-1".to_string(),
            "Test Event".to_string(),
            vec![IoC::new(IoCKind::Domain, "evil-malware.com")],
        )];
        let report = me.run_batch(events);
        assert_eq!(report.events_enriched.len(), 1);
        assert!(report.total_attributes_enriched > 0);
    }

    #[test]
    fn test_is_valid_ipv4() {
        assert!(is_valid_ipv4("10.0.0.1"));
        assert!(!is_valid_ipv4("256.0.0.1"));
        assert!(!is_valid_ipv4("not.an.ip"));
    }

    #[test]
    fn test_ioc_kind_display() {
        assert_eq!(IoCKind::Sha256.to_string(), "Sha256");
        assert_eq!(IoCKind::IpAddress.to_string(), "IpAddress");
    }
}
