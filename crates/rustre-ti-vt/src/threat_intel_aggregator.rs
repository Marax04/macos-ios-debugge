//! Threat intelligence aggregator.
//!
//! Merges indicators from multiple intelligence sources, de-duplicates them,
//! computes composite threat scores, and organises results into campaigns and
//! threat-actor profiles.

use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// IOC type
// ---------------------------------------------------------------------------

/// The kind of indicator of compromise carried by a `ThreatIndicator`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IocType {
    /// SHA-256 file hash.
    Sha256,
    /// MD5 file hash.
    Md5,
    /// SHA-1 file hash.
    Sha1,
    /// IPv4 or IPv6 address.
    Ip,
    /// Domain name.
    Domain,
    /// Full URL.
    Url,
    /// E-mail address.
    Email,
    /// Autonomous system number (e.g. `"AS12345"`).
    Asn,
    /// CIDR network block.
    Cidr,
    /// Windows registry key path.
    RegKey,
    /// File-system path.
    FilePath,
    /// Windows mutex name.
    Mutex,
}

impl IocType {
    /// Returns a short, human-readable label for the IOC type.
    #[must_use] 
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Ip => "ip",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::Email => "email",
            Self::Asn => "asn",
            Self::Cidr => "cidr",
            Self::RegKey => "regkey",
            Self::FilePath => "filepath",
            Self::Mutex => "mutex",
        }
    }

    /// Returns `true` if this IOC type describes a network observable.
    #[must_use] 
    pub const fn is_network(&self) -> bool {
        matches!(
            self,
            Self::Ip | Self::Domain | Self::Url | Self::Email | Self::Asn | Self::Cidr
        )
    }

    /// Returns `true` if this IOC type describes a file observable.
    #[must_use] 
    pub const fn is_file(&self) -> bool {
        matches!(
            self,
            Self::Sha256 | Self::Md5 | Self::Sha1 | Self::FilePath
        )
    }
}

// ---------------------------------------------------------------------------
// Intel source
// ---------------------------------------------------------------------------

/// A named source from which threat intelligence was obtained.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IntelSource {
    /// `VirusTotal`.
    VirusTotal,
    /// MISP (Malware Information Sharing Platform).
    Misp,
    /// OTX `AlienVault`.
    OtxAlienVault,
    /// Abuse.ch feeds.
    AbuseCh,
    /// `ThreatFox`.
    ThreatFox,
    /// A user-defined custom source.
    Custom(String),
}

impl IntelSource {
    /// Returns a short string identifier for the source.
    #[must_use] 
    pub const fn id(&self) -> &str {
        match self {
            Self::VirusTotal => "virustotal",
            Self::Misp => "misp",
            Self::OtxAlienVault => "otx",
            Self::AbuseCh => "abuse.ch",
            Self::ThreatFox => "threatfox",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Numeric reliability score 0–100 for this source.
    #[must_use] 
    pub const fn reliability_score(&self) -> u8 {
        match self {
            Self::VirusTotal => 90,
            Self::Misp => 85,
            Self::OtxAlienVault => 75,
            Self::AbuseCh => 80,
            Self::ThreatFox => 78,
            Self::Custom(_) => 50,
        }
    }
}

// ---------------------------------------------------------------------------
// ThreatIndicator
// ---------------------------------------------------------------------------

/// A single indicator of compromise enriched with context from one or more
/// intelligence sources.
#[derive(Debug, Clone)]
pub struct ThreatIndicator {
    /// The indicator value (hash, IP, domain, …).
    pub ioc_value: String,
    /// Category of this indicator.
    pub ioc_type: IocType,
    /// Aggregated confidence score (0–100).
    pub confidence: u8,
    /// Sources that reported this indicator.
    pub sources: Vec<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
    /// Unix timestamp of first observation.
    pub first_seen: u64,
    /// Unix timestamp of most recent observation.
    pub last_seen: u64,
    /// High-level threat categories (e.g. `"ransomware"`, `"c2"`).
    pub threat_types: Vec<String>,
    /// MITRE ATT&CK technique IDs (e.g. `"T1059.001"`).
    pub mitre_techniques: Vec<String>,
}

impl ThreatIndicator {
    /// Create a minimal `ThreatIndicator` with a single source.
    pub fn new(
        ioc_value: impl Into<String>,
        ioc_type: IocType,
        confidence: u8,
        source: IntelSource,
    ) -> Self {
        Self {
            ioc_value: ioc_value.into(),
            ioc_type,
            confidence: confidence.min(100),
            sources: vec![source.id().to_owned()],
            tags: Vec::new(),
            first_seen: 0,
            last_seen: 0,
            threat_types: Vec::new(),
            mitre_techniques: Vec::new(),
        }
    }

    /// Add a tag if it is not already present.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let t = tag.into();
        if !self.tags.contains(&t) {
            self.tags.push(t);
        }
    }

    /// Add a MITRE technique ID if it is not already present.
    pub fn add_technique(&mut self, tid: impl Into<String>) {
        let t = tid.into();
        if !self.mitre_techniques.contains(&t) {
            self.mitre_techniques.push(t);
        }
    }

    /// Returns `true` if this indicator is considered highly reliable
    /// (confidence ≥ 70 and reported by at least two distinct sources).
    #[must_use] 
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 70 && self.sources.len() >= 2
    }

    /// Merge another indicator's metadata into this one (in-place).
    ///
    /// Only call this if both have the same `ioc_value`.
    pub fn merge_from(&mut self, other: &Self) {
        // confidence: take the max
        self.confidence = self.confidence.max(other.confidence);

        // sources: union
        for s in &other.sources {
            if !self.sources.contains(s) {
                self.sources.push(s.clone());
            }
        }

        // tags: union
        for t in &other.tags {
            if !self.tags.contains(t) {
                self.tags.push(t.clone());
            }
        }

        // threat_types: union
        for tt in &other.threat_types {
            if !self.threat_types.contains(tt) {
                self.threat_types.push(tt.clone());
            }
        }

        // mitre_techniques: union
        for m in &other.mitre_techniques {
            if !self.mitre_techniques.contains(m) {
                self.mitre_techniques.push(m.clone());
            }
        }

        // timestamps: extend the observed window
        if other.first_seen != 0
            && (self.first_seen == 0 || other.first_seen < self.first_seen) {
                self.first_seen = other.first_seen;
            }
        if other.last_seen > self.last_seen {
            self.last_seen = other.last_seen;
        }
    }
}

// ---------------------------------------------------------------------------
// Campaign / ThreatActor
// ---------------------------------------------------------------------------

/// A malicious campaign grouping several IOCs and TTPs.
#[derive(Debug, Clone)]
pub struct Campaign {
    /// Campaign name (e.g. `"Operation SilverFox"`).
    pub name: String,
    /// IOC values associated with this campaign.
    pub iocs: Vec<String>,
    /// MITRE ATT&CK technique IDs observed in this campaign.
    pub techniques: Vec<String>,
    /// Approximate start time (Unix timestamp).
    pub start_time: u64,
}

impl Campaign {
    /// Create a new empty campaign.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            iocs: Vec::new(),
            techniques: Vec::new(),
            start_time: 0,
        }
    }

    /// Add an IOC value to the campaign.
    pub fn add_ioc(&mut self, ioc: impl Into<String>) {
        let v = ioc.into();
        if !self.iocs.contains(&v) {
            self.iocs.push(v);
        }
    }

    /// Add a MITRE technique ID.
    pub fn add_technique(&mut self, tid: impl Into<String>) {
        let t = tid.into();
        if !self.techniques.contains(&t) {
            self.techniques.push(t);
        }
    }
}

/// A known threat actor (APT group, criminal gang, etc.).
#[derive(Debug, Clone)]
pub struct ThreatActor {
    /// Primary name (e.g. `"APT28"`).
    pub name: String,
    /// Alternative names / aliases.
    pub aliases: Vec<String>,
    /// Motivation string (e.g. `"espionage"`, `"financial"`, `"hacktivism"`).
    pub motivation: String,
    /// Observed TTPs (MITRE technique IDs or free text).
    pub ttps: Vec<String>,
}

impl ThreatActor {
    /// Create a new `ThreatActor`.
    pub fn new(
        name: impl Into<String>,
        motivation: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            aliases: Vec::new(),
            motivation: motivation.into(),
            ttps: Vec::new(),
        }
    }

    /// Add a TTP entry.
    pub fn add_ttp(&mut self, ttp: impl Into<String>) {
        let t = ttp.into();
        if !self.ttps.contains(&t) {
            self.ttps.push(t);
        }
    }

    /// Returns `true` if `query` matches the primary name or any alias
    /// (case-insensitive).
    #[must_use] 
    pub fn matches_name(&self, query: &str) -> bool {
        let q = query.to_lowercase();
        if self.name.to_lowercase() == q {
            return true;
        }
        self.aliases.iter().any(|a| a.to_lowercase() == q)
    }
}

// ---------------------------------------------------------------------------
// AggregatedReport
// ---------------------------------------------------------------------------

/// The final output of `ThreatIntelAggregator::aggregate()`.
#[derive(Debug, Clone)]
pub struct AggregatedReport {
    /// De-duplicated and merged indicators.
    pub indicators: Vec<ThreatIndicator>,
    /// Identified campaigns.
    pub campaigns: Vec<Campaign>,
    /// Known threat actors referenced.
    pub threat_actors: Vec<ThreatActor>,
    /// Overall threat score (0.0–100.0).
    pub overall_score: f64,
}

impl AggregatedReport {
    /// Returns all high-confidence indicators.
    #[must_use] 
    pub fn high_confidence_indicators(&self) -> Vec<&ThreatIndicator> {
        self.indicators.iter().filter(|i| i.is_high_confidence()).collect()
    }

    /// Returns indicators of the given type.
    #[must_use] 
    pub fn indicators_of_type(&self, ioc_type: &IocType) -> Vec<&ThreatIndicator> {
        self.indicators
            .iter()
            .filter(|i| &i.ioc_type == ioc_type)
            .collect()
    }

    /// Returns the set of all unique MITRE technique IDs across all indicators.
    #[must_use] 
    pub fn all_techniques(&self) -> HashSet<&str> {
        self.indicators
            .iter()
            .flat_map(|i| i.mitre_techniques.iter().map(std::string::String::as_str))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ThreatIntelAggregator
// ---------------------------------------------------------------------------

/// Aggregates threat intelligence from multiple sources.
///
/// # Workflow
/// 1. Call `add_indicator()` (or `add_indicators()`) to ingest raw indicators.
/// 2. Call `add_campaign()` / `add_threat_actor()` as needed.
/// 3. Call `aggregate()` to produce a deduplicated, scored `AggregatedReport`.
pub struct ThreatIntelAggregator {
    raw_indicators: Vec<ThreatIndicator>,
    campaigns: Vec<Campaign>,
    threat_actors: Vec<ThreatActor>,
}

impl ThreatIntelAggregator {
    /// Create a new empty aggregator.
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            raw_indicators: Vec::new(),
            campaigns: Vec::new(),
            threat_actors: Vec::new(),
        }
    }

    /// Add a single raw indicator.
    pub fn add_indicator(&mut self, indicator: ThreatIndicator) {
        self.raw_indicators.push(indicator);
    }

    /// Add a collection of raw indicators.
    pub fn add_indicators(&mut self, indicators: impl IntoIterator<Item = ThreatIndicator>) {
        self.raw_indicators.extend(indicators);
    }

    /// Register a campaign.
    pub fn add_campaign(&mut self, campaign: Campaign) {
        self.campaigns.push(campaign);
    }

    /// Register a threat actor.
    pub fn add_threat_actor(&mut self, actor: ThreatActor) {
        self.threat_actors.push(actor);
    }

    /// Returns the number of raw (pre-merge) indicators currently held.
    #[must_use] 
    pub const fn raw_indicator_count(&self) -> usize {
        self.raw_indicators.len()
    }

    /// De-duplicate indicators by `ioc_value`, merging sources and metadata.
    ///
    /// Indicators with the same value are folded into a single entry.
    #[must_use] 
    pub fn merge_indicators(&self) -> Vec<ThreatIndicator> {
        let mut map: HashMap<String, ThreatIndicator> = HashMap::new();
        for ind in &self.raw_indicators {
            if let Some(existing) = map.get_mut(&ind.ioc_value) {
                existing.merge_from(ind);
            } else {
                map.insert(ind.ioc_value.clone(), ind.clone());
            }
        }
        let mut merged: Vec<ThreatIndicator> = map.into_values().collect();
        merged.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        merged
    }

    /// Compute a threat score for a single merged indicator.
    ///
    /// Formula:  `confidence × ln(source_count + 1) × uniqueness_factor`
    /// where `uniqueness_factor` = 1 + (`technique_count` * 0.1).
    #[must_use] 
    pub fn compute_threat_score(indicator: &ThreatIndicator) -> f64 {
        let source_count = indicator.sources.len() as f64;
        let technique_count = indicator.mitre_techniques.len() as f64;
        let uniqueness = technique_count.mul_add(0.1, 1.0);
        let raw = f64::from(indicator.confidence) * source_count.ln_1p() * uniqueness;
        raw.min(100.0)
    }

    /// Compute the overall threat score for a collection of merged indicators.
    ///
    /// Returns the weighted average, capped at 100.
    #[must_use] 
    pub fn compute_overall_score(indicators: &[ThreatIndicator]) -> f64 {
        if indicators.is_empty() {
            return 0.0;
        }
        let total: f64 = indicators
            .iter()
            .map(Self::compute_threat_score)
            .sum();
        (total / indicators.len() as f64).min(100.0)
    }

    /// Produce the final `AggregatedReport`.
    #[must_use] 
    pub fn aggregate(&self) -> AggregatedReport {
        let indicators = self.merge_indicators();
        let overall_score = Self::compute_overall_score(&indicators);
        AggregatedReport {
            indicators,
            campaigns: self.campaigns.clone(),
            threat_actors: self.threat_actors.clone(),
            overall_score,
        }
    }

    /// Returns a sorted slice of the most prolific IOC types.
    #[must_use] 
    pub fn ioc_type_histogram(indicators: &[ThreatIndicator]) -> Vec<(String, usize)> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for ind in indicators {
            *counts.entry(ind.ioc_type.label().to_owned()).or_insert(0) += 1;
        }
        let mut pairs: Vec<(String, usize)> = counts.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs
    }

    /// Returns all distinct MITRE technique IDs seen across indicators.
    #[must_use] 
    pub fn all_techniques(indicators: &[ThreatIndicator]) -> Vec<String> {
        let mut set: HashSet<String> = HashSet::new();
        for ind in indicators {
            for t in &ind.mitre_techniques {
                set.insert(t.clone());
            }
        }
        let mut v: Vec<String> = set.into_iter().collect();
        v.sort();
        v
    }

    /// Find all indicators whose `last_seen` is within `window_secs` of `now`.
    #[must_use] 
    pub fn recently_active(
        indicators: &[ThreatIndicator],
        now: u64,
        window_secs: u64,
    ) -> Vec<&ThreatIndicator> {
        indicators
            .iter()
            .filter(|i| i.last_seen != 0 && now.saturating_sub(i.last_seen) <= window_secs)
            .collect()
    }

    /// Filter indicators to those tagged with any of the given threat types.
    #[must_use] 
    pub fn filter_by_threat_type<'a>(
        indicators: &'a [ThreatIndicator],
        threat_type: &str,
    ) -> Vec<&'a ThreatIndicator> {
        indicators
            .iter()
            .filter(|i| {
                i.threat_types
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case(threat_type))
            })
            .collect()
    }
}

impl Default for ThreatIntelAggregator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_indicator(value: &str, confidence: u8, source: IntelSource) -> ThreatIndicator {
        ThreatIndicator::new(value, IocType::Sha256, confidence, source)
    }

    #[test]
    fn test_ioc_type_labels() {
        assert_eq!(IocType::Sha256.label(), "sha256");
        assert_eq!(IocType::Ip.label(), "ip");
        assert_eq!(IocType::Domain.label(), "domain");
        assert_eq!(IocType::Mutex.label(), "mutex");
    }

    #[test]
    fn test_ioc_type_is_network() {
        assert!(IocType::Ip.is_network());
        assert!(IocType::Domain.is_network());
        assert!(!IocType::Sha256.is_network());
        assert!(!IocType::FilePath.is_network());
    }

    #[test]
    fn test_ioc_type_is_file() {
        assert!(IocType::Sha256.is_file());
        assert!(IocType::Md5.is_file());
        assert!(!IocType::Ip.is_file());
    }

    #[test]
    fn test_intel_source_id() {
        assert_eq!(IntelSource::VirusTotal.id(), "virustotal");
        assert_eq!(IntelSource::Custom("myorg".to_owned()).id(), "myorg");
    }

    #[test]
    fn test_intel_source_reliability() {
        assert!(IntelSource::VirusTotal.reliability_score() > IntelSource::Custom("x".into()).reliability_score());
    }

    #[test]
    fn test_threat_indicator_new() {
        let ind = make_indicator("abc123", 80, IntelSource::VirusTotal);
        assert_eq!(ind.ioc_value, "abc123");
        assert_eq!(ind.confidence, 80);
        assert_eq!(ind.sources, vec!["virustotal"]);
    }

    #[test]
    fn test_threat_indicator_confidence_capped() {
        let ind = make_indicator("x", 200, IntelSource::Misp);
        assert_eq!(ind.confidence, 100);
    }

    #[test]
    fn test_threat_indicator_merge() {
        let mut a = make_indicator("hash1", 60, IntelSource::VirusTotal);
        a.add_tag("ransomware");
        a.first_seen = 1000;
        a.last_seen = 2000;

        let mut b = make_indicator("hash1", 80, IntelSource::ThreatFox);
        b.add_tag("c2");
        b.add_technique("T1059");
        b.first_seen = 500;
        b.last_seen = 3000;

        a.merge_from(&b);

        assert_eq!(a.confidence, 80);
        assert!(a.sources.contains(&"virustotal".to_owned()));
        assert!(a.sources.contains(&"threatfox".to_owned()));
        assert!(a.tags.contains(&"ransomware".to_owned()));
        assert!(a.tags.contains(&"c2".to_owned()));
        assert!(a.mitre_techniques.contains(&"T1059".to_owned()));
        assert_eq!(a.first_seen, 500);
        assert_eq!(a.last_seen, 3000);
    }

    #[test]
    fn test_merge_deduplicates() {
        let mut agg = ThreatIntelAggregator::new();
        agg.add_indicator(make_indicator("hash1", 70, IntelSource::VirusTotal));
        agg.add_indicator(make_indicator("hash1", 80, IntelSource::Misp));
        agg.add_indicator(make_indicator("hash2", 50, IntelSource::AbuseCh));

        let merged = agg.merge_indicators();
        assert_eq!(merged.len(), 2);
        let h1 = merged.iter().find(|i| i.ioc_value == "hash1").unwrap();
        assert_eq!(h1.sources.len(), 2);
    }

    #[test]
    fn test_compute_threat_score_basic() {
        let ind = make_indicator("x", 100, IntelSource::VirusTotal);
        let score = ThreatIntelAggregator::compute_threat_score(&ind);
        assert!(score > 0.0);
        assert!(score <= 100.0);
    }

    #[test]
    fn test_compute_threat_score_increases_with_sources() {
        let ind1 = make_indicator("x", 80, IntelSource::VirusTotal);
        let mut ind2 = make_indicator("x", 80, IntelSource::VirusTotal);
        ind2.sources.push("misp".to_owned());
        ind2.sources.push("threatfox".to_owned());

        let s1 = ThreatIntelAggregator::compute_threat_score(&ind1);
        let s2 = ThreatIntelAggregator::compute_threat_score(&ind2);
        assert!(s2 > s1, "more sources should yield a higher score");
    }

    #[test]
    fn test_aggregate_produces_report() {
        let mut agg = ThreatIntelAggregator::new();
        agg.add_indicator(make_indicator("a", 75, IntelSource::VirusTotal));
        agg.add_indicator(make_indicator("b", 50, IntelSource::Misp));
        agg.add_campaign(Campaign::new("TestCampaign"));
        agg.add_threat_actor(ThreatActor::new("APT99", "espionage"));

        let report = agg.aggregate();
        assert_eq!(report.indicators.len(), 2);
        assert_eq!(report.campaigns.len(), 1);
        assert_eq!(report.threat_actors.len(), 1);
        assert!(report.overall_score > 0.0);
    }

    #[test]
    fn test_high_confidence_filter() {
        let mut agg = ThreatIntelAggregator::new();
        let mut ind = make_indicator("x", 80, IntelSource::VirusTotal);
        ind.sources.push("misp".to_owned());
        agg.add_indicator(ind);
        agg.add_indicator(make_indicator("y", 30, IntelSource::Misp));

        let report = agg.aggregate();
        let hc = report.high_confidence_indicators();
        assert_eq!(hc.len(), 1);
        assert_eq!(hc[0].ioc_value, "x");
    }

    #[test]
    fn test_ioc_type_histogram() {
        let indicators = vec![
            make_indicator("a", 50, IntelSource::VirusTotal),
            make_indicator("b", 50, IntelSource::VirusTotal),
            ThreatIndicator::new("1.2.3.4", IocType::Ip, 50, IntelSource::Misp),
        ];
        let hist = ThreatIntelAggregator::ioc_type_histogram(&indicators);
        assert_eq!(hist[0].0, "sha256");
        assert_eq!(hist[0].1, 2);
    }

    #[test]
    fn test_all_techniques() {
        let mut ind1 = make_indicator("a", 50, IntelSource::VirusTotal);
        ind1.add_technique("T1059");
        let mut ind2 = make_indicator("b", 50, IntelSource::Misp);
        ind2.add_technique("T1059");
        ind2.add_technique("T1078");

        let techs = ThreatIntelAggregator::all_techniques(&[ind1, ind2]);
        assert_eq!(techs.len(), 2);
        assert!(techs.contains(&"T1059".to_owned()));
        assert!(techs.contains(&"T1078".to_owned()));
    }

    #[test]
    fn test_recently_active() {
        let mut ind1 = make_indicator("a", 50, IntelSource::VirusTotal);
        ind1.last_seen = 1_000_000;
        let mut ind2 = make_indicator("b", 50, IntelSource::Misp);
        ind2.last_seen = 900_000;

        let indicators = [ind1, ind2];
        let recent = ThreatIntelAggregator::recently_active(&indicators, 1_000_100, 200);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].ioc_value, "a");
    }

    #[test]
    fn test_filter_by_threat_type() {
        let mut ind = make_indicator("x", 70, IntelSource::VirusTotal);
        ind.threat_types.push("Ransomware".to_owned());

        let indicators = [ind];
        let filtered = ThreatIntelAggregator::filter_by_threat_type(&indicators, "ransomware");
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_campaign_ioc_dedup() {
        let mut c = Campaign::new("C1");
        c.add_ioc("hash1");
        c.add_ioc("hash1");
        assert_eq!(c.iocs.len(), 1);
    }

    #[test]
    fn test_threat_actor_matches_name() {
        let mut actor = ThreatActor::new("APT28", "espionage");
        actor.aliases.push("Fancy Bear".to_owned());

        assert!(actor.matches_name("apt28"));
        assert!(actor.matches_name("Fancy Bear"));
        assert!(!actor.matches_name("Cozy Bear"));
    }

    #[test]
    fn test_overall_score_empty() {
        assert_eq!(ThreatIntelAggregator::compute_overall_score(&[]), 0.0);
    }
}
