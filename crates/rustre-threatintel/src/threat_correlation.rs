//! Threat intelligence correlation: indicators, rules, threat graphs,
//! campaign detection, actor attribution, and scoring.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── ThreatIndicator ──────────────────────────────────────────────────────────

/// A single threat indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub id: String,
    pub kind: IndicatorKind,
    pub value: String,
    pub confidence: u8,
    pub tlp: TlpLevel,
    pub tags: Vec<String>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub source: String,
    pub actor: Option<String>,
    pub campaign: Option<String>,
    pub malware_family: Option<String>,
    pub enrichments: HashMap<String, String>,
}

impl ThreatIndicator {
    /// Create a new indicator.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        kind: IndicatorKind,
        value: impl Into<String>,
        confidence: u8,
    ) -> Self {
        Self {
            id: id.into(),
            kind,
            value: value.into(),
            confidence: confidence.min(100),
            tlp: TlpLevel::White,
            tags: vec![],
            first_seen_ms: 0,
            last_seen_ms: 0,
            source: String::new(),
            actor: None,
            campaign: None,
            malware_family: None,
            enrichments: HashMap::new(),
        }
    }

    /// Add a tag.
    pub fn tag(&mut self, t: impl Into<String>) {
        self.tags.push(t.into());
    }

    /// Set enrichment data.
    pub fn enrich(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.enrichments.insert(key.into(), value.into());
    }

    /// Returns `true` if confidence meets threshold.
    #[must_use]
    pub const fn is_confident(&self, threshold: u8) -> bool {
        self.confidence >= threshold
    }
}

/// The kind of threat indicator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IndicatorKind {
    Ipv4,
    Ipv6,
    Domain,
    Url,
    FileHashMd5,
    FileHashSha1,
    FileHashSha256,
    Email,
    Mutex,
    RegistryKey,
    FilePath,
    CertificateHash,
    JarmHash,
    AsNumber,
    Other(String),
}

impl fmt::Display for IndicatorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4 => write!(f, "ipv4"),
            Self::Ipv6 => write!(f, "ipv6"),
            Self::Domain => write!(f, "domain"),
            Self::Url => write!(f, "url"),
            Self::FileHashMd5 => write!(f, "hash:md5"),
            Self::FileHashSha1 => write!(f, "hash:sha1"),
            Self::FileHashSha256 => write!(f, "hash:sha256"),
            Self::Email => write!(f, "email"),
            Self::Mutex => write!(f, "mutex"),
            Self::RegistryKey => write!(f, "registry_key"),
            Self::FilePath => write!(f, "filepath"),
            Self::CertificateHash => write!(f, "cert_hash"),
            Self::JarmHash => write!(f, "jarm"),
            Self::AsNumber => write!(f, "asn"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// TLP marking level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlpLevel {
    White,
    Green,
    Amber,
    AmberStrict,
    Red,
}

impl fmt::Display for TlpLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::White => write!(f, "TLP:WHITE"),
            Self::Green => write!(f, "TLP:GREEN"),
            Self::Amber => write!(f, "TLP:AMBER"),
            Self::AmberStrict => write!(f, "TLP:AMBER+STRICT"),
            Self::Red => write!(f, "TLP:RED"),
        }
    }
}

// ─── CorrelationRule ──────────────────────────────────────────────────────────

/// A rule for correlating threat indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub required_kinds: Vec<IndicatorKind>,
    pub required_tags: Vec<String>,
    pub min_indicator_count: usize,
    pub output_tag: String,
    pub confidence_boost: u8,
}

impl CorrelationRule {
    /// Create a new rule.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        required_kinds: Vec<IndicatorKind>,
        min_count: usize,
        output_tag: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            required_kinds,
            required_tags: vec![],
            min_indicator_count: min_count,
            output_tag: output_tag.into(),
            confidence_boost: 10,
        }
    }

    /// Check if this rule matches a set of indicators.
    #[must_use]
    pub fn matches(&self, indicators: &[ThreatIndicator]) -> bool {
        if indicators.len() < self.min_indicator_count {
            return false;
        }
        let kinds_present: HashSet<&IndicatorKind> = indicators.iter().map(|i| &i.kind).collect();
        self.required_kinds
            .iter()
            .all(|k| kinds_present.contains(k))
    }
}

// ─── ThreatGraph ──────────────────────────────────────────────────────────────

/// A graph of threat indicators linked by shared attributes.
#[derive(Debug, Default)]
pub struct ThreatGraph {
    nodes: HashMap<String, ThreatIndicator>,
    edges: Vec<(String, String, String)>, // (from_id, to_id, relation)
}

impl ThreatGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an indicator as a node.
    pub fn add_node(&mut self, indicator: ThreatIndicator) {
        self.nodes.insert(indicator.id.clone(), indicator);
    }

    /// Add a directed edge.
    pub fn add_edge(
        &mut self,
        from: impl Into<String>,
        to: impl Into<String>,
        relation: impl Into<String>,
    ) {
        self.edges.push((from.into(), to.into(), relation.into()));
    }

    /// Get a node by ID.
    #[must_use]
    pub fn get_node(&self, id: &str) -> Option<&ThreatIndicator> {
        self.nodes.get(id)
    }

    /// All neighbors of a node.
    #[must_use]
    pub fn neighbors(&self, id: &str) -> Vec<(&ThreatIndicator, &str)> {
        self.edges
            .iter()
            .filter(|(from, _, _)| from == id)
            .filter_map(|(_, to, rel)| self.nodes.get(to.as_str()).map(|n| (n, rel.as_str())))
            .collect()
    }

    /// Node count.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Edge count.
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Find all nodes matching a tag.
    #[must_use]
    pub fn by_tag(&self, tag: &str) -> Vec<&ThreatIndicator> {
        self.nodes
            .values()
            .filter(|n| n.tags.contains(&tag.to_string()))
            .collect()
    }

    /// Find all nodes of a given kind.
    #[must_use]
    pub fn by_kind(&self, kind: &IndicatorKind) -> Vec<&ThreatIndicator> {
        self.nodes.values().filter(|n| &n.kind == kind).collect()
    }

    /// Find connected components (simple BFS).
    #[must_use]
    pub fn connected_components(&self) -> Vec<Vec<String>> {
        let mut visited = HashSet::new();
        let mut components = Vec::new();
        for id in self.nodes.keys() {
            if !visited.contains(id.as_str()) {
                let mut component = Vec::new();
                let mut queue = std::collections::VecDeque::new();
                queue.push_back(id.clone());
                while let Some(current) = queue.pop_front() {
                    if !visited.insert(current.clone()) {
                        continue;
                    }
                    component.push(current.clone());
                    for (from, to, _) in &self.edges {
                        if from == &current && !visited.contains(to.as_str()) {
                            queue.push_back(to.clone());
                        }
                        if to == &current && !visited.contains(from.as_str()) {
                            queue.push_back(from.clone());
                        }
                    }
                }
                if !component.is_empty() {
                    components.push(component);
                }
            }
        }
        components
    }
}

// ─── CampaignDetector ─────────────────────────────────────────────────────────

/// Detects campaigns from clusters of related indicators.
#[derive(Debug, Clone, Default)]
pub struct CampaignDetector {
    /// Minimum number of correlated indicators to declare a campaign.
    pub min_cluster_size: usize,
}

/// A detected campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedCampaign {
    pub id: String,
    pub name: String,
    pub indicator_count: usize,
    pub attributed_actor: Option<String>,
    pub confidence: u8,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub ttp_ids: Vec<String>,
    pub tags: Vec<String>,
}

impl CampaignDetector {
    /// Create a detector with a minimum cluster size.
    #[must_use]
    pub const fn new(min_cluster_size: usize) -> Self {
        Self { min_cluster_size }
    }

    /// Cluster indicators by shared actor or campaign tags.
    #[must_use]
    pub fn cluster_by_actor(&self, indicators: &[ThreatIndicator]) -> Vec<DetectedCampaign> {
        let mut by_actor: HashMap<String, Vec<&ThreatIndicator>> = HashMap::new();
        for ind in indicators {
            if let Some(ref actor) = ind.actor {
                by_actor.entry(actor.clone()).or_default().push(ind);
            }
        }
        let mut campaigns = Vec::new();
        for (actor, iocs) in &by_actor {
            if iocs.len() >= self.min_cluster_size {
                let first = iocs.iter().map(|i| i.first_seen_ms).min().unwrap_or(0);
                let last = iocs.iter().map(|i| i.last_seen_ms).max().unwrap_or(0);
                let avg_u32 = iocs.iter().map(|i| u32::from(i.confidence)).sum::<u32>()
                    / u32::try_from(iocs.len().max(1)).unwrap_or(u32::MAX);
                let avg_confidence = u8::try_from(avg_u32.min(u32::from(u8::MAX))).unwrap_or(u8::MAX);
                campaigns.push(DetectedCampaign {
                    id: format!("CAMP-{}", campaigns.len() + 1),
                    name: format!("{actor} campaign"),
                    indicator_count: iocs.len(),
                    attributed_actor: Some(actor.clone()),
                    confidence: avg_confidence,
                    first_seen_ms: first,
                    last_seen_ms: last,
                    ttp_ids: vec![],
                    tags: vec![],
                });
            }
        }
        campaigns
    }

    /// Cluster indicators by shared campaign tag.
    #[must_use]
    pub fn cluster_by_campaign_tag(&self, indicators: &[ThreatIndicator]) -> Vec<DetectedCampaign> {
        let mut by_campaign: HashMap<String, Vec<&ThreatIndicator>> = HashMap::new();
        for ind in indicators {
            if let Some(ref camp) = ind.campaign {
                by_campaign.entry(camp.clone()).or_default().push(ind);
            }
        }
        let mut campaigns = Vec::new();
        for (camp_name, iocs) in &by_campaign {
            if iocs.len() >= self.min_cluster_size {
                campaigns.push(DetectedCampaign {
                    id: format!("CAMP-TAG-{}", campaigns.len() + 1),
                    name: camp_name.clone(),
                    indicator_count: iocs.len(),
                    attributed_actor: iocs.iter().find_map(|i| i.actor.clone()),
                    confidence: 75,
                    first_seen_ms: iocs.iter().map(|i| i.first_seen_ms).min().unwrap_or(0),
                    last_seen_ms: iocs.iter().map(|i| i.last_seen_ms).max().unwrap_or(0),
                    ttp_ids: vec![],
                    tags: vec![camp_name.clone()],
                });
            }
        }
        campaigns
    }
}

// ─── ActorAttribution ─────────────────────────────────────────────────────────

/// Attributes a set of indicators to a threat actor.
#[derive(Debug, Clone, Default)]
pub struct ActorAttribution;

/// Attribution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionResult {
    pub actor_name: String,
    pub confidence: u8,
    pub evidence_count: usize,
    pub technique_overlap: Vec<String>,
    pub infrastructure_overlap: Vec<String>,
    pub rationale: String,
}

impl AttributionResult {
    /// Returns `true` if attribution is high-confidence.
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 75
    }
}

impl ActorAttribution {
    /// Create a new attribution engine.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Attribute indicators to known actors based on TTPs and infrastructure.
    #[must_use]
    pub fn attribute(
        &self,
        indicators: &[ThreatIndicator],
        known_actors: &[(&str, &[&str])],
    ) -> Vec<AttributionResult> {
        let mut results = Vec::new();
        for (actor, actor_ioc_patterns) in known_actors {
            let mut matches = 0usize;
            let mut infra_overlap = Vec::new();
            for ind in indicators {
                for pat in *actor_ioc_patterns {
                    if ind.value.contains(pat) || ind.tags.iter().any(|t| t.contains(pat)) {
                        matches += 1;
                        infra_overlap.push(ind.value.clone());
                    }
                }
            }
            if matches > 0 {
                let confidence = u8::try_from((matches.min(10) * 8).min(90)).unwrap_or(90);
                results.push(AttributionResult {
                    actor_name: actor.to_string(),
                    confidence,
                    evidence_count: matches,
                    technique_overlap: vec![],
                    infrastructure_overlap: infra_overlap,
                    rationale: format!("{matches} indicator(s) matched {actor} known patterns"),
                });
            }
        }
        results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        results
    }
}

// ─── ThreatScore ──────────────────────────────────────────────────────────────

/// Computes a composite threat score from multiple indicators.
#[derive(Debug, Clone, Default)]
pub struct ThreatScore;

/// A composite threat score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositeScore {
    pub total: f64,
    pub normalized: u8,
    pub component_scores: HashMap<String, f64>,
    pub verdict: ThreatVerdict,
}

/// A threat verdict based on score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatVerdict {
    Clean,
    Suspicious,
    Likely,
    Confirmed,
}

impl fmt::Display for ThreatVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => write!(f, "clean"),
            Self::Suspicious => write!(f, "suspicious"),
            Self::Likely => write!(f, "likely"),
            Self::Confirmed => write!(f, "confirmed"),
        }
    }
}

impl ThreatScore {
    /// Create a new scorer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compute a composite score from a list of indicators.
    #[must_use]
    pub fn compute(&self, indicators: &[ThreatIndicator]) -> CompositeScore {
        let mut components: HashMap<String, f64> = HashMap::new();

        let ip_count = indicators
            .iter()
            .filter(|i| matches!(i.kind, IndicatorKind::Ipv4))
            .count();
        let domain_count = indicators
            .iter()
            .filter(|i| matches!(i.kind, IndicatorKind::Domain))
            .count();
        let hash_count = indicators
            .iter()
            .filter(|i| {
                matches!(
                    i.kind,
                    IndicatorKind::FileHashSha256 | IndicatorKind::FileHashMd5
                )
            })
            .count();
        let avg_conf = if indicators.is_empty() {
            0.0
        } else {
            indicators.iter().map(|i| f64::from(i.confidence)).sum::<f64>()
                / f64::from(u32::try_from(indicators.len()).unwrap_or(u32::MAX))
        };

        components.insert("ip_score".into(), f64::from(u32::try_from(ip_count).unwrap_or(u32::MAX)) * 5.0);
        components.insert("domain_score".into(), f64::from(u32::try_from(domain_count).unwrap_or(u32::MAX)) * 4.0);
        components.insert("hash_score".into(), f64::from(u32::try_from(hash_count).unwrap_or(u32::MAX)) * 8.0);
        components.insert("avg_confidence".into(), avg_conf);

        let raw: f64 = components.values().sum();
        let normalized = crate::casts::f64_to_u8_sat(raw.min(100.0));

        let verdict = match normalized {
            0..=20 => ThreatVerdict::Clean,
            21..=50 => ThreatVerdict::Suspicious,
            51..=80 => ThreatVerdict::Likely,
            _ => ThreatVerdict::Confirmed,
        };

        CompositeScore {
            total: raw,
            normalized,
            component_scores: components,
            verdict,
        }
    }

    /// Score a single indicator.
    #[must_use]
    pub fn score_indicator(ind: &ThreatIndicator) -> u8 {
        let base: u8 = match ind.kind {
            IndicatorKind::FileHashSha256 | IndicatorKind::FileHashMd5 => 20,
            IndicatorKind::Ipv4 | IndicatorKind::Domain => 15,
            IndicatorKind::Url => 12,
            IndicatorKind::Mutex | IndicatorKind::RegistryKey => 10,
            _ => 5,
        };
        ((u16::from(base) * u16::from(ind.confidence)) / 100).min(100) as u8
    }
}

// ─── ThreatCorrelation ────────────────────────────────────────────────────────

/// Main threat correlation engine.
pub struct ThreatCorrelation {
    pub graph: ThreatGraph,
    pub rules: Vec<CorrelationRule>,
    pub scorer: ThreatScore,
    pub campaign_detector: CampaignDetector,
    pub attribution: ActorAttribution,
}

/// Result of a full threat correlation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub matched_rules: Vec<String>,
    pub campaigns: Vec<DetectedCampaign>,
    pub score: CompositeScore,
    pub graph_nodes: usize,
    pub graph_edges: usize,
    pub components: usize,
}

impl ThreatCorrelation {
    /// Create a new correlation engine with default rules.
    #[must_use]
    pub fn new() -> Self {
        let rules = vec![
            CorrelationRule::new(
                "RULE-001",
                "IP + Domain C2",
                vec![IndicatorKind::Ipv4, IndicatorKind::Domain],
                2,
                "c2",
            ),
            CorrelationRule::new(
                "RULE-002",
                "Hash + IP",
                vec![IndicatorKind::FileHashSha256, IndicatorKind::Ipv4],
                2,
                "malware_with_c2",
            ),
            CorrelationRule::new(
                "RULE-003",
                "Multi-hash cluster",
                vec![IndicatorKind::FileHashSha256],
                3,
                "hash_cluster",
            ),
            CorrelationRule::new(
                "RULE-004",
                "Email + Domain",
                vec![IndicatorKind::Email, IndicatorKind::Domain],
                2,
                "phishing",
            ),
        ];
        Self {
            graph: ThreatGraph::new(),
            rules,
            scorer: ThreatScore::new(),
            campaign_detector: CampaignDetector::new(2),
            attribution: ActorAttribution::new(),
        }
    }

    /// Add an indicator.
    pub fn add_indicator(&mut self, ind: ThreatIndicator) {
        self.graph.add_node(ind);
    }

    /// Run full correlation.
    #[must_use]
    pub fn correlate(&self) -> CorrelationResult {
        let all_indicators: Vec<&ThreatIndicator> = self.graph.nodes.values().collect();
        let owned: Vec<ThreatIndicator> = all_indicators.iter().map(|i| (*i).clone()).collect();

        let mut matched_rules = Vec::new();
        for rule in &self.rules {
            if rule.matches(&owned) {
                matched_rules.push(format!("{}: {}", rule.id, rule.name));
            }
        }

        let campaigns = self.campaign_detector.cluster_by_actor(&owned);
        let score = self.scorer.compute(&owned);
        let components = self.graph.connected_components().len();

        CorrelationResult {
            matched_rules,
            campaigns,
            score,
            graph_nodes: self.graph.node_count(),
            graph_edges: self.graph.edge_count(),
            components,
        }
    }

    /// Build a mock correlation engine for testing.
    #[must_use]
    pub fn mock() -> Self {
        let mut engine = Self::new();

        let mut ip = ThreatIndicator::new("IND-001", IndicatorKind::Ipv4, "185.220.101.1", 90);
        ip.actor = Some("APT28".into());
        ip.first_seen_ms = 1_700_000_000_000;
        ip.last_seen_ms = 1_700_100_000_000;
        ip.tag("c2");
        engine.add_indicator(ip);

        let mut dom = ThreatIndicator::new("IND-002", IndicatorKind::Domain, "c2.evil.com", 85);
        dom.actor = Some("APT28".into());
        dom.tag("c2");
        engine.add_indicator(dom);

        let mut hash = ThreatIndicator::new(
            "IND-003",
            IndicatorKind::FileHashSha256,
            "deadbeef0123456789abcdef",
            95,
        );
        hash.actor = Some("APT28".into());
        hash.malware_family = Some("SOFACY".into());
        engine.add_indicator(hash);

        engine.graph.add_edge("IND-001", "IND-002", "resolves_to");
        engine.graph.add_edge("IND-002", "IND-003", "hosts");

        engine
    }
}

impl Default for ThreatCorrelation {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mock() -> ThreatCorrelation {
        ThreatCorrelation::mock()
    }

    // ThreatIndicator
    #[test]
    fn test_indicator_new() {
        let i = ThreatIndicator::new("I1", IndicatorKind::Ipv4, "1.2.3.4", 80);
        assert_eq!(i.id, "I1");
        assert_eq!(i.confidence, 80);
    }
    #[test]
    fn test_indicator_confidence_cap() {
        let i = ThreatIndicator::new("I1", IndicatorKind::Ipv4, "1.2.3.4", 200);
        assert_eq!(i.confidence, 100);
    }
    #[test]
    fn test_indicator_tag_and_enrich() {
        let mut i = ThreatIndicator::new("I1", IndicatorKind::Domain, "evil.com", 80);
        i.tag("c2");
        i.enrich("asn", "AS12345");
        assert!(i.tags.contains(&"c2".to_string()));
        assert_eq!(i.enrichments.get("asn"), Some(&"AS12345".to_string()));
    }
    #[test]
    fn test_indicator_kind_display() {
        assert_eq!(IndicatorKind::Ipv4.to_string(), "ipv4");
    }
    #[test]
    fn test_tlp_display() {
        assert_eq!(TlpLevel::Amber.to_string(), "TLP:AMBER");
    }
    #[test]
    fn test_indicator_is_confident() {
        let i = ThreatIndicator::new("I1", IndicatorKind::Ipv4, "1.2.3.4", 80);
        assert!(i.is_confident(70));
        assert!(!i.is_confident(90));
    }

    // CorrelationRule
    #[test]
    fn test_rule_matches() {
        let rule = CorrelationRule::new(
            "R1",
            "test",
            vec![IndicatorKind::Ipv4, IndicatorKind::Domain],
            2,
            "c2",
        );
        let inds = vec![
            ThreatIndicator::new("I1", IndicatorKind::Ipv4, "1.2.3.4", 80),
            ThreatIndicator::new("I2", IndicatorKind::Domain, "evil.com", 80),
        ];
        assert!(rule.matches(&inds));
    }
    #[test]
    fn test_rule_no_match_too_few() {
        let rule = CorrelationRule::new("R1", "test", vec![IndicatorKind::Ipv4], 3, "tag");
        let inds = vec![ThreatIndicator::new(
            "I1",
            IndicatorKind::Ipv4,
            "1.2.3.4",
            80,
        )];
        assert!(!rule.matches(&inds));
    }
    #[test]
    fn test_rule_no_match_missing_kind() {
        let rule = CorrelationRule::new(
            "R1",
            "test",
            vec![IndicatorKind::Ipv4, IndicatorKind::Domain],
            1,
            "tag",
        );
        let inds = vec![ThreatIndicator::new(
            "I1",
            IndicatorKind::Ipv4,
            "1.2.3.4",
            80,
        )];
        assert!(!rule.matches(&inds));
    }

    // ThreatGraph
    #[test]
    fn test_graph_add_node() {
        let mut g = ThreatGraph::new();
        g.add_node(ThreatIndicator::new(
            "I1",
            IndicatorKind::Ipv4,
            "1.2.3.4",
            80,
        ));
        assert_eq!(g.node_count(), 1);
    }
    #[test]
    fn test_graph_add_edge() {
        let mut g = ThreatGraph::new();
        g.add_node(ThreatIndicator::new(
            "I1",
            IndicatorKind::Ipv4,
            "1.2.3.4",
            80,
        ));
        g.add_node(ThreatIndicator::new(
            "I2",
            IndicatorKind::Domain,
            "evil.com",
            80,
        ));
        g.add_edge("I1", "I2", "resolves_to");
        assert_eq!(g.edge_count(), 1);
    }
    #[test]
    fn test_graph_neighbors() {
        let m = mock();
        let neighbors = m.graph.neighbors("IND-001");
        assert!(!neighbors.is_empty());
    }
    #[test]
    fn test_graph_by_kind() {
        let m = mock();
        assert!(!m.graph.by_kind(&IndicatorKind::Ipv4).is_empty());
    }
    #[test]
    fn test_graph_connected_components() {
        let m = mock();
        let comps = m.graph.connected_components();
        assert!(!comps.is_empty());
    }

    // CampaignDetector
    #[test]
    fn test_campaign_by_actor() {
        let detector = CampaignDetector::new(2);
        let mut i1 = ThreatIndicator::new("I1", IndicatorKind::Ipv4, "1.2.3.4", 80);
        i1.actor = Some("APT28".into());
        let mut i2 = ThreatIndicator::new("I2", IndicatorKind::Domain, "evil.com", 85);
        i2.actor = Some("APT28".into());
        let campaigns = detector.cluster_by_actor(&[i1, i2]);
        assert_eq!(campaigns.len(), 1);
        assert_eq!(campaigns[0].attributed_actor, Some("APT28".into()));
    }
    #[test]
    fn test_campaign_too_few_inds() {
        let detector = CampaignDetector::new(3);
        let mut i1 = ThreatIndicator::new("I1", IndicatorKind::Ipv4, "1.2.3.4", 80);
        i1.actor = Some("APT28".into());
        let campaigns = detector.cluster_by_actor(&[i1]);
        assert!(campaigns.is_empty());
    }
    #[test]
    fn test_campaign_by_tag() {
        let detector = CampaignDetector::new(2);
        let mut i1 = ThreatIndicator::new("I1", IndicatorKind::Ipv4, "1.2.3.4", 80);
        i1.campaign = Some("OP_DARKSIDE".into());
        let mut i2 = ThreatIndicator::new("I2", IndicatorKind::Domain, "evil.com", 80);
        i2.campaign = Some("OP_DARKSIDE".into());
        let campaigns = detector.cluster_by_campaign_tag(&[i1, i2]);
        assert_eq!(campaigns.len(), 1);
    }

    // ActorAttribution
    #[test]
    fn test_attribution_matches() {
        let attr = ActorAttribution::new();
        let mut i = ThreatIndicator::new("I1", IndicatorKind::Ipv4, "185.220.101.1", 90);
        i.tag("sofacy");
        let known = vec![("APT28", &["185.220.101", "sofacy"][..])];
        let results = attr.attribute(&[i], &known);
        assert!(!results.is_empty());
    }
    #[test]
    fn test_attribution_no_match() {
        let attr = ActorAttribution::new();
        let i = ThreatIndicator::new("I1", IndicatorKind::Ipv4, "1.2.3.4", 80);
        let known = vec![("APT28", &["185.220"][..])];
        let results = attr.attribute(&[i], &known);
        assert!(results.is_empty());
    }
    #[test]
    fn test_attribution_is_high_confidence() {
        let r = AttributionResult {
            actor_name: "APT28".into(),
            confidence: 80,
            evidence_count: 5,
            technique_overlap: vec![],
            infrastructure_overlap: vec![],
            rationale: "test".into(),
        };
        assert!(r.is_high_confidence());
    }

    // ThreatScore
    #[test]
    fn test_score_empty() {
        let s = ThreatScore::new();
        let result = s.compute(&[]);
        assert_eq!(result.verdict, ThreatVerdict::Clean);
    }
    #[test]
    fn test_score_hash_indicators() {
        let s = ThreatScore::new();
        let inds: Vec<_> = (0..5)
            .map(|i| {
                ThreatIndicator::new(
                    format!("I{i}"),
                    IndicatorKind::FileHashSha256,
                    format!("hash{i}"),
                    90,
                )
            })
            .collect();
        let result = s.compute(&inds);
        assert!(result.normalized > 0);
    }
    #[test]
    fn test_score_verdict_display() {
        assert_eq!(ThreatVerdict::Confirmed.to_string(), "confirmed");
    }
    #[test]
    fn test_score_single_indicator() {
        let i = ThreatIndicator::new("I1", IndicatorKind::Ipv4, "1.2.3.4", 80);
        let score = ThreatScore::score_indicator(&i);
        assert!(score > 0);
    }

    // ThreatCorrelation
    #[test]
    fn test_correlate_mock() {
        let m = mock();
        let r = m.correlate();
        assert!(r.graph_nodes >= 3);
        assert!(r.graph_edges >= 2);
    }
    #[test]
    fn test_correlate_finds_rules() {
        let m = mock();
        let r = m.correlate();
        assert!(!r.matched_rules.is_empty());
    }
    #[test]
    fn test_correlate_finds_campaigns() {
        let m = mock();
        let r = m.correlate();
        assert!(!r.campaigns.is_empty());
    }
    #[test]
    fn test_correlate_score_positive() {
        let m = mock();
        let r = m.correlate();
        assert!(r.score.normalized > 0);
    }
    #[test]
    fn test_correlate_components() {
        let m = mock();
        let r = m.correlate();
        assert!(r.components >= 1);
    }
    #[test]
    fn test_indicator_kind_other() {
        assert_eq!(IndicatorKind::Other("x".into()).to_string(), "x");
    }
    #[test]
    fn test_tlp_red_display() {
        assert_eq!(TlpLevel::Red.to_string(), "TLP:RED");
    }
    #[test]
    fn test_threat_graph_by_tag() {
        let m = mock();
        let tagged = m.graph.by_tag("c2");
        assert!(!tagged.is_empty());
    }
    #[test]
    fn test_correlation_new_has_rules() {
        let c = ThreatCorrelation::new();
        assert!(!c.rules.is_empty());
    }
}
