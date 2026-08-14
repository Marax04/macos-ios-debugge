// misp_correlation.rs — Correlate analysis findings with MISP threat intelligence
//
// Provides: CorrelationResult, MispMatch, AttributionHypothesis, CorrelationGraph
// Searches MISP for matching IOCs, finds related events/attributes/objects,
// computes threat actor attribution confidence, and builds a full correlation graph.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;
use serde::{Deserialize, Serialize};

// ── IOC types ────────────────────────────────────────────────────────────────

/// Canonical IOC type understood by the correlator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IocKind {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Ipv4,
    Ipv6,
    Domain,
    Url,
    Email,
    Filename,
    RegistryKey,
    MutexName,
    PdbPath,
    Imphash,
    Ssdeep,
    Tlsh,
    Other(String),
}

impl fmt::Display for IocKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(s) => write!(f, "other:{s}"),
            _ => write!(f, "{self:?}"),
        }
    }
}

/// A single IOC value with its kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    pub kind: IocKind,
    pub value: String,
    /// Confidence that this IOC is valid (0.0–1.0).
    pub confidence: f32,
}

impl PartialEq for Ioc {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.value == other.value
            && self.confidence.to_bits() == other.confidence.to_bits()
    }
}

impl Eq for Ioc {}

impl std::hash::Hash for Ioc {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.kind.hash(state);
        self.value.hash(state);
        self.confidence.to_bits().hash(state);
    }
}

impl Ioc {
    pub fn new(kind: IocKind, value: impl Into<String>) -> Self {
        Self { kind, value: value.into(), confidence: 1.0 }
    }
    #[must_use]
    pub const fn with_confidence(mut self, c: f32) -> Self {
        // NaN-safe clamp: `f32::clamp` propagates NaN and `is_nan()` is not
        // available in a const fn. A NaN confidence would lose every comparison
        // it takes part in, dropping the correlation out of every ranking.
        self.confidence = if c >= 1.0 {
            1.0
        } else if c > 0.0 {
            c
        } else {
            0.0
        };
        self
    }
}

// ── MISP data model (lightweight stubs for correlation) ──────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispAttributeRef {
    pub id: String,
    pub event_id: String,
    pub r#type: String,
    pub value: String,
    pub category: String,
    pub to_ids: bool,
    pub timestamp: u64,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispEventRef {
    pub id: String,
    pub uuid: String,
    pub info: String,
    pub threat_level: u8,
    pub analysis: u8,
    pub timestamp: u64,
    pub orgc_name: String,
    pub tags: Vec<String>,
    pub attribute_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispObjectRef {
    pub id: String,
    pub event_id: String,
    pub name: String,
    pub meta_category: String,
    pub template_uuid: String,
}

// ── Match result ─────────────────────────────────────────────────────────────

/// How strong a MISP match is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MatchStrength {
    Weak,
    Moderate,
    Strong,
    Exact,
}

impl fmt::Display for MatchStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A single match between a local IOC and a MISP attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispMatch {
    pub local_ioc: Ioc,
    pub misp_attribute: MispAttributeRef,
    pub strength: MatchStrength,
    /// Similarity score 0.0–1.0 (1.0 = exact value match).
    pub similarity: f32,
    pub match_method: String,
}

impl MispMatch {
    fn exact(ioc: Ioc, attr: MispAttributeRef) -> Self {
        Self {
            local_ioc: ioc,
            misp_attribute: attr,
            strength: MatchStrength::Exact,
            similarity: 1.0,
            match_method: "exact".into(),
        }
    }

    fn fuzzy(ioc: Ioc, attr: MispAttributeRef, sim: f32, method: impl Into<String>) -> Self {
        let strength = if sim >= 0.9 {
            MatchStrength::Strong
        } else if sim >= 0.7 {
            MatchStrength::Moderate
        } else {
            MatchStrength::Weak
        };
        Self {
            local_ioc: ioc,
            misp_attribute: attr,
            strength,
            similarity: sim,
            match_method: method.into(),
        }
    }
}

// ── Correlation result ────────────────────────────────────────────────────────

/// The full result of correlating one set of IOCs against MISP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub matches: Vec<MispMatch>,
    /// Unique event IDs referenced by the matches.
    pub matched_event_ids: HashSet<String>,
    /// Unique attribute IDs referenced.
    pub matched_attribute_ids: HashSet<String>,
    /// Overall correlation score 0.0–1.0.
    pub score: f32,
    /// Total IOCs submitted.
    pub total_iocs: usize,
    /// IOCs that produced at least one match.
    pub matched_iocs: usize,
    /// Events fetched and inspected.
    pub events_inspected: Vec<MispEventRef>,
    /// Objects referenced by matched attributes.
    pub related_objects: Vec<MispObjectRef>,
    pub attribution: Vec<AttributionHypothesis>,
}

impl CorrelationResult {
    fn empty(total: usize) -> Self {
        Self {
            matches: Vec::new(),
            matched_event_ids: HashSet::new(),
            matched_attribute_ids: HashSet::new(),
            score: 0.0,
            total_iocs: total,
            matched_iocs: 0,
            events_inspected: Vec::new(),
            related_objects: Vec::new(),
            attribution: Vec::new(),
        }
    }

    fn compute_score(&mut self) {
        if self.total_iocs == 0 {
            self.score = 0.0;
            return;
        }
        let exact = self.matches.iter().filter(|m| m.strength == MatchStrength::Exact).count() as f32;
        let strong = self.matches.iter().filter(|m| m.strength == MatchStrength::Strong).count() as f32;
        let moderate = self.matches.iter().filter(|m| m.strength == MatchStrength::Moderate).count() as f32;
        let weak = self.matches.iter().filter(|m| m.strength == MatchStrength::Weak).count() as f32;
        let weighted = weak.mul_add(0.2, moderate.mul_add(0.5, strong.mul_add(0.8, exact * 1.0)));
        self.score = (weighted / self.total_iocs as f32).min(1.0);
    }

    /// Highest-confidence attribution hypothesis, if any.
    #[must_use]
    pub fn top_attribution(&self) -> Option<&AttributionHypothesis> {
        self.attribution.iter().max_by(|a, b| {
            a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// All matches for a specific event ID.
    #[must_use]
    pub fn matches_for_event(&self, event_id: &str) -> Vec<&MispMatch> {
        self.matches.iter().filter(|m| m.misp_attribute.event_id == event_id).collect()
    }
}

// ── Attribution ───────────────────────────────────────────────────────────────

/// A threat actor attribution hypothesis derived from correlated MISP data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionHypothesis {
    pub actor_name: String,
    pub actor_uuid: Option<String>,
    /// Galaxy cluster UUIDs supporting this hypothesis.
    pub supporting_clusters: Vec<String>,
    /// Event IDs that reference this actor.
    pub supporting_events: Vec<String>,
    /// Confidence 0.0–1.0.
    pub confidence: f32,
    pub rationale: String,
    pub mitre_techniques: Vec<String>,
    pub mitre_groups: Vec<String>,
}

impl AttributionHypothesis {
    fn new(actor: impl Into<String>, conf: f32) -> Self {
        Self {
            actor_name: actor.into(),
            actor_uuid: None,
            supporting_clusters: Vec::new(),
            supporting_events: Vec::new(),
            confidence: conf.clamp(0.0, 1.0),
            rationale: String::new(),
            mitre_techniques: Vec::new(),
            mitre_groups: Vec::new(),
        }
    }

    /// Increase confidence by merging additional evidence.
    pub fn merge_evidence(&mut self, events: &[String], clusters: &[String], boost: f32) {
        for e in events {
            if !self.supporting_events.contains(e) {
                self.supporting_events.push(e.clone());
            }
        }
        for c in clusters {
            if !self.supporting_clusters.contains(c) {
                self.supporting_clusters.push(c.clone());
            }
        }
        self.confidence = (self.confidence + boost).min(1.0);
    }
}

// ── Correlation graph ─────────────────────────────────────────────────────────

/// Node kinds in the correlation graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeKind {
    LocalIoc,
    MispAttribute,
    MispEvent,
    MispObject,
    ThreatActor,
    MitreGroup,
    MitreTechnique,
}

/// A node in the correlation graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub kind: NodeKind,
    pub weight: f32,
    pub metadata: BTreeMap<String, String>,
}

impl GraphNode {
    fn new(id: impl Into<String>, label: impl Into<String>, kind: NodeKind) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            kind,
            weight: 1.0,
            metadata: BTreeMap::new(),
        }
    }
}

/// An edge in the correlation graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub src: String,
    pub dst: String,
    pub label: String,
    pub weight: f32,
}

impl GraphEdge {
    fn new(src: impl Into<String>, dst: impl Into<String>, label: impl Into<String>, w: f32) -> Self {
        Self { src: src.into(), dst: dst.into(), label: label.into(), weight: w }
    }
}

/// Full correlation graph built from a `CorrelationResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationGraph {
    pub nodes: HashMap<String, GraphNode>,
    pub edges: Vec<GraphEdge>,
}

impl CorrelationGraph {
    #[must_use]
    pub fn new() -> Self {
        Self { nodes: HashMap::new(), edges: Vec::new() }
    }

    fn add_node(&mut self, node: GraphNode) {
        self.nodes.entry(node.id.clone()).or_insert(node);
    }

    fn add_edge(&mut self, edge: GraphEdge) {
        // Deduplicate edges by (src, dst, label).
        let exists = self.edges.iter().any(|e| e.src == edge.src && e.dst == edge.dst && e.label == edge.label);
        if !exists {
            self.edges.push(edge);
        }
    }

    /// Build a graph from a completed `CorrelationResult`.
    #[must_use]
    pub fn from_result(result: &CorrelationResult) -> Self {
        let mut g = Self::new();

        for m in &result.matches {
            // Local IOC node.
            let ioc_id = format!("ioc:{}:{}", m.local_ioc.kind, m.local_ioc.value);
            g.add_node(GraphNode::new(&ioc_id, &m.local_ioc.value, NodeKind::LocalIoc));

            // MISP attribute node.
            let attr_id = format!("attr:{}", m.misp_attribute.id);
            g.add_node(GraphNode::new(&attr_id, &m.misp_attribute.value, NodeKind::MispAttribute));

            // MISP event node.
            let ev_id = format!("event:{}", m.misp_attribute.event_id);

            g.add_edge(GraphEdge::new(&ioc_id, &attr_id, "matches", m.similarity));
            g.add_edge(GraphEdge::new(&attr_id, &ev_id, "member_of", 1.0));
        }

        for ev in &result.events_inspected {
            let ev_id = format!("event:{}", ev.id);
            let mut node = GraphNode::new(&ev_id, &ev.info, NodeKind::MispEvent);
            node.metadata.insert("threat_level".into(), ev.threat_level.to_string());
            node.metadata.insert("org".into(), ev.orgc_name.clone());
            g.add_node(node);
        }

        for obj in &result.related_objects {
            let obj_id = format!("obj:{}", obj.id);
            let node = GraphNode::new(&obj_id, &obj.name, NodeKind::MispObject);
            g.add_node(node);
            let ev_id = format!("event:{}", obj.event_id);
            g.add_edge(GraphEdge::new(&ev_id, &obj_id, "contains", 1.0));
        }

        for hyp in &result.attribution {
            let actor_id = format!("actor:{}", hyp.actor_name);
            let mut actor_node = GraphNode::new(&actor_id, &hyp.actor_name, NodeKind::ThreatActor);
            actor_node.weight = hyp.confidence;
            g.add_node(actor_node);

            for ev_id_raw in &hyp.supporting_events {
                let ev_id = format!("event:{ev_id_raw}");
                g.add_edge(GraphEdge::new(&ev_id, &actor_id, "attributed_to", hyp.confidence));
            }

            for technique in &hyp.mitre_techniques {
                let t_id = format!("technique:{technique}");
                g.add_node(GraphNode::new(&t_id, technique, NodeKind::MitreTechnique));
                g.add_edge(GraphEdge::new(&actor_id, &t_id, "uses", 1.0));
            }

            for group in &hyp.mitre_groups {
                let g_id = format!("group:{group}");
                g.add_node(GraphNode::new(&g_id, group, NodeKind::MitreGroup));
                g.add_edge(GraphEdge::new(&actor_id, &g_id, "alias", 1.0));
            }
        }

        g
    }

    /// BFS from a given node id, returns reachable node ids up to `depth` hops.
    #[must_use]
    pub fn reachable_from(&self, start: &str, depth: usize) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((start.to_string(), 0usize));
        while let Some((node, d)) = queue.pop_front() {
            if !visited.insert(node.clone()) {
                continue;
            }
            if d >= depth {
                continue;
            }
            for edge in &self.edges {
                if edge.src == node {
                    queue.push_back((edge.dst.clone(), d + 1));
                }
            }
        }
        visited
    }

    /// Export to DOT format.
    #[must_use]
    pub fn to_dot(&self) -> String {
        let mut out = String::from("digraph correlation {\n  rankdir=LR;\n");
        for node in self.nodes.values() {
            let shape = match node.kind {
                NodeKind::LocalIoc => "diamond",
                NodeKind::MispAttribute => "box",
                NodeKind::MispEvent => "ellipse",
                NodeKind::MispObject => "hexagon",
                NodeKind::ThreatActor => "doubleoctagon",
                NodeKind::MitreGroup => "octagon",
                NodeKind::MitreTechnique => "parallelogram",
            };
            let label = node.label.replace('"', "\\\"");
            out.push_str(&format!("  \"{}\" [label=\"{}\" shape={}];\n", node.id, label, shape));
        }
        for edge in &self.edges {
            out.push_str(&format!(
                "  \"{}\" -> \"{}\" [label=\"{}\"];\n",
                edge.src, edge.dst, edge.label
            ));
        }
        out.push_str("}\n");
        out
    }

    #[must_use]
    pub fn node_count(&self) -> usize { self.nodes.len() }
    #[must_use]
    pub const fn edge_count(&self) -> usize { self.edges.len() }
}

impl Default for CorrelationGraph {
    fn default() -> Self { Self::new() }
}

// ── Correlator configuration ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatorConfig {
    /// Minimum similarity for fuzzy hash matches (0.0–1.0).
    pub fuzzy_min_similarity: f32,
    /// Whether to perform domain substring matching.
    pub domain_substring_match: bool,
    /// Whether to resolve PTR records for IP matching (offline: disabled).
    pub resolve_ptr: bool,
    /// Maximum events to fetch for each matched attribute.
    pub max_events_per_match: usize,
    /// Minimum confidence for an attribution hypothesis to be included.
    pub min_attribution_confidence: f32,
    /// Whether to build the full correlation graph.
    pub build_graph: bool,
    /// Tags to treat as high-TLP (will not generate attribution from them).
    pub high_tlp_tags: HashSet<String>,
}

impl Default for CorrelatorConfig {
    fn default() -> Self {
        Self {
            fuzzy_min_similarity: 0.7,
            domain_substring_match: false,
            resolve_ptr: false,
            max_events_per_match: 5,
            min_attribution_confidence: 0.3,
            build_graph: true,
            high_tlp_tags: ["tlp:red", "tlp:amber+strict"].iter().map(std::string::ToString::to_string).collect(),
        }
    }
}

// ── In-memory MISP index (used as a stand-in for a real MISP API) ─────────────

/// A simple in-memory index for offline/unit-test correlation.
#[derive(Debug, Default)]
pub struct MispIndex {
    attributes: Vec<MispAttributeRef>,
    events: HashMap<String, MispEventRef>,
    objects: Vec<MispObjectRef>,
    /// `actor_name` → (galaxy cluster UUIDs, MITRE groups, MITRE techniques)
    actor_clusters: HashMap<String, (Vec<String>, Vec<String>, Vec<String>)>,
}

impl MispIndex {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    pub fn add_attribute(&mut self, attr: MispAttributeRef) {
        self.attributes.push(attr);
    }

    pub fn add_event(&mut self, ev: MispEventRef) {
        self.events.insert(ev.id.clone(), ev);
    }

    pub fn add_object(&mut self, obj: MispObjectRef) {
        self.objects.push(obj);
    }

    pub fn register_actor(
        &mut self,
        name: impl Into<String>,
        clusters: Vec<String>,
        groups: Vec<String>,
        techniques: Vec<String>,
    ) {
        self.actor_clusters.insert(name.into(), (clusters, groups, techniques));
    }

    /// Look up attributes whose value exactly matches `value`.
    #[must_use]
    pub fn find_exact(&self, value: &str) -> Vec<&MispAttributeRef> {
        self.attributes.iter().filter(|a| a.value == value).collect()
    }

    /// Look up attributes whose value contains `substr` (case-insensitive).
    #[must_use]
    pub fn find_substring(&self, substr: &str) -> Vec<&MispAttributeRef> {
        let lower = substr.to_lowercase();
        self.attributes.iter().filter(|a| a.value.to_lowercase().contains(&lower)).collect()
    }

    #[must_use]
    pub fn get_event(&self, id: &str) -> Option<&MispEventRef> {
        self.events.get(id)
    }

    #[must_use]
    pub fn objects_for_event(&self, event_id: &str) -> Vec<&MispObjectRef> {
        self.objects.iter().filter(|o| o.event_id == event_id).collect()
    }
}

// ── Fuzzy hash helpers ────────────────────────────────────────────────────────

/// Very lightweight edit-distance ratio between two hex/ASCII strings.
/// Used for TLSH/ssdeep approximate matching in the absence of external crates.
fn simple_similarity(a: &str, b: &str) -> f32 {
    if a == b {
        return 1.0;
    }
    let la = a.len();
    let lb = b.len();
    if la == 0 && lb == 0 {
        return 1.0;
    }
    if la == 0 || lb == 0 {
        return 0.0;
    }
    // Count common bytes (not true edit distance but sufficient for scoring).
    let common = a.bytes().zip(b.bytes()).filter(|(x, y)| x == y).count();
    let max_len = la.max(lb) as f32;
    common as f32 / max_len
}

// ── Main correlator ───────────────────────────────────────────────────────────

pub struct MispCorrelator {
    config: CorrelatorConfig,
}

impl MispCorrelator {
    #[must_use]
    pub fn new() -> Self {
        Self { config: CorrelatorConfig::default() }
    }

    #[must_use]
    pub const fn with_config(config: CorrelatorConfig) -> Self {
        Self { config }
    }

    /// Correlate `iocs` against `index`, returning a full `CorrelationResult`.
    #[must_use]
    pub fn correlate(&self, iocs: &[Ioc], index: &MispIndex) -> CorrelationResult {
        let mut result = CorrelationResult::empty(iocs.len());
        let mut matched_ioc_set: HashSet<String> = HashSet::new();

        for ioc in iocs {
            let matches = self.find_matches(ioc, index);
            for m in matches {
                let ioc_key = format!("{}:{}", ioc.kind, ioc.value);
                matched_ioc_set.insert(ioc_key);
                result.matched_event_ids.insert(m.misp_attribute.event_id.clone());
                result.matched_attribute_ids.insert(m.misp_attribute.id.clone());
                result.matches.push(m);
            }
        }

        result.matched_iocs = matched_ioc_set.len();

        // Fetch events for all matched event IDs (up to max_events_per_match per IOC).
        let event_ids: Vec<String> = result.matched_event_ids.iter().cloned().collect();
        for eid in event_ids.iter().take(self.config.max_events_per_match * iocs.len().max(1)) {
            if let Some(ev) = index.get_event(eid) {
                if !result.events_inspected.iter().any(|e| e.id == ev.id) {
                    result.events_inspected.push(ev.clone());
                }
                for obj in index.objects_for_event(eid) {
                    if !result.related_objects.iter().any(|o| o.id == obj.id) {
                        result.related_objects.push(obj.clone());
                    }
                }
            }
        }

        // Build attribution hypotheses.
        result.attribution = self.build_attribution(&result, index);

        result.compute_score();
        result
    }

    fn find_matches(&self, ioc: &Ioc, index: &MispIndex) -> Vec<MispMatch> {
        let mut out = Vec::new();

        // 1. Exact match.
        for attr in index.find_exact(&ioc.value) {
            out.push(MispMatch::exact(ioc.clone(), attr.clone()));
        }

        if !out.is_empty() {
            return out; // Exact match found; skip fuzzy.
        }

        // 2. Fuzzy / substring matching depending on IOC kind.
        match &ioc.kind {
            IocKind::Ssdeep | IocKind::Tlsh => {
                // Use simple_similarity for fuzzy hashes.
                for attr in &index.attributes {
                    let sim = simple_similarity(&ioc.value, &attr.value);
                    if sim >= self.config.fuzzy_min_similarity {
                        out.push(MispMatch::fuzzy(ioc.clone(), attr.clone(), sim, "fuzzy_hash"));
                    }
                }
            }
            IocKind::Domain if self.config.domain_substring_match => {
                for attr in index.find_substring(&ioc.value) {
                    let sim = if attr.value == ioc.value { 1.0 } else { 0.75 };
                    out.push(MispMatch::fuzzy(ioc.clone(), attr.clone(), sim, "domain_substring"));
                }
            }
            _ => {}
        }

        out
    }

    fn build_attribution(&self, result: &CorrelationResult, index: &MispIndex) -> Vec<AttributionHypothesis> {
        // Count how many matched events reference each known actor.
        let mut actor_evidence: HashMap<String, (Vec<String>, Vec<String>)> = HashMap::new();

        for ev in &result.events_inspected {
            // Skip high-TLP events.
            if ev.tags.iter().any(|t| self.config.high_tlp_tags.contains(t)) {
                continue;
            }
            for actor in index.actor_clusters.keys() {
                // Heuristic: actor name appears in event info or tags.
                let actor_lower = actor.to_lowercase();
                let mentioned = ev.info.to_lowercase().contains(&actor_lower)
                    || ev.tags.iter().any(|t| t.to_lowercase().contains(&actor_lower));
                if mentioned {
                    let entry = actor_evidence.entry(actor.clone()).or_default();
                    if !entry.0.contains(&ev.id) {
                        entry.0.push(ev.id.clone());
                    }
                    if let Some((clusters, _, _)) = index.actor_clusters.get(actor) {
                        for c in clusters {
                            if !entry.1.contains(c) {
                                entry.1.push(c.clone());
                            }
                        }
                    }
                }
            }
        }

        let mut hypotheses = Vec::new();
        for (actor, (events, clusters)) in actor_evidence {
            let base_conf = (events.len() as f32 * 0.25).min(0.95);
            let cluster_boost = (clusters.len() as f32 * 0.05).min(0.2);
            let confidence = (base_conf + cluster_boost).min(1.0);

            if confidence < self.config.min_attribution_confidence {
                continue;
            }

            let (_, groups, techniques) = index.actor_clusters
                .get(&actor).cloned()
                .unwrap_or_default();

            let mut hyp = AttributionHypothesis::new(&actor, confidence);
            hyp.supporting_events = events;
            hyp.supporting_clusters = clusters;
            hyp.mitre_groups = groups;
            hyp.mitre_techniques = techniques;
            hyp.rationale = format!(
                "Actor '{}' was mentioned in {} matched MISP event(s).",
                actor,
                hyp.supporting_events.len()
            );

            hypotheses.push(hyp);
        }

        hypotheses.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        hypotheses
    }

    /// Convenience: correlate and build the graph in one call.
    #[must_use]
    pub fn correlate_with_graph(
        &self,
        iocs: &[Ioc],
        index: &MispIndex,
    ) -> (CorrelationResult, Option<CorrelationGraph>) {
        let result = self.correlate(iocs, index);
        let graph = if self.config.build_graph {
            Some(CorrelationGraph::from_result(&result))
        } else {
            None
        };
        (result, graph)
    }
}

impl Default for MispCorrelator {
    fn default() -> Self { Self::new() }
}

// ── Utility: extract IOCs from raw text ──────────────────────────────────────

/// Naively extract potential IOCs from a free-form text blob.
#[must_use]
pub fn extract_iocs_from_text(text: &str) -> Vec<Ioc> {
    let mut out = Vec::new();
    for token in text.split_whitespace() {
        let clean = token.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != ':' && c != '/' && c != '@');
        if clean.is_empty() {
            continue;
        }
        let kind = classify_token(clean);
        if kind != IocKind::Other(String::new()) {
            out.push(Ioc::new(kind, clean));
        }
    }
    out
}

fn classify_token(t: &str) -> IocKind {
    // MD5
    if t.len() == 32 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        return IocKind::Md5;
    }
    // SHA1
    if t.len() == 40 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        return IocKind::Sha1;
    }
    // SHA256
    if t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        return IocKind::Sha256;
    }
    // SHA512
    if t.len() == 128 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        return IocKind::Sha512;
    }
    // IPv4
    {
        let parts: Vec<&str> = t.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            return IocKind::Ipv4;
        }
    }
    // URL
    if t.starts_with("http://") || t.starts_with("https://") || t.starts_with("ftp://") {
        return IocKind::Url;
    }
    // Email
    if t.contains('@') && t.contains('.') {
        return IocKind::Email;
    }
    // Registry key
    if t.starts_with("HKEY_") || t.starts_with("HKLM\\") || t.starts_with("HKCU\\") {
        return IocKind::RegistryKey;
    }
    // Domain heuristic: contains dot, no spaces, no slashes
    if t.contains('.') && !t.contains('/') && !t.contains(' ') && t.len() > 3 {
        return IocKind::Domain;
    }
    IocKind::Other(String::new())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_attr(id: &str, event_id: &str, typ: &str, value: &str) -> MispAttributeRef {
        MispAttributeRef {
            id: id.into(),
            event_id: event_id.into(),
            r#type: typ.into(),
            value: value.into(),
            category: "Network activity".into(),
            to_ids: true,
            timestamp: 0,
            tags: vec![],
        }
    }

    fn make_event(id: &str, info: &str) -> MispEventRef {
        MispEventRef {
            id: id.into(),
            uuid: format!("uuid-{}", id),
            info: info.into(),
            threat_level: 1,
            analysis: 2,
            timestamp: 1_000_000,
            orgc_name: "TestOrg".into(),
            tags: vec!["tlp:white".into()],
            attribute_count: 10,
        }
    }

    fn build_test_index() -> MispIndex {
        let mut idx = MispIndex::new();
        idx.add_attribute(make_attr("1", "100", "ip-dst", "1.2.3.4"));
        idx.add_attribute(make_attr("2", "100", "md5", "d41d8cd98f00b204e9800998ecf8427e"));
        idx.add_attribute(make_attr("3", "101", "domain", "evil.example.com"));
        idx.add_event(make_event("100", "APT28 campaign"));
        idx.add_event(make_event("101", "Lazarus phishing"));
        idx.register_actor(
            "APT28",
            vec!["cluster-apt28".into()],
            vec!["G0007".into()],
            vec!["T1059".into(), "T1027".into()],
        );
        idx
    }

    #[test]
    fn test_exact_ip_match() {
        let idx = build_test_index();
        let correlator = MispCorrelator::new();
        let iocs = vec![Ioc::new(IocKind::Ipv4, "1.2.3.4")];
        let result = correlator.correlate(&iocs, &idx);
        assert_eq!(result.matched_iocs, 1);
        assert!(!result.matches.is_empty());
        assert_eq!(result.matches[0].strength, MatchStrength::Exact);
    }

    #[test]
    fn test_exact_md5_match() {
        let idx = build_test_index();
        let correlator = MispCorrelator::new();
        let iocs = vec![Ioc::new(IocKind::Md5, "d41d8cd98f00b204e9800998ecf8427e")];
        let result = correlator.correlate(&iocs, &idx);
        assert_eq!(result.matched_iocs, 1);
    }

    #[test]
    fn test_no_match() {
        let idx = build_test_index();
        let correlator = MispCorrelator::new();
        let iocs = vec![Ioc::new(IocKind::Ipv4, "9.9.9.9")];
        let result = correlator.correlate(&iocs, &idx);
        assert_eq!(result.matched_iocs, 0);
        assert_eq!(result.score, 0.0);
    }

    #[test]
    fn test_score_increases_with_matches() {
        let idx = build_test_index();
        let correlator = MispCorrelator::new();
        let iocs = vec![
            Ioc::new(IocKind::Ipv4, "1.2.3.4"),
            Ioc::new(IocKind::Md5, "d41d8cd98f00b204e9800998ecf8427e"),
        ];
        let result = correlator.correlate(&iocs, &idx);
        assert!(result.score > 0.5);
    }

    #[test]
    fn test_events_inspected() {
        let idx = build_test_index();
        let correlator = MispCorrelator::new();
        let iocs = vec![Ioc::new(IocKind::Ipv4, "1.2.3.4")];
        let result = correlator.correlate(&iocs, &idx);
        assert!(result.events_inspected.iter().any(|e| e.id == "100"));
    }

    #[test]
    fn test_attribution_apt28() {
        let idx = build_test_index();
        let correlator = MispCorrelator::new();
        let iocs = vec![Ioc::new(IocKind::Ipv4, "1.2.3.4")];
        let result = correlator.correlate(&iocs, &idx);
        let top = result.top_attribution();
        assert!(top.is_some());
        let hyp = top.unwrap();
        assert_eq!(hyp.actor_name, "APT28");
        assert!(!hyp.mitre_techniques.is_empty());
    }

    #[test]
    fn test_correlation_graph_built() {
        let idx = build_test_index();
        let correlator = MispCorrelator::new();
        let iocs = vec![Ioc::new(IocKind::Ipv4, "1.2.3.4")];
        let (result, graph) = correlator.correlate_with_graph(&iocs, &idx);
        let g = graph.unwrap();
        assert!(g.node_count() > 0);
        assert!(g.edge_count() > 0);
        let _ = result.score;
    }

    #[test]
    fn test_graph_dot_export() {
        let idx = build_test_index();
        let correlator = MispCorrelator::new();
        let iocs = vec![Ioc::new(IocKind::Ipv4, "1.2.3.4")];
        let (result, graph) = correlator.correlate_with_graph(&iocs, &idx);
        let g = graph.unwrap();
        let dot = g.to_dot();
        assert!(dot.contains("digraph"));
        let _ = result;
    }

    #[test]
    fn test_graph_reachable_from() {
        let idx = build_test_index();
        let correlator = MispCorrelator::new();
        let iocs = vec![Ioc::new(IocKind::Ipv4, "1.2.3.4")];
        let (result, graph) = correlator.correlate_with_graph(&iocs, &idx);
        let g = graph.unwrap();
        let ioc_id = "ioc:Ipv4:1.2.3.4";
        let reachable = g.reachable_from(ioc_id, 3);
        assert!(!reachable.is_empty());
        let _ = result;
    }

    #[test]
    fn test_matches_for_event() {
        let idx = build_test_index();
        let correlator = MispCorrelator::new();
        let iocs = vec![Ioc::new(IocKind::Ipv4, "1.2.3.4")];
        let result = correlator.correlate(&iocs, &idx);
        let ev_matches = result.matches_for_event("100");
        assert!(!ev_matches.is_empty());
    }

    #[test]
    fn test_empty_ioc_list() {
        let idx = build_test_index();
        let correlator = MispCorrelator::new();
        let result = correlator.correlate(&[], &idx);
        assert_eq!(result.total_iocs, 0);
        assert_eq!(result.score, 0.0);
    }

    #[test]
    fn test_fuzzy_hash_matching() {
        let mut idx = MispIndex::new();
        idx.add_attribute(make_attr("10", "200", "ssdeep", "3:ABCDEF:XYZ"));
        let correlator = MispCorrelator::with_config(CorrelatorConfig {
            fuzzy_min_similarity: 0.1,
            ..Default::default()
        });
        let iocs = vec![Ioc::new(IocKind::Ssdeep, "3:ABCDEF:XYZ")];
        let result = correlator.correlate(&iocs, &idx);
        assert!(!result.matches.is_empty());
    }

    #[test]
    fn test_extract_iocs_from_text() {
        let text = "Malware IP: 192.168.1.1 hash: d41d8cd98f00b204e9800998ecf8427e domain: bad.example.com";
        let iocs = extract_iocs_from_text(text);
        assert!(iocs.iter().any(|i| i.kind == IocKind::Ipv4));
        assert!(iocs.iter().any(|i| i.kind == IocKind::Md5));
        assert!(iocs.iter().any(|i| i.kind == IocKind::Domain));
    }

    #[test]
    fn test_classify_token_sha256() {
        let hash = "a".repeat(64);
        let kind = classify_token(&hash);
        assert_eq!(kind, IocKind::Sha256);
    }

    #[test]
    fn test_classify_token_url() {
        let kind = classify_token("https://evil.example.com/payload.exe");
        assert_eq!(kind, IocKind::Url);
    }

    #[test]
    fn test_classify_token_email() {
        let kind = classify_token("attacker@evil.example.com");
        assert_eq!(kind, IocKind::Email);
    }

    #[test]
    fn test_attribution_hypothesis_merge() {
        let mut hyp = AttributionHypothesis::new("APT99", 0.4);
        hyp.merge_evidence(&["ev1".into(), "ev2".into()], &["cluster-x".into()], 0.2);
        assert_eq!(hyp.supporting_events.len(), 2);
        assert_eq!(hyp.supporting_clusters.len(), 1);
        assert!((hyp.confidence - 0.6).abs() < 1e-5);
    }

    #[test]
    fn test_ioc_confidence_clamp() {
        let ioc = Ioc::new(IocKind::Ipv4, "1.1.1.1").with_confidence(1.5);
        assert_eq!(ioc.confidence, 1.0);
        let ioc2 = Ioc::new(IocKind::Ipv4, "2.2.2.2").with_confidence(-0.5);
        assert_eq!(ioc2.confidence, 0.0);
    }

    #[test]
    fn test_build_graph_disabled() {
        let idx = build_test_index();
        let correlator = MispCorrelator::with_config(CorrelatorConfig {
            build_graph: false,
            ..Default::default()
        });
        let iocs = vec![Ioc::new(IocKind::Ipv4, "1.2.3.4")];
        let (_, graph) = correlator.correlate_with_graph(&iocs, &idx);
        assert!(graph.is_none());
    }

    #[test]
    fn test_domain_display() {
        let ioc = Ioc::new(IocKind::Domain, "evil.com");
        assert_eq!(format!("{}", ioc.kind), "Domain");
    }

    #[test]
    fn test_match_strength_ordering() {
        assert!(MatchStrength::Exact > MatchStrength::Strong);
        assert!(MatchStrength::Strong > MatchStrength::Moderate);
        assert!(MatchStrength::Moderate > MatchStrength::Weak);
    }
}
