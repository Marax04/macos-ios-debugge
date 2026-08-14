//! IoC knowledge graph correlator.
//!
//! Builds a directed graph where every node is an observable entity
//! (IP, domain, hash, URL, actor, malware family, campaign) and every edge
//! represents a relationship between them:
//!
//! * `ObservedWith` — two IoCs seen in the same sample or report.
//! * `ResolvesTo` — domain → IP (passive DNS).
//! * `CommunicatesWith` — sample hash → C2 IP/domain.
//! * `UsedBy` — IoC → threat actor or campaign.
//! * `Variant` — malware variant lineage.
//!
//! After construction the graph supports:
//! * Path queries between any two nodes.
//! * Pivot queries: all nodes reachable from a starting IoC.
//! * Community detection via label propagation.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

// ── Node types ────────────────────────────────────────────────────────────────

/// The kind of entity represented by a graph node.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeKind {
    Ip,
    Domain,
    Url,
    FileHash,
    Email,
    ThreatActor,
    MalwareFamily,
    Campaign,
    AutonomousSystem,
    DomainRegistrar,
}

impl std::fmt::Display for NodeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Ip => "IP",
            Self::Domain => "Domain",
            Self::Url => "URL",
            Self::FileHash => "Hash",
            Self::Email => "Email",
            Self::ThreatActor => "Actor",
            Self::MalwareFamily => "Malware",
            Self::Campaign => "Campaign",
            Self::AutonomousSystem => "AS",
            Self::DomainRegistrar => "Registrar",
        };
        write!(f, "{s}")
    }
}

/// A node in the IoC knowledge graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: u64,
    pub kind: NodeKind,
    /// Canonical value (e.g. lowercase domain, hex hash).
    pub value: String,
    /// Confidence that this node is malicious / relevant `[0.0, 1.0]`.
    pub confidence: f32,
    /// Community assigned by label propagation (-1 = unassigned).
    pub community: i64,
    /// Free-form attributes.
    pub attrs: HashMap<String, String>,
}

impl GraphNode {
    pub fn new(id: u64, kind: NodeKind, value: impl Into<String>, confidence: f32) -> Self {
        Self {
            id,
            kind,
            value: value.into(),
            confidence: confidence.clamp(0.0, 1.0),
            community: -1,
            attrs: HashMap::new(),
        }
    }
}

// ── Edge types ────────────────────────────────────────────────────────────────

/// Relationship between two nodes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    /// Two IoCs co-observed in the same sample or intelligence report.
    ObservedWith,
    /// Domain resolves to IP (passive DNS record).
    ResolvesTo,
    /// Malware sample communicates with a C2 server.
    CommunicatesWith,
    /// IoC attributed to / used by an actor or campaign.
    UsedBy,
    /// Malware variant / lineage relationship.
    Variant,
    /// IP belongs to an autonomous system.
    BelongsTo,
    /// Domain registered by a registrar.
    RegisteredWith,
}

/// A directed edge in the IoC knowledge graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub id: u64,
    pub source: u64,
    pub target: u64,
    pub kind: EdgeKind,
    /// Strength/weight of this relationship `[0.0, 1.0]`.
    pub weight: f32,
    /// UNIX timestamp when the relationship was observed.
    pub observed_at: u64,
    /// Source report or feed this edge came from.
    pub source_ref: Option<String>,
}

impl GraphEdge {
    pub fn new(id: u64, source: u64, target: u64, kind: EdgeKind, weight: f32) -> Self {
        Self {
            id,
            source,
            target,
            kind,
            weight: weight.clamp(0.0, 1.0),
            observed_at: 0,
            source_ref: None,
        }
    }
}

// ── Core graph ────────────────────────────────────────────────────────────────

/// The IoC knowledge graph.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IoCGraph {
    nodes: HashMap<u64, GraphNode>,
    edges: HashMap<u64, GraphEdge>,
    /// Index: value → node_id (for O(1) lookup by canonical value).
    value_index: HashMap<String, u64>,
    /// Adjacency list: node_id → Vec<edge_id> (out-edges).
    adjacency: HashMap<u64, Vec<u64>>,
    /// Reverse adjacency (in-edges).
    reverse_adjacency: HashMap<u64, Vec<u64>>,
    next_node_id: u64,
    next_edge_id: u64,
}

impl IoCGraph {
    pub fn new() -> Self {
        Self::default()
    }

    // ── Node management ───────────────────────────────────────────────────

    /// Add a node, returning its ID. If a node with the same `value` exists,
    /// update its confidence (take max) and return the existing ID.
    pub fn add_node(&mut self, kind: NodeKind, value: impl Into<String>, confidence: f32) -> u64 {
        let value = value.into();
        if let Some(&id) = self.value_index.get(&value) {
            // Update confidence
            if let Some(n) = self.nodes.get_mut(&id) {
                n.confidence = n.confidence.max(confidence);
            }
            return id;
        }
        let id = self.next_node_id;
        self.next_node_id += 1;
        let node = GraphNode::new(id, kind, value.clone(), confidence);
        self.value_index.insert(value, id);
        self.nodes.insert(id, node);
        self.adjacency.entry(id).or_default();
        self.reverse_adjacency.entry(id).or_default();
        id
    }

    pub fn get_node(&self, id: u64) -> Option<&GraphNode> {
        self.nodes.get(&id)
    }

    pub fn get_node_by_value(&self, value: &str) -> Option<&GraphNode> {
        self.value_index.get(value).and_then(|id| self.nodes.get(id))
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    // ── Edge management ───────────────────────────────────────────────────

    /// Add a directed edge. Returns the edge ID.
    pub fn add_edge(&mut self, source: u64, target: u64, kind: EdgeKind, weight: f32) -> u64 {
        let id = self.next_edge_id;
        self.next_edge_id += 1;
        let edge = GraphEdge::new(id, source, target, kind, weight);
        self.adjacency.entry(source).or_default().push(id);
        self.reverse_adjacency.entry(target).or_default().push(id);
        self.edges.insert(id, edge);
        id
    }

    pub fn get_edge(&self, id: u64) -> Option<&GraphEdge> {
        self.edges.get(&id)
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// All out-edges from a node.
    pub fn out_edges(&self, node_id: u64) -> Vec<&GraphEdge> {
        self.adjacency
            .get(&node_id)
            .map(|ids| ids.iter().filter_map(|eid| self.edges.get(eid)).collect())
            .unwrap_or_default()
    }

    /// All in-edges to a node.
    pub fn in_edges(&self, node_id: u64) -> Vec<&GraphEdge> {
        self.reverse_adjacency
            .get(&node_id)
            .map(|ids| ids.iter().filter_map(|eid| self.edges.get(eid)).collect())
            .unwrap_or_default()
    }

    // ── Pivot query ───────────────────────────────────────────────────────

    /// BFS pivot: return all nodes reachable from `start_value` within `max_hops`.
    /// Optionally filter by edge kind.
    pub fn pivot(
        &self,
        start_value: &str,
        max_hops: usize,
        edge_filter: Option<&[EdgeKind]>,
    ) -> Vec<PivotResult> {
        let start_id = match self.value_index.get(start_value) {
            Some(id) => *id,
            None => return vec![],
        };

        let mut visited: HashSet<u64> = HashSet::new();
        let mut queue: VecDeque<(u64, usize, Vec<u64>)> = VecDeque::new();
        let mut results: Vec<PivotResult> = Vec::new();

        visited.insert(start_id);
        queue.push_back((start_id, 0, vec![]));

        while let Some((node_id, depth, path)) = queue.pop_front() {
            if depth > 0 {
                if let Some(node) = self.nodes.get(&node_id) {
                    results.push(PivotResult {
                        node: node.clone(),
                        depth,
                        path_node_ids: path.clone(),
                    });
                }
            }
            if depth >= max_hops {
                continue;
            }
            for edge in self.out_edges(node_id) {
                if let Some(filter) = edge_filter {
                    if !filter.contains(&edge.kind) {
                        continue;
                    }
                }
                if !visited.contains(&edge.target) {
                    visited.insert(edge.target);
                    let mut new_path = path.clone();
                    new_path.push(node_id);
                    queue.push_back((edge.target, depth + 1, new_path));
                }
            }
        }
        results
    }

    // ── Path query ────────────────────────────────────────────────────────

    /// BFS shortest path between two values. Returns the list of node IDs
    /// (inclusive of source and target) or None if unreachable.
    pub fn shortest_path(&self, from_value: &str, to_value: &str) -> Option<Vec<u64>> {
        let from = *self.value_index.get(from_value)?;
        let to = *self.value_index.get(to_value)?;
        if from == to {
            return Some(vec![from]);
        }

        let mut visited: HashSet<u64> = HashSet::new();
        let mut queue: VecDeque<(u64, Vec<u64>)> = VecDeque::new();
        visited.insert(from);
        queue.push_back((from, vec![from]));

        while let Some((node, path)) = queue.pop_front() {
            for edge in self.out_edges(node) {
                if !visited.contains(&edge.target) {
                    let mut new_path = path.clone();
                    new_path.push(edge.target);
                    if edge.target == to {
                        return Some(new_path);
                    }
                    visited.insert(edge.target);
                    queue.push_back((edge.target, new_path));
                }
            }
        }
        None
    }

    // ── Community detection ───────────────────────────────────────────────

    /// Label propagation community detection (synchronous variant).
    /// Returns the number of communities found.
    pub fn detect_communities(&mut self, max_iterations: usize) -> usize {
        // Initialize: each node is its own community.
        // Cap at i64::MAX to avoid wrap-around for very large node IDs.
        for node in self.nodes.values_mut() {
            node.community = i64::try_from(node.id).unwrap_or(i64::MAX);
        }

        for _iter in 0..max_iterations {
            let mut changed = false;
            let node_ids: Vec<u64> = self.nodes.keys().copied().collect();

            for &nid in &node_ids {
                let neighbors = self.neighbor_communities(nid);
                if neighbors.is_empty() {
                    continue;
                }
                // Majority label among neighbors
                let mut counts: HashMap<i64, usize> = HashMap::new();
                for c in &neighbors {
                    *counts.entry(*c).or_insert(0) += 1;
                }
                let max_count = counts.values().copied().max().unwrap_or(0);
                let best_community = counts
                    .into_iter()
                    .filter(|(_, v)| *v == max_count)
                    .map(|(c, _)| c)
                    .min()
                    .unwrap();

                if let Some(node) = self.nodes.get_mut(&nid) {
                    if node.community != best_community {
                        node.community = best_community;
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }

        // Count distinct communities
        let communities: HashSet<i64> = self.nodes.values().map(|n| n.community).collect();
        communities.len()
    }

    fn neighbor_communities(&self, node_id: u64) -> Vec<i64> {
        let mut out = Vec::new();
        for edge in self.out_edges(node_id) {
            if let Some(n) = self.nodes.get(&edge.target) {
                out.push(n.community);
            }
        }
        for edge in self.in_edges(node_id) {
            if let Some(n) = self.nodes.get(&edge.source) {
                out.push(n.community);
            }
        }
        out
    }

    /// Get all nodes belonging to a community.
    pub fn community_members(&self, community: i64) -> Vec<&GraphNode> {
        self.nodes
            .values()
            .filter(|n| n.community == community)
            .collect()
    }

    /// Summary statistics for all communities.
    pub fn community_summary(&self) -> Vec<CommunitySummary> {
        let mut by_community: HashMap<i64, Vec<&GraphNode>> = HashMap::new();
        for node in self.nodes.values() {
            by_community.entry(node.community).or_default().push(node);
        }
        let mut summaries: Vec<CommunitySummary> = by_community
            .into_iter()
            .map(|(id, nodes)| {
                let avg_confidence =
                    nodes.iter().map(|n| n.confidence).sum::<f32>() / nodes.len() as f32;
                let kinds: HashSet<String> =
                    nodes.iter().map(|n| n.kind.to_string()).collect();
                CommunitySummary {
                    community_id: id,
                    size: nodes.len(),
                    avg_confidence,
                    node_kinds: kinds,
                }
            })
            .collect();
        summaries.sort_by(|a, b| b.size.cmp(&a.size));
        summaries
    }
}

// ── Result types ──────────────────────────────────────────────────────────────

/// A single node found during a pivot query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivotResult {
    pub node: GraphNode,
    /// Hop distance from the pivot origin.
    pub depth: usize,
    /// Node IDs on the path from origin to this node (not including this node).
    pub path_node_ids: Vec<u64>,
}

/// Summary statistics for a detected community.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunitySummary {
    pub community_id: i64,
    pub size: usize,
    pub avg_confidence: f32,
    pub node_kinds: HashSet<String>,
}

// ── Graph builder helper ──────────────────────────────────────────────────────

/// Convenience builder for constructing an [`IoCGraph`] from raw intelligence.
pub struct IoCGraphBuilder {
    graph: IoCGraph,
}

impl IoCGraphBuilder {
    pub fn new() -> Self {
        Self {
            graph: IoCGraph::new(),
        }
    }

    /// Add a passive DNS resolution edge: `domain` → `ip`.
    pub fn add_pdns(&mut self, domain: &str, ip: &str, weight: f32) {
        let d = self.graph.add_node(NodeKind::Domain, domain, 0.5);
        let i = self.graph.add_node(NodeKind::Ip, ip, 0.5);
        self.graph.add_edge(d, i, EdgeKind::ResolvesTo, weight);
    }

    /// Add a co-observation edge between two IoC values.
    pub fn add_co_observation(&mut self, value_a: &str, kind_a: NodeKind, value_b: &str, kind_b: NodeKind, weight: f32) {
        let a = self.graph.add_node(kind_a, value_a, 0.5);
        let b = self.graph.add_node(kind_b, value_b, 0.5);
        self.graph.add_edge(a, b, EdgeKind::ObservedWith, weight);
        self.graph.add_edge(b, a, EdgeKind::ObservedWith, weight); // undirected
    }

    /// Add a malware → C2 communication edge.
    pub fn add_c2_communication(&mut self, hash: &str, c2: &str, c2_kind: NodeKind, weight: f32) {
        let h = self.graph.add_node(NodeKind::FileHash, hash, 0.8);
        let c = self.graph.add_node(c2_kind, c2, 0.7);
        self.graph.add_edge(h, c, EdgeKind::CommunicatesWith, weight);
    }

    /// Attribute an IoC to an actor.
    pub fn add_attribution(&mut self, ioc_value: &str, ioc_kind: NodeKind, actor: &str, confidence: f32) {
        let i = self.graph.add_node(ioc_kind, ioc_value, confidence);
        let a = self.graph.add_node(NodeKind::ThreatActor, actor, 1.0);
        self.graph.add_edge(i, a, EdgeKind::UsedBy, confidence);
    }

    pub fn build(self) -> IoCGraph {
        self.graph
    }
}

impl Default for IoCGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_graph() -> IoCGraph {
        let mut b = IoCGraphBuilder::new();
        b.add_pdns("evil.com", "1.2.3.4", 0.9);
        b.add_pdns("evil.com", "5.6.7.8", 0.7);
        b.add_c2_communication("aabbcc00112233", "1.2.3.4", NodeKind::Ip, 0.95);
        b.add_attribution("1.2.3.4", NodeKind::Ip, "APT99", 0.8);
        b.build()
    }

    #[test]
    fn pivot_finds_related() {
        let g = sample_graph();
        let results = g.pivot("evil.com", 3, None);
        let values: Vec<&str> = results.iter().map(|r| r.node.value.as_str()).collect();
        assert!(values.contains(&"1.2.3.4"), "should find 1.2.3.4");
        assert!(values.contains(&"5.6.7.8"), "should find 5.6.7.8");
    }

    #[test]
    fn shortest_path() {
        let g = sample_graph();
        let path = g.shortest_path("evil.com", "APT99");
        assert!(path.is_some(), "path should exist");
        let p = path.unwrap();
        assert!(p.len() >= 2);
    }

    #[test]
    fn community_detection() {
        let mut g = sample_graph();
        let count = g.detect_communities(10);
        assert!(count >= 1, "at least one community: {count}");
    }

    #[test]
    fn dedup_node_by_value() {
        let mut g = IoCGraph::new();
        let id1 = g.add_node(NodeKind::Domain, "evil.com", 0.5);
        let id2 = g.add_node(NodeKind::Domain, "evil.com", 0.9);
        assert_eq!(id1, id2, "same value should return same node");
        assert_eq!(g.node_count(), 1);
        assert!(
            (g.get_node(id1).unwrap().confidence - 0.9).abs() < 1e-6,
            "confidence should be updated to max"
        );
    }

    #[test]
    fn no_path_between_disconnected() {
        let mut g = IoCGraph::new();
        g.add_node(NodeKind::Ip, "1.1.1.1", 0.5);
        g.add_node(NodeKind::Ip, "8.8.8.8", 0.5);
        assert!(g.shortest_path("1.1.1.1", "8.8.8.8").is_none());
    }
}
