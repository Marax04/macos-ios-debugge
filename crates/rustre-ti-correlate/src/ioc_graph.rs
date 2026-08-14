//! IOC relationship graph: file→domain→IP→actor nodes; petgraph-based;
//! community detection; shortest path between indicators.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use petgraph::algo::astar;
use petgraph::graph::{Graph, NodeIndex, EdgeIndex};
use petgraph::visit::EdgeRef;

use rustre_core::errors::{CoreError, Result as CoreResult};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Node types
// ---------------------------------------------------------------------------

/// The kind of an IOC node in the graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeKind {
    /// A malware sample identified by SHA-256.
    File,
    /// A domain name (e.g. "evil.com").
    Domain,
    /// An IP address (v4 or v6).
    Ip,
    /// A URL (including path).
    Url,
    /// A threat actor (group name or code name).
    Actor,
    /// A malware family name.
    Family,
    /// A YARA rule name.
    YaraRule,
    /// A MITRE ATT&CK technique.
    Technique,
    /// A mutex / named object.
    Mutex,
    /// A registry key.
    RegistryKey,
    /// A named pipe.
    Pipe,
    /// A campaign identifier.
    Campaign,
    /// A certificate thumbprint.
    Certificate,
    /// An autonomous system number.
    Asn,
}

impl fmt::Display for NodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            NodeKind::File => "file",
            NodeKind::Domain => "domain",
            NodeKind::Ip => "ip",
            NodeKind::Url => "url",
            NodeKind::Actor => "actor",
            NodeKind::Family => "family",
            NodeKind::YaraRule => "yara",
            NodeKind::Technique => "technique",
            NodeKind::Mutex => "mutex",
            NodeKind::RegistryKey => "registry",
            NodeKind::Pipe => "pipe",
            NodeKind::Campaign => "campaign",
            NodeKind::Certificate => "certificate",
            NodeKind::Asn => "asn",
        };
        write!(f, "{s}")
    }
}

/// A single node in the IOC graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocNode {
    pub kind: NodeKind,
    /// Primary identifier (SHA-256 for files, domain string, IP string, etc.).
    pub value: String,
    /// Human-readable label.
    pub label: Option<String>,
    /// Confidence of this node (0.0..=1.0).
    pub confidence: f64,
    /// Tags attached to the node.
    pub tags: Vec<String>,
    /// First observed timestamp.
    pub first_seen: Option<u64>,
    /// Last observed timestamp.
    pub last_seen: Option<u64>,
}

impl IocNode {
    pub fn new(kind: NodeKind, value: impl Into<String>) -> Self {
        IocNode {
            kind,
            value: value.into(),
            label: None,
            confidence: 1.0,
            tags: vec![],
            first_seen: None,
            last_seen: None,
        }
    }

    pub fn with_confidence(mut self, c: f64) -> Self { self.confidence = c; self }
    pub fn with_label(mut self, l: impl Into<String>) -> Self { self.label = Some(l.into()); self }

    pub fn display_name(&self) -> &str {
        self.label.as_deref().unwrap_or(&self.value)
    }
}

// ---------------------------------------------------------------------------
// Edge types
// ---------------------------------------------------------------------------

/// The kind of a relationship between two IOC nodes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    /// File resolves / contacts a domain.
    ContactsDomain,
    /// Domain resolves to an IP.
    ResolvesTo,
    /// File contacts an IP directly.
    ContactsIp,
    /// File drops another file.
    Drops,
    /// File was attributed to an actor.
    AttributedTo,
    /// Actor operates a domain.
    OperatesDomain,
    /// Actor uses a family.
    UsesFamiliy,
    /// File belongs to a family.
    BelongsToFamily,
    /// File matches a YARA rule.
    MatchesYara,
    /// File uses a MITRE technique.
    UsesTechnique,
    /// File is part of a campaign.
    PartOfCampaign,
    /// Actor is linked to a campaign.
    LinkedToCampaign,
    /// IP belongs to an ASN.
    BelongsToAsn,
    /// Domain uses a certificate.
    UsesCertificate,
    /// Generic "related to" link.
    RelatedTo,
    /// Similarity edge with a score weight.
    SimilarTo,
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            EdgeKind::ContactsDomain => "contacts_domain",
            EdgeKind::ResolvesTo => "resolves_to",
            EdgeKind::ContactsIp => "contacts_ip",
            EdgeKind::Drops => "drops",
            EdgeKind::AttributedTo => "attributed_to",
            EdgeKind::OperatesDomain => "operates_domain",
            EdgeKind::UsesFamiliy => "uses_family",
            EdgeKind::BelongsToFamily => "belongs_to_family",
            EdgeKind::MatchesYara => "matches_yara",
            EdgeKind::UsesTechnique => "uses_technique",
            EdgeKind::PartOfCampaign => "part_of_campaign",
            EdgeKind::LinkedToCampaign => "linked_to_campaign",
            EdgeKind::BelongsToAsn => "belongs_to_asn",
            EdgeKind::UsesCertificate => "uses_certificate",
            EdgeKind::RelatedTo => "related_to",
            EdgeKind::SimilarTo => "similar_to",
        };
        write!(f, "{s}")
    }
}

/// An edge in the IOC graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocEdge {
    pub kind: EdgeKind,
    /// Confidence of this relationship (0.0..=1.0).
    pub confidence: f64,
    /// Source of evidence (e.g. "sandbox", "passive_dns", "manual").
    pub source: String,
    /// Timestamp when the link was observed.
    pub observed_at: Option<u64>,
}

impl IocEdge {
    pub fn new(kind: EdgeKind) -> Self {
        IocEdge { kind, confidence: 1.0, source: String::new(), observed_at: None }
    }
    pub fn with_confidence(mut self, c: f64) -> Self { self.confidence = c; self }
    pub fn with_source(mut self, s: impl Into<String>) -> Self { self.source = s.into(); self }
    /// Edge weight for path-finding: lower confidence = higher cost.
    pub fn weight(&self) -> f64 { 1.0 - self.confidence + 0.01 }
}

// ---------------------------------------------------------------------------
// IOC graph
// ---------------------------------------------------------------------------

/// Petgraph-backed directed IOC relationship graph.
pub struct IocGraph {
    /// The underlying directed graph.
    inner: Graph<IocNode, IocEdge>,
    /// Map from (kind, value) → NodeIndex for O(1) lookup.
    node_map: HashMap<(String, String), NodeIndex>,
}

impl IocGraph {
    pub fn new() -> Self {
        IocGraph {
            inner: Graph::new(),
            node_map: HashMap::new(),
        }
    }

    fn node_key(kind: &NodeKind, value: &str) -> (String, String) {
        (kind.to_string(), value.to_ascii_lowercase())
    }

    /// Get or create a node; returns its NodeIndex.
    pub fn get_or_create_node(&mut self, node: IocNode) -> NodeIndex {
        let key = Self::node_key(&node.kind, &node.value);
        if let Some(&idx) = self.node_map.get(&key) {
            return idx;
        }
        let idx = self.inner.add_node(node);
        self.node_map.insert(key, idx);
        idx
    }

    /// Get a node index by kind and value.
    pub fn find_node(&self, kind: &NodeKind, value: &str) -> Option<NodeIndex> {
        self.node_map.get(&Self::node_key(kind, value)).copied()
    }

    /// Like [`find_node`] but returns a [`CoreError::Internal`] when no
    /// matching node exists, giving callers structured context (node kind and
    /// value) without an unwrap.
    pub fn find_node_or_err(&self, kind: &NodeKind, value: &str) -> CoreResult<NodeIndex> {
        self.find_node(kind, value).ok_or_else(|| {
            CoreError::Internal { message: format!("IocGraph: no {kind} node with value '{value}'") }
        })
    }

    /// Get node data.
    pub fn node(&self, idx: NodeIndex) -> Option<&IocNode> {
        self.inner.node_weight(idx)
    }

    /// Get node data (mutable).
    pub fn node_mut(&mut self, idx: NodeIndex) -> Option<&mut IocNode> {
        self.inner.node_weight_mut(idx)
    }

    /// Add a directed edge between two nodes.
    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex, edge: IocEdge) -> EdgeIndex {
        self.inner.add_edge(from, to, edge)
    }

    /// Add an edge by node value (creating nodes if needed).
    pub fn link(
        &mut self,
        from_kind: NodeKind, from_value: &str,
        to_kind: NodeKind, to_value: &str,
        edge: IocEdge,
    ) -> EdgeIndex {
        let from = self.get_or_create_node(IocNode::new(from_kind, from_value));
        let to = self.get_or_create_node(IocNode::new(to_kind, to_value));
        self.inner.add_edge(from, to, edge)
    }

    /// Number of nodes.
    pub fn node_count(&self) -> usize { self.inner.node_count() }

    /// Number of edges.
    pub fn edge_count(&self) -> usize { self.inner.edge_count() }

    /// Neighbours (outgoing) of a node.
    pub fn neighbors_out(&self, idx: NodeIndex) -> Vec<NodeIndex> {
        self.inner.neighbors(idx).collect()
    }

    /// Neighbours (incoming) of a node.
    pub fn neighbors_in(&self, idx: NodeIndex) -> Vec<NodeIndex> {
        self.inner.neighbors_directed(idx, petgraph::Direction::Incoming).collect()
    }

    /// All nodes of a given kind.
    pub fn nodes_of_kind(&self, kind: &NodeKind) -> Vec<NodeIndex> {
        self.inner.node_indices()
            .filter(|&i| self.inner[i].kind == *kind)
            .collect()
    }

    /// Find shortest path between two nodes using A* (cost = edge weight).
    /// Returns (total_cost, path_node_indices) or None.
    pub fn shortest_path(&self, src: NodeIndex, dst: NodeIndex) -> Option<(f64, Vec<NodeIndex>)> {
        astar(
            &self.inner,
            src,
            |goal| goal == dst,
            |e| e.weight().weight(),
            |_| 0.0,
        ).map(|(cost, path)| (cost, path))
    }

    /// Return all paths from src to dst up to max_depth using BFS.
    pub fn all_paths(&self, src: NodeIndex, dst: NodeIndex, max_depth: usize) -> Vec<Vec<NodeIndex>> {
        let mut results: Vec<Vec<NodeIndex>> = Vec::new();
        let mut queue: VecDeque<Vec<NodeIndex>> = VecDeque::new();
        queue.push_back(vec![src]);

        while let Some(path) = queue.pop_front() {
            let last = *path.last().unwrap();
            if last == dst && path.len() > 1 {
                results.push(path.clone());
                continue;
            }
            if path.len() > max_depth { continue; }
            // Avoid cycles.
            let visited: HashSet<NodeIndex> = path.iter().copied().collect();
            for neighbor in self.inner.neighbors(last) {
                if !visited.contains(&neighbor) {
                    let mut new_path = path.clone();
                    new_path.push(neighbor);
                    queue.push_back(new_path);
                }
            }
        }
        results
    }

    /// BFS distance between two nodes (unweighted hop count).
    pub fn bfs_distance(&self, src: NodeIndex, dst: NodeIndex) -> Option<usize> {
        let mut visited: HashSet<NodeIndex> = HashSet::new();
        let mut queue: VecDeque<(NodeIndex, usize)> = VecDeque::new();
        queue.push_back((src, 0));
        visited.insert(src);
        while let Some((node, depth)) = queue.pop_front() {
            if node == dst { return Some(depth); }
            for neighbor in self.inner.neighbors(node) {
                if !visited.contains(&neighbor) {
                    visited.insert(neighbor);
                    queue.push_back((neighbor, depth + 1));
                }
            }
        }
        None
    }

    /// Return all nodes reachable from src within max_hops.
    pub fn reachable(&self, src: NodeIndex, max_hops: usize) -> HashSet<NodeIndex> {
        let mut visited = HashSet::new();
        let mut queue: VecDeque<(NodeIndex, usize)> = VecDeque::new();
        queue.push_back((src, 0));
        visited.insert(src);
        while let Some((node, depth)) = queue.pop_front() {
            if depth >= max_hops { continue; }
            for neighbor in self.inner.neighbors(node) {
                if !visited.contains(&neighbor) {
                    visited.insert(neighbor);
                    queue.push_back((neighbor, depth + 1));
                }
            }
        }
        visited
    }
}

impl Default for IocGraph {
    fn default() -> Self { IocGraph::new() }
}

// ---------------------------------------------------------------------------
// Community detection (Label Propagation)
// ---------------------------------------------------------------------------

/// A community (cluster) of nodes in the IOC graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Community {
    pub id: usize,
    pub members: Vec<NodeIndex>,
    /// Whether this community is dominated by a particular node kind.
    pub dominant_kind: Option<NodeKind>,
    pub size: usize,
}

/// Run label propagation community detection on the undirected projection of the IOC graph.
/// Returns community assignments as a map from NodeIndex → community_id.
pub fn label_propagation(graph: &IocGraph, max_iter: usize) -> HashMap<NodeIndex, usize> {
    let n = graph.inner.node_count();
    if n == 0 { return HashMap::new(); }

    // Assign initial labels.
    let indices: Vec<NodeIndex> = graph.inner.node_indices().collect();
    let mut labels: HashMap<NodeIndex, usize> = indices.iter().enumerate().map(|(i, &node)| (node, i)).collect();

    for _ in 0..max_iter {
        let mut changed = false;
        // Randomised order (deterministic: just use node index order).
        for &node in &indices {
            let mut counts: HashMap<usize, usize> = HashMap::new();
            // Count labels of all neighbors (undirected: in + out).
            for neighbor in graph.inner.neighbors(node) {
                *counts.entry(*labels.get(&neighbor).unwrap_or(&0)).or_insert(0) += 1;
            }
            for neighbor in graph.inner.neighbors_directed(node, petgraph::Direction::Incoming) {
                *counts.entry(*labels.get(&neighbor).unwrap_or(&0)).or_insert(0) += 1;
            }
            if let Some((&best_label, _)) = counts.iter().max_by_key(|&(_, &c)| c) {
                let current = *labels.get(&node).unwrap();
                if best_label != current {
                    labels.insert(node, best_label);
                    changed = true;
                }
            }
        }
        if !changed { break; }
    }
    labels
}

/// Build community structs from a label map.
pub fn build_communities(graph: &IocGraph, labels: &HashMap<NodeIndex, usize>) -> Vec<Community> {
    let mut groups: HashMap<usize, Vec<NodeIndex>> = HashMap::new();
    for (&node, &label) in labels {
        groups.entry(label).or_default().push(node);
    }

    let mut communities: Vec<Community> = groups.into_iter().map(|(id, members)| {
        // Find dominant kind.
        let mut kind_counts: HashMap<String, usize> = HashMap::new();
        for &m in &members {
            if let Some(node) = graph.inner.node_weight(m) {
                *kind_counts.entry(node.kind.to_string()).or_insert(0) += 1;
            }
        }
        let dominant_kind_str = kind_counts.into_iter().max_by_key(|(_, c)| *c).map(|(k, _)| k);
        let dominant_kind = dominant_kind_str.and_then(|s| match s.as_str() {
            "file" => Some(NodeKind::File),
            "domain" => Some(NodeKind::Domain),
            "ip" => Some(NodeKind::Ip),
            "actor" => Some(NodeKind::Actor),
            "family" => Some(NodeKind::Family),
            "campaign" => Some(NodeKind::Campaign),
            _ => None,
        });
        let size = members.len();
        Community { id, members, dominant_kind, size }
    }).collect();

    communities.sort_by(|a, b| b.size.cmp(&a.size));
    communities
}

// ---------------------------------------------------------------------------
// Graph statistics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStats {
    pub node_count: usize,
    pub edge_count: usize,
    pub node_count_by_kind: HashMap<String, usize>,
    pub edge_count_by_kind: HashMap<String, usize>,
    pub avg_degree: f64,
    pub max_degree: usize,
    pub connected_components: usize,
}

pub fn graph_stats(graph: &IocGraph) -> GraphStats {
    let mut kind_counts: HashMap<String, usize> = HashMap::new();
    let mut edge_kind_counts: HashMap<String, usize> = HashMap::new();
    let mut max_degree = 0usize;
    let mut total_degree = 0usize;

    for idx in graph.inner.node_indices() {
        if let Some(node) = graph.inner.node_weight(idx) {
            *kind_counts.entry(node.kind.to_string()).or_insert(0) += 1;
        }
        let degree = graph.inner.neighbors(idx).count()
            + graph.inner.neighbors_directed(idx, petgraph::Direction::Incoming).count();
        total_degree += degree;
        if degree > max_degree { max_degree = degree; }
    }

    for edge in graph.inner.edge_references() {
        *edge_kind_counts.entry(edge.weight().kind.to_string()).or_insert(0) += 1;
    }

    let n = graph.inner.node_count();
    let avg_degree = if n > 0 { total_degree as f64 / n as f64 } else { 0.0 };

    // Connected components via BFS.
    let mut visited: HashSet<NodeIndex> = HashSet::new();
    let mut components = 0usize;
    for start in graph.inner.node_indices() {
        if visited.contains(&start) { continue; }
        components += 1;
        let reachable = graph.reachable(start, usize::MAX);
        visited.extend(reachable);
    }

    GraphStats {
        node_count: graph.inner.node_count(),
        edge_count: graph.inner.edge_count(),
        node_count_by_kind: kind_counts,
        edge_count_by_kind: edge_kind_counts,
        avg_degree,
        max_degree,
        connected_components: components,
    }
}

// ---------------------------------------------------------------------------
// Export to DOT format
// ---------------------------------------------------------------------------

pub fn to_dot(graph: &IocGraph) -> String {
    let mut out = String::from("digraph ioc_graph {\n  rankdir=LR;\n  node [shape=box];\n");
    for idx in graph.inner.node_indices() {
        if let Some(node) = graph.inner.node_weight(idx) {
            let label = node.display_name().replace('"', "\\\"");
            let color = match node.kind {
                NodeKind::File => "lightblue",
                NodeKind::Domain => "lightyellow",
                NodeKind::Ip => "lightgreen",
                NodeKind::Actor => "salmon",
                NodeKind::Family => "orchid",
                NodeKind::Campaign => "gold",
                _ => "white",
            };
            out.push_str(&format!(
                "  n{} [label=\"{} [{}]\" style=filled fillcolor={}];\n",
                idx.index(), label, node.kind, color
            ));
        }
    }
    for edge in graph.inner.edge_references() {
        out.push_str(&format!(
            "  n{} -> n{} [label=\"{}\" weight={:.2}];\n",
            edge.source().index(),
            edge.target().index(),
            edge.weight().kind,
            edge.weight().confidence,
        ));
    }
    out.push_str("}\n");
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_graph() -> IocGraph {
        let mut g = IocGraph::new();
        g.link(NodeKind::File, "abc123", NodeKind::Domain, "evil.com",
            IocEdge::new(EdgeKind::ContactsDomain).with_confidence(0.9));
        g.link(NodeKind::Domain, "evil.com", NodeKind::Ip, "1.2.3.4",
            IocEdge::new(EdgeKind::ResolvesTo).with_confidence(1.0));
        g.link(NodeKind::File, "abc123", NodeKind::Actor, "APT99",
            IocEdge::new(EdgeKind::AttributedTo).with_confidence(0.7));
        g
    }

    #[test]
    fn test_node_creation() {
        let mut g = IocGraph::new();
        let n1 = g.get_or_create_node(IocNode::new(NodeKind::File, "sha256_abc"));
        let n2 = g.get_or_create_node(IocNode::new(NodeKind::File, "sha256_abc"));
        assert_eq!(n1, n2, "same file should return same node");
        assert_eq!(g.node_count(), 1);
    }

    #[test]
    fn test_shortest_path() {
        let g = sample_graph();
        let file = g.find_node(&NodeKind::File, "abc123").unwrap();
        let ip = g.find_node(&NodeKind::Ip, "1.2.3.4").unwrap();
        let result = g.shortest_path(file, ip);
        assert!(result.is_some(), "should find a path file→domain→ip");
        let (_, path) = result.unwrap();
        assert_eq!(path.len(), 3, "path should have 3 nodes");
    }

    #[test]
    fn test_bfs_distance() {
        let g = sample_graph();
        let file = g.find_node(&NodeKind::File, "abc123").unwrap();
        let ip = g.find_node(&NodeKind::Ip, "1.2.3.4").unwrap();
        assert_eq!(g.bfs_distance(file, ip), Some(2));
    }

    #[test]
    fn test_community_detection() {
        let g = sample_graph();
        let labels = label_propagation(&g, 10);
        assert_eq!(labels.len(), g.node_count());
        let communities = build_communities(&g, &labels);
        assert!(!communities.is_empty());
    }

    #[test]
    fn test_graph_stats() {
        let g = sample_graph();
        let stats = graph_stats(&g);
        assert_eq!(stats.node_count, 4);
        assert_eq!(stats.edge_count, 3);
        assert!(stats.connected_components >= 1);
    }

    #[test]
    fn test_to_dot_valid() {
        let g = sample_graph();
        let dot = to_dot(&g);
        assert!(dot.contains("digraph ioc_graph"));
        assert!(dot.contains("evil.com"));
        assert!(dot.contains("APT99"));
    }

    #[test]
    fn test_reachable() {
        let g = sample_graph();
        let file = g.find_node(&NodeKind::File, "abc123").unwrap();
        let reachable = g.reachable(file, 2);
        // Should reach file itself + domain + ip + actor.
        assert!(reachable.len() >= 3);
    }
}
