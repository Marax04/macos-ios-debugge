//! `VirusTotal` Graph API — node/edge types, graph traversal, relationship expansion.
//!
//! The VT Graph API allows analysts to build graphs linking files, URLs, domains,
//! IP addresses, and threat actors via their known relationships. This module
//! provides strongly-typed representations and traversal helpers.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ─── Node types ───────────────────────────────────────────────────────────────

/// The kind of entity a graph node represents.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VtNodeKind {
    File,
    Url,
    Domain,
    IpAddress,
    Collection,
    ThreatActor,
    Signature,
    Mitreattack,
    Unknown(String),
}

impl fmt::Display for VtNodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File => write!(f, "file"),
            Self::Url => write!(f, "url"),
            Self::Domain => write!(f, "domain"),
            Self::IpAddress => write!(f, "ip_address"),
            Self::Collection => write!(f, "collection"),
            Self::ThreatActor => write!(f, "threat_actor"),
            Self::Signature => write!(f, "signature"),
            Self::Mitreattack => write!(f, "mitre_attack"),
            Self::Unknown(s) => write!(f, "{s}"),
        }
    }
}

impl VtNodeKind {
    #[must_use] 
    pub fn from_str(s: &str) -> Self {
        match s {
            "file" => Self::File,
            "url" => Self::Url,
            "domain" => Self::Domain,
            "ip_address" => Self::IpAddress,
            "collection" => Self::Collection,
            "threat_actor" => Self::ThreatActor,
            "signature" => Self::Signature,
            "mitre_attack" => Self::Mitreattack,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

/// Threat classification attached to a node.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VtThreatLabel {
    /// e.g. "trojan", "ransomware", "adware"
    pub category: Option<String>,
    /// e.g. "`WannaCry`", "Emotet"
    pub family: Option<String>,
    /// Platform such as "Win32", "JS", "PDF"
    pub platform: Option<String>,
    /// Full label string from VT
    pub full_label: Option<String>,
}

/// Attributes stored on a graph node.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VtNodeAttributes {
    /// Display name / filename / hostname
    pub name: Option<String>,
    /// SHA-256 hash (for file nodes)
    pub sha256: Option<String>,
    /// SHA-1 hash
    pub sha1: Option<String>,
    /// MD5 hash
    pub md5: Option<String>,
    /// File size in bytes
    pub size: Option<u64>,
    /// MIME type
    pub type_tag: Option<String>,
    /// First seen (UNIX timestamp)
    pub first_submission_date: Option<i64>,
    /// Last analysis date
    pub last_analysis_date: Option<i64>,
    /// Detection ratio: positives / total
    pub detection_ratio: Option<f32>,
    /// Reputation score (-100 … +100)
    pub reputation: Option<i32>,
    /// Threat label
    pub threat_label: Option<VtThreatLabel>,
    /// Country (for IP nodes)
    pub country: Option<String>,
    /// AS number (for IP nodes)
    pub asn: Option<u32>,
    /// AS owner
    pub as_owner: Option<String>,
    /// Registrar (for domain nodes)
    pub registrar: Option<String>,
    /// Creation date (domain/IP)
    pub creation_date: Option<i64>,
    /// Tags assigned by VT
    pub tags: Vec<String>,
    /// Additional arbitrary attributes
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// A node in the VT graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtGraphNode {
    /// Unique node identifier (typically the SHA-256, URL ID, or domain)
    pub id: String,
    /// Node kind
    pub kind: VtNodeKind,
    /// Node attributes
    pub attributes: VtNodeAttributes,
    /// Whether this is the root/pivot node in a traversal
    pub is_root: bool,
    /// Graph depth at which this node was discovered
    pub depth: u32,
}

impl VtGraphNode {
    pub fn new(id: impl Into<String>, kind: VtNodeKind) -> Self {
        Self {
            id: id.into(),
            kind,
            attributes: VtNodeAttributes::default(),
            is_root: false,
            depth: 0,
        }
    }

    #[must_use] 
    pub const fn with_root(mut self) -> Self {
        self.is_root = true;
        self
    }

    #[must_use] 
    pub const fn with_depth(mut self, depth: u32) -> Self {
        self.depth = depth;
        self
    }

    /// Returns true if the node has a positive detection ratio above the threshold.
    #[must_use] 
    pub fn is_malicious(&self, threshold: f32) -> bool {
        self.attributes
            .detection_ratio
            .is_some_and(|r| r >= threshold)
    }

    /// Returns the best available hash identifier.
    #[must_use] 
    pub fn hash_id(&self) -> Option<&str> {
        self.attributes
            .sha256
            .as_deref()
            .or(self.attributes.sha1.as_deref())
            .or(self.attributes.md5.as_deref())
    }
}

// ─── Edge types ───────────────────────────────────────────────────────────────

/// The semantic relationship an edge represents.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VtEdgeKind {
    /// File dropped by the source during execution
    DroppedFile,
    /// File contacted this domain
    ContactedDomain,
    /// File contacted this IP
    ContactedIp,
    /// File requested this URL
    ContactedUrl,
    /// File was bundled/packed inside source
    EmbeddedFile,
    /// File was served from domain/IP
    ServedFrom,
    /// File downloads this URL
    Downloads,
    /// Domain resolves to IP
    ResolvesTo,
    /// File uses this signature
    Signature,
    /// Attribution to threat actor
    AttributedTo,
    /// File was executed / spawned by source
    Executed,
    /// File contains this string/IOC
    Contains,
    /// Network relationship (generic)
    Network,
    /// Similarity edge (similar code/behavior)
    Similar,
    /// Graph-editor user link (custom)
    ManualLink(String),
}

impl fmt::Display for VtEdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DroppedFile => write!(f, "dropped_file"),
            Self::ContactedDomain => write!(f, "contacted_domain"),
            Self::ContactedIp => write!(f, "contacted_ip"),
            Self::ContactedUrl => write!(f, "contacted_url"),
            Self::EmbeddedFile => write!(f, "embedded_file"),
            Self::ServedFrom => write!(f, "served_from"),
            Self::Downloads => write!(f, "downloads"),
            Self::ResolvesTo => write!(f, "resolves_to"),
            Self::Signature => write!(f, "signature"),
            Self::AttributedTo => write!(f, "attributed_to"),
            Self::Executed => write!(f, "executed"),
            Self::Contains => write!(f, "contains"),
            Self::Network => write!(f, "network"),
            Self::Similar => write!(f, "similar"),
            Self::ManualLink(s) => write!(f, "manual:{s}"),
        }
    }
}

impl VtEdgeKind {
    #[must_use] 
    pub fn from_str(s: &str) -> Self {
        match s {
            "dropped_file" | "dropped_files" => Self::DroppedFile,
            "contacted_domain" | "contacted_domains" => Self::ContactedDomain,
            "contacted_ip" | "contacted_ips" => Self::ContactedIp,
            "contacted_url" | "contacted_urls" => Self::ContactedUrl,
            "embedded_file" | "embedded_files" => Self::EmbeddedFile,
            "served_from" => Self::ServedFrom,
            "downloads" => Self::Downloads,
            "resolves_to" | "resolutions" => Self::ResolvesTo,
            "signature" | "signatures" => Self::Signature,
            "attributed_to" => Self::AttributedTo,
            "executed" | "execution_parents" | "execution_children" => Self::Executed,
            "contains" => Self::Contains,
            "network" => Self::Network,
            "similar" | "similar_files" => Self::Similar,
            other => Self::ManualLink(other.to_owned()),
        }
    }
}

/// A directed edge in the VT graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtGraphEdge {
    /// Source node ID
    pub source: String,
    /// Target node ID
    pub target: String,
    /// Relationship kind
    pub kind: VtEdgeKind,
    /// Optional context (e.g., sandbox name, score)
    pub context: Option<String>,
    /// First seen timestamp for this relationship
    pub first_seen: Option<i64>,
    /// Last seen timestamp
    pub last_seen: Option<i64>,
}

impl VtGraphEdge {
    pub fn new(source: impl Into<String>, target: impl Into<String>, kind: VtEdgeKind) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
            kind,
            context: None,
            first_seen: None,
            last_seen: None,
        }
    }
}

// ─── Graph container ──────────────────────────────────────────────────────────

/// A named VT graph with nodes and edges.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VtGraph {
    /// Graph ID (from VT API)
    pub id: Option<String>,
    /// Human-readable name
    pub name: Option<String>,
    /// Description
    pub description: Option<String>,
    /// All nodes indexed by ID
    pub nodes: HashMap<String, VtGraphNode>,
    /// All edges
    pub edges: Vec<VtGraphEdge>,
    /// Graph creation timestamp
    pub created_at: Option<i64>,
    /// Last modified
    pub modified_at: Option<i64>,
    /// Whether the graph is public
    pub public: bool,
}

impl VtGraph {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Add a node, returning true if it was newly inserted.
    pub fn add_node(&mut self, node: VtGraphNode) -> bool {
        let id = node.id.clone();
        if self.nodes.contains_key(&id) {
            return false;
        }
        self.nodes.insert(id, node);
        true
    }

    /// Add an edge. Nodes must already exist.
    pub fn add_edge(&mut self, edge: VtGraphEdge) {
        self.edges.push(edge);
    }

    /// Returns all edges originating from the given node ID.
    pub fn edges_from(&self, node_id: &str) -> impl Iterator<Item = &VtGraphEdge> {
        self.edges.iter().filter(move |e| e.source == node_id)
    }

    /// Returns all edges targeting the given node ID.
    pub fn edges_to(&self, node_id: &str) -> impl Iterator<Item = &VtGraphEdge> {
        self.edges.iter().filter(move |e| e.target == node_id)
    }

    /// Returns the neighbours of a node (outgoing edge targets).
    #[must_use] 
    pub fn neighbours(&self, node_id: &str) -> Vec<&VtGraphNode> {
        self.edges_from(node_id)
            .filter_map(|e| self.nodes.get(&e.target))
            .collect()
    }

    /// Returns all nodes of a given kind.
    #[must_use] 
    pub fn nodes_of_kind(&self, kind: &VtNodeKind) -> Vec<&VtGraphNode> {
        self.nodes.values().filter(|n| &n.kind == kind).collect()
    }

    /// Count nodes by kind.
    #[must_use] 
    pub fn node_counts(&self) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for node in self.nodes.values() {
            *counts.entry(node.kind.to_string()).or_insert(0) += 1;
        }
        counts
    }

    /// Returns all malicious nodes (`detection_ratio` >= threshold).
    #[must_use] 
    pub fn malicious_nodes(&self, threshold: f32) -> Vec<&VtGraphNode> {
        self.nodes.values().filter(|n| n.is_malicious(threshold)).collect()
    }

    /// BFS traversal from a root node up to `max_depth`.
    /// Returns visited node IDs in BFS order.
    #[must_use] 
    pub fn bfs(&self, root: &str, max_depth: u32) -> Vec<String> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(String, u32)> = VecDeque::new();
        let mut result: Vec<String> = Vec::new();

        if !self.nodes.contains_key(root) {
            return result;
        }

        queue.push_back((root.to_owned(), 0));
        visited.insert(root.to_owned());

        while let Some((id, depth)) = queue.pop_front() {
            result.push(id.clone());
            if depth >= max_depth {
                continue;
            }
            for edge in self.edges_from(&id) {
                if !visited.contains(&edge.target) {
                    visited.insert(edge.target.clone());
                    queue.push_back((edge.target.clone(), depth + 1));
                }
            }
        }
        result
    }

    /// DFS traversal from a root node up to `max_depth`.
    #[must_use] 
    pub fn dfs(&self, root: &str, max_depth: u32) -> Vec<String> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut result: Vec<String> = Vec::new();
        self.dfs_inner(root, 0, max_depth, &mut visited, &mut result);
        result
    }

    fn dfs_inner(
        &self,
        id: &str,
        depth: u32,
        max_depth: u32,
        visited: &mut HashSet<String>,
        result: &mut Vec<String>,
    ) {
        if visited.contains(id) {
            return;
        }
        if !self.nodes.contains_key(id) {
            return;
        }
        visited.insert(id.to_owned());
        result.push(id.to_owned());
        if depth < max_depth {
            let targets: Vec<String> = self.edges_from(id).map(|e| e.target.clone()).collect();
            for t in targets {
                self.dfs_inner(&t, depth + 1, max_depth, visited, result);
            }
        }
    }

    /// Find shortest path between two nodes using BFS.
    #[must_use] 
    pub fn shortest_path(&self, from: &str, to: &str) -> Option<Vec<String>> {
        if from == to {
            return Some(vec![from.to_owned()]);
        }
        let mut visited: HashSet<String> = HashSet::new();
        let mut prev: HashMap<String, String> = HashMap::new();
        let mut queue: VecDeque<String> = VecDeque::new();

        visited.insert(from.to_owned());
        queue.push_back(from.to_owned());

        while let Some(cur) = queue.pop_front() {
            for edge in self.edges_from(&cur) {
                let next = &edge.target;
                if visited.contains(next.as_str()) {
                    continue;
                }
                prev.insert(next.clone(), cur.clone());
                if next == to {
                    // Reconstruct path
                    let mut path = vec![to.to_owned()];
                    let mut node = to.to_owned();
                    while let Some(p) = prev.get(&node) {
                        path.push(p.clone());
                        node = p.clone();
                    }
                    path.reverse();
                    return Some(path);
                }
                visited.insert(next.clone());
                queue.push_back(next.clone());
            }
        }
        None
    }

    /// Serialize the graph to JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize a graph from JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }

    /// Returns a summary of the graph.
    #[must_use] 
    pub fn summary(&self) -> GraphSummary {
        let malicious = self.malicious_nodes(0.5).len();
        let node_counts = self.node_counts();
        let edge_kind_counts: HashMap<String, usize> = {
            let mut m = HashMap::new();
            for e in &self.edges {
                *m.entry(e.kind.to_string()).or_insert(0) += 1;
            }
            m
        };
        GraphSummary {
            total_nodes: self.nodes.len(),
            total_edges: self.edges.len(),
            malicious_nodes: malicious,
            node_counts,
            edge_kind_counts,
        }
    }
}

/// Summary statistics for a VT graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSummary {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub malicious_nodes: usize,
    pub node_counts: HashMap<String, usize>,
    pub edge_kind_counts: HashMap<String, usize>,
}

// ─── Graph builder ────────────────────────────────────────────────────────────

/// Builder for constructing VT graphs programmatically.
pub struct VtGraphBuilder {
    graph: VtGraph,
    root_id: Option<String>,
}

impl VtGraphBuilder {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            graph: VtGraph::new(),
            root_id: None,
        }
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.graph.name = Some(name.into());
        self
    }

    pub fn root(mut self, id: impl Into<String>, kind: VtNodeKind) -> Self {
        let id = id.into();
        let node = VtGraphNode::new(id.clone(), kind).with_root().with_depth(0);
        self.root_id = Some(id);
        self.graph.add_node(node);
        self
    }

    pub fn node(mut self, id: impl Into<String>, kind: VtNodeKind, depth: u32) -> Self {
        let node = VtGraphNode::new(id, kind).with_depth(depth);
        self.graph.add_node(node);
        self
    }

    pub fn edge(mut self, src: impl Into<String>, tgt: impl Into<String>, kind: VtEdgeKind) -> Self {
        let edge = VtGraphEdge::new(src, tgt, kind);
        self.graph.add_edge(edge);
        self
    }

    #[must_use] 
    pub fn build(self) -> VtGraph {
        self.graph
    }
}

impl Default for VtGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Relationship expansion ───────────────────────────────────────────────────

/// Specifies which relationship types to follow during traversal.
#[derive(Debug, Clone, Default)]
pub struct TraversalConfig {
    /// Relationship types to follow (empty = follow all)
    pub edge_kinds: Vec<VtEdgeKind>,
    /// Node kinds to include in results (empty = include all)
    pub node_kinds: Vec<VtNodeKind>,
    /// Maximum traversal depth
    pub max_depth: u32,
    /// Maximum total nodes to return
    pub max_nodes: usize,
    /// Only return nodes that are malicious (`detection_ratio` >= threshold)
    pub malicious_only: bool,
    /// Detection ratio threshold for malicious filtering
    pub malicious_threshold: f32,
}

impl TraversalConfig {
    #[must_use] 
    pub fn new(max_depth: u32) -> Self {
        Self {
            max_depth,
            max_nodes: 1000,
            malicious_threshold: 0.5,
            ..Default::default()
        }
    }

    pub fn following(mut self, kinds: impl IntoIterator<Item = VtEdgeKind>) -> Self {
        self.edge_kinds = kinds.into_iter().collect();
        self
    }

    pub fn of_kind(mut self, kinds: impl IntoIterator<Item = VtNodeKind>) -> Self {
        self.node_kinds = kinds.into_iter().collect();
        self
    }
}

/// Performs a configurable traversal over a VT graph.
pub struct GraphTraversal<'a> {
    graph: &'a VtGraph,
    config: TraversalConfig,
}

impl<'a> GraphTraversal<'a> {
    #[must_use] 
    pub const fn new(graph: &'a VtGraph, config: TraversalConfig) -> Self {
        GraphTraversal { graph, config }
    }

    fn edge_allowed(&self, edge: &VtGraphEdge) -> bool {
        if self.config.edge_kinds.is_empty() {
            return true;
        }
        self.config.edge_kinds.contains(&edge.kind)
    }

    fn node_allowed(&self, node: &VtGraphNode) -> bool {
        if self.config.node_kinds.is_empty() {
            return true;
        }
        self.config.node_kinds.contains(&node.kind)
    }

    /// Run the traversal from the given root, returning matching node IDs.
    #[must_use] 
    pub fn run(&self, root: &str) -> TraversalResult {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(String, u32)> = VecDeque::new();
        let mut result_nodes: Vec<String> = Vec::new();
        let mut result_edges: Vec<&VtGraphEdge> = Vec::new();

        if !self.graph.nodes.contains_key(root) {
            return TraversalResult::default();
        }

        queue.push_back((root.to_owned(), 0));
        visited.insert(root.to_owned());

        while let Some((id, depth)) = queue.pop_front() {
            if result_nodes.len() >= self.config.max_nodes {
                break;
            }

            if let Some(node) = self.graph.nodes.get(&id) {
                let passes_malicious = !self.config.malicious_only
                    || node.is_malicious(self.config.malicious_threshold);
                let passes_kind = self.node_allowed(node);

                if passes_malicious && passes_kind {
                    result_nodes.push(id.clone());
                }
            }

            if depth >= self.config.max_depth {
                continue;
            }

            for edge in self.graph.edges_from(&id) {
                if !self.edge_allowed(edge) {
                    continue;
                }
                if !visited.contains(&edge.target) {
                    visited.insert(edge.target.clone());
                    queue.push_back((edge.target.clone(), depth + 1));
                    result_edges.push(edge);
                }
            }
        }

        TraversalResult {
            node_ids: result_nodes,
            edges_traversed: result_edges.len(),
        }
    }
}

/// Result of a graph traversal.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraversalResult {
    /// IDs of nodes found during traversal (in BFS order)
    pub node_ids: Vec<String>,
    /// Number of edges traversed
    pub edges_traversed: usize,
}

impl TraversalResult {
    #[must_use] 
    pub const fn node_count(&self) -> usize {
        self.node_ids.len()
    }
}

// ─── Graph merge ──────────────────────────────────────────────────────────────

/// Merges `other` into `base`, adding any nodes/edges not already present.
/// Returns the number of nodes and edges added.
pub fn merge_graphs(base: &mut VtGraph, other: &VtGraph) -> (usize, usize) {
    let mut added_nodes = 0usize;
    let mut added_edges = 0usize;

    for (id, node) in &other.nodes {
        if !base.nodes.contains_key(id) {
            base.nodes.insert(id.clone(), node.clone());
            added_nodes += 1;
        }
    }

    for edge in &other.edges {
        let already = base.edges.iter().any(|e| {
            e.source == edge.source && e.target == edge.target && e.kind == edge.kind
        });
        if !already {
            base.edges.push(edge.clone());
            added_edges += 1;
        }
    }

    (added_nodes, added_edges)
}

// ─── Filtering ────────────────────────────────────────────────────────────────

/// Creates a subgraph containing only nodes reachable from the given root
/// within `max_depth` steps, including all edges between those nodes.
#[must_use] 
pub fn subgraph_from_root(graph: &VtGraph, root: &str, max_depth: u32) -> VtGraph {
    let reachable: HashSet<String> = graph.bfs(root, max_depth).into_iter().collect();

    let mut sub = VtGraph::new();
    sub.name = graph.name.as_ref().map(|n| format!("{n} (subgraph)"));

    for id in &reachable {
        if let Some(node) = graph.nodes.get(id) {
            sub.nodes.insert(id.clone(), node.clone());
        }
    }

    for edge in &graph.edges {
        if reachable.contains(&edge.source) && reachable.contains(&edge.target) {
            sub.edges.push(edge.clone());
        }
    }

    sub
}

/// Filters a graph to only include nodes of the given kinds.
#[must_use] 
pub fn filter_by_kind(graph: &VtGraph, kinds: &[VtNodeKind]) -> VtGraph {
    let kind_set: HashSet<&VtNodeKind> = kinds.iter().collect();
    let mut sub = VtGraph::new();
    sub.name = graph.name.clone();

    for (id, node) in &graph.nodes {
        if kind_set.contains(&node.kind) {
            sub.nodes.insert(id.clone(), node.clone());
        }
    }

    for edge in &graph.edges {
        if sub.nodes.contains_key(&edge.source) && sub.nodes.contains_key(&edge.target) {
            sub.edges.push(edge.clone());
        }
    }

    sub
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_graph() -> VtGraph {
        VtGraphBuilder::new()
            .name("test graph")
            .root("sha256_root", VtNodeKind::File)
            .node("domain1", VtNodeKind::Domain, 1)
            .node("ip1", VtNodeKind::IpAddress, 2)
            .node("drop1", VtNodeKind::File, 1)
            .edge("sha256_root", "domain1", VtEdgeKind::ContactedDomain)
            .edge("domain1", "ip1", VtEdgeKind::ResolvesTo)
            .edge("sha256_root", "drop1", VtEdgeKind::DroppedFile)
            .build()
    }

    #[test]
    fn test_bfs_order() {
        let g = sample_graph();
        let bfs = g.bfs("sha256_root", 5);
        assert!(bfs.contains(&"sha256_root".to_owned()));
        assert!(bfs.contains(&"domain1".to_owned()));
        assert!(bfs.contains(&"ip1".to_owned()));
    }

    #[test]
    fn test_shortest_path() {
        let g = sample_graph();
        let path = g.shortest_path("sha256_root", "ip1").unwrap();
        assert_eq!(path, vec!["sha256_root", "domain1", "ip1"]);
    }

    #[test]
    fn test_node_counts() {
        let g = sample_graph();
        let counts = g.node_counts();
        assert_eq!(*counts.get("file").unwrap_or(&0), 2);
        assert_eq!(*counts.get("domain").unwrap_or(&0), 1);
    }

    #[test]
    fn test_json_roundtrip() {
        let g = sample_graph();
        let json = g.to_json().unwrap();
        let g2 = VtGraph::from_json(&json).unwrap();
        assert_eq!(g.nodes.len(), g2.nodes.len());
        assert_eq!(g.edges.len(), g2.edges.len());
    }

    #[test]
    fn test_subgraph() {
        let g = sample_graph();
        let sub = subgraph_from_root(&g, "sha256_root", 1);
        // sha256_root + domain1 + drop1 = 3 nodes (ip1 is at depth 2)
        assert_eq!(sub.nodes.len(), 3);
    }

    #[test]
    fn test_filter_by_kind() {
        let g = sample_graph();
        let files_only = filter_by_kind(&g, &[VtNodeKind::File]);
        assert_eq!(files_only.nodes.len(), 2);
    }

    #[test]
    fn test_merge() {
        let mut base = sample_graph();
        let mut extra = VtGraph::new();
        let n = VtGraphNode::new("new_node", VtNodeKind::Url);
        extra.add_node(n);
        let (added_nodes, _) = merge_graphs(&mut base, &extra);
        assert_eq!(added_nodes, 1);
    }
}
