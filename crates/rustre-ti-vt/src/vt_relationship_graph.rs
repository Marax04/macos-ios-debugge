//! `vt_relationship_graph` — file → domain → IP → URL relationship graph.
//!
//! Builds a directed property graph from `VirusTotal` relationship data.
//! Nodes represent `VirusTotal` objects (files, domains, IPs, URLs) and edges
//! represent typed relationships between them.
//!
//! The graph is backed by `petgraph::stable_graph::StableDiGraph` so that
//! nodes can be removed without invalidating other indices.

use std::collections::HashMap;
use std::fmt;

use petgraph::stable_graph::{NodeIndex, StableDiGraph};
use petgraph::visit::{EdgeRef, IntoEdgeReferences};
use petgraph::Direction;
use serde::{Deserialize, Serialize};

// ── Node types ────────────────────────────────────────────────────────────────

/// The kind of `VirusTotal` object represented by a graph node.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VtNodeKind {
    /// A file (identified by SHA-256 hash).
    File,
    /// A domain name.
    Domain,
    /// An IPv4 or IPv6 address.
    IpAddress,
    /// A URL.
    Url,
    /// A `VirusTotal` collection.
    Collection,
    /// An actor / threat-actor.
    ThreatActor,
    /// A YARA rule.
    YaraRule,
    /// Unclassified node.
    Other(String),
}

impl fmt::Display for VtNodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File => write!(f, "file"),
            Self::Domain => write!(f, "domain"),
            Self::IpAddress => write!(f, "ip"),
            Self::Url => write!(f, "url"),
            Self::Collection => write!(f, "collection"),
            Self::ThreatActor => write!(f, "threat_actor"),
            Self::YaraRule => write!(f, "yara_rule"),
            Self::Other(s) => write!(f, "other({s})"),
        }
    }
}

/// A node in the `VirusTotal` relationship graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtNode {
    /// Unique `VirusTotal` identifier (hash, FQDN, IP string, URL, …).
    pub id: String,
    /// Kind of object.
    pub kind: VtNodeKind,
    /// Free-form attributes (detection count, tags, etc.).
    pub attributes: HashMap<String, String>,
    /// `VirusTotal` detection ratio e.g. 23/72.
    pub detection_ratio: Option<(u32, u32)>,
}

impl VtNode {
    /// Create a minimal node.
    #[must_use]
    pub fn new(id: impl Into<String>, kind: VtNodeKind) -> Self {
        Self {
            id: id.into(),
            kind,
            attributes: HashMap::new(),
            detection_ratio: None,
        }
    }

    /// Return `true` if the node has at least one detection.
    #[must_use]
    pub fn is_malicious(&self) -> bool {
        self.detection_ratio.is_some_and(|(detected, _)| detected > 0)
    }

    /// Detection percentage in [0.0, 100.0].
    #[must_use]
    pub fn detection_pct(&self) -> Option<f64> {
        self.detection_ratio.map(|(d, t)| {
            if t == 0 { 0.0 } else { f64::from(d) / f64::from(t) * 100.0 }
        })
    }
}

impl fmt::Display for VtNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind, self.id)
    }
}

// ── Edge types ────────────────────────────────────────────────────────────────

/// The kind of relationship between two `VirusTotal` objects.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelationshipKind {
    /// File contacts domain.
    ContactsDomain,
    /// File contacts IP address.
    ContactsIp,
    /// File downloads from URL.
    DownloadsFrom,
    /// File dropped by another file.
    DroppedBy,
    /// File drops another file.
    Drops,
    /// Domain resolves to IP.
    ResolvesToIp,
    /// URL is served by IP.
    ServedByIp,
    /// URL is on domain.
    OnDomain,
    /// File is bundled in collection.
    InCollection,
    /// Associated with a threat actor.
    AttributedTo,
    /// Matched by a YARA rule.
    MatchesYara,
    /// Generic unclassified relationship.
    Other(String),
}

impl fmt::Display for RelationshipKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContactsDomain => write!(f, "contacts_domain"),
            Self::ContactsIp => write!(f, "contacts_ip"),
            Self::DownloadsFrom => write!(f, "downloads_from"),
            Self::DroppedBy => write!(f, "dropped_by"),
            Self::Drops => write!(f, "drops"),
            Self::ResolvesToIp => write!(f, "resolves_to_ip"),
            Self::ServedByIp => write!(f, "served_by_ip"),
            Self::OnDomain => write!(f, "on_domain"),
            Self::InCollection => write!(f, "in_collection"),
            Self::AttributedTo => write!(f, "attributed_to"),
            Self::MatchesYara => write!(f, "matches_yara"),
            Self::Other(s) => write!(f, "other({s})"),
        }
    }
}

/// An edge in the relationship graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipEdge {
    /// The relationship kind.
    pub kind: RelationshipKind,
    /// Source of this relationship data (e.g., "`vt_api`", "manual").
    pub source: String,
    /// Confidence score in [0.0, 1.0].
    pub confidence: f64,
    /// Optional context string.
    pub context: Option<String>,
}

impl RelationshipEdge {
    /// Create a new edge.
    #[must_use]
    pub fn new(kind: RelationshipKind, source: impl Into<String>) -> Self {
        Self { kind, source: source.into(), confidence: 1.0, context: None }
    }

    /// Builder: set confidence.
    #[must_use]
    pub const fn with_confidence(mut self, c: f64) -> Self {
        // NaN-safe clamp: `f64::clamp` propagates NaN and `is_nan()` is not
        // available in a const fn.
        self.confidence = if c >= 1.0 {
            1.0
        } else if c > 0.0 {
            c
        } else {
            0.0
        };
        self
    }

    /// Builder: set context.
    #[must_use]
    pub fn with_context(mut self, ctx: impl Into<String>) -> Self {
        self.context = Some(ctx.into());
        self
    }
}

impl fmt::Display for RelationshipEdge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[conf={:.2}]", self.kind, self.confidence)
    }
}

// ── VtRelationshipGraph ───────────────────────────────────────────────────────

/// Directed property graph of `VirusTotal` object relationships.
///
/// Nodes are [`VtNode`]s; edges are [`RelationshipEdge`]s.  An internal map
/// from `id` string → `NodeIndex` allows O(1) lookup by identifier.
///
/// # Example
///
/// ```
/// use rustre_ti_vt::vt_relationship_graph::{
///     VtRelationshipGraph, VtNode, VtNodeKind, RelationshipEdge, RelationshipKind,
/// };
///
/// let mut g = VtRelationshipGraph::new();
/// let file = g.add_or_update_node(VtNode::new("deadbeef", VtNodeKind::File));
/// let domain = g.add_or_update_node(VtNode::new("evil.com", VtNodeKind::Domain));
/// g.add_edge_by_id(
///     "deadbeef",
///     "evil.com",
///     RelationshipEdge::new(RelationshipKind::ContactsDomain, "vt_api"),
/// );
/// assert_eq!(g.node_count(), 2);
/// ```
#[derive(Debug)]
pub struct VtRelationshipGraph {
    graph: StableDiGraph<VtNode, RelationshipEdge>,
    id_to_idx: HashMap<String, NodeIndex>,
}

impl VtRelationshipGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self {
            graph: StableDiGraph::new(),
            id_to_idx: HashMap::new(),
        }
    }

    // ── Node management ───────────────────────────────────────────────────────

    /// Add a node or update it if a node with the same `id` already exists.
    ///
    /// Returns the `NodeIndex` for the node.
    pub fn add_or_update_node(&mut self, node: VtNode) -> NodeIndex {
        if let Some(&idx) = self.id_to_idx.get(&node.id) {
            self.graph[idx] = node;
            idx
        } else {
            let id = node.id.clone();
            let idx = self.graph.add_node(node);
            self.id_to_idx.insert(id, idx);
            idx
        }
    }

    /// Return the `NodeIndex` for the node with `id`, if present.
    #[must_use]
    pub fn node_index(&self, id: &str) -> Option<NodeIndex> {
        self.id_to_idx.get(id).copied()
    }

    /// Return a reference to the node with `id`.
    #[must_use]
    pub fn node_by_id(&self, id: &str) -> Option<&VtNode> {
        let idx = self.id_to_idx.get(id)?;
        self.graph.node_weight(*idx)
    }

    /// Remove the node with `id` and all its edges.
    pub fn remove_node(&mut self, id: &str) {
        if let Some(idx) = self.id_to_idx.remove(id) {
            self.graph.remove_node(idx);
        }
    }

    /// Number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    // ── Edge management ───────────────────────────────────────────────────────

    /// Add an edge between nodes identified by string IDs.
    ///
    /// If either node doesn't exist, this is a no-op and returns `false`.
    pub fn add_edge_by_id(
        &mut self,
        from_id: &str,
        to_id: &str,
        edge: RelationshipEdge,
    ) -> bool {
        let from = match self.id_to_idx.get(from_id).copied() {
            Some(i) => i,
            None => return false,
        };
        let to = match self.id_to_idx.get(to_id).copied() {
            Some(i) => i,
            None => return false,
        };
        self.graph.add_edge(from, to, edge);
        true
    }

    /// Add an edge by `NodeIndex`.
    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex, edge: RelationshipEdge) {
        self.graph.add_edge(from, to, edge);
    }

    /// Number of edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /// Return all nodes of the given `kind`.
    #[must_use]
    pub fn nodes_of_kind(&self, kind: &VtNodeKind) -> Vec<&VtNode> {
        self.graph
            .node_weights()
            .filter(|n| &n.kind == kind)
            .collect()
    }

    /// Return all neighbours of node `id` reachable via outgoing edges.
    #[must_use]
    pub fn outgoing_neighbours(&self, id: &str) -> Vec<&VtNode> {
        let idx = match self.id_to_idx.get(id) {
            Some(&i) => i,
            None => return vec![],
        };
        self.graph
            .neighbors_directed(idx, Direction::Outgoing)
            .filter_map(|ni| self.graph.node_weight(ni))
            .collect()
    }

    /// Return all neighbours of node `id` via incoming edges.
    #[must_use]
    pub fn incoming_neighbours(&self, id: &str) -> Vec<&VtNode> {
        let idx = match self.id_to_idx.get(id) {
            Some(&i) => i,
            None => return vec![],
        };
        self.graph
            .neighbors_directed(idx, Direction::Incoming)
            .filter_map(|ni| self.graph.node_weight(ni))
            .collect()
    }

    /// Return all edges outgoing from node `id`.
    #[must_use]
    pub fn edges_from(&self, id: &str) -> Vec<(&VtNode, &RelationshipEdge)> {
        let idx = match self.id_to_idx.get(id) {
            Some(&i) => i,
            None => return vec![],
        };
        self.graph
            .edges_directed(idx, Direction::Outgoing)
            .filter_map(|er| {
                let target = self.graph.node_weight(er.target())?;
                Some((target, er.weight()))
            })
            .collect()
    }

    /// Return all nodes that are marked as malicious (have detections).
    #[must_use]
    pub fn malicious_nodes(&self) -> Vec<&VtNode> {
        self.graph.node_weights().filter(|n| n.is_malicious()).collect()
    }

    /// Return all nodes reachable from `start_id` via BFS.
    #[must_use]
    pub fn bfs_reachable(&self, start_id: &str) -> Vec<&VtNode> {
        use petgraph::visit::Bfs;
        let start = match self.id_to_idx.get(start_id) {
            Some(&i) => i,
            None => return vec![],
        };
        let mut bfs = Bfs::new(&self.graph, start);
        let mut result = Vec::new();
        while let Some(nx) = bfs.next(&self.graph) {
            if let Some(node) = self.graph.node_weight(nx) {
                result.push(node);
            }
        }
        result
    }

    /// Find the shortest path between `from_id` and `to_id` using Dijkstra.
    ///
    /// Returns the sequence of node IDs on the path, or `None` if unreachable.
    #[must_use]
    pub fn shortest_path(&self, from_id: &str, to_id: &str) -> Option<Vec<String>> {
        use petgraph::algo::dijkstra;
        let from = *self.id_to_idx.get(from_id)?;
        let to = *self.id_to_idx.get(to_id)?;
        let costs = dijkstra(&self.graph, from, Some(to), |_| 1u32);
        if !costs.contains_key(&to) {
            return None;
        }
        // Reconstruct path greedily (good enough for small graphs).
        let mut path = vec![to_id.to_string()];
        let mut current = to;
        'outer: loop {
            if current == from {
                break;
            }
            let current_cost = *costs.get(&current)?;
            for neighbor in self.graph.neighbors_directed(current, Direction::Incoming) {
                if let Some(&ncost) = costs.get(&neighbor)
                    && ncost + 1 == current_cost
                        && let Some(node) = self.graph.node_weight(neighbor) {
                            path.push(node.id.clone());
                            current = neighbor;
                            continue 'outer;
                        }
            }
            break;
        }
        path.reverse();
        Some(path)
    }

    /// Return a summary of the graph for display.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "VtRelationshipGraph: {} nodes, {} edges",
            self.node_count(),
            self.edge_count(),
        )
    }

    /// Iterate all nodes.
    pub fn iter_nodes(&self) -> impl Iterator<Item = &VtNode> {
        self.graph.node_weights()
    }

    /// Iterate all edges as `(source_node, edge, target_node)`.
    pub fn iter_edges(&self) -> impl Iterator<Item = (&VtNode, &RelationshipEdge, &VtNode)> {
        self.graph.edge_references().filter_map(|er| {
            let src = self.graph.node_weight(er.source())?;
            let tgt = self.graph.node_weight(er.target())?;
            Some((src, er.weight(), tgt))
        })
    }
}

impl Default for VtRelationshipGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for VtRelationshipGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn file_node(id: &str) -> VtNode {
        VtNode::new(id, VtNodeKind::File)
    }

    fn domain_node(id: &str) -> VtNode {
        VtNode::new(id, VtNodeKind::Domain)
    }

    fn ip_node(id: &str) -> VtNode {
        VtNode::new(id, VtNodeKind::IpAddress)
    }

    fn contacts_edge() -> RelationshipEdge {
        RelationshipEdge::new(RelationshipKind::ContactsDomain, "vt_api")
    }

    fn resolves_edge() -> RelationshipEdge {
        RelationshipEdge::new(RelationshipKind::ResolvesToIp, "vt_api")
    }

    // ── Node management ───────────────────────────────────────────────────────

    #[test]
    fn test_add_node_increments_count() {
        let mut g = VtRelationshipGraph::new();
        g.add_or_update_node(file_node("abc"));
        assert_eq!(g.node_count(), 1);
    }

    #[test]
    fn test_add_duplicate_node_no_increase() {
        let mut g = VtRelationshipGraph::new();
        g.add_or_update_node(file_node("abc"));
        g.add_or_update_node(file_node("abc")); // update
        assert_eq!(g.node_count(), 1);
    }

    #[test]
    fn test_node_by_id() {
        let mut g = VtRelationshipGraph::new();
        g.add_or_update_node(domain_node("evil.com"));
        let n = g.node_by_id("evil.com").unwrap();
        assert_eq!(n.id, "evil.com");
        assert_eq!(n.kind, VtNodeKind::Domain);
    }

    #[test]
    fn test_node_by_id_missing() {
        let g = VtRelationshipGraph::new();
        assert!(g.node_by_id("nope").is_none());
    }

    #[test]
    fn test_remove_node() {
        let mut g = VtRelationshipGraph::new();
        g.add_or_update_node(file_node("f1"));
        g.remove_node("f1");
        assert_eq!(g.node_count(), 0);
        assert!(g.node_by_id("f1").is_none());
    }

    // ── Edge management ───────────────────────────────────────────────────────

    #[test]
    fn test_add_edge_increments_count() {
        let mut g = VtRelationshipGraph::new();
        g.add_or_update_node(file_node("f1"));
        g.add_or_update_node(domain_node("evil.com"));
        g.add_edge_by_id("f1", "evil.com", contacts_edge());
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn test_add_edge_missing_node_no_add() {
        let mut g = VtRelationshipGraph::new();
        g.add_or_update_node(file_node("f1"));
        let added = g.add_edge_by_id("f1", "ghost", contacts_edge());
        assert!(!added);
        assert_eq!(g.edge_count(), 0);
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    #[test]
    fn test_nodes_of_kind() {
        let mut g = VtRelationshipGraph::new();
        g.add_or_update_node(file_node("f1"));
        g.add_or_update_node(file_node("f2"));
        g.add_or_update_node(domain_node("evil.com"));
        let files = g.nodes_of_kind(&VtNodeKind::File);
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_outgoing_neighbours() {
        let mut g = VtRelationshipGraph::new();
        g.add_or_update_node(file_node("f1"));
        g.add_or_update_node(domain_node("evil.com"));
        g.add_edge_by_id("f1", "evil.com", contacts_edge());
        let nb = g.outgoing_neighbours("f1");
        assert_eq!(nb.len(), 1);
        assert_eq!(nb[0].id, "evil.com");
    }

    #[test]
    fn test_incoming_neighbours() {
        let mut g = VtRelationshipGraph::new();
        g.add_or_update_node(file_node("f1"));
        g.add_or_update_node(domain_node("evil.com"));
        g.add_edge_by_id("f1", "evil.com", contacts_edge());
        let nb = g.incoming_neighbours("evil.com");
        assert_eq!(nb.len(), 1);
        assert_eq!(nb[0].id, "f1");
    }

    #[test]
    fn test_malicious_nodes() {
        let mut g = VtRelationshipGraph::new();
        let mut f = file_node("f1");
        f.detection_ratio = Some((5, 72));
        g.add_or_update_node(f);
        g.add_or_update_node(file_node("f2")); // no detections
        let malicious = g.malicious_nodes();
        assert_eq!(malicious.len(), 1);
        assert_eq!(malicious[0].id, "f1");
    }

    #[test]
    fn test_bfs_reachable() {
        let mut g = VtRelationshipGraph::new();
        g.add_or_update_node(file_node("f1"));
        g.add_or_update_node(domain_node("evil.com"));
        g.add_or_update_node(ip_node("1.2.3.4"));
        g.add_edge_by_id("f1", "evil.com", contacts_edge());
        g.add_edge_by_id("evil.com", "1.2.3.4", resolves_edge());
        let reachable = g.bfs_reachable("f1");
        let ids: Vec<_> = reachable.iter().map(|n| n.id.as_str()).collect();
        assert!(ids.contains(&"f1"));
        assert!(ids.contains(&"evil.com"));
        assert!(ids.contains(&"1.2.3.4"));
    }

    #[test]
    fn test_edges_from() {
        let mut g = VtRelationshipGraph::new();
        g.add_or_update_node(file_node("f1"));
        g.add_or_update_node(domain_node("d1"));
        g.add_edge_by_id("f1", "d1", contacts_edge());
        let edges = g.edges_from("f1");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].0.id, "d1");
    }

    // ── VtNode helpers ────────────────────────────────────────────────────────

    #[test]
    fn test_node_is_malicious() {
        let mut n = file_node("x");
        assert!(!n.is_malicious());
        n.detection_ratio = Some((1, 10));
        assert!(n.is_malicious());
    }

    #[test]
    fn test_node_detection_pct() {
        let mut n = file_node("x");
        n.detection_ratio = Some((10, 100));
        assert!((n.detection_pct().unwrap() - 10.0).abs() < 1e-6);
    }

    // ── RelationshipEdge ──────────────────────────────────────────────────────

    #[test]
    fn test_edge_confidence_clamped() {
        let e = RelationshipEdge::new(RelationshipKind::ContactsDomain, "api").with_confidence(2.5);
        assert_eq!(e.confidence, 1.0);
    }

    #[test]
    fn test_edge_display() {
        let e = RelationshipEdge::new(RelationshipKind::Drops, "api");
        assert!(e.to_string().contains("drops"));
    }

    // ── iter helpers ─────────────────────────────────────────────────────────

    #[test]
    fn test_iter_nodes() {
        let mut g = VtRelationshipGraph::new();
        g.add_or_update_node(file_node("a"));
        g.add_or_update_node(file_node("b"));
        assert_eq!(g.iter_nodes().count(), 2);
    }

    #[test]
    fn test_iter_edges() {
        let mut g = VtRelationshipGraph::new();
        g.add_or_update_node(file_node("a"));
        g.add_or_update_node(domain_node("b"));
        g.add_edge_by_id("a", "b", contacts_edge());
        assert_eq!(g.iter_edges().count(), 1);
    }
}
