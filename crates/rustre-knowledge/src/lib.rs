//! `rustre-knowledge`
//!
//! Knowledge graph layer for `RustRE` — import, export, and merge of
//! reverse-engineering knowledge graphs.

pub mod knowledge_importer;
pub mod knowledge_exporter;
pub mod knowledge_merger;

pub mod entities;
pub mod events;
pub mod store;
pub mod query;

pub use knowledge_importer::{KnowledgeImporter, ImportSource, ImportResult, import_from_json};
pub use knowledge_exporter::{KnowledgeExporter, ExportFormat, ExportResult, export_to_json};
pub use knowledge_merger::{KnowledgeMerger, MergeStrategy, MergeResult, merge_graphs};

pub use entities::{
    Address, Bookmark, ByteLen, Comment, CommentScope, EntityId, EntityKind, EntitySnapshot,
    Function, Patch, Symbol, SymbolScope, Tag, Trace, TypeDef, TypeKind, Xref, XrefKind,
};
pub use events::{EventError, EventLog, EventPayload, KnowledgeEvent};
pub use store::{JsonBackend, KnowledgeStore, NullBackend, PersistBackend, StoreError, Transaction};

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Core graph types shared across sub-modules
// ---------------------------------------------------------------------------

/// A node in the knowledge graph representing a named entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnowledgeNode {
    /// Unique identifier.
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// Kind of entity (function, type, variable, module, …).
    pub kind: String,
    /// Arbitrary metadata.
    pub metadata: HashMap<String, serde_json::Value>,
}

impl KnowledgeNode {
    /// Create a new node with no metadata.
    #[must_use]
    pub fn new(id: impl Into<String>, label: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            kind: kind.into(),
            metadata: HashMap::new(),
        }
    }
}

/// A directed edge connecting two [`KnowledgeNode`]s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnowledgeEdge {
    /// Source node identifier.
    pub from: String,
    /// Target node identifier.
    pub to: String,
    /// Relationship label (calls, references, contains, …).
    pub relation: String,
    /// Optional weight or confidence score.
    pub weight: Option<u32>,
}

impl KnowledgeEdge {
    /// Create a new edge with no weight.
    #[must_use]
    pub fn new(from: impl Into<String>, to: impl Into<String>, relation: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            relation: relation.into(),
            weight: None,
        }
    }
}

/// A complete knowledge graph.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KnowledgeGraph {
    /// All nodes, keyed by their `id`.
    pub nodes: HashMap<String, KnowledgeNode>,
    /// All directed edges.
    pub edges: Vec<KnowledgeEdge>,
}

impl KnowledgeGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a node, overwriting any existing node with the same id.
    pub fn add_node(&mut self, node: KnowledgeNode) {
        self.nodes.insert(node.id.clone(), node);
    }

    /// Add a directed edge.
    pub fn add_edge(&mut self, edge: KnowledgeEdge) {
        self.edges.push(edge);
    }

    /// Number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of edges.
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Outgoing edges from a node.
    #[must_use]
    pub fn outgoing(&self, node_id: &str) -> Vec<&KnowledgeEdge> {
        self.edges.iter().filter(|e| e.from == node_id).collect()
    }

    /// Incoming edges to a node.
    #[must_use]
    pub fn incoming(&self, node_id: &str) -> Vec<&KnowledgeEdge> {
        self.edges.iter().filter(|e| e.to == node_id).collect()
    }
}
