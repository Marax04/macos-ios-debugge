//! `knowledge_importer` — Import knowledge graphs from external sources.
//!
//! Provides [`KnowledgeImporter`], [`ImportSource`], [`ImportResult`], and
//! the primary entry point [`import_from_json`].

use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::path::Path;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{KnowledgeEdge, KnowledgeGraph, KnowledgeNode};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by import operations.
#[derive(Debug, Error)]
pub enum ImportError {
    /// JSON parsing error.
    #[error("json parse error: {0}")]
    Json(#[from] serde_json::Error),
    /// I/O error while reading the source.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The source data is structurally invalid.
    #[error("invalid source structure: {0}")]
    InvalidStructure(String),
    /// A required field is missing.
    #[error("missing required field: '{0}'")]
    MissingField(String),
    /// A node references a nonexistent ID.
    #[error("dangling reference: edge from '{0}' to '{1}' — node not found")]
    DanglingReference(String, String),
    /// Import was aborted because the source is empty.
    #[error("empty import source")]
    EmptySource,
    /// Format is not supported.
    #[error("unsupported import format: '{0}'")]
    UnsupportedFormat(String),
}

// ---------------------------------------------------------------------------
// ImportSource
// ---------------------------------------------------------------------------

/// Where to read the knowledge from.
#[derive(Debug, Clone)]
pub enum ImportSource {
    /// Raw JSON string.
    JsonString(String),
    /// JSON file path.
    JsonFile(std::path::PathBuf),
    /// Raw bytes (auto-detected format).
    Bytes(Vec<u8>),
    /// An in-memory reader.
    InMemory(Vec<u8>),
}

impl ImportSource {
    /// Read the source into a byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ImportError::Io`] on read failure.
    pub fn read_bytes(&self) -> Result<Vec<u8>, ImportError> {
        /// Hard limit for file reads: 256 MiB (matches `MAX_IMPORT_BYTES`).
        const FILE_READ_LIMIT: u64 = 256 * 1024 * 1024;
        match self {
            Self::JsonString(s) => Ok(s.as_bytes().to_vec()),
            Self::JsonFile(path) => {
                let mut f = std::fs::File::open(path)?;
                // Enforce the size limit at read time so that a huge file does
                // not exhaust memory before the post-read check in `import_json`.
                let mut limited = f.by_ref().take(FILE_READ_LIMIT + 1);
                let mut buf = Vec::new();
                limited.read_to_end(&mut buf)?;
                if buf.len() as u64 > FILE_READ_LIMIT {
                    return Err(ImportError::InvalidStructure(format!(
                        "import file exceeds maximum allowed size ({FILE_READ_LIMIT} bytes)",
                    )));
                }
                Ok(buf)
            }
            Self::Bytes(b) | Self::InMemory(b) => Ok(b.clone()),
        }
    }

    /// Read the source as a UTF-8 string.
    ///
    /// # Errors
    ///
    /// Returns [`ImportError::Io`] or [`ImportError::InvalidStructure`] on failure.
    pub fn read_string(&self) -> Result<String, ImportError> {
        let bytes = self.read_bytes()?;
        String::from_utf8(bytes)
            .map_err(|_| ImportError::InvalidStructure("source is not valid UTF-8".to_string()))
    }
}

impl fmt::Display for ImportSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JsonString(_) => write!(f, "<json-string>"),
            Self::JsonFile(p) => write!(f, "{}", p.display()),
            Self::Bytes(b) => write!(f, "<bytes:{}>", b.len()),
            Self::InMemory(b) => write!(f, "<memory:{}>", b.len()),
        }
    }
}

// ---------------------------------------------------------------------------
// ImportStats
// ---------------------------------------------------------------------------

/// Statistics collected during an import operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportStats {
    /// Number of nodes imported.
    pub nodes_imported: usize,
    /// Number of edges imported.
    pub edges_imported: usize,
    /// Number of nodes skipped (duplicates).
    pub nodes_skipped: usize,
    /// Number of edges skipped (duplicates or dangling).
    pub edges_skipped: usize,
    /// Warnings generated during import.
    pub warnings: Vec<String>,
}

impl fmt::Display for ImportStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "nodes:{} edges:{} skipped_nodes:{} skipped_edges:{} warnings:{}",
            self.nodes_imported,
            self.edges_imported,
            self.nodes_skipped,
            self.edges_skipped,
            self.warnings.len()
        )
    }
}

// ---------------------------------------------------------------------------
// ImportResult
// ---------------------------------------------------------------------------

/// The result of an import operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    /// The imported knowledge graph.
    pub graph: KnowledgeGraph,
    /// Import statistics.
    pub stats: ImportStats,
    /// Source label (path or description).
    pub source_label: String,
}

impl ImportResult {
    /// Returns `true` if the import produced no warnings.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.stats.warnings.is_empty()
    }

    /// Total items (nodes + edges) imported.
    #[must_use]
    pub const fn total_imported(&self) -> usize {
        self.stats.nodes_imported + self.stats.edges_imported
    }
}

impl fmt::Display for ImportResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ImportResult[{}] {}", self.source_label, self.stats)
    }
}

// ---------------------------------------------------------------------------
// JSON intermediate representation
// ---------------------------------------------------------------------------

/// Serialisable JSON representation of a knowledge graph for import/export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphJson {
    /// Schema version.
    #[serde(default)]
    pub version: String,
    /// Graph metadata.
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
    /// Node list.
    pub nodes: Vec<NodeJson>,
    /// Edge list.
    pub edges: Vec<EdgeJson>,
}

/// JSON representation of a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeJson {
    pub id: String,
    pub label: String,
    pub kind: String,
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// JSON representation of an edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeJson {
    pub from: String,
    pub to: String,
    pub relation: String,
    #[serde(default)]
    pub weight: Option<u32>,
}

impl GraphJson {
    /// Parse from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns [`ImportError::Json`] on parse failure.
    pub fn from_json_str(s: &str) -> Result<Self, ImportError> {
        Ok(serde_json::from_str(s)?)
    }

    /// Parse from a JSON byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`ImportError::Json`] on parse failure.
    pub fn from_json_bytes(b: &[u8]) -> Result<Self, ImportError> {
        Ok(serde_json::from_slice(b)?)
    }
}

// ---------------------------------------------------------------------------
// ImportConfig
// ---------------------------------------------------------------------------

/// Configuration options for the importer.
#[derive(Debug, Clone)]
pub struct ImportConfig {
    /// If `true`, skip edges whose endpoints are not in the node set.
    pub skip_dangling_edges: bool,
    /// If `true`, skip duplicate nodes instead of overwriting them.
    pub skip_duplicate_nodes: bool,
    /// Optional node kind filter: only import nodes of these kinds.
    pub node_kind_filter: Option<Vec<String>>,
    /// Optional relation filter: only import edges of these relation types.
    pub relation_filter: Option<Vec<String>>,
    /// Maximum number of nodes to import (0 = unlimited).
    pub max_nodes: usize,
    /// Maximum number of edges to import (0 = unlimited).
    pub max_edges: usize,
}

impl Default for ImportConfig {
    fn default() -> Self {
        Self {
            skip_dangling_edges: true,
            skip_duplicate_nodes: false,
            node_kind_filter: None,
            relation_filter: None,
            max_nodes: 0,
            max_edges: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// KnowledgeImporter
// ---------------------------------------------------------------------------

/// Imports knowledge graphs from various sources into a [`KnowledgeGraph`].
pub struct KnowledgeImporter {
    config: ImportConfig,
}

impl KnowledgeImporter {
    /// Create a new importer with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self { config: ImportConfig::default() }
    }

    /// Create a new importer with the given configuration.
    #[must_use]
    pub const fn with_config(config: ImportConfig) -> Self {
        Self { config }
    }

    /// Skip edges whose endpoints are not in the node set.
    #[must_use]
    pub const fn skip_dangling(mut self, skip: bool) -> Self {
        self.config.skip_dangling_edges = skip;
        self
    }

    /// Filter nodes to only the given kinds.
    #[must_use]
    pub fn filter_node_kinds(mut self, kinds: Vec<String>) -> Self {
        self.config.node_kind_filter = Some(kinds);
        self
    }

    /// Filter edges to only the given relation types.
    #[must_use]
    pub fn filter_relations(mut self, relations: Vec<String>) -> Self {
        self.config.relation_filter = Some(relations);
        self
    }

    /// Set a maximum node count (0 = unlimited).
    #[must_use]
    pub const fn max_nodes(mut self, n: usize) -> Self {
        self.config.max_nodes = n;
        self
    }

    /// Import from a [`ImportSource`] in JSON format.
    ///
    /// # Errors
    ///
    /// Returns [`ImportError`] on parse or validation failure.
    /// Maximum number of bytes accepted from a single import source (256 MiB).
    const MAX_IMPORT_BYTES: usize = 256 * 1024 * 1024;

    /// Import from an [`ImportSource`] in JSON format.
    ///
    /// # Errors
    ///
    /// Returns [`ImportError`] on parse or validation failure.
    pub fn import_json(&self, source: &ImportSource) -> Result<ImportResult, ImportError> {
        let label = source.to_string();
        let data = source.read_bytes()?;
        if data.is_empty() {
            return Err(ImportError::EmptySource);
        }
        if data.len() > Self::MAX_IMPORT_BYTES {
            return Err(ImportError::InvalidStructure(format!(
                "import source too large: {} bytes (limit {})",
                data.len(),
                Self::MAX_IMPORT_BYTES,
            )));
        }
        let graph_json = GraphJson::from_json_bytes(&data)?;
        let result = self.build_graph(graph_json, label);
        Ok(result)
    }

    /// Import from a JSON string directly.
    ///
    /// # Errors
    ///
    /// Returns [`ImportError`] on parse or validation failure.
    pub fn import_json_str(&self, json: &str) -> Result<ImportResult, ImportError> {
        self.import_json(&ImportSource::JsonString(json.to_string()))
    }

    /// Import from a JSON file.
    ///
    /// # Errors
    ///
    /// Returns [`ImportError`] on I/O or parse failure.
    pub fn import_json_file(&self, path: &Path) -> Result<ImportResult, ImportError> {
        self.import_json(&ImportSource::JsonFile(path.to_path_buf()))
    }

    /// Import from a [`GraphJson`] structure directly.
    ///
    /// # Errors
    ///
    /// Returns [`ImportError`] on validation failure.
    pub fn import_graph_json(&self, graph_json: GraphJson) -> Result<ImportResult, ImportError> {
        Ok(self.build_graph(graph_json, "<direct>".to_string()))
    }

    /// Sanitize an untrusted string for safe inclusion in log/warning messages.
    ///
    /// Replaces ASCII control characters (including `\n`, `\r`, `\t`) with `·`
    /// so that an attacker-controlled node id cannot inject fake log lines.
    fn sanitize_for_log(s: &str) -> String {
        s.chars()
            .map(|c| if c.is_ascii_control() { '\u{00B7}' } else { c })
            .collect()
    }

    fn build_graph(&self, gj: GraphJson, label: String) -> ImportResult {
        let mut graph = KnowledgeGraph::new();
        let mut stats = ImportStats::default();

        let kind_filter = self.config.node_kind_filter.as_deref();
        let rel_filter = self.config.relation_filter.as_deref();

        // Import nodes
        for node_json in gj.nodes {
            if self.config.max_nodes > 0 && stats.nodes_imported >= self.config.max_nodes {
                // Count how many remaining nodes will be skipped (nodes after this point in the list).
                // We can't know the exact count here without consuming the iterator, so we use a
                // conservative "at least 1 more" message. The caller can inspect stats.nodes_skipped.
                stats.warnings.push(format!(
                    "node limit ({}) reached; remaining nodes skipped",
                    self.config.max_nodes,
                ));
                break;
            }
            if let Some(kinds) = kind_filter
                && !kinds.contains(&node_json.kind) {
                    stats.nodes_skipped += 1;
                    continue;
                }
            if node_json.id.is_empty() {
                stats.warnings.push("skipped node with empty id".to_string());
                stats.nodes_skipped += 1;
                continue;
            }
            if self.config.skip_duplicate_nodes && graph.nodes.contains_key(&node_json.id) {
                stats.nodes_skipped += 1;
                continue;
            }
            let node = KnowledgeNode {
                id: node_json.id,
                label: node_json.label,
                kind: node_json.kind,
                metadata: node_json.metadata,
            };
            graph.add_node(node);
            stats.nodes_imported += 1;
        }

        // Import edges
        let max_edges = self.config.max_edges;
        for edge_json in gj.edges {
            if max_edges > 0 && stats.edges_imported >= max_edges {
                break;
            }
            if let Some(rels) = rel_filter
                && !rels.contains(&edge_json.relation) {
                    stats.edges_skipped += 1;
                    continue;
                }
            if self.config.skip_dangling_edges {
                if !graph.nodes.contains_key(&edge_json.from) {
                    stats.warnings.push(format!(
                        "dangling edge: source '{}' not in graph",
                        Self::sanitize_for_log(&edge_json.from),
                    ));
                    stats.edges_skipped += 1;
                    continue;
                }
                if !graph.nodes.contains_key(&edge_json.to) {
                    stats.warnings.push(format!(
                        "dangling edge: target '{}' not in graph",
                        Self::sanitize_for_log(&edge_json.to),
                    ));
                    stats.edges_skipped += 1;
                    continue;
                }
            }
            let edge = KnowledgeEdge {
                from: edge_json.from,
                to: edge_json.to,
                relation: edge_json.relation,
                weight: edge_json.weight,
            };
            graph.add_edge(edge);
            stats.edges_imported += 1;
        }

        ImportResult { graph, stats, source_label: label }
    }
}

impl Default for KnowledgeImporter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for KnowledgeImporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KnowledgeImporter(skip_dangling={})", self.config.skip_dangling_edges)
    }
}

// ---------------------------------------------------------------------------
// import_from_json — primary entry point
// ---------------------------------------------------------------------------

/// Import a [`KnowledgeGraph`] from a JSON string.
///
/// This is the primary one-shot entry point.
///
/// # Errors
///
/// Returns [`ImportError`] on parse or validation failure.
pub fn import_from_json(json: &str) -> Result<ImportResult, ImportError> {
    KnowledgeImporter::new().import_json_str(json)
}

// ---------------------------------------------------------------------------
// Helper: build minimal JSON for tests
// ---------------------------------------------------------------------------

/// Build a minimal valid graph JSON string for testing.
///
/// Values are JSON-escaped so that ids/labels containing `"` or `\` do not
/// produce malformed output.
#[must_use]
pub fn minimal_graph_json(nodes: &[(&str, &str, &str)], edges: &[(&str, &str, &str)]) -> String {
    fn json_str(s: &str) -> String {
        // Use serde_json to produce a properly escaped JSON string (including quotes).
        serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
    }
    let nodes_json: Vec<String> = nodes.iter().map(|(id, label, kind)| {
        format!(
            r#"{{"id":{},"label":{},"kind":{}}}"#,
            json_str(id), json_str(label), json_str(kind)
        )
    }).collect();
    let edges_json: Vec<String> = edges.iter().map(|(from, to, rel)| {
        format!(
            r#"{{"from":{},"to":{},"relation":{}}}"#,
            json_str(from), json_str(to), json_str(rel)
        )
    }).collect();
    format!(
        r#"{{"version":"1.0","nodes":[{}],"edges":[{}]}}"#,
        nodes_json.join(","),
        edges_json.join(",")
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> String {
        minimal_graph_json(
            &[("f1", "main", "function"), ("f2", "helper", "function"), ("t1", "MyType", "type")],
            &[("f1", "f2", "calls"), ("f2", "t1", "references")],
        )
    }

    #[test]
    fn test_import_from_json_basic() {
        let result = import_from_json(&sample_json()).unwrap();
        assert_eq!(result.graph.node_count(), 3);
        assert_eq!(result.graph.edge_count(), 2);
    }

    #[test]
    fn test_import_empty_error() {
        let err = import_from_json("");
        assert!(err.is_err());
    }

    #[test]
    fn test_import_invalid_json_error() {
        let err = import_from_json("{invalid json}");
        assert!(err.is_err());
    }

    #[test]
    fn test_import_result_total() {
        let result = import_from_json(&sample_json()).unwrap();
        assert_eq!(result.total_imported(), 5);
    }

    #[test]
    fn test_import_clean_no_warnings() {
        let result = import_from_json(&sample_json()).unwrap();
        assert!(result.is_clean());
    }

    #[test]
    fn test_import_dangling_edge_skipped() {
        let json = minimal_graph_json(
            &[("a", "A", "function")],
            &[("a", "b", "calls")], // b does not exist
        );
        let result = import_from_json(&json).unwrap();
        assert_eq!(result.graph.edge_count(), 0);
        assert_eq!(result.stats.edges_skipped, 1);
        assert!(!result.is_clean()); // warning was generated
    }

    #[test]
    fn test_import_filter_node_kinds() {
        let importer = KnowledgeImporter::new()
            .filter_node_kinds(vec!["function".to_string()]);
        let result = importer.import_json_str(&sample_json()).unwrap();
        // Only function nodes should be imported
        assert_eq!(result.graph.node_count(), 2);
    }

    #[test]
    fn test_import_filter_relations() {
        let importer = KnowledgeImporter::new()
            .filter_relations(vec!["calls".to_string()]);
        let result = importer.import_json_str(&sample_json()).unwrap();
        // Only "calls" edges
        assert_eq!(result.graph.edge_count(), 1);
    }

    #[test]
    fn test_import_max_nodes() {
        let importer = KnowledgeImporter::new().max_nodes(2);
        let result = importer.import_json_str(&sample_json()).unwrap();
        assert!(result.graph.node_count() <= 2);
    }

    #[test]
    fn test_import_skip_duplicate_nodes() {
        // Two nodes with the same id
        let json = r#"{"nodes":[
            {"id":"a","label":"A","kind":"function"},
            {"id":"a","label":"A2","kind":"function"}
        ],"edges":[]}"#;
        let importer = KnowledgeImporter::new().skip_dangling(false);
        let result = importer.import_json_str(json).unwrap();
        // Second one overwrites first (default: no skip)
        assert_eq!(result.graph.node_count(), 1);
    }

    #[test]
    fn test_import_source_json_string() {
        let src = ImportSource::JsonString(sample_json());
        let bytes = src.read_bytes().unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_import_source_in_memory() {
        let src = ImportSource::InMemory(sample_json().into_bytes());
        let s = src.read_string().unwrap();
        assert!(s.contains("function"));
    }

    #[test]
    fn test_graph_json_parse() {
        let gj = GraphJson::from_json_str(&sample_json()).unwrap();
        assert_eq!(gj.nodes.len(), 3);
        assert_eq!(gj.edges.len(), 2);
    }

    #[test]
    fn test_import_result_display() {
        let result = import_from_json(&sample_json()).unwrap();
        let s = result.to_string();
        assert!(s.contains("ImportResult"));
    }

    #[test]
    fn test_import_stats_display() {
        let stats = ImportStats {
            nodes_imported: 5,
            edges_imported: 3,
            nodes_skipped: 1,
            edges_skipped: 0,
            warnings: vec![],
        };
        let s = stats.to_string();
        assert!(s.contains("nodes:5"));
        assert!(s.contains("edges:3"));
    }
}
