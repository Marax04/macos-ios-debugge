//! `knowledge_exporter` — Export knowledge graphs to various formats.
//!
//! Provides [`KnowledgeExporter`], [`ExportFormat`], [`ExportResult`], and
//! the primary entry point [`export_to_json`].

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{KnowledgeEdge, KnowledgeGraph, KnowledgeNode};
use crate::knowledge_importer::{GraphJson, NodeJson, EdgeJson};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by export operations.
#[derive(Debug, Error)]
pub enum ExportError {
    /// JSON serialisation error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// I/O error while writing to destination.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The requested export format is not supported.
    #[error("unsupported export format: '{0}'")]
    UnsupportedFormat(String),
    /// The graph is empty and cannot be exported.
    #[error("graph is empty")]
    EmptyGraph,
    /// Serialisation of a specific field failed.
    #[error("serialisation failed for field '{0}': {1}")]
    SerialisationFailed(String, String),
}

// ---------------------------------------------------------------------------
// ExportFormat
// ---------------------------------------------------------------------------

/// Output format for a knowledge graph export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExportFormat {
    /// Compact JSON (no indentation).
    JsonCompact,
    /// Pretty-printed JSON (2-space indentation).
    JsonPretty,
    /// `GraphML` XML format.
    GraphMl,
    /// DOT (Graphviz) format.
    Dot,
    /// CSV (nodes and edges as separate tables).
    Csv,
    /// GEXF (Graph Exchange XML Format).
    Gexf,
}

impl ExportFormat {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::JsonCompact => "json-compact",
            Self::JsonPretty => "json-pretty",
            Self::GraphMl => "graphml",
            Self::Dot => "dot",
            Self::Csv => "csv",
            Self::Gexf => "gexf",
        }
    }

    /// Canonical file extension for this format.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::JsonCompact | Self::JsonPretty => "json",
            Self::GraphMl => "graphml",
            Self::Dot => "dot",
            Self::Csv => "csv",
            Self::Gexf => "gexf",
        }
    }

    /// MIME type.
    #[must_use]
    pub const fn mime_type(self) -> &'static str {
        match self {
            Self::JsonCompact | Self::JsonPretty => "application/json",
            Self::GraphMl | Self::Gexf => "application/xml",
            Self::Dot => "text/vnd.graphviz",
            Self::Csv => "text/csv",
        }
    }

    /// Returns `true` if this is a JSON variant.
    #[must_use]
    pub const fn is_json(self) -> bool {
        matches!(self, Self::JsonCompact | Self::JsonPretty)
    }

    /// Returns `true` if this is an XML variant.
    #[must_use]
    pub const fn is_xml(self) -> bool {
        matches!(self, Self::GraphMl | Self::Gexf)
    }
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// ExportStats
// ---------------------------------------------------------------------------

/// Statistics collected during an export operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExportStats {
    /// Number of nodes exported.
    pub nodes_exported: usize,
    /// Number of edges exported.
    pub edges_exported: usize,
    /// Number of nodes skipped (filtered out).
    pub nodes_skipped: usize,
    /// Number of edges skipped (filtered out).
    pub edges_skipped: usize,
    /// Size of the output in bytes.
    pub output_bytes: usize,
}

impl fmt::Display for ExportStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "nodes:{} edges:{} bytes:{}",
            self.nodes_exported, self.edges_exported, self.output_bytes
        )
    }
}

// ---------------------------------------------------------------------------
// ExportResult
// ---------------------------------------------------------------------------

/// The result of an export operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportResult {
    /// The serialised graph bytes.
    pub data: Vec<u8>,
    /// The format used.
    pub format: ExportFormat,
    /// Export statistics.
    pub stats: ExportStats,
}

impl ExportResult {
    /// The exported data as a UTF-8 string, if it is valid UTF-8.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.data).ok()
    }

    /// Write the exported data to a file.
    ///
    /// # Errors
    ///
    /// Returns [`ExportError::Io`] on write failure.
    pub fn write_to_file(&self, path: &Path) -> Result<(), ExportError> {
        let mut f = std::fs::File::create(path)?;
        f.write_all(&self.data)?;
        Ok(())
    }

    /// Size of the exported data in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> usize {
        self.data.len()
    }
}

impl fmt::Display for ExportResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExportResult[{}] {}", self.format, self.stats)
    }
}

// ---------------------------------------------------------------------------
// ExportConfig
// ---------------------------------------------------------------------------

/// Configuration for a knowledge graph export.
#[derive(Debug, Clone)]
pub struct ExportConfig {
    /// Optional node kind filter: only export nodes of these kinds.
    pub node_kind_filter: Option<Vec<String>>,
    /// Optional relation filter: only export edges of these relation types.
    pub relation_filter: Option<Vec<String>>,
    /// Whether to include node metadata in the output.
    pub include_metadata: bool,
    /// Whether to include edge weights in the output.
    pub include_weights: bool,
    /// Schema version string to embed in JSON output.
    pub version: String,
    /// Additional metadata to embed at the graph level.
    pub graph_metadata: HashMap<String, serde_json::Value>,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            node_kind_filter: None,
            relation_filter: None,
            include_metadata: true,
            include_weights: true,
            version: "1.0".to_string(),
            graph_metadata: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// KnowledgeExporter
// ---------------------------------------------------------------------------

/// Exports a [`KnowledgeGraph`] to various output formats.
pub struct KnowledgeExporter {
    config: ExportConfig,
}

impl KnowledgeExporter {
    /// Create a new exporter with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self { config: ExportConfig::default() }
    }

    /// Create a new exporter with the given configuration.
    #[must_use]
    pub const fn with_config(config: ExportConfig) -> Self {
        Self { config }
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

    /// Include or exclude node metadata in the output.
    #[must_use]
    pub const fn include_metadata(mut self, include: bool) -> Self {
        self.config.include_metadata = include;
        self
    }

    /// Export a graph in the given format.
    ///
    /// # Errors
    ///
    /// Returns [`ExportError`] if serialisation fails.
    pub fn export(&self, graph: &KnowledgeGraph, format: ExportFormat) -> Result<ExportResult, ExportError> {
        match format {
            ExportFormat::JsonCompact => self.export_json(graph, false),
            ExportFormat::JsonPretty => self.export_json(graph, true),
            ExportFormat::GraphMl => Ok(self.export_graphml(graph)),
            ExportFormat::Dot => Ok(self.export_dot(graph)),
            ExportFormat::Csv => Ok(self.export_csv(graph)),
            ExportFormat::Gexf => Ok(self.export_gexf(graph)),
        }
    }

    /// Export to a file, detecting format from the file extension.
    ///
    /// # Errors
    ///
    /// Returns [`ExportError`] if serialisation or I/O fails.
    pub fn export_to_file(
        &self,
        graph: &KnowledgeGraph,
        path: &Path,
        format: ExportFormat,
    ) -> Result<ExportResult, ExportError> {
        let result = self.export(graph, format)?;
        result.write_to_file(path)?;
        Ok(result)
    }

    // -----------------------------------------------------------------------
    // JSON export
    // -----------------------------------------------------------------------

    fn export_json(&self, graph: &KnowledgeGraph, pretty: bool) -> Result<ExportResult, ExportError> {
        let (nodes, edges, stats) = self.filter_graph(graph);
        let gj = GraphJson {
            version: self.config.version.clone(),
            metadata: self.config.graph_metadata.clone(),
            nodes: nodes.iter().map(|n| NodeJson {
                id: n.id.clone(),
                label: n.label.clone(),
                kind: n.kind.clone(),
                metadata: if self.config.include_metadata {
                    n.metadata.clone()
                } else {
                    HashMap::new()
                },
            }).collect(),
            edges: edges.iter().map(|e| EdgeJson {
                from: e.from.clone(),
                to: e.to.clone(),
                relation: e.relation.clone(),
                weight: if self.config.include_weights { e.weight } else { None },
            }).collect(),
        };

        let data = if pretty {
            serde_json::to_vec_pretty(&gj)?
        } else {
            serde_json::to_vec(&gj)?
        };
        let format = if pretty { ExportFormat::JsonPretty } else { ExportFormat::JsonCompact };
        let mut stats = stats;
        stats.output_bytes = data.len();
        Ok(ExportResult { data, format, stats })
    }

    // -----------------------------------------------------------------------
    // GraphML export
    // -----------------------------------------------------------------------

    fn export_graphml(&self, graph: &KnowledgeGraph) -> ExportResult {
        let (nodes, edges, mut stats) = self.filter_graph(graph);
        let mut xml = String::from(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<graphml xmlns="http://graphml.graphdrawing.org/graphml">
  <key id="label" for="node" attr.name="label" attr.type="string"/>
  <key id="kind" for="node" attr.name="kind" attr.type="string"/>
  <key id="relation" for="edge" attr.name="relation" attr.type="string"/>
  <key id="weight" for="edge" attr.name="weight" attr.type="int"/>
  <graph id="G" edgedefault="directed">
"#,
        );
        for node in &nodes {
            let _ = write!(
                xml,
                "    <node id=\"{}\">\n      <data key=\"label\">{}</data>\n      <data key=\"kind\">{}</data>\n    </node>\n",
                xml_escape(&node.id),
                xml_escape(&node.label),
                xml_escape(&node.kind),
            );
        }
        for (i, edge) in edges.iter().enumerate() {
            let weight_str = edge.weight.map_or(String::new(), |w| {
                format!("\n      <data key=\"weight\">{w}</data>")
            });
            let _ = write!(
                xml,
                "    <edge id=\"e{i}\" source=\"{}\" target=\"{}\">\n      <data key=\"relation\">{}</data>{}\n    </edge>\n",
                xml_escape(&edge.from),
                xml_escape(&edge.to),
                xml_escape(&edge.relation),
                weight_str,
            );
        }
        xml.push_str("  </graph>\n</graphml>\n");
        let data = xml.into_bytes();
        stats.output_bytes = data.len();
        ExportResult { data, format: ExportFormat::GraphMl, stats }
    }

    // -----------------------------------------------------------------------
    // DOT export
    // -----------------------------------------------------------------------

    fn export_dot(&self, graph: &KnowledgeGraph) -> ExportResult {
        let (nodes, edges, mut stats) = self.filter_graph(graph);
        let mut dot = String::from("digraph G {\n  rankdir=LR;\n");
        for node in &nodes {
            let escaped_label = node.label.replace('"', "\\\"");
            let _ = writeln!(
                dot,
                "  \"{}\" [label=\"{}\" kind=\"{}\"];",
                dot_escape(&node.id),
                escaped_label,
                node.kind,
            );
        }
        for edge in &edges {
            let label = if self.config.include_weights {
                edge.weight.map_or_else(|| edge.relation.clone(), |w| format!("{} ({})", edge.relation, w))
            } else {
                edge.relation.clone()
            };
            let _ = writeln!(
                dot,
                "  \"{}\" -> \"{}\" [label=\"{}\"];",
                dot_escape(&edge.from),
                dot_escape(&edge.to),
                label.replace('"', "\\\""),
            );
        }
        dot.push_str("}\n");
        let data = dot.into_bytes();
        stats.output_bytes = data.len();
        ExportResult { data, format: ExportFormat::Dot, stats }
    }

    // -----------------------------------------------------------------------
    // CSV export
    // -----------------------------------------------------------------------

    fn export_csv(&self, graph: &KnowledgeGraph) -> ExportResult {
        let (nodes, edges, mut stats) = self.filter_graph(graph);
        let mut csv = String::from("id,label,kind\n");
        for node in &nodes {
            let _ = writeln!(
                csv,
                "{},{},{}",
                csv_escape(&node.id),
                csv_escape(&node.label),
                csv_escape(&node.kind),
            );
        }
        csv.push_str("\nfrom,to,relation,weight\n");
        for edge in &edges {
            let weight = edge.weight.map_or(String::new(), |w| w.to_string());
            let _ = writeln!(
                csv,
                "{},{},{},{}",
                csv_escape(&edge.from),
                csv_escape(&edge.to),
                csv_escape(&edge.relation),
                weight,
            );
        }
        let data = csv.into_bytes();
        stats.output_bytes = data.len();
        ExportResult { data, format: ExportFormat::Csv, stats }
    }

    // -----------------------------------------------------------------------
    // GEXF export
    // -----------------------------------------------------------------------

    fn export_gexf(&self, graph: &KnowledgeGraph) -> ExportResult {
        let (nodes, edges, mut stats) = self.filter_graph(graph);
        let mut xml = String::from(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<gexf xmlns="http://gexf.net/1.3" version="1.3">
  <graph defaultedgetype="directed">
    <nodes>
"#,
        );
        for node in &nodes {
            let _ = writeln!(
                xml,
                "      <node id=\"{}\" label=\"{}\"/>",
                xml_escape(&node.id),
                xml_escape(&node.label),
            );
        }
        xml.push_str("    </nodes>\n    <edges>\n");
        for (i, edge) in edges.iter().enumerate() {
            let weight_attr = edge.weight.map_or(String::new(), |w| {
                format!(" weight=\"{w}\"")
            });
            let _ = writeln!(
                xml,
                "      <edge id=\"{i}\" source=\"{}\" target=\"{}\" label=\"{}\"{}/>",
                xml_escape(&edge.from),
                xml_escape(&edge.to),
                xml_escape(&edge.relation),
                weight_attr,
            );
        }
        xml.push_str("    </edges>\n  </graph>\n</gexf>\n");
        let data = xml.into_bytes();
        stats.output_bytes = data.len();
        ExportResult { data, format: ExportFormat::Gexf, stats }
    }

    // -----------------------------------------------------------------------
    // Filter helpers
    // -----------------------------------------------------------------------

    fn filter_graph<'a>(
        &self,
        graph: &'a KnowledgeGraph,
    ) -> (Vec<&'a KnowledgeNode>, Vec<&'a KnowledgeEdge>, ExportStats) {
        let kind_filter = self.config.node_kind_filter.as_deref();
        let rel_filter = self.config.relation_filter.as_deref();
        let mut stats = ExportStats::default();

        let nodes: Vec<&KnowledgeNode> = graph.nodes.values().filter(|n| {
            if let Some(kinds) = kind_filter
                && !kinds.contains(&n.kind) {
                    return false;
                }
            true
        }).collect();
        stats.nodes_exported = nodes.len();
        stats.nodes_skipped = graph.node_count().saturating_sub(nodes.len());

        let node_ids: std::collections::HashSet<&str> =
            nodes.iter().map(|n| n.id.as_str()).collect();

        let edges: Vec<&KnowledgeEdge> = graph.edges.iter().filter(|e| {
            if let Some(rels) = rel_filter
                && !rels.contains(&e.relation) {
                    return false;
                }
            node_ids.contains(e.from.as_str()) && node_ids.contains(e.to.as_str())
        }).collect();
        stats.edges_exported = edges.len();
        stats.edges_skipped = graph.edge_count().saturating_sub(edges.len());

        (nodes, edges, stats)
    }
}

impl Default for KnowledgeExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for KnowledgeExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KnowledgeExporter(format_count=6)")
    }
}

// ---------------------------------------------------------------------------
// export_to_json — primary entry point
// ---------------------------------------------------------------------------

/// Export a [`KnowledgeGraph`] to a compact JSON string.
///
/// # Errors
///
/// Returns [`ExportError`] if JSON serialisation fails.
pub fn export_to_json(graph: &KnowledgeGraph) -> Result<ExportResult, ExportError> {
    KnowledgeExporter::new().export(graph, ExportFormat::JsonCompact)
}

// ---------------------------------------------------------------------------
// String escaping helpers
// ---------------------------------------------------------------------------

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn dot_escape(s: &str) -> String {
    s.replace('"', "\\\"")
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KnowledgeGraph, KnowledgeNode, KnowledgeEdge};

    fn sample_graph() -> KnowledgeGraph {
        let mut g = KnowledgeGraph::new();
        g.add_node(KnowledgeNode::new("f1", "main", "function"));
        g.add_node(KnowledgeNode::new("f2", "helper", "function"));
        g.add_node(KnowledgeNode::new("t1", "MyType", "type"));
        g.add_edge(KnowledgeEdge { from: "f1".into(), to: "f2".into(), relation: "calls".into(), weight: Some(3) });
        g.add_edge(KnowledgeEdge { from: "f2".into(), to: "t1".into(), relation: "references".into(), weight: None });
        g
    }

    #[test]
    fn test_export_to_json_basic() {
        let g = sample_graph();
        let result = export_to_json(&g).unwrap();
        assert!(!result.data.is_empty());
        let s = result.as_str().unwrap();
        assert!(s.contains("\"nodes\""));
        assert!(s.contains("\"edges\""));
    }

    #[test]
    fn test_export_json_pretty() {
        let g = sample_graph();
        let exporter = KnowledgeExporter::new();
        let result = exporter.export(&g, ExportFormat::JsonPretty).unwrap();
        let s = result.as_str().unwrap();
        assert!(s.contains('\n'));
    }

    #[test]
    fn test_export_graphml() {
        let g = sample_graph();
        let exporter = KnowledgeExporter::new();
        let result = exporter.export(&g, ExportFormat::GraphMl).unwrap();
        let s = result.as_str().unwrap();
        assert!(s.contains("<graphml"));
        assert!(s.contains("<node "));
        assert!(s.contains("<edge "));
    }

    #[test]
    fn test_export_dot() {
        let g = sample_graph();
        let exporter = KnowledgeExporter::new();
        let result = exporter.export(&g, ExportFormat::Dot).unwrap();
        let s = result.as_str().unwrap();
        assert!(s.contains("digraph G"));
        assert!(s.contains("->"));
    }

    #[test]
    fn test_export_csv() {
        let g = sample_graph();
        let exporter = KnowledgeExporter::new();
        let result = exporter.export(&g, ExportFormat::Csv).unwrap();
        let s = result.as_str().unwrap();
        assert!(s.contains("id,label,kind"));
        assert!(s.contains("from,to,relation,weight"));
    }

    #[test]
    fn test_export_gexf() {
        let g = sample_graph();
        let exporter = KnowledgeExporter::new();
        let result = exporter.export(&g, ExportFormat::Gexf).unwrap();
        let s = result.as_str().unwrap();
        assert!(s.contains("<gexf"));
        assert!(s.contains("<nodes>"));
        assert!(s.contains("<edges>"));
    }

    #[test]
    fn test_export_filter_node_kinds() {
        let g = sample_graph();
        let exporter = KnowledgeExporter::new()
            .filter_node_kinds(vec!["function".to_string()]);
        let result = exporter.export(&g, ExportFormat::JsonCompact).unwrap();
        let s = result.as_str().unwrap();
        // MyType (kind=type) should not appear in nodes
        assert!(!s.contains("\"MyType\""));
        assert_eq!(result.stats.nodes_exported, 2);
    }

    #[test]
    fn test_export_filter_relations() {
        let g = sample_graph();
        let exporter = KnowledgeExporter::new()
            .filter_relations(vec!["calls".to_string()]);
        let result = exporter.export(&g, ExportFormat::JsonCompact).unwrap();
        assert_eq!(result.stats.edges_exported, 1);
    }

    #[test]
    fn test_export_exclude_metadata() {
        let g = sample_graph();
        let exporter = KnowledgeExporter::new().include_metadata(false);
        let result = exporter.export(&g, ExportFormat::JsonPretty).unwrap();
        let s = result.as_str().unwrap();
        // metadata fields should be empty objects
        assert!(s.contains("\"metadata\": {}"));
    }

    #[test]
    fn test_export_stats() {
        let g = sample_graph();
        let result = export_to_json(&g).unwrap();
        assert_eq!(result.stats.nodes_exported, 3);
        assert_eq!(result.stats.edges_exported, 2);
        assert!(result.stats.output_bytes > 0);
    }

    #[test]
    fn test_export_format_names() {
        assert_eq!(ExportFormat::JsonCompact.name(), "json-compact");
        assert_eq!(ExportFormat::GraphMl.name(), "graphml");
        assert_eq!(ExportFormat::Dot.name(), "dot");
        assert_eq!(ExportFormat::Csv.name(), "csv");
        assert_eq!(ExportFormat::Gexf.name(), "gexf");
    }

    #[test]
    fn test_export_format_is_json() {
        assert!(ExportFormat::JsonCompact.is_json());
        assert!(ExportFormat::JsonPretty.is_json());
        assert!(!ExportFormat::Dot.is_json());
    }

    #[test]
    fn test_export_format_is_xml() {
        assert!(ExportFormat::GraphMl.is_xml());
        assert!(ExportFormat::Gexf.is_xml());
        assert!(!ExportFormat::Csv.is_xml());
    }

    #[test]
    fn test_export_result_size() {
        let g = sample_graph();
        let result = export_to_json(&g).unwrap();
        assert_eq!(result.size_bytes(), result.data.len());
    }

    #[test]
    fn test_xml_escape() {
        assert_eq!(xml_escape("a & b < c > d"), "a &amp; b &lt; c &gt; d");
        assert_eq!(xml_escape("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn test_csv_escape_with_comma() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("plain"), "plain");
    }
}
