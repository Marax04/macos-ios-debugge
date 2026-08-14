//! Knowledge graph export to multiple formats.
//!
//! Supported output formats:
//! * **GraphML** — XML format used by Gephi, yEd, Cytoscape.
//! * **GEXF** — Gephi Extended Exchange Format (supports dynamic graphs).
//! * **DOT** — Graphviz DOT language.
//! * **JSON** — Cytoscape.js-compatible JSON (`{ nodes: [...], edges: [...] }`).
//! * **Neo4j Cypher** — batch `MERGE` statements for Neo4j import.
//! * **CSV** — edge list CSV (`source,target,kind,weight`).
//!
//! All exporters respect optional attribute filters so callers can exclude
//! sensitive or irrelevant properties.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as FmtWrite;
use std::io::Write;

use serde::{Deserialize, Serialize};

// ── Graph model (self-contained for export layer) ─────────────────────────────

/// A node ready for export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportNode {
    pub id: String,
    pub label: String,
    pub node_type: String,
    pub attributes: HashMap<String, String>,
}

/// An edge ready for export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub kind: String,
    pub weight: f64,
    pub directed: bool,
    pub attributes: HashMap<String, String>,
}

/// A complete graph ready for export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportGraph {
    pub name: String,
    pub nodes: Vec<ExportNode>,
    pub edges: Vec<ExportEdge>,
    /// Schema: `attr_name` → `attr_type` ("string"|"integer"|"double"|"boolean")
    pub node_schema: HashMap<String, String>,
    pub edge_schema: HashMap<String, String>,
}

impl ExportGraph {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            nodes: Vec::new(),
            edges: Vec::new(),
            node_schema: HashMap::default(),
            edge_schema: HashMap::default(),
        }
    }

    pub fn add_node(&mut self, node: ExportNode) {
        self.nodes.push(node);
    }

    pub fn add_edge(&mut self, edge: ExportEdge) {
        self.edges.push(edge);
    }

    pub fn register_node_attr(&mut self, name: impl Into<String>, ty: impl Into<String>) {
        self.node_schema.insert(name.into(), ty.into());
    }

    pub fn register_edge_attr(&mut self, name: impl Into<String>, ty: impl Into<String>) {
        self.edge_schema.insert(name.into(), ty.into());
    }
}

// ── Filter spec ───────────────────────────────────────────────────────────────

/// Attribute filter applied during export.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExportFilter {
    /// Node types to include (empty = all).
    pub include_node_types: HashSet<String>,
    /// Node attribute keys to include (empty = all).
    pub include_node_attrs: HashSet<String>,
    /// Edge kinds to include (empty = all).
    pub include_edge_kinds: HashSet<String>,
    /// Edge attribute keys to include (empty = all).
    pub include_edge_attrs: HashSet<String>,
    /// Minimum edge weight to include.
    pub min_edge_weight: f64,
    /// Maximum number of nodes (0 = unlimited, sorted by… strategy).
    pub max_nodes: usize,
}

impl ExportFilter {
    #[must_use]
    pub fn accepts_node(&self, node: &ExportNode) -> bool {
        if !self.include_node_types.is_empty()
            && !self.include_node_types.contains(&node.node_type)
        {
            return false;
        }
        true
    }
 #[must_use]
    pub fn accepts_edge(&self, edge: &ExportEdge) -> bool {
        if !self.include_edge_kinds.is_empty()
            && !self.include_edge_kinds.contains(&edge.kind)
        {
            return false;
        }
        if edge.weight < self.min_edge_weight {
            return false;
        }
        true
    }

    #[must_use]
    pub fn filter_node_attrs<'a>(&self, attrs: &'a HashMap<String, String>) -> HashMap<String, &'a str> {
        if self.include_node_attrs.is_empty() {
            return attrs.iter().map(|(k, v)| (k.clone(), v.as_str())).collect();
        }
        attrs
            .iter()
            .filter(|(k, _)| self.include_node_attrs.contains(*k))
            .map(|(k, v)| (k.clone(), v.as_str()))
            .collect()
    }

    #[must_use]
    pub fn filter_edge_attrs<'a>(&self, attrs: &'a HashMap<String, String>) -> HashMap<String, &'a str> {
        if self.include_edge_attrs.is_empty() {
            return attrs.iter().map(|(k, v)| (k.clone(), v.as_str())).collect();
        }
        attrs
            .iter()
            .filter(|(k, _)| self.include_edge_attrs.contains(*k))
            .map(|(k, v)| (k.clone(), v.as_str()))
            .collect()
    }
}

// ── GraphML exporter ──────────────────────────────────────────────────────────

/// Exports an [`ExportGraph`] to `GraphML` XML.
pub struct GraphMLExporter;

impl GraphMLExporter {
    #[must_use]
    pub fn export(graph: &ExportGraph, filter: &ExportFilter) -> String {
        let mut out = String::with_capacity(4096);

        out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.push_str("<graphml xmlns=\"http://graphml.graphdrawing.org/graphml\"\n");
        out.push_str("         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n");
        out.push_str("         xsi:schemaLocation=\"http://graphml.graphdrawing.org/graphml\n");
        out.push_str("           http://graphml.graphdrawing.org/graphml/1.0/graphml.xsd\">\n");

        // Attribute keys
        out.push_str("  <key id=\"klabel\" for=\"node\" attr.name=\"label\" attr.type=\"string\"/>\n");
        out.push_str("  <key id=\"ktype\" for=\"node\" attr.name=\"type\" attr.type=\"string\"/>\n");
        for (attr, ty) in &graph.node_schema {
            let gml_type = match ty.as_str() {
                "integer" => "int",
                "double" => "double",
                "boolean" => "boolean",
                _ => "string",
            };
            writeln!(out, "  <key id=\"n_{attr}\" for=\"node\" attr.name=\"{attr}\" attr.type=\"{gml_type}\"/>").unwrap();
        }
        out.push_str("  <key id=\"kweight\" for=\"edge\" attr.name=\"weight\" attr.type=\"double\"/>\n");
        out.push_str("  <key id=\"kkind\" for=\"edge\" attr.name=\"kind\" attr.type=\"string\"/>\n");
        for (attr, ty) in &graph.edge_schema {
            let gml_type = match ty.as_str() {
                "integer" => "int",
                "double" => "double",
                "boolean" => "boolean",
                _ => "string",
            };
            writeln!(out, "  <key id=\"e_{attr}\" for=\"edge\" attr.name=\"{attr}\" attr.type=\"{gml_type}\"/>").unwrap();
        }

        out.push_str("  <graph id=\"G\" edgedefault=\"directed\">\n");

        // Nodes
        for node in &graph.nodes {
            if !filter.accepts_node(node) {
                continue;
            }
            writeln!(out, "    <node id=\"{}\">", xml_escape(&node.id)).unwrap();
            writeln!(out, "      <data key=\"klabel\">{}</data>",
                xml_escape(&node.label)
            ).unwrap();
            writeln!(out, "      <data key=\"ktype\">{}</data>",
                xml_escape(&node.node_type)
            ).unwrap();
            let attrs = filter.filter_node_attrs(&node.attributes);
            for (k, v) in &attrs {
                writeln!(out, "      <data key=\"n_{k}\">{}</data>",
                    xml_escape(v)
                ).unwrap();
            }
            out.push_str("    </node>\n");
        }

        // Edges
        for edge in &graph.edges {
            if !filter.accepts_edge(edge) {
                continue;
            }
            writeln!(out, "    <edge id=\"{}\" source=\"{}\" target=\"{}\">",
                xml_escape(&edge.id),
                xml_escape(&edge.source),
                xml_escape(&edge.target)
            ).unwrap();
            writeln!(out, "      <data key=\"kweight\">{}</data>", edge.weight).unwrap();
            writeln!(out, "      <data key=\"kkind\">{}</data>",
                xml_escape(&edge.kind)
            ).unwrap();
            let attrs = filter.filter_edge_attrs(&edge.attributes);
            for (k, v) in &attrs {
                writeln!(out, "      <data key=\"e_{k}\">{}</data>",
                    xml_escape(v)
                ).unwrap();
            }
            out.push_str("    </edge>\n");
        }

        out.push_str("  </graph>\n");
        out.push_str("</graphml>\n");
        out
    }
}

// ── GEXF exporter ────────────────────────────────────────────────────────────

/// Exports to Gephi Extended Exchange Format (GEXF 1.3).
pub struct GEXFExporter;

impl GEXFExporter {
    #[must_use]
    pub fn export(graph: &ExportGraph, filter: &ExportFilter) -> String {
        let mut out = String::with_capacity(4096);
        out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.push_str("<gexf xmlns=\"http://gexf.net/1.3\" version=\"1.3\">\n");
        out.push_str("  <graph defaultedgetype=\"directed\">\n");

        // Node attributes
        out.push_str("    <attributes class=\"node\">\n");
        out.push_str("      <attribute id=\"0\" title=\"type\" type=\"string\"/>\n");
        for (i, (attr, _)) in graph.node_schema.iter().enumerate() {
            writeln!(out, "      <attribute id=\"n{}\" title=\"{}\" type=\"string\"/>",
                i + 1, xml_escape(attr)
            ).unwrap();
        }
        out.push_str("    </attributes>\n");

        // Edge attributes
        out.push_str("    <attributes class=\"edge\">\n");
        out.push_str("      <attribute id=\"e0\" title=\"kind\" type=\"string\"/>\n");
        out.push_str("    </attributes>\n");

        // Nodes
        out.push_str("    <nodes>\n");
        for node in &graph.nodes {
            if !filter.accepts_node(node) { continue; }
            writeln!(out, "      <node id=\"{}\" label=\"{}\">",
                xml_escape(&node.id), xml_escape(&node.label)
            ).unwrap();
            out.push_str("        <attvalues>\n");
            writeln!(out, "          <attvalue for=\"0\" value=\"{}\"/>",
                xml_escape(&node.node_type)
            ).unwrap();
            out.push_str("        </attvalues>\n");
            out.push_str("      </node>\n");
        }
        out.push_str("    </nodes>\n");

        // Edges
        out.push_str("    <edges>\n");
        for edge in &graph.edges {
            if !filter.accepts_edge(edge) { continue; }
            writeln!(out, "      <edge id=\"{}\" source=\"{}\" target=\"{}\" weight=\"{}\">",
                xml_escape(&edge.id), xml_escape(&edge.source),
                xml_escape(&edge.target), edge.weight
            ).unwrap();
            out.push_str("        <attvalues>\n");
            writeln!(out, "          <attvalue for=\"e0\" value=\"{}\"/>",
                xml_escape(&edge.kind)
            ).unwrap();
            out.push_str("        </attvalues>\n");
            out.push_str("      </edge>\n");
        }
        out.push_str("    </edges>\n");
        out.push_str("  </graph>\n");
        out.push_str("</gexf>\n");
        out
    }
}

// ── DOT exporter ──────────────────────────────────────────────────────────────

/// Exports to Graphviz DOT format.
pub struct DotExporter;

impl DotExporter {
    #[must_use]
    pub fn export(graph: &ExportGraph, filter: &ExportFilter) -> String {
        let mut out = String::with_capacity(2048);
        writeln!(out, "digraph \"{}\" {{", dot_escape(&graph.name)).unwrap();
        out.push_str("  graph [rankdir=LR];\n");
        out.push_str("  node [shape=box, style=filled, fillcolor=lightblue];\n");

        for node in &graph.nodes {
            if !filter.accepts_node(node) { continue; }
            let color = Self::color_for_type(&node.node_type);
            writeln!(out, "  \"{}\" [label=\"{}\", fillcolor=\"{}\", type=\"{}\"];",
                dot_escape(&node.id),
                dot_escape(&node.label),
                color,
                dot_escape(&node.node_type)
            ).unwrap();
        }

        for edge in &graph.edges {
            if !filter.accepts_edge(edge) { continue; }
            writeln!(out, "  \"{}\" -> \"{}\" [label=\"{}\", weight={:.2}];",
                dot_escape(&edge.source),
                dot_escape(&edge.target),
                dot_escape(&edge.kind),
                edge.weight
            ).unwrap();
        }

        out.push_str("}\n");
        out
    }

    fn color_for_type(ty: &str) -> &'static str {
        match ty {
            "IP" => "#FFB3B3",
            "Domain" => "#B3FFB3",
            "Hash" => "#B3B3FF",
            "Actor" => "#FFD9B3",
            "Malware" => "#FFB3FF",
            "Campaign" => "#FFFFB3",
            _ => "#E0E0E0",
        }
    }
}

// ── Cytoscape JSON exporter ───────────────────────────────────────────────────

/// Exports to Cytoscape.js-compatible JSON.
pub struct CytoscapeExporter;

impl CytoscapeExporter {
    #[must_use]
    pub fn export(graph: &ExportGraph, filter: &ExportFilter) -> String {
        let mut nodes_json: Vec<String> = Vec::new();
        let mut edges_json: Vec<String> = Vec::new();

        for node in &graph.nodes {
            if !filter.accepts_node(node) { continue; }
            let attrs_json = node.attributes.iter()
                .map(|(k, v)| format!("\"{}\":\"{}\"", json_escape(k), json_escape(v)))
                .collect::<Vec<_>>()
                .join(",");
            nodes_json.push(format!(
                "{{\"data\":{{\"id\":\"{}\",\"label\":\"{}\",\"type\":\"{}\"{}}}}}",
                json_escape(&node.id),
                json_escape(&node.label),
                json_escape(&node.node_type),
                if attrs_json.is_empty() { String::new() } else { format!(",{attrs_json}") }
            ));
        }

        for edge in &graph.edges {
            if !filter.accepts_edge(edge) { continue; }
            edges_json.push(format!(
                "{{\"data\":{{\"id\":\"{}\",\"source\":\"{}\",\"target\":\"{}\",\"kind\":\"{}\",\"weight\":{}}}}}",
                json_escape(&edge.id),
                json_escape(&edge.source),
                json_escape(&edge.target),
                json_escape(&edge.kind),
                edge.weight
            ));
        }

        format!(
            "{{\"elements\":{{\"nodes\":[{}],\"edges\":[{}]}}}}",
            nodes_json.join(","),
            edges_json.join(",")
        )
    }
}

// ── Neo4j Cypher exporter ─────────────────────────────────────────────────────

/// Exports batch `MERGE` statements for Neo4j import.
pub struct Neo4jCypherExporter;

impl Neo4jCypherExporter {
    #[must_use]
    pub fn export(graph: &ExportGraph, filter: &ExportFilter) -> String {
        let mut out = String::with_capacity(4096);
        out.push_str("// Neo4j Cypher batch import\n");
        out.push_str("// Run with: cypher-shell -f import.cypher\n\n");

        for node in &graph.nodes {
            if !filter.accepts_node(node) { continue; }
            let props: Vec<String> = std::iter::once(format!("label:\"{}\"", cypher_escape(&node.label)))
                .chain(node.attributes.iter()
                    .map(|(k, v)| format!("{}:\"{}\"", cypher_escape(k), cypher_escape(v))))
                .collect();
            writeln!(out, "MERGE (n:{} {{id:\"{}\", {}}});",
                capitalize(&node.node_type),
                cypher_escape(&node.id),
                props.join(", ")
            ).unwrap();
        }

        out.push('\n');
        for edge in &graph.edges {
            if !filter.accepts_edge(edge) { continue; }
            writeln!(out, "MATCH (a {{id:\"{}\"}}), (b {{id:\"{}\"}}) MERGE (a)-[:{} {{weight:{}}}]->(b);",
                cypher_escape(&edge.source),
                cypher_escape(&edge.target),
                edge.kind.to_uppercase().replace(' ', "_"),
                edge.weight
            ).unwrap();
        }

        out
    }
}

// ── CSV edge list exporter ────────────────────────────────────────────────────

/// Exports a simple CSV edge list.
pub struct CsvExporter;

impl CsvExporter {
    #[must_use]
    pub fn export_edges(graph: &ExportGraph, filter: &ExportFilter) -> String {
        let mut out = String::from("source,target,kind,weight,directed\n");
        for edge in &graph.edges {
            if !filter.accepts_edge(edge) { continue; }
            writeln!(out, "{},{},{},{},{}",
                csv_escape(&edge.source),
                csv_escape(&edge.target),
                csv_escape(&edge.kind),
                edge.weight,
                if edge.directed { "true" } else { "false" }
            ).unwrap();
        }
        out
    }

    #[must_use]
    pub fn export_nodes(graph: &ExportGraph, filter: &ExportFilter) -> String {
        let mut out = String::from("id,label,type\n");
        for node in &graph.nodes {
            if !filter.accepts_node(node) { continue; }
            writeln!(out, "{},{},{}",
                csv_escape(&node.id),
                csv_escape(&node.label),
                csv_escape(&node.node_type)
            ).unwrap();
        }
        out
    }
}

// ── Streaming writers ─────────────────────────────────────────────────────────

/// Write any supported export format to a [`std::io::Write`] sink, avoiding the
/// need for callers to allocate the full output string.
///
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn write_export<W: Write>(
    writer: &mut W,
    graph: &ExportGraph,
    filter: &ExportFilter,
    format: ExportFormat,
) -> std::io::Result<()> {
    let body = match format {
        ExportFormat::GraphML => GraphMLExporter::export(graph, filter),
        ExportFormat::GEXF => GEXFExporter::export(graph, filter),
        ExportFormat::Dot => DotExporter::export(graph, filter),
        ExportFormat::Json => CytoscapeExporter::export(graph, filter),
        ExportFormat::Cypher => Neo4jCypherExporter::export(graph, filter),
        ExportFormat::CsvEdges => CsvExporter::export_edges(graph, filter),
        ExportFormat::CsvNodes => CsvExporter::export_nodes(graph, filter),
    };
    writer.write_all(body.as_bytes())
}

/// Supported export formats for [`write_export`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    GraphML,
    GEXF,
    Dot,
    Json,
    Cypher,
    CsvEdges,
    CsvNodes,
}

// ── Utilities ─────────────────────────────────────────────────────────────────

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

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn cypher_escape(s: &str) -> String {
    s.replace('\'', "\\'").replace('"', "\\\"")
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next().map_or_else(String::new, |f| f.to_uppercase().collect::<String>() + c.as_str())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_graph() -> ExportGraph {
        let mut g = ExportGraph::new("TestGraph");
        g.register_node_attr("confidence", "double");
        g.register_edge_attr("timestamp", "integer");

        let mut n1 = ExportNode {
            id: "n1".into(),
            label: "evil.com".into(),
            node_type: "Domain".into(),
            attributes: HashMap::default(),
        };
        n1.attributes.insert("confidence".into(), "0.9".into());

        let n2 = ExportNode {
            id: "n2".into(),
            label: "1.2.3.4".into(),
            node_type: "IP".into(),
            attributes: HashMap::default(),
        };

        g.add_node(n1);
        g.add_node(n2);

        let e1 = ExportEdge {
            id: "e1".into(),
            source: "n1".into(),
            target: "n2".into(),
            kind: "ResolvesTo".into(),
            weight: 0.8,
            directed: true,
            attributes: HashMap::default(),
        };
        g.add_edge(e1);
        g
    }

    #[test]
    fn graphml_contains_nodes() {
        let g = sample_graph();
        let out = GraphMLExporter::export(&g, &ExportFilter::default());
        assert!(out.contains("evil.com"));
        assert!(out.contains("1.2.3.4"));
        assert!(out.contains("ResolvesTo"));
    }

    #[test]
    fn dot_contains_edge() {
        let g = sample_graph();
        let out = DotExporter::export(&g, &ExportFilter::default());
        assert!(out.contains("->"));
        assert!(out.contains("ResolvesTo"));
    }

    #[test]
    fn cytoscape_valid_json() {
        let g = sample_graph();
        let out = CytoscapeExporter::export(&g, &ExportFilter::default());
        assert!(out.starts_with("{\"elements\""));
        assert!(out.contains("evil.com"));
    }

    #[test]
    fn neo4j_contains_merge() {
        let g = sample_graph();
        let out = Neo4jCypherExporter::export(&g, &ExportFilter::default());
        assert!(out.contains("MERGE"));
        assert!(out.contains("MATCH"));
    }

    #[test]
    fn csv_header() {
        let g = sample_graph();
        let out = CsvExporter::export_edges(&g, &ExportFilter::default());
        assert!(out.starts_with("source,target,kind,weight,directed"));
        assert!(out.contains("n1,n2,ResolvesTo"));
    }

    #[test]
    fn filter_by_edge_kind() {
        let g = sample_graph();
        let mut filter = ExportFilter::default();
        filter.include_edge_kinds.insert("NonExistentEdge".into());
        let out = CsvExporter::export_edges(&g, &filter);
        // Only header line
        assert_eq!(out.lines().count(), 1);
    }

    #[test]
    fn gexf_valid_structure() {
        let g = sample_graph();
        let out = GEXFExporter::export(&g, &ExportFilter::default());
        assert!(out.contains("<gexf"));
        assert!(out.contains("evil.com"));
    }
}
