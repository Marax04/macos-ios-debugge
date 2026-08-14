//! `jadx_call_graph_builder` — Build a method call graph from JADX decompiled sources.
//!
//! This module parses method bodies produced by JADX and extracts call sites to
//! build a directed call graph backed by [`petgraph`].  Each node is a method
//! identified by its fully-qualified signature; each edge records the call site.

use std::collections::HashMap;

use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};

use crate::jadx_output_parser::JadxClass;
use crate::JadxError;

// ─────────────────────────────────────────────────────────────────────────────
// MethodId — stable identifier for a method node
// ─────────────────────────────────────────────────────────────────────────────

/// A unique, stable identifier for a method in the call graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MethodId {
    /// Fully-qualified class name.
    pub class_fqn: String,
    /// Method simple name.
    pub method_name: String,
    /// Descriptor-style param string (comma-joined types).
    pub descriptor: String,
}

impl MethodId {
    /// Construct a `MethodId`.
    pub fn new(class_fqn: impl Into<String>, method_name: impl Into<String>, descriptor: impl Into<String>) -> Self {
        Self {
            class_fqn: class_fqn.into(),
            method_name: method_name.into(),
            descriptor: descriptor.into(),
        }
    }

    /// Return the dot-qualified display form `com.example.Foo.bar(int)`.
    #[must_use]
    pub fn display(&self) -> String {
        format!("{}.{}({})", self.class_fqn, self.method_name, self.descriptor)
    }
}

impl std::fmt::Display for MethodId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JadxCallEdge — call-site metadata stored on graph edges
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata attached to a directed call-graph edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JadxCallEdge {
    /// 1-based line number in the source file where the call occurs.
    pub call_line: usize,
    /// The raw call expression as it appears in the source.
    pub raw_expr: String,
    /// Whether the call is on `super`.
    pub is_super_call: bool,
    /// Whether the call is static (`ClassName.method()`).
    pub is_static_call: bool,
    /// Whether the call is to an interface method (heuristic).
    pub is_interface_call: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// CallGraphNode — metadata stored on graph nodes
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata for a method node in the call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphNode {
    pub id: MethodId,
    pub is_native: bool,
    pub is_static: bool,
    pub is_abstract: bool,
    pub return_type: String,
    pub params: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// JadxCallGraph — the built graph
// ─────────────────────────────────────────────────────────────────────────────

/// A directed call graph built from JADX-decompiled Java source.
///
/// Nodes are methods; edges are call sites.
pub struct JadxCallGraph {
    /// Underlying petgraph directed graph.
    pub graph: DiGraph<CallGraphNode, JadxCallEdge>,
    /// Map from [`MethodId`] to its `NodeIndex` in `graph`.
    node_map: HashMap<MethodId, NodeIndex>,
}

impl JadxCallGraph {
    fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
        }
    }

    /// Return the `NodeIndex` for a method, inserting a placeholder if absent.
    fn get_or_insert(&mut self, id: MethodId, info: Option<&CallGraphNode>) -> NodeIndex {
        if let Some(&n) = self.node_map.get(&id) {
            return n;
        }
        let node = info.cloned().unwrap_or_else(|| CallGraphNode {
            id: id.clone(),
            is_native: false,
            is_static: false,
            is_abstract: false,
            return_type: String::from("?"),
            params: Vec::new(),
        });
        let n = self.graph.add_node(node);
        self.node_map.insert(id, n);
        n
    }

    /// Look up the `NodeIndex` for a `MethodId`.
    #[must_use]
    pub fn node_index(&self, id: &MethodId) -> Option<NodeIndex> {
        self.node_map.get(id).copied()
    }

    /// Total number of method nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Total number of call edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Returns `true` if a direct call edge exists from `caller` to `callee`.
    #[must_use]
    pub fn has_edge(&self, caller: &MethodId, callee: &MethodId) -> bool {
        match (self.node_map.get(caller), self.node_map.get(callee)) {
            (Some(&a), Some(&b)) => self.graph.contains_edge(a, b),
            _ => false,
        }
    }

    /// Callees of a method (direct calls).
    #[must_use]
    pub fn callees(&self, id: &MethodId) -> Vec<&CallGraphNode> {
        let Some(&n) = self.node_map.get(id) else { return vec![] };
        self.graph
            .neighbors(n)
            .filter_map(|nb| self.graph.node_weight(nb))
            .collect()
    }

    /// Callers of a method (reverse edges).
    #[must_use]
    pub fn callers(&self, id: &MethodId) -> Vec<&CallGraphNode> {
        use petgraph::Direction;
        let Some(&n) = self.node_map.get(id) else { return vec![] };
        self.graph
            .neighbors_directed(n, Direction::Incoming)
            .filter_map(|nb| self.graph.node_weight(nb))
            .collect()
    }

    /// All methods that are never called by any method in the graph (roots).
    #[must_use]
    pub fn roots(&self) -> Vec<&CallGraphNode> {
        use petgraph::Direction;
        self.graph
            .node_indices()
            .filter(|&n| self.graph.neighbors_directed(n, Direction::Incoming).count() == 0)
            .filter_map(|n| self.graph.node_weight(n))
            .collect()
    }

    /// All methods that call no other method in the graph (leaves / sinks).
    #[must_use]
    pub fn leaves(&self) -> Vec<&CallGraphNode> {
        self.graph
            .node_indices()
            .filter(|&n| self.graph.neighbors(n).count() == 0)
            .filter_map(|n| self.graph.node_weight(n))
            .collect()
    }

    /// Find a shortest call path from `src` to `dst` (BFS).
    #[must_use]
    pub fn shortest_path(&self, src: &MethodId, dst: &MethodId) -> Option<Vec<MethodId>> {
        use std::collections::VecDeque;
        let start = *self.node_map.get(src)?;
        let end = *self.node_map.get(dst)?;
        let mut visited = HashMap::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        visited.insert(start, None::<NodeIndex>);
        while let Some(cur) = queue.pop_front() {
            if cur == end {
                // Reconstruct path
                let mut path = Vec::new();
                let mut node = end;
                loop {
                    path.push(self.graph[node].id.clone());
                    match visited[&node] {
                        None => break,
                        Some(prev) => node = prev,
                    }
                }
                path.reverse();
                return Some(path);
            }
            for nb in self.graph.neighbors(cur) {
                if let std::collections::hash_map::Entry::Vacant(e) = visited.entry(nb) {
                    e.insert(Some(cur));
                    queue.push_back(nb);
                }
            }
        }
        None
    }

    /// All native methods referenced in the graph.
    #[must_use]
    pub fn native_methods(&self) -> Vec<&CallGraphNode> {
        self.graph
            .node_weights()
            .filter(|n| n.is_native)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JadxCallGraphBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a [`JadxCallGraph`] from a collection of [`JadxClass`] values.
///
/// # Example
///
/// ```no_run
/// use rustre_mobile_jadx::jadx_call_graph_builder::JadxCallGraphBuilder;
/// use rustre_mobile_jadx::jadx_output_parser::parse_jadx_dir;
/// use std::path::Path;
///
/// let classes = parse_jadx_dir(Path::new("/tmp/jadx_out")).unwrap();
/// let graph = JadxCallGraphBuilder::new().build(&classes).unwrap();
/// println!("Nodes: {}, Edges: {}", graph.node_count(), graph.edge_count());
/// ```
#[derive(Debug, Clone)]
pub struct JadxCallGraphBuilder {
    /// If true, create stub nodes for external callees not present in the class list.
    pub include_external: bool,
    /// Maximum number of call sites to extract per method body (safety cap).
    pub max_calls_per_method: usize,
}

impl Default for JadxCallGraphBuilder {
    fn default() -> Self {
        Self {
            include_external: true,
            max_calls_per_method: 1024,
        }
    }
}

impl JadxCallGraphBuilder {
    /// Create a builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a call graph from a list of classes.
    ///
    /// # Errors
    /// Currently infallible but returns `JadxError` for future compatibility.
    pub fn build(&self, classes: &[JadxClass]) -> Result<JadxCallGraph, JadxError> {
        let mut cg = JadxCallGraph::new();

        // First pass: register all known methods as nodes.
        for cls in classes {
            for method in &cls.methods {
                let id = MethodId::new(
                    cls.fqn.clone(),
                    method.name.clone(),
                    method.param_descriptor(),
                );
                let node = CallGraphNode {
                    id: id.clone(),
                    is_native: method.is_native,
                    is_static: method.is_static,
                    is_abstract: method.is_abstract,
                    return_type: method.return_type.clone(),
                    params: method.params.clone(),
                };
                cg.get_or_insert(id, Some(&node));
            }
        }

        // Second pass: extract calls from method bodies.
        for cls in classes {
            for method in &cls.methods {
                let caller_id = MethodId::new(
                    cls.fqn.clone(),
                    method.name.clone(),
                    method.param_descriptor(),
                );
                let caller_node = cg.node_map[&caller_id];

                let calls = extract_calls(&method.body, &cls.fqn, self.max_calls_per_method);
                for call in calls {
                    if !self.include_external {
                        // Skip if callee is not already in node_map
                        if !cg.node_map.contains_key(&call.callee) {
                            continue;
                        }
                    }
                    let dst_node = cg.get_or_insert(call.callee, None);
                    let edge = JadxCallEdge {
                        call_line: call.line,
                        raw_expr: call.raw_expr,
                        is_super_call: call.is_super,
                        is_static_call: call.is_static,
                        is_interface_call: false,
                    };
                    cg.graph.add_edge(caller_node, dst_node, edge);
                }
            }
        }

        Ok(cg)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Call extraction from Java source
// ─────────────────────────────────────────────────────────────────────────────

struct RawCall {
    callee: MethodId,
    line: usize,
    raw_expr: String,
    is_super: bool,
    is_static: bool,
}

/// Heuristically extract method calls from a Java method body.
fn extract_calls(body: &str, enclosing_fqn: &str, limit: usize) -> Vec<RawCall> {
    let mut calls = Vec::new();

    for (line_idx, line) in body.lines().enumerate() {
        if calls.len() >= limit { break; }
        let t = line.trim();
        // Skip comments
        if t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') { continue; }

        // Find all call patterns: `qualifier.method(` or `method(`
        // We scan for `(` and backtrack to find the method name.
        let chars: Vec<char> = t.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '(' {
                // Backtrack: collect identifier chars
                let mut j = i;
                while j > 0 && (chars[j-1].is_alphanumeric() || chars[j-1] == '_') {
                    j -= 1;
                }
                let method_name: String = chars[j..i].iter().collect();
                if method_name.is_empty() || is_java_keyword(&method_name) {
                    i += 1;
                    continue;
                }
                // Find qualifier (may be `super`, `this`, class name, or variable)
                let qualifier = if j > 1 && chars[j-1] == '.' {
                    let mut k = j - 1;
                    while k > 0 && (chars[k-1].is_alphanumeric() || chars[k-1] == '_' || chars[k-1] == '.') {
                        k -= 1;
                    }
                    chars[k..j-1].iter().collect::<String>()
                } else {
                    String::new()
                };
                let is_super = qualifier == "super";
                let is_static = !qualifier.is_empty()
                    && qualifier.chars().next().is_some_and(char::is_uppercase);

                let class_fqn = if qualifier.is_empty() || qualifier == "this" {
                    enclosing_fqn.to_owned()
                } else {
                    qualifier.clone()
                };

                let raw_expr = format!("{qualifier}.{method_name}()");
                calls.push(RawCall {
                    callee: MethodId::new(class_fqn, method_name, String::new()),
                    line: line_idx + 1,
                    raw_expr,
                    is_super,
                    is_static,
                });
                if calls.len() >= limit { break; }
            }
            i += 1;
        }
    }
    calls
}

fn is_java_keyword(s: &str) -> bool {
    matches!(
        s,
        "if" | "for" | "while" | "switch" | "catch" | "throw"
            | "return" | "new" | "assert" | "synchronized"
            | "try" | "else" | "do" | "case" | "default"
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// GraphStats
// ─────────────────────────────────────────────────────────────────────────────

/// Summary statistics over a built call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStats {
    pub node_count: usize,
    pub edge_count: usize,
    pub root_count: usize,
    pub leaf_count: usize,
    pub native_count: usize,
    pub max_out_degree: usize,
    pub max_in_degree: usize,
}

impl GraphStats {
    /// Compute stats over a call graph.
    #[must_use]
    pub fn compute(cg: &JadxCallGraph) -> Self {
        use petgraph::Direction;
        let mut max_out = 0usize;
        let mut max_in = 0usize;
        for n in cg.graph.node_indices() {
            let out = cg.graph.neighbors_directed(n, Direction::Outgoing).count();
            let inc = cg.graph.neighbors_directed(n, Direction::Incoming).count();
            max_out = max_out.max(out);
            max_in = max_in.max(inc);
        }
        Self {
            node_count: cg.node_count(),
            edge_count: cg.edge_count(),
            root_count: cg.roots().len(),
            leaf_count: cg.leaves().len(),
            native_count: cg.native_methods().len(),
            max_out_degree: max_out,
            max_in_degree: max_in,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jadx_output_parser::{JadxClass, JadxMethod};
    use std::path::PathBuf;

    fn make_method(name: &str, body: &str, is_native: bool, is_static: bool) -> JadxMethod {
        JadxMethod {
            name: name.to_owned(),
            signature: format!("{name}()"),
            return_type: "void".to_owned(),
            params: vec![],
            modifiers: vec![],
            body: body.to_owned(),
            is_native,
            is_static,
            is_abstract: false,
            line_number: 1,
            annotations: vec![],
        }
    }

    fn make_class(fqn: &str, methods: Vec<JadxMethod>) -> JadxClass {
        JadxClass {
            class_name: fqn.rsplit('.').next().unwrap_or(fqn).to_owned(),
            package: fqn.rsplit_once('.').map_or("", |x| x.0).to_owned(),
            fqn: fqn.to_owned(),
            super_class: None,
            interfaces: vec![],
            modifiers: vec![],
            annotations: vec![],
            methods,
            fields: vec![],
            source: String::new(),
            source_path: PathBuf::from("/tmp/dummy.java"),
            has_bad_code: false,
        }
    }

    #[test]
    fn test_method_id_display() {
        let id = MethodId::new("com.example.Foo", "bar", "int, String");
        assert_eq!(id.display(), "com.example.Foo.bar(int, String)");
    }

    #[test]
    fn test_build_empty() {
        let builder = JadxCallGraphBuilder::new();
        let cg = builder.build(&[]).unwrap();
        assert_eq!(cg.node_count(), 0);
        assert_eq!(cg.edge_count(), 0);
    }

    #[test]
    fn test_build_registers_methods() {
        let m = make_method("foo", "", false, false);
        let cls = make_class("com.example.Bar", vec![m]);
        let cg = JadxCallGraphBuilder::new().build(&[cls]).unwrap();
        assert_eq!(cg.node_count(), 1);
    }

    #[test]
    fn test_build_with_call() {
        let body_a = "helper();";
        let body_b = "";
        let m_a = make_method("caller", body_a, false, false);
        let m_b = make_method("helper", body_b, false, false);
        let cls = make_class("com.example.MyClass", vec![m_a, m_b]);
        let cg = JadxCallGraphBuilder::new().build(&[cls]).unwrap();
        // Should have at least the 2 registered methods
        assert!(cg.node_count() >= 2);
    }

    #[test]
    fn test_has_edge() {
        let body = "other();";
        let m_run = make_method("run", body, false, false);
        let m_other = make_method("other", "", false, false);
        let cls = make_class("com.Pkg.Cls", vec![m_run, m_other]);
        let cg = JadxCallGraphBuilder { include_external: false, ..Default::default() }
            .build(&[cls])
            .unwrap();
        let id_run = MethodId::new("com.Pkg.Cls", "run", "");
        let id_other = MethodId::new("com.Pkg.Cls", "other", "");
        assert!(cg.has_edge(&id_run, &id_other));
    }

    #[test]
    fn test_native_methods() {
        let m = make_method("nativeOp", "", true, false);
        let cls = make_class("com.Native", vec![m]);
        let cg = JadxCallGraphBuilder::new().build(&[cls]).unwrap();
        assert_eq!(cg.native_methods().len(), 1);
    }

    #[test]
    fn test_roots_and_leaves() {
        // A calls B; B has no calls.  A is a root, B is a leaf.
        let m_a = make_method("alpha", "beta();", false, false);
        let m_b = make_method("beta", "", false, false);
        let cls = make_class("pkg.X", vec![m_a, m_b]);
        let cg = JadxCallGraphBuilder { include_external: false, ..Default::default() }
            .build(&[cls])
            .unwrap();
        // At least alpha should be a root (no incoming edges)
        assert!(!cg.roots().is_empty());
        // beta (no outgoing) should be a leaf
        assert!(!cg.leaves().is_empty());
    }

    #[test]
    fn test_graph_stats() {
        let m = make_method("m", "", false, false);
        let cls = make_class("p.C", vec![m]);
        let cg = JadxCallGraphBuilder::new().build(&[cls]).unwrap();
        let stats = GraphStats::compute(&cg);
        assert_eq!(stats.node_count, 1);
        assert_eq!(stats.edge_count, 0);
    }

    #[test]
    fn test_callees_empty() {
        let m = make_method("m", "", false, false);
        let cls = make_class("p.C", vec![m]);
        let cg = JadxCallGraphBuilder::new().build(&[cls]).unwrap();
        let id = MethodId::new("p.C", "m", "");
        assert!(cg.callees(&id).is_empty());
    }

    #[test]
    fn test_callers_empty() {
        let m = make_method("m", "", false, false);
        let cls = make_class("p.C", vec![m]);
        let cg = JadxCallGraphBuilder::new().build(&[cls]).unwrap();
        let id = MethodId::new("p.C", "m", "");
        assert!(cg.callers(&id).is_empty());
    }

    #[test]
    fn test_extract_calls_detects_super() {
        let body = "super.onCreate(bundle);";
        let calls = extract_calls(body, "com.Example", 100);
        let mut super_calls = calls.iter().filter(|c| c.is_super);
        assert!(super_calls.next().is_some());
    }

    #[test]
    fn test_shortest_path_none() {
        let m = make_method("alpha", "", false, false);
        let m2 = make_method("beta", "", false, false);
        let cls = make_class("p.C", vec![m, m2]);
        let cg = JadxCallGraphBuilder::new().build(&[cls]).unwrap();
        let a = MethodId::new("p.C", "alpha", "");
        let b = MethodId::new("p.C", "beta", "");
        assert!(cg.shortest_path(&a, &b).is_none());
    }
}
