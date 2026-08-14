//! Cross-reference query engine.
//!
//! Provides structured queries over an `XrefCallGraph`: find all callers, find all callees,
//! build caller trees, compute transitive closure, filter by edge kind, etc.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::xref_call_graph::{XrefCallGraph, XrefEdge, XrefKind};

// ---------------------------------------------------------------------------
// Query predicate
// ---------------------------------------------------------------------------

/// A predicate that filters xref edges.
#[derive(Debug, Clone)]
pub enum XrefPredicate {
    /// Accept edges of the specified kind only.
    KindIs(XrefKind),
    /// Accept edges with confidence >= threshold.
    MinConfidence(u8),
    /// Accept edges whose site is in [start, end).
    SiteRange { start: u64, end: u64 },
    /// Accept any edge (wildcard).
    Any,
    /// Logical AND of two predicates.
    And(Box<Self>, Box<Self>),
    /// Logical OR of two predicates.
    Or(Box<Self>, Box<Self>),
    /// Logical NOT.
    Not(Box<Self>),
}

impl XrefPredicate {
    #[must_use] 
    pub fn matches(&self, edge: &XrefEdge) -> bool {
        match self {
            Self::KindIs(k)          => edge.kind == *k,
            Self::MinConfidence(th)   => edge.confidence >= *th,
            Self::SiteRange { start, end } => edge.site >= *start && edge.site < *end,
            Self::Any                => true,
            Self::And(a, b)          => a.matches(edge) && b.matches(edge),
            Self::Or(a, b)           => a.matches(edge) || b.matches(edge),
            Self::Not(inner)          => !inner.matches(edge),
        }
    }

    #[must_use] 
    pub fn and(self, other: Self) -> Self {
        Self::And(Box::new(self), Box::new(other))
    }

    #[must_use] 
    pub fn or(self, other: Self) -> Self {
        Self::Or(Box::new(self), Box::new(other))
    }

    #[must_use]
    pub fn negate(self) -> Self {
        Self::Not(Box::new(self))
    }
}

// ---------------------------------------------------------------------------
// XrefQuery
// ---------------------------------------------------------------------------

/// A structured query for cross-references.
#[derive(Debug, Clone)]
pub struct XrefQuery {
    /// The address to query about.
    pub address: u64,
    /// Direction of traversal.
    pub direction: TraversalDirection,
    /// Edge predicate to filter results.
    pub predicate: XrefPredicate,
    /// Maximum traversal depth (None = unlimited).
    pub max_depth: Option<usize>,
    /// Whether to include the query address in results.
    pub include_root: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraversalDirection {
    /// Follow outgoing edges (callees / data targets).
    Outgoing,
    /// Follow incoming edges (callers / data sources).
    Incoming,
    /// Follow both directions.
    Both,
}

impl XrefQuery {
    #[must_use] 
    pub fn callers_of(address: u64) -> Self {
        Self {
            address,
            direction: TraversalDirection::Incoming,
            predicate: XrefPredicate::KindIs(XrefKind::DirectCall)
                .or(XrefPredicate::KindIs(XrefKind::IndirectCall))
                .or(XrefPredicate::KindIs(XrefKind::TailCall)),
            max_depth: Some(1),
            include_root: false,
        }
    }

    #[must_use] 
    pub fn callees_of(address: u64) -> Self {
        Self {
            address,
            direction: TraversalDirection::Outgoing,
            predicate: XrefPredicate::KindIs(XrefKind::DirectCall)
                .or(XrefPredicate::KindIs(XrefKind::IndirectCall))
                .or(XrefPredicate::KindIs(XrefKind::TailCall)),
            max_depth: Some(1),
            include_root: false,
        }
    }

    #[must_use] 
    pub fn data_refs_from(address: u64) -> Self {
        Self {
            address,
            direction: TraversalDirection::Outgoing,
            predicate: XrefPredicate::KindIs(XrefKind::DataRead)
                .or(XrefPredicate::KindIs(XrefKind::DataWrite))
                .or(XrefPredicate::KindIs(XrefKind::CodeToData)),
            max_depth: Some(1),
            include_root: false,
        }
    }

    #[must_use] 
    pub fn transitive_callers(address: u64) -> Self {
        Self {
            address,
            direction: TraversalDirection::Incoming,
            predicate: XrefPredicate::KindIs(XrefKind::DirectCall)
                .or(XrefPredicate::KindIs(XrefKind::IndirectCall))
                .or(XrefPredicate::KindIs(XrefKind::TailCall)),
            max_depth: None,
            include_root: false,
        }
    }

    #[must_use] 
    pub fn transitive_callees(address: u64) -> Self {
        Self {
            address,
            direction: TraversalDirection::Outgoing,
            predicate: XrefPredicate::KindIs(XrefKind::DirectCall)
                .or(XrefPredicate::KindIs(XrefKind::IndirectCall))
                .or(XrefPredicate::KindIs(XrefKind::TailCall)),
            max_depth: None,
            include_root: false,
        }
    }

    #[must_use] 
    pub const fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = Some(depth);
        self
    }

    #[must_use] 
    pub fn with_predicate(mut self, pred: XrefPredicate) -> Self {
        self.predicate = pred;
        self
    }

    #[must_use] 
    pub const fn include_root(mut self) -> Self {
        self.include_root = true;
        self
    }
}

// ---------------------------------------------------------------------------
// QueryResult
// ---------------------------------------------------------------------------

/// A single result entry from a query.
#[derive(Debug, Clone)]
pub struct QueryResult {
    /// The matched address.
    pub address: u64,
    /// Depth at which this address was discovered (0 = direct neighbor).
    pub depth: usize,
    /// The edge that connects the previous hop to this address.
    pub via_edge: XrefEdge,
    /// The address of the previous hop (None for depth-0 results).
    pub from_address: Option<u64>,
}

/// The result set of an `XrefQuery`.
#[derive(Debug, Clone)]
pub struct QueryResultSet {
    pub query_address: u64,
    pub results: Vec<QueryResult>,
}

impl QueryResultSet {
    #[must_use] 
    pub fn addresses(&self) -> Vec<u64> {
        self.results.iter().map(|r| r.address).collect()
    }

    #[must_use] 
    pub fn at_depth(&self, depth: usize) -> Vec<&QueryResult> {
        self.results.iter().filter(|r| r.depth == depth).collect()
    }

    #[must_use] 
    pub fn max_depth(&self) -> usize {
        self.results.iter().map(|r| r.depth).max().unwrap_or(0)
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.results.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CallerTree
// ---------------------------------------------------------------------------

/// A tree structure showing callers (or callees) up to N levels deep.
#[derive(Debug, Clone)]
pub struct CallerTreeNode {
    pub address: u64,
    pub name: Option<String>,
    pub children: Vec<Self>,
}

impl CallerTreeNode {
    #[must_use] 
    pub const fn new(address: u64, name: Option<String>) -> Self {
        Self { address, name, children: Vec::new() }
    }

    #[must_use] 
    pub fn depth(&self) -> usize {
        if self.children.is_empty() {
            0
        } else {
            1 + self.children.iter().map(Self::depth).max().unwrap_or(0)
        }
    }

    #[must_use] 
    pub fn total_nodes(&self) -> usize {
        1 + self.children.iter().map(Self::total_nodes).sum::<usize>()
    }

    /// Render as a text tree (like `tree` command output).
    #[must_use] 
    pub fn render(&self, prefix: &str, is_last: bool) -> String {
        let connector = if is_last { "└─" } else { "├─" };
        let name_part = self.name.as_deref().unwrap_or("<unknown>");
        let mut out = format!("{prefix}{connector} 0x{:016X}  {name_part}\n", self.address);
        let child_prefix = format!("{}{}", prefix, if is_last { "  " } else { "│ " });
        for (i, child) in self.children.iter().enumerate() {
            let last = i + 1 == self.children.len();
            out.push_str(&child.render(&child_prefix, last));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// XrefQueryEngine
// ---------------------------------------------------------------------------

/// The query engine: runs structured queries against an `XrefCallGraph`.
pub struct XrefQueryEngine<'g> {
    graph: &'g XrefCallGraph,
}

impl<'g> XrefQueryEngine<'g> {
    #[must_use] 
    pub const fn new(graph: &'g XrefCallGraph) -> Self {
        Self { graph }
    }

    /// Execute a query and return the result set.
    #[must_use] 
    pub fn execute(&self, query: &XrefQuery) -> QueryResultSet {
        let mut results = Vec::new();
        let mut visited: HashSet<u64> = HashSet::new();
        // Queue: (address, depth, from_address, via_edge)
        let mut queue: VecDeque<(u64, usize, Option<u64>, Option<XrefEdge>)> = VecDeque::new();
        queue.push_back((query.address, 0, None, None));
        visited.insert(query.address);

        while let Some((addr, depth, from_addr, via_edge)) = queue.pop_front() {
            // Emit result (skip root unless include_root)
            if (addr != query.address || query.include_root)
                && let Some(edge) = via_edge {
                    results.push(QueryResult {
                        address: addr,
                        depth: depth.saturating_sub(1),
                        via_edge: edge,
                        from_address: from_addr,
                    });
                }

            // Check depth limit
            if let Some(max) = query.max_depth
                && depth >= max { continue; }

            // Expand neighbors
            let neighbors = match query.direction {
                TraversalDirection::Outgoing => self.graph.xrefs_from(addr),
                TraversalDirection::Incoming => self.graph.xrefs_to(addr),
                TraversalDirection::Both => {
                    let mut all = self.graph.xrefs_from(addr);
                    all.extend(self.graph.xrefs_to(addr));
                    all
                }
            };

            for (neighbor_addr, edge) in neighbors {
                if !query.predicate.matches(edge) { continue; }
                if visited.contains(&neighbor_addr) { continue; }
                visited.insert(neighbor_addr);
                queue.push_back((neighbor_addr, depth + 1, Some(addr), Some(edge.clone())));
            }
        }

        QueryResultSet { query_address: query.address, results }
    }

    /// Build a caller tree up to `max_depth` levels deep.
    #[must_use] 
    pub fn caller_tree(&self, address: u64, max_depth: usize) -> CallerTreeNode {
        let name = self.graph.node_info(address).and_then(|n| n.name.clone());
        let mut root = CallerTreeNode::new(address, name);
        if max_depth == 0 { return root; }

        let mut visited = HashSet::new();
        visited.insert(address);
        self.build_caller_tree(&mut root, &mut visited, max_depth);
        root
    }

    fn build_caller_tree(&self, node: &mut CallerTreeNode, visited: &mut HashSet<u64>, depth_remaining: usize) {
        if depth_remaining == 0 { return; }
        let callers = self.graph.callers_of(node.address);
        for caller_addr in callers {
            if visited.contains(&caller_addr) { continue; }
            visited.insert(caller_addr);
            let name = self.graph.node_info(caller_addr).and_then(|n| n.name.clone());
            let mut child = CallerTreeNode::new(caller_addr, name);
            self.build_caller_tree(&mut child, visited, depth_remaining - 1);
            node.children.push(child);
        }
    }

    /// Build a callee tree (what this function calls, recursively).
    #[must_use] 
    pub fn callee_tree(&self, address: u64, max_depth: usize) -> CallerTreeNode {
        let name = self.graph.node_info(address).and_then(|n| n.name.clone());
        let mut root = CallerTreeNode::new(address, name);
        if max_depth == 0 { return root; }

        let mut visited = HashSet::new();
        visited.insert(address);
        self.build_callee_tree(&mut root, &mut visited, max_depth);
        root
    }

    fn build_callee_tree(&self, node: &mut CallerTreeNode, visited: &mut HashSet<u64>, depth_remaining: usize) {
        if depth_remaining == 0 { return; }
        let callees = self.graph.callees_of(node.address);
        for callee_addr in callees {
            if visited.contains(&callee_addr) { continue; }
            visited.insert(callee_addr);
            let name = self.graph.node_info(callee_addr).and_then(|n| n.name.clone());
            let mut child = CallerTreeNode::new(callee_addr, name);
            self.build_callee_tree(&mut child, visited, depth_remaining - 1);
            node.children.push(child);
        }
    }

    /// Find all functions that reference a given data address.
    #[must_use] 
    pub fn functions_referencing_data(&self, data_addr: u64) -> Vec<u64> {
        self.graph.xrefs_to(data_addr)
            .into_iter()
            .filter(|(_, e)| e.is_data_ref())
            .map(|(addr, _)| addr)
            .collect()
    }

    /// Compute the "fan-in" (number of unique callers) for each function.
    #[must_use] 
    pub fn fan_in_map(&self) -> HashMap<u64, usize> {
        let mut map = HashMap::new();
        for node in self.graph.function_nodes() {
            let count = self.graph.callers_of(node.address)
                .into_iter()
                .collect::<HashSet<_>>()
                .len();
            map.insert(node.address, count);
        }
        map
    }

    /// Compute the "fan-out" (number of unique callees) for each function.
    #[must_use] 
    pub fn fan_out_map(&self) -> HashMap<u64, usize> {
        let mut map = HashMap::new();
        for node in self.graph.function_nodes() {
            let count = self.graph.callees_of(node.address)
                .into_iter()
                .collect::<HashSet<_>>()
                .len();
            map.insert(node.address, count);
        }
        map
    }

    /// Return the top N most-called functions by caller count.
    #[must_use] 
    pub fn top_called(&self, n: usize) -> Vec<(u64, usize)> {
        let mut pairs: Vec<(u64, usize)> = self.fan_in_map().into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        pairs.truncate(n);
        pairs
    }

    /// Return the top N functions by number of outgoing calls.
    #[must_use] 
    pub fn top_calling(&self, n: usize) -> Vec<(u64, usize)> {
        let mut pairs: Vec<(u64, usize)> = self.fan_out_map().into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        pairs.truncate(n);
        pairs
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xref_call_graph::{XrefCallGraph, XrefEdge, XrefKind, XrefNode};

    fn make_graph() -> XrefCallGraph {
        let mut g = XrefCallGraph::new();
        // main(0x1000) → foo(0x2000), bar(0x3000)
        // foo(0x2000) → bar(0x3000), baz(0x4000)
        // bar(0x3000) → baz(0x4000)
        // data(0x8000) ← bar reads it
        g.add_node(XrefNode::new(0x1000).with_name("main").as_function());
        g.add_node(XrefNode::new(0x2000).with_name("foo").as_function());
        g.add_node(XrefNode::new(0x3000).with_name("bar").as_function());
        g.add_node(XrefNode::new(0x4000).with_name("baz").as_function());
        g.add_node(XrefNode::new(0x8000).as_data());

        g.add_xref(0x1000, 0x2000, XrefEdge::new(XrefKind::DirectCall, 0x1005));
        g.add_xref(0x1000, 0x3000, XrefEdge::new(XrefKind::DirectCall, 0x1010));
        g.add_xref(0x2000, 0x3000, XrefEdge::new(XrefKind::DirectCall, 0x2005));
        g.add_xref(0x2000, 0x4000, XrefEdge::new(XrefKind::DirectCall, 0x2010));
        g.add_xref(0x3000, 0x4000, XrefEdge::new(XrefKind::DirectCall, 0x3005));
        g.add_xref(0x3000, 0x8000, XrefEdge::new(XrefKind::DataRead, 0x3010));
        g
    }

    #[test]
    fn query_direct_callers() {
        let g = make_graph();
        let engine = XrefQueryEngine::new(&g);
        let res = engine.execute(&XrefQuery::callers_of(0x3000));
        let mut addrs = res.addresses();
        addrs.sort();
        assert_eq!(addrs, vec![0x1000, 0x2000]);
    }

    #[test]
    fn query_direct_callees() {
        let g = make_graph();
        let engine = XrefQueryEngine::new(&g);
        let res = engine.execute(&XrefQuery::callees_of(0x2000));
        let mut addrs = res.addresses();
        addrs.sort();
        assert_eq!(addrs, vec![0x3000, 0x4000]);
    }

    #[test]
    fn query_transitive_callers_of_baz() {
        let g = make_graph();
        let engine = XrefQueryEngine::new(&g);
        let res = engine.execute(&XrefQuery::transitive_callers(0x4000));
        let mut addrs = res.addresses();
        addrs.sort();
        // foo → baz, bar → baz, main → foo → baz, main → bar → baz
        assert!(addrs.contains(&0x1000));
        assert!(addrs.contains(&0x2000));
        assert!(addrs.contains(&0x3000));
    }

    #[test]
    fn functions_referencing_data() {
        let g = make_graph();
        let engine = XrefQueryEngine::new(&g);
        let refs = engine.functions_referencing_data(0x8000);
        assert_eq!(refs, vec![0x3000]);
    }

    #[test]
    fn caller_tree_depth_1() {
        let g = make_graph();
        let engine = XrefQueryEngine::new(&g);
        let tree = engine.caller_tree(0x4000, 1);
        // baz has callers foo and bar
        assert_eq!(tree.children.len(), 2);
    }

    #[test]
    fn caller_tree_depth_2() {
        let g = make_graph();
        let engine = XrefQueryEngine::new(&g);
        let tree = engine.caller_tree(0x4000, 2);
        // At depth 2, foo's callers (main) and bar's callers (main, foo) should appear
        assert!(tree.depth() >= 2);
    }

    #[test]
    fn callee_tree_main() {
        let g = make_graph();
        let engine = XrefQueryEngine::new(&g);
        let tree = engine.callee_tree(0x1000, 10);
        // main calls foo and bar, which call baz
        assert!(tree.total_nodes() >= 4);
    }

    #[test]
    fn caller_tree_render_non_empty() {
        let g = make_graph();
        let engine = XrefQueryEngine::new(&g);
        let tree = engine.caller_tree(0x3000, 1);
        let text = tree.render("", true);
        assert!(text.contains("bar") || text.contains("0x0000000000003000"));
    }

    #[test]
    fn fan_in_baz_highest() {
        let g = make_graph();
        let engine = XrefQueryEngine::new(&g);
        let fan_in = engine.fan_in_map();
        // baz is called by foo and bar (fan-in = 2)
        assert_eq!(fan_in.get(&0x4000).copied().unwrap_or(0), 2);
    }

    #[test]
    fn top_called_order() {
        let g = make_graph();
        let engine = XrefQueryEngine::new(&g);
        let top = engine.top_called(3);
        // baz(2), bar(2), foo(1) or similar
        assert!(!top.is_empty());
        assert!(top[0].1 >= top.last().unwrap().1);
    }

    #[test]
    fn predicate_min_confidence() {
        let mut g = XrefCallGraph::new();
        g.add_node(XrefNode::new(0x1000).as_function());
        g.add_xref(0x1000, 0x2000, XrefEdge::new(XrefKind::DirectCall, 0x1000).with_confidence(80));
        g.add_xref(0x1000, 0x3000, XrefEdge::new(XrefKind::DirectCall, 0x1005).with_confidence(40));

        let engine = XrefQueryEngine::new(&g);
        let query = XrefQuery::callees_of(0x1000)
            .with_predicate(XrefPredicate::MinConfidence(60).and(
                XrefPredicate::KindIs(XrefKind::DirectCall).or(
                    XrefPredicate::KindIs(XrefKind::TailCall)
                )
            ));
        let res = engine.execute(&query);
        assert_eq!(res.addresses(), vec![0x2000]);
    }
}
