//! Project-wide cross-reference analysis.
//!
//! Builds a `GlobalCallGraph`, clusters xrefs by `ApiGrouping`, identifies
//! `EntryPointGraph` connectivity, tracks `DataDependency` edges, and groups
//! strongly-connected functions into `XrefCluster`s.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Xref / XrefKind
// ─────────────────────────────────────────────────────────────────────────────

/// Type of a cross-reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XrefKind {
    Call,
    Jump,
    DataRead,
    DataWrite,
    StringRef,
}

impl fmt::Display for XrefKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Call => "call",
            Self::Jump => "jump",
            Self::DataRead => "data_read",
            Self::DataWrite => "data_write",
            Self::StringRef => "string_ref",
        };
        f.write_str(s)
    }
}

/// A single cross-reference record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Xref {
    pub from: u64,
    pub to: u64,
    pub kind: XrefKind,
}

impl Xref {
    #[must_use]
    pub const fn new(from: u64, to: u64, kind: XrefKind) -> Self {
        Self { from, to, kind }
    }

    #[must_use]
    pub const fn call(from: u64, to: u64) -> Self {
        Self::new(from, to, XrefKind::Call)
    }

    #[must_use]
    pub const fn data_read(from: u64, to: u64) -> Self {
        Self::new(from, to, XrefKind::DataRead)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GlobalCallGraph
// ─────────────────────────────────────────────────────────────────────────────

/// A project-wide directed call graph.
#[derive(Debug, Default)]
pub struct GlobalCallGraph {
    /// All registered xrefs.
    xrefs: Vec<Xref>,
    /// Adjacency list (caller → callees).
    adj: HashMap<u64, Vec<u64>>,
    /// Reverse adjacency (callee → callers).
    rev: HashMap<u64, Vec<u64>>,
}

impl GlobalCallGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a cross-reference.
    pub fn add_xref(&mut self, xref: Xref) {
        if xref.kind == XrefKind::Call {
            self.adj.entry(xref.from).or_default().push(xref.to);
            self.rev.entry(xref.to).or_default().push(xref.from);
        }
        self.xrefs.push(xref);
    }

    /// Add a direct call edge.
    pub fn add_call(&mut self, from: u64, to: u64) {
        self.add_xref(Xref::call(from, to));
    }

    /// All functions that `addr` calls.
    #[must_use]
    pub fn callees(&self, addr: u64) -> Vec<u64> {
        self.adj.get(&addr).cloned().unwrap_or_default()
    }

    /// All functions that call `addr`.
    #[must_use]
    pub fn callers(&self, addr: u64) -> Vec<u64> {
        self.rev.get(&addr).cloned().unwrap_or_default()
    }

    /// All nodes in the call graph.
    #[must_use]
    pub fn nodes(&self) -> HashSet<u64> {
        let mut s = HashSet::new();
        for xref in &self.xrefs {
            if xref.kind == XrefKind::Call {
                s.insert(xref.from);
                s.insert(xref.to);
            }
        }
        s
    }

    /// All call xrefs.
    #[must_use]
    pub fn call_xrefs(&self) -> Vec<&Xref> {
        self.xrefs
            .iter()
            .filter(|x| x.kind == XrefKind::Call)
            .collect()
    }

    /// BFS reachability from `start`.
    #[must_use]
    pub fn reachable_from(&self, start: u64) -> HashSet<u64> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        visited.insert(start);
        while let Some(n) = queue.pop_front() {
            for &callee in self.adj.get(&n).unwrap_or(&vec![]) {
                if visited.insert(callee) {
                    queue.push_back(callee);
                }
            }
        }
        visited
    }

    /// In-degree of `addr` (number of functions that call it).
    #[must_use]
    pub fn in_degree(&self, addr: u64) -> usize {
        self.rev.get(&addr).map_or(0, std::vec::Vec::len)
    }

    /// Out-degree of `addr` (number of functions it calls).
    #[must_use]
    pub fn out_degree(&self, addr: u64) -> usize {
        self.adj.get(&addr).map_or(0, std::vec::Vec::len)
    }

    /// Total number of call xrefs.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.xrefs
            .iter()
            .filter(|x| x.kind == XrefKind::Call)
            .count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DataDependency
// ─────────────────────────────────────────────────────────────────────────────

/// A data-dependency edge: `from` reads/writes data at `data_addr`.
#[derive(Debug, Clone)]
pub struct DataDependency {
    pub from_func: u64,
    pub data_addr: u64,
    pub is_write: bool,
}

impl DataDependency {
    #[must_use]
    pub const fn read(from_func: u64, data_addr: u64) -> Self {
        Self {
            from_func,
            data_addr,
            is_write: false,
        }
    }

    #[must_use]
    pub const fn write(from_func: u64, data_addr: u64) -> Self {
        Self {
            from_func,
            data_addr,
            is_write: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ApiGrouping
// ─────────────────────────────────────────────────────────────────────────────

/// Groups functions by the set of imported/exported APIs they call.
#[derive(Debug, Default)]
pub struct ApiGrouping {
    /// `api_name` → addresses of callers.
    callers_by_api: HashMap<String, Vec<u64>>,
    /// address → APIs called.
    apis_by_func: HashMap<u64, Vec<String>>,
}

impl ApiGrouping {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that function `addr` calls API `api`.
    pub fn record_call(&mut self, addr: u64, api: impl Into<String>) {
        let api_str: String = api.into();
        self.callers_by_api
            .entry(api_str.clone())
            .or_default()
            .push(addr);
        self.apis_by_func.entry(addr).or_default().push(api_str);
    }

    /// All functions that call `api`.
    #[must_use]
    pub fn callers_of(&self, api: &str) -> Vec<u64> {
        self.callers_by_api.get(api).cloned().unwrap_or_default()
    }

    /// All APIs called by `addr`.
    #[must_use]
    pub fn apis_called_by(&self, addr: u64) -> Vec<&str> {
        let empty: &[String] = &[];
        self.apis_by_func
            .get(&addr)
            .map_or(empty, Vec::as_slice)
            .iter()
            .map(String::as_str)
            .collect()
    }

    /// Functions that call any of the given APIs.
    #[must_use]
    pub fn funcs_using_any(&self, apis: &[&str]) -> Vec<u64> {
        let mut result: HashSet<u64> = HashSet::new();
        for &api in apis {
            for &addr in self.callers_by_api.get(api).unwrap_or(&vec![]) {
                result.insert(addr);
            }
        }
        let mut v: Vec<u64> = result.into_iter().collect();
        v.sort_unstable();
        v
    }

    /// Total distinct APIs tracked.
    #[must_use]
    pub fn api_count(&self) -> usize {
        self.callers_by_api.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EntryPointGraph
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks reachability from binary entry points.
#[derive(Debug, Default)]
pub struct EntryPointGraph {
    pub entry_points: Vec<u64>,
    /// address → set of entry points that can reach it.
    pub covered_by: HashMap<u64, HashSet<u64>>,
}

impl EntryPointGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the entry-point graph from a `GlobalCallGraph`.
    #[must_use]
    pub fn build(cg: &GlobalCallGraph, entries: &[u64]) -> Self {
        let mut epg = Self::new();
        epg.entry_points = entries.to_vec();

        for &entry in entries {
            let reachable = cg.reachable_from(entry);
            for addr in reachable {
                epg.covered_by.entry(addr).or_default().insert(entry);
            }
        }
        epg
    }

    /// Whether `addr` is reachable from any entry point.
    #[must_use]
    pub fn is_reachable(&self, addr: u64) -> bool {
        self.covered_by.contains_key(&addr)
    }

    /// Entry points from which `addr` is reachable.
    #[must_use]
    pub fn entry_points_for(&self, addr: u64) -> Vec<u64> {
        self.covered_by.get(&addr).map_or(Vec::new(), |s| {
            let mut v: Vec<u64> = s.iter().copied().collect();
            v.sort_unstable();
            v
        })
    }

    /// Functions reachable from all entry points (intersection).
    #[must_use]
    pub fn core_functions(&self) -> Vec<u64> {
        if self.entry_points.is_empty() {
            return Vec::new();
        }
        let all_entries: HashSet<u64> = self.entry_points.iter().copied().collect();
        let mut result: Vec<u64> = self
            .covered_by
            .iter()
            .filter(|(_, entries)| *entries == &all_entries)
            .map(|(addr, _)| *addr)
            .collect();
        result.sort_unstable();
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XrefCluster
// ─────────────────────────────────────────────────────────────────────────────

/// A cluster of mutually-reachable functions (SCC of the call graph).
#[derive(Debug, Clone)]
pub struct XrefCluster {
    pub id: usize,
    pub members: Vec<u64>,
    /// Whether this cluster is a loop (non-trivial SCC).
    pub is_recursive: bool,
}

impl XrefCluster {
    /// Size of the cluster.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.members.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GlobalXrefAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// Project-wide cross-reference analysis driver.
pub struct GlobalXrefAnalysis {
    pub call_graph: GlobalCallGraph,
    pub data_deps: Vec<DataDependency>,
    pub api_grouping: ApiGrouping,
}

impl Default for GlobalXrefAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalXrefAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self {
            call_graph: GlobalCallGraph::new(),
            data_deps: Vec::new(),
            api_grouping: ApiGrouping::new(),
        }
    }

    /// Add a call xref.
    pub fn add_call(&mut self, from: u64, to: u64) {
        self.call_graph.add_call(from, to);
    }

    /// Add a data dependency.
    pub fn add_data_dep(&mut self, dep: DataDependency) {
        self.data_deps.push(dep);
    }

    /// Record an API call.
    pub fn record_api(&mut self, addr: u64, api: impl Into<String>) {
        self.api_grouping.record_call(addr, api);
    }

    /// Build the entry-point graph.
    #[must_use]
    pub fn entry_point_graph(&self, entries: &[u64]) -> EntryPointGraph {
        EntryPointGraph::build(&self.call_graph, entries)
    }

    /// Compute SCCs of the call graph and return `XrefCluster`s.
    #[must_use]
    pub fn clusters(&self) -> Vec<XrefCluster> {
        let nodes: Vec<u64> = {
            let mut v: Vec<u64> = self.call_graph.nodes().into_iter().collect();
            v.sort_unstable();
            v
        };

        let mut state = GlobalTarjanState::new(&self.call_graph);
        for &n in &nodes {
            if !state.index.contains_key(&n) {
                state.run(n);
            }
        }

        state.sccs.into_iter()
            .enumerate()
            .map(|(id, members)| {
                let self_loop =
                    members.len() == 1 && self.call_graph.callees(members[0]).contains(&members[0]);
                let is_recursive = members.len() > 1 || self_loop;
                XrefCluster {
                    id,
                    members,
                    is_recursive,
                }
            })
            .collect()
    }

    /// Find all functions that write to `data_addr`.
    #[must_use]
    pub fn writers_of(&self, data_addr: u64) -> Vec<u64> {
        let mut v: Vec<u64> = self
            .data_deps
            .iter()
            .filter(|d| d.data_addr == data_addr && d.is_write)
            .map(|d| d.from_func)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        v.sort_unstable();
        v
    }

    /// Find all functions that read `data_addr`.
    #[must_use]
    pub fn readers_of(&self, data_addr: u64) -> Vec<u64> {
        let mut v: Vec<u64> = self
            .data_deps
            .iter()
            .filter(|d| d.data_addr == data_addr && !d.is_write)
            .map(|d| d.from_func)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        v.sort_unstable();
        v
    }
}

struct GlobalTarjanState<'a> {
    cg: &'a GlobalCallGraph,
    counter: u32,
    stack: Vec<u64>,
    on_stack: HashSet<u64>,
    index: HashMap<u64, u32>,
    lowlink: HashMap<u64, u32>,
    sccs: Vec<Vec<u64>>,
}

impl<'a> GlobalTarjanState<'a> {
    fn new(cg: &'a GlobalCallGraph) -> Self {
        Self {
            cg,
            counter: 0,
            stack: Vec::new(),
            on_stack: HashSet::new(),
            index: HashMap::new(),
            lowlink: HashMap::new(),
            sccs: Vec::new(),
        }
    }

    fn run(&mut self, root: u64) {
        // Iterative Tarjan with an explicit work stack to avoid stack
        // overflow on deep call graphs from real binaries.
        // Each frame is (node, neighbors, next neighbor index).
        let mut work: Vec<(u64, Vec<u64>, usize)> = Vec::new();

        let idx = self.counter;
        self.index.insert(root, idx);
        self.lowlink.insert(root, idx);
        self.counter += 1;
        self.stack.push(root);
        self.on_stack.insert(root);
        work.push((root, self.cg.callees(root), 0));

        while let Some(&mut (v, ref neighbors, ref mut i)) = work.last_mut() {
            if *i < neighbors.len() {
                let w = neighbors[*i];
                *i += 1;
                if !self.index.contains_key(&w) {
                    let idx = self.counter;
                    self.index.insert(w, idx);
                    self.lowlink.insert(w, idx);
                    self.counter += 1;
                    self.stack.push(w);
                    self.on_stack.insert(w);
                    work.push((w, self.cg.callees(w), 0));
                } else if self.on_stack.contains(&w) {
                    let idx_w = *self.index.get(&w).unwrap_or(&u32::MAX);
                    let ll_v = self.lowlink.get_mut(&v).unwrap();
                    *ll_v = (*ll_v).min(idx_w);
                }
            } else {
                if self.lowlink.get(&v) == self.index.get(&v) {
                    let mut scc = Vec::new();
                    loop {
                        let w = self.stack.pop().expect("tarjan stack");
                        self.on_stack.remove(&w);
                        scc.push(w);
                        if w == v { break; }
                    }
                    self.sccs.push(scc);
                }
                work.pop();
                if let Some(&mut (parent, _, _)) = work.last_mut() {
                    let ll_v = *self.lowlink.get(&v).unwrap_or(&u32::MAX);
                    let ll_p = self.lowlink.get_mut(&parent).unwrap();
                    *ll_p = (*ll_p).min(ll_v);
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // 1. Add call and query callees
    #[test]
    fn test_add_call_callees() {
        let mut cg = GlobalCallGraph::new();
        cg.add_call(0x1000, 0x2000);
        assert!(cg.callees(0x1000).contains(&0x2000));
    }

    // 2. Callers
    #[test]
    fn test_callers() {
        let mut cg = GlobalCallGraph::new();
        cg.add_call(0x1000, 0x2000);
        cg.add_call(0x3000, 0x2000);
        let callers = cg.callers(0x2000);
        assert!(callers.contains(&0x1000));
        assert!(callers.contains(&0x3000));
    }

    // GlobalTarjanState (5th SCC implementation, pipeline-gated): property
    // tests against a brute-force mutual-reachability oracle, determinism,
    // and deep-graph stack safety.

    use crate::test_prng::xorshift;

    fn oracle_reach(n: usize, adj: &[Vec<usize>], from: usize) -> Vec<bool> {
        let mut seen = vec![false; n];
        let mut stack = vec![from];
        seen[from] = true;
        while let Some(u) = stack.pop() {
            for &v in &adj[u] {
                if !seen[v] {
                    seen[v] = true;
                    stack.push(v);
                }
            }
        }
        seen
    }

    #[test]
    fn global_tarjan_clusters_match_mutual_reachability_oracle() {
        let mut rng = 0xfeed_face_cafe_beefu64;
        for _trial in 0..800 {
            let n = 2 + (xorshift(&mut rng) % 9) as usize; // 2..=10
            let mut analysis = GlobalXrefAnalysis::new();
            let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
            let edges = 1 + (xorshift(&mut rng) % (2 * n as u64)) as usize;
            for _ in 0..edges {
                let f = (xorshift(&mut rng) % n as u64) as usize;
                let t = (xorshift(&mut rng) % n as u64) as usize;
                adj[f].push(t);
                analysis.add_call(0x1000 + 8 * f as u64, 0x1000 + 8 * t as u64);
            }
            let clusters = analysis.clusters();

            // Map each address back to its index and its cluster id.
            let mut cluster_of: HashMap<usize, usize> = HashMap::new();
            for c in &clusters {
                for &m in &c.members {
                    let i = ((m - 0x1000) / 8) as usize;
                    assert!(
                        cluster_of.insert(i, c.id).is_none(),
                        "node {i} appears in two clusters"
                    );
                }
            }

            // Oracle: same SCC iff mutually reachable (reflexive trivially).
            let reach: Vec<Vec<bool>> = (0..n).map(|s| oracle_reach(n, &adj, s)).collect();
            let in_graph: Vec<usize> = (0..n)
                .filter(|&i| !adj[i].is_empty() || adj.iter().any(|r| r.contains(&i)))
                .collect();
            for &a in &in_graph {
                assert!(cluster_of.contains_key(&a), "graph node {a} missing from clusters");
                for &b in &in_graph {
                    let same_oracle = reach[a][b] && reach[b][a];
                    let same_cluster = cluster_of[&a] == cluster_of[&b];
                    assert_eq!(
                        same_oracle, same_cluster,
                        "nodes {a},{b}: oracle {same_oracle} vs clusters {same_cluster} (adj={adj:?})"
                    );
                }
            }

            // is_recursive: singleton clusters recursive iff self-loop.
            for c in &clusters {
                if c.members.len() == 1 {
                    let i = ((c.members[0] - 0x1000) / 8) as usize;
                    assert_eq!(c.is_recursive, adj[i].contains(&i));
                } else {
                    assert!(c.is_recursive);
                }
            }
        }
    }

    #[test]
    fn global_tarjan_clusters_are_deterministic() {
        let build = || {
            let mut a = GlobalXrefAnalysis::new();
            // Fixed edge set inserted in the same order both times.
            for &(f, t) in &[(1u64, 2u64), (2, 3), (3, 1), (3, 4), (5, 5), (4, 2)] {
                a.add_call(0x1000 + 8 * f, 0x1000 + 8 * t);
            }
            a.clusters()
                .into_iter()
                .map(|c| (c.id, c.members, c.is_recursive))
                .collect::<Vec<_>>()
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn global_tarjan_deep_chain_no_stack_overflow() {
        let mut analysis = GlobalXrefAnalysis::new();
        const N: u64 = 10_000;
        for i in 0..N {
            analysis.add_call(0x1000 + 8 * i, 0x1000 + 8 * (i + 1));
        }
        let clusters = analysis.clusters();
        // A pure chain has N+1 singleton, non-recursive SCCs.
        assert_eq!(clusters.len(), (N + 1) as usize);
        assert!(clusters.iter().all(|c| c.members.len() == 1 && !c.is_recursive));
    }

    // 3. Nodes returns all participants
    #[test]
    fn test_nodes() {
        let mut cg = GlobalCallGraph::new();
        cg.add_call(0x1000, 0x2000);
        let nodes = cg.nodes();
        assert!(nodes.contains(&0x1000));
        assert!(nodes.contains(&0x2000));
    }

    // 4. reachable_from linear chain
    #[test]
    fn test_reachable_chain() {
        let mut cg = GlobalCallGraph::new();
        cg.add_call(0x1000, 0x2000);
        cg.add_call(0x2000, 0x3000);
        let r = cg.reachable_from(0x1000);
        assert!(r.contains(&0x1000));
        assert!(r.contains(&0x2000));
        assert!(r.contains(&0x3000));
    }

    // 5. reachable_from does not include unreachable
    #[test]
    fn test_reachable_excludes() {
        let mut cg = GlobalCallGraph::new();
        cg.add_call(0x1000, 0x2000);
        cg.add_call(0x5000, 0x6000);
        let r = cg.reachable_from(0x1000);
        assert!(!r.contains(&0x5000));
    }

    // 6. in_degree and out_degree
    #[test]
    fn test_degrees() {
        let mut cg = GlobalCallGraph::new();
        cg.add_call(0x1000, 0x2000);
        cg.add_call(0x3000, 0x2000);
        assert_eq!(cg.in_degree(0x2000), 2);
        assert_eq!(cg.out_degree(0x1000), 1);
    }

    // 7. call_count
    #[test]
    fn test_call_count() {
        let mut cg = GlobalCallGraph::new();
        cg.add_call(0x1000, 0x2000);
        cg.add_call(0x1000, 0x3000);
        assert_eq!(cg.call_count(), 2);
    }

    // 8. add_xref data_read does not add to adj
    #[test]
    fn test_add_xref_data_read() {
        let mut cg = GlobalCallGraph::new();
        cg.add_xref(Xref::data_read(0x1000, 0x4000));
        assert!(cg.callees(0x1000).is_empty());
        assert_eq!(cg.call_count(), 0);
    }

    // 9. DataDependency read/write
    #[test]
    fn test_data_dependency() {
        let r = DataDependency::read(0x1000, 0x5000);
        assert!(!r.is_write);
        let w = DataDependency::write(0x2000, 0x5000);
        assert!(w.is_write);
    }

    // 10. GlobalXrefAnalysis writers_of
    #[test]
    fn test_writers_of() {
        let mut gxa = GlobalXrefAnalysis::new();
        gxa.add_data_dep(DataDependency::write(0x1000, 0x8000));
        gxa.add_data_dep(DataDependency::write(0x2000, 0x8000));
        let writers = gxa.writers_of(0x8000);
        assert!(writers.contains(&0x1000));
        assert!(writers.contains(&0x2000));
    }

    // 11. GlobalXrefAnalysis readers_of
    #[test]
    fn test_readers_of() {
        let mut gxa = GlobalXrefAnalysis::new();
        gxa.add_data_dep(DataDependency::read(0x3000, 0x9000));
        assert_eq!(gxa.readers_of(0x9000), vec![0x3000]);
    }

    // 12. ApiGrouping record and query
    #[test]
    fn test_api_grouping() {
        let mut ag = ApiGrouping::new();
        ag.record_call(0x1000, "CreateFile");
        ag.record_call(0x2000, "CreateFile");
        let callers = ag.callers_of("CreateFile");
        assert!(callers.contains(&0x1000));
        assert!(callers.contains(&0x2000));
    }

    // 13. ApiGrouping apis_called_by
    #[test]
    fn test_apis_called_by() {
        let mut ag = ApiGrouping::new();
        ag.record_call(0x1000, "CreateFile");
        ag.record_call(0x1000, "WriteFile");
        let apis = ag.apis_called_by(0x1000);
        assert!(apis.contains(&"CreateFile"));
        assert!(apis.contains(&"WriteFile"));
    }

    // 14. ApiGrouping funcs_using_any
    #[test]
    fn test_funcs_using_any() {
        let mut ag = ApiGrouping::new();
        ag.record_call(0x1000, "CreateFile");
        ag.record_call(0x2000, "WriteFile");
        ag.record_call(0x3000, "ReadFile");
        let funcs = ag.funcs_using_any(&["CreateFile", "WriteFile"]);
        assert!(funcs.contains(&0x1000));
        assert!(funcs.contains(&0x2000));
        assert!(!funcs.contains(&0x3000));
    }

    // 15. ApiGrouping api_count
    #[test]
    fn test_api_count() {
        let mut ag = ApiGrouping::new();
        ag.record_call(0x1000, "A");
        ag.record_call(0x2000, "B");
        ag.record_call(0x3000, "A"); // duplicate API
        assert_eq!(ag.api_count(), 2);
    }

    // 16. EntryPointGraph build
    #[test]
    fn test_entry_point_graph_build() {
        let mut cg = GlobalCallGraph::new();
        cg.add_call(0x1000, 0x2000);
        cg.add_call(0x2000, 0x3000);
        let epg = EntryPointGraph::build(&cg, &[0x1000]);
        assert!(epg.is_reachable(0x3000));
    }

    // 17. EntryPointGraph not reachable
    #[test]
    fn test_entry_not_reachable() {
        let cg = GlobalCallGraph::new();
        let epg = EntryPointGraph::build(&cg, &[0x1000]);
        assert!(!epg.is_reachable(0x9999));
    }

    // 18. EntryPointGraph entry_points_for
    #[test]
    fn test_entry_points_for() {
        let mut cg = GlobalCallGraph::new();
        cg.add_call(0x1000, 0x3000);
        cg.add_call(0x2000, 0x3000);
        let epg = EntryPointGraph::build(&cg, &[0x1000, 0x2000]);
        let eps = epg.entry_points_for(0x3000);
        assert!(eps.contains(&0x1000));
        assert!(eps.contains(&0x2000));
    }

    // 19. EntryPointGraph core_functions
    #[test]
    fn test_core_functions() {
        let mut cg = GlobalCallGraph::new();
        cg.add_call(0x1000, 0x4000);
        cg.add_call(0x2000, 0x4000);
        let epg = EntryPointGraph::build(&cg, &[0x1000, 0x2000]);
        let core = epg.core_functions();
        assert!(core.contains(&0x4000));
    }

    // 20. EntryPointGraph empty entries
    #[test]
    fn test_empty_entries() {
        let cg = GlobalCallGraph::new();
        let epg = EntryPointGraph::build(&cg, &[]);
        assert!(epg.core_functions().is_empty());
    }

    // 21. XrefCluster is_recursive for mutual recursion
    #[test]
    fn test_cluster_recursive() {
        let mut gxa = GlobalXrefAnalysis::new();
        gxa.add_call(0x1000, 0x2000);
        gxa.add_call(0x2000, 0x1000);
        let clusters = gxa.clusters();
        
        assert!(clusters.iter().any(|c| c.is_recursive));
    }

    // 22. XrefCluster size
    #[test]
    fn test_cluster_size() {
        let mut gxa = GlobalXrefAnalysis::new();
        gxa.add_call(0x1000, 0x2000);
        let clusters = gxa.clusters();
        assert!(!clusters.is_empty());
    }

    // 23. GlobalCallGraph empty
    #[test]
    fn test_empty_call_graph() {
        let cg = GlobalCallGraph::new();
        assert_eq!(cg.call_count(), 0);
        assert!(cg.nodes().is_empty());
    }

    // 24. Xref::call constructor
    #[test]
    fn test_xref_call_constructor() {
        let x = Xref::call(0x1000, 0x2000);
        assert_eq!(x.kind, XrefKind::Call);
    }

    // 25. XrefKind Display
    #[test]
    fn test_xref_kind_display() {
        assert_eq!(XrefKind::Call.to_string(), "call");
        assert_eq!(XrefKind::DataRead.to_string(), "data_read");
    }

    // 26. GlobalXrefAnalysis record_api and query
    #[test]
    fn test_record_api() {
        let mut gxa = GlobalXrefAnalysis::new();
        gxa.record_api(0x1000, "printf");
        assert!(gxa.api_grouping.callers_of("printf").contains(&0x1000));
    }

    // 27. GlobalXrefAnalysis entry_point_graph
    #[test]
    fn test_entry_point_graph_via_gxa() {
        let mut gxa = GlobalXrefAnalysis::new();
        gxa.add_call(0x1000, 0x2000);
        let epg = gxa.entry_point_graph(&[0x1000]);
        assert!(epg.is_reachable(0x2000));
    }

    // 28. ApiGrouping empty callers
    #[test]
    fn test_api_empty_callers() {
        let ag = ApiGrouping::new();
        assert!(ag.callers_of("nonexistent").is_empty());
    }

    // 29. GlobalCallGraph call_xrefs
    #[test]
    fn test_call_xrefs() {
        let mut cg = GlobalCallGraph::new();
        cg.add_xref(Xref::call(0x1000, 0x2000));
        cg.add_xref(Xref::data_read(0x1000, 0x5000));
        let xrefs = cg.call_xrefs();
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].kind, XrefKind::Call);
    }

    // 30. reachable_from includes self
    #[test]
    fn test_reachable_includes_self() {
        let cg = GlobalCallGraph::new();
        let r = cg.reachable_from(0x1000);
        assert!(r.contains(&0x1000));
    }

    // 31. clusters non-recursive for chain
    #[test]
    fn test_cluster_chain_not_recursive() {
        let mut gxa = GlobalXrefAnalysis::new();
        gxa.add_call(0x1000, 0x2000);
        gxa.add_call(0x2000, 0x3000);
        let clusters = gxa.clusters();
        assert!(clusters.iter().all(|c| !c.is_recursive));
    }

    // 32. DataDependency fields
    #[test]
    fn test_data_dependency_fields() {
        let d = DataDependency::read(0x1234, 0x5678);
        assert_eq!(d.from_func, 0x1234);
        assert_eq!(d.data_addr, 0x5678);
    }

    // 33. Multiple callers per callee
    #[test]
    fn test_multiple_callers() {
        let mut cg = GlobalCallGraph::new();
        for i in 0u64..5 {
            cg.add_call(i * 0x100 + 0x1000, 0x9000);
        }
        assert_eq!(cg.in_degree(0x9000), 5);
    }

    // 34. writers_of empty when none
    #[test]
    fn test_writers_of_empty() {
        let gxa = GlobalXrefAnalysis::new();
        assert!(gxa.writers_of(0x1234).is_empty());
    }

    // 35. EntryPointGraph with no call edges
    #[test]
    fn test_epg_no_edges() {
        let cg = GlobalCallGraph::new();
        let epg = EntryPointGraph::build(&cg, &[0x1000]);
        // Entry itself is reachable
        assert!(epg.is_reachable(0x1000));
    }

    // 36. ApiGrouping apis_called_by empty
    #[test]
    fn test_apis_called_by_empty() {
        let ag = ApiGrouping::new();
        assert!(ag.apis_called_by(0x1234).is_empty());
    }

    // 37. GlobalXrefAnalysis default is empty
    #[test]
    fn test_gxa_default_empty() {
        let gxa = GlobalXrefAnalysis::default();
        assert_eq!(gxa.call_graph.call_count(), 0);
        assert!(gxa.data_deps.is_empty());
    }

    // 38. Xref equality
    #[test]
    fn test_xref_equality() {
        let a = Xref::call(0x1000, 0x2000);
        let b = Xref::call(0x1000, 0x2000);
        assert_eq!(a, b);
    }

    // 39. EntryPointGraph multiple entry points
    #[test]
    fn test_epg_multiple_entries() {
        let mut cg = GlobalCallGraph::new();
        cg.add_call(0x1000, 0x5000);
        cg.add_call(0x2000, 0x5000);
        cg.add_call(0x2000, 0x6000);
        let epg = EntryPointGraph::build(&cg, &[0x1000, 0x2000]);
        assert_eq!(epg.entry_points_for(0x5000).len(), 2);
        assert_eq!(epg.entry_points_for(0x6000).len(), 1);
    }

    // 40. XrefCluster id
    #[test]
    fn test_cluster_id() {
        let mut gxa = GlobalXrefAnalysis::new();
        gxa.add_call(0x1000, 0x2000);
        let clusters = gxa.clusters();
        for (i, c) in clusters.iter().enumerate() {
            assert_eq!(c.id, i);
        }
    }

    // 41. GlobalCallGraph out_degree zero for leaf
    #[test]
    fn test_out_degree_leaf() {
        let mut cg = GlobalCallGraph::new();
        cg.add_call(0x1000, 0x2000);
        assert_eq!(cg.out_degree(0x2000), 0);
    }

    // 42. ApiGrouping funcs_using_any returns sorted
    #[test]
    fn test_funcs_using_any_sorted() {
        let mut ag = ApiGrouping::new();
        ag.record_call(0x3000, "A");
        ag.record_call(0x1000, "A");
        ag.record_call(0x2000, "A");
        let funcs = ag.funcs_using_any(&["A"]);
        let mut sorted = funcs.clone();
        sorted.sort_unstable();
        assert_eq!(funcs, sorted);
    }

    // 43. XrefKind Display for all remaining variants (Jump, DataWrite, StringRef)
    #[test]
    fn test_xref_kind_display_all_variants() {
        assert_eq!(XrefKind::Jump.to_string(), "jump");
        assert_eq!(XrefKind::DataWrite.to_string(), "data_write");
        assert_eq!(XrefKind::StringRef.to_string(), "string_ref");
    }

    // 44. Xref::new with a non-Call kind is not registered in adjacency
    #[test]
    fn test_xref_new_jump_not_in_adj() {
        let mut cg = GlobalCallGraph::new();
        cg.add_xref(Xref::new(0x1000, 0x2000, XrefKind::Jump));
        assert!(cg.callees(0x1000).is_empty());
        assert!(cg.nodes().is_empty());
    }

    // 45. XrefCluster::size reflects member count
    #[test]
    fn test_cluster_size_value() {
        let mut gxa = GlobalXrefAnalysis::new();
        gxa.add_call(0x1000, 0x2000);
        gxa.add_call(0x2000, 0x1000); // mutual recursion -> one SCC of size 2
        let clusters = gxa.clusters();
        let recursive = clusters.iter().find(|c| c.is_recursive).unwrap();
        assert_eq!(recursive.size(), 2);
    }

    // 46. callees/callers for an address never seen returns empty, not a panic
    #[test]
    fn test_callees_callers_unknown_addr() {
        let cg = GlobalCallGraph::new();
        assert!(cg.callees(0xDEAD).is_empty());
        assert!(cg.callers(0xDEAD).is_empty());
        assert_eq!(cg.in_degree(0xDEAD), 0);
        assert_eq!(cg.out_degree(0xDEAD), 0);
    }

    // 47. self-loop counts as a recursive singleton cluster
    #[test]
    fn test_self_loop_is_recursive_singleton() {
        let mut gxa = GlobalXrefAnalysis::new();
        gxa.add_call(0x1000, 0x1000);
        let clusters = gxa.clusters();
        assert_eq!(clusters.len(), 1);
        assert!(clusters[0].is_recursive);
        assert_eq!(clusters[0].size(), 1);
    }

    // 48. core_functions with a single entry point returns everything reachable from it
    #[test]
    fn test_core_functions_single_entry() {
        let mut cg = GlobalCallGraph::new();
        cg.add_call(0x1000, 0x2000);
        let epg = EntryPointGraph::build(&cg, &[0x1000]);
        let core = epg.core_functions();
        assert!(core.contains(&0x1000));
        assert!(core.contains(&0x2000));
    }
}
