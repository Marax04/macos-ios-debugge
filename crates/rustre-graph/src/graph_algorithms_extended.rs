//! Extended graph algorithms for `rustre-graph`.
//!
//! Implements:
//! - [`PageRank`]: power-iteration `PageRank`.
//! - [`BetweennessCentrality`]: Brandes algorithm.
//! - [`ClosenessCentrality`]: BFS-based closeness.
//! - [`GraphPartitioning`]: Kernighan-Lin bisection.
//! - [`MaxFlow`]: Dinic's algorithm.
//! - [`MinCut`]: global min-cut (Stoer-Wagner).
//! - [`SpanningTree`]: Prim's and Kruskal's MST.
//! - [`GraphColoring`]: `DSatur` greedy coloring.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::fmt;

/// Build a degree map (vertex -> outgoing edge count) for the given graph.
/// Useful as a quick sanity-check or input to centrality algorithms below.
#[must_use]
pub fn degree_map(graph: &Graph) -> HashMap<usize, usize> {
    let mut out = HashMap::with_capacity(graph.n);
    for u in 0..graph.n {
        out.insert(u, graph.edges[u].len());
    }
    out
}

impl fmt::Display for Graph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let edge_count: usize = self.edges.iter().map(Vec::len).sum();
        write!(f, "Graph(n={}, edges={})", self.n, edge_count)
    }
}

// ---------------------------------------------------------------------------
// Generic graph representation (adjacency list)
// ---------------------------------------------------------------------------

/// A lightweight directed/undirected graph.
#[derive(Debug, Clone, Default)]
pub struct Graph {
    pub n: usize,
    /// Adjacency list: `edges[u]` = list of `(v, weight)`.
    pub edges: Vec<Vec<(usize, f64)>>,
}

impl Graph {
    #[must_use]
    pub fn new(n: usize) -> Self {
        Self {
            n,
            edges: vec![Vec::new(); n],
        }
    }

    pub fn add_edge(&mut self, u: usize, v: usize, w: f64) {
        if u < self.n && v < self.n {
            self.edges[u].push((v, w));
        }
    }

    pub fn add_undirected_edge(&mut self, u: usize, v: usize, w: f64) {
        self.add_edge(u, v, w);
        self.add_edge(v, u, w);
    }

    /// BFS shortest-path distances from `src` (unweighted).
    ///
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn bfs_distances(&self, src: usize) -> Vec<Option<usize>> {
        let mut dist = vec![None; self.n];
        if src >= self.n {
            return dist;
        }
        dist[src] = Some(0);
        let mut queue = VecDeque::new();
        queue.push_back(src);
        while let Some(u) = queue.pop_front() {
            for &(v, _) in &self.edges[u] {
                if dist[v].is_none() {
                    dist[v] = Some(dist[u].unwrap() + 1);
                    queue.push_back(v);
                }
            }
        }
        dist
    }

    /// Dijkstra shortest paths from `src`.
    #[must_use]
    pub fn dijkstra(&self, src: usize) -> Vec<f64> {
        let mut dist = vec![f64::INFINITY; self.n];
        if src >= self.n {
            return dist;
        }
        dist[src] = 0.0;
        let mut heap = BinaryHeap::new();
        heap.push(Reverse((ordered_float::OrderedFloat(0.0), src)));
        while let Some(Reverse((ordered_float::OrderedFloat(d), u))) = heap.pop() {
            if d > dist[u] {
                continue;
            }
            for &(v, w) in &self.edges[u] {
                let nd = dist[u] + w;
                if nd < dist[v] {
                    dist[v] = nd;
                    heap.push(Reverse((ordered_float::OrderedFloat(nd), v)));
                }
            }
        }
        dist
    }
}

// Simple ordered float wrapper to avoid external dep.
mod ordered_float {
    #[derive(Clone, Copy, PartialEq)]
    pub struct OrderedFloat(pub f64);
    impl Eq for OrderedFloat {}
    impl PartialOrd for OrderedFloat {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }
    impl Ord for OrderedFloat {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.0.partial_cmp(&other.0).unwrap_or(std::cmp::Ordering::Equal)
        }
    }
}

// ---------------------------------------------------------------------------
// PageRank
// ---------------------------------------------------------------------------

/// Power-iteration `PageRank`.
#[derive(Debug, Clone)]
pub struct PageRank {
    pub scores: Vec<f64>,
    pub iterations: usize,
    pub converged: bool,
}

impl PageRank {
    /// Compute `PageRank` for `graph` with damping `d` and convergence `eps`.
    #[must_use]
    pub fn compute(graph: &Graph, damping: f64, max_iter: usize, eps: f64) -> Self {
        let n = graph.n;
        if n == 0 {
            return Self {
                scores: Vec::new(),
                iterations: 0,
                converged: true,
            };
        }
        let mut rank = vec![1.0 / n as f64; n];
        let mut new_rank = vec![0.0f64; n];
        let mut iterations = 0;
        let mut converged = false;

        // Out-degree for each node.
        let out_degree: Vec<f64> = graph.edges.iter().map(|e| e.len() as f64).collect();

        for iter in 0..max_iter {
            iterations = iter + 1;
            new_rank.fill((1.0 - damping) / n as f64);
            for u in 0..n {
                if out_degree[u] < 0.5 {
                    // Dangling node: distribute uniformly.
                    let contrib = damping * rank[u] / n as f64;
                    for __item in new_rank.iter_mut().take(n) {
                        (*__item) += contrib;
                    }
                } else {
                    let contrib = damping * rank[u] / out_degree[u];
                    for &(v, _) in &graph.edges[u] {
                        new_rank[v] += contrib;
                    }
                }
            }
            let diff: f64 = rank
                .iter()
                .zip(new_rank.iter())
                .map(|(a, b)| (a - b).abs())
                .sum();
            std::mem::swap(&mut rank, &mut new_rank);
            if diff < eps {
                converged = true;
                break;
            }
        }

        Self {
            scores: rank,
            iterations,
            converged,
        }
    }

    /// Top-k nodes by `PageRank` score.
    #[must_use]
    pub fn top_k(&self, k: usize) -> Vec<(usize, f64)> {
        let mut indexed: Vec<(usize, f64)> = self.scores.iter().copied().enumerate().collect();
        indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        indexed.truncate(k);
        indexed
    }
}

// ---------------------------------------------------------------------------
// BetweennessCentrality
// ---------------------------------------------------------------------------

/// Brandes algorithm for betweenness centrality (unweighted).
#[derive(Debug, Clone)]
pub struct BetweennessCentrality {
    pub scores: Vec<f64>,
}

impl BetweennessCentrality {
    #[must_use]
    pub fn compute(graph: &Graph) -> Self {
        let n = graph.n;
        let mut cb = vec![0.0f64; n];

        for s in 0..n {
            let mut stack: Vec<usize> = Vec::new();
            let mut pred: Vec<Vec<usize>> = vec![Vec::new(); n];
            let mut sigma = vec![0.0f64; n];
            sigma[s] = 1.0;
            let mut dist = vec![-1i64; n];
            dist[s] = 0;
            let mut queue = VecDeque::new();
            queue.push_back(s);

            while let Some(v) = queue.pop_front() {
                stack.push(v);
                for &(w, _) in &graph.edges[v] {
                    if dist[w] < 0 {
                        dist[w] = dist[v] + 1;
                        queue.push_back(w);
                    }
                    if dist[w] == dist[v] + 1 {
                        sigma[w] += sigma[v];
                        pred[w].push(v);
                    }
                }
            }

            let mut delta = vec![0.0f64; n];
            while let Some(w) = stack.pop() {
                for &v in &pred[w] {
                    delta[v] += sigma[v] / sigma[w] * (1.0 + delta[w]);
                }
                if w != s {
                    cb[w] += delta[w];
                }
            }
        }

        Self { scores: cb }
    }

    #[must_use]
    pub fn top_k(&self, k: usize) -> Vec<(usize, f64)> {
        let mut indexed: Vec<(usize, f64)> = self.scores.iter().copied().enumerate().collect();
        indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        indexed.truncate(k);
        indexed
    }
}

// ---------------------------------------------------------------------------
// ClosenessCentrality
// ---------------------------------------------------------------------------

/// BFS-based closeness centrality.
#[derive(Debug, Clone)]
pub struct ClosenessCentrality {
    pub scores: Vec<f64>,
}

impl ClosenessCentrality {
    #[must_use]
    pub fn compute(graph: &Graph) -> Self {
        let n = graph.n;
        let scores: Vec<f64> = (0..n)
            .map(|s| {
                let dists = graph.bfs_distances(s);
                let reachable: Vec<usize> = dists.iter().filter_map(|&d| d).collect();
                let sum: usize = reachable.iter().sum();
                if sum == 0 || reachable.len() < 2 {
                    0.0
                } else {
                    (reachable.len() - 1) as f64 / sum as f64
                }
            })
            .collect();
        Self { scores }
    }
}

// ---------------------------------------------------------------------------
// GraphPartitioning (Kernighan-Lin bisection)
// ---------------------------------------------------------------------------

/// Result of a graph bisection.
#[derive(Debug, Clone)]
pub struct BisectionResult {
    /// Partition A.
    pub set_a: Vec<usize>,
    /// Partition B.
    pub set_b: Vec<usize>,
    /// Cut size (sum of weights of edges crossing the cut).
    pub cut_cost: f64,
}

/// Kernighan-Lin graph bisection.
pub struct GraphPartitioning;

impl GraphPartitioning {
    /// Bisect `graph` into two roughly equal parts.
    #[must_use]
    pub fn kernighan_lin(graph: &Graph, max_passes: usize) -> BisectionResult {
        fn cut_cost(graph: &Graph, in_a: &[bool]) -> f64 {
            let mut cost = 0.0;
            for u in 0..graph.n {
                for &(v, w) in &graph.edges[u] {
                    if in_a[u] != in_a[v] {
                        cost += w;
                    }
                }
            }
            cost / 2.0
        }
        let n = graph.n;
        if n < 2 {
            return BisectionResult {
                set_a: (0..n).collect(),
                set_b: Vec::new(),
                cut_cost: 0.0,
            };
        }

        // Initial partition.
        let mut in_a: Vec<bool> = (0..n).map(|i| i < n / 2).collect();
        let mut best = cut_cost(graph, &in_a);
        let mut best_in_a = in_a.clone();

        for _ in 0..max_passes {
            let mut locked = vec![false; n];
            let mut gains = Vec::new();

            for _ in 0..n / 2 {
                let mut best_gain = f64::NEG_INFINITY;
                let mut best_a = 0;
                let mut best_b = 0;

                for a in 0..n {
                    if locked[a] || !in_a[a] {
                        continue;
                    }
                    for b in 0..n {
                        if locked[b] || in_a[b] {
                            continue;
                        }
                        // Compute gain.
                        let mut d_a = 0.0f64;
                        let mut d_b = 0.0f64;
                        for &(v, w) in &graph.edges[a] {
                            if in_a[v] {
                                d_a -= w;
                            } else {
                                d_a += w;
                            }
                        }
                        for &(v, w) in &graph.edges[b] {
                            if in_a[v] {
                                d_b += w;
                            } else {
                                d_b -= w;
                            }
                        }
                        let c_ab: f64 = graph.edges[a]
                            .iter()
                            .filter(|&&(v, _)| v == b)
                            .map(|&(_, w)| w)
                            .sum();
                        let gain = d_a + d_b - 2.0 * c_ab;
                        if gain > best_gain {
                            best_gain = gain;
                            best_a = a;
                            best_b = b;
                        }
                    }
                }

                locked[best_a] = true;
                locked[best_b] = true;
                gains.push((best_gain, best_a, best_b));

                // Apply swap.
                in_a[best_a] = false;
                in_a[best_b] = true;
            }

            // Find prefix of gains that maximizes cumulative.
            let mut cum = 0.0;
            let mut best_k = 0;
            let mut best_cum = 0.0f64;
            for (k, &(g, _, _)) in gains.iter().enumerate() {
                cum += g;
                if cum > best_cum {
                    best_cum = cum;
                    best_k = k + 1;
                }
            }

            if best_k == 0 {
                break;
            }

            // Reset and apply best_k swaps.
            in_a.clone_from(&best_in_a);
            for &(_, a, b) in &gains[..best_k] {
                in_a[a] = false;
                in_a[b] = true;
            }
            let new_cut = cut_cost(graph, &in_a);
            if new_cut < best {
                best = new_cut;
                best_in_a.clone_from(&in_a);
            } else {
                break;
            }
        }

        let set_a: Vec<usize> = (0..n).filter(|&i| best_in_a[i]).collect();
        let set_b: Vec<usize> = (0..n).filter(|&i| !best_in_a[i]).collect();
        BisectionResult {
            set_a,
            set_b,
            cut_cost: best,
        }
    }
}

// ---------------------------------------------------------------------------
// MaxFlow – Dinic's algorithm
// ---------------------------------------------------------------------------

/// Dinic's maximum flow algorithm.
pub struct MaxFlow {
    pub n: usize,
    /// Internal edge list: `(to, cap, rev_idx)`.
    edges: Vec<Vec<(usize, f64, usize)>>,
}

impl MaxFlow {
    #[must_use]
    pub fn new(n: usize) -> Self {
        Self {
            n,
            edges: vec![Vec::new(); n],
        }
    }

    pub fn add_edge(&mut self, u: usize, v: usize, cap: f64) {
        let ru = self.edges[v].len();
        let rv = self.edges[u].len();
        self.edges[u].push((v, cap, ru));
        self.edges[v].push((u, 0.0, rv));
    }

    /// Compute max-flow from `s` to `t`.
    #[must_use]
    pub fn max_flow(&mut self, s: usize, t: usize) -> f64 {
        let mut flow = 0.0;
        loop {
            let level = self.bfs_level(s, t);
            if level[t] < 0 {
                break;
            }
            let mut iter = vec![0usize; self.n];
            loop {
                let f = self.dfs(s, t, f64::INFINITY, &level, &mut iter);
                if f <= 0.0 {
                    break;
                }
                flow += f;
            }
        }
        flow
    }

    fn bfs_level(&self, s: usize, t: usize) -> Vec<i32> {
        let mut level = vec![-1i32; self.n];
        level[s] = 0;
        let mut queue = VecDeque::new();
        queue.push_back(s);
        while let Some(u) = queue.pop_front() {
            if u == t {
                continue;
            } // sink reached — record level but skip outgoing edges
            for &(v, cap, _) in &self.edges[u] {
                if cap > 0.0 && level[v] < 0 {
                    level[v] = level[u] + 1;
                    queue.push_back(v);
                }
            }
        }
        level
    }

    fn dfs(
        &mut self,
        u: usize,
        t: usize,
        pushed: f64,
        level: &[i32],
        iter: &mut Vec<usize>,
    ) -> f64 {
        if u == t {
            return pushed;
        }
        while iter[u] < self.edges[u].len() {
            let (v, cap, rev) = self.edges[u][iter[u]];
            if cap > 0.0 && level[v] == level[u] + 1 {
                let d = self.dfs(v, t, pushed.min(cap), level, iter);
                if d > 0.0 {
                    self.edges[u][iter[u]].1 -= d;
                    self.edges[v][rev].1 += d;
                    return d;
                }
            }
            iter[u] += 1;
        }
        0.0
    }
}

// ---------------------------------------------------------------------------
// MinCut – Stoer-Wagner
// ---------------------------------------------------------------------------

/// Stoer-Wagner global minimum cut.
pub struct MinCut;

impl MinCut {
    /// Compute the global minimum cut for an undirected weighted graph.
    /// Returns `(cut_value, partition_a, partition_b)`.
    #[must_use]
    pub fn stoer_wagner(graph: &Graph) -> (f64, Vec<usize>, Vec<usize>) {
        let n = graph.n;
        if n < 2 {
            return (0.0, (0..n).collect(), Vec::new());
        }

        // Build adjacency matrix.
        let mut w = vec![vec![0.0f64; n]; n];
        for (u, edges) in graph.edges.iter().enumerate().take(n) {
            for &(v, wt) in edges {
                w[u][v] += wt;
            }
        }

        let mut merged: Vec<Vec<usize>> = (0..n).map(|i| vec![i]).collect();
        let mut active: Vec<usize> = (0..n).collect();
        let mut min_cut = f64::INFINITY;
        let mut best_partition: Vec<usize> = Vec::new();

        for phase in 0..n - 1 {
            // Minimum cut phase.
            let mut key = vec![0.0f64; n];
            let mut in_a = vec![false; n];
            let mut last = 0;
            let mut second_last = 0;

            for i in 0..active.len() {
                // Pick maximum key node not in A.
                let next = *active
                    .iter()
                    .filter(|&&u| !in_a[u])
                    .max_by(|&&a, &&b| {
                        key[a]
                            .partial_cmp(&key[b])
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .unwrap_or(&active[0]);
                if i == active.len() - 1 {
                    if key[next] < min_cut {
                        min_cut = key[next];
                        best_partition.clone_from(&merged[next]);
                    }
                    // Merge last with second_last.
                    let ml = merged[last].clone();
                    for &v in &ml {
                        if !merged[next].contains(&v) {
                            merged[next].push(v);
                        }
                    }
                    for u in &active {
                        w[*u][next] += w[*u][last];
                        w[next][*u] += w[last][*u];
                    }
                    active.retain(|&u| u != last);
                    second_last = last;
                    last = next;
                } else {
                    second_last = last;
                    last = next;
                }
                in_a[next] = true;
                for &u in &active {
                    if !in_a[u] {
                        key[u] += w[next][u];
                    }
                }
            }
            let _ = (phase, second_last);
        }

        let other: Vec<usize> = (0..n).filter(|v| !best_partition.contains(v)).collect();
        (min_cut, best_partition, other)
    }
}

// ---------------------------------------------------------------------------
// SpanningTree – Prim's and Kruskal's
// ---------------------------------------------------------------------------

/// An edge in the spanning tree.
#[derive(Debug, Clone)]
pub struct SpanningEdge {
    pub u: usize,
    pub v: usize,
    pub weight: f64,
}

/// Minimum spanning tree algorithms.
pub struct SpanningTree;

impl SpanningTree {
    /// Prim's MST (for dense/connected graphs).
    #[must_use]
    pub fn prim(graph: &Graph) -> (f64, Vec<SpanningEdge>) {
        let n = graph.n;
        if n == 0 {
            return (0.0, Vec::new());
        }
        let mut in_mst = vec![false; n];
        let mut key = vec![f64::INFINITY; n];
        let mut parent = vec![usize::MAX; n];
        key[0] = 0.0;
        let mut total = 0.0;
        let mut edges = Vec::new();

        for _ in 0..n {
            // Pick minimum key not in MST.
            let u = (0..n)
                .filter(|&v| !in_mst[v])
                .min_by(|&a, &b| {
                    key[a]
                        .partial_cmp(&key[b])
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .unwrap_or(0);
            in_mst[u] = true;
            total += if key[u] == f64::INFINITY { 0.0 } else { key[u] };
            if parent[u] != usize::MAX {
                edges.push(SpanningEdge {
                    u: parent[u],
                    v: u,
                    weight: key[u],
                });
            }
            for &(v, w) in &graph.edges[u] {
                if !in_mst[v] && w < key[v] {
                    key[v] = w;
                    parent[v] = u;
                }
            }
        }
        (total, edges)
    }

    /// Kruskal's MST (for sparse graphs).
    #[must_use]
    pub fn kruskal(graph: &Graph) -> (f64, Vec<SpanningEdge>) {
        fn find(parent: &mut Vec<usize>, x: usize) -> usize {
            if parent[x] != x {
                parent[x] = find(parent, parent[x]);
            }
            parent[x]
        }
        fn union(parent: &mut Vec<usize>, rank: &mut [u32], x: usize, y: usize) -> bool {
            let rx = find(parent, x);
            let ry = find(parent, y);
            if rx == ry {
                return false;
            }
            if rank[rx] < rank[ry] {
                parent[rx] = ry;
            } else if rank[rx] > rank[ry] {
                parent[ry] = rx;
            } else {
                parent[ry] = rx;
                rank[rx] += 1;
            }
            true
        }
        let n = graph.n;
        let edge_count_hint: usize = graph.edges.iter().map(std::vec::Vec::len).sum::<usize>() / 2;
        let mut all_edges: Vec<(f64, usize, usize)> = Vec::with_capacity(edge_count_hint);
        for u in 0..n {
            for &(v, w) in &graph.edges[u] {
                if u < v {
                    all_edges.push((w, u, v));
                }
            }
        }
        all_edges.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

        let mut parent: Vec<usize> = (0..n).collect();
        let mut rank = vec![0u32; n];
        let mut total = 0.0;
        let mut edges = Vec::new();
        for (w, u, v) in all_edges {
            if union(&mut parent, &mut rank, u, v) {
                total += w;
                edges.push(SpanningEdge { u, v, weight: w });
            }
        }
        (total, edges)
    }
}

// ---------------------------------------------------------------------------
// GraphColoring – DSatur
// ---------------------------------------------------------------------------

/// Result of graph coloring.
#[derive(Debug, Clone)]
pub struct ColoringResult {
    /// `colors[v]` = color assigned to vertex `v` (0-indexed).
    pub colors: Vec<usize>,
    /// Number of colors used.
    pub chromatic_number: usize,
}

/// `DSatur` greedy graph coloring.
pub struct GraphColoring;

impl GraphColoring {
    #[must_use]
    pub fn dsatur(graph: &Graph) -> ColoringResult {
        let n = graph.n;
        let mut colors = vec![usize::MAX; n];
        let mut saturation = vec![0usize; n]; // number of distinct neighbor colors

        for _ in 0..n {
            // Pick uncolored vertex with max saturation (break ties by degree).
            let u = (0..n)
                .filter(|&v| colors[v] == usize::MAX)
                .max_by(|&a, &b| {
                    saturation[a]
                        .cmp(&saturation[b])
                        .then(graph.edges[a].len().cmp(&graph.edges[b].len()))
                })
                .unwrap_or(0);

            // Find the smallest usable color.
            let neighbor_colors: HashSet<usize> = graph.edges[u]
                .iter()
                .filter_map(|&(v, _)| {
                    if colors[v] == usize::MAX {
                        None
                    } else {
                        Some(colors[v])
                    }
                })
                .collect();
            let color = (0..).find(|c| !neighbor_colors.contains(c)).unwrap_or(0);
            colors[u] = color;

            // Update saturation of uncolored neighbors.
            for &(v, _) in &graph.edges[u] {
                if colors[v] == usize::MAX {
                    let nc: HashSet<usize> = graph.edges[v]
                        .iter()
                        .filter_map(|&(w, _)| {
                            if colors[w] == usize::MAX {
                                None
                            } else {
                                Some(colors[w])
                            }
                        })
                        .collect();
                    saturation[v] = nc.len();
                }
            }
        }

        // `unwrap_or(&0)` used to invent a colour 0 when NOTHING was coloured,
        // and the `+ 1` then reported one colour in use. The chromatic number
        // of a graph with no vertices is 0, and a caller that allocates
        // `chromatic_number` slots would otherwise reserve a resource that does
        // not exist.
        let chromatic_number = colors
            .iter()
            .filter(|&&c| c != usize::MAX)
            .max()
            .map_or(0, |&c| c + 1);
        ColoringResult {
            colors,
            chromatic_number,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn triangle() -> Graph {
        let mut g = Graph::new(3);
        g.add_undirected_edge(0, 1, 1.0);
        g.add_undirected_edge(1, 2, 1.0);
        g.add_undirected_edge(2, 0, 1.0);
        g
    }

    fn path(n: usize) -> Graph {
        let mut g = Graph::new(n);
        for i in 0..n - 1 {
            g.add_undirected_edge(i, i + 1, 1.0);
        }
        g
    }

    // ── Graph helpers ──────────────────────────────────────────────────────

    #[test]
    fn bfs_distances_path() {
        let g = path(5);
        let d = g.bfs_distances(0);
        assert_eq!(d[0], Some(0));
        assert_eq!(d[4], Some(4));
    }

    #[test]
    fn dijkstra_path() {
        let g = path(4);
        let d = g.dijkstra(0);
        assert!((d[3] - 3.0).abs() < 1e-9);
    }

    // ── PageRank ──────────────────────────────────────────────────────────

    #[test]
    fn pagerank_sum_to_one() {
        let g = triangle();
        let pr = PageRank::compute(&g, 0.85, 100, 1e-6);
        let sum: f64 = pr.scores.iter().sum();
        assert!((sum - 1.0).abs() < 0.01);
    }

    #[test]
    fn pagerank_symmetric_equal_scores() {
        let g = triangle();
        let pr = PageRank::compute(&g, 0.85, 100, 1e-6);
        assert!((pr.scores[0] - pr.scores[1]).abs() < 0.01);
    }

    #[test]
    fn pagerank_empty_graph() {
        let g = Graph::new(0);
        let pr = PageRank::compute(&g, 0.85, 100, 1e-6);
        assert!(pr.scores.is_empty());
    }

    #[test]
    fn pagerank_top_k() {
        let g = triangle();
        let pr = PageRank::compute(&g, 0.85, 100, 1e-6);
        let top = pr.top_k(1);
        assert_eq!(top.len(), 1);
    }

    // ── BetweennessCentrality ─────────────────────────────────────────────

    #[test]
    fn betweenness_path_middle_highest() {
        let g = path(3); // 0-1-2: node 1 is on all paths
        let bc = BetweennessCentrality::compute(&g);
        assert!(bc.scores[1] > bc.scores[0]);
        assert!(bc.scores[1] > bc.scores[2]);
    }

    #[test]
    fn betweenness_triangle_symmetric() {
        let g = triangle();
        let bc = BetweennessCentrality::compute(&g);
        assert!((bc.scores[0] - bc.scores[1]).abs() < 0.01);
    }

    #[test]
    fn betweenness_top_k() {
        let g = path(5);
        let bc = BetweennessCentrality::compute(&g);
        let top = bc.top_k(2);
        assert_eq!(top.len(), 2);
    }

    // ── ClosenessCentrality ───────────────────────────────────────────────

    #[test]
    fn closeness_center_of_path() {
        let g = path(5); // 0-1-2-3-4: node 2 is center
        let cc = ClosenessCentrality::compute(&g);
        assert!(cc.scores[2] >= cc.scores[0]);
    }

    #[test]
    fn closeness_isolated_node_zero() {
        let g = Graph::new(3); // no edges
        let cc = ClosenessCentrality::compute(&g);
        assert_eq!(cc.scores[0], 0.0);
    }

    // ── GraphPartitioning ─────────────────────────────────────────────────

    #[test]
    fn partitioning_two_cliques_low_cut() {
        // Two triangles connected by one edge.
        let mut g = Graph::new(6);
        g.add_undirected_edge(0, 1, 1.0);
        g.add_undirected_edge(1, 2, 1.0);
        g.add_undirected_edge(2, 0, 1.0);
        g.add_undirected_edge(3, 4, 1.0);
        g.add_undirected_edge(4, 5, 1.0);
        g.add_undirected_edge(5, 3, 1.0);
        g.add_undirected_edge(2, 3, 0.1); // bridge
        let result = GraphPartitioning::kernighan_lin(&g, 10);
        assert_eq!(result.set_a.len() + result.set_b.len(), 6);
    }

    // ── MaxFlow ───────────────────────────────────────────────────────────

    #[test]
    fn max_flow_simple_path() {
        let mut mf = MaxFlow::new(4);
        mf.add_edge(0, 1, 10.0);
        mf.add_edge(1, 2, 5.0);
        mf.add_edge(2, 3, 10.0);
        let flow = mf.max_flow(0, 3);
        assert!((flow - 5.0).abs() < 1e-9);
    }

    #[test]
    fn max_flow_parallel_paths() {
        let mut mf = MaxFlow::new(4);
        mf.add_edge(0, 1, 3.0);
        mf.add_edge(0, 2, 4.0);
        mf.add_edge(1, 3, 3.0);
        mf.add_edge(2, 3, 4.0);
        let flow = mf.max_flow(0, 3);
        assert!((flow - 7.0).abs() < 1e-9);
    }

    #[test]
    fn max_flow_no_path() {
        let mut mf = MaxFlow::new(2);
        let flow = mf.max_flow(0, 1);
        assert_eq!(flow, 0.0);
    }

    // ── SpanningTree ──────────────────────────────────────────────────────

    #[test]
    fn prim_path_correct_weight() {
        let g = path(4);
        let (total, edges) = SpanningTree::prim(&g);
        assert!((total - 3.0).abs() < 1e-9);
        assert_eq!(edges.len(), 3);
    }

    #[test]
    fn kruskal_triangle() {
        let g = triangle();
        let (total, edges) = SpanningTree::kruskal(&g);
        assert!((total - 2.0).abs() < 1e-9);
        assert_eq!(edges.len(), 2);
    }

    #[test]
    fn prim_empty_graph() {
        let g = Graph::new(0);
        let (total, _) = SpanningTree::prim(&g);
        assert_eq!(total, 0.0);
    }

    // ── GraphColoring ─────────────────────────────────────────────────────

    #[test]
    fn coloring_triangle_needs_3() {
        let g = triangle();
        let r = GraphColoring::dsatur(&g);
        assert_eq!(r.chromatic_number, 3);
    }

    #[test]
    fn coloring_bipartite_needs_2() {
        // Complete bipartite K_{2,2}.
        let mut g = Graph::new(4);
        g.add_undirected_edge(0, 2, 1.0);
        g.add_undirected_edge(0, 3, 1.0);
        g.add_undirected_edge(1, 2, 1.0);
        g.add_undirected_edge(1, 3, 1.0);
        let r = GraphColoring::dsatur(&g);
        assert_eq!(r.chromatic_number, 2);
    }

    #[test]
    fn coloring_no_edges_needs_1() {
        let g = Graph::new(5);
        let r = GraphColoring::dsatur(&g);
        assert_eq!(r.chromatic_number, 1);
    }

    #[test]
    fn coloring_adjacent_different_colors() {
        let g = triangle();
        let r = GraphColoring::dsatur(&g);
        for u in 0..3 {
            for &(v, _) in &g.edges[u] {
                assert_ne!(r.colors[u], r.colors[v], "adjacent nodes have same color");
            }
        }
    }

    // ── MinCut ────────────────────────────────────────────────────────────

    #[test]
    fn min_cut_single_bridge() {
        let mut g = Graph::new(4);
        g.add_undirected_edge(0, 1, 10.0);
        g.add_undirected_edge(1, 2, 1.0); // bridge
        g.add_undirected_edge(2, 3, 10.0);
        let (cut, _, _) = MinCut::stoer_wagner(&g);
        assert!(cut <= 1.1);
    }
}
