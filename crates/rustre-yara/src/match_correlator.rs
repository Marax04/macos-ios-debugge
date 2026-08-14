// match_correlator.rs — Correlate YARA matches across files/processes

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use petgraph::graph::{DiGraph, NodeIndex};

use crate::scanner_engine::ScanMatch;

// ── Types ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileScanResult {
    pub path: PathBuf,
    pub sha256: [u8; 32],
    pub size: u64,
    pub matches: Vec<ScanMatch>,
    pub scan_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub clusters: Vec<FileCluster>,
    pub rule_hit_map: HashMap<String, Vec<PathBuf>>,
    pub shared_rules: Vec<SharedRuleInfo>,
    pub unique_to_file: HashMap<PathBuf, Vec<String>>,
    pub total_files: usize,
    pub total_matches: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCluster {
    pub id: usize,
    pub files: Vec<PathBuf>,
    pub shared_rules: Vec<String>,
    pub similarity: f64,
    pub cluster_type: ClusterType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClusterType {
    SameMalwareFamily,
    SharedPacker,
    SharedCrypto,
    SharedC2Infrastructure,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedRuleInfo {
    pub rule_name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub matching_files: Vec<PathBuf>,
    pub match_count: usize,
    pub prevalence: f64,
}

// ── Correlator ────────────────────────────────────────────────────────────────

pub struct MatchCorrelator {
    results: Vec<FileScanResult>,
    similarity_threshold: f64,
}

impl MatchCorrelator {
    #[must_use] 
    pub const fn new(similarity_threshold: f64) -> Self {
        Self {
            results: Vec::new(),
            similarity_threshold,
        }
    }

    pub fn add_result(&mut self, result: FileScanResult) {
        self.results.push(result);
    }

    #[must_use] 
    pub fn correlate(&self) -> CorrelationResult {
        let rule_hit_map = self.build_rule_hit_map();
        let shared_rules = self.compute_shared_rules(&rule_hit_map);
        let unique_to_file = self.compute_unique_rules(&rule_hit_map);
        let clusters = self.cluster_files();
        let total_matches: usize = self.results.iter().map(|r| r.matches.len()).sum();

        CorrelationResult {
            clusters,
            rule_hit_map,
            shared_rules,
            unique_to_file,
            total_files: self.results.len(),
            total_matches,
        }
    }

    fn build_rule_hit_map(&self) -> HashMap<String, Vec<PathBuf>> {
        let mut map: HashMap<String, Vec<PathBuf>> = HashMap::new();
        for result in &self.results {
            for m in &result.matches {
                let key = format!("{}::{}", m.namespace, m.rule_name);
                map.entry(key).or_default().push(result.path.clone());
            }
        }
        map
    }

    fn compute_shared_rules(
        &self,
        rule_hit_map: &HashMap<String, Vec<PathBuf>>,
    ) -> Vec<SharedRuleInfo> {
        let total = self.results.len().max(1);
        let mut shared: Vec<SharedRuleInfo> = rule_hit_map
            .iter()
            .filter(|(_, files)| files.len() > 1)
            .map(|(key, files)| {
                let mut parts = key.splitn(2, "::");
                let namespace = parts.next().unwrap_or("").to_string();
                let rule_name = parts.next().unwrap_or(key).to_string();
                let prevalence = f64::from(u32::try_from(files.len()).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total).unwrap_or(u32::MAX));

                // Find tags from first match
                let tags = self
                    .results
                    .iter()
                    .flat_map(|r| r.matches.iter())
                    .find(|m| m.rule_name == rule_name && m.namespace == namespace)
                    .map(|m| m.tags.clone())
                    .unwrap_or_default();

                SharedRuleInfo {
                    rule_name,
                    namespace,
                    tags,
                    match_count: files.len(),
                    matching_files: files.clone(),
                    prevalence,
                }
            })
            .collect();

        shared.sort_by(|a, b| b.match_count.cmp(&a.match_count));
        shared
    }

    fn compute_unique_rules(
        &self,
        rule_hit_map: &HashMap<String, Vec<PathBuf>>,
    ) -> HashMap<PathBuf, Vec<String>> {
        let mut unique: HashMap<PathBuf, Vec<String>> = HashMap::new();
        for result in &self.results {
            let file_rules: Vec<String> = result
                .matches
                .iter()
                .filter(|m| {
                    let key = format!("{}::{}", m.namespace, m.rule_name);
                    rule_hit_map.get(&key).is_none_or(|files| files.len() == 1)
                })
                .map(|m| m.rule_name.clone())
                .collect();

            if !file_rules.is_empty() {
                unique.insert(result.path.clone(), file_rules);
            }
        }
        unique
    }

    fn cluster_files(&self) -> Vec<FileCluster> {
        if self.results.is_empty() {
            return vec![];
        }

        // Build similarity matrix using Jaccard similarity on rule sets
        let file_rules: HashMap<PathBuf, HashSet<String>> = self
            .results
            .iter()
            .map(|r| {
                let rules: HashSet<String> = r
                    .matches
                    .iter()
                    .map(|m| format!("{}::{}", m.namespace, m.rule_name))
                    .collect();
                (r.path.clone(), rules)
            })
            .collect();

        // Build graph: edge between files with similarity > threshold
        let files: Vec<&PathBuf> = file_rules.keys().collect();
        let n = files.len();
        let mut graph: DiGraph<PathBuf, f64> = DiGraph::new();
        let node_indices: Vec<NodeIndex> = files
            .iter()
            .map(|p| graph.add_node((*p).clone()))
            .collect();

        for i in 0..n {
            for j in (i + 1)..n {
                let rules_i = &file_rules[files[i]];
                let rules_j = &file_rules[files[j]];

                if rules_i.is_empty() && rules_j.is_empty() {
                    continue;
                }

                let intersection_len = rules_i.intersection(rules_j).count();
                let union_size = rules_i.union(rules_j).count();

                if union_size == 0 {
                    continue;
                }

                let jaccard = f64::from(u32::try_from(intersection_len).unwrap_or(u32::MAX)) / f64::from(u32::try_from(union_size).unwrap_or(u32::MAX));

                if jaccard >= self.similarity_threshold {
                    graph.add_edge(node_indices[i], node_indices[j], jaccard);
                    graph.add_edge(node_indices[j], node_indices[i], jaccard);
                }
            }
        }

        self.extract_clusters(
            n, &graph, &node_indices, &files, &file_rules,
        )
    }

    fn extract_clusters(
        &self,
        n: usize,
        graph: &DiGraph<PathBuf, f64>,
        node_indices: &[NodeIndex],
        files: &[&PathBuf],
        file_rules: &HashMap<PathBuf, HashSet<String>>,
    ) -> Vec<FileCluster> {
        let mut visited = vec![false; n];
        let mut clusters = Vec::new();
        let mut cluster_id = 0;

        for start in 0..n {
            if visited[start] {
                continue;
            }

            let mut component = vec![start];
            let mut queue = std::collections::VecDeque::new();
            queue.push_back(start);
            visited[start] = true;

            while let Some(curr) = queue.pop_front() {
                for neighbor in graph.neighbors(node_indices[curr]) {
                    let neighbor_idx = graph
                        .node_indices()
                        .position(|ni| ni == neighbor)
                        .unwrap_or(n);
                    if neighbor_idx < n && !visited[neighbor_idx] {
                        visited[neighbor_idx] = true;
                        component.push(neighbor_idx);
                        queue.push_back(neighbor_idx);
                    }
                }
            }

            if component.len() < 2 {
                continue;
            }

            let shared_rules = Self::compute_component_shared_rules(&component, files, file_rules);

            let avg_similarity = Self::compute_avg_similarity(&component, graph, node_indices);

            let cluster_type = self.classify_cluster(&shared_rules);

            clusters.push(FileCluster {
                id: cluster_id,
                files: component.iter().map(|&idx| files[idx].clone()).collect(),
                shared_rules,
                similarity: avg_similarity,
                cluster_type,
            });

            cluster_id += 1;
        }

        let mut sorted = clusters;
        sorted.sort_by(|a, b| b.files.len().cmp(&a.files.len()));
        sorted
    }

    fn compute_component_shared_rules(
        component: &[usize],
        files: &[&PathBuf],
        file_rules: &HashMap<PathBuf, HashSet<String>>,
    ) -> Vec<String> {
        let component_rules: Vec<HashSet<&str>> = component
            .iter()
            .map(|&idx| {
                file_rules[files[idx]]
                    .iter()
                    .map(std::string::String::as_str)
                    .collect::<HashSet<&str>>()
            })
            .collect();

        if component_rules.is_empty() {
            vec![]
        } else {
            let mut intersection: HashSet<&str> = component_rules[0].clone();
            for rules in &component_rules[1..] {
                intersection = intersection.intersection(rules).copied().collect();
            }
            intersection.into_iter().map(std::string::ToString::to_string).collect()
        }
    }

    fn compute_avg_similarity(
        component: &[usize],
        graph: &DiGraph<PathBuf, f64>,
        node_indices: &[NodeIndex],
    ) -> f64 {
        if component.len() <= 1 {
            return 1.0;
        }
        let mut sum = 0.0;
        let mut count = 0;
        for i in 0..component.len() {
            for j in (i + 1)..component.len() {
                if let Some(edge) = graph.find_edge(node_indices[component[i]], node_indices[component[j]]) {
                    sum += graph.edge_weight(edge).copied().unwrap_or(0.0);
                    count += 1;
                }
            }
        }
        if count > 0 { sum / f64::from(count) } else { 0.0 }
    }

    fn classify_cluster(&self, shared_rules: &[String]) -> ClusterType {
        let has_tag = |tag: &str| {
            self.results
                .iter()
                .flat_map(|r| r.matches.iter())
                .any(|m| m.tags.iter().any(|t| t == tag))
        };

        let rule_names: Vec<&str> = shared_rules.iter().map(std::string::String::as_str).collect();

        // Tag-based classification takes precedence over rule-name heuristics:
        // YARA tags are an explicit author signal of intent, while rule names
        // are only loosely conventional.
        if has_tag("packer") {
            ClusterType::SharedPacker
        } else if has_tag("crypto") {
            ClusterType::SharedCrypto
        } else if has_tag("c2") || has_tag("beacon") {
            ClusterType::SharedC2Infrastructure
        } else if rule_names.iter().any(|r| r.contains("packer") || r.contains("upx") || r.contains("themida")) {
            ClusterType::SharedPacker
        } else if rule_names.iter().any(|r| r.contains("crypto") || r.contains("aes") || r.contains("rc4")) {
            ClusterType::SharedCrypto
        } else if rule_names.iter().any(|r| r.contains("c2") || r.contains("beacon") || r.contains("cobalt")) {
            ClusterType::SharedC2Infrastructure
        } else if shared_rules.len() > 3 {
            ClusterType::SameMalwareFamily
        } else {
            ClusterType::Unknown
        }
    }

    #[must_use] 
    pub fn build_match_graph(&self) -> MatchGraph {
        let mut graph = MatchGraph::new();

        for result in &self.results {
            let file_node = graph.add_file(&result.path, result.sha256);
            for m in &result.matches {
                let rule_node = graph.add_rule(&m.rule_name, &m.namespace, &m.tags);
                graph.add_edge(file_node, rule_node, EdgeKind::Matches);
            }
        }

        graph
    }

    #[must_use] 
    pub fn export_stix2(&self, correlation: &CorrelationResult) -> serde_json::Value {
        use serde_json::{json, Value};

        let mut objects: Vec<Value> = Vec::new();

        // Bundle header
        let bundle_id = format!("bundle--{}", uuid_v4());

        // Malware objects for each cluster
        for (i, cluster) in correlation.clusters.iter().enumerate() {
            let malware_id = format!("malware--{}", uuid_v4());
            objects.push(json!({
                "type": "malware",
                "spec_version": "2.1",
                "id": malware_id,
                "name": format!("Cluster-{}", i),
                "malware_types": ["unknown"],
                "is_family": cluster.files.len() > 2,
                "description": format!(
                    "Cluster of {} samples sharing {} YARA rules",
                    cluster.files.len(),
                    cluster.shared_rules.len()
                ),
                "labels": cluster.shared_rules,
            }));

            // File objects
            for path in &cluster.files {
                let sha256 = self
                    .results
                    .iter()
                    .find(|r| &r.path == path)
                    .map(|r| hex::encode(r.sha256))
                    .unwrap_or_default();

                let file_id = format!("file--{}", uuid_v4());
                objects.push(json!({
                    "type": "file",
                    "spec_version": "2.1",
                    "id": file_id,
                    "name": path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown"),
                    "hashes": { "SHA-256": sha256 },
                }));
            }
        }

        // YARA indicator objects for shared rules
        for rule_info in &correlation.shared_rules {
            if rule_info.prevalence > 0.5 {
                continue; // Too common to be useful as IoC
            }
            let indicator_id = format!("indicator--{}", uuid_v4());
            objects.push(json!({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "name": rule_info.rule_name,
                "indicator_types": ["malicious-activity"],
                "pattern_type": "yara",
                "pattern": format!("rule {} {{ condition: true }}", rule_info.rule_name),
                "valid_from": "2024-01-01T00:00:00Z",
                "description": format!(
                    "YARA rule matching {} files (prevalence: {:.1}%)",
                    rule_info.match_count,
                    rule_info.prevalence * 100.0
                ),
                "labels": rule_info.tags,
            }));
        }

        json!({
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "objects": objects,
        })
    }
}

fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    format!("{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        t, t >> 16, t & 0xFFF, (t >> 8) & 0x3FFF | 0x8000, u64::from(t))
}

// ── Match graph ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GraphNode {
    File { path: PathBuf, sha256: [u8; 32] },
    Rule { name: String, namespace: String, tags: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdgeKind {
    Matches,
    RelatedTo,
    SameFamily,
}

pub struct MatchGraph {
    nodes: Vec<GraphNode>,
    edges: Vec<(usize, usize, EdgeKind)>,
    file_index: HashMap<PathBuf, usize>,
    rule_index: HashMap<String, usize>,
}

impl Default for MatchGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl MatchGraph {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            file_index: HashMap::new(),
            rule_index: HashMap::new(),
        }
    }

    pub fn add_file(&mut self, path: &PathBuf, sha256: [u8; 32]) -> usize {
        if let Some(&idx) = self.file_index.get(path) {
            return idx;
        }
        let idx = self.nodes.len();
        self.nodes.push(GraphNode::File { path: path.clone(), sha256 });
        self.file_index.insert(path.clone(), idx);
        idx
    }

    pub fn add_rule(&mut self, name: &str, namespace: &str, tags: &[String]) -> usize {
        let key = format!("{namespace}::{name}");
        if let Some(&idx) = self.rule_index.get(&key) {
            return idx;
        }
        let idx = self.nodes.len();
        self.nodes.push(GraphNode::Rule {
            name: name.to_string(),
            namespace: namespace.to_string(),
            tags: tags.to_vec(),
        });
        self.rule_index.insert(key, idx);
        idx
    }

    pub fn add_edge(&mut self, from: usize, to: usize, kind: EdgeKind) {
        self.edges.push((from, to, kind));
    }

    #[must_use] 
    pub const fn node_count(&self) -> usize { self.nodes.len() }
    #[must_use] 
    pub const fn edge_count(&self) -> usize { self.edges.len() }

    #[must_use] 
    pub fn files_matching_rule(&self, rule_name: &str, namespace: &str) -> Vec<&PathBuf> {
        let key = format!("{namespace}::{rule_name}");
        let Some(&rule_idx) = self.rule_index.get(&key) else { return vec![] };

        self.edges
            .iter()
            .filter(|(_, to, _)| *to == rule_idx)
            .filter_map(|(from, _, _)| {
                if let GraphNode::File { path, .. } = &self.nodes[*from] {
                    Some(path)
                } else {
                    None
                }
            })
            .collect()
    }

    #[must_use] 
    pub fn rules_for_file(&self, path: &PathBuf) -> Vec<&GraphNode> {
        let Some(&file_idx) = self.file_index.get(path) else { return vec![] };

        self.edges
            .iter()
            .filter(|(from, _, _)| *from == file_idx)
            .map(|(_, to, _)| &self.nodes[*to])
            .collect()
    }

    #[must_use] 
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;

        let nodes: Vec<_> = self.nodes.iter().enumerate().map(|(i, n)| match n {
            GraphNode::File { path, sha256 } => json!({
                "id": i,
                "type": "file",
                "label": path.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
                "path": path.to_string_lossy(),
                "sha256": hex::encode(sha256),
            }),
            GraphNode::Rule { name, namespace, tags } => json!({
                "id": i,
                "type": "rule",
                "label": name,
                "namespace": namespace,
                "tags": tags,
            }),
        }).collect();

        let edges: Vec<_> = self.edges.iter().map(|(from, to, kind)| json!({
            "from": from,
            "to": to,
            "kind": format!("{:?}", kind),
        })).collect();

        json!({ "nodes": nodes, "edges": edges })
    }
}

// ── Statistics ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationStats {
    pub total_files: usize,
    pub total_unique_rules: usize,
    pub total_matches: usize,
    pub cluster_count: usize,
    pub avg_cluster_size: f64,
    pub most_common_rules: Vec<(String, usize)>,
    pub coverage_pct: f64,
}

#[must_use] 
pub fn compute_stats(results: &[FileScanResult], correlation: &CorrelationResult) -> CorrelationStats {
    let files_with_matches = results.iter().filter(|r| !r.matches.is_empty()).count();
    let coverage_pct = if results.is_empty() {
        0.0
    } else {
        f64::from(u32::try_from(files_with_matches).unwrap_or(u32::MAX)) / f64::from(u32::try_from(results.len()).unwrap_or(u32::MAX)) * 100.0
    };

    let avg_cluster_size = if correlation.clusters.is_empty() {
        0.0
    } else {
        f64::from(u32::try_from(correlation.clusters.iter().map(|c| c.files.len()).sum::<usize>()).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(correlation.clusters.len()).unwrap_or(u32::MAX))
    };

    let mut rule_counts: Vec<(String, usize)> = correlation
        .rule_hit_map
        .iter()
        .map(|(k, v)| (k.clone(), v.len()))
        .collect();
    rule_counts.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    rule_counts.truncate(10);

    CorrelationStats {
        total_files: results.len(),
        total_unique_rules: correlation.rule_hit_map.len(),
        total_matches: correlation.total_matches,
        cluster_count: correlation.clusters.len(),
        avg_cluster_size,
        most_common_rules: rule_counts,
        coverage_pct,
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(path: &str, rules: &[&str]) -> FileScanResult {
        FileScanResult {
            path: PathBuf::from(path),
            sha256: [0u8; 32],
            size: 1024,
            scan_time_ms: 10,
            matches: rules
                .iter()
                .map(|r| ScanMatch {
                    rule_name: r.to_string(),
                    namespace: "default".to_string(),
                    tags: vec![],
                    meta: HashMap::new(),
                    pattern_matches: vec![],
                })
                .collect(),
        }
    }

    #[test]
    fn test_correlator_clusters() {
        let mut correlator = MatchCorrelator::new(0.5);
        correlator.add_result(make_result("a.exe", &["ransomware_lockbit", "crypto_aes", "upx"]));
        correlator.add_result(make_result("b.exe", &["ransomware_lockbit", "crypto_aes"]));
        correlator.add_result(make_result("c.exe", &["clean_tool"]));

        let result = correlator.correlate();
        assert!(!result.clusters.is_empty());
        // a.exe and b.exe should cluster together
        let ab_cluster = result.clusters.iter().find(|c| c.files.len() == 2);
        assert!(ab_cluster.is_some());
    }

    #[test]
    fn test_match_graph() {
        let mut graph = MatchGraph::new();
        let f1 = graph.add_file(&PathBuf::from("a.exe"), [0u8; 32]);
        let r1 = graph.add_rule("test_rule", "default", &[]);
        graph.add_edge(f1, r1, EdgeKind::Matches);

        assert_eq!(graph.node_count(), 2);
        assert_eq!(graph.edge_count(), 1);
        assert_eq!(graph.files_matching_rule("test_rule", "default").len(), 1);
    }
}
