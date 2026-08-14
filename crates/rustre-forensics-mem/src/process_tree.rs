//! Process-tree reconstruction from a flat list of `ProcessInfo` records.
//!
//! Builds a parent-child hierarchy, provides DFS traversal, orphan detection,
//! ASCII rendering, and summary statistics.

use crate::ProcessInfo;
use crate::casts::usize_to_f64;

// ─── ProcessNode ─────────────────────────────────────────────────────────────

/// A node in the reconstructed process tree.
#[derive(Debug, Clone)]
pub struct ProcessNode {
    /// Information about this process.
    pub info: ProcessInfo,
    /// Child processes whose PPID matches this process's PID.
    pub children: Vec<Self>,
    /// Depth from the tree root (roots have depth 0).
    pub depth: u32,
}

impl ProcessNode {
    const fn new(info: ProcessInfo, depth: u32) -> Self {
        Self {
            info,
            children: Vec::new(),
            depth,
        }
    }

    /// Recursively collect all descendant PIDs.
    #[must_use]
    pub fn descendant_pids(&self) -> Vec<u32> {
        let mut out = Vec::new();
        for child in &self.children {
            out.push(child.info.pid);
            out.extend(child.descendant_pids());
        }
        out
    }

    /// Maximum depth of any descendant (0 if no children).
    #[must_use]
    pub fn subtree_depth(&self) -> u32 {
        if self.children.is_empty() {
            0
        } else {
            self.children
                .iter()
                .map(|c| 1 + c.subtree_depth())
                .max()
                .unwrap_or(0)
        }
    }

    /// Number of direct children.
    #[must_use]
    pub const fn child_count(&self) -> usize {
        self.children.len()
    }
}

// ─── ProcessTree ─────────────────────────────────────────────────────────────

/// A reconstructed process hierarchy.
#[derive(Debug, Default)]
pub struct ProcessTree {
    /// Root-level processes (those with no living parent in the input list,
    /// including PID 0/1 system processes).
    pub roots: Vec<ProcessNode>,
}

impl ProcessTree {
    /// Build a tree from a flat list of [`ProcessInfo`] records.
    ///
    /// Processes whose PPID does not correspond to any other process in the
    /// list become roots. PID 0 always becomes a root.
    #[must_use]
    pub fn build(processes: Vec<ProcessInfo>) -> Self {
        // Collect all known PIDs
        let all_pids: std::collections::HashSet<u32> = processes.iter().map(|p| p.pid).collect();

        // Separate roots from children
        let mut root_infos: Vec<ProcessInfo> = Vec::new();
        let mut child_infos: Vec<ProcessInfo> = Vec::new();

        for p in processes {
            if p.ppid == 0 || !all_pids.contains(&p.ppid) || p.ppid == p.pid {
                root_infos.push(p);
            } else {
                child_infos.push(p);
            }
        }

        // Build initial root nodes at depth 0
        let mut roots: Vec<ProcessNode> = root_infos
            .into_iter()
            .map(|p| ProcessNode::new(p, 0))
            .collect();

        // Iteratively attach children until no changes occur
        let mut remaining = child_infos;
        loop {
            let before = remaining.len();
            let mut still_remaining: Vec<ProcessInfo> = Vec::new();
            for child in remaining {
                if !attach_child(&mut roots, &child, 0) {
                    still_remaining.push(child);
                }
            }
            remaining = still_remaining;
            if remaining.len() == before {
                break; // No progress made; remaining are true orphans → make roots
            }
        }

        // Any truly orphaned processes become additional roots
        for orphan in remaining {
            roots.push(ProcessNode::new(orphan, 0));
        }

        Self { roots }
    }

    /// Search the tree by PID using depth-first traversal.
    #[must_use]
    pub fn find(&self, pid: u32) -> Option<&ProcessNode> {
        for root in &self.roots {
            if let Some(node) = find_node(root, pid) {
                return Some(node);
            }
        }
        None
    }

    /// Collect all (depth, &`ProcessInfo`) pairs in DFS pre-order.
    #[must_use]
    pub fn all_nodes(&self) -> Vec<(u32, &ProcessInfo)> {
        let mut out = Vec::new();
        for root in &self.roots {
            collect_nodes(root, &mut out);
        }
        out
    }

    /// Return processes that have a non-zero PPID but whose parent is not
    /// present in the tree (true orphans in the input).
    ///
    /// Note: after [`ProcessTree::build`] these appear as roots with PPID != 0.
    #[must_use]
    pub fn orphans(&self) -> Vec<&ProcessInfo> {
        let nodes = self.all_nodes();
        let all_pids: std::collections::HashSet<u32> =
            nodes.iter().map(|(_, p)| p.pid).collect();

        nodes
            .into_iter()
            .filter_map(|(_, p)| {
                if p.ppid != 0 && !all_pids.contains(&p.ppid) {
                    Some(p)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Total number of processes in the tree.
    #[must_use]
    pub fn total(&self) -> usize {
        fn count(node: &ProcessNode) -> usize {
            1 + node.children.iter().map(count).sum::<usize>()
        }
        self.roots.iter().map(count).sum()
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Attempt to attach `child` to the correct parent in `nodes`. Returns `true`
/// on success.
fn attach_child(nodes: &mut [ProcessNode], child: &ProcessInfo, depth: u32) -> bool {
    for node in nodes.iter_mut() {
        if node.info.pid == child.ppid {
            let depth = depth + 1;
            node.children.push(ProcessNode::new(child.clone(), depth));
            return true;
        }
        if attach_child(&mut node.children, child, depth + 1) {
            return true;
        }
    }
    false
}

fn find_node(node: &ProcessNode, pid: u32) -> Option<&ProcessNode> {
    if node.info.pid == pid {
        return Some(node);
    }
    for child in &node.children {
        if let Some(found) = find_node(child, pid) {
            return Some(found);
        }
    }
    None
}

fn collect_nodes<'a>(node: &'a ProcessNode, out: &mut Vec<(u32, &'a ProcessInfo)>) {
    out.push((node.depth, &node.info));
    for child in &node.children {
        collect_nodes(child, out);
    }
}

// ─── ASCII renderer ───────────────────────────────────────────────────────────

/// Render the process tree as an ASCII-art string.
///
/// Output format (depth indicated by indentation):
/// ```text
/// [4] System
///   [1000] explorer.exe
///     [2000] cmd.exe
/// ```
#[must_use]
pub fn render_tree(tree: &ProcessTree) -> String {
    let mut out = String::new();
    for root in &tree.roots {
        render_node(root, &mut out);
    }
    out
}

fn render_node(node: &ProcessNode, out: &mut String) {
    use std::fmt::Write;
    for _ in 0..node.depth {
        out.push_str("  ");
    }
    let _ = writeln!(out, "[{}] {}", node.info.pid, node.info.name);
    for child in &node.children {
        render_node(child, out);
    }
}

// ─── ProcessStats ─────────────────────────────────────────────────────────────

/// Summary statistics for a process tree.
#[derive(Debug, Clone)]
pub struct ProcessStats {
    /// Total number of processes.
    pub total: usize,
    /// Maximum depth of any node.
    pub max_depth: u32,
    /// Average number of children per non-leaf node.
    pub avg_children: f64,
    /// Number of root-level processes.
    pub roots: usize,
}

/// Compute summary statistics for a process tree.
#[must_use]
pub fn compute_stats(tree: &ProcessTree) -> ProcessStats {
    let all = tree.all_nodes();
    let total = all.len();
    let roots = tree.roots.len();

    let max_depth = all.iter().map(|(d, _)| *d).max().unwrap_or(0);

    // Average children for nodes that have at least one child
    let nodes_with_children: Vec<usize> = {
        let mut counts = Vec::new();
        for root in &tree.roots {
            collect_child_counts(root, &mut counts);
        }
        counts.into_iter().filter(|&c| c > 0).collect()
    };

    let avg_children = if nodes_with_children.is_empty() {
        0.0
    } else {
        usize_to_f64(nodes_with_children.iter().sum::<usize>()) / usize_to_f64(nodes_with_children.len())
    };

    ProcessStats {
        total,
        max_depth,
        avg_children,
        roots,
    }
}

fn collect_child_counts(node: &ProcessNode, out: &mut Vec<usize>) {
    out.push(node.children.len());
    for child in &node.children {
        collect_child_counts(child, out);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pi(pid: u32, ppid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            name: name.to_string(),
            base: 0,
            size: 0,
            threads: vec![],
            modules: vec![],
            handle_count: 0,
            create_time: 0,
        }
    }

    fn sample_processes() -> Vec<ProcessInfo> {
        vec![
            pi(4, 0, "System"),
            pi(8, 4, "Registry"),
            pi(1000, 4, "svchost.exe"),
            pi(1100, 1000, "cmd.exe"),
            pi(1200, 1000, "powershell.exe"),
            pi(2000, 0, "wininit.exe"),
            pi(2100, 2000, "services.exe"),
            pi(2200, 2100, "spoolsv.exe"),
        ]
    }

    #[test]
    fn build_tree_total_count() {
        let tree = ProcessTree::build(sample_processes());
        assert_eq!(tree.total(), 8);
    }

    #[test]
    fn build_tree_roots_count() {
        let tree = ProcessTree::build(sample_processes());
        // PID 4 and PID 2000 are roots (PPID=0)
        assert_eq!(tree.roots.len(), 2);
    }

    #[test]
    fn build_tree_find_by_pid() {
        let tree = ProcessTree::build(sample_processes());
        let node = tree.find(1100).unwrap();
        assert_eq!(node.info.name, "cmd.exe");
    }

    #[test]
    fn build_tree_find_missing() {
        let tree = ProcessTree::build(sample_processes());
        assert!(tree.find(9999).is_none());
    }

    #[test]
    fn build_tree_child_count() {
        let tree = ProcessTree::build(sample_processes());
        let svchost = tree.find(1000).unwrap();
        assert_eq!(svchost.children.len(), 2);
    }

    #[test]
    fn build_tree_depth_assignment() {
        let tree = ProcessTree::build(sample_processes());
        let cmd = tree.find(1100).unwrap();
        // System(0) → svchost(1) → cmd(2)
        assert_eq!(cmd.depth, 2);
    }

    #[test]
    fn build_tree_spoolsv_depth() {
        let tree = ProcessTree::build(sample_processes());
        let spoolsv = tree.find(2200).unwrap();
        // wininit(0) → services(1) → spoolsv(2)
        assert_eq!(spoolsv.depth, 2);
    }

    #[test]
    fn all_nodes_dfs_order() {
        let tree = ProcessTree::build(sample_processes());
        let all = tree.all_nodes();
        assert_eq!(all.len(), 8);
    }

    #[test]
    fn orphans_returns_empty_for_complete_tree() {
        let tree = ProcessTree::build(sample_processes());
        let orphans = tree.orphans();
        assert!(
            orphans.is_empty(),
            "expected no orphans, got {:?}",
            orphans.iter().map(|p| p.pid).collect::<Vec<_>>()
        );
    }

    #[test]
    fn orphans_detects_missing_parent() {
        let mut procs = sample_processes();
        // Add process with missing parent PPID=9999
        procs.push(pi(5000, 9999, "orphan.exe"));
        let tree = ProcessTree::build(procs);
        let orphans = tree.orphans();
        assert!(orphans.iter().any(|p| p.pid == 5000));
    }

    #[test]
    fn render_tree_contains_pid() {
        let tree = ProcessTree::build(sample_processes());
        let rendered = render_tree(&tree);
        assert!(rendered.contains("[4]"));
        assert!(rendered.contains("System"));
    }

    #[test]
    fn render_tree_indented_children() {
        let tree = ProcessTree::build(sample_processes());
        let rendered = render_tree(&tree);
        // cmd.exe should appear with 4 spaces of indent (depth 2)
        assert!(rendered.contains("    [1100]") || rendered.contains("    [1200]"));
    }

    #[test]
    fn render_tree_empty() {
        let tree = ProcessTree::default();
        let rendered = render_tree(&tree);
        assert!(rendered.is_empty());
    }

    #[test]
    fn compute_stats_total() {
        let tree = ProcessTree::build(sample_processes());
        let stats = compute_stats(&tree);
        assert_eq!(stats.total, 8);
    }

    #[test]
    fn compute_stats_roots() {
        let tree = ProcessTree::build(sample_processes());
        let stats = compute_stats(&tree);
        assert_eq!(stats.roots, 2);
    }

    #[test]
    fn compute_stats_max_depth() {
        let tree = ProcessTree::build(sample_processes());
        let stats = compute_stats(&tree);
        assert_eq!(stats.max_depth, 2);
    }

    #[test]
    fn compute_stats_avg_children_nonzero() {
        let tree = ProcessTree::build(sample_processes());
        let stats = compute_stats(&tree);
        assert!(stats.avg_children > 0.0);
    }

    #[test]
    fn build_single_process() {
        let tree = ProcessTree::build(vec![pi(1, 0, "init")]);
        assert_eq!(tree.roots.len(), 1);
        assert_eq!(tree.total(), 1);
    }

    #[test]
    fn build_empty() {
        let tree = ProcessTree::build(vec![]);
        assert_eq!(tree.total(), 0);
        assert!(tree.roots.is_empty());
    }

    #[test]
    fn descendant_pids() {
        let tree = ProcessTree::build(sample_processes());
        let system = tree.find(4).unwrap();
        let desc = system.descendant_pids();
        assert!(desc.contains(&8));
        assert!(desc.contains(&1000));
        assert!(desc.contains(&1100));
        assert!(desc.contains(&1200));
    }

    #[test]
    fn subtree_depth_leaf() {
        let tree = ProcessTree::build(sample_processes());
        let cmd = tree.find(1100).unwrap();
        assert_eq!(cmd.subtree_depth(), 0);
    }

    #[test]
    fn subtree_depth_root() {
        let tree = ProcessTree::build(sample_processes());
        let system = tree.find(4).unwrap();
        assert_eq!(system.subtree_depth(), 2);
    }

    #[test]
    fn node_child_count() {
        let tree = ProcessTree::build(sample_processes());
        let system = tree.find(4).unwrap();
        assert_eq!(system.child_count(), 2); // Registry + svchost
    }

    #[test]
    fn all_nodes_all_depths_present() {
        let tree = ProcessTree::build(sample_processes());
        let depths: std::collections::HashSet<u32> =
            tree.all_nodes().iter().map(|(d, _)| *d).collect();
        assert!(depths.contains(&0));
        assert!(depths.contains(&1));
        assert!(depths.contains(&2));
    }
}
