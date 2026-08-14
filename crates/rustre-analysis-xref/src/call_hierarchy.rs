//! `call_hierarchy` — Call hierarchy construction and traversal for binary analysis.
//!
//! Provides [`CallHierarchy`] and [`HierarchyNode`] for building caller/callee trees,
//! plus free functions [`callers_of`] and [`callees_of`].

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ── NodeFlags ─────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Attributes of a function node in the hierarchy.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NodeFlags: u32 {
        /// Function is an import/thunk stub.
        const IMPORT    = 1 << 0;
        /// Function is exported from the binary.
        const EXPORT    = 1 << 1;
        /// Function is a recursive entry (appears in its own subtree).
        const RECURSIVE = 1 << 2;
        /// Function is a leaf (no callees found).
        const LEAF      = 1 << 3;
        /// Function is a root (nothing calls it from within the binary).
        const ROOT      = 1 << 4;
        /// Function has indirect call sites (target not statically known).
        const INDIRECT  = 1 << 5;
    }
}

// ── HierarchyNode ─────────────────────────────────────────────────────────────

/// A function node in the call hierarchy graph.
#[derive(Debug, Clone)]
pub struct HierarchyNode {
    /// Virtual address of the function.
    pub address: u64,
    /// Human-readable name (symbol, demangled, or auto-generated).
    pub name: String,
    /// Callers (functions that call this one). Sorted ascending.
    pub callers: Vec<u64>,
    /// Callees (functions this one calls). Sorted ascending.
    pub callees: Vec<u64>,
    /// Node attributes.
    pub flags: NodeFlags,
    /// Call-site count (how many times this function is called total).
    pub call_site_count: usize,
    /// Optional module/section tag.
    pub module: Option<String>,
}

impl HierarchyNode {
    /// Create a new node for `address` with the given name.
    #[must_use]
    pub fn new(address: u64, name: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
            callers: Vec::new(),
            callees: Vec::new(),
            flags: NodeFlags::empty(),
            call_site_count: 0,
            module: None,
        }
    }

    /// Whether this node is a leaf (calls nothing).
    #[must_use]
    pub const fn is_leaf(&self) -> bool {
        self.callees.is_empty()
    }

    /// Whether this node is a root (nothing calls it in-binary).
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.callers.is_empty()
    }

    /// Whether this node is recursive (directly or indirectly calls itself).
    #[must_use]
    pub const fn is_recursive(&self) -> bool {
        self.flags.contains(NodeFlags::RECURSIVE)
    }

    /// Whether this node is an imported stub.
    #[must_use]
    pub const fn is_import(&self) -> bool {
        self.flags.contains(NodeFlags::IMPORT)
    }

    /// Fan-in: number of distinct callers.
    #[must_use]
    pub const fn fan_in(&self) -> usize {
        self.callers.len()
    }

    /// Fan-out: number of distinct callees.
    #[must_use]
    pub const fn fan_out(&self) -> usize {
        self.callees.len()
    }

    /// Set the module name.
    #[must_use]
    pub fn with_module(mut self, module: impl Into<String>) -> Self {
        self.module = Some(module.into());
        self
    }
}

impl fmt::Display for HierarchyNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}  {}", self.address, self.name)?;
        if !self.callers.is_empty() || !self.callees.is_empty() {
            write!(f, "  [in:{} out:{}]", self.fan_in(), self.fan_out())?;
        }
        if self.flags.contains(NodeFlags::IMPORT) {
            write!(f, "  <import>")?;
        }
        if self.flags.contains(NodeFlags::RECURSIVE) {
            write!(f, "  <recursive>")?;
        }
        Ok(())
    }
}

// ── CallEdge ──────────────────────────────────────────────────────────────────

/// A directed call edge in the hierarchy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallEdge {
    /// Caller address.
    pub from: u64,
    /// Callee address.
    pub to: u64,
    /// Number of call sites from `from` to `to`.
    pub site_count: usize,
}

// ── HierarchyConfig ───────────────────────────────────────────────────────────

/// Configuration for hierarchy queries.
#[derive(Debug, Clone)]
pub struct HierarchyConfig {
    /// Maximum traversal depth (0 = unlimited).
    pub max_depth: usize,
    /// Stop descending into import nodes.
    pub stop_at_imports: bool,
    /// Include nodes with no symbols.
    pub include_unnamed: bool,
}

impl Default for HierarchyConfig {
    fn default() -> Self {
        Self { max_depth: 16, stop_at_imports: true, include_unnamed: true }
    }
}

impl HierarchyConfig {
    #[must_use]
    pub const fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    #[must_use]
    pub const fn stopping_at_imports(mut self) -> Self {
        self.stop_at_imports = true;
        self
    }
}

// ── CallTree ──────────────────────────────────────────────────────────────────

/// A tree-shaped view of the call hierarchy rooted at one function.
///
/// Each node carries the child trees for its callees (callers-of view is
/// inverted: children are *callers*).
#[derive(Debug, Clone)]
pub struct CallTree {
    /// Root function address.
    pub root: u64,
    /// Root function name.
    pub name: String,
    /// Child subtrees (callees or callers depending on direction).
    pub children: Vec<Self>,
    /// Depth from the original query root.
    pub depth: usize,
    /// Cycle guard: this node was already visited in this path.
    pub is_cycle: bool,
}

impl Drop for CallTree {
    /// Iteratively drain `children` instead of relying on the compiler's
    /// default (recursive) drop glue.
    ///
    /// `CallTree` is a chain of nested `Vec<CallTree>`s, and with
    /// `HierarchyConfig::max_depth == 0` (unlimited) a long acyclic call
    /// chain builds a tree tens of thousands of levels deep. Even after
    /// [`CallHierarchy::build_tree_iterative`] eliminated the recursive
    /// *construction*, dropping such a tree still overflowed the stack:
    /// the auto-generated `Drop` for `CallTree` drops its `children` Vec,
    /// which drops each child `CallTree`, which drops *its* children, one
    /// native stack frame per level. This explicit `Drop` walks the tree
    /// with a heap-allocated work stack instead, taking children out of
    /// each node (replacing them with an empty `Vec`, which is a cheap
    /// no-op drop) so the recursive glue never fires.
    fn drop(&mut self) {
        let mut stack: Vec<Self> = std::mem::take(&mut self.children);
        while let Some(mut node) = stack.pop() {
            stack.append(&mut node.children);
            // `node` drops here with empty `children` — no recursion.
        }
    }
}

impl CallTree {
    /// Total number of nodes in this tree.
    ///
    /// Iterative (explicit work-stack) rather than recursive: `CallTree`s
    /// built with `HierarchyConfig::max_depth == 0` (unlimited) can be as
    /// deep as the longest acyclic call chain in the binary, and a naive
    /// recursive walk over an adversarially deep or crafted tree risks a
    /// native stack overflow (same class of bug as the recursion risk fixed
    /// in `cfg_dominators.rs`).
    #[must_use]
    pub fn node_count(&self) -> usize {
        let mut stack: Vec<&Self> = vec![self];
        let mut count = 0usize;
        while let Some(t) = stack.pop() {
            count += 1;
            stack.extend(t.children.iter());
        }
        count
    }

    /// Maximum depth of the tree. Iterative for the same reason as
    /// [`Self::node_count`].
    #[must_use]
    pub fn max_depth(&self) -> usize {
        let mut stack: Vec<&Self> = vec![self];
        let mut best = self.depth;
        while let Some(t) = stack.pop() {
            best = best.max(t.depth);
            stack.extend(t.children.iter());
        }
        best
    }

    /// Collect all unique addresses in the tree. Iterative for the same
    /// reason as [`Self::node_count`].
    pub fn collect_addresses(&self, out: &mut HashSet<u64>) {
        let mut stack: Vec<&Self> = vec![self];
        while let Some(t) = stack.pop() {
            out.insert(t.root);
            stack.extend(t.children.iter());
        }
    }

    /// Format the tree as indented text.
    #[must_use]
    pub fn format_tree(&self) -> String {
        use std::fmt::Write as _;
        let mut buf = String::new();
        // Iterative pre-order DFS (explicit stack) instead of recursion, for
        // the same stack-overflow-avoidance reason as `node_count` above.
        // Children are pushed in reverse so they're popped/printed in their
        // original left-to-right order.
        let mut stack: Vec<(&Self, usize)> = vec![(self, 0)];
        while let Some((t, indent)) = stack.pop() {
            let prefix = "  ".repeat(indent);
            if t.is_cycle {
                let _ = writeln!(buf, "{prefix}{:#010x}  {} <cycle>", t.root, t.name);
                continue;
            }
            let _ = writeln!(buf, "{prefix}{:#010x}  {}", t.root, t.name);
            for child in t.children.iter().rev() {
                stack.push((child, indent + 1));
            }
        }
        buf
    }
}

// ── HierarchyStats ────────────────────────────────────────────────────────────

/// Statistics about the call hierarchy graph.
#[derive(Debug, Clone)]
pub struct HierarchyStats {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub root_count: usize,
    pub leaf_count: usize,
    pub import_count: usize,
    pub recursive_count: usize,
    pub max_fan_in: usize,
    pub max_fan_out: usize,
    /// Address of the function with highest fan-in.
    pub hottest_target: Option<u64>,
}

impl HierarchyStats {
    #[must_use]
    pub fn format_report(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        let _ = writeln!(s, "Nodes         : {}", self.total_nodes);
        let _ = writeln!(s, "Edges         : {}", self.total_edges);
        let _ = writeln!(s, "Roots         : {}", self.root_count);
        let _ = writeln!(s, "Leaves        : {}", self.leaf_count);
        let _ = writeln!(s, "Imports       : {}", self.import_count);
        let _ = writeln!(s, "Recursive     : {}", self.recursive_count);
        let _ = writeln!(s, "Max fan-in    : {}", self.max_fan_in);
        let _ = writeln!(s, "Max fan-out   : {}", self.max_fan_out);
        if let Some(addr) = self.hottest_target {
            let _ = writeln!(s, "Hottest target: {addr:#010x}");
        }
        s
    }
}

// ── CallHierarchy ─────────────────────────────────────────────────────────────

/// The call hierarchy of a binary — a directed graph of function-call
/// relationships.
///
/// Nodes are keyed by their virtual address. Edge directionality:
/// `from → to` means "`from` calls `to`".
#[derive(Debug, Default)]
pub struct CallHierarchy {
    nodes: HashMap<u64, HierarchyNode>,
    /// Keyed by `(from, to)` mapping to the site count. A plain
    /// `HashSet<CallEdge>` was used previously, but `CallEdge`'s derived
    /// `Hash`/`Eq` include `site_count`, which made every increment insert a
    /// *new* set entry instead of updating one; each `add_call`/`remove_call`
    /// then had to linearly scan the whole edge set to find the entry with
    /// the current count, making hierarchy construction O(E^2). Keying by
    /// `(from, to)` alone makes both operations O(1).
    edges: HashMap<(u64, u64), usize>,
}

impl CallHierarchy {
    /// Create an empty hierarchy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ── Node operations ───────────────────────────────────────────────────────

    /// Add or return a node for `address`. If it already exists the name is
    /// updated only when the existing name starts with "sub_" (i.e. auto-gen).
    ///
    /// # Panics
    ///
    /// Panics if the node cannot be retrieved after insertion (should never happen).
    pub fn add_node(&mut self, address: u64, name: impl Into<String>) -> &mut HierarchyNode {
        let name = name.into();
        let node = self.nodes.entry(address).or_insert_with(|| HierarchyNode::new(address, ""));
        if node.name.is_empty() || node.name.starts_with("sub_") {
            node.name = name;
        }
        self.nodes.get_mut(&address).expect("just inserted")
    }

    /// Get a node by address.
    #[must_use]
    pub fn node(&self, address: u64) -> Option<&HierarchyNode> {
        self.nodes.get(&address)
    }

    /// Get a mutable node reference.
    pub fn node_mut(&mut self, address: u64) -> Option<&mut HierarchyNode> {
        self.nodes.get_mut(&address)
    }

    /// Set the name of a node, creating it if it doesn't exist.
    pub fn set_name(&mut self, address: u64, name: impl Into<String>) {
        let name = name.into();
        self.nodes
            .entry(address)
            .and_modify(|n| n.name.clone_from(&name))
            .or_insert_with(|| HierarchyNode::new(address, name));
    }

    /// Mark a node as an import.
    pub fn mark_import(&mut self, address: u64) {
        if let Some(n) = self.nodes.get_mut(&address) {
            n.flags |= NodeFlags::IMPORT;
        }
    }

    /// Mark a node as exported.
    pub fn mark_export(&mut self, address: u64) {
        if let Some(n) = self.nodes.get_mut(&address) {
            n.flags |= NodeFlags::EXPORT;
        }
    }

    // ── Edge operations ───────────────────────────────────────────────────────

    /// Record a call from `caller` to `dest`.  Both nodes are created if they
    /// don't yet exist (with auto-generated names).
    ///
    /// # Panics
    ///
    /// Panics if nodes cannot be retrieved after insertion (should never happen).
    pub fn add_call(&mut self, caller: u64, dest: u64) {
        let caller_name = format!("sub_{caller:08x}");
        let dest_name = format!("sub_{dest:08x}");
        self.nodes.entry(caller).or_insert_with(|| HierarchyNode::new(caller, caller_name));
        self.nodes.entry(dest).or_insert_with(|| HierarchyNode::new(dest, dest_name));

        // Update adjacency lists.
        let dest_in_callers = self.nodes[&dest].callers.contains(&caller);
        let caller_in_callees = self.nodes[&caller].callees.contains(&dest);

        if !dest_in_callers {
            self.nodes.get_mut(&dest).expect("just inserted").callers.push(caller);
            self.nodes.get_mut(&dest).expect("just inserted").callers.sort_unstable();
        }
        if !caller_in_callees {
            self.nodes.get_mut(&caller).expect("just inserted").callees.push(dest);
            self.nodes.get_mut(&caller).expect("just inserted").callees.sort_unstable();
        }

        *self.edges.entry((caller, dest)).or_insert(0) += 1;

        // Increment call_site_count on dest.
        if let Some(n) = self.nodes.get_mut(&dest) {
            n.call_site_count += 1;
        }
    }

    /// Remove the call edge `caller → dest`. Returns true if it existed.
    pub fn remove_call(&mut self, caller: u64, dest: u64) -> bool {
        // The edge value is the NUMBER of call sites, and removing the edge
        // removes all of them. Subtracting a fixed 1 left a permanently
        // inflated fan-in on every edge with more than one call site — after
        // removing the only caller, `call_site_count` still claimed the target
        // was called N-1 times.
        let removed = self.edges.remove(&(caller, dest));
        let existed = removed.is_some();
        if let Some(sites) = removed {
            if let Some(n) = self.nodes.get_mut(&dest) {
                n.callers.retain(|&a| a != caller);
                n.call_site_count = n.call_site_count.saturating_sub(sites);
            }
            if let Some(n) = self.nodes.get_mut(&caller) {
                n.callees.retain(|&a| a != dest);
            }
        }
        existed
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /// All callers of `address` (direct, one level).
    #[must_use]
    pub fn callers_of(&self, address: u64) -> Vec<u64> {
        self.nodes.get(&address).map_or(Vec::new(), |n| n.callers.clone())
    }

    /// All callees of `address` (direct, one level).
    #[must_use]
    pub fn callees_of(&self, address: u64) -> Vec<u64> {
        self.nodes.get(&address).map_or(Vec::new(), |n| n.callees.clone())
    }

    /// All root functions (no callers within the binary).
    #[must_use]
    pub fn roots(&self) -> Vec<u64> {
        let mut out: Vec<u64> = self.nodes
            .values()
            .filter(|n| n.callers.is_empty() && !n.flags.contains(NodeFlags::IMPORT))
            .map(|n| n.address)
            .collect();
        out.sort_unstable();
        out
    }

    /// All leaf functions (call nothing).
    #[must_use]
    pub fn leaves(&self) -> Vec<u64> {
        let mut out: Vec<u64> = self.nodes
            .values()
            .filter(|n| n.callees.is_empty())
            .map(|n| n.address)
            .collect();
        out.sort_unstable();
        out
    }

    /// Functions reachable from `start` (BFS, callee direction), up to `max_depth`.
    #[must_use]
    pub fn reachable_callees(&self, start: u64, max_depth: usize) -> Vec<u64> {
        let mut visited: HashSet<u64> = HashSet::new();
        let mut queue: VecDeque<(u64, usize)> = VecDeque::new();
        queue.push_back((start, 0));
        while let Some((addr, depth)) = queue.pop_front() {
            if visited.contains(&addr) {
                continue;
            }
            visited.insert(addr);
            if max_depth > 0 && depth >= max_depth {
                continue;
            }
            if let Some(node) = self.nodes.get(&addr) {
                for &callee in &node.callees {
                    if !visited.contains(&callee) {
                        queue.push_back((callee, depth + 1));
                    }
                }
            }
        }
        visited.remove(&start);
        let mut out: Vec<u64> = visited.into_iter().collect();
        out.sort_unstable();
        out
    }

    /// Functions that transitively call `target`, up to `max_depth`.
    #[must_use]
    pub fn transitive_callers(&self, target: u64, max_depth: usize) -> Vec<u64> {
        let mut visited: HashSet<u64> = HashSet::new();
        let mut queue: VecDeque<(u64, usize)> = VecDeque::new();
        queue.push_back((target, 0));
        while let Some((addr, depth)) = queue.pop_front() {
            if visited.contains(&addr) {
                continue;
            }
            visited.insert(addr);
            if max_depth > 0 && depth >= max_depth {
                continue;
            }
            if let Some(node) = self.nodes.get(&addr) {
                for &caller in &node.callers {
                    if !visited.contains(&caller) {
                        queue.push_back((caller, depth + 1));
                    }
                }
            }
        }
        visited.remove(&target);
        let mut out: Vec<u64> = visited.into_iter().collect();
        out.sort_unstable();
        out
    }

    /// Build a callee call tree rooted at `start`.
    #[must_use]
    pub fn callee_tree(&self, start: u64, cfg: &HierarchyConfig) -> CallTree {
        self.build_tree_iterative(start, cfg, true)
    }

    /// Build a caller tree (inverse direction) rooted at `start`.
    #[must_use]
    pub fn caller_tree(&self, start: u64, cfg: &HierarchyConfig) -> CallTree {
        self.build_tree_iterative(start, cfg, false)
    }

    /// Shared implementation for [`Self::callee_tree`] / [`Self::caller_tree`].
    ///
    /// Implemented as an explicit-stack iterative post-order build rather
    /// than the natural recursive-descent formulation: with
    /// `HierarchyConfig::max_depth == 0` (unlimited) an adversarial or simply
    /// very large binary can produce a call chain deep enough that a
    /// recursive walk overflows the native stack (the same bug class fixed
    /// in `cfg_dominators.rs`'s recursion risk and the iterative rewrite of
    /// [`Self::detect_recursive`] above). The cycle guard (`path`) still
    /// bounds any single branch to at most `nodes.len()` deep even when
    /// `max_depth` is unlimited.
    fn build_tree_iterative(&self, start: u64, cfg: &HierarchyConfig, callee_dir: bool) -> CallTree {
        struct Frame {
            addr: u64,
            depth: usize,
            name: String,
            neighbors: Vec<u64>,
            next: usize,
            children: Vec<CallTree>,
        }

        // Build the frame for `addr` at `depth`, given the current DFS path
        // (for cycle detection). Returns `(frame, is_cycle)`; when
        // `is_cycle` is true the frame's `children`/`neighbors` are unused.
        let make_frame = |addr: u64, depth: usize, path: &HashSet<u64>| -> (Frame, bool) {
            let node = self.nodes.get(&addr);
            let name = node.map_or_else(|| format!("sub_{addr:08x}"), |n| n.name.clone());
            if path.contains(&addr) {
                return (
                    Frame { addr, depth, name, neighbors: Vec::new(), next: 0, children: Vec::new() },
                    true,
                );
            }
            let stop = (cfg.max_depth > 0 && depth >= cfg.max_depth)
                || (callee_dir
                    && cfg.stop_at_imports
                    && node.is_some_and(|n| n.flags.contains(NodeFlags::IMPORT)));
            let neighbors = if stop {
                Vec::new()
            } else {
                node.map_or(Vec::new(), |n| {
                    if callee_dir { n.callees.clone() } else { n.callers.clone() }
                })
            };
            (Frame { addr, depth, name, neighbors, next: 0, children: Vec::new() }, false)
        };

        let mut path: HashSet<u64> = HashSet::new();
        let (root_frame, root_is_cycle) = make_frame(start, 0, &path);
        if root_is_cycle {
            return CallTree { root: start, name: root_frame.name, children: Vec::new(), depth: 0, is_cycle: true };
        }
        path.insert(start);
        let mut stack: Vec<Frame> = vec![root_frame];

        loop {
            let top = stack.last_mut().expect("stack non-empty by loop invariant");
            if top.next < top.neighbors.len() {
                let child_addr = top.neighbors[top.next];
                top.next += 1;
                let child_depth = top.depth + 1;
                let (child_frame, child_is_cycle) = make_frame(child_addr, child_depth, &path);
                if child_is_cycle {
                    top.children.push(CallTree {
                        root: child_addr,
                        name: child_frame.name,
                        children: Vec::new(),
                        depth: child_depth,
                        is_cycle: true,
                    });
                } else {
                    path.insert(child_addr);
                    stack.push(child_frame);
                }
            } else {
                let done = stack.pop().expect("just checked via last_mut");
                path.remove(&done.addr);
                let tree = CallTree {
                    root: done.addr,
                    name: done.name,
                    children: done.children,
                    depth: done.depth,
                    is_cycle: false,
                };
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(tree);
                } else {
                    return tree;
                }
            }
        }
    }

    // ── Recursive detection ───────────────────────────────────────────────────

    /// Detect and mark all recursive functions (self-loops or back-edges in DFS).
    /// Returns addresses of recursive functions.
    ///
    /// Implemented as a single-pass iterative DFS (white/gray/black coloring)
    /// over the whole node set, i.e. O(V+E) total. An earlier version ran a
    /// fresh DFS from every node (O(V·(V+E))), which was quadratic on large,
    /// densely-connected call graphs.
    pub fn detect_recursive(&mut self) -> Vec<u64> {
        let addrs: Vec<u64> = {
            let mut v: Vec<u64> = self.nodes.keys().copied().collect();
            v.sort_unstable();
            v
        };
        let mut recursive: HashSet<u64> = HashSet::new();
        // 0 = white (unvisited), 1 = gray (on current DFS stack), 2 = black (done).
        let mut color: HashMap<u64, u8> = HashMap::with_capacity(addrs.len());

        for &start in &addrs {
            if color.get(&start).copied().unwrap_or(0) != 0 {
                continue;
            }
            let mut stack: Vec<(u64, usize)> = vec![(start, 0)];
            color.insert(start, 1);
            while let Some(&mut (addr, ref mut next_idx)) = stack.last_mut() {
                let callees = self.nodes.get(&addr).map_or(&[][..], |n| n.callees.as_slice());
                if let Some(&callee) = callees.get(*next_idx) {
                    *next_idx += 1;
                    match color.get(&callee).copied().unwrap_or(0) {
                        1 => {
                            // Back-edge to an ancestor on the current path: both
                            // ends of the edge participate in a cycle.
                            recursive.insert(callee);
                            recursive.insert(addr);
                        }
                        0 => {
                            color.insert(callee, 1);
                            stack.push((callee, 0));
                        }
                        _ => {}
                    }
                } else {
                    color.insert(addr, 2);
                    stack.pop();
                }
            }
        }

        for &a in &recursive {
            if let Some(n) = self.nodes.get_mut(&a) {
                n.flags |= NodeFlags::RECURSIVE;
            }
        }
        let mut out: Vec<u64> = recursive.into_iter().collect();
        out.sort_unstable();
        out
    }

    // ── Merge ─────────────────────────────────────────────────────────────────

    /// Merge another hierarchy into this one.
    pub fn merge(&mut self, other: Self) {
        for (addr, node) in other.nodes {
            for callee in node.callees {
                self.add_call(addr, callee);
            }
            if let Some(n) = self.nodes.get_mut(&addr) {
                n.flags |= node.flags;
                if n.name.starts_with("sub_") && !node.name.starts_with("sub_") {
                    n.name = node.name;
                }
            }
        }
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    /// Total number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Total number of directed edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Whether the hierarchy has no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Compute hierarchy statistics.
    #[must_use]
    pub fn stats(&self) -> HierarchyStats {
        let mut max_fan_in = 0usize;
        let mut max_fan_out = 0usize;
        let mut hottest_target: Option<u64> = None;
        let mut root_count = 0usize;
        let mut leaf_count = 0usize;
        let mut import_count = 0usize;
        let mut recursive_count = 0usize;

        for n in self.nodes.values() {
            if n.fan_in() > max_fan_in {
                max_fan_in = n.fan_in();
                hottest_target = Some(n.address);
            }
            max_fan_out = max_fan_out.max(n.fan_out());
            if n.is_root() {
                root_count += 1;
            }
            if n.is_leaf() {
                leaf_count += 1;
            }
            if n.flags.contains(NodeFlags::IMPORT) {
                import_count += 1;
            }
            if n.flags.contains(NodeFlags::RECURSIVE) {
                recursive_count += 1;
            }
        }

        HierarchyStats {
            total_nodes: self.nodes.len(),
            total_edges: self.edges.len(),
            root_count,
            leaf_count,
            import_count,
            recursive_count,
            max_fan_in,
            max_fan_out,
            hottest_target,
        }
    }

    /// Top N functions by fan-in (most called).
    #[must_use]
    pub fn top_by_fan_in(&self, n: usize) -> Vec<(u64, usize)> {
        let mut list: Vec<(u64, usize)> = self.nodes
            .values()
            .map(|node| (node.address, node.fan_in()))
            .collect();
        list.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        list.truncate(n);
        list
    }

    /// Top N functions by fan-out (calls the most others).
    #[must_use]
    pub fn top_by_fan_out(&self, n: usize) -> Vec<(u64, usize)> {
        let mut list: Vec<(u64, usize)> = self.nodes
            .values()
            .map(|node| (node.address, node.fan_out()))
            .collect();
        list.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        list.truncate(n);
        list
    }

    /// Iterate over all nodes.
    pub fn iter_nodes(&self) -> impl Iterator<Item = &HierarchyNode> {
        self.nodes.values()
    }

    /// Iterate over all edges.
    pub fn iter_edges(&self) -> impl Iterator<Item = CallEdge> + '_ {
        self.edges
            .iter()
            .map(|(&(from, to), &site_count)| CallEdge { from, to, site_count })
    }
}

// ── Free functions ─────────────────────────────────────────────────────────────

/// Return the direct callers of `address` from `hierarchy`.
#[must_use]
pub fn callers_of(hierarchy: &CallHierarchy, address: u64) -> Vec<u64> {
    hierarchy.callers_of(address)
}

/// Return the direct callees of `address` from `hierarchy`.
#[must_use]
pub fn callees_of(hierarchy: &CallHierarchy, address: u64) -> Vec<u64> {
    hierarchy.callees_of(address)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_hierarchy() -> CallHierarchy {
        // main → foo → bar
        //      → baz
        let mut h = CallHierarchy::new();
        h.add_call(0x1000, 0x2000); // main → foo
        h.add_call(0x1000, 0x3000); // main → baz
        h.add_call(0x2000, 0x4000); // foo  → bar
        h.set_name(0x1000, "main");
        h.set_name(0x2000, "foo");
        h.set_name(0x3000, "baz");
        h.set_name(0x4000, "bar");
        h
    }

    #[test]
    fn test_node_new() {
        let n = HierarchyNode::new(0x1000, "main");
        assert_eq!(n.address, 0x1000);
        assert_eq!(n.name, "main");
        assert!(n.is_leaf());
        assert!(n.is_root());
    }

    #[test]
    fn test_node_flags() {
        let mut n = HierarchyNode::new(0x1000, "imp");
        n.flags |= NodeFlags::IMPORT;
        assert!(n.is_import());
    }

    #[test]
    fn test_node_display() {
        let n = HierarchyNode::new(0x1000, "main");
        let s = n.to_string();
        assert!(s.contains("0x00001000"));
        assert!(s.contains("main"));
    }

    #[test]
    fn test_add_call_and_callers() {
        let h = simple_hierarchy();
        let callers = h.callers_of(0x2000); // callers of foo
        assert_eq!(callers, vec![0x1000]);
    }

    #[test]
    fn test_callees_of() {
        let h = simple_hierarchy();
        let callees = h.callees_of(0x1000); // callees of main
        assert!(callees.contains(&0x2000));
        assert!(callees.contains(&0x3000));
    }

    #[test]
    fn test_roots() {
        let h = simple_hierarchy();
        let roots = h.roots();
        assert_eq!(roots, vec![0x1000]); // only main is a root
    }

    #[test]
    fn test_leaves() {
        let h = simple_hierarchy();
        let leaves = h.leaves();
        assert!(leaves.contains(&0x3000)); // baz has no callees
        assert!(leaves.contains(&0x4000)); // bar has no callees
    }

    #[test]
    fn test_reachable_callees() {
        let h = simple_hierarchy();
        let r = h.reachable_callees(0x1000, 10);
        assert!(r.contains(&0x2000));
        assert!(r.contains(&0x3000));
        assert!(r.contains(&0x4000));
    }

    #[test]
    fn test_transitive_callers() {
        let h = simple_hierarchy();
        let tc = h.transitive_callers(0x4000, 10); // who transitively calls bar?
        assert!(tc.contains(&0x2000)); // foo calls bar
        assert!(tc.contains(&0x1000)); // main calls foo
    }

    #[test]
    fn test_callee_tree() {
        let h = simple_hierarchy();
        let cfg = HierarchyConfig::default();
        let tree = h.callee_tree(0x1000, &cfg);
        assert_eq!(tree.root, 0x1000);
        assert_eq!(tree.children.len(), 2);
    }

    #[test]
    fn test_caller_tree() {
        let h = simple_hierarchy();
        let cfg = HierarchyConfig::default();
        let tree = h.caller_tree(0x4000, &cfg); // who calls bar?
        assert_eq!(tree.root, 0x4000);
        assert_eq!(tree.children.len(), 1); // foo
    }

    #[test]
    fn test_callee_tree_depth_limit() {
        let h = simple_hierarchy();
        let cfg = HierarchyConfig::default().with_max_depth(1);
        let tree = h.callee_tree(0x1000, &cfg);
        // depth 1: main's direct callees (foo, baz) — foo's children not expanded
        for child in &tree.children {
            assert!(child.children.is_empty());
        }
    }

    #[test]
    fn test_callee_tree_node_count() {
        let h = simple_hierarchy();
        let cfg = HierarchyConfig::default();
        let tree = h.callee_tree(0x1000, &cfg);
        assert_eq!(tree.node_count(), 4); // main, foo, baz, bar
    }

    #[test]
    fn test_call_tree_format() {
        let h = simple_hierarchy();
        let cfg = HierarchyConfig::default();
        let tree = h.callee_tree(0x1000, &cfg);
        let s = tree.format_tree();
        assert!(s.contains("main"));
        assert!(s.contains("foo"));
    }

    #[test]
    fn test_detect_recursive() {
        let mut h = CallHierarchy::new();
        h.add_call(0x1000, 0x2000);
        h.add_call(0x2000, 0x1000); // back-edge
        let rec = h.detect_recursive();
        assert!(rec.contains(&0x1000) || rec.contains(&0x2000));
    }

    #[test]
    fn test_detect_self_recursive() {
        let mut h = CallHierarchy::new();
        h.add_call(0x1000, 0x1000); // self-call
        let rec = h.detect_recursive();
        assert!(rec.contains(&0x1000));
    }

    #[test]
    fn test_merge() {
        let mut a = simple_hierarchy();
        let mut b = CallHierarchy::new();
        b.add_call(0x5000, 0x6000);
        a.merge(b);
        assert!(a.node(0x5000).is_some());
        assert!(a.node(0x6000).is_some());
    }

    #[test]
    fn test_stats() {
        let h = simple_hierarchy();
        let s = h.stats();
        assert_eq!(s.total_nodes, 4);
        assert_eq!(s.total_edges, 3);
        assert!(s.root_count >= 1);
        assert!(s.leaf_count >= 1);
    }

    #[test]
    fn test_top_by_fan_in() {
        let h = simple_hierarchy();
        let top = h.top_by_fan_in(3);
        // Only functions with at least 1 caller
        assert!(!top.is_empty());
    }

    #[test]
    fn test_top_by_fan_out() {
        let h = simple_hierarchy();
        let top = h.top_by_fan_out(3);
        assert_eq!(top[0].0, 0x1000); // main calls 2
    }

    #[test]
    fn test_remove_call() {
        let mut h = CallHierarchy::new();
        h.add_call(0x1000, 0x2000);
        let existed = h.remove_call(0x1000, 0x2000);
        assert!(existed);
        assert!(h.callees_of(0x1000).is_empty());
    }

    #[test]
    fn test_free_callers_of() {
        let h = simple_hierarchy();
        let c = callers_of(&h, 0x2000);
        assert_eq!(c, vec![0x1000]);
    }

    #[test]
    fn test_free_callees_of() {
        let h = simple_hierarchy();
        let c = callees_of(&h, 0x1000);
        assert!(c.contains(&0x2000));
    }

    #[test]
    fn test_hierarchy_is_empty() {
        let h = CallHierarchy::new();
        assert!(h.is_empty());
    }

    #[test]
    fn test_mark_import() {
        let mut h = CallHierarchy::new();
        h.add_node(0x9000, "LoadLibraryA");
        h.mark_import(0x9000);
        assert!(h.node(0x9000).expect("node").is_import());
    }

    #[test]
    fn test_stats_format_report() {
        let h = simple_hierarchy();
        let report = h.stats().format_report();
        assert!(report.contains("Nodes"));
        assert!(report.contains("Edges"));
    }

    #[test]
    fn test_collect_addresses() {
        let h = simple_hierarchy();
        let cfg = HierarchyConfig::default();
        let tree = h.callee_tree(0x1000, &cfg);
        let mut addrs = HashSet::new();
        tree.collect_addresses(&mut addrs);
        assert!(addrs.contains(&0x1000));
        assert!(addrs.contains(&0x4000));
    }

    #[test]
    fn test_reachable_depth_zero_means_unlimited() {
        let h = simple_hierarchy();
        let r = h.reachable_callees(0x1000, 0);
        // max_depth=0 means unlimited — should still reach bar
        assert!(r.contains(&0x4000));
    }

    /// Regression: `callee_tree`/`caller_tree` used to be built with plain
    /// recursion, one native stack frame per level. With
    /// `HierarchyConfig::max_depth == 0` (unlimited) a very long acyclic
    /// call chain — the kind an adversarial or just large real-world binary
    /// can produce — would blow the stack. The iterative rewrite must
    /// handle chains far deeper than any plausible default stack allows
    /// without crashing, and must still visit every node.
    #[test]
    fn test_callee_tree_deep_chain_no_stack_overflow() {
        let mut h = CallHierarchy::new();
        const DEPTH: u64 = 50_000;
        for i in 0..DEPTH {
            h.add_call(i, i + 1);
        }
        let cfg = HierarchyConfig::default().with_max_depth(0); // unlimited
        let tree = h.callee_tree(0, &cfg);
        assert_eq!(tree.node_count(), (DEPTH + 1) as usize);
        assert_eq!(tree.max_depth(), DEPTH as usize);
    }

    #[test]
    fn test_caller_tree_deep_chain_no_stack_overflow() {
        let mut h = CallHierarchy::new();
        const DEPTH: u64 = 50_000;
        for i in 0..DEPTH {
            h.add_call(i, i + 1);
        }
        let cfg = HierarchyConfig::default().with_max_depth(0); // unlimited
        let tree = h.caller_tree(DEPTH, &cfg);
        assert_eq!(tree.node_count(), (DEPTH + 1) as usize);
    }

    /// `callee_tree`/`caller_tree` on an address absent from the hierarchy
    /// must not panic — it should produce a single synthetic `sub_...` leaf,
    /// same as the direct-indexing-vs-`.get()` bounds-check pattern audited
    /// elsewhere in this crate.
    #[test]
    fn test_tree_on_unknown_address_does_not_panic() {
        let h = CallHierarchy::new();
        let cfg = HierarchyConfig::default();
        let tree = h.callee_tree(0xDEAD_BEEF, &cfg);
        assert_eq!(tree.root, 0xDEAD_BEEF);
        assert!(tree.children.is_empty());
        assert!(!tree.is_cycle);

        let tree2 = h.caller_tree(0xDEAD_BEEF, &cfg);
        assert_eq!(tree2.root, 0xDEAD_BEEF);
    }

    /// A node that calls itself must be reported as a one-level cycle, not
    /// recurse indefinitely.
    #[test]
    fn test_callee_tree_self_loop_is_cycle_child() {
        let mut h = CallHierarchy::new();
        h.add_call(0x1000, 0x1000);
        let cfg = HierarchyConfig::default();
        let tree = h.callee_tree(0x1000, &cfg);
        assert_eq!(tree.children.len(), 1);
        assert!(tree.children[0].is_cycle);
    }

    #[test]
    fn test_format_tree_deep_chain_no_stack_overflow() {
        let mut h = CallHierarchy::new();
        const DEPTH: u64 = 20_000;
        for i in 0..DEPTH {
            h.add_call(i, i + 1);
        }
        let cfg = HierarchyConfig::default().with_max_depth(0);
        let tree = h.callee_tree(0, &cfg);
        let s = tree.format_tree();
        assert!(s.lines().count() as u64 >= DEPTH);
    }
}
