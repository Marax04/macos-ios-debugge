//! Lua upvalue reference tracking: resolves upvalue chains across nested
//! closures and builds a closure-dependency graph.
//!
//! # Relationship to `lua_vm_semantics::UpvalueClosing`
//!
//! [`crate::lua_vm_semantics::UpvalueClosing`] models the *runtime* lifecycle of
//! upvalues during VM execution: open upvalues that point at stack slots, and the
//! closing event that copies a value to the heap when a scope exits.
//!
//! This module operates at the *static-analysis* level: given the upvalue
//! descriptor tables from a compiled Lua `Proto`, it resolves the origin of each
//! upvalue (which enclosing register or parent upvalue index it was captured from),
//! and builds a graph of closure dependencies.  No runtime stack is involved.

use std::collections::{HashMap, VecDeque};
use std::fmt;

// ─── UpvalueRef ───────────────────────────────────────────────────────────────

/// The origin of a single upvalue in a Lua closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpvalueOrigin {
    /// Captured directly from the enclosing function's register `reg`.
    Register(u32),
    /// Inherited from upvalue `index` of the immediately enclosing function.
    Upvalue(usize),
    /// The global environment table `_ENV` (Lua 5.2+).
    Env,
}

impl fmt::Display for UpvalueOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register(r) => write!(f, "reg({r})"),
            Self::Upvalue(i) => write!(f, "upval({i})"),
            Self::Env => write!(f, "_ENV"),
        }
    }
}

/// A resolved upvalue reference within a single closure.
#[derive(Debug, Clone)]
pub struct UpvalueRef {
    /// Index of this upvalue within its owning closure.
    pub index: usize,
    /// Name from the debug information, if available.
    pub name: Option<String>,
    /// How this upvalue is sourced.
    pub origin: UpvalueOrigin,
    /// Closure ID that owns this upvalue.
    pub owner_id: u32,
    /// Whether this upvalue is "on-stack" (open) at some observed point.
    pub is_open: bool,
}

impl UpvalueRef {
    /// Create a new `UpvalueRef`.
    #[must_use] 
    pub const fn new(index: usize, origin: UpvalueOrigin, owner_id: u32) -> Self {
        Self {
            index,
            name: None,
            origin,
            owner_id,
            is_open: true,
        }
    }

    /// Attach a name from debug information.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Mark this upvalue as closed (moved to heap).
    pub const fn close(&mut self) {
        self.is_open = false;
    }
}

impl fmt::Display for UpvalueRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name.as_deref().unwrap_or("?");
        let state = if self.is_open { "open" } else { "closed" };
        write!(
            f,
            "[{}] {} <- {} ({state})",
            self.index, name, self.origin
        )
    }
}

// ─── ClosureInfo ─────────────────────────────────────────────────────────────

/// Information about a single Lua closure (function prototype).
#[derive(Debug, Clone)]
pub struct ClosureInfo {
    /// Unique identifier assigned during registration.
    pub id: u32,
    /// Unique identifier of the parent closure (0 = top-level / chunk).
    pub parent_id: u32,
    /// Optional human-readable name (function name from debug info).
    pub name: Option<String>,
    /// Upvalues declared in this closure.
    pub upvalues: Vec<UpvalueRef>,
    /// Instruction count (number of 4-byte words in the code vector).
    pub instruction_count: usize,
    /// Source line where this closure starts (0 = unknown).
    pub source_line: u32,
}

impl ClosureInfo {
    /// Create an empty `ClosureInfo`.
    #[must_use] 
    pub const fn new(id: u32, parent_id: u32) -> Self {
        Self {
            id,
            parent_id,
            name: None,
            upvalues: Vec::new(),
            instruction_count: 0,
            source_line: 0,
        }
    }

    /// Attach a name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Return the upvalue at `index`, or `None` if out of range.
    #[must_use] 
    pub fn upvalue_at(&self, index: usize) -> Option<&UpvalueRef> {
        self.upvalues.get(index)
    }

    /// Add an upvalue to this closure.
    pub fn push_upvalue(&mut self, uv: UpvalueRef) {
        self.upvalues.push(uv);
    }

    /// Return `true` if this closure captures at least one register from its
    /// parent (i.e. has at least one `UpvalueOrigin::Register` upvalue).
    #[must_use] 
    pub fn captures_registers(&self) -> bool {
        self.upvalues
            .iter()
            .any(|u| matches!(u.origin, UpvalueOrigin::Register(_)))
    }
}

impl fmt::Display for ClosureInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name.as_deref().unwrap_or("<anonymous>");
        write!(
            f,
            "Closure[{}] {name} (parent={}, upvals={})",
            self.id,
            self.parent_id,
            self.upvalues.len()
        )
    }
}

// ─── ClosureGraph ─────────────────────────────────────────────────────────────

/// A directed graph of Lua closures linked by upvalue dependencies.
///
/// Nodes are [`ClosureInfo`] entries; edges represent "closure A captures an
/// upvalue from closure B" relationships.
#[derive(Debug, Default)]
pub struct ClosureGraph {
    nodes: HashMap<u32, ClosureInfo>,
    /// `child_id` -> `parent_id`
    parent_map: HashMap<u32, u32>,
    /// `parent_id` -> Vec<`child_id`>
    children_map: HashMap<u32, Vec<u32>>,
    next_id: u32,
}

impl ClosureGraph {
    /// Create an empty graph.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a new closure ID and register the closure.
    pub fn add_closure(&mut self, parent_id: u32) -> u32 {
        self.next_id += 1;
        let id = self.next_id;
        let info = ClosureInfo::new(id, parent_id);
        self.nodes.insert(id, info);
        self.parent_map.insert(id, parent_id);
        self.children_map.entry(parent_id).or_default().push(id);
        id
    }

    /// Return a reference to the closure with `id`, or `None`.
    #[must_use] 
    pub fn closure(&self, id: u32) -> Option<&ClosureInfo> {
        self.nodes.get(&id)
    }

    /// Return a mutable reference to the closure with `id`, or `None`.
    pub fn closure_mut(&mut self, id: u32) -> Option<&mut ClosureInfo> {
        self.nodes.get_mut(&id)
    }

    /// Return all closures in insertion order.
    #[must_use] 
    pub fn all_closures(&self) -> Vec<&ClosureInfo> {
        let mut v: Vec<&ClosureInfo> = self.nodes.values().collect();
        v.sort_by_key(|c| c.id);
        v
    }

    /// Return the direct children of `parent_id`.
    #[must_use] 
    pub fn children(&self, parent_id: u32) -> Vec<u32> {
        self.children_map
            .get(&parent_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Return the chain of ancestor IDs from `id` up to (but not including)
    /// the root, in bottom-up order.
    #[must_use] 
    pub fn ancestor_chain(&self, id: u32) -> Vec<u32> {
        let mut chain = Vec::new();
        let mut current = id;
        for _ in 0..512 {
            match self.parent_map.get(&current) {
                Some(&p) if p != 0 && p != current => {
                    chain.push(p);
                    current = p;
                }
                _ => break,
            }
        }
        chain
    }

    /// BFS traversal starting at `root_id`; returns IDs in BFS order.
    #[must_use] 
    pub fn bfs_from(&self, root_id: u32) -> Vec<u32> {
        let mut visited: Vec<u32> = Vec::new();
        let mut queue: VecDeque<u32> = VecDeque::new();
        queue.push_back(root_id);
        while let Some(id) = queue.pop_front() {
            if visited.contains(&id) {
                continue;
            }
            visited.push(id);
            for &child in self.children_map.get(&id).iter().flat_map(|v| v.iter()) {
                queue.push_back(child);
            }
        }
        visited
    }

    /// Return the total number of registered closures.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Return `true` if no closures have been registered.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

// ─── UpvalueTracker ───────────────────────────────────────────────────────────

/// Tracks upvalue references across a hierarchy of Lua closures.
///
/// Use [`UpvalueTracker::register_closure`] to add a prototype, then call
/// [`UpvalueTracker::add_upvalue`] for each upvalue declared in that prototype.
/// After all closures are registered, call [`UpvalueTracker::resolve`] to
/// resolve the full inheritance chain.
#[derive(Debug)]
pub struct UpvalueTracker {
    graph: ClosureGraph,
    /// Root closure ID (the top-level chunk function).
    root_id: u32,
}

impl UpvalueTracker {
    /// Create a new tracker.  The root closure (chunk-level function) is
    /// created automatically with ID 1.
    #[must_use] 
    pub fn new() -> Self {
        let mut graph = ClosureGraph::new();
        let root_id = graph.add_closure(0 /* no parent */);
        Self { graph, root_id }
    }

    /// Return the ID of the root closure.
    #[must_use] 
    pub const fn root_id(&self) -> u32 {
        self.root_id
    }

    /// Register a child closure nested inside `parent_id`.  Returns the new
    /// closure's ID.
    pub fn register_closure(&mut self, parent_id: u32) -> u32 {
        self.graph.add_closure(parent_id)
    }

    /// Add an upvalue to closure `owner_id`.
    pub fn add_upvalue(
        &mut self,
        owner_id: u32,
        index: usize,
        origin: UpvalueOrigin,
        name: Option<&str>,
    ) {
        let mut uv = UpvalueRef::new(index, origin, owner_id);
        if let Some(n) = name {
            uv = uv.with_name(n);
        }
        if let Some(closure) = self.graph.closure_mut(owner_id) {
            closure.push_upvalue(uv);
        }
    }

    /// Return the upvalue at `index` for closure `id`.
    #[must_use] 
    pub fn upvalue_at_index(&self, id: u32, index: usize) -> Option<&UpvalueRef> {
        self.graph.closure(id)?.upvalue_at(index)
    }

    /// Resolve the ultimate origin of upvalue `index` in closure `id`.
    ///
    /// When the immediate origin is `UpvalueOrigin::Upvalue(n)`, this function
    /// walks up the parent chain to find the original `Register` or `Env`
    /// source.  Returns `None` if resolution fails (e.g. dangling reference).
    #[must_use] 
    pub fn resolve_origin(&self, id: u32, index: usize) -> Option<UpvalueOrigin> {
        let mut current_id = id;
        let mut current_index = index;

        for _ in 0..64 {
            let closure = self.graph.closure(current_id)?;
            let uv = closure.upvalue_at(current_index)?;
            match &uv.origin {
                UpvalueOrigin::Register(_) | UpvalueOrigin::Env => {
                    return Some(uv.origin.clone());
                }
                UpvalueOrigin::Upvalue(parent_uv_index) => {
                    let parent_id = self.graph.parent_map.get(&current_id).copied()?;
                    current_index = *parent_uv_index;
                    current_id = parent_id;
                }
            }
        }
        None // cycle or too deep
    }

    /// Resolve all inherited upvalues and return a flat list of
    /// `(closure_id, upvalue_index, resolved_origin)`.
    #[must_use] 
    pub fn resolve_all(&self) -> Vec<(u32, usize, UpvalueOrigin)> {
        let mut result = Vec::new();
        for closure in self.graph.all_closures() {
            for uv in &closure.upvalues {
                if let UpvalueOrigin::Upvalue(_) = &uv.origin
                    && let Some(resolved) = self.resolve_origin(closure.id, uv.index) {
                        result.push((closure.id, uv.index, resolved));
                        continue;
                    }
                result.push((closure.id, uv.index, uv.origin.clone()));
            }
        }
        result
    }

    /// Build a summary mapping `(closure_id, upvalue_index) -> resolved origin`.
    #[must_use] 
    pub fn build_resolution_map(&self) -> HashMap<(u32, usize), UpvalueOrigin> {
        self.resolve_all()
            .into_iter()
            .map(|(id, idx, origin)| ((id, idx), origin))
            .collect()
    }

    /// Return all upvalues for closure `id` that ultimately originate from
    /// register `reg` in some ancestor.
    #[must_use] 
    pub fn upvalues_from_register(&self, id: u32, reg: u32) -> Vec<usize> {
        let mut result = Vec::new();
        if let Some(closure) = self.graph.closure(id) {
            for uv in &closure.upvalues {
                if let Some(UpvalueOrigin::Register(r)) =
                    self.resolve_origin(id, uv.index)
                    && r == reg {
                        result.push(uv.index);
                    }
            }
        }
        result
    }

    /// Detect closures that capture variables from closures other than their
    /// immediate parent (i.e. skip-level captures due to inheritance chains).
    #[must_use] 
    pub fn find_skip_level_captures(&self) -> Vec<(u32, usize)> {
        let mut found = Vec::new();
        for closure in self.graph.all_closures() {
            for uv in &closure.upvalues {
                if let UpvalueOrigin::Upvalue(parent_idx) = uv.origin {
                    // Walk the parent to see if its upvalue also inherited.
                    if let Some(parent_id) = self.graph.parent_map.get(&closure.id).copied()
                        && let Some(parent_closure) = self.graph.closure(parent_id)
                            && let Some(parent_uv) = parent_closure.upvalue_at(parent_idx)
                                && matches!(parent_uv.origin, UpvalueOrigin::Upvalue(_)) {
                                    found.push((closure.id, uv.index));
                                }
                }
            }
        }
        found
    }

    /// Return the underlying closure graph.
    #[must_use] 
    pub const fn graph(&self) -> &ClosureGraph {
        &self.graph
    }

    /// Mark all open upvalues in closure `id` as closed (CLOSE instruction
    /// was seen at the given register threshold `min_reg`).
    pub fn close_upvalues(&mut self, id: u32, min_reg: u32) {
        if let Some(closure) = self.graph.closure_mut(id) {
            for uv in &mut closure.upvalues {
                if let UpvalueOrigin::Register(r) = uv.origin
                    && r >= min_reg {
                        uv.close();
                    }
            }
        }
    }

    /// Return the number of open upvalues in closure `id`.
    #[must_use] 
    pub fn open_upvalue_count(&self, id: u32) -> usize {
        self.graph
            .closure(id)
            .map_or(0, |c| c.upvalues.iter().filter(|u| u.is_open).count())
    }
}

impl Default for UpvalueTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─── upvalue_at_index free function ───────────────────────────────────────────

/// Look up the upvalue at `index` for closure `id` in `tracker`.
///
/// This is a convenience free function that mirrors the OO method for use
/// in contexts where a method call is inconvenient.
#[must_use] 
pub fn upvalue_at_index(
    tracker: &UpvalueTracker,
    closure_id: u32,
    index: usize,
) -> Option<&UpvalueRef> {
    tracker.upvalue_at_index(closure_id, index)
}

// ─── UpvalueReport ────────────────────────────────────────────────────────────

/// A human-readable summary of all upvalue relationships in a `UpvalueTracker`.
pub struct UpvalueReport {
    lines: Vec<String>,
}

impl UpvalueReport {
    /// Build a report from a tracker.
    #[must_use] 
    pub fn build(tracker: &UpvalueTracker) -> Self {
        let mut lines = Vec::new();
        let resolution = tracker.build_resolution_map();

        for closure in tracker.graph().all_closures() {
            let name = closure.name.as_deref().unwrap_or("<anon>");
            lines.push(format!(
                "Closure[{}] {} (parent={}, upvals={}):",
                closure.id, name, closure.parent_id, closure.upvalues.len()
            ));
            for uv in &closure.upvalues {
                let resolved = resolution
                    .get(&(closure.id, uv.index)).map_or_else(|| "?".to_owned(), std::string::ToString::to_string);
                let uv_name = uv.name.as_deref().unwrap_or("?");
                let state = if uv.is_open { "open" } else { "closed" };
                lines.push(format!(
                    "  [{:3}] {uv_name:<20} immediate={} resolved={resolved} ({state})",
                    uv.index, uv.origin
                ));
            }
        }
        Self { lines }
    }

    /// Return all lines of the report.
    #[must_use] 
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// Format the report as a single string with newlines.
    #[must_use] 
    pub fn to_string_report(&self) -> String {
        self.lines.join("\n")
    }
}

impl fmt::Display for UpvalueReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for line in &self.lines {
            writeln!(f, "{line}")?;
        }
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_created_on_new() {
        let t = UpvalueTracker::new();
        assert_eq!(t.root_id(), 1);
        assert!(t.graph().closure(1).is_some());
    }

    #[test]
    fn test_register_child_closure() {
        let mut t = UpvalueTracker::new();
        let child = t.register_closure(t.root_id());
        assert_eq!(child, 2);
        assert_eq!(t.graph().children(t.root_id()), vec![child]);
    }

    #[test]
    fn test_add_and_retrieve_upvalue() {
        let mut t = UpvalueTracker::new();
        t.add_upvalue(1, 0, UpvalueOrigin::Env, Some("_ENV"));
        let uv = t.upvalue_at_index(1, 0).unwrap();
        assert!(matches!(uv.origin, UpvalueOrigin::Env));
        assert_eq!(uv.name.as_deref(), Some("_ENV"));
    }

    #[test]
    fn test_resolve_register_origin() {
        let mut t = UpvalueTracker::new();
        // root captures reg(5)
        t.add_upvalue(1, 0, UpvalueOrigin::Register(5), Some("x"));
        // child inherits upvalue(0) from root
        let child = t.register_closure(1);
        t.add_upvalue(child, 0, UpvalueOrigin::Upvalue(0), Some("x"));
        let resolved = t.resolve_origin(child, 0).unwrap();
        assert!(matches!(resolved, UpvalueOrigin::Register(5)));
    }

    #[test]
    fn test_resolve_all_produces_entries() {
        let mut t = UpvalueTracker::new();
        t.add_upvalue(1, 0, UpvalueOrigin::Register(2), None);
        let entries = t.resolve_all();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_close_upvalues() {
        let mut t = UpvalueTracker::new();
        t.add_upvalue(1, 0, UpvalueOrigin::Register(3), Some("y"));
        t.add_upvalue(1, 1, UpvalueOrigin::Register(1), Some("z"));
        t.close_upvalues(1, 2); // close regs >= 2
        let uv0 = t.upvalue_at_index(1, 0).unwrap();
        let uv1 = t.upvalue_at_index(1, 1).unwrap();
        assert!(!uv0.is_open); // reg 3 >= 2 → closed
        assert!(uv1.is_open);  // reg 1 < 2  → still open
    }

    #[test]
    fn test_bfs_traversal() {
        let mut t = UpvalueTracker::new();
        let c1 = t.register_closure(1);
        let _c2 = t.register_closure(c1);
        let order = t.graph().bfs_from(1);
        assert_eq!(order[0], 1);
        assert!(order.contains(&c1));
    }

    #[test]
    fn test_upvalue_report_not_empty() {
        let mut t = UpvalueTracker::new();
        t.add_upvalue(1, 0, UpvalueOrigin::Env, Some("_ENV"));
        let report = UpvalueReport::build(&t);
        assert!(!report.lines().is_empty());
    }
}
