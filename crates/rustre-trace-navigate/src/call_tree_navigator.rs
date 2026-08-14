//! Navigate trace call tree: expand/collapse call frames, jump to
//! caller/callee, find all calls to a function, compute call depths,
//! detect recursive calls, visualize call tree as text.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::{Address, ExecutionTrace, EntryKind, NavError};

// ── CallFrame ─────────────────────────────────────────────────────────────────

/// A single frame in the call tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallFrame {
    /// Unique frame ID (assigned during tree build).
    pub id: u32,
    /// Parent frame ID (`u32::MAX` = root).
    pub parent_id: u32,
    /// Function entry address.
    pub fn_addr: Address,
    /// Return address (where this frame will return to).
    pub ret_addr: Address,
    /// Trace index of the CALL instruction.
    pub call_idx: usize,
    /// Trace index of the matching RET instruction (`u32::MAX` = unmatched).
    pub ret_idx: usize,
    /// Depth in the call tree (0 = outermost frame).
    pub depth: u32,
    /// Optional resolved symbol name.
    pub name: Option<String>,
    /// Whether this frame is currently expanded in the UI.
    pub expanded: bool,
    /// Children frame IDs.
    pub children: Vec<u32>,
}

impl CallFrame {
    /// Create a new frame.
    #[must_use]
    pub const fn new(id: u32, parent_id: u32, fn_addr: Address, ret_addr: Address, call_idx: usize, depth: u32) -> Self {
        Self {
            id,
            parent_id,
            fn_addr,
            ret_addr,
            call_idx,
            ret_idx: usize::MAX,
            depth,
            name: None,
            expanded: true,
            children: Vec::new(),
        }
    }

    /// Display name: symbol or hex address.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| format!("0x{:x}", self.fn_addr))
    }

    /// Returns `true` if this frame has a matched return.
    #[must_use]
    pub const fn has_return(&self) -> bool {
        self.ret_idx != usize::MAX
    }

    /// Returns `true` if this frame has children.
    #[must_use]
    pub const fn has_children(&self) -> bool {
        !self.children.is_empty()
    }
}

// ── CallTree ──────────────────────────────────────────────────────────────────

/// The complete call tree built from a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallTree {
    /// All frames, indexed by ID.
    pub frames: Vec<CallFrame>,
    /// Root frame IDs (depth = 0 frames).
    pub roots: Vec<u32>,
    /// Index: `trace_idx` -> `frame_id` for all CALL entries.
    call_idx_to_frame: HashMap<usize, u32>,
    /// Index: `fn_addr` -> list of frame IDs.
    fn_addr_to_frames: HashMap<Address, Vec<u32>>,
}

impl CallTree {
    /// Build the call tree from an execution trace.
    #[must_use]
    pub fn build(trace: &ExecutionTrace) -> Self {
        let mut frames: Vec<CallFrame> = Vec::new();
        let mut stack: Vec<u32> = Vec::new();
        let mut call_idx_to_frame: HashMap<usize, u32> = HashMap::new();
        let mut fn_addr_to_frames: HashMap<Address, Vec<u32>> = HashMap::new();
        let mut roots: Vec<u32> = Vec::new();
        let mut next_id = 0u32;

        for entry in &trace.entries {
            match entry.kind {
                EntryKind::Call { target, ret_addr } => {
                    let parent_id = stack.last().copied().unwrap_or(u32::MAX);
                    let depth = u32::try_from(stack.len()).unwrap_or(u32::MAX);
                    let id = next_id;
                    next_id += 1;

                    let mut frame = CallFrame::new(id, parent_id, target, ret_addr, entry.idx, depth);
                    frame.name = None; // Resolved separately via symbols.

                    // Link to parent.
                    if parent_id == u32::MAX {
                        roots.push(id);
                    } else if let Some(parent) = frames.get_mut(parent_id as usize) {
                        parent.children.push(id);
                    }

                    call_idx_to_frame.insert(entry.idx, id);
                    fn_addr_to_frames.entry(target).or_default().push(id);
                    frames.push(frame);
                    stack.push(id);
                }
                EntryKind::Ret { .. } => {
                    if let Some(frame_id) = stack.pop()
                        && let Some(frame) = frames.get_mut(frame_id as usize) {
                            frame.ret_idx = entry.idx;
                        }
                }
                _ => {}
            }
        }

        Self { frames, roots, call_idx_to_frame, fn_addr_to_frames }
    }

    /// Apply a symbol table to all frames.
    pub fn apply_symbols(&mut self, symbols: &HashMap<Address, String>) {
        for frame in &mut self.frames {
            if let Some(name) = symbols.get(&frame.fn_addr) {
                frame.name = Some(name.clone());
            }
        }
    }

    /// Get a frame by ID.
    #[must_use]
    pub fn get(&self, id: u32) -> Option<&CallFrame> {
        self.frames.get(id as usize)
    }

    /// Get a mutable frame by ID.
    pub fn get_mut(&mut self, id: u32) -> Option<&mut CallFrame> {
        self.frames.get_mut(id as usize)
    }

    /// Number of frames in the tree.
    #[must_use]
    pub const fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// Maximum call depth across all frames.
    #[must_use]
    pub fn max_depth(&self) -> u32 {
        self.frames.iter().map(|f| f.depth).max().unwrap_or(0)
    }

    /// All frames at a given depth.
    #[must_use]
    pub fn frames_at_depth(&self, depth: u32) -> Vec<&CallFrame> {
        self.frames.iter().filter(|f| f.depth == depth).collect()
    }

    /// All frames for a given function address.
    #[must_use]
    pub fn frames_for_fn(&self, fn_addr: Address) -> Vec<&CallFrame> {
        self.fn_addr_to_frames.get(&fn_addr)
            .map(|ids| ids.iter().filter_map(|&id| self.get(id)).collect())
            .unwrap_or_default()
    }

    /// Find all calls to a function, returning (`frame_id`, `call_trace_idx`) pairs.
    #[must_use]
    pub fn find_calls_to(&self, fn_addr: Address) -> Vec<(u32, usize)> {
        self.fn_addr_to_frames.get(&fn_addr)
            .map(|ids| ids.iter().filter_map(|&id| {
                let frame = self.get(id)?;
                Some((id, frame.call_idx))
            }).collect())
            .unwrap_or_default()
    }

    /// The parent frame of `frame_id`, if any.
    #[must_use]
    pub fn parent_of(&self, frame_id: u32) -> Option<&CallFrame> {
        let frame = self.get(frame_id)?;
        if frame.parent_id == u32::MAX { None } else { self.get(frame.parent_id) }
    }

    /// All ancestors of `frame_id` (root first).
    #[must_use]
    pub fn ancestors_of(&self, frame_id: u32) -> Vec<&CallFrame> {
        let mut result = Vec::new();
        let mut cur_id = frame_id;
        while let Some(frame) = self.get(cur_id) {
            if frame.parent_id == u32::MAX {
                break;
            }
            if let Some(parent) = self.get(frame.parent_id) {
                result.push(parent);
                cur_id = parent.id;
            } else {
                break;
            }
        }
        result.reverse();
        result
    }

    /// Children frames of `frame_id`.
    #[must_use]
    pub fn children_of(&self, frame_id: u32) -> Vec<&CallFrame> {
        let Some(frame) = self.get(frame_id) else { return Vec::new() };
        frame.children.iter().filter_map(|&id| self.get(id)).collect()
    }

    /// Detect recursive calls: frames where `fn_addr` appears in the ancestor chain.
    #[must_use]
    pub fn detect_recursion(&self) -> Vec<RecursionInfo> {
        let mut result = Vec::new();
        for frame in &self.frames {
            let ancestors = self.ancestors_of(frame.id);
            if ancestors.iter().map(|a| a.fn_addr).any(|x| x == frame.fn_addr) {
                let depth = ancestors.iter().filter(|a| a.fn_addr == frame.fn_addr).count();
                result.push(RecursionInfo {
                    fn_addr: frame.fn_addr,
                    name: frame.name.clone(),
                    frame_id: frame.id,
                    recursion_depth: u32::try_from(depth).unwrap_or(u32::MAX),
                });
            }
        }
        result
    }

    /// Expand all frames.
    pub fn expand_all(&mut self) {
        for f in &mut self.frames { f.expanded = true; }
    }

    /// Collapse all frames.
    pub fn collapse_all(&mut self) {
        for f in &mut self.frames { f.expanded = false; }
    }

    /// Toggle the expanded state of a frame.
    ///
    /// # Errors
    /// Returns `NavError::OutOfBounds` if the frame ID is invalid.
    pub fn toggle_expand(&mut self, frame_id: u32) -> Result<bool, NavError> {
        let max = self.frames.len().saturating_sub(1);
        let frame = self.frames.get_mut(frame_id as usize)
            .ok_or(NavError::OutOfBounds { idx: frame_id as usize, max })?;
        frame.expanded = !frame.expanded;
        Ok(frame.expanded)
    }
}

// ── RecursionInfo ─────────────────────────────────────────────────────────────

/// Information about a detected recursive call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursionInfo {
    /// The function that calls itself.
    pub fn_addr: Address,
    /// Resolved name (if any).
    pub name: Option<String>,
    /// Frame ID of the recursive call.
    pub frame_id: u32,
    /// How many levels deep the recursion goes at this frame.
    pub recursion_depth: u32,
}

impl RecursionInfo {
    /// Display label.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| format!("0x{:x}", self.fn_addr))
    }
}

// ── CallTreeQuery ─────────────────────────────────────────────────────────────

/// Query parameters for searching the call tree.
#[derive(Debug, Clone, Default)]
pub struct CallTreeQuery {
    /// Filter by function address.
    pub fn_addr: Option<Address>,
    /// Filter by name substring.
    pub name_contains: Option<String>,
    /// Filter by minimum depth.
    pub min_depth: Option<u32>,
    /// Filter by maximum depth.
    pub max_depth: Option<u32>,
    /// Only return frames with at least one child.
    pub has_children: Option<bool>,
    /// Only return frames that have a matched return.
    pub has_return: Option<bool>,
    /// Maximum results.
    pub limit: Option<usize>,
}

impl CallTreeQuery {
    /// Create an empty query.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Filter by function address.
    #[must_use]
    pub const fn fn_addr(mut self, addr: Address) -> Self { self.fn_addr = Some(addr); self }

    /// Filter by name substring.
    #[must_use]
    pub fn name(mut self, s: impl Into<String>) -> Self { self.name_contains = Some(s.into()); self }

    /// Filter by depth range.
    #[must_use]
    pub const fn depth_range(mut self, min: u32, max: u32) -> Self {
        self.min_depth = Some(min);
        self.max_depth = Some(max);
        self
    }

    /// Test whether `frame` matches.
    #[must_use]
    pub fn matches(&self, frame: &CallFrame) -> bool {
        if let Some(addr) = self.fn_addr
            && frame.fn_addr != addr { return false; }
        if let Some(ref sub) = self.name_contains {
            let name = frame.display_name();
            if !name.contains(sub.as_str()) { return false; }
        }
        if let Some(min) = self.min_depth
            && frame.depth < min { return false; }
        if let Some(max) = self.max_depth
            && frame.depth > max { return false; }
        if let Some(hc) = self.has_children
            && frame.has_children() != hc { return false; }
        if let Some(hr) = self.has_return
            && frame.has_return() != hr { return false; }
        true
    }
}

// ── NavigationState ───────────────────────────────────────────────────────────

/// Navigation state for interactive call tree browsing.
#[derive(Debug, Clone, Default)]
pub struct NavigationState {
    /// Currently focused frame ID (`u32::MAX` = none).
    pub focused_frame_id: u32,
    /// Stack of visited frame IDs (for back navigation).
    history: Vec<u32>,
    /// Forward stack (for redo).
    forward: Vec<u32>,
}

impl NavigationState {
    /// Create a new navigation state.
    #[must_use]
    pub const fn new() -> Self {
        Self { focused_frame_id: u32::MAX, history: Vec::new(), forward: Vec::new() }
    }

    /// Navigate to a frame.
    pub fn navigate_to(&mut self, frame_id: u32) {
        if self.focused_frame_id != u32::MAX {
            self.history.push(self.focused_frame_id);
        }
        self.forward.clear();
        self.focused_frame_id = frame_id;
    }

    /// Go back.
    pub fn go_back(&mut self) -> Option<u32> {
        let prev = self.history.pop()?;
        self.forward.push(self.focused_frame_id);
        self.focused_frame_id = prev;
        Some(prev)
    }

    /// Go forward.
    pub fn go_forward(&mut self) -> Option<u32> {
        let next = self.forward.pop()?;
        self.history.push(self.focused_frame_id);
        self.focused_frame_id = next;
        Some(next)
    }

    /// Whether back navigation is available.
    #[must_use]
    pub const fn can_go_back(&self) -> bool { !self.history.is_empty() }

    /// Whether forward navigation is available.
    #[must_use]
    pub const fn can_go_forward(&self) -> bool { !self.forward.is_empty() }
}

// ── CallTreeNavigator ─────────────────────────────────────────────────────────

/// Interactive call tree navigator.
pub struct CallTreeNavigator {
    /// The call tree.
    pub tree: CallTree,
    /// Navigation state.
    pub nav: NavigationState,
    /// Symbol table.
    pub symbols: HashMap<Address, String>,
}

impl CallTreeNavigator {
    /// Build a navigator from a trace.
    #[must_use]
    pub fn from_trace(trace: &ExecutionTrace) -> Self {
        let mut tree = CallTree::build(trace);
        let symbols = HashMap::new();
        tree.apply_symbols(&symbols);
        Self { tree, nav: NavigationState::new(), symbols }
    }

    /// Register a symbol.
    pub fn add_symbol(&mut self, addr: Address, name: impl Into<String>) {
        self.symbols.insert(addr, name.into());
        // Re-resolve.
        self.tree.apply_symbols(&self.symbols);
    }

    /// Jump to the first call to a function address.
    ///
    /// # Errors
    /// Returns `NavError::NoResults` if the function was never called.
    pub fn jump_to_first_call(&mut self, fn_addr: Address) -> Result<&CallFrame, NavError> {
        let calls = self.tree.find_calls_to(fn_addr);
        let (frame_id, _) = calls.into_iter()
            .min_by_key(|&(_, idx)| idx)
            .ok_or(NavError::NoResults)?;
        self.nav.navigate_to(frame_id);
        self.tree.get(frame_id).ok_or(NavError::NoResults)
    }

    /// Jump to the Nth call to a function.
    ///
    /// # Errors
    /// Returns `NavError::OutOfBounds` or `NavError::NoResults`.
    pub fn jump_to_nth_call(&mut self, fn_addr: Address, n: usize) -> Result<&CallFrame, NavError> {
        let mut calls = self.tree.find_calls_to(fn_addr);
        calls.sort_by_key(|&(_, idx)| idx);
        let (frame_id, _) = calls.into_iter().nth(n)
            .ok_or(NavError::OutOfBounds { idx: n, max: 0 })?;
        self.nav.navigate_to(frame_id);
        self.tree.get(frame_id).ok_or(NavError::NoResults)
    }

    /// Jump to the caller of the focused frame.
    ///
    /// # Errors
    /// Returns `NavError::NoResults` if already at root.
    pub fn go_to_caller(&mut self) -> Result<&CallFrame, NavError> {
        let cur = self.nav.focused_frame_id;
        let parent = self.tree.parent_of(cur).ok_or(NavError::NoResults)?;
        let id = parent.id;
        self.nav.navigate_to(id);
        self.tree.get(id).ok_or(NavError::NoResults)
    }

    /// Jump to the first callee of the focused frame.
    ///
    /// # Errors
    /// Returns `NavError::NoResults` if the focused frame has no children.
    pub fn go_to_first_callee(&mut self) -> Result<&CallFrame, NavError> {
        let cur = self.nav.focused_frame_id;
        let children = self.tree.children_of(cur);
        let first = children.into_iter().min_by_key(|f| f.call_idx)
            .ok_or(NavError::NoResults)?;
        let id = first.id;
        self.nav.navigate_to(id);
        self.tree.get(id).ok_or(NavError::NoResults)
    }

    /// Search frames with a query.
    #[must_use]
    pub fn search(&self, query: &CallTreeQuery) -> Vec<&CallFrame> {
        let mut results: Vec<&CallFrame> = self.tree.frames.iter()
            .filter(|f| query.matches(f))
            .collect();
        results.sort_by_key(|f| f.call_idx);
        if let Some(lim) = query.limit { results.truncate(lim); }
        results
    }

    /// Render the call tree as indented text.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        for &root_id in &self.tree.roots {
            self.render_frame(root_id, &mut out);
        }
        out
    }

    fn render_frame(&self, id: u32, out: &mut String) {
        let Some(frame) = self.tree.get(id) else { return };
        let indent = "  ".repeat(frame.depth as usize);
        let ret_info = if frame.has_return() {
            format!(" -> ret@{}", frame.ret_idx)
        } else {
            " (no-ret)".to_string()
        };
        let _ = writeln!(out, "{}[{}] {} call@{}{}", indent, frame.id, frame.display_name(), frame.call_idx, ret_info);
        if frame.expanded {
            let children: Vec<u32> = frame.children.clone();
            for child_id in children {
                self.render_frame(child_id, out);
            }
        }
    }

    /// Get all unique function addresses called in the trace.
    #[must_use]
    pub fn all_called_functions(&self) -> HashSet<Address> {
        self.tree.frames.iter().map(|f| f.fn_addr).collect()
    }

    /// Call depth histogram: depth -> number of calls.
    #[must_use]
    pub fn depth_histogram(&self) -> HashMap<u32, usize> {
        let mut hist: HashMap<u32, usize> = HashMap::new();
        for f in &self.tree.frames {
            *hist.entry(f.depth).or_insert(0) += 1;
        }
        hist
    }

    /// Detect recursive calls.
    #[must_use]
    pub fn find_recursion(&self) -> Vec<RecursionInfo> {
        self.tree.detect_recursion()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TraceBuilder};

    fn make_trace() -> ExecutionTrace {
        let mut b = TraceBuilder::new("test");
        b.insn(0x1000, 0, "nop");
        b.call(0x1001, 0, 0x2000, 0x1006);
        b.insn(0x2000, 0, "push rbp");
        b.call(0x2001, 0, 0x3000, 0x2006);
        b.insn(0x3000, 0, "push rbp");
        b.ret(0x3010, 0, 0x2006);
        b.ret(0x2010, 0, 0x1006);
        b.insn(0x1006, 0, "nop");
        b.build()
    }

    #[test]
    fn test_call_tree_build() {
        let trace = make_trace();
        let tree = CallTree::build(&trace);
        assert!(tree.frame_count() > 0);
        assert!(!tree.roots.is_empty());
    }

    #[test]
    fn test_find_calls_to() {
        let trace = make_trace();
        let tree = CallTree::build(&trace);
        let calls = tree.find_calls_to(0x2000);
        assert!(!calls.is_empty());
    }

    #[test]
    fn test_max_depth() {
        let trace = make_trace();
        let tree = CallTree::build(&trace);
        assert!(tree.max_depth() >= 1);
    }

    #[test]
    fn test_call_tree_navigator_render() {
        let trace = make_trace();
        let nav = CallTreeNavigator::from_trace(&trace);
        let text = nav.render_text();
        assert!(!text.is_empty());
        assert!(text.contains("0x2000") || text.contains("0x3000"));
    }

    #[test]
    fn test_navigation_state() {
        let mut nav = NavigationState::new();
        nav.navigate_to(1);
        nav.navigate_to(2);
        nav.navigate_to(3);
        assert_eq!(nav.focused_frame_id, 3);
        nav.go_back();
        assert_eq!(nav.focused_frame_id, 2);
        nav.go_forward();
        assert_eq!(nav.focused_frame_id, 3);
    }

    #[test]
    fn test_query_by_depth() {
        let trace = make_trace();
        let nav = CallTreeNavigator::from_trace(&trace);
        let q = CallTreeQuery::new().depth_range(0, 0);
        let results = nav.search(&q);
        for r in &results {
            assert_eq!(r.depth, 0);
        }
    }

    #[test]
    fn test_depth_histogram() {
        let trace = make_trace();
        let nav = CallTreeNavigator::from_trace(&trace);
        let hist = nav.depth_histogram();
        assert!(!hist.is_empty());
    }

    #[test]
    fn test_all_called_functions() {
        let trace = make_trace();
        let nav = CallTreeNavigator::from_trace(&trace);
        let funcs = nav.all_called_functions();
        assert!(funcs.contains(&0x2000));
        assert!(funcs.contains(&0x3000));
    }
}
