//! `control_flow_recovery` — Control flow recovery from HLIL.
//!
//! Recovers structured control flow from flat HLIL basic blocks:
//!
//! * [`IfElseRecovery`] — matches conditional-branch patterns.
//! * [`WhileLoopRecovery`] — detects while-loop back-edges.
//! * [`DoWhileRecovery`] — detects do-while patterns.
//! * [`ForLoopRecovery`] — identifies for-loop induction variables.
//! * [`SwitchRecovery`] — reconstructs jump-table switches.
//! * [`GotoReduction`] — eliminates unnecessary gotos via dominance.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Basic block abstraction ──────────────────────────────────────────────────

/// Unique identifier for a basic block in the CFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlockId(pub u32);

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "B{}", self.0)
    }
}

/// A high-level statement in a basic block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HlilStatement {
    /// An assignment statement.
    Assign { lhs: String, rhs: String },
    /// A conditional branch.
    CondBranch {
        cond: String,
        true_target: BlockId,
        false_target: BlockId,
    },
    /// An unconditional jump.
    Jump(BlockId),
    /// A function return with optional value.
    Return(Option<String>),
    /// A raw string (fallback).
    Raw(String),
    /// An indirect jump (switch-style).
    IndirectJump { expr: String, targets: Vec<BlockId> },
}

impl fmt::Display for HlilStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Assign { lhs, rhs } => write!(f, "{lhs} = {rhs}"),
            Self::CondBranch {
                cond,
                true_target,
                false_target,
            } => {
                write!(f, "if ({cond}) goto {true_target} else goto {false_target}")
            }
            Self::Jump(t) => write!(f, "goto {t}"),
            Self::Return(v) => write!(f, "return {}", v.as_deref().unwrap_or("")),
            Self::Raw(s) => write!(f, "{s}"),
            Self::IndirectJump { expr, targets } => {
                write!(f, "switch ({expr}) [{} targets]", targets.len())
            }
        }
    }
}

/// A basic block with a list of HLIL statements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HlilBlock {
    pub id: BlockId,
    pub statements: Vec<HlilStatement>,
    pub successors: Vec<BlockId>,
    pub predecessors: Vec<BlockId>,
}

impl HlilBlock {
    /// Create a new empty block.
    #[must_use]
    pub const fn new(id: BlockId) -> Self {
        Self {
            id,
            statements: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
        }
    }

    /// Return the terminal statement, if any.
    #[must_use]
    pub fn terminal(&self) -> Option<&HlilStatement> {
        self.statements.last()
    }

    /// Return `true` if the block ends with an unconditional jump.
    #[must_use]
    pub fn is_jump(&self) -> bool {
        matches!(self.terminal(), Some(HlilStatement::Jump(_)))
    }

    /// Return `true` if the block ends with a conditional branch.
    #[must_use]
    pub fn is_conditional(&self) -> bool {
        matches!(self.terminal(), Some(HlilStatement::CondBranch { .. }))
    }

    /// Return `true` if the block ends with a return.
    #[must_use]
    pub fn is_return(&self) -> bool {
        matches!(self.terminal(), Some(HlilStatement::Return(_)))
    }
}

// ─── ControlFlowGraph ────────────────────────────────────────────────────────

/// An in-memory CFG for control flow recovery.
#[derive(Debug, Default, Clone)]
pub struct ControlFlowGraph {
    blocks: HashMap<BlockId, HlilBlock>,
    entry: Option<BlockId>,
}

impl ControlFlowGraph {
    /// Create an empty CFG.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a block to the CFG.
    pub fn add_block(&mut self, block: HlilBlock) {
        let id = block.id;
        self.blocks.insert(id, block);
        if self.entry.is_none() {
            self.entry = Some(id);
        }
    }

    /// Set the entry block.
    pub const fn set_entry(&mut self, id: BlockId) {
        self.entry = Some(id);
    }

    /// Return the entry block id.
    #[must_use]
    pub const fn entry(&self) -> Option<BlockId> {
        self.entry
    }

    /// Return a block by id.
    #[must_use]
    pub fn block(&self, id: BlockId) -> Option<&HlilBlock> {
        self.blocks.get(&id)
    }

    /// Return a mutable block by id.
    pub fn block_mut(&mut self, id: BlockId) -> Option<&mut HlilBlock> {
        self.blocks.get_mut(&id)
    }

    /// Return all block IDs in the CFG.
    #[must_use]
    pub fn block_ids(&self) -> Vec<BlockId> {
        let mut ids: Vec<BlockId> = self.blocks.keys().copied().collect();
        ids.sort();
        ids
    }

    /// Return the number of blocks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Return `true` if the CFG is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Compute a simple post-order DFS traversal order.
    #[must_use]
    pub fn post_order(&self) -> Vec<BlockId> {
        let Some(entry) = self.entry else { return Vec::new() };
        let mut visited = HashSet::new();
        let mut order = Vec::new();
        self.dfs_post(entry, &mut visited, &mut order);
        order
    }

    fn dfs_post(&self, id: BlockId, visited: &mut HashSet<BlockId>, order: &mut Vec<BlockId>) {
        self.dfs_post_depth(id, visited, order, 0);
    }

    fn dfs_post_depth(
        &self,
        id: BlockId,
        visited: &mut HashSet<BlockId>,
        order: &mut Vec<BlockId>,
        depth: usize,
    ) {
        // Guard against stack overflow on adversarial/deeply nested CFGs.
        if depth > 65536 || !visited.insert(id) {
            return;
        }
        if let Some(block) = self.blocks.get(&id) {
            for &succ in &block.successors {
                self.dfs_post_depth(succ, visited, order, depth + 1);
            }
        }
        order.push(id);
    }

    /// Compute the set of back-edges (edges that point to ancestors in the DFS
    /// tree, indicating loops).
    #[must_use]
    pub fn back_edges(&self) -> Vec<(BlockId, BlockId)> {
        let Some(entry) = self.entry else { return Vec::new() };
        let mut visited = HashSet::new();
        let mut on_stack = HashSet::new();
        let mut back = Vec::new();
        self.find_back_edges(entry, &mut visited, &mut on_stack, &mut back);
        back
    }

    fn find_back_edges(
        &self,
        id: BlockId,
        visited: &mut HashSet<BlockId>,
        on_stack: &mut HashSet<BlockId>,
        back: &mut Vec<(BlockId, BlockId)>,
    ) {
        self.find_back_edges_depth(id, visited, on_stack, back, 0);
    }

    fn find_back_edges_depth(
        &self,
        id: BlockId,
        visited: &mut HashSet<BlockId>,
        on_stack: &mut HashSet<BlockId>,
        back: &mut Vec<(BlockId, BlockId)>,
        depth: usize,
    ) {
        // Guard against stack overflow on adversarial/deeply nested CFGs.
        if depth > 65536 || !visited.insert(id) {
            return;
        }
        on_stack.insert(id);
        if let Some(block) = self.blocks.get(&id) {
            for &succ in &block.successors {
                if on_stack.contains(&succ) {
                    back.push((id, succ)); // back-edge
                } else {
                    self.find_back_edges_depth(succ, visited, on_stack, back, depth + 1);
                }
            }
        }
        on_stack.remove(&id);
    }

    /// Compute immediate dominators using a simple O(n²) algorithm.
    ///
    /// Returns a map from block ID to its immediate dominator, or `None` for
    /// the entry block.
    #[must_use]
    pub fn idom(&self) -> HashMap<BlockId, Option<BlockId>> {
        let rpo = {
            let mut order = self.post_order();
            order.reverse();
            order
        };
        let mut dom: HashMap<BlockId, Option<BlockId>> = HashMap::new();
        let Some(entry) = self.entry else { return dom };
        dom.insert(entry, None);
        let mut changed = true;
        while changed {
            changed = false;
            for &b in &rpo {
                if b == entry {
                    continue;
                }
                let Some(block) = self.blocks.get(&b) else { continue };
                let new_idom = block
                    .predecessors
                    .iter()
                    .filter(|&&p| dom.contains_key(&p))
                    .copied()
                    .reduce(|a, b_id| intersect(&dom, a, b_id));
                let current = dom.get(&b).copied().flatten();
                if new_idom != current {
                    dom.insert(b, new_idom);
                    changed = true;
                }
            }
        }
        dom
    }
}

fn collect_loop_blocks(cfg: &ControlFlowGraph, header: BlockId, latch: BlockId) -> HashSet<BlockId> {
    let mut out = HashSet::new();
    out.insert(header);
    out.insert(latch);
    let mut queue: VecDeque<BlockId> = VecDeque::new();
    if let Some(hb) = cfg.block(header) {
        for &s in &hb.successors { if s != header { queue.push_back(s); } }
    }
    while let Some(id) = queue.pop_front() {
        if id == header || !out.insert(id) { continue; }
        if let Some(b) = cfg.block(id) {
            for &s in &b.successors { if s != header { queue.push_back(s); } }
        }
    }
    out
}

fn intersect(dom: &HashMap<BlockId, Option<BlockId>>, mut a: BlockId, mut b: BlockId) -> BlockId {
    let mut seen = HashSet::new();
    loop {
        if a == b {
            return a;
        }
        if seen.contains(&a) {
            return b;
        }
        seen.insert(a);
        if let Some(Some(pa)) = dom.get(&a) {
            a = *pa;
        } else {
            return b;
        }
        if let Some(Some(pb)) = dom.get(&b) {
            b = *pb;
        } else {
            return a;
        }
    }
}

// ─── RecoveredStructure ───────────────────────────────────────────────────────

/// A recovered high-level control-flow structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveredStructure {
    /// Linear sequence of statements.
    Sequence(Vec<String>),
    /// `if (cond) { body }` (no else branch).
    If { cond: String, body: Vec<String> },
    /// `if (cond) { then_body } else { else_body }`.
    IfElse {
        cond: String,
        then_body: Vec<String>,
        else_body: Vec<String>,
    },
    /// `while (cond) { body }`.
    While { cond: String, body: Vec<String> },
    /// `do { body } while (cond);`.
    DoWhile { cond: String, body: Vec<String> },
    /// `for (init; cond; step) { body }`.
    For {
        init: String,
        cond: String,
        step: String,
        body: Vec<String>,
    },
    /// `switch (expr) { cases }`.
    Switch {
        expr: String,
        cases: Vec<(String, Vec<String>)>,
    },
    /// Unstructured goto.
    Goto(String),
}

impl RecoveredStructure {
    /// Emit pseudo-C lines.
    #[must_use]
    pub fn emit(&self, indent: usize) -> Vec<String> {
        let pad = "  ".repeat(indent);
        let mut lines = Vec::new();
        match self {
            Self::Sequence(stmts) => {
                for s in stmts {
                    lines.push(format!("{pad}{s}"));
                }
            }
            Self::If { cond, body } => {
                lines.push(format!("{pad}if ({cond}) {{"));
                for s in body {
                    lines.push(format!("{pad}  {s}"));
                }
                lines.push(format!("{pad}}}"));
            }
            Self::IfElse {
                cond,
                then_body,
                else_body,
            } => {
                lines.push(format!("{pad}if ({cond}) {{"));
                for s in then_body {
                    lines.push(format!("{pad}  {s}"));
                }
                lines.push(format!("{pad}}} else {{"));
                for s in else_body {
                    lines.push(format!("{pad}  {s}"));
                }
                lines.push(format!("{pad}}}"));
            }
            Self::While { cond, body } => {
                lines.push(format!("{pad}while ({cond}) {{"));
                for s in body {
                    lines.push(format!("{pad}  {s}"));
                }
                lines.push(format!("{pad}}}"));
            }
            Self::DoWhile { cond, body } => {
                lines.push(format!("{pad}do {{"));
                for s in body {
                    lines.push(format!("{pad}  {s}"));
                }
                lines.push(format!("{pad}}} while ({cond});"));
            }
            Self::For {
                init,
                cond,
                step,
                body,
            } => {
                lines.push(format!("{pad}for ({init}; {cond}; {step}) {{"));
                for s in body {
                    lines.push(format!("{pad}  {s}"));
                }
                lines.push(format!("{pad}}}"));
            }
            Self::Switch { expr, cases } => {
                lines.push(format!("{pad}switch ({expr}) {{"));
                for (val, stmts) in cases {
                    lines.push(format!("{pad}  case {val}:"));
                    for s in stmts {
                        lines.push(format!("{pad}    {s}"));
                    }
                    lines.push(format!("{pad}    break;"));
                }
                lines.push(format!("{pad}}}"));
            }
            Self::Goto(label) => {
                lines.push(format!("{pad}goto {label};"));
            }
        }
        lines
    }
}

// ─── IfElseRecovery ───────────────────────────────────────────────────────────

/// Matches if/else patterns in the CFG.
///
/// A block with a conditional branch that has one or two arms converging at a
/// join block.
#[derive(Debug, Default)]
pub struct IfElseRecovery {
    recovered: u32,
}

impl IfElseRecovery {
    /// Create a new `IfElseRecovery`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to recover an if/else structure rooted at `header` in `cfg`.
    ///
    /// Returns `Some(RecoveredStructure::If{..})` or `Some(IfElse{..})` on
    /// success, `None` if no matching pattern is found.
    pub fn try_recover(
        &mut self,
        cfg: &ControlFlowGraph,
        header: BlockId,
    ) -> Option<RecoveredStructure> {
        let block = cfg.block(header)?;
        if let Some(HlilStatement::CondBranch {
            cond,
            true_target,
            false_target,
        }) = block.terminal().cloned()
        {
            self.recovered += 1;
            // Check if both targets converge (have the same immediate successor).
            let true_block = cfg.block(true_target);
            let false_block = cfg.block(false_target);

            let true_body: Vec<String> = true_block
                .map(|b| {
                    b.statements
                        .iter()
                        .filter(|s| !matches!(s, HlilStatement::CondBranch { .. }))
                        .map(std::string::ToString::to_string)
                        .collect()
                })
                .unwrap_or_default();

            let false_body: Vec<String> = false_block
                .map(|b| {
                    b.statements
                        .iter()
                        .filter(|s| !matches!(s, HlilStatement::CondBranch { .. }))
                        .map(std::string::ToString::to_string)
                        .collect()
                })
                .unwrap_or_default();

            if false_body.is_empty() {
                Some(RecoveredStructure::If {
                    cond,
                    body: true_body,
                })
            } else {
                Some(RecoveredStructure::IfElse {
                    cond,
                    then_body: true_body,
                    else_body: false_body,
                })
            }
        } else {
            None
        }
    }

    /// Return the number of if/else structures recovered.
    #[must_use]
    pub const fn recovered(&self) -> u32 {
        self.recovered
    }
}

// ─── WhileLoopRecovery ────────────────────────────────────────────────────────

/// Detects while-loop patterns from back-edges in the CFG.
#[derive(Debug, Default)]
pub struct WhileLoopRecovery {
    recovered: u32,
}

impl WhileLoopRecovery {
    /// Create a new `WhileLoopRecovery`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to recover a while-loop for the back-edge `(latch, header)`.
    pub fn try_recover(
        &mut self,
        cfg: &ControlFlowGraph,
        header: BlockId,
        latch: BlockId,
    ) -> Option<RecoveredStructure> {
        let header_block = cfg.block(header)?;
        let cond = match header_block.terminal() {
            Some(HlilStatement::CondBranch { cond, .. }) => cond.clone(),
            _ => return None,
        };
        // Collect body: blocks between header and latch.
        let body_stmts = Self::collect_body(cfg, header, latch);
        self.recovered += 1;
        Some(RecoveredStructure::While {
            cond,
            body: body_stmts,
        })
    }

    fn collect_body(cfg: &ControlFlowGraph, header: BlockId, latch: BlockId) -> Vec<String> {
        let mut stmts = Vec::new();
        // Simple BFS from successors of header until latch or header.
        let Some(header_block) = cfg.block(header) else { return stmts };
        let mut visited = HashSet::new();
        let mut queue: VecDeque<BlockId> = header_block
            .successors
            .iter()
            .filter(|&&s| s != header)
            .copied()
            .collect();
        while let Some(id) = queue.pop_front() {
            if id == header || id == latch || !visited.insert(id) {
                continue;
            }
            if let Some(b) = cfg.block(id) {
                for s in &b.statements {
                    if !matches!(s, HlilStatement::CondBranch { .. } | HlilStatement::Jump(_)) {
                        stmts.push(s.to_string());
                    }
                }
                for &succ in &b.successors {
                    if succ != header {
                        queue.push_back(succ);
                    }
                }
            }
        }
        stmts
    }

    /// Return the number of while-loops recovered.
    #[must_use]
    pub const fn recovered(&self) -> u32 {
        self.recovered
    }
}

// ─── DoWhileRecovery ─────────────────────────────────────────────────────────

/// Detects do-while patterns where the condition test is at the loop tail.
#[derive(Debug, Default)]
pub struct DoWhileRecovery {
    recovered: u32,
}

impl DoWhileRecovery {
    /// Create a new `DoWhileRecovery`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to recover a do-while loop where `latch` ends with the
    /// conditional that has `header` as its back-edge target.
    pub fn try_recover(
        &mut self,
        cfg: &ControlFlowGraph,
        header: BlockId,
        latch: BlockId,
    ) -> Option<RecoveredStructure> {
        let latch_block = cfg.block(latch)?;
        let cond = match latch_block.terminal() {
            Some(HlilStatement::CondBranch {
                cond, true_target, ..
            }) if *true_target == header => cond.clone(),
            _ => return None,
        };
        let mut body: Vec<String> = latch_block
            .statements
            .iter()
            .filter(|s| !matches!(s, HlilStatement::CondBranch { .. }))
            .map(std::string::ToString::to_string)
            .collect();
        // Prepend header body.
        if let Some(hb) = cfg.block(header) {
            let header_stmts: Vec<String> = hb
                .statements
                .iter()
                .filter(|s| !matches!(s, HlilStatement::CondBranch { .. } | HlilStatement::Jump(_)))
                .map(std::string::ToString::to_string)
                .collect();
            let mut full = header_stmts;
            full.append(&mut body);
            body = full;
        }
        self.recovered += 1;
        Some(RecoveredStructure::DoWhile { cond, body })
    }

    /// Return the number of do-while loops recovered.
    #[must_use]
    pub const fn recovered(&self) -> u32 {
        self.recovered
    }
}

// ─── ForLoopRecovery ─────────────────────────────────────────────────────────

/// Identifies for-loop patterns by detecting induction-variable assignments.
///
/// Pattern: `init_block → [for header with cond] → body → [step at latch] → header`
#[derive(Debug, Default)]
pub struct ForLoopRecovery {
    recovered: u32,
}

impl ForLoopRecovery {
    /// Create a new `ForLoopRecovery`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to recover a for-loop from a while-loop structure.
    ///
    /// `init` should be a simple "var = expr" string from the predecessor block.
    /// `step` should be a simple "var += N" string from the latch block.
    pub fn try_recover(
        &mut self,
        cfg: &ControlFlowGraph,
        header: BlockId,
        latch: BlockId,
        init: &str,
        step: &str,
    ) -> Option<RecoveredStructure> {
        let header_block = cfg.block(header)?;
        let cond = match header_block.terminal() {
            Some(HlilStatement::CondBranch { cond, .. }) => cond.clone(),
            _ => return None,
        };
        // Body = blocks between header and latch.
        let body: Vec<String> = Self::collect_body(cfg, header, latch);
        self.recovered += 1;
        Some(RecoveredStructure::For {
            init: init.to_string(),
            cond,
            step: step.to_string(),
            body,
        })
    }

    fn collect_body(cfg: &ControlFlowGraph, header: BlockId, latch: BlockId) -> Vec<String> {
        let mut stmts = Vec::new();
        let Some(header_block) = cfg.block(header) else { return stmts };
        for &succ in &header_block.successors {
            if succ == latch || succ == header {
                continue;
            }
            if let Some(b) = cfg.block(succ) {
                for s in &b.statements {
                    if !matches!(s, HlilStatement::CondBranch { .. } | HlilStatement::Jump(_)) {
                        stmts.push(s.to_string());
                    }
                }
            }
        }
        stmts
    }

    /// Return the number of for-loops recovered.
    #[must_use]
    pub const fn recovered(&self) -> u32 {
        self.recovered
    }

    /// Try to auto-detect a for-loop idiom from the CFG structure alone.
    ///
    /// Conservative rules (all must hold):
    ///   1. `header` ends with a `CondBranch` whose `cond` mentions some var `v`.
    ///   2. Exactly one predecessor of `header` (other than a back-edge from
    ///      inside the loop) contains an `Assign { lhs: v, rhs: <init> }` as
    ///      its last non-jump statement. That assignment becomes `init`.
    ///   3. The `latch` block ends with an `Assign { lhs: v, rhs: <step> }` as
    ///      its last non-jump statement, where `rhs` textually references `v`
    ///      (typical induction step like `v + 1`). That becomes `step`.
    ///
    /// On any mismatch returns `None` so the caller falls back to
    /// [`WhileLoopRecovery`].
    pub fn try_auto_recover(
        &mut self,
        cfg: &ControlFlowGraph,
        header: BlockId,
        latch: BlockId,
    ) -> Option<RecoveredStructure> {
        let header_block = cfg.block(header)?;
        let cond = match header_block.terminal() {
            Some(HlilStatement::CondBranch { cond, .. }) => cond.clone(),
            _ => return None,
        };

        // Find the induction variable: pick the lhs of the latch's last assign,
        // require it appears textually in cond.
        let latch_block = cfg.block(latch)?;
        let (ind_var, step_rhs) = latch_block
            .statements
            .iter()
            .rev()
            .find_map(|s| match s {
                HlilStatement::Assign { lhs, rhs } => Some((lhs.clone(), rhs.clone())),
                _ => None,
            })?;
        if !cond.contains(&ind_var) {
            return None;
        }
        if !step_rhs.contains(&ind_var) {
            return None;
        }

        // Find init in a non-loop predecessor of header.
        let mut init_value: Option<String> = None;
        for &pred in &header_block.predecessors {
            if pred == latch {
                continue;
            }
            if let Some(pb) = cfg.block(pred)
                && let Some((_, rhs)) = pb.statements.iter().rev().find_map(|s| match s {
                    HlilStatement::Assign { lhs, rhs } if lhs == &ind_var => {
                        Some((lhs.clone(), rhs.clone()))
                    }
                    _ => None,
                }) {
                    if init_value.is_some() {
                        // Ambiguous init — bail conservatively.
                        return None;
                    }
                    init_value = Some(rhs);
                }
        }
        let init_rhs = init_value?;

        // Body = blocks between header and latch, but drop the step assignment.
        let mut body: Vec<String> = Self::collect_body(cfg, header, latch);
        // Also collect non-step statements from latch (everything before the step assign).
        let mut latch_body: Vec<String> = Vec::new();
        let mut step_seen = false;
        for s in latch_block.statements.iter().rev() {
            if !step_seen {
                if matches!(s, HlilStatement::Assign { lhs, .. } if lhs == &ind_var) {
                    step_seen = true;
                    continue;
                }
                if matches!(
                    s,
                    HlilStatement::CondBranch { .. } | HlilStatement::Jump(_)
                ) {
                    continue;
                }
            }
            if !matches!(
                s,
                HlilStatement::CondBranch { .. } | HlilStatement::Jump(_)
            ) {
                latch_body.push(s.to_string());
            }
        }
        latch_body.reverse();
        body.extend(latch_body);

        self.recovered += 1;
        Some(RecoveredStructure::For {
            init: format!("{ind_var} = {init_rhs}"),
            cond,
            step: format!("{ind_var} = {step_rhs}"),
            body,
        })
    }
}

// ─── BreakContinueLifter ─────────────────────────────────────────────────────

/// Rewrites raw `goto` lines inside a recovered loop body into `break;` /
/// `continue;` when the target matches the loop's exit / header.
///
/// Conservative rules:
///   * Only literal `goto LABEL;` lines (after trim) are touched.
///   * `goto <exit_label>;` → `break;`
///   * `goto <header_label>;` → `continue;`
///   * All other lines (including `if (cond) goto …`) are left untouched —
///     callers that want to lift conditional gotos should do so structurally.
#[derive(Debug, Default)]
pub struct BreakContinueLifter {
    lifted: u32,
}

impl BreakContinueLifter {
    /// Create a new lifter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Rewrite a loop body in place.
    pub fn lift(&mut self, body: &mut [String], header_label: &str, exit_label: &str) {
        for line in body.iter_mut() {
            let trimmed = line.trim_start();
            let indent_len = line.len() - trimmed.len();
            if let Some(target) = extract_goto_target(trimmed) {
                let replacement = if target == exit_label {
                    Some("break;")
                } else if target == header_label {
                    Some("continue;")
                } else {
                    None
                };
                if let Some(rep) = replacement {
                    let pad = &line[..indent_len];
                    *line = format!("{pad}{rep}");
                    self.lifted += 1;
                }
            }
        }
    }

    /// Number of goto → break/continue rewrites performed.
    #[must_use]
    pub const fn lifted(&self) -> u32 {
        self.lifted
    }
}

// ─── SwitchRecovery ──────────────────────────────────────────────────────────

/// Reconstructs switch statements from indirect jump tables.
#[derive(Debug, Default)]
pub struct SwitchRecovery {
    recovered: u32,
}

impl SwitchRecovery {
    /// Create a new `SwitchRecovery`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to recover a switch from an indirect jump in `block`.
    ///
    /// `case_values` maps each target block ID to its case label string.
    pub fn try_recover(
        &mut self,
        cfg: &ControlFlowGraph,
        block: BlockId,
        case_values: &HashMap<BlockId, String>,
    ) -> Option<RecoveredStructure> {
        let b = cfg.block(block)?;
        let (expr, targets) = match b.terminal() {
            Some(HlilStatement::IndirectJump { expr, targets }) => (expr.clone(), targets.clone()),
            _ => return None,
        };
        let cases: Vec<(String, Vec<String>)> = targets
            .iter()
            .map(|&t| {
                let label = case_values
                    .get(&t)
                    .cloned()
                    .unwrap_or_else(|| format!("{t}"));
                let body: Vec<String> = cfg
                    .block(t)
                    .map(|tb| {
                        tb.statements
                            .iter()
                            .filter(|s| !matches!(s, HlilStatement::Jump(_)))
                            .map(std::string::ToString::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                (label, body)
            })
            .collect();
        self.recovered += 1;
        Some(RecoveredStructure::Switch { expr, cases })
    }

    /// Return the number of switch statements recovered.
    #[must_use]
    pub const fn recovered(&self) -> u32 {
        self.recovered
    }
}

/// Apply a detected jump table to `block_id`.
///
/// Rewrites that block's terminal into an [`HlilStatement::IndirectJump`] whose
/// targets are the block's current successors (capped at the analysed dense case
/// count), and returns the case-value labels mapping each target block to its
/// dense index (`"0"`, `"1"`, …).
///
/// This is the bridge that makes [`SwitchRecovery`] reachable from real
/// jump-table detection ([`crate::jump_table::detect_jump_table`]): feed the
/// returned map straight into [`SwitchRecovery::try_recover`].
#[must_use]
pub fn apply_jump_table(
    cfg: &mut ControlFlowGraph,
    block_id: BlockId,
    jt: &crate::jump_table::JumpTableInfo,
) -> HashMap<BlockId, String> {
    let mut case_values = HashMap::new();
    let Some(block) = cfg.block_mut(block_id) else {
        return case_values;
    };

    // Case targets are the block's successors, in order, up to the dense case
    // count recovered from the bound check.
    let count = (jt.case_count as usize).min(block.successors.len());
    let targets: Vec<BlockId> = block.successors.iter().copied().take(count).collect();

    // Replace a trailing direct/conditional terminal so the indirect jump
    // becomes the block's sole terminal rather than a duplicate.
    if matches!(
        block.statements.last(),
        Some(HlilStatement::Jump(_) | HlilStatement::CondBranch { .. })
    ) {
        block.statements.pop();
    }
    block.statements.push(HlilStatement::IndirectJump {
        expr: jt.index.clone(),
        targets: targets.clone(),
    });

    for (i, t) in targets.iter().enumerate() {
        case_values.insert(*t, i.to_string());
    }
    case_values
}

// ─── GotoReduction ───────────────────────────────────────────────────────────

/// Eliminates unnecessary `goto` statements from a recovered function body.
///
/// A goto is unnecessary when the target is the next sequential statement.
#[derive(Debug, Default)]
pub struct GotoReduction {
    eliminated: u32,
}

impl GotoReduction {
    /// Create a new `GotoReduction`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove gotos from a sequence of pseudo-C lines where the target is the
    /// immediately following label.
    pub fn reduce(&mut self, lines: &[String]) -> Vec<String> {
        let mut result = Vec::new();
        let n = lines.len();
        for i in 0..n {
            let line = &lines[i];
            // Pattern: "goto LABEL;"
            if let Some(label) = extract_goto_target(line) {
                // Look for "LABEL:" in the next non-empty line.
                if let Some(next) = lines.get(i + 1) {
                    let next_trim = next.trim();
                    let label_colon = format!("{label}:");
                    if next_trim == label_colon || next_trim.starts_with(&label_colon) {
                        self.eliminated += 1;
                        continue; // skip goto
                    }
                }
            }
            result.push(line.clone());
        }
        result
    }

    /// Return the number of gotos eliminated.
    #[must_use]
    pub const fn eliminated(&self) -> u32 {
        self.eliminated
    }
}

fn extract_goto_target(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.starts_with("goto ") && trimmed.ends_with(';') {
        let label = trimmed.strip_prefix("goto ")?.strip_suffix(';')?;
        Some(label.trim().to_string())
    } else {
        None
    }
}

// ─── ControlFlowRecovery ─────────────────────────────────────────────────────

/// Top-level driver that combines all recovery passes.
#[derive(Debug, Default)]
pub struct ControlFlowRecovery {
    pub if_else: IfElseRecovery,
    pub while_loop: WhileLoopRecovery,
    pub do_while: DoWhileRecovery,
    pub for_loop: ForLoopRecovery,
    pub switch: SwitchRecovery,
    pub goto_red: GotoReduction,
    pub bc_lifter: BreakContinueLifter,
}

impl ControlFlowRecovery {
    /// Create a new composite recovery pass.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Recover all structures from `cfg`.
    ///
    /// Returns a flat list of pseudo-C lines emitted in CFG order.
    pub fn recover_all(&mut self, cfg: &ControlFlowGraph) -> Vec<String> {
        let mut lines = Vec::new();
        let back_edges = cfg.back_edges();
        let mut consumed: HashSet<BlockId> = HashSet::new();
        let loop_headers: HashMap<BlockId, BlockId> = back_edges.iter().map(|(l, h)| (*h, *l)).collect();
        let do_while_headers: HashSet<BlockId> = loop_headers.iter()
            .filter(|(h, _)| cfg.block(**h).is_some_and(|b| !b.is_conditional()))
            .map(|(h, _)| *h)
            .collect();

        for id in cfg.block_ids() {
            if consumed.contains(&id) { continue; }
            let latch_for_header = loop_headers.get(&id).copied();
            let is_do_while_header = do_while_headers.contains(&id);
            if latch_for_header.is_none() && !is_do_while_header
                && let Some(s) = self.if_else.try_recover(cfg, id) {
                    lines.extend(s.emit(0));
                    continue;
                }
            if let Some(latch) = latch_for_header
                && let Some((emitted, blocks)) = self.try_recover_loop(cfg, id, latch) {
                    lines.extend(emitted);
                    consumed.extend(blocks);
                    continue;
                }
            if let Some(block) = cfg.block(id) {
                for stmt in &block.statements {
                    if !matches!(stmt, HlilStatement::CondBranch { .. } | HlilStatement::Jump(_)) {
                        lines.push(stmt.to_string());
                    }
                }
            }
        }
        self.goto_red.reduce(&lines)
    }

    fn try_recover_loop(
        &mut self,
        cfg: &ControlFlowGraph,
        id: BlockId,
        latch: BlockId,
    ) -> Option<(Vec<String>, HashSet<BlockId>)> {
        let header_label = format!("{id}");
        let exit_label = cfg.block(id)
            .and_then(|b| match b.terminal() {
                Some(HlilStatement::CondBranch { false_target, .. }) => Some(format!("{false_target}")),
                _ => None,
            })
            .unwrap_or_default();

        if let Some(mut s) = self.for_loop.try_auto_recover(cfg, id, latch) {
            if let RecoveredStructure::For { body, .. } = &mut s {
                self.bc_lifter.lift(body, &header_label, &exit_label);
            }
            return Some((s.emit(0), collect_loop_blocks(cfg, id, latch)));
        }
        if cfg.block(id).is_some_and(HlilBlock::is_conditional)
            && let Some(mut s) = self.while_loop.try_recover(cfg, id, latch) {
                if let RecoveredStructure::While { body, .. } = &mut s {
                    self.bc_lifter.lift(body, &header_label, &exit_label);
                }
                let mut blocks = HashSet::new();
                blocks.insert(id);
                blocks.insert(latch);
                return Some((s.emit(0), blocks));
            }
        if let Some(mut s) = self.do_while.try_recover(cfg, id, latch) {
            if let RecoveredStructure::DoWhile { body, .. } = &mut s {
                let exit = cfg.block(latch)
                    .and_then(|b| match b.terminal() {
                        Some(HlilStatement::CondBranch { false_target, .. }) => Some(format!("{false_target}")),
                        _ => None,
                    })
                    .unwrap_or_default();
                self.bc_lifter.lift(body, &header_label, &exit);
            }
            return Some((s.emit(0), collect_loop_blocks(cfg, id, latch)));
        }
        None
    }

    /// Summary of structures recovered.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "if_else={}, while={}, do_while={}, for={}, switch={}, goto_elim={}, bc_lift={}",
            self.if_else.recovered(),
            self.while_loop.recovered(),
            self.do_while.recovered(),
            self.for_loop.recovered(),
            self.switch.recovered(),
            self.goto_red.eliminated(),
            self.bc_lifter.lifted(),
        )
    }
}

impl fmt::Display for ControlFlowRecovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ControlFlowRecovery {{ {} }}", self.summary())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_cond_cfg() -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new();
        let mut header = HlilBlock::new(BlockId(0));
        header.statements.push(HlilStatement::CondBranch {
            cond: "x > 0".to_string(),
            true_target: BlockId(1),
            false_target: BlockId(2),
        });
        header.successors = vec![BlockId(1), BlockId(2)];

        let mut then_b = HlilBlock::new(BlockId(1));
        then_b.statements.push(HlilStatement::Assign {
            lhs: "y".into(),
            rhs: "x + 1".into(),
        });
        then_b.successors = vec![BlockId(3)];

        let mut else_b = HlilBlock::new(BlockId(2));
        else_b.statements.push(HlilStatement::Assign {
            lhs: "y".into(),
            rhs: "0".into(),
        });
        else_b.successors = vec![BlockId(3)];

        let ret_b = HlilBlock::new(BlockId(3));

        cfg.add_block(header);
        cfg.add_block(then_b);
        cfg.add_block(else_b);
        cfg.add_block(ret_b);
        cfg
    }

    fn simple_while_cfg() -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new();
        let mut header = HlilBlock::new(BlockId(0));
        header.statements.push(HlilStatement::CondBranch {
            cond: "i < 10".to_string(),
            true_target: BlockId(1),
            false_target: BlockId(2),
        });
        header.successors = vec![BlockId(1), BlockId(2)];
        header.predecessors = vec![BlockId(1)];

        let mut body = HlilBlock::new(BlockId(1));
        body.statements.push(HlilStatement::Assign {
            lhs: "i".into(),
            rhs: "i + 1".into(),
        });
        body.statements.push(HlilStatement::Jump(BlockId(0)));
        body.successors = vec![BlockId(0)];
        body.predecessors = vec![BlockId(0)];

        let exit = HlilBlock::new(BlockId(2));
        cfg.add_block(header);
        cfg.add_block(body);
        cfg.add_block(exit);
        cfg
    }

    // ── CFG basics ───────────────────────────────────────────────────────

    #[test]
    fn test_cfg_add_and_block() {
        let mut cfg = ControlFlowGraph::new();
        cfg.add_block(HlilBlock::new(BlockId(0)));
        assert_eq!(cfg.len(), 1);
        assert!(cfg.block(BlockId(0)).is_some());
    }

    #[test]
    fn test_cfg_post_order() {
        let cfg = simple_while_cfg();
        let order = cfg.post_order();
        // Entry (0) should appear after its successors in post-order.
        assert!(!order.is_empty());
    }

    #[test]
    fn test_cfg_back_edges() {
        let cfg = simple_while_cfg();
        let back = cfg.back_edges();
        // Expect body(1) → header(0) to be a back-edge.
        assert!(back.contains(&(BlockId(1), BlockId(0))));
    }

    #[test]
    fn test_block_terminal() {
        let cfg = simple_cond_cfg();
        let b = cfg.block(BlockId(0)).unwrap();
        assert!(b.is_conditional());
        let b1 = cfg.block(BlockId(1)).unwrap();
        assert!(!b1.is_conditional());
    }

    // ── IfElseRecovery ───────────────────────────────────────────────────

    #[test]
    fn test_if_else_recovery_if_else() {
        let cfg = simple_cond_cfg();
        let mut r = IfElseRecovery::new();
        let result = r.try_recover(&cfg, BlockId(0));
        assert!(matches!(result, Some(RecoveredStructure::IfElse { .. })));
        assert_eq!(r.recovered(), 1);
    }

    #[test]
    fn test_if_else_recovery_no_match() {
        let cfg = simple_cond_cfg();
        let mut r = IfElseRecovery::new();
        // Block 1 (then-body) has no conditional branch → None
        assert!(r.try_recover(&cfg, BlockId(1)).is_none());
    }

    #[test]
    fn test_if_else_emit() {
        let s = RecoveredStructure::IfElse {
            cond: "a > b".into(),
            then_body: vec!["x = 1;".into()],
            else_body: vec!["x = 0;".into()],
        };
        let lines = s.emit(0);
        assert!(lines[0].contains("if (a > b)"));
        assert!(lines.iter().any(|l| l.contains("else")));
    }

    // ── WhileLoopRecovery ────────────────────────────────────────────────

    #[test]
    fn test_while_recovery() {
        let cfg = simple_while_cfg();
        let mut r = WhileLoopRecovery::new();
        let result = r.try_recover(&cfg, BlockId(0), BlockId(1));
        assert!(matches!(result, Some(RecoveredStructure::While { .. })));
        assert_eq!(r.recovered(), 1);
    }

    #[test]
    fn test_while_emit() {
        let s = RecoveredStructure::While {
            cond: "i < 10".into(),
            body: vec!["i++;".into()],
        };
        let lines = s.emit(1);
        assert!(lines[0].contains("while (i < 10)"));
    }

    // ── DoWhileRecovery ──────────────────────────────────────────────────

    #[test]
    fn test_do_while_recovery() {
        let mut cfg = ControlFlowGraph::new();
        let mut header = HlilBlock::new(BlockId(0));
        header.statements.push(HlilStatement::Assign {
            lhs: "i".into(),
            rhs: "i + 1".into(),
        });
        header.successors = vec![BlockId(1)];

        let mut latch = HlilBlock::new(BlockId(1));
        latch.statements.push(HlilStatement::CondBranch {
            cond: "i < 10".to_string(),
            true_target: BlockId(0),
            false_target: BlockId(2),
        });
        latch.successors = vec![BlockId(0), BlockId(2)];

        let exit = HlilBlock::new(BlockId(2));
        cfg.add_block(header);
        cfg.add_block(latch);
        cfg.add_block(exit);

        let mut r = DoWhileRecovery::new();
        let result = r.try_recover(&cfg, BlockId(0), BlockId(1));
        assert!(matches!(result, Some(RecoveredStructure::DoWhile { .. })));
    }

    #[test]
    fn test_do_while_emit() {
        let s = RecoveredStructure::DoWhile {
            cond: "i < 5".into(),
            body: vec!["print(i);".into()],
        };
        let lines = s.emit(0);
        assert!(lines[0].contains("do {"));
        assert!(lines.last().unwrap().contains("while (i < 5)"));
    }

    // ── ForLoopRecovery ──────────────────────────────────────────────────

    #[test]
    fn test_for_recovery() {
        let cfg = simple_while_cfg();
        let mut r = ForLoopRecovery::new();
        let result = r.try_recover(&cfg, BlockId(0), BlockId(1), "i = 0", "i++");
        assert!(matches!(result, Some(RecoveredStructure::For { .. })));
    }

    #[test]
    fn test_for_emit() {
        let s = RecoveredStructure::For {
            init: "i = 0".into(),
            cond: "i < n".into(),
            step: "i++".into(),
            body: vec!["buf[i] = 0;".into()],
        };
        let lines = s.emit(0);
        assert!(lines[0].starts_with("for ("));
    }

    // ── SwitchRecovery ───────────────────────────────────────────────────

    #[test]
    fn test_switch_recovery() {
        let mut cfg = ControlFlowGraph::new();
        let mut block = HlilBlock::new(BlockId(0));
        block.statements.push(HlilStatement::IndirectJump {
            expr: "opcode".to_string(),
            targets: vec![BlockId(1), BlockId(2)],
        });
        block.successors = vec![BlockId(1), BlockId(2)];
        cfg.add_block(block);
        cfg.add_block(HlilBlock::new(BlockId(1)));
        cfg.add_block(HlilBlock::new(BlockId(2)));

        let mut case_vals = HashMap::new();
        case_vals.insert(BlockId(1), "0".to_string());
        case_vals.insert(BlockId(2), "1".to_string());

        let mut r = SwitchRecovery::new();
        let result = r.try_recover(&cfg, BlockId(0), &case_vals);
        assert!(matches!(result, Some(RecoveredStructure::Switch { .. })));
        assert_eq!(r.recovered(), 1);
    }

    #[test]
    fn jump_table_detection_feeds_switch_recovery() {
        use crate::jump_table::detect_jump_table;
        use rustre_core::address::Address;
        use rustre_core::arch::{InstrFlags, Instruction};

        let mk = |addr: u64, m: &str, o: &str| Instruction {
            address: Address::from(addr),
            size: 1,
            mnemonic: m.to_string(),
            operands: o.to_string(),
            operand_list: Vec::new(),
            flags: InstrFlags::empty(),
            bytes: Vec::new(),
            comment: None,
        };

        // Real detection: a 3-case dense switch.
        let insns = vec![
            mk(0x1000, "cmp", "eax, 2"),
            mk(0x1003, "ja", "0x1050"),
            mk(0x1009, "jmp", "[0x401000 + eax*4]"),
        ];
        let jt = detect_jump_table(&insns).expect("jump table detected");
        assert_eq!(jt.case_count, 3);

        // A CFG whose switch block fans out to the three case blocks.
        let mut cfg = ControlFlowGraph::new();
        let mut head = HlilBlock::new(BlockId(0));
        head.successors = vec![BlockId(1), BlockId(2), BlockId(3)];
        cfg.add_block(head);
        for id in 1..=3 {
            cfg.add_block(HlilBlock::new(BlockId(id)));
        }

        // Bridge: apply the detected table, then recover the switch.
        let case_values = apply_jump_table(&mut cfg, BlockId(0), &jt);
        assert_eq!(case_values.len(), 3);
        assert_eq!(case_values.get(&BlockId(1)).map(String::as_str), Some("0"));

        let mut r = SwitchRecovery::new();
        match r.try_recover(&cfg, BlockId(0), &case_values) {
            Some(RecoveredStructure::Switch { expr, cases }) => {
                assert_eq!(expr, "eax");
                assert_eq!(cases.len(), 3);
            }
            other => panic!("expected switch, got {other:?}"),
        }
        assert_eq!(r.recovered(), 1);
    }

    #[test]
    fn test_switch_emit() {
        let s = RecoveredStructure::Switch {
            expr: "x".into(),
            cases: vec![
                ("0".into(), vec!["action_a();".into()]),
                ("1".into(), vec!["action_b();".into()]),
            ],
        };
        let lines = s.emit(0);
        assert!(lines[0].contains("switch (x)"));
    }

    // ── GotoReduction ────────────────────────────────────────────────────

    #[test]
    fn test_goto_reduction_removes_sequential() {
        let mut r = GotoReduction::new();
        let lines = vec!["goto loop_end;".to_string(), "loop_end:".to_string()];
        let reduced = r.reduce(&lines);
        assert!(!reduced.iter().any(|l| l.contains("goto")));
        assert_eq!(r.eliminated(), 1);
    }

    #[test]
    fn test_goto_reduction_keeps_non_sequential() {
        let mut r = GotoReduction::new();
        let lines = vec![
            "goto somewhere;".to_string(),
            "x = 1;".to_string(),
            "somewhere:".to_string(),
        ];
        let reduced = r.reduce(&lines);
        // The goto is NOT sequential → should be kept.
        assert!(reduced.iter().any(|l| l.contains("goto somewhere")));
    }

    // ── ControlFlowRecovery ──────────────────────────────────────────────

    #[test]
    fn test_cfr_recover_all_while() {
        let cfg = simple_while_cfg();
        let mut cfr = ControlFlowRecovery::new();
        let lines = cfr.recover_all(&cfg);
        // Should have recovered the while loop.
        assert!(cfr.while_loop.recovered() > 0 || !lines.is_empty());
    }

    #[test]
    fn test_cfr_summary() {
        let cfr = ControlFlowRecovery::new();
        let s = cfr.summary();
        assert!(s.contains("if_else="));
    }

    #[test]
    fn test_cfr_display() {
        let cfr = ControlFlowRecovery::new();
        assert!(cfr.to_string().contains("ControlFlowRecovery"));
    }

    // ── for-loop auto-detect ─────────────────────────────────────────────

    /// Build a CFG of the canonical for-loop idiom:
    ///   B-1 (pre): i = 0; goto B0
    ///   B0  (hdr): if (i < 10) goto B1 else goto B2     (header)
    ///   B1  (lat): buf[i] = 0; i = i + 1; goto B0       (body + step at latch)
    ///   B2  (exit)
    fn for_loop_cfg() -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new();

        let mut pre = HlilBlock::new(BlockId(3));
        pre.statements.push(HlilStatement::Assign {
            lhs: "i".into(),
            rhs: "0".into(),
        });
        pre.statements.push(HlilStatement::Jump(BlockId(0)));
        pre.successors = vec![BlockId(0)];

        let mut header = HlilBlock::new(BlockId(0));
        header.statements.push(HlilStatement::CondBranch {
            cond: "i < 10".into(),
            true_target: BlockId(1),
            false_target: BlockId(2),
        });
        header.successors = vec![BlockId(1), BlockId(2)];
        header.predecessors = vec![BlockId(3), BlockId(1)];

        let mut latch = HlilBlock::new(BlockId(1));
        latch.statements.push(HlilStatement::Assign {
            lhs: "buf[i]".into(),
            rhs: "0".into(),
        });
        latch.statements.push(HlilStatement::Assign {
            lhs: "i".into(),
            rhs: "i + 1".into(),
        });
        latch.statements.push(HlilStatement::Jump(BlockId(0)));
        latch.successors = vec![BlockId(0)];
        latch.predecessors = vec![BlockId(0)];

        let exit = HlilBlock::new(BlockId(2));

        cfg.add_block(pre);
        cfg.add_block(header);
        cfg.add_block(latch);
        cfg.add_block(exit);
        cfg.set_entry(BlockId(3));
        cfg
    }

    #[test]
    fn test_for_loop_auto_detect() {
        let cfg = for_loop_cfg();
        let mut r = ForLoopRecovery::new();
        let s = r
            .try_auto_recover(&cfg, BlockId(0), BlockId(1))
            .expect("for-loop should auto-detect");
        match s {
            RecoveredStructure::For {
                init,
                cond,
                step,
                body,
            } => {
                assert_eq!(init, "i = 0");
                assert_eq!(cond, "i < 10");
                assert_eq!(step, "i = i + 1");
                // Body should retain the non-step latch stmt.
                assert!(body.iter().any(|l| l.contains("buf[i] = 0")));
                // Body must NOT contain the step assignment.
                assert!(!body.iter().any(|l| l == "i = i + 1"));
            }
            other => panic!("expected For, got {other:?}"),
        }
    }

    #[test]
    fn test_for_auto_detect_rejects_non_idiom() {
        // simple_while_cfg has body `i = i + 1` but NO init in a predecessor
        // (entry block 0 IS the header itself, has no separate pre-block).
        let cfg = simple_while_cfg();
        let mut r = ForLoopRecovery::new();
        assert!(r.try_auto_recover(&cfg, BlockId(0), BlockId(1)).is_none());
    }

    #[test]
    fn test_cfr_emits_for_loop() {
        let cfg = for_loop_cfg();
        let mut cfr = ControlFlowRecovery::new();
        let lines = cfr.recover_all(&cfg);
        let joined = lines.join("\n");
        assert!(
            joined.contains("for (i = 0; i < 10; i = i + 1)"),
            "expected for-loop output, got:\n{joined}"
        );
        assert_eq!(cfr.for_loop.recovered(), 1);
    }

    // ── do-while emission via orchestrator ───────────────────────────────

    fn do_while_cfg() -> ControlFlowGraph {
        // B0 header (no cond, falls into B1)
        // B1 latch (cond at tail; true→B0, false→B2)
        // B2 exit
        let mut cfg = ControlFlowGraph::new();
        let mut header = HlilBlock::new(BlockId(0));
        header.statements.push(HlilStatement::Assign {
            lhs: "i".into(),
            rhs: "i + 1".into(),
        });
        header.successors = vec![BlockId(1)];
        header.predecessors = vec![BlockId(1)];

        let mut latch = HlilBlock::new(BlockId(1));
        latch.statements.push(HlilStatement::CondBranch {
            cond: "i < 10".into(),
            true_target: BlockId(0),
            false_target: BlockId(2),
        });
        latch.successors = vec![BlockId(0), BlockId(2)];
        latch.predecessors = vec![BlockId(0)];

        let exit = HlilBlock::new(BlockId(2));
        cfg.add_block(header);
        cfg.add_block(latch);
        cfg.add_block(exit);
        cfg.set_entry(BlockId(0));
        cfg
    }

    #[test]
    fn test_cfr_emits_do_while() {
        let cfg = do_while_cfg();
        let mut cfr = ControlFlowRecovery::new();
        let lines = cfr.recover_all(&cfg);
        let joined = lines.join("\n");
        assert!(
            joined.contains("do {") && joined.contains("} while (i < 10)"),
            "expected do/while output, got:\n{joined}"
        );
    }

    // ── break / continue lifting ─────────────────────────────────────────

    #[test]
    fn test_bc_lifter_break_and_continue() {
        let mut lifter = BreakContinueLifter::new();
        let mut body = vec![
            "  x = 1;".to_string(),
            "  goto B2;".to_string(),     // → break
            "  goto B0;".to_string(),     // → continue
            "  goto B7;".to_string(),     // untouched (unrelated label)
        ];
        lifter.lift(&mut body, "B0", "B2");
        assert_eq!(body[0], "  x = 1;");
        assert_eq!(body[1], "  break;");
        assert_eq!(body[2], "  continue;");
        assert_eq!(body[3], "  goto B7;");
        assert_eq!(lifter.lifted(), 2);
    }

    #[test]
    fn test_bc_lifter_ignores_conditional_goto() {
        let mut lifter = BreakContinueLifter::new();
        let mut body = vec!["if (done) goto B2;".to_string()];
        lifter.lift(&mut body, "B0", "B2");
        // Conditional gotos aren't simple literal `goto` lines — keep them.
        assert_eq!(body[0], "if (done) goto B2;");
        assert_eq!(lifter.lifted(), 0);
    }

    #[test]
    fn test_bc_lifter_via_orchestrator_in_while() {
        // CFG:
        //   B0 header: if (running) goto B1 else goto B3 (exit)
        //   B1 body:   Raw("goto B3;"); jump B2
        //   B2 latch:  jump B0 (back-edge)
        //   B3 exit
        // The literal `goto B3;` line in the body should become `break;`.
        let mut cfg = ControlFlowGraph::new();
        let mut header = HlilBlock::new(BlockId(0));
        header.statements.push(HlilStatement::CondBranch {
            cond: "running".into(),
            true_target: BlockId(1),
            false_target: BlockId(3),
        });
        header.successors = vec![BlockId(1), BlockId(3)];
        header.predecessors = vec![BlockId(2)];

        let mut body = HlilBlock::new(BlockId(1));
        body.statements.push(HlilStatement::Raw("goto B3;".into()));
        body.statements.push(HlilStatement::Jump(BlockId(2)));
        body.successors = vec![BlockId(2)];
        body.predecessors = vec![BlockId(0)];

        let mut latch = HlilBlock::new(BlockId(2));
        latch.statements.push(HlilStatement::Jump(BlockId(0)));
        latch.successors = vec![BlockId(0)];
        latch.predecessors = vec![BlockId(1)];

        let exit = HlilBlock::new(BlockId(3));
        cfg.add_block(header);
        cfg.add_block(body);
        cfg.add_block(latch);
        cfg.add_block(exit);
        cfg.set_entry(BlockId(0));

        let mut cfr = ControlFlowRecovery::new();
        let lines = cfr.recover_all(&cfg);
        let joined = lines.join("\n");
        assert!(
            joined.contains("break;"),
            "expected break in output, got:\n{joined}"
        );
        assert!(cfr.bc_lifter.lifted() >= 1);
    }
}
