//! CFG simplification passes: dead block removal, empty block removal,
//! block merging (collapsing straight-line chains).
//!
//! # Relationship to `cfg_simplifier`
//!
//! This module is a **low-level, stateless pass layer**: each function takes a
//! `ControlFlowGraph` by mutable reference and performs one simplification
//! sweep, returning a [`SimplifyResult`] with statistics.  It also hosts the
//! layout helpers (`layout_cfg`, `cfg_to_json`) and the loop nesting forest
//! builder (`build_loop_nesting_forest`) that are re-exported from the crate
//! root.
//!
//! [`cfg_simplifier`](super::cfg_simplifier) is a **higher-level, stateful
//! orchestrator**: it wraps the same transformations behind a
//! `CfgSimplifier` struct that drives a fixed-point loop, exposes
//! `MergeCandidate` for callers that need fine-grained control, and
//! recomputes dominators / post-dominators after each round.  Prefer
//! `CfgSimplifier` when full pipeline integration is needed; use this module
//! directly for lightweight, one-shot passes.

use crate::{CfgEdge, ControlFlowGraph};
#[cfg(test)]
use crate::EdgeKind;
use rustre_core::address::Address;
use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// SimplifyResult
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics produced by a simplification pass.
#[derive(Debug, Clone, Default)]
pub struct SimplifyResult {
    pub removed_dead_blocks: usize,
    pub removed_empty_blocks: usize,
    pub merged_blocks: usize,
}

impl SimplifyResult {
    /// Whether any simplification was performed.
    #[must_use]
    pub const fn any_change(&self) -> bool {
        self.removed_dead_blocks > 0 || self.removed_empty_blocks > 0 || self.merged_blocks > 0
    }
}

impl std::fmt::Display for SimplifyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "dead={} empty={} merged={}",
            self.removed_dead_blocks, self.removed_empty_blocks, self.merged_blocks
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CfgSimplifier
// ─────────────────────────────────────────────────────────────────────────────

/// Applies structural simplifications to a mutable `ControlFlowGraph`.
///
/// Each pass returns a `SimplifyResult` describing what changed.  Passes can
/// be run until convergence by checking `result.any_change()`.
pub struct CfgSimplifier;

impl CfgSimplifier {
    // NOTE: none of the passes below update `cfg.dom_tree`, `cfg.post_dom_tree`,
    // or `cfg.loops` after mutating `blocks`/`edges` — those fields are left
    // stale and reference addresses that may no longer exist in `cfg.blocks`.
    // Callers that need consistent dominator/loop info after simplifying must
    // recompute it explicitly (this is what `cfg_simplifier::CfgSimplifier`
    // does after each round). Do not read `dom_tree`/`post_dom_tree`/`loops`
    // off a CFG immediately after calling these functions without recomputing.

    /// Run all simplification passes until convergence and return the
    /// cumulative result.
    #[must_use]
    pub fn simplify_to_fixpoint(cfg: &mut ControlFlowGraph) -> SimplifyResult {
        let mut total = SimplifyResult::default();
        loop {
            let r = Self::simplify_once(cfg);
            if !r.any_change() {
                break;
            }
            total.removed_dead_blocks += r.removed_dead_blocks;
            total.removed_empty_blocks += r.removed_empty_blocks;
            total.merged_blocks += r.merged_blocks;
        }
        total
    }

    /// Run all passes once and return the result.
    #[must_use]
    pub fn simplify_once(cfg: &mut ControlFlowGraph) -> SimplifyResult {
        SimplifyResult {
            removed_dead_blocks: Self::remove_dead_blocks(cfg),
            removed_empty_blocks: Self::remove_empty_blocks(cfg),
            merged_blocks: Self::merge_straight_chains(cfg),
        }
    }

    /// Remove all blocks that are not reachable from the entry node.
    ///
    /// Returns the number of blocks removed.
    pub fn remove_dead_blocks(cfg: &mut ControlFlowGraph) -> usize {
        let reachable = cfg.reachable_from(cfg.entry);
        // Use a `HashSet` (not `Vec::contains`) so the subsequent edge retain
        // is O(E) rather than O(E * dead_blocks) on CFGs with many dead
        // blocks (e.g. after aggressive inlining or jump-table cleanup).
        let dead: HashSet<Address> = cfg
            .blocks
            .keys()
            .copied()
            .filter(|a| !reachable.contains(a))
            .collect();
        let n = dead.len();
        for addr in &dead {
            cfg.blocks.remove(addr);
        }
        cfg.edges
            .retain(|e| !dead.contains(&e.from) && !dead.contains(&e.to));
        n
    }

    /// Remove empty blocks (blocks with zero instructions) that have exactly
    /// one successor.  Their single in-edge is retargeted to the successor.
    ///
    /// Returns the number of blocks removed.
    ///
    /// # Performance
    /// The previous implementation re-derived its candidate from scratch each
    /// iteration via `cfg.blocks.iter().filter(...)` (an O(V) scan) and used
    /// `cfg.successors`/edge `retain`/`push` (each an O(E) scan), so removing
    /// `k` empty blocks from a CFG with `V` blocks and `E` edges cost
    /// `O(k * (V + E))` — quadratic on CFGs with many empty blocks (a common
    /// post-inlining / jump-table-cleanup shape). This version builds
    /// `from`/`to` edge-index adjacency once (`O(E)`), mutates edges in place
    /// through that index, and does a single `O(E)` compaction pass at the
    /// end, making the whole pass `O(V + E)`.
    pub fn remove_empty_blocks(cfg: &mut ControlFlowGraph) -> usize {
        let n_edges = cfg.edges.len();
        let mut from_idx: HashMap<Address, Vec<usize>> = HashMap::new();
        let mut to_idx: HashMap<Address, Vec<usize>> = HashMap::new();
        for (i, e) in cfg.edges.iter().enumerate() {
            from_idx.entry(e.from).or_default().push(i);
            to_idx.entry(e.to).or_default().push(i);
        }

        // Candidacy (empty body, not entry, exactly one outgoing edge) never
        // changes as *other* empty blocks are processed, since it only
        // depends on the block's own instruction count and out-degree — so
        // the whole worklist can be computed once up front.
        let worklist: Vec<Address> = cfg
            .blocks
            .iter()
            .filter(|(addr, bb)| {
                bb.instructions.is_empty()
                    && **addr != cfg.entry
                    && from_idx.get(*addr).is_some_and(|v| {
                        // Exactly one outgoing edge, and it must not be a
                        // self-loop: a block whose only outgoing edge points
                        // back at itself has `successor == empty`, so
                        // "retarget incoming edges at successor, then remove
                        // `empty`" would leave those incoming edges dangling
                        // at a now-removed block.
                        v.len() == 1 && cfg.edges[v[0]].to != **addr
                    })
            })
            .map(|(addr, _)| *addr)
            .collect();

        let mut removed_edges: HashSet<usize> = HashSet::new();
        let mut removed = 0usize;

        for empty in worklist {
            if !cfg.blocks.contains_key(&empty) {
                continue; // already absorbed as someone else's successor chain
            }
            let Some(out_idxs) = from_idx.get(&empty) else { continue };
            let out_idx = out_idxs[0];
            if removed_edges.contains(&out_idx) {
                continue;
            }
            let successor = cfg.edges[out_idx].to;
            if successor == empty {
                // The out-edge was not a self-loop when the worklist was
                // built, but an earlier removal in this pass retargeted it
                // back at this block (e.g. a cycle of empty blocks
                // 1 -> 2 -> 1: removing 1 rewrites 2 -> 1 into 2 -> 2).
                // Removing the block now would retarget its incoming edges
                // at itself and then delete it, leaving them dangling.
                continue;
            }
            removed_edges.insert(out_idx);

            let incoming: Vec<usize> = to_idx.get(&empty).cloned().unwrap_or_default();
            for idx in incoming {
                if removed_edges.contains(&idx) {
                    continue;
                }
                if cfg.edges[idx].from == empty {
                    // Self-loop into the empty block: drop entirely.
                    removed_edges.insert(idx);
                    continue;
                }
                cfg.edges[idx].to = successor;
                to_idx.entry(successor).or_default().push(idx);
            }

            cfg.blocks.remove(&empty);
            removed += 1;
        }

        if removed > 0 {
            let mut kept: Vec<CfgEdge> = Vec::with_capacity(n_edges.saturating_sub(removed_edges.len()));
            for (i, e) in cfg.edges.iter().enumerate() {
                if !removed_edges.contains(&i) {
                    kept.push(e.clone());
                }
            }
            cfg.edges = kept;
        }

        removed
    }

    /// Merge straight-line chains: when a block has exactly one successor and
    /// that successor has exactly one predecessor, fold them into one block.
    ///
    /// Returns the number of merges performed.
    ///
    /// # Performance
    /// The previous implementation recomputed its candidate via
    /// `cfg.blocks.keys().find(...)` (O(V)) with `cfg.successors`/
    /// `cfg.predecessors` calls inside the predicate (each O(E)) on *every*
    /// block for *every* merge, then rebuilt edges with `retain`/`push`
    /// (another O(E)). That is `O(V * (V*E))` in the worst case (a long
    /// straight-line chain of `V` blocks re-scans the whole edge/block set on
    /// each of the `V` merge steps). This version builds `from`/`to` edge
    /// index adjacency and live successor/predecessor counts once (`O(E)`),
    /// then processes a worklist of merge candidates, updating only the
    /// O(degree) state touched by each merge, for an overall `O(V + E)` pass.
    pub fn merge_straight_chains(cfg: &mut ControlFlowGraph) -> usize {
        let mut from_idx: HashMap<Address, Vec<usize>> = HashMap::new();
        let mut to_count: HashMap<Address, usize> = HashMap::new();
        for (i, e) in cfg.edges.iter().enumerate() {
            from_idx.entry(e.from).or_default().push(i);
            *to_count.entry(e.to).or_default() += 1;
        }

        let is_candidate = |addr: Address,
                             from_idx: &HashMap<Address, Vec<usize>>,
                             to_count: &HashMap<Address, usize>,
                             cfg: &ControlFlowGraph|
         -> Option<(Address, usize)> {
            let outs = from_idx.get(&addr)?;
            if outs.len() != 1 {
                return None;
            }
            let out_idx = outs[0];
            let succ = cfg.edges[out_idx].to;
            if succ == addr || succ == cfg.entry {
                return None;
            }
            if to_count.get(&succ).copied().unwrap_or(0) != 1 {
                return None;
            }
            Some((succ, out_idx))
        };

        let mut worklist: VecDeque<Address> = cfg.blocks.keys().copied().collect();
        let mut in_worklist: HashSet<Address> = worklist.iter().copied().collect();
        let mut merged = 0usize;

        while let Some(head) = worklist.pop_front() {
            in_worklist.remove(&head);
            if !cfg.blocks.contains_key(&head) {
                continue;
            }
            let Some((tail, head_to_tail_idx)) = is_candidate(head, &from_idx, &to_count, cfg)
            else {
                continue;
            };
            if !cfg.blocks.contains_key(&tail) {
                continue;
            }

            // Merge tail's instructions into head.
            let tail_instrs = cfg.blocks[&tail].instructions.clone();
            let tail_end = cfg.blocks[&tail].end;
            if let Some(head_block) = cfg.blocks.get_mut(&head) {
                head_block.instructions.extend(tail_instrs);
                head_block.end = tail_end;
            }

            // Re-point tail's outgoing edges at head (edit `from` in place —
            // `to_count` is unaffected since the edge's target is unchanged).
            let tail_out = from_idx.remove(&tail).unwrap_or_default();
            for &idx in &tail_out {
                cfg.edges[idx].from = head;
            }
            from_idx.insert(head, tail_out);

            // Drop the now-internal head→tail edge and tail's block.
            let ht_to = cfg.edges[head_to_tail_idx].to; // == tail
            debug_assert_eq!(ht_to, tail);
            *to_count.entry(tail).or_default() = 0;
            // `swap_remove` is O(1) (vs. `Vec::remove`'s O(E) shift), but it
            // moves the last element into `head_to_tail_idx` — patch up the
            // one `from_idx` entry that referenced the old last index rather
            // than rescanning every edge.
            let last_idx = cfg.edges.len() - 1;
            cfg.edges.swap_remove(head_to_tail_idx);
            if last_idx != head_to_tail_idx {
                let moved_from = cfg.edges[head_to_tail_idx].from;
                if let Some(idxs) = from_idx.get_mut(&moved_from) {
                    for i in idxs.iter_mut() {
                        if *i == last_idx {
                            *i = head_to_tail_idx;
                            break;
                        }
                    }
                }
            }
            cfg.blocks.remove(&tail);
            merged += 1;

            // `head` may now itself be a fresh candidate (e.g. tail had
            // exactly one outgoing edge, extending the chain further).
            if in_worklist.insert(head) {
                worklist.push_back(head);
            }
        }

        merged
    }

    /// Deduplicate edges: remove exact duplicate edges (same from, to, kind).
    pub fn deduplicate_edges(cfg: &mut ControlFlowGraph) -> usize {
        let mut seen: HashSet<(Address, Address, u8)> = HashSet::new();
        let before = cfg.edges.len();
        cfg.edges
            .retain(|e| seen.insert((e.from, e.to, e.kind as u8)));
        before - cfg.edges.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CFG serialization
// ─────────────────────────────────────────────────────────────────────────────

/// Serialize a `ControlFlowGraph` to a compact JSON representation.
///
/// # Errors
/// Returns `Err` if JSON serialization fails.
pub fn cfg_to_json(cfg: &ControlFlowGraph) -> Result<String, serde_json::Error> {
    use serde_json::{Map, Value};

    let blocks: Vec<Value> = {
        let mut addrs: Vec<Address> = cfg.blocks.keys().copied().collect();
        addrs.sort_by_key(|a| a.0);
        addrs
            .iter()
            .map(|addr| {
                let bb = &cfg.blocks[addr];
                let mut m = Map::new();
                m.insert("start".into(), Value::String(format!("0x{:x}", bb.start.0)));
                m.insert("end".into(), Value::String(format!("0x{:x}", bb.end.0)));
                m.insert(
                    "instr_count".into(),
                    Value::Number(bb.instructions.len().into()),
                );
                Value::Object(m)
            })
            .collect()
    };

    let edges: Vec<Value> = cfg
        .edges
        .iter()
        .map(|e| {
            let mut m = Map::new();
            m.insert("from".into(), Value::String(format!("0x{:x}", e.from.0)));
            m.insert("to".into(), Value::String(format!("0x{:x}", e.to.0)));
            m.insert("kind".into(), Value::String(format!("{:?}", e.kind)));
            Value::Object(m)
        })
        .collect();

    let loops: Vec<Value> = cfg
        .loops
        .iter()
        .map(|lp| {
            let mut m = Map::new();
            m.insert(
                "header".into(),
                Value::String(format!("0x{:x}", lp.header.0)),
            );
            m.insert("size".into(), Value::Number(lp.size().into()));
            m.insert("innermost".into(), Value::Bool(lp.is_innermost));
            Value::Object(m)
        })
        .collect();

    let mut root = Map::new();
    root.insert(
        "entry".into(),
        Value::String(format!("0x{:x}", cfg.entry.0)),
    );
    root.insert("blocks".into(), Value::Array(blocks));
    root.insert("edges".into(), Value::Array(edges));
    root.insert("loops".into(), Value::Array(loops));

    serde_json::to_string(&Value::Object(root))
}

// ─────────────────────────────────────────────────────────────────────────────
// CFG Layout
// ─────────────────────────────────────────────────────────────────────────────

/// A layout position for one basic block (x, y in abstract layout space).
#[derive(Debug, Clone)]
pub struct BlockPosition {
    pub addr: Address,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// A simple hierarchical layout for a CFG.  Nodes are placed in BFS layers.
///
/// Returns a `Vec<BlockPosition>` with one entry per block.
#[must_use]
pub fn layout_cfg(cfg: &ControlFlowGraph) -> Vec<BlockPosition> {
    use std::collections::VecDeque;

    let h_spacing = 160.0_f64;
    let v_spacing = 100.0_f64;
    let node_width = 120.0_f64;
    let node_height = 40.0_f64;

    let mut layer: HashMap<Address, usize> = HashMap::new();
    let mut queue: VecDeque<Address> = VecDeque::new();

    if cfg.blocks.contains_key(&cfg.entry) {
        queue.push_back(cfg.entry);
        layer.insert(cfg.entry, 0);
    }

    while let Some(node) = queue.pop_front() {
        let l = *layer.get(&node).unwrap_or(&0);
        for succ in cfg.successors(node) {
            if let std::collections::hash_map::Entry::Vacant(e) = layer.entry(succ) {
                e.insert(l + 1);
                queue.push_back(succ);
            }
        }
    }

    // Group nodes by layer. `layer` is a HashMap, so iterating it directly
    // (as this used to) makes both the within-layer node order and the
    // by-layer iteration order below nondeterministic across runs (varies
    // with the hasher's random seed) even though the BFS layer assignment
    // itself is deterministic. Sort so the returned layout is reproducible.
    let mut by_layer: HashMap<usize, Vec<Address>> = HashMap::new();
    for (&addr, &l) in &layer {
        by_layer.entry(l).or_default().push(addr);
    }
    for addrs in by_layer.values_mut() {
        addrs.sort_by_key(|a| a.0);
    }
    let mut layer_ids: Vec<usize> = by_layer.keys().copied().collect();
    layer_ids.sort_unstable();

    let mut positions = Vec::new();
    for l in layer_ids {
        let addrs = &by_layer[&l];
        let n = addrs.len();
        let total_width = (n as f64).mul_add(node_width + h_spacing, -h_spacing);
        let x_start = -total_width / 2.0;
        for (i, &addr) in addrs.iter().enumerate() {
            positions.push(BlockPosition {
                addr,
                x: (i as f64).mul_add(node_width + h_spacing, x_start),
                y: l as f64 * (node_height + v_spacing),
                width: node_width,
                height: node_height,
            });
        }
    }

    // Emit entries that were not reached in BFS (disconnected subgraphs).
    let mut y_extra =
        (by_layer.keys().max().copied().unwrap_or(0) + 1) as f64 * (node_height + v_spacing);
    let mut extra_addrs: Vec<Address> = cfg
        .blocks
        .keys()
        .copied()
        .filter(|addr| !layer.contains_key(addr))
        .collect();
    extra_addrs.sort_by_key(|a| a.0);
    for addr in extra_addrs {
        positions.push(BlockPosition {
            addr,
            x: 0.0,
            y: y_extra,
            width: node_width,
            height: node_height,
        });
        y_extra += node_height + v_spacing;
    }

    positions
}

// ─────────────────────────────────────────────────────────────────────────────
// Loop nesting forest
// ─────────────────────────────────────────────────────────────────────────────

/// A node in the loop nesting forest.
#[derive(Debug, Clone)]
pub struct LoopNode {
    /// Header of this loop, or `None` for the top-level forest root.
    pub header: Option<Address>,
    /// Headers of immediately nested child loops.
    pub children: Vec<Address>,
    /// Basic blocks in this loop body but not in any child loop.
    pub own_blocks: Vec<Address>,
    /// All blocks in this loop (own + all children's blocks).
    pub all_blocks: Vec<Address>,
    /// Nesting depth (0 = outermost loop, top-level functions blocks = `usize::MAX`).
    pub depth: usize,
}

/// Build the loop nesting forest from the already-computed `loops` list on a CFG.
#[must_use]
pub fn build_loop_nesting_forest(cfg: &ControlFlowGraph) -> Vec<LoopNode> {
    use crate::NaturalLoop;
    let loops = &cfg.loops;

    // Sort loops by body size (smaller = inner).
    let mut sorted: Vec<&NaturalLoop> = loops.iter().collect();
    sorted.sort_by_key(|l| l.size());

    // For each loop, find its parent (smallest enclosing loop).
    let mut parent: HashMap<Address, Option<Address>> = HashMap::new();
    for lp in &sorted {
        parent.insert(lp.header, None);
    }

    for i in 0..sorted.len() {
        for j in (i + 1)..sorted.len() {
            // Is loop[i] strictly inside loop[j]?
            if sorted[i].body.is_subset(&sorted[j].body) && sorted[i].body != sorted[j].body {
                // Check if there's a tighter enclosing loop already assigned.
                let current_parent = parent[&sorted[i].header];
                let new_parent = sorted[j].header;
                let should_update = match current_parent {
                    None => true,
                    Some(cp) => {
                        // Choose the smaller parent loop.
                        let cp_size = sorted
                            .iter()
                            .find(|l| l.header == cp)
                            .map_or(usize::MAX, |l| l.size());
                        let np_size = sorted
                            .iter()
                            .find(|l| l.header == new_parent)
                            .map_or(usize::MAX, |l| l.size());
                        np_size < cp_size
                    }
                };
                if should_update {
                    *parent.get_mut(&sorted[i].header).unwrap() = Some(new_parent);
                    break;
                }
            }
        }
    }

    // Build child lists.
    let mut children: HashMap<Address, Vec<Address>> =
        loops.iter().map(|l| (l.header, Vec::new())).collect();
    for (&child_hdr, &par_opt) in &parent {
        if let Some(par) = par_opt {
            children.entry(par).or_default().push(child_hdr);
        }
    }

    // Build LoopNode list.
    sorted
        .iter()
        .map(|lp| {
            let header = lp.header;
            // `children` was built by iterating the `parent` HashMap, so its
            // per-header Vec order is nondeterministic (hash-iteration
            // order, not insertion order); `lp.body` is a HashSet, so
            // collecting it directly is nondeterministic too. Sort both
            // before they land in the returned `LoopNode`, otherwise
            // `children`/`own_blocks`/`all_blocks` order varies run to run.
            let mut ch = children[&header].clone();
            ch.sort_by_key(|a| a.0);
            // Own blocks = loop body minus child loop bodies.
            let child_bodies: HashSet<Address> = ch
                .iter()
                .filter_map(|&ch_hdr| sorted.iter().find(|l| l.header == ch_hdr))
                .flat_map(|l| l.body.iter().copied())
                .collect();
            let mut own: Vec<Address> = lp
                .body
                .iter()
                .filter(|b| !child_bodies.contains(b) || **b == header)
                .copied()
                .collect();
            own.sort_by_key(|a| a.0);
            let depth = {
                let mut d = 0usize;
                let mut cur = header;
                while let Some(p) = parent.get(&cur).copied().flatten() {
                    d = d.saturating_add(1);
                    cur = p;
                }
                d
            };
            let mut all_blocks: Vec<Address> = lp.body.iter().copied().collect();
            all_blocks.sort_by_key(|a| a.0);
            LoopNode {
                header: Some(header),
                children: ch,
                own_blocks: own,
                all_blocks,
                depth,
            }
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BasicBlock, DominatorTree, PostDominatorTree, find_natural_loops};

    fn a(v: u64) -> Address {
        Address::new(v)
    }

    fn make_cfg(block_ids: &[u64], raw_edges: &[(u64, u64)]) -> ControlFlowGraph {
        let blocks: HashMap<Address, BasicBlock> = block_ids
            .iter()
            .map(|&n| {
                let addr = a(n);
                (
                    addr,
                    BasicBlock {
                        start: addr,
                        end: addr,
                        instructions: vec![],
                    },
                )
            })
            .collect();
        let edges: Vec<CfgEdge> = raw_edges
            .iter()
            .map(|&(f, t)| CfgEdge {
                from: a(f),
                to: a(t),
                kind: EdgeKind::Unconditional,
            })
            .collect();
        let entry = a(block_ids[0]);
        let dom_tree = DominatorTree::compute(&blocks, &edges, entry);
        let post_dom_tree = PostDominatorTree::compute(&blocks, &edges);
        let mut cfg = ControlFlowGraph {
            blocks,
            edges,
            entry,
            dom_tree,
            post_dom_tree,
            loops: vec![],
        };
        cfg.loops = find_natural_loops(&cfg);
        cfg
    }

    #[test]
    fn test_remove_dead_blocks() {
        // 0 → 1; 2 is disconnected
        let mut cfg = make_cfg(&[0, 1, 2], &[(0, 1)]);
        let removed = CfgSimplifier::remove_dead_blocks(&mut cfg);
        assert_eq!(removed, 1);
        assert!(!cfg.blocks.contains_key(&a(2)));
    }

    #[test]
    fn test_remove_empty_blocks() {
        let mut cfg = make_cfg(&[0, 1, 2], &[(0, 1), (1, 2)]);
        // Block 1 is empty (no instructions) and has one successor (2).
        let removed = CfgSimplifier::remove_empty_blocks(&mut cfg);
        assert!(removed > 0 || !cfg.blocks.contains_key(&a(1)));
    }

    #[test]
    fn test_merge_straight_chain() {
        // 0 → 1 → 2 (each has exactly one pred/succ) — should collapse.
        let mut cfg = make_cfg(&[0, 1, 2], &[(0, 1), (1, 2)]);
        let merged = CfgSimplifier::merge_straight_chains(&mut cfg);
        // 0 and 1 merge (0 → 1, 1 → 2 → they form a chain).
        assert!(merged > 0);
    }

    #[test]
    fn test_merge_straight_chains_never_deletes_entry() {
        // 1 -> 0 (entry), where 0 has exactly one predecessor (1).
        // A naive merge would fold `0` (as `tail`) away, corrupting cfg.entry.
        let mut cfg = make_cfg(&[0, 1], &[(1, 0)]);
        let entry_before = cfg.entry;
        CfgSimplifier::merge_straight_chains(&mut cfg);
        assert_eq!(cfg.entry, entry_before);
        assert!(
            cfg.blocks.contains_key(&cfg.entry),
            "entry block must survive merge_straight_chains"
        );
    }

    #[test]
    fn test_merge_straight_chain_long_collapses_to_one_block() {
        // A long straight-line chain 0→1→2→...→19 should collapse entirely
        // into the entry block. Regression test for the worklist-based
        // rewrite of `merge_straight_chains` (previously O(V) full rescans
        // per merge step).
        let ids: Vec<u64> = (0..20).collect();
        let edges: Vec<(u64, u64)> = (0..19).map(|i| (i, i + 1)).collect();
        let mut cfg = make_cfg(&ids, &edges);
        let merged = CfgSimplifier::merge_straight_chains(&mut cfg);
        assert_eq!(merged, 19);
        assert_eq!(cfg.blocks.len(), 1);
        assert!(cfg.blocks.contains_key(&cfg.entry));
        assert!(cfg.edges.is_empty());
    }

    #[test]
    fn test_remove_empty_blocks_chained_empties_redirect_to_final_target() {
        // 0 (entry, non-empty) → 1 (empty) → 2 (empty) → 3 (non-empty target
        // reused via a self-loop to keep it non-removable). Both 1 and 2 are
        // empty single-successor blocks and should be removed, redirecting
        // 0's edge straight to 3 regardless of worklist processing order.
        let blocks: HashMap<Address, BasicBlock> = [0u64, 1, 2, 3]
            .iter()
            .map(|&n| {
                let addr = a(n);
                let instrs = if n == 0 || n == 3 {
                    vec![rustre_il_llil::LlilInstruction::Ret]
                } else {
                    vec![]
                };
                (addr, BasicBlock { start: addr, end: addr, instructions: instrs })
            })
            .collect();
        let edges: Vec<CfgEdge> = [(0u64, 1u64), (1, 2), (2, 3)]
            .iter()
            .map(|&(f, t)| CfgEdge { from: a(f), to: a(t), kind: EdgeKind::Unconditional })
            .collect();
        let entry = a(0);
        let dom_tree = DominatorTree::compute(&blocks, &edges, entry);
        let post_dom_tree = PostDominatorTree::compute(&blocks, &edges);
        let mut cfg = ControlFlowGraph {
            blocks,
            edges,
            entry,
            dom_tree,
            post_dom_tree,
            loops: vec![],
        };
        cfg.loops = find_natural_loops(&cfg);

        let removed = CfgSimplifier::remove_empty_blocks(&mut cfg);
        assert_eq!(removed, 2);
        assert!(!cfg.blocks.contains_key(&a(1)));
        assert!(!cfg.blocks.contains_key(&a(2)));
        assert!(cfg.blocks.contains_key(&a(0)));
        assert!(cfg.blocks.contains_key(&a(3)));
        assert_eq!(cfg.edges.len(), 1);
        assert_eq!(cfg.edges[0].from, a(0));
        assert_eq!(cfg.edges[0].to, a(3));
    }

    #[test]
    fn test_remove_empty_blocks_self_loop_candidate_is_not_dangling() {
        // Block 1 is empty and its *only* outgoing edge is a self-loop
        // (1 -> 1). It also has an incoming edge from 0. Candidacy for
        // `remove_empty_blocks` only checks "empty + exactly one outgoing
        // edge", which a self-loop-only block satisfies, computing
        // `successor == empty` itself. If the pass proceeds to remove the
        // block anyway, the incoming edge 0->1 is left dangling (redirected
        // to a `successor` address that no longer exists in `cfg.blocks`),
        // corrupting the CFG. This must not happen: either the block is not
        // treated as a candidate, or removal must leave the graph consistent
        // (no edges pointing at a removed block).
        let blocks: HashMap<Address, BasicBlock> = [0u64, 1]
            .iter()
            .map(|&n| {
                let addr = a(n);
                let instrs = if n == 0 {
                    vec![rustre_il_llil::LlilInstruction::Ret]
                } else {
                    vec![]
                };
                (
                    addr,
                    BasicBlock {
                        start: addr,
                        end: addr,
                        instructions: instrs,
                    },
                )
            })
            .collect();
        let edges: Vec<CfgEdge> = [(0u64, 1u64), (1, 1)]
            .iter()
            .map(|&(f, t)| CfgEdge {
                from: a(f),
                to: a(t),
                kind: EdgeKind::Unconditional,
            })
            .collect();
        let entry = a(0);
        let dom_tree = DominatorTree::compute(&blocks, &edges, entry);
        let post_dom_tree = PostDominatorTree::compute(&blocks, &edges);
        let mut cfg = ControlFlowGraph {
            blocks,
            edges,
            entry,
            dom_tree,
            post_dom_tree,
            loops: vec![],
        };
        cfg.loops = find_natural_loops(&cfg);

        CfgSimplifier::remove_empty_blocks(&mut cfg);

        // Whatever happened, every edge endpoint must reference a live block.
        for e in &cfg.edges {
            assert!(
                cfg.blocks.contains_key(&e.from),
                "dangling edge: from {:?} no longer exists",
                e.from
            );
            assert!(
                cfg.blocks.contains_key(&e.to),
                "dangling edge: to {:?} no longer exists",
                e.to
            );
        }
    }

    #[test]
    fn test_remove_empty_blocks_cycle_of_empties_leaves_no_dangling_edges() {
        // Regression test (found by soundness_fuzz): 0 (non-empty) -> 1 -> 2
        // -> 1 where both 1 and 2 are empty. Removing 1 retargets 2 -> 1 into
        // the self-loop 2 -> 2; block 2's out-edge is then a self-loop even
        // though it was not when the worklist was built. The pass used to
        // proceed to remove 2 anyway, retargeting the (former 0 -> 1) edge at
        // the just-deleted block 2 and leaving it dangling.
        let blocks: HashMap<Address, BasicBlock> = [0u64, 1, 2]
            .iter()
            .map(|&n| {
                let addr = a(n);
                let instrs = if n == 0 {
                    vec![rustre_il_llil::LlilInstruction::Ret]
                } else {
                    vec![]
                };
                (addr, BasicBlock { start: addr, end: addr, instructions: instrs })
            })
            .collect();
        let edges: Vec<CfgEdge> = [(0u64, 1u64), (1, 2), (2, 1)]
            .iter()
            .map(|&(f, t)| CfgEdge { from: a(f), to: a(t), kind: EdgeKind::Unconditional })
            .collect();
        let entry = a(0);
        let dom_tree = DominatorTree::compute(&blocks, &edges, entry);
        let post_dom_tree = PostDominatorTree::compute(&blocks, &edges);
        let mut cfg = ControlFlowGraph {
            blocks,
            edges,
            entry,
            dom_tree,
            post_dom_tree,
            loops: vec![],
        };
        cfg.loops = find_natural_loops(&cfg);

        CfgSimplifier::remove_empty_blocks(&mut cfg);

        assert!(cfg.blocks.contains_key(&cfg.entry));
        for e in &cfg.edges {
            assert!(
                cfg.blocks.contains_key(&e.from),
                "dangling edge: from {:?} no longer exists",
                e.from
            );
            assert!(
                cfg.blocks.contains_key(&e.to),
                "dangling edge: to {:?} no longer exists",
                e.to
            );
        }
    }

    #[test]
    fn test_deduplicate_edges() {
        let mut cfg = make_cfg(&[0, 1], &[(0, 1)]);
        // Add a duplicate edge manually.
        cfg.edges.push(CfgEdge {
            from: a(0),
            to: a(1),
            kind: EdgeKind::Unconditional,
        });
        assert_eq!(cfg.edges.len(), 2);
        let removed = CfgSimplifier::deduplicate_edges(&mut cfg);
        assert_eq!(removed, 1);
        assert_eq!(cfg.edges.len(), 1);
    }

    #[test]
    fn test_simplify_result_display() {
        let r = SimplifyResult {
            removed_dead_blocks: 1,
            removed_empty_blocks: 2,
            merged_blocks: 3,
        };
        let s = r.to_string();
        assert!(s.contains("dead=1"));
        assert!(s.contains("empty=2"));
        assert!(s.contains("merged=3"));
    }

    #[test]
    fn test_simplify_result_any_change() {
        let r = SimplifyResult::default();
        assert!(!r.any_change());
        let r2 = SimplifyResult {
            removed_dead_blocks: 1,
            ..SimplifyResult::default()
        };
        assert!(r2.any_change());
    }

    #[test]
    fn test_cfg_to_json() {
        let cfg = make_cfg(&[0, 1, 2], &[(0, 1), (1, 2)]);
        let json = cfg_to_json(&cfg).unwrap();
        assert!(json.contains("entry"));
        assert!(json.contains("blocks"));
        assert!(json.contains("edges"));
    }

    #[test]
    fn test_cfg_to_json_includes_loop_entries() {
        // 0 -> 1 -> 2 -> 1 (natural loop headed at 1).
        let cfg = make_cfg(&[0, 1, 2], &[(0, 1), (1, 2), (2, 1)]);
        assert!(!cfg.loops.is_empty(), "expected a natural loop for this CFG");
        let json = cfg_to_json(&cfg).unwrap();
        assert!(json.contains("\"loops\""));
        assert!(json.contains("\"header\""));
        assert!(json.contains(&format!("0x{:x}", a(1).0)));
    }

    #[test]
    fn test_layout_cfg_produces_positions() {
        let cfg = make_cfg(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)]);
        let layout = layout_cfg(&cfg);
        assert_eq!(layout.len(), cfg.blocks.len());
    }

    #[test]
    fn test_layout_entry_at_layer_zero() {
        let cfg = make_cfg(&[0, 1, 2], &[(0, 1), (1, 2)]);
        let layout = layout_cfg(&cfg);
        let entry_pos = layout.iter().find(|p| p.addr == a(0)).unwrap();
        assert_eq!(entry_pos.y, 0.0);
    }

    #[test]
    fn test_layout_cfg_same_layer_nodes_sorted_by_address() {
        // Regression test: nodes grouped into the same BFS layer used to be
        // ordered by HashMap iteration (nondeterministic across runs)
        // instead of by address, so x-positions within a layer, and the
        // by-layer iteration itself, varied run to run. Build a node with
        // several same-layer siblings inserted out of numeric order and
        // confirm the returned positions are always in ascending address
        // order within each y (layer).
        let cfg = make_cfg(
            &[0, 50, 10, 40, 20, 30],
            &[(0, 50), (0, 10), (0, 40), (0, 20), (0, 30)],
        );
        let layout = layout_cfg(&cfg);
        let mut layer1: Vec<(u64, f64)> = layout
            .iter()
            .filter(|p| p.addr != a(0))
            .map(|p| (p.addr.0, p.x))
            .collect();
        // Positions should already come out address-sorted; verify that,
        // and that x strictly increases with address (left-to-right layout).
        let expected_order: Vec<u64> = vec![10, 20, 30, 40, 50];
        assert_eq!(
            layer1.iter().map(|(a, _)| *a).collect::<Vec<_>>(),
            expected_order
        );
        layer1.sort_by(|x, y| x.1.partial_cmp(&y.1).unwrap());
        assert_eq!(
            layer1.iter().map(|(a, _)| *a).collect::<Vec<_>>(),
            expected_order
        );
    }

    #[test]
    fn test_loop_nesting_forest_children_and_blocks_are_sorted() {
        // Regression test: `LoopNode::children`/`own_blocks`/`all_blocks`
        // used to be built directly from HashMap/HashSet iteration
        // (nondeterministic order); confirm they now come out sorted by
        // address regardless of insertion order.
        // 0 -> 1 -> 2 -> 1 (inner loop), 1 -> 3 -> 0 (outer loop)
        let cfg = make_cfg(
            &[0, 1, 2, 3],
            &[(0, 1), (1, 2), (2, 1), (1, 3), (3, 0)],
        );
        let forest = build_loop_nesting_forest(&cfg);
        for node in &forest {
            let mut sorted_children = node.children.clone();
            sorted_children.sort_by_key(|addr| addr.0);
            assert_eq!(node.children, sorted_children, "children not sorted");

            let mut sorted_own = node.own_blocks.clone();
            sorted_own.sort_by_key(|addr| addr.0);
            assert_eq!(node.own_blocks, sorted_own, "own_blocks not sorted");

            let mut sorted_all = node.all_blocks.clone();
            sorted_all.sort_by_key(|addr| addr.0);
            assert_eq!(node.all_blocks, sorted_all, "all_blocks not sorted");
        }
    }

    #[test]
    fn test_loop_nesting_forest_no_loops() {
        let cfg = make_cfg(&[0, 1, 2], &[(0, 1), (1, 2)]);
        let forest = build_loop_nesting_forest(&cfg);
        assert!(forest.is_empty());
    }

    #[test]
    fn test_loop_nesting_forest_one_loop() {
        let cfg = make_cfg(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 1), (1, 3)]);
        let forest = build_loop_nesting_forest(&cfg);
        assert_eq!(forest.len(), 1);
        assert_eq!(forest[0].header, Some(a(1)));
    }

    #[test]
    fn test_loop_nesting_forest_nested_loops() {
        let cfg = make_cfg(
            &[0, 1, 2, 3, 4],
            &[(0, 1), (1, 2), (2, 3), (3, 2), (3, 1), (1, 4)],
        );
        let forest = build_loop_nesting_forest(&cfg);
        assert_eq!(forest.len(), 2);
        let outer = forest.iter().find(|n| n.header == Some(a(1))).unwrap();
        let inner = forest.iter().find(|n| n.header == Some(a(2))).unwrap();
        assert_eq!(outer.depth, 0);
        assert_eq!(inner.depth, 1);
    }

    #[test]
    fn test_layout_cfg_disconnected_subgraph_placed_below_main_layers() {
        // 0 -> 1 (reachable), 2 -> 3 (disconnected island, never visited by BFS
        // from entry). Both 2 and 3 must still get a position, placed after
        // (below) all BFS-reached layers, and sorted by address.
        let mut cfg = make_cfg(&[0, 1, 2, 3], &[(0, 1)]);
        // Manually add the disconnected edge (make_cfg's entry is block 0;
        // 2->3 has no path from entry).
        cfg.edges.push(CfgEdge { from: a(2), to: a(3), kind: EdgeKind::Unconditional });

        let layout = layout_cfg(&cfg);
        assert_eq!(layout.len(), 4);

        let max_reached_y = layout
            .iter()
            .filter(|p| p.addr == a(0) || p.addr == a(1))
            .map(|p| p.y)
            .fold(f64::MIN, f64::max);

        let pos2 = layout.iter().find(|p| p.addr == a(2)).unwrap();
        let pos3 = layout.iter().find(|p| p.addr == a(3)).unwrap();
        assert!(pos2.y > max_reached_y, "disconnected block must be laid out below reached layers");
        assert!(pos3.y > pos2.y, "disconnected blocks must be ordered by address (2 before 3)");
    }

    #[test]
    fn test_loop_nesting_forest_own_blocks_exclude_child_body() {
        // Outer loop header=1, body {1,2,3}; inner loop header=2, body {2,3}.
        // 0 -> 1 -> 2 -> 3 -> 2 (inner back), 3 -> 1 (outer back), 1 -> 4 (exit)
        let cfg = make_cfg(
            &[0, 1, 2, 3, 4],
            &[(0, 1), (1, 2), (2, 3), (3, 2), (3, 1), (1, 4)],
        );
        let forest = build_loop_nesting_forest(&cfg);
        assert_eq!(forest.len(), 2);
        let outer = forest.iter().find(|n| n.header == Some(a(1))).unwrap();
        let inner = forest.iter().find(|n| n.header == Some(a(2))).unwrap();

        assert_eq!(outer.children, vec![a(2)]);
        assert_eq!(inner.all_blocks, vec![a(2), a(3)]);
        // Outer's own blocks = outer.body - inner.body = {1}.
        assert_eq!(outer.own_blocks, vec![a(1)]);
        assert_eq!(outer.all_blocks, vec![a(1), a(2), a(3)]);
        assert_eq!(inner.own_blocks, vec![a(2), a(3)]);
    }

    #[test]
    fn test_simplify_to_fixpoint_convergence() {
        // Disconnected graph + dead block: should remove dead block in one pass.
        let mut cfg = make_cfg(&[0, 1, 2], &[(0, 1)]);
        let result = CfgSimplifier::simplify_to_fixpoint(&mut cfg);
        assert!(result.removed_dead_blocks >= 1);
    }
}
