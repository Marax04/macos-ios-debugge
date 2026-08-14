//! Stream-order CFG construction from a flat LLIL instruction list.
//!
//! This is the block-boundary + edge derivation that `rustre-decompiler`
//! previously kept privately inside `build_mlil_cfg`. It is RELOCATED here
//! because `rustre-analysis-cfg` owns control-flow graph construction; the
//! decompiler now delegates to it and only materialises its own index-keyed
//! `MlilBasicBlock`s from the result.
//!
//! # Why this is not [`crate::analyze_cfg`]
//!
//! [`crate::analyze_cfg`] is an *address-ordered* builder with a narrow
//! terminator set (it splits after `Jump`/`CondJump`/`JumpTo`/`Ret` only).
//! A decompiler stream needs three things it does not provide, and silently
//! swapping one for the other is NOT output-neutral:
//!
//! 1. **Full terminator coverage.** `LlilInstruction::is_terminator()` also
//!    includes `Call`, `TailCall`, `Trap`, `Return`, `ConditionalJump`,
//!    `CondCall`, `Undefined` and the `Unimplemented*` variants. `Call` in
//!    particular splits a block after *every* call site; `analyze_cfg` would
//!    merge those, producing a completely different block structure for
//!    essentially every real function.
//! 2. **Stream order, not address order.** Blocks are grouped and numbered in
//!    the order they appear in the instruction stream, and fallthrough edges
//!    go to the next block *in that stream*. Compilers routinely lay a
//!    function's blocks out in non-ascending address order; sorting by address
//!    would silently re-thread the graph.
//! 3. **Multi-op source instructions.** Several LLIL ops can share one source
//!    address. A new block may only open on a genuinely new address, so a
//!    lifted instruction is never split down the middle.
//!
//! Out-of-range and indirect branch targets are simply left unresolved (no
//! edge), never guessed at.

use crate::{BasicBlock, CfgEdge, ControlFlowGraph, DominatorTree, EdgeKind, PostDominatorTree};
use rustre_core::address::Address;
use rustre_il_llil::{LlilExpr, LlilInstruction};
use std::collections::{BTreeSet, HashMap};

/// A CFG built from a flat instruction stream, carrying both the
/// address-keyed [`ControlFlowGraph`] (for dominators, post-dominators,
/// dominance frontiers, natural loops, reducibility) and the stream-ordered,
/// index-keyed edge vectors a block-list consumer needs.
#[derive(Debug, Clone)]
pub struct StreamCfg {
    /// Fully analysed address-keyed CFG.
    pub cfg: ControlFlowGraph,
    /// Block start addresses, in stream order. Index `i` here is block id `i`.
    pub order: Vec<Address>,
    /// Half-open end address of each block, parallel to `order`.
    pub ends: Vec<Address>,
    /// The `(address, instruction)` ops of each block, parallel to `order`.
    /// Retained per-op addresses because several ops can share one source
    /// address and downstream lifters need to preserve that mapping.
    pub block_ops: Vec<Vec<(Address, LlilInstruction)>>,
    /// Successor block indices, parallel to `order`. For a two-way branch the
    /// true target is pushed first, then the false target.
    pub successors: Vec<Vec<u32>>,
    /// Predecessor block indices, parallel to `order`.
    pub predecessors: Vec<Vec<u32>>,
}

/// Statically-known constant branch target of a jump destination expression.
fn const_target(expr: &LlilExpr) -> Option<u64> {
    if let LlilExpr::Const { value, .. } = expr { Some(*value) } else { None }
}

/// Split `instrs` into stream-ordered basic blocks and derive their edges.
///
/// `instrs` is a flat `(address, instruction)` list in stream order; several
/// consecutive entries may share one address. Only branch targets inside
/// `[func_start, func_end)` are treated as block leaders.
///
/// Returns `None` for an empty stream.
#[must_use]
pub fn analyze_cfg_stream(
    instrs: &[(Address, LlilInstruction)],
    func_start: u64,
    func_end: u64,
) -> Option<StreamCfg> {
    if instrs.is_empty() {
        return None;
    }
    let in_range = |a: u64| (func_start..func_end).contains(&a);

    // ── 1. Leaders: function entry, in-range branch targets, and the
    //       fallthrough address after every terminator. ──────────────────────
    let mut starts: BTreeSet<u64> = BTreeSet::new();
    starts.insert(func_start);
    for (i, (_, instr)) in instrs.iter().enumerate() {
        if !instr.is_terminator() {
            continue;
        }
        match instr {
            LlilInstruction::CondJump { true_dest, false_dest, .. } => {
                if in_range(true_dest.0) {
                    starts.insert(true_dest.0);
                }
                if in_range(false_dest.0) {
                    starts.insert(false_dest.0);
                }
            }
            LlilInstruction::Jump(dest) | LlilInstruction::JumpDest { dest } => {
                if let Some(t) = const_target(dest)
                    && in_range(t)
                {
                    starts.insert(t);
                }
            }
            _ => {}
        }
        // The address right after a terminator opens a new block even for an
        // unconditional jump: it may still be a landing pad for another edge
        // (dead code after a jump island, or a target only reached via a
        // branch not yet visited).
        if let Some((next, _)) = instrs.get(i + 1) {
            starts.insert(next.0);
        }
    }

    // ── 2. Group into blocks in STREAM order. ─────────────────────────────
    let mut order: Vec<Address> = Vec::new();
    let mut groups: Vec<Vec<(Address, LlilInstruction)>> = Vec::new();
    let mut ends: Vec<Address> = Vec::new();
    let mut last_addr: Option<u64> = None;
    for (addr, instr) in instrs {
        let is_new_addr = last_addr != Some(addr.0);
        if groups.is_empty() || (is_new_addr && starts.contains(&addr.0)) {
            order.push(*addr);
            groups.push(Vec::new());
            ends.push(*addr);
        }
        groups.last_mut().unwrap().push((*addr, instr.clone()));
        *ends.last_mut().unwrap() = Address::new(addr.0 + 1);
        last_addr = Some(addr.0);
    }

    let index_by_start: HashMap<u64, usize> =
        order.iter().enumerate().map(|(i, a)| (a.0, i)).collect();

    // ── 3. Edges, from each block's LAST instruction. ─────────────────────
    let n = order.len();
    let mut successors: Vec<Vec<u32>> = vec![Vec::new(); n];
    for (i, ops) in groups.iter().enumerate() {
        let Some((_, last)) = ops.last() else { continue };
        match last {
            LlilInstruction::CondJump { true_dest, false_dest, .. } => {
                if let Some(&t) = index_by_start.get(&true_dest.0) {
                    successors[i].push(t as u32);
                }
                if let Some(&f) = index_by_start.get(&false_dest.0) {
                    successors[i].push(f as u32);
                }
            }
            LlilInstruction::Jump(dest) | LlilInstruction::JumpDest { dest } => {
                if let Some(t) = const_target(dest)
                    && let Some(&ti) = index_by_start.get(&t)
                {
                    successors[i].push(ti as u32);
                }
            }
            other if other.is_terminator() => {
                // Ret / TailCall / Call / Trap / indirect jump / … — no
                // resolved intra-function successor.
            }
            _ => {
                // Ran into the next block's leader without a terminator: a
                // real fallthrough edge, to the next block IN STREAM ORDER.
                if i + 1 < n {
                    successors[i].push((i + 1) as u32);
                }
            }
        }
    }
    let mut predecessors: Vec<Vec<u32>> = vec![Vec::new(); n];
    for (i, succs) in successors.iter().enumerate() {
        for &s in succs {
            predecessors[s as usize].push(i as u32);
        }
    }

    // ── 4. Address-keyed view + the full dominance/loop analyses. ─────────
    let mut blocks: HashMap<Address, BasicBlock> = HashMap::with_capacity(n);
    for (i, &start) in order.iter().enumerate() {
        blocks.insert(
            start,
            BasicBlock {
                start,
                end: ends[i],
                instructions: groups[i].iter().map(|(_, ins)| ins.clone()).collect(),
            },
        );
    }
    let mut edges: Vec<CfgEdge> = Vec::new();
    for (i, succs) in successors.iter().enumerate() {
        for (k, &s) in succs.iter().enumerate() {
            let kind = if succs.len() >= 2 {
                if k == 0 { EdgeKind::TrueBranch } else { EdgeKind::FalseBranch }
            } else if groups[i].last().is_some_and(|(_, t)| t.is_terminator()) {
                EdgeKind::Unconditional
            } else {
                EdgeKind::Fallthrough
            };
            edges.push(CfgEdge { from: order[i], to: order[s as usize], kind });
        }
    }

    let entry = order[0];
    let dom_tree = DominatorTree::compute(&blocks, &edges, entry);
    let post_dom_tree = PostDominatorTree::compute(&blocks, &edges);
    let mut cfg =
        ControlFlowGraph { blocks, edges, entry, dom_tree, post_dom_tree, loops: Vec::new() };
    cfg.loops = crate::find_natural_loops(&cfg);

    Some(StreamCfg { cfg, order, ends, block_ops: groups, successors, predecessors })
}
