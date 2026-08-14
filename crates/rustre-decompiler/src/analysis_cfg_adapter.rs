//! Adapter: decompiler-private MLIL CFG -> `rustre_analysis_cfg::ControlFlowGraph`.
//!
//! Owner directive seam. `rustre-analysis-cfg` owns control-flow graph
//! construction and dominance analysis; `rustre-decompiler` currently builds
//! its own block graph in `build_mlil_cfg`. This module maps the latter onto
//! the former's public model so the two can be cross-checked before any
//! consumer is switched over.
//!
//! NOTHING CONSUMES THIS YET — it is deliberately output-neutral.
//!
//! Mapping notes:
//! - Both models are address-keyed block graphs, and `build_mlil_cfg`
//!   guarantees block start addresses are unique (it builds a
//!   `HashMap<start, index>` for edge resolution), so `Address -> BasicBlock`
//!   is a faithful keying.
//! - `analysis_cfg::BasicBlock::instructions` is `Vec<LlilInstruction>` while
//!   the decompiler blocks hold *MLIL*. There is no MLIL->LLIL lowering and
//!   inventing one would be a fabrication, so the instruction vector is left
//!   empty: this adapter models CFG STRUCTURE only. Every analysis in
//!   `rustre-analysis-cfg` (dominators, post-dominators, frontiers, natural
//!   loops, RPO) reads only `blocks` keys + `edges`, so structure is
//!   sufficient for all of them.
//! - Edge kinds are inferred from successor arity/position: 2 successors =>
//!   TrueBranch/FalseBranch in the order `build_mlil_cfg` pushes them
//!   (true first, then false); 1 successor => Unconditional when the block
//!   ends in a terminator, Fallthrough otherwise.

use rustre_analysis_cfg::{BasicBlock, CfgEdge, ControlFlowGraph, DominatorTree, EdgeKind};
use rustre_core::address::Address;
use rustre_il_mlil::MlilBasicBlock;
use std::collections::HashMap;

/// Does this MLIL block end in an explicit control-flow terminator?
fn ends_in_terminator(b: &MlilBasicBlock) -> bool {
    b.instrs.last().is_some_and(|ai| ai.instr.is_terminator())
}

/// Build a `rustre_analysis_cfg::ControlFlowGraph` from the decompiler's own
/// MLIL basic blocks (the output of `build_mlil_cfg`).
///
/// `blocks` must be non-empty; the first block is taken as the entry, which
/// matches `build_mlil_cfg` (block 0 always starts at `func_start`).
#[must_use]
pub fn to_analysis_cfg(blocks: &[MlilBasicBlock]) -> Option<ControlFlowGraph> {
    let first = blocks.first()?;
    let entry = first.start;

    let mut map: HashMap<Address, BasicBlock> = HashMap::with_capacity(blocks.len());
    for b in blocks {
        map.insert(b.start, BasicBlock { start: b.start, end: b.end, instructions: Vec::new() });
    }

    let mut edges: Vec<CfgEdge> = Vec::new();
    for b in blocks {
        let term = ends_in_terminator(b);
        for (i, &s) in b.successors.iter().enumerate() {
            let Some(target) = blocks.get(s as usize) else { continue };
            let kind = if b.successors.len() >= 2 {
                if i == 0 { EdgeKind::TrueBranch } else { EdgeKind::FalseBranch }
            } else if term {
                EdgeKind::Unconditional
            } else {
                EdgeKind::Fallthrough
            };
            edges.push(CfgEdge { from: b.start, to: target.start, kind });
        }
    }

    let dom_tree = DominatorTree::compute(&map, &edges, entry);
    let post_dom_tree = rustre_analysis_cfg::PostDominatorTree::compute(&map, &edges);
    let mut cfg = ControlFlowGraph {
        blocks: map,
        edges,
        entry,
        dom_tree,
        loops: Vec::new(),
        post_dom_tree,
    };
    cfg.loops = rustre_analysis_cfg::find_natural_loops(&cfg);
    Some(cfg)
}

#[cfg(test)]
#[path = "analysis_cfg_adapter_difftest.rs"]
mod differential_tests;
