//! Serializable basic-block records derived from a fully analysed
//! [`ControlFlowGraph`].
//!
//! These records flatten the rich CFG types in [`crate`] into a compact form
//! that can be sent across IPC boundaries (e.g. JSON for the MCP service or a
//! UI front-end).  Each block is tagged with a [`BlockKind`] describing its
//! topological role: entry, exit, plain straight-line, conditional/multiway
//! branch, or loop header.

use crate::{ControlFlowGraph, analyze_cfg};
use rustre_core::address::Address;
use rustre_il_llil::LlilInstruction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Topological role of a basic block within the CFG.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum BlockKind {
    /// No incoming edges (the function entry).
    Entry,
    /// No outgoing edges (returns / terminal blocks).
    Exit,
    /// Single successor, single-or-more predecessor straight-line block.
    Normal,
    /// Two or more successors (conditional or jump-table branch).
    Branch,
    /// Has a back-edge from a descendant block (loop header).
    LoopHeader,
}

/// Flat, serializable record describing one basic block.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct BasicBlockRec {
    pub id: u32,
    pub start_addr: u64,
    pub end_addr: u64,
    pub size: u64,
    pub kind: BlockKind,
    pub successors: Vec<u32>,
    pub predecessors: Vec<u32>,
}

/// Build a list of [`BasicBlockRec`] from a fully analysed
/// [`ControlFlowGraph`].
///
/// Blocks are returned in ascending start-address order so the resulting `id`
/// values are stable across invocations on the same CFG.
#[must_use]
pub fn basic_blocks_from_cfg(cfg: &ControlFlowGraph) -> Vec<BasicBlockRec> {
    let mut starts: Vec<Address> = cfg.blocks.keys().copied().collect();
    starts.sort_by_key(|a| a.0);

    // Assign stable ids by sorted start address.
    let id_map: HashMap<Address, u32> = starts
        .iter()
        .enumerate()
        .map(|(i, a)| (*a, i as u32))
        .collect();

    // `ControlFlowGraph::successors`/`predecessors` each do an O(E) linear
    // scan of `cfg.edges`. Calling them per block (plus once more inside
    // `is_loop_header`) made this function O(V * E): quadratic-or-worse on
    // functions with many blocks and/or dense edge sets (e.g. large
    // jump-table switches). Build both adjacency maps once, in O(E), and
    // look blocks up in them instead.
    let mut succ_map: HashMap<Address, Vec<Address>> = HashMap::with_capacity(starts.len());
    let mut pred_map: HashMap<Address, Vec<Address>> = HashMap::with_capacity(starts.len());
    for e in &cfg.edges {
        succ_map.entry(e.from).or_default().push(e.to);
        pred_map.entry(e.to).or_default().push(e.from);
    }

    let mut out = Vec::with_capacity(starts.len());
    for (id, addr) in starts.iter().enumerate() {
        let bb = &cfg.blocks[addr];
        let empty: Vec<Address> = Vec::new();
        let succs: &Vec<Address> = succ_map.get(addr).unwrap_or(&empty);
        let preds: &Vec<Address> = pred_map.get(addr).unwrap_or(&empty);

        // Classify the block.  Order matters: an Entry that also has >=2
        // successors is still reported as Entry, while a LoopHeader takes
        // precedence over a plain Branch classification because the loop
        // structure is the more informative property for downstream tooling.
        let kind = if preds.is_empty() {
            BlockKind::Entry
        } else if succs.is_empty() {
            BlockKind::Exit
        } else if preds
            .iter()
            .any(|&p| cfg.dom_tree.dominates(*addr, p))
        {
            BlockKind::LoopHeader
        } else if succs.len() >= 2 {
            BlockKind::Branch
        } else {
            BlockKind::Normal
        };

        let start_addr = bb.start.0;
        let end_addr = bb.end.0;
        let size = end_addr.saturating_sub(start_addr);

        let successors: Vec<u32> = succs
            .iter()
            .filter_map(|a| id_map.get(a).copied())
            .collect();
        let predecessors: Vec<u32> = preds
            .iter()
            .filter_map(|a| id_map.get(a).copied())
            .collect();

        out.push(BasicBlockRec {
            id: id as u32,
            start_addr,
            end_addr,
            size,
            kind,
            successors,
            predecessors,
        });
    }
    out
}

/// Build basic-block records for the function starting at `addr` given its
/// decoded instruction stream.
///
/// `addr` identifies which function is being analysed (it must equal
/// `instrs[0].0`).  Internally calls [`analyze_cfg`] to produce a fully
/// analysed CFG (dominator tree + natural loops), then projects each block
/// into a [`BasicBlockRec`].  Blocks are returned in ascending start-address
/// order; the entry block has id = 0.
///
/// Returns an empty `Vec` when `instrs` is empty.
#[must_use]
pub fn basic_blocks(addr: Address, instrs: &[(Address, LlilInstruction)]) -> Vec<BasicBlockRec> {
    let _ = addr; // entry is already encoded as instrs[0].0
    basic_blocks_with_instrs(instrs)
}

/// Build basic-block records directly from a decoded `(address, instruction)`
/// stream covering one function.
#[must_use]
pub fn basic_blocks_with_instrs(
    instrs: &[(Address, LlilInstruction)],
) -> Vec<BasicBlockRec> {
    if instrs.is_empty() {
        return Vec::new();
    }
    let cfg = analyze_cfg(instrs);
    basic_blocks_from_cfg(&cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_il_llil::{LlilExpr, Size};

    fn const_expr(v: u64) -> LlilExpr {
        LlilExpr::Const {
            value: v,
            size: Size::QWord,
        }
    }

    /// Straight-line function ending in `Ret` → 1 block, kind Entry (no preds,
    /// no succs).  The first test exercises the trivial path through the
    /// classifier.
    #[test]
    fn straight_line_single_block() {
        let instrs = vec![
            (Address::new(0x100), LlilInstruction::Nop),
            (Address::new(0x104), LlilInstruction::Ret),
        ];
        let recs = basic_blocks_with_instrs(&instrs);
        assert_eq!(recs.len(), 1, "expected one basic block");
        let b = &recs[0];
        assert_eq!(b.start_addr, 0x100);
        // No predecessors AND no successors — Entry wins by ordering.
        assert!(b.predecessors.is_empty());
        assert!(b.successors.is_empty());
        assert_eq!(b.kind, BlockKind::Entry);
    }

    /// Conditional split: entry block with `CondJump` to two ret blocks,
    /// producing exactly three basic blocks with one Entry + two Exits.
    ///
    /// CFG shape:
    ///   0x200 (Entry)  --(true)-->  0x210 (Exit/Ret)
    ///                  --(false)--> 0x220 (Exit/Ret)
    #[test]
    fn conditional_split_three_blocks() {
        let instrs = vec![
            (
                Address::new(0x200),
                LlilInstruction::CondJump {
                    cond: const_expr(1),
                    true_dest: Address::new(0x210),
                    false_dest: Address::new(0x220),
                },
            ),
            (Address::new(0x210), LlilInstruction::Ret),
            (Address::new(0x220), LlilInstruction::Ret),
        ];
        let recs = basic_blocks(Address::new(0x200), &instrs);
        assert_eq!(recs.len(), 3, "expected three basic blocks");

        let entry = recs.iter().find(|b| b.start_addr == 0x200).unwrap();
        assert_eq!(entry.kind, BlockKind::Entry, "0x200 should be Entry");
        assert_eq!(entry.successors.len(), 2, "entry should branch to 2 successors");
        assert!(entry.predecessors.is_empty(), "entry has no predecessors");

        let t = recs.iter().find(|b| b.start_addr == 0x210).unwrap();
        let f = recs.iter().find(|b| b.start_addr == 0x220).unwrap();
        assert_eq!(t.kind, BlockKind::Exit, "0x210 should be Exit");
        assert_eq!(f.kind, BlockKind::Exit, "0x220 should be Exit");
        assert!(t.predecessors.contains(&entry.id), "true arm pred should be entry");
        assert!(f.predecessors.contains(&entry.id), "false arm pred should be entry");
        assert!(t.successors.is_empty(), "true arm has no successors");
        assert!(f.successors.is_empty(), "false arm has no successors");
    }

    /// Multi-block loop: 0x500 (Entry) falls into 0x510 (loop header) which
    /// conditionally jumps back to itself (0x510, true) or exits to 0x520
    /// (false). The back-edge 0x510 -> 0x510 comes from 0x510 itself here,
    /// so exercise a *distinct* descendant back-edge instead: 0x510 always
    /// jumps to 0x520, which conditionally jumps back to 0x510 (loop) or
    /// falls through to 0x530 (exit). This ensures `is_loop_header` is
    /// exercised via a predecessor that is NOT the block itself.
    ///
    /// CFG shape:
    ///   0x500 (Entry) --> 0x510 (LoopHeader)
    ///   0x510 --> 0x520
    ///   0x520 --(true, back-edge)--> 0x510
    ///   0x520 --(false)--> 0x530 (Exit)
    #[test]
    fn multi_block_loop_back_edge_from_descendant() {
        let instrs = vec![
            (Address::new(0x500), LlilInstruction::Jump(const_expr(0x510))),
            (Address::new(0x510), LlilInstruction::Jump(const_expr(0x520))),
            (
                Address::new(0x520),
                LlilInstruction::CondJump {
                    cond: const_expr(1),
                    true_dest: Address::new(0x510),
                    false_dest: Address::new(0x530),
                },
            ),
            (Address::new(0x530), LlilInstruction::Ret),
        ];
        let recs = basic_blocks_with_instrs(&instrs);
        assert_eq!(recs.len(), 4, "expected four basic blocks");

        let entry = recs.iter().find(|b| b.start_addr == 0x500).unwrap();
        assert_eq!(entry.kind, BlockKind::Entry);

        let header = recs.iter().find(|b| b.start_addr == 0x510).unwrap();
        assert_eq!(
            header.kind,
            BlockKind::LoopHeader,
            "0x510 dominates 0x520 which jumps back to it, so it's a loop header"
        );

        let body = recs.iter().find(|b| b.start_addr == 0x520).unwrap();
        assert_eq!(body.kind, BlockKind::Branch);

        let exit = recs.iter().find(|b| b.start_addr == 0x530).unwrap();
        assert_eq!(exit.kind, BlockKind::Exit);
        assert!(exit.predecessors.contains(&body.id));
    }

    /// Wide dispatcher: one block jump-tables to many case blocks that all
    /// return. Regression test for the O(V*E) `successors`/`predecessors`
    /// rescans that `basic_blocks_from_cfg` used to perform per block (fixed
    /// by precomputing adjacency maps once); this also exercises correctness
    /// of the fix on a CFG with many edges fanning out of a single node.
    #[test]
    fn wide_dispatcher_many_case_blocks() {
        const N: u64 = 64;
        let mut instrs = vec![(
            Address::new(0x1000),
            LlilInstruction::JumpTo {
                dest: const_expr(0),
                targets: (0..N).map(|i| Address::new(0x2000 + i * 0x10)).collect(),
            },
        )];
        for i in 0..N {
            instrs.push((Address::new(0x2000 + i * 0x10), LlilInstruction::Ret));
        }
        let recs = basic_blocks_with_instrs(&instrs);
        assert_eq!(recs.len(), N as usize + 1);

        let dispatcher = recs.iter().find(|b| b.start_addr == 0x1000).unwrap();
        assert_eq!(dispatcher.kind, BlockKind::Entry);
        assert_eq!(dispatcher.successors.len(), N as usize);

        for i in 0..N {
            let case = recs
                .iter()
                .find(|b| b.start_addr == 0x2000 + i * 0x10)
                .unwrap();
            assert_eq!(case.kind, BlockKind::Exit);
            assert_eq!(case.predecessors, vec![dispatcher.id]);
        }
    }

    /// Empty instruction stream must yield no basic blocks (not panic).
    #[test]
    fn empty_instrs_yields_no_blocks() {
        let recs = basic_blocks_with_instrs(&[]);
        assert!(recs.is_empty());
    }

    /// A single block whose only instruction is an unconditional jump back
    /// to itself: a self-loop CFG. It should be classified as `LoopHeader`
    /// (it has no way to exit and is its own predecessor via a back-edge),
    /// not `Entry`/`Exit`/`Normal`/`Branch`.
    #[test]
    fn self_loop_only_block_is_loop_header() {
        let instrs = vec![(
            Address::new(0x400),
            LlilInstruction::Jump(const_expr(0x400)),
        )];
        let recs = basic_blocks_with_instrs(&instrs);
        assert_eq!(recs.len(), 1, "expected exactly one basic block");
        let b = &recs[0];
        assert_eq!(b.start_addr, 0x400);
        assert!(b.predecessors.contains(&b.id), "block is its own predecessor");
        assert!(b.successors.contains(&b.id), "block is its own successor");
        assert_eq!(b.kind, BlockKind::LoopHeader);
    }

    /// Diamond shape: entry branches to two arms that rejoin at a single exit.
    ///
    /// CFG shape:
    ///   0x300 (Entry/Branch) --> 0x310 (Normal) --> 0x320 (Exit)
    ///                        --> 0x320 (Exit)
    #[test]
    fn diamond_three_blocks() {
        let instrs = vec![
            (
                Address::new(0x300),
                LlilInstruction::CondJump {
                    cond: const_expr(1),
                    true_dest: Address::new(0x310),
                    false_dest: Address::new(0x320),
                },
            ),
            (Address::new(0x310), LlilInstruction::Nop),
            (Address::new(0x320), LlilInstruction::Ret),
        ];
        let recs = basic_blocks(Address::new(0x300), &instrs);
        assert_eq!(recs.len(), 3, "expected three basic blocks");

        let entry = recs.iter().find(|b| b.start_addr == 0x300).unwrap();
        assert_eq!(entry.kind, BlockKind::Entry);
        assert_eq!(entry.successors.len(), 2);

        let arm = recs.iter().find(|b| b.start_addr == 0x310).unwrap();
        assert_eq!(arm.kind, BlockKind::Normal);
        assert_eq!(arm.predecessors.len(), 1);
        assert_eq!(arm.successors.len(), 1);

        let exit = recs.iter().find(|b| b.start_addr == 0x320).unwrap();
        assert_eq!(exit.kind, BlockKind::Exit);
        assert_eq!(exit.predecessors.len(), 2);
        assert!(exit.successors.is_empty());
    }
}
