//! Rich control-flow edge classification and basic-block construction helpers.
//!
//! The base [`crate::EdgeKind`] enum distinguishes the four structural edge
//! roles used by the dominator machinery.  For higher-level analyses (call
//! graph extraction, interprocedural slicing) a finer taxonomy is useful, so
//! this module adds [`FlowEdgeKind`] which separates intra-procedural transfers
//! (`jump`, `branch-taken`, `branch-not-taken`, `fallthrough`) from
//! inter-procedural ones (`call`, `return`).

use crate::{BasicBlock, CfgEdge, EdgeKind};
use rustre_core::address::Address;
use rustre_il_llil::LlilInstruction;
use std::collections::{HashMap, HashSet};

/// A fine-grained classification of a control-flow transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum FlowEdgeKind {
    /// Straight-line fallthrough to the next sequential block.
    Fallthrough,
    /// Unconditional jump.
    Jump,
    /// Conditional branch, condition evaluated true.
    BranchTaken,
    /// Conditional branch, condition evaluated false (fallthrough side).
    BranchNotTaken,
    /// Call to another function (the call site's return edge is `Return`).
    Call,
    /// Return from the current function back to a caller.
    Return,
    /// Indirect transfer whose precise nature is unknown.
    Indirect,
}

impl FlowEdgeKind {
    /// Whether this edge stays inside the current function.
    #[must_use]
    pub const fn is_intraprocedural(self) -> bool {
        !matches!(self, Self::Call | Self::Return)
    }

    /// Whether this edge is conditional.
    #[must_use]
    pub const fn is_conditional(self) -> bool {
        matches!(self, Self::BranchTaken | Self::BranchNotTaken)
    }

    /// Map to the coarse structural [`EdgeKind`] used by the dominator code.
    #[must_use]
    pub const fn to_edge_kind(self) -> EdgeKind {
        match self {
            Self::Fallthrough | Self::BranchNotTaken => EdgeKind::Fallthrough,
            Self::Jump | Self::Call | Self::Return | Self::Indirect => EdgeKind::Unconditional,
            Self::BranchTaken => EdgeKind::TrueBranch,
        }
    }

    /// Short textual tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Fallthrough => "fallthrough",
            Self::Jump => "jump",
            Self::BranchTaken => "branch_taken",
            Self::BranchNotTaken => "branch_not_taken",
            Self::Call => "call",
            Self::Return => "return",
            Self::Indirect => "indirect",
        }
    }
}

/// A classified control-flow edge carrying the fine-grained [`FlowEdgeKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowEdge {
    /// Source block start address.
    pub from: Address,
    /// Destination block start address.
    pub to: Address,
    /// Fine-grained edge classification.
    pub kind: FlowEdgeKind,
}

impl FlowEdge {
    /// Construct a [`FlowEdge`].
    #[must_use]
    pub const fn new(from: Address, to: Address, kind: FlowEdgeKind) -> Self {
        Self { from, to, kind }
    }

    /// Lower to the structural [`CfgEdge`].
    #[must_use]
    pub const fn to_cfg_edge(self) -> CfgEdge {
        CfgEdge {
            from: self.from,
            to: self.to,
            kind: self.kind.to_edge_kind(),
        }
    }
}

/// Classify the out-edges of a block given its terminator instruction and the
/// address of the following sequential block (`fallthrough`, if any).
///
/// `block_start` is the address of the block being classified.  For a
/// conditional jump the *taken* edge goes to `true_dest` and the *not-taken*
/// edge to `false_dest`.
#[must_use]
pub fn classify_terminator(
    block_start: Address,
    terminator: &LlilInstruction,
    fallthrough: Option<Address>,
) -> Vec<FlowEdge> {
    let mut edges = Vec::new();
    match terminator {
        // `Jump(dest)` (tuple form, emitted by `llil_builder`) and
        // `JumpDest { dest }` (struct form) are two representations of the
        // same unconditional-jump terminator -- every other consumer in the
        // workspace (decompiler, MLIL bridge, SSA reconstruction, optimizer)
        // matches both together. Missing `Jump` here used to silently treat
        // it as a non-terminator, falling through to the generic fallthrough
        // arm below and merging real jump targets into the wrong block.
        LlilInstruction::JumpDest { dest } | LlilInstruction::Jump(dest) => {
            if let rustre_il_llil::LlilExpr::Const { value, .. } = dest {
                edges.push(FlowEdge::new(
                    block_start,
                    Address::new(*value),
                    FlowEdgeKind::Jump,
                ));
            } else if let Some(ft) = fallthrough {
                // Unknown indirect target —" record an indirect edge to the
                // fallthrough as a placeholder so the block is not orphaned.
                edges.push(FlowEdge::new(block_start, ft, FlowEdgeKind::Indirect));
            }
        }
        LlilInstruction::JumpTo { targets, .. } => {
            for &t in targets {
                edges.push(FlowEdge::new(block_start, t, FlowEdgeKind::Jump));
            }
        }
        LlilInstruction::CondJump {
            true_dest,
            false_dest,
            ..
        } => {
            edges.push(FlowEdge::new(
                block_start,
                *true_dest,
                FlowEdgeKind::BranchTaken,
            ));
            edges.push(FlowEdge::new(
                block_start,
                *false_dest,
                FlowEdgeKind::BranchNotTaken,
            ));
        }
        LlilInstruction::CallDest { dest } | LlilInstruction::CondCall { dest, .. } => {
            if let rustre_il_llil::LlilExpr::Const { value, .. } = dest {
                edges.push(FlowEdge::new(
                    block_start,
                    Address::new(*value),
                    FlowEdgeKind::Call,
                ));
            }
            // A (non-tail) call returns, so the fallthrough is also a successor.
            if let Some(ft) = fallthrough {
                edges.push(FlowEdge::new(block_start, ft, FlowEdgeKind::Fallthrough));
            }
        }
        LlilInstruction::TailCall { dest } => {
            if let rustre_il_llil::LlilExpr::Const { value, .. } = dest {
                edges.push(FlowEdge::new(
                    block_start,
                    Address::new(*value),
                    FlowEdgeKind::Call,
                ));
            }
        }
        LlilInstruction::Ret => {
            // No intra-procedural successor.
        }
        // Non-terminators / traps fall through if a successor exists.
        _ => {
            if let Some(ft) = fallthrough {
                edges.push(FlowEdge::new(block_start, ft, FlowEdgeKind::Fallthrough));
            }
        }
    }
    edges
}

/// Compute the set of basic-block *leaders* from a flat, address-sorted list of
/// `(address, instruction)` pairs.
///
/// A leader is the first instruction of a block: the entry, any branch/jump
/// target, and any instruction following a terminator.
#[must_use]
pub fn compute_leaders(instrs: &[(Address, LlilInstruction)]) -> HashSet<Address> {
    let mut leaders = HashSet::new();
    if instrs.is_empty() {
        return leaders;
    }
    leaders.insert(instrs[0].0);

    let addr_set: HashSet<Address> = instrs.iter().map(|(a, _)| *a).collect();

    for (i, (_, inst)) in instrs.iter().enumerate() {
        // Successor (next sequential instruction) is a leader after a terminator.
        let next = instrs.get(i + 1).map(|(a, _)| *a);
        match inst {
            // See the matching comment in `classify_terminator`: `Jump` and
            // `JumpDest` are the same terminator in two syntactic forms.
            LlilInstruction::JumpDest { dest } | LlilInstruction::Jump(dest) => {
                if let rustre_il_llil::LlilExpr::Const { value, .. } = dest {
                    let t = Address::new(*value);
                    if addr_set.contains(&t) {
                        leaders.insert(t);
                    }
                }
                if let Some(n) = next {
                    leaders.insert(n);
                }
            }
            LlilInstruction::CondJump {
                true_dest,
                false_dest,
                ..
            } => {
                for t in [*true_dest, *false_dest] {
                    if addr_set.contains(&t) {
                        leaders.insert(t);
                    }
                }
                if let Some(n) = next {
                    leaders.insert(n);
                }
            }
            LlilInstruction::JumpTo { targets, .. } => {
                for &t in targets {
                    if addr_set.contains(&t) {
                        leaders.insert(t);
                    }
                }
                if let Some(n) = next {
                    leaders.insert(n);
                }
            }
            LlilInstruction::Ret | LlilInstruction::TailCall { .. } => {
                if let Some(n) = next {
                    leaders.insert(n);
                }
            }
            _ => {}
        }
    }
    leaders
}

/// Split an address-sorted instruction list into basic blocks keyed by the
/// block's start address.  Pure structural splitting based on leaders.
#[must_use]
pub fn split_basic_blocks(instrs: &[(Address, LlilInstruction)]) -> HashMap<Address, BasicBlock> {
    let leaders = compute_leaders(instrs);
    let mut blocks: HashMap<Address, BasicBlock> = HashMap::new();
    let mut current_start: Option<Address> = None;
    let mut current: Vec<LlilInstruction> = Vec::new();

    for (i, (addr, inst)) in instrs.iter().enumerate() {
        if leaders.contains(addr) {
            // Flush any in-progress block.
            if let Some(start) = current_start.take() {
                let end = *addr;
                blocks.insert(
                    start,
                    BasicBlock {
                        start,
                        end,
                        instructions: std::mem::take(&mut current),
                    },
                );
            }
            current_start = Some(*addr);
        }
        current.push(inst.clone());

        let is_last = i + 1 == instrs.len();
        let next_is_leader = instrs.get(i + 1).is_some_and(|(a, _)| leaders.contains(a));
        if let Some(start) = current_start.filter(|_| is_last || next_is_leader) {
            current_start = None;
            let end = if is_last {
                // End = address past the last instruction; approximate as addr+1.
                // Saturate: `addr` is derived from disassembly of untrusted
                // input, so an adversarial stream can place the last
                // instruction at `u64::MAX`, where plain `+ 1` would panic
                // in debug builds and silently wrap to 0 in release.
                Address::new(addr.as_u64().saturating_add(1))
            } else {
                instrs[i + 1].0
            };
            blocks.insert(
                start,
                BasicBlock {
                    start,
                    end,
                    instructions: std::mem::take(&mut current),
                },
            );
        }
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_il_llil::{LlilExpr, Size, llil_const, llil_reg};

    fn jump_to(v: u64) -> LlilInstruction {
        LlilInstruction::JumpDest {
            dest: llil_const(v, Size::QWord),
        }
    }

    fn cond(t: u64, f: u64) -> LlilInstruction {
        LlilInstruction::CondJump {
            cond: llil_reg("zf", Size::Byte),
            true_dest: Address::new(t),
            false_dest: Address::new(f),
        }
    }

    #[test]
    fn flow_edge_kind_properties() {
        assert!(FlowEdgeKind::Jump.is_intraprocedural());
        assert!(!FlowEdgeKind::Call.is_intraprocedural());
        assert!(!FlowEdgeKind::Return.is_intraprocedural());
        assert!(FlowEdgeKind::BranchTaken.is_conditional());
        assert!(!FlowEdgeKind::Fallthrough.is_conditional());
        assert_eq!(FlowEdgeKind::BranchTaken.tag(), "branch_taken");
    }

    #[test]
    fn flow_edge_kind_lowering() {
        assert_eq!(
            FlowEdgeKind::BranchTaken.to_edge_kind(),
            EdgeKind::TrueBranch
        );
        assert_eq!(
            FlowEdgeKind::BranchNotTaken.to_edge_kind(),
            EdgeKind::Fallthrough
        );
        assert_eq!(FlowEdgeKind::Jump.to_edge_kind(), EdgeKind::Unconditional);
    }

    #[test]
    fn classify_unconditional_jump() {
        let edges =
            classify_terminator(Address::new(0x10), &jump_to(0x40), Some(Address::new(0x20)));
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].kind, FlowEdgeKind::Jump);
        assert_eq!(edges[0].to, Address::new(0x40));
    }

    #[test]
    fn classify_conditional_jump() {
        let edges = classify_terminator(
            Address::new(0x10),
            &cond(0x40, 0x20),
            Some(Address::new(0x20)),
        );
        assert_eq!(edges.len(), 2);
        let taken = edges
            .iter()
            .find(|e| e.kind == FlowEdgeKind::BranchTaken)
            .unwrap();
        let nt = edges
            .iter()
            .find(|e| e.kind == FlowEdgeKind::BranchNotTaken)
            .unwrap();
        assert_eq!(taken.to, Address::new(0x40));
        assert_eq!(nt.to, Address::new(0x20));
    }

    #[test]
    fn classify_call_has_fallthrough() {
        let call = LlilInstruction::CallDest {
            dest: llil_const(0x500, Size::QWord),
        };
        let edges = classify_terminator(Address::new(0x10), &call, Some(Address::new(0x15)));
        assert_eq!(edges.len(), 2);
        assert!(
            edges
                .iter()
                .any(|e| e.kind == FlowEdgeKind::Call && e.to == Address::new(0x500))
        );
        assert!(
            edges
                .iter()
                .any(|e| e.kind == FlowEdgeKind::Fallthrough && e.to == Address::new(0x15))
        );
    }

    #[test]
    fn classify_ret_has_no_successor() {
        let edges = classify_terminator(
            Address::new(0x10),
            &LlilInstruction::Ret,
            Some(Address::new(0x15)),
        );
        assert!(edges.is_empty());
    }

    #[test]
    fn classify_jump_table() {
        let jt = LlilInstruction::JumpTo {
            dest: LlilExpr::RegisterRef {
                reg: rustre_il_llil::LlilRegister::Concrete("rax".to_string()),
                size: Size::QWord,
            },
            targets: vec![
                Address::new(0x100),
                Address::new(0x200),
                Address::new(0x300),
            ],
        };
        let edges = classify_terminator(Address::new(0x10), &jt, None);
        assert_eq!(edges.len(), 3);
        assert!(edges.iter().all(|e| e.kind == FlowEdgeKind::Jump));
    }

    #[test]
    fn leaders_branchy_function() {
        // 0: cond -> 8 / 4 ; 4: jump 0xC ; 8: nop ; C: ret
        let instrs = vec![
            (Address::new(0), cond(8, 4)),
            (Address::new(4), jump_to(0xC)),
            (Address::new(8), LlilInstruction::Nop),
            (Address::new(0xC), LlilInstruction::Ret),
        ];
        let leaders = compute_leaders(&instrs);
        assert!(leaders.contains(&Address::new(0)));
        assert!(leaders.contains(&Address::new(4)));
        assert!(leaders.contains(&Address::new(8)));
        assert!(leaders.contains(&Address::new(0xC)));
    }

    #[test]
    fn split_blocks_branchy() {
        let instrs = vec![
            (Address::new(0), LlilInstruction::Nop),
            (Address::new(2), cond(8, 4)),
            (Address::new(4), LlilInstruction::Nop),
            (Address::new(6), jump_to(0xC)),
            (Address::new(8), LlilInstruction::Nop),
            (Address::new(0xC), LlilInstruction::Ret),
        ];
        let blocks = split_basic_blocks(&instrs);
        // Blocks should start at 0, 4, 8, 0xC.
        assert!(blocks.contains_key(&Address::new(0)));
        assert!(blocks.contains_key(&Address::new(4)));
        assert!(blocks.contains_key(&Address::new(8)));
        assert!(blocks.contains_key(&Address::new(0xC)));
        // First block holds nop + condjump.
        assert_eq!(blocks[&Address::new(0)].instructions.len(), 2);
    }

    #[test]
    fn split_basic_blocks_overflowing_last_address_does_not_panic() {
        // Regression test: the last block's `end` used to be computed as
        // `addr.as_u64() + 1`. An adversarial/malformed instruction stream
        // that places its final instruction at u64::MAX would panic (debug)
        // or silently wrap to 0 (release) instead of saturating.
        let addr = Address::new(u64::MAX);
        let instrs = vec![(addr, LlilInstruction::Nop)];
        let blocks = split_basic_blocks(&instrs);
        let block = blocks.get(&addr).expect("block should exist");
        assert_eq!(block.end, Address::new(u64::MAX));
    }

    #[test]
    fn flow_edge_to_cfg_edge() {
        let fe = FlowEdge::new(Address::new(1), Address::new(2), FlowEdgeKind::BranchTaken);
        let ce = fe.to_cfg_edge();
        assert_eq!(ce.from, Address::new(1));
        assert_eq!(ce.to, Address::new(2));
        assert_eq!(ce.kind, EdgeKind::TrueBranch);
    }
}
