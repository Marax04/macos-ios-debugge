//! Tail-call detection.
//!
//! A tail call is a `jmp` used in place of `call`+`ret`: control transfers to
//! another function and never returns to the current one.  We detect:
//!
//! 1. Explicit [`LlilInstruction::TailCall`] terminators emitted by lifters.
//! 2. Unconditional jumps whose constant target lies *outside* the address
//!    range of the current function ("jmp other_func").
//! 3. Indirect jumps in exit blocks (no CFG successors) — likely tail calls
//!    through a register or import thunk (`jmp [rip+…]`), reported with lower
//!    confidence.

use crate::ControlFlowGraph;
use rustre_core::address::Address;
use rustre_il_llil::{LlilExpr, LlilInstruction};
use std::collections::HashSet;

/// How a tail call was identified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TailCallKind {
    /// The IL already carries an explicit `TailCall` terminator.
    ExplicitIl,
    /// Direct `jmp` to a constant address outside the function body.
    JumpOutOfFunction,
    /// Indirect `jmp` in a block with no CFG successors (thunk-style).
    IndirectExitJump,
}

/// A detected tail-call site.
#[derive(Debug, Clone)]
pub struct TailCallSite {
    /// Address of the basic block whose terminator is the tail call.
    pub block: Address,
    /// Statically-known callee address, if any.
    pub target: Option<Address>,
    /// How the site was classified.
    pub kind: TailCallKind,
    /// `true` for high-confidence detections (explicit IL or const target
    /// outside the function); `false` for heuristic indirect-jump sites.
    pub certain: bool,
}

/// Detect tail calls in `cfg`.
///
/// `function_range` is the `[start, end)` byte range of the function; when
/// `None` it is derived from the min block start and max block end in the
/// CFG (which under-approximates for functions with gaps, so pass the real
/// range when known).
#[must_use]
pub fn detect_tail_calls(
    cfg: &ControlFlowGraph,
    function_range: Option<(Address, Address)>,
) -> Vec<TailCallSite> {
    let (lo, hi) = function_range.unwrap_or_else(|| derive_range(cfg));
    let in_function = |t: Address| t >= lo && t <= hi;

    let mut has_succ: HashSet<Address> = HashSet::new();
    for e in &cfg.edges {
        has_succ.insert(e.from);
    }

    let mut sites: Vec<TailCallSite> = Vec::new();
    let mut blocks: Vec<Address> = cfg.blocks.keys().copied().collect();
    blocks.sort_by_key(|a| a.0);

    for baddr in blocks {
        let bb = &cfg.blocks[&baddr];
        let Some(last) = bb.instructions.last() else {
            continue;
        };
        match last {
            LlilInstruction::TailCall { dest } => {
                sites.push(TailCallSite {
                    block: baddr,
                    target: const_target(dest),
                    kind: TailCallKind::ExplicitIl,
                    certain: true,
                });
            }
            LlilInstruction::JumpDest { dest } | LlilInstruction::Jump(dest) => {
                match const_target(dest) {
                    Some(t) if !in_function(t) => {
                        sites.push(TailCallSite {
                            block: baddr,
                            target: Some(t),
                            kind: TailCallKind::JumpOutOfFunction,
                            certain: true,
                        });
                    }
                    Some(_) => {} // intra-function jump: normal control flow
                    None => {
                        // Indirect jump: tail-call candidate only when the
                        // block has no recorded CFG successors (i.e. the jump
                        // target is not a known intra-function block).
                        if !has_succ.contains(&baddr) {
                            sites.push(TailCallSite {
                                block: baddr,
                                target: None,
                                kind: TailCallKind::IndirectExitJump,
                                certain: false,
                            });
                        }
                    }
                }
            }
            LlilInstruction::JumpTo { targets, .. } => {
                // A resolved indirect jump where *every* target is outside
                // the function is a (switch-dispatched) tail call.
                if !targets.is_empty() && targets.iter().all(|&t| !in_function(t)) {
                    for &t in targets {
                        sites.push(TailCallSite {
                            block: baddr,
                            target: Some(t),
                            kind: TailCallKind::JumpOutOfFunction,
                            certain: true,
                        });
                    }
                }
            }
            _ => {}
        }
    }

    sites
}

/// Extract a constant jump target from an expression, looking through the
/// `Load(Const)` pattern used for import thunks (`jmp [imp_addr]`) — the
/// *pointer slot* address is not the callee, so only a bare `Const` counts.
fn const_target(e: &LlilExpr) -> Option<Address> {
    match e {
        LlilExpr::Const { value, .. } => Some(Address::new(*value)),
        _ => None,
    }
}

fn derive_range(cfg: &ControlFlowGraph) -> (Address, Address) {
    let lo = cfg
        .blocks
        .values()
        .map(|b| b.start)
        .min()
        .unwrap_or(Address::new(0));
    let hi = cfg
        .blocks
        .values()
        .map(|b| b.end)
        .max()
        .unwrap_or(Address::new(0));
    (lo, hi)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BasicBlock, CfgEdge, DominatorTree, EdgeKind, PostDominatorTree};
    use rustre_il_llil::Size;
    use std::collections::HashMap;

    fn a(v: u64) -> Address {
        Address::new(v)
    }

    fn konst(v: u64) -> LlilExpr {
        LlilExpr::Const {
            value: v,
            size: Size::QWord,
        }
    }

    fn build_cfg(blocks: Vec<(u64, u64, Vec<LlilInstruction>)>, edges: &[(u64, u64)]) -> ControlFlowGraph {
        let entry = a(blocks.first().map_or(0, |b| b.0));
        let bmap: HashMap<Address, BasicBlock> = blocks
            .into_iter()
            .map(|(s, e, ins)| {
                (
                    a(s),
                    BasicBlock {
                        start: a(s),
                        end: a(e),
                        instructions: ins,
                    },
                )
            })
            .collect();
        let edges: Vec<CfgEdge> = edges
            .iter()
            .map(|&(f, t)| CfgEdge {
                from: a(f),
                to: a(t),
                kind: EdgeKind::Unconditional,
            })
            .collect();
        let dom_tree = DominatorTree::compute(&bmap, &edges, entry);
        let post_dom_tree = PostDominatorTree::compute(&bmap, &edges);
        ControlFlowGraph {
            blocks: bmap,
            edges,
            entry,
            dom_tree,
            loops: vec![],
            post_dom_tree,
        }
    }

    #[test]
    fn explicit_il_tail_call() {
        let cfg = build_cfg(
            vec![(0x1000, 0x1004, vec![LlilInstruction::TailCall { dest: konst(0x9000) }])],
            &[],
        );
        let sites = detect_tail_calls(&cfg, None);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].kind, TailCallKind::ExplicitIl);
        assert_eq!(sites[0].target, Some(a(0x9000)));
        assert!(sites[0].certain);
    }

    #[test]
    fn jump_out_of_function_is_tail_call() {
        let cfg = build_cfg(
            vec![
                (0x1000, 0x1004, vec![LlilInstruction::Nop]),
                (0x1008, 0x100C, vec![LlilInstruction::Jump(konst(0x2000))]),
            ],
            &[(0x1000, 0x1008)],
        );
        let sites = detect_tail_calls(&cfg, Some((a(0x1000), a(0x1010))));
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].kind, TailCallKind::JumpOutOfFunction);
        assert_eq!(sites[0].target, Some(a(0x2000)));
        assert_eq!(sites[0].block, a(0x1008));
    }

    #[test]
    fn intra_function_jump_is_not_tail_call() {
        let cfg = build_cfg(
            vec![
                (0x1000, 0x1004, vec![LlilInstruction::Jump(konst(0x1008))]),
                (0x1008, 0x100C, vec![LlilInstruction::Ret]),
            ],
            &[(0x1000, 0x1008)],
        );
        let sites = detect_tail_calls(&cfg, None);
        assert!(sites.is_empty());
    }

    #[test]
    fn derived_range_flags_external_jump() {
        // No explicit range: blocks span 0x1000..0x100C, jump to 0x5000.
        let cfg = build_cfg(
            vec![
                (0x1000, 0x1004, vec![LlilInstruction::Nop]),
                (0x1008, 0x100C, vec![LlilInstruction::JumpDest { dest: konst(0x5000) }]),
            ],
            &[(0x1000, 0x1008)],
        );
        let sites = detect_tail_calls(&cfg, None);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].target, Some(a(0x5000)));
    }

    #[test]
    fn indirect_exit_jump_is_uncertain_candidate() {
        // jmp rax with no successors.
        let ind = LlilExpr::RegisterRef {
            reg: rustre_il_llil::LlilRegister::from("rax"),
            size: Size::QWord,
        };
        let cfg = build_cfg(
            vec![(0x1000, 0x1004, vec![LlilInstruction::Jump(ind)])],
            &[],
        );
        let sites = detect_tail_calls(&cfg, None);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].kind, TailCallKind::IndirectExitJump);
        assert!(!sites[0].certain);
        assert_eq!(sites[0].target, None);
    }

    #[test]
    fn jump_table_all_external_targets() {
        let cfg = build_cfg(
            vec![(
                0x1000,
                0x1004,
                vec![LlilInstruction::JumpTo {
                    dest: konst(0),
                    targets: vec![a(0x8000), a(0x8100)],
                }],
            )],
            &[],
        );
        let sites = detect_tail_calls(&cfg, Some((a(0x1000), a(0x1010))));
        assert_eq!(sites.len(), 2);
        assert!(sites.iter().all(|s| s.kind == TailCallKind::JumpOutOfFunction));
    }

    #[test]
    fn jump_table_internal_targets_not_flagged() {
        let cfg = build_cfg(
            vec![
                (
                    0x1000,
                    0x1004,
                    vec![LlilInstruction::JumpTo {
                        dest: konst(0),
                        targets: vec![a(0x1008)],
                    }],
                ),
                (0x1008, 0x100C, vec![LlilInstruction::Ret]),
            ],
            &[(0x1000, 0x1008)],
        );
        let sites = detect_tail_calls(&cfg, None);
        assert!(sites.is_empty());
    }

    #[test]
    fn ret_is_not_tail_call() {
        let cfg = build_cfg(vec![(0x1000, 0x1004, vec![LlilInstruction::Ret])], &[]);
        assert!(detect_tail_calls(&cfg, None).is_empty());
    }
}
