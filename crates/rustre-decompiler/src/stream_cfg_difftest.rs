//! DIFFERENTIAL PROOF for the `rustre-analysis-cfg` delegation in
//! `build_mlil_cfg`.
//!
//! `build_mlil_cfg` no longer computes block boundaries or edges: it calls
//! `rustre_analysis_cfg::analyze_cfg_stream`. That makes the pre-existing
//! `analysis_cfg_adapter_difftest` insufficient on its own — it proves the
//! ADAPTER faithfully re-expresses a block graph, but the production path now
//! *produces* the graph in the other crate.
//!
//! So this file keeps the decompiler's ORIGINAL private boundary+edge
//! algorithm, verbatim, as an independent reference implementation, and
//! asserts that the relocated `analyze_cfg_stream` agrees with it on:
//!   * block start addresses, in stream order
//!   * per-block half-open end addresses
//!   * per-block successor index vectors (INCLUDING order — true edge first)
//!   * per-block predecessor index vectors
//!
//! over hand-shaped streams that exercise each terminator class plus 4000
//! randomized LLIL streams. If someone later "simplifies" `analyze_cfg_stream`
//! in a way that changes decompiler block structure, this fails loudly.

use rustre_core::address::Address;
use rustre_il_llil::{LlilExpr, LlilInstruction, Size};

// ── Reference: the original private algorithm, verbatim ──────────────────

struct RefBlocks {
    order: Vec<u64>,
    ends: Vec<u64>,
    successors: Vec<Vec<u32>>,
    predecessors: Vec<Vec<u32>>,
}

fn resolve_const_target(expr: &LlilExpr) -> Option<u64> {
    if let LlilExpr::Const { value, .. } = expr { Some(*value) } else { None }
}

fn reference_build(flat: &[(u64, LlilInstruction)], func_start: u64, func_end: u64) -> RefBlocks {
    let mut starts: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    starts.insert(func_start);
    for (i, (_addr, instr)) in flat.iter().enumerate() {
        if !instr.is_terminator() {
            continue;
        }
        match instr {
            LlilInstruction::CondJump { true_dest, false_dest, .. } => {
                if (func_start..func_end).contains(&true_dest.0) {
                    starts.insert(true_dest.0);
                }
                if (func_start..func_end).contains(&false_dest.0) {
                    starts.insert(false_dest.0);
                }
            }
            LlilInstruction::Jump(dest) | LlilInstruction::JumpDest { dest } => {
                if let Some(target) = resolve_const_target(dest)
                    && (func_start..func_end).contains(&target)
                {
                    starts.insert(target);
                }
            }
            _ => {}
        }
        if let Some((next_addr, _)) = flat.get(i + 1) {
            starts.insert(*next_addr);
        }
    }

    struct RawBlock {
        start: u64,
        ops: Vec<(u64, LlilInstruction)>,
    }
    let mut raw_blocks: Vec<RawBlock> = Vec::new();
    let mut last_addr: Option<u64> = None;
    for (addr, instr) in flat {
        let is_new_addr = last_addr != Some(*addr);
        if raw_blocks.is_empty() || (is_new_addr && starts.contains(addr)) {
            raw_blocks.push(RawBlock { start: *addr, ops: Vec::new() });
        }
        raw_blocks.last_mut().unwrap().ops.push((*addr, instr.clone()));
        last_addr = Some(*addr);
    }

    let block_index_by_start: std::collections::HashMap<u64, usize> =
        raw_blocks.iter().enumerate().map(|(i, b)| (b.start, i)).collect();

    let n = raw_blocks.len();
    let mut successors: Vec<Vec<u32>> = vec![Vec::new(); n];
    for (i, b) in raw_blocks.iter().enumerate() {
        let Some((_, last_instr)) = b.ops.last() else { continue };
        match last_instr {
            LlilInstruction::CondJump { true_dest, false_dest, .. } => {
                if let Some(&t) = block_index_by_start.get(&true_dest.0) {
                    successors[i].push(t as u32);
                }
                if let Some(&f) = block_index_by_start.get(&false_dest.0) {
                    successors[i].push(f as u32);
                }
            }
            LlilInstruction::Jump(dest) | LlilInstruction::JumpDest { dest } => {
                if let Some(target) = resolve_const_target(dest)
                    && let Some(&t) = block_index_by_start.get(&target)
                {
                    successors[i].push(t as u32);
                }
            }
            other if other.is_terminator() => {}
            _ => {
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

    RefBlocks {
        order: raw_blocks.iter().map(|b| b.start).collect(),
        ends: raw_blocks
            .iter()
            .map(|b| b.ops.last().map_or(b.start, |(a, _)| *a + 1))
            .collect(),
        successors,
        predecessors,
    }
}

// ── Comparison harness ───────────────────────────────────────────────────

fn assert_agrees(flat: &[(u64, LlilInstruction)], func_start: u64, func_end: u64, what: &str) {
    let reference = reference_build(flat, func_start, func_end);
    let owned: Vec<(Address, LlilInstruction)> =
        flat.iter().map(|(a, i)| (Address::new(*a), i.clone())).collect();
    let Some(delegated) = rustre_analysis_cfg::analyze_cfg_stream(&owned, func_start, func_end)
    else {
        assert!(reference.order.is_empty(), "{what}: delegation returned None for a non-empty graph");
        return;
    };

    let got_order: Vec<u64> = delegated.order.iter().map(|a| a.0).collect();
    let got_ends: Vec<u64> = delegated.ends.iter().map(|a| a.0).collect();
    assert_eq!(reference.order, got_order, "{what}: block start addresses diverged");
    assert_eq!(reference.ends, got_ends, "{what}: block end addresses diverged");
    assert_eq!(reference.successors, delegated.successors, "{what}: successors diverged");
    assert_eq!(reference.predecessors, delegated.predecessors, "{what}: predecessors diverged");
}

fn c(v: u64) -> LlilExpr {
    LlilExpr::Const { value: v, size: Size::QWord }
}

// ── Hand-shaped cases: one per terminator class ──────────────────────────

#[test]
fn straight_line_no_terminator() {
    let f = vec![(0x1000, LlilInstruction::Nop), (0x1001, LlilInstruction::Nop)];
    assert_agrees(&f, 0x1000, 0x2000, "straight line");
}

#[test]
fn call_splits_the_block() {
    // `Call` IS a terminator for LLIL — the single most common reason the
    // decompiler's block structure differs from a naive jump-only splitter.
    let f = vec![
        (0x1000, LlilInstruction::Nop),
        (0x1001, LlilInstruction::Call(c(0x9000))),
        (0x1002, LlilInstruction::Nop),
        (0x1003, LlilInstruction::Ret),
    ];
    assert_agrees(&f, 0x1000, 0x2000, "call split");
}

#[test]
fn conditional_branch_true_edge_first() {
    let f = vec![
        (0x1000, LlilInstruction::CondJump {
            cond: c(1),
            true_dest: Address::new(0x1002),
            false_dest: Address::new(0x1001),
        }),
        (0x1001, LlilInstruction::Ret),
        (0x1002, LlilInstruction::Ret),
    ];
    assert_agrees(&f, 0x1000, 0x2000, "cond branch");
}

#[test]
fn self_loop_and_back_edge() {
    let f = vec![
        (0x1000, LlilInstruction::Nop),
        (0x1001, LlilInstruction::CondJump {
            cond: c(1),
            true_dest: Address::new(0x1000),
            false_dest: Address::new(0x1002),
        }),
        (0x1002, LlilInstruction::Ret),
    ];
    assert_agrees(&f, 0x1000, 0x2000, "loop");
}

#[test]
fn out_of_range_target_yields_no_edge() {
    let f = vec![
        (0x1000, LlilInstruction::Jump(c(0xDEAD_0000))),
        (0x1001, LlilInstruction::Ret),
    ];
    assert_agrees(&f, 0x1000, 0x2000, "out of range");
}

#[test]
fn indirect_jump_yields_no_edge() {
    let f = vec![
        (0x1000, LlilInstruction::Jump(LlilExpr::Register { id: 3, size: Size::QWord })),
        (0x1001, LlilInstruction::Ret),
    ];
    assert_agrees(&f, 0x1000, 0x2000, "indirect");
}

#[test]
fn multi_op_instruction_never_split_mid_address() {
    // Three LLIL ops sharing one source address, where that address is also a
    // branch target: exactly one block may open, at the first op.
    let f = vec![
        (0x1000, LlilInstruction::CondJump {
            cond: c(1),
            true_dest: Address::new(0x1004),
            false_dest: Address::new(0x1004),
        }),
        (0x1004, LlilInstruction::Nop),
        (0x1004, LlilInstruction::Nop),
        (0x1004, LlilInstruction::Ret),
    ];
    assert_agrees(&f, 0x1000, 0x2000, "multi-op");
}

#[test]
fn descending_address_layout_keeps_stream_order() {
    // Blocks laid out in NON-ascending address order — the case an
    // address-sorted builder would silently re-thread.
    let f = vec![
        (0x1900, LlilInstruction::Jump(c(0x1100))),
        (0x1100, LlilInstruction::Nop),
        (0x1101, LlilInstruction::Ret),
    ];
    assert_agrees(&f, 0x1000, 0x2000, "descending layout");
}

#[test]
fn trap_tailcall_return_all_terminate() {
    let f = vec![
        (0x1000, LlilInstruction::Trap { code: 3 }),
        (0x1001, LlilInstruction::TailCall { dest: c(0x9000) }),
        (0x1002, LlilInstruction::Return { value: None }),
        (0x1003, LlilInstruction::Nop),
    ];
    assert_agrees(&f, 0x1000, 0x2000, "misc terminators");
}

// ── Randomized streams ───────────────────────────────────────────────────

#[test]
fn randomized_streams_agree() {
    let mut state: u64 = 0x243F_6A88_85A3_08D3;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for case in 0..4000u32 {
        let func_start = 0x1000u64;
        let func_end = 0x1000u64 + 64;
        let len = 1 + (next() % 14) as usize;
        let mut flat: Vec<(u64, LlilInstruction)> = Vec::new();
        let mut addr = func_start;
        for _ in 0..len {
            // Sometimes emit several ops at the SAME address.
            if next() % 4 != 0 {
                addr += 1 + next() % 3;
            }
            let target = func_start + next() % 72; // sometimes out of range
            let other = func_start + next() % 72;
            let instr = match next() % 9 {
                0 => LlilInstruction::Nop,
                1 => LlilInstruction::Call(c(target)),
                2 => LlilInstruction::Ret,
                3 => LlilInstruction::Jump(c(target)),
                4 => LlilInstruction::CondJump {
                    cond: c(1),
                    true_dest: Address::new(target),
                    false_dest: Address::new(other),
                },
                5 => LlilInstruction::Trap { code: 3 },
                6 => LlilInstruction::TailCall { dest: c(target) },
                7 => LlilInstruction::Jump(LlilExpr::Register { id: 1, size: Size::QWord }),
                _ => LlilInstruction::Return { value: None },
            };
            flat.push((addr, instr));
        }
        assert_agrees(&flat, func_start, func_end, &format!("random case {case}"));
    }
}
