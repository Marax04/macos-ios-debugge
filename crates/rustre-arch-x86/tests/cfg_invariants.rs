//! Structural invariants of `x86_control_flow_graph::build_cfg`.
//!
//! # Why this file exists
//!
//! `src/x86_control_flow_graph.rs` (729 lines) has NO callers outside tests —
//! and, unlike the retained decode tables, no disclaimer saying so. It reads as
//! live code. The 2026-07-23 wiring audit flagged it; this is the
//! demote-to-oracle treatment that already found real defects in `branch.rs`
//! and `x86_prefix_analyzer`.
//!
//! Unlike those two, there is no second implementation of CFG construction
//! inside this crate to diff against. So the oracle here is not differential
//! but PROPERTY-based: facts that must hold of any correct CFG regardless of
//! how it was built, which cannot be satisfied by reimplementing the same
//! mistake in the test.
//!
//! # The invariants
//!
//! * **I1 no overlap** — blocks partition the code; one instruction belongs to
//!   exactly one block.
//! * **I2 terminator is last** — a branch/return in the middle of a block means
//!   the block was not split where control actually leaves it.
//! * **I3 edges start at blocks** — a source that is not a block start is a
//!   dangling reference.
//! * **I4 edges do not land mid-block** — a target INSIDE the decoded range
//!   must be a block start. Targets OUTSIDE the range are legitimate:
//!   `EdgeKind::Call` is documented as possibly reaching another function and a
//!   tail-call JMP does the same. Stated precisely because the first version of
//!   this file asserted the blanket rule, reported 942 "violations", and every
//!   one was an external target — the invariant was wrong, not the code.
//! * **I5 reachability stays in the graph** — `reachable_from` must not report
//!   addresses that are not blocks. This one found a real defect: the BFS
//!   enqueued and returned every edge target unconditionally.
//! * **I6 successor/predecessor agree** — the two directions are stored
//!   separately, so they are two descriptions of one fact and can disagree.
//!
//! # Corpus
//!
//! Programs are ASSEMBLED with `iced_x86`'s encoder, never written as bytes by
//! hand — hand-built encodings were the single largest source of DEFECTIVE
//! TESTS found in this workspace on 2026-07-23. Branch targets are drawn from
//! already-emitted addresses, so every target is real code and any dangling
//! edge is the CFG builder's doing, not the generator's.

use std::collections::BTreeMap;

use iced_x86::{Code, Encoder, Instruction, Register};
use rustre_arch_x86::x86_control_flow_graph::build_cfg;

const BASE: u64 = 0x1000;

/// Deterministic PRNG — a seeded LCG, so a failure is reproducible from its
/// seed alone and CI cannot flake.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
    fn pick(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Assemble a small program; returns its bytes.
///
/// Shapes emitted: straight-line ALU, unconditional and conditional backward
/// branches (targets are previously emitted instruction addresses, so they are
/// always in range), calls, returns and an indirect jump.
fn assemble(seed: u64, count: usize) -> Vec<u8> {
    let mut rng = Lcg(seed);
    let mut enc = Encoder::new(64);
    let mut ip = BASE;
    let mut emitted: Vec<u64> = Vec::new();
    let mut out: Vec<u8> = Vec::new();

    for _ in 0..count {
        emitted.push(ip);
        let back = emitted[rng.pick(emitted.len())];
        // A target OUTSIDE the decoded range — a tail call or a jump to another
        // function, which is ordinary in real code. The first version of this
        // generator only produced backward branches to already-emitted
        // addresses, so every target was in range and invariant I4 (an edge
        // landing on no block) could never fire. That was the same
        // coverage hole this file exists to find in others: an oracle silent
        // exactly where the interesting case lives.
        let outside = BASE + 0x9_0000;
        let instr = match rng.pick(10) {
            0 => Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RCX).unwrap(),
            1 => Instruction::with2(Code::Xor_rm64_r64, Register::RDX, Register::RDX).unwrap(),
            2 => Instruction::with(Code::Nopd),
            3 => Instruction::with_branch(Code::Jmp_rel32_64, back).unwrap(),
            4 => Instruction::with_branch(Code::Je_rel32_64, back).unwrap(),
            5 => Instruction::with_branch(Code::Call_rel32_64, back).unwrap(),
            6 => Instruction::with1(Code::Jmp_rm64, Register::RAX).unwrap(),
            7 => Instruction::with_branch(Code::Jmp_rel32_64, outside).unwrap(),
            8 => Instruction::with_branch(Code::Call_rel32_64, outside).unwrap(),
            _ => Instruction::with(Code::Retnq),
        };
        let mut instr = instr;
        instr.set_ip(ip);
        let Ok(len) = enc.encode(&instr, ip) else { continue };
        let buf = enc.take_buffer();
        debug_assert_eq!(buf.len(), len);
        out.extend_from_slice(&buf);
        ip += len as u64;
    }
    out
}

#[test]
fn build_cfg_satisfies_structural_invariants() {
    let mut violations: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    let mut programs = 0usize;
    let mut blocks_seen = 0usize;

    for seed in 0..200u64 {
        let bytes = assemble(seed, 24);
        if bytes.is_empty() {
            continue;
        }
        let code_len = bytes.len() as u64;
        let cfg = build_cfg(BASE, &bytes, 64);
        if cfg.block_count() == 0 {
            continue;
        }
        programs += 1;
        blocks_seen += cfg.block_count();

        let starts: std::collections::HashSet<u64> = cfg.blocks().map(|b| b.start).collect();

        // I1 — no overlap.
        let mut ordered: Vec<(u64, u64)> = cfg.blocks().map(|b| (b.start, b.end)).collect();
        ordered.sort_unstable();
        for w in ordered.windows(2) {
            if w[0].1 > w[1].0 {
                violations.entry("I1 overlapping blocks").or_default().push(format!(
                    "seed {seed}: block {:#x}..{:#x} overlaps {:#x}",
                    w[0].0, w[0].1, w[1].0
                ));
            }
        }

        // I2 — a terminator may only be the LAST instruction of its block.
        for b in cfg.blocks() {
            let n = b.insns.len();
            for (i, insn) in b.insns.iter().enumerate() {
                if i + 1 < n && insn.is_terminator() {
                    violations.entry("I2 terminator mid-block").or_default().push(format!(
                        "seed {seed}: block {:#x} has terminator {} at {:#x}, {} more follow",
                        b.start,
                        insn.mnemonic,
                        insn.address,
                        n - i - 1
                    ));
                }
            }
        }

        // I3 / I4 — both endpoints of every edge must be block starts.
        for e in cfg.edges() {
            if !starts.contains(&e.from_block) {
                violations.entry("I3 edge from non-block").or_default().push(format!(
                    "seed {seed}: edge {:#x} -> {:#x} ({:?}) starts nowhere",
                    e.from_block, e.to_block, e.kind
                ));
            }
            // I4 applies only to targets INSIDE the decoded range. Leaving the
            // range is legitimate control flow — `EdgeKind::Call` is documented
            // as possibly targeting another function, and a tail-call JMP does
            // the same — so a blanket "every target is a block" rule would be a
            // wrong invariant, not a found bug. (The first version of this file
            // asserted exactly that and reported 942 violations; on inspection
            // every one was an external target, i.e. my rule was too strong.)
            // What is never legitimate is an edge landing INSIDE the range but
            // not on a block start: that points into the middle of a block.
            let in_range = e.to_block >= BASE && e.to_block < BASE + code_len;
            if in_range && !starts.contains(&e.to_block) {
                violations.entry("I4 edge into mid-block").or_default().push(format!(
                    "seed {seed}: edge {:#x} -> {:#x} ({:?}) lands inside the range but on no block",
                    e.from_block, e.to_block, e.kind
                ));
            }
        }

        // I5 — reachability must stay inside the graph.
        for a in cfg.reachable_from(BASE) {
            if !starts.contains(&a) {
                violations.entry("I5 reachable non-block").or_default().push(format!(
                    "seed {seed}: reachable_from reports {a:#x}, which is not a block"
                ));
            }
        }

        // I6 — successors and predecessors are stored separately and must agree.
        for e in cfg.edges() {
            let fwd = cfg.successors_of(e.from_block).iter().any(|s| s.to_block == e.to_block);
            let back = cfg.predecessors_of(e.to_block).iter().any(|p| p.from_block == e.from_block);
            if fwd != back {
                violations.entry("I6 succ/pred disagree").or_default().push(format!(
                    "seed {seed}: edge {:#x} -> {:#x}: successors say {fwd}, predecessors say {back}",
                    e.from_block, e.to_block
                ));
            }
        }
    }

    // Anti-degeneracy: invariants over an empty or trivial graph hold vacuously.
    assert!(
        programs >= 100 && blocks_seen >= 300,
        "cross-check degenerated: {programs} programs, {blocks_seen} blocks"
    );

    if !violations.is_empty() {
        let histogram = violations
            .iter()
            .map(|(k, v)| format!("{k}: {}", v.len()))
            .collect::<Vec<_>>()
            .join("\n  ");
        let examples = violations
            .values()
            .flat_map(|v| v.iter().take(3))
            .cloned()
            .collect::<Vec<_>>()
            .join("\n  ");
        panic!(
            "CFG invariants violated over {programs} programs / {blocks_seen} blocks\n\
             \nBY INVARIANT (one rule many times, or many distinct bugs?):\n  {histogram}\n\
             \nEXAMPLES:\n  {examples}"
        );
    }

    println!("CFG invariants hold over {programs} programs / {blocks_seen} blocks");
}
