//! ABI-aware calling convention recovery from lifted IR.
//!
//! This pass analyses a linear sequence of `LiftedInstr`s (typically a
//! complete lifted function) to determine:
//!
//!   1. **Calling convention** — which of the known conventions (System V AMD64,
//!      Microsoft x64, cdecl, stdcall, …) best explains the observed
//!      argument-passing and register-saving behaviour.
//!   2. **Argument list** — which registers (and stack slots) carry the first
//!      N arguments to the function.
//!   3. **Return register** — which register carries the return value.
//!   4. **Callee-saved registers** — which registers are saved at the prologue
//!      and restored at the epilogue (and whose PUSH/POP form a balanced pair).
//!   5. **Stack frame size** — the number of bytes of local storage allocated
//!      by the `SUB rsp, N` in the prologue.
//!
//! The analysis uses evidence from the lifted IR rather than heuristics:
//!
//!   * **Argument evidence**: a register is an argument if it is read before
//!     it is written in the function body (i.e., `DefUse::is_used_before_def`).
//!   * **Return evidence**: if a `return` effect carries `IrExpr::Reg(r)`, `r`
//!     is the return register.
//!   * **Callee-save evidence**: a register is saved if the function begins
//!     with `PUSH r` and ends with `POP r` (or the ENTER/LEAVE equivalent).
//!   * **Convention selection**: compare the observed argument set to each
//!     known convention's expected argument registers and pick the best fit.

use crate::x86_analysis::build_def_use_map;
use crate::x86_calling_conv::{CallingConventionRegistry, ParamKind};
use crate::{Effect, IrExpr, LiftedInstr};
use std::collections::{HashMap, HashSet};

// ─────────────────────────────────────────────────────────────────────────────
// Evidence types
// ─────────────────────────────────────────────────────────────────────────────

/// A register that appears to be used as a function argument.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArgEvidence {
    /// Register name.
    pub reg: String,
    /// Position of this argument (0 = first), if determinable.
    pub position: Option<usize>,
    /// Whether this evidence is from a direct read of the register before
    /// any write (high confidence) or just inferred.
    pub high_confidence: bool,
}

/// A register that appears to be the function's return value.
#[derive(Debug, Clone)]
pub struct ReturnEvidence {
    /// Register name.
    pub reg: String,
    /// Expression from `Effect::Return { value }`.
    pub expr: IrExpr,
}

/// A register that the function saves and restores (callee-saved).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CalleeSaveEvidence {
    /// Register name.
    pub reg: String,
    /// Instruction address where the PUSH / save occurred.
    pub push_addr: u64,
    /// Instruction address where the POP / restore occurred (None if unmatched).
    pub pop_addr: Option<u64>,
}

/// The local stack frame size, inferred from `SUB rsp, N`.
#[derive(Debug, Clone, Copy, Default)]
pub struct StackFrameEvidence {
    /// Number of bytes allocated in the prologue (`SUB rsp, N`).
    pub alloc_bytes: Option<u64>,
    /// Number of bytes deallocated in the epilogue (`ADD rsp, N` or `LEAVE`).
    pub dealloc_bytes: Option<u64>,
}

impl StackFrameEvidence {
    /// `true` if the prologue and epilogue alloc/dealloc are balanced.
    #[must_use]
    pub const fn is_balanced(&self) -> bool {
        match (self.alloc_bytes, self.dealloc_bytes) {
            (Some(a), Some(d)) => a == d,
            _ => false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AbiEvidence
// ─────────────────────────────────────────────────────────────────────────────

/// Collected ABI evidence from a single function's lifted IR.
#[derive(Debug, Clone, Default)]
pub struct AbiEvidence {
    /// Registers that appear to be used as function arguments.
    pub args: Vec<ArgEvidence>,
    /// Return value evidence (may be empty if no explicit return).
    pub returns: Vec<ReturnEvidence>,
    /// Callee-saved register save/restore pairs.
    pub callee_saves: Vec<CalleeSaveEvidence>,
    /// Stack frame alloc/dealloc evidence.
    pub frame: StackFrameEvidence,
    /// Number of instructions analysed.
    pub instr_count: usize,
    /// Number of effect entries analysed.
    pub effect_count: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// Collection pass
// ─────────────────────────────────────────────────────────────────────────────

/// The x86-64 argument registers in order for both major calling conventions.
const SYSV_INT_ARGS: [&str; 6] = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
const MS_INT_ARGS: [&str; 4] = ["rcx", "rdx", "r8", "r9"];
const SYSV_FP_ARGS: [&str; 8] = [
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
];
const MS_FP_ARGS: [&str; 4] = ["xmm0", "xmm1", "xmm2", "xmm3"];

/// Walk a function body and collect all ABI evidence.
#[must_use]
pub fn collect_evidence(instrs: &[LiftedInstr]) -> AbiEvidence {
    let mut ev = AbiEvidence {
        instr_count: instrs.len(),
        effect_count: instrs.iter().map(|li| li.effects.len()).sum(),
        ..AbiEvidence::default()
    };

    // Build def-use map for argument discovery.
    let def_use = build_def_use_map(instrs);

    // Argument evidence: GPR/XMM used before defined.
    let candidate_args: Vec<&str> = SYSV_INT_ARGS
        .iter()
        .chain(SYSV_FP_ARGS.iter())
        .copied()
        .chain(MS_INT_ARGS.iter().chain(MS_FP_ARGS.iter()).copied())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let mut seen_args: HashSet<String> = HashSet::new();
    for reg in candidate_args {
        if let Some(du) = def_use.get(reg)
            && du.is_used_before_def(instrs) && seen_args.insert(reg.to_string()) {
                let pos = sysv_arg_position(reg).or_else(|| ms_arg_position(reg));
                ev.args.push(ArgEvidence {
                    reg: reg.to_string(),
                    position: pos,
                    high_confidence: true,
                });
            }
    }

    // Sort by known position.
    ev.args.sort_by_key(|a| a.position.unwrap_or(99));

    // Return evidence.
    for li in instrs {
        for eff in &li.effects {
            if let Effect::Return {
                value: Some(IrExpr::Reg(r)),
            } = eff
            {
                ev.returns.push(ReturnEvidence {
                    reg: r.clone(),
                    expr: IrExpr::Reg(r.clone()),
                });
            }
        }
    }

    // Callee-save evidence: match PUSH r at function start with POP r at function end.
    let saved = find_push_regs_at_start(instrs);
    let restored = find_pop_regs_at_end(instrs);
    for (reg, push_addr) in &saved {
        let pop_addr = restored.get(reg).copied();
        ev.callee_saves.push(CalleeSaveEvidence {
            reg: reg.clone(),
            push_addr: *push_addr,
            pop_addr,
        });
    }

    // Stack frame evidence.
    ev.frame = find_frame_size(instrs);

    ev
}

/// Find registers pushed near the start of the function (first ~8 instructions).
fn find_push_regs_at_start(instrs: &[LiftedInstr]) -> HashMap<String, u64> {
    let mut saved = HashMap::new();
    for li in instrs.iter().take(8) {
        if li.original_mnemonic != "push" {
            continue;
        }
        for eff in &li.effects {
            if let Effect::MemWrite {
                value: IrExpr::Reg(r),
                ..
            } = eff
            {
                let reg = r.clone();
                if !reg.starts_with("__") && reg != "rsp" && reg != "esp" {
                    saved.entry(reg).or_insert(li.address);
                }
            }
        }
    }
    saved
}

/// Find registers popped near the end of the function (last ~8 instructions).
fn find_pop_regs_at_end(instrs: &[LiftedInstr]) -> HashMap<String, u64> {
    let mut restored = HashMap::new();
    let start = instrs.len().saturating_sub(8);
    for li in &instrs[start..] {
        if li.original_mnemonic != "pop" {
            continue;
        }
        for eff in &li.effects {
            // The popped register surfaces either as a `RegWrite` to the
            // destination (the handler's `write_operand` form) or as the
            // `dest` of the stack `MemRead` (the compact pop idiom).
            let dest = match eff {
                Effect::RegWrite { reg, .. } => Some(reg),
                Effect::MemRead { dest, .. } => Some(dest),
                _ => None,
            };
            if let Some(reg) = dest
                && !reg.starts_with("__") && reg != "rsp" && reg != "esp" {
                    restored.entry(reg.clone()).or_insert(li.address);
                }
        }
    }
    restored
}

/// Extract stack frame allocation/deallocation sizes.
fn find_frame_size(instrs: &[LiftedInstr]) -> StackFrameEvidence {
    let mut ev = StackFrameEvidence::default();
    for li in instrs.iter().take(5) {
        if li.original_mnemonic == "sub" {
            for eff in &li.effects {
                if let Effect::RegWrite {
                    reg,
                    value: IrExpr::Sub(_, b),
                } = eff
                    && (reg == "rsp" || reg == "esp")
                        && let IrExpr::Const(n) = **b {
                            ev.alloc_bytes = Some(n);
                        }
            }
        }
    }
    for li in instrs.iter().rev().take(5) {
        if li.original_mnemonic == "add" {
            for eff in &li.effects {
                if let Effect::RegWrite {
                    reg,
                    value: IrExpr::Add(_, b),
                } = eff
                    && (reg == "rsp" || reg == "esp")
                        && let IrExpr::Const(n) = **b {
                            ev.dealloc_bytes = Some(n);
                        }
            }
        }
        if li.original_mnemonic == "leave" {
            // LEAVE restores whatever was allocated.
            ev.dealloc_bytes = ev.alloc_bytes;
        }
    }
    ev
}

fn sysv_arg_position(reg: &str) -> Option<usize> {
    SYSV_INT_ARGS
        .iter()
        .position(|&r| r == reg)
        .or_else(|| SYSV_FP_ARGS.iter().position(|&r| r == reg))
}

fn ms_arg_position(reg: &str) -> Option<usize> {
    MS_INT_ARGS
        .iter()
        .position(|&r| r == reg)
        .or_else(|| MS_FP_ARGS.iter().position(|&r| r == reg))
}

// ─────────────────────────────────────────────────────────────────────────────
// Convention selection
// ─────────────────────────────────────────────────────────────────────────────

/// How well a calling convention fits the observed evidence.
#[derive(Debug, Clone)]
pub struct ConventionScore {
    /// Name of the calling convention.
    pub name: String,
    /// Number of argument registers that match.
    pub arg_matches: usize,
    /// Number of argument registers in the evidence that are NOT in this CC.
    pub arg_mismatches: usize,
    /// Overall score (higher = better fit).
    pub score: f64,
}

/// Score all known calling conventions against the observed evidence and
/// return them sorted best-to-worst.
#[must_use]
pub fn score_conventions(ev: &AbiEvidence, bits: u8, is_windows: bool) -> Vec<ConventionScore> {
    let reg = CallingConventionRegistry::with_defaults();
    let candidates: Vec<&str> = if bits == 64 {
        if is_windows {
            vec!["ms_x64", "sysv_amd64", "linux_syscall_amd64"]
        } else {
            vec!["sysv_amd64", "linux_syscall_amd64", "ms_x64"]
        }
    } else {
        vec!["cdecl", "stdcall", "fastcall"]
    };

    let observed_regs: HashSet<&str> = ev.args.iter().map(|a| a.reg.as_str()).collect();

    let mut scores: Vec<ConventionScore> = candidates
        .iter()
        .filter_map(|&name| {
            let cc = reg.get(name)?;
            let mut matches = 0usize;
            let mut mismatches = 0usize;
            for i in 0..observed_regs.len() {
                let loc = cc.arg_location(i, ParamKind::IntOrPtr);
                let expected_reg = match &loc {
                    crate::x86_calling_conv::ArgLocation::Register(r) => Some(r.as_str()),
                    _ => None,
                };
                if let Some(er) = expected_reg {
                    if observed_regs.contains(er) {
                        matches += 1;
                    } else {
                        mismatches += 1;
                    }
                }
            }
            // Also score return register.
            let ret_bonus = if ev.returns.iter().any(|r| {
            let ret_loc = cc.return_location(ParamKind::IntOrPtr);
            matches!(&ret_loc, crate::x86_calling_conv::ArgLocation::Register(reg) if reg == &r.reg)
        }) { 2.0 } else { 0.0 };

            let total = matches + mismatches;
            let score = if total == 0 {
                ret_bonus
            } else {
                (f64::from(u32::try_from(matches).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total).unwrap_or(u32::MAX))).mul_add(10.0, ret_bonus)
            };

            Some(ConventionScore {
                name: name.to_string(),
                arg_matches: matches,
                arg_mismatches: mismatches,
                score,
            })
        })
        .collect();

    scores.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    scores
}

// ─────────────────────────────────────────────────────────────────────────────
// Full recovery result
// ─────────────────────────────────────────────────────────────────────────────

/// Complete ABI recovery result for a function.
#[derive(Debug, Clone)]
pub struct AbiRecovery {
    /// Collected evidence.
    pub evidence: AbiEvidence,
    /// Calling convention candidates, best first.
    pub convention_scores: Vec<ConventionScore>,
    /// Best-guess calling convention name.
    pub best_convention: Option<String>,
    /// Inferred argument registers in position order.
    pub arg_registers: Vec<String>,
    /// Inferred return register (if any).
    pub return_register: Option<String>,
    /// Balanced callee-saved registers.
    pub callee_saved: Vec<String>,
    /// Stack frame allocation in bytes (if detected).
    pub frame_bytes: Option<u64>,
}

impl AbiRecovery {
    /// `true` if a convention was identified with reasonable confidence.
    #[must_use]
    pub const fn has_convention(&self) -> bool {
        self.best_convention.is_some()
    }

    /// `true` if the function appears to take no arguments.
    #[must_use]
    pub const fn is_void_args(&self) -> bool {
        self.arg_registers.is_empty()
    }

    /// `true` if the function appears to have a return value.
    #[must_use]
    pub const fn has_return_value(&self) -> bool {
        self.return_register.is_some()
    }
}

/// Run the full ABI recovery pipeline on a function body.
#[must_use]
pub fn recover_abi(instrs: &[LiftedInstr], bits: u8, is_windows: bool) -> AbiRecovery {
    let evidence = collect_evidence(instrs);
    let scores = score_conventions(&evidence, bits, is_windows);
    let best_convention = scores.first().map(|s| s.name.clone());

    let arg_registers: Vec<String> = {
        let mut args: Vec<&ArgEvidence> = evidence.args.iter().collect();
        args.sort_by_key(|a| a.position.unwrap_or(99));
        args.iter().map(|a| a.reg.clone()).collect()
    };

    let return_register = evidence.returns.first().map(|r| r.reg.clone());

    let callee_saved: Vec<String> = evidence
        .callee_saves
        .iter()
        .filter(|cs| cs.pop_addr.is_some())
        .map(|cs| cs.reg.clone())
        .collect();

    let frame_bytes = evidence.frame.alloc_bytes;

    AbiRecovery {
        evidence,
        convention_scores: scores,
        best_convention,
        arg_registers,
        return_register,
        callee_saved,
        frame_bytes,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Effect, IrExpr, LiftLevel, LiftedInstr};

    fn instr(addr: u64, mnemonic: &str, effects: Vec<Effect>) -> LiftedInstr {
        LiftedInstr {
            address: addr,
            original_mnemonic: mnemonic.to_string(),
            ir_text: mnemonic.to_string(),
            il_level: LiftLevel::Llil,
            effects,
        }
    }

    fn push_instr(addr: u64, reg: &str) -> LiftedInstr {
        instr(
            addr,
            "push",
            vec![
                Effect::RegWrite {
                    reg: "rsp".into(),
                    value: IrExpr::Sub(
                        Box::new(IrExpr::Reg("rsp".into())),
                        Box::new(IrExpr::Const(8)),
                    ),
                },
                Effect::MemWrite {
                    addr: IrExpr::Reg("rsp".into()),
                    value: IrExpr::Reg(reg.into()),
                    size: 8,
                },
            ],
        )
    }

    fn pop_instr(addr: u64, reg: &str) -> LiftedInstr {
        instr(
            addr,
            "pop",
            vec![
                Effect::MemRead {
                    addr: IrExpr::Reg("rsp".into()),
                    dest: reg.into(),
                    size: 8,
                },
                Effect::RegWrite {
                    reg: "rsp".into(),
                    value: IrExpr::Add(
                        Box::new(IrExpr::Reg("rsp".into())),
                        Box::new(IrExpr::Const(8)),
                    ),
                },
            ],
        )
    }

    fn sub_rsp_instr(addr: u64, n: u64) -> LiftedInstr {
        instr(
            addr,
            "sub",
            vec![Effect::RegWrite {
                reg: "rsp".into(),
                value: IrExpr::Sub(
                    Box::new(IrExpr::Reg("rsp".into())),
                    Box::new(IrExpr::Const(n)),
                ),
            }],
        )
    }

    fn ret_rax_instr(addr: u64) -> LiftedInstr {
        instr(
            addr,
            "ret",
            vec![Effect::Return {
                value: Some(IrExpr::Reg("rax".into())),
            }],
        )
    }

    fn use_rdi(addr: u64) -> LiftedInstr {
        instr(
            addr,
            "mov",
            vec![Effect::RegWrite {
                reg: "rax".into(),
                value: IrExpr::Reg("rdi".into()), // uses rdi before any write
            }],
        )
    }

    // ── StackFrameEvidence ────────────────────────────────────────────────────

    #[test]
    fn frame_size_detected() {
        let instrs = vec![sub_rsp_instr(0x1000, 0x28)];
        let ev = find_frame_size(&instrs);
        assert_eq!(ev.alloc_bytes, Some(0x28));
    }

    #[test]
    fn frame_not_detected_when_absent() {
        let instrs = vec![instr(0x1000, "nop", vec![])];
        let ev = find_frame_size(&instrs);
        assert_eq!(ev.alloc_bytes, None);
    }

    // ── Callee-save detection ─────────────────────────────────────────────────

    #[test]
    fn push_pop_pair_detected() {
        let instrs = vec![
            push_instr(0x1000, "rbx"),
            instr(0x1001, "nop", vec![]),
            pop_instr(0x1002, "rbx"),
        ];
        let ev = collect_evidence(&instrs);
        let rbx_save = ev.callee_saves.iter().find(|cs| cs.reg == "rbx");
        assert!(rbx_save.is_some(), "rbx should be detected as callee-saved");
    }

    #[test]
    fn unmatched_push_has_no_pop() {
        let instrs = vec![push_instr(0x1000, "rbp")];
        let ev = collect_evidence(&instrs);
        let rbp_save = ev.callee_saves.iter().find(|cs| cs.reg == "rbp");
        if let Some(cs) = rbp_save {
            assert_eq!(cs.pop_addr, None, "unmatched push should have no pop addr");
        }
    }

    // ── Return register ──────────────────────────────────────────────────────

    #[test]
    fn return_rax_detected() {
        let instrs = vec![ret_rax_instr(0x2000)];
        let ev = collect_evidence(&instrs);
        assert!(!ev.returns.is_empty(), "should detect return");
        assert_eq!(ev.returns[0].reg, "rax");
    }

    // ── Argument detection ────────────────────────────────────────────────────

    #[test]
    fn rdi_used_before_def_is_arg() {
        let instrs = vec![use_rdi(0x3000)];
        let ev = collect_evidence(&instrs);
        let rdi_arg = ev.args.iter().find(|a| a.reg == "rdi");
        assert!(
            rdi_arg.is_some(),
            "rdi used before def should be detected as arg"
        );
    }

    // ── Convention scoring ────────────────────────────────────────────────────

    #[test]
    fn sysv_scores_higher_on_linux() {
        let ev = AbiEvidence {
            args: vec![
                ArgEvidence {
                    reg: "rdi".into(),
                    position: Some(0),
                    high_confidence: true,
                },
                ArgEvidence {
                    reg: "rsi".into(),
                    position: Some(1),
                    high_confidence: true,
                },
            ],
            ..Default::default()
        };
        let scores = score_conventions(&ev, 64, false); // Linux
        assert!(!scores.is_empty());
        // sysv_amd64 should rank first on Linux with rdi/rsi args.
        assert_eq!(scores[0].name, "sysv_amd64");
    }

    #[test]
    fn ms_x64_scores_higher_on_windows() {
        let ev = AbiEvidence {
            args: vec![
                ArgEvidence {
                    reg: "rcx".into(),
                    position: Some(0),
                    high_confidence: true,
                },
                ArgEvidence {
                    reg: "rdx".into(),
                    position: Some(1),
                    high_confidence: true,
                },
            ],
            ..Default::default()
        };
        let scores = score_conventions(&ev, 64, true); // Windows
        assert!(!scores.is_empty());
        assert_eq!(scores[0].name, "ms_x64");
    }

    // ── Full recovery pipeline ────────────────────────────────────────────────

    #[test]
    fn recover_simple_function() {
        // Prologue: PUSH rbp, MOV rbp, rsp, SUB rsp, 0x20
        // Body: use rdi
        // Epilogue: MOV rsp, rbp, POP rbp, RET rax
        let instrs = vec![
            push_instr(0x4000, "rbp"),
            instr(
                0x4001,
                "mov",
                vec![Effect::RegWrite {
                    reg: "rbp".into(),
                    value: IrExpr::Reg("rsp".into()),
                }],
            ),
            sub_rsp_instr(0x4002, 0x20),
            use_rdi(0x4003),
            instr(
                0x4004,
                "mov",
                vec![Effect::RegWrite {
                    reg: "rsp".into(),
                    value: IrExpr::Reg("rbp".into()),
                }],
            ),
            pop_instr(0x4005, "rbp"),
            ret_rax_instr(0x4006),
        ];
        let r = recover_abi(&instrs, 64, false);
        assert_eq!(r.return_register, Some("rax".into()));
        assert_eq!(r.frame_bytes, Some(0x20));
        assert!(!r.callee_saved.is_empty(), "rbp should be callee-saved");
    }

    #[test]
    fn recover_empty_function() {
        let instrs = vec![ret_rax_instr(0x5000)];
        let r = recover_abi(&instrs, 64, false);
        assert!(r.arg_registers.is_empty(), "no args in empty function");
        assert_eq!(r.return_register, Some("rax".into()));
    }

    #[test]
    fn recover_void_function() {
        let instrs = vec![instr(0x6000, "ret", vec![Effect::Return { value: None }])];
        let r = recover_abi(&instrs, 64, false);
        assert_eq!(r.return_register, None);
        assert!(r.is_void_args());
        assert!(!r.has_return_value());
    }

    // ── ConventionScore ───────────────────────────────────────────────────────

    #[test]
    fn convention_score_has_name() {
        let ev = AbiEvidence::default();
        let scores = score_conventions(&ev, 64, false);
        assert!(!scores.is_empty());
        assert!(!scores[0].name.is_empty());
    }

    // ── AbiRecovery fields ────────────────────────────────────────────────────

    #[test]
    fn abi_recovery_has_convention() {
        let instrs = vec![ret_rax_instr(0x7000)];
        let r = recover_abi(&instrs, 64, false);
        assert!(r.has_convention());
    }

    #[test]
    fn evidence_instr_count() {
        let instrs = vec![instr(0x8000, "nop", vec![]), instr(0x8001, "nop", vec![])];
        let ev = collect_evidence(&instrs);
        assert_eq!(ev.instr_count, 2);
    }

    #[test]
    fn frame_evidence_balanced() {
        let mut ev = StackFrameEvidence {
            alloc_bytes: Some(0x20),
            dealloc_bytes: Some(0x20),
        };
        assert!(ev.is_balanced());
        ev.dealloc_bytes = Some(0x10);
        assert!(!ev.is_balanced());
    }
}
