//! Static analysis passes on lifted x86 IR.
//!
//! This module operates directly on `Vec<LiftedInstr>` (the output of the
//! lifter) without ascending to MLIL. Its analyses are used by:
//!
//!   * The lifter's own test suite (verify that flag definitions and uses
//!     are consistent).
//!   * `rustre-analysis-cfg` to seed the CFG with liveness information
//!     before SSA construction.
//!   * The MLIL lifting pass to eliminate dead flag assignments.
//!
//! All analyses are **intra-procedural** over a flat instruction stream. For
//! interprocedural or loop-aware analysis, see `rustre-il-mlil`.

use crate::{Effect, IrExpr, LiftLevel, LiftedInstr};
use std::collections::{BTreeMap, HashMap, HashSet};

// ─────────────────────────────────────────────────────────────────────────────
// Register use / def
// ─────────────────────────────────────────────────────────────────────────────

/// One entry in the def-use chain: identifies the instruction and the
/// specific `Effect` index within it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DefUseRef {
    /// Address of the instruction.
    pub instr_addr: u64,
    /// Index of the effect within `LiftedInstr::effects`.
    pub effect_idx: usize,
}

/// Def-use information for a single register name.
#[derive(Debug, Clone, Default)]
pub struct RegDefUse {
    /// All points where this register is written (defined).
    pub defs: Vec<DefUseRef>,
    /// All points where this register is read (used).
    pub uses: Vec<DefUseRef>,
}

impl RegDefUse {
    /// `true` if there are no definitions of this register.
    #[must_use]
    pub const fn has_def(&self) -> bool {
        !self.defs.is_empty()
    }

    /// `true` if there are no uses of this register after any definition.
    #[must_use]
    pub const fn is_dead_after_def(&self) -> bool {
        self.has_def() && self.uses.is_empty()
    }

    /// `true` if the register is read before it is ever written (potential UB
    /// or an input register / global state dependency).
    #[must_use]
    pub fn is_used_before_def(&self, instrs: &[LiftedInstr]) -> bool {
        // Build address-to-index map for ordering.
        let order: HashMap<u64, usize> = instrs
            .iter()
            .enumerate()
            .map(|(i, li)| (li.address, i))
            .collect();
        let first_def = self
            .defs
            .iter()
            .map(|d| *order.get(&d.instr_addr).unwrap_or(&usize::MAX))
            .min();
        let first_use = self
            .uses
            .iter()
            .map(|u| *order.get(&u.instr_addr).unwrap_or(&usize::MAX))
            .min();
        match (first_use, first_def) {
            (Some(u), Some(d)) => u < d,
            (Some(_), None) => true,
            _ => false,
        }
    }
}

/// Build a complete def-use map for all registers in the given instruction
/// stream. Temporaries (`__t*`) are included but can be filtered afterwards.
#[must_use]
pub fn build_def_use_map(instrs: &[LiftedInstr]) -> HashMap<String, RegDefUse> {
    // Heuristic: assume ~4 distinct registers touched per instruction on average.
    let mut map: HashMap<String, RegDefUse> = HashMap::with_capacity(instrs.len() * 4);

    for li in instrs {
        for (eff_idx, eff) in li.effects.iter().enumerate() {
            let site = DefUseRef {
                instr_addr: li.address,
                effect_idx: eff_idx,
            };

            // Definitions (writes).
            for reg in eff.written_registers() {
                map.entry(reg).or_default().defs.push(site.clone());
            }
            // Uses (reads).
            for reg in eff.read_registers() {
                map.entry(reg).or_default().uses.push(site.clone());
            }
            // For IrExpr trees embedded in effects, recursively collect reads.
            collect_expr_reads_from_effect(eff, &site, &mut map);
        }
    }
    map
}

/// Collect all register *reads* that appear in expression trees within `eff`,
/// including those nested inside address computations and branch conditions.
fn collect_expr_reads_from_effect(
    eff: &Effect,
    site: &DefUseRef,
    map: &mut HashMap<String, RegDefUse>,
) {
    match eff {
        Effect::RegWrite { value, .. } => collect_expr_reads(value, site, map),
        Effect::MemWrite { addr, value, .. } => {
            collect_expr_reads(addr, site, map);
            collect_expr_reads(value, site, map);
        }
        Effect::MemRead { addr, .. } => collect_expr_reads(addr, site, map),
        Effect::Call { target } => collect_expr_reads(target, site, map),
        Effect::Branch { target, condition } => {
            collect_expr_reads(target, site, map);
            if let Some(c) = condition {
                collect_expr_reads(c, site, map);
            }
        }
        Effect::Return { value } => {
            if let Some(v) = value {
                collect_expr_reads(v, site, map);
            }
        }
        Effect::Syscall { nr } => collect_expr_reads(nr, site, map),
        Effect::Intrinsic { args, .. } => {
            for a in args {
                collect_expr_reads(a, site, map);
            }
        }
        Effect::Trap { .. } | Effect::NoReturn => {}
        Effect::ConditionalTrap { condition, .. } => collect_expr_reads(condition, site, map),
        }
}

fn collect_expr_reads(expr: &IrExpr, site: &DefUseRef, map: &mut HashMap<String, RegDefUse>) {
    collect_expr_reads_inner(expr, site, map, 1024);
}

fn collect_expr_reads_inner(
    expr: &IrExpr,
    site: &DefUseRef,
    map: &mut HashMap<String, RegDefUse>,
    depth_remaining: usize,
) {
    if depth_remaining == 0 {
        return;
    }
    match expr {
        IrExpr::Reg(name) => {
            map.entry(name.clone()).or_default().uses.push(site.clone());
        }
        IrExpr::Const(_) | IrExpr::Undef => {}
        IrExpr::Not(e) | IrExpr::Deref(e, _) | IrExpr::CmpEqZero(e) | IrExpr::Parity(e) => {
            collect_expr_reads_inner(e, site, map, depth_remaining - 1);
        }
        IrExpr::Add(l, r)
        | IrExpr::Sub(l, r)
        | IrExpr::Mul(l, r)
        | IrExpr::And(l, r)
        | IrExpr::Or(l, r)
        | IrExpr::Xor(l, r)
        | IrExpr::Shl(l, r)
        | IrExpr::Shr(l, r)
        | IrExpr::Sar(l, r)
        | IrExpr::CmpEq(l, r)
        | IrExpr::CmpLt(l, r)
        | IrExpr::CmpLtU(l, r)
        | IrExpr::CmpGt(l, r)
        | IrExpr::Eq(l, r)
        | IrExpr::Ne(l, r) => {
            collect_expr_reads_inner(l, site, map, depth_remaining - 1);
            collect_expr_reads_inner(r, site, map, depth_remaining - 1);
        }
        IrExpr::IfThenElse(c, t, e) => {
            collect_expr_reads_inner(c, site, map, depth_remaining - 1);
            collect_expr_reads_inner(t, site, map, depth_remaining - 1);
            collect_expr_reads_inner(e, site, map, depth_remaining - 1);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Flag liveness
// ─────────────────────────────────────────────────────────────────────────────

/// The six architectural x86 flags tracked by the lifter.
pub const X86_FLAGS: [&str; 6] = ["cf", "pf", "af", "zf", "sf", "of"];
/// Direction and interrupt flags — relevant for specific analysis passes.
pub const X86_CTRL_FLAGS: [&str; 2] = ["df", "if"];

/// Liveness information for a single flag at a specific program point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagLiveness {
    /// Flag is live (may be read by a future instruction).
    Live,
    /// Flag is dead (no future instruction reads it before the next write).
    Dead,
    /// Cannot determine liveness (non-linear CFG, indirect branch, etc.).
    Unknown,
}

/// Per-flag liveness at each instruction in a linear block.
/// Outer key: instruction address. Inner key: flag name.
pub type FlagLivenessMap = BTreeMap<u64, HashMap<&'static str, FlagLiveness>>;

/// Compute a backward liveness pass over a flat, linear instruction stream.
///
/// This is the standard textbook liveness analysis assuming no branches lead
/// back into the stream (i.e., no loops). For loops, feed a fixed-point
/// solver on top.
#[must_use]
pub fn compute_flag_liveness(instrs: &[LiftedInstr]) -> FlagLivenessMap {
    let mut map = FlagLivenessMap::new();

    // Seed: all flags unknown at exit.
    let mut live: HashMap<&'static str, FlagLiveness> = X86_FLAGS
        .iter()
        .map(|&f| (f, FlagLiveness::Unknown))
        .collect();

    // Backward pass.
    for li in instrs.iter().rev() {
        // Before applying this instruction's effects, record the live set.
        map.insert(li.address, live.clone());

        // Check what flags are USED in this instruction's effects.
        for &flag in &X86_FLAGS {
            let uses_flag = li
                .effects
                .iter()
                .any(|e| e.read_registers().contains(&flag.to_string()));
            if uses_flag {
                live.insert(flag, FlagLiveness::Live);
            }
        }

        // Check what flags are DEFINED in this instruction's effects.
        for &flag in &X86_FLAGS {
            let defs_flag = li
                .effects
                .iter()
                .any(|e| e.written_registers().contains(&flag.to_string()));
            if defs_flag {
                // After definition, the prior live status is killed.
                live.insert(flag, FlagLiveness::Dead);
            }
        }
    }

    map
}

/// Returns the set of flag-write effects in `instr` that are dead (the
/// written flag is not read by any later instruction in `suffix`).
///
/// `suffix` is the slice of instructions that follow `instr` in program order.
#[must_use]
pub fn dead_flag_writes(instr: &LiftedInstr, suffix: &[LiftedInstr]) -> Vec<usize> {
    // Collect which flags are read anywhere in the suffix.
    let mut read_flags: HashSet<String> = HashSet::new();
    for li in suffix {
        for reg in li.read_registers() {
            read_flags.insert(reg);
        }
        // If there's a branch or call, conservatively assume all flags live.
        if li.is_terminator() {
            return vec![];
        }
    }

    let mut dead_idxs = Vec::new();
    for (idx, eff) in instr.effects.iter().enumerate() {
        if let Effect::RegWrite { reg, .. } = eff
            && X86_FLAGS.contains(&reg.as_str()) && !read_flags.contains(reg.as_str()) {
                dead_idxs.push(idx);
            }
    }
    dead_idxs
}

// ─────────────────────────────────────────────────────────────────────────────
// Effect classification
// ─────────────────────────────────────────────────────────────────────────────

/// Broad category for an `Effect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectClass {
    /// Register arithmetic / data movement.
    RegArith,
    /// Flag write.
    FlagWrite,
    /// Memory load.
    MemLoad,
    /// Memory store.
    MemStore,
    /// Control-flow transfer (branch, call, return).
    ControlFlow,
    /// Syscall / interrupt.
    Syscall,
    /// Opaque intrinsic.
    Intrinsic,
}

impl EffectClass {
    /// Classify a single `Effect`.
    #[must_use]
    pub fn of(eff: &Effect) -> Self {
        match eff {
            Effect::RegWrite { reg, .. } => {
                if X86_FLAGS.contains(&reg.as_str()) || X86_CTRL_FLAGS.contains(&reg.as_str()) {
                    Self::FlagWrite
                } else {
                    Self::RegArith
                }
            }
            Effect::MemRead { .. } => Self::MemLoad,
            Effect::MemWrite { .. } => Self::MemStore,
            Effect::Branch { .. } | Effect::Call { .. } | Effect::Return { .. } => {
                Self::ControlFlow
            }
            Effect::Syscall { .. } => Self::Syscall,
            Effect::Intrinsic { .. } => Self::Intrinsic,
            Effect::Trap { .. } | Effect::ConditionalTrap { .. } | Effect::NoReturn => Self::ControlFlow,
            }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Per-instruction-stream statistics: counts of each `EffectClass`.
#[derive(Debug, Clone, Default)]
pub struct StreamStats {
    pub reg_arith_count: u64,
    pub flag_write_count: u64,
    pub mem_load_count: u64,
    pub mem_store_count: u64,
    pub control_flow_count: u64,
    pub syscall_count: u64,
    pub intrinsic_count: u64,
    pub total_instructions: u64,
    pub total_effects: u64,
    pub unimplemented_count: u64,
}

impl StreamStats {
    #[must_use]
    pub fn from_instrs(instrs: &[LiftedInstr]) -> Self {
        let mut s = Self {
            total_instructions: instrs.len() as u64,
            ..Self::default()
        };
        for li in instrs {
            if li.il_level == LiftLevel::Raw {
                s.unimplemented_count += 1;
            }
            for eff in &li.effects {
                s.total_effects += 1;
                match EffectClass::of(eff) {
                    EffectClass::RegArith => s.reg_arith_count += 1,
                    EffectClass::FlagWrite => s.flag_write_count += 1,
                    EffectClass::MemLoad => s.mem_load_count += 1,
                    EffectClass::MemStore => s.mem_store_count += 1,
                    EffectClass::ControlFlow => s.control_flow_count += 1,
                    EffectClass::Syscall => s.syscall_count += 1,
                    EffectClass::Intrinsic => s.intrinsic_count += 1,
                }
            }
        }
        s
    }

    /// Fraction of instructions that are fully lifted (not unimplemented).
    #[must_use]
    pub fn coverage(&self) -> f64 {
        if self.total_instructions == 0 {
            return 1.0;
        }
        1.0 - (f64::from(u32::try_from(self.unimplemented_count).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.total_instructions).unwrap_or(u32::MAX)))
    }

    /// Average number of effects (μOps) per instruction.
    #[must_use]
    pub fn avg_effects_per_instr(&self) -> f64 {
        if self.total_instructions == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.total_effects).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.total_instructions).unwrap_or(u32::MAX))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Intrinsic census
// ─────────────────────────────────────────────────────────────────────────────

/// Count how many times each intrinsic name appears in the stream.
#[must_use]
pub fn intrinsic_census(instrs: &[LiftedInstr]) -> BTreeMap<String, u64> {
    let mut census: BTreeMap<String, u64> = BTreeMap::new();
    for li in instrs {
        for eff in &li.effects {
            if let Effect::Intrinsic { name, .. } = eff {
                *census.entry(name.clone()).or_insert(0) += 1;
            }
        }
    }
    census
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory access pattern analyser
// ─────────────────────────────────────────────────────────────────────────────

/// A single memory access (load or store) recorded in the stream.
#[derive(Debug, Clone)]
pub struct MemAccess {
    pub instr_addr: u64,
    pub is_write: bool,
    pub size: u8,
    pub addr_expr: IrExpr,
}

/// Collect all memory accesses in the stream.
#[must_use]
pub fn collect_mem_accesses(instrs: &[LiftedInstr]) -> Vec<MemAccess> {
    let mut accesses = Vec::with_capacity(instrs.len());
    for li in instrs {
        for eff in &li.effects {
            match eff {
                Effect::MemRead { addr, size, .. } => accesses.push(MemAccess {
                    instr_addr: li.address,
                    is_write: false,
                    size: *size,
                    addr_expr: addr.clone(),
                }),
                Effect::MemWrite { addr, size, .. } => accesses.push(MemAccess {
                    instr_addr: li.address,
                    is_write: true,
                    size: *size,
                    addr_expr: addr.clone(),
                }),
                _ => {}
            }
        }
    }
    accesses
}

// ─────────────────────────────────────────────────────────────────────────────
// Call-site extractor
// ─────────────────────────────────────────────────────────────────────────────

/// A call-site extracted from the instruction stream.
#[derive(Debug, Clone)]
pub struct CallSite {
    /// Address of the CALL instruction.
    pub instr_addr: u64,
    /// Target expression from `Effect::Call`.
    pub target: IrExpr,
    /// `true` if the target is a concrete constant address.
    pub is_direct: bool,
}

/// Extract all call sites from the stream.
#[must_use]
pub fn extract_call_sites(instrs: &[LiftedInstr]) -> Vec<CallSite> {
    let mut sites = Vec::new();
    for li in instrs {
        for eff in &li.effects {
            if let Effect::Call { target } = eff {
                let is_direct = matches!(target, IrExpr::Const(_));
                sites.push(CallSite {
                    instr_addr: li.address,
                    target: target.clone(),
                    is_direct,
                });
            }
        }
    }
    sites
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Effect, IrExpr, LiftLevel, LiftedInstr};

    fn make_instr(addr: u64, effects: Vec<Effect>) -> LiftedInstr {
        LiftedInstr {
            address: addr,
            original_mnemonic: "test".into(),
            ir_text: "test".into(),
            il_level: LiftLevel::Llil,
            effects,
        }
    }

    // ── EffectClass ─────────────────────────────────────────────────────────

    #[test]
    fn classify_reg_write() {
        let e = Effect::RegWrite {
            reg: "rax".into(),
            value: IrExpr::Const(0),
        };
        assert_eq!(EffectClass::of(&e), EffectClass::RegArith);
    }

    #[test]
    fn classify_flag_write() {
        let e = Effect::RegWrite {
            reg: "zf".into(),
            value: IrExpr::Const(1),
        };
        assert_eq!(EffectClass::of(&e), EffectClass::FlagWrite);
    }

    #[test]
    fn classify_cf_write() {
        let e = Effect::RegWrite {
            reg: "cf".into(),
            value: IrExpr::Undef,
        };
        assert_eq!(EffectClass::of(&e), EffectClass::FlagWrite);
    }

    #[test]
    fn classify_mem_read() {
        let e = Effect::MemRead {
            addr: IrExpr::Const(0),
            dest: "rax".into(),
            size: 8,
        };
        assert_eq!(EffectClass::of(&e), EffectClass::MemLoad);
    }

    #[test]
    fn classify_mem_write() {
        let e = Effect::MemWrite {
            addr: IrExpr::Const(0),
            value: IrExpr::Const(1),
            size: 4,
        };
        assert_eq!(EffectClass::of(&e), EffectClass::MemStore);
    }

    #[test]
    fn classify_branch() {
        let e = Effect::Branch {
            target: IrExpr::Const(0x0040_1000),
            condition: None,
        };
        assert_eq!(EffectClass::of(&e), EffectClass::ControlFlow);
    }

    #[test]
    fn classify_intrinsic() {
        let e = Effect::Intrinsic {
            name: "x86.cpuid".into(),
            args: vec![],
        };
        assert_eq!(EffectClass::of(&e), EffectClass::Intrinsic);
    }

    // ── StreamStats ─────────────────────────────────────────────────────────

    #[test]
    fn stats_empty_stream() {
        let s = StreamStats::from_instrs(&[]);
        assert_eq!(s.total_instructions, 0);
        assert_eq!(s.total_effects, 0);
        assert!((s.coverage() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn stats_counts_effects() {
        let instrs = vec![
            make_instr(
                0x1000,
                vec![
                    Effect::RegWrite {
                        reg: "rax".into(),
                        value: IrExpr::Const(0),
                    },
                    Effect::RegWrite {
                        reg: "zf".into(),
                        value: IrExpr::Const(0),
                    },
                ],
            ),
            make_instr(
                0x1002,
                vec![Effect::MemRead {
                    addr: IrExpr::Const(0),
                    dest: "rbx".into(),
                    size: 8,
                }],
            ),
        ];
        let s = StreamStats::from_instrs(&instrs);
        assert_eq!(s.total_instructions, 2);
        assert_eq!(s.total_effects, 3);
        assert_eq!(s.reg_arith_count, 1);
        assert_eq!(s.flag_write_count, 1);
        assert_eq!(s.mem_load_count, 1);
    }

    #[test]
    fn stats_avg_effects() {
        let instrs = vec![make_instr(
            0x1000,
            vec![
                Effect::RegWrite {
                    reg: "rax".into(),
                    value: IrExpr::Const(0),
                },
                Effect::RegWrite {
                    reg: "rbx".into(),
                    value: IrExpr::Const(0),
                },
            ],
        )];
        let s = StreamStats::from_instrs(&instrs);
        assert!((s.avg_effects_per_instr() - 2.0).abs() < 1e-9);
    }

    // ── Def-use map ─────────────────────────────────────────────────────────

    #[test]
    fn def_use_single_write() {
        let instrs = vec![make_instr(
            0x1000,
            vec![Effect::RegWrite {
                reg: "rax".into(),
                value: IrExpr::Const(1),
            }],
        )];
        let map = build_def_use_map(&instrs);
        assert!(map.contains_key("rax"));
        assert_eq!(map["rax"].defs.len(), 1);
    }

    #[test]
    fn def_use_chain() {
        let instrs = vec![
            make_instr(
                0x1000,
                vec![Effect::RegWrite {
                    reg: "rax".into(),
                    value: IrExpr::Const(5),
                }],
            ),
            make_instr(
                0x1002,
                vec![Effect::RegWrite {
                    reg: "rbx".into(),
                    value: IrExpr::Add(
                        Box::new(IrExpr::Reg("rax".into())),
                        Box::new(IrExpr::Const(1)),
                    ),
                }],
            ),
        ];
        let map = build_def_use_map(&instrs);
        // rax should have 1 def and at least 1 use.
        assert_eq!(map["rax"].defs.len(), 1);
        assert!(!map["rax"].uses.is_empty());
    }

    // ── Call site extraction ─────────────────────────────────────────────────

    #[test]
    fn extract_direct_call() {
        let instrs = vec![make_instr(
            0x2000,
            vec![Effect::Call {
                target: IrExpr::Const(0x0040_1000),
            }],
        )];
        let sites = extract_call_sites(&instrs);
        assert_eq!(sites.len(), 1);
        assert!(sites[0].is_direct);
        assert_eq!(sites[0].instr_addr, 0x2000);
    }

    #[test]
    fn extract_indirect_call() {
        let instrs = vec![make_instr(
            0x3000,
            vec![Effect::Call {
                target: IrExpr::Reg("rax".into()),
            }],
        )];
        let sites = extract_call_sites(&instrs);
        assert_eq!(sites.len(), 1);
        assert!(!sites[0].is_direct);
    }

    // ── Memory access collection ─────────────────────────────────────────────

    #[test]
    fn collect_mem_store() {
        let instrs = vec![make_instr(
            0x4000,
            vec![Effect::MemWrite {
                addr: IrExpr::Const(0x8000),
                value: IrExpr::Const(0),
                size: 4,
            }],
        )];
        let accesses = collect_mem_accesses(&instrs);
        assert_eq!(accesses.len(), 1);
        assert!(accesses[0].is_write);
        assert_eq!(accesses[0].size, 4);
    }

    #[test]
    fn collect_mem_load() {
        let instrs = vec![make_instr(
            0x5000,
            vec![Effect::MemRead {
                addr: IrExpr::Const(0x9000),
                dest: "rax".into(),
                size: 8,
            }],
        )];
        let accesses = collect_mem_accesses(&instrs);
        assert_eq!(accesses.len(), 1);
        assert!(!accesses[0].is_write);
        assert_eq!(accesses[0].size, 8);
    }

    // ── Intrinsic census ─────────────────────────────────────────────────────

    #[test]
    fn intrinsic_census_counts() {
        let instrs = vec![make_instr(
            0x6000,
            vec![
                Effect::Intrinsic {
                    name: "x86.cpuid".into(),
                    args: vec![],
                },
                Effect::Intrinsic {
                    name: "x86.cpuid".into(),
                    args: vec![],
                },
                Effect::Intrinsic {
                    name: "x86.rdtsc".into(),
                    args: vec![],
                },
            ],
        )];
        let census = intrinsic_census(&instrs);
        assert_eq!(census["x86.cpuid"], 2);
        assert_eq!(census["x86.rdtsc"], 1);
    }

    // ── Dead flag detection ──────────────────────────────────────────────────

    #[test]
    fn dead_flag_zf_when_not_read() {
        let instr = make_instr(
            0x7000,
            vec![
                Effect::RegWrite {
                    reg: "rax".into(),
                    value: IrExpr::Const(0),
                },
                Effect::RegWrite {
                    reg: "zf".into(),
                    value: IrExpr::Const(0),
                },
            ],
        );
        // suffix with no flag reads
        let suffix = vec![make_instr(
            0x7002,
            vec![Effect::RegWrite {
                reg: "rbx".into(),
                value: IrExpr::Const(0),
            }],
        )];
        let dead = dead_flag_writes(&instr, &suffix);
        // effect index 1 (zf write) should be dead
        assert!(
            dead.contains(&1),
            "expected zf write at idx 1 to be dead, got: {dead:?}"
        );
    }

    #[test]
    fn flag_not_dead_if_read() {
        let instr = make_instr(
            0x8000,
            vec![Effect::RegWrite {
                reg: "zf".into(),
                value: IrExpr::Const(1),
            }],
        );
        let suffix = vec![make_instr(
            0x8002,
            vec![Effect::Branch {
                target: IrExpr::Const(0x0040_1000),
                condition: Some(IrExpr::Reg("zf".into())),
            }],
        )];
        let dead = dead_flag_writes(&instr, &suffix);
        assert!(dead.is_empty(), "zf should be live");
    }
}
