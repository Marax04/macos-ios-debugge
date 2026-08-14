//! Randomised property / oracle tests for ABI-table and inference invariants.
//!
//! Deterministic: every generator is driven by a seeded xorshift64* PRNG
//! declared here (no external dependencies), so a failure is always
//! reproducible from the seed printed in the assertion message.
//!
//! Where a cheap brute-force oracle exists (graph colouring validity, argument
//! index bounds) the property is checked against the oracle rather than against
//! the implementation's own notion of correctness.

#![cfg(test)]

use crate::argument_tracker::{ArgumentTracker, CallSiteInstrExt, CsInstrKind, PassingMechanism};
use crate::cc_database::CcRegistry;
use crate::cc_detector::CcPattern;
use crate::register_colouring::{ChaitinColorer, InterferenceGraph, VReg};
use crate::{
    aapcs32, aapcs64, cdecl_x86, fastcall_x86, mips_o32, msvc_x64, riscv64_lp64d, stdcall_x86,
    sysv_x64, thiscall_x86, vectorcall_x64, CallingConventionPattern,
};
use std::collections::{HashMap, HashSet};

// ─────────────────────────────────────────────────────────────────────────────
// Seeded PRNG (xorshift64*)
// ─────────────────────────────────────────────────────────────────────────────

struct Rng(u64);

impl Rng {
    const fn new(seed: u64) -> Self {
        // Avoid the zero fixed point.
        Self(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed })
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// Uniform-ish in `[0, n)`; `n` must be non-zero.
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % (n as u64)) as usize
    }
    fn chance(&mut self, num: u32, den: u32) -> bool {
        (self.next_u64() % u64::from(den)) < u64::from(num)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The tables under test
// ─────────────────────────────────────────────────────────────────────────────

/// Every hand-written `CallingConventionPattern` constructor in `lib.rs`.
fn all_lib_patterns() -> Vec<CallingConventionPattern> {
    vec![
        sysv_x64(),
        msvc_x64(),
        cdecl_x86(),
        stdcall_x86(),
        fastcall_x86(),
        thiscall_x86(),
        vectorcall_x64(),
        aapcs64(),
        aapcs32(),
        mips_o32(),
        riscv64_lp64d(),
    ]
}

/// Every hand-written `CcPattern` constructor in `cc_detector.rs`.
fn all_detector_patterns() -> Vec<CcPattern> {
    vec![
        CcPattern::sysv_amd64(),
        CcPattern::ms_x64(),
        CcPattern::cdecl_x86(),
        CcPattern::stdcall_x86(),
        CcPattern::thiscall_x86(),
        CcPattern::aapcs64(),
    ]
}

/// Pairs `(lib.rs pattern, cc_detector.rs pattern)` that describe the SAME ABI
/// and therefore must agree on their register sets.
fn cross_table_pairs() -> Vec<(&'static str, CallingConventionPattern, CcPattern)> {
    vec![
        ("sysv_x64", sysv_x64(), CcPattern::sysv_amd64()),
        ("msvc_x64", msvc_x64(), CcPattern::ms_x64()),
        ("cdecl_x86", cdecl_x86(), CcPattern::cdecl_x86()),
        ("stdcall_x86", stdcall_x86(), CcPattern::stdcall_x86()),
        ("thiscall_x86", thiscall_x86(), CcPattern::thiscall_x86()),
        ("aapcs64", aapcs64(), CcPattern::aapcs64()),
    ]
}

/// Map from a `lib.rs` pattern name to the `cc_database.rs` static describing
/// the same ABI, for the entries where both tables exist.
fn db_pairs() -> Vec<(&'static str, CallingConventionPattern, &'static str)> {
    vec![
        ("sysv_x64", sysv_x64(), "sysv_amd64"),
        ("msvc_x64", msvc_x64(), "ms_x64"),
        ("cdecl_x86", cdecl_x86(), "cdecl"),
        ("stdcall_x86", stdcall_x86(), "stdcall"),
        ("fastcall_x86", fastcall_x86(), "fastcall"),
        ("thiscall_x86", thiscall_x86(), "thiscall"),
        ("vectorcall_x64", vectorcall_x64(), "vectorcall"),
        ("aapcs64", aapcs64(), "aapcs64"),
        ("mips_o32", mips_o32(), "mips_o32"),
        ("riscv64_lp64d", riscv64_lp64d(), "riscv64_lp64d"),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// P1 — callee-saved and caller-saved sets are disjoint in every table
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prop_lib_callee_and_caller_saved_are_disjoint() {
    for p in all_lib_patterns() {
        let callee: HashSet<&str> = p.callee_saved.iter().map(String::as_str).collect();
        for r in &p.caller_saved {
            assert!(
                !callee.contains(r.as_str()),
                "{}: register {r} is BOTH callee-saved and caller-saved",
                p.name
            );
        }
    }
}

#[test]
fn prop_detector_callee_and_caller_saved_are_disjoint() {
    for p in all_detector_patterns() {
        let callee: HashSet<&str> = p.callee_saved.iter().map(String::as_str).collect();
        for r in &p.caller_saved {
            assert!(
                !callee.contains(r.as_str()),
                "{}: register {r} is BOTH callee-saved and caller-saved",
                p.name
            );
        }
    }
}

/// Argument registers are volatile across a call by definition, so no argument
/// register may be declared callee-saved.
#[test]
fn prop_arg_registers_are_never_callee_saved() {
    for p in all_lib_patterns() {
        for r in p.arg_registers.iter().chain(p.fp_arg_registers.iter()) {
            assert!(
                !p.callee_saved.contains(r),
                "{}: argument register {r} is also declared callee-saved",
                p.name
            );
        }
    }
    for p in all_detector_patterns() {
        for r in p.arg_regs.iter().chain(p.fp_arg_regs.iter()) {
            assert!(
                !p.callee_saved.contains(r),
                "{}: argument register {r} is also declared callee-saved",
                p.name
            );
        }
    }
}

/// No table may list the same register twice within one role — a duplicate
/// silently shifts every later argument's position.
#[test]
fn prop_no_duplicate_registers_within_a_role() {
    let check = |name: &str, role: &str, regs: &[String]| {
        let mut seen = HashSet::new();
        for r in regs {
            assert!(
                seen.insert(r.as_str()),
                "{name}: duplicate register {r} in {role}"
            );
        }
    };
    for p in all_lib_patterns() {
        check(&p.name, "arg_registers", &p.arg_registers);
        check(&p.name, "fp_arg_registers", &p.fp_arg_registers);
        check(&p.name, "callee_saved", &p.callee_saved);
        check(&p.name, "caller_saved", &p.caller_saved);
        check(&p.name, "retval_registers", &p.retval_registers);
    }
    for p in all_detector_patterns() {
        check(&p.name, "arg_regs", &p.arg_regs);
        check(&p.name, "fp_arg_regs", &p.fp_arg_regs);
        check(&p.name, "callee_saved", &p.callee_saved);
        check(&p.name, "caller_saved", &p.caller_saved);
        check(&p.name, "retval_regs", &p.retval_regs);
    }
}

/// `max_reg_args` must equal the number of integer argument registers actually
/// listed, otherwise `arg_register_at` and arity inference disagree.
#[test]
fn prop_max_reg_args_matches_arg_register_count() {
    for p in all_lib_patterns() {
        assert_eq!(
            p.max_reg_args as usize,
            p.arg_registers.len(),
            "{}: max_reg_args={} but {} arg registers listed",
            p.name,
            p.max_reg_args,
            p.arg_registers.len()
        );
    }
    for p in all_detector_patterns() {
        assert_eq!(
            p.max_reg_args as usize,
            p.arg_regs.len(),
            "{}: max_reg_args={} but {} arg registers listed",
            p.name,
            p.max_reg_args,
            p.arg_regs.len()
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// P2 — the tables agree with each other (exhaustive, no randomness needed)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prop_lib_and_detector_tables_agree() {
    for (label, lib, det) in cross_table_pairs() {
        assert_eq!(
            lib.arg_registers, det.arg_regs,
            "{label}: integer arg registers diverge between lib.rs and cc_detector.rs"
        );
        assert_eq!(
            lib.fp_arg_registers, det.fp_arg_regs,
            "{label}: fp arg registers diverge between lib.rs and cc_detector.rs"
        );
        assert_eq!(
            lib.retval_registers, det.retval_regs,
            "{label}: retval registers diverge between lib.rs and cc_detector.rs"
        );
        let a: HashSet<&String> = lib.callee_saved.iter().collect();
        let b: HashSet<&String> = det.callee_saved.iter().collect();
        assert_eq!(a, b, "{label}: callee-saved sets diverge");
        let a: HashSet<&String> = lib.caller_saved.iter().collect();
        let b: HashSet<&String> = det.caller_saved.iter().collect();
        assert_eq!(a, b, "{label}: caller-saved sets diverge");
        assert_eq!(
            lib.shadow_space_bytes, det.shadow_space,
            "{label}: shadow space diverges"
        );
        assert_eq!(
            lib.stack_alignment, det.stack_alignment,
            "{label}: stack alignment diverges"
        );
        assert_eq!(
            lib.max_reg_args, det.max_reg_args,
            "{label}: max_reg_args diverges"
        );
        assert_eq!(
            lib.hidden_this_ptr, det.has_hidden_this,
            "{label}: hidden-this flag diverges"
        );
        // lib.caller_cleanup == true  <=>  det.callee_cleans_stack == false
        assert_eq!(
            lib.caller_cleanup, !det.callee_cleans_stack,
            "{label}: stack-cleanup responsibility diverges"
        );
    }
}

#[test]
fn prop_lib_and_cc_database_tables_agree() {
    let reg = CcRegistry::full();
    for (label, lib, db_name) in db_pairs() {
        let def = reg
            .get(db_name)
            .unwrap_or_else(|| panic!("{label}: cc_database has no entry named {db_name}"));
        assert_eq!(
            lib.arg_registers, def.int_arg_regs,
            "{label}: integer arg registers diverge between lib.rs and cc_database.rs"
        );
        assert_eq!(
            lib.fp_arg_registers, def.float_arg_regs,
            "{label}: fp arg registers diverge between lib.rs and cc_database.rs"
        );
        let a: HashSet<&str> = lib.callee_saved.iter().map(String::as_str).collect();
        let b: HashSet<&str> = def.callee_saved.iter().copied().collect();
        assert_eq!(a, b, "{label}: callee-saved sets diverge (lib vs cc_database)");
        assert_eq!(
            lib.shadow_space_bytes, def.shadow_space,
            "{label}: shadow space diverges (lib vs cc_database)"
        );
        assert_eq!(
            lib.stack_alignment, def.stack_align,
            "{label}: stack alignment diverges (lib vs cc_database)"
        );
        assert_eq!(
            lib.hidden_this_ptr, def.has_this_ptr,
            "{label}: hidden-this flag diverges (lib vs cc_database)"
        );
        assert_eq!(
            lib.retval_registers.first().map(String::as_str),
            Some(def.int_ret_reg),
            "{label}: primary integer return register diverges (lib vs cc_database)"
        );
    }
}

/// Regression (minimised from `prop_lib_and_cc_database_tables_agree`):
/// AAPCS64's callee-saved set omitted x30 (LR) in `lib.rs::aapcs64()` and
/// `cc_detector.rs::CcPattern::aapcs64()`, while `cc_database.rs::CC_AAPCS64`
/// listed it. Under the omission, the canonical AArch64 prologue
/// `stp x29, x30, [sp, #-16]!` had its x30 save counted as an unexplained
/// register save instead of a callee-save, depressing the AAPCS64 match score.
#[test]
fn regression_aapcs64_lr_x30_is_callee_saved_in_every_table() {
    assert!(
        aapcs64().is_callee_saved("x30"),
        "lib.rs::aapcs64(): x30 (LR) must be callee-saved"
    );
    assert!(
        CcPattern::aapcs64().is_callee_saved("x30"),
        "cc_detector.rs::CcPattern::aapcs64(): x30 (LR) must be callee-saved"
    );
    let reg = CcRegistry::full();
    assert!(
        reg.get("aapcs64").unwrap().is_callee_saved("x30"),
        "cc_database.rs::CC_AAPCS64: x30 (LR) must be callee-saved"
    );
    // And it must not simultaneously be caller-saved.
    assert!(!aapcs64().caller_saved.iter().any(|r| r == "x30"));
    assert!(!CcPattern::aapcs64().caller_saved.iter().any(|r| r == "x30"));
}

// ─────────────────────────────────────────────────────────────────────────────
// P3 — register classification is self-consistent under random probing
// ─────────────────────────────────────────────────────────────────────────────

/// For 2000 random (pattern, register) probes, the predicate methods must agree
/// with a brute-force scan of the underlying vectors, and `arg_register_at`
/// must never return an index at or beyond the ABI arity.
#[test]
fn prop_register_predicates_match_brute_force_oracle() {
    const SEED: u64 = 0x00AB_1CAF_1234_5678;
    let mut rng = Rng::new(SEED);
    let pats = all_lib_patterns();

    // A vocabulary of plausible register names drawn from every table, plus
    // some names that belong to no convention at all.
    let mut vocab: Vec<String> = Vec::new();
    for p in &pats {
        for r in p
            .arg_registers
            .iter()
            .chain(&p.fp_arg_registers)
            .chain(&p.callee_saved)
            .chain(&p.caller_saved)
            .chain(&p.retval_registers)
        {
            vocab.push(r.clone());
        }
    }
    vocab.extend(["zz0".into(), "".into(), "RDI".into(), "rdi ".into()]);

    for trial in 0..2000 {
        let p = &pats[rng.below(pats.len())];
        let reg = &vocab[rng.below(vocab.len())];

        // Oracle: brute-force membership.
        let oracle_arg =
            p.arg_registers.iter().any(|r| r == reg) || p.fp_arg_registers.iter().any(|r| r == reg);
        let oracle_callee = p.callee_saved.iter().any(|r| r == reg);
        let oracle_ret = p.retval_registers.iter().any(|r| r == reg);

        assert_eq!(
            p.is_arg_register(reg),
            oracle_arg,
            "seed={SEED:#x} trial={trial}: is_arg_register({reg}) disagrees with oracle for {}",
            p.name
        );
        assert_eq!(
            p.is_callee_saved(reg),
            oracle_callee,
            "seed={SEED:#x} trial={trial}: is_callee_saved({reg}) disagrees with oracle for {}",
            p.name
        );
        assert_eq!(
            p.is_retval_register(reg),
            oracle_ret,
            "seed={SEED:#x} trial={trial}: is_retval_register({reg}) disagrees with oracle for {}",
            p.name
        );

        // arg_register_at must be Some exactly below the arity and never above.
        let n = rng.below(32);
        let got = p.arg_register_at(n);
        assert_eq!(
            got.is_some(),
            n < p.arg_register_count(),
            "seed={SEED:#x} trial={trial}: arg_register_at({n}) presence disagrees with \
             arg_register_count()={} for {}",
            p.arg_register_count(),
            p.name
        );
        assert_eq!(
            p.arg_register_count(),
            p.max_reg_args as usize,
            "{}: arity disagrees with max_reg_args",
            p.name
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// P4 — argument-list construction never exceeds the ABI arity
// ─────────────────────────────────────────────────────────────────────────────

/// Build random pre-call instruction windows and assert that every REGISTER
/// argument produced carries an index strictly below the convention's integer
/// argument-register count. A register argument at index >= arity would be a
/// phantom parameter — exactly the failure mode that fooled the recompilability
/// metric in the sibling decompiler crate.
#[test]
fn prop_argument_indices_never_exceed_abi_arity() {
    const SEED: u64 = 0x0BAD_5EED_0000_0001;
    let mut rng = Rng::new(SEED);
    let pats = all_lib_patterns();

    for trial in 0..1000 {
        let cc = pats[rng.below(pats.len())].clone();
        let arity = cc.arg_registers.len();
        let bits = if rng.chance(1, 2) { 32 } else { 64 };
        let tracker = ArgumentTracker::new(cc.clone(), bits);

        // Vocabulary: this convention's registers plus foreign ones.
        let mut names: Vec<String> = cc.arg_registers.clone();
        names.extend(cc.fp_arg_registers.clone());
        names.extend(cc.caller_saved.clone());
        names.push("zz0".into());

        let len = rng.below(12);
        let mut instrs = Vec::with_capacity(len);
        for i in 0..len {
            let dst = names[rng.below(names.len())].clone();
            let src = names[rng.below(names.len())].clone();
            let kind = match rng.below(6) {
                0 => CsInstrKind::MovRegImm {
                    dst,
                    imm: rng.next_u64() as i64,
                },
                1 => CsInstrKind::MovRegReg { dst, src },
                2 => CsInstrKind::Lea {
                    dst,
                    offset: (rng.next_u64() % 4096) as i64,
                },
                3 => CsInstrKind::Push { reg: src },
                4 => CsInstrKind::Xor {
                    dst: dst.clone(),
                    src: dst,
                },
                _ => CsInstrKind::RegWrite { reg: dst },
            };
            instrs.push(CallSiteInstrExt {
                address: 0x1000 + i as u64,
                kind,
            });
        }

        let result = tracker.analyze_call_site(&instrs);
        for a in result.arguments.iter() {
            if matches!(a.mechanism, PassingMechanism::Register { .. }) {
                assert!(
                    a.index < arity.max(1),
                    "seed={SEED:#x} trial={trial}: register argument index {} >= ABI arity {} \
                     for {} (instrs={instrs:?})",
                    a.index,
                    arity,
                    cc.name
                );
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// P5 — Chaitin colouring produces a VALID colouring, and is deterministic
// ─────────────────────────────────────────────────────────────────────────────

/// Generate random interference graphs and check the colouring against a
/// brute-force oracle: for every edge (a, b) where BOTH endpoints received a
/// colour, those colours must differ. Also check that no colour exceeds k-1 and
/// that `colors_used` bounds the palette actually used.
#[test]
fn prop_chaitin_colouring_is_valid() {
    const SEED: u64 = 0x00C0_1030_DEAD_BEEF;
    let mut rng = Rng::new(SEED);

    for trial in 0..800 {
        let n = 1 + rng.below(14);
        let k = 1 + rng.below(6);
        let mut ig = InterferenceGraph::new();
        for i in 0..n {
            ig.add_register(VReg(i as u32));
        }
        let mut edges: Vec<(VReg, VReg)> = Vec::new();
        for a in 0..n {
            for b in (a + 1)..n {
                if rng.chance(1, 3) {
                    ig.add_edge(VReg(a as u32), VReg(b as u32));
                    edges.push((VReg(a as u32), VReg(b as u32)));
                }
            }
        }

        let res = ChaitinColorer::new(k).color(&ig);

        // Oracle: no two adjacent coloured nodes share a colour.
        for &(a, b) in &edges {
            if let (Some(ca), Some(cb)) = (res.color_of(a), res.color_of(b)) {
                assert_ne!(
                    ca, cb,
                    "seed={SEED:#x} trial={trial}: invalid colouring — interfering {a:?} and \
                     {b:?} both got colour {ca} (n={n}, k={k}, edges={edges:?})"
                );
            }
        }

        // Every assigned colour is inside the palette.
        for i in 0..n {
            if let Some(c) = res.color_of(VReg(i as u32)) {
                assert!(
                    (c as usize) < k,
                    "seed={SEED:#x} trial={trial}: colour {c} outside palette k={k}"
                );
            }
        }

        // colors_used must bound the distinct colours actually handed out.
        let distinct: HashSet<u32> = (0..n)
            .filter_map(|i| res.color_of(VReg(i as u32)))
            .collect();
        let max_used = distinct.iter().copied().max().map_or(0, |m| m as usize + 1);
        assert_eq!(
            res.colors_used, max_used,
            "seed={SEED:#x} trial={trial}: colors_used={} but highest colour implies {max_used}",
            res.colors_used
        );

        // Uncoloured set is exactly the complement of the coloured set.
        let uncoloured: HashSet<VReg> = res.uncolored.iter().copied().collect();
        for i in 0..n {
            let v = VReg(i as u32);
            assert_eq!(
                uncoloured.contains(&v),
                res.color_of(v).is_none(),
                "seed={SEED:#x} trial={trial}: {v:?} membership in `uncolored` disagrees with \
                 color_of()"
            );
        }
    }
}

/// The colouring must be reproducible: the same graph, coloured repeatedly and
/// built with the insertion order permuted, must yield the same assignment.
/// (`InterferenceGraph` is backed by hash sets, so this is the property that
/// hash-iteration-order nondeterminism would break.)
#[test]
fn prop_chaitin_colouring_is_deterministic() {
    const SEED: u64 = 0x00DE_7E12_0000_0007;
    let mut rng = Rng::new(SEED);

    for trial in 0..500 {
        let n = 1 + rng.below(12);
        let k = 1 + rng.below(5);
        let mut edges: Vec<(u32, u32)> = Vec::new();
        for a in 0..n {
            for b in (a + 1)..n {
                if rng.chance(2, 5) {
                    edges.push((a as u32, b as u32));
                }
            }
        }

        let build = |order: &[usize], edge_order: &[usize]| {
            let mut ig = InterferenceGraph::new();
            for &i in order {
                ig.add_register(VReg(i as u32));
            }
            for &e in edge_order {
                let (a, b) = edges[e];
                ig.add_edge(VReg(a), VReg(b));
            }
            ChaitinColorer::new(k).color(&ig)
        };

        let fwd: Vec<usize> = (0..n).collect();
        let fwd_e: Vec<usize> = (0..edges.len()).collect();
        let rev: Vec<usize> = (0..n).rev().collect();
        let rev_e: Vec<usize> = (0..edges.len()).rev().collect();

        let a = build(&fwd, &fwd_e);
        let b = build(&fwd, &fwd_e);
        let c = build(&rev, &rev_e);

        let snap = |r: &crate::register_colouring::ColoringResult| {
            let mut m: Vec<(u32, u32)> =
                r.colors.iter().map(|(v, c)| (v.0, *c)).collect::<Vec<_>>();
            m.sort_unstable();
            (m, r.colors_used, r.uncolored.clone())
        };

        assert_eq!(
            snap(&a),
            snap(&b),
            "seed={SEED:#x} trial={trial}: repeated colouring of the same graph differed \
             (n={n}, k={k})"
        );
        assert_eq!(
            snap(&a),
            snap(&c),
            "seed={SEED:#x} trial={trial}: colouring depends on insertion order \
             (n={n}, k={k}, edges={edges:?})"
        );
    }
}

/// Colouring a graph with no edges must use at most one colour per the greedy
/// rule (every node can take colour 0) — a cheap sanity oracle that catches a
/// palette-allocation regression.
#[test]
fn prop_edgeless_graph_uses_single_colour() {
    const SEED: u64 = 0x0E06_E1E5_0000_0001;
    let mut rng = Rng::new(SEED);
    for trial in 0..200 {
        let n = 1 + rng.below(20);
        let k = 1 + rng.below(4);
        let mut ig = InterferenceGraph::new();
        for i in 0..n {
            ig.add_register(VReg(i as u32));
        }
        let res = ChaitinColorer::new(k).color(&ig);
        for i in 0..n {
            assert_eq!(
                res.color_of(VReg(i as u32)),
                Some(0),
                "seed={SEED:#x} trial={trial}: edgeless graph gave a non-zero colour"
            );
        }
        assert_eq!(res.colors_used, 1);
        assert!(res.uncolored.is_empty());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// P6 — CallingConventionDetector::{detect, detect_with_hints} are functions of
//      the candidate SET, not of the order it is presented in
//
// `detect_with_hints` is the crate's most-consumed inference entry point: it is
// what `rustre-decompiler`'s `callconv_bridge.rs` calls for every function it
// decompiles. It had only hand-written example tests.
//
// The oracle is DEFINITIONAL, not a mirror of the scorer: "return the single
// best-matching convention among the candidates, or an error" says nothing
// about the order the candidates arrive in, so permuting the slice must not
// change the verdict. This is exactly the property that first-wins `>` /
// `tie` bookkeeping and `sort_unstable_by` (which does NOT preserve the input
// order of equal-scoring candidates) can violate — and a wrong-but-confident
// convention is precisely the failure mode that compiles cleanly and silently
// destroys signature fidelity.
//
//   O1 membership  — a returned pattern is one of the candidates supplied.
//   O2 order-free  — permuting the candidate slice cannot change the verdict.
//   O3 duplicates  — the same candidate listed twice describes the same set.
//   O4 degenerate  — an empty candidate slice is always an error.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn prop_detector_verdict_is_order_free_and_returns_a_candidate() {
    use crate::{CallConvError, CallingConventionDetector, ObservedPattern};

    const SEED: u64 = 0x0DEC_7EC7_0000_0001;
    let mut rng = Rng::new(SEED);

    let pool = all_lib_patterns();
    // Registers spanning several ABIs, plus names belonging to none.
    let regs = [
        "rdi", "rsi", "rdx", "rcx", "r8", "r9", "ecx", "edx", "eax", "rbx", "rbp", "r12", "x0",
        "x1", "zz0", "",
    ];
    let fpregs = ["xmm0", "xmm1", "xmm2", "d0", "f12", "zz1"];

    // Coverage counters — the test must fail if any interesting shape dries up.
    let mut cov_ok = 0usize;
    let mut cov_nomatch = 0usize;
    let mut cov_ambiguous = 0usize;
    let mut cov_empty_cands = 0usize;
    let mut cov_single_cand = 0usize;
    let mut cov_dup = 0usize;
    let mut cov_thisptr = 0usize;
    let mut cov_shadow = 0usize;
    let mut cov_calleepop = 0usize;
    let mut cov_no_evidence = 0usize;

    let label = |r: &Result<CallingConventionPattern, CallConvError>| match r {
        Ok(p) => p.name.clone(),
        Err(CallConvError::NoMatch) => "<NoMatch>".to_string(),
        Err(e) => format!("<{e:?}>"),
    };

    for trial in 0..1200 {
        // ── candidate set: 0..=len, sometimes with a deliberate duplicate ──
        let n_cand = rng.below(pool.len() + 1);
        let mut cands: Vec<CallingConventionPattern> = Vec::with_capacity(n_cand + 1);
        for _ in 0..n_cand {
            cands.push(pool[rng.below(pool.len())].clone());
        }
        if rng.chance(1, 5) && !cands.is_empty() {
            let d = cands[rng.below(cands.len())].clone(); // O3
            cands.push(d);
            cov_dup += 1;
        }
        if cands.is_empty() {
            cov_empty_cands += 1;
        }
        if cands.len() == 1 {
            cov_single_cand += 1;
        }

        // ── observed evidence, including the all-empty (no evidence) shape ──
        let mut obs = ObservedPattern::new();
        if rng.chance(1, 8) {
            cov_no_evidence += 1; // leave everything default
        } else {
            for _ in 0..rng.below(5) {
                obs.read_before_write
                    .push(regs[rng.below(regs.len())].to_string());
            }
            for _ in 0..rng.below(3) {
                obs.fp_read_before_write
                    .push(fpregs[rng.below(fpregs.len())].to_string());
            }
            for _ in 0..rng.below(4) {
                obs.saved_registers
                    .push(regs[rng.below(regs.len())].to_string());
            }
            for _ in 0..rng.below(3) {
                obs.written_before_return
                    .push(regs[rng.below(regs.len())].to_string());
            }
            if rng.chance(1, 3) {
                obs.callee_pops_stack = true;
                obs.callee_stack_pop = 4 * (1 + rng.below(8)) as u32;
                cov_calleepop += 1;
            }
            if rng.chance(1, 3) {
                obs.this_ptr_hint = true;
                cov_thisptr += 1;
            }
            if rng.chance(1, 3) {
                obs.shadow_space_observed = true;
                cov_shadow += 1;
            }
            obs.max_stack_frame = (rng.below(4) * 32) as u32;
            obs.stack_arg_count = rng.below(4) as u32;
        }

        let base_detect = CallingConventionDetector::detect(&obs, &cands);
        let base_hints = CallingConventionDetector::detect_with_hints(&obs, &cands);

        match &base_hints {
            Ok(_) => cov_ok += 1,
            Err(CallConvError::Ambiguous) => cov_ambiguous += 1,
            Err(_) => cov_nomatch += 1,
        }

        // O4 — no candidates ⇒ never a verdict.
        if cands.is_empty() {
            assert!(
                base_detect.is_err() && base_hints.is_err(),
                "seed={SEED:#x} trial={trial}: empty candidate list produced a verdict"
            );
        }

        // O1 — membership.
        for (which, r) in [("detect", &base_detect), ("detect_with_hints", &base_hints)] {
            if let Ok(p) = r {
                assert!(
                    cands.iter().any(|c| c.name == p.name),
                    "seed={SEED:#x} trial={trial}: {which} returned {} which is not among the \
                     candidates {:?}",
                    p.name,
                    cands.iter().map(|c| &c.name).collect::<Vec<_>>()
                );
            }
        }

        // O2/O3 — the verdict is a function of the candidate SET.
        for perm in 0..4 {
            let mut shuffled = cands.clone();
            for i in (1..shuffled.len()).rev() {
                let j = rng.below(i + 1);
                shuffled.swap(i, j);
            }
            assert_eq!(
                label(&base_detect),
                label(&CallingConventionDetector::detect(&obs, &shuffled)),
                "seed={SEED:#x} trial={trial} perm={perm}: detect() verdict depends on candidate \
                 ORDER (candidates={:?}, permuted={:?}, observed={obs:?})",
                cands.iter().map(|c| &c.name).collect::<Vec<_>>(),
                shuffled.iter().map(|c| &c.name).collect::<Vec<_>>()
            );
            assert_eq!(
                label(&base_hints),
                label(&CallingConventionDetector::detect_with_hints(&obs, &shuffled)),
                "seed={SEED:#x} trial={trial} perm={perm}: detect_with_hints() verdict depends on \
                 candidate ORDER (candidates={:?}, permuted={:?}, observed={obs:?})",
                cands.iter().map(|c| &c.name).collect::<Vec<_>>(),
                shuffled.iter().map(|c| &c.name).collect::<Vec<_>>()
            );
        }
    }

    // Generator-coverage assertions: if any of these dry up the property above
    // is no longer exercising what its name claims.
    assert!(cov_ok > 50, "generator never produced a decisive verdict ({cov_ok})");
    assert!(
        cov_nomatch + cov_ambiguous > 50,
        "generator never produced an undecided verdict ({cov_nomatch} nomatch, {cov_ambiguous} ambiguous)"
    );
    assert!(cov_empty_cands > 10, "generator never produced an empty candidate set");
    assert!(cov_single_cand > 10, "generator never produced a singleton candidate set");
    assert!(cov_dup > 20, "generator never produced a duplicated candidate");
    assert!(cov_thisptr > 20, "generator never produced a this-ptr hint");
    assert!(cov_shadow > 20, "generator never produced a shadow-space hint");
    assert!(cov_calleepop > 20, "generator never produced callee stack cleanup");
    assert!(cov_no_evidence > 20, "generator never produced an evidence-free observation");
}

/// `InterferenceGraph::interferes` must agree with a brute-force adjacency set,
/// symmetrically, and `degree` must equal the neighbour count.
#[test]
fn prop_interference_graph_matches_oracle() {
    const SEED: u64 = 0x0117_E2FE_0000_0003;
    let mut rng = Rng::new(SEED);

    for trial in 0..500 {
        let n = 1 + rng.below(16);
        let mut ig = InterferenceGraph::new();
        let mut oracle: HashMap<u32, HashSet<u32>> = HashMap::new();
        for i in 0..n {
            ig.add_register(VReg(i as u32));
            oracle.entry(i as u32).or_default();
        }
        for _ in 0..(2 * n) {
            let a = rng.below(n) as u32;
            let b = rng.below(n) as u32;
            ig.add_edge(VReg(a), VReg(b));
            if a != b {
                oracle.entry(a).or_default().insert(b);
                oracle.entry(b).or_default().insert(a);
            }
        }
        for a in 0..n as u32 {
            for b in 0..n as u32 {
                let expect = oracle[&a].contains(&b);
                assert_eq!(
                    ig.interferes(VReg(a), VReg(b)),
                    expect,
                    "seed={SEED:#x} trial={trial}: interferes({a},{b}) disagrees with oracle"
                );
                assert_eq!(
                    ig.interferes(VReg(a), VReg(b)),
                    ig.interferes(VReg(b), VReg(a)),
                    "seed={SEED:#x} trial={trial}: interferes is not symmetric for ({a},{b})"
                );
            }
            assert_eq!(
                ig.degree(VReg(a)),
                oracle[&a].len(),
                "seed={SEED:#x} trial={trial}: degree({a}) disagrees with oracle"
            );
        }
    }
}
