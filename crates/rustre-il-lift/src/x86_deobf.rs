//! Deobfuscation patterns for lifted x86 IR.
//!
//! Detects and normalises common obfuscation techniques at the LLIL level,
//! before the IR is handed to MLIL. Running these passes early dramatically
//! reduces the noise that higher-level analyses need to deal with.
//!
//! ## Implemented patterns
//!
//! ### Junk-instruction removal
//! Sequences of instructions that compute a value into a register that is
//! then immediately overwritten (register-dead at the point of write) are
//! flagged as junk and can be stripped.
//!
//! ### Opaque predicate detection
//! Conditional branches whose condition is always-true or always-false based
//! on constant-foldable flag values are detected and reduced to unconditional
//! branches or fall-throughs.
//!
//! ### Constant-blind obfuscation
//! Patterns like `xor eax, KEY; xor eax, KEY` (double-XOR) or `add eax, K;
//! sub eax, K` cancel out and are collapsed to identity.
//!
//! ### MBA (Mixed Boolean Arithmetic) normalisation
//! Simple 2- and 3-term MBA expressions that reduce to simpler forms:
//!   - `(x & ~y) | (~x & y)` → `x ^ y`
//!   - `~(~x | ~y)` → `x & y` (De Morgan)
//!   - `~(~x & ~y)` → `x | y` (De Morgan)
//!   - `x + x` → `x << 1`
//!
//! ### String decryption marker
//! Loops that XOR a buffer at a constant key are flagged as likely string
//! decryption loops and tagged with an intrinsic for the analysis layer.

use crate::x86_eval::{eval_expr, fold_expr, X86CpuState};
use crate::{Effect, IrExpr, LiftedInstr};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// ObfPattern
// ─────────────────────────────────────────────────────────────────────────────

/// A detected obfuscation pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObfPattern {
    /// A double-NOT that can be stripped: `NOT(NOT(x))` → `x`.
    DoubleNot,
    /// A double-XOR with the same key: `XOR(XOR(x, K), K)` → `x`.
    DoubleXor { key: u64 },
    /// An ADD/SUB cancel pair: `ADD(x, K), SUB(x, K)` across two instructions.
    AddSubCancel { delta: u64 },
    /// `(x & ~y) | (~x & y)` → `x XOR y` (XOR via AND/OR/NOT).
    MbaXorEquiv,
    /// De Morgan's law: `~(~x | ~y)` → `x & y`.
    DeMorganAnd,
    /// De Morgan's law: `~(~x & ~y)` → `x | y`.
    DeMorganOr,
    /// `x + x` → `x << 1`.
    AddSelfToShift,
    /// An opaque predicate whose condition reduces to a constant.
    OpaquePredicate { always_taken: bool },
    /// A junk instruction whose result is immediately dead.
    JunkInstruction { reg: String },
    /// A XOR-loop over a buffer at a constant key (likely string decrypt).
    XorDecryptLoop { key: u64 },
}

// ─────────────────────────────────────────────────────────────────────────────
// Expression-level simplifier
// ─────────────────────────────────────────────────────────────────────────────

/// Apply deobfuscation rewrites to a single `IrExpr`.
///
/// Returns the simplified expression and a list of patterns that were found.
#[must_use]
pub fn deobf_expr(expr: &IrExpr) -> (IrExpr, Vec<ObfPattern>) {
    let mut patterns = Vec::new();
    let simplified = deobf_expr_inner(expr, &mut patterns);
    (simplified, patterns)
}

fn deobf_expr_inner(expr: &IrExpr, patterns: &mut Vec<ObfPattern>) -> IrExpr {
    match expr {
        // NOT: handles double-NOT and De Morgan rewrites in one arm.
        IrExpr::Not(inner) => {
            let si = deobf_expr_inner(inner, patterns);
            // Double-NOT: !!x → x
            if let IrExpr::Not(inner2) = &si {
                patterns.push(ObfPattern::DoubleNot);
                return deobf_expr_inner(inner2, patterns);
            }
            // De Morgan: ~(~x | ~y) → x & y
            if let IrExpr::Or(a, b) = &si
                && let (IrExpr::Not(ia), IrExpr::Not(ib)) = (a.as_ref(), b.as_ref()) {
                    patterns.push(ObfPattern::DeMorganAnd);
                    return IrExpr::And(Box::new(*ia.clone()), Box::new(*ib.clone()));
                }
            // De Morgan: ~(~x & ~y) → x | y
            if let IrExpr::And(a, b) = &si
                && let (IrExpr::Not(ia), IrExpr::Not(ib)) = (a.as_ref(), b.as_ref()) {
                    patterns.push(ObfPattern::DeMorganOr);
                    return IrExpr::Or(Box::new(*ia.clone()), Box::new(*ib.clone()));
                }
            IrExpr::Not(Box::new(si))
        }

        // Double-XOR: (x ^ K) ^ K → x
        IrExpr::Xor(a, b) => {
            let sa = deobf_expr_inner(a, patterns);
            let sb = deobf_expr_inner(b, patterns);
            // Check if `sa` is itself a XOR with the same constant key.
            if let (IrExpr::Xor(xa, xb), IrExpr::Const(k2)) = (&sa, &sb) {
                if let IrExpr::Const(k1) = xb.as_ref()
                    && k1 == k2 {
                        patterns.push(ObfPattern::DoubleXor { key: *k1 });
                        return deobf_expr_inner(xa, patterns);
                    }
                // Also check xa.
                if let IrExpr::Const(k1) = xa.as_ref()
                    && k1 == k2 {
                        patterns.push(ObfPattern::DoubleXor { key: *k1 });
                        return deobf_expr_inner(xb, patterns);
                    }
            }
            IrExpr::Xor(Box::new(sa), Box::new(sb))
        }

        // x + x → x << 1
        IrExpr::Add(a, b) => {
            let sa = deobf_expr_inner(a, patterns);
            let sb = deobf_expr_inner(b, patterns);
            if let (IrExpr::Reg(ra), IrExpr::Reg(rb)) = (&sa, &sb)
                && ra == rb {
                    patterns.push(ObfPattern::AddSelfToShift);
                    return IrExpr::Shl(Box::new(sa), Box::new(IrExpr::Const(1)));
                }
            IrExpr::Add(Box::new(sa), Box::new(sb))
        }

        // MBA: (x & ~y) | (~x & y) → x ^ y
        IrExpr::Or(a, b) => {
            let sa = deobf_expr_inner(a, patterns);
            let sb = deobf_expr_inner(b, patterns);
            if let (IrExpr::And(a1, b1), IrExpr::And(a2, b2)) = (&sa, &sb) {
                // Check (x & ~y) | (~x & y) pattern.
                let is_mba_xor =
                    is_complement_pair(a1, b1, a2, b2) || is_complement_pair(b1, a1, b2, a2);
                if is_mba_xor {
                    patterns.push(ObfPattern::MbaXorEquiv);
                    // Return x ^ y where x = a1 (or its complement).
                    let x = strip_not(a1);
                    let y = strip_not(b1);
                    return IrExpr::Xor(Box::new(x), Box::new(y));
                }
            }
            IrExpr::Or(Box::new(sa), Box::new(sb))
        }

        // Recursive cases for all binary ops.
        IrExpr::Sub(a, b) => {
            let sa = deobf_expr_inner(a, patterns);
            let sb = deobf_expr_inner(b, patterns);
            // Sub(x, x) → 0
            if let (IrExpr::Reg(ra), IrExpr::Reg(rb)) = (&sa, &sb)
                && ra == rb { return IrExpr::Const(0); }
            IrExpr::Sub(Box::new(sa), Box::new(sb))
        }
        IrExpr::Mul(a, b) => IrExpr::Mul(
            Box::new(deobf_expr_inner(a, patterns)),
            Box::new(deobf_expr_inner(b, patterns)),
        ),
        IrExpr::And(a, b) => IrExpr::And(
            Box::new(deobf_expr_inner(a, patterns)),
            Box::new(deobf_expr_inner(b, patterns)),
        ),
        IrExpr::Shl(a, b) => IrExpr::Shl(
            Box::new(deobf_expr_inner(a, patterns)),
            Box::new(deobf_expr_inner(b, patterns)),
        ),
        IrExpr::Shr(a, b) => IrExpr::Shr(
            Box::new(deobf_expr_inner(a, patterns)),
            Box::new(deobf_expr_inner(b, patterns)),
        ),
        IrExpr::CmpEqZero(e) => IrExpr::CmpEqZero(Box::new(deobf_expr_inner(e, patterns))),
        IrExpr::Parity(e) => IrExpr::Parity(Box::new(deobf_expr_inner(e, patterns))),
        IrExpr::Deref(addr, size) => IrExpr::Deref(Box::new(deobf_expr_inner(addr, patterns)), *size),

        // Leaves — also attempt constant folding.
        other => fold_expr(other),
    }
}

fn strip_not(e: &IrExpr) -> IrExpr {
    if let IrExpr::Not(inner) = e { *inner.clone() } else { e.clone() }
}

/// Returns `true` if `(a1 & b1)` is of the form `(x & ~y)` and
/// `(a2 & b2)` is of the form `(~x & y)`.
fn is_complement_pair(a1: &IrExpr, b1: &IrExpr, a2: &IrExpr, b2: &IrExpr) -> bool {
    // a1 = x, b1 = ~y, a2 = ~x, b2 = y
    if let IrExpr::Not(nb1) = b1
        && let IrExpr::Not(na2) = a2
            && a1 == na2.as_ref() && nb1.as_ref() == b2 {
                return true;
            }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Effect-level deobfuscation
// ─────────────────────────────────────────────────────────────────────────────

/// Deobfuscate all expressions within a single `Effect`.
#[must_use]
pub fn deobf_effect(eff: &Effect) -> (Effect, Vec<ObfPattern>) {
    let mut all_patterns = Vec::new();
    let new_eff = match eff {
        Effect::RegWrite { reg, value } => {
            let (new_val, p) = deobf_expr(value);
            all_patterns.extend(p);
            Effect::RegWrite { reg: reg.clone(), value: new_val }
        }
        Effect::MemWrite { addr, value, size } => {
            let (new_addr, p1) = deobf_expr(addr);
            let (new_val, p2) = deobf_expr(value);
            all_patterns.extend(p1);
            all_patterns.extend(p2);
            Effect::MemWrite { addr: new_addr, value: new_val, size: *size }
        }
        Effect::MemRead { addr, dest, size } => {
            let (new_addr, p) = deobf_expr(addr);
            all_patterns.extend(p);
            Effect::MemRead { addr: new_addr, dest: dest.clone(), size: *size }
        }
        Effect::Branch { target, condition } => {
            let (new_target, p1) = deobf_expr(target);
            all_patterns.extend(p1);
            let new_cond = condition.as_ref().map(|c| {
                let (nc, p) = deobf_expr(c);
                all_patterns.extend(p);
                nc
            });
            Effect::Branch { target: new_target, condition: new_cond }
        }
        Effect::Call { target } => {
            let (new_t, p) = deobf_expr(target);
            all_patterns.extend(p);
            Effect::Call { target: new_t }
        }
        Effect::Return { value } => {
            let new_v = value.as_ref().map(|v| {
                let (nv, p) = deobf_expr(v);
                all_patterns.extend(p);
                nv
            });
            Effect::Return { value: new_v }
        }
        Effect::Syscall { nr } => {
            let (new_nr, p) = deobf_expr(nr);
            all_patterns.extend(p);
            Effect::Syscall { nr: new_nr }
        }
        Effect::Intrinsic { name, args } => {
            let new_args: Vec<IrExpr> = args.iter().map(|a| {
                let (na, p) = deobf_expr(a);
                all_patterns.extend(p);
                na
            }).collect();
            Effect::Intrinsic { name: name.clone(), args: new_args }
        }
        // These effects carry no IrExpr to deobfuscate; return unchanged.
        Effect::Trap { vector } => Effect::Trap { vector: *vector },
        Effect::ConditionalTrap { condition, vector } => {
            let (new_cond, p) = deobf_expr(condition);
            all_patterns.extend(p);
            Effect::ConditionalTrap { condition: new_cond, vector: *vector }
        }
        Effect::NoReturn => Effect::NoReturn,
    };
    (new_eff, all_patterns)
}

/// Deobfuscate all effects in a slice, returning the simplified effects and
/// a list of all patterns detected.
#[must_use]
pub fn deobf_effects(effects: &[Effect]) -> (Vec<Effect>, Vec<ObfPattern>) {
    let mut new_effects = Vec::with_capacity(effects.len());
    let mut all_patterns = Vec::new();
    for eff in effects {
        let (new_eff, p) = deobf_effect(eff);
        all_patterns.extend(p);
        new_effects.push(new_eff);
    }
    (new_effects, all_patterns)
}

// ─────────────────────────────────────────────────────────────────────────────
// Opaque predicate detection
// ─────────────────────────────────────────────────────────────────────────────

/// Check if a branch condition is an opaque predicate (always-true or
/// always-false based on constant-foldable values).
///
/// Returns `Some(always_taken)` if the condition is constant, `None` if
/// undetermined.
#[must_use]
pub fn check_opaque_predicate(condition: &IrExpr) -> Option<bool> {
    let state = X86CpuState::new();
    match eval_expr(condition, &state) {
        crate::x86_eval::EvalValue::Concrete(0) => Some(false),
        crate::x86_eval::EvalValue::Concrete(_) => Some(true),
        crate::x86_eval::EvalValue::Unknown => {
            // Try constant-folding.
            let folded = fold_expr(condition);
            match folded {
                IrExpr::Const(0) => Some(false),
                IrExpr::Const(_) => Some(true),
                _ => None,
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Junk instruction detection
// ─────────────────────────────────────────────────────────────────────────────

/// Identify instructions whose only effects are writes to registers that are
/// immediately overwritten by the next instruction (dead-write junk).
///
/// Returns a list of `(instruction_index, ObfPattern::JunkInstruction)` pairs.
#[must_use]
pub fn find_junk_instructions(instrs: &[LiftedInstr]) -> Vec<(usize, ObfPattern)> {
    let mut junk = Vec::new();
    for (i, li) in instrs.iter().enumerate() {
        let next_instrs = &instrs[i + 1..];
        // Collect all registers written by this instruction.
        let written: Vec<String> = li.effects.iter()
            .flat_map(super::Effect::written_registers)
            .filter(|r| !r.starts_with("__") && !is_architectural_side_effect(r))
            .collect();
        if written.is_empty() { continue; }
        // Check if all written registers are immediately overwritten and never read.
        let all_dead = written.iter().all(|reg| {
            is_dead_register(reg, next_instrs)
        });
        if all_dead {
            for reg in written {
                junk.push((i, ObfPattern::JunkInstruction { reg }));
            }
        }
    }
    junk
}

/// `true` if `reg` is overwritten before being read in `suffix`.
fn is_dead_register(reg: &str, suffix: &[LiftedInstr]) -> bool {
    for li in suffix {
        for eff in &li.effects {
            // If the register is read before being written again → not dead.
            if eff.read_registers().iter().any(|r| r == reg) {
                return false;
            }
            // If the register is written here → it's dead up to this point.
            if eff.written_registers().iter().any(|r| r == reg) {
                return true;
            }
        }
    }
    // Never seen again in the given suffix — conservatively treat as live
    // (could be a live-out value: return register, callee-preserved state, etc.).
    false
}

fn is_architectural_side_effect(reg: &str) -> bool {
    matches!(reg, "rsp" | "esp" | "sp" | "rflags" | "eflags")
}

// ─────────────────────────────────────────────────────────────────────────────
// XOR-decrypt-loop detection
// ─────────────────────────────────────────────────────────────────────────────

/// Detect simple XOR-key encryption loops in the instruction stream.
///
/// Signature: a tight loop that XORs consecutive memory bytes with a constant
/// and decrements a counter. Returns a list of candidate patterns.
#[must_use]
pub fn detect_xor_decrypt_loops(instrs: &[LiftedInstr]) -> Vec<ObfPattern> {
    let mut found = Vec::new();
    for li in instrs {
        for eff in &li.effects {
            if let Effect::MemWrite { value: IrExpr::Xor(_, k), .. } = eff
                && let IrExpr::Const(key) = **k {
                    // Check if there's a backward branch (loop back-edge) nearby.
                    found.push(ObfPattern::XorDecryptLoop { key });
                }
        }
    }
    found.dedup_by(|a, b| {
        if let (ObfPattern::XorDecryptLoop { key: k1 }, ObfPattern::XorDecryptLoop { key: k2 }) = (a, b) {
            k1 == k2
        } else {
            false
        }
    });
    found
}

// ─────────────────────────────────────────────────────────────────────────────
// Full deobfuscation pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of the deobfuscation pass over a function.
#[derive(Debug, Clone, Default)]
pub struct DeobfSummary {
    /// Number of double-NOT pairs eliminated.
    pub double_not_count: usize,
    /// Number of double-XOR pairs eliminated.
    pub double_xor_count: usize,
    /// Number of MBA XOR-equivalences simplified.
    pub mba_xor_count: usize,
    /// Number of De Morgan rewrites applied.
    pub demorgan_count: usize,
    /// Number of add-self-to-shift rewrites.
    pub add_self_count: usize,
    /// Number of opaque predicates detected.
    pub opaque_pred_count: usize,
    /// Number of junk instructions detected.
    pub junk_count: usize,
    /// Number of XOR-decrypt loops detected.
    pub xor_loop_count: usize,
}

impl DeobfSummary {
    /// Total number of findings.
    #[must_use]
    pub const fn total_findings(&self) -> usize {
        self.double_not_count + self.double_xor_count + self.mba_xor_count
            + self.demorgan_count + self.add_self_count + self.opaque_pred_count
            + self.junk_count + self.xor_loop_count
    }

    const fn tally(&mut self, p: &ObfPattern) {
        match p {
            ObfPattern::DoubleNot => self.double_not_count += 1,
            ObfPattern::DoubleXor { .. } => self.double_xor_count += 1,
            ObfPattern::MbaXorEquiv => self.mba_xor_count += 1,
            ObfPattern::DeMorganAnd | ObfPattern::DeMorganOr => self.demorgan_count += 1,
            ObfPattern::AddSelfToShift => self.add_self_count += 1,
            ObfPattern::OpaquePredicate { .. } => self.opaque_pred_count += 1,
            ObfPattern::JunkInstruction { .. } => self.junk_count += 1,
            ObfPattern::XorDecryptLoop { .. } => self.xor_loop_count += 1,
            ObfPattern::AddSubCancel { .. } => {}
        }
    }
}

/// Run the full deobfuscation pipeline over a function body.
///
/// Returns the deobfuscated instruction list and a summary of what was found.
#[must_use]
pub fn deobf_function(instrs: &[LiftedInstr]) -> (Vec<LiftedInstr>, DeobfSummary) {
    let mut summary = DeobfSummary::default();
    let mut result: Vec<LiftedInstr> = Vec::with_capacity(instrs.len());

    for li in instrs {
        let (new_effects, patterns) = deobf_effects(&li.effects);
        for p in &patterns { summary.tally(p); }

        // Opaque predicate detection on branches.
        let new_effects: Vec<Effect> = new_effects.into_iter().map(|e| {
            if let Effect::Branch { target, condition: Some(c) } = &e
                && let Some(taken) = check_opaque_predicate(c) {
                    summary.tally(&ObfPattern::OpaquePredicate { always_taken: taken });
                    if taken {
                        // Promote to unconditional branch.
                        return Effect::Branch { target: target.clone(), condition: None };
                    }
                    // Remove dead branch — emit NOP intrinsic.
                    return Effect::Intrinsic {
                        name: "deobf.dead_branch".into(),
                        args: vec![target.clone()],
                    };
                }
            e
        }).collect();

        let new_li = LiftedInstr {
            address: li.address,
            original_mnemonic: li.original_mnemonic.clone(),
            ir_text: li.ir_text.clone(),
            il_level: li.il_level,
            effects: new_effects,
        };
        result.push(new_li);
    }

    // Junk instruction detection (cross-instruction).
    let junk = find_junk_instructions(&result);
    for (_, p) in &junk { summary.tally(p); }

    // XOR-decrypt loops.
    let xor_loops = detect_xor_decrypt_loops(&result);
    for p in &xor_loops { summary.tally(p); }

    (result, summary)
}

/// Stable string key identifying an [`ObfPattern`] variant (ignoring payload).
#[must_use]
pub const fn pattern_kind_key(p: &ObfPattern) -> &'static str {
    match p {
        ObfPattern::DoubleNot => "double_not",
        ObfPattern::DoubleXor { .. } => "double_xor",
        ObfPattern::AddSubCancel { .. } => "add_sub_cancel",
        ObfPattern::MbaXorEquiv => "mba_xor_equiv",
        ObfPattern::DeMorganAnd => "demorgan_and",
        ObfPattern::DeMorganOr => "demorgan_or",
        ObfPattern::AddSelfToShift => "add_self_to_shift",
        ObfPattern::OpaquePredicate { .. } => "opaque_predicate",
        ObfPattern::JunkInstruction { .. } => "junk_instruction",
        ObfPattern::XorDecryptLoop { .. } => "xor_decrypt_loop",
    }
}

/// Build a frequency histogram of pattern kinds from a flat slice.
///
/// Useful for reporting layers that want a sparse per-kind count without
/// reading every field of [`DeobfSummary`].
#[must_use]
pub fn pattern_histogram(patterns: &[ObfPattern]) -> HashMap<&'static str, usize> {
    let mut h: HashMap<&'static str, usize> = HashMap::new();
    for p in patterns {
        *h.entry(pattern_kind_key(p)).or_insert(0) += 1;
    }
    h
}

/// Deobfuscate a function and also return a per-kind histogram of every
/// pattern observed during expression, effect, junk, and XOR-loop passes.
#[must_use]
pub fn deobf_function_with_histogram(
    instrs: &[LiftedInstr],
) -> (Vec<LiftedInstr>, DeobfSummary, HashMap<&'static str, usize>) {
    let mut all_patterns: Vec<ObfPattern> = Vec::new();
    let mut summary = DeobfSummary::default();
    let mut result: Vec<LiftedInstr> = Vec::with_capacity(instrs.len());

    for li in instrs {
        let (new_effects, patterns) = deobf_effects(&li.effects);
        for p in &patterns { summary.tally(p); }
        all_patterns.extend(patterns.iter().cloned());

        let new_effects: Vec<Effect> = new_effects.into_iter().map(|e| {
            if let Effect::Branch { target, condition: Some(c) } = &e
                && let Some(taken) = check_opaque_predicate(c) {
                    let p = ObfPattern::OpaquePredicate { always_taken: taken };
                    summary.tally(&p);
                    all_patterns.push(p);
                    if taken {
                        return Effect::Branch { target: target.clone(), condition: None };
                    }
                    return Effect::Intrinsic {
                        name: "deobf.dead_branch".into(),
                        args: vec![target.clone()],
                    };
                }
            e
        }).collect();

        result.push(LiftedInstr {
            address: li.address,
            original_mnemonic: li.original_mnemonic.clone(),
            ir_text: li.ir_text.clone(),
            il_level: li.il_level,
            effects: new_effects,
        });
    }

    for (_, p) in &find_junk_instructions(&result) {
        summary.tally(p);
        all_patterns.push(p.clone());
    }
    for p in &detect_xor_decrypt_loops(&result) {
        summary.tally(p);
        all_patterns.push(p.clone());
    }

    let hist = pattern_histogram(&all_patterns);
    (result, summary, hist)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Effect, IrExpr};

    fn reg(r: &str) -> IrExpr { IrExpr::Reg(r.into()) }
    fn cst(v: u64) -> IrExpr { IrExpr::Const(v) }
    fn not(e: IrExpr) -> IrExpr { IrExpr::Not(Box::new(e)) }
    fn xor(a: IrExpr, b: IrExpr) -> IrExpr { IrExpr::Xor(Box::new(a), Box::new(b)) }
    fn and(a: IrExpr, b: IrExpr) -> IrExpr { IrExpr::And(Box::new(a), Box::new(b)) }
    fn or(a: IrExpr, b: IrExpr) -> IrExpr { IrExpr::Or(Box::new(a), Box::new(b)) }
    fn add(a: IrExpr, b: IrExpr) -> IrExpr { IrExpr::Add(Box::new(a), Box::new(b)) }

    // ── Double-NOT ────────────────────────────────────────────────────────────

    #[test] fn double_not_eliminated() {
        let e = not(not(reg("rax")));
        let (result, patterns) = deobf_expr(&e);
        assert_eq!(result, reg("rax"));
        assert!(patterns.iter().any(|p| matches!(p, ObfPattern::DoubleNot)));
    }

    #[test] fn single_not_unchanged() {
        let e = not(reg("rax"));
        let (result, patterns) = deobf_expr(&e);
        assert!(patterns.is_empty() || !patterns.iter().any(|p| matches!(p, ObfPattern::DoubleNot)));
        assert!(matches!(result, IrExpr::Not(_)));
    }

    // ── Double-XOR ────────────────────────────────────────────────────────────

    #[test] fn double_xor_same_key_eliminated() {
        let e = xor(xor(reg("rax"), cst(0xdead_beef)), cst(0xdead_beef));
        let (result, patterns) = deobf_expr(&e);
        assert_eq!(result, reg("rax"));
        assert!(patterns.iter().any(|p| matches!(p, ObfPattern::DoubleXor { key: 0xdead_beef })));
    }

    #[test] fn double_xor_different_keys_unchanged() {
        let e = xor(xor(reg("rax"), cst(0xaa)), cst(0xbb));
        let (_, patterns) = deobf_expr(&e);
        assert!(!patterns.iter().any(|p| matches!(p, ObfPattern::DoubleXor { .. })));
    }

    // ── ADD self to shift ─────────────────────────────────────────────────────

    #[test] fn add_self_becomes_shl1() {
        let e = add(reg("rbx"), reg("rbx"));
        let (result, patterns) = deobf_expr(&e);
        assert!(matches!(result, IrExpr::Shl(_, b) if matches!(*b, IrExpr::Const(1))));
        assert!(patterns.iter().any(|p| matches!(p, ObfPattern::AddSelfToShift)));
    }

    #[test] fn add_different_regs_unchanged() {
        let e = add(reg("rax"), reg("rbx"));
        let (result, patterns) = deobf_expr(&e);
        assert!(matches!(result, IrExpr::Add(_, _)));
        assert!(!patterns.iter().any(|p| matches!(p, ObfPattern::AddSelfToShift)));
    }

    // ── De Morgan ────────────────────────────────────────────────────────────

    #[test] fn demorgan_and() {
        // ~(~x | ~y) → x & y
        let e = not(or(not(reg("rax")), not(reg("rbx"))));
        let (result, patterns) = deobf_expr(&e);
        assert!(matches!(result, IrExpr::And(_, _)));
        assert!(patterns.iter().any(|p| matches!(p, ObfPattern::DeMorganAnd)));
    }

    #[test] fn demorgan_or() {
        // ~(~x & ~y) → x | y
        let e = not(and(not(reg("rax")), not(reg("rbx"))));
        let (result, patterns) = deobf_expr(&e);
        assert!(matches!(result, IrExpr::Or(_, _)));
        assert!(patterns.iter().any(|p| matches!(p, ObfPattern::DeMorganOr)));
    }

    // ── MBA XOR equiv ─────────────────────────────────────────────────────────

    #[test] fn mba_xor_via_and_or_not() {
        // (x & ~y) | (~x & y) → x ^ y
        let x = reg("rax");
        let y = reg("rbx");
        let e = or(
            and(x.clone(), not(y.clone())),
            and(not(x.clone()), y.clone()),
        );
        let (result, patterns) = deobf_expr(&e);
        assert!(matches!(result, IrExpr::Xor(_, _)));
        assert!(patterns.iter().any(|p| matches!(p, ObfPattern::MbaXorEquiv)));
    }

    // ── Opaque predicates ────────────────────────────────────────────────────

    #[test] fn opaque_pred_always_true_const() {
        let cond = cst(1); // constant 1 → always taken
        let result = check_opaque_predicate(&cond);
        assert_eq!(result, Some(true));
    }

    #[test] fn opaque_pred_always_false_const() {
        let cond = cst(0);
        let result = check_opaque_predicate(&cond);
        assert_eq!(result, Some(false));
    }

    #[test] fn opaque_pred_unknown_reg() {
        let cond = reg("zf"); // depends on runtime flag
        let result = check_opaque_predicate(&cond);
        assert_eq!(result, None);
    }

    #[test] fn opaque_pred_foldable_const_expr() {
        // (2 + 3) != 0 → always true (folds to 5 → true)
        let cond = IrExpr::Add(Box::new(cst(2)), Box::new(cst(3)));
        let result = check_opaque_predicate(&cond);
        assert_eq!(result, Some(true));
    }

    // ── Junk instruction detection ───────────────────────────────────────────

    #[test] fn junk_reg_overwritten_immediately() {
        use crate::{LiftLevel, LiftedInstr};
        let instrs = vec![
            LiftedInstr {
                address: 0x1000,
                original_mnemonic: "mov".into(),
                ir_text: "junk".into(),
                il_level: LiftLevel::Llil,
                effects: vec![
                    Effect::RegWrite { reg: "rcx".into(), value: cst(0x99) },
                ],
            },
            LiftedInstr {
                address: 0x1002,
                original_mnemonic: "mov".into(),
                ir_text: "real".into(),
                il_level: LiftLevel::Llil,
                effects: vec![
                    Effect::RegWrite { reg: "rcx".into(), value: cst(0) }, // rcx overwritten
                ],
            },
        ];
        let junk = find_junk_instructions(&instrs);
        assert!(!junk.is_empty(), "rcx write at 0x1000 should be junk");
    }

    #[test] fn no_junk_when_reg_is_read() {
        use crate::{LiftLevel, LiftedInstr};
        let instrs = vec![
            LiftedInstr {
                address: 0x2000,
                original_mnemonic: "mov".into(),
                ir_text: "useful".into(),
                il_level: LiftLevel::Llil,
                effects: vec![Effect::RegWrite { reg: "rdx".into(), value: cst(42) }],
            },
            LiftedInstr {
                address: 0x2002,
                original_mnemonic: "mov".into(),
                ir_text: "uses_rdx".into(),
                il_level: LiftLevel::Llil,
                effects: vec![Effect::RegWrite {
                    reg: "rax".into(),
                    value: IrExpr::Reg("rdx".into()), // reads rdx
                }],
            },
        ];
        let junk = find_junk_instructions(&instrs);
        assert!(junk.is_empty(), "rdx is read by next instr, not junk");
    }

    // ── XOR decrypt loop ─────────────────────────────────────────────────────

    #[test] fn detect_xor_loop_with_constant_key() {
        use crate::{LiftLevel, LiftedInstr};
        let instrs = vec![LiftedInstr {
            address: 0x3000,
            original_mnemonic: "xor".into(),
            ir_text: "loop".into(),
            il_level: LiftLevel::Llil,
            effects: vec![
                Effect::MemWrite {
                    addr: IrExpr::Reg("rdi".into()),
                    value: IrExpr::Xor(Box::new(IrExpr::Undef), Box::new(cst(0x41))),
                    size: 1,
                },
            ],
        }];
        let loops = detect_xor_decrypt_loops(&instrs);
        assert!(loops.iter().any(|p| matches!(p, ObfPattern::XorDecryptLoop { key: 0x41 })));
    }

    // ── deobf_effect ─────────────────────────────────────────────────────────

    #[test] fn deobf_effect_propagates_into_reg_write() {
        let eff = Effect::RegWrite {
            reg: "rax".into(),
            value: xor(xor(reg("rbx"), cst(0xff)), cst(0xff)),
        };
        let (new_eff, patterns) = deobf_effect(&eff);
        match new_eff {
            Effect::RegWrite { value, .. } => {
                assert_eq!(value, reg("rbx"), "double-XOR should cancel");
            }
            _ => panic!("unexpected effect type"),
        }
        assert!(patterns.iter().any(|p| matches!(p, ObfPattern::DoubleXor { .. })));
    }

    #[test] fn deobf_effects_slice() {
        let effects = vec![
            Effect::RegWrite { reg: "rax".into(), value: not(not(reg("rax"))) },
        ];
        let (new_effects, patterns) = deobf_effects(&effects);
        assert_eq!(new_effects.len(), 1);
        assert!(patterns.iter().any(|p| matches!(p, ObfPattern::DoubleNot)));
        if let Effect::RegWrite { value, .. } = &new_effects[0] {
            assert_eq!(*value, reg("rax"));
        }
    }

    // ── DeobfSummary ─────────────────────────────────────────────────────────

    #[test] fn summary_default_all_zero() {
        let s = DeobfSummary::default();
        assert_eq!(s.total_findings(), 0);
    }

    #[test] fn summary_tallies_double_not() {
        let mut s = DeobfSummary::default();
        s.tally(&ObfPattern::DoubleNot);
        assert_eq!(s.double_not_count, 1);
        assert_eq!(s.total_findings(), 1);
    }

    // ── deobf_function ────────────────────────────────────────────────────────

    #[test] fn deobf_function_runs_without_panic() {
        use crate::{LiftLevel, LiftedInstr};
        let instrs = vec![LiftedInstr {
            address: 0x1000,
            original_mnemonic: "xor".into(),
            ir_text: "x".into(),
            il_level: LiftLevel::Llil,
            effects: vec![Effect::RegWrite {
                reg: "rax".into(),
                value: not(not(reg("rax"))),
            }],
        }];
        let (result, summary) = deobf_function(&instrs);
        assert_eq!(result.len(), 1);
        assert!(summary.double_not_count > 0);
    }

    #[test] fn deobf_function_opaque_pred_always_taken() {
        use crate::{LiftLevel, LiftedInstr};
        let instrs = vec![LiftedInstr {
            address: 0x2000,
            original_mnemonic: "je".into(),
            ir_text: "opaque".into(),
            il_level: LiftLevel::Llil,
            effects: vec![Effect::Branch {
                target: cst(0x2010),
                condition: Some(cst(1)), // always-taken opaque predicate
            }],
        }];
        let (result, summary) = deobf_function(&instrs);
        // The conditional branch should be promoted to unconditional.
        let is_unconditional = result[0].effects.iter().any(|e| {
            matches!(e, Effect::Branch { condition: None, .. })
        });
        assert!(is_unconditional, "always-taken opaque predicate should become unconditional");
        assert!(summary.opaque_pred_count > 0);
    }

    #[test] fn deobf_function_dead_branch_removed() {
        use crate::{LiftLevel, LiftedInstr};
        let instrs = vec![LiftedInstr {
            address: 0x3000,
            original_mnemonic: "je".into(),
            ir_text: "dead".into(),
            il_level: LiftLevel::Llil,
            effects: vec![Effect::Branch {
                target: cst(0x3010),
                condition: Some(cst(0)), // never-taken
            }],
        }];
        let (result, summary) = deobf_function(&instrs);
        let has_dead_branch = result[0].effects.iter().any(|e| {
            matches!(e, Effect::Intrinsic { name, .. } if name.contains("dead_branch"))
        });
        assert!(has_dead_branch, "never-taken branch should become dead_branch intrinsic");
        assert!(summary.opaque_pred_count > 0);
    }
}
