//! CFG-based SSA-lite variable splitting — the correctness core.
//!
//! When one register name carries several *independent* live ranges (a pointer
//! on one line, a loop counter three lines later), that single name reads as two
//! different things. This module computes, over the basic-block CFG, which
//! ranges can be given distinct names WITHOUT phi nodes and WITHOUT changing
//! semantics. It is deliberately split into a pure analysis ([`plan_splits`],
//! fully unit-tested here) and a later rewrite step, so the correctness-critical
//! part can be validated in isolation before any pipeline wiring.
//!
//! Safety model (see the design memo): a split is emitted only when the live
//! ranges are provably disjoint — every use is reached by exactly one class of
//! definitions, and a definition that reads the variable stays in its source
//! range. Parameters / live-in values are modelled by a synthetic entry
//! definition, so a use reachable from both the entry and a later definition is
//! a merge point and is never split.

use rustre_decompiler_cfs::{BasicBlock, Statement};
use std::collections::{HashMap, HashSet};

/// General-purpose registers that may carry splittable values. The frame/stack
/// pointers and the instruction pointer are NEVER candidates — renaming them
/// would be catastrophic.
const FROZEN: [&str; 3] = ["rsp", "rbp", "rip"];

/// Compound assignment operators: the LHS is both a use and a def.
const COMPOUND_OPS: [&str; 10] =
    ["+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="];

/// Is `name` a splittable variable candidate at block stage (a raw GP register,
/// excluding the frozen frame/stack/instruction pointers)?
fn is_candidate(name: &str) -> bool {
    if FROZEN.contains(&name) {
        return false;
    }
    matches!(
        name,
        "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi"
            | "r8" | "r9" | "r10" | "r11" | "r12" | "r13" | "r14" | "r15"
    )
}

/// The 32-bit alias of each candidate 64-bit GP register. A write to one of
/// these IS a full definition of the 64-bit parent: AMD APM vol. 3 (pub 24594
/// rev 3.34, "Instruction Overview", registers in 64-bit mode) — "The high 32
/// bits of doubleword operands are zero-extended to 64 bits, but the high
/// bits of word and byte operands are not modified".
const SUBREG32: [(&str, &str); 14] = [
    ("eax", "rax"), ("ebx", "rbx"), ("ecx", "rcx"), ("edx", "rdx"),
    ("esi", "rsi"), ("edi", "rdi"),
    ("r8d", "r8"), ("r9d", "r9"), ("r10d", "r10"), ("r11d", "r11"),
    ("r12d", "r12"), ("r13d", "r13"), ("r14d", "r14"), ("r15d", "r15"),
];

/// 8/16-bit aliases. Writes to these do NOT zero-extend (see [`SUBREG32`]
/// citation), so in sub-register-aware mode any mention of one poisons its
/// 64-bit parent — the parent is then never split.
const SUBREG_PARTIAL: [(&str, &str); 32] = [
    ("al", "rax"), ("ah", "rax"), ("ax", "rax"),
    ("bl", "rbx"), ("bh", "rbx"), ("bx", "rbx"),
    ("cl", "rcx"), ("ch", "rcx"), ("cx", "rcx"),
    ("dl", "rdx"), ("dh", "rdx"), ("dx", "rdx"),
    ("sil", "rsi"), ("si", "rsi"),
    ("dil", "rdi"), ("di", "rdi"),
    ("r8b", "r8"), ("r8w", "r8"), ("r9b", "r9"), ("r9w", "r9"),
    ("r10b", "r10"), ("r10w", "r10"), ("r11b", "r11"), ("r11w", "r11"),
    ("r12b", "r12"), ("r12w", "r12"), ("r13b", "r13"), ("r13w", "r13"),
    ("r14b", "r14"), ("r14w", "r14"), ("r15b", "r15"), ("r15w", "r15"),
];

/// The 64-bit parent of a 32-bit register name, if `name` is one.
fn canon32(name: &str) -> Option<&'static str> {
    SUBREG32.iter().find(|&&(s, _)| s == name).map(|&(_, c)| c)
}

/// The 32-bit alias of a 64-bit candidate register name, if `name` is one.
fn sub32_of(name: &str) -> Option<&'static str> {
    SUBREG32.iter().find(|&&(_, c)| c == name).map(|&(s, _)| s)
}

/// The 64-bit parent of an 8/16-bit register name, if `name` is one.
fn partial_alias(name: &str) -> Option<&'static str> {
    SUBREG_PARTIAL.iter().find(|&&(s, _)| s == name).map(|&(_, c)| c)
}

/// Candidacy with optional sub-register normalization: in `subreg` mode a
/// 32-bit register name resolves to its (candidate) 64-bit parent.
fn norm_candidate(name: &str, subreg: bool) -> Option<String> {
    if is_candidate(name) {
        return Some(name.to_string());
    }
    if subreg && let Some(c) = canon32(name) && is_candidate(c) {
        return Some(c.to_string());
    }
    None
}

/// USE-position candidacy: a 32-bit alias read (`eax`) is ALWAYS a read of its
/// 64-bit parent (`rax`), in both modes. Without this, a use spelled with the
/// 32-bit alias — e.g. the `eax` printf argument that `infer_call_arguments`
/// folds out of `edx = eax` — was invisible to the reaching-defs plan, so the
/// producing call's `rax` def looked dead, was split into a fresh register
/// family, and the emitted C read an uninitialised variable
/// (`// DCE(df): v4 = f1_1(43, 30);` … `__mingw_printf(fmt, result);`).
/// Only USES normalize unconditionally; treating a 32-bit DEF as a full-width
/// def stays gated behind subreg mode. An alias mention that would have been a
/// def merely becomes a use, which can only MERGE live ranges (fewer splits) —
/// never an unsound rename.
fn norm_use(name: &str) -> Option<String> {
    if let Some(c) = norm_candidate(name, true) {
        return Some(c);
    }
    // An 8/16-bit alias READ (`dl`, `cx`) is a read of the low bits of its
    // 64-bit parent, so it is a genuine USE of that parent. Modelling it makes
    // narrow reads visible to the reaching-defs plan, which is what lets the
    // blanket partial-alias ban be narrowed to partial *writes* (the only
    // positions that are architecturally unmodellable — they do not
    // zero-extend). Like the 32-bit case, extra uses can only MERGE ranges.
    if let Some(p) = partial_alias(name)
        && is_candidate(p)
    {
        return Some(p.to_string());
    }
    None
}

/// Width class of an 8/16-bit register alias: 0 = low byte (`dl`, `sil`,
/// `r10b`), 1 = high byte (`dh` — only the legacy a/b/c/d registers have one),
/// 2 = 16-bit word (`dx`, `si`, `r10w`).
fn partial_class(alias: &str) -> u8 {
    if alias.len() == 2 && alias.ends_with('h') {
        1
    } else if alias.ends_with('l') || alias.ends_with('b') {
        0
    } else {
        2
    }
}

/// The 8/16-bit alias of `parent` in width class `class`, if it has one.
fn partial_name_for(parent: &str, class: u8) -> Option<&'static str> {
    SUBREG_PARTIAL
        .iter()
        .find(|&&(a, p)| p == parent && partial_class(a) == class)
        .map(|&(a, _)| a)
}

/// Parents of 8/16-bit aliases that appear in a DEF (assignment-LHS) position.
///
/// A partial *write* does not zero-extend (see [`SUBREG32`]), so the full-width
/// def/use model cannot describe it and the parent must stay unsplittable.
/// A partial *read* carries no such hazard — it is handled by [`norm_use`] —
/// so it no longer disqualifies the register. This distinction is what unblocks
/// the two-loop stack-array shape, where `rdx` is a pointer cursor in the fill
/// loop and `edx` an int counter in the consume loop, and the only narrow
/// mention is the READ in `test $1, %dl`.
fn partial_def_parents(blocks: &[BasicBlock]) -> HashSet<&'static str> {
    let mut set = HashSet::new();
    let mut note = |lhs: &str| {
        if let Some(v) = plain_scalar_lhs(lhs)
            && let Some(p) = partial_alias(&v)
        {
            set.insert(p);
        }
    };
    for b in blocks {
        for s in &b.stmts {
            match s {
                Statement::Assign { lhs, .. } => note(lhs),
                Statement::Raw(r) => {
                    if let Some((lhs, _)) = split_compound(r) {
                        note(&lhs);
                    } else if let Some((lhs, _)) = parse_raw_assign(r) {
                        note(&lhs);
                    }
                }
                _ => {}
            }
        }
    }
    set
}

/// Extract identifier tokens from an expression string (letters/`_` start, then
/// word chars). Pure lexical; callers filter to candidates.
fn idents(expr: &str) -> Vec<String> {
    let b = expr.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_alphabetic() || b[i] == b'_' {
            let s = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            out.push(expr[s..i].to_string());
        } else {
            i += 1;
        }
    }
    out
}

/// The def and uses a statement contributes, restricted to candidate variables.
struct DefUse {
    /// The (single) candidate variable defined here, if any.
    def: Option<String>,
    /// Candidate variables read here (a compound-assign LHS appears here too).
    uses: Vec<String>,
}

/// Parse `lhs`/`rhs` of a plain assignment out of a Raw string, if it is one.
/// Returns `None` for comparisons/compound forms and non-assignments.
fn parse_raw_assign(s: &str) -> Option<(String, String)> {
    let t = s.trim();
    // Reject obvious non-assignments up front.
    if t.starts_with("if")
        || t.starts_with('*')
        || t.starts_with('[')
        || t.starts_with("goto")
        || t.starts_with("return")
    {
        return None;
    }
    let eq = t.find('=')?;
    // Not `==`, `<=`, `>=`, `!=`, and not a compound op just before `=`.
    let before = t.as_bytes().get(eq.wrapping_sub(1)).copied();
    let after = t.as_bytes().get(eq + 1).copied();
    if after == Some(b'=') || matches!(before, Some(b'<' | b'>' | b'!' | b'=')) {
        return None;
    }
    if matches!(before, Some(b'+' | b'-' | b'*' | b'/' | b'%' | b'&' | b'|' | b'^')) {
        return None; // compound — handled separately
    }
    let lhs = t[..eq].trim().to_string();
    let rhs = t[eq + 1..].trim().trim_end_matches(';').to_string();
    Some((lhs, rhs))
}

/// Is `lhs` a plain scalar identifier (not a memory/field write)?
fn plain_scalar_lhs(lhs: &str) -> Option<String> {
    let l = lhs.trim();
    if l.contains(['*', '[', '.', '+', '-', ' ']) || l.contains("->") {
        return None;
    }
    (!l.is_empty() && (l.as_bytes()[0].is_ascii_alphabetic() || l.as_bytes()[0] == b'_'))
        .then(|| l.to_string())
}

/// Compute the candidate DEF/USE of a single statement (historical mode).
fn stmt_def_use(s: &Statement) -> DefUse {
    stmt_def_use_mode(s, false)
}

/// Compute the candidate DEF/USE of a single statement. In `subreg` mode,
/// 32-bit register names normalize to their 64-bit parents (a 32-bit write is
/// a full def — zero-extension, see [`SUBREG32`]).
fn stmt_def_use_mode(s: &Statement, subreg: bool) -> DefUse {
    match s {
        Statement::Return(Some(v)) => DefUse {
            def: None,
            uses: idents(v).into_iter().filter_map(|i| norm_use(&i)).collect(),
        },
        // A bare `return;` still implicitly carries the function's result out
        // through rax/rdx (win64/SysV integer return regs) whenever the
        // function is non-void — the CFS statement just doesn't spell it out.
        // Without this, the last real def of rax reaching this exit looks
        // unused to the reaching-defs analysis and gets renamed to a fresh
        // register by split_versions, silently losing the return value (the
        // renamed spelling isn't recognized by the later text-level
        // `rewrite_bare_return_with_value` return-alias detection).
        Statement::Return(None) => DefUse { def: None, uses: RETURN_REGS.iter().map(|r| r.to_string()).collect() },
        Statement::Branch(c) => DefUse {
            def: None,
            uses: idents(c).into_iter().filter_map(|i| norm_use(&i)).collect(),
        },
        Statement::Assign { lhs, rhs } => def_use_from_assign(lhs, rhs, subreg),
        Statement::Raw(r) => {
            // Compound assign? (A compound def always also reads its LHS, so a
            // 32-bit compound like `ecx += 1` is def+use of rcx — correct for
            // both the zero-extending result and the low-32 read.)
            if let Some((lhs, op)) = split_compound(r)
                && let Some(v) = plain_scalar_lhs(&lhs)
                && let Some(v) = norm_candidate(&v, subreg)
            {
                let mut uses: Vec<String> =
                    idents(&op).into_iter().filter_map(|i| norm_use(&i)).collect();
                uses.push(v.clone()); // compound reads the LHS too
                return DefUse { def: Some(v), uses };
            }
            if let Some((lhs, rhs)) = parse_raw_assign(r) {
                return def_use_from_assign(&lhs, &rhs, subreg);
            }
            // Not an assignment: everything is a use.
            DefUse {
                def: None,
                uses: idents(r).into_iter().filter_map(|i| norm_use(&i)).collect(),
            }
        }
    }
}

/// Split a compound-assign Raw like `rbx += rax` into `(lhs, rhs)`.
fn split_compound(r: &str) -> Option<(String, String)> {
    let t = r.trim().trim_end_matches(';');
    for op in COMPOUND_OPS {
        if let Some(p) = t.find(op) {
            return Some((t[..p].to_string(), t[p + op.len()..].to_string()));
        }
    }
    None
}

fn def_use_from_assign(lhs: &str, rhs: &str, subreg: bool) -> DefUse {
    let mut uses: Vec<String> =
        idents(rhs).into_iter().filter_map(|i| norm_use(&i)).collect();
    // A non-scalar LHS (`*(rax+8)`, `rax[i]`) is a USE of its base, not a def.
    match plain_scalar_lhs(lhs).and_then(|v| norm_candidate(&v, subreg)) {
        Some(v) => DefUse { def: Some(v), uses },
        _ => {
            uses.extend(idents(lhs).into_iter().filter_map(|i| norm_use(&i)));
            DefUse { def: None, uses }
        }
    }
}

/// The 64-bit parent register of a *plain 32-bit-alias copy* store, if `s` is
/// one. A 32-bit register write (`ecx = edx`, `ecx = 0`) unconditionally
/// zero-extends into the full 64-bit parent (see [`SUBREG32`]), so it is a FULL
/// definition of `rcx` — architecturally sound to treat as a def even outside
/// sub-register mode. Restricted to a "plain copy" RHS (a single register token
/// or immediate, no operators) so the promotion stays conservative: this is the
/// win64 argument-register shuffle shape (`mov %edx,%ecx` moving a tail-call
/// argument into the callee's arg register) that otherwise reuses a live
/// parameter's name for a DEAD value, yielding a misleading
/// `// DCE(df): a1 = a2;` above an `if (a1 != 0)` that reads the parameter.
/// Splitting the dead range off gives it a fresh name and an honest marker.
fn plain_copy32_parent(s: &Statement) -> Option<&'static str> {
    let (lhs, rhs) = match s {
        Statement::Assign { lhs, rhs } => (lhs.clone(), rhs.clone()),
        Statement::Raw(r) => parse_raw_assign(r)?,
        _ => return None,
    };
    let lhs = plain_scalar_lhs(&lhs)?;
    let parent = canon32(&lhs)?; // LHS must be a 32-bit alias
    if !is_candidate(parent) {
        return None;
    }
    // RHS must be a single register token, no operators — a genuine
    // register-to-register copy that fully (zero-extending) overwrites the
    // destination. Immediates (`ecx = 0`) are deliberately excluded: promoting
    // those would perturb live-accumulator init patterns and break the default
    // path's historical byte-identical guarantee for no fidelity gain (the
    // dead-shuffle case this targets is always a reg→reg move).
    let toks = idents(&rhs);
    let r = rhs.trim().trim_end_matches(';').trim();
    let is_single_reg = toks.len() == 1
        && canon32(r).is_some() // the RHS itself is a 32-bit register token
        && !r.contains(['*', '[', '.', '+', '-', '/', '%', '&', '|', '^', '(', ' ']);
    if is_single_reg {
        Some(parent)
    } else {
        None
    }
}

// ── union-find ────────────────────────────────────────────────────────────
struct Uf(Vec<usize>);
impl Uf {
    fn new(n: usize) -> Self {
        Self((0..n).collect())
    }
    fn find_root(&mut self, mut x: usize) -> usize {
        while self.0[x] != x {
            self.0[x] = self.0[self.0[x]];
            x = self.0[x];
        }
        x
    }
    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find_root(a), self.find_root(b));
        if ra != rb {
            self.0[ra] = rb;
        }
    }
}

/// The plan for one splittable variable: the version (0 = original) assigned to
/// each def/use position. Only variables that actually split (≥2 versions) are
/// returned.
#[derive(Debug, PartialEq, Eq)]
pub struct SplitPlan {
    pub var: String,
    /// `(block_index, stmt_index) -> version`. Version 0 keeps the original name.
    pub versions: Vec<((usize, usize), usize)>,
}

/// Analyse `blocks` and return the safe variable splits. Pure: no mutation.
///
/// A variable is split only when its definitions partition into ≥2 classes such
/// that no use is reached by two classes (phi-free) — guaranteed by construction
/// because a multi-reaching use unions its reaching defs into one class.
#[must_use]
pub fn plan_splits(blocks: &[BasicBlock]) -> Vec<SplitPlan> {
    plan_splits_with(blocks, false)
}

/// Like [`plan_splits`], with optional sub-register awareness (opt-in; the
/// default path is bit-for-bit the historical behavior).
///
/// When `subreg_aware` is true, a write to a 32-bit GP register name (`eax`,
/// `ecx`, …, `r8d`–`r15d`) is treated as a full definition of its 64-bit
/// parent register. This is the architected x86-64 behavior — AMD APM vol. 3
/// (pub 24594 rev 3.34, "Instruction Overview", registers in 64-bit mode):
/// "The high 32 bits of doubleword operands are zero-extended to 64 bits,
/// but the high bits of word and byte operands are not modified". Because
/// 8/16-bit writes do NOT zero-extend, any mention of an 8/16-bit alias
/// conservatively disqualifies that whole register from splitting.
#[must_use]
pub fn plan_splits_with(blocks: &[BasicBlock], subreg_aware: bool) -> Vec<SplitPlan> {
    if blocks.is_empty() {
        return Vec::new();
    }
    // Poison: in subreg mode, a register whose 8/16-bit alias is mentioned
    // ANYWHERE cannot be reasoned about with full-width defs (partial writes
    // do not zero-extend) — remove it from candidacy entirely.
    let poison: HashSet<&'static str> = if subreg_aware {
        partial_def_parents(blocks)
    } else {
        HashSet::new()
    };
    // Parents that have an 8/16-bit alias mentioned anywhere: a full-width copy
    // def is still architecturally sound for these, but a *narrow read* of the
    // same parent (`cl`) is invisible to the reaching-defs analysis and would
    // desync after a rename — so we do NOT promote 32-bit copies to defs there.
    // (Independent of `poison`, which only exists in sub-register mode.)
    let partial_parents: HashSet<&'static str> = partial_def_parents(blocks);
    let id_to_idx: HashMap<u32, usize> =
        blocks.iter().enumerate().map(|(i, b)| (b.id.0, i)).collect();

    // Promotion of a plain 32-bit-alias copy (`ecx = edx`) to a full def of its
    // zero-extending 64-bit parent (see `plain_copy32_parent`). This is done in
    // the default (non-subreg) path ONLY for a genuinely DEAD shuffle — the
    // parent register is never read again after the copy — so the dead range
    // splits off the live parameter's range instead of shadowing it (the D6
    // `apply` flag-copy-select bug). Restricting to dead copies keeps the
    // default path byte-identical for live values (accumulators, copy-out
    // chains), which would otherwise churn. Disabled entirely when the CFG has
    // a back-edge (loop): the linear last-use approximation is unsound there.
    let has_backedge = blocks.iter().enumerate().any(|(bi, b)| {
        b.successors.iter().any(|s| id_to_idx.get(&s.0).is_some_and(|&ti| ti <= bi))
    });
    // Last (block, stmt) position where each candidate parent is READ (base
    // def/use, no promotion), for the dead-after-copy check.
    let mut last_use: HashMap<String, (usize, usize)> = HashMap::new();
    for (bi, b) in blocks.iter().enumerate() {
        for (si, s) in b.stmts.iter().enumerate() {
            // A plain 32-bit copy's LHS (`ecx`) is spelled as a USE of its parent
            // by the base def/use (it isn't a recognised def in the non-subreg
            // path). That spurious self-use must not count against the deadness
            // check for the very copy we may promote — it's a write, not a read.
            let self_copy_parent = plain_copy32_parent(s);
            for u in stmt_def_use_mode(s, subreg_aware).uses {
                if self_copy_parent == Some(u.as_str()) {
                    continue;
                }
                last_use
                    .entry(u)
                    .and_modify(|p| *p = (*p).max((bi, si)))
                    .or_insert((bi, si));
            }
        }
    }
    let promoted_defs: HashSet<(usize, usize)> = if has_backedge {
        HashSet::new()
    } else {
        let mut set = HashSet::new();
        for (bi, b) in blocks.iter().enumerate() {
            for (si, s) in b.stmts.iter().enumerate() {
                if stmt_def_use_mode(s, subreg_aware).def.is_some() {
                    continue; // already a recognised def
                }
                if let Some(p) = plain_copy32_parent(s)
                    && !partial_parents.contains(p)
                    && last_use.get(p).is_none_or(|&lu| lu < (bi, si))
                {
                    set.insert((bi, si));
                }
            }
        }
        set
    };
    let du_of = |bi: usize, si: usize, s: &Statement| -> DefUse {
        let mut du = stmt_def_use_mode(s, subreg_aware);
        if !poison.is_empty() {
            if du.def.as_deref().is_some_and(|d| poison.contains(d)) {
                du.def = None;
            }
            du.uses.retain(|u| !poison.contains(u.as_str()));
        }
        if du.def.is_none()
            && promoted_defs.contains(&(bi, si))
            && let Some(p) = plain_copy32_parent(s)
        {
            du.def = Some(p.to_string());
            du.uses.retain(|u| u != p);
        }
        du
    };

    // Enumerate real def sites + a synthetic entry def per candidate var.
    let mut sites: Vec<(usize, isize, String)> = Vec::new(); // (block, stmt or -1, var)
    let mut candidate_vars: HashSet<String> = HashSet::new();
    for (bi, b) in blocks.iter().enumerate() {
        for (si, s) in b.stmts.iter().enumerate() {
            let du = du_of(bi, si, s);
            for u in &du.uses {
                candidate_vars.insert(u.clone());
            }
            if let Some(d) = du.def {
                candidate_vars.insert(d.clone());
                sites.push((bi, si as isize, d));
            }
        }
    }
    // Entry defs (block 0, stmt -1) model live-in / parameters.
    for v in &candidate_vars {
        sites.push((0, -1, v.clone()));
    }
    if sites.is_empty() {
        return Vec::new();
    }
    let site_id: HashMap<(usize, isize, String), usize> =
        sites.iter().enumerate().map(|(i, s)| (s.clone(), i)).collect();
    let defs_of: HashMap<&str, Vec<usize>> = {
        let mut m: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, (_, _, v)) in sites.iter().enumerate() {
            m.entry(v.as_str()).or_default().push(i);
        }
        m
    };

    // Predecessors from successors.
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
    for (bi, b) in blocks.iter().enumerate() {
        for s in &b.successors {
            if let Some(&ti) = id_to_idx.get(&s.0) {
                preds[ti].push(bi);
            }
        }
    }

    // gen/kill per block over def ids.
    let mut gen_: Vec<HashSet<usize>> = vec![HashSet::new(); blocks.len()];
    let mut kill: Vec<HashSet<usize>> = vec![HashSet::new(); blocks.len()];
    for (bi, b) in blocks.iter().enumerate() {
        let mut last: HashMap<String, usize> = HashMap::new();
        for (si, s) in b.stmts.iter().enumerate() {
            if let Some(d) = du_of(bi, si, s).def {
                last.insert(d, si);
            }
        }
        for (v, si) in &last {
            let id = site_id[&(bi, *si as isize, v.clone())];
            gen_[bi].insert(id);
            for &other in &defs_of[v.as_str()] {
                if other != id {
                    kill[bi].insert(other);
                }
            }
        }
    }

    // IN/OUT reaching-defs fixpoint. Entry IN seeded with entry defs.
    let mut in_: Vec<HashSet<usize>> = vec![HashSet::new(); blocks.len()];
    let mut out: Vec<HashSet<usize>> = vec![HashSet::new(); blocks.len()];
    for v in &candidate_vars {
        in_[0].insert(site_id[&(0, -1, v.clone())]);
    }
    let mut changed = true;
    while changed {
        changed = false;
        for bi in 0..blocks.len() {
            let mut new_in: HashSet<usize> = if bi == 0 {
                candidate_vars.iter().map(|v| site_id[&(0, -1, v.clone())]).collect()
            } else {
                HashSet::new()
            };
            for &p in &preds[bi] {
                new_in.extend(&out[p]);
            }
            let new_out: HashSet<usize> = gen_[bi]
                .iter()
                .copied()
                .chain(new_in.iter().copied().filter(|d| !kill[bi].contains(d)))
                .collect();
            if new_in != in_[bi] || new_out != out[bi] {
                in_[bi] = new_in;
                out[bi] = new_out;
                changed = true;
            }
        }
    }

    // Union defs that a use (or a self-reading def) sees together.
    let mut uf = Uf::new(sites.len());
    // First reaching def seen at a bare `return;` per return register: EVERY
    // range reaching a bare return carries the function's result out through
    // that register, so all such ranges are semantically the same value (the
    // source's `result` variable) and must stay one class. Without this, a
    // switch whose arms each define rax and bare-return splits into per-arm
    // classes, only one of which can keep the canonical spelling — the others
    // are renamed and their return value is silently lost (classify case 7:
    // `v4 <<= a3; return result;` with `result` uninitialised).
    let mut ret_anchor: HashMap<String, usize> = HashMap::new();
    // A bare-return block that assigns xmm0 returns through the FLOAT channel:
    // rax at that return is dead scratch (e.g. a loop counter), and anchoring
    // it would re-merge the counter with the "return slot" name (undoing the
    // D16 counter/result split in float-returning functions like dot()).
    let returns_via_xmm0 = blocks.iter().any(|b| {
        b.stmts.iter().any(|s| matches!(s, Statement::Return(None)))
            && b.stmts.iter().any(|s| {
                matches!(s, Statement::Assign { lhs, .. } if lhs == "xmm0")
                    || matches!(s, Statement::Raw(r)
                        if parse_raw_assign(r).is_some_and(|(l, _)| l == "xmm0"))
            })
    });
    for (bi, b) in blocks.iter().enumerate() {
        let mut cur = in_[bi].clone();
        for (si, s) in b.stmts.iter().enumerate() {
            let du = du_of(bi, si, s);
            if matches!(s, Statement::Return(None)) && !returns_via_xmm0 {
                for u in &du.uses {
                    let Some(&first) =
                        cur.iter().find(|&&d| sites[d].2 == *u)
                    else {
                        continue;
                    };
                    match ret_anchor.get(u) {
                        Some(&a) => {
                            uf.union(a, first);
                        }
                        None => {
                            ret_anchor.insert(u.clone(), first);
                        }
                    }
                }
            }
            // Reads see the current reaching defs of their var.
            for u in &du.uses {
                let reaching: Vec<usize> =
                    cur.iter().copied().filter(|&d| sites[d].2 == *u).collect();
                for w in reaching.windows(2) {
                    uf.union(w[0], w[1]);
                }
            }
            // Apply the def: it kills prior defs of the same var in `cur`.
            if let Some(d) = &du.def {
                let id = site_id[&(bi, si as isize, d.clone())];
                // A def that also reads its var (compound) stays in the read range.
                if du.uses.contains(d) {
                    let reaching: Vec<usize> =
                        cur.iter().copied().filter(|&x| sites[x].2 == *d).collect();
                    for r in reaching {
                        uf.union(id, r);
                    }
                }
                cur.retain(|&x| sites[x].2 != *d);
                cur.insert(id);
            }
        }
    }

    // For each var, collect the class root of every REAL def/use position (the
    // synthetic entry def is ignored unless a real use actually reaches it — a
    // live-in/parameter value). A var splits only when ≥2 such classes exist.
    let mut plans = Vec::new();
    for v in &candidate_vars {
        let ent = uf.find_root(site_id[&(0, -1, v.clone())]);
        // (position, class_root) for every real mention, in program order.
        let mut positions: Vec<((usize, usize), usize)> = Vec::new();
        // The class reaching a bare/explicit `return` for a return register
        // (rax/rdx) — this range must keep the original spelling (see below),
        // since a renamed spelling isn't recognized by the later text-level
        // return-value-alias detection and the return value is silently lost.
        let mut return_root: Option<usize> = None;
        let is_return_reg = RETURN_REGS.contains(&v.as_str());
        for (bi, b) in blocks.iter().enumerate() {
            let mut cur = in_[bi].clone();
            for (si, s) in b.stmts.iter().enumerate() {
                let du = du_of(bi, si, s);
                let is_def = du.def.as_deref() == Some(v.as_str());
                let is_use = du.uses.iter().any(|u| u == v);
                if is_def || is_use {
                    let root = if is_def {
                        uf.find_root(site_id[&(bi, si as isize, v.clone())])
                    } else {
                        match cur.iter().copied().find(|&d| sites[d].2 == *v) {
                            Some(d) => uf.find_root(d),
                            None => ent,
                        }
                    };
                    if is_use && is_return_reg && matches!(s, Statement::Return(_)) {
                        return_root = Some(root);
                    }
                    positions.push(((bi, si), root));
                }
                if let Some(d) = &du.def {
                    let id = site_id[&(bi, si as isize, d.clone())];
                    cur.retain(|&x| sites[x].2 != *d);
                    cur.insert(id);
                }
            }
        }
        // Distinct classes actually used by real positions.
        let mut roots: Vec<usize> = positions.iter().map(|&(_, r)| r).collect();
        roots.sort_unstable();
        roots.dedup();
        if roots.len() < 2 {
            continue; // single live range → no split
        }
        // Version 0 = the class reaching the function's return (if this is a
        // return register — it must keep the canonical name); else the entry
        // class if it is used (a genuine live-in range); else the first real
        // class in program order. The rest get 1, 2, ….
        let mut ver: HashMap<usize, usize> = HashMap::new();
        // D17: the ENTRY class wins version 0 when present. A parameter's
        // live-in range has no materialisable defining copy, so renaming it
        // leaves an undefined local; the return class always has a real
        // defining assignment and can safely be renamed instead.
        if roots.contains(&ent) {
            // If a DIFFERENT class reaches the return, neither can be renamed:
            // the entry class has no materialisable defining copy and the
            // return class must keep the canonical spelling. Only one can be
            // version 0 → this var cannot split safely at all.
            if !returns_via_xmm0
                && return_root.is_some_and(|rr| roots.contains(&rr) && uf.find_root(rr) != uf.find_root(ent))
            {
                continue;
            }
            ver.insert(ent, 0);
        } else if let Some(rr) = return_root.filter(|r| roots.contains(r)) {
            ver.insert(rr, 0);
        }
        let mut next = if ver.is_empty() { 0 } else { 1 };
        for &(_, r) in &positions {
            ver.entry(r).or_insert_with(|| {
                let x = next;
                next += 1;
                x
            });
        }
        let versions = positions.into_iter().map(|(p, r)| (p, ver[&r])).collect();
        plans.push(SplitPlan { var: v.clone(), versions });
    }
    plans.sort_by(|a, b| a.var.cmp(&b.var));
    plans
}

/// Non-argument, non-frozen GP register families usable as fresh split names.
/// Excludes rcx/rdx/r8/r9/rax (argument/return regs the win64 pass rewrites) so
/// a split name never interferes with calling-convention recovery.
const FRESH_POOL: [&str; 9] =
    ["rbx", "rsi", "rdi", "r10", "r11", "r12", "r13", "r14", "r15"];

/// All register-ish identifier tokens mentioned anywhere in `blocks` (so a fresh
/// name can be checked for non-collision).
fn mentioned_idents(blocks: &[BasicBlock]) -> HashSet<String> {
    let mut set = HashSet::new();
    let mut add = |s: &str| set.extend(idents(s));
    for b in blocks {
        for st in &b.stmts {
            match st {
                Statement::Raw(r) | Statement::Branch(r) => add(r),
                Statement::Assign { lhs, rhs } => {
                    add(lhs);
                    add(rhs);
                }
                Statement::Return(Some(v)) => add(v),
                Statement::Return(None) => {}
            }
        }
    }
    set
}

/// Replace whole-word `from` with `to` in a string (identifier-boundary aware).
fn replace_word(s: &str, from: &str, to: &str) -> String {
    if !s.contains(from) {
        return s.to_string();
    }
    let b = s.as_bytes();
    let f = from.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        if i + f.len() <= b.len()
            && &b[i..i + f.len()] == f
            && (i == 0 || !word(b[i - 1]))
            && (i + f.len() == b.len() || !word(b[i + f.len()]))
        {
            out.push_str(to);
            i += f.len();
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

fn rewrite_stmt_var(st: &mut Statement, from: &str, to: &str) {
    match st {
        Statement::Raw(r) | Statement::Branch(r) => *r = replace_word(r, from, to),
        Statement::Assign { lhs, rhs } => {
            *lhs = replace_word(lhs, from, to);
            *rhs = replace_word(rhs, from, to);
        }
        Statement::Return(Some(v)) => *v = replace_word(v, from, to),
        Statement::Return(None) => {}
    }
}

/// Apply [`plan_splits`] to `blocks` in place: each split version ≥1 of a
/// variable is renamed to a fresh, previously-unused register family, so the
/// existing downstream `rename_locals_v1_vn` gives it its own `vN` and
/// `sync_local_declarations` declares it — no naming coordination needed.
///
/// A variable is only split when enough fresh registers are free; otherwise it
/// is left untouched. Functions with no split stay byte-identical.
pub fn split_versions(blocks: &mut Vec<BasicBlock>) {
    // Opt-in: RUSTRE_SSA_SUBREG=1 enables sub-register-aware splitting (see
    // `plan_splits_with`). Unset → historical behavior, byte-identical.
    let subreg = subreg_opt_in(std::env::var("RUSTRE_SSA_SUBREG").ok().as_deref());
    split_versions_with(blocks, subreg);
}

/// Parse the `RUSTRE_SSA_SUBREG` opt-in gate.
///
/// `None` (unset) → disabled, so the default pipeline stays byte-identical.
/// A set-but-falsy value (`0`/``/`false`/`no`/`off`, case- and
/// whitespace-insensitive) → disabled: the previous `env::var(..).is_ok()`
/// test was true for ANY set value, so `RUSTRE_SSA_SUBREG=0` turned the pass
/// ON. Any other set value → enabled (keeps `=1` working).
fn subreg_opt_in(val: Option<&str>) -> bool {
    match val {
        // Default ON since the partial-alias ban was narrowed to partial
        // *writes*: with narrow reads modelled (see `norm_use`), sub-register
        // awareness is what keeps a pointer cursor and an int counter that
        // share one register from collapsing into a single variable (D16).
        // Still overridable — set the var to a falsy value to opt out.
        None => true,
        Some(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "no" | "off"
        ),
    }
}

/// [`split_versions`] with an explicit sub-register-awareness mode (testable
/// without touching the process environment).
pub fn split_versions_with(blocks: &mut Vec<BasicBlock>, subreg_aware: bool) {
    let plans = plan_splits_with(blocks, subreg_aware);
    if plans.is_empty() {
        return;
    }
    let mut used = mentioned_idents(blocks);
    for plan in plans {
        // Highest version index for this var.
        let max_ver = plan.versions.iter().map(|&(_, v)| v).max().unwrap_or(0);
        if max_ver == 0 {
            continue;
        }
        // Allocate a fresh register for each version ≥1.
        let mut names: HashMap<usize, String> = HashMap::new();
        let mut ok = true;
        // Width classes of this variable's narrow aliases mentioned anywhere.
        let narrow_classes: Vec<u8> = {
            let mut c: Vec<u8> = SUBREG_PARTIAL
                .iter()
                .filter(|&&(a, p)| p == plan.var && used.contains(a))
                .map(|&(a, _)| partial_class(a))
                .collect();
            c.sort_unstable();
            c.dedup();
            c
        };
        for ver in 1..=max_ver {
            // The fresh family's 32-bit alias must be free too — a renamed
            // 32-bit-spelled position will be rewritten with it (both modes:
            // use positions may spell the alias even without subreg mode).
            let Some(reg) = FRESH_POOL.iter().find(|r| {
                !used.contains(**r)
                    && sub32_of(r).is_none_or(|s32| !used.contains(s32))
                    // Any narrow (8/16-bit) alias of the split variable that
                    // appears in the function will be rewritten to the fresh
                    // family's alias of the SAME width class, so that class
                    // must exist there and be free (r8–r15 have no high byte).
                    && narrow_classes.iter().all(|&c| {
                        partial_name_for(r, c).is_some_and(|n| !used.contains(n))
                    })
            }) else {
                ok = false;
                break;
            };
            used.insert((*reg).to_string());
            if let Some(s32) = sub32_of(reg) {
                used.insert(s32.to_string());
            }
            for &c in &narrow_classes {
                if let Some(n) = partial_name_for(reg, c) {
                    used.insert(n.to_string());
                }
            }
            names.insert(ver, (*reg).to_string());
        }
        if !ok {
            continue; // not enough free registers → leave this var unsplit
        }
        // Rewrite each version-≥1 position. Within a statement every occurrence
        // of the var is the same version (self-reads stay in-range), so a
        // whole-statement word replace is exact.
        for ((bi, si), ver) in plan.versions {
            if ver >= 1
                && let Some(to) = names.get(&ver)
            {
                rewrite_stmt_var(&mut blocks[bi].stmts[si], &plan.var, to);
                // A position may spell the register with its 32-bit alias
                // (`ecx = 0`, or a use like `printf(fmt, eax)`) — rewrite
                // that to the fresh family's 32-bit alias so the width is
                // preserved. Applies in BOTH modes: use positions normalize
                // 32-bit aliases unconditionally (see `norm_use`).
                if let (Some(from32), Some(to32)) = (sub32_of(&plan.var), sub32_of(to))
                {
                    rewrite_stmt_var(&mut blocks[bi].stmts[si], from32, to32);
                }
                // Likewise for narrow reads (`dl`, `cx`): rewrite to the fresh
                // family's alias of the same width class, so the split does not
                // leave the old register name spelled at a renamed position.
                for &c in &narrow_classes {
                    if let (Some(f), Some(t)) =
                        (partial_name_for(&plan.var, c), partial_name_for(to, c))
                    {
                        rewrite_stmt_var(&mut blocks[bi].stmts[si], f, t);
                    }
                }
            }
        }
    }
}

// ── cross-block copy propagation (rewrite-only) ─────────────────────────────

/// Reaching-definitions over the block CFG, computed independently of
/// [`plan_splits`] (which keeps its own inline copy) so this pass cannot perturb
/// the validated split output.
struct Reaching {
    sites: Vec<(usize, isize, String)>,
    site_id: HashMap<(usize, isize, String), usize>,
    in_: Vec<HashSet<usize>>,
}

impl Reaching {
    /// The reaching-def ids of `var` immediately BEFORE statement `(tbi, tsi)`.
    fn reaching(&self, blocks: &[BasicBlock], tbi: usize, tsi: usize, var: &str) -> Vec<usize> {
        let mut cur = self.in_[tbi].clone();
        for (si, s) in blocks[tbi].stmts.iter().enumerate() {
            if si == tsi {
                break;
            }
            if let Some(d) = stmt_def_use(s).def {
                cur.retain(|&x| self.sites[x].2 != d);
                cur.insert(self.site_id[&(tbi, si as isize, d)]);
            }
        }
        cur.into_iter().filter(|&d| self.sites[d].2 == var).collect()
    }
}

fn compute_reaching(blocks: &[BasicBlock]) -> Reaching {
    let id_to_idx: HashMap<u32, usize> =
        blocks.iter().enumerate().map(|(i, b)| (b.id.0, i)).collect();
    let mut sites: Vec<(usize, isize, String)> = Vec::new();
    let mut candidate_vars: HashSet<String> = HashSet::new();
    for (bi, b) in blocks.iter().enumerate() {
        for (si, s) in b.stmts.iter().enumerate() {
            let du = stmt_def_use(s);
            for u in &du.uses {
                candidate_vars.insert(u.clone());
            }
            if let Some(d) = du.def {
                candidate_vars.insert(d.clone());
                sites.push((bi, si as isize, d));
            }
        }
    }
    for v in &candidate_vars {
        sites.push((0, -1, v.clone()));
    }
    let site_id: HashMap<(usize, isize, String), usize> =
        sites.iter().enumerate().map(|(i, s)| (s.clone(), i)).collect();
    if sites.is_empty() {
        return Reaching { sites, site_id, in_: vec![HashSet::new(); blocks.len()] };
    }
    let mut defs_of: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, (_, _, v)) in sites.iter().enumerate() {
        defs_of.entry(v.as_str()).or_default().push(i);
    }
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
    for (bi, b) in blocks.iter().enumerate() {
        for s in &b.successors {
            if let Some(&ti) = id_to_idx.get(&s.0) {
                preds[ti].push(bi);
            }
        }
    }
    let mut gen_: Vec<HashSet<usize>> = vec![HashSet::new(); blocks.len()];
    let mut kill: Vec<HashSet<usize>> = vec![HashSet::new(); blocks.len()];
    for (bi, b) in blocks.iter().enumerate() {
        let mut last: HashMap<String, usize> = HashMap::new();
        for (si, s) in b.stmts.iter().enumerate() {
            if let Some(d) = stmt_def_use(s).def {
                last.insert(d, si);
            }
        }
        for (v, si) in &last {
            let id = site_id[&(bi, *si as isize, v.clone())];
            gen_[bi].insert(id);
            for &other in &defs_of[v.as_str()] {
                if other != id {
                    kill[bi].insert(other);
                }
            }
        }
    }
    let mut in_: Vec<HashSet<usize>> = vec![HashSet::new(); blocks.len()];
    let mut out: Vec<HashSet<usize>> = vec![HashSet::new(); blocks.len()];
    for v in &candidate_vars {
        in_[0].insert(site_id[&(0, -1, v.clone())]);
    }
    let mut changed = true;
    while changed {
        changed = false;
        for bi in 0..blocks.len() {
            let mut new_in: HashSet<usize> = if bi == 0 {
                candidate_vars.iter().map(|v| site_id[&(0, -1, v.clone())]).collect()
            } else {
                HashSet::new()
            };
            for &p in &preds[bi] {
                new_in.extend(&out[p]);
            }
            let new_out: HashSet<usize> = gen_[bi]
                .iter()
                .copied()
                .chain(new_in.iter().copied().filter(|d| !kill[bi].contains(d)))
                .collect();
            if new_in != in_[bi] || new_out != out[bi] {
                in_[bi] = new_in;
                out[bi] = new_out;
                changed = true;
            }
        }
    }
    Reaching { sites, site_id, in_ }
}

/// If `s` is a pure register copy `x = y` (both candidate registers, RHS a lone
/// bare identifier — no operator/deref/index/call/constant), return `(x, y)`.
fn is_copy(s: &Statement) -> Option<(String, String)> {
    let x = stmt_def_use(s).def?;
    let rhs = match s {
        Statement::Assign { rhs, .. } => rhs.trim().trim_end_matches(';').trim().to_string(),
        Statement::Raw(r) => parse_raw_assign(r)?.1,
        _ => return None,
    };
    let toks = idents(&rhs);
    if toks.len() != 1 || rhs != toks[0] {
        return None;
    }
    let y = toks[0].clone();
    if !is_candidate(&y) || x == y {
        return None;
    }
    Some((x, y))
}

/// Plan cross-block copy forwards: for each pure copy `x = y`, at every USE of x
/// (excluding positions that also DEFINE x — compound/self-assign) where the copy
/// is the UNIQUE reaching def of x AND y's reaching def is unchanged from the
/// copy point, record a rewrite of that use `x → y`. Rewrite-only (no removal).
#[must_use]
pub fn plan_copy_forwards(blocks: &[BasicBlock]) -> Vec<((usize, usize), String, String)> {
    if blocks.is_empty() {
        return Vec::new();
    }
    let r = compute_reaching(blocks);
    if r.sites.is_empty() {
        return Vec::new();
    }
    let mut rewrites: Vec<((usize, usize), String, String)> = Vec::new();
    for (bi, b) in blocks.iter().enumerate() {
        for (si, s) in b.stmts.iter().enumerate() {
            let Some((x, y)) = is_copy(s) else { continue };
            let copy_id = r.site_id[&(bi, si as isize, x.clone())];
            let ry = r.reaching(blocks, bi, si, &y);
            if ry.len() != 1 {
                continue; // y already ambiguous at the copy
            }
            let ry = ry[0];
            for (ubi, ub) in blocks.iter().enumerate() {
                for (usi, us) in ub.stmts.iter().enumerate() {
                    let du = stmt_def_use(us);
                    // Never rewrite a position that also DEFINES x (compound /
                    // self-assign) — replacing there would change the def name.
                    if du.def.as_deref() == Some(x.as_str()) || !du.uses.iter().any(|u| *u == x) {
                        continue;
                    }
                    let rx = r.reaching(blocks, ubi, usi, &x);
                    let ryu = r.reaching(blocks, ubi, usi, &y);
                    if rx.len() == 1 && rx[0] == copy_id && ryu.len() == 1 && ryu[0] == ry {
                        rewrites.push(((ubi, usi), x.clone(), y.clone()));
                    }
                }
            }
        }
    }
    rewrites
}

/// Return registers that may carry a value out of the function (System V / win64
/// integer returns are `rax`, with `rdx` for the high half of a 128-bit return).
/// A dead copy whose destination is one of these must NOT be removed.
const RETURN_REGS: [&str; 2] = ["rax", "rdx"];

/// Apply cross-block copy propagation in place: forward each safe copy use
/// `x → y`, then remove the copy `x = y` if `x` has no surviving use anywhere
/// and is not a return register (so it cannot be live out of the function).
/// Callee-saved and argument registers are restored/caller-owned, so a dead
/// intermediate assignment to them is genuinely dead. Functions with no
/// forwardable copy stay byte-identical.
pub fn propagate_copies(blocks: &mut [BasicBlock]) {
    let rewrites = plan_copy_forwards(blocks);
    if rewrites.is_empty() {
        return;
    }
    // The copy sites (x = y) whose uses we are forwarding.
    let mut copy_sites: Vec<(usize, usize, String)> = Vec::new();
    for (bi, b) in blocks.iter().enumerate() {
        for (si, s) in b.stmts.iter().enumerate() {
            if let Some((x, _)) = is_copy(s) {
                copy_sites.push((bi, si, x));
            }
        }
    }
    for ((bi, si), x, y) in rewrites {
        rewrite_stmt_var(&mut blocks[bi].stmts[si], &x, &y);
    }
    // Dead-copy removal: after forwarding, a copy `x = y` whose `x` is now read
    // nowhere and is not a return register is dead.
    let mut remove: HashSet<(usize, usize)> = HashSet::new();
    for (bi, si, x) in &copy_sites {
        if RETURN_REGS.contains(&x.as_str()) {
            continue;
        }
        let still_used = blocks.iter().enumerate().any(|(ubi, ub)| {
            ub.stmts.iter().enumerate().any(|(usi, us)| {
                (ubi, usi) != (*bi, *si) && stmt_def_use(us).uses.iter().any(|u| u == x)
            })
        });
        if !still_used {
            remove.insert((*bi, *si));
        }
    }
    if remove.is_empty() {
        return;
    }
    for (bi, b) in blocks.iter_mut().enumerate() {
        let mut si = 0;
        b.stmts.retain(|_| {
            let keep = !remove.contains(&(bi, si));
            si += 1;
            keep
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_decompiler_cfs::BlockId;

    fn blk(id: u32, stmts: Vec<Statement>, succ: Vec<u32>) -> BasicBlock {
        BasicBlock::new(BlockId::new(id))
            .with_stmts(stmts)
            .with_successors(succ.into_iter().map(BlockId::new).collect())
    }
    fn raw(s: &str) -> Statement {
        Statement::Raw(s.to_string())
    }
    fn split_vars(plans: &[SplitPlan]) -> Vec<&str> {
        plans.iter().map(|p| p.var.as_str()).collect()
    }

    /// D1 regression (fuzz seed 1): a call result (`rax = f1_1(...)`) consumed
    /// by a later call argument spelled with the 32-BIT alias
    /// (`__mingw_printf(rcx, eax);` — the form `infer_call_arguments` leaves
    /// after folding `edx = eax`) must stay in ONE live range with its def.
    /// The alias use was invisible to the plan, so the def looked dead, was
    /// split to a fresh family, and the emitted C read an uninitialised
    /// variable while the live call got `// DCE(df)`-commented out.
    #[test]
    fn call_result_used_via_32bit_alias_arg_stays_connected() {
        let mut blocks = vec![blk(
            0,
            vec![
                raw("rax = f1_1(43, 30);"),
                raw("__mingw_printf(rcx, eax);"),
                raw("rax = f1_3(77);"),
                Statement::Return(Some("rax".to_string())),
            ],
            vec![],
        )];
        // The plan must put the f1_1 def and the eax use in the SAME class.
        let plans = plan_splits(&blocks);
        if let Some(p) = plans.iter().find(|p| p.var == "rax") {
            let v_def = p.versions.iter().find(|&&((_, si), _)| si == 0).map(|&(_, v)| v);
            let v_use = p.versions.iter().find(|&&((_, si), _)| si == 1).map(|&(_, v)| v);
            assert_eq!(v_def, v_use, "f1_1 def and eax arg use must share a version: {p:?}");
        }
        // And after applying the split, whatever name the call result gets,
        // the printf argument must spell (the 32-bit alias of) the SAME family.
        split_versions_with(&mut blocks, false);
        let stmts = &blocks[0].stmts;
        let Statement::Raw(call) = &stmts[0] else { panic!() };
        let Statement::Raw(printf) = &stmts[1] else { panic!() };
        let fam = call.split(" = ").next().unwrap().trim();
        let expected32 = sub32_of(fam).unwrap_or(fam);
        assert!(
            printf.contains(expected32) || printf.contains(fam),
            "printf arg lost the call-result family: call={call:?} printf={printf:?}"
        );
    }

    /// D6 regression (`apply`, sample6_c): a flag-copy select. `rcx` (param
    /// `a1`/use_mul) is read by the flag test that feeds the cmov branch, then a
    /// DEAD argument-register shuffle (`mov %edx,%ecx` — x → the callee's arg1
    /// register for the tail call) re-writes `ecx`. In the default (non-subreg)
    /// path a 32-bit write was not a def, so `rcx` never split: the dead shuffle
    /// kept the name `a1` and DCE commented `// DCE(df): a1 = a2;` right above
    /// `if (a1 != 0)`, reading as if it clobbered the branch variable. Treating
    /// the zero-extending 32-bit copy as a full def splits the dead range off to
    /// a fresh register, so the parameter range keeps `rcx` and the branch is
    /// unambiguous.
    #[test]
    fn dead_32bit_copy_shuffle_splits_off_the_live_parameter() {
        let mut blocks = vec![blk(
            0,
            vec![
                raw("rax = &add_fn;"),
                raw("/* test ecx , ecx */"), // flag test reads rcx (= param a1)
                Statement::Assign { lhs: "ecx".into(), rhs: "edx".into() }, // dead shuffle
                raw("rdx = &mul_fn;"),
                raw("if (flags !=) rax = rdx;"), // cmov (flag from the test above)
                Statement::Return(Some("JUMPOUT(rax)".to_string())),
            ],
            vec![],
        )];
        // rcx must split: the entry/param range (read by the test) is version 0,
        // the dead `ecx = edx` def is a fresh version ≥1.
        let plans = plan_splits(&blocks);
        let rcx = plans.iter().find(|p| p.var == "rcx").expect("rcx must split");
        let def_ver = rcx
            .versions
            .iter()
            .find(|&&((_, si), _)| si == 2) // the `ecx = edx` statement
            .map(|&(_, v)| v)
            .expect("copy def present");
        assert!(def_ver >= 1, "dead shuffle must get a fresh version: {rcx:?}");

        split_versions_with(&mut blocks, false);
        // The shuffle no longer writes ecx/rcx (renamed to a fresh family), so
        // the parameter `rcx` is never shadowed before the flag test's branch.
        let Statement::Assign { lhs, .. } = &blocks[0].stmts[2] else { panic!() };
        assert_ne!(lhs, "ecx", "dead shuffle still shadows the a1 parameter: {lhs}");
    }

    /// D17 regression (sample11 sum_varargs): `rdx` is BOTH the incoming
    /// parameter and the early-exit return temp (`rdx = 0; return rdx;`).
    /// The ENTRY class must keep version 0 (the canonical `rdx` spelling) —
    /// a parameter live-in range has no materialisable defining copy, so
    /// renaming it emits an undefined local and silently drops the argument.
    /// The return class does have a real def and is the one that may be renamed.
    #[test]
    fn param_and_early_exit_return_share_reg_entry_class_keeps_name() {
        let mk = || {
            vec![
                blk(0, vec![raw("rax = rcx")], vec![1, 2]),
                // early exit: rdx used as a return temp with a real def
                blk(1, vec![raw("rdx = 0"), Statement::Return(Some("rdx".to_string()))], vec![]),
                // main path: rdx is the incoming parameter, live-in, no def
                blk(2, vec![raw("rbx = rdx"), Statement::Return(Some("rbx".to_string()))], vec![]),
            ]
        };
        for subreg in [false, true] {
            let blocks = mk();
            let plans = plan_splits_with(&blocks, subreg);
            if let Some(p) = plans.iter().find(|p| p.var == "rdx") {
                // the parameter use (block 2, stmt 0) must be version 0
                let v_param = p
                    .versions
                    .iter()
                    .find(|&&((bi, si), _)| bi == 2 && si == 0)
                    .map(|&(_, v)| v);
                assert_eq!(v_param, Some(0), "entry/param class must be version 0 (subreg={subreg}): {p:?}");
            }
            // and after applying the split the parameter must still spell `rdx`
            let mut blocks = mk();
            split_versions_with(&mut blocks, subreg);
            let txt = match &blocks[2].stmts[0] {
                Statement::Raw(r) => r.clone(),
                _ => String::new(),
            };
            assert!(
                txt.contains("rdx"),
                "parameter use must keep the canonical rdx spelling (subreg={subreg}), got {txt:?}"
            );
        }
    }

    /// D5 regression (fuzz seed 4, f4_3): strength-reduced `x - 4*x` where gcc
    /// writes the 32-bit alias (`lea 0x56(%rax), %edx`) and the very next
    /// multiply reads the 64-bit parent (`lea (,%rdx,4), %r8d`). The multiply's
    /// `rdx` use must stay in the SAME live range/version as the just-written
    /// `edx` def — never get attached to (or renamed against) an earlier rdx
    /// range, which made the emitted C read the previous iteration's value
    /// (`v6 = v5*4` instead of `v6 = v3*4`; f4_3(30) returned 2100, not 1276).
    #[test]
    fn multiply_after_32bit_alias_def_reads_just_written_value() {
        let stmts = || {
            vec![
                raw("rdx = rax"),       // earlier, unrelated rdx range (stale value)
                raw("rcx = rdx"),       // last use of that range
                raw("edx = eax + 86"),  // 32-bit def: full (zero-extending) def of rdx
                raw("r8 = rdx * 4"),    // strength-reduced multiply reads the NEW value
                raw("edx = edx - r8d"),
                Statement::Return(Some("rdx".to_string())),
            ]
        };
        // Sub-register-aware plan: the multiply use must share a version with
        // the alias def, and NOT with the earlier stale def.
        let blocks = vec![blk(0, stmts(), vec![])];
        let plans = plan_splits_with(&blocks, true);
        if let Some(p) = plans.iter().find(|p| p.var == "rdx") {
            let ver_at = |si: usize| {
                p.versions.iter().find(|&&((_, s), _)| s == si).map(|&(_, v)| v)
            };
            let (def_old, def_new, mul_use) = (ver_at(0), ver_at(2), ver_at(3));
            assert_eq!(def_new, mul_use, "multiply must read the just-written def: {p:?}");
            assert_ne!(def_old, mul_use, "multiply must NOT read the stale range: {p:?}");
        }
        // Both modes: after applying the split, the multiply operand must spell
        // the same register family as the statement just above it.
        for subreg in [false, true] {
            let mut blocks = vec![blk(0, stmts(), vec![])];
            split_versions_with(&mut blocks, subreg);
            let text: Vec<String> = blocks[0]
                .stmts
                .iter()
                .map(|s| match s {
                    Statement::Raw(r) => r.clone(),
                    _ => String::new(),
                })
                .collect();
            let def_fam = text[2].split(' ').next().unwrap(); // e.g. edx or a rename's 32-bit alias
            let def_parent = canon32(def_fam).unwrap_or(def_fam);
            let mul_src = text[3]
                .split(" = ")
                .nth(1)
                .unwrap()
                .split(" *")
                .next()
                .unwrap()
                .trim();
            let mul_parent = canon32(mul_src).unwrap_or(mul_src);
            assert_eq!(
                mul_parent, def_parent,
                "subreg={subreg}: multiply reads stale family: {text:?}"
            );
        }
    }

    #[test]
    fn straight_line_reuse_splits() {
        // rbx is a pointer, fully consumed, then reused as an unrelated scalar.
        let b = blk(
            0,
            vec![
                raw("rbx = rcx"),
                raw("rdx = rbx"),   // last use of range-1
                raw("rbx = 0"),     // range-2 starts (no self-read)
                raw("rax = rbx"),   // use of range-2
                Statement::Return(None),
            ],
            vec![],
        );
        let plans = plan_splits(std::slice::from_ref(&b));
        assert!(split_vars(&plans).contains(&"rbx"), "rbx must split: {plans:?}");
        let p = plans.iter().find(|p| p.var == "rbx").unwrap();
        // Two distinct versions present.
        let vers: std::collections::HashSet<usize> = p.versions.iter().map(|(_, v)| *v).collect();
        assert_eq!(vers.len(), 2, "{p:?}");
    }

    #[test]
    fn parameter_live_in_at_merge_does_not_split() {
        // rcx is a parameter (live-in). One branch redefines it; the merge use
        // sees both the entry value and the redef → a phi point → NO split.
        let entry = blk(0, vec![Statement::Branch("rax == 0".to_string())], vec![1, 2]);
        let then_b = blk(1, vec![raw("rcx = rax")], vec![3]);
        let else_b = blk(2, vec![], vec![3]);
        let merge = blk(3, vec![raw("rdx = rcx"), Statement::Return(None)], vec![]);
        let plans = plan_splits(&[entry, then_b, else_b, merge]);
        assert!(!split_vars(&plans).contains(&"rcx"), "param at merge must NOT split: {plans:?}");
    }

    #[test]
    fn bare_return_ranges_of_return_reg_never_renamed() {
        // Two disjoint switch-arm ranges of rax, each ending in its own bare
        // `return;` (the classify @0x1400014a0 shape). Every range reaching a
        // bare return carries the function's result out through rax — renaming
        // ANY of them silently drops that arm's return value (the text-level
        // return-alias detection only recognises the canonical spelling).
        let head = blk(0, vec![Statement::Branch("rcx".to_string())], vec![1, 2]);
        let arm_a =
            blk(1, vec![raw("rax = rdx"), raw("rax = rax - r8"), Statement::Return(None)], vec![]);
        let arm_b =
            blk(2, vec![raw("rax = r8"), raw("rax = rax << 2"), Statement::Return(None)], vec![]);
        let mut blocks = vec![head, arm_a, arm_b];
        split_versions(&mut blocks);
        let text = body_text(&blocks);
        for t in &text {
            assert!(
                !t.contains("rbx") && !t.contains("rsi") && !t.contains("rdi"),
                "a bare-return-reaching rax range was renamed: {text:?}"
            );
        }
        assert!(text.contains(&"rax = rdx".to_string()), "{text:?}");
        assert!(text.contains(&"rax = r8".to_string()), "{text:?}");
    }

    #[test]
    fn loop_carried_counter_does_not_split() {
        // rbx defined in the header-preceding block and incremented in the loop
        // body forms ONE live range across the back edge → NO split.
        let pre = blk(0, vec![raw("rbx = 0")], vec![1]);
        let body = blk(
            1,
            vec![raw("rbx += 1"), Statement::Branch("rbx < 10".to_string())],
            vec![1, 2], // back edge to self + exit
        );
        let exit = blk(2, vec![raw("rax = rbx"), Statement::Return(None)], vec![]);
        let plans = plan_splits(&[pre, body, exit]);
        assert!(!split_vars(&plans).contains(&"rbx"), "loop counter must NOT split: {plans:?}");
    }

    #[test]
    fn frozen_registers_never_split() {
        let b = blk(
            0,
            vec![raw("rsp = rsp + 8"), raw("rbp = rsp"), Statement::Return(None)],
            vec![],
        );
        let plans = plan_splits(std::slice::from_ref(&b));
        assert!(plans.is_empty(), "frozen regs must never be candidates: {plans:?}");
    }

    #[test]
    fn split_versions_renames_second_range_to_fresh_register() {
        let mut blocks = vec![blk(
            0,
            vec![
                raw("rbx = rcx"),
                raw("rdx = rbx"),
                raw("rbx = 0"),
                raw("rax = rbx"),
                Statement::Return(None),
            ],
            vec![],
        )];
        split_versions(&mut blocks);
        let text: Vec<String> = blocks[0]
            .stmts
            .iter()
            .map(|s| match s {
                Statement::Raw(r) => r.clone(),
                _ => String::new(),
            })
            .collect();
        // range-1 keeps rbx; range-2 became a fresh unused register.
        assert_eq!(text[0], "rbx = rcx");
        assert_eq!(text[1], "rdx = rbx");
        assert_ne!(text[2], "rbx = 0", "range-2 def must be renamed: {text:?}");
        assert!(text[2].ends_with("= 0"));
        // The two ranges now use different names.
        let v2name = text[2].split(' ').next().unwrap();
        assert_ne!(v2name, "rbx");
        assert_eq!(text[3], format!("rax = {v2name}"));
    }

    #[test]
    fn split_versions_noop_when_nothing_splits() {
        // A loop counter must not split → blocks unchanged.
        let mut blocks = vec![
            blk(0, vec![raw("rbx = 0")], vec![1]),
            blk(1, vec![raw("rbx += 1"), Statement::Branch("rbx < 10".to_string())], vec![1, 2]),
            blk(2, vec![raw("rax = rbx"), Statement::Return(None)], vec![]),
        ];
        let before = format!("{blocks:?}");
        split_versions(&mut blocks);
        assert_eq!(before, format!("{blocks:?}"), "no split → byte-identical");
    }

    #[test]
    fn unrelated_function_produces_no_plan() {
        // Single def, single use → nothing to split.
        let b = blk(0, vec![raw("rax = rcx"), Statement::Return(Some("rax".to_string()))], vec![]);
        assert!(plan_splits(std::slice::from_ref(&b)).is_empty());
    }

    fn body_text(blocks: &[BasicBlock]) -> Vec<String> {
        blocks
            .iter()
            .flat_map(|b| b.stmts.iter())
            .filter_map(|s| match s {
                Statement::Raw(r) | Statement::Branch(r) => Some(r.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn copyprop_forwards_across_blocks() {
        // rbx = rcx in block 0; the use of rbx in block 2 (after a branch) is
        // forwarded to rcx — the straight-line text pass can't cross the branch.
        let mut blocks = vec![
            blk(0, vec![raw("rbx = rcx"), Statement::Branch("rax == 0".to_string())], vec![1, 2]),
            blk(1, vec![], vec![2]),
            blk(2, vec![raw("rdx = rbx"), Statement::Return(None)], vec![]),
        ];
        propagate_copies(&mut blocks);
        assert!(body_text(&blocks).contains(&"rdx = rcx".to_string()), "{blocks:?}");
    }

    #[test]
    fn copyprop_must_not_cross_redef_of_y() {
        // rbx = rcx; rcx = rdx; ... rdx2 = rbx  → forwarding to rcx is WRONG
        // (rcx now holds rdx). Must stay `= rbx`.
        let mut blocks = vec![blk(
            0,
            vec![raw("rbx = rcx"), raw("rcx = rdx"), raw("rsi = rbx"), Statement::Return(None)],
            vec![],
        )];
        propagate_copies(&mut blocks);
        assert!(body_text(&blocks).contains(&"rsi = rbx".to_string()), "must not forward: {blocks:?}");
    }

    #[test]
    fn copyprop_must_not_cross_merge() {
        // x defined on both branches → the merge use has two reaching defs.
        let mut blocks = vec![
            blk(0, vec![Statement::Branch("rax == 0".to_string())], vec![1, 2]),
            blk(1, vec![raw("rbx = rcx")], vec![3]),
            blk(2, vec![raw("rbx = rdx")], vec![3]),
            blk(3, vec![raw("rsi = rbx"), Statement::Return(None)], vec![]),
        ];
        let before = format!("{blocks:?}");
        propagate_copies(&mut blocks);
        assert_eq!(before, format!("{blocks:?}"), "merge must not forward");
    }

    /// The exact block shape of corpus `accumulate` (sample1_c @ 0x140001460):
    /// rcx enters as the `pts` pointer parameter; `ecx = 0` (a 32-bit write,
    /// which zero-extends into rcx per AMD APM vol. 3, 24594 rev 3.34) starts
    /// an unrelated accumulator live range.
    fn accumulate_blocks() -> Vec<BasicBlock> {
        vec![
            blk(0, vec![Statement::Branch("edx <= 0".to_string())], vec![1, 4]),
            blk(
                1,
                vec![raw("rax = rcx"), raw("rdx = edx"), raw("rdx = rdx + rdx*2"),
                     raw("r8 = rcx + rdx*8"), raw("ecx = 0")],
                vec![2],
            ),
            blk(
                2,
                vec![raw("rdx = *(rax + 8)"), raw("rdx = rdx + *rax"),
                     raw("*(rax + 0x10) = rdx"), raw("rcx = rcx + rdx"),
                     raw("rax = rax + 0x18"), Statement::Branch("rax != r8".to_string())],
                vec![3, 2],
            ),
            blk(3, vec![raw("rax = rcx"), Statement::Return(None)], vec![]),
            blk(4, vec![raw("ecx = 0")], vec![3]),
        ]
    }

    #[test]
    fn subreg_aware_splits_32bit_zeroed_accumulator() {
        let blocks = accumulate_blocks();
        // Default mode must be unchanged: it cannot see `ecx = 0` as a def of
        // rcx, so rcx must NOT split (this is the historical behavior).
        assert!(
            !split_vars(&plan_splits(&blocks)).contains(&"rcx"),
            "default mode must be unchanged"
        );
        // Sub-register-aware mode: `ecx = 0` is a full def of rcx, so the
        // pointer range and the accumulator range are disjoint → split.
        let plans = plan_splits_with(&blocks, true);
        let p = plans
            .iter()
            .find(|p| p.var == "rcx")
            .expect("subreg-aware mode must split rcx");
        let vers: std::collections::HashSet<usize> =
            p.versions.iter().map(|(_, v)| *v).collect();
        assert_eq!(vers.len(), 2, "{p:?}");
    }

    #[test]
    fn subreg_partial_write_poisons_candidate() {
        // Same shape, but the redefinition is an 8-bit write. `cl = 0` does
        // NOT zero-extend (APM: high bits of byte operands are not modified),
        // so rcx's ranges are not provably disjoint → NO split, even opted in.
        let mut blocks = accumulate_blocks();
        blocks[1].stmts[4] = raw("cl = 0");
        blocks[4].stmts[0] = raw("cl = 0");
        let plans = plan_splits_with(&blocks, true);
        assert!(
            !split_vars(&plans).contains(&"rcx"),
            "8-bit partial write must poison rcx: {plans:?}"
        );
    }

    /// D16: a pointer-advancing range and an integer-counting range that share
    /// one architectural register must NOT be unified.
    ///
    /// Shape (min_d14 `g`, 0x140001460): `rdx` is the fill loop's pointer cursor
    /// (`rdx = rsp`, `rdx += 4`), then `edx = 0` starts the consume loop's int
    /// counter (`edx += 1`, `edx == 6`). The only narrow mention is the READ in
    /// `test $1, %dl`. Before the fix that read poisoned rdx wholesale, the two
    /// ranges merged into one pointer-typed variable, and `++i` strode 4 bytes
    /// against an `i == 6` test — a loop that never terminates and runs off the
    /// end of the buffer. A partial READ carries no zero-extension hazard, so
    /// only partial WRITES may disqualify the register.
    fn cursor_then_counter_blocks() -> Vec<BasicBlock> {
        vec![
            blk(0, vec![raw("rdx = rsp"), raw("rcx = rcx + 0x228")], vec![1]),
            blk(
                1,
                vec![raw("*rdx = rax"), raw("rax = rax + 0x5C"), raw("rdx = rdx + 4"),
                     Statement::Branch("rax != rcx".to_string())],
                vec![1, 2],
            ),
            // New live range: 32-bit zeroing def of the same parent register.
            blk(2, vec![raw("edx = 0")], vec![3]),
            blk(
                3,
                vec![raw("rax = *r8"), raw("edx = edx + 1"),
                     // Narrow READ of the counter — must not poison rdx.
                     Statement::Branch("dl & 1".to_string())],
                vec![3, 4],
            ),
            blk(4, vec![Statement::Return(None)], vec![]),
        ]
    }

    #[test]
    fn pointer_cursor_and_int_counter_are_not_unified() {
        let blocks = cursor_then_counter_blocks();
        let plans = plan_splits_with(&blocks, true);
        assert!(
            split_vars(&plans).contains(&"rdx"),
            "cursor and counter ranges must split: {plans:?}"
        );
    }

    #[test]
    fn narrow_read_is_renamed_with_its_range() {
        // The rewrite must carry the `dl` read into the fresh family, or the
        // renamed counter would leave a dangling mention of the old register.
        let mut blocks = cursor_then_counter_blocks();
        split_versions_with(&mut blocks, true);
        let text = body_text(&blocks).join("\n");
        // Whichever side moves, the cursor's stride and the counter's increment
        // must end up on DIFFERENT variables — that is the whole defect.
        let cursor = text
            .lines()
            .find_map(|l| l.strip_suffix(" + 4").and_then(|p| p.split(" = ").next()))
            .expect("cursor stride line")
            .to_string();
        let counter = text
            .lines()
            .find_map(|l| l.strip_suffix(" + 1").and_then(|p| p.split(" = ").next()))
            .expect("counter increment line")
            .to_string();
        assert_ne!(
            canon32(&counter).unwrap_or(&counter),
            canon32(&cursor).unwrap_or(&cursor),
            "cursor and counter must be distinct variables: {text}"
        );
        // The narrow read must stay attached to the counter's family.
        let dl = text.lines().find(|l| l.ends_with("& 1")).expect("narrow read");
        let dl_reg = dl.split(" &").next().unwrap();
        assert_eq!(
            partial_alias(dl_reg).unwrap_or(dl_reg),
            canon32(&counter).unwrap_or(&counter),
            "narrow read must follow the counter range: {text}"
        );
    }

    #[test]
    fn split_versions_subreg_renames_32bit_alias_consistently() {
        // End-to-end rewrite: the accumulator range (including its 32-bit
        // spelling `ecx`) is renamed to one fresh register family; the pointer
        // parameter range keeps `rcx`.
        let mut blocks = accumulate_blocks();
        split_versions_with(&mut blocks, true);
        let text = body_text(&blocks);
        // The parameter range keeps its original name as the copy SOURCE.
        // (The copy's destination rax may itself be split — that default
        // rax/rdx splitting is unchanged and checked by the sibling test —
        // so the LHS spelling is not asserted here.)
        assert!(text.iter().any(|t| t.ends_with(" = rcx")), "{text:?}");
        assert!(text.contains(&"r8 = rcx + rdx*8".to_string()), "{text:?}");
        // The accumulator def is renamed away from ecx/rcx …
        assert!(!text.contains(&"ecx = 0".to_string()), "accumulator def must be renamed: {text:?}");
        assert!(!text.contains(&"rcx = rcx + rdx".to_string()), "accumulator add must be renamed: {text:?}");
        // … and all three accumulator positions agree on ONE fresh family:
        // the def `eN = 0` (32-bit spelling preserved), the add, the ret copy.
        let def_line = text.iter().find(|t| t.ends_with(" = 0") && t.contains('e') && !t.starts_with("rdx")).cloned();
        assert!(def_line.is_some(), "renamed 32-bit def missing: {text:?}");
    }

    #[test]
    fn split_versions_default_ignores_subreg_defs() {
        // Without the opt-in, the same input stays byte-identical for rcx
        // (rax/rdx may still split as before — that behavior is unchanged).
        let mut blocks = accumulate_blocks();
        split_versions_with(&mut blocks, false);
        let text = body_text(&blocks);
        assert!(text.contains(&"ecx = 0".to_string()), "{text:?}");
        assert!(text.contains(&"rcx = rcx + rdx".to_string()), "{text:?}");
    }

    #[test]
    fn subreg_opt_in_flag_parsing() {
        // Unset → disabled (historical default must stay byte-identical).
        assert!(subreg_opt_in(None), "default is now ON");
        // Explicitly truthy → enabled.
        for v in ["1", "true", "TRUE", "yes", "on", "On"] {
            assert!(subreg_opt_in(Some(v)), "{v:?} must enable");
        }
        // Explicitly falsy → disabled. `env::var(..).is_ok()` used to return
        // true for ANY set value, so `RUSTRE_SSA_SUBREG=0` silently ENABLED
        // the pass — the opposite of what it says.
        for v in ["0", "", "false", "FALSE", "no", "off", "  0  "] {
            assert!(!subreg_opt_in(Some(v)), "{v:?} must NOT enable");
        }
    }

    #[test]
    fn copyprop_rejects_non_copy_rhs() {
        // `rbx = rcx + 1` and `rbx = *(rcx + 8)` are not pure copies.
        assert!(is_copy(&raw("rbx = rcx + 1")).is_none());
        assert!(is_copy(&raw("rbx = *(rcx + 8)")).is_none());
        assert!(is_copy(&raw("rbx = 0")).is_none());
        assert!(is_copy(&raw("rbx = rbx")).is_none());
        assert_eq!(is_copy(&raw("rbx = rcx")), Some(("rbx".into(), "rcx".into())));
        // A frozen register is never a copy source.
        assert!(is_copy(&raw("rbx = rsp")).is_none());
    }
}
