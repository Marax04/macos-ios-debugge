//! MLIL-SSA-driven register reuse splitting — opt-in IL integration slice.
//!
//! The text-level `ssa_split` pass misses one recurring shape: a *parameter
//! register* that is later clobbered inside a loop body as a scratch temp
//! (ground truth `accumulate`: `edx` is the `n` parameter, and the loop body
//! re-defines `rdx` as the per-element sum). The emitted C then shows the
//! parameter name (`a2`) meaning two unrelated things.
//!
//! This module uses REAL MLIL SSA form (`rustre_il_mlil::MlilFunction::into_ssa`,
//! i.e. phi placement + version renaming from the `rustre-il-*` stack) as the
//! decision oracle:
//!
//! 1. [`reuse_hints`] — build SSA over the function's MLIL CFG, group the SSA
//!    versions of each x86 GPR *family* (rdx/edx/dx/dl…) into def-use webs
//!    (unioned through phis and through defs that read the same family), and
//!    report registers that carry (a) a live-in/parameter web AND (b) a
//!    disjoint, phi-free, single-block web — i.e. a provable block-local reuse.
//! 2. [`apply_hints`] — on the decompiler's own `BasicBlock` statements,
//!    re-verify the shape with a family-aware liveness check (belt and braces:
//!    the rename only happens when BOTH the MLIL SSA oracle and the text-level
//!    liveness agree) and rename the reused range to a fresh, unused register
//!    family so downstream naming gives it its own variable.
//!
//! OPT-IN: gated on `RUSTRE_MLIL_SSA_SPLIT=1`. Default-off ⇒ byte-identical
//! output.

use rustre_decompiler_cfs::{BasicBlock, Statement};
use rustre_il_mlil::{MlilFunction, MlilInstruction, SsaVar};
use std::collections::{HashMap, HashSet};

/// Parse the opt-in gate value: `1`, `true`, `on` (case-insensitive) enable.
#[must_use]
pub fn opt_in(val: Option<&str>) -> bool {
    matches!(
        val.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("1" | "true" | "on")
    )
}

// ─── x86 GPR families ────────────────────────────────────────────────────────

/// Sub-register aliases per canonical 64-bit GPR, widest first:
/// `[64, 32, 16, 8lo]` (the high-byte forms ah/bh/ch/dh are listed separately).
const FAMILIES: [[&str; 4]; 14] = [
    ["rax", "eax", "ax", "al"],
    ["rbx", "ebx", "bx", "bl"],
    ["rcx", "ecx", "cx", "cl"],
    ["rdx", "edx", "dx", "dl"],
    ["rsi", "esi", "si", "sil"],
    ["rdi", "edi", "di", "dil"],
    ["r8", "r8d", "r8w", "r8b"],
    ["r9", "r9d", "r9w", "r9b"],
    ["r10", "r10d", "r10w", "r10b"],
    ["r11", "r11d", "r11w", "r11b"],
    ["r12", "r12d", "r12w", "r12b"],
    ["r13", "r13d", "r13w", "r13b"],
    ["r14", "r14d", "r14w", "r14b"],
    ["r15", "r15d", "r15w", "r15b"],
];

/// High-byte forms that alias into the classic families.
const HIGH_BYTES: [(&str, &str); 4] =
    [("ah", "rax"), ("bh", "rbx"), ("ch", "rcx"), ("dh", "rdx")];

/// Canonical 64-bit family name for `name`, or `None` if not a GPR.
#[must_use]
pub fn canonical(name: &str) -> Option<&'static str> {
    for fam in &FAMILIES {
        if fam.contains(&name) {
            return Some(fam[0]);
        }
    }
    HIGH_BYTES
        .iter()
        .find(|(hb, _)| *hb == name)
        .map(|&(_, canon)| canon)
}

/// The width slot (0..4) of `name` inside its family, high-bytes map to slot 3.
fn width_slot(name: &str) -> usize {
    for fam in &FAMILIES {
        if let Some(i) = fam.iter().position(|m| *m == name) {
            return i;
        }
    }
    3 // high-byte forms rename to the 8-bit alias
}

fn family_members(canon: &str) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = FAMILIES
        .iter()
        .find(|f| f[0] == canon)
        .map(|f| f.to_vec())
        .unwrap_or_default();
    for (hb, c) in &HIGH_BYTES {
        if *c == canon {
            out.push(hb);
        }
    }
    out
}

// ─── MLIL SSA analysis (the oracle) ─────────────────────────────────────────

/// The subset of `candidates` read by `instr`.
fn single_instr_uses(instr: &MlilInstruction, candidates: &HashSet<SsaVar>) -> Vec<SsaVar> {
    candidates
        .iter()
        .filter(|v| instr.uses_var(v))
        .cloned()
        .collect()
}

/// Union-find over SSA-version indices.
struct Uf(Vec<usize>);
impl Uf {
    fn new(n: usize) -> Self {
        Self((0..n).collect())
    }
    fn find(&mut self, mut x: usize) -> usize {
        while self.0[x] != x {
            self.0[x] = self.0[self.0[x]];
            x = self.0[x];
        }
        x
    }
    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.0[ra] = rb;
        }
    }
}

/// Compute reuse hints from REAL MLIL SSA form.
///
/// Returns the canonical 64-bit names of registers whose SSA versions form at
/// least two disjoint webs, where one web is the live-in/parameter web and
/// some other web is phi-free and entirely contained in a single basic block.
#[must_use]
pub fn reuse_hints(func: &MlilFunction) -> Vec<String> {
    if func.blocks.is_empty() {
        return Vec::new();
    }
    let ssa = func.clone().into_ssa().into_inner();

    // Pass 1: every SSA var appearing anywhere (candidate set for the
    // use-scans below). `fam_vars` is deliberately NOT built here — it is
    // rebuilt after dead-phi pruning, because a dead phi's SOURCES must not
    // register as vars either: a version-0 source would fabricate a live-in
    // web that no real instruction reads (witness: the no-live-in-web test
    // hinted rdx/r8 purely from pruned phis at the join block).
    let mut seen: HashSet<SsaVar> = HashSet::new();
    for b in &ssa.blocks {
        for ai in &b.instrs {
            if let Some(d) = ai.instr.defined_var() {
                seen.insert(d.clone());
            }
        }
        for u in b.used_vars() {
            seen.insert(u);
        }
    }

    // Dead-phi pruning: the SSA builder conservatively places phis for
    // variables that are not actually live at the join (e.g. a loop temp gets
    // `rdx#2 = φ(rdx#1, rdx#3)` even though no instruction ever reads rdx#2).
    // A dead phi would incorrectly union disjoint webs, so compute phi
    // liveness (dest used by a non-phi instruction, or by a live phi) and
    // treat dead phis as nonexistent.
    let mut phi_list: Vec<(SsaVar, Vec<SsaVar>)> = Vec::new();
    let mut used_by_nonphi: HashSet<SsaVar> = HashSet::new();
    for b in &ssa.blocks {
        for ai in &b.instrs {
            if let MlilInstruction::Phi { dest, sources } = &ai.instr {
                phi_list.push((dest.clone(), sources.clone()));
            }
        }
        // used_vars covers phi sources too; subtract them below via fixpoint
        // by collecting non-phi uses per instruction instead.
        for ai in b.non_phi_instrs() {
            for u in single_instr_uses(&ai.instr, &seen) {
                used_by_nonphi.insert(u);
            }
        }
    }
    let mut live_phi: Vec<bool> = phi_list
        .iter()
        .map(|(d, _)| used_by_nonphi.contains(d))
        .collect();
    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..phi_list.len() {
            if live_phi[i] {
                continue;
            }
            let dest = &phi_list[i].0;
            let used_by_live_phi = phi_list
                .iter()
                .enumerate()
                .any(|(j, (_, srcs))| live_phi[j] && srcs.contains(dest));
            if used_by_live_phi {
                live_phi[i] = true;
                changed = true;
            }
        }
    }
    let dead_phi_dests: HashSet<&SsaVar> = phi_list
        .iter()
        .enumerate()
        .filter(|(i, _)| !live_phi[*i])
        .map(|(_, (d, _))| d)
        .collect();

    // Pass 2: family vars from LIVE instructions only — dead phis are
    // nonexistent, dest and sources alike (see pass-1 comment).
    let mut fam_vars: HashMap<&'static str, Vec<SsaVar>> = HashMap::new();
    let mut noted: HashSet<SsaVar> = HashSet::new();
    for b in &ssa.blocks {
        for ai in &b.instrs {
            if let MlilInstruction::Phi { dest, .. } = &ai.instr {
                if dead_phi_dests.contains(dest) {
                    continue;
                }
            }
            let mut note = |v: &SsaVar| {
                if let Some(c) = canonical(&v.name) {
                    if noted.insert(v.clone()) {
                        fam_vars.entry(c).or_default().push(v.clone());
                    }
                }
            };
            if let Some(d) = ai.instr.defined_var() {
                note(d);
            }
            for u in single_instr_uses(&ai.instr, &seen) {
                note(&u);
            }
        }
    }

    let mut hints: Vec<String> = Vec::new();
    for (canon, vars) in &fam_vars {
        if vars.len() < 2 {
            continue;
        }
        let idx: HashMap<&SsaVar, usize> =
            vars.iter().enumerate().map(|(i, v)| (v, i)).collect();
        let mut uf = Uf::new(vars.len());
        // Per-version bookkeeping: blocks where defined/used, phi membership.
        let mut blocks_of: Vec<HashSet<u32>> = vec![HashSet::new(); vars.len()];
        let mut in_phi: Vec<bool> = vec![false; vars.len()];
        let mut has_def: Vec<bool> = vec![false; vars.len()];

        for b in &ssa.blocks {
            for ai in &b.instrs {
                // Dead phis are treated as nonexistent (see pruning above).
                if let MlilInstruction::Phi { dest, .. } = &ai.instr {
                    if dead_phi_dests.contains(dest) {
                        continue;
                    }
                }
                let def = ai.instr.defined_var().cloned();
                let def_i = def.as_ref().and_then(|d| idx.get(d).copied());
                if let Some(di) = def_i {
                    has_def[di] = true;
                    blocks_of[di].insert(b.id);
                }
                // Union def with any same-family version it reads; record uses.
                for (vi, v) in vars.iter().enumerate() {
                    if Some(vi) == def_i {
                        continue;
                    }
                    if ai.instr.uses_var(v) {
                        blocks_of[vi].insert(b.id);
                        if let Some(di) = def_i {
                            uf.union(di, vi);
                        }
                    }
                }
                if let MlilInstruction::Phi { dest, sources } = &ai.instr {
                    if let Some(&di) = idx.get(dest) {
                        in_phi[di] = true;
                        for s in sources {
                            if let Some(&si) = idx.get(s) {
                                in_phi[si] = true;
                                uf.union(di, si);
                            }
                        }
                    }
                }
            }
        }
        // Live-in versions (version 0, never defined) all name the same
        // physical entry value: union them across sub-register names.
        let live_in: Vec<usize> = vars
            .iter()
            .enumerate()
            .filter(|(i, v)| v.version == 0 && !has_def[*i])
            .map(|(i, _)| i)
            .collect();
        for w in live_in.windows(2) {
            uf.union(w[0], w[1]);
        }
        let Some(&entry0) = live_in.first() else {
            continue; // no live-in web ⇒ not a parameter register here
        };
        let entry_root = uf.find(entry0);

        // Group into webs.
        let mut webs: HashMap<usize, Vec<usize>> = HashMap::new();
        for i in 0..vars.len() {
            let r = uf.find(i);
            webs.entry(r).or_default().push(i);
        }
        if webs.len() < 2 {
            continue;
        }
        let reusable = webs.iter().any(|(&root, members)| {
            if root == entry_root {
                return false;
            }
            // Phi-free and single-block.
            let mut all_blocks: HashSet<u32> = HashSet::new();
            for &m in members {
                if in_phi[m] {
                    return false;
                }
                all_blocks.extend(blocks_of[m].iter().copied());
            }
            all_blocks.len() == 1 && members.iter().any(|&m| has_def[m])
        });
        if reusable {
            hints.push((*canon).to_string());
        }
    }
    hints.sort();
    hints
}

// ─── Text-side application (belt-and-braces re-verification) ────────────────

/// Word-boundary-aware "does `s` mention identifier `name`".
fn mentions(s: &str, name: &str) -> bool {
    let b = s.as_bytes();
    let f = name.as_bytes();
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while i + f.len() <= b.len() {
        if &b[i..i + f.len()] == f
            && (i == 0 || !word(b[i - 1]))
            && (i + f.len() == b.len() || !word(b[i + f.len()]))
        {
            return true;
        }
        i += 1;
    }
    false
}

/// Whole-word replace of `from` with `to` in `s`.
fn replace_word(s: &str, from: &str, to: &str) -> String {
    if !mentions(s, from) {
        return s.to_string();
    }
    let b = s.as_bytes();
    let f = from.as_bytes();
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
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

/// Does the statement READ any member of the family (reads only — a plain
/// `member = rhs` LHS is a write, but `*(member+8) = rhs` is a read)?
fn stmt_reads_family(st: &Statement, members: &[&str]) -> bool {
    match st {
        Statement::Raw(r) | Statement::Branch(r) => members.iter().any(|m| mentions(r, m)),
        Statement::Assign { lhs, rhs } => {
            if members.iter().any(|m| mentions(rhs, m)) {
                return true;
            }
            // LHS reads: deref/index stores, or compound ops (`x += …` keeps
            // the family alive; the emitter splits compounds earlier, but be
            // conservative).
            let plain_write = members.iter().any(|m| lhs.trim() == *m);
            !plain_write && members.iter().any(|m| mentions(lhs, m))
        }
        Statement::Return(Some(v)) => members.iter().any(|m| mentions(v, m)),
        Statement::Return(None) => false,
    }
}

/// Is the statement a full (non-reading) definition of a family member?
fn stmt_fresh_def(st: &Statement, members: &[&str]) -> bool {
    if let Statement::Assign { lhs, rhs } = st {
        members.iter().any(|m| lhs.trim() == *m)
            && !members.iter().any(|m| mentions(rhs, m))
    } else {
        false
    }
}

/// Is the statement ANY definition of a family member (kills liveness)?
fn stmt_any_def(st: &Statement, members: &[&str]) -> bool {
    if let Statement::Assign { lhs, .. } = st {
        members.iter().any(|m| lhs.trim() == *m)
    } else {
        false
    }
}

fn rewrite_stmt(st: &mut Statement, from: &str, to: &str) {
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

/// Every identifier-ish word mentioned anywhere in `blocks` (for fresh-name
/// pool selection).
fn any_mention(blocks: &[BasicBlock], names: &[&str]) -> bool {
    blocks.iter().any(|b| {
        b.stmts.iter().any(|st| {
            let strs: Vec<&String> = match st {
                Statement::Raw(r) | Statement::Branch(r) => vec![r],
                Statement::Assign { lhs, rhs } => vec![lhs, rhs],
                Statement::Return(Some(v)) => vec![v],
                Statement::Return(None) => vec![],
            };
            strs.iter().any(|s| names.iter().any(|n| mentions(s, n)))
        })
    })
}

/// Apply MLIL-derived reuse hints to the decompiler's text blocks.
///
/// For each hinted register family the text-side liveness is RE-VERIFIED:
/// the family must be live-in at the entry block (it carries a parameter),
/// and a rename only happens in a non-entry block `b` that starts a fresh
/// (non-reading) definition of the family and out of which the family is NOT
/// live. Returns the number of renamed ranges.
pub fn apply_hints(blocks: &mut Vec<BasicBlock>, hints: &[String]) -> usize {
    if blocks.is_empty() || hints.is_empty() {
        return 0;
    }
    let id_index: HashMap<u32, usize> =
        blocks.iter().enumerate().map(|(i, b)| (b.id.0, i)).collect();
    let mut renamed = 0usize;

    for canon in hints {
        let members = family_members(canon);
        if members.is_empty() {
            continue;
        }
        // Per-block UBD (use before def) and DEF flags.
        let n = blocks.len();
        let mut ubd = vec![false; n];
        let mut has_def = vec![false; n];
        for (i, b) in blocks.iter().enumerate() {
            for st in &b.stmts {
                if stmt_reads_family(st, &members) {
                    ubd[i] = true;
                    break;
                }
                if stmt_any_def(st, &members) {
                    has_def[i] = true;
                    break;
                }
            }
            if !has_def[i] {
                has_def[i] = b.stmts.iter().any(|st| stmt_any_def(st, &members));
            }
        }
        // Backward liveness fixpoint (block granularity).
        let mut live_in = ubd.clone();
        let mut changed = true;
        while changed {
            changed = false;
            for i in 0..n {
                let live_out = blocks[i]
                    .successors
                    .iter()
                    .filter_map(|s| id_index.get(&s.0))
                    .any(|&j| live_in[j]);
                let li = ubd[i] || (live_out && !has_def[i]);
                if li != live_in[i] {
                    live_in[i] = li;
                    changed = true;
                }
            }
        }
        // Text-side parameter requirement.
        if !live_in[0] {
            continue;
        }
        // Fresh register pool: an entirely unmentioned family.
        let pool = ["r10", "r11", "r12", "r13", "r14", "r15", "rbx", "rsi", "rdi"];
        let fresh = pool.iter().find(|c| {
            let fam = family_members(c);
            !any_mention(blocks, &fam)
        });
        let Some(fresh) = fresh else { continue };
        let fresh_fam = family_members(fresh);

        for i in 1..n {
            let live_out = blocks[i]
                .successors
                .iter()
                .filter_map(|s| id_index.get(&s.0))
                .any(|&j| live_in[j]);
            if live_out {
                continue;
            }
            let Some(start) = blocks[i]
                .stmts
                .iter()
                .position(|st| stmt_fresh_def(st, &members))
            else {
                continue;
            };
            let stmts = &mut blocks[i].stmts;
            for st in stmts.iter_mut().skip(start) {
                for m in &members {
                    let slot = width_slot(m);
                    rewrite_stmt(st, m, fresh_fam[slot.min(3)]);
                }
            }
            renamed += 1;
        }
    }
    renamed
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;
    use rustre_decompiler_cfs::BlockId;
    use rustre_il_mlil::{MlilAnnotatedInstr, MlilBasicBlock, MlilExpr, Size};

    fn var(name: &str) -> SsaVar {
        SsaVar::new(name, 0)
    }
    fn v(name: &str) -> MlilExpr {
        MlilExpr::Var {
            var: var(name),
            size: Size::QWord,
        }
    }
    fn c(val: u64) -> MlilExpr {
        MlilExpr::Const {
            value: val,
            size: Size::QWord,
        }
    }
    fn assign(addr: u64, dest: &str, src: MlilExpr) -> MlilAnnotatedInstr {
        MlilAnnotatedInstr {
            address: Address::new(addr),
            instr: MlilInstruction::Assign {
                dest: var(dest),
                size: Size::QWord,
                src,
            },
        }
    }

    /// Miniature `accumulate`: block 0 branches on the parameter register
    /// `edx`; block 1 derives the loop bound from it (`rdx = edx*3`); block 2
    /// (a self-loop) CLOBBERS `rdx` with a loaded value and consumes it
    /// block-locally; block 3 returns something else.
    fn accumulate_like_mlil() -> MlilFunction {
        let mut f = MlilFunction::new(Address::new(0x1000));
        let b0 = MlilBasicBlock {
            id: 0,
            start: Address::new(0x1000),
            end: Address::new(0x1004),
            instrs: vec![MlilAnnotatedInstr {
                address: Address::new(0x1000),
                instr: MlilInstruction::CondJump {
                    cond: v("edx"),
                    true_dest: Address::new(0x1010),
                    false_dest: Address::new(0x1030),
                },
            }],
            predecessors: vec![],
            successors: vec![1, 3],
        };
        let b1 = MlilBasicBlock {
            id: 1,
            start: Address::new(0x1010),
            end: Address::new(0x1018),
            instrs: vec![
                assign(
                    0x1010,
                    "rdx",
                    MlilExpr::Mul(Box::new(v("edx")), Box::new(c(3)), Size::QWord),
                ),
                assign(
                    0x1014,
                    "r8",
                    MlilExpr::Add(Box::new(v("rcx")), Box::new(v("rdx")), Size::QWord),
                ),
            ],
            predecessors: vec![0],
            successors: vec![2],
        };
        let b2 = MlilBasicBlock {
            id: 2,
            start: Address::new(0x1020),
            end: Address::new(0x102c),
            instrs: vec![
                // rdx = *(rax+8)  — fresh def, unrelated to the parameter web
                assign(
                    0x1020,
                    "rdx",
                    MlilExpr::Load {
                        addr: Box::new(MlilExpr::Add(
                            Box::new(v("rax")),
                            Box::new(c(8)),
                            Size::QWord,
                        )),
                        size: Size::QWord,
                    },
                ),
                // rcx = rcx + rdx — block-local consumption
                assign(
                    0x1024,
                    "rcx",
                    MlilExpr::Add(Box::new(v("rcx")), Box::new(v("rdx")), Size::QWord),
                ),
                MlilAnnotatedInstr {
                    address: Address::new(0x1028),
                    instr: MlilInstruction::CondJump {
                        cond: v("rax"),
                        true_dest: Address::new(0x1020),
                        false_dest: Address::new(0x1030),
                    },
                },
            ],
            predecessors: vec![1, 2],
            successors: vec![2, 3],
        };
        let b3 = MlilBasicBlock {
            id: 3,
            start: Address::new(0x1030),
            end: Address::new(0x1034),
            instrs: vec![MlilAnnotatedInstr {
                address: Address::new(0x1030),
                instr: MlilInstruction::Ret {
                    values: vec![v("rcx")],
                },
            }],
            predecessors: vec![0, 2],
            successors: vec![],
        };
        f.blocks = vec![b0, b1, b2, b3];
        f
    }

    #[test]
    fn dbg_ssa_dump() {
        let f = accumulate_like_mlil();
        let ssa = f.clone().into_ssa().into_inner();
        for b in &ssa.blocks {
            eprintln!("block {}", b.id);
            for ai in &b.instrs {
                eprintln!("  {:?}", ai.instr);
            }
        }
    }

    #[test]
    fn opt_in_gate() {
        assert!(opt_in(Some("1")));
        assert!(opt_in(Some("true")));
        assert!(opt_in(Some("ON")));
        assert!(!opt_in(Some("0")));
        assert!(!opt_in(None));
    }

    #[test]
    fn canonical_families() {
        assert_eq!(canonical("edx"), Some("rdx"));
        assert_eq!(canonical("r8d"), Some("r8"));
        assert_eq!(canonical("ah"), Some("rax"));
        assert_eq!(canonical("xmm0"), None);
    }

    #[test]
    fn mlil_ssa_detects_param_register_reuse() {
        let f = accumulate_like_mlil();
        let hints = reuse_hints(&f);
        assert!(
            hints.iter().any(|h| h == "rdx"),
            "expected rdx reuse hint, got {hints:?}"
        );
    }

    #[test]
    fn mlil_ssa_no_hint_without_live_in_web() {
        // Same CFG but the register is fully defined before every use —
        // no parameter web, so no hint.
        let mut f = accumulate_like_mlil();
        // Replace the block-0 use of edx with a constant condition and the
        // block-1 use of edx with a constant: rdx never has a live-in web.
        f.blocks[0].instrs[0].instr = MlilInstruction::CondJump {
            cond: v("rax"),
            true_dest: Address::new(0x1010),
            false_dest: Address::new(0x1030),
        };
        f.blocks[1].instrs[0] = assign(0x1010, "rdx", c(3));
        let hints = reuse_hints(&f);
        assert!(
            !hints.iter().any(|h| h == "rdx"),
            "no live-in web ⇒ no hint, got {hints:?}"
        );
    }

    // ── text-side apply ──────────────────────────────────────────────────

    fn blk(id: u32, stmts: Vec<Statement>, succ: Vec<u32>) -> BasicBlock {
        BasicBlock {
            id: BlockId(id),
            stmts,
            successors: succ.into_iter().map(BlockId).collect(),
        }
    }
    fn asg(lhs: &str, rhs: &str) -> Statement {
        Statement::Assign {
            lhs: lhs.into(),
            rhs: rhs.into(),
        }
    }

    fn accumulate_like_blocks() -> Vec<BasicBlock> {
        vec![
            blk(0, vec![Statement::Branch("edx <= 0".into())], vec![1, 4]),
            blk(
                1,
                vec![
                    asg("rax", "rcx"),
                    asg("rdx", "edx"),
                    asg("rdx", "rdx + rdx*2"),
                    asg("r8", "rcx + rdx*8"),
                    asg("ecx", "0"),
                ],
                vec![2],
            ),
            blk(
                2,
                vec![
                    asg("rdx", "*(rax + 8)"),
                    asg("rdx", "rdx + *rax"),
                    asg("*(rax + 0x10)", "rdx"),
                    asg("rcx", "rcx + rdx"),
                    asg("rax", "rax + 0x18"),
                    Statement::Branch("rax != r8".into()),
                ],
                vec![3, 2],
            ),
            blk(3, vec![asg("rax", "rcx"), Statement::Return(None)], vec![]),
            blk(4, vec![asg("ecx", "0")], vec![3]),
        ]
    }

    #[test]
    fn apply_renames_block_local_reuse_only() {
        let mut blocks = accumulate_like_blocks();
        let n = apply_hints(&mut blocks, &["rdx".to_string()]);
        assert_eq!(n, 1, "exactly the loop-body range renames");
        // Parameter web untouched.
        assert_eq!(blocks[0].stmts[0], Statement::Branch("edx <= 0".into()));
        assert_eq!(blocks[1].stmts[1], asg("rdx", "edx"));
        // Loop body renamed to a fresh family (r10 is first free in pool).
        assert_eq!(blocks[2].stmts[0], asg("r10", "*(rax + 8)"));
        assert_eq!(blocks[2].stmts[1], asg("r10", "r10 + *rax"));
        assert_eq!(blocks[2].stmts[2], asg("*(rax + 0x10)", "r10"));
        assert_eq!(blocks[2].stmts[3], asg("rcx", "rcx + r10"));
    }

    #[test]
    fn apply_skips_when_family_live_out() {
        // Same shape but block 3 READS rdx → live out of the loop block →
        // renaming would be unsound → must be a no-op.
        let mut blocks = accumulate_like_blocks();
        blocks[3].stmts[0] = asg("rax", "rdx");
        let before = blocks.clone();
        let n = apply_hints(&mut blocks, &["rdx".to_string()]);
        assert_eq!(n, 0);
        assert_eq!(
            format!("{blocks:?}"),
            format!("{before:?}"),
            "live-out family must not be renamed"
        );
    }

    #[test]
    fn apply_skips_without_entry_liveness() {
        // Family never live-in at entry (not a parameter) → no rename.
        let mut blocks = accumulate_like_blocks();
        blocks[0].stmts[0] = Statement::Branch("eax <= 0".into());
        blocks[1].stmts[1] = asg("rdx", "5");
        let n = apply_hints(&mut blocks, &["rdx".to_string()]);
        assert_eq!(n, 0);
    }

    #[test]
    fn apply_no_hints_is_noop() {
        let mut blocks = accumulate_like_blocks();
        let before = format!("{blocks:?}");
        assert_eq!(apply_hints(&mut blocks, &[]), 0);
        assert_eq!(format!("{blocks:?}"), before);
    }
}
