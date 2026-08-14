//! Standard SSA (Static Single Assignment) construction.
//!
//! Implements the classic Cytron et al. algorithm:
//!
//! 1. Compute dominators using the simple iterative dataflow formulation
//!    (Cooper, Harvey, Kennedy "A Simple, Fast Dominance Algorithm").
//! 2. Compute dominance frontiers from the dominator tree.
//! 3. Place phi nodes at the iterated dominance frontier of every variable's
//!    definition set.
//! 4. Rename variables by a DFS over the dominator tree, maintaining a
//!    per-variable version stack.
//!
//! The module is intentionally decoupled from the rest of the workspace via
//! the [`SsaInput`] trait — any caller that can describe a CFG, variable
//! definitions, and variable uses can construct SSA form here.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

/// Block identifier — a small dense integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockId(pub u32);

impl BlockId {
    /// Construct a [`BlockId`] from a `u32`.
    #[must_use]
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Raw `u32` value.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// Variable identifier — a small dense integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarId(pub u32);

impl VarId {
    /// Construct a [`VarId`] from a `u32`.
    #[must_use]
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Raw `u32` value.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// A versioned SSA variable: `x_3` means the third version of variable `x`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SsaVar {
    /// The underlying variable.
    pub var: VarId,
    /// The SSA version number (0-based).
    pub version: u32,
}

impl SsaVar {
    /// Construct an [`SsaVar`].
    #[must_use]
    pub const fn new(var: VarId, version: u32) -> Self {
        Self { var, version }
    }
}

/// A phi node placed at the head of a join block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhiNode {
    /// The destination SSA variable produced by the phi.
    pub dest: SsaVar,
    /// The underlying variable being merged.
    pub var: VarId,
    /// One (predecessor block, incoming SSA version) pair per predecessor.
    pub sources: Vec<(BlockId, SsaVar)>,
}

/// One SSA statement: either an ordinary def/use site or a phi placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsaStatement {
    /// `dest = op(uses...)` after renaming.
    Assign {
        /// The SSA variable defined by this statement.
        dest: SsaVar,
        /// The SSA variables used by this statement.
        uses: Vec<SsaVar>,
    },
    /// A use without any definition (e.g. a return / branch / store).
    Use {
        /// The SSA variables read by this statement.
        uses: Vec<SsaVar>,
    },
    /// A phi marker (also tracked separately in [`SsaForm::phi_nodes`]).
    Phi(PhiNode),
}

/// One block of SSA-renamed statements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsaBlock {
    /// The block identifier.
    pub id: BlockId,
    /// The renamed statements in program order.
    pub statements: Vec<SsaStatement>,
}

/// The complete SSA form produced by [`construct_ssa`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsaForm {
    /// All blocks with their renamed statements.
    pub blocks: Vec<SsaBlock>,
    /// Phi nodes placed at the head of each block (only blocks with phis are
    /// included).  Iteration order matches block-id order for determinism.
    pub phi_nodes: BTreeMap<BlockId, Vec<PhiNode>>,
    /// Total number of fresh SSA versions handed out (= number of distinct
    /// defs in the renamed program, including phi defs).
    pub def_count: u32,
}

/// One original (pre-SSA) statement in the input program.
///
/// A statement may define at most one variable (`def`) and use zero or more
/// variables (`uses`).  Block statements should be in program order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputStatement {
    /// Optional defined variable.
    pub def: Option<VarId>,
    /// Variables read by this statement.
    pub uses: Vec<VarId>,
}

impl InputStatement {
    /// A statement that defines `def` and uses `uses`.
    #[must_use]
    pub const fn assign(def: VarId, uses: Vec<VarId>) -> Self {
        Self {
            def: Some(def),
            uses,
        }
    }

    /// A statement with only uses (no def).
    #[must_use]
    pub const fn use_only(uses: Vec<VarId>) -> Self {
        Self { def: None, uses }
    }
}

/// Trait describing the input CFG and variable activity to [`construct_ssa`].
///
/// Implementors expose:
/// * a list of block ids (the first one is the entry),
/// * the successor list of each block,
/// * the original statements inside each block in program order,
/// * the universe of variables to rename.
pub trait SsaInput {
    /// All block ids in the CFG.  `blocks()[0]` is treated as the entry.
    fn blocks(&self) -> &[BlockId];

    /// Successors of the given block.
    fn successors(&self, block: BlockId) -> &[BlockId];

    /// Statements of the given block in program order.
    fn statements(&self, block: BlockId) -> &[InputStatement];

    /// All variables that should participate in SSA renaming.
    fn variables(&self) -> &[VarId];
}

// ─────────────────────────────────────────────────────────────────────────────
// Dominator computation (Cooper/Harvey/Kennedy simple iterative algorithm).
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the immediate dominator of every reachable block.
///
/// Returns a map `block -> idom(block)`.  The entry block maps to itself.
fn compute_idoms(
    blocks: &[BlockId],
    preds: &HashMap<BlockId, Vec<BlockId>>,
    rpo: &[BlockId],
    rpo_index: &HashMap<BlockId, u32>,
) -> HashMap<BlockId, BlockId> {
    let entry = blocks[0];
    let mut idom: HashMap<BlockId, Option<BlockId>> = HashMap::new();
    for &b in blocks {
        idom.insert(b, None);
    }
    idom.insert(entry, Some(entry));

    let intersect =
        |mut b1: BlockId, mut b2: BlockId, idom: &HashMap<BlockId, Option<BlockId>>| -> BlockId {
            loop {
                let i1 = rpo_index.get(&b1).copied().unwrap_or(u32::MAX);
                let i2 = rpo_index.get(&b2).copied().unwrap_or(u32::MAX);
                if i1 == i2 {
                    return b1;
                }
                // Higher RPO index = deeper in the graph.  Walk the deeper one up.
                if i1 > i2 {
                    let next = idom.get(&b1).copied().flatten().unwrap_or(b1);
                    if next == b1 {
                        // Stall: malformed/irreducible CFG — bail with the other node.
                        return b2;
                    }
                    b1 = next;
                } else {
                    let next = idom.get(&b2).copied().flatten().unwrap_or(b2);
                    if next == b2 {
                        return b1;
                    }
                    b2 = next;
                }
            }
        };

    let mut changed = true;
    while changed {
        changed = false;
        for &b in rpo.iter().skip(1) {
            let empty: Vec<BlockId> = Vec::new();
            let bp = preds.get(&b).unwrap_or(&empty);
            // Pick the first processed predecessor as the running idom.
            let mut new_idom: Option<BlockId> = None;
            for &p in bp {
                if idom.get(&p).copied().flatten().is_some() {
                    new_idom = Some(p);
                    break;
                }
            }
            let Some(mut cur) = new_idom else { continue };
            for &p in bp {
                if Some(p) == new_idom {
                    continue;
                }
                if idom.get(&p).copied().flatten().is_some() {
                    cur = intersect(p, cur, &idom);
                }
            }
            let prev = idom.get(&b).copied().flatten();
            if prev != Some(cur) {
                idom.insert(b, Some(cur));
                changed = true;
            }
        }
    }

    let mut out = HashMap::new();
    for &b in blocks {
        if let Some(Some(d)) = idom.get(&b).copied().map(Some)
            && let Some(d) = d {
                out.insert(b, d);
            }
    }
    out
}

/// Compute reverse postorder starting from `entry`.
fn reverse_postorder(
    entry: BlockId,
    succs: &HashMap<BlockId, Vec<BlockId>>,
) -> Vec<BlockId> {
    let mut visited: HashSet<BlockId> = HashSet::new();
    let mut post: Vec<BlockId> = Vec::new();

    // Iterative DFS with explicit stack.
    let mut stack: Vec<(BlockId, usize)> = vec![(entry, 0)];
    visited.insert(entry);
    while let Some(&(node, idx)) = stack.last() {
        let empty: Vec<BlockId> = Vec::new();
        let s = succs.get(&node).unwrap_or(&empty);
        if idx < s.len() {
            let next = s[idx];
            let last = stack.last_mut().expect("stack non-empty");
            last.1 += 1;
            if visited.insert(next) {
                stack.push((next, 0));
            }
        } else {
            post.push(node);
            stack.pop();
        }
    }

    post.reverse();
    post
}

/// Compute dominance frontiers from the immediate-dominator map.
fn compute_dominance_frontiers(
    blocks: &[BlockId],
    preds: &HashMap<BlockId, Vec<BlockId>>,
    idom: &HashMap<BlockId, BlockId>,
) -> HashMap<BlockId, HashSet<BlockId>> {
    let mut df: HashMap<BlockId, HashSet<BlockId>> = HashMap::new();
    for &b in blocks {
        df.insert(b, HashSet::new());
    }
    for &b in blocks {
        let empty: Vec<BlockId> = Vec::new();
        let bp = preds.get(&b).unwrap_or(&empty);
        if bp.len() < 2 {
            continue;
        }
        let Some(&idom_b) = idom.get(&b) else {
            continue;
        };
        for &p in bp {
            let mut runner = p;
            while runner != idom_b {
                df.entry(runner).or_default().insert(b);
                let Some(&next) = idom.get(&runner) else {
                    break;
                };
                if next == runner {
                    break;
                }
                runner = next;
            }
        }
    }
    df
}

// ─────────────────────────────────────────────────────────────────────────────
// SSA construction entry point.
// ─────────────────────────────────────────────────────────────────────────────

/// Iterative DFS frame used by the SSA renaming pass.
#[derive(Debug)]
enum SsaRenameFrame {
    Enter(BlockId),
    Leave { block: BlockId, pushed: Vec<VarId> },
}

/// Mutable state threaded through the SSA renaming work-loop.
struct SsaRenameCtx<'a> {
    counter: &'a mut HashMap<VarId, u32>,
    stack: &'a mut HashMap<VarId, Vec<u32>>,
    renamed_stmts: &'a mut HashMap<BlockId, Vec<SsaStatement>>,
    phi_nodes_map: &'a mut BTreeMap<BlockId, Vec<PhiNode>>,
}

/// Phase 1: compute the set of blocks where a phi node must be placed for each
/// variable, using the iterated dominance frontier (Cytron et al.).
fn compute_phi_placement<I: SsaInput>(
    input: &I,
    blocks: &[BlockId],
    df: &HashMap<BlockId, HashSet<BlockId>>,
) -> HashMap<BlockId, BTreeSet<VarId>> {
    let mut defs_of: HashMap<VarId, HashSet<BlockId>> = HashMap::new();
    for &b in blocks {
        for stmt in input.statements(b) {
            if let Some(v) = stmt.def {
                defs_of.entry(v).or_default().insert(b);
            }
        }
    }
    let mut phis_to_place: HashMap<BlockId, BTreeSet<VarId>> = HashMap::new();
    for &v in input.variables() {
        let Some(seed) = defs_of.get(&v) else { continue };
        let mut worklist: VecDeque<BlockId> = seed.iter().copied().collect();
        let mut has_phi: HashSet<BlockId> = HashSet::new();
        let mut ever_on_worklist: HashSet<BlockId> = seed.iter().copied().collect();
        while let Some(x) = worklist.pop_front() {
            let empty: HashSet<BlockId> = HashSet::new();
            for &y in df.get(&x).unwrap_or(&empty) {
                if has_phi.insert(y) {
                    phis_to_place.entry(y).or_default().insert(v);
                    if ever_on_worklist.insert(y) {
                        worklist.push_back(y);
                    }
                }
            }
        }
    }
    phis_to_place
}

/// Phase 2 work-loop: rename all variables using an iterative DFS over the
/// dominator tree, maintaining a per-variable version stack.
fn run_ssa_rename<I: SsaInput>(
    entry: BlockId,
    input: &I,
    _succs: &HashMap<BlockId, Vec<BlockId>>,
    dom_children: &HashMap<BlockId, Vec<BlockId>>,
    ctx: &mut SsaRenameCtx<'_>,
) {
    let mut work: Vec<SsaRenameFrame> = vec![SsaRenameFrame::Enter(entry)];
    while let Some(frame) = work.pop() {
        match frame {
            SsaRenameFrame::Enter(b) => {
                let mut pushed_here: Vec<VarId> = Vec::new();
                if let Some(phis) = ctx.phi_nodes_map.get_mut(&b) {
                    for phi in phis.iter_mut() {
                        let v = phi.var;
                        let c = ctx.counter.entry(v).or_insert(0);
                        let new_ver = *c;
                        *c += 1;
                        ctx.stack.entry(v).or_default().push(new_ver);
                        pushed_here.push(v);
                        phi.dest = SsaVar::new(v, new_ver);
                    }
                }
                let mut out_stmts: Vec<SsaStatement> = Vec::new();
                for stmt in input.statements(b) {
                    let uses: Vec<SsaVar> = stmt.uses.iter().map(|u| {
                        let top = ctx.stack.get(u).and_then(|s| s.last().copied()).unwrap_or(0);
                        SsaVar::new(*u, top)
                    }).collect();
                    if let Some(v) = stmt.def {
                        let c = ctx.counter.entry(v).or_insert(0);
                        let new_ver = *c;
                        *c += 1;
                        ctx.stack.entry(v).or_default().push(new_ver);
                        pushed_here.push(v);
                        out_stmts.push(SsaStatement::Assign { dest: SsaVar::new(v, new_ver), uses });
                    } else {
                        out_stmts.push(SsaStatement::Use { uses });
                    }
                }
                ctx.renamed_stmts.insert(b, out_stmts);
                for s in input.successors(b) {
                    if let Some(phis) = ctx.phi_nodes_map.get_mut(s) {
                        for phi in phis.iter_mut() {
                            let v = phi.var;
                            let top = ctx.stack.get(&v).and_then(|st| st.last().copied()).unwrap_or(0);
                            phi.sources.push((b, SsaVar::new(v, top)));
                        }
                    }
                }
                work.push(SsaRenameFrame::Leave { block: b, pushed: pushed_here });
                if let Some(children) = dom_children.get(&b) {
                    for &c in children.iter().rev() {
                        work.push(SsaRenameFrame::Enter(c));
                    }
                }
            }
            SsaRenameFrame::Leave { block, pushed } => {
                debug_assert!(ctx.renamed_stmts.contains_key(&block));
                for v in pushed {
                    if let Some(s) = ctx.stack.get_mut(&v) { s.pop(); }
                }
            }
        }
    }
}

/// Construct SSA form from an [`SsaInput`].
///
/// See the module-level documentation for the algorithm outline.
pub fn construct_ssa<I: SsaInput>(input: &I) -> SsaForm {
    let blocks = input.blocks().to_vec();
    if blocks.is_empty() {
        return SsaForm {
            blocks: Vec::new(),
            phi_nodes: BTreeMap::new(),
            def_count: 0,
        };
    }
    let entry = blocks[0];

    // Build successor and predecessor maps.
    let mut succs: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
    let mut preds: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
    for &b in &blocks {
        succs.insert(b, input.successors(b).to_vec());
        preds.entry(b).or_default();
    }
    for &b in &blocks {
        for &s in input.successors(b) {
            preds.entry(s).or_default().push(b);
        }
    }

    // Compute RPO, idoms, dominance frontiers.
    let rpo = reverse_postorder(entry, &succs);
    let mut rpo_index: HashMap<BlockId, u32> = HashMap::new();
    for (i, &b) in rpo.iter().enumerate() {
        let idx = u32::try_from(i).unwrap_or(u32::MAX);
        rpo_index.insert(b, idx);
    }
    let idom = compute_idoms(&blocks, &preds, &rpo, &rpo_index);
    let df = compute_dominance_frontiers(&blocks, &preds, &idom);

    // ── Phase 1: phi-node placement (Cytron iterated DF). ────────────────
    let phis_to_place = compute_phi_placement(input, &blocks, &df);

    // ── Phase 2: renaming (Cytron DFS over dominator tree). ──────────────
    // Build dominator tree children list.
    let mut dom_children: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
    for &b in &blocks {
        dom_children.entry(b).or_default();
    }
    for &b in &blocks {
        if b == entry { continue; }
        if let Some(&d) = idom.get(&b) && d != b {
            dom_children.entry(d).or_default().push(b);
        }
    }
    for v in dom_children.values_mut() { v.sort(); }

    let mut counter: HashMap<VarId, u32> = HashMap::new();
    let mut stack: HashMap<VarId, Vec<u32>> = HashMap::new();
    for &v in input.variables() {
        counter.insert(v, 0);
        stack.insert(v, Vec::new());
    }

    let mut renamed_stmts: HashMap<BlockId, Vec<SsaStatement>> = HashMap::new();
    let mut phi_nodes_map: BTreeMap<BlockId, Vec<PhiNode>> = BTreeMap::new();

    for (&b, vars) in &phis_to_place {
        let entry_list: Vec<PhiNode> = vars.iter().map(|&v| PhiNode {
            dest: SsaVar::new(v, 0),
            var: v,
            sources: Vec::new(),
        }).collect();
        phi_nodes_map.insert(b, entry_list);
    }

    let mut rename_ctx = SsaRenameCtx {
        counter: &mut counter,
        stack: &mut stack,
        renamed_stmts: &mut renamed_stmts,
        phi_nodes_map: &mut phi_nodes_map,
    };
    run_ssa_rename(entry, input, &succs, &dom_children, &mut rename_ctx);

    // Stitch the final SsaForm together in block-id order.
    let mut final_blocks: Vec<SsaBlock> = Vec::new();
    let mut sorted_blocks = blocks;
    sorted_blocks.sort();
    for b in sorted_blocks {
        let rs = renamed_stmts.remove(&b).unwrap_or_else(|| {
            // Block unreachable from the entry: the rename DFS never visited
            // it.  Fall back to version-0 renaming so its statements are
            // preserved rather than silently dropped.
            input
                .statements(b)
                .iter()
                .map(|stmt| {
                    let uses: Vec<SsaVar> =
                        stmt.uses.iter().map(|&u| SsaVar::new(u, 0)).collect();
                    match stmt.def {
                        Some(v) => SsaStatement::Assign { dest: SsaVar::new(v, 0), uses },
                        None => SsaStatement::Use { uses },
                    }
                })
                .collect()
        });
        let phis = phi_nodes_map.get(&b).map(Vec::as_slice).unwrap_or(&[]);
        let mut stmts: Vec<SsaStatement> = Vec::with_capacity(phis.len() + rs.len());
        for p in phis {
            stmts.push(SsaStatement::Phi(p.clone()));
        }
        stmts.extend(rs);
        final_blocks.push(SsaBlock { id: b, statements: stmts });
    }

    let def_count: u32 = counter.values().copied().sum();

    SsaForm {
        blocks: final_blocks,
        phi_nodes: phi_nodes_map,
        def_count,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny adapter implementing [`SsaInput`] from in-memory tables.
    struct TestCfg {
        blocks: Vec<BlockId>,
        succs: HashMap<BlockId, Vec<BlockId>>,
        stmts: HashMap<BlockId, Vec<InputStatement>>,
        vars: Vec<VarId>,
    }

    impl SsaInput for TestCfg {
        fn blocks(&self) -> &[BlockId] {
            &self.blocks
        }
        fn successors(&self, b: BlockId) -> &[BlockId] {
            self.succs.get(&b).map(Vec::as_slice).unwrap_or(&[])
        }
        fn statements(&self, b: BlockId) -> &[InputStatement] {
            self.stmts.get(&b).map(Vec::as_slice).unwrap_or(&[])
        }
        fn variables(&self) -> &[VarId] {
            &self.vars
        }
    }

    fn b(n: u32) -> BlockId {
        BlockId::new(n)
    }
    fn v(n: u32) -> VarId {
        VarId::new(n)
    }

    #[test]
    fn linear_cfg_has_no_phi() {
        // B0 -> B1 -> B2; variable x defined in B0, used in B2.
        let mut succs = HashMap::new();
        succs.insert(b(0), vec![b(1)]);
        succs.insert(b(1), vec![b(2)]);
        succs.insert(b(2), vec![]);
        let mut stmts = HashMap::new();
        stmts.insert(b(0), vec![InputStatement::assign(v(0), vec![])]);
        stmts.insert(b(1), vec![]);
        stmts.insert(b(2), vec![InputStatement::use_only(vec![v(0)])]);
        let cfg = TestCfg {
            blocks: vec![b(0), b(1), b(2)],
            succs,
            stmts,
            vars: vec![v(0)],
        };
        let ssa = construct_ssa(&cfg);
        assert!(ssa.phi_nodes.is_empty(), "linear CFG should have no phis");
        assert_eq!(ssa.def_count, 1);
    }

    #[test]
    fn if_else_join_has_one_phi() {
        // B0 -> {B1, B2} -> B3.  x defined in both B1 and B2, used in B3.
        let mut succs = HashMap::new();
        succs.insert(b(0), vec![b(1), b(2)]);
        succs.insert(b(1), vec![b(3)]);
        succs.insert(b(2), vec![b(3)]);
        succs.insert(b(3), vec![]);
        let mut stmts = HashMap::new();
        stmts.insert(b(0), vec![]);
        stmts.insert(b(1), vec![InputStatement::assign(v(0), vec![])]);
        stmts.insert(b(2), vec![InputStatement::assign(v(0), vec![])]);
        stmts.insert(b(3), vec![InputStatement::use_only(vec![v(0)])]);
        let cfg = TestCfg {
            blocks: vec![b(0), b(1), b(2), b(3)],
            succs,
            stmts,
            vars: vec![v(0)],
        };
        let ssa = construct_ssa(&cfg);
        let phis_at_3 = ssa.phi_nodes.get(&b(3)).expect("phi at join");
        assert_eq!(phis_at_3.len(), 1);
        assert_eq!(phis_at_3[0].var, v(0));
        assert_eq!(phis_at_3[0].sources.len(), 2);
        // Versions in B1 and B2 should differ.
        let vs: Vec<u32> = phis_at_3[0].sources.iter().map(|(_, s)| s.version).collect();
        assert_ne!(vs[0], vs[1]);
    }

    #[test]
    fn while_loop_has_phi_at_header() {
        // B0 -> B1; B1 -> {B2 (body), B3 (exit)}; B2 -> B1.  x defined in B0 and B2.
        let mut succs = HashMap::new();
        succs.insert(b(0), vec![b(1)]);
        succs.insert(b(1), vec![b(2), b(3)]);
        succs.insert(b(2), vec![b(1)]);
        succs.insert(b(3), vec![]);
        let mut stmts = HashMap::new();
        stmts.insert(b(0), vec![InputStatement::assign(v(0), vec![])]);
        stmts.insert(b(1), vec![InputStatement::use_only(vec![v(0)])]);
        stmts.insert(b(2), vec![InputStatement::assign(v(0), vec![v(0)])]);
        stmts.insert(b(3), vec![InputStatement::use_only(vec![v(0)])]);
        let cfg = TestCfg {
            blocks: vec![b(0), b(1), b(2), b(3)],
            succs,
            stmts,
            vars: vec![v(0)],
        };
        let ssa = construct_ssa(&cfg);
        let header_phis = ssa.phi_nodes.get(&b(1)).expect("phi at loop header");
        assert_eq!(header_phis.len(), 1);
        assert_eq!(header_phis[0].sources.len(), 2);
    }

    #[test]
    fn def_count_matches_total_versions() {
        // Two vars, simple if-else.
        let mut succs = HashMap::new();
        succs.insert(b(0), vec![b(1), b(2)]);
        succs.insert(b(1), vec![b(3)]);
        succs.insert(b(2), vec![b(3)]);
        succs.insert(b(3), vec![]);
        let mut stmts = HashMap::new();
        stmts.insert(b(0), vec![InputStatement::assign(v(0), vec![])]);
        stmts.insert(b(1), vec![InputStatement::assign(v(1), vec![v(0)])]);
        stmts.insert(b(2), vec![InputStatement::assign(v(1), vec![v(0)])]);
        stmts.insert(b(3), vec![InputStatement::use_only(vec![v(1)])]);
        let cfg = TestCfg {
            blocks: vec![b(0), b(1), b(2), b(3)],
            succs,
            stmts,
            vars: vec![v(0), v(1)],
        };
        let ssa = construct_ssa(&cfg);
        // v0 defined once; v1 defined twice + 1 phi = 3 versions.  Total = 4.
        assert_eq!(ssa.def_count, 4);
    }

    #[test]
    fn empty_cfg_produces_empty_form() {
        let cfg = TestCfg {
            blocks: vec![],
            succs: HashMap::new(),
            stmts: HashMap::new(),
            vars: vec![],
        };
        let ssa = construct_ssa(&cfg);
        assert!(ssa.blocks.is_empty());
        assert!(ssa.phi_nodes.is_empty());
        assert_eq!(ssa.def_count, 0);
    }
}
