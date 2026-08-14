//! Dead code elimination: mark reachable blocks from entry, remove unreachable
//! ones, and identify dead instructions (NOPs, constant-result branches, unused
//! assignments).
//!
//! [`DeadCodeEliminator`] operates on a simple IR-like representation so it
//! can be used without a full disassembler.  For production use the IL-level
//! pass is preferred; this module provides the data-flow scaffolding.

use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// Variable / Register abstraction
// ─────────────────────────────────────────────────────────────────────────────

/// A symbolic variable or physical register identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Var {
    /// Named variable (e.g. from MLIL).
    Named(String),
    /// Physical register by index.
    Reg(u32),
    /// Temporary scratch variable.
    Temp(u32),
}

impl std::fmt::Display for Var {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Named(s) => write!(f, "{s}"),
            Self::Reg(r) => write!(f, "r{r}"),
            Self::Temp(t) => write!(f, "tmp{t}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IrInstruction
// ─────────────────────────────────────────────────────────────────────────────

/// Simplified IR instruction for liveness analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrInstruction {
    /// `dst = src` or `dst = constant`.
    Assign { dst: Var, src_vars: Vec<Var> },
    /// Conditional branch that always resolves to `taken`.
    ConstantBranch { condition_var: Var, taken: bool },
    /// No-operation (already dead).
    Nop,
    /// A `call` to `target` with `args`.
    Call {
        target: String,
        args: Vec<Var>,
        result: Option<Var>,
    },
    /// Generic instruction with explicit defs and uses.
    Generic { defs: Vec<Var>, uses: Vec<Var> },
}

impl IrInstruction {
    /// Variables defined (written) by this instruction.
    #[must_use]
    pub fn defs(&self) -> Vec<&Var> {
        match self {
            Self::Assign { dst, .. } => vec![dst],
            Self::Call {
                result: Some(r), ..
            } => vec![r],
            Self::Generic { defs, .. } => defs.iter().collect(),
            _ => vec![],
        }
    }

    /// Variables used (read) by this instruction.
    #[must_use]
    pub fn uses(&self) -> Vec<&Var> {
        match self {
            Self::Assign { src_vars, .. } => src_vars.iter().collect(),
            Self::ConstantBranch { condition_var, .. } => vec![condition_var],
            Self::Call { args, .. } => args.iter().collect(),
            Self::Generic { uses, .. } => uses.iter().collect(),
            Self::Nop => vec![],
        }
    }

    /// `true` if this instruction is a NOP or a constant-result branch.
    #[must_use]
    pub const fn is_trivially_dead(&self) -> bool {
        matches!(self, Self::Nop | Self::ConstantBranch { .. })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeadInstruction
// ─────────────────────────────────────────────────────────────────────────────

/// Description of a dead or useless instruction discovered by the eliminator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeadInstruction {
    /// A NOP or zero-operand no-op.
    Nop {
        /// Block offset containing the instruction.
        block_offset: usize,
        /// Instruction index within the block.
        insn_index: usize,
    },
    /// A branch whose condition is provably constant.
    ConstantResultBranch {
        block_offset: usize,
        insn_index: usize,
        /// The branch is always taken (`true`) or never taken (`false`).
        always_taken: bool,
    },
    /// An assignment whose destination is never subsequently read.
    UnusedAssignment {
        block_offset: usize,
        insn_index: usize,
        /// The dead variable.
        var: Var,
    },
}

impl DeadInstruction {
    /// Block offset containing the dead instruction.
    #[must_use]
    pub const fn block_offset(&self) -> usize {
        match self {
            Self::Nop { block_offset, .. }
            | Self::ConstantResultBranch { block_offset, .. }
            | Self::UnusedAssignment { block_offset, .. } => *block_offset,
        }
    }

    /// Human-readable description of the dead instruction.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::Nop {
                block_offset,
                insn_index,
            } => format!("NOP at block {block_offset:#x} insn {insn_index}"),
            Self::ConstantResultBranch {
                block_offset,
                insn_index,
                always_taken,
            } => format!(
                "constant-branch at block {block_offset:#x} insn {insn_index} ({})",
                if *always_taken {
                    "always taken"
                } else {
                    "never taken"
                }
            ),
            Self::UnusedAssignment {
                block_offset,
                insn_index,
                var,
            } => format!("unused assignment of {var} at block {block_offset:#x} insn {insn_index}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IrBlock
// ─────────────────────────────────────────────────────────────────────────────

/// A basic block containing a list of [`IrInstruction`]s.
#[derive(Debug, Clone)]
pub struct IrBlock {
    /// File/virtual offset of this block.
    pub offset: usize,
    /// Instructions in execution order.
    pub instructions: Vec<IrInstruction>,
    /// Successor block offsets.
    pub successors: Vec<usize>,
}

impl IrBlock {
    /// Create a new block.
    #[must_use]
    pub const fn new(offset: usize, instructions: Vec<IrInstruction>, successors: Vec<usize>) -> Self {
        Self {
            offset,
            instructions,
            successors,
        }
    }

    /// Number of instructions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Returns `true` if the block has no instructions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LiveVariableAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// Per-block liveness sets produced by [`LiveVariableAnalysis`].
#[derive(Debug, Clone, Default)]
pub struct LivenessSets {
    /// Variables live at the block *entry* (used before being defined).
    pub live_in: HashSet<Var>,
    /// Variables live at the block *exit* (used in at least one successor).
    pub live_out: HashSet<Var>,
    /// Variables generated (used before defined) in this block.
    pub r#gen: HashSet<Var>,
    /// Variables killed (defined before used) in this block.
    pub kill: HashSet<Var>,
}

/// Classic backwards liveness dataflow over [`IrBlock`]s.
///
/// Algorithm:
/// 1. Compute per-block GEN/KILL sets.
/// 2. Iterate backwards until a fixpoint:
///    - `live_out[B] = union of live_in[S] for each successor S`
///    - `live_in[B] = (live_out[B] - kill[B]) ∪ gen[B]`
#[derive(Debug, Clone, Default)]
pub struct LiveVariableAnalysis;

impl LiveVariableAnalysis {
    /// Create a new analysis.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Run liveness dataflow over `blocks`.
    ///
    /// Returns a map from block offset to [`LivenessSets`].
    ///
    /// # Panics
    ///
    /// Panics if an offset appears in the successor list but has no entry in
    /// the liveness set (i.e. the IR graph is inconsistent).
    #[must_use]
    pub fn analyze(&self, blocks: &[IrBlock]) -> HashMap<usize, LivenessSets> {
        let mut sets: HashMap<usize, LivenessSets> = blocks
            .iter()
            .map(|b| (b.offset, Self::compute_gen_kill(b)))
            .collect();

        // Iterative backwards dataflow.
        let max_iter = blocks.len() * 2 + 4;

        // Process blocks in reverse offset order for faster convergence.
        // Hoisted out of the loop — block offsets don't change.
        let mut offsets: Vec<usize> = blocks.iter().map(|b| b.offset).collect();
        offsets.sort_unstable_by(|a, b| b.cmp(a)); // descending

        // Index from offset → block, to avoid O(n) linear scans inside the loop.
        let block_by_offset: HashMap<usize, &IrBlock> =
            blocks.iter().map(|b| (b.offset, b)).collect();

        for _ in 0..max_iter {
            let mut changed = false;

            for &off in &offsets {
                let new_live_out: HashSet<Var> = {
                    let block = block_by_offset.get(&off).unwrap();
                    block
                        .successors
                        .iter()
                        .flat_map(|s| sets.get(s).into_iter().flat_map(|ls| ls.live_in.iter().cloned()))
                        .collect()
                };

                let ls = sets.get(&off).unwrap();
                let new_live_in: HashSet<Var> = ls
                    .r#gen
                    .iter()
                    .cloned()
                    .chain(
                        new_live_out
                            .iter()
                            .filter(|v| !ls.kill.contains(v))
                            .cloned(),
                    )
                    .collect();

                let ls_mut = sets.get_mut(&off).unwrap();
                if new_live_out != ls_mut.live_out || new_live_in != ls_mut.live_in {
                    ls_mut.live_out = new_live_out;
                    ls_mut.live_in = new_live_in;
                    changed = true;
                }
            }

            if !changed {
                break;
            }
        }

        sets
    }

    /// Compute the GEN and KILL sets for a single block.
    fn compute_gen_kill(block: &IrBlock) -> LivenessSets {
        let mut r#gen: HashSet<Var> = HashSet::new();
        let mut kill: HashSet<Var> = HashSet::new();

        for insn in &block.instructions {
            // Uses that are not yet killed come from outside — add to GEN.
            // NOTE: uses MUST be tested before defs are recorded. An
            // instruction reads its operands before writing its result, so a
            // read-modify-write (`a = a + 1`) must GEN `a`, not kill it.
            for u in insn.uses() {
                if !kill.contains(u) {
                    r#gen.insert(u.clone());
                }
            }
            // Defs kill variables.
            for d in insn.defs() {
                kill.insert(d.clone());
            }
        }

        LivenessSets {
            live_in: r#gen.clone(),
            live_out: HashSet::new(),
            r#gen,
            kill,
        }
    }

    /// Return the set of variables live immediately before instruction `index`
    /// in `block`, given precomputed liveness `sets`.
    #[must_use]
    pub fn live_before(
        &self,
        block: &IrBlock,
        index: usize,
        sets: &HashMap<usize, LivenessSets>,
    ) -> HashSet<Var> {
        let live_out = sets
            .get(&block.offset)
            .map(|s| s.live_out.clone())
            .unwrap_or_default();

        // Walk backwards from the block's live_out.
        let mut live = live_out;
        for i in (index..block.instructions.len()).rev() {
            let insn = &block.instructions[i];
            for d in insn.defs() {
                live.remove(d);
            }
            for u in insn.uses() {
                live.insert(u.clone());
            }
        }
        live
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EliminationResult
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of what the dead-code elimination pass accomplished.
#[derive(Debug, Clone, Default)]
pub struct EliminationResult {
    /// Number of unreachable blocks removed.
    pub unreachable_blocks_removed: usize,
    /// Dead instructions identified (not physically removed here — patches
    /// should be generated from these).
    pub dead_instructions: Vec<DeadInstruction>,
}

impl EliminationResult {
    /// Total number of dead findings.
    #[must_use]
    pub const fn total_dead(&self) -> usize {
        self.unreachable_blocks_removed + self.dead_instructions.len()
    }

    /// Return only dead NOPs.
    pub fn nops(&self) -> impl Iterator<Item = &DeadInstruction> {
        self.dead_instructions
            .iter()
            .filter(|d| matches!(d, DeadInstruction::Nop { .. }))
    }

    /// Return only dead branches.
    pub fn constant_branches(&self) -> impl Iterator<Item = &DeadInstruction> {
        self.dead_instructions
            .iter()
            .filter(|d| matches!(d, DeadInstruction::ConstantResultBranch { .. }))
    }

    /// Return only unused assignments.
    pub fn unused_assignments(&self) -> impl Iterator<Item = &DeadInstruction> {
        self.dead_instructions
            .iter()
            .filter(|d| matches!(d, DeadInstruction::UnusedAssignment { .. }))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeadCodeEliminator
// ─────────────────────────────────────────────────────────────────────────────

/// Performs dead-code elimination at the block and instruction level.
///
/// Steps:
/// 1. Mark reachable blocks via DFS from `entry`.
/// 2. Identify dead instructions in reachable blocks via liveness analysis.
#[derive(Debug, Clone, Default)]
pub struct DeadCodeEliminator {
    /// Run unused-assignment detection (requires liveness analysis).
    pub detect_unused_assignments: bool,
    /// Run constant-branch detection.
    pub detect_constant_branches: bool,
    /// Run NOP detection.
    pub detect_nops: bool,
}

impl DeadCodeEliminator {
    /// Create an eliminator with all detection enabled.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            detect_unused_assignments: true,
            detect_constant_branches: true,
            detect_nops: true,
        }
    }

    /// Run elimination on `blocks` with `entry` as the entry block offset.
    ///
    /// Returns the live blocks and an [`EliminationResult`] summary.
    #[must_use]
    pub fn eliminate(
        &self,
        blocks: Vec<IrBlock>,
        entry: usize,
    ) -> (Vec<IrBlock>, EliminationResult) {
        let mut result = EliminationResult::default();

        // Step 1: compute reachability via DFS.
        let reachable = self.dfs_reachable(&blocks, entry);

        let (live_blocks, dead_blocks): (Vec<IrBlock>, Vec<IrBlock>) = blocks
            .into_iter()
            .partition(|b| reachable.contains(&b.offset));

        result.unreachable_blocks_removed = dead_blocks.len();

        // Step 2: run liveness analysis over live blocks.
        if self.detect_unused_assignments {
            let analysis = LiveVariableAnalysis::new();
            let sets = analysis.analyze(&live_blocks);

            for block in &live_blocks {
                let Some(ls) = sets.get(&block.offset) else { continue };
                let mut live: HashSet<Var> = ls.live_out.clone();

                // Walk backwards through the block.
                for (i, insn) in block.instructions.iter().enumerate().rev() {
                    let defs = insn.defs();
                    for d in &defs {
                        if !live.contains(d) {
                            result
                                .dead_instructions
                                .push(DeadInstruction::UnusedAssignment {
                                    block_offset: block.offset,
                                    insn_index: i,
                                    var: (*d).clone(),
                                });
                        }
                    }
                    // Update liveness.
                    for d in defs {
                        live.remove(d);
                    }
                    for u in insn.uses() {
                        live.insert(u.clone());
                    }
                }
            }
        }

        // Step 3: detect NOPs and constant branches.
        for block in &live_blocks {
            for (i, insn) in block.instructions.iter().enumerate() {
                if self.detect_nops
                    && matches!(insn, IrInstruction::Nop) {
                        result.dead_instructions.push(DeadInstruction::Nop {
                            block_offset: block.offset,
                            insn_index: i,
                        });
                    }
                if self.detect_constant_branches
                    && let IrInstruction::ConstantBranch { taken, .. } = insn {
                        result
                            .dead_instructions
                            .push(DeadInstruction::ConstantResultBranch {
                                block_offset: block.offset,
                                insn_index: i,
                                always_taken: *taken,
                            });
                    }
            }
        }

        (live_blocks, result)
    }

    /// BFS / DFS reachability from `entry`.
    #[must_use]
    pub fn dfs_reachable(&self, blocks: &[IrBlock], entry: usize) -> HashSet<usize> {
        let offset_map: HashMap<usize, &IrBlock> = blocks.iter().map(|b| (b.offset, b)).collect();

        let mut reachable = HashSet::new();
        let mut stack = vec![entry];

        while let Some(off) = stack.pop() {
            if !reachable.insert(off) {
                continue;
            }
            if let Some(b) = offset_map.get(&off) {
                for &s in &b.successors {
                    if !reachable.contains(&s) {
                        stack.push(s);
                    }
                }
            }
        }
        reachable
    }

    /// BFS order from `entry`.
    #[must_use]
    pub fn bfs_order(&self, blocks: &[IrBlock], entry: usize) -> Vec<usize> {
        let offset_map: HashMap<usize, &IrBlock> = blocks.iter().map(|b| (b.offset, b)).collect();

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut order = Vec::new();
        queue.push_back(entry);

        while let Some(off) = queue.pop_front() {
            if !visited.insert(off) {
                continue;
            }
            order.push(off);
            if let Some(b) = offset_map.get(&off) {
                for &s in &b.successors {
                    if !visited.contains(&s) {
                        queue.push_back(s);
                    }
                }
            }
        }
        order
    }

    /// Count dead blocks (not reachable from `entry`).
    #[must_use]
    pub fn dead_block_count(&self, blocks: &[IrBlock], entry: usize) -> usize {
        let reachable = self.dfs_reachable(blocks, entry);
        blocks
            .iter()
            .filter(|b| !reachable.contains(&b.offset))
            .count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn assign(dst: u32, src: u32) -> IrInstruction {
        IrInstruction::Assign {
            dst: Var::Reg(dst),
            src_vars: vec![Var::Reg(src)],
        }
    }

    fn assign_from(dst: u32, srcs: Vec<u32>) -> IrInstruction {
        IrInstruction::Assign {
            dst: Var::Reg(dst),
            src_vars: srcs.into_iter().map(Var::Reg).collect(),
        }
    }

    fn const_branch(cond: u32, taken: bool) -> IrInstruction {
        IrInstruction::ConstantBranch {
            condition_var: Var::Reg(cond),
            taken,
        }
    }

    fn nop_insn() -> IrInstruction {
        IrInstruction::Nop
    }

    fn generic(defs: Vec<u32>, uses: Vec<u32>) -> IrInstruction {
        IrInstruction::Generic {
            defs: defs.into_iter().map(Var::Reg).collect(),
            uses: uses.into_iter().map(Var::Reg).collect(),
        }
    }

    fn block(offset: usize, insns: Vec<IrInstruction>, succs: Vec<usize>) -> IrBlock {
        IrBlock::new(offset, insns, succs)
    }

    // ── Reachability ─────────────────────────────────────────────────────────

    #[test]
    fn test_dfs_reachable_simple() {
        let blocks = vec![
            block(0, vec![nop_insn()], vec![10]),
            block(10, vec![nop_insn()], vec![]),
        ];
        let elim = DeadCodeEliminator::new();
        let r = elim.dfs_reachable(&blocks, 0);
        assert!(r.contains(&0));
        assert!(r.contains(&10));
    }

    #[test]
    fn test_dfs_unreachable_block() {
        let blocks = vec![block(0, vec![], vec![]), block(100, vec![], vec![])];
        let elim = DeadCodeEliminator::new();
        let r = elim.dfs_reachable(&blocks, 0);
        assert!(!r.contains(&100));
    }

    #[test]
    fn test_eliminate_removes_dead_block() {
        let blocks = vec![
            block(0, vec![nop_insn()], vec![]),
            block(999, vec![nop_insn()], vec![]),
        ];
        let elim = DeadCodeEliminator::new();
        let (live, result) = elim.eliminate(blocks, 0);
        assert_eq!(result.unreachable_blocks_removed, 1);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].offset, 0);
    }

    #[test]
    fn test_eliminate_keeps_all_reachable() {
        let blocks = vec![
            block(0, vec![], vec![10, 20]),
            block(10, vec![], vec![]),
            block(20, vec![], vec![]),
        ];
        let elim = DeadCodeEliminator::new();
        let (live, result) = elim.eliminate(blocks, 0);
        assert_eq!(result.unreachable_blocks_removed, 0);
        assert_eq!(live.len(), 3);
    }

    // ── NOP detection ─────────────────────────────────────────────────────────

    #[test]
    fn test_detect_nops() {
        let blocks = vec![block(0, vec![nop_insn(), nop_insn()], vec![])];
        let elim = DeadCodeEliminator::new();
        let (_, result) = elim.eliminate(blocks, 0);
        let nop_count = result.nops().count();
        assert_eq!(nop_count, 2);
    }

    #[test]
    fn test_no_nops_detected_when_disabled() {
        let blocks = vec![block(0, vec![nop_insn()], vec![])];
        let elim = DeadCodeEliminator {
            detect_nops: false,
            ..DeadCodeEliminator::default()
        };
        let (_, result) = elim.eliminate(blocks, 0);
        assert_eq!(result.nops().count(), 0);
    }

    // ── Constant branch detection ─────────────────────────────────────────────

    #[test]
    fn test_detect_constant_branch_taken() {
        let blocks = vec![block(0, vec![const_branch(0, true)], vec![])];
        let elim = DeadCodeEliminator::new();
        let (_, result) = elim.eliminate(blocks, 0);
        let branches: Vec<_> = result.constant_branches().collect();
        assert_eq!(branches.len(), 1);
        if let DeadInstruction::ConstantResultBranch { always_taken, .. } = branches[0] {
            assert!(always_taken);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_detect_constant_branch_not_taken() {
        let blocks = vec![block(0, vec![const_branch(5, false)], vec![])];
        let elim = DeadCodeEliminator::new();
        let (_, result) = elim.eliminate(blocks, 0);
        assert_eq!(result.constant_branches().count(), 1);
    }

    // ── Unused assignment detection ───────────────────────────────────────────

    #[test]
    fn test_unused_assignment_detected() {
        // r0 is assigned but never used; r1 is used in a generic insn.
        let blocks = vec![block(
            0,
            vec![
                assign(0, 1),             // r0 = r1  (r0 never used after)
                generic(vec![], vec![1]), // uses r1 only
            ],
            vec![],
        )];
        let elim = DeadCodeEliminator::new();
        let (_, result) = elim.eliminate(blocks, 0);
        let unused: Vec<_> = result.unused_assignments().collect();
        assert!(!unused.is_empty());
        let dead_var = match &unused[0] {
            DeadInstruction::UnusedAssignment { var, .. } => var.clone(),
            _ => panic!("unexpected"),
        };
        assert_eq!(dead_var, Var::Reg(0));
    }

    #[test]
    fn test_used_assignment_not_marked_dead() {
        // r0 = r1; then r0 is used.
        let blocks = vec![block(
            0,
            vec![
                assign(0, 1),
                generic(vec![], vec![0]), // uses r0
            ],
            vec![],
        )];
        let elim = DeadCodeEliminator::new();
        let (_, result) = elim.eliminate(blocks, 0);
        let unused: Vec<_> = result.unused_assignments().collect();
        // r0 is used — must NOT be flagged.
        assert!(unused.iter().all(|d| {
            if let DeadInstruction::UnusedAssignment { var, .. } = d {
                *var != Var::Reg(0)
            } else {
                true
            }
        }));
    }

    // ── LiveVariableAnalysis ──────────────────────────────────────────────────

    #[test]
    fn test_liveness_gen_kill() {
        let blk = IrBlock::new(
            0,
            vec![
                generic(vec![0], vec![1]), // def r0, use r1
                generic(vec![2], vec![0]), // def r2, use r0
            ],
            vec![],
        );
        let analysis = LiveVariableAnalysis::new();
        let sets = analysis.analyze(&[blk]);
        let ls = &sets[&0];
        // r1 is used before being defined → in GEN.
        assert!(ls.r#gen.contains(&Var::Reg(1)));
        // r0 and r2 are defined → in KILL.
        assert!(ls.kill.contains(&Var::Reg(0)));
        assert!(ls.kill.contains(&Var::Reg(2)));
    }

    #[test]
    fn test_liveness_propagates_across_blocks() {
        // Block 0 uses r5; block 10 defines r5. So r5 live at exit of block 10.
        let blocks = vec![
            IrBlock::new(0, vec![generic(vec![], vec![5])], vec![]),
            IrBlock::new(10, vec![generic(vec![5], vec![])], vec![0]),
        ];
        let analysis = LiveVariableAnalysis::new();
        let sets = analysis.analyze(&blocks);
        // r5 should be live at the exit of block 10 (because block 0 needs it).
        assert!(sets[&10].live_out.contains(&Var::Reg(5)));
    }

    // ── Read-modify-write / accumulator (gen-before-kill bug probe) ──────────

    /// `a = a + 1` must record `a` in GEN: an instruction reads its operands
    /// BEFORE writing its result, so its own def must not kill its own use.
    #[test]
    fn probe_rmw_use_survives_own_def_in_gen_kill() {
        let blk = IrBlock::new(
            0,
            vec![IrInstruction::Assign {
                dst: Var::Reg(0),
                src_vars: vec![Var::Reg(0)],
            }],
            vec![],
        );
        let sets = LiveVariableAnalysis::new().analyze(&[blk]);
        let ls = &sets[&0];
        assert!(ls.r#gen.contains(&Var::Reg(0)), "a = a + 1 must GEN a");
        assert!(ls.live_in.contains(&Var::Reg(0)), "a must be live-in");
    }

    /// Accumulator loop: `a = 0; loop { a = a + 1 } ; use a`.
    /// Neither the initialiser nor the increment may be reported dead.
    #[test]
    fn probe_accumulator_loop_init_not_dead() {
        let blocks = vec![
            block(0, vec![assign_from(0, vec![])], vec![10]), // a = 0
            block(
                10,
                vec![assign_from(0, vec![0])], // a = a + 1
                vec![10, 20],
            ),
            block(20, vec![generic(vec![], vec![0])], vec![]), // use a
        ];
        let (_, result) = DeadCodeEliminator::new().eliminate(blocks, 0);
        let dead: Vec<_> = result.unused_assignments().collect();
        assert!(dead.is_empty(), "nothing may be dead, got {dead:?}");
    }

    /// Straight-line accumulator: `a = 1; a = a + 1; use a`.
    #[test]
    fn probe_accumulator_straightline_init_not_dead() {
        let blocks = vec![block(
            0,
            vec![
                assign_from(0, vec![]),      // a = 1
                assign_from(0, vec![0]),     // a = a + 1
                generic(vec![], vec![0]),    // use a
            ],
            vec![],
        )];
        let (_, result) = DeadCodeEliminator::new().eliminate(blocks, 0);
        let dead: Vec<_> = result.unused_assignments().collect();
        assert!(dead.is_empty(), "nothing may be dead, got {dead:?}");
    }

    /// `live_before` at the RMW instruction must report `a` live.
    #[test]
    fn probe_live_before_rmw() {
        let blk = IrBlock::new(0, vec![assign_from(0, vec![0])], vec![]);
        let sets = LiveVariableAnalysis::new().analyze(std::slice::from_ref(&blk));
        let live = LiveVariableAnalysis::new().live_before(&blk, 0, &sets);
        assert!(live.contains(&Var::Reg(0)));
    }

    // ── BFS order ────────────────────────────────────────────────────────────

    #[test]
    fn test_bfs_order_correct() {
        let blocks = vec![
            block(0, vec![], vec![10]),
            block(10, vec![], vec![20]),
            block(20, vec![], vec![]),
        ];
        let elim = DeadCodeEliminator::new();
        let order = elim.bfs_order(&blocks, 0);
        assert_eq!(order, vec![0, 10, 20]);
    }

    #[test]
    fn test_bfs_skips_unreachable() {
        let blocks = vec![
            block(0, vec![], vec![10]),
            block(10, vec![], vec![]),
            block(999, vec![], vec![]),
        ];
        let elim = DeadCodeEliminator::new();
        let order = elim.bfs_order(&blocks, 0);
        assert!(!order.contains(&999));
    }

    // ── Dead block count ──────────────────────────────────────────────────────

    #[test]
    fn test_dead_block_count() {
        let blocks = vec![
            block(0, vec![], vec![]),
            block(100, vec![], vec![]),
            block(200, vec![], vec![]),
        ];
        let elim = DeadCodeEliminator::new();
        assert_eq!(elim.dead_block_count(&blocks, 0), 2);
    }

    // ── EliminationResult helpers ─────────────────────────────────────────────

    #[test]
    fn test_elimination_result_total_dead() {
        let mut r = EliminationResult {
            unreachable_blocks_removed: 2,
            ..EliminationResult::default()
        };
        r.dead_instructions.push(DeadInstruction::Nop {
            block_offset: 0,
            insn_index: 0,
        });
        assert_eq!(r.total_dead(), 3);
    }

    // ── IrInstruction API ────────────────────────────────────────────────────

    #[test]
    fn test_assign_defs_uses() {
        let insn = assign(3, 7);
        assert_eq!(insn.defs(), vec![&Var::Reg(3)]);
        assert_eq!(insn.uses(), vec![&Var::Reg(7)]);
    }

    #[test]
    fn test_nop_no_defs_uses() {
        let insn = nop_insn();
        assert!(insn.defs().is_empty());
        assert!(insn.uses().is_empty());
        assert!(insn.is_trivially_dead());
    }

    #[test]
    fn test_constant_branch_trivially_dead() {
        let insn = const_branch(0, true);
        assert!(insn.is_trivially_dead());
    }

    // ── Var display ───────────────────────────────────────────────────────────

    #[test]
    fn test_var_display() {
        assert_eq!(Var::Named("x".into()).to_string(), "x");
        assert_eq!(Var::Reg(5).to_string(), "r5");
        assert_eq!(Var::Temp(3).to_string(), "tmp3");
    }

    // ── DeadInstruction description ───────────────────────────────────────────

    #[test]
    fn test_dead_instruction_description_nop() {
        let d = DeadInstruction::Nop {
            block_offset: 0x1000,
            insn_index: 3,
        };
        assert!(d.description().contains("NOP"));
        assert!(d.description().contains("0x1000"));
    }

    #[test]
    fn test_dead_instruction_block_offset() {
        let d = DeadInstruction::ConstantResultBranch {
            block_offset: 0x2000,
            insn_index: 0,
            always_taken: false,
        };
        assert_eq!(d.block_offset(), 0x2000);
    }
}
