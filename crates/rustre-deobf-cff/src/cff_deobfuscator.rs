//! Control-flow flattening deobfuscator.
//!
//! Detects the state machine, solves state transitions via constant propagation,
//! and rebuilds the CFG by splicing the original edges and removing the dispatcher.

use std::collections::{HashMap, HashSet};

use crate::cff_state_machine::{BasicBlock, CffStateMachine, DispatcherInfo};
#[cfg(test)]
use crate::cff_state_machine::DispatchRead;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeobfError {
    DetectionFailed(String),
    ConstantPropFailed(String),
    CfgRebuildFailed(String),
    MaxIterationsExceeded,
}

impl std::fmt::Display for DeobfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DetectionFailed(s) => write!(f, "detection failed: {s}"),
            Self::ConstantPropFailed(s) => write!(f, "constant prop failed: {s}"),
            Self::CfgRebuildFailed(s) => write!(f, "CFG rebuild failed: {s}"),
            Self::MaxIterationsExceeded => write!(f, "max deobfuscation iterations exceeded"),
        }
    }
}

impl std::error::Error for DeobfError {}

// ─── CondExpr ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CondExpr {
    Always,
    IfTrue(u64),  // conditional jump taken (target addr)
    IfFalse(u64), // conditional jump not taken (fall-through addr)
}

// ─── StateAssignment ─────────────────────────────────────────────────────────

/// A write to the state variable within a state block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateAssignment {
    pub state_var_offset: i32,
    pub new_value: u32,
    pub condition: Option<CondExpr>,
}

// ─── DeobfConfig ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DeobfConfig {
    pub remove_dispatcher: bool,
    pub inline_states: bool,
    pub simplify_state_variable: bool,
    pub max_iterations: u32,
}

impl Default for DeobfConfig {
    fn default() -> Self {
        Self {
            remove_dispatcher: true,
            inline_states: true,
            simplify_state_variable: true,
            max_iterations: 64,
        }
    }
}

// ─── DeobfResult ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct DeobfResult {
    pub original_block_count: u32,
    pub deobfuscated_block_count: u32,
    pub removed_blocks: Vec<u64>,
    pub added_edges: Vec<(u64, u64)>,
    pub modified_blocks: Vec<u64>,
}

// ─── RebuiltCfg ──────────────────────────────────────────────────────────────

/// The output of deobfuscation: a simplified CFG with no dispatcher.
#[derive(Debug, Clone, Default)]
pub struct RebuiltCfg {
    pub blocks: HashMap<u64, BasicBlock>,
    pub entry: u64,
}

impl RebuiltCfg {
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
}

// ─── CffDeobfuscator ─────────────────────────────────────────────────────────

pub struct CffDeobfuscator {
    pub config: DeobfConfig,
    /// Raw basic blocks of the function under analysis.
    blocks: HashMap<u64, BasicBlock>,
    /// State assignments discovered per block address.
    state_assignments: HashMap<u64, Vec<StateAssignment>>,
}

impl CffDeobfuscator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: DeobfConfig::default(),
            blocks: HashMap::new(),
            state_assignments: HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_config(config: DeobfConfig) -> Self {
        Self { config, blocks: HashMap::new(), state_assignments: HashMap::new() }
    }

    pub fn add_block(&mut self, block: BasicBlock) {
        self.blocks.insert(block.addr, block);
    }

    pub fn set_state_assignments(
        &mut self,
        block_addr: u64,
        assignments: Vec<StateAssignment>,
    ) {
        self.state_assignments.insert(block_addr, assignments);
    }

    /// Main entry point: detect SM, solve transitions, rebuild CFG.
    ///
    /// # Errors
    ///
    /// Returns `Err` when no dispatcher is found, constant propagation fails,
    /// or the CFG cannot be rebuilt.
    pub fn remove_flattening(&self) -> Result<(RebuiltCfg, DeobfResult), DeobfError> {
        let original_count = u32::try_from(self.blocks.len()).unwrap_or(u32::MAX);

        // 1. Build SM analyser
        let mut sm = CffStateMachine::new();
        for block in self.blocks.values() {
            sm.add_block(block.clone());
        }

        let dispatcher = sm
            .detect_dispatcher()
            .map_err(|e| DeobfError::DetectionFailed(e.to_string()))?;

        // 2. Solve constant state transitions
        let resolved_edges =
            self.recover_original_edges(&dispatcher, &sm)?;

        // 3. Rebuild CFG
        let (rebuilt, result) =
            self.rebuild_cfg_without_dispatcher(&dispatcher, &resolved_edges, original_count);

        Ok((rebuilt, result))
    }

    /// For each state block, determine its successor by solving which new state
    /// value is written to the state variable at the block's end.
    ///
    /// # Errors
    ///
    /// Returns `Err` when the CFG cannot be rebuilt from the recovered edges.
    pub fn recover_original_edges(
        &self,
        dispatcher: &DispatcherInfo,
        _sm: &CffStateMachine,
    ) -> Result<HashMap<u64, Vec<(u64, CondExpr)>>, DeobfError> {
        let mut edges: HashMap<u64, Vec<(u64, CondExpr)>> = HashMap::new();

        for &block_addr in &dispatcher.dispatch_block_addrs {
            let Some(assignments_vec) = self.state_assignments.get(&block_addr) else {
                // No assignments: try to infer from block successors
                if let Some(b) = self.blocks.get(&block_addr) {
                    for &succ in &b.successors {
                        if dispatcher.dispatch_block_addrs.contains(&succ) {
                            edges.entry(block_addr).or_default().push((succ, CondExpr::Always));
                        }
                    }
                }
                continue;
            };
            let assignments = assignments_vec.as_slice();

            let sv_offset = dispatcher.state_var_offset.unwrap_or_else(
                || assignments.first().map_or(0, |a| a.state_var_offset),
            );

            for assign in assignments {
                if assign.state_var_offset != sv_offset {
                    continue;
                }
                let new_state = assign.new_value as usize;
                if let Some(&target_addr) =
                    dispatcher.dispatch_block_addrs.get(new_state)
                {
                    let cond = assign.condition.clone().unwrap_or(CondExpr::Always);
                    edges.entry(block_addr).or_default().push((target_addr, cond));
                }
            }
        }

        Ok(edges)
    }

    /// Constant propagation: if the state variable is always a known constant
    /// at the dispatcher, resolve the single dispatch target directly.
    #[must_use]
    pub fn solve_constant_state(
        &self,
        dispatcher_addr: u64,
        known_state_values: &HashMap<u64, u32>,
        dispatch_targets: &[u64],
    ) -> Option<u64> {
        let state_val = *known_state_values.get(&dispatcher_addr)?;
        dispatch_targets.get(state_val as usize).copied()
    }

    /// Remove the dispatcher block and splice original edges into the CFG.
    #[must_use]
    pub fn rebuild_cfg_without_dispatcher(
        &self,
        dispatcher: &DispatcherInfo,
        recovered_edges: &HashMap<u64, Vec<(u64, CondExpr)>>,
        original_count: u32,
    ) -> (RebuiltCfg, DeobfResult) {
        let mut new_blocks: HashMap<u64, BasicBlock> = HashMap::new();
        let mut removed: Vec<u64> = Vec::new();
        let mut added_edges: Vec<(u64, u64)> = Vec::new();
        let mut modified: Vec<u64> = Vec::new();

        for (&addr, block) in &self.blocks {
            // Skip the dispatcher block
            if addr == dispatcher.dispatcher_addr {
                removed.push(addr);
                continue;
            }

            let mut new_block = block.clone();

            // Replace successors that point to dispatcher with resolved targets
            let new_succs: Vec<u64> = new_block
                .successors
                .iter()
                .flat_map(|&succ| {
                    if succ == dispatcher.dispatcher_addr {
                        // Replace with recovered targets
                        recovered_edges.get(&addr).map_or_else(
                            Vec::new,
                            |targets| targets.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
                        )
                    } else {
                        vec![succ]
                    }
                })
                .collect();

            if new_succs != new_block.successors {
                for &ns in &new_succs {
                    added_edges.push((addr, ns));
                }
                modified.push(addr);
            }
            new_block.successors = new_succs;
            new_blocks.insert(addr, new_block);
        }

        // Determine the function entry (block with no predecessors in the new CFG)
        let all_targets: HashSet<u64> =
            new_blocks.values().flat_map(|b| b.successors.iter().copied()).collect();
        let entry = new_blocks
            .keys()
            .find(|&&a| !all_targets.contains(&a))
            .copied()
            .or_else(|| {
                // Cyclic CFG: fall back to the first dispatch target, or smallest
                // block address, so callers still get a meaningful entry point.
                dispatcher
                    .dispatch_block_addrs
                    .iter()
                    .find(|a| new_blocks.contains_key(a))
                    .copied()
                    .or_else(|| new_blocks.keys().min().copied())
            })
            .unwrap_or(0);

        let deobf_count = u32::try_from(new_blocks.len()).unwrap_or(u32::MAX);

        let result = DeobfResult {
            original_block_count: original_count,
            deobfuscated_block_count: deobf_count,
            removed_blocks: removed,
            added_edges,
            modified_blocks: modified,
        };

        (RebuiltCfg { blocks: new_blocks, entry }, result)
    }

    /// Iterative deobfuscation for multi-level CFF.
    ///
    /// # Errors
    ///
    /// Returns `Err` when edge recovery fails or maximum iterations are exceeded.
    pub fn remove_flattening_iterative(
        &mut self,
    ) -> Result<(RebuiltCfg, Vec<DeobfResult>), DeobfError> {
        let mut results = Vec::new();
        let mut current_blocks = self.blocks.clone();

        for _iter in 0..self.config.max_iterations {
            // Rebuild analyser from current state
            let mut sm = CffStateMachine::new();
            for b in current_blocks.values() {
                sm.add_block(b.clone());
            }

            let Ok(dispatcher) = sm.detect_dispatcher() else { break };

            // Temporary deobfuscator instance
            let mut tmp = Self::new();
            tmp.blocks.clone_from(&current_blocks);
            tmp.state_assignments.clone_from(&self.state_assignments);

            let recovered =
                tmp.recover_original_edges(&dispatcher, &sm)?;
            let (rebuilt, result) = tmp.rebuild_cfg_without_dispatcher(
                &dispatcher,
                &recovered,
                u32::try_from(current_blocks.len()).unwrap_or(u32::MAX),
            );

            current_blocks.clone_from(&rebuilt.blocks);
            results.push(result);
        }

        if u32::try_from(results.len()).unwrap_or(u32::MAX) >= self.config.max_iterations {
            return Err(DeobfError::MaxIterationsExceeded);
        }

        let entry = current_blocks
            .keys()
            .copied()
            .next()
            .unwrap_or(0);

        Ok((RebuiltCfg { blocks: current_blocks, entry }, results))
    }
}

impl Default for CffDeobfuscator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dispatcher(addr: u64, targets: Vec<u64>) -> BasicBlock {
        let mut b = BasicBlock::new(addr);
        b.switch_targets = targets.clone();
        b.successors = targets;
        b.dispatch_read = Some(DispatchRead { stack_offset: Some(-4), register: None });
        b
    }

    fn make_state(addr: u64, succs: Vec<u64>) -> BasicBlock {
        let mut b = BasicBlock::new(addr);
        b.successors = succs;
        b
    }

    fn deobf_with_5_states() -> CffDeobfuscator {
        let mut d = CffDeobfuscator::new();
        let targets: Vec<u64> = (0u64..5).map(|i| 0x200 + i * 0x100).collect();
        d.add_block(make_dispatcher(0x1000, targets.clone()));
        for (i, &t) in targets.iter().enumerate() {
            let mut b = make_state(t, vec![0x1000]);
            b.loop_depth = 0;
            d.add_block(b);
            // State i writes state i+1 (last wraps to 0)
            let next = u32::try_from((i + 1) % 5).unwrap_or(u32::MAX);
            d.set_state_assignments(
                t,
                vec![StateAssignment {
                    state_var_offset: -4,
                    new_value: next,
                    condition: Some(CondExpr::Always),
                }],
            );
        }
        d
    }

    // 1. remove_flattening succeeds on simple case
    #[test]
    fn test_remove_flattening_basic() {
        let d = deobf_with_5_states();
        let (rebuilt, result) = d.remove_flattening().unwrap();
        assert!(result.deobfuscated_block_count < result.original_block_count);
        assert!(!rebuilt.blocks.is_empty());
    }

    // 2. Dispatcher block is removed
    #[test]
    fn test_dispatcher_removed() {
        let d = deobf_with_5_states();
        let (rebuilt, result) = d.remove_flattening().unwrap();
        assert!(result.removed_blocks.contains(&0x1000));
        assert!(!rebuilt.blocks.contains_key(&0x1000));
    }

    // 3. Recovered edges replace dispatcher successors
    #[test]
    fn test_edges_replaced() {
        let d = deobf_with_5_states();
        let (rebuilt, result) = d.remove_flattening().unwrap();
        // At least some edges should have been added
        assert!(!result.added_edges.is_empty());
        // No block should have 0x1000 as a successor
        for block in rebuilt.blocks.values() {
            assert!(!block.successors.contains(&0x1000),
                "block 0x{:x} still points to dispatcher", block.addr);
        }
    }

    // 4. DeobfResult counts are consistent
    #[test]
    fn test_deobf_result_counts() {
        let d = deobf_with_5_states();
        let (_, result) = d.remove_flattening().unwrap();
        assert_eq!(result.original_block_count, 6); // 5 states + 1 dispatcher
        assert_eq!(result.deobfuscated_block_count, 5);
    }

    // 5. solve_constant_state resolves correct target
    #[test]
    fn test_solve_constant_state() {
        let d = CffDeobfuscator::new();
        let targets = vec![0x100u64, 0x200, 0x300];
        let mut known = HashMap::new();
        known.insert(0xaaau64, 2u32);
        let result = d.solve_constant_state(0xaaa, &known, &targets);
        assert_eq!(result, Some(0x300));
    }

    // 6. solve_constant_state out-of-bounds returns None
    #[test]
    fn test_solve_constant_state_oob() {
        let d = CffDeobfuscator::new();
        let targets = vec![0x100u64];
        let mut known = HashMap::new();
        known.insert(0xaaau64, 99u32);
        assert!(d.solve_constant_state(0xaaa, &known, &targets).is_none());
    }

    // 7. CondExpr::Always assignment unconditionally resolved
    #[test]
    fn test_cond_always() {
        let mut d = CffDeobfuscator::new();
        let targets = vec![0x100u64, 0x200, 0x300, 0x400, 0x500];
        d.add_block(make_dispatcher(0x1000, targets.clone()));
        for &t in &targets {
            d.add_block(make_state(t, vec![0x1000]));
        }
        d.set_state_assignments(
            0x100,
            vec![StateAssignment {
                state_var_offset: -4,
                new_value: 2,
                condition: Some(CondExpr::Always),
            }],
        );

        let mut sm = CffStateMachine::new();
        for b in d.blocks.values() { sm.add_block(b.clone()); }
        let info = sm.detect_dispatcher().unwrap();
        let edges = d.recover_original_edges(&info, &sm).unwrap();
        let resolved = edges.get(&0x100).unwrap();
        assert!(resolved.iter().any(|(addr, _)| *addr == 0x300));
    }

    // 8. CondExpr::IfTrue recorded correctly
    #[test]
    fn test_cond_if_true_recorded() {
        let assign = StateAssignment {
            state_var_offset: -4,
            new_value: 1,
            condition: Some(CondExpr::IfTrue(0x2000)),
        };
        assert_eq!(assign.condition, Some(CondExpr::IfTrue(0x2000)));
    }

    // 9. Empty deobfuscator returns detection error
    #[test]
    fn test_empty_deobfuscator() {
        let d = CffDeobfuscator::new();
        let err = d.remove_flattening().unwrap_err();
        assert!(matches!(err, DeobfError::DetectionFailed(_)));
    }

    // 10. rebuild_cfg_without_dispatcher entry is non-zero
    #[test]
    fn test_rebuilt_entry_non_zero() {
        let d = deobf_with_5_states();
        let (rebuilt, _) = d.remove_flattening().unwrap();
        assert_ne!(rebuilt.entry, 0u64);
    }

    // 11. StateAssignment equality
    #[test]
    fn test_state_assignment_equality() {
        let a = StateAssignment { state_var_offset: -4, new_value: 3, condition: None };
        let b = StateAssignment { state_var_offset: -4, new_value: 3, condition: None };
        assert_eq!(a, b);
    }

    // 12. DeobfConfig default values
    #[test]
    fn test_default_config() {
        let c = DeobfConfig::default();
        assert!(c.remove_dispatcher);
        assert!(c.inline_states);
        assert_eq!(c.max_iterations, 64);
    }

    // 13. Modified blocks list non-empty after deobf
    #[test]
    fn test_modified_blocks_non_empty() {
        let d = deobf_with_5_states();
        let (_, result) = d.remove_flattening().unwrap();
        assert!(!result.modified_blocks.is_empty());
    }

    // 14. No duplicate blocks in rebuilt CFG
    #[test]
    fn test_no_duplicate_blocks() {
        let d = deobf_with_5_states();
        let (rebuilt, _) = d.remove_flattening().unwrap();
        let addrs: Vec<u64> = rebuilt.blocks.keys().copied().collect();
        let unique: HashSet<u64> = addrs.iter().copied().collect();
        assert_eq!(addrs.len(), unique.len());
    }

    // 15. remove_flattening_iterative stops when no more dispatchers
    #[test]
    fn test_iterative_stops_cleanly() {
        let mut d = deobf_with_5_states();
        let (rebuilt, results) = d.remove_flattening_iterative().unwrap();
        assert!(!results.is_empty());
        assert!(!rebuilt.blocks.is_empty());
    }
}
