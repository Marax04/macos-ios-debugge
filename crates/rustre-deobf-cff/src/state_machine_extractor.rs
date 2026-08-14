//! CFF state-machine extractor.
//!
//! After the flattening detector has identified a dispatcher block and state
//! variable, this module reconstructs the original control-flow graph by:
//!
//! 1. Building a state-transition table: `(state_value, block_id)` pairs.
//! 2. Computing the successor state for each "real" block by tracking
//!    assignments to the state variable.
//! 3. Reassembling the recovered CFG as a [`RecoveredCfg`] with direct
//!    block-to-block edges.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// State values
// ─────────────────────────────────────────────────────────────────────────────

/// A concrete value of the state variable (e.g., `0xdead_beef`).
pub type StateValue = u64;

/// Outcome of a state-variable assignment in a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateAssignment {
    /// The block sets the state variable to a known constant.
    Constant(StateValue),
    /// The block sets the state variable to one of several possible values
    /// (conditional update).
    Conditional { true_val: StateValue, false_val: StateValue },
    /// The block's assignment is not statically determinable.
    Unknown,
    /// The block does not modify the state variable.
    None,
}

// ─────────────────────────────────────────────────────────────────────────────
// StateMapping — maps state values to block IDs
// ─────────────────────────────────────────────────────────────────────────────

/// Maps each state value to the block that handles it.
#[derive(Debug, Clone, Default)]
pub struct StateMapping {
    /// `state_value → block_id`
    pub entries: HashMap<StateValue, u64>,
    /// Reverse map: `block_id → state_value`
    pub reverse: HashMap<u64, StateValue>,
}

impl StateMapping {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    pub fn insert(&mut self, state_val: StateValue, block_id: u64) {
        self.entries.insert(state_val, block_id);
        self.reverse.insert(block_id, state_val);
    }

    #[must_use]
    pub fn block_for(&self, state_val: StateValue) -> Option<u64> {
        self.entries.get(&state_val).copied()
    }

    #[must_use]
    pub fn state_for_block(&self, block_id: u64) -> Option<StateValue> {
        self.reverse.get(&block_id).copied()
    }

    #[must_use]
    pub fn len(&self) -> usize { self.entries.len() }

    #[must_use]
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

// ─────────────────────────────────────────────────────────────────────────────
// StateTransition
// ─────────────────────────────────────────────────────────────────────────────

/// A single transition in the recovered state machine.
#[derive(Debug, Clone)]
pub struct StateTransition {
    pub from_block: u64,
    pub from_state: StateValue,
    pub to_state: StateAssignment,
    /// Resolved successor block IDs (may be 1 or 2 for conditionals).
    pub successors: Vec<u64>,
}

impl StateTransition {
    #[must_use]
    pub const fn is_conditional(&self) -> bool {
        matches!(self.to_state, StateAssignment::Conditional { .. })
    }

    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self.to_state, StateAssignment::None)
    }
}

impl fmt::Display for StateTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "block_{:#x}(state={:#x}) → {:?}", self.from_block, self.from_state, self.to_state)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OriginalCfg (input representation used by the extractor)
// ─────────────────────────────────────────────────────────────────────────────

/// A block in the flattened CFG, annotated with state-machine information.
#[derive(Debug, Clone)]
pub struct FlatBlock {
    pub id: u64,
    /// Which state value routes execution here.
    pub entry_state: Option<StateValue>,
    /// How this block updates the state variable before returning to the dispatcher.
    pub state_assignment: StateAssignment,
    /// Original successors in the flat CFG (usually just the dispatcher).
    pub flat_successors: Vec<u64>,
    /// True if this is the function's exit (no state update).
    pub is_exit: bool,
    /// Instruction count (for weighting).
    pub instruction_count: usize,
}

impl FlatBlock {
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self {
            id,
            entry_state: None,
            state_assignment: StateAssignment::None,
            flat_successors: vec![],
            is_exit: false,
            instruction_count: 0,
        }
    }
}

/// A complete flattened function representation fed into the extractor.
#[derive(Debug, Default)]
pub struct FlatFunction {
    pub blocks: HashMap<u64, FlatBlock>,
    pub dispatcher_id: u64,
    pub entry_id: u64,
    pub entry_state: StateValue,
    pub state_mapping: StateMapping,
}

impl FlatFunction {
    #[must_use]
    pub fn new(dispatcher_id: u64, entry_id: u64, entry_state: StateValue) -> Self {
        Self {
            blocks: HashMap::new(),
            dispatcher_id,
            entry_id,
            entry_state,
            state_mapping: StateMapping::new(),
        }
    }

    pub fn add_block(&mut self, block: FlatBlock) {
        if let Some(sv) = block.entry_state {
            self.state_mapping.insert(sv, block.id);
        }
        self.blocks.insert(block.id, block);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RecoveredCfg
// ─────────────────────────────────────────────────────────────────────────────

/// A recovered block in the de-flattened CFG.
#[derive(Debug, Clone)]
pub struct RecoveredBlock {
    pub id: u64,
    /// Recovered successors (after removing dispatcher hops).
    pub successors: Vec<u64>,
    /// True if this is a conditional branch.
    pub is_conditional: bool,
    pub instruction_count: usize,
    pub original_state: Option<StateValue>,
}

/// The output of the state-machine extractor: a de-flattened CFG.
#[derive(Debug, Default)]
pub struct RecoveredCfg {
    pub blocks: HashMap<u64, RecoveredBlock>,
    pub entry_id: u64,
    pub transitions: Vec<StateTransition>,
    /// Blocks that could not be recovered (unknown state assignment).
    pub unresolved_blocks: Vec<u64>,
}

impl RecoveredCfg {
    #[must_use]
    pub fn block_count(&self) -> usize { self.blocks.len() }

    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.blocks.values().map(|b| b.successors.len()).sum()
    }

    /// BFS order starting from the entry.
    #[must_use]
    pub fn bfs_order(&self) -> Vec<u64> {
        let mut visited = HashSet::new();
        let mut order = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(self.entry_id);
        while let Some(id) = queue.pop_front() {
            if !visited.insert(id) { continue; }
            order.push(id);
            if let Some(b) = self.blocks.get(&id) {
                for &s in &b.successors { queue.push_back(s); }
            }
        }
        order
    }

    /// True if the recovered CFG forms a DAG (no back-edges from BFS).
    #[must_use]
    pub fn is_dag(&self) -> bool {
        let order = self.bfs_order();
        let rank: HashMap<u64, usize> = order.iter().enumerate().map(|(i, &id)| (id, i)).collect();
        for (id, block) in &self.blocks {
            let r = *rank.get(id).unwrap_or(&usize::MAX);
            for s in &block.successors {
                if *rank.get(s).unwrap_or(&usize::MAX) <= r { return false; }
            }
        }
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CffStateMachine — the recovered state machine model
// ─────────────────────────────────────────────────────────────────────────────

/// The intermediate state machine model, before conversion to a CFG.
#[derive(Debug)]
pub struct CffStateMachine {
    pub initial_state: StateValue,
    pub states: Vec<StateValue>,
    pub transitions: Vec<StateTransition>,
    pub terminal_states: Vec<StateValue>,
}

impl CffStateMachine {
    #[must_use]
    pub const fn state_count(&self) -> usize { self.states.len() }

    #[must_use]
    pub const fn transition_count(&self) -> usize { self.transitions.len() }

    #[must_use]
    pub fn is_deterministic(&self) -> bool {
        !self.transitions.iter().any(StateTransition::is_conditional)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StateMachineExtractor
// ─────────────────────────────────────────────────────────────────────────────

/// Extracts the original control-flow structure from a CFF-obfuscated function.
#[derive(Debug, Default)]
pub struct StateMachineExtractor;

impl StateMachineExtractor {
    #[must_use]
    pub const fn new() -> Self { Self }

    /// Run extraction and return a [`RecoveredCfg`].
    #[must_use]
    pub fn extract(&self, func: &FlatFunction) -> RecoveredCfg {
        let sm = self.build_state_machine(func);
        self.state_machine_to_cfg(&sm, func)
    }

    /// Build the abstract state machine from a [`FlatFunction`].
    #[must_use]
    pub fn build_state_machine(&self, func: &FlatFunction) -> CffStateMachine {
        let mut states: Vec<StateValue> = func.state_mapping.entries.keys().copied().collect();
        states.sort_unstable();

        let mut transitions = Vec::new();
        let mut terminal_states = Vec::new();

        for &sv in &states {
            let Some(block_id) = func.state_mapping.block_for(sv) else {
                terminal_states.push(sv);
                continue;
            };
            let Some(block) = func.blocks.get(&block_id) else { continue };

            let successors = Self::resolve_successors(&block.state_assignment, func);
            if block.is_exit || successors.is_empty() {
                terminal_states.push(sv);
            }

            transitions.push(StateTransition {
                from_block: block_id,
                from_state: sv,
                to_state: block.state_assignment.clone(),
                successors,
            });
        }

        CffStateMachine {
            initial_state: func.entry_state,
            states,
            transitions,
            terminal_states,
        }
    }

    fn resolve_successors(assignment: &StateAssignment, func: &FlatFunction) -> Vec<u64> {
        match assignment {
            StateAssignment::Constant(sv) => {
                func.state_mapping.block_for(*sv).into_iter().collect()
            }
            StateAssignment::Conditional { true_val, false_val } => {
                let mut succ = Vec::new();
                if let Some(b) = func.state_mapping.block_for(*true_val) { succ.push(b); }
                if let Some(b) = func.state_mapping.block_for(*false_val) { succ.push(b); }
                succ.dedup();
                succ
            }
            _ => vec![],
        }
    }

    /// Convert a [`CffStateMachine`] into a [`RecoveredCfg`].
    #[must_use]
    pub fn state_machine_to_cfg(&self, sm: &CffStateMachine, func: &FlatFunction) -> RecoveredCfg {
        let mut cfg = RecoveredCfg {
            entry_id: func.state_mapping.block_for(sm.initial_state).unwrap_or(func.entry_id),
            ..Default::default()
        };

        let mut unresolved = Vec::new();

        for t in &sm.transitions {
            let is_cond = t.is_conditional();
            let orig_state = func.state_mapping.state_for_block(t.from_block);
            let inst_count = func.blocks.get(&t.from_block)
                .map_or(0, |b| b.instruction_count);

            if matches!(t.to_state, StateAssignment::Unknown) {
                unresolved.push(t.from_block);
            }

            let rb = RecoveredBlock {
                id: t.from_block,
                successors: t.successors.clone(),
                is_conditional: is_cond,
                instruction_count: inst_count,
                original_state: orig_state,
            };
            cfg.blocks.insert(t.from_block, rb);
        }

        // Include terminal (exit) blocks with no successors
        for &sv in &sm.terminal_states {
            if let Some(block_id) = func.state_mapping.block_for(sv) {
                let inst_count = func.blocks.get(&block_id)
                    .map_or(0, |b| b.instruction_count);
                cfg.blocks.entry(block_id).or_insert_with(|| RecoveredBlock {
                    id: block_id,
                    successors: vec![],
                    is_conditional: false,
                    instruction_count: inst_count,
                    original_state: Some(sv),
                });
            }
        }

        cfg.transitions.clone_from(&sm.transitions);
        cfg.unresolved_blocks = unresolved;
        cfg
    }

    /// Compute which blocks are reachable from the initial state.
    #[must_use]
    pub fn reachable_states(&self, sm: &CffStateMachine) -> HashSet<StateValue> {
        let mut reachable = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(sm.initial_state);
        while let Some(sv) = queue.pop_front() {
            if !reachable.insert(sv) { continue; }
            for t in &sm.transitions {
                if t.from_state == sv {
                    match &t.to_state {
                        StateAssignment::Constant(next) => { queue.push_back(*next); }
                        StateAssignment::Conditional { true_val, false_val } => {
                            queue.push_back(*true_val);
                            queue.push_back(*false_val);
                        }
                        _ => {}
                    }
                }
            }
        }
        reachable
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_flat_func() -> FlatFunction {
        //  Entry (state=0) → A(1) → B(2) → Exit(3)
        let mut func = FlatFunction::new(100, 0, 0);

        let mut entry = FlatBlock::new(0);
        entry.entry_state = Some(0);
        entry.state_assignment = StateAssignment::Constant(1);
        entry.instruction_count = 5;
        func.add_block(entry);

        let mut a = FlatBlock::new(1);
        a.entry_state = Some(1);
        a.state_assignment = StateAssignment::Conditional { true_val: 2, false_val: 3 };
        a.instruction_count = 8;
        func.add_block(a);

        let mut b = FlatBlock::new(2);
        b.entry_state = Some(2);
        b.state_assignment = StateAssignment::Constant(3);
        b.instruction_count = 4;
        func.add_block(b);

        let mut exit = FlatBlock::new(3);
        exit.entry_state = Some(3);
        exit.state_assignment = StateAssignment::None;
        exit.is_exit = true;
        exit.instruction_count = 2;
        func.add_block(exit);

        func
    }

    #[test]
    fn test_state_machine_built() {
        let func = make_flat_func();
        let extractor = StateMachineExtractor::new();
        let sm = extractor.build_state_machine(&func);
        assert_eq!(sm.state_count(), 4);
        assert!(!sm.is_deterministic()); // block 1 is conditional
    }

    #[test]
    fn test_recovered_cfg_blocks() {
        let func = make_flat_func();
        let extractor = StateMachineExtractor::new();
        let cfg = extractor.extract(&func);
        assert_eq!(cfg.block_count(), 4);
        assert!(cfg.unresolved_blocks.is_empty());
    }

    #[test]
    fn test_entry_block_correct() {
        let func = make_flat_func();
        let extractor = StateMachineExtractor::new();
        let cfg = extractor.extract(&func);
        assert_eq!(cfg.entry_id, 0);
    }

    #[test]
    fn test_conditional_block() {
        let func = make_flat_func();
        let extractor = StateMachineExtractor::new();
        let cfg = extractor.extract(&func);
        let b1 = cfg.blocks.get(&1).unwrap();
        assert!(b1.is_conditional);
        assert_eq!(b1.successors.len(), 2);
    }

    #[test]
    fn test_exit_block_no_successors() {
        let func = make_flat_func();
        let extractor = StateMachineExtractor::new();
        let cfg = extractor.extract(&func);
        let exit = cfg.blocks.get(&3).unwrap();
        assert!(exit.successors.is_empty());
    }

    #[test]
    fn test_reachable_states() {
        let func = make_flat_func();
        let extractor = StateMachineExtractor::new();
        let sm = extractor.build_state_machine(&func);
        let reachable = extractor.reachable_states(&sm);
        assert!(reachable.contains(&0));
        assert!(reachable.contains(&1));
        assert!(reachable.contains(&2));
        assert!(reachable.contains(&3));
    }

    #[test]
    fn test_state_mapping() {
        let mut m = StateMapping::new();
        m.insert(0xdead_beef, 42);
        assert_eq!(m.block_for(0xdead_beef), Some(42));
        assert_eq!(m.state_for_block(42), Some(0xdead_beef));
        assert_eq!(m.block_for(99), None);
    }
}
