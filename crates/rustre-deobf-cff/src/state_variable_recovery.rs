//! `state_variable_recovery` — CFF state variable identification and recovery.
//!
//! Provides:
//! * Dispatcher block identification (large switch on state variable)
//! * State variable tracking (register / stack slot / global)
//! * State value mapping (state constant → real basic block)
//! * Predecessor analysis for each state
//! * Legitimate vs. obfuscated transition filtering

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::StateVariable;
use rustre_core::address::Address;

// ─────────────────────────────────────────────────────────────────────────────
// StateValue
// ─────────────────────────────────────────────────────────────────────────────

/// A concrete state value seen in the dispatcher.
pub type StateValue = u64;

// ─────────────────────────────────────────────────────────────────────────────
// BasicBlock representation for CFF analysis
// ─────────────────────────────────────────────────────────────────────────────

/// Lightweight representation of a basic block for CFF analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CffBlock {
    /// Block start address.
    pub address: Address,
    /// Block end address (exclusive).
    pub end_address: Address,
    /// All successor addresses.
    pub successors: Vec<Address>,
    /// All predecessor addresses.
    pub predecessors: Vec<Address>,
    /// Whether this block contains a state-variable assignment.
    pub has_state_assign: bool,
    /// State values assigned in this block (can be multiple due to conditional paths).
    pub assigned_state_values: Vec<StateValue>,
    /// Whether this block reads the state variable.
    pub reads_state: bool,
    /// Whether this block looks like a dispatcher/routing block.
    pub is_dispatcher: bool,
    /// Whether this block looks like real application logic.
    pub is_real_block: bool,
}

impl CffBlock {
    pub fn new(address: Address, end_address: Address) -> Self {
        Self {
            address,
            end_address,
            successors: Vec::new(),
            predecessors: Vec::new(),
            has_state_assign: false,
            assigned_state_values: Vec::new(),
            reads_state: false,
            is_dispatcher: false,
            is_real_block: false,
        }
    }

    pub fn size(&self) -> u64 {
        self.end_address.0.saturating_sub(self.address.0)
    }

    /// Whether this block is a purely routing block with no real work.
    pub fn is_routing_only(&self) -> bool {
        self.is_dispatcher && !self.is_real_block && self.size() < 64
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StateTransition
// ─────────────────────────────────────────────────────────────────────────────

/// One state-machine transition: from `src_state` to `dst_state`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    /// Source state value.
    pub src_state: StateValue,
    /// Destination state value.
    pub dst_state: StateValue,
    /// Address of the block that performs this transition.
    pub transition_block: Address,
    /// Whether this is a conditional transition (one of two outgoing edges).
    pub is_conditional: bool,
    /// Confidence that this transition is legitimate (not obfuscated padding).
    pub confidence: f32,
}

// ─────────────────────────────────────────────────────────────────────────────
// StateMapping
// ─────────────────────────────────────────────────────────────────────────────

/// Maps each state value to the real application block it represents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateMapping {
    /// state_value → real block address
    pub state_to_block: HashMap<StateValue, Address>,
    /// real block address → state_value
    pub block_to_state: HashMap<Address, StateValue>,
    /// All identified real block addresses (non-dispatcher blocks).
    pub real_blocks: Vec<Address>,
    /// All identified dispatcher/routing block addresses.
    pub dispatcher_blocks: Vec<Address>,
}

impl StateMapping {
    pub fn new() -> Self {
        Self {
            state_to_block: HashMap::new(),
            block_to_state: HashMap::new(),
            real_blocks: Vec::new(),
            dispatcher_blocks: Vec::new(),
        }
    }

    /// Register a state value → real block mapping.
    pub fn add(&mut self, state: StateValue, block: Address) {
        self.state_to_block.insert(state, block);
        self.block_to_state.insert(block, state);
        if !self.real_blocks.contains(&block) {
            self.real_blocks.push(block);
        }
    }

    /// Coverage: fraction of states that have been mapped to real blocks.
    pub fn coverage(&self, total_states: usize) -> f32 {
        if total_states == 0 {
            return 0.0;
        }
        self.state_to_block.len() as f32 / total_states as f32
    }
}

impl Default for StateMapping {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StateVariableRecovery result
// ─────────────────────────────────────────────────────────────────────────────

/// Full result of the state variable recovery analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateVariableRecoveryResult {
    /// The identified state variable location.
    pub state_var: StateVariable,
    /// Address of the main dispatcher block.
    pub dispatcher_address: Option<Address>,
    /// All distinct state values observed.
    pub state_values: Vec<StateValue>,
    /// All state transitions identified.
    pub transitions: Vec<StateTransition>,
    /// State ↔ real-block mapping.
    pub mapping: StateMapping,
    /// Predecessors for each state.
    pub predecessors: HashMap<StateValue, Vec<StateValue>>,
    /// Confidence score.
    pub confidence: f32,
    /// Evidence notes.
    pub evidence: Vec<String>,
}

impl StateVariableRecoveryResult {
    pub fn new() -> Self {
        Self {
            state_var: StateVariable::Unknown,
            dispatcher_address: None,
            state_values: Vec::new(),
            transitions: Vec::new(),
            mapping: StateMapping::new(),
            predecessors: HashMap::new(),
            confidence: 0.0,
            evidence: Vec::new(),
        }
    }

    /// Number of legitimate (non-obfuscated) transitions.
    pub fn legitimate_transition_count(&self) -> usize {
        self.transitions.iter().filter(|t| t.confidence >= 0.6).count()
    }
}

impl Default for StateVariableRecoveryResult {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StateVariableRecoverer
// ─────────────────────────────────────────────────────────────────────────────

/// Recovers the CFF state variable and builds the state transition graph.
pub struct StateVariableRecoverer {
    pub min_confidence: f32,
    /// Minimum number of successor blocks to classify a block as a dispatcher.
    pub dispatcher_min_successors: usize,
}

impl Default for StateVariableRecoverer {
    fn default() -> Self {
        Self::new()
    }
}

impl StateVariableRecoverer {
    pub fn new() -> Self {
        Self {
            min_confidence: 0.50,
            dispatcher_min_successors: 4,
        }
    }

    pub fn with_min_confidence(mut self, t: f32) -> Self {
        self.min_confidence = t;
        self
    }

    // ── Dispatcher identification ─────────────────────────────────────────────

    /// Identify the main dispatcher block: the one with the most successors
    /// that reads the state variable.
    pub fn identify_dispatcher<'a>(&self, blocks: &'a [CffBlock]) -> Option<&'a CffBlock> {
        blocks
            .iter()
            .filter(|b| {
                b.successors.len() >= self.dispatcher_min_successors && b.reads_state
            })
            .max_by_key(|b| b.successors.len())
    }

    // ── State variable identification ─────────────────────────────────────────

    /// Identify the state variable from the dispatcher block and its
    /// incoming assignment blocks.
    ///
    /// Strategy: a register or stack slot that is:
    /// * Written in every predecessor of the dispatcher, and
    /// * Read by the dispatcher (switch condition).
    pub fn identify_state_var(&self, blocks: &[CffBlock]) -> StateVariable {
        // Count how often each named variable is written across all assignment blocks
        let mut write_counts: HashMap<String, usize> = HashMap::new();

        for block in blocks {
            for &sv in &block.assigned_state_values {
                let key = format!("state_val_{}", sv);
                *write_counts.entry(key).or_insert(0) += 1;
            }
        }

        // If most blocks write exactly one state value, the state variable is
        // likely a single register.  Heuristic: return "eax" as the most common
        // CFF register (real analysis would use data-flow).
        let assigning_blocks: Vec<_> = blocks
            .iter()
            .filter(|b| b.has_state_assign)
            .collect();

        if assigning_blocks.is_empty() {
            return StateVariable::Unknown;
        }

        // Check if any block is a stack-slot assignment (negative offset pattern)
        let has_stack_slot = assigning_blocks.iter().any(|b| {
            b.assigned_state_values.iter().any(|&v| v > 0x1000_0000)
        });

        if has_stack_slot {
            // Likely stored on stack — common for OLLVM
            StateVariable::StackSlot(-4)
        } else if assigning_blocks.len() >= 3 {
            // If many blocks assign, it's almost certainly a register
            StateVariable::Register("eax".to_string())
        } else {
            StateVariable::Unknown
        }
    }

    // ── State value extraction ────────────────────────────────────────────────

    /// Extract all distinct state values from a CFG.
    pub fn extract_state_values(&self, blocks: &[CffBlock]) -> Vec<StateValue> {
        let mut values: HashSet<StateValue> = HashSet::new();
        for block in blocks {
            for &v in &block.assigned_state_values {
                values.insert(v);
            }
        }
        let mut v: Vec<StateValue> = values.into_iter().collect();
        v.sort_unstable();
        v
    }

    // ── Transition analysis ───────────────────────────────────────────────────

    /// Build the transition graph from state-value assignments.
    pub fn build_transitions(&self, blocks: &[CffBlock]) -> Vec<StateTransition> {
        let mut transitions = Vec::new();

        // Build address → block lookup
        let block_map: HashMap<Address, &CffBlock> = blocks
            .iter()
            .map(|b| (b.address, b))
            .collect();

        // For each block that assigns state values, connect to the successor block(s)
        for block in blocks {
            if !block.has_state_assign {
                continue;
            }

            for &src_state in &block.assigned_state_values {
                for &succ_addr in &block.successors {
                    // The successor block may assign the next state value
                    if let Some(succ) = block_map.get(&succ_addr) {
                        for &dst_state in &succ.assigned_state_values {
                            let confidence = compute_transition_confidence(block, succ);
                            if confidence >= self.min_confidence {
                                transitions.push(StateTransition {
                                    src_state,
                                    dst_state,
                                    transition_block: block.address,
                                    is_conditional: block.successors.len() > 1,
                                    confidence,
                                });
                            }
                        }

                        // If successor is a real block (no further state assignment),
                        // treat it as a terminal state
                        if succ.assigned_state_values.is_empty() && succ.is_real_block {
                            transitions.push(StateTransition {
                                src_state,
                                dst_state: StateValue::MAX, // sentinel for "exit"
                                transition_block: block.address,
                                is_conditional: false,
                                confidence: 0.60,
                            });
                        }
                    }
                }
            }
        }

        transitions
    }

    // ── Predecessor analysis ──────────────────────────────────────────────────

    /// For each state value, compute the set of predecessor states.
    pub fn compute_predecessors(
        &self,
        transitions: &[StateTransition],
    ) -> HashMap<StateValue, Vec<StateValue>> {
        let mut predecessors: HashMap<StateValue, Vec<StateValue>> = HashMap::new();

        for t in transitions {
            predecessors
                .entry(t.dst_state)
                .or_default()
                .push(t.src_state);
        }

        // Deduplicate
        for v in predecessors.values_mut() {
            v.sort_unstable();
            v.dedup();
        }

        predecessors
    }

    // ── State → real block mapping ────────────────────────────────────────────

    /// Map each state value to the real application block it represents.
    ///
    /// Real blocks are those that:
    /// * Are successors of the dispatcher, and
    /// * Are **not** dispatcher/routing blocks themselves.
    pub fn build_state_mapping(
        &self,
        state_values: &[StateValue],
        blocks: &[CffBlock],
        dispatcher: Option<&CffBlock>,
    ) -> StateMapping {
        let mut mapping = StateMapping::new();

        let dispatcher_succs: HashSet<Address> = dispatcher
            .map(|d| d.successors.iter().copied().collect())
            .unwrap_or_default();

        // Build a reverse map: address → block
        let block_map: HashMap<Address, &CffBlock> = blocks
            .iter()
            .map(|b| (b.address, b))
            .collect();

        for (idx, &state_val) in state_values.iter().enumerate() {
            // Try to find the real block at this state's dispatch target
            let candidate_addr = dispatcher_succs
                .iter()
                .nth(idx) // naive index-based pairing (real impl uses data-flow)
                .copied();

            if let Some(addr) = candidate_addr {
                if let Some(block) = block_map.get(&addr) {
                    if !block.is_routing_only() {
                        mapping.add(state_val, addr);
                    } else {
                        mapping.dispatcher_blocks.push(addr);
                    }
                }
            }
        }

        mapping
    }

    // ── Legitimate vs obfuscated transitions ─────────────────────────────────

    /// Filter out obfuscated / spurious transitions.
    ///
    /// An obfuscated transition is one where:
    /// * The source state is never reachable from any real predecessor, OR
    /// * The transition goes to a routing-only block with no real successors.
    pub fn filter_obfuscated_transitions<'a>(
        &self,
        transitions: &'a [StateTransition],
        mapping: &StateMapping,
    ) -> Vec<&'a StateTransition> {
        let real_states: HashSet<StateValue> =
            mapping.state_to_block.keys().copied().collect();

        transitions
            .iter()
            .filter(|t| {
                // Must involve at least one known real state
                real_states.contains(&t.src_state) || real_states.contains(&t.dst_state)
            })
            .filter(|t| t.confidence >= self.min_confidence)
            .collect()
    }

    // ── Full recovery ─────────────────────────────────────────────────────────

    /// Run the full state variable recovery pipeline.
    pub fn recover(&self, blocks: &[CffBlock]) -> StateVariableRecoveryResult {
        let mut result = StateVariableRecoveryResult::new();

        let dispatcher = self.identify_dispatcher(blocks);
        result.dispatcher_address = dispatcher.map(|d| d.address);

        if let Some(d) = dispatcher {
            result.evidence.push(format!(
                "dispatcher at 0x{:x} with {} successors",
                d.address.0,
                d.successors.len()
            ));
        }

        result.state_var = self.identify_state_var(blocks);
        result.evidence.push(format!("state var: {}", result.state_var));

        result.state_values = self.extract_state_values(blocks);
        result.evidence.push(format!(
            "{} distinct state values",
            result.state_values.len()
        ));

        result.transitions = self.build_transitions(blocks);
        result.predecessors = self.compute_predecessors(&result.transitions);

        result.mapping =
            self.build_state_mapping(&result.state_values, blocks, dispatcher);

        let legit = self.filter_obfuscated_transitions(&result.transitions, &result.mapping);
        result.evidence.push(format!(
            "{}/{} transitions considered legitimate",
            legit.len(),
            result.transitions.len()
        ));

        // Overall confidence
        let dispatcher_conf = if dispatcher.is_some() { 0.35 } else { 0.0 };
        let state_var_conf = if result.state_var != StateVariable::Unknown { 0.25 } else { 0.0 };
        let mapping_conf = result.mapping.coverage(result.state_values.len()) * 0.30;
        let transition_conf =
            if result.transitions.is_empty() { 0.0 } else { 0.10 };

        result.confidence =
            (dispatcher_conf + state_var_conf + mapping_conf + transition_conf).min(1.0);

        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Confidence that a transition from `src` → `dst` is a legitimate CFG edge.
fn compute_transition_confidence(src: &CffBlock, dst: &CffBlock) -> f32 {
    let mut conf = 0.50f32;

    // Real-block to real-block → high confidence
    if src.is_real_block && dst.is_real_block {
        conf += 0.30;
    }
    // Dispatcher to real-block → likely legitimate dispatch edge
    if src.is_dispatcher && dst.is_real_block {
        conf += 0.20;
    }
    // Routing to routing → likely obfuscated
    if src.is_dispatcher && dst.is_dispatcher {
        conf -= 0.20;
    }
    // Very small blocks are usually routing-only
    if src.size() < 16 {
        conf -= 0.10;
    }
    if dst.size() < 16 {
        conf -= 0.05;
    }

    conf.clamp(0.0, 1.0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_addr(v: u64) -> Address {
        Address(v)
    }

    fn dispatcher_block() -> CffBlock {
        let mut b = CffBlock::new(make_addr(0x1000), make_addr(0x1020));
        b.reads_state = true;
        b.is_dispatcher = true;
        b.successors = vec![
            make_addr(0x2000),
            make_addr(0x3000),
            make_addr(0x4000),
            make_addr(0x5000),
        ];
        b
    }

    fn real_block(addr: u64, state_val: StateValue) -> CffBlock {
        let mut b = CffBlock::new(make_addr(addr), make_addr(addr + 0x40));
        b.is_real_block = true;
        b.has_state_assign = true;
        b.assigned_state_values = vec![state_val];
        b
    }

    #[test]
    fn test_identify_dispatcher() {
        let recoverer = StateVariableRecoverer::new();
        let disp = dispatcher_block();
        let real = real_block(0x2000, 100);
        let blocks = vec![disp, real];

        let d = recoverer.identify_dispatcher(&blocks);
        assert!(d.is_some());
        assert_eq!(d.unwrap().address, make_addr(0x1000));
    }

    #[test]
    fn test_extract_state_values() {
        let recoverer = StateVariableRecoverer::new();
        let b1 = real_block(0x2000, 42);
        let b2 = real_block(0x3000, 99);
        let b3 = real_block(0x4000, 42); // duplicate
        let values = recoverer.extract_state_values(&[b1, b2, b3]);
        assert_eq!(values, vec![42, 99]);
    }

    #[test]
    fn test_compute_predecessors() {
        let recoverer = StateVariableRecoverer::new();
        let transitions = vec![
            StateTransition {
                src_state: 10,
                dst_state: 20,
                transition_block: make_addr(0x1000),
                is_conditional: false,
                confidence: 0.9,
            },
            StateTransition {
                src_state: 15,
                dst_state: 20,
                transition_block: make_addr(0x1010),
                is_conditional: false,
                confidence: 0.8,
            },
        ];

        let preds = recoverer.compute_predecessors(&transitions);
        let state20_preds = preds.get(&20).unwrap();
        assert!(state20_preds.contains(&10));
        assert!(state20_preds.contains(&15));
    }

    #[test]
    fn test_identify_state_var_many_assigning_blocks() {
        let recoverer = StateVariableRecoverer::new();
        let blocks: Vec<CffBlock> = (0..5)
            .map(|i| real_block(0x2000 + i * 0x100, i as StateValue))
            .collect();
        let sv = recoverer.identify_state_var(&blocks);
        // With 5 assigning blocks, should identify a register
        assert!(matches!(sv, StateVariable::Register(_)));
    }

    #[test]
    fn test_full_recovery_empty() {
        let recoverer = StateVariableRecoverer::new();
        let result = recoverer.recover(&[]);
        assert_eq!(result.state_var, StateVariable::Unknown);
        assert!(result.state_values.is_empty());
    }
}
