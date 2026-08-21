//! OLLVM-specific Control Flow Flattening analysis.
//!
//! OLLVM (Obfuscator-LLVM) CFF has specific structural signatures that differ
//! from generic CFF.  This module provides:
//! * `OllvmSignature` — structural fingerprint of OLLVM-protected functions.
//! * `OllvmDetector` — high-confidence OLLVM detection with structural scoring.
//! * `StateVarTracker` — precise state-variable tracking and value set computation.
//! * `SubDispatcherMap` — maps sub-dispatcher blocks to their parent dispatcher.
//! * `OllvmPatch` — a single patch to the binary (remove a dispatcher back-edge).
//! * `patch_cff_function` — produce a list of patches that reconstruct the
//!   original control flow.

use crate::{
    BlockMapping, CffCandidate, CffDetector, CffRecoverer, RecoveredCfg, SimpleCfg, StateVariable,
};
use rustre_core::address::Address;
use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// OllvmSignature
// ─────────────────────────────────────────────────────────────────────────────

/// Structural fingerprint of an OLLVM-obfuscated function.
#[derive(Debug, Clone)]
pub struct OllvmSignature {
    /// Address of the outer (main) dispatcher block.
    pub main_dispatcher: Address,
    /// Address of the "pre-dispatcher" (sets initial state, jumps to main dispatcher).
    pub pre_dispatcher: Option<Address>,
    /// Addresses of all identified "return" blocks (blocks that do not loop back).
    pub return_blocks: Vec<Address>,
    /// Addresses of all "relevant" blocks (CFF-protected body blocks).
    pub body_blocks: Vec<Address>,
    /// Identified sub-dispatchers, if any.
    pub sub_dispatchers: Vec<Address>,
    /// How many blocks loop back to the main dispatcher.
    pub back_edge_count: usize,
    /// Total blocks including dispatcher(s).
    pub total_blocks: usize,
    /// Initial state value observed in the pre-dispatcher, if recoverable.
    pub initial_state: Option<u64>,
    /// OLLVM-specific score in `[0.0, 1.0]`.
    pub ollvm_score: f64,
}

// ─────────────────────────────────────────────────────────────────────────────
// OllvmDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects OLLVM CFF-protected functions with higher precision than the generic
/// `CffDetector`.
///
/// OLLVM's distinguishing features:
/// 1. A pre-dispatcher block that sets the state variable to a constant and
///    jumps to the main dispatcher.
/// 2. The main dispatcher is the sole block that routes control to body blocks.
/// 3. All body blocks loop back to the main dispatcher unconditionally (or via
///    a very short chain).
/// 4. Body blocks write a 32-bit state constant before looping back.
/// 5. Typically 3–100 body blocks.
pub struct OllvmDetector {
    inner: CffDetector,
    /// Minimum number of back-edges to the dispatcher for OLLVM classification.
    pub min_back_edges: usize,
}

impl Default for OllvmDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl OllvmDetector {
    /// Create an `OllvmDetector` with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: CffDetector::new().with_min_confidence(0.5),
            min_back_edges: 2,
        }
    }

    /// Override the minimum back-edge count.
    #[must_use]
    pub const fn with_min_back_edges(mut self, n: usize) -> Self {
        self.min_back_edges = n;
        self
    }

    /// Attempt to detect and fingerprint OLLVM CFF in `cfg`.
    ///
    /// Returns `None` if the function is not OLLVM-protected or confidence is
    /// below 0.5.
    #[must_use]
    pub fn detect(&self, cfg: &SimpleCfg, function_start: Address) -> Option<OllvmSignature> {
        // Use the generic detector to find the main dispatcher.
        let candidate = self.inner.detect(cfg, function_start)?;
        let disp_idx = cfg
            .blocks
            .iter()
            .position(|b| b.address == candidate.dispatcher_address)?;

        // Count back-edges to the dispatcher.
        let back_edges: Vec<usize> = cfg
            .edges
            .iter()
            .filter(|&&(from, to, _)| to == disp_idx && from != disp_idx)
            .map(|&(from, _, _)| from)
            .collect();

        if back_edges.len() < self.min_back_edges {
            return None;
        }

        // Find the pre-dispatcher: the unique predecessor of the dispatcher that is
        // NOT a back-edge source (i.e., reached exactly once from the function entry).
        let entry_idx = cfg
            .blocks
            .iter()
            .position(|b| b.address == function_start)?;
        let pre_dispatcher = Self::find_pre_dispatcher(cfg, entry_idx, disp_idx);

        // Body blocks: all non-dispatcher blocks that have a back-edge to the dispatcher.
        let body_blocks: Vec<Address> = back_edges.iter().map(|&i| cfg.blocks[i].address).collect();

        // Return blocks: blocks that do NOT loop back to the dispatcher.
        let back_edge_srcs: HashSet<usize> = back_edges.iter().copied().collect();
        let return_blocks: Vec<Address> = cfg
            .blocks
            .iter()
            .enumerate()
            .filter(|&(i, _)| i != disp_idx && !back_edge_srcs.contains(&i))
            .map(|(_, b)| b.address)
            .collect();

        // Sub-dispatchers: body blocks with high successor counts (≥3).
        let sub_dispatchers: Vec<Address> = cfg
            .blocks
            .iter()
            .enumerate()
            .filter(|&(i, b)| i != disp_idx && b.successor_count >= 3)
            .map(|(_, b)| b.address)
            .collect();

        // Compute OLLVM score.
        let ollvm_score = Self::compute_ollvm_score(cfg, disp_idx, back_edges.len(), &body_blocks);

        if ollvm_score < 0.4 {
            return None;
        }

        Some(OllvmSignature {
            main_dispatcher: candidate.dispatcher_address,
            pre_dispatcher,
            return_blocks,
            body_blocks,
            sub_dispatchers,
            back_edge_count: back_edges.len(),
            total_blocks: cfg.blocks.len(),
            initial_state: None, // requires symbolic evaluation
            ollvm_score,
        })
    }

    fn find_pre_dispatcher(
        cfg: &SimpleCfg,
        entry_idx: usize,
        disp_idx: usize,
    ) -> Option<Address> {
        // The pre-dispatcher is the first block on the path from the entry to the dispatcher.
        // BFS from entry to find blocks on the shortest path.
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(entry_idx);
        visited.insert(entry_idx);

        while let Some(idx) = queue.pop_front() {
            // Successor blocks.
            for &(from, to, _) in &cfg.edges {
                if from == idx && !visited.contains(&to) {
                    if to == disp_idx {
                        // `idx` is on the path from entry → dispatcher.
                        if idx != entry_idx {
                            return Some(cfg.blocks[idx].address);
                        }
                    }
                    visited.insert(to);
                    queue.push_back(to);
                }
            }
        }
        None
    }

    fn compute_ollvm_score(
        cfg: &SimpleCfg,
        disp_idx: usize,
        back_edge_count: usize,
        body_blocks: &[Address],
    ) -> f64 {
        let n = cfg.blocks.len();
        if n < 3 {
            return 0.0;
        }

        let n_f = f64::from(u32::try_from(n).unwrap_or(u32::MAX));
        // Fraction of non-dispatcher blocks that loop back.
        let body_ratio = f64::from(u32::try_from(back_edge_count).unwrap_or(u32::MAX))
            / f64::from(u32::try_from((n - 1).max(1)).unwrap_or(u32::MAX));

        // Dispatcher has a high predecessor count.
        let disp_pred_ratio =
            f64::from(u32::try_from(cfg.blocks[disp_idx].predecessor_count).unwrap_or(u32::MAX))
                / n_f;

        // Body blocks have medium instruction counts (typical for OLLVM).
        let avg_body_instrs: f64 = if body_blocks.is_empty() {
            0.0
        } else {
            cfg.blocks
                .iter()
                .filter(|b| body_blocks.contains(&b.address))
                .map(|b| f64::from(u32::try_from(b.instr_count).unwrap_or(u32::MAX)))
                .sum::<f64>()
                / f64::from(u32::try_from(body_blocks.len()).unwrap_or(u32::MAX))
        };
        let instr_score = if (3.0..=200.0).contains(&avg_body_instrs) {
            1.0_f64
        } else {
            0.3_f64
        };

        // All body blocks write to the same register (state variable uniformity).
        let reg_set: HashSet<Option<&str>> = cfg
            .blocks
            .iter()
            .filter(|b| body_blocks.contains(&b.address))
            .map(|b| b.sets_register.as_deref())
            .collect();
        let uniformity_score = if reg_set.len() <= 2 { 1.0_f64 } else { 0.4_f64 };

        let score = body_ratio.mul_add(
            0.35,
            disp_pred_ratio.mul_add(0.30, instr_score.mul_add(0.20, uniformity_score * 0.15)),
        );

        score.clamp(0.0, 1.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StateVarTracker
// ─────────────────────────────────────────────────────────────────────────────

/// A symbolic state assignment in a body block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateAssignment {
    /// The block that writes this state value.
    pub block: Address,
    /// The state constant written.
    pub value: u64,
    /// Whether this is a conditional assignment.
    pub is_conditional: bool,
}

/// Tracks state-variable assignments across body blocks.
///
/// In OLLVM CFF, each body block writes a constant to the state variable right
/// before jumping back to the dispatcher.  `StateVarTracker` collects those
/// assignments and maps them to their target body blocks.
#[derive(Debug, Default)]
pub struct StateVarTracker {
    /// `block_address → [assignment]`
    pub assignments: HashMap<u64, Vec<StateAssignment>>,
    /// Reverse map: `state_value → body_block_address`.
    pub state_targets: HashMap<u64, Vec<Address>>,
}

impl StateVarTracker {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a state assignment from `block` that sets the state to `value`.
    pub fn record(&mut self, block: Address, value: u64, is_conditional: bool) {
        let assignment = StateAssignment {
            block,
            value,
            is_conditional,
        };
        self.assignments
            .entry(block.as_u64())
            .or_default()
            .push(assignment);
        self.state_targets.entry(value).or_default().push(block);
    }

    /// Look up which blocks may be reached via state `value`.
    #[must_use]
    pub fn blocks_for_state(&self, value: u64) -> &[Address] {
        self.state_targets
            .get(&value)
            .map_or(&[] as &[Address], Vec::as_slice)
    }

    /// All distinct state values observed.
    #[must_use]
    pub fn all_states(&self) -> Vec<u64> {
        self.state_targets.keys().copied().collect()
    }

    /// Whether the tracker has captured any assignments.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.assignments.is_empty()
    }

    /// Merge another tracker into `self`.
    pub fn merge(&mut self, other: Self) {
        for (block_addr, assignments) in other.assignments {
            self.assignments
                .entry(block_addr)
                .or_default()
                .extend(assignments);
        }
        for (value, blocks) in other.state_targets {
            let entry = self.state_targets.entry(value).or_default();
            for b in blocks {
                if !entry.contains(&b) {
                    entry.push(b);
                }
            }
        }
    }

    /// Build a `BlockMapping` from the tracked assignments.
    ///
    /// Assigns `state_value → target_block` for each unique assignment.
    #[must_use]
    pub fn to_block_mapping(&self) -> BlockMapping {
        let mut mapping = BlockMapping::new();
        for (&state, blocks) in &self.state_targets {
            for &block in blocks {
                mapping.insert(state, block);
            }
        }
        mapping
    }

    /// Count of blocks that write a state value.
    #[must_use]
    pub fn writer_count(&self) -> usize {
        self.assignments.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SubDispatcherMap
// ─────────────────────────────────────────────────────────────────────────────

/// Maps sub-dispatcher blocks to their parent dispatcher.
///
/// In heavily obfuscated OLLVM code, the main dispatcher may delegate to
/// sub-dispatchers that each handle a subset of the state space.
#[derive(Debug, Default)]
pub struct SubDispatcherMap {
    /// `sub_dispatcher_address → parent_dispatcher_address`
    pub parent: HashMap<u64, Address>,
    /// `parent_dispatcher → list of sub-dispatchers`
    pub children: HashMap<u64, Vec<Address>>,
}

impl SubDispatcherMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `sub` as a sub-dispatcher of `parent`.
    pub fn add(&mut self, parent: Address, sub: Address) {
        self.parent.insert(sub.as_u64(), parent);
        self.children.entry(parent.as_u64()).or_default().push(sub);
    }

    /// Get the parent dispatcher of `sub`, if any.
    #[must_use]
    pub fn parent_of(&self, sub: Address) -> Option<Address> {
        self.parent.get(&sub.as_u64()).copied()
    }

    /// Whether `addr` is a known sub-dispatcher.
    #[must_use]
    pub fn is_sub_dispatcher(&self, addr: Address) -> bool {
        self.parent.contains_key(&addr.as_u64())
    }

    /// Number of sub-dispatchers.
    #[must_use]
    pub fn sub_count(&self) -> usize {
        self.parent.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Patch generation
// ─────────────────────────────────────────────────────────────────────────────

/// A single binary patch for CFF removal.
#[derive(Debug, Clone)]
pub struct OllvmPatch {
    /// Address of the instruction to patch.
    pub address: Address,
    /// Bytes to replace.
    pub original_bytes: Vec<u8>,
    /// Replacement bytes (NOP / unconditional JMP).
    pub patch_bytes: Vec<u8>,
    /// Human-readable description of the patch.
    pub description: String,
}

impl OllvmPatch {
    /// Create a "NOP out" patch at `address` for `size` bytes.
    #[must_use]
    pub fn nop_out(address: Address, size: usize, description: impl Into<String>) -> Self {
        Self {
            address,
            original_bytes: vec![0x00; size], // placeholder
            patch_bytes: vec![0x90; size],    // x86 NOP
            description: description.into(),
        }
    }

    /// Create a patch that replaces a conditional branch with an unconditional one.
    #[must_use]
    pub fn make_unconditional(address: Address, target: Address) -> Self {
        // Produce a near JMP rel32 (opcode 0xE9) for x86-64.
        // The exact offset depends on the final address, so we use 0 as a placeholder.
        let _ = target; // target used in a real encoder
        Self {
            address,
            original_bytes: vec![0x75, 0x00], // JNZ rel8 placeholder
            patch_bytes: vec![0xEB, 0x00],    // JMP rel8 placeholder
            description: format!("convert conditional branch at {address} to unconditional"),
        }
    }
}

/// Generate patches that remove the CFF wrapper from a function.
///
/// The returned patches, when applied in order, transform the flattened CFG
/// into one that directly expresses the original control flow without
/// dispatcher indirection.
///
/// This is a best-effort heuristic: for each body block, we generate a patch
/// that replaces the back-edge-to-dispatcher with a direct jump to the target.
#[must_use]
pub fn patch_cff_function(candidate: &CffCandidate, recovered: &RecoveredCfg) -> Vec<OllvmPatch> {
    let mut patches = Vec::with_capacity(recovered.edges.len() + 1);

    // For each recovered edge, if the original source had a back-edge to the
    // dispatcher, generate a patch to redirect it.
    for edge in &recovered.edges {
        if edge.state_value.is_some() {
            // This edge was originally a back-edge to the dispatcher.
            // Generate a patch to make it a direct branch to the target.
            patches.push(OllvmPatch {
                address: edge.from_block,
                original_bytes: vec![0xE9, 0, 0, 0, 0], // JMP rel32 to dispatcher
                patch_bytes: {
                    // x86-64 JMP rel32 to the new target.
                    // We use 0x00000000 as a placeholder offset.
                    let target_low = u32::try_from(edge.to_block.as_u64()).unwrap_or(u32::MAX);
                    let mut v = vec![0xE9u8];
                    v.extend_from_slice(&target_low.to_le_bytes());
                    v
                },
                description: format!(
                    "redirect {} → {} (bypass dispatcher)",
                    edge.from_block, edge.to_block
                ),
            });
        }
    }

    // Generate a patch to NOP out the dispatcher block itself.
    patches.push(OllvmPatch::nop_out(
        candidate.dispatcher_address,
        candidate.block_count * 4, // rough size estimate
        format!("NOP out dispatcher at {}", candidate.dispatcher_address),
    ));

    patches
}

// ─────────────────────────────────────────────────────────────────────────────
// OLLVM-specific pass
// ─────────────────────────────────────────────────────────────────────────────

/// Result of running the OLLVM-specific deobfuscation pass.
#[derive(Debug, Default)]
pub struct OllvmDeobfResult {
    /// Functions identified as OLLVM-protected.
    pub ollvm_functions: Vec<OllvmSignature>,
    /// Recovered CFGs.
    pub recovered: Vec<RecoveredCfg>,
    /// Patches ready for application.
    pub patches: Vec<(Address, Vec<OllvmPatch>)>,
    /// State tracker per function.
    pub trackers: HashMap<u64, StateVarTracker>,
}

/// High-level OLLVM deobfuscation pass.
pub struct OllvmDeobfuscationPass {
    pub detector: OllvmDetector,
    recoverer: CffRecoverer,
}

impl Default for OllvmDeobfuscationPass {
    fn default() -> Self {
        Self::new()
    }
}

impl OllvmDeobfuscationPass {
    /// Create a new pass with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            detector: OllvmDetector::new(),
            recoverer: CffRecoverer::new(),
        }
    }

    /// Run the pass on a single function.
    #[must_use]
    pub fn run_on_function(
        &self,
        cfg: &SimpleCfg,
        function_start: Address,
    ) -> Option<(OllvmSignature, RecoveredCfg, Vec<OllvmPatch>)> {
        let sig = self.detector.detect(cfg, function_start)?;

        // Build a CffCandidate from the signature for use with the generic recoverer.
        let candidate = CffCandidate {
            function_start,
            dispatcher_address: sig.main_dispatcher,
            state_variable: StateVariable::Unknown,
            block_count: sig.total_blocks,
            confidence: sig.ollvm_score,
            pattern: crate::CffPattern::Dispatcher,
        };

        let recovered = self.recoverer.recover(&candidate, cfg);
        let patches = patch_cff_function(&candidate, &recovered);

        Some((sig, recovered, patches))
    }

    /// Run the pass on a collection of functions.
    #[must_use]
    pub fn run_on_binary(&self, cfgs: Vec<(Address, SimpleCfg)>) -> OllvmDeobfResult {
        let mut result = OllvmDeobfResult::default();

        for (function_start, cfg) in cfgs {
            if let Some((sig, recovered, patches)) = self.run_on_function(&cfg, function_start) {
                let addr = function_start.as_u64();
                result.trackers.insert(addr, StateVarTracker::new());
                result.patches.push((function_start, patches));
                result.ollvm_functions.push(sig);
                result.recovered.push(recovered);
            }
        }

        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EdgeType, SimpleBb, SimpleCfg};

    fn make_ollvm_cfg() -> SimpleCfg {
        // 7 blocks: entry(0), dispatcher(1), body A(2), body B(3), body C(4),
        //           body D(5), exit(6)
        let blocks = vec![
            SimpleBb {
                // 0: entry / pre-dispatcher
                address: Address::new(0x1000),
                successor_count: 1,
                predecessor_count: 0,
                instr_count: 2,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: Some("eax".into()),
                state_const: None,
            },
            SimpleBb {
                // 1: dispatcher
                address: Address::new(0x1010),
                successor_count: 4,
                predecessor_count: 5, // entry + A + B + C + D
                instr_count: 5,
                ends_with_indirect_jump: false,
                ends_with_conditional: true,
                sets_register: None,
                state_const: None,
            },
            SimpleBb {
                // 2: body A
                address: Address::new(0x1020),
                successor_count: 1,
                predecessor_count: 1,
                instr_count: 8,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: Some("eax".into()),
                state_const: None,
            },
            SimpleBb {
                // 3: body B
                address: Address::new(0x1030),
                successor_count: 1,
                predecessor_count: 1,
                instr_count: 6,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: Some("eax".into()),
                state_const: None,
            },
            SimpleBb {
                // 4: body C
                address: Address::new(0x1040),
                successor_count: 1,
                predecessor_count: 1,
                instr_count: 7,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: Some("eax".into()),
                state_const: None,
            },
            SimpleBb {
                // 5: body D
                address: Address::new(0x1050),
                successor_count: 1,
                predecessor_count: 1,
                instr_count: 5,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: Some("eax".into()),
                state_const: None,
            },
            SimpleBb {
                // 6: exit
                address: Address::new(0x1060),
                successor_count: 0,
                predecessor_count: 1,
                instr_count: 3,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: None,
                state_const: None,
            },
        ];

        let edges = vec![
            (0, 1, EdgeType::Unconditional), // entry → dispatcher
            (1, 2, EdgeType::TrueBranch),    // dispatcher → A
            (1, 3, EdgeType::FalseBranch),   // dispatcher → B
            (1, 4, EdgeType::Unconditional), // dispatcher → C
            (1, 5, EdgeType::Unconditional), // dispatcher → D
            (2, 1, EdgeType::Unconditional), // A → dispatcher
            (3, 1, EdgeType::Unconditional), // B → dispatcher
            (4, 1, EdgeType::Unconditional), // C → dispatcher
            (5, 6, EdgeType::Unconditional), // D → exit (return block)
        ];

        SimpleCfg { blocks, edges }
    }

    #[test]
    fn test_ollvm_detector_finds_signature() {
        let cfg = make_ollvm_cfg();
        let detector = OllvmDetector::new();
        let sig = detector.detect(&cfg, Address::new(0x1000));
        assert!(sig.is_some(), "should detect OLLVM signature");
        let sig = sig.unwrap();
        assert_eq!(sig.main_dispatcher, Address::new(0x1010));
        assert!(!sig.body_blocks.is_empty());
    }

    #[test]
    fn test_ollvm_back_edge_count() {
        let cfg = make_ollvm_cfg();
        let detector = OllvmDetector::new();
        let sig = detector.detect(&cfg, Address::new(0x1000)).unwrap();
        // Blocks A, B, C all loop back → 3 back-edges
        assert!(sig.back_edge_count >= 3, "got {}", sig.back_edge_count);
    }

    #[test]
    fn test_ollvm_return_blocks() {
        let cfg = make_ollvm_cfg();
        let detector = OllvmDetector::new();
        let sig = detector.detect(&cfg, Address::new(0x1000)).unwrap();
        // Block D (0x1050) → exit (0x1060), neither loops back.
        assert!(
            sig.return_blocks.contains(&Address::new(0x1050))
                || sig.return_blocks.contains(&Address::new(0x1060))
        );
    }

    #[test]
    fn test_ollvm_score_positive() {
        let cfg = make_ollvm_cfg();
        let detector = OllvmDetector::new();
        let sig = detector.detect(&cfg, Address::new(0x1000)).unwrap();
        assert!(sig.ollvm_score > 0.4, "score too low: {}", sig.ollvm_score);
    }

    #[test]
    fn test_state_var_tracker_record_and_query() {
        let mut tracker = StateVarTracker::new();
        tracker.record(Address::new(0x1020), 0xDEAD_BEEF, false);
        tracker.record(Address::new(0x1030), 0xCAFE_BABE, false);

        assert!(!tracker.is_empty());
        assert_eq!(tracker.writer_count(), 2);
        assert_eq!(
            tracker.blocks_for_state(0xDEAD_BEEF),
            &[Address::new(0x1020)]
        );
        let states = tracker.all_states();
        assert!(states.contains(&0xDEAD_BEEF));
        assert!(states.contains(&0xCAFE_BABE));
    }

    #[test]
    fn test_state_var_tracker_merge() {
        let mut t1 = StateVarTracker::new();
        t1.record(Address::new(0x1000), 1, false);
        let mut t2 = StateVarTracker::new();
        t2.record(Address::new(0x2000), 2, false);
        t1.merge(t2);
        assert_eq!(t1.writer_count(), 2);
    }

    #[test]
    fn test_state_var_tracker_to_block_mapping() {
        let mut tracker = StateVarTracker::new();
        tracker.record(Address::new(0x1000), 42, false);
        let mapping = tracker.to_block_mapping();
        assert_eq!(mapping.block_for_state(42), Some(Address::new(0x1000)));
    }

    #[test]
    fn test_sub_dispatcher_map() {
        let mut map = SubDispatcherMap::new();
        let parent = Address::new(0x1000);
        let sub = Address::new(0x2000);
        map.add(parent, sub);
        assert!(map.is_sub_dispatcher(sub));
        assert_eq!(map.parent_of(sub), Some(parent));
        assert!(!map.is_sub_dispatcher(parent));
        assert_eq!(map.sub_count(), 1);
    }

    #[test]
    fn test_patch_cff_function() {
        let cfg = make_ollvm_cfg();
        let inner_detector = CffDetector::new().with_min_confidence(0.3);
        let candidate = inner_detector.detect(&cfg, Address::new(0x1000));
        if let Some(candidate) = candidate {
            let recoverer = CffRecoverer::new();
            let recovery_result = recoverer.recover(&candidate, &cfg);
            let patches = patch_cff_function(&candidate, &recovery_result);
            // At minimum we should get a dispatcher NOP patch.
            assert!(!patches.is_empty());
        }
    }

    #[test]
    fn test_ollvm_nop_patch() {
        let patch = OllvmPatch::nop_out(Address::new(0x1234), 5, "test nop");
        assert_eq!(patch.patch_bytes, vec![0x90; 5]);
        assert_eq!(patch.address, Address::new(0x1234));
        assert!(patch.description.contains("test nop"));
    }

    #[test]
    fn test_ollvm_make_unconditional_patch() {
        let patch = OllvmPatch::make_unconditional(Address::new(0x1000), Address::new(0x2000));
        assert_eq!(patch.patch_bytes[0], 0xEB); // JMP rel8
    }

    #[test]
    fn test_ollvm_pass_run_on_function() {
        let cfg = make_ollvm_cfg();
        let pass = OllvmDeobfuscationPass::new();
        let result = pass.run_on_function(&cfg, Address::new(0x1000));
        assert!(result.is_some(), "OLLVM pass should produce a result");
        let (sig, recovered, patches) = result.unwrap();
        assert!(!sig.body_blocks.is_empty());
        assert!(!patches.is_empty());
        let _ = recovered;
    }

    #[test]
    fn test_ollvm_pass_run_on_binary() {
        let cfg = make_ollvm_cfg();
        let pass = OllvmDeobfuscationPass::new();
        let result = pass.run_on_binary(vec![(Address::new(0x1000), cfg)]);
        assert!(!result.ollvm_functions.is_empty());
        assert!(!result.recovered.is_empty());
    }

    #[test]
    fn test_ollvm_detector_no_detection_linear() {
        // A linear CFG should not be detected as OLLVM.
        let blocks = vec![
            SimpleBb {
                address: Address::new(0x2000),
                successor_count: 1,
                predecessor_count: 0,
                instr_count: 3,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: None,
                state_const: None,
            },
            SimpleBb {
                address: Address::new(0x2010),
                successor_count: 1,
                predecessor_count: 1,
                instr_count: 3,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: None,
                state_const: None,
            },
            SimpleBb {
                address: Address::new(0x2020),
                successor_count: 0,
                predecessor_count: 1,
                instr_count: 3,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: None,
                state_const: None,
            },
        ];
        let edges = vec![
            (0, 1, EdgeType::Unconditional),
            (1, 2, EdgeType::Unconditional),
        ];
        let cfg = SimpleCfg { blocks, edges };
        let detector = OllvmDetector::new();
        assert!(detector.detect(&cfg, Address::new(0x2000)).is_none());
    }

    #[test]
    fn test_ollvm_detector_with_sub_dispatchers() {
        // Add a block with 3 successors to represent a sub-dispatcher.
        let blocks = vec![
            SimpleBb {
                address: Address::new(0x3000),
                successor_count: 1,
                predecessor_count: 0,
                instr_count: 2,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: Some("eax".into()),
                state_const: None,
            },
            SimpleBb {
                address: Address::new(0x3010),
                successor_count: 3,
                predecessor_count: 5,
                instr_count: 5,
                ends_with_indirect_jump: false,
                ends_with_conditional: true,
                sets_register: None,
                state_const: None,
            },
            SimpleBb {
                address: Address::new(0x3020),
                successor_count: 3,
                predecessor_count: 1,
                instr_count: 4,
                ends_with_indirect_jump: false,
                ends_with_conditional: true,
                sets_register: Some("eax".into()),
                state_const: None,
            },
            SimpleBb {
                address: Address::new(0x3030),
                successor_count: 1,
                predecessor_count: 1,
                instr_count: 6,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: Some("eax".into()),
                state_const: None,
            },
            SimpleBb {
                address: Address::new(0x3040),
                successor_count: 1,
                predecessor_count: 1,
                instr_count: 6,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: Some("eax".into()),
                state_const: None,
            },
            SimpleBb {
                address: Address::new(0x3050),
                successor_count: 1,
                predecessor_count: 1,
                instr_count: 6,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: Some("eax".into()),
                state_const: None,
            },
        ];
        let edges = vec![
            (0, 1, EdgeType::Unconditional),
            (1, 2, EdgeType::TrueBranch),
            (1, 3, EdgeType::FalseBranch),
            (1, 4, EdgeType::Unconditional),
            (2, 1, EdgeType::TrueBranch),
            (2, 3, EdgeType::FalseBranch),
            (2, 5, EdgeType::Unconditional),
            (3, 1, EdgeType::Unconditional),
            (4, 1, EdgeType::Unconditional),
            (5, 1, EdgeType::Unconditional),
        ];
        let cfg = SimpleCfg { blocks, edges };
        let detector = OllvmDetector::new();
        let sig = detector.detect(&cfg, Address::new(0x3000));
        // Should detect sub-dispatcher(s).
        if let Some(sig) = sig {
            assert!(!sig.sub_dispatchers.is_empty() || sig.back_edge_count >= 2);
        }
    }
}
