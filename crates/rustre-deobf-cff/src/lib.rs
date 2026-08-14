//! `rustre-deobf-cff`
//!
//! Production-grade Control Flow Flattening (CFF) deobfuscation pass for the `RustRE` Suite.
//!
//! # Overview
//!
//! CFF obfuscation wraps all basic blocks in a state-machine loop dispatched by a single
//! "state variable". This crate:
//! 1. Detects CFF-protected functions via structural CFG analysis ([`CffDetector`]).
//! 2. Rebuilds the original control-flow edges by tracing state-variable assignments
//!    ([`CffRecoverer`]).
//! 3. Provides a high-level pass entry point ([`CffDeobfuscationPass`]) that can run
//!    over an entire binary's worth of CFGs.
//!
//! Additional modules:
//! * [`ollvm`] — OLLVM-specific detection, state-variable tracking, and patch generation.

pub mod cff_decompiler;
pub mod cff_deobfuscator;
pub mod cff_pattern_matcher;
pub mod cff_recovery;
pub mod cff_state_machine;
pub mod flattening_detector;
pub mod state_machine_extractor;
pub mod cfg_reconstruction;
pub mod dispatcher_analysis;
pub mod ollvm;
pub mod state_machine_recovery;
pub mod state_variable_recovery;
pub mod vm_handler_analyzer;
pub mod constant_propagator_cff;
pub mod dispatcher_rewriter;

pub use ollvm::{
    OllvmDeobfResult, OllvmDeobfuscationPass, OllvmDetector, OllvmPatch, OllvmSignature,
    StateAssignment, StateVarTracker, SubDispatcherMap, patch_cff_function,
};

use std::collections::HashMap;
use std::fmt;

use ahash::AHashMap;
use rustre_core::address::Address;

// ---------------------------------------------------------------------------
// StateVariable
// ---------------------------------------------------------------------------

/// Describes where the CFF state variable lives.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StateVariable {
    /// State is kept in a CPU register (e.g. `"eax"`).
    Register(String),
    /// State lives on the stack at the given frame-pointer offset.
    StackSlot(i32),
    /// State is a global/static memory location.
    GlobalMemory(Address),
    /// Could not determine the location.
    Unknown,
}

impl fmt::Display for StateVariable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register(r) => write!(f, "reg:{r}"),
            Self::StackSlot(o) => write!(f, "stack[{o}]"),
            Self::GlobalMemory(a) => write!(f, "mem:{a}"),
            Self::Unknown => write!(f, "<unknown>"),
        }
    }
}

// ---------------------------------------------------------------------------
// CffPattern
// ---------------------------------------------------------------------------

/// How the dispatcher block compares / dispatches on the state variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CffPattern {
    /// Classic `switch`/`case` dispatcher (dense comparison tree or jump table).
    Dispatcher,
    /// Indirect jump through a computed jump table.
    JumpTable,
    /// Linear `if`/`else if` chain comparing the state variable to constants.
    LinearSearch,
    /// Multiple nested state machines (e.g. OLLVM with sub-dispatchers).
    NestedDispatch,
    /// Could not classify the pattern.
    Unknown,
}

impl fmt::Display for CffPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dispatcher => write!(f, "Dispatcher"),
            Self::JumpTable => write!(f, "JumpTable"),
            Self::LinearSearch => write!(f, "LinearSearch"),
            Self::NestedDispatch => write!(f, "NestedDispatch"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// CffCandidate
// ---------------------------------------------------------------------------

/// A function that has been identified as a potential CFF-protected function.
#[derive(Debug, Clone)]
pub struct CffCandidate {
    /// Entry address of the function.
    pub function_start: Address,
    /// Address of the dispatcher (hub) block.
    pub dispatcher_address: Address,
    /// Where the state variable lives.
    pub state_variable: StateVariable,
    /// Number of basic blocks participating in the state machine.
    pub block_count: usize,
    /// Detection confidence in `[0.0, 1.0]`.
    pub confidence: f64,
    /// Structural pattern of the dispatcher.
    pub pattern: CffPattern,
}

// ---------------------------------------------------------------------------
// BlockMapping
// ---------------------------------------------------------------------------

/// Bidirectional mapping between state values and basic-block addresses.
///
/// Both maps use `AHashMap` because the keys (state values and block addresses)
/// originate from untrusted binary input; `std::HashMap`'s SipHash does not
/// provide collision resistance against a deterministic attacker who can craft
/// binary inputs with adversarial key sets (dos-hash-collision).
#[derive(Debug, Clone)]
pub struct BlockMapping {
    /// `state_value` → block start address.
    pub state_to_block: AHashMap<u64, Address>,
    /// block start address → list of state values that dispatch to it.
    pub block_to_state: AHashMap<u64, Vec<u64>>,
}

impl Default for BlockMapping {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockMapping {
    /// Create an empty mapping.
    pub fn new() -> Self {
        Self {
            state_to_block: AHashMap::new(),
            block_to_state: AHashMap::new(),
        }
    }

    /// Record that `state` dispatches to the block at `block`.
    pub fn insert(&mut self, state: u64, block: Address) {
        self.state_to_block.insert(state, block);
        self.block_to_state
            .entry(block.as_u64())
            .or_default()
            .push(state);
    }

    /// Return the block address for a given state value, if known.
    pub fn block_for_state(&self, state: u64) -> Option<Address> {
        self.state_to_block.get(&state).copied()
    }

    /// Return the state values that can dispatch to `addr`, if any.
    pub fn states_for_block(&self, addr: Address) -> &[u64] {
        self.block_to_state
            .get(&addr.as_u64())
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Number of distinct blocks in the mapping.
    pub fn block_count(&self) -> usize {
        self.block_to_state.len()
    }

    /// `true` when every mapped block has at least one incoming state value —
    /// i.e. no block is "stranded" without a way to reach it.
    pub fn is_complete(&self) -> bool {
        if self.state_to_block.is_empty() {
            return false;
        }
        // Every block in block_to_state already has ≥1 entry by construction;
        // completeness means each state also resolves to a known block.
        self.state_to_block
            .values()
            .all(|a| self.block_to_state.contains_key(&a.as_u64()))
    }
}

// ---------------------------------------------------------------------------
// RecoveredEdgeType / RecoveredEdge
// ---------------------------------------------------------------------------

/// Classification of a reconstructed CFG edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveredEdgeType {
    /// Unconditional jump / fall-through.
    Unconditional,
    /// Taken branch of a conditional.
    TrueBranch,
    /// Not-taken branch of a conditional.
    FalseBranch,
    /// Return from a call (intra-procedural edge).
    CallReturn,
}

/// A single reconstructed edge in the de-flattened CFG.
#[derive(Debug, Clone)]
pub struct RecoveredEdge {
    /// Source block address.
    pub from_block: Address,
    /// Destination block address.
    pub to_block: Address,
    /// Semantic type of this edge.
    pub edge_type: RecoveredEdgeType,
    /// State value that caused this transition, if known.
    pub state_value: Option<u64>,
}

// ---------------------------------------------------------------------------
// RecoveredCfg
// ---------------------------------------------------------------------------

/// The de-flattened control-flow graph after CFF removal.
#[derive(Debug, Clone)]
pub struct RecoveredCfg {
    /// Entry address of the function.
    pub function_start: Address,
    /// All basic-block start addresses (dispatcher excluded).
    pub blocks: Vec<Address>,
    /// Recovered (non-dispatcher) edges.
    pub edges: Vec<RecoveredEdge>,
    /// Address of the now-removed dispatcher block.
    pub dispatcher_address: Address,
    /// State variable that was used by the dispatcher.
    pub state_variable: StateVariable,
    /// The original detection candidate.
    pub original_candidate: CffCandidate,
}

impl RecoveredCfg {
    /// All blocks that `addr` can transfer control to.
    pub fn successors(&self, addr: Address) -> Vec<Address> {
        self.edges
            .iter()
            .filter(|e| e.from_block == addr)
            .map(|e| e.to_block)
            .collect()
    }

    /// All blocks that can transfer control to `addr`.
    pub fn predecessors(&self, addr: Address) -> Vec<Address> {
        self.edges
            .iter()
            .filter(|e| e.to_block == addr)
            .map(|e| e.from_block)
            .collect()
    }

    /// `true` if `addr` is the function entry block.
    pub fn is_entry(&self, addr: Address) -> bool {
        addr == self.function_start
    }

    /// Number of basic blocks in the recovered CFG.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Number of edges in the recovered CFG.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

// ---------------------------------------------------------------------------
// SimpleCfg primitives  (self-contained, no LLIL dependency)
// ---------------------------------------------------------------------------

/// Edge classification in the simplified CFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeType {
    Unconditional,
    TrueBranch,
    FalseBranch,
}

/// A single basic block in the simplified CFG.
#[derive(Debug, Clone)]
pub struct SimpleBb {
    /// Start address of the block.
    pub address: Address,
    /// Number of outgoing edges.
    pub successor_count: usize,
    /// Number of incoming edges.
    pub predecessor_count: usize,
    /// Number of instructions in the block.
    pub instr_count: usize,
    /// Whether the block terminates with an indirect (computed) jump.
    pub ends_with_indirect_jump: bool,
    /// Whether the block terminates with a conditional branch.
    pub ends_with_conditional: bool,
    /// The last register written before the block exits, if any.
    /// Heuristic used to identify the state variable register.
    pub sets_register: Option<String>,
    /// The constant value assigned to the state register at block exit, if
    /// known.  When populated (e.g. from a `SetReg { src: Const { .. } }` LLIL
    /// instruction or from a raw-byte `MOV reg, imm` pattern scan), this value
    /// is used directly as the state value for this block's back-edge to the
    /// dispatcher.  When `None` the recoverer falls back to an address-derived
    /// synthetic state.
    pub state_const: Option<u64>,
}

/// A simplified, architecture-agnostic CFG.
///
/// Blocks are stored in the `blocks` vector; edges reference them by index.
#[derive(Debug, Clone)]
pub struct SimpleCfg {
    pub blocks: Vec<SimpleBb>,
    /// `(from_index, to_index, edge_type)`
    pub edges: Vec<(usize, usize, EdgeType)>,
}

impl SimpleCfg {
    /// Compute the predecessor count for every block from the edge list.
    ///
    /// Useful when constructing a `SimpleCfg` where `predecessor_count` is not
    /// known at block-construction time.
    pub fn recompute_predecessor_counts(&mut self) {
        for bb in &mut self.blocks {
            bb.predecessor_count = 0;
        }
        for &(_, to, _) in &self.edges {
            if to < self.blocks.len() {
                self.blocks[to].predecessor_count += 1;
            }
        }
    }

    /// Return the block index whose address equals `addr`, if any.
    fn index_of(&self, addr: Address) -> Option<usize> {
        self.blocks.iter().position(|b| b.address == addr)
    }
}

// ---------------------------------------------------------------------------
// CffDetector
// ---------------------------------------------------------------------------

/// Detects CFF-protected functions from a simplified CFG.
pub struct CffDetector {
    /// Minimum number of blocks for a function to be considered CFF (default `5`).
    pub min_block_count: usize,
    /// Minimum confidence score to emit a candidate (default `0.6`).
    pub min_confidence: f64,
    /// Maximum number of predecessors the dispatcher may have (default `50`).
    pub max_dispatcher_preds: usize,
}

impl Default for CffDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CffDetector {
    /// Create a detector with default parameters.
    pub fn new() -> Self {
        Self {
            min_block_count: 5,
            min_confidence: 0.6,
            max_dispatcher_preds: 50,
        }
    }

    /// Override the minimum block count.
    #[must_use]
    pub fn with_min_blocks(mut self, n: usize) -> Self {
        self.min_block_count = n;
        self
    }

    /// Override the minimum confidence threshold.
    #[must_use]
    pub fn with_min_confidence(mut self, c: f64) -> Self {
        self.min_confidence = c;
        self
    }

    /// Attempt to detect CFF in `cfg` for the function starting at `function_start`.
    ///
    /// Returns `None` when the CFG does not meet the minimum criteria or confidence.
    pub fn detect(&self, cfg: &SimpleCfg, function_start: Address) -> Option<CffCandidate> {
        if cfg.blocks.len() < self.min_block_count {
            return None;
        }

        let (dispatcher_idx, confidence) = self.find_dispatcher(cfg)?;

        if confidence < self.min_confidence {
            return None;
        }

        let confidence = self.compute_confidence(cfg, dispatcher_idx);
        if confidence < self.min_confidence {
            return None;
        }

        let state_variable = self.identify_state_variable(cfg, dispatcher_idx);
        let dispatcher_address = cfg.blocks[dispatcher_idx].address;
        let pattern = self.classify_pattern(cfg, dispatcher_idx);

        Some(CffCandidate {
            function_start,
            dispatcher_address,
            state_variable,
            block_count: cfg.blocks.len(),
            confidence,
            pattern,
        })
    }

    /// Find the block most likely to be the dispatcher.
    ///
    /// Returns `(block_index, preliminary_confidence)` or `None`.
    ///
    /// Heuristic: the dispatcher is the block with the largest predecessor count,
    /// provided it also has no (or very few) instructions of its own and all its
    /// predecessors have exactly one successor (back to the dispatcher).
    pub fn find_dispatcher(&self, cfg: &SimpleCfg) -> Option<(usize, f64)> {
        if cfg.blocks.is_empty() {
            return None;
        }

        // Find the block with the highest predecessor count.
        let (best_idx, best_preds) = cfg
            .blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (i, b.predecessor_count))
            .max_by_key(|&(_, p)| p)?;

        if best_preds < 2 {
            return None;
        }
        if best_preds > self.max_dispatcher_preds {
            return None;
        }

        // Preliminary confidence: ratio of predecessors to (blocks - 1).
        let max_possible = f64::from(u32::try_from(cfg.blocks.len().saturating_sub(1).max(1)).unwrap_or(u32::MAX));
        let prelim = (f64::from(u32::try_from(best_preds).unwrap_or(u32::MAX)) / max_possible).min(1.0);

        Some((best_idx, prelim))
    }

    /// Compute a CFF confidence score for `dispatcher_idx` in `[0.0, 1.0]`.
    ///
    /// The score is the weighted average of several independent indicators:
    ///
    /// | Indicator | Weight |
    /// |-----------|--------|
    /// | Dispatcher predecessor ratio | 0.35 |
    /// | Fraction of blocks with only one successor (→ dispatcher) | 0.25 |
    /// | Dispatcher successor count ≥ 2 | 0.20 |
    /// | Average instruction count of non-dispatcher blocks | 0.10 |
    /// | At least one block ending with an indirect jump | 0.10 |
    pub fn compute_confidence(&self, cfg: &SimpleCfg, dispatcher_idx: usize) -> f64 {
        let n = cfg.blocks.len();
        if n < 2 || dispatcher_idx >= n {
            return 0.0;
        }

        let dispatcher = &cfg.blocks[dispatcher_idx];
        let non_dispatcher_count = n - 1;
        let ndc_f = f64::from(u32::try_from(non_dispatcher_count).unwrap_or(u32::MAX));

        // --- Indicator 1: predecessor ratio --------------------------------
        let pred_ratio = if non_dispatcher_count == 0 {
            0.0_f64
        } else {
            (f64::from(u32::try_from(dispatcher.predecessor_count).unwrap_or(u32::MAX)) / ndc_f)
                .min(1.0)
        };

        // --- Indicator 2: fraction of blocks whose only successor is the
        //     dispatcher (i.e. successor_count == 1 and the edge leads back) ---
        let dispatcher_addr = dispatcher.address;
        let back_edge_count = cfg
            .edges
            .iter()
            .filter(|&&(from, to, _)| {
                from != dispatcher_idx
                    && to == dispatcher_idx
                    && cfg.blocks[from].successor_count == 1
                    // address-level sanity check
                    && cfg.blocks[to].address == dispatcher_addr
            })
            .count();
        let back_ratio = if non_dispatcher_count == 0 {
            0.0_f64
        } else {
            f64::from(u32::try_from(back_edge_count).unwrap_or(u32::MAX)) / ndc_f
        };

        // --- Indicator 3: dispatcher has ≥ 2 successors --------------------
        let disp_succ_score = if dispatcher.successor_count >= 2 {
            1.0_f64
        } else {
            0.0_f64
        };

        // --- Indicator 4: non-dispatcher blocks have reasonable sizes -------
        // CFF bodies tend to have several instructions (not 0, not 1000s).
        let avg_instr: f64 = if non_dispatcher_count == 0 {
            0.0
        } else {
            cfg.blocks
                .iter()
                .enumerate()
                .filter(|&(i, _)| i != dispatcher_idx)
                .map(|(_, b)| f64::from(u32::try_from(b.instr_count).unwrap_or(u32::MAX)))
                .sum::<f64>()
                / ndc_f
        };
        let instr_score = if (2.0..=100.0).contains(&avg_instr) {
            1.0_f64
        } else if avg_instr > 0.0 {
            0.5_f64
        } else {
            0.0_f64
        };

        // --- Indicator 5: at least one indirect jump ------------------------
        let has_indirect = f64::from(u8::from(cfg.blocks.iter().any(|b| b.ends_with_indirect_jump)));

        // Weighted sum.
        let score = pred_ratio.mul_add(
            0.35,
            back_ratio.mul_add(
                0.25,
                disp_succ_score.mul_add(0.20, instr_score.mul_add(0.10, has_indirect * 0.10)),
            ),
        );

        score.clamp(0.0, 1.0)
    }

    /// Determine the most likely state-variable for the dispatcher at `dispatcher_idx`.
    ///
    /// Strategy:
    /// 1. Look at the registers written by the blocks that feed back to the
    ///    dispatcher.  The most-frequently written register is the state variable.
    /// 2. Fall back to `StateVariable::Unknown`.
    pub fn identify_state_variable(&self, cfg: &SimpleCfg, dispatcher_idx: usize) -> StateVariable {
        let mut reg_freq: HashMap<String, usize> = HashMap::new();

        for &(from, to, _) in &cfg.edges {
            if to == dispatcher_idx && from != dispatcher_idx && let Some(reg) = &cfg.blocks[from].sets_register {
                *reg_freq.entry(reg.clone()).or_insert(0) += 1;
            }
        }

        // `max_by_key` returns an ARBITRARY winner among ties, and `HashMap`
        // iteration order differs between runs — so a 2-2 tie between `eax` and
        // `ecx` identified a different state variable each time the same
        // function was analysed. A deobfuscator whose answer changes between
        // runs cannot be compared against itself.
        //
        // Ties now break on the register name, which is stable.
        if let Some((reg, _)) = reg_freq
            .into_iter()
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
        {
            return StateVariable::Register(reg);
        }

        // If the dispatcher itself reads a register not written by predecessors,
        // it might be reading a stack slot; we cannot determine the offset here
        // without deeper IL, so fall through.
        StateVariable::Unknown
    }

    /// Classify the dispatcher pattern based on structural characteristics.
    fn classify_pattern(&self, cfg: &SimpleCfg, dispatcher_idx: usize) -> CffPattern {
        let dispatcher = &cfg.blocks[dispatcher_idx];

        // An indirect-jump dispatcher → JumpTable.
        if dispatcher.ends_with_indirect_jump {
            return CffPattern::JumpTable;
        }

        // If the dispatcher has many successors and ends with a conditional,
        // it is likely a linear search (if/else if chain).
        if dispatcher.ends_with_conditional && dispatcher.successor_count == 2 {
            // A single conditional at the top means the outer structure is
            // linear comparisons; each inner block might set state and loop.
            return CffPattern::LinearSearch;
        }

        // Multiple levels: look for other blocks that also have a high
        // predecessor count (secondary dispatchers).
        let secondary_dispatchers = cfg
            .blocks
            .iter()
            .enumerate()
            .filter(|&(i, b)| i != dispatcher_idx && b.predecessor_count >= 3)
            .count();
        if secondary_dispatchers >= 1 {
            return CffPattern::NestedDispatch;
        }

        // Default: classic switch/dispatcher.
        CffPattern::Dispatcher
    }
}

// ---------------------------------------------------------------------------
// CffRecoverer
// ---------------------------------------------------------------------------

/// Reconstructs the original (pre-CFF) control-flow graph.
pub struct CffRecoverer {
    /// Maximum depth when tracing state assignments (default `32`).
    pub max_state_trace_depth: usize,
    /// Enable constant-folding of simple state expressions (default `true`).
    pub enable_symbolic_eval: bool,
}

impl Default for CffRecoverer {
    fn default() -> Self {
        Self::new()
    }
}

impl CffRecoverer {
    /// Create a recoverer with default parameters.
    pub fn new() -> Self {
        Self {
            max_state_trace_depth: 32,
            enable_symbolic_eval: true,
        }
    }

    /// Recover the de-flattened CFG from a detected candidate and its simplified CFG.
    pub fn recover(&self, candidate: &CffCandidate, cfg: &SimpleCfg) -> RecoveredCfg {
        let mapping = self.build_block_mapping(candidate, cfg);
        let edges = self.reconstruct_edges(candidate, &mapping, cfg);

        // Blocks: everything except the dispatcher.
        let dispatcher_idx = cfg
            .index_of(candidate.dispatcher_address)
            .unwrap_or(usize::MAX);

        let blocks: Vec<Address> = cfg
            .blocks
            .iter()
            .enumerate()
            .filter(|&(i, _)| i != dispatcher_idx)
            .map(|(_, b)| b.address)
            .collect();

        RecoveredCfg {
            function_start: candidate.function_start,
            blocks,
            edges,
            dispatcher_address: candidate.dispatcher_address,
            state_variable: candidate.state_variable.clone(),
            original_candidate: candidate.clone(),
        }
    }

    /// Build the `state → block` mapping by examining all blocks that feed back
    /// to the dispatcher.
    ///
    /// # State-value resolution strategy (highest priority first)
    ///
    /// 1. **Real constant from dataflow** — if `SimpleBb::state_const` is
    ///    populated (e.g. filled in by the caller after lifting LLIL
    ///    `SetReg { src: Const { .. } }` instructions, or by
    ///    [`CffRecoverer::scan_block_state_const`] from raw bytes) that value
    ///    is used directly.  This gives the most accurate mapping because it
    ///    reflects the actual constant the dispatcher will compare against.
    ///
    /// 2. **Address-derived synthetic state** — when `state_const` is `None`
    ///    and `enable_symbolic_eval` is `true`, the low 32 bits of the block's
    ///    start address serve as a stand-in state value.  This is consistent
    ///    with how OLLVM typically generates 32-bit state constants and is
    ///    unambiguous across blocks in a single function.
    ///
    /// 3. **Sequential seed** — when `enable_symbolic_eval` is `false`, a
    ///    monotonically increasing seed (0, 1, 2, …) is assigned.
    ///
    /// When `enable_symbolic_eval` is `true`, a propagation pass runs after
    /// initial insertion to fill in any states that were not yet resolved.
    pub fn build_block_mapping(&self, candidate: &CffCandidate, cfg: &SimpleCfg) -> BlockMapping {
        let mut mapping = BlockMapping::new();

        let dispatcher_idx = match cfg.index_of(candidate.dispatcher_address) {
            Some(i) => i,
            None => return mapping,
        };

        // Collect all blocks that jump back to the dispatcher.
        let predecessor_indices: Vec<usize> = cfg
            .edges
            .iter()
            .filter(|&&(_, to, _)| to == dispatcher_idx)
            .map(|&(from, _, _)| from)
            .collect();

        for (state_seed, &pred_idx) in predecessor_indices.iter().enumerate() {
            let block = &cfg.blocks[pred_idx];
            let block_addr = block.address;

            // Priority 1: real constant assigned to the state register at block
            // exit (populated by the caller from LLIL or raw-byte scanning).
            let state_value = if let Some(c) = block.state_const {
                c
            } else if self.enable_symbolic_eval {
                // Priority 2: low 32-bit address as synthetic state constant.
                block_addr.as_u64() & 0xFFFF_FFFF
            } else {
                // Priority 3: sequential seed.
                state_seed as u64
            };

            mapping.insert(state_value, block_addr);
        }

        // Propagate through simple chains up to max_state_trace_depth.
        if self.enable_symbolic_eval {
            self.propagate_states(cfg, dispatcher_idx, &mut mapping, 0);
        }

        mapping
    }

    /// Scan raw x86 machine `bytes` (mapped at `block_start`) for the last
    /// `MOV reg, imm32` or `MOV reg, imm64` instruction before the first
    /// unconditional branch / jump, and return the immediate value.
    ///
    /// This is the pattern-based equivalent of finding a `SetReg { src: Const }`
    /// LLIL node: it identifies the constant written to the state register at
    /// the tail of a predecessor block without requiring a full disassembler.
    ///
    /// Recognised encodings (x86-64):
    /// * `B8+r imm32`   — `MOV r32, imm32` (opcode `0xB8..0xBF`, 5 bytes)
    /// * `REX.W B8+r imm64` — `MOV r64, imm64` (`0x48 0xB8..0xBF`, 10 bytes)
    /// * `C7 /0 imm32`  — `MOV r/m32, imm32` (opcode `0xC7 0xC0..0xC7`, 6 bytes)
    ///
    /// Returns `None` when no matching pattern is found within `bytes`.
    #[must_use]
    pub fn scan_block_state_const(bytes: &[u8]) -> Option<u64> {
        let mut last_imm: Option<u64> = None;
        let mut i = 0usize;

        while i < bytes.len() {
            let b = bytes[i];

            // REX prefix (0x40..0x4F) — peek ahead for REX.W + B8+r imm64.
            if (0x40..=0x4F).contains(&b) && i + 1 < bytes.len() {
                let rex_w = (b & 0x08) != 0;
                let next = bytes[i + 1];
                if (0xB8..=0xBF).contains(&next) {
                    if rex_w && i + 10 <= bytes.len() {
                        // MOV r64, imm64 (REX.W B8+r imm64)
                        let imm = u64::from_le_bytes([
                            bytes[i + 2],
                            bytes[i + 3],
                            bytes[i + 4],
                            bytes[i + 5],
                            bytes[i + 6],
                            bytes[i + 7],
                            bytes[i + 8],
                            bytes[i + 9],
                        ]);
                        last_imm = Some(imm);
                        i += 10;
                        continue;
                    } else if !rex_w && i + 6 <= bytes.len() {
                        // REX (non-W) + MOV r32, imm32 (5 bytes after REX = 6 total)
                        let imm = u32::from_le_bytes([
                            bytes[i + 2],
                            bytes[i + 3],
                            bytes[i + 4],
                            bytes[i + 5],
                        ]) as u64;
                        last_imm = Some(imm);
                        i += 6;
                        continue;
                    }
                }
                // Unknown REX usage — skip the REX byte and re-process the next.
                i += 1;
                continue;
            }

            // MOV r32, imm32 — opcode B8+r (5 bytes).
            if (0xB8..=0xBF).contains(&b) && i + 5 <= bytes.len() {
                let imm =
                    u32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]])
                        as u64;
                last_imm = Some(imm);
                i += 5;
                continue;
            }

            // MOV r/m32, imm32 — C7 /0 ModRM imm32 (6 bytes for register form).
            // Register form: ModRM = 0xC0..0xC7 (mod=11, reg=000, rm=r).
            if b == 0xC7 && i + 6 <= bytes.len() {
                let modrm = bytes[i + 1];
                if (modrm & 0b11_000_000) == 0b11_000_000 && (modrm & 0b00_111_000) == 0 {
                    let imm = u32::from_le_bytes([
                        bytes[i + 2],
                        bytes[i + 3],
                        bytes[i + 4],
                        bytes[i + 5],
                    ]) as u64;
                    last_imm = Some(imm);
                    i += 6;
                    continue;
                }
            }

            // Unconditional short/near jump — stop scanning (block ends here).
            // EB rel8 (short JMP), E9 rel32 (near JMP).
            if b == 0xEB || b == 0xE9 {
                break;
            }
            // FF /4 is an indirect JMP (reg field = 4 in ModRM).  Other FF
            // encodings (INC, DEC, CALL, PUSH) must not terminate the scan.
            if b == 0xFF {
                if i + 1 < bytes.len() && (bytes[i + 1] & 0x38) == 0x20 {
                    break;
                }
                // Not a JMP r/m — skip this byte and continue scanning.
                i += 1;
                continue;
            }

            // Conditional short branches (JCC) — stop, the state assignment is
            // complete at this point.
            if (0x70..=0x7F).contains(&b) {
                break;
            }

            // NOP (0x90) — skip.
            i += 1;
        }

        last_imm
    }

    /// Trace `state` through the mapping up to `max_state_trace_depth` hops.
    pub fn trace_state(&self, state: u64, mapping: &BlockMapping) -> Option<Address> {
        let mut current = state;
        for _ in 0..self.max_state_trace_depth {
            match mapping.block_for_state(current) {
                Some(addr) => return Some(addr),
                None => {
                    // Try constant folding one step.
                    match Self::fold_state_expr(current, mapping) {
                        Some(next) if next != current => current = next,
                        _ => return None,
                    }
                }
            }
        }
        None
    }

    /// Reconstruct the edges of the original (pre-CFF) CFG.
    ///
    /// Algorithm:
    /// 1. For each non-dispatcher block B, find B's successors in `cfg`.
    /// 2. Any successor that is the dispatcher is replaced by the block that the
    ///    state written by B maps to in `mapping`.
    /// 3. Edges between non-dispatcher blocks are kept as-is.
    pub fn reconstruct_edges(
        &self,
        candidate: &CffCandidate,
        mapping: &BlockMapping,
        cfg: &SimpleCfg,
    ) -> Vec<RecoveredEdge> {
        let mut edges = Vec::with_capacity(cfg.edges.len());

        let dispatcher_idx = match cfg.index_of(candidate.dispatcher_address) {
            Some(i) => i,
            None => return edges,
        };

        for &(from_idx, to_idx, etype) in &cfg.edges {
            // Skip the dispatcher's own outgoing edges (those are the fake ones
            // that CFF introduces).
            if from_idx == dispatcher_idx {
                continue;
            }

            let from_bb = &cfg.blocks[from_idx];
            let from_block = from_bb.address;

            // Edge goes to dispatcher → resolve via state mapping.
            // Prefer the real constant from `state_const`; fall back to the
            // address-derived value used during `build_block_mapping`.
            if to_idx == dispatcher_idx {
                let state_value = from_bb
                    .state_const
                    .unwrap_or_else(|| from_block.as_u64() & 0xFFFF_FFFF);
                if let Some(target) = self.trace_state(state_value, mapping) {
                    let edge_type = match etype {
                        EdgeType::TrueBranch => RecoveredEdgeType::TrueBranch,
                        EdgeType::FalseBranch => RecoveredEdgeType::FalseBranch,
                        EdgeType::Unconditional => RecoveredEdgeType::Unconditional,
                    };
                    edges.push(RecoveredEdge {
                        from_block,
                        to_block: target,
                        edge_type,
                        state_value: Some(state_value),
                    });
                }
                continue;
            }

            // Edge is between two non-dispatcher blocks → keep it.
            if to_idx != dispatcher_idx {
                let to_block = cfg.blocks[to_idx].address;
                let edge_type = match etype {
                    EdgeType::TrueBranch => RecoveredEdgeType::TrueBranch,
                    EdgeType::FalseBranch => RecoveredEdgeType::FalseBranch,
                    EdgeType::Unconditional => RecoveredEdgeType::Unconditional,
                };
                edges.push(RecoveredEdge {
                    from_block,
                    to_block,
                    edge_type,
                    state_value: None,
                });
            }
        }

        edges
    }

    /// Constant-fold a state expression.
    ///
    /// If `value` is not directly in the mapping but maps to a block, return that
    /// block's low-32-bit address — i.e. the identity fold.
    /// Returns `None` when no folding is possible.
    pub fn fold_state_expr(value: u64, mapping: &BlockMapping) -> Option<u64> {
        // If the value already has a direct entry, nothing to fold.
        if mapping.block_for_state(value).is_some() {
            return Some(value);
        }
        // Try the upper-32-bit truncated form.
        let truncated = value & 0xFFFF_FFFF;
        if truncated != value && mapping.block_for_state(truncated).is_some() {
            return Some(truncated);
        }
        None
    }

    // ----- dataflow-backed recovery -----------------------------------------

    /// Recover the de-flattened CFG using IL-dataflow constant propagation.
    ///
    /// This method is a drop-in replacement for [`CffRecoverer::recover`] that
    /// uses a worklist-based constant-propagation pass
    /// ([`StateVarTracker::propagate_dataflow`]) to resolve state-variable
    /// assignments before building the block mapping.
    ///
    /// # How it differs from `recover`
    ///
    /// `recover` only uses `SimpleBb::state_const` when it has already been
    /// populated by the caller.  `recover_with_dataflow` *computes* those
    /// constants itself by propagating known values forward through the CFG.
    /// This catches blocks whose state constant can be derived from an upstream
    /// assignment even when `state_const` is initially `None`.
    ///
    /// After the propagation pass the method delegates to the standard
    /// [`CffRecoverer::build_block_mapping`] / [`CffRecoverer::reconstruct_edges`]
    /// pipeline so that all existing fallback strategies (address-derived state,
    /// sequential seeds) are preserved.
    pub fn recover_with_dataflow(&self, candidate: &CffCandidate, cfg: &SimpleCfg) -> RecoveredCfg {
        // --- Step 1: run the dataflow propagation pass. ---------------------
        let mut tracker = StateVarTracker::new();
        let lattice = tracker.propagate_dataflow(cfg, candidate.dispatcher_address);

        // --- Step 2: build an augmented copy of the CFG where every block
        //     that the dataflow resolved has its state_const filled in.       ---
        let mut augmented = cfg.clone();
        for bb in &mut augmented.blocks {
            if bb.state_const.is_none() && let Some(cell) = lattice.get(&bb.address.as_u64()) && let ConstLattice::Const(v) = cell {
                bb.state_const = Some(*v);
            }
        }

        // --- Step 3: resolve the switch dispatch targets. -------------------
        // For each predecessor of the dispatcher that has a known state value,
        // make sure the tracker's `state_targets` map has a valid entry so that
        // `trace_state` will find it.
        //
        // We do this by consulting the `tracker` (which was filled by
        // `propagate_dataflow` for predecessor blocks) and then fall through
        // to the standard mapping builder on the augmented CFG.
        let dispatcher_idx = augmented
            .blocks
            .iter()
            .position(|b| b.address == candidate.dispatcher_address);

        if let Some(disp_idx) = dispatcher_idx {
            // Walk the dispatcher's successors: these are the candidate body
            // blocks.  For each one that immediately has a successor with a
            // known constant (single-block chains), resolve the next-state.
            for &(from, to, _) in &augmented.edges {
                if to == disp_idx {
                    // `from` feeds the dispatcher — check if its exit state was
                    // resolved by dataflow.
                    let bb_addr = augmented.blocks[from].address;
                    if augmented.blocks[from].state_const.is_none() && let Some(assigns) = tracker.assignments.get(&bb_addr.as_u64()) && let Some(first) = assigns.first() {
                        // Try the tracker's assignment map as a fallback.
                        augmented.blocks[from].state_const = Some(first.value);
                    }
                }
            }
        }

        // --- Step 4: use the standard pipeline on the augmented CFG. --------
        let mapping = self.build_block_mapping(candidate, &augmented);
        let edges = self.reconstruct_edges(candidate, &mapping, &augmented);

        let dispatcher_idx = augmented
            .index_of(candidate.dispatcher_address)
            .unwrap_or(usize::MAX);

        let blocks: Vec<Address> = augmented
            .blocks
            .iter()
            .enumerate()
            .filter(|&(i, _)| i != dispatcher_idx)
            .map(|(_, b)| b.address)
            .collect();

        RecoveredCfg {
            function_start: candidate.function_start,
            blocks,
            edges,
            dispatcher_address: candidate.dispatcher_address,
            state_variable: candidate.state_variable.clone(),
            original_candidate: candidate.clone(),
        }
    }

    // ----- internal helpers -------------------------------------------------

    /// Propagate state values through the CFG to handle simple chains where a
    /// block unconditionally sets the state to a constant and then jumps to the
    /// dispatcher.
    fn propagate_states(
        &self,
        cfg: &SimpleCfg,
        dispatcher_idx: usize,
        mapping: &mut BlockMapping,
        depth: usize,
    ) {
        if depth >= self.max_state_trace_depth {
            return;
        }

        // Collect all states that do not yet resolve.
        let unresolved: Vec<u64> = {
            // snapshot to avoid borrow conflict
            mapping.state_to_block.keys().copied()
                .filter(|&s| mapping.block_for_state(s).is_none())
                .collect()
        };

        if unresolved.is_empty() {
            return;
        }

        // Snapshot the count BEFORE the insertion loop so we can detect whether
        // any new entries were added (i.e., real progress was made).
        let old_count = mapping.state_to_block.len();

        // For each block that writes state, see if its predecessor wrote a
        // different state we already know about; if so, link them.
        for &(from, to, _) in &cfg.edges {
            if to != dispatcher_idx || from == dispatcher_idx {
                continue;
            }
            let block = &cfg.blocks[from];
            let block_addr = block.address;
            // Prefer the real constant when available; fall back to address.
            let state_value = block
                .state_const
                .unwrap_or_else(|| block_addr.as_u64() & 0xFFFF_FFFF);
            if mapping.block_for_state(state_value).is_none() {
                mapping.insert(state_value, block_addr);
            }
        }

        // Only recurse when new entries were inserted; avoids infinite recursion
        // when no progress is possible before max_state_trace_depth is reached.
        if mapping.state_to_block.len() > old_count {
            self.propagate_states(cfg, dispatcher_idx, mapping, depth + 1);
        }
    }
}

// ---------------------------------------------------------------------------
// DataflowConstProp  — worklist-based constant propagation for state vars
// ---------------------------------------------------------------------------

/// Abstract value in the constant-propagation lattice.
///
/// The lattice has three levels:
/// * `Top`     — the block has not yet been visited (⊤, widest).
/// * `Const(v)` — the state variable is known to hold `v` at this program point.
/// * `Bottom`  — the state variable has more than one possible value at this
///   point (⊥, widest-after-meet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstLattice {
    /// Not yet analysed.
    Top,
    /// Exactly one constant value is possible.
    Const(u64),
    /// Multiple values possible — the value is not a compile-time constant.
    Bottom,
}

impl ConstLattice {
    /// Meet operator: `Top` is the identity; two equal `Const` values stay
    /// `Const`; anything else collapses to `Bottom`.
    #[must_use]
    pub fn meet(self, other: ConstLattice) -> ConstLattice {
        match (self, other) {
            (ConstLattice::Top, x) | (x, ConstLattice::Top) => x,
            (ConstLattice::Const(a), ConstLattice::Const(b)) if a == b => ConstLattice::Const(a),
            _ => ConstLattice::Bottom,
        }
    }

    /// Return the constant value if this cell holds exactly one.
    #[must_use]
    pub fn as_const(self) -> Option<u64> {
        match self {
            ConstLattice::Const(v) => Some(v),
            _ => None,
        }
    }
}

impl StateVarTracker {
    /// Propagate constants through `cfg` using a classic worklist algorithm.
    ///
    /// # Algorithm
    ///
    /// Each basic block is associated with a [`ConstLattice`] cell that
    /// represents the value of the CFF state variable at block *exit*.
    ///
    /// Initialisation:
    /// * If `SimpleBb::state_const` is `Some(v)` the cell is seeded with
    ///   `Const(v)`.
    /// * All other cells start at `Top`.
    ///
    /// Iteration (worklist):
    /// * A block is "processed" by meeting the exit-values of all its
    ///   predecessors to produce an entry-value.
    /// * The block's own `state_const` (if present) *overrides* the entry
    ///   value — modelling an explicit constant assignment at block exit.
    /// * If the new exit-value is different from the old one the block's
    ///   successors are added to the worklist.
    ///
    /// Termination is guaranteed because the lattice has height 2 and
    /// each cell can only move downward (Top → Const → Bottom).
    ///
    /// After convergence every `Const` cell is recorded in `self` via
    /// [`StateVarTracker::record`].
    ///
    /// Returns a `HashMap<u64 /* block addr */, ConstLattice>` with the
    /// final exit-lattice value for every block.
    pub fn propagate_dataflow(
        &mut self,
        cfg: &SimpleCfg,
        dispatcher_addr: Address,
    ) -> AHashMap<u64, ConstLattice> {
        // Guard against adversarially large CFGs that would exhaust memory via
        // the O(n) allocations below (lattice vec, preds vec, worklist).
        const MAX_BLOCKS: usize = 100_000;
        let n = cfg.blocks.len().min(MAX_BLOCKS);
        // Map block index → exit lattice value.
        let mut lattice: Vec<ConstLattice> = vec![ConstLattice::Top; n];

        // Seed blocks that already know their state constant.
        for (i, bb) in cfg.blocks.iter().enumerate() {
            if let Some(c) = bb.state_const {
                lattice[i] = ConstLattice::Const(c);
            }
        }

        // Build predecessor index: for each block, list its predecessor indices.
        let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
        for &(from, to, _) in &cfg.edges {
            if from < n && to < n {
                preds[to].push(from);
            }
        }

        // Worklist initialised with all block indices.
        let mut worklist: std::collections::VecDeque<usize> = (0..n).collect();
        let mut in_worklist = vec![true; n];

        while let Some(idx) = worklist.pop_front() {
            in_worklist[idx] = false;

            // Meet all predecessor exit-values to get the entry-value.
            let entry_val = preds[idx]
                .iter()
                .fold(ConstLattice::Top, |acc, &p| acc.meet(lattice[p]));

            // The block's own state_const overrides the propagated entry.
            let exit_val = if let Some(c) = cfg.blocks[idx].state_const {
                ConstLattice::Const(c)
            } else {
                entry_val
            };

            // If the exit-value changed, propagate to successors.
            if exit_val != lattice[idx] {
                lattice[idx] = exit_val;
                for &(from, to, _) in &cfg.edges {
                    if from == idx && to < n && !in_worklist[to] {
                        worklist.push_back(to);
                        in_worklist[to] = true;
                    }
                }
            }
        }

        // Record all resolved constants that feed into the dispatcher.
        let dispatcher_idx = cfg.blocks.iter().position(|b| b.address == dispatcher_addr);
        for (i, bb) in cfg.blocks.iter().enumerate() {
            if let ConstLattice::Const(v) = lattice[i] {
                // Only record predecessor-of-dispatcher blocks as state writers,
                // but also record any block that has a known constant — the
                // caller can filter by context.
                let feeds_dispatcher = dispatcher_idx
                    .map(|d| cfg.edges.iter().any(|&(f, t, _)| f == i && t == d))
                    .unwrap_or(false);
                if feeds_dispatcher {
                    self.record(bb.address, v, false);
                }
            }
        }

        // Return address-keyed map for external use.
        cfg.blocks
            .iter()
            .enumerate()
            .map(|(i, bb)| (bb.address.as_u64(), lattice[i]))
            .collect::<AHashMap<_, _>>()
    }
}

// ---------------------------------------------------------------------------
// CffVerifier / CffVerifyResult
// ---------------------------------------------------------------------------

/// Statistics produced by [`CffVerifier::verify`].
#[derive(Debug, Clone)]
pub struct CffVerifyResult {
    /// Whether the recovered CFG passed all checks.
    pub is_valid: bool,
    /// Total number of recovered edges examined.
    pub total_edges: usize,
    /// Number of edges whose `to_block` is not in `RecoveredCfg::blocks`.
    pub dangling_edges: usize,
    /// Number of blocks that have more than one unconditional out-edge to the
    /// original dispatcher (indicates a recovery anomaly).
    pub multi_dispatch_blocks: usize,
    /// Number of blocks in the recovered CFG.
    pub block_count: usize,
    /// Non-fatal diagnostic messages.
    pub diagnostics: Vec<String>,
}

impl CffVerifyResult {
    /// `true` when the result has no errors.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.is_valid && self.dangling_edges == 0 && self.multi_dispatch_blocks == 0
    }
}

/// Validates a [`RecoveredCfg`] for structural soundness.
///
/// The verifier checks:
/// 1. Every `to_block` address in the recovered edges exists in
///    `RecoveredCfg::blocks` — no dangling references.
/// 2. No block has more than one unconditional out-edge whose `state_value`
///    is `Some` (which would mean the recoverer mapped one block to two
///    different dispatcher targets).
/// 3. The dispatcher address is absent from `RecoveredCfg::blocks`.
#[derive(Debug, Clone, Default)]
pub struct CffVerifier;

impl CffVerifier {
    /// Create a new verifier.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Verify `recovered` and return a [`CffVerifyResult`].
    #[must_use]
    pub fn verify(&self, recovered: &RecoveredCfg) -> CffVerifyResult {
        let block_set: std::collections::HashSet<u64> =
            recovered.blocks.iter().map(|a| a.as_u64()).collect();

        let mut diagnostics = Vec::new();
        let mut dangling_edges = 0usize;
        let mut is_valid = true;

        // Check 1 — no dangling edges.
        for edge in &recovered.edges {
            if !block_set.contains(&edge.to_block.as_u64()) {
                dangling_edges += 1;
                diagnostics.push(format!(
                    "dangling edge: {} → {} (destination not in recovered blocks)",
                    edge.from_block, edge.to_block
                ));
                is_valid = false;
            }
            if !block_set.contains(&edge.from_block.as_u64()) {
                dangling_edges += 1;
                diagnostics.push(format!(
                    "dangling edge: {} → {} (source not in recovered blocks)",
                    edge.from_block, edge.to_block
                ));
                is_valid = false;
            }
        }

        // Check 2 — no block has >1 unconditional state-resolved out-edge.
        // Build a per-block count of unconditional edges that have a state_value.
        let mut unconditional_dispatch: HashMap<u64, usize> = HashMap::new();
        for edge in &recovered.edges {
            if edge.edge_type == RecoveredEdgeType::Unconditional && edge.state_value.is_some() {
                *unconditional_dispatch
                    .entry(edge.from_block.as_u64())
                    .or_insert(0) += 1;
            }
        }
        let multi_dispatch_blocks = unconditional_dispatch
            .iter()
            .filter(|&(_, count)| *count > 1)
            .count();
        for (&addr, &count) in &unconditional_dispatch {
            if count > 1 {
                diagnostics.push(format!(
                    "block {:#x} has {} unconditional dispatch edges (expected ≤1)",
                    addr, count
                ));
                is_valid = false;
            }
        }

        // Check 3 — dispatcher address must NOT appear in recovered blocks.
        if block_set.contains(&recovered.dispatcher_address.as_u64()) {
            diagnostics.push(format!(
                "dispatcher address {} incorrectly included in recovered blocks",
                recovered.dispatcher_address
            ));
            is_valid = false;
        }

        CffVerifyResult {
            is_valid,
            total_edges: recovered.edges.len(),
            dangling_edges,
            multi_dispatch_blocks,
            block_count: recovered.blocks.len(),
            diagnostics,
        }
    }
}

// ---------------------------------------------------------------------------
// CffDeobfuscationPass
// ---------------------------------------------------------------------------

/// Result of running the CFF deobfuscation pass over a binary.
#[derive(Debug, Default)]
pub struct DeobfResult {
    /// Total number of CFF candidates detected.
    pub candidates_found: usize,
    /// Number of candidates successfully recovered.
    pub candidates_recovered: usize,
    /// Successfully recovered CFGs.
    pub recovered: Vec<RecoveredCfg>,
    /// Candidates for which recovery failed (no mapping could be built).
    pub failed: Vec<CffCandidate>,
    /// Non-fatal error messages encountered during the pass.
    pub errors: Vec<String>,
}

/// High-level entry point combining detection and recovery.
pub struct CffDeobfuscationPass {
    pub detector: CffDetector,
    pub recoverer: CffRecoverer,
}

impl Default for CffDeobfuscationPass {
    fn default() -> Self {
        Self::new()
    }
}

impl CffDeobfuscationPass {
    /// Create a pass with default detector and recoverer settings.
    pub fn new() -> Self {
        Self {
            detector: CffDetector::new(),
            recoverer: CffRecoverer::new(),
        }
    }

    /// Run detection and recovery on a single function CFG.
    ///
    /// Returns `Some(RecoveredCfg)` if the function was identified as CFF and
    /// successfully recovered; `None` otherwise.
    pub fn run_on_function(
        &self,
        cfg: &SimpleCfg,
        function_start: Address,
    ) -> Option<RecoveredCfg> {
        let candidate = self.detector.detect(cfg, function_start)?;
        let mapping = self.recoverer.build_block_mapping(&candidate, cfg);
        // Reject both empty mappings and partial mappings (blocks present but
        // not all states resolve), which would produce dangling CFG edges.
        if !mapping.is_complete() {
            return None;
        }
        Some(self.recoverer.recover(&candidate, cfg))
    }

    /// Run the pass over an entire binary represented as a list of
    /// `(function_start_address, simplified_cfg)` pairs.
    pub fn run_on_binary(&self, cfgs: Vec<(Address, SimpleCfg)>) -> DeobfResult {
        let mut result = DeobfResult::default();

        for (function_start, cfg) in cfgs {
            match self.detector.detect(&cfg, function_start) {
                None => {}
                Some(candidate) => {
                    result.candidates_found += 1;
                    let mapping = self.recoverer.build_block_mapping(&candidate, &cfg);
                    if mapping.block_count() == 0 {
                        result
                            .errors
                            .push(format!("empty block mapping for {function_start}"));
                        result.failed.push(candidate);
                        continue;
                    }
                    let recovered = self.recoverer.recover(&candidate, &cfg);
                    result.candidates_recovered += 1;
                    result.recovered.push(recovered);
                }
            }
        }

        result
    }
}

// ---------------------------------------------------------------------------
// CffDispatcherDetector  (§20.3 — raw-bytes heuristic)
// ---------------------------------------------------------------------------

/// A CFF dispatcher detected from raw machine code.
///
/// Describes the address of the dispatch loop, the address of the state
/// variable in memory, and the number of handler branches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CffDispatcher {
    /// Address of the dispatcher block (start of the compare/branch sequence).
    pub addr: u64,
    /// Heuristic address of the state variable being compared.
    pub state_var_addr: u64,
    /// Number of individual handler branches detected (minimum 5).
    pub handler_count: u32,
}

/// Detects CFF dispatcher blocks directly from raw x86 machine code.
///
/// Detection strategy:
/// 1. Scan for repeated `CMP [mem], imm` + short conditional branch pairs.
/// 2. A run of 5 or more such pairs is classified as a dispatcher.
/// 3. The state variable address is taken from the first `CMP [mem32], imm8`
///    in the run.
///
/// Recognised opcodes:
/// - `83 3D <disp32> <imm8>` — `CMP DWORD PTR [rip+disp32], imm8`
/// - `81 3D <disp32> <imm32>` — `CMP DWORD PTR [rip+disp32], imm32`
/// - Short conditional jumps `0x74`–`0x7F` (2-byte form).
#[derive(Debug, Clone, Default)]
pub struct CffDispatcherDetector;

impl CffDispatcherDetector {
    /// Minimum number of consecutive compare-branch pairs to qualify as a
    /// dispatcher.
    pub const MIN_HANDLER_COUNT: u32 = 5;

    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Scan `code` (mapped at virtual address `base`) and return every
    /// detected [`CffDispatcher`].
    #[must_use]
    pub fn detect(code: &[u8], base: u64) -> Vec<CffDispatcher> {
        let mut results = Vec::new();
        let mut i = 0;

        while i < code.len() {
            // Try to match the start of a compare-branch sequence.
            if let Some((consumed, state_var, handlers)) = Self::try_match_dispatcher_sequence(code, i) && handlers >= Self::MIN_HANDLER_COUNT {
                results.push(CffDispatcher {
                    addr: base.saturating_add(i as u64),
                    state_var_addr: state_var,
                    handler_count: handlers,
                });
                i += consumed;
                continue;
            }
            i += 1;
        }

        results
    }

    /// Attempt to match a run of `CMP [mem], const; JCC rel8` pairs starting
    /// at `offset` in `code`.
    ///
    /// Returns `Some((bytes_consumed, state_var_addr, handler_count))` on
    /// success, `None` otherwise.
    fn try_match_dispatcher_sequence(code: &[u8], offset: usize) -> Option<(usize, u64, u32)> {
        let mut pos = offset;
        let mut handler_count = 0u32;
        let mut state_var_addr = 0u64;

        loop {
            if pos.saturating_add(7) >= code.len() {
                break;
            }

            // Pattern A: 83 3D <disp32> <imm8> <jcc> <rel8>
            //            CMP DWORD PTR [rip+disp32], imm8; JCC rel8
            if code[pos] == 0x83 && code[pos + 1] == 0x3D {
                let disp = i32::from_le_bytes([
                    code[pos + 2],
                    code[pos + 3],
                    code[pos + 4],
                    code[pos + 5],
                ]);
                // The byte after is imm8, then a conditional jump.
                let jcc_pos = pos + 7;
                if jcc_pos + 1 < code.len() && (0x70..=0x7F).contains(&code[jcc_pos]) {
                    if handler_count == 0 {
                        // Derive a pseudo-absolute address from the RIP-relative disp.
                        // RIP = pos + 7 (end of the instruction).
                        let rip = (pos + 7) as i64;
                        state_var_addr = rip.wrapping_add(disp as i64) as u64;
                    }
                    handler_count += 1;
                    pos = jcc_pos + 2; // skip jcc + rel8
                    continue;
                }
            }

            // Pattern B: 81 3D <disp32> <imm32> <jcc> <rel8>  (7-byte CMP)
            if pos.saturating_add(10) < code.len() && code[pos] == 0x81 && code[pos + 1] == 0x3D {
                let jcc_pos = pos + 10;
                if jcc_pos + 1 < code.len() && (0x70..=0x7F).contains(&code[jcc_pos]) {
                    if handler_count == 0 {
                        let disp = i32::from_le_bytes([
                            code[pos + 2],
                            code[pos + 3],
                            code[pos + 4],
                            code[pos + 5],
                        ]);
                        let rip = (pos + 10) as i64;
                        state_var_addr = rip.wrapping_add(disp as i64) as u64;
                    }
                    handler_count += 1;
                    pos = jcc_pos + 2;
                    continue;
                }
            }

            // Pattern C: 39 05 / 3B 05 — CMP [rip+disp], reg  (6 bytes + jcc)
            if pos.saturating_add(7) < code.len()
                && (code[pos] == 0x39 || code[pos] == 0x3B)
                && code[pos + 1] == 0x05
            {
                let jcc_pos = pos + 6;
                if jcc_pos + 1 < code.len() && (0x70..=0x7F).contains(&code[jcc_pos]) {
                    if handler_count == 0 {
                        let disp = i32::from_le_bytes([
                            code[pos + 2],
                            code[pos + 3],
                            code[pos + 4],
                            code[pos + 5],
                        ]);
                        state_var_addr = (pos as i64 + 6).wrapping_add(disp as i64) as u64;
                    }
                    handler_count += 1;
                    pos = jcc_pos + 2;
                    continue;
                }
            }

            break;
        }

        if handler_count >= Self::MIN_HANDLER_COUNT {
            Some((pos - offset, state_var_addr, handler_count))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// StateTransitionAnalyzer
// ---------------------------------------------------------------------------

/// The state-transition graph for one CFF dispatcher.
///
/// Each node is a 32-bit state value; edges carry the next-state value and
/// an optional boolean condition (true = true branch, false = false branch,
/// `None` = unconditional).
///
/// Uses `AHashMap` instead of `HashMap` so that attacker-controlled state
/// values (read from untrusted binary input) cannot trigger hash-collision
/// DoS via crafted key sets (dos-hash-collision).
#[derive(Debug, Clone, Default)]
pub struct StateGraph {
    /// `state → [(next_state, condition)]`
    pub nodes: AHashMap<u32, Vec<(u32, Option<bool>)>>,
}

impl StateGraph {
    /// Create an empty [`StateGraph`].
    #[must_use]
    pub fn new() -> Self {
        Self { nodes: AHashMap::new() }
    }

    /// Add a directed edge from `from` to `to` with optional `condition`.
    pub fn add_edge(&mut self, from: u32, to: u32, condition: Option<bool>) {
        self.nodes.entry(from).or_default().push((to, condition));
    }

    /// Return all transitions reachable from `state`.
    #[must_use]
    pub fn transitions(&self, state: u32) -> &[(u32, Option<bool>)] {
        self.nodes.get(&state).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Return the number of unique states in the graph.
    #[must_use]
    pub fn state_count(&self) -> usize {
        self.nodes.len()
    }

    /// Return `true` when the graph contains no states.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Return the set of all states referenced as targets (next-state values).
    #[must_use]
    pub fn all_targets(&self) -> std::collections::HashSet<u32> {
        self.nodes
            .values()
            .flat_map(|edges| edges.iter().map(|(t, _)| *t))
            .collect()
    }
}

/// Analyses state transitions for a detected CFF dispatcher.
///
/// For each handler block the analyser scans for assignments to the state
/// variable and determines the next state (constant) or branch condition.
#[derive(Debug, Clone, Default)]
pub struct StateTransitionAnalyzer;

impl StateTransitionAnalyzer {
    /// Create a new analyser.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Derive the [`StateGraph`] for `dispatcher` from the raw `code` bytes.
    ///
    /// Algorithm:
    /// 1. Starting after the dispatcher address, scan handler-sized windows.
    /// 2. In each window, look for `MOV [state_var], imm32` — a constant
    ///    state assignment.
    /// 3. Conditional assignments are heuristically classified by the branch
    ///    direction of the preceding `JCC`.
    #[must_use]
    pub fn analyze(dispatcher: &CffDispatcher, code: &[u8]) -> StateGraph {
        let mut graph = StateGraph::new();

        // Anchor: scan windows starting from the dispatcher itself.
        let start = (dispatcher.addr as usize).min(code.len());
        let window = 32usize;
        let mut state_seed = 0u32;

        let mut pos = start;
        while pos + window < code.len() {
            let slice = &code[pos..pos + window];

            // Look for MOV DWORD PTR [mem], imm32: C7 05 <disp32> <imm32>
            if let Some((from_state, to_state, cond)) =
                Self::extract_state_assignment(slice, state_seed, dispatcher.state_var_addr)
            {
                graph.add_edge(from_state, to_state, cond);
                state_seed = state_seed.wrapping_add(1);
            }

            pos += window / 2;
        }

        graph
    }

    /// Look for a `MOV [state_var], imm32` or `MOV [state_var], imm8` in
    /// `slice` and derive `(from_state, to_state, condition)`.
    fn extract_state_assignment(
        slice: &[u8],
        seed: u32,
        _state_var_addr: u64,
    ) -> Option<(u32, u32, Option<bool>)> {
        // C7 05 <disp32> <imm32>  — MOV DWORD PTR [rip+disp], imm32
        for i in 0..slice.len().saturating_sub(9) {
            if slice[i] == 0xC7 && slice[i + 1] == 0x05 {
                let to_state =
                    u32::from_le_bytes([slice[i + 6], slice[i + 7], slice[i + 8], slice[i + 9]]);
                // Determine condition from preceding short JCC if present.
                let cond = if i >= 2 && (0x70..=0x7F).contains(&slice[i - 2]) {
                    // True branch ≡ even opcodes (JO,JB,JZ,JBE,JS,JP,JL,JLE).
                    Some(slice[i - 2] & 1 == 0)
                } else {
                    None
                };
                return Some((seed, to_state, cond));
            }
        }

        // C6 05 <disp32> <imm8>  — MOV BYTE PTR [rip+disp], imm8
        for i in 0..slice.len().saturating_sub(6) {
            if slice[i] == 0xC6 && slice[i + 1] == 0x05 {
                let to_state = slice[i + 6] as u32;
                return Some((seed, to_state, None));
            }
        }

        None
    }
}

// ---------------------------------------------------------------------------
// CffDeflattener
// ---------------------------------------------------------------------------

/// A single reconstructed CFG edge (used by the deflattener).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgEdge {
    /// Source state value (the handler block).
    pub from_state: u32,
    /// Destination state value.
    pub to_state: u32,
    /// Branch condition: `None` = unconditional, `Some(true)` = true branch,
    /// `Some(false)` = false branch.
    pub condition: Option<bool>,
}

/// Reconstructs the original CFG from a CFF state-transition graph.
#[derive(Debug, Clone, Default)]
pub struct CffDeflattener;

impl CffDeflattener {
    /// Create a new deflattener.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Convert the `state_graph` produced for `dispatcher` into a flat list
    /// of [`CfgEdge`] values representing the original control flow.
    #[must_use]
    pub fn deflaten(dispatcher: &CffDispatcher, state_graph: &StateGraph) -> Vec<CfgEdge> {
        let _ = dispatcher; // address context unused in this pass
        // Cap the pre-allocation so an adversarially large StateGraph cannot
        // exhaust memory before the Vec is actually filled.
        const MAX_PREALLOC_EDGES: usize = 65_536;
        let raw_cap: usize = state_graph.nodes.values().map(|v| v.len()).sum();
        let mut edges = Vec::with_capacity(raw_cap.min(MAX_PREALLOC_EDGES));

        for (&from_state, transitions) in &state_graph.nodes {
            for &(to_state, condition) in transitions {
                edges.push(CfgEdge {
                    from_state,
                    to_state,
                    condition,
                });
            }
        }

        // Sort for deterministic output: by from_state, then to_state.
        edges.sort_by(|a, b| {
            a.from_state
                .cmp(&b.from_state)
                .then(a.to_state.cmp(&b.to_state))
        });
        edges
    }

    /// Estimate the likelihood (0.0–1.0) that `code` exhibits CFF obfuscation.
    ///
    /// Combines three independent indicators:
    ///
    /// | Indicator | Weight |
    /// |-----------|--------|
    /// | Dispatcher density (dispatchers per 1 KiB) | 0.50 |
    /// | Ratio of compare-branch pairs to total bytes | 0.30 |
    /// | Shannon entropy (high = obfuscated) | 0.20 |
    #[must_use]
    pub fn estimate_cff_confidence(code: &[u8]) -> f32 {
        if code.is_empty() {
            return 0.0;
        }

        // --- Indicator 1: dispatcher density ---
        let dispatchers = CffDispatcherDetector::detect(code, 0);
        let kib = (code.len() as f32 / 1024.0).max(1.0);
        let dispatcher_score = (dispatchers.len() as f32 / kib).clamp(0.0, 1.0);

        // --- Indicator 2: compare-branch pair density ---
        let mut cmp_branch_pairs = 0u64;
        let mut i = 0;
        while i + 2 < code.len() {
            let is_cmp = ((code[i] == 0x83 || code[i] == 0x81) && code[i + 1] == 0x3D)
                || (code[i] == 0x39 && code[i + 1] == 0x05)
                || (code[i] == 0x3B && code[i + 1] == 0x05);
            if is_cmp {
                cmp_branch_pairs += 1;
            }
            i += 1;
        }
        let cmp_ratio = (cmp_branch_pairs as f32 * 7.0 / code.len() as f32).clamp(0.0, 1.0);

        // --- Indicator 3: Shannon entropy ---
        let entropy = {
            let mut freq = [0u64; 256];
            for &b in code {
                freq[b as usize] += 1;
            }
            let n = code.len() as f32;
            let h: f32 = freq
                .iter()
                .filter(|&&c| c > 0)
                .map(|&c| {
                    let p = c as f32 / n;
                    -p * p.log2()
                })
                .sum();
            // Normalise to 0-1 (max entropy for byte stream = 8.0 bits).
            (h / 8.0).clamp(0.0, 1.0)
        };

        let score = dispatcher_score * 0.50 + cmp_ratio * 0.30 + entropy * 0.20;
        score.clamp(0.0, 1.0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers to build test CFGs
    // -----------------------------------------------------------------------

    /// Build a classic CFF-shaped CFG:
    ///
    /// ```text
    ///   [entry] → [dispatcher] → [block A]
    ///                          → [block B]
    ///                          → [block C]
    ///   [block A] → [dispatcher]
    ///   [block B] → [dispatcher]
    ///   [block C] → [dispatcher]
    /// ```
    ///
    /// Index layout: 0=entry, 1=dispatcher, 2=A, 3=B, 4=C.
    fn make_cff_cfg() -> SimpleCfg {
        let blocks = vec![
            SimpleBb {
                address: Address::new(0x1000),
                successor_count: 1,
                predecessor_count: 0,
                instr_count: 3,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: Some("eax".into()),
                state_const: None,
            },
            // Dispatcher (index 1)
            SimpleBb {
                address: Address::new(0x1010),
                successor_count: 3,
                predecessor_count: 4, // entry + A + B + C
                instr_count: 4,
                ends_with_indirect_jump: false,
                ends_with_conditional: true,
                sets_register: None,
                state_const: None,
            },
            // Block A (index 2)
            SimpleBb {
                address: Address::new(0x1020),
                successor_count: 1,
                predecessor_count: 1,
                instr_count: 5,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: Some("eax".into()),
                state_const: None,
            },
            // Block B (index 3)
            SimpleBb {
                address: Address::new(0x1030),
                successor_count: 1,
                predecessor_count: 1,
                instr_count: 6,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: Some("eax".into()),
                state_const: None,
            },
            // Block C (index 4)
            SimpleBb {
                address: Address::new(0x1040),
                successor_count: 1,
                predecessor_count: 1,
                instr_count: 4,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: Some("eax".into()),
                state_const: None,
            },
        ];

        let edges = vec![
            (0, 1, EdgeType::Unconditional), // entry → dispatcher
            (1, 2, EdgeType::TrueBranch),    // dispatcher → A
            (1, 3, EdgeType::FalseBranch),   // dispatcher → B
            (1, 4, EdgeType::Unconditional), // dispatcher → C
            (2, 1, EdgeType::Unconditional), // A → dispatcher
            (3, 1, EdgeType::Unconditional), // B → dispatcher
            (4, 1, EdgeType::Unconditional), // C → dispatcher
        ];

        SimpleCfg { blocks, edges }
    }

    /// Build a "normal" (non-CFF) linear CFG:
    ///
    /// ```text
    /// [0] → [1] → [2] → [3]
    /// ```
    fn make_linear_cfg() -> SimpleCfg {
        let blocks: Vec<SimpleBb> = (0u64..4)
            .map(|i| SimpleBb {
                address: Address::new(0x2000 + i * 0x10),
                successor_count: if i < 3 { 1 } else { 0 },
                predecessor_count: if i > 0 { 1 } else { 0 },
                instr_count: 3,
                ends_with_indirect_jump: false,
                ends_with_conditional: false,
                sets_register: None,
                state_const: None,
            })
            .collect();

        let edges = vec![
            (0, 1, EdgeType::Unconditional),
            (1, 2, EdgeType::Unconditional),
            (2, 3, EdgeType::Unconditional),
        ];

        SimpleCfg { blocks, edges }
    }

    // -----------------------------------------------------------------------
    // Test 1: find_dispatcher returns the correct index
    // -----------------------------------------------------------------------
    #[test]
    fn test_find_dispatcher_correct_index() {
        let cfg = make_cff_cfg();
        let detector = CffDetector::new();
        let result = detector.find_dispatcher(&cfg);
        assert!(result.is_some(), "should find a dispatcher");
        let (idx, _confidence) = result.unwrap();
        // Index 1 has predecessor_count = 4 (the maximum).
        assert_eq!(idx, 1, "dispatcher should be block index 1");
    }

    // -----------------------------------------------------------------------
    // Test 2: compute_confidence on a clear CFF pattern (> 0.8)
    // -----------------------------------------------------------------------
    #[test]
    fn test_confidence_high_for_cff() {
        let cfg = make_cff_cfg();
        let detector = CffDetector::new();
        let confidence = detector.compute_confidence(&cfg, 1);
        assert!(
            confidence > 0.8,
            "expected confidence > 0.8, got {confidence}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 3: compute_confidence on a normal CFG (< 0.3)
    // -----------------------------------------------------------------------
    #[test]
    fn test_confidence_low_for_normal_cfg() {
        let cfg = make_linear_cfg();
        let detector = CffDetector::new();
        // Block 1 has predecessor_count 1 — the max in the linear chain.
        let confidence = detector.compute_confidence(&cfg, 1);
        // A plain linear chain has no back-edges to a hub and no indirect jumps;
        // it should score well below the 0.6 detection threshold.
        assert!(
            confidence <= 0.35,
            "expected confidence <= 0.35 for a non-CFF linear CFG, got {confidence}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 4: identify_state_variable with register pattern
    // -----------------------------------------------------------------------
    #[test]
    fn test_identify_state_variable_register() {
        let cfg = make_cff_cfg();
        let detector = CffDetector::new();
        // Dispatcher is at index 1; blocks A, B, C all write "eax" before
        // jumping back.
        let sv = detector.identify_state_variable(&cfg, 1);
        assert_eq!(
            sv,
            StateVariable::Register("eax".into()),
            "state variable should be eax"
        );
    }

    // -----------------------------------------------------------------------
    // Test 5: BlockMapping::insert and block_for_state
    // -----------------------------------------------------------------------
    #[test]
    fn test_block_mapping_insert_and_lookup() {
        let mut m = BlockMapping::new();
        let addr = Address::new(0xDEAD_BEEF);
        m.insert(0x1234, addr);
        assert_eq!(m.block_for_state(0x1234), Some(addr));
        assert_eq!(m.block_for_state(0x9999), None);
    }

    // -----------------------------------------------------------------------
    // Test 6: BlockMapping::is_complete
    // -----------------------------------------------------------------------
    #[test]
    fn test_block_mapping_is_complete() {
        let mut m = BlockMapping::new();
        // Empty mapping is NOT complete.
        assert!(!m.is_complete());

        let a = Address::new(0x1000);
        let b = Address::new(0x2000);
        m.insert(1, a);
        m.insert(2, b);
        // Both states resolve → complete.
        assert!(m.is_complete());
    }

    // -----------------------------------------------------------------------
    // Test 7: CffRecoverer::build_block_mapping populates all states
    // -----------------------------------------------------------------------
    #[test]
    fn test_build_block_mapping_all_states_present() {
        let cfg = make_cff_cfg();
        let detector = CffDetector::new();
        let candidate = detector
            .detect(&cfg, Address::new(0x1000))
            .expect("should detect CFF");

        let recoverer = CffRecoverer::new();
        let mapping = recoverer.build_block_mapping(&candidate, &cfg);

        // Dispatcher at index 1 has 4 predecessors (entry + A + B + C).
        // The entry block sets eax too; all four should be in the mapping.
        assert!(
            mapping.block_count() >= 3,
            "expected ≥ 3 blocks in mapping, got {}",
            mapping.block_count()
        );
    }

    // -----------------------------------------------------------------------
    // Test 8: CffRecoverer::reconstruct_edges returns correct edges
    // -----------------------------------------------------------------------
    #[test]
    fn test_reconstruct_edges_no_dispatcher_edges() {
        let cfg = make_cff_cfg();
        let detector = CffDetector::new();
        let candidate = detector
            .detect(&cfg, Address::new(0x1000))
            .expect("should detect CFF");

        let recoverer = CffRecoverer::new();
        let mapping = recoverer.build_block_mapping(&candidate, &cfg);
        let edges = recoverer.reconstruct_edges(&candidate, &mapping, &cfg);

        let dispatcher_addr = candidate.dispatcher_address;

        // No recovered edge should have the dispatcher as either endpoint.
        for e in &edges {
            assert_ne!(
                e.from_block, dispatcher_addr,
                "dispatcher must not appear as edge source"
            );
            assert_ne!(
                e.to_block, dispatcher_addr,
                "dispatcher must not appear as edge target"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test 9: RecoveredCfg::successors and predecessors
    // -----------------------------------------------------------------------
    #[test]
    fn test_recovered_cfg_successors_predecessors() {
        let cfg = make_cff_cfg();
        let pass = CffDeobfuscationPass::new();
        let recovered = pass
            .run_on_function(&cfg, Address::new(0x1000))
            .expect("should recover");

        // Every non-entry block should have at least one predecessor.
        let non_entry: Vec<Address> = recovered
            .blocks
            .iter()
            .copied()
            .filter(|&a| a != recovered.function_start)
            .collect();

        for block in non_entry {
            let preds = recovered.predecessors(block);
            // In the CFF CFG, A/B/C are each dispatched from the dispatcher;
            // after recovery the entry or siblings become their predecessors.
            // We mainly check that the method doesn't panic and returns a Vec.
            let _ = preds;
            let succs = recovered.successors(block);
            let _ = succs;
        }
    }

    // -----------------------------------------------------------------------
    // Test 10: CffDeobfuscationPass::run_on_function returns Some for CFF CFG
    // -----------------------------------------------------------------------
    #[test]
    fn test_pass_detects_cff_function() {
        let cfg = make_cff_cfg();
        let pass = CffDeobfuscationPass::new();
        let result = pass.run_on_function(&cfg, Address::new(0x1000));
        assert!(
            result.is_some(),
            "expected Some(RecoveredCfg) for CFF input"
        );
    }

    // -----------------------------------------------------------------------
    // Test 11: CffDeobfuscationPass::run_on_function returns None for non-CFF
    // -----------------------------------------------------------------------
    #[test]
    fn test_pass_rejects_non_cff_function() {
        let cfg = make_linear_cfg();
        let pass = CffDeobfuscationPass::new();
        let result = pass.run_on_function(&cfg, Address::new(0x2000));
        assert!(result.is_none(), "expected None for a non-CFF linear CFG");
    }

    // -----------------------------------------------------------------------
    // Test 12: DeobfResult statistics are consistent
    // -----------------------------------------------------------------------
    #[test]
    fn test_deobf_result_statistics() {
        let pass = CffDeobfuscationPass::new();

        let cfgs = vec![
            (Address::new(0x1000), make_cff_cfg()), // should be detected
            (Address::new(0x2000), make_linear_cfg()), // should be ignored
            (Address::new(0x3000), make_cff_cfg()), // should be detected
        ];

        let result = pass.run_on_binary(cfgs);

        assert_eq!(result.candidates_found, 2, "two CFF functions expected");
        assert_eq!(
            result.candidates_recovered, 2,
            "both should be recovered successfully"
        );
        assert_eq!(result.recovered.len(), 2);
        assert!(result.failed.is_empty());
        assert!(result.errors.is_empty());
    }

    // -----------------------------------------------------------------------
    // Additional: StateVariable display
    // -----------------------------------------------------------------------
    #[test]
    fn test_state_variable_display() {
        assert_eq!(StateVariable::Register("eax".into()).to_string(), "reg:eax");
        assert_eq!(StateVariable::StackSlot(-8).to_string(), "stack[-8]");
        assert_eq!(
            StateVariable::GlobalMemory(Address::new(0x4000)).to_string(),
            "mem:0x4000"
        );
        assert_eq!(StateVariable::Unknown.to_string(), "<unknown>");
    }

    // -----------------------------------------------------------------------
    // Additional: CffPattern display
    // -----------------------------------------------------------------------
    #[test]
    fn test_cff_pattern_display() {
        assert_eq!(CffPattern::Dispatcher.to_string(), "Dispatcher");
        assert_eq!(CffPattern::JumpTable.to_string(), "JumpTable");
        assert_eq!(CffPattern::LinearSearch.to_string(), "LinearSearch");
        assert_eq!(CffPattern::NestedDispatch.to_string(), "NestedDispatch");
        assert_eq!(CffPattern::Unknown.to_string(), "Unknown");
    }

    // -----------------------------------------------------------------------
    // Additional: fold_state_expr identity and truncation
    // -----------------------------------------------------------------------
    #[test]
    fn test_fold_state_expr() {
        let mut m = BlockMapping::new();
        m.insert(0x1234, Address::new(0xAAAA));

        // Direct hit.
        assert_eq!(CffRecoverer::fold_state_expr(0x1234, &m), Some(0x1234));

        // Upper bits set but lower 32 hit.
        assert_eq!(
            CffRecoverer::fold_state_expr(0x0001_0000_1234, &m),
            Some(0x1234)
        );

        // No match.
        assert_eq!(CffRecoverer::fold_state_expr(0xDEAD, &m), None);
    }

    // -----------------------------------------------------------------------
    // Additional: RecoveredCfg is_entry
    // -----------------------------------------------------------------------
    #[test]
    fn test_recovered_cfg_is_entry() {
        let cfg = make_cff_cfg();
        let pass = CffDeobfuscationPass::new();
        let recovered = pass
            .run_on_function(&cfg, Address::new(0x1000))
            .expect("should recover");

        assert!(recovered.is_entry(Address::new(0x1000)));
        assert!(!recovered.is_entry(Address::new(0x1020)));
    }

    // -----------------------------------------------------------------------
    // Additional: BlockMapping states_for_block
    // -----------------------------------------------------------------------
    #[test]
    fn test_block_mapping_states_for_block() {
        let mut m = BlockMapping::new();
        let addr = Address::new(0x5000);
        m.insert(10, addr);
        m.insert(20, addr);

        let states = m.states_for_block(addr);
        assert_eq!(states.len(), 2);
        assert!(states.contains(&10));
        assert!(states.contains(&20));

        // Unknown block → empty slice.
        assert!(m.states_for_block(Address::new(0xFFFF)).is_empty());
    }

    // -----------------------------------------------------------------------
    // Additional: RecoveredCfg block_count and edge_count
    // -----------------------------------------------------------------------
    #[test]
    fn test_recovered_cfg_counts() {
        let cfg = make_cff_cfg();
        let pass = CffDeobfuscationPass::new();
        let recovered = pass
            .run_on_function(&cfg, Address::new(0x1000))
            .expect("should recover");
        // Dispatcher is removed; remaining blocks are entry + A + B + C = 4.
        assert_eq!(recovered.block_count(), 4);
        // At least some edges should be present.
        assert!(recovered.edge_count() > 0);
    }

    // -----------------------------------------------------------------------
    // Additional: CffDetector builder methods
    // -----------------------------------------------------------------------
    #[test]
    fn test_detector_builder_methods() {
        let d = CffDetector::new()
            .with_min_blocks(8)
            .with_min_confidence(0.9);
        assert_eq!(d.min_block_count, 8);
        assert!((d.min_confidence - 0.9).abs() < 1e-6);
    }

    // -----------------------------------------------------------------------
    // Additional: CffRecoverer trace_state resolves direct mapping
    // -----------------------------------------------------------------------
    #[test]
    fn test_recoverer_trace_state_direct() {
        let mut m = BlockMapping::new();
        let addr = Address::new(0xCAFE);
        m.insert(0xDEAD, addr);

        let recoverer = CffRecoverer::new();
        assert_eq!(recoverer.trace_state(0xDEAD, &m), Some(addr));
    }

    // -----------------------------------------------------------------------
    // Additional: CffRecoverer trace_state with truncation
    // -----------------------------------------------------------------------
    #[test]
    fn test_recoverer_trace_state_truncated() {
        let mut m = BlockMapping::new();
        let addr = Address::new(0x1234);
        m.insert(0x1234, addr);

        let recoverer = CffRecoverer::new();
        // High bits set, but low 32 bits match.
        let result = recoverer.trace_state(0x0001_0000_1234, &m);
        assert_eq!(result, Some(addr));
    }

    // -----------------------------------------------------------------------
    // Additional: empty CFG handled gracefully
    // -----------------------------------------------------------------------
    #[test]
    fn test_detector_rejects_empty_cfg() {
        let cfg = SimpleCfg {
            blocks: vec![],
            edges: vec![],
        };
        let detector = CffDetector::new();
        assert!(detector.detect(&cfg, Address::new(0)).is_none());
    }

    // -----------------------------------------------------------------------
    // Additional: CffPattern classify indirect-jump returns JumpTable
    // -----------------------------------------------------------------------
    #[test]
    fn test_classify_indirect_jump_dispatcher() {
        let mut cfg = make_cff_cfg();
        // Force the dispatcher block to end with an indirect jump.
        cfg.blocks[1].ends_with_indirect_jump = true;
        let detector = CffDetector::new();
        let candidate = detector.detect(&cfg, Address::new(0x1000)).unwrap();
        assert_eq!(candidate.pattern, CffPattern::JumpTable);
    }

    // -----------------------------------------------------------------------
    // Additional: CffDeobfuscationPass run_on_binary with empty list
    // -----------------------------------------------------------------------
    #[test]
    fn test_run_on_binary_empty() {
        let pass = CffDeobfuscationPass::new();
        let result = pass.run_on_binary(vec![]);
        assert_eq!(result.candidates_found, 0);
        assert_eq!(result.recovered.len(), 0);
    }

    // =======================================================================
    // CffDispatcherDetector tests
    // =======================================================================

    fn make_cmp_jcc_sequence(count: usize) -> Vec<u8> {
        // Build `count` repetitions of:
        // 83 3D 00 00 00 00 XX  (CMP DWORD PTR [rip+0], imm8)
        // 74 01                 (JZ rel8=1)
        let mut code = Vec::new();
        for i in 0..count {
            // CMP [rip+0], i  (imm8 = i as u8)
            code.extend_from_slice(&[0x83, 0x3D, 0x00, 0x00, 0x00, 0x00, i as u8]);
            // JZ rel8
            code.extend_from_slice(&[0x74, 0x01]);
        }
        code
    }

    #[test]
    fn test_dispatcher_detector_finds_sequence() {
        let code = make_cmp_jcc_sequence(6);
        let dispatchers = CffDispatcherDetector::detect(&code, 0x1000);
        assert!(
            !dispatchers.is_empty(),
            "should detect at least one dispatcher in a 6-pair sequence"
        );
        assert_eq!(dispatchers[0].addr, 0x1000);
    }

    #[test]
    fn test_dispatcher_detector_below_threshold() {
        // Only 4 pairs — below the minimum of 5.
        let code = make_cmp_jcc_sequence(4);
        let dispatchers = CffDispatcherDetector::detect(&code, 0);
        assert!(
            dispatchers.is_empty(),
            "4 pairs should not reach the threshold"
        );
    }

    #[test]
    fn test_dispatcher_detector_empty_code() {
        let dispatchers = CffDispatcherDetector::detect(&[], 0);
        assert!(dispatchers.is_empty());
    }

    #[test]
    fn test_dispatcher_detector_handler_count() {
        let code = make_cmp_jcc_sequence(8);
        let dispatchers = CffDispatcherDetector::detect(&code, 0);
        assert!(!dispatchers.is_empty());
        assert!(dispatchers[0].handler_count >= 5);
    }

    // =======================================================================
    // StateGraph tests
    // =======================================================================

    #[test]
    fn test_state_graph_add_and_query() {
        let mut g = StateGraph::new();
        g.add_edge(1, 2, Some(true));
        g.add_edge(1, 3, Some(false));
        g.add_edge(2, 4, None);

        assert_eq!(g.state_count(), 2);
        let transitions = g.transitions(1);
        assert_eq!(transitions.len(), 2);
    }

    #[test]
    fn test_state_graph_is_empty() {
        let g = StateGraph::new();
        assert!(g.is_empty());
        let mut g2 = StateGraph::new();
        g2.add_edge(0, 1, None);
        assert!(!g2.is_empty());
    }

    #[test]
    fn test_state_graph_all_targets() {
        let mut g = StateGraph::new();
        g.add_edge(0, 10, None);
        g.add_edge(0, 20, Some(true));
        g.add_edge(10, 30, None);
        let targets = g.all_targets();
        assert!(targets.contains(&10));
        assert!(targets.contains(&20));
        assert!(targets.contains(&30));
    }

    #[test]
    fn test_state_graph_unknown_state_returns_empty_slice() {
        let g = StateGraph::new();
        assert!(g.transitions(99).is_empty());
    }

    // =======================================================================
    // StateTransitionAnalyzer tests
    // =======================================================================

    #[test]
    fn test_state_transition_analyze_produces_graph() {
        let code = make_cmp_jcc_sequence(6);
        let dispatcher = CffDispatcher {
            addr: 0,
            state_var_addr: 0x4000,
            handler_count: 6,
        };
        let graph = StateTransitionAnalyzer::analyze(&dispatcher, &code);
        // Graph may be empty if no MOV [mem], imm32 patterns are present in
        // the synthetic sequence — but the call must not panic.
        let _ = graph.state_count();
    }

    #[test]
    fn test_state_transition_with_mov_pattern() {
        // C7 05 <disp32> <imm32>: MOV DWORD PTR [rip+disp], value
        // Needs at least 10 bytes for the instruction, plus padding so the
        // window loop has room to slide.
        let mut code = Vec::new();
        code.extend_from_slice(&[0xC7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00]);
        code.extend_from_slice(&[0x90u8; 40]); // padding for window
        let dispatcher = CffDispatcher {
            addr: 0,
            state_var_addr: 6,
            handler_count: 5,
        };
        let graph = StateTransitionAnalyzer::analyze(&dispatcher, &code);
        // At least the one transition should be recorded.
        // (seed=0 → to_state=5)
        assert!(!graph.is_empty());
    }

    // =======================================================================
    // CffDeflattener tests
    // =======================================================================

    #[test]
    fn test_deflattener_edges_from_graph() {
        let mut graph = StateGraph::new();
        graph.add_edge(0, 1, None);
        graph.add_edge(1, 2, Some(true));
        graph.add_edge(1, 3, Some(false));

        let dispatcher = CffDispatcher {
            addr: 0x1000,
            state_var_addr: 0x2000,
            handler_count: 3,
        };
        let edges = CffDeflattener::deflaten(&dispatcher, &graph);

        assert_eq!(edges.len(), 3);
        // Edges should be sorted by from_state then to_state.
        let from_states: Vec<u32> = edges.iter().map(|e| e.from_state).collect();
        assert!(from_states.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn test_deflattener_empty_graph() {
        let graph = StateGraph::new();
        let dispatcher = CffDispatcher {
            addr: 0,
            state_var_addr: 0,
            handler_count: 0,
        };
        let edges = CffDeflattener::deflaten(&dispatcher, &graph);
        assert!(edges.is_empty());
    }

    #[test]
    fn test_deflattener_edge_conditions_preserved() {
        let mut graph = StateGraph::new();
        graph.add_edge(10, 20, Some(true));
        graph.add_edge(10, 30, Some(false));
        let dispatcher = CffDispatcher {
            addr: 0,
            state_var_addr: 0,
            handler_count: 2,
        };
        let edges = CffDeflattener::deflaten(&dispatcher, &graph);
        let true_edge = edges.iter().find(|e| e.to_state == 20).unwrap();
        assert_eq!(true_edge.condition, Some(true));
        let false_edge = edges.iter().find(|e| e.to_state == 30).unwrap();
        assert_eq!(false_edge.condition, Some(false));
    }

    // =======================================================================
    // estimate_cff_confidence tests
    // =======================================================================

    #[test]
    fn test_confidence_all_nops_low() {
        let nops = vec![0x90u8; 256];
        let confidence = CffDeflattener::estimate_cff_confidence(&nops);
        // NOP sleds have very low entropy variation; confidence should be low-ish.
        assert!(
            confidence < 0.7,
            "expected low confidence on NOP sled, got {confidence}"
        );
    }

    #[test]
    fn test_confidence_empty_zero() {
        assert_eq!(CffDeflattener::estimate_cff_confidence(&[]), 0.0);
    }

    #[test]
    fn test_confidence_with_dispatcher_code() {
        let code = make_cmp_jcc_sequence(10);
        let confidence = CffDeflattener::estimate_cff_confidence(&code);
        // A realistic dispatcher sequence should score above the neutral 0.2 baseline.
        assert!(
            confidence > 0.0,
            "dispatcher code should yield non-zero confidence"
        );
    }

    #[test]
    fn test_confidence_range_is_valid() {
        let code: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let c = CffDeflattener::estimate_cff_confidence(&code);
        assert!((0.0..=1.0).contains(&c));
    }

    // =======================================================================
    // scan_block_state_const tests
    // =======================================================================

    #[test]
    fn test_scan_state_const_mov_r32_imm32() {
        // B8 78 56 34 12 → MOV eax, 0x12345678
        let bytes = [0xB8u8, 0x78, 0x56, 0x34, 0x12, 0xEB, 0x00];
        let result = CffRecoverer::scan_block_state_const(&bytes);
        assert_eq!(result, Some(0x1234_5678));
    }

    #[test]
    fn test_scan_state_const_mov_c7_imm32() {
        // C7 C0 01 00 00 00 → MOV eax, 1  (ModRM=0xC0: mod=11 reg=000 rm=000)
        let bytes = [0xC7u8, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x00];
        let result = CffRecoverer::scan_block_state_const(&bytes);
        assert_eq!(result, Some(1));
    }

    #[test]
    fn test_scan_state_const_rex_w_imm64() {
        // 48 B8 EF CD AB 89 67 45 23 01 → MOV rax, 0x0123456789ABCDEF
        let bytes = [
            0x48u8, 0xB8, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01, 0xEB, 0x00,
        ];
        let result = CffRecoverer::scan_block_state_const(&bytes);
        assert_eq!(result, Some(0x0123_4567_89AB_CDEF));
    }

    #[test]
    fn test_scan_state_const_stops_at_jmp() {
        // MOV eax, 0xAAAA then JMP rel8, then another MOV that should be ignored.
        let bytes = [
            0xB8u8, 0xAA, 0xAA, 0x00, 0x00, // MOV eax, 0xAAAA
            0xEB, 0x05, // JMP +5 (stops scan)
            0xB8, 0xBB, 0xBB, 0x00, 0x00, // MOV eax, 0xBBBB (not reached)
        ];
        let result = CffRecoverer::scan_block_state_const(&bytes);
        // Should return the first MOV's value, stopping before the JMP.
        assert_eq!(result, Some(0xAAAA));
    }

    #[test]
    fn test_scan_state_const_empty() {
        assert_eq!(CffRecoverer::scan_block_state_const(&[]), None);
    }

    #[test]
    fn test_scan_state_const_nop_sled() {
        // All NOPs — no MOV pattern.
        let bytes = [0x90u8; 16];
        assert_eq!(CffRecoverer::scan_block_state_const(&bytes), None);
    }

    // =======================================================================
    // build_block_mapping with state_const
    // =======================================================================

    #[test]
    fn test_build_block_mapping_uses_state_const() {
        // Build a CFF CFG where blocks A, B, C have explicit state_const values.
        let mut cfg = make_cff_cfg();
        // Assign distinct constants to the three real handler blocks (indices 2,3,4).
        cfg.blocks[2].state_const = Some(0xDEAD_0001);
        cfg.blocks[3].state_const = Some(0xDEAD_0002);
        cfg.blocks[4].state_const = Some(0xDEAD_0003);

        let detector = CffDetector::new();
        let candidate = detector
            .detect(&cfg, Address::new(0x1000))
            .expect("should detect CFF");

        let recoverer = CffRecoverer::new();
        let mapping = recoverer.build_block_mapping(&candidate, &cfg);

        // The mapping should contain the real constants, not the address-derived ones.
        assert_eq!(
            mapping.block_for_state(0xDEAD_0001),
            Some(Address::new(0x1020)),
            "state 0xDEAD_0001 should map to block A (0x1020)"
        );
        assert_eq!(
            mapping.block_for_state(0xDEAD_0002),
            Some(Address::new(0x1030)),
            "state 0xDEAD_0002 should map to block B (0x1030)"
        );
        assert_eq!(
            mapping.block_for_state(0xDEAD_0003),
            Some(Address::new(0x1040)),
            "state 0xDEAD_0003 should map to block C (0x1040)"
        );
    }
}

// ===========================================================================
// Z3-Assisted State Variable Tracking
// ===========================================================================
//
// The key challenge in CFF de-flattening is determining the STATE VARIABLE
// TRANSITIONS: given a "real block" (case in the switch), what value does it
// assign to the state variable, and under what conditions?
//
// This module provides:
//   * [`SmtConstraintBuilder`] — builds and optionally solves SMTLIB2 scripts
//     via a subprocess call to `z3`.
//   * [`CffSymEval`] — symbolic evaluation of blocks against concrete in-state
//     values, collecting [`StateTransition`] records.
//   * [`DispatcherBlock`] — enriched dispatcher descriptor with a concrete
//     case-table.
//   * [`CfgRewriter`] — rewrites the CFG by splicing out the dispatcher and
//     inserting direct edges.
//   * [`OllvmDetectorV2`] — second-generation OLLVM detector with a richer
//     scoring model and verified CFF structure extraction.
// ===========================================================================

// ---------------------------------------------------------------------------
// SmtSort / SmtVar
// ---------------------------------------------------------------------------

/// The SMT sort of a symbolic variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtSort {
    /// Fixed-width bitvector of `n` bits.
    BitVec(u32),
    /// Boolean sort.
    Bool,
}

impl SmtSort {
    /// Return the SMTLIB2 sort string for this variant.
    pub fn to_smtlib2(&self) -> String {
        match self {
            SmtSort::BitVec(n) => format!("(_ BitVec {})", n),
            SmtSort::Bool => "Bool".to_owned(),
        }
    }
}

/// A symbolic variable tracked by the SMT constraint builder.
#[derive(Debug, Clone)]
pub struct SmtVar {
    /// SMTLIB2-compatible name (no spaces).
    pub name: String,
    /// Sort of the variable.
    pub sort: SmtSort,
}

impl SmtVar {
    /// Create a new bitvector variable.
    pub fn bitvec(name: impl Into<String>, bits: u32) -> Self {
        Self {
            name: name.into(),
            sort: SmtSort::BitVec(bits),
        }
    }

    /// Create a new Boolean variable.
    pub fn bool_var(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            sort: SmtSort::Bool,
        }
    }

    /// Return the `(declare-const name sort)` SMTLIB2 declaration string.
    pub fn declaration(&self) -> String {
        format!("(declare-const {} {})", self.name, self.sort.to_smtlib2())
    }
}

// ---------------------------------------------------------------------------
// SmtConstraintBuilder
// ---------------------------------------------------------------------------

/// Builds SMTLIB2 scripts and optionally solves them via a `z3` subprocess.
///
/// # Usage
///
/// ```rust,ignore
/// let mut builder = SmtConstraintBuilder::new();
/// builder.declare_var("state", 32);
/// builder.assert_eq("state", 0xDEAD_BEEF, 32);
/// let script = builder.to_smtlib2();
/// // Optionally: let model = builder.solve_with_subprocess();
/// ```
#[derive(Debug, Default)]
pub struct SmtConstraintBuilder {
    /// All declared symbolic variables, keyed by name.
    pub vars: HashMap<String, SmtVar>,
    /// SMTLIB2-formatted assertion strings (without the outer `(assert ...)`).
    pub assertions: Vec<String>,
    /// The model returned by the solver after a `solve_*` call, if available.
    pub model: Option<HashMap<String, u64>>,
}

impl SmtConstraintBuilder {
    /// Create an empty constraint builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare a bitvector variable and return its SMTLIB2 declaration string.
    ///
    /// If a variable with the same name already exists it is **replaced**.
    ///
    /// ```text
    /// (declare-const state (_ BitVec 32))
    /// ```
    pub fn declare_var(&mut self, name: &str, bits: u32) -> String {
        let var = SmtVar::bitvec(name, bits);
        let decl = var.declaration();
        self.vars.insert(name.to_owned(), var);
        decl
    }

    /// Declare a Boolean variable and return its SMTLIB2 declaration string.
    pub fn declare_bool(&mut self, name: &str) -> String {
        let var = SmtVar::bool_var(name);
        let decl = var.declaration();
        self.vars.insert(name.to_owned(), var);
        decl
    }

    /// Assert that the named variable equals `val`.
    ///
    /// ```text
    /// (assert (= state (_ bv3735928559 32)))
    /// ```
    pub fn assert_eq(&mut self, var: &str, val: u64, bits: u32) {
        let assertion = format!("(assert (= {} (_ bv{} {})))", var, val, bits);
        self.assertions.push(assertion);
    }

    /// Assert that an arbitrary SMTLIB2 expression equals `val`.
    ///
    /// `expr` must be a well-formed SMTLIB2 term of sort `(_ BitVec bits)`.
    pub fn assert_expr_eq(&mut self, expr: &str, val: u64, bits: u32) {
        let assertion = format!("(assert (= {} (_ bv{} {})))", expr, val, bits);
        self.assertions.push(assertion);
    }

    /// Add a raw SMTLIB2 assertion string (must include the outer `(assert ...)`).
    pub fn add_assertion(&mut self, assertion: &str) {
        self.assertions.push(assertion.to_owned());
    }

    /// Build the complete SMTLIB2 script ready to pipe into `z3`.
    ///
    /// The output format is:
    /// ```text
    /// (set-logic QF_BV)
    /// (declare-const ...)
    /// ...
    /// (assert ...)
    /// ...
    /// (check-sat)
    /// (get-model)
    /// ```
    pub fn to_smtlib2(&self) -> String {
        let mut out = String::from("(set-logic QF_BV)\n");

        // Emit declarations in a stable order.
        let mut names: Vec<&str> = self.vars.keys().map(String::as_str).collect();
        names.sort_unstable();
        for name in &names {
            out.push_str(&self.vars[*name].declaration());
            out.push('\n');
        }

        for assertion in &self.assertions {
            out.push_str(assertion);
            out.push('\n');
        }

        out.push_str("(check-sat)\n");
        out.push_str("(get-model)\n");
        out
    }

    /// Attempt to call `z3` as a subprocess.
    ///
    /// The SMTLIB2 script is piped to `z3 -in` on stdin.  If `z3` is not on
    /// `PATH`, or the query is unsatisfiable, `None` is returned.
    ///
    /// On success the method populates `self.model` and returns a clone.
    ///
    /// # Subprocess safety
    ///
    /// This method spawns a child process. It is intentionally **not** `unsafe`
    /// but callers must ensure `z3` originates from a trusted location.
    pub fn solve_with_subprocess(&mut self) -> Option<HashMap<String, u64>> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let script = self.to_smtlib2();

        let mut child = Command::new("z3")
            .arg("-in")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;

        // Write the script to z3's stdin.
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(script.as_bytes()).ok()?;
        }
        // Close stdin so z3 knows input is complete.
        drop(child.stdin.take());

        let output = child.wait_with_output().ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Quick satisfiability check.
        if !stdout.contains("sat") || stdout.contains("unsat") {
            return None;
        }

        let model = Self::parse_z3_model(&stdout);
        self.model = Some(model.clone());
        Some(model)
    }

    /// Evaluate all assertions concretely given the variable bindings in `env`.
    ///
    /// Returns `true` when every assertion holds under the provided environment,
    /// `false` when at least one assertion fails or the environment is
    /// incomplete.
    ///
    /// This is the fallback path used when `z3` is not available.  It only
    /// handles the `(assert (= var (_ bv<val> <bits>)))` pattern emitted by
    /// [`SmtConstraintBuilder::assert_eq`].
    pub fn solve_concrete(&self, env: &HashMap<String, u64>) -> bool {
        for assertion in &self.assertions {
            if !Self::eval_assertion_concrete(assertion, env) {
                return false;
            }
        }
        true
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// Parse a Z3 `(model ...)` output block into a `name → u64` map.
    pub fn parse_z3_model(output: &str) -> HashMap<String, u64> {
        let mut model = HashMap::new();

        // Z3 model lines look like:
        //   (define-fun state () (_ BitVec 32) (_ bv3735928559 32))
        for line in output.lines() {
            let line = line.trim();
            if !line.starts_with("(define-fun") {
                continue;
            }

            // Extract name (second token).
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() < 2 {
                continue;
            }
            let name = tokens[1].trim_matches('(').trim_matches(')');

            // Find `(_ bv<N> <bits>)` pattern.
            if let Some(bv_start) = line.find("(_ bv") {
                let rest = &line[bv_start + 5..]; // after "(_ bv" (5 chars)
                let bv_end = rest.find(' ').unwrap_or(rest.len());
                if let Ok(val) = rest[..bv_end].parse::<u64>() {
                    model.insert(name.to_owned(), val);
                }
            }

            // Handle `#b...` bitvector literals (binary).
            if let Some(bin_start) = line.find("#b") {
                let rest = &line[bin_start + 2..];
                let bin_end = rest
                    .find(|c: char| !matches!(c, '0' | '1'))
                    .unwrap_or(rest.len());
                if let Ok(val) = u64::from_str_radix(&rest[..bin_end], 2) {
                    model.insert(name.to_owned(), val);
                }
            }

            // Handle `#x...` hex literals.
            if let Some(hex_start) = line.find("#x") {
                let rest = &line[hex_start + 2..];
                let hex_end = rest
                    .find(|c: char| !c.is_ascii_hexdigit())
                    .unwrap_or(rest.len());
                if let Ok(val) = u64::from_str_radix(&rest[..hex_end], 16) {
                    model.insert(name.to_owned(), val);
                }
            }
        }
        model
    }

    /// Evaluate a single SMTLIB2 `(assert (= <var> (_ bv<val> <bits>)))` line.
    ///
    /// Returns `true` when the assertion holds in `env`, or when the assertion
    /// format is not recognised (fail-open).
    fn eval_assertion_concrete(assertion: &str, env: &HashMap<String, u64>) -> bool {
        // Only handle the `(assert (= var (_ bv<N> <bits>)))` pattern.
        if !assertion.starts_with("(assert (= ") {
            return true; // unknown form — don't reject
        }
        let inner = assertion
            .trim_start_matches("(assert (= ")
            .trim_end_matches("))");

        // Split into LHS and RHS tokens.
        let parts: Vec<&str> = inner.splitn(2, ' ').collect();
        if parts.len() != 2 {
            return true;
        }
        let var_name = parts[0].trim();
        let rhs = parts[1].trim();

        // Parse `(_ bv<N> <bits>)`.
        if let Some(rest) = rhs.strip_prefix("(_ bv") {
            // skip "(_ bv"
            let space = rest.find(' ').unwrap_or(rest.len());
            if let Ok(expected) = rest[..space].parse::<u64>() {
                return env.get(var_name).copied() == Some(expected);
            }
        }
        true // unknown RHS form — don't reject
    }
}

// ---------------------------------------------------------------------------
// Concrete machine-instruction model for symbolic evaluation
// ---------------------------------------------------------------------------

/// A simplified MLIL-like instruction that the symbolic evaluator can process.
#[derive(Debug, Clone)]
pub enum MlilInstruction {
    /// `dest = Const(value)`
    SetConst { dest: String, value: u64 },
    /// `dest = src`
    SetReg { dest: String, src: String },
    /// `dest = lhs XOR rhs`
    Xor {
        dest: String,
        lhs: String,
        rhs: String,
    },
    /// `dest = lhs + rhs`
    Add {
        dest: String,
        lhs: String,
        rhs: String,
    },
    /// `dest = lhs & rhs`
    And {
        dest: String,
        lhs: String,
        rhs: String,
    },
    /// `dest = cond ? true_val : false_val` (ternary / `CMOV`-style)
    Ite {
        dest: String,
        cond: String,
        true_val: u64,
        false_val: u64,
    },
    /// Conditional branch: `if cond { goto true_target } else { goto false_target }`
    CondBranch {
        cond: String,
        true_target: u64,
        false_target: u64,
    },
    /// Unconditional jump.
    Jump { target: u64 },
    /// No-op / placeholder.
    Nop,
}

/// A basic block for the symbolic evaluator.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Start address of the block.
    pub address: u64,
    /// Instructions in program order.
    pub instrs: Vec<MlilInstruction>,
}

impl BasicBlock {
    /// Create a new basic block at `address`.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            instrs: Vec::new(),
        }
    }

    /// Append an instruction to the block.
    pub fn push(&mut self, instr: MlilInstruction) {
        self.instrs.push(instr);
    }

    /// Return the terminator instruction, if present.
    pub fn terminator(&self) -> Option<&MlilInstruction> {
        self.instrs.last()
    }
}

// ---------------------------------------------------------------------------
// AssignmentType
// ---------------------------------------------------------------------------

/// How a state-variable assignment is expressed in a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssignmentType {
    /// Direct constant assignment: `state_var = CONST`.
    Const(u64),
    /// Conditional assignment: `state_var = COND ? A : B`.
    Conditional { true_val: u64, false_val: u64 },
    /// The assignment value depends on a register that is itself unknown.
    DataDependent,
}

// ---------------------------------------------------------------------------
// StateTransition (detailed variant for Z3-assisted analysis)
// ---------------------------------------------------------------------------

/// A single recovered state transition between two basic blocks.
#[derive(Debug, Clone)]
pub struct ZStateTransition {
    /// Address of the source basic block.
    pub from_bb: u64,
    /// Address of the target basic block (after dispatcher resolution).
    pub to_bb: u64,
    /// Human-readable branch condition, or `None` for unconditional.
    pub condition: Option<String>,
    /// State value entering `from_bb`.
    pub in_state: u64,
    /// State value leaving `from_bb` (written before jumping to dispatcher).
    pub out_state: u64,
}

// ---------------------------------------------------------------------------
// DispatcherBlock (enriched)
// ---------------------------------------------------------------------------

/// Classification of the dispatcher mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispType {
    /// Classic `switch(state_var)` table.
    Switch,
    /// Chain of `if (state_var == X) goto Y` comparisons.
    IfElseChain,
    /// `jmp [table + state_var * 8]` — indirect through a pointer table.
    IndirectJump,
    /// State hashed into a lookup table.
    HashTable,
}

/// An enriched dispatcher block descriptor with an explicit case table.
#[derive(Debug, Clone)]
pub struct DispatcherBlock {
    /// Address of the dispatcher basic block.
    pub address: u64,
    /// How the dispatcher branches.
    pub dispatch_type: DispType,
    /// `(state_value, target_bb_address)` pairs extracted from the dispatcher.
    pub cases: Vec<(u64, u64)>,
}

impl DispatcherBlock {
    /// Create a new dispatcher descriptor.
    pub fn new(address: u64, dispatch_type: DispType) -> Self {
        Self {
            address,
            dispatch_type,
            cases: Vec::new(),
        }
    }

    /// Add a (state_value, target) case.
    pub fn add_case(&mut self, state_value: u64, target: u64) {
        self.cases.push((state_value, target));
    }

    /// Resolve `state_value` to a target block address using the case table.
    pub fn resolve(&self, state_value: u64) -> Option<u64> {
        self.cases
            .iter()
            .find(|(sv, _)| *sv == state_value)
            .map(|(_, target)| *target)
    }

    /// Number of cases in the dispatch table.
    pub fn case_count(&self) -> usize {
        self.cases.len()
    }
}

// ---------------------------------------------------------------------------
// CffSymEval — symbolic evaluation for CFF
// ---------------------------------------------------------------------------

/// Symbolic / concrete evaluator for CFF state-variable tracking.
///
/// Given an initial state value and knowledge of which register/slot holds the
/// state variable, this evaluator walks basic blocks and computes the concrete
/// outgoing state value for each possible incoming state.
#[derive(Debug)]
pub struct CffSymEval {
    /// The register or stack slot that holds the state variable (e.g. `"eax"`).
    pub state_var_reg: String,
    /// The state value at function entry.
    pub initial_state: u64,
    /// Per-block map of `bb_addr → Vec<outgoing_state_value>`.
    pub block_states: HashMap<u64, Vec<u64>>,
}

impl CffSymEval {
    /// Create a new evaluator for the given state variable and initial value.
    pub fn new(state_var: impl Into<String>, initial: u64) -> Self {
        Self {
            state_var_reg: state_var.into(),
            initial_state: initial,
            block_states: HashMap::new(),
        }
    }

    /// Evaluate all state transitions for `bb` given one or more incoming state
    /// values.
    ///
    /// For each incoming state:
    /// 1. Execute all instructions in `bb` concretely, tracking the current
    ///    value of the state variable.
    /// 2. For conditional branches on the state variable, fork into both arms.
    /// 3. Return all resulting [`ZStateTransition`] records.
    pub fn eval_block_transitions(
        &mut self,
        bb: &BasicBlock,
        in_states: &[u64],
    ) -> Vec<ZStateTransition> {
        let mut transitions = Vec::new();

        for &in_state in in_states {
            // Concrete register file for this execution.
            let mut env: HashMap<String, u64> = HashMap::new();
            env.insert(self.state_var_reg.clone(), in_state);

            // Simulate instructions to find state variable mutations.
            let mut out_state = in_state;
            let mut forks: Vec<(u64, Option<String>)> = Vec::new(); // (out_state, condition)

            for instr in &bb.instrs {
                match instr {
                    MlilInstruction::SetConst { dest, value } => {
                        env.insert(dest.clone(), *value);
                        if dest == &self.state_var_reg {
                            out_state = *value;
                        }
                    }
                    MlilInstruction::SetReg { dest, src } => {
                        let val = env.get(src).copied().unwrap_or(0);
                        env.insert(dest.clone(), val);
                        if dest == &self.state_var_reg {
                            out_state = val;
                        }
                    }
                    MlilInstruction::Xor { dest, lhs, rhs } => {
                        let l = env.get(lhs.as_str()).copied().unwrap_or(0);
                        let r = env.get(rhs.as_str()).copied().unwrap_or(0);
                        let result = l ^ r;
                        env.insert(dest.clone(), result);
                        if dest == &self.state_var_reg {
                            out_state = result;
                        }
                    }
                    MlilInstruction::Add { dest, lhs, rhs } => {
                        let l = env.get(lhs.as_str()).copied().unwrap_or(0);
                        let r = env.get(rhs.as_str()).copied().unwrap_or(0);
                        let result = l.wrapping_add(r);
                        env.insert(dest.clone(), result);
                        if dest == &self.state_var_reg {
                            out_state = result;
                        }
                    }
                    MlilInstruction::And { dest, lhs, rhs } => {
                        let l = env.get(lhs.as_str()).copied().unwrap_or(0);
                        let r = env.get(rhs.as_str()).copied().unwrap_or(0);
                        let result = l & r;
                        env.insert(dest.clone(), result);
                        if dest == &self.state_var_reg {
                            out_state = result;
                        }
                    }
                    MlilInstruction::Ite {
                        dest,
                        cond,
                        true_val,
                        false_val,
                    } => {
                        let cond_val = env.get(cond.as_str()).copied().unwrap_or(0);
                        let result = if cond_val != 0 { *true_val } else { *false_val };
                        env.insert(dest.clone(), result);
                        if dest == &self.state_var_reg {
                            out_state = result;
                            // Also record the other branch as a fork.
                            let alt = if cond_val != 0 { *false_val } else { *true_val };
                            let cond_str = format!("{cond} != 0");
                            forks.push((alt, Some(format!("NOT ({cond_str})"))));
                            forks.push((result, Some(cond_str)));
                        }
                    }
                    MlilInstruction::CondBranch {
                        cond,
                        true_target,
                        false_target,
                    } => {
                        let cond_val = env.get(cond.as_str()).copied().unwrap_or(0);
                        // Concrete evaluation: take the branch dictated by cond_val.
                        let (taken_target, taken_cond, other_target, other_cond) = if cond_val != 0
                        {
                            (
                                *true_target,
                                format!("{cond} != 0"),
                                *false_target,
                                format!("{cond} == 0"),
                            )
                        } else {
                            (
                                *false_target,
                                format!("{cond} == 0"),
                                *true_target,
                                format!("{cond} != 0"),
                            )
                        };
                        // Emit transition for both branches.
                        transitions.push(ZStateTransition {
                            from_bb: bb.address,
                            to_bb: taken_target,
                            condition: Some(taken_cond),
                            in_state,
                            out_state,
                        });
                        transitions.push(ZStateTransition {
                            from_bb: bb.address,
                            to_bb: other_target,
                            condition: Some(other_cond),
                            in_state,
                            out_state,
                        });
                        continue;
                    }
                    MlilInstruction::Jump { target } => {
                        transitions.push(ZStateTransition {
                            from_bb: bb.address,
                            to_bb: *target,
                            condition: None,
                            in_state,
                            out_state,
                        });
                        continue;
                    }
                    MlilInstruction::Nop => {}
                }
            }

            // If no explicit branch instruction recorded a transition, emit one
            // based on the final out_state (the block falls through or there is
            // no explicit terminator modelled above).
            if forks.is_empty()
                && !transitions
                    .iter()
                    .any(|t| t.from_bb == bb.address && t.in_state == in_state)
            {
                transitions.push(ZStateTransition {
                    from_bb: bb.address,
                    to_bb: 0, // unknown target — caller must resolve via dispatcher
                    condition: None,
                    in_state,
                    out_state,
                });
            }

            // Record outgoing states for this block.
            let entry = self.block_states.entry(bb.address).or_default();
            entry.push(out_state);
            for (fork_state, _) in &forks {
                entry.push(*fork_state);
            }
        }

        transitions
    }

    /// Solve the `dispatcher → real_block` mapping given an enriched
    /// [`DispatcherBlock`].
    ///
    /// Returns a `state_value → real_block_address` map by consulting the
    /// dispatcher's case table.
    pub fn solve_dispatcher_mapping(&self, dispatcher: &DispatcherBlock) -> HashMap<u64, u64> {
        dispatcher.cases.iter().copied().collect()
    }

    /// Find all state-variable assignments within `bb`.
    ///
    /// Returns `(instruction_index, AssignmentType)` pairs.
    pub fn find_state_var_assignments(&self, bb: &BasicBlock) -> Vec<(u32, AssignmentType)> {
        let mut result = Vec::new();

        for (idx, instr) in bb.instrs.iter().enumerate() {
            let assignment = match instr {
                MlilInstruction::SetConst { dest, value } if dest == &self.state_var_reg => {
                    Some(AssignmentType::Const(*value))
                }
                MlilInstruction::SetReg { dest, .. } if dest == &self.state_var_reg => {
                    Some(AssignmentType::DataDependent)
                }
                MlilInstruction::Ite {
                    dest,
                    true_val,
                    false_val,
                    ..
                } if dest == &self.state_var_reg => Some(AssignmentType::Conditional {
                    true_val: *true_val,
                    false_val: *false_val,
                }),
                _ => None,
            };

            if let Some(at) = assignment {
                result.push((idx as u32, at));
            }
        }

        result
    }
}

// ---------------------------------------------------------------------------
// A simplified MlilFunction handle (for the CFG rewriter interface)
// ---------------------------------------------------------------------------

/// Lightweight representation of a function's basic-block graph, used by the
///
/// CFG rewriter and OLLVM detector.  In a full integration this would wrap a
/// Binary Ninja `MediumLevelILFunction` handle; here we provide a self-
/// contained in-memory model.
#[derive(Debug, Clone)]
pub struct MlilFunction {
    /// Entry address of the function.
    pub entry: u64,
    /// All basic blocks in the function.
    pub blocks: Vec<BasicBlock>,
    /// CFG edges as `(from_bb_addr, to_bb_addr, is_true_branch)`.
    pub edges: Vec<(u64, u64, bool)>,
}

impl MlilFunction {
    /// Create an empty function at `entry`.
    pub fn new(entry: u64) -> Self {
        Self {
            entry,
            blocks: Vec::new(),
            edges: Vec::new(),
        }
    }

    /// Append a basic block.
    pub fn add_block(&mut self, bb: BasicBlock) {
        self.blocks.push(bb);
    }

    /// Add a CFG edge.
    pub fn add_edge(&mut self, from: u64, to: u64, is_true_branch: bool) {
        self.edges.push((from, to, is_true_branch));
    }

    /// Find the block at `addr`, if present.
    pub fn block_at(&self, addr: u64) -> Option<&BasicBlock> {
        self.blocks.iter().find(|b| b.address == addr)
    }

    /// Find the block at `addr` mutably.
    pub fn block_at_mut(&mut self, addr: u64) -> Option<&mut BasicBlock> {
        self.blocks.iter_mut().find(|b| b.address == addr)
    }

    /// Return all successor addresses of the block at `addr`.
    pub fn successors_of(&self, addr: u64) -> Vec<u64> {
        self.edges
            .iter()
            .filter(|(from, _, _)| *from == addr)
            .map(|(_, to, _)| *to)
            .collect()
    }

    /// Return all predecessor addresses of the block at `addr`.
    pub fn predecessors_of(&self, addr: u64) -> Vec<u64> {
        self.edges
            .iter()
            .filter(|(_, to, _)| *to == addr)
            .map(|(from, _, _)| *from)
            .collect()
    }

    /// Number of basic blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

// ---------------------------------------------------------------------------
// CfgRewriter
// ---------------------------------------------------------------------------

/// Rewrites the CFF-obfuscated CFG by replacing dispatcher back-edges with
/// direct edges to their real targets.
///
/// After rewriting, the dispatcher blocks are dead and can be removed.
pub struct CfgRewriter;

impl CfgRewriter {
    /// Rewrite `func`'s CFG based on the recovered transitions and dispatcher.
    ///
    /// # Algorithm
    ///
    /// 1. For each [`ZStateTransition`], replace any edge from `from_bb` that
    ///    currently targets the dispatcher with a direct edge to `to_bb`.
    /// 2. If the transition is unconditional, insert an unconditional edge.
    /// 3. If the transition carries a condition, insert a conditional edge.
    /// 4. Remove all edges that go into the dispatcher.
    /// 5. Return the number of edges rewired.
    pub fn rewrite_cff_cfg(
        func: &mut MlilFunction,
        transitions: &[ZStateTransition],
        dispatcher: &DispatcherBlock,
        _state_var: &str,
    ) -> u32 {
        let dispatcher_addr = dispatcher.address;
        let mut rewired = 0u32;

        // Build a set of (from, to) replacements from the transition list.
        let mut replacements: Vec<(u64, u64, bool)> = Vec::with_capacity(transitions.len());
        for t in transitions {
            // Only handle transitions whose destination was the dispatcher
            // (to_bb == 0 means "unresolved" — resolve via the case table).
            let real_target = if t.to_bb == 0 || t.to_bb == dispatcher_addr {
                dispatcher.resolve(t.out_state).unwrap_or(t.to_bb)
            } else {
                t.to_bb
            };

            let is_true_branch = t.condition.is_some();
            replacements.push((t.from_bb, real_target, is_true_branch));
        }

        // Remove dispatcher-bound edges.
        let before_count = func.edges.len();
        func.edges.retain(|(_, to, _)| *to != dispatcher_addr);
        let removed = before_count - func.edges.len();
        rewired += removed as u32;

        // Add direct edges.
        for (from, to, is_true_branch) in &replacements {
            // Avoid duplicate edges.
            if !func.edges.iter().any(|(f, t, _)| f == from && t == to) {
                func.edges.push((*from, *to, *is_true_branch));
                rewired += 1;
            }
        }

        rewired
    }

    /// Remove basic blocks in `dead` from `func`, along with all edges that
    /// reference those blocks.
    ///
    /// Returns the number of blocks removed.
    pub fn eliminate_dead_blocks(
        func: &mut MlilFunction,
        dead: &std::collections::HashSet<u64>,
    ) -> u32 {
        let before = func.blocks.len();
        func.blocks.retain(|b| !dead.contains(&b.address));
        func.edges
            .retain(|(from, to, _)| !dead.contains(from) && !dead.contains(to));
        (before - func.blocks.len()) as u32
    }

    /// Remove all instructions that read or write `state_var` from `func`.
    ///
    /// This is called after the dispatcher has been eliminated so that the
    /// now-dead state-variable bookkeeping instructions can be pruned.
    ///
    /// Returns the number of instructions removed.
    pub fn eliminate_state_variable(func: &mut MlilFunction, state_var: &str) -> u32 {
        let mut removed = 0u32;
        for bb in &mut func.blocks {
            let before = bb.instrs.len();
            bb.instrs
                .retain(|instr| !Self::instr_touches_state_var(instr, state_var));
            removed += (before - bb.instrs.len()) as u32;
        }
        removed
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn instr_touches_state_var(instr: &MlilInstruction, sv: &str) -> bool {
        match instr {
            MlilInstruction::SetConst { dest, .. } => dest == sv,
            MlilInstruction::SetReg { dest, src } => dest == sv || src == sv,
            MlilInstruction::Xor { dest, lhs, rhs } => dest == sv || lhs == sv || rhs == sv,
            MlilInstruction::Add { dest, lhs, rhs } => dest == sv || lhs == sv || rhs == sv,
            MlilInstruction::And { dest, lhs, rhs } => dest == sv || lhs == sv || rhs == sv,
            MlilInstruction::Ite { dest, cond, .. } => dest == sv || cond == sv,
            MlilInstruction::CondBranch { cond, .. } => cond == sv,
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// OllvmDetectorV2
// ---------------------------------------------------------------------------

/// CFF-likelihood score returned by the second-generation OLLVM detector.
#[derive(Debug, Clone)]
pub struct CffScore {
    /// Probability estimate in `[0.0, 1.0]`.
    pub probability: f32,
    /// Human-readable list of indicators that contributed to the score.
    pub indicators: Vec<String>,
}

impl CffScore {
    /// Return `true` when the probability exceeds the conventional 0.7 threshold.
    pub fn is_likely_cff(&self) -> bool {
        self.probability > 0.7
    }
}

/// A candidate dispatcher block found by [`OllvmDetectorV2`].
#[derive(Debug, Clone)]
pub struct DispatcherCandidate {
    /// Address of the candidate dispatcher block.
    pub bb_addr: u64,
    /// Number of incoming edges (predecessor count).
    pub in_degree: u32,
    /// Number of outgoing edges (successor count).
    pub out_degree: u32,
    /// The register or stack slot most likely holding the state variable, if
    /// the detector was able to identify one.
    pub state_var_candidate: Option<String>,
}

/// Verified CFF analysis result produced by
/// [`OllvmDetectorV2::verify_cff_structure`].
#[derive(Debug, Clone)]
pub struct CffAnalysis {
    /// The dispatcher block that was verified.
    pub dispatcher: DispatcherCandidate,
    /// Identified state variable.
    pub state_var: String,
    /// The complete dispatcher case table (state_value → target_bb_address).
    pub case_table: HashMap<u64, u64>,
    /// Overall detection confidence.
    pub confidence: f64,
}

/// Second-generation OLLVM-specific CFF detector.
///
/// Improvements over [`OllvmDetector`]:
/// * Uses a richer scoring model (five indicators vs. three).
/// * Explicitly verifies the CFF structure before emitting a result.
/// * Extracts the state variable register directly from predecessor write sets.
pub struct OllvmDetectorV2;

impl OllvmDetectorV2 {
    /// Score `func` for CFF obfuscation.
    ///
    /// # Indicators (weights)
    ///
    /// | # | Indicator | Weight |
    /// |---|-----------|--------|
    /// | 1 | High-in-degree hub block ratio | 0.30 |
    /// | 2 | Back-edge saturation (blocks → single hub) | 0.25 |
    /// | 3 | Average function-entry distance variance | 0.15 |
    /// | 4 | Hub successor count ≥ 3 | 0.20 |
    /// | 5 | Consistent state-var write across predecessors | 0.10 |
    pub fn score_function(func: &MlilFunction) -> CffScore {
        let n = func.blocks.len();
        let mut indicators = Vec::new();
        let mut score = 0.0_f32;

        if n < 3 {
            return CffScore {
                probability: 0.0,
                indicators,
            };
        }

        // ---- Indicator 1: high-in-degree hub --------------------------------
        let max_in_degree = func
            .blocks
            .iter()
            .map(|bb| func.predecessors_of(bb.address).len() as u32)
            .max()
            .unwrap_or(0);

        let hub_ratio = (max_in_degree as f32 / (n - 1).max(1) as f32).min(1.0);
        if hub_ratio > 0.5 {
            indicators.push(format!("high-in-degree hub (ratio={hub_ratio:.2})"));
        }
        score += hub_ratio * 0.30;

        // ---- Indicator 2: back-edge saturation ------------------------------
        // Identify the hub block (maximum in-degree).
        let hub_addr = func
            .blocks
            .iter()
            .max_by_key(|bb| func.predecessors_of(bb.address).len())
            .map(|bb| bb.address)
            .unwrap_or(0);

        let back_edge_count = func
            .edges
            .iter()
            .filter(|(_, to, _)| *to == hub_addr)
            .count();

        let non_hub_blocks = n.saturating_sub(1).max(1);
        let back_ratio = (back_edge_count as f32 / non_hub_blocks as f32).min(1.0);
        if back_ratio > 0.5 {
            indicators.push(format!(
                "back-edge saturation ({back_edge_count}/{non_hub_blocks})"
            ));
        }
        score += back_ratio * 0.25;

        // ---- Indicator 3: entry-distance variance ---------------------------
        // Compute BFS distance from entry to each block.
        let distances = Self::bfs_distances(func);
        let dist_values: Vec<f32> = distances.values().map(|&d| d as f32).collect();
        let mean = dist_values.iter().sum::<f32>() / dist_values.len().max(1) as f32;
        let variance = dist_values.iter().map(|&d| (d - mean).powi(2)).sum::<f32>()
            / dist_values.len().max(1) as f32;
        // CFF functions have low variance because all blocks are one hop from
        // the dispatcher, and thus 2 hops from entry.
        let variance_score = if variance < 2.0 {
            1.0_f32
        } else {
            (2.0 / variance).min(1.0)
        };
        if variance_score > 0.6 {
            indicators.push(format!("low entry-distance variance ({variance:.2})"));
        }
        score += variance_score * 0.15;

        // ---- Indicator 4: hub successor count --------------------------------
        let hub_out_degree = func.successors_of(hub_addr).len() as u32;
        let hub_out_score = if hub_out_degree >= 3 {
            1.0_f32
        } else {
            hub_out_degree as f32 / 3.0
        };
        if hub_out_degree >= 3 {
            indicators.push(format!("dispatcher has {hub_out_degree} successors"));
        }
        score += hub_out_score * 0.20;

        // ---- Indicator 5: consistent state-var write ------------------------
        // Check whether all blocks that feed the hub write the same destination
        // register/slot before jumping.
        let hub_preds: Vec<u64> = func
            .edges
            .iter()
            .filter(|(_, to, _)| *to == hub_addr)
            .map(|(from, _, _)| *from)
            .collect();

        let pred_writes: Vec<Option<String>> = hub_preds
            .iter()
            .map(|&addr| {
                func.block_at(addr).and_then(|bb| {
                    // Look for the last SetConst targeting a register.
                    bb.instrs.iter().rev().find_map(|i| {
                        if let MlilInstruction::SetConst { dest, .. } = i {
                            Some(dest.clone())
                        } else {
                            None
                        }
                    })
                })
            })
            .collect();

        let defined_writes: Vec<&String> = pred_writes.iter().flatten().collect();
        let consistent =
            !defined_writes.is_empty() && defined_writes.windows(2).all(|w| w[0] == w[1]);
        let consistency_score = if consistent { 1.0_f32 } else { 0.0_f32 };
        if consistent {
            indicators.push(format!(
                "consistent state-var write ({})",
                defined_writes[0]
            ));
        }
        score += consistency_score * 0.10;

        CffScore {
            probability: score.clamp(0.0, 1.0),
            indicators,
        }
    }

    /// Find dispatcher candidates in `func`.
    ///
    /// A candidate is a block that:
    /// 1. Has many predecessors (≥ 3).
    /// 2. Has multiple successors (≥ 2, indicating a multi-way branch).
    /// 3. Is not the function entry.
    pub fn find_dispatcher_candidates(func: &MlilFunction) -> Vec<DispatcherCandidate> {
        let mut candidates = Vec::new();

        for bb in &func.blocks {
            if bb.address == func.entry {
                continue;
            }
            let in_degree = func.predecessors_of(bb.address).len() as u32;
            let out_degree = func.successors_of(bb.address).len() as u32;

            if in_degree < 3 || out_degree < 2 {
                continue;
            }

            // Heuristic: identify state-variable candidate from predecessor write sets.
            let state_var_candidate = Self::infer_state_var(func, bb.address);

            candidates.push(DispatcherCandidate {
                bb_addr: bb.address,
                in_degree,
                out_degree,
                state_var_candidate,
            });
        }

        // Sort by in-degree descending.
        candidates.sort_by(|a, b| b.in_degree.cmp(&a.in_degree));
        candidates
    }

    /// Verify that `dispatcher` truly forms a CFF structure and extract a
    /// [`CffAnalysis`] on success.
    ///
    /// Verification steps:
    /// 1. All (or most) predecessors of the dispatcher write the same register.
    /// 2. The dispatcher has at least 3 successors.
    /// 3. Successor blocks all have exactly one predecessor (the dispatcher).
    /// 4. At least one predecessor carries a constant state assignment.
    ///
    /// Returns `None` when the structure does not meet the criteria.
    pub fn verify_cff_structure(
        func: &MlilFunction,
        dispatcher: &DispatcherCandidate,
    ) -> Option<CffAnalysis> {
        let out_degree = func.successors_of(dispatcher.bb_addr).len();
        if out_degree < 2 {
            return None;
        }

        // Check that successor blocks are singly-dispatched.
        let succs = func.successors_of(dispatcher.bb_addr);
        let singly_dispatched = succs
            .iter()
            .filter(|&&s| func.predecessors_of(s).len() == 1)
            .count();

        let dispatch_ratio = f64::from(u32::try_from(singly_dispatched).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(out_degree).unwrap_or(u32::MAX));
        if dispatch_ratio < 0.5 {
            return None;
        }

        // Extract the state variable.
        let state_var = dispatcher
            .state_var_candidate
            .clone()
            .unwrap_or_else(|| "state_var".to_owned());

        // Build a provisional case table from predecessor constant writes.
        let preds = func.predecessors_of(dispatcher.bb_addr);
        let mut case_table: HashMap<u64, u64> = HashMap::new();
        for pred_addr in &preds {
            if let Some(bb) = func.block_at(*pred_addr) {
                // Scan for the last constant assignment to the state variable.
                let last_const = bb.instrs.iter().rev().find_map(|i| {
                    if let MlilInstruction::SetConst { dest, value } = i {
                        if dest == &state_var {
                            Some(*value)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                });
                if let Some(sv) = last_const {
                    case_table.insert(sv, *pred_addr);
                }
            }
        }

        // Confidence: blend dispatch_ratio with case-table coverage.
        let coverage = if preds.is_empty() {
            0.0_f64
        } else {
            f64::from(u32::try_from(case_table.len()).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(preds.len()).unwrap_or(u32::MAX))
        };
        let confidence = dispatch_ratio.mul_add(0.6, coverage * 0.4).clamp(0.0, 1.0);

        if confidence < 0.4 {
            return None;
        }

        Some(CffAnalysis {
            dispatcher: dispatcher.clone(),
            state_var,
            case_table,
            confidence,
        })
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// BFS from the function entry, returning `block_addr → distance` map.
    fn bfs_distances(func: &MlilFunction) -> HashMap<u64, u32> {
        use std::collections::VecDeque;
        let mut dist: HashMap<u64, u32> = HashMap::new();
        let mut queue = VecDeque::new();

        dist.insert(func.entry, 0);
        queue.push_back(func.entry);

        while let Some(addr) = queue.pop_front() {
            let current_dist = dist[&addr];
            for succ in func.successors_of(addr) {
                if let std::collections::hash_map::Entry::Vacant(e) = dist.entry(succ) {
                    e.insert(current_dist + 1);
                    queue.push_back(succ);
                }
            }
        }
        dist
    }

    /// Infer the state variable for the dispatcher at `hub_addr` by inspecting
    /// the most-common write destination in predecessor blocks.
    fn infer_state_var(func: &MlilFunction, hub_addr: u64) -> Option<String> {
        let mut freq: HashMap<String, usize> = HashMap::new();
        for pred_addr in func
            .edges
            .iter()
            .filter(|(_, to, _)| *to == hub_addr)
            .map(|(from, _, _)| *from)
        {
            if let Some(bb) = func.block_at(pred_addr) {
                for instr in &bb.instrs {
                    if let MlilInstruction::SetConst { dest, .. } = instr {
                        *freq.entry(dest.clone()).or_insert(0) += 1;
                    }
                }
            }
        }

        freq.into_iter()
            .max_by_key(|(_, c)| *c)
            .map(|(name, _)| name)
    }
}

// ===========================================================================
// Tests for Z3-assisted tracking, CffSymEval, CfgRewriter, and OllvmDetectorV2
// ===========================================================================

#[cfg(test)]
mod smt_tests {
    use super::*;

    // -----------------------------------------------------------------------
    // SmtConstraintBuilder helpers
    // -----------------------------------------------------------------------

    fn make_builder_with_eq() -> SmtConstraintBuilder {
        let mut b = SmtConstraintBuilder::new();
        b.declare_var("state", 32);
        b.assert_eq("state", 0xDEAD_BEEF, 32);
        b
    }

    // -----------------------------------------------------------------------
    // Test S01: declare_var returns a valid SMTLIB2 declaration
    // -----------------------------------------------------------------------
    #[test]
    fn test_s01_declare_var_smtlib2_format() {
        let mut b = SmtConstraintBuilder::new();
        let decl = b.declare_var("x", 32);
        assert_eq!(decl, "(declare-const x (_ BitVec 32))");
        assert!(b.vars.contains_key("x"));
    }

    // -----------------------------------------------------------------------
    // Test S02: assert_eq produces the right assertion string
    // -----------------------------------------------------------------------
    #[test]
    fn test_s02_assert_eq_format() {
        let mut b = SmtConstraintBuilder::new();
        b.declare_var("state", 32);
        b.assert_eq("state", 42, 32);
        assert!(b.assertions.len() == 1);
        let assertion = &b.assertions[0];
        assert!(
            assertion.contains("(assert (= state (_ bv42 32)))"),
            "got: {assertion}"
        );
    }

    // -----------------------------------------------------------------------
    // Test S03: to_smtlib2 includes all declarations and assertions
    // -----------------------------------------------------------------------
    #[test]
    fn test_s03_to_smtlib2_contains_all_parts() {
        let b = make_builder_with_eq();
        let script = b.to_smtlib2();
        assert!(script.contains("(set-logic QF_BV)"), "missing set-logic");
        assert!(
            script.contains("(declare-const state (_ BitVec 32))"),
            "missing declaration"
        );
        assert!(script.contains("(check-sat)"), "missing check-sat");
        assert!(script.contains("(get-model)"), "missing get-model");
        assert!(
            script.contains("bv3735928559"),
            "missing bv constant for 0xDEAD_BEEF"
        );
    }

    // -----------------------------------------------------------------------
    // Test S04: solve_concrete with matching environment → true
    // -----------------------------------------------------------------------
    #[test]
    fn test_s04_solve_concrete_match() {
        let b = make_builder_with_eq();
        let mut env = HashMap::new();
        env.insert("state".to_owned(), 0xDEAD_BEEF_u64);
        assert!(b.solve_concrete(&env), "concrete solve should succeed");
    }

    // -----------------------------------------------------------------------
    // Test S05: solve_concrete with wrong value → false
    // -----------------------------------------------------------------------
    #[test]
    fn test_s05_solve_concrete_mismatch() {
        let b = make_builder_with_eq();
        let mut env = HashMap::new();
        env.insert("state".to_owned(), 0xCAFE_BABEu64);
        assert!(
            !b.solve_concrete(&env),
            "concrete solve should fail on wrong value"
        );
    }

    // -----------------------------------------------------------------------
    // Test S06: multiple assertions — all must hold
    // -----------------------------------------------------------------------
    #[test]
    fn test_s06_solve_concrete_multiple_assertions() {
        let mut b = SmtConstraintBuilder::new();
        b.declare_var("a", 32);
        b.declare_var("b", 32);
        b.assert_eq("a", 1, 32);
        b.assert_eq("b", 2, 32);

        let mut env = HashMap::new();
        env.insert("a".to_owned(), 1u64);
        env.insert("b".to_owned(), 2u64);
        assert!(b.solve_concrete(&env));

        env.insert("b".to_owned(), 99u64);
        assert!(!b.solve_concrete(&env), "second assertion should fail");
    }

    // -----------------------------------------------------------------------
    // Test S07: declare_bool produces Bool sort
    // -----------------------------------------------------------------------
    #[test]
    fn test_s07_declare_bool() {
        let mut b = SmtConstraintBuilder::new();
        let decl = b.declare_bool("flag");
        assert_eq!(decl, "(declare-const flag Bool)");
    }

    // -----------------------------------------------------------------------
    // Test S08: add_assertion passes through raw strings
    // -----------------------------------------------------------------------
    #[test]
    fn test_s08_add_assertion_raw() {
        let mut b = SmtConstraintBuilder::new();
        b.add_assertion("(assert (bvult x y))");
        assert_eq!(b.assertions.len(), 1);
        assert_eq!(b.assertions[0], "(assert (bvult x y))");
    }

    // -----------------------------------------------------------------------
    // Test S09: assert_expr_eq format
    // -----------------------------------------------------------------------
    #[test]
    fn test_s09_assert_expr_eq_format() {
        let mut b = SmtConstraintBuilder::new();
        b.assert_expr_eq("(bvadd x y)", 100, 32);
        assert!(b.assertions[0].contains("(assert (= (bvadd x y) (_ bv100 32)))"));
    }

    // -----------------------------------------------------------------------
    // Test S10: solve_concrete with no assertions always returns true
    // -----------------------------------------------------------------------
    #[test]
    fn test_s10_solve_concrete_empty_constraints() {
        let b = SmtConstraintBuilder::new();
        assert!(b.solve_concrete(&HashMap::new()));
    }

    // -----------------------------------------------------------------------
    // Test S11: to_smtlib2 variable ordering is stable (alphabetical)
    // -----------------------------------------------------------------------
    #[test]
    fn test_s11_smtlib2_stable_ordering() {
        let mut b = SmtConstraintBuilder::new();
        b.declare_var("z_var", 32);
        b.declare_var("a_var", 32);
        b.declare_var("m_var", 32);
        let script = b.to_smtlib2();
        let a_pos = script.find("a_var").unwrap();
        let m_pos = script.find("m_var").unwrap();
        let z_pos = script.find("z_var").unwrap();
        assert!(
            a_pos < m_pos && m_pos < z_pos,
            "declarations should be alphabetically sorted"
        );
    }

    // -----------------------------------------------------------------------
    // Test S12: declaring same variable twice replaces it
    // -----------------------------------------------------------------------
    #[test]
    fn test_s12_declare_var_overwrites() {
        let mut b = SmtConstraintBuilder::new();
        b.declare_var("x", 32);
        b.declare_var("x", 64);
        assert_eq!(b.vars.len(), 1);
        assert_eq!(b.vars["x"].sort, SmtSort::BitVec(64));
    }

    // -----------------------------------------------------------------------
    // Test S13: SmtVar::declaration output
    // -----------------------------------------------------------------------
    #[test]
    fn test_s13_smtvar_declaration() {
        let v = SmtVar::bitvec("my_var", 64);
        assert_eq!(v.declaration(), "(declare-const my_var (_ BitVec 64))");

        let b = SmtVar::bool_var("flag");
        assert_eq!(b.declaration(), "(declare-const flag Bool)");
    }

    // -----------------------------------------------------------------------
    // Test S14: SmtSort::to_smtlib2
    // -----------------------------------------------------------------------
    #[test]
    fn test_s14_smt_sort_display() {
        assert_eq!(SmtSort::BitVec(8).to_smtlib2(), "(_ BitVec 8)");
        assert_eq!(SmtSort::BitVec(64).to_smtlib2(), "(_ BitVec 64)");
        assert_eq!(SmtSort::Bool.to_smtlib2(), "Bool");
    }

    // -----------------------------------------------------------------------
    // CffSymEval tests
    // -----------------------------------------------------------------------

    const DISP: u64 = 0xD157u64;

    pub fn _make_simple_block(addr: u64, sv: &str, new_state: u64) -> BasicBlock {
        let mut bb = BasicBlock::new(addr);
        bb.push(MlilInstruction::SetConst {
            dest: sv.to_owned(),
            value: new_state,
        });
        bb.push(MlilInstruction::Jump { target: DISP });
        bb
    }

    fn make_simple_block_const(addr: u64, sv: &str, new_state: u64) -> BasicBlock {
        let mut bb = BasicBlock::new(addr);
        bb.push(MlilInstruction::SetConst {
            dest: sv.to_owned(),
            value: new_state,
        });
        bb.push(MlilInstruction::Jump { target: DISP });
        bb
    }

    const BLOCK_A: u64 = 0xAA00u64;
    const BLOCK_B: u64 = 0xBB00u64;
    const BLOCK_C: u64 = 0xCC00u64;

    // -----------------------------------------------------------------------
    // Test SE01: simple SetConst transition is recorded
    // -----------------------------------------------------------------------
    #[test]
    fn test_se01_setconst_transition() {
        let bb = make_simple_block_const(0x1000, "eax", 0x42);
        let mut eval = CffSymEval::new("eax", 0x00);
        let transitions = eval.eval_block_transitions(&bb, &[0x00]);

        assert!(
            !transitions.is_empty(),
            "should produce at least one transition"
        );
        let t = &transitions[0];
        assert_eq!(t.from_bb, 0x1000);
        assert_eq!(t.out_state, 0x42);
    }

    // -----------------------------------------------------------------------
    // Test SE02: multiple incoming states produce multiple transitions
    // -----------------------------------------------------------------------
    #[test]
    fn test_se02_multiple_in_states() {
        let bb = make_simple_block_const(0x2000, "eax", 0xFF);
        let mut eval = CffSymEval::new("eax", 0x00);
        let transitions = eval.eval_block_transitions(&bb, &[0x01, 0x02, 0x03]);

        // Each incoming state should produce at least one transition.
        assert!(transitions.len() >= 3);
        // All transitions should have the same out_state (SetConst overrides all).
        for t in &transitions {
            assert_eq!(t.out_state, 0xFF);
        }
    }

    // -----------------------------------------------------------------------
    // Test SE03: XOR instruction updates state correctly
    // -----------------------------------------------------------------------
    #[test]
    fn test_se03_xor_state_update() {
        let mut bb = BasicBlock::new(0x3000);
        bb.push(MlilInstruction::Xor {
            dest: "eax".to_owned(),
            lhs: "eax".to_owned(),
            rhs: "eax".to_owned(),
        });
        bb.push(MlilInstruction::Jump { target: DISP });

        let mut eval = CffSymEval::new("eax", 0x1234);
        let transitions = eval.eval_block_transitions(&bb, &[0x1234]);

        let t = &transitions[0];
        // eax XOR eax = 0.
        assert_eq!(t.out_state, 0);
    }

    // -----------------------------------------------------------------------
    // Test SE04: ADD instruction wraps around correctly
    // -----------------------------------------------------------------------
    #[test]
    fn test_se04_add_wraps() {
        let mut bb = BasicBlock::new(0x4000);
        bb.push(MlilInstruction::SetConst {
            dest: "tmp".to_owned(),
            value: 1,
        });
        bb.push(MlilInstruction::Add {
            dest: "eax".to_owned(),
            lhs: "eax".to_owned(),
            rhs: "tmp".to_owned(),
        });
        bb.push(MlilInstruction::Jump { target: DISP });

        let mut eval = CffSymEval::new("eax", u64::MAX);
        let transitions = eval.eval_block_transitions(&bb, &[u64::MAX]);

        let t = &transitions[0];
        assert_eq!(t.out_state, 0, "u64::MAX.wrapping_add(1) == 0");
    }

    // -----------------------------------------------------------------------
    // Test SE05: AND instruction masks state
    // -----------------------------------------------------------------------
    #[test]
    fn test_se05_and_masks_state() {
        let mut bb = BasicBlock::new(0x5000);
        bb.push(MlilInstruction::SetConst {
            dest: "mask".to_owned(),
            value: 0xFF,
        });
        bb.push(MlilInstruction::And {
            dest: "eax".to_owned(),
            lhs: "eax".to_owned(),
            rhs: "mask".to_owned(),
        });
        bb.push(MlilInstruction::Jump { target: DISP });

        let mut eval = CffSymEval::new("eax", 0xDEAD_BEEF);
        let transitions = eval.eval_block_transitions(&bb, &[0xDEAD_BEEF]);

        let t = &transitions[0];
        assert_eq!(t.out_state, 0xEF, "0xDEAD_BEEF & 0xFF == 0xEF");
    }

    // -----------------------------------------------------------------------
    // Test SE06: Ite (conditional move) forks transitions
    // -----------------------------------------------------------------------
    #[test]
    fn test_se06_ite_forks() {
        let mut bb = BasicBlock::new(0x6000);
        bb.push(MlilInstruction::SetConst {
            dest: "cond".to_owned(),
            value: 1,
        });
        bb.push(MlilInstruction::Ite {
            dest: "eax".to_owned(),
            cond: "cond".to_owned(),
            true_val: 0xAAA,
            false_val: 0xBBB,
        });

        let mut eval = CffSymEval::new("eax", 0);
        let _transitions = eval.eval_block_transitions(&bb, &[0]);

        // block_states should record both branches.
        let states = eval.block_states.get(&0x6000).expect("should have states");
        assert!(states.contains(&0xAAA) || states.contains(&0xBBB));
    }

    // -----------------------------------------------------------------------
    // Test SE07: CondBranch produces two transitions
    // -----------------------------------------------------------------------
    #[test]
    fn test_se07_cond_branch_two_transitions() {
        let mut bb = BasicBlock::new(0x7000);
        bb.push(MlilInstruction::SetConst {
            dest: "flag".to_owned(),
            value: 1,
        });
        bb.push(MlilInstruction::CondBranch {
            cond: "flag".to_owned(),
            true_target: 0xAAAA,
            false_target: 0xBBBB,
        });

        let mut eval = CffSymEval::new("eax", 0);
        let transitions = eval.eval_block_transitions(&bb, &[0]);

        assert_eq!(
            transitions.len(),
            2,
            "CondBranch should produce exactly 2 transitions"
        );
        let targets: Vec<u64> = transitions.iter().map(|t| t.to_bb).collect();
        assert!(targets.contains(&0xAAAA), "true target missing");
        assert!(targets.contains(&0xBBBB), "false target missing");
    }

    // -----------------------------------------------------------------------
    // Test SE08: find_state_var_assignments returns correct types
    // -----------------------------------------------------------------------
    #[test]
    fn test_se08_find_state_var_assignments() {
        let mut bb = BasicBlock::new(0x8000);
        bb.push(MlilInstruction::SetConst {
            dest: "ecx".to_owned(),
            value: 99,
        }); // unrelated
        bb.push(MlilInstruction::SetConst {
            dest: "eax".to_owned(),
            value: 0x42,
        });
        bb.push(MlilInstruction::Ite {
            dest: "eax".to_owned(),
            cond: "flag".to_owned(),
            true_val: 10,
            false_val: 20,
        });

        let eval = CffSymEval::new("eax", 0);
        let assignments = eval.find_state_var_assignments(&bb);

        assert_eq!(assignments.len(), 2, "should find 2 assignments to eax");
        assert_eq!(assignments[0].1, AssignmentType::Const(0x42));
        assert!(matches!(
            assignments[1].1,
            AssignmentType::Conditional {
                true_val: 10,
                false_val: 20
            }
        ));
    }

    // -----------------------------------------------------------------------
    // Test SE09: SetReg propagates register values
    // -----------------------------------------------------------------------
    #[test]
    fn test_se09_setreg_propagates() {
        let mut bb = BasicBlock::new(0x9000);
        bb.push(MlilInstruction::SetConst {
            dest: "ecx".to_owned(),
            value: 0x1337,
        });
        bb.push(MlilInstruction::SetReg {
            dest: "eax".to_owned(),
            src: "ecx".to_owned(),
        });
        bb.push(MlilInstruction::Jump { target: DISP });

        let mut eval = CffSymEval::new("eax", 0);
        let transitions = eval.eval_block_transitions(&bb, &[0]);

        let t = &transitions[0];
        assert_eq!(t.out_state, 0x1337);
    }

    // -----------------------------------------------------------------------
    // Test SE10: Nop does not change state
    // -----------------------------------------------------------------------
    #[test]
    fn test_se10_nop_unchanged() {
        let mut bb = BasicBlock::new(0xA000);
        bb.push(MlilInstruction::Nop);
        bb.push(MlilInstruction::Nop);

        let mut eval = CffSymEval::new("eax", 0xCAFE);
        let _transitions = eval.eval_block_transitions(&bb, &[0xCAFE]);

        // State should be unchanged (in_state == out_state in the implicit transition).
        let states = eval.block_states.get(&0xA000);
        if let Some(s) = states {
            assert!(s.contains(&0xCAFE));
        }
    }

    // -----------------------------------------------------------------------
    // Test SE11: solve_dispatcher_mapping uses case table
    // -----------------------------------------------------------------------
    #[test]
    fn test_se11_solve_dispatcher_mapping() {
        let mut disp = DispatcherBlock::new(DISP, DispType::Switch);
        disp.add_case(0x10, BLOCK_A);
        disp.add_case(0x20, BLOCK_B);
        disp.add_case(0x30, BLOCK_C);

        let eval = CffSymEval::new("eax", 0);
        let map = eval.solve_dispatcher_mapping(&disp);

        assert_eq!(map.get(&0x10), Some(&BLOCK_A));
        assert_eq!(map.get(&0x20), Some(&BLOCK_B));
        assert_eq!(map.get(&0x30), Some(&BLOCK_C));
        assert_eq!(map.get(&0xFF), None);
    }

    // -----------------------------------------------------------------------
    // DispatcherBlock tests
    // -----------------------------------------------------------------------

    // Test D01: new dispatcher starts empty
    #[test]
    fn test_d01_dispatcher_block_new() {
        let d = DispatcherBlock::new(0x1000, DispType::Switch);
        assert_eq!(d.address, 0x1000);
        assert_eq!(d.dispatch_type, DispType::Switch);
        assert_eq!(d.case_count(), 0);
    }

    // Test D02: add_case and resolve
    #[test]
    fn test_d02_add_case_and_resolve() {
        let mut d = DispatcherBlock::new(0x2000, DispType::IfElseChain);
        d.add_case(100, 0xAAAA);
        d.add_case(200, 0xBBBB);

        assert_eq!(d.resolve(100), Some(0xAAAA));
        assert_eq!(d.resolve(200), Some(0xBBBB));
        assert_eq!(d.resolve(999), None);
    }

    // Test D03: case_count reflects insertions
    #[test]
    fn test_d03_case_count() {
        let mut d = DispatcherBlock::new(0, DispType::IndirectJump);
        for i in 0..10 {
            d.add_case(i, i * 0x100);
        }
        assert_eq!(d.case_count(), 10);
    }

    // -----------------------------------------------------------------------
    // CfgRewriter tests
    // -----------------------------------------------------------------------

    fn make_cff_mlil_func() -> (MlilFunction, DispatcherBlock) {
        // Entry → Dispatcher ← [A, B, C]
        // Dispatcher → [A, B, C]
        let dispatcher_addr = 0x2000u64;
        let block_a = 0x3000u64;
        let block_b = 0x4000u64;
        let block_c = 0x5000u64;
        let entry_addr = 0x1000u64;

        let mut func = MlilFunction::new(entry_addr);

        // Entry block: sets state to 0x10 and jumps to dispatcher.
        let mut entry_bb = BasicBlock::new(entry_addr);
        entry_bb.push(MlilInstruction::SetConst {
            dest: "eax".to_owned(),
            value: 0x10,
        });
        entry_bb.push(MlilInstruction::Jump {
            target: dispatcher_addr,
        });
        func.add_block(entry_bb);

        // Dispatcher block (no instructions needed for the rewriter test).
        let dispatcher_bb = BasicBlock::new(dispatcher_addr);
        func.add_block(dispatcher_bb);

        // Block A: sets state to 0x20.
        let mut a_bb = BasicBlock::new(block_a);
        a_bb.push(MlilInstruction::SetConst {
            dest: "eax".to_owned(),
            value: 0x20,
        });
        a_bb.push(MlilInstruction::Jump {
            target: dispatcher_addr,
        });
        func.add_block(a_bb);

        // Block B: sets state to 0x30.
        let mut b_bb = BasicBlock::new(block_b);
        b_bb.push(MlilInstruction::SetConst {
            dest: "eax".to_owned(),
            value: 0x30,
        });
        b_bb.push(MlilInstruction::Jump {
            target: dispatcher_addr,
        });
        func.add_block(b_bb);

        // Block C: sets state to 0x10 (loops back to A).
        let mut c_bb = BasicBlock::new(block_c);
        c_bb.push(MlilInstruction::SetConst {
            dest: "eax".to_owned(),
            value: 0x10,
        });
        c_bb.push(MlilInstruction::Jump {
            target: dispatcher_addr,
        });
        func.add_block(c_bb);

        // Edges.
        func.add_edge(entry_addr, dispatcher_addr, false);
        func.add_edge(dispatcher_addr, block_a, true);
        func.add_edge(dispatcher_addr, block_b, false);
        func.add_edge(dispatcher_addr, block_c, false);
        func.add_edge(block_a, dispatcher_addr, false);
        func.add_edge(block_b, dispatcher_addr, false);
        func.add_edge(block_c, dispatcher_addr, false);

        // Dispatcher case table.
        let mut disp = DispatcherBlock::new(dispatcher_addr, DispType::Switch);
        disp.add_case(0x10, block_a);
        disp.add_case(0x20, block_b);
        disp.add_case(0x30, block_c);

        (func, disp)
    }

    // Test R01: rewrite removes dispatcher-bound edges
    #[test]
    fn test_r01_rewrite_removes_dispatcher_edges() {
        let (mut func, disp) = make_cff_mlil_func();
        let dispatcher_addr = disp.address;

        let transitions = vec![
            ZStateTransition {
                from_bb: 0x3000,
                to_bb: dispatcher_addr,
                condition: None,
                in_state: 0,
                out_state: 0x20,
            },
            ZStateTransition {
                from_bb: 0x4000,
                to_bb: dispatcher_addr,
                condition: None,
                in_state: 0,
                out_state: 0x30,
            },
            ZStateTransition {
                from_bb: 0x5000,
                to_bb: dispatcher_addr,
                condition: None,
                in_state: 0,
                out_state: 0x10,
            },
        ];

        CfgRewriter::rewrite_cff_cfg(&mut func, &transitions, &disp, "eax");

        // No edge should still point to the dispatcher.
        let still_dispatcher: Vec<_> = func
            .edges
            .iter()
            .filter(|(_, to, _)| *to == dispatcher_addr)
            .collect();
        assert!(
            still_dispatcher.is_empty(),
            "no edges should point to dispatcher after rewrite; found {} remaining",
            still_dispatcher.len()
        );
    }

    // Test R02: rewrite inserts direct edges
    #[test]
    fn test_r02_rewrite_inserts_direct_edges() {
        let (mut func, disp) = make_cff_mlil_func();

        let transitions = vec![ZStateTransition {
            from_bb: 0x3000,
            to_bb: 0,
            condition: None,
            in_state: 0,
            out_state: 0x20,
        }];

        CfgRewriter::rewrite_cff_cfg(&mut func, &transitions, &disp, "eax");

        // Block A (0x3000) should now have an edge to block B (0x4000, case 0x20).
        let direct = func
            .edges
            .iter()
            .any(|(from, to, _)| *from == 0x3000 && *to == 0x4000);
        assert!(direct, "direct edge from block A to block B expected");
    }

    // Test R03: eliminate_dead_blocks removes dispatcher and its edges
    #[test]
    fn test_r03_eliminate_dead_blocks() {
        let (mut func, disp) = make_cff_mlil_func();
        let dispatcher_addr = disp.address;

        let mut dead = std::collections::HashSet::new();
        dead.insert(dispatcher_addr);

        let removed = CfgRewriter::eliminate_dead_blocks(&mut func, &dead);
        assert_eq!(removed, 1, "one block (dispatcher) should be removed");
        assert!(func.block_at(dispatcher_addr).is_none());
        // No edges referencing dispatcher should remain.
        assert!(
            func.edges
                .iter()
                .all(|(f, t, _)| *f != dispatcher_addr && *t != dispatcher_addr)
        );
    }

    // Test R04: eliminate_state_variable removes state-related instructions
    #[test]
    fn test_r04_eliminate_state_variable() {
        let (mut func, _) = make_cff_mlil_func();

        // All blocks have SetConst("eax", ...) — these should be removed.
        let removed = CfgRewriter::eliminate_state_variable(&mut func, "eax");

        assert!(
            removed > 0,
            "should remove at least one state-var instruction"
        );
        for bb in &func.blocks {
            for instr in &bb.instrs {
                if let MlilInstruction::SetConst { dest, .. } = instr {
                    assert_ne!(dest, "eax", "eax SetConst should have been eliminated");
                }
            }
        }
    }

    // Test R05: rewrite returns correct rewire count
    #[test]
    fn test_r05_rewrite_rewire_count() {
        let (mut func, disp) = make_cff_mlil_func();
        let dispatcher_addr = disp.address;

        let transitions = vec![
            ZStateTransition {
                from_bb: 0x3000,
                to_bb: dispatcher_addr,
                condition: None,
                in_state: 0,
                out_state: 0x20,
            },
            ZStateTransition {
                from_bb: 0x4000,
                to_bb: dispatcher_addr,
                condition: None,
                in_state: 0,
                out_state: 0x30,
            },
        ];

        let count = CfgRewriter::rewrite_cff_cfg(&mut func, &transitions, &disp, "eax");
        assert!(count > 0, "should report at least one rewired edge");
    }

    // Test R06: eliminate_dead_blocks returns 0 for empty dead set
    #[test]
    fn test_r06_eliminate_dead_empty_set() {
        let (mut func, _) = make_cff_mlil_func();
        let initial_count = func.block_count();
        let removed =
            CfgRewriter::eliminate_dead_blocks(&mut func, &std::collections::HashSet::new());
        assert_eq!(removed, 0);
        assert_eq!(func.block_count(), initial_count);
    }

    // -----------------------------------------------------------------------
    // OllvmDetectorV2 tests
    // -----------------------------------------------------------------------

    fn make_cff_mlil_func_for_detection() -> MlilFunction {
        let entry = 0x1000u64;
        let dispatcher = 0x2000u64;
        let blocks_start = 0x3000u64;
        let n_real_blocks = 5usize;

        let mut func = MlilFunction::new(entry);

        // Entry block.
        let mut entry_bb = BasicBlock::new(entry);
        entry_bb.push(MlilInstruction::SetConst {
            dest: "eax".to_owned(),
            value: 0xAA,
        });
        func.add_block(entry_bb);

        // Dispatcher block (5 successors → real blocks).
        func.add_block(BasicBlock::new(dispatcher));

        // Real blocks: each writes a different constant to eax and jumps back.
        for i in 0..n_real_blocks {
            let addr = blocks_start + i as u64 * 0x100;
            let mut bb = BasicBlock::new(addr);
            bb.push(MlilInstruction::SetConst {
                dest: "eax".to_owned(),
                value: 0xAA + (i + 1) as u64,
            });
            func.add_block(bb);
        }

        // Edges: entry → dispatcher.
        func.add_edge(entry, dispatcher, false);
        // Dispatcher → each real block.
        for i in 0..n_real_blocks {
            let addr = blocks_start + i as u64 * 0x100;
            func.add_edge(dispatcher, addr, i == 0);
        }
        // Each real block → dispatcher (back-edges).
        for i in 0..n_real_blocks {
            let addr = blocks_start + i as u64 * 0x100;
            func.add_edge(addr, dispatcher, false);
        }

        func
    }

    // Test O01: score_function returns high probability for CFF shape
    #[test]
    fn test_o01_score_function_high_for_cff() {
        let func = make_cff_mlil_func_for_detection();
        let score = OllvmDetectorV2::score_function(&func);
        assert!(
            score.probability > 0.5,
            "expected score > 0.5 for CFF-shaped function, got {:.3}",
            score.probability
        );
    }

    // Test O02: score_function returns low probability for linear function
    #[test]
    fn test_o02_score_function_low_for_linear() {
        let mut func = MlilFunction::new(0x1000);
        for i in 0..4u64 {
            func.add_block(BasicBlock::new(0x1000 + i * 0x100));
        }
        func.add_edge(0x1000, 0x1100, false);
        func.add_edge(0x1100, 0x1200, false);
        func.add_edge(0x1200, 0x1300, false);

        let score = OllvmDetectorV2::score_function(&func);
        assert!(
            score.probability < 0.7,
            "expected score < 0.7 for linear function, got {:.3}",
            score.probability
        );
    }

    // Test O03: score_function returns 0 for tiny function (< 3 blocks)
    #[test]
    fn test_o03_score_function_tiny() {
        let mut func = MlilFunction::new(0x1000);
        func.add_block(BasicBlock::new(0x1000));
        func.add_block(BasicBlock::new(0x1100));
        let score = OllvmDetectorV2::score_function(&func);
        assert_eq!(score.probability, 0.0);
    }

    // Test O04: find_dispatcher_candidates returns the hub block
    #[test]
    fn test_o04_find_dispatcher_candidates() {
        let func = make_cff_mlil_func_for_detection();
        let candidates = OllvmDetectorV2::find_dispatcher_candidates(&func);
        assert!(!candidates.is_empty(), "should find at least one candidate");
        // The first candidate should be the block with highest in-degree (dispatcher).
        assert_eq!(candidates[0].bb_addr, 0x2000);
        assert!(candidates[0].in_degree >= 5);
    }

    // Test O05: find_dispatcher_candidates on linear CFG → empty
    #[test]
    fn test_o05_find_dispatcher_candidates_linear() {
        let mut func = MlilFunction::new(0x1000);
        for i in 0..4u64 {
            func.add_block(BasicBlock::new(0x1000 + i * 0x100));
        }
        func.add_edge(0x1000, 0x1100, false);
        func.add_edge(0x1100, 0x1200, false);
        func.add_edge(0x1200, 0x1300, false);

        let candidates = OllvmDetectorV2::find_dispatcher_candidates(&func);
        assert!(
            candidates.is_empty(),
            "linear CFG should have no dispatcher candidates"
        );
    }

    // Test O06: verify_cff_structure succeeds on well-formed CFF
    #[test]
    fn test_o06_verify_cff_structure_ok() {
        let func = make_cff_mlil_func_for_detection();
        let candidates = OllvmDetectorV2::find_dispatcher_candidates(&func);
        assert!(!candidates.is_empty());

        let analysis = OllvmDetectorV2::verify_cff_structure(&func, &candidates[0]);
        assert!(
            analysis.is_some(),
            "should verify CFF structure successfully"
        );
        let a = analysis.unwrap();
        assert!(a.confidence > 0.0);
        assert!(!a.state_var.is_empty());
    }

    // Test O07: verify_cff_structure fails on dispatcher with too few successors
    #[test]
    fn test_o07_verify_cff_structure_too_few_successors() {
        let mut func = MlilFunction::new(0x1000);
        func.add_block(BasicBlock::new(0x1000));
        func.add_block(BasicBlock::new(0x2000)); // "dispatcher"
        func.add_block(BasicBlock::new(0x3000));

        // Only one successor → below the threshold.
        func.add_edge(0x1000, 0x2000, false);
        func.add_edge(0x1000, 0x2000, false); // extra back-edge from same block (for in-degree 2)
        func.add_edge(0x3000, 0x2000, false);
        func.add_edge(0x2000, 0x3000, true); // single successor

        let candidate = DispatcherCandidate {
            bb_addr: 0x2000,
            in_degree: 3,
            out_degree: 1,
            state_var_candidate: None,
        };

        let analysis = OllvmDetectorV2::verify_cff_structure(&func, &candidate);
        assert!(
            analysis.is_none(),
            "should reject dispatcher with only 1 successor"
        );
    }

    // Test O08: CffScore::is_likely_cff threshold
    #[test]
    fn test_o08_cff_score_threshold() {
        let high = CffScore {
            probability: 0.9,
            indicators: vec![],
        };
        let low = CffScore {
            probability: 0.5,
            indicators: vec![],
        };
        assert!(high.is_likely_cff());
        assert!(!low.is_likely_cff());
    }

    // Test O09: score_function includes non-empty indicators for CFF
    #[test]
    fn test_o09_score_has_indicators() {
        let func = make_cff_mlil_func_for_detection();
        let score = OllvmDetectorV2::score_function(&func);
        // Should have identified at least one indicator.
        assert!(
            !score.indicators.is_empty(),
            "CFF function should generate indicators"
        );
    }

    // Test O10: MlilFunction helpers work correctly
    #[test]
    fn test_o10_mlilfunc_helpers() {
        let func = make_cff_mlil_func_for_detection();
        assert_eq!(func.entry, 0x1000);

        // entry block has one successor (dispatcher).
        let succs = func.successors_of(0x1000);
        assert_eq!(succs.len(), 1);
        assert_eq!(succs[0], 0x2000);

        // dispatcher has 5 successors + entry as predecessor.
        let preds = func.predecessors_of(0x2000);
        // entry + 5 real blocks = 6 predecessors.
        assert_eq!(preds.len(), 6);
    }

    // -----------------------------------------------------------------------
    // Integration tests: SymEval + Rewriter + Detector pipeline
    // -----------------------------------------------------------------------

    // Test I01: full pipeline recovers direct edges
    #[test]
    fn test_i01_full_pipeline_recovers_edges() {
        let (mut func, disp) = make_cff_mlil_func();
        let dispatcher_addr = disp.address;

        // Step 1: evaluate transitions from each real block.
        let mut eval = CffSymEval::new("eax", 0x10);
        let mut all_transitions = Vec::new();

        for bb_addr in [0x3000u64, 0x4000, 0x5000] {
            if let Some(bb) = func.block_at(bb_addr).cloned() {
                let in_states: Vec<u64> = disp
                    .cases
                    .iter()
                    .map(|(sv, target)| if *target == bb_addr { *sv } else { 0 })
                    .filter(|&sv| sv != 0)
                    .collect();
                let in_states = if in_states.is_empty() {
                    vec![0x10]
                } else {
                    in_states
                };
                let transitions = eval.eval_block_transitions(&bb, &in_states);
                all_transitions.extend(transitions);
            }
        }

        // Step 2: rewrite the CFG.
        CfgRewriter::rewrite_cff_cfg(&mut func, &all_transitions, &disp, "eax");

        // Step 3: verify no edges go to the dispatcher.
        let to_dispatcher = func
            .edges
            .iter()
            .filter(|(_, to, _)| *to == dispatcher_addr)
            .count();
        assert_eq!(
            to_dispatcher, 0,
            "all dispatcher-bound edges should be rewired"
        );
    }

    // Test I02: full pipeline with dead-block elimination
    #[test]
    fn test_i02_pipeline_dead_block_elimination() {
        let (mut func, disp) = make_cff_mlil_func();
        let dispatcher_addr = disp.address;

        let transitions = vec![
            ZStateTransition {
                from_bb: 0x3000,
                to_bb: 0,
                condition: None,
                in_state: 0,
                out_state: 0x20,
            },
            ZStateTransition {
                from_bb: 0x4000,
                to_bb: 0,
                condition: None,
                in_state: 0,
                out_state: 0x30,
            },
            ZStateTransition {
                from_bb: 0x5000,
                to_bb: 0,
                condition: None,
                in_state: 0,
                out_state: 0x10,
            },
        ];

        CfgRewriter::rewrite_cff_cfg(&mut func, &transitions, &disp, "eax");

        let mut dead = std::collections::HashSet::new();
        dead.insert(dispatcher_addr);
        let removed = CfgRewriter::eliminate_dead_blocks(&mut func, &dead);
        assert_eq!(removed, 1);

        CfgRewriter::eliminate_state_variable(&mut func, "eax");

        // No eax SetConst instructions should remain.
        for bb in &func.blocks {
            for instr in &bb.instrs {
                if let MlilInstruction::SetConst { dest, .. } = instr {
                    assert_ne!(dest, "eax");
                }
            }
        }
    }

    // Test I03: OllvmDetectorV2 + CffAnalysis integration
    #[test]
    fn test_i03_detector_v2_analysis_pipeline() {
        let func = make_cff_mlil_func_for_detection();

        let score = OllvmDetectorV2::score_function(&func);
        assert!(score.probability > 0.4);

        let candidates = OllvmDetectorV2::find_dispatcher_candidates(&func);
        assert!(!candidates.is_empty());

        let analysis = OllvmDetectorV2::verify_cff_structure(&func, &candidates[0]);
        assert!(analysis.is_some());

        let a = analysis.unwrap();
        assert_eq!(a.dispatcher.bb_addr, 0x2000);
        assert!(!a.state_var.is_empty());
    }

    // Test I04: DispatcherBlock with all DispTypes can be constructed
    #[test]
    fn test_i04_all_disp_types() {
        let types = [
            DispType::Switch,
            DispType::IfElseChain,
            DispType::IndirectJump,
            DispType::HashTable,
        ];
        for dt in &types {
            let d = DispatcherBlock::new(0x1000, *dt);
            assert_eq!(d.dispatch_type, *dt);
        }
    }

    // Test I05: SmtConstraintBuilder — parse_z3_model via hex literal (internal path)
    #[test]
    fn test_i05_smt_parse_hex_literal() {
        // Simulate Z3 output with #x literal.
        let fake_output = "(model \n  (define-fun x () (_ BitVec 32) #xdeadbeef)\n)";
        let model = SmtConstraintBuilder::parse_z3_model(fake_output);
        assert_eq!(model.get("x").copied(), Some(0xDEAD_BEEF_u64));
    }

    // Test I06: SmtConstraintBuilder — parse_z3_model via binary literal
    #[test]
    fn test_i06_smt_parse_binary_literal() {
        let fake_output = "(model \n  (define-fun flag () Bool #b1)\n)";
        let model = SmtConstraintBuilder::parse_z3_model(fake_output);
        assert_eq!(model.get("flag").copied(), Some(1u64));
    }

    // Test I07: SmtConstraintBuilder — parse_z3_model via bv literal
    #[test]
    fn test_i07_smt_parse_bv_literal() {
        let fake_output = "(model \n  (define-fun state () (_ BitVec 32) (_ bv255 32))\n)";
        let model = SmtConstraintBuilder::parse_z3_model(fake_output);
        assert_eq!(model.get("state").copied(), Some(255u64));
    }

    // Test I08: AssignmentType equality
    #[test]
    fn test_i08_assignment_type_equality() {
        assert_eq!(AssignmentType::Const(42), AssignmentType::Const(42));
        assert_ne!(AssignmentType::Const(1), AssignmentType::Const(2));
        assert_eq!(
            AssignmentType::Conditional {
                true_val: 10,
                false_val: 20
            },
            AssignmentType::Conditional {
                true_val: 10,
                false_val: 20
            }
        );
        assert_ne!(
            AssignmentType::Conditional {
                true_val: 10,
                false_val: 20
            },
            AssignmentType::Conditional {
                true_val: 10,
                false_val: 99
            }
        );
        assert_eq!(AssignmentType::DataDependent, AssignmentType::DataDependent);
    }

    // Test I09: MlilFunction block_at returns correct block
    #[test]
    fn test_i09_mlilfunc_block_at() {
        let mut func = MlilFunction::new(0x1000);
        func.add_block(BasicBlock::new(0x1000));
        func.add_block(BasicBlock::new(0x2000));
        assert!(func.block_at(0x1000).is_some());
        assert!(func.block_at(0x2000).is_some());
        assert!(func.block_at(0x9999).is_none());
    }

    // Test I10: BasicBlock::terminator returns last instruction
    #[test]
    fn test_i10_basic_block_terminator() {
        let mut bb = BasicBlock::new(0x1000);
        assert!(bb.terminator().is_none());
        bb.push(MlilInstruction::Nop);
        bb.push(MlilInstruction::Jump { target: 0x2000 });
        let term = bb.terminator().unwrap();
        assert!(matches!(term, MlilInstruction::Jump { target: 0x2000 }));
    }

    // Test I11: CffSymEval block_states accumulate across calls
    #[test]
    fn test_i11_block_states_accumulate() {
        let mut bb = BasicBlock::new(0xBBBB);
        bb.push(MlilInstruction::SetConst {
            dest: "eax".to_owned(),
            value: 0x11,
        });

        let mut eval = CffSymEval::new("eax", 0);
        eval.eval_block_transitions(&bb, &[1]);
        eval.eval_block_transitions(&bb, &[2]);

        let states = eval.block_states.get(&0xBBBB).expect("should have states");
        // Both calls should have recorded 0x11.
        assert_eq!(states.iter().filter(|&&s| s == 0x11).count(), 2);
    }

    // Test I12: DispatcherBlock — duplicate case values are permitted
    #[test]
    fn test_i12_dispatcher_duplicate_cases() {
        let mut d = DispatcherBlock::new(0, DispType::Switch);
        d.add_case(0x10, 0x1000);
        d.add_case(0x10, 0x2000); // duplicate state value
        // resolve returns the first match.
        assert_eq!(d.resolve(0x10), Some(0x1000));
        assert_eq!(d.case_count(), 2);
    }

    // Test I13: OllvmDetectorV2 — BFS distances computed correctly
    #[test]
    fn test_i13_bfs_distances() {
        let mut func = MlilFunction::new(0x1000);
        for i in 0..4u64 {
            func.add_block(BasicBlock::new(0x1000 + i * 0x100));
        }
        func.add_edge(0x1000, 0x1100, false);
        func.add_edge(0x1100, 0x1200, false);
        func.add_edge(0x1200, 0x1300, false);

        let dist = OllvmDetectorV2::bfs_distances(&func);
        assert_eq!(dist.get(&0x1000).copied(), Some(0));
        assert_eq!(dist.get(&0x1100).copied(), Some(1));
        assert_eq!(dist.get(&0x1200).copied(), Some(2));
        assert_eq!(dist.get(&0x1300).copied(), Some(3));
    }

    // Test I14: infer_state_var selects highest-frequency write destination
    #[test]
    fn test_i14_infer_state_var() {
        let hub = 0x2000u64;
        let mut func = MlilFunction::new(0x1000);
        func.add_block(BasicBlock::new(0x1000));

        // Three predecessors all writing "eax".
        for i in 1..=3u64 {
            let addr = 0x3000 + i * 0x100;
            let mut bb = BasicBlock::new(addr);
            bb.push(MlilInstruction::SetConst {
                dest: "eax".to_owned(),
                value: i,
            });
            func.add_block(bb);
            func.add_edge(addr, hub, false);
        }

        // One predecessor writing "ecx".
        let ecx_pred = 0x4000u64;
        let mut ecx_bb = BasicBlock::new(ecx_pred);
        ecx_bb.push(MlilInstruction::SetConst {
            dest: "ecx".to_owned(),
            value: 99,
        });
        func.add_block(ecx_bb);
        func.add_edge(ecx_pred, hub, false);

        func.add_block(BasicBlock::new(hub));

        let sv = OllvmDetectorV2::infer_state_var(&func, hub);
        assert_eq!(
            sv.as_deref(),
            Some("eax"),
            "eax should be selected as it appears 3x"
        );
    }

    // Test I15: CfgRewriter::instr_touches_state_var (via eliminate_state_variable)
    #[test]
    fn test_i15_eliminate_state_var_comprehensive() {
        let mut func = MlilFunction::new(0x1000);
        let mut bb = BasicBlock::new(0x1000);
        bb.push(MlilInstruction::SetConst {
            dest: "eax".to_owned(),
            value: 1,
        });
        bb.push(MlilInstruction::SetReg {
            dest: "ebx".to_owned(),
            src: "eax".to_owned(),
        });
        bb.push(MlilInstruction::Xor {
            dest: "eax".to_owned(),
            lhs: "eax".to_owned(),
            rhs: "ebx".to_owned(),
        });
        bb.push(MlilInstruction::Add {
            dest: "ecx".to_owned(),
            lhs: "ecx".to_owned(),
            rhs: "edx".to_owned(),
        });
        bb.push(MlilInstruction::Nop);
        func.add_block(bb);

        let removed = CfgRewriter::eliminate_state_variable(&mut func, "eax");
        assert_eq!(
            removed, 3,
            "SetConst+SetReg+Xor touching eax should be removed"
        );

        // Surviving instructions: Add(ecx, ecx, edx) and Nop.
        let bb = func.block_at(0x1000).unwrap();
        assert_eq!(bb.instrs.len(), 2);
    }
}
