//! LLIL register tracking and binding.
//!
//! Tracks the abstract register state at each LLIL program point, recording
//! which registers hold known values and how they are bound to LLIL temporaries
//! or constants.
//!
//! # Key types
//! - [`RegId`]               — architecture-independent register identifier.
//! - [`RegState`]            — per-register lattice value at one program point.
//! - [`RegBinding`]          — what a register is currently bound to.
//! - [`LlilRegisterAllocator`] — the main tracker.
//! - [`track_regs`]          — convenience entry point.

use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// RegId
// ─────────────────────────────────────────────────────────────────────────────

/// Architecture-independent register identifier.
///
/// Registers are identified by a compact integer.  Architecture-specific
/// lifters are responsible for assigning stable ids to physical registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegId(pub u32);

impl RegId {
    /// Create a new register id.
    #[must_use]
    pub const fn new(v: u32) -> Self {
        Self(v)
    }

    /// A sentinel for the stack pointer (by convention id = 4).
    pub const SP: Self = Self(4);
    /// A sentinel for the base pointer (by convention id = 5).
    pub const BP: Self = Self(5);
    /// Program counter (by convention id = 8).
    pub const PC: Self = Self(8);
}

impl std::fmt::Display for RegId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "r{}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TempId — LLIL temporary
// ─────────────────────────────────────────────────────────────────────────────

/// An LLIL SSA temporary (phi-free; produced by lifters).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TempId(pub u32);

impl TempId {
    #[must_use]
    pub const fn new(v: u32) -> Self {
        Self(v)
    }
}

impl std::fmt::Display for TempId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "t{}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegBinding — what a register currently holds
// ─────────────────────────────────────────────────────────────────────────────

/// The concrete or abstract value a register is bound to at a program point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegBinding {
    /// The register holds a known constant value.
    Const(i64),
    /// The register is bound to an LLIL temporary (forward data-flow copy).
    Temp(TempId),
    /// The register holds the address of a global symbol.
    GlobalAddr(u64),
    /// The register value is unknown but the register has been written.
    Unknown,
}

impl RegBinding {
    /// Return the constant value if known.
    #[must_use]
    pub const fn as_const(&self) -> Option<i64> {
        if let Self::Const(c) = self {
            Some(*c)
        } else {
            None
        }
    }

    /// Return `true` if the binding is a known constant.
    #[must_use]
    pub const fn is_const(&self) -> bool {
        matches!(self, Self::Const(_))
    }

    /// Return `true` if the binding is completely unknown.
    #[must_use]
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

impl std::fmt::Display for RegBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Const(c) => write!(f, "#{c}"),
            Self::Temp(t) => write!(f, "{t}"),
            Self::GlobalAddr(a) => write!(f, "0x{a:x}"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegState — per-register lattice value
// ─────────────────────────────────────────────────────────────────────────────

/// The abstract state of all registers at one program point.
///
/// Registers absent from the map are at `Top` (no information yet).
/// A register present with `RegBinding::Unknown` is at `Bottom`
/// (written but value not determined).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RegState {
    pub bindings: HashMap<RegId, RegBinding>,
}

impl RegState {
    /// Create an empty state (all registers at Top).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the binding for a register (Top = None).
    #[must_use]
    pub fn get(&self, reg: RegId) -> Option<&RegBinding> {
        self.bindings.get(&reg)
    }

    /// Set the binding for a register.
    pub fn set(&mut self, reg: RegId, binding: RegBinding) {
        self.bindings.insert(reg, binding);
    }

    /// Mark a register as having an unknown value.
    pub fn clobber(&mut self, reg: RegId) {
        self.bindings.insert(reg, RegBinding::Unknown);
    }

    /// Remove all knowledge about a register (back to Top).
    pub fn forget(&mut self, reg: RegId) {
        self.bindings.remove(&reg);
    }

    /// Join `other` into `self` (meet on bindings — conservative).
    ///
    /// Returns `true` if any binding changed.
    pub fn join_from(&mut self, other: &Self) -> bool {
        let mut changed = false;
        // Meet semantics:
        // - binding present on only one side → drop it (Top): we cannot
        //   assume anything about the register on the path where it is
        //   unbound, so adopting the other side's value would be unsound.
        // - present on both sides with the same binding: no change.
        // - present on both sides with different bindings: Unknown (Bottom).
        let self_keys: Vec<RegId> = self.bindings.keys().copied().collect();
        for reg in self_keys {
            if !other.bindings.contains_key(&reg) {
                self.bindings.remove(&reg);
                changed = true;
            }
        }
        let other_keys: Vec<RegId> = other.bindings.keys().copied().collect();
        for reg in other_keys {
            let other_val = &other.bindings[&reg];
            match self.bindings.get(&reg) {
                // Missing in self → stays Top; do not adopt other's value.
                None => {}
                Some(self_val) if self_val == other_val => {}
                Some(_) => {
                    // Conflict → Unknown.
                    let prev = self.bindings.insert(reg, RegBinding::Unknown);
                    if prev.as_ref() != Some(&RegBinding::Unknown) {
                        changed = true;
                    }
                }
            }
        }
        changed
    }

    /// Return all registers with a known constant value.
    #[must_use]
    pub fn known_constants(&self) -> Vec<(RegId, i64)> {
        let mut v: Vec<(RegId, i64)> = self
            .bindings
            .iter()
            .filter_map(|(&r, b)| b.as_const().map(|c| (r, c)))
            .collect();
        v.sort_by_key(|(r, _)| *r);
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Abstract LLIL instruction for the register tracker
// ─────────────────────────────────────────────────────────────────────────────

/// A simplified LLIL instruction for register-tracking purposes.
///
/// The tracker operates on this abstract form rather than the concrete
/// [`rustre_il_llil::LlilInstruction`] to remain self-contained.
#[derive(Debug, Clone)]
pub enum RegInstr {
    /// `dst_temp ← reg` — read a register into a temporary.
    ReadReg { temp: TempId, reg: RegId },
    /// `reg ← temp` — write a temporary back to a register.
    WriteReg { reg: RegId, temp: TempId },
    /// `reg ← const` — load a constant into a register.
    LoadConst { reg: RegId, value: i64 },
    /// `reg ← global_addr` — load a global symbol address.
    LoadGlobal { reg: RegId, addr: u64 },
    /// Clobber one or more registers (call, interrupt, etc.).
    Clobber { regs: Vec<RegId> },
    /// Mark a register as forgotten (returned to Top, e.g. at function entry).
    Forget { reg: RegId },
    /// No effect (padding / nop).
    Nop,
}

// ─────────────────────────────────────────────────────────────────────────────
// RegBlock — a basic block for the tracker
// ─────────────────────────────────────────────────────────────────────────────

/// A basic block in the register-tracking CFG.
#[derive(Debug, Clone)]
pub struct RegBlock {
    pub id: usize,
    pub instrs: Vec<RegInstr>,
    pub succs: Vec<usize>,
}

// ─────────────────────────────────────────────────────────────────────────────
// RegTrackResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of register tracking for a function.
#[derive(Debug, Clone)]
pub struct RegTrackResult {
    /// Per-block state on entry (indexed by block id).
    pub in_states: Vec<RegState>,
    /// Per-block state on exit (indexed by block id).
    pub out_states: Vec<RegState>,
    /// Number of worklist iterations.
    pub iterations: usize,
}

impl RegTrackResult {
    /// Return the binding of `reg` at the exit of `block_id`.
    #[must_use]
    pub fn binding_at_exit(&self, block_id: usize, reg: RegId) -> Option<&RegBinding> {
        self.out_states.get(block_id)?.get(reg)
    }

    /// Return all registers with a known constant value at the exit of `block_id`.
    #[must_use]
    pub fn constants_at_exit(&self, block_id: usize) -> Vec<(RegId, i64)> {
        self.out_states
            .get(block_id)
            .map(RegState::known_constants)
            .unwrap_or_default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LlilRegisterAllocator
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks register bindings across LLIL basic blocks using a forward
/// data-flow analysis.
///
/// Unlike a traditional register allocator (which assigns variables to
/// registers for code generation), this tracks what values *are* in each
/// register at every program point — useful for lifting and analysis.
#[derive(Debug, Clone, Default)]
pub struct LlilRegisterAllocator {
    /// Maximum iterations before giving up.
    pub max_iterations: usize,
    /// Registers that are clobbered by every call instruction.
    pub caller_saved: HashSet<RegId>,
}

impl LlilRegisterAllocator {
    /// Create a tracker with default settings (no caller-saved set).
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_iterations: 10_000,
            caller_saved: HashSet::new(),
        }
    }

    /// Apply the transfer function for one block.
    #[must_use]
    pub fn transfer(&self, block: &RegBlock, in_state: &RegState) -> RegState {
        let mut state = in_state.clone();
        for instr in &block.instrs {
            self.apply_instr(instr, &mut state);
        }
        state
    }

    fn apply_instr(&self, instr: &RegInstr, state: &mut RegState) {
        match instr {
            RegInstr::ReadReg { .. } | RegInstr::Nop => {
                // Reading a register or a no-op doesn't change state.
            }
            RegInstr::WriteReg { reg, temp } => {
                // When we write a temp back to a register, we can record the
                // binding if we know the temp came from a constant register.
                // For now, mark as Unknown (temp binding resolved in richer analysis).
                state.set(*reg, RegBinding::Temp(*temp));
            }
            RegInstr::LoadConst { reg, value } => {
                state.set(*reg, RegBinding::Const(*value));
            }
            RegInstr::LoadGlobal { reg, addr } => {
                state.set(*reg, RegBinding::GlobalAddr(*addr));
            }
            RegInstr::Clobber { regs } => {
                for &r in regs {
                    state.clobber(r);
                }
                // Also clobber caller-saved registers.
                for &r in &self.caller_saved {
                    state.clobber(r);
                }
            }
            RegInstr::Forget { reg } => {
                state.forget(*reg);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// track_regs — top-level entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Run register tracking over a function's CFG.
///
/// # Arguments
/// - `blocks`   — basic blocks (ids must be contiguous `0..n`).
/// - `entry`    — entry block id.
/// - `preds`    — predecessor lists.
/// - `tracker`  — configured [`LlilRegisterAllocator`].
#[must_use]
pub fn track_regs(
    blocks: &[RegBlock],
    entry: usize,
    preds: &[Vec<usize>],
    tracker: &LlilRegisterAllocator,
) -> RegTrackResult {
    let n = blocks.len();
    if n == 0 {
        return RegTrackResult {
            in_states: vec![],
            out_states: vec![],
            iterations: 0,
        };
    }

    let mut in_states: Vec<RegState> = (0..n).map(|_| RegState::new()).collect();
    let mut out_states: Vec<RegState> = (0..n)
        .map(|i| tracker.transfer(&blocks[i], &in_states[i]))
        .collect();

    let mut worklist: VecDeque<usize> = (0..n).collect();
    let mut in_wl: Vec<bool> = vec![true; n];
    let mut iterations = 0usize;

    while let Some(bid) = worklist.pop_front() {
        in_wl[bid] = false;
        iterations += 1;
        if iterations > tracker.max_iterations {
            break;
        }

        // Compute new in_state: entry/empty-pred blocks start fresh;
        // for all other blocks join all predecessors' out_states.
        let block_preds = preds.get(bid).map_or(&[][..], Vec::as_slice);
        let new_in = if bid == entry || block_preds.is_empty() {
            RegState::new()
        } else {
            let mut acc = out_states[block_preds[0]].clone();
            for &p in &block_preds[1..] {
                acc.join_from(&out_states[p]);
            }
            acc
        };

        let new_out = tracker.transfer(&blocks[bid], &new_in);

        if new_out != out_states[bid] {
            out_states[bid] = new_out;
            for &succ in &blocks[bid].succs {
                if succ < n && !in_wl[succ] {
                    in_wl[succ] = true;
                    worklist.push_back(succ);
                }
            }
        }
        in_states[bid] = new_in;
    }

    RegTrackResult {
        in_states,
        out_states,
        iterations,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegisterUseSummary — aggregate per-function register usage
// ─────────────────────────────────────────────────────────────────────────────

/// Summarizes which registers are read, written, and clobbered in a function.
#[derive(Debug, Clone, Default)]
pub struct RegisterUseSummary {
    /// Registers read in at least one block.
    pub read_regs: HashSet<RegId>,
    /// Registers written in at least one block.
    pub written_regs: HashSet<RegId>,
    /// Registers clobbered (set to Unknown) at some point.
    pub clobbered_regs: HashSet<RegId>,
    /// Registers that are read before being defined in at least one block
    /// (the union of the per-block liveness GEN sets).
    ///
    /// This is order-sensitive and must be accumulated during the block scan:
    /// a register that a block both reads and writes (`a = a + 1`) is only
    /// killed by that write if the write comes *first*.
    pub gen_regs: HashSet<RegId>,
}

impl RegisterUseSummary {
    /// Build a summary from a sequence of blocks.
    #[must_use]
    pub fn from_blocks(blocks: &[RegBlock]) -> Self {
        let mut s = Self::default();
        for block in blocks {
            // Per-block KILL set, accumulated in program order so that a use
            // is only killed by a def that *precedes* it.
            let mut killed: HashSet<RegId> = HashSet::new();
            for instr in &block.instrs {
                match instr {
                    RegInstr::ReadReg { reg, .. } => {
                        s.read_regs.insert(*reg);
                        // GEN: read before any def of this reg in this block.
                        if !killed.contains(reg) {
                            s.gen_regs.insert(*reg);
                        }
                    }
                    RegInstr::WriteReg { reg, .. } | RegInstr::LoadConst { reg, .. } | RegInstr::LoadGlobal { reg, .. } => {
                        s.written_regs.insert(*reg);
                        killed.insert(*reg);
                    }
                    RegInstr::Clobber { regs } => {
                        for &r in regs {
                            s.clobbered_regs.insert(r);
                            killed.insert(r);
                        }
                    }
                    RegInstr::Forget { reg } => {
                        s.clobbered_regs.insert(*reg);
                        killed.insert(*reg);
                    }
                    RegInstr::Nop => {}
                }
            }
        }
        s
    }

    /// Registers that are live-in (read before any write).
    ///
    /// Returns the union of the per-block GEN sets: a register read before it
    /// is defined in *some* block.  This is a conservative over-approximation
    /// of the function's true live-in set.
    ///
    /// It is deliberately **not** `read_regs - written_regs`: that formulation
    /// lets a block's own def kill the block's own use, so an accumulator or
    /// induction variable (`a = a + 1`) would be reported dead-on-entry and its
    /// defining assignment silently deleted.  Liveness must kill before it gens.
    #[must_use]
    pub fn live_in_regs(&self) -> HashSet<RegId> {
        self.gen_regs.clone()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn r(n: u32) -> RegId {
        RegId::new(n)
    }

    fn t(n: u32) -> TempId {
        TempId::new(n)
    }

    fn make_blocks(
        layout: Vec<(usize, Vec<RegInstr>, Vec<usize>)>,
    ) -> (Vec<RegBlock>, Vec<Vec<usize>>) {
        let n = layout.len();
        let mut preds: Vec<Vec<usize>> = vec![vec![]; n];
        let blocks: Vec<RegBlock> = layout
            .into_iter()
            .map(|(id, instrs, succs)| {
                for &s in &succs {
                    if s < n {
                        preds[s].push(id);
                    }
                }
                RegBlock { id, instrs, succs }
            })
            .collect();
        (blocks, preds)
    }

    #[test]
    fn test_join_from_missing_on_either_side_goes_to_top() {
        // Binding only in `other`: must NOT be adopted (self is Top there).
        let mut a = RegState::new();
        let mut b = RegState::new();
        b.set(r(0), RegBinding::Const(42));
        let changed = a.join_from(&b);
        assert!(!changed);
        assert_eq!(a.get(r(0)), None);

        // Binding only in `self`: must be dropped to Top, not silently kept.
        let mut c = RegState::new();
        c.set(r(1), RegBinding::Const(7));
        let changed = c.join_from(&RegState::new());
        assert!(changed);
        assert_eq!(c.get(r(1)), None);

        // Agreeing bindings survive; conflicting go to Unknown.
        let mut d = RegState::new();
        d.set(r(2), RegBinding::Const(1));
        d.set(r(3), RegBinding::Const(2));
        let mut e = RegState::new();
        e.set(r(2), RegBinding::Const(1));
        e.set(r(3), RegBinding::Const(9));
        assert!(d.join_from(&e));
        assert_eq!(d.get(r(2)), Some(&RegBinding::Const(1)));
        assert_eq!(d.get(r(3)), Some(&RegBinding::Unknown));
    }

    #[test]
    fn test_load_const_propagates() {
        let (blocks, preds) = make_blocks(vec![
            (0, vec![RegInstr::LoadConst { reg: r(0), value: 42 }], vec![1]),
            (1, vec![], vec![]),
        ]);
        let tracker = LlilRegisterAllocator::new();
        let result = track_regs(&blocks, 0, &preds, &tracker);
        assert_eq!(
            result.binding_at_exit(0, r(0)),
            Some(&RegBinding::Const(42))
        );
        assert_eq!(
            result.binding_at_exit(1, r(0)),
            Some(&RegBinding::Const(42))
        );
    }

    #[test]
    fn test_clobber_sets_unknown() {
        let (blocks, preds) = make_blocks(vec![(
            0,
            vec![
                RegInstr::LoadConst { reg: r(0), value: 7 },
                RegInstr::Clobber { regs: vec![r(0)] },
            ],
            vec![],
        )]);
        let tracker = LlilRegisterAllocator::new();
        let result = track_regs(&blocks, 0, &preds, &tracker);
        assert_eq!(
            result.binding_at_exit(0, r(0)),
            Some(&RegBinding::Unknown)
        );
    }

    #[test]
    fn test_join_same_constant() {
        // Both predecessors set r0 = 5 → r0 = 5 at join.
        let (blocks, preds) = make_blocks(vec![
            (0, vec![], vec![1, 2]),
            (1, vec![RegInstr::LoadConst { reg: r(0), value: 5 }], vec![3]),
            (2, vec![RegInstr::LoadConst { reg: r(0), value: 5 }], vec![3]),
            (3, vec![], vec![]),
        ]);
        let tracker = LlilRegisterAllocator::new();
        let result = track_regs(&blocks, 0, &preds, &tracker);
        assert_eq!(
            result.binding_at_exit(3, r(0)),
            Some(&RegBinding::Const(5))
        );
    }

    #[test]
    fn test_join_different_constants_gives_unknown() {
        // Predecessors set r0 = 3 and r0 = 7 → Unknown at join.
        let (blocks, preds) = make_blocks(vec![
            (0, vec![], vec![1, 2]),
            (1, vec![RegInstr::LoadConst { reg: r(0), value: 3 }], vec![3]),
            (2, vec![RegInstr::LoadConst { reg: r(0), value: 7 }], vec![3]),
            (3, vec![], vec![]),
        ]);
        let tracker = LlilRegisterAllocator::new();
        let result = track_regs(&blocks, 0, &preds, &tracker);
        assert_eq!(
            result.binding_at_exit(3, r(0)),
            Some(&RegBinding::Unknown)
        );
    }

    #[test]
    fn test_write_reg_binds_temp() {
        let (blocks, preds) = make_blocks(vec![(
            0,
            vec![RegInstr::WriteReg { reg: r(1), temp: t(0) }],
            vec![],
        )]);
        let tracker = LlilRegisterAllocator::new();
        let result = track_regs(&blocks, 0, &preds, &tracker);
        assert_eq!(
            result.binding_at_exit(0, r(1)),
            Some(&RegBinding::Temp(t(0)))
        );
    }

    #[test]
    fn test_forget_clears_binding() {
        let (blocks, preds) = make_blocks(vec![(
            0,
            vec![
                RegInstr::LoadConst { reg: r(0), value: 99 },
                RegInstr::Forget { reg: r(0) },
            ],
            vec![],
        )]);
        let tracker = LlilRegisterAllocator::new();
        let result = track_regs(&blocks, 0, &preds, &tracker);
        assert!(result.binding_at_exit(0, r(0)).is_none());
    }

    #[test]
    fn test_register_use_summary() {
        let blocks = vec![
            RegBlock {
                id: 0,
                instrs: vec![
                    RegInstr::ReadReg { temp: t(0), reg: r(0) },
                    RegInstr::LoadConst { reg: r(1), value: 10 },
                ],
                succs: vec![],
            },
        ];
        let summary = RegisterUseSummary::from_blocks(&blocks);
        assert!(summary.read_regs.contains(&r(0)));
        assert!(summary.written_regs.contains(&r(1)));
    }

    /// `a = a + 1`: the register is read *before* it is written, so it is
    /// live-in.  The block's own def must not kill the block's own use.
    #[test]
    fn live_in_regs_accumulator_read_before_write() {
        let blocks = vec![RegBlock {
            id: 0,
            instrs: vec![
                RegInstr::ReadReg { temp: t(0), reg: r(0) },
                RegInstr::WriteReg { reg: r(0), temp: t(0) },
            ],
            succs: vec![],
        }];
        let summary = RegisterUseSummary::from_blocks(&blocks);
        assert!(
            summary.live_in_regs().contains(&r(0)),
            "r0 is read before it is written, so it must be live-in"
        );
    }

    /// A register defined before its first read is *not* live-in.
    #[test]
    fn live_in_regs_write_before_read_is_not_live_in() {
        let blocks = vec![RegBlock {
            id: 0,
            instrs: vec![
                RegInstr::LoadConst { reg: r(1), value: 10 },
                RegInstr::ReadReg { temp: t(0), reg: r(1) },
            ],
            succs: vec![],
        }];
        let summary = RegisterUseSummary::from_blocks(&blocks);
        assert!(
            !summary.live_in_regs().contains(&r(1)),
            "r1 is written before it is read, so it is not live-in"
        );
    }

    /// A clobber (call) also kills a subsequent read.
    #[test]
    fn live_in_regs_clobber_before_read_is_not_live_in() {
        let blocks = vec![RegBlock {
            id: 0,
            instrs: vec![
                RegInstr::Clobber { regs: vec![r(2)] },
                RegInstr::ReadReg { temp: t(0), reg: r(2) },
            ],
            succs: vec![],
        }];
        let summary = RegisterUseSummary::from_blocks(&blocks);
        assert!(!summary.live_in_regs().contains(&r(2)));
    }

    /// Read-before-write in *any* block makes the register live-in
    /// (conservative union over blocks).
    #[test]
    fn live_in_regs_union_over_blocks() {
        let blocks = vec![
            RegBlock {
                id: 0,
                instrs: vec![RegInstr::LoadConst { reg: r(3), value: 1 }],
                succs: vec![1],
            },
            RegBlock {
                id: 1,
                instrs: vec![RegInstr::ReadReg { temp: t(1), reg: r(4) }],
                succs: vec![],
            },
        ];
        let summary = RegisterUseSummary::from_blocks(&blocks);
        assert!(summary.live_in_regs().contains(&r(4)));
        assert!(!summary.live_in_regs().contains(&r(3)));
    }

    #[test]
    fn test_global_addr_binding() {
        let (blocks, preds) = make_blocks(vec![(
            0,
            vec![RegInstr::LoadGlobal { reg: r(2), addr: 0xdeadbeef }],
            vec![],
        )]);
        let tracker = LlilRegisterAllocator::new();
        let result = track_regs(&blocks, 0, &preds, &tracker);
        assert_eq!(
            result.binding_at_exit(0, r(2)),
            Some(&RegBinding::GlobalAddr(0xdeadbeef))
        );
    }

    #[test]
    fn test_empty_cfg() {
        let tracker = LlilRegisterAllocator::new();
        let result = track_regs(&[], 0, &[], &tracker);
        assert_eq!(result.iterations, 0);
    }
}
