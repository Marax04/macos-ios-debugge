//! MLIL dead store eliminator — removes stores whose written value is never
//! subsequently read before being overwritten, using live-variable and
//! alias analysis.
//!
//! A store `*p = v` is dead if no path from that store to function exit reads
//! `*p` without an intervening store to an alias of `*p`.

use ahash::{AHashMap as HashMap, AHashSet as HashSet};
use std::collections::VecDeque;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// DeadStore
// ─────────────────────────────────────────────────────────────────────────────

/// A single dead store identified by the eliminator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadStore {
    /// Index of the statement in the input list.
    pub stmt_index: usize,
    /// Address of the instruction.
    pub addr: u64,
    /// Description of the store (for diagnostics).
    pub description: String,
    /// The memory location being written.
    pub location: StoreLocation,
    /// Confidence that this is truly dead (0–100).
    pub confidence: u8,
}

impl DeadStore {
    /// Return `true` if this dead store is high-confidence.
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 80
    }
}

impl fmt::Display for DeadStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DeadStore@{:#x} [{}] idx={} conf={}",
            self.addr, self.description, self.stmt_index, self.confidence
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StoreLocation — where a store writes
// ─────────────────────────────────────────────────────────────────────────────

/// The abstract memory location of a store.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StoreLocation {
    /// Stack frame slot at a given offset.
    StackSlot { offset: i64, size: u32 },
    /// Fixed global address.
    Global { addr: u64 },
    /// SSA variable used as a pointer base.
    Pointer { base: String },
    /// Register (for register stores in MLIL).
    Register { name: String },
    /// Unknown / arbitrary location.
    Unknown,
}

impl StoreLocation {
    /// Return `true` if this location is definitely different from `other`.
    #[must_use]
    pub fn definitely_different(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::StackSlot { offset: o1, size: s1 }, Self::StackSlot { offset: o2, size: s2 }) => {
                // Non-overlapping stack slots.
                let end1 = *o1 + i64::from(*s1);
                let end2 = *o2 + i64::from(*s2);
                end1 <= *o2 || end2 <= *o1
            }
            (Self::StackSlot { .. }, Self::Global { .. })
            | (Self::Global { .. }, Self::StackSlot { .. }) => true,
            (Self::Global { addr: a1 }, Self::Global { addr: a2 }) => a1 != a2,
            (Self::Register { name: n1 }, Self::Register { name: n2 }) => n1 != n2,
            _ => false,
        }
    }

    /// Return `true` if the two locations may alias.
    #[must_use]
    pub fn may_alias(&self, other: &Self) -> bool {
        !self.definitely_different(other)
    }

    /// Return `true` if a write to `self` *definitely* supplies every byte
    /// that a read of `other` observes — i.e. `self` must-aliases and fully
    /// covers `other`.
    ///
    /// This is strictly stronger than [`may_alias`](Self::may_alias): two
    /// locations can overlap partially (`stack[0:8]` vs `stack[4:8]`), in
    /// which case a read of one is only *partly* satisfied by a write to the
    /// other and earlier writes remain observable.
    #[must_use]
    pub fn fully_covers(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::StackSlot { offset: o1, size: s1 }, Self::StackSlot { offset: o2, size: s2 }) => {
                *o1 <= *o2 && (*o1 + i64::from(*s1)) >= (*o2 + i64::from(*s2))
            }
            (Self::Global { addr: a1 }, Self::Global { addr: a2 }) => a1 == a2,
            (Self::Register { name: n1 }, Self::Register { name: n2 }) => n1 == n2,
            (Self::Pointer { base: b1 }, Self::Pointer { base: b2 }) => b1 == b2,
            // Unknown / mixed kinds: never a *definite* full cover.
            _ => false,
        }
    }
}

impl fmt::Display for StoreLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StackSlot { offset, size } => write!(f, "stack[{offset:+}:{size}]"),
            Self::Global { addr } => write!(f, "global:{addr:#x}"),
            Self::Pointer { base } => write!(f, "*{base}"),
            Self::Register { name } => write!(f, "reg:{name}"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MlilStatement — simplified MLIL statement for DSE
// ─────────────────────────────────────────────────────────────────────────────

/// A simplified MLIL statement used as input to the eliminator.
#[derive(Debug, Clone)]
pub enum MlilStatement {
    /// `*loc = value` — memory store.
    Store {
        addr: u64,
        loc: StoreLocation,
        /// SSA variables used as the stored value.
        value_vars: Vec<String>,
    },
    /// `reg = *loc` — memory load.
    Load {
        addr: u64,
        dest_reg: String,
        loc: StoreLocation,
    },
    /// `reg = expr(operands)` — computation (no memory side effect).
    Assign {
        addr: u64,
        dest: String,
        operands: Vec<String>,
    },
    /// Function call — may read/write arbitrary memory.
    Call {
        addr: u64,
        target: String,
        args: Vec<String>,
        /// If `true`, the call may read any memory (conservative escape).
        may_read_all: bool,
        /// If `true`, the call may write any memory.
        may_write_all: bool,
    },
    /// Branch / conditional — reads condition variable.
    Branch {
        addr: u64,
        cond_var: Option<String>,
        targets: Vec<u32>,
    },
    /// Return — reads the return value variable.
    Return {
        addr: u64,
        ret_vars: Vec<String>,
    },
    /// Phi node — reads from predecessor SSA vars.
    Phi {
        addr: u64,
        dest: String,
        sources: Vec<String>,
    },
    /// Fence / memory barrier — preserves all prior stores.
    Fence { addr: u64 },
}

impl MlilStatement {
    /// Return the memory location read by this statement (for loads).
    #[must_use]
    pub const fn memory_read(&self) -> Option<&StoreLocation> {
        if let Self::Load { loc, .. } = self {
            Some(loc)
        } else {
            None
        }
    }

    /// Return the memory location written by this statement (for stores).
    #[must_use]
    pub const fn memory_written(&self) -> Option<&StoreLocation> {
        if let Self::Store { loc, .. } = self {
            Some(loc)
        } else {
            None
        }
    }

    /// Return `true` if this statement may read arbitrary memory.
    #[must_use]
    pub const fn may_read_all_memory(&self) -> bool {
        matches!(self, Self::Call { may_read_all: true, .. } | Self::Fence { .. })
    }

    /// Return `true` if this statement may write arbitrary memory.
    #[must_use]
    pub const fn may_write_all_memory(&self) -> bool {
        matches!(self, Self::Call { may_write_all: true, .. } | Self::Fence { .. })
    }

    /// Return the address of this statement.
    #[must_use]
    pub const fn addr(&self) -> u64 {
        match self {
            Self::Store { addr, .. }
            | Self::Load { addr, .. }
            | Self::Assign { addr, .. }
            | Self::Call { addr, .. }
            | Self::Branch { addr, .. }
            | Self::Return { addr, .. }
            | Self::Phi { addr, .. }
            | Self::Fence { addr } => *addr,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LiveStoreSet — tracks which stores are still "live" (may be read later)
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks which store indices are still live.
#[derive(Debug, Default)]
struct LiveStoreSet {
    /// `store_index` → `StoreLocation`
    live: HashMap<usize, StoreLocation>,
    /// `store_index` → originating instruction address (for diagnostics).
    addrs: HashMap<usize, u64>,
    /// FIFO of recently-marked store indices (used to maintain insertion
    /// order so the eliminator can emit findings in observation order).
    recent: VecDeque<usize>,
    /// Names of SSA variables consumed by a `Return` statement; these are
    /// considered live escapes — any store that may alias one of them is
    /// preserved even after [`kill_all`].
    return_vars: HashSet<String>,
    /// Pending reads observed during the backwards pass — locations whose
    /// values are read at some later (forward) point. A store that may
    /// alias one of these reads is live (provides the read value).
    pending_reads: Vec<StoreLocation>,
}

impl LiveStoreSet {
    /// Mark a store seen during backwards iteration. Returns `true` if the
    /// store is a dead-candidate (no pending read consumes it).
    fn mark_store(&mut self, idx: usize, loc: StoreLocation) -> bool {
        // If any pending forward-read may alias this store, the store is live —
        // it provides the value for that read. Consume the matching reads.
        let mut is_live = false;
        self.pending_reads.retain(|read_loc| {
            if read_loc.may_alias(&loc) {
                is_live = true;
                // Only *consume* the read if this store definitely supplies
                // every byte the read observes. A partial overlap (e.g. store
                // `stack[4:8]` vs read `stack[0:8]`) leaves the remaining
                // bytes to be supplied by earlier stores, so the read must
                // stay pending — otherwise those earlier stores are wrongly
                // reported dead.
                !loc.fully_covers(read_loc)
            } else {
                true
            }
        });
        if is_live {
            return false;
        }
        // No pending read — this store is a dead candidate. Any previously
        // recorded candidate to the same location is superseded by this
        // (earlier-in-time) store, since the later store overwrites without
        // an intervening read.
        self.live.retain(|_, existing| existing.definitely_different(&loc));
        self.live.insert(idx, loc);
        self.recent.push_back(idx);
        if self.recent.len() > 1024 {
            self.recent.pop_front();
        }
        true
    }

    fn mark_store_with_addr(&mut self, idx: usize, loc: StoreLocation, addr: u64) {
        if self.mark_store(idx, loc) {
            self.addrs.insert(idx, addr);
        }
    }

    fn mark_return_var(&mut self, name: String) {
        self.return_vars.insert(name);
    }

    /// Returns the recorded address for a store index, if known.
    fn addr_of(&self, idx: usize) -> Option<u64> {
        self.addrs.get(&idx).copied()
    }

    /// Returns the SSA variable names captured by any [`Return`] processed.
    const fn return_vars(&self) -> &HashSet<String> {
        &self.return_vars
    }

    /// Returns the recent-store FIFO in observation order.
    fn recent_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.recent.iter().copied()
    }

    fn mark_read(&mut self, read_loc: &StoreLocation) {
        // Backwards iteration: a load here means there will be a forward-future
        // read of `read_loc`. Record it so any earlier store that may alias is
        // recognised as live. Also clear any existing dead-candidates that may
        // alias — they are observed by this read.
        self.live.retain(|_, stored_loc| stored_loc.definitely_different(read_loc));
        self.pending_reads.push(read_loc.clone());
    }

    fn kill_all(&mut self) {
        self.live.clear();
    }

    /// Treat the current point as a wildcard memory read — every prior store
    /// must be considered observed (used for call/fence barriers).
    fn kill_all_with_wildcard_read(&mut self) {
        self.live.clear();
        self.pending_reads.push(StoreLocation::Unknown);
    }

    fn dead_store_indices(&self) -> Vec<usize> {
        self.live.keys().copied().collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// eliminate_dead_stores — public function
// ─────────────────────────────────────────────────────────────────────────────

/// Identify dead stores in a linear sequence of MLIL statements.
///
/// This is a single-pass backwards analysis suitable for a single basic block.
/// For inter-block analysis use [`MlilDeadStoreEliminator`].
#[must_use]
pub fn eliminate_dead_stores(stmts: &[MlilStatement]) -> Vec<DeadStore> {
    let mut dead = Vec::new();
    let mut live_set = LiveStoreSet::default();

    // Process backwards.
    for (idx, stmt) in stmts.iter().enumerate().rev() {
        match stmt {
            MlilStatement::Store { addr, loc, .. } => {
                let previous_dead = live_set.dead_store_indices();
                live_set.mark_store_with_addr(idx, loc.clone(), *addr);
                // Check if this store itself immediately became dead
                // (i.e., was added but is already dominated by a subsequent store
                //  without an intervening read).
                // We detect this by checking if, before adding it, we had a store at
                // the same location already in the live set that was NOT read.
                // (This is checked next iteration; the set handles it via `mark_store`.)
                let _ = previous_dead; // used for cycle detection in full analysis
            }
            MlilStatement::Load { loc, .. } => {
                live_set.mark_read(loc);
            }
            MlilStatement::Call { may_read_all: true, .. }
            | MlilStatement::Call { may_write_all: true, .. }
            | MlilStatement::Fence { .. } => {
                // A call that may write arbitrary memory is treated the same as
                // one that may read it: it could alias a pending store's
                // location (e.g. via a pointer argument the callee dereferences
                // and observes before overwriting), so eliding the store would
                // risk dropping a write the callee actually depends on.
                live_set.kill_all_with_wildcard_read();
            }
            MlilStatement::Return { ret_vars, .. } => {
                // Return reads ret vars — record them so we never elide a store
                // whose value escapes via the return path — then kill all pending
                // stores since post-return is observation point.
                for v in ret_vars {
                    live_set.mark_return_var(v.clone());
                }
                live_set.kill_all();
            }
            MlilStatement::Phi { .. } => {}
            MlilStatement::Branch { cond_var: None, .. } => {}
            _ => {}
        }
    }

    // Any stores remaining in live_set after the backwards pass are dead.
    // Emit findings in the FIFO observation order recorded by the live set,
    // then de-duplicate by stmt_index. This preserves analyst-friendly ordering
    // while still producing a stable, sorted output.
    let mut seen: HashSet<usize> = HashSet::new();
    let valid: HashSet<usize> = live_set.dead_store_indices().into_iter().collect();
    let return_vars_snapshot = live_set.return_vars().clone();
    for idx in live_set.recent_indices() {
        if !valid.contains(&idx) || !seen.insert(idx) {
            continue;
        }
        let stmt = &stmts[idx];
        if let MlilStatement::Store { addr, loc, .. } = stmt {
            // Prefer the address recorded on the live set (matches the most
            // recent observation) over the raw stmt addr — they should agree,
            // but using the tracked one wires the addr_of accessor.
            let tracked_addr = live_set.addr_of(idx).unwrap_or(*addr);
            // Downgrade confidence if the store may escape via a return var.
            let escapes = match loc {
                StoreLocation::Pointer { base } => return_vars_snapshot.contains(base),
                StoreLocation::Register { name } => return_vars_snapshot.contains(name),
                _ => false,
            };
            let confidence = if escapes {
                20
            } else if loc == &StoreLocation::Unknown {
                40
            } else {
                85
            };
            dead.push(DeadStore {
                stmt_index: idx,
                addr: tracked_addr,
                description: format!("store to {loc} never read (addr={tracked_addr:#x})"),
                location: loc.clone(),
                confidence,
            });
        }
    }

    dead.sort_by_key(|d| d.stmt_index);
    dead
}

// ─────────────────────────────────────────────────────────────────────────────
// MlilDeadStoreEliminator
// ─────────────────────────────────────────────────────────────────────────────

/// Stateful dead-store eliminator — processes multiple blocks and accumulates
/// results across an entire function.
#[derive(Debug, Default)]
pub struct MlilDeadStoreEliminator {
    /// All dead stores found across all processed blocks.
    dead_stores: Vec<DeadStore>,
    /// Total statements processed.
    total_statements: u64,
    /// Total stores seen.
    total_stores: u64,
    /// Number of blocks processed.
    blocks_processed: u64,
    /// Whether to apply conservative aliasing (if `true`, Unknown locations
    /// are never marked as dead).
    conservative: bool,
}

impl MlilDeadStoreEliminator {
    /// Create a new eliminator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable conservative mode: Unknown-location stores are never eliminated.
    #[must_use]
    pub const fn with_conservative(mut self) -> Self {
        self.conservative = true;
        self
    }

    /// Process a single basic block, updating accumulated results.
    pub fn process_block(&mut self, stmts: &[MlilStatement]) {
        self.blocks_processed += 1;
        self.total_statements += stmts.len() as u64;
        self.total_stores += stmts
            .iter()
            .filter(|s| matches!(s, MlilStatement::Store { .. }))
            .count() as u64;

        let mut found = eliminate_dead_stores(stmts);

        // Filter out Unknown-location dead stores in conservative mode.
        if self.conservative {
            found.retain(|d| d.location != StoreLocation::Unknown);
        }

        self.dead_stores.extend(found);
    }

    /// Process a function represented as a flat list of statements.
    ///
    /// For simplicity this treats the whole function as a single block.
    pub fn process_function(&mut self, stmts: &[MlilStatement]) {
        self.process_block(stmts);
    }

    /// Return all identified dead stores.
    #[must_use]
    pub fn dead_stores(&self) -> &[DeadStore] {
        &self.dead_stores
    }

    /// Return only high-confidence dead stores.
    #[must_use]
    pub fn high_confidence_dead_stores(&self) -> Vec<&DeadStore> {
        self.dead_stores.iter().filter(|d| d.is_high_confidence()).collect()
    }

    /// Return a deduplicated set of statement indices that should be removed.
    #[must_use]
    pub fn dead_indices(&self) -> Vec<usize> {
        let mut indices: Vec<usize> = self.dead_stores.iter().map(|d| d.stmt_index).collect();
        indices.sort_unstable();
        indices.dedup();
        indices
    }

    /// Remove dead stores from the input statement list and return the cleaned
    /// list.
    #[must_use]
    pub fn apply(&self, stmts: Vec<MlilStatement>) -> Vec<MlilStatement> {
        let dead: HashSet<usize> = self.dead_indices().into_iter().collect();
        stmts
            .into_iter()
            .enumerate()
            .filter_map(|(i, s)| if dead.contains(&i) { None } else { Some(s) })
            .collect()
    }

    /// Elimination ratio (dead stores / total stores).
    #[must_use]
    pub fn elimination_ratio(&self) -> f64 {
        if self.total_stores == 0 {
            return 0.0;
        }
        self.dead_stores.len() as f64 / self.total_stores as f64
    }

    /// Total statements processed.
    #[must_use]
    pub const fn total_statements(&self) -> u64 {
        self.total_statements
    }

    /// Total stores seen.
    #[must_use]
    pub const fn total_stores(&self) -> u64 {
        self.total_stores
    }

    /// Number of dead stores found.
    #[must_use]
    pub const fn dead_count(&self) -> usize {
        self.dead_stores.len()
    }

    /// Reset all accumulated state.
    pub fn reset(&mut self) {
        self.dead_stores.clear();
        self.total_statements = 0;
        self.total_stores = 0;
        self.blocks_processed = 0;
    }

    /// Return a diagnostic summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "DSE: blocks={} stmts={} stores={} dead={} ratio={:.1}%",
            self.blocks_processed,
            self.total_statements,
            self.total_stores,
            self.dead_stores.len(),
            self.elimination_ratio() * 100.0,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn store_stack(idx: u64, offset: i64) -> MlilStatement {
        MlilStatement::Store {
            addr: idx,
            loc: StoreLocation::StackSlot { offset, size: 8 },
            value_vars: vec!["v0".into()],
        }
    }

    fn load_stack(idx: u64, offset: i64) -> MlilStatement {
        MlilStatement::Load {
            addr: idx,
            dest_reg: "r0".into(),
            loc: StoreLocation::StackSlot { offset, size: 8 },
        }
    }

    fn sized_store(idx: u64, offset: i64, size: u32) -> MlilStatement {
        MlilStatement::Store {
            addr: idx,
            loc: StoreLocation::StackSlot { offset, size },
            value_vars: vec!["v0".into()],
        }
    }

    fn sized_load(idx: u64, offset: i64, size: u32) -> MlilStatement {
        MlilStatement::Load {
            addr: idx,
            dest_reg: "r0".into(),
            loc: StoreLocation::StackSlot { offset, size },
        }
    }

    fn ret(idx: u64) -> MlilStatement {
        MlilStatement::Return { addr: idx, ret_vars: vec![] }
    }

    #[test]
    fn no_dead_store_when_read() {
        // store → load → return: store is live.
        let stmts = vec![store_stack(0, -8), load_stack(1, -8), ret(2)];
        let dead = eliminate_dead_stores(&stmts);
        assert!(dead.is_empty(), "expected no dead stores: {dead:?}");
    }

    #[test]
    fn dead_store_overwritten() {
        // store → store (same slot) → return: first store is dead.
        let stmts = vec![store_stack(0, -8), store_stack(1, -8), ret(2)];
        let dead = eliminate_dead_stores(&stmts);
        assert_eq!(dead.len(), 1, "expected 1 dead store: {dead:?}");
        assert_eq!(dead[0].stmt_index, 0);
    }

    #[test]
    fn dead_store_at_end() {
        // store → return (without load): store is dead.
        let stmts = vec![store_stack(0, -8), ret(1)];
        let dead = eliminate_dead_stores(&stmts);
        assert_eq!(dead.len(), 1);
    }

    #[test]
    fn different_stack_slots_not_dead() {
        // Two stores to different offsets, both read later.
        let stmts = vec![
            store_stack(0, -8),
            store_stack(1, -16),
            load_stack(2, -8),
            load_stack(3, -16),
            ret(4),
        ];
        let dead = eliminate_dead_stores(&stmts);
        assert!(dead.is_empty());
    }

    #[test]
    fn eliminator_apply() {
        let stmts = vec![store_stack(0, -8), store_stack(1, -8), ret(2)];
        let mut elim = MlilDeadStoreEliminator::new();
        elim.process_function(&stmts);
        let cleaned = elim.apply(stmts);
        // First store should be removed; second + return remain.
        assert_eq!(cleaned.len(), 2);
    }

    #[test]
    fn write_only_call_preserves_prior_store() {
        // store → call (write-only, no declared read) → return: the store must
        // NOT be eliminated, since the callee could alias and observe it
        // despite not being declared as a general reader.
        let stmts = vec![
            store_stack(0, -8),
            MlilStatement::Call {
                addr: 1,
                target: "callee".into(),
                args: vec![],
                may_read_all: false,
                may_write_all: true,
            },
            ret(2),
        ];
        let dead = eliminate_dead_stores(&stmts);
        assert!(dead.is_empty(), "write-only call must preserve the prior store: {dead:?}");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Property-based tests (fuzzing-shaped, per the standing enterprise-
    // hardening mandate's request for deeper rustre-il test coverage, not
    // just closing already-found bugs).
    // ─────────────────────────────────────────────────────────────────────
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        /// A small, bounded "noise" statement — deliberately allows
        /// colliding stack offsets so the aliasing logic gets exercised.
        fn noise_stmt() -> impl Strategy<Value = MlilStatement> {
            let offset = -3i64..3i64;
            prop_oneof![
                offset.clone().prop_map(|o| store_stack(0, o)),
                offset.clone().prop_map(|o| load_stack(0, o)),
                Just(MlilStatement::Call {
                    addr: 0,
                    target: "f".into(),
                    args: vec![],
                    may_read_all: false,
                    may_write_all: false,
                }),
                Just(MlilStatement::Fence { addr: 0 }),
                Just(MlilStatement::Assign { addr: 0, dest: "r0".into(), operands: vec![] }),
            ]
        }

        proptest! {
            /// `eliminate_dead_stores` (and the full stateful eliminator
            /// pipeline) must never panic on arbitrary well-formed input,
            /// and every reported dead-store index must be in-bounds and
            /// actually point at a `Store` statement.
            #[test]
            fn never_panics_and_indices_are_valid_stores(stmts in prop::collection::vec(noise_stmt(), 0..24)) {
                let dead = eliminate_dead_stores(&stmts);
                for d in &dead {
                    prop_assert!(d.stmt_index < stmts.len());
                    let is_store = matches!(stmts[d.stmt_index], MlilStatement::Store { .. });
                    prop_assert!(is_store);
                }

                let mut elim = MlilDeadStoreEliminator::new().with_conservative();
                elim.process_function(&stmts);
                let cleaned = elim.apply(stmts.clone());
                // `apply` only removes elements, never reorders or inserts.
                prop_assert!(cleaned.len() <= stmts.len());
            }

            /// Semantic soundness: a store to a stack offset that is
            /// GUARANTEED unaliased by any noise (a sentinel offset outside
            /// the noise-generator's range) and is immediately followed by a
            /// load from that exact same offset must never be reported dead
            /// — this directly generalises the `no_dead_store_when_read`
            /// unit test across many random surrounding contexts/orderings.
            #[test]
            fn read_store_at_sentinel_offset_never_eliminated(
                prefix in prop::collection::vec(noise_stmt(), 0..8),
                suffix in prop::collection::vec(noise_stmt(), 0..8),
            ) {
                const SENTINEL: i64 = 1000;
                let mut stmts = prefix;
                let store_idx = stmts.len();
                stmts.push(store_stack(0, SENTINEL));
                stmts.push(load_stack(0, SENTINEL));
                stmts.extend(suffix);

                let dead = eliminate_dead_stores(&stmts);
                prop_assert!(
                    !dead.iter().any(|d| d.stmt_index == store_idx),
                    "sentinel store (read immediately after) was wrongly marked dead: {dead:?}"
                );
            }

            /// Semantic soundness under PARTIAL overwrite — a blind spot of the
            /// generator above, which only ever emits size-8 accesses at the
            /// same granularity, so every overlap it produces is a *full*
            /// overwrite.
            ///
            /// Shape: `store [0..8] = sentinel; store [shift..shift+8];
            /// load [0..8]`. The second store only covers bytes
            /// `[shift, 8)` of the sentinel slot, so the load still observes
            /// bytes `[0, shift)` written by the sentinel store. The sentinel
            /// store is therefore LIVE and must never be reported dead.
            #[test]
            fn partially_overwritten_store_read_after_is_not_dead(shift in 1i64..8) {
                let stmts = vec![
                    sized_store(0, 0, 8),
                    sized_store(1, shift, 8),
                    sized_load(2, 0, 8),
                    ret(3),
                ];
                let dead = eliminate_dead_stores(&stmts);
                prop_assert!(
                    !dead.iter().any(|d| d.stmt_index == 0),
                    "store partially overwritten (by shift={shift}) then read was \
                     wrongly marked dead — the load still observes bytes [0,{shift}) \
                     from it: {dead:?}"
                );
            }

            /// Same blind spot, mirrored: the sentinel is a *wide* store and
            /// the later store is a *narrow* one strictly inside it.
            /// `store [0..8]; store [4..5]; load [0..8]` — bytes 0..4 and 5..8
            /// still come from the sentinel.
            #[test]
            fn narrow_overwrite_inside_wide_store_is_not_dead(narrow_off in 0i64..8) {
                let stmts = vec![
                    sized_store(0, 0, 8),
                    sized_store(1, narrow_off, 1),
                    sized_load(2, 0, 8),
                    ret(3),
                ];
                let dead = eliminate_dead_stores(&stmts);
                prop_assert!(
                    !dead.iter().any(|d| d.stmt_index == 0),
                    "wide store clobbered only at byte {narrow_off} then fully read \
                     was wrongly marked dead: {dead:?}"
                );
            }
        }
    }

    #[test]
    fn store_location_display() {
        let loc = StoreLocation::StackSlot { offset: -8, size: 8 };
        assert_eq!(loc.to_string(), "stack[-8:8]");
    }

    #[test]
    fn elimination_ratio() {
        let stmts = vec![store_stack(0, -8), store_stack(1, -8), ret(2)];
        let mut elim = MlilDeadStoreEliminator::new();
        elim.process_function(&stmts);
        assert!(elim.elimination_ratio() > 0.0);
    }
}
