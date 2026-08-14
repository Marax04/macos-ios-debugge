//! Constant propagation specialized for CFF deobfuscation.
//!
//! Implements a forward dataflow analysis that tracks concrete values for
//! registers, stack slots, and global locations.  The dispatcher resolution
//! routine uses this to fold the state variable to a concrete value at each
//! dispatch site, enabling single-target resolution of `call_indirect`-style
//! dispatches.

use std::collections::{HashMap, HashSet, VecDeque};

// ---------------------------------------------------------------------------
// VarId
// ---------------------------------------------------------------------------

/// Identifies a storage location tracked by the propagator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum VarId {
    /// CPU register by index (0 = first GP register per architecture).
    Register(u8),
    /// Stack slot relative to frame pointer.
    StackSlot(i32),
    /// Global / static memory location.
    Global(u64),
}

impl std::fmt::Display for VarId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Register(n) => write!(f, "r{n}"),
            Self::StackSlot(o) => write!(f, "sp[{o}]"),
            Self::Global(a) => write!(f, "g@{a:#x}"),
        }
    }
}

// ---------------------------------------------------------------------------
// BinOpKind
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BinOpKind {
    Add, Sub, Mul, Div, And, Or, Xor, Shl, Shr,
    Eq, Ne, Lt, Le,
}

// ---------------------------------------------------------------------------
// AbstractValue
// ---------------------------------------------------------------------------

/// The abstract domain: either a known concrete value, unknown (may vary),
/// or undefined (unanalysed / unreachable path).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AbstractValue {
    Concrete(i64),
    Unknown,
    Undefined,
}

impl AbstractValue {
    pub const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Undefined, x) | (x, Self::Undefined) => x,
            (Self::Concrete(a), Self::Concrete(b)) if a == b => Self::Concrete(a),
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn is_concrete(self) -> bool {
        matches!(self, Self::Concrete(_))
    }

    #[must_use]
    pub const fn as_concrete(self) -> Option<i64> {
        if let Self::Concrete(v) = self { Some(v) } else { None }
    }
}

impl std::fmt::Display for AbstractValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Concrete(v) => write!(f, "{v:#x}"),
            Self::Unknown => write!(f, "?"),
            Self::Undefined => write!(f, "undef"),
        }
    }
}

// ---------------------------------------------------------------------------
// PropagationState
// ---------------------------------------------------------------------------

/// Lattice state at a single program point.
#[derive(Debug, Clone, Default)]
pub struct PropagationState {
    pub known: HashMap<VarId, i64>,
    pub undefined: HashSet<VarId>,
}

impl PropagationState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn get(&self, var: VarId) -> AbstractValue {
        if self.undefined.contains(&var) {
            AbstractValue::Undefined
        } else if let Some(&v) = self.known.get(&var) {
            AbstractValue::Concrete(v)
        } else {
            AbstractValue::Unknown
        }
    }

    pub fn set_concrete(&mut self, var: VarId, val: i64) {
        self.undefined.remove(&var);
        self.known.insert(var, val);
    }

    pub fn set_unknown(&mut self, var: VarId) {
        self.undefined.remove(&var);
        self.known.remove(&var);
    }

    pub fn set_undefined(&mut self, var: VarId) {
        self.known.remove(&var);
        self.undefined.insert(var);
    }

    /// Merge `other` into `self` (join). Return `true` if `self` changed.
    pub fn join_with(&mut self, other: &Self) -> bool {
        let mut changed = false;

        let other_keys: Vec<VarId> = other.known.keys().chain(other.undefined.iter()).copied().collect();
        let mut all_keys: HashSet<VarId> = self.known.keys().chain(self.undefined.iter()).copied().collect();
        all_keys.extend(other_keys);

        let mut new_known: HashMap<VarId, i64> = HashMap::new();
        let mut new_undef: HashSet<VarId> = HashSet::new();

        for var in all_keys {
            let self_seen = self.known.contains_key(&var) || self.undefined.contains(&var);
            let other_seen = other.known.contains_key(&var) || other.undefined.contains(&var);
            let joined = match (self_seen, other_seen) {
                (true, true) => self.get(var).join(other.get(var)),
                (true, false) => self.get(var),
                (false, true) => other.get(var),
                (false, false) => AbstractValue::Unknown,
            };
            match joined {
                AbstractValue::Concrete(v) => { new_known.insert(var, v); }
                AbstractValue::Undefined => { new_undef.insert(var); }
                AbstractValue::Unknown => {}
            }
        }

        if new_known != self.known || new_undef != self.undefined {
            self.known = new_known;
            self.undefined = new_undef;
            changed = true;
        }
        changed
    }
}

// ---------------------------------------------------------------------------
// Transfer functions
// ---------------------------------------------------------------------------

/// Apply an assignment `dst = val`.
pub fn transfer_assign(dst: VarId, val: AbstractValue, state: &mut PropagationState) {
    match val {
        AbstractValue::Concrete(v) => state.set_concrete(dst, v),
        AbstractValue::Unknown => state.set_unknown(dst),
        AbstractValue::Undefined => state.set_undefined(dst),
    }
}

/// Apply a phi-node `dst = phi(srcs)` where each source is `(var, block_addr)`.
pub fn transfer_phi(
    dst: VarId,
    srcs: &[(VarId, u64)],
    state: &mut PropagationState,
) {
    if srcs.is_empty() {
        state.set_undefined(dst);
        return;
    }
    let first = state.get(srcs[0].0);
    let joined = srcs[1..].iter().fold(first, |acc, &(var, _)| acc.join(state.get(var)));
    transfer_assign(dst, joined, state);
}

/// Constant-fold a binary operation.
pub fn transfer_binary(
    dst: VarId,
    op: BinOpKind,
    a: AbstractValue,
    b: AbstractValue,
    state: &mut PropagationState,
) {
    let result = eval_binary(op, a, b);
    transfer_assign(dst, result, state);
}

/// Evaluate a binary operation over abstract values.
pub fn eval_binary(op: BinOpKind, a: AbstractValue, b: AbstractValue) -> AbstractValue {
    match (a, b) {
        (AbstractValue::Concrete(av), AbstractValue::Concrete(bv)) => {
            let result: Option<i64> = match op {
                BinOpKind::Add => av.checked_add(bv),
                BinOpKind::Sub => av.checked_sub(bv),
                BinOpKind::Mul => av.checked_mul(bv),
                BinOpKind::Div => {
                    if bv == 0 { return AbstractValue::Unknown; }
                    av.checked_div(bv)
                }
                BinOpKind::And => Some(av & bv),
                BinOpKind::Or  => Some(av | bv),
                BinOpKind::Xor => Some(av ^ bv),
                BinOpKind::Shl => {
                    if !(0..64).contains(&bv) { return AbstractValue::Unknown; }
                    Some(av << bv)
                }
                BinOpKind::Shr => {
                    if !(0..64).contains(&bv) { return AbstractValue::Unknown; }
                    Some(av >> bv)
                }
                BinOpKind::Eq  => Some(i64::from(av == bv)),
                BinOpKind::Ne  => Some(i64::from(av != bv)),
                BinOpKind::Lt  => Some(i64::from(av <  bv)),
                BinOpKind::Le  => Some(i64::from(av <= bv)),
            };
            result.map_or(AbstractValue::Unknown, AbstractValue::Concrete)
        }
        (AbstractValue::Undefined, _) | (_, AbstractValue::Undefined) => AbstractValue::Undefined,
        _ => AbstractValue::Unknown,
    }
}

// ---------------------------------------------------------------------------
// DispatcherInfo
// ---------------------------------------------------------------------------

/// Information about a CFF dispatcher needed by the resolver.
#[derive(Debug, Clone)]
pub struct DispatcherInfo {
    /// The `VarId` that holds the state variable.
    pub state_var: VarId,
    /// Maps concrete state values to block addresses.
    pub state_to_block: HashMap<i64, u64>,
}

impl DispatcherInfo {
    #[must_use]
    pub fn new(state_var: VarId) -> Self {
        Self {
            state_var,
            state_to_block: HashMap::new(),
        }
    }

    pub fn register_state(&mut self, value: i64, block_addr: u64) {
        self.state_to_block.insert(value, block_addr);
    }
}

/// Resolve the dispatch target from a concrete state variable.
///
/// Returns the full 64-bit block address so that binaries with code above
/// `0xFFFF_FFFF` are handled correctly.
#[must_use]
pub fn resolve_state_variable(
    dispatcher: &DispatcherInfo,
    state: &PropagationState,
) -> Option<u64> {
    let val = state.get(dispatcher.state_var).as_concrete()?;
    let &target_addr = dispatcher.state_to_block.get(&val)?;
    Some(target_addr)
}

// ---------------------------------------------------------------------------
// ConstantPropagatorCff — worklist algorithm
// ---------------------------------------------------------------------------

/// An instruction in our micro IR for the propagator.
#[derive(Debug, Clone)]
pub enum MicroInsn {
    Assign { dst: VarId, val: AbstractValue },
    BinaryOp { dst: VarId, op: BinOpKind, lhs: VarId, rhs: VarId },
    BinaryOpImm { dst: VarId, op: BinOpKind, lhs: VarId, rhs: i64 },
    Phi { dst: VarId, srcs: Vec<(VarId, u64)> },
    Kill(VarId),
}

/// A basic block in the propagator's IR.
#[derive(Debug, Clone)]
pub struct PropBlock {
    pub addr: u64,
    pub insns: Vec<MicroInsn>,
    pub successors: Vec<u64>,
    pub predecessors: Vec<u64>,
}

impl PropBlock {
    #[must_use]
    pub const fn new(addr: u64) -> Self {
        Self { addr, insns: Vec::new(), successors: Vec::new(), predecessors: Vec::new() }
    }
}

/// The constant propagator.
#[derive(Debug)]
pub struct ConstantPropagatorCff {
    pub blocks: HashMap<u64, PropBlock>,
    pub entry: u64,
    /// Per-block output states.
    pub out_states: HashMap<u64, PropagationState>,
}

impl ConstantPropagatorCff {
    #[must_use]
    pub fn new(entry: u64) -> Self {
        Self {
            blocks: HashMap::new(),
            entry,
            out_states: HashMap::new(),
        }
    }

    pub fn add_block(&mut self, block: PropBlock) {
        self.blocks.insert(block.addr, block);
    }

    // -----------------------------------------------------------------------
    // Worklist propagation
    // -----------------------------------------------------------------------

    /// Execute forward dataflow until a fixed point.
    pub fn propagate_worklist(&mut self, initial: PropagationState) {
        // Initialise all out-states to empty
        let addrs: Vec<u64> = self.blocks.keys().copied().collect();
        for addr in addrs {
            self.out_states.insert(addr, PropagationState::new());
        }

        let mut worklist: VecDeque<u64> = VecDeque::new();
        worklist.push_back(self.entry);
        let mut in_states: HashMap<u64, PropagationState> = HashMap::new();
        in_states.insert(self.entry, initial);

        while let Some(addr) = worklist.pop_front() {
            let block = match self.blocks.get(&addr) {
                Some(b) => b.clone(),
                None => continue,
            };

            let in_state = in_states.entry(addr).or_default().clone();
            let out_state = Self::transfer_block(&block, in_state);

            for &succ in &block.successors {
                let entry = in_states.entry(succ).or_default();
                let changed = entry.join_with(&out_state);
                if changed {
                    worklist.push_back(succ);
                }
            }

            self.out_states.insert(addr, out_state);
        }
    }

    /// Transfer function for a block: apply each instruction to the state.
    fn transfer_block(block: &PropBlock, mut state: PropagationState) -> PropagationState {
        for insn in &block.insns {
            match insn {
                MicroInsn::Assign { dst, val } => {
                    transfer_assign(*dst, *val, &mut state);
                }
                MicroInsn::BinaryOp { dst, op, lhs, rhs } => {
                    let a = state.get(*lhs);
                    let b = state.get(*rhs);
                    transfer_binary(*dst, *op, a, b, &mut state);
                }
                MicroInsn::BinaryOpImm { dst, op, lhs, rhs } => {
                    let a = state.get(*lhs);
                    let b = AbstractValue::Concrete(*rhs);
                    transfer_binary(*dst, *op, a, b, &mut state);
                }
                MicroInsn::Phi { dst, srcs } => {
                    transfer_phi(*dst, srcs, &mut state);
                }
                MicroInsn::Kill(var) => {
                    state.set_unknown(*var);
                }
            }
        }
        state
    }

    /// Get the out-state for a block after propagation.
    #[must_use]
    pub fn out_state(&self, addr: u64) -> Option<&PropagationState> {
        self.out_states.get(&addr)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concrete_add() {
        let result = eval_binary(
            BinOpKind::Add,
            AbstractValue::Concrete(3),
            AbstractValue::Concrete(4),
        );
        assert_eq!(result, AbstractValue::Concrete(7));
    }

    #[test]
    fn unknown_add_yields_unknown() {
        let result = eval_binary(BinOpKind::Add, AbstractValue::Unknown, AbstractValue::Concrete(1));
        assert_eq!(result, AbstractValue::Unknown);
    }

    #[test]
    fn div_by_zero_unknown() {
        let result = eval_binary(BinOpKind::Div, AbstractValue::Concrete(10), AbstractValue::Concrete(0));
        assert_eq!(result, AbstractValue::Unknown);
    }

    #[test]
    fn eq_fold() {
        let r = eval_binary(BinOpKind::Eq, AbstractValue::Concrete(5), AbstractValue::Concrete(5));
        assert_eq!(r, AbstractValue::Concrete(1));
    }

    #[test]
    fn join_same_concrete() {
        let a = AbstractValue::Concrete(42);
        let b = AbstractValue::Concrete(42);
        assert_eq!(a.join(b), AbstractValue::Concrete(42));
    }

    #[test]
    fn join_different_concrete() {
        let a = AbstractValue::Concrete(1);
        let b = AbstractValue::Concrete(2);
        assert_eq!(a.join(b), AbstractValue::Unknown);
    }

    #[test]
    fn join_undefined_with_concrete() {
        let a = AbstractValue::Undefined;
        let b = AbstractValue::Concrete(7);
        assert_eq!(a.join(b), AbstractValue::Concrete(7));
    }

    #[test]
    fn transfer_assign_concrete() {
        let mut state = PropagationState::new();
        let var = VarId::Register(0);
        transfer_assign(var, AbstractValue::Concrete(100), &mut state);
        assert_eq!(state.get(var), AbstractValue::Concrete(100));
    }

    #[test]
    fn transfer_assign_unknown() {
        let mut state = PropagationState::new();
        let var = VarId::Register(0);
        state.set_concrete(var, 42);
        transfer_assign(var, AbstractValue::Unknown, &mut state);
        assert_eq!(state.get(var), AbstractValue::Unknown);
    }

    #[test]
    fn transfer_phi_all_same() {
        let mut state = PropagationState::new();
        let a = VarId::Register(0);
        let b = VarId::Register(1);
        state.set_concrete(a, 5);
        state.set_concrete(b, 5);
        let dst = VarId::Register(2);
        transfer_phi(dst, &[(a, 0x100), (b, 0x200)], &mut state);
        assert_eq!(state.get(dst), AbstractValue::Concrete(5));
    }

    #[test]
    fn transfer_phi_different() {
        let mut state = PropagationState::new();
        let a = VarId::Register(0);
        let b = VarId::Register(1);
        state.set_concrete(a, 1);
        state.set_concrete(b, 2);
        let dst = VarId::Register(2);
        transfer_phi(dst, &[(a, 0x100), (b, 0x200)], &mut state);
        assert_eq!(state.get(dst), AbstractValue::Unknown);
    }

    #[test]
    fn resolve_state_variable_success() {
        let mut di = DispatcherInfo::new(VarId::Register(0));
        di.register_state(1, 0x300);
        di.register_state(2, 0x400);
        let mut state = PropagationState::new();
        state.set_concrete(VarId::Register(0), 1);
        assert_eq!(resolve_state_variable(&di, &state), Some(0x300u64));
    }

    #[test]
    fn resolve_state_variable_unknown() {
        let di = DispatcherInfo::new(VarId::Register(0));
        let state = PropagationState::new();
        assert!(resolve_state_variable(&di, &state).is_none());
    }

    #[test]
    fn worklist_simple_linear() {
        let r0 = VarId::Register(0);
        let r1 = VarId::Register(1);

        let mut block_a = PropBlock::new(0x100);
        block_a.insns.push(MicroInsn::Assign { dst: r0, val: AbstractValue::Concrete(10) });
        block_a.successors.push(0x200);

        let mut block_b = PropBlock::new(0x200);
        block_b.insns.push(MicroInsn::BinaryOpImm { dst: r1, op: BinOpKind::Add, lhs: r0, rhs: 5 });
        block_b.predecessors.push(0x100);

        let mut prop = ConstantPropagatorCff::new(0x100);
        prop.add_block(block_a);
        prop.add_block(block_b);
        prop.propagate_worklist(PropagationState::new());

        let out_b = prop.out_state(0x200).unwrap();
        assert_eq!(out_b.get(r1), AbstractValue::Concrete(15));
    }

    #[test]
    fn shl_fold() {
        let r = eval_binary(BinOpKind::Shl, AbstractValue::Concrete(1), AbstractValue::Concrete(4));
        assert_eq!(r, AbstractValue::Concrete(16));
    }

    #[test]
    fn xor_fold() {
        let r = eval_binary(BinOpKind::Xor, AbstractValue::Concrete(0xFF), AbstractValue::Concrete(0x0F));
        assert_eq!(r, AbstractValue::Concrete(0xF0));
    }
}
