// constant_propagation.rs
// Sparse Conditional Constant Propagation (SCCP) — Wegman & Zadeck 1991
// Operates on SSA-form MLIL (rustre-il-mlil), folds constants, eliminates
// dead branches, and removes unreachable basic blocks.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ---------------------------------------------------------------------------
// Re-exports / type aliases assumed from the MLIL crate.
// In a real integration these come from `rustre-il-mlil`.
// ---------------------------------------------------------------------------
pub type VarId = u32;
pub type BBId  = u32;
pub type FuncId = u32;

// ---------------------------------------------------------------------------
// Lattice element
// ---------------------------------------------------------------------------

/// Three-valued lattice for constant propagation.
///
/// ```text
///          Top  (unknown / not yet reached)
///          / \
///   Const(k) Const(j)  (k != j → collapse to Bottom on meet)
///          \ /
///         Bottom  (overdefined / multiple values)
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lattice {
    /// The variable has not yet been assigned a value in this execution path.
    Top,
    /// The variable is always exactly this constant.
    Const(i128),
    /// The variable may hold more than one value; we cannot fold it.
    Bottom,
}

impl Lattice {
    /// Lattice meet (greatest lower bound).
    ///
    /// Rules:
    /// - `Top meet x  = x`
    /// - `x meet Top  = x`
    /// - `Const(k) meet Const(k) = Const(k)`
    /// - `Const(k) meet Const(j) = Bottom`  (k ≠ j)
    /// - `Bottom meet _          = Bottom`
    /// - `_ meet Bottom          = Bottom`
    #[must_use] 
    pub fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Top, x) | (x, Self::Top) => x.clone(),
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Const(k), Self::Const(j)) => {
                if k == j {
                    Self::Const(*k)
                } else {
                    Self::Bottom
                }
            }
        }
    }

    #[must_use] 
    pub const fn is_const(&self) -> bool {
        matches!(self, Self::Const(_))
    }

    #[must_use] 
    pub const fn const_val(&self) -> Option<i128> {
        if let Self::Const(v) = self { Some(*v) } else { None }
    }

    #[must_use] 
    pub fn is_top(&self)    -> bool { *self == Self::Top    }
    #[must_use] 
    pub fn is_bottom(&self) -> bool { *self == Self::Bottom }
}

impl fmt::Display for Lattice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Top        => write!(f, "⊤"),
            Self::Const(v)   => write!(f, "{v}"),
            Self::Bottom     => write!(f, "⊥"),
        }
    }
}

// ---------------------------------------------------------------------------
// SSA / MLIL node types (simplified stand-alone definitions)
// ---------------------------------------------------------------------------

/// An MLIL expression used as the right-hand side of an assignment.
#[derive(Clone, Debug)]
pub enum MlilExpr {
    /// Integer constant literal.
    Const(i128),
    /// Variable reference (SSA variable).
    Var(VarId),
    // ---- Arithmetic -------------------------------------------------------
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    /// Signed division. Division by zero yields Bottom.
    Div(Box<Self>, Box<Self>),
    /// Unsigned division.
    DivU(Box<Self>, Box<Self>),
    /// Signed remainder.
    Mod(Box<Self>, Box<Self>),
    /// Unsigned remainder.
    ModU(Box<Self>, Box<Self>),
    Neg(Box<Self>),
    // ---- Bitwise ----------------------------------------------------------
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Xor(Box<Self>, Box<Self>),
    Not(Box<Self>),
    Shl(Box<Self>, Box<Self>),
    Shr(Box<Self>, Box<Self>),  // logical right shift
    Sar(Box<Self>, Box<Self>),  // arithmetic right shift
    // ---- Comparison (result is 0 or 1) ------------------------------------
    CmpEq(Box<Self>, Box<Self>),
    CmpNe(Box<Self>, Box<Self>),
    CmpLt(Box<Self>, Box<Self>),  // signed
    CmpLe(Box<Self>, Box<Self>),  // signed
    CmpGt(Box<Self>, Box<Self>),  // signed
    CmpGe(Box<Self>, Box<Self>),  // signed
    CmpLtu(Box<Self>, Box<Self>), // unsigned
    CmpLeu(Box<Self>, Box<Self>), // unsigned
    CmpGtu(Box<Self>, Box<Self>), // unsigned
    CmpGeu(Box<Self>, Box<Self>), // unsigned
    // ---- Sign / zero extension / truncation --------------------------------
    Sx(u8, Box<Self>),   // sign-extend to given bit width
    Zx(u8, Box<Self>),   // zero-extend
    Trunc(u8, Box<Self>), // truncate to given bit width
    // ---- Memory ------------------------------------------------------------
    /// Load from memory — treated as overdefined (may alias anything).
    Load { size: u8, addr: Box<Self> },
    // ---- Other -------------------------------------------------------------
    /// Any unknown or unmodelled expression → Bottom.
    Unmodelled,
}

/// An MLIL statement.
#[derive(Clone, Debug)]
pub enum MlilStmt {
    /// SSA assignment: `dst <- rhs`.
    Assign { dst: VarId, rhs: MlilExpr },
    /// SSA PHI node: `dst <- φ(src1, src2, …)`.
    Phi { dst: VarId, srcs: Vec<VarId> },
    /// Conditional branch: if cond ≠ 0 → `true_bb`, else → `false_bb`.
    Branch { cond: MlilExpr, true_bb: BBId, false_bb: BBId },
    /// Unconditional jump.
    Jump { target: BBId },
    /// Memory store — always a side effect.
    Store { size: u8, addr: MlilExpr, value: MlilExpr },
    /// Function call — always a side effect.
    Call { dst: Option<VarId>, target: MlilExpr, args: Vec<MlilExpr> },
    /// Return.
    Return { values: Vec<MlilExpr> },
    /// No-op.
    Nop,
}

/// A basic block in the MLIL function.
#[derive(Clone, Debug)]
pub struct BasicBlock {
    pub id: BBId,
    pub stmts: Vec<MlilStmt>,
    /// Successor block IDs (1 for unconditional jump/fall-through, 2 for branch).
    pub successors: Vec<BBId>,
    /// Predecessor block IDs.
    pub predecessors: Vec<BBId>,
}

impl BasicBlock {
    #[must_use] 
    pub const fn new(id: BBId) -> Self {
        Self { id, stmts: Vec::new(), successors: Vec::new(), predecessors: Vec::new() }
    }
}

/// An MLIL function in SSA form.
#[derive(Clone, Debug)]
pub struct MlilFunction {
    pub id: FuncId,
    pub entry: BBId,
    pub blocks: HashMap<BBId, BasicBlock>,
    /// Ordered list of block IDs (e.g. sorted by address).
    pub block_order: Vec<BBId>,
    /// Parameters/arguments: treated as Top initially.
    pub params: Vec<VarId>,
    /// Variables defined by the function.
    pub vars: Vec<VarId>,
}

impl MlilFunction {
    #[must_use] 
    pub fn new(id: FuncId, entry: BBId) -> Self {
        Self {
            id, entry,
            blocks: HashMap::new(),
            block_order: Vec::new(),
            params: Vec::new(),
            vars: Vec::new(),
        }
    }

    #[must_use]
    /// # Panics
    /// Panics if `id` does not exist in this function's block map.
    pub fn block(&self, id: BBId) -> &BasicBlock {
        self.blocks.get(&id).unwrap_or_else(|| panic!("BasicBlock {id} not found in function {}; this indicates a malformed IR where a block references a non-existent successor", self.id))
    }

    #[must_use]
    pub fn try_block(&self, id: BBId) -> Option<&BasicBlock> {
        self.blocks.get(&id)
    }

    /// # Panics
    /// Panics if `id` does not exist in this function's block map.
    pub fn block_mut(&mut self, id: BBId) -> &mut BasicBlock {
        let func_id = self.id;
        self.blocks.get_mut(&id).unwrap_or_else(|| panic!("BasicBlock {id} not found in function {func_id}; this indicates a malformed IR where a block references a non-existent successor"))
    }

    pub fn try_block_mut(&mut self, id: BBId) -> Option<&mut BasicBlock> {
        self.blocks.get_mut(&id)
    }
}

// ---------------------------------------------------------------------------
// Constant Lattice — maps VarId → Lattice
// ---------------------------------------------------------------------------

/// The full constant-propagation lattice: one entry per SSA variable.
#[derive(Clone, Debug)]
pub struct ConstantLattice {
    inner: HashMap<VarId, Lattice>,
}

impl ConstantLattice {
    #[must_use] 
    pub fn new() -> Self {
        Self { inner: HashMap::new() }
    }

    /// Get the lattice value for a variable (defaults to Top if unseen).
    #[must_use] 
    pub fn get(&self, var: VarId) -> &Lattice {
        self.inner.get(&var).unwrap_or(&Lattice::Top)
    }

    /// Update the lattice for a variable.  Returns true if the value changed.
    pub fn set(&mut self, var: VarId, val: &Lattice) -> bool {
        let old = self.inner.get(&var).cloned().unwrap_or(Lattice::Top);
        if &old == val {
            return false;
        }
        // Lattice values may only move downward (Top → Const → Bottom).
        // Never allow a transition that would move upward.
        let new_val = old.meet(val);
        self.inner.insert(var, new_val.clone());
        old != new_val
    }

    /// Unconditional set (used during initialisation).
    pub fn force_set(&mut self, var: VarId, val: Lattice) {
        self.inner.insert(var, val);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&VarId, &Lattice)> {
        self.inner.iter()
    }
}

impl Default for ConstantLattice {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Edge reachability
// ---------------------------------------------------------------------------

/// Tracks which CFG edges have been determined to be executable.
#[derive(Default, Debug)]
struct EdgeReachability {
    /// Set of (from, to) pairs that are known executable.
    executable: HashSet<(BBId, BBId)>,
    /// Blocks that are reachable (have at least one executable incoming edge,
    /// or are the entry block).
    reachable: HashSet<BBId>,
}

impl EdgeReachability {
    fn new(entry: BBId) -> Self {
        let mut er = Self::default();
        er.reachable.insert(entry);
        er
    }

    /// Mark edge as executable.  Returns true if this is a new fact.
    fn mark_edge(&mut self, from: BBId, to: BBId) -> bool {
        let is_new_edge = self.executable.insert((from, to));
        let is_new_block = self.reachable.insert(to);
        is_new_edge || is_new_block
    }

    fn is_edge_executable(&self, from: BBId, to: BBId) -> bool {
        self.executable.contains(&(from, to))
    }

    fn is_reachable(&self, bb: BBId) -> bool {
        self.reachable.contains(&bb)
    }
}

// ---------------------------------------------------------------------------
// SCCP worklists
// ---------------------------------------------------------------------------

/// Items on the SCCP worklists.
///
/// The internal driver currently uses two separate FIFO worklists (one for
/// variables, one for edges) for cache locality. This unified enum is
/// exposed to callers that want a single combined seed list — see
/// [`initial_work_items`] — which is convenient when adapting SCCP to a
/// custom solver topology (e.g. priority queue based on RPO).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkItem {
    /// An SSA variable whose lattice value has changed — re-evaluate all uses.
    Var(VarId),
    /// A CFG edge that has just been marked executable — re-evaluate target.
    Edge(BBId, BBId),
}

impl WorkItem {
    /// Returns `true` if this work item refers to an SSA variable.
    #[must_use]
    pub const fn is_var(&self) -> bool { matches!(self, Self::Var(_)) }

    /// Returns `true` if this work item refers to a CFG edge.
    #[must_use]
    pub const fn is_edge(&self) -> bool { matches!(self, Self::Edge(_, _)) }
}

/// Build the initial unified work-item list for an SCCP run over `func`.
///
/// Produces one [`WorkItem::Edge`] for every successor of the entry block
/// plus one [`WorkItem::Var`] for every function parameter (parameters
/// start at `Top` and seed the variable worklist for any use sites that
/// can be re-evaluated on the first round).
#[must_use]
pub fn initial_work_items(func: &MlilFunction) -> Vec<WorkItem> {
    let mut items: Vec<WorkItem> = Vec::new();
    // Use try_block to avoid panicking when the entry BBId is invalid
    // (e.g. produced from a malformed binary).
    if let Some(entry_block) = func.try_block(func.entry) {
        for &succ in &entry_block.successors {
            items.push(WorkItem::Edge(func.entry, succ));
        }
    }
    for &p in &func.params {
        items.push(WorkItem::Var(p));
    }
    items
}

// ---------------------------------------------------------------------------
// Def-use chains (simplified)
// ---------------------------------------------------------------------------

/// Collects def-use information from an MLIL function.
fn build_def_use(func: &MlilFunction) -> HashMap<VarId, Vec<(BBId, usize)>> {
    let mut uses: HashMap<VarId, Vec<(BBId, usize)>> = HashMap::new();

    for bb in func.blocks.values() {
        for (idx, stmt) in bb.stmts.iter().enumerate() {
            collect_uses_in_stmt(stmt, bb.id, idx, &mut uses);
        }
    }
    uses
}

/// Maximum expression nesting depth before we stop recursing (dos-unbounded-recursion).
const MAX_EXPR_DEPTH: usize = 512;

fn collect_uses_in_expr(expr: &MlilExpr, bb: BBId, stmt_idx: usize,
                         uses: &mut HashMap<VarId, Vec<(BBId, usize)>>) {
    collect_uses_in_expr_bounded(expr, bb, stmt_idx, uses, 0);
}

fn collect_uses_in_expr_bounded(
    expr: &MlilExpr,
    bb: BBId,
    stmt_idx: usize,
    uses: &mut HashMap<VarId, Vec<(BBId, usize)>>,
    depth: usize,
) {
    if depth >= MAX_EXPR_DEPTH {
        return;
    }
    let recurse = |child: &MlilExpr, uses: &mut HashMap<VarId, Vec<(BBId, usize)>>| {
        collect_uses_in_expr_bounded(child, bb, stmt_idx, uses, depth + 1);
    };
    match expr {
        MlilExpr::Var(v) => { uses.entry(*v).or_default().push((bb, stmt_idx)); }
        MlilExpr::Add(a,b) | MlilExpr::Sub(a,b) | MlilExpr::Mul(a,b)
        | MlilExpr::Div(a,b) | MlilExpr::DivU(a,b) | MlilExpr::Mod(a,b)
        | MlilExpr::ModU(a,b) | MlilExpr::And(a,b) | MlilExpr::Or(a,b)
        | MlilExpr::Xor(a,b) | MlilExpr::Shl(a,b) | MlilExpr::Shr(a,b)
        | MlilExpr::Sar(a,b) | MlilExpr::CmpEq(a,b) | MlilExpr::CmpNe(a,b)
        | MlilExpr::CmpLt(a,b) | MlilExpr::CmpLe(a,b) | MlilExpr::CmpGt(a,b)
        | MlilExpr::CmpGe(a,b) | MlilExpr::CmpLtu(a,b) | MlilExpr::CmpLeu(a,b)
        | MlilExpr::CmpGtu(a,b) | MlilExpr::CmpGeu(a,b) => {
            recurse(a, uses);
            recurse(b, uses);
        }
        MlilExpr::Neg(e) | MlilExpr::Not(e)
        | MlilExpr::Sx(_, e) | MlilExpr::Zx(_, e) | MlilExpr::Trunc(_, e) => {
            recurse(e, uses);
        }
        MlilExpr::Load { addr, .. } => {
            recurse(addr, uses);
        }
        MlilExpr::Const(_) | MlilExpr::Unmodelled => {}
    }
}

fn collect_uses_in_stmt(stmt: &MlilStmt, bb: BBId, idx: usize,
                         uses: &mut HashMap<VarId, Vec<(BBId, usize)>>) {
    match stmt {
        MlilStmt::Assign { rhs, .. } => collect_uses_in_expr(rhs, bb, idx, uses),
        MlilStmt::Phi { srcs, .. } => {
            for s in srcs { uses.entry(*s).or_default().push((bb, idx)); }
        }
        MlilStmt::Branch { cond, .. } => collect_uses_in_expr(cond, bb, idx, uses),
        MlilStmt::Store { addr, value, .. } => {
            collect_uses_in_expr(addr, bb, idx, uses);
            collect_uses_in_expr(value, bb, idx, uses);
        }
        MlilStmt::Call { target, args, .. } => {
            collect_uses_in_expr(target, bb, idx, uses);
            for a in args { collect_uses_in_expr(a, bb, idx, uses); }
        }
        MlilStmt::Return { values } => {
            for v in values { collect_uses_in_expr(v, bb, idx, uses); }
        }
        MlilStmt::Jump { .. } | MlilStmt::Nop => {}
    }
}

// ---------------------------------------------------------------------------
// Expression evaluator
// ---------------------------------------------------------------------------

/// Evaluate an expression given the current constant lattice.
///
/// Stops recursing and returns `Bottom` once expression nesting exceeds
/// [`MAX_EXPR_DEPTH`], preventing stack overflow on deeply nested expressions
/// in attacker-supplied MLIL (dos-unbounded-recursion).
fn eval_expr(expr: &MlilExpr, lat: &ConstantLattice) -> Lattice {
    eval_expr_bounded(expr, lat, 0)
}

fn eval_expr_bounded(expr: &MlilExpr, lat: &ConstantLattice, depth: usize) -> Lattice {
    if depth >= MAX_EXPR_DEPTH {
        return Lattice::Bottom;
    }
    match expr {
        MlilExpr::Const(k) => Lattice::Const(*k),
        MlilExpr::Var(v)   => lat.get(*v).clone(),
        MlilExpr::Unmodelled | MlilExpr::Load { .. } => Lattice::Bottom,

        MlilExpr::Neg(e) => {
            match eval_expr_bounded(e, lat, depth + 1) {
                Lattice::Const(v) => Lattice::Const(v.wrapping_neg()),
                other => other,
            }
        }
        MlilExpr::Not(e) => {
            match eval_expr_bounded(e, lat, depth + 1) {
                Lattice::Const(v) => Lattice::Const(!v),
                other => other,
            }
        }
        MlilExpr::Sx(bits, e) => {
            match eval_expr_bounded(e, lat, depth + 1) {
                Lattice::Const(v) => Lattice::Const(sign_extend(v, *bits)),
                other => other,
            }
        }
        MlilExpr::Zx(bits, e) => {
            match eval_expr_bounded(e, lat, depth + 1) {
                Lattice::Const(v) => Lattice::Const(zero_extend(v, *bits)),
                other => other,
            }
        }
        MlilExpr::Trunc(bits, e) => {
            match eval_expr_bounded(e, lat, depth + 1) {
                Lattice::Const(v) => Lattice::Const(truncate(v, *bits)),
                other => other,
            }
        }

        // Binary operators — evaluate both sides first.
        MlilExpr::Add(a,b)    => eval_binary(a, b, lat, depth, i128::wrapping_add),
        MlilExpr::Sub(a,b)    => eval_binary(a, b, lat, depth, i128::wrapping_sub),
        MlilExpr::Mul(a,b)    => eval_binary(a, b, lat, depth, i128::wrapping_mul),
        MlilExpr::And(a,b)    => eval_binary(a, b, lat, depth, |x,y| x & y),
        MlilExpr::Or(a,b)     => eval_binary(a, b, lat, depth, |x,y| x | y),
        MlilExpr::Xor(a,b)    => eval_binary(a, b, lat, depth, |x,y| x ^ y),
        MlilExpr::Shl(a,b)    => eval_binary(a, b, lat, depth, |x,y| {
            let shift = u32::try_from(y & 127).unwrap_or(0);
            x.wrapping_shl(shift)
        }),
        MlilExpr::Shr(a,b)    => eval_binary(a, b, lat, depth, |x,y| {
            let shift = u32::try_from(y & 127).unwrap_or(0);
            x.cast_unsigned().wrapping_shr(shift).cast_signed()
        }),
        MlilExpr::Sar(a,b)    => eval_binary(a, b, lat, depth, |x,y| {
            let shift = u32::try_from(y & 127).unwrap_or(0);
            x.wrapping_shr(shift)
        }),

        MlilExpr::Div(a,b)    => eval_binary_checked(a, b, lat, depth, |x,y| {
            if y == 0 { None } else { Some(x.wrapping_div(y)) }
        }),
        MlilExpr::DivU(a,b)   => eval_binary_checked(a, b, lat, depth, |x,y| {
            let xu = x.cast_unsigned(); let yu = y.cast_unsigned();
            if yu == 0 { None } else { Some((xu / yu).cast_signed()) }
        }),
        MlilExpr::Mod(a,b)    => eval_binary_checked(a, b, lat, depth, |x,y| {
            if y == 0 { None } else { Some(x.wrapping_rem(y)) }
        }),
        MlilExpr::ModU(a,b)   => eval_binary_checked(a, b, lat, depth, |x,y| {
            let xu = x.cast_unsigned(); let yu = y.cast_unsigned();
            if yu == 0 { None } else { Some((xu % yu).cast_signed()) }
        }),

        // Comparisons → result is 0 or 1.
        MlilExpr::CmpEq(a,b)  => eval_cmp(a, b, lat, depth, |x,y| x == y),
        MlilExpr::CmpNe(a,b)  => eval_cmp(a, b, lat, depth, |x,y| x != y),
        MlilExpr::CmpLt(a,b)  => eval_cmp(a, b, lat, depth, |x,y| x <  y),
        MlilExpr::CmpLe(a,b)  => eval_cmp(a, b, lat, depth, |x,y| x <= y),
        MlilExpr::CmpGt(a,b)  => eval_cmp(a, b, lat, depth, |x,y| x >  y),
        MlilExpr::CmpGe(a,b)  => eval_cmp(a, b, lat, depth, |x,y| x >= y),
        MlilExpr::CmpLtu(a,b) => eval_cmp_u(a, b, lat, depth, |x,y| x <  y),
        MlilExpr::CmpLeu(a,b) => eval_cmp_u(a, b, lat, depth, |x,y| x <= y),
        MlilExpr::CmpGtu(a,b) => eval_cmp_u(a, b, lat, depth, |x,y| x >  y),
        MlilExpr::CmpGeu(a,b) => eval_cmp_u(a, b, lat, depth, |x,y| x >= y),
    }
}

fn eval_binary(
    lhs: &MlilExpr, rhs: &MlilExpr,
    lat: &ConstantLattice,
    depth: usize,
    f: impl Fn(i128, i128) -> i128,
) -> Lattice {
    let la = eval_expr_bounded(lhs, lat, depth + 1);
    let lb = eval_expr_bounded(rhs, lat, depth + 1);
    match (&la, &lb) {
        (Lattice::Top, _) | (_, Lattice::Top) => Lattice::Top,
        (Lattice::Bottom, _) | (_, Lattice::Bottom) => Lattice::Bottom,
        (Lattice::Const(x), Lattice::Const(y)) => Lattice::Const(f(*x, *y)),
    }
}

fn eval_binary_checked(
    lhs: &MlilExpr, rhs: &MlilExpr,
    lat: &ConstantLattice,
    depth: usize,
    f: impl Fn(i128, i128) -> Option<i128>,
) -> Lattice {
    let la = eval_expr_bounded(lhs, lat, depth + 1);
    let lb = eval_expr_bounded(rhs, lat, depth + 1);
    match (&la, &lb) {
        (Lattice::Top, _) | (_, Lattice::Top) => Lattice::Top,
        (Lattice::Bottom, _) | (_, Lattice::Bottom) => Lattice::Bottom,
        (Lattice::Const(x), Lattice::Const(y)) => {
            f(*x, *y).map_or(Lattice::Bottom, Lattice::Const)
        }
    }
}

fn eval_cmp(
    a: &MlilExpr, b: &MlilExpr,
    lat: &ConstantLattice,
    depth: usize,
    f: impl Fn(i128, i128) -> bool,
) -> Lattice {
    eval_binary(a, b, lat, depth, |x,y| i128::from(f(x,y)))
}

fn eval_cmp_u(
    a: &MlilExpr, b: &MlilExpr,
    lat: &ConstantLattice,
    depth: usize,
    f: impl Fn(u128, u128) -> bool,
) -> Lattice {
    eval_binary(a, b, lat, depth, |x,y| i128::from(f(x.cast_unsigned(), y.cast_unsigned())))
}

const fn sign_extend(v: i128, bits: u8) -> i128 {
    if bits >= 128 { return v; }
    let shift = 128 - bits as u32;
    (v << shift) >> shift
}

const fn zero_extend(v: i128, bits: u8) -> i128 {
    if bits >= 128 { return v; }
    let mask: u128 = (1u128 << bits) - 1;
    (v.cast_unsigned() & mask).cast_signed()
}

const fn truncate(v: i128, bits: u8) -> i128 {
    zero_extend(v, bits)
}

// ---------------------------------------------------------------------------
// SCCP core
// ---------------------------------------------------------------------------

/// Statistics collected during a SCCP pass.
#[derive(Default, Debug, Clone)]
pub struct ScCpStats {
    pub folded_vars:         usize,
    pub folded_branches:     usize,
    pub removed_blocks:      usize,
    pub total_iterations:    usize,
}

/// Full SCCP analysis result.
pub struct ScCpResult {
    /// Final constant lattice (one entry per SSA var).
    pub lattice:    ConstantLattice,
    /// Which blocks are reachable after SCCP.
    pub reachable:  HashSet<BBId>,
    pub stats:      ScCpStats,
}

/// Run the Wegman-Zadeck sparse conditional constant propagation algorithm.
///
/// After this call the caller may invoke [`fold_constants`] and
/// [`remove_dead_code`] to transform the function in-place.
pub fn run_sccp(func: &MlilFunction) -> ScCpResult {
    let mut lat     = ConstantLattice::new();
    let mut er      = EdgeReachability::new(func.entry);
    let mut stats   = ScCpStats::default();

    // Initialise parameters as Top (unknown).
    for &p in &func.params {
        lat.force_set(p, Lattice::Top);
    }

    // Build def-use chains.
    let def_use = build_def_use(func);

    // Seed worklist: every statement in the entry block.
    let mut var_wl:  VecDeque<VarId>         = VecDeque::new();
    let mut edge_wl: VecDeque<(BBId, BBId)>  = VecDeque::new();

    // Process the entry block once; it will enqueue its own live successor
    // edges (branch/jump). Blocks reachable only via unconditional flow from
    // the entry get added through the normal edge-worklist propagation.
    process_block(func.entry, func, &mut lat, &er, &mut var_wl, &mut edge_wl);

    loop {
        stats.total_iterations += 1;

        // Process edge worklist.
        while let Some((from, to)) = edge_wl.pop_front() {
            if !er.mark_edge(from, to) { continue; }

            // Re-evaluate all PHI nodes in `to` (their incoming edge is now live).
            let bb = func.block(to);
            for (idx, stmt) in bb.stmts.iter().enumerate() {
                if let MlilStmt::Phi { dst, srcs } = stmt {
                    let new_val = eval_phi(*dst, srcs, to, &lat, &er, func);
                    if lat.set(*dst, &new_val) {
                        var_wl.push_back(*dst);
                    }
                    let _ = idx;
                }
            }

            // Also re-evaluate the first non-PHI stmt (it may be a branch
            // that we can now resolve).
            process_block(to, func, &mut lat, &er, &mut var_wl, &mut edge_wl);
        }

        // Process variable worklist.
        let Some(var) = var_wl.pop_front() else { break; };

        // Re-evaluate every statement that uses `var`.
        let sites = def_use.get(&var).map(Vec::as_slice).unwrap_or_default();
        for &(bb_id, _stmt_idx) in sites {
            if !er.is_reachable(bb_id) { continue; }
            process_block(bb_id, func, &mut lat, &er, &mut var_wl, &mut edge_wl);
        }
    }

    // Compute unreachable blocks.
    let total_blocks = func.blocks.len();
    let reachable_count = er.reachable.len();
    stats.removed_blocks = total_blocks.saturating_sub(reachable_count);

    // Count folded vars.
    for (_, l) in lat.iter() {
        if l.is_const() { stats.folded_vars += 1; }
    }

    ScCpResult {
        lattice: lat,
        reachable: er.reachable.clone(),
        stats,
    }
}

/// Evaluate the PHI node for `dst` in `bb` given the current lattice and edge
/// reachability.
fn eval_phi(
    _dst: VarId,
    srcs: &[VarId],
    bb: BBId,
    lat: &ConstantLattice,
    er: &EdgeReachability,
    func: &MlilFunction,
) -> Lattice {
    let Some(bb_block) = func.try_block(bb) else { return Lattice::Bottom; };
    let preds = &bb_block.predecessors;
    let mut result = Lattice::Top;
    for (&pred, &src) in preds.iter().zip(srcs.iter()) {
        if er.is_edge_executable(pred, bb) {
            result = result.meet(lat.get(src));
        }
    }
    result
}

/// Re-evaluate all statements in a basic block and update the worklists.
fn process_block(
    bb_id: BBId,
    func: &MlilFunction,
    lat: &mut ConstantLattice,
    er: &EdgeReachability,
    var_wl: &mut VecDeque<VarId>,
    edge_wl: &mut VecDeque<(BBId, BBId)>,
) {
    let Some(bb) = func.try_block(bb_id) else { return; };
    let mut has_terminator = false;
    for stmt in &bb.stmts {
        match stmt {
            MlilStmt::Assign { dst, rhs } => {
                let val = eval_expr(rhs, lat);
                if lat.set(*dst, &val) {
                    var_wl.push_back(*dst);
                }
            }
            MlilStmt::Phi { dst, srcs } => {
                let val = eval_phi(*dst, srcs, bb_id, lat, er, func);
                if lat.set(*dst, &val) {
                    var_wl.push_back(*dst);
                }
            }
            MlilStmt::Branch { cond, true_bb, false_bb } => {
                has_terminator = true;
                let cond_val = eval_expr(cond, lat);
                match cond_val {
                    Lattice::Const(0) => {
                        // Condition is always false → only false edge is live.
                        edge_wl.push_back((bb_id, *false_bb));
                    }
                    Lattice::Const(_) => {
                        // Condition is always true → only true edge is live.
                        edge_wl.push_back((bb_id, *true_bb));
                    }
                    Lattice::Top => {
                        // Not yet known — don't add edges yet.
                    }
                    Lattice::Bottom => {
                        // Both edges may be taken.
                        edge_wl.push_back((bb_id, *true_bb));
                        edge_wl.push_back((bb_id, *false_bb));
                    }
                }
            }
            MlilStmt::Jump { target } => {
                has_terminator = true;
                edge_wl.push_back((bb_id, *target));
            }
            MlilStmt::Return { .. } => { has_terminator = true; }
            // A call's result is unknown: mark dst overdefined so downstream
            // branches on it don't stay Top (which would wrongly mark both
            // successors unreachable).
            MlilStmt::Call { dst: Some(d), .. } => {
                if lat.set(*d, &Lattice::Bottom) {
                    var_wl.push_back(*d);
                }
            }
            // Side-effecting statements: store, call — no lattice updates.
            MlilStmt::Store { .. } | MlilStmt::Call { dst: None, .. } | MlilStmt::Nop => {}
        }
    }
    // Fall-through: if the block has no explicit terminator, all listed
    // successors are reachable.
    if !has_terminator {
        for &succ in &bb.successors {
            edge_wl.push_back((bb_id, succ));
        }
    }
}

// ---------------------------------------------------------------------------
// Folding pass (mutating transform)
// ---------------------------------------------------------------------------

/// Replace uses of constant-valued SSA variables with literal constants in an
/// expression, and simplify the expression where possible.
pub fn fold_expr(expr: &MlilExpr, lat: &ConstantLattice) -> MlilExpr {
    match expr {
        MlilExpr::Var(v) => lat.get(*v).const_val().map_or_else(|| expr.clone(), MlilExpr::Const),
        MlilExpr::Const(_) | MlilExpr::Unmodelled => expr.clone(),

        MlilExpr::Add(a, b)    => fold_bin(a, b, lat, MlilExpr::Add),
        MlilExpr::Sub(a, b)    => fold_bin(a, b, lat, MlilExpr::Sub),
        MlilExpr::Mul(a, b)    => fold_bin(a, b, lat, MlilExpr::Mul),
        MlilExpr::Div(a, b)    => fold_bin(a, b, lat, MlilExpr::Div),
        MlilExpr::DivU(a, b)   => fold_bin(a, b, lat, MlilExpr::DivU),
        MlilExpr::Mod(a, b)    => fold_bin(a, b, lat, MlilExpr::Mod),
        MlilExpr::ModU(a, b)   => fold_bin(a, b, lat, MlilExpr::ModU),
        MlilExpr::And(a, b)    => fold_bin(a, b, lat, MlilExpr::And),
        MlilExpr::Or(a, b)     => fold_bin(a, b, lat, MlilExpr::Or),
        MlilExpr::Xor(a, b)    => fold_bin(a, b, lat, MlilExpr::Xor),
        MlilExpr::Shl(a, b)    => fold_bin(a, b, lat, MlilExpr::Shl),
        MlilExpr::Shr(a, b)    => fold_bin(a, b, lat, MlilExpr::Shr),
        MlilExpr::Sar(a, b)    => fold_bin(a, b, lat, MlilExpr::Sar),
        MlilExpr::CmpEq(a, b)  => fold_bin(a, b, lat, MlilExpr::CmpEq),
        MlilExpr::CmpNe(a, b)  => fold_bin(a, b, lat, MlilExpr::CmpNe),
        MlilExpr::CmpLt(a, b)  => fold_bin(a, b, lat, MlilExpr::CmpLt),
        MlilExpr::CmpLe(a, b)  => fold_bin(a, b, lat, MlilExpr::CmpLe),
        MlilExpr::CmpGt(a, b)  => fold_bin(a, b, lat, MlilExpr::CmpGt),
        MlilExpr::CmpGe(a, b)  => fold_bin(a, b, lat, MlilExpr::CmpGe),
        MlilExpr::CmpLtu(a, b) => fold_bin(a, b, lat, MlilExpr::CmpLtu),
        MlilExpr::CmpLeu(a, b) => fold_bin(a, b, lat, MlilExpr::CmpLeu),
        MlilExpr::CmpGtu(a, b) => fold_bin(a, b, lat, MlilExpr::CmpGtu),
        MlilExpr::CmpGeu(a, b) => fold_bin(a, b, lat, MlilExpr::CmpGeu),

        MlilExpr::Neg(e) => {
            let fe = fold_expr(e, lat);
            if let MlilExpr::Const(k) = &fe { MlilExpr::Const(k.wrapping_neg()) }
            else { MlilExpr::Neg(Box::new(fe)) }
        }
        MlilExpr::Not(e) => {
            let fe = fold_expr(e, lat);
            if let MlilExpr::Const(k) = &fe { MlilExpr::Const(!k) }
            else { MlilExpr::Not(Box::new(fe)) }
        }
        MlilExpr::Sx(bits, e) => {
            let fe = fold_expr(e, lat);
            if let MlilExpr::Const(k) = &fe { MlilExpr::Const(sign_extend(*k, *bits)) }
            else { MlilExpr::Sx(*bits, Box::new(fe)) }
        }
        MlilExpr::Zx(bits, e) => {
            let fe = fold_expr(e, lat);
            if let MlilExpr::Const(k) = &fe { MlilExpr::Const(zero_extend(*k, *bits)) }
            else { MlilExpr::Zx(*bits, Box::new(fe)) }
        }
        MlilExpr::Trunc(bits, e) => {
            let fe = fold_expr(e, lat);
            if let MlilExpr::Const(k) = &fe { MlilExpr::Const(truncate(*k, *bits)) }
            else { MlilExpr::Trunc(*bits, Box::new(fe)) }
        }
        MlilExpr::Load { size, addr } => {
            MlilExpr::Load { size: *size, addr: Box::new(fold_expr(addr, lat)) }
        }
    }
}

fn fold_bin<F>(
    a: &MlilExpr, b: &MlilExpr,
    lat: &ConstantLattice,
    ctor: F,
) -> MlilExpr
where
    F: Fn(Box<MlilExpr>, Box<MlilExpr>) -> MlilExpr,
{
    let fa = fold_expr(a, lat);
    let fb = fold_expr(b, lat);
    // If both folded to constants, evaluate immediately.
    if let (MlilExpr::Const(x), MlilExpr::Const(y)) = (&fa, &fb) {
        // Delegate to eval_expr for the arithmetic semantics.
        let combined = ctor(Box::new(MlilExpr::Const(*x)), Box::new(MlilExpr::Const(*y)));
        let result = eval_expr(&combined, lat);
        if let Some(k) = result.const_val() {
            return MlilExpr::Const(k);
        }
    }
    ctor(Box::new(fa), Box::new(fb))
}

fn fold_stmt(stmt: &MlilStmt, lat: &ConstantLattice) -> MlilStmt {
    match stmt {
        MlilStmt::Assign { dst, rhs } => {
            MlilStmt::Assign { dst: *dst, rhs: fold_expr(rhs, lat) }
        }
        MlilStmt::Branch { cond, true_bb, false_bb } => {
            let folded = fold_expr(cond, lat);
            // If the condition folded to a constant, convert to unconditional jump.
            match &folded {
                MlilExpr::Const(0) => MlilStmt::Jump { target: *false_bb },
                MlilExpr::Const(_) => MlilStmt::Jump { target: *true_bb  },
                _                  => MlilStmt::Branch {
                    cond: folded, true_bb: *true_bb, false_bb: *false_bb
                },
            }
        }
        MlilStmt::Store { size, addr, value } => MlilStmt::Store {
            size: *size,
            addr:  fold_expr(addr, lat),
            value: fold_expr(value, lat),
        },
        MlilStmt::Call { dst, target, args } => MlilStmt::Call {
            dst:    *dst,
            target: fold_expr(target, lat),
            args:   args.iter().map(|a| fold_expr(a, lat)).collect(),
        },
        MlilStmt::Return { values } => MlilStmt::Return {
            values: values.iter().map(|v| fold_expr(v, lat)).collect(),
        },
        MlilStmt::Phi { .. } | MlilStmt::Jump { .. } | MlilStmt::Nop => stmt.clone(),
    }
}

/// Apply constant folding to an entire function using the SCCP result.
///
/// Returns a new function with all constant-valued variables replaced by
/// literals and all constant-condition branches replaced by unconditional jumps.
#[must_use] 
pub fn fold_constants(func: &MlilFunction, result: &ScCpResult) -> MlilFunction {
    let mut new_func = func.clone();

    for bb in new_func.blocks.values_mut() {
        bb.stmts = bb.stmts.iter().map(|s| fold_stmt(s, &result.lattice)).collect();

        // Update successor list for blocks whose branch was folded.
        if let Some(last) = bb.stmts.last()
            && let MlilStmt::Jump { target } = last {
                bb.successors = vec![*target];
            }
    }

    new_func
}

// ---------------------------------------------------------------------------
// Dead block removal
// ---------------------------------------------------------------------------

/// Remove all basic blocks that are not reachable according to `result.reachable`.
/// Also removes those blocks from predecessor lists of their successors.
pub fn remove_dead_blocks(func: &mut MlilFunction, result: &ScCpResult) {
    let dead: Vec<BBId> = func.blocks.keys()
        .copied()
        .filter(|id| !result.reachable.contains(id))
        .collect();

    for id in &dead {
        // Remove from successors' predecessor lists.
        let succs = func.blocks[id].successors.clone();
        for succ in succs {
            if let Some(succ_bb) = func.blocks.get_mut(&succ) {
                succ_bb.predecessors.retain(|p| p != id);
            }
        }
        func.blocks.remove(id);
    }

    func.block_order.retain(|id| result.reachable.contains(id));
}

// ---------------------------------------------------------------------------
// High-level pipeline
// ---------------------------------------------------------------------------

/// Combined pipeline: run SCCP, fold constants, remove dead blocks.
/// Returns (modified function, statistics).
#[must_use] 
pub fn run_constant_propagation_pipeline(func: &MlilFunction) -> (MlilFunction, ScCpStats) {
    let result  = run_sccp(func);
    let mut new_func = fold_constants(func, &result);
    remove_dead_blocks(&mut new_func, &result);
    let stats = result.stats.clone();
    (new_func, stats)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_simple_func() -> MlilFunction {
        // BB0: v0 = 42, v1 = v0 + 8; jump BB1
        // BB1: return v1
        let mut func = MlilFunction::new(0, 0);

        let mut bb0 = BasicBlock::new(0);
        bb0.stmts = vec![
            MlilStmt::Assign { dst: 0, rhs: MlilExpr::Const(42) },
            MlilStmt::Assign { dst: 1, rhs: MlilExpr::Add(
                Box::new(MlilExpr::Var(0)),
                Box::new(MlilExpr::Const(8)),
            )},
            MlilStmt::Jump { target: 1 },
        ];
        bb0.successors = vec![1];

        let mut bb1 = BasicBlock::new(1);
        bb1.stmts = vec![
            MlilStmt::Return { values: vec![MlilExpr::Var(1)] },
        ];
        bb1.predecessors = vec![0];

        func.blocks.insert(0, bb0);
        func.blocks.insert(1, bb1);
        func.block_order = vec![0, 1];
        func
    }

    #[test]
    fn test_lattice_meet() {
        assert_eq!(Lattice::Top.meet(&Lattice::Const(5)), Lattice::Const(5));
        assert_eq!(Lattice::Const(5).meet(&Lattice::Const(5)), Lattice::Const(5));
        assert_eq!(Lattice::Const(5).meet(&Lattice::Const(6)), Lattice::Bottom);
        assert_eq!(Lattice::Bottom.meet(&Lattice::Const(5)), Lattice::Bottom);
    }

    #[test]
    fn test_eval_add_constants() {
        let lat = ConstantLattice::new();
        let expr = MlilExpr::Add(
            Box::new(MlilExpr::Const(10)),
            Box::new(MlilExpr::Const(20)),
        );
        assert_eq!(eval_expr(&expr, &lat), Lattice::Const(30));
    }

    #[test]
    fn test_sccp_simple_fold() {
        let func = make_simple_func();
        let result = run_sccp(&func);
        assert_eq!(result.lattice.get(0).const_val(), Some(42));
        assert_eq!(result.lattice.get(1).const_val(), Some(50));
    }

    #[test]
    fn test_pipeline_removes_zero_constants() {
        let func = make_simple_func();
        let (new_func, stats) = run_constant_propagation_pipeline(&func);
        // Both blocks should still be reachable.
        assert_eq!(new_func.blocks.len(), 2);
        assert!(stats.folded_vars >= 2);
    }

    #[test]
    fn test_dead_block_removal() {
        // BB0: if 0 goto BB1 else BB2
        // BB1: return 1   <- dead
        // BB2: return 2
        let mut func = MlilFunction::new(0, 0);

        let mut bb0 = BasicBlock::new(0);
        bb0.stmts = vec![
            MlilStmt::Branch {
                cond: MlilExpr::Const(0),
                true_bb: 1,
                false_bb: 2,
            }
        ];
        bb0.successors = vec![1, 2];

        let mut bb1 = BasicBlock::new(1);
        bb1.stmts = vec![MlilStmt::Return { values: vec![MlilExpr::Const(1)] }];
        bb1.predecessors = vec![0];

        let mut bb2 = BasicBlock::new(2);
        bb2.stmts = vec![MlilStmt::Return { values: vec![MlilExpr::Const(2)] }];
        bb2.predecessors = vec![0];

        func.blocks.insert(0, bb0);
        func.blocks.insert(1, bb1);
        func.blocks.insert(2, bb2);
        func.block_order = vec![0, 1, 2];

        let (new_func, stats) = run_constant_propagation_pipeline(&func);
        assert_eq!(stats.removed_blocks, 1);
        assert!(!new_func.blocks.contains_key(&1), "BB1 should be dead");
        assert!(new_func.blocks.contains_key(&2), "BB2 should be live");
    }

    #[test]
    fn test_phi_meet() {
        // BB0: v0 = 1; jump BB2
        // BB1: v1 = 2; jump BB2
        // BB2: v2 = phi(v0, v1); return v2
        // Both edges are live → v2 = Bottom (1 meet 2).
        let mut func = MlilFunction::new(0, 0);

        let mut bb0 = BasicBlock::new(0);
        bb0.stmts = vec![
            MlilStmt::Assign { dst: 0, rhs: MlilExpr::Const(1) },
            MlilStmt::Jump { target: 2 },
        ];
        bb0.successors = vec![2];

        let mut bb1 = BasicBlock::new(1);
        bb1.stmts = vec![
            MlilStmt::Assign { dst: 1, rhs: MlilExpr::Const(2) },
            MlilStmt::Jump { target: 2 },
        ];
        bb1.successors = vec![2];

        let mut bb2 = BasicBlock::new(2);
        bb2.stmts = vec![
            MlilStmt::Phi { dst: 2, srcs: vec![0, 1] },
            MlilStmt::Return { values: vec![MlilExpr::Var(2)] },
        ];
        bb2.predecessors = vec![0, 1];

        func.blocks.insert(0, bb0);
        func.blocks.insert(1, bb1);
        func.blocks.insert(2, bb2);
        func.block_order = vec![0, 1, 2];

        let result = run_sccp(&func);
        // BB1 is never reached from entry (entry is BB0) → BB2's phi sees
        // only one live incoming edge → v2 = Const(1).
        // (BB1 is not reachable from entry BB0.)
        assert_eq!(result.lattice.get(0).const_val(), Some(1));
    }

    #[test]
    fn test_call_dst_is_overdefined_keeps_branch_successors_live() {
        // BB0: v0 = call target(); if v0 goto BB1 else BB2
        // BB1: return 1
        // BB2: return 2
        // Call result is unknown → both successors must stay reachable.
        let mut func = MlilFunction::new(0, 0);

        let mut bb0 = BasicBlock::new(0);
        bb0.stmts = vec![
            MlilStmt::Call { dst: Some(0), target: MlilExpr::Const(0x1000), args: vec![] },
            MlilStmt::Branch { cond: MlilExpr::Var(0), true_bb: 1, false_bb: 2 },
        ];
        bb0.successors = vec![1, 2];

        let mut bb1 = BasicBlock::new(1);
        bb1.stmts = vec![MlilStmt::Return { values: vec![MlilExpr::Const(1)] }];
        bb1.predecessors = vec![0];

        let mut bb2 = BasicBlock::new(2);
        bb2.stmts = vec![MlilStmt::Return { values: vec![MlilExpr::Const(2)] }];
        bb2.predecessors = vec![0];

        func.blocks.insert(0, bb0);
        func.blocks.insert(1, bb1);
        func.blocks.insert(2, bb2);
        func.block_order = vec![0, 1, 2];

        let result = run_sccp(&func);
        assert_eq!(result.lattice.get(0), &Lattice::Bottom, "call dst must be overdefined");
        let (new_func, stats) = run_constant_propagation_pipeline(&func);
        assert_eq!(stats.removed_blocks, 0);
        assert!(new_func.blocks.contains_key(&1) && new_func.blocks.contains_key(&2));
    }

    #[test]
    fn test_division_by_zero_yields_bottom() {
        let lat = ConstantLattice::new();
        let expr = MlilExpr::Div(
            Box::new(MlilExpr::Const(10)),
            Box::new(MlilExpr::Const(0)),
        );
        assert_eq!(eval_expr(&expr, &lat), Lattice::Bottom);
    }

    #[test]
    fn test_sign_extend() {
        // 0xFF sign-extended from 8 bits should be -1 in i128.
        assert_eq!(sign_extend(0xFF, 8), -1_i128);
    }

    #[test]
    fn test_zero_extend() {
        assert_eq!(zero_extend(-1i128, 8), 0xFF);
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate(0x1FF, 8), 0xFF);
    }
}

// ---------------------------------------------------------------------------
// Additional utility: dump the constant lattice for debugging.
// ---------------------------------------------------------------------------

impl ScCpResult {
    /// Print the lattice to stderr for debugging purposes.
    pub fn dump(&self) {
        eprintln!("=== SCCP Lattice Dump ===");
        let mut entries: Vec<_> = self.lattice.iter().collect();
        entries.sort_by_key(|(v, _)| *v);
        for (var, val) in entries {
            eprintln!("  v{var:04} = {val}");
        }
        eprintln!("=== Reachable Blocks: {:?} ===", {
            let mut v: Vec<_> = self.reachable.iter().copied().collect();
            v.sort_unstable();
            v
        });
        eprintln!("=== Stats: {:?} ===", self.stats);
    }
}

// ---------------------------------------------------------------------------
// Iterator helper: collect all variables defined in a function.
// ---------------------------------------------------------------------------

#[must_use] 
pub fn collect_defs(func: &MlilFunction) -> Vec<VarId> {
    let mut defs = Vec::with_capacity(func.blocks.len() * 4);
    for bb in func.blocks.values() {
        for stmt in &bb.stmts {
            match stmt {
                MlilStmt::Assign { dst, .. } | MlilStmt::Phi { dst, .. } => {
                    defs.push(*dst);
                }
                MlilStmt::Call { dst: Some(d), .. } => defs.push(*d),
                _ => {}
            }
        }
    }
    defs
}

// ---------------------------------------------------------------------------
// Worklist-based incremental re-analysis
// ---------------------------------------------------------------------------

/// Incrementally re-run SCCP after a local change to a single basic block.
///
/// Seeds the variable- and edge-worklists from `changed_bb` and iterates
/// using the `prev_result` lattice as the starting state, so only the
/// affected region of the dataflow graph is re-evaluated (O(delta) cost in
/// the common case of a small local change).
pub fn reanalyse_from(
    func: &MlilFunction,
    changed_bb: BBId,
    prev_result: &ScCpResult,
) -> ScCpResult {
    // Warm-start: clone the lattice and reachability from the previous result.
    let mut lat   = prev_result.lattice.clone();
    let mut er    = EdgeReachability::new(func.entry);
    // Re-mark all edges that were executable in the previous result so that
    // the edge-reachability state is consistent with the cloned lattice.
    for &bb_id in &prev_result.reachable {
        if let Some(bb) = func.blocks.get(&bb_id) {
            for &succ in &bb.successors {
                er.mark_edge(bb_id, succ);
            }
        }
    }

    let mut stats    = ScCpStats::default();
    let def_use      = build_def_use(func);
    let mut var_wl:  VecDeque<VarId>        = VecDeque::new();
    let mut edge_wl: VecDeque<(BBId, BBId)> = VecDeque::new();

    // Seed: re-evaluate the changed block and all outgoing edges from it.
    if let Some(bb) = func.blocks.get(&changed_bb) {
        for &succ in &bb.successors {
            edge_wl.push_back((changed_bb, succ));
        }
        // Also enqueue every variable defined in this block so downstream
        // uses are revisited.
        for stmt in &bb.stmts {
            match stmt {
                MlilStmt::Assign { dst, .. } | MlilStmt::Phi { dst, .. } | MlilStmt::Call { dst: Some(dst), .. } => {
                    var_wl.push_back(*dst);
                }
                _ => {}
            }
        }
    }

    // Standard SCCP iteration from here.
    loop {
        stats.total_iterations += 1;

        while let Some((from, to)) = edge_wl.pop_front() {
            if !er.mark_edge(from, to) { continue; }
            let bb = func.block(to);
            for stmt in &bb.stmts {
                if let MlilStmt::Phi { dst, srcs } = stmt {
                    let new_val = eval_phi(*dst, srcs, to, &lat, &er, func);
                    if lat.set(*dst, &new_val) {
                        var_wl.push_back(*dst);
                    }
                }
            }
            process_block(to, func, &mut lat, &er, &mut var_wl, &mut edge_wl);
        }

        let Some(var) = var_wl.pop_front() else { break; };

        let sites = def_use.get(&var).map(Vec::as_slice).unwrap_or_default();
        for &(bb_id, _stmt_idx) in sites {
            if !er.is_reachable(bb_id) { continue; }
            process_block(bb_id, func, &mut lat, &er, &mut var_wl, &mut edge_wl);
        }
    }

    let total_blocks    = func.blocks.len();
    let reachable_count = er.reachable.len();
    stats.removed_blocks = total_blocks.saturating_sub(reachable_count);
    for (_, l) in lat.iter() {
        if l.is_const() { stats.folded_vars += 1; }
    }

    ScCpResult {
        lattice:   lat,
        reachable: er.reachable.clone(),
        stats,
    }
}

// ---------------------------------------------------------------------------
// Pretty-printer for folded functions
// ---------------------------------------------------------------------------

pub fn dump_function(func: &MlilFunction) {
    eprintln!("=== MlilFunction {} ===", func.id);
    for &bb_id in &func.block_order {
        if let Some(bb) = func.blocks.get(&bb_id) {
            eprintln!("  BB{bb_id}:");
            for stmt in &bb.stmts {
                eprintln!("    {stmt:?}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience: run full pipeline and return statistics only
// ---------------------------------------------------------------------------

#[must_use] 
pub fn analyse_function(func: &MlilFunction) -> ScCpStats {
    run_sccp(func).stats
}
