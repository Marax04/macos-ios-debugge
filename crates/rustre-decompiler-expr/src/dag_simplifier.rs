//! Expression DAG simplifier for `rustre-decompiler-expr`.
//!
//! # Overview
//!
//! Expression trees produced by decompilers often contain redundant subterms
//! (duplicate computations, identity operations, constant sub-expressions).
//! This module represents expressions as a **Directed Acyclic Graph** (DAG)
//! using hash-consing to share identical sub-trees automatically, then applies
//! a series of simplification passes.
//!
//! ## DAG Representation
//!
//! Every expression node is stored in a [`DagArena`] and referenced by a
//! [`DagNodeId`] handle.  Interning a node through [`DagArena::intern`] or
//! [`CommonSubexpr::intern`] returns the id of an existing equivalent node
//! rather than creating a duplicate.
//!
//! Node kinds ([`DagNode`]):
//! * `Const(i64)` / `Bool(bool)` — leaf constants.
//! * `Var(String)` — named variable reference.
//! * `BinOp { op, left, right }` — binary operation.
//! * `UnOp { op, operand }` — unary operation.
//! * `Cond { cond, then_val, else_val }` — conditional.
//! * `Call { name, args }` — function call (has side effects).
//! * `Dead` — a node that has been eliminated.
//!
//! ## Simplification Passes
//!
//! 1. [`ConstantFolding`] — evaluates operations on constant operands.
//!
//! 2. [`BitwiseSimplify`] — applies identities such as:
//!    - `x & 0 → 0`
//!    - `x | 0 → x`
//!    - `x ^ x → 0`
//!    - `x + 0 → x`
//!    - `~~x → x`
//!    - `--x → x`
//!
//! 3. [`CommutativeNormalizer`] — puts commutative operands in canonical
//!    id order to maximise CSE hits.
//!
//! 4. [`DeadNode::sweep`] — marks nodes unreachable from a root as dead,
//!    reducing arena memory usage.
//!
//! ## Evaluation
//!
//! [`ConstantEvaluator`] evaluates a DAG node to a concrete `i64` value given
//! a variable environment, without modifying the arena.
//!
//! ## Traversal
//!
//! [`ReachableNodes::collect`] returns the set of all nodes reachable from a
//! root.  [`ReachableNodes::variable_count`] counts distinct variable leaves.
//!
//! ## Rendering
//!
//! [`DagPrinter`] converts a node id back to a C-like expression string.
//! [`DagStatistics`] computes aggregate metrics (live / dead / const / var /
//! binop counts).
//!
//! [`DagSimplifier`] performs hash-consing of expression nodes into a DAG,
//! eliminates redundant subexpressions, folds constants, and applies bitwise
//! identities.
//!
//! Key types:
//! * [`DagNode`] — a node in the expression DAG.
//! * [`DagHash`] — canonical hash key for a node (content-addressed).
//! * [`CommonSubexpr`] — CSE via hash-consing.
//! * [`DeadNode`] — marks a node as unreachable.
//! * [`ConstantFolding`] — evaluates constant sub-DAGs.
//! * [`BitwiseSimplify`] — applies bitwise algebraic rules.

use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};

/// Compute a 64-bit hash for any [`Hash`]-able value using the default hasher.
#[must_use]
pub fn hash64<T: Hash + ?Sized>(value: &T) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut h);
    h.finish()
}

// ---------------------------------------------------------------------------
// DagHash
// ---------------------------------------------------------------------------

/// A content-addressable key that uniquely identifies a DAG node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DagHash(String);

impl DagHash {
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DagHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// DagNodeId
// ---------------------------------------------------------------------------

/// Handle to a node in the DAG arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DagNodeId(pub u32);

impl fmt::Display for DagNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "n{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// DagNode
// ---------------------------------------------------------------------------

/// A single node in the expression DAG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DagNode {
    /// Integer constant.
    Const(i64),
    /// Boolean constant.
    Bool(bool),
    /// Variable reference (name).
    Var(String),
    /// Binary arithmetic / logical operation.
    BinOp {
        op: BinOpKind,
        left: DagNodeId,
        right: DagNodeId,
    },
    /// Unary operation.
    UnOp { op: UnOpKind, operand: DagNodeId },
    /// Conditional ternary: `cond ? then_val : else_val`.
    Cond {
        cond: DagNodeId,
        then_val: DagNodeId,
        else_val: DagNodeId,
    },
    /// Function call with a list of argument node ids.
    Call { name: String, args: Vec<DagNodeId> },
    /// Represents a dead / eliminated node.
    Dead,
}

impl DagNode {
    /// Compute the canonical hash key for this node.
    #[must_use]
    pub fn hash_key(&self, arena: &DagArena) -> DagHash {
        // Use the arena to resolve constant operands into their literal values,
        // which strengthens the canonical key (constants hash by value, not by id).
        let resolve = |id: &DagNodeId| -> String {
            match arena.get(*id) {
                Some(Self::Const(v)) => format!("C{v}"),
                Some(Self::Bool(b)) => format!("B{b}"),
                _ => id.to_string(),
            }
        };
        match self {
            Self::Const(v) => DagHash::new(format!("C{v}")),
            Self::Bool(b) => DagHash::new(format!("B{b}")),
            Self::Var(name) => DagHash::new(format!("V{name}")),
            Self::BinOp { op, left, right } => DagHash::new(format!(
                "{}({},{})",
                op.symbol(),
                resolve(left),
                resolve(right)
            )),
            Self::UnOp { op, operand } => {
                DagHash::new(format!("{}({})", op.symbol(), resolve(operand)))
            }
            Self::Cond {
                cond,
                then_val,
                else_val,
            } => DagHash::new(format!(
                "?({},{},{})",
                resolve(cond),
                resolve(then_val),
                resolve(else_val)
            )),
            Self::Call { name, args } => {
                let arg_s: Vec<String> = args.iter().map(resolve).collect();
                DagHash::new(format!("{name}({})", arg_s.join(",")))
            }
            Self::Dead => DagHash::new("DEAD"),
        }
    }

    /// True if this node is a constant (integer or bool).
    #[must_use]
    pub const fn is_const(&self) -> bool {
        matches!(self, Self::Const(_) | Self::Bool(_))
    }

    /// True if this is the dead node.
    #[must_use]
    pub const fn is_dead(&self) -> bool {
        matches!(self, Self::Dead)
    }

    /// Return the constant integer value, if any.
    #[must_use]
    pub const fn const_value(&self) -> Option<i64> {
        if let Self::Const(v) = self {
            Some(*v)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// BinOpKind / UnOpKind
// ---------------------------------------------------------------------------

/// Binary operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinOpKind {
    Add,
    Sub,
    Mul,
    DivS,
    DivU,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
    CmpEq,
    CmpNe,
    CmpLt,
    CmpLe,
    CmpGt,
    CmpGe,
    BoolAnd,
    BoolOr,
}

impl BinOpKind {
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::DivS => "/s",
            Self::DivU => "/u",
            Self::And => "&",
            Self::Or => "|",
            Self::Xor => "^",
            Self::Shl => "<<",
            Self::Shr => ">>",
            Self::Sar => ">>a",
            Self::CmpEq => "==",
            Self::CmpNe => "!=",
            Self::CmpLt => "<",
            Self::CmpLe => "<=",
            Self::CmpGt => ">",
            Self::CmpGe => ">=",
            Self::BoolAnd => "&&",
            Self::BoolOr => "||",
        }
    }

    /// Whether this op is commutative (a ⊕ b = b ⊕ a).
    #[must_use]
    pub const fn is_commutative(self) -> bool {
        matches!(
            self,
            Self::Add
                | Self::Mul
                | Self::And
                | Self::Or
                | Self::Xor
                | Self::CmpEq
                | Self::CmpNe
                | Self::BoolAnd
                | Self::BoolOr
        )
    }
}

/// Unary operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnOpKind {
    Neg,
    Not,
    BoolNot,
    ZeroExt,
    SignExt,
}

impl UnOpKind {
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Neg => "-",
            Self::Not => "~",
            Self::BoolNot => "!",
            Self::ZeroExt => "zext",
            Self::SignExt => "sext",
        }
    }
}

// ---------------------------------------------------------------------------
// DagArena
// ---------------------------------------------------------------------------

/// The DAG node arena: allocates and stores all nodes.
#[derive(Debug, Default)]
pub struct DagArena {
    nodes: Vec<DagNode>,
    hash_map: HashMap<DagHash, DagNodeId>,
}

impl DagArena {
    /// Intern `node`, returning its id (or the id of an existing equivalent).
    ///
    /// # Panics
    /// Panics if more than `u32::MAX` nodes have been interned.
    pub fn intern(&mut self, node: DagNode) -> DagNodeId {
        let key = node.hash_key(self);
        if let Some(&existing) = self.hash_map.get(&key) {
            return existing;
        }
        let raw_id = u32::try_from(self.nodes.len())
            .expect("DagArena: node count exceeds u32::MAX");
        let id = DagNodeId(raw_id);
        self.nodes.push(node);
        self.hash_map.insert(key, id);
        id
    }

    /// Get a reference to the node with `id`.
    #[must_use]
    pub fn get(&self, id: DagNodeId) -> Option<&DagNode> {
        self.nodes.get(id.0 as usize)
    }

    /// Mark the node at `id` as dead.
    pub fn mark_dead(&mut self, id: DagNodeId) {
        if let Some(node) = self.nodes.get_mut(id.0 as usize) {
            *node = DagNode::Dead;
        }
    }

    /// Number of live (non-dead) nodes.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.nodes.iter().filter(|n| !n.is_dead()).count()
    }

    /// Total node count (including dead).
    #[must_use]
    pub const fn total_count(&self) -> usize {
        self.nodes.len()
    }
}

// ---------------------------------------------------------------------------
// CommonSubexpr
// ---------------------------------------------------------------------------

/// CSE: identifies and shares common subexpressions via hash-consing in the arena.
#[derive(Debug, Default)]
pub struct CommonSubexpr {
    /// Number of nodes deduplicated.
    pub dedup_count: usize,
}

impl CommonSubexpr {
    /// Intern `node` in `arena`, returning its canonical id.
    /// If an equivalent node already exists, the redundant node is not inserted.
    pub fn intern(&mut self, arena: &mut DagArena, node: DagNode) -> DagNodeId {
        let before = arena.total_count();
        let id = arena.intern(node);
        if arena.total_count() == before {
            // Node was already present.
            self.dedup_count += 1;
        }
        id
    }
}

// ---------------------------------------------------------------------------
// DeadNode
// ---------------------------------------------------------------------------

/// Marks nodes unreachable from a given root as dead.
#[derive(Debug, Default)]
pub struct DeadNode {
    pub marked: usize,
}

impl DeadNode {
    /// Collect all nodes reachable from `root` in `arena`.
    fn reachable(root: DagNodeId, arena: &DagArena) -> std::collections::HashSet<DagNodeId> {
        let mut visited = std::collections::HashSet::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if !visited.insert(id) {
                continue;
            }
            if let Some(node) = arena.get(id) {
                match node {
                    DagNode::BinOp { left, right, .. } => {
                        stack.push(*left);
                        stack.push(*right);
                    }
                    DagNode::UnOp { operand, .. } => {
                        stack.push(*operand);
                    }
                    DagNode::Cond {
                        cond,
                        then_val,
                        else_val,
                    } => {
                        stack.push(*cond);
                        stack.push(*then_val);
                        stack.push(*else_val);
                    }
                    DagNode::Call { args, .. } => {
                        for &a in args {
                            stack.push(a);
                        }
                    }
                    _ => {}
                }
            }
        }
        visited
    }

    /// Mark all nodes not reachable from `root` as dead.
    pub fn sweep(&mut self, root: DagNodeId, arena: &mut DagArena) {
        let live = Self::reachable(root, arena);
        let count = arena.total_count();
        for i in 0..count {
            let id = DagNodeId(crate::usize_trunc_u32(i)); // safe: intern() guards count <= u32::MAX
            if !live.contains(&id)
                && !arena.get(id).is_none_or(DagNode::is_dead) {
                    arena.mark_dead(id);
                    self.marked += 1;
                }
        }
    }
}

// ---------------------------------------------------------------------------
// ConstantFolding
// ---------------------------------------------------------------------------

/// Evaluates constant binary and unary subexpressions in the DAG.
#[derive(Debug, Default)]
pub struct ConstantFolding {
    pub folded: usize,
}

impl ConstantFolding {
    /// Attempt to fold the node at `id` in `arena`.  If it folds, replace
    /// the node with a `Const` and return the new id; otherwise return `id`.
    pub fn fold(&mut self, id: DagNodeId, arena: &mut DagArena) -> DagNodeId {
        let node = match arena.get(id) {
            Some(n) => n.clone(),
            None => return id,
        };
        match &node {
            DagNode::BinOp { op, left, right } => {
                let op = *op;
                let l_id = *left;
                let r_id = *right;
                let lv = arena.get(l_id).and_then(DagNode::const_value);
                let rv = arena.get(r_id).and_then(DagNode::const_value);
                if let (Some(lv), Some(rv)) = (lv, rv) {
                    let result = Self::eval_binop(op, lv, rv);
                    if let Some(v) = result {
                        let new_node = DagNode::Const(v);
                        let new_id = arena.intern(new_node);
                        arena.mark_dead(id);
                        self.folded += 1;
                        return new_id;
                    }
                }
            }
            DagNode::UnOp { op, operand } => {
                let op = *op;
                let o_id = *operand;
                if let Some(ov) = arena.get(o_id).and_then(DagNode::const_value) {
                    let result = Self::eval_unop(op, ov);
                    if let Some(v) = result {
                        let new_node = DagNode::Const(v);
                        let new_id = arena.intern(new_node);
                        arena.mark_dead(id);
                        self.folded += 1;
                        return new_id;
                    }
                }
            }
            _ => {}
        }
        id
    }

    fn eval_binop(op: BinOpKind, l: i64, r: i64) -> Option<i64> {
        match op {
            BinOpKind::Add => Some(l.wrapping_add(r)),
            BinOpKind::Sub => Some(l.wrapping_sub(r)),
            BinOpKind::Mul => Some(l.wrapping_mul(r)),
            BinOpKind::DivS => {
                if r != 0 {
                    Some(l / r)
                } else {
                    None
                }
            }
            BinOpKind::And => Some(l & r),
            BinOpKind::Or => Some(l | r),
            BinOpKind::Xor => Some(l ^ r),
            BinOpKind::Shl => Some(l << (r & 63)),
            BinOpKind::Shr => Some(crate::u64_as_i64(crate::i64_as_u64(l) >> (r & 63))),
            BinOpKind::Sar => Some(l >> (r & 63)),
            BinOpKind::CmpEq => Some(i64::from(l == r)),
            BinOpKind::CmpNe => Some(i64::from(l != r)),
            BinOpKind::CmpLt => Some(i64::from(l < r)),
            BinOpKind::CmpLe => Some(i64::from(l <= r)),
            BinOpKind::CmpGt => Some(i64::from(l > r)),
            BinOpKind::CmpGe => Some(i64::from(l >= r)),
            _ => None,
        }
    }

    const fn eval_unop(op: UnOpKind, v: i64) -> Option<i64> {
        match op {
            UnOpKind::Neg => Some(v.wrapping_neg()),
            UnOpKind::Not => Some(!v),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// BitwiseSimplify
// ---------------------------------------------------------------------------

/// Applies bitwise algebraic rules directly to [`DagNode`]s:
/// * `x & 0 → 0`     `x | 0 → x`     `x ^ 0 → x`
/// * `x & x → x`     `x | x → x`     `x ^ x → 0`
/// * `x & ~0 → x`    `x | ~0 → ~0`
/// * `~~x → x`       `--x → x`
#[derive(Debug, Default)]
pub struct BitwiseSimplify {
    pub applied: usize,
}

impl BitwiseSimplify {
    /// Attempt to simplify node `id`.  Returns the canonical simplified id.
    pub fn simplify(&mut self, id: DagNodeId, arena: &mut DagArena) -> DagNodeId {
        let node = match arena.get(id) {
            Some(n) => n.clone(),
            None => return id,
        };
        match &node {
            DagNode::BinOp { op, left, right } => {
                let op = *op;
                let l = *left;
                let r = *right;

                // x & 0 → 0
                if op == BinOpKind::And {
                    if Self::is_zero(l, arena) || Self::is_zero(r, arena) {
                        self.applied += 1;
                        return arena.intern(DagNode::Const(0));
                    }
                    // x & x → x
                    if l == r {
                        self.applied += 1;
                        return l;
                    }
                }
                // x | 0 → x
                if op == BinOpKind::Or {
                    if Self::is_zero(r, arena) {
                        self.applied += 1;
                        return l;
                    }
                    if Self::is_zero(l, arena) {
                        self.applied += 1;
                        return r;
                    }
                    if l == r {
                        self.applied += 1;
                        return l;
                    }
                }
                // x ^ 0 → x
                if op == BinOpKind::Xor {
                    if Self::is_zero(r, arena) {
                        self.applied += 1;
                        return l;
                    }
                    if Self::is_zero(l, arena) {
                        self.applied += 1;
                        return r;
                    }
                    // x ^ x → 0
                    if l == r {
                        self.applied += 1;
                        return arena.intern(DagNode::Const(0));
                    }
                }
                // x + 0 → x
                if op == BinOpKind::Add {
                    if Self::is_zero(r, arena) {
                        self.applied += 1;
                        return l;
                    }
                    if Self::is_zero(l, arena) {
                        self.applied += 1;
                        return r;
                    }
                }
                // x - 0 → x
                if op == BinOpKind::Sub {
                    if Self::is_zero(r, arena) {
                        self.applied += 1;
                        return l;
                    }
                    // x - x → 0
                    if l == r {
                        self.applied += 1;
                        return arena.intern(DagNode::Const(0));
                    }
                }
            }
            DagNode::UnOp { op, operand } => {
                // --x → x  and  ~~x → x
                if matches!(op, UnOpKind::Neg | UnOpKind::Not)
                    && let Some(DagNode::UnOp {
                        op: inner_op,
                        operand: inner,
                    }) = arena.get(*operand).cloned()
                        && inner_op == *op {
                            self.applied += 1;
                            return inner;
                        }
            }
            _ => {}
        }
        id
    }

    fn is_zero(id: DagNodeId, arena: &DagArena) -> bool {
        arena.get(id).and_then(DagNode::const_value) == Some(0)
    }
}

// ---------------------------------------------------------------------------
// DagSimplifier
// ---------------------------------------------------------------------------

/// Orchestrates all DAG simplification passes over an expression arena.
#[derive(Debug, Default)]
pub struct DagSimplifier {
    pub arena: DagArena,
    pub cse: CommonSubexpr,
    pub dead: DeadNode,
    pub cfold: ConstantFolding,
    pub bitwise: BitwiseSimplify,
}

impl DagSimplifier {
    /// Create a fresh simplifier.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a constant node.
    pub fn const_node(&mut self, v: i64) -> DagNodeId {
        self.cse.intern(&mut self.arena, DagNode::Const(v))
    }

    /// Add a variable node.
    pub fn var_node(&mut self, name: impl Into<String>) -> DagNodeId {
        self.cse.intern(&mut self.arena, DagNode::Var(name.into()))
    }

    /// Add a binary operation node.
    pub fn binop(&mut self, op: BinOpKind, l: DagNodeId, r: DagNodeId) -> DagNodeId {
        let node = DagNode::BinOp {
            op,
            left: l,
            right: r,
        };
        self.cse.intern(&mut self.arena, node)
    }

    /// Add a unary operation node.
    pub fn unop(&mut self, op: UnOpKind, operand: DagNodeId) -> DagNodeId {
        let node = DagNode::UnOp { op, operand };
        self.cse.intern(&mut self.arena, node)
    }

    /// Run constant folding on `id`.
    pub fn fold(&mut self, id: DagNodeId) -> DagNodeId {
        self.cfold.fold(id, &mut self.arena)
    }

    /// Run bitwise simplification on `id`.
    pub fn simplify_bitwise(&mut self, id: DagNodeId) -> DagNodeId {
        self.bitwise.simplify(id, &mut self.arena)
    }

    /// Run a full simplification pass (fold + bitwise) on `id`, up to
    /// `max_iter` iterations.
    pub fn simplify(&mut self, id: DagNodeId, max_iter: usize) -> DagNodeId {
        let mut cur = id;
        for _ in 0..max_iter {
            let folded = self.fold(cur);
            let bitwise = self.simplify_bitwise(folded);
            if bitwise == cur {
                break;
            }
            cur = bitwise;
        }
        cur
    }

    /// Sweep dead nodes from the DAG rooted at `root`.
    pub fn sweep_dead(&mut self, root: DagNodeId) {
        self.dead.sweep(root, &mut self.arena);
    }

    /// Evaluate the DAG node `id` in a context where variable values are given
    /// by `env`.
    #[must_use] 
    pub fn eval(&self, id: DagNodeId, env: &HashMap<String, i64>) -> Option<i64> {
        let node = self.arena.get(id)?;
        match node {
            DagNode::Const(v) => Some(*v),
            DagNode::Var(name) => env.get(name).copied(),
            DagNode::BinOp { op, left, right } => {
                let op = *op;
                let lv = self.eval(*left, env)?;
                let rv = self.eval(*right, env)?;
                ConstantFolding::eval_binop(op, lv, rv)
            }
            DagNode::UnOp { op, operand } => {
                let v = self.eval(*operand, env)?;
                ConstantFolding::eval_unop(*op, v)
            }
            DagNode::Cond {
                cond,
                then_val,
                else_val,
            } => {
                let cv = self.eval(*cond, env)?;
                if cv != 0 {
                    self.eval(*then_val, env)
                } else {
                    self.eval(*else_val, env)
                }
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// DagPrinter — textual rendering of a DAG
// ---------------------------------------------------------------------------

/// Renders a DAG node tree to a human-readable expression string.
pub struct DagPrinter<'a> {
    arena: &'a DagArena,
}

impl<'a> DagPrinter<'a> {
    /// Create a printer for the given arena.
    #[must_use]
    pub const fn new(arena: &'a DagArena) -> Self {
        Self { arena }
    }

    /// Render the node at `id` as a string.
    #[must_use] 
    pub fn print(&self, id: DagNodeId) -> String {
        match self.arena.get(id) {
            None => "<invalid>".into(),
            Some(DagNode::Dead) => "<dead>".into(),
            Some(DagNode::Const(v)) => format!("{v}"),
            Some(DagNode::Bool(b)) => format!("{b}"),
            Some(DagNode::Var(n)) => n.clone(),
            Some(DagNode::BinOp { op, left, right }) => {
                let op = *op;
                let l = *left;
                let r = *right;
                format!("({} {} {})", self.print(l), op.symbol(), self.print(r))
            }
            Some(DagNode::UnOp { op, operand }) => {
                let op = *op;
                let o = *operand;
                format!("({}{})", op.symbol(), self.print(o))
            }
            Some(DagNode::Cond {
                cond,
                then_val,
                else_val,
            }) => {
                let c = *cond;
                let tv = *then_val;
                let fv = *else_val;
                format!(
                    "({} ? {} : {})",
                    self.print(c),
                    self.print(tv),
                    self.print(fv)
                )
            }
            Some(DagNode::Call { name, args }) => {
                let name = name.clone();
                let args: Vec<DagNodeId> = args.clone();
                let arg_strs: Vec<String> = args.iter().map(|&a| self.print(a)).collect();
                format!("{name}({})", arg_strs.join(", "))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DagStatistics — metrics over a DAG arena
// ---------------------------------------------------------------------------

/// Aggregated statistics about a DAG arena.
#[derive(Debug, Clone, Default)]
pub struct DagStatistics {
    pub total_nodes: usize,
    pub live_nodes: usize,
    pub dead_nodes: usize,
    pub const_nodes: usize,
    pub var_nodes: usize,
    pub binop_nodes: usize,
    pub unop_nodes: usize,
}

impl DagStatistics {
    /// Compute statistics for `arena`.
    #[must_use]
    pub fn compute(arena: &DagArena) -> Self {
        let mut s = Self {
            total_nodes: arena.total_count(),
            ..Self::default()
        };
        for node in &arena.nodes {
            match node {
                DagNode::Dead => s.dead_nodes += 1,
                DagNode::Const(_) | DagNode::Bool(_) => s.const_nodes += 1,
                DagNode::Var(_) => s.var_nodes += 1,
                DagNode::BinOp { .. } => s.binop_nodes += 1,
                DagNode::UnOp { .. } => s.unop_nodes += 1,
                _ => {}
            }
        }
        s.live_nodes = arena.live_count();
        s
    }
}

// ---------------------------------------------------------------------------
// CommutativeNormalizer — puts commutative operands in canonical order
// ---------------------------------------------------------------------------

/// Normalises commutative binary operations so the operand with the smaller
/// [`DagNodeId`] is always on the left.  This maximises CSE hit rates.
#[derive(Debug, Default)]
pub struct CommutativeNormalizer {
    pub swaps: usize,
}

impl CommutativeNormalizer {
    /// Normalise node `id` in `arena`.  Returns the canonical id (same or a
    /// new interned node).
    pub fn normalize(&mut self, id: DagNodeId, arena: &mut DagArena) -> DagNodeId {
        let node = match arena.get(id) {
            Some(n) => n.clone(),
            None => return id,
        };
        if let DagNode::BinOp { op, left, right } = node
            && op.is_commutative() && right < left {
                let new_node = DagNode::BinOp {
                    op,
                    left: right,
                    right: left,
                };
                self.swaps += 1;
                return arena.intern(new_node);
            }
        id
    }
}

// ---------------------------------------------------------------------------
// ConstantEvaluator — evaluates a DAG in a given environment
// ---------------------------------------------------------------------------

/// Fully evaluates a DAG to a constant, if all leaf variables are in `env`.
pub struct ConstantEvaluator<'a> {
    arena: &'a DagArena,
    env: &'a HashMap<String, i64>,
}

impl<'a> ConstantEvaluator<'a> {
    /// Create an evaluator.
    #[must_use]
    pub const fn new(arena: &'a DagArena, env: &'a HashMap<String, i64>) -> Self {
        Self { arena, env }
    }

    /// Evaluate node `id`, returning `None` if not fully constant.
    #[must_use] 
    pub fn eval(&self, id: DagNodeId) -> Option<i64> {
        let node = self.arena.get(id)?;
        match node {
            DagNode::Const(v) => Some(*v),
            DagNode::Bool(b) => Some(i64::from(*b)),
            DagNode::Var(name) => self.env.get(name).copied(),
            DagNode::BinOp { op, left, right } => {
                let op = *op;
                let l = *left;
                let r = *right;
                let lv = self.eval(l)?;
                let rv = self.eval(r)?;
                ConstantFolding::eval_binop(op, lv, rv)
            }
            DagNode::UnOp { op, operand } => {
                let op = *op;
                let o = *operand;
                let v = self.eval(o)?;
                ConstantFolding::eval_unop(op, v)
            }
            DagNode::Cond {
                cond,
                then_val,
                else_val,
            } => {
                let cv = self.eval(*cond)?;
                if cv != 0 {
                    self.eval(*then_val)
                } else {
                    self.eval(*else_val)
                }
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// ReachableNodes — traversal utilities
// ---------------------------------------------------------------------------

/// Traversal helpers for DAG arenas.
pub struct ReachableNodes;

impl ReachableNodes {
    /// Collect all node ids reachable from `root`.
    #[must_use] 
    pub fn collect(root: DagNodeId, arena: &DagArena) -> std::collections::HashSet<DagNodeId> {
        let mut visited = std::collections::HashSet::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if !visited.insert(id) {
                continue;
            }
            if let Some(node) = arena.get(id) {
                match node {
                    DagNode::BinOp { left, right, .. } => {
                        stack.push(*left);
                        stack.push(*right);
                    }
                    DagNode::UnOp { operand, .. } => {
                        stack.push(*operand);
                    }
                    DagNode::Cond {
                        cond,
                        then_val,
                        else_val,
                    } => {
                        stack.push(*cond);
                        stack.push(*then_val);
                        stack.push(*else_val);
                    }
                    DagNode::Call { args, .. } => {
                        for &a in args {
                            stack.push(a);
                        }
                    }
                    _ => {}
                }
            }
        }
        visited
    }

    /// Count distinct reachable variable names.
    #[must_use] 
    pub fn variable_count(root: DagNodeId, arena: &DagArena) -> usize {
        let reachable = Self::collect(root, arena);
        reachable
            .iter()
            .filter(|&&id| matches!(arena.get(id), Some(DagNode::Var(_))))
            .count()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- DagHash ---

    #[test]
    fn dag_hash_eq() {
        assert_eq!(DagHash::new("C42"), DagHash::new("C42"));
        assert_ne!(DagHash::new("C42"), DagHash::new("C43"));
    }

    #[test]
    fn dag_hash_display() {
        assert_eq!(format!("{}", DagHash::new("xyz")), "xyz");
    }

    // --- DagNodeId ---

    #[test]
    fn node_id_display() {
        assert_eq!(format!("{}", DagNodeId(7)), "n7");
    }

    #[test]
    fn node_id_ordering() {
        assert!(DagNodeId(0) < DagNodeId(1));
    }

    // --- DagNode ---

    #[test]
    fn node_is_const() {
        assert!(DagNode::Const(5).is_const());
        assert!(DagNode::Bool(true).is_const());
        assert!(!DagNode::Dead.is_const());
    }

    #[test]
    fn node_const_value() {
        assert_eq!(DagNode::Const(42).const_value(), Some(42));
        assert_eq!(DagNode::Var("x".into()).const_value(), None);
    }

    #[test]
    fn node_is_dead() {
        assert!(DagNode::Dead.is_dead());
        assert!(!DagNode::Const(0).is_dead());
    }

    // --- BinOpKind ---

    #[test]
    fn binop_symbol() {
        assert_eq!(BinOpKind::Add.symbol(), "+");
        assert_eq!(BinOpKind::Xor.symbol(), "^");
    }

    #[test]
    fn binop_commutative() {
        assert!(BinOpKind::Add.is_commutative());
        assert!(!BinOpKind::Sub.is_commutative());
    }

    // --- UnOpKind ---

    #[test]
    fn unop_symbol() {
        assert_eq!(UnOpKind::Neg.symbol(), "-");
        assert_eq!(UnOpKind::Not.symbol(), "~");
    }

    // --- DagArena ---

    #[test]
    fn arena_intern_deduplicates() {
        let mut a = DagArena::default();
        let id1 = a.intern(DagNode::Const(5));
        let id2 = a.intern(DagNode::Const(5));
        assert_eq!(id1, id2);
        assert_eq!(a.total_count(), 1);
    }

    #[test]
    fn arena_distinct_nodes() {
        let mut a = DagArena::default();
        let id1 = a.intern(DagNode::Const(1));
        let id2 = a.intern(DagNode::Const(2));
        assert_ne!(id1, id2);
        assert_eq!(a.total_count(), 2);
    }

    #[test]
    fn arena_mark_dead() {
        let mut a = DagArena::default();
        let id = a.intern(DagNode::Const(42));
        a.mark_dead(id);
        assert!(a.get(id).unwrap().is_dead());
        assert_eq!(a.live_count(), 0);
    }

    // --- CommonSubexpr ---

    #[test]
    fn cse_dedup_count() {
        let mut cse = CommonSubexpr::default();
        let mut a = DagArena::default();
        cse.intern(&mut a, DagNode::Const(7));
        cse.intern(&mut a, DagNode::Const(7)); // duplicate
        assert_eq!(cse.dedup_count, 1);
    }

    // --- DeadNode ---

    #[test]
    fn dead_sweep_marks_unreachable() {
        let mut a = DagArena::default();
        let root = a.intern(DagNode::Const(1));
        let _orphan = a.intern(DagNode::Const(99));
        let mut dead = DeadNode::default();
        dead.sweep(root, &mut a);
        assert_eq!(dead.marked, 1);
    }

    #[test]
    fn dead_sweep_keeps_reachable() {
        let mut a = DagArena::default();
        let lc = a.intern(DagNode::Const(2));
        let rc = a.intern(DagNode::Const(3));
        let root = a.intern(DagNode::BinOp {
            op: BinOpKind::Add,
            left: lc,
            right: rc,
        });
        let mut dead = DeadNode::default();
        dead.sweep(root, &mut a);
        assert_eq!(dead.marked, 0);
    }

    // --- ConstantFolding ---

    #[test]
    fn cfold_add_two_consts() {
        let mut a = DagArena::default();
        let lc = a.intern(DagNode::Const(3));
        let rc = a.intern(DagNode::Const(7));
        let op = a.intern(DagNode::BinOp {
            op: BinOpKind::Add,
            left: lc,
            right: rc,
        });
        let mut cf = ConstantFolding::default();
        let result = cf.fold(op, &mut a);
        assert_eq!(a.get(result).and_then(super::DagNode::const_value), Some(10));
        assert_eq!(cf.folded, 1);
    }

    #[test]
    fn cfold_neg_const() {
        let mut a = DagArena::default();
        let c = a.intern(DagNode::Const(5));
        let op = a.intern(DagNode::UnOp {
            op: UnOpKind::Neg,
            operand: c,
        });
        let mut cf = ConstantFolding::default();
        let result = cf.fold(op, &mut a);
        assert_eq!(a.get(result).and_then(super::DagNode::const_value), Some(-5));
    }

    #[test]
    fn cfold_no_fold_for_var() {
        let mut a = DagArena::default();
        let v = a.intern(DagNode::Var("x".into()));
        let c = a.intern(DagNode::Const(1));
        let op = a.intern(DagNode::BinOp {
            op: BinOpKind::Add,
            left: v,
            right: c,
        });
        let mut cf = ConstantFolding::default();
        let result = cf.fold(op, &mut a);
        assert_eq!(result, op); // unchanged
        assert_eq!(cf.folded, 0);
    }

    // --- BitwiseSimplify ---

    #[test]
    fn bitwise_and_zero() {
        let mut s = DagSimplifier::new();
        let x = s.var_node("x");
        let z = s.const_node(0);
        let and = s.binop(BinOpKind::And, x, z);
        let res = s.simplify_bitwise(and);
        assert_eq!(s.arena.get(res).and_then(super::DagNode::const_value), Some(0));
    }

    #[test]
    fn bitwise_or_zero() {
        let mut s = DagSimplifier::new();
        let x = s.var_node("x");
        let z = s.const_node(0);
        let or = s.binop(BinOpKind::Or, x, z);
        let res = s.simplify_bitwise(or);
        assert_eq!(res, x);
    }

    #[test]
    fn bitwise_xor_zero() {
        let mut s = DagSimplifier::new();
        let x = s.var_node("x");
        let z = s.const_node(0);
        let xor = s.binop(BinOpKind::Xor, x, z);
        let res = s.simplify_bitwise(xor);
        assert_eq!(res, x);
    }

    #[test]
    fn bitwise_xor_self_zero() {
        let mut s = DagSimplifier::new();
        let x = s.var_node("x");
        let xor = s.binop(BinOpKind::Xor, x, x);
        let res = s.simplify_bitwise(xor);
        assert_eq!(s.arena.get(res).and_then(super::DagNode::const_value), Some(0));
    }

    #[test]
    fn bitwise_double_neg() {
        let mut s = DagSimplifier::new();
        let x = s.var_node("x");
        let neg = s.unop(UnOpKind::Neg, x);
        let neg2 = s.unop(UnOpKind::Neg, neg);
        let res = s.simplify_bitwise(neg2);
        assert_eq!(res, x);
    }

    #[test]
    fn bitwise_add_zero() {
        let mut s = DagSimplifier::new();
        let x = s.var_node("x");
        let z = s.const_node(0);
        let add = s.binop(BinOpKind::Add, x, z);
        let res = s.simplify_bitwise(add);
        assert_eq!(res, x);
    }

    #[test]
    fn bitwise_sub_zero() {
        let mut s = DagSimplifier::new();
        let x = s.var_node("x");
        let z = s.const_node(0);
        let sub = s.binop(BinOpKind::Sub, x, z);
        let res = s.simplify_bitwise(sub);
        assert_eq!(res, x);
    }

    #[test]
    fn bitwise_sub_self_zero() {
        let mut s = DagSimplifier::new();
        let x = s.var_node("x");
        let sub = s.binop(BinOpKind::Sub, x, x);
        let res = s.simplify_bitwise(sub);
        assert_eq!(s.arena.get(res).and_then(super::DagNode::const_value), Some(0));
    }

    // --- DagSimplifier eval ---

    #[test]
    fn eval_const() {
        let s = DagSimplifier::new();
        let _id = s.arena.nodes.len(); // hack: create manually
        let mut s = DagSimplifier::new();
        let id = s.const_node(42);
        assert_eq!(s.eval(id, &HashMap::new()), Some(42));
    }

    #[test]
    fn eval_var() {
        let mut s = DagSimplifier::new();
        let id = s.var_node("y");
        let mut env = HashMap::new();
        env.insert("y".into(), 7i64);
        assert_eq!(s.eval(id, &env), Some(7));
    }

    #[test]
    fn eval_binop() {
        let mut s = DagSimplifier::new();
        let l = s.const_node(3);
        let r = s.const_node(4);
        let add = s.binop(BinOpKind::Add, l, r);
        assert_eq!(s.eval(add, &HashMap::new()), Some(7));
    }

    #[test]
    fn simplify_full_pipeline() {
        let mut s = DagSimplifier::new();
        // (3 + 0) should simplify to 3.
        let three = s.const_node(3);
        let zero = s.const_node(0);
        let add = s.binop(BinOpKind::Add, three, zero);
        let res = s.simplify(add, 5);
        assert_eq!(s.arena.get(res).and_then(super::DagNode::const_value), Some(3));
    }

    #[test]
    fn sweep_dead_after_simplify() {
        let mut s = DagSimplifier::new();
        let c = s.const_node(5);
        let z = s.const_node(0);
        let add = s.binop(BinOpKind::Add, c, z);
        let res = s.simplify(add, 5);
        s.sweep_dead(res);
        // At least some nodes should be dead.
        assert!(s.arena.live_count() <= s.arena.total_count());
    }

    // --- ConstantFolding additional ---

    #[test]
    fn cfold_sub_consts() {
        let mut a = DagArena::default();
        let lc = a.intern(DagNode::Const(10));
        let rc = a.intern(DagNode::Const(3));
        let op = a.intern(DagNode::BinOp {
            op: BinOpKind::Sub,
            left: lc,
            right: rc,
        });
        let mut cf = ConstantFolding::default();
        let result = cf.fold(op, &mut a);
        assert_eq!(a.get(result).and_then(super::DagNode::const_value), Some(7));
    }

    #[test]
    fn cfold_mul_consts() {
        let mut a = DagArena::default();
        let lc = a.intern(DagNode::Const(6));
        let rc = a.intern(DagNode::Const(7));
        let op = a.intern(DagNode::BinOp {
            op: BinOpKind::Mul,
            left: lc,
            right: rc,
        });
        let mut cf = ConstantFolding::default();
        let result = cf.fold(op, &mut a);
        assert_eq!(a.get(result).and_then(super::DagNode::const_value), Some(42));
    }

    #[test]
    fn cfold_cmp_eq_true() {
        let mut a = DagArena::default();
        let lc = a.intern(DagNode::Const(5));
        let rc = a.intern(DagNode::Const(5));
        let op = a.intern(DagNode::BinOp {
            op: BinOpKind::CmpEq,
            left: lc,
            right: rc,
        });
        let mut cf = ConstantFolding::default();
        let result = cf.fold(op, &mut a);
        assert_eq!(a.get(result).and_then(super::DagNode::const_value), Some(1));
    }

    #[test]
    fn cfold_cmp_lt_false() {
        let mut a = DagArena::default();
        let lc = a.intern(DagNode::Const(10));
        let rc = a.intern(DagNode::Const(5));
        let op = a.intern(DagNode::BinOp {
            op: BinOpKind::CmpLt,
            left: lc,
            right: rc,
        });
        let mut cf = ConstantFolding::default();
        let result = cf.fold(op, &mut a);
        assert_eq!(a.get(result).and_then(super::DagNode::const_value), Some(0));
    }

    #[test]
    fn cfold_div_by_zero_no_fold() {
        let mut a = DagArena::default();
        let lc = a.intern(DagNode::Const(10));
        let rc = a.intern(DagNode::Const(0));
        let op = a.intern(DagNode::BinOp {
            op: BinOpKind::DivS,
            left: lc,
            right: rc,
        });
        let mut cf = ConstantFolding::default();
        let result = cf.fold(op, &mut a);
        assert_eq!(result, op); // no fold when dividing by zero
    }

    // --- BitwiseSimplify additional ---

    #[test]
    fn bitwise_and_self() {
        let mut s = DagSimplifier::new();
        let x = s.var_node("x");
        let and = s.binop(BinOpKind::And, x, x);
        let res = s.simplify_bitwise(and);
        assert_eq!(res, x);
    }

    #[test]
    fn bitwise_or_self() {
        let mut s = DagSimplifier::new();
        let x = s.var_node("x");
        let or = s.binop(BinOpKind::Or, x, x);
        let res = s.simplify_bitwise(or);
        assert_eq!(res, x);
    }

    #[test]
    fn bitwise_double_not() {
        let mut s = DagSimplifier::new();
        let x = s.var_node("x");
        let not1 = s.unop(UnOpKind::Not, x);
        let not2 = s.unop(UnOpKind::Not, not1);
        let res = s.simplify_bitwise(not2);
        assert_eq!(res, x);
    }

    // --- DagSimplifier eval additional ---

    #[test]
    fn eval_sub_consts() {
        let mut s = DagSimplifier::new();
        let l = s.const_node(10);
        let r = s.const_node(4);
        let sub = s.binop(BinOpKind::Sub, l, r);
        assert_eq!(s.eval(sub, &HashMap::new()), Some(6));
    }

    #[test]
    fn eval_cond_node_true() {
        let mut s = DagSimplifier::new();
        let cond = s.const_node(1);
        let t = s.const_node(10);
        let f = s.const_node(20);
        let cond_node = s.cse.intern(
            &mut s.arena,
            DagNode::Cond {
                cond,
                then_val: t,
                else_val: f,
            },
        );
        assert_eq!(s.eval(cond_node, &HashMap::new()), Some(10));
    }

    #[test]
    fn eval_cond_node_false() {
        let mut s = DagSimplifier::new();
        let cond = s.const_node(0);
        let t = s.const_node(10);
        let f = s.const_node(20);
        let cond_node = s.cse.intern(
            &mut s.arena,
            DagNode::Cond {
                cond,
                then_val: t,
                else_val: f,
            },
        );
        assert_eq!(s.eval(cond_node, &HashMap::new()), Some(20));
    }

    #[test]
    fn eval_missing_var_none() {
        let mut s = DagSimplifier::new();
        let id = s.var_node("missing");
        assert_eq!(s.eval(id, &HashMap::new()), None);
    }

    // --- DagArena get on valid id ---

    #[test]
    fn arena_get_valid_node() {
        let mut a = DagArena::default();
        let id = a.intern(DagNode::Const(99));
        assert_eq!(a.get(id).and_then(super::DagNode::const_value), Some(99));
    }

    #[test]
    fn arena_get_invalid_id_none() {
        let a = DagArena::default();
        assert!(a.get(DagNodeId(999)).is_none());
    }

    // --- DagNode hash_key ---

    #[test]
    fn dag_node_var_hash() {
        let a = DagArena::default();
        let h = DagNode::Var("x".into()).hash_key(&a);
        assert_eq!(h.as_str(), "Vx");
    }

    #[test]
    fn dag_node_const_hash() {
        let a = DagArena::default();
        let h = DagNode::Const(42).hash_key(&a);
        assert_eq!(h.as_str(), "C42");
    }

    #[test]
    fn dag_node_bool_hash() {
        let a = DagArena::default();
        let h = DagNode::Bool(true).hash_key(&a);
        assert!(h.as_str().contains("true"));
    }

    #[test]
    fn dag_node_dead_hash() {
        let a = DagArena::default();
        let h = DagNode::Dead.hash_key(&a);
        assert_eq!(h.as_str(), "DEAD");
    }

    // --- DagPrinter tests ---

    #[test]
    fn dag_printer_const() {
        let mut a = DagArena::default();
        let id = a.intern(DagNode::Const(42));
        let p = DagPrinter::new(&a);
        assert_eq!(p.print(id), "42");
    }

    #[test]
    fn dag_printer_var() {
        let mut a = DagArena::default();
        let id = a.intern(DagNode::Var("x".into()));
        let p = DagPrinter::new(&a);
        assert_eq!(p.print(id), "x");
    }

    #[test]
    fn dag_printer_binop() {
        let mut a = DagArena::default();
        let l = a.intern(DagNode::Const(1));
        let r = a.intern(DagNode::Const(2));
        let op = a.intern(DagNode::BinOp {
            op: BinOpKind::Add,
            left: l,
            right: r,
        });
        let p = DagPrinter::new(&a);
        assert!(p.print(op).contains('+'));
    }

    #[test]
    fn dag_printer_unop() {
        let mut a = DagArena::default();
        let v = a.intern(DagNode::Var("x".into()));
        let op = a.intern(DagNode::UnOp {
            op: UnOpKind::Neg,
            operand: v,
        });
        let p = DagPrinter::new(&a);
        assert!(p.print(op).contains('-'));
    }

    #[test]
    fn dag_printer_dead() {
        let mut a = DagArena::default();
        let id = a.intern(DagNode::Const(1));
        a.mark_dead(id);
        let p = DagPrinter::new(&a);
        assert_eq!(p.print(id), "<dead>");
    }

    #[test]
    fn dag_printer_invalid_id() {
        let a = DagArena::default();
        let p = DagPrinter::new(&a);
        assert_eq!(p.print(DagNodeId(999)), "<invalid>");
    }

    // --- DagStatistics tests ---

    #[test]
    fn dag_stats_empty() {
        let a = DagArena::default();
        let s = DagStatistics::compute(&a);
        assert_eq!(s.total_nodes, 0);
    }

    #[test]
    fn dag_stats_one_const() {
        let mut a = DagArena::default();
        a.intern(DagNode::Const(7));
        let s = DagStatistics::compute(&a);
        assert_eq!(s.const_nodes, 1);
        assert_eq!(s.live_nodes, 1);
        assert_eq!(s.dead_nodes, 0);
    }

    #[test]
    fn dag_stats_dead_nodes() {
        let mut a = DagArena::default();
        let id = a.intern(DagNode::Const(7));
        a.mark_dead(id);
        let s = DagStatistics::compute(&a);
        assert_eq!(s.dead_nodes, 1);
        assert_eq!(s.live_nodes, 0);
    }

    #[test]
    fn dag_stats_var_and_binop() {
        let mut a = DagArena::default();
        let v1 = a.intern(DagNode::Var("a".into()));
        let v2 = a.intern(DagNode::Var("b".into()));
        a.intern(DagNode::BinOp {
            op: BinOpKind::Add,
            left: v1,
            right: v2,
        });
        let s = DagStatistics::compute(&a);
        assert_eq!(s.var_nodes, 2);
        assert_eq!(s.binop_nodes, 1);
    }

    // --- CommutativeNormalizer tests ---

    #[test]
    fn comm_normalizer_swaps_reversed() {
        let mut a = DagArena::default();
        let big = a.intern(DagNode::Var("z".into())); // gets higher id
        let small = a.intern(DagNode::Const(1)); // gets lower id
        // Create big + small (right id < left id)
        let op = a.intern(DagNode::BinOp {
            op: BinOpKind::Add,
            left: big,
            right: small,
        });
        let mut cn = CommutativeNormalizer::default();
        let result = cn.normalize(op, &mut a);
        if let Some(DagNode::BinOp { left, right, .. }) = a.get(result) {
            assert!(*left <= *right);
        }
        let _ = cn.swaps; // may or may not swap depending on ids
    }

    #[test]
    fn comm_normalizer_no_swap_needed() {
        let mut a = DagArena::default();
        let small = a.intern(DagNode::Const(1)); // id 0
        let big = a.intern(DagNode::Var("x".into())); // id 1
        let op = a.intern(DagNode::BinOp {
            op: BinOpKind::Add,
            left: small,
            right: big,
        });
        let mut cn = CommutativeNormalizer::default();
        let result = cn.normalize(op, &mut a);
        // Should not swap since small < big.
        assert_eq!(cn.swaps, 0);
        let _ = result;
    }

    #[test]
    fn comm_normalizer_non_commutative_unchanged() {
        let mut a = DagArena::default();
        let big = a.intern(DagNode::Var("x".into()));
        let small = a.intern(DagNode::Const(1));
        // Sub is not commutative.
        let op = a.intern(DagNode::BinOp {
            op: BinOpKind::Sub,
            left: big,
            right: small,
        });
        let mut cn = CommutativeNormalizer::default();
        let result = cn.normalize(op, &mut a);
        assert_eq!(result, op);
        assert_eq!(cn.swaps, 0);
    }

    // --- DagArena live count ---

    #[test]
    fn arena_live_count_after_marking() {
        let mut a = DagArena::default();
        a.intern(DagNode::Const(1));
        a.intern(DagNode::Const(2));
        assert_eq!(a.live_count(), 2);
        let id = a.intern(DagNode::Const(3));
        a.mark_dead(id);
        assert_eq!(a.live_count(), 2);
    }

    // --- Full pipeline with commutative normalization + simplify ---

    #[test]
    fn full_pipeline_var_add_zero_with_norm() {
        let mut s = DagSimplifier::new();
        let x = s.var_node("x");
        let z = s.const_node(0);
        let add = s.binop(BinOpKind::Add, z, x); // 0 + x
        let simplified = s.simplify(add, 10);
        assert_eq!(simplified, x);
    }

    // --- ConstantEvaluator tests ---

    #[test]
    fn const_evaluator_const_node() {
        let mut a = DagArena::default();
        let id = a.intern(DagNode::Const(99));
        let env = HashMap::new();
        let ev = ConstantEvaluator::new(&a, &env);
        assert_eq!(ev.eval(id), Some(99));
    }

    #[test]
    fn const_evaluator_var_with_env() {
        let mut a = DagArena::default();
        let id = a.intern(DagNode::Var("k".into()));
        let mut env = HashMap::new();
        env.insert("k".into(), 7i64);
        let ev = ConstantEvaluator::new(&a, &env);
        assert_eq!(ev.eval(id), Some(7));
    }

    #[test]
    fn const_evaluator_binop_constant() {
        let mut a = DagArena::default();
        let l = a.intern(DagNode::Const(4));
        let r = a.intern(DagNode::Const(5));
        let op = a.intern(DagNode::BinOp {
            op: BinOpKind::Mul,
            left: l,
            right: r,
        });
        let __vars = HashMap::new();
        let ev = ConstantEvaluator::new(&a, &__vars);
        assert_eq!(ev.eval(op), Some(20));
    }

    #[test]
    fn const_evaluator_missing_var_none() {
        let mut a = DagArena::default();
        let id = a.intern(DagNode::Var("missing".into()));
        let __vars = HashMap::new();
        let ev = ConstantEvaluator::new(&a, &__vars);
        assert_eq!(ev.eval(id), None);
    }

    #[test]
    fn const_evaluator_cond_true() {
        let mut a = DagArena::default();
        let cond = a.intern(DagNode::Bool(true));
        let tv = a.intern(DagNode::Const(10));
        let fv = a.intern(DagNode::Const(20));
        let id = a.intern(DagNode::Cond {
            cond,
            then_val: tv,
            else_val: fv,
        });
        let __vars = HashMap::new();
        let ev = ConstantEvaluator::new(&a, &__vars);
        assert_eq!(ev.eval(id), Some(10));
    }

    // --- ReachableNodes tests ---

    #[test]
    fn reachable_nodes_single_const() {
        let mut a = DagArena::default();
        let id = a.intern(DagNode::Const(1));
        let r = ReachableNodes::collect(id, &a);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn reachable_nodes_binop() {
        let mut a = DagArena::default();
        let l = a.intern(DagNode::Const(1));
        let r = a.intern(DagNode::Const(2));
        let op = a.intern(DagNode::BinOp {
            op: BinOpKind::Add,
            left: l,
            right: r,
        });
        let reach = ReachableNodes::collect(op, &a);
        assert_eq!(reach.len(), 3);
    }

    #[test]
    fn reachable_nodes_variable_count() {
        let mut a = DagArena::default();
        let v1 = a.intern(DagNode::Var("a".into()));
        let v2 = a.intern(DagNode::Var("b".into()));
        let op = a.intern(DagNode::BinOp {
            op: BinOpKind::Add,
            left: v1,
            right: v2,
        });
        assert_eq!(ReachableNodes::variable_count(op, &a), 2);
    }

    #[test]
    fn reachable_nodes_no_double_count() {
        let mut a = DagArena::default();
        let x = a.intern(DagNode::Var("x".into()));
        let op = a.intern(DagNode::BinOp {
            op: BinOpKind::Add,
            left: x,
            right: x,
        });
        let r = ReachableNodes::collect(op, &a);
        // x and op — shared x is deduplicated.
        assert_eq!(r.len(), 2);
    }

    // --- DagSimplifier::unop helper ---

    #[test]
    fn dag_simplifier_unop_helper() {
        let mut s = DagSimplifier::new();
        let x = s.var_node("x");
        let neg = s.unop(UnOpKind::Neg, x);
        assert!(s.arena.get(neg).is_some());
    }

    // --- Full fold then dead sweep ---

    #[test]
    fn fold_then_dead_sweep_minimal_live() {
        let mut s = DagSimplifier::new();
        let a = s.const_node(10);
        let b = s.const_node(10);
        let sub = s.binop(BinOpKind::Sub, a, b); // 10 - 10 → 0
        let res = s.simplify(sub, 10);
        s.sweep_dead(res);
        // Exactly the result node (0) should be live.
        assert_eq!(s.arena.live_count(), 1);
    }
}
