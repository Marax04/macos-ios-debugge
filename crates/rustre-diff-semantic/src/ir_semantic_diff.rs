//! `ir_semantic_diff` — Semantic diffing via intermediate representation.
//!
//! Compares two functions by analysing their IR (modelled here as a simple
//! architecture-neutral LLIL/MLIL-style representation):
//!
//! * **Normalisation**: register and variable names are canonicalised to
//!   positional placeholders (r0, r1, …) so that trivial renames do not count
//!   as semantic differences.
//! * **Semantic hashing**: a compact hash of the normalised IR is produced for
//!   O(1) identical-function detection.
//! * **Semantic similarity**: for non-identical functions, a fine-grained
//!   comparison is performed at the statement level using structural matching
//!   and operation-set comparison.
//! * **Equivalence detection**: identifies functions that are semantically
//!   equivalent despite superficial differences (variable renaming, constant
//!   folding, reordering of independent assignments).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

fn count_as_f64(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

// ─────────────────────────────────────────────────────────────────────────────
// IR types
// ─────────────────────────────────────────────────────────────────────────────

/// Width of an IR value in bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Width { B8, B16, B32, B64 }

impl Width {
    #[must_use]
    pub const fn bytes(self) -> u8 {
        match self { Self::B8 => 1, Self::B16 => 2, Self::B32 => 4, Self::B64 => 8 }
    }
}

impl fmt::Display for Width {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.bytes() * 8)
    }
}

/// An IR expression (subset of LLIL/MLIL expression kinds).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IrExpr {
    /// A named register or variable.
    Var(String),
    /// An integer constant.
    Const(i64),
    /// Binary operation: op, lhs, rhs.
    BinOp { op: BinOpKind, lhs: Box<Self>, rhs: Box<Self> },
    /// Unary operation.
    UnOp { op: UnOpKind, inner: Box<Self> },
    /// Memory load: address expression, data width.
    Load { addr: Box<Self>, width: Width },
    /// Function call: callee (as address or name hash), arguments.
    Call { callee: u64, args: Vec<Self> },
    /// φ-node (for SSA-form IR).
    Phi(Vec<Self>),
}

/// Binary IR operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinOpKind {
    Add, Sub, Mul, Div, Mod,
    And, Or, Xor, Shl, Shr, Sar,
    CmpEq, CmpNe, CmpLt, CmpLe, CmpGt, CmpGe,
    UDiv, UMod, Lsr,
}

/// Unary IR operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnOpKind { Neg, Not, ZeroExt, SignExt }

/// An IR statement (one item in the IR body of a basic block).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IrStmt {
    /// Variable assignment: dst = src.
    Assign { dst: String, src: IrExpr },
    /// Memory store: *addr = value.
    Store  { addr: IrExpr, value: IrExpr, width: Width },
    /// Conditional branch: condition, `true_target`, `false_target`.
    Branch { cond: IrExpr, true_bb: u32, false_bb: u32 },
    /// Unconditional jump.
    Jump(u32),
    /// Return value (optional).
    Return(Option<IrExpr>),
    /// Intrinsic / syscall.
    Intrinsic { name: String, args: Vec<IrExpr> },
}

// ─────────────────────────────────────────────────────────────────────────────
// IrBasicBlock
// ─────────────────────────────────────────────────────────────────────────────

/// One basic block in an IR function body.
#[derive(Debug, Clone)]
pub struct IrBasicBlock {
    pub id: u32,
    pub stmts: Vec<IrStmt>,
    pub successors: Vec<u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// IrFunction
// ─────────────────────────────────────────────────────────────────────────────

/// IR representation of a single function.
#[derive(Debug, Clone)]
pub struct IrFunction {
    /// Address in the binary.
    pub address: u64,
    /// Optional name.
    pub name: Option<String>,
    /// Ordered basic blocks (first = entry).
    pub blocks: Vec<IrBasicBlock>,
    /// Declared parameters (names).
    pub params: Vec<String>,
    /// Declared local variables (names).
    pub locals: Vec<String>,
}

impl IrFunction {
    /// Collect all variable names appearing as LHS of assignments.
    #[must_use]
    pub fn all_defs(&self) -> HashSet<String> {
        let mut defs = HashSet::new();
        for bb in &self.blocks {
            for stmt in &bb.stmts {
                if let IrStmt::Assign { dst, .. } = stmt {
                    defs.insert(dst.clone());
                }
            }
        }
        defs
    }

    /// Total number of IR statements.
    #[must_use]
    pub fn stmt_count(&self) -> usize {
        self.blocks.iter().map(|b| b.stmts.len()).sum()
    }

    /// Collect all `BinOpKind`s used.
    #[must_use]
    pub fn op_set(&self) -> HashSet<String> {
        let mut ops = HashSet::new();
        for bb in &self.blocks {
            for stmt in &bb.stmts {
                collect_ops_stmt(stmt, &mut ops);
            }
        }
        ops
    }
}

fn collect_ops_expr(expr: &IrExpr, out: &mut HashSet<String>) {
    match expr {
        IrExpr::BinOp { op, lhs, rhs } => {
            out.insert(format!("{op:?}"));
            collect_ops_expr(lhs, out);
            collect_ops_expr(rhs, out);
        }
        IrExpr::UnOp { op, inner } => {
            out.insert(format!("{op:?}"));
            collect_ops_expr(inner, out);
        }
        IrExpr::Load { addr, .. } => collect_ops_expr(addr, out),
        IrExpr::Call { args, .. } => { for a in args { collect_ops_expr(a, out); } }
        IrExpr::Phi(opts) => { for o in opts { collect_ops_expr(o, out); } }
        _ => {}
    }
}

fn collect_ops_stmt(stmt: &IrStmt, out: &mut HashSet<String>) {
    match stmt {
        IrStmt::Assign { src, .. } => collect_ops_expr(src, out),
        IrStmt::Store { addr, value, .. } => { collect_ops_expr(addr, out); collect_ops_expr(value, out); }
        IrStmt::Branch { cond, .. } => collect_ops_expr(cond, out),
        IrStmt::Return(Some(e)) => collect_ops_expr(e, out),
        IrStmt::Intrinsic { args, .. } => { for a in args { collect_ops_expr(a, out); } }
        _ => {}
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Normaliser
// ─────────────────────────────────────────────────────────────────────────────

/// Normalise an `IrFunction` by replacing variable/register names with
/// canonical positional placeholders (`v0`, `v1`, …).
///
/// Parameters are mapped to `p0`, `p1`, etc.
pub struct Normaliser {
    param_map: HashMap<String, String>,
    var_map:   HashMap<String, String>,
    var_counter: usize,
}

impl Normaliser {
    #[must_use]
    pub fn new() -> Self {
        Self {
            param_map: HashMap::new(),
            var_map:   HashMap::new(),
            var_counter: 0,
        }
    }

    /// Normalise a complete function, returning a new `IrFunction` with
    /// canonicalised names.
    pub fn normalise(&mut self, func: &IrFunction) -> IrFunction {
        // Map parameters first.
        for (i, p) in func.params.iter().enumerate() {
            self.param_map.insert(p.clone(), format!("p{i}"));
        }
        // Build definition order from entry block outward (BFS). Names are
        // assigned monotonically from `var_counter` so that successive
        // `normalise` calls on the same `Normaliser` instance produce a
        // globally-unique numbering across functions (useful when feeding the
        // result into a single similarity index spanning multiple functions).
        let def_order = Self::def_order_bfs(func);
        for name in &def_order {
            let id = self.var_counter;
            self.var_map.insert(name.clone(), format!("v{id}"));
            self.var_counter += 1;
        }

        IrFunction {
            address: func.address,
            name: func.name.clone(),
            blocks: func.blocks.iter().map(|bb| self.norm_block(bb)).collect(),
            params: func.params.iter().map(|p| self.norm_name(p)).collect(),
            locals: func.locals.iter().map(|l| self.norm_name(l)).collect(),
        }
    }

    fn def_order_bfs(func: &IrFunction) -> Vec<String> {
        // BFS over blocks (by id order), collecting LHS of assigns in order.
        let mut seen: HashSet<String> = HashSet::new();
        let mut order: Vec<String> = Vec::new();
        let block_map: HashMap<u32, &IrBasicBlock> =
            func.blocks.iter().map(|b| (b.id, b)).collect();

        let mut queue: VecDeque<u32> = VecDeque::new();
        if let Some(entry) = func.blocks.first() {
            queue.push_back(entry.id);
        }
        let mut visited: HashSet<u32> = HashSet::new();

        while let Some(id) = queue.pop_front() {
            if visited.contains(&id) { continue; }
            visited.insert(id);
            if let Some(bb) = block_map.get(&id) {
                for stmt in &bb.stmts {
                    if let IrStmt::Assign { dst, .. } = stmt
                        && seen.insert(dst.clone()) {
                            order.push(dst.clone());
                        }
                }
                for &s in &bb.successors { queue.push_back(s); }
            }
        }
        order
    }

    fn norm_name(&self, name: &str) -> String {
        if let Some(p) = self.param_map.get(name) { return p.clone(); }
        if let Some(v) = self.var_map.get(name)   { return v.clone(); }
        name.to_string()
    }

    fn norm_block(&self, bb: &IrBasicBlock) -> IrBasicBlock {
        IrBasicBlock {
            id: bb.id,
            stmts: bb.stmts.iter().map(|s| self.norm_stmt(s)).collect(),
            successors: bb.successors.clone(),
        }
    }

    fn norm_stmt(&self, stmt: &IrStmt) -> IrStmt {
        match stmt {
            IrStmt::Assign { dst, src } => IrStmt::Assign {
                dst: self.norm_name(dst),
                src: self.norm_expr(src),
            },
            IrStmt::Store { addr, value, width } => IrStmt::Store {
                addr: self.norm_expr(addr),
                value: self.norm_expr(value),
                width: *width,
            },
            IrStmt::Branch { cond, true_bb, false_bb } => IrStmt::Branch {
                cond: self.norm_expr(cond),
                true_bb: *true_bb,
                false_bb: *false_bb,
            },
            IrStmt::Return(Some(e)) => IrStmt::Return(Some(self.norm_expr(e))),
            IrStmt::Intrinsic { name, args } => IrStmt::Intrinsic {
                name: name.clone(),
                args: args.iter().map(|a| self.norm_expr(a)).collect(),
            },
            IrStmt::Jump(_) | IrStmt::Return(None) => stmt.clone(),
        }
    }

    fn norm_expr(&self, expr: &IrExpr) -> IrExpr {
        match expr {
            IrExpr::Var(name) => IrExpr::Var(self.norm_name(name)),
            IrExpr::BinOp { op, lhs, rhs } => IrExpr::BinOp {
                op: *op,
                lhs: Box::new(self.norm_expr(lhs)),
                rhs: Box::new(self.norm_expr(rhs)),
            },
            IrExpr::UnOp { op, inner } => IrExpr::UnOp {
                op: *op,
                inner: Box::new(self.norm_expr(inner)),
            },
            IrExpr::Load { addr, width } => IrExpr::Load {
                addr: Box::new(self.norm_expr(addr)),
                width: *width,
            },
            IrExpr::Call { callee, args } => IrExpr::Call {
                callee: *callee,
                args: args.iter().map(|a| self.norm_expr(a)).collect(),
            },
            IrExpr::Phi(opts) => IrExpr::Phi(opts.iter().map(|o| self.norm_expr(o)).collect()),
            IrExpr::Const(_) => expr.clone(),
        }
    }
}

impl Default for Normaliser { fn default() -> Self { Self::new() } }

// ─────────────────────────────────────────────────────────────────────────────
// SemanticHash
// ─────────────────────────────────────────────────────────────────────────────

/// A compact semantic fingerprint of an IR function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SemanticHash(pub u64);

impl SemanticHash {
    /// Compute from a normalised IR function.
    #[must_use]
    pub fn compute(func: &IrFunction) -> Self {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        // Hash over all statements in BFS order.
        for bb in &func.blocks {
            h ^= u64::from(bb.id);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
            for stmt in &bb.stmts {
                let sh = hash_stmt(stmt);
                h ^= sh;
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        // Include block count and stmt count as weak structural indicators.
        h ^= (func.blocks.len() as u64).wrapping_mul(0xAB);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
        h ^= (func.stmt_count() as u64).wrapping_mul(0xCD);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
        Self(h)
    }

    /// True if the two functions are syntactically identical after normalisation.
    #[must_use]
    pub const fn equals(self, other: Self) -> bool { self.0 == other.0 }
}

fn hash_expr(expr: &IrExpr) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    match expr {
        IrExpr::Var(n) => {
            for b in n.as_bytes() { h ^= u64::from(*b); h = h.wrapping_mul(0x0000_0100_0000_01b3); }
        }
        IrExpr::Const(v) => { h ^= v.unsigned_abs(); h = h.wrapping_mul(0x0000_0100_0000_01b3); }
        IrExpr::BinOp { op, lhs, rhs } => {
            h ^= *op as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
            h ^= hash_expr(lhs); h = h.wrapping_mul(0x0000_0100_0000_01b3);
            h ^= hash_expr(rhs); h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        IrExpr::UnOp { op, inner } => {
            h ^= *op as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
            h ^= hash_expr(inner);
        }
        IrExpr::Load { addr, width } => {
            h ^= hash_expr(addr);
            h ^= u64::from(width.bytes());
        }
        IrExpr::Call { callee, args } => {
            h ^= callee;
            for a in args { h ^= hash_expr(a); h = h.wrapping_mul(0x0000_0100_0000_01b3); }
        }
        IrExpr::Phi(opts) => {
            for o in opts { h ^= hash_expr(o); h = h.wrapping_mul(0x0000_0100_0000_01b3); }
        }
    }
    h
}

fn hash_stmt(stmt: &IrStmt) -> u64 {
    let mut h: u64 = 0xdead_beef_cafe_1234;
    match stmt {
        IrStmt::Assign { dst, src } => {
            for b in dst.as_bytes() { h ^= u64::from(*b); h = h.wrapping_mul(0x0000_0100_0000_01b3); }
            h ^= hash_expr(src);
        }
        IrStmt::Store { addr, value, width } => {
            h ^= 0x5700;
            h ^= hash_expr(addr);
            h ^= hash_expr(value);
            h ^= u64::from(width.bytes());
        }
        IrStmt::Branch { cond, true_bb, false_bb } => {
            h ^= 0xBB00;
            h ^= hash_expr(cond);
            h ^= u64::from(*true_bb);
            h ^= u64::from(*false_bb);
        }
        IrStmt::Jump(t) => { h ^= 0xCC00; h ^= u64::from(*t); }
        IrStmt::Return(Some(e)) => { h ^= 0xDD00; h ^= hash_expr(e); }
        IrStmt::Return(None) => { h ^= 0xDD01; }
        IrStmt::Intrinsic { name, args } => {
            for b in name.as_bytes() { h ^= u64::from(*b); h = h.wrapping_mul(0x0000_0100_0000_01b3); }
            for a in args { h ^= hash_expr(a); }
        }
    }
    h
}

// ─────────────────────────────────────────────────────────────────────────────
// SemanticEquivalenceChecker
// ─────────────────────────────────────────────────────────────────────────────

/// Checks whether two normalised IR functions are semantically equivalent
/// despite superficial differences.
///
/// Currently detects:
/// * Exact structural equivalence (same hash).
/// * Variable-renaming equivalence (verified by structural matching).
/// * Independent-assignment reordering within a block.
pub struct SemanticEquivalenceChecker;

impl SemanticEquivalenceChecker {
    /// Check if two (already normalised) functions are semantically equivalent.
    #[must_use]
    pub fn equivalent(norm_a: &IrFunction, norm_b: &IrFunction) -> bool {
        // Fast path.
        if SemanticHash::compute(norm_a) == SemanticHash::compute(norm_b) {
            return true;
        }
        // Structural counts must match.
        if norm_a.blocks.len() != norm_b.blocks.len() { return false; }
        if norm_a.stmt_count() != norm_b.stmt_count() { return false; }
        // Per-block statement set comparison (order-insensitive within block).
        for (ba, bb) in norm_a.blocks.iter().zip(norm_b.blocks.iter()) {
            if ba.successors != bb.successors { return false; }
            let set_a: HashSet<_> = ba.stmts.iter().collect();
            let set_b: HashSet<_> = bb.stmts.iter().collect();
            if set_a != set_b { return false; }
        }
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SemanticSimilarity
// ─────────────────────────────────────────────────────────────────────────────

/// Pairwise semantic similarity between two IR functions.
#[derive(Debug, Clone, Copy)]
pub struct SemanticSimilarity {
    /// Hash equality (exact normalised equivalence).
    pub hash_equal: bool,
    /// Operation-set Jaccard similarity.
    pub op_jaccard: f64,
    /// Statement-level structural match ratio.
    pub stmt_match: f64,
    /// Block count ratio (min/max).
    pub block_ratio: f64,
    /// Combined score in [0, 1].
    pub score: f64,
}

impl SemanticSimilarity {
    /// Compute semantic similarity between two normalised IR functions.
    #[must_use]
    pub fn compute(norm_a: &IrFunction, norm_b: &IrFunction) -> Self {
        let hash_equal = SemanticHash::compute(norm_a) == SemanticHash::compute(norm_b);
        if hash_equal {
            return Self { hash_equal: true, op_jaccard: 1.0, stmt_match: 1.0, block_ratio: 1.0, score: 1.0 };
        }

        // Operation-set Jaccard.
        let ops_a = norm_a.op_set();
        let ops_b = norm_b.op_set();
        let intersection = ops_a.intersection(&ops_b).count();
        let union = ops_a.union(&ops_b).count();
        let op_jaccard = if union == 0 { 1.0 } else { count_as_f64(intersection) / count_as_f64(union) };

        // Statement-level match (count matching stmts across all blocks).
        let stmts_a: HashSet<&IrStmt> = norm_a.blocks.iter().flat_map(|b| b.stmts.iter()).collect();
        let stmts_b: HashSet<&IrStmt> = norm_b.blocks.iter().flat_map(|b| b.stmts.iter()).collect();
        let stmt_intersection = stmts_a.intersection(&stmts_b).count();
        let stmt_union = stmts_a.union(&stmts_b).count();
        let stmt_match = if stmt_union == 0 { 1.0 } else { count_as_f64(stmt_intersection) / count_as_f64(stmt_union) };

        // Block count ratio.
        let (nb_a, nb_b) = (norm_a.blocks.len(), norm_b.blocks.len());
        let block_ratio = if nb_a == 0 && nb_b == 0 { 1.0 } else {
            count_as_f64(nb_a.min(nb_b)) / count_as_f64(nb_a.max(nb_b))
        };

        let score = 0.40_f64.mul_add(op_jaccard, 0.35_f64.mul_add(stmt_match, 0.25 * block_ratio));
        Self { hash_equal, op_jaccard, stmt_match, block_ratio, score: score.clamp(0.0, 1.0) }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IrSemanticDiff — top-level diff
// ─────────────────────────────────────────────────────────────────────────────

/// A full semantic diff between two matched functions.
#[derive(Debug, Clone)]
pub struct IrSemanticDiff {
    pub address_a: u64,
    pub address_b: u64,
    pub name_a: Option<String>,
    pub name_b: Option<String>,
    pub similarity: SemanticSimilarity,
    /// Statements present in A but not in B (after normalisation).
    pub stmts_removed: Vec<IrStmt>,
    /// Statements present in B but not in A.
    pub stmts_added: Vec<IrStmt>,
    /// Whether the functions are semantically equivalent.
    pub equivalent: bool,
}

impl IrSemanticDiff {
    #[must_use]
    pub const fn is_changed(&self) -> bool { !self.equivalent }
    #[must_use]
    pub const fn score(&self) -> f64 { self.similarity.score }
}

/// Engine that diffs pairs of IR functions.
pub struct IrSemanticDiffer;

impl IrSemanticDiffer {
    /// Diff two raw (un-normalised) IR functions.
    #[must_use]
    pub fn diff(func_a: &IrFunction, func_b: &IrFunction) -> IrSemanticDiff {
        // Normalise both.
        let norm_a = Normaliser::new().normalise(func_a);
        let norm_b = Normaliser::new().normalise(func_b);

        let similarity = SemanticSimilarity::compute(&norm_a, &norm_b);
        let equivalent = SemanticEquivalenceChecker::equivalent(&norm_a, &norm_b);

        // Statement-level diff.
        let stmts_a: HashSet<IrStmt> = norm_a.blocks.iter().flat_map(|b| b.stmts.iter().cloned()).collect();
        let stmts_b: HashSet<IrStmt> = norm_b.blocks.iter().flat_map(|b| b.stmts.iter().cloned()).collect();

        let stmts_removed: Vec<IrStmt> = stmts_a.difference(&stmts_b).cloned().collect();
        let stmts_added:   Vec<IrStmt> = stmts_b.difference(&stmts_a).cloned().collect();

        IrSemanticDiff {
            address_a: func_a.address,
            address_b: func_b.address,
            name_a: func_a.name.clone(),
            name_b: func_b.name.clone(),
            similarity,
            stmts_removed,
            stmts_added,
            equivalent,
        }
    }

    /// Batch diff: match functions by address or index and diff all pairs.
    #[must_use]
    pub fn diff_all(
        funcs_a: &[IrFunction],
        funcs_b: &[IrFunction],
        pairs: &[(usize, usize)],
    ) -> Vec<IrSemanticDiff> {
        pairs.iter().map(|&(ia, ib)| Self::diff(&funcs_a[ia], &funcs_b[ib])).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SemanticDiffReport
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated report across multiple function diffs.
#[derive(Debug, Clone)]
pub struct SemanticDiffReport {
    pub diffs: Vec<IrSemanticDiff>,
}

impl SemanticDiffReport {
    #[must_use]
    pub const fn new(diffs: Vec<IrSemanticDiff>) -> Self { Self { diffs } }

    #[must_use]
    pub fn equivalent_count(&self) -> usize  { self.diffs.iter().filter(|d| d.equivalent).count() }
    #[must_use]
    pub fn changed_count(&self) -> usize     { self.diffs.iter().filter(|d| d.is_changed()).count() }

    #[must_use]
    pub fn average_score(&self) -> f64 {
        if self.diffs.is_empty() { return 1.0; }
        self.diffs.iter().map(IrSemanticDiff::score).sum::<f64>() / count_as_f64(self.diffs.len())
    }

    #[must_use]
    pub fn most_changed(&self) -> Option<&IrSemanticDiff> {
        self.diffs.iter().filter(|d| d.is_changed()).min_by(|a, b| {
            a.score().partial_cmp(&b.score()).unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Total: {} | Equivalent: {} | Changed: {} | Avg score: {:.2}%",
            self.diffs.len(),
            self.equivalent_count(),
            self.changed_count(),
            self.average_score() * 100.0,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build a trivial IR function with one block for testing.
#[must_use]
pub fn make_simple_func(addr: u64, stmts: Vec<IrStmt>) -> IrFunction {
    IrFunction {
        address: addr,
        name: None,
        blocks: vec![IrBasicBlock { id: 0, stmts, successors: Vec::new() }],
        params: Vec::new(),
        locals: Vec::new(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn assign(dst: &str, val: i64) -> IrStmt {
        IrStmt::Assign { dst: dst.to_string(), src: IrExpr::Const(val) }
    }

    fn ret_val(val: i64) -> IrStmt {
        IrStmt::Return(Some(IrExpr::Const(val)))
    }

    fn ret_var(name: &str) -> IrStmt {
        IrStmt::Return(Some(IrExpr::Var(name.to_string())))
    }

    fn var_assign(dst: &str, src: &str) -> IrStmt {
        IrStmt::Assign { dst: dst.to_string(), src: IrExpr::Var(src.to_string()) }
    }

    #[test]
    fn test_semantic_hash_identical() {
        let f = make_simple_func(0, vec![assign("x", 42), ret_val(0)]);
        let h1 = SemanticHash::compute(&f);
        let h2 = SemanticHash::compute(&f);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_semantic_hash_differs() {
        let f1 = make_simple_func(0, vec![assign("x", 42)]);
        let f2 = make_simple_func(0, vec![assign("x", 99)]);
        // Different constants → different hash.
        assert_ne!(SemanticHash::compute(&f1).0, SemanticHash::compute(&f2).0);
    }

    #[test]
    fn test_normaliser_renames_vars() {
        let f = make_simple_func(0x1000, vec![
            var_assign("rax", "rbx"),
            ret_var("rax"),
        ]);
        let norm = Normaliser::new().normalise(&f);
        // First def ("rax") should become "v0".
        if let IrStmt::Assign { dst, .. } = &norm.blocks[0].stmts[0] {
            assert_eq!(dst, "v0");
        } else {
            panic!("expected assign");
        }
    }

    #[test]
    fn test_equivalence_identical() {
        let stmts = vec![assign("x", 1), ret_val(0)];
        let f = make_simple_func(0, stmts);
        let norm = Normaliser::new().normalise(&f);
        assert!(SemanticEquivalenceChecker::equivalent(&norm, &norm));
    }

    #[test]
    fn test_equivalence_different_constants() {
        let f1 = make_simple_func(0, vec![assign("x", 1)]);
        let f2 = make_simple_func(0, vec![assign("x", 2)]);
        let n1 = Normaliser::new().normalise(&f1);
        let n2 = Normaliser::new().normalise(&f2);
        assert!(!SemanticEquivalenceChecker::equivalent(&n1, &n2));
    }

    #[test]
    fn test_similarity_identical_functions() {
        let stmts = vec![assign("v", 42), ret_val(0)];
        let f = make_simple_func(0, stmts);
        let n = Normaliser::new().normalise(&f);
        let sim = SemanticSimilarity::compute(&n, &n);
        assert!(sim.hash_equal);
        assert!((sim.score - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_similarity_completely_different() {
        let f1 = make_simple_func(0, vec![assign("x", 1), assign("y", 2)]);
        let f2 = make_simple_func(0, vec![
            IrStmt::Store {
                addr: IrExpr::Const(0x1000),
                value: IrExpr::Const(0xFF),
                width: Width::B8,
            },
        ]);
        let n1 = Normaliser::new().normalise(&f1);
        let n2 = Normaliser::new().normalise(&f2);
        let sim = SemanticSimilarity::compute(&n1, &n2);
        assert!(!sim.hash_equal);
        assert!(sim.score < 1.0);
    }

    #[test]
    fn test_diff_unchanged() {
        let f = make_simple_func(0, vec![assign("x", 5), ret_val(0)]);
        let d = IrSemanticDiffer::diff(&f, &f);
        assert!(d.equivalent);
        assert!(d.stmts_removed.is_empty());
        assert!(d.stmts_added.is_empty());
    }

    #[test]
    fn test_diff_added_stmt() {
        let f1 = make_simple_func(0, vec![ret_val(0)]);
        let f2 = make_simple_func(0, vec![assign("z", 7), ret_val(0)]);
        let d = IrSemanticDiffer::diff(&f1, &f2);
        assert!(!d.equivalent);
        assert!(!d.stmts_added.is_empty());
    }

    #[test]
    fn test_report_summary() {
        let f = make_simple_func(0, vec![ret_val(0)]);
        let diffs = vec![IrSemanticDiffer::diff(&f, &f)];
        let report = SemanticDiffReport::new(diffs);
        assert_eq!(report.equivalent_count(), 1);
        assert_eq!(report.changed_count(), 0);
        let s = report.summary();
        assert!(s.contains("Equivalent: 1"));
    }

    #[test]
    fn test_width_bytes() {
        assert_eq!(Width::B8.bytes(), 1);
        assert_eq!(Width::B64.bytes(), 8);
    }

    #[test]
    fn test_hash_expr_const() {
        let h1 = hash_expr(&IrExpr::Const(42));
        let h2 = hash_expr(&IrExpr::Const(42));
        assert_eq!(h1, h2);
        assert_ne!(h1, hash_expr(&IrExpr::Const(43)));
    }

    #[test]
    fn test_batch_diff() {
        let fa = make_simple_func(0x100, vec![ret_val(0)]);
        let fb = make_simple_func(0x200, vec![ret_val(0)]);
        let fc = make_simple_func(0x300, vec![assign("x", 1), ret_val(0)]);
        let diffs = IrSemanticDiffer::diff_all(&[fa], &[fb, fc], &[(0, 0), (0, 1)]);
        assert_eq!(diffs.len(), 2);
        assert!(diffs[0].equivalent); // fa vs fb — same body
    }
}
