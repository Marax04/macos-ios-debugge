//! `ir_to_hlil_bridge.rs` — MLIL → HLIL elevation bridge.
//!
//! Handles edge cases in IR-to-HLIL lifting:
//! - Phi removal / SSA deconstruction
//! - Variable coalescing (merging SSA versions of the same variable)
//! - Expression hoisting (moving invariant expressions out of loops)
//! - Side-effect ordering preservation

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// MLIL expression model (simplified)
// ─────────────────────────────────────────────────────────────────────────────

/// Identifier for an SSA variable: (`base_name`, version).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SsaVar {
    pub name: String,
    pub version: u32,
}

impl SsaVar {
    pub fn new(name: impl Into<String>, version: u32) -> Self {
        Self { name: name.into(), version }
    }

    /// The non-SSA name (drops the version suffix).
    #[must_use] 
    pub fn base_name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SsaVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}", self.name, self.version)
    }
}

/// A simplified MLIL/SSA expression.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MlilExpr {
    /// Constant integer.
    Const(u64),
    /// SSA variable reference.
    Var(SsaVar),
    /// Binary operation.
    BinOp {
        op: BinOp,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    /// Unary operation.
    UnOp {
        op: UnOp,
        operand: Box<Self>,
    },
    /// Memory load at address.
    Load {
        addr: Box<Self>,
        size: u8,
    },
    /// Phi function: join of values from predecessor blocks.
    Phi {
        dst: SsaVar,
        sources: Vec<(usize, SsaVar)>, // (pred_block_id, source_var)
    },
    /// Function call.
    Call {
        target: Box<Self>,
        args: Vec<Self>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BinOp {
    Add, Sub, Mul, Div, Mod,
    And, Or, Xor, Shl, Shr, Sar,
    Eq, Ne, Lt, Le, Gt, Ge,
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Add => write!(f, "+"), Self::Sub => write!(f, "-"),
            Self::Mul => write!(f, "*"), Self::Div => write!(f, "/"),
            Self::Mod => write!(f, "%"), Self::And => write!(f, "&"),
            Self::Or => write!(f, "|"), Self::Xor => write!(f, "^"),
            Self::Shl => write!(f, "<<"), Self::Shr => write!(f, ">>"),
            Self::Sar => write!(f, ">>s"), Self::Eq => write!(f, "=="),
            Self::Ne => write!(f, "!="), Self::Lt => write!(f, "<"),
            Self::Le => write!(f, "<="), Self::Gt => write!(f, ">"),
            Self::Ge => write!(f, ">="),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnOp {
    Neg, Not, ZeroExtend, SignExtend,
}

/// A simplified MLIL/SSA statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MlilStmt {
    /// Assign: dst = expr.
    Assign { dst: SsaVar, expr: MlilExpr },
    /// Store: mem[addr] = val.
    Store { addr: MlilExpr, val: MlilExpr, size: u8 },
    /// Phi: dst = phi(sources).
    Phi { dst: SsaVar, sources: Vec<(usize, SsaVar)> },
    /// Call (for side effects).
    Call { target: MlilExpr, args: Vec<MlilExpr> },
    /// Conditional jump.
    CondJump { cond: MlilExpr, true_block: usize, false_block: usize },
    /// Unconditional jump.
    Jump { target: usize },
    /// Return.
    Return { val: Option<MlilExpr> },
}

/// A basic block in MLIL/SSA form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlilBlock {
    pub id: usize,
    pub stmts: Vec<MlilStmt>,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
}

/// A complete MLIL/SSA function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlilFunction {
    pub blocks: Vec<MlilBlock>,
    pub entry: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// HLIL expression model (high-level)
// ─────────────────────────────────────────────────────────────────────────────

/// A HLIL variable (non-SSA).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HlilVar {
    pub name: String,
    pub type_hint: String,
}

impl HlilVar {
    pub fn new(name: impl Into<String>, type_hint: impl Into<String>) -> Self {
        Self { name: name.into(), type_hint: type_hint.into() }
    }
}

impl fmt::Display for HlilVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// A HLIL expression (higher-level, phi-free).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HlilExpr {
    Const(u64),
    Var(HlilVar),
    BinOp {
        op: BinOp,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    UnOp {
        op: UnOp,
        operand: Box<Self>,
    },
    Load {
        addr: Box<Self>,
        size: u8,
    },
    Call {
        target: Box<Self>,
        args: Vec<Self>,
    },
    /// Hoisted invariant expression (tagged for display).
    Hoisted {
        inner: Box<Self>,
        hoist_target: String,
    },
}

impl fmt::Display for HlilExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const(v) => write!(f, "{v:#x}"),
            Self::Var(v) => write!(f, "{}", v.name),
            Self::BinOp { op, lhs, rhs } => write!(f, "({lhs} {op} {rhs})"),
            Self::UnOp { op, operand } => write!(f, "({op:?} {operand})"),
            Self::Load { addr, size } => write!(f, "*(u{} *){addr}", size * 8),
            Self::Call { target, args } => {
                write!(f, "{target}(")?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "{a}")?;
                }
                write!(f, ")")
            }
            Self::Hoisted { inner, hoist_target } => write!(f, "/* hoisted to {hoist_target} */ {inner}"),
        }
    }
}

/// A HLIL statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HlilStmt {
    Assign { dst: HlilVar, expr: HlilExpr },
    Store { addr: HlilExpr, val: HlilExpr, size: u8 },
    Call { target: HlilExpr, args: Vec<HlilExpr> },
    If { cond: HlilExpr, then_block: usize, else_block: usize },
    While { cond: HlilExpr, body: Vec<Self> },
    Return { val: Option<HlilExpr> },
    Goto { target: usize },
    Comment(String),
}

/// A HLIL basic block (phi-free).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HlilBlock {
    pub id: usize,
    pub stmts: Vec<HlilStmt>,
    pub successors: Vec<usize>,
}

/// A complete HLIL function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HlilFunction {
    pub blocks: Vec<HlilBlock>,
    pub entry: usize,
    pub hoisted_vars: Vec<(String, HlilExpr)>,
}

// ─────────────────────────────────────────────────────────────────────────────
// PhiEliminator — SSA deconstruction (phi removal)
// ─────────────────────────────────────────────────────────────────────────────

/// Removes phi functions by inserting parallel copies at predecessor edges.
///
/// Algorithm (standard SSA destruction):
/// 1. For each phi `dst = phi(b1: v1, b2: v2, ...)`, insert a copy
///    `dst_coalesced = vN` at the end of block bN before its terminator.
/// 2. Replace all uses of SSA versions with the coalesced base name.
pub struct PhiEliminator {
    /// Map from SSA var to the coalesced non-SSA name.
    pub coalesce_map: HashMap<SsaVar, String>,
}

impl PhiEliminator {
    #[must_use] 
    pub fn new() -> Self {
        Self { coalesce_map: HashMap::new() }
    }

    /// Compute the coalescing map from all phi statements in `func`.
    pub fn build_coalesce_map(&mut self, func: &MlilFunction) {
        for block in &func.blocks {
            for stmt in &block.stmts {
                if let MlilStmt::Phi { dst, sources } = stmt {
                    let base = dst.name.clone();
                    // Map dst and all sources to the same base name.
                    self.coalesce_map.insert(dst.clone(), base.clone());
                    for (_, src) in sources {
                        self.coalesce_map.entry(src.clone()).or_insert_with(|| base.clone());
                    }
                }
            }
        }
    }

    /// Coalesced name for an SSA variable (falls back to base name if not in map).
    #[must_use] 
    pub fn coalesced_name(&self, var: &SsaVar) -> String {
        self.coalesce_map
            .get(var)
            .cloned()
            .unwrap_or_else(|| var.name.clone())
    }

    /// Eliminate all phi statements from `func`, returning parallel-copy-annotated blocks.
    pub fn eliminate(&mut self, func: &MlilFunction) -> MlilFunction {
        self.build_coalesce_map(func);
        let mut new_blocks: Vec<MlilBlock> = func.blocks.clone();

        // For each phi, insert copies at each predecessor.
        for (block_idx, block) in func.blocks.iter().enumerate() {
            for stmt in &block.stmts {
                if let MlilStmt::Phi { dst, sources } = stmt {
                    let dst_name = self.coalesced_name(dst);
                    for (pred_id, src) in sources {
                        let src_name = self.coalesced_name(src);
                        if dst_name != src_name {
                            // Insert a copy at the end of pred block (before terminator).
                            if let Some(pred_block) = new_blocks.get_mut(*pred_id) {
                                let copy = MlilStmt::Assign {
                                    dst: SsaVar::new(dst_name.clone(), 0),
                                    expr: MlilExpr::Var(SsaVar::new(src_name, src.version)),
                                };
                                // Insert before the last terminator statement.
                                let insert_pos = pred_block.stmts.len().saturating_sub(1);
                                pred_block.stmts.insert(insert_pos, copy);
                            }
                        }
                    }
                }
            }

            // Remove phi statements from the block.
            new_blocks[block_idx]
                .stmts
                .retain(|s| !matches!(s, MlilStmt::Phi { .. }));
        }

        MlilFunction { blocks: new_blocks, entry: func.entry }
    }
}

impl Default for PhiEliminator {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// VariableCoalescer — merge SSA versions
// ─────────────────────────────────────────────────────────────────────────────

/// Merges SSA versions of the same variable into a single HLIL variable.
pub struct VariableCoalescer {
    /// Union-Find parent map: SSA var → canonical representative.
    parent: HashMap<SsaVar, SsaVar>,
}

impl VariableCoalescer {
    #[must_use] 
    pub fn new() -> Self {
        Self { parent: HashMap::new() }
    }

    /// Find the canonical representative of `var` (path-compressing union-find).
    pub fn find(&mut self, var: &SsaVar) -> SsaVar {
        if let Some(parent) = self.parent.get(var).cloned() {
            if &parent == var {
                return var.clone();
            }
            let root = self.find(&parent);
            self.parent.insert(var.clone(), root.clone());
            root
        } else {
            var.clone()
        }
    }

    /// Union two SSA variables into the same equivalence class.
    pub fn union(&mut self, a: &SsaVar, b: &SsaVar) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra != rb {
            // Keep the one with the smaller version as canonical.
            let (canon, other) = if ra.version <= rb.version {
                (ra, rb)
            } else {
                (rb, ra)
            };
            self.parent.insert(other, canon);
        }
    }

    /// Collect coalescing opportunities: variables that are always copies of each other.
    pub fn build_from_assigns(
        &mut self,
        stmts: &[MlilStmt],
    ) {
        for stmt in stmts {
            if let MlilStmt::Assign { dst, expr: MlilExpr::Var(src) } = stmt {
                // If dst := src, they can be coalesced if their live ranges don't conflict.
                // For simplicity, coalesce all direct copies.
                if dst.name == src.name {
                    self.union(dst, src);
                }
            }
        }
    }

    /// Return the canonical HLIL variable name for an SSA var.
    pub fn canonical_name(&mut self, var: &SsaVar) -> String {
        let canon = self.find(var);
        canon.name
    }
}

impl Default for VariableCoalescer {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExpressionHoister — move loop-invariant expressions out of loops
// ─────────────────────────────────────────────────────────────────────────────

fn hlil_is_invariant(expr: &HlilExpr, loop_defs: &HashSet<String>) -> bool {
    match expr {
        HlilExpr::Const(_) => true,
        HlilExpr::Var(v) => !loop_defs.contains(&v.name),
        HlilExpr::BinOp { lhs, rhs, .. } => {
            hlil_is_invariant(lhs, loop_defs) && hlil_is_invariant(rhs, loop_defs)
        }
        HlilExpr::UnOp { operand, .. } => hlil_is_invariant(operand, loop_defs),
        HlilExpr::Load { .. } | HlilExpr::Call { .. } => false,
        HlilExpr::Hoisted { inner, .. } => hlil_is_invariant(inner, loop_defs),
    }
}

/// Identifies and hoists loop-invariant expressions.
pub struct ExpressionHoister {
    /// Expressions that were hoisted: (name, expr).
    pub hoisted: Vec<(String, HlilExpr)>,
    /// Counter for naming hoisted temporaries.
    counter: usize,
}

impl ExpressionHoister {
    #[must_use] 
    pub const fn new() -> Self {
        Self { hoisted: Vec::new(), counter: 0 }
    }

    /// Generate a fresh hoisted-variable name.
    fn fresh_name(&mut self) -> String {
        let name = format!("hoist_{}", self.counter);
        self.counter += 1;
        name
    }

    /// Returns `true` if `expr` is loop-invariant (contains no memory loads
    /// or calls, and only references variables not defined inside the loop).
    #[must_use]
    pub fn is_invariant(&self, expr: &HlilExpr, loop_defs: &HashSet<String>) -> bool {
        hlil_is_invariant(expr, loop_defs)
    }

    /// Collect all variables defined within a loop body (set of block IDs).
    #[must_use]
    pub fn collect_loop_defs(
        blocks: &[HlilBlock],
        loop_block_ids: &HashSet<usize>,
    ) -> HashSet<String> {
        let mut defs = HashSet::new();
        for block in blocks {
            if !loop_block_ids.contains(&block.id) {
                continue;
            }
            for stmt in &block.stmts {
                if let HlilStmt::Assign { dst, .. } = stmt {
                    defs.insert(dst.name.clone());
                }
            }
        }
        defs
    }

    /// Attempt to hoist `expr` if it is invariant with respect to `loop_defs`.
    ///
    /// Returns a hoisted expression referencing a new temporary, and records
    /// the temporary in `self.hoisted`.
    pub fn try_hoist(
        &mut self,
        expr: HlilExpr,
        loop_defs: &HashSet<String>,
        _hoist_target: &str,
    ) -> HlilExpr {
        if self.is_invariant(&expr, loop_defs) {
            let name = self.fresh_name();
            self.hoisted.push((name.clone(), expr));
            HlilExpr::Var(HlilVar::new(name, "auto"))
        } else {
            expr
        }
    }

    /// Apply hoisting to all assignment RHS-es in a set of loop blocks.
    pub fn hoist_in_loop(
        &mut self,
        blocks: &mut [HlilBlock],
        loop_block_ids: &HashSet<usize>,
        hoist_target: &str,
    ) {
        let loop_defs = Self::collect_loop_defs(blocks, loop_block_ids);
        for block in blocks.iter_mut() {
            if !loop_block_ids.contains(&block.id) {
                continue;
            }
            for stmt in &mut block.stmts {
                if let HlilStmt::Assign { expr, .. } = stmt {
                    let old = expr.clone();
                    *expr = self.try_hoist(old, &loop_defs, hoist_target);
                }
            }
        }
    }
}

impl Default for ExpressionHoister {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// SideEffectOrderer — preserve ordering of side-effecting operations
// ─────────────────────────────────────────────────────────────────────────────

/// Ensures that side-effecting operations (calls, stores) are not reordered
/// during expression lifting.
pub struct SideEffectOrderer {
    /// Sequence of side-effect operations in order they must execute.
    pub ordered_effects: Vec<SideEffect>,
}

/// A single side-effecting operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideEffect {
    /// The statement that produces the side effect.
    pub stmt_idx: usize,
    /// Kind of side effect.
    pub kind: SideEffectKind,
    /// Block ID containing the side effect.
    pub block_id: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SideEffectKind {
    MemoryWrite,
    FunctionCall,
    Io,
    Synchronization,
}

impl SideEffectOrderer {
    #[must_use] 
    pub const fn new() -> Self {
        Self { ordered_effects: Vec::new() }
    }

    /// Scan a function's blocks and record all side-effecting statements.
    pub fn analyze(&mut self, func: &HlilFunction) {
        for block in &func.blocks {
            for (idx, stmt) in block.stmts.iter().enumerate() {
                match stmt {
                    HlilStmt::Store { .. } => {
                        self.ordered_effects.push(SideEffect {
                            stmt_idx: idx,
                            kind: SideEffectKind::MemoryWrite,
                            block_id: block.id,
                        });
                    }
                    HlilStmt::Call { .. } => {
                        self.ordered_effects.push(SideEffect {
                            stmt_idx: idx,
                            kind: SideEffectKind::FunctionCall,
                            block_id: block.id,
                        });
                    }
                    _ => {}
                }
            }
        }
    }

    /// Returns `true` if moving the statement at `from_idx` in `block_id`
    /// before `to_idx` in the same block would violate side-effect ordering.
    #[must_use] 
    pub fn would_reorder(&self, block_id: usize, from_idx: usize, to_idx: usize) -> bool {
        if from_idx <= to_idx {
            return false; // moving forward is fine
        }
        // Check if there is any side effect between to_idx and from_idx.
        self.ordered_effects.iter().any(|se| {
            se.block_id == block_id && se.stmt_idx >= to_idx && se.stmt_idx < from_idx
        })
    }

    /// Count of all recorded side effects.
    #[must_use] 
    pub const fn count(&self) -> usize {
        self.ordered_effects.len()
    }
}

impl Default for SideEffectOrderer {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// MlilToHlilBridge — the main translation driver
// ─────────────────────────────────────────────────────────────────────────────

/// SSA-level feature flags (sub-group of [`BridgeConfig`]).
#[derive(Debug, Clone)]
pub struct BridgeFlags {
    /// Whether to eliminate phi functions.
    pub eliminate_phi: bool,
    /// Whether to coalesce SSA variables.
    pub coalesce_vars: bool,
    /// Whether to hoist loop-invariant expressions.
    pub hoist_invariants: bool,
}

impl Default for BridgeFlags {
    fn default() -> Self {
        Self {
            eliminate_phi: true,
            coalesce_vars: true,
            hoist_invariants: true,
        }
    }
}

/// Configuration for the MLIL → HLIL bridge.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// SSA-level feature flags.
    pub flags: BridgeFlags,
    /// Whether to check side-effect ordering.
    pub preserve_side_effect_order: bool,
    /// Maximum phi-elimination iterations before giving up.
    pub max_phi_iter: usize,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            flags: BridgeFlags::default(),
            preserve_side_effect_order: true,
            max_phi_iter: 100,
        }
    }
}

/// Translates an MLIL/SSA function to HLIL form.
pub struct MlilToHlilBridge {
    config: BridgeConfig,
    phi_eliminator: PhiEliminator,
    coalescer: VariableCoalescer,
    hoister: ExpressionHoister,
    orderer: SideEffectOrderer,
}

impl MlilToHlilBridge {
    #[must_use] 
    pub fn new(config: BridgeConfig) -> Self {
        Self {
            config,
            phi_eliminator: PhiEliminator::new(),
            coalescer: VariableCoalescer::new(),
            hoister: ExpressionHoister::new(),
            orderer: SideEffectOrderer::new(),
        }
    }

    #[must_use] 
    pub fn with_default_config() -> Self {
        Self::new(BridgeConfig::default())
    }

    /// Translate `mlil_func` to HLIL.
    pub fn translate(&mut self, mlil_func: &MlilFunction) -> HlilFunction {
        // Step 1: phi elimination.
        let phi_free = if self.config.flags.eliminate_phi {
            self.phi_eliminator.eliminate(mlil_func)
        } else {
            mlil_func.clone()
        };

        // Step 2: variable coalescing.
        if self.config.flags.coalesce_vars {
            // Collect all assign statements for coalescing analysis.
            let all_stmts: Vec<MlilStmt> = phi_free
                .blocks
                .iter()
                .flat_map(|b| b.stmts.clone())
                .collect();
            self.coalescer.build_from_assigns(&all_stmts);
        }

        // Step 3: translate MLIL blocks to HLIL blocks.
        let mut hlil_blocks: Vec<HlilBlock> = phi_free
            .blocks
            .iter()
            .map(|b| self.translate_block(b))
            .collect();

        // Step 4: identify loop block sets (simple heuristic: back-edge targets).
        let loop_sets = Self::find_loop_block_sets(&phi_free);

        // Step 5: hoist loop-invariant expressions.
        if self.config.flags.hoist_invariants {
            for loop_set in &loop_sets {
                let header_id = loop_set.iter().min().copied().unwrap_or(0);
                let hoist_target = format!("block_{header_id}_preheader");
                self.hoister.hoist_in_loop(&mut hlil_blocks, loop_set, &hoist_target);
            }
        }

        // Step 6: analyze side-effect ordering.
        let hlil_func = HlilFunction {
            blocks: hlil_blocks,
            entry: phi_free.entry,
            hoisted_vars: self.hoister.hoisted.clone(),
        };
        if self.config.preserve_side_effect_order {
            let mut orderer = SideEffectOrderer::new();
            orderer.analyze(&hlil_func);
            self.orderer = orderer;
        }

        hlil_func
    }

    /// Translate a single MLIL block to a HLIL block.
    fn translate_block(&mut self, block: &MlilBlock) -> HlilBlock {
        let stmts: Vec<HlilStmt> = block
            .stmts
            .iter()
            .map(|s| self.translate_stmt(s))
            .collect();
        HlilBlock {
            id: block.id,
            stmts,
            successors: block.successors.clone(),
        }
    }

    /// Translate a single MLIL statement to a HLIL statement.
    fn translate_stmt(&mut self, stmt: &MlilStmt) -> HlilStmt {
        match stmt {
            MlilStmt::Phi { .. } => {
                // Phi should have been eliminated; emit a comment if not.
                HlilStmt::Comment(
                    "/* PHI not eliminated */".to_string(),
                )
            }
            MlilStmt::Assign { dst, expr } => {
                let hlil_expr = self.translate_expr(expr);
                let coalesced = self.coalescer.canonical_name(dst);
                HlilStmt::Assign {
                    dst: HlilVar::new(coalesced, "auto"),
                    expr: hlil_expr,
                }
            }
            MlilStmt::Store { addr, val, size } => HlilStmt::Store {
                addr: self.translate_expr(addr),
                val: self.translate_expr(val),
                size: *size,
            },
            MlilStmt::Call { target, args } => HlilStmt::Call {
                target: self.translate_expr(target),
                args: args.iter().map(|a| self.translate_expr(a)).collect(),
            },
            MlilStmt::CondJump { cond, true_block, false_block } => HlilStmt::If {
                cond: self.translate_expr(cond),
                then_block: *true_block,
                else_block: *false_block,
            },
            MlilStmt::Jump { target } => HlilStmt::Goto { target: *target },
            MlilStmt::Return { val } => HlilStmt::Return {
                val: val.as_ref().map(|v| self.translate_expr(v)),
            },
        }
    }

    /// Translate a MLIL expression to a HLIL expression.
    fn translate_expr(&mut self, expr: &MlilExpr) -> HlilExpr {
        match expr {
            MlilExpr::Const(v) => HlilExpr::Const(*v),
            MlilExpr::Var(ssa) => {
                let name = self.coalescer.canonical_name(ssa);
                HlilExpr::Var(HlilVar::new(name, "auto"))
            }
            MlilExpr::BinOp { op, lhs, rhs } => HlilExpr::BinOp {
                op: *op,
                lhs: Box::new(self.translate_expr(lhs)),
                rhs: Box::new(self.translate_expr(rhs)),
            },
            MlilExpr::UnOp { op, operand } => HlilExpr::UnOp {
                op: *op,
                operand: Box::new(self.translate_expr(operand)),
            },
            MlilExpr::Load { addr, size } => HlilExpr::Load {
                addr: Box::new(self.translate_expr(addr)),
                size: *size,
            },
            MlilExpr::Phi { .. } => {
                // Should not reach here after phi elimination.
                HlilExpr::Const(0)
            }
            MlilExpr::Call { target, args } => HlilExpr::Call {
                target: Box::new(self.translate_expr(target)),
                args: args.iter().map(|a| self.translate_expr(a)).collect(),
            },
        }
    }

    /// Identify sets of block IDs that belong to loops using a simple
    /// back-edge heuristic (any edge to a block with lower ID).
    fn find_loop_block_sets(func: &MlilFunction) -> Vec<HashSet<usize>> {
        fn dfs(
            node: usize,
            blocks: &[MlilBlock],
            visited: &mut HashSet<usize>,
            on_stack: &mut HashSet<usize>,
            stack: &mut Vec<usize>,
            loops: &mut Vec<HashSet<usize>>,
        ) {
            if visited.contains(&node) {
                return;
            }
            visited.insert(node);
            on_stack.insert(node);
            stack.push(node);

            if let Some(block) = blocks.get(node) {
                for &succ in &block.successors {
                    if on_stack.contains(&succ) {
                        // Found a back edge: collect loop body.
                        let header = succ;
                        let loop_body: HashSet<usize> = stack
                            .iter()
                            .rev()
                            .take_while(|&&b| b != header)
                            .chain(std::iter::once(&header))
                            .copied()
                            .collect();
                        loops.push(loop_body);
                    } else if !visited.contains(&succ) {
                        dfs(succ, blocks, visited, on_stack, stack, loops);
                    }
                }
            }

            stack.pop();
            on_stack.remove(&node);
        }

        let mut loops: Vec<HashSet<usize>> = Vec::new();
        let mut visited = HashSet::new();
        let mut stack = Vec::new();
        let mut on_stack = HashSet::new();

        dfs(
            func.entry,
            &func.blocks,
            &mut visited,
            &mut on_stack,
            &mut stack,
            &mut loops,
        );

        loops
    }

    /// Return statistics about the translation.
    #[must_use] 
    pub fn stats(&self) -> BridgeStats {
        BridgeStats {
            phi_vars_coalesced: self.phi_eliminator.coalesce_map.len(),
            ssa_vars_merged: self.coalescer.parent.len(),
            exprs_hoisted: self.hoister.hoisted.len(),
            side_effects_ordered: self.orderer.count(),
        }
    }
}

/// Statistics produced by the bridge translation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeStats {
    pub phi_vars_coalesced: usize,
    pub ssa_vars_merged: usize,
    pub exprs_hoisted: usize,
    pub side_effects_ordered: usize,
}

impl fmt::Display for BridgeStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "phi_coalesced={} ssa_merged={} hoisted={} side_effects={}",
            self.phi_vars_coalesced,
            self.ssa_vars_merged,
            self.exprs_hoisted,
            self.side_effects_ordered,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_simple_function() -> MlilFunction {
        // Block 0: x_0 = 1; y_0 = x_0 + 2; return y_0
        let block0 = MlilBlock {
            id: 0,
            stmts: vec![
                MlilStmt::Assign {
                    dst: SsaVar::new("x", 0),
                    expr: MlilExpr::Const(1),
                },
                MlilStmt::Assign {
                    dst: SsaVar::new("y", 0),
                    expr: MlilExpr::BinOp {
                        op: BinOp::Add,
                        lhs: Box::new(MlilExpr::Var(SsaVar::new("x", 0))),
                        rhs: Box::new(MlilExpr::Const(2)),
                    },
                },
                MlilStmt::Return {
                    val: Some(MlilExpr::Var(SsaVar::new("y", 0))),
                },
            ],
            successors: vec![],
            predecessors: vec![],
        };
        MlilFunction { blocks: vec![block0], entry: 0 }
    }

    fn make_phi_function() -> MlilFunction {
        // Block 0: if (cond) goto 1 else goto 2
        // Block 1: x_1 = 10
        // Block 2: x_2 = phi(1: x_1, 0: x_0); return x_2
        let block0 = MlilBlock {
            id: 0,
            stmts: vec![MlilStmt::CondJump { cond: MlilExpr::Const(1), true_block: 1, false_block: 2 }],
            successors: vec![1, 2],
            predecessors: vec![],
        };
        let block1 = MlilBlock {
            id: 1,
            stmts: vec![
                MlilStmt::Assign { dst: SsaVar::new("x", 1), expr: MlilExpr::Const(10) },
                MlilStmt::Jump { target: 2 },
            ],
            successors: vec![2],
            predecessors: vec![0],
        };
        let block2 = MlilBlock {
            id: 2,
            stmts: vec![
                MlilStmt::Phi {
                    dst: SsaVar::new("x", 2),
                    sources: vec![(1, SsaVar::new("x", 1)), (0, SsaVar::new("x", 0))],
                },
                MlilStmt::Return { val: Some(MlilExpr::Var(SsaVar::new("x", 2))) },
            ],
            successors: vec![],
            predecessors: vec![0, 1],
        };
        MlilFunction { blocks: vec![block0, block1, block2], entry: 0 }
    }

    #[test]
    fn phi_eliminator_removes_phis() {
        let func = make_phi_function();
        let mut elim = PhiEliminator::new();
        let result = elim.eliminate(&func);
        for block in &result.blocks {
            for stmt in &block.stmts {
                assert!(!matches!(stmt, MlilStmt::Phi { .. }), "phi not eliminated");
            }
        }
    }

    #[test]
    fn phi_eliminator_coalesce_map() {
        let func = make_phi_function();
        let mut elim = PhiEliminator::new();
        elim.build_coalesce_map(&func);
        // x_0, x_1, x_2 should all coalesce to "x".
        assert_eq!(elim.coalesced_name(&SsaVar::new("x", 2)), "x");
        assert_eq!(elim.coalesced_name(&SsaVar::new("x", 1)), "x");
    }

    #[test]
    fn variable_coalescer_direct_copy() {
        let mut coalescer = VariableCoalescer::new();
        let stmts = vec![MlilStmt::Assign {
            dst: SsaVar::new("a", 1),
            expr: MlilExpr::Var(SsaVar::new("a", 0)),
        }];
        coalescer.build_from_assigns(&stmts);
        assert_eq!(coalescer.canonical_name(&SsaVar::new("a", 1)), "a");
    }

    #[test]
    fn expression_hoister_invariant_detection() {
        let hoister = ExpressionHoister::new();
        let loop_defs: HashSet<String> = ["i".to_string()].into_iter().collect();

        let const_expr = HlilExpr::Const(42);
        assert!(hoister.is_invariant(&const_expr, &loop_defs));

        let loop_var = HlilExpr::Var(HlilVar::new("i", "int"));
        assert!(!hoister.is_invariant(&loop_var, &loop_defs));

        let outer_var = HlilExpr::Var(HlilVar::new("x", "int"));
        assert!(hoister.is_invariant(&outer_var, &loop_defs));
    }

    #[test]
    fn bridge_simple_function() {
        let func = make_simple_function();
        let mut bridge = MlilToHlilBridge::with_default_config();
        let hlil = bridge.translate(&func);
        assert_eq!(hlil.blocks.len(), 1);
        assert!(!hlil.blocks[0].stmts.is_empty());
    }

    #[test]
    fn bridge_phi_function() {
        let func = make_phi_function();
        let mut bridge = MlilToHlilBridge::with_default_config();
        let hlil = bridge.translate(&func);
        for block in &hlil.blocks {
            for stmt in &block.stmts {
                // No phi comments should appear in a clean translation.
                if let HlilStmt::Comment(c) = stmt {
                    assert!(!c.contains("PHI not eliminated"), "unexpected phi comment");
                }
            }
        }
    }

    #[test]
    fn bridge_stats() {
        let func = make_phi_function();
        let mut bridge = MlilToHlilBridge::with_default_config();
        bridge.translate(&func);
        let stats = bridge.stats();
        assert!(stats.phi_vars_coalesced > 0);
    }
}
