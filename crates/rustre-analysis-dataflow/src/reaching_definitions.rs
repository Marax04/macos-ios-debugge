//! `reaching_definitions` — Reaching definitions, def-use/use-def chains,
//! live variables, available expressions, constant propagation, and copy propagation.
//!
//! # Relationship to [`crate::reaching_defs`]
//! This module is a *self-contained bundle* built on its own `BasicBlockInfo`
//! IR (blocks keyed by `u64` IDs with named [`Var`] variables).  It packs
//! several analyses together: [`ReachingDefs`], [`DefUseChain`], [`UseDefChain`],
//! [`LiveVariables`], [`AvailableExpressions`], [`ConstantPropagation`], and
//! [`CopyPropagation`].
//!
//! [`crate::reaching_defs`] targets the project's shared non-SSA CFG IR
//! (`cfg_dom::Cfg` + `NonSsaInstruction` with numeric `DefId`/`var_id`
//! identifiers) and is the lower-level layer used by the main analysis pipeline.
//! The two modules are intentionally kept separate.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataflowError {
    CfgNodeNotFound(u64),
    FixpointNotReached(usize),
    EmptyProgram,
}

impl fmt::Display for DataflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CfgNodeNotFound(id) => write!(f, "CFG node not found: {id:#x}"),
            Self::FixpointNotReached(iters) => {
                write!(f, "fixpoint not reached after {iters} iterations")
            }
            Self::EmptyProgram => write!(f, "empty program"),
        }
    }
}

impl std::error::Error for DataflowError {}

// ─── Variable / Definition / Use ─────────────────────────────────────────────

/// A variable identifier (register name or symbolic variable).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Var(pub String);

impl Var {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

impl fmt::Display for Var {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A definition: (variable, definition site as `block_id` + `instr_index`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Def {
    pub var: Var,
    pub block_id: u64,
    pub instr_idx: usize,
}

/// A use: (variable, use site).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Use {
    pub var: Var,
    pub block_id: u64,
    pub instr_idx: usize,
}

// ─── BasicBlockInfo ──────────────────────────────────────────────────────────

/// Precomputed per-block gen/kill sets for reaching definitions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BasicBlockInfo {
    pub block_id: u64,
    /// Definitions generated in this block (not killed by later defs in block).
    #[serde(rename = "gen")]
    pub r#gen: HashSet<Def>,
    /// Variables for which all reaching defs from outside are killed.
    pub kill_vars: HashSet<Var>,
    /// All defs in this block, in order.
    pub defs: Vec<Def>,
    /// All uses in this block.
    pub uses: Vec<Use>,
    /// Successor block IDs.
    pub successors: Vec<u64>,
    /// Predecessor block IDs.
    pub predecessors: Vec<u64>,
}

impl BasicBlockInfo {
    #[must_use] 
    pub fn new(block_id: u64) -> Self {
        Self {
            block_id,
            ..Default::default()
        }
    }
}

// ─── ReachingDefs ────────────────────────────────────────────────────────────

/// Reaching-definitions analysis result.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ReachingDefs {
    /// Maps each block ID → set of definitions reaching the block entry.
    pub reach_in: HashMap<u64, HashSet<Def>>,
    /// Maps each block ID → set of definitions reaching the block exit.
    pub reach_out: HashMap<u64, HashSet<Def>>,
}

impl ReachingDefs {
    /// Run reaching-definitions analysis on a list of basic blocks.
    ///
    /// # Errors
    /// Returns [`DataflowError::FixpointNotReached`] if the analysis does not
    /// converge within `max_iters` iterations.
    pub fn compute(
        blocks: &[BasicBlockInfo],
        entry: u64,
        max_iters: usize,
    ) -> Result<Self, DataflowError> {
        if blocks.is_empty() {
            return Err(DataflowError::EmptyProgram);
        }
        // FxHashMap prevents hash-collision DoS when block_ids come from
        // attacker-controlled binary input (many blocks colliding on SipHash).
        let block_map: FxHashMap<u64, &BasicBlockInfo> =
            blocks.iter().map(|b| (b.block_id, b)).collect();

        if !block_map.contains_key(&entry) {
            return Err(DataflowError::EmptyProgram);
        }

        let mut reach_in: FxHashMap<u64, HashSet<Def>> = FxHashMap::default();
        let mut reach_out: FxHashMap<u64, HashSet<Def>> = FxHashMap::default();

        for b in blocks {
            reach_in.insert(b.block_id, HashSet::new());
            reach_out.insert(b.block_id, HashSet::new());
        }

        // Seed the entry block at the front of the worklist so the fixpoint
        // converges from the program's start.
        let mut worklist: VecDeque<u64> = VecDeque::with_capacity(blocks.len());
        worklist.push_back(entry);
        for b in blocks {
            if b.block_id != entry {
                worklist.push_back(b.block_id);
            }
        }
        let mut iter_count = 0;

        while let Some(bid) = worklist.pop_front() {
            iter_count += 1;
            if iter_count > max_iters {
                return Err(DataflowError::FixpointNotReached(iter_count));
            }
            let Some(block) = block_map.get(&bid) else { continue };

            // IN[B] = union of OUT[P] for all predecessors P.
            let new_in: HashSet<Def> = block
                .predecessors
                .iter()
                .flat_map(|&pred| reach_out.get(&pred).cloned().unwrap_or_default())
                .collect();

            // OUT[B] = gen[B] ∪ (IN[B] - kill[B])
            let filtered_in: HashSet<Def> = new_in
                .iter()
                .filter(|d| !block.kill_vars.contains(&d.var))
                .cloned()
                .collect();
            let new_out: HashSet<Def> = block.r#gen.union(&filtered_in).cloned().collect();

            if reach_in.get(&bid).is_none_or(|prev| new_in != *prev)
                || reach_out.get(&bid).is_none_or(|prev| new_out != *prev)
            {
                reach_in.insert(bid, new_in);
                reach_out.insert(bid, new_out);
                for &succ in &block.successors {
                    worklist.push_back(succ);
                }
            }
        }

        Ok(Self {
            reach_in: reach_in.into_iter().collect(),
            reach_out: reach_out.into_iter().collect(),
        })
    }

    /// Get definitions of `var` that reach the entry of `block`.
    #[must_use] 
    pub fn reaching_defs_at(&self, block: u64, var: &Var) -> Vec<&Def> {
        self.reach_in
            .get(&block)
            .map(|s| s.iter().filter(|d| &d.var == var).collect())
            .unwrap_or_default()
    }
}

// ─── DefUseChain ─────────────────────────────────────────────────────────────

/// Maps each definition to all its uses.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DefUseChain {
    pub chains: HashMap<Def, Vec<Use>>,
}

impl DefUseChain {
    /// Build def-use chains from reaching defs and block information.
    #[must_use]
    pub fn build(blocks: &[BasicBlockInfo], reaching: &ReachingDefs) -> Self {
        // FxHashMap prevents hash-collision DoS when Def keys contain
        // attacker-controlled variable-name strings from parsed binary input.
        let mut chains: FxHashMap<Def, Vec<Use>> = FxHashMap::default();

        for block in blocks {
            // For each use in the block, find reaching defs.
            for use_site in &block.uses {
                let defs = reaching.reaching_defs_at(block.block_id, &use_site.var);
                for def in defs {
                    chains
                        .entry(def.clone())
                        .or_default()
                        .push(use_site.clone());
                }
            }
        }
        Self { chains: chains.into_iter().collect() }
    }

    /// Return all uses for a definition.
    #[must_use] 
    pub fn uses_of(&self, def: &Def) -> &[Use] {
        self.chains.get(def).map_or(&[], std::vec::Vec::as_slice)
    }

    /// Number of def-use pairs.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.chains.values().map(std::vec::Vec::len).sum()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.chains.is_empty()
    }
}

// ─── UseDefChain ─────────────────────────────────────────────────────────────

/// Maps each use to all definitions that might reach it.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UseDefChain {
    pub chains: HashMap<Use, Vec<Def>>,
}

impl UseDefChain {
    /// Build use-def chains from reaching defs and block information.
    #[must_use]
    pub fn build(blocks: &[BasicBlockInfo], reaching: &ReachingDefs) -> Self {
        // FxHashMap prevents hash-collision DoS when Use keys contain
        // attacker-controlled variable-name strings from parsed binary input.
        let mut chains: FxHashMap<Use, Vec<Def>> = FxHashMap::default();

        for block in blocks {
            for use_site in &block.uses {
                let defs = reaching.reaching_defs_at(block.block_id, &use_site.var);
                chains
                    .entry(use_site.clone())
                    .or_default()
                    .extend(defs.into_iter().cloned());
            }
        }
        Self { chains: chains.into_iter().collect() }
    }

    /// Return all definitions reaching a use.
    #[must_use] 
    pub fn defs_of(&self, use_site: &Use) -> &[Def] {
        self.chains
            .get(use_site)
            .map_or(&[], std::vec::Vec::as_slice)
    }
}

// ─── LiveVariables ────────────────────────────────────────────────────────────

/// Live-variable analysis result (backward analysis).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LiveVariables {
    pub live_in: HashMap<u64, HashSet<Var>>,
    pub live_out: HashMap<u64, HashSet<Var>>,
}

impl LiveVariables {
    /// Compute live-variable analysis.
    ///
    /// `use_sets`: maps `block_id` → variables used before defined (upward-exposed uses).
    /// `def_sets`: maps `block_id` → variables defined in the block.
    ///
    /// # Errors
    /// Returns [`DataflowError::FixpointNotReached`] if the analysis does not
    /// converge within `max_iters` iterations.
    ///
    /// # Panics
    /// Panics if `entry` is not present in `blocks`.
    pub fn compute(
        blocks: &[BasicBlockInfo],
        entry: u64,
        max_iters: usize,
    ) -> Result<Self, DataflowError> {
        if blocks.is_empty() {
            return Err(DataflowError::EmptyProgram);
        }

        // FxHashMap prevents hash-collision DoS on attacker-controlled block IDs.
        let block_map: FxHashMap<u64, &BasicBlockInfo> =
            blocks.iter().map(|b| (b.block_id, b)).collect();

        if !block_map.contains_key(&entry) {
            return Err(DataflowError::EmptyProgram);
        }

        let mut live_in: FxHashMap<u64, HashSet<Var>> = FxHashMap::default();
        let mut live_out: FxHashMap<u64, HashSet<Var>> = FxHashMap::default();
        for b in blocks {
            live_in.insert(b.block_id, HashSet::new());
            live_out.insert(b.block_id, HashSet::new());
        }

        // Backward analysis — process in reverse order.
        let mut changed = true;
        let mut iters = 0;
        while changed {
            iters += 1;
            if iters > max_iters {
                return Err(DataflowError::FixpointNotReached(iters));
            }
            changed = false;
            for block in blocks.iter().rev() {
                // live_out[B] = union of live_in[S] for all successors S.
                let new_out: HashSet<Var> = block
                    .successors
                    .iter()
                    .flat_map(|&s| live_in.get(&s).cloned().unwrap_or_default())
                    .collect();

                // Upward-exposed uses in this block, computed in instruction
                // order so that a use before its definition is correctly
                // included in the upward-exposed set even when the same
                // variable is also defined later in the block.
                let mut defined_so_far: HashSet<Var> = HashSet::new();
                let mut upward: HashSet<Var> = HashSet::new();
                // Build a sorted event list: (instr_idx, is_def).
                // At the SAME index, uses must be processed BEFORE defs: a single
                // instruction reads its operands before writing its result. For a
                // read-modify-write such as `a = a + 1` the def and the use share
                // an `instr_idx`, and taking the def first would let the
                // instruction's own def kill its own use — `a` would be dropped
                // from the upward-exposed set, the analysis would call `a`
                // dead-on-entry, and the assignment feeding it would be deleted.
                // That is a silent miscompilation for every accumulator and
                // induction variable, so the tie must break towards the use.
                let mut def_events: Vec<(usize, &Def)> = block
                    .defs
                    .iter()
                    .map(|d| (d.instr_idx, d))
                    .collect();
                def_events.sort_by_key(|&(idx, _)| idx);
                let mut use_events: Vec<(usize, &Use)> = block
                    .uses
                    .iter()
                    .map(|u| (u.instr_idx, u))
                    .collect();
                use_events.sort_by_key(|&(idx, _)| idx);
                // Merge-process both sorted lists in instruction order.
                let mut di = 0usize;
                let mut ui = 0usize;
                while di < def_events.len() || ui < use_events.len() {
                    let take_def = match (def_events.get(di), use_events.get(ui)) {
                        // Strict `<`: on a tie the use wins, so an instruction's
                        // operands are read before its result is written.
                        (Some(&(di_idx, _)), Some(&(ui_idx, _))) => di_idx < ui_idx,
                        (Some(_), None) => true,
                        _ => false,
                    };
                    if take_def {
                        defined_so_far.insert(def_events[di].1.var.clone());
                        di += 1;
                    } else {
                        let u = use_events[ui].1;
                        if !defined_so_far.contains(&u.var) {
                            upward.insert(u.var.clone());
                        }
                        ui += 1;
                    }
                }
                let defined: HashSet<Var> = defined_so_far;

                // live_in[B] = use[B] ∪ (live_out[B] - def[B])
                let filtered_out: HashSet<Var> = new_out
                    .iter()
                    .filter(|v| !defined.contains(*v))
                    .cloned()
                    .collect();
                let new_in: HashSet<Var> = upward.union(&filtered_out).cloned().collect();

                if new_out != *live_out.get(&block.block_id).unwrap()
                    || new_in != *live_in.get(&block.block_id).unwrap()
                {
                    live_out.insert(block.block_id, new_out);
                    live_in.insert(block.block_id, new_in);
                    changed = true;
                }
            }
        }
        Ok(Self {
            live_in: live_in.into_iter().collect(),
            live_out: live_out.into_iter().collect(),
        })
    }

    /// Returns the set of variables live at the entry of a block.
    #[must_use] 
    pub fn live_at_entry(&self, block: u64) -> HashSet<Var> {
        self.live_in.get(&block).cloned().unwrap_or_default()
    }

    /// Returns the set of variables live at the exit of a block.
    #[must_use] 
    pub fn live_at_exit(&self, block: u64) -> HashSet<Var> {
        self.live_out.get(&block).cloned().unwrap_or_default()
    }
}

// ─── AvailableExpressions ─────────────────────────────────────────────────────

/// An expression that may be tracked for availability.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Expr {
    pub op: String,
    pub operands: Vec<Var>,
}

impl Expr {
    pub fn new(op: impl Into<String>, operands: Vec<Var>) -> Self {
        Self {
            op: op.into(),
            operands,
        }
    }

    /// Returns true if any operand is `var`.
    #[must_use] 
    pub fn uses_var(&self, var: &Var) -> bool {
        self.operands.contains(var)
    }
}

/// Available expressions analysis result.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AvailableExpressions {
    pub avail_in: HashMap<u64, HashSet<Expr>>,
    pub avail_out: HashMap<u64, HashSet<Expr>>,
}

impl AvailableExpressions {
    /// Compute available expressions.
    ///
    /// `gen_exprs`: expressions computed and not killed in each block.
    /// `kill_exprs`: expressions killed (containing a defined variable).
    ///
    /// # Errors
    /// Returns [`DataflowError::FixpointNotReached`] if the analysis does not
    /// converge within `max_iters` iterations.
    ///
    /// # Panics
    /// Panics if `entry` is not present in `blocks`.
    pub fn compute(
        blocks: &[BasicBlockInfo],
        gen_exprs: &HashMap<u64, HashSet<Expr>>,
        kill_exprs: &HashMap<u64, HashSet<Expr>>,
        entry: u64,
        all_exprs: &HashSet<Expr>,
        max_iters: usize,
    ) -> Result<Self, DataflowError> {
        if blocks.is_empty() {
            return Err(DataflowError::EmptyProgram);
        }

        // FxHashMap prevents hash-collision DoS on attacker-controlled block IDs.
        let mut avail_in: FxHashMap<u64, HashSet<Expr>> = FxHashMap::default();
        let mut avail_out: FxHashMap<u64, HashSet<Expr>> = FxHashMap::default();

        // Entry: avail_in[entry] = {} (nothing available on entry).
        avail_in.insert(entry, HashSet::new());
        // All other blocks: initialise to universe.
        for b in blocks {
            if b.block_id != entry {
                avail_in.insert(b.block_id, all_exprs.clone());
            }
            let r#gen = gen_exprs.get(&b.block_id).cloned().unwrap_or_default();
            avail_out.insert(b.block_id, r#gen);
        }

        // FxHashMap prevents hash-collision DoS on attacker-controlled block IDs.
        let block_map: FxHashMap<u64, &BasicBlockInfo> =
            blocks.iter().map(|b| (b.block_id, b)).collect();

        // Validate that every successor / predecessor edge references a real
        // block. This catches malformed CFGs before they cause silent
        // imprecision in the fixpoint.
        for b in blocks {
            for pred in &b.predecessors {
                debug_assert!(
                    block_map.contains_key(pred),
                    "predecessor {pred} of block {} is not in the block list",
                    b.block_id
                );
            }
        }

        let mut changed = true;
        let mut iters = 0;
        while changed {
            iters += 1;
            if iters > max_iters {
                return Err(DataflowError::FixpointNotReached(iters));
            }
            changed = false;
            for block in blocks {
                if block.block_id == entry {
                    continue;
                }
                // avail_in[B] = ∩ avail_out[P] for all predecessors P.
                let new_in = if block.predecessors.is_empty() {
                    HashSet::new()
                } else {
                    let mut iter = block.predecessors.iter();
                    let first = avail_out
                        .get(iter.next().unwrap())
                        .cloned()
                        .unwrap_or_default();
                    iter.fold(first, |acc: HashSet<Expr>, pred| {
                        let pred_out = avail_out.get(pred).cloned().unwrap_or_default();
                        acc.intersection(&pred_out).cloned().collect()
                    })
                };

                // avail_out[B] = gen[B] ∪ (avail_in[B] - kill[B])
                let kill = kill_exprs.get(&block.block_id).cloned().unwrap_or_default();
                let filtered: HashSet<Expr> = new_in
                    .iter()
                    .filter(|e| !kill.contains(*e))
                    .cloned()
                    .collect();
                let r#gen = gen_exprs.get(&block.block_id).cloned().unwrap_or_default();
                let new_out: HashSet<Expr> = r#gen.union(&filtered).cloned().collect();

                if avail_in.get(&block.block_id).map_or(!new_in.is_empty(), |prev| new_in != *prev)
                    || avail_out.get(&block.block_id).map_or(!new_out.is_empty(), |prev| new_out != *prev)
                {
                    avail_in.insert(block.block_id, new_in);
                    avail_out.insert(block.block_id, new_out);
                    changed = true;
                }
            }
        }
        Ok(Self {
            avail_in: avail_in.into_iter().collect(),
            avail_out: avail_out.into_iter().collect(),
        })
    }
}

// ─── ConstantPropagation ─────────────────────────────────────────────────────

/// Lattice value for constant propagation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstLattice {
    /// Top: the variable hasn't been analysed yet.
    Top,
    /// Constant: the variable has a known constant value.
    Const(i64),
    /// Bottom: the variable may hold multiple different values.
    Bottom,
}

impl ConstLattice {
    #[must_use] 
    pub fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Top, x) | (x, Self::Top) => x.clone(),
            (Self::Const(a), Self::Const(b)) if a == b => Self::Const(*a),
            _ => Self::Bottom,
        }
    }

    #[must_use] 
    pub const fn is_constant(&self) -> bool {
        matches!(self, Self::Const(_))
    }
}

/// Sparse conditional constant propagation.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ConstantPropagation {
    /// Maps variable → lattice value at each block exit.
    pub values: HashMap<u64, HashMap<Var, ConstLattice>>,
}

impl ConstantPropagation {
    /// Run constant propagation.
    ///
    /// `assignments`: maps `block_id` → list of (var, `const_value_or_none`).
    ///
    /// # Errors
    /// Returns [`DataflowError::FixpointNotReached`] if the analysis does not
    /// converge within `max_iters` iterations.
    pub fn compute(
        blocks: &[BasicBlockInfo],
        assignments: &HashMap<u64, Vec<(Var, Option<i64>)>>,
        entry: u64,
        max_iters: usize,
    ) -> Result<Self, DataflowError> {
        if blocks.is_empty() {
            return Err(DataflowError::EmptyProgram);
        }

        // FxHashMap prevents hash-collision DoS on attacker-controlled block IDs
        // and variable-name strings from parsed binary input.
        let mut values: FxHashMap<u64, FxHashMap<Var, ConstLattice>> = FxHashMap::default();
        for b in blocks {
            values.insert(b.block_id, FxHashMap::default());
        }

        let block_map: FxHashMap<u64, &BasicBlockInfo> =
            blocks.iter().map(|b| (b.block_id, b)).collect();

        if !block_map.contains_key(&entry) {
            return Err(DataflowError::EmptyProgram);
        }

        // Process the entry block first so initial constant values propagate
        // forward as early as possible.
        let mut worklist: VecDeque<u64> = VecDeque::with_capacity(blocks.len());
        worklist.push_back(entry);
        for b in blocks {
            if b.block_id != entry {
                worklist.push_back(b.block_id);
            }
        }
        let mut iters = 0;

        while let Some(bid) = worklist.pop_front() {
            iters += 1;
            if iters > max_iters * blocks.len() {
                return Err(DataflowError::FixpointNotReached(iters));
            }
            let Some(block) = block_map.get(&bid) else { continue };

            // Merge incoming values from predecessors.
            let mut in_vals: FxHashMap<Var, ConstLattice> = FxHashMap::default();
            for &pred in &block.predecessors {
                if let Some(pred_vals) = values.get(&pred) {
                    for (var, lat) in pred_vals {
                        let entry = in_vals.entry(var.clone()).or_insert(ConstLattice::Top);
                        *entry = entry.meet(lat);
                    }
                }
            }

            // Apply assignments in this block.
            if let Some(assigns) = assignments.get(&bid) {
                for (var, maybe_const) in assigns {
                    let lat = maybe_const.as_ref().map_or(ConstLattice::Bottom, |c| ConstLattice::Const(*c));
                    in_vals.insert(var.clone(), lat);
                }
            }

            let old = values.get(&bid).cloned().unwrap_or_default();
            if old != in_vals {
                values.insert(bid, in_vals);
                for &succ in &block.successors {
                    worklist.push_back(succ);
                }
            }
        }
        Ok(Self {
            values: values
                .into_iter()
                .map(|(k, inner)| (k, inner.into_iter().collect()))
                .collect(),
        })
    }

    /// Get the constant value of a variable at a block exit, if known.
    #[must_use] 
    pub fn constant_at(&self, block: u64, var: &Var) -> Option<i64> {
        self.values.get(&block).and_then(|m| {
            m.get(var).and_then(|lat| {
                if let ConstLattice::Const(c) = lat {
                    Some(*c)
                } else {
                    None
                }
            })
        })
    }

    /// Collect all variables with known constant values at a block.
    #[must_use] 
    pub fn constants_at_block(&self, block: u64) -> HashMap<Var, i64> {
        self.values
            .get(&block)
            .map(|m| {
                m.iter()
                    .filter_map(|(v, lat)| {
                        if let ConstLattice::Const(c) = lat {
                            Some((v.clone(), *c))
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

// ─── CopyPropagation ─────────────────────────────────────────────────────────

/// Copy propagation: tracks which variables are copies of others.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CopyPropagation {
    /// Maps variable → the variable it is a copy of (at each block exit).
    pub copies: HashMap<u64, HashMap<Var, Var>>,
}

impl CopyPropagation {
    /// Run copy propagation.
    ///
    /// `copy_assignments`: maps `block_id` → list of (dst, src) copy instructions.
    ///
    /// # Errors
    /// Returns [`DataflowError::FixpointNotReached`] if the analysis does not
    /// converge within `max_iters` iterations.
    pub fn compute(
        blocks: &[BasicBlockInfo],
        copy_assignments: &HashMap<u64, Vec<(Var, Var)>>,
        max_iters: usize,
    ) -> Result<Self, DataflowError> {
        if blocks.is_empty() {
            return Err(DataflowError::EmptyProgram);
        }

        // FxHashMap prevents hash-collision DoS on attacker-controlled block IDs
        // and variable-name string keys from parsed binary input.
        let mut copies: FxHashMap<u64, FxHashMap<Var, Var>> = FxHashMap::default();
        for b in blocks {
            copies.insert(b.block_id, FxHashMap::default());
        }

        let block_map: FxHashMap<u64, &BasicBlockInfo> =
            blocks.iter().map(|b| (b.block_id, b)).collect();

        // Validate that every successor edge references a block that exists.
        for b in blocks {
            for succ in &b.successors {
                debug_assert!(
                    block_map.contains_key(succ),
                    "successor {succ} of block {} is not in the block list",
                    b.block_id
                );
            }
        }

        let mut changed = true;
        let mut iters = 0;
        while changed {
            iters += 1;
            if iters > max_iters {
                return Err(DataflowError::FixpointNotReached(iters));
            }
            changed = false;
            for block in blocks {
                // Intersect predecessor copies.
                let pred_copies: Vec<&FxHashMap<Var, Var>> = block
                    .predecessors
                    .iter()
                    .filter_map(|p| copies.get(p))
                    .collect();

                let mut in_copies: FxHashMap<Var, Var> = if pred_copies.is_empty() {
                    FxHashMap::default()
                } else {
                    let mut m = pred_copies[0].clone();
                    for other in &pred_copies[1..] {
                        let other: &FxHashMap<Var, Var> = other;
                        m.retain(|k, v| other.get(k) == Some(&*v));
                    }
                    m
                };

                // Apply this block's copy assignments.
                if let Some(assigns) = copy_assignments.get(&block.block_id) {
                    for (dst, src) in assigns {
                        // Follow the copy chain.
                        let canonical_src = in_copies.get(src).cloned().unwrap_or_else(|| src.clone());
                        in_copies.insert(dst.clone(), canonical_src);
                    }
                }

                // Kill copies involving variables defined (non-copy) in this block.
                for def in &block.defs {
                    let is_copy = copy_assignments
                        .get(&block.block_id)
                        .is_some_and(|assigns| assigns.iter().any(|(d, _)| d == &def.var));
                    if !is_copy {
                        in_copies.retain(|k, v| k != &def.var && v != &def.var);
                    }
                }

                let old = copies.get(&block.block_id).cloned().unwrap_or_default();
                if old != in_copies {
                    copies.insert(block.block_id, in_copies);
                    changed = true;
                }
            }
        }
        Ok(Self {
            copies: copies
                .into_iter()
                .map(|(k, inner)| (k, inner.into_iter().collect()))
                .collect(),
        })
    }

    /// Resolve the canonical source of a variable at a block.
    #[must_use] 
    pub fn resolve(&self, block: u64, var: &Var) -> Var {
        self.copies
            .get(&block)
            .and_then(|m| m.get(var))
            .cloned()
            .unwrap_or_else(|| var.clone())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_block(id: u64, succs: Vec<u64>, preds: Vec<u64>) -> BasicBlockInfo {
        let mut b = BasicBlockInfo::new(id);
        b.successors = succs;
        b.predecessors = preds;
        b
    }

    fn var(s: &str) -> Var {
        Var::new(s)
    }

    fn def(v: &str, block: u64, idx: usize) -> Def {
        Def {
            var: var(v),
            block_id: block,
            instr_idx: idx,
        }
    }

    fn use_(v: &str, block: u64, idx: usize) -> Use {
        Use {
            var: var(v),
            block_id: block,
            instr_idx: idx,
        }
    }

    #[test]
    fn reaching_defs_linear() {
        // Block 0 defines x; block 1 uses x.
        let mut b0 = simple_block(0, vec![1], vec![]);
        let d = def("x", 0, 0);
        b0.r#gen.insert(d.clone());
        b0.defs.push(d);

        let mut b1 = simple_block(1, vec![], vec![0]);
        b1.uses.push(use_("x", 1, 0));

        let blocks = vec![b0, b1];
        let result = ReachingDefs::compute(&blocks, 0, 1000).unwrap();

        // x should reach into block 1.
        let reaching = result.reaching_defs_at(1, &var("x"));
        assert!(!reaching.is_empty());
    }

    #[test]
    fn reaching_defs_kill() {
        // Block 0 defines x; block 1 re-defines x and kills old defs; block 2 sees only block 1's def.
        let mut b0 = simple_block(0, vec![1], vec![]);
        let d0 = def("x", 0, 0);
        b0.r#gen.insert(d0.clone());
        b0.defs.push(d0);

        let mut b1 = simple_block(1, vec![2], vec![0]);
        let d1 = def("x", 1, 0);
        b1.r#gen.insert(d1.clone());
        b1.kill_vars.insert(var("x"));
        b1.defs.push(d1);

        let b2 = simple_block(2, vec![], vec![1]);

        let blocks = vec![b0, b1, b2];
        let result = ReachingDefs::compute(&blocks, 0, 1000).unwrap();

        let reaching_b2 = result.reaching_defs_at(2, &var("x"));
        // Only block 1's definition of x should reach block 2.
        assert_eq!(reaching_b2.len(), 1);
        assert_eq!(reaching_b2[0].block_id, 1);
    }

    #[test]
    fn reaching_defs_empty_error() {
        let result = ReachingDefs::compute(&[], 0, 100);
        assert!(matches!(result, Err(DataflowError::EmptyProgram)));
    }

    #[test]
    fn def_use_chain_build() {
        let mut b0 = simple_block(0, vec![1], vec![]);
        let d = def("y", 0, 0);
        b0.r#gen.insert(d.clone());
        b0.defs.push(d);

        let mut b1 = simple_block(1, vec![], vec![0]);
        b1.uses.push(use_("y", 1, 0));

        let blocks = vec![b0, b1];
        let reaching = ReachingDefs::compute(&blocks, 0, 1000).unwrap();
        let du = DefUseChain::build(&blocks, &reaching);

        assert!(!du.is_empty());
        let def_y = def("y", 0, 0);
        let uses = du.uses_of(&def_y);
        assert!(!uses.is_empty());
    }

    #[test]
    fn use_def_chain_build() {
        let mut b0 = simple_block(0, vec![1], vec![]);
        let d = def("z", 0, 0);
        b0.r#gen.insert(d.clone());
        b0.defs.push(d);

        let mut b1 = simple_block(1, vec![], vec![0]);
        b1.uses.push(use_("z", 1, 0));

        let blocks = vec![b0, b1];
        let reaching = ReachingDefs::compute(&blocks, 0, 1000).unwrap();
        let ud = UseDefChain::build(&blocks, &reaching);

        let use_z = use_("z", 1, 0);
        let defs = ud.defs_of(&use_z);
        assert!(!defs.is_empty());
    }

    #[test]
    fn live_variables_linear() {
        let mut b0 = simple_block(0, vec![1], vec![]);
        b0.uses.push(use_("a", 0, 0));

        let b1 = simple_block(1, vec![], vec![0]);

        let blocks = vec![b0, b1];
        let lv = LiveVariables::compute(&blocks, 0, 1000).unwrap();
        // 'a' is used in b0 without being defined → live at entry of b0.
        let live = lv.live_at_entry(0);
        assert!(live.contains(&var("a")));
    }

    #[test]
    fn live_variables_empty_error() {
        let result = LiveVariables::compute(&[], 0, 100);
        assert!(matches!(result, Err(DataflowError::EmptyProgram)));
    }

    /// Regression: a read-modify-write statement (`a = a + 1`) reads `a`
    /// BEFORE it writes `a`. Both the def and the use carry the same
    /// `instr_idx`, and the use must be treated as upward-exposed: the
    /// statement's own def must not kill the statement's own use.
    ///
    /// b0: a = 0        (def a @0)
    /// b1: a = a + 1    (use a @0, def a @0)  ← accumulator / induction var
    ///
    /// `a` must be live at entry of b1, and therefore live-out of b0 — else
    /// the `a = 0` in b0 is reported dead, deleted, and b1 reads uninitialised
    /// memory. Silent miscompilation.
    #[test]
    fn live_variables_read_modify_write_use_is_upward_exposed() {
        let mut b0 = simple_block(0, vec![1], vec![]);
        b0.defs.push(def("a", 0, 0));

        let mut b1 = simple_block(1, vec![], vec![0]);
        b1.uses.push(use_("a", 1, 0));
        b1.defs.push(def("a", 1, 0));

        let blocks = vec![b0, b1];
        let lv = LiveVariables::compute(&blocks, 0, 1000).unwrap();

        assert!(
            lv.live_at_entry(1).contains(&var("a")),
            "`a = a + 1` reads `a`: a must be live at entry of b1, got {:?}",
            lv.live_at_entry(1)
        );
        assert!(
            lv.live_at_exit(0).contains(&var("a")),
            "the `a = 0` in b0 is read by b1: a must be live-out of b0, got {:?}",
            lv.live_at_exit(0)
        );
    }

    /// A use at a LATER instruction than the def in the same block is genuinely
    /// killed by that def and must NOT be upward-exposed. Guards the fix from
    /// over-correcting into "every use is upward-exposed".
    #[test]
    fn live_variables_use_after_def_in_same_block_is_not_upward_exposed() {
        let mut b0 = simple_block(0, vec![], vec![]);
        b0.defs.push(def("a", 0, 0)); // a = 0
        b0.uses.push(use_("a", 0, 1)); // b = a   (later instr)

        let blocks = vec![b0];
        let lv = LiveVariables::compute(&blocks, 0, 1000).unwrap();
        assert!(
            !lv.live_at_entry(0).contains(&var("a")),
            "a is defined at idx 0 before its use at idx 1 → not upward-exposed"
        );
    }

    #[test]
    fn live_variables_dead_variable() {
        let mut b0 = simple_block(0, vec![], vec![]);
        let d = def("dead_var", 0, 0);
        b0.defs.push(d);
        b0.kill_vars.insert(var("dead_var"));

        let blocks = vec![b0];
        let lv = LiveVariables::compute(&blocks, 0, 1000).unwrap();
        let live_out = lv.live_at_exit(0);
        assert!(!live_out.contains(&var("dead_var")));
    }

    #[test]
    fn const_lattice_meet_same() {
        let a = ConstLattice::Const(42);
        let b = ConstLattice::Const(42);
        assert_eq!(a.meet(&b), ConstLattice::Const(42));
    }

    #[test]
    fn const_lattice_meet_different() {
        let a = ConstLattice::Const(1);
        let b = ConstLattice::Const(2);
        assert_eq!(a.meet(&b), ConstLattice::Bottom);
    }

    #[test]
    fn const_lattice_meet_top() {
        let a = ConstLattice::Top;
        let b = ConstLattice::Const(5);
        assert_eq!(a.meet(&b), ConstLattice::Const(5));
    }

    #[test]
    fn constant_propagation_known_constant() {
        let b0 = simple_block(0, vec![1], vec![]);
        let b1 = simple_block(1, vec![], vec![0]);
        let mut assigns = HashMap::new();
        assigns.insert(0u64, vec![(var("x"), Some(42i64))]);
        let blocks = vec![b0, b1];
        let cp = ConstantPropagation::compute(&blocks, &assigns, 0, 1000).unwrap();
        assert_eq!(cp.constant_at(0, &var("x")), Some(42));
    }

    #[test]
    fn constant_propagation_non_constant() {
        let b0 = simple_block(0, vec![], vec![]);
        let mut assigns = HashMap::new();
        assigns.insert(0u64, vec![(var("x"), None::<i64>)]);
        let blocks = vec![b0];
        let cp = ConstantPropagation::compute(&blocks, &assigns, 0, 1000).unwrap();
        assert_eq!(cp.constant_at(0, &var("x")), None);
    }

    #[test]
    fn constant_propagation_constants_at_block() {
        let b0 = simple_block(0, vec![], vec![]);
        let mut assigns = HashMap::new();
        assigns.insert(0u64, vec![(var("a"), Some(1i64)), (var("b"), Some(2i64))]);
        let blocks = vec![b0];
        let cp = ConstantPropagation::compute(&blocks, &assigns, 0, 1000).unwrap();
        let consts = cp.constants_at_block(0);
        assert_eq!(consts.get(&var("a")), Some(&1));
        assert_eq!(consts.get(&var("b")), Some(&2));
    }

    #[test]
    fn copy_propagation_simple() {
        let b0 = simple_block(0, vec![], vec![]);
        let mut copies_map = HashMap::new();
        copies_map.insert(0u64, vec![(var("b"), var("a"))]);
        let blocks = vec![b0];
        let cp = CopyPropagation::compute(&blocks, &copies_map, 1000).unwrap();
        assert_eq!(cp.resolve(0, &var("b")), var("a"));
    }

    #[test]
    fn copy_propagation_no_copy() {
        let b0 = simple_block(0, vec![], vec![]);
        let blocks = vec![b0];
        let cp = CopyPropagation::compute(&blocks, &HashMap::new(), 1000).unwrap();
        assert_eq!(cp.resolve(0, &var("x")), var("x"));
    }

    #[test]
    fn expr_uses_var() {
        let e = Expr::new("add", vec![var("a"), var("b")]);
        assert!(e.uses_var(&var("a")));
        assert!(!e.uses_var(&var("c")));
    }

    #[test]
    fn dataflow_error_display() {
        let e = DataflowError::FixpointNotReached(100);
        assert!(e.to_string().contains("100"));
    }

    #[test]
    fn var_display() {
        let v = Var::new("eax");
        assert_eq!(v.to_string(), "eax");
    }
}
