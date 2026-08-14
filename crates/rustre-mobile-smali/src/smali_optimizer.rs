//! Smali optimizer: dead code removal, constant propagation,
//! trivial move elimination, NOP removal, and basic peephole rewrites.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use crate::smali_parser::{ParsedClass, ParsedInstruction, ParsedLabel, ParsedMethod};
use crate::DalvikOpcode;

// ── OptimizationStats ─────────────────────────────────────────────────────────

/// Summary of what was changed during an optimization pass.
#[derive(Debug, Clone, Default)]
pub struct OptimizationStats {
    pub nops_removed: usize,
    pub trivial_moves_removed: usize,
    pub dead_instructions_removed: usize,
    pub constants_propagated: usize,
    pub branches_simplified: usize,
    pub methods_optimized: usize,
}

impl OptimizationStats {
    #[must_use] 
    pub const fn total_changes(&self) -> usize {
        self.nops_removed
            + self.trivial_moves_removed
            + self.dead_instructions_removed
            + self.constants_propagated
            + self.branches_simplified
    }

    pub const fn merge(&mut self, other: &Self) {
        self.nops_removed += other.nops_removed;
        self.trivial_moves_removed += other.trivial_moves_removed;
        self.dead_instructions_removed += other.dead_instructions_removed;
        self.constants_propagated += other.constants_propagated;
        self.branches_simplified += other.branches_simplified;
        self.methods_optimized += other.methods_optimized;
    }
}

impl fmt::Display for OptimizationStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NOPs={} TrivialMoves={} DeadCode={} ConstProp={} Branches={}",
            self.nops_removed,
            self.trivial_moves_removed,
            self.dead_instructions_removed,
            self.constants_propagated,
            self.branches_simplified,
        )
    }
}

// ── ConstantValue ─────────────────────────────────────────────────────────────

/// Abstract constant lattice value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstantValue {
    Unknown,
    Const(i64),
    /// String pool index.
    String(String),
    /// Type descriptor.
    Type(String),
    /// Null reference.
    Null,
    /// Non-constant (merged from two different values).
    Top,
}

impl ConstantValue {
    #[must_use] 
    pub fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (a, b) if a == b => a.clone(),
            (Self::Unknown, x) | (x, Self::Unknown) => x.clone(),
            _ => Self::Top,
        }
    }

    #[must_use] 
    pub const fn is_known_const(&self) -> bool {
        matches!(self, Self::Const(_) | Self::Null)
    }
}

// ── RegisterFile ──────────────────────────────────────────────────────────────

/// Map of register index → constant value (for constant propagation).
#[derive(Debug, Clone, Default)]
pub struct RegisterFile {
    pub regs: HashMap<u8, ConstantValue>,
}

impl RegisterFile {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            regs: HashMap::new(),
        }
    }

    pub fn set(&mut self, reg: u8, val: ConstantValue) {
        self.regs.insert(reg, val);
    }

    #[must_use] 
    pub fn get(&self, reg: u8) -> &ConstantValue {
        self.regs.get(&reg).unwrap_or(&ConstantValue::Unknown)
    }

    pub fn kill(&mut self, reg: u8) {
        self.regs.insert(reg, ConstantValue::Top);
    }

    /// Merge another register file into this one (join).
    pub fn merge(&mut self, other: &Self) {
        let keys: HashSet<u8> = self.regs.keys().chain(other.regs.keys()).copied().collect();
        for k in keys {
            let av = self.get(k).clone();
            let bv = other.get(k).clone();
            self.regs.insert(k, av.join(&bv));
        }
    }
}

// ── CFG ───────────────────────────────────────────────────────────────────────

/// Basic block in the control-flow graph.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: usize,
    pub start: usize,
    pub end: usize, // exclusive
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
}

/// Build a minimal CFG from instruction list + label map.
#[must_use] 
pub fn build_cfg(
    instructions: &[ParsedInstruction],
    labels: &HashMap<String, ParsedLabel>,
) -> Vec<BasicBlock> {
    if instructions.is_empty() {
        return Vec::new();
    }
    // Collect leader indices (start of basic blocks).
    let mut leaders: HashSet<usize> = HashSet::new();
    leaders.insert(0);
    for (i, insn) in instructions.iter().enumerate() {
        if is_branch(insn) || is_jump(insn) || is_return(insn) {
            if i + 1 < instructions.len() {
                leaders.insert(i + 1);
            }
            // The jump target is also a leader.
            if let Some(label) = &insn.label
                && let Some(lbl) = labels.get(label) {
                    leaders.insert(lbl.instruction_index);
                }
        }
    }
    let mut sorted_leaders: Vec<usize> = leaders.into_iter().collect();
    sorted_leaders.sort_unstable();
    let _n = sorted_leaders.len();
    let mut blocks: Vec<BasicBlock> = sorted_leaders
        .iter()
        .enumerate()
        .map(|(id, &start)| {
            let end = sorted_leaders.get(id + 1).copied().unwrap_or(instructions.len());
            BasicBlock {
                id,
                start,
                end,
                successors: Vec::new(),
                predecessors: Vec::new(),
            }
        })
        .collect();
    // Compute successors.
    for i in 0..blocks.len() {
        let block = &blocks[i];
        let last_idx = if block.end > 0 { block.end - 1 } else { continue };
        let last = &instructions[last_idx];
        if is_return(last) {
            // No successors.
        } else if is_jump(last) {
            if let Some(label) = &last.label
                && let Some(lbl) = labels.get(label) {
                    let target = lbl.instruction_index;
                    let target_block = blocks.iter().position(|b| b.start == target);
                    if let Some(tb) = target_block {
                        blocks[i].successors.push(tb);
                    }
                }
        } else if is_branch(last) {
            // Fall-through.
            if i + 1 < blocks.len() {
                blocks[i].successors.push(i + 1);
            }
            // Branch target.
            if let Some(label) = &last.label
                && let Some(lbl) = labels.get(label) {
                    let target = lbl.instruction_index;
                    if let Some(tb) = blocks.iter().position(|b| b.start == target)
                        && !blocks[i].successors.contains(&tb) {
                            blocks[i].successors.push(tb);
                        }
                }
        } else if i + 1 < blocks.len() {
            blocks[i].successors.push(i + 1);
        }
    }
    // Compute predecessors.
    let succs: Vec<Vec<usize>> = blocks.iter().map(|b| b.successors.clone()).collect();
    for (i, succ_list) in succs.iter().enumerate() {
        for &s in succ_list {
            blocks[s].predecessors.push(i);
        }
    }
    blocks
}

const fn is_branch(insn: &ParsedInstruction) -> bool {
    matches!(
        insn.opcode,
        DalvikOpcode::IfEq
            | DalvikOpcode::IfNe
            | DalvikOpcode::IfLt
            | DalvikOpcode::IfGe
            | DalvikOpcode::IfGt
            | DalvikOpcode::IfLe
            | DalvikOpcode::IfEqz
            | DalvikOpcode::IfNez
            | DalvikOpcode::IfLtz
            | DalvikOpcode::IfGez
            | DalvikOpcode::IfGtz
            | DalvikOpcode::IfLez
    )
}

const fn is_jump(insn: &ParsedInstruction) -> bool {
    matches!(insn.opcode, DalvikOpcode::Goto)
}

const fn is_return(insn: &ParsedInstruction) -> bool {
    matches!(
        insn.opcode,
        DalvikOpcode::ReturnVoid | DalvikOpcode::Return | DalvikOpcode::Throw
    )
}

fn is_nop(insn: &ParsedInstruction) -> bool {
    insn.opcode == DalvikOpcode::Nop
}

fn is_trivial_move(insn: &ParsedInstruction) -> bool {
    matches!(insn.opcode, DalvikOpcode::Move)
        && insn.registers.first() == insn.registers.get(1)
}

fn defines_register(insn: &ParsedInstruction) -> Option<u8> {
    match insn.opcode {
        DalvikOpcode::Move
        | DalvikOpcode::MoveResult
        | DalvikOpcode::Const4
        | DalvikOpcode::Const16
        | DalvikOpcode::Const
        | DalvikOpcode::ConstString
        | DalvikOpcode::ConstClass
        | DalvikOpcode::NewInstance
        | DalvikOpcode::NewArray
        | DalvikOpcode::Aget
        | DalvikOpcode::Iget
        | DalvikOpcode::Sget
        | DalvikOpcode::NegInt
        | DalvikOpcode::NotInt
        | DalvikOpcode::NegLong
        | DalvikOpcode::IntToLong
        | DalvikOpcode::IntToFloat
        | DalvikOpcode::IntToDouble
        | DalvikOpcode::LongToInt
        | DalvikOpcode::FloatToInt
        | DalvikOpcode::DoubleToInt
        | DalvikOpcode::IntToByte
        | DalvikOpcode::IntToChar
        | DalvikOpcode::IntToShort
        | DalvikOpcode::AddInt
        | DalvikOpcode::SubInt
        | DalvikOpcode::MulInt
        | DalvikOpcode::DivInt
        | DalvikOpcode::RemInt
        | DalvikOpcode::AndInt
        | DalvikOpcode::OrInt
        | DalvikOpcode::XorInt
        | DalvikOpcode::CheckCast
        | DalvikOpcode::InstanceOf
        | DalvikOpcode::ArrayLength => insn.registers.first().copied(),
        _ => None,
    }
}

fn uses_registers(insn: &ParsedInstruction) -> Vec<u8> {
    match insn.opcode {
        DalvikOpcode::Move => insn.registers.get(1).copied().into_iter().collect(),
        DalvikOpcode::Return
        | DalvikOpcode::Throw
        | DalvikOpcode::MonitorEnter
        | DalvikOpcode::MonitorExit
        | DalvikOpcode::CheckCast
        | DalvikOpcode::ConstClass
        | DalvikOpcode::NewArray
        | DalvikOpcode::ArrayLength
        | DalvikOpcode::Iget
        | DalvikOpcode::Iput
        | DalvikOpcode::Sput
        | DalvikOpcode::Sget => insn.registers.iter().skip(1).copied().collect(),
        DalvikOpcode::InvokeVirtual
        | DalvikOpcode::InvokeDirect
        | DalvikOpcode::InvokeStatic
        | DalvikOpcode::InvokeSuper
        | DalvikOpcode::InvokeInterface => insn.registers.clone(),
        DalvikOpcode::AddInt
        | DalvikOpcode::SubInt
        | DalvikOpcode::MulInt
        | DalvikOpcode::DivInt
        | DalvikOpcode::RemInt
        | DalvikOpcode::AndInt
        | DalvikOpcode::OrInt
        | DalvikOpcode::XorInt
        | DalvikOpcode::Aget => insn.registers.iter().skip(1).copied().collect(),
        DalvikOpcode::IfEq
        | DalvikOpcode::IfNe
        | DalvikOpcode::IfLt
        | DalvikOpcode::IfGe
        | DalvikOpcode::IfGt
        | DalvikOpcode::IfLe => insn.registers.clone(),
        DalvikOpcode::IfEqz
        | DalvikOpcode::IfNez
        | DalvikOpcode::IfLtz
        | DalvikOpcode::IfGez
        | DalvikOpcode::IfGtz
        | DalvikOpcode::IfLez => insn.registers.clone(),
        _ => Vec::new(),
    }
}

// ── Liveness ──────────────────────────────────────────────────────────────────

/// Compute live-in sets per instruction (backward liveness analysis).
#[must_use] 
pub fn liveness_analysis(
    instructions: &[ParsedInstruction],
    _blocks: &[BasicBlock],
) -> Vec<HashSet<u8>> {
    let n = instructions.len();
    if n == 0 {
        return Vec::new();
    }
    // live_in[i] = registers live immediately before instruction i
    let mut live_in: Vec<HashSet<u8>> = vec![HashSet::new(); n];
    let mut live_out: Vec<HashSet<u8>> = vec![HashSet::new(); n];
    let max_iter = n * 4 + 10;
    for _ in 0..max_iter {
        let mut changed = false;
        // Process instructions in reverse order.
        for i in (0..n).rev() {
            let new_live_out: HashSet<u8> = if i + 1 < n {
                live_in[i + 1].clone()
            } else {
                HashSet::new()
            };
            let insn = &instructions[i];
            let defs: HashSet<u8> = defines_register(insn).into_iter().collect();
            let uses: HashSet<u8> = uses_registers(insn).into_iter().collect();
            // live_in = uses ∪ (live_out - defs)
            let new_live_in: HashSet<u8> = uses
                .union(&new_live_out.difference(&defs).copied().collect())
                .copied()
                .collect();
            if new_live_in != live_in[i] || new_live_out != live_out[i] {
                changed = true;
            }
            live_in[i] = new_live_in;
            live_out[i] = new_live_out;
        }
        if !changed {
            break;
        }
    }
    live_in
}

/// Set of instruction indices that are live (reachable and have live output).
#[must_use] 
pub fn find_dead_instructions(
    instructions: &[ParsedInstruction],
    labels: &HashMap<String, ParsedLabel>,
) -> HashSet<usize> {
    // Reachability: BFS from instruction 0.
    let n = instructions.len();
    if n == 0 {
        return HashSet::new();
    }
    let mut reachable = vec![false; n];
    let mut queue: VecDeque<usize> = VecDeque::new();
    queue.push_back(0);
    while let Some(i) = queue.pop_front() {
        if reachable[i] {
            continue;
        }
        reachable[i] = true;
        let insn = &instructions[i];
        if is_return(insn) {
            continue;
        }
        if is_jump(insn) {
            if let Some(label) = &insn.label
                && let Some(lbl) = labels.get(label) {
                    let target = lbl.instruction_index;
                    if target < n {
                        queue.push_back(target);
                    }
                }
            continue;
        }
        if is_branch(insn) {
            if i + 1 < n {
                queue.push_back(i + 1);
            }
            if let Some(label) = &insn.label
                && let Some(lbl) = labels.get(label) {
                    let target = lbl.instruction_index;
                    if target < n {
                        queue.push_back(target);
                    }
                }
            continue;
        }
        if i + 1 < n {
            queue.push_back(i + 1);
        }
    }
    (0..n).filter(|&i| !reachable[i]).collect()
}

// ── Pass implementations ──────────────────────────────────────────────────────

/// Remove all NOP instructions that are not required for alignment.
pub fn remove_nops(
    instructions: &mut Vec<ParsedInstruction>,
    labels: &mut HashMap<String, ParsedLabel>,
    stats: &mut OptimizationStats,
) {
    let mut removed = 0usize;
    let mut index_map: Vec<Option<usize>> = Vec::with_capacity(instructions.len());
    let mut new_instructions: Vec<ParsedInstruction> = Vec::new();
    let mut new_idx = 0usize;
    for insn in instructions.iter() {
        if is_nop(insn) {
            index_map.push(None);
            removed += 1;
        } else {
            index_map.push(Some(new_idx));
            new_instructions.push(insn.clone());
            new_idx += 1;
        }
    }
    // Update label targets.
    for lbl in labels.values_mut() {
        let old = lbl.instruction_index;
        // Find new index: first non-None at or after old.
        let new = (old..index_map.len())
            .find_map(|i| index_map[i])
            .unwrap_or(new_instructions.len());
        lbl.instruction_index = new;
    }
    *instructions = new_instructions;
    stats.nops_removed += removed;
}

/// Remove trivial self-moves `move vX, vX`.
pub fn remove_trivial_moves(
    instructions: &mut Vec<ParsedInstruction>,
    labels: &mut HashMap<String, ParsedLabel>,
    stats: &mut OptimizationStats,
) {
    let mut removed_indices: HashSet<usize> = HashSet::new();
    for (i, insn) in instructions.iter().enumerate() {
        if is_trivial_move(insn) {
            removed_indices.insert(i);
        }
    }
    remove_instructions_by_indices(instructions, labels, &removed_indices);
    stats.trivial_moves_removed += removed_indices.len();
}

/// Remove unreachable instructions.
pub fn remove_dead_code(
    instructions: &mut Vec<ParsedInstruction>,
    labels: &mut HashMap<String, ParsedLabel>,
    stats: &mut OptimizationStats,
) {
    let dead = find_dead_instructions(instructions, labels);
    remove_instructions_by_indices(instructions, labels, &dead);
    stats.dead_instructions_removed += dead.len();
}

fn remove_instructions_by_indices(
    instructions: &mut Vec<ParsedInstruction>,
    labels: &mut HashMap<String, ParsedLabel>,
    remove: &HashSet<usize>,
) {
    if remove.is_empty() {
        return;
    }
    let mut index_map: Vec<Option<usize>> = Vec::with_capacity(instructions.len());
    let mut new_instructions = Vec::new();
    let mut new_idx = 0usize;
    for (i, insn) in instructions.iter().enumerate() {
        if remove.contains(&i) {
            index_map.push(None);
        } else {
            index_map.push(Some(new_idx));
            new_instructions.push(insn.clone());
            new_idx += 1;
        }
    }
    for lbl in labels.values_mut() {
        let old = lbl.instruction_index;
        let new = (old..index_map.len())
            .find_map(|i| index_map[i])
            .unwrap_or(new_instructions.len());
        lbl.instruction_index = new;
    }
    *instructions = new_instructions;
}

/// Propagate constants through register assignments.
/// Replaces `move vA, vB` where vB has a known const with `const vA, literal`.
pub fn constant_propagation(
    instructions: &mut [ParsedInstruction],
    stats: &mut OptimizationStats,
) -> usize {
    let n = instructions.len();
    if n == 0 {
        return 0;
    }
    let mut propagated = 0;
    let mut rf = RegisterFile::new();
    for insn in instructions.iter_mut() {
        match insn.opcode {
            DalvikOpcode::Const4 | DalvikOpcode::Const16 | DalvikOpcode::Const => {
                if let Some(&r) = insn.registers.first()
                    && let Some(lit) = insn.literal {
                        rf.set(r, ConstantValue::Const(lit));
                    }
            }
            DalvikOpcode::ConstString => {
                if let Some(&r) = insn.registers.first()
                    && let Some(s) = &insn.string_ref {
                        rf.set(r, ConstantValue::String(s.clone()));
                    }
            }
            DalvikOpcode::Move => {
                if insn.registers.len() >= 2 {
                    let src = insn.registers[1];
                    let dst = insn.registers[0];
                    match rf.get(src).clone() {
                        ConstantValue::Const(v) => {
                            // Replace move with const.
                            insn.opcode = DalvikOpcode::Const16;
                            insn.registers = vec![dst];
                            insn.literal = Some(v);
                            rf.set(dst, ConstantValue::Const(v));
                            propagated += 1;
                        }
                        ConstantValue::Null => {
                            insn.opcode = DalvikOpcode::Const4;
                            insn.registers = vec![dst];
                            insn.literal = Some(0);
                            rf.set(dst, ConstantValue::Null);
                            propagated += 1;
                        }
                        other => {
                            rf.set(dst, other);
                        }
                    }
                }
            }
            DalvikOpcode::IfEqz => {
                if let Some(&r) = insn.registers.first() {
                    if rf.get(r).clone() == ConstantValue::Const(0) {
                        // if-eqz v0, :label where v0==0 → unconditional goto.
                        insn.opcode = DalvikOpcode::Goto;
                        insn.registers = vec![];
                        propagated += 1;
                        stats.branches_simplified += 1;
                    } else if let ConstantValue::Const(v) = rf.get(r).clone()
                        && v != 0 {
                            // Branch never taken — replace with nop.
                            insn.opcode = DalvikOpcode::Nop;
                            insn.registers = vec![];
                            insn.label = None;
                            propagated += 1;
                            stats.branches_simplified += 1;
                        }
                }
            }
            DalvikOpcode::IfNez => {
                if let Some(&r) = insn.registers.first() {
                    if rf.get(r).clone() == ConstantValue::Const(0) {
                        // if-nez v0, :label where v0==0 → branch never taken → nop.
                        insn.opcode = DalvikOpcode::Nop;
                        insn.registers = vec![];
                        insn.label = None;
                        propagated += 1;
                        stats.branches_simplified += 1;
                    } else if let ConstantValue::Const(v) = rf.get(r).clone()
                        && v != 0 {
                            insn.opcode = DalvikOpcode::Goto;
                            insn.registers = vec![];
                            propagated += 1;
                            stats.branches_simplified += 1;
                        }
                }
            }
            // For instructions that write an output register, kill constant info.
            _ => {
                if let Some(def) = defines_register(insn) {
                    rf.kill(def);
                }
            }
        }
    }
    stats.constants_propagated += propagated;
    propagated
}

// ── SmaliOptimizer ────────────────────────────────────────────────────────────

/// Configuration for the optimizer.
#[derive(Debug, Clone)]
pub struct OptimizerConfig {
    pub remove_nops: bool,
    pub remove_trivial_moves: bool,
    pub remove_dead_code: bool,
    pub constant_propagation: bool,
    /// Number of passes to run.
    pub passes: usize,
}

impl Default for OptimizerConfig {
    fn default() -> Self {
        Self {
            remove_nops: true,
            remove_trivial_moves: true,
            remove_dead_code: true,
            constant_propagation: true,
            passes: 3,
        }
    }
}

impl OptimizerConfig {
    #[must_use] 
    pub const fn conservative() -> Self {
        Self {
            remove_nops: true,
            remove_trivial_moves: true,
            remove_dead_code: false,
            constant_propagation: false,
            passes: 1,
        }
    }

    #[must_use] 
    pub fn aggressive() -> Self {
        Self {
            passes: 6,
            ..Default::default()
        }
    }
}

/// The main optimizer struct.
pub struct SmaliOptimizer {
    config: OptimizerConfig,
}

impl SmaliOptimizer {
    #[must_use] 
    pub const fn new(config: OptimizerConfig) -> Self {
        Self { config }
    }

    #[must_use] 
    pub fn default() -> Self {
        Self::new(OptimizerConfig::default())
    }

    /// Optimize a single method.
    pub fn optimize_method(
        &self,
        method: &mut ParsedMethod,
    ) -> OptimizationStats {
        let mut stats = OptimizationStats::default();
        for _pass in 0..self.config.passes {
            let before = method.instructions.len();
            if self.config.constant_propagation {
                constant_propagation(&mut method.instructions, &mut stats);
            }
            if self.config.remove_nops {
                remove_nops(&mut method.instructions, &mut method.labels, &mut stats);
            }
            if self.config.remove_trivial_moves {
                remove_trivial_moves(&mut method.instructions, &mut method.labels, &mut stats);
            }
            if self.config.remove_dead_code {
                remove_dead_code(&mut method.instructions, &mut method.labels, &mut stats);
            }
            let after = method.instructions.len();
            if after == before {
                break; // Fixed point.
            }
        }
        stats.methods_optimized = 1;
        stats
    }

    /// Optimize all methods in a class.
    pub fn optimize_class(&self, class: &mut ParsedClass) -> OptimizationStats {
        let mut total = OptimizationStats::default();
        for method in &mut class.methods {
            let s = self.optimize_method(method);
            total.merge(&s);
        }
        total
    }
}

// ── MethodSizeEstimator ───────────────────────────────────────────────────────

/// Estimate encoded bytecode size from instruction list.
#[must_use] 
pub fn estimate_bytecode_size(instructions: &[ParsedInstruction]) -> usize {
    instructions.iter().map(instruction_size).sum()
}

const fn instruction_size(insn: &ParsedInstruction) -> usize {
    match insn.opcode {
        DalvikOpcode::Nop => 2,
        DalvikOpcode::Move => 2,
        DalvikOpcode::ReturnVoid | DalvikOpcode::Return | DalvikOpcode::Throw => 2,
        DalvikOpcode::Const4 => 2,
        DalvikOpcode::Const16 => 4,
        DalvikOpcode::Const => 6,
        DalvikOpcode::ConstString => 4,
        DalvikOpcode::NewInstance | DalvikOpcode::CheckCast | DalvikOpcode::ConstClass => 4,
        DalvikOpcode::Goto => 2,
        DalvikOpcode::IfEq
        | DalvikOpcode::IfNe
        | DalvikOpcode::IfLt
        | DalvikOpcode::IfGe
        | DalvikOpcode::IfGt
        | DalvikOpcode::IfLe
        | DalvikOpcode::IfEqz
        | DalvikOpcode::IfNez
        | DalvikOpcode::IfLtz
        | DalvikOpcode::IfGez
        | DalvikOpcode::IfGtz
        | DalvikOpcode::IfLez => 4,
        DalvikOpcode::InvokeVirtual
        | DalvikOpcode::InvokeDirect
        | DalvikOpcode::InvokeStatic
        | DalvikOpcode::InvokeSuper
        | DalvikOpcode::InvokeInterface => 6,
        DalvikOpcode::Iget | DalvikOpcode::Iput | DalvikOpcode::Sget | DalvikOpcode::Sput => 4,
        DalvikOpcode::MoveResult => 2,
        DalvikOpcode::NegInt
        | DalvikOpcode::NotInt
        | DalvikOpcode::NegLong
        | DalvikOpcode::ArrayLength => 2,
        DalvikOpcode::IntToLong
        | DalvikOpcode::IntToFloat
        | DalvikOpcode::IntToDouble
        | DalvikOpcode::LongToInt
        | DalvikOpcode::FloatToInt
        | DalvikOpcode::DoubleToInt
        | DalvikOpcode::IntToByte
        | DalvikOpcode::IntToChar
        | DalvikOpcode::IntToShort => 2,
        DalvikOpcode::AddInt
        | DalvikOpcode::SubInt
        | DalvikOpcode::MulInt
        | DalvikOpcode::DivInt
        | DalvikOpcode::RemInt
        | DalvikOpcode::AndInt
        | DalvikOpcode::OrInt
        | DalvikOpcode::XorInt => 4,
        DalvikOpcode::Aget | DalvikOpcode::Aput => 4,
        DalvikOpcode::NewArray | DalvikOpcode::InstanceOf => 4,
        DalvikOpcode::MonitorEnter | DalvikOpcode::MonitorExit => 2,
        _ => 2,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smali_parser::parse_smali;

    fn make_nop_method() -> ParsedMethod {
        let insns = vec![
            ParsedInstruction::new(DalvikOpcode::Nop, 1),
            ParsedInstruction::new(DalvikOpcode::Nop, 2),
            ParsedInstruction::new(DalvikOpcode::ReturnVoid, 3),
        ];
        ParsedMethod {
            name: "test".into(),
            access_flags: vec!["public".into()],
            descriptor: "test()V".into(),
            instructions: insns,
            labels: HashMap::new(),
            try_catch: Vec::new(),
            registers_directive: Some(1),
            locals_directive: None,
            line: 1,
        }
    }

    #[test]
    fn test_remove_nops() {
        let mut method = make_nop_method();
        let mut stats = OptimizationStats::default();
        remove_nops(
            &mut method.instructions,
            &mut method.labels,
            &mut stats,
        );
        assert_eq!(stats.nops_removed, 2);
        assert_eq!(method.instructions.len(), 1);
    }

    #[test]
    fn test_remove_trivial_moves() {
        let mut insn = ParsedInstruction::new(DalvikOpcode::Move, 1);
        insn.registers = vec![5, 5];
        let insns = vec![insn, ParsedInstruction::new(DalvikOpcode::ReturnVoid, 2)];
        let mut method = ParsedMethod {
            name: "t".into(),
            access_flags: vec![],
            descriptor: "()V".into(),
            instructions: insns,
            labels: HashMap::new(),
            try_catch: Vec::new(),
            registers_directive: None,
            locals_directive: None,
            line: 1,
        };
        let mut stats = OptimizationStats::default();
        remove_trivial_moves(&mut method.instructions, &mut method.labels, &mut stats);
        assert_eq!(stats.trivial_moves_removed, 1);
    }

    #[test]
    fn test_constant_propagation() {
        let mut insn_const = ParsedInstruction::new(DalvikOpcode::Const4, 1);
        insn_const.registers = vec![0];
        insn_const.literal = Some(42);
        let mut insn_move = ParsedInstruction::new(DalvikOpcode::Move, 2);
        insn_move.registers = vec![1, 0];
        let ret = ParsedInstruction::new(DalvikOpcode::ReturnVoid, 3);
        let mut insns = vec![insn_const, insn_move, ret];
        let mut stats = OptimizationStats::default();
        let changed = constant_propagation(&mut insns, &mut stats);
        assert!(changed > 0);
        assert!(matches!(insns[1].opcode, DalvikOpcode::Const16));
    }

    #[test]
    fn test_optimizer_full_pass() {
        let src = r"
.class public Lopt/Test;
.super Ljava/lang/Object;
.method public run()V
    .registers 3
    nop
    nop
    move v0, v0
    return-void
.end method
";
        let mut class = parse_smali(src).unwrap();
        let opt = SmaliOptimizer::default();
        let stats = opt.optimize_class(&mut class);
        assert!(stats.nops_removed >= 2);
        assert!(stats.trivial_moves_removed >= 1);
    }

    #[test]
    fn test_dead_code_removal() {
        let goto = {
            let mut i = ParsedInstruction::new(DalvikOpcode::Goto, 1);
            i.label = Some("end".into());
            i
        };
        let dead_nop = ParsedInstruction::new(DalvikOpcode::Nop, 2);
        let dead_ret = ParsedInstruction::new(DalvikOpcode::ReturnVoid, 3);
        let real_ret = ParsedInstruction::new(DalvikOpcode::ReturnVoid, 4);
        let mut labels = HashMap::new();
        labels.insert(
            "end".to_string(),
            ParsedLabel {
                name: "end".into(),
                instruction_index: 3,
                line: 4,
            },
        );
        let mut insns = vec![goto, dead_nop, dead_ret, real_ret];
        let mut stats = OptimizationStats::default();
        remove_dead_code(&mut insns, &mut labels, &mut stats);
        assert!(stats.dead_instructions_removed >= 1);
    }

    #[test]
    fn test_liveness_analysis() {
        let mut insn_const = ParsedInstruction::new(DalvikOpcode::Const4, 1);
        insn_const.registers = vec![0];
        insn_const.literal = Some(0);
        let mut insn_return = ParsedInstruction::new(DalvikOpcode::Return, 2);
        insn_return.registers = vec![0];
        let insns = vec![insn_const, insn_return];
        let blocks = build_cfg(&insns, &HashMap::new());
        let live = liveness_analysis(&insns, &blocks);
        assert!(!live.is_empty());
    }

    #[test]
    fn test_liveness_rmw_accumulator_self_use_not_killed_by_own_def() {
        // v0 = v0 + v1  (accumulator / induction variable).
        // The statement's own USE of v0 must survive its own DEF of v0.
        // Buggy order (live_out U use) - def would drop v0 from live_in,
        // making the earlier defining const-4 look dead.
        let mut c0 = ParsedInstruction::new(DalvikOpcode::Const4, 1);
        c0.registers = vec![0];
        c0.literal = Some(0);
        let mut c1 = ParsedInstruction::new(DalvikOpcode::Const4, 2);
        c1.registers = vec![1];
        c1.literal = Some(1);
        let mut add = ParsedInstruction::new(DalvikOpcode::AddInt, 3);
        add.registers = vec![0, 0, 1];
        let mut ret = ParsedInstruction::new(DalvikOpcode::Return, 4);
        ret.registers = vec![0];

        let insns = vec![c0, c1, add, ret];
        let blocks = build_cfg(&insns, &HashMap::new());
        let live = liveness_analysis(&insns, &blocks);

        // live_in of the add must contain v0 (its own use) and v1.
        assert!(live[2].contains(&0), "v0 must be live-in at its own read-modify-write");
        assert!(live[2].contains(&1), "v1 must be live-in at the add");
        // therefore v0 is live across the whole accumulator chain
        assert!(live[1].contains(&0), "v0 from const-4 must stay live to the add");
    }

    #[test]
    fn test_estimate_bytecode_size() {
        let insns = vec![
            ParsedInstruction::new(DalvikOpcode::Nop, 1),
            ParsedInstruction::new(DalvikOpcode::ReturnVoid, 2),
        ];
        let size = estimate_bytecode_size(&insns);
        assert_eq!(size, 4);
    }
}
