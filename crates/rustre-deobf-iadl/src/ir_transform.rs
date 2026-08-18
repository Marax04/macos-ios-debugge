use std::collections::HashMap;
use serde::{Serialize, Deserialize};

// ── IR representation for deobfuscation ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IrValue {
    Const(u64),
    Var(VarId),
    Undef,
}

pub type VarId = u32;
pub type BlockId = u32;
pub type InsnId = u32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrInsn {
    pub id: InsnId,
    pub block: BlockId,
    pub op: IrOp,
    pub dst: Option<VarId>,
    pub src: Vec<IrValue>,
    pub flags: InsnFlags,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InsnFlags {
    pub is_dead: bool,
    pub is_canonical: bool,
    pub was_obfuscated: bool,
    pub deobf_note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IrOp {
    Nop,
    Move,
    // Arithmetic
    Add, Sub, Mul, UDiv, SDiv, URem, SRem,
    // Bitwise
    And, Or, Xor, Not, Shl, Lshr, Ashr,
    // Comparison
    CmpEq, CmpNe, CmpUlt, CmpUle, CmpSlt, CmpSle, CmpUgt, CmpSgt,
    // Boolean
    BoolAnd, BoolOr, BoolNot,
    // Memory
    Load { size: u8 }, Store { size: u8 },
    // Conversion
    ZExt { to_bits: u8 }, SExt { to_bits: u8 }, Trunc { to_bits: u8 },
    // Control flow
    Branch, CondBranch, Call { callee: String }, Ret,
    // PHI
    Phi,
    // Special deobf pseudo-ops
    Select, // ternary: dst = cond ? a : b
    Rotate { left: bool },
    ByteSwap,
    PopCount,
    BitScanForward,
    BitScanReverse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrBlock {
    pub id: BlockId,
    pub insns: Vec<InsnId>,
    pub predecessors: Vec<BlockId>,
    pub successors: Vec<BlockId>,
    pub dominates: Vec<BlockId>,
    pub dominated_by: Option<BlockId>,
    pub loop_depth: u32,
    pub phi_nodes: Vec<InsnId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrFunction {
    pub name: String,
    pub entry: BlockId,
    pub blocks: HashMap<BlockId, IrBlock>,
    pub insns: HashMap<InsnId, IrInsn>,
    pub var_types: HashMap<VarId, VarType>,
    pub use_def: HashMap<VarId, InsnId>,  // var -> defining insn
    pub def_use: HashMap<VarId, Vec<InsnId>>,  // var -> using insns
    pub block_order: Vec<BlockId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VarType { Int8, Int16, Int32, Int64, Float32, Float64, Ptr64, Bool, Unknown }

// ── Deobfuscation transforms ──────────────────────────────────────────────────

pub struct DeobfuscationPipeline {
    passes: Vec<Box<dyn TransformPass>>,
    stats: PipelineStats,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PipelineStats {
    pub passes_run: usize,
    pub insns_eliminated: usize,
    pub insns_simplified: usize,
    pub blocks_merged: usize,
    pub constants_propagated: usize,
    pub phis_simplified: usize,
}

pub trait TransformPass: Send {
    fn name(&self) -> &str;
    fn run(&self, func: &mut IrFunction, stats: &mut PipelineStats) -> bool;
    fn is_idempotent(&self) -> bool { false }
}

impl DeobfuscationPipeline {
    #[must_use]
    pub fn new() -> Self {
        Self { passes: Vec::new(), stats: PipelineStats::default() }
    }

    #[must_use]
    pub fn add_pass(mut self, pass: Box<dyn TransformPass>) -> Self {
        self.passes.push(pass);
        self
    }

    #[must_use]
    pub fn standard() -> Self {
        Self::new()
            .add_pass(Box::new(ConstantFoldingPass))
            .add_pass(Box::new(DeadCodeElimination))
            .add_pass(Box::new(CopyPropagation))
            .add_pass(Box::new(CommonSubexpressionElim))
            .add_pass(Box::new(BooleanSimplification))
            .add_pass(Box::new(XorChainSimplifier))
            .add_pass(Box::new(MbaSimplifier))
            .add_pass(Box::new(OpaquePredicateElim))
            .add_pass(Box::new(BlockMerging))
            .add_pass(Box::new(PhiElimination))
    }

    pub fn run_all(&mut self, func: &mut IrFunction) -> PipelineStats {
        let max_rounds = 10;
        for _round in 0..max_rounds {
            let mut changed = false;
            for pass in &self.passes {
                if pass.run(func, &mut self.stats) {
                    changed = true;
                }
                self.stats.passes_run += 1;
            }
            if !changed { break; }
        }
        self.stats.clone()
    }
}

impl Default for DeobfuscationPipeline {
    fn default() -> Self { Self::new() }
}

// ── Individual passes ─────────────────────────────────────────────────────────

pub struct ConstantFoldingPass;
impl TransformPass for ConstantFoldingPass {
    fn name(&self) -> &str { "constant-folding" }
    fn is_idempotent(&self) -> bool { false }

    fn run(&self, func: &mut IrFunction, stats: &mut PipelineStats) -> bool {
        let mut changed = false;
        let ids: Vec<InsnId> = func.insns.keys().copied().collect();
        for id in ids {
            if let Some(insn) = func.insns.get(&id).cloned() {
                if let Some(folded) = fold_constant(&insn) {
                    if let Some(dst) = insn.dst {
                        // Replace all uses of dst with constant
                        let uses: Vec<InsnId> = func.def_use.get(&dst).cloned().unwrap_or_default();
                        for use_id in uses {
                            if let Some(use_insn) = func.insns.get_mut(&use_id) {
                                for src in &mut use_insn.src {
                                    if *src == IrValue::Var(dst) {
                                        *src = IrValue::Const(folded);
                                        changed = true;
                                        stats.constants_propagated += 1;
                                    }
                                }
                            }
                        }
                        // Mark original insn as dead if no non-trivial side effects
                        if let Some(orig) = func.insns.get_mut(&id) {
                            orig.flags.is_dead = true;
                            stats.insns_simplified += 1;
                        }
                    }
                }
            }
        }
        changed
    }
}

fn fold_constant(insn: &IrInsn) -> Option<u64> {
    if insn.src.len() < 1 { return None; }
    match &insn.op {
        IrOp::Move => {
            if let IrValue::Const(c) = insn.src[0] { return Some(c); }
        }
        IrOp::Add => {
            if let (IrValue::Const(a), IrValue::Const(b)) = (&insn.src.get(0)?, &insn.src.get(1)?) {
                return Some(a.wrapping_add(*b));
            }
        }
        IrOp::Sub => {
            if let (IrValue::Const(a), IrValue::Const(b)) = (&insn.src.get(0)?, &insn.src.get(1)?) {
                return Some(a.wrapping_sub(*b));
            }
        }
        IrOp::Mul => {
            if let (IrValue::Const(a), IrValue::Const(b)) = (&insn.src.get(0)?, &insn.src.get(1)?) {
                return Some(a.wrapping_mul(*b));
            }
        }
        IrOp::And => {
            if let (IrValue::Const(a), IrValue::Const(b)) = (&insn.src.get(0)?, &insn.src.get(1)?) {
                return Some(a & b);
            }
            // x & 0 = 0
            if insn.src.iter().any(|s| *s == IrValue::Const(0)) { return Some(0); }
        }
        IrOp::Or => {
            if let (IrValue::Const(a), IrValue::Const(b)) = (&insn.src.get(0)?, &insn.src.get(1)?) {
                return Some(a | b);
            }
            // x | 0 = x — not a constant unless other arg is const
        }
        IrOp::Xor => {
            if let (IrValue::Const(a), IrValue::Const(b)) = (&insn.src.get(0)?, &insn.src.get(1)?) {
                return Some(a ^ b);
            }
            // x ^ x = 0
            if insn.src.len() == 2 && insn.src[0] == insn.src[1] { return Some(0); }
        }
        IrOp::Not => {
            if let IrValue::Const(a) = insn.src[0] { return Some(!a); }
        }
        IrOp::Shl => {
            if let (IrValue::Const(a), IrValue::Const(b)) = (&insn.src.get(0)?, &insn.src.get(1)?) {
                return Some(a.wrapping_shl(*b as u32));
            }
            if insn.src.get(1) == Some(&IrValue::Const(0)) {
                if let IrValue::Const(a) = insn.src[0] { return Some(a); }
            }
        }
        IrOp::Lshr => {
            if let (IrValue::Const(a), IrValue::Const(b)) = (&insn.src.get(0)?, &insn.src.get(1)?) {
                return Some(a.wrapping_shr(*b as u32));
            }
        }
        IrOp::ZExt { .. } => {
            if let IrValue::Const(c) = insn.src[0] { return Some(c); }
        }
        IrOp::CmpEq => {
            if let (IrValue::Const(a), IrValue::Const(b)) = (&insn.src.get(0)?, &insn.src.get(1)?) {
                return Some(if a == b { 1 } else { 0 });
            }
        }
        IrOp::CmpNe => {
            if let (IrValue::Const(a), IrValue::Const(b)) = (&insn.src.get(0)?, &insn.src.get(1)?) {
                return Some(if a != b { 1 } else { 0 });
            }
        }
        _ => {}
    }
    None
}

pub struct DeadCodeElimination;
impl TransformPass for DeadCodeElimination {
    fn name(&self) -> &str { "dce" }
    fn run(&self, func: &mut IrFunction, stats: &mut PipelineStats) -> bool {
        let mut changed = false;
        // Mark dead: any insn with a dst not used anywhere, unless it has side effects
        let ids: Vec<InsnId> = func.insns.keys().copied().collect();
        for id in ids {
            if let Some(insn) = func.insns.get(&id) {
                if insn.flags.is_dead { continue; }
                if let Some(dst) = insn.dst {
                    let uses = func.def_use.get(&dst).map(|u| u.len()).unwrap_or(0);
                    if uses == 0 && !has_side_effects(&insn.op) {
                        if let Some(insn_mut) = func.insns.get_mut(&id) {
                            insn_mut.flags.is_dead = true;
                            stats.insns_eliminated += 1;
                            changed = true;
                        }
                    }
                }
            }
        }
        changed
    }
}

const fn has_side_effects(op: &IrOp) -> bool {
    matches!(op, IrOp::Store { .. } | IrOp::Call { .. } | IrOp::Ret
        | IrOp::Branch | IrOp::CondBranch)
}

pub struct CopyPropagation;
impl TransformPass for CopyPropagation {
    fn name(&self) -> &str { "copy-prop" }
    fn run(&self, func: &mut IrFunction, stats: &mut PipelineStats) -> bool {
        let mut changed = false;
        let mut copy_map: HashMap<VarId, IrValue> = HashMap::new();

        // Collect all copy assignments: dst = MOVE src_var
        for insn in func.insns.values() {
            if insn.op == IrOp::Move {
                if let Some(dst) = insn.dst {
                    if let Some(src) = insn.src.first() {
                        copy_map.insert(dst, src.clone());
                    }
                }
            }
        }

        // Propagate: replace Var(x) with its copy source if x is in copy_map
        let ids: Vec<InsnId> = func.insns.keys().copied().collect();
        for id in ids {
            if let Some(insn) = func.insns.get_mut(&id) {
                for src in &mut insn.src {
                    if let IrValue::Var(v) = *src {
                        if let Some(replacement) = copy_map.get(&v) {
                            *src = replacement.clone();
                            changed = true;
                            stats.constants_propagated += 1;
                        }
                    }
                }
            }
        }
        changed
    }
}

pub struct CommonSubexpressionElim;
impl TransformPass for CommonSubexpressionElim {
    fn name(&self) -> &str { "cse" }
    fn run(&self, func: &mut IrFunction, stats: &mut PipelineStats) -> bool {
        let mut changed = false;
        let mut expr_map: HashMap<(IrOp, Vec<IrValue>), VarId> = HashMap::new();

        let ids: Vec<InsnId> = func.insns.keys().copied().collect();
        for id in ids {
            let (op, src, dst) = {
                let insn = match func.insns.get(&id) { Some(i) => i, None => continue };
                if insn.flags.is_dead { continue; }
                (insn.op.clone(), insn.src.clone(), insn.dst)
            };

            if has_side_effects(&op) { continue; }
            if let Some(dst_var) = dst {
                let key = (op.clone(), src.clone());
                if let Some(&existing_var) = expr_map.get(&key) {
                    // Replace dst with existing_var in all uses
                    let uses: Vec<InsnId> = func.def_use.get(&dst_var).cloned().unwrap_or_default();
                    for use_id in uses {
                        if let Some(use_insn) = func.insns.get_mut(&use_id) {
                            for s in &mut use_insn.src {
                                if *s == IrValue::Var(dst_var) {
                                    *s = IrValue::Var(existing_var);
                                    changed = true;
                                    stats.insns_simplified += 1;
                                }
                            }
                        }
                    }
                    if let Some(insn) = func.insns.get_mut(&id) {
                        insn.flags.is_dead = true;
                    }
                } else {
                    expr_map.insert(key, dst_var);
                }
            }
        }
        changed
    }
}

pub struct BooleanSimplification;
impl TransformPass for BooleanSimplification {
    fn name(&self) -> &str { "bool-simp" }
    fn run(&self, func: &mut IrFunction, stats: &mut PipelineStats) -> bool {
        let mut changed = false;
        let ids: Vec<InsnId> = func.insns.keys().copied().collect();
        for id in ids {
            let (op, src) = {
                let insn = match func.insns.get(&id) { Some(i) => i, None => continue };
                (insn.op.clone(), insn.src.clone())
            };
            let simplified = match &op {
                // not not x = x
                IrOp::Not => {
                    if let IrValue::Var(v) = &src[0] {
                        if let Some(def) = func.use_def.get(v) {
                            if let Some(def_insn) = func.insns.get(def) {
                                if def_insn.op == IrOp::Not {
                                    def_insn.src.first().cloned()
                                } else { None }
                            } else { None }
                        } else { None }
                    } else { None }
                }
                // x & x = x
                IrOp::And if src.len() == 2 && src[0] == src[1] => Some(src[0].clone()),
                // x | x = x
                IrOp::Or if src.len() == 2 && src[0] == src[1] => Some(src[0].clone()),
                // x ^ x = 0
                IrOp::Xor if src.len() == 2 && src[0] == src[1] => Some(IrValue::Const(0)),
                // x & ~x = 0
                IrOp::And if src.len() == 2 => {
                    let is_not_pair = |a: &IrValue, b: &IrValue| -> bool {
                        if let (IrValue::Var(va), IrValue::Var(vb)) = (a, b) {
                            if let Some(def_b) = func.use_def.get(vb) {
                                if let Some(def_insn) = func.insns.get(def_b) {
                                    if def_insn.op == IrOp::Not {
                                        if def_insn.src.first() == Some(&IrValue::Var(*va)) {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                        false
                    };
                    if is_not_pair(&src[0], &src[1]) || is_not_pair(&src[1], &src[0]) {
                        Some(IrValue::Const(0))
                    } else { None }
                }
                _ => None,
            };

            if let Some(new_val) = simplified {
                if let Some(insn) = func.insns.get_mut(&id) {
                    insn.op = IrOp::Move;
                    insn.src = vec![new_val];
                    insn.flags.was_obfuscated = true;
                    insn.flags.deobf_note = Some(format!("simplified {op:?}"));
                    changed = true;
                    stats.insns_simplified += 1;
                }
            }
        }
        changed
    }
}

pub struct XorChainSimplifier;
impl TransformPass for XorChainSimplifier {
    fn name(&self) -> &str { "xor-chain" }
    fn run(&self, func: &mut IrFunction, stats: &mut PipelineStats) -> bool {
        // Detect: v1 = x ^ k1; v2 = v1 ^ k2; ... -> vN = x ^ (k1^k2^...^kN)
        let mut changed = false;
        let mut xor_chains: HashMap<VarId, (VarId, u64)> = HashMap::new(); // var -> (base_var, accumulated_const)

        for insn in func.insns.values() {
            if insn.op != IrOp::Xor { continue; }
            if let Some(dst) = insn.dst {
                match (&insn.src.get(0), &insn.src.get(1)) {
                    (Some(IrValue::Var(v)), Some(IrValue::Const(c))) |
                    (Some(IrValue::Const(c)), Some(IrValue::Var(v))) => {
                        if let Some(&(base, prev_c)) = xor_chains.get(v) {
                            xor_chains.insert(dst, (base, prev_c ^ c));
                        } else {
                            xor_chains.insert(dst, (*v, *c));
                        }
                    }
                    _ => {}
                }
            }
        }

        // Replace: if chain found, simplify to single XOR with accumulated constant
        for (var, (base, acc_const)) in &xor_chains {
            if let Some(&def_id) = func.use_def.get(var) {
                if let Some(insn) = func.insns.get_mut(&def_id) {
                    if insn.op == IrOp::Xor {
                        insn.src = vec![IrValue::Var(*base), IrValue::Const(*acc_const)];
                        insn.flags.was_obfuscated = true;
                        insn.flags.deobf_note = Some(format!("XOR chain collapsed, const={acc_const:#x}"));
                        changed = true;
                        stats.insns_simplified += 1;
                    }
                }
            }
        }
        changed
    }
}

pub struct MbaSimplifier;
impl TransformPass for MbaSimplifier {
    fn name(&self) -> &str { "mba-simplifier" }
    fn run(&self, func: &mut IrFunction, stats: &mut PipelineStats) -> bool {
        // Detect and simplify Mixed Boolean Arithmetic expressions
        // e.g.: (a & b) + (a | b) = a + b
        //       (a & ~b) + (~a & b) = a ^ b
        //       (a ^ b) + 2*(a & b) = a + b
        let mut changed = false;
        // Simplified: just look for constant MBA patterns on two variables
        let ids: Vec<InsnId> = func.insns.keys().copied().collect();
        for id in ids {
            let (op, src) = {
                let insn = match func.insns.get(&id) { Some(i) => i, None => continue };
                (insn.op.clone(), insn.src.clone())
            };
            // Pattern: x XOR y where x and y have known MBA expansions
            // For now, detect (x | y) - (x & y) = x ^ y
            if let IrOp::Sub = &op {
                // check if src[0] is (a | b) and src[1] is (a & b)
                let result = try_resolve_mba_sub(func, &src);
                if let Some((new_op, new_srcs)) = result {
                    if let Some(insn) = func.insns.get_mut(&id) {
                        insn.op = new_op;
                        insn.src = new_srcs;
                        insn.flags.was_obfuscated = true;
                        insn.flags.deobf_note = Some("MBA simplification".to_string());
                        changed = true;
                        stats.insns_simplified += 1;
                    }
                }
            }
        }
        changed
    }
}

fn try_resolve_mba_sub(func: &IrFunction, src: &[IrValue]) -> Option<(IrOp, Vec<IrValue>)> {
    let (s0, s1) = (src.get(0)?, src.get(1)?);
    let (v0, v1) = match (s0, s1) {
        (IrValue::Var(a), IrValue::Var(b)) => (*a, *b),
        _ => return None,
    };
    let insn0 = func.insns.get(func.use_def.get(&v0)?)?;
    let insn1 = func.insns.get(func.use_def.get(&v1)?)?;
    // (a | b) - (a & b) = a ^ b
    if insn0.op == IrOp::Or && insn1.op == IrOp::And {
        if insn0.src.len() == 2 && insn1.src.len() == 2 {
            if (insn0.src[0] == insn1.src[0] && insn0.src[1] == insn1.src[1]) ||
               (insn0.src[0] == insn1.src[1] && insn0.src[1] == insn1.src[0]) {
                return Some((IrOp::Xor, insn0.src.clone()));
            }
        }
    }
    None
}

pub struct OpaquePredicateElim;
impl TransformPass for OpaquePredicateElim {
    fn name(&self) -> &str { "opaque-pred" }
    fn run(&self, func: &mut IrFunction, stats: &mut PipelineStats) -> bool {
        let mut changed = false;
        // Look for comparisons that always evaluate to the same value
        // e.g.: x & 1 == 0 or x & 1 == 1 where x is always 0 or always non-zero
        // For now, detect: x ^ x (always 0), ~(x ^ ~x) (always 0), (x & ~x) (always 0)
        let ids: Vec<InsnId> = func.insns.keys().copied().collect();
        for id in ids {
            if let Some(insn) = func.insns.get(&id) {
                if !matches!(insn.op, IrOp::CmpEq | IrOp::CmpNe | IrOp::CondBranch) { continue; }
                // Check if condition is always-true or always-false
                if let Some(const_val) = evaluate_opaque(func, insn) {
                    let note = format!("opaque predicate folded to {const_val}");
                    if let Some(i) = func.insns.get_mut(&id) {
                        i.op = IrOp::Move;
                        i.src = vec![IrValue::Const(const_val)];
                        i.flags.was_obfuscated = true;
                        i.flags.deobf_note = Some(note);
                        changed = true;
                        stats.insns_simplified += 1;
                    }
                }
            }
        }
        changed
    }
}

fn evaluate_opaque(func: &IrFunction, insn: &IrInsn) -> Option<u64> {
    // Only handle trivial cases: comparison of a known-zero expression with 0
    if insn.src.len() < 2 { return None; }
    match (&insn.op, &insn.src[1]) {
        (IrOp::CmpEq, IrValue::Const(0)) => {
            // Is src[0] always 0? Check for x^x or x&~x
            if let IrValue::Var(v) = &insn.src[0] {
                if let Some(&def_id) = func.use_def.get(v) {
                    if let Some(def) = func.insns.get(&def_id) {
                        if def.op == IrOp::Xor && def.src.len() == 2 && def.src[0] == def.src[1] {
                            return Some(1); // x^x == 0 is always true
                        }
                    }
                }
            }
        }
        _ => {}
    }
    None
}

pub struct BlockMerging;
impl TransformPass for BlockMerging {
    fn name(&self) -> &str { "block-merge" }
    fn run(&self, func: &mut IrFunction, stats: &mut PipelineStats) -> bool {
        let mut changed = false;
        // Merge block A -> block B where A has one successor (B) and B has one predecessor (A)
        let block_ids: Vec<BlockId> = func.blocks.keys().copied().collect();
        for bid in block_ids {
            let (single_succ, succ_id) = {
                let block = match func.blocks.get(&bid) { Some(b) => b, None => continue };
                if block.successors.len() != 1 { continue; }
                (true, block.successors[0])
            };
            if !single_succ { continue; }
            if bid == succ_id { continue; }
            let single_pred = func.blocks.get(&succ_id)
                .map(|b| b.predecessors.len() == 1 && b.predecessors[0] == bid)
                .unwrap_or(false);
            if !single_pred { continue; }

            // Merge succ into bid
            let succ_insns = func.blocks.get(&succ_id).map(|b| b.insns.clone()).unwrap_or_default();
            let succ_succs = func.blocks.get(&succ_id).map(|b| b.successors.clone()).unwrap_or_default();
            if let Some(block) = func.blocks.get_mut(&bid) {
                block.insns.extend(succ_insns);
                block.successors = succ_succs;
            }
            func.blocks.remove(&succ_id);
            stats.blocks_merged += 1;
            changed = true;
        }
        changed
    }
}

pub struct PhiElimination;
impl TransformPass for PhiElimination {
    fn name(&self) -> &str { "phi-elim" }
    fn run(&self, func: &mut IrFunction, stats: &mut PipelineStats) -> bool {
        let mut changed = false;
        // If a PHI has all identical args -> replace with simple move
        let ids: Vec<InsnId> = func.insns.keys().copied().collect();
        for id in ids {
            let (_op, src, _dst) = {
                let insn = match func.insns.get(&id) { Some(i) => i, None => continue };
                if insn.op != IrOp::Phi { continue; }
                (insn.op.clone(), insn.src.clone(), insn.dst)
            };
            if src.is_empty() { continue; }
            let first = &src[0];
            if src.iter().all(|s| s == first) {
                if let Some(insn) = func.insns.get_mut(&id) {
                    insn.op = IrOp::Move;
                    insn.src = vec![first.clone()];
                    changed = true;
                    stats.phis_simplified += 1;
                }
            }
        }
        changed
    }
}
