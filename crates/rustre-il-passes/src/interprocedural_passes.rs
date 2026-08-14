//! Interprocedural passes — inlining, devirtualization, dead function elimination,
//! and cross-call constant propagation.
//!
//! # Passes
//! * [`InliningPass`] — inline callees below the size/frequency threshold.
//! * [`DevirtualizationPass`] — replace indirect vtable calls with direct calls.
//! * [`DeadFunctionEliminationPass`] — remove functions unreachable from roots.
//! * [`CrossCallConstantPropPass`] — propagate constant arguments into callees.

use std::collections::{HashMap, HashSet, VecDeque};

use rustre_il_llil::{LlilAnnotatedInstr, LlilExpr, LlilFunction, LlilInstruction,
                     LlilRegister, Size};

use crate::{AnalysisPass, PassContext};

// ─────────────────────────────────────────────────────────────────────────────
// CallGraph
// ─────────────────────────────────────────────────────────────────────────────

/// An edge in the call graph.
#[derive(Debug, Clone)]
pub struct CallEdge {
    /// Address of the call instruction.
    pub call_site: u64,
    /// Address of the callee (direct call) or `None` for indirect.
    pub callee_addr: Option<u64>,
    /// Whether the call is indirect (via register or computed target).
    pub is_indirect: bool,
    /// Constant arguments passed at the call site, indexed by position.
    pub const_args: HashMap<usize, u64>,
}

/// Call graph over a set of functions.
#[derive(Debug, Clone, Default)]
pub struct CallGraph {
    /// Map from caller address → list of outgoing call edges.
    pub edges: HashMap<u64, Vec<CallEdge>>,
    /// Map from callee address → set of caller addresses.
    pub callers: HashMap<u64, HashSet<u64>>,
    /// All known function addresses.
    pub functions: HashSet<u64>,
}

impl CallGraph {
    /// Build the call graph from a slice of functions.
    #[must_use] 
    pub fn build(funcs: &[LlilFunction]) -> Self {
        let mut cg = Self::default();
        for func in funcs {
            cg.functions.insert(func.address.0);
        }

        for func in funcs {
            let caller_addr = func.address.0;
            let mut edges = Vec::new();

            for block in &func.blocks {
                for ai in &block.instrs {
                    let target_expr = match &ai.instr {
                        // Tuple-form call: Call(target_expr)
                        LlilInstruction::Call(t) => Some(t),
                        LlilInstruction::CallDest { dest } | LlilInstruction::TailCall { dest } => Some(dest),
                        _ => None,
                    };
                    if let Some(target) = target_expr {
                        let (target_addr, is_indirect) = match target {
                            LlilExpr::Const { value, .. } => (Some(*value), false),
                            _ => (None, true),
                        };
                        let edge = CallEdge {
                            call_site: ai.address.0,
                            callee_addr: target_addr,
                            is_indirect,
                            const_args: HashMap::new(),
                        };
                        if let Some(ca) = target_addr {
                            cg.callers.entry(ca).or_default().insert(caller_addr);
                        }
                        edges.push(edge);
                    }
                }
            }

            if !edges.is_empty() {
                cg.edges.insert(caller_addr, edges);
            }
        }

        cg
    }

    /// BFS reachability from `roots`.
    #[must_use] 
    pub fn reachable_from(&self, roots: &[u64]) -> HashSet<u64> {
        let mut visited = HashSet::new();
        let mut queue: VecDeque<u64> = roots.iter().copied().collect();
        while let Some(addr) = queue.pop_front() {
            if !visited.insert(addr) { continue; }
            if let Some(edges) = self.edges.get(&addr) {
                for e in edges {
                    if let Some(ca) = e.callee_addr
                        && !visited.contains(&ca) {
                            queue.push_back(ca);
                        }
                }
            }
        }
        visited
    }

    /// Call frequency of a function (number of distinct callers).
    #[must_use] 
    pub fn call_frequency(&self, addr: u64) -> usize {
        self.callers.get(&addr).map_or(0, std::collections::HashSet::len)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InliningCostModel
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct InliningCostModel {
    pub size_threshold: usize,
    pub max_call_frequency: usize,
    pub always_inline_leaves: bool,
    pub leaf_size_threshold: usize,
}

impl Default for InliningCostModel {
    fn default() -> Self {
        Self {
            size_threshold: 30,
            max_call_frequency: 10,
            always_inline_leaves: true,
            leaf_size_threshold: 10,
        }
    }
}

impl InliningCostModel {
    #[must_use] 
    pub fn should_inline(&self, callee: &LlilFunction, cg: &CallGraph) -> bool {
        let size: usize = callee.blocks.iter().map(|b| b.instrs.len()).sum();
        let freq = cg.call_frequency(callee.address.0);
        let is_leaf = !callee
            .blocks
            .iter()
            .flat_map(|b| b.instrs.iter())
            .any(|ai| matches!(&ai.instr, LlilInstruction::Call(_) | LlilInstruction::CallDest { .. }));

        if self.always_inline_leaves && is_leaf && size <= self.leaf_size_threshold {
            return true;
        }
        size <= self.size_threshold && freq <= self.max_call_frequency
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InliningPass
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[derive(Default)]
pub struct InliningPass {
    pub cost_model: InliningCostModel,
}


impl InliningPass {
    #[must_use] 
    pub const fn with_cost_model(cost_model: InliningCostModel) -> Self {
        Self { cost_model }
    }

    pub fn inline_into(
        &self,
        func: &mut LlilFunction,
        func_map: &HashMap<u64, &LlilFunction>,
        cg: &CallGraph,
        ctx: &mut PassContext,
    ) {
        let mut inlined = 0usize;

        for block in &mut func.blocks {
            let mut i = 0;
            while i < block.instrs.len() {
                let maybe_callee_addr = match &block.instrs[i].instr {
                    LlilInstruction::Call(LlilExpr::Const { value: addr, .. })
                    | LlilInstruction::CallDest { dest: LlilExpr::Const { value: addr, .. } } => Some(*addr),
                    _ => None,
                };
                if let Some(callee_addr) = maybe_callee_addr
                    && let Some(&callee) = func_map.get(&callee_addr)
                        && self.cost_model.should_inline(callee, cg) {
                            let suffix = format!("__inl{callee_addr:x}");
                            let inlined_instrs = inline_body(callee, &suffix);
                            block.instrs.remove(i);
                            for (k, ai) in inlined_instrs.into_iter().enumerate() {
                                block.instrs.insert(i + k, ai);
                            }
                            inlined += 1;
                            ctx.mark_changed();
                            continue; // re-check same position
                        }
                i += 1;
            }
        }

        ctx.stats.instrs_modified += inlined;
    }
}

/// Clone the non-return body of `callee`, renaming registers with `suffix`.
fn inline_body(callee: &LlilFunction, suffix: &str) -> Vec<LlilAnnotatedInstr> {
    callee
        .blocks
        .iter()
        .flat_map(|b| b.instrs.iter())
        .filter(|ai| !matches!(&ai.instr, LlilInstruction::Ret | LlilInstruction::Return { .. }))
        .map(|ai| {
            let mut new_ai = ai.clone();
            new_ai.instr = rename_regs_in_instr(ai.instr.clone(), suffix);
            new_ai
        })
        .collect()
}

fn rename_regs_in_instr(instr: LlilInstruction, suffix: &str) -> LlilInstruction {
    match instr {
        LlilInstruction::SetReg { dest, size, value } => LlilInstruction::SetReg {
            dest: rename_reg(&dest, suffix),
            size,
            value: rename_regs_in_expr(value, suffix),
        },
        LlilInstruction::Store { addr, size, value } => LlilInstruction::Store {
            addr: rename_regs_in_expr(addr, suffix),
            size,
            value: rename_regs_in_expr(value, suffix),
        },
        LlilInstruction::Load { dest, size, addr } => LlilInstruction::Load {
            dest: rename_reg(&dest, suffix),
            size,
            addr: rename_regs_in_expr(addr, suffix),
        },
        LlilInstruction::SetFlag { name, src } => LlilInstruction::SetFlag {
            name,
            src: rename_regs_in_expr(src, suffix),
        },
        other => other,
    }
}

fn rename_reg(reg: &LlilRegister, suffix: &str) -> LlilRegister {
    LlilRegister::Concrete(format!("{}{suffix}", reg.name()))
}

fn rename_regs_in_expr(expr: LlilExpr, suffix: &str) -> LlilExpr {
    match expr {
        LlilExpr::RegisterRef { reg, size } => LlilExpr::RegisterRef {
            reg: rename_reg(&reg, suffix),
            size,
        },
        LlilExpr::Add { left, right, size } => LlilExpr::Add {
            left: Box::new(rename_regs_in_expr(*left, suffix)),
            right: Box::new(rename_regs_in_expr(*right, suffix)),
            size,
        },
        LlilExpr::Sub { left, right, size } => LlilExpr::Sub {
            left: Box::new(rename_regs_in_expr(*left, suffix)),
            right: Box::new(rename_regs_in_expr(*right, suffix)),
            size,
        },
        LlilExpr::Mul { left, right, size } => LlilExpr::Mul {
            left: Box::new(rename_regs_in_expr(*left, suffix)),
            right: Box::new(rename_regs_in_expr(*right, suffix)),
            size,
        },
        LlilExpr::Load { addr, size } => LlilExpr::Load {
            addr: Box::new(rename_regs_in_expr(*addr, suffix)),
            size,
        },
        other => other,
    }
}

impl AnalysisPass for InliningPass {
    fn name(&self) -> &'static str { "inlining" }
    fn description(&self) -> &'static str { "Inline small / leaf callees into callers" }
    fn run(&self, _func: &mut LlilFunction, ctx: &mut PassContext) {
        ctx.add_warning(
            "InliningPass.run() called without function map; use inline_into() instead".to_owned(),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DevirtualizationPass
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VtableEntry {
    pub base_type: String,
    pub vtable_offset: u64,
    pub concrete_fn: u64,
}

/// Devirtualization pass: replaces indirect vtable calls with direct calls.
#[derive(Debug, Clone, Default)]
pub struct DevirtualizationPass {
    pub vtables: HashMap<String, HashMap<u64, u64>>,
    pub type_hints: HashMap<u64, String>,
}

impl DevirtualizationPass {
    pub fn register_vtable(&mut self, type_name: &str, entries: &[(u64, u64)]) {
        let map: HashMap<u64, u64> = entries.iter().copied().collect();
        self.vtables.insert(type_name.to_owned(), map);
    }

    pub fn add_type_hint(&mut self, load_addr: u64, type_name: &str) {
        self.type_hints.insert(load_addr, type_name.to_owned());
    }

    fn resolve(&self, target: &LlilExpr) -> Option<u64> {
        if let LlilExpr::Load { addr, .. } = target
            && let LlilExpr::Add { left, right, .. } = addr.as_ref() {
                let base_opt = if let LlilExpr::Const { value, .. } = left.as_ref() { Some(*value) } else { None };
                let off_opt = if let LlilExpr::Const { value, .. } = right.as_ref() { Some(*value) } else { None };
                if let (Some(base), Some(off)) = (base_opt, off_opt)
                    && let Some(type_name) = self.type_hints.get(&base)
                        && let Some(vtbl) = self.vtables.get(type_name) {
                            return vtbl.get(&off).copied();
                        }
            }
        None
    }
}

impl AnalysisPass for DevirtualizationPass {
    fn name(&self) -> &'static str { "devirtualization" }
    fn description(&self) -> &'static str {
        "Replace indirect vtable calls with direct calls when concrete type is known"
    }

    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let mut devirt = 0usize;

        for block in &mut func.blocks {
            for ai in &mut block.instrs {
                match &mut ai.instr {
                    LlilInstruction::Call(target) | LlilInstruction::CallDest { dest: target } => {
                        if let Some(concrete) = self.resolve(target) {
                            *target = LlilExpr::Const { value: concrete, size: Size::QWord };
                            devirt += 1;
                            ctx.mark_changed();
                        }
                    }
                    _ => {}
                }
            }
        }

        ctx.stats.instrs_modified += devirt;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeadFunctionEliminationPass
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DeadFunctionEliminationPass {
    pub roots: Vec<u64>,
}

impl DeadFunctionEliminationPass {
    #[must_use] 
    pub const fn new(roots: Vec<u64>) -> Self {
        Self { roots }
    }

    #[must_use] 
    pub fn dead_functions(&self, cg: &CallGraph) -> HashSet<u64> {
        let live = cg.reachable_from(&self.roots);
        cg.functions.difference(&live).copied().collect()
    }
}

impl AnalysisPass for DeadFunctionEliminationPass {
    fn name(&self) -> &'static str { "dead-function-elimination" }
    fn description(&self) -> &'static str {
        "Identify functions unreachable from known roots (no CFG modification)"
    }

    fn run(&self, _func: &mut LlilFunction, ctx: &mut PassContext) {
        ctx.add_warning(
            "DeadFunctionEliminationPass: use dead_functions() with a CallGraph instead".to_owned(),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CrossCallConstantPropPass
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct CrossCallConstantPropPass {
    pub known_args: HashMap<u64, Vec<Option<u64>>>,
    pub known_returns: HashMap<u64, u64>,
}

impl CrossCallConstantPropPass {
    pub fn observe_arg(&mut self, callee: u64, arg_idx: usize, value: u64) {
        let args = self.known_args.entry(callee).or_default();
        if args.len() <= arg_idx {
            args.resize(arg_idx + 1, Some(value));
        }
        let slot = &mut args[arg_idx];
        match *slot {
            Some(v) if v != value => *slot = None,
            _ => {}
        }
    }

    pub fn observe_return(&mut self, callee: u64, value: u64) {
        self.known_returns.insert(callee, value);
    }

    /// Scan `func` for constant arguments at call sites and record them.
    pub fn collect_from_caller(&mut self, func: &LlilFunction) {
        for block in &func.blocks {
            for ai in &block.instrs {
                let callee_addr = match &ai.instr {
                    LlilInstruction::Call(LlilExpr::Const { value: addr, .. })
                    | LlilInstruction::CallDest { dest: LlilExpr::Const { value: addr, .. } } => Some(*addr),
                    _ => None,
                };
                if let Some(addr) = callee_addr {
                    // Scan backwards in the block for SetReg to argument registers.
                    let pos = block.instrs.iter().position(|x| std::ptr::eq(x, ai)).unwrap_or(0);
                    let arg_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9",
                                    "a0", "a1", "a2", "a3", "a4", "a5"];
                    let mut arg_vals: HashMap<&str, u64> = HashMap::new();
                    for prev in block.instrs[..pos].iter().rev() {
                        if let LlilInstruction::SetReg { dest, value: LlilExpr::Const { value: c, .. }, .. } = &prev.instr {
                            let rn = dest.name();
                            if let Some(&reg) = arg_regs.iter().find(|&&r| r == rn.as_str()) {
                                arg_vals.entry(reg).or_insert(*c);
                            }
                        }
                    }
                    for (idx, &reg) in arg_regs.iter().enumerate() {
                        if let Some(&c) = arg_vals.get(reg) {
                            self.observe_arg(addr, idx, c);
                        }
                    }
                }
            }
        }
    }

    /// Replace loads from known-constant argument registers with constants.
    pub fn specialise(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let Some(args) = self.known_args.get(&func.address.0) else { return; };
        let arg_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9",
                        "a0", "a1", "a2", "a3", "a4", "a5"];
        let mut subst = 0usize;

        for block in &mut func.blocks {
            for ai in &mut block.instrs {
                if let LlilInstruction::SetReg { value, .. } = &mut ai.instr
                    && let LlilExpr::RegisterRef { reg, .. } = value {
                        let rn = reg.name();
                        if let Some(idx) = arg_regs.iter().position(|&r| r == rn.as_str())
                            && let Some(Some(c)) = args.get(idx) {
                                *value = LlilExpr::Const { value: *c, size: Size::QWord };
                                subst += 1;
                                ctx.mark_changed();
                            }
                    }
            }
        }

        ctx.stats.const_folded += subst;
    }
}

impl AnalysisPass for CrossCallConstantPropPass {
    fn name(&self) -> &'static str { "cross-call-const-prop" }
    fn description(&self) -> &'static str {
        "Propagate constant arguments and return values across function boundaries"
    }

    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let mut pass = self.clone();
        pass.collect_from_caller(func);
        pass.specialise(func, ctx);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_il_llil::{LlilBasicBlock, LlilAnnotatedInstr, LlilFunction, Size};
    use rustre_core::address::Address;

    fn empty_func(addr: u64) -> LlilFunction {
        LlilFunction {
            entry: Address::new(addr),
            address: Address::new(addr),
            blocks: vec![LlilBasicBlock {
                id: 0,
                start: Address::new(addr),
                end: Address::new(addr),
                instrs: vec![],
                successors: vec![],
            }],
            ..Default::default()
        }
    }

    fn make_call_instr(target_addr: u64, call_site: u64) -> LlilAnnotatedInstr {
        LlilAnnotatedInstr {
            address: Address::new(call_site),
            size: 5,
            length: 5,
            instr: LlilInstruction::Call(LlilExpr::Const { value: target_addr, size: Size::QWord }),
        }
    }

    #[test]
    fn test_call_graph_build() {
        let mut caller = empty_func(0x1000);
        caller.blocks[0].instrs.push(make_call_instr(0x2000, 0x1000));
        let callee = empty_func(0x2000);
        let cg = CallGraph::build(&[caller, callee]);
        assert!(cg.functions.contains(&0x1000));
        assert!(cg.functions.contains(&0x2000));
        let reachable = cg.reachable_from(&[0x1000]);
        assert!(reachable.contains(&0x2000));
    }

    #[test]
    fn test_dead_function_elimination() {
        let f1 = empty_func(0x1000);
        let f2 = empty_func(0x2000);
        let cg = CallGraph::build(&[f1, f2]);
        let dfe = DeadFunctionEliminationPass::new(vec![0x1000]);
        let dead = dfe.dead_functions(&cg);
        assert!(dead.contains(&0x2000));
        assert!(!dead.contains(&0x1000));
    }

    #[test]
    fn test_devirtualization() {
        let mut pass = DevirtualizationPass::default();
        pass.register_vtable("Foo", &[(0, 0xDEAD), (8, 0xBEEF)]);
        pass.add_type_hint(0x5000, "Foo");

        let mut func = empty_func(0x3000);
        func.blocks[0].instrs.push(LlilAnnotatedInstr {
            address: Address::new(0x3000),
            size: 2,
            length: 2,
            instr: LlilInstruction::Call(LlilExpr::Load {
                addr: Box::new(LlilExpr::Add {
                    left: Box::new(LlilExpr::Const { value: 0x5000, size: Size::QWord }),
                    right: Box::new(LlilExpr::Const { value: 8, size: Size::QWord }),
                    size: Size::QWord,
                }),
                size: Size::QWord,
            }),
        });

        let mut ctx = PassContext::new();
        pass.run(&mut func, &mut ctx);

        match &func.blocks[0].instrs[0].instr {
            LlilInstruction::Call(LlilExpr::Const { value, .. }) => {
                assert_eq!(*value, 0xBEEF);
            }
            other => panic!("expected devirt'd call, got {:?}", other),
        }
        assert!(ctx.changed);
    }

    #[test]
    fn test_cross_call_const_prop_conflict() {
        let mut pass = CrossCallConstantPropPass::default();
        pass.observe_arg(0x4000, 0, 42);
        pass.observe_arg(0x4000, 0, 42);
        pass.observe_arg(0x4000, 0, 99); // conflict → None
        assert_eq!(pass.known_args[&0x4000][0], None);
    }

    #[test]
    fn test_inlining_cost_model_leaf() {
        let model = InliningCostModel {
            always_inline_leaves: true,
            leaf_size_threshold: 5,
            ..Default::default()
        };
        let mut callee = empty_func(0x9000);
        for _ in 0..3 {
            callee.blocks[0].instrs.push(LlilAnnotatedInstr {
                address: Address::new(0x9000),
                size: 1,
                length: 1,
                instr: LlilInstruction::Nop,
            });
        }
        let cg = CallGraph::build(&[callee.clone()]);
        assert!(model.should_inline(&callee, &cg));
    }
}
