use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write;

// ── Lua control flow graph ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlockId(pub usize);

#[derive(Debug, Clone)]
pub struct LuaBasicBlock {
    pub id: BlockId,
    pub start_pc: u32,
    pub end_pc: u32,
    pub instructions: Vec<LuaCfgInstr>,
    pub successors: Vec<BlockId>,
    pub predecessors: Vec<BlockId>,
    pub block_type: LuaBlockType,
    pub dominators: HashSet<usize>,
    pub immediate_dominator: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LuaBlockType {
    Entry,
    Normal,
    LoopHeader,
    LoopBody,
    LoopExit,
    ConditionalTrue,
    ConditionalFalse,
    Return,
    TailCall,
}

#[derive(Debug, Clone)]
pub struct LuaCfgInstr {
    pub pc: u32,
    pub opcode: u8,
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub bx: u32,
    pub sbx: i32,
    pub ax: u32,
    pub mnemonic: &'static str,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_return: bool,
}

impl LuaCfgInstr {
    #[must_use] 
    pub fn branch_target(&self) -> Option<u32> {
        if !self.is_branch { return None; }
        match self.opcode {
            // JMP (index 54 in LUA54_OPCODES)
            // FORLOOP (71), FORPREP (72)
            // TFORLOOP (75): target is pc+1+sbx (sBx encodes negative offset back to loop header)
            54 | 71 | 72 | 75 => {
                let target = i32::try_from(self.pc).unwrap_or(i32::MAX) + 1 + self.sbx;
                u32::try_from(target).ok()
            }
            // EQ..GEI (indices 55..=63 in LUA54_OPCODES)
            55..=63 => Some(self.pc + 2),
            _ => None,
        }
    }

    #[must_use] 
    pub const fn fallthrough(&self) -> Option<u32> {
        if self.is_return { return None; }
        Some(self.pc + 1)
    }
}

// ── CFG builder ───────────────────────────────────────────────────────────────

pub struct LuaCfgBuilder;

impl LuaCfgBuilder {
    #[must_use] 
    pub fn build(instrs: &[LuaCfgInstr]) -> LuaCfg {
        if instrs.is_empty() {
            return LuaCfg { blocks: HashMap::new(), entry: BlockId(0), exit_blocks: Vec::new(), block_order: Vec::new() };
        }
        let leaders = Self::find_leaders(instrs);
        let blocks = Self::build_blocks(instrs, &leaders);
        let (blocks_with_edges, exit_blocks) = Self::add_edges(blocks);
        let entry = BlockId(0);
        let block_order: Vec<BlockId> = blocks_with_edges.keys().map(|&k| BlockId(k)).collect();
        let mut cfg = LuaCfg { blocks: blocks_with_edges.into_iter().map(|(k,v)| (BlockId(k), v)).collect(), entry, exit_blocks, block_order };
        cfg.compute_dominators();
        cfg
    }

    fn find_leaders(instrs: &[LuaCfgInstr]) -> HashSet<u32> {
        let mut leaders = HashSet::new();
        if !instrs.is_empty() { leaders.insert(instrs[0].pc); }
        for instr in instrs {
            if instr.is_branch {
                if let Some(target) = instr.branch_target() { leaders.insert(target); }
                if let Some(ft) = instr.fallthrough() { leaders.insert(ft); }
            }
            if instr.is_return
                && let Some(next) = instr.fallthrough() { leaders.insert(next); }
        }
        leaders
    }

    fn build_blocks(instrs: &[LuaCfgInstr], leaders: &HashSet<u32>) -> HashMap<usize, LuaBasicBlock> {
        let mut blocks: HashMap<usize, LuaBasicBlock> = HashMap::new();
        let mut current: Option<LuaBasicBlock> = None;
        for instr in instrs {
            if leaders.contains(&instr.pc) {
                if let Some(block) = current.take() {
                    let id = block.id.0;
                    blocks.insert(id, block);
                }
                let id = instr.pc as usize;
                current = Some(LuaBasicBlock {
                    id: BlockId(id),
                    start_pc: instr.pc,
                    end_pc: instr.pc,
                    instructions: Vec::new(),
                    successors: Vec::new(),
                    predecessors: Vec::new(),
                    block_type: if id == 0 { LuaBlockType::Entry } else { LuaBlockType::Normal },
                    dominators: HashSet::new(),
                    immediate_dominator: None,
                });
            }
            if let Some(ref mut block) = current {
                block.end_pc = instr.pc;
                block.instructions.push(instr.clone());
                if instr.is_return {
                    block.block_type = LuaBlockType::Return;
                }
            }
        }
        if let Some(block) = current {
            let id = block.id.0;
            blocks.insert(id, block);
        }
        blocks
    }

    fn add_edges(mut blocks: HashMap<usize, LuaBasicBlock>) -> (HashMap<usize, LuaBasicBlock>, Vec<BlockId>) {
        let mut exit_blocks = Vec::new();
        let block_ids: Vec<usize> = blocks.keys().copied().collect();
        // Build a lookup from start_pc → block id to avoid O(n) linear scans per edge.
        let start_pc_to_id: HashMap<u32, usize> =
            blocks.values().map(|b| (b.start_pc, b.id.0)).collect();
        let mut edges: Vec<(usize, usize)> = Vec::new();
        for id in &block_ids {
            if let Some(block) = blocks.get(id)
                && let Some(last) = block.instructions.last() {
                    if last.is_return {
                        exit_blocks.push(BlockId(*id));
                        continue;
                    }
                    if last.is_branch {
                        if let Some(target) = last.branch_target()
                            && let Some(&target_id) = start_pc_to_id.get(&target) {
                                edges.push((*id, target_id));
                            }
                        if let Some(ft) = last.fallthrough()
                            && let Some(&ft_id) = start_pc_to_id.get(&ft) {
                                edges.push((*id, ft_id));
                            }
                    } else if let Some(ft) = last.fallthrough()
                        && let Some(&ft_id) = start_pc_to_id.get(&ft) {
                            edges.push((*id, ft_id));
                        }
                }
        }
        for (from, to) in edges {
            if let Some(b) = blocks.get_mut(&from) { b.successors.push(BlockId(to)); }
            if let Some(b) = blocks.get_mut(&to) { b.predecessors.push(BlockId(from)); }
        }
        (blocks, exit_blocks)
    }
}

// ── CFG ──────────────────────────────────────────────────────────────────────

pub struct LuaCfg {
    pub blocks: HashMap<BlockId, LuaBasicBlock>,
    pub entry: BlockId,
    pub exit_blocks: Vec<BlockId>,
    pub block_order: Vec<BlockId>,
}

impl LuaCfg {
    #[must_use] 
    pub fn block_count(&self) -> usize { self.blocks.len() }

    #[must_use] 
    pub fn get_block(&self, id: &BlockId) -> Option<&LuaBasicBlock> { self.blocks.get(id) }

    #[must_use] 
    pub fn predecessors(&self, id: &BlockId) -> Vec<&LuaBasicBlock> {
        self.blocks.get(id).map_or_else(Vec::new, |block| block.predecessors.iter().filter_map(|pid| self.blocks.get(pid)).collect())
    }

    #[must_use] 
    pub fn successors(&self, id: &BlockId) -> Vec<&LuaBasicBlock> {
        self.blocks.get(id).map_or_else(Vec::new, |block| block.successors.iter().filter_map(|sid| self.blocks.get(sid)).collect())
    }

    pub fn compute_dominators(&mut self) {
        let all_ids: HashSet<usize> = self.blocks.keys().map(|k| k.0).collect();
        for block in self.blocks.values_mut() {
            block.dominators.clone_from(&all_ids);
        }
        if let Some(entry_block) = self.blocks.get_mut(&self.entry) {
            let entry_id = entry_block.id.0;
            entry_block.dominators = HashSet::from([entry_id]);
        }
        let mut changed = true;
        while changed {
            changed = false;
            let ids: Vec<usize> = self.blocks.keys().map(|k| k.0).collect();
            for id in ids {
                if id == self.entry.0 { continue; }
                let preds: Vec<usize> = self.blocks.get(&BlockId(id)).map(|b| b.predecessors.iter().map(|p| p.0).collect()).unwrap_or_default();
                let new_doms = if preds.is_empty() {
                    HashSet::new()
                } else {
                    let mut dom_set = self.blocks.get(&BlockId(preds[0])).map(|b| b.dominators.clone()).unwrap_or_default();
                    for &pred in &preds[1..] {
                        let pred_doms = self.blocks.get(&BlockId(pred)).map(|b| b.dominators.clone()).unwrap_or_default();
                        dom_set = dom_set.intersection(&pred_doms).copied().collect();
                    }
                    dom_set.insert(id);
                    dom_set
                };
                if let Some(block) = self.blocks.get_mut(&BlockId(id))
                    && block.dominators != new_doms {
                        block.dominators = new_doms;
                        changed = true;
                    }
            }
        }
    }

    #[must_use] 
    pub fn dominates(&self, dominator: usize, node: usize) -> bool {
        self.blocks.get(&BlockId(node)).is_some_and(|b| b.dominators.contains(&dominator))
    }

    #[must_use] 
    pub fn bfs_order(&self) -> Vec<&LuaBasicBlock> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut order = Vec::new();
        if let Some(_entry) = self.blocks.get(&self.entry) {
            queue.push_back(&self.entry);
            visited.insert(self.entry.0);
        }
        while let Some(id) = queue.pop_front() {
            if let Some(block) = self.blocks.get(id) {
                order.push(block);
                for succ in &block.successors {
                    if visited.insert(succ.0) {
                        queue.push_back(succ);
                    }
                }
            }
        }
        order
    }

    pub fn detect_loops(&self) -> Vec<LuaLoop> {
        let mut loops = Vec::new();
        for (id, block) in &self.blocks {
            for succ in &block.successors {
                if self.dominates(succ.0, id.0) {
                    let header = succ.0;
                    let back_edge_src = id.0;
                    let mut body = HashSet::new();
                    body.insert(header);
                    body.insert(back_edge_src);
                    let mut worklist = vec![back_edge_src];
                    while let Some(n) = worklist.pop() {
                        for pred in self.predecessors(&BlockId(n)) {
                            if body.insert(pred.id.0) {
                                worklist.push(pred.id.0);
                            }
                        }
                    }
                    loops.push(LuaLoop { header_id: BlockId(header), body_blocks: body.into_iter().map(BlockId).collect(), back_edge: (BlockId(back_edge_src), BlockId(header)) });
                }
            }
        }
        loops
    }

    #[must_use] 
    pub fn to_dot(&self) -> String {
        let mut out = String::from("digraph lua_cfg {\n");
        for (id, block) in &self.blocks {
            let label = format!("BB{} [{}..{}]", id.0, block.start_pc, block.end_pc);
            let _ = writeln!(out, "  {} [label=\"{}\"];", id.0, label);
        }
        for (id, block) in &self.blocks {
            for succ in &block.successors {
                let _ = writeln!(out, "  {} -> {};", id.0, succ.0);
            }
        }
        out.push_str("}\n");
        out
    }

    #[must_use] 
    pub fn stats(&self) -> CfgStats {
        let total_instrs: usize = self.blocks.values().map(|b| b.instructions.len()).sum();
        let branch_count: usize = self.blocks.values().flat_map(|b| b.instructions.iter()).filter(|i| i.is_branch).count();
        CfgStats { block_count: self.blocks.len(), edge_count: self.blocks.values().map(|b| b.successors.len()).sum(), total_instructions: total_instrs, branch_count, loop_count: self.detect_loops().len() }
    }
}

#[derive(Debug, Clone)]
pub struct LuaLoop {
    pub header_id: BlockId,
    pub body_blocks: Vec<BlockId>,
    pub back_edge: (BlockId, BlockId),
}

#[derive(Debug, Clone)]
pub struct CfgStats {
    pub block_count: usize,
    pub edge_count: usize,
    pub total_instructions: usize,
    pub branch_count: usize,
    pub loop_count: usize,
}

// ── Reaching definitions ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Definition {
    pub reg: u32,
    pub pc: u32,
    pub block_id: usize,
}

pub struct ReachingDefs {
    pub r#gen: HashMap<usize, HashSet<Definition>>,
    pub kill: HashMap<usize, HashSet<u32>>,
    pub in_set: HashMap<usize, HashSet<Definition>>,
    pub out_set: HashMap<usize, HashSet<Definition>>,
}

impl ReachingDefs {
    /// # Panics
    ///
    /// Panics when an argument is outside the range the instruction encoding
    /// can represent; callers must validate untrusted values first.
    #[must_use] 
    pub fn compute(cfg: &LuaCfg) -> Self {
        let mut r#gen: HashMap<usize, HashSet<Definition>> = HashMap::new();
        let mut kill: HashMap<usize, HashSet<u32>> = HashMap::new();
        for (id, block) in &cfg.blocks {
            let mut g = HashSet::new();
            let mut k = HashSet::new();
            for instr in &block.instructions {
                if instr.opcode < 0x50 {
                    let reg = instr.a;
                    k.insert(reg);
                    g.retain(|d: &Definition| d.reg != reg);
                    g.insert(Definition { reg, pc: instr.pc, block_id: id.0 });
                }
            }
            r#gen.insert(id.0, g);
            kill.insert(id.0, k);
        }
        let mut in_set: HashMap<usize, HashSet<Definition>> = HashMap::new();
        let mut out_set: HashMap<usize, HashSet<Definition>> = HashMap::new();
        for id in cfg.blocks.keys() { in_set.insert(id.0, HashSet::new()); out_set.insert(id.0, HashSet::new()); }
        let mut changed = true;
        while changed {
            changed = false;
            for (id, block) in &cfg.blocks {
                let pred_out: HashSet<Definition> = block.predecessors.iter().flat_map(|pid| out_set.get(&pid.0).cloned().unwrap_or_default()).collect();
                let new_in = pred_out;
                let g = r#gen.get(&id.0).cloned().unwrap_or_default();
                let k = kill.get(&id.0).cloned().unwrap_or_default();
                let new_out: HashSet<Definition> = g.union(&new_in.iter().filter(|d| !k.contains(&d.reg)).cloned().collect()).cloned().collect();
                if new_in != *in_set.get(&id.0).unwrap() || new_out != *out_set.get(&id.0).unwrap() {
                    in_set.insert(id.0, new_in);
                    out_set.insert(id.0, new_out);
                    changed = true;
                }
            }
        }
        Self { r#gen, kill, in_set, out_set }
    }

    #[must_use] 
    pub fn defs_reaching(&self, block_id: usize, reg: u32) -> Vec<&Definition> {
        self.in_set.get(&block_id).map(|s| s.iter().filter(|d| d.reg == reg).collect::<Vec<&Definition>>()).unwrap_or_default()
    }
}
