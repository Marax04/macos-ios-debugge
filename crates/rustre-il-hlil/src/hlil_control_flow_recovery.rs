//! `hlil_control_flow_recovery` — Structured control-flow recovery for HLIL.
//!
//! Recovers loops, conditionals, and switch statements from a flat HLIL
//! statement sequence by performing back-edge detection, dominance-frontier
//! approximation, and pattern matching on the statement tree.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use petgraph::graph::DiGraph;
use petgraph::visit::EdgeRef;

// ── LoopKind ─────────────────────────────────────────────────────────────────

/// The structural shape of a recovered loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoopKind {
    /// `while (cond) { ... }` — condition tested before the body.
    While,
    /// `do { ... } while (cond);` — condition tested after the body.
    DoWhile,
    /// `for (init; cond; step) { ... }` — counting loop with an increment.
    For,
    /// An infinite loop with no detectable exit condition.
    Infinite,
}

impl fmt::Display for LoopKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::While => write!(f, "while"),
            Self::DoWhile => write!(f, "do-while"),
            Self::For => write!(f, "for"),
            Self::Infinite => write!(f, "infinite"),
        }
    }
}

// ── RecoveredLoop ─────────────────────────────────────────────────────────────

/// A loop recovered from the control-flow graph.
#[derive(Debug, Clone)]
pub struct RecoveredLoop {
    /// Kind of loop structure.
    pub kind: LoopKind,
    /// The index of the block that is the loop header (entry).
    pub header_block: u32,
    /// Set of block indices that form the loop body.
    pub body_blocks: HashSet<u32>,
    /// Block index that is the loop exit (first block after the loop).
    pub exit_block: Option<u32>,
    /// Back-edge source block (the block whose successor is the header).
    pub back_edge_source: u32,
    /// Nesting depth (0 = outermost).
    pub depth: usize,
    /// Estimated iteration bound, if detectable from a `for`-loop counter.
    pub estimated_bound: Option<u64>,
}

impl RecoveredLoop {
    /// Returns `true` if `block_id` is within this loop's body.
    #[must_use]
    pub fn contains_block(&self, block_id: u32) -> bool {
        self.body_blocks.contains(&block_id) || block_id == self.header_block
    }

    /// Number of blocks in the loop body (including the header).
    #[must_use]
    pub fn size(&self) -> usize {
        self.body_blocks.len() + 1
    }
}

impl fmt::Display for RecoveredLoop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} loop header={} body_blocks={} depth={}",
            self.kind,
            self.header_block,
            self.body_blocks.len(),
            self.depth
        )
    }
}

// ── CondBranch ────────────────────────────────────────────────────────────────

/// A recovered conditional branch (`if` / `if-else`).
#[derive(Debug, Clone)]
pub struct CondBranch {
    /// Block index where the branch starts.
    pub branch_block: u32,
    /// True-target block.
    pub true_target: u32,
    /// False-target (fall-through) block.
    pub false_target: u32,
    /// Whether an `else` body was identified.
    pub has_else: bool,
    /// Block index where both branches reconverge.
    pub merge_block: Option<u32>,
}

impl fmt::Display for CondBranch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "if-branch block={} true={} false={} has_else={} merge={:?}",
            self.branch_block,
            self.true_target,
            self.false_target,
            self.has_else,
            self.merge_block
        )
    }
}

// ── CfgBlock ──────────────────────────────────────────────────────────────────

/// A simplified basic block descriptor used by the recovery algorithm.
#[derive(Debug, Clone)]
pub struct CfgBlock {
    /// Block identifier (typically the entry address or DFS order index).
    pub id: u32,
    /// Successor block ids.
    pub successors: Vec<u32>,
    /// Predecessor block ids.
    pub predecessors: Vec<u32>,
    /// Whether this block ends with a conditional branch.
    pub is_conditional: bool,
    /// Whether this block ends with an unconditional jump.
    pub is_unconditional_jump: bool,
    /// Whether this block is a return site.
    pub is_return: bool,
}

impl CfgBlock {
    /// Create a simple linear block with one successor.
    #[must_use]
    pub fn linear(id: u32, next: u32) -> Self {
        Self {
            id,
            successors: vec![next],
            predecessors: vec![],
            is_conditional: false,
            is_unconditional_jump: false,
            is_return: false,
        }
    }

    /// Create a conditional block with two successors.
    #[must_use]
    pub fn conditional(id: u32, true_succ: u32, false_succ: u32) -> Self {
        Self {
            id,
            successors: vec![true_succ, false_succ],
            predecessors: vec![],
            is_conditional: true,
            is_unconditional_jump: false,
            is_return: false,
        }
    }

    /// Create a return block with no successors.
    #[must_use]
    pub const fn ret(id: u32) -> Self {
        Self {
            id,
            successors: vec![],
            predecessors: vec![],
            is_conditional: false,
            is_unconditional_jump: false,
            is_return: true,
        }
    }
}

// ── HlilControlFlowRecovery ───────────────────────────────────────────────────

/// Recovers structured control flow (loops, branches, nested loops) from a
/// flat block graph.
///
/// Algorithm:
/// 1. Compute DFS tree ordering and back-edges.
/// 2. For each back-edge, collect the natural loop using a reverse-BFS from
///    the back-edge source to the loop header.
/// 3. Identify conditional branches that are not loop headers.
/// 4. Merge overlapping loop regions into nested loops.
pub struct HlilControlFlowRecovery {
    /// DFS ordering of block ids (entry first).
    pub dfs_order: Vec<u32>,
    /// Immediate dominators: block id → dominator id.
    pub idoms: HashMap<u32, u32>,
    /// All back-edges found during DFS: (source, target=header).
    pub back_edges: Vec<(u32, u32)>,
    /// Recovered loops.
    pub loops: Vec<RecoveredLoop>,
    /// Recovered conditional branches.
    pub branches: Vec<CondBranch>,
    /// Nesting map: loop header → parent loop header (if nested).
    pub nesting: HashMap<u32, u32>,
}

impl HlilControlFlowRecovery {
    /// Create a new recovery context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            dfs_order: Vec::new(),
            idoms: HashMap::new(),
            back_edges: Vec::new(),
            loops: Vec::new(),
            branches: Vec::new(),
            nesting: HashMap::new(),
        }
    }

    /// Run the full recovery on the provided block graph.
    ///
    /// `entry` is the id of the entry block.  Modifies `self` in-place.
    pub fn recover(&mut self, blocks: &[CfgBlock], entry: u32) {
        let block_map: HashMap<u32, &CfgBlock> = blocks.iter().map(|b| (b.id, b)).collect();
        self.dfs_and_back_edges(&block_map, entry);
        self.compute_idoms(&block_map, entry);
        self.recover_natural_loops(&block_map);
        self.compute_nesting();
        self.recover_branches(&block_map);
    }

    // ── Phase 1: DFS + back-edge detection ───────────────────────────────────

    fn dfs_and_back_edges(&mut self, block_map: &HashMap<u32, &CfgBlock>, entry: u32) {
        let mut visited: HashSet<u32> = HashSet::new();
        let mut on_stack: HashSet<u32> = HashSet::new();
        let mut order: Vec<u32> = Vec::new();
        let mut back: Vec<(u32, u32)> = Vec::new();
        Self::dfs_visit(entry, block_map, &mut visited, &mut on_stack, &mut order, &mut back);
        self.dfs_order = order;
        self.back_edges = back;
    }

    fn dfs_visit(
        node: u32,
        block_map: &HashMap<u32, &CfgBlock>,
        visited: &mut HashSet<u32>,
        on_stack: &mut HashSet<u32>,
        order: &mut Vec<u32>,
        back_edges: &mut Vec<(u32, u32)>,
    ) {
        if visited.contains(&node) {
            return;
        }
        visited.insert(node);
        on_stack.insert(node);
        order.push(node);
        if let Some(block) = block_map.get(&node) {
            for &succ in &block.successors {
                if on_stack.contains(&succ) {
                    back_edges.push((node, succ));
                } else if !visited.contains(&succ) {
                    Self::dfs_visit(succ, block_map, visited, on_stack, order, back_edges);
                }
            }
        }
        on_stack.remove(&node);
    }

    // ── Phase 2: Immediate dominators (simple Cooper et al. algorithm) ────────

    fn compute_idoms(&mut self, block_map: &HashMap<u32, &CfgBlock>, entry: u32) {
        // Build post-order numbering.
        let po: Vec<u32> = self.dfs_order.iter().rev().copied().collect();
        let po_num: HashMap<u32, usize> = po
            .iter()
            .enumerate()
            .map(|(i, &id)| (id, i))
            .collect();

        let mut idoms: HashMap<u32, u32> = HashMap::new();
        idoms.insert(entry, entry);

        let mut changed = true;
        while changed {
            changed = false;
            for &b in po.iter().rev() {
                if b == entry {
                    continue;
                }
                let preds: Vec<u32> = block_map
                    .get(&b)
                    .map(|blk| blk.predecessors.clone())
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|p| idoms.contains_key(p))
                    .collect();
                if preds.is_empty() {
                    continue;
                }
                let mut new_idom = preds[0];
                for &p in preds.iter().skip(1) {
                    new_idom =
                        Self::intersect(new_idom, p, &idoms, &po_num);
                }
                if idoms.get(&b) != Some(&new_idom) {
                    idoms.insert(b, new_idom);
                    changed = true;
                }
            }
        }
        self.idoms = idoms;
    }

    fn intersect(
        mut b1: u32,
        mut b2: u32,
        idoms: &HashMap<u32, u32>,
        po_num: &HashMap<u32, usize>,
    ) -> u32 {
        let num = |x: u32| po_num.get(&x).copied().unwrap_or(0);
        while b1 != b2 {
            while num(b1) < num(b2) {
                b1 = idoms.get(&b1).copied().unwrap_or(b1);
            }
            while num(b2) < num(b1) {
                b2 = idoms.get(&b2).copied().unwrap_or(b2);
            }
        }
        b1
    }

    // ── Phase 3: Natural loop recovery ───────────────────────────────────────

    fn recover_natural_loops(&mut self, block_map: &HashMap<u32, &CfgBlock>) {
        for &(src, header) in &self.back_edges.clone() {
            let body = self.natural_loop_body(src, header, block_map);
            let exit = self.find_loop_exit(header, &body, block_map);
            let kind = self.classify_loop_kind(header, src, &body, block_map);
            let loop_info = RecoveredLoop {
                kind,
                header_block: header,
                body_blocks: body,
                exit_block: exit,
                back_edge_source: src,
                depth: 0, // filled by compute_nesting
                estimated_bound: None,
            };
            self.loops.push(loop_info);
        }
    }

    fn natural_loop_body(
        &self,
        back_src: u32,
        header: u32,
        block_map: &HashMap<u32, &CfgBlock>,
    ) -> HashSet<u32> {
        let mut body: HashSet<u32> = HashSet::new();
        body.insert(header);
        body.insert(back_src);
        let mut worklist: VecDeque<u32> = VecDeque::new();
        if back_src != header {
            worklist.push_back(back_src);
        }
        while let Some(node) = worklist.pop_front() {
            if let Some(block) = block_map.get(&node) {
                for &pred in &block.predecessors {
                    if pred != header && !body.contains(&pred) {
                        body.insert(pred);
                        worklist.push_back(pred);
                    }
                }
            }
        }
        body
    }

    fn find_loop_exit(
        &self,
        _header: u32,
        body: &HashSet<u32>,
        block_map: &HashMap<u32, &CfgBlock>,
    ) -> Option<u32> {
        for &bid in body {
            if let Some(block) = block_map.get(&bid) {
                for &succ in &block.successors {
                    if !body.contains(&succ) {
                        return Some(succ);
                    }
                }
            }
        }
        None
    }

    fn classify_loop_kind(
        &self,
        header: u32,
        back_src: u32,
        body: &HashSet<u32>,
        block_map: &HashMap<u32, &CfgBlock>,
    ) -> LoopKind {
        // If header is conditional and back-src is the last block: while loop.
        let header_block = block_map.get(&header);
        let back_block = block_map.get(&back_src);

        let header_cond = header_block.is_some_and(|b| b.is_conditional);
        let back_cond = back_block.is_some_and(|b| b.is_conditional);

        if header_cond && back_src != header {
            // Exit at header: while loop.
            LoopKind::While
        } else if back_cond && !header_cond {
            // Exit at back-edge source: do-while loop.
            LoopKind::DoWhile
        } else if body.len() >= 3 && header_cond {
            // Heuristic: 3+ body blocks with conditional header → for loop.
            LoopKind::For
        } else if header_block.is_some_and(|b| b.successors.len() == 1) {
            LoopKind::Infinite
        } else {
            LoopKind::While
        }
    }

    // ── Phase 4: Nesting computation ─────────────────────────────────────────

    fn compute_nesting(&mut self) {
        // For each loop, check if its header is inside another loop's body.
        let headers: Vec<u32> = self.loops.iter().map(|l| l.header_block).collect();
        let bodies: Vec<(u32, HashSet<u32>)> = self
            .loops
            .iter()
            .map(|l| (l.header_block, l.body_blocks.clone()))
            .collect();

        let mut nesting: HashMap<u32, u32> = HashMap::new();
        let mut depths: HashMap<u32, usize> = HashMap::new();

        for &h in &headers {
            for &(other_h, ref other_body) in &bodies {
                if other_h != h && other_body.contains(&h) {
                    nesting.insert(h, other_h);
                }
            }
        }

        // Compute depths.
        for &h in &headers {
            let mut depth = 0usize;
            let mut cur = h;
            while let Some(&parent) = nesting.get(&cur) {
                depth += 1;
                cur = parent;
                if depth > 16 {
                    break; // cycle guard
                }
            }
            depths.insert(h, depth);
        }

        // Apply depths to loops.
        for loop_info in &mut self.loops {
            loop_info.depth = depths
                .get(&loop_info.header_block)
                .copied()
                .unwrap_or(0);
        }

        self.nesting = nesting;
    }

    // ── Phase 5: Branch recovery ──────────────────────────────────────────────

    fn recover_branches(&mut self, block_map: &HashMap<u32, &CfgBlock>) {
        let loop_headers: HashSet<u32> = self.loops.iter().map(|l| l.header_block).collect();
        for block in block_map.values() {
            if !block.is_conditional {
                continue;
            }
            if loop_headers.contains(&block.id) {
                continue; // This is a loop, not a simple branch.
            }
            if block.successors.len() != 2 {
                continue;
            }
            let true_target = block.successors[0];
            let false_target = block.successors[1];
            let merge = self.find_merge_block(true_target, false_target, block_map);
            let has_else = merge != Some(false_target);
            self.branches.push(CondBranch {
                branch_block: block.id,
                true_target,
                false_target,
                has_else,
                merge_block: merge,
            });
        }
    }

    fn find_merge_block(
        &self,
        true_target: u32,
        false_target: u32,
        block_map: &HashMap<u32, &CfgBlock>,
    ) -> Option<u32> {
        // BFS from true_target and false_target; return first common reachable block.
        let reachable_from = |start: u32| -> HashSet<u32> {
            let mut visited = HashSet::new();
            let mut q = VecDeque::new();
            q.push_back(start);
            while let Some(node) = q.pop_front() {
                if !visited.insert(node) {
                    continue;
                }
                if let Some(block) = block_map.get(&node) {
                    for &succ in &block.successors {
                        q.push_back(succ);
                    }
                }
            }
            visited
        };
        let rt = reachable_from(true_target);
        let rf = reachable_from(false_target);
        let common: HashSet<u32> = rt.intersection(&rf).copied().collect();
        // Pick the one with the smallest DFS order (earliest convergence).
        let dfs_pos: HashMap<u32, usize> = self
            .dfs_order
            .iter()
            .enumerate()
            .map(|(i, &id)| (id, i))
            .collect();
        common
            .iter()
            .min_by_key(|&&id| dfs_pos.get(&id).copied().unwrap_or(usize::MAX))
            .copied()
    }

    // ── Query methods ─────────────────────────────────────────────────────────

    /// Return loops sorted by nesting depth, innermost first.
    #[must_use]
    pub fn innermost_loops(&self) -> Vec<&RecoveredLoop> {
        let mut sorted: Vec<&RecoveredLoop> = self.loops.iter().collect();
        sorted.sort_by(|a, b| b.depth.cmp(&a.depth));
        sorted
    }

    /// Return the loop that contains `block_id`, if any (innermost).
    #[must_use]
    pub fn loop_for_block(&self, block_id: u32) -> Option<&RecoveredLoop> {
        self.loops
            .iter()
            .filter(|l| l.contains_block(block_id))
            .max_by_key(|l| l.depth)
    }

    /// Return the nesting depth of a block (0 if not inside any loop).
    #[must_use]
    pub fn nesting_depth_of(&self, block_id: u32) -> usize {
        self.loop_for_block(block_id)
            .map_or(0, |l| l.depth + 1)
    }

    /// Return a summary of the recovery.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "CFG recovery: {} loops ({} while, {} do-while, {} for, {} infinite), {} branches",
            self.loops.len(),
            self.loops.iter().filter(|l| l.kind == LoopKind::While).count(),
            self.loops.iter().filter(|l| l.kind == LoopKind::DoWhile).count(),
            self.loops.iter().filter(|l| l.kind == LoopKind::For).count(),
            self.loops.iter().filter(|l| l.kind == LoopKind::Infinite).count(),
            self.branches.len()
        )
    }
}

impl Default for HlilControlFlowRecovery {
    fn default() -> Self {
        Self::new()
    }
}

// ── recover_loops (free function) ─────────────────────────────────────────────

/// Convenience function: build a recovery object and run it on `blocks`.
///
/// Returns the recovered loop list, sorted by nesting depth (innermost first).
/// Costruisce il CFG dei salti a partire dagli `HlilStatement`.
///
/// ⚠ **E' il pezzo che mancava.** Questo modulo (758 righe) era esportato ma
/// **mai chiamato da nessuno** in tutto il workspace: `recover`, `recover_loops`
/// e le utility petgraph pretendono un `&[CfgBlock]` **gia' costruito**, e
/// nessuno lo costruiva dagli statement. Senza questo ponte il motore non
/// poteva essere usato — ne' misurato.
///
/// Nodi: ENTRY (id 0) piu' una `Label`; archi: `Goto` e la caduta da
/// un'etichetta alla successiva. E' il grafo dei **salti**: gli `If`/`While`
/// gia' strutturati non producono archi, ed e' corretto cosi' — e' esattamente
/// il sottografo che decide se i `goto` residui sono chiudibili.
///
/// Ritorna `(blocchi, entry)`; gli id sono INDICI progressivi (`u32`), perche'
/// `CfgBlock` usa `u32` mentre gli indirizzi HLIL sono `u64`.
#[must_use]
pub fn cfg_from_hlil(body: &[crate::HlilStatement]) -> (Vec<CfgBlock>, u32) {
    use crate::HlilStatement;

    fn val_label(l: &str) -> Option<u64> {
        let t = l
            .strip_prefix("label_")
            .or_else(|| l.strip_prefix("loc_"))
            .or_else(|| l.strip_prefix("L"))
            .unwrap_or(l)
            .trim_start_matches("0x");
        u64::from_str_radix(t, 16).ok().or_else(|| t.parse::<u64>().ok())
    }
    fn raccogli(
        stmts: &[HlilStatement],
        nodi: &mut Vec<u64>,
        archi: &mut Vec<(u64, u64)>,
        cur: &mut u64,
        ret: &mut HashSet<u64>,
    ) {
        for s in stmts {
            match s {
                HlilStatement::Label(a) => {
                    if let Some(v) = val_label(a) {
                        archi.push((*cur, v));
                        nodi.push(v);
                        *cur = v;
                    }
                }
                HlilStatement::Goto(a) => archi.push((*cur, a.0)),
                HlilStatement::Return(_) => {
                    ret.insert(*cur);
                }
                _ => {}
            }
            for b in crate::hlil_structuring::stmt_bodies_pub(s) {
                raccogli(b, nodi, archi, cur, ret);
            }
        }
    }

    const ENTRY: u64 = 0;
    let mut nodi = vec![ENTRY];
    let mut archi = Vec::new();
    let mut ret = HashSet::new();
    let mut cur = ENTRY;
    raccogli(body, &mut nodi, &mut archi, &mut cur, &mut ret);
    nodi.sort_unstable();
    nodi.dedup();
    let idx: HashMap<u64, u32> =
        nodi.iter().enumerate().map(|(i, &n)| (n, i as u32)).collect();

    let mut succ: HashMap<u32, Vec<u32>> = HashMap::new();
    for (a, b) in &archi {
        if let (Some(&x), Some(&y)) = (idx.get(a), idx.get(b)) {
            let e = succ.entry(x).or_default();
            if !e.contains(&y) {
                e.push(y);
            }
        }
    }
    let blocchi: Vec<CfgBlock> = nodi
        .iter()
        .map(|n| {
            let id = idx[n];
            let s = succ.get(&id).cloned().unwrap_or_default();
            let e_ret = s.is_empty() || ret.contains(n);
            CfgBlock {
                id,
                is_conditional: s.len() > 1,
                is_unconditional_jump: s.len() == 1,
                is_return: e_ret && s.is_empty(),
                successors: s,
                predecessors: Vec::new(),
            }
        })
        .collect();
    (blocchi, idx[&ENTRY])
}

/// Variante di [`cfg_from_hlil`] che considera nodi **solo le etichette del
/// livello corrente**.
///
/// Perche' esiste: `cfg_from_hlil` ricorre nei corpi annidati, il che e'
/// giusto per MISURARE la riducibilita' ma sbagliato per RIEMETTERE — la
/// riemissione riscrive un livello, e con i nodi piu' profondi nel grafo
/// rifiutava tutto (no-op misurato). Qui grafo e riscrittura parlano dello
/// stesso livello.
///
/// I `goto` annidati restano ARCHI, attribuiti al blocco che li contiene: un
/// salto dentro un `if` trasferisce comunque il controllo fuori dal blocco.
/// Le etichette annidate NON sono nodi: non sono riscrivibili qui.
///
/// Ritorna `(blocchi, entry, indirizzi)`: `indirizzi[i]` e' l'indirizzo del
/// nodo `i`, cosi' il chiamante non deve ricostruire l'ordinamento.
#[must_use]
pub fn cfg_from_hlil_level(body: &[crate::HlilStatement]) -> (Vec<CfgBlock>, u32, Vec<u64>) {
    use crate::HlilStatement;

    fn val_label(l: &str) -> Option<u64> {
        let t = l
            .strip_prefix("label_")
            .or_else(|| l.strip_prefix("loc_"))
            .or_else(|| l.strip_prefix("L"))
            .unwrap_or(l)
            .trim_start_matches("0x");
        u64::from_str_radix(t, 16).ok().or_else(|| t.parse::<u64>().ok())
    }
    /// Raccoglie i `goto` annidati, senza creare nodi per le etichette annidate.
    fn goto_annidati(stmts: &[HlilStatement], cur: u64, archi: &mut Vec<(u64, u64)>) {
        for s in stmts {
            if let HlilStatement::Goto(a) = s {
                archi.push((cur, a.0));
            }
            for b in crate::hlil_structuring::stmt_bodies_pub(s) {
                goto_annidati(b, cur, archi);
            }
        }
    }

    const ENTRY: u64 = 0;
    let mut nodi = vec![ENTRY];
    let mut archi: Vec<(u64, u64)> = Vec::new();
    let mut ret: HashSet<u64> = HashSet::new();
    let mut cur = ENTRY;
    for s in body {
        match s {
            HlilStatement::Label(a) => {
                if let Some(v) = val_label(a) {
                    archi.push((cur, v));
                    nodi.push(v);
                    cur = v;
                }
            }
            HlilStatement::Goto(a) => archi.push((cur, a.0)),
            HlilStatement::Return(_) => {
                ret.insert(cur);
            }
            _ => {}
        }
        for b in crate::hlil_structuring::stmt_bodies_pub(s) {
            goto_annidati(b, cur, &mut archi);
        }
    }
    nodi.sort_unstable();
    nodi.dedup();
    let idx: HashMap<u64, u32> = nodi.iter().enumerate().map(|(i, &n)| (n, i as u32)).collect();

    let mut succ: HashMap<u32, Vec<u32>> = HashMap::new();
    for (a, b) in &archi {
        if let (Some(&x), Some(&y)) = (idx.get(a), idx.get(b)) {
            let e = succ.entry(x).or_default();
            if !e.contains(&y) {
                e.push(y);
            }
        }
    }
    let blocchi: Vec<CfgBlock> = nodi
        .iter()
        .map(|n| {
            let id = idx[n];
            let s = succ.get(&id).cloned().unwrap_or_default();
            CfgBlock {
                id,
                is_conditional: s.len() > 1,
                is_unconditional_jump: s.len() == 1,
                is_return: s.is_empty(),
                successors: s,
                predecessors: Vec::new(),
            }
        })
        .collect();
    (blocchi, idx[&ENTRY], nodi)
}

#[must_use]
pub fn recover_loops(blocks: &[CfgBlock], entry: u32) -> Vec<RecoveredLoop> {
    // Build predecessor lists.
    let mut blocks_with_preds: Vec<CfgBlock> = blocks.to_vec();
    for i in 0..blocks_with_preds.len() {
        let id = blocks_with_preds[i].id;
        let succs: Vec<u32> = blocks_with_preds[i].successors.clone();
        for succ in succs {
            if let Some(target) = blocks_with_preds.iter_mut().find(|b| b.id == succ) {
                if !target.predecessors.contains(&id) {
                    target.predecessors.push(id);
                }
            }
        }
    }

    let mut recovery = HlilControlFlowRecovery::new();
    recovery.recover(&blocks_with_preds, entry);
    let mut loops = recovery.loops;
    loops.sort_by(|a, b| b.depth.cmp(&a.depth));
    loops
}

// ── petgraph CFG builder ──────────────────────────────────────────────────────

/// Build a petgraph [`DiGraph`] from a slice of [`CfgBlock`]s.
///
/// Each node carries the block id (`u32`); each directed edge represents a
/// control-flow successor relationship.  The returned map associates every
/// block id with its [`petgraph::graph::NodeIndex`] so callers can look up
/// nodes for further graph queries (e.g. dominance, reachability).
///
/// This is the canonical way to hand the CFG off to petgraph algorithms such
/// as `petgraph::algo::dominators` or `petgraph::algo::is_cyclic_directed`.
#[must_use]
pub fn build_cfg_graph(
    blocks: &[CfgBlock],
) -> (DiGraph<u32, ()>, HashMap<u32, petgraph::graph::NodeIndex>) {
    let mut graph: DiGraph<u32, ()> = DiGraph::new();
    let mut id_to_node: HashMap<u32, petgraph::graph::NodeIndex> = HashMap::new();

    // Add all nodes first so we can safely add edges in a second pass.
    for block in blocks {
        let node = graph.add_node(block.id);
        id_to_node.insert(block.id, node);
    }

    // Add edges.
    for block in blocks {
        if let Some(&src_node) = id_to_node.get(&block.id) {
            for &succ in &block.successors {
                if let Some(&dst_node) = id_to_node.get(&succ) {
                    graph.add_edge(src_node, dst_node, ());
                }
            }
        }
    }

    (graph, id_to_node)
}

/// Return the set of block ids reachable from `entry` using petgraph's DFS.
#[must_use]
pub fn reachable_blocks_petgraph(blocks: &[CfgBlock], entry: u32) -> HashSet<u32> {
    let (graph, id_to_node) = build_cfg_graph(blocks);
    let Some(&entry_node) = id_to_node.get(&entry) else { return HashSet::new() };
    let mut reachable = HashSet::new();
    let mut dfs = petgraph::visit::Dfs::new(&graph, entry_node);
    while let Some(nx) = dfs.next(&graph) {
        reachable.insert(graph[nx]);
    }
    reachable
}

/// Enumerate the CFG edges as `(src_block_id, dst_block_id)` pairs by
/// walking the petgraph edge iterator. Uses [`EdgeRef`] for source/target
/// access rather than indexing nodes manually.
#[must_use]
pub fn cfg_edge_list(blocks: &[CfgBlock]) -> Vec<(u32, u32)> {
    let (graph, _) = build_cfg_graph(blocks);
    let mut edges: Vec<(u32, u32)> = Vec::with_capacity(graph.edge_count());
    for e in graph.edge_references() {
        edges.push((graph[e.source()], graph[e.target()]));
    }
    edges
}

/// Return `true` when the CFG contains at least one back-edge (cycle), i.e. has loops.
#[must_use]
pub fn cfg_has_cycles(blocks: &[CfgBlock]) -> bool {
    let (graph, _) = build_cfg_graph(blocks);
    petgraph::algo::is_cyclic_directed(&graph)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build_while_loop_cfg() -> Vec<CfgBlock> {
        // 0 (cond) -> 1 (body) -> 0 (back-edge)
        //          -> 2 (exit)
        vec![
            CfgBlock { id: 0, successors: vec![1, 2], predecessors: vec![1], is_conditional: true, is_unconditional_jump: false, is_return: false },
            CfgBlock { id: 1, successors: vec![0], predecessors: vec![0], is_conditional: false, is_unconditional_jump: true, is_return: false },
            CfgBlock { id: 2, successors: vec![], predecessors: vec![0], is_conditional: false, is_unconditional_jump: false, is_return: true },
        ]
    }

    #[test]
    fn test_while_loop_recovery() {
        let cfg = build_while_loop_cfg();
        let loops = recover_loops(&cfg, 0);
        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].kind, LoopKind::While);
        assert_eq!(loops[0].header_block, 0);
    }

    #[test]
    fn test_loop_exit_detection() {
        let cfg = build_while_loop_cfg();
        let loops = recover_loops(&cfg, 0);
        assert_eq!(loops[0].exit_block, Some(2));
    }

    #[test]
    fn test_dfs_order_populated() {
        let cfg = build_while_loop_cfg();
        let mut recovery = HlilControlFlowRecovery::new();
        recovery.recover(&cfg, 0);
        assert!(!recovery.dfs_order.is_empty());
    }

    #[test]
    fn test_nested_loop() {
        // Outer: 0 -> 1 -> 2 -> 0  (back edge 2->0)
        // Inner: 1 -> 1             (self-loop, back edge 1->1)
        let blocks = vec![
            CfgBlock { id: 0, successors: vec![1, 3], predecessors: vec![2], is_conditional: true, is_unconditional_jump: false, is_return: false },
            CfgBlock { id: 1, successors: vec![1, 2], predecessors: vec![0, 1], is_conditional: true, is_unconditional_jump: false, is_return: false },
            CfgBlock { id: 2, successors: vec![0], predecessors: vec![1], is_conditional: false, is_unconditional_jump: true, is_return: false },
            CfgBlock { id: 3, successors: vec![], predecessors: vec![0], is_conditional: false, is_unconditional_jump: false, is_return: true },
        ];
        let loops = recover_loops(&blocks, 0);
        assert!(loops.len() >= 1);
    }

    #[test]
    fn test_summary_output() {
        let cfg = build_while_loop_cfg();
        let mut recovery = HlilControlFlowRecovery::new();
        recovery.recover(&cfg, 0);
        let summary = recovery.summary();
        assert!(summary.contains("loop"));
    }

    #[test]
    fn test_no_loops_linear_cfg() {
        let blocks = vec![
            CfgBlock { id: 0, successors: vec![1], predecessors: vec![], is_conditional: false, is_unconditional_jump: false, is_return: false },
            CfgBlock { id: 1, successors: vec![2], predecessors: vec![0], is_conditional: false, is_unconditional_jump: false, is_return: false },
            CfgBlock { id: 2, successors: vec![], predecessors: vec![1], is_conditional: false, is_unconditional_jump: false, is_return: true },
        ];
        let loops = recover_loops(&blocks, 0);
        assert!(loops.is_empty());
    }

    /// ⚠ PRIMA esecuzione REALE di questo motore: fino a oggi il modulo era
    /// esportato ma **mai chiamato**, perche' mancava il ponte dagli
    /// `HlilStatement`. Qui si costruisce il CFG da statement veri e si verifica
    /// che `recover_loops` trovi il ciclo — cioe' che le 758 righe funzionino.
    #[test]
    fn cfg_from_hlil_sblocca_il_motore() {
        use crate::HlilStatement;
        use rustre_core::address::Address;

        // `loc_10: … goto loc_10;` — un ciclo, un solo ingresso.
        let body = vec![
            HlilStatement::Label("loc_10".to_string()),
            HlilStatement::Goto(Address::new(0x10)),
        ];
        let (blocchi, entry) = cfg_from_hlil(&body);
        assert_eq!(blocchi.len(), 2, "ENTRY + l'etichetta: {blocchi:?}");
        let loops = recover_loops(&blocchi, entry);
        assert_eq!(loops.len(), 1, "il motore non ha trovato il ciclo: {loops:?}");

        // RIFIUTO — nessun salto: nessun ciclo, e nessun blocco oltre l'ENTRY.
        let dritto = vec![HlilStatement::Return(Vec::new())];
        let (b2, e2) = cfg_from_hlil(&dritto);
        assert_eq!(b2.len(), 1);
        assert!(recover_loops(&b2, e2).is_empty());

        // RIFIUTO — salto in AVANTI verso un'etichetta: nessun ciclo.
        let avanti = vec![
            HlilStatement::Goto(Address::new(0x20)),
            HlilStatement::Label("loc_20".to_string()),
        ];
        let (b3, e3) = cfg_from_hlil(&avanti);
        assert!(recover_loops(&b3, e3).is_empty(), "un salto in avanti non e' un ciclo");
    }
}
