//! JVM bytecode analysis: control-flow graph, stack-depth dataflow,
//! exception table reconstruction, JSR/RET handling, and local-variable
//! type narrowing from checkcast / instanceof.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use crate::class_parser_full::{CodeAttribute, ExceptionTableEntry};

// ── Opcode widths ─────────────────────────────────────────────────────────────

/// Return the byte length of the instruction at `pc` in `code`.
/// Returns 0 if the opcode is unknown.
#[must_use] 
pub fn instruction_width(code: &[u8], pc: usize) -> usize {
    let op = code[pc];
    match op {
        // 2-byte
        0x10 | 0x12 | 0x15..=0x19 | 0x36..=0x3A | 0xA9 => 2,
        // 3-byte
        0x11 | 0x13 | 0x14 | 0x84 | 0x99..=0xA8 => 3,
        0xAA         => { // tableswitch (variable)
            let pad = (4 - ((pc + 1) % 4)) % 4;
            if pc + 1 + pad + 12 > code.len() { return 1; }
            let low  = i32_at(code, pc + 1 + pad + 4);
            let high = i32_at(code, pc + 1 + pad + 8);
            let count = nn_i32_as_usize((high - low + 1).max(0));
            1 + pad + 12 + count * 4
        }
        0xAB         => { // lookupswitch (variable)
            let pad = (4 - ((pc + 1) % 4)) % 4;
            if pc + 1 + pad + 8 > code.len() { return 1; }
            let npairs = nn_i32_as_usize(i32_at(code, pc + 1 + pad + 4));
            1 + pad + 8 + npairs * 8
        }
        // 3-byte field/invoke/new/checkcast
        0xB2..=0xB8 | 0xBB | 0xBD | 0xC0 | 0xC1 => 3,
        0xB9 | 0xBA => 5, // invokeinterface, invokedynamic
        0xBC         => 2, // newarray
        0xC4         => { // wide
            if pc + 2 >= code.len() { return 1; }
            match code[pc + 1] {
                0x15..=0x19 | 0x36..=0x3A | 0xA9 => 4,
                0x84 => 6,
                _ => 2,
            }
        }
        0xC5         => 4, // multianewarray
        0xC6 | 0xC7  => 3, // ifnull, ifnonnull
        0xC8 | 0xC9  => 5, // goto_w, jsr_w
        _ => 1,
    }
}

fn i32_at(code: &[u8], off: usize) -> i32 {
    if off + 4 > code.len() { return 0; }
    i32::from_be_bytes([code[off], code[off+1], code[off+2], code[off+3]])
}

fn u16_at(code: &[u8], off: usize) -> u16 {
    if off + 2 > code.len() { return 0; }
    u16::from_be_bytes([code[off], code[off+1]])
}

// ── Cast helpers (isolate lossy casts that are intentional in JVM bytecode) ──

/// `pc` (usize) is bounded by code length (= `u32::MAX` in practice for JVM methods).
fn pc_as_i32(pc: usize) -> i32 { i32::try_from(pc).unwrap_or(i32::MAX) }

/// Branch target: `pc` + signed offset → u32 PC.
fn branch_target(pc: usize, off: i32) -> u32 {
    u32::try_from(i64::from(pc_as_i32(pc)) + i64::from(off)).unwrap_or(0)
}

/// usize → u32 used for PCs within a method (always fits).
fn usz_as_u32(x: usize) -> u32 { u32::try_from(x).unwrap_or(u32::MAX) }

/// usize derived from a small non-negative i32 (count/index).
fn nn_i32_as_usize(x: i32) -> usize { usize::try_from(x.max(0)).unwrap_or(0) }

// ── Basic blocks ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BasicBlock {
    /// Inclusive start PC
    pub start: u32,
    /// Exclusive end PC (first byte of next block)
    pub end:   u32,
    /// Successor block PCs (fall-through + taken branches)
    pub successors: Vec<u32>,
    /// Whether this block is the target of an exception handler
    pub is_exception_handler: bool,
    /// Max operand-stack depth entering this block (from dataflow)
    pub stack_depth_in: i32,
}

impl BasicBlock {
    #[must_use]
    pub const fn instructions<'a>(&self, code: &'a [u8]) -> InstrIter<'a> {
        InstrIter { code, pc: self.start as usize, end: self.end as usize }
    }
}

pub struct InstrIter<'a> {
    code: &'a [u8],
    pc:   usize,
    end:  usize,
}

impl Iterator for InstrIter<'_> {
    type Item = (usize, u8);
    fn next(&mut self) -> Option<Self::Item> {
        if self.pc >= self.end || self.pc >= self.code.len() { return None; }
        let op = self.code[self.pc];
        let here = self.pc;
        let w = instruction_width(self.code, self.pc).max(1);
        self.pc += w;
        Some((here, op))
    }
}

// ── CFG construction ──────────────────────────────────────────────────────────

fn leader_set(code: &[u8], exc_table: &[ExceptionTableEntry]) -> HashSet<u32> {
    let mut leaders = HashSet::new();
    leaders.insert(0u32);

    // Exception handler entry points
    for e in exc_table {
        leaders.insert(u32::from(e.handler_pc));
    }

    let mut pc = 0usize;
    while pc < code.len() {
        let op = code[pc];
        let w  = instruction_width(code, pc).max(1);
        let next = usz_as_u32(pc + w);

        match op {
            // Unconditional branches
            0xA7 /* goto */   => {
                let off = i32::from(i16::from_be_bytes([code[pc+1], code[pc+2]]));
                leaders.insert(branch_target(pc, off));
                leaders.insert(next);
            }
            0xC8 /* goto_w */ => {
                let off = i32_at(code, pc + 1);
                leaders.insert(branch_target(pc, off));
                leaders.insert(next);
            }
            0xA8 /* jsr */    => {
                let off = i32::from(i16::from_be_bytes([code[pc+1], code[pc+2]]));
                leaders.insert(branch_target(pc, off));
                leaders.insert(next);
            }
            0xC9 /* jsr_w */  => {
                let off = i32_at(code, pc + 1);
                leaders.insert(branch_target(pc, off));
                leaders.insert(next);
            }
            // Conditional branches
            0x99..=0xA6 | 0xC6 | 0xC7 => {
                let off = i32::from(i16::from_be_bytes([code[pc+1], code[pc+2]]));
                leaders.insert(branch_target(pc, off));
                leaders.insert(next);
            }
            // Returns / throw
            0xAC..=0xB1 | 0xBF => {
                leaders.insert(next);
            }
            // tableswitch
            0xAA => {
                let pad  = (4 - ((pc + 1) % 4)) % 4;
                let base = pc + 1 + pad;
                let def_off  = i32_at(code, base);
                let low      = i32_at(code, base + 4);
                let high     = i32_at(code, base + 8);
                leaders.insert(branch_target(pc, def_off));
                for i in 0..nn_i32_as_usize((high - low + 1).max(0)) {
                    let off = i32_at(code, base + 12 + i * 4);
                    leaders.insert(branch_target(pc, off));
                }
                leaders.insert(next);
            }
            // lookupswitch
            0xAB => {
                let pad     = (4 - ((pc + 1) % 4)) % 4;
                let base    = pc + 1 + pad;
                let def_off = i32_at(code, base);
                leaders.insert(branch_target(pc, def_off));
                let npairs  = nn_i32_as_usize(i32_at(code, base + 4));
                for i in 0..npairs {
                    let off = i32_at(code, base + 8 + i * 8 + 4);
                    leaders.insert(branch_target(pc, off));
                }
                leaders.insert(next);
            }
            _ => {}
        }
        pc += w;
    }
    leaders
}

fn compute_successors(code: &[u8], start: u32, end: u32) -> Vec<u32> {
    // Walk to the last instruction in [start, end)
    let mut pc = start as usize;
    let end_   = end as usize;
    let mut last_pc = pc;
    while pc < end_ && pc < code.len() {
        last_pc = pc;
        let w = instruction_width(code, pc).max(1);
        pc += w;
    }

    let op   = code[last_pc];
    let next = end; // first byte after this block

    match op {
        0xAC..=0xB1 | 0xBF => vec![], // return / athrow — no successors
        0xA9 => vec![], // ret — handled separately
        0xA7 => { // goto
            let off = i32::from(i16::from_be_bytes([code[last_pc+1], code[last_pc+2]]));
            vec![branch_target(last_pc, off)]
        }
        0xC8 => { // goto_w
            let off = i32_at(code, last_pc + 1);
            vec![branch_target(last_pc, off)]
        }
        0xA8 => { // jsr
            let off = i32::from(i16::from_be_bytes([code[last_pc+1], code[last_pc+2]]));
            vec![branch_target(last_pc, off), next]
        }
        0xC9 => { // jsr_w
            let off = i32_at(code, last_pc + 1);
            vec![branch_target(last_pc, off), next]
        }
        0x99..=0xA6 | 0xC6 | 0xC7 => { // conditional
            let off = i32::from(i16::from_be_bytes([code[last_pc+1], code[last_pc+2]]));
            vec![branch_target(last_pc, off), next]
        }
        0xAA => { // tableswitch
            let pad  = (4 - ((last_pc + 1) % 4)) % 4;
            let base = last_pc + 1 + pad;
            let def_off  = i32_at(code, base);
            let low      = i32_at(code, base + 4);
            let high     = i32_at(code, base + 8);
            let mut targets = vec![branch_target(last_pc, def_off)];
            for i in 0..nn_i32_as_usize((high - low + 1).max(0)) {
                let off = i32_at(code, base + 12 + i * 4);
                targets.push(branch_target(last_pc, off));
            }
            targets.sort_unstable(); targets.dedup();
            targets
        }
        0xAB => { // lookupswitch
            let pad     = (4 - ((last_pc + 1) % 4)) % 4;
            let base    = last_pc + 1 + pad;
            let def_off = i32_at(code, base);
            let npairs  = nn_i32_as_usize(i32_at(code, base + 4));
            let mut targets = vec![branch_target(last_pc, def_off)];
            for i in 0..npairs {
                let off = i32_at(code, base + 8 + i * 8 + 4);
                targets.push(branch_target(last_pc, off));
            }
            targets.sort_unstable(); targets.dedup();
            targets
        }
        _ => vec![next], // fall-through
    }
}

/// Build a CFG (map from block-start-pc → `BasicBlock`) for the given code + exception table.
#[must_use]
pub fn build_cfg(code: &[u8], exc_table: &[ExceptionTableEntry]) -> BTreeMap<u32, BasicBlock> {
    let leaders: Vec<u32> = {
        let mut v: Vec<u32> = leader_set(code, exc_table).into_iter().collect();
        v.sort_unstable();
        v
    };

    let handler_pcs: HashSet<u32> = exc_table.iter().map(|e| u32::from(e.handler_pc)).collect();
    let mut blocks  = BTreeMap::new();

    for i in 0..leaders.len() {
        let start = leaders[i];
        let end   = leaders.get(i + 1).copied().unwrap_or_else(|| usz_as_u32(code.len()));
        if start >= usz_as_u32(code.len()) { continue; }
        let successors          = compute_successors(code, start, end);
        let is_exception_handler = handler_pcs.contains(&start);
        blocks.insert(start, BasicBlock {
            start, end, successors,
            is_exception_handler,
            stack_depth_in: -1, // unresolved
        });
    }
    blocks
}

// ── Stack-depth dataflow ──────────────────────────────────────────────────────

/// Net stack change produced by a single opcode (does not account for
/// wide-prefixed variants — those are equivalent for stack purposes).
fn opcode_stack_delta(code: &[u8], pc: usize) -> i32 {
    let op = code[pc];
    match op {
        // +1 push
        0x01 | 0x02..=0x08 | 0x0B..=0x0D | 0x10..=0x13 | 0x15 | 0x16 | 0x19
        | 0x1A..=0x1D | 0x22..=0x25 | 0x2A..=0x2D | 0x59..=0x5B | 0xA8 | 0xBB | 0xC9 | 0xB2 => 1,
        // +2 push (long/double)
        0x09 | 0x0A | 0x0E | 0x0F | 0x14 | 0x17 | 0x18 | 0x1E..=0x21 | 0x26..=0x29
        | 0x5C..=0x5E => 2,
        // -1 pop
        0x2E | 0x30 | 0x32..=0x36 | 0x3A | 0x3B..=0x3E | 0x43..=0x46 | 0x4B..=0x4E
        | 0x57 | 0x60..=0x63 | 0x64..=0x67 | 0x68..=0x6B | 0x6C..=0x6F | 0x70..=0x73
        | 0x78..=0x83 | 0x99..=0x9E | 0xA9..=0xAB | 0xAC | 0xAE | 0xB0 | 0xB1
        | 0xB3 | 0xBF | 0xC2 | 0xC3 | 0xC6 | 0xC7 => -1,
        // -2 pop
        0x37 | 0x38 | 0x39 | 0x3F..=0x42 | 0x47..=0x4A | 0x58
        | 0x9F..=0xA4 | 0xA5 | 0xA6 | 0xAD | 0xAF | 0xB5 => -2,
        // -3 pop (array store: index + arr + value, value is cat-1)
        0x4F | 0x51 | 0x53 | 0x54 | 0x55 | 0x56 => -3,
        // -4 pop (array store: index + arr + value, value is cat-2)
        0x50 | 0x52 => -4,
        0xC4 => {
            if pc + 1 < code.len() { opcode_stack_delta(code, pc + 1) }
            else { 0 }
        }
        0xC5 => -i32::from(code.get(pc + 3).copied().unwrap_or(1)) + 1, // multianewarray
        // 0 — explicit zero or unknown; wildcard handles 0x00 (nop), 0x2F/0x31 (laload/daload),
        // 0x5F (swap), 0x74..=0x77 (neg), 0x84 (iinc), 0x85..=0x98 (conversions),
        // 0xA7 (goto), 0xB4 (getfield approx), 0xB6..=0xBA (invoke approx), 0xBC..=0xBE,
        // 0xC0/0xC1 (checkcast/instanceof), 0xC8 (goto_w), and unknown opcodes.
        _ => 0,
    }
}

/// Compute `stack_depth_in` for every basic block via BFS/worklist.
///
/// # Panics
/// Panics only on internal invariants — the entry block is taken from
/// `blocks.keys().next()` after a non-empty check.
pub fn compute_stack_depths(blocks: &mut BTreeMap<u32, BasicBlock>, code: &[u8]) {
    if blocks.is_empty() { return; }

    let entry = *blocks.keys().next().unwrap();
    blocks.get_mut(&entry).unwrap().stack_depth_in = 0;

    let mut worklist: VecDeque<u32> = VecDeque::new();
    worklist.push_back(entry);

    while let Some(bb_start) = worklist.pop_front() {
        let (depth_in, end, successors) = {
            let bb = &blocks[&bb_start];
            (bb.stack_depth_in, bb.end, bb.successors.clone())
        };
        if depth_in < 0 { continue; }

        // Simulate stack through the block
        let mut depth = depth_in;
        let mut pc = bb_start as usize;
        while pc < end as usize && pc < code.len() {
            depth += opcode_stack_delta(code, pc);
            let w = instruction_width(code, pc).max(1);
            pc += w;
        }
        let depth_out = depth;

        for succ in successors {
            if let Some(sb) = blocks.get_mut(&succ)
                && sb.stack_depth_in < 0 {
                    sb.stack_depth_in = depth_out;
                    worklist.push_back(succ);
                }
        }
    }
}

// ── Exception handler reconstruction ─────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TryCatch {
    pub try_start:    u32,
    pub try_end:      u32,
    pub handler_pc:   u32,
    /// None = catch-all / finally
    pub catch_type_cp: Option<u16>,
    pub is_finally:   bool,
}

/// Group consecutive exception-table entries into logical try-catch(-finally) regions.
#[must_use]
pub fn reconstruct_try_catch(exc_table: &[ExceptionTableEntry]) -> Vec<TryCatch> {
    exc_table.iter().map(|e| TryCatch {
        try_start:     u32::from(e.start_pc),
        try_end:       u32::from(e.end_pc),
        handler_pc:    u32::from(e.handler_pc),
        catch_type_cp: if e.catch_type == 0 { None } else { Some(e.catch_type) },
        is_finally:    e.catch_type == 0,
    }).collect()
}

// ── JSR / RET subroutine handling ─────────────────────────────────────────────

/// A subroutine identified by its entry PC.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Subroutine {
    pub entry_pc:   u32,
    /// All PCs that are `JSR/JSR_W` targets of this subroutine.
    pub call_sites: Vec<u32>,
    /// The ret instruction PC (if found).
    pub ret_pc:     Option<u32>,
}

/// Identify all JSR targets and associated RET instructions.
#[must_use]
pub fn find_subroutines(code: &[u8]) -> Vec<Subroutine> {
    let mut jsr_targets: HashMap<u32, Vec<u32>> = HashMap::new();

    let mut pc = 0usize;
    while pc < code.len() {
        let op = code[pc];
        let target: Option<u32> = match op {
            0xA8 => {
                let off = i32::from(i16::from_be_bytes([code[pc+1], code[pc+2]]));
                Some(branch_target(pc, off))
            }
            0xC9 => {
                let off = i32_at(code, pc + 1);
                Some(branch_target(pc, off))
            }
            _ => None,
        };
        if let Some(t) = target {
            jsr_targets.entry(t).or_default().push(usz_as_u32(pc));
        }
        pc += instruction_width(code, pc).max(1);
    }

    let mut subs: Vec<Subroutine> = jsr_targets
        .into_iter()
        .map(|(entry, calls)| Subroutine { entry_pc: entry, call_sites: calls, ret_pc: None })
        .collect();

    // Find RET instructions (approximate: each subroutine ends at the first RET after entry)
    for sub in &mut subs {
        let start = sub.entry_pc as usize;
        let mut pc2 = start;
        while pc2 < code.len() {
            if code[pc2] == 0xA9 {
                sub.ret_pc = Some(usz_as_u32(pc2));
                break;
            }
            pc2 += instruction_width(code, pc2).max(1);
        }
    }

    subs
}

// ── Type narrowing ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum JvmType {
    Int,
    Long,
    Float,
    Double,
    Reference(String),
    Narrowed { original: Box<Self>, cast_to: String },
    ReturnAddress,
    Unknown,
}

impl JvmType {
    #[must_use]
    pub const fn is_category2(&self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }
}

/// Map from local-variable slot → inferred type at a given point.
pub type LocalTypes = HashMap<u16, JvmType>;

/// Walk the bytecode and record type narrowing induced by checkcast / instanceof.
/// Returns a map of local-var slot → narrowed type at the point of checkcast.
#[must_use]
pub fn collect_narrowing_hints<S: std::hash::BuildHasher>(
    code: &[u8],
    cp_class_names: &HashMap<u16, String, S>,
) -> Vec<(u32, u16, JvmType)> {
    // Each entry: (pc of checkcast/instanceof, aload slot if preceding op was aload_N, new type)
    let mut hints: Vec<(u32, u16, JvmType)> = Vec::new();

    let mut pc = 0usize;
    while pc < code.len() {
        let op = code[pc];
        match op {
            0xC0 | 0xC1 => {
                // checkcast / instanceof: next 2 bytes = constant pool index into Class
                let cp_idx = u16_at(code, pc + 1);
                if let Some(name) = cp_class_names.get(&cp_idx) {
                    // Look back one instruction to see if top-of-stack came from aload_N
                    if pc >= 1 {
                        let prev_op = code[pc - 1];
                        let slot: Option<u16> = match prev_op {
                            0x2A => Some(0),
                            0x2B => Some(1),
                            0x2C => Some(2),
                            0x2D => Some(3),
                            _ => None,
                        };
                        if let Some(slot) = slot {
                            hints.push((
                                usz_as_u32(pc),
                                slot,
                                JvmType::Narrowed {
                                    original: Box::new(JvmType::Reference("java/lang/Object".into())),
                                    cast_to:  name.clone(),
                                },
                            ));
                        }
                    }
                }
            }
            _ => {}
        }
        pc += instruction_width(code, pc).max(1);
    }
    hints
}

// ── Full method analysis ──────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MethodAnalysis {
    pub blocks:      Vec<BasicBlock>,
    pub try_catches: Vec<TryCatch>,
    pub subroutines: Vec<Subroutine>,
    pub narrowing:   Vec<(u32, u16, JvmType)>,
    pub max_stack_reached: i32,
}

impl MethodAnalysis {
    /// Run full analysis on a `CodeAttribute`.
    #[must_use]
    pub fn analyze(code_attr: &CodeAttribute, cp_class_names: &HashMap<u16, String>) -> Self {
        let code = &code_attr.code;
        let exc  = &code_attr.exception_table;

        let mut block_map = build_cfg(code, exc);
        compute_stack_depths(&mut block_map, code);

        let max_stack_reached = block_map.values()
            .map(|b| b.stack_depth_in)
            .filter(|&d| d >= 0)
            .max()
            .unwrap_or(0);

        let blocks      = block_map.into_values().collect();
        let try_catches = reconstruct_try_catch(exc);
        let subroutines = find_subroutines(code);
        let narrowing   = collect_narrowing_hints(code, cp_class_names);

        Self { blocks, try_catches, subroutines, narrowing, max_stack_reached }
    }

    /// Number of basic blocks.
    #[must_use]
    pub const fn block_count(&self) -> usize { self.blocks.len() }

    /// Block with largest PC range (heuristic for "hot" code region).
    #[must_use]
    pub fn largest_block(&self) -> Option<&BasicBlock> {
        self.blocks.iter().max_by_key(|b| b.end - b.start)
    }

    /// All exception handler entry PCs.
    #[must_use]
    pub fn handler_pcs(&self) -> Vec<u32> {
        self.try_catches.iter().map(|t| t.handler_pc).collect()
    }

    /// True if the method uses JSR/RET (old finally style, Java < 7).
    #[must_use]
    pub const fn has_subroutines(&self) -> bool { !self.subroutines.is_empty() }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple linear bytecode: `iconst_0`, ireturn
    #[test]
    fn cfg_linear() {
        let code = [0x03u8, 0xAC]; // iconst_0, ireturn
        let blocks = build_cfg(&code, &[]);
        assert_eq!(blocks.len(), 1);
        let b = blocks.values().next().unwrap();
        assert_eq!(b.start, 0);
        assert!(b.successors.is_empty());
    }

    #[test]
    fn cfg_branch() {
        // ifeq +5 (jumps to offset 8), iconst_0, goto +2, iconst_1, ireturn
        // [0] 0x99 0x00 0x05   ifeq +5  → target pc 8? Let's use synthetic
        let code: Vec<u8> = vec![
            0x99, 0x00, 0x05, // ifeq → pc 8 (pc 0 + 5 = 5... but jump is from pc 0)
            0x03,             // iconst_0  pc 3
            0xA7, 0x00, 0x03, // goto +3 → pc 9
            0x04,             // iconst_1  pc 7
            0xAC,             // ireturn   pc 8
        ];
        let blocks = build_cfg(&code, &[]);
        assert!(blocks.len() >= 2);
    }

    #[test]
    fn stack_depth_simple() {
        let code = [0x03u8, 0x04, 0x60, 0xAC]; // iconst_0, iconst_1, iadd, ireturn
        let mut blocks = build_cfg(&code, &[]);
        compute_stack_depths(&mut blocks, &code);
        let b = blocks.values().next().unwrap();
        assert_eq!(b.stack_depth_in, 0);
    }

    #[test]
    fn instruction_widths() {
        let mut code = vec![0u8; 256];
        code[0] = 0xAA; // tableswitch, starts at 0
        // pad = (4 - 1%4)%4 = 3
        // low=0, high=1 → 2 offsets
        // total = 1 + 3 + 12 + 2*4 = 24
        code[4] = 0; code[5] = 0; code[6] = 0; code[7] = 0;   // default
        code[8] = 0; code[9] = 0; code[10] = 0; code[11] = 0; // low=0
        code[12]= 0; code[13]= 0; code[14]= 0; code[15]= 1;   // high=1
        let w = instruction_width(&code, 0);
        assert_eq!(w, 24);
    }
}
