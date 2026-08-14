//! Memory access pattern analysis — stride detection, struct field layout
//! inference, heap allocation tracking, and per-function aliasing summaries.
//!
//! # Analyses
//! * [`StrideAnalysis`] — detect regular (constant-stride) array traversals.
//! * [`StructLayoutInference`] — infer struct field layout from fixed-offset
//!   access patterns relative to a base pointer.
//! * [`HeapTracker`] — pair malloc/free calls across a function; identify
//!   allocation sites and likely lifetimes.
//! * [`AliasSummary`] — coarse may-alias summary per function (points-to sets).

use std::collections::{HashMap, HashSet};

use rustre_il_llil::{LlilExpr, LlilFunction, LlilInstruction};

use crate::{AnalysisPass, PassContext};

// ─────────────────────────────────────────────────────────────────────────────
// AbstractLoc
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AbstractLoc {
    Stack { offset: i64 },
    Heap { site: u64 },
    Global { addr: u64 },
    Unknown,
}

impl AbstractLoc {
    #[must_use]
    pub fn may_alias(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Unknown, _) | (_, Self::Unknown) => true,
            _ => self == other,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemAccess
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MemAccess {
    pub block: usize,
    pub instr: usize,
    pub kind: AccessKind,
    pub loc: AbstractLoc,
    pub size: u8,
    pub addr_expr: LlilExpr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Read,
    Write,
}

// ─────────────────────────────────────────────────────────────────────────────
// StrideAnalysis
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StridePattern {
    pub base: String,
    pub stride: i64,
    pub elem_size: u8,
    pub access_count: usize,
    pub blocks: Vec<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct StrideAnalysis {
    pub patterns: HashMap<String, StridePattern>,
}

impl StrideAnalysis {
    #[must_use] 
    pub fn run(func: &LlilFunction) -> Self {
        let mut accesses: HashMap<String, Vec<(i64, u8)>> = HashMap::new();

        for block in &func.blocks {
            for ai in &block.instrs {
                match &ai.instr {
                    LlilInstruction::Store { addr, size, .. } | LlilInstruction::Load { addr, size, .. } => {
                        if let Some((base, off)) = extract_base_offset(addr) {
                            accesses.entry(base).or_default().push((off, u8::try_from(size.bytes()).unwrap_or(0)));
                        }
                    }
                    LlilInstruction::SetReg { value, .. } => {
                        if let LlilExpr::Load { addr, size } = value
                            && let Some((base, off)) = extract_base_offset(addr) {
                                accesses.entry(base).or_default().push((off, u8::try_from(size.bytes()).unwrap_or(0)));
                            }
                    }
                    _ => {}
                }
            }
        }

        let mut patterns = HashMap::new();
        for (base, mut offsets) in accesses {
            if offsets.len() < 2 { continue; }
            offsets.sort_by_key(|&(off, _)| off);
            let differences: Vec<i64> = offsets.windows(2).map(|w| w[1].0 - w[0].0).collect();
            if !differences.is_empty() && differences.iter().all(|&d| d == differences[0]) && differences[0] > 0 {
                let stride = differences[0];
                let elem_size = offsets[0].1;
                patterns.insert(base.clone(), StridePattern {
                    base,
                    stride,
                    elem_size,
                    access_count: offsets.len(),
                    blocks: vec![],
                });
            }
        }

        Self { patterns }
    }

    #[must_use]
    pub fn has_patterns(&self) -> bool {
        !self.patterns.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StructLayoutInference
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct InferredField {
    pub offset: u64,
    pub size: u8,
    pub access_count: usize,
    pub written: bool,
}

#[derive(Debug, Clone)]
pub struct InferredStruct {
    pub base: String,
    pub fields: Vec<InferredField>,
    pub total_size: u64,
}

impl InferredStruct {
    #[must_use] 
    pub fn field_at(&self, offset: u64) -> Option<&InferredField> {
        self.fields.iter().find(|f| f.offset == offset)
    }
}

#[derive(Debug, Clone, Default)]
pub struct StructLayoutInference {
    pub structs: HashMap<String, InferredStruct>,
}

impl StructLayoutInference {
    #[must_use] 
    pub fn run(func: &LlilFunction) -> Self {
        // (base, offset) → (size_bytes, count, written)
        let mut field_accesses: HashMap<String, HashMap<u64, (u8, usize, bool)>> = HashMap::new();

        for block in &func.blocks {
            for ai in &block.instrs {
                match &ai.instr {
                    LlilInstruction::Store { addr, size, .. } => {
                        if let Some((base, off)) = extract_base_offset(addr)
                            && off >= 0 {
                                let sz = u8::try_from(size.bytes()).unwrap_or(0);
                                let entry = field_accesses
                                    .entry(base).or_default()
                                    .entry(off.cast_unsigned())
                                    .or_insert_with(|| (sz, 0, false));
                                entry.1 += 1;
                                entry.2 = true;
                            }
                    }
                    LlilInstruction::SetReg { value, .. } => {
                        if let LlilExpr::Load { addr, size } = value
                            && let Some((base, off)) = extract_base_offset(addr)
                                && off >= 0 {
                                    let sz = u8::try_from(size.bytes()).unwrap_or(0);
                                    let entry = field_accesses
                                        .entry(base).or_default()
                                        .entry(off.cast_unsigned())
                                        .or_insert_with(|| (sz, 0, false));
                                    entry.1 += 1;
                                }
                    }
                    LlilInstruction::Load { addr, size, .. } => {
                        if let Some((base, off)) = extract_base_offset(addr)
                            && off >= 0 {
                                let sz = u8::try_from(size.bytes()).unwrap_or(0);
                                let entry = field_accesses
                                    .entry(base).or_default()
                                    .entry(off.cast_unsigned())
                                    .or_insert_with(|| (sz, 0, false));
                                entry.1 += 1;
                            }
                    }
                    _ => {}
                }
            }
        }

        let mut structs = HashMap::new();
        for (base, field_map) in field_accesses {
            if field_map.len() < 2 { continue; }
            let mut fields: Vec<InferredField> = field_map
                .iter()
                .map(|(&off, &(sz, cnt, written))| InferredField { offset: off, size: sz, access_count: cnt, written })
                .collect();
            fields.sort_by_key(|f| f.offset);
            let total_size = fields.last().map_or(0, |f| f.offset + u64::from(f.size));
            structs.insert(base.clone(), InferredStruct { base, fields, total_size });
        }

        Self { structs }
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.structs.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HeapTracker
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HeapAllocation {
    pub alloc_site: u64,
    pub ptr_reg: String,
    pub has_free: bool,
    pub free_site: Option<u64>,
    pub size_arg: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct HeapTracker {
    pub allocations: Vec<HeapAllocation>,
}

const ALLOC_FNS: &[&str] = &["malloc", "calloc", "realloc", "new", "_Znwm", "_Znam"];
const FREE_FNS: &[&str] = &["free", "delete", "_ZdlPv", "_ZdaPv"];

impl HeapTracker {
    pub fn run(func: &LlilFunction, symbols: &HashMap<u64, String>) -> Self {
        let mut allocs: Vec<HeapAllocation> = Vec::new();
        // Map from register name → allocation index.
        let mut ptr_to_alloc: HashMap<String, usize> = HashMap::new();

        for block in &func.blocks {
            let block_addr = block.start.0;
            for ai in &block.instrs {
                match &ai.instr {
                    // SetReg { dest: ptr_reg, value: Load { addr: call_target } }
                    // This heuristic detects: ptr = malloc(size) compiled as a Load
                    // of the return value; real detection should be platform-specific.
                    // We handle the pattern: SetReg after a Call instruction to an allocator.
                    LlilInstruction::SetReg { dest, value: LlilExpr::Const { value: addr, .. }, .. } => {
                        // Look for alloc pattern: dest = Const(alloc_addr) — can't tell easily.
                        // Instead track when the instruction immediately follows a known alloc call.
                        // For now record any Const that matches a known symbol as alloc.
                        {
                            let sym = symbols.get(addr).map_or("", String::as_str);
                            if ALLOC_FNS.iter().any(|&f| sym.contains(f)) {
                                let idx = allocs.len();
                                allocs.push(HeapAllocation {
                                    alloc_site: block_addr,
                                    ptr_reg: dest.name(),
                                    has_free: false,
                                    free_site: None,
                                    size_arg: None,
                                });
                                ptr_to_alloc.insert(dest.name(), idx);
                            }
                        }
                    }
                    // Call(free_addr) — check if callee is a free function.
                    LlilInstruction::Call(LlilExpr::Const { value: addr, .. })
                    | LlilInstruction::CallDest { dest: LlilExpr::Const { value: addr, .. } } => {
                        let sym = symbols.get(addr).map_or("", String::as_str);
                        if FREE_FNS.iter().any(|&f| sym.contains(f)) {
                            // Heuristic: the freed register is in the preceding SetReg/argument.
                            // Look backwards for a RegisterRef that was recently set from an alloc.
                            for prev in block.instrs.iter().rev() {
                                if let LlilInstruction::SetReg { dest: _, value: LlilExpr::RegisterRef { reg, .. }, .. } = &prev.instr
                                    && let Some(&idx) = ptr_to_alloc.get(&reg.name()) {
                                        allocs[idx].has_free = true;
                                        allocs[idx].free_site = Some(block_addr);
                                        break;
                                    }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Self { allocations: allocs }
    }

    #[must_use] 
    pub fn potential_leaks(&self) -> Vec<&HeapAllocation> {
        self.allocations.iter().filter(|a| !a.has_free).collect()
    }

    #[must_use]
    pub fn paired_count(&self) -> usize {
        self.allocations.iter().filter(|a| a.has_free).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AliasSummary
// ─────────────────────────────────────────────────────────────────────────────

pub type PointsToSet = HashSet<AbstractLoc>;

#[derive(Debug, Clone, Default)]
pub struct AliasSummary {
    /// Points-to sets for every register in the function.
    pub points_to: HashMap<String, PointsToSet>,
    pub may_alias_pairs: Vec<((usize, usize), (usize, usize))>,
}

impl AliasSummary {
    /// Build a flow-insensitive, Andersen-style points-to summary for `func`.
    #[must_use] 
    pub fn build(func: &LlilFunction) -> Self {
        let mut pts: HashMap<String, PointsToSet> = HashMap::new();

        let mut changed = true;
        while changed {
            changed = false;
            for block in &func.blocks {
                let block_addr = block.start.0;
                for ai in &block.instrs {
                    if let LlilInstruction::SetReg { dest, value, .. } = &ai.instr {
                        let new_pts = derive_points_to(value, &pts, block_addr);
                        let entry = pts.entry(dest.name()).or_default();
                        let before = entry.len();
                        entry.extend(new_pts);
                        if entry.len() > before { changed = true; }
                    }
                }
            }
        }

        let mut accesses: Vec<MemAccess> = Vec::new();
        for (bidx, block) in func.blocks.iter().enumerate() {
            for (iidx, ai) in block.instrs.iter().enumerate() {
                match &ai.instr {
                    LlilInstruction::Store { addr, size, .. } => {
                        accesses.push(MemAccess {
                            block: bidx, instr: iidx,
                            kind: AccessKind::Write,
                            loc: resolve_loc(addr, &pts),
                            size: u8::try_from(size.bytes()).unwrap_or(0),
                            addr_expr: addr.clone(),
                        });
                    }
                    LlilInstruction::SetReg { value: LlilExpr::Load { addr, size }, .. } => {
                        accesses.push(MemAccess {
                            block: bidx, instr: iidx,
                            kind: AccessKind::Read,
                            loc: resolve_loc(addr, &pts),
                            size: u8::try_from(size.bytes()).unwrap_or(0),
                            addr_expr: addr.as_ref().clone(),
                        });
                    }
                    LlilInstruction::Load { addr, size, .. } => {
                        accesses.push(MemAccess {
                            block: bidx, instr: iidx,
                            kind: AccessKind::Read,
                            loc: resolve_loc(addr, &pts),
                            size: u8::try_from(size.bytes()).unwrap_or(0),
                            addr_expr: addr.clone(),
                        });
                    }
                    _ => {}
                }
            }
        }

        let mut may_alias_pairs = Vec::new();
        for i in 0..accesses.len() {
            for j in (i + 1)..accesses.len() {
                if accesses[i].loc.may_alias(&accesses[j].loc) {
                    may_alias_pairs.push((
                        (accesses[i].block, accesses[i].instr),
                        (accesses[j].block, accesses[j].instr),
                    ));
                }
            }
        }

        Self { points_to: pts, may_alias_pairs }
    }

    #[must_use] 
    pub fn may_alias(&self, b1: usize, i1: usize, b2: usize, i2: usize) -> bool {
        let a = if (b1, i1) < (b2, i2) { (b1, i1) } else { (b2, i2) };
        let b = if (b1, i1) < (b2, i2) { (b2, i2) } else { (b1, i1) };
        self.may_alias_pairs.iter().any(|&(x, y)| x == a && y == b)
    }

    #[must_use]
    pub const fn alias_pair_count(&self) -> usize {
        self.may_alias_pairs.len()
    }
}

fn derive_points_to(
    expr: &LlilExpr,
    pts: &HashMap<String, PointsToSet>,
    _block_addr: u64,
) -> PointsToSet {
    let mut result = HashSet::new();
    match expr {
        LlilExpr::Add { left, right, .. }
            if matches!(left.as_ref(), LlilExpr::StackPointer(_)) =>
        {
            if let LlilExpr::Const { value: off, .. } = right.as_ref() {
                result.insert(AbstractLoc::Stack { offset: (*off).cast_signed() });
            } else {
                result.insert(AbstractLoc::Unknown);
            }
        }
        LlilExpr::StackPointer(_) => {
            result.insert(AbstractLoc::Stack { offset: 0 });
        }
        LlilExpr::Const { value, .. } if *value > 0x1000 => {
            result.insert(AbstractLoc::Global { addr: *value });
        }
        LlilExpr::RegisterRef { reg, .. } => {
            if let Some(src_pts) = pts.get(&reg.name()) {
                result.extend(src_pts.iter().cloned());
            }
        }
        _ => {
            result.insert(AbstractLoc::Unknown);
        }
    }
    result
}

fn resolve_loc(addr: &LlilExpr, pts: &HashMap<String, PointsToSet>) -> AbstractLoc {
    match addr {
        LlilExpr::Const { value, .. } => AbstractLoc::Global { addr: *value },
        LlilExpr::RegisterRef { reg, .. } => {
            if let Some(set) = pts.get(&reg.name())
                && set.len() == 1 {
                    return set.iter().next().unwrap().clone();
                }
            AbstractLoc::Unknown
        }
        LlilExpr::Add { left, right, .. }
            if matches!(left.as_ref(), LlilExpr::StackPointer(_)) =>
        {
            if let LlilExpr::Const { value: off, .. } = right.as_ref() {
                AbstractLoc::Stack { offset: (*off).cast_signed() }
            } else {
                AbstractLoc::Unknown
            }
        }
        _ => AbstractLoc::Unknown,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryAccessPatternPass (top-level)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct MemoryAccessPatternPass;

impl AnalysisPass for MemoryAccessPatternPass {
    fn name(&self) -> &'static str { "memory-access-patterns" }
    fn description(&self) -> &'static str {
        "Stride detection, struct layout inference, heap tracking, alias summary"
    }

    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext) {
        let stride = StrideAnalysis::run(func);
        let layout = StructLayoutInference::run(func);
        let alias = AliasSummary::build(func);

        ctx.add_warning(format!(
            "memory-access-patterns: {} stride patterns, {} inferred structs, {} alias pairs",
            stride.patterns.len(),
            layout.count(),
            alias.alias_pair_count()
        ));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extract (`base_register_name`, `signed_offset`) from an address expression.
fn extract_base_offset(expr: &LlilExpr) -> Option<(String, i64)> {
    match expr {
        LlilExpr::Add { left, right, .. } => match (left.as_ref(), right.as_ref()) {
            (LlilExpr::RegisterRef { reg, .. }, LlilExpr::Const { value, .. })
            | (LlilExpr::Const { value, .. }, LlilExpr::RegisterRef { reg, .. }) => {
                Some((reg.name(), (*value).cast_signed()))
            }
            _ => None,
        },
        LlilExpr::Sub { left, right, .. } => match (left.as_ref(), right.as_ref()) {
            (LlilExpr::RegisterRef { reg, .. }, LlilExpr::Const { value, .. }) => {
                Some((reg.name(), -((*value).cast_signed())))
            }
            _ => None,
        },
        LlilExpr::RegisterRef { reg, .. } => Some((reg.name(), 0)),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_il_llil::{LlilAnnotatedInstr, LlilBasicBlock, LlilFunction, Size, LlilRegister};
    use rustre_core::address::Address;

    fn make_load(base: &str, offset: u64, block_addr: u64) -> LlilAnnotatedInstr {
        LlilAnnotatedInstr {
            address: Address::new(block_addr),
            size: 4,
            length: 4,
            instr: LlilInstruction::SetReg {
                dest: LlilRegister::Concrete(format!("tmp_{offset}")),
                size: Size::DWord,
                value: LlilExpr::Load {
                    addr: Box::new(LlilExpr::Add {
                        left: Box::new(LlilExpr::RegisterRef {
                            reg: LlilRegister::Concrete(base.to_owned()),
                            size: Size::QWord,
                        }),
                        right: Box::new(LlilExpr::Const { value: offset, size: Size::QWord }),
                        size: Size::QWord,
                    }),
                    size: Size::DWord,
                },
            },
        }
    }

    fn func_with_accesses(instrs: Vec<LlilAnnotatedInstr>) -> LlilFunction {
        LlilFunction {
            entry: Address::new(0x1000),
            address: Address::new(0x1000),
            blocks: vec![LlilBasicBlock {
                id: 0,
                start: Address::new(0x1000),
                end: Address::new(0x1000),
                instrs,
                successors: vec![],
            }],
            ..Default::default()
        }
    }

    #[test]
    fn test_stride_detection_array() {
        let func = func_with_accesses(vec![
            make_load("arr", 0, 0x1000),
            make_load("arr", 4, 0x1004),
            make_load("arr", 8, 0x1008),
            make_load("arr", 12, 0x100c),
        ]);
        let sa = StrideAnalysis::run(&func);
        assert!(sa.has_patterns());
        let pat = sa.patterns.get("arr").unwrap();
        assert_eq!(pat.stride, 4);
        assert_eq!(pat.access_count, 4);
    }

    #[test]
    fn test_struct_layout_inference() {
        let func = func_with_accesses(vec![
            make_load("obj", 0, 0x1000),
            make_load("obj", 4, 0x1004),
            make_load("obj", 8, 0x1008),
        ]);
        let layout = StructLayoutInference::run(&func);
        assert_eq!(layout.count(), 1);
        let s = layout.structs.get("obj").unwrap();
        assert_eq!(s.fields.len(), 3);
        assert_eq!(s.total_size, 12); // offset 8 + size 4
    }

    #[test]
    fn test_abstract_loc_alias() {
        let a = AbstractLoc::Stack { offset: 8 };
        let b = AbstractLoc::Stack { offset: 8 };
        let c = AbstractLoc::Stack { offset: 16 };
        assert!(a.may_alias(&b));
        assert!(!a.may_alias(&c));
        assert!(AbstractLoc::Unknown.may_alias(&c));
    }

    #[test]
    fn test_extract_base_offset() {
        let expr = LlilExpr::Add {
            left: Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete("rax".to_owned()),
                size: Size::QWord,
            }),
            right: Box::new(LlilExpr::Const { value: 16, size: Size::QWord }),
            size: Size::QWord,
        };
        let result = extract_base_offset(&expr);
        assert_eq!(result, Some(("rax".to_owned(), 16)));
    }

    // ── Additional edge-case coverage ────────────────────────────────────────

    #[test]
    fn test_extract_base_offset_commuted_operands() {
        // Const on the left, Reg on the right — must still match.
        let expr = LlilExpr::Add {
            left: Box::new(LlilExpr::Const { value: 8, size: Size::QWord }),
            right: Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete("rbx".to_owned()),
                size: Size::QWord,
            }),
            size: Size::QWord,
        };
        assert_eq!(extract_base_offset(&expr), Some(("rbx".to_owned(), 8)));
    }

    #[test]
    fn test_extract_base_offset_sub_negates_offset() {
        // rcx - 12 → offset -12.
        let expr = LlilExpr::Sub {
            left: Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete("rcx".to_owned()),
                size: Size::QWord,
            }),
            right: Box::new(LlilExpr::Const { value: 12, size: Size::QWord }),
            size: Size::QWord,
        };
        assert_eq!(extract_base_offset(&expr), Some(("rcx".to_owned(), -12)));
    }

    #[test]
    fn test_extract_base_offset_bare_reg_is_zero() {
        // A plain register reference is base with offset 0.
        let expr = LlilExpr::RegisterRef {
            reg: LlilRegister::Concrete("rdx".to_owned()),
            size: Size::QWord,
        };
        assert_eq!(extract_base_offset(&expr), Some(("rdx".to_owned(), 0)));
    }

    #[test]
    fn test_extract_base_offset_returns_none_for_unsupported() {
        // Const-only address has no base register.
        let expr = LlilExpr::Const { value: 0x1000, size: Size::QWord };
        assert_eq!(extract_base_offset(&expr), None);
        // Two registers added together — not the recognised pattern.
        let two_regs = LlilExpr::Add {
            left: Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete("rax".to_owned()),
                size: Size::QWord,
            }),
            right: Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete("rbx".to_owned()),
                size: Size::QWord,
            }),
            size: Size::QWord,
        };
        assert_eq!(extract_base_offset(&two_regs), None);
    }

    #[test]
    fn test_stride_detection_rejects_irregular_access() {
        // Accesses at 0, 4, 9, 12 — second gap is 5, not 4 — must NOT register
        // as a stride pattern.
        let func = func_with_accesses(vec![
            make_load("foo", 0, 0x1000),
            make_load("foo", 4, 0x1004),
            make_load("foo", 9, 0x1008),
            make_load("foo", 12, 0x100c),
        ]);
        let sa = StrideAnalysis::run(&func);
        assert!(!sa.patterns.contains_key("foo"));
    }

    #[test]
    fn test_stride_detection_requires_two_accesses() {
        // A single access cannot establish a stride.
        let func = func_with_accesses(vec![make_load("singleton", 0, 0x1000)]);
        let sa = StrideAnalysis::run(&func);
        assert!(!sa.has_patterns());
    }

    #[test]
    fn test_empty_function_has_no_patterns_or_structs() {
        let func = func_with_accesses(vec![]);
        let sa = StrideAnalysis::run(&func);
        let layout = StructLayoutInference::run(&func);
        assert!(!sa.has_patterns());
        assert_eq!(layout.count(), 0);
    }

    #[test]
    fn test_struct_layout_requires_two_distinct_fields() {
        // Only one offset → not enough to call it a struct.
        let func = func_with_accesses(vec![
            make_load("obj", 0, 0x1000),
            make_load("obj", 0, 0x1004),
        ]);
        let layout = StructLayoutInference::run(&func);
        assert_eq!(layout.count(), 0);
    }

    #[test]
    fn test_struct_layout_field_at_lookup() {
        let func = func_with_accesses(vec![
            make_load("p", 0, 0x1000),
            make_load("p", 16, 0x1004),
            make_load("p", 24, 0x1008),
        ]);
        let layout = StructLayoutInference::run(&func);
        let s = layout.structs.get("p").expect("struct inferred");
        assert!(s.field_at(0).is_some());
        assert!(s.field_at(16).is_some());
        assert!(s.field_at(24).is_some());
        // A non-existent offset returns None.
        assert!(s.field_at(100).is_none());
    }

    #[test]
    fn test_abstract_loc_alias_cross_kind() {
        // Stack vs Global vs Heap — distinct kinds never alias (unless Unknown).
        let s = AbstractLoc::Stack { offset: 0 };
        let g = AbstractLoc::Global { addr: 0 };
        let h = AbstractLoc::Heap { site: 0 };
        assert!(!s.may_alias(&g));
        assert!(!s.may_alias(&h));
        assert!(!g.may_alias(&h));
        // Unknown aliases ALL kinds.
        let u = AbstractLoc::Unknown;
        assert!(u.may_alias(&s));
        assert!(u.may_alias(&g));
        assert!(u.may_alias(&h));
        assert!(s.may_alias(&u));
    }

    #[test]
    fn test_heap_tracker_empty_function() {
        let func = func_with_accesses(vec![]);
        let symbols: HashMap<u64, String> = HashMap::new();
        let tracker = HeapTracker::run(&func, &symbols);
        assert!(tracker.allocations.is_empty());
        assert_eq!(tracker.paired_count(), 0);
        assert!(tracker.potential_leaks().is_empty());
    }

    #[test]
    fn test_struct_layout_total_size_uses_last_field_end() {
        // Fields at 0..4, 16..24 → total_size = 24.
        let func = LlilFunction {
            entry: Address::new(0x1000),
            address: Address::new(0x1000),
            blocks: vec![LlilBasicBlock {
                id: 0,
                start: Address::new(0x1000),
                end: Address::new(0x1000),
                instrs: vec![
                    make_load("obj", 0, 0x1000),
                    {
                        // Synthesize an 8-byte access at offset 16.
                        LlilAnnotatedInstr {
                            address: Address::new(0x1004),
                            size: 4,
                            length: 4,
                            instr: LlilInstruction::SetReg {
                                dest: LlilRegister::Concrete("tmp_16".into()),
                                size: Size::QWord,
                                value: LlilExpr::Load {
                                    addr: Box::new(LlilExpr::Add {
                                        left: Box::new(LlilExpr::RegisterRef {
                                            reg: LlilRegister::Concrete("obj".into()),
                                            size: Size::QWord,
                                        }),
                                        right: Box::new(LlilExpr::Const {
                                            value: 16,
                                            size: Size::QWord,
                                        }),
                                        size: Size::QWord,
                                    }),
                                    size: Size::QWord,
                                },
                            },
                        }
                    },
                ],
                successors: vec![],
            }],
            ..Default::default()
        };
        let layout = StructLayoutInference::run(&func);
        let s = layout.structs.get("obj").expect("inferred");
        // Largest offset 16 + 8 byte field = 24.
        assert_eq!(s.total_size, 24);
    }
}
