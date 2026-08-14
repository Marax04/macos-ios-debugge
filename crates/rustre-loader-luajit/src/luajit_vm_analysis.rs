//! `LuaJIT` VM and trace IR analysis.
//!
//! Provides structures for analysing `LuaJIT`'s internal trace IR (intermediate
//! representation), trace snapshots, IR constants, and JIT optimisation
//! passes as applied to a recording.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LjError {
    InvalidTraceHeader,
    TruncatedIr { slot: usize },
    UnknownIrOp(u16),
    InvalidSnapshot { trace_id: u32 },
    TooManyInstructions(usize),
    InvalidConstType(u8),
    SlotOutOfRange { slot: usize, max: usize },
    CyclicDependency,
    InvalidGcRef(u64),
    TraceAborted { reason: String },
}

impl std::fmt::Display for LjError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTraceHeader => write!(f, "invalid LuaJIT trace header"),
            Self::TruncatedIr { slot } => write!(f, "truncated IR at slot {slot}"),
            Self::UnknownIrOp(op) => write!(f, "unknown IR opcode {op:#06x}"),
            Self::InvalidSnapshot { trace_id } => write!(f, "invalid snapshot in trace {trace_id}"),
            Self::TooManyInstructions(n) => write!(f, "too many IR instructions: {n}"),
            Self::InvalidConstType(t) => write!(f, "invalid const type {t}"),
            Self::SlotOutOfRange { slot, max } => write!(f, "slot {slot} out of range [0,{max})"),
            Self::CyclicDependency => write!(f, "cyclic dependency in trace IR"),
            Self::InvalidGcRef(r) => write!(f, "invalid GC reference {r:#x}"),
            Self::TraceAborted { reason } => write!(f, "trace aborted: {reason}"),
        }
    }
}

impl std::error::Error for LjError {}

// ---------------------------------------------------------------------------
// IR opcodes (representative subset of LuaJIT IR)
// ---------------------------------------------------------------------------

/// `LuaJIT` IR operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum IrOp {
    // Constants
    KGC = 0x00,  // GC object constant
    KPRI = 0x01, // Primitive (nil/false/true)
    KINT = 0x02, // int32 constant
    KI64 = 0x03, // int64 constant
    KU64 = 0x04, // uint64 constant
    KNum = 0x05, // double constant

    // Loads
    LdVar = 0x10,
    LdGVar = 0x11,
    LdUpVar = 0x12,
    LdTMeth = 0x13,
    LdField = 0x14,
    LdTab = 0x15,
    LdTabB = 0x16,

    // Stores
    StGVar = 0x20,
    StUpVar = 0x21,
    StField = 0x22,
    StTab = 0x23,

    // Arithmetic
    Add = 0x30,
    Sub = 0x31,
    Mul = 0x32,
    Div = 0x33,
    Mod = 0x34,
    Pow = 0x35,
    Unm = 0x36,
    AddOv = 0x37,
    SubOv = 0x38,
    MulOv = 0x39,
    Abs = 0x3a,
    Atan2 = 0x3b,
    LdLen = 0x3c,

    // Comparisons
    Eq = 0x40,
    Ne = 0x41,
    Lt = 0x42,
    Le = 0x43,
    Gt = 0x44,
    Ge = 0x45,

    // Bit ops
    Band = 0x50,
    Bor = 0x51,
    Bxor = 0x52,
    Bshl = 0x53,
    Bshr = 0x54,
    Bsar = 0x55,
    Brol = 0x56,
    Bror = 0x57,
    Bnot = 0x58,
    Bswap = 0x59,

    // Conversions
    ToInt = 0x60,
    ToNum = 0x61,
    ToStr = 0x62,
    ToI64 = 0x63,
    ToU64 = 0x64,

    // Calls
    CallN = 0x70,
    CallL = 0x71,
    CallXS = 0x72,
    FunCw = 0x73,
    FunCF = 0x74,
    FunLua = 0x75,

    // GC / Alloc
    GcAlloc = 0x80,
    GcStep = 0x81,
    GcBarrier = 0x82,
    TNew = 0x83,
    TNxt = 0x84,
    TabNew = 0x85,

    // Guards / side exits
    Guard = 0x90,
    GuardN = 0x91,
    Exit = 0x92,

    // Loop
    Loop = 0xa0,
    Phi = 0xa1,

    // Misc
    Nop = 0xf0,
    Rename = 0xf1,
}

impl IrOp {
    pub fn from_u16(v: u16) -> Result<Self, LjError> {
        let ops: &[(u16, Self)] = &[
            (0x00, Self::KGC),
            (0x01, Self::KPRI),
            (0x02, Self::KINT),
            (0x03, Self::KI64),
            (0x04, Self::KU64),
            (0x05, Self::KNum),
            (0x10, Self::LdVar),
            (0x11, Self::LdGVar),
            (0x12, Self::LdUpVar),
            (0x13, Self::LdTMeth),
            (0x14, Self::LdField),
            (0x15, Self::LdTab),
            (0x16, Self::LdTabB),
            (0x20, Self::StGVar),
            (0x21, Self::StUpVar),
            (0x22, Self::StField),
            (0x23, Self::StTab),
            (0x30, Self::Add),
            (0x31, Self::Sub),
            (0x32, Self::Mul),
            (0x33, Self::Div),
            (0x34, Self::Mod),
            (0x35, Self::Pow),
            (0x36, Self::Unm),
            (0x37, Self::AddOv),
            (0x38, Self::SubOv),
            (0x39, Self::MulOv),
            (0x3a, Self::Abs),
            (0x3b, Self::Atan2),
            (0x3c, Self::LdLen),
            (0x40, Self::Eq),
            (0x41, Self::Ne),
            (0x42, Self::Lt),
            (0x43, Self::Le),
            (0x44, Self::Gt),
            (0x45, Self::Ge),
            (0x50, Self::Band),
            (0x51, Self::Bor),
            (0x52, Self::Bxor),
            (0x53, Self::Bshl),
            (0x54, Self::Bshr),
            (0x55, Self::Bsar),
            (0x56, Self::Brol),
            (0x57, Self::Bror),
            (0x58, Self::Bnot),
            (0x59, Self::Bswap),
            (0x60, Self::ToInt),
            (0x61, Self::ToNum),
            (0x62, Self::ToStr),
            (0x63, Self::ToI64),
            (0x64, Self::ToU64),
            (0x70, Self::CallN),
            (0x71, Self::CallL),
            (0x72, Self::CallXS),
            (0x73, Self::FunCw),
            (0x74, Self::FunCF),
            (0x75, Self::FunLua),
            (0x80, Self::GcAlloc),
            (0x81, Self::GcStep),
            (0x82, Self::GcBarrier),
            (0x83, Self::TNew),
            (0x84, Self::TNxt),
            (0x85, Self::TabNew),
            (0x90, Self::Guard),
            (0x91, Self::GuardN),
            (0x92, Self::Exit),
            (0xa0, Self::Loop),
            (0xa1, Self::Phi),
            (0xf0, Self::Nop),
            (0xf1, Self::Rename),
        ];
        for &(code, op) in ops {
            if code == v {
                return Ok(op);
            }
        }
        Err(LjError::UnknownIrOp(v))
    }

    #[must_use]
    pub const fn is_const(self) -> bool {
        matches!(
            self,
            Self::KGC | Self::KPRI | Self::KINT | Self::KI64 | Self::KU64 | Self::KNum
        )
    }
    #[must_use]
    pub const fn is_load(self) -> bool {
        (self as u16) >> 4 == 1
    }
    #[must_use]
    pub const fn is_store(self) -> bool {
        (self as u16) >> 4 == 2
    }
    #[must_use]
    pub const fn is_arith(self) -> bool {
        (self as u16) >> 4 == 3
    }
    #[must_use]
    pub const fn is_cmp(self) -> bool {
        (self as u16) >> 4 == 4
    }
    #[must_use]
    pub const fn is_call(self) -> bool {
        (self as u16) >> 4 == 7
    }
    #[must_use]
    pub const fn is_guard(self) -> bool {
        (self as u16) >> 4 == 9
    }
}

// ---------------------------------------------------------------------------
// IrConst
// ---------------------------------------------------------------------------

/// A typed constant in the IR constant pool.
#[derive(Debug, Clone)]
pub enum IrConst {
    Int(i32),
    I64(i64),
    U64(u64),
    Num(f64),
    /// Primitive: nil=0, false=1, true=2.
    Prim(u8),
    /// GC-managed reference (address).
    GcRef(u64),
    /// String constant.
    Str(String),
}

impl IrConst {
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Int(_) => "int",
            Self::I64(_) => "i64",
            Self::U64(_) => "u64",
            Self::Num(_) => "num",
            Self::Prim(_) => "prim",
            Self::GcRef(_) => "gcref",
            Self::Str(_) => "str",
        }
    }

    #[must_use]
    pub const fn as_i32(&self) -> Option<i32> {
        if let Self::Int(v) = self {
            Some(*v)
        } else {
            None
        }
    }
    #[must_use]
    pub const fn as_f64(&self) -> Option<f64> {
        if let Self::Num(v) = self {
            Some(*v)
        } else {
            None
        }
    }
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        if let Self::Str(s) = self {
            Some(s)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// IrInstruction
// ---------------------------------------------------------------------------

/// One `LuaJIT` IR instruction.
#[derive(Debug, Clone)]
pub struct IrInstruction {
    /// IR slot index (1-based, matching `LuaJIT`'s conventions).
    pub slot: u32,
    pub op: IrOp,
    /// Left operand slot reference (0 = none).
    pub op1: u32,
    /// Right operand slot reference (0 = none).
    pub op2: u32,
    /// Type tag.
    pub ir_type: u8,
    /// Whether this instruction has been marked as a PHI join point.
    pub is_phi: bool,
    /// Optional constant value for constant opcodes.
    pub constant: Option<IrConst>,
}

impl IrInstruction {
    #[must_use]
    pub const fn new(slot: u32, op: IrOp, op1: u32, op2: u32, ir_type: u8) -> Self {
        Self {
            slot,
            op,
            op1,
            op2,
            ir_type,
            is_phi: false,
            constant: None,
        }
    }

    #[must_use]
    pub const fn new_const(slot: u32, op: IrOp, constant: IrConst, ir_type: u8) -> Self {
        Self {
            slot,
            op,
            op1: 0,
            op2: 0,
            ir_type,
            is_phi: false,
            constant: Some(constant),
        }
    }

    /// `true` if this slot has operand references to process.
    #[must_use]
    pub const fn has_operands(&self) -> bool {
        self.op1 != 0 || self.op2 != 0
    }
}

// ---------------------------------------------------------------------------
// SnapshotEntry
// ---------------------------------------------------------------------------

/// One slot entry in an IR snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotEntry {
    /// Stack slot index.
    pub slot: i16,
    /// IR reference (slot number of the IR instruction whose value lives here).
    pub ref_slot: u32,
}

impl SnapshotEntry {
    #[must_use]
    pub const fn new(slot: i16, ref_slot: u32) -> Self {
        Self { slot, ref_slot }
    }
}

// ---------------------------------------------------------------------------
// IrSnapshot
// ---------------------------------------------------------------------------

/// A snapshot of the interpreter stack state at a side-exit point.
#[derive(Debug, Clone)]
pub struct IrSnapshot {
    /// IR instruction slot at which this snapshot was taken.
    pub ir_ref: u32,
    /// PC offset (bytecode instruction index) for the associated side exit.
    pub pc_offset: u32,
    /// Number of stack frames covered.
    pub nframelinks: u16,
    /// Snapshot slot entries.
    pub entries: Vec<SnapshotEntry>,
}

impl IrSnapshot {
    #[must_use]
    pub const fn new(ir_ref: u32, pc_offset: u32) -> Self {
        Self {
            ir_ref,
            pc_offset,
            nframelinks: 0,
            entries: vec![],
        }
    }

    /// Number of live values captured.
    #[must_use]
    pub const fn live_value_count(&self) -> usize {
        self.entries.len()
    }

    /// Find the IR slot for a given stack slot, if present.
    #[must_use]
    pub fn find_slot(&self, slot: i16) -> Option<u32> {
        self.entries
            .iter()
            .find(|e| e.slot == slot)
            .map(|e| e.ref_slot)
    }
}

// ---------------------------------------------------------------------------
// JitOptimization
// ---------------------------------------------------------------------------

/// A JIT optimisation pass applied to a trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JitOptimization {
    DeadCodeElimination { removed: usize },
    ConstantFolding { folded: usize },
    LoopUnrolling { unroll_factor: u32 },
    Inlining { callee: String },
    AliasAnalysis { resolved: usize },
    EscapeAnalysis { escaped: usize },
    RegisterAllocation { spills: usize },
    GuardElimination { eliminated: usize },
    SinkingOptimization { sunk: usize },
    NarrowingConversion { narrowed: usize },
}

impl JitOptimization {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::DeadCodeElimination { .. } => "DCE",
            Self::ConstantFolding { .. } => "CF",
            Self::LoopUnrolling { .. } => "LU",
            Self::Inlining { .. } => "INL",
            Self::AliasAnalysis { .. } => "AA",
            Self::EscapeAnalysis { .. } => "EA",
            Self::RegisterAllocation { .. } => "RA",
            Self::GuardElimination { .. } => "GE",
            Self::SinkingOptimization { .. } => "SINK",
            Self::NarrowingConversion { .. } => "NARROW",
        }
    }

    #[must_use]
    pub const fn impact_score(&self) -> u32 {
        match self {
            Self::DeadCodeElimination { removed } => *removed as u32,
            Self::ConstantFolding { folded } => *folded as u32,
            Self::LoopUnrolling { unroll_factor } => *unroll_factor * 10,
            Self::GuardElimination { eliminated } => *eliminated as u32 * 5,
            Self::Inlining { .. } => 20,
            _ => 1,
        }
    }
}

// ---------------------------------------------------------------------------
// TraceIr
// ---------------------------------------------------------------------------

/// One complete JIT trace with its IR.
#[derive(Debug, Clone)]
pub struct TraceIr {
    pub trace_id: u32,
    pub parent_trace_id: Option<u32>,
    pub instructions: Vec<IrInstruction>,
    pub snapshots: Vec<IrSnapshot>,
    pub constants: Vec<IrConst>,
    pub optimizations: Vec<JitOptimization>,
    /// `true` if this trace has a loop.
    pub has_loop: bool,
    /// Native code size in bytes (0 if not compiled yet).
    pub native_size: u32,
}

impl TraceIr {
    #[must_use]
    pub const fn new(id: u32) -> Self {
        Self {
            trace_id: id,
            parent_trace_id: None,
            instructions: Vec::new(),
            snapshots: Vec::new(),
            constants: Vec::new(),
            optimizations: Vec::new(),
            has_loop: false,
            native_size: 0,
        }
    }

    /// Find an instruction by slot.
    #[must_use]
    pub fn instruction_at(&self, slot: u32) -> Option<&IrInstruction> {
        self.instructions.iter().find(|i| i.slot == slot)
    }

    /// All guard instructions.
    #[must_use]
    pub fn guards(&self) -> Vec<&IrInstruction> {
        self.instructions
            .iter()
            .filter(|i| i.op.is_guard())
            .collect()
    }

    /// All arithmetic instructions.
    #[must_use]
    pub fn arith_instructions(&self) -> Vec<&IrInstruction> {
        self.instructions
            .iter()
            .filter(|i| i.op.is_arith())
            .collect()
    }

    /// Total impact score of all optimisations.
    #[must_use]
    pub fn optimization_score(&self) -> u32 {
        self.optimizations.iter().map(JitOptimization::impact_score).sum()
    }

    /// Number of side exits (one per snapshot).
    #[must_use]
    pub const fn side_exit_count(&self) -> usize {
        self.snapshots.len()
    }

    /// `true` if the trace was compiled to native code.
    #[must_use]
    pub const fn is_compiled(&self) -> bool {
        self.native_size > 0
    }
}

// ---------------------------------------------------------------------------
// LuaJitVmAnalysis  -  top-level aggregator
// ---------------------------------------------------------------------------

/// Complete `LuaJIT` VM analysis across all traces.
#[derive(Debug, Default)]
pub struct LuaJitVmAnalysis {
    pub traces: Vec<TraceIr>,
    trace_by_id: HashMap<u32, usize>,
}

impl LuaJitVmAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_trace(&mut self, trace: TraceIr) {
        let idx = self.traces.len();
        self.trace_by_id.insert(trace.trace_id, idx);
        self.traces.push(trace);
    }

    #[must_use]
    pub fn find_trace(&self, id: u32) -> Option<&TraceIr> {
        self.trace_by_id.get(&id).map(|&i| &self.traces[i])
    }

    /// All compiled traces.
    #[must_use]
    pub fn compiled_traces(&self) -> Vec<&TraceIr> {
        self.traces.iter().filter(|t| t.is_compiled()).collect()
    }

    /// Trace with the highest optimisation score.
    #[must_use]
    pub fn hottest_trace(&self) -> Option<&TraceIr> {
        self.traces.iter().max_by_key(|t| t.optimization_score())
    }

    /// Total native code size across all compiled traces.
    #[must_use]
    pub fn total_native_size(&self) -> u64 {
        self.traces.iter().map(|t| u64::from(t.native_size)).sum()
    }

    /// All traces that have loops.
    #[must_use]
    pub fn loop_traces(&self) -> Vec<&TraceIr> {
        self.traces.iter().filter(|t| t.has_loop).collect()
    }
}

// ---------------------------------------------------------------------------
// MCodePatch  -  native code patch for JIT traces
// ---------------------------------------------------------------------------

/// A single patch to apply to JIT-compiled native code.
#[derive(Debug, Clone)]
pub struct MCodePatch {
    /// Offset in the native code buffer.
    pub offset: u32,
    /// Replacement bytes.
    pub bytes: Vec<u8>,
    /// Reason for this patch.
    pub reason: String,
}

impl MCodePatch {
    pub fn new(offset: u32, bytes: Vec<u8>, reason: impl Into<String>) -> Self {
        Self {
            offset,
            bytes,
            reason: reason.into(),
        }
    }

    /// Apply this patch to a mutable buffer.
    pub fn apply(&self, buf: &mut [u8]) -> bool {
        let end = self.offset as usize + self.bytes.len();
        if end > buf.len() {
            return false;
        }
        buf[self.offset as usize..end].copy_from_slice(&self.bytes);
        true
    }
}

// ---------------------------------------------------------------------------
// IrDCE  -  Dead Code Elimination pass
// ---------------------------------------------------------------------------

/// Dead code elimination over the IR.
pub struct IrDce;

impl IrDce {
    /// Remove instructions with no side effects whose result is unused.
    /// Returns the number of instructions removed.
    pub fn run(trace: &mut TraceIr) -> usize {
        let mut used = std::collections::HashSet::new();
        // Mark all operand references as used
        for instr in &trace.instructions {
            if instr.op1 != 0 {
                used.insert(instr.op1);
            }
            if instr.op2 != 0 {
                used.insert(instr.op2);
            }
        }
        let before = trace.instructions.len();
        trace.instructions.retain(|i| {
            // Guards, stores, calls always have side effects  -  keep them.
            if i.op.is_guard() || i.op.is_store() || i.op.is_call() {
                return true;
            }
            // Loops and phi nodes
            if matches!(i.op, IrOp::Loop | IrOp::Phi) {
                return true;
            }
            // Keep if result is used
            used.contains(&i.slot)
        });
        let removed = before - trace.instructions.len();
        if removed > 0 {
            trace
                .optimizations
                .push(JitOptimization::DeadCodeElimination { removed });
        }
        removed
    }
}

// ---------------------------------------------------------------------------
// IrConstFolding  -  Constant folding pass
// ---------------------------------------------------------------------------

/// Constant folding over the IR.
pub struct IrConstFolding;

impl IrConstFolding {
    /// Fold constant arithmetic instructions.
    /// Returns the number of folds applied.
    pub fn run(trace: &mut TraceIr) -> usize {
        let mut folded = 0;
        // Build a map of slot  ->  const value for quick lookup
        let const_map: HashMap<u32, i32> = trace
            .instructions
            .iter()
            .filter_map(|i| {
                if let (Some(IrConst::Int(v)), _) = (&i.constant, i.op) {
                    if i.op.is_const() {
                        Some((i.slot, *v))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        for instr in &mut trace.instructions {
            if instr.op.is_arith() && instr.op1 != 0 && instr.op2 != 0
                && let (Some(&a), Some(&b)) = (const_map.get(&instr.op1), const_map.get(&instr.op2))
                {
                    let result = match instr.op {
                        IrOp::Add => Some(a.wrapping_add(b)),
                        IrOp::Sub => Some(a.wrapping_sub(b)),
                        IrOp::Mul => Some(a.wrapping_mul(b)),
                        IrOp::Div if b != 0 => Some(a / b),
                        _ => None,
                    };
                    if let Some(v) = result {
                        instr.op = IrOp::KINT;
                        instr.constant = Some(IrConst::Int(v));
                        instr.op1 = 0;
                        instr.op2 = 0;
                        folded += 1;
                    }
                }
        }
        if folded > 0 {
            trace
                .optimizations
                .push(JitOptimization::ConstantFolding { folded });
        }
        folded
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// IrRegisterAllocator  -  linear scan register allocation for JIT
// ---------------------------------------------------------------------------

/// One interval in a linear-scan register allocator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveInterval {
    pub slot: u32,
    pub start: u32,
    pub end: u32,
    pub assigned_reg: Option<u8>,
    pub is_spilled: bool,
}

impl LiveInterval {
    #[must_use]
    pub const fn new(slot: u32, start: u32, end: u32) -> Self {
        Self {
            slot,
            start,
            end,
            assigned_reg: None,
            is_spilled: false,
        }
    }

    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    #[must_use]
    pub const fn length(&self) -> u32 {
        self.end.saturating_sub(self.start)
    }
}

/// Minimal linear-scan register allocator for IR slots.
#[derive(Debug, Default)]
pub struct IrRegisterAllocator {
    pub intervals: Vec<LiveInterval>,
    pub num_physical_regs: u8,
    pub spill_count: usize,
}

impl IrRegisterAllocator {
    #[must_use]
    pub const fn new(num_regs: u8) -> Self {
        Self {
            intervals: Vec::new(),
            num_physical_regs: num_regs,
            spill_count: 0,
        }
    }

    pub fn add_interval(&mut self, interval: LiveInterval) {
        self.intervals.push(interval);
    }

    /// Perform linear-scan allocation.
    pub fn allocate(&mut self) {
        // Sort by start point
        self.intervals.sort_by_key(|i| i.start);
        let mut active: Vec<usize> = Vec::new();
        let mut free_regs: Vec<u8> = (0..self.num_physical_regs).collect();

        for i in 0..self.intervals.len() {
            // Expire old intervals
            let cur_start = self.intervals[i].start;
            active.retain(|&j| {
                if self.intervals[j].end <= cur_start {
                    // Release the register
                    if let Some(r) = self.intervals[j].assigned_reg {
                        free_regs.push(r);
                        free_regs.sort_unstable();
                    }
                    false
                } else {
                    true
                }
            });

            if free_regs.is_empty() {
                // Spill the interval with the farthest end
                if let Some(&spill_idx) = active.iter().max_by_key(|&&j| self.intervals[j].end) {
                    if self.intervals[spill_idx].end > self.intervals[i].end {
                        let reg = self.intervals[spill_idx].assigned_reg.take();
                        self.intervals[spill_idx].is_spilled = true;
                        self.spill_count += 1;
                        self.intervals[i].assigned_reg = reg;
                        active.retain(|&j| j != spill_idx);
                        active.push(i);
                    } else {
                        self.intervals[i].is_spilled = true;
                        self.spill_count += 1;
                    }
                }
            } else {
                let reg = free_regs.remove(0);
                self.intervals[i].assigned_reg = Some(reg);
                active.push(i);
            }
        }
    }

    #[must_use]
    pub fn allocated_count(&self) -> usize {
        self.intervals
            .iter()
            .filter(|i| i.assigned_reg.is_some())
            .count()
    }
}

// ---------------------------------------------------------------------------
// TraceRecorder  -  simulates LuaJIT trace recording
// ---------------------------------------------------------------------------

/// State of a trace being recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingState {
    /// Idle  -  no trace in progress.
    Idle,
    /// Recording  -  capturing instructions.
    Recording { pc: u32 },
    /// Stitching  -  linking trace to parent.
    Stitching { trace_id: u32 },
    /// Aborted  -  recording was cancelled.
    Aborted,
}

/// Records `LuaJIT` trace IR during JIT compilation.
#[derive(Debug)]
pub struct TraceRecorder {
    pub state: RecordingState,
    pub current_trace: Option<TraceIr>,
    pub abort_reasons: Vec<String>,
    /// Maximum number of IR instructions before aborting.
    pub max_ir_instructions: usize,
}

impl TraceRecorder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: RecordingState::Idle,
            current_trace: None,
            abort_reasons: Vec::new(),
            max_ir_instructions: 4096,
        }
    }

    /// Start recording a new trace.
    pub fn start(&mut self, trace_id: u32, pc: u32) {
        self.state = RecordingState::Recording { pc };
        self.current_trace = Some(TraceIr::new(trace_id));
    }

    /// Emit one IR instruction.
    pub fn emit(&mut self, instr: IrInstruction) -> Result<(), LjError> {
        let trace = self
            .current_trace
            .as_mut()
            .ok_or(LjError::InvalidTraceHeader)?;
        if trace.instructions.len() >= self.max_ir_instructions {
            self.state = RecordingState::Aborted;
            let reason = format!("too many instructions (>{})", self.max_ir_instructions);
            self.abort_reasons.push(reason.clone());
            return Err(LjError::TraceAborted { reason });
        }
        trace.instructions.push(instr);
        Ok(())
    }

    /// Finalise and return the completed trace.
    pub const fn finish(&mut self) -> Option<TraceIr> {
        self.state = RecordingState::Idle;
        self.current_trace.take()
    }

    /// Abort the current trace recording.
    pub fn abort(&mut self, reason: impl Into<String>) {
        self.abort_reasons.push(reason.into());
        self.state = RecordingState::Aborted;
        self.current_trace = None;
    }

    #[must_use]
    pub const fn is_recording(&self) -> bool {
        matches!(self.state, RecordingState::Recording { .. })
    }

    #[must_use]
    pub const fn abort_count(&self) -> usize {
        self.abort_reasons.len()
    }
}

impl Default for TraceRecorder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// IrTypeInfo  -  type information attached to IR slots
// ---------------------------------------------------------------------------

/// `LuaJIT` IR type tags (IRT_* constants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrType {
    Nil = 0,
    False = 1,
    True = 2,
    Int = 3,
    U32 = 4,
    I64 = 5,
    U64 = 6,
    Num = 7,
    Tab = 8,
    Func = 9,
    Str = 10,
    Udata = 11,
    P32 = 12,
    P64 = 13,
    CData = 14,
}

impl IrType {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Nil,
            1 => Self::False,
            2 => Self::True,
            3 => Self::Int,
            4 => Self::U32,
            5 => Self::I64,
            6 => Self::U64,
            7 => Self::Num,
            8 => Self::Tab,
            9 => Self::Func,
            10 => Self::Str,
            11 => Self::Udata,
            12 => Self::P32,
            13 => Self::P64,
            14 => Self::CData,
            _ => Self::Nil,
        }
    }

    #[must_use]
    pub const fn is_number(self) -> bool {
        matches!(
            self,
            Self::Int | Self::U32 | Self::I64 | Self::U64 | Self::Num
        )
    }

    #[must_use]
    pub const fn is_gc(self) -> bool {
        matches!(
            self,
            Self::Tab | Self::Func | Self::Str | Self::Udata | Self::CData
        )
    }

    #[must_use]
    pub const fn is_pointer(self) -> bool {
        matches!(self, Self::P32 | Self::P64)
    }

    #[must_use]
    pub const fn size_bytes(self) -> usize {
        match self {
            Self::Int | Self::U32 | Self::P32 | Self::False | Self::True | Self::Nil => 4,
            Self::I64 | Self::U64 | Self::Num | Self::P64 => 8,
            Self::Tab | Self::Func | Self::Str | Self::Udata | Self::CData => 8, // pointer size
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_trace(id: u32) -> TraceIr {
        let mut t = TraceIr::new(id);
        t.instructions
            .push(IrInstruction::new_const(1, IrOp::KINT, IrConst::Int(42), 0));
        t.instructions
            .push(IrInstruction::new(2, IrOp::Add, 1, 1, 0));
        t.instructions
            .push(IrInstruction::new(3, IrOp::Guard, 2, 0, 0));
        t
    }

    // ---- IrOp ----

    #[test]
    fn test_irop_from_u16_valid() {
        assert_eq!(IrOp::from_u16(0x30).unwrap(), IrOp::Add);
        assert_eq!(IrOp::from_u16(0x00).unwrap(), IrOp::KGC);
    }

    #[test]
    fn test_irop_from_u16_unknown() {
        assert!(matches!(
            IrOp::from_u16(0xbeef),
            Err(LjError::UnknownIrOp(0xbeef))
        ));
    }

    #[test]
    fn test_irop_is_const() {
        assert!(IrOp::KINT.is_const());
        assert!(!IrOp::Add.is_const());
    }

    #[test]
    fn test_irop_is_arith() {
        assert!(IrOp::Add.is_arith());
        assert!(IrOp::Sub.is_arith());
        assert!(!IrOp::Guard.is_arith());
    }

    #[test]
    fn test_irop_is_cmp() {
        assert!(IrOp::Eq.is_cmp());
        assert!(!IrOp::Add.is_cmp());
    }

    #[test]
    fn test_irop_is_guard() {
        assert!(IrOp::Guard.is_guard());
        assert!(!IrOp::Add.is_guard());
    }

    #[test]
    fn test_irop_is_call() {
        assert!(IrOp::CallN.is_call());
        assert!(!IrOp::Add.is_call());
    }

    #[test]
    fn test_irop_is_load() {
        assert!(IrOp::LdVar.is_load());
        assert!(!IrOp::Add.is_load());
    }

    #[test]
    fn test_irop_is_store() {
        assert!(IrOp::StGVar.is_store());
        assert!(!IrOp::LdVar.is_store());
    }

    // ---- IrConst ----

    #[test]
    fn test_irconst_type_names() {
        assert_eq!(IrConst::Int(0).type_name(), "int");
        assert_eq!(IrConst::Num(0.0).type_name(), "num");
        assert_eq!(IrConst::Str("hi".into()).type_name(), "str");
        assert_eq!(IrConst::GcRef(0).type_name(), "gcref");
    }

    #[test]
    fn test_irconst_as_i32() {
        assert_eq!(IrConst::Int(99).as_i32(), Some(99));
        assert!(IrConst::Num(1.0).as_i32().is_none());
    }

    #[test]
    fn test_irconst_as_f64() {
        let c = IrConst::Num(3.14_f64);
        assert!((c.as_f64().unwrap() - 3.14_f64).abs() < 1e-9);
    }

    #[test]
    fn test_irconst_as_str() {
        let c = IrConst::Str("hello".into());
        assert_eq!(c.as_str(), Some("hello"));
    }

    // ---- IrInstruction ----

    #[test]
    fn test_ir_instruction_has_operands() {
        let i = IrInstruction::new(1, IrOp::Add, 2, 3, 0);
        assert!(i.has_operands());
    }

    #[test]
    fn test_ir_instruction_no_operands() {
        let i = IrInstruction::new(1, IrOp::Nop, 0, 0, 0);
        assert!(!i.has_operands());
    }

    // ---- IrSnapshot ----

    #[test]
    fn test_snapshot_find_slot() {
        let mut snap = IrSnapshot::new(5, 10);
        snap.entries.push(SnapshotEntry::new(3, 42));
        assert_eq!(snap.find_slot(3), Some(42));
        assert!(snap.find_slot(4).is_none());
    }

    #[test]
    fn test_snapshot_live_count() {
        let mut snap = IrSnapshot::new(1, 0);
        snap.entries.push(SnapshotEntry::new(0, 1));
        snap.entries.push(SnapshotEntry::new(1, 2));
        assert_eq!(snap.live_value_count(), 2);
    }

    // ---- JitOptimization ----

    #[test]
    fn test_opt_names() {
        assert_eq!(
            JitOptimization::DeadCodeElimination { removed: 5 }.name(),
            "DCE"
        );
        assert_eq!(
            JitOptimization::LoopUnrolling { unroll_factor: 4 }.name(),
            "LU"
        );
        assert_eq!(
            JitOptimization::Inlining {
                callee: "foo".into()
            }
            .name(),
            "INL"
        );
    }

    #[test]
    fn test_opt_impact_score_dce() {
        let o = JitOptimization::DeadCodeElimination { removed: 10 };
        assert_eq!(o.impact_score(), 10);
    }

    #[test]
    fn test_opt_impact_score_loop_unroll() {
        let o = JitOptimization::LoopUnrolling { unroll_factor: 4 };
        assert_eq!(o.impact_score(), 40);
    }

    #[test]
    fn test_opt_impact_score_guard_elim() {
        let o = JitOptimization::GuardElimination { eliminated: 3 };
        assert_eq!(o.impact_score(), 15);
    }

    // ---- TraceIr ----

    #[test]
    fn test_trace_instruction_at() {
        let t = simple_trace(1);
        assert!(t.instruction_at(1).is_some());
        assert!(t.instruction_at(99).is_none());
    }

    #[test]
    fn test_trace_guards() {
        let t = simple_trace(1);
        assert_eq!(t.guards().len(), 1);
    }

    #[test]
    fn test_trace_arith() {
        let t = simple_trace(1);
        assert_eq!(t.arith_instructions().len(), 1);
    }

    #[test]
    fn test_trace_is_compiled_false() {
        let t = simple_trace(1);
        assert!(!t.is_compiled());
    }

    #[test]
    fn test_trace_is_compiled_true() {
        let mut t = simple_trace(1);
        t.native_size = 256;
        assert!(t.is_compiled());
    }

    #[test]
    fn test_trace_optimization_score() {
        let mut t = simple_trace(1);
        t.optimizations
            .push(JitOptimization::DeadCodeElimination { removed: 5 });
        t.optimizations
            .push(JitOptimization::ConstantFolding { folded: 3 });
        assert_eq!(t.optimization_score(), 8);
    }

    #[test]
    fn test_trace_side_exit_count() {
        let mut t = simple_trace(1);
        t.snapshots.push(IrSnapshot::new(3, 10));
        t.snapshots.push(IrSnapshot::new(5, 20));
        assert_eq!(t.side_exit_count(), 2);
    }

    // ---- LuaJitVmAnalysis ----

    #[test]
    fn test_analysis_add_and_find_trace() {
        let mut a = LuaJitVmAnalysis::new();
        a.add_trace(simple_trace(42));
        assert!(a.find_trace(42).is_some());
        assert!(a.find_trace(99).is_none());
    }

    #[test]
    fn test_analysis_compiled_traces() {
        let mut a = LuaJitVmAnalysis::new();
        let mut t1 = simple_trace(1);
        t1.native_size = 128;
        a.add_trace(t1);
        a.add_trace(simple_trace(2));
        assert_eq!(a.compiled_traces().len(), 1);
    }

    #[test]
    fn test_analysis_total_native_size() {
        let mut a = LuaJitVmAnalysis::new();
        let mut t1 = simple_trace(1);
        t1.native_size = 100;
        let mut t2 = simple_trace(2);
        t2.native_size = 200;
        a.add_trace(t1);
        a.add_trace(t2);
        assert_eq!(a.total_native_size(), 300);
    }

    #[test]
    fn test_analysis_loop_traces() {
        let mut a = LuaJitVmAnalysis::new();
        let mut t1 = simple_trace(1);
        t1.has_loop = true;
        a.add_trace(t1);
        a.add_trace(simple_trace(2));
        assert_eq!(a.loop_traces().len(), 1);
    }

    #[test]
    fn test_analysis_hottest_trace() {
        let mut a = LuaJitVmAnalysis::new();
        let mut t1 = simple_trace(1);
        t1.optimizations
            .push(JitOptimization::DeadCodeElimination { removed: 100 });
        let t2 = simple_trace(2);
        a.add_trace(t1);
        a.add_trace(t2);
        assert_eq!(a.hottest_trace().unwrap().trace_id, 1);
    }

    #[test]
    fn test_lj_error_display() {
        let e = LjError::UnknownIrOp(0xff);
        assert!(e.to_string().contains("ff"));
        let e2 = LjError::TraceAborted {
            reason: "NYI: test".into(),
        };
        assert!(e2.to_string().contains("NYI"));
    }

    #[test]
    fn test_snapshot_entry_construction() {
        let e = SnapshotEntry::new(-1, 5);
        assert_eq!(e.slot, -1);
        assert_eq!(e.ref_slot, 5);
    }

    #[test]
    fn test_irop_all_bitops_are_bitops() {
        for op in [IrOp::Band, IrOp::Bor, IrOp::Bxor, IrOp::Bshl, IrOp::Bshr] {
            // bit ops live in 0x5x range, not arith (0x3x)
            assert!(!op.is_arith(), "{op:?} should not be arith");
        }
    }

    #[test]
    fn test_trace_parent_id() {
        let mut t = TraceIr::new(5);
        t.parent_trace_id = Some(3);
        assert_eq!(t.parent_trace_id, Some(3));
    }

    #[test]
    fn test_trace_constants_store() {
        let mut t = TraceIr::new(1);
        t.constants.push(IrConst::Int(99));
        t.constants.push(IrConst::Str("hello".into()));
        assert_eq!(t.constants.len(), 2);
    }

    #[test]
    fn test_jit_opt_constant_folding() {
        let o = JitOptimization::ConstantFolding { folded: 7 };
        assert_eq!(o.name(), "CF");
        assert_eq!(o.impact_score(), 7);
    }

    #[test]
    fn test_jit_opt_alias_analysis() {
        let o = JitOptimization::AliasAnalysis { resolved: 4 };
        assert_eq!(o.name(), "AA");
    }

    #[test]
    fn test_jit_opt_escape_analysis() {
        let o = JitOptimization::EscapeAnalysis { escaped: 2 };
        assert_eq!(o.name(), "EA");
    }

    #[test]
    fn test_jit_opt_sinking() {
        let o = JitOptimization::SinkingOptimization { sunk: 3 };
        assert_eq!(o.name(), "SINK");
    }

    #[test]
    fn test_jit_opt_narrowing() {
        let o = JitOptimization::NarrowingConversion { narrowed: 5 };
        assert_eq!(o.name(), "NARROW");
    }

    #[test]
    fn test_ir_const_prim() {
        let c = IrConst::Prim(0);
        assert_eq!(c.type_name(), "prim");
        assert!(c.as_i32().is_none());
    }

    #[test]
    fn test_analysis_no_traces() {
        let a = LuaJitVmAnalysis::new();
        assert!(a.hottest_trace().is_none());
        assert_eq!(a.total_native_size(), 0);
    }

    #[test]
    fn test_lj_error_slot_out_of_range() {
        let e = LjError::SlotOutOfRange { slot: 10, max: 8 };
        assert!(e.to_string().contains("10"));
    }

    #[test]
    fn test_ir_instruction_const_slot() {
        let i = IrInstruction::new_const(7, IrOp::KINT, IrConst::Int(42), 0);
        assert_eq!(i.slot, 7);
        assert!(i.constant.is_some());
        assert!(!i.has_operands());
    }

    #[test]
    fn test_irop_nop_not_any_category() {
        assert!(!IrOp::Nop.is_const());
        assert!(!IrOp::Nop.is_arith());
        assert!(!IrOp::Nop.is_guard());
    }
}

// ---------------------------------------------------------------------------
// JitTraceStats - per-trace statistics
// ---------------------------------------------------------------------------

/// Statistics for a single JIT trace.
#[derive(Debug, Clone, Default)]
pub struct JitTraceStats {
    pub trace_id: u32,
    pub total_ir_instructions: usize,
    pub guard_count: usize,
    pub call_count: usize,
    pub loop_count: usize,
    pub spill_count: usize,
    pub side_exit_count: usize,
    pub compilation_time_us: u64,
}

impl JitTraceStats {
    #[must_use]
    pub fn from_trace(trace: &TraceIr) -> Self {
        Self {
            trace_id: trace.trace_id,
            total_ir_instructions: trace.instructions.len(),
            guard_count: trace.guards().len(),
            call_count: trace.instructions.iter().filter(|i| i.op.is_call()).count(),
            loop_count: trace
                .instructions
                .iter()
                .filter(|i| matches!(i.op, IrOp::Loop))
                .count(),
            spill_count: 0,
            side_exit_count: trace.side_exit_count(),
            compilation_time_us: 0,
        }
    }
    #[must_use]
    pub fn instructions_per_guard(&self) -> f64 {
        if self.guard_count == 0 {
            return 0.0;
        }
        self.total_ir_instructions as f64 / self.guard_count as f64
    }
}
// ---------------------------------------------------------------------------
// JitHeatMap - per-PC hotness tracking
// ---------------------------------------------------------------------------

/// A hotness map tracking how many times each bytecode PC was compiled.
#[derive(Debug, Default)]
pub struct JitHeatMap {
    pub entries: std::collections::HashMap<u32, u32>,
}

impl JitHeatMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn increment(&mut self, pc: u32) {
        *self.entries.entry(pc).or_insert(0) += 1;
    }
    #[must_use]
    pub fn count(&self, pc: u32) -> u32 {
        *self.entries.get(&pc).unwrap_or(&0)
    }
    #[must_use]
    pub fn hottest_pc(&self) -> Option<(u32, u32)> {
        self.entries
            .iter()
            .max_by_key(|&(_, &v)| v)
            .map(|(&k, &v)| (k, v))
    }
    #[must_use]
    pub fn pcs_above_threshold(&self, threshold: u32) -> Vec<u32> {
        self.entries
            .iter()
            .filter(|&(_, &v)| v >= threshold)
            .map(|(&k, _)| k)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// IrDump - human-readable IR dump
// ---------------------------------------------------------------------------

/// Produce a human-readable dump of a trace's IR.
pub struct IrDump;

impl IrDump {
    #[must_use]
    pub fn dump_trace(trace: &TraceIr) -> String {
        let mut out = format!("=== Trace {} ===\n", trace.trace_id);
        if let Some(pid) = trace.parent_trace_id {
            out += &format!("  parent: {pid}\n");
        }
        out += &format!(
            "  has_loop: {}\n  native_size: {}\n",
            trace.has_loop, trace.native_size
        );
        out += "  IR instructions:\n";
        for i in &trace.instructions {
            let const_str = if let Some(c) = &i.constant {
                format!(" [{}]", c.type_name())
            } else {
                String::new()
            };
            out += &format!(
                "    [{:04}] {:?}  op1={} op2={}{}\n",
                i.slot, i.op, i.op1, i.op2, const_str
            );
        }
        out += &format!("  snapshots: {}\n", trace.snapshots.len());
        out += &format!("  optimizations: {}\n", trace.optimizations.len());
        out
    }
}

// ---------------------------------------------------------------------------
// LuaJitVersionInfo - version detection
// ---------------------------------------------------------------------------

/// `LuaJIT` version detection result.
#[derive(Debug, Clone)]
pub struct LuaJitVersionInfo {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
    pub is_openresty_build: bool,
    pub has_ffi: bool,
    pub has_jit: bool,
}

impl LuaJitVersionInfo {
    #[must_use]
    pub fn version_string(&self) -> String {
        format!("LuaJIT {}.{}.{}", self.major, self.minor, self.patch)
    }

    #[must_use]
    pub const fn is_version_2_1(&self) -> bool {
        self.major == 2 && self.minor == 1
    }
    #[must_use]
    pub const fn is_version_2_0(&self) -> bool {
        self.major == 2 && self.minor == 0
    }
}

// ---------------------------------------------------------------------------
// JitAbortReason - categorised trace abort reasons
// ---------------------------------------------------------------------------

/// Categorised reason for a JIT trace abort.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JitAbortReason {
    TooManyInstructions,
    TooManySideExits,
    NYI, // Not yet implemented
    BlacklistHit,
    RecursionLimit,
    InterruptHook,
    InnerLoopAbort,
    OuterLoopAbort,
    SideExitPatch,
    Other(String),
}

impl JitAbortReason {
    #[must_use]
    pub const fn is_nyi(&self) -> bool {
        matches!(self, Self::NYI)
    }
    #[must_use]
    pub const fn is_instruction_limit(&self) -> bool {
        matches!(self, Self::TooManyInstructions)
    }
    #[must_use]
    pub const fn name(&self) -> &str {
        match self {
            Self::TooManyInstructions => "Too many instructions",
            Self::TooManySideExits => "Too many side exits",
            Self::NYI => "NYI",
            Self::BlacklistHit => "Blacklist hit",
            Self::RecursionLimit => "Recursion limit",
            Self::InterruptHook => "Interrupt hook",
            Self::InnerLoopAbort => "Inner loop abort",
            Self::OuterLoopAbort => "Outer loop abort",
            Self::SideExitPatch => "Side exit patch",
            Self::Other(s) => s.as_str(),
        }
    }
}

// ---------------------------------------------------------------------------
// JitTraceChain - side-trace / root-trace relationship
// ---------------------------------------------------------------------------

/// Chain of traces linked by side exits.
#[derive(Debug, Default)]
pub struct JitTraceChain {
    pub trace_ids: Vec<u32>,
}

impl JitTraceChain {
    #[must_use]
    pub fn new(root: u32) -> Self {
        Self {
            trace_ids: vec![root],
        }
    }
    pub fn extend(&mut self, id: u32) {
        self.trace_ids.push(id);
    }
    #[must_use]
    pub fn root(&self) -> Option<u32> {
        self.trace_ids.first().copied()
    }
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.trace_ids.len()
    }
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/// Read a null-terminated UTF-8 string from a byte slice at `offset`.
#[must_use]
pub fn read_cstring(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map_or(data.len(), |p| offset + p);
    std::str::from_utf8(&data[offset..end])
        .ok()
        .map(std::borrow::ToOwned::to_owned)
}

/// Align a value up to `align` (power-of-two).
#[must_use]
pub const fn align_up(val: u64, align: u64) -> u64 {
    if align == 0 {
        return val;
    }
    (val + align - 1) & !(align - 1)
}

/// Align a value down to `align` (power-of-two).
#[must_use]
pub const fn align_down(val: u64, align: u64) -> u64 {
    if align == 0 {
        return val;
    }
    val & !(align - 1)
}

/// Check whether `val` is a power of two.
#[must_use]
pub const fn is_power_of_two(val: u64) -> bool {
    val != 0 && val.is_power_of_two()
}

/// Simple entropy estimate over a byte slice (0.0 = uniform, 1.0 = random).
#[must_use]
pub fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &freq {
        if c > 0 {
            let p = f64::from(c) / n;
            entropy = p.mul_add(-p.log2(), entropy);
        }
    }
    entropy / 8.0 // normalise to [0, 1]
}

// ---------------------------------------------------------------------------
// Additional parsing utilities
// ---------------------------------------------------------------------------

/// Parse a little-endian u16.
#[inline]
#[must_use]
pub fn le_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[off], data[off + 1]])
}
/// Parse a little-endian u32.
#[inline]
#[must_use]
pub fn le_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}
/// Parse a little-endian u64.
#[inline]
#[must_use]
pub fn le_u64(data: &[u8], off: usize) -> u64 {
    if off + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}
/// Parse a big-endian u32.
#[inline]
#[must_use]
pub fn be_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_be_bytes(data[off..off + 4].try_into().unwrap())
}
/// Verify a 32-bit Adler-32 checksum over `data`.
#[must_use]
pub fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

// ---------------------------------------------------------------------------
// Byte pattern matching utilities
// ---------------------------------------------------------------------------

/// Search `haystack` for the first occurrence of `needle`.
#[must_use]
pub fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Count non-overlapping occurrences of `needle` in `haystack`.
#[must_use]
pub fn count_bytes(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut pos = 0;
    while let Some(idx) = haystack[pos..]
        .windows(needle.len())
        .position(|w| w == needle)
    {
        count += 1;
        pos += idx + needle.len();
    }
    count
}

/// Extract a sub-slice at `offset` with `len`, returning `None` if out of bounds.
#[must_use]
pub fn try_slice(data: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    data.get(offset..offset + len)
}

// Last additions
/// Check if a byte slice is all zeros.
#[must_use]
pub fn is_zeroed(data: &[u8]) -> bool {
    data.iter().all(|&b| b == 0)
}
/// Reverse bytes in-place.
pub const fn reverse_bytes(data: &mut [u8]) {
    data.reverse();
}
/// XOR all bytes with `key`.
pub fn xor_bytes(data: &mut [u8], key: u8) {
    for b in data.iter_mut() {
        *b ^= key;
    }
}
/// Rotate `val` left by `n` bits (32-bit).
#[must_use]
pub const fn rol32(val: u32, n: u32) -> u32 {
    val.rotate_left(n)
}
/// Rotate `val` right by `n` bits (32-bit).
#[must_use]
pub const fn ror32(val: u32, n: u32) -> u32 {
    val.rotate_right(n)
}

/// CRC32 (IEEE polynomial) checksum.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}
/// FNV-1a 32-bit hash.
#[must_use]
pub fn fnv1a32(data: &[u8]) -> u32 {
    let mut h = 2166136261u32;
    for &b in data {
        h ^= u32::from(b);
        h = h.wrapping_mul(16777619);
    }
    h
}

/// `MurmurHash3` 32-bit (simplified, no seed mixing).
#[must_use]
pub fn murmur3_32(data: &[u8], seed: u32) -> u32 {
    let mut h = seed;
    let mut chunks = data.chunks_exact(4);
    for chunk in chunks.by_ref() {
        let mut k = u32::from_le_bytes(chunk.try_into().unwrap());
        k = k.wrapping_mul(0xcc9e2d51);
        k = k.rotate_left(15);
        k = k.wrapping_mul(0x1b873593);
        h ^= k;
        h = h.rotate_left(13);
        h = h.wrapping_mul(5).wrapping_add(0xe6546b64);
    }
    h ^= data.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85ebca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2ae35);
    h ^ (h >> 16)
}
/// SipHash-like 1-liner for IDs.
#[must_use]
pub fn siphash_id(data: &[u8]) -> u64 {
    let mut h: u64 = 0x736f6d6570736575;
    for chunk in data.chunks(8) {
        let mut v = 0u64;
        for (i, &b) in chunk.iter().enumerate() {
            v |= u64::from(b) << (i * 8);
        }
        h ^= v;
        h = h
            .wrapping_add(h.rotate_left(17))
            .wrapping_mul(0xd6e8feb86659fd93);
    }
    h
}
