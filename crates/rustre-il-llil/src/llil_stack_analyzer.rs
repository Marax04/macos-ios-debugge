//! LLIL stack frame analysis.
//!
//! Tracks stack-pointer adjustments and slot accesses to reconstruct the
//! layout of a function's stack frame.  Each distinct offset from the
//! canonical frame pointer becomes a [`StackSlot`], which is given a type,
//! access pattern, and provenance.
//!
//! # Key types
//! - [`StackSlot`]        — one identified slot in the stack frame.
//! - [`StackFrame`]       — the complete recovered frame layout.
//! - [`LlilStackAnalyzer`] — the analysis driver.
//! - [`analyze_stack`]    — convenience entry point.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

// ─────────────────────────────────────────────────────────────────────────────
// StackOffset — signed byte offset from the frame pointer
// ─────────────────────────────────────────────────────────────────────────────

/// A signed byte offset from the canonical frame pointer (e.g. RBP on x86-64).
///
/// Negative values are typical on x86-64 (locals live below the frame pointer).
/// Positive values are seen on ARM-style call frames where the frame pointer
/// points to the bottom of the saved-register area.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StackOffset(pub i64);

impl StackOffset {
    /// Create a new stack offset.
    #[must_use]
    pub const fn new(v: i64) -> Self {
        Self(v)
    }

    /// Return `true` if this offset is below the frame pointer (local variable).
    #[must_use]
    pub const fn is_local(&self) -> bool {
        self.0 < 0
    }

    /// Return `true` if this offset is above the frame pointer (argument / saved
    /// registers).
    #[must_use]
    pub const fn is_above_frame(&self) -> bool {
        self.0 > 0
    }
}

impl std::fmt::Display for StackOffset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 >= 0 {
            write!(f, "+{}", self.0)
        } else {
            write!(f, "{}", self.0)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SlotKind — semantic role of a stack slot
// ─────────────────────────────────────────────────────────────────────────────

/// The semantic role of a stack slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlotKind {
    /// A local variable (temporary storage for the current function).
    LocalVar,
    /// A function argument passed on the stack.
    Argument,
    /// A callee-saved register spill.
    SavedReg,
    /// The return address (pushed by the call instruction).
    ReturnAddress,
    /// Spilled temporary that does not map to a named variable.
    SpilledTemp,
    /// The slot role could not be determined.
    Unknown,
}

impl std::fmt::Display for SlotKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LocalVar => write!(f, "local"),
            Self::Argument => write!(f, "arg"),
            Self::SavedReg => write!(f, "saved_reg"),
            Self::ReturnAddress => write!(f, "ret_addr"),
            Self::SpilledTemp => write!(f, "spill"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StackSlot
// ─────────────────────────────────────────────────────────────────────────────

/// One identified slot in the stack frame.
#[derive(Debug, Clone)]
pub struct StackSlot {
    /// Byte offset from the frame pointer.
    pub offset: StackOffset,
    /// Size of the slot in bytes.
    pub size: u8,
    /// Semantic role.
    pub kind: SlotKind,
    /// Generated name (e.g. `local_-8` or `arg_8`).
    pub name: String,
    /// Number of read accesses to this slot.
    pub reads: usize,
    /// Number of write accesses to this slot.
    pub writes: usize,
    /// Set of program addresses at which this slot was accessed.
    pub access_addrs: HashSet<u64>,
    /// Whether a pointer escape was observed (address of slot taken).
    pub address_taken: bool,
}

impl StackSlot {
    fn new(offset: StackOffset, size: u8) -> Self {
        let kind = if offset.is_local() {
            SlotKind::LocalVar
        } else if offset.is_above_frame() {
            SlotKind::Argument
        } else {
            SlotKind::Unknown
        };
        let name = match kind {
            SlotKind::LocalVar => format!("local_{}", offset.0),
            SlotKind::Argument => format!("arg_{}", offset.0),
            _ => format!("slot_{}", offset.0),
        };
        Self {
            offset,
            size,
            kind,
            name,
            reads: 0,
            writes: 0,
            access_addrs: HashSet::new(),
            address_taken: false,
        }
    }

    /// Return `true` if this slot has been both read and written.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        self.reads > 0 && self.writes > 0
    }

    /// Return `true` if this slot appears to be write-only (never read after
    /// being written — possibly a dead store).
    #[must_use]
    pub const fn is_dead_store_candidate(&self) -> bool {
        self.writes > 0 && self.reads == 0
    }

    /// Byte range `[offset, offset + size)` (in signed offset space).
    #[must_use]
    pub fn range(&self) -> (i64, i64) {
        (self.offset.0, self.offset.0 + i64::from(self.size))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StackFrame
// ─────────────────────────────────────────────────────────────────────────────

/// The complete recovered stack frame layout for a function.
#[derive(Debug, Clone)]
pub struct StackFrame {
    /// All identified slots, sorted by offset.
    pub slots: Vec<StackSlot>,
    /// Total size of the local area (absolute value of the most-negative offset).
    pub local_size: u64,
    /// Number of argument slots detected above the frame pointer.
    pub arg_count: usize,
    /// Whether the frame pointer is used (as opposed to SP-relative addressing).
    pub has_frame_pointer: bool,
    /// The constant by which the stack pointer was adjusted at entry.
    pub sp_adjustment: i64,
    /// Maximum observed alignment of a slot (power of two).
    pub max_alignment: u8,
}

impl StackFrame {
    /// Return the slot at a given offset, if any.
    #[must_use]
    pub fn slot_at(&self, offset: StackOffset) -> Option<&StackSlot> {
        self.slots.iter().find(|s| s.offset == offset)
    }

    /// Return all local variable slots (offset < 0).
    #[must_use]
    pub fn locals(&self) -> Vec<&StackSlot> {
        self.slots.iter().filter(|s| s.offset.is_local()).collect()
    }

    /// Return all argument slots (offset > 0).
    #[must_use]
    pub fn arguments(&self) -> Vec<&StackSlot> {
        self.slots
            .iter()
            .filter(|s| s.offset.is_above_frame())
            .collect()
    }

    /// Produce a text summary of the frame layout.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut s = format!(
            "StackFrame: local_size={} arg_count={} sp_adj={}\n",
            self.local_size, self.arg_count, self.sp_adjustment
        );
        for slot in &self.slots {
            let _ = writeln!(s, "  [{}] {} {}B {} r={} w={}",
                slot.offset, slot.name, slot.size, slot.kind, slot.reads, slot.writes);
        }
        s
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Abstract stack instructions for the analyzer
// ─────────────────────────────────────────────────────────────────────────────

/// An abstract representation of a stack-related LLIL instruction.
#[derive(Debug, Clone)]
pub enum StackInstr {
    /// Adjust the stack pointer by a signed amount (push/sub/add).
    AdjustSp { delta: i64, addr: u64 },
    /// Load from a frame-relative slot.
    FrameLoad { offset: StackOffset, size: u8, addr: u64 },
    /// Store to a frame-relative slot.
    FrameStore { offset: StackOffset, size: u8, addr: u64 },
    /// Take the address of a frame-relative slot (address-taken).
    TakeAddr { offset: StackOffset, addr: u64 },
    /// Push a value onto the stack (x86 `push`).
    Push { size: u8, addr: u64 },
    /// Pop a value from the stack (x86 `pop`).
    Pop { size: u8, addr: u64 },
    /// Establish the frame pointer from SP (e.g. `mov rbp, rsp`).
    SetFramePointer { addr: u64 },
    /// A call instruction (may pass arguments on the stack above SP).
    Call { stack_arg_bytes: u32, addr: u64 },
    /// A return instruction.
    Return { addr: u64 },
    /// No stack effect.
    Nop,
}

// ─────────────────────────────────────────────────────────────────────────────
// StackBlock — basic block for the stack analyzer
// ─────────────────────────────────────────────────────────────────────────────

/// A basic block for stack analysis.
#[derive(Debug, Clone)]
pub struct StackBlock {
    pub id: usize,
    pub instrs: Vec<StackInstr>,
    pub succs: Vec<usize>,
}

// ─────────────────────────────────────────────────────────────────────────────
// LlilStackAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Analyzes the stack frame of an LLIL function.
///
/// The analyzer processes abstract stack instructions in program order,
/// tracking the SP offset and recording slot accesses.
#[derive(Debug, Clone)]
pub struct LlilStackAnalyzer {
    /// Pointer width of the target (4 or 8 bytes).
    pub pointer_width: u8,
    /// Minimum number of accesses required to report a slot.
    pub min_accesses: usize,
}

impl Default for LlilStackAnalyzer {
    fn default() -> Self {
        Self::new(8)
    }
}

impl LlilStackAnalyzer {
    /// Create a new analyzer for the given pointer width.
    #[must_use]
    pub const fn new(pointer_width: u8) -> Self {
        Self {
            pointer_width,
            min_accesses: 1,
        }
    }

    /// Create a 64-bit analyzer.
    #[must_use]
    pub const fn new_64bit() -> Self {
        Self::new(8)
    }

    /// Create a 32-bit analyzer.
    #[must_use]
    pub const fn new_32bit() -> Self {
        Self::new(4)
    }

    /// Analyze a sequence of abstract stack instructions and return a
    /// [`StackFrame`].
    #[must_use]
    pub fn analyze_instrs(&self, instrs: &[StackInstr]) -> StackFrame {
        let single_block = StackBlock {
            id: 0,
            instrs: instrs.to_vec(),
            succs: vec![],
        };
        analyze_stack(&[single_block], 0, &[[]], self)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// analyze_stack — top-level entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Analyze the stack frame of a function.
///
/// Processes all blocks in DFS order from `entry`, accumulating slot accesses
/// and SP adjustments.
type SlotMap = HashMap<(i64, u8), StackSlot>;

fn process_stack_instr(
    instr: &StackInstr,
    local_sp: &mut i64,
    max_sp_delta: &mut i64,
    has_frame_pointer: &mut bool,
    slot_map: &mut SlotMap,
    analyzer: &LlilStackAnalyzer,
) {
    match instr {
        StackInstr::AdjustSp { delta, .. } => {
            *local_sp += delta;
            if *local_sp < *max_sp_delta { *max_sp_delta = *local_sp; }
        }
        StackInstr::Push { size, addr } => {
            *local_sp -= i64::from(*size);
            if *local_sp < *max_sp_delta { *max_sp_delta = *local_sp; }
            let offset = StackOffset::new(*local_sp);
            let slot = slot_map.entry((offset.0, *size)).or_insert_with(|| StackSlot::new(offset, *size));
            slot.writes += 1;
            slot.access_addrs.insert(*addr);
        }
        StackInstr::Pop { size, addr } => {
            let offset = StackOffset::new(*local_sp);
            let slot = slot_map.entry((offset.0, *size)).or_insert_with(|| StackSlot::new(offset, *size));
            slot.reads += 1;
            slot.access_addrs.insert(*addr);
            *local_sp += i64::from(*size);
        }
        StackInstr::FrameLoad { offset, size, addr } => {
            let slot = slot_map.entry((offset.0, *size)).or_insert_with(|| StackSlot::new(*offset, *size));
            slot.reads += 1;
            slot.access_addrs.insert(*addr);
        }
        StackInstr::FrameStore { offset, size, addr } => {
            let slot = slot_map.entry((offset.0, *size)).or_insert_with(|| StackSlot::new(*offset, *size));
            slot.writes += 1;
            slot.access_addrs.insert(*addr);
        }
        StackInstr::TakeAddr { offset, addr: _ } => {
            let size = analyzer.pointer_width;
            let slot = slot_map.entry((offset.0, size)).or_insert_with(|| StackSlot::new(*offset, size));
            slot.address_taken = true;
        }
        StackInstr::SetFramePointer { .. } => { *has_frame_pointer = true; }
        StackInstr::Call { stack_arg_bytes, addr } => {
            if *stack_arg_bytes > 0 {
                let offset = StackOffset::new(*local_sp + i64::from(*stack_arg_bytes));
                let size = analyzer.pointer_width;
                let slot = slot_map.entry((offset.0, size)).or_insert_with(|| {
                    let mut s = StackSlot::new(offset, size);
                    s.kind = SlotKind::Argument;
                    s.name = format!("arg_{}", offset.0);
                    s
                });
                slot.writes += 1;
                slot.access_addrs.insert(*addr);
            }
        }
        StackInstr::Return { .. } | StackInstr::Nop => {}
    }
}

fn traverse_blocks(
    blocks: &[StackBlock],
    entry: usize,
    analyzer: &LlilStackAnalyzer,
) -> (SlotMap, i64, bool, i64) {
    let mut visited: HashSet<usize> = HashSet::new();
    let mut worklist: Vec<usize> = vec![entry];
    let mut slot_map: SlotMap = HashMap::new();
    let mut sp_adjustment: i64 = 0;
    let mut has_frame_pointer = false;
    let mut max_sp_delta: i64 = 0;
    while let Some(bid) = worklist.pop() {
        if !visited.insert(bid) { continue; }
        let Some(block) = blocks.get(bid) else { continue };
        let mut local_sp = sp_adjustment;
        for instr in &block.instrs {
            process_stack_instr(instr, &mut local_sp, &mut max_sp_delta,
                &mut has_frame_pointer, &mut slot_map, analyzer);
        }
        sp_adjustment = local_sp;
        for &s in &block.succs { worklist.push(s); }
    }
    (slot_map, sp_adjustment, has_frame_pointer, max_sp_delta)
}

pub fn analyze_stack(
    blocks: &[StackBlock],
    entry: usize,
    _preds: &[impl AsRef<[usize]>],
    analyzer: &LlilStackAnalyzer,
) -> StackFrame {
    let (slot_map, _sp_adjustment, has_frame_pointer, max_sp_delta) =
        traverse_blocks(blocks, entry, analyzer);

    let min_acc = analyzer.min_accesses;
    let mut slots: Vec<StackSlot> = slot_map
        .into_values()
        .filter(|s| s.reads + s.writes >= min_acc || s.address_taken)
        .collect();
    slots.sort_by_key(|s| s.offset.0);

    let local_size = slots.iter().filter(|s| s.offset.is_local())
        .map(|s| s.offset.0.unsigned_abs()).max().unwrap_or(0);
    let arg_count = slots.iter().filter(|s| s.offset.is_above_frame()).count();
    let max_alignment: u8 = slots.iter().map(|s| s.size).max().unwrap_or(1);

    StackFrame { slots, local_size, arg_count, has_frame_pointer,
        sp_adjustment: max_sp_delta, max_alignment }
}

// ─────────────────────────────────────────────────────────────────────────────
// FrameSizeEstimator — heuristic frame size from SP adjustments only
// ─────────────────────────────────────────────────────────────────────────────

/// Estimates the stack frame size from a sequence of SP adjustment deltas,
/// without needing full slot analysis.
#[must_use]
pub fn estimate_frame_size(adjustments: &[i64]) -> u64 {
    let mut sp: i64 = 0;
    let mut min_sp: i64 = 0;
    for &delta in adjustments {
        sp += delta;
        if sp < min_sp {
            min_sp = sp;
        }
    }
    min_sp.unsigned_abs()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn so(n: i64) -> StackOffset {
        StackOffset::new(n)
    }

    fn make_block(instrs: Vec<StackInstr>) -> Vec<StackBlock> {
        vec![StackBlock { id: 0, instrs, succs: vec![] }]
    }

    fn run(instrs: Vec<StackInstr>) -> StackFrame {
        let blocks = make_block(instrs);
        let analyzer = LlilStackAnalyzer::new_64bit();
        analyze_stack(&blocks, 0, &[Vec::<usize>::new()], &analyzer)
    }

    #[test]
    fn test_frame_store_creates_slot() {
        let frame = run(vec![StackInstr::FrameStore {
            offset: so(-8),
            size: 8,
            addr: 0x1000,
        }]);
        assert_eq!(frame.slots.len(), 1);
        assert_eq!(frame.slots[0].offset, so(-8));
        assert_eq!(frame.slots[0].writes, 1);
    }

    #[test]
    fn test_frame_load_creates_slot() {
        let frame = run(vec![StackInstr::FrameLoad {
            offset: so(-8),
            size: 8,
            addr: 0x1004,
        }]);
        assert_eq!(frame.slots.len(), 1);
        assert_eq!(frame.slots[0].reads, 1);
    }

    #[test]
    fn test_push_pop_balance() {
        let frame = run(vec![
            StackInstr::Push { size: 8, addr: 0x1000 },
            StackInstr::Pop { size: 8, addr: 0x1008 },
        ]);
        // One slot should be created at offset -8.
        let slot = frame.slot_at(so(-8)).expect("slot at -8");
        assert_eq!(slot.writes, 1); // push
        assert_eq!(slot.reads, 1);  // pop
    }

    #[test]
    fn test_adjust_sp_tracks_delta() {
        let frame = run(vec![
            StackInstr::AdjustSp { delta: -32, addr: 0x1000 },
        ]);
        assert_eq!(frame.sp_adjustment, -32);
    }

    #[test]
    fn test_frame_pointer_detected() {
        let frame = run(vec![StackInstr::SetFramePointer { addr: 0x1000 }]);
        assert!(frame.has_frame_pointer);
    }

    #[test]
    fn test_local_size() {
        let frame = run(vec![
            StackInstr::FrameStore { offset: so(-16), size: 8, addr: 0 },
            StackInstr::FrameStore { offset: so(-8), size: 8, addr: 4 },
        ]);
        // Local size is the most-negative offset's magnitude.
        assert_eq!(frame.local_size, 16);
    }

    #[test]
    fn test_address_taken_flag() {
        let frame = run(vec![StackInstr::TakeAddr { offset: so(-8), addr: 0x2000 }]);
        let slot = frame.slot_at(so(-8)).expect("slot exists");
        assert!(slot.address_taken);
    }

    #[test]
    fn test_estimate_frame_size() {
        let adjustments = [-16i64, -8, 8, 16];
        assert_eq!(estimate_frame_size(&adjustments), 24);
    }

    #[test]
    fn test_locals_and_args() {
        let frame = run(vec![
            StackInstr::FrameStore { offset: so(-8), size: 8, addr: 0 },
            StackInstr::FrameLoad { offset: so(16), size: 8, addr: 4 },
        ]);
        assert_eq!(frame.locals().len(), 1);
        assert_eq!(frame.arguments().len(), 1);
    }

    #[test]
    fn test_summary_non_empty() {
        let frame = run(vec![
            StackInstr::FrameStore { offset: so(-8), size: 8, addr: 0 },
        ]);
        let s = frame.summary();
        assert!(!s.is_empty());
        assert!(s.contains("local_-8"));
    }

    #[test]
    fn test_dead_store_candidate() {
        let frame = run(vec![
            StackInstr::FrameStore { offset: so(-4), size: 4, addr: 0 },
        ]);
        let slot = frame.slot_at(so(-4)).unwrap();
        assert!(slot.is_dead_store_candidate());
        assert!(!slot.is_live());
    }
}
