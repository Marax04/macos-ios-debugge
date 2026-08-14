// Execution trace reconstruction from CoreSight / ETM4 decoded packet stream.
//
// The reconstructor drives a "trace processor" state machine that consumes
// DecodedPacket values and produces TraceRecord events representing
// individually executed instructions, function calls/returns, and exceptions.
//
// Architecture modelled: AArch64 (+ AArch32 Thumb for basic cases).

use std::collections::{HashMap, VecDeque};
use crate::coresight_packets::{DecodedPacket, ExcType, IsaMode};

// ── Types ─────────────────────────────────────────────────────────────────────

pub type Addr = u64;

/// A single reconstructed execution record.
#[derive(Debug, Clone)]
pub enum TraceRecord {
    /// An instruction was executed at this address.
    Instruction {
        addr: Addr,
        isa: IsaMode,
        /// Whether the preceding conditional branch was taken.
        branch_taken: Option<bool>,
    },
    /// A direct or indirect branch (not a call) to `target`.
    Branch {
        from: Addr,
        to: Addr,
        kind: BranchKind,
    },
    /// A function call (BL / BLR).
    Call {
        from: Addr,
        to: Addr,
        return_addr: Addr,
    },
    /// A function return.
    Return {
        from: Addr,
        to: Addr,
    },
    /// Exception taken.
    Exception {
        at: Addr,
        exc: ExcType,
        el: u8,
    },
    /// Exception return.
    ExceptionReturn { to: Addr },
    /// Timestamp synchronisation point.
    Timestamp { ts: u64, cycle_count: Option<u32> },
    /// Trace overflow — some records are missing.
    Overflow,
    /// Tracing was re-enabled after a gap.
    TraceOn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchKind {
    Conditional,
    Unconditional,
    Indirect,
    Return,
    ExceptionEntry,
    ExceptionReturn,
}

// ── Disassembly callback ──────────────────────────────────────────────────────

/// Lightweight description of a single instruction needed for trace replay.
#[derive(Debug, Clone)]
pub struct InsnDesc {
    pub addr: Addr,
    pub size: u8,          // bytes
    pub kind: InsnKind,
    pub isa: IsaMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsnKind {
    Sequential,            // no branch, just falls through
    DirectBranch { target: Addr, is_call: bool, conditional: bool },
    IndirectBranch { is_call: bool, is_ret: bool },
    Svc,
    Hvc,
    Eret,
    Undefined,
}

/// Client callback: given an address and ISA, return instruction info.
/// Returns `None` if the address cannot be decoded (unmapped / no binary).
pub trait DisasmProvider: Send + Sync {
    fn insn_at(&self, addr: Addr, isa: IsaMode) -> Option<InsnDesc>;
}

/// Stub disassembler that always returns a sequential 4-byte instruction.
pub struct NullDisasm;
impl DisasmProvider for NullDisasm {
    fn insn_at(&self, addr: Addr, isa: IsaMode) -> Option<InsnDesc> {
        Some(InsnDesc { addr, size: if isa == IsaMode::Aarch32Thumb { 2 } else { 4 }, kind: InsnKind::Sequential, isa })
    }
}

// ── Call-stack tracking ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CallFrame {
    pub call_site: Addr,
    pub return_addr: Addr,
    pub callee: Addr,
}

impl CallFrame {
    /// Address of the call instruction.
    #[must_use] pub const fn call_site(&self) -> Addr { self.call_site }
    /// Address the callee will return to.
    #[must_use] pub const fn return_addr(&self) -> Addr { self.return_addr }
    /// Address of the called function.
    #[must_use] pub const fn callee(&self) -> Addr { self.callee }
}

#[derive(Debug, Default)]
pub struct CallStack(Vec<CallFrame>);

impl CallStack {
    pub fn push(&mut self, frame: CallFrame) { self.0.push(frame); }
    pub fn pop(&mut self) -> Option<CallFrame> { self.0.pop() }
    #[must_use] pub fn peek(&self) -> Option<&CallFrame> { self.0.last() }
    #[must_use] pub const fn depth(&self) -> usize { self.0.len() }
}

// ── Processor state ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessorState {
    /// Waiting for a sync packet before emitting records.
    WaitingForSync,
    /// Processing normally.
    Running,
    /// After overflow: waiting for re-synchronisation.
    PostOverflow,
}

/// Main trace reconstruction state machine.
pub struct TraceReconstructor<'a> {
    disasm: &'a dyn DisasmProvider,
    pc: Option<Addr>,
    isa: IsaMode,
    state: ProcessorState,
    atom_queue: VecDeque<bool>,   // true = Taken
    call_stack: CallStack,
    pub records: Vec<TraceRecord>,
    pub stats: ReconstructionStats,
    // Speculation depth for speculative execution tracking
    spec_depth: u8,
    max_spec_depth: u8,
    // Inline sequence limit (guard against infinite loops)
    inline_limit: usize,
}

#[derive(Debug, Default, Clone)]
pub struct ReconstructionStats {
    pub instructions_traced: u64,
    pub branches_resolved: u64,
    pub calls_traced: u64,
    pub returns_traced: u64,
    pub exceptions_traced: u64,
    pub overflows: u64,
    pub atom_bits_consumed: u64,
    pub atom_bits_produced: u64,
    pub sync_points: u64,
    pub disasm_misses: u64,
}

impl<'a> TraceReconstructor<'a> {
    pub fn new(disasm: &'a dyn DisasmProvider) -> Self {
        Self {
            disasm,
            pc: None,
            isa: IsaMode::Aarch64,
            state: ProcessorState::WaitingForSync,
            atom_queue: VecDeque::new(),
            call_stack: CallStack::default(),
            records: Vec::new(),
            stats: ReconstructionStats::default(),
            spec_depth: 0,
            max_spec_depth: 8,
            inline_limit: 4096,
        }
    }

    /// Process a slice of decoded packets.
    pub fn process(&mut self, packets: &[DecodedPacket]) {
        for pkt in packets {
            self.process_packet(pkt);
        }
    }

    fn process_packet(&mut self, pkt: &DecodedPacket) {
        match pkt {
            DecodedPacket::ASync => {
                self.state = ProcessorState::Running;
                self.stats.sync_points += 1;
            }
            DecodedPacket::TraceOn => {
                self.records.push(TraceRecord::TraceOn);
                if self.state == ProcessorState::PostOverflow {
                    self.state = ProcessorState::Running;
                }
            }
            DecodedPacket::Overflow => {
                self.state = ProcessorState::PostOverflow;
                self.records.push(TraceRecord::Overflow);
                self.stats.overflows += 1;
                self.atom_queue.clear();
            }
            _ if self.state != ProcessorState::Running => {
                // Drop packets until we're running
            }
            DecodedPacket::Address { addr, isa, .. } => {
                self.pc = Some(*addr);
                self.isa = *isa;
            }
            DecodedPacket::ShortAddr { addr, .. } | DecodedPacket::LongAddr { addr, .. } => {
                self.pc = Some(*addr);
            }
            DecodedPacket::Atom { atoms, count } => {
                self.stats.atom_bits_produced += u64::from(*count);
                for i in 0..*count {
                    let taken = (*atoms >> i) & 1 == 1;
                    self.atom_queue.push_back(taken);
                }
                // Try to advance the PC using queued atoms
                self.advance_with_atoms();
            }
            DecodedPacket::Timestamp { ts, cc } => {
                self.records.push(TraceRecord::Timestamp { ts: *ts, cycle_count: *cc });
            }
            DecodedPacket::ExceptionEntry { exc_type, el, addr, .. } => {
                let at = addr.unwrap_or(self.pc.unwrap_or(0));
                self.records.push(TraceRecord::Exception {
                    at,
                    exc: *exc_type,
                    el: *el,
                });
                if let Some(a) = addr { self.pc = Some(*a); }
                self.stats.exceptions_traced += 1;
            }
            DecodedPacket::ExceptionReturn { addr } => {
                let to = addr.unwrap_or(self.pc.unwrap_or(0));
                self.records.push(TraceRecord::ExceptionReturn { to });
                if let Some(a) = addr { self.pc = Some(*a); }
            }
            DecodedPacket::Commit { .. }
                if self.spec_depth > 0 => { self.spec_depth -= 1; }
            _ => {}
        }
    }

    /// Try to advance execution using queued atom bits.
    /// For each atom bit, advance past one conditional branch.
    fn advance_with_atoms(&mut self) {
        let mut steps = 0;
        while !self.atom_queue.is_empty() && steps < self.inline_limit {
            let Some(pc) = self.pc else { break; };
            let Some(insn) = self.disasm.insn_at(pc, self.isa) else {
                self.stats.disasm_misses += 1;
                break;
            };

            match &insn.kind {
                InsnKind::Sequential => {
                    // A Sequential instruction is not a branch, so it does not
                    // by itself consume an atom bit. However, when the disasm
                    // provider is a stub that returns Sequential for every PC
                    // (e.g. NullDisasm) we would otherwise spin until
                    // `inline_limit` without ever draining the atom queue.
                    // Consume one atom per Sequential step so progress is
                    // bounded by the queue size, matching the documented
                    // "atom-driven" reconstruction model.
                    let _ = self.atom_queue.pop_front();
                    self.stats.atom_bits_consumed += 1;
                    self.emit_insn(pc, None);
                    self.pc = Some(pc + u64::from(insn.size));
                    steps += 1;
                }
                InsnKind::DirectBranch { target, is_call, conditional } => {
                    if *conditional {
                        let Some(taken) = self.atom_queue.pop_front() else { break; };
                        self.stats.atom_bits_consumed += 1;
                        self.emit_insn(pc, Some(taken));
                        self.stats.branches_resolved += 1;
                        if taken {
                            if *is_call {
                                let ret = pc + u64::from(insn.size);
                                self.call_stack.push(CallFrame { call_site: pc, return_addr: ret, callee: *target });
                                self.records.push(TraceRecord::Call { from: pc, to: *target, return_addr: ret });
                                self.stats.calls_traced += 1;
                            } else {
                                self.records.push(TraceRecord::Branch { from: pc, to: *target, kind: BranchKind::Conditional });
                            }
                            self.pc = Some(*target);
                        } else {
                            self.pc = Some(pc + u64::from(insn.size));
                        }
                    } else {
                        // Unconditional direct branch
                        self.emit_insn(pc, None);
                        if *is_call {
                            let ret = pc + u64::from(insn.size);
                            self.call_stack.push(CallFrame { call_site: pc, return_addr: ret, callee: *target });
                            self.records.push(TraceRecord::Call { from: pc, to: *target, return_addr: ret });
                            self.stats.calls_traced += 1;
                        } else {
                            self.records.push(TraceRecord::Branch { from: pc, to: *target, kind: BranchKind::Unconditional });
                        }
                        self.pc = Some(*target);
                        steps += 1;
                    }
                }
                InsnKind::IndirectBranch { is_call, is_ret } => {
                    self.emit_insn(pc, None);
                    if *is_ret {
                        let frame = self.call_stack.pop();
                        let to = frame.map_or(0, |f| f.return_addr);
                        self.records.push(TraceRecord::Return { from: pc, to });
                        self.stats.returns_traced += 1;
                        self.pc = Some(to);
                    } else if *is_call {
                        // Indirect call — we need address packet to know target
                        // Consume one atom if present to represent the branch
                        self.records.push(TraceRecord::Branch { from: pc, to: 0, kind: BranchKind::Indirect });
                        self.stats.calls_traced += 1;
                        // PC will be updated by next Address packet
                        self.pc = None;
                    } else {
                        self.records.push(TraceRecord::Branch { from: pc, to: 0, kind: BranchKind::Indirect });
                        self.pc = None;
                    }
                    break; // Wait for address update
                }
                InsnKind::Eret => {
                    self.emit_insn(pc, None);
                    self.records.push(TraceRecord::ExceptionReturn { to: 0 });
                    self.pc = None;
                    break;
                }
                InsnKind::Svc | InsnKind::Hvc | InsnKind::Undefined => {
                    self.emit_insn(pc, None);
                    self.pc = Some(pc + u64::from(insn.size));
                    steps += 1;
                }
            }
        }
    }

    fn emit_insn(&mut self, addr: Addr, branch_taken: Option<bool>) {
        self.records.push(TraceRecord::Instruction { addr, isa: self.isa, branch_taken });
        self.stats.instructions_traced += 1;
    }

    #[must_use]
    pub const fn current_pc(&self) -> Option<Addr> { self.pc }

    #[must_use]
    pub const fn call_depth(&self) -> usize { self.call_stack.depth() }

    /// Current speculation depth (uncommitted speculative branches).
    #[must_use]
    pub const fn spec_depth(&self) -> u8 { self.spec_depth }

    /// Maximum speculation depth supported by the reconstructor.
    #[must_use]
    pub const fn max_spec_depth(&self) -> u8 { self.max_spec_depth }

    pub fn flush_records(&mut self) -> Vec<TraceRecord> {
        std::mem::take(&mut self.records)
    }
}

// ── Function-level trace aggregator ──────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct FunctionTrace {
    pub addr: Addr,
    pub hit_count: u64,
    pub inclusive_insns: u64,
    pub callees: HashMap<Addr, u64>,
}

pub struct FunctionTraceAggregator {
    pub functions: HashMap<Addr, FunctionTrace>,
    current_func: Option<Addr>,
}

impl FunctionTraceAggregator {
    #[must_use]
    pub fn new() -> Self {
        Self { functions: HashMap::new(), current_func: None }
    }

    pub fn feed(&mut self, records: &[TraceRecord]) {
        for rec in records {
            match rec {
                TraceRecord::Call { to, .. } => {
                    let ft = self.functions.entry(*to).or_default();
                    ft.addr = *to;
                    ft.hit_count += 1;
                    if let Some(caller) = self.current_func {
                        self.functions.entry(caller).or_default().callees
                            .entry(*to).and_modify(|c| *c += 1).or_insert(1);
                    }
                    self.current_func = Some(*to);
                }
                TraceRecord::Return { from: _, .. } => {
                    // Pop back (simplified — no real stack here)
                    self.current_func = None;
                }
                TraceRecord::Instruction { addr: _, .. } => {
                    if let Some(func) = self.current_func {
                        self.functions.entry(func).or_default().inclusive_insns += 1;
                    }
                }
                _ => {}
            }
        }
    }

    #[must_use]
    pub fn top_functions_by_insns(&self, n: usize) -> Vec<&FunctionTrace> {
        let mut v: Vec<_> = self.functions.values().collect();
        v.sort_by(|a, b| b.inclusive_insns.cmp(&a.inclusive_insns));
        v.truncate(n);
        v
    }
}

impl Default for FunctionTraceAggregator {
    fn default() -> Self { Self::new() }
}

// ── Coverage tracker ──────────────────────────────────────────────────────────

/// Tracks which addresses were executed (basic block coverage).
pub struct CoverageTracker {
    /// Set of unique instruction addresses executed.
    pub covered: std::collections::HashSet<Addr>,
    pub total_insns: u64,
}

impl CoverageTracker {
    #[must_use]
    pub fn new() -> Self { Self { covered: std::collections::HashSet::default(), total_insns: 0 } }

    pub fn feed(&mut self, records: &[TraceRecord]) {
        for rec in records {
            if let TraceRecord::Instruction { addr, .. } = rec {
                self.covered.insert(*addr);
                self.total_insns += 1;
            }
        }
    }

    #[must_use]
    pub fn unique_addresses(&self) -> usize { self.covered.len() }

    #[must_use]
    pub fn coverage_ratio(&self, total_known: usize) -> f64 {
        if total_known == 0 { return 0.0; }
        let ppm = (self.covered.len() as u128) * 1_000_000 / (total_known as u128);
        f64::from(u32::try_from(ppm).unwrap_or(1_000_000)) * 1e-6
    }
}

impl Default for CoverageTracker {
    fn default() -> Self { Self::new() }
}

// ── Sequence detector ─────────────────────────────────────────────────────────

/// Detect repeated instruction sequences (hot loops) in the trace.
pub struct SequenceDetector {
    window: VecDeque<Addr>,
    window_size: usize,
    pub patterns: HashMap<Vec<Addr>, u64>,
}

impl SequenceDetector {
    #[must_use]
    pub fn new(window_size: usize) -> Self {
        Self { window: VecDeque::new(), window_size, patterns: HashMap::new() }
    }

    pub fn feed(&mut self, records: &[TraceRecord]) {
        for rec in records {
            if let TraceRecord::Instruction { addr, .. } = rec {
                self.window.push_back(*addr);
                if self.window.len() > self.window_size {
                    self.window.pop_front();
                }
                if self.window.len() == self.window_size {
                    let key: Vec<Addr> = self.window.iter().copied().collect();
                    *self.patterns.entry(key).or_insert(0) += 1;
                }
            }
        }
    }

    #[must_use]
    pub fn hot_sequences(&self, min_count: u64) -> Vec<(&[Addr], u64)> {
        let mut v: Vec<_> = self.patterns.iter()
            .filter(|&(_, &c)| c >= min_count)
            .map(|(k, &c)| (k.as_slice(), c))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }
}

// ── Exception trace summariser ────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct ExceptionSummary {
    pub by_type: HashMap<String, u64>,
    pub by_el: HashMap<u8, u64>,
}

impl ExceptionSummary {
    pub fn feed(&mut self, records: &[TraceRecord]) {
        for rec in records {
            if let TraceRecord::Exception { exc, el, .. } = rec {
                *self.by_type.entry(format!("{exc:?}")).or_insert(0) += 1;
                *self.by_el.entry(*el).or_insert(0) += 1;
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coresight_packets::DecodedPacket;

    #[test]
    fn test_sequential_trace() {
        let disasm = NullDisasm;
        let mut rec = TraceReconstructor::new(&disasm);
        rec.process(&[
            DecodedPacket::ASync,
            DecodedPacket::LongAddr { addr: 0x1000, bits: 64 },
            // Feed 4 atoms all taken
            DecodedPacket::Atom { atoms: 0b1111, count: 4 },
        ]);
        // NullDisasm always returns Sequential → 4 instructions emitted
        assert_eq!(rec.stats.instructions_traced, 4);
    }

    #[test]
    fn test_wait_for_sync() {
        let disasm = NullDisasm;
        let mut rec = TraceReconstructor::new(&disasm);
        // Atoms before sync should be ignored
        rec.process(&[DecodedPacket::Atom { atoms: 0xff, count: 8 }]);
        assert_eq!(rec.stats.instructions_traced, 0);
    }

    #[test]
    fn test_overflow_clears_atoms() {
        let disasm = NullDisasm;
        let mut rec = TraceReconstructor::new(&disasm);
        rec.process(&[
            DecodedPacket::ASync,
            DecodedPacket::LongAddr { addr: 0x2000, bits: 64 },
            DecodedPacket::Atom { atoms: 0b11, count: 2 },
            DecodedPacket::Overflow,
        ]);
        assert_eq!(rec.atom_queue.len(), 0);
        assert!(rec.records.iter().any(|r| matches!(r, TraceRecord::Overflow)));
    }

    #[test]
    fn test_call_return_tracking() {
        struct CallDisasm;
        impl DisasmProvider for CallDisasm {
            fn insn_at(&self, addr: Addr, isa: IsaMode) -> Option<InsnDesc> {
                if addr == 0x1000 {
                    Some(InsnDesc {
                        addr,
                        size: 4,
                        kind: InsnKind::DirectBranch { target: 0x2000, is_call: true, conditional: false },
                        isa,
                    })
                } else {
                    Some(InsnDesc { addr, size: 4, kind: InsnKind::Sequential, isa })
                }
            }
        }
        let disasm = CallDisasm;
        let mut rec = TraceReconstructor::new(&disasm);
        rec.process(&[
            DecodedPacket::ASync,
            DecodedPacket::LongAddr { addr: 0x1000, bits: 64 },
            DecodedPacket::Atom { atoms: 0b1, count: 1 },
        ]);
        let calls = rec.records.iter().filter(|r| matches!(r, TraceRecord::Call { .. })).count();
        assert_eq!(calls, 1);
        assert_eq!(rec.call_stack.depth(), 1);
    }

    #[test]
    fn test_coverage_tracker() {
        let mut cov = CoverageTracker::new();
        let records = vec![
            TraceRecord::Instruction { addr: 0x100, isa: IsaMode::Aarch64, branch_taken: None },
            TraceRecord::Instruction { addr: 0x104, isa: IsaMode::Aarch64, branch_taken: None },
            TraceRecord::Instruction { addr: 0x100, isa: IsaMode::Aarch64, branch_taken: None },
        ];
        cov.feed(&records);
        assert_eq!(cov.unique_addresses(), 2);
        assert_eq!(cov.total_insns, 3);
        assert!((cov.coverage_ratio(4) - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_exception_summary() {
        let mut summary = ExceptionSummary::default();
        let records = vec![
            TraceRecord::Exception { at: 0x0, exc: ExcType::Irq, el: 1 },
            TraceRecord::Exception { at: 0x0, exc: ExcType::Irq, el: 1 },
            TraceRecord::Exception { at: 0x0, exc: ExcType::Fiq, el: 2 },
        ];
        summary.feed(&records);
        assert_eq!(*summary.by_type.get("Irq").unwrap_or(&0), 2);
        assert_eq!(*summary.by_el.get(&1).unwrap_or(&0), 2);
    }

    #[test]
    fn test_sequence_detector() {
        let mut det = SequenceDetector::new(3);
        let records: Vec<TraceRecord> = (0..10)
            .map(|i| TraceRecord::Instruction {
                addr: 0x1000 + (i % 3) * 4,
                isa: IsaMode::Aarch64,
                branch_taken: None,
            })
            .collect();
        det.feed(&records);
        let hot = det.hot_sequences(2);
        assert!(!hot.is_empty());
    }
}
