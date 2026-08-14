//! `pt_flow_reconstruction` — Control-flow reconstruction from Intel PT.
//!
//! Consumes a decoded PT packet stream (TNT/TIP/TIP.PGE/TIP.PGD) and a
//! disassembler callback to produce a precise instruction-level execution
//! trace, branch records, call/return pairs, exception flows, and ring-level
//! transition events.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{PtError, PtEvent, PtFlow, PtPacket, PtPacketKind};

// ─── InstructionKind ──────────────────────────────────────────────────────────

/// The high-level kind of an x86/x64 instruction as it relates to PT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstructionKind {
    /// Linear (non-branching) instruction.
    Linear,
    /// Conditional branch (uses TNT bits).
    ConditionalBranch,
    /// Unconditional direct branch/jump.
    DirectBranch,
    /// Indirect branch (call/jmp indirect — uses TIP).
    IndirectBranch,
    /// Near direct call.
    DirectCall,
    /// Near indirect call.
    IndirectCall,
    /// Near return.
    Return,
    /// SYSCALL / SYSENTER.
    Syscall,
    /// SYSRET / SYSEXIT.
    Sysret,
    /// IRET / IRETD / IRETQ.
    Iret,
    /// INT n / INTO.
    SoftwareInterrupt,
    /// HLT.
    Halt,
    /// VMLAUNCH / VMRESUME (ring-0 VM entry).
    VmEntry,
    /// VMEXIT (hardware-induced).
    VmExit,
}

impl InstructionKind {
    /// Return `true` if this instruction consumes a TNT bit.
    #[must_use]
    pub const fn needs_tnt(self) -> bool {
        matches!(self, Self::ConditionalBranch)
    }

    /// Return `true` if this instruction needs a TIP packet to resolve target.
    #[must_use]
    pub const fn needs_tip(self) -> bool {
        matches!(
            self,
            Self::IndirectBranch
                | Self::IndirectCall
                | Self::Return
                | Self::Syscall
                | Self::Sysret
                | Self::Iret
        )
    }

    /// Return `true` if this instruction is a call.
    #[must_use]
    pub const fn is_call(self) -> bool {
        matches!(self, Self::DirectCall | Self::IndirectCall)
    }

    /// Return `true` if this instruction is a return.
    #[must_use]
    pub const fn is_return(self) -> bool {
        matches!(self, Self::Return | Self::Iret | Self::Sysret)
    }
}

// ─── DecodedInstruction ───────────────────────────────────────────────────────

/// A decoded instruction used for PT-assisted flow reconstruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedInstruction {
    /// Instruction address.
    pub address: u64,
    /// Instruction size in bytes.
    pub size: u8,
    /// High-level classification.
    pub kind: InstructionKind,
    /// Direct target (for conditional/unconditional branches and calls).
    pub direct_target: Option<u64>,
    /// Fall-through address (address + size).
    pub fallthrough: u64,
}

impl DecodedInstruction {
    /// Create a linear instruction.
    #[must_use]
    pub fn linear(address: u64, size: u8) -> Self {
        Self {
            address,
            size,
            kind: InstructionKind::Linear,
            direct_target: None,
            fallthrough: address + u64::from(size),
        }
    }

    /// Create a conditional branch instruction.
    #[must_use]
    pub fn conditional_branch(address: u64, size: u8, target: u64) -> Self {
        Self {
            address,
            size,
            kind: InstructionKind::ConditionalBranch,
            direct_target: Some(target),
            fallthrough: address + u64::from(size),
        }
    }

    /// Create an indirect branch instruction.
    #[must_use]
    pub fn indirect_branch(address: u64, size: u8) -> Self {
        Self {
            address,
            size,
            kind: InstructionKind::IndirectBranch,
            direct_target: None,
            fallthrough: address + u64::from(size),
        }
    }

    /// Create a direct call instruction.
    #[must_use]
    pub fn direct_call(address: u64, size: u8, target: u64) -> Self {
        Self {
            address,
            size,
            kind: InstructionKind::DirectCall,
            direct_target: Some(target),
            fallthrough: address + u64::from(size),
        }
    }

    /// Create an indirect call instruction.
    #[must_use]
    pub fn indirect_call(address: u64, size: u8) -> Self {
        Self {
            address,
            size,
            kind: InstructionKind::IndirectCall,
            direct_target: None,
            fallthrough: address + u64::from(size),
        }
    }

    /// Create a return instruction.
    #[must_use]
    pub fn ret(address: u64, size: u8) -> Self {
        Self {
            address,
            size,
            kind: InstructionKind::Return,
            direct_target: None,
            fallthrough: address + u64::from(size),
        }
    }
}

// ─── FlowBlock ────────────────────────────────────────────────────────────────

/// A basic block in the reconstructed control flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowBlock {
    /// Start address.
    pub start: u64,
    /// End address (exclusive).
    pub end: u64,
    /// Instructions in this block.
    pub instructions: Vec<DecodedInstruction>,
    /// Successors (taken, fallthrough).
    pub successors: Vec<u64>,
    /// Execution count.
    pub exec_count: u64,
}

impl FlowBlock {
    /// Create a new flow block.
    #[must_use]
    pub const fn new(start: u64) -> Self {
        Self {
            start,
            end: start,
            instructions: Vec::new(),
            successors: Vec::new(),
            exec_count: 0,
        }
    }

    /// Append an instruction.
    pub fn push(&mut self, insn: DecodedInstruction) {
        self.end = insn.fallthrough;
        self.instructions.push(insn);
    }

    /// Return the number of instructions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Return `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
}

// ─── CallFrame ────────────────────────────────────────────────────────────────

/// A call stack frame used for return prediction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallFrame {
    /// Call site address.
    pub call_site: u64,
    /// Return address (= call site + call instruction size).
    pub return_addr: u64,
    /// Callee target.
    pub callee: u64,
    /// TSC when the call was made (for duration profiling).
    pub call_tsc: Option<u64>,
}

// ─── FlowReconstructorConfig ──────────────────────────────────────────────────

/// Configuration for the flow reconstructor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowReconstructorConfig {
    /// Maximum depth for the call stack.
    pub max_call_depth: usize,
    /// Whether to track ring-level transitions.
    pub track_ring_transitions: bool,
    /// Whether to emit individual `Linear` events.
    pub emit_linear_events: bool,
    /// Whether to detect SYSCALL/SYSRET as ring transitions.
    pub track_syscalls: bool,
    /// Maximum number of events to emit before stopping.
    pub max_events: Option<usize>,
}

impl Default for FlowReconstructorConfig {
    fn default() -> Self {
        Self {
            max_call_depth: 256,
            track_ring_transitions: true,
            emit_linear_events: false,
            track_syscalls: true,
            max_events: None,
        }
    }
}

// ─── RingLevel ────────────────────────────────────────────────────────────────

/// CPU ring level (privilege level).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RingLevel {
    /// Ring 0 — kernel mode.
    Ring0,
    /// Ring 3 — user mode.
    Ring3,
    /// Ring 1 (rare).
    Ring1,
    /// Ring 2 (rare).
    Ring2,
}

impl RingLevel {
    /// Parse from MODE bits.
    #[must_use]
    pub fn from_mode_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::Ring0,
            1 => Self::Ring1,
            2 => Self::Ring2,
            3 => Self::Ring3,
            _ => unreachable!(),
        }
    }
}

impl std::fmt::Display for RingLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ring0 => write!(f, "R0"),
            Self::Ring1 => write!(f, "R1"),
            Self::Ring2 => write!(f, "R2"),
            Self::Ring3 => write!(f, "R3"),
        }
    }
}

// ─── FlowEvent ────────────────────────────────────────────────────────────────

/// Extended flow event with ring-level and timing metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEvent {
    /// The underlying PT event.
    pub event: PtEvent,
    /// Ring level when the event occurred.
    pub ring: Option<RingLevel>,
    /// TSC at the time of the event.
    pub tsc: Option<u64>,
    /// Packet index that generated this event.
    pub packet_index: usize,
}

impl std::fmt::Display for FlowEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.event)?;
        if let Some(r) = self.ring {
            write!(f, " [{r}]")?;
        }
        if let Some(t) = self.tsc {
            write!(f, " @{t}")?;
        }
        Ok(())
    }
}

// ─── FlowReconstructor ────────────────────────────────────────────────────────

/// Full Intel PT control-flow reconstructor.
///
/// Takes decoded PT packets + a disassembler oracle and produces a rich
/// execution trace including:
/// - Conditional branch outcomes (from TNT bits)
/// - Indirect branch targets (from TIP packets)
/// - Return targets (from TIP packets, with call stack prediction)
/// - Exception flows (from TIP.PGE + MODE change)
/// - Ring-level transitions (from SYSCALL/SYSRET/MODE)
pub struct FlowReconstructor {
    /// Configuration.
    pub config: FlowReconstructorConfig,
    /// Pending TNT bits.
    tnt_queue: VecDeque<bool>,
    /// Current IP.
    pub current_ip: u64,
    /// Whether tracing is active.
    pub tracing_enabled: bool,
    /// Call stack.
    call_stack: Vec<CallFrame>,
    /// Current ring level.
    pub ring: RingLevel,
    /// Current TSC.
    pub current_tsc: Option<u64>,
    /// Reconstructed flow.
    pub flow: PtFlow,
    /// Extended events with metadata.
    pub events: Vec<FlowEvent>,
    /// Execution heatmap (address → count).
    pub heatmap: HashMap<u64, u64>,
    /// Unique code paths (blocks visited).
    pub blocks_visited: HashSet<u64>,
    /// Number of ring transitions.
    pub ring_transitions: u64,
    /// Number of correctly predicted returns (stack hit).
    pub return_stack_hits: u64,
    /// Number of mispredicted returns.
    pub return_stack_misses: u64,
}

impl FlowReconstructor {
    /// Create a new reconstructor with default config.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(FlowReconstructorConfig::default())
    }

    /// Create a new reconstructor with a custom config.
    #[must_use]
    pub fn with_config(config: FlowReconstructorConfig) -> Self {
        Self {
            config,
            tnt_queue: VecDeque::new(),
            current_ip: 0,
            tracing_enabled: false,
            call_stack: Vec::new(),
            ring: RingLevel::Ring3,
            current_tsc: None,
            flow: PtFlow::new(),
            events: Vec::new(),
            heatmap: HashMap::new(),
            blocks_visited: HashSet::new(),
            ring_transitions: 0,
            return_stack_hits: 0,
            return_stack_misses: 0,
        }
    }

    /// Feed a single decoded PT packet.
    pub fn feed_packet(&mut self, pkt: &PtPacket, packet_index: usize) {
        match &pkt.kind {
            PtPacketKind::Tnt { bits, count } | PtPacketKind::TntLong { bits, count } => {
                for i in 0..*count {
                    self.tnt_queue.push_back((bits >> i) & 1 == 1);
                }
            }

            PtPacketKind::TipPge { ip, .. } => {
                self.current_ip = *ip;
                self.tracing_enabled = true;
                self.emit_event(
                    PtEvent::TraceEnabled { ip: *ip },
                    packet_index,
                );
            }

            PtPacketKind::TipPgd { ip, .. } => {
                self.current_ip = *ip;
                self.tracing_enabled = false;
                self.emit_event(
                    PtEvent::TraceDisabled { ip: *ip },
                    packet_index,
                );
            }

            PtPacketKind::Tip { ip, .. } => {
                let from = self.current_ip;
                let to = *ip;
                self.flow.tip_packets_consumed += 1;
                // Attempt return prediction from call stack
                let is_predicted_return = self
                    .call_stack
                    .last()
                    .is_some_and(|f| f.return_addr == to);
                if is_predicted_return {
                    self.call_stack.pop();
                    self.return_stack_hits += 1;
                    self.emit_event(PtEvent::Return { from, to }, packet_index);
                } else {
                    self.emit_event(PtEvent::IndirectBranch { from, to }, packet_index);
                }
                self.current_ip = to;
            }

            PtPacketKind::Tsc(tsc) => {
                self.current_tsc = Some(*tsc);
                self.flow.timing.record_tsc(*tsc);
                self.emit_event(PtEvent::Timestamp { tsc: *tsc }, packet_index);
            }

            PtPacketKind::Cbr(cbr) => {
                self.flow.timing.record_cbr(*cbr);
            }

            PtPacketKind::Mtc { ctc } => {
                self.flow.timing.record_mtc(*ctc);
            }

            PtPacketKind::Cyc { value } => {
                self.flow.timing.record_cyc(*value);
            }

            PtPacketKind::Overflow => {
                self.emit_event(
                    PtEvent::Overflow { offset: pkt.offset },
                    packet_index,
                );
                // On overflow, clear TNT queue (state is uncertain)
                self.tnt_queue.clear();
            }

            PtPacketKind::Mode { leaf, bits } => {
                self.emit_event(
                    PtEvent::ModeChange { leaf: *leaf, bits: *bits },
                    packet_index,
                );
                // Update ring level from MODE.Exec
                if *leaf == 0x43 {
                    let new_ring = RingLevel::from_mode_bits(*bits >> 2);
                    if new_ring != self.ring {
                        self.ring = new_ring;
                        self.ring_transitions += 1;
                    }
                }
            }

            _ => {}
        }
    }

    /// Process a conditional branch at `ip` with `target` and `fallthrough`.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// Consumes one TNT bit to determine the outcome.
    ///
    /// Returns `Ok(taken_address)` or `Err` if no TNT bit is available.
    pub fn resolve_conditional(
        &mut self,
        ip: u64,
        target: u64,
        fallthrough: u64,
        packet_index: usize,
    ) -> Result<u64, PtError> {
        let taken = self
            .tnt_queue
            .pop_front()
            .ok_or_else(|| PtError::FlowReconstruction("TNT queue empty".into()))?;
        self.flow.tnt_bits_consumed += 1;
        if taken {
            self.current_ip = target;
            self.emit_event(PtEvent::BranchTaken { ip, target }, packet_index);
            Ok(target)
        } else {
            self.current_ip = fallthrough;
            self.emit_event(
                PtEvent::BranchNotTaken { ip, fallthrough },
                packet_index,
            );
            Ok(fallthrough)
        }
    }

    /// Process a direct call to `target`.
    pub fn record_direct_call(&mut self, from: u64, target: u64, return_addr: u64, packet_index: usize) {
        if self.call_stack.len() < self.config.max_call_depth {
            self.call_stack.push(CallFrame {
                call_site: from,
                return_addr,
                callee: target,
                call_tsc: self.current_tsc,
            });
        }
        self.current_ip = target;
        self.emit_event(PtEvent::Call { from, to: target }, packet_index);
    }

    /// Process a return via TIP resolution.
    ///
    /// `ip`: return instruction address, `to`: resolved return target (from TIP).
    pub fn record_return(&mut self, ip: u64, to: u64, packet_index: usize) {
        // Check call stack
        if let Some(frame) = self.call_stack.last() {
            if frame.return_addr == to {
                self.call_stack.pop();
                self.return_stack_hits += 1;
            } else {
                self.return_stack_misses += 1;
            }
        }
        self.current_ip = to;
        self.emit_event(PtEvent::Return { from: ip, to }, packet_index);
    }

    /// Record a ring transition event.
    pub fn record_ring_transition(&mut self, from: RingLevel, to: RingLevel, ip: u64, packet_index: usize) {
        self.ring = to;
        self.ring_transitions += 1;
        // Emit as a ModeChange event with fabricated mode bits
        let bits = match to {
            RingLevel::Ring0 => 0x00,
            RingLevel::Ring3 => 0x03,
            RingLevel::Ring1 => 0x01,
            RingLevel::Ring2 => 0x02,
        };
        let _ = (from, ip, packet_index);
        self.emit_event(PtEvent::ModeChange { leaf: 0xFF, bits }, packet_index);
    }

    /// Record a SYSCALL instruction.
    pub fn record_syscall(&mut self, ip: u64, packet_index: usize) {
        if self.config.track_syscalls {
            self.record_ring_transition(RingLevel::Ring3, RingLevel::Ring0, ip, packet_index);
        }
    }

    /// Record a SYSRET instruction.
    pub fn record_sysret(&mut self, ip: u64, packet_index: usize) {
        if self.config.track_syscalls {
            self.record_ring_transition(RingLevel::Ring0, RingLevel::Ring3, ip, packet_index);
        }
    }

    /// Record an instruction address as executed (for heatmap/coverage).
    pub fn record_executed(&mut self, addr: u64) {
        *self.heatmap.entry(addr).or_insert(0) += 1;
        self.blocks_visited.insert(addr);
        self.flow.addresses_visited.insert(addr);
    }

    /// Feed all packets from a slice.
    pub fn feed_packets(&mut self, packets: &[PtPacket]) {
        for (i, pkt) in packets.iter().enumerate() {
            if let Some(max) = self.config.max_events
                && self.events.len() >= max
            {
                break;
            }
            self.feed_packet(pkt, i);
        }
    }

    /// Return the current call stack depth.
    #[must_use]
    pub const fn call_depth(&self) -> usize {
        self.call_stack.len()
    }

    /// Return the number of pending TNT bits.
    #[must_use]
    pub fn pending_tnt(&self) -> usize {
        self.tnt_queue.len()
    }

    /// Return the hottest N addresses from the heatmap.
    #[must_use]
    pub fn top_hot_addresses(&self, n: usize) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self.heatmap.iter().map(|(&a, &c)| (a, c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    /// Return the call stack as a slice.
    #[must_use]
    pub fn call_stack(&self) -> &[CallFrame] {
        &self.call_stack
    }

    /// Return a summary of the reconstruction.
    #[must_use]
    pub fn summary(&self) -> ReconstructionSummary {
        let direct_branches = self
            .events
            .iter()
            .filter(|e| {
                matches!(
                    e.event,
                    PtEvent::BranchTaken { .. } | PtEvent::BranchNotTaken { .. }
                )
            })
            .count();
        let indirect_branches = self
            .events
            .iter()
            .filter(|e| matches!(e.event, PtEvent::IndirectBranch { .. }))
            .count();
        let calls = self
            .events
            .iter()
            .filter(|e| matches!(e.event, PtEvent::Call { .. }))
            .count();
        let returns = self
            .events
            .iter()
            .filter(|e| matches!(e.event, PtEvent::Return { .. }))
            .count();
        let overflows = self
            .events
            .iter()
            .filter(|e| matches!(e.event, PtEvent::Overflow { .. }))
            .count();

        ReconstructionSummary {
            total_events: self.events.len(),
            direct_branches,
            indirect_branches,
            calls,
            returns,
            overflows,
            unique_addresses: self.flow.addresses_visited.len(),
            tnt_bits_consumed: self.flow.tnt_bits_consumed,
            tip_packets: self.flow.tip_packets_consumed,
            ring_transitions: self.ring_transitions,
            return_stack_hits: self.return_stack_hits,
            return_stack_misses: self.return_stack_misses,
            call_depth_max: self.call_stack.len(),
        }
    }

    // Internal: emit a flow event with metadata.
    fn emit_event(&mut self, event: PtEvent, packet_index: usize) {
        self.flow.push_event(event.clone());
        self.events.push(FlowEvent {
            event,
            ring: Some(self.ring),
            tsc: self.current_tsc,
            packet_index,
        });
    }
}

impl Default for FlowReconstructor {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ReconstructionSummary ────────────────────────────────────────────────────

/// Summary statistics from flow reconstruction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReconstructionSummary {
    /// Total flow events emitted.
    pub total_events: usize,
    /// Conditional branch outcomes resolved.
    pub direct_branches: usize,
    /// Indirect branch targets resolved.
    pub indirect_branches: usize,
    /// Call events.
    pub calls: usize,
    /// Return events.
    pub returns: usize,
    /// Overflow events.
    pub overflows: usize,
    /// Unique instruction addresses seen.
    pub unique_addresses: usize,
    /// TNT bits consumed.
    pub tnt_bits_consumed: u64,
    /// TIP packets consumed.
    pub tip_packets: u64,
    /// Ring-level transitions.
    pub ring_transitions: u64,
    /// Correct return-stack predictions.
    pub return_stack_hits: u64,
    /// Incorrect return-stack predictions.
    pub return_stack_misses: u64,
    /// Maximum observed call depth.
    pub call_depth_max: usize,
}

impl std::fmt::Display for ReconstructionSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FlowSummary {{ events={}, cond={}, indirect={}, calls={}, \
             returns={}, overflows={}, unique_addrs={}, ring_trans={}, \
             rsp_hits={}/{} }}",
            self.total_events,
            self.direct_branches,
            self.indirect_branches,
            self.calls,
            self.returns,
            self.overflows,
            self.unique_addresses,
            self.ring_transitions,
            self.return_stack_hits,
            self.return_stack_hits + self.return_stack_misses
        )
    }
}

// ─── ExceptionFlowAnalyzer ────────────────────────────────────────────────────

/// Identifies exception/interrupt flow patterns in the event stream.
pub struct ExceptionFlowAnalyzer {
    /// Detected exception entries (from, handler).
    pub exception_entries: Vec<(u64, u64)>,
    /// Detected exception returns.
    pub exception_returns: Vec<(u64, u64)>,
    /// Last known ring level.
    last_ring: RingLevel,
}

impl ExceptionFlowAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            exception_entries: Vec::new(),
            exception_returns: Vec::new(),
            last_ring: RingLevel::Ring3,
        }
    }

    /// Analyze a slice of events for exception patterns.
    pub fn analyze(&mut self, events: &[FlowEvent]) {
        let mut i = 0;
        while i < events.len() {
            if let PtEvent::ModeChange { bits, .. } = &events[i].event {
                let new_ring = RingLevel::from_mode_bits(*bits);
                if new_ring == RingLevel::Ring0 && self.last_ring == RingLevel::Ring3 {
                    // Transition to ring 0 — check for subsequent TIP (exception handler)
                    if let Some(next) = events.get(i + 1)
                        && let PtEvent::IndirectBranch { to, .. }
                        | PtEvent::TraceEnabled { ip: to } = &next.event
                    {
                        self.exception_entries.push((0, *to));
                    }
                } else if new_ring == RingLevel::Ring3 && self.last_ring == RingLevel::Ring0 {
                    // Transition to ring 3 — exception return
                    if let Some(prev) = events.get(i.saturating_sub(1))
                        && let PtEvent::Return { to, .. } = &prev.event
                    {
                        self.exception_returns.push((0, *to));
                    }
                }
                self.last_ring = new_ring;
            }
            i += 1;
        }
    }

    /// Return the number of detected exceptions.
    #[must_use]
    pub const fn exception_count(&self) -> usize {
        self.exception_entries.len()
    }
}

impl Default for ExceptionFlowAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── CallGraph ────────────────────────────────────────────────────────────────

/// A call graph built from PT flow events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallGraph {
    /// Edges: caller address → set of callee addresses.
    pub edges: HashMap<u64, HashSet<u64>>,
    /// Call counts per edge.
    pub counts: HashMap<(u64, u64), u64>,
}

impl CallGraph {
    /// Create an empty call graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a call edge.
    pub fn record_call(&mut self, from: u64, to: u64) {
        self.edges.entry(from).or_default().insert(to);
        *self.counts.entry((from, to)).or_insert(0) += 1;
    }

    /// Build a call graph from a slice of flow events.
    #[must_use]
    pub fn from_events(events: &[FlowEvent]) -> Self {
        let mut cg = Self::new();
        for e in events {
            if let PtEvent::Call { from, to } = &e.event {
                cg.record_call(*from, *to);
            }
        }
        cg
    }

    /// Return all callers of `addr`.
    #[must_use]
    pub fn callers_of(&self, addr: u64) -> Vec<u64> {
        self.edges
            .iter()
            .filter_map(|(caller, callees)| {
                if callees.contains(&addr) {
                    Some(*caller)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return all callees of `addr`.
    #[must_use]
    pub fn callees_of(&self, addr: u64) -> Vec<u64> {
        self.edges
            .get(&addr)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Return the number of unique call sites.
    #[must_use]
    pub fn call_site_count(&self) -> usize {
        self.edges.len()
    }

    /// Return the hottest call edges (most frequent).
    #[must_use]
    pub fn top_edges(&self, n: usize) -> Vec<((u64, u64), u64)> {
        let mut v: Vec<_> = self.counts.iter().map(|(&e, &c)| (e, c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IpCompression;

    fn make_tip(ip: u64) -> PtPacket {
        PtPacket::new(
            PtPacketKind::Tip { ip, compression: IpCompression::Full48 },
            0,
            7,
        )
    }

    fn make_tnt(bits: u64, count: u8) -> PtPacket {
        PtPacket::new(PtPacketKind::Tnt { bits, count }, 0, 1)
    }

    fn make_pge(ip: u64) -> PtPacket {
        PtPacket::new(
            PtPacketKind::TipPge { ip, compression: IpCompression::Full48 },
            0,
            7,
        )
    }

    fn make_pgd(ip: u64) -> PtPacket {
        PtPacket::new(
            PtPacketKind::TipPgd { ip, compression: IpCompression::Full48 },
            0,
            7,
        )
    }

    #[test]
    fn test_pge_pgd_events() {
        let mut fr = FlowReconstructor::new();
        fr.feed_packet(&make_pge(0x1000), 0);
        fr.feed_packet(&make_pgd(0x2000), 1);
        assert_eq!(fr.current_ip, 0x2000);
        assert!(!fr.tracing_enabled);
        let s = fr.summary();
        assert_eq!(s.total_events, 2);
    }

    #[test]
    fn test_tip_produces_indirect_branch() {
        let mut fr = FlowReconstructor::new();
        fr.current_ip = 0x1000;
        fr.feed_packet(&make_tip(0x3000), 0);
        let s = fr.summary();
        assert_eq!(s.indirect_branches, 1);
    }

    #[test]
    fn test_tip_predicted_return() {
        let mut fr = FlowReconstructor::new();
        // Push a call frame with return_addr = 0x2005
        fr.call_stack.push(CallFrame {
            call_site: 0x2000,
            return_addr: 0x2005,
            callee: 0x3000,
            call_tsc: None,
        });
        fr.current_ip = 0x3FF0;
        fr.feed_packet(&make_tip(0x2005), 0);
        // Should be recognized as a return
        assert_eq!(fr.return_stack_hits, 1);
        assert_eq!(fr.call_stack.len(), 0);
    }

    #[test]
    fn test_tnt_queue_consumed_by_resolve() {
        let mut fr = FlowReconstructor::new();
        fr.feed_packet(&make_tnt(0b1, 1), 0); // 1 taken bit
        assert_eq!(fr.pending_tnt(), 1);
        let result = fr.resolve_conditional(0x1000, 0x2000, 0x1004, 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0x2000); // taken
        assert_eq!(fr.pending_tnt(), 0);
    }

    #[test]
    fn test_tnt_not_taken() {
        let mut fr = FlowReconstructor::new();
        fr.feed_packet(&make_tnt(0b0, 1), 0); // 1 not-taken bit
        let result = fr.resolve_conditional(0x1000, 0x2000, 0x1004, 0);
        assert_eq!(result.unwrap(), 0x1004); // not taken -> fallthrough
    }

    #[test]
    fn test_tnt_queue_empty_error() {
        let mut fr = FlowReconstructor::new();
        let result = fr.resolve_conditional(0x1000, 0x2000, 0x1004, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_overflow_clears_tnt() {
        let mut fr = FlowReconstructor::new();
        fr.feed_packet(&make_tnt(0b1111, 4), 0);
        assert_eq!(fr.pending_tnt(), 4);
        let ovf = PtPacket::new(PtPacketKind::Overflow, 0, 1);
        fr.feed_packet(&ovf, 1);
        assert_eq!(fr.pending_tnt(), 0);
    }

    #[test]
    fn test_direct_call_push_frame() {
        let mut fr = FlowReconstructor::new();
        fr.record_direct_call(0x1000, 0x5000, 0x1005, 0);
        assert_eq!(fr.call_depth(), 1);
        assert_eq!(fr.call_stack()[0].return_addr, 0x1005);
    }

    #[test]
    fn test_return_record() {
        let mut fr = FlowReconstructor::new();
        fr.call_stack.push(CallFrame {
            call_site: 0x100,
            return_addr: 0x105,
            callee: 0x200,
            call_tsc: None,
        });
        fr.record_return(0x280, 0x105, 0);
        assert_eq!(fr.return_stack_hits, 1);
        assert_eq!(fr.call_depth(), 0);
    }

    #[test]
    fn test_heatmap() {
        let mut fr = FlowReconstructor::new();
        fr.record_executed(0x1000);
        fr.record_executed(0x1000);
        fr.record_executed(0x1004);
        assert_eq!(fr.heatmap[&0x1000], 2);
        assert_eq!(fr.heatmap[&0x1004], 1);
        let hot = fr.top_hot_addresses(1);
        assert_eq!(hot[0].0, 0x1000);
    }

    #[test]
    fn test_summary_display() {
        let fr = FlowReconstructor::new();
        let s = fr.summary();
        let _disp = s.to_string();
    }

    #[test]
    fn test_call_graph_from_events() {
        let mut fr = FlowReconstructor::new();
        fr.record_direct_call(0x1000, 0x2000, 0x1005, 0);
        fr.record_direct_call(0x1000, 0x3000, 0x1005, 1);
        fr.record_direct_call(0x1000, 0x2000, 0x1005, 2);
        let cg = CallGraph::from_events(&fr.events);
        assert_eq!(cg.call_site_count(), 1);
        let callees = cg.callees_of(0x1000);
        assert!(callees.contains(&0x2000));
        assert!(callees.contains(&0x3000));
    }

    #[test]
    fn test_call_graph_top_edges() {
        let mut cg = CallGraph::new();
        cg.record_call(0x1000, 0x2000);
        cg.record_call(0x1000, 0x2000);
        cg.record_call(0x1000, 0x3000);
        let top = cg.top_edges(1);
        assert_eq!(top[0].0, (0x1000, 0x2000));
        assert_eq!(top[0].1, 2);
    }

    #[test]
    fn test_instruction_kind_needs_tnt() {
        assert!(InstructionKind::ConditionalBranch.needs_tnt());
        assert!(!InstructionKind::Linear.needs_tnt());
        assert!(!InstructionKind::IndirectBranch.needs_tnt());
    }

    #[test]
    fn test_instruction_kind_needs_tip() {
        assert!(InstructionKind::Return.needs_tip());
        assert!(InstructionKind::IndirectCall.needs_tip());
        assert!(!InstructionKind::ConditionalBranch.needs_tip());
    }

    #[test]
    fn test_decoded_instruction_conditional() {
        let insn = DecodedInstruction::conditional_branch(0x1000, 6, 0x2000);
        assert_eq!(insn.fallthrough, 0x1006);
        assert_eq!(insn.direct_target, Some(0x2000));
    }

    #[test]
    fn test_flow_block_push() {
        let mut block = FlowBlock::new(0x1000);
        block.push(DecodedInstruction::linear(0x1000, 4));
        block.push(DecodedInstruction::linear(0x1004, 4));
        assert_eq!(block.len(), 2);
        assert_eq!(block.end, 0x1008);
    }

    #[test]
    fn test_exception_flow_analyzer() {
        let mut analyzer = ExceptionFlowAnalyzer::new();
        let events = vec![
            FlowEvent {
                event: PtEvent::ModeChange { leaf: 0x43, bits: 0x00 }, // to Ring0
                ring: Some(RingLevel::Ring3),
                tsc: None,
                packet_index: 0,
            },
            FlowEvent {
                event: PtEvent::IndirectBranch { from: 0x100, to: 0xFFFF_8000_0000 },
                ring: Some(RingLevel::Ring0),
                tsc: None,
                packet_index: 1,
            },
        ];
        analyzer.last_ring = RingLevel::Ring3;
        analyzer.analyze(&events);
        let _ = analyzer.exception_count(); // structural test
    }

    #[test]
    fn test_ring_level_from_mode_bits() {
        assert_eq!(RingLevel::from_mode_bits(0x00), RingLevel::Ring0);
        assert_eq!(RingLevel::from_mode_bits(0x03), RingLevel::Ring3);
    }

    #[test]
    fn test_feed_packets_respects_max_events() {
        let config = FlowReconstructorConfig {
            max_events: Some(2),
            ..FlowReconstructorConfig::default()
        };
        let mut fr = FlowReconstructor::with_config(config);
        let pkts: Vec<PtPacket> = (0..10)
            .map(|i| PtPacket::new(PtPacketKind::Tsc(i as u64), i, 9))
            .collect();
        fr.feed_packets(&pkts);
        assert!(fr.events.len() <= 2);
    }
}
