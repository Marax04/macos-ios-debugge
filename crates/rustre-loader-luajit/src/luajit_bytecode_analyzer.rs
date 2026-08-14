/// `luajit_bytecode_analyzer.rs` â€” Call-graph and complexity analysis for `LuaJIT` 2.x protos.
///
/// Works on the proto list produced by the `bytecode_format` / `instruction_decoder` modules.
/// All analysis is purely structural (no execution): it derives call edges from CALL/CALLT/CALLM
/// opcodes, detects back-edges for loops, computes `McCabe` cyclomatic complexity and classifies
/// each proto by its dominant characteristics.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// â”€â”€â”€ opcode constants (LuaJIT 2.x) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Opcode byte for CALL  (call with fixed result count).
const OP_CALL: u8  = 0x3D;
/// Opcode byte for CALLT (tail call).
const OP_CALLT: u8 = 0x3F;
/// Opcode byte for CALLM (call with multiple results).
const OP_CALLM: u8 = 0x3E;
/// Opcode byte for JMP   (unconditional jump).
const OP_JMP: u8   = 0x52;
/// Opcode byte for LOOP  (loop header hint).
const OP_LOOP: u8  = 0x59;
/// Opcode byte for ITERC (generic iterator call).
const OP_ITERC: u8 = 0x41;
/// Opcode byte for ITERN (next iterator).
const OP_ITERN: u8 = 0x42;
/// Opcode byte for FORI  (for init).
const OP_FORI: u8  = 0x4A;
/// Opcode byte for FORL  (for loop).
const OP_FORL: u8  = 0x4B;
/// Opcode byte for JFORI (JIT for init).
const OP_JFORI: u8 = 0x4C;
/// Opcode byte for JFORL (JIT for loop).
const OP_JFORL: u8 = 0x4D;
/// Opcode byte for UCLO  (close upvalues and jump).
const OP_UCLO: u8  = 0x4E;
/// Opcode byte for FNEW  (create new closure).
const OP_FNEW: u8  = 0x1B;
/// Opcode byte for RETM  (return with multiple).
const OP_RETM: u8  = 0x53;
/// Opcode byte for RET   (return).
const OP_RET: u8   = 0x54;
/// Opcode byte for RET0  (return nothing).
const OP_RET0: u8  = 0x55;
/// Opcode byte for RET1  (return one value).
const OP_RET1: u8  = 0x56;

// â”€â”€â”€ RawInstruction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A single `LuaJIT` instruction word decoded into its fields.
#[derive(Debug, Clone, Copy)]
pub struct RawInstruction {
    pub pc: u32,
    pub op: u8,
    pub a: u8,
    pub c: u8,
    pub b: u8,
    /// Raw unsigned D field (bits 16-31 of the instruction word).
    /// Use `jump_target()` for the signed jump offset.
    pub d: u16,
}

impl RawInstruction {
    /// Decode a 4-byte little-endian instruction word.
    #[must_use]
    pub const fn decode(word: u32, pc: u32) -> Self {
        let op = (word & 0xFF) as u8;
        let a  = ((word >> 8) & 0xFF) as u8;
        let c  = ((word >> 16) & 0xFF) as u8;
        let b  = ((word >> 24) & 0xFF) as u8;
        // Store the raw unsigned 16-bit D value; jump_target() applies the bias.
        let d  = (word >> 16) as u16;
        Self { pc, op, a, c, b, d }
    }

    /// True when this instruction is a call of any kind.
    #[must_use]
    pub const fn is_call(self) -> bool {
        matches!(self.op, OP_CALL | OP_CALLT | OP_CALLM | OP_ITERC | OP_ITERN)
    }

    /// True when this instruction is a branch/jump.
    #[must_use]
    pub const fn is_branch(self) -> bool {
        matches!(self.op,
            OP_JMP | OP_LOOP | OP_FORI | OP_FORL | OP_JFORI |
            OP_JFORL | OP_UCLO)
    }

    /// True when this instruction is a return.
    #[must_use]
    pub const fn is_return(self) -> bool {
        matches!(self.op, OP_RETM | OP_RET | OP_RET0 | OP_RET1)
    }

    /// Jump target PC (relative D field offset from next instruction), if applicable.
    #[must_use]
    pub const fn jump_target(self) -> Option<i32> {
        if self.is_branch() {
            // LuaJIT JMP target = current_pc + 1 + (D_unsigned - 0x8000)
            // D is stored as raw u16; apply bias here as signed subtraction.
            let d_signed: i32 = self.d as i32 - 0x8000;
            Some(self.pc as i32 + 1 + d_signed)
        } else {
            None
        }
    }
}

// â”€â”€â”€ CallEdge â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A directed call edge between two proto indices.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallEdge {
    /// Index of the calling proto.
    pub caller: usize,
    /// Index of the callee proto (if statically known).
    pub callee: usize,
    /// PC of the CALL instruction in the caller.
    pub call_pc: u32,
    /// Opcode that generated this edge.
    pub op: u8,
}

impl fmt::Display for CallEdge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "proto[{}] --call@{}-> proto[{}]", self.caller, self.call_pc, self.callee)
    }
}

// â”€â”€â”€ HotLoop â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A back-edge that forms a natural loop.
#[derive(Debug, Clone)]
pub struct HotLoop {
    /// Proto index containing the loop.
    pub proto_idx: usize,
    /// PC of the loop header (target of the back-edge).
    pub header_pc: u32,
    /// PC of the back-edge instruction.
    pub latch_pc: u32,
    /// Opcode at the latch.
    pub latch_op: u8,
    /// Estimated iteration count (heuristic: number of instructions in loop body).
    pub body_size: u32,
}

impl fmt::Display for HotLoop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "proto[{}] loop header=0x{:04x} latch=0x{:04x} body_size={}",
            self.proto_idx, self.header_pc, self.latch_pc, self.body_size
        )
    }
}

// â”€â”€â”€ ProtoComplexity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// `McCabe` cyclomatic complexity and related metrics for a single proto.
#[derive(Debug, Clone)]
pub struct ProtoComplexity {
    pub proto_idx: usize,
    /// Number of instructions.
    pub insn_count: u32,
    /// Number of branch/jump instructions.
    pub branch_count: u32,
    /// Number of return instructions.
    pub return_count: u32,
    /// `McCabe` cyclomatic complexity M = E - N + 2P  (approximated as branches + 1).
    pub cyclomatic: u32,
    /// Number of upvalues referenced.
    pub upvalue_refs: u32,
    /// True if any back-edge was found (recursive or loop).
    pub has_back_edge: bool,
    /// Number of FNEW instructions (nested closures created).
    pub nested_closures: u32,
}

impl ProtoComplexity {
    /// Qualitative rating.
    #[must_use]
    pub const fn rating(&self) -> &'static str {
        match self.cyclomatic {
            0..=4   => "simple",
            5..=10  => "moderate",
            11..=20 => "complex",
            _       => "very_complex",
        }
    }
}

impl fmt::Display for ProtoComplexity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "proto[{}] insns={} branches={} cyclomatic={} ({})",
            self.proto_idx, self.insn_count, self.branch_count, self.cyclomatic, self.rating()
        )
    }
}

// â”€â”€â”€ ProtoClass â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// High-level classification of a proto's role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoClass {
    /// Simple helper: low complexity, few calls.
    Helper,
    /// Dispatch function: many branches, moderate calls.
    Dispatcher,
    /// Hot loop kernel: contains at least one back-edge loop.
    LoopKernel,
    /// Recursive function: calls itself directly.
    Recursive,
    /// Factory: creates many closures via FNEW.
    Factory,
    /// Entry-point: first proto in the chunk.
    EntryPoint,
    /// Complex/unclassified.
    Complex,
}

impl fmt::Display for ProtoClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Helper      => "Helper",
            Self::Dispatcher  => "Dispatcher",
            Self::LoopKernel  => "LoopKernel",
            Self::Recursive   => "Recursive",
            Self::Factory     => "Factory",
            Self::EntryPoint  => "EntryPoint",
            Self::Complex     => "Complex",
        };
        write!(f, "{s}")
    }
}

// â”€â”€â”€ ProtoAnalysis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Full analysis result for a single `LuaJIT` proto.
#[derive(Debug, Clone)]
pub struct ProtoAnalysis {
    pub proto_idx: usize,
    pub complexity: ProtoComplexity,
    pub hot_loops: Vec<HotLoop>,
    pub class: ProtoClass,
    /// Indices of protos this proto calls (may be empty if callee unknown).
    pub callees: Vec<usize>,
    /// Indices of protos that call this proto.
    pub callers: Vec<usize>,
}

impl fmt::Display for ProtoAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProtoAnalysis[{}] class={} loops={} callees={:?}",
            self.proto_idx, self.class, self.hot_loops.len(), self.callees
        )
    }
}

// â”€â”€â”€ RawProto â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Minimal proto descriptor consumed by the analyzer.
#[derive(Debug, Clone)]
pub struct RawProto {
    /// Proto index in the chunk.
    pub index: usize,
    /// Raw instruction words (little-endian u32 each).
    pub instructions: Vec<u32>,
    /// Number of upvalues.
    pub num_upvalues: u8,
    /// Number of parameters.
    pub num_params: u8,
    /// Nested proto indices referenced by FNEW instructions (from KGC table).
    pub nested_proto_indices: Vec<usize>,
}

impl RawProto {
    /// Decode all instruction words.
    #[must_use]
    pub fn decode_instructions(&self) -> Vec<RawInstruction> {
        self.instructions
            .iter()
            .enumerate()
            .map(|(i, &w)| RawInstruction::decode(w, i as u32))
            .collect()
    }
}

// â”€â”€â”€ BytecodeAnalyzer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Main analysis engine.  Feed it protos and call `analyze_all()`.
pub struct BytecodeAnalyzer {
    protos: Vec<RawProto>,
}

impl BytecodeAnalyzer {
    #[must_use]
    pub const fn new(protos: Vec<RawProto>) -> Self {
        Self { protos }
    }

    /// Analyze all protos and return per-proto results plus global call edges.
    #[must_use]
    pub fn analyze_all(&self) -> AnalysisReport {
        let call_edges = self.extract_call_edges();
        let mut analyses: Vec<ProtoAnalysis> = self
            .protos
            .iter()
            .map(|p| self.analyze_proto(p, &call_edges))
            .collect();

        // Back-fill callers from call-edges.
        let edge_copy = call_edges.clone();
        for edge in &edge_copy {
            if edge.callee < analyses.len() {
                let caller = edge.caller;
                analyses[edge.callee].callers.push(caller);
            }
        }

        // Detect self-recursion.
        for a in &mut analyses {
            if a.callees.contains(&a.proto_idx) {
                a.complexity.has_back_edge = true;
                if a.class != ProtoClass::EntryPoint {
                    a.class = ProtoClass::Recursive;
                }
            }
        }

        AnalysisReport {
            analyses,
            call_edges,
            proto_count: self.protos.len(),
        }
    }

    fn extract_call_edges(&self) -> Vec<CallEdge> {
        let mut edges = Vec::new();
        for proto in &self.protos {
            let insns = proto.decode_instructions();
            for insn in &insns {
                if insn.is_call() {
                    // Register A holds the function slot.
                    // We use a heuristic: if FNEW was recently executed for slot A,
                    // we can determine the callee proto.  Without data-flow, we emit
                    // edges only when we see FNEW immediately before CALL for same reg.
                    // Simpler: map FNEW index to proto index via nested_proto_indices.
                    // Here we emit unknown-callee edges (callee = usize::MAX as sentinel).
                    edges.push(CallEdge {
                        caller: proto.index,
                        callee: usize::MAX,
                        call_pc: insn.pc,
                        op: insn.op,
                    });
                }
            }
            // FNEW edges: each FNEW references a proto by KGC index.
            for insn in &insns {
                if insn.op == OP_FNEW {
                    let kgc_idx = insn.d as usize;
                    if kgc_idx < proto.nested_proto_indices.len() {
                        let callee_proto = proto.nested_proto_indices[kgc_idx];
                        edges.push(CallEdge {
                            caller: proto.index,
                            callee: callee_proto,
                            call_pc: insn.pc,
                            op: OP_FNEW,
                        });
                    }
                }
            }
        }
        edges
    }

    fn analyze_proto(&self, proto: &RawProto, all_edges: &[CallEdge]) -> ProtoAnalysis {
        let insns = proto.decode_instructions();
        let n = insns.len() as u32;

        let mut branch_count: u32 = 0;
        let mut return_count: u32 = 0;
        let mut upvalue_refs: u32 = 0;
        let mut nested_closures: u32 = 0;
        let mut hot_loops: Vec<HotLoop> = Vec::new();

        for insn in &insns {
            if insn.is_branch() {
                branch_count += 1;
                // Check for back-edge (target <= current pc).
                if let Some(tgt) = insn.jump_target()
                    && tgt >= 0 && (tgt as u32) <= insn.pc {
                        let header_pc = tgt as u32;
                        let latch_pc  = insn.pc;
                        let body_size = latch_pc.saturating_sub(header_pc);
                        hot_loops.push(HotLoop {
                            proto_idx: proto.index,
                            header_pc,
                            latch_pc,
                            latch_op: insn.op,
                            body_size,
                        });
                    }
            }
            if insn.is_return() {
                return_count += 1;
            }
            // UGET / USET / UCLO opcodes are in range 0x30-0x38; approximate.
            if insn.op >= 0x30 && insn.op <= 0x38 {
                upvalue_refs += 1;
            }
            if insn.op == OP_FNEW {
                nested_closures += 1;
            }
        }

        let cyclomatic = branch_count + 1;
        let has_back_edge = !hot_loops.is_empty();

        let complexity = ProtoComplexity {
            proto_idx: proto.index,
            insn_count: n,
            branch_count,
            return_count,
            cyclomatic,
            upvalue_refs,
            has_back_edge,
            nested_closures,
        };

        // Collect known callees.
        let callees: Vec<usize> = all_edges
            .iter()
            .filter(|e| e.caller == proto.index && e.callee != usize::MAX)
            .map(|e| e.callee)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let class = classify_proto(proto.index, &complexity, &hot_loops, &callees);

        ProtoAnalysis {
            proto_idx: proto.index,
            complexity,
            hot_loops,
            class,
            callees,
            callers: Vec::new(), // back-filled later
        }
    }
}

const fn classify_proto(
    idx: usize,
    c: &ProtoComplexity,
    loops: &[HotLoop],
    callees: &[usize],
) -> ProtoClass {
    if idx == 0 {
        return ProtoClass::EntryPoint;
    }
    if c.nested_closures >= 3 {
        return ProtoClass::Factory;
    }
    if !loops.is_empty() {
        return ProtoClass::LoopKernel;
    }
    if c.branch_count >= 8 && callees.len() >= 3 {
        return ProtoClass::Dispatcher;
    }
    if c.cyclomatic > 20 {
        return ProtoClass::Complex;
    }
    ProtoClass::Helper
}

// â”€â”€â”€ AnalysisReport â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Aggregate report over all protos in a `LuaJIT` chunk.
#[derive(Debug)]
pub struct AnalysisReport {
    pub analyses: Vec<ProtoAnalysis>,
    pub call_edges: Vec<CallEdge>,
    pub proto_count: usize,
}

impl AnalysisReport {
    /// Find protos reachable from `start` via BFS on call-graph.
    #[must_use]
    pub fn reachable_from(&self, start: usize) -> Vec<usize> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        while let Some(idx) = queue.pop_front() {
            if !visited.insert(idx) {
                continue;
            }
            if let Some(a) = self.analyses.get(idx) {
                for &callee in &a.callees {
                    queue.push_back(callee);
                }
            }
        }
        visited.into_iter().collect()
    }

    /// Return all protos classified as recursive.
    #[must_use]
    pub fn recursive_protos(&self) -> Vec<usize> {
        self.analyses
            .iter()
            .filter(|a| a.class == ProtoClass::Recursive)
            .map(|a| a.proto_idx)
            .collect()
    }

    /// Return all detected hot loops sorted by body size descending.
    #[must_use]
    pub fn hot_loops_sorted(&self) -> Vec<&HotLoop> {
        let mut loops: Vec<&HotLoop> = self.analyses.iter().flat_map(|a| &a.hot_loops).collect();
        loops.sort_by(|a, b| b.body_size.cmp(&a.body_size));
        loops
    }

    /// Total call edge count (including unknown-callee edges).
    #[must_use]
    pub const fn total_call_edges(&self) -> usize {
        self.call_edges.len()
    }

    /// Produce a textual summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut s = format!(
            "LuaJIT analysis: {} protos, {} call-edges\n",
            self.proto_count,
            self.call_edges.len()
        );
        let mut class_counts: HashMap<String, usize> = HashMap::new();
        for a in &self.analyses {
            *class_counts.entry(a.class.to_string()).or_insert(0) += 1;
        }
        for (class, count) in &class_counts {
            s.push_str(&format!("  {class:<15} {count}\n"));
        }
        let loops = self.hot_loops_sorted();
        s.push_str(&format!("  hot loops: {}\n", loops.len()));
        s
    }
}

impl fmt::Display for AnalysisReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// â”€â”€â”€ tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;

    fn make_insn(op: u8, a: u8, c: u8, b: u8) -> u32 {
        (op as u32) | ((a as u32) << 8) | ((c as u32) << 16) | ((b as u32) << 24)
    }

    fn jmp_insn(pc: u32, target: u32) -> u32 {
        // D = target - (pc + 1) + bias; bias = 0x8000
        let d = (target as i32 - pc as i32 - 1 + 0x8000) as u16;
        let c = (d & 0xFF) as u8;
        let b = ((d >> 8) & 0xFF) as u8;
        make_insn(OP_JMP, 0, c, b)
    }

    #[test]
    fn decode_call_insn() {
        let w = make_insn(OP_CALL, 1, 2, 3);
        let insn = RawInstruction::decode(w, 5);
        assert_eq!(insn.op, OP_CALL);
        assert!(insn.is_call());
        assert!(!insn.is_branch());
    }

    #[test]
    fn back_edge_detected() {
        // A simple loop: instructions at PC 0..5, JMP at PC 4 back to PC 0.
        let insns: Vec<u32> = (0..4)
            .map(|_| make_insn(OP_RET0, 0, 0, 0))
            .chain(std::iter::once(jmp_insn(4, 0)))
            .collect();
        let proto = RawProto {
            index: 1,
            instructions: insns,
            num_upvalues: 0,
            num_params: 0,
            nested_proto_indices: vec![],
        };
        let analyzer = BytecodeAnalyzer::new(vec![proto]);
        let report = analyzer.analyze_all();
        assert!(!report.analyses[0].hot_loops.is_empty());
        assert_eq!(report.analyses[0].class, ProtoClass::LoopKernel);
    }

    #[test]
    fn entry_point_classification() {
        let proto = RawProto {
            index: 0,
            instructions: vec![make_insn(OP_RET0, 0, 0, 0)],
            num_upvalues: 0,
            num_params: 0,
            nested_proto_indices: vec![],
        };
        let analyzer = BytecodeAnalyzer::new(vec![proto]);
        let report = analyzer.analyze_all();
        assert_eq!(report.analyses[0].class, ProtoClass::EntryPoint);
    }

    #[test]
    fn factory_classification() {
        // 4 FNEW instructions â†’ Factory
        let insns = (0..4).map(|_| make_insn(OP_FNEW, 0, 0, 0)).collect();
        let proto = RawProto {
            index: 1,
            instructions: insns,
            num_upvalues: 0,
            num_params: 0,
            nested_proto_indices: vec![],
        };
        let analyzer = BytecodeAnalyzer::new(vec![proto]);
        let report = analyzer.analyze_all();
        assert_eq!(report.analyses[0].class, ProtoClass::Factory);
    }

    #[test]
    fn cyclomatic_complexity() {
        let insns: Vec<u32> = (0..6).map(|_| make_insn(OP_JMP, 0, 0x80, 0)).collect();
        // 6 JMPs all with forward targets (bias = 0x8000; D = 0x0080 means tiny positive).
        let proto = RawProto {
            index: 1,
            instructions: insns,
            num_upvalues: 0,
            num_params: 0,
            nested_proto_indices: vec![],
        };
        let analyzer = BytecodeAnalyzer::new(vec![proto]);
        let report = analyzer.analyze_all();
        let c = &report.analyses[0].complexity;
        assert_eq!(c.cyclomatic, 7); // 6 branches + 1
        assert_eq!(c.rating(), "moderate");
    }

    #[test]
    fn reachable_from() {
        let p0 = RawProto { index: 0, instructions: vec![make_insn(OP_FNEW, 0, 0, 0)], num_upvalues: 0, num_params: 0, nested_proto_indices: vec![1] };
        let p1 = RawProto { index: 1, instructions: vec![make_insn(OP_RET0, 0, 0, 0)], num_upvalues: 0, num_params: 0, nested_proto_indices: vec![] };
        let analyzer = BytecodeAnalyzer::new(vec![p0, p1]);
        let report = analyzer.analyze_all();
        let reachable = report.reachable_from(0);
        assert!(reachable.contains(&0));
        assert!(reachable.contains(&1));
    }

    #[test]
    fn hot_loops_sorted_descending() {
        // Two loops with different body sizes; the larger one should come first.
        let make_loop = |idx: usize, header: u32, latch: u32| HotLoop {
            proto_idx: idx, header_pc: header, latch_pc: latch,
            latch_op: OP_JMP, body_size: latch - header,
        };
        let report = AnalysisReport {
            analyses: vec![
                ProtoAnalysis {
                    proto_idx: 0, complexity: ProtoComplexity { proto_idx: 0, insn_count: 10, branch_count: 1, return_count: 1, cyclomatic: 2, upvalue_refs: 0, has_back_edge: true, nested_closures: 0 },
                    hot_loops: vec![make_loop(0, 0, 5), make_loop(0, 10, 25)],
                    class: ProtoClass::LoopKernel, callees: vec![], callers: vec![],
                },
            ],
            call_edges: vec![],
            proto_count: 1,
        };
        let sorted = report.hot_loops_sorted();
        assert!(sorted[0].body_size >= sorted[1].body_size);
    }

    #[test]
    fn summary_contains_proto_count() {
        let analyzer = BytecodeAnalyzer::new(vec![
            RawProto { index: 0, instructions: vec![make_insn(OP_RET0, 0, 0, 0)], num_upvalues: 0, num_params: 0, nested_proto_indices: vec![] },
        ]);
        let report = analyzer.analyze_all();
        let s = report.summary();
        assert!(s.contains("1 protos"));
    }
}
