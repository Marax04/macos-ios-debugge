//! Instruction-level analysis utilities.
//!
//! Provides [`InstrClassifier`], [`ControlFlowEdge`], [`CfgBuilder`],
//! [`InstrPattern`] matching, and basic block boundary detection.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// InstrClass
// ─────────────────────────────────────────────────────────────────────────────

/// High-level classification of an instruction's behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InstrClass {
    /// Integer arithmetic (ADD, SUB, MUL, DIV, …).
    Arithmetic,
    /// Logical operations (AND, OR, XOR, NOT, …).
    Logic,
    /// Data movement (MOV, LOAD, STORE, PUSH, POP, …).
    DataMove,
    /// Comparison / test (CMP, TEST, …).
    Compare,
    /// Unconditional jump (JMP, B, J, …).
    Jump,
    /// Conditional branch (JCC, CBZ, BEQ, …).
    Branch,
    /// Direct call (CALL, BL, JAL, …).
    Call,
    /// Return (RET, BX LR, JALR x0, …).
    Return,
    /// Indirect call through a register.
    IndirectCall,
    /// Indirect jump through a register or memory.
    IndirectJump,
    /// System call / interrupt.
    Syscall,
    /// Floating-point operation.
    FloatOp,
    /// SIMD / vector operation.
    VectorOp,
    /// Cryptographic instruction (AES-NI, SHA, …).
    Crypto,
    /// Privileged / ring-0 instruction.
    Privileged,
    /// No-operation.
    Nop,
    /// Undefined / invalid.
    Undefined,
    /// Other / not classified.
    Other,
}

impl InstrClass {
    /// Returns true if this instruction can change control flow.
    #[must_use]
    pub const fn is_control_flow(self) -> bool {
        matches!(
            self,
            Self::Jump
                | Self::Branch
                | Self::Call
                | Self::Return
                | Self::IndirectCall
                | Self::IndirectJump
                | Self::Syscall
        )
    }

    /// Returns true if this instruction terminates a basic block.
    #[must_use]
    pub const fn is_block_terminator(self) -> bool {
        matches!(
            self,
            Self::Jump | Self::Branch | Self::Return | Self::IndirectJump | Self::Undefined
        )
    }

    /// Returns true if this instruction calls a subroutine.
    #[must_use]
    pub const fn is_call(self) -> bool {
        matches!(self, Self::Call | Self::IndirectCall)
    }
}

impl fmt::Display for InstrClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Arithmetic => "arith",
            Self::Logic => "logic",
            Self::DataMove => "move",
            Self::Compare => "cmp",
            Self::Jump => "jump",
            Self::Branch => "branch",
            Self::Call => "call",
            Self::Return => "return",
            Self::IndirectCall => "indirect_call",
            Self::IndirectJump => "indirect_jump",
            Self::Syscall => "syscall",
            Self::FloatOp => "float",
            Self::VectorOp => "vector",
            Self::Crypto => "crypto",
            Self::Privileged => "privileged",
            Self::Nop => "nop",
            Self::Undefined => "undefined",
            Self::Other => "other",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InstrClassifier
// ─────────────────────────────────────────────────────────────────────────────

/// Classifies instructions by mnemonic string.
///
/// Architecture-agnostic: operates on normalized mnemonic strings.
pub struct InstrClassifier {
    /// Mnemonic prefix → class mappings.
    prefix_map: Vec<(&'static str, InstrClass)>,
    /// Exact mnemonic → class mappings (checked first).
    exact_map: HashMap<&'static str, InstrClass>,
}

impl Default for InstrClassifier {
    fn default() -> Self {
        let mut exact: HashMap<&'static str, InstrClass> = HashMap::new();
        // x86-64 specials
        exact.insert("nop", InstrClass::Nop);
        exact.insert("ret", InstrClass::Return);
        exact.insert("retn", InstrClass::Return);
        exact.insert("retf", InstrClass::Return);
        exact.insert("hlt", InstrClass::Privileged);
        exact.insert("int", InstrClass::Syscall);
        exact.insert("int3", InstrClass::Undefined);
        exact.insert("syscall", InstrClass::Syscall);
        exact.insert("sysenter", InstrClass::Syscall);
        exact.insert("ud2", InstrClass::Undefined);
        exact.insert("call", InstrClass::Call);
        exact.insert("jmp", InstrClass::Jump);
        exact.insert("cmp", InstrClass::Compare);
        exact.insert("test", InstrClass::Compare);
        // AArch64
        exact.insert("ret", InstrClass::Return);
        exact.insert("bl", InstrClass::Call);
        exact.insert("blr", InstrClass::IndirectCall);
        exact.insert("b", InstrClass::Jump);
        exact.insert("br", InstrClass::IndirectJump);
        exact.insert("svc", InstrClass::Syscall);
        // MIPS
        exact.insert("jr", InstrClass::IndirectJump);
        exact.insert("jalr", InstrClass::IndirectCall);
        exact.insert("jal", InstrClass::Call);
        exact.insert("j", InstrClass::Jump);
        exact.insert("syscall", InstrClass::Syscall);
        // RISC-V
        exact.insert("ecall", InstrClass::Syscall);
        exact.insert("ebreak", InstrClass::Undefined);
        exact.insert("auipc", InstrClass::DataMove);
        // x86 mnemonics that would otherwise hit the "b"/"sd" prefixes
        exact.insert("bt", InstrClass::Logic);
        exact.insert("btc", InstrClass::Logic);
        exact.insert("btr", InstrClass::Logic);
        exact.insert("bts", InstrClass::Logic);
        exact.insert("bsf", InstrClass::Logic);
        exact.insert("bsr", InstrClass::Logic);
        exact.insert("bswap", InstrClass::DataMove);
        exact.insert("bound", InstrClass::Other);
        exact.insert("sdiv", InstrClass::Arithmetic);

        let prefix: Vec<(&'static str, InstrClass)> = vec![
            ("add", InstrClass::Arithmetic),
            ("sub", InstrClass::Arithmetic),
            ("mul", InstrClass::Arithmetic),
            ("div", InstrClass::Arithmetic),
            ("imul", InstrClass::Arithmetic),
            ("idiv", InstrClass::Arithmetic),
            ("inc", InstrClass::Arithmetic),
            ("dec", InstrClass::Arithmetic),
            ("neg", InstrClass::Arithmetic),
            ("adc", InstrClass::Arithmetic),
            ("sbb", InstrClass::Arithmetic),
            ("and", InstrClass::Logic),
            ("or", InstrClass::Logic),
            ("xor", InstrClass::Logic),
            ("not", InstrClass::Logic),
            ("shl", InstrClass::Logic),
            ("shr", InstrClass::Logic),
            ("sar", InstrClass::Logic),
            ("rol", InstrClass::Logic),
            ("ror", InstrClass::Logic),
            ("mov", InstrClass::DataMove),
            ("lea", InstrClass::DataMove),
            ("push", InstrClass::DataMove),
            ("pop", InstrClass::DataMove),
            ("xchg", InstrClass::DataMove),
            ("ldr", InstrClass::DataMove),
            ("str", InstrClass::DataMove),
            ("ld", InstrClass::DataMove),
            ("sd", InstrClass::DataMove),
            ("sw", InstrClass::DataMove),
            ("lw", InstrClass::DataMove),
            ("j", InstrClass::Branch),  // jcc prefix
            ("b", InstrClass::Branch),  // beq, bne, etc.
            ("cb", InstrClass::Branch), // cbz, cbnz
            ("tb", InstrClass::Branch), // tbz, tbnz
            ("fld", InstrClass::FloatOp),
            ("fst", InstrClass::FloatOp),
            ("fadd", InstrClass::FloatOp),
            ("fsub", InstrClass::FloatOp),
            ("fmul", InstrClass::FloatOp),
            ("fdiv", InstrClass::FloatOp),
            ("vadd", InstrClass::VectorOp),
            ("vsub", InstrClass::VectorOp),
            ("vmov", InstrClass::VectorOp),
            ("vpxor", InstrClass::VectorOp),
            ("aes", InstrClass::Crypto),
            ("sha", InstrClass::Crypto),
        ];

        Self {
            exact_map: exact,
            prefix_map: prefix,
        }
    }
}

impl InstrClassifier {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Classify a mnemonic string.
    #[must_use]
    pub fn classify(&self, mnemonic: &str) -> InstrClass {
        // Fast path: avoid allocation when mnemonic is already ASCII lowercase
        // (the common case for disassembler output).
        if mnemonic.bytes().all(|b| !b.is_ascii_uppercase()) {
            if let Some(&cls) = self.exact_map.get(mnemonic) {
                return cls;
            }
            for &(prefix, cls) in &self.prefix_map {
                if mnemonic.starts_with(prefix) {
                    return cls;
                }
            }
            return InstrClass::Other;
        }
        let lower = mnemonic.to_ascii_lowercase();
        let s = lower.as_str();
        if let Some(&cls) = self.exact_map.get(s) {
            return cls;
        }
        for &(prefix, cls) in &self.prefix_map {
            if s.starts_with(prefix) {
                return cls;
            }
        }
        InstrClass::Other
    }

    /// Register a custom exact mapping.
    pub fn register_exact(&mut self, mnemonic: &'static str, cls: InstrClass) {
        self.exact_map.insert(mnemonic, cls);
    }

    /// Classify a batch of mnemonics.
    pub fn classify_all<'a>(&self, mnemonics: impl Iterator<Item = &'a str>) -> Vec<InstrClass> {
        mnemonics.map(|m| self.classify(m)).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ControlFlowEdge
// ─────────────────────────────────────────────────────────────────────────────

/// An edge in the control-flow graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFlowEdge {
    pub from: u64,
    pub to: u64,
    pub kind: EdgeKind,
}

/// What kind of control-flow edge this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeKind {
    /// Unconditional fall-through or direct jump.
    Unconditional,
    /// Taken branch (condition true).
    BranchTaken,
    /// Not-taken branch (condition false / fall-through).
    BranchNotTaken,
    /// Call edge.
    Call,
    /// Return edge.
    Return,
    /// Exception / unwind edge.
    Exception,
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Unconditional => "→",
            Self::BranchTaken => "T→",
            Self::BranchNotTaken => "F→",
            Self::Call => "call",
            Self::Return => "ret",
            Self::Exception => "ex",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BasicBlock
// ─────────────────────────────────────────────────────────────────────────────

/// A basic block: maximal straight-line sequence of instructions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub start: u64,
    pub end: u64, // exclusive
    pub instr_count: usize,
    pub terminator_class: InstrClass,
    pub successors: Vec<u64>,
    pub predecessors: Vec<u64>,
}

impl BasicBlock {
    #[must_use]
    pub const fn new(start: u64) -> Self {
        Self {
            start,
            end: start,
            instr_count: 0,
            terminator_class: InstrClass::Other,
            successors: Vec::new(),
            predecessors: Vec::new(),
        }
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    #[must_use]
    pub const fn is_entry(&self) -> bool {
        self.predecessors.is_empty()
    }

    #[must_use]
    pub const fn is_exit(&self) -> bool {
        matches!(
            self.terminator_class,
            InstrClass::Return | InstrClass::IndirectJump | InstrClass::Undefined
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CfgBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Incrementally builds a control-flow graph from decoded instruction info.
pub struct CfgBuilder {
    pub blocks: BTreeMap<u64, BasicBlock>,
    pub edges: Vec<ControlFlowEdge>,
    classifier: InstrClassifier,
    /// Block starts identified so far.
    block_starts: HashSet<u64>,
}

impl CfgBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            blocks: BTreeMap::new(),
            edges: Vec::new(),
            classifier: InstrClassifier::new(),
            block_starts: HashSet::new(),
        }
    }

    /// Feed an instruction into the builder.
    ///
    /// `addr` = address, `size` = byte length, `mnemonic` = mnemonic string,
    /// `branch_targets` = explicit branch targets (empty if none).
    pub fn add_instr(&mut self, addr: u64, size: u64, mnemonic: &str, branch_targets: &[u64]) {
        let cls = self.classifier.classify(mnemonic);
        let next_addr = addr.saturating_add(size);

        // Ensure a block exists at this address.
        self.block_starts.insert(addr);
        let block = self
            .blocks
            .entry(addr)
            .or_insert_with(|| BasicBlock::new(addr));
        block.instr_count += 1;
        block.end = next_addr;
        block.terminator_class = cls;

        if cls.is_block_terminator() {
            // Add edges for known targets.
            for &target in branch_targets {
                self.block_starts.insert(target);
                let edge_kind = if matches!(cls, InstrClass::Branch) {
                    EdgeKind::BranchTaken
                } else {
                    EdgeKind::Unconditional
                };
                self.edges.push(ControlFlowEdge {
                    from: addr,
                    to: target,
                    kind: edge_kind,
                });
                if let Some(block) = self.blocks.get_mut(&addr)
                    && !block.successors.contains(&target)
                {
                    block.successors.push(target);
                }
            }
            // If it is a conditional branch, add the fall-through edge too.
            if matches!(cls, InstrClass::Branch) && !branch_targets.is_empty() {
                self.edges.push(ControlFlowEdge {
                    from: addr,
                    to: next_addr,
                    kind: EdgeKind::BranchNotTaken,
                });
                if let Some(block) = self.blocks.get_mut(&addr)
                    && !block.successors.contains(&next_addr)
                {
                    block.successors.push(next_addr);
                }
            }
        } else if !matches!(cls, InstrClass::Call | InstrClass::Syscall) {
            // Normal fall-through.
            if let Some(block) = self.blocks.get_mut(&addr)
                && !block.successors.contains(&next_addr)
            {
                block.successors.push(next_addr);
            }
        }
    }

    /// Finalize: wire predecessor lists and return the finished graph.
    pub fn finish(&mut self) {
        // Build predecessor lists from successor lists.
        let all_edges: Vec<(u64, u64)> = self
            .blocks
            .iter()
            .flat_map(|(addr, b)| b.successors.iter().map(|&s| (*addr, s)))
            .collect();
        for (from, to) in all_edges {
            if let Some(block) = self.blocks.get_mut(&to)
                && !block.predecessors.contains(&from)
            {
                block.predecessors.push(from);
            }
        }
    }

    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Entry blocks (no predecessors).
    #[must_use]
    pub fn entry_blocks(&self) -> Vec<&BasicBlock> {
        self.blocks.values().filter(|b| b.is_entry()).collect()
    }

    /// Exit blocks (return / indirect jump / undefined).
    #[must_use]
    pub fn exit_blocks(&self) -> Vec<&BasicBlock> {
        self.blocks.values().filter(|b| b.is_exit()).collect()
    }
}

impl Default for CfgBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InstrPattern
// ─────────────────────────────────────────────────────────────────────────────

/// A pattern that can be matched against a sequence of instruction mnemonics.
#[derive(Debug, Clone)]
pub struct InstrPattern {
    pub name: String,
    /// Sequence of mnemonic prefixes to match (in order).
    pub sequence: Vec<String>,
    /// Allow wildcards (`*`) in the pattern.
    pub allow_wildcards: bool,
}

impl InstrPattern {
    pub fn new(name: impl Into<String>, sequence: Vec<&str>) -> Self {
        Self {
            name: name.into(),
            sequence: sequence
                .into_iter()
                .map(std::string::ToString::to_string)
                .collect(),
            allow_wildcards: true,
        }
    }

    /// Try to match starting at position `offset` in `mnemonics`.
    /// Returns the number of instructions consumed, or None if no match.
    #[must_use]
    pub fn try_match(&self, mnemonics: &[&str], offset: usize) -> Option<usize> {
        if offset + self.sequence.len() > mnemonics.len() {
            return None;
        }
        let mut consumed = 0;
        for (i, pat) in self.sequence.iter().enumerate() {
            if pat == "*" && self.allow_wildcards {
                consumed += 1;
                continue;
            }
            let m = mnemonics[offset + i];
            let p = pat.as_str();
            let matches = if m.bytes().all(|b| !b.is_ascii_uppercase()) {
                m.starts_with(p)
            } else if m.len() < p.len() {
                false
            } else {
                m.as_bytes()[..p.len()].eq_ignore_ascii_case(p.as_bytes())
            };
            if !matches {
                return None;
            }
            consumed += 1;
        }
        Some(consumed)
    }

    /// Search for all occurrences in a slice of mnemonics.
    #[must_use]
    pub fn find_all(&self, mnemonics: &[&str]) -> Vec<usize> {
        let mut offsets = Vec::new();
        for i in 0..mnemonics.len() {
            if self.try_match(mnemonics, i).is_some() {
                offsets.push(i);
            }
        }
        offsets
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Prologue / epilogue detectors
// ─────────────────────────────────────────────────────────────────────────────

/// Known x86-64 function prologue patterns.
#[must_use]
pub fn x86_64_prologue_patterns() -> Vec<InstrPattern> {
    vec![
        InstrPattern::new("push_rbp_mov_rsp", vec!["push", "mov"]),
        InstrPattern::new("sub_rsp", vec!["sub"]),
        InstrPattern::new("endbr64_push_rbp", vec!["endbr64", "push", "mov"]),
    ]
}

/// Known x86-64 function epilogue patterns.
#[must_use]
pub fn x86_64_epilogue_patterns() -> Vec<InstrPattern> {
    vec![
        InstrPattern::new("leave_ret", vec!["leave", "ret"]),
        InstrPattern::new("pop_rbp_ret", vec!["pop", "ret"]),
        InstrPattern::new("add_rsp_ret", vec!["add", "ret"]),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// InstrStats
// ─────────────────────────────────────────────────────────────────────────────

/// Per-classification instruction counters.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct InstrStats {
    pub arithmetic: u32,
    pub logic: u32,
    pub data_move: u32,
    pub compare: u32,
    pub jump: u32,
    pub branch: u32,
    pub call: u32,
    pub return_: u32,
    pub indirect_call: u32,
    pub indirect_jump: u32,
    pub syscall: u32,
    pub float_op: u32,
    pub vector_op: u32,
    pub crypto: u32,
    pub privileged: u32,
    pub nop: u32,
    pub undefined: u32,
    pub other: u32,
    pub total: u32,
}

impl InstrStats {
    pub const fn record(&mut self, cls: InstrClass) {
        self.total += 1;
        match cls {
            InstrClass::Arithmetic => self.arithmetic += 1,
            InstrClass::Logic => self.logic += 1,
            InstrClass::DataMove => self.data_move += 1,
            InstrClass::Compare => self.compare += 1,
            InstrClass::Jump => self.jump += 1,
            InstrClass::Branch => self.branch += 1,
            InstrClass::Call => self.call += 1,
            InstrClass::Return => self.return_ += 1,
            InstrClass::IndirectCall => self.indirect_call += 1,
            InstrClass::IndirectJump => self.indirect_jump += 1,
            InstrClass::Syscall => self.syscall += 1,
            InstrClass::FloatOp => self.float_op += 1,
            InstrClass::VectorOp => self.vector_op += 1,
            InstrClass::Crypto => self.crypto += 1,
            InstrClass::Privileged => self.privileged += 1,
            InstrClass::Nop => self.nop += 1,
            InstrClass::Undefined => self.undefined += 1,
            InstrClass::Other => self.other += 1,
        }
    }

    #[must_use]
    pub fn from_mnemonics(classifier: &InstrClassifier, mnemonics: &[&str]) -> Self {
        let mut s = Self::default();
        for &m in mnemonics {
            s.record(classifier.classify(m));
        }
        s
    }

    /// Fraction of instructions that are arithmetic [0.0, 1.0].
    #[must_use]
    pub fn arithmetic_fraction(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            f64::from(self.arithmetic) / f64::from(self.total)
        }
    }

    /// Fraction of instructions that are control flow.
    #[must_use]
    pub fn control_flow_fraction(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        // Sum directly as f64 to avoid both u32 overflow and precision-loss casts.
        // f64 can represent u32 values exactly (53-bit mantissa > 32 bits).
        let cf = f64::from(self.jump)
            + f64::from(self.branch)
            + f64::from(self.call)
            + f64::from(self.return_)
            + f64::from(self.indirect_call)
            + f64::from(self.indirect_jump)
            + f64::from(self.syscall);
        cf / f64::from(self.total)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn classifier() -> InstrClassifier {
        InstrClassifier::new()
    }

    // --- InstrClass ---

    #[test]
    fn instr_class_is_control_flow() {
        assert!(InstrClass::Jump.is_control_flow());
        assert!(InstrClass::Branch.is_control_flow());
        assert!(!InstrClass::DataMove.is_control_flow());
    }

    #[test]
    fn instr_class_is_block_terminator() {
        assert!(InstrClass::Return.is_block_terminator());
        assert!(!InstrClass::Arithmetic.is_block_terminator());
    }

    #[test]
    fn instr_class_is_call() {
        assert!(InstrClass::Call.is_call());
        assert!(InstrClass::IndirectCall.is_call());
        assert!(!InstrClass::Branch.is_call());
    }

    #[test]
    fn instr_class_display() {
        assert_eq!(format!("{}", InstrClass::Nop), "nop");
    }

    // --- InstrClassifier ---

    #[test]
    fn classifier_ret_exact() {
        assert_eq!(classifier().classify("ret"), InstrClass::Return);
    }

    #[test]
    fn classifier_nop_exact() {
        assert_eq!(classifier().classify("nop"), InstrClass::Nop);
    }

    #[test]
    fn classifier_add_prefix() {
        assert_eq!(classifier().classify("addq"), InstrClass::Arithmetic);
    }

    #[test]
    fn classifier_mov_prefix() {
        assert_eq!(classifier().classify("movzx"), InstrClass::DataMove);
    }

    #[test]
    fn classifier_jmp_exact() {
        assert_eq!(classifier().classify("jmp"), InstrClass::Jump);
    }

    #[test]
    fn classifier_jcc_prefix() {
        assert_eq!(classifier().classify("je"), InstrClass::Branch);
    }

    #[test]
    fn classifier_call_exact() {
        assert_eq!(classifier().classify("call"), InstrClass::Call);
    }

    #[test]
    fn classifier_case_insensitive() {
        assert_eq!(classifier().classify("RET"), InstrClass::Return);
    }

    #[test]
    fn classifier_aes_crypto() {
        assert_eq!(classifier().classify("aesenc"), InstrClass::Crypto);
    }

    #[test]
    fn classifier_unknown_other() {
        assert_eq!(classifier().classify("fnstcw"), InstrClass::Other);
    }

    #[test]
    fn classifier_custom_exact() {
        let mut c = InstrClassifier::new();
        c.register_exact("custom_op", InstrClass::Privileged);
        assert_eq!(c.classify("custom_op"), InstrClass::Privileged);
    }

    // --- ControlFlowEdge ---

    #[test]
    fn edge_kind_display() {
        assert_eq!(format!("{}", EdgeKind::BranchTaken), "T→");
    }

    // --- BasicBlock ---

    #[test]
    fn basic_block_size() {
        let mut b = BasicBlock::new(0x1000);
        b.end = 0x1020;
        assert_eq!(b.size(), 0x20);
    }

    #[test]
    fn basic_block_is_entry_no_preds() {
        let b = BasicBlock::new(0x1000);
        assert!(b.is_entry());
    }

    #[test]
    fn basic_block_is_exit_return() {
        let mut b = BasicBlock::new(0x1000);
        b.terminator_class = InstrClass::Return;
        assert!(b.is_exit());
    }

    // --- CfgBuilder ---

    #[test]
    fn cfg_builder_simple_linear() {
        let mut builder = CfgBuilder::new();
        builder.add_instr(0x1000, 4, "mov", &[]);
        builder.add_instr(0x1004, 4, "add", &[]);
        builder.add_instr(0x1008, 1, "ret", &[]);
        builder.finish();
        // At least the entry block should exist
        assert!(builder.block_count() >= 1);
    }

    #[test]
    fn cfg_builder_branch_creates_edge() {
        let mut builder = CfgBuilder::new();
        builder.add_instr(0x1000, 4, "je", &[0x1010]);
        builder.finish();
        assert!(builder.edge_count() >= 1);
    }

    #[test]
    fn cfg_builder_entry_block_no_preds() {
        let mut builder = CfgBuilder::new();
        builder.add_instr(0x1000, 4, "mov", &[]);
        builder.add_instr(0x1004, 1, "ret", &[]);
        builder.finish();
        let entries = builder.entry_blocks();
        assert!(!entries.is_empty());
    }

    // --- InstrPattern ---

    #[test]
    fn pattern_match_basic() {
        let pat = InstrPattern::new("test", vec!["push", "mov"]);
        let mnemonics = &["push", "mov", "ret"];
        assert_eq!(pat.try_match(mnemonics, 0), Some(2));
    }

    #[test]
    fn pattern_no_match() {
        let pat = InstrPattern::new("test", vec!["push", "push"]);
        let mnemonics = &["push", "mov", "ret"];
        assert!(pat.try_match(mnemonics, 0).is_none());
    }

    #[test]
    fn pattern_wildcard() {
        let pat = InstrPattern::new("test", vec!["push", "*", "ret"]);
        let mnemonics = &["push", "mov", "ret"];
        assert_eq!(pat.try_match(mnemonics, 0), Some(3));
    }

    #[test]
    fn pattern_find_all() {
        let pat = InstrPattern::new("test", vec!["nop"]);
        let mnemonics = &["nop", "mov", "nop", "ret"];
        let found = pat.find_all(mnemonics);
        assert_eq!(found, vec![0, 2]);
    }

    #[test]
    fn pattern_too_short() {
        let pat = InstrPattern::new("test", vec!["a", "b", "c"]);
        assert!(pat.try_match(&["a", "b"], 0).is_none());
    }

    // --- x86_64_prologue/epilogue patterns ---

    #[test]
    fn prologue_patterns_not_empty() {
        assert!(!x86_64_prologue_patterns().is_empty());
    }

    #[test]
    fn epilogue_leave_ret_matches() {
        let patterns = x86_64_epilogue_patterns();
        let leave_ret = patterns.iter().find(|p| p.name == "leave_ret").unwrap();
        let mnemonics = &["leave", "ret"];
        assert!(leave_ret.try_match(mnemonics, 0).is_some());
    }

    // --- InstrStats ---

    #[test]
    fn instr_stats_record() {
        let mut s = InstrStats::default();
        s.record(InstrClass::Arithmetic);
        s.record(InstrClass::Arithmetic);
        s.record(InstrClass::Return);
        assert_eq!(s.arithmetic, 2);
        assert_eq!(s.return_, 1);
        assert_eq!(s.total, 3);
    }

    #[test]
    fn instr_stats_from_mnemonics() {
        let c = InstrClassifier::new();
        let mnemonics = &["mov", "add", "ret"];
        let s = InstrStats::from_mnemonics(&c, mnemonics);
        assert_eq!(s.total, 3);
    }

    #[test]
    fn instr_stats_arithmetic_fraction() {
        let mut s = InstrStats::default();
        s.record(InstrClass::Arithmetic);
        s.record(InstrClass::Arithmetic);
        s.record(InstrClass::DataMove);
        assert!((s.arithmetic_fraction() - 2.0 / 3.0).abs() < 1e-10);
    }

    #[test]
    fn instr_stats_zero_total_fraction() {
        let s = InstrStats::default();
        assert!(s.arithmetic_fraction().abs() < f64::EPSILON);
    }
}
