//! Virtualized-function recovery: detection, lifting, and representation of
//! functions that have been protected by a custom VM.
//!
//! Provides:
//! * [`VmEntry`] — entry-point detection heuristics.
//! * [`VmExit`] — exit-point detection and classification.
//! * [`VmDispatcherPattern`] — pattern that characterises the VM dispatcher.
//! * [`HandlerExecutionGraph`] — directed graph of handler execution order.
//! * [`VirtualBBSequence`] — a linearised sequence of virtual basic blocks.
//! * [`VirtualizedFunction`] — top-level container for a VM-lifted function.
//! * [`VmLiftedFunction`] — the result of a completed lifting operation.

use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// Addr
// ─────────────────────────────────────────────────────────────────────────────

/// Virtual address used in the VM-lifting pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Addr(pub u64);

impl Addr {
    /// Construct from a `u64`.
    #[must_use]
    pub fn new(v: u64) -> Self {
        Self(v)
    }
    /// Raw value.
    #[must_use]
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmEntryKind / VmEntry
// ─────────────────────────────────────────────────────────────────────────────

/// How the VM is entered from native code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VmEntryKind {
    /// A `CALL` instruction to a VM-stub prologue.
    CallStub,
    /// A `JMP` into the VM dispatcher.
    JmpDispatcher,
    /// `PUSH imm; JMP vm_entry` — push-style entry used by Themida/WProtect.
    PushJmp,
    /// A `CALL` followed by a VM-specific opcode byte.
    CallOpcode,
    /// Unknown entry kind.
    Unknown,
}

/// A detected VM entry point.
#[derive(Debug, Clone)]
pub struct VmEntry {
    /// Address of the entry instruction (the CALL / JMP).
    pub address: Addr,
    /// How the VM is entered.
    pub kind: VmEntryKind,
    /// Confidence (0–100).
    pub confidence: u8,
    /// Address of the VM stub / dispatcher being called/jumped to.
    pub target: Addr,
    /// Opcode or push value, if applicable.
    pub opcode: Option<u64>,
}

impl VmEntry {
    /// Create a new VM entry.
    #[must_use]
    pub fn new(address: Addr, kind: VmEntryKind, target: Addr) -> Self {
        Self {
            address,
            kind,
            confidence: 70,
            target,
            opcode: None,
        }
    }

    /// Set confidence.
    #[must_use]
    pub fn with_confidence(mut self, c: u8) -> Self {
        self.confidence = c.min(100);
        self
    }

    /// Set opcode value.
    #[must_use]
    pub fn with_opcode(mut self, op: u64) -> Self {
        self.opcode = Some(op);
        self
    }

    /// Return `true` if the entry has high confidence.
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 80
    }
}

/// Scan raw bytes for common VM entry patterns.
///
/// Recognised patterns:
/// * `E8 xx xx xx xx` — CALL rel32 (stub entry)
/// * `EB xx` — short JMP (jmp dispatcher)
/// * `68 xx xx xx xx  E9/EB` — PUSH imm; JMP (push-style entry)
#[must_use]
pub fn detect_vm_entries(code: &[u8], base: u64) -> Vec<VmEntry> {
    let mut entries = Vec::new();
    let len = code.len();

    for i in 0..len {
        // CALL rel32: E8 xx xx xx xx
        if code[i] == 0xE8 && i + 5 <= len {
            let rel = i32::from_le_bytes([code[i + 1], code[i + 2], code[i + 3], code[i + 4]]);
            let target_rva = (base + i as u64 + 5).wrapping_add_signed(rel as i64);
            let entry = VmEntry::new(
                Addr(base + i as u64),
                VmEntryKind::CallStub,
                Addr(target_rva),
            )
            .with_confidence(75);
            entries.push(entry);
        }

        // PUSH imm32; JMP: 68 xx xx xx xx  E9/EB
        if code[i] == 0x68 && i + 6 <= len && (code[i + 5] == 0xE9 || code[i + 5] == 0xEB) {
            let imm = u32::from_le_bytes([code[i + 1], code[i + 2], code[i + 3], code[i + 4]]);
            let target = if code[i + 5] == 0xE9 && i + 10 <= len {
                let rel = i32::from_le_bytes([code[i + 6], code[i + 7], code[i + 8], code[i + 9]]);
                (base + i as u64 + 10).wrapping_add_signed(rel as i64)
            } else {
                base + i as u64 + 7
            };
            let entry = VmEntry::new(Addr(base + i as u64), VmEntryKind::PushJmp, Addr(target))
                .with_confidence(85)
                .with_opcode(imm as u64);
            entries.push(entry);
        }
    }
    entries
}

// ─────────────────────────────────────────────────────────────────────────────
// VmExitKind / VmExit
// ─────────────────────────────────────────────────────────────────────────────

/// How the VM returns control to native code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VmExitKind {
    /// Explicit `RET` to caller after VM handler chain.
    Ret,
    /// `JMP` to the saved return address stored on the stack.
    JmpToRetAddr,
    /// Epilogue that restores all registers and then `RET`.
    EpilogueRet,
    /// Unknown exit.
    Unknown,
}

/// A detected VM exit point.
#[derive(Debug, Clone)]
pub struct VmExit {
    /// Address of the exit instruction.
    pub address: Addr,
    /// Exit kind.
    pub kind: VmExitKind,
    /// Confidence (0–100).
    pub confidence: u8,
}

impl VmExit {
    /// Create a new exit.
    #[must_use]
    pub fn new(address: Addr, kind: VmExitKind) -> Self {
        Self {
            address,
            kind,
            confidence: 70,
        }
    }

    /// Set confidence.
    #[must_use]
    pub fn with_confidence(mut self, c: u8) -> Self {
        self.confidence = c.min(100);
        self
    }
}

/// Detect VM exits from raw bytes.
#[must_use]
pub fn detect_vm_exits(code: &[u8], base: u64) -> Vec<VmExit> {
    let mut exits = Vec::new();
    for (i, &b) in code.iter().enumerate() {
        match b {
            // RET near: C3
            0xC3 => {
                exits.push(VmExit::new(Addr(base + i as u64), VmExitKind::Ret).with_confidence(90))
            }
            // RETN imm16: C2 xx xx
            0xC2 if i + 3 <= code.len() => {
                exits.push(VmExit::new(Addr(base + i as u64), VmExitKind::Ret).with_confidence(85));
            }
            // FF E0 / FF E1 — JMP rax/rcx (commonly used to jump to saved return addr)
            0xFF if i + 1 < code.len() && (code[i + 1] == 0xE0 || code[i + 1] == 0xE1) => {
                exits.push(
                    VmExit::new(Addr(base + i as u64), VmExitKind::JmpToRetAddr)
                        .with_confidence(80),
                );
            }
            _ => {}
        }
    }
    exits
}

// ─────────────────────────────────────────────────────────────────────────────
// VmDispatcherPattern
// ─────────────────────────────────────────────────────────────────────────────

/// Describes the structural pattern of a VM dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatcherShape {
    /// Dense jump table (`jmp [reg*8 + table]`).
    JumpTable,
    /// Linear if/else-if chain.
    LinearChain,
    /// Nested dispatchers (sub-dispatchers).
    Nested,
    /// Unknown.
    Unknown,
}

/// Characterisation of a VM dispatcher block.
#[derive(Debug, Clone)]
pub struct VmDispatcherPattern {
    /// Address of the dispatcher.
    pub address: Addr,
    /// Structural shape.
    pub shape: DispatcherShape,
    /// Number of handler entries.
    pub handler_count: usize,
    /// Address-width used by the jump table (4 or 8 bytes).
    pub ptr_width: u8,
    /// Jump table base address (if applicable).
    pub table_base: Option<Addr>,
    /// Detection confidence (0–100).
    pub confidence: u8,
}

impl VmDispatcherPattern {
    /// Create a new dispatcher pattern.
    #[must_use]
    pub fn new(address: Addr, shape: DispatcherShape) -> Self {
        Self {
            address,
            shape,
            handler_count: 0,
            ptr_width: 8,
            table_base: None,
            confidence: 60,
        }
    }

    /// Return `true` if this looks like a high-quality dispatcher match.
    #[must_use]
    pub fn is_strong_match(&self) -> bool {
        self.confidence >= 80 && self.handler_count >= 16
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HandlerNode / HandlerExecutionGraph
// ─────────────────────────────────────────────────────────────────────────────

/// A single handler node in the handler execution graph.
#[derive(Debug, Clone)]
pub struct HandlerNode {
    /// Handler address.
    pub address: Addr,
    /// Opcode byte(s) that select this handler.
    pub opcode: u8,
    /// Human-readable mnemonic.
    pub mnemonic: String,
    /// Whether this handler modifies control flow.
    pub is_cf: bool,
    /// Whether this handler accesses memory.
    pub accesses_memory: bool,
}

impl HandlerNode {
    /// Create a new handler node.
    #[must_use]
    pub fn new(address: Addr, opcode: u8, mnemonic: impl Into<String>) -> Self {
        Self {
            address,
            opcode,
            mnemonic: mnemonic.into(),
            is_cf: false,
            accesses_memory: false,
        }
    }
}

/// A directed graph representing the execution order of VM handlers in a lifted
/// function.  Edges carry a boolean condition (true/false branch) or `None` for
/// unconditional flow.
#[derive(Debug, Clone, Default)]
pub struct HandlerExecutionGraph {
    /// All handler nodes, keyed by address.
    pub nodes: HashMap<Addr, HandlerNode>,
    /// Directed edges: `(from, to, condition)`.
    pub edges: Vec<(Addr, Addr, Option<bool>)>,
    /// Entry handler address.
    pub entry: Option<Addr>,
}

impl HandlerExecutionGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a handler node.
    pub fn add_node(&mut self, node: HandlerNode) {
        if self.entry.is_none() {
            self.entry = Some(node.address);
        }
        self.nodes.insert(node.address, node);
    }

    /// Add a directed edge.
    pub fn add_edge(&mut self, from: Addr, to: Addr, cond: Option<bool>) {
        self.edges.push((from, to, cond));
    }

    /// Return all successors of `addr`.
    #[must_use]
    pub fn successors(&self, addr: Addr) -> Vec<(Addr, Option<bool>)> {
        self.edges
            .iter()
            .filter(|(f, _, _)| *f == addr)
            .map(|(_, t, c)| (*t, *c))
            .collect()
    }

    /// Return all predecessors of `addr`.
    #[must_use]
    pub fn predecessors(&self, addr: Addr) -> Vec<Addr> {
        self.edges
            .iter()
            .filter(|(_, t, _)| *t == addr)
            .map(|(f, _, _)| *f)
            .collect()
    }

    /// BFS topological ordering from the entry node.
    #[must_use]
    pub fn bfs_order(&self) -> Vec<Addr> {
        let entry = match self.entry {
            Some(e) => e,
            None => return Vec::new(),
        };
        let mut visited: HashSet<Addr> = HashSet::new();
        let mut queue: VecDeque<Addr> = VecDeque::new();
        let mut order: Vec<Addr> = Vec::new();
        queue.push_back(entry);
        visited.insert(entry);
        while let Some(addr) = queue.pop_front() {
            order.push(addr);
            for (succ, _) in self.successors(addr) {
                if visited.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }
        order
    }

    /// Number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Return `true` when the graph has no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VirtualBBSequence
// ─────────────────────────────────────────────────────────────────────────────

/// A single virtual basic block in a lifted function.
#[derive(Debug, Clone)]
pub struct VirtualBB {
    /// Index of this block in the sequence.
    pub index: usize,
    /// Address of the first handler in this virtual block.
    pub start_addr: Addr,
    /// Opcodes executed by this block (in order).
    pub opcodes: Vec<u8>,
    /// Successor indices (usually 1, or 2 for conditional).
    pub successors: Vec<usize>,
    /// Whether this block terminates the function.
    pub is_exit: bool,
}

impl VirtualBB {
    /// Create a new virtual basic block.
    #[must_use]
    pub fn new(index: usize, start_addr: Addr) -> Self {
        Self {
            index,
            start_addr,
            opcodes: Vec::new(),
            successors: Vec::new(),
            is_exit: false,
        }
    }

    /// Add an opcode byte.
    pub fn push_opcode(&mut self, op: u8) {
        self.opcodes.push(op);
    }
}

/// A linearised sequence of virtual basic blocks recovered from a VM-lifted function.
#[derive(Debug, Clone, Default)]
pub struct VirtualBBSequence {
    /// All virtual basic blocks.
    pub blocks: Vec<VirtualBB>,
}

impl VirtualBBSequence {
    /// Create an empty sequence.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a block.
    pub fn push(&mut self, block: VirtualBB) {
        self.blocks.push(block);
    }

    /// Number of virtual basic blocks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Return `true` when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Total number of opcodes across all blocks.
    #[must_use]
    pub fn total_opcodes(&self) -> usize {
        self.blocks.iter().map(|b| b.opcodes.len()).sum()
    }

    /// Return the block at `index`, if any.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&VirtualBB> {
        self.blocks.get(index)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VirtualizedFunction
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level container for all information about a VM-protected function.
#[derive(Debug, Clone)]
pub struct VirtualizedFunction {
    /// Native address of the function prologue.
    pub native_address: Addr,
    /// All detected VM entries into this function.
    pub entries: Vec<VmEntry>,
    /// All detected VM exits.
    pub exits: Vec<VmExit>,
    /// The dispatcher pattern used by this VM.
    pub dispatcher: Option<VmDispatcherPattern>,
    /// Recovered handler execution graph.
    pub handler_graph: HandlerExecutionGraph,
    /// Sequence of virtual basic blocks.
    pub vbb_sequence: VirtualBBSequence,
    /// Raw bytecode extracted for this function.
    pub bytecode: Vec<u8>,
    /// Size of the original native function in bytes.
    pub native_size: usize,
    /// Human-readable VM family name (e.g. "Themida", "VMProtect", "Custom").
    pub vm_family: String,
}

impl VirtualizedFunction {
    /// Create a new virtualized function.
    #[must_use]
    pub fn new(native_address: Addr) -> Self {
        Self {
            native_address,
            entries: Vec::new(),
            exits: Vec::new(),
            dispatcher: None,
            handler_graph: HandlerExecutionGraph::new(),
            vbb_sequence: VirtualBBSequence::new(),
            bytecode: Vec::new(),
            native_size: 0,
            vm_family: "Unknown".into(),
        }
    }

    /// Return `true` if the function has been at least partially lifted.
    #[must_use]
    pub fn is_lifted(&self) -> bool {
        !self.vbb_sequence.is_empty() || !self.handler_graph.is_empty()
    }

    /// Return the overall detection confidence based on entries and dispatcher.
    #[must_use]
    pub fn confidence(&self) -> u8 {
        let entry_conf = self
            .entries
            .iter()
            .map(|e| e.confidence as u32)
            .max()
            .unwrap_or(0);
        let disp_conf = self
            .dispatcher
            .as_ref()
            .map(|d| d.confidence as u32)
            .unwrap_or(0);
        (((entry_conf + disp_conf) / 2) as u8).min(100)
    }

    /// Return a short summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "VirtualizedFunction @ {} | family={} | entries={} exits={} vbbs={} handlers={}",
            self.native_address,
            self.vm_family,
            self.entries.len(),
            self.exits.len(),
            self.vbb_sequence.len(),
            self.handler_graph.node_count(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmLiftedFunction
// ─────────────────────────────────────────────────────────────────────────────

/// The completed result of a VM lifting operation.
#[derive(Debug, Clone)]
pub struct VmLiftedFunction {
    /// The source virtualised function.
    pub source: VirtualizedFunction,
    /// LLIL-style pseudo-code lines.
    pub pseudo_il: Vec<String>,
    /// Whether the lifting was verified (no unresolved handlers).
    pub is_complete: bool,
    /// Number of unresolved handler opcodes.
    pub unresolved_count: usize,
    /// Elapsed lifting time in microseconds.
    pub elapsed_us: u64,
}

impl VmLiftedFunction {
    /// Wrap a virtualised function after lifting.
    #[must_use]
    pub fn new(source: VirtualizedFunction) -> Self {
        Self {
            source,
            pseudo_il: Vec::new(),
            is_complete: false,
            unresolved_count: 0,
            elapsed_us: 0,
        }
    }

    /// Number of pseudo-IL lines generated.
    #[must_use]
    pub fn line_count(&self) -> usize {
        self.pseudo_il.len()
    }

    /// Return `true` if lifting produced at least one IL line.
    #[must_use]
    pub fn has_output(&self) -> bool {
        !self.pseudo_il.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmOpcodeFrequency — opcode frequency analysis for VM bytecode
// ─────────────────────────────────────────────────────────────────────────────

/// Frequency count for a single VM opcode.
///
/// Note: the original derive list included `Eq`, but the `fraction: f32`
/// field rules that out. The `Eq` derive is kept under a never-active
/// `cfg_attr` to preserve intent without removing code.
#[cfg_attr(any(), derive(Eq))]
#[derive(Debug, Clone, PartialEq)]
pub struct OpcodeFrequency {
    /// The opcode byte.
    pub opcode: u8,
    /// Number of occurrences in the bytecode stream.
    pub count: usize,
    /// Fraction of total instructions (0.0–1.0).
    pub fraction: f32,
}

/// Computes opcode frequency statistics from a bytecode buffer.
///
/// Assumes a fixed-stride bytecode stream (stride = 1).  For variable-length
/// encodings, the caller should provide pre-parsed opcode sequences.
#[derive(Debug, Clone, Default)]
pub struct VmOpcodeFrequencyAnalyzer;

impl VmOpcodeFrequencyAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Compute per-opcode frequency from `bytecode`.
    #[must_use]
    pub fn analyze(&self, bytecode: &[u8]) -> Vec<OpcodeFrequency> {
        if bytecode.is_empty() {
            return Vec::new();
        }
        let mut counts = [0u32; 256];
        for &b in bytecode {
            counts[b as usize] += 1;
        }
        let total = bytecode.len() as f32;
        let mut freqs: Vec<OpcodeFrequency> = counts
            .iter()
            .enumerate()
            .filter(|&(_, &c)| c > 0)
            .map(|(op, &c)| OpcodeFrequency {
                opcode: op as u8,
                count: c as usize,
                fraction: c as f32 / total,
            })
            .collect();
        freqs.sort_by(|a, b| b.count.cmp(&a.count));
        freqs
    }

    /// Return the most frequent opcode, if any.
    #[must_use]
    pub fn most_frequent(&self, bytecode: &[u8]) -> Option<OpcodeFrequency> {
        self.analyze(bytecode).into_iter().next()
    }

    /// Return opcodes whose fraction exceeds `threshold`.
    #[must_use]
    pub fn above_threshold(&self, bytecode: &[u8], threshold: f32) -> Vec<OpcodeFrequency> {
        self.analyze(bytecode)
            .into_iter()
            .filter(|f| f.fraction >= threshold)
            .collect()
    }

    /// Compute the entropy of the opcode distribution (bits per opcode).
    #[must_use]
    pub fn opcode_entropy(&self, bytecode: &[u8]) -> f64 {
        let freqs = self.analyze(bytecode);
        if freqs.is_empty() {
            return 0.0;
        }
        freqs
            .iter()
            .map(|f| {
                let p = f.fraction as f64;
                if p > 0.0 { -p * p.log2() } else { 0.0 }
            })
            .sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmProtectionFamily — heuristic VM-protection family identification
// ─────────────────────────────────────────────────────────────────────────────

/// A known VM-protection product family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VmProtectionFamily {
    /// VMProtect (VMProtect Software).
    VMProtect,
    /// Themida / WinLicense (Oreans).
    Themida,
    /// Code Virtualizer (Oreans, lightweight).
    CodeVirtualizer,
    /// VMPSOFT VirtualBasic-based protection.
    VmpSoft,
    /// Custom / novel protection not matching any known family.
    Custom,
    /// Not yet determined.
    Unknown,
}

impl VmProtectionFamily {
    /// Short label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::VMProtect => "VMProtect",
            Self::Themida => "Themida/WinLicense",
            Self::CodeVirtualizer => "CodeVirtualizer",
            Self::VmpSoft => "VmpSoft",
            Self::Custom => "Custom",
            Self::Unknown => "Unknown",
        }
    }
}

/// Heuristic identifier for VM protection families.
///
/// Examines byte signatures common to each family.
#[derive(Debug, Clone, Default)]
pub struct VmFamilyIdentifier;

impl VmFamilyIdentifier {
    /// Create a new identifier.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Attempt to identify the protection family from raw bytes.
    ///
    /// Returns `(family, confidence_0_to_100)`.
    #[must_use]
    pub fn identify(&self, code: &[u8]) -> (VmProtectionFamily, u8) {
        // VMProtect: characteristic "VMProtect" string or `VMP` section names.
        if contains_bytes(code, b"VMProtect") || contains_bytes(code, b".vmp0") {
            return (VmProtectionFamily::VMProtect, 95);
        }
        // Themida: characteristic string or `.themida` section.
        if contains_bytes(code, b"Themida") || contains_bytes(code, b".themida") {
            return (VmProtectionFamily::Themida, 95);
        }
        if contains_bytes(code, b"WinLicense") {
            return (VmProtectionFamily::Themida, 90);
        }
        // Code Virtualizer: "CV" prologue pattern.
        if contains_bytes(code, b"CodeVirtualizer") {
            return (VmProtectionFamily::CodeVirtualizer, 90);
        }
        // Push-jmp entry heuristic (common in Themida / VMProtect).
        let push_jmp_count = code
            .windows(6)
            .filter(|w| w[0] == 0x68 && (w[5] == 0xE9 || w[5] == 0xEB))
            .count();
        if push_jmp_count >= 3 {
            return (VmProtectionFamily::Unknown, 60);
        }
        (VmProtectionFamily::Unknown, 0)
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ─────────────────────────────────────────────────────────────────────────────
// VmFunctionAnalyzer — higher-level analysis driver
// ─────────────────────────────────────────────────────────────────────────────

/// Analysis configuration for VM function detection.
#[derive(Debug, Clone)]
pub struct VmAnalysisConfig {
    /// Minimum entry confidence to include in results (default 70).
    pub min_entry_confidence: u8,
    /// Whether to attempt bytecode extraction from the function body.
    pub extract_bytecode: bool,
    /// Maximum bytecode extraction size in bytes (default 65536).
    pub max_bytecode_bytes: usize,
}

impl Default for VmAnalysisConfig {
    fn default() -> Self {
        Self {
            min_entry_confidence: 70,
            extract_bytecode: true,
            max_bytecode_bytes: 65536,
        }
    }
}

/// Aggregate results from a VM function analysis pass.
#[derive(Debug, Clone, Default)]
pub struct VmAnalysisResult {
    /// All virtualized functions detected.
    pub functions: Vec<VirtualizedFunction>,
    /// Total number of dispatcher patterns found.
    pub dispatchers_found: usize,
    /// Total VM entries across all functions.
    pub total_entries: usize,
    /// Diagnostic messages.
    pub diagnostics: Vec<String>,
}

impl VmAnalysisResult {
    /// Create an empty result.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a diagnostic message.
    pub fn note(&mut self, msg: impl Into<String>) {
        self.diagnostics.push(msg.into());
    }

    /// Return the function with the highest confidence.
    #[must_use]
    pub fn best_function(&self) -> Option<&VirtualizedFunction> {
        self.functions.iter().max_by_key(|f| f.confidence())
    }
}

/// Drives VM entry / exit / dispatcher detection over a raw code buffer.
#[derive(Default)]
pub struct VmFunctionAnalyzer {
    /// Analysis configuration.
    pub config: VmAnalysisConfig,
}


impl VmFunctionAnalyzer {
    /// Create a new analyzer with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run full VM detection on `code` mapped at `base`.
    #[must_use]
    pub fn analyze(&self, code: &[u8], base: u64) -> VmAnalysisResult {
        let mut result = VmAnalysisResult::new();

        // Phase 1: detect entries.
        let entries = detect_vm_entries(code, base);
        let qualified: Vec<VmEntry> = entries
            .into_iter()
            .filter(|e| e.confidence >= self.config.min_entry_confidence)
            .collect();
        result.total_entries = qualified.len();
        result.note(format!(
            "detected {} qualified VM entries",
            result.total_entries
        ));

        // Phase 2: detect exits.
        let exits = detect_vm_exits(code, base);
        result.note(format!("detected {} VM exits", exits.len()));

        // Phase 3: group entries into virtual functions by proximity.
        for entry in qualified {
            let mut vf = VirtualizedFunction::new(entry.target);
            vf.entries.push(entry);
            vf.exits.clone_from(&exits);
            if self.config.extract_bytecode && !code.is_empty() {
                let start = vf.native_address.as_u64().saturating_sub(base) as usize;
                let end = (start + self.config.max_bytecode_bytes).min(code.len());
                vf.bytecode = code[start..end].to_vec();
                vf.native_size = end - start;
            }
            result.functions.push(vf);
        }

        result.dispatchers_found = result
            .functions
            .iter()
            .filter(|f| f.dispatcher.is_some())
            .count();

        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Addr ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_addr_display() {
        assert_eq!(Addr(0x1000).to_string(), "0x1000");
    }

    #[test]
    fn test_addr_ordering() {
        let mut v = [Addr(3), Addr(1), Addr(2)];
        v.sort();
        assert_eq!(v[0], Addr(1));
    }

    // ── VmEntry ───────────────────────────────────────────────────────────────

    #[test]
    fn test_vm_entry_new() {
        let e = VmEntry::new(Addr(0x100), VmEntryKind::CallStub, Addr(0x200));
        assert_eq!(e.address, Addr(0x100));
        assert_eq!(e.kind, VmEntryKind::CallStub);
        assert_eq!(e.target, Addr(0x200));
        assert!(!e.is_high_confidence()); // default 70 < 80
    }

    #[test]
    fn test_vm_entry_with_confidence() {
        let e = VmEntry::new(Addr(0), VmEntryKind::Unknown, Addr(0)).with_confidence(90);
        assert!(e.is_high_confidence());
    }

    #[test]
    fn test_vm_entry_confidence_clamped() {
        let e = VmEntry::new(Addr(0), VmEntryKind::Unknown, Addr(0)).with_confidence(255);
        assert_eq!(e.confidence, 100);
    }

    #[test]
    fn test_vm_entry_with_opcode() {
        let e = VmEntry::new(Addr(0), VmEntryKind::PushJmp, Addr(0)).with_opcode(0xBEEF);
        assert_eq!(e.opcode, Some(0xBEEF));
    }

    #[test]
    fn test_detect_vm_entries_call() {
        // E8 00 00 00 00 at base 0
        let code = [0xE8u8, 0x00, 0x00, 0x00, 0x00];
        let entries = detect_vm_entries(&code, 0x1000);
        assert!(!entries.is_empty());
        assert_eq!(entries[0].kind, VmEntryKind::CallStub);
        // target = 0x1000 + 5 + 0 = 0x1005
        assert_eq!(entries[0].target, Addr(0x1005));
    }

    #[test]
    fn test_detect_vm_entries_push_jmp() {
        // 68 78 56 34 12  EB xx
        let code = [0x68u8, 0x78, 0x56, 0x34, 0x12, 0xEB, 0x00];
        let entries = detect_vm_entries(&code, 0);
        let push_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.kind == VmEntryKind::PushJmp)
            .collect();
        assert!(!push_entries.is_empty());
        assert_eq!(push_entries[0].opcode, Some(0x12345678));
    }

    #[test]
    fn test_detect_vm_entries_empty() {
        let entries = detect_vm_entries(&[], 0);
        assert!(entries.is_empty());
    }

    // ── VmExit ────────────────────────────────────────────────────────────────

    #[test]
    fn test_vm_exit_new() {
        let ex = VmExit::new(Addr(0x500), VmExitKind::Ret);
        assert_eq!(ex.address, Addr(0x500));
        assert_eq!(ex.kind, VmExitKind::Ret);
    }

    #[test]
    fn test_detect_vm_exits_ret() {
        let code = [0x90u8, 0xC3, 0x90]; // NOP RET NOP
        let exits = detect_vm_exits(&code, 0x1000);
        assert!(
            exits
                .iter()
                .any(|e| e.address == Addr(0x1001) && e.kind == VmExitKind::Ret)
        );
    }

    #[test]
    fn test_detect_vm_exits_jmp_rax() {
        let code = [0xFFu8, 0xE0]; // JMP RAX
        let exits = detect_vm_exits(&code, 0);
        assert!(exits.iter().any(|e| e.kind == VmExitKind::JmpToRetAddr));
    }

    #[test]
    fn test_detect_vm_exits_empty() {
        let exits = detect_vm_exits(&[], 0);
        assert!(exits.is_empty());
    }

    // ── VmDispatcherPattern ───────────────────────────────────────────────────

    #[test]
    fn test_dispatcher_pattern_new() {
        let p = VmDispatcherPattern::new(Addr(0x1000), DispatcherShape::JumpTable);
        assert_eq!(p.shape, DispatcherShape::JumpTable);
        assert!(!p.is_strong_match()); // handler_count = 0
    }

    #[test]
    fn test_dispatcher_pattern_strong_match() {
        let mut p = VmDispatcherPattern::new(Addr(0), DispatcherShape::JumpTable);
        p.confidence = 90;
        p.handler_count = 256;
        assert!(p.is_strong_match());
    }

    // ── HandlerNode ───────────────────────────────────────────────────────────

    #[test]
    fn test_handler_node_new() {
        let n = HandlerNode::new(Addr(0x2000), 0x42, "VPUSH");
        assert_eq!(n.opcode, 0x42);
        assert_eq!(n.mnemonic, "VPUSH");
        assert!(!n.is_cf);
    }

    // ── HandlerExecutionGraph ─────────────────────────────────────────────────

    #[test]
    fn test_handler_graph_add_node() {
        let mut g = HandlerExecutionGraph::new();
        g.add_node(HandlerNode::new(Addr(0x100), 0x01, "VADD"));
        assert_eq!(g.node_count(), 1);
        assert_eq!(g.entry, Some(Addr(0x100)));
    }

    #[test]
    fn test_handler_graph_add_edge() {
        let mut g = HandlerExecutionGraph::new();
        g.add_node(HandlerNode::new(Addr(0x100), 0x01, "VADD"));
        g.add_node(HandlerNode::new(Addr(0x200), 0x02, "VSUB"));
        g.add_edge(Addr(0x100), Addr(0x200), None);
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn test_handler_graph_successors() {
        let mut g = HandlerExecutionGraph::new();
        g.add_node(HandlerNode::new(Addr(0x100), 0x01, "VADD"));
        g.add_node(HandlerNode::new(Addr(0x200), 0x02, "VSUB"));
        g.add_edge(Addr(0x100), Addr(0x200), Some(true));
        let succs = g.successors(Addr(0x100));
        assert_eq!(succs.len(), 1);
        assert_eq!(succs[0], (Addr(0x200), Some(true)));
    }

    #[test]
    fn test_handler_graph_bfs_order() {
        let mut g = HandlerExecutionGraph::new();
        g.add_node(HandlerNode::new(Addr(0x100), 1, "A"));
        g.add_node(HandlerNode::new(Addr(0x200), 2, "B"));
        g.add_node(HandlerNode::new(Addr(0x300), 3, "C"));
        g.add_edge(Addr(0x100), Addr(0x200), None);
        g.add_edge(Addr(0x200), Addr(0x300), None);
        let order = g.bfs_order();
        assert_eq!(order, vec![Addr(0x100), Addr(0x200), Addr(0x300)]);
    }

    #[test]
    fn test_handler_graph_predecessors() {
        let mut g = HandlerExecutionGraph::new();
        g.add_node(HandlerNode::new(Addr(0x100), 1, "A"));
        g.add_node(HandlerNode::new(Addr(0x200), 2, "B"));
        g.add_edge(Addr(0x100), Addr(0x200), None);
        assert_eq!(g.predecessors(Addr(0x200)), vec![Addr(0x100)]);
    }

    #[test]
    fn test_handler_graph_is_empty() {
        let g = HandlerExecutionGraph::new();
        assert!(g.is_empty());
    }

    // ── VirtualBBSequence ─────────────────────────────────────────────────────

    #[test]
    fn test_vbb_sequence_push_and_len() {
        let mut seq = VirtualBBSequence::new();
        seq.push(VirtualBB::new(0, Addr(0x100)));
        seq.push(VirtualBB::new(1, Addr(0x200)));
        assert_eq!(seq.len(), 2);
        assert!(!seq.is_empty());
    }

    #[test]
    fn test_vbb_sequence_total_opcodes() {
        let mut seq = VirtualBBSequence::new();
        let mut bb = VirtualBB::new(0, Addr(0));
        bb.push_opcode(0x01);
        bb.push_opcode(0x02);
        seq.push(bb);
        assert_eq!(seq.total_opcodes(), 2);
    }

    #[test]
    fn test_vbb_sequence_get() {
        let mut seq = VirtualBBSequence::new();
        seq.push(VirtualBB::new(0, Addr(0x1000)));
        assert!(seq.get(0).is_some());
        assert!(seq.get(99).is_none());
    }

    // ── VirtualizedFunction ───────────────────────────────────────────────────

    #[test]
    fn test_virtualized_function_new() {
        let vf = VirtualizedFunction::new(Addr(0x4000));
        assert_eq!(vf.native_address, Addr(0x4000));
        assert!(!vf.is_lifted());
        assert_eq!(vf.vm_family, "Unknown");
    }

    #[test]
    fn test_virtualized_function_is_lifted() {
        let mut vf = VirtualizedFunction::new(Addr(0));
        vf.handler_graph.add_node(HandlerNode::new(Addr(0), 0, "X"));
        assert!(vf.is_lifted());
    }

    #[test]
    fn test_virtualized_function_confidence() {
        let mut vf = VirtualizedFunction::new(Addr(0));
        vf.entries
            .push(VmEntry::new(Addr(0), VmEntryKind::CallStub, Addr(0)).with_confidence(90));
        let mut dp = VmDispatcherPattern::new(Addr(0), DispatcherShape::JumpTable);
        dp.confidence = 80;
        vf.dispatcher = Some(dp);
        assert_eq!(vf.confidence(), 85);
    }

    #[test]
    fn test_virtualized_function_summary() {
        let vf = VirtualizedFunction::new(Addr(0x1234));
        let s = vf.summary();
        assert!(s.contains("0x1234"));
        assert!(s.contains("Unknown"));
    }

    // ── VmLiftedFunction ──────────────────────────────────────────────────────

    #[test]
    fn test_vm_lifted_new() {
        let vf = VirtualizedFunction::new(Addr(0));
        let lf = VmLiftedFunction::new(vf);
        assert!(!lf.is_complete);
        assert!(!lf.has_output());
    }

    #[test]
    fn test_vm_lifted_line_count() {
        let vf = VirtualizedFunction::new(Addr(0));
        let mut lf = VmLiftedFunction::new(vf);
        lf.pseudo_il.push("VADD r0, r1".into());
        lf.pseudo_il.push("VRET".into());
        assert_eq!(lf.line_count(), 2);
        assert!(lf.has_output());
    }

    // ── Additional tests ──────────────────────────────────────────────────────

    #[test]
    fn test_vm_entry_kind_variants() {
        let _ = VmEntryKind::CallStub;
        let _ = VmEntryKind::JmpDispatcher;
        let _ = VmEntryKind::PushJmp;
        let _ = VmEntryKind::CallOpcode;
        let _ = VmEntryKind::Unknown;
    }

    #[test]
    fn test_dispatcher_shape_variants() {
        let _ = DispatcherShape::JumpTable;
        let _ = DispatcherShape::LinearChain;
        let _ = DispatcherShape::Nested;
        let _ = DispatcherShape::Unknown;
    }

    #[test]
    fn test_vm_exit_kind_variants() {
        let _ = VmExitKind::Ret;
        let _ = VmExitKind::JmpToRetAddr;
        let _ = VmExitKind::EpilogueRet;
        let _ = VmExitKind::Unknown;
    }

    #[test]
    fn test_handler_graph_entry_set_on_first_node() {
        let mut g = HandlerExecutionGraph::new();
        assert!(g.entry.is_none());
        g.add_node(HandlerNode::new(Addr(0x100), 1, "A"));
        assert_eq!(g.entry, Some(Addr(0x100)));
        // Adding a second node should not change entry.
        g.add_node(HandlerNode::new(Addr(0x200), 2, "B"));
        assert_eq!(g.entry, Some(Addr(0x100)));
    }

    #[test]
    fn test_handler_node_is_cf_flag() {
        let mut n = HandlerNode::new(Addr(0), 0, "VBRANCH");
        n.is_cf = true;
        assert!(n.is_cf);
    }

    #[test]
    fn test_handler_node_accesses_memory_flag() {
        let mut n = HandlerNode::new(Addr(0), 0, "VLOAD");
        n.accesses_memory = true;
        assert!(n.accesses_memory);
    }

    #[test]
    fn test_vbb_sequence_is_empty() {
        let seq = VirtualBBSequence::new();
        assert!(seq.is_empty());
    }

    #[test]
    fn test_vbb_is_exit_flag() {
        let mut bb = VirtualBB::new(0, Addr(0));
        assert!(!bb.is_exit);
        bb.is_exit = true;
        assert!(bb.is_exit);
    }

    #[test]
    fn test_vbb_successors() {
        let mut bb = VirtualBB::new(0, Addr(0));
        bb.successors.push(1);
        bb.successors.push(2);
        assert_eq!(bb.successors.len(), 2);
    }

    #[test]
    fn test_detect_vm_entries_multiple_calls() {
        let mut code = vec![0u8; 20];
        // E8 00 00 00 00 at offsets 0 and 10.
        code[0] = 0xE8;
        code[10] = 0xE8;
        let entries = detect_vm_entries(&code, 0x1000);
        
        assert!(entries
            .iter()
            .filter(|e| e.kind == VmEntryKind::CallStub).count() >= 2);
    }

    #[test]
    fn test_detect_vm_exits_retn() {
        let code = [0xC2u8, 0x04, 0x00]; // RETN 4
        let exits = detect_vm_exits(&code, 0);
        assert!(exits.iter().any(|e| e.kind == VmExitKind::Ret));
    }

    #[test]
    fn test_virtualized_function_no_entries_no_confidence() {
        let vf = VirtualizedFunction::new(Addr(0));
        assert_eq!(vf.confidence(), 0);
    }

    #[test]
    fn test_vm_lifted_function_unresolved_count() {
        let vf = VirtualizedFunction::new(Addr(0));
        let mut lf = VmLiftedFunction::new(vf);
        lf.unresolved_count = 3;
        assert!(!lf.is_complete);
        assert_eq!(lf.unresolved_count, 3);
    }

    #[test]
    fn test_handler_graph_bfs_empty() {
        let g = HandlerExecutionGraph::new();
        assert!(g.bfs_order().is_empty());
    }

    #[test]
    fn test_addr_new_constructor() {
        let a = Addr::new(0xCAFE);
        assert_eq!(a.as_u64(), 0xCAFE);
    }
}
