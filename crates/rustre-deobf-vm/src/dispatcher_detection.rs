//! VM Dispatcher Detection
//!
//! Identifies VM dispatchers in binary code by analysing MLIL patterns,
//! control-flow topology, and byte-level signatures for major commercial
//! protectors (`VMProtect` 2.x / 3.x, Themida, Code Virtualizer, Tigress).

#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

use std::collections::{HashMap, HashSet, VecDeque};
use serde::{Deserialize, Serialize};

// ─── Address type (local stub if rustre_core is unavailable) ────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Addr(pub u64);

impl Addr {
    #[must_use]
    pub const fn new(v: u64) -> Self { Self(v) }
    #[must_use]
    pub const fn as_u64(self) -> u64 { self.0 }
    #[must_use]
    pub const fn offset(self, delta: i64) -> Self { Self(self.0.cast_signed().wrapping_add(delta).cast_unsigned()) }
    #[must_use]
    pub const fn distance_to(self, other: Self) -> i64 { other.0.cast_signed() - self.0.cast_signed() }
    #[must_use]
    pub const fn is_aligned(self, n: u64) -> bool { n > 0 && self.0.is_multiple_of(n) }
    #[must_use]
    pub const fn page(self) -> u64 { self.0 & !0xFFF }
}

impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:016x}", self.0)
    }
}

// ─── BasicBlock ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub start: Addr,
    pub end: Addr,
    pub instructions: Vec<RawInstruction>,
    pub successors: Vec<Addr>,
    pub predecessors: Vec<Addr>,
    pub is_indirect_jump: bool,
    pub is_conditional: bool,
    pub call_targets: Vec<Addr>,
}

impl BasicBlock {
    #[must_use]
    pub const fn new(start: Addr, end: Addr) -> Self {
        Self {
            start, end,
            instructions: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
            is_indirect_jump: false,
            is_conditional: false,
            call_targets: Vec::new(),
        }
    }
    #[must_use]
    pub const fn size_bytes(&self) -> u64 { self.end.as_u64().saturating_sub(self.start.as_u64()) }
    #[must_use]
    pub const fn instruction_count(&self) -> usize { self.instructions.len() }
    #[must_use]
    pub const fn has_call(&self) -> bool { !self.call_targets.is_empty() }
    #[must_use]
    pub const fn successor_count(&self) -> usize { self.successors.len() }
    #[must_use]
    pub const fn predecessor_count(&self) -> usize { self.predecessors.len() }
    #[must_use]
    pub fn is_loop_back_edge_target(&self, cfg: &ControlFlowGraph) -> bool {
        self.predecessors.iter().any(|&p| {
            cfg.get_block(p).is_some_and(|b| b.start >= self.start)
        })
    }
}

// ─── RawInstruction ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawInstruction {
    pub addr: Addr,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub length: u8,
    pub is_branch: bool,
    pub is_indirect: bool,
    pub is_call: bool,
    pub is_return: bool,
    pub immediate: Option<i64>,
    pub memory_base: Option<String>,
    pub memory_disp: Option<i64>,
    pub reads_memory: bool,
    pub writes_memory: bool,
}

impl RawInstruction {
    #[must_use]
    pub fn new(addr: Addr, mnemonic: &str, operands: &str) -> Self {
        Self {
            addr,
            bytes: Vec::new(),
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
            length: 0,
            is_branch: false,
            is_indirect: false,
            is_call: false,
            is_return: false,
            immediate: None,
            memory_base: None,
            memory_disp: None,
            reads_memory: false,
            writes_memory: false,
        }
    }

    #[must_use]
    pub fn looks_like_vpc_advance(&self) -> bool {
        // ADD ESI/RSI/EDI/RDI, imm — VPC register advance pattern
        matches!(self.mnemonic.to_lowercase().as_str(), "add" | "inc" | "lea") &&
            (self.operands.to_lowercase().contains("esi") ||
             self.operands.to_lowercase().contains("rsi") ||
             self.operands.to_lowercase().contains("edi") ||
             self.operands.to_lowercase().contains("rdi"))
    }

    #[must_use]
    pub fn looks_like_opcode_fetch(&self) -> bool {
        // MOVZX/MOVSX/MOV fetching a byte/word from [reg] — opcode byte fetch
        let mn = self.mnemonic.to_lowercase();
        (mn == "movzx" || mn == "movsx" || mn == "mov") && self.reads_memory
    }

    #[must_use]
    pub fn is_jmp_through_table(&self) -> bool {
        // JMP [table_base + reg*scale] or JMP [reg]
        self.mnemonic.to_lowercase() == "jmp" && self.is_indirect
    }

    #[must_use]
    pub fn is_nop_like(&self) -> bool {
        matches!(self.mnemonic.to_lowercase().as_str(), "nop" | "xchg" | "lea")
    }
}

// ─── ControlFlowGraph ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    pub blocks: HashMap<u64, BasicBlock>,
    pub entry: Option<Addr>,
}

impl ControlFlowGraph {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    pub fn add_block(&mut self, block: BasicBlock) {
        self.blocks.insert(block.start.as_u64(), block);
    }

    #[must_use]
    pub fn get_block(&self, addr: Addr) -> Option<&BasicBlock> {
        self.blocks.get(&addr.as_u64())
    }

    pub fn get_block_mut(&mut self, addr: Addr) -> Option<&mut BasicBlock> {
        self.blocks.get_mut(&addr.as_u64())
    }

    #[must_use]
    pub fn block_count(&self) -> usize { self.blocks.len() }

    #[must_use]
    pub fn has_indirect_jump(&self) -> bool {
        self.blocks.values().any(|b| b.is_indirect_jump)
    }

    #[must_use]
    pub fn find_high_predecessor_blocks(&self, min_preds: usize) -> Vec<&BasicBlock> {
        self.blocks.values()
            .filter(|b| b.predecessor_count() >= min_preds)
            .collect()
    }

    /// Count edges in the CFG
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.blocks.values().map(|b| b.successors.len()).sum()
    }

    /// Find all basic blocks that are targets of indirect jumps
    #[must_use]
    pub fn indirect_jump_targets(&self) -> HashSet<Addr> {
        let mut targets = HashSet::new();
        for block in self.blocks.values() {
            if block.is_indirect_jump {
                for &succ in &block.successors {
                    targets.insert(succ);
                }
            }
        }
        targets
    }

    /// Dominators: for each block, compute set of blocks that dominate it
    #[must_use]
    pub fn compute_dominators(&self) -> HashMap<u64, HashSet<u64>> {
        let entry = match self.entry {
            Some(e) => e.as_u64(),
            None => return HashMap::new(),
        };
        let all_blocks: HashSet<u64> = self.blocks.keys().copied().collect();
        let mut dom: HashMap<u64, HashSet<u64>> = HashMap::new();
        // Initialize
        dom.insert(entry, std::iter::once(entry).collect());
        for &b in &all_blocks {
            if b != entry {
                dom.insert(b, all_blocks.clone());
            }
        }
        // Iterate to fixed point
        let mut changed = true;
        while changed {
            changed = false;
            for (&b, block) in &self.blocks {
                if b == entry { continue; }
                let preds = &block.predecessors;
                if preds.is_empty() { continue; }
                let mut new_dom: HashSet<u64> = dom[&preds[0].as_u64()].clone();
                for p in preds.iter().skip(1) {
                    let p_dom = &dom[&p.as_u64()];
                    new_dom = new_dom.intersection(p_dom).copied().collect();
                }
                new_dom.insert(b);
                if new_dom != dom[&b] {
                    dom.insert(b, new_dom);
                    changed = true;
                }
            }
        }
        dom
    }

    /// Find back-edges (edges from n to header where header dominates n)
    #[must_use]
    pub fn find_back_edges(&self) -> Vec<(Addr, Addr)> {
        let doms = self.compute_dominators();
        let mut back_edges = Vec::new();
        for (addr, block) in &self.blocks {
            for &succ in &block.successors {
                if let Some(dom_set) = doms.get(addr)
                    && dom_set.contains(&succ.as_u64())
                {
                    back_edges.push((Addr::new(*addr), succ));
                }
            }
        }
        back_edges
    }

    /// Check if the CFG has a "hub" pattern: one block with many predecessors
    #[must_use]
    pub fn has_hub_pattern(&self, threshold: usize) -> bool {
        self.blocks.values().any(|b| b.predecessor_count() >= threshold)
    }

    /// Find candidate dispatcher: block with most predecessors and indirect jump
    #[must_use]
    pub fn find_dispatcher_candidate(&self) -> Option<&BasicBlock> {
        self.blocks.values()
            .filter(|b| b.is_indirect_jump)
            .max_by_key(|b| b.predecessor_count())
    }

    /// Detect loop: basic check via back-edges
    #[must_use]
    pub fn has_loop(&self) -> bool {
        !self.find_back_edges().is_empty()
    }

    /// Blocks reachable from start via BFS
    #[must_use]
    pub fn reachable_from(&self, start: Addr) -> HashSet<Addr> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        while let Some(curr) = queue.pop_front() {
            if visited.contains(&curr) { continue; }
            visited.insert(curr);
            if let Some(block) = self.get_block(curr) {
                for &succ in &block.successors {
                    queue.push_back(succ);
                }
            }
        }
        visited
    }

    /// Compute the ratio of blocks that return to the dispatcher
    #[must_use]
    pub fn dispatcher_return_ratio(&self, dispatcher_addr: Addr) -> f64 {
        let total = self.blocks.len();
        if total == 0 { return 0.0; }
        let returning = self.blocks.values()
            .filter(|b| b.successors.contains(&dispatcher_addr))
            .count();
        f64::from(u32::try_from(returning).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
    }
}

// ─── DispatcherKind ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DispatcherKind {
    /// Simple switch: JMP [table + reg*N]
    JumpTable,
    /// Computed goto: `JMP [handler_array + opcode*8]`
    ComputedGoto,
    /// Threaded: each handler ends with `JMP [next_handler]`
    ThreadedCode,
    /// Encrypted: handler table is encrypted at runtime
    EncryptedTable,
    /// Two-level: outer dispatcher + per-opcode-group inner dispatchers
    TwoLevel,
    /// Indirect call: CALL [table + reg*8]
    IndirectCall,
    /// Unknown pattern
    Unknown,
}

impl DispatcherKind {
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::JumpTable      => "Jump-table dispatch (JMP [table + reg*N])",
            Self::ComputedGoto   => "Computed-goto dispatch",
            Self::ThreadedCode   => "Threaded-code dispatch (each handler chains to next)",
            Self::EncryptedTable => "Encrypted handler-table dispatch",
            Self::TwoLevel       => "Two-level dispatch (outer + inner dispatchers)",
            Self::IndirectCall   => "Indirect-call dispatch",
            Self::Unknown        => "Unknown dispatch pattern",
        }
    }

    #[must_use]
    pub const fn complexity_score(&self) -> u8 {
        match self {
            Self::JumpTable      => 2,
            Self::ComputedGoto | Self::IndirectCall => 3,
            Self::ThreadedCode   => 4,
            Self::EncryptedTable => 8,
            Self::TwoLevel       => 7,
            Self::Unknown        => 1,
        }
    }
}

// ─── ProtectorKind ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtectorKind {
    VMProtect2,
    VMProtect3,
    Themida,
    WinLicense,
    CodeVirtualizer,
    Tigress,
    Custom,
    Unknown,
}

impl ProtectorKind {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::VMProtect2      => "VMProtect 2.x",
            Self::VMProtect3      => "VMProtect 3.x",
            Self::Themida         => "Themida",
            Self::WinLicense      => "WinLicense",
            Self::CodeVirtualizer => "Code Virtualizer",
            Self::Tigress         => "Tigress",
            Self::Custom          => "Custom VM",
            Self::Unknown         => "Unknown Protector",
        }
    }

    #[must_use]
    pub const fn typical_handler_size_range(&self) -> (usize, usize) {
        match self {
            Self::VMProtect2      => (20, 100),
            Self::VMProtect3      => (30, 150),
            Self::Themida | Self::WinLicense => (50, 300),
            Self::CodeVirtualizer => (10, 60),
            Self::Tigress         => (5, 40),
            Self::Custom          => (5, 500),
            Self::Unknown         => (1, 1000),
        }
    }

    #[must_use]
    pub const fn uses_encrypted_table(&self) -> bool {
        matches!(self, Self::Themida | Self::WinLicense | Self::VMProtect3)
    }

    #[must_use]
    pub const fn supports_multiple_vms(&self) -> bool {
        matches!(self, Self::VMProtect2 | Self::VMProtect3 | Self::Themida)
    }
}

// ─── DispatcherInfo ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatcherInfo {
    /// Address of the dispatcher basic block
    pub address: Addr,
    /// Kind of dispatch mechanism detected
    pub kind: DispatcherKind,
    /// Confidence score 0.0 – 1.0
    pub confidence: f64,
    /// Likely protector
    pub protector: ProtectorKind,
    /// Address of the handler table (if detected)
    pub handler_table: Option<Addr>,
    /// Number of entries in handler table
    pub handler_count: Option<usize>,
    /// Address of the virtual program counter register or memory slot
    pub vpc_location: Option<VpcLocation>,
    /// Number of basic blocks in the surrounding function
    pub function_bb_count: usize,
    /// Ratio of blocks that return to this dispatcher
    pub return_ratio: f64,
    /// Evidence items that led to this detection
    pub evidence: Vec<String>,
    /// Byte patterns that matched known signatures
    pub matched_signatures: Vec<String>,
}

impl DispatcherInfo {
    #[must_use]
    pub const fn new(address: Addr) -> Self {
        Self {
            address,
            kind: DispatcherKind::Unknown,
            confidence: 0.0,
            protector: ProtectorKind::Unknown,
            handler_table: None,
            handler_count: None,
            vpc_location: None,
            function_bb_count: 0,
            return_ratio: 0.0,
            evidence: Vec::new(),
            matched_signatures: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_evidence(mut self, e: impl Into<String>) -> Self {
        self.evidence.push(e.into());
        self
    }

    pub fn add_evidence(&mut self, e: impl Into<String>) {
        self.evidence.push(e.into());
    }

    #[must_use]
    pub fn is_high_confidence(&self) -> bool { self.confidence >= 0.75 }
    #[must_use]
    pub fn is_medium_confidence(&self) -> bool { self.confidence >= 0.50 }

    #[must_use]
    pub fn confidence_label(&self) -> &'static str {
        if self.confidence >= 0.85 { "HIGH" }
        else if self.confidence >= 0.60 { "MEDIUM" }
        else if self.confidence >= 0.35 { "LOW" }
        else { "SPECULATIVE" }
    }
}

// ─── VpcLocation ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VpcLocation {
    /// VPC kept in a CPU register (e.g. RSI, ESI, RDI)
    Register(String),
    /// VPC stored in a fixed memory address
    MemoryFixed(Addr),
    /// VPC stored at offset from a base pointer
    MemoryRelative { base_reg: String, offset: i64 },
}

impl VpcLocation {
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::Register(r) => format!("CPU register {r}"),
            Self::MemoryFixed(a) => format!("memory at {a}"),
            Self::MemoryRelative { base_reg, offset } =>
                format!("[{base_reg}+{offset:#x}]"),
        }
    }

    #[must_use]
    pub const fn is_register(&self) -> bool { matches!(self, Self::Register(_)) }
}

// ─── DispatcherScore ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DispatcherScore {
    /// Has at least one loop (back-edge)
    pub has_loop: f64,
    /// Has an indirect jump
    pub has_indirect_jump: f64,
    /// High predecessor count at dispatcher candidate
    pub hub_score: f64,
    /// Many blocks return to same target (the hub)
    pub return_convergence: f64,
    /// Detected VPC fetch pattern
    pub vpc_fetch: f64,
    /// Matched a known protector signature
    pub signature_match: f64,
    /// Handler table detected in memory
    pub handler_table: f64,
    /// Opcode range matches expected (e.g. 0-255)
    pub opcode_range: f64,
}

impl DispatcherScore {
    #[must_use]
    pub fn total(&self) -> f64 {
        let scores = [
            self.has_loop * 0.10,
            self.has_indirect_jump * 0.15,
            self.hub_score * 0.20,
            self.return_convergence * 0.15,
            self.vpc_fetch * 0.15,
            self.signature_match * 0.15,
            self.handler_table * 0.05,
            self.opcode_range * 0.05,
        ];
        scores.iter().sum::<f64>().min(1.0)
    }

    #[must_use]
    pub const fn normalize(v: f64) -> f64 { v.clamp(0.0, 1.0) }
}

// ─── DispatcherDetector ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DispatcherDetector {
    /// Minimum confidence threshold for a positive detection
    pub min_confidence: f64,
    /// Minimum number of handlers in table for a valid VM
    pub min_handler_count: usize,
    /// Maximum CFG size to analyse (performance limit)
    pub max_cfg_blocks: usize,
    /// Enable signature-based matching
    pub use_signatures: bool,
}

impl Default for DispatcherDetector {
    fn default() -> Self {
        Self {
            min_confidence: 0.40,
            min_handler_count: 4,
            max_cfg_blocks: 5000,
            use_signatures: true,
        }
    }
}

impl DispatcherDetector {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    #[must_use]
    pub const fn with_min_confidence(mut self, c: f64) -> Self {
        // NaN-safe clamp: `f64::clamp` propagates NaN and `is_nan()` is not
        // available in a const fn. A NaN threshold would reject every candidate
        // in silence, since all comparisons against NaN are false.
        self.min_confidence = if c >= 1.0 {
            1.0
        } else if c > 0.0 {
            c
        } else {
            0.0
        };
        self
    }

    #[must_use]
    pub const fn with_min_handler_count(mut self, n: usize) -> Self {
        self.min_handler_count = n;
        self
    }

    /// Analyse a CFG and return all detected dispatchers sorted by confidence.
    #[must_use]
    pub fn detect(&self, cfg: &ControlFlowGraph) -> Vec<DispatcherInfo> {
        if cfg.block_count() > self.max_cfg_blocks {
            return Vec::new();
        }
        let mut candidates = Vec::new();
        // Step 1: find hub candidates (high predecessor count + indirect jump)
        for block in cfg.blocks.values() {
            if block.is_indirect_jump && block.predecessor_count() >= 2 {
                let info = self.score_block(block, cfg);
                if info.confidence >= self.min_confidence {
                    candidates.push(info);
                }
            }
        }
        // Step 2: also check blocks with very high predecessor count even without indirect jump
        for block in cfg.blocks.values() {
            let ratio = cfg.dispatcher_return_ratio(block.start);
            if ratio >= 0.5 && block.predecessor_count() >= 4 {
                let already = candidates.iter().any(|c| c.address == block.start);
                if !already {
                    let info = self.score_block(block, cfg);
                    if info.confidence >= self.min_confidence {
                        candidates.push(info);
                    }
                }
            }
        }
        candidates.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        candidates
    }

    /// Score a single candidate basic block as potential dispatcher.
    #[must_use]
    pub fn score_block(&self, block: &BasicBlock, cfg: &ControlFlowGraph) -> DispatcherInfo {
        let mut info = DispatcherInfo::new(block.start);
        let mut score = DispatcherScore::default();

        // 1. Loop detection
        if cfg.has_loop() {
            score.has_loop = 1.0;
            info.add_evidence("CFG contains at least one loop (back-edge)");
        }

        // 2. Indirect jump
        if block.is_indirect_jump {
            score.has_indirect_jump = 1.0;
            info.kind = DispatcherKind::JumpTable;
            info.add_evidence("Block ends with indirect jump");
        }

        // 3. Hub score (predecessor count)
        let pred_count = block.predecessor_count();
        if pred_count >= 20 {
            score.hub_score = 1.0;
            info.add_evidence(format!("Very high predecessor count: {pred_count}"));
        } else if pred_count >= 10 {
            score.hub_score = 0.8;
            info.add_evidence(format!("High predecessor count: {pred_count}"));
        } else if pred_count >= 4 {
            score.hub_score = 0.5;
            info.add_evidence(format!("Elevated predecessor count: {pred_count}"));
        } else if pred_count >= 2 {
            score.hub_score = 0.2;
        }

        // 4. Return convergence: ratio of blocks that return here
        let ratio = cfg.dispatcher_return_ratio(block.start);
        info.return_ratio = ratio;
        info.function_bb_count = cfg.block_count();
        if ratio >= 0.6 {
            score.return_convergence = 1.0;
            info.add_evidence(format!("High return convergence ratio: {:.1}%", ratio * 100.0_f64));
        } else if ratio >= 0.4 {
            score.return_convergence = 0.7;
        } else if ratio >= 0.2 {
            score.return_convergence = 0.3;
        }

        // 5. VPC fetch pattern in instructions
        let vpc_result = Self::detect_vpc_fetch(block);
        if let Some(vpc_loc) = vpc_result {
            score.vpc_fetch = 0.9;
            info.add_evidence(format!("VPC fetch pattern detected: {}", vpc_loc.description()));
            info.vpc_location = Some(vpc_loc);
        }

        // 6. Signature matching
        if self.use_signatures {
            let sig_result = Self::match_signatures(block);
            if let Some((protector, sig_name)) = sig_result {
                score.signature_match = 1.0;
                info.protector = protector;
                info.matched_signatures.push(sig_name.clone());
                info.add_evidence(format!("Matched signature: {sig_name}"));
            }
        }

        // 7. Opcode range check (are successors within a plausible range?)
        if block.successors.len() >= 4 {
            let max_addr = block.successors.iter().map(|a| a.as_u64()).max().unwrap_or(0);
            let min_addr = block.successors.iter().map(|a| a.as_u64()).min().unwrap_or(0);
            let range = max_addr.saturating_sub(min_addr);
            if range < 0x100_000 { // All handlers within 1MB of each other
                score.opcode_range = 0.8;
                info.handler_count = Some(block.successors.len());
                let hcount = block.successors.len();
            info.add_evidence(format!("Handler targets within 1MB range, count={hcount}"));
            }
        }

        // Determine dispatch kind
        if score.signature_match > 0.5 {
            // Keep protector-specific kind from signature
        } else if block.is_indirect_jump && pred_count >= 8 {
            info.kind = DispatcherKind::JumpTable;
        } else if pred_count >= 8 && !block.is_indirect_jump {
            info.kind = DispatcherKind::ThreadedCode;
        }

        let total_conf = score.total();
        info.confidence = total_conf;
        info
    }

    /// Detect VPC (virtual program counter) fetch pattern in a basic block.
    fn detect_vpc_fetch(block: &BasicBlock) -> Option<VpcLocation> {
        // Pattern 1: MOVZX reg, byte ptr [ESI/RSI] — fetch opcode byte from VPC register
        for insn in &block.instructions {
            if insn.looks_like_opcode_fetch()
                && let Some(base) = &insn.memory_base
            {
                let b = base.to_lowercase();
                if b == "esi" || b == "rsi" {
                    return Some(VpcLocation::Register("RSI/ESI".to_string()));
                }
                if b == "edi" || b == "rdi" {
                    return Some(VpcLocation::Register("RDI/EDI".to_string()));
                }
                if b == "ebx" || b == "rbx" {
                    return Some(VpcLocation::Register("RBX/EBX".to_string()));
                }
                if b == "ecx" || b == "rcx" {
                    return Some(VpcLocation::Register("RCX/ECX".to_string()));
                }
            }
        }
        // Pattern 2: fetch from [mem_base + const_offset]
        for insn in &block.instructions {
            if insn.looks_like_opcode_fetch()
                && let (Some(base), Some(disp)) = (&insn.memory_base, insn.memory_disp)
            {
                return Some(VpcLocation::MemoryRelative {
                    base_reg: base.clone(),
                    offset: disp,
                });
            }
        }
        None
    }

    /// Match byte patterns against known protector signatures.
    fn match_signatures(block: &BasicBlock) -> Option<(ProtectorKind, String)> {
        // Collect all bytes from block instructions
        let bytes: Vec<u8> = block.instructions.iter()
            .flat_map(|i| i.bytes.iter().copied())
            .collect();

        // VMProtect 2.x: characteristic stub bytes (simplified heuristic)
        // Real VMProtect stub often starts with: 68 xx xx xx xx (PUSH imm32) E8 xx xx xx xx (CALL handler)
        if bytes.len() >= 6 && bytes[0] == 0x68 && bytes[5] == 0xE8 {
            return Some((ProtectorKind::VMProtect2, "VMProtect2 entry stub (PUSH+CALL)".to_string()));
        }

        // VMProtect 3.x: often uses CPUID-based VM detection bypass pattern
        // 0F A2 = CPUID
        if bytes.windows(2).any(|w| w == [0x0F, 0xA2]) {
            return Some((ProtectorKind::VMProtect3, "VMProtect3 CPUID anti-detection".to_string()));
        }

        // Code Virtualizer: characteristic short handlers, JMP pattern
        // Handlers are typically 10-40 bytes with JMP at end
        let instr_count = block.instruction_count();
        if (5..=25).contains(&instr_count) && block.is_indirect_jump {
            // Short handler ending in indirect JMP is Code Virtualizer style
            return Some((ProtectorKind::CodeVirtualizer, "Short handler with indirect JMP".to_string()));
        }

        // Themida: large dispatcher with many XOR/encryption instructions
        let xor_count = block.instructions.iter()
            .filter(|i| i.mnemonic.to_lowercase() == "xor")
            .count();
        if xor_count >= 5 {
            return Some((ProtectorKind::Themida, "High XOR instruction density (encryption/decryption)".to_string()));
        }

        None
    }

    /// High-level wrapper: analyse raw binary bytes to find dispatcher candidates.
    #[must_use]
    pub fn detect_from_bytes(&self, bytes: &[u8], base_addr: u64) -> Vec<DispatcherInfo> {
        let cfg = Self::build_synthetic_cfg(bytes, base_addr);
        self.detect(&cfg)
    }

    /// Build a synthetic CFG from raw bytes (simplified: each 16-byte aligned region = block).
    fn build_synthetic_cfg(bytes: &[u8], base_addr: u64) -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new();
        let block_size: usize = 16;
        let n_blocks = bytes.len() / block_size;
        if n_blocks == 0 { return cfg; }

        for i in 0..n_blocks {
            let start = Addr::new(base_addr + (i * block_size) as u64);
            let end = Addr::new(base_addr + ((i + 1) * block_size) as u64);
            let mut block = BasicBlock::new(start, end);
            block.instructions = bytes[i*block_size..(i+1)*block_size]
                .chunks(4)
                .enumerate()
                .map(|(j, chunk)| {
                    let mut insn = RawInstruction::new(
                        Addr::new(start.as_u64() + j as u64 * 4),
                        "nop", "",
                    );
                    insn.bytes = chunk.to_vec();
                    insn
                })
                .collect();
            // Heuristic: if last byte is 0xFF, mark as indirect jump
            if bytes[(i+1)*block_size - 1] == 0xFF {
                block.is_indirect_jump = true;
            }
            // Add successor to next block
            if i + 1 < n_blocks {
                block.successors.push(Addr::new(base_addr + ((i + 1) * block_size) as u64));
            }
            cfg.add_block(block);
        }

        // Build predecessor lists
        let succ_pairs: Vec<(u64, u64)> = cfg.blocks.values()
            .flat_map(|b| b.successors.iter().map(move |&s| (b.start.as_u64(), s.as_u64())))
            .collect();
        for (from, to) in succ_pairs {
            if let Some(block) = cfg.get_block_mut(Addr::new(to)) {
                block.predecessors.push(Addr::new(from));
            }
        }

        cfg.entry = cfg.blocks.keys().copied().min().map(Addr::new);
        cfg
    }
}

// ─── FunctionSignatureDatabase ───────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignatureDatabase {
    pub entries: Vec<SignatureEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureEntry {
    pub name: String,
    pub protector: ProtectorKind,
    pub pattern: Vec<BytePattern>,
    pub description: String,
    pub confidence_bonus: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BytePattern {
    Exact(u8),
    Wildcard,
    Range(u8, u8),
    OneOf(Vec<u8>),
}

impl BytePattern {
    #[must_use]
    pub fn matches(&self, byte: u8) -> bool {
        match self {
            Self::Exact(b) => *b == byte,
            Self::Wildcard => true,
            Self::Range(lo, hi) => byte >= *lo && byte <= *hi,
            Self::OneOf(options) => options.contains(&byte),
        }
    }
}

impl SignatureDatabase {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    #[must_use]
    pub fn with_builtin_signatures() -> Self {
        let mut db = Self::new();

        // VMProtect 2.x dispatcher stub
        db.entries.push(SignatureEntry {
            name: "VMProtect2_Dispatcher".to_string(),
            protector: ProtectorKind::VMProtect2,
            pattern: vec![
                BytePattern::Exact(0x68),  // PUSH imm32
                BytePattern::Wildcard, BytePattern::Wildcard, BytePattern::Wildcard, BytePattern::Wildcard,
                BytePattern::Exact(0xE8),  // CALL rel32
                BytePattern::Wildcard, BytePattern::Wildcard, BytePattern::Wildcard, BytePattern::Wildcard,
            ],
            description: "VMProtect 2.x entry stub: PUSH imm32; CALL handler".to_string(),
            confidence_bonus: 0.85,
        });

        // VMProtect 2.x MOVZX opcode fetch
        db.entries.push(SignatureEntry {
            name: "VMProtect2_OpcodeFetch".to_string(),
            protector: ProtectorKind::VMProtect2,
            pattern: vec![
                BytePattern::Exact(0x0F), BytePattern::Exact(0xB6), // MOVZX
                BytePattern::Range(0x00, 0x3F), // ModRM: reg, [reg]
            ],
            description: "VMProtect 2.x opcode fetch: MOVZX reg, byte ptr [VPC]".to_string(),
            confidence_bonus: 0.70,
        });

        // VMProtect 3.x CPUID probe
        db.entries.push(SignatureEntry {
            name: "VMProtect3_CPUID".to_string(),
            protector: ProtectorKind::VMProtect3,
            pattern: vec![
                BytePattern::Exact(0x0F), BytePattern::Exact(0xA2), // CPUID
            ],
            description: "VMProtect 3.x uses CPUID for VM detection evasion".to_string(),
            confidence_bonus: 0.60,
        });

        // Themida: LEA + encryption sequence
        db.entries.push(SignatureEntry {
            name: "Themida_XorDecrypt".to_string(),
            protector: ProtectorKind::Themida,
            pattern: vec![
                BytePattern::Exact(0x33), BytePattern::Range(0xC0, 0xFF), // XOR reg, reg/mem
                BytePattern::Exact(0x33), BytePattern::Range(0xC0, 0xFF), // XOR reg, reg/mem
                BytePattern::Exact(0x33), BytePattern::Range(0xC0, 0xFF), // XOR reg, reg/mem
            ],
            description: "Themida: three consecutive XOR instructions (decryption loop)".to_string(),
            confidence_bonus: 0.65,
        });

        // Code Virtualizer: short handler + RET/JMP
        db.entries.push(SignatureEntry {
            name: "CodeVirtualizer_Handler".to_string(),
            protector: ProtectorKind::CodeVirtualizer,
            pattern: vec![
                BytePattern::Wildcard,
                BytePattern::Wildcard,
                BytePattern::Wildcard,
                BytePattern::Exact(0xFF), BytePattern::Range(0x20, 0x27), // JMP [reg]
            ],
            description: "Code Virtualizer short handler ending with indirect JMP".to_string(),
            confidence_bonus: 0.55,
        });

        db
    }

    #[must_use]
    pub fn match_bytes(&self, bytes: &[u8]) -> Vec<(&SignatureEntry, usize)> {
        let mut results = Vec::new();
        for entry in &self.entries {
            if let Some(offset) = Self::find_pattern(bytes, &entry.pattern) {
                results.push((entry, offset));
            }
        }
        results
    }

    fn find_pattern(haystack: &[u8], pattern: &[BytePattern]) -> Option<usize> {
        if pattern.is_empty() || haystack.len() < pattern.len() { return None; }
        (0..=(haystack.len() - pattern.len()))
            .find(|&i| pattern.iter().zip(&haystack[i..]).all(|(p, &b)| p.matches(b)))
    }

    #[must_use]
    pub const fn entry_count(&self) -> usize { self.entries.len() }
}

// ─── VpcDetectionResult ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpcDetectionResult {
    pub vpc_location: VpcLocation,
    pub confidence: f64,
    pub detection_method: String,
    pub supporting_instructions: Vec<String>,
    pub estimated_step_size: Option<u32>,
}

impl VpcDetectionResult {
    #[must_use]
    pub fn new(loc: VpcLocation, confidence: f64, method: &str) -> Self {
        Self {
            vpc_location: loc,
            confidence,
            detection_method: method.to_string(),
            supporting_instructions: Vec::new(),
            estimated_step_size: None,
        }
    }
}

// ─── VpcAnalyzer ────────────────────────────────────────────────────────────

pub struct VpcAnalyzer;

impl VpcAnalyzer {
    /// Analyse all basic blocks in a CFG to find the virtual program counter.
    #[must_use]
    pub fn detect(cfg: &ControlFlowGraph) -> Option<VpcDetectionResult> {
        // Strategy 1: Find the register most commonly used as memory base for byte fetches
        let mut reg_fetch_count: HashMap<String, u32> = HashMap::new();
        for block in cfg.blocks.values() {
            for insn in &block.instructions {
                if insn.looks_like_opcode_fetch()
                    && let Some(base) = &insn.memory_base
                {
                    *reg_fetch_count.entry(base.clone()).or_insert(0) += 1;
                }
            }
        }
        if let Some((reg, count)) = reg_fetch_count.iter().max_by_key(|&(_, &c)| c)
            && *count >= 2
        {
            return Some(VpcDetectionResult {
                vpc_location: VpcLocation::Register(reg.clone()),
                confidence: (f64::from(*count) / 10.0).min(0.95),
                detection_method: format!("Register {reg} used as fetch base {count} times"),
                supporting_instructions: Vec::new(),
                estimated_step_size: None,
            });
        }

        // Strategy 2: Find register that is incremented/decremented before indirect jump
        for block in cfg.blocks.values() {
            if !block.is_indirect_jump { continue; }
            for insn in &block.instructions {
                if insn.looks_like_vpc_advance()
                    && let Some(step) = insn.immediate
                {
                    let reg = insn.operands.split(',').next()
                        .unwrap_or("unknown")
                        .trim()
                        .to_uppercase();
                    return Some(VpcDetectionResult {
                        vpc_location: VpcLocation::Register(reg.clone()),
                        confidence: 0.70,
                        detection_method: format!("Register {reg} advanced by {step} before indirect jump"),
                        supporting_instructions: vec![
                            format!("{} {}", insn.mnemonic, insn.operands),
                        ],
                        estimated_step_size: Some(u32::try_from(step.unsigned_abs()).unwrap_or(u32::MAX)),
                    });
                }
            }
        }

        None
    }
}

// ─── DispatcherReport ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatcherReport {
    pub dispatchers: Vec<DispatcherInfo>,
    pub vpc_analysis: Option<VpcDetectionResult>,
    pub signature_matches: Vec<String>,
    pub overall_confidence: f64,
    pub recommended_strategy: String,
    pub analysis_notes: Vec<String>,
}

impl DispatcherReport {
    #[must_use]
    pub fn from_detections(
        dispatchers: Vec<DispatcherInfo>,
        vpc: Option<VpcDetectionResult>,
    ) -> Self {
        let overall = dispatchers.iter()
            .map(|d| d.confidence)
            .fold(0.0f64, f64::max);

        let strategy = if overall >= 0.80 {
            "High confidence VM detected. Proceed with handler extraction and ISA recovery.".to_string()
        } else if overall >= 0.50 {
            "Medium confidence VM. Manual verification recommended before full analysis.".to_string()
        } else {
            "Low confidence or no VM detected. May not be a virtual machine protector.".to_string()
        };

        let mut notes = Vec::new();
        if dispatchers.is_empty() {
            notes.push("No dispatcher candidates found. Binary may not use VM obfuscation.".to_string());
        }
        if let Some(ref vpc) = vpc {
            notes.push(format!("VPC identified: {} (confidence: {:.0}%)",
                vpc.vpc_location.description(), vpc.confidence * 100.0));
        }

        Self {
            signature_matches: dispatchers.iter()
                .flat_map(|d| d.matched_signatures.iter().cloned())
                .collect(),
            overall_confidence: overall,
            recommended_strategy: strategy,
            analysis_notes: notes,
            dispatchers,
            vpc_analysis: vpc,
        }
    }

    #[must_use]
    pub fn best_dispatcher(&self) -> Option<&DispatcherInfo> {
        self.dispatchers.iter().max_by(|a, b|
            a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal))
    }

    #[must_use]
    pub fn has_high_confidence_detection(&self) -> bool {
        self.dispatchers.iter().any(DispatcherInfo::is_high_confidence)
    }

    #[must_use]
    pub fn detected_protectors(&self) -> Vec<&ProtectorKind> {
        self.dispatchers.iter().map(|d| &d.protector).collect()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block(start: u64, preds: Vec<u64>, succs: Vec<u64>, indirect: bool) -> BasicBlock {
        let mut b = BasicBlock::new(Addr::new(start), Addr::new(start + 16));
        b.predecessors = preds.into_iter().map(Addr::new).collect();
        b.successors = succs.into_iter().map(Addr::new).collect();
        b.is_indirect_jump = indirect;
        b
    }

    fn make_cfg_with_hub() -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new();
        // Dispatcher at 0x1000 with 10 predecessors
        let mut disp = make_block(0x1000, (0..10).map(|i| 0x2000 + i * 0x100).collect(), vec![0x3000, 0x3100], true);
        disp.is_indirect_jump = true;
        cfg.add_block(disp);
        // Handler blocks that return to dispatcher
        for i in 0u64..10 {
            let b = make_block(0x2000 + i * 0x100, vec![0x1000], vec![0x1000], false);
            cfg.add_block(b);
        }
        cfg.entry = Some(Addr::new(0x1000));
        cfg
    }

    #[test]
    fn test_dispatcher_detection_basic() {
        let cfg = make_cfg_with_hub();
        let detector = DispatcherDetector::new();
        let results = detector.detect(&cfg);
        assert!(!results.is_empty(), "Should detect at least one dispatcher candidate");
    }

    #[test]
    fn test_dispatcher_confidence_positive() {
        let cfg = make_cfg_with_hub();
        let detector = DispatcherDetector::new();
        let results = detector.detect(&cfg);
        assert!(results[0].confidence > 0.40, "Confidence should exceed threshold");
    }

    #[test]
    fn test_empty_cfg_no_detection() {
        let cfg = ControlFlowGraph::new();
        let detector = DispatcherDetector::new();
        let results = detector.detect(&cfg);
        assert!(results.is_empty());
    }

    #[test]
    fn test_return_ratio_calculation() {
        let cfg = make_cfg_with_hub();
        let ratio = cfg.dispatcher_return_ratio(Addr::new(0x1000));
        assert!(ratio > 0.5, "More than half the blocks return to dispatcher");
    }

    #[test]
    fn test_addr_offset() {
        let a = Addr::new(0x1000);
        assert_eq!(a.offset(0x100).as_u64(), 0x1100);
        assert_eq!(a.offset(-0x10).as_u64(), 0xFF0);
    }

    #[test]
    fn test_addr_page() {
        assert_eq!(Addr::new(0x12345).page(), 0x12000);
    }

    #[test]
    fn test_dispatcher_score_total_clamped() {
        let s = DispatcherScore {
            has_loop: 1.0,
            has_indirect_jump: 1.0,
            hub_score: 1.0,
            return_convergence: 1.0,
            vpc_fetch: 1.0,
            signature_match: 1.0,
            handler_table: 1.0,
            opcode_range: 1.0,
        };
        assert!(s.total() <= 1.0);
    }

    #[test]
    fn test_protector_kind_names() {
        assert_eq!(ProtectorKind::VMProtect2.name(), "VMProtect 2.x");
        assert_eq!(ProtectorKind::Themida.name(), "Themida");
        assert!(ProtectorKind::Themida.uses_encrypted_table());
        assert!(!ProtectorKind::CodeVirtualizer.uses_encrypted_table());
    }

    #[test]
    fn test_dispatcher_kind_complexity() {
        assert!(DispatcherKind::EncryptedTable.complexity_score() > DispatcherKind::JumpTable.complexity_score());
    }

    #[test]
    fn test_vpc_location_description() {
        let v1 = VpcLocation::Register("RSI".to_string());
        assert!(v1.description().contains("RSI"));
        assert!(v1.is_register());
        let v2 = VpcLocation::MemoryFixed(Addr::new(0x0040_4000));
        assert!(v2.description().contains("memory"));
    }

    #[test]
    fn test_signature_database_builtin() {
        let db = SignatureDatabase::with_builtin_signatures();
        assert!(db.entry_count() >= 5);
    }

    #[test]
    fn test_signature_match_vmprotect2() {
        let db = SignatureDatabase::with_builtin_signatures();
        let bytes = vec![0x68, 0x11, 0x22, 0x33, 0x44, 0xE8, 0x01, 0x02, 0x03, 0x04];
        let matches = db.match_bytes(&bytes);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].0.protector, ProtectorKind::VMProtect2);
    }

    #[test]
    fn test_byte_pattern_exact() {
        assert!(BytePattern::Exact(0xAB).matches(0xAB));
        assert!(!BytePattern::Exact(0xAB).matches(0xAC));
    }

    #[test]
    fn test_byte_pattern_wildcard() {
        for b in 0u8..=255 {
            assert!(BytePattern::Wildcard.matches(b));
        }
    }

    #[test]
    fn test_byte_pattern_range() {
        let p = BytePattern::Range(0x10, 0x20);
        assert!(p.matches(0x10));
        assert!(p.matches(0x20));
        assert!(p.matches(0x15));
        assert!(!p.matches(0x09));
        assert!(!p.matches(0x21));
    }

    #[test]
    fn test_byte_pattern_one_of() {
        let p = BytePattern::OneOf(vec![0xAA, 0xBB, 0xCC]);
        assert!(p.matches(0xAA));
        assert!(p.matches(0xCC));
        assert!(!p.matches(0xDD));
    }

    #[test]
    fn test_dominator_computation_simple() {
        let mut cfg = ControlFlowGraph::new();
        let entry = make_block(0x1000, vec![], vec![0x2000], false);
        let b2 = make_block(0x2000, vec![0x1000], vec![], false);
        cfg.add_block(entry);
        cfg.add_block(b2);
        cfg.entry = Some(Addr::new(0x1000));
        let doms = cfg.compute_dominators();
        assert!(doms[&0x1000].contains(&0x1000));
        assert!(doms[&0x2000].contains(&0x1000));
        assert!(doms[&0x2000].contains(&0x2000));
    }

    #[test]
    fn test_reachable_from_simple() {
        let cfg = make_cfg_with_hub();
        let reachable = cfg.reachable_from(Addr::new(0x1000));
        assert!(reachable.contains(&Addr::new(0x1000)));
    }

    #[test]
    fn test_dispatcher_report_best() {
        let d1 = DispatcherInfo { confidence: 0.6, ..DispatcherInfo::new(Addr::new(0x1000)) };
        let d2 = DispatcherInfo { confidence: 0.9, ..DispatcherInfo::new(Addr::new(0x2000)) };
        let report = DispatcherReport::from_detections(vec![d1, d2], None);
        assert_eq!(report.best_dispatcher().unwrap().address, Addr::new(0x2000));
        assert!(report.has_high_confidence_detection());
    }

    #[test]
    fn test_dispatcher_report_empty() {
        let report = DispatcherReport::from_detections(vec![], None);
        assert!(!report.has_high_confidence_detection());
        assert!(report.best_dispatcher().is_none());
        assert!(!report.analysis_notes.is_empty());
    }

    #[test]
    fn test_detect_from_bytes_returns_vec() {
        let detector = DispatcherDetector::new();
        let bytes = vec![0u8; 256];
        let result = detector.detect_from_bytes(&bytes, 0x0040_0000);
        // Result may be empty for zero bytes, but should not panic
        let _ = result;
    }

    #[test]
    fn test_confidence_label() {
        let mut info = DispatcherInfo::new(Addr::new(0));
        info.confidence = 0.95;
        assert_eq!(info.confidence_label(), "HIGH");
        info.confidence = 0.70;
        assert_eq!(info.confidence_label(), "MEDIUM");
        info.confidence = 0.45;
        assert_eq!(info.confidence_label(), "LOW");
        info.confidence = 0.10;
        assert_eq!(info.confidence_label(), "SPECULATIVE");
    }

    #[test]
    fn test_basic_block_size() {
        let b = BasicBlock::new(Addr::new(0x1000), Addr::new(0x1010));
        assert_eq!(b.size_bytes(), 16);
    }

    #[test]
    fn test_basic_block_is_loop_back_edge_target() {
        let mut cfg = ControlFlowGraph::new();
        // 0x1000 -> 0x2000 -> 0x1000 (loop)
        let b1 = make_block(0x1000, vec![0x2000], vec![0x2000], false);
        let b2 = make_block(0x2000, vec![0x1000], vec![0x1000], false);
        cfg.add_block(b1);
        cfg.add_block(b2);
        let b2_ref = cfg.get_block(Addr::new(0x2000)).unwrap();
        // 0x2000 predecessor is 0x1000 which is < 0x2000, so not a back-edge target
        assert!(!b2_ref.is_loop_back_edge_target(&cfg));
        let b1_ref = cfg.get_block(Addr::new(0x1000)).unwrap();
        // 0x1000 has predecessor 0x2000 which is > 0x1000, so IS a loop target
        assert!(b1_ref.is_loop_back_edge_target(&cfg));
    }

    #[test]
    fn test_vpc_analyzer_returns_option() {
        let cfg = ControlFlowGraph::new();
        let result = VpcAnalyzer::detect(&cfg);
        assert!(result.is_none()); // empty CFG has no VPC
    }

    #[test]
    fn test_dispatcher_detector_with_min_confidence() {
        let detector = DispatcherDetector::new().with_min_confidence(0.9);
        assert!((detector.min_confidence - 0.9_f64).abs() < f64::EPSILON);
    }

    #[test]
    fn test_dispatcher_info_with_evidence() {
        let info = DispatcherInfo::new(Addr::new(0x1000))
            .with_evidence("test evidence A")
            .with_evidence("test evidence B");
        assert_eq!(info.evidence.len(), 2);
    }

    #[test]
    fn test_cfg_edge_count() {
        let cfg = make_cfg_with_hub();
        assert!(cfg.edge_count() > 0);
    }

    #[test]
    fn test_cfg_has_hub_pattern() {
        let cfg = make_cfg_with_hub();
        assert!(cfg.has_hub_pattern(5));
        assert!(!cfg.has_hub_pattern(50));
    }

    #[test]
    fn test_cfg_has_loop_false_for_linear() {
        let mut cfg = ControlFlowGraph::new();
        // A -> B -> C (no loop)
        cfg.add_block(make_block(0x1000, vec![], vec![0x2000], false));
        cfg.add_block(make_block(0x2000, vec![0x1000], vec![0x3000], false));
        cfg.add_block(make_block(0x3000, vec![0x2000], vec![], false));
        cfg.entry = Some(Addr::new(0x1000));
        // No back-edges
        let back = cfg.find_back_edges();
        assert!(back.is_empty(), "Linear CFG should have no back-edges");
    }
}
