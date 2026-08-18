//! Junk code remover.
//!
//! After the [`conditional_simplifier`] has identified dead branches, this pass
//! walks each dead basic block and marks every instruction in it as
//! *dead* (junk).  A separate NOP-fill or removal step can then act on
//! the resulting `RemoveResult`.
//!
//! Dead-code analysis
//! ──────────────────
//! 1. Seed the dead set with all dead branch targets supplied by the
//!    conditional simplifier.
//! 2. Iteratively add successors of dead blocks until convergence.
//! 3. Mark every instruction in dead blocks as `DeadInstruction`.
//! 4. Exclude blocks that are reachable from a live block (conservative).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ── DeadInstruction ───────────────────────────────────────────────────────────

/// A single instruction identified as dead code.
#[derive(Debug, Clone)]
pub struct DeadInstruction {
    /// Virtual address of the instruction.
    pub address: u64,
    /// Instruction size in bytes.
    pub size: u8,
    /// Raw opcode bytes (up to 15 bytes for x86).
    pub bytes: Vec<u8>,
    /// Reason the instruction is considered dead.
    pub reason: DeadReason,
}

impl fmt::Display for DeadInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#x} ({} bytes) — {}",
            self.address, self.size, self.reason
        )
    }
}

// ── DeadReason ────────────────────────────────────────────────────────────────

/// Why an instruction is dead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeadReason {
    /// It lives in a basic block reachable only from a dead branch target.
    UnreachableBlock { block_start: u64 },
    /// It is in a block that was transitively marked dead.
    TransitivelDead { block_start: u64 },
    /// Explicit NOP or padding inserted by the obfuscator.
    ObfuscatorNop,
}

impl fmt::Display for DeadReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnreachableBlock { block_start } => {
                write!(f, "unreachable block @ {block_start:#x}")
            }
            Self::TransitivelDead { block_start } => {
                write!(f, "transitively dead from block @ {block_start:#x}")
            }
            Self::ObfuscatorNop => write!(f, "obfuscator NOP"),
        }
    }
}

// ── BasicBlock ────────────────────────────────────────────────────────────────

/// A basic block in the dead-code analysis.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Start address (first instruction).
    pub start: u64,
    /// Instructions: `(address, size_bytes, raw_bytes)`.
    pub instructions: Vec<(u64, u8, Vec<u8>)>,
    /// Successor block addresses (up to 2 for conditional branches).
    pub successors: Vec<u64>,
}

impl BasicBlock {
    /// Create a new block.
    #[must_use]
    pub const fn new(start: u64) -> Self {
        Self {
            start,
            instructions: Vec::new(),
            successors: Vec::new(),
        }
    }

    /// Add an instruction.
    pub fn push_insn(&mut self, address: u64, size: u8, bytes: Vec<u8>) {
        self.instructions.push((address, size, bytes));
    }

    /// Add a successor.
    pub fn add_successor(&mut self, target: u64) {
        if !self.successors.contains(&target) {
            self.successors.push(target);
        }
    }

    /// Total byte span of this block.
    #[must_use]
    pub fn byte_span(&self) -> u64 {
        self.instructions
            .iter()
            .map(|(_, sz, _)| u64::from(*sz))
            .sum()
    }

    /// Last address in the block.
    #[must_use]
    pub fn last_address(&self) -> Option<u64> {
        self.instructions.last().map(|(a, _, _)| *a)
    }
}

// ── RemoveResult ──────────────────────────────────────────────────────────────

/// Summary of the junk-code removal pass.
#[derive(Debug, Clone)]
pub struct RemoveResult {
    /// All instructions identified as dead.
    pub dead_instructions: Vec<DeadInstruction>,
    /// Addresses of blocks that were eliminated.
    pub dead_blocks: Vec<u64>,
    /// Total bytes that can be NOP-filled or removed.
    pub dead_bytes: u64,
    /// Number of blocks that are live (not removed).
    pub live_block_count: usize,
}

impl RemoveResult {
    /// Returns `true` when no dead code was found.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.dead_instructions.is_empty()
    }

    /// Addresses of all dead instructions.
    #[must_use]
    pub fn dead_addresses(&self) -> Vec<u64> {
        self.dead_instructions.iter().map(|i| i.address).collect()
    }
}

impl fmt::Display for RemoveResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RemoveResult: {} dead insns in {} blocks ({} bytes), {} live blocks",
            self.dead_instructions.len(),
            self.dead_blocks.len(),
            self.dead_bytes,
            self.live_block_count
        )
    }
}

// ── JunkCodeRemover ───────────────────────────────────────────────────────────

/// Performs dead-code removal on a control-flow graph.
///
/// Supply a set of basic blocks and a set of dead-branch targets (from the
/// conditional simplifier), then call [`JunkCodeRemover::remove`].
pub struct JunkCodeRemover {
    /// All basic blocks keyed by start address.
    blocks: HashMap<u64, BasicBlock>,
    /// Addresses that are known entry points (always live).
    live_entries: HashSet<u64>,
    /// Dead branch targets (seed for the dead set).
    dead_seeds: Vec<u64>,
}

impl JunkCodeRemover {
    /// Create a new remover.
    #[must_use]
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            live_entries: HashSet::new(),
            dead_seeds: Vec::new(),
        }
    }

    /// Register a basic block.
    pub fn add_block(&mut self, block: BasicBlock) {
        self.blocks.insert(block.start, block);
    }

    /// Mark an address as a live entry point (never removed).
    pub fn add_live_entry(&mut self, address: u64) {
        self.live_entries.insert(address);
    }

    /// Add a dead-branch target seed.
    pub fn add_dead_seed(&mut self, address: u64) {
        self.dead_seeds.push(address);
    }

    /// Add multiple dead-branch target seeds.
    pub fn add_dead_seeds(&mut self, addresses: &[u64]) {
        for &a in addresses {
            self.dead_seeds.push(a);
        }
    }

    /// Run the dead-code removal analysis and return a [`RemoveResult`].
    #[must_use]
    pub fn remove(&self) -> RemoveResult {
        // BFS from each dead seed; stop at live-entry blocks.
        let mut dead_set: HashSet<u64> = HashSet::new();
        let mut queue: VecDeque<u64> = self.dead_seeds.iter().copied().collect();

        while let Some(addr) = queue.pop_front() {
            if dead_set.contains(&addr) {
                continue;
            }
            // Do not mark live entries as dead.
            if self.live_entries.contains(&addr) {
                continue;
            }
            // Only mark known blocks.
            if !self.blocks.contains_key(&addr) {
                continue;
            }
            dead_set.insert(addr);
            // Enqueue successors.
            if let Some(block) = self.blocks.get(&addr) {
                for &s in &block.successors {
                    if !dead_set.contains(&s) {
                        queue.push_back(s);
                    }
                }
            }
        }

        // Collect dead instructions.
        let mut dead_instructions: Vec<DeadInstruction> = Vec::new();
        let mut dead_blocks: Vec<u64> = Vec::new();
        let mut dead_bytes: u64 = 0;

        for &block_start in &dead_set {
            if let Some(block) = self.blocks.get(&block_start) {
                dead_blocks.push(block_start);
                for (addr, size, bytes) in &block.instructions {
                    dead_bytes += u64::from(*size);
                    dead_instructions.push(DeadInstruction {
                        address: *addr,
                        size: *size,
                        bytes: bytes.clone(),
                        reason: if self.dead_seeds.contains(&block_start) {
                            DeadReason::UnreachableBlock { block_start }
                        } else {
                            DeadReason::TransitivelDead { block_start }
                        },
                    });
                }
            }
        }

        // Sort for determinism.
        dead_instructions.sort_by_key(|i| i.address);
        dead_blocks.sort_unstable();

        let live_block_count = self.blocks.len().saturating_sub(dead_set.len());

        RemoveResult {
            dead_instructions,
            dead_blocks,
            dead_bytes,
            live_block_count,
        }
    }

    /// Scan a raw byte slice for obfuscator NOPs (multi-byte NOP sequences).
    /// Returns their addresses and sizes.
    #[must_use]
    pub fn scan_obfuscator_nops(
        base: u64,
        bytes: &[u8],
    ) -> Vec<DeadInstruction> {
        let mut result = Vec::new();
        let mut i = 0usize;
        while i < bytes.len() {
            // Single-byte NOP.
            if bytes[i] == 0x90 {
                let start = i;
                while i < bytes.len() && bytes[i] == 0x90 {
                    i += 1;
                }
                let count = i - start;
                if count >= 2 {
                    result.push(DeadInstruction {
                        address: base + start as u64,
                        size: count as u8,
                        bytes: vec![0x90; count],
                        reason: DeadReason::ObfuscatorNop,
                    });
                }
                continue;
            }
            // x86 multi-byte NOP: 0F 1F /0 (2–9 bytes).
            if i + 1 < bytes.len() && bytes[i] == 0x0F && bytes[i + 1] == 0x1F {
                let end = (i + 2).min(bytes.len());
                let size = end - i;
                result.push(DeadInstruction {
                    address: base + i as u64,
                    size: size as u8,
                    bytes: bytes[i..end].to_vec(),
                    reason: DeadReason::ObfuscatorNop,
                });
                i = end;
                continue;
            }
            i += 1;
        }
        result
    }

    /// Total number of basic blocks registered.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
}

impl Default for JunkCodeRemover {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block(start: u64, succs: Vec<u64>) -> BasicBlock {
        let mut b = BasicBlock::new(start);
        b.push_insn(start, 1, vec![0x90]);
        b.push_insn(start + 1, 1, vec![0x90]);
        for s in succs {
            b.add_successor(s);
        }
        b
    }

    // ── remove: simple dead block ─────────────────────────────────────────────

    #[test]
    fn dead_seed_block_removed() {
        let mut r = JunkCodeRemover::new();
        r.add_block(make_block(0x1000, vec![]));
        r.add_block(make_block(0x2000, vec![]));
        r.add_dead_seed(0x1000);
        let res = r.remove();
        assert!(res.dead_blocks.contains(&0x1000));
        assert!(!res.dead_blocks.contains(&0x2000));
    }

    // ── remove: transitive dead ───────────────────────────────────────────────

    #[test]
    fn transitive_dead() {
        let mut r = JunkCodeRemover::new();
        // 0x1000 → 0x1100 → 0x1200 (dead chain)
        r.add_block(make_block(0x1000, vec![0x1100]));
        r.add_block(make_block(0x1100, vec![0x1200]));
        r.add_block(make_block(0x1200, vec![]));
        r.add_dead_seed(0x1000);
        let res = r.remove();
        assert_eq!(res.dead_blocks.len(), 3);
    }

    // ── live_entries prevents removal ─────────────────────────────────────────

    #[test]
    fn live_entry_protected() {
        let mut r = JunkCodeRemover::new();
        r.add_block(make_block(0x1000, vec![0x2000]));
        r.add_block(make_block(0x2000, vec![]));
        r.add_dead_seed(0x1000);
        r.add_live_entry(0x2000);
        let res = r.remove();
        // 0x2000 is live; only 0x1000 should be dead.
        assert!(res.dead_blocks.contains(&0x1000));
        assert!(!res.dead_blocks.contains(&0x2000));
    }

    // ── dead_bytes accounting ─────────────────────────────────────────────────

    #[test]
    fn dead_bytes_counted() {
        let mut r = JunkCodeRemover::new();
        let mut b = BasicBlock::new(0x1000);
        b.push_insn(0x1000, 3, vec![0x90, 0x90, 0x90]);
        b.push_insn(0x1003, 2, vec![0x90, 0x90]);
        r.add_block(b);
        r.add_dead_seed(0x1000);
        let res = r.remove();
        assert_eq!(res.dead_bytes, 5);
    }

    // ── is_clean ──────────────────────────────────────────────────────────────

    #[test]
    fn is_clean_when_no_dead() {
        let r = JunkCodeRemover::new();
        let res = r.remove();
        assert!(res.is_clean());
    }

    // ── scan_obfuscator_nops ──────────────────────────────────────────────────

    #[test]
    fn scan_nop_sled() {
        let bytes = vec![0x90u8; 5];
        let nops = JunkCodeRemover::scan_obfuscator_nops(0x1000, &bytes);
        assert_eq!(nops.len(), 1);
        assert_eq!(nops[0].size, 5);
        assert_eq!(nops[0].reason, DeadReason::ObfuscatorNop);
    }

    #[test]
    fn scan_single_nop_not_flagged() {
        let bytes = vec![0x90u8];
        let nops = JunkCodeRemover::scan_obfuscator_nops(0x1000, &bytes);
        assert!(nops.is_empty());
    }

    #[test]
    fn scan_multibyte_nop() {
        let bytes = vec![0x0F, 0x1F, 0x00];
        let nops = JunkCodeRemover::scan_obfuscator_nops(0x2000, &bytes);
        assert_eq!(nops.len(), 1);
        assert_eq!(nops[0].address, 0x2000);
    }

    // ── dead_addresses ────────────────────────────────────────────────────────

    #[test]
    fn dead_addresses() {
        let mut r = JunkCodeRemover::new();
        r.add_block(make_block(0x1000, vec![]));
        r.add_dead_seed(0x1000);
        let res = r.remove();
        assert!(res.dead_addresses().contains(&0x1000));
    }

    // ── RemoveResult display ──────────────────────────────────────────────────

    #[test]
    fn remove_result_display() {
        let res = RemoveResult {
            dead_instructions: vec![],
            dead_blocks: vec![],
            dead_bytes: 0,
            live_block_count: 5,
        };
        let s = res.to_string();
        assert!(s.contains("RemoveResult"));
        assert!(s.contains("5 live"));
    }

    // ── DeadInstruction display ───────────────────────────────────────────────

    #[test]
    fn dead_instruction_display() {
        let di = DeadInstruction {
            address: 0x1000,
            size: 1,
            bytes: vec![0x90],
            reason: DeadReason::ObfuscatorNop,
        };
        let s = di.to_string();
        assert!(s.contains("0x1000"));
    }

    // ── BasicBlock helpers ────────────────────────────────────────────────────

    #[test]
    fn basic_block_byte_span() {
        let mut b = BasicBlock::new(0x100);
        b.push_insn(0x100, 3, vec![0; 3]);
        b.push_insn(0x103, 2, vec![0; 2]);
        assert_eq!(b.byte_span(), 5);
    }

    #[test]
    fn basic_block_last_address() {
        let b = make_block(0x1000, vec![]);
        assert_eq!(b.last_address(), Some(0x1001));
    }

    // ── add_dead_seeds ────────────────────────────────────────────────────────

    #[test]
    fn add_dead_seeds_batch() {
        let mut r = JunkCodeRemover::new();
        r.add_block(make_block(0xA000, vec![]));
        r.add_block(make_block(0xB000, vec![]));
        r.add_dead_seeds(&[0xA000, 0xB000]);
        let res = r.remove();
        assert_eq!(res.dead_blocks.len(), 2);
    }
}
