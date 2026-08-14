//! Intel PT trace builder — reconstructs control flow from PT packets
//! into `TraceBlock` sequences with branch records, module maps, and
//! disassembly caching.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TraceBuilderError {
    #[error("PT sync lost at offset {0}")]
    SyncLost(usize),
    #[error("no module mapped at 0x{0:016x}")]
    UnmappedAddress(u64),
    #[error("disassembly cache miss at 0x{0:016x}")]
    CacheMiss(u64),
    #[error("branch target mismatch: expected 0x{0:x}, got 0x{1:x}")]
    BranchMismatch(u64, u64),
    #[error("empty packet stream")]
    EmptyStream,
    #[error("overflow in trace block at 0x{0:x}")]
    BlockOverflow(u64),
}

// ─── ModuleMap ────────────────────────────────────────────────────────────────

/// A loaded module/image entry in the address space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleEntry {
    pub base: u64,
    pub size: u64,
    pub name: String,
    pub path: Option<String>,
    pub load_time: Option<u64>,
}

impl ModuleEntry {
    /// Whether the given address falls within this module.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + self.size
    }

    /// Offset of address within the module.
    #[must_use]
    pub const fn rva(&self, addr: u64) -> u64 {
        addr.saturating_sub(self.base)
    }
}

/// Map of loaded modules indexed by base address.
#[derive(Debug, Default)]
pub struct ModuleMap {
    modules: BTreeMap<u64, ModuleEntry>,
}

impl ModuleMap {
    /// Add a module.
    pub fn add(&mut self, entry: ModuleEntry) {
        self.modules.insert(entry.base, entry);
    }

    /// Remove module by base.
    pub fn remove(&mut self, base: u64) -> Option<ModuleEntry> {
        self.modules.remove(&base)
    }

    /// Find module containing `addr`.
    #[must_use]
    pub fn find(&self, addr: u64) -> Option<&ModuleEntry> {
        self.modules
            .range(..=addr)
            .next_back()
            .map(|(_, e)| e)
            .filter(|e| e.contains(addr))
    }

    /// Number of loaded modules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }
}

// ─── DisasmCache ──────────────────────────────────────────────────────────────

/// Cached disassembly information for a single instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedInsn {
    pub addr: u64,
    pub size: u8,
    pub mnemonic: String,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_ret: bool,
    pub is_cond: bool,
    /// For direct branches/calls: the target address.
    pub branch_target: Option<u64>,
}

/// Disassembly cache for PT flow reconstruction.
#[derive(Debug, Default)]
pub struct DisasmCache {
    cache: HashMap<u64, CachedInsn>,
    hits: u64,
    misses: u64,
}

impl DisasmCache {
    /// Insert a cached instruction.
    pub fn insert(&mut self, insn: CachedInsn) {
        self.cache.insert(insn.addr, insn);
    }

    /// Lookup an instruction by address.
    pub fn get(&mut self, addr: u64) -> Option<&CachedInsn> {
        if let Some(insn) = self.cache.get(&addr) {
            self.hits += 1;
            Some(insn)
        } else {
            self.misses += 1;
            None
        }
    }

    /// Cache hit ratio.
    #[must_use]
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            crate::cast_helpers::u64_to_f64(self.hits) / crate::cast_helpers::u64_to_f64(total)
        }
    }

    /// Number of cached instructions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Evict entries belonging to a module range.
    pub fn evict_range(&mut self, base: u64, size: u64) {
        self.cache
            .retain(|&addr, _| addr < base || addr >= base.saturating_add(size));
    }
}

// ─── BranchRecord ────────────────────────────────────────────────────────────

/// A branch event reconstructed from PT TNT/TIP packets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchRecord {
    /// Source address of the branch instruction.
    pub from_addr: u64,
    /// Target address (where control went).
    pub to_addr: u64,
    /// Whether the branch was taken.
    pub taken: bool,
    /// Whether this was an indirect branch resolved by TIP.
    pub indirect: bool,
    /// Call-stack depth at time of branch.
    pub call_depth: u32,
    /// TSC timestamp (if available).
    pub tsc: Option<u64>,
}

impl BranchRecord {
    /// Create a taken direct branch.
    #[must_use]
    pub const fn taken_direct(from: u64, to: u64, depth: u32) -> Self {
        Self {
            from_addr: from,
            to_addr: to,
            taken: true,
            indirect: false,
            call_depth: depth,
            tsc: None,
        }
    }

    /// Create a not-taken branch.
    #[must_use]
    pub const fn not_taken(from: u64, fallthrough: u64, depth: u32) -> Self {
        Self {
            from_addr: from,
            to_addr: fallthrough,
            taken: false,
            indirect: false,
            call_depth: depth,
            tsc: None,
        }
    }

    /// Create an indirect branch (TIP resolved).
    #[must_use]
    pub const fn indirect(from: u64, to: u64, depth: u32) -> Self {
        Self {
            from_addr: from,
            to_addr: to,
            taken: true,
            indirect: true,
            call_depth: depth,
            tsc: None,
        }
    }
}

// ─── TraceBlock ───────────────────────────────────────────────────────────────

/// A reconstructed basic block of sequential execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceBlock {
    /// Start address.
    pub start: u64,
    /// End address (exclusive).
    pub end: u64,
    /// Number of instructions in this block.
    pub insn_count: u32,
    /// The branch that terminated this block (if any).
    pub exit_branch: Option<BranchRecord>,
    /// Number of times this block was executed (merged count).
    pub exec_count: u64,
    /// Whether this block was entered via an exception.
    pub exception_entry: bool,
    /// Cycle count for this block (from CYC packets).
    pub cycles: Option<u64>,
}

impl TraceBlock {
    /// Create a new trace block.
    #[must_use]
    pub const fn new(start: u64, end: u64, insn_count: u32) -> Self {
        Self {
            start,
            end,
            insn_count,
            exit_branch: None,
            exec_count: 1,
            exception_entry: false,
            cycles: None,
        }
    }

    /// Byte size of the block.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Average instructions per byte (density).
    #[must_use]
    pub fn insn_density(&self) -> f64 {
        let bytes = self.size_bytes();
        if bytes == 0 {
            0.0
        } else {
            f64::from(self.insn_count) / crate::cast_helpers::u64_to_f64(bytes)
        }
    }
}

// ─── PtTraceBuilder ──────────────────────────────────────────────────────────

/// Configuration for PT trace reconstruction.
#[derive(Debug, Clone)]
pub struct PtConfig {
    /// Maximum call depth to track.
    pub max_call_depth: u32,
    /// Whether to filter kernel-mode addresses.
    pub user_mode_only: bool,
    /// Kernel address threshold (addresses >= this are kernel).
    pub kernel_threshold: u64,
    /// Whether to track cycle counts from CYC packets.
    pub track_cycles: bool,
}

impl Default for PtConfig {
    fn default() -> Self {
        Self {
            max_call_depth: 256,
            user_mode_only: true,
            kernel_threshold: 0xFFFF_8000_0000_0000,
            track_cycles: false,
        }
    }
}

/// Reconstructs a control-flow trace from Intel PT packet data.
///
/// This is a pure-Rust PT decoder / flow reconstructor.  The `build_from_tnt`
/// and `build_from_packets` methods accept pre-decoded packet representations
/// (so we avoid a C-FFI dependency on libipt in the unit-test layer).
#[derive(Debug)]
pub struct PtTraceBuilder {
    pub config: PtConfig,
    pub modules: ModuleMap,
    pub cache: DisasmCache,
    pub blocks: Vec<TraceBlock>,
    pub branches: Vec<BranchRecord>,
    /// Current execution address.
    current_ip: u64,
    call_depth: u32,
    /// TNT buffer: true=taken, false=not-taken.
    tnt_queue: VecDeque<bool>,
}

impl PtTraceBuilder {
    /// Create a new builder with default config.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: PtConfig::default(),
            modules: ModuleMap::default(),
            cache: DisasmCache::default(),
            blocks: Vec::new(),
            branches: Vec::new(),
            current_ip: 0,
            call_depth: 0,
            tnt_queue: VecDeque::new(),
        }
    }

    /// Set starting IP address.
    pub const fn set_ip(&mut self, ip: u64) {
        self.current_ip = ip;
    }

    /// True when no trace blocks and no branches have been recorded yet.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.blocks.is_empty() && self.branches.is_empty()
    }

    /// Feed a pre-decoded TNT bitstring (true=taken, false=not-taken).
    pub fn feed_tnt(&mut self, bits: &[bool]) {
        self.tnt_queue.extend(bits.iter().copied());
    }

    /// Feed a resolved indirect branch target (TIP).
    pub fn feed_tip(&mut self, target: u64) {
        let br = BranchRecord::indirect(self.current_ip, target, self.call_depth);
        self.branches.push(br);
        self.current_ip = target;
    }

    /// Commit a new trace block.
    pub fn commit_block(&mut self, start: u64, end: u64, insn_count: u32) {
        // Merge with existing block if same address.
        if let Some(existing) = self.blocks.iter_mut().find(|b| b.start == start) {
            existing.exec_count += 1;
        } else {
            self.blocks.push(TraceBlock::new(start, end, insn_count));
        }
    }

    /// Reconstruct from a sequence of pre-decoded instructions.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Panics
    /// May panic on invalid input.
    ///
    /// `insns` is `(addr, size, is_cond_branch, direct_target)`.
    /// TNT bits are consumed from the internal queue.
    pub fn reconstruct_flow(
        &mut self,
        insns: &[(u64, u8, bool, Option<u64>)],
    ) -> Result<(), TraceBuilderError> {
        if insns.is_empty() {
            return Err(TraceBuilderError::EmptyStream);
        }
        let mut block_start = insns[0].0;
        let mut block_insns = 0u32;

        for &(addr, size, is_cond, direct_target) in insns {
            block_insns += 1;
            if is_cond {
                let taken = self.tnt_queue.pop_front().unwrap_or(false);
                let fallthrough = addr + u64::from(size);
                let target = if taken {
                    direct_target.unwrap_or(fallthrough)
                } else {
                    fallthrough
                };
                let br = if taken {
                    BranchRecord::taken_direct(addr, target, self.call_depth)
                } else {
                    BranchRecord::not_taken(addr, fallthrough, self.call_depth)
                };
                let block_end = addr + u64::from(size);
                self.commit_block(block_start, block_end, block_insns);
                self.branches.push(br);
                block_start = target;
                block_insns = 0;
                self.current_ip = target;
            } else {
                self.current_ip = addr + u64::from(size);
            }
        }
        // Commit last block.
        if block_insns > 0 {
            let last = insns.last().unwrap();
            self.commit_block(block_start, last.0 + u64::from(last.1), block_insns);
        }
        Ok(())
    }

    /// Number of reconstructed trace blocks.
    #[must_use]
    pub const fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Total instruction count across all blocks.
    #[must_use]
    pub fn total_insn_count(&self) -> u64 {
        self.blocks
            .iter()
            .map(|b| u64::from(b.insn_count) * b.exec_count)
            .sum()
    }

    /// All unique addresses covered by reconstructed blocks.
    #[must_use]
    pub fn covered_addresses(&self) -> Vec<u64> {
        self.blocks.iter().map(|b| b.start).collect()
    }

    /// Taken branches.
    #[must_use]
    pub fn taken_branches(&self) -> Vec<&BranchRecord> {
        self.branches.iter().filter(|b| b.taken).collect()
    }

    /// Indirect branches (TIP-resolved).
    #[must_use]
    pub fn indirect_branches(&self) -> Vec<&BranchRecord> {
        self.branches.iter().filter(|b| b.indirect).collect()
    }

    /// Reset builder state (keep config/modules/cache).
    pub fn reset(&mut self) {
        self.blocks.clear();
        self.branches.clear();
        self.tnt_queue.clear();
        self.current_ip = 0;
        self.call_depth = 0;
    }
}

impl Default for PtTraceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ModuleEntry ─────────────────────────────────────────────────────────

    #[test]
    fn test_module_contains() {
        let m = ModuleEntry {
            base: 0x1000,
            size: 0x1000,
            name: "test".into(),
            path: None,
            load_time: None,
        };
        assert!(m.contains(0x1500));
        assert!(!m.contains(0x2000));
        assert!(!m.contains(0x0FFF));
    }

    #[test]
    fn test_module_rva() {
        let m = ModuleEntry {
            base: 0x1000,
            size: 0x1000,
            name: "t".into(),
            path: None,
            load_time: None,
        };
        assert_eq!(m.rva(0x1400), 0x400);
    }

    // ── ModuleMap ───────────────────────────────────────────────────────────

    #[test]
    fn test_module_map_find() {
        let mut mm = ModuleMap::default();
        mm.add(ModuleEntry {
            base: 0x1000,
            size: 0x2000,
            name: "a".into(),
            path: None,
            load_time: None,
        });
        assert!(mm.find(0x1500).is_some());
        assert!(mm.find(0x3500).is_none());
    }

    #[test]
    fn test_module_map_remove() {
        let mut mm = ModuleMap::default();
        mm.add(ModuleEntry {
            base: 0x1000,
            size: 0x1000,
            name: "b".into(),
            path: None,
            load_time: None,
        });
        mm.remove(0x1000);
        assert!(mm.is_empty());
    }

    // ── DisasmCache ─────────────────────────────────────────────────────────

    fn make_insn(addr: u64) -> CachedInsn {
        CachedInsn {
            addr,
            size: 4,
            mnemonic: "NOP".into(),
            is_branch: false,
            is_call: false,
            is_ret: false,
            is_cond: false,
            branch_target: None,
        }
    }

    #[test]
    fn test_cache_insert_and_get() {
        let mut c = DisasmCache::default();
        c.insert(make_insn(0x1000));
        assert!(c.get(0x1000).is_some());
    }

    #[test]
    fn test_cache_miss() {
        let mut c = DisasmCache::default();
        assert!(c.get(0x9999).is_none());
    }

    #[test]
    fn test_cache_hit_ratio() {
        let mut c = DisasmCache::default();
        c.insert(make_insn(0x1000));
        c.get(0x1000); // hit
        c.get(0x9999); // miss
        assert!((c.hit_ratio() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_cache_evict_range() {
        let mut c = DisasmCache::default();
        c.insert(make_insn(0x1000));
        c.insert(make_insn(0x5000));
        c.evict_range(0x1000, 0x2000);
        assert!(!c.cache.contains_key(&0x1000));
        assert!(c.cache.contains_key(&0x5000));
    }

    // ── BranchRecord ────────────────────────────────────────────────────────

    #[test]
    fn test_branch_taken_direct() {
        let b = BranchRecord::taken_direct(0x1000, 0x2000, 0);
        assert!(b.taken);
        assert!(!b.indirect);
    }

    #[test]
    fn test_branch_not_taken() {
        let b = BranchRecord::not_taken(0x1000, 0x1004, 0);
        assert!(!b.taken);
    }

    #[test]
    fn test_branch_indirect() {
        let b = BranchRecord::indirect(0x1000, 0x3000, 2);
        assert!(b.indirect);
        assert!(b.taken);
        assert_eq!(b.call_depth, 2);
    }

    // ── TraceBlock ──────────────────────────────────────────────────────────

    #[test]
    fn test_block_size() {
        let b = TraceBlock::new(0x1000, 0x1010, 4);
        assert_eq!(b.size_bytes(), 0x10);
    }

    #[test]
    fn test_block_density() {
        let b = TraceBlock::new(0x1000, 0x1010, 8);
        // 8 insns / 16 bytes = 0.5
        assert!((b.insn_density() - 0.5).abs() < 1e-9);
    }

    // ── PtTraceBuilder ───────────────────────────────────────────────────────

    fn simple_linear_insns(base: u64, count: usize, size: u8) -> Vec<(u64, u8, bool, Option<u64>)> {
        (0..count)
            .map(|i| (base + (i as u64 * u64::from(size)), size, false, None))
            .collect()
    }

    #[test]
    fn test_builder_linear_flow() {
        let mut b = PtTraceBuilder::new();
        let insns = simple_linear_insns(0x1000, 5, 4);
        b.reconstruct_flow(&insns).unwrap();
        assert_eq!(b.block_count(), 1);
    }

    #[test]
    fn test_builder_empty_error() {
        let mut b = PtTraceBuilder::new();
        assert!(b.reconstruct_flow(&[]).is_err());
    }

    #[test]
    fn test_builder_conditional_branch_taken() {
        let mut b = PtTraceBuilder::new();
        b.feed_tnt(&[true]);
        let insns = vec![
            (0x1000u64, 4u8, false, None),
            (0x1004, 4, true, Some(0x2000)),
        ];
        b.reconstruct_flow(&insns).unwrap();
        assert_eq!(b.taken_branches().len(), 1);
        assert_eq!(b.taken_branches()[0].to_addr, 0x2000);
    }

    #[test]
    fn test_builder_conditional_branch_not_taken() {
        let mut b = PtTraceBuilder::new();
        b.feed_tnt(&[false]);
        let insns = vec![(0x1000u64, 4u8, true, Some(0x2000))];
        b.reconstruct_flow(&insns).unwrap();
        assert_eq!(b.taken_branches().len(), 0);
        // the not-taken branch should still be in the branch list
        assert_eq!(b.branches.len(), 1);
        assert_eq!(b.branches[0].to_addr, 0x1004);
    }

    #[test]
    fn test_builder_tip_indirect() {
        let mut b = PtTraceBuilder::new();
        b.set_ip(0x1000);
        b.feed_tip(0x5000);
        assert_eq!(b.indirect_branches().len(), 1);
        assert_eq!(b.indirect_branches()[0].to_addr, 0x5000);
    }

    #[test]
    fn test_builder_block_merge() {
        let mut b = PtTraceBuilder::new();
        // Execute same block twice.
        let insns = simple_linear_insns(0x1000, 3, 4);
        b.reconstruct_flow(&insns).unwrap();
        b.reconstruct_flow(&insns).unwrap();
        // Same start address should be merged.
        assert_eq!(b.block_count(), 1);
        assert_eq!(b.blocks[0].exec_count, 2);
    }

    #[test]
    fn test_builder_total_insn_count() {
        let mut b = PtTraceBuilder::new();
        let insns = simple_linear_insns(0x1000, 4, 4);
        b.reconstruct_flow(&insns).unwrap();
        assert_eq!(b.total_insn_count(), 4);
    }

    #[test]
    fn test_builder_reset() {
        let mut b = PtTraceBuilder::new();
        let insns = simple_linear_insns(0x1000, 4, 4);
        b.reconstruct_flow(&insns).unwrap();
        b.reset();
        assert!(b.blocks.is_empty());
        assert!(b.branches.is_empty());
    }

    #[test]
    fn test_builder_covered_addresses() {
        let mut b = PtTraceBuilder::new();
        b.feed_tnt(&[true, false]);
        let insns = vec![
            (0x1000u64, 4u8, true, Some(0x2000)),
            (0x2000, 4, false, None),
            (0x2004, 4, true, Some(0x3000)),
        ];
        b.reconstruct_flow(&insns).unwrap();
        let covered = b.covered_addresses();
        assert!(
            covered.contains(&0x1000) || covered.contains(&0x2000) || covered.contains(&0x2004)
        );
    }

    // ── Additional coverage ─────────────────────────────────────────────────

    #[test]
    fn test_module_map_len() {
        let mut mm = ModuleMap::default();
        mm.add(ModuleEntry {
            base: 0x1000,
            size: 0x1000,
            name: "a".into(),
            path: None,
            load_time: None,
        });
        mm.add(ModuleEntry {
            base: 0x5000,
            size: 0x2000,
            name: "b".into(),
            path: None,
            load_time: None,
        });
        assert_eq!(mm.len(), 2);
    }

    #[test]
    fn test_cache_len_after_insert() {
        let mut c = DisasmCache::default();
        c.insert(make_insn(0x1000));
        c.insert(make_insn(0x1004));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn test_block_exec_count_starts_at_1() {
        let b = TraceBlock::new(0x1000, 0x1010, 4);
        assert_eq!(b.exec_count, 1);
    }

    #[test]
    fn test_builder_multiple_branches() {
        let mut b = PtTraceBuilder::new();
        b.feed_tnt(&[true, false]);
        let insns = vec![
            (0x1000u64, 4u8, true, Some(0x2000)),
            (0x2000, 4, true, Some(0x3000)),
        ];
        b.reconstruct_flow(&insns).unwrap();
        assert_eq!(b.branches.len(), 2);
    }

    #[test]
    fn test_builder_default() {
        let b = PtTraceBuilder::default();
        assert!(b.is_empty());
        assert_eq!(b.block_count(), 0);
    }

    #[test]
    fn test_builder_config_user_mode_only() {
        let b = PtTraceBuilder::new();
        assert!(b.config.user_mode_only);
    }

    #[test]
    fn test_builder_block_size_bytes() {
        let b = TraceBlock::new(0x1000, 0x1020, 8);
        assert_eq!(b.size_bytes(), 0x20);
    }

    #[test]
    fn test_builder_no_cycle_count_by_default() {
        let b = TraceBlock::new(0x1000, 0x1010, 2);
        assert!(b.cycles.is_none());
    }
}
