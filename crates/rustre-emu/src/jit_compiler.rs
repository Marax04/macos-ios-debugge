//! Simple JIT compiler for emulation in `rustre-emu`.

use crate::EmulatorArch;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

// Re-exported so JIT callers can build error and timing types using the
// same identifiers exposed by the rest of the emulator crate.
pub use crate::EmulatorError;
pub use std::time::Duration;

/// Lossy conversion from usize to f32 (used for ratio statistics).
fn usize_to_f32(v: usize) -> f32 {
    let hi = u16::try_from((v >> 16) & 0xFFFF).unwrap_or(u16::MAX);
    let lo = u16::try_from(v & 0xFFFF).unwrap_or(u16::MAX);
    f32::from(hi).mul_add(65536.0, f32::from(lo))
}

/// Lossy conversion from u64 to f64 (used for ratio statistics).
fn u64_to_f64_local(v: u64) -> f64 {
    let hi = u32::try_from(v >> 32).unwrap_or(u32::MAX);
    let lo = u32::try_from(v & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    f64::from(hi).mul_add(4_294_967_296.0, f64::from(lo))
}

// ── IL instruction (simple IR) ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IlOp {
    Nop,
    Mov { dst: u8, src: u8 },
    MovImm { dst: u8, imm: u64 },
    Add { dst: u8, lhs: u8, rhs: u8 },
    Sub { dst: u8, lhs: u8, rhs: u8 },
    And { dst: u8, lhs: u8, rhs: u8 },
    Or { dst: u8, lhs: u8, rhs: u8 },
    Xor { dst: u8, lhs: u8, rhs: u8 },
    Not { dst: u8, src: u8 },
    Shl { dst: u8, src: u8, shift: u8 },
    Shr { dst: u8, src: u8, shift: u8 },
    Load { dst: u8, addr_reg: u8 },
    Store { addr_reg: u8, src: u8 },
    Jump { offset: i32 },
    JumpCond { cond_reg: u8, offset: i32 },
    Call { target: u64 },
    Ret,
}

impl IlOp {
    #[must_use]
    pub const fn is_control_flow(&self) -> bool {
        matches!(
            self,
            Self::Jump { .. } | Self::JumpCond { .. } | Self::Call { .. } | Self::Ret
        )
    }
}

// ── JitBlock ──────────────────────────────────────────────────────────────────

/// A compiled native code block for a basic block.
#[derive(Debug, Clone)]
pub struct JitBlock {
    pub guest_addr: u64,
    pub native_code: Vec<u8>,
    pub il_instructions: Vec<IlOp>,
    pub compilation_time_us: u64,
    pub execution_count: u64,
    pub last_executed: Option<Instant>,
}

impl JitBlock {
    #[must_use]
    pub const fn new(
        guest_addr: u64,
        native_code: Vec<u8>,
        il: Vec<IlOp>,
        compilation_time_us: u64,
    ) -> Self {
        Self {
            guest_addr,
            native_code,
            il_instructions: il,
            compilation_time_us,
            execution_count: 0,
            last_executed: None,
        }
    }

    pub fn record_execution(&mut self) {
        self.execution_count += 1;
        self.last_executed = Some(Instant::now());
    }

    #[must_use]
    pub const fn native_size(&self) -> usize {
        self.native_code.len()
    }

    #[must_use]
    pub const fn il_count(&self) -> usize {
        self.il_instructions.len()
    }

    #[must_use]
    pub fn code_density(&self) -> f32 {
        if self.il_count() == 0 {
            return 0.0;
        }
        usize_to_f32(self.native_size()) / usize_to_f32(self.il_count())
    }
}

// ── JitCache ──────────────────────────────────────────────────────────────────

/// Maps guest basic-block addresses to compiled `JitBlocks`.
#[derive(Debug, Default)]
pub struct JitCache {
    blocks: HashMap<u64, JitBlock>,
    total_native_bytes: usize,
}

impl JitCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, block: JitBlock) {
        self.total_native_bytes += block.native_size();
        self.blocks.insert(block.guest_addr, block);
    }

    #[must_use]
    pub fn get(&self, addr: u64) -> Option<&JitBlock> {
        self.blocks.get(&addr)
    }

    pub fn get_mut(&mut self, addr: u64) -> Option<&mut JitBlock> {
        self.blocks.get_mut(&addr)
    }

    pub fn invalidate(&mut self, addr: u64) -> bool {
        if let Some(b) = self.blocks.remove(&addr) {
            self.total_native_bytes = self.total_native_bytes.saturating_sub(b.native_size());
            true
        } else {
            false
        }
    }

    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    #[must_use]
    pub const fn total_native_bytes(&self) -> usize {
        self.total_native_bytes
    }

    #[must_use]
    pub fn contains(&self, addr: u64) -> bool {
        self.blocks.contains_key(&addr)
    }

    /// Return the hottest blocks (most executed), sorted descending.
    #[must_use]
    pub fn hot_blocks(&self, top_n: usize) -> Vec<&JitBlock> {
        let mut blocks: Vec<&JitBlock> = self.blocks.values().collect();
        blocks.sort_by(|a, b| b.execution_count.cmp(&a.execution_count));
        blocks.truncate(top_n);
        blocks
    }
}

// ── JitStats ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JitStats {
    pub compilations: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub total_compilation_us: u64,
    pub total_executions: u64,
    pub invalidations: u64,
}

impl JitStats {
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            u64_to_f64_local(self.cache_hits) / u64_to_f64_local(total)
        }
    }

    #[must_use]
    pub fn avg_compilation_us(&self) -> f64 {
        if self.compilations == 0 {
            0.0
        } else {
            u64_to_f64_local(self.total_compilation_us) / u64_to_f64_local(self.compilations)
        }
    }
}

// ── JitCodegen ────────────────────────────────────────────────────────────────

/// Emits x86-64 bytes from IL instructions.
pub struct JitCodegen {
    pub arch: EmulatorArch,
}

impl JitCodegen {
    #[must_use]
    pub const fn new(arch: EmulatorArch) -> Self {
        Self { arch }
    }

    /// Compile a slice of IL instructions to native code bytes.
    #[must_use]
    pub fn compile(&self, il: &[IlOp]) -> Vec<u8> {
        // Average emitted size is ~6 bytes/op; pre-allocate to avoid repeated growth.
        let mut out = Vec::with_capacity(il.len() * 8);
        for op in il {
            Self::emit_op(op, &mut out);
        }
        out
    }

    fn emit_op(op: &IlOp, out: &mut Vec<u8>) {
        match op {
            IlOp::Nop => out.push(0x90),
            IlOp::MovImm { dst, imm } => {
                // REX.W + MOV r64, imm64: 48 B8+rd imm64
                out.push(0x48 | ((*dst & 0x8) >> 3));
                out.push(0xB8 | (*dst & 0x7));
                out.extend_from_slice(&imm.to_le_bytes());
            }
            IlOp::Mov { dst, src } => {
                // MOV r64, r64: 48 89 /r
                let rex = 0x48 | ((*src & 0x8) >> 1) | ((*dst & 0x8) >> 3);
                out.push(rex);
                out.push(0x89);
                out.push(0xC0 | ((*src & 0x7) << 3) | (*dst & 0x7));
            }
            IlOp::Add { dst, lhs, rhs } => {
                // MOV dst, lhs; ADD dst, rhs (simplified)
                out.push(0x48);
                out.push(0x89);
                out.push(0xC0 | ((*lhs & 0x7) << 3) | (*dst & 0x7));
                out.push(0x48);
                out.push(0x01);
                out.push(0xC0 | ((*rhs & 0x7) << 3) | (*dst & 0x7));
            }
            IlOp::Xor { dst, lhs, rhs } => {
                out.push(0x48);
                out.push(0x89);
                out.push(0xC0 | ((*lhs & 0x7) << 3) | (*dst & 0x7));
                out.push(0x48);
                out.push(0x31);
                out.push(0xC0 | ((*rhs & 0x7) << 3) | (*dst & 0x7));
            }
            IlOp::Ret => out.push(0xC3),
            IlOp::Jump { offset } => {
                // Near JMP: E9 rel32
                out.push(0xE9);
                out.extend_from_slice(&offset.to_le_bytes());
            }
            IlOp::JumpCond { cond_reg, offset } => {
                // TEST cond_reg, cond_reg; JNZ offset
                out.push(0x48);
                out.push(0x85);
                out.push(0xC0 | ((*cond_reg & 0x7) * 9));
                out.push(0x0F);
                out.push(0x85);
                out.extend_from_slice(&offset.to_le_bytes());
            }
            _ => {
                /* other ops produce a single NOP placeholder */
                out.push(0x90);
            }
        }
    }
}

// ── DirectDispatch / IndirectDispatch ─────────────────────────────────────────

/// Dispatches directly to a pre-compiled JIT block.
pub struct DirectDispatch {
    pub cache: JitCache,
    pub stats: JitStats,
    codegen: JitCodegen,
}

impl DirectDispatch {
    #[must_use]
    pub fn new(arch: EmulatorArch) -> Self {
        Self {
            cache: JitCache::new(),
            stats: JitStats::default(),
            codegen: JitCodegen::new(arch),
        }
    }

    /// Look up or compile a block for `guest_addr` using `il`.
    ///
    /// # Panics
    /// Panics if the cache entry just inserted cannot be looked up — should not happen in practice.
    pub fn dispatch(&mut self, guest_addr: u64, il: &[IlOp]) -> &JitBlock {
        if self.cache.contains(guest_addr) {
            self.stats.cache_hits += 1;
            self.cache.get_mut(guest_addr).unwrap().record_execution();
            self.stats.total_executions += 1;
            return self.cache.get(guest_addr).unwrap();
        }
        self.stats.cache_misses += 1;
        self.compile_and_cache(guest_addr, il);
        self.cache.get_mut(guest_addr).unwrap().record_execution();
        self.stats.total_executions += 1;
        self.cache.get(guest_addr).unwrap()
    }

    fn compile_and_cache(&mut self, guest_addr: u64, il: &[IlOp]) {
        let start = Instant::now();
        let native = self.codegen.compile(il);
        let us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.stats.compilations += 1;
        self.stats.total_compilation_us += us;
        let block = JitBlock::new(guest_addr, native, il.to_vec(), us);
        self.cache.insert(block);
    }

    pub fn invalidate(&mut self, addr: u64) {
        if self.cache.invalidate(addr) {
            self.stats.invalidations += 1;
        }
    }
}

/// Indirect dispatch via a lookup table (for virtual dispatch).
pub struct IndirectDispatch {
    table: HashMap<u64, u64>,
}

impl Default for IndirectDispatch {
    fn default() -> Self {
        Self::new()
    }
}

impl IndirectDispatch {
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
        }
    }

    pub fn register(&mut self, guest_addr: u64, native_ptr: u64) {
        self.table.insert(guest_addr, native_ptr);
    }

    #[must_use]
    pub fn lookup(&self, guest_addr: u64) -> Option<u64> {
        self.table.get(&guest_addr).copied()
    }

    #[must_use]
    pub fn contains(&self, guest_addr: u64) -> bool {
        self.table.contains_key(&guest_addr)
    }
}

// ── JitCompiler ───────────────────────────────────────────────────────────────

pub struct JitCompiler {
    pub arch: EmulatorArch,
    pub direct: DirectDispatch,
    pub indirect: IndirectDispatch,
}

impl JitCompiler {
    #[must_use]
    pub fn new(arch: EmulatorArch) -> Self {
        Self {
            arch,
            direct: DirectDispatch::new(arch),
            indirect: IndirectDispatch::new(),
        }
    }

    /// Compile `il` for `guest_addr` and return the native code.
    pub fn compile(&mut self, guest_addr: u64, il: &[IlOp]) -> &JitBlock {
        self.direct.dispatch(guest_addr, il)
    }

    #[must_use]
    pub const fn stats(&self) -> &JitStats {
        &self.direct.stats
    }

    #[must_use]
    pub fn cache_hit_rate(&self) -> f64 {
        self.direct.stats.hit_rate()
    }

    #[must_use]
    pub fn block_count(&self) -> usize {
        self.direct.cache.block_count()
    }

    pub fn invalidate(&mut self, addr: u64) {
        self.direct.invalidate(addr);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── IlOp ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_il_op_control_flow() {
        assert!(IlOp::Ret.is_control_flow());
        assert!(IlOp::Jump { offset: 0 }.is_control_flow());
        assert!(!IlOp::Nop.is_control_flow());
        assert!(!IlOp::MovImm { dst: 0, imm: 42 }.is_control_flow());
    }

    // ── JitBlock ─────────────────────────────────────────────────────────────

    #[test]
    fn test_jit_block_creation() {
        let b = JitBlock::new(0x1000, vec![0x90, 0x90], vec![IlOp::Nop], 100);
        assert_eq!(b.guest_addr, 0x1000);
        assert_eq!(b.native_size(), 2);
        assert_eq!(b.il_count(), 1);
    }

    #[test]
    fn test_jit_block_execution_count() {
        let mut b = JitBlock::new(0, vec![], vec![], 0);
        b.record_execution();
        b.record_execution();
        assert_eq!(b.execution_count, 2);
    }

    #[test]
    fn test_jit_block_code_density() {
        let b = JitBlock::new(0, vec![0x90; 10], vec![IlOp::Nop, IlOp::Ret], 0);
        assert!((b.code_density() - 5.0).abs() < 0.001);
    }

    // ── JitCache ──────────────────────────────────────────────────────────────

    #[test]
    fn test_jit_cache_insert_get() {
        let mut cache = JitCache::new();
        let b = JitBlock::new(0x1000, vec![0x90], vec![], 0);
        cache.insert(b);
        assert!(cache.get(0x1000).is_some());
        assert!(cache.get(0x2000).is_none());
    }

    #[test]
    fn test_jit_cache_invalidate() {
        let mut cache = JitCache::new();
        cache.insert(JitBlock::new(0x1000, vec![0x90], vec![], 0));
        assert!(cache.invalidate(0x1000));
        assert!(!cache.contains(0x1000));
        assert!(!cache.invalidate(0x2000));
    }

    #[test]
    fn test_jit_cache_native_bytes_tracked() {
        let mut cache = JitCache::new();
        cache.insert(JitBlock::new(0x1000, vec![0x90; 10], vec![], 0));
        assert_eq!(cache.total_native_bytes(), 10);
        cache.invalidate(0x1000);
        assert_eq!(cache.total_native_bytes(), 0);
    }

    #[test]
    fn test_jit_cache_hot_blocks() {
        let mut cache = JitCache::new();
        let mut b1 = JitBlock::new(0x1000, vec![], vec![], 0);
        let mut b2 = JitBlock::new(0x2000, vec![], vec![], 0);
        b1.execution_count = 100;
        b2.execution_count = 5;
        cache.insert(b1);
        cache.insert(b2);
        let hot = cache.hot_blocks(1);
        assert_eq!(hot[0].guest_addr, 0x1000);
    }

    // ── JitStats ──────────────────────────────────────────────────────────────

    #[test]
    fn test_jit_stats_hit_rate() {
        let stats = JitStats {
            cache_hits: 3,
            cache_misses: 1,
            ..Default::default()
        };
        assert!((stats.hit_rate() - 0.75).abs() < 0.001);
    }

    #[test]
    fn test_jit_stats_avg_compilation() {
        let stats = JitStats {
            compilations: 2,
            total_compilation_us: 100,
            ..Default::default()
        };
        assert!((stats.avg_compilation_us() - 50.0).abs() < f64::EPSILON);
    }

    // ── JitCodegen ────────────────────────────────────────────────────────────

    #[test]
    fn test_codegen_nop() {
        let cg = JitCodegen::new(EmulatorArch::X86_64);
        let code = cg.compile(&[IlOp::Nop]);
        assert_eq!(code, vec![0x90]);
    }

    #[test]
    fn test_codegen_ret() {
        let cg = JitCodegen::new(EmulatorArch::X86_64);
        let code = cg.compile(&[IlOp::Ret]);
        assert_eq!(code, vec![0xC3]);
    }

    #[test]
    fn test_codegen_mov_imm() {
        let cg = JitCodegen::new(EmulatorArch::X86_64);
        let code = cg.compile(&[IlOp::MovImm { dst: 0, imm: 42 }]);
        assert!(!code.is_empty());
        assert_eq!(code[0] & 0xF8, 0x48); // REX prefix
    }

    #[test]
    fn test_codegen_jump() {
        let cg = JitCodegen::new(EmulatorArch::X86_64);
        let code = cg.compile(&[IlOp::Jump { offset: 10 }]);
        assert_eq!(code[0], 0xE9); // JMP near
        assert_eq!(i32::from_le_bytes(code[1..5].try_into().unwrap()), 10);
    }

    #[test]
    fn test_codegen_empty() {
        let cg = JitCodegen::new(EmulatorArch::X86_64);
        let code = cg.compile(&[]);
        assert!(code.is_empty());
    }

    // ── DirectDispatch ────────────────────────────────────────────────────────

    #[test]
    fn test_direct_dispatch_compile_and_cache() {
        let mut dd = DirectDispatch::new(EmulatorArch::X86_64);
        let il = vec![IlOp::Nop, IlOp::Ret];
        dd.dispatch(0x1000, &il);
        assert_eq!(dd.stats.compilations, 1);
        assert_eq!(dd.stats.cache_misses, 1);
        assert!(dd.cache.contains(0x1000));
    }

    #[test]
    fn test_direct_dispatch_cache_hit() {
        let mut dd = DirectDispatch::new(EmulatorArch::X86_64);
        let il = vec![IlOp::Nop];
        dd.dispatch(0x1000, &il);
        dd.dispatch(0x1000, &il); // second call should be a cache hit
        assert_eq!(dd.stats.cache_hits, 1);
    }

    #[test]
    fn test_direct_dispatch_invalidate() {
        let mut dd = DirectDispatch::new(EmulatorArch::X86_64);
        dd.dispatch(0x1000, &[IlOp::Nop]);
        dd.invalidate(0x1000);
        assert_eq!(dd.stats.invalidations, 1);
        assert!(!dd.cache.contains(0x1000));
    }

    // ── IndirectDispatch ──────────────────────────────────────────────────────

    #[test]
    fn test_indirect_dispatch_register_lookup() {
        let mut id = IndirectDispatch::new();
        id.register(0x1000, 0xDEAD_BEEF);
        assert_eq!(id.lookup(0x1000), Some(0xDEAD_BEEF));
        assert_eq!(id.lookup(0x2000), None);
    }

    #[test]
    fn test_indirect_dispatch_contains() {
        let mut id = IndirectDispatch::new();
        id.register(0x1000, 0);
        assert!(id.contains(0x1000));
        assert!(!id.contains(0x2000));
    }

    // ── JitCompiler ───────────────────────────────────────────────────────────

    #[test]
    fn test_jit_compiler_compile() {
        let mut jit = JitCompiler::new(EmulatorArch::X86_64);
        jit.compile(0x1000, &[IlOp::Nop, IlOp::Ret]);
        assert_eq!(jit.block_count(), 1);
    }

    #[test]
    fn test_jit_compiler_hit_rate() {
        let mut jit = JitCompiler::new(EmulatorArch::X86_64);
        jit.compile(0x1000, &[IlOp::Ret]);
        jit.compile(0x1000, &[IlOp::Ret]); // cache hit
        assert!(jit.cache_hit_rate() > 0.0);
    }

    #[test]
    fn test_jit_compiler_invalidate() {
        let mut jit = JitCompiler::new(EmulatorArch::X86_64);
        jit.compile(0x1000, &[IlOp::Nop]);
        jit.invalidate(0x1000);
        assert_eq!(jit.block_count(), 0);
    }

    #[test]
    fn test_jit_compiler_stats() {
        let mut jit = JitCompiler::new(EmulatorArch::X86_64);
        jit.compile(0x1000, &[IlOp::Ret]);
        let stats = jit.stats();
        assert_eq!(stats.compilations, 1);
    }
}
