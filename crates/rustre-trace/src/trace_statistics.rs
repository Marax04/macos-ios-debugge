// trace_statistics.rs — Execution trace statistical analysis
//
// Computes:
//   - Instruction mix histogram (by instruction mnemonic prefix / opcode category)
//   - Most-executed basic blocks and hot functions
//   - Memory access patterns (stride, locality, read/write ratio)
//   - Syscall frequency table
//   - Branch prediction data (taken/not-taken rates)
//   - Loop detection via back-edge heuristic
//   - Coverage metrics
//   - Call depth histogram
//   - Sequential run-length encoding of PCs

use std::collections::{HashMap, BTreeMap};
use std::fmt;

use super::trace_format::{TraceRecord, TraceEventKind};

// ── Instruction category ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InsnCategory {
    Alu,         // arithmetic / logic (add, sub, and, or, xor, ...)
    Mov,         // data movement (mov, lea, push, pop, ...)
    Control,     // branches (jmp, jcc, call, ret, ...)
    FloatingPt,  // FP / SIMD
    Memory,      // load/store (not captured in insn bytes, inferred from mem events)
    System,      // syscall, sysret, int, in, out, ...
    String,      // rep movs, rep scas, ...
    Crypto,      // aes*, sha*, ...
    Other,
    Unknown,
}

impl InsnCategory {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Alu => "ALU", Self::Mov => "MOV", Self::Control => "Control",
            Self::FloatingPt => "Float/SIMD", Self::Memory => "Memory",
            Self::System => "System", Self::String => "String",
            Self::Crypto => "Crypto", Self::Other => "Other", Self::Unknown => "Unknown",
        }
    }

    /// Classify a raw x86 opcode byte (very coarse, first byte only)
    pub fn from_x86_opcode(opcode: u8) -> Self {
        match opcode {
            // Data movement
            0x88..=0x8C | 0x8E | 0x8F | 0xA0..=0xA5 | 0xB0..=0xBF | 0x50..=0x5F
            | 0xC6 | 0xC7 => Self::Mov,
            // ALU
            0x00..=0x3D | 0x40..=0x47 | 0x48..=0x4F
            | 0xF6 | 0xF7 | 0xD0..=0xD3 => Self::Alu,
            // Control flow
            0x70..=0x7F | 0xE0..=0xE3 | 0xEB | 0xE8 | 0xE9 | 0xFF | 0xC3 | 0xCB
            | 0xC2 | 0xCA => Self::Control,
            // String
            0xA6..=0xAF | 0xF2 | 0xF3 => Self::String,
            // System
            0xCC | 0xCD | 0xCE | 0xCF | 0xE4..=0xE7 | 0xEC..=0xEF | 0xF4 | 0xFA | 0xFB => Self::System,
            // Float (escape to x87)
            0xD8..=0xDF => Self::FloatingPt,
            _ => Self::Other,
        }
    }
}

// ── Instruction mix ───────────────────────────────────────────────────────────

/// Histogram of instruction categories
#[derive(Debug, Default, Clone)]
pub struct InstructionMix {
    pub counts: HashMap<InsnCategory, u64>,
    pub total: u64,
}

impl InstructionMix {
    pub fn record(&mut self, cat: InsnCategory) {
        *self.counts.entry(cat).or_insert(0) += 1;
        self.total += 1;
    }

    pub fn fraction(&self, cat: InsnCategory) -> f64 {
        if self.total == 0 { return 0.0; }
        *self.counts.get(&cat).unwrap_or(&0) as f64 / self.total as f64
    }

    pub fn sorted_by_count(&self) -> Vec<(InsnCategory, u64)> {
        let mut v: Vec<_> = self.counts.iter().map(|(&k, &v)| (k, v)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }

    pub fn merge(&mut self, other: &InstructionMix) {
        for (&cat, &cnt) in &other.counts {
            *self.counts.entry(cat).or_insert(0) += cnt;
        }
        self.total += other.total;
    }
}

impl fmt::Display for InstructionMix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Instruction Mix ({} total)", self.total)?;
        for (cat, cnt) in self.sorted_by_count() {
            writeln!(f, "  {:15} {:8}  ({:.1}%)", cat.name(), cnt, self.fraction(cat) * 100.0)?;
        }
        Ok(())
    }
}

// ── Basic block hit counter ────────────────────────────────────────────────────

/// Tracks how many times each basic block (start address) was executed
#[derive(Debug, Default, Clone)]
pub struct BasicBlockHits {
    pub hits: HashMap<u64, u64>,
    pub total_executions: u64,
}

impl BasicBlockHits {
    pub fn record(&mut self, addr: u64) {
        *self.hits.entry(addr).or_insert(0) += 1;
        self.total_executions += 1;
    }

    /// Top N most-executed basic blocks, sorted descending
    pub fn top_n(&self, n: usize) -> Vec<(u64, u64)> {
        let mut v: Vec<_> = self.hits.iter().map(|(&a, &h)| (a, h)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    pub fn unique_blocks(&self) -> usize { self.hits.len() }

    /// Fraction of total executions in the top N blocks
    pub fn top_n_coverage(&self, n: usize) -> f64 {
        if self.total_executions == 0 { return 0.0; }
        let top: u64 = self.top_n(n).iter().map(|(_, h)| h).sum();
        top as f64 / self.total_executions as f64
    }
}

// ── Memory access pattern analysis ────────────────────────────────────────────

/// Stride histogram (difference between consecutive memory addresses of the same kind)
#[derive(Debug, Default, Clone)]
pub struct StrideHistogram {
    pub strides: BTreeMap<i64, u64>,
    last_read_addr: Option<u64>,
    last_write_addr: Option<u64>,
}

impl StrideHistogram {
    pub fn record_read(&mut self, addr: u64) {
        if let Some(prev) = self.last_read_addr {
            let stride = addr as i64 - prev as i64;
            // Clamp to [-4096, 4096] for practical histogram
            let clamped = stride.max(-4096).min(4096);
            *self.strides.entry(clamped).or_insert(0) += 1;
        }
        self.last_read_addr = Some(addr);
    }

    pub fn record_write(&mut self, addr: u64) {
        if let Some(prev) = self.last_write_addr {
            let stride = addr as i64 - prev as i64;
            let clamped = stride.max(-4096).min(4096);
            *self.strides.entry(clamped).or_insert(0) += 1;
        }
        self.last_write_addr = Some(addr);
    }

    /// Most common stride value
    pub fn dominant_stride(&self) -> Option<i64> {
        self.strides.iter().max_by_key(|&(_, &c)| c).map(|(&s, _)| s)
    }

    /// Fraction of accesses that are sequential (stride == element_size)
    pub fn sequential_fraction(&self, element_size: i64) -> f64 {
        let total: u64 = self.strides.values().sum();
        if total == 0 { return 0.0; }
        let seq = *self.strides.get(&element_size).unwrap_or(&0);
        seq as f64 / total as f64
    }
}

/// Memory access statistics
#[derive(Debug, Default, Clone)]
pub struct MemoryStats {
    pub read_count: u64,
    pub write_count: u64,
    pub unique_read_addrs: HashMap<u64, u64>,
    pub unique_write_addrs: HashMap<u64, u64>,
    pub stride: StrideHistogram,
    /// Cache line (64-byte) set hit rates
    pub cache_line_hits: HashMap<u64, u64>,
}

impl MemoryStats {
    pub fn record_read(&mut self, addr: u64, _size: u8) {
        self.read_count += 1;
        *self.unique_read_addrs.entry(addr).or_insert(0) += 1;
        self.stride.record_read(addr);
        let cl = addr >> 6; // 64-byte cache lines
        *self.cache_line_hits.entry(cl).or_insert(0) += 1;
    }

    pub fn record_write(&mut self, addr: u64, _size: u8) {
        self.write_count += 1;
        *self.unique_write_addrs.entry(addr).or_insert(0) += 1;
        self.stride.record_write(addr);
        let cl = addr >> 6;
        *self.cache_line_hits.entry(cl).or_insert(0) += 1;
    }

    pub fn total_accesses(&self) -> u64 { self.read_count + self.write_count }
    pub fn write_ratio(&self) -> f64 {
        let t = self.total_accesses();
        if t == 0 { 0.0 } else { self.write_count as f64 / t as f64 }
    }
    pub fn unique_addresses(&self) -> usize {
        let mut s = self.unique_read_addrs.len() + self.unique_write_addrs.len();
        // subtract overlap
        for k in self.unique_read_addrs.keys() {
            if self.unique_write_addrs.contains_key(k) { s -= 1; }
        }
        s
    }

    /// Top N most-accessed cache lines
    pub fn hot_cache_lines(&self, n: usize) -> Vec<(u64, u64)> {
        let mut v: Vec<_> = self.cache_line_hits.iter().map(|(&a, &c)| (a, c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }
}

// ── Syscall frequency ─────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct SyscallFrequency {
    pub counts: HashMap<u64, u64>,
    pub total: u64,
}

impl SyscallFrequency {
    pub fn record(&mut self, syscall_nr: u64) {
        *self.counts.entry(syscall_nr).or_insert(0) += 1;
        self.total += 1;
    }

    pub fn top_n(&self, n: usize) -> Vec<(u64, u64)> {
        let mut v: Vec<_> = self.counts.iter().map(|(&k, &v)| (k, v)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    pub fn unique_syscalls(&self) -> usize { self.counts.len() }
}

// ── Branch statistics ─────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct BranchStats {
    /// (from_addr, to_addr) → count
    pub edges: HashMap<(u64, u64), u64>,
    /// Per-address taken/not-taken counters
    pub taken: HashMap<u64, u64>,
    pub not_taken: HashMap<u64, u64>,
    pub total_branches: u64,
    pub back_edges: Vec<(u64, u64)>,
}

impl BranchStats {
    pub fn record_branch(&mut self, from: u64, to: u64, taken: bool) {
        *self.edges.entry((from, to)).or_insert(0) += 1;
        if taken {
            *self.taken.entry(from).or_insert(0) += 1;
        } else {
            *self.not_taken.entry(from).or_insert(0) += 1;
        }
        self.total_branches += 1;
        // Back edge heuristic: target address < source address
        if taken && to < from {
            if !self.back_edges.contains(&(from, to)) {
                self.back_edges.push((from, to));
            }
        }
    }

    pub fn taken_rate(&self, addr: u64) -> f64 {
        let t = *self.taken.get(&addr).unwrap_or(&0);
        let nt = *self.not_taken.get(&addr).unwrap_or(&0);
        let total = t + nt;
        if total == 0 { 0.5 } else { t as f64 / total as f64 }
    }

    pub fn overall_taken_rate(&self) -> f64 {
        let total_taken: u64 = self.taken.values().sum();
        if self.total_branches == 0 { 0.5 } else { total_taken as f64 / self.total_branches as f64 }
    }

    pub fn biased_branches(&self, threshold: f64) -> Vec<(u64, f64)> {
        let mut result = Vec::new();
        let addrs: std::collections::HashSet<u64> = self.taken.keys()
            .chain(self.not_taken.keys()).copied().collect();
        for addr in addrs {
            let rate = self.taken_rate(addr);
            if rate >= threshold || rate <= 1.0 - threshold {
                result.push((addr, rate));
            }
        }
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }

    pub fn likely_loops(&self) -> &[(u64, u64)] { &self.back_edges }
}

// ── Call depth histogram ───────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct CallDepthHistogram {
    pub depths: HashMap<u32, u64>,
    pub max_depth: u32,
    pub total_samples: u64,
}

impl CallDepthHistogram {
    pub fn record(&mut self, depth: u32) {
        *self.depths.entry(depth).or_insert(0) += 1;
        if depth > self.max_depth { self.max_depth = depth; }
        self.total_samples += 1;
    }

    pub fn mean_depth(&self) -> f64 {
        if self.total_samples == 0 { return 0.0; }
        let sum: u64 = self.depths.iter().map(|(&d, &c)| d as u64 * c).sum();
        sum as f64 / self.total_samples as f64
    }

    pub fn percentile_depth(&self, pct: f64) -> u32 {
        if self.total_samples == 0 { return 0; }
        let target = (self.total_samples as f64 * pct / 100.0).ceil() as u64;
        let mut sorted: Vec<(u32, u64)> = self.depths.iter().map(|(&d, &c)| (d, c)).collect();
        sorted.sort_by_key(|(d, _)| *d);
        let mut cumulative = 0u64;
        for (d, c) in sorted {
            cumulative += c;
            if cumulative >= target { return d; }
        }
        self.max_depth
    }
}

// ── Run-length encoding of PC sequences ───────────────────────────────────────

/// A run of repeated PC executions
#[derive(Debug, Clone, Copy)]
pub struct PcRun {
    pub pc: u64,
    pub count: u32,
}

/// Run-length encode a sequence of PC values (captures hot loops compactly)
pub fn rle_encode_pcs(records: &[TraceRecord]) -> Vec<PcRun> {
    let mut runs = Vec::new();
    let mut last_pc: Option<u64> = None;
    let mut run_count: u32 = 0;

    for rec in records {
        if rec.event != TraceEventKind::Instruction && rec.event != TraceEventKind::BasicBlock {
            continue;
        }
        match last_pc {
            Some(p) if p == rec.pc => { run_count += 1; }
            _ => {
                if let Some(p) = last_pc {
                    runs.push(PcRun { pc: p, count: run_count });
                }
                last_pc = Some(rec.pc);
                run_count = 1;
            }
        }
    }
    if let Some(p) = last_pc {
        runs.push(PcRun { pc: p, count: run_count });
    }
    runs
}

// ── Coverage metrics ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CoverageMetrics {
    /// Total unique addresses seen
    pub unique_pcs: usize,
    /// Total instruction events
    pub total_instructions: u64,
    /// Estimate of total code size covered (in bytes, using BB size hints)
    pub estimated_bytes_covered: u64,
    pub bb_count: usize,
}

// ── Aggregate statistics ───────────────────────────────────────────────────────

/// Full statistical summary of a trace
#[derive(Debug, Default)]
pub struct TraceStatistics {
    pub insn_mix: InstructionMix,
    pub bb_hits: BasicBlockHits,
    pub memory: MemoryStats,
    pub syscalls: SyscallFrequency,
    pub branches: BranchStats,
    pub call_depth: CallDepthHistogram,
    pub total_records: u64,
    pub unique_threads: std::collections::HashSet<u32>,
    pub function_entry_counts: HashMap<u64, u64>,
    pub function_return_counts: HashMap<u64, u64>,
}

impl TraceStatistics {
    pub fn new() -> Self { TraceStatistics::default() }

    /// Compute statistics from a slice of trace records
    pub fn compute(records: &[TraceRecord]) -> Self {
        let mut stats = Self::new();
        let mut call_stack: Vec<u64> = Vec::new();

        for rec in records {
            stats.total_records += 1;
            stats.unique_threads.insert(rec.tid);

            match rec.event {
                TraceEventKind::Instruction => {
                    stats.insn_mix.record(
                        rec.insn_bytes.first()
                            .map(|&b| InsnCategory::from_x86_opcode(b))
                            .unwrap_or(InsnCategory::Unknown)
                    );
                }
                TraceEventKind::BasicBlock => {
                    stats.bb_hits.record(rec.pc);
                    stats.insn_mix.record(InsnCategory::Other);
                }
                TraceEventKind::MemRead => {
                    stats.memory.record_read(rec.mem_addr, rec.mem_size);
                    stats.insn_mix.record(InsnCategory::Memory);
                }
                TraceEventKind::MemWrite => {
                    stats.memory.record_write(rec.mem_addr, rec.mem_size);
                    stats.insn_mix.record(InsnCategory::Memory);
                }
                TraceEventKind::Syscall => {
                    stats.syscalls.record(rec.aux);
                    stats.insn_mix.record(InsnCategory::System);
                }
                TraceEventKind::Branch => {
                    let taken = rec.aux != 0;
                    let target = if taken { rec.aux } else { rec.pc };
                    stats.branches.record_branch(rec.pc, target, taken);
                    stats.insn_mix.record(InsnCategory::Control);
                }
                TraceEventKind::Call => {
                    *stats.function_entry_counts.entry(rec.aux).or_insert(0) += 1;
                    call_stack.push(rec.pc);
                    stats.call_depth.record(call_stack.len() as u32);
                    stats.insn_mix.record(InsnCategory::Control);
                }
                TraceEventKind::Return => {
                    *stats.function_return_counts.entry(rec.pc).or_insert(0) += 1;
                    call_stack.pop();
                    stats.call_depth.record(call_stack.len() as u32);
                    stats.insn_mix.record(InsnCategory::Control);
                }
                _ => {}
            }
        }

        stats
    }

    pub fn coverage_metrics(&self) -> CoverageMetrics {
        let unique_pcs = self.bb_hits.hits.len();
        let estimated_bytes_covered = unique_pcs as u64 * 8; // very rough
        CoverageMetrics {
            unique_pcs,
            total_instructions: self.insn_mix.total,
            estimated_bytes_covered,
            bb_count: self.bb_hits.unique_blocks(),
        }
    }

    pub fn thread_count(&self) -> usize { self.unique_threads.len() }

    pub fn hot_functions(&self, n: usize) -> Vec<(u64, u64)> {
        let mut v: Vec<_> = self.function_entry_counts.iter().map(|(&a, &c)| (a, c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    pub fn top_syscalls(&self, n: usize) -> Vec<(u64, u64)> {
        self.syscalls.top_n(n)
    }
}

impl fmt::Display for TraceStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Trace Statistics ===")?;
        writeln!(f, "Total records     : {}", self.total_records)?;
        writeln!(f, "Unique threads    : {}", self.thread_count())?;
        writeln!(f, "Unique BBs        : {}", self.bb_hits.unique_blocks())?;
        writeln!(f, "Total mem reads   : {}", self.memory.read_count)?;
        writeln!(f, "Total mem writes  : {}", self.memory.write_count)?;
        writeln!(f, "Total syscalls    : {}", self.syscalls.total)?;
        writeln!(f, "Total branches    : {}", self.branches.total_branches)?;
        writeln!(f, "Branch taken rate : {:.1}%", self.branches.overall_taken_rate() * 100.0)?;
        writeln!(f, "Max call depth    : {}", self.call_depth.max_depth)?;
        writeln!(f, "Mean call depth   : {:.1}", self.call_depth.mean_depth())?;
        writeln!(f, "Likely loops      : {}", self.branches.likely_loops().len())?;
        writeln!(f, "Write ratio       : {:.1}%", self.memory.write_ratio() * 100.0)?;
        write!(f, "{}", self.insn_mix)
    }
}

// ── Difference analysis between two traces ────────────────────────────────────

#[derive(Debug)]
pub struct TraceDifference {
    pub new_bbs: Vec<u64>,
    pub lost_bbs: Vec<u64>,
    pub bb_hit_delta: Vec<(u64, i64)>,
    pub new_syscalls: Vec<u64>,
    pub mem_read_delta: i64,
    pub mem_write_delta: i64,
}

/// Compare two TraceStatistics and return their differences
pub fn diff_statistics(before: &TraceStatistics, after: &TraceStatistics) -> TraceDifference {
    let new_bbs: Vec<u64> = after.bb_hits.hits.keys()
        .filter(|k| !before.bb_hits.hits.contains_key(k))
        .copied().collect();
    let lost_bbs: Vec<u64> = before.bb_hits.hits.keys()
        .filter(|k| !after.bb_hits.hits.contains_key(k))
        .copied().collect();

    let mut bb_hit_delta = Vec::new();
    for (&addr, &a_count) in &after.bb_hits.hits {
        let b_count = *before.bb_hits.hits.get(&addr).unwrap_or(&0);
        if a_count as i64 - b_count as i64 != 0 {
            bb_hit_delta.push((addr, a_count as i64 - b_count as i64));
        }
    }
    bb_hit_delta.sort_by(|a, b| b.1.abs().cmp(&a.1.abs()));

    let new_syscalls: Vec<u64> = after.syscalls.counts.keys()
        .filter(|k| !before.syscalls.counts.contains_key(k))
        .copied().collect();

    TraceDifference {
        new_bbs,
        lost_bbs,
        bb_hit_delta,
        new_syscalls,
        mem_read_delta: after.memory.read_count as i64 - before.memory.read_count as i64,
        mem_write_delta: after.memory.write_count as i64 - before.memory.write_count as i64,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace_format::TraceRecord;

    fn make_records() -> Vec<TraceRecord> {
        vec![
            TraceRecord::new_bb(0, 0, 0x1000, 10),
            TraceRecord::new_bb(1, 0, 0x1000, 10),
            TraceRecord::new_bb(2, 0, 0x2000, 5),
            TraceRecord::new_call(3, 0, 0x1010, 0x3000),
            TraceRecord::new_call(4, 0, 0x1020, 0x4000),
            {
                let r = TraceRecord::new_mem(5, 0, 0x1030, false, 0x8000, 4);
                r
            },
            {
                let r = TraceRecord::new_mem(6, 0, 0x1030, true, 0x8004, 4);
                r
            },
            {
                let mut r = TraceRecord::new_insn(7, 0, 0x1040);
                r.event = TraceEventKind::Syscall;
                r.aux = 60;
                r
            },
        ]
    }

    #[test]
    fn test_compute_stats_basic() {
        let records = make_records();
        let stats = TraceStatistics::compute(&records);
        assert_eq!(stats.total_records, 8);
        assert_eq!(stats.bb_hits.unique_blocks(), 2);
        assert_eq!(*stats.bb_hits.hits.get(&0x1000).unwrap(), 2);
        assert_eq!(*stats.bb_hits.hits.get(&0x2000).unwrap(), 1);
        assert_eq!(stats.memory.read_count, 1);
        assert_eq!(stats.memory.write_count, 1);
        assert_eq!(stats.syscalls.total, 1);
        assert_eq!(*stats.syscalls.counts.get(&60).unwrap(), 1);
        assert_eq!(stats.function_entry_counts.get(&0x3000), Some(&1));
    }

    #[test]
    fn test_bb_top_n() {
        let mut bb = BasicBlockHits::default();
        bb.record(0x1000);
        bb.record(0x1000);
        bb.record(0x2000);
        let top = bb.top_n(1);
        assert_eq!(top[0], (0x1000, 2));
    }

    #[test]
    fn test_branch_taken_rate() {
        let mut br = BranchStats::default();
        br.record_branch(0x100, 0x200, true);
        br.record_branch(0x100, 0x110, false);
        br.record_branch(0x100, 0x200, true);
        assert!((br.taken_rate(0x100) - 2.0/3.0).abs() < 1e-9);
    }

    #[test]
    fn test_back_edge_detection() {
        let mut br = BranchStats::default();
        br.record_branch(0x2000, 0x1000, true); // back edge
        br.record_branch(0x1000, 0x2000, true); // forward edge
        assert_eq!(br.likely_loops().len(), 1);
        assert_eq!(br.likely_loops()[0], (0x2000, 0x1000));
    }

    #[test]
    fn test_rle_encode_pcs() {
        let records = vec![
            TraceRecord::new_insn(0, 0, 0x1000),
            TraceRecord::new_insn(1, 0, 0x1000),
            TraceRecord::new_insn(2, 0, 0x1004),
        ];
        let rle = rle_encode_pcs(&records);
        assert_eq!(rle.len(), 2);
        assert_eq!(rle[0].pc, 0x1000);
        assert_eq!(rle[0].count, 2);
        assert_eq!(rle[1].pc, 0x1004);
        assert_eq!(rle[1].count, 1);
    }

    #[test]
    fn test_insn_mix_fraction() {
        let mut mix = InstructionMix::default();
        mix.record(InsnCategory::Alu);
        mix.record(InsnCategory::Alu);
        mix.record(InsnCategory::Mov);
        assert!((mix.fraction(InsnCategory::Alu) - 2.0/3.0).abs() < 1e-9);
        assert!((mix.fraction(InsnCategory::Mov) - 1.0/3.0).abs() < 1e-9);
        assert_eq!(mix.fraction(InsnCategory::Control), 0.0);
    }

    #[test]
    fn test_call_depth_histogram() {
        let mut h = CallDepthHistogram::default();
        h.record(1); h.record(1); h.record(2); h.record(3);
        assert_eq!(h.max_depth, 3);
        assert!((h.mean_depth() - 7.0/4.0).abs() < 1e-9);
    }

    #[test]
    fn test_stride_histogram() {
        let mut sh = StrideHistogram::default();
        sh.record_read(0x1000);
        sh.record_read(0x1004);
        sh.record_read(0x1008);
        assert_eq!(sh.dominant_stride(), Some(4));
        assert!((sh.sequential_fraction(4) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_diff_statistics() {
        let before_records = vec![TraceRecord::new_bb(0, 0, 0x1000, 5)];
        let after_records = vec![
            TraceRecord::new_bb(0, 0, 0x1000, 5),
            TraceRecord::new_bb(1, 0, 0x2000, 5),
        ];
        let b = TraceStatistics::compute(&before_records);
        let a = TraceStatistics::compute(&after_records);
        let diff = diff_statistics(&b, &a);
        assert_eq!(diff.new_bbs, vec![0x2000]);
        assert!(diff.lost_bbs.is_empty());
    }
}
