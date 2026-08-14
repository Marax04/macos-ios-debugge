//! `pt_block_decoder` — Decode Intel Processor Trace (PT) packets into basic blocks.
//!
//! Takes a raw PT byte stream and reconstructs the sequence of executed basic
//! blocks (contiguous instruction ranges ending at a branch).  Integrates with
//! the existing `PtDecoder` / `PtPacket` types from the crate root.

use std::collections::HashMap;
use std::fmt;

// ── BlockKind ─────────────────────────────────────────────────────────────────

/// The kind of basic block that was decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockKind {
    /// Normal sequential block ending with an unconditional jump.
    UnconditionalJump,
    /// Block ending with a conditional branch that was taken.
    ConditionalTaken,
    /// Block ending with a conditional branch that was not taken (fall-through).
    ConditionalFallThrough,
    /// Block ending with a direct call instruction.
    Call,
    /// Block ending with a return instruction.
    Return,
    /// Block ending with an indirect jump (e.g., jmp rax).
    IndirectJump,
    /// Block ending with an indirect call (e.g., call [rax]).
    IndirectCall,
    /// Synthesised block boundary from PT timing or overflow packet.
    Synthetic,
    /// The block kind could not be determined.
    Unknown,
}

impl fmt::Display for BlockKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::UnconditionalJump => "jmp",
            Self::ConditionalTaken => "jcc-taken",
            Self::ConditionalFallThrough => "jcc-fall",
            Self::Call => "call",
            Self::Return => "ret",
            Self::IndirectJump => "jmp*",
            Self::IndirectCall => "call*",
            Self::Synthetic => "synthetic",
            Self::Unknown => "?",
        };
        f.write_str(s)
    }
}

// ── DecodedBlock ──────────────────────────────────────────────────────────────

/// A single decoded basic block from the PT stream.
#[derive(Debug, Clone)]
pub struct DecodedBlock {
    /// Address of the first instruction in the block.
    pub start_ip: u64,
    /// Address of the last instruction in the block (branch/call/ret).
    pub end_ip: u64,
    /// Number of instructions contained in this block.
    pub insn_count: u32,
    /// Byte size of the block (`end_ip` - `start_ip` + `last_insn_size`).
    pub byte_size: u32,
    /// Kind of control-flow transfer at the end of the block.
    pub kind: BlockKind,
    /// IP of the next block executed (if known from TNT/TIP/CALL packets).
    pub next_ip: Option<u64>,
    /// Index of this block in the decoded sequence.
    pub sequence_index: u64,
    /// Whether this block was speculatively executed (inside TSX region).
    pub speculative: bool,
}

impl DecodedBlock {
    /// Create a new decoded block.
    #[must_use]
    pub const fn new(
        start_ip: u64,
        end_ip: u64,
        insn_count: u32,
        byte_size: u32,
        kind: BlockKind,
    ) -> Self {
        Self {
            start_ip,
            end_ip,
            insn_count,
            byte_size,
            kind,
            next_ip: None,
            sequence_index: 0,
            speculative: false,
        }
    }

    /// Return the span of addresses covered by this block.
    #[must_use]
    pub const fn address_range(&self) -> std::ops::Range<u64> {
        self.start_ip..self.end_ip + 1
    }

    /// Format in a style similar to `ptdump --blocks`.
    #[must_use]
    pub fn format_ptdump(&self) -> String {
        let next = self
            .next_ip
            .map(|a| format!("-> 0x{a:x}"))
            .unwrap_or_default();
        format!(
            "[{:08}] 0x{:016x}-0x{:016x}  insns={:4}  bytes={:4}  {}  {}",
            self.sequence_index,
            self.start_ip,
            self.end_ip,
            self.insn_count,
            self.byte_size,
            self.kind,
            next,
        )
    }
}

impl fmt::Display for DecodedBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.format_ptdump())
    }
}

// ── BlockStats ────────────────────────────────────────────────────────────────

/// Aggregate statistics over a decoded block sequence.
#[derive(Debug, Clone, Default)]
pub struct BlockStats {
    /// Total blocks decoded.
    pub total_blocks: u64,
    /// Total instructions across all blocks.
    pub total_insns: u64,
    /// Number of taken conditional branches.
    pub taken_branches: u64,
    /// Number of fall-through conditional branches.
    pub fall_branches: u64,
    /// Number of call instructions.
    pub calls: u64,
    /// Number of return instructions.
    pub returns: u64,
    /// Number of indirect jumps/calls.
    pub indirect: u64,
    /// How many distinct start IPs were seen (coverage).
    pub unique_ips: usize,
}

impl BlockStats {
    /// Accumulate a block into the stats.
    pub fn accumulate(&mut self, block: &DecodedBlock) {
        self.total_blocks += 1;
        self.total_insns += u64::from(block.insn_count);
        match block.kind {
            BlockKind::ConditionalTaken => self.taken_branches += 1,
            BlockKind::ConditionalFallThrough => self.fall_branches += 1,
            BlockKind::Call => self.calls += 1,
            BlockKind::Return => self.returns += 1,
            BlockKind::IndirectJump | BlockKind::IndirectCall => self.indirect += 1,
            _ => {}
        }
    }

    /// Average instructions per block.
    #[must_use]
    pub fn avg_insns_per_block(&self) -> f64 {
        if self.total_blocks == 0 {
            return 0.0;
        }
        crate::cast_helpers::u64_to_f64(self.total_insns) / crate::cast_helpers::u64_to_f64(self.total_blocks)
    }
}

impl fmt::Display for BlockStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "blocks={} insns={} taken={} fall={} calls={} rets={} indirect={} unique_ips={}",
            self.total_blocks,
            self.total_insns,
            self.taken_branches,
            self.fall_branches,
            self.calls,
            self.returns,
            self.indirect,
            self.unique_ips,
        )
    }
}

// ── PtBlockDecoder ────────────────────────────────────────────────────────────

/// Simulated Intel PT basic-block decoder.
///
/// In a real implementation this would wrap `libipt` via a C FFI layer and use
/// the `pt_block_decoder` API.  Here we simulate decoding from a structured
/// byte stream where each "packet" is an 18-byte record:
///
/// ```text
/// [0..7]  start_ip     (u64 LE)
/// [8..11] insn_count   (u32 LE)
/// [12]    kind_byte
/// [13]    flags        (bit 0 = speculative, bit 1 = has_next_ip)
/// [14..15] byte_size   (u16 LE)
/// [16..23] next_ip     (u64 LE, only meaningful if flags bit 1 set)
/// ```
///
/// Total record size: 24 bytes.
#[derive(Debug)]
pub struct PtBlockDecoder {
    /// Decoded blocks in sequence order.
    pub blocks: Vec<DecodedBlock>,
    /// Per-start-IP hit counts (hot path tracking).
    pub hit_counts: HashMap<u64, u64>,
    /// Accumulated statistics.
    pub stats: BlockStats,
    /// Whether decoding has been completed.
    pub finished: bool,
}

const RECORD_SIZE: usize = 24;

impl PtBlockDecoder {
    /// Create a new decoder (empty, before any stream is fed).
    #[must_use]
    pub fn new() -> Self {
        Self {
            blocks: Vec::new(),
            hit_counts: HashMap::new(),
            stats: BlockStats::default(),
            finished: false,
        }
    }

    /// Decode a PT byte stream (our structured format) and return the block list.
    ///
    /// # Panics
    /// May panic on invalid input.
    ///
    /// Returns the number of blocks decoded.
    pub fn decode_stream(&mut self, data: &[u8]) -> usize {
        let count_before = self.blocks.len();
        let mut seq = self.blocks.len() as u64;
        let mut i = 0;
        while i + RECORD_SIZE <= data.len() {
            let record = &data[i..i + RECORD_SIZE];
            let start_ip = u64::from_le_bytes(record[0..8].try_into().unwrap());
            let insn_count = u32::from_le_bytes(record[8..12].try_into().unwrap());
            let kind_byte = record[12];
            let flags = record[13];
            let byte_size = u32::from(u16::from_le_bytes(record[14..16].try_into().unwrap()));
            let next_ip_raw = u64::from_le_bytes(record[16..24].try_into().unwrap());

            let kind = kind_from_byte(kind_byte);
            let speculative = flags & 0x01 != 0;
            let has_next = flags & 0x02 != 0;

            // Derive end_ip from start_ip + byte_size - last_insn_size (approx 4).
            let end_ip = start_ip.saturating_add(u64::from(byte_size.saturating_sub(4)));

            let mut block = DecodedBlock::new(start_ip, end_ip, insn_count, byte_size, kind);
            block.speculative = speculative;
            block.sequence_index = seq;
            if has_next && next_ip_raw != 0 {
                block.next_ip = Some(next_ip_raw);
            }

            *self.hit_counts.entry(start_ip).or_insert(0) += 1;
            self.stats.accumulate(&block);
            self.blocks.push(block);
            seq += 1;
            i += RECORD_SIZE;
        }
        self.stats.unique_ips = self.hit_counts.len();
        self.finished = true;
        self.blocks.len() - count_before
    }

    /// Return blocks sorted by hit count (hottest first).
    #[must_use]
    pub fn hot_blocks(&self) -> Vec<(&DecodedBlock, u64)> {
        let mut pairs: Vec<(&DecodedBlock, u64)> = self
            .blocks
            .iter()
            .map(|b| {
                let hits = self.hit_counts.get(&b.start_ip).copied().unwrap_or(0);
                (b, hits)
            })
            .collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs
    }

    /// Find all blocks that contain `ip` in their address range.
    #[must_use]
    pub fn blocks_containing(&self, ip: u64) -> Vec<&DecodedBlock> {
        self.blocks
            .iter()
            .filter(|b| b.address_range().contains(&ip))
            .collect()
    }

    /// Return a formatted block trace (ptdump style).
    #[must_use]
    pub fn format_trace(&self) -> String {
        let mut out = String::new();
        for b in &self.blocks {
            out.push_str(&b.format_ptdump());
            out.push('\n');
        }
        out
    }
}

impl Default for PtBlockDecoder {
    fn default() -> Self {
        Self::new()
    }
}

const fn kind_from_byte(b: u8) -> BlockKind {
    match b {
        0 => BlockKind::UnconditionalJump,
        1 => BlockKind::ConditionalTaken,
        2 => BlockKind::ConditionalFallThrough,
        3 => BlockKind::Call,
        4 => BlockKind::Return,
        5 => BlockKind::IndirectJump,
        6 => BlockKind::IndirectCall,
        7 => BlockKind::Synthetic,
        _ => BlockKind::Unknown,
    }
}

/// Encode a block description into our 24-byte wire format for testing.
#[must_use]
pub fn encode_block_record(
    start_ip: u64,
    insn_count: u32,
    byte_size: u16,
    kind: u8,
    speculative: bool,
    next_ip: Option<u64>,
) -> [u8; RECORD_SIZE] {
    let mut rec = [0u8; RECORD_SIZE];
    rec[0..8].copy_from_slice(&start_ip.to_le_bytes());
    rec[8..12].copy_from_slice(&insn_count.to_le_bytes());
    rec[12] = kind;
    let mut flags = 0u8;
    if speculative {
        flags |= 0x01;
    }
    if next_ip.is_some() {
        flags |= 0x02;
    }
    rec[13] = flags;
    rec[14..16].copy_from_slice(&byte_size.to_le_bytes());
    rec[16..24].copy_from_slice(&next_ip.unwrap_or(0).to_le_bytes());
    rec
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_stream(records: &[[u8; RECORD_SIZE]]) -> Vec<u8> {
        records.iter().flat_map(|r| r.iter().copied()).collect()
    }

    fn simple_record(start: u64, insns: u32, size: u16, kind: u8) -> [u8; RECORD_SIZE] {
        encode_block_record(start, insns, size, kind, false, None)
    }

    #[test]
    fn test_new_decoder_empty() {
        let d = PtBlockDecoder::new();
        assert!(d.blocks.is_empty());
        assert!(!d.finished);
    }

    #[test]
    fn test_decode_single_block() {
        let mut d = PtBlockDecoder::new();
        let rec = simple_record(0x1000, 5, 20, 3); // Call
        let n = d.decode_stream(&rec);
        assert_eq!(n, 1);
        assert_eq!(d.blocks.len(), 1);
        assert_eq!(d.blocks[0].start_ip, 0x1000);
        assert_eq!(d.blocks[0].insn_count, 5);
        assert_eq!(d.blocks[0].kind, BlockKind::Call);
    }

    #[test]
    fn test_decode_multiple_blocks() {
        let mut d = PtBlockDecoder::new();
        let stream = make_stream(&[
            simple_record(0x1000, 3, 12, 1), // ConditionalTaken
            simple_record(0x2000, 4, 16, 2), // ConditionalFallThrough
            simple_record(0x3000, 2, 8, 4),  // Return
        ]);
        let n = d.decode_stream(&stream);
        assert_eq!(n, 3);
        assert_eq!(d.blocks[0].kind, BlockKind::ConditionalTaken);
        assert_eq!(d.blocks[1].kind, BlockKind::ConditionalFallThrough);
        assert_eq!(d.blocks[2].kind, BlockKind::Return);
    }

    #[test]
    fn test_decode_with_next_ip() {
        let mut d = PtBlockDecoder::new();
        let rec = encode_block_record(0x1000, 5, 20, 3, false, Some(0x2000));
        let n = d.decode_stream(&rec);
        assert_eq!(n, 1);
        assert_eq!(d.blocks[0].next_ip, Some(0x2000));
    }

    #[test]
    fn test_decode_speculative() {
        let mut d = PtBlockDecoder::new();
        let rec = encode_block_record(0x1000, 2, 8, 0, true, None);
        d.decode_stream(&rec);
        assert!(d.blocks[0].speculative);
    }

    #[test]
    fn test_hit_counts_accumulate() {
        let mut d = PtBlockDecoder::new();
        let stream = make_stream(&[
            simple_record(0x1000, 3, 12, 0),
            simple_record(0x1000, 3, 12, 0),
            simple_record(0x2000, 1, 4, 4),
        ]);
        d.decode_stream(&stream);
        assert_eq!(d.hit_counts[&0x1000], 2);
        assert_eq!(d.hit_counts[&0x2000], 1);
    }

    #[test]
    fn test_stats_totals() {
        let mut d = PtBlockDecoder::new();
        let stream = make_stream(&[
            simple_record(0x1000, 4, 16, 3), // call
            simple_record(0x2000, 2, 8, 4),  // ret
        ]);
        d.decode_stream(&stream);
        assert_eq!(d.stats.total_blocks, 2);
        assert_eq!(d.stats.total_insns, 6);
        assert_eq!(d.stats.calls, 1);
        assert_eq!(d.stats.returns, 1);
    }

    #[test]
    fn test_stats_avg_insns() {
        let mut d = PtBlockDecoder::new();
        let stream = make_stream(&[
            simple_record(0x1000, 4, 16, 0),
            simple_record(0x2000, 6, 24, 0),
        ]);
        d.decode_stream(&stream);
        let avg = d.stats.avg_insns_per_block();
        assert!((avg - 5.0).abs() < 1e-9);
    }

    #[test]
    fn test_hot_blocks_order() {
        let mut d = PtBlockDecoder::new();
        let stream = make_stream(&[
            simple_record(0x1000, 1, 4, 0),
            simple_record(0x1000, 1, 4, 0),
            simple_record(0x2000, 1, 4, 0),
        ]);
        d.decode_stream(&stream);
        let hot = d.hot_blocks();
        assert_eq!(hot[0].0.start_ip, 0x1000);
        assert_eq!(hot[0].1, 2);
    }

    #[test]
    fn test_blocks_containing() {
        let mut d = PtBlockDecoder::new();
        let rec = simple_record(0x1000, 5, 20, 0);
        d.decode_stream(&rec);
        let found = d.blocks_containing(0x1005);
        assert_eq!(found.len(), 1);
        let not_found = d.blocks_containing(0x2000);
        assert!(not_found.is_empty());
    }

    #[test]
    fn test_sequence_index_increments() {
        let mut d = PtBlockDecoder::new();
        let stream = make_stream(&[
            simple_record(0x1000, 1, 4, 0),
            simple_record(0x2000, 1, 4, 0),
        ]);
        d.decode_stream(&stream);
        assert_eq!(d.blocks[0].sequence_index, 0);
        assert_eq!(d.blocks[1].sequence_index, 1);
    }

    #[test]
    fn test_format_trace_contains_addresses() {
        let mut d = PtBlockDecoder::new();
        let rec = simple_record(0xdead_beef, 3, 12, 0);
        d.decode_stream(&rec);
        let trace = d.format_trace();
        assert!(trace.contains("deadbeef"));
    }

    #[test]
    fn test_block_display() {
        let b = DecodedBlock::new(0x1000, 0x100c, 4, 16, BlockKind::Return);
        let s = b.to_string();
        assert!(s.contains("ret"));
    }

    #[test]
    fn test_kind_display() {
        assert_eq!(BlockKind::Call.to_string(), "call");
        assert_eq!(BlockKind::Return.to_string(), "ret");
        assert_eq!(BlockKind::ConditionalTaken.to_string(), "jcc-taken");
        assert_eq!(BlockKind::Unknown.to_string(), "?");
    }

    #[test]
    fn test_address_range() {
        let b = DecodedBlock::new(0x1000, 0x1010, 5, 20, BlockKind::Call);
        assert!(b.address_range().contains(&0x1000));
        assert!(b.address_range().contains(&0x1010));
        assert!(!b.address_range().contains(&0x1020));
    }

    #[test]
    fn test_partial_record_ignored() {
        let mut d = PtBlockDecoder::new();
        // Only 10 bytes — too short for a record
        let partial = vec![0u8; 10];
        let n = d.decode_stream(&partial);
        assert_eq!(n, 0);
        assert!(d.blocks.is_empty());
    }

    #[test]
    fn test_unique_ips_count() {
        let mut d = PtBlockDecoder::new();
        let stream = make_stream(&[
            simple_record(0x1000, 1, 4, 0),
            simple_record(0x1000, 1, 4, 0),
            simple_record(0x2000, 1, 4, 0),
        ]);
        d.decode_stream(&stream);
        assert_eq!(d.stats.unique_ips, 2);
    }

    #[test]
    fn test_decode_indirect() {
        let mut d = PtBlockDecoder::new();
        let stream = make_stream(&[
            simple_record(0x1000, 2, 8, 5),  // IndirectJump
            simple_record(0x2000, 2, 8, 6),  // IndirectCall
        ]);
        d.decode_stream(&stream);
        assert_eq!(d.stats.indirect, 2);
    }

    #[test]
    fn test_block_stats_display() {
        let s = BlockStats {
            total_blocks: 10,
            total_insns: 50,
            taken_branches: 3,
            fall_branches: 2,
            calls: 4,
            returns: 4,
            indirect: 1,
            unique_ips: 8,
        };
        let txt = s.to_string();
        assert!(txt.contains("blocks=10"));
        assert!(txt.contains("insns=50"));
    }

    #[test]
    fn test_decode_incremental() {
        let mut d = PtBlockDecoder::new();
        let r1 = simple_record(0x1000, 2, 8, 0);
        d.decode_stream(&r1);
        assert_eq!(d.blocks.len(), 1);
        let r2 = simple_record(0x2000, 3, 12, 4);
        let n = d.decode_stream(&r2);
        assert_eq!(n, 1);
        assert_eq!(d.blocks.len(), 2);
        assert_eq!(d.blocks[1].sequence_index, 1);
    }
}
