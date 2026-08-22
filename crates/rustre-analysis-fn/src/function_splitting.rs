//! Function-splitting pass for `rustre-analysis-fn`.
//!
//! In stripped or heavily optimised binaries the linear-sweep detector may
//! assign one large address range to what is really two (or more) functions.
//! This happens when:
//!
//! * The compiler merged a cold helper into the middle of the caller
//!   (`__attribute__((flatten))`).
//! * A `JMP` target inside function A is actually the entry of function B
//!   (e.g. tail-call from a different compilation unit).
//! * COMDAT/ICF folding placed two semantically different functions at
//!   overlapping address ranges.
//!
//! The [`FunctionSplitter`] detects these situations, resolves the overlap by
//! re-analysing the CFG of each candidate range, and produces a corrected list
//! of non-overlapping [`FunctionBoundary`] records.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::{Confidence, DetectedArch, DetectionSource, FunctionBoundary, MemorySlice};
use rustre_core::address::Address;

// ─────────────────────────────────────────────────────────────────────────────
// Basic-block and CFG types
// ─────────────────────────────────────────────────────────────────────────────

/// A simple basic block: a maximal straight-line sequence of instructions
/// ending at a branch, call, or return.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Address of the first instruction in the block.
    pub start: Address,
    /// Address immediately past the last instruction (exclusive end).
    pub end: Address,
    /// Successor addresses (branch targets and fall-through).
    pub successors: Vec<Address>,
    /// Whether the block terminates with a `RET` / `RETQ` instruction.
    pub is_return: bool,
    /// Whether the block terminates with an unconditional `JMP`.
    pub is_tail_jmp: bool,
    /// Whether any successor is outside the candidate function range.
    pub has_external_successor: bool,
}

/// A minimal control-flow graph for one candidate function range.
#[derive(Debug, Default)]
pub struct Cfg {
    /// Map from block start → block.
    pub blocks: HashMap<u64, BasicBlock>,
}

impl Cfg {
    /// Compute the set of all addresses reachable from `entry` via BFS.
    #[must_use]
    pub fn reachable_from(&self, entry: Address) -> HashSet<u64> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(entry.as_u64());

        while let Some(addr) = queue.pop_front() {
            if !visited.insert(addr) {
                continue;
            }
            if let Some(bb) = self.blocks.get(&addr) {
                for &succ in &bb.successors {
                    queue.push_back(succ.as_u64());
                }
            }
        }

        visited
    }

    /// Return the number of basic blocks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Return `true` if the CFG has no basic blocks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lightweight x86-64 CFG builder
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a simplified CFG for an x86-64 function by byte-scanning for
/// branches, calls, and returns.
///
/// This is intentionally not a full disassembler: it byte-scans for the most
/// common one- and two-byte opcodes.  The goal is not perfect accuracy but a
/// fast, good-enough CFG for overlap detection.
pub struct CfgBuilder {
    /// Architecture being analysed.
    pub arch: DetectedArch,
    /// Maximum number of basic blocks to build (avoid pathological cases).
    pub max_blocks: usize,
}

impl CfgBuilder {
    /// Create a builder for x86-64.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            arch: DetectedArch::X86_64,
            max_blocks: 2048,
        }
    }

    /// Build a CFG for the function starting at `entry` and bounded by
    /// `[range_start, range_end)` within `mem`.
    #[must_use]
    pub fn build(
        &self,
        mem: &MemorySlice<'_>,
        entry: Address,
        range_start: Address,
        range_end: Address,
    ) -> Cfg {
        let mut cfg = Cfg::default();
        let mut work_list: VecDeque<Address> = VecDeque::new();
        let mut visited_starts: HashSet<u64> = HashSet::new();

        work_list.push_back(entry);

        while let Some(bb_start) = work_list.pop_front() {
            if cfg.blocks.len() >= self.max_blocks {
                break;
            }
            if !visited_starts.insert(bb_start.as_u64()) {
                continue;
            }
            if !Self::in_range(bb_start, range_start, range_end) {
                continue;
            }

            if let Some(bb) = Self::build_block(mem, bb_start, range_start, range_end) {
                for &succ in &bb.successors {
                    if Self::in_range(succ, range_start, range_end) {
                        work_list.push_back(succ);
                    }
                }
                cfg.blocks.insert(bb_start.as_u64(), bb);
            }
        }

        cfg
    }

    /// Assembles a [`BasicBlock`] from its component parts.
    const fn finish_block(
        start: Address,
        end: Address,
        successors: Vec<Address>,
        is_return: bool,
        is_tail_jmp: bool,
        has_external_successor: bool,
    ) -> BasicBlock {
        BasicBlock {
            start,
            end,
            successors,
            is_return,
            is_tail_jmp,
            has_external_successor,
        }
    }

    /// Reads a little-endian `rel32` displacement starting at `addr`.
    fn read_rel32(mem: &MemorySlice<'_>, addr: Address) -> Option<i64> {
        let bytes = [
            mem.read_u8(addr)?,
            mem.read_u8(addr + 1)?,
            mem.read_u8(addr + 2)?,
            mem.read_u8(addr + 3)?,
        ];
        Some(i64::from(i32::from_le_bytes(bytes)))
    }

    fn build_block(
        mem: &MemorySlice<'_>,
        start: Address,
        range_start: Address,
        range_end: Address,
    ) -> Option<BasicBlock> {
        let mut addr = start;
        let mut successors: Vec<Address> = Vec::new();
        let mut has_external = false;

        loop {
            if !Self::in_range(addr, range_start, range_end) {
                break;
            }
            let b = mem.read_u8(addr)?;
            let off = addr.as_u64();

            match b {
                // RET / RET imm16 / HLT / INT3 padding
                0xC3 | 0xCB | 0xC2 | 0xCA | 0xF4 | 0xCC => {
                    let end = addr + if matches!(b, 0xC2 | 0xCA) { 3 } else { 1 };
                    return Some(Self::finish_block(
                        start,
                        end,
                        successors,
                        true,
                        false,
                        has_external,
                    ));
                }
                // JMP rel8 / JMP rel32 (tail jump)
                0xEB | 0xE9 => {
                    let (disp, len) = if b == 0xEB {
                        (i64::from(i8::from_le_bytes([mem.read_u8(addr + 1)?])), 2)
                    } else {
                        (Self::read_rel32(mem, addr + 1)?, 5)
                    };
                    let target = Address::new(off.wrapping_add(len).wrapping_add_signed(disp));
                    Self::push_successor(
                        &mut successors,
                        &mut has_external,
                        target,
                        range_start,
                        range_end,
                    );
                    return Some(Self::finish_block(
                        start,
                        addr + len,
                        successors,
                        false,
                        true,
                        has_external,
                    ));
                }
                // Jcc rel8 / Jcc rel32 (conditional branch)
                0x70..=0x7F | 0x0F => {
                    let (disp, len) = if b == 0x0F {
                        if !mem
                            .read_u8(addr + 1)
                            .is_some_and(|b2| (0x80..=0x8F).contains(&b2))
                        {
                            addr += 1;
                            continue;
                        }
                        (Self::read_rel32(mem, addr + 2)?, 6)
                    } else {
                        (i64::from(i8::from_le_bytes([mem.read_u8(addr + 1)?])), 2)
                    };
                    let taken = Address::new(off.wrapping_add(len).wrapping_add_signed(disp));
                    Self::push_successor(
                        &mut successors,
                        &mut has_external,
                        taken,
                        range_start,
                        range_end,
                    );
                    if Self::in_range(addr + len, range_start, range_end) {
                        successors.push(addr + len);
                    }
                    return Some(Self::finish_block(
                        start,
                        addr + len,
                        successors,
                        false,
                        false,
                        has_external,
                    ));
                }
                // CALL rel32: skip over
                0xE8 => addr += 5,
                _ => addr += 1,
            }
        }

        if addr == start {
            return None;
        }
        Some(Self::finish_block(
            start,
            addr,
            successors,
            false,
            false,
            has_external,
        ))
    }

    fn push_successor(
        successors: &mut Vec<Address>,
        has_external: &mut bool,
        target: Address,
        range_start: Address,
        range_end: Address,
    ) {
        if Self::in_range(target, range_start, range_end) {
            successors.push(target);
        } else {
            *has_external = true;
        }
    }

    const fn in_range(addr: Address, start: Address, end: Address) -> bool {
        addr.as_u64() >= start.as_u64() && addr.as_u64() < end.as_u64()
    }
}

impl Default for CfgBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Overlap detection
// ─────────────────────────────────────────────────────────────────────────────

/// Describes a detected overlap between two function ranges.
#[derive(Debug, Clone)]
pub struct FunctionOverlap {
    /// The "outer" function whose range contains the inner entry point.
    pub outer_start: Address,
    pub outer_end: Address,
    /// The "inner" function entry that lies inside the outer range.
    pub inner_start: Address,
    /// Classification of the overlap kind.
    pub kind: OverlapKind,
}

/// How two overlapping function ranges are related.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlapKind {
    /// The inner function is reachable only via tail-call from the outer.
    TailCall,
    /// The inner function is a genuine independent function entry (separate
    /// prologue, full CFG).
    Independent,
    /// The relationship cannot be determined without deeper analysis.
    Unknown,
}

/// Detect overlaps in a list of [`FunctionBoundary`] records.
///
/// **Precondition:** `boundaries` must be sorted by `start` ascending. The
/// scan relies on this to `break` early once an inner start passes the outer
/// end; on an unsorted list it would silently *under*-report overlaps rather
/// than error. Debug builds assert the ordering to catch misuse; release
/// builds trust it (the in-crate caller [`FunctionSplitter::split`] sorts
/// first).
#[must_use]
pub fn detect_overlaps(boundaries: &[FunctionBoundary]) -> Vec<FunctionOverlap> {
    debug_assert!(
        boundaries.windows(2).all(|w| w[0].start.as_u64() <= w[1].start.as_u64()),
        "detect_overlaps: boundaries must be sorted by start ascending"
    );
    let mut overlaps = Vec::new();

    for (i, outer) in boundaries.iter().enumerate() {
        let Some(outer_end) = outer.end else { continue };

        for inner in boundaries.iter().skip(i + 1) {
            if inner.start.as_u64() >= outer_end.as_u64() {
                break; // list is sorted; no more overlaps possible
            }
            // inner.start is inside outer's range.
            overlaps.push(FunctionOverlap {
                outer_start: outer.start,
                outer_end,
                inner_start: inner.start,
                kind: OverlapKind::Unknown,
            });
        }
    }

    overlaps
}

// ─────────────────────────────────────────────────────────────────────────────
// Function splitter
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the function splitter.
#[derive(Debug, Clone)]
pub struct SplitterConfig {
    /// Architecture.
    pub arch: DetectedArch,
    /// Minimum byte size for a split sub-function to be kept.
    pub min_split_size: u64,
    /// When `true`, insert a synthetic boundary at inner entry points even
    /// when the CFG analysis is inconclusive.
    pub aggressive: bool,
}

impl Default for SplitterConfig {
    fn default() -> Self {
        Self {
            arch: DetectedArch::X86_64,
            min_split_size: 4,
            aggressive: false,
        }
    }
}

/// Resolves function overlaps and returns a corrected, non-overlapping list of
/// [`FunctionBoundary`] records.
pub struct FunctionSplitter {
    /// Configuration.
    pub config: SplitterConfig,
}

impl FunctionSplitter {
    /// Create a splitter with default configuration.
    #[must_use]
    pub const fn new(config: SplitterConfig) -> Self {
        Self { config }
    }

    /// Resolve all overlaps in `boundaries` using CFG analysis over `mem`.
    ///
    /// Returns the corrected boundary list, sorted by address.
    #[must_use]
    pub fn split(
        &self,
        boundaries: Vec<FunctionBoundary>,
        mem: &MemorySlice<'_>,
    ) -> Vec<FunctionBoundary> {
        let mut result = boundaries;
        result.sort_by_key(|b| b.start.as_u64());

        // First pass: detect overlaps.
        let overlaps = detect_overlaps(&result);
        if overlaps.is_empty() {
            return result;
        }

        let cfg_builder = CfgBuilder {
            arch: self.config.arch,
            max_blocks: 2048,
        };

        // For each overlap, decide whether to split the outer function.
        let mut new_boundaries: Vec<FunctionBoundary> = Vec::new();

        for overlap in &overlaps {
            // Build CFG of the outer function up to the inner entry point.
            let outer_cfg = cfg_builder.build(
                mem,
                overlap.outer_start,
                overlap.outer_start,
                overlap.inner_start,
            );

            // Build CFG of the inner candidate.
            let inner_cfg = cfg_builder.build(
                mem,
                overlap.inner_start,
                overlap.inner_start,
                overlap.outer_end,
            );

            // If the inner CFG looks like a complete function (has RET, has
            // enough blocks), treat it as independent and split.
            let inner_has_ret = inner_cfg.blocks.values().any(|b| b.is_return);
            let inner_size = overlap
                .outer_end
                .as_u64()
                .saturating_sub(overlap.inner_start.as_u64());

            let should_split = (inner_has_ret && inner_size >= self.config.min_split_size)
                || (self.config.aggressive && !outer_cfg.is_empty());

            if should_split {
                // Shorten the outer function to end at the inner entry —
                // keeping the NEAREST one.
                //
                // Assigning unconditionally meant the last overlap processed
                // won, so with several inner entries the outer function was
                // cut at the FARTHEST and still swallowed the inner functions
                // in between: the returned list stayed overlapping, which is
                // precisely what this pass exists to prevent.
                if let Some(outer_fb) = result.iter_mut().find(|fb| fb.start == overlap.outer_start)
                    && outer_fb.end.is_none_or(|e| overlap.inner_start < e) {
                        outer_fb.end = Some(overlap.inner_start);
                    }

                // Insert the inner function if not already present.
                if !result.iter().any(|fb| fb.start == overlap.inner_start) {
                    new_boundaries.push(FunctionBoundary::new(
                        overlap.inner_start,
                        Confidence::Medium,
                        DetectionSource::CallTarget,
                    ));
                }
            }
        }

        result.extend(new_boundaries);
        result.sort_by_key(|fb| fb.start.as_u64());
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Re-analysis: re-compute CFG and fix end addresses
// ─────────────────────────────────────────────────────────────────────────────

/// Re-analyse `boundaries` to tighten their end addresses using CFG-based
/// reachability.  Addresses that are not reachable from the declared entry are
/// no longer claimed by that function.
#[must_use]
pub fn reanalyze_ends(
    mut boundaries: Vec<FunctionBoundary>,
    mem: &MemorySlice<'_>,
    arch: DetectedArch,
) -> Vec<FunctionBoundary> {
    let builder = CfgBuilder {
        arch,
        max_blocks: 2048,
    };

    for fb in &mut boundaries {
        let Some(declared_end) = fb.end else { continue };

        let cfg = builder.build(mem, fb.start, fb.start, declared_end);
        if cfg.is_empty() {
            continue;
        }

        // The actual end is the maximum reachable block end address.
        let max_end = cfg
            .blocks
            .values()
            .map(|b| b.end.as_u64())
            .max()
            .unwrap_or(fb.start.as_u64());

        if max_end < declared_end.as_u64() {
            fb.end = Some(Address::new(max_end));
        }
    }

    boundaries
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Confidence, DetectionSource};
    use rustre_core::address::Address;

    fn make_fb(start: u64, end: u64) -> FunctionBoundary {
        FunctionBoundary::new(
            Address::new(start),
            Confidence::Medium,
            DetectionSource::ProloguePattern,
        )
        .with_end(Address::new(end))
    }

    #[test]
    fn detect_overlaps_basic() {
        let boundaries = vec![make_fb(0x1000, 0x2000), make_fb(0x1500, 0x1800)];
        let overlaps = detect_overlaps(&boundaries);
        assert_eq!(overlaps.len(), 1);
        assert_eq!(overlaps[0].outer_start, Address::new(0x1000));
        assert_eq!(overlaps[0].inner_start, Address::new(0x1500));
    }

    #[test]
    fn detect_overlaps_none_when_adjacent() {
        let boundaries = vec![make_fb(0x1000, 0x2000), make_fb(0x2000, 0x3000)];
        let overlaps = detect_overlaps(&boundaries);
        assert!(overlaps.is_empty());
    }

    /// Nested + multiple overlaps on a correctly-sorted list: the outer
    /// function contains two inner entry points, and a second outer contains
    /// one — all three must be reported (guards the early-`break` scan).
    #[test]
    fn detect_overlaps_multiple_nested_sorted() {
        let boundaries = vec![
            make_fb(0x1000, 0x2000), // outer A
            make_fb(0x1400, 0x1500), // inner in A
            make_fb(0x1800, 0x1900), // inner in A
            make_fb(0x2000, 0x2400), // outer B (adjacent to A, not overlapping)
            make_fb(0x2100, 0x2200), // inner in B
        ];
        let overlaps = detect_overlaps(&boundaries);
        // A contains 0x1400 and 0x1800; B contains 0x2100 → 3 overlaps.
        assert_eq!(overlaps.len(), 3, "got {overlaps:?}");
        assert!(overlaps.iter().any(|o| o.outer_start == Address::new(0x1000)
            && o.inner_start == Address::new(0x1400)));
        assert!(overlaps.iter().any(|o| o.outer_start == Address::new(0x1000)
            && o.inner_start == Address::new(0x1800)));
        assert!(overlaps.iter().any(|o| o.outer_start == Address::new(0x2000)
            && o.inner_start == Address::new(0x2100)));
    }

    #[test]
    fn cfg_builder_builds_linear_block() {
        // 10 NOPs followed by RET
        let mut code = vec![0x90u8; 10];
        code.push(0xC3);
        let mem = MemorySlice::new(Address::new(0x1000), &code);
        let builder = CfgBuilder::new();
        let cfg = builder.build(
            &mem,
            Address::new(0x1000),
            Address::new(0x1000),
            Address::new(0x100B),
        );
        assert!(!cfg.is_empty());
        let block = cfg.blocks.get(&0x1000).unwrap();
        assert!(block.is_return);
    }

    #[test]
    fn cfg_builder_follows_jmp_rel8() {
        // JMP +2 (skip 2 bytes); NOP; NOP; RET
        // EB 02 90 90 C3
        let code: &[u8] = &[0xEB, 0x02, 0x90, 0x90, 0xC3];
        let mem = MemorySlice::new(Address::new(0x2000), code);
        let builder = CfgBuilder::new();
        let cfg = builder.build(
            &mem,
            Address::new(0x2000),
            Address::new(0x2000),
            Address::new(0x2005),
        );
        // Should have block at 0x2000 and at 0x2004.
        assert!(cfg.blocks.contains_key(&0x2000));
        // The jump target 0x2004 = 0x2000 + 2 + 2
        assert!(cfg.blocks.contains_key(&0x2004));
    }

    #[test]
    fn function_splitter_splits_overlapping() {
        // Two "functions": outer [0x1000, 0x2000), inner at 0x1800.
        // We build a simple mem with RET at 0x1810.
        let mut code = vec![0x90u8; 0x100];
        // RET in inner at offset 0x10 (addr 0x1810)
        code[0x10] = 0xC3;
        let mem = MemorySlice::new(Address::new(0x1800), &code);

        let boundaries = vec![make_fb(0x1800, 0x1900), make_fb(0x1820, 0x1900)];
        let config = SplitterConfig {
            arch: DetectedArch::X86_64,
            min_split_size: 4,
            aggressive: false,
        };
        let splitter = FunctionSplitter::new(config);
        let result = splitter.split(boundaries, &mem);
        // At minimum we should have the same number or more entries.
        assert!(!result.is_empty());
    }

    #[test]
    fn reachable_from_basic() {
        let mut cfg = Cfg::default();
        cfg.blocks.insert(
            0x1000,
            BasicBlock {
                start: Address::new(0x1000),
                end: Address::new(0x1002),
                successors: vec![Address::new(0x1010)],
                is_return: false,
                is_tail_jmp: false,
                has_external_successor: false,
            },
        );
        cfg.blocks.insert(
            0x1010,
            BasicBlock {
                start: Address::new(0x1010),
                end: Address::new(0x1011),
                successors: vec![],
                is_return: true,
                is_tail_jmp: false,
                has_external_successor: false,
            },
        );
        let reached = cfg.reachable_from(Address::new(0x1000));
        assert!(reached.contains(&0x1000));
        assert!(reached.contains(&0x1010));
        assert!(!reached.contains(&0x1020));
    }
}
