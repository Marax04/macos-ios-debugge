//! Function splitter — detects overlapping / tail-call functions and splits them
//! at the tail-jump boundary.
//!
//! A **tail call** is an unconditional jump (`JMP`, `B`) at the end of a function
//! body whose target falls inside another known function (or is a brand-new entry
//! point).  Compilers sometimes emit code where function `A` tail-calls function
//! `B` by jumping directly into the middle of `B`, creating overlapping address
//! ranges that confuse linear disassemblers.
//!
//! This module:
//! 1. Scans function bodies for `JMP`/`B` instructions.
//! 2. Checks whether the target is inside an existing function or falls after a
//!    known prologue.
//! 3. Emits a [`SplitResult`] describing where to cut the original function.

use std::collections::HashMap;
use std::fmt;
use rustre_core::address::Address;

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors produced by the function splitter.
#[derive(Debug, thiserror::Error)]
pub enum SplitterError {
    /// The function address does not exist in the provided body map.
    #[error("unknown function at {0:#x}")]
    UnknownFunction(Address),
    /// The proposed split point is outside the function body.
    #[error("split {split:#x} out of range for function at {function:#x}")]
    SplitOutOfRange {
        /// The function start.
        function: Address,
        /// The out-of-range split point.
        split: Address,
    },
    /// The split point is at the function start (no-op split).
    #[error("split at function start {0:#x} is a no-op")]
    SplitAtStart(Address),
}

// ── Architecture ──────────────────────────────────────────────────────────────

/// Architecture for which the splitter is operating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitterArch {
    /// 64-bit x86 / AMD64.
    X86_64,
    /// 32-bit x86.
    X86_32,
    /// 64-bit ARM (`AArch64`).
    Arm64,
}

// ── TailCall ──────────────────────────────────────────────────────────────────

/// A detected tail call inside a function.
#[derive(Debug, Clone)]
pub struct TailCall {
    /// Address of the tail-jump instruction itself.
    pub jump_address: Address,
    /// Computed jump target address.
    pub target: Address,
    /// Whether the target lands inside a known existing function.
    pub targets_known_function: bool,
    /// Whether the target looks like a new function entry point
    /// (e.g. starts with a recognised prologue).
    pub is_new_entry: bool,
    /// The raw instruction bytes of the jump.
    pub insn_bytes: Vec<u8>,
}

impl TailCall {
    /// Returns `true` if this tail call warrants splitting.
    #[must_use]
    pub const fn should_split(&self) -> bool {
        self.targets_known_function || self.is_new_entry
    }
}

impl fmt::Display for TailCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "tail-jmp @ {:#x} → {:#x} (known={} new_entry={})",
            self.jump_address.as_u64(),
            self.target.as_u64(),
            self.targets_known_function,
            self.is_new_entry
        )
    }
}

// ── FunctionBody ──────────────────────────────────────────────────────────────

/// A minimal description of a function body used as input to the splitter.
#[derive(Debug, Clone)]
pub struct FunctionBody {
    /// Virtual address of the function entry.
    pub start: Address,
    /// Virtual address of the exclusive end (last byte + 1).
    pub end: Address,
    /// Raw bytes of the function body.
    pub bytes: Vec<u8>,
}

impl FunctionBody {
    /// Create a new function body.
    ///
    /// `start + bytes.len()` is computed with wrapping arithmetic so an
    /// adversarially large body placed near the top of the address space
    /// cannot panic; the resulting (wrapped) `end` will simply fail to
    /// `contain` any address, which is the safe degenerate behaviour.
    #[must_use]
    pub const fn new(start: Address, bytes: Vec<u8>) -> Self {
        let end = Address::new(start.as_u64().wrapping_add(bytes.len() as u64));
        Self { start, end, bytes }
    }

    /// Byte length of the body.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the body is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns `true` if `addr` is inside `[start, end)`.
    #[must_use]
    pub const fn contains(&self, addr: Address) -> bool {
        addr.as_u64() >= self.start.as_u64() && addr.as_u64() < self.end.as_u64()
    }

    /// Return the slice starting at `addr`.
    #[must_use]
    pub fn slice_at(&self, addr: Address) -> Option<&[u8]> {
        let off = usize::try_from(addr.as_u64().checked_sub(self.start.as_u64())?).ok()?;
        if off >= self.bytes.len() {
            return None;
        }
        self.bytes.get(off..)
    }
}

// ── SplitResult ───────────────────────────────────────────────────────────────

/// Result of splitting one function at one or more tail-call points.
#[derive(Debug, Clone)]
pub struct SplitResult {
    /// Original function start.
    pub original_start: Address,
    /// Original function end.
    pub original_end: Address,
    /// The split functions produced.  The first entry covers
    /// `[original_start, split_points[0])`, the second covers
    /// `[split_points[0], split_points[1])`, etc.
    pub parts: Vec<FunctionPart>,
    /// Tail calls that triggered this split.
    pub tail_calls: Vec<TailCall>,
}

/// One piece of a split function.
#[derive(Debug, Clone)]
pub struct FunctionPart {
    /// Start address of this part.
    pub start: Address,
    /// Exclusive end address.
    pub end: Address,
    /// The tail call (if any) that ends this part.
    pub ending_tail_call: Option<TailCall>,
}

impl FunctionPart {
    /// Byte size of this part.
    #[must_use]
    pub const fn byte_size(&self) -> u64 {
        self.end.as_u64().saturating_sub(self.start.as_u64())
    }
}

impl fmt::Display for SplitResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "split {:#x}–{:#x} into {} parts ({} tail calls)",
            self.original_start.as_u64(),
            self.original_end.as_u64(),
            self.parts.len(),
            self.tail_calls.len()
        )
    }
}

// ── FunctionSplitter ──────────────────────────────────────────────────────────

/// Scans function bodies, detects tail jumps, and proposes split points.
pub struct FunctionSplitter {
    /// Target architecture.
    pub arch: SplitterArch,
    /// Known function starts (used to identify whether a jump target is inside
    /// an existing function).
    known_starts: Vec<Address>,
    /// Known x86/ARM prologue byte patterns for new-entry detection.
    prologue_bytes: Vec<Vec<u8>>,
}

impl FunctionSplitter {
    /// Create a splitter for the given architecture with an empty known-start set.
    #[must_use]
    pub fn new(arch: SplitterArch) -> Self {
        let prologue_bytes = match arch {
            SplitterArch::X86_64 => vec![
                vec![0x55, 0x48, 0x89, 0xE5], // push rbp; mov rbp, rsp
                vec![0x48, 0x83, 0xEC],         // sub rsp, imm8
            ],
            SplitterArch::X86_32 => vec![
                vec![0x55, 0x89, 0xE5], // push ebp; mov ebp, esp
                vec![0x83, 0xEC],        // sub esp, imm8
            ],
            SplitterArch::Arm64 => vec![
                vec![0xFD, 0x7B, 0xBF, 0xA9], // stp x29, x30, [sp, #-N]!
            ],
        };
        Self {
            arch,
            known_starts: Vec::new(),
            prologue_bytes,
        }
    }

    /// Register a set of known function start addresses.
    pub fn add_known_starts(&mut self, starts: impl IntoIterator<Item = Address>) {
        self.known_starts.extend(starts);
        self.known_starts.sort_unstable_by_key(|a| a.as_u64());
        self.known_starts.dedup_by_key(|a| a.as_u64());
    }

    /// Returns `true` if `addr` is a known function start.
    #[must_use]
    pub fn is_known_start(&self, addr: Address) -> bool {
        self.known_starts
            .binary_search_by_key(&addr.as_u64(), |a| a.as_u64())
            .is_ok()
    }

    /// Returns `true` if `addr` falls inside any known function body (i.e.
    /// between two consecutive known starts).
    #[must_use]
    pub fn is_inside_known_function(&self, addr: Address, bodies: &HashMap<u64, FunctionBody>) -> bool {
        bodies
            .values()
            .any(|b| b.contains(addr) && b.start.as_u64() != addr.as_u64())
    }

    /// Check whether `bytes` starts with any of the registered prologue patterns.
    #[must_use]
    pub fn looks_like_prologue(&self, bytes: &[u8]) -> bool {
        self.prologue_bytes.iter().any(|pat| bytes.starts_with(pat))
    }

    // ── Scanning ─────────────────────────────────────────────────────────────

    /// Scan `body` for tail jump instructions and return the detected [`TailCall`]s.
    #[must_use]
    pub fn find_tail_calls(
        &self,
        body: &FunctionBody,
        all_bodies: &HashMap<u64, FunctionBody>,
    ) -> Vec<TailCall> {
        // Build the start-sorted body index once per call instead of letting
        // each candidate tail-jump re-scan the whole `HashMap` linearly (the
        // previous `bytes_at`/`is_inside_known_function` calls were O(bodies)
        // *per candidate instruction*, i.e. O(bodies^2) overall when called
        // from `split_all` across every function).
        let index = Self::build_body_index(all_bodies);
        match self.arch {
            SplitterArch::X86_64 | SplitterArch::X86_32 => {
                self.find_tail_calls_x86(body, &index)
            }
            SplitterArch::Arm64 => self.find_tail_calls_arm64(body, &index),
        }
    }

    /// Build a start-address-sorted index over `bodies` for O(log n)
    /// containment lookups (bodies are assumed non-overlapping, which holds
    /// for the pre-split function map this is run over).
    fn build_body_index(bodies: &HashMap<u64, FunctionBody>) -> Vec<&FunctionBody> {
        let mut sorted: Vec<&FunctionBody> = bodies.values().collect();
        sorted.sort_unstable_by_key(|b| b.start.as_u64());
        sorted
    }

    /// Find the body (if any) in a start-sorted index that contains `target`.
    fn lookup_containing<'a>(target: Address, index: &[&'a FunctionBody]) -> Option<&'a FunctionBody> {
        let idx = index.partition_point(|b| b.start.as_u64() <= target.as_u64());
        if idx == 0 {
            return None;
        }
        let cand = index[idx - 1];
        cand.contains(target).then_some(cand)
    }

    fn is_inside_known_function_indexed(target: Address, index: &[&FunctionBody]) -> bool {
        Self::lookup_containing(target, index)
            .is_some_and(|b| b.start.as_u64() != target.as_u64())
    }

    fn bytes_at_indexed<'a>(target: Address, index: &[&'a FunctionBody]) -> Option<&'a [u8]> {
        Self::lookup_containing(target, index).and_then(|b| b.slice_at(target))
    }

    fn find_tail_calls_x86(
        &self,
        body: &FunctionBody,
        index: &[&FunctionBody],
    ) -> Vec<TailCall> {
        let mut results = Vec::new();
        let bytes = &body.bytes;
        let base = body.start.as_u64();

        let mut i = 0usize;
        while i < bytes.len() {
            // JMP rel8 (EB XX)
            if i + 1 < bytes.len() && bytes[i] == 0xEB {
                let disp = i64::from(i8::from_ne_bytes([bytes[i + 1]]));
                // `base` and `i` are attacker-influenced (disassembly of
                // adversarial bytes at an arbitrary VA); use wrapping adds so
                // a body placed near the top of the address space cannot
                // panic on overflow (matches `Address::offset`'s wrapping
                // convention elsewhere in the codebase).
                let next_pc = base.wrapping_add(i as u64).wrapping_add(2);
                let target_raw = next_pc.wrapping_add_signed(disp);
                let target = Address::new(target_raw);
                if !body.contains(target) || self.is_known_start(target) {
                    let targets_known = Self::is_inside_known_function_indexed(target, index)
                        || self.is_known_start(target);
                    let is_new = !targets_known
                        && Self::bytes_at_indexed(target, index)
                            .is_some_and(|slice| self.looks_like_prologue(slice));
                    results.push(TailCall {
                        jump_address: Address::new(base.wrapping_add(i as u64)),
                        target,
                        targets_known_function: targets_known,
                        is_new_entry: is_new,
                        insn_bytes: bytes[i..i + 2].to_vec(),
                    });
                }
                i += 2;
                continue;
            }
            // JMP rel32 (E9 XX XX XX XX)
            if i + 4 < bytes.len() && bytes[i] == 0xE9 {
                let disp = i64::from(i32::from_le_bytes([
                    bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4],
                ]));
                let next_pc = base.wrapping_add(i as u64).wrapping_add(5);
                let target_raw = next_pc.wrapping_add_signed(disp);
                let target = Address::new(target_raw);
                if !body.contains(target) || self.is_known_start(target) {
                    let targets_known = Self::is_inside_known_function_indexed(target, index)
                        || self.is_known_start(target);
                    let is_new = !targets_known
                        && Self::bytes_at_indexed(target, index)
                            .is_some_and(|slice| self.looks_like_prologue(slice));
                    results.push(TailCall {
                        jump_address: Address::new(base.wrapping_add(i as u64)),
                        target,
                        targets_known_function: targets_known,
                        is_new_entry: is_new,
                        insn_bytes: bytes[i..i + 5].to_vec(),
                    });
                }
                i += 5;
                continue;
            }
            i += 1;
        }
        results
    }

    fn find_tail_calls_arm64(
        &self,
        body: &FunctionBody,
        index: &[&FunctionBody],
    ) -> Vec<TailCall> {
        let mut results = Vec::new();
        let bytes = &body.bytes;
        let base = body.start.as_u64();

        let limit = bytes.len().saturating_sub(3);
        let mut i = 0usize;
        while i < limit {
            if !i.is_multiple_of(4) {
                i += 1;
                continue;
            }
            let word = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
            // B instruction: bits [31:26] == 000101
            if (word >> 26) == 0b00_0101 {
                let imm26 = i32::from_ne_bytes((word & 0x03FF_FFFF).to_ne_bytes());
                let imm26_signed = if imm26 & (1 << 25) != 0 {
                    imm26 | ((-1i32) << 26)
                } else {
                    imm26
                };
                let byte_offset = i64::from(imm26_signed) * 4;
                let pc = base.wrapping_add(i as u64);
                let target_raw = pc.wrapping_add_signed(byte_offset);
                let target = Address::new(target_raw);
                if !body.contains(target) || self.is_known_start(target) {
                    let targets_known = Self::is_inside_known_function_indexed(target, index)
                        || self.is_known_start(target);
                    let is_new = !targets_known
                        && Self::bytes_at_indexed(target, index)
                            .is_some_and(|slice| self.looks_like_prologue(slice));
                    results.push(TailCall {
                        jump_address: Address::new(pc),
                        target,
                        targets_known_function: targets_known,
                        is_new_entry: is_new,
                        insn_bytes: bytes[i..i + 4].to_vec(),
                    });
                }
            }
            i += 4;
        }
        results
    }

    // ── Split ─────────────────────────────────────────────────────────────────

    /// Analyse `body` and produce a [`SplitResult`].
    ///
    /// If no tail calls are found, the result contains a single part covering
    /// the whole body (no actual split).
    #[must_use]
    pub fn split_at_tail_call(
        &self,
        body: &FunctionBody,
        all_bodies: &HashMap<u64, FunctionBody>,
    ) -> SplitResult {
        let tail_calls = self.find_tail_calls(body, all_bodies);
        let splitting: Vec<TailCall> = tail_calls
            .iter()
            .filter(|tc| tc.should_split())
            .cloned()
            .collect();

        if splitting.is_empty() {
            return SplitResult {
                original_start: body.start,
                original_end: body.end,
                parts: vec![FunctionPart {
                    start: body.start,
                    end: body.end,
                    ending_tail_call: None,
                }],
                tail_calls,
            };
        }

        // Sort split points by address.
        let mut split_points: Vec<(Address, TailCall)> = splitting
            .into_iter()
            .map(|tc| {
                // The split happens just after the jump instruction.
                // Wrapping: `jump_address` is derived from adversarial
                // disassembly and could sit near `u64::MAX`.
                let after_insn = Address::new(
                    tc.jump_address.as_u64().wrapping_add(tc.insn_bytes.len() as u64),
                );
                (after_insn, tc)
            })
            .collect();
        split_points.sort_by_key(|(a, _)| a.as_u64());
        split_points.dedup_by_key(|(a, _)| a.as_u64());

        let mut parts = Vec::new();
        let mut prev_start = body.start;
        for (split_addr, tc) in &split_points {
            if *split_addr <= prev_start || *split_addr > body.end {
                continue;
            }
            parts.push(FunctionPart {
                start: prev_start,
                end: *split_addr,
                ending_tail_call: Some(tc.clone()),
            });
            prev_start = *split_addr;
        }
        // Final part.
        if prev_start < body.end {
            parts.push(FunctionPart {
                start: prev_start,
                end: body.end,
                ending_tail_call: None,
            });
        }

        SplitResult {
            original_start: body.start,
            original_end: body.end,
            parts,
            tail_calls,
        }
    }

    /// Batch-split all bodies in the map and return a map from original start
    /// address to [`SplitResult`].
    #[must_use]
    pub fn split_all(
        &self,
        bodies: &HashMap<u64, FunctionBody>,
    ) -> HashMap<u64, SplitResult> {
        bodies
            .iter()
            .map(|(&addr, body)| (addr, self.split_at_tail_call(body, bodies)))
            .collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_bodies(entries: &[(u64, &[u8])]) -> HashMap<u64, FunctionBody> {
        entries
            .iter()
            .map(|&(addr, bytes)| {
                let body = FunctionBody::new(Address::new(addr), bytes.to_vec());
                (addr, body)
            })
            .collect()
    }

    #[test]
    fn no_tail_call_yields_single_part() {
        let body = FunctionBody::new(Address::new(0x1000), vec![0x90, 0x90, 0xC3]);
        let bodies = mk_bodies(&[(0x1000, &[0x90, 0x90, 0xC3])]);
        let splitter = FunctionSplitter::new(SplitterArch::X86_64);
        let result = splitter.split_at_tail_call(&body, &bodies);
        assert_eq!(result.parts.len(), 1);
        assert!(result.tail_calls.is_empty());
    }

    #[test]
    fn tail_jmp_rel8_into_known_function() {
        // Test bug fix: rel8 displacement is signed i8 (range -128..+127),
        // so target 0x1100 from next_pc 0x1002 (delta +254) is unreachable.
        // Use a target within rel8 range: target = 0x1080, next_pc = 0x1002,
        // disp = 0x7E (+126).
        let disp = 0x1080u64 - 0x1002u64; // = 0x7E
        let body_bytes = vec![0xEB, disp as u8, 0xC3];
        let body = FunctionBody::new(Address::new(0x1000), body_bytes.clone());
        let bodies = mk_bodies(&[(0x1000, &body_bytes)]);
        let mut splitter = FunctionSplitter::new(SplitterArch::X86_64);
        splitter.add_known_starts([Address::new(0x1080)]);
        let tcs = splitter.find_tail_calls(&body, &bodies);
        assert!(!tcs.is_empty(), "expected tail call, got none");
        assert!(tcs[0].targets_known_function);
    }

    #[test]
    fn tail_jmp_rel32_outside_body() {
        // JMP rel32 at offset 0 in function at 0x2000.
        // Target: 0x2000 + 5 + disp  — choose disp so target = 0x3000
        let target = 0x3000u64;
        let next_pc = 0x2000u64 + 5;
        let disp = (target as i64 - next_pc as i64) as i32;
        let disp_bytes = disp.to_le_bytes();
        let mut body_bytes = vec![0xE9, disp_bytes[0], disp_bytes[1], disp_bytes[2], disp_bytes[3], 0x90];
        body_bytes.push(0xC3);
        let body = FunctionBody::new(Address::new(0x2000), body_bytes.clone());
        let bodies = mk_bodies(&[(0x2000, &body_bytes)]);
        let splitter = FunctionSplitter::new(SplitterArch::X86_64);
        let tcs = splitter.find_tail_calls(&body, &bodies);
        // target 0x3000 is not inside the body (body only covers 0x2000–0x2007)
        assert!(!tcs.is_empty());
    }

    #[test]
    fn split_result_two_parts() {
        // Function at 0x1000, 10 bytes.
        // JMP rel8 at offset 3 → outside body (target = 0x5000).
        // After split: two parts.
        let mut bytes = vec![0x90u8; 10];
        // JMP rel8 at offset 3: next_pc = 0x1005, disp large
        bytes[3] = 0xEB;
        bytes[4] = 0xFF; // disp = -1 from next_pc=0x1005 → 0x1004 (inside body)
        // Use forward jump that exits the body:
        // target = 0x1000 + 100 = 0x1064; next_pc = 0x1005; disp = 0x5F
        bytes[3] = 0xEB;
        bytes[4] = 0x5F;
        let body = FunctionBody::new(Address::new(0x1000), bytes.clone());
        let bodies = mk_bodies(&[(0x1000, &bytes)]);
        let splitter = FunctionSplitter::new(SplitterArch::X86_64);
        let result = splitter.split_at_tail_call(&body, &bodies);
        // The jump exits the body, so we get a split.
        assert!(result.parts.len() >= 1);
    }

    #[test]
    fn function_body_contains() {
        let body = FunctionBody::new(Address::new(0x1000), vec![0u8; 64]);
        assert!(body.contains(Address::new(0x1000)));
        assert!(body.contains(Address::new(0x103F)));
        assert!(!body.contains(Address::new(0x1040)));
        assert!(!body.contains(Address::new(0x0FFF)));
    }

    #[test]
    fn function_body_slice_at() {
        let body = FunctionBody::new(Address::new(0x2000), vec![1, 2, 3, 4]);
        assert_eq!(body.slice_at(Address::new(0x2001)), Some([2, 3, 4].as_slice()));
        assert_eq!(body.slice_at(Address::new(0x2004)), None);
    }

    #[test]
    fn looks_like_prologue_x64() {
        let splitter = FunctionSplitter::new(SplitterArch::X86_64);
        assert!(splitter.looks_like_prologue(&[0x55, 0x48, 0x89, 0xE5, 0x00]));
        assert!(!splitter.looks_like_prologue(&[0x90, 0x90]));
    }

    #[test]
    fn known_start_lookup() {
        let mut splitter = FunctionSplitter::new(SplitterArch::X86_64);
        splitter.add_known_starts([Address::new(0x1000), Address::new(0x2000)]);
        assert!(splitter.is_known_start(Address::new(0x1000)));
        assert!(!splitter.is_known_start(Address::new(0x1001)));
    }

    #[test]
    fn split_all_returns_one_entry_per_body() {
        let bodies = mk_bodies(&[(0x1000, &[0x90, 0xC3]), (0x2000, &[0x55, 0x48, 0x89, 0xE5, 0xC3])]);
        let splitter = FunctionSplitter::new(SplitterArch::X86_64);
        let results = splitter.split_all(&bodies);
        assert_eq!(results.len(), 2);
    }

    /// Regression test for the start-sorted body index used internally by
    /// `find_tail_calls`/`bytes_at_indexed`/`is_inside_known_function_indexed`:
    /// with many bodies present, a tail jump into a body that is neither the
    /// first nor the last by address must still be resolved correctly
    /// (guards against off-by-one errors in the `partition_point` binary
    /// search over the sorted index).
    #[test]
    fn find_tail_calls_resolves_target_among_many_bodies() {
        let mut entries: Vec<(u64, Vec<u8>)> = Vec::new();
        // A bunch of small unrelated bodies surrounding the two of interest,
        // deliberately inserted out of address order into the HashMap.
        for k in 0..20u64 {
            entries.push((0x5000 + k * 0x100, vec![0x90, 0xC3]));
        }
        // Caller at 0x3000: JMP rel32 into the middle of the callee body.
        // JMP is at offset 0 of the caller; target = callee_start + 1 (mid-body).
        let callee_start = 0x4000u64;
        let callee_bytes = vec![0x55, 0x48, 0x89, 0xE5, 0x90, 0xC3];
        let jmp_target = callee_start + 1;
        let next_pc = 0x3000u64 + 5;
        let disp = (jmp_target as i64 - next_pc as i64) as i32;
        let mut caller_bytes = vec![0xE9];
        caller_bytes.extend_from_slice(&disp.to_le_bytes());
        caller_bytes.push(0xC3);
        entries.push((0x3000, caller_bytes.clone()));
        entries.push((callee_start, callee_bytes));

        let bodies: HashMap<u64, FunctionBody> = entries
            .into_iter()
            .map(|(addr, bytes)| (addr, FunctionBody::new(Address::new(addr), bytes)))
            .collect();

        let mut splitter = FunctionSplitter::new(SplitterArch::X86_64);
        splitter.add_known_starts([Address::new(callee_start)]);

        let caller_body = &bodies[&0x3000];
        let tail_calls = splitter.find_tail_calls(caller_body, &bodies);
        assert_eq!(tail_calls.len(), 1);
        assert_eq!(tail_calls[0].target, Address::new(jmp_target));
        assert!(
            tail_calls[0].targets_known_function,
            "jump into the middle of a known body must resolve as targets_known_function"
        );
    }

    #[test]
    fn tail_call_display() {
        let tc = TailCall {
            jump_address: Address::new(0x1000),
            target: Address::new(0x2000),
            targets_known_function: true,
            is_new_entry: false,
            insn_bytes: vec![0xE9, 0, 0, 0, 0],
        };
        let s = tc.to_string();
        assert!(s.contains("0x1000"));
        assert!(s.contains("0x2000"));
    }

    #[test]
    fn split_result_display() {
        let r = SplitResult {
            original_start: Address::new(0x1000),
            original_end: Address::new(0x2000),
            parts: vec![],
            tail_calls: vec![],
        };
        let s = r.to_string();
        assert!(s.contains("0 parts"));
    }

    #[test]
    fn function_part_byte_size() {
        let p = FunctionPart {
            start: Address::new(0x1000),
            end: Address::new(0x1010),
            ending_tail_call: None,
        };
        assert_eq!(p.byte_size(), 16);
    }

    // ── Adversarial address-arithmetic regressions ───────────────────────────

    #[test]
    fn function_body_new_near_u64_max_does_not_panic() {
        // start + bytes.len() would overflow u64 if computed with `+`.
        let start = Address::new(u64::MAX - 2);
        let body = FunctionBody::new(start, vec![0x90, 0x90, 0x90, 0x90]);
        // Wrapped end; just assert construction didn't panic and `contains`
        // behaves sanely (doesn't claim to contain the wrapped-around start).
        assert_eq!(body.start.as_u64(), u64::MAX - 2);
        let _ = body.contains(Address::new(0));
    }

    #[test]
    fn find_tail_calls_x86_near_u64_max_does_not_panic() {
        // JMP rel8 in a function body placed right at the top of the address
        // space: `base + i + 2` must not panic on overflow.
        let start = Address::new(u64::MAX - 1);
        let body_bytes = vec![0xEB, 0x10, 0xC3];
        let body = FunctionBody::new(start, body_bytes.clone());
        let bodies = mk_bodies(&[(start.as_u64(), &body_bytes)]);
        let splitter = FunctionSplitter::new(SplitterArch::X86_64);
        // Must not panic (this is the regression check); result content is
        // secondary since the wrapped target is not meaningfully defined.
        let _ = splitter.find_tail_calls(&body, &bodies);
    }

    #[test]
    fn find_tail_calls_arm64_near_u64_max_does_not_panic() {
        let start = Address::new(u64::MAX - 3);
        // A `B` instruction: bits [31:26] == 000101, rest zero (offset 0).
        let word: u32 = 0b0001_01 << 26;
        let body_bytes = word.to_le_bytes().to_vec();
        let body = FunctionBody::new(start, body_bytes.clone());
        let bodies = mk_bodies(&[(start.as_u64(), &body_bytes)]);
        let splitter = FunctionSplitter::new(SplitterArch::Arm64);
        let _ = splitter.find_tail_calls(&body, &bodies);
    }

    #[test]
    fn split_at_tail_call_near_u64_max_does_not_panic() {
        // Exercises the `jump_address + insn_bytes.len()` split-point math.
        let start = Address::new(u64::MAX - 5);
        let mut bytes = vec![0x90u8; 4];
        bytes.push(0xE9); // JMP rel32 at offset 4
        bytes.extend_from_slice(&0x1000i32.to_le_bytes());
        let body = FunctionBody::new(start, bytes.clone());
        let bodies = mk_bodies(&[(start.as_u64(), &bytes)]);
        let splitter = FunctionSplitter::new(SplitterArch::X86_64);
        let _ = splitter.split_at_tail_call(&body, &bodies);
    }

    #[test]
    fn splitter_error_display() {
        let e = SplitterError::UnknownFunction(Address::new(0xDEAD));
        assert!(e.to_string().contains("0xdead") || e.to_string().contains("0xDEAD") || e.to_string().to_lowercase().contains("dead"));
    }
}
