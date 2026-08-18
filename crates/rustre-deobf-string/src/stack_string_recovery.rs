//! `stack_string_recovery` — Recovery of stack-allocated strings.
//!
//! Identifies sequential byte-push patterns and byte-level assignments to local
//! variables, extracts the assembled string, and can substitute a string literal
//! back into the pseudocode representation.

use crate::RecoveredString;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// StackByte — a single byte assignment to a stack slot
// ─────────────────────────────────────────────────────────────────────────────

/// A single byte assignment observed in the instruction stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackByte {
    /// Offset within the local variable / stack frame (0 = first byte).
    pub frame_offset: i32,
    /// The byte value being assigned.
    pub value: u8,
    /// Virtual address of the instruction that performs the assignment.
    pub insn_addr: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// StackStringPattern — describes one detected stack-string construction
// ─────────────────────────────────────────────────────────────────────────────

/// The way bytes are placed on the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlacementStyle {
    /// Sequential `mov [rbp-N], imm8` / `mov [rsp+N], imm8` instructions.
    MovImm8,
    /// Wide character (2-byte) placement (`mov [rbp-N], imm16`).
    MovImm16Wide,
    /// `push imm8` followed by single-byte reads.
    PushImm8,
    /// Placement via `xor` + `mov` (common in obfuscated code).
    XorMov,
    /// Detected DWORD-at-a-time placement (4 bytes per instruction).
    MovImm32,
}

/// One recovered stack string with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackStringPattern {
    /// Start virtual address (first assignment instruction).
    pub start_addr: u64,
    /// End virtual address (last assignment instruction).
    pub end_addr: u64,
    /// Stack frame base register name (`rbp`, `rsp`, `ebp`, …).
    pub frame_register: String,
    /// Base frame offset of the first byte.
    pub base_offset: i32,
    /// Recovered bytes (NUL-terminated strings will include the terminator).
    pub bytes: Vec<u8>,
    /// Placement style detected.
    pub style: PlacementStyle,
    /// Number of assignment instructions in the sequence.
    pub instruction_count: usize,
}

impl StackStringPattern {
    /// Attempt to decode the bytes as UTF-8 (or lossy).
    #[must_use]
    pub fn as_str_lossy(&self) -> String {
        // Strip trailing NUL bytes
        let trimmed = self.bytes.iter().rev().skip_while(|&&b| b == 0).count();
        let relevant = &self.bytes[..self.bytes.len() - (self.bytes.len() - trimmed)
            .min(self.bytes.len())];
        String::from_utf8_lossy(relevant).into_owned()
    }

    /// Whether the recovered bytes look like a printable ASCII string.
    #[must_use]
    pub fn is_ascii_printable(&self) -> bool {
        self.bytes
            .iter()
            .filter(|&&b| b != 0)
            .all(|&b| b >= 0x20 && b <= 0x7E)
    }

    /// Convert to a [`RecoveredString`].
    #[must_use]
    pub fn to_recovered(&self) -> RecoveredString {
        RecoveredString {
            offset: self.start_addr,
            value: self.as_str_lossy(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StackByteSorter — assembles sorted bytes into a string
// ─────────────────────────────────────────────────────────────────────────────

/// Accumulates stack bytes (potentially out of order) and assembles them.
#[derive(Debug, Default)]
pub struct StackByteSorter {
    entries: Vec<StackByte>,
}

impl StackByteSorter {
    /// Add a byte assignment.
    pub fn push(&mut self, sb: StackByte) {
        self.entries.push(sb);
    }

    /// Check whether the entries form a contiguous range starting at `base_offset`.
    #[must_use]
    pub fn is_contiguous(&self) -> bool {
        if self.entries.is_empty() {
            return false;
        }
        let mut offsets: Vec<i32> = self.entries.iter().map(|e| e.frame_offset).collect();
        offsets.sort_unstable();
        offsets.dedup();
        let min = *offsets.first().unwrap();
        let max = *offsets.last().unwrap();
        (max - min + 1) as usize == offsets.len()
    }

    /// Assemble bytes sorted by frame offset, returning the assembled Vec.
    #[must_use]
    pub fn assemble(&self) -> Vec<u8> {
        if self.entries.is_empty() {
            return vec![];
        }
        let mut sorted = self.entries.clone();
        sorted.sort_by_key(|e| e.frame_offset);
        sorted.iter().map(|e| e.value).collect()
    }

    /// Minimum frame offset seen.
    #[must_use]
    pub fn base_offset(&self) -> i32 {
        self.entries
            .iter()
            .map(|e| e.frame_offset)
            .min()
            .unwrap_or(0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StackStringScanner — high-level scanner
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the stack string scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackScanConfig {
    /// Minimum number of byte assignments to consider a stack string.
    pub min_bytes: usize,
    /// Maximum number of bytes in a single stack string.
    pub max_bytes: usize,
    /// Maximum instruction gap (in addresses) between consecutive assignments
    /// before the sequence is considered broken.
    pub max_addr_gap: u64,
    /// Whether to include wide-char (UTF-16 LE) strings.
    pub include_wide: bool,
    /// Minimum printable ASCII ratio for the recovered string to be kept.
    pub min_printable_ratio: f32,
}

impl Default for StackScanConfig {
    fn default() -> Self {
        Self {
            min_bytes: 4,
            max_bytes: 4096,
            max_addr_gap: 256,
            include_wide: true,
            min_printable_ratio: 0.70,
        }
    }
}

/// Abstract instruction representation for stack-string scanning.
///
/// Callers (lifted IL consumers) produce these from the decoded instruction stream.
#[derive(Debug, Clone)]
pub struct ByteAssignment {
    /// Instruction virtual address.
    pub insn_addr: u64,
    /// Frame register (e.g. `"rbp"`, `"rsp"`, `"ebp"`).
    pub frame_register: String,
    /// Offset from frame register.
    pub offset: i32,
    /// The byte (or bytes for wide-char) assigned.
    pub bytes: Vec<u8>,
    /// Placement style.
    pub style: PlacementStyle,
}

/// High-level stack string scanner.
pub struct StackStringScanner {
    config: StackScanConfig,
}

impl StackStringScanner {
    #[must_use]
    pub const fn new(config: StackScanConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(StackScanConfig::default())
    }

    /// Scan a sorted sequence of [`ByteAssignment`]s and return all detected patterns.
    #[must_use]
    pub fn scan(&self, assignments: &[ByteAssignment]) -> Vec<StackStringPattern> {
        if assignments.is_empty() {
            return vec![];
        }

        // Group by (frame_register, base_region).
        // A "base_region" is the minimum offset within a window.
        let mut groups: std::collections::HashMap<(String, i32), Vec<&ByteAssignment>> =
            std::collections::HashMap::new();

        for a in assignments {
            // Round base to nearest 0x10 block for grouping
            let region_base = (a.offset / 0x100) * 0x100;
            groups
                .entry((a.frame_register.clone(), region_base))
                .or_default()
                .push(a);
        }

        let mut patterns = Vec::new();

        for ((frame_reg, _), mut group) in groups {
            group.sort_by_key(|a| (a.insn_addr, a.offset));

            // Split group at gaps
            let mut current: Vec<&ByteAssignment> = Vec::new();

            for a in &group {
                if let Some(last) = current.last() {
                    let addr_gap = a.insn_addr.saturating_sub(last.insn_addr);
                    let offset_gap = (a.offset - last.offset).abs();
                    if addr_gap > self.config.max_addr_gap || offset_gap > 256 {
                        if current.len() >= self.config.min_bytes {
                            if let Some(p) = self.build_pattern(&frame_reg, &current) {
                                patterns.push(p);
                            }
                        }
                        current.clear();
                    }
                }
                current.push(a);
            }

            if current.len() >= self.config.min_bytes {
                if let Some(p) = self.build_pattern(&frame_reg, &current) {
                    patterns.push(p);
                }
            }
        }

        patterns.sort_by_key(|p| p.start_addr);
        patterns
    }

    fn build_pattern(
        &self,
        frame_reg: &str,
        group: &[&ByteAssignment],
    ) -> Option<StackStringPattern> {
        if group.is_empty() {
            return None;
        }

        let start_addr = group.first().unwrap().insn_addr;
        let end_addr = group.last().unwrap().insn_addr;
        let base_offset = group.iter().map(|a| a.offset).min().unwrap_or(0);

        // Assemble bytes sorted by offset, keeping the LAST write to each slot.
        //
        // A store REPLACES what was there: obfuscators write decoy bytes and
        // overwrite them precisely to defeat naive recovery, so this is the
        // case the pass exists for.
        //
        // The previous version sorted `(offset, byte)` pairs and deduplicated
        // them. Both steps have implicit behaviour that combined to keep the
        // WRONG write: `sort_by_key` is STABLE, so equal offsets stayed in
        // their original order (ascending `insn_addr`), and `dedup_by_key`
        // keeps the FIRST of each run — so the EARLIEST write survived and
        // `"XXXX"` overwritten by `"Hi! "` was recovered as `"XXXX"`.
        //
        // Carrying `insn_addr` into the tuple and ordering it DESCENDING within
        // an offset makes the most recent write the one `dedup_by_key` keeps.
        let mut byte_slots: Vec<(i32, u64, u8)> = group
            .iter()
            .flat_map(|a| {
                a.bytes
                    .iter()
                    .enumerate()
                    .map(|(i, &b)| (a.offset + i as i32, a.insn_addr, b))
                    .collect::<Vec<_>>()
            })
            .collect();
        byte_slots.sort_by(|x, y| x.0.cmp(&y.0).then(y.1.cmp(&x.1)));
        byte_slots.dedup_by_key(|(off, _, _)| *off);

        let bytes: Vec<u8> = byte_slots.into_iter().map(|(_, _, b)| b).collect();

        if bytes.len() > self.config.max_bytes || bytes.len() < self.config.min_bytes {
            return None;
        }

        // Printability check
        let printable = bytes.iter().filter(|&&b| b == 0 || (b >= 0x20 && b <= 0x7E)).count();
        let ratio = printable as f32 / bytes.len() as f32;
        if ratio < self.config.min_printable_ratio {
            // Try wide-char
            if self.config.include_wide {
                let wide_ok = is_utf16_le(&bytes);
                if !wide_ok {
                    return None;
                }
            } else {
                return None;
            }
        }

        let style = group
            .first()
            .map(|a| a.style)
            .unwrap_or(PlacementStyle::MovImm8);

        Some(StackStringPattern {
            start_addr,
            end_addr,
            frame_register: frame_reg.to_string(),
            base_offset,
            bytes,
            style,
            instruction_count: group.len(),
        })
    }
}

/// Heuristic: check if `bytes` looks like a UTF-16 LE string.
fn is_utf16_le(bytes: &[u8]) -> bool {
    if bytes.len() < 4 || bytes.len() % 2 != 0 {
        return false;
    }
    let printable = bytes
        .chunks(2)
        .filter(|w| {
            let codepoint = u16::from_le_bytes([w[0], w[1]]);
            codepoint == 0 || (codepoint >= 0x0020 && codepoint <= 0x007E)
        })
        .count();
    printable as f32 / (bytes.len() / 2) as f32 >= 0.70
}

// ─────────────────────────────────────────────────────────────────────────────
// PseudocodeRewriter — substitutes detected stack strings into pseudocode
// ─────────────────────────────────────────────────────────────────────────────

/// Represents a line of pseudocode (simplified model).
#[derive(Debug, Clone)]
pub struct PseudocodeLine {
    pub addr: u64,
    pub text: String,
}

/// Rewrites pseudocode lines by substituting stack string assignments with
/// a single string literal assignment.
pub struct PseudocodeRewriter {
    patterns: Vec<StackStringPattern>,
}

impl PseudocodeRewriter {
    #[must_use]
    pub const fn new(patterns: Vec<StackStringPattern>) -> Self {
        Self { patterns }
    }

    /// Rewrite `lines`: lines covered by a stack string pattern are replaced by
    /// a single `char* var = "recovered_string";` line; the rest are kept.
    #[must_use]
    pub fn rewrite(&self, lines: Vec<PseudocodeLine>) -> Vec<PseudocodeLine> {
        let mut result = Vec::new();
        let mut skip_until: u64 = 0;

        for line in &lines {
            if line.addr < skip_until {
                continue;
            }
            // Check if this line starts a stack string pattern
            if let Some(pat) = self
                .patterns
                .iter()
                .find(|p| p.start_addr == line.addr)
            {
                let s = pat.as_str_lossy();
                let safe = s.replace('\\', "\\\\").replace('"', "\\\"");
                result.push(PseudocodeLine {
                    addr: line.addr,
                    text: format!(
                        "  // [stack-string recovered: {} bytes] char *s = \"{}\";",
                        pat.bytes.len(),
                        safe
                    ),
                });
                skip_until = pat.end_addr + 1;
            } else {
                result.push(line.clone());
            }
        }
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_assignment(addr: u64, reg: &str, offset: i32, byte: u8) -> ByteAssignment {
        ByteAssignment {
            insn_addr: addr,
            frame_register: reg.into(),
            offset,
            bytes: vec![byte],
            style: PlacementStyle::MovImm8,
        }
    }

    #[test]
    fn test_stack_string_scan() {
        let msg = b"Hello\0";
        // The i-th character of a string sits at a HIGHER address than the
        // (i-1)-th. This fixture used `-(8 + i)`, which puts 'H' at rbp-8 and
        // the terminator at rbp-13 — a LOWER address — so the bytes in memory
        // spell "\0olleH" and the recovery, which correctly orders by offset,
        // could never produce "Hello". The layout was backwards, not the code.
        let base = -(8 + msg.len() as i32 - 1);
        let assignments: Vec<ByteAssignment> = msg
            .iter()
            .enumerate()
            .map(|(i, &b)| make_assignment(0x1000 + i as u64 * 4, "rbp", base + i as i32, b))
            .collect();

        let scanner = StackStringScanner::with_defaults();
        let patterns = scanner.scan(&assignments);
        assert!(!patterns.is_empty(), "should detect stack string");
        let p = &patterns[0];
        assert!(p.as_str_lossy().contains("Hello"), "recovered: {}", p.as_str_lossy());
    }

    #[test]
    fn test_stack_byte_sorter_assemble() {
        let mut sorter = StackByteSorter::default();
        sorter.push(StackByte { frame_offset: -8, value: b'A', insn_addr: 0x100 });
        sorter.push(StackByte { frame_offset: -7, value: b'B', insn_addr: 0x104 });
        sorter.push(StackByte { frame_offset: -6, value: b'C', insn_addr: 0x108 });
        assert!(sorter.is_contiguous());
        assert_eq!(sorter.assemble(), b"ABC".to_vec());
    }

    #[test]
    fn test_is_utf16_le() {
        // "AB" in UTF-16 LE
        let wide = b"\x41\x00\x42\x00\x00\x00";
        assert!(is_utf16_le(wide));
    }
}
