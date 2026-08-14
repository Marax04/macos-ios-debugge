//! `disassembler.rs` — MSP430 disassembler.
//!
//! Provides three entry points:
//!
//! * [`disassemble_linear`]    — sweep every two bytes from start to end.
//! * [`disassemble_recursive`] — follow CALLs and branches (limited depth).
//! * [`format_insn`]           — render an [`Msp430Insn`] in AT&T syntax.
//!
//! The AT&T syntax used here:
//!
//! ```text
//! MOV.W  #0x1234,R5
//! ADD.B  @R4+,0x10(R6)
//! JNE    0x403C
//! CALL   #0x4400
//! ```

use std::collections::{BTreeMap, HashSet, VecDeque};

use crate::decoder::{Msp430Insn, decode_insn};
pub use rustre_core::errors::CoreError;

// ── Disassembled line ─────────────────────────────────────────────────────────

/// One disassembled instruction with its address and formatted text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisasmLine {
    /// Address of this instruction.
    pub addr: u64,
    /// Total instruction byte width.
    pub size: usize,
    /// Raw bytes (up to 6).
    pub bytes: Vec<u8>,
    /// Formatted text (AT&T style).
    pub text: String,
    /// Branch/call target if statically known.
    pub target: Option<u64>,
}

impl DisasmLine {
    /// Create a `DisasmLine` from an [`Msp430Insn`] and the raw byte slice.
    #[must_use]
    pub fn from_insn(insn: &Msp430Insn, raw: &[u8]) -> Self {
        let bytes = raw[..insn.size.min(raw.len())].to_vec();
        let text = format_insn(insn);
        let target = insn.branch_target().or_else(|| {
            // For CALLs, the target is encoded in the source operand if it's an immediate.
            if insn.is_call()
                && let crate::decoder::InsnKind::OneOp { src, .. } = &insn.kind {
                    return src.ext.map(u64::from);
                }
            None
        });
        Self {
            addr: insn.addr,
            size: insn.size,
            bytes,
            text,
            target,
        }
    }
}

// ── Linear disassembler ───────────────────────────────────────────────────────

/// Perform a linear sweep disassembly of `bytes` starting at `base_addr`.
///
/// Every 2-byte-aligned word is decoded in sequence.  On decode failure the
/// word is emitted as `DC.W 0x????` and the sweep advances by 2 bytes.
///
/// Returns `Ok(lines)` on success.  An empty slice yields an empty Vec.
///
/// # Errors
/// Never returns an error — decode failures are represented as `DC.W` lines.
#[must_use] 
pub fn disassemble_linear(bytes: &[u8], base_addr: u64) -> Vec<DisasmLine> {
    let mut result = Vec::with_capacity(bytes.len() / 3);
    let mut off = 0usize;
    while off + 1 < bytes.len() {
        let addr = base_addr + off as u64;
        let slice = &bytes[off..];
        if let Ok(insn) = decode_insn(slice, addr) {
            let line = DisasmLine::from_insn(&insn, slice);
            off += insn.size;
            result.push(line);
        } else {
            let word = u16::from_le_bytes([bytes[off], bytes[off + 1]]);
            result.push(DisasmLine {
                addr,
                size: 2,
                bytes: bytes[off..off + 2].to_vec(),
                text: format!("DC.W\t0x{word:04X}"),
                target: None,
            });
            off += 2;
        }
    }
    result
}

// ── Recursive disassembler ────────────────────────────────────────────────────

/// Configuration for the recursive disassembler.
#[derive(Debug, Clone)]
pub struct RecursiveConfig {
    /// Maximum number of basic blocks to disassemble.
    pub max_blocks: usize,
    /// Whether to follow CALL targets (adds entry to work-list).
    pub follow_calls: bool,
    /// Whether to follow conditional branches.
    pub follow_conditionals: bool,
}

impl Default for RecursiveConfig {
    fn default() -> Self {
        Self {
            max_blocks: 256,
            follow_calls: true,
            follow_conditionals: true,
        }
    }
}

/// Result of a recursive disassembly pass.
#[derive(Debug, Default)]
pub struct RecursiveResult {
    /// All disassembled lines, keyed by address.
    pub lines: BTreeMap<u64, DisasmLine>,
    /// Entry points discovered (initial + call targets).
    pub entries: HashSet<u64>,
    /// Number of basic blocks decoded.
    pub block_count: usize,
}

impl RecursiveResult {
    /// Return all lines sorted by address.
    #[must_use]
    pub fn sorted_lines(&self) -> Vec<&DisasmLine> {
        self.lines.values().collect()
    }
}

/// Recursive (branch-following) disassembler.
///
/// Starting from `entry`, decode instructions until a terminator is reached,
/// then enqueue branch/call targets and repeat.
///
/// `bytes` is the flat image buffer; addresses are computed as
/// `base_addr + offset_into_bytes`.
///
/// # Errors
/// Never returns `Err` — all per-instruction failures are represented as
/// `DC.W` lines.
#[must_use] 
pub fn disassemble_recursive(
    bytes: &[u8],
    base_addr: u64,
    entry: u64,
    cfg: &RecursiveConfig,
) -> RecursiveResult {
    let mut result = RecursiveResult::default();
    let mut worklist: VecDeque<u64> = VecDeque::new();
    let mut visited_blocks: HashSet<u64> = HashSet::new();

    worklist.push_back(entry);
    result.entries.insert(entry);

    while let Some(block_start) = worklist.pop_front() {
        if visited_blocks.contains(&block_start) {
            continue;
        }
        if result.block_count >= cfg.max_blocks {
            break;
        }

        // Bounds check.
        if block_start < base_addr || block_start >= base_addr + bytes.len() as u64 {
            continue;
        }

        visited_blocks.insert(block_start);
        result.block_count += 1;

        let mut cur = block_start;

        loop {
            if cur < base_addr || cur >= base_addr + bytes.len() as u64 {
                break;
            }
            let off = usize::try_from(cur - base_addr).unwrap_or(usize::MAX);
            let slice = &bytes[off..];

            let Ok(insn) = decode_insn(slice, cur) else {
                // Emit DC.W and stop block.
                let word = if slice.len() >= 2 {
                    u16::from_le_bytes([slice[0], slice[1]])
                } else {
                    0
                };
                result.lines.entry(cur).or_insert_with(|| DisasmLine {
                    addr: cur,
                    size: 2,
                    bytes: slice.get(..2).unwrap_or(&[]).to_vec(),
                    text: format!("DC.W\t0x{word:04X}"),
                    target: None,
                });
                break;
            };

            let is_term = insn.is_terminator();
            let is_call = insn.is_call();
            let is_cond = insn.is_conditional();
            let target = insn.branch_target();
            let next = cur + insn.size as u64;

            let line = DisasmLine::from_insn(&insn, slice);
            result.lines.entry(cur).or_insert(line);

            cur = next;

            if is_term {
                // Enqueue branch targets.
                if let Some(t) = target
                    && !visited_blocks.contains(&t) {
                        worklist.push_back(t);
                    }
                // Conditional branches also fall through.
                if is_cond && cfg.follow_conditionals
                    && !visited_blocks.contains(&cur) {
                        worklist.push_back(cur);
                    }
                // CALL: enqueue call target.
                if is_call && cfg.follow_calls {
                    if let Some(t) = target
                        && !result.entries.contains(&t) {
                            result.entries.insert(t);
                            worklist.push_back(t);
                        }
                    // After a call, also continue at the return address.
                    if !visited_blocks.contains(&cur) {
                        worklist.push_back(cur);
                    }
                }
                break;
            }
        }
    }

    result
}

// ── Instruction formatter ─────────────────────────────────────────────────────

/// Format an [`Msp430Insn`] as an AT&T-style text string.
///
/// Output format: `MNEMONIC\tOPERANDS` (tab-separated).
#[must_use]
pub fn format_insn(insn: &Msp430Insn) -> String {
    insn.display()
}

/// Format an address as a hex string suitable for labels.
#[must_use]
pub fn format_addr(addr: u64) -> String {
    format!("loc_{addr:04X}")
}

/// Render a full disassembly listing as text.
///
/// Each line is formatted as:
/// ```text
/// 0x4002  04 55        ADD.W   R4,R5
/// ```
#[must_use]
pub fn render_listing(lines: &[DisasmLine]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for line in lines {
        let hex: String = line
            .bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(out, "0x{:04X}  {:12} {}", line.addr, hex, line.text);
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // Simple helper: 4 bytes = MOV.W R4,R5 ; ADD.W R4,R5
    fn two_insn_bytes() -> Vec<u8> {
        vec![0x04, 0x45, 0x04, 0x55]
    }

    // ── Linear disassembler ───────────────────────────────────────────────────

    #[test]
    fn linear_two_instructions() {
        let lines = disassemble_linear(&two_insn_bytes(), 0x4000);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].addr, 0x4000);
        assert_eq!(lines[1].addr, 0x4002);
        assert!(lines[0].text.contains("MOV"));
        assert!(lines[1].text.contains("ADD"));
    }

    #[test]
    fn linear_empty_input() {
        let lines = disassemble_linear(&[], 0x4000);
        assert!(lines.is_empty());
    }

    #[test]
    fn linear_single_byte_ignored() {
        // Only one byte — too short to decode.
        let lines = disassemble_linear(&[0x04], 0x4000);
        assert!(lines.is_empty());
    }

    #[test]
    fn linear_yields_dcw_on_unknown() {
        // Low opcode (0x0000) is a data word.
        let bytes = [0x00u8, 0x00];
        let lines = disassemble_linear(&bytes, 0x4000);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].text.starts_with("DC.W"));
    }

    #[test]
    fn linear_addresses_increment_correctly() {
        // MOV #0x1234, R4 (4 bytes) then RETI (2 bytes).
        let bytes = [0x34u8, 0x40, 0x34, 0x12, 0x00, 0x13];
        let lines = disassemble_linear(&bytes, 0x4000);
        assert_eq!(lines[0].addr, 0x4000);
        assert_eq!(lines[0].size, 4);
        assert_eq!(lines[1].addr, 0x4004);
        assert_eq!(lines[1].size, 2);
    }

    // ── Recursive disassembler ────────────────────────────────────────────────

    #[test]
    fn recursive_follows_jmp() {
        // Layout: [0x4000] JMP +2  → 0x4006
        //         [0x4002] DC.W 0x0000 (never reached)
        //         [0x4004] DC.W 0x0000 (never reached)
        //         [0x4006] RETI
        // JMP +2 at 0x4000: raw_off = 2, target = 0x4000+2 + 2*2 = 0x4006
        // Encoding: cond=7 (JMP), offset=2 → word = 0x3C02
        let mut bytes = vec![0u8; 8];
        bytes[0] = 0x02;
        bytes[1] = 0x3C; // JMP offset=2
        bytes[6] = 0x00;
        bytes[7] = 0x13; // RETI
        let cfg = RecursiveConfig::default();
        let res = disassemble_recursive(&bytes, 0x4000, 0x4000, &cfg);
        // Should have visited 0x4000 (JMP) and 0x4006 (RETI).
        assert!(res.lines.contains_key(&0x4000));
        assert!(res.lines.contains_key(&0x4006));
        // 0x4002 and 0x4004 should NOT have been visited.
        assert!(!res.lines.contains_key(&0x4002));
    }

    #[test]
    fn recursive_follows_conditional() {
        // JNE offset=-1 at 0x4002 (self-branch back to 0x4002) + fallthrough.
        // JNE: cond=0, offset=-1 → raw=0x1FF, word = (001 000 01 1111 1111) = 0x23FF
        let bytes = [0xFFu8, 0x23, 0x00, 0x13]; // JNE self; RETI
        let cfg = RecursiveConfig::default();
        let res = disassemble_recursive(&bytes, 0x4000, 0x4000, &cfg);
        // Fallthrough (0x4002) and branch target (0x4000) should both be visited.
        assert!(res.lines.contains_key(&0x4000));
        assert!(res.lines.contains_key(&0x4002));
    }

    #[test]
    fn recursive_max_blocks_respected() {
        // A trivial infinite loop: JMP 0 (offset=-1 → raw=0x1FF) at 0x4000
        // Actually JMP with offset=-1: target = 0x4002 + (-1)*2 = 0x4000
        // cond=7, offset=-1 → raw = (−1) & 0x3FF = 0x3FF → word = 0x3FFF
        let bytes = [0xFF, 0x3F]; // JMP self-loop
        let cfg = RecursiveConfig {
            max_blocks: 1,
            ..Default::default()
        };
        let res = disassemble_recursive(&bytes, 0x4000, 0x4000, &cfg);
        assert!(res.block_count <= 1);
    }

    #[test]
    fn recursive_follows_call() {
        // CALL #0x4006 then RETI; [0x4006] RET
        // CALL #imm: opcode3=5, as=3 (immediate), reg=0 → 0x12B0; ext=0x4006
        let mut bytes = vec![0u8; 10];
        bytes[0] = 0xB0;
        bytes[1] = 0x12; // CALL (imm src)
        bytes[2] = 0x06;
        bytes[3] = 0x40; // #0x4006
        bytes[4] = 0x00;
        bytes[5] = 0x13; // RETI
        bytes[6] = 0x30;
        bytes[7] = 0x41; // RET
        let cfg = RecursiveConfig::default();
        let res = disassemble_recursive(&bytes, 0x4000, 0x4000, &cfg);
        assert!(res.lines.contains_key(&0x4006));
        assert!(res.entries.contains(&0x4006));
    }

    // ── format_insn ──────────────────────────────────────────────────────────

    #[test]
    fn format_mov_reg_reg() {
        let insn = crate::decoder::decode_insn(&[0x04, 0x45], 0x4000).unwrap();
        let text = format_insn(&insn);
        assert!(text.contains("MOV"));
        assert!(text.contains("R4"));
        assert!(text.contains("R5"));
    }

    #[test]
    fn format_jmp() {
        let insn = crate::decoder::decode_insn(&[0x00, 0x3C], 0x4000).unwrap();
        let text = format_insn(&insn);
        assert!(text.contains("JMP"));
        assert!(text.contains("4002"));
    }

    #[test]
    fn format_call_imm() {
        let insn = crate::decoder::decode_insn(&[0xB0, 0x12, 0x00, 0x44], 0x4000).unwrap();
        let text = format_insn(&insn);
        assert!(text.contains("CALL"));
        assert!(text.contains("4400"));
    }

    // ── render_listing ────────────────────────────────────────────────────────

    #[test]
    fn render_listing_contains_addr_and_bytes() {
        let lines = disassemble_linear(&[0x04u8, 0x45], 0x4000);
        let text = render_listing(&lines);
        assert!(text.contains("4000"));
        assert!(text.contains("04 45"));
    }

    // ── DisasmLine ────────────────────────────────────────────────────────────

    #[test]
    fn disasm_line_target_for_jmp() {
        let insn = crate::decoder::decode_insn(&[0x00, 0x3C], 0x4000).unwrap();
        let raw = &[0x00u8, 0x3C];
        let line = DisasmLine::from_insn(&insn, raw);
        assert_eq!(line.target, Some(0x4002));
    }

    #[test]
    fn disasm_line_no_target_for_mov() {
        let insn = crate::decoder::decode_insn(&[0x04, 0x45], 0x4000).unwrap();
        let line = DisasmLine::from_insn(&insn, &[0x04u8, 0x45]);
        assert_eq!(line.target, None);
    }

    // ── format_addr ──────────────────────────────────────────────────────────

    #[test]
    fn format_addr_zero_padded() {
        assert_eq!(format_addr(0x4000), "loc_4000");
        assert_eq!(format_addr(0x0042), "loc_0042");
    }
}
