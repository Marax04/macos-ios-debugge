//! ARM32 .ARM.exidx / .ARM.extab exception index table parser.
//!
//! The `.ARM.exidx` section contains an array of 2-DWORD entries used for
//! ARM EHABI unwinding (and as a side-effect, for function boundary detection
//! in stripped binaries). Each entry consists of:
//!   - A PREL31 offset to the function start.
//!   - An inline compact unwind opcode OR a PREL31 pointer to an `.ARM.extab` entry.
//!
//! PREL31 encoding: the offset is sign-extended 31-bit, PC-relative.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sentinel value meaning "no unwind information / CANTUNWIND".
pub const EXIDX_CANTUNWIND: u32 = 0x0000_0001;

/// Bit 31 of the second word: 1 = inline unwind, 0 = pointer to .ARM.extab.
pub const EXIDX_COMPACT_INLINE: u32 = 0x8000_0000;

/// ARM compact model index bits [27:24].
pub const ARM_COMPACT_MODEL_MASK: u32 = 0x0F00_0000;
pub const ARM_COMPACT_MODEL_0: u32 = 0x0000_0000; // Su16 (Thumb)
pub const ARM_COMPACT_MODEL_1: u32 = 0x0100_0000; // Lu16
pub const ARM_COMPACT_MODEL_2: u32 = 0x0200_0000; // Lu32

// ---------------------------------------------------------------------------
// PREL31 helpers
// ---------------------------------------------------------------------------

/// Decode a PREL31 encoded value at `entry_address` with the stored word `word`.
///
/// The offset field is bits [30:0], sign-extended to 32 bits.
/// The resulting virtual address is `entry_address + sign_extend(word & 0x7FFFFFFF)`.
#[must_use]
pub const fn prel31_to_addr(entry_address: u32, word: u32) -> u32 {
    let offset = word & 0x7FFF_FFFF;
    // Sign-extend from bit 30
    let signed_offset = (offset.cast_signed() << 1) >> 1;
    entry_address.wrapping_add(signed_offset.cast_unsigned())
}

/// Encode an address as PREL31 relative to `entry_address`.
#[must_use]
pub const fn addr_to_prel31(entry_address: u32, target: u32) -> u32 {
    let diff = target.wrapping_sub(entry_address).cast_signed();
    diff.cast_unsigned() & 0x7FFF_FFFF
}

// ---------------------------------------------------------------------------
// Unwind opcodes
// ---------------------------------------------------------------------------

/// Decoded ARM unwind opcode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnwindOpcode {
    /// vsp += (n + 1) * 4
    VspAdd(u8),
    /// vsp -= (n + 1) * 4
    VspSub(u8),
    /// Pop integer registers from stack (register bitmask).
    PopRegs(u16),
    /// Pop VFP registers s0-s15 (vstmfpd / fldmfdx).
    PopVfpS0S15(u8),
    /// Pop VFP registers (fstmfdx model).
    PopVfpFstmfdx { start: u8, count: u8 },
    /// Pop VFP double-precision registers d8-d15 (vstmfdd).
    PopVfpD8D15(u8),
    /// vsp = core register r[n]
    SetVspFromReg(u8),
    /// Spare / reserved opcode.
    Spare(u8),
    /// End of unwind sequence.
    Finish,
    /// WMMX registers.
    WmmxPop { regmask: u16 },
}

/// Decode a single ARM EHABI unwind byte.
#[must_use]
pub const fn decode_unwind_byte(opcode: u8) -> UnwindOpcode {
    match opcode {
        0x00..=0x3F => UnwindOpcode::VspAdd(opcode & 0x3F),
        0x40..=0x7F => UnwindOpcode::VspSub(opcode & 0x3F),
        0xB0 => UnwindOpcode::Finish,
        // uleb128 vsp offset
        0x80..=0x8F => {
            // Handled as 2-byte opcode — caller provides next byte
            UnwindOpcode::Spare(opcode)
        }
        0x90..=0x9F => {
            let reg = opcode & 0x0F;
            if reg == 13 || reg == 15 {
                UnwindOpcode::Spare(opcode) // reserved
            } else {
                UnwindOpcode::SetVspFromReg(reg)
            }
        }
        0xA0..=0xAF => {
            // Pop under masks {r15?}{r14?}{r7..r4}
            let count = (opcode & 0x07) + 1;
            let r14 = if opcode & 0x08 != 0 { 1u16 << 14 } else { 0 };
            let regs: u16 = ((1u16 << count) - 1) << 4 | r14;
            UnwindOpcode::PopRegs(regs)
        }
        _ => UnwindOpcode::Spare(opcode),
    }
}

/// Decode a 2-byte pop-registers opcode sequence (opcodes 0x80..0x8F + next).
#[must_use]
pub const fn decode_pop_regs_2(hi: u8, lo: u8) -> UnwindOpcode {
    let mask = ((hi as u16 & 0x0F) << 8) | lo as u16;
    // Bit 15 of mask = r15 (pc), bits 14..0 = r14..r0
    let regmask = (mask & 0x0FFF) | if mask & 0x0800 != 0 { 1 << 15 } else { 0 };
    UnwindOpcode::PopRegs(regmask)
}

// ---------------------------------------------------------------------------
// Raw exidx entry
// ---------------------------------------------------------------------------

/// One entry from the `.ARM.exidx` section.
#[derive(Debug, Clone)]
pub struct ExidxEntry {
    /// Virtual address of this entry in the exidx section.
    pub entry_vaddr: u32,
    /// First DWORD: PREL31 offset to function start.
    pub word0: u32,
    /// Second DWORD: compact unwind or extab pointer.
    pub word1: u32,
}

impl ExidxEntry {
    /// Decoded function start address.
    #[must_use]
    pub const fn function_address(&self) -> u32 {
        prel31_to_addr(self.entry_vaddr, self.word0) & !1 // clear Thumb bit
    }

    /// Returns `true` if the second word is an inline compact unwind sequence.
    #[must_use]
    pub const fn is_inline_compact(&self) -> bool {
        self.word1 & EXIDX_COMPACT_INLINE != 0
    }

    /// Returns `true` if unwind is not possible (CANTUNWIND sentinel).
    #[must_use]
    pub const fn is_cant_unwind(&self) -> bool {
        self.word1 == EXIDX_CANTUNWIND
    }

    /// Return the `.ARM.extab` virtual address (for non-inline entries).
    #[must_use]
    pub const fn extab_address(&self) -> Option<u32> {
        if self.is_inline_compact() || self.is_cant_unwind() {
            None
        } else {
            Some(prel31_to_addr(self.entry_vaddr + 4, self.word1))
        }
    }

    /// Extract inline compact unwind bytes (3 bytes for su16 model).
    #[must_use]
    pub const fn inline_opcode_bytes(&self) -> Option<[u8; 3]> {
        if !self.is_inline_compact() {
            return None;
        }
        // word1 bits [23:0] contain the 3 opcode bytes (big-endian within word)
        let b0 = ((self.word1 >> 16) & 0xFF) as u8;
        let b1 = ((self.word1 >> 8) & 0xFF) as u8;
        let b2 = (self.word1 & 0xFF) as u8;
        Some([b0, b1, b2])
    }

    /// Decode the compact unwind model index (bits [27:24] of word1).
    #[must_use]
    pub const fn compact_model(&self) -> u32 {
        if self.is_inline_compact() {
            (self.word1 & ARM_COMPACT_MODEL_MASK) >> 24
        } else {
            0xFF // N/A
        }
    }
}

// ---------------------------------------------------------------------------
// Parse .ARM.exidx section
// ---------------------------------------------------------------------------

/// Parse the `.ARM.exidx` section into a list of entries.
///
/// `data` — full ELF file bytes.
/// `section_offset` — file offset of the `.ARM.exidx` section.
/// `section_size` — size in bytes.
/// `section_vaddr` — virtual address of the section (needed for PREL31 decode).
#[must_use] 
pub fn parse_arm_exidx(
    data: &[u8],
    section_offset: usize,
    section_size: usize,
    section_vaddr: u32,
) -> Vec<ExidxEntry> {
    let mut entries = Vec::new();
    let end = (section_offset + section_size).min(data.len());
    let mut off = section_offset;
    let mut voff = section_vaddr;

    while off + 8 <= end {
        let word0 = u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]));
        let word1 = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap_or([0; 4]));
        entries.push(ExidxEntry {
            entry_vaddr: voff,
            word0,
            word1,
        });
        off += 8;
        voff = voff.wrapping_add(8);
    }
    entries
}

// ---------------------------------------------------------------------------
// Function list from exidx
// ---------------------------------------------------------------------------

/// Extract function start addresses from parsed exidx entries, sorted.
#[must_use] 
pub fn exidx_function_addresses(entries: &[ExidxEntry]) -> Vec<u32> {
    let mut addrs: Vec<u32> = entries.iter().map(ExidxEntry::function_address).collect();
    addrs.sort_unstable();
    addrs.dedup();
    addrs
}

// ---------------------------------------------------------------------------
// .ARM.extab parsing (top-level)
// ---------------------------------------------------------------------------

/// Parsed `.ARM.extab` entry (variable layout — we decode the header only).
#[derive(Debug, Clone)]
pub struct ExtabEntry {
    /// Virtual address of the extab entry.
    pub vaddr: u32,
    /// First DWORD of the extab entry.
    pub header: u32,
    /// Compact model index (0-2).
    pub model: u32,
    /// Raw personality routine address (if using generic personality).
    pub personality_rva: Option<u32>,
}

/// Parse a `.ARM.extab` section.
#[must_use] 
pub fn parse_arm_extab(
    data: &[u8],
    section_offset: usize,
    section_size: usize,
    section_vaddr: u32,
) -> Vec<ExtabEntry> {
    let mut entries = Vec::new();
    let end = (section_offset + section_size).min(data.len());
    let mut off = section_offset;
    let mut voff = section_vaddr;

    while off + 4 <= end {
        let header = u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]));
        let is_compact = header & 0x8000_0000 != 0;
        let model = if is_compact {
            (header & ARM_COMPACT_MODEL_MASK) >> 24
        } else {
            0xFF
        };
        let personality_rva = if is_compact {
            None
        } else {
            Some(prel31_to_addr(voff, header))
        };
        entries.push(ExtabEntry {
            vaddr: voff,
            header,
            model,
            personality_rva,
        });
        off += 4;
        voff = voff.wrapping_add(4);
    }
    entries
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prel31_to_addr_zero() {
        // Offset 0 → same address
        assert_eq!(prel31_to_addr(0x1000, 0), 0x1000);
    }

    #[test]
    fn test_prel31_to_addr_positive() {
        // offset = 0x100 → 0x1000 + 0x100 = 0x1100
        assert_eq!(prel31_to_addr(0x1000, 0x0100), 0x1100);
    }

    #[test]
    fn test_prel31_to_addr_negative() {
        // offset = 0x7FFFF000 (sign-extended = -0x1000)
        let word: u32 = 0x7FFF_F000; // 0x7FFF_F000 sign-extended = 0xFFFF_F000 (negative)
        let result = prel31_to_addr(0x2000, word);
        // 0x2000 + (signed)0xFFFF_F000 = 0x2000 - 0x1000 = 0x1000
        assert_eq!(result, 0x1000);
    }

    #[test]
    fn test_addr_to_prel31_roundtrip() {
        let base = 0x8000_0000u32;
        let target = 0x8000_0400u32;
        let encoded = addr_to_prel31(base, target);
        let decoded = prel31_to_addr(base, encoded);
        assert_eq!(decoded, target);
    }

    #[test]
    fn test_exidx_entry_cant_unwind() {
        let e = ExidxEntry {
            entry_vaddr: 0x1000,
            word0: 0x0000_0100, // PREL31 +0x100
            word1: EXIDX_CANTUNWIND,
        };
        assert!(e.is_cant_unwind());
        assert!(e.extab_address().is_none());
        assert!(e.inline_opcode_bytes().is_none());
        assert_eq!(e.function_address(), 0x1100);
    }

    #[test]
    fn test_exidx_entry_inline_compact() {
        // word1 has bit 31 set → inline compact
        let word1: u32 = EXIDX_COMPACT_INLINE | 0x00B0_B000; // compact model 0, opcodes
        let e = ExidxEntry {
            entry_vaddr: 0x2000,
            word0: 0x0200, // +0x200
            word1,
        };
        assert!(e.is_inline_compact());
        assert!(!e.is_cant_unwind());
        assert_eq!(e.extab_address(), None);
        let opcodes = e.inline_opcode_bytes().unwrap();
        assert_eq!(opcodes[0], 0xB0); // bits [23:16] of word1 (0x80B0B000 -> 0xB0)
    }

    #[test]
    fn test_exidx_entry_extab_pointer() {
        // word1 does NOT have bit 31 set, not CANTUNWIND → extab pointer
        let e = ExidxEntry {
            entry_vaddr: 0x3000,
            word0: 0x0100,
            word1: 0x0000_0200, // PREL31 relative to entry_vaddr+4 = 0x3004 + 0x200 = 0x3204
        };
        assert!(!e.is_inline_compact());
        assert!(!e.is_cant_unwind());
        let extab = e.extab_address().unwrap();
        assert_eq!(extab, prel31_to_addr(0x3004, 0x0200));
    }

    #[test]
    fn test_parse_arm_exidx_basic() {
        // Two entries at vaddr 0x5000
        let word0_a: u32 = 0x0100; // PREL31 → fn at 0x5100
        let word1_a: u32 = EXIDX_CANTUNWIND;
        let word0_b: u32 = 0x0200; // PREL31 → fn at 0x5208
        let word1_b: u32 = EXIDX_COMPACT_INLINE | 0x00B0_B0B0;
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&word0_a.to_le_bytes());
        data[4..8].copy_from_slice(&word1_a.to_le_bytes());
        data[8..12].copy_from_slice(&word0_b.to_le_bytes());
        data[12..16].copy_from_slice(&word1_b.to_le_bytes());

        let entries = parse_arm_exidx(&data, 0, 16, 0x5000);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].function_address(), 0x5100);
        assert!(entries[0].is_cant_unwind());
        assert!(entries[1].is_inline_compact());
    }

    #[test]
    fn test_exidx_function_addresses_dedup_sorted() {
        let entries = vec![
            ExidxEntry {
                entry_vaddr: 0x1000,
                word0: 0x0100,
                word1: EXIDX_CANTUNWIND,
            },
            ExidxEntry {
                entry_vaddr: 0x1008,
                word0: 0x0200,
                word1: EXIDX_CANTUNWIND,
            },
            ExidxEntry {
                entry_vaddr: 0x1010,
                word0: 0x0100,
                word1: EXIDX_CANTUNWIND,
            }, // dup
        ];
        let addrs = exidx_function_addresses(&entries);
        // Should be sorted and deduped
        assert!(addrs.windows(2).all(|w| w[0] <= w[1]));
        // Check for no duplicates
        for i in 1..addrs.len() {
            assert_ne!(addrs[i - 1], addrs[i]);
        }
    }

    #[test]
    fn test_decode_unwind_byte_vsp_add() {
        assert_eq!(decode_unwind_byte(0x04), UnwindOpcode::VspAdd(4));
        assert_eq!(decode_unwind_byte(0x00), UnwindOpcode::VspAdd(0));
        assert_eq!(decode_unwind_byte(0x3F), UnwindOpcode::VspAdd(0x3F));
    }

    #[test]
    fn test_decode_unwind_byte_vsp_sub() {
        assert_eq!(decode_unwind_byte(0x40), UnwindOpcode::VspSub(0));
        assert_eq!(decode_unwind_byte(0x7F), UnwindOpcode::VspSub(0x3F));
    }

    #[test]
    fn test_decode_unwind_byte_finish() {
        assert_eq!(decode_unwind_byte(0xB0), UnwindOpcode::Finish);
    }

    #[test]
    fn test_decode_unwind_byte_set_vsp() {
        assert_eq!(decode_unwind_byte(0x91), UnwindOpcode::SetVspFromReg(1));
        // r13 and r15 are reserved
        assert_eq!(decode_unwind_byte(0x9D), UnwindOpcode::Spare(0x9D));
        assert_eq!(decode_unwind_byte(0x9F), UnwindOpcode::Spare(0x9F));
    }
}
