//! PE base relocation directory (.reloc) parser and applicator.

use crate::imports::{RvaSection, rva_to_file_offset};

// ---------------------------------------------------------------------------
// Relocation type constants
// ---------------------------------------------------------------------------

pub const IMAGE_REL_BASED_ABSOLUTE: u8 = 0;
pub const IMAGE_REL_BASED_HIGH: u8 = 1;
pub const IMAGE_REL_BASED_LOW: u8 = 2;
pub const IMAGE_REL_BASED_HIGHLOW: u8 = 3;
pub const IMAGE_REL_BASED_HIGHADJ: u8 = 4;
pub const IMAGE_REL_BASED_MIPS_JMPADDR: u8 = 5;
pub const IMAGE_REL_BASED_ARM_MOV32: u8 = 5;
pub const IMAGE_REL_BASED_RISCV_HIGH20: u8 = 5;
pub const IMAGE_REL_BASED_THUMB_MOV32: u8 = 7;
pub const IMAGE_REL_BASED_RISCV_LOW12I: u8 = 7;
pub const IMAGE_REL_BASED_RISCV_LOW12S: u8 = 8;
pub const IMAGE_REL_BASED_MIPS_JMPADDR16: u8 = 9;
pub const IMAGE_REL_BASED_DIR64: u8 = 10;

/// Human-readable name for a base relocation type.
#[must_use]
pub const fn reloc_type_name(t: u8) -> &'static str {
    match t {
        IMAGE_REL_BASED_ABSOLUTE => "ABSOLUTE",
        IMAGE_REL_BASED_HIGH => "HIGH",
        IMAGE_REL_BASED_LOW => "LOW",
        IMAGE_REL_BASED_HIGHLOW => "HIGHLOW",
        IMAGE_REL_BASED_HIGHADJ => "HIGHADJ",
        IMAGE_REL_BASED_ARM_MOV32 => "ARM_MOV32/MIPS_JMPADDR/RISCV_HIGH20",
        IMAGE_REL_BASED_THUMB_MOV32 => "THUMB_MOV32/RISCV_LOW12I",
        IMAGE_REL_BASED_RISCV_LOW12S => "RISCV_LOW12S",
        IMAGE_REL_BASED_MIPS_JMPADDR16 => "MIPS_JMPADDR16",
        IMAGE_REL_BASED_DIR64 => "DIR64",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// One relocation fixup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relocation {
    /// The virtual address of the fixup (image-base-relative when at preferred base).
    pub virtual_address: u32,
    /// The relocation type (`IMAGE_REL_BASED_*`).
    pub reloc_type: u8,
}

impl Relocation {
    /// Return `true` if this is a padding/filler entry (type `ABSOLUTE`).
    #[must_use]
    pub const fn is_absolute(&self) -> bool {
        self.reloc_type == IMAGE_REL_BASED_ABSOLUTE
    }
}

/// One `IMAGE_BASE_RELOCATION` block.
#[derive(Debug, Clone)]
pub struct RelocationBlock {
    /// Base RVA of the block (all entries are offsets from this).
    pub virtual_address: u32,
    /// Block size including this 8-byte header.
    pub size_of_block: u32,
    /// All fixup entries in this block.
    pub entries: Vec<Relocation>,
}

// ---------------------------------------------------------------------------
// Parse relocation directory
// ---------------------------------------------------------------------------

/// Parse all base relocation blocks from the .reloc section.
#[must_use]
pub fn parse_relocation_directory(
    data: &[u8],
    sections: &[RvaSection],
    reloc_dir_rva: u32,
    reloc_dir_size: u32,
) -> Vec<RelocationBlock> {
    let Some(mut off) = rva_to_file_offset(reloc_dir_rva, sections) else {
        return Vec::new();
    };

    let Some(end_off) = off.checked_add(usize::try_from(reloc_dir_size).unwrap_or(usize::MAX)) else {
        return Vec::new();
    };
    // Most relocation blocks cover a 4KB page; pre-size to that estimate,
    // capped by what the file could actually hold (each block header is 8 bytes).
    let est_blocks = (usize::try_from(reloc_dir_size).unwrap_or(usize::MAX) / 4096)
        .max(8)
        .min(data.len() / 8 + 1);
    let mut blocks = Vec::with_capacity(est_blocks);

    while off + 8 <= end_off && off + 8 <= data.len() {
        let va = u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]));
        let block_size = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap_or([0; 4]));

        if va == 0 && block_size == 0 {
            break;
        }
        if block_size < 8 {
            break;
        }

        // `block_size` is a raw u32 from the file: cap the entry count by the
        // bytes actually remaining in the buffer (2 bytes per entry).
        let entries_off = off + 8;
        let num_entries = ((usize::try_from(block_size).unwrap_or(usize::MAX).saturating_sub(8)) / 2)
            .min(data.len().saturating_sub(entries_off) / 2);
        let mut entries = Vec::with_capacity(num_entries);

        for i in 0..num_entries {
            let entry_off = entries_off + i * 2;
            if entry_off + 2 > data.len() {
                break;
            }
            let raw =
                u16::from_le_bytes(data[entry_off..entry_off + 2].try_into().unwrap_or([0; 2]));
            let reloc_type = u8::try_from(raw >> 12).unwrap_or(u8::MAX);
            let offset = raw & 0x0FFF;
            entries.push(Relocation {
                virtual_address: va.wrapping_add(u32::from(offset)),
                reloc_type,
            });
        }

        blocks.push(RelocationBlock {
            virtual_address: va,
            size_of_block: block_size,
            entries,
        });

        off += usize::try_from(block_size).unwrap_or(usize::MAX);
    }

    blocks
}

// ---------------------------------------------------------------------------
// Apply relocations
// ---------------------------------------------------------------------------

/// Apply all base relocations to a loaded PE image (in-memory slice).
///
/// `old_base` is the original preferred image base; `new_base` is the actual
/// load address. The image bytes are modified in place.
///
/// `sections` must be the section table of the PE. Each relocation entry's
/// `virtual_address` (an RVA) is translated to a file offset via the section
/// table before indexing into `image`. When `sections` is empty the RVA is
/// used directly as an index — this is only correct for a fully loaded
/// (virtually mapped) image where RVAs equal file offsets.
pub fn apply_relocations(
    image: &mut [u8],
    blocks: &[RelocationBlock],
    old_base: u64,
    new_base: u64,
    sections: &[RvaSection],
) {
    let delta = new_base.wrapping_sub(old_base).cast_signed();
    if delta == 0 {
        return;
    }

    for block in blocks {
        for entry in &block.entries {
            let addr = if sections.is_empty() {
                usize::try_from(entry.virtual_address).unwrap_or(usize::MAX)
            } else {
                match rva_to_file_offset(entry.virtual_address, sections) {
                    Some(off) => off,
                    None => continue, // RVA outside any section; skip
                }
            };
            match entry.reloc_type {
                IMAGE_REL_BASED_HIGHLOW => {
                    if addr + 4 <= image.len() {
                        let val =
                            u32::from_le_bytes(image[addr..addr + 4].try_into().unwrap_or([0; 4]));
                        let new_val = val.wrapping_add(
                            u32::try_from(delta.cast_unsigned() & u64::from(u32::MAX)).unwrap_or(0),
                        );
                        image[addr..addr + 4].copy_from_slice(&new_val.to_le_bytes());
                    }
                }

                IMAGE_REL_BASED_DIR64 => {
                    if addr + 8 <= image.len() {
                        let val =
                            u64::from_le_bytes(image[addr..addr + 8].try_into().unwrap_or([0; 8]));
                        let new_val = val.wrapping_add(delta.cast_unsigned());
                        image[addr..addr + 8].copy_from_slice(&new_val.to_le_bytes());
                    }
                }

                IMAGE_REL_BASED_HIGH => {
                    if addr + 2 <= image.len() {
                        let val =
                            u16::from_le_bytes(image[addr..addr + 2].try_into().unwrap_or([0; 2]));
                        // High 16 bits of a 32-bit pointer; delta >> 16
                        let adj = i32::try_from(delta >> 16).unwrap_or(i32::MAX);
                        let new_val = u16::try_from((i32::from(val) + adj) & 0xFFFF).unwrap_or(0);
                        image[addr..addr + 2].copy_from_slice(&new_val.to_le_bytes());
                    }
                }

                IMAGE_REL_BASED_LOW
                    if addr + 2 <= image.len() => {
                        let val =
                            u16::from_le_bytes(image[addr..addr + 2].try_into().unwrap_or([0; 2]));
                        let adj = i32::try_from(delta & 0xFFFF).unwrap_or(0);
                        let new_val = u16::try_from((i32::from(val) + adj) & 0xFFFF).unwrap_or(0);
                        image[addr..addr + 2].copy_from_slice(&new_val.to_le_bytes());
                    }

                _ => {} // ABSOLUTE (padding) or architecture-specific, skip
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/// Summary statistics for the relocation directory.
#[derive(Debug, Clone, Default)]
pub struct RelocationStats {
    /// Total number of blocks.
    pub block_count: usize,
    /// Total number of fixup entries (including ABSOLUTE padding).
    pub total_entries: usize,
    /// Count of HIGHLOW (32-bit) entries.
    pub highlow_count: usize,
    /// Count of DIR64 (64-bit) entries.
    pub dir64_count: usize,
    /// Count of non-padding entries.
    pub real_fixup_count: usize,
}

impl RelocationStats {
    /// Build stats from a list of parsed relocation blocks.
    #[must_use]
    pub fn from_blocks(blocks: &[RelocationBlock]) -> Self {
        let mut stats = Self {
            block_count: blocks.len(),
            ..Self::default()
        };
        for block in blocks {
            stats.total_entries += block.entries.len();
            for e in &block.entries {
                match e.reloc_type {
                    IMAGE_REL_BASED_ABSOLUTE => {}
                    IMAGE_REL_BASED_HIGHLOW => {
                        stats.highlow_count += 1;
                        stats.real_fixup_count += 1;
                    }
                    IMAGE_REL_BASED_DIR64 => {
                        stats.dir64_count += 1;
                        stats.real_fixup_count += 1;
                    }
                    _ => {
                        stats.real_fixup_count += 1;
                    }
                }
            }
        }
        stats
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_reloc_block(base_va: u32, entries: &[(u8, u16)]) -> Vec<u8> {
        // header: va (4) + size (4) + entries (2 each)
        let size = 8 + entries.len() * 2;
        let mut buf = vec![0u8; size];
        buf[0..4].copy_from_slice(&base_va.to_le_bytes());
        buf[4..8].copy_from_slice(&(u32::try_from(size).unwrap_or(u32::MAX)).to_le_bytes());
        for (i, &(rtype, offset)) in entries.iter().enumerate() {
            let raw: u16 = (u16::from(rtype) << 12) | (offset & 0x0FFF);
            buf[8 + i * 2..8 + i * 2 + 2].copy_from_slice(&raw.to_le_bytes());
        }
        buf
    }

    fn make_sections_covering(raw_off: u32, size: u32) -> Vec<RvaSection> {
        vec![RvaSection {
            virtual_address: 0x5000,
            virtual_size: size,
            raw_size: size,
            raw_offset: raw_off,
        }]
    }

    #[test]
    fn test_reloc_type_name() {
        assert_eq!(reloc_type_name(IMAGE_REL_BASED_ABSOLUTE), "ABSOLUTE");
        assert_eq!(reloc_type_name(IMAGE_REL_BASED_HIGHLOW), "HIGHLOW");
        assert_eq!(reloc_type_name(IMAGE_REL_BASED_DIR64), "DIR64");
        assert_eq!(reloc_type_name(11), "UNKNOWN");
    }

    #[test]
    fn test_parse_relocation_single_block() {
        // VA=0x1000, one HIGHLOW fixup at offset 0x100
        let block = make_reloc_block(0x1000, &[(IMAGE_REL_BASED_HIGHLOW, 0x100)]);
        // Put block at file offset 0x2000 and map it to RVA 0x5000
        let mut data = vec![0u8; 0x2000 + block.len()];
        data[0x2000..0x2000 + block.len()].copy_from_slice(&block);

        let sections = make_sections_covering(0x2000, u32::try_from(block.len()).unwrap_or(u32::MAX));
        let blocks = parse_relocation_directory(&data, &sections, 0x5000, u32::try_from(block.len()).unwrap_or(u32::MAX));

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].virtual_address, 0x1000);
        assert_eq!(blocks[0].entries.len(), 1);
        let e = &blocks[0].entries[0];
        assert_eq!(e.virtual_address, 0x1100); // 0x1000 + 0x100
        assert_eq!(e.reloc_type, IMAGE_REL_BASED_HIGHLOW);
        assert!(!e.is_absolute());
    }

    #[test]
    fn test_parse_relocation_absolute_padding() {
        let block = make_reloc_block(0x2000, &[(IMAGE_REL_BASED_ABSOLUTE, 0)]);
        let mut data = vec![0u8; 0x1000 + block.len()];
        data[0x1000..0x1000 + block.len()].copy_from_slice(&block);
        let sections = make_sections_covering(0x1000, u32::try_from(block.len()).unwrap_or(u32::MAX));
        let blocks = parse_relocation_directory(&data, &sections, 0x5000, u32::try_from(block.len()).unwrap_or(u32::MAX));
        assert_eq!(blocks[0].entries[0].reloc_type, IMAGE_REL_BASED_ABSOLUTE);
        assert!(blocks[0].entries[0].is_absolute());
    }

    #[test]
    fn test_apply_relocations_highlow() {
        let old_base: u64 = 0x0040_0000;
        let new_base: u64 = 0x0060_0000;
        // Image: 0x0040_1000 stored as HIGHLOW at offset 0
        let original: u32 = 0x0040_1000;
        let mut image = original.to_le_bytes().to_vec();
        // Pad to 8 bytes so DIR64 tests don't OOB
        image.extend_from_slice(&[0u8; 4]);

        let blocks = vec![RelocationBlock {
            virtual_address: 0x0000,
            size_of_block: 10,
            entries: vec![Relocation {
                virtual_address: 0x0000,
                reloc_type: IMAGE_REL_BASED_HIGHLOW,
            }],
        }];

        apply_relocations(&mut image, &blocks, old_base, new_base, &[]);

        let result = u32::from_le_bytes(image[0..4].try_into().unwrap());
        // 0x0040_1000 + (0x0060_0000 - 0x0040_0000) = 0x0060_1000
        assert_eq!(result, 0x0060_1000);
    }

    #[test]
    fn test_apply_relocations_dir64() {
        let old_base: u64 = 0x1_4000_0000;
        let new_base: u64 = 0x1_8000_0000;
        let original: u64 = 0x1_4000_1000;
        let mut image = original.to_le_bytes().to_vec();

        let blocks = vec![RelocationBlock {
            virtual_address: 0,
            size_of_block: 10,
            entries: vec![Relocation {
                virtual_address: 0,
                reloc_type: IMAGE_REL_BASED_DIR64,
            }],
        }];

        apply_relocations(&mut image, &blocks, old_base, new_base, &[]);
        let result = u64::from_le_bytes(image[0..8].try_into().unwrap());
        assert_eq!(result, 0x1_8000_1000);
    }

    #[test]
    fn test_apply_relocations_no_delta() {
        let base: u64 = 0x40_0000;
        let original: u32 = 0x40_1000;
        let mut image = original.to_le_bytes().to_vec();
        image.extend_from_slice(&[0u8; 4]);
        let blocks = vec![RelocationBlock {
            virtual_address: 0,
            size_of_block: 10,
            entries: vec![Relocation {
                virtual_address: 0,
                reloc_type: IMAGE_REL_BASED_HIGHLOW,
            }],
        }];
        apply_relocations(&mut image, &blocks, base, base, &[]);
        let result = u32::from_le_bytes(image[0..4].try_into().unwrap());
        assert_eq!(result, original); // unchanged
    }

    #[test]
    fn test_relocation_stats() {
        let blocks = vec![RelocationBlock {
            virtual_address: 0x1000,
            size_of_block: 16,
            entries: vec![
                Relocation {
                    virtual_address: 0x1000,
                    reloc_type: IMAGE_REL_BASED_HIGHLOW,
                },
                Relocation {
                    virtual_address: 0x1004,
                    reloc_type: IMAGE_REL_BASED_ABSOLUTE,
                },
                Relocation {
                    virtual_address: 0x1008,
                    reloc_type: IMAGE_REL_BASED_DIR64,
                },
            ],
        }];
        let stats = RelocationStats::from_blocks(&blocks);
        assert_eq!(stats.block_count, 1);
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.highlow_count, 1);
        assert_eq!(stats.dir64_count, 1);
        assert_eq!(stats.real_fixup_count, 2);
    }

    #[test]
    fn test_parse_relocation_no_sections() {
        let result = parse_relocation_directory(&[], &[], 0x5000, 100);
        assert!(result.is_empty());
    }
}
