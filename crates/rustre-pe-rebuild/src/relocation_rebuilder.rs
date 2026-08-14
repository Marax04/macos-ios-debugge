//! PE relocation table rebuilding.
//!
//! Provides [`RelocationRebuilder`], [`RelocationEntry`], [`RelocationBlock`],
//! and [`rebuild_relocs`].  Reconstructs a valid `.reloc` section from a list
//! of fixup addresses encountered during analysis.

use std::collections::BTreeMap;
use std::fmt;

// ── RelocationType ────────────────────────────────────────────────────────────

/// PE base-relocation type codes (`IMAGE_REL_BASED_*`).
///
/// Several architectures share numeric value 5 for different semantics
/// (ARM `ThumbMovw` vs. RISC-V High20).  This enum uses `ThumbMovw` for value 5
/// (the dominant desktop use-case).  RISC-V High20 fixups parsed from a
/// RISC-V binary will be represented as `ThumbMovw` at the numeric level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RelocationType {
    /// No fixup needed.
    Absolute = 0,
    /// 32-bit high word fixup.
    High = 1,
    /// 32-bit low word fixup.
    Low = 2,
    /// 32-bit high + low word fixup.
    HighLow = 3,
    /// High word delta fixup.
    HighAdj = 4,
    /// Architecture-specific type 5 — ARM THUMB MOVW/MOVT on ARM, RISC-V
    /// High20 on RISC-V.  Numeric value is 5 in both cases.
    ThumbMovw = 5,
    /// 64-bit absolute fixup.
    Dir64 = 10,
}

impl RelocationType {
    /// Return the numeric value of this type.
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }

    /// Byte width of the fixup target.
    #[must_use]
    pub const fn size_bytes(self) -> usize {
        match self {
            Self::Absolute => 0,
            Self::High | Self::Low | Self::HighAdj => 2,
            Self::HighLow | Self::ThumbMovw => 4,
            Self::Dir64 => 8,
        }
    }

    /// Try to construct from the raw 4-bit type nibble.
    #[must_use]
    pub const fn from_nibble(n: u8) -> Option<Self> {
        match n {
            0 => Some(Self::Absolute),
            1 => Some(Self::High),
            2 => Some(Self::Low),
            3 => Some(Self::HighLow),
            4 => Some(Self::HighAdj),
            5 => Some(Self::ThumbMovw),
            10 => Some(Self::Dir64),
            _ => None,
        }
    }
}

impl fmt::Display for RelocationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Absolute => "ABS",
            Self::High => "HIGH",
            Self::Low => "LOW",
            Self::HighLow => "HIGHLOW",
            Self::HighAdj => "HIGHADJ",
            Self::ThumbMovw => "THUMB_MOVW",
            Self::Dir64 => "DIR64",
        };
        f.write_str(s)
    }
}

// ── RelocationEntry ───────────────────────────────────────────────────────────

/// A single relocation fixup record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationEntry {
    /// Relative virtual address of the fixup location.
    pub rva: u32,
    /// The type of fixup to apply.
    pub reloc_type: RelocationType,
    /// Optional padding word for 4-byte alignment (`HighAdj` uses this).
    pub param: u16,
}

impl RelocationEntry {
    /// Create a standard `HIGHLOW` (32-bit) relocation.
    #[must_use]
    pub const fn highlow(rva: u32) -> Self {
        Self { rva, reloc_type: RelocationType::HighLow, param: 0 }
    }

    /// Create a 64-bit `DIR64` relocation.
    #[must_use]
    pub const fn dir64(rva: u32) -> Self {
        Self { rva, reloc_type: RelocationType::Dir64, param: 0 }
    }

    /// Return `true` if this is a padding (type 0) entry.
    #[must_use]
    pub fn is_padding(&self) -> bool {
        self.reloc_type == RelocationType::Absolute
    }

    /// Encode as a PE relocation word: high 4 bits = type, low 12 bits = page offset.
    #[must_use]
    pub const fn encode_word(&self, page_base: u32) -> u16 {
        let offset = (self.rva.wrapping_sub(page_base)) & 0x0FFF;
        ((self.reloc_type.value() as u16) << 12) | (offset as u16)
    }
}

impl fmt::Display for RelocationEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RELOC {} @ RVA {:#010x}", self.reloc_type, self.rva)
    }
}

// ── RelocationBlock ───────────────────────────────────────────────────────────

/// A PE relocation block covering a 4 KiB page.
///
/// Each block corresponds to one `IMAGE_BASE_RELOCATION` structure in the
/// `.reloc` section.
#[derive(Debug, Clone)]
pub struct RelocationBlock {
    /// The 4 KiB-aligned virtual page base address for this block.
    pub page_rva: u32,
    /// All fixup entries within this block.
    pub entries: Vec<RelocationEntry>,
}

impl RelocationBlock {
    /// Create an empty block for `page_rva`.
    #[must_use]
    pub const fn new(page_rva: u32) -> Self {
        Self { page_rva: page_rva & !0xFFF, entries: Vec::new() }
    }

    /// Add a relocation entry.  The entry's RVA must fall within this page.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the RVA does not belong to this page.
    pub fn add_entry(&mut self, entry: RelocationEntry) -> Result<(), String> {
        let page = entry.rva & !0xFFF;
        if page != self.page_rva {
            return Err(format!(
                "entry RVA {:#x} belongs to page {:#x}, not {:#x}",
                entry.rva, page, self.page_rva
            ));
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Sort entries by RVA.
    pub fn sort(&mut self) {
        self.entries.sort_by_key(|e| e.rva);
    }

    /// Serialised size of this block in bytes (header + words, padded to 4 bytes).
    #[must_use]
    pub const fn serialised_size(&self) -> usize {
        let n = self.entries.len();
        // Each entry is a 2-byte word; header is 8 bytes.
        let raw = 8 + n * 2;
        // Pad to 4-byte alignment.
        (raw + 3) & !3
    }

    /// Serialise into the binary `.reloc` block format.
    ///
    /// Returns the bytes for one `IMAGE_BASE_RELOCATION` block.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut entries = self.entries.clone();
        // Ensure even entry count for 4-byte alignment.
        let raw_size = 8 + entries.len() * 2;
        if !raw_size.is_multiple_of(4) {
            entries.push(RelocationEntry {
                rva: self.page_rva,
                reloc_type: RelocationType::Absolute,
                param: 0,
            });
        }
        let block_size = u32::try_from(8 + entries.len() * 2).unwrap_or(u32::MAX);
        let mut out = Vec::with_capacity(block_size as usize);
        out.extend_from_slice(&self.page_rva.to_le_bytes());
        out.extend_from_slice(&block_size.to_le_bytes());
        for e in &entries {
            let word = e.encode_word(self.page_rva);
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// Count of non-padding entries.
    #[must_use]
    pub fn real_entry_count(&self) -> usize {
        self.entries.iter().filter(|e| !e.is_padding()).count()
    }
}

impl fmt::Display for RelocationBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Block page={:#010x} entries={} size={}B",
            self.page_rva,
            self.entries.len(),
            self.serialised_size()
        )
    }
}

// ── RelocationStatistics ──────────────────────────────────────────────────────

/// Statistics generated after a rebuild pass.
#[derive(Debug, Clone, Default)]
pub struct RelocationStatistics {
    /// Total number of relocation entries added.
    pub total_entries: usize,
    /// Number of 4 KiB blocks emitted.
    pub block_count: usize,
    /// Total `.reloc` section size in bytes.
    pub section_size: usize,
    /// Number of duplicate RVAs skipped.
    pub duplicates_skipped: usize,
    /// Number of out-of-range entries rejected.
    pub rejected: usize,
}

impl fmt::Display for RelocationStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Relocations: {} entries, {} blocks, {}B, {} dups, {} rejected",
            self.total_entries,
            self.block_count,
            self.section_size,
            self.duplicates_skipped,
            self.rejected
        )
    }
}

// ── RelocationRebuilder ───────────────────────────────────────────────────────

/// Reconstructs the `.reloc` section of a PE image.
///
/// Callers feed individual RVA fixup addresses via [`add_fixup`] then call
/// [`build`] to obtain serialised section data.
///
/// [`add_fixup`]: RelocationRebuilder::add_fixup
/// [`build`]: RelocationRebuilder::build
#[derive(Debug, Clone)]
pub struct RelocationRebuilder {
    /// The image's preferred load address (used only for delta calculation).
    pub image_base: u64,
    /// Section virtual address to restrict fixup acceptance (`0` = no limit).
    pub section_rva_start: u32,
    /// Section size to restrict fixup acceptance (`0` = no limit).
    pub section_size: u32,
    /// Default relocation type applied when type is not specified.
    pub default_type: RelocationType,
    /// Collected fixup entries, keyed by RVA.
    fixups: BTreeMap<u32, RelocationType>,
    /// Statistics accumulated during the last `build()` call.
    stats: RelocationStatistics,
}

impl RelocationRebuilder {
    /// Create a new rebuilder for a 64-bit image.
    #[must_use]
    pub fn new_x64(image_base: u64) -> Self {
        Self {
            image_base,
            section_rva_start: 0,
            section_size: 0,
            default_type: RelocationType::Dir64,
            fixups: BTreeMap::new(),
            stats: RelocationStatistics::default(),
        }
    }

    /// Create a new rebuilder for a 32-bit image.
    #[must_use]
    pub fn new_x86(image_base: u32) -> Self {
        Self {
            image_base: u64::from(image_base),
            section_rva_start: 0,
            section_size: 0,
            default_type: RelocationType::HighLow,
            fixups: BTreeMap::new(),
            stats: RelocationStatistics::default(),
        }
    }

    /// Add a fixup at `rva` with the default relocation type.
    ///
    /// Duplicate RVAs are silently ignored.  Returns `false` if the RVA was
    /// already present.
    pub fn add_fixup(&mut self, rva: u32) -> bool {
        let t = self.default_type;
        self.add_fixup_typed(rva, t)
    }

    /// Add a fixup at `rva` with an explicit [`RelocationType`].
    pub fn add_fixup_typed(&mut self, rva: u32, reloc_type: RelocationType) -> bool {
        self.fixups.insert(rva, reloc_type).is_none()
    }

    /// Bulk-add fixup addresses from a slice.
    pub fn add_fixups(&mut self, rvas: &[u32]) {
        for &rva in rvas {
            self.add_fixup(rva);
        }
    }

    /// Remove a fixup by RVA.  Returns `true` if it existed.
    pub fn remove_fixup(&mut self, rva: u32) -> bool {
        self.fixups.remove(&rva).is_some()
    }

    /// Clear all collected fixups.
    pub fn clear(&mut self) {
        self.fixups.clear();
        self.stats = RelocationStatistics::default();
    }

    /// Total number of fixups collected so far.
    #[must_use]
    pub fn fixup_count(&self) -> usize {
        self.fixups.len()
    }

    /// Return a reference to the statistics from the last `build()` call.
    #[must_use]
    pub const fn stats(&self) -> &RelocationStatistics {
        &self.stats
    }

    /// Assemble all fixups into [`RelocationBlock`]s.
    #[must_use]
    pub fn blocks(&self) -> Vec<RelocationBlock> {
        let mut map: BTreeMap<u32, RelocationBlock> = BTreeMap::new();
        for (&rva, &reloc_type) in &self.fixups {
            let page = rva & !0xFFF;
            let block = map.entry(page).or_insert_with(|| RelocationBlock::new(page));
            let _ = block.add_entry(RelocationEntry { rva, reloc_type, param: 0 });
        }
        for block in map.values_mut() {
            block.sort();
        }
        map.into_values().collect()
    }

    /// Serialise all relocation blocks into `.reloc` section bytes.
    ///
    /// Also updates internal statistics.
    #[must_use]
    pub fn build(&mut self) -> Vec<u8> {
        let blocks = self.blocks();
        let mut out = Vec::new();
        let mut stats = RelocationStatistics {
            block_count: blocks.len(),
            ..RelocationStatistics::default()
        };
        for block in &blocks {
            stats.total_entries += block.real_entry_count();
            let bytes = block.to_bytes();
            stats.section_size += bytes.len();
            out.extend_from_slice(&bytes);
        }
        self.stats = stats;
        out
    }

    /// Parse an existing `.reloc` section and import its entries.
    ///
    /// Returns the number of entries imported or an error if the data is
    /// malformed.
    ///
    /// # Errors
    ///
    /// Returns `Err` if a relocation block has an invalid size field.
    pub fn import_reloc_section(&mut self, data: &[u8]) -> Result<usize, String> {
        let mut pos = 0usize;
        let mut imported = 0usize;
        while pos + 8 <= data.len() {
            let page_rva = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]);
            let block_size = u32::from_le_bytes([data[pos+4], data[pos+5], data[pos+6], data[pos+7]]);
            if block_size < 8 { return Err(format!("invalid block size {block_size} at offset {pos}")); }
            let entry_bytes = (block_size as usize).saturating_sub(8);
            let n_entries = entry_bytes / 2;
            for i in 0..n_entries {
                let off = pos + 8 + i * 2;
                if off + 2 > data.len() { break; }
                let word = u16::from_le_bytes([data[off], data[off+1]]);
                let type_nibble = (word >> 12) as u8;
                let page_off = u32::from(word & 0x0FFF);
                let reloc_type = RelocationType::from_nibble(type_nibble)
                    .unwrap_or(RelocationType::Absolute);
                if reloc_type == RelocationType::Absolute { continue; }
                let rva = page_rva + page_off;
                self.add_fixup_typed(rva, reloc_type);
                imported += 1;
            }
            pos += block_size as usize;
        }
        Ok(imported)
    }

    /// Scan `image_data` for absolute pointer values that match a known virtual
    /// address range and add them as fixups.
    ///
    /// `va_start` and `va_end` define the expected address range.  Only
    /// locations whose 8-byte (or 4-byte for 32-bit) value falls within that
    /// range are registered.
    ///
    /// Returns the count of fixups found.
    pub fn heuristic_scan_x64(
        &mut self,
        image_data: &[u8],
        section_rva: u32,
        va_start: u64,
        va_end: u64,
    ) -> usize {
        let mut count = 0usize;
        let aligned_len = image_data.len() & !7;
        for off in (0..aligned_len).step_by(8) {
            let val = u64::from_le_bytes([
                image_data[off],   image_data[off+1], image_data[off+2], image_data[off+3],
                image_data[off+4], image_data[off+5], image_data[off+6], image_data[off+7],
            ]);
            if val >= va_start && val <= va_end {
                let rva = section_rva + u32::try_from(off).unwrap_or(u32::MAX);
                if self.add_fixup_typed(rva, RelocationType::Dir64) {
                    count += 1;
                }
            }
        }
        count
    }
}

impl fmt::Display for RelocationRebuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RelocationRebuilder base={:#018x} type={} fixups={}",
            self.image_base,
            self.default_type,
            self.fixups.len()
        )
    }
}

// ── rebuild_relocs ────────────────────────────────────────────────────────────

/// Build a `.reloc` section from a list of RVA fixup addresses.
///
/// `rvas` is a slice of RVAs where absolute pointers reside.
/// `image_base` is the preferred load address of the image.
/// `is_x64` selects `DIR64` (true) or `HIGHLOW` (false) relocation type.
///
/// Returns the serialised `.reloc` section bytes.
#[must_use]
pub fn rebuild_relocs(rvas: &[u32], image_base: u64, is_x64: bool) -> Vec<u8> {
    let mut rebuilder = if is_x64 {
        RelocationRebuilder::new_x64(image_base)
    } else {
        RelocationRebuilder::new_x86(u32::try_from(image_base).unwrap_or(u32::MAX))
    };
    rebuilder.add_fixups(rvas);
    rebuilder.build()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relocation_type_value() {
        assert_eq!(RelocationType::HighLow.value(), 3);
        assert_eq!(RelocationType::Dir64.value(), 10);
        assert_eq!(RelocationType::Absolute.value(), 0);
    }

    #[test]
    fn test_relocation_type_size() {
        assert_eq!(RelocationType::HighLow.size_bytes(), 4);
        assert_eq!(RelocationType::Dir64.size_bytes(), 8);
        assert_eq!(RelocationType::Absolute.size_bytes(), 0);
    }

    #[test]
    fn test_relocation_type_from_nibble() {
        assert_eq!(RelocationType::from_nibble(3), Some(RelocationType::HighLow));
        assert_eq!(RelocationType::from_nibble(10), Some(RelocationType::Dir64));
        assert_eq!(RelocationType::from_nibble(15), None);
    }

    #[test]
    fn test_entry_encode_word() {
        let entry = RelocationEntry::highlow(0x1234);
        let page = 0x1000u32;
        let word = entry.encode_word(page);
        // type = 3 (HIGHLOW), offset = 0x234
        assert_eq!(word >> 12, 3);
        assert_eq!(word & 0xFFF, 0x234);
    }

    #[test]
    fn test_entry_is_padding() {
        let pad = RelocationEntry { rva: 0x1000, reloc_type: RelocationType::Absolute, param: 0 };
        assert!(pad.is_padding());
        let real = RelocationEntry::highlow(0x1234);
        assert!(!real.is_padding());
    }

    #[test]
    fn test_block_add_entry_wrong_page_fails() {
        let mut block = RelocationBlock::new(0x1000);
        let entry = RelocationEntry::highlow(0x2000);
        assert!(block.add_entry(entry).is_err());
    }

    #[test]
    fn test_block_add_entry_correct_page() {
        let mut block = RelocationBlock::new(0x1000);
        let entry = RelocationEntry::highlow(0x1100);
        assert!(block.add_entry(entry).is_ok());
        assert_eq!(block.entries.len(), 1);
    }

    #[test]
    fn test_block_to_bytes_alignment() {
        let mut block = RelocationBlock::new(0x1000);
        block.add_entry(RelocationEntry::highlow(0x1100)).unwrap();
        let bytes = block.to_bytes();
        // Header (8) + 1 entry (2) + 1 padding (2) = 12 bytes
        assert_eq!(bytes.len() % 4, 0);
    }

    #[test]
    fn test_block_to_bytes_header() {
        let mut block = RelocationBlock::new(0x2000);
        block.add_entry(RelocationEntry::highlow(0x2400)).unwrap();
        block.add_entry(RelocationEntry::highlow(0x2800)).unwrap();
        let bytes = block.to_bytes();
        let page = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(page, 0x2000);
        let size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        assert_eq!(size as usize, bytes.len());
    }

    #[test]
    fn test_rebuilder_add_and_build_x86() {
        let mut r = RelocationRebuilder::new_x86(0x0040_0000);
        r.add_fixup(0x1000);
        r.add_fixup(0x1008);
        r.add_fixup(0x2000);
        let bytes = r.build();
        assert!(!bytes.is_empty());
        assert_eq!(r.stats().block_count, 2);
        assert_eq!(r.stats().total_entries, 3);
    }

    #[test]
    fn test_rebuilder_duplicate_skipped() {
        let mut r = RelocationRebuilder::new_x64(0x1_4000_0000);
        assert!(r.add_fixup(0x1000));
        assert!(!r.add_fixup(0x1000)); // duplicate
        assert_eq!(r.fixup_count(), 1);
    }

    #[test]
    fn test_rebuild_relocs_function() {
        let rvas = vec![0x1000u32, 0x1008, 0x1010, 0x2000];
        let bytes = rebuild_relocs(&rvas, 0x0040_0000, false);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_import_reloc_section_roundtrip() {
        let mut r1 = RelocationRebuilder::new_x86(0x0040_0000);
        r1.add_fixups(&[0x1000, 0x1010, 0x1020, 0x2000, 0x2100]);
        let bytes = r1.build();

        let mut r2 = RelocationRebuilder::new_x86(0x0040_0000);
        let imported = r2.import_reloc_section(&bytes).unwrap();
        assert_eq!(imported, 5);
        assert_eq!(r2.fixup_count(), 5);
    }

    #[test]
    fn test_heuristic_scan() {
        let image_base = 0x1_4000_0000u64;
        let va_start = image_base;
        let va_end = image_base + 0x10_0000;
        // Build 8 bytes of data holding a pointer in range
        let ptr = image_base + 0x1000;
        let mut data = vec![0u8; 16];
        data[0..8].copy_from_slice(&ptr.to_le_bytes());
        let mut r = RelocationRebuilder::new_x64(image_base);
        let count = r.heuristic_scan_x64(&data, 0x1000, va_start, va_end);
        assert_eq!(count, 1);
        assert_eq!(r.fixup_count(), 1);
    }

    #[test]
    fn test_rebuilder_display() {
        let r = RelocationRebuilder::new_x64(0x1_4000_0000);
        let s = r.to_string();
        assert!(s.contains("RelocationRebuilder"));
    }
}
