//! `dyld_rebase_info_parser` — Parse dyld rebase-info opcodes from Mach-O images.
//!
//! The rebase-info stream records every location inside a Mach-O image that
//! contains an absolute pointer that must be slid by the ASLR delta when dyld
//! loads the image.  Each location is encoded as a sequence of opcodes that
//! advance a small cursor through (segment, offset) space.
//!
//! # Relationship to `dyld_bind_info_parser`
//!
//! These are two symmetric parsers for two distinct Mach-O opcode streams:
//!
//! * **`dyld_rebase_info_parser`** (this module) — decodes the *rebase*-info stream.
//!   Rebase opcodes identify in-image absolute pointer locations that must be adjusted
//!   by the ASLR slide.  The state machine tracks only (segment, offset, `rebase_type`);
//!   there is no symbol name or dylib ordinal.
//!
//! * **`dyld_bind_info_parser`** — decodes the *bind*-info stream.  Bind opcodes carry
//!   external symbol names, dylib ordinals, addends, and flags; they resolve imported
//!   symbols rather than sliding local pointers.
//!
//! Both share the same ULEB128 wire format and a nearly identical opcode dispatch loop
//! but carry different semantic state and produce different result types.  They must
//! remain separate modules.

use crate::DyldError;

// ─────────────────────────────────────────────────────────────────────────────
// RebaseOpcode
// ─────────────────────────────────────────────────────────────────────────────

/// A single rebase-info opcode decoded from the raw byte stream.
///
/// The byte format is identical to bind-info: `(high-4-bits opcode) | (low-4-bits imm)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebaseOpcode {
    /// `REBASE_OPCODE_DONE` — ends the stream.
    Done,
    /// Set the rebase type (pointer / `text_absolute32` / `text_pcrel32`).
    SetTypeImm(u8),
    /// Set segment index and advance offset from a ULEB128.
    SetSegmentAndOffsetUleb { seg_index: u8, offset: u64 },
    /// Advance the current offset by `delta`.
    AddAddrUleb(u64),
    /// Advance by `imm * ptr_size` bytes.
    AddAddrImmScaled(u8),
    /// Rebase `imm` times, advancing by `ptr_size` between each.
    DoRebaseImmTimes(u8),
    /// Rebase a ULEB128-encoded number of times.
    DoRebaseUlebTimes(u64),
    /// Rebase once, then advance by a ULEB128-encoded delta.
    DoRebaseAddAddrUleb(u64),
    /// Rebase a ULEB128 count, advancing by (`skip` + `ptr_size`) between each.
    DoRebaseUlebTimesSkippingUleb { count: u64, skip: u64 },
    /// Unknown / unrecognised opcode byte.
    Unknown(u8),
}

impl std::fmt::Display for RebaseOpcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Done => write!(f, "DONE"),
            Self::SetTypeImm(t) => write!(f, "SET_TYPE_IMM({t})"),
            Self::SetSegmentAndOffsetUleb { seg_index, offset } => {
                write!(f, "SET_SEGMENT({seg_index}) OFFSET({offset:#x})")
            }
            Self::AddAddrUleb(d) => write!(f, "ADD_ADDR_ULEB({d:#x})"),
            Self::AddAddrImmScaled(s) => write!(f, "ADD_ADDR_IMM_SCALED({s})"),
            Self::DoRebaseImmTimes(n) => write!(f, "DO_REBASE_IMM_TIMES({n})"),
            Self::DoRebaseUlebTimes(n) => write!(f, "DO_REBASE_ULEB_TIMES({n})"),
            Self::DoRebaseAddAddrUleb(d) => write!(f, "DO_REBASE_ADD_ADDR_ULEB({d:#x})"),
            Self::DoRebaseUlebTimesSkippingUleb { count, skip } => {
                write!(f, "DO_REBASE_ULEB_TIMES_SKIPPING(count={count}, skip={skip:#x})")
            }
            Self::Unknown(b) => write!(f, "UNKNOWN({b:#04x})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RebaseEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A decoded rebase fixup location.
///
/// Represents a single pointer in the Mach-O image that dyld must slide by the
/// ASLR offset at load time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebaseEntry {
    /// Mach-O segment index (0-based).
    pub seg_index: u8,
    /// Byte offset within the segment where the pointer lives.
    pub seg_offset: u64,
    /// Rebase type: 1 = pointer, 2 = `text_absolute32`, 3 = `text_pcrel32`.
    pub rebase_type: u8,
}

impl RebaseEntry {
    /// Rebase type constant: pointer.
    pub const TYPE_POINTER: u8 = 1;
    /// Rebase type constant: 32-bit text absolute.
    pub const TYPE_TEXT_ABSOLUTE32: u8 = 2;
    /// Rebase type constant: 32-bit text PC-relative.
    pub const TYPE_TEXT_PCREL32: u8 = 3;

    /// Return a human-readable name for the rebase type.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self.rebase_type {
            Self::TYPE_POINTER => "pointer",
            Self::TYPE_TEXT_ABSOLUTE32 => "text_absolute32",
            Self::TYPE_TEXT_PCREL32 => "text_pcrel32",
            _ => "unknown",
        }
    }

    /// Return `true` if this entry is a simple 64-bit pointer rebase.
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        self.rebase_type == Self::TYPE_POINTER
    }
}

impl std::fmt::Display for RebaseEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RebaseEntry {{ seg={}, off={:#x}, type={} }}",
            self.seg_index,
            self.seg_offset,
            self.type_name()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ULEB helper
// ─────────────────────────────────────────────────────────────────────────────

fn read_uleb128(data: &[u8], pos: &mut usize) -> Result<u64, DyldError> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(*pos).ok_or(DyldError::Truncated(*pos))?;
        *pos += 1;
        if shift < 64 {
            result |= u64::from(byte & 0x7F) << shift;
        }
        shift = shift.saturating_add(7);
        if byte & 0x80 == 0 {
            break;
        }
        if shift >= 70 {
            return Err(DyldError::Parse("ULEB128 overflow".into()));
        }
    }
    Ok(result)
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldRebaseInfoParser
// ─────────────────────────────────────────────────────────────────────────────

/// Parser for a dyld rebase-info opcode stream.
///
/// Consumes raw rebase-info bytes (from `__LINKEDIT`) and converts them into a
/// flat list of [`RebaseEntry`] records — one per pointer fixup location.
///
/// # Example
/// ```text
/// let parser = DyldRebaseInfoParser::new(&rebase_info_bytes);
/// let entries = parser.parse_rebase_opcodes()?;
/// for entry in &entries {
///     println!("{entry}");
/// }
/// ```
pub struct DyldRebaseInfoParser<'a> {
    /// Raw byte slice of the rebase-info stream.
    data: &'a [u8],
    /// Pointer width in bytes (4 or 8).
    ptr_size: usize,
}

impl<'a> DyldRebaseInfoParser<'a> {
    /// Create a new parser for 64-bit images (default pointer size = 8).
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, ptr_size: 8 }
    }

    /// Create a parser for 32-bit images.
    #[must_use]
    pub const fn new_32bit(data: &'a [u8]) -> Self {
        Self { data, ptr_size: 4 }
    }

    /// Override the pointer size.
    #[must_use]
    pub const fn with_ptr_size(mut self, ptr_size: usize) -> Self {
        self.ptr_size = ptr_size;
        self
    }

    /// Decode the opcode stream into a list of raw [`RebaseOpcode`] values.
    ///
    /// No state machine is evaluated; each opcode is returned as-is.
    ///
    /// # Errors
    /// Returns [`DyldError`] on truncated data or ULEB128 overflow.
    pub fn decode_opcodes(&self) -> Result<Vec<RebaseOpcode>, DyldError> {
        let mut out = Vec::new();
        let mut pos = 0usize;

        while pos < self.data.len() {
            let byte = self.data[pos];
            pos += 1;
            let opcode = byte & 0xF0;
            let imm = byte & 0x0F;

            let decoded = match opcode {
                0x00 => {
                    out.push(RebaseOpcode::Done);
                    break;
                }
                0x10 => RebaseOpcode::SetTypeImm(imm),
                0x20 => RebaseOpcode::SetSegmentAndOffsetUleb {
                    seg_index: imm,
                    offset: read_uleb128(self.data, &mut pos)?,
                },
                0x30 => RebaseOpcode::AddAddrUleb(read_uleb128(self.data, &mut pos)?),
                0x40 => RebaseOpcode::AddAddrImmScaled(imm),
                0x50 => RebaseOpcode::DoRebaseImmTimes(imm),
                0x60 => RebaseOpcode::DoRebaseUlebTimes(read_uleb128(self.data, &mut pos)?),
                0x70 => RebaseOpcode::DoRebaseAddAddrUleb(read_uleb128(self.data, &mut pos)?),
                0x80 => {
                    let count = read_uleb128(self.data, &mut pos)?;
                    let skip = read_uleb128(self.data, &mut pos)?;
                    RebaseOpcode::DoRebaseUlebTimesSkippingUleb { count, skip }
                }
                _ => RebaseOpcode::Unknown(byte),
            };
            out.push(decoded);
        }
        Ok(out)
    }

    /// Decode the opcode stream and produce a flat list of [`RebaseEntry`] fixups.
    ///
    /// Runs the full opcode state machine, emitting one `RebaseEntry` for every
    /// "do-rebase" step.
    ///
    /// # Errors
    /// Returns [`DyldError`] on truncated data or ULEB128 overflow.
    pub fn parse_rebase_opcodes(&self) -> Result<Vec<RebaseEntry>, DyldError> {
        let mut entries = Vec::new();
        let mut pos = 0usize;

        let mut seg_index: u8 = 0;
        let mut seg_offset: u64 = 0;
        let mut rebase_type: u8 = RebaseEntry::TYPE_POINTER;

        let ptr_size = self.ptr_size as u64;

        macro_rules! emit {
            () => {
                entries.push(RebaseEntry {
                    seg_index,
                    seg_offset,
                    rebase_type,
                });
            };
        }

        while pos < self.data.len() {
            let byte = self.data[pos];
            pos += 1;
            let opcode = byte & 0xF0;
            let imm = byte & 0x0F;

            match opcode {
                // DONE
                0x00 => break,
                // SET_TYPE_IMM
                0x10 => {
                    rebase_type = imm;
                }
                // SET_SEGMENT_AND_OFFSET_ULEB
                0x20 => {
                    seg_index = imm;
                    seg_offset = read_uleb128(self.data, &mut pos)?;
                }
                // ADD_ADDR_ULEB
                0x30 => {
                    seg_offset = seg_offset.wrapping_add(read_uleb128(self.data, &mut pos)?);
                }
                // ADD_ADDR_IMM_SCALED (advance by imm * ptr_size)
                0x40 => {
                    seg_offset = seg_offset.wrapping_add(u64::from(imm).wrapping_mul(ptr_size));
                }
                // DO_REBASE_IMM_TIMES
                0x50 => {
                    for _ in 0..imm {
                        emit!();
                        seg_offset = seg_offset.wrapping_add(ptr_size);
                    }
                }
                // DO_REBASE_ULEB_TIMES
                0x60 => {
                    let count = read_uleb128(self.data, &mut pos)?;
                    for _ in 0..count {
                        emit!();
                        seg_offset = seg_offset.wrapping_add(ptr_size);
                    }
                }
                // DO_REBASE_ADD_ADDR_ULEB
                0x70 => {
                    emit!();
                    seg_offset = seg_offset
                        .wrapping_add(read_uleb128(self.data, &mut pos)?)
                        .wrapping_add(ptr_size);
                }
                // DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
                0x80 => {
                    let count = read_uleb128(self.data, &mut pos)?;
                    let skip = read_uleb128(self.data, &mut pos)?;
                    for _ in 0..count {
                        emit!();
                        seg_offset = seg_offset
                            .wrapping_add(skip)
                            .wrapping_add(ptr_size);
                    }
                }
                _ => {
                    // Unknown opcode — skip
                }
            }
        }

        Ok(entries)
    }

    /// Count the total number of rebase fixups without storing them.
    ///
    /// # Errors
    /// Returns [`DyldError`] on parse failure.
    pub fn count_entries(&self) -> Result<usize, DyldError> {
        Ok(self.parse_rebase_opcodes()?.len())
    }

    /// Return all entries in the given segment index.
    ///
    /// # Errors
    /// Returns [`DyldError`] on parse failure.
    pub fn entries_for_segment(&self, seg_index: u8) -> Result<Vec<RebaseEntry>, DyldError> {
        Ok(self
            .parse_rebase_opcodes()?
            .into_iter()
            .filter(|e| e.seg_index == seg_index)
            .collect())
    }

    /// Return all entries of a given rebase type.
    ///
    /// # Errors
    /// Returns [`DyldError`] on parse failure.
    pub fn entries_of_type(&self, rebase_type: u8) -> Result<Vec<RebaseEntry>, DyldError> {
        Ok(self
            .parse_rebase_opcodes()?
            .into_iter()
            .filter(|e| e.rebase_type == rebase_type)
            .collect())
    }

    /// Return all entries sorted by (`seg_index`, `seg_offset`).
    ///
    /// # Errors
    /// Returns [`DyldError`] on parse failure.
    pub fn entries_sorted(&self) -> Result<Vec<RebaseEntry>, DyldError> {
        let mut v = self.parse_rebase_opcodes()?;
        v.sort_by_key(|e| (e.seg_index, e.seg_offset));
        Ok(v)
    }

    /// Return statistics about the rebase stream.
    ///
    /// Returns `(total_entries, segment_breakdown)` where `segment_breakdown`
    /// maps segment index to the number of fixups in that segment.
    ///
    /// # Errors
    /// Returns [`DyldError`] on parse failure.
    pub fn statistics(&self) -> Result<RebaseStats, DyldError> {
        let entries = self.parse_rebase_opcodes()?;
        let total = entries.len();
        let mut by_segment: std::collections::BTreeMap<u8, usize> =
            std::collections::BTreeMap::new();
        let mut by_type: std::collections::BTreeMap<u8, usize> =
            std::collections::BTreeMap::new();
        for e in &entries {
            *by_segment.entry(e.seg_index).or_insert(0) += 1;
            *by_type.entry(e.rebase_type).or_insert(0) += 1;
        }
        Ok(RebaseStats {
            total,
            by_segment: by_segment.into_iter().collect(),
            by_type: by_type.into_iter().collect(),
        })
    }
}

impl std::fmt::Debug for DyldRebaseInfoParser<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DyldRebaseInfoParser")
            .field("data_len", &self.data.len())
            .field("ptr_size", &self.ptr_size)
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RebaseStats
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics about a rebase-info stream.
#[derive(Debug, Clone)]
pub struct RebaseStats {
    /// Total number of fixup entries.
    pub total: usize,
    /// Fixup count per segment index.
    pub by_segment: Vec<(u8, usize)>,
    /// Fixup count per rebase type.
    pub by_type: Vec<(u8, usize)>,
}

impl std::fmt::Display for RebaseStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "RebaseStats {{ total={} }}", self.total)?;
        for (seg, count) in &self.by_segment {
            writeln!(f, "  segment {seg}: {count} fixups")?;
        }
        for (ty, count) in &self.by_type {
            let name = match *ty {
                1 => "pointer",
                2 => "text_absolute32",
                3 => "text_pcrel32",
                _ => "unknown",
            };
            writeln!(f, "  type {name}: {count} fixups")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal rebase-info stream:
    /// 1. `SET_TYPE_IMM(1)`       → pointer type
    /// 2. `SET_SEGMENT_AND_OFFSET_ULEB(seg=0`, off=0x08)
    /// 3. `DO_REBASE_IMM_TIMES(3)`  → 3 pointer fixups at 0x08, 0x10, 0x18
    /// 4. DONE
    fn minimal_rebase_stream() -> Vec<u8> {
        let mut v = vec![];
        // SET_TYPE_IMM(1) = 0x10 | 1
        v.push(0x11);
        // SET_SEGMENT_AND_OFFSET_ULEB(seg=0) = 0x20 | 0
        v.push(0x20);
        // ULEB128(0x08)
        v.push(0x08);
        // DO_REBASE_IMM_TIMES(3) = 0x50 | 3
        v.push(0x53);
        // DONE
        v.push(0x00);
        v
    }

    #[test]
    fn test_parse_minimal_stream_three_entries() {
        let data = minimal_rebase_stream();
        let parser = DyldRebaseInfoParser::new(&data);
        let entries = parser.parse_rebase_opcodes().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].seg_offset, 0x08);
        assert_eq!(entries[1].seg_offset, 0x10);
        assert_eq!(entries[2].seg_offset, 0x18);
        assert!(entries.iter().all(|e| e.rebase_type == 1));
    }

    #[test]
    fn test_decode_opcodes_set_type_imm() {
        let data = minimal_rebase_stream();
        let parser = DyldRebaseInfoParser::new(&data);
        let ops = parser.decode_opcodes().unwrap();
        assert!(ops.iter().any(|o| matches!(o, RebaseOpcode::SetTypeImm(1))));
        assert!(ops.iter().any(|o| matches!(o, RebaseOpcode::Done)));
    }

    #[test]
    fn test_count_entries() {
        let data = minimal_rebase_stream();
        let parser = DyldRebaseInfoParser::new(&data);
        assert_eq!(parser.count_entries().unwrap(), 3);
    }

    #[test]
    fn test_empty_stream() {
        let parser = DyldRebaseInfoParser::new(&[]);
        assert!(parser.parse_rebase_opcodes().unwrap().is_empty());
    }

    #[test]
    fn test_done_only_stream() {
        let data = [0x00u8];
        let parser = DyldRebaseInfoParser::new(&data);
        assert!(parser.parse_rebase_opcodes().unwrap().is_empty());
    }

    #[test]
    fn test_entries_for_segment() {
        let data = minimal_rebase_stream();
        let parser = DyldRebaseInfoParser::new(&data);
        let seg0 = parser.entries_for_segment(0).unwrap();
        assert_eq!(seg0.len(), 3);
        let seg1 = parser.entries_for_segment(1).unwrap();
        assert!(seg1.is_empty());
    }

    #[test]
    fn test_entries_of_type() {
        let data = minimal_rebase_stream();
        let parser = DyldRebaseInfoParser::new(&data);
        let ptrs = parser.entries_of_type(RebaseEntry::TYPE_POINTER).unwrap();
        assert_eq!(ptrs.len(), 3);
        let text = parser
            .entries_of_type(RebaseEntry::TYPE_TEXT_ABSOLUTE32)
            .unwrap();
        assert!(text.is_empty());
    }

    #[test]
    fn test_entries_sorted() {
        let data = minimal_rebase_stream();
        let parser = DyldRebaseInfoParser::new(&data);
        let sorted = parser.entries_sorted().unwrap();
        for w in sorted.windows(2) {
            assert!(
                (w[0].seg_index, w[0].seg_offset) <= (w[1].seg_index, w[1].seg_offset)
            );
        }
    }

    #[test]
    fn test_statistics() {
        let data = minimal_rebase_stream();
        let parser = DyldRebaseInfoParser::new(&data);
        let stats = parser.statistics().unwrap();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.by_segment.len(), 1);
        assert_eq!(stats.by_segment[0], (0, 3));
        assert_eq!(stats.by_type.len(), 1);
        assert_eq!(stats.by_type[0], (1, 3));
    }

    #[test]
    fn test_statistics_display() {
        let data = minimal_rebase_stream();
        let parser = DyldRebaseInfoParser::new(&data);
        let stats = parser.statistics().unwrap();
        let s = stats.to_string();
        assert!(s.contains("total=3"));
        assert!(s.contains("pointer"));
    }

    #[test]
    fn test_do_rebase_uleb_times() {
        let mut data = vec![];
        // SET_TYPE_IMM(1)
        data.push(0x11);
        // SET_SEGMENT_AND_OFFSET_ULEB(0, 0)
        data.push(0x20);
        data.push(0x00);
        // DO_REBASE_ULEB_TIMES(5) = 0x60; ULEB128(5)
        data.push(0x60);
        data.push(5);
        data.push(0x00);
        let parser = DyldRebaseInfoParser::new(&data);
        let entries = parser.parse_rebase_opcodes().unwrap();
        assert_eq!(entries.len(), 5);
    }

    #[test]
    fn test_do_rebase_add_addr_uleb() {
        let mut data = vec![];
        // SET_TYPE_IMM(1)
        data.push(0x11);
        // SET_SEGMENT_AND_OFFSET_ULEB(0, 0x0)
        data.push(0x20);
        data.push(0x00);
        // DO_REBASE_ADD_ADDR_ULEB (0x70) with ULEB128(0x10) skip
        data.push(0x70);
        data.push(0x10); // skip = 0x10
        data.push(0x00);
        let parser = DyldRebaseInfoParser::new(&data);
        let entries = parser.parse_rebase_opcodes().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].seg_offset, 0x00);
    }

    #[test]
    fn test_do_rebase_uleb_times_skipping() {
        let mut data = vec![];
        data.push(0x11); // SET_TYPE_IMM(1)
        data.push(0x20); // SET_SEGMENT_AND_OFFSET_ULEB(0)
        data.push(0x00); // offset=0
        // DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
        data.push(0x80);
        data.push(4); // count=4
        data.push(8); // skip=8
        data.push(0x00);
        let parser = DyldRebaseInfoParser::new(&data);
        let entries = parser.parse_rebase_opcodes().unwrap();
        assert_eq!(entries.len(), 4);
        // Offsets: 0, 8+8=16, 32, 48
        assert_eq!(entries[0].seg_offset, 0);
        assert_eq!(entries[1].seg_offset, 16);
    }

    #[test]
    fn test_32bit_ptr_size() {
        let mut data = vec![];
        data.push(0x11); // SET_TYPE_IMM(1)
        data.push(0x20); // SET_SEGMENT_AND_OFFSET_ULEB(0)
        data.push(0x00);
        data.push(0x53); // DO_REBASE_IMM_TIMES(3)
        data.push(0x00);
        let parser = DyldRebaseInfoParser::new_32bit(&data);
        let entries = parser.parse_rebase_opcodes().unwrap();
        assert_eq!(entries.len(), 3);
        // With ptr_size=4, offsets: 0, 4, 8
        assert_eq!(entries[1].seg_offset, 4);
        assert_eq!(entries[2].seg_offset, 8);
    }

    #[test]
    fn test_rebase_entry_type_name() {
        let e = RebaseEntry {
            seg_index: 0,
            seg_offset: 0,
            rebase_type: RebaseEntry::TYPE_POINTER,
        };
        assert_eq!(e.type_name(), "pointer");
        assert!(e.is_pointer());
    }

    #[test]
    fn test_rebase_entry_display() {
        let e = RebaseEntry {
            seg_index: 2,
            seg_offset: 0x400,
            rebase_type: 1,
        };
        let s = e.to_string();
        assert!(s.contains("0x400"));
        assert!(s.contains("pointer"));
    }

    #[test]
    fn test_rebase_opcode_display() {
        assert_eq!(RebaseOpcode::Done.to_string(), "DONE");
        assert_eq!(RebaseOpcode::SetTypeImm(1).to_string(), "SET_TYPE_IMM(1)");
    }

    #[test]
    fn test_add_addr_imm_scaled() {
        let mut data = vec![];
        data.push(0x11); // SET_TYPE_IMM(1)
        data.push(0x20); // SET_SEGMENT(0) OFFSET(0)
        data.push(0x00);
        // ADD_ADDR_IMM_SCALED(2) = 0x40 | 2  → advance by 2*8 = 16
        data.push(0x42);
        // DO_REBASE_IMM_TIMES(1) = 0x50 | 1
        data.push(0x51);
        data.push(0x00);
        let parser = DyldRebaseInfoParser::new(&data);
        let entries = parser.parse_rebase_opcodes().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].seg_offset, 16);
    }

    #[test]
    fn test_parser_debug() {
        let p = DyldRebaseInfoParser::new(&[0x00]);
        let s = format!("{p:?}");
        assert!(s.contains("DyldRebaseInfoParser"));
    }

    #[test]
    fn test_unknown_opcode_skipped() {
        let mut data = vec![];
        data.push(0xF0); // Unknown opcode
        data.push(0x11); // SET_TYPE_IMM(1)
        data.push(0x20); data.push(0x00); // SET_SEGMENT(0, 0)
        data.push(0x51); // DO_REBASE_IMM_TIMES(1)
        data.push(0x00);
        let parser = DyldRebaseInfoParser::new(&data);
        let entries = parser.parse_rebase_opcodes().unwrap();
        assert_eq!(entries.len(), 1);
    }
}
