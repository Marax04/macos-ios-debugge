//! `dyld_bind_info_parser` — Parse dyld bind-info opcodes from Mach-O images.
//!
//! The dyld bind-info stream records all external symbol fixups that dyld must
//! perform at load time.  Each fixup is encoded as a sequence of opcodes that
//! manipulate a small "cursor" state machine.  This module decodes the opcode
//! stream into a flat list of [`BindEntry`] records.
//!
//! # Relationship to `dyld_rebase_info_parser`
//!
//! These are two symmetric parsers for two distinct Mach-O opcode streams:
//!
//! * **`dyld_bind_info_parser`** (this module) — decodes the *bind*-info stream
//!   (`__LINKEDIT` bind / lazy-bind / weak-bind sections).  Bind opcodes resolve external
//!   symbol references; the state machine tracks dylib ordinal, symbol name, addend, flags.
//!
//! * **`dyld_rebase_info_parser`** — decodes the *rebase*-info stream
//!   (`__LINKEDIT` rebase section).  Rebase opcodes record locations of absolute in-image
//!   pointers that must be slid by the ASLR delta; there is no symbol name or dylib ordinal.
//!
//! Both share the same ULEB128 wire format and a nearly identical opcode dispatch loop but
//! carry completely different semantic state and produce different result types.  They must
//! remain separate modules.

use crate::DyldError;

// ─────────────────────────────────────────────────────────────────────────────
// BindOpcode
// ─────────────────────────────────────────────────────────────────────────────

/// A single bind-info opcode, decoded from the raw byte stream.
///
/// Each opcode byte has the form `(high-4-bits opcode) | (low-4-bits imm)`.
/// Some opcodes are followed by ULEB128 or NUL-terminated string data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindOpcode {
    /// `BIND_OPCODE_DONE` — ends the bind-info stream.
    Done,
    /// Set the bind type (pointer, `text_abs`, `text_pcrel32`).
    SetDylibOrdinalImm(u8),
    /// Set the library ordinal from a ULEB128-encoded value.
    SetDylibOrdinalUleb(u64),
    /// Set the library ordinal from a signed SLEB128 value (special ordinals).
    SetDylibSpecialImm(i8),
    /// Set the target symbol name.
    SetSymbolTrailingFlagsImm { flags: u8, name: String },
    /// Set the bind type (0=pointer, `1=text_abs`, `2=text_pcrel32`).
    SetTypeImm(u8),
    /// Set the addend from a SLEB128-encoded value.
    SetAddendSleb(i64),
    /// Set the segment index and offset from a ULEB128 offset.
    SetSegmentAndOffsetUleb { seg_index: u8, offset: u64 },
    /// Advance the offset within the current segment by `delta * ptr_size`.
    AddAddrUleb(u64),
    /// Perform a bind and advance by one pointer width.
    DoBind,
    /// Perform `count` binds, advancing by `skip` bytes between each.
    DoBindAddAddrUleb(u64),
    /// Perform a bind, then advance by `imm * ptr_size` bytes.
    DoBindAddAddrImmScaled(u8),
    /// Perform `count` binds spaced `skip` bytes apart.
    DoBindUlebTimesSkippingUleb { count: u64, skip: u64 },
    /// Weak binds (`BIND_OPCODE_THREADED`).
    Threaded(u8),
    /// Unknown / unrecognised opcode byte.
    Unknown(u8),
}

impl std::fmt::Display for BindOpcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Done => write!(f, "DONE"),
            Self::SetDylibOrdinalImm(n) => write!(f, "SET_DYLIB_ORDINAL_IMM({n})"),
            Self::SetDylibOrdinalUleb(n) => write!(f, "SET_DYLIB_ORDINAL_ULEB({n})"),
            Self::SetDylibSpecialImm(n) => write!(f, "SET_DYLIB_SPECIAL_IMM({n})"),
            Self::SetSymbolTrailingFlagsImm { flags, name } => {
                write!(f, "SET_SYMBOL(flags={flags:#x}, name={name:?})")
            }
            Self::SetTypeImm(t) => write!(f, "SET_TYPE_IMM({t})"),
            Self::SetAddendSleb(a) => write!(f, "SET_ADDEND_SLEB({a})"),
            Self::SetSegmentAndOffsetUleb { seg_index, offset } => {
                write!(f, "SET_SEGMENT({seg_index}) OFFSET({offset:#x})")
            }
            Self::AddAddrUleb(d) => write!(f, "ADD_ADDR_ULEB({d:#x})"),
            Self::DoBind => write!(f, "DO_BIND"),
            Self::DoBindAddAddrUleb(skip) => write!(f, "DO_BIND_ADD_ADDR_ULEB({skip:#x})"),
            Self::DoBindAddAddrImmScaled(imm) => write!(f, "DO_BIND_ADD_ADDR_IMM_SCALED({imm})"),
            Self::DoBindUlebTimesSkippingUleb { count, skip } => {
                write!(f, "DO_BIND_ULEB_TIMES_SKIPPING_ULEB(count={count}, skip={skip:#x})")
            }
            Self::Threaded(sub) => write!(f, "THREADED({sub:#x})"),
            Self::Unknown(b) => write!(f, "UNKNOWN({b:#04x})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BindEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A decoded bind fixup entry.
///
/// After all state-machine opcodes have been interpreted, each "do-bind" step
/// produces one `BindEntry`.
#[derive(Debug, Clone)]
pub struct BindEntry {
    /// Mach-O segment index (0-based).
    pub seg_index: u8,
    /// Byte offset within the segment where the fixup is applied.
    pub seg_offset: u64,
    /// Bind type: 0 = pointer, 1 = text absolute, 2 = text pc-relative 32-bit.
    pub bind_type: u8,
    /// Library ordinal (1-based).  0 means "self", negative = special.
    pub library_ordinal: i32,
    /// Name of the symbol to bind.
    pub symbol_name: String,
    /// Symbol flags from the opcode stream.
    pub symbol_flags: u8,
    /// Addend added to the symbol value.
    pub addend: i64,
    /// `true` for weak-bind entries.
    pub is_weak: bool,
    /// `true` for lazy-bind entries.
    pub is_lazy: bool,
}

impl BindEntry {
    /// Return `true` if this entry targets an Objective-C symbol.
    #[must_use]
    pub fn is_objc(&self) -> bool {
        self.symbol_name.starts_with("_OBJC_") || self.symbol_name.starts_with("_objc_")
    }

    /// Return `true` if this entry targets a Swift symbol.
    #[must_use]
    pub fn is_swift(&self) -> bool {
        self.symbol_name.starts_with("$s") || self.symbol_name.starts_with("_$s")
    }
}

impl std::fmt::Display for BindEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BindEntry {{ seg={}, off={:#x}, ord={}, sym={:?}, addend={} }}",
            self.seg_index, self.seg_offset, self.library_ordinal, self.symbol_name, self.addend
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ULEB / SLEB helpers
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

fn read_sleb128(data: &[u8], pos: &mut usize) -> Result<i64, DyldError> {
    let mut result = 0i64;
    let mut shift = 0u32;
    let last_byte: u8;
    loop {
        let byte = *data.get(*pos).ok_or(DyldError::Truncated(*pos))?;
        *pos += 1;
        if shift < 64 {
            result |= i64::from(byte & 0x7F) << shift;
        }
        shift = shift.saturating_add(7);
        if byte & 0x80 == 0 {
            last_byte = byte;
            break;
        }
    }
    // Sign-extend
    if shift < 64 && (last_byte & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    Ok(result)
}

fn read_cstring(data: &[u8], pos: &mut usize) -> Result<String, DyldError> {
    let start = *pos;
    while *pos < data.len() && data[*pos] != 0 {
        *pos += 1;
    }
    let s = std::str::from_utf8(&data[start..*pos])
        .map_err(|_| DyldError::Parse("non-UTF-8 symbol name".into()))?
        .to_string();
    if *pos < data.len() {
        *pos += 1; // consume NUL
    }
    Ok(s)
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldBindInfoParser
// ─────────────────────────────────────────────────────────────────────────────

/// Parser for a dyld bind-info opcode stream.
///
/// Consumes raw bind-info bytes (extracted from a Mach-O `__LINKEDIT` section)
/// and decodes them into [`BindEntry`] and [`BindOpcode`] sequences.
///
/// # Usage
/// ```text
/// let parser = DyldBindInfoParser::new(&bind_info_bytes);
/// let entries = parser.parse_bind_opcodes()?;
/// ```
pub struct DyldBindInfoParser<'a> {
    /// Raw byte slice of the bind-info stream.
    data: &'a [u8],
    /// Whether to treat entries as lazy binds.
    is_lazy: bool,
    /// Whether to treat entries as weak binds.
    is_weak: bool,
    /// Pointer size in bytes (4 or 8).
    ptr_size: usize,
}

impl<'a> DyldBindInfoParser<'a> {
    /// Create a parser for a regular (non-lazy) bind-info stream.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            is_lazy: false,
            is_weak: false,
            ptr_size: 8,
        }
    }

    /// Create a parser for a lazy-bind stream.
    #[must_use]
    pub const fn new_lazy(data: &'a [u8]) -> Self {
        Self {
            data,
            is_lazy: true,
            is_weak: false,
            ptr_size: 8,
        }
    }

    /// Create a parser for a weak-bind stream.
    #[must_use]
    pub const fn new_weak(data: &'a [u8]) -> Self {
        Self {
            data,
            is_lazy: false,
            is_weak: true,
            ptr_size: 8,
        }
    }

    /// Set pointer size (4 for 32-bit images, 8 for 64-bit images).
    #[must_use]
    pub const fn with_ptr_size(mut self, ptr_size: usize) -> Self {
        self.ptr_size = ptr_size;
        self
    }

    /// Decode the opcode stream and return a list of bind entries.
    ///
    /// # Errors
    /// Returns [`DyldError`] on truncated data or malformed ULEB128/string.
    pub fn parse_bind_opcodes(&self) -> Result<Vec<BindEntry>, DyldError> {
        let mut entries = Vec::new();
        let mut pos = 0usize;

        // State machine cursor
        let mut seg_index: u8 = 0;
        let mut seg_offset: u64 = 0;
        let mut bind_type: u8 = 1; // BIND_TYPE_POINTER = 1
        let mut library_ordinal: i32 = 0;
        let mut symbol_name = String::new();
        let mut symbol_flags: u8 = 0;
        let mut addend: i64 = 0;

        let ptr_size = self.ptr_size as u64;

        macro_rules! emit_bind {
            () => {
                entries.push(BindEntry {
                    seg_index,
                    seg_offset,
                    bind_type,
                    library_ordinal,
                    symbol_name: symbol_name.clone(),
                    symbol_flags,
                    addend,
                    is_weak: self.is_weak,
                    is_lazy: self.is_lazy,
                });
            };
        }

        while pos < self.data.len() {
            let byte = self.data[pos];
            pos += 1;
            let opcode = byte & 0xF0;
            let imm = byte & 0x0F;

            match opcode {
                // BIND_OPCODE_DONE
                0x00 => break,
                // SET_DYLIB_ORDINAL_IMM
                0x10 => {
                    library_ordinal = i32::from(imm);
                }
                // SET_DYLIB_ORDINAL_ULEB
                0x20 => {
                    library_ordinal = read_uleb128(self.data, &mut pos)? as i32;
                }
                // SET_DYLIB_SPECIAL_IMM (negative ordinals: -1=self, -2=executable, -3=flat)
                0x30 => {
                    library_ordinal = if imm == 0 {
                        0
                    } else {
                        i32::from(imm) | !0x0F_i32
                    };
                }
                // SET_SYMBOL_TRAILING_FLAGS_IMM
                0x40 => {
                    symbol_flags = imm;
                    symbol_name = read_cstring(self.data, &mut pos)?;
                }
                // SET_TYPE_IMM
                0x50 => {
                    bind_type = imm;
                }
                // SET_ADDEND_SLEB
                0x60 => {
                    addend = read_sleb128(self.data, &mut pos)?;
                }
                // SET_SEGMENT_AND_OFFSET_ULEB
                0x70 => {
                    seg_index = imm;
                    seg_offset = read_uleb128(self.data, &mut pos)?;
                }
                // ADD_ADDR_ULEB
                0x80 => {
                    seg_offset = seg_offset.wrapping_add(read_uleb128(self.data, &mut pos)?);
                }
                // DO_BIND
                0x90 => {
                    seg_offset = seg_offset.wrapping_add(ptr_size);
                    emit_bind!();
                }
                // DO_BIND_ADD_ADDR_ULEB
                0xA0 => {
                    emit_bind!();
                    seg_offset = seg_offset
                        .wrapping_add(read_uleb128(self.data, &mut pos)?)
                        .wrapping_add(ptr_size);
                }
                // DO_BIND_ADD_ADDR_IMM_SCALED
                0xB0 => {
                    emit_bind!();
                    seg_offset = seg_offset
                        .wrapping_add(u64::from(imm).wrapping_mul(ptr_size))
                        .wrapping_add(ptr_size);
                }
                // DO_BIND_ULEB_TIMES_SKIPPING_ULEB
                0xC0 => {
                    let count = read_uleb128(self.data, &mut pos)?;
                    let skip = read_uleb128(self.data, &mut pos)?;
                    for _ in 0..count {
                        emit_bind!();
                        seg_offset = seg_offset
                            .wrapping_add(skip)
                            .wrapping_add(ptr_size);
                    }
                }
                // BIND_OPCODE_THREADED
                _ => {
                    // Unknown opcode — skip
                }
            }
        }

        Ok(entries)
    }

    /// Decode the opcode stream into a list of raw [`BindOpcode`] values (no state evaluation).
    ///
    /// Useful for disassembling the raw stream without executing the state machine.
    ///
    /// # Errors
    /// Returns [`DyldError`] on truncated data or malformed ULEB128/string.
    pub fn decode_opcodes(&self) -> Result<Vec<BindOpcode>, DyldError> {
        let mut out = Vec::new();
        let mut pos = 0usize;

        while pos < self.data.len() {
            let byte = self.data[pos];
            pos += 1;
            let opcode = byte & 0xF0;
            let imm = byte & 0x0F;

            let decoded = match opcode {
                0x00 => { out.push(BindOpcode::Done); break; }
                0x10 => BindOpcode::SetDylibOrdinalImm(imm),
                0x20 => BindOpcode::SetDylibOrdinalUleb(read_uleb128(self.data, &mut pos)?),
                0x30 => {
                    let v = if imm == 0 { 0i8 } else { imm.cast_signed() | !0x0F_i8 };
                    BindOpcode::SetDylibSpecialImm(v)
                }
                0x40 => {
                    let name = read_cstring(self.data, &mut pos)?;
                    BindOpcode::SetSymbolTrailingFlagsImm { flags: imm, name }
                }
                0x50 => BindOpcode::SetTypeImm(imm),
                0x60 => BindOpcode::SetAddendSleb(read_sleb128(self.data, &mut pos)?),
                0x70 => BindOpcode::SetSegmentAndOffsetUleb {
                    seg_index: imm,
                    offset: read_uleb128(self.data, &mut pos)?,
                },
                0x80 => BindOpcode::AddAddrUleb(read_uleb128(self.data, &mut pos)?),
                0x90 => BindOpcode::DoBind,
                0xA0 => BindOpcode::DoBindAddAddrUleb(read_uleb128(self.data, &mut pos)?),
                0xB0 => BindOpcode::DoBindAddAddrImmScaled(imm),
                0xC0 => {
                    let count = read_uleb128(self.data, &mut pos)?;
                    let skip = read_uleb128(self.data, &mut pos)?;
                    BindOpcode::DoBindUlebTimesSkippingUleb { count, skip }
                }
                0xD0 => BindOpcode::Threaded(imm),
                _ => BindOpcode::Unknown(byte),
            };
            out.push(decoded);
        }
        Ok(out)
    }

    /// Count the number of bind entries in the stream without storing them.
    ///
    /// # Errors
    /// Returns [`DyldError`] on parse failure.
    pub fn count_entries(&self) -> Result<usize, DyldError> {
        Ok(self.parse_bind_opcodes()?.len())
    }

    /// Filter entries by library ordinal.
    ///
    /// # Errors
    /// Returns [`DyldError`] on parse failure.
    pub fn entries_for_ordinal(&self, ordinal: i32) -> Result<Vec<BindEntry>, DyldError> {
        Ok(self
            .parse_bind_opcodes()?
            .into_iter()
            .filter(|e| e.library_ordinal == ordinal)
            .collect())
    }

    /// Filter entries by symbol name prefix.
    ///
    /// # Errors
    /// Returns [`DyldError`] on parse failure.
    pub fn entries_with_symbol_prefix(&self, prefix: &str) -> Result<Vec<BindEntry>, DyldError> {
        Ok(self
            .parse_bind_opcodes()?
            .into_iter()
            .filter(|e| e.symbol_name.starts_with(prefix))
            .collect())
    }
}

impl std::fmt::Debug for DyldBindInfoParser<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DyldBindInfoParser")
            .field("data_len", &self.data.len())
            .field("is_lazy", &self.is_lazy)
            .field("is_weak", &self.is_weak)
            .field("ptr_size", &self.ptr_size)
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal bind-info stream that encodes:
    /// 1. `SET_DYLIB_ORDINAL_IMM(1)`
    /// 2. `SET_SYMBOL` "foo" flags=0
    /// 3. `SET_SEGMENT_AND_OFFSET_ULEB(0`, 0x10)
    /// 4. `DO_BIND`
    /// 5. DONE
    fn minimal_bind_stream() -> Vec<u8> {
        let mut v = vec![];
        // SET_DYLIB_ORDINAL_IMM(1) = 0x10 | 1
        v.push(0x11);
        // SET_SYMBOL_TRAILING_FLAGS_IMM flags=0 = 0x40 | 0
        v.push(0x40);
        v.extend_from_slice(b"foo\0");
        // SET_SEGMENT_AND_OFFSET_ULEB(seg=0) = 0x70 | 0
        v.push(0x70);
        // ULEB128(0x10)
        v.push(0x10);
        // DO_BIND = 0x90
        v.push(0x90);
        // DONE = 0x00
        v.push(0x00);
        v
    }

    #[test]
    fn test_parse_minimal_bind_stream() {
        let data = minimal_bind_stream();
        let parser = DyldBindInfoParser::new(&data);
        let entries = parser.parse_bind_opcodes().unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.symbol_name, "foo");
        assert_eq!(e.library_ordinal, 1);
        assert_eq!(e.seg_index, 0);
        assert_eq!(e.seg_offset, 0x10 + 8); // advanced by ptr_size after DO_BIND
    }

    #[test]
    fn test_decode_opcodes_minimal() {
        let data = minimal_bind_stream();
        let parser = DyldBindInfoParser::new(&data);
        let ops = parser.decode_opcodes().unwrap();
        assert!(ops.iter().any(|o| matches!(o, BindOpcode::SetDylibOrdinalImm(1))));
        assert!(ops.iter().any(|o| matches!(o, BindOpcode::DoBind)));
        assert!(ops.iter().any(|o| matches!(o, BindOpcode::Done)));
    }

    #[test]
    fn test_count_entries() {
        let data = minimal_bind_stream();
        let parser = DyldBindInfoParser::new(&data);
        assert_eq!(parser.count_entries().unwrap(), 1);
    }

    #[test]
    fn test_empty_stream_no_entries() {
        let parser = DyldBindInfoParser::new(&[]);
        let entries = parser.parse_bind_opcodes().unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_done_only_stream() {
        let data = [0x00u8];
        let parser = DyldBindInfoParser::new(&data);
        let entries = parser.parse_bind_opcodes().unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_lazy_flag_propagated() {
        let data = minimal_bind_stream();
        let parser = DyldBindInfoParser::new_lazy(&data);
        let entries = parser.parse_bind_opcodes().unwrap();
        assert!(entries[0].is_lazy);
        assert!(!entries[0].is_weak);
    }

    #[test]
    fn test_weak_flag_propagated() {
        let data = minimal_bind_stream();
        let parser = DyldBindInfoParser::new_weak(&data);
        let entries = parser.parse_bind_opcodes().unwrap();
        assert!(entries[0].is_weak);
    }

    #[test]
    fn test_entries_for_ordinal_filters() {
        let data = minimal_bind_stream();
        let parser = DyldBindInfoParser::new(&data);
        let found = parser.entries_for_ordinal(1).unwrap();
        assert_eq!(found.len(), 1);
        let missing = parser.entries_for_ordinal(99).unwrap();
        assert!(missing.is_empty());
    }

    #[test]
    fn test_entries_with_symbol_prefix() {
        let data = minimal_bind_stream();
        let parser = DyldBindInfoParser::new(&data);
        let found = parser.entries_with_symbol_prefix("fo").unwrap();
        assert_eq!(found.len(), 1);
        let none = parser.entries_with_symbol_prefix("_OBJC").unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn test_bind_entry_is_objc_false() {
        let e = BindEntry {
            seg_index: 0,
            seg_offset: 0,
            bind_type: 1,
            library_ordinal: 1,
            symbol_name: "_malloc".into(),
            symbol_flags: 0,
            addend: 0,
            is_weak: false,
            is_lazy: false,
        };
        assert!(!e.is_objc());
        assert!(!e.is_swift());
    }

    #[test]
    fn test_bind_entry_is_objc_true() {
        let e = BindEntry {
            seg_index: 0,
            seg_offset: 0,
            bind_type: 1,
            library_ordinal: 2,
            symbol_name: "_OBJC_CLASS_$_NSObject".into(),
            symbol_flags: 0,
            addend: 0,
            is_weak: false,
            is_lazy: false,
        };
        assert!(e.is_objc());
    }

    #[test]
    fn test_bind_entry_display() {
        let e = BindEntry {
            seg_index: 1,
            seg_offset: 0x100,
            bind_type: 1,
            library_ordinal: 3,
            symbol_name: "_malloc".into(),
            symbol_flags: 0,
            addend: 0,
            is_weak: false,
            is_lazy: false,
        };
        let s = e.to_string();
        assert!(s.contains("_malloc"));
    }

    #[test]
    fn test_bind_opcode_display_done() {
        assert_eq!(BindOpcode::Done.to_string(), "DONE");
    }

    #[test]
    fn test_uleb128_multi_byte() {
        // Build stream that sets ordinal via ULEB128 = 300 (0xAC 0x02)
        let mut data = vec![];
        data.push(0x20); // SET_DYLIB_ORDINAL_ULEB
        data.push(0xAC); // ULEB128 byte 1
        data.push(0x02); // ULEB128 byte 2 (300 = 0xAC & 0x7F | (0x02 << 7) = 44 + 256 = 300)
        data.push(0x00); // DONE
        let parser = DyldBindInfoParser::new(&data);
        let ops = parser.decode_opcodes().unwrap();
        assert!(ops.iter().any(|o| matches!(o, BindOpcode::SetDylibOrdinalUleb(300))));
    }

    #[test]
    fn test_set_addend_sleb() {
        let mut data = vec![];
        data.push(0x60); // SET_ADDEND_SLEB
        data.push(0x7F); // SLEB128: -1 in one byte (0x7F = sign bit set → -1)
        data.push(0x00); // DONE
        let parser = DyldBindInfoParser::new(&data);
        let ops = parser.decode_opcodes().unwrap();
        assert!(ops.iter().any(|o| matches!(o, BindOpcode::SetAddendSleb(-1))));
    }

    #[test]
    fn test_parser_debug() {
        let data = [0u8; 4];
        let p = DyldBindInfoParser::new(&data);
        let s = format!("{p:?}");
        assert!(s.contains("DyldBindInfoParser"));
    }

    #[test]
    fn test_do_bind_uleb_times_skipping() {
        let mut data = vec![];
        // SET_SYMBOL "bar"
        data.push(0x40);
        data.extend_from_slice(b"bar\0");
        // SET_SEGMENT_AND_OFFSET_ULEB(0, 0x00)
        data.push(0x70);
        data.push(0x00);
        // DO_BIND_ULEB_TIMES_SKIPPING_ULEB count=3 skip=0
        data.push(0xC0);
        data.push(3); // count
        data.push(0); // skip
        data.push(0x00); // DONE
        let parser = DyldBindInfoParser::new(&data);
        let entries = parser.parse_bind_opcodes().unwrap();
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().all(|e| e.symbol_name == "bar"));
    }
}
