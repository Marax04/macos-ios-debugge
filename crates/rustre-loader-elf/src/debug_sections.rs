//! ELF debug-section parsers: `.debug_str`, `.debug_abbrev`, `.debug_info`,
//! `.debug_line`, `.debug_frame`, `.eh_frame`, and `.debug_loc`.
//!
//! These are thin, allocation-efficient parsers targeting the subset of DWARF
//! information most useful for reverse engineering (compilation unit headers,
//! string lookups, line-number table prologs, CIE/FDE parsing for `.eh_frame`).

// ─────────────────────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────────────────────

fn read_u8(data: &[u8], off: usize) -> Option<u8> {
    data.get(off).copied()
}

fn read_u16_le(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .and_then(|b| b.try_into().ok())
        .map(u16::from_le_bytes)
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
}

fn read_u64_le(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
}

/// Decode an unsigned LEB128 integer from `data` starting at `*off`.
/// Advances `*off` past the encoded bytes.
fn read_uleb128(data: &[u8], off: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *data.get(*off)?;
        *off += 1;
        result |= (u64::from(b & 0x7F)) << shift;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 64 {
            return None; // overflow
        }
    }
}

/// Decode a signed LEB128 integer.
fn read_sleb128(data: &[u8], off: &mut usize) -> Option<i64> {
    let mut result = 0i64;
    let mut shift = 0u32;
    // Read all bytes; the last byte determines sign-extension.
    let final_byte = loop {
        let b = *data.get(*off)?;
        *off += 1;
        result |= i64::from(b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break b;
        }
        if shift >= 64 {
            return None;
        }
    };
    // Sign-extend if the last byte's sign bit was set.
    if shift < 64 && (final_byte & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    Some(result)
}

// ─────────────────────────────────────────────────────────────────────────────
// .debug_str parser
// ─────────────────────────────────────────────────────────────────────────────

/// Lookup a NUL-terminated string in the `.debug_str` section at byte offset
/// `offset`.
///
/// # Errors
/// Returns `Err(String)` if `offset` is out of range or no NUL is found.
pub fn debug_str_get(section: &[u8], offset: usize) -> Result<&str, String> {
    if offset >= section.len() {
        return Err(format!(".debug_str offset {offset} out of range"));
    }
    let end = section[offset..]
        .iter()
        .position(|&b| b == 0)
        .map_or(section.len(), |n| offset + n);
    std::str::from_utf8(&section[offset..end])
        .map_err(|e| format!("invalid UTF-8 in .debug_str: {e}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// .debug_abbrev types
// ─────────────────────────────────────────────────────────────────────────────

/// One attribute specification in an abbreviation declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbbrevAttrSpec {
    /// `DW_AT`_* tag (0 = end-of-list sentinel).
    pub name: u64,
    /// `DW_FORM`_* form (0 = end-of-list sentinel).
    pub form: u64,
}

/// One abbreviation declaration from `.debug_abbrev`.
#[derive(Debug, Clone)]
pub struct AbbrevDecl {
    /// Abbreviation code (unique within a compilation unit's abbrev table).
    pub code: u64,
    /// `DW_TAG`_* tag.
    pub tag: u64,
    /// Whether this DIE has children.
    pub has_children: bool,
    /// Ordered attribute specs.
    pub attrs: Vec<AbbrevAttrSpec>,
}

/// Parse all abbreviation declarations from a `.debug_abbrev` section.
///
/// # Errors
/// Returns `Err(String)` if the data is malformed.
pub fn parse_debug_abbrev(data: &[u8]) -> Result<Vec<AbbrevDecl>, String> {
    let mut off = 0;
    let mut decls = Vec::new();

    loop {
        let code = read_uleb128(data, &mut off)
            .ok_or_else(|| format!("truncated abbrev code at {off}"))?;
        if code == 0 {
            break; // end of abbreviation declarations
        }
        let tag =
            read_uleb128(data, &mut off).ok_or_else(|| format!("truncated abbrev tag at {off}"))?;
        let has_children = *data
            .get(off)
            .ok_or_else(|| format!("truncated has_children at {off}"))?
            == 1;
        off += 1;

        let mut attrs = Vec::new();
        loop {
            let name = read_uleb128(data, &mut off)
                .ok_or_else(|| format!("truncated attr name at {off}"))?;
            let form = read_uleb128(data, &mut off)
                .ok_or_else(|| format!("truncated attr form at {off}"))?;
            if name == 0 && form == 0 {
                break;
            }
            attrs.push(AbbrevAttrSpec { name, form });
        }

        decls.push(AbbrevDecl {
            code,
            tag,
            has_children,
            attrs,
        });
    }

    Ok(decls)
}

// ─────────────────────────────────────────────────────────────────────────────
// .debug_info — compilation unit header
// ─────────────────────────────────────────────────────────────────────────────

/// DWARF version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DwarfVersion {
    V2,
    V3,
    V4,
    V5,
    Unknown(u16),
}

impl DwarfVersion {
    const fn from_u16(v: u16) -> Self {
        match v {
            2 => Self::V2,
            3 => Self::V3,
            4 => Self::V4,
            5 => Self::V5,
            other => Self::Unknown(other),
        }
    }

    /// Return the numeric version value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::V2 => 2,
            Self::V3 => 3,
            Self::V4 => 4,
            Self::V5 => 5,
            Self::Unknown(v) => v,
        }
    }
}

/// DWARF compilation unit header.
#[derive(Debug, Clone)]
pub struct DebugInfoCuHeader {
    /// Unit length in bytes (not including the `unit_length` field itself).
    pub unit_length: u64,
    /// Whether this is a DWARF64 unit.
    pub is_64bit: bool,
    /// DWARF version.
    pub version: DwarfVersion,
    /// Offset into `.debug_abbrev` for this CU's abbreviation table.
    pub debug_abbrev_offset: u64,
    /// Address size in bytes (4 or 8).
    pub address_size: u8,
    /// Byte offset of the first DIE within `.debug_info`.
    pub first_die_offset: usize,
}

/// Parse all compilation unit headers from `.debug_info`.
///
/// # Errors
/// Returns `Err(String)` if a header is truncated or malformed.
pub fn parse_debug_info_headers(data: &[u8]) -> Result<Vec<DebugInfoCuHeader>, String> {
    let mut off = 0;
    let mut headers = Vec::new();

    while off < data.len() {
        let start = off;

        // Peek at the initial length to detect DWARF32 vs DWARF64.
        let initial_len =
            read_u32_le(data, off).ok_or_else(|| format!("short .debug_info at {off}"))?;
        off += 4;
        let (unit_length, is_64bit, length_size) = if initial_len == 0xFFFF_FFFF {
            let len =
                read_u64_le(data, off).ok_or_else(|| format!("short DWARF64 length at {off}"))?;
            off += 8;
            (len, true, 12usize)
        } else {
            (u64::from(initial_len), false, 4usize)
        };

        if unit_length == 0 {
            break;
        }

        let version_raw =
            read_u16_le(data, off).ok_or_else(|| format!("short .debug_info version at {off}"))?;
        off += 2;

        let version = DwarfVersion::from_u16(version_raw);

        let debug_abbrev_offset = if is_64bit {
            let v =
                read_u64_le(data, off).ok_or_else(|| format!("short abbrev_offset at {off}"))?;
            off += 8;
            v
        } else {
            let v =
                read_u32_le(data, off).ok_or_else(|| format!("short abbrev_offset at {off}"))?;
            off += 4;
            u64::from(v)
        };

        let address_size =
            read_u8(data, off).ok_or_else(|| format!("short address_size at {off}"))?;
        off += 1;

        let first_die_offset = off;

        headers.push(DebugInfoCuHeader {
            unit_length,
            is_64bit,
            version,
            debug_abbrev_offset,
            address_size,
            first_die_offset,
        });

        // Advance to the next CU.
        let unit_length_usize = usize::try_from(unit_length)
            .map_err(|_| format!("unit_length {unit_length} too large for usize"))?;
        let cu_end = start
            .checked_add(length_size)
            .and_then(|v| v.checked_add(unit_length_usize))
            .ok_or_else(|| format!("CU end overflows at offset {start}"))?;
        off = cu_end;
    }

    Ok(headers)
}

// ─────────────────────────────────────────────────────────────────────────────
// .debug_line — line number table prolog
// ─────────────────────────────────────────────────────────────────────────────

/// The prolog of a DWARF line-number table.
#[derive(Debug, Clone)]
pub struct LineTableProlog {
    pub total_length: u64,
    pub is_64bit: bool,
    pub version: u16,
    pub header_length: u64,
    pub min_instruction_length: u8,
    pub default_is_stmt: bool,
    pub line_base: i8,
    pub line_range: u8,
    pub opcode_base: u8,
    /// File names listed in the prolog.
    pub file_names: Vec<String>,
    /// Include directories listed in the prolog.
    pub include_dirs: Vec<String>,
    /// Offset (within `data`) of the first byte past the prolog. Equal to the
    /// start of the line-number opcode program. Lets callers resume parsing
    /// without having to recompute prolog length.
    pub prolog_end_offset: usize,
}

/// Parse the first line-number table prolog from `.debug_line` data.
///
/// # Errors
/// Returns `Err(String)` if the data is truncated or malformed.
pub fn parse_line_table_prolog(data: &[u8]) -> Result<LineTableProlog, String> {
    let mut off = 0;

    let initial_len =
        read_u32_le(data, off).ok_or_else(|| "short .debug_line initial_len".to_string())?;
    off += 4;
    let (total_length, is_64bit, hdr_off) = if initial_len == 0xFFFF_FFFF {
        let len = read_u64_le(data, off).ok_or_else(|| "short DWARF64 total_length".to_string())?;
        (len, true, 12usize)
    } else {
        (u64::from(initial_len), false, 4usize)
    };
    let _ = hdr_off;

    let version = read_u16_le(data, off).ok_or_else(|| "short .debug_line version".to_string())?;
    off += 2;

    let header_length = if is_64bit {
        let v = read_u64_le(data, off).ok_or_else(|| "short header_length".to_string())?;
        off += 8;
        v
    } else {
        let v = read_u32_le(data, off).ok_or_else(|| "short header_length".to_string())?;
        off += 4;
        u64::from(v)
    };

    let min_instruction_length = read_u8(data, off).ok_or_else(|| "short min_insn_len".to_string())?;
    off += 1;

    let default_is_stmt = read_u8(data, off).ok_or_else(|| "short default_is_stmt".to_string())? != 0;
    off += 1;

    let line_base = read_u8(data, off).ok_or_else(|| "short line_base".to_string())?.cast_signed();
    off += 1;

    let line_range = read_u8(data, off).ok_or_else(|| "short line_range".to_string())?;
    off += 1;

    let opcode_base = read_u8(data, off).ok_or_else(|| "short opcode_base".to_string())?;
    off += 1;

    // Skip standard opcode lengths array (opcode_base - 1 entries).
    off += (opcode_base as usize).saturating_sub(1);

    // Read include directories (NUL-terminated strings, terminated by an empty string).
    let mut include_dirs = Vec::new();
    loop {
        if off >= data.len() {
            return Err(format!(".debug_line include_dirs: offset {off} out of bounds"));
        }
        let end = data[off..].iter().position(|&b| b == 0).unwrap_or(0);
        if end == 0 {
            off += 1; // skip the terminator
            break;
        }
        let s = String::from_utf8_lossy(&data[off..off + end]).to_string();
        include_dirs.push(s);
        off += end + 1;
    }

    // Read file names: each entry is name(str), dir_idx(uleb), mtime(uleb), size(uleb).
    let mut file_names = Vec::new();
    loop {
        if off >= data.len() {
            return Err(format!(".debug_line file_names: offset {off} out of bounds"));
        }
        let end = data[off..].iter().position(|&b| b == 0).unwrap_or(0);
        if end == 0 {
            off += 1; // advance past the empty-string terminator byte
            break;
        }
        let name = String::from_utf8_lossy(&data[off..off + end]).to_string();
        off += end + 1;
        let _ = read_uleb128(data, &mut off); // dir_idx
        let _ = read_uleb128(data, &mut off); // mtime
        let _ = read_uleb128(data, &mut off); // size
        file_names.push(name);
    }

    Ok(LineTableProlog {
        total_length,
        is_64bit,
        version,
        header_length,
        min_instruction_length,
        default_is_stmt,
        line_base,
        line_range,
        opcode_base,
        file_names,
        include_dirs,
        prolog_end_offset: off,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// .eh_frame / .debug_frame — CIE and FDE
// ─────────────────────────────────────────────────────────────────────────────

/// Common Information Entry (CIE) from `.eh_frame` / `.debug_frame`.
#[derive(Debug, Clone)]
pub struct Cie {
    /// Offset of the CIE within the section.
    pub offset: usize,
    /// Return address register column.
    pub return_address_register: u8,
    /// Code alignment factor.
    pub code_alignment_factor: u64,
    /// Data alignment factor.
    pub data_alignment_factor: i64,
    /// Augmentation string (e.g. `"zR"`, `"zPL"`).
    pub augmentation: String,
    /// Whether this is a DWARF64 entry.
    pub is_64bit: bool,
}

/// Frame Description Entry (FDE) from `.eh_frame` / `.debug_frame`.
#[derive(Debug, Clone)]
pub struct Fde {
    /// Offset of the FDE within the section.
    pub offset: usize,
    /// Offset of the associated CIE.
    pub cie_offset: usize,
    /// Initial location (program counter value).
    pub initial_location: u64,
    /// Length of the covered range.
    pub address_range: u64,
}

/// The result of parsing `.eh_frame` or `.debug_frame`.
#[derive(Debug, Clone, Default)]
pub struct FrameSection {
    pub cies: Vec<Cie>,
    pub fdes: Vec<Fde>,
}

impl FrameSection {
    /// Number of CIEs + FDEs parsed.
    #[must_use]
    pub const fn total_entries(&self) -> usize {
        self.cies.len() + self.fdes.len()
    }

    /// Find the CIE at byte `offset` (if any).
    #[must_use]
    pub fn cie_at(&self, offset: usize) -> Option<&Cie> {
        self.cies.iter().find(|c| c.offset == offset)
    }

    /// Find the FDE at byte `offset` (if any).
    #[must_use]
    pub fn fde_at(&self, offset: usize) -> Option<&Fde> {
        self.fdes.iter().find(|f| f.offset == offset)
    }

    /// All FDEs whose range covers `pc`.
    #[must_use]
    pub fn fdes_for_pc(&self, pc: u64) -> Vec<&Fde> {
        self.fdes
            .iter()
            .filter(|f| pc >= f.initial_location && pc < f.initial_location + f.address_range)
            .collect()
    }
}

/// Parse `.eh_frame` data (a variant of DWARF call-frame information).
///
/// This handles both DWARF32 and DWARF64 entries and correctly distinguishes
/// CIE vs FDE entries via the CIE-ID field.
///
/// # Errors
/// Parse a CIE body starting at `off` in `data`, returning a `Cie` and an updated offset.
fn parse_cie_body(data: &[u8], off: usize, entry_start: usize, is_64bit: bool) -> Option<Cie> {
    let _version = read_u8(data, off)?;
    let mut cur = off + 1;
    let aug_end = data[cur..].iter().position(|&b| b == 0).unwrap_or(0);
    let augmentation = String::from_utf8_lossy(&data[cur..cur + aug_end]).to_string();
    cur += aug_end + 1;
    let code_alignment_factor = read_uleb128(data, &mut cur).unwrap_or(1);
    let data_alignment_factor = read_sleb128(data, &mut cur).unwrap_or(-1);
    let return_address_register = read_u8(data, cur).unwrap_or(0);
    Some(Cie { offset: entry_start, return_address_register, code_alignment_factor, data_alignment_factor, augmentation, is_64bit })
}

/// Parse the `.eh_frame` section into `CIE` and `FDE` records.
///
/// # Errors
/// Returns `Err(String)` if the data is truncated.
pub fn parse_eh_frame(data: &[u8]) -> Result<FrameSection, String> {
    let mut section = FrameSection::default();
    let mut off = 0;

    while off < data.len() {
        let entry_start = off;
        let initial_len_raw =
            read_u32_le(data, off).ok_or_else(|| format!("short eh_frame length at {off}"))?;
        if initial_len_raw == 0 { break; }

        off += 4;
        let (entry_len, is_64bit, length_field_size) = if initial_len_raw == 0xFFFF_FFFF {
            let len = read_u64_le(data, off)
                .ok_or_else(|| format!("short DWARF64 eh_frame length at {off}"))?;
            let len_usize = usize::try_from(len)
                .map_err(|_| format!("eh_frame entry_len {len} too large"))?;
            off += 8;
            (len_usize, true, 12usize)
        } else {
            (usize::try_from(initial_len_raw).unwrap_or(0), false, 4usize)
        };

        let id_off = off;
        let entry_data_end = entry_start
            .checked_add(length_field_size)
            .and_then(|v| v.checked_add(entry_len))
            .ok_or_else(|| format!("eh_frame entry_data_end overflows at {entry_start}"))?;
        if entry_data_end > data.len() {
            return Err(format!(
                "eh_frame entry extends to {entry_data_end} but data is only {} bytes",
                data.len()
            ));
        }

        if is_64bit {
            let cie_id =
                read_u64_le(data, off).ok_or_else(|| format!("short CIE_ID (64) at {off}"))?;
            off += 8;
            if cie_id == 0 {
                if let Some(cie) = parse_cie_body(data, off, entry_start, is_64bit) {
                    section.cies.push(cie);
                }
            } else {
                let cie_delta = usize::try_from(cie_id).unwrap_or(usize::MAX);
                let cie_pointer = id_off.saturating_add(4).saturating_sub(cie_delta);
                let initial_location = read_u64_le(data, off).unwrap_or(0);
                off += 8;
                let address_range = read_u64_le(data, off).unwrap_or(0);
                section.fdes.push(Fde { offset: entry_start, cie_offset: cie_pointer, initial_location, address_range });
            }
        } else {
            let cie_id =
                read_u32_le(data, off).ok_or_else(|| format!("short CIE_ID (32) at {off}"))?;
            off += 4;
            if cie_id == 0 {
                if let Some(cie) = parse_cie_body(data, off, entry_start, is_64bit) {
                    section.cies.push(cie);
                }
            } else {
                let cie_offset = id_off.saturating_add(4)
                    .saturating_sub(usize::try_from(cie_id).unwrap_or(0));
                let initial_location = read_u32_le(data, off).map_or(0, u64::from);
                off += 4;
                let address_range = read_u32_le(data, off).map_or(0, u64::from);
                section.fdes.push(Fde { offset: entry_start, cie_offset, initial_location, address_range });
            }
        }

        off = entry_data_end;
    }

    Ok(section)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── .debug_str ────────────────────────────────────────────────────────────

    #[test]
    fn test_debug_str_get_basic() {
        let data = b"hello\0world\0".to_vec();
        assert_eq!(debug_str_get(&data, 0).unwrap(), "hello");
        assert_eq!(debug_str_get(&data, 6).unwrap(), "world");
    }

    #[test]
    fn test_debug_str_get_out_of_range() {
        assert!(debug_str_get(&[], 0).is_err());
        assert!(debug_str_get(b"abc\0", 100).is_err());
    }

    // ── LEB128 ────────────────────────────────────────────────────────────────

    #[test]
    fn test_uleb128_single_byte() {
        let data = [0x05u8];
        let mut off = 0;
        assert_eq!(read_uleb128(&data, &mut off), Some(5));
        assert_eq!(off, 1);
    }

    #[test]
    fn test_uleb128_multi_byte() {
        // 0x80 0x01 encodes 128.
        let data = [0x80u8, 0x01];
        let mut off = 0;
        assert_eq!(read_uleb128(&data, &mut off), Some(128));
        assert_eq!(off, 2);
    }

    #[test]
    fn test_sleb128_negative() {
        // 0x7F encodes -1 in SLEB128.
        let data = [0x7Fu8];
        let mut off = 0;
        assert_eq!(read_sleb128(&data, &mut off), Some(-1));
    }

    #[test]
    fn test_sleb128_positive() {
        let data = [0x01u8];
        let mut off = 0;
        assert_eq!(read_sleb128(&data, &mut off), Some(1));
    }

    // ── .debug_abbrev ─────────────────────────────────────────────────────────

    #[test]
    fn test_parse_debug_abbrev_empty() {
        let data = [0u8]; // single zero = end of declarations
        let decls = parse_debug_abbrev(&data).unwrap();
        assert!(decls.is_empty());
    }

    #[test]
    fn test_parse_debug_abbrev_one_decl() {
        // code=1, tag=17 (DW_TAG_compile_unit), has_children=1, attr name=3 (DW_AT_name),
        // form=8 (DW_FORM_string), end (0,0), end code (0).
        let data: Vec<u8> = vec![
            0x01, // code = 1
            0x11, // tag = 17 (DW_TAG_compile_unit)
            0x01, // has_children = true
            0x03, // attr name = 3 (DW_AT_name)
            0x08, // form = 8 (DW_FORM_string)
            0x00, 0x00, // end of attrs
            0x00, // end of declarations
        ];
        let decls = parse_debug_abbrev(&data).unwrap();
        assert_eq!(decls.len(), 1);
        let d = &decls[0];
        assert_eq!(d.code, 1);
        assert_eq!(d.tag, 17);
        assert!(d.has_children);
        assert_eq!(d.attrs.len(), 1);
        assert_eq!(d.attrs[0].name, 3);
        assert_eq!(d.attrs[0].form, 8);
    }

    // ── .debug_info CU header ─────────────────────────────────────────────────

    #[test]
    fn test_parse_debug_info_headers_empty() {
        let headers = parse_debug_info_headers(&[]).unwrap();
        assert!(headers.is_empty());
    }

    #[test]
    fn test_parse_debug_info_headers_basic_dwarf4() {
        // DWARF32, version 4, address_size 8.
        // unit_length = 11 (version(2) + abbrev_offset(4) + addr_size(1) + 4 dummy bytes)
        let mut data = vec![0u8; 4 + 11]; // length field + unit content
        // unit_length = 11
        data[0..4].copy_from_slice(&11u32.to_le_bytes());
        // version = 4
        data[4..6].copy_from_slice(&4u16.to_le_bytes());
        // debug_abbrev_offset = 0
        data[6..10].copy_from_slice(&0u32.to_le_bytes());
        // address_size = 8
        data[10] = 8;
        // 4 dummy DIE bytes
        data[11..15].fill(0xFF);

        let headers = parse_debug_info_headers(&data).unwrap();
        assert_eq!(headers.len(), 1);
        let h = &headers[0];
        assert_eq!(h.version, DwarfVersion::V4);
        assert_eq!(h.address_size, 8);
        assert!(!h.is_64bit);
        assert_eq!(h.unit_length, 11);
    }

    #[test]
    fn test_parse_debug_info_headers_zero_length_terminates() {
        let data = vec![0u8; 4]; // unit_length = 0 → terminator
        let headers = parse_debug_info_headers(&data).unwrap();
        assert!(headers.is_empty());
    }

    // ── .debug_line prolog ────────────────────────────────────────────────────

    #[test]
    fn test_parse_line_table_prolog_minimal() {
        // Minimal DWARF32 line table prolog with no include dirs or files.
        // Fields: total_length(4), version(2), header_length(4), min_insn_len(1),
        //         default_is_stmt(1), line_base(1), line_range(1), opcode_base(1),
        //         standard_opcode_lengths[0..opcode_base-2], \0 (end dirs), \0 (end files)
        let opcode_base: u8 = 1; // no standard opcodes
        let prolog_content: Vec<u8> = vec![
            0x02,
            0x00, // version = 2
            0x06,
            0x00,
            0x00,
            0x00,        // header_length = 6
            0x01,        // min_insn_len = 1
            0x01,        // default_is_stmt = true
            0xFB,        // line_base = -5 (as i8)
            0x0A,        // line_range = 10
            opcode_base, // opcode_base = 1
            // no standard opcode lengths (opcode_base - 1 = 0 entries)
            0x00, // end of include dirs
            0x00, // end of file names
        ];
        let total_len = prolog_content.len() as u32;
        let mut data = total_len.to_le_bytes().to_vec();
        data.extend_from_slice(&prolog_content);

        let prolog = parse_line_table_prolog(&data).unwrap();
        assert_eq!(prolog.version, 2);
        assert_eq!(prolog.min_instruction_length, 1);
        assert_eq!(prolog.line_base, -5);
        assert_eq!(prolog.line_range, 10);
        assert!(prolog.include_dirs.is_empty());
        assert!(prolog.file_names.is_empty());
    }

    // ── .eh_frame / .debug_frame ─────────────────────────────────────────────

    #[test]
    fn test_parse_eh_frame_empty() {
        let fs = parse_eh_frame(&[]).unwrap();
        assert_eq!(fs.total_entries(), 0);
    }

    #[test]
    fn test_parse_eh_frame_terminator() {
        // 4-byte terminator (length = 0).
        let data = [0u8; 4];
        let fs = parse_eh_frame(&data).unwrap();
        assert_eq!(fs.total_entries(), 0);
    }

    #[test]
    fn test_parse_eh_frame_cie_minimal() {
        // Minimal CIE: length=12, CIE_ID=0, version=1, aug="", code_af=1, data_af=-4, RA reg=16
        // For DWARF32 eh_frame:
        //   length (4) = 12
        //   CIE_ID (4) = 0
        //   version (1) = 1
        //   augmentation (1) = 0  (empty string)
        //   code_alignment_factor (uleb128) = 1 → 0x01
        //   data_alignment_factor (sleb128) = -4 → 0x7C
        //   return_address_register (1) = 16
        let data: Vec<u8> = vec![
            0x0C, 0x00, 0x00, 0x00, // length = 12
            0x00, 0x00, 0x00, 0x00, // CIE_ID = 0 → this is a CIE
            0x01, // version = 1
            0x00, // augmentation = "" (NUL)
            0x01, // code_af = 1 (ULEB128)
            0x7C, // data_af = -4 (SLEB128)
            0x10, // RA register = 16
            0x00, 0x00, 0x00, // padding to make length = 12
        ];
        let fs = parse_eh_frame(&data).unwrap();
        assert_eq!(fs.cies.len(), 1);
        assert_eq!(fs.fdes.len(), 0);
        let cie = &fs.cies[0];
        assert_eq!(cie.return_address_register, 16);
        assert_eq!(cie.code_alignment_factor, 1);
        assert_eq!(cie.data_alignment_factor, -4);
    }

    #[test]
    fn test_frame_section_fdes_for_pc() {
        let mut fs = FrameSection::default();
        fs.fdes.push(Fde {
            offset: 0,
            cie_offset: 0,
            initial_location: 0x1000,
            address_range: 0x100,
        });
        assert_eq!(fs.fdes_for_pc(0x1050).len(), 1);
        assert_eq!(fs.fdes_for_pc(0x2000).len(), 0);
    }

    #[test]
    fn test_dwarf_version_roundtrip() {
        for v in [2u16, 3, 4, 5, 99] {
            let dv = DwarfVersion::from_u16(v);
            assert_eq!(dv.as_u16(), v);
        }
    }

    #[test]
    fn test_abbrev_attr_spec_eq() {
        let a = AbbrevAttrSpec { name: 3, form: 8 };
        let b = AbbrevAttrSpec { name: 3, form: 8 };
        assert_eq!(a, b);
    }

    #[test]
    fn test_parse_debug_info_multiple_cus() {
        // Build two back-to-back minimal CUs.
        let cu = {
            let mut v = vec![0u8; 4 + 7]; // 4-byte length + 7-byte content
            v[0..4].copy_from_slice(&7u32.to_le_bytes()); // unit_length = 7
            v[4..6].copy_from_slice(&4u16.to_le_bytes()); // version = 4
            v[6..10].copy_from_slice(&0u32.to_le_bytes()); // abbrev_offset = 0
            v[10] = 4; // address_size = 4
            v
        };
        let mut data = cu.clone();
        data.extend_from_slice(&cu);
        let headers = parse_debug_info_headers(&data).unwrap();
        assert_eq!(headers.len(), 2);
    }
}
