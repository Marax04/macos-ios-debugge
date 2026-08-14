//! `ar` archive and COFF object-file scanner.
//!
//! Parses Unix-style `.a` (ar) archives and COFF `.obj` files to extract
//! function bytes that can be turned into FLIRT patterns.

use std::collections::HashMap;

// ── LibraryError ──────────────────────────────────────────────────────────────

/// Errors that can occur while parsing library archives or object files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LibraryError {
    /// The file magic bytes do not match the expected format.
    InvalidMagic,
    /// The data ended before parsing was complete.
    Truncated,
    /// A structural parse error.
    ParseError(String),
    /// The object-file format is not supported.
    UnsupportedFormat,
}

impl std::fmt::Display for LibraryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid library magic"),
            Self::Truncated => write!(f, "library data truncated"),
            Self::ParseError(s) => write!(f, "library parse error: {s}"),
            Self::UnsupportedFormat => write!(f, "unsupported library format"),
        }
    }
}

impl std::error::Error for LibraryError {}

// ── FunctionSample ────────────────────────────────────────────────────────────

/// A raw function body extracted from an object file.
#[derive(Debug, Clone)]
pub struct FunctionSample {
    /// Function name as recorded in the symbol table.
    pub name: String,
    /// Raw byte content of the function.
    pub bytes: Vec<u8>,
    /// Byte offsets within `bytes` that contain relocatable addresses.
    pub reloc_offsets: Vec<u16>,
}

// ── ArMember ──────────────────────────────────────────────────────────────────

/// One member (entry) of a Unix `ar` archive.
#[derive(Debug, Clone)]
pub struct ArMember {
    /// Member file name (may be a long-name index like `/42`).
    pub name: String,
    /// Modification timestamp (seconds since Unix epoch).
    pub timestamp: u64,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// File mode / permissions.
    pub mode: u32,
    /// Size of the member data in bytes.
    pub size: usize,
    /// Raw data bytes of this member.
    pub data: Vec<u8>,
}

// ── ArArchive ─────────────────────────────────────────────────────────────────

/// A parsed Unix `ar` archive.
#[derive(Debug, Default)]
pub struct ArArchive {
    /// All non-special members of the archive.
    pub members: Vec<ArMember>,
}

/// Magic bytes at the start of every `ar` archive.
pub const AR_MAGIC: &[u8] = b"!<arch>\n";
/// Magic bytes of the `ar` member header terminator.
const AR_FMAG: &[u8] = b"`\n";
/// Size of a single `ar` member header.
const AR_HDR_SIZE: usize = 60;

impl ArArchive {
    /// Parse a Unix `ar` archive from raw bytes.
    ///
    /// Long-filename members (`//`) and symbol table members (`/`) are
    /// consumed silently.
    ///
    /// # Errors
    ///
    /// Returns [`LibraryError::InvalidMagic`] if the file does not start with
    /// `!<arch>\n`, [`LibraryError::Truncated`] if the data is too short, or
    /// [`LibraryError::ParseError`] for structural problems.
    pub fn parse(data: &[u8]) -> Result<Self, LibraryError> {
        if data.len() < AR_MAGIC.len() {
            return Err(LibraryError::Truncated);
        }
        if &data[..AR_MAGIC.len()] != AR_MAGIC {
            return Err(LibraryError::InvalidMagic);
        }

        let mut pos = AR_MAGIC.len();
        let mut members: Vec<ArMember> = Vec::new();
        // Long-filename strtab (present when a `//` member exists)
        let mut long_names: Option<Vec<u8>> = None;

        while pos + AR_HDR_SIZE <= data.len() {
            let hdr = &data[pos..pos + AR_HDR_SIZE];
            pos += AR_HDR_SIZE;

            // Validate FMAG
            if &hdr[58..60] != AR_FMAG {
                // Try to resync: skip to next even boundary
                if !pos.is_multiple_of(2) {
                    pos += 1;
                }
                continue;
            }

            let raw_name = trim_ar_field(&hdr[0..16]);
            let raw_date = trim_ar_field(&hdr[16..28]);
            let raw_uid = trim_ar_field(&hdr[28..34]);
            let group_field = trim_ar_field(&hdr[34..40]);
            let raw_mode = trim_ar_field(&hdr[40..48]);
            let raw_size = trim_ar_field(&hdr[48..58]);

            let size: usize = raw_size
                .parse()
                .map_err(|_| LibraryError::ParseError(format!("bad size field: {raw_size}")))?;

            let end_pos = pos.checked_add(size).ok_or(LibraryError::Truncated)?;
            if end_pos > data.len() {
                return Err(LibraryError::Truncated);
            }

            let member_data = data[pos..end_pos].to_vec();
            // Advance, aligning to even offset
            pos = end_pos;
            if !pos.is_multiple_of(2) {
                pos = pos.saturating_add(1);
            }

            let timestamp: u64 = raw_date.parse().unwrap_or(0);
            let uid: u32 = raw_uid.parse().unwrap_or(0);
            let gid: u32 = group_field.parse().unwrap_or(0);
            let mode: u32 = u32::from_str_radix(raw_mode, 8).unwrap_or(0);

            // Handle special members
            if raw_name == "/" || raw_name == "__.SYMDEF" || raw_name == "__.SYMDEF SORTED" {
                // Symbol table: skip
                continue;
            }
            if raw_name == "//" {
                // GNU long-filename table
                long_names = Some(member_data);
                continue;
            }

            // Resolve long name (GNU: `/offset` format)
            let resolved_name = long_names.as_ref().map_or_else(
                || raw_name.to_string(),
                |lns| raw_name.strip_prefix('/').map_or_else(
                    || raw_name.to_string(),
                    |offset_str| {
                        let off: usize = offset_str.parse().unwrap_or(0);
                        read_long_name(lns, off)
                    },
                ),
            );

            members.push(ArMember {
                name: resolved_name,
                timestamp,
                uid,
                gid,
                mode,
                size,
                data: member_data,
            });
        }

        Ok(Self { members })
    }

    /// Find a member by exact name.
    #[must_use]
    pub fn find_member(&self, name: &str) -> Option<&ArMember> {
        self.members.iter().find(|m| m.name == name)
    }
}

fn trim_ar_field(s: &[u8]) -> &str {
    std::str::from_utf8(s).unwrap_or("").trim_end()
}

fn read_long_name(strtab: &[u8], off: usize) -> String {
    if off >= strtab.len() {
        return String::new();
    }
    let slice = &strtab[off..];
    let end = slice
        .iter()
        .position(|&b| b == b'/' || b == 0)
        .unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).trim().to_string()
}

// ── COFF types ────────────────────────────────────────────────────────────────

/// Machine type constants used in COFF headers.
pub mod machine {
    /// x86 (32-bit).
    pub const X86: u16 = 0x014C;
    /// x86-64 (64-bit).
    pub const X64: u16 = 0x8664;
    /// ARM64 (`AArch64`).
    pub const ARM64: u16 = 0xAA64;
}

/// A parsed COFF object-file header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoffObjectHeader {
    /// Machine type (see [`machine`] constants).
    pub machine: u16,
    /// Number of sections.
    pub num_sections: u16,
    /// Timestamp.
    pub timestamp: u32,
    /// Byte offset of the symbol table.
    pub sym_table_ptr: u32,
    /// Number of symbols.
    pub sym_count: u32,
    /// Size of the optional header (usually 0 for object files).
    pub opt_header_size: u16,
    /// Characteristics flags.
    pub characteristics: u16,
}

/// A single section from a COFF object file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoffSection {
    /// Section name (up to 8 bytes, NUL-padded).
    pub name: String,
    /// Virtual size (in memory).
    pub virtual_size: u32,
    /// Virtual address (RVA).
    pub virtual_addr: u32,
    /// Size of raw data on disk.
    pub raw_size: u32,
    /// File offset to raw data.
    pub raw_offset: u32,
    /// Section flags.
    pub characteristics: u32,
}

/// A single symbol from a COFF symbol table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoffSymbol {
    /// Symbol name (resolved from string table if needed).
    pub name: String,
    /// Symbol value (usually an offset within the section).
    pub value: u32,
    /// Section number (1-based; 0 = undefined, -1 = absolute, -2 = debug).
    pub section_num: i16,
    /// Type field (bits 4-7 encode derived type: 0x20 = function).
    pub type_field: u16,
    /// Storage class (2 = EXTERNAL, 3 = STATIC, 101 = FUNCTION).
    pub storage_class: u8,
}

// ── COFF parser ───────────────────────────────────────────────────────────────

fn coff_u16(data: &[u8], off: usize) -> Result<u16, LibraryError> {
    if off + 2 > data.len() {
        return Err(LibraryError::Truncated);
    }
    Ok(u16::from_le_bytes([data[off], data[off + 1]]))
}

fn coff_u32(data: &[u8], off: usize) -> Result<u32, LibraryError> {
    if off + 4 > data.len() {
        return Err(LibraryError::Truncated);
    }
    Ok(u32::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
    ]))
}

fn coff_i16(data: &[u8], off: usize) -> Result<i16, LibraryError> {
    if off + 2 > data.len() {
        return Err(LibraryError::Truncated);
    }
    Ok(i16::from_le_bytes([data[off], data[off + 1]]))
}

/// Parse a COFF object-file from raw bytes.
///
/// Returns `(header, sections, symbols)`.
///
/// # Errors
///
/// Returns [`LibraryError::UnsupportedFormat`] for unrecognised machine types,
/// [`LibraryError::Truncated`] if the data ends prematurely, or
/// [`LibraryError::ParseError`] for structural problems.
pub fn parse_coff_object(
    data: &[u8],
) -> Result<(CoffObjectHeader, Vec<CoffSection>, Vec<CoffSymbol>), LibraryError> {
    if data.len() < 20 {
        return Err(LibraryError::Truncated);
    }

    let machine = coff_u16(data, 0)?;
    match machine {
        machine::X86 | machine::X64 | machine::ARM64 => {}
        _ => return Err(LibraryError::UnsupportedFormat),
    }

    let num_sections = coff_u16(data, 2)?;
    let timestamp = coff_u32(data, 4)?;
    let sym_table_ptr = coff_u32(data, 8)?;
    let sym_count = coff_u32(data, 12)?;
    let opt_header_size = coff_u16(data, 16)?;
    let characteristics = coff_u16(data, 18)?;

    let header = CoffObjectHeader {
        machine,
        num_sections,
        timestamp,
        sym_table_ptr,
        sym_count,
        opt_header_size,
        characteristics,
    };

    // Section headers start after the COFF header (20 bytes) + optional header
    let section_table_off = 20 + opt_header_size as usize;
    let sections = parse_coff_sections(data, section_table_off, num_sections as usize)?;

    // Symbol table and string table
    let sym_off = sym_table_ptr as usize;
    let sym_count_u = sym_count as usize;
    let string_table_off = sym_off.saturating_add(sym_count_u.saturating_mul(18));

    let symbols = if sym_off > 0 && sym_count_u > 0 && string_table_off <= data.len() {
        let strtab_size = if string_table_off.saturating_add(4) <= data.len() {
            coff_u32(data, string_table_off)? as usize
        } else {
            4
        };
        let strtab_end = string_table_off.saturating_add(strtab_size).min(data.len());
        let strtab = &data[string_table_off..strtab_end];
        parse_coff_symbols(data, sym_off, sym_count_u, strtab)?
    } else {
        Vec::new()
    };

    Ok((header, sections, symbols))
}

fn parse_coff_sections(
    data: &[u8],
    off: usize,
    count: usize,
) -> Result<Vec<CoffSection>, LibraryError> {
    const SECTION_HDR_SIZE: usize = 40;
    // Guard against an inflated count from untrusted COFF data; the maximum
    // number of sections is limited by what can actually fit in the file.
    let max_sections = data.len().saturating_sub(off) / SECTION_HDR_SIZE;
    if count > max_sections {
        return Err(LibraryError::Truncated);
    }
    let mut sections = Vec::with_capacity(count);

    for i in 0..count {
        let base = off + i * SECTION_HDR_SIZE;
        if base + SECTION_HDR_SIZE > data.len() {
            return Err(LibraryError::Truncated);
        }
        // Name: 8 bytes, NUL-padded
        let raw_name = &data[base..base + 8];
        let name_end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&raw_name[..name_end]).to_string();

        let virtual_size = coff_u32(data, base + 8)?;
        let virtual_addr = coff_u32(data, base + 12)?;
        let raw_size = coff_u32(data, base + 16)?;
        let raw_offset = coff_u32(data, base + 20)?;
        let characteristics = coff_u32(data, base + 36)?;

        sections.push(CoffSection {
            name,
            virtual_size,
            virtual_addr,
            raw_size,
            raw_offset,
            characteristics,
        });
    }

    Ok(sections)
}

fn parse_coff_symbols(
    data: &[u8],
    sym_off: usize,
    sym_count: usize,
    strtab: &[u8],
) -> Result<Vec<CoffSymbol>, LibraryError> {
    const SYM_SIZE: usize = 18;
    let mut symbols = Vec::new();
    let mut i = 0;

    while i < sym_count {
        let base = sym_off + i * SYM_SIZE;
        if base + SYM_SIZE > data.len() {
            break;
        }

        // Name: first 4 bytes are 0 = long name (offset in strtab at bytes 4-7)
        let name = if data[base..base + 4] == [0, 0, 0, 0] {
            let off = coff_u32(data, base + 4)? as usize;
            read_coff_str(strtab, off)
        } else {
            let raw = &data[base..base + 8];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&raw[..end]).to_string()
        };

        let value = coff_u32(data, base + 8)?;
        let section_num = coff_i16(data, base + 12)?;
        let type_field = coff_u16(data, base + 14)?;
        let storage_class = data[base + 16];
        let aux_count = data[base + 17] as usize;

        symbols.push(CoffSymbol {
            name,
            value,
            section_num,
            type_field,
            storage_class,
        });

        // Skip auxiliary records
        i += 1 + aux_count;
    }

    Ok(symbols)
}

fn read_coff_str(strtab: &[u8], off: usize) -> String {
    if off >= strtab.len() {
        return String::new();
    }
    let slice = &strtab[off..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).to_string()
}

// ── Function extraction ───────────────────────────────────────────────────────

/// Extract function byte sequences from a COFF object.
///
/// Considers symbols in `.text`-like sections with `EXTERNAL` (2) or
/// `STATIC` (3) storage class.
#[must_use]
pub fn extract_function_bytes_from_coff(
    data: &[u8],
    header: &CoffObjectHeader,
    sections: &[CoffSection],
    syms: &[CoffSymbol],
) -> Vec<FunctionSample> {
    let _ = header; // currently unused but kept for API completeness
    let mut samples = Vec::new();

    // Find .text sections (characteristic bit 0x20 = code)
    let text_sections: HashMap<usize, &CoffSection> = sections
        .iter()
        .enumerate()
        .filter(|(_, s)| (s.characteristics & 0x20) != 0 || s.name.starts_with(".text"))
        .map(|(i, s)| (i + 1, s)) // 1-based section index
        .collect();

    // Build a list of (section_num, value, name) for each eligible symbol,
    // then sort by (section_num, value) to compute symbol sizes.
    let mut eligible: Vec<(usize, u32, &str)> = syms
        .iter()
        .filter(|s| {
            (s.storage_class == 2 || s.storage_class == 3)
                && s.section_num > 0
                && text_sections.contains_key(&(usize::try_from(s.section_num).unwrap_or(0)))
        })
        .map(|s| (usize::try_from(s.section_num).unwrap_or(0), s.value, s.name.as_str()))
        .collect();

    eligible.sort_by_key(|(sec, val, _)| (*sec, *val));

    for i in 0..eligible.len() {
        let (sec_idx, start_val, name) = eligible[i];
        let sec = match text_sections.get(&sec_idx) {
            Some(s) => *s,
            None => continue,
        };

        // Determine end: next symbol in same section or end of section
        let end_val: u32 = eligible
            .iter()
            .skip(i + 1)
            .find(|(s, _, _)| *s == sec_idx)
            .map_or(sec.raw_size, |(_, v, _)| *v);

        let size = end_val.saturating_sub(start_val) as usize;
        if size == 0 {
            continue;
        }

        let Some(data_start) = (sec.raw_offset as usize).checked_add(start_val as usize) else { continue };
        let Some(data_end) = data_start.checked_add(size) else { continue };
        if data_end > data.len() {
            continue;
        }

        let bytes = data[data_start..data_end].to_vec();

        samples.push(FunctionSample {
            name: name.to_string(),
            bytes,
            reloc_offsets: Vec::new(), // reloc table not parsed here
        });
    }

    samples
}

/// Extract all function samples from every COFF member in an `ar` archive.
#[must_use]
pub fn extract_samples_from_ar(archive: &ArArchive) -> Vec<FunctionSample> {
    let mut all = Vec::new();

    for member in &archive.members {
        // Attempt to parse as COFF
        if let Ok((hdr, secs, syms)) = parse_coff_object(&member.data) {
            let mut samples =
                extract_function_bytes_from_coff(&member.data, &hdr, &secs, &syms);
            all.append(&mut samples);
        } else {
            // Not a COFF object; skip silently.
        }
    }

    all
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ArArchive ─────────────────────────────────────────────────────────────

    fn make_ar_member_header(name: &str, size: usize) -> Vec<u8> {
        let mut hdr = vec![b' '; 60];
        // Name (16 bytes)
        let name_b = name.as_bytes();
        let nlen = name_b.len().min(16);
        hdr[..nlen].copy_from_slice(&name_b[..nlen]);
        // Date (12 bytes)
        let date = b"0           ";
        hdr[16..28].copy_from_slice(date);
        // UID (6) GID (6)
        let uid = b"0     ";
        hdr[28..34].copy_from_slice(uid);
        hdr[34..40].copy_from_slice(uid);
        // Mode (8)
        hdr[40..48].copy_from_slice(b"100644  ");
        // Size (10)
        let size_str = format!("{size:<10}");
        let sb = size_str.as_bytes();
        hdr[48..58].copy_from_slice(&sb[..10]);
        // FMAG
        hdr[58] = b'`';
        hdr[59] = b'\n';
        hdr
    }

    fn make_ar_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut data = AR_MAGIC.to_vec();
        for (name, content) in members {
            let hdr = make_ar_member_header(name, content.len());
            data.extend_from_slice(&hdr);
            data.extend_from_slice(content);
            if content.len() % 2 != 0 {
                data.push(b'\n'); // padding
            }
        }
        data
    }

    #[test]
    fn test_ar_parse_empty_archive() {
        let data = AR_MAGIC.to_vec();
        let ar = ArArchive::parse(&data).unwrap();
        assert!(ar.members.is_empty());
    }

    #[test]
    fn test_ar_parse_invalid_magic() {
        let r = ArArchive::parse(b"NOT_AR_ARCHIVE");
        assert!(matches!(r, Err(LibraryError::InvalidMagic)));
    }

    #[test]
    fn test_ar_parse_truncated() {
        let r = ArArchive::parse(b"!<ar");
        assert!(matches!(r, Err(LibraryError::Truncated)));
    }

    #[test]
    fn test_ar_parse_single_member() {
        let content = b"hello world";
        let data = make_ar_archive(&[("test.o  ", content)]);
        let ar = ArArchive::parse(&data).unwrap();
        assert_eq!(ar.members.len(), 1);
        assert_eq!(ar.members[0].data, content);
    }

    #[test]
    fn test_ar_parse_multiple_members() {
        let data = make_ar_archive(&[("a.o     ", b"aaa"), ("b.o     ", b"bbbb")]);
        let ar = ArArchive::parse(&data).unwrap();
        assert_eq!(ar.members.len(), 2);
    }

    #[test]
    fn test_ar_find_member_found() {
        let data = make_ar_archive(&[("foo.o   ", b"data")]);
        let ar = ArArchive::parse(&data).unwrap();
        assert!(ar.find_member("foo.o").is_some());
    }

    #[test]
    fn test_ar_find_member_not_found() {
        let data = make_ar_archive(&[("foo.o   ", b"data")]);
        let ar = ArArchive::parse(&data).unwrap();
        assert!(ar.find_member("bar.o").is_none());
    }

    // ── COFF parser ───────────────────────────────────────────────────────────

    fn make_minimal_coff(machine: u16) -> Vec<u8> {
        let mut v = vec![0u8; 20];
        v[0..2].copy_from_slice(&machine.to_le_bytes());
        v[2..4].copy_from_slice(&0u16.to_le_bytes()); // num_sections
        v[8..12].copy_from_slice(&0u32.to_le_bytes()); // sym_table_ptr
        v[12..16].copy_from_slice(&0u32.to_le_bytes()); // sym_count
        v[16..18].copy_from_slice(&0u16.to_le_bytes()); // opt_header_size
        v[18..20].copy_from_slice(&0u16.to_le_bytes()); // characteristics
        v
    }

    #[test]
    fn test_parse_coff_x86() {
        let data = make_minimal_coff(machine::X86);
        let (hdr, secs, syms) = parse_coff_object(&data).unwrap();
        assert_eq!(hdr.machine, machine::X86);
        assert!(secs.is_empty());
        assert!(syms.is_empty());
    }

    #[test]
    fn test_parse_coff_x64() {
        let data = make_minimal_coff(machine::X64);
        let (hdr, _, _) = parse_coff_object(&data).unwrap();
        assert_eq!(hdr.machine, machine::X64);
    }

    #[test]
    fn test_parse_coff_arm64() {
        let data = make_minimal_coff(machine::ARM64);
        let (hdr, _, _) = parse_coff_object(&data).unwrap();
        assert_eq!(hdr.machine, machine::ARM64);
    }

    #[test]
    fn test_parse_coff_unsupported_machine() {
        let data = make_minimal_coff(0x1234);
        let r = parse_coff_object(&data);
        assert!(matches!(r, Err(LibraryError::UnsupportedFormat)));
    }

    #[test]
    fn test_parse_coff_truncated() {
        let r = parse_coff_object(b"short");
        assert!(matches!(r, Err(LibraryError::Truncated)));
    }

    // ── LibraryError display ──────────────────────────────────────────────────

    #[test]
    fn test_error_display_invalid_magic() {
        assert!(!LibraryError::InvalidMagic.to_string().is_empty());
    }

    #[test]
    fn test_error_display_truncated() {
        assert!(!LibraryError::Truncated.to_string().is_empty());
    }

    #[test]
    fn test_error_display_parse_error() {
        let e = LibraryError::ParseError("oops".to_string());
        assert!(e.to_string().contains("oops"));
    }

    #[test]
    fn test_error_display_unsupported_format() {
        assert!(!LibraryError::UnsupportedFormat.to_string().is_empty());
    }

    // ── extract_samples_from_ar ───────────────────────────────────────────────

    #[test]
    fn test_extract_samples_empty_archive() {
        let ar = ArArchive::default();
        let samples = extract_samples_from_ar(&ar);
        assert!(samples.is_empty());
    }

    #[test]
    fn test_extract_samples_non_coff_member() {
        let data = make_ar_archive(&[("notcoff.o", b"this is not a COFF object at all")]);
        let ar = ArArchive::parse(&data).unwrap();
        let samples = extract_samples_from_ar(&ar);
        // Should not crash; non-COFF members are silently skipped
        assert!(samples.is_empty());
    }

    #[test]
    fn test_function_sample_fields() {
        let s = FunctionSample {
            name: "my_fn".to_string(),
            bytes: vec![0x55, 0x8B, 0xEC],
            reloc_offsets: vec![],
        };
        assert_eq!(s.name, "my_fn");
        assert_eq!(s.bytes.len(), 3);
        assert!(s.reloc_offsets.is_empty());
    }
}
