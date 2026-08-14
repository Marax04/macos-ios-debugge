//! `code_cave` — Locate executable code caves inside PE and ELF binaries.
//!
//! Code caves are runs of padding bytes used as scratch space when applying
//! inline patches that need extra room (e.g. detours, trampolines, jump islands).
//!
//! Parses only the headers/section tables — no third-party object-file
//! dependency is pulled in. Anything that fails sanity checks is rejected,
//! never silently ignored.

use std::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced while scanning for code caves.
#[derive(Debug, Error)]
pub enum CaveError {
    /// The binary is too small to contain even a header.
    #[error("binary too small ({0} bytes) to contain valid headers")]
    TooSmall(usize),
    /// The format is not recognised (neither PE nor ELF).
    #[error("unrecognised binary format (magic = {0:#06x})")]
    UnknownFormat(u16),
    /// A header field points outside the binary.
    #[error("malformed header: {0}")]
    Malformed(&'static str),
    /// The minimum cave size requested is zero.
    #[error("minimum cave size must be greater than zero")]
    InvalidMinSize,
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Binary format detected by the scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    /// Portable Executable (Windows).
    Pe,
    /// Executable and Linkable Format (Unix-like).
    Elf,
}

impl fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pe => "PE",
            Self::Elf => "ELF",
        })
    }
}

/// A contiguous executable region of padding bytes inside a binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeCave {
    /// Section name (e.g. `.text`, `.code`).
    pub section: String,
    /// File offset of the first padding byte.
    pub file_offset: u64,
    /// Virtual address of the first padding byte (if known).
    pub virtual_address: Option<u64>,
    /// Length of the cave in bytes.
    pub size: usize,
    /// The padding byte that fills this cave (commonly `0x00` or `0xCC`).
    pub fill_byte: u8,
}

impl fmt::Display for CodeCave {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.virtual_address {
            Some(va) => write!(
                f,
                "CodeCave[{}] file@{:#x} va@{:#x} {} bytes (fill={:#04x})",
                self.section, self.file_offset, va, self.size, self.fill_byte
            ),
            None => write!(
                f,
                "CodeCave[{}] file@{:#x} {} bytes (fill={:#04x})",
                self.section, self.file_offset, self.size, self.fill_byte
            ),
        }
    }
}

/// Section view used internally — represents an executable section of the binary.
#[derive(Debug, Clone)]
struct ExecSection {
    name: String,
    file_offset: u64,
    file_size: u64,
    virtual_address: Option<u64>,
}

/// Scanner that searches a binary for code caves.
#[derive(Debug, Clone)]
pub struct CodeCaveScanner {
    /// Minimum cave size to report (bytes).
    pub min_size: usize,
    /// Padding bytes considered cave fillers. Defaults to `[0x00, 0xCC, 0x90]`.
    pub fill_bytes: Vec<u8>,
}

impl Default for CodeCaveScanner {
    fn default() -> Self {
        Self {
            min_size: 16,
            fill_bytes: vec![0x00, 0xCC, 0x90],
        }
    }
}

impl CodeCaveScanner {
    /// Create a new scanner with the given minimum cave size.
    ///
    /// # Errors
    ///
    /// Returns [`CaveError::InvalidMinSize`] if `min_size` is zero.
    pub fn new(min_size: usize) -> Result<Self, CaveError> {
        if min_size == 0 {
            return Err(CaveError::InvalidMinSize);
        }
        Ok(Self {
            min_size,
            fill_bytes: vec![0x00, 0xCC, 0x90],
        })
    }

    /// Replace the set of fill bytes considered cave material.
    #[must_use]
    pub fn with_fill_bytes(mut self, fill_bytes: Vec<u8>) -> Self {
        self.fill_bytes = fill_bytes;
        self
    }

    /// Detect the binary format from magic bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CaveError::TooSmall`] if `binary` is shorter than the magic, or
    /// [`CaveError::UnknownFormat`] if no known signature is detected.
    pub fn detect_format(binary: &[u8]) -> Result<BinaryFormat, CaveError> {
        if binary.len() < 4 {
            return Err(CaveError::TooSmall(binary.len()));
        }
        if &binary[0..4] == b"\x7FELF" {
            return Ok(BinaryFormat::Elf);
        }
        if binary.len() >= 2 && &binary[0..2] == b"MZ" {
            return Ok(BinaryFormat::Pe);
        }
        let magic = u16::from_le_bytes([binary[0], binary[1]]);
        Err(CaveError::UnknownFormat(magic))
    }

    /// Scan the binary and return all code caves at least `min_size` bytes long.
    ///
    /// # Errors
    ///
    /// Returns [`CaveError`] if the binary format cannot be detected or its
    /// headers are malformed.
    pub fn scan(&self, binary: &[u8]) -> Result<Vec<CodeCave>, CaveError> {
        let format = Self::detect_format(binary)?;
        let sections = match format {
            BinaryFormat::Pe => parse_pe_exec_sections(binary)?,
            BinaryFormat::Elf => parse_elf_exec_sections(binary)?,
        };

        let mut caves = Vec::new();
        for section in sections {
            self.scan_section(binary, &section, &mut caves);
        }
        Ok(caves)
    }

    fn scan_section(&self, binary: &[u8], section: &ExecSection, out: &mut Vec<CodeCave>) {
        let start = usize::try_from(section.file_offset).unwrap_or(usize::MAX);
        let end = start.saturating_add(usize::try_from(section.file_size).unwrap_or(usize::MAX)).min(binary.len());
        if start >= end {
            return;
        }
        let slice = &binary[start..end];

        let mut i = 0;
        while i < slice.len() {
            let byte = slice[i];
            if !self.fill_bytes.contains(&byte) {
                i += 1;
                continue;
            }
            let run_start = i;
            while i < slice.len() && self.fill_bytes.contains(&slice[i]) {
                i += 1;
            }
            let run_len = i - run_start;
            if run_len >= self.min_size {
                let file_offset = (start + run_start) as u64;
                let virtual_address = section
                    .virtual_address
                    .map(|va| va + run_start as u64);
                out.push(CodeCave {
                    section: section.name.clone(),
                    file_offset,
                    virtual_address,
                    size: run_len,
                    fill_byte: byte,
                });
            }
        }
    }

    /// Find the smallest cave that fits the requested byte count, if any.
    ///
    /// # Errors
    ///
    /// Returns [`CaveError`] from the underlying [`Self::scan`] call.
    pub fn find_first_fit(&self, binary: &[u8], needed: usize) -> Result<Option<CodeCave>, CaveError> {
        let mut caves = self.scan(binary)?;
        caves.retain(|c| c.size >= needed);
        caves.sort_by_key(|c| c.size);
        Ok(caves.into_iter().next())
    }
}

// ---------------------------------------------------------------------------
// PE parsing (minimal, headers only)
// ---------------------------------------------------------------------------

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

fn parse_pe_exec_sections(binary: &[u8]) -> Result<Vec<ExecSection>, CaveError> {
    if binary.len() < 0x40 {
        return Err(CaveError::TooSmall(binary.len()));
    }
    let pe_off = u32::from_le_bytes([binary[0x3C], binary[0x3D], binary[0x3E], binary[0x3F]]) as usize;
    if pe_off + 24 > binary.len() {
        return Err(CaveError::Malformed("PE header offset out of bounds"));
    }
    if &binary[pe_off..pe_off + 4] != b"PE\0\0" {
        return Err(CaveError::Malformed("missing PE\\0\\0 signature"));
    }
    let coff = pe_off + 4;
    let num_sections = u16::from_le_bytes([binary[coff + 2], binary[coff + 3]]) as usize;
    let opt_hdr_size = u16::from_le_bytes([binary[coff + 16], binary[coff + 17]]) as usize;
    let sec_table = coff + 20 + opt_hdr_size;
    let sec_size = 40usize;
    let sections_total = num_sections.checked_mul(sec_size)
        .ok_or(CaveError::Malformed("PE: section table size overflow"))?;
    let sec_table_end = sec_table.checked_add(sections_total)
        .ok_or(CaveError::Malformed("PE: section table end overflow"))?;
    if sec_table_end > binary.len() {
        return Err(CaveError::Malformed("PE section table out of bounds"));
    }

    let mut out = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let base = sec_table + i * sec_size;
        let name_raw = &binary[base..base + 8];
        let name_end = name_raw.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_raw[..name_end]).into_owned();
        let virtual_address = u64::from(u32::from_le_bytes([
            binary[base + 12], binary[base + 13], binary[base + 14], binary[base + 15],
        ]));
        let raw_size = u64::from(u32::from_le_bytes([
            binary[base + 16], binary[base + 17], binary[base + 18], binary[base + 19],
        ]));
        let raw_ptr = u64::from(u32::from_le_bytes([
            binary[base + 20], binary[base + 21], binary[base + 22], binary[base + 23],
        ]));
        let characteristics = u32::from_le_bytes([
            binary[base + 36], binary[base + 37], binary[base + 38], binary[base + 39],
        ]);
        if characteristics & IMAGE_SCN_MEM_EXECUTE != 0 && raw_size > 0 {
            out.push(ExecSection {
                name,
                file_offset: raw_ptr,
                file_size: raw_size,
                virtual_address: Some(virtual_address),
            });
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// ELF parsing (minimal, section headers only)
// ---------------------------------------------------------------------------

const SHF_EXECINSTR: u64 = 0x4;

fn parse_elf_exec_sections(binary: &[u8]) -> Result<Vec<ExecSection>, CaveError> {
    if binary.len() < 0x40 {
        return Err(CaveError::TooSmall(binary.len()));
    }
    let class = binary[4]; // 1 = ELF32, 2 = ELF64
    let data = binary[5]; // 1 = little endian, 2 = big endian
    if data != 1 {
        return Err(CaveError::Malformed("only little-endian ELF supported"));
    }
    match class {
        1 => parse_elf32(binary),
        2 => parse_elf64(binary),
        _ => Err(CaveError::Malformed("unknown ELF class")),
    }
}

fn read_u16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}
fn read_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn read_u64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(8)?)?;
    Some(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

fn parse_elf64(binary: &[u8]) -> Result<Vec<ExecSection>, CaveError> {
    let shoff = usize::try_from(read_u64(binary, 0x28).ok_or(CaveError::Malformed("ELF64: cannot read e_shoff"))?)
        .map_err(|_| CaveError::Malformed("ELF64: e_shoff exceeds usize"))?;
    let shentsize = read_u16(binary, 0x3A).ok_or(CaveError::Malformed("ELF64: cannot read e_shentsize"))? as usize;
    let shnum = read_u16(binary, 0x3C).ok_or(CaveError::Malformed("ELF64: cannot read e_shnum"))? as usize;
    let shstrndx = read_u16(binary, 0x3E).ok_or(CaveError::Malformed("ELF64: cannot read e_shstrndx"))? as usize;
    if shoff == 0 || shentsize == 0 || shnum == 0 {
        return Ok(Vec::new());
    }
    // Guard against shnum * shentsize overflow before the bounds check.
    let table_size = shnum.checked_mul(shentsize)
        .ok_or(CaveError::Malformed("ELF64: section header table size overflow"))?;
    let table_end = shoff.checked_add(table_size)
        .ok_or(CaveError::Malformed("ELF64: section header table offset overflow"))?;
    if table_end > binary.len() {
        return Err(CaveError::Malformed("ELF section header table out of bounds"));
    }
    if shstrndx >= shnum {
        return Err(CaveError::Malformed("ELF shstrndx out of range"));
    }
    let strtab_hdr = shoff.checked_add(shstrndx.checked_mul(shentsize)
        .ok_or(CaveError::Malformed("ELF64: strtab hdr offset overflow"))?)
        .ok_or(CaveError::Malformed("ELF64: strtab hdr offset overflow"))?;
    let strtab_off = usize::try_from(read_u64(binary, strtab_hdr.checked_add(24).ok_or(CaveError::Malformed("ELF64: strtab offset field oob"))?)
        .ok_or(CaveError::Malformed("ELF64: cannot read strtab sh_offset"))?)
        .map_err(|_| CaveError::Malformed("ELF64: strtab offset exceeds usize"))?;
    let strtab_size = usize::try_from(read_u64(binary, strtab_hdr.checked_add(32).ok_or(CaveError::Malformed("ELF64: strtab size field oob"))?)
        .ok_or(CaveError::Malformed("ELF64: cannot read strtab sh_size"))?)
        .map_err(|_| CaveError::Malformed("ELF64: strtab size exceeds usize"))?;
    let strtab_end = strtab_off.checked_add(strtab_size)
        .ok_or(CaveError::Malformed("ELF64: string table range overflow"))?;
    if strtab_end > binary.len() {
        return Err(CaveError::Malformed("ELF string table out of bounds"));
    }
    let strtab = &binary[strtab_off..strtab_end];

    let mut out = Vec::new();
    for i in 0..shnum {
        let base = shoff.checked_add(i.checked_mul(shentsize)
            .ok_or(CaveError::Malformed("ELF64: section base overflow"))?)
            .ok_or(CaveError::Malformed("ELF64: section base overflow"))?;
        let name_off = read_u32(binary, base).ok_or(CaveError::Malformed("ELF64: cannot read sh_name"))? as usize;
        let flags = read_u64(binary, base.checked_add(8).ok_or(CaveError::Malformed("ELF64: sh_flags oob"))?)
            .ok_or(CaveError::Malformed("ELF64: cannot read sh_flags"))?;
        let addr = read_u64(binary, base.checked_add(16).ok_or(CaveError::Malformed("ELF64: sh_addr oob"))?)
            .ok_or(CaveError::Malformed("ELF64: cannot read sh_addr"))?;
        let off = read_u64(binary, base.checked_add(24).ok_or(CaveError::Malformed("ELF64: sh_offset oob"))?)
            .ok_or(CaveError::Malformed("ELF64: cannot read sh_offset"))?;
        let size = read_u64(binary, base.checked_add(32).ok_or(CaveError::Malformed("ELF64: sh_size oob"))?)
            .ok_or(CaveError::Malformed("ELF64: cannot read sh_size"))?;
        if flags & SHF_EXECINSTR == 0 || size == 0 {
            continue;
        }
        let name = read_cstring(strtab, name_off);
        out.push(ExecSection {
            name,
            file_offset: off,
            file_size: size,
            virtual_address: if addr == 0 { None } else { Some(addr) },
        });
    }
    Ok(out)
}

fn parse_elf32(binary: &[u8]) -> Result<Vec<ExecSection>, CaveError> {
    let shoff = read_u32(binary, 0x20).ok_or(CaveError::Malformed("ELF32: cannot read e_shoff"))? as usize;
    let shentsize = read_u16(binary, 0x2E).ok_or(CaveError::Malformed("ELF32: cannot read e_shentsize"))? as usize;
    let shnum = read_u16(binary, 0x30).ok_or(CaveError::Malformed("ELF32: cannot read e_shnum"))? as usize;
    let shstrndx = read_u16(binary, 0x32).ok_or(CaveError::Malformed("ELF32: cannot read e_shstrndx"))? as usize;
    if shoff == 0 || shentsize == 0 || shnum == 0 {
        return Ok(Vec::new());
    }
    // Guard against shnum * shentsize overflow before the bounds check.
    let table_size = shnum.checked_mul(shentsize)
        .ok_or(CaveError::Malformed("ELF32 section header table size overflow"))?;
    let table_end = shoff.checked_add(table_size)
        .ok_or(CaveError::Malformed("ELF32 section header table offset overflow"))?;
    if table_end > binary.len() {
        return Err(CaveError::Malformed("ELF32 section header table out of bounds"));
    }
    if shstrndx >= shnum {
        return Err(CaveError::Malformed("ELF32 shstrndx out of range"));
    }
    let strtab_hdr = shoff.checked_add(shstrndx.checked_mul(shentsize)
        .ok_or(CaveError::Malformed("ELF32: strtab hdr offset overflow"))?)
        .ok_or(CaveError::Malformed("ELF32: strtab hdr offset overflow"))?;
    let strtab_off = read_u32(binary, strtab_hdr.checked_add(16).ok_or(CaveError::Malformed("ELF32: strtab offset field oob"))?)
        .ok_or(CaveError::Malformed("ELF32: cannot read strtab sh_offset"))? as usize;
    let strtab_size = read_u32(binary, strtab_hdr.checked_add(20).ok_or(CaveError::Malformed("ELF32: strtab size field oob"))?)
        .ok_or(CaveError::Malformed("ELF32: cannot read strtab sh_size"))? as usize;
    let strtab_end = strtab_off.checked_add(strtab_size)
        .ok_or(CaveError::Malformed("ELF32: string table range overflow"))?;
    if strtab_end > binary.len() {
        return Err(CaveError::Malformed("ELF32 string table out of bounds"));
    }
    let strtab = &binary[strtab_off..strtab_end];

    let mut out = Vec::new();
    for i in 0..shnum {
        let base = shoff.checked_add(i.checked_mul(shentsize)
            .ok_or(CaveError::Malformed("ELF32: section base overflow"))?)
            .ok_or(CaveError::Malformed("ELF32: section base overflow"))?;
        let name_off = read_u32(binary, base).ok_or(CaveError::Malformed("ELF32: cannot read sh_name"))? as usize;
        let flags = u64::from(read_u32(binary, base.checked_add(8).ok_or(CaveError::Malformed("ELF32: sh_flags oob"))?)
            .ok_or(CaveError::Malformed("ELF32: cannot read sh_flags"))?);
        let addr = u64::from(read_u32(binary, base.checked_add(12).ok_or(CaveError::Malformed("ELF32: sh_addr oob"))?)
            .ok_or(CaveError::Malformed("ELF32: cannot read sh_addr"))?);
        let off = u64::from(read_u32(binary, base.checked_add(16).ok_or(CaveError::Malformed("ELF32: sh_offset oob"))?)
            .ok_or(CaveError::Malformed("ELF32: cannot read sh_offset"))?);
        let size = u64::from(read_u32(binary, base.checked_add(20).ok_or(CaveError::Malformed("ELF32: sh_size oob"))?)
            .ok_or(CaveError::Malformed("ELF32: cannot read sh_size"))?);
        if flags & SHF_EXECINSTR == 0 || size == 0 {
            continue;
        }
        let name = read_cstring(strtab, name_off);
        out.push(ExecSection {
            name,
            file_offset: off,
            file_size: size,
            virtual_address: if addr == 0 { None } else { Some(addr) },
        });
    }
    Ok(out)
}

fn read_cstring(strtab: &[u8], offset: usize) -> String {
    if offset >= strtab.len() {
        return String::new();
    }
    let slice = &strtab[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

// ---------------------------------------------------------------------------
// Convenience entry point
// ---------------------------------------------------------------------------

/// Scan `binary` for code caves of at least `min_size` bytes, using the default
/// fill-byte set (`0x00`, `0xCC`, `0x90`).
///
/// # Errors
///
/// Returns [`CaveError`] if `min_size` is zero or the binary cannot be parsed.
pub fn find_code_caves(binary: &[u8], min_size: usize) -> Result<Vec<CodeCave>, CaveError> {
    CodeCaveScanner::new(min_size)?.scan(binary)
}

/// I/O error wrapper for the path-based entry point.
#[derive(Debug, Error)]
pub enum CavePathError {
    /// File could not be read from disk.
    #[error("io error reading {path}: {source}")]
    Io {
        /// File path that failed to load.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Underlying cave-scanner error.
    #[error(transparent)]
    Cave(#[from] CaveError),
}

/// Load a binary file from `path` and scan it for code caves.
///
/// This is the path-accepting counterpart to [`find_code_caves`] used by MCP
/// wrappers that receive a `path` parameter — it loads the file directly when
/// no in-memory session buffer is available, mirroring the `loader_pe_*` style.
///
/// # Errors
///
/// Returns [`CavePathError::Io`] if the file cannot be read, or
/// [`CavePathError::Cave`] if the loaded bytes fail to parse.
pub fn find_code_caves_from_path<P: AsRef<std::path::Path>>(
    path: P,
    min_size: usize,
) -> Result<Vec<CodeCave>, CavePathError> {
    let p = path.as_ref();
    let data = std::fs::read(p).map_err(|e| CavePathError::Io {
        path: p.display().to_string(),
        source: e,
    })?;
    Ok(find_code_caves(&data, min_size)?)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_elf64_with_text(text: &[u8]) -> Vec<u8> {
        // Build: ehdr (64) + .text data + shstrtab + 3 section headers (NULL, .text, .shstrtab)
        let shentsize = 64usize;
        let ehdr_size = 64usize;
        let text_off = ehdr_size;
        let text_size = text.len();
        let shstrtab_off = text_off + text_size;
        // shstrtab: \0 .text\0 .shstrtab\0
        let mut shstrtab = Vec::new();
        shstrtab.push(0);
        let name_text = u32::try_from(shstrtab.len()).unwrap();
        shstrtab.extend_from_slice(b".text\0");
        let name_shstr = u32::try_from(shstrtab.len()).unwrap();
        shstrtab.extend_from_slice(b".shstrtab\0");
        let shstrtab_size = shstrtab.len();
        let shoff = shstrtab_off + shstrtab_size;
        let total = shoff + 3 * shentsize;

        let mut out = vec![0u8; total];
        // ELF magic + ident
        out[0..4].copy_from_slice(b"\x7FELF");
        out[4] = 2; // ELF64
        out[5] = 1; // LE
        out[6] = 1; // version
        // e_shoff @ 0x28
        out[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
        // e_shentsize @ 0x3A
        out[0x3A..0x3C].copy_from_slice(&u16::try_from(shentsize).unwrap().to_le_bytes());
        // e_shnum @ 0x3C
        out[0x3C..0x3E].copy_from_slice(&3u16.to_le_bytes());
        // e_shstrndx @ 0x3E
        out[0x3E..0x40].copy_from_slice(&2u16.to_le_bytes());

        // text payload
        out[text_off..text_off + text_size].copy_from_slice(text);
        // shstrtab payload
        out[shstrtab_off..shstrtab_off + shstrtab_size].copy_from_slice(&shstrtab);

        // section header 0 (NULL) — left zeroed
        // section header 1 (.text)
        let sh1 = shoff + shentsize;
        out[sh1..sh1 + 4].copy_from_slice(&name_text.to_le_bytes());
        out[sh1 + 4..sh1 + 8].copy_from_slice(&1u32.to_le_bytes()); // PROGBITS
        out[sh1 + 8..sh1 + 16].copy_from_slice(&(SHF_EXECINSTR | 0x2).to_le_bytes()); // ALLOC|EXEC
        out[sh1 + 16..sh1 + 24].copy_from_slice(&0x1000u64.to_le_bytes()); // addr
        out[sh1 + 24..sh1 + 32].copy_from_slice(&(text_off as u64).to_le_bytes());
        out[sh1 + 32..sh1 + 40].copy_from_slice(&(text_size as u64).to_le_bytes());

        // section header 2 (.shstrtab)
        let sh2 = shoff + 2 * shentsize;
        out[sh2..sh2 + 4].copy_from_slice(&name_shstr.to_le_bytes());
        out[sh2 + 4..sh2 + 8].copy_from_slice(&3u32.to_le_bytes()); // STRTAB
        out[sh2 + 24..sh2 + 32].copy_from_slice(&(shstrtab_off as u64).to_le_bytes());
        out[sh2 + 32..sh2 + 40].copy_from_slice(&(shstrtab_size as u64).to_le_bytes());

        out
    }

    #[test]
    fn detects_elf_format() {
        let bin = make_minimal_elf64_with_text(&[0x90; 32]);
        assert_eq!(CodeCaveScanner::detect_format(&bin).unwrap(), BinaryFormat::Elf);
    }

    #[test]
    fn rejects_unknown_format() {
        let bin = vec![0xFF; 16];
        assert!(matches!(
            CodeCaveScanner::detect_format(&bin),
            Err(CaveError::UnknownFormat(_))
        ));
    }

    #[test]
    fn finds_cave_in_elf_text() {
        let mut text = vec![0x55u8; 8]; // some code
        text.extend(std::iter::repeat_n(0xCC, 64)); // cave
        text.extend(vec![0x55u8; 8]);
        let bin = make_minimal_elf64_with_text(&text);
        let caves = find_code_caves(&bin, 16).unwrap();
        assert_eq!(caves.len(), 1);
        assert_eq!(caves[0].section, ".text");
        assert_eq!(caves[0].size, 64);
        assert_eq!(caves[0].fill_byte, 0xCC);
        assert_eq!(caves[0].virtual_address, Some(0x1000 + 8));
    }

    #[test]
    fn first_fit_picks_smallest_sufficient() {
        let mut text = vec![0x55u8; 4];
        text.extend(std::iter::repeat_n(0x00, 32));
        text.push(0x55);
        text.extend(std::iter::repeat_n(0x00, 128));
        let bin = make_minimal_elf64_with_text(&text);
        let scanner = CodeCaveScanner::new(16).unwrap();
        let cave = scanner.find_first_fit(&bin, 20).unwrap().unwrap();
        assert_eq!(cave.size, 32);
    }

    #[test]
    fn rejects_zero_min_size() {
        assert!(matches!(CodeCaveScanner::new(0), Err(CaveError::InvalidMinSize)));
    }

    #[test]
    fn rejects_too_small_binary() {
        let bin = vec![0u8; 2];
        assert!(matches!(
            CodeCaveScanner::detect_format(&bin),
            Err(CaveError::TooSmall(_))
        ));
    }

    /// FIX D regression: `find_code_caves_from_path` must load the file from
    /// the given path and produce the same caves as the in-memory entry point,
    /// so MCP wrappers can honour their `path` parameter without a session.
    #[test]
    fn fix_d_find_code_caves_from_path_loads_file() {
        let mut text = vec![0x55u8; 8];
        text.extend(std::iter::repeat_n(0xCC, 64));
        text.extend(vec![0x55u8; 8]);
        let bin = make_minimal_elf64_with_text(&text);
        let path = std::env::temp_dir().join("rustre_patch_fixd_caves.bin");
        std::fs::write(&path, &bin).unwrap();
        let caves = find_code_caves_from_path(&path, 16).unwrap();
        assert_eq!(caves.len(), 1);
        assert_eq!(caves[0].size, 64);
        assert_eq!(caves[0].fill_byte, 0xCC);
        let _ = std::fs::remove_file(&path);
    }
}
