//! Signature extractor: parse ELF/PE binaries, iterate functions,
//! extract initial bytes, compute CRC16, and find public symbol names.

use std::fmt;

use anyhow::{bail, Result};

// ── CRC16 ─────────────────────────────────────────────────────────────────────

/// The FLIRT tail CRC over `data`.
///
/// BUG FIX: this was CRC-16/CCITT-FALSE (forward poly 0x1021), but its only
/// caller is `FunctionBytes::crc16_window`, which produces the CRC stored in a
/// generated signature — a tail CRC. The matcher recomputes that field with the
/// reflected FLIRT CRC, so every signature this extractor emitted carried a CRC
/// the matcher could not reproduce.
#[must_use]
pub fn crc16(data: &[u8]) -> u16 {
    rustre_flirt::crc::flirt_tail(data)
}

/// Pre-computed table for the reflected FLIRT tail CRC.
///
/// Was a forward CCITT-FALSE table; rebuilt for the reflected polynomial so
/// that [`crc16_fast`] and [`crc16`] agree (pinned by test over all 256 bytes).
#[must_use]
pub fn crc16_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    for i in 0..256u16 {
        let mut crc = i;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0x8408 } else { crc >> 1 };
        }
        table[i as usize] = crc;
    }
    table
}

/// Table-driven form of [`crc16`]; the two are pinned to agree.
#[must_use]
pub fn crc16_fast(data: &[u8], table: &[u16; 256]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        let i = ((crc as u8) ^ byte) as usize;
        crc = (crc >> 8) ^ table[i];
    }
    crc
}

// ── Binary format detection ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    Elf32Le,
    Elf32Be,
    Elf64Le,
    Elf64Be,
    Pe32,
    Pe64,
    RawBytes,
}

impl BinaryFormat {
    #[must_use]
    pub fn detect(data: &[u8]) -> Self {
        if data.len() >= 4 && &data[..4] == b"\x7fELF" {
            let bits = data.get(4).copied().unwrap_or(0);
            let endian = data.get(5).copied().unwrap_or(0);
            match (bits, endian) {
                (1, 1) => Self::Elf32Le,
                (1, 2) => Self::Elf32Be,
                (2, 1) => Self::Elf64Le,
                (2, 2) => Self::Elf64Be,
                _ => Self::RawBytes,
            }
        } else if data.len() >= 2 && &data[..2] == b"MZ" {
            // Check PE signature
            if data.len() >= 0x40 {
                let pe_off = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap_or([0; 4])) as usize;
                if pe_off + 4 <= data.len() && &data[pe_off..pe_off + 4] == b"PE\0\0" {
                    // A PE's word size is stated by the optional header's
                    // Magic (0x20b = PE32+, 0x10b = PE32), NOT by the machine
                    // type. Testing `machine == 0x8664` classified every
                    // non-x64 64-bit image as 32-bit — arm64 (0xAA64) above
                    // all, and Windows on ARM ships. That drives pointer width
                    // and offsets downstream, so patterns extracted from such a
                    // binary were built on the wrong layout.
                    let opt_off = pe_off + 24;
                    let magic = if opt_off + 2 <= data.len() {
                        u16::from_le_bytes(data[opt_off..opt_off + 2].try_into().unwrap_or([0; 2]))
                    } else {
                        0
                    };
                    return match magic {
                        0x20b => Self::Pe64,
                        0x10b => Self::Pe32,
                        // Magic unreadable (truncated header): fall back to the
                        // machine, listing the 64-bit ones this workspace knows —
                        // better than assuming 32-bit.
                        _ => {
                            let machine = if pe_off + 6 <= data.len() {
                                u16::from_le_bytes(
                                    data[pe_off + 4..pe_off + 6].try_into().unwrap_or([0; 2]),
                                )
                            } else {
                                0
                            };
                            if matches!(machine, 0x8664 | 0xAA64 | 0x0200 | 0xA641) {
                                Self::Pe64
                            } else {
                                Self::Pe32
                            }
                        }
                    };
                }
            }
            Self::Pe32
        } else {
            Self::RawBytes
        }
    }

    #[must_use]
    pub const fn is_elf(&self) -> bool {
        matches!(
            self,
            Self::Elf32Le | Self::Elf32Be | Self::Elf64Le | Self::Elf64Be
        )
    }

    #[must_use]
    pub const fn is_pe(&self) -> bool {
        matches!(self, Self::Pe32 | Self::Pe64)
    }

    #[must_use]
    pub const fn is_64bit(&self) -> bool {
        matches!(self, Self::Elf64Le | Self::Elf64Be | Self::Pe64)
    }

    #[must_use]
    pub const fn is_little_endian(&self) -> bool {
        matches!(self, Self::Elf32Le | Self::Elf64Le | Self::Pe32 | Self::Pe64)
    }
}

// ── ExtractedFunction ─────────────────────────────────────────────────────────

/// A function extracted from a binary for signature generation.
#[derive(Debug, Clone)]
pub struct ExtractedFunction {
    /// Public name (if any).
    pub name: Option<String>,
    /// Additional aliases / mangled names.
    pub aliases: Vec<String>,
    /// Virtual address within the binary.
    pub address: u64,
    /// Raw function bytes.
    pub bytes: Vec<u8>,
    /// Locations in `bytes` that contain relocations (to be masked with `..`).
    pub reloc_offsets: Vec<usize>,
    /// Source section name.
    pub section: String,
}

impl ExtractedFunction {
    /// Length of the function in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// First `count` bytes (initial pattern bytes for FLIRT).
    #[must_use]
    pub fn initial_bytes(&self, count: usize) -> &[u8] {
        let len = self.bytes.len().min(count);
        &self.bytes[..len]
    }

    /// CRC16 over bytes starting at `offset` up to `length` bytes.
    #[must_use]
    pub fn crc16_window(&self, offset: usize, length: usize) -> u16 {
        let end = (offset + length).min(self.bytes.len());
        if offset >= self.bytes.len() {
            return 0;
        }
        let window = &self.bytes[offset..end];
        // Zero out relocation bytes.
        let mut buf = window.to_vec();
        for &roff in &self.reloc_offsets {
            if roff >= offset && roff < offset + length {
                let local = roff - offset;
                if local < buf.len() {
                    buf[local] = 0;
                }
            }
        }
        crc16(&buf)
    }

    /// Build a FLIRT-style hex pattern for the initial bytes, with `..` for relocations.
    #[must_use]
    pub fn pattern_hex(&self, initial_len: usize) -> String {
        use std::fmt::Write as _;
        let bytes = self.initial_bytes(initial_len);
        let mut out = String::with_capacity(initial_len * 3);
        for (i, &b) in bytes.iter().enumerate() {
            if self.reloc_offsets.contains(&i) {
                out.push_str("..");
            } else {
                let _ = write!(out, "{b:02X}");
            }
            out.push(' ');
        }
        out.trim_end().to_string()
    }
}

// ── ELF parser ────────────────────────────────────────────────────────────────

/// Minimal ELF symbol table entry.
#[derive(Debug, Clone)]
pub struct ElfSymbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub sym_type: u8,  // STT_*
    pub binding: u8,   // STB_*
    pub section_idx: u16,
}

impl ElfSymbol {
    #[must_use]
    pub const fn is_function(&self) -> bool {
        self.sym_type == 2 // STT_FUNC
    }

    #[must_use]
    pub const fn is_global(&self) -> bool {
        self.binding == 1 // STB_GLOBAL
    }

    #[must_use]
    pub const fn is_local(&self) -> bool {
        self.binding == 0 // STB_LOCAL
    }

    #[must_use]
    pub const fn is_weak(&self) -> bool {
        self.binding == 2 // STB_WEAK
    }
}

/// Minimal ELF section.
#[derive(Debug, Clone)]
pub struct ElfSection {
    pub name: String,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub data: Vec<u8>,
}

impl ElfSection {
    #[must_use]
    pub const fn is_code(&self) -> bool {
        // SHF_EXECINSTR = 0x4
        self.sh_flags & 0x4 != 0
    }

    #[must_use]
    pub const fn is_alloc(&self) -> bool {
        // SHF_ALLOC = 0x2
        self.sh_flags & 0x2 != 0
    }
}

/// Parse ELF binary and extract symbols + sections.
pub struct ElfParser<'a> {
    data: &'a [u8],
    format: BinaryFormat,
}

impl<'a> ElfParser<'a> {
    /// # Errors
    /// Returns an error if the data is not a valid ELF binary.
    pub fn new(data: &'a [u8]) -> Result<Self> {
        let format = BinaryFormat::detect(data);
        if !format.is_elf() {
            bail!("not an ELF binary");
        }
        Ok(Self {
            data,
            format,
        })
    }

    fn read_u16(&self, off: usize) -> u16 {
        if off + 2 > self.data.len() {
            return 0;
        }
        if self.format.is_little_endian() {
            u16::from_le_bytes(self.data[off..off + 2].try_into().unwrap_or([0; 2]))
        } else {
            u16::from_be_bytes(self.data[off..off + 2].try_into().unwrap_or([0; 2]))
        }
    }

    fn read_u32(&self, off: usize) -> u32 {
        if off + 4 > self.data.len() {
            return 0;
        }
        if self.format.is_little_endian() {
            u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap_or([0; 4]))
        } else {
            u32::from_be_bytes(self.data[off..off + 4].try_into().unwrap_or([0; 4]))
        }
    }

    fn read_u64(&self, off: usize) -> u64 {
        if off + 8 > self.data.len() {
            return 0;
        }
        if self.format.is_little_endian() {
            u64::from_le_bytes(self.data[off..off + 8].try_into().unwrap_or([0; 8]))
        } else {
            u64::from_be_bytes(self.data[off..off + 8].try_into().unwrap_or([0; 8]))
        }
    }


    fn read_cstr(&self, off: usize) -> String {
        let mut i = off;
        while i < self.data.len() && self.data[i] != 0 {
            i += 1;
        }
        String::from_utf8_lossy(&self.data[off..i]).into_owned()
    }

    /// Parse all section headers.
    ///
    /// # Errors
    /// Returns an error if section data is malformed.
    pub fn sections(&self) -> Result<Vec<ElfSection>> {
        let shoff = if self.format.is_64bit() {
            usize::try_from(self.read_u64(0x28)).unwrap_or(0)
        } else {
            self.read_u32(0x20) as usize
        };
        let shentsize = self.read_u16(if self.format.is_64bit() { 0x3a } else { 0x2e }) as usize;
        let shnum = self.read_u16(if self.format.is_64bit() { 0x3c } else { 0x30 }) as usize;
        let shstrndx = self.read_u16(if self.format.is_64bit() { 0x3e } else { 0x32 }) as usize;
        // Read section name string table.
        let strtab_off = if shstrndx < shnum && shentsize > 0 {
            let sec_off = shoff + shstrndx * shentsize;
            if self.format.is_64bit() {
                usize::try_from(self.read_u64(sec_off + 0x18)).unwrap_or(0)
            } else {
                self.read_u32(sec_off + 0x10) as usize
            }
        } else {
            0
        };
        let mut sections = Vec::new();
        for i in 0..shnum {
            let sec_off = shoff + i * shentsize;
            if sec_off + shentsize > self.data.len() {
                break;
            }
            let name_off = self.read_u32(sec_off) as usize;
            let sh_type = self.read_u32(sec_off + 4);
            let (sh_flags, sh_addr, offset, sh_size) = if self.format.is_64bit() {
                (
                    self.read_u64(sec_off + 8),
                    self.read_u64(sec_off + 16),
                    usize::try_from(self.read_u64(sec_off + 24)).unwrap_or(0),
                    usize::try_from(self.read_u64(sec_off + 32)).unwrap_or(0),
                )
            } else {
                (
                    u64::from(self.read_u32(sec_off + 8)),
                    u64::from(self.read_u32(sec_off + 12)),
                    self.read_u32(sec_off + 16) as usize,
                    self.read_u32(sec_off + 20) as usize,
                )
            };
            let name = if strtab_off > 0 && strtab_off + name_off < self.data.len() {
                self.read_cstr(strtab_off + name_off)
            } else {
                format!(".sec{i}")
            };
            let end = (offset + sh_size).min(self.data.len());
            let data = if sh_type != 8 && offset < self.data.len() {
                // SHT_NOBITS = 8
                self.data[offset..end].to_vec()
            } else {
                Vec::new()
            };
            sections.push(ElfSection {
                name,
                sh_type,
                sh_flags,
                sh_addr,
                sh_offset: offset as u64,
                sh_size: sh_size as u64,
                data,
            });
        }
        Ok(sections)
    }

    /// Parse symbol table (`.symtab`).
    ///
    /// # Errors
    /// Returns an error if symbol data is malformed.
    pub fn symbols(&self, sections: &[ElfSection]) -> Result<Vec<ElfSymbol>> {
        let Some(symtab) = sections.iter().find(|s| s.name == ".symtab" || s.sh_type == 2) else {
            return Ok(Vec::new());
        };
        let strtab = sections.iter().find(|s| s.name == ".strtab" || s.sh_type == 3);
        let sym_size = if self.format.is_64bit() { 24 } else { 16 };
        let mut symbols = Vec::new();
        for chunk in symtab.data.chunks_exact(sym_size) {
            let name_off = u32::from_le_bytes(chunk[0..4].try_into().unwrap_or([0; 4])) as usize;
            let (value, size, info, section_idx) = if self.format.is_64bit() {
                let info = chunk[4];
                let section_idx = u16::from_le_bytes(chunk[6..8].try_into().unwrap_or([0; 2]));
                let value = u64::from_le_bytes(chunk[8..16].try_into().unwrap_or([0; 8]));
                let size = u64::from_le_bytes(chunk[16..24].try_into().unwrap_or([0; 8]));
                (value, size, info, section_idx)
            } else {
                let value = u64::from(u32::from_le_bytes(chunk[4..8].try_into().unwrap_or([0; 4])));
                let size = u64::from(u32::from_le_bytes(chunk[8..12].try_into().unwrap_or([0; 4])));
                let info = chunk[12];
                let section_idx = u16::from_le_bytes(chunk[14..16].try_into().unwrap_or([0; 2]));
                (value, size, info, section_idx)
            };
            let name = strtab.map_or_else(String::new, |st| {
                if name_off < st.data.len() {
                    let end = st.data[name_off..]
                        .iter()
                        .position(|&b| b == 0)
                        .map_or(st.data.len(), |i| name_off + i);
                    String::from_utf8_lossy(&st.data[name_off..end]).into_owned()
                } else {
                    String::new()
                }
            });
            symbols.push(ElfSymbol {
                name,
                value,
                size,
                sym_type: info & 0xf,
                binding: info >> 4,
                section_idx,
            });
        }
        Ok(symbols)
    }

    /// Extract all functions with their bytecodes.
    ///
    /// # Errors
    ///
    /// Returns an error if section or symbol parsing fails.
    pub fn extract_functions(&self) -> Result<Vec<ExtractedFunction>> {
        let sections = self.sections()?;
        let symbols = self.symbols(&sections)?;
        let code_sections: Vec<&ElfSection> = sections.iter().filter(|s| s.is_code()).collect();
        let mut functions = Vec::new();
        for sym in &symbols {
            if !sym.is_function() || sym.size == 0 {
                continue;
            }
            // Find the section that contains this function.
            let section = if (sym.section_idx as usize) < sections.len() {
                &sections[sym.section_idx as usize]
            } else {
                match code_sections.first() {
                    Some(s) => s,
                    None => continue,
                }
            };
            let func_off = usize::try_from(sym.value - section.sh_addr).unwrap_or(0);
            let func_end = (func_off + usize::try_from(sym.size).unwrap_or(0)).min(section.data.len());
            if func_off >= section.data.len() {
                continue;
            }
            let bytes = section.data[func_off..func_end].to_vec();
            // Detect relocations in this range (simplified: look for 0x00 sequences
            // that suggest relocation placeholders — a real impl would parse .rela.text).
            let reloc_offsets = detect_reloc_placeholders(&bytes);
            functions.push(ExtractedFunction {
                name: if sym.name.is_empty() { None } else { Some(sym.name.clone()) },
                aliases: Vec::new(),
                address: sym.value,
                bytes,
                reloc_offsets,
                section: section.name.clone(),
            });
        }
        Ok(functions)
    }
}

// ── PE parser ─────────────────────────────────────────────────────────────────

/// PE section header.
#[derive(Debug, Clone)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub data: Vec<u8>,
}

impl PeSection {
    #[must_use]
    pub const fn is_code(&self) -> bool {
        self.characteristics & 0x20 != 0 // IMAGE_SCN_CNT_CODE
            || self.characteristics & 0x2000_0000 != 0 // IMAGE_SCN_MEM_EXECUTE
    }

    #[must_use]
    pub fn contains_va(&self, va: u32) -> bool {
        va >= self.virtual_address && va < self.virtual_address + self.virtual_size.max(self.raw_size)
    }

    #[must_use]
    pub fn offset_for_va(&self, va: u32) -> Option<usize> {
        if self.contains_va(va) {
            Some((va - self.virtual_address) as usize)
        } else {
            None
        }
    }
}

pub struct PeParser<'a> {
    data: &'a [u8],
    pe_off: usize,
    is_64: bool,
}

impl<'a> PeParser<'a> {
    /// # Errors
    ///
    /// Returns an error if `data` is not a valid PE binary.
    pub fn new(data: &'a [u8]) -> Result<Self> {
        if data.len() < 0x40 || &data[..2] != b"MZ" {
            bail!("not a PE binary");
        }
        let pe_off = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap_or([0; 4])) as usize;
        if pe_off + 4 > data.len() || &data[pe_off..pe_off + 4] != b"PE\0\0" {
            bail!("invalid PE signature");
        }
        let machine = u16::from_le_bytes(data[pe_off + 4..pe_off + 6].try_into().unwrap_or([0; 2]));
        let is_64 = machine == 0x8664 || machine == 0xAA64;
        Ok(Self { data, pe_off, is_64 })
    }

    fn r16(&self, off: usize) -> u16 {
        if off + 2 <= self.data.len() {
            u16::from_le_bytes(self.data[off..off + 2].try_into().unwrap_or([0; 2]))
        } else {
            0
        }
    }

    fn r32(&self, off: usize) -> u32 {
        if off + 4 <= self.data.len() {
            u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap_or([0; 4]))
        } else {
            0
        }
    }

    /// Parse PE section headers.
    #[must_use]
    pub fn sections(&self) -> Vec<PeSection> {
        let coff_off = self.pe_off + 4; // COFF header starts after PE\0\0
        let num_sections = self.r16(coff_off + 2) as usize;
        let opt_header_size = self.r16(coff_off + 16) as usize;
        let sections_off = coff_off + 20 + opt_header_size;
        let mut sections = Vec::new();
        for i in 0..num_sections {
            let sec_off = sections_off + i * 40;
            if sec_off + 40 > self.data.len() {
                break;
            }
            let name_bytes = &self.data[sec_off..sec_off + 8];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
            let virtual_size = self.r32(sec_off + 8);
            let virtual_address = self.r32(sec_off + 12);
            let raw_size = self.r32(sec_off + 16);
            let raw_offset = self.r32(sec_off + 20);
            let characteristics = self.r32(sec_off + 36);
            let start = raw_offset as usize;
            let end = (start + raw_size as usize).min(self.data.len());
            let data = if start < self.data.len() {
                self.data[start..end].to_vec()
            } else {
                Vec::new()
            };
            sections.push(PeSection {
                name,
                virtual_address,
                virtual_size,
                raw_offset,
                raw_size,
                characteristics,
                data,
            });
        }
        sections
    }

    /// Parse export directory to find exported functions.
    #[must_use]
    pub fn exports(&self, sections: &[PeSection]) -> Vec<(String, u32)> {
        let opt_off = self.pe_off + 24; // optional header
        // Export directory RVA is at offset 16 into optional header data directory.
        let dd_off = opt_off + if self.is_64 { 112 } else { 96 };
        let export_rva = self.r32(dd_off);
        if export_rva == 0 {
            return Vec::new();
        }
        let Some(sec) = sections.iter().find(|s| s.contains_va(export_rva)) else { return Vec::new() };
        let Some(off) = sec.offset_for_va(export_rva) else { return Vec::new() };
        let section_data = &sec.data;
        if off + 40 > section_data.len() {
            return Vec::new();
        }
        let _num_funcs = u32::from_le_bytes(section_data[off + 20..off + 24].try_into().unwrap_or([0; 4])) as usize;
        let num_names = u32::from_le_bytes(section_data[off + 24..off + 28].try_into().unwrap_or([0; 4])) as usize;
        let addr_table_rva = u32::from_le_bytes(section_data[off + 28..off + 32].try_into().unwrap_or([0; 4]));
        let name_table_rva = u32::from_le_bytes(section_data[off + 32..off + 36].try_into().unwrap_or([0; 4]));
        let ordinal_table_rva = u32::from_le_bytes(section_data[off + 36..off + 40].try_into().unwrap_or([0; 4]));
        let mut exports = Vec::new();
        for i in 0..num_names {
            let Some(name_rva_off) = sec.offset_for_va(name_table_rva + u32::try_from(i).unwrap_or(u32::MAX) * 4) else { continue };
            if name_rva_off + 4 > section_data.len() {
                continue;
            }
            let name_rva = u32::from_le_bytes(section_data[name_rva_off..name_rva_off + 4].try_into().unwrap_or([0; 4]));
            let Some(name_off) = sec.offset_for_va(name_rva) else { continue };
            let name_end = section_data[name_off..].iter().position(|&b| b == 0).map_or(name_off, |p| name_off + p);
            let name = String::from_utf8_lossy(&section_data[name_off..name_end]).into_owned();
            let Some(ord_off) = sec.offset_for_va(ordinal_table_rva + u32::try_from(i).unwrap_or(u32::MAX) * 2) else { continue };
            if ord_off + 2 > section_data.len() {
                continue;
            }
            let ordinal = u32::from(u16::from_le_bytes(section_data[ord_off..ord_off + 2].try_into().unwrap_or([0; 2])));
            let Some(func_rva_off) = sec.offset_for_va(addr_table_rva + ordinal * 4) else { continue };
            if func_rva_off + 4 > section_data.len() {
                continue;
            }
            let func_rva = u32::from_le_bytes(section_data[func_rva_off..func_rva_off + 4].try_into().unwrap_or([0; 4]));
            exports.push((name, func_rva));
        }
        exports
    }

    /// Extract all code functions from PE export table.
    ///
    /// # Errors
    ///
    /// Returns an error if the export table is malformed.
    pub fn extract_functions(&self) -> Result<Vec<ExtractedFunction>> {
        let sections = self.sections();
        let exports = self.exports(&sections);
        let mut functions = Vec::new();
        for (name, rva) in exports {
            let Some(sec) = sections.iter().find(|s| s.contains_va(rva)) else { continue };
            if !sec.is_code() {
                continue;
            }
            let Some(off) = sec.offset_for_va(rva) else { continue };
            // Estimate function size by scanning for ret instructions.
            let bytes = &sec.data[off..];
            let size = estimate_function_size(bytes, if self.is_64 { 8 } else { 4 });
            let func_bytes = bytes[..size].to_vec();
            let reloc_offsets = detect_reloc_placeholders(&func_bytes);
            functions.push(ExtractedFunction {
                name: Some(name),
                aliases: Vec::new(),
                address: u64::from(rva),
                bytes: func_bytes,
                reloc_offsets,
                section: sec.name.clone(),
            });
        }
        Ok(functions)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Detect likely relocation placeholder offsets in x86/x86-64 code.
/// This is a heuristic: looks for 4-byte zero sequences after certain opcodes.
fn detect_reloc_placeholders(bytes: &[u8]) -> Vec<usize> {
    let mut relocs = Vec::new();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        match bytes[i] {
            // CALL rel32, JMP rel32
            0xe8 | 0xe9 => {
                relocs.push(i + 1);
                relocs.push(i + 2);
                relocs.push(i + 3);
                relocs.push(i + 4);
                i += 5;
            }
            // MOV r/m, imm32 or LEA
            0x48 if i + 2 < bytes.len() && (bytes[i + 1] == 0x8d || bytes[i + 1] == 0xb8) => {
                if bytes[i + 2..].windows(4).next().is_some_and(|w| w == [0, 0, 0, 0]) {
                    relocs.push(i + 3);
                    relocs.push(i + 4);
                    relocs.push(i + 5);
                    relocs.push(i + 6);
                }
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    relocs
}

/// Estimate function size by scanning for ret/retn opcodes.
fn estimate_function_size(bytes: &[u8], _ptr_size: usize) -> usize {
    let max = bytes.len().min(4096);
    let mut i = 0;
    while i < max {
        match bytes[i] {
            0xc3 | 0xc2 => return i + 1, // ret / ret imm16
            0xeb => {
                // short jmp — advance past opcode + 1-byte displacement
                i += 2;
            }
            0xe8 => i += 5,
            0x0f if i + 1 < max && bytes[i + 1] == 0x0b => return i + 2, // UD2
            _ => i += 1,
        }
    }
    max
}

// ── SignatureExtractor ────────────────────────────────────────────────────────

/// Configuration for extraction.
#[derive(Debug, Clone)]
pub struct ExtractorConfig {
    /// Minimum function size to extract.
    pub min_func_size: usize,
    /// Maximum function size to extract.
    pub max_func_size: usize,
    /// Number of initial bytes to use for the signature pattern.
    pub initial_bytes: usize,
    /// Length of the CRC16 window (starting after `initial_bytes`).
    pub crc_window: usize,
    /// Skip unnamed functions.
    pub named_only: bool,
}

impl Default for ExtractorConfig {
    fn default() -> Self {
        Self {
            min_func_size: 4,
            max_func_size: 0x10000,
            initial_bytes: 32,
            crc_window: 64,
            named_only: false,
        }
    }
}

/// High-level extractor that handles ELF and PE.
pub struct SignatureExtractor {
    config: ExtractorConfig,
}

impl SignatureExtractor {
    #[must_use]
    pub const fn new(config: ExtractorConfig) -> Self {
        Self {
            config,
        }
    }

    /// Extract functions from raw binary data.
    ///
    /// # Errors
    ///
    /// Returns an error if the binary format is unsupported or parsing fails.
    pub fn extract(&self, data: &[u8]) -> Result<Vec<ExtractedFunction>> {
        let format = BinaryFormat::detect(data);
        let mut fns = match format {
            f if f.is_elf() => ElfParser::new(data)?.extract_functions()?,
            f if f.is_pe() => PeParser::new(data)?.extract_functions()?,
            _ => bail!("unsupported binary format"),
        };
        // Filter by config.
        fns.retain(|f| {
            if self.config.named_only && f.name.is_none() {
                return false;
            }
            f.len() >= self.config.min_func_size && f.len() <= self.config.max_func_size
        });
        Ok(fns)
    }

    /// Build a `FunctionSignature` from an `ExtractedFunction`.
    #[must_use]
    pub fn to_signature(&self, func: &ExtractedFunction) -> FunctionSignature {
        let initial = func.initial_bytes(self.config.initial_bytes);
        let crc_off = initial.len();
        let crc_val = func.crc16_window(crc_off, self.config.crc_window);
        let pattern = func.pattern_hex(self.config.initial_bytes);
        FunctionSignature {
            pattern,
            crc16: crc_val,
            crc_length: u16::try_from(self.config.crc_window.min(func.len().saturating_sub(crc_off))).unwrap_or(u16::MAX),
            total_length: u32::try_from(func.len()).unwrap_or(u32::MAX),
            name: func.name.clone().unwrap_or_else(|| format!("sub_{:08x}", func.address)),
            offset: 0,
            refs: Vec::new(),
        }
    }

    /// Extract and convert all functions.
    ///
    /// # Errors
    ///
    /// Returns an error if extraction fails.
    pub fn extract_signatures(&self, data: &[u8]) -> Result<Vec<FunctionSignature>> {
        let fns = self.extract(data)?;
        Ok(fns.iter().map(|f| self.to_signature(f)).collect())
    }
}

// ── FunctionSignature ─────────────────────────────────────────────────────────

/// A FLIRT-compatible function signature.
#[derive(Debug, Clone)]
pub struct FunctionSignature {
    /// Hex pattern (with `..` for wildcards).
    pub pattern: String,
    pub crc16: u16,
    pub crc_length: u16,
    pub total_length: u32,
    /// Public function name.
    pub name: String,
    /// Offset of the name within the function (usually 0).
    pub offset: u32,
    /// Reference names at specific offsets (for tail calls etc.).
    pub refs: Vec<(u32, String)>,
}

impl FunctionSignature {
    /// Check if another signature is a duplicate.
    #[must_use]
    pub fn is_duplicate_of(&self, other: &Self) -> bool {
        self.pattern == other.pattern && self.crc16 == other.crc16
    }
}

impl fmt::Display for FunctionSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {:02X} {:04X} {:04X} :0000 {}",
            self.pattern,
            self.crc_length,
            self.crc16,
            self.total_length & 0xffff,
            self.name,
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc16_known() {
        // Tail CRC = MCRF4XX, whose catalogue check value is 0x6F91.
        // This used to pin CCITT-FALSE's 0x29B1, which is a different algorithm.
        let result = crc16(b"123456789");
        assert_eq!(result, 0x6F91);
    }

    #[test]
    fn test_crc16_agrees_with_canonical_flirt_tail() {
        // The extractor produces tail CRCs; they must equal what the matcher
        // recomputes. Exhaustive over single bytes, not a sample.
        for b in 0..=255u8 {
            assert_eq!(crc16(&[b]), rustre_flirt::crc::flirt_tail(&[b]), "byte {b:#04x}");
        }
        assert_eq!(crc16(b"123456789"), 0x6F91);
    }

    #[test]
    fn test_crc16_table_path_matches_bitwise_for_every_byte() {
        let table = crc16_table();
        for b in 0..=255u8 {
            assert_eq!(crc16_fast(&[b], &table), crc16(&[b]), "byte {b:#04x}");
        }
    }

    #[test]
    fn test_crc16_fast_matches_slow() {
        let table = crc16_table();
        let data = b"hello world test";
        assert_eq!(crc16(data), crc16_fast(data, &table));
    }

    #[test]
    fn test_binary_format_detection() {
        let elf = b"\x7fELF\x02\x01";
        assert_eq!(BinaryFormat::detect(elf), BinaryFormat::Elf64Le);
        let pe = {
            let mut v = vec![0u8; 0x60];
            v[0] = b'M';
            v[1] = b'Z';
            v[0x3c] = 0x40;
            v[0x40..0x44].copy_from_slice(b"PE\0\0");
            v[0x44] = 0x64;
            v[0x45] = 0x86;
            v
        };
        assert_eq!(BinaryFormat::detect(&pe), BinaryFormat::Pe64);
    }

    /// A 64-bit PE is 64-bit whatever its machine type.
    ///
    /// `detect` returned `Pe64` only for `IMAGE_FILE_MACHINE_AMD64` (0x8664)
    /// and `Pe32` for everything else, so an **arm64** image (0xAA64) — a
    /// shipping Windows platform — was classified as 32-bit. That drives
    /// pointer width and offsets in signature extraction, so every pattern
    /// taken from such a binary would be built on the wrong layout.
    ///
    /// The authoritative field is the optional header's **Magic**
    /// (0x20b = PE32+, 0x10b = PE32), not the machine — the same correction
    /// made for `find_debug_directory` in rustre-debug (iter 339). Note this
    /// very file already knew about arm64 elsewhere
    /// (`machine == 0x8664 || machine == 0xAA64`, ~line 544): the two halves
    /// disagreed with each other.
    #[test]
    fn a_64bit_pe_is_detected_from_magic_not_from_the_machine_type() {
        let pe = |machine: u16, magic: u16| {
            let mut v = vec![0u8; 0x80];
            v[0] = b'M';
            v[1] = b'Z';
            v[0x3c] = 0x40;
            v[0x40..0x44].copy_from_slice(b"PE  ");
            v[0x44..0x46].copy_from_slice(&machine.to_le_bytes());
            // Optional header starts at pe_off + 24 = 0x58.
            v[0x58..0x5a].copy_from_slice(&magic.to_le_bytes());
            v
        };

        // x64: both fields agree, and must keep working.
        assert_eq!(BinaryFormat::detect(&pe(0x8664, 0x20b)), BinaryFormat::Pe64);
        // arm64: PE32+ with a machine that is not x64.
        assert_eq!(
            BinaryFormat::detect(&pe(0xAA64, 0x20b)),
            BinaryFormat::Pe64,
            "an arm64 image is PE32+ like any other 64-bit PE"
        );
        // 32-bit x86 must still be Pe32.
        assert_eq!(BinaryFormat::detect(&pe(0x014c, 0x10b)), BinaryFormat::Pe32);
    }

    #[test]
    fn test_extracted_function_pattern() {
        let func = ExtractedFunction {
            name: Some("foo".into()),
            aliases: Vec::new(),
            address: 0x1000,
            bytes: vec![0x55, 0x48, 0x89, 0xe5, 0x00, 0x00, 0x00, 0x00],
            reloc_offsets: vec![4, 5, 6, 7],
            section: ".text".into(),
        };
        let pat = func.pattern_hex(8);
        assert!(pat.contains(".."));
        assert!(pat.contains("55"));
    }

    #[test]
    fn test_function_signature_display() {
        let sig = FunctionSignature {
            pattern: "55 48 89 E5".into(),
            crc16: 0x1234,
            crc_length: 16,
            total_length: 64,
            name: "my_func".into(),
            offset: 0,
            refs: Vec::new(),
        };
        let s = format!("{sig}");
        assert!(s.contains("my_func"));
        assert!(s.contains("1234"));
    }

    #[test]
    fn test_detect_reloc_placeholders() {
        let code = vec![0xe8, 0x00, 0x00, 0x00, 0x00, 0x90];
        let relocs = detect_reloc_placeholders(&code);
        assert!(relocs.contains(&1));
    }

    #[test]
    fn test_extractor_config_default() {
        let cfg = ExtractorConfig::default();
        assert_eq!(cfg.initial_bytes, 32);
        assert_eq!(cfg.crc_window, 64);
    }
}
