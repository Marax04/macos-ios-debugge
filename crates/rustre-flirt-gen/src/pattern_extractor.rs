//! `pattern_extractor` — Extract FLIRT patterns from COFF .obj library members.
//!
//! Parses COFF object files, extracts function bytes by walking the symbol table,
//! identifies variable bytes (relocation targets), computes the leading 32-byte
//! pattern with wildcards applied, and computes the CRC-16 tail.

use std::collections::HashMap;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ExtractError {
    TooShort,
    BadMagic(u16),
    SectionIndexOutOfRange { index: usize, count: usize },
    SymtabOutOfRange,
    Parse(String),
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "data too short"),
            Self::BadMagic(m) => write!(f, "bad COFF magic 0x{m:04X}"),
            Self::SectionIndexOutOfRange { index, count } =>
                write!(f, "section index {index} out of range (count={count})"),
            Self::SymtabOutOfRange => write!(f, "symbol table pointer out of range"),
            Self::Parse(s) => write!(f, "parse error: {s}"),
        }
    }
}

impl std::error::Error for ExtractError {}

// ── RelocationMask ────────────────────────────────────────────────────────────

/// Describes a byte range inside a function body that should be wildcarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationMask {
    /// Byte offset within the function (0-based).
    pub offset: u32,
    /// Number of bytes to mask.
    pub length: u8,
}

impl RelocationMask {
    #[must_use]
    pub const fn new(offset: u32, length: u8) -> Self { Self { offset, length } }

    /// Return true if byte at `pos` is inside this mask.
    #[must_use]
    pub const fn covers(&self, pos: u32) -> bool {
        pos >= self.offset && pos < self.offset + self.length as u32
    }
}

// ── PatternBytes ──────────────────────────────────────────────────────────────

/// Leading N-byte pattern for a function with wildcards applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternBytes {
    /// Pattern bytes: `None` = wildcard, `Some(b)` = exact.
    pub bytes: Vec<Option<u8>>,
}

impl PatternBytes {
    #[must_use]
    pub fn new(raw: &[u8], masks: &[RelocationMask], limit: usize) -> Self {
        let len = raw.len().min(limit);
        let bytes = (0..len).map(|i| {
            if masks.iter().any(|m| m.covers(u32::try_from(i).unwrap_or(u32::MAX))) { None } else { Some(raw[i]) }
        }).collect();
        Self { bytes }
    }

    /// Hex string with `..` for wildcards (FLIRT `.pat` format).
    #[must_use]
    pub fn to_hex_string(&self) -> String {
        self.bytes.iter().map(|b| b.map_or_else(|| "..".to_string(), |v| format!("{v:02X}"))).collect()
    }

    /// Number of non-wildcard bytes.
    #[must_use]
    pub fn concrete_count(&self) -> usize {
        self.bytes.iter().filter(|b| b.is_some()).count()
    }
}

// ── CrcTail ───────────────────────────────────────────────────────────────────

/// CRC-16 computed over stable bytes in the tail region of a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrcTail {
    /// CRC-16 over the stable region.
    pub crc: u16,
    /// Number of bytes in the region.
    pub length: u8,
}

impl CrcTail {
    #[must_use]
    pub fn compute(raw: &[u8], masks: &[RelocationMask], start: usize, max_len: usize) -> Self {
        let end = (start + max_len).min(raw.len());
        let stable: Vec<u8> = (start..end)
            .filter(|&i| !masks.iter().any(|m| m.covers(u32::try_from(i).unwrap_or(u32::MAX))))
            .map(|i| raw[i])
            .collect();
        let crc = crc16_flirt_std(&stable);
        Self { crc, length: u8::try_from(stable.len().min(255)).unwrap_or(255) }
    }
}

/// CRC-16 used by IDA FLIRT (CRC-16/X-25: poly 0x8408 reflected, init 0xFFFF,
/// final XOR 0xFFFF).
fn crc16_flirt_std(data: &[u8]) -> u16 {
    // BUG FIX: this used to apply a final `^ 0xFFFF`, i.e. it was CRC-16/X-25,
    // while the consumer of this value —
    // `rustre_flirt_apply::match_validator::compute_flirt_crc` — is MCRF4XX.
    // The two differ on *every* input (see `rustre_flirt::crc` tests), so every
    // CRC this generator produced was the bitwise complement of what the
    // matcher expected. Both sides now route through the single definition.
    rustre_flirt::crc::flirt_tail(data)
}

// ── CoffSection ───────────────────────────────────────────────────────────────

/// A parsed COFF section header.
#[derive(Debug, Clone)]
pub struct CoffSection {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub number_of_relocations: u16,
    pub characteristics: u32,
}

impl CoffSection {
    /// True if this section has the CODE characteristic.
    #[must_use]
    pub const fn is_code(&self) -> bool { self.characteristics & 0x0000_0020 != 0 }
    /// True if this section has the EXECUTE characteristic.
    #[must_use]
    pub const fn is_executable(&self) -> bool { self.characteristics & 0x2000_0000 != 0 }
}

// ── CoffRelocation ────────────────────────────────────────────────────────────

/// A single COFF relocation record.
#[derive(Debug, Clone, Copy)]
pub struct CoffRelocation {
    /// Byte offset within the section.
    pub virtual_address: u32,
    /// Index into symbol table.
    pub symbol_index: u32,
    /// Relocation type.
    pub reloc_type: u16,
}

impl CoffRelocation {
    /// Number of bytes this relocation type occupies (approximate for common types).
    #[must_use]
    pub const fn byte_size(&self, machine: u16) -> u8 {
        match machine {
            0x014C => match self.reloc_type { // x86
                0x02 | 0x03 => 2,
                _ => 4,
            },
            0x8664 => match self.reloc_type { // x64
                0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x08 | 0x09 | 0x0A | 0x0C | 0x0D => 4,
                _ => 8,
            },
            _ => 4,
        }
    }
}

// ── CoffSymbol ────────────────────────────────────────────────────────────────

/// Parsed COFF symbol table entry.
#[derive(Debug, Clone)]
pub struct CoffSymbol {
    pub name: String,
    pub value: u32,
    pub section_number: i16,
    pub type_: u16,
    pub storage_class: u8,
}

impl CoffSymbol {
    /// True if this is a function symbol (type high nibble = 0x20).
    #[must_use]
    pub const fn is_function(&self) -> bool { (self.type_ >> 4) & 0x0F == 0x02 }
    /// True if symbol is defined (`section_number` > 0).
    #[must_use]
    pub const fn is_defined(&self) -> bool { self.section_number > 0 }
    /// True if externally visible.
    #[must_use]
    pub const fn is_external(&self) -> bool { self.storage_class == 2 }
    /// True if static.
    #[must_use]
    pub const fn is_static(&self) -> bool { self.storage_class == 3 }
}

// ── ObjParser ─────────────────────────────────────────────────────────────────

/// Parses a COFF relocatable object file and exposes sections, symbols, and relocs.
pub struct ObjParser<'a> {
    data: &'a [u8],
    pub machine: u16,
    pub sections: Vec<CoffSection>,
    pub symbols: Vec<CoffSymbol>,
    /// Relocations indexed by section index.
    pub relocs: HashMap<usize, Vec<CoffRelocation>>,
}

impl<'a> ObjParser<'a> {
    /// Parse a COFF `.obj` file.
    ///
    /// # Errors
    ///
    /// Returns [`ExtractError`] if the data is not a valid COFF object file.
    pub fn parse(data: &'a [u8]) -> Result<Self, ExtractError> {
        if data.len() < 20 { return Err(ExtractError::TooShort); }

        let machine             = read_u16(data, 0);
        let num_sections        = read_u16(data, 2) as usize;
        let _time_date_stamp    = read_u32(data, 4);
        let symtab_ptr          = read_u32(data, 8) as usize;
        let num_symbols         = read_u32(data, 12) as usize;
        let opt_header_size     = read_u16(data, 16) as usize;
        let _characteristics    = read_u16(data, 18);

        // Validate machine type (allow common ones)
        match machine {
            0x014C | 0x8664 | 0x01C4 | 0xAA64 | 0x0200 | 0x01C0 => {}
            m => return Err(ExtractError::BadMagic(m)),
        }

        let section_start = 20 + opt_header_size;
        if section_start + num_sections * 40 > data.len() {
            return Err(ExtractError::Parse("section headers out of range".into()));
        }

        // Parse sections
        let sections = Self::parse_sections(data, section_start, num_sections);

        // Parse string table (immediately after symbol table)
        let strtab_offset = if symtab_ptr > 0 { symtab_ptr + num_symbols * 18 } else { 0 };
        let strtab = if strtab_offset + 4 <= data.len() && symtab_ptr > 0 {
            let strtab_len = read_u32(data, strtab_offset) as usize;
            if strtab_offset + strtab_len <= data.len() {
                &data[strtab_offset..strtab_offset + strtab_len]
            } else { &[] }
        } else { &[] };

        // Parse symbols
        let symbols = if symtab_ptr > 0 {
            if symtab_ptr + num_symbols * 18 > data.len() {
                return Err(ExtractError::SymtabOutOfRange);
            }
            Self::parse_symbols(data, symtab_ptr, num_symbols, strtab)
        } else { Vec::new() };

        // Parse relocations per section
        let mut relocs: HashMap<usize, Vec<CoffRelocation>> = HashMap::new();
        for (i, sec) in sections.iter().enumerate() {
            if sec.number_of_relocations == 0 || sec.pointer_to_relocations == 0 { continue; }
            let rptr = sec.pointer_to_relocations as usize;
            let rcount = sec.number_of_relocations as usize;
            if rptr + rcount * 10 > data.len() { continue; }
            let mut rvec = Vec::with_capacity(rcount);
            for r in 0..rcount {
                let base = rptr + r * 10;
                rvec.push(CoffRelocation {
                    virtual_address: read_u32(data, base),
                    symbol_index:    read_u32(data, base + 4),
                    reloc_type:      read_u16(data, base + 8),
                });
            }
            relocs.insert(i, rvec);
        }

        Ok(Self { data, machine, sections, symbols, relocs })
    }

    fn parse_sections(data: &[u8], offset: usize, count: usize) -> Vec<CoffSection> {
        let mut sections = Vec::with_capacity(count);
        for i in 0..count {
            let base = offset + i * 40;
            if base + 40 > data.len() { break; }
            // String table references (starting with '/') are treated the same as inline names for now.
            let name = coff_short_name(&data[base..base + 8]);
            sections.push(CoffSection {
                name,
                virtual_size:             read_u32(data, base + 8),
                virtual_address:          read_u32(data, base + 12),
                size_of_raw_data:         read_u32(data, base + 16),
                pointer_to_raw_data:      read_u32(data, base + 20),
                pointer_to_relocations:   read_u32(data, base + 24),
                number_of_relocations:    read_u16(data, base + 32),
                characteristics:          read_u32(data, base + 36),
            });
        }
        sections
    }

    fn parse_symbols(data: &[u8], offset: usize, count: usize, strtab: &[u8]) -> Vec<CoffSymbol> {
        let mut symbols = Vec::new();
        let mut i = 0usize;
        while i < count {
            let base = offset + i * 18;
            if base + 18 > data.len() { break; }
            // Name: if first 4 bytes are zero, next 4 are offset into string table
            let name = if data[base] == 0 && data[base+1] == 0 && data[base+2] == 0 && data[base+3] == 0 {
                let str_off = read_u32(data, base + 4) as usize;
                read_cstr_strtab(strtab, str_off)
            } else {
                coff_short_name(&data[base..base + 8])
            };
            let value          = read_u32(data, base + 8);
            let section_number = i16::from_le_bytes(read_u16(data, base + 12).to_le_bytes());
            let type_          = read_u16(data, base + 14);
            let storage_class  = data[base + 16];
            let aux_count      = data[base + 17] as usize;
            symbols.push(CoffSymbol { name, value, section_number, type_, storage_class });
            i += 1 + aux_count;
        }
        symbols
    }

    /// Return the raw bytes of section `sec_idx`.
    #[must_use]
    pub fn section_data(&self, sec_idx: usize) -> Option<&[u8]> {
        let sec = self.sections.get(sec_idx)?;
        let start = sec.pointer_to_raw_data as usize;
        let end   = start + sec.size_of_raw_data as usize;
        if end > self.data.len() { return None; }
        Some(&self.data[start..end])
    }

    /// Relocations for a section, as [`RelocationMask`] offsets.
    #[must_use]
    pub fn reloc_masks(&self, sec_idx: usize) -> Vec<RelocationMask> {
        self.relocs.get(&sec_idx)
            .map(|relocs| relocs.iter().map(|r| {
                let sz = r.byte_size(self.machine);
                RelocationMask::new(r.virtual_address, sz)
            }).collect())
            .unwrap_or_default()
    }
}

// ── PatternExtractor ──────────────────────────────────────────────────────────

/// Extracted FLIRT-style pattern for a single function.
#[derive(Debug, Clone)]
pub struct ExtractedPattern {
    pub name: String,
    pub pattern: PatternBytes,
    pub crc: CrcTail,
    /// Total function byte length.
    pub func_len: u32,
    /// Raw function bytes.
    pub raw_bytes: Vec<u8>,
    pub reloc_masks: Vec<RelocationMask>,
}

impl ExtractedPattern {
    /// True if the pattern has enough concrete bytes to be useful.
    #[must_use]
    pub fn is_viable(&self, min_concrete: usize) -> bool {
        self.pattern.concrete_count() >= min_concrete
    }
}

/// Extracts FLIRT patterns from a COFF object file.
pub struct PatternExtractor {
    /// Length of the leading pattern (default 32).
    pub initial_len: usize,
    /// Length of the CRC region (default 16).
    pub crc_len: usize,
    /// Minimum concrete bytes required for a viable pattern.
    pub min_concrete: usize,
}

impl Default for PatternExtractor {
    fn default() -> Self { Self { initial_len: 32, crc_len: 16, min_concrete: 4 } }
}

impl PatternExtractor {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Extract all function patterns from a COFF `.obj` file.
    ///
    /// # Errors
    ///
    /// Returns [`ExtractError`] if the object file cannot be parsed.
    pub fn extract_from_coff(&self, data: &[u8]) -> Result<Vec<ExtractedPattern>, ExtractError> {
        let parser = ObjParser::parse(data)?;
        let mut results = Vec::new();

        for sym in &parser.symbols {
            if !sym.is_defined() { continue; }
            if !sym.is_function() && !sym.is_external() && !sym.is_static() { continue; }
            if sym.name.is_empty() || sym.name.starts_with('.') { continue; }

            let Ok(sec_idx) = usize::try_from(sym.section_number - 1) else { continue };
            let Some(sec_data) = parser.section_data(sec_idx) else { continue };
            let offset = sym.value as usize;
            if offset >= sec_data.len() { continue; }
            let func_bytes = &sec_data[offset..];

            // Determine function length: use next symbol at same section if possible
            let func_len = Self::estimate_func_len(
                &parser.symbols, sym.section_number, sym.value, sec_data.len() - offset,
            );
            if func_len == 0 { continue; }
            let func_bytes = &func_bytes[..func_len];

            // Build relocation masks relative to function start
            let mut masks: Vec<RelocationMask> = parser.reloc_masks(sec_idx)
                .into_iter()
                .filter(|m| {
                    let m_start = m.offset;
                    let m_end = m_start + u32::from(m.length);
                    m_start >= sym.value && m_end <= sym.value + u32::try_from(func_len).unwrap_or(u32::MAX)
                })
                .map(|m| RelocationMask::new(m.offset - sym.value, m.length))
                .collect();
            masks.sort_by_key(|m| m.offset);

            let pattern = PatternBytes::new(func_bytes, &masks, self.initial_len);
            let crc = CrcTail::compute(func_bytes, &masks, self.initial_len, self.crc_len);

            let ep = ExtractedPattern {
                name: sym.name.clone(),
                pattern, crc,
                func_len: u32::try_from(func_len).unwrap_or(u32::MAX),
                raw_bytes: func_bytes.to_vec(),
                reloc_masks: masks,
            };
            if ep.is_viable(self.min_concrete) {
                results.push(ep);
            }
        }
        Ok(results)
    }

    fn estimate_func_len(
        symbols: &[CoffSymbol],
        section_num: i16,
        func_offset: u32,
        max: usize,
    ) -> usize {
        // Find the next function symbol in same section with a higher offset
        let mut next_offset: Option<u32> = None;
        for sym in symbols {
            if sym.section_number != section_num { continue; }
            if sym.value > func_offset {
                let n = sym.value;
                match next_offset {
                    None => next_offset = Some(n),
                    Some(cur) if n < cur => next_offset = Some(n),
                    _ => {}
                }
            }
        }
        let raw_len = next_offset.map_or(max, |n| (n - func_offset) as usize);
        raw_len.min(max).min(4096) // cap at 4 KiB for safety
    }
}

// ── Low-level helpers ─────────────────────────────────────────────────────────

/// Decode a COFF 8-byte short name (section names, inline symbol names).
///
/// The field is NUL-**padded**, so the name ends at the first NUL — not at the
/// last one. This used to be `trim_end_matches('\0')`, which strips only
/// *trailing* NULs and therefore returns a `String` with an interior NUL and
/// trailing garbage whenever the padding is not all zeroes (T37).
///
/// The two rules coincide on linker-emitted objects, which is why the
/// divergence never showed up in practice and why the crate's other COFF
/// decoder in `library_scanner.rs` — which always truncated at the first NUL —
/// silently disagreed with this one. `flirt-gen` ingests third-party `.lib`
/// archives, whose bytes are not trusted, and a symbol short name becomes the
/// name of an emitted signature.
fn coff_short_name(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn read_u16(data: &[u8], o: usize) -> u16 {
    if o + 2 > data.len() { return 0; }
    u16::from_le_bytes([data[o], data[o+1]])
}

fn read_u32(data: &[u8], o: usize) -> u32 {
    if o + 4 > data.len() { return 0; }
    u32::from_le_bytes(data[o..o+4].try_into().unwrap_or([0;4]))
}

fn read_cstr_strtab(strtab: &[u8], off: usize) -> String {
    if off >= strtab.len() { return String::new(); }
    let end = strtab[off..].iter().position(|&b| b == 0).unwrap_or(strtab.len() - off);
    String::from_utf8_lossy(&strtab[off..off + end]).to_string()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relocation_mask_covers() {
        let m = RelocationMask::new(4, 4);
        assert!(m.covers(4));
        assert!(m.covers(7));
        assert!(!m.covers(3));
        assert!(!m.covers(8));
    }

    #[test]
    fn pattern_bytes_wildcards() {
        let raw = [0x55u8, 0x48, 0x89, 0xE5, 0xC3];
        let masks = vec![RelocationMask::new(2, 2)];
        let p = PatternBytes::new(&raw, &masks, 5);
        assert_eq!(p.bytes[0], Some(0x55));
        assert_eq!(p.bytes[2], None);
        assert_eq!(p.bytes[3], None);
        assert_eq!(p.bytes[4], Some(0xC3));
    }

    #[test]
    fn pattern_bytes_hex_string() {
        let raw = [0x55u8, 0x48];
        let p = PatternBytes::new(&raw, &[], 2);
        assert_eq!(p.to_hex_string(), "5548");
    }

    #[test]
    fn pattern_bytes_hex_with_wildcard() {
        let raw = [0x55u8, 0x48];
        let masks = vec![RelocationMask::new(1, 1)];
        let p = PatternBytes::new(&raw, &masks, 2);
        assert_eq!(p.to_hex_string(), "55..");
    }

    #[test]
    fn crc_tail_deterministic() {
        let raw: Vec<u8> = (0u8..64).collect();
        let c1 = CrcTail::compute(&raw, &[], 32, 16);
        let c2 = CrcTail::compute(&raw, &[], 32, 16);
        assert_eq!(c1.crc, c2.crc);
        assert_eq!(c1.length, 16);
    }

    #[test]
    fn crc_tail_skips_masked() {
        let mut a: Vec<u8> = (0u8..64).collect();
        let b = a.clone();
        a[36] = 0xFF; // differ inside mask
        let masks = vec![RelocationMask::new(36, 4)];
        let ca = CrcTail::compute(&a, &masks, 32, 16);
        let cb = CrcTail::compute(&b, &masks, 32, 16);
        assert_eq!(ca.crc, cb.crc, "CRC must be equal when diff is inside mask");
    }

    #[test]
    fn crc16_known_vector() {
        // The generator's tail CRC must be MCRF4XX, identical to the matcher's.
        // Pinned against the catalogue check value, not just "it's stable".
        assert_eq!(crc16_flirt_std(b"123456789"), 0x6F91);
        assert_eq!(crc16_flirt_std(&[]), 0xFFFF);
    }

    /// The defect this file used to have: generator and matcher must agree.
    #[test]
    fn generator_tail_crc_agrees_with_the_canonical_definition() {
        for d in [&b""[..], b"IDA", b"123456789", &[0x55u8; 32][..], &[0u8; 7][..]] {
            assert_eq!(
                crc16_flirt_std(d),
                rustre_flirt::crc::flirt_tail(d),
                "generator CRC diverged from the canonical FLIRT tail CRC"
            );
        }
    }

    #[test]
    fn pattern_extractor_reject_bad_magic() {
        let data = [0x00u8; 64]; // machine = 0x0000, not valid
        let extractor = PatternExtractor::new();
        let result = extractor.extract_from_coff(&data);
        assert!(result.is_err());
    }

    #[test]
    fn pattern_extractor_reject_too_short() {
        let extractor = PatternExtractor::new();
        let result = extractor.extract_from_coff(&[0u8; 5]);
        assert!(matches!(result, Err(ExtractError::TooShort)));
    }

    #[test]
    fn concrete_count_all_concrete() {
        let raw = [0x55u8; 8];
        let p = PatternBytes::new(&raw, &[], 8);
        assert_eq!(p.concrete_count(), 8);
    }

    #[test]
    fn concrete_count_all_wildcard() {
        let raw = [0x55u8; 4];
        let masks = vec![RelocationMask::new(0, 4)];
        let p = PatternBytes::new(&raw, &masks, 4);
        assert_eq!(p.concrete_count(), 0);
    }

    #[test]
    fn extracted_pattern_is_viable() {
        let pattern = PatternBytes {
            bytes: vec![Some(0x55), Some(0x48), None, None, Some(0x89)],
        };
        let ep = ExtractedPattern {
            name: "foo".to_string(),
            pattern,
            crc: CrcTail { crc: 0x1234, length: 8 },
            func_len: 32,
            raw_bytes: vec![0x55; 32],
            reloc_masks: vec![],
        };
        assert!(ep.is_viable(3));
        assert!(!ep.is_viable(4));
    }

    #[test]
    fn reloc_mask_zero_length() {
        let m = RelocationMask::new(10, 0);
        assert!(!m.covers(10));
    }

    #[test]
    fn coff_symbol_is_function() {
        let sym = CoffSymbol {
            name: "foo".to_string(), value: 0,
            section_number: 1, type_: 0x0020, storage_class: 2,
        };
        assert!(sym.is_function());
        assert!(sym.is_external());
    }

    #[test]
    fn coff_symbol_not_function() {
        let sym = CoffSymbol {
            name: "bar".to_string(), value: 4,
            section_number: 1, type_: 0x0000, storage_class: 3,
        };
        assert!(!sym.is_function());
        assert!(sym.is_static());
    }
}
