//! Built-in binary file templates (010 Editor–style).
//!
//! Provides a rich set of pre-built templates for common binary formats:
//! PE (DOS/MZ, COFF, Optional Header, Section Table, Import Directory, Export Directory),
//! ELF 32-bit and 64-bit, ZIP (Local File Header, Central Directory, EOCD),
//! PNG (chunks), JPEG (markers), GIF, MP4 / ISO BMFF boxes, PDF, and GZIP.
//!
//! Every template produces a [`TemplateResult`] containing a flat list of
//! [`TemplateField`] entries with name, offset, size, human-readable value
//! representation, a categorization colour hint, and optional nested children.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// TemplateField
// ─────────────────────────────────────────────────────────────────────────────

/// RGBA colour hint for GUI highlighting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    /// Create an opaque colour.
    #[must_use]
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    /// Predefined: headers (blue).
    pub const HEADER: Self = Self::rgb(0x4A, 0x90, 0xD9);
    /// Predefined: signatures/magic (green).
    pub const MAGIC: Self = Self::rgb(0x27, 0xAE, 0x60);
    /// Predefined: offsets/pointers (orange).
    pub const OFFSET: Self = Self::rgb(0xE6, 0x7E, 0x22);
    /// Predefined: sizes (purple).
    pub const SIZE: Self = Self::rgb(0x8E, 0x44, 0xAD);
    /// Predefined: flags (red).
    pub const FLAGS: Self = Self::rgb(0xC0, 0x39, 0x2B);
    /// Predefined: data (grey).
    pub const DATA: Self = Self::rgb(0x7F, 0x8C, 0x8D);
    /// Predefined: strings / names (teal).
    pub const STRING: Self = Self::rgb(0x16, 0xA0, 0x85);
}

/// A single resolved field from applying a built-in template.
#[derive(Debug, Clone)]
pub struct TemplateField {
    /// Field name (e.g. `"e_magic"`, `"Machine"`).
    pub name: String,
    /// Byte offset from the start of the input buffer.
    pub offset: usize,
    /// Byte size of this field.
    pub size: usize,
    /// Human-readable value representation (hex, decimal, enum label, etc.).
    pub value_repr: String,
    /// GUI colour hint.
    pub color: Color,
    /// Optional nested child fields (for structs / arrays).
    pub children: Vec<TemplateField>,
}

impl TemplateField {
    /// Create a leaf field (no children).
    #[must_use]
    pub fn leaf(
        name: impl Into<String>,
        offset: usize,
        size: usize,
        value_repr: impl Into<String>,
        color: Color,
    ) -> Self {
        Self {
            name: name.into(),
            offset,
            size,
            value_repr: value_repr.into(),
            color,
            children: Vec::new(),
        }
    }

    /// Create a group field with child fields.
    #[must_use]
    pub fn group(
        name: impl Into<String>,
        offset: usize,
        size: usize,
        color: Color,
        children: Vec<TemplateField>,
    ) -> Self {
        Self {
            name: name.into(),
            offset,
            size,
            value_repr: String::new(),
            color,
            children,
        }
    }

    /// Returns `true` if this field has nested children.
    #[must_use]
    pub const fn is_group(&self) -> bool {
        !self.children.is_empty()
    }

    /// Total byte span covered by this field (including children).
    #[must_use]
    pub const fn end_offset(&self) -> usize {
        self.offset + self.size
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateResult
// ─────────────────────────────────────────────────────────────────────────────

/// The result of applying a [`BuiltinTemplate`] to a byte slice.
#[derive(Debug, Clone)]
pub struct TemplateResult {
    /// Which template produced this result.
    pub template: BuiltinTemplate,
    /// Flat list of top-level fields (some may have children).
    pub fields: Vec<TemplateField>,
    /// Bytes that were not covered by any field.
    pub unparsed_offset: usize,
    /// Any non-fatal warnings produced during parsing.
    pub warnings: Vec<String>,
}

impl TemplateResult {
    const fn new(template: BuiltinTemplate) -> Self {
        Self {
            template,
            fields: Vec::new(),
            unparsed_offset: 0,
            warnings: Vec::new(),
        }
    }

    /// Total number of fields (including nested).
    #[must_use]
    pub fn total_field_count(&self) -> usize {
        fn count(fields: &[TemplateField]) -> usize {
            fields.iter().map(|f| 1 + count(&f.children)).sum()
        }
        count(&self.fields)
    }

    /// Find the first field with `name` at the top level.
    #[must_use]
    pub fn find_field(&self, name: &str) -> Option<&TemplateField> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Read the raw value of a top-level field as a `u64`, if numeric.
    #[must_use]
    pub fn field_u64(&self, name: &str, bytes: &[u8]) -> Option<u64> {
        let f = self.find_field(name)?;
        read_u64_le(bytes, f.offset, f.size)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BuiltinTemplate enum
// ─────────────────────────────────────────────────────────────────────────────

/// Enumeration of all built-in binary templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuiltinTemplate {
    /// Microsoft PE executable (DOS header + PE header + optional + sections + imports + exports).
    Pe,
    /// ELF 32-bit executable.
    Elf32,
    /// ELF 64-bit executable.
    Elf64,
    /// ZIP archive (local file headers + central directory + EOCD).
    Zip,
    /// PNG image (signature + chunks).
    Png,
    /// JPEG image (SOI + marker segments).
    Jpeg,
    /// GIF image (header + logical screen descriptor + blocks).
    Gif,
    /// MP4 / ISO BMFF container (box hierarchy).
    Mp4,
    /// PDF document (header + cross-reference / object stubs).
    Pdf,
    /// GZIP compressed file.
    Gzip,
}

impl BuiltinTemplate {
    /// Human-readable display name.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Pe => "PE Executable",
            Self::Elf32 => "ELF 32-bit",
            Self::Elf64 => "ELF 64-bit",
            Self::Zip => "ZIP Archive",
            Self::Png => "PNG Image",
            Self::Jpeg => "JPEG Image",
            Self::Gif => "GIF Image",
            Self::Mp4 => "MP4 / ISOBMFF",
            Self::Pdf => "PDF Document",
            Self::Gzip => "GZIP Compressed",
        }
    }

    /// Apply this template to `bytes`, returning a [`TemplateResult`].
    #[must_use]
    pub fn apply(self, bytes: &[u8]) -> TemplateResult {
        match self {
            Self::Pe => PeTemplate::apply(bytes),
            Self::Elf32 => ElfTemplate::apply(bytes, false),
            Self::Elf64 => ElfTemplate::apply(bytes, true),
            Self::Zip => ZipTemplate::apply(bytes),
            Self::Png => PngTemplate::apply(bytes),
            Self::Jpeg => JpegTemplate::apply(bytes),
            Self::Gif => GifTemplate::apply(bytes),
            Self::Mp4 => Mp4Template::apply(bytes),
            Self::Pdf => PdfTemplate::apply(bytes),
            Self::Gzip => GzipTemplate::apply(bytes),
        }
    }

    /// Detect which template best matches the magic bytes of `bytes`.
    #[must_use]
    pub fn detect(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }
        // PE: MZ signature
        if bytes.starts_with(b"MZ") || bytes.starts_with(b"ZM") {
            return Some(Self::Pe);
        }
        // ELF
        if bytes.starts_with(b"\x7FELF") {
            let class = bytes.get(4).copied().unwrap_or(0);
            return Some(if class == 2 { Self::Elf64 } else { Self::Elf32 });
        }
        // ZIP (local file header or EOCD)
        if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
            return Some(Self::Zip);
        }
        // PNG
        if bytes.starts_with(b"\x89PNG\r\n\x1A\n") {
            return Some(Self::Png);
        }
        // JPEG
        if bytes.starts_with(b"\xFF\xD8\xFF") {
            return Some(Self::Jpeg);
        }
        // GIF
        if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
            return Some(Self::Gif);
        }
        // PDF
        if bytes.starts_with(b"%PDF-") {
            return Some(Self::Pdf);
        }
        // GZIP
        if bytes.starts_with(b"\x1F\x8B") {
            return Some(Self::Gzip);
        }
        // MP4 / ISOBMFF: check for 'ftyp' box
        if bytes.len() >= 8 && &bytes[4..8] == b"ftyp" {
            return Some(Self::Mp4);
        }
        None
    }

    /// All variants in a canonical order.
    pub const ALL: &'static [Self] = &[
        Self::Pe,
        Self::Elf32,
        Self::Elf64,
        Self::Zip,
        Self::Png,
        Self::Jpeg,
        Self::Gif,
        Self::Mp4,
        Self::Pdf,
        Self::Gzip,
    ];
}

// ─────────────────────────────────────────────────────────────────────────────
// Byte-reading helpers
// ─────────────────────────────────────────────────────────────────────────────

fn read_u8(bytes: &[u8], off: usize) -> Option<u8> {
    bytes.get(off).copied()
}

fn read_u16_le(bytes: &[u8], off: usize) -> Option<u16> {
    if off + 2 <= bytes.len() {
        Some(u16::from_le_bytes(bytes[off..off + 2].try_into().ok()?))
    } else {
        None
    }
}

fn read_u16_be(bytes: &[u8], off: usize) -> Option<u16> {
    if off + 2 <= bytes.len() {
        Some(u16::from_be_bytes(bytes[off..off + 2].try_into().ok()?))
    } else {
        None
    }
}

fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    if off + 4 <= bytes.len() {
        Some(u32::from_le_bytes(bytes[off..off + 4].try_into().ok()?))
    } else {
        None
    }
}

fn read_u32_be(bytes: &[u8], off: usize) -> Option<u32> {
    if off + 4 <= bytes.len() {
        Some(u32::from_be_bytes(bytes[off..off + 4].try_into().ok()?))
    } else {
        None
    }
}

fn read_u64_le(bytes: &[u8], off: usize, size: usize) -> Option<u64> {
    if off + size > bytes.len() {
        return None;
    }
    Some(match size {
        1 => u64::from(bytes[off]),
        2 => u64::from(u16::from_le_bytes(bytes[off..off + 2].try_into().ok()?)),
        4 => u64::from(u32::from_le_bytes(bytes[off..off + 4].try_into().ok()?)),
        8 => u64::from_le_bytes(bytes[off..off + 8].try_into().ok()?),
        _ => return None,
    })
}

fn hex_bytes(bytes: &[u8], off: usize, len: usize) -> String {
    if off + len > bytes.len() {
        return "<out of bounds>".to_string();
    }
    bytes[off..off + len]
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn ascii_str(bytes: &[u8], off: usize, len: usize) -> String {
    if off + len > bytes.len() {
        return "<eof>".to_string();
    }
    bytes[off..off + len]
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// PE Template
// ─────────────────────────────────────────────────────────────────────────────

/// PE executable template: DOS header + PE signature + COFF header +
/// optional header (PE32/PE32+) + section table + import directory + export directory.
pub struct PeTemplate;

impl PeTemplate {
    /// Apply the PE template to `bytes`.
    #[must_use]
    pub fn apply(bytes: &[u8]) -> TemplateResult {
        let mut result = TemplateResult::new(BuiltinTemplate::Pe);

        // ── DOS header ──────────────────────────────────────────────────────
        let dos = Self::parse_dos_header(bytes, &mut result);
        let pe_off = dos.unwrap_or(0x40);

        // ── PE signature ────────────────────────────────────────────────────
        if pe_off + 4 <= bytes.len() {
            result.fields.push(TemplateField::leaf(
                "PESignature",
                pe_off,
                4,
                hex_bytes(bytes, pe_off, 4),
                Color::MAGIC,
            ));
        } else {
            result.warnings.push("PE offset out of range".to_string());
            return result;
        }

        let coff_off = pe_off + 4;

        // ── COFF header ─────────────────────────────────────────────────────
        let num_sections = Self::parse_coff_header(bytes, coff_off, &mut result);
        let opt_header_off = coff_off + 20;
        let opt_header_size = read_u16_le(bytes, coff_off + 16).unwrap_or(0) as usize;

        // ── Optional header ─────────────────────────────────────────────────
        let is_pe32plus =
            Self::parse_optional_header(bytes, opt_header_off, opt_header_size, &mut result);

        // ── Section table ────────────────────────────────────────────────────
        let sections_off = opt_header_off + opt_header_size;
        let n_sections = num_sections.unwrap_or(0) as usize;
        Self::parse_section_table(bytes, sections_off, n_sections, &mut result);

        // ── Import directory ─────────────────────────────────────────────────
        let _ = is_pe32plus;
        Self::parse_import_directory(bytes, pe_off, opt_header_off, &mut result);

        // ── Export directory ─────────────────────────────────────────────────
        Self::parse_export_directory(bytes, pe_off, opt_header_off, &mut result);

        result.unparsed_offset = sections_off + n_sections * 40;
        result
    }

    fn parse_dos_header(bytes: &[u8], result: &mut TemplateResult) -> Option<usize> {
        if bytes.len() < 64 {
            result
                .warnings
                .push("file too small for DOS header".to_string());
            return None;
        }
        let mut children = Vec::new();
        let fields: &[(&str, usize, usize)] = &[
            ("e_magic", 0, 2),
            ("e_cblp", 2, 2),
            ("e_cp", 4, 2),
            ("e_crlc", 6, 2),
            ("e_cparhdr", 8, 2),
            ("e_minalloc", 10, 2),
            ("e_maxalloc", 12, 2),
            ("e_ss", 14, 2),
            ("e_sp", 16, 2),
            ("e_csum", 18, 2),
            ("e_ip", 20, 2),
            ("e_cs", 22, 2),
            ("e_lfarlc", 24, 2),
            ("e_ovno", 26, 2),
            ("e_res", 28, 8),
            ("e_oemid", 36, 2),
            ("e_oeminfo", 38, 2),
            ("e_res2", 40, 20),
            ("e_lfanew", 60, 4),
        ];
        for &(name, off, sz) in fields {
            let color = if name == "e_magic" {
                Color::MAGIC
            } else if name == "e_lfanew" {
                Color::OFFSET
            } else {
                Color::HEADER
            };
            let repr = if sz <= 8 {
                read_u64_le(bytes, off, sz)
                    .map(|v| format!("0x{v:X}"))
                    .unwrap_or_else(|| "<eof>".to_string())
            } else {
                hex_bytes(bytes, off, sz)
            };
            children.push(TemplateField::leaf(name, off, sz, repr, color));
        }
        let pe_off = read_u32_le(bytes, 60).unwrap_or(0x40) as usize;
        result.fields.push(TemplateField::group(
            "DOSHeader",
            0,
            64,
            Color::HEADER,
            children,
        ));
        Some(pe_off)
    }

    fn parse_coff_header(bytes: &[u8], off: usize, result: &mut TemplateResult) -> Option<u16> {
        if off + 20 > bytes.len() {
            result.warnings.push("COFF header out of range".to_string());
            return None;
        }
        let machine = read_u16_le(bytes, off).unwrap_or(0);
        let num_sections = read_u16_le(bytes, off + 2).unwrap_or(0);
        let ts = read_u32_le(bytes, off + 4).unwrap_or(0);
        let sym_tbl = read_u32_le(bytes, off + 8).unwrap_or(0);
        let num_sym = read_u32_le(bytes, off + 12).unwrap_or(0);
        let opt_sz = read_u16_le(bytes, off + 16).unwrap_or(0);
        let chars = read_u16_le(bytes, off + 18).unwrap_or(0);

        let machine_name = match machine {
            0x014C => "IMAGE_FILE_MACHINE_I386",
            0x8664 => "IMAGE_FILE_MACHINE_AMD64",
            0x01C4 => "IMAGE_FILE_MACHINE_ARMNT",
            0xAA64 => "IMAGE_FILE_MACHINE_ARM64",
            _ => "Unknown",
        };

        let children = vec![
            TemplateField::leaf(
                "Machine",
                off,
                2,
                format!("0x{machine:04X} ({machine_name})"),
                Color::HEADER,
            ),
            TemplateField::leaf(
                "NumberOfSections",
                off + 2,
                2,
                num_sections.to_string(),
                Color::SIZE,
            ),
            TemplateField::leaf(
                "TimeDateStamp",
                off + 4,
                4,
                format!("0x{ts:08X}"),
                Color::DATA,
            ),
            TemplateField::leaf(
                "PointerToSymbolTable",
                off + 8,
                4,
                format!("0x{sym_tbl:08X}"),
                Color::OFFSET,
            ),
            TemplateField::leaf(
                "NumberOfSymbols",
                off + 12,
                4,
                num_sym.to_string(),
                Color::SIZE,
            ),
            TemplateField::leaf(
                "SizeOfOptionalHeader",
                off + 16,
                2,
                opt_sz.to_string(),
                Color::SIZE,
            ),
            TemplateField::leaf(
                "Characteristics",
                off + 18,
                2,
                format!("0x{chars:04X}"),
                Color::FLAGS,
            ),
        ];
        result.fields.push(TemplateField::group(
            "COFFHeader",
            off,
            20,
            Color::HEADER,
            children,
        ));
        Some(num_sections)
    }

    fn parse_optional_header(
        bytes: &[u8],
        off: usize,
        size: usize,
        result: &mut TemplateResult,
    ) -> bool {
        if size == 0 || off + size > bytes.len() {
            return false;
        }
        let magic = read_u16_le(bytes, off).unwrap_or(0);
        let is_pe32plus = magic == 0x020B;
        let label = if is_pe32plus { "PE32+" } else { "PE32" };

        let entry_off = read_u32_le(bytes, off + 16).unwrap_or(0);
        let image_base: u64 = if is_pe32plus {
            read_u64_le(bytes, off + 24, 8).unwrap_or(0)
        } else {
            read_u64_le(bytes, off + 28, 4).unwrap_or(0)
        };

        let _ = is_pe32plus;
        let size_of_image = read_u32_le(bytes, off + 56).unwrap_or(0);

        let subsystem = read_u16_le(bytes, off + 68).unwrap_or(0);

        let sub_name = match subsystem {
            1 => "NATIVE",
            2 => "WINDOWS_GUI",
            3 => "WINDOWS_CUI",
            5 => "OS2_CUI",
            7 => "POSIX_CUI",
            9 => "WINDOWS_CE_GUI",
            10 => "EFI_APPLICATION",
            _ => "UNKNOWN",
        };

        let children = vec![
            TemplateField::leaf(
                "Magic",
                off,
                2,
                format!("0x{magic:04X} ({label})"),
                Color::MAGIC,
            ),
            TemplateField::leaf(
                "MajorLinkerVersion",
                off + 2,
                1,
                read_u8(bytes, off + 2).unwrap_or(0).to_string(),
                Color::DATA,
            ),
            TemplateField::leaf(
                "MinorLinkerVersion",
                off + 3,
                1,
                read_u8(bytes, off + 3).unwrap_or(0).to_string(),
                Color::DATA,
            ),
            TemplateField::leaf(
                "SizeOfCode",
                off + 4,
                4,
                format!("0x{:08X}", read_u32_le(bytes, off + 4).unwrap_or(0)),
                Color::SIZE,
            ),
            TemplateField::leaf(
                "AddressOfEntryPoint",
                off + 16,
                4,
                format!("0x{entry_off:08X}"),
                Color::OFFSET,
            ),
            TemplateField::leaf(
                "ImageBase",
                off + if is_pe32plus { 24 } else { 28 },
                if is_pe32plus { 8 } else { 4 },
                format!("0x{image_base:X}"),
                Color::OFFSET,
            ),
            TemplateField::leaf(
                "SizeOfImage",
                off + 56,
                4,
                format!("0x{size_of_image:08X}"),
                Color::SIZE,
            ),
            TemplateField::leaf(
                "Subsystem",
                off + 68,
                2,
                format!("0x{subsystem:04X} ({sub_name})"),
                Color::DATA,
            ),
        ];

        result.fields.push(TemplateField::group(
            if is_pe32plus {
                "OptionalHeader (PE32+)"
            } else {
                "OptionalHeader (PE32)"
            },
            off,
            size,
            Color::HEADER,
            children,
        ));
        is_pe32plus
    }

    fn parse_section_table(bytes: &[u8], off: usize, count: usize, result: &mut TemplateResult) {
        for i in 0..count {
            let sec_off = off + i * 40;
            if sec_off + 40 > bytes.len() {
                break;
            }
            let name_str = ascii_str(bytes, sec_off, 8)
                .trim_end_matches('.')
                .trim_end()
                .to_string();
            let virt_sz = read_u32_le(bytes, sec_off + 8).unwrap_or(0);
            let virt_addr = read_u32_le(bytes, sec_off + 12).unwrap_or(0);
            let raw_sz = read_u32_le(bytes, sec_off + 16).unwrap_or(0);
            let raw_ptr = read_u32_le(bytes, sec_off + 20).unwrap_or(0);
            let chars = read_u32_le(bytes, sec_off + 36).unwrap_or(0);

            let children = vec![
                TemplateField::leaf("Name", sec_off, 8, name_str.clone(), Color::STRING),
                TemplateField::leaf(
                    "VirtualSize",
                    sec_off + 8,
                    4,
                    format!("0x{virt_sz:08X}"),
                    Color::SIZE,
                ),
                TemplateField::leaf(
                    "VirtualAddress",
                    sec_off + 12,
                    4,
                    format!("0x{virt_addr:08X}"),
                    Color::OFFSET,
                ),
                TemplateField::leaf(
                    "SizeOfRawData",
                    sec_off + 16,
                    4,
                    format!("0x{raw_sz:08X}"),
                    Color::SIZE,
                ),
                TemplateField::leaf(
                    "PointerToRawData",
                    sec_off + 20,
                    4,
                    format!("0x{raw_ptr:08X}"),
                    Color::OFFSET,
                ),
                TemplateField::leaf(
                    "Characteristics",
                    sec_off + 36,
                    4,
                    format!("0x{chars:08X}"),
                    Color::FLAGS,
                ),
            ];
            result.fields.push(TemplateField::group(
                format!("Section[{i}] ({name_str})"),
                sec_off,
                40,
                Color::DATA,
                children,
            ));
        }
    }

    fn parse_import_directory(
        bytes: &[u8],
        pe_off: usize,
        opt_off: usize,
        result: &mut TemplateResult,
    ) {
        // Sanity-check the optional header lies inside the PE image past the
        // NT signature at `pe_off`.
        debug_assert!(opt_off >= pe_off + 24);
        // Data directory entry 1 (import table) is at opt_off + 104 (PE32) or +120 (PE32+).
        let magic = read_u16_le(bytes, opt_off).unwrap_or(0);
        let import_dir_off = if magic == 0x020B {
            opt_off + 120
        } else {
            opt_off + 104
        };
        let import_rva = read_u32_le(bytes, import_dir_off).unwrap_or(0);
        let import_size = read_u32_le(bytes, import_dir_off + 4).unwrap_or(0);
        if import_rva == 0 || import_size == 0 {
            return;
        }
        // We emit a stub field indicating the RVA/size, anchored to `pe_off`
        // for cross-referencing against the NT headers.
        result.fields.push(TemplateField::leaf(
            "ImportDirectory",
            import_dir_off,
            8,
            format!("RVA=0x{import_rva:08X} Size={import_size} (pe_off=0x{pe_off:08X})"),
            Color::OFFSET,
        ));
    }

    fn parse_export_directory(
        bytes: &[u8],
        pe_off: usize,
        opt_off: usize,
        result: &mut TemplateResult,
    ) {
        debug_assert!(opt_off >= pe_off + 24);
        let magic = read_u16_le(bytes, opt_off).unwrap_or(0);
        let export_dir_off = if magic == 0x020B {
            opt_off + 112
        } else {
            opt_off + 96
        };
        let export_rva = read_u32_le(bytes, export_dir_off).unwrap_or(0);
        let export_size = read_u32_le(bytes, export_dir_off + 4).unwrap_or(0);
        if export_rva == 0 || export_size == 0 {
            return;
        }
        result.fields.push(TemplateField::leaf(
            "ExportDirectory",
            export_dir_off,
            8,
            format!("RVA=0x{export_rva:08X} Size={export_size}"),
            Color::OFFSET,
        ));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ELF Template
// ─────────────────────────────────────────────────────────────────────────────

/// ELF 32-bit and 64-bit template: ELF header + section headers + program headers.
pub struct ElfTemplate;

impl ElfTemplate {
    /// Apply the ELF template.  `is_64` selects 64-bit vs 32-bit mode.
    #[must_use]
    pub fn apply(bytes: &[u8], is_64: bool) -> TemplateResult {
        let template = if is_64 {
            BuiltinTemplate::Elf64
        } else {
            BuiltinTemplate::Elf32
        };
        let mut result = TemplateResult::new(template);

        let hdr_size: usize = if is_64 { 64 } else { 52 };
        if bytes.len() < hdr_size {
            result
                .warnings
                .push("file too small for ELF header".to_string());
            return result;
        }

        // ELF header
        Self::parse_elf_header(bytes, is_64, &mut result);

        // Program headers
        let (phoff, phentsize, phnum): (u64, usize, usize) = if is_64 {
            (
                read_u64_le(bytes, 32, 8).unwrap_or(0),
                read_u16_le(bytes, 54).unwrap_or(56) as usize,
                read_u16_le(bytes, 56).unwrap_or(0) as usize,
            )
        } else {
            (
                u64::from(read_u32_le(bytes, 28).unwrap_or(0)),
                read_u16_le(bytes, 42).unwrap_or(32) as usize,
                read_u16_le(bytes, 44).unwrap_or(0) as usize,
            )
        };
        Self::parse_program_headers(bytes, is_64, phoff as usize, phentsize, phnum, &mut result);

        // Section headers
        let (shoff, shentsize, shnum): (u64, usize, usize) = if is_64 {
            (
                read_u64_le(bytes, 40, 8).unwrap_or(0),
                read_u16_le(bytes, 58).unwrap_or(64) as usize,
                read_u16_le(bytes, 60).unwrap_or(0) as usize,
            )
        } else {
            (
                u64::from(read_u32_le(bytes, 32).unwrap_or(0)),
                read_u16_le(bytes, 46).unwrap_or(40) as usize,
                read_u16_le(bytes, 48).unwrap_or(0) as usize,
            )
        };
        Self::parse_section_headers(bytes, is_64, shoff as usize, shentsize, shnum, &mut result);

        result.unparsed_offset = hdr_size;
        result
    }

    fn parse_elf_header(bytes: &[u8], is_64: bool, result: &mut TemplateResult) {
        let ei_class = bytes.get(4).copied().unwrap_or(0);
        let ei_data = bytes.get(5).copied().unwrap_or(0);
        let e_type = read_u16_le(bytes, 16).unwrap_or(0);
        let e_machine = read_u16_le(bytes, 18).unwrap_or(0);

        let type_name = match e_type {
            0 => "ET_NONE",
            1 => "ET_REL",
            2 => "ET_EXEC",
            3 => "ET_DYN",
            4 => "ET_CORE",
            _ => "Unknown",
        };
        let machine_name = match e_machine {
            0x03 => "x86",
            0x3E => "x86-64",
            0x28 => "ARM",
            0xB7 => "AArch64",
            0xF3 => "RISC-V",
            _ => "Unknown",
        };

        let hdr_size: usize = if is_64 { 64 } else { 52 };
        let children = vec![
            TemplateField::leaf("e_ident", 0, 16, hex_bytes(bytes, 0, 16), Color::MAGIC),
            TemplateField::leaf(
                "e_ident[EI_CLASS]",
                4,
                1,
                format!(
                    "{ei_class} ({})",
                    if is_64 { "ELFCLASS64" } else { "ELFCLASS32" }
                ),
                Color::DATA,
            ),
            TemplateField::leaf(
                "e_ident[EI_DATA]",
                5,
                1,
                format!("{ei_data} ({})", if ei_data == 1 { "LSB" } else { "MSB" }),
                Color::DATA,
            ),
            TemplateField::leaf(
                "e_type",
                16,
                2,
                format!("0x{e_type:04X} ({type_name})"),
                Color::HEADER,
            ),
            TemplateField::leaf(
                "e_machine",
                18,
                2,
                format!("0x{e_machine:04X} ({machine_name})"),
                Color::HEADER,
            ),
            TemplateField::leaf(
                "e_version",
                20,
                4,
                read_u32_le(bytes, 20).unwrap_or(0).to_string(),
                Color::DATA,
            ),
            TemplateField::leaf(
                "e_entry",
                24,
                if is_64 { 8 } else { 4 },
                format!(
                    "0x{:X}",
                    read_u64_le(bytes, 24, if is_64 { 8 } else { 4 }).unwrap_or(0)
                ),
                Color::OFFSET,
            ),
        ];

        result.fields.push(TemplateField::group(
            if is_64 { "ELF64Header" } else { "ELF32Header" },
            0,
            hdr_size,
            Color::HEADER,
            children,
        ));
    }

    fn parse_program_headers(
        bytes: &[u8],
        is_64: bool,
        off: usize,
        entsize: usize,
        count: usize,
        result: &mut TemplateResult,
    ) {
        for i in 0..count.min(32) {
            let ph_off = off + i * entsize;
            if ph_off + entsize > bytes.len() {
                break;
            }
            let p_type = read_u32_le(bytes, ph_off).unwrap_or(0);
            let type_name = match p_type {
                0 => "PT_NULL",
                1 => "PT_LOAD",
                2 => "PT_DYNAMIC",
                3 => "PT_INTERP",
                4 => "PT_NOTE",
                6 => "PT_PHDR",
                _ => "PT_OTHER",
            };
            let p_offset = if is_64 {
                read_u64_le(bytes, ph_off + 8, 8).unwrap_or(0)
            } else {
                u64::from(read_u32_le(bytes, ph_off + 4).unwrap_or(0))
            };
            let p_vaddr = if is_64 {
                read_u64_le(bytes, ph_off + 16, 8).unwrap_or(0)
            } else {
                u64::from(read_u32_le(bytes, ph_off + 8).unwrap_or(0))
            };
            let p_filesz = if is_64 {
                read_u64_le(bytes, ph_off + 32, 8).unwrap_or(0)
            } else {
                u64::from(read_u32_le(bytes, ph_off + 16).unwrap_or(0))
            };
            let p_flags = if is_64 {
                read_u32_le(bytes, ph_off + 4).unwrap_or(0)
            } else {
                read_u32_le(bytes, ph_off + 24).unwrap_or(0)
            };

            let children = vec![
                TemplateField::leaf(
                    "p_type",
                    ph_off,
                    4,
                    format!("0x{p_type:08X} ({type_name})"),
                    Color::HEADER,
                ),
                TemplateField::leaf(
                    "p_flags",
                    if is_64 { ph_off + 4 } else { ph_off + 24 },
                    4,
                    format!("0x{p_flags:08X}"),
                    Color::FLAGS,
                ),
                TemplateField::leaf(
                    "p_offset",
                    if is_64 { ph_off + 8 } else { ph_off + 4 },
                    if is_64 { 8 } else { 4 },
                    format!("0x{p_offset:X}"),
                    Color::OFFSET,
                ),
                TemplateField::leaf(
                    "p_vaddr",
                    if is_64 { ph_off + 16 } else { ph_off + 8 },
                    if is_64 { 8 } else { 4 },
                    format!("0x{p_vaddr:X}"),
                    Color::OFFSET,
                ),
                TemplateField::leaf(
                    "p_filesz",
                    if is_64 { ph_off + 32 } else { ph_off + 16 },
                    if is_64 { 8 } else { 4 },
                    format!("0x{p_filesz:X}"),
                    Color::SIZE,
                ),
            ];
            result.fields.push(TemplateField::group(
                format!("Phdr[{i}] ({type_name})"),
                ph_off,
                entsize,
                Color::DATA,
                children,
            ));
        }
    }

    fn parse_section_headers(
        bytes: &[u8],
        is_64: bool,
        off: usize,
        entsize: usize,
        count: usize,
        result: &mut TemplateResult,
    ) {
        for i in 0..count.min(64) {
            let sh_off = off + i * entsize;
            if sh_off + entsize > bytes.len() {
                break;
            }
            let sh_type = read_u32_le(bytes, sh_off + 4).unwrap_or(0);
            let type_name = match sh_type {
                0 => "SHT_NULL",
                1 => "SHT_PROGBITS",
                2 => "SHT_SYMTAB",
                3 => "SHT_STRTAB",
                4 => "SHT_RELA",
                6 => "SHT_DYNAMIC",
                8 => "SHT_NOBITS",
                9 => "SHT_REL",
                11 => "SHT_DYNSYM",
                _ => "SHT_OTHER",
            };
            let sh_flags = if is_64 {
                read_u64_le(bytes, sh_off + 8, 8).unwrap_or(0)
            } else {
                u64::from(read_u32_le(bytes, sh_off + 8).unwrap_or(0))
            };
            let sh_addr = if is_64 {
                read_u64_le(bytes, sh_off + 16, 8).unwrap_or(0)
            } else {
                u64::from(read_u32_le(bytes, sh_off + 12).unwrap_or(0))
            };
            let sh_size = if is_64 {
                read_u64_le(bytes, sh_off + 32, 8).unwrap_or(0)
            } else {
                u64::from(read_u32_le(bytes, sh_off + 20).unwrap_or(0))
            };

            let children = vec![
                TemplateField::leaf(
                    "sh_name",
                    sh_off,
                    4,
                    format!("0x{:08X}", read_u32_le(bytes, sh_off).unwrap_or(0)),
                    Color::STRING,
                ),
                TemplateField::leaf(
                    "sh_type",
                    sh_off + 4,
                    4,
                    format!("0x{sh_type:08X} ({type_name})"),
                    Color::HEADER,
                ),
                TemplateField::leaf(
                    "sh_flags",
                    sh_off + 8,
                    if is_64 { 8 } else { 4 },
                    format!("0x{sh_flags:X}"),
                    Color::FLAGS,
                ),
                TemplateField::leaf(
                    "sh_addr",
                    sh_off + if is_64 { 16 } else { 12 },
                    if is_64 { 8 } else { 4 },
                    format!("0x{sh_addr:X}"),
                    Color::OFFSET,
                ),
                TemplateField::leaf(
                    "sh_size",
                    sh_off + if is_64 { 32 } else { 20 },
                    if is_64 { 8 } else { 4 },
                    format!("0x{sh_size:X}"),
                    Color::SIZE,
                ),
            ];
            result.fields.push(TemplateField::group(
                format!("Shdr[{i}] ({type_name})"),
                sh_off,
                entsize,
                Color::DATA,
                children,
            ));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ZIP Template
// ─────────────────────────────────────────────────────────────────────────────

/// ZIP archive template: local file headers + central directory + EOCD.
pub struct ZipTemplate;

impl ZipTemplate {
    #[must_use]
    pub fn apply(bytes: &[u8]) -> TemplateResult {
        let mut result = TemplateResult::new(BuiltinTemplate::Zip);
        let mut off = 0usize;

        while off + 4 <= bytes.len() {
            let sig = read_u32_le(bytes, off).unwrap_or(0);
            match sig {
                0x04034B50 => {
                    // Local file header
                    if off + 30 > bytes.len() {
                        break;
                    }
                    let fname_len = read_u16_le(bytes, off + 26).unwrap_or(0) as usize;
                    let extra_len = read_u16_le(bytes, off + 28).unwrap_or(0) as usize;
                    let comp_sz = read_u32_le(bytes, off + 18).unwrap_or(0) as usize;
                    let uncomp_sz = read_u32_le(bytes, off + 22).unwrap_or(0);
                    let method = read_u16_le(bytes, off + 8).unwrap_or(0);
                    let method_name = match method {
                        0 => "Stored",
                        8 => "Deflate",
                        _ => "Other",
                    };

                    let fname_off = off + 30;
                    let fname = ascii_str(bytes, fname_off, fname_len);
                    let total = 30 + fname_len + extra_len + comp_sz;

                    let children = vec![
                        TemplateField::leaf(
                            "Signature",
                            off,
                            4,
                            "PK\\x03\\x04".to_string(),
                            Color::MAGIC,
                        ),
                        TemplateField::leaf(
                            "VersionNeeded",
                            off + 4,
                            2,
                            read_u16_le(bytes, off + 4).unwrap_or(0).to_string(),
                            Color::DATA,
                        ),
                        TemplateField::leaf(
                            "GeneralPurposeBitFlag",
                            off + 6,
                            2,
                            format!("0x{:04X}", read_u16_le(bytes, off + 6).unwrap_or(0)),
                            Color::FLAGS,
                        ),
                        TemplateField::leaf(
                            "CompressionMethod",
                            off + 8,
                            2,
                            format!("{method} ({method_name})"),
                            Color::DATA,
                        ),
                        TemplateField::leaf(
                            "CompressedSize",
                            off + 18,
                            4,
                            comp_sz.to_string(),
                            Color::SIZE,
                        ),
                        TemplateField::leaf(
                            "UncompressedSize",
                            off + 22,
                            4,
                            uncomp_sz.to_string(),
                            Color::SIZE,
                        ),
                        TemplateField::leaf(
                            "FileNameLength",
                            off + 26,
                            2,
                            fname_len.to_string(),
                            Color::SIZE,
                        ),
                        TemplateField::leaf(
                            "FileName",
                            fname_off,
                            fname_len.min(bytes.len() - fname_off),
                            fname.clone(),
                            Color::STRING,
                        ),
                    ];
                    result.fields.push(TemplateField::group(
                        format!("LocalFileHeader ({fname})"),
                        off,
                        total.min(bytes.len() - off),
                        Color::HEADER,
                        children,
                    ));
                    off += total;
                }
                0x02014B50 => {
                    // Central directory file header
                    if off + 46 > bytes.len() {
                        break;
                    }
                    let fname_len = read_u16_le(bytes, off + 28).unwrap_or(0) as usize;
                    let extra_len = read_u16_le(bytes, off + 30).unwrap_or(0) as usize;
                    let comment_len = read_u16_le(bytes, off + 32).unwrap_or(0) as usize;
                    let fname = ascii_str(bytes, off + 46, fname_len);
                    let total = 46 + fname_len + extra_len + comment_len;
                    result.fields.push(TemplateField::leaf(
                        format!("CentralDirectoryEntry ({fname})"),
                        off,
                        total.min(bytes.len() - off),
                        format!("file: {fname}"),
                        Color::DATA,
                    ));
                    off += total;
                }
                0x06054B50 => {
                    // End of central directory
                    let comment_len = read_u16_le(bytes, off + 20).unwrap_or(0) as usize;
                    let total = 22 + comment_len;
                    result.fields.push(TemplateField::leaf(
                        "EndOfCentralDirectory",
                        off,
                        total.min(bytes.len() - off),
                        "EOCD record".to_string(),
                        Color::HEADER,
                    ));
                    off += total;
                    break;
                }
                _ => break,
            }
        }

        result.unparsed_offset = off;
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PNG Template
// ─────────────────────────────────────────────────────────────────────────────

/// PNG image template: signature + chunks (IHDR, IDAT, PLTE, IEND, others).
pub struct PngTemplate;

impl PngTemplate {
    #[must_use]
    pub fn apply(bytes: &[u8]) -> TemplateResult {
        let mut result = TemplateResult::new(BuiltinTemplate::Png);

        if bytes.len() < 8 {
            result
                .warnings
                .push("file too small for PNG signature".to_string());
            return result;
        }

        result.fields.push(TemplateField::leaf(
            "PNGSignature",
            0,
            8,
            hex_bytes(bytes, 0, 8),
            Color::MAGIC,
        ));

        let mut off = 8usize;
        while off + 12 <= bytes.len() {
            let length = read_u32_be(bytes, off).unwrap_or(0) as usize;
            let type_bytes = &bytes[off + 4..off + 8];
            let chunk_type = ascii_str(bytes, off + 4, 4);
            // Critical chunks have an uppercase first letter (bit 5 of byte 0 = 0).
            let is_critical = type_bytes[0].is_ascii_uppercase();
            let data_off = off + 8;
            let crc_off = data_off + length;
            let total = 12 + length;

            if crc_off + 4 > bytes.len() {
                result
                    .warnings
                    .push(format!("chunk {chunk_type} data exceeds file size"));
                break;
            }

            let mut children = vec![
                TemplateField::leaf("Length", off, 4, length.to_string(), Color::SIZE),
                TemplateField::leaf(
                    "Type",
                    off + 4,
                    4,
                    format!(
                        "{} ({})",
                        chunk_type,
                        if is_critical { "critical" } else { "ancillary" }
                    ),
                    Color::HEADER,
                ),
            ];

            // Parse IHDR fields
            if chunk_type == "IHDR" && length >= 13 {
                let width = read_u32_be(bytes, data_off).unwrap_or(0);
                let height = read_u32_be(bytes, data_off + 4).unwrap_or(0);
                let bit_depth = read_u8(bytes, data_off + 8).unwrap_or(0);
                let color_type = read_u8(bytes, data_off + 9).unwrap_or(0);
                let color_name = match color_type {
                    0 => "Grayscale",
                    2 => "RGB",
                    3 => "Indexed",
                    4 => "Grayscale+Alpha",
                    6 => "RGBA",
                    _ => "Unknown",
                };
                children.push(TemplateField::leaf(
                    "Width",
                    data_off,
                    4,
                    width.to_string(),
                    Color::DATA,
                ));
                children.push(TemplateField::leaf(
                    "Height",
                    data_off + 4,
                    4,
                    height.to_string(),
                    Color::DATA,
                ));
                children.push(TemplateField::leaf(
                    "BitDepth",
                    data_off + 8,
                    1,
                    bit_depth.to_string(),
                    Color::DATA,
                ));
                children.push(TemplateField::leaf(
                    "ColorType",
                    data_off + 9,
                    1,
                    format!("{color_type} ({color_name})"),
                    Color::DATA,
                ));
                children.push(TemplateField::leaf(
                    "CompressionMethod",
                    data_off + 10,
                    1,
                    read_u8(bytes, data_off + 10).unwrap_or(0).to_string(),
                    Color::DATA,
                ));
                children.push(TemplateField::leaf(
                    "FilterMethod",
                    data_off + 11,
                    1,
                    read_u8(bytes, data_off + 11).unwrap_or(0).to_string(),
                    Color::DATA,
                ));
                children.push(TemplateField::leaf(
                    "InterlaceMethod",
                    data_off + 12,
                    1,
                    read_u8(bytes, data_off + 12).unwrap_or(0).to_string(),
                    Color::DATA,
                ));
            } else if length > 0 {
                children.push(TemplateField::leaf(
                    "Data",
                    data_off,
                    length,
                    format!("{length} bytes"),
                    Color::DATA,
                ));
            }
            children.push(TemplateField::leaf(
                "CRC",
                crc_off,
                4,
                format!("0x{:08X}", read_u32_be(bytes, crc_off).unwrap_or(0)),
                Color::DATA,
            ));

            result.fields.push(TemplateField::group(
                format!("Chunk_{chunk_type}"),
                off,
                total,
                Color::if_true(
                    chunk_type == "IHDR" || chunk_type == "IEND",
                    Color::HEADER,
                    Color::DATA,
                ),
                children,
            ));
            off += total;
            if chunk_type == "IEND" {
                break;
            }
        }

        result.unparsed_offset = off;
        result
    }
}

// Helper for conditional color selection
impl Color {
    const fn if_true(cond: bool, a: Color, b: Color) -> Color {
        if cond { a } else { b }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JPEG Template
// ─────────────────────────────────────────────────────────────────────────────

/// JPEG image template: SOI marker + APP0/JFIF/EXIF + marker segments.
pub struct JpegTemplate;

impl JpegTemplate {
    #[must_use]
    pub fn apply(bytes: &[u8]) -> TemplateResult {
        let mut result = TemplateResult::new(BuiltinTemplate::Jpeg);
        if bytes.len() < 2 {
            result.warnings.push("file too small for JPEG".to_string());
            return result;
        }

        // SOI
        result.fields.push(TemplateField::leaf(
            "SOI",
            0,
            2,
            "\\xFF\\xD8".to_string(),
            Color::MAGIC,
        ));
        let mut off = 2usize;

        while off + 2 <= bytes.len() {
            if bytes[off] != 0xFF {
                break;
            }
            let marker = bytes[off + 1];
            if marker == 0xD9 {
                result.fields.push(TemplateField::leaf(
                    "EOI",
                    off,
                    2,
                    "\\xFF\\xD9".to_string(),
                    Color::MAGIC,
                ));
                off += 2;
                break;
            }
            // Markers with no length (standalone)
            if matches!(marker, 0xD0..=0xD7 | 0x01) {
                result.fields.push(TemplateField::leaf(
                    format!("Marker_{marker:02X}"),
                    off,
                    2,
                    format!("\\xFF\\x{marker:02X}"),
                    Color::HEADER,
                ));
                off += 2;
                continue;
            }
            if off + 4 > bytes.len() {
                break;
            }
            let length = read_u16_be(bytes, off + 2).unwrap_or(0) as usize;
            let total = 2 + length;
            let marker_name = match marker {
                0xE0 => "APP0/JFIF",
                0xE1 => "APP1/EXIF",
                0xDB => "DQT",
                0xC0 | 0xC2 => "SOF",
                0xC4 => "DHT",
                0xDA => "SOS",
                0xFE => "COM",
                _ => "Segment",
            };
            let data_repr = if length > 2 {
                format!("{} bytes", length - 2)
            } else {
                String::new()
            };
            result.fields.push(TemplateField::leaf(
                format!("Marker_{marker:02X}_{marker_name}"),
                off,
                total.min(bytes.len() - off),
                format!("len={length} {data_repr}"),
                Color::HEADER,
            ));
            if off + total > bytes.len() {
                break;
            }
            off += total;
        }

        result.unparsed_offset = off;
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GIF Template
// ─────────────────────────────────────────────────────────────────────────────

/// GIF image template: header + logical screen descriptor + extension blocks + image descriptors.
pub struct GifTemplate;

impl GifTemplate {
    #[must_use]
    pub fn apply(bytes: &[u8]) -> TemplateResult {
        let mut result = TemplateResult::new(BuiltinTemplate::Gif);
        if bytes.len() < 13 {
            result
                .warnings
                .push("file too small for GIF header".to_string());
            return result;
        }

        let version = ascii_str(bytes, 0, 6);
        if version != "GIF87a" && version != "GIF89a" {
            result
                .warnings
                .push(format!("unexpected GIF version signature: {version}"));
        }
        let width = read_u16_le(bytes, 6).unwrap_or(0);
        let height = read_u16_le(bytes, 8).unwrap_or(0);
        let packed = bytes[10];
        let has_gct = (packed >> 7) & 1;
        let gct_size = 1usize << ((packed & 0x07) + 1);
        let bg_idx = bytes[11];
        let aspect = bytes[12];

        let header_children = vec![
            TemplateField::leaf("Signature", 0, 3, ascii_str(bytes, 0, 3), Color::MAGIC),
            TemplateField::leaf("Version", 3, 3, ascii_str(bytes, 3, 3), Color::DATA),
        ];
        result.fields.push(TemplateField::group(
            "Header",
            0,
            6,
            Color::MAGIC,
            header_children,
        ));

        let lsd_children = vec![
            TemplateField::leaf("LogicalScreenWidth", 6, 2, width.to_string(), Color::DATA),
            TemplateField::leaf("LogicalScreenHeight", 8, 2, height.to_string(), Color::DATA),
            TemplateField::leaf(
                "PackedField",
                10,
                1,
                format!("0x{packed:02X}"),
                Color::FLAGS,
            ),
            TemplateField::leaf(
                "BackgroundColorIndex",
                11,
                1,
                bg_idx.to_string(),
                Color::DATA,
            ),
            TemplateField::leaf("PixelAspectRatio", 12, 1, aspect.to_string(), Color::DATA),
        ];
        result.fields.push(TemplateField::group(
            "LogicalScreenDescriptor",
            6,
            7,
            Color::HEADER,
            lsd_children,
        ));

        let mut off = 13usize;

        // Global color table
        if has_gct != 0 {
            let gct_bytes = gct_size * 3;
            if off + gct_bytes <= bytes.len() {
                result.fields.push(TemplateField::leaf(
                    "GlobalColorTable",
                    off,
                    gct_bytes,
                    format!("{gct_size} entries"),
                    Color::DATA,
                ));
                off += gct_bytes;
            }
        }

        // Blocks
        while off < bytes.len() {
            match bytes[off] {
                0x2C => {
                    // Image descriptor
                    if off + 10 > bytes.len() {
                        break;
                    }
                    let left = read_u16_le(bytes, off + 1).unwrap_or(0);
                    let top = read_u16_le(bytes, off + 3).unwrap_or(0);
                    let w = read_u16_le(bytes, off + 5).unwrap_or(0);
                    let h = read_u16_le(bytes, off + 7).unwrap_or(0);
                    result.fields.push(TemplateField::leaf(
                        "ImageDescriptor",
                        off,
                        10,
                        format!("{}x{} at ({},{})", w, h, left, top),
                        Color::HEADER,
                    ));
                    off += 10;
                    // Skip LCT + sub-blocks
                    break; // simplified
                }
                0x21 => {
                    // Extension
                    if off + 2 > bytes.len() {
                        break;
                    }
                    let ext_label = bytes[off + 1];
                    let ext_name = match ext_label {
                        0xF9 => "GraphicControl",
                        0xFE => "Comment",
                        0x01 => "PlainText",
                        0xFF => "Application",
                        _ => "Unknown",
                    };
                    result.fields.push(TemplateField::leaf(
                        format!("Extension_{ext_label:02X}_{ext_name}"),
                        off,
                        2,
                        ext_name.to_string(),
                        Color::DATA,
                    ));
                    off += 2;
                    // Skip sub-blocks
                    while off < bytes.len() {
                        let sub_len = bytes[off] as usize;
                        off += 1 + sub_len;
                        if sub_len == 0 {
                            break;
                        }
                    }
                }
                0x3B => {
                    result.fields.push(TemplateField::leaf(
                        "Trailer",
                        off,
                        1,
                        "GIF trailer".to_string(),
                        Color::MAGIC,
                    ));
                    off += 1;
                    break;
                }
                _ => break,
            }
        }

        result.unparsed_offset = off;
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MP4 / ISO BMFF Template
// ─────────────────────────────────────────────────────────────────────────────

/// MP4 / ISO BMFF container template: iterates top-level boxes.
pub struct Mp4Template;

impl Mp4Template {
    #[must_use]
    pub fn apply(bytes: &[u8]) -> TemplateResult {
        let mut result = TemplateResult::new(BuiltinTemplate::Mp4);
        let mut off = 0usize;
        let mut depth = 0usize;

        while off + 8 <= bytes.len() && depth < 512 {
            let size = read_u32_be(bytes, off).unwrap_or(0);
            let box_type = ascii_str(bytes, off + 4, 4);

            let actual_size: usize = if size == 0 {
                bytes.len() - off
            } else if size == 1 {
                // 64-bit size
                if off + 16 > bytes.len() {
                    break;
                }
                read_u64_le(bytes, off + 8, 8).unwrap_or(0) as usize
            } else {
                size as usize
            };

            if actual_size < 8 {
                break;
            }

            let children = vec![
                TemplateField::leaf("Size", off, 4, size.to_string(), Color::SIZE),
                TemplateField::leaf("Type", off + 4, 4, box_type.clone(), Color::HEADER),
            ];

            // Parse ftyp box
            let group_children = if box_type == "ftyp" && actual_size >= 16 {
                let brand = ascii_str(bytes, off + 8, 4);
                let version = read_u32_be(bytes, off + 12).unwrap_or(0);
                let mut ch = children;
                ch.push(TemplateField::leaf(
                    "MajorBrand",
                    off + 8,
                    4,
                    brand,
                    Color::DATA,
                ));
                ch.push(TemplateField::leaf(
                    "MinorVersion",
                    off + 12,
                    4,
                    version.to_string(),
                    Color::DATA,
                ));
                ch
            } else {
                children
            };

            result.fields.push(TemplateField::group(
                format!("Box_{box_type}"),
                off,
                actual_size.min(bytes.len() - off),
                Color::HEADER,
                group_children,
            ));

            off += actual_size;
            depth += 1;
        }

        result.unparsed_offset = off;
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PDF Template
// ─────────────────────────────────────────────────────────────────────────────

/// PDF document template: header magic + a scan for `obj ... endobj` and `xref`.
pub struct PdfTemplate;

impl PdfTemplate {
    #[must_use]
    pub fn apply(bytes: &[u8]) -> TemplateResult {
        let mut result = TemplateResult::new(BuiltinTemplate::Pdf);
        if bytes.len() < 8 {
            result.warnings.push("file too small for PDF".to_string());
            return result;
        }

        // PDF header
        result.fields.push(TemplateField::leaf(
            "PDFMagic",
            0,
            4,
            "%PDF".to_string(),
            Color::MAGIC,
        ));
        result.fields.push(TemplateField::leaf(
            "PDFVersion",
            4,
            4,
            ascii_str(bytes, 4, 4),
            Color::DATA,
        ));

        // Scan for %%EOF
        if let Some(eof_pos) = Self::find_sequence(bytes, b"%%EOF") {
            result.fields.push(TemplateField::leaf(
                "EOF",
                eof_pos,
                5,
                "%%EOF".to_string(),
                Color::MAGIC,
            ));
        }

        // Scan for xref
        if let Some(xref_pos) = Self::find_sequence(bytes, b"xref") {
            result.fields.push(TemplateField::leaf(
                "XRefTable",
                xref_pos,
                4,
                "xref".to_string(),
                Color::OFFSET,
            ));
        }

        // Scan for startxref
        if let Some(sxref_pos) = Self::find_sequence(bytes, b"startxref") {
            result.fields.push(TemplateField::leaf(
                "StartXRef",
                sxref_pos,
                9,
                "startxref".to_string(),
                Color::OFFSET,
            ));
        }

        result.unparsed_offset = bytes.len();
        result
    }

    fn find_sequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GZIP Template
// ─────────────────────────────────────────────────────────────────────────────

/// GZIP compressed file template.
pub struct GzipTemplate;

impl GzipTemplate {
    #[must_use]
    pub fn apply(bytes: &[u8]) -> TemplateResult {
        let mut result = TemplateResult::new(BuiltinTemplate::Gzip);
        if bytes.len() < 18 {
            result
                .warnings
                .push("file too small for GZIP header".to_string());
            return result;
        }

        let id1 = bytes[0];
        let id2 = bytes[1];
        let cm = bytes[2];
        let flg = bytes[3];
        let mtime = read_u32_le(bytes, 4).unwrap_or(0);
        let xfl = bytes[8];
        let os = bytes[9];

        let os_name = match os {
            0 => "FAT filesystem",
            3 => "Unix",
            7 => "Macintosh",
            11 => "NTFS",
            255 => "Unknown",
            _ => "Other",
        };

        let mut children = vec![
            TemplateField::leaf("ID1", 0, 1, format!("0x{id1:02X}"), Color::MAGIC),
            TemplateField::leaf("ID2", 1, 1, format!("0x{id2:02X}"), Color::MAGIC),
            TemplateField::leaf(
                "CM",
                2,
                1,
                format!("{cm} ({})", if cm == 8 { "deflate" } else { "unknown" }),
                Color::DATA,
            ),
            TemplateField::leaf("FLG", 3, 1, format!("0x{flg:02X}"), Color::FLAGS),
            TemplateField::leaf("MTIME", 4, 4, format!("0x{mtime:08X}"), Color::DATA),
            TemplateField::leaf("XFL", 8, 1, format!("0x{xfl:02X}"), Color::DATA),
            TemplateField::leaf("OS", 9, 1, format!("{os} ({os_name})"), Color::DATA),
        ];

        let mut off = 10usize;

        // FEXTRA
        if flg & 0x04 != 0 && off + 2 <= bytes.len() {
            let xlen = read_u16_le(bytes, off).unwrap_or(0) as usize;
            children.push(TemplateField::leaf(
                "FEXTRA",
                off,
                2 + xlen,
                format!("{xlen} bytes"),
                Color::DATA,
            ));
            off += 2 + xlen;
        }

        // FNAME (null-terminated)
        if flg & 0x08 != 0 {
            let start = off;
            while off < bytes.len() && bytes[off] != 0 {
                off += 1;
            }
            let fname = ascii_str(bytes, start, off - start);
            children.push(TemplateField::leaf(
                "FNAME",
                start,
                off - start + 1,
                fname,
                Color::STRING,
            ));
            off += 1; // null
        }

        // FCOMMENT
        if flg & 0x10 != 0 {
            let start = off;
            while off < bytes.len() && bytes[off] != 0 {
                off += 1;
            }
            children.push(TemplateField::leaf(
                "FCOMMENT",
                start,
                off - start + 1,
                "<comment>".to_string(),
                Color::STRING,
            ));
            off += 1;
        }

        // FHCRC
        if flg & 0x02 != 0 && off + 2 <= bytes.len() {
            children.push(TemplateField::leaf(
                "FHCRC",
                off,
                2,
                format!("0x{:04X}", read_u16_le(bytes, off).unwrap_or(0)),
                Color::DATA,
            ));
            off += 2;
        }

        result.fields.push(TemplateField::group(
            "GZIPHeader",
            0,
            off,
            Color::HEADER,
            children,
        ));

        // Trailer (CRC32 + ISIZE, last 8 bytes)
        if bytes.len() >= 8 {
            let trail_off = bytes.len() - 8;
            let crc32 = read_u32_le(bytes, trail_off).unwrap_or(0);
            let isize = read_u32_le(bytes, trail_off + 4).unwrap_or(0);
            result.fields.push(TemplateField::group(
                "GZIPTrailer",
                trail_off,
                8,
                Color::HEADER,
                vec![
                    TemplateField::leaf(
                        "CRC32",
                        trail_off,
                        4,
                        format!("0x{crc32:08X}"),
                        Color::DATA,
                    ),
                    TemplateField::leaf("ISIZE", trail_off + 4, 4, isize.to_string(), Color::SIZE),
                ],
            ));
        }

        result.unparsed_offset = bytes.len();
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BuiltinTemplateRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// A registry mapping display names to [`BuiltinTemplate`] variants.
#[derive(Debug, Default)]
pub struct BuiltinTemplateRegistry {
    map: HashMap<&'static str, BuiltinTemplate>,
}

impl BuiltinTemplateRegistry {
    /// Create a registry containing all built-in templates.
    #[must_use]
    pub fn new() -> Self {
        let mut map = HashMap::new();
        for &t in BuiltinTemplate::ALL {
            map.insert(t.display_name(), t);
        }
        Self { map }
    }

    /// Look up a template by display name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<BuiltinTemplate> {
        self.map.get(name).copied()
    }

    /// All template display names.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = self.map.keys().copied().collect();
        names.sort_unstable();
        names
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── BuiltinTemplate::detect ───────────────────────────────────────────────

    #[test]
    fn test_detect_pe() {
        let mut data = vec![0u8; 64];
        data[0] = b'M';
        data[1] = b'Z';
        assert_eq!(BuiltinTemplate::detect(&data), Some(BuiltinTemplate::Pe));
    }

    #[test]
    fn test_detect_elf32() {
        let data = b"\x7FELF\x01\x01\x01\0\0\0\0\0\0\0\0\0";
        assert_eq!(BuiltinTemplate::detect(data), Some(BuiltinTemplate::Elf32));
    }

    #[test]
    fn test_detect_elf64() {
        let data = b"\x7FELF\x02\x01\x01\0\0\0\0\0\0\0\0\0";
        assert_eq!(BuiltinTemplate::detect(data), Some(BuiltinTemplate::Elf64));
    }

    #[test]
    fn test_detect_zip() {
        let data = b"PK\x03\x04\0\0\0\0";
        assert_eq!(BuiltinTemplate::detect(data), Some(BuiltinTemplate::Zip));
    }

    #[test]
    fn test_detect_png() {
        let data = b"\x89PNG\r\n\x1A\nXXXXXXXX";
        assert_eq!(BuiltinTemplate::detect(data), Some(BuiltinTemplate::Png));
    }

    #[test]
    fn test_detect_jpeg() {
        let data = b"\xFF\xD8\xFF\xE0\0\0\0\0";
        assert_eq!(BuiltinTemplate::detect(data), Some(BuiltinTemplate::Jpeg));
    }

    #[test]
    fn test_detect_gif() {
        let data = b"GIF89a\0\0\0\0\0\0";
        assert_eq!(BuiltinTemplate::detect(data), Some(BuiltinTemplate::Gif));
    }

    #[test]
    fn test_detect_pdf() {
        let data = b"%PDF-1.4 xxxx";
        assert_eq!(BuiltinTemplate::detect(data), Some(BuiltinTemplate::Pdf));
    }

    #[test]
    fn test_detect_gzip() {
        let data = b"\x1F\x8B\x08\0\0\0\0\0";
        assert_eq!(BuiltinTemplate::detect(data), Some(BuiltinTemplate::Gzip));
    }

    #[test]
    fn test_detect_none() {
        let data = b"\x00\x01\x02\x03";
        assert_eq!(BuiltinTemplate::detect(data), None);
    }

    // ── Color ────────────────────────────────────────────────────────────────

    #[test]
    fn test_color_rgb() {
        let c = Color::rgb(0xFF, 0x00, 0x80);
        assert_eq!(c.r, 0xFF);
        assert_eq!(c.g, 0x00);
        assert_eq!(c.b, 0x80);
        assert_eq!(c.a, 255);
    }

    // ── TemplateField ────────────────────────────────────────────────────────

    #[test]
    fn test_template_field_leaf_is_not_group() {
        let f = TemplateField::leaf("x", 0, 4, "0x1234".to_string(), Color::DATA);
        assert!(!f.is_group());
        assert_eq!(f.end_offset(), 4);
    }

    #[test]
    fn test_template_field_group() {
        let child = TemplateField::leaf("c", 0, 2, "val".to_string(), Color::DATA);
        let g = TemplateField::group("g", 0, 4, Color::HEADER, vec![child]);
        assert!(g.is_group());
        assert_eq!(g.children.len(), 1);
    }

    // ── TemplateResult helpers ────────────────────────────────────────────────

    #[test]
    fn test_result_find_field() {
        let mut result = TemplateResult::new(BuiltinTemplate::Pdf);
        result.fields.push(TemplateField::leaf(
            "Magic",
            0,
            4,
            "%PDF".to_string(),
            Color::MAGIC,
        ));
        assert!(result.find_field("Magic").is_some());
        assert!(result.find_field("Missing").is_none());
    }

    #[test]
    fn test_result_total_field_count() {
        let mut result = TemplateResult::new(BuiltinTemplate::Pdf);
        let child = TemplateField::leaf("c", 0, 1, "x".to_string(), Color::DATA);
        result
            .fields
            .push(TemplateField::group("g", 0, 1, Color::HEADER, vec![child]));
        assert_eq!(result.total_field_count(), 2);
    }

    // ── PE template ───────────────────────────────────────────────────────────

    #[test]
    fn test_pe_apply_minimal_mz() {
        let mut data = vec![0u8; 256];
        data[0] = b'M';
        data[1] = b'Z';
        data[60] = 0x80; // e_lfanew = 0x80
        let result = BuiltinTemplate::Pe.apply(&data);
        assert!(!result.fields.is_empty());
        assert!(result.find_field("DOSHeader").is_some());
    }

    #[test]
    fn test_pe_warnings_on_small_file() {
        let data = vec![b'M', b'Z'];
        let result = BuiltinTemplate::Pe.apply(&data);
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_pe_full_header() {
        let mut data = vec![0u8; 512];
        data[0] = b'M';
        data[1] = b'Z';
        data[60] = 0x40; // e_lfanew = 0x40
        // PE signature
        data[0x40] = b'P';
        data[0x41] = b'E';
        data[0x42] = 0;
        data[0x43] = 0;
        // COFF: machine=0x8664, sections=2
        data[0x44] = 0x64;
        data[0x45] = 0x86;
        data[0x46] = 0x02;
        data[0x47] = 0x00;
        let result = BuiltinTemplate::Pe.apply(&data);
        assert!(result.find_field("PESignature").is_some());
        assert!(result.find_field("COFFHeader").is_some());
    }

    // ── ELF32 template ────────────────────────────────────────────────────────

    #[test]
    fn test_elf32_minimal() {
        let mut data = vec![0u8; 52];
        data[0] = 0x7F;
        data[1] = b'E';
        data[2] = b'L';
        data[3] = b'F';
        data[4] = 1; // ELFCLASS32
        data[5] = 1; // ELFDATA2LSB
        let result = BuiltinTemplate::Elf32.apply(&data);
        assert!(result.find_field("ELF32Header").is_some());
    }

    #[test]
    fn test_elf64_minimal() {
        let mut data = vec![0u8; 64];
        data[0] = 0x7F;
        data[1] = b'E';
        data[2] = b'L';
        data[3] = b'F';
        data[4] = 2; // ELFCLASS64
        let result = BuiltinTemplate::Elf64.apply(&data);
        assert!(result.find_field("ELF64Header").is_some());
    }

    #[test]
    fn test_elf_too_small() {
        let data = vec![0x7F, b'E', b'L', b'F'];
        let result = BuiltinTemplate::Elf32.apply(&data);
        assert!(!result.warnings.is_empty());
    }

    // ── ZIP template ──────────────────────────────────────────────────────────

    #[test]
    fn test_zip_local_header() {
        let mut data = vec![0u8; 64];
        data[0] = 0x50;
        data[1] = 0x4B;
        data[2] = 0x03;
        data[3] = 0x04;
        data[26] = 4; // filename length
        data[30] = b't';
        data[31] = b'e';
        data[32] = b's';
        data[33] = b't';
        let result = BuiltinTemplate::Zip.apply(&data);
        assert!(!result.fields.is_empty());
    }

    #[test]
    fn test_zip_eocd() {
        let mut data = vec![0u8; 32];
        data[0] = 0x50;
        data[1] = 0x4B;
        data[2] = 0x05;
        data[3] = 0x06;
        let result = BuiltinTemplate::Zip.apply(&data);
        let has_eocd = result
            .fields
            .iter()
            .any(|f| f.name.contains("EndOfCentralDirectory"));
        assert!(has_eocd);
    }

    // ── PNG template ──────────────────────────────────────────────────────────

    #[test]
    fn test_png_signature() {
        let data = b"\x89PNG\r\n\x1A\n\0\0\0\rIHDR\0\0\0\x01\0\0\0\x01\x08\x02\0\0\0\x90wS\xDE";
        let result = BuiltinTemplate::Png.apply(data);
        assert!(result.find_field("PNGSignature").is_some());
    }

    #[test]
    fn test_png_too_small() {
        let data = b"\x89PNG";
        let result = BuiltinTemplate::Png.apply(data);
        assert!(!result.warnings.is_empty());
    }

    // ── JPEG template ─────────────────────────────────────────────────────────

    #[test]
    fn test_jpeg_soi() {
        let data = b"\xFF\xD8\xFF\xE0\0\x10JFIF\0\x01\x01\0\0\x01\0\x01\0\0";
        let result = BuiltinTemplate::Jpeg.apply(data);
        assert!(result.find_field("SOI").is_some());
    }

    // ── GIF template ──────────────────────────────────────────────────────────

    #[test]
    fn test_gif_header() {
        let mut data = vec![0u8; 32];
        data[0..6].copy_from_slice(b"GIF89a");
        data[6] = 10; // width=10
        data[8] = 8; // height=8
        let result = BuiltinTemplate::Gif.apply(&data);
        assert!(result.find_field("Header").is_some());
        assert!(result.find_field("LogicalScreenDescriptor").is_some());
    }

    // ── GZIP template ─────────────────────────────────────────────────────────

    #[test]
    fn test_gzip_header() {
        let mut data = vec![0u8; 20];
        data[0] = 0x1F;
        data[1] = 0x8B;
        data[2] = 8; // CM = deflate
        data[3] = 0; // FLG = none
        data[9] = 3; // OS = Unix
        let result = BuiltinTemplate::Gzip.apply(&data);
        assert!(result.find_field("GZIPHeader").is_some());
    }

    #[test]
    fn test_gzip_too_small() {
        let data = vec![0x1F, 0x8B];
        let result = BuiltinTemplate::Gzip.apply(&data);
        assert!(!result.warnings.is_empty());
    }

    // ── PDF template ──────────────────────────────────────────────────────────

    #[test]
    fn test_pdf_magic() {
        let data = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<</Type/Catalog>>\nendobj\n%%EOF\n";
        let result = BuiltinTemplate::Pdf.apply(data);
        assert!(result.find_field("PDFMagic").is_some());
    }

    // ── MP4 template ──────────────────────────────────────────────────────────

    #[test]
    fn test_mp4_ftyp_box() {
        // ftyp box: size=0x18, type='ftyp', brand='mp42', version=0, compat=['isom']
        let mut data = vec![0u8; 32];
        data[0] = 0;
        data[1] = 0;
        data[2] = 0;
        data[3] = 0x18;
        data[4] = b'f';
        data[5] = b't';
        data[6] = b'y';
        data[7] = b'p';
        data[8] = b'm';
        data[9] = b'p';
        data[10] = b'4';
        data[11] = b'2';
        let result = BuiltinTemplate::Mp4.apply(&data);
        let has_ftyp = result.fields.iter().any(|f| f.name.contains("ftyp"));
        assert!(has_ftyp);
    }

    // ── BuiltinTemplateRegistry ───────────────────────────────────────────────

    #[test]
    fn test_registry_contains_all() {
        let reg = BuiltinTemplateRegistry::new();
        for &t in BuiltinTemplate::ALL {
            assert!(
                reg.get(t.display_name()).is_some(),
                "missing: {}",
                t.display_name()
            );
        }
    }

    #[test]
    fn test_registry_names_sorted() {
        let reg = BuiltinTemplateRegistry::new();
        let names = reg.names();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    // ── Display names ─────────────────────────────────────────────────────────

    #[test]
    fn test_display_names_nonempty() {
        for &t in BuiltinTemplate::ALL {
            assert!(!t.display_name().is_empty());
        }
    }

    #[test]
    fn test_all_templates_apply_on_empty() {
        // All templates should not panic on empty input.
        for &t in BuiltinTemplate::ALL {
            let result = t.apply(&[]);
            // Should produce warnings or empty fields, not panic.
            let _ = result.total_field_count();
        }
    }

    #[test]
    fn test_elf32_with_program_headers() {
        let mut data = vec![0u8; 256];
        data[0] = 0x7F;
        data[1] = b'E';
        data[2] = b'L';
        data[3] = b'F';
        data[4] = 1;
        data[5] = 1;
        // e_phoff=52, e_phentsize=32, e_phnum=1
        let phoff: u32 = 52;
        data[28..32].copy_from_slice(&phoff.to_le_bytes());
        data[42..44].copy_from_slice(&32u16.to_le_bytes()); // phentsize
        data[44..46].copy_from_slice(&1u16.to_le_bytes()); // phnum
        let result = BuiltinTemplate::Elf32.apply(&data);
        let has_phdr = result.fields.iter().any(|f| f.name.contains("Phdr"));
        assert!(has_phdr);
    }

    #[test]
    fn test_field_u64_read() {
        let mut result = TemplateResult::new(BuiltinTemplate::Gzip);
        result.fields.push(TemplateField::leaf(
            "val",
            0,
            4,
            "0x42".to_string(),
            Color::DATA,
        ));
        let bytes = 0x12345678u32.to_le_bytes();
        let v = result.field_u64("val", &bytes);
        assert_eq!(v, Some(0x12345678));
    }
}
