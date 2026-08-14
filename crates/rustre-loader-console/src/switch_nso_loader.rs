//! Nintendo Switch NSO Loader.
//!
//! Parses the NSO0 binary format used by Nintendo Switch executables, handles
//! LZ4-compressed segments, the MOD0 header embedded in the text segment, and
//! the ELF-like `.dynamic` section for symbol table resolution.

use std::fmt;

/// Upper bound on how much memory a single LZ4 pre-allocation may reserve.
///
/// The declared decompressed size comes straight from the file header, so it
/// is never trusted for the initial reservation; anything larger simply grows
/// as the decompressor produces real bytes.
const MAX_LZ4_PREALLOC: usize = 1 << 20; // 1 MiB


// ─── Constants ────────────────────────────────────────────────────────────────

/// NSO magic bytes "NSO0".
pub const NSO_MAGIC: [u8; 4] = [b'N', b'S', b'O', b'0'];

/// NSO header is 0x100 bytes.
pub const NSO_HEADER_SIZE: usize = 0x100;

/// MOD0 magic bytes "MOD0".
pub const MOD0_MAGIC: [u8; 4] = [b'M', b'O', b'D', b'0'];

/// MOD0 header size (minimal structure).
pub const MOD0_HEADER_SIZE: usize = 0x1C;

/// Segment index: text (0), rodata (1), data (2).
pub const SEG_TEXT: usize = 0;
pub const SEG_RODATA: usize = 1;
pub const SEG_DATA: usize = 2;

/// LZ4 frame magic (little-endian).
pub const LZ4_FRAME_MAGIC: u32 = 0x184D_2204;

/// LZ4 legacy frame magic.
pub const LZ4_LEGACY_MAGIC: u32 = 0x184C_2102;

/// `DT_NULL` terminator tag.
pub const DT_NULL: u64 = 0;
/// `DT_NEEDED` tag.
pub const DT_NEEDED: u64 = 1;
/// `DT_PLTRELSZ` tag.
pub const DT_PLTRELSZ: u64 = 2;
/// `DT_PLTGOT` tag.
pub const DT_PLTGOT: u64 = 3;
/// `DT_SYMTAB` tag.
pub const DT_SYMTAB: u64 = 6;
/// `DT_STRTAB` tag.
pub const DT_STRTAB: u64 = 5;
/// `DT_STRSZ` tag.
pub const DT_STRSZ: u64 = 10;
/// `DT_SYMENT` tag.
pub const DT_SYMENT: u64 = 11;
/// `DT_RELA` tag.
pub const DT_RELA: u64 = 7;
/// `DT_RELASZ` tag.
pub const DT_RELASZ: u64 = 8;
/// `DT_RELAENT` tag.
pub const DT_RELAENT: u64 = 9;
/// `DT_JMPREL` tag.
pub const DT_JMPREL: u64 = 23;
/// `DT_REL` tag.
pub const DT_REL: u64 = 17;
/// `DT_RELSZ` tag.
pub const DT_RELSZ: u64 = 18;
/// `DT_RELENT` tag.
pub const DT_RELENT: u64 = 19;

// ─── NsoSegment ───────────────────────────────────────────────────────────────

/// One of the three segments in an NSO binary (text, rodata, data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsoSegment {
    /// File offset of the (possibly compressed) segment data.
    pub file_offset: u32,
    /// Virtual memory offset (relative to load base).
    pub mem_offset: u32,
    /// Decompressed (in-memory) size in bytes.
    pub decompressed_size: u32,
    /// Segment name for display purposes.
    pub name: &'static str,
    /// Whether this segment is compressed with LZ4.
    pub compressed: bool,
    /// Compressed file size (0 if uncompressed).
    pub file_size: u32,
}

impl NsoSegment {
    /// Returns `true` if this segment should be mapped as executable.
    #[must_use]
    pub fn is_exec(&self) -> bool {
        self.name == "text"
    }

    /// Returns `true` if this segment should be mapped as writable.
    #[must_use]
    pub fn is_write(&self) -> bool {
        self.name == "data"
    }

    /// Returns the end virtual address of this segment (relative to load base).
    #[must_use]
    pub const fn mem_end(&self) -> u32 {
        self.mem_offset.wrapping_add(self.decompressed_size)
    }
}

impl fmt::Display for NsoSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            ".{} mem={:#010x}+{:#x} file_off={:#010x}{}",
            self.name,
            self.mem_offset,
            self.decompressed_size,
            self.file_offset,
            if self.compressed { " [LZ4]" } else { "" },
        )
    }
}

// ─── NsoHeader ────────────────────────────────────────────────────────────────

/// Parsed NSO0 file header (0x100 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsoHeader {
    /// Magic "NSO0".
    pub magic: [u8; 4],
    /// Format version (always 0).
    pub version: u32,
    /// Reserved field (always 0 in known builds).
    pub reserved: u32,
    /// Flags: bits 0–2 indicate whether text/rodata/data are LZ4-compressed.
    pub flags: u32,
    /// Text segment descriptor.
    pub text_seg: NsoSegment,
    /// Module name offset (within memory image, relative to base).
    pub module_name_offset: u32,
    /// Rodata segment descriptor.
    pub rodata_seg: NsoSegment,
    /// Module name size in bytes.
    pub module_name_size: u32,
    /// Data segment descriptor.
    pub data_seg: NsoSegment,
    /// BSS size in bytes.
    pub bss_size: u32,
    /// Module ID (build ID) — 32 bytes.
    pub module_id: [u8; 32],
    /// Compressed text file size (0 if uncompressed).
    pub text_file_size: u32,
    /// Compressed rodata file size (0 if uncompressed).
    pub rodata_file_size: u32,
    /// Compressed data file size (0 if uncompressed).
    pub data_file_size: u32,
    /// Rodata embedded NRO offset (reserved; 0 in typical NSOs).
    pub rodata_nro_offset: u32,
    /// Rodata embedded NRO size (reserved).
    pub rodata_nro_size: u32,
    /// SHA-256 hash of text segment (decompressed).
    pub text_hash: [u8; 32],
    /// SHA-256 hash of rodata segment (decompressed).
    pub rodata_hash: [u8; 32],
    /// SHA-256 hash of data segment (decompressed).
    pub data_hash: [u8; 32],
}

impl NsoHeader {
    /// Parse a 0x100-byte NSO header from `data`.
    ///
    /// # Errors
    /// Returns an error string if data is too short or magic does not match.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < NSO_HEADER_SIZE {
            return Err(format!(
                "NSO data too short: {} < {NSO_HEADER_SIZE}",
                data.len()
            ));
        }
        if data[..4] != NSO_MAGIC {
            return Err("invalid NSO magic".to_string());
        }
        let version = u32_le(data, 4);
        let reserved = u32_le(data, 8);
        let flags = u32_le(data, 0xC);

        let text_file_off = u32_le(data, 0x10);
        let text_mem_off  = u32_le(data, 0x14);
        let text_decomp   = u32_le(data, 0x18);
        let module_name_offset = u32_le(data, 0x1C);

        let rodata_file_off = u32_le(data, 0x20);
        let rodata_mem_off  = u32_le(data, 0x24);
        let rodata_decomp   = u32_le(data, 0x28);
        let module_name_size = u32_le(data, 0x2C);

        let data_file_off = u32_le(data, 0x30);
        let data_mem_off  = u32_le(data, 0x34);
        let data_decomp   = u32_le(data, 0x38);
        let bss_size      = u32_le(data, 0x3C);

        let mut module_id = [0u8; 32];
        module_id.copy_from_slice(&data[0x40..0x60]);

        let text_file_size   = u32_le(data, 0x60);
        let rodata_file_size = u32_le(data, 0x64);
        let data_file_size   = u32_le(data, 0x68);

        let rodata_nro_offset = u32_le(data, 0x6C);
        let rodata_nro_size   = u32_le(data, 0x70);

        let text_compressed   = (flags & (1 << SEG_TEXT))   != 0;
        let rodata_compressed = (flags & (1 << SEG_RODATA)) != 0;
        let data_compressed   = (flags & (1 << SEG_DATA))   != 0;

        let text_seg = NsoSegment {
            file_offset: text_file_off,
            mem_offset: text_mem_off,
            decompressed_size: text_decomp,
            name: "text",
            compressed: text_compressed,
            file_size: text_file_size,
        };
        let rodata_seg = NsoSegment {
            file_offset: rodata_file_off,
            mem_offset: rodata_mem_off,
            decompressed_size: rodata_decomp,
            name: "rodata",
            compressed: rodata_compressed,
            file_size: rodata_file_size,
        };
        let data_seg = NsoSegment {
            file_offset: data_file_off,
            mem_offset: data_mem_off,
            decompressed_size: data_decomp,
            name: "data",
            compressed: data_compressed,
            file_size: data_file_size,
        };

        let mut text_hash   = [0u8; 32];
        let mut rodata_hash = [0u8; 32];
        let mut data_hash   = [0u8; 32];
        text_hash.copy_from_slice(&data[0xA0..0xC0]);
        rodata_hash.copy_from_slice(&data[0xC0..0xE0]);
        data_hash.copy_from_slice(&data[0xE0..0x100]);

        Ok(Self {
            magic: NSO_MAGIC,
            version,
            reserved,
            flags,
            text_seg,
            module_name_offset,
            rodata_seg,
            module_name_size,
            data_seg,
            bss_size,
            module_id,
            text_file_size,
            rodata_file_size,
            data_file_size,
            rodata_nro_offset,
            rodata_nro_size,
            text_hash,
            rodata_hash,
            data_hash,
        })
    }

    /// Returns `true` if any segment is LZ4-compressed.
    #[must_use]
    pub const fn has_compressed_segments(&self) -> bool {
        self.text_seg.compressed || self.rodata_seg.compressed || self.data_seg.compressed
    }

    /// Module ID as a lowercase hex string.
    #[must_use]
    pub fn module_id_hex(&self) -> String {
        self.module_id.iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }
}

impl fmt::Display for NsoHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NSO0 v{} flags={:#06x} id={} bss={:#x}",
            self.version,
            self.flags,
            &self.module_id_hex()[..16],
            self.bss_size,
        )
    }
}

// ─── LZ4 decompression ────────────────────────────────────────────────────────

/// Decompress an LZ4 block-format stream into `out`.
///
/// Nintendo Switch NSO segments use the raw LZ4 block format (no frame header).
/// Returns the number of bytes written to `out`.
///
/// # Errors
/// Returns an error string if the compressed data is malformed.
pub fn lz4_decompress_block(src: &[u8], out: &mut Vec<u8>, max_out: usize) -> Result<usize, String> {
    let mut sp = 0usize; // source position
    let start_len = out.len();

    while sp < src.len() {
        if out.len() - start_len >= max_out {
            break;
        }

        let token = *src.get(sp).ok_or("LZ4: unexpected end of input at token")?;
        sp += 1;

        // Literal length from high nibble.
        let mut lit_len = (token >> 4) as usize;
        if lit_len == 15 {
            loop {
                let extra = *src.get(sp).ok_or("LZ4: unexpected end reading literal length")?;
                sp += 1;
                lit_len += extra as usize;
                if extra != 255 {
                    break;
                }
            }
        }

        // Copy literal bytes.
        if sp + lit_len > src.len() {
            return Err(format!(
                "LZ4: literal overflow sp={sp} lit_len={lit_len} src_len={}",
                src.len()
            ));
        }
        out.extend_from_slice(&src[sp..sp + lit_len]);
        sp += lit_len;

        if sp >= src.len() {
            // End of stream after final literals.
            break;
        }

        // Match copy.
        let offset_lo = *src.get(sp).ok_or("LZ4: missing match offset lo")?;
        let offset_hi = *src.get(sp + 1).ok_or("LZ4: missing match offset hi")?;
        sp += 2;
        let match_offset = u16::from_le_bytes([offset_lo, offset_hi]) as usize;
        if match_offset == 0 {
            return Err("LZ4: zero match offset".to_string());
        }

        let mut match_len = (token & 0xF) as usize + 4;
        if match_len - 4 == 15 {
            loop {
                let extra = *src.get(sp).ok_or("LZ4: unexpected end reading match length")?;
                sp += 1;
                match_len += extra as usize;
                if extra != 255 {
                    break;
                }
            }
        }

        let cur_len = out.len();
        if match_offset > cur_len {
            return Err(format!(
                "LZ4: match offset {match_offset} > output len {cur_len}"
            ));
        }
        let copy_start = cur_len - match_offset;
        // Copy byte-by-byte to handle overlapping matches correctly.
        for i in 0..match_len {
            let b = out[copy_start + (i % match_offset)];
            out.push(b);
            if out.len() - start_len >= max_out {
                break;
            }
        }
    }

    Ok(out.len() - start_len)
}

/// Decompress an NSO segment.
///
/// If `seg.compressed` is true, runs LZ4 block decompression.
/// Otherwise, copies the raw bytes directly.
///
/// # Errors
/// Returns an error string if decompression fails or file data is truncated.
pub fn decompress_segment(data: &[u8], seg: &NsoSegment) -> Result<Vec<u8>, String> {
    let off = seg.file_offset as usize;
    let file_sz = if seg.compressed && seg.file_size > 0 {
        seg.file_size as usize
    } else {
        seg.decompressed_size as usize
    };
    if off + file_sz > data.len() {
        return Err(format!(
            "segment {} data extends past EOF (off={off} file_sz={file_sz} file_len={})",
            seg.name,
            data.len()
        ));
    }
    let seg_data = &data[off..off + file_sz];
    if seg.compressed {
        // Bound the pre-allocation driven by the header's decompressed_size;
        // the Vec still grows to whatever the decompressor really emits.
        let mut out =
            Vec::with_capacity((seg.decompressed_size as usize).min(MAX_LZ4_PREALLOC));
        lz4_decompress_block(seg_data, &mut out, seg.decompressed_size as usize)?;
        if out.len() < seg.decompressed_size as usize {
            out.resize(seg.decompressed_size as usize, 0);
        }
        Ok(out)
    } else {
        let mut out = seg_data.to_vec();
        out.resize(seg.decompressed_size as usize, 0);
        Ok(out)
    }
}

// ─── Mod0Header ───────────────────────────────────────────────────────────────

/// The MOD0 header embedded in the text segment of an NSO/NRO.
///
/// Pointed to by a relative pointer at text+4 (the instruction at offset 4 in
/// the text segment is `b #imm`, where imm points to the MOD0 structure).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mod0Header {
    /// Offset from the start of the text segment to this MOD0 structure.
    pub mod0_offset: u32,
    /// Offset from MOD0 to the start of .dynamic section.
    pub dynamic_offset: i32,
    /// Offset from MOD0 to BSS start.
    pub bss_start_offset: i32,
    /// Offset from MOD0 to BSS end.
    pub bss_end_offset: i32,
    /// Offset from MOD0 to EH frame header start.
    pub eh_frame_hdr_start: i32,
    /// Offset from MOD0 to EH frame header end.
    pub eh_frame_hdr_end: i32,
    /// Offset from MOD0 to the module object (runtime link map).
    pub module_object_offset: i32,
}

impl Mod0Header {
    /// Parse the MOD0 header from `text_seg` at a given `offset`.
    ///
    /// `text_base` is the virtual address of the text segment start.
    ///
    /// # Errors
    /// Returns an error if the data is too short or magic is wrong.
    pub fn parse(text_seg: &[u8], offset: usize) -> Result<Self, String> {
        if offset + MOD0_HEADER_SIZE > text_seg.len() {
            return Err(format!(
                "MOD0 at {offset:#x} extends past text segment end ({})",
                text_seg.len()
            ));
        }
        let d = &text_seg[offset..];
        if &d[..4] != MOD0_MAGIC.as_ref() {
            return Err(format!(
                "invalid MOD0 magic at {offset:#x}: {:02x}{:02x}{:02x}{:02x}",
                d[0], d[1], d[2], d[3]
            ));
        }
        let dynamic_offset      = i32::from_le_bytes([d[4],  d[5],  d[6],  d[7]]);
        let bss_start_offset    = i32::from_le_bytes([d[8],  d[9],  d[10], d[11]]);
        let bss_end_offset      = i32::from_le_bytes([d[12], d[13], d[14], d[15]]);
        let eh_frame_hdr_start  = i32::from_le_bytes([d[16], d[17], d[18], d[19]]);
        let eh_frame_hdr_end    = i32::from_le_bytes([d[20], d[21], d[22], d[23]]);
        let module_object_offset = if d.len() >= 28 {
            i32::from_le_bytes([d[24], d[25], d[26], d[27]])
        } else {
            0
        };

        Ok(Self {
            mod0_offset: u32::try_from(offset).unwrap_or(u32::MAX),
            dynamic_offset,
            bss_start_offset,
            bss_end_offset,
            eh_frame_hdr_start,
            eh_frame_hdr_end,
            module_object_offset,
        })
    }

    /// Virtual address of the .dynamic section (relative to text base `text_va`).
    #[must_use]
    pub const fn dynamic_va(&self, text_va: u64) -> u64 {
        // u64::from / i64::from not stable in const; lossless casts: u32→u64, i32→i64
        let mod0_va = text_va + self.mod0_offset as u64;
        (mod0_va.cast_signed() + self.dynamic_offset as i64).cast_unsigned()
    }

    /// Virtual address of BSS start.
    #[must_use]
    pub const fn bss_start_va(&self, text_va: u64) -> u64 {
        let mod0_va = text_va + self.mod0_offset as u64;
        (mod0_va.cast_signed() + self.bss_start_offset as i64).cast_unsigned()
    }

    /// BSS size in bytes.
    #[must_use]
    pub const fn bss_size(&self) -> u64 {
        let start = self.bss_start_offset as i64;
        let end = self.bss_end_offset as i64;
        if end > start { (end - start).cast_unsigned() } else { 0 }
    }
}

// ─── NxDynamic ────────────────────────────────────────────────────────────────

/// A single entry from the ELF `.dynamic` section of an NSO binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NxDynamic {
    /// Dynamic tag (DT_* constant).
    pub tag: u64,
    /// Tag value (address or integer depending on tag type).
    pub value: u64,
}

impl NxDynamic {
    /// Parse all dynamic entries from a byte slice.
    ///
    /// Each entry is 16 bytes (`AArch64`: 8-byte tag + 8-byte value).
    /// Parsing stops at `DT_NULL`.
    #[must_use]
    pub fn parse_all(data: &[u8]) -> Vec<Self> {
        let mut entries = Vec::new();
        let mut off = 0usize;
        while off + 16 <= data.len() {
            let tag = u64::from_le_bytes([
                data[off],     data[off + 1], data[off + 2], data[off + 3],
                data[off + 4], data[off + 5], data[off + 6], data[off + 7],
            ]);
            let value = u64::from_le_bytes([
                data[off + 8],  data[off + 9],  data[off + 10], data[off + 11],
                data[off + 12], data[off + 13], data[off + 14], data[off + 15],
            ]);
            if tag == DT_NULL {
                break;
            }
            entries.push(Self { tag, value });
            off += 16;
        }
        entries
    }

    /// Look up the first entry with the given tag.
    #[must_use]
    pub fn find(entries: &[Self], tag: u64) -> Option<u64> {
        entries.iter().find(|e| e.tag == tag).map(|e| e.value)
    }
}

// ─── NsoSymbol ────────────────────────────────────────────────────────────────

/// A symbol extracted from the NSO dynamic symbol table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsoSymbol {
    /// Symbol name.
    pub name: String,
    /// Virtual address (`st_value`).
    pub address: u64,
    /// Symbol size.
    pub size: u64,
    /// Symbol type (ELF `st_info` low nibble).
    pub sym_type: u8,
    /// Symbol binding (ELF `st_info` high nibble).
    pub binding: u8,
    /// Section index.
    pub shndx: u16,
}

impl NsoSymbol {
    /// Returns `true` if this symbol is a function.
    #[must_use]
    pub const fn is_function(&self) -> bool {
        self.sym_type == 2
    }

    /// Returns `true` if this is a global or weak symbol.
    #[must_use]
    pub const fn is_exported(&self) -> bool {
        self.binding == 1 || self.binding == 2
    }
}

// ─── NsoLoader ────────────────────────────────────────────────────────────────

/// The primary Nintendo Switch NSO loader.
///
/// Decompresses segments, finds the MOD0 header, parses the dynamic section,
/// and builds a symbol table.
#[derive(Debug)]
pub struct NsoLoader {
    /// Parsed NSO file header.
    pub header: NsoHeader,
    /// Decompressed text segment bytes.
    pub text: Vec<u8>,
    /// Decompressed rodata segment bytes.
    pub rodata: Vec<u8>,
    /// Decompressed data segment bytes.
    pub data: Vec<u8>,
    /// MOD0 header, if found in the text segment.
    pub mod0: Option<Mod0Header>,
    /// Dynamic entries from the `.dynamic` section.
    pub dynamic: Vec<NxDynamic>,
    /// Symbols extracted from the dynamic symbol table.
    pub symbols: Vec<NsoSymbol>,
    /// Virtual base address of the loaded image (usually 0 for position-independent).
    pub base_va: u64,
    /// Module name, if retrievable.
    pub module_name: String,
}

impl NsoLoader {
    /// Load an NSO binary from `data` at virtual base `base_va`.
    ///
    /// # Errors
    /// Returns an error string on parse failure or decompression error.
    pub fn load(data: &[u8], base_va: u64) -> Result<Self, String> {
        let header = NsoHeader::parse(data)?;

        let text   = decompress_segment(data, &header.text_seg)?;
        let ro_seg = decompress_segment(data, &header.rodata_seg)?;
        let data_seg = decompress_segment(data, &header.data_seg)?;

        // Find the MOD0 header.
        // The branch instruction at text+4 encodes the offset to MOD0.
        let mod0 = if text.len() >= 8 {
            find_mod0_in_text(&text)
        } else {
            None
        };

        // Build an in-memory image for dynamic resolution.
        // Layout: text at base_va, rodata after, data after.
        let text_va   = base_va + u64::from(header.text_seg.mem_offset);
        let rodata_va = base_va + u64::from(header.rodata_seg.mem_offset);
        let data_va   = base_va + u64::from(header.data_seg.mem_offset);

        // Build a flat image map: va → slice for lookups.
        let segments: &[(&[u8], u64)] = &[
            (&text, text_va),
            (&ro_seg, rodata_va),
            (&data_seg, data_va),
        ];

        // Locate .dynamic using MOD0.
        let dynamic_va = mod0.as_ref().map(|m| m.dynamic_va(text_va));
        let dynamic = dynamic_va.map_or_else(Vec::new, |dyn_va| {
            read_segment_bytes(segments, dyn_va, 16 * 64)
                .map(NxDynamic::parse_all)
                .unwrap_or_default()
        });

        // Parse symbol table.
        let symbols = parse_dynsym(segments, &dynamic, base_va);

        // Retrieve module name from dynamic section or header.
        let module_name = resolve_module_name(
            &header,
            segments,
            rodata_va,
        );

        Ok(Self {
            header,
            text,
            rodata: ro_seg,
            data: data_seg,
            mod0,
            dynamic,
            symbols,
            base_va,
            module_name,
        })
    }

    /// Entry point virtual address.
    #[must_use]
    pub const fn entry_point(&self) -> u64 {
        // u64::from not stable in const context; u32→u64 cast is lossless
        self.base_va + self.header.text_seg.mem_offset as u64
    }

    /// Returns all function symbols sorted by address.
    #[must_use]
    pub fn functions(&self) -> Vec<&NsoSymbol> {
        let mut fns: Vec<&NsoSymbol> = self.symbols.iter().filter(|s| s.is_function()).collect();
        fns.sort_by_key(|s| s.address);
        fns
    }

    /// Total in-memory size of the image (text + rodata + data + bss).
    #[must_use]
    pub const fn total_image_size(&self) -> u64 {
        // u64::from not stable in const context; u32→u64 casts are lossless
        self.header.data_seg.mem_offset as u64
            + self.header.data_seg.decompressed_size as u64
            + self.header.bss_size as u64
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "NSO \"{}\" base={:#018x} text={:#x} rodata={:#x} data={:#x} syms={}",
            self.module_name,
            self.base_va,
            self.header.text_seg.decompressed_size,
            self.header.rodata_seg.decompressed_size,
            self.header.data_seg.decompressed_size,
            self.symbols.len(),
        )
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Read a little-endian u32 from `data` at `offset`.
#[inline]
fn u32_le(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]])
}

/// Search for the MOD0 magic in the text segment using the branch at offset 4.
fn find_mod0_in_text(text: &[u8]) -> Option<Mod0Header> {
    // The branch instruction at text[4] is: B #(imm26 * 4) from PC.
    // AArch64 B encoding: bits[31:26]=000101, bits[25:0]=imm26 (signed).
    if text.len() < 8 {
        return None;
    }
    let instr = u32::from_le_bytes([text[4], text[5], text[6], text[7]]);
    // Check B opcode: bits[31:26] == 0b000101.
    if (instr >> 26) != 0b00_0101 {
        // Fall back: scan for "MOD0" magic in first 0x1000 bytes.
        let scan_end = text.len().min(0x1000);
        for i in (0..scan_end.saturating_sub(4)).step_by(4) {
            if &text[i..i + 4] == MOD0_MAGIC.as_ref() {
                return Mod0Header::parse(text, i).ok();
            }
        }
        return None;
    }
    let imm26 = instr & 0x03FF_FFFF;
    // Sign-extend 26-bit offset.
    let offset_instr = if imm26 & 0x0200_0000 != 0 {
        (imm26 | 0xFC00_0000).cast_signed()
    } else {
        imm26.cast_signed()
    };
    // Branch destination relative to the instruction at offset 4.
    let mod0_off = usize::try_from((4i32).wrapping_add(offset_instr * 4)).unwrap_or(0);
    Mod0Header::parse(text, mod0_off).ok()
}

/// Look up a virtual address in the segment map and return a byte slice.
fn read_segment_bytes<'a>(
    segments: &[(&'a [u8], u64)],
    va: u64,
    max_len: usize,
) -> Option<&'a [u8]> {
    for &(data, seg_va) in segments {
        if va >= seg_va && va < seg_va + data.len() as u64 {
            let off = usize::try_from(va - seg_va).unwrap_or(usize::MAX);
            let end = (off + max_len).min(data.len());
            return Some(&data[off..end]);
        }
    }
    None
}

/// Parse the ELF64 dynamic symbol table from the `.dynamic` entries.
fn parse_dynsym(segments: &[(&[u8], u64)], dynamic: &[NxDynamic], base_va: u64) -> Vec<NsoSymbol> {
    let symtab_va = NxDynamic::find(dynamic, DT_SYMTAB).unwrap_or(0);
    let strtab_va = NxDynamic::find(dynamic, DT_STRTAB).unwrap_or(0);
    let strsz     = usize::try_from(NxDynamic::find(dynamic, DT_STRSZ).unwrap_or(0)).unwrap_or(usize::MAX);
    let syment    = usize::try_from(NxDynamic::find(dynamic, DT_SYMENT).unwrap_or(24)).unwrap_or(usize::MAX);

    if symtab_va == 0 || strtab_va == 0 || syment < 24 {
        return Vec::new();
    }

    let strtab_bytes = read_segment_bytes(segments, strtab_va, strsz.max(256))
        .unwrap_or(&[]);

    let mut syms = Vec::new();
    let mut sym_va = symtab_va;

    // Scan symbols until we hit an out-of-range address (no symtab size in .dynamic).
    loop {
        let sym_data = match read_segment_bytes(segments, sym_va, syment) {
            Some(d) if d.len() >= 24 => d,
            _ => break,
        };
        // ELF64 Sym: st_name(4), st_info(1), st_other(1), st_shndx(2), st_value(8), st_size(8).
        let st_name  = u32::from_le_bytes([sym_data[0], sym_data[1], sym_data[2], sym_data[3]]);
        let st_info  = sym_data[4];
        let st_shndx = u16::from_le_bytes([sym_data[6], sym_data[7]]);
        let st_value = u64::from_le_bytes([
            sym_data[8],  sym_data[9],  sym_data[10], sym_data[11],
            sym_data[12], sym_data[13], sym_data[14], sym_data[15],
        ]);
        let st_size  = u64::from_le_bytes([
            sym_data[16], sym_data[17], sym_data[18], sym_data[19],
            sym_data[20], sym_data[21], sym_data[22], sym_data[23],
        ]);

        let name_off = st_name as usize;
        let name = if name_off < strtab_bytes.len() {
            let end = strtab_bytes[name_off..]
                .iter()
                .position(|&b| b == 0)
                .map_or(strtab_bytes.len() - name_off, |p| p);
            String::from_utf8_lossy(&strtab_bytes[name_off..name_off + end]).to_string()
        } else {
            String::new()
        };

        // A sym with all zeros and empty name is likely padding; stop there.
        if name.is_empty() && st_value == 0 && !syms.is_empty() {
            break;
        }

        let address = if st_value != 0 && st_shndx != 0 {
            base_va + st_value
        } else {
            st_value
        };

        syms.push(NsoSymbol {
            name,
            address,
            size: st_size,
            sym_type: st_info & 0xF,
            binding: st_info >> 4,
            shndx: st_shndx,
        });

        sym_va += u64::try_from(syment).unwrap_or(u64::MAX);
        if syms.len() > 4096 {
            break; // Safety cap.
        }
    }

    syms
}

/// Try to retrieve the module name from rodata or the NSO header's module name field.
fn resolve_module_name(
    header: &NsoHeader,
    segments: &[(&[u8], u64)],
    rodata_va: u64,
) -> String {
    // The module name is stored at (rodata_va + module_name_offset) as a
    // length-prefixed ASCII string: u32 offset_from_start, u32 name_length, chars.
    let mn_off = header.module_name_offset as usize;
    if let Some(slice) = read_segment_bytes(segments, rodata_va + mn_off as u64, 4 + header.module_name_size as usize)
        && slice.len() >= 8
    {
        let _rel_off = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
        let name_len = u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]) as usize;
        if 8 + name_len <= slice.len() {
            let name_bytes = &slice[8..8 + name_len];
            if let Ok(s) = std::str::from_utf8(name_bytes) && !s.is_empty() {
                return s.trim_end_matches('\0').to_string();
            }
        }
    }
    // Fall back to module ID prefix.
    format!("nso_{}", &header.module_id_hex()[..8])
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_nso() -> Vec<u8> {
        let mut data = vec![0u8; NSO_HEADER_SIZE + 0x1000];
        data[0..4].copy_from_slice(&NSO_MAGIC);
        // flags = 0 (uncompressed)
        // text: file_off=0x100, mem_off=0, decomp=0x200
        data[0x10..0x14].copy_from_slice(&0x100u32.to_le_bytes());
        data[0x14..0x18].copy_from_slice(&0x0000u32.to_le_bytes());
        data[0x18..0x1C].copy_from_slice(&0x200u32.to_le_bytes());
        // rodata: file_off=0x300, mem_off=0x200, decomp=0x100
        data[0x20..0x24].copy_from_slice(&0x300u32.to_le_bytes());
        data[0x24..0x28].copy_from_slice(&0x200u32.to_le_bytes());
        data[0x28..0x2C].copy_from_slice(&0x100u32.to_le_bytes());
        // data: file_off=0x400, mem_off=0x300, decomp=0x100
        data[0x30..0x34].copy_from_slice(&0x400u32.to_le_bytes());
        data[0x34..0x38].copy_from_slice(&0x300u32.to_le_bytes());
        data[0x38..0x3C].copy_from_slice(&0x100u32.to_le_bytes());
        data
    }

    #[test]
    fn test_nso_header_parse() {
        let d = make_minimal_nso();
        let h = NsoHeader::parse(&d).unwrap();
        assert_eq!(h.magic, NSO_MAGIC);
        assert_eq!(h.text_seg.file_offset, 0x100);
        assert_eq!(h.rodata_seg.mem_offset, 0x200);
        assert_eq!(h.data_seg.decompressed_size, 0x100);
        assert!(!h.has_compressed_segments());
    }

    #[test]
    fn test_nso_header_bad_magic() {
        let mut d = make_minimal_nso();
        d[0] = 0xFF;
        assert!(NsoHeader::parse(&d).is_err());
    }

    #[test]
    fn test_lz4_decompress_block_simple() {
        // Build a simple LZ4 block: token=0x20 (2 literals, 0 match extra), then 2 bytes.
        // token high nibble = 2 → 2 literals; low nibble = 0 → 4 match len but no offset bytes follow.
        // Actually to avoid a match, just encode end-of-stream after literals.
        // Minimal: token=0x20, lit0, lit1 (end of stream).
        let src = vec![0x20, b'A', b'B'];
        let mut out = Vec::new();
        lz4_decompress_block(&src, &mut out, 1024).unwrap();
        assert_eq!(&out, b"AB");
    }

    #[test]
    fn test_lz4_decompress_with_match() {
        // Encode "ABCABCABC" using a match copy.
        // Literal "ABC" then match offset=3, match_len=6.
        // token: lit_len=3 (high nibble=3), match_extra = 6-4=2 = (low nibble=2).
        // So token = 0x32
        // Then literal bytes: 'A','B','C'
        // Then offset = 3 (LE u16): 0x03, 0x00
        let src = vec![0x32, b'A', b'B', b'C', 0x03, 0x00];
        let mut out = Vec::new();
        lz4_decompress_block(&src, &mut out, 1024).unwrap();
        assert_eq!(&out, b"ABCABCABC");
    }

    #[test]
    fn test_mod0_parse() {
        let mut text = vec![0u8; 0x40];
        // Place MOD0 at offset 0x08.
        text[0x08..0x0C].copy_from_slice(MOD0_MAGIC.as_ref());
        text[0x0C..0x10].copy_from_slice(&0x1000i32.to_le_bytes()); // dynamic_offset
        text[0x10..0x14].copy_from_slice(&0x2000i32.to_le_bytes()); // bss_start_offset
        text[0x14..0x18].copy_from_slice(&0x3000i32.to_le_bytes()); // bss_end_offset
        text[0x18..0x1C].copy_from_slice(&0i32.to_le_bytes()); // eh_frame_hdr_start
        text[0x1C..0x20].copy_from_slice(&0i32.to_le_bytes()); // eh_frame_hdr_end
        text[0x20..0x24].copy_from_slice(&0i32.to_le_bytes()); // module_object_offset
        let m = Mod0Header::parse(&text, 0x08).unwrap();
        assert_eq!(m.mod0_offset, 0x08);
        assert_eq!(m.dynamic_offset, 0x1000);
        assert_eq!(m.bss_size(), 0x1000);
    }

    #[test]
    fn test_nx_dynamic_parse() {
        let mut data = vec![0u8; 48];
        // Entry 0: DT_SYMTAB=6, value=0x5000
        data[0..8].copy_from_slice(&DT_SYMTAB.to_le_bytes());
        data[8..16].copy_from_slice(&0x5000u64.to_le_bytes());
        // Entry 1: DT_STRTAB=5, value=0x6000
        data[16..24].copy_from_slice(&DT_STRTAB.to_le_bytes());
        data[24..32].copy_from_slice(&0x6000u64.to_le_bytes());
        // Entry 2: DT_NULL
        data[32..40].copy_from_slice(&DT_NULL.to_le_bytes());

        let entries = NxDynamic::parse_all(&data);
        assert_eq!(entries.len(), 2);
        assert_eq!(NxDynamic::find(&entries, DT_SYMTAB), Some(0x5000));
        assert_eq!(NxDynamic::find(&entries, DT_STRTAB), Some(0x6000));
        assert_eq!(NxDynamic::find(&entries, DT_STRSZ), None);
    }

    #[test]
    fn test_nso_segment_display() {
        let seg = NsoSegment {
            file_offset: 0x100,
            mem_offset: 0,
            decompressed_size: 0x400,
            name: "text",
            compressed: true,
            file_size: 0x200,
        };
        let s = seg.to_string();
        assert!(s.contains(".text"));
        assert!(s.contains("[LZ4]"));
    }
}
