//! dyld shared cache extraction: parse `dyld_shared_cache` header, image list,
//! mapping info, extract individual dylibs, fix ASLR slide (rebase),
//! export symbols, dump all dylibs.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ExtractError {
    #[error("invalid dyld_shared_cache magic")]
    BadMagic,
    #[error("buffer too short at offset {0:#x}")]
    UnexpectedEof(usize),
    #[error("image '{0}' not found in cache")]
    ImageNotFound(String),
    #[error("mapping not found for address {0:#x}")]
    MappingNotFound(u64),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type ExtractResult<T> = Result<T, ExtractError>;

// ── Magic strings ─────────────────────────────────────────────────────────────

pub const DYLD_CACHE_MAGIC_ARM64: &[u8] = b"dyld_v1   arm64";
pub const DYLD_CACHE_MAGIC_ARM64E: &[u8] = b"dyld_v1  arm64e";
pub const DYLD_CACHE_MAGIC_X86_64: &[u8] = b"dyld_v1  x86_64";
pub const DYLD_CACHE_MAGIC_X86_64H: &[u8] = b"dyld_v1 x86_64h";
pub const DYLD_CACHE_MAGIC_ARM: &[u8] = b"dyld_v1     armv";

/// Cache architecture, detected from the magic string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheArch {
    Arm64,
    Arm64e,
    X86_64,
    X86_64h,
    Arm,
    Unknown,
}

impl CacheArch {
    #[must_use] 
    pub fn from_magic(magic: &[u8]) -> Self {
        if magic.len() < 15 {
            return Self::Unknown;
        }
        if &magic[..15] == DYLD_CACHE_MAGIC_ARM64 {
            Self::Arm64
        } else if &magic[..15] == DYLD_CACHE_MAGIC_ARM64E {
            Self::Arm64e
        } else if &magic[..15] == DYLD_CACHE_MAGIC_X86_64 {
            Self::X86_64
        } else if &magic[..15] == DYLD_CACHE_MAGIC_X86_64H {
            Self::X86_64h
        } else if magic.starts_with(b"dyld_v1     armv") {
            Self::Arm
        } else {
            Self::Unknown
        }
    }

    #[must_use] 
    pub const fn is_64bit(self) -> bool {
        matches!(self, Self::Arm64 | Self::Arm64e | Self::X86_64 | Self::X86_64h)
    }

    #[must_use] 
    pub const fn pointer_size(self) -> usize {
        if self.is_64bit() { 8 } else { 4 }
    }
}

// ── Parsed header ─────────────────────────────────────────────────────────────

/// Parsed `dyld_cache_header` (common fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedCacheHeader {
    pub magic: String,
    pub arch: CacheArch,
    pub mapping_offset: u32,
    pub mapping_count: u32,
    pub images_offset: u32,
    pub images_count: u32,
    pub dyld_base_address: u64,
    pub code_signature_offset: u64,
    pub code_signature_size: u64,
    pub slide_info_offset_unused: u64,
    pub slide_info_size_unused: u64,
    pub local_symbols_offset: u64,
    pub local_symbols_size: u64,
    pub uuid: [u8; 16],
    pub cache_type: u64,
    pub branch_pools_offset: u32,
    pub branch_pools_count: u32,
    pub dyld_in_cache_offset: u64,
    pub dyld_in_cache_entry: u64,
    pub images_text_offset: u64,
    pub images_text_count: u64,
}

// ── Mapping info ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMapping {
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub max_prot: u32,
    pub init_prot: u32,
}

impl CacheMapping {
    #[must_use] 
    pub const fn contains_address(&self, addr: u64) -> bool {
        addr >= self.address && addr < self.address + self.size
    }

    #[must_use] 
    pub const fn address_to_offset(&self, addr: u64) -> Option<u64> {
        if self.contains_address(addr) {
            Some(self.file_offset + (addr - self.address))
        } else {
            None
        }
    }

    #[must_use] 
    pub const fn is_text(&self) -> bool {
        self.init_prot & 0x4 != 0 // VM_PROT_EXECUTE
    }

    #[must_use] 
    pub const fn is_data(&self) -> bool {
        self.init_prot & 0x2 != 0 // VM_PROT_WRITE
    }
}

// ── Image info ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheImage {
    pub address: u64,
    pub mod_time: u64,
    pub inode: u64,
    pub path_file_offset: u32,
    pub pad: u32,
    pub path: String,
}

impl CacheImage {
    #[must_use] 
    pub fn install_name(&self) -> &str {
        &self.path
    }

    #[must_use] 
    pub fn dylib_name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }
}

// ── Parsed cache ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedCache {
    pub header: SharedCacheHeader,
    pub mappings: Vec<CacheMapping>,
    pub images: Vec<CacheImage>,
    pub slide: u64,
}

impl SharedCache {
    #[must_use] 
    pub fn find_image(&self, name: &str) -> Option<&CacheImage> {
        self.images.iter().find(|img| {
            img.path.contains(name)
                || img.path.ends_with(name)
                || img.dylib_name() == name
        })
    }

    #[must_use] 
    pub fn address_to_file_offset(&self, addr: u64) -> Option<u64> {
        self.mappings.iter().find_map(|m| m.address_to_offset(addr))
    }

    #[must_use] 
    pub fn file_offset_to_data<'a>(&self, data: &'a [u8], offset: u64) -> Option<&'a [u8]> {
        let off = offset as usize;
        if off < data.len() {
            Some(&data[off..])
        } else {
            None
        }
    }

    /// Build an index mapping install name -> image index.
    #[must_use] 
    pub fn install_name_index(&self) -> HashMap<String, usize> {
        self.images
            .iter()
            .enumerate()
            .map(|(i, img)| (img.install_name().to_string(), i))
            .collect()
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

pub struct SharedCacheParser<'a> {
    data: &'a [u8],
}

impl<'a> SharedCacheParser<'a> {
    #[must_use] 
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn read_u32_at(&self, off: usize) -> ExtractResult<u32> {
        if off + 4 > self.data.len() {
            return Err(ExtractError::UnexpectedEof(off));
        }
        Ok(u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap()))
    }

    fn read_u64_at(&self, off: usize) -> ExtractResult<u64> {
        if off + 8 > self.data.len() {
            return Err(ExtractError::UnexpectedEof(off));
        }
        Ok(u64::from_le_bytes(self.data[off..off + 8].try_into().unwrap()))
    }

    fn read_cstr_at(&self, off: usize) -> String {
        if off >= self.data.len() {
            return String::new();
        }
        let end = self.data[off..].iter().position(|&b| b == 0).unwrap_or(self.data.len() - off);
        String::from_utf8_lossy(&self.data[off..off + end]).into_owned()
    }

    pub fn parse_header(&self) -> ExtractResult<SharedCacheHeader> {
        if self.data.len() < 0x100 {
            return Err(ExtractError::BadMagic);
        }

        let magic_bytes = &self.data[..16];
        let arch = CacheArch::from_magic(magic_bytes);
        if arch == CacheArch::Unknown {
            return Err(ExtractError::BadMagic);
        }

        let magic = String::from_utf8_lossy(&self.data[..16]).trim_end_matches('\0').to_owned();

        let mapping_offset = self.read_u32_at(0x10)?;
        let mapping_count = self.read_u32_at(0x14)?;
        let images_offset = self.read_u32_at(0x18)?;
        let images_count = self.read_u32_at(0x1C)?;
        let dyld_base_address = self.read_u64_at(0x20)?;
        let code_signature_offset = self.read_u64_at(0x28)?;
        let code_signature_size = self.read_u64_at(0x30)?;
        let slide_info_offset_unused = self.read_u64_at(0x38)?;
        let slide_info_size_unused = self.read_u64_at(0x40)?;
        let local_symbols_offset = self.read_u64_at(0x48)?;
        let local_symbols_size = self.read_u64_at(0x50)?;

        let mut uuid = [0u8; 16];
        if self.data.len() >= 0x68 {
            uuid.copy_from_slice(&self.data[0x58..0x68]);
        }

        let cache_type = self.read_u64_at(0x68).unwrap_or(0);
        let branch_pools_offset = self.read_u32_at(0x70).unwrap_or(0);
        let branch_pools_count = self.read_u32_at(0x74).unwrap_or(0);
        let dyld_in_cache_offset = self.read_u64_at(0x78).unwrap_or(0);
        let dyld_in_cache_entry = self.read_u64_at(0x80).unwrap_or(0);
        let images_text_offset = self.read_u64_at(0x88).unwrap_or(0);
        let images_text_count = self.read_u64_at(0x90).unwrap_or(0);

        Ok(SharedCacheHeader {
            magic,
            arch,
            mapping_offset,
            mapping_count,
            images_offset,
            images_count,
            dyld_base_address,
            code_signature_offset,
            code_signature_size,
            slide_info_offset_unused,
            slide_info_size_unused,
            local_symbols_offset,
            local_symbols_size,
            uuid,
            cache_type,
            branch_pools_offset,
            branch_pools_count,
            dyld_in_cache_offset,
            dyld_in_cache_entry,
            images_text_offset,
            images_text_count,
        })
    }

    pub fn parse_mappings(&self, header: &SharedCacheHeader) -> ExtractResult<Vec<CacheMapping>> {
        let mut mappings = Vec::new();
        let base = header.mapping_offset as usize;
        // Each mapping_info is 0x28 bytes
        for i in 0..header.mapping_count as usize {
            let off = base + i * 0x28;
            let address = self.read_u64_at(off)?;
            let size = self.read_u64_at(off + 8)?;
            let file_offset = self.read_u64_at(off + 0x10)?;
            let max_prot = self.read_u32_at(off + 0x18)?;
            let init_prot = self.read_u32_at(off + 0x1C)?;
            mappings.push(CacheMapping { address, size, file_offset, max_prot, init_prot });
        }
        Ok(mappings)
    }

    pub fn parse_images(
        &self,
        header: &SharedCacheHeader,
    ) -> ExtractResult<Vec<CacheImage>> {
        let mut images = Vec::new();
        let base = header.images_offset as usize;
        // Each dyld_cache_image_info is 0x20 bytes
        for i in 0..header.images_count as usize {
            let off = base + i * 0x20;
            let address = self.read_u64_at(off)?;
            let mod_time = self.read_u64_at(off + 8)?;
            let inode = self.read_u64_at(off + 0x10)?;
            let path_file_offset = self.read_u32_at(off + 0x18)?;
            let pad = self.read_u32_at(off + 0x1C)?;
            let path = self.read_cstr_at(path_file_offset as usize);
            images.push(CacheImage { address, mod_time, inode, path_file_offset, pad, path });
        }
        Ok(images)
    }

    pub fn parse(&self) -> ExtractResult<SharedCache> {
        let header = self.parse_header()?;
        let mappings = self.parse_mappings(&header)?;
        let images = self.parse_images(&header)?;
        Ok(SharedCache { header, mappings, images, slide: 0 })
    }
}

// ── ASLR slide fixup ──────────────────────────────────────────────────────────

/// Apply a slide to a parsed Mach-O image (rebase all pointers).
/// In a real implementation this would use the slide info to fix up
/// chained fixups or v1–v5 slide info structs. Here we expose the interface.
pub struct SlideApplicator<'a> {
    data: &'a mut Vec<u8>,
    slide: u64,
    text_offset: usize,
    text_size: usize,
}

impl<'a> SlideApplicator<'a> {
    pub const fn new(data: &'a mut Vec<u8>, slide: u64, text_offset: usize, text_size: usize) -> Self {
        Self { data, slide, text_offset, text_size }
    }

    /// Apply slide to all 64-bit pointers in a data section.
    /// Only pointers in the range [`data_start`, `data_end`) are adjusted.
    pub fn apply_slide_to_data_section(&mut self, data_offset: usize, data_size: usize) {
        let end = (data_offset + data_size).min(self.data.len());
        let mut off = data_offset;
        while off + 8 <= end {
            let ptr = u64::from_le_bytes(self.data[off..off + 8].try_into().unwrap());
            // Heuristic: pointers in the range of known load addresses get slid
            if ptr > 0x1000_0000 && ptr < 0xFFFF_FFFF_FFFF {
                let rebased = ptr.wrapping_add(self.slide);
                self.data[off..off + 8].copy_from_slice(&rebased.to_le_bytes());
            }
            off += 8;
        }
    }

    #[must_use] 
    pub const fn slide(&self) -> u64 {
        self.slide
    }

    /// File offset of the TEXT region this applicator was configured for.
    #[must_use] 
    pub const fn text_offset(&self) -> usize {
        self.text_offset
    }

    /// Size of the TEXT region this applicator was configured for.
    #[must_use] 
    pub const fn text_size(&self) -> usize {
        self.text_size
    }

    /// Convenience: returns the (offset, size) range of the TEXT region.
    #[must_use] 
    pub const fn text_range(&self) -> (usize, usize) {
        (self.text_offset, self.text_offset + self.text_size)
    }
}

// ── Image extractor ───────────────────────────────────────────────────────────

/// Result of extracting a single dylib from the shared cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedDylib {
    pub install_name: String,
    pub size: usize,
    pub address: u64,
    pub slide_applied: bool,
    pub symbol_count: usize,
}

/// Extract a single dylib image from the shared cache bytes.
///
/// This performs a simplified extraction:
/// 1. Locate the image by name.
/// 2. Map its Mach-O header from the file offset.
/// 3. Copy all segments.
/// 4. Optionally apply the slide.
pub fn extract_image(
    cache_data: &[u8],
    cache: &SharedCache,
    image_name: &str,
    apply_slide: bool,
) -> ExtractResult<Vec<u8>> {
    let image = cache
        .find_image(image_name)
        .ok_or_else(|| ExtractError::ImageNotFound(image_name.to_owned()))?;

    let file_off = cache
        .address_to_file_offset(image.address)
        .ok_or(ExtractError::MappingNotFound(image.address))?;

    let mach_start = file_off as usize;
    if mach_start + 4 > cache_data.len() {
        return Err(ExtractError::UnexpectedEof(mach_start));
    }

    // Read Mach-O magic to determine size strategy
    let magic = u32::from_le_bytes(cache_data[mach_start..mach_start + 4].try_into().unwrap());
    let is_64 = magic == 0xFEED_FACF;
    let is_fat = magic == 0xCAFE_BABE || magic == 0xBEBA_FECA;

    if is_fat {
        return Err(ExtractError::UnexpectedEof(mach_start)); // FAT not expected in cache
    }

    let header_size = if is_64 { 32usize } else { 28usize };
    if mach_start + header_size > cache_data.len() {
        return Err(ExtractError::UnexpectedEof(mach_start));
    }

    // ncmds is at offset 16 (both 32 and 64 bit)
    let ncmds = u32::from_le_bytes(
        cache_data[mach_start + 16..mach_start + 20].try_into().unwrap(),
    );
    let sizeofcmds = u32::from_le_bytes(
        cache_data[mach_start + 20..mach_start + 24].try_into().unwrap(),
    ) as usize;

    // Collect all segment commands to determine total image size
    let cmds_start = mach_start + header_size;
    let cmds_end = cmds_start + sizeofcmds;
    if cmds_end > cache_data.len() {
        return Err(ExtractError::UnexpectedEof(cmds_end));
    }

    let mut total_size: usize = 0;
    let mut off = cmds_start;
    for _ in 0..ncmds as usize {
        if off + 8 > cache_data.len() {
            break;
        }
        let cmd = u32::from_le_bytes(cache_data[off..off + 4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(cache_data[off + 4..off + 8].try_into().unwrap()) as usize;
        if cmdsize == 0 {
            break;
        }
        // LC_SEGMENT = 0x1, LC_SEGMENT_64 = 0x19
        if cmd == 0x1 || cmd == 0x19 {
            let fileoff_field = if cmd == 0x19 { off + 0x28 } else { off + 0x20 };
            let filesize_field = if cmd == 0x19 { off + 0x30 } else { off + 0x24 };
            if fileoff_field + 8 <= cache_data.len() && filesize_field + 8 <= cache_data.len() {
                let seg_fileoff = u64::from_le_bytes(
                    cache_data[fileoff_field..fileoff_field + 8].try_into().unwrap(),
                ) as usize;
                let seg_filesize = u64::from_le_bytes(
                    cache_data[filesize_field..filesize_field + 8].try_into().unwrap(),
                ) as usize;
                if seg_fileoff + seg_filesize > total_size {
                    total_size = seg_fileoff + seg_filesize;
                }
            }
        }
        off += cmdsize;
    }

    if total_size == 0 || total_size > 512 * 1024 * 1024 {
        // Fallback: extract a reasonable chunk
        total_size = (sizeofcmds + header_size + 0x1000).min(cache_data.len() - mach_start);
    }

    let end = (mach_start + total_size).min(cache_data.len());
    let mut extracted = cache_data[mach_start..end].to_vec();

    if apply_slide && cache.slide != 0 {
        // Apply slide to the __DATA segment area (heuristic)
        let data_offset = header_size + sizeofcmds;
        let data_size = extracted.len().saturating_sub(data_offset);
        let mut applicator = SlideApplicator::new(&mut extracted, cache.slide, 0, header_size + sizeofcmds);
        applicator.apply_slide_to_data_section(data_offset, data_size);
    }

    Ok(extracted)
}

// ── Symbol export ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedSymbol {
    pub name: String,
    pub address: u64,
    pub flags: u32,
    pub kind: SymbolKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolKind {
    Regular,
    ThreadLocal,
    Absolute,
    ReExport,
    Stub,
}

/// Attempt to read the export trie from a Mach-O binary and return exported symbols.
/// This is a simplified implementation that only reads the `LC_DYLD_INFO_ONLY` export trie.
#[must_use] 
pub fn read_export_trie(mach_data: &[u8], base_address: u64) -> Vec<ExportedSymbol> {
    if mach_data.len() < 32 {
        return Vec::new();
    }

    let magic = u32::from_le_bytes(mach_data[..4].try_into().unwrap());
    let is_64 = magic == 0xFEED_FACF;
    let header_size = if is_64 { 32usize } else { 28usize };
    let ncmds = u32::from_le_bytes(mach_data[16..20].try_into().unwrap()) as usize;
    let sizeofcmds = u32::from_le_bytes(mach_data[20..24].try_into().unwrap()) as usize;

    let cmds_start = header_size;
    let cmds_end = (cmds_start + sizeofcmds).min(mach_data.len());
    let mut off = cmds_start;

    let mut export_off = 0usize;
    let mut export_size = 0usize;

    for _ in 0..ncmds {
        if off + 8 > mach_data.len() || off >= cmds_end {
            break;
        }
        let cmd = u32::from_le_bytes(mach_data[off..off + 4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(mach_data[off + 4..off + 8].try_into().unwrap()) as usize;
        if cmdsize == 0 { break; }

        // LC_DYLD_INFO = 0x22, LC_DYLD_INFO_ONLY = 0x80000022, LC_DYLD_EXPORTS_TRIE = 0x80000033
        if cmd == 0x22 || cmd == 0x8000_0022 || cmd == 0x8000_0033 {
            let exports_field = if cmd == 0x8000_0033 { off + 8 } else { off + 0x30 };
            if exports_field + 8 <= mach_data.len() {
                export_off = u32::from_le_bytes(mach_data[exports_field..exports_field + 4].try_into().unwrap()) as usize;
                export_size = u32::from_le_bytes(mach_data[exports_field + 4..exports_field + 8].try_into().unwrap()) as usize;
            }
        }
        off += cmdsize;
    }

    if export_off == 0 || export_size == 0 {
        return Vec::new();
    }

    let trie_end = (export_off + export_size).min(mach_data.len());
    let trie = &mach_data[export_off..trie_end];

    let mut symbols = Vec::new();
    walk_export_trie(trie, 0, &mut String::new(), base_address, &mut symbols);
    symbols
}

fn walk_export_trie(
    trie: &[u8],
    node: usize,
    prefix: &mut String,
    base: u64,
    out: &mut Vec<ExportedSymbol>,
) {
    if node >= trie.len() {
        return;
    }

    let (terminal_size, adv) = read_uleb128_at(trie, node);
    let mut pos = node + adv;

    if terminal_size > 0 {
        let flags_pos = pos;
        let (flags, flags_adv) = read_uleb128_at(trie, flags_pos);
        pos += flags_adv;
        let (offset, _) = read_uleb128_at(trie, pos);
        let address = base.wrapping_add(offset);
        let kind = match flags & 0x3 {
            1 => SymbolKind::ThreadLocal,
            2 => SymbolKind::Absolute,
            3 => SymbolKind::ReExport,
            _ => SymbolKind::Regular,
        };
        out.push(ExportedSymbol {
            name: prefix.clone(),
            address,
            flags: flags as u32,
            kind,
        });
    }

    let children_start = node + adv + terminal_size as usize;
    if children_start >= trie.len() {
        return;
    }

    let child_count = trie[children_start] as usize;
    let mut child_pos = children_start + 1;

    for _ in 0..child_count {
        if child_pos >= trie.len() {
            break;
        }
        // Read edge label (NUL-terminated)
        let label_end = trie[child_pos..].iter().position(|&b| b == 0).unwrap_or(0);
        let label = std::str::from_utf8(&trie[child_pos..child_pos + label_end]).unwrap_or("");
        child_pos += label_end + 1;

        // Read child node offset (ULEB128)
        let (child_off, adv) = read_uleb128_at(trie, child_pos);
        child_pos += adv;

        prefix.push_str(label);
        walk_export_trie(trie, child_off as usize, prefix, base, out);
        for _ in 0..label.len() { prefix.pop(); }
    }
}

fn read_uleb128_at(data: &[u8], mut pos: usize) -> (u64, usize) {
    let start = pos;
    let mut result: u64 = 0;
    let mut shift = 0;
    loop {
        if pos >= data.len() || shift >= 64 { break; }
        let b = u64::from(data[pos]);
        pos += 1;
        result |= (b & 0x7f) << shift;
        if b & 0x80 == 0 { break; }
        shift += 7;
    }
    (result, pos - start)
}

// ── Dump all dylibs ───────────────────────────────────────────────────────────

/// Extract all dylibs from a shared cache, returning (path, data) pairs.
pub fn dump_all_dylibs(
    cache_data: &[u8],
    apply_slide: bool,
) -> ExtractResult<Vec<ExtractedDylib>> {
    let parser = SharedCacheParser::new(cache_data);
    let cache = parser.parse()?;

    let mut results = Vec::new();
    for image in &cache.images {
        if let Ok(data) = extract_image(cache_data, &cache, image.dylib_name(), apply_slide) {
            let symbols = read_export_trie(&data, image.address);
            results.push(ExtractedDylib {
                install_name: image.path.clone(),
                size: data.len(),
                address: image.address,
                slide_applied: apply_slide,
                symbol_count: symbols.len(),
            });
        } else {
            // Skip images that can't be extracted
        }
    }

    Ok(results)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arch_from_magic() {
        assert_eq!(CacheArch::from_magic(b"dyld_v1   arm64\0"), CacheArch::Arm64);
        assert_eq!(CacheArch::from_magic(b"dyld_v1  x86_64\0"), CacheArch::X86_64);
        assert_eq!(CacheArch::from_magic(b"garbage_magic!!!"), CacheArch::Unknown);
    }

    #[test]
    fn test_arch_pointer_size() {
        assert_eq!(CacheArch::Arm64.pointer_size(), 8);
        assert_eq!(CacheArch::Arm.pointer_size(), 4);
    }

    #[test]
    fn test_mapping_contains_address() {
        let m = CacheMapping {
            address: 0x1000_0000,
            size: 0x10_0000,
            file_offset: 0,
            max_prot: 5,
            init_prot: 5,
        };
        assert!(m.contains_address(0x1000_0000));
        assert!(m.contains_address(0x100F_FFFF));
        assert!(!m.contains_address(0x1010_0000));
    }

    #[test]
    fn test_mapping_address_to_offset() {
        let m = CacheMapping {
            address: 0x1000_0000,
            size: 0x10_0000,
            file_offset: 0x5000,
            max_prot: 5,
            init_prot: 5,
        };
        assert_eq!(m.address_to_offset(0x1000_0000), Some(0x5000));
        assert_eq!(m.address_to_offset(0x1000_1000), Some(0x6000));
        assert_eq!(m.address_to_offset(0x2000_0000), None);
    }

    #[test]
    fn test_parse_bad_magic() {
        let data = vec![0u8; 0x200];
        let parser = SharedCacheParser::new(&data);
        let result = parser.parse();
        assert!(matches!(result, Err(ExtractError::BadMagic)));
    }

    #[test]
    fn test_read_uleb128() {
        let data = &[0x01u8];
        let (v, adv) = read_uleb128_at(data, 0);
        assert_eq!(v, 1);
        assert_eq!(adv, 1);

        let data2 = &[0x80u8, 0x01];
        let (v2, adv2) = read_uleb128_at(data2, 0);
        assert_eq!(v2, 128);
        assert_eq!(adv2, 2);
    }

    #[test]
    fn test_image_dylib_name() {
        let img = CacheImage {
            address: 0,
            mod_time: 0,
            inode: 0,
            path_file_offset: 0,
            pad: 0,
            path: "/usr/lib/libSystem.B.dylib".to_owned(),
        };
        assert_eq!(img.dylib_name(), "libSystem.B.dylib");
    }
}
