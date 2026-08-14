// rustre-pe-rebuild/src/section_realigner.rs
// Fix section raw offsets, sizes, VAs after rebase; fix characteristics;
// update the optional header SizeOfImage and SizeOfHeaders fields.

use std::collections::HashMap;
use std::fmt;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Default file alignment used by MSVC linker.
pub const DEFAULT_FILE_ALIGN: u32 = 0x200;
/// Default section alignment for most PE files.
pub const DEFAULT_SECTION_ALIGN: u32 = 0x1000;

// ─── Section characteristics flags ───────────────────────────────────────────

pub const IMAGE_SCN_CNT_CODE:               u32 = 0x0000_0020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA:   u32 = 0x0000_0040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const IMAGE_SCN_MEM_EXECUTE:            u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ:               u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE:              u32 = 0x8000_0000;

// ─── Section layout ───────────────────────────────────────────────────────────

/// All layout parameters for one PE section after realignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionLayout {
    /// Section name (up to 8 ASCII bytes).
    pub name: [u8; 8],
    /// Original virtual address.
    pub original_va: u32,
    /// New virtual address after rebase.
    pub new_va: u32,
    /// Size of section data in memory (virtual size).
    pub virtual_size: u32,
    /// Original raw offset in the file.
    pub original_raw_off: u32,
    /// New raw offset after realignment.
    pub new_raw_off: u32,
    /// Original raw data size.
    pub original_raw_size: u32,
    /// New raw data size (aligned to file alignment).
    pub new_raw_size: u32,
    /// Section characteristics.
    pub characteristics: u32,
    /// True if the layout changed.
    pub modified: bool,
}

impl SectionLayout {
    #[must_use]
    pub fn name_str(&self) -> String {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }

    #[must_use]
    pub const fn is_code(&self) -> bool {
        self.characteristics & IMAGE_SCN_CNT_CODE != 0
            || self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }

    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_READ != 0
    }

    /// Raw size aligned up to `file_align`.
    #[must_use]
    pub fn aligned_raw_size(virtual_size: u32, file_align: u32) -> u32 {
        align_up(virtual_size, file_align)
    }
}

impl fmt::Display for SectionLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] VA: 0x{:08x}->0x{:08x}  raw: 0x{:x}->0x{:x}  sz: 0x{:x}->0x{:x}",
            self.name_str(),
            self.original_va, self.new_va,
            self.original_raw_off, self.new_raw_off,
            self.original_raw_size, self.new_raw_size)
    }
}

// ─── Raw section header (for parsing/writing) ─────────────────────────────────

/// Raw `IMAGE_SECTION_HEADER` (40 bytes).
#[derive(Debug, Clone, Copy)]
pub struct RawSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

impl RawSectionHeader {
    /// Parse from 40 bytes.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 40 { return None; }
        let mut name = [0u8; 8];
        name.copy_from_slice(&b[0..8]);
        Some(Self {
            name,
            virtual_size:           u32::from_le_bytes(b[8..12].try_into().ok()?),
            virtual_address:        u32::from_le_bytes(b[12..16].try_into().ok()?),
            size_of_raw_data:       u32::from_le_bytes(b[16..20].try_into().ok()?),
            pointer_to_raw_data:    u32::from_le_bytes(b[20..24].try_into().ok()?),
            pointer_to_relocations: u32::from_le_bytes(b[24..28].try_into().ok()?),
            pointer_to_linenumbers: u32::from_le_bytes(b[28..32].try_into().ok()?),
            number_of_relocations:  u16::from_le_bytes(b[32..34].try_into().ok()?),
            number_of_linenumbers:  u16::from_le_bytes(b[34..36].try_into().ok()?),
            characteristics:        u32::from_le_bytes(b[36..40].try_into().ok()?),
        })
    }

    /// Serialize back to 40 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[0..8].copy_from_slice(&self.name);
        out[8..12].copy_from_slice(&self.virtual_size.to_le_bytes());
        out[12..16].copy_from_slice(&self.virtual_address.to_le_bytes());
        out[16..20].copy_from_slice(&self.size_of_raw_data.to_le_bytes());
        out[20..24].copy_from_slice(&self.pointer_to_raw_data.to_le_bytes());
        out[24..28].copy_from_slice(&self.pointer_to_relocations.to_le_bytes());
        out[28..32].copy_from_slice(&self.pointer_to_linenumbers.to_le_bytes());
        out[32..34].copy_from_slice(&self.number_of_relocations.to_le_bytes());
        out[34..36].copy_from_slice(&self.number_of_linenumbers.to_le_bytes());
        out[36..40].copy_from_slice(&self.characteristics.to_le_bytes());
        out
    }
}

// ─── Alignment helpers ────────────────────────────────────────────────────────

#[must_use]
pub const fn align_up(val: u32, align: u32) -> u32 {
    if align == 0 { return val; }
    val.saturating_add(align - 1) & !(align - 1)
}

#[must_use]
pub const fn align_down(val: u32, align: u32) -> u32 {
    if align == 0 { return val; }
    val & !(align - 1)
}

// ─── Optional header fix record ───────────────────────────────────────────────

/// Fields in the PE optional header that need updating after realignment.
#[derive(Debug, Clone)]
pub struct OptHeaderFix {
    /// New `SizeOfImage` (aligned to section alignment).
    pub size_of_image: u32,
    /// New `SizeOfHeaders` (aligned to file alignment).
    pub size_of_headers: u32,
    /// New `ImageBase` (if rebased).
    pub image_base: u64,
    /// Was `SizeOfImage` changed?
    pub image_size_changed: bool,
    /// Was `SizeOfHeaders` changed?
    pub headers_size_changed: bool,
    /// Was `ImageBase` changed?
    pub base_changed: bool,
}

// ─── Align result ─────────────────────────────────────────────────────────────

/// The complete output of a section realignment pass.
#[derive(Debug, Clone)]
pub struct AlignResult {
    /// Per-section layout changes.
    pub sections: Vec<SectionLayout>,
    /// Updated optional header fields.
    pub opt_header: OptHeaderFix,
    /// Number of sections that were modified.
    pub modified_count: usize,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
    /// Fatal errors that prevented complete realignment.
    pub errors: Vec<String>,
}

impl AlignResult {
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }

    #[must_use]
    pub fn sections_modified(&self) -> usize {
        self.sections.iter().filter(|s| s.modified).count()
    }
}

// ─── Section realigner ────────────────────────────────────────────────────────

/// Configuration for the realigner.
#[derive(Debug, Clone)]
pub struct RealignConfig {
    pub file_alignment: u32,
    pub section_alignment: u32,
    /// New image base (0 = keep existing).
    pub new_image_base: Option<u64>,
    /// Fix characteristics for .text / .data heuristically.
    pub fix_characteristics: bool,
    /// Remove zero-size sections.
    pub remove_zero_size: bool,
}

impl Default for RealignConfig {
    fn default() -> Self {
        Self {
            file_alignment: DEFAULT_FILE_ALIGN,
            section_alignment: DEFAULT_SECTION_ALIGN,
            new_image_base: None,
            fix_characteristics: true,
            remove_zero_size: false,
        }
    }
}

/// Realigns all sections in a PE image.
pub struct SectionRealigner {
    pub config: RealignConfig,
}

impl SectionRealigner {
    #[must_use]
    pub const fn new(config: RealignConfig) -> Self {
        Self { config }
    }

    /// Parse section headers from a PE image starting at the section table offset.
    #[must_use]
    pub fn parse_sections(&self, pe_bytes: &[u8], section_table_off: usize, count: usize)
        -> Vec<RawSectionHeader>
    {
        let mut headers = Vec::with_capacity(count);
        for i in 0..count {
            let off = section_table_off + i * 40;
            if off + 40 > pe_bytes.len() { break; }
            if let Some(hdr) = RawSectionHeader::from_bytes(&pe_bytes[off..off+40]) {
                headers.push(hdr);
            }
        }
        headers
    }

    /// Core realignment logic.
    #[must_use]
    pub fn realign(&self, headers: &[RawSectionHeader], current_headers_size: u32,
        current_image_base: u64) -> AlignResult
    {
        let file_align = self.config.file_alignment;
        let sect_align = self.config.section_alignment;
        let new_base = self.config.new_image_base.unwrap_or(current_image_base);

        let mut sections: Vec<SectionLayout> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        // First pass: compute aligned raw sizes and raw offsets sequentially.
        let mut raw_off = align_up(current_headers_size, file_align);
        let mut next_va = align_up(current_headers_size, sect_align);

        for hdr in headers {
            if self.config.remove_zero_size
                && hdr.virtual_size == 0 && hdr.size_of_raw_data == 0
            {
                continue;
            }

            let orig_raw_off  = hdr.pointer_to_raw_data;
            let orig_raw_size = hdr.size_of_raw_data;
            let orig_va       = hdr.virtual_address;
            let vsize         = if hdr.virtual_size == 0 { hdr.size_of_raw_data } else { hdr.virtual_size };

            // Compute new aligned raw size.
            let new_raw_size  = SectionLayout::aligned_raw_size(vsize, file_align);
            // Pack sections sequentially.
            let new_raw_off   = if orig_raw_off == 0 { 0 } else { raw_off };
            // Compute new VA relative to new image base.
            let va_delta: i64 = new_base.cast_signed() - current_image_base.cast_signed();
            let new_va = u32::try_from(
                (i64::from(orig_va) + va_delta).max(i64::from(next_va))
            ).unwrap_or(u32::MAX);
            let new_va = align_up(new_va, sect_align);

            if new_raw_size > 0 {
                raw_off += new_raw_size;
            }
            next_va = align_up(new_va + vsize, sect_align);

            let mut characteristics = hdr.characteristics;
            if self.config.fix_characteristics {
                characteristics = Self::fix_characteristics(hdr.name, characteristics);
            }

            let modified = orig_raw_off != new_raw_off
                || orig_raw_size != new_raw_size
                || orig_va != new_va
                || hdr.characteristics != characteristics;

            if orig_raw_size > 0 && new_raw_size < orig_raw_size {
                warnings.push(format!("section {} raw size reduced from 0x{:x} to 0x{:x}",
                    RawSectionHeader { name: hdr.name, ..*hdr }.name_str_lossy(),
                    orig_raw_size, new_raw_size));
            }
            // Hard error: virtual layout overflowed a 32-bit RVA.
            if u64::from(new_va) + u64::from(vsize) > u64::from(u32::MAX) {
                errors.push(format!(
                    "section {} virtual layout overflows 32-bit RVA (va={:#x} size={:#x})",
                    RawSectionHeader { name: hdr.name, ..*hdr }.name_str_lossy(),
                    new_va,
                    vsize
                ));
            }

            sections.push(SectionLayout {
                name: hdr.name,
                original_va: orig_va,
                new_va,
                virtual_size: vsize,
                original_raw_off: orig_raw_off,
                new_raw_off,
                original_raw_size: orig_raw_size,
                new_raw_size,
                characteristics,
                modified,
            });
        }

        // Compute new SizeOfImage.
        let last_va_end = sections.iter()
            .map(|s| s.new_va + align_up(s.virtual_size, sect_align))
            .max()
            .unwrap_or(sect_align);
        let size_of_image = align_up(last_va_end, sect_align);

        // Compute new SizeOfHeaders.
        let hdr_size_needed = align_up(
            current_headers_size + u32::try_from(sections.len()).unwrap_or(u32::MAX) * 40,
            file_align,
        );
        let size_of_headers = hdr_size_needed.max(align_up(current_headers_size, file_align));

        let modified_count = sections.iter().filter(|s| s.modified).count();
        AlignResult {
            opt_header: OptHeaderFix {
                size_of_image,
                size_of_headers,
                image_base: new_base,
                image_size_changed: true,
                headers_size_changed: size_of_headers != align_up(current_headers_size, file_align),
                base_changed: new_base != current_image_base,
            },
            modified_count,
            sections,
            warnings,
            errors,
        }
    }

    /// Group the section layouts in `result` by their characteristics flags,
    /// returning a flag→count map. Useful for surfacing how many sections
    /// ended up RWX after the realignment pass.
    #[must_use]
    pub fn characteristics_histogram(&self, result: &AlignResult) -> HashMap<u32, usize> {
        let mut h: HashMap<u32, usize> = HashMap::new();
        for s in &result.sections {
            *h.entry(s.characteristics).or_insert(0) += 1;
        }
        h
    }

    /// Apply computed layouts to PE bytes, updating section headers in-place.
    pub fn apply(&self, pe_bytes: &mut [u8], section_table_off: usize,
        result: &AlignResult)
    {
        for (i, layout) in result.sections.iter().enumerate() {
            let off = section_table_off + i * 40;
            if off + 40 > pe_bytes.len() { break; }
            if !layout.modified { continue; }
            let mut hdr_bytes = [0u8; 40];
            hdr_bytes[0..8].copy_from_slice(&layout.name);
            hdr_bytes[8..12].copy_from_slice(&layout.virtual_size.to_le_bytes());
            hdr_bytes[12..16].copy_from_slice(&layout.new_va.to_le_bytes());
            hdr_bytes[16..20].copy_from_slice(&layout.new_raw_size.to_le_bytes());
            hdr_bytes[20..24].copy_from_slice(&layout.new_raw_off.to_le_bytes());
            // Relocations and linenumbers are zero for stripped PE.
            hdr_bytes[36..40].copy_from_slice(&layout.characteristics.to_le_bytes());
            pe_bytes[off..off+40].copy_from_slice(&hdr_bytes);
        }
    }

    fn fix_characteristics(name: [u8; 8], mut chars: u32) -> u32 {
        let name_str = String::from_utf8_lossy(&name);
        let name_str = name_str.trim_end_matches('\0');
        if name_str == ".text" || name_str == "CODE" {
            chars |= IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        } else if name_str == ".data" || name_str == ".rdata" || name_str == ".idata" {
            chars |= IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
            if name_str == ".data" {
                chars |= IMAGE_SCN_MEM_WRITE;
            }
        } else if name_str == ".bss" {
            chars |= IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        }
        chars
    }
}

impl Default for SectionRealigner {
    fn default() -> Self {
        Self::new(RealignConfig::default())
    }
}

// Helper trait to get a lossy name string from RawSectionHeader.
trait NameStrLossy {
    fn name_str_lossy(&self) -> String;
}
impl NameStrLossy for RawSectionHeader {
    fn name_str_lossy(&self) -> String {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A hostile PE can put a section size near `u32::MAX`; rounding it up must
    /// saturate rather than wrap to a small value (or panic under
    /// overflow-checks).  Ordinary values are unaffected.
    #[test]
    fn align_up_saturates_near_max() {
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(align_up(0, 0x1000), 0);
        assert_eq!(align_up(5, 0), 5);
        // u32::MAX + 0xFFF would wrap; the result must stay >= the input's page.
        assert_eq!(align_up(u32::MAX, 0x1000), u32::MAX & !0xFFF);
    }

    fn make_section(name: &str, va: u32, raw_off: u32, raw_size: u32,
        vsize: u32, chars: u32) -> RawSectionHeader
    {
        let mut n = [0u8; 8];
        let nb = name.as_bytes();
        n[..nb.len().min(8)].copy_from_slice(&nb[..nb.len().min(8)]);
        RawSectionHeader {
            name: n,
            virtual_size: vsize,
            virtual_address: va,
            size_of_raw_data: raw_size,
            pointer_to_raw_data: raw_off,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: chars,
        }
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0x201, 0x200), 0x400);
        assert_eq!(align_up(0x200, 0x200), 0x200);
        assert_eq!(align_up(0,     0x200), 0x000);
    }

    #[test]
    fn test_align_down() {
        assert_eq!(align_down(0x1FF, 0x200), 0x000);
        assert_eq!(align_down(0x200, 0x200), 0x200);
    }

    #[test]
    fn test_realign_single_section() {
        let realigner = SectionRealigner::default();
        let hdrs = vec![make_section(".text", 0x1000, 0x400, 0x600, 0x590,
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)];
        let result = realigner.realign(&hdrs, 0x400, 0x1_4000_0000);
        assert_eq!(result.sections.len(), 1);
        // Raw size should be aligned to 0x200.
        assert_eq!(result.sections[0].new_raw_size % 0x200, 0);
        assert!(result.is_clean());
    }

    #[test]
    fn test_realign_fixes_characteristics() {
        let realigner = SectionRealigner::default();
        // .text with no characteristics.
        let hdrs = vec![make_section(".text", 0x1000, 0x400, 0x200, 0x1F0, 0)];
        let result = realigner.realign(&hdrs, 0x400, 0x0040_0000);
        let chars = result.sections[0].characteristics;
        assert_ne!(chars & IMAGE_SCN_MEM_EXECUTE, 0, ".text should be executable");
        assert_ne!(chars & IMAGE_SCN_MEM_READ, 0, ".text should be readable");
    }

    #[test]
    fn test_raw_section_header_roundtrip() {
        let hdr = make_section(".data", 0x3000, 0x800, 0x400, 0x3F0,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
        let bytes = hdr.to_bytes();
        let parsed = RawSectionHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.virtual_address, 0x3000);
        assert_eq!(parsed.size_of_raw_data, 0x400);
        assert_eq!(parsed.characteristics, hdr.characteristics);
    }

    #[test]
    fn test_section_layout_is_code() {
        let layout = SectionLayout {
            name: *b".text\0\0\0",
            original_va: 0x1000, new_va: 0x1000,
            virtual_size: 0x500, original_raw_off: 0x400,
            new_raw_off: 0x400, original_raw_size: 0x600,
            new_raw_size: 0x600,
            characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
            modified: false,
        };
        assert!(layout.is_code());
        assert!(layout.is_readable());
        assert!(!layout.is_writable());
    }

    #[test]
    fn test_size_of_image_calculation() {
        let realigner = SectionRealigner::default();
        let hdrs = vec![
            make_section(".text", 0x1000, 0x400, 0x400, 0x3F0,
                IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE),
            make_section(".data", 0x2000, 0x800, 0x200, 0x1F0,
                IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE),
        ];
        let result = realigner.realign(&hdrs, 0x400, 0x0040_0000);
        assert_eq!(result.opt_header.size_of_image % DEFAULT_SECTION_ALIGN, 0);
    }
}
