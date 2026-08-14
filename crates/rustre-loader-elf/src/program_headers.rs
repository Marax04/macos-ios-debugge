//! ELF program header (Phdr) parsing — all PT_* types.
//!
//! Program headers describe segments used at runtime (LOAD, INTERP, TLS, etc.).
//! This module provides raw Phdr parsing plus structured segment analysis.

// ---------------------------------------------------------------------------
// PT_* segment type constants
// ---------------------------------------------------------------------------

pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_LOOS: u32 = 0x6000_0000;
pub const PT_HIOS: u32 = 0x6FFF_FFFF;
pub const PT_LOPROC: u32 = 0x7000_0000;
pub const PT_HIPROC: u32 = 0x7FFF_FFFF;

// GNU extension segment types
pub const PT_GNU_EH_FRAME: u32 = 0x6474_E550;
pub const PT_GNU_STACK: u32 = 0x6474_E551;
pub const PT_GNU_RELRO: u32 = 0x6474_E552;
pub const PT_GNU_PROPERTY: u32 = 0x6474_E553;
pub const PT_GNU_MBIND_LO: u32 = 0x6474_E555;
pub const PT_GNU_MBIND_HI: u32 = 0x6474_F554;

// Sun/Solaris extension types
pub const PT_SUNWBSS: u32 = 0x6FFF_FEFA;
pub const PT_SUNWSTACK: u32 = 0x6FFF_FEFB;

// ARM-specific
pub const PT_ARM_UNWIND: u32 = 0x7000_0001;
pub const PT_ARM_ARCHEXT: u32 = 0x7000_0000;

// AARCH64-specific
// PT_AARCH64_ARCHEXT == PT_ARM_ARCHEXT == 0x7000_0000 (shared value)
// PT_AARCH64_UNWIND  == PT_ARM_UNWIND  == 0x7000_0001 (shared value)
pub const PT_AARCH64_MEMTAG_MTE: u32 = 0x7000_0002;

// MIPS-specific
pub const PT_MIPS_REGINFO: u32 = 0x7000_0000;
pub const PT_MIPS_RTPROC: u32 = 0x7000_0001;
pub const PT_MIPS_OPTIONS: u32 = 0x7000_0002;
pub const PT_MIPS_ABIFLAGS: u32 = 0x7000_0003;

// ---------------------------------------------------------------------------
// PF_* permission flags
// ---------------------------------------------------------------------------

pub const PF_X: u32 = 0x1; // Execute
pub const PF_W: u32 = 0x2; // Write
pub const PF_R: u32 = 0x4; // Read
pub const PF_MASKOS: u32 = 0x0FF0_0000;
pub const PF_MASKPROC: u32 = 0xF000_0000;

/// Human-readable name for a segment type.
#[must_use]
pub const fn segment_type_name(pt: u32) -> &'static str {
    match pt {
        PT_NULL => "PT_NULL",
        PT_LOAD => "PT_LOAD",
        PT_DYNAMIC => "PT_DYNAMIC",
        PT_INTERP => "PT_INTERP",
        PT_NOTE => "PT_NOTE",
        PT_SHLIB => "PT_SHLIB",
        PT_PHDR => "PT_PHDR",
        PT_TLS => "PT_TLS",
        PT_GNU_EH_FRAME => "PT_GNU_EH_FRAME",
        PT_GNU_STACK => "PT_GNU_STACK",
        PT_GNU_RELRO => "PT_GNU_RELRO",
        PT_GNU_PROPERTY => "PT_GNU_PROPERTY",
        PT_SUNWBSS => "PT_SUNWBSS",
        PT_SUNWSTACK => "PT_SUNWSTACK",
        PT_ARM_UNWIND => "PT_ARM/AARCH64_UNWIND",
        PT_MIPS_REGINFO => "PT_MIPS_REGINFO",
        PT_MIPS_OPTIONS => "PT_MIPS_OPTIONS",
        PT_MIPS_ABIFLAGS => "PT_MIPS_ABIFLAGS",
        _ if pt >= PT_LOPROC => "PT_LOPROC..HIPROC (arch-specific)",
        _ if pt >= PT_LOOS => "PT_LOOS..HIOS (OS-specific)",
        _ => "Unknown",
    }
}

/// Format PF_* flags as a string like "rwx", "r--", etc.
#[must_use]
pub fn format_phdr_flags(flags: u32) -> String {
    let r = if flags & PF_R != 0 { 'r' } else { '-' };
    let w = if flags & PF_W != 0 { 'w' } else { '-' };
    let x = if flags & PF_X != 0 { 'x' } else { '-' };
    format!("{r}{w}{x}")
}

// ---------------------------------------------------------------------------
// Raw Phdr32 / Phdr64
// ---------------------------------------------------------------------------

/// Raw 32-bit ELF program header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phdr32 {
    pub p_type: u32,
    pub p_offset: u32,
    pub p_vaddr: u32,
    pub p_paddr: u32,
    pub p_filesz: u32,
    pub p_memsz: u32,
    pub p_flags: u32,
    pub p_align: u32,
}

impl Phdr32 {
    pub const SIZE: usize = 32;

    /// Parse a single 32-bit program header from `data` at `offset`.
    ///
    /// # Errors
    /// Returns an error string if the data is too short at the given offset.
    pub fn parse(data: &[u8], offset: usize, le: bool) -> Result<Self, String> {
        if offset.checked_add(Self::SIZE).is_none_or(|end| end > data.len()) {
            return Err(format!("Phdr32 truncated at offset {offset:#x}"));
        }
        let r32 = |off: usize| -> u32 {
            let b: [u8; 4] = data[off..off + 4].try_into().unwrap_or([0; 4]);
            if le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };
        let b = offset;
        Ok(Self {
            p_type: r32(b),
            p_offset: r32(b + 4),
            p_vaddr: r32(b + 8),
            p_paddr: r32(b + 12),
            p_filesz: r32(b + 16),
            p_memsz: r32(b + 20),
            p_flags: r32(b + 24),
            p_align: r32(b + 28),
        })
    }

    /// Parse all program headers from the ELF data.
    #[must_use] 
    pub fn parse_all(
        data: &[u8],
        e_phoff: u32,
        e_phentsize: u16,
        e_phnum: u16,
        le: bool,
    ) -> Vec<Self> {
        let mut phdrs = Vec::with_capacity(e_phnum as usize);
        let step = e_phentsize as usize;
        for i in 0..e_phnum as usize {
            let off = e_phoff as usize + i * step;
            if let Ok(ph) = Self::parse(data, off, le) {
                phdrs.push(ph);
            }
        }
        phdrs
    }
}

/// Raw 64-bit ELF program header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phdr64 {
    pub p_type: u32,
    pub p_flags: u32, // NOTE: flags comes before offset in ELF64
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl Phdr64 {
    pub const SIZE: usize = 56;

    /// Parse a single 64-bit program header from `data` at `offset`.
    ///
    /// # Errors
    /// Returns an error string if the data is too short at the given offset.
    pub fn parse(data: &[u8], offset: usize, le: bool) -> Result<Self, String> {
        if offset.checked_add(Self::SIZE).is_none_or(|end| end > data.len()) {
            return Err(format!("Phdr64 truncated at offset {offset:#x}"));
        }
        let r32 = |off: usize| -> u32 {
            let b: [u8; 4] = data[off..off + 4].try_into().unwrap_or([0; 4]);
            if le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };
        let r64 = |off: usize| -> u64 {
            let b: [u8; 8] = data[off..off + 8].try_into().unwrap_or([0; 8]);
            if le {
                u64::from_le_bytes(b)
            } else {
                u64::from_be_bytes(b)
            }
        };
        let b = offset;
        Ok(Self {
            p_type: r32(b),
            p_flags: r32(b + 4),
            p_offset: r64(b + 8),
            p_vaddr: r64(b + 16),
            p_paddr: r64(b + 24),
            p_filesz: r64(b + 32),
            p_memsz: r64(b + 40),
            p_align: r64(b + 48),
        })
    }

    /// Parse all program headers from the ELF data.
    #[must_use] 
    pub fn parse_all(
        data: &[u8],
        e_phoff: u64,
        e_phentsize: u16,
        e_phnum: u16,
        le: bool,
    ) -> Vec<Self> {
        let mut phdrs = Vec::with_capacity(usize::from(e_phnum));
        let step = usize::from(e_phentsize);
        for i in 0..usize::from(e_phnum) {
            let off = usize::try_from(e_phoff).unwrap_or(usize::MAX).saturating_add(i * step);
            if let Ok(ph) = Self::parse(data, off, le) {
                phdrs.push(ph);
            }
        }
        phdrs
    }
}

// ---------------------------------------------------------------------------
// High-level segment analysis
// ---------------------------------------------------------------------------

/// Normalized ELF segment (arch-independent).
#[derive(Debug, Clone)]
pub struct ElfSegment {
    /// Segment type (PT_*).
    pub segment_type: u32,
    /// Segment flags (PF_*).
    pub flags: u32,
    /// File offset.
    pub offset: u64,
    /// Virtual address.
    pub vaddr: u64,
    /// Physical address.
    pub paddr: u64,
    /// Size in file.
    pub filesz: u64,
    /// Size in memory.
    pub memsz: u64,
    /// Alignment.
    pub align: u64,
}

impl ElfSegment {
    /// Build from a 32-bit phdr.
    #[must_use]
    pub const fn from_phdr32(ph: &Phdr32) -> Self {
        Self {
            segment_type: ph.p_type,
            flags: ph.p_flags,
            offset: ph.p_offset as u64,
            vaddr: ph.p_vaddr as u64,
            paddr: ph.p_paddr as u64,
            filesz: ph.p_filesz as u64,
            memsz: ph.p_memsz as u64,
            align: ph.p_align as u64,
        }
    }

    /// Build from a 64-bit phdr.
    #[must_use]
    pub const fn from_phdr64(ph: &Phdr64) -> Self {
        Self {
            segment_type: ph.p_type,
            flags: ph.p_flags,
            offset: ph.p_offset,
            vaddr: ph.p_vaddr,
            paddr: ph.p_paddr,
            filesz: ph.p_filesz,
            memsz: ph.p_memsz,
            align: ph.p_align,
        }
    }

    /// Returns `true` if the segment is executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.flags & PF_X != 0
    }

    /// Returns `true` if the segment is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.flags & PF_W != 0
    }

    /// Returns `true` if the segment is readable.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.flags & PF_R != 0
    }

    /// Formatted permission string.
    #[must_use]
    pub fn flags_str(&self) -> String {
        format_phdr_flags(self.flags)
    }

    /// Returns `true` if the segment has a BSS-like extension (memsz > filesz).
    #[must_use]
    pub const fn has_bss_region(&self) -> bool {
        self.memsz > self.filesz
    }

    /// Virtual address range end.
    #[must_use]
    pub const fn vaddr_end(&self) -> u64 {
        self.vaddr.saturating_add(self.memsz)
    }
}

// ---------------------------------------------------------------------------
// LOAD segment analysis
// ---------------------------------------------------------------------------

/// Analyse a slice of ELF segments for security and structural properties.
#[derive(Debug, Clone, Default)]
pub struct SegmentAnalysis {
    /// Number of LOAD segments.
    pub load_count: usize,
    /// `true` if any LOAD segment is both writable AND executable (W+X).
    pub has_wx_segment: bool,
    /// `true` if `PT_GNU_STACK` has `PF_X` set (non-executable stack disabled).
    pub has_executable_stack: bool,
    /// `true` if `PT_GNU_RELRO` is present.
    pub has_relro: bool,
    /// Interpreter path (from `PT_INTERP`), if any.
    pub interpreter: Option<String>,
    /// TLS segment virtual address (from `PT_TLS`), if any.
    pub tls_vaddr: Option<u64>,
    /// TLS segment memory size (from `PT_TLS`), if any.
    pub tls_memsz: Option<u64>,
}

/// Analyse a list of segments for security properties.
#[must_use] 
pub fn analyze_segments(data: &[u8], segments: &[ElfSegment]) -> SegmentAnalysis {
    let mut a = SegmentAnalysis::default();

    for seg in segments {
        match seg.segment_type {
            PT_LOAD => {
                a.load_count += 1;
                if seg.is_writable() && seg.is_executable() {
                    a.has_wx_segment = true;
                }
            }
            PT_INTERP => {
                // Read null-terminated interpreter path
                let off = usize::try_from(seg.offset).unwrap_or(usize::MAX);
                let sz = usize::try_from(seg.filesz).unwrap_or(usize::MAX);
                if off + sz <= data.len() && sz > 0 {
                    let slice = &data[off..off + sz];
                    let null = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
                    a.interpreter = Some(String::from_utf8_lossy(&slice[..null]).into_owned());
                }
            }
            PT_GNU_STACK => {
                if seg.is_executable() {
                    a.has_executable_stack = true;
                }
            }
            PT_GNU_RELRO => {
                a.has_relro = true;
            }
            PT_TLS => {
                a.tls_vaddr = Some(seg.vaddr);
                a.tls_memsz = Some(seg.memsz);
            }
            _ => {}
        }
    }
    a
}

// ---------------------------------------------------------------------------
// GNU_PROPERTY parsing
// ---------------------------------------------------------------------------

/// A single `GNU_PROPERTY` note property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnuProperty {
    /// Property type (e.g. `GNU_PROPERTY_X86_FEATURE_1_AND`).
    pub pr_type: u32,
    /// Property data bytes.
    pub data: Vec<u8>,
}

pub const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xC000_0002;
pub const GNU_PROPERTY_X86_ISA_1_NEEDED: u32 = 0xC008_0002;
pub const GNU_PROPERTY_STACK_SIZE: u32 = 1;
pub const GNU_PROPERTY_NO_COPY_ON_PROTECTED: u32 = 2;
pub const GNU_PROPERTY_X86_FEATURE_1_IBT: u32 = 0x1;
pub const GNU_PROPERTY_X86_FEATURE_1_SHSTK: u32 = 0x2;

/// Parse `GNU_PROPERTY` note data into a list of properties.
///
/// The note data uses 4-byte type + 4-byte data size + data (padded to align).
#[must_use] 
pub fn parse_gnu_properties(data: &[u8], is_64bit: bool) -> Vec<GnuProperty> {
    let align = if is_64bit { 8usize } else { 4usize };
    let mut props = Vec::new();
    let mut off = 0usize;

    while off + 8 <= data.len() {
        let pr_type = u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]));
        let pr_datasz =
            u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap_or([0; 4])) as usize;
        off += 8;
        if off + pr_datasz > data.len() {
            break;
        }
        let prop_data = data[off..off + pr_datasz].to_vec();
        props.push(GnuProperty {
            pr_type,
            data: prop_data,
        });
        // Advance with alignment padding
        let step = (pr_datasz + align - 1) & !(align - 1);
        off += step;
    }
    props
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_phdr32_bytes(p_type: u32, flags: u32, vaddr: u32, filesz: u32) -> Vec<u8> {
        let mut b = vec![0u8; 32];
        b[0..4].copy_from_slice(&p_type.to_le_bytes());
        b[4..8].copy_from_slice(&0u32.to_le_bytes()); // offset
        b[8..12].copy_from_slice(&vaddr.to_le_bytes());
        b[12..16].copy_from_slice(&vaddr.to_le_bytes()); // paddr
        b[16..20].copy_from_slice(&filesz.to_le_bytes());
        b[20..24].copy_from_slice(&filesz.to_le_bytes()); // memsz
        b[24..28].copy_from_slice(&flags.to_le_bytes());
        b[28..32].copy_from_slice(&0x1000u32.to_le_bytes()); // align
        b
    }

    fn make_phdr64_bytes(p_type: u32, flags: u32, vaddr: u64, filesz: u64) -> Vec<u8> {
        let mut b = vec![0u8; 56];
        b[0..4].copy_from_slice(&p_type.to_le_bytes());
        b[4..8].copy_from_slice(&flags.to_le_bytes());
        b[8..16].copy_from_slice(&0u64.to_le_bytes()); // offset
        b[16..24].copy_from_slice(&vaddr.to_le_bytes());
        b[24..32].copy_from_slice(&vaddr.to_le_bytes()); // paddr
        b[32..40].copy_from_slice(&filesz.to_le_bytes());
        b[40..48].copy_from_slice(&filesz.to_le_bytes()); // memsz
        b[48..56].copy_from_slice(&0x1000u64.to_le_bytes()); // align
        b
    }

    #[test]
    fn test_parse_phdr32() {
        let b = make_phdr32_bytes(PT_LOAD, PF_R | PF_X, 0x0804_8000, 0x1000);
        let ph = Phdr32::parse(&b, 0, true).unwrap();
        assert_eq!(ph.p_type, PT_LOAD);
        assert_eq!(ph.p_vaddr, 0x0804_8000);
        assert_eq!(ph.p_flags, PF_R | PF_X);
    }

    #[test]
    fn test_parse_phdr64() {
        let b = make_phdr64_bytes(PT_LOAD, PF_R | PF_W, 0x0040_0000, 0x2000);
        let ph = Phdr64::parse(&b, 0, true).unwrap();
        assert_eq!(ph.p_type, PT_LOAD);
        assert_eq!(ph.p_vaddr, 0x0040_0000);
        assert_eq!(ph.p_flags, PF_R | PF_W);
    }

    #[test]
    fn test_elf_segment_from_phdr32() {
        let b = make_phdr32_bytes(PT_LOAD, PF_R | PF_X, 0x1000, 0x500);
        let ph = Phdr32::parse(&b, 0, true).unwrap();
        let seg = ElfSegment::from_phdr32(&ph);
        assert!(seg.is_readable());
        assert!(seg.is_executable());
        assert!(!seg.is_writable());
        assert_eq!(seg.flags_str(), "r-x");
    }

    #[test]
    fn test_elf_segment_wx() {
        let b = make_phdr32_bytes(PT_LOAD, PF_R | PF_W | PF_X, 0x1000, 0x500);
        let ph = Phdr32::parse(&b, 0, true).unwrap();
        let seg = ElfSegment::from_phdr32(&ph);
        assert!(seg.is_writable() && seg.is_executable());
    }

    #[test]
    fn test_segment_type_name() {
        assert_eq!(segment_type_name(PT_LOAD), "PT_LOAD");
        assert_eq!(segment_type_name(PT_INTERP), "PT_INTERP");
        assert_eq!(segment_type_name(PT_GNU_STACK), "PT_GNU_STACK");
        assert_eq!(segment_type_name(PT_GNU_RELRO), "PT_GNU_RELRO");
        assert_eq!(segment_type_name(PT_TLS), "PT_TLS");
    }

    #[test]
    fn test_format_phdr_flags() {
        assert_eq!(format_phdr_flags(PF_R | PF_W | PF_X), "rwx");
        assert_eq!(format_phdr_flags(PF_R | PF_X), "r-x");
        assert_eq!(format_phdr_flags(PF_R), "r--");
        assert_eq!(format_phdr_flags(0), "---");
    }

    #[test]
    fn test_analyze_segments_executable_stack() {
        let b = make_phdr32_bytes(PT_GNU_STACK, PF_R | PF_W | PF_X, 0, 0);
        let ph = Phdr32::parse(&b, 0, true).unwrap();
        let seg = ElfSegment::from_phdr32(&ph);
        let analysis = analyze_segments(&[], &[seg]);
        assert!(analysis.has_executable_stack);
    }

    #[test]
    fn test_analyze_segments_relro() {
        let b = make_phdr64_bytes(PT_GNU_RELRO, PF_R, 0x0060_0000, 0x200);
        let ph = Phdr64::parse(&b, 0, true).unwrap();
        let seg = ElfSegment::from_phdr64(&ph);
        let analysis = analyze_segments(&[], &[seg]);
        assert!(analysis.has_relro);
    }

    #[test]
    fn test_analyze_segments_interp() {
        // Build a fake data buffer with interpreter path at offset 0
        let interp = b"/lib64/ld-linux-x86-64.so.2\0";
        let b = make_phdr64_bytes(PT_INTERP, PF_R, 0, interp.len() as u64);
        let ph = Phdr64::parse(&b, 0, true).unwrap();
        let seg = ElfSegment::from_phdr64(&ph);
        let analysis = analyze_segments(interp, &[seg]);
        assert_eq!(
            analysis.interpreter.as_deref(),
            Some("/lib64/ld-linux-x86-64.so.2")
        );
    }

    #[test]
    fn test_analyze_segments_wx() {
        let b = make_phdr64_bytes(PT_LOAD, PF_R | PF_W | PF_X, 0x0040_0000, 0x1000);
        let ph = Phdr64::parse(&b, 0, true).unwrap();
        let seg = ElfSegment::from_phdr64(&ph);
        let analysis = analyze_segments(&[], &[seg]);
        assert!(analysis.has_wx_segment);
        assert_eq!(analysis.load_count, 1);
    }

    #[test]
    fn test_parse_gnu_properties() {
        // PR_TYPE=GNU_PROPERTY_X86_FEATURE_1_AND, datasz=4, data=IBT|SHSTK
        let mut buf = Vec::new();
        buf.extend_from_slice(&GNU_PROPERTY_X86_FEATURE_1_AND.to_le_bytes());
        buf.extend_from_slice(&4u32.to_le_bytes()); // datasz
        let features: u32 = GNU_PROPERTY_X86_FEATURE_1_IBT | GNU_PROPERTY_X86_FEATURE_1_SHSTK;
        buf.extend_from_slice(&features.to_le_bytes());
        // No padding needed (4 bytes, aligned to 4)
        let props = parse_gnu_properties(&buf, false);
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].pr_type, GNU_PROPERTY_X86_FEATURE_1_AND);
        assert_eq!(props[0].data.len(), 4);
    }

    #[test]
    fn test_phdr32_parse_truncated() {
        assert!(Phdr32::parse(&[0u8; 10], 0, true).is_err());
    }

    #[test]
    fn test_phdr64_parse_truncated() {
        assert!(Phdr64::parse(&[0u8; 10], 0, true).is_err());
    }

    #[test]
    fn test_segment_bss_region() {
        let mut seg = ElfSegment::from_phdr64(&Phdr64 {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_W,
            p_offset: 0,
            p_vaddr: 0x0060_0000,
            p_paddr: 0x0060_0000,
            p_filesz: 0x100,
            p_memsz: 0x200, // 0x100 bytes of BSS
            p_align: 0x1000,
        });
        assert!(seg.has_bss_region());
        seg.memsz = seg.filesz;
        assert!(!seg.has_bss_region());
    }
}
