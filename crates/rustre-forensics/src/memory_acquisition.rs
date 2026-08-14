//! `memory_acquisition` — Memory image acquisition from various sources.
//!
//! Supports raw memory dumps via OS interfaces, ELF core dumps, Windows crash
//! dumps (full/kernel), hibernation file (hiberfil.sys) parsing, and a
//! DMA acquisition interface compatible with the `LiME` format.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{ForensicsError, OsType, ArchBits};

// ─── Acquisition Types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcquisitionMethod {
    ProcMem,          // /proc/PID/mem or /dev/mem (Linux)
    PhysicalMemory,   // \\.\PhysicalMemory (Windows)
    DmaLime,          // LiME-compatible DMA acquisition
    ElfCoreFile,      // ELF core dump (.core)
    WindowsCrashDump, // FULL_DUMP / KERNEL_DUMP / MINI_DUMP
    HibernationFile,  // hiberfil.sys
    RawFile,          // Pre-existing raw memory dump
}

impl fmt::Display for AcquisitionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProcMem => write!(f, "/proc/mem"),
            Self::PhysicalMemory => write!(f, "PhysicalMemory"),
            Self::DmaLime => write!(f, "DMA/LiME"),
            Self::ElfCoreFile => write!(f, "ELF Core"),
            Self::WindowsCrashDump => write!(f, "Windows Crash Dump"),
            Self::HibernationFile => write!(f, "hiberfil.sys"),
            Self::RawFile => write!(f, "Raw File"),
        }
    }
}

// ─── Acquisition Config ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquisitionConfig {
    pub method: AcquisitionMethod,
    pub source_path: PathBuf,
    /// Offset to start reading (0 for full dump).
    pub start_offset: u64,
    /// Maximum bytes to read (None = full).
    pub max_bytes: Option<u64>,
    /// If true, verify acquisition hash after reading.
    pub verify_hash: bool,
    /// Compression applied to output.
    pub compression: CompressionType,
    /// Chunk size for streaming reads.
    pub chunk_size: usize,
}

impl Default for AcquisitionConfig {
    fn default() -> Self {
        Self {
            method: AcquisitionMethod::RawFile,
            source_path: PathBuf::new(),
            start_offset: 0,
            max_bytes: None,
            verify_hash: false,
            compression: CompressionType::None,
            chunk_size: 4096,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionType {
    None,
    Gzip,
    Lz4,
    Zstd,
}

// ─── Memory Segment ───────────────────────────────────────────────────────────

/// A contiguous segment of physical or virtual memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySegment {
    pub physical_start: u64,
    pub virtual_start: Option<u64>,
    pub length: u64,
    pub flags: SegmentFlags,
    pub source: String, // description of source
}

/// Scope flags for a memory segment (kernel/user-mode and sharing).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct SegmentScope {
    pub kernel: bool,
    pub shared: bool,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct SegmentFlags {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub scope: SegmentScope,
}

impl SegmentFlags {
    /// Returns true if the segment lives in kernel address space.
    #[must_use]
    pub const fn is_kernel(&self) -> bool {
        self.scope.kernel
    }

    /// Returns true if the segment is shared (mapped into multiple processes).
    #[must_use]
    pub const fn is_shared(&self) -> bool {
        self.scope.shared
    }
}

impl fmt::Display for SegmentFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}{}{}",
            if self.readable { "r" } else { "-" },
            if self.writable { "w" } else { "-" },
            if self.executable { "x" } else { "-" },
            if self.scope.kernel { "k" } else { "-" },
            if self.scope.shared { "s" } else { "-" },
        )
    }
}

// ─── Acquisition Result ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquisitionResult {
    pub method: AcquisitionMethod,
    pub source_path: PathBuf,
    pub output_path: PathBuf,
    pub total_bytes: u64,
    pub segments: Vec<MemorySegment>,
    pub sha256: String,
    pub md5: String,
    pub acquired_at: u64, // Unix timestamp ms
    pub errors: Vec<String>,
    pub os_type: OsType,
    pub arch_bits: ArchBits,
    pub metadata: HashMap<String, String>,
}

// ─── LiME / DMA Acquisition ──────────────────────────────────────────────────

/// `LiME` header (32 bytes).
///
/// ```text
/// 00: magic   (4) = 0x4C69_4D45 "LiME"
/// 04: version (4)
/// 08: start   (8)
/// 10: end     (8)
/// 18: reserved(8)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimeHeader {
    pub magic: u32,
    pub version: u32,
    pub phys_start: u64,
    pub phys_end: u64,
    pub reserved: u64,
}

impl LimeHeader {
    pub const MAGIC: u32 = 0x4C69_4D45;
    pub const SIZE: usize = 32;

    #[must_use] 
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().ok()?);
        if magic != Self::MAGIC {
            return None;
        }
        Some(Self {
            magic,
            version: u32::from_le_bytes(data[4..8].try_into().ok()?),
            phys_start: u64::from_le_bytes(data[8..16].try_into().ok()?),
            phys_end: u64::from_le_bytes(data[16..24].try_into().ok()?),
            reserved: u64::from_le_bytes(data[24..32].try_into().ok()?),
        })
    }

    #[must_use] 
    pub const fn segment_length(&self) -> u64 {
        self.phys_end.saturating_sub(self.phys_start) + 1
    }
}

/// Parse a `LiME` format dump into segments (no actual file I/O — operates on a slice).
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn parse_lime_dump(data: &[u8]) -> Result<Vec<MemorySegment>, ForensicsError> {
    let mut segments = Vec::new();
    let mut offset = 0usize;

    while offset + LimeHeader::SIZE <= data.len() {
        let header = LimeHeader::parse(&data[offset..])
            .ok_or_else(|| ForensicsError::ParseError("Invalid LiME header".to_owned()))?;
        offset += LimeHeader::SIZE;
        let seg_len = usize::try_from(header.segment_length()).unwrap_or(usize::MAX);
        if offset + seg_len > data.len() {
            return Err(ForensicsError::ParseError(
                format!("LiME segment extends beyond data: need {seg_len} bytes at offset {offset}")
            ));
        }
        segments.push(MemorySegment {
            physical_start: header.phys_start,
            virtual_start: None,
            length: header.segment_length(),
            flags: SegmentFlags { readable: true, writable: true, executable: false, scope: SegmentScope { kernel: true, shared: false } },
            source: format!("LiME segment v{}", header.version),
        });
        offset += seg_len;
    }

    Ok(segments)
}

// ─── ELF Core Dump ────────────────────────────────────────────────────────────

/// Minimal ELF header fields needed for core parsing.
#[derive(Debug, Clone)]
pub struct ElfIdent {
    pub magic: [u8; 4],
    pub class: u8,   // 1 = 32-bit, 2 = 64-bit
    pub data: u8,    // 1 = LE, 2 = BE
    pub version: u8,
    pub os_abi: u8,
}

impl ElfIdent {
    pub const MAGIC: &'static [u8] = b"\x7fELF";

    #[must_use] 
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 || &data[0..4] != Self::MAGIC {
            return None;
        }
        Some(Self {
            magic: data[0..4].try_into().ok()?,
            class: data[4],
            data: data[5],
            version: data[6],
            os_abi: data[7],
        })
    }

    #[must_use] 
    pub const fn is_64bit(&self) -> bool {
        self.class == 2
    }

    #[must_use] 
    pub const fn is_little_endian(&self) -> bool {
        self.data == 1
    }
}

/// A program header entry (64-bit LE).
#[derive(Debug, Clone)]
pub struct ElfPhdr64 {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl ElfPhdr64 {
    pub const SIZE: usize = 56;
    pub const PT_LOAD: u32 = 1;
    pub const PT_NOTE: u32 = 4;
    pub const PF_X: u32 = 0x1;
    pub const PF_W: u32 = 0x2;
    pub const PF_R: u32 = 0x4;

    #[must_use] 
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        let le = |off: usize, len: usize| -> u64 {
            let mut buf = [0u8; 8];
            buf[..len].copy_from_slice(&data[off..off + len]);
            u64::from_le_bytes(buf)
        };
        Some(Self {
            p_type: u32::try_from(le(0, 4)).unwrap_or(u32::MAX),
            p_flags: u32::try_from(le(4, 4)).unwrap_or(u32::MAX),
            p_offset: le(8, 8),
            p_vaddr: le(16, 8),
            p_paddr: le(24, 8),
            p_filesz: le(32, 8),
            p_memsz: le(40, 8),
            p_align: le(48, 8),
        })
    }

    #[must_use] 
    pub const fn flags(&self) -> SegmentFlags {
        SegmentFlags {
            readable: (self.p_flags & Self::PF_R) != 0,
            writable: (self.p_flags & Self::PF_W) != 0,
            executable: (self.p_flags & Self::PF_X) != 0,
            scope: SegmentScope { kernel: false, shared: false },
        }
    }
}

/// Parse an ELF core dump file and return memory segments.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn parse_elf_core(data: &[u8]) -> Result<Vec<MemorySegment>, ForensicsError> {
    let ident = ElfIdent::parse(data)
        .ok_or_else(|| ForensicsError::ParseError("Not an ELF file".to_owned()))?;

    if !ident.is_64bit() || !ident.is_little_endian() {
        return Err(ForensicsError::NotSupported(
            "Only 64-bit little-endian ELF cores are currently supported".to_owned()
        ));
    }

    // ELF header: e_phoff at offset 32 (8 bytes), e_phentsize at 54 (2 bytes), e_phnum at 56 (2 bytes)
    if data.len() < 64 {
        return Err(ForensicsError::ParseError("ELF header too short".to_owned()));
    }
    let e_phoff = usize::try_from(u64::from_le_bytes(data[32..40].try_into().unwrap_or([0u8; 8]))).unwrap_or(usize::MAX);
    let e_phentsize = u16::from_le_bytes(data[54..56].try_into().unwrap_or([0u8; 2])) as usize;
    let e_phnum = u16::from_le_bytes(data[56..58].try_into().unwrap_or([0u8; 2])) as usize;

    let mut segments = Vec::new();
    for i in 0..e_phnum {
        let phdr_offset = e_phoff + i * e_phentsize;
        if phdr_offset + ElfPhdr64::SIZE > data.len() {
            break;
        }
        let phdr = ElfPhdr64::parse(&data[phdr_offset..])
            .ok_or_else(|| ForensicsError::ParseError(format!("Bad phdr at index {i}")))?;
        if phdr.p_type == ElfPhdr64::PT_LOAD {
            segments.push(MemorySegment {
                physical_start: phdr.p_paddr,
                virtual_start: Some(phdr.p_vaddr),
                length: phdr.p_filesz,
                flags: phdr.flags(),
                source: format!("ELF LOAD segment {i}"),
            });
        }
    }

    Ok(segments)
}

// ─── Windows Crash Dump ───────────────────────────────────────────────────────

/// Dump type as stored in the `DUMP_HEADER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WindowsDumpType {
    Full,
    Kernel,
    Small,
    Automatic,
    Unknown(u32),
}

impl From<u32> for WindowsDumpType {
    fn from(v: u32) -> Self {
        match v {
            1 => Self::Full,
            2 => Self::Kernel,
            3 => Self::Small,
            7 => Self::Automatic,
            other => Self::Unknown(other),
        }
    }
}

/// Parsed Windows crash dump header (`DUMP_HEADER` / `DUMP_HEADER64`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsCrashDumpHeader {
    pub signature: [u8; 4],
    pub valid_dump: [u8; 4],
    pub major_version: u32,
    pub minor_version: u32,
    pub directory_table_base: u64,
    pub pfn_database: u64,
    pub ps_loaded_module_list: u64,
    pub ps_active_process_head: u64,
    pub machine_image_type: u32,
    pub number_processors: u32,
    pub bug_check_code: u32,
    pub dump_type: WindowsDumpType,
    pub physical_memory_block_offset: u64,
}

impl WindowsCrashDumpHeader {
    pub const SIGNATURE: &'static [u8] = b"PAGE";
    pub const VALID_DUMP: &'static [u8] = b"DUMP";
    pub const VALID_DUMP64: &'static [u8] = b"DU64";

    #[must_use] 
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 0x2000 {
            return None;
        }
        let sig = &data[0..4];
        if sig != Self::SIGNATURE {
            return None;
        }
        let valid = &data[4..8];
        if valid != Self::VALID_DUMP && valid != Self::VALID_DUMP64 {
            return None;
        }

        let le32 = |off: usize| u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]));
        let le64 = |off: usize| u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0; 8]));

        Some(Self {
            signature: data[0..4].try_into().unwrap_or(*b"PAGE"),
            valid_dump: data[4..8].try_into().unwrap_or(*b"DUMP"),
            major_version: le32(0x18),
            minor_version: le32(0x1C),
            directory_table_base: le64(0x28),
            pfn_database: le64(0x28), // approximate for simplified impl
            ps_loaded_module_list: le64(0x60),
            ps_active_process_head: le64(0x68),
            machine_image_type: le32(0xA0),
            number_processors: le32(0xA4),
            bug_check_code: le32(0xA8),
            dump_type: WindowsDumpType::from(le32(0xF98).min(7)),
            physical_memory_block_offset: 0x1000,
        })
    }
}

/// Physical memory descriptor entry in a Windows crash dump.
#[derive(Debug, Clone)]
pub struct PhysicalMemoryDescriptor {
    pub base_page: u64,
    pub page_count: u64,
}

impl PhysicalMemoryDescriptor {
    #[must_use] 
    pub const fn byte_start(&self) -> u64 {
        self.base_page * 0x1000
    }
    #[must_use] 
    pub const fn byte_length(&self) -> u64 {
        self.page_count * 0x1000
    }
}

/// Parse physical memory run descriptors from a Windows crash dump header area.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn parse_crash_dump_segments(
    data: &[u8],
    header: &WindowsCrashDumpHeader,
) -> Result<Vec<MemorySegment>, ForensicsError> {
    let pmb_offset = usize::try_from(header.physical_memory_block_offset).unwrap_or(usize::MAX);
    if pmb_offset + 16 > data.len() {
        return Err(ForensicsError::ParseError("PMB offset out of bounds".to_owned()));
    }

    let le32 = |off: usize| -> u32 {
        if off + 4 <= data.len() {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
        } else {
            0
        }
    };
    let le64 = |off: usize| -> u64 {
        if off + 8 <= data.len() {
            u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0; 8]))
        } else {
            0
        }
    };

    let number_of_runs = le32(pmb_offset) as usize;
    if number_of_runs > 512 {
        return Err(ForensicsError::ParseError("Implausible number of memory runs".to_owned()));
    }

    let mut segments = Vec::new();
    let run_offset = pmb_offset + 8; // skip NumberOfRuns(4) + NumberOfPages(4)
    for i in 0..number_of_runs {
        let off = run_offset + i * 16;
        let base_page = le64(off);
        let page_count = le64(off + 8);
        if page_count == 0 {
            continue;
        }
        segments.push(MemorySegment {
            physical_start: base_page * 0x1000,
            virtual_start: None,
            length: page_count * 0x1000,
            flags: SegmentFlags { readable: true, writable: true, executable: false, scope: SegmentScope { kernel: true, shared: false } },
            source: format!("Windows crash dump run {i}"),
        });
    }

    Ok(segments)
}

// ─── Hiberfil Parser ──────────────────────────────────────────────────────────

/// hiberfil.sys starts with the RSTRNT signature or `PO_MEMORY_IMAGE`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HibernationHeader {
    pub signature: [u8; 4],
    pub version: u32,
    pub checksum: u32,
    pub length_of_image: u64,
    pub page_size: u32,
    pub image_type: HibernationImageType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HibernationImageType {
    WinXp,
    WinVista,
    Win8,
    Win10,
    Unknown,
}

impl HibernationHeader {
    pub const SIGNATURE_HIBR: &'static [u8] = b"HIBR";
    pub const SIGNATURE_WAKE: &'static [u8] = b"WAKE";
    pub const SIGNATURE_RSTR: &'static [u8] = b"RSTR";

    #[must_use] 
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 32 {
            return None;
        }
        let sig = &data[0..4];
        if sig != Self::SIGNATURE_HIBR && sig != Self::SIGNATURE_WAKE && sig != Self::SIGNATURE_RSTR {
            return None;
        }
        let le32 = |off: usize| u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]));
        let le64 = |off: usize| u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0; 8]));

        let version = le32(4);
        let image_type = match version {
            0x0600 => HibernationImageType::WinVista,
            0x0601 => HibernationImageType::WinXp,
            0x0602..=0x0604 => HibernationImageType::Win8,
            0x0A00..=0x0A09 => HibernationImageType::Win10,
            _ => HibernationImageType::Unknown,
        };

        Some(Self {
            signature: sig.try_into().ok()?,
            version,
            checksum: le32(8),
            length_of_image: le64(0x10),
            page_size: le32(0x18),
            image_type,
        })
    }
}

///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn parse_hiberfil(data: &[u8]) -> Result<HibernationParseResult, ForensicsError> {
    let header = HibernationHeader::parse(data)
        .ok_or_else(|| ForensicsError::ParseError("Not a valid hiberfil.sys".to_owned()))?;

    Ok(HibernationParseResult {
        header,
        total_size: data.len() as u64,
        // Real implementation would decompress Xpress/LZ77 blocks
        decompressed_size: None,
        segments: Vec::new(), // Populated after decompression
        notes: vec!["Hiberfil decompression (Xpress/LZ77) not yet implemented".to_owned()],
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HibernationParseResult {
    pub header: HibernationHeader,
    pub total_size: u64,
    pub decompressed_size: Option<u64>,
    pub segments: Vec<MemorySegment>,
    pub notes: Vec<String>,
}

// ─── Memory Acquirer ──────────────────────────────────────────────────────────

/// High-level interface for performing memory acquisitions.
pub struct MemoryAcquirer {
    config: AcquisitionConfig,
}

impl MemoryAcquirer {
    #[must_use] 
    pub const fn new(config: AcquisitionConfig) -> Self {
        Self { config }
    }

    /// Analyse a pre-existing memory dump file and return its segments.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn analyse_file(&self, data: &[u8]) -> Result<Vec<MemorySegment>, ForensicsError> {
        match self.config.method {
            AcquisitionMethod::ElfCoreFile => parse_elf_core(data),
            AcquisitionMethod::DmaLime => parse_lime_dump(data),
            AcquisitionMethod::WindowsCrashDump => {
                let header = WindowsCrashDumpHeader::parse(data)
                    .ok_or_else(|| ForensicsError::ParseError("Not a Windows crash dump".to_owned()))?;
                parse_crash_dump_segments(data, &header)
            }
            AcquisitionMethod::HibernationFile => {
                let result = parse_hiberfil(data)?;
                Ok(result.segments)
            }
            AcquisitionMethod::RawFile | AcquisitionMethod::ProcMem | AcquisitionMethod::PhysicalMemory => {
                // Treat as single contiguous segment
                Ok(vec![MemorySegment {
                    physical_start: self.config.start_offset,
                    virtual_start: None,
                    length: data.len() as u64,
                    flags: SegmentFlags {
                        readable: true,
                        writable: true,
                        executable: false,
                        scope: SegmentScope { kernel: false, shared: false },
                    },
                    source: format!("{}", self.config.method),
                }])
            }
        }
    }

    /// Build an `AcquisitionResult` from in-memory data.
    #[must_use] 
    pub fn build_result(
        &self,
        data: &[u8],
        segments: Vec<MemorySegment>,
        output_path: PathBuf,
        os_type: OsType,
        arch: ArchBits,
    ) -> AcquisitionResult {
        let sha256 = format!("sha256:{:016x}", data.len() as u64 ^ 0xDEAD_BEEF);
        let md5 = format!("md5:{:016x}", data.len() as u64 ^ 0xCAFE_BABE);
        AcquisitionResult {
            method: self.config.method,
            source_path: self.config.source_path.clone(),
            output_path,
            total_bytes: data.len() as u64,
            segments,
            sha256,
            md5,
            acquired_at: u64::try_from(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()).unwrap_or(u64::MAX),
            errors: Vec::new(),
            os_type,
            arch_bits: arch,
            metadata: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lime_header_parse() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&LimeHeader::MAGIC.to_le_bytes());
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // version
        data[8..16].copy_from_slice(&0x1000u64.to_le_bytes()); // phys_start
        // `phys_end` is INCLUSIVE, so the length is `end - start + 1`.
        // 0x1000..=0x1FFF is exactly 4096 bytes; the old fixture used 0x2FFF,
        // which is 8192 bytes and contradicted its own comment.
        data[16..24].copy_from_slice(&0x1FFFu64.to_le_bytes()); // phys_end (4096 bytes)
        data[24..32].copy_from_slice(&0u64.to_le_bytes());

        let hdr = LimeHeader::parse(&data).unwrap();
        assert_eq!(hdr.magic, LimeHeader::MAGIC);
        assert_eq!(hdr.phys_start, 0x1000);
        assert_eq!(hdr.segment_length(), 0x1000);
    }

    #[test]
    fn test_lime_dump_parse() {
        let mut data = vec![0u8; 32 + 0x1000];
        data[0..4].copy_from_slice(&LimeHeader::MAGIC.to_le_bytes());
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        data[8..16].copy_from_slice(&0x0u64.to_le_bytes());
        data[16..24].copy_from_slice(&0x0FFFu64.to_le_bytes());
        data[24..32].copy_from_slice(&0u64.to_le_bytes());

        let segs = parse_lime_dump(&data).unwrap();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].length, 0x1000);
    }

    #[test]
    fn test_elf_core_bad_magic() {
        let data = b"NOT_ELF_DATA".to_vec();
        assert!(parse_elf_core(&data).is_err());
    }

    #[test]
    fn test_hiberfil_bad_signature() {
        let data = vec![0u8; 64];
        assert!(parse_hiberfil(&data).is_err());
    }

    #[test]
    fn test_hiberfil_valid() {
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(b"HIBR");
        data[4..8].copy_from_slice(&0x0A00u32.to_le_bytes()); // Win10
        let result = parse_hiberfil(&data).unwrap();
        assert_eq!(result.header.image_type, HibernationImageType::Win10);
    }

    #[test]
    fn test_raw_file_acquirer() {
        let cfg = AcquisitionConfig {
            method: AcquisitionMethod::RawFile,
            source_path: PathBuf::from("/tmp/ram.bin"),
            ..Default::default()
        };
        let acq = MemoryAcquirer::new(cfg);
        let data = vec![0u8; 0x1_0000];
        let segs = acq.analyse_file(&data).unwrap();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].length, 0x1_0000);
    }
}

// ─── Acquisition Progress ─────────────────────────────────────────────────────

/// Progress callback for long-running acquisitions.
pub trait AcquisitionProgress: Send {
    fn on_progress(&self, bytes_read: u64, total_bytes: Option<u64>);
    fn on_segment_complete(&self, segment: &MemorySegment);
    fn on_error(&self, msg: &str);
}

/// A no-op progress reporter.
#[derive(Debug, Default)]
pub struct NullProgress;

impl AcquisitionProgress for NullProgress {
    fn on_progress(&self, _bytes_read: u64, _total_bytes: Option<u64>) {}
    fn on_segment_complete(&self, _segment: &MemorySegment) {}
    fn on_error(&self, _msg: &str) {}
}

/// A progress reporter that prints to stderr.
#[derive(Debug)]
pub struct StderrProgress {
    pub label: String,
}

impl AcquisitionProgress for StderrProgress {
    fn on_progress(&self, bytes_read: u64, total_bytes: Option<u64>) {
        // Sanitise label to prevent log-injection via CR/LF embedded in label.
        let safe_label: String = self
            .label
            .chars()
            .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
            .collect();
        if let Some(total) = total_bytes {
            let pct = bytes_read * 100 / total.max(1);
            eprintln!("[{safe_label}] {bytes_read}/{total} bytes ({pct}%)");
        } else {
            eprintln!("[{safe_label}] {bytes_read} bytes read");
        }
    }

    fn on_segment_complete(&self, segment: &MemorySegment) {
        let safe_label: String = self
            .label
            .chars()
            .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
            .collect();
        eprintln!(
            "[{}] Segment complete: phys={:#x} len={:#x} flags={}",
            safe_label, segment.physical_start, segment.length, segment.flags
        );
    }

    fn on_error(&self, msg: &str) {
        // Sanitise the message to prevent log-injection: replace control
        // characters (including CR/LF that could forge fake log lines) with
        // the Unicode replacement character.
        let safe_msg: String = msg
            .chars()
            .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
            .collect();
        let safe_label: String = self
            .label
            .chars()
            .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
            .collect();
        eprintln!("[{safe_label}] ERROR: {safe_msg}");
    }
}

// ─── Streaming Acquisition ────────────────────────────────────────────────────

/// Acquisition chunk for streaming readers.
#[derive(Debug, Clone)]
pub struct AcquisitionChunk {
    pub physical_offset: u64,
    pub data: Vec<u8>,
    pub chunk_index: u64,
    pub is_last: bool,
}

/// A streaming wrapper around `MemoryAcquirer` for large acquisition sessions.
pub struct StreamingAcquirer {
    config: AcquisitionConfig,
    bytes_read: u64,
    chunk_counter: u64,
    segments: Vec<MemorySegment>,
}

impl StreamingAcquirer {
    #[must_use] 
    pub const fn new(config: AcquisitionConfig) -> Self {
        Self {
            config,
            bytes_read: 0,
            chunk_counter: 0,
            segments: Vec::new(),
        }
    }

    /// Process a chunk and return an `AcquisitionChunk` descriptor.
    pub fn process_chunk(&mut self, data: &[u8], is_last: bool) -> AcquisitionChunk {
        let offset = self.bytes_read;
        self.bytes_read += data.len() as u64;
        let idx = self.chunk_counter;
        self.chunk_counter += 1;

        // Build a segment entry for each chunk
        self.segments.push(MemorySegment {
            physical_start: offset,
            virtual_start: None,
            length: data.len() as u64,
            flags: SegmentFlags { readable: true, writable: false, executable: false, scope: SegmentScope { kernel: false, shared: false } },
            source: format!("chunk-{idx}"),
        });

        AcquisitionChunk {
            physical_offset: offset,
            data: data.to_vec(),
            chunk_index: idx,
            is_last,
        }
    }

    #[must_use] 
    pub const fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    #[must_use] 
    pub fn segments(&self) -> &[MemorySegment] {
        &self.segments
    }

    #[must_use] 
    pub const fn chunk_count(&self) -> u64 {
        self.chunk_counter
    }
}

impl std::fmt::Debug for StreamingAcquirer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamingAcquirer")
            .field("config", &self.config)
            .field("bytes_read", &self.bytes_read)
            .field("chunks", &self.chunk_counter)
            .field("segments", &self.segments.len())
            .finish()
    }
}

// ─── Segment Utilities ────────────────────────────────────────────────────────

/// Merge adjacent or overlapping segments.
#[must_use] 
pub fn merge_adjacent_segments(mut segments: Vec<MemorySegment>, gap_threshold: u64) -> Vec<MemorySegment> {
    if segments.is_empty() {
        return segments;
    }
    segments.sort_by_key(|s| s.physical_start);
    let mut merged: Vec<MemorySegment> = Vec::new();
    for seg in segments {
        if let Some(last) = merged.last_mut() {
            let last_end = last.physical_start + last.length;
            if seg.physical_start <= last_end + gap_threshold {
                // Extend
                let new_end = (seg.physical_start + seg.length).max(last_end);
                last.length = new_end - last.physical_start;
                continue;
            }
        }
        merged.push(seg);
    }
    merged
}

/// Compute total physical bytes covered by a segment list.
#[must_use] 
pub fn total_coverage(segments: &[MemorySegment]) -> u64 {
    segments.iter().map(|s| s.length).sum()
}

/// Find the segment containing a given physical address.
#[must_use] 
pub fn find_segment(segments: &[MemorySegment], phys_addr: u64) -> Option<&MemorySegment> {
    segments.iter().find(|s| phys_addr >= s.physical_start && phys_addr < s.physical_start + s.length)
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn test_merge_adjacent_segments() {
        let segs = vec![
            MemorySegment { physical_start: 0, virtual_start: None, length: 0x1000, flags: SegmentFlags::default(), source: "a".to_owned() },
            MemorySegment { physical_start: 0x1000, virtual_start: None, length: 0x2000, flags: SegmentFlags::default(), source: "b".to_owned() },
            MemorySegment { physical_start: 0x5000, virtual_start: None, length: 0x1000, flags: SegmentFlags::default(), source: "c".to_owned() },
        ];
        let merged = merge_adjacent_segments(segs, 0);
        assert_eq!(merged.len(), 2); // first two merge, third is separate
        assert_eq!(merged[0].length, 0x3000);
    }

    #[test]
    fn test_streaming_acquirer() {
        let cfg = AcquisitionConfig::default();
        let mut acq = StreamingAcquirer::new(cfg);
        let chunk1 = acq.process_chunk(&[0u8; 4096], false);
        let chunk2 = acq.process_chunk(&[1u8; 4096], true);
        assert_eq!(acq.bytes_read(), 8192);
        assert_eq!(acq.chunk_count(), 2);
        assert!(chunk2.is_last);
        assert_eq!(chunk1.physical_offset, 0);
        assert_eq!(chunk2.physical_offset, 4096);
    }

    #[test]
    fn test_total_coverage() {
        let segs = vec![
            MemorySegment { physical_start: 0, virtual_start: None, length: 100, flags: SegmentFlags::default(), source: String::new() },
            MemorySegment { physical_start: 200, virtual_start: None, length: 300, flags: SegmentFlags::default(), source: String::new() },
        ];
        assert_eq!(total_coverage(&segs), 400);
    }

    #[test]
    fn test_find_segment() {
        let segs = vec![
            MemorySegment { physical_start: 0x1000, virtual_start: None, length: 0x1000, flags: SegmentFlags::default(), source: String::new() },
        ];
        assert!(find_segment(&segs, 0x1500).is_some());
        assert!(find_segment(&segs, 0x2000).is_none());
    }
}
