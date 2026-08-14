//! Profile auto-detection for memory forensics.
//!
//! This module implements automatic OS profile detection from a raw memory
//! image.  It covers:
//!
//! - **Windows KDBG scan**: searching for `KdDebuggerDataBlock` by its
//!   signature and owner tag to recover OS version and build number.
//! - **PDB URL construction**: given a PE debug directory GUID and age,
//!   builds the Microsoft symbol server URL so PDB files can be fetched.
//! - **PDB offset parsing**: minimal PDB7 stream-directory parser that can
//!   extract type and symbol records containing field offset information.
//! - **Linux KASLR detection**: finds the kernel base in a physical memory
//!   dump by scanning for ELF magic at 2 MiB aligned offsets and reading
//!   the `linux_banner` string.
//! - **Profile caching**: a versioned, in-memory cache that stores detected
//!   field offsets keyed by a (build, architecture) fingerprint.

use std::collections::HashMap;
use crate::casts::usize_to_u32;

// ---------------------------------------------------------------------------
// Windows version fingerprint
// ---------------------------------------------------------------------------

/// Uniquely identifies a Windows build and architecture.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WindowsFingerprint {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub arch: ArchWidth,
}

/// Pointer width of the target system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArchWidth {
    X86,
    X64,
    Arm64,
}

impl ArchWidth {
    /// Pointer size in bytes.
    #[must_use]
    pub const fn ptr_size(self) -> usize {
        match self {
            Self::X86 => 4,
            Self::X64 | Self::Arm64 => 8,
        }
    }
}

impl WindowsFingerprint {
    #[must_use]
    pub const fn new(major: u32, minor: u32, build: u32, arch: ArchWidth) -> Self {
        Self { major, minor, build, arch }
    }

    /// Returns a short human-readable tag like "Win10-x64-19041".
    #[must_use]
    pub fn tag(&self) -> String {
        let arch = match self.arch {
            ArchWidth::X86 => "x86",
            ArchWidth::X64 => "x64",
            ArchWidth::Arm64 => "arm64",
        };
        format!("Win{}.{}-{}-{}", self.major, self.minor, arch, self.build)
    }
}

// ---------------------------------------------------------------------------
// KDBG scan
// ---------------------------------------------------------------------------

/// The `KdDebuggerDataBlock` owner tag (`\x4a\x42\x47\x4b` = "JBGK").
/// In practice the tag appears as `KDBG` in pool memory.
pub const KDBG_OWNER_TAG: &[u8; 4] = b"KDBG";

/// Alternative signatures used on some builds.
pub const KDBG_SIGNATURE_64: &[u8; 16] = b"KDBGKDBG\x00\x00\x00\x00\x00\x00\x00\x00";

/// Offset of the `NtBuildNumber` field within `KDDEBUGGER_DATA64`.
pub const KDBG_BUILD_NUMBER_OFFSET: usize = 0x138;
/// Offset of the `PsActiveProcessHead` field.
pub const KDBG_PS_ACTIVE_PROCESS_HEAD_OFFSET: usize = 0x050;
/// Offset of the `PsLoadedModuleList` field.
pub const KDBG_PS_LOADED_MODULE_LIST_OFFSET: usize = 0x058;
/// Offset of the `KernBase` field.
pub const KDBG_KERN_BASE_OFFSET: usize = 0x018;
/// Offset of the `ServiceDescriptorTable` (SSDT) field.
pub const KDBG_SERVICE_DESCRIPTOR_TABLE_OFFSET: usize = 0x0B0;

/// Result of a successful KDBG scan.
#[derive(Debug, Clone)]
pub struct KdbgInfo {
    /// Physical / virtual offset of the KDBG structure.
    pub kdbg_offset: u64,
    /// Windows build number extracted from the structure.
    pub build_number: u32,
    /// Kernel base virtual address.
    pub kern_base: u64,
    /// `PsActiveProcessHead` (`LIST_ENTRY` in kernel VAS).
    pub ps_active_process_head: u64,
    /// `PsLoadedModuleList` (`LIST_ENTRY` in kernel VAS).
    pub ps_loaded_module_list: u64,
    /// `KeServiceDescriptorTable` (SSDT pointer).
    pub service_descriptor_table: u64,
}

/// Scan `memory` for the KDBG signature and extract key fields.
///
/// The function searches at every 8-byte aligned offset for the 4-byte
/// owner tag `KDBG`, then validates the surrounding fields.  On 64-bit
/// Windows the `_KDDEBUGGER_DATA64` structure is typically 0x340 bytes long.
#[must_use]
pub fn scan_kdbg(memory: &[u8]) -> Vec<KdbgInfo> {
    let mut results = Vec::new();
    let mut i = 0usize;
    while i + 8 <= memory.len() {
        if &memory[i..i + 4] == KDBG_OWNER_TAG.as_ref()
            && let Some(info) = parse_kdbg_at(memory, i) {
                results.push(info);
                i += 0x340;
                continue;
            }
        i += 8;
    }
    results
}

fn parse_kdbg_at(memory: &[u8], offset: usize) -> Option<KdbgInfo> {
    // We need at least enough bytes to read all fields.
    let min_size = offset + KDBG_BUILD_NUMBER_OFFSET + 4;
    if min_size > memory.len() {
        return None;
    }
    let kdbg_offset = offset as u64;
    let kern_base = read_u64_at(memory, offset + KDBG_KERN_BASE_OFFSET)?;
    let ps_active_process_head =
        read_u64_at(memory, offset + KDBG_PS_ACTIVE_PROCESS_HEAD_OFFSET)?;
    let ps_loaded_module_list =
        read_u64_at(memory, offset + KDBG_PS_LOADED_MODULE_LIST_OFFSET)?;
    let service_descriptor_table =
        read_u64_at(memory, offset + KDBG_SERVICE_DESCRIPTOR_TABLE_OFFSET)
            .unwrap_or(0);
    let build_number = read_u32_at(memory, offset + KDBG_BUILD_NUMBER_OFFSET)?;

    // Sanity check: kern_base should be in high VA range for x64.
    if kern_base != 0 && kern_base < 0xFFFF_8000_0000_0000 {
        // Might be a 32-bit kernel — still accept if build_number looks right.
        if !(2000..=30000).contains(&build_number) {
            return None;
        }
    } else if kern_base == 0 && build_number == 0 {
        return None;
    }

    Some(KdbgInfo {
        kdbg_offset,
        build_number,
        kern_base,
        ps_active_process_head,
        ps_loaded_module_list,
        service_descriptor_table,
    })
}

// ---------------------------------------------------------------------------
// PDB URL construction
// ---------------------------------------------------------------------------

/// A PDB GUID as it appears in the PE `IMAGE_DEBUG_DIRECTORY`.
///
/// The GUID is stored in mixed-endian format in the PE.  We convert it to
/// the uppercase hex string used by the Microsoft symbol server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl PdbGuid {
    /// Parse a 16-byte raw GUID as it appears in a PE debug directory.
    ///
    /// # Panics
    /// Panics if slice-to-array conversion fails (cannot happen as sizes are fixed).
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 16]) -> Self {
        Self {
            data1: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            data2: u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
            data3: u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
            data4: bytes[8..16].try_into().unwrap(),
        }
    }

    /// Return the uppercase hex representation used in symbol server URLs.
    ///
    /// Format: `AABBCCDD-EEFF-GGHH-IIJJ-KKLLMMNNOOPP` without dashes,
    /// all uppercase.
    #[must_use]
    pub fn to_symbol_server_str(&self) -> String {
        format!(
            "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0], self.data4[1], self.data4[2], self.data4[3],
            self.data4[4], self.data4[5], self.data4[6], self.data4[7],
        )
    }
}

/// Microsoft public symbol server base URL.
pub const MS_SYMBOL_SERVER: &str = "https://msdl.microsoft.com/download/symbols";

/// Construct the download URL for a PDB file given the module name, GUID, and age.
///
/// URL format: `{server}/{pdb_name}/{guid}{age}/{pdb_name}`
///
/// Example: `https://msdl.microsoft.com/download/symbols/ntoskrnl.pdb/ABCDEF0012345678/ntoskrnl.pdb`
#[must_use]
pub fn build_pdb_url(server: &str, pdb_name: &str, guid: &PdbGuid, age: u32) -> String {
    format!(
        "{}/{}/{}{:X}/{}",
        server,
        pdb_name,
        guid.to_symbol_server_str(),
        age,
        pdb_name,
    )
}

/// Extract PDB debug info from a PE file's debug directory.
///
/// This looks for the `IMAGE_DEBUG_TYPE_CODEVIEW` (2) entry and parses its
/// `RSDS` header.  Returns `(pdb_filename, guid, age)` on success.
#[must_use]
pub fn extract_pdb_info(pe_bytes: &[u8]) -> Option<PdbDebugInfo> {
    // Check MZ
    if pe_bytes.len() < 0x40 || &pe_bytes[..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(pe_bytes[0x3C..0x40].try_into().ok()?) as usize;
    if e_lfanew + 4 > pe_bytes.len() {
        return None;
    }
    if &pe_bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }

    // Read Optional Header to find the debug directory.
    let coff_offset = e_lfanew + 4;
    if coff_offset + 20 > pe_bytes.len() { return None; }
    let size_of_optional = u16::from_le_bytes(
        pe_bytes[coff_offset + 16..coff_offset + 18].try_into().ok()?,
    ) as usize;
    let optional_start = coff_offset + 20;
    let magic = u16::from_le_bytes(
        pe_bytes.get(optional_start..optional_start + 2)?.try_into().ok()?,
    );

    // Debug directory is data directory entry 6 (IMAGE_DIRECTORY_ENTRY_DEBUG).
    // For PE32+ (magic=0x20B): data directories start at optional_start + 112.
    // For PE32 (magic=0x10B): data directories start at optional_start + 96.
    let dd_start = optional_start + if magic == 0x20B { 112 } else { 96 };
    let debug_dd_offset = dd_start + 6 * 8;
    if debug_dd_offset + 8 > pe_bytes.len() { return None; }
    let debug_va = u32::from_le_bytes(
        pe_bytes[debug_dd_offset..debug_dd_offset + 4].try_into().ok()?,
    ) as usize;
    let debug_size = u32::from_le_bytes(
        pe_bytes[debug_dd_offset + 4..debug_dd_offset + 8].try_into().ok()?,
    ) as usize;
    if debug_size == 0 { return None; }

    // Find the raw offset of the debug directory by scanning sections.
    let section_table_start = optional_start + size_of_optional;
    let num_sections = u16::from_le_bytes(
        pe_bytes[coff_offset + 2..coff_offset + 4].try_into().ok()?,
    ) as usize;

    let debug_raw = va_to_raw(pe_bytes, usize_to_u32(debug_va), section_table_start, num_sections)?;

    // Scan IMAGE_DEBUG_DIRECTORY entries (each 28 bytes).
    let mut offset = debug_raw;
    let end = offset + debug_size;
    while offset + 28 <= end.min(pe_bytes.len()) {
        let debug_type = u32::from_le_bytes(
            pe_bytes[offset + 12..offset + 16].try_into().ok()?,
        );
        if debug_type == 2 {
            // CODEVIEW
            let data_size = u32::from_le_bytes(
                pe_bytes[offset + 16..offset + 20].try_into().ok()?,
            ) as usize;
            let data_ptr = u32::from_le_bytes(
                pe_bytes[offset + 24..offset + 28].try_into().ok()?,
            ) as usize;
            if data_ptr + data_size > pe_bytes.len() { return None; }
            return parse_rsds(&pe_bytes[data_ptr..data_ptr + data_size]);
        }
        offset += 28;
    }
    None
}

/// Result of parsing an RSDS `CodeView` record from a PE debug directory.
#[derive(Debug, Clone)]
pub struct PdbDebugInfo {
    pub pdb_path: String,
    pub guid: PdbGuid,
    pub age: u32,
}

impl PdbDebugInfo {
    /// Build the full download URL using the Microsoft symbol server.
    #[must_use]
    pub fn download_url(&self) -> String {
        let pdb_name = self.pdb_path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(&self.pdb_path);
        build_pdb_url(MS_SYMBOL_SERVER, pdb_name, &self.guid, self.age)
    }
}

/// Parse an RSDS `CodeView` record.  Format:
/// `"RSDS"(4) | GUID(16) | Age(4) | PdbPath(NUL-terminated)`
fn parse_rsds(data: &[u8]) -> Option<PdbDebugInfo> {
    if data.len() < 24 { return None; }
    if &data[..4] != b"RSDS" { return None; }
    let guid_bytes: &[u8; 16] = data[4..20].try_into().ok()?;
    let guid = PdbGuid::from_bytes(guid_bytes);
    let age = u32::from_le_bytes(data[20..24].try_into().ok()?);
    let path_bytes = &data[24..];
    let null_pos = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
    let pdb_path = String::from_utf8_lossy(&path_bytes[..null_pos]).into_owned();
    Some(PdbDebugInfo { pdb_path, guid, age })
}

/// Convert a virtual address to a raw file offset using the section table.
fn va_to_raw(
    pe: &[u8],
    va: u32,
    section_table_start: usize,
    num_sections: usize,
) -> Option<usize> {
    for i in 0..num_sections {
        let s = section_table_start + i * 40;
        if s + 40 > pe.len() { break; }
        let virt_addr = u32::from_le_bytes(pe[s + 12..s + 16].try_into().ok()?);
        let virt_size = u32::from_le_bytes(pe[s + 8..s + 12].try_into().ok()?);
        let raw_offset = u32::from_le_bytes(pe[s + 20..s + 24].try_into().ok()?);
        // Both operands come from a hostile section header, so a wrapping
        // `virt_addr + virt_size` would silently skip the section.
        if va >= virt_addr && va < virt_addr.saturating_add(virt_size) {
            return raw_offset.checked_add(va - virt_addr).map(|v| v as usize);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Minimal PDB7 parser for field offsets
// ---------------------------------------------------------------------------

/// The PDB7 magic string at the start of the file.
pub const PDB7_MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00";

/// Parsed PDB7 super-block (multi-stream file header).
#[derive(Debug, Clone)]
pub struct Pdb7SuperBlock {
    pub block_size: u32,
    pub free_block_map_block: u32,
    pub num_blocks: u32,
    pub num_directory_bytes: u32,
    pub block_map_addr: u32,
}

impl Pdb7SuperBlock {
    /// Parse the PDB7 super-block from the beginning of a PDB file.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 64 { return None; }
        if &data[..32] != PDB7_MAGIC.as_ref() {
            return None;
        }
        Some(Self {
            block_size: u32::from_le_bytes(data[32..36].try_into().ok()?),
            free_block_map_block: u32::from_le_bytes(data[36..40].try_into().ok()?),
            num_blocks: u32::from_le_bytes(data[40..44].try_into().ok()?),
            num_directory_bytes: u32::from_le_bytes(data[44..48].try_into().ok()?),
            block_map_addr: u32::from_le_bytes(data[52..56].try_into().ok()?),
        })
    }

    /// Compute the offset of a block by its block number.
    #[must_use]
    pub const fn block_offset(&self, block_num: u32) -> usize {
        (block_num as usize) * (self.block_size as usize)
    }
}

/// A field offset record extracted from a PDB type stream.
#[derive(Debug, Clone)]
pub struct PdbFieldOffset {
    /// The containing struct/class type name.
    pub struct_name: String,
    /// The field name.
    pub field_name: String,
    /// Byte offset of the field within the struct.
    pub offset: u32,
    /// Size of the field in bytes.
    pub field_size: u32,
}

/// Parse a very small subset of the DBI / type stream to extract field offsets.
///
/// In a real implementation this would use a full `CodeView` type stream parser.
/// Here we scan for the `LF_MEMBER` (0x150D) leaf in the data and extract
/// offset + name pairs.
#[must_use]
pub fn scan_pdb_field_offsets(pdb_stream: &[u8], struct_name: &str) -> Vec<PdbFieldOffset> {
    const LF_MEMBER: u16 = 0x150D;
    let mut results = Vec::new();
    let mut i = 0usize;
    while i + 8 <= pdb_stream.len() {
        let leaf = u16::from_le_bytes([pdb_stream[i], pdb_stream[i + 1]]);
        if leaf == LF_MEMBER {
            // LF_MEMBER: leaf(2) | attr(2) | type(4) | offset(4) | name(\0)
            if i + 12 > pdb_stream.len() { break; }
            let offset_val = u32::from_le_bytes(
                pdb_stream[i + 8..i + 12].try_into().unwrap_or([0; 4]),
            );
            // Read the null-terminated field name after offset
            let name_start = i + 12;
            let name_end = pdb_stream[name_start..]
                .iter()
                .position(|&b| b == 0)
                .map_or(pdb_stream.len(), |p| name_start + p);
            let field_name = String::from_utf8_lossy(&pdb_stream[name_start..name_end])
                .into_owned();
            results.push(PdbFieldOffset {
                struct_name: struct_name.to_string(),
                field_name,
                offset: offset_val,
                field_size: 0, // requires type lookup, not implemented here
            });
            i = name_end + 1;
            continue;
        }
        i += 2;
    }
    results
}

// ---------------------------------------------------------------------------
// Linux KASLR detection
// ---------------------------------------------------------------------------

/// The `linux_banner` string that appears near the start of kernel `.rodata`.
/// Typical value: `Linux version 5.15.0 ...`.
pub const LINUX_BANNER_PREFIX: &[u8] = b"Linux version ";

/// Page size used for alignment during kernel base search.
pub const KASLR_ALIGN: usize = 0x200_000; // 2 MiB

/// ELF64 magic bytes.
pub const ELF_MAGIC: &[u8; 4] = b"\x7FELF";

/// ELF `e_type`: `ET_EXEC`.
pub const ET_EXEC: u16 = 2;

/// Detected Linux kernel info.
#[derive(Debug, Clone)]
pub struct LinuxKernelInfo {
    /// Physical offset of the kernel ELF header in the dump.
    pub phys_offset: u64,
    /// Kernel version string (e.g. "5.15.0-generic").
    pub version_string: String,
    /// Whether KASLR is likely active (base != default load address).
    pub kaslr_active: bool,
    /// Default kernel load address (without KASLR).
    pub default_load_addr: u64,
}

/// Scan a raw memory buffer for the Linux kernel base address and version.
///
/// Strategy:
/// 1. Search at 2 MiB aligned offsets for the ELF64 magic `\x7FELF`.
/// 2. At each candidate, try to find the `linux_banner` string within the
///    next 1 MiB (it lives in `.rodata`).
/// 3. Report the first match.
#[must_use]
pub fn detect_linux_kernel(memory: &[u8]) -> Option<LinuxKernelInfo> {
    let mut off = 0usize;
    while off + 4 <= memory.len() {
        if &memory[off..off + 4] == ELF_MAGIC.as_ref() {
            // Verify this looks like a 64-bit ELF.
            if off + 16 > memory.len() { off += KASLR_ALIGN; continue; }
            let ei_class = memory[off + 4];
            let ei_data = memory[off + 5];
            if ei_class != 2 || ei_data != 1 {
                // Not ELF64 LE
                off += KASLR_ALIGN;
                continue;
            }
            // Search for linux_banner within the next 1 MiB.
            let search_end = (off + 0x10_0000).min(memory.len());
            let banner_window = &memory[off..search_end];
            if let Some(rel) = banner_window
                .windows(LINUX_BANNER_PREFIX.len())
                .position(|w| w == LINUX_BANNER_PREFIX)
            {
                let banner_start = off + rel;
                let banner_end = memory[banner_start..]
                    .iter()
                    .position(|&b| b == b'\n' || b == 0)
                    .map_or(search_end, |p| banner_start + p);
                let version_string =
                    String::from_utf8_lossy(&memory[banner_start..banner_end]).into_owned();
                let phys_offset = off as u64;
                let default_load_addr = 0x100_0000u64; // typical x86_64 kernel phys base
                let kaslr_active = phys_offset != default_load_addr;
                return Some(LinuxKernelInfo {
                    phys_offset,
                    version_string,
                    kaslr_active,
                    default_load_addr,
                });
            }
        }
        off += KASLR_ALIGN;
    }
    None
}

/// Parse the kernel version from a `linux_banner` string.
///
/// Input: `"Linux version 5.15.0-generic #42-Ubuntu SMP ..."`
/// Output: `"5.15.0-generic"`.
#[must_use]
pub fn parse_kernel_version(banner: &str) -> Option<&str> {
    let rest = banner.strip_prefix("Linux version ")?;
    rest.split_whitespace().next()
}

/// Extract the numeric version triple `(major, minor, patch)` from a version string.
/// Accepts formats like `"5.15.0"`, `"5.15.0-generic"`, etc.
#[must_use]
pub fn parse_version_triple(version: &str) -> Option<(u32, u32, u32)> {
    let base = version.split('-').next()?;
    let mut parts = base.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    let patch = parts.next().unwrap_or("0").parse::<u32>().ok()?;
    Some((major, minor, patch))
}

// ---------------------------------------------------------------------------
// Profile cache
// ---------------------------------------------------------------------------

/// A set of field offsets for a specific OS build.
#[derive(Debug, Clone)]
pub struct FieldOffsets {
    /// Map from "StructName.FieldName" to byte offset.
    pub offsets: HashMap<String, u32>,
    /// Map from "StructName.FieldName" to size in bytes.
    pub sizes: HashMap<String, u32>,
}

impl FieldOffsets {
    #[must_use]
    pub fn new() -> Self {
        Self {
            offsets: HashMap::new(),
            sizes: HashMap::new(),
        }
    }

    /// Insert an offset entry.
    pub fn insert(&mut self, struct_name: &str, field_name: &str, offset: u32) {
        let key = format!("{struct_name}.{field_name}");
        self.offsets.insert(key, offset);
    }

    /// Retrieve an offset, returning `None` if not found.
    #[must_use]
    pub fn get(&self, struct_name: &str, field_name: &str) -> Option<u32> {
        let key = format!("{struct_name}.{field_name}");
        self.offsets.get(&key).copied()
    }

    /// Insert from a slice of (struct, field, offset) tuples.
    pub fn bulk_insert(&mut self, entries: &[(&str, &str, u32)]) {
        for &(s, f, o) in entries {
            self.insert(s, f, o);
        }
    }
}

impl Default for FieldOffsets {
    fn default() -> Self { Self::new() }
}

/// A profile cache that maps build fingerprints to their `FieldOffsets`.
#[derive(Debug, Default)]
pub struct ProfileCache {
    windows: HashMap<WindowsFingerprint, FieldOffsets>,
    linux: HashMap<(u32, u32, u32), FieldOffsets>, // (major, minor, patch)
}

impl ProfileCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store Windows offsets for a fingerprint.
    pub fn insert_windows(&mut self, fp: WindowsFingerprint, offsets: FieldOffsets) {
        self.windows.insert(fp, offsets);
    }

    /// Retrieve Windows offsets, falling back to the closest build.
    #[must_use]
    pub fn get_windows(&self, fp: &WindowsFingerprint) -> Option<&FieldOffsets> {
        // Exact match first.
        if let Some(o) = self.windows.get(fp) {
            return Some(o);
        }
        // Fall back: same major.minor, closest build number.
        let mut best: Option<(&WindowsFingerprint, &FieldOffsets)> = None;
        for (key, val) in &self.windows {
            if key.major == fp.major && key.minor == fp.minor && key.arch == fp.arch {
                match best {
                    None => best = Some((key, val)),
                    Some((prev_key, _)) => {
                        if (i64::from(key.build) - i64::from(fp.build)).abs()
                            < (i64::from(prev_key.build) - i64::from(fp.build)).abs()
                        {
                            best = Some((key, val));
                        }
                    }
                }
            }
        }
        best.map(|(_, v)| v)
    }

    /// Store Linux offsets for a kernel version triple.
    pub fn insert_linux(&mut self, version: (u32, u32, u32), offsets: FieldOffsets) {
        self.linux.insert(version, offsets);
    }

    /// Retrieve Linux offsets for a version triple.
    #[must_use]
    pub fn get_linux(&self, version: &(u32, u32, u32)) -> Option<&FieldOffsets> {
        self.linux.get(version)
    }

    /// Returns the number of Windows profiles stored.
    #[must_use]
    pub fn windows_count(&self) -> usize {
        self.windows.len()
    }

    /// Returns the number of Linux profiles stored.
    #[must_use]
    pub fn linux_count(&self) -> usize {
        self.linux.len()
    }
}

// ---------------------------------------------------------------------------
// Pre-built profiles
// ---------------------------------------------------------------------------

/// Build the Win10 x64 19041 profile with standard _EPROCESS offsets.
#[must_use]
pub fn win10_x64_19041_profile() -> FieldOffsets {
    let mut fo = FieldOffsets::new();
    fo.bulk_insert(&[
        ("_EPROCESS", "UniqueProcessId",             0x2E8),
        ("_EPROCESS", "ActiveProcessLinks",           0x2F0),
        ("_EPROCESS", "InheritedFromUniqueProcessId", 0x3E8),
        ("_EPROCESS", "ImageFileName",                0x450),
        ("_EPROCESS", "Peb",                          0x550),
        ("_EPROCESS", "VadRoot",                      0x7D8),
        ("_EPROCESS", "ObjectTable",                  0x570),
        ("_EPROCESS", "Token",                        0x4B8),
        ("_EPROCESS", "CreateTime",                   0x2C8),
        ("_EPROCESS", "ExitTime",                     0x2D0),
        ("_EPROCESS", "ActiveThreads",                0x5F0),
        ("_EPROCESS", "ExitStatus",                   0x47C),
        ("_EPROCESS", "SectionBaseAddress",            0x520),
        ("_EPROCESS", "DirectoryTableBase",            0x028),
        ("_ETHREAD",  "Cid",                          0x3F8),
        ("_ETHREAD",  "Win32StartAddress",             0x450),
        ("_ETHREAD",  "CreateTime",                   0x2C8),
        ("_ETHREAD",  "ExitStatus",                   0x468),
        ("_KTHREAD",  "InitialStack",                 0x028),
        ("_KTHREAD",  "StackLimit",                   0x030),
        ("_KTHREAD",  "KernelStack",                  0x058),
        ("_KTHREAD",  "Teb",                          0x0F0),
        ("_KTHREAD",  "State",                        0x184),
        ("_PEB",      "Ldr",                          0x018),
        ("_PEB",      "ProcessParameters",            0x020),
        ("_PEB",      "ImageBaseAddress",             0x010),
        ("_PEB",      "BeingDebugged",                0x002),
        ("_LDR_DATA_TABLE_ENTRY", "DllBase",          0x030),
        ("_LDR_DATA_TABLE_ENTRY", "SizeOfImage",      0x040),
        ("_LDR_DATA_TABLE_ENTRY", "FullDllName",      0x048),
        ("_LDR_DATA_TABLE_ENTRY", "BaseDllName",      0x058),
        ("_RTL_USER_PROCESS_PARAMETERS", "CommandLine", 0x070),
        ("_RTL_USER_PROCESS_PARAMETERS", "ImagePathName", 0x060),
    ]);
    fo
}

/// Build the Win7 x64 7601 profile.
#[must_use]
pub fn win7_x64_7601_profile() -> FieldOffsets {
    let mut fo = FieldOffsets::new();
    fo.bulk_insert(&[
        ("_EPROCESS", "UniqueProcessId",             0x180),
        ("_EPROCESS", "ActiveProcessLinks",           0x188),
        ("_EPROCESS", "InheritedFromUniqueProcessId", 0x2D8),
        ("_EPROCESS", "ImageFileName",                0x2D0),
        ("_EPROCESS", "Peb",                          0x338),
        ("_EPROCESS", "VadRoot",                      0x448),
        ("_EPROCESS", "ObjectTable",                  0x200),
        ("_EPROCESS", "Token",                        0x208),
        ("_EPROCESS", "CreateTime",                   0x148),
        ("_EPROCESS", "ExitTime",                     0x150),
        ("_ETHREAD",  "Cid",                          0x3B0),
        ("_ETHREAD",  "Win32StartAddress",             0x3F8),
        ("_PEB",      "Ldr",                          0x018),
        ("_PEB",      "ProcessParameters",            0x020),
        ("_PEB",      "ImageBaseAddress",             0x010),
    ]);
    fo
}

/// Build the Linux 5.15 `x86_64` profile.
#[must_use]
pub fn linux_515_x64_profile() -> FieldOffsets {
    let mut fo = FieldOffsets::new();
    fo.bulk_insert(&[
        ("task_struct", "state",         0x0000),
        ("task_struct", "flags",         0x001C),
        ("task_struct", "pid",           0x02B8),
        ("task_struct", "tgid",          0x02BC),
        ("task_struct", "real_parent",   0x02C0),
        ("task_struct", "comm",          0x0650),
        ("task_struct", "mm",            0x0590),
        ("task_struct", "active_mm",     0x0598),
        ("task_struct", "cred",          0x07C8),
        ("task_struct", "files",         0x0740),
        ("task_struct", "signal",        0x0770),
        ("task_struct", "exit_code",     0x0A18),
        ("task_struct", "start_time",    0x0B30),
        ("mm_struct",   "mmap",          0x0000),
        ("mm_struct",   "pgd",           0x0040),
        ("mm_struct",   "total_vm",      0x02B0),
        ("mm_struct",   "start_code",    0x0460),
        ("mm_struct",   "end_code",      0x0468),
        ("mm_struct",   "start_brk",     0x04A0),
        ("mm_struct",   "brk",           0x04A8),
        ("mm_struct",   "start_stack",   0x04B0),
        ("vm_area_struct", "vm_start",   0x0000),
        ("vm_area_struct", "vm_end",     0x0008),
        ("vm_area_struct", "vm_flags",   0x0050),
        ("vm_area_struct", "vm_file",    0x0090),
        ("cred", "uid",                  0x0004),
        ("cred", "euid",                 0x0014),
        ("cred", "cap_effective",        0x0038),
    ]);
    fo
}

/// Initialize a `ProfileCache` with the built-in profiles.
#[must_use]
pub fn default_profile_cache() -> ProfileCache {
    let mut cache = ProfileCache::new();
    cache.insert_windows(
        WindowsFingerprint::new(10, 0, 19041, ArchWidth::X64),
        win10_x64_19041_profile(),
    );
    cache.insert_windows(
        WindowsFingerprint::new(6, 1, 7601, ArchWidth::X64),
        win7_x64_7601_profile(),
    );
    cache.insert_linux((5, 15, 0), linux_515_x64_profile());
    cache
}

// ---------------------------------------------------------------------------
// Inline helpers
// ---------------------------------------------------------------------------

fn read_u64_at(memory: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let slice: &[u8] = memory.get(offset..end)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}

fn read_u32_at(memory: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let slice: &[u8] = memory.get(offset..end)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- WindowsFingerprint ----

    #[test]
    fn fingerprint_tag_win10() {
        let fp = WindowsFingerprint::new(10, 0, 19041, ArchWidth::X64);
        assert_eq!(fp.tag(), "Win10.0-x64-19041");
    }

    #[test]
    fn fingerprint_equality() {
        let a = WindowsFingerprint::new(10, 0, 19041, ArchWidth::X64);
        let b = WindowsFingerprint::new(10, 0, 19041, ArchWidth::X64);
        assert_eq!(a, b);
    }

    #[test]
    fn arch_ptr_size_x64() {
        assert_eq!(ArchWidth::X64.ptr_size(), 8);
    }

    #[test]
    fn arch_ptr_size_x86() {
        assert_eq!(ArchWidth::X86.ptr_size(), 4);
    }

    // ---- scan_kdbg ----

    fn make_kdbg_buf() -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];
        // Place "KDBG" tag at offset 0
        buf[0..4].copy_from_slice(b"KDBG");
        // KernBase at KDBG_KERN_BASE_OFFSET
        buf[KDBG_KERN_BASE_OFFSET..KDBG_KERN_BASE_OFFSET + 8]
            .copy_from_slice(&0xFFFF_F800_0200_0000u64.to_le_bytes());
        // PsActiveProcessHead
        buf[KDBG_PS_ACTIVE_PROCESS_HEAD_OFFSET..KDBG_PS_ACTIVE_PROCESS_HEAD_OFFSET + 8]
            .copy_from_slice(&0xFFFF_F800_0400_0000u64.to_le_bytes());
        // PsLoadedModuleList
        buf[KDBG_PS_LOADED_MODULE_LIST_OFFSET..KDBG_PS_LOADED_MODULE_LIST_OFFSET + 8]
            .copy_from_slice(&0xFFFF_F800_0500_0000u64.to_le_bytes());
        // ServiceDescriptorTable
        if KDBG_SERVICE_DESCRIPTOR_TABLE_OFFSET + 8 < buf.len() {
            buf[KDBG_SERVICE_DESCRIPTOR_TABLE_OFFSET..KDBG_SERVICE_DESCRIPTOR_TABLE_OFFSET + 8]
                .copy_from_slice(&0xFFFF_F800_1234_0000u64.to_le_bytes());
        }
        // BuildNumber at KDBG_BUILD_NUMBER_OFFSET
        buf[KDBG_BUILD_NUMBER_OFFSET..KDBG_BUILD_NUMBER_OFFSET + 4]
            .copy_from_slice(&19041u32.to_le_bytes());
        buf
    }

    #[test]
    fn scan_kdbg_finds_entry() {
        let buf = make_kdbg_buf();
        let results = scan_kdbg(&buf);
        assert!(!results.is_empty(), "expected at least one KDBG");
    }

    #[test]
    fn scan_kdbg_build_number() {
        let buf = make_kdbg_buf();
        let results = scan_kdbg(&buf);
        assert_eq!(results[0].build_number, 19041);
    }

    #[test]
    fn scan_kdbg_kern_base() {
        let buf = make_kdbg_buf();
        let results = scan_kdbg(&buf);
        assert_eq!(results[0].kern_base, 0xFFFF_F800_0200_0000);
    }

    #[test]
    fn scan_kdbg_ps_active_process_head() {
        let buf = make_kdbg_buf();
        let results = scan_kdbg(&buf);
        assert_eq!(results[0].ps_active_process_head, 0xFFFF_F800_0400_0000);
    }

    #[test]
    fn scan_kdbg_empty_memory() {
        let results = scan_kdbg(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn scan_kdbg_no_tag() {
        let buf = vec![0u8; 512];
        let results = scan_kdbg(&buf);
        assert!(results.is_empty());
    }

    // ---- PdbGuid ----

    #[test]
    fn pdb_guid_to_symbol_server_str() {
        let bytes: [u8; 16] = [
            0xAA, 0xBB, 0xCC, 0xDD, // data1 (LE) -> DDCCBBAA
            0xEE, 0xFF,               // data2 (LE) -> FFEE
            0x11, 0x22,               // data3 (LE) -> 2211
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        ];
        let guid = PdbGuid::from_bytes(&bytes);
        let s = guid.to_symbol_server_str();
        assert_eq!(s, "DDCCBBAAFFEE22113344556677889900");
    }

    #[test]
    fn build_pdb_url_format() {
        let bytes = [0u8; 16];
        let guid = PdbGuid::from_bytes(&bytes);
        let url = build_pdb_url(MS_SYMBOL_SERVER, "ntoskrnl.pdb", &guid, 1);
        assert!(url.starts_with(MS_SYMBOL_SERVER));
        assert!(url.contains("ntoskrnl.pdb"));
        // MS symbol server format concatenates GUID and age without a separator
        assert!(url.contains("1/ntoskrnl.pdb"));
    }

    // ---- RSDS parsing ----

    fn make_rsds_buf() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"RSDS");
        // GUID (16 bytes)
        let guid_bytes = [
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06,
            0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        buf.extend_from_slice(&guid_bytes);
        // Age = 2
        buf.extend_from_slice(&2u32.to_le_bytes());
        // PDB path
        buf.extend_from_slice(b"C:\\ProgramData\\ntoskrnl.pdb\0");
        buf
    }

    #[test]
    fn rsds_parse_path() {
        let buf = make_rsds_buf();
        let info = parse_rsds(&buf).unwrap();
        assert!(info.pdb_path.contains("ntoskrnl.pdb"));
    }

    #[test]
    fn rsds_parse_age() {
        let buf = make_rsds_buf();
        let info = parse_rsds(&buf).unwrap();
        assert_eq!(info.age, 2);
    }

    #[test]
    fn rsds_parse_invalid_magic() {
        let mut buf = make_rsds_buf();
        buf[0] = b'X';
        assert!(parse_rsds(&buf).is_none());
    }

    #[test]
    fn pdb_debug_info_download_url() {
        let buf = make_rsds_buf();
        let info = parse_rsds(&buf).unwrap();
        let url = info.download_url();
        assert!(url.contains("ntoskrnl.pdb"));
        assert!(url.starts_with("https://msdl.microsoft.com"));
    }

    // ---- Linux detection ----

    fn make_linux_mem() -> Vec<u8> {
        let mut mem = vec![0u8; KASLR_ALIGN * 4];
        // Place ELF header at 2nd 2 MiB aligned offset
        let base = KASLR_ALIGN * 2;
        mem[base..base + 4].copy_from_slice(b"\x7FELF");
        mem[base + 4] = 2; // ELFCLASS64
        mem[base + 5] = 1; // ELFDATA2LSB
        // Place linux_banner 0x2000 bytes after the ELF header
        let banner_off = base + 0x2000;
        let banner = b"Linux version 5.15.0-generic #42-Ubuntu SMP foo\n";
        mem[banner_off..banner_off + banner.len()].copy_from_slice(banner);
        mem
    }

    #[test]
    fn detect_linux_kernel_found() {
        let mem = make_linux_mem();
        let info = detect_linux_kernel(&mem);
        assert!(info.is_some());
    }

    #[test]
    fn detect_linux_kernel_version() {
        let mem = make_linux_mem();
        let info = detect_linux_kernel(&mem).unwrap();
        assert!(info.version_string.contains("5.15.0"));
    }

    #[test]
    fn detect_linux_kernel_kaslr() {
        let mem = make_linux_mem();
        let info = detect_linux_kernel(&mem).unwrap();
        // Base is 4 MiB, default is 1 MiB -> KASLR active
        assert!(info.kaslr_active);
    }

    #[test]
    fn detect_linux_kernel_empty() {
        let mem = vec![0u8; 1024];
        assert!(detect_linux_kernel(&mem).is_none());
    }

    #[test]
    fn parse_kernel_version_basic() {
        let banner = "Linux version 5.15.0-generic #42-Ubuntu SMP";
        let ver = parse_kernel_version(banner).unwrap();
        assert_eq!(ver, "5.15.0-generic");
    }

    #[test]
    fn parse_version_triple_basic() {
        let (maj, min, patch) = parse_version_triple("5.15.0-generic").unwrap();
        assert_eq!((maj, min, patch), (5, 15, 0));
    }

    #[test]
    fn parse_version_triple_no_patch() {
        let (maj, min, patch) = parse_version_triple("5.15").unwrap();
        assert_eq!((maj, min, patch), (5, 15, 0));
    }

    // ---- Profile cache ----

    #[test]
    fn profile_cache_insert_and_get_windows() {
        let mut cache = ProfileCache::new();
        let fp = WindowsFingerprint::new(10, 0, 19041, ArchWidth::X64);
        let mut fo = FieldOffsets::new();
        fo.insert("_EPROCESS", "Peb", 0x550);
        cache.insert_windows(fp.clone(), fo);
        let retrieved = cache.get_windows(&fp).unwrap();
        assert_eq!(retrieved.get("_EPROCESS", "Peb"), Some(0x550));
    }

    #[test]
    fn profile_cache_fallback_to_closest_build() {
        let mut cache = ProfileCache::new();
        let fp19041 = WindowsFingerprint::new(10, 0, 19041, ArchWidth::X64);
        let mut fo = FieldOffsets::new();
        fo.insert("_EPROCESS", "Peb", 0x550);
        cache.insert_windows(fp19041, fo);
        // Query with a nearby build
        let fp19045 = WindowsFingerprint::new(10, 0, 19045, ArchWidth::X64);
        let retrieved = cache.get_windows(&fp19045).unwrap();
        assert_eq!(retrieved.get("_EPROCESS", "Peb"), Some(0x550));
    }

    #[test]
    fn profile_cache_insert_and_get_linux() {
        let mut cache = ProfileCache::new();
        let mut fo = FieldOffsets::new();
        fo.insert("task_struct", "pid", 0x02B8);
        cache.insert_linux((5, 15, 0), fo);
        let retrieved = cache.get_linux(&(5, 15, 0)).unwrap();
        assert_eq!(retrieved.get("task_struct", "pid"), Some(0x02B8));
    }

    #[test]
    fn default_profile_cache_windows_count() {
        let cache = default_profile_cache();
        assert!(cache.windows_count() >= 2);
    }

    #[test]
    fn default_profile_cache_linux_count() {
        let cache = default_profile_cache();
        assert!(cache.linux_count() >= 1);
    }

    #[test]
    fn win10_profile_eprocess_peb_offset() {
        let cache = default_profile_cache();
        let fp = WindowsFingerprint::new(10, 0, 19041, ArchWidth::X64);
        let fo = cache.get_windows(&fp).unwrap();
        assert_eq!(fo.get("_EPROCESS", "Peb"), Some(0x550));
    }

    #[test]
    fn win7_profile_eprocess_apl_offset() {
        let cache = default_profile_cache();
        let fp = WindowsFingerprint::new(6, 1, 7601, ArchWidth::X64);
        let fo = cache.get_windows(&fp).unwrap();
        assert_eq!(fo.get("_EPROCESS", "ActiveProcessLinks"), Some(0x188));
    }

    #[test]
    fn linux_profile_task_comm_offset() {
        let fo = linux_515_x64_profile();
        assert_eq!(fo.get("task_struct", "comm"), Some(0x0650));
    }

    #[test]
    fn field_offsets_bulk_insert() {
        let mut fo = FieldOffsets::new();
        fo.bulk_insert(&[
            ("A", "x", 0x10),
            ("A", "y", 0x18),
            ("B", "z", 0x20),
        ]);
        assert_eq!(fo.get("A", "x"), Some(0x10));
        assert_eq!(fo.get("B", "z"), Some(0x20));
        assert_eq!(fo.get("A", "missing"), None);
    }

    #[test]
    fn pdb7_superblock_invalid_magic() {
        let buf = vec![0u8; 64];
        assert!(Pdb7SuperBlock::parse(&buf).is_none());
    }

    #[test]
    fn scan_pdb_field_offsets_finds_lf_member() {
        // Build a minimal fake type stream with one LF_MEMBER entry
        let mut buf: Vec<u8> = Vec::new();
        // leaf = LF_MEMBER (0x150D)
        buf.extend_from_slice(&0x150Du16.to_le_bytes());
        // attr (2 bytes)
        buf.extend_from_slice(&0u16.to_le_bytes());
        // type index (4 bytes)
        buf.extend_from_slice(&0u32.to_le_bytes());
        // offset (4 bytes) = 0x2E8
        buf.extend_from_slice(&0x2E8u32.to_le_bytes());
        // field name + null
        buf.extend_from_slice(b"UniqueProcessId\0");
        // Some garbage at the end
        buf.extend_from_slice(&[0xFE, 0xFF, 0xAA]);
        let results = scan_pdb_field_offsets(&buf, "_EPROCESS");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].field_name, "UniqueProcessId");
        assert_eq!(results[0].offset, 0x2E8);
    }

    #[test]
    fn scan_pdb_field_offsets_empty() {
        let results = scan_pdb_field_offsets(&[], "_EPROCESS");
        assert!(results.is_empty());
    }
}
