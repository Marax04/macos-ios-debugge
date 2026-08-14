//! VAD (Virtual Address Descriptor) tree traversal and analysis.
//!
//! The Windows kernel tracks per-process virtual memory using a red-black
//! tree of `_MMVAD` / `_VAD_NODE` structures rooted at
//! `_EPROCESS.VadRoot`.  This module provides:
//!
//! - In-order traversal of the red-black tree given a memory accessor.
//! - Classification of VAD nodes into: Private, `MappedFile`, `ImageSection`,
//!   Shared, Physical.
//! - Decoding of VAD protection flags (`PAGE_READONLY`, `PAGE_EXECUTE_READWRITE`,
//!   etc.) from the `_MMVAD_FLAGS` union.
//! - Address lookup: find the VAD containing a given virtual address.
//! - Enumeration of all VADs in a process.
//! - Suspicious VAD detection: RWX private pages = injection candidate.
//! - File-backing resolution: `Subsection -> FileObject -> filename` chain.

use crate::casts::u64_to_usize;
use crate::windows_structs::{
    MmVadFlags, VadNode,
    VAD_LEFT_CHILD_OFFSET, VAD_RIGHT_CHILD_OFFSET,
    VAD_STARTING_VPN_OFFSET, VAD_ENDING_VPN_OFFSET,
    VAD_FLAGS_OFFSET, VAD_SUBSECTION_OFFSET,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ, PAGE_READWRITE,
    PAGE_READONLY, PAGE_EXECUTE, PAGE_NOACCESS, PAGE_WRITECOPY,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOCACHE,
    protection_name,
};

// ---------------------------------------------------------------------------
// Page size
// ---------------------------------------------------------------------------

pub const PAGE_SIZE: u64 = 0x1000;

// ---------------------------------------------------------------------------
// VAD classification
// ---------------------------------------------------------------------------

/// The category of a VAD node, derived from `_MMVAD_FLAGS.VadType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VadCategory {
    /// Private committed / reserved memory (no file backing).
    Private,
    /// Memory-mapped file (data file, not an executable image).
    MappedFile,
    /// Image section (executable PE/ELF loaded as a section).
    ImageSection,
    /// Shared memory (backed by a pagefile section, not a file).
    Shared,
    /// Physical memory mapping (e.g., for a device driver).
    Physical,
    /// Heap or stack region (heuristically detected).
    HeapOrStack,
    /// Unknown / not yet classified.
    Unknown,
}

impl VadCategory {
    /// Derive a category from the `_MMVAD_FLAGS.vad_type` nibble and
    /// the `private_memory` flag.
    #[must_use]
    pub const fn from_flags(flags: &MmVadFlags) -> Self {
        if flags.private_memory {
            return Self::Private;
        }
        match flags.vad_type {
            0 => Self::Private,
            1 => Self::MappedFile,
            2 => Self::ImageSection,
            3 => Self::Shared,
            4 => Self::Physical,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Private => "Private",
            Self::MappedFile => "MappedFile",
            Self::ImageSection => "ImageSection",
            Self::Shared => "Shared",
            Self::Physical => "Physical",
            Self::HeapOrStack => "HeapOrStack",
            Self::Unknown => "Unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// Protection flags
// ---------------------------------------------------------------------------

/// Bitfield encoding of decoded Windows page protection flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageProtectionFlags(pub u8);

impl PageProtectionFlags {
    const READABLE: u8      = 0x01;
    const WRITABLE: u8      = 0x02;
    const EXECUTABLE: u8    = 0x04;
    const COPY_ON_WRITE: u8 = 0x08;
    const GUARD: u8         = 0x10;
    const NO_CACHE: u8      = 0x20;

    /// `true` if the region is readable.
    #[must_use] pub const fn is_readable(self) -> bool { self.0 & Self::READABLE != 0 }
    /// `true` if the region is writable.
    #[must_use] pub const fn is_writable(self) -> bool { self.0 & Self::WRITABLE != 0 }
    /// `true` if the region is executable.
    #[must_use] pub const fn is_executable(self) -> bool { self.0 & Self::EXECUTABLE != 0 }
    /// `true` if copy-on-write is set.
    #[must_use] pub const fn is_copy_on_write(self) -> bool { self.0 & Self::COPY_ON_WRITE != 0 }
    /// `true` if the guard page flag is set.
    #[must_use] pub const fn is_guard(self) -> bool { self.0 & Self::GUARD != 0 }
    /// `true` if the no-cache modifier is set.
    #[must_use] pub const fn is_no_cache(self) -> bool { self.0 & Self::NO_CACHE != 0 }
}

/// Full set of Windows page protection flags as a decoded struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageProtection {
    /// Raw Windows protection value (PAGE_* constant).
    pub raw: u32,
    /// Decoded protection flag bits.
    pub flags: PageProtectionFlags,
}

impl PageProtection {
    /// Decode a Windows page protection value.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        let base = raw & 0xFF;
        let readable = if matches!(
            base,
            PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        ) { PageProtectionFlags::READABLE } else { 0 };
        let writable = if matches!(
            base,
            PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY |
            PAGE_EXECUTE_WRITECOPY
        ) { PageProtectionFlags::WRITABLE } else { 0 };
        let executable = if matches!(
            base,
            PAGE_EXECUTE | PAGE_EXECUTE_READ |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        ) { PageProtectionFlags::EXECUTABLE } else { 0 };
        let cow = if matches!(base, PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)
            { PageProtectionFlags::COPY_ON_WRITE } else { 0 };
        let guard = if raw & PAGE_GUARD != 0 { PageProtectionFlags::GUARD } else { 0 };
        let nocache = if raw & PAGE_NOCACHE != 0 { PageProtectionFlags::NO_CACHE } else { 0 };
        Self {
            raw,
            flags: PageProtectionFlags(readable | writable | executable | cow | guard | nocache),
        }
    }

    /// Returns `true` for RWX memory (READ + WRITE + EXECUTE simultaneously).
    #[must_use]
    pub const fn is_rwx(&self) -> bool {
        self.flags.is_readable() && self.flags.is_writable() && self.flags.is_executable()
    }

    /// Human-readable protection string (e.g. "`PAGE_EXECUTE_READWRITE`").
    #[must_use]
    pub const fn name(&self) -> &'static str {
        protection_name(self.raw)
    }
}

/// Convert a VAD protection nibble (from `_MMVAD_FLAGS.Protection`) to a
/// Windows page protection constant.
///
/// The mapping is documented in the Windows Internals book and the `ReactOS`
/// source (`Mi_PROTECTION_TO_VAD_PROTECTION`):
///
/// | Nibble | Windows constant               |
/// |--------|-------------------------------|
/// | 0x00   | PAGE_NOACCESS                  |
/// | 0x01   | PAGE_READONLY                  |
/// | 0x02   | PAGE_EXECUTE                   |
/// | 0x03   | PAGE_EXECUTE_READ              |
/// | 0x04   | PAGE_READWRITE                 |
/// | 0x05   | PAGE_WRITECOPY                 |
/// | 0x06   | PAGE_EXECUTE_READWRITE         |
/// | 0x07   | PAGE_EXECUTE_WRITECOPY         |
/// | 0x08   | PAGE_NOACCESS (nocache)        |
/// | 0x09   | PAGE_READONLY | PAGE_NOCACHE   |
/// | 0x0A   | PAGE_EXECUTE | PAGE_NOCACHE    |
/// | 0x0B   | PAGE_EXECUTE_READ | NOCACHE    |
/// | 0x0C   | PAGE_READWRITE | NOCACHE       |
/// | 0x0D   | PAGE_WRITECOPY | NOCACHE       |
/// | 0x0E   | PAGE_EXECUTE_READWRITE|NOCACHE |
/// | 0x0F   | PAGE_EXECUTE_WRITECOPY|NOCACHE |
#[must_use]
pub const fn vad_prot_to_page_prot(vad_prot: u8) -> u32 {
    const TABLE: [u32; 16] = [
        PAGE_NOACCESS,                                // 0
        PAGE_READONLY,                                // 1
        PAGE_EXECUTE,                                 // 2
        PAGE_EXECUTE_READ,                            // 3
        PAGE_READWRITE,                               // 4
        PAGE_WRITECOPY,                               // 5
        PAGE_EXECUTE_READWRITE,                       // 6
        PAGE_EXECUTE_WRITECOPY,                       // 7
        PAGE_NOACCESS | PAGE_NOCACHE,                 // 8
        PAGE_READONLY | PAGE_NOCACHE,                 // 9
        PAGE_EXECUTE | PAGE_NOCACHE,                  // 10
        PAGE_EXECUTE_READ | PAGE_NOCACHE,             // 11
        PAGE_READWRITE | PAGE_NOCACHE,                // 12
        PAGE_WRITECOPY | PAGE_NOCACHE,                // 13
        PAGE_EXECUTE_READWRITE | PAGE_NOCACHE,        // 14
        PAGE_EXECUTE_WRITECOPY | PAGE_NOCACHE,        // 15
    ];
    TABLE[vad_prot as usize & 0xF]
}

// ---------------------------------------------------------------------------
// Full VAD entry (after traversal and enrichment)
// ---------------------------------------------------------------------------

/// A fully classified VAD entry, ready for reporting.
#[derive(Debug, Clone)]
pub struct VadEntry {
    /// Virtual address of the VAD node in kernel space.
    pub node_addr: u64,
    /// Start virtual address of the region (inclusive).
    pub start: u64,
    /// End virtual address of the region (exclusive).
    pub end: u64,
    /// Node category.
    pub category: VadCategory,
    /// Decoded page protection.
    pub protection: PageProtection,
    /// Raw VAD flags.
    pub flags: MmVadFlags,
    /// File name if file-backed, otherwise `None`.
    pub file_name: Option<String>,
    /// Commit charge (number of committed pages for private memory).
    pub commit_charge: u64,
    /// Whether this VAD is suspicious (RWX private without file backing).
    pub is_suspicious: bool,
    /// Reason for suspicion, if any.
    pub suspicion_reason: Option<String>,
}

impl VadEntry {
    /// Size of the region in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Returns `true` if the address falls within this VAD.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Format as a compact info line for display.
    #[must_use]
    pub fn info_line(&self) -> String {
        let file = self.file_name.as_deref().unwrap_or("");
        let susp = if self.is_suspicious { " [SUSPICIOUS]" } else { "" };
        format!(
            "{:#018x}-{:#018x} {:>14} {:>30}{} {}",
            self.start,
            self.end,
            self.category.name(),
            self.protection.name(),
            susp,
            file,
        )
    }
}

// ---------------------------------------------------------------------------
// Memory accessor trait
// ---------------------------------------------------------------------------

/// Provides raw byte access to process / physical memory.
pub trait MemoryReader: Send + Sync {
    /// Read `len` bytes from `addr`.  Returns `None` if the address is not
    /// accessible or if there are fewer than `len` bytes available.
    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>>;

    /// Convenience: read a `u64` from `addr`.
    fn read_u64(&self, addr: u64) -> Option<u64> {
        let bytes = self.read(addr, 8)?;
        bytes[..8].try_into().ok().map(u64::from_le_bytes)
    }

    /// Convenience: read a `u32` from `addr`.
    fn read_u32(&self, addr: u64) -> Option<u32> {
        let bytes = self.read(addr, 4)?;
        bytes[..4].try_into().ok().map(u32::from_le_bytes)
    }

    /// Convenience: read a null-terminated ANSI string from `addr`.
    fn read_ansi(&self, addr: u64, max_len: usize) -> Option<String> {
        let bytes = self.read(addr, max_len)?;
        let len = bytes.iter().position(|&b| b == 0).unwrap_or(max_len);
        String::from_utf8(bytes[..len].to_vec()).ok()
    }
}

// ---------------------------------------------------------------------------
// In-memory mock reader (for testing)
// ---------------------------------------------------------------------------

/// A simple in-memory implementation of `MemoryReader` for unit testing.
pub struct FlatMemoryReader {
    pub data: Vec<u8>,
    pub base: u64,
}

impl FlatMemoryReader {
    #[must_use]
    pub const fn new(data: Vec<u8>, base: u64) -> Self {
        Self { data, base }
    }

    #[must_use]
    pub const fn from_bytes(data: Vec<u8>) -> Self {
        Self::new(data, 0)
    }

    /// Write `bytes` at `addr` (relative to `base`).
    pub fn write_at(&mut self, addr: u64, bytes: &[u8]) {
        let offset = u64_to_usize(addr.saturating_sub(self.base));
        if offset + bytes.len() <= self.data.len() {
            self.data[offset..offset + bytes.len()].copy_from_slice(bytes);
        }
    }

    /// Write a `u64` at `addr`.
    pub fn write_u64(&mut self, addr: u64, val: u64) {
        self.write_at(addr, &val.to_le_bytes());
    }

    /// Write a `u32` at `addr`.
    pub fn write_u32(&mut self, addr: u64, val: u32) {
        self.write_at(addr, &val.to_le_bytes());
    }
}

impl MemoryReader for FlatMemoryReader {
    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let offset = u64_to_usize(addr.checked_sub(self.base)?);
        let end = offset.checked_add(len)?;
        if end > self.data.len() { return None; }
        Some(self.data[offset..end].to_vec())
    }
}

// ---------------------------------------------------------------------------
// Subsection / FileObject resolution
// ---------------------------------------------------------------------------

/// Offsets within `_SUBSECTION` (Windows 10 x64).
pub const SUBSECTION_CONTROL_AREA_OFFSET: usize = 0x000;

/// Offsets within `_CONTROL_AREA` (Windows 10 x64).
pub const CONTROL_AREA_FILE_POINTER_OFFSET: usize = 0x040;

/// Offsets within `_FILE_OBJECT` (Windows 10 x64).
pub const FILE_OBJECT_FILE_NAME_OFFSET: usize = 0x058; // _UNICODE_STRING (16 bytes)
pub const FILE_OBJECT_FILE_NAME_LENGTH_OFFSET: usize = 0x058;
pub const FILE_OBJECT_FILE_NAME_BUFFER_OFFSET: usize = 0x060;

/// Attempt to resolve a file name from a `Subsection` pointer.
///
/// Chain: `Subsection -> _CONTROL_AREA -> _FILE_OBJECT -> FileName`.
///
/// Returns `None` if any pointer in the chain is NULL or unreadable.
#[must_use]
pub fn resolve_file_name(reader: &dyn MemoryReader, subsection_ptr: u64) -> Option<String> {
    // _SUBSECTION.ControlArea (first pointer). If the read fails (e.g. NULL
    // subsection in a real dump), bail out; an all-zero structure also means
    // NULL ControlArea below.
    let control_area_ptr = reader.read_u64(subsection_ptr)?;
    if control_area_ptr == 0 { return None; }

    // _CONTROL_AREA.FilePointer (EX_FAST_REF, strip low bits)
    let raw_file_ptr = reader.read_u64(control_area_ptr + CONTROL_AREA_FILE_POINTER_OFFSET as u64)?;
    let file_obj_ptr = raw_file_ptr & !0xF;
    if file_obj_ptr == 0 { return None; }

    // _FILE_OBJECT.FileName (_UNICODE_STRING: Length(2) MaxLen(2) pad(4) Buffer(8))
    let name_length = reader.read_u32(file_obj_ptr + FILE_OBJECT_FILE_NAME_OFFSET as u64)?;
    let len_bytes = (name_length & 0xFFFF) as usize; // low 16 bits = Length
    let buffer_ptr = reader.read_u64(file_obj_ptr + FILE_OBJECT_FILE_NAME_BUFFER_OFFSET as u64)?;
    if buffer_ptr == 0 || len_bytes == 0 { return None; }

    // Read the UTF-16LE string
    let raw = reader.read(buffer_ptr, len_bytes)?;
    let utf16: Vec<u16> = raw.chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&utf16).ok()
}

// ---------------------------------------------------------------------------
// Red-black tree node colour helpers
// ---------------------------------------------------------------------------

/// Strip the colour bits (low 2 bits) from a node pointer.
#[inline]
#[must_use] 
pub const fn node_ptr(raw: u64) -> u64 {
    raw & !0x3
}

/// Maximum recursion depth for tree traversal (guards against corrupt trees).
pub const MAX_TRAVERSE_DEPTH: usize = 512;

// ---------------------------------------------------------------------------
// VAD tree traversal
// ---------------------------------------------------------------------------

/// Recursively traverse the VAD red-black tree in in-order (sorted by VPN)
/// and collect all nodes.
///
/// # Arguments
///
/// * `reader` — provides raw memory reads.
/// * `node_va` — virtual address of the current VAD node (0 = sentinel/NULL).
/// * `depth` — current recursion depth (guard against infinite loops).
/// * `out` — output vector accumulating `VadNode`s.
pub fn traverse_vad_tree(
    reader: &dyn MemoryReader,
    node_va: u64,
    depth: usize,
    out: &mut Vec<VadNode>,
) {
    // node_va == 0 is the NULL sentinel only for child links (depth > 0).
    // At depth 0, a caller may legitimately have the root at address 0.
    if depth > MAX_TRAVERSE_DEPTH {
        return;
    }
    if node_va == 0 && depth > 0 {
        return;
    }
    // Read enough bytes to parse the node (at least 0x70 bytes).
    let Some(buf) = reader.read(node_va, 0x100) else { return };
    let Some(vad) = VadNode::parse(&buf, node_va) else { return };

    // Left subtree first (in-order)
    let left = node_ptr(vad.left_child);
    traverse_vad_tree(reader, left, depth + 1, out);

    // Emit the current node
    out.push(vad.clone());

    // Right subtree
    let right = node_ptr(vad.right_child);
    traverse_vad_tree(reader, right, depth + 1, out);
}

/// Collect all VAD nodes for a process given the `VadRoot` pointer.
///
/// Returns a `Vec<VadNode>` sorted by starting VPN.
#[must_use]
pub fn enumerate_vad_nodes(reader: &dyn MemoryReader, vad_root: u64) -> Vec<VadNode> {
    let mut nodes = Vec::new();
    traverse_vad_tree(reader, vad_root, 0, &mut nodes);
    // Should already be in order from in-order traversal, but sort for safety.
    nodes.sort_by_key(|n| n.starting_vpn);
    nodes
}

/// Find the VAD node that contains `virtual_address`.
///
/// Binary searches the red-black tree without reading every node.  Returns
/// `None` if the address is not mapped.
#[must_use]
pub fn find_vad_for_address(
    reader: &dyn MemoryReader,
    vad_root: u64,
    virtual_address: u64,
) -> Option<VadNode> {
    let vpn = virtual_address / PAGE_SIZE;
    let mut node_va = vad_root;
    let mut depth = 0usize;
    while node_va != 0 && depth < MAX_TRAVERSE_DEPTH {
        let buf = reader.read(node_va, 0x100)?;
        let vad = VadNode::parse(&buf, node_va)?;
        if vpn < vad.starting_vpn {
            node_va = node_ptr(vad.left_child);
        } else if vpn > vad.ending_vpn {
            node_va = node_ptr(vad.right_child);
        } else {
            return Some(vad);
        }
        depth += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// Enrichment: VadNode → VadEntry
// ---------------------------------------------------------------------------

/// Enrich a raw `VadNode` into a `VadEntry` by resolving protection, category,
/// and optionally the file name.
#[must_use]
pub fn enrich_vad_node(reader: &dyn MemoryReader, node: &VadNode) -> VadEntry {
    let category = VadCategory::from_flags(&node.flags);
    let win_prot = vad_prot_to_page_prot(node.flags.protection);
    let protection = PageProtection::from_raw(win_prot);
    let file_name = if node.subsection != 0 {
        resolve_file_name(reader, node.subsection)
    } else {
        None
    };

    let (is_suspicious, suspicion_reason) = classify_suspicion(node, protection, file_name.as_ref());

    VadEntry {
        node_addr: node.address,
        start: node.start_addr(),
        end: node.end_addr() + 1,
        category,
        protection,
        flags: node.flags.clone(),
        file_name,
        commit_charge: node.flags.commit_charge,
        is_suspicious,
        suspicion_reason,
    }
}

/// Determine whether a VAD is suspicious and why.
fn classify_suspicion(
    node: &VadNode,
    prot: PageProtection,
    file_name: Option<&String>,
) -> (bool, Option<String>) {
    let mut reasons: Vec<&'static str> = Vec::new();

    // RWX private anonymous memory is the classic shellcode/injection indicator.
    if prot.is_rwx() && file_name.is_none() && node.flags.private_memory {
        reasons.push("RWX private anonymous");
    }

    // Execute + private without a file is suspicious even without write.
    if prot.flags.is_executable() && file_name.is_none() && node.flags.private_memory && !prot.flags.is_writable() {
        reasons.push("private executable anonymous");
    }

    // Very large anonymous RW private regions may be hollowing or reflective DLL.
    if node.size() > 100 * 1024 * 1024
        && prot.flags.is_readable() && prot.flags.is_writable() && file_name.is_none()
    {
        reasons.push("large anonymous writable (>100 MiB)");
    }

    let is_suspicious = !reasons.is_empty();
    let reason = if is_suspicious {
        Some(reasons.join("; "))
    } else {
        None
    };
    (is_suspicious, reason)
}

// ---------------------------------------------------------------------------
// High-level process VAD enumeration
// ---------------------------------------------------------------------------

/// Result of a full process VAD walk.
#[derive(Debug, Default)]
pub struct ProcessVadResult {
    pub entries: Vec<VadEntry>,
    /// Number of VADs that were flagged as suspicious.
    pub suspicious_count: usize,
    /// Total committed bytes across all private VADs.
    pub total_private_committed: u64,
    /// Total bytes covered by image sections.
    pub total_image_bytes: u64,
    /// Total bytes of anonymous writable mappings.
    pub total_anon_bytes: u64,
}

impl ProcessVadResult {
    /// Find the VAD containing `addr`, or `None`.
    #[must_use]
    pub fn find_for_address(&self, addr: u64) -> Option<&VadEntry> {
        self.entries.iter().find(|e| e.contains(addr))
    }

    /// Return only the suspicious entries.
    #[must_use]
    pub fn suspicious(&self) -> Vec<&VadEntry> {
        self.entries.iter().filter(|e| e.is_suspicious).collect()
    }

    /// Return only image section entries.
    #[must_use]
    pub fn image_sections(&self) -> Vec<&VadEntry> {
        self.entries
            .iter()
            .filter(|e| e.category == VadCategory::ImageSection)
            .collect()
    }

    /// Return only mapped-file entries.
    #[must_use]
    pub fn mapped_files(&self) -> Vec<&VadEntry> {
        self.entries
            .iter()
            .filter(|e| e.category == VadCategory::MappedFile)
            .collect()
    }
}

/// Walk all VADs for a process and return a `ProcessVadResult`.
#[must_use]
pub fn walk_process_vads(reader: &dyn MemoryReader, vad_root: u64) -> ProcessVadResult {
    let nodes = enumerate_vad_nodes(reader, vad_root);
    let mut result = ProcessVadResult::default();
    for node in &nodes {
        let entry = enrich_vad_node(reader, node);
        if entry.is_suspicious {
            result.suspicious_count += 1;
        }
        match entry.category {
            VadCategory::ImageSection => {
                result.total_image_bytes += entry.size();
            }
            VadCategory::Private => {
                result.total_private_committed +=
                    entry.commit_charge * PAGE_SIZE;
                result.total_anon_bytes += entry.size();
            }
            _ => {}
        }
        result.entries.push(entry);
    }
    result
}

// ---------------------------------------------------------------------------
// File-name extraction helpers
// ---------------------------------------------------------------------------

/// Given a file name from VAD (e.g. `\Device\HarddiskVolume3\Windows\System32\ntdll.dll`),
/// extract just the filename component.
#[must_use]
pub fn vad_file_basename(path: &str) -> &str {
    path.rsplit('\\').next().unwrap_or(path)
}

/// Returns `true` if the VAD file name appears to be from a system32 / syswow64 directory.
#[must_use]
pub fn is_system_module_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("\\windows\\system32\\")
        || lower.contains("\\windows\\syswow64\\")
        || lower.contains("\\windows\\sysnative\\")
}

/// Returns `true` if the VAD file name is a known-suspicious non-system path
/// (e.g., from `\Device\HarddiskVolume3\Users\...` or `\Device\...Temp\...`).
#[must_use]
pub fn is_suspicious_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("\\temp\\")
        || lower.contains("\\tmp\\")
        || lower.contains("\\appdata\\local\\temp\\")
        || lower.contains("\\users\\public\\")
}

// ---------------------------------------------------------------------------
// Fake VAD builder for testing
// ---------------------------------------------------------------------------

/// Build a minimal fake VAD node buffer for in-memory testing.
///
/// The node is placed at offset 0 in the buffer.  `left_child` and
/// `right_child` are set to 0 (no children), so the tree is a single leaf.
#[must_use]
pub fn make_vad_node_buf(
    starting_vpn: u64,
    ending_vpn: u64,
    raw_flags: u64,
    subsection: u64,
    left_child: u64,
    right_child: u64,
) -> Vec<u8> {
    let mut buf = vec![0u8; 0x100];
    buf[VAD_LEFT_CHILD_OFFSET..VAD_LEFT_CHILD_OFFSET + 8]
        .copy_from_slice(&left_child.to_le_bytes());
    buf[VAD_RIGHT_CHILD_OFFSET..VAD_RIGHT_CHILD_OFFSET + 8]
        .copy_from_slice(&right_child.to_le_bytes());
    // parent = 0
    buf[VAD_STARTING_VPN_OFFSET..VAD_STARTING_VPN_OFFSET + 8]
        .copy_from_slice(&starting_vpn.to_le_bytes());
    buf[VAD_ENDING_VPN_OFFSET..VAD_ENDING_VPN_OFFSET + 8]
        .copy_from_slice(&ending_vpn.to_le_bytes());
    buf[VAD_FLAGS_OFFSET..VAD_FLAGS_OFFSET + 8].copy_from_slice(&raw_flags.to_le_bytes());
    buf[VAD_SUBSECTION_OFFSET..VAD_SUBSECTION_OFFSET + 8]
        .copy_from_slice(&subsection.to_le_bytes());
    buf
}

/// Build a fake flat memory space containing a small VAD tree.
///
/// Layout:
/// ```text
/// addr=0x1000  : root node (starting_vpn=0x100, ending_vpn=0x1FF)
///   left child  : addr=0x2000 (starting_vpn=0x050, ending_vpn=0x0FF)
///   right child : addr=0x3000 (starting_vpn=0x200, ending_vpn=0x2FF)
/// ```
#[must_use]
pub fn make_test_memory() -> FlatMemoryReader {
    let mut mem = FlatMemoryReader::new(vec![0u8; 0x10000], 0);

    // Right-child VAD at 0x3000 (leaf, no children)
    let right_buf = make_vad_node_buf(0x200, 0x2FF, 0x04u64 << 16, 0, 0, 0);
    mem.write_at(0x3000, &right_buf);

    // Left-child VAD at 0x2000 (leaf, no children)
    // flags: PAGE_READWRITE (0x04) with private_memory bit (bit 21)
    let lflags = (0x04u64 << 16) | (1u64 << 21);
    let left_buf = make_vad_node_buf(0x050, 0x0FF, lflags, 0, 0, 0);
    mem.write_at(0x2000, &left_buf);

    // Root VAD at 0x1000
    // flags: PAGE_EXECUTE_READWRITE (0x06) + private (bit 21) = suspicious RWX
    let root_flags = (0x06u64 << 16) | (1u64 << 21);
    let root_buf = make_vad_node_buf(0x100, 0x1FF, root_flags, 0, 0x2000, 0x3000);
    mem.write_at(0x1000, &root_buf);

    mem
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- PageProtection ----

    #[test]
    fn page_prot_rwx_detection() {
        let p = PageProtection::from_raw(PAGE_EXECUTE_READWRITE);
        assert!(p.is_rwx());
        assert!(p.flags.is_readable());
        assert!(p.flags.is_writable());
        assert!(p.flags.is_executable());
    }

    #[test]
    fn page_prot_readonly() {
        let p = PageProtection::from_raw(PAGE_READONLY);
        assert!(p.flags.is_readable());
        assert!(!p.flags.is_writable());
        assert!(!p.flags.is_executable());
        assert!(!p.is_rwx());
    }

    #[test]
    fn page_prot_execute_only() {
        let p = PageProtection::from_raw(PAGE_EXECUTE);
        assert!(!p.flags.is_readable());
        assert!(!p.flags.is_writable());
        assert!(p.flags.is_executable());
    }

    #[test]
    fn page_prot_guard_flag() {
        let p = PageProtection::from_raw(PAGE_READWRITE | PAGE_GUARD);
        assert!(p.flags.is_guard());
        assert!(p.flags.is_writable());
    }

    #[test]
    fn page_prot_copy_on_write() {
        let p = PageProtection::from_raw(PAGE_WRITECOPY);
        assert!(p.flags.is_copy_on_write());
        assert!(!p.flags.is_executable());
    }

    #[test]
    fn page_prot_name_readwrite() {
        let p = PageProtection::from_raw(PAGE_READWRITE);
        assert_eq!(p.name(), "PAGE_READWRITE");
    }

    // ---- vad_prot_to_page_prot ----

    #[test]
    fn vad_prot_4_is_readwrite() {
        assert_eq!(vad_prot_to_page_prot(4), PAGE_READWRITE);
    }

    #[test]
    fn vad_prot_6_is_execute_readwrite() {
        assert_eq!(vad_prot_to_page_prot(6), PAGE_EXECUTE_READWRITE);
    }

    #[test]
    fn vad_prot_1_is_readonly() {
        assert_eq!(vad_prot_to_page_prot(1), PAGE_READONLY);
    }

    #[test]
    fn vad_prot_0_is_noaccess() {
        assert_eq!(vad_prot_to_page_prot(0), PAGE_NOACCESS);
    }

    #[test]
    fn vad_prot_14_is_rwx_nocache() {
        assert_eq!(vad_prot_to_page_prot(14), PAGE_EXECUTE_READWRITE | PAGE_NOCACHE);
    }

    // ---- VadCategory ----

    #[test]
    fn vad_category_private() {
        let flags = MmVadFlags::parse(1u64 << 21); // private_memory bit
        let cat = VadCategory::from_flags(&flags);
        assert_eq!(cat, VadCategory::Private);
    }

    #[test]
    fn vad_category_image_section() {
        // vad_type = 2 (bits 12..14), no private_memory
        let raw: u64 = 2u64 << 12;
        let flags = MmVadFlags::parse(raw);
        let cat = VadCategory::from_flags(&flags);
        assert_eq!(cat, VadCategory::ImageSection);
    }

    #[test]
    fn vad_category_mapped_file() {
        let raw: u64 = 1u64 << 12;
        let flags = MmVadFlags::parse(raw);
        let cat = VadCategory::from_flags(&flags);
        assert_eq!(cat, VadCategory::MappedFile);
    }

    #[test]
    fn vad_category_name() {
        assert_eq!(VadCategory::ImageSection.name(), "ImageSection");
        assert_eq!(VadCategory::Private.name(), "Private");
    }

    // ---- FlatMemoryReader ----

    #[test]
    fn flat_reader_basic_read() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let reader = FlatMemoryReader::from_bytes(data);
        let result = reader.read(0, 4).unwrap();
        assert_eq!(result, vec![1, 2, 3, 4]);
    }

    #[test]
    fn flat_reader_out_of_bounds() {
        let data = vec![0u8; 8];
        let reader = FlatMemoryReader::from_bytes(data);
        assert!(reader.read(10, 1).is_none());
    }

    #[test]
    fn flat_reader_u64() {
        let val: u64 = 0xDEAD_BEEF_1234_5678;
        let data = val.to_le_bytes().to_vec();
        let reader = FlatMemoryReader::from_bytes(data);
        assert_eq!(reader.read_u64(0), Some(val));
    }

    #[test]
    fn flat_reader_u32() {
        let val: u32 = 0xABCD_1234;
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&val.to_le_bytes());
        let reader = FlatMemoryReader::from_bytes(data);
        assert_eq!(reader.read_u32(0), Some(val));
    }

    #[test]
    fn flat_reader_write_and_read() {
        let mut reader = FlatMemoryReader::new(vec![0u8; 16], 0x1000);
        reader.write_u64(0x1000, 0x1234_ABCD_5678_EF00);
        assert_eq!(reader.read_u64(0x1000), Some(0x1234_ABCD_5678_EF00));
    }

    // ---- VAD tree traversal ----

    #[test]
    fn traverse_empty_tree() {
        let reader = FlatMemoryReader::from_bytes(vec![0u8; 16]);
        let mut out = Vec::new();
        traverse_vad_tree(&reader, 0, 0, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn traverse_single_node() {
        let buf = make_vad_node_buf(0x100, 0x1FF, 0x04u64 << 16, 0, 0, 0);
        let reader = FlatMemoryReader::from_bytes(buf);
        let mut out = Vec::new();
        traverse_vad_tree(&reader, 0, 0, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].starting_vpn, 0x100);
        assert_eq!(out[0].ending_vpn, 0x1FF);
    }

    #[test]
    fn traverse_test_memory_three_nodes() {
        let mem = make_test_memory();
        let mut out = Vec::new();
        traverse_vad_tree(&mem, 0x1000, 0, &mut out);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn traverse_test_memory_in_order() {
        let mem = make_test_memory();
        let mut out = Vec::new();
        traverse_vad_tree(&mem, 0x1000, 0, &mut out);
        // Should be in-order: left (0x050..0x0FF), root (0x100..0x1FF), right (0x200..0x2FF)
        assert_eq!(out[0].starting_vpn, 0x050);
        assert_eq!(out[1].starting_vpn, 0x100);
        assert_eq!(out[2].starting_vpn, 0x200);
    }

    #[test]
    fn enumerate_vad_nodes_sorted() {
        let mem = make_test_memory();
        let nodes = enumerate_vad_nodes(&mem, 0x1000);
        assert_eq!(nodes.len(), 3);
        assert!(nodes.windows(2).all(|w| w[0].starting_vpn <= w[1].starting_vpn));
    }

    // ---- find_vad_for_address ----

    #[test]
    fn find_vad_for_address_found() {
        let mem = make_test_memory();
        // Root node covers 0x100..0x1FF -> addresses 0x100000..0x1FFFFF
        let addr = 0x150 * PAGE_SIZE; // middle of root VPN range
        let vad = find_vad_for_address(&mem, 0x1000, addr);
        assert!(vad.is_some());
        let vad = vad.unwrap();
        assert_eq!(vad.starting_vpn, 0x100);
    }

    #[test]
    fn find_vad_for_address_left_child() {
        let mem = make_test_memory();
        let addr = 0x080 * PAGE_SIZE; // in left child VPN range 0x050..0x0FF
        let vad = find_vad_for_address(&mem, 0x1000, addr);
        assert!(vad.is_some());
        assert_eq!(vad.unwrap().starting_vpn, 0x050);
    }

    #[test]
    fn find_vad_for_address_not_found() {
        let mem = make_test_memory();
        // VPN 0x010 is before the leftmost node (0x050)
        let addr = 0x010 * PAGE_SIZE;
        let vad = find_vad_for_address(&mem, 0x1000, addr);
        assert!(vad.is_none());
    }

    #[test]
    fn find_vad_for_address_right_child() {
        let mem = make_test_memory();
        let addr = 0x250 * PAGE_SIZE; // in right child VPN range 0x200..0x2FF
        let vad = find_vad_for_address(&mem, 0x1000, addr);
        assert!(vad.is_some());
        assert_eq!(vad.unwrap().starting_vpn, 0x200);
    }

    // ---- enrich_vad_node ----

    #[test]
    fn enrich_vad_rwx_private_is_suspicious() {
        let mem = make_test_memory();
        let mut out = Vec::new();
        traverse_vad_tree(&mem, 0x1000, 0, &mut out);
        // Root node: RWX private
        let root = out.iter().find(|n| n.starting_vpn == 0x100).unwrap();
        let entry = enrich_vad_node(&mem, root);
        assert!(entry.is_suspicious);
    }

    #[test]
    fn enrich_vad_readwrite_private_not_suspicious() {
        let mem = make_test_memory();
        let mut out = Vec::new();
        traverse_vad_tree(&mem, 0x1000, 0, &mut out);
        // Left child: PAGE_READWRITE private (no execute)
        let left = out.iter().find(|n| n.starting_vpn == 0x050).unwrap();
        let entry = enrich_vad_node(&mem, left);
        assert!(!entry.is_suspicious);
    }

    #[test]
    fn enrich_vad_entry_size() {
        let mem = make_test_memory();
        let mut out = Vec::new();
        traverse_vad_tree(&mem, 0x1000, 0, &mut out);
        let root = out.iter().find(|n| n.starting_vpn == 0x100).unwrap();
        let entry = enrich_vad_node(&mem, root);
        // 0x100 pages = 0x100 * 0x1000 bytes
        assert_eq!(entry.size(), 0x100 * PAGE_SIZE);
    }

    #[test]
    fn enrich_vad_entry_contains() {
        let mem = make_test_memory();
        let mut out = Vec::new();
        traverse_vad_tree(&mem, 0x1000, 0, &mut out);
        let root = out.iter().find(|n| n.starting_vpn == 0x100).unwrap();
        let entry = enrich_vad_node(&mem, root);
        assert!(entry.contains(0x150 * PAGE_SIZE));
        assert!(!entry.contains(0x050 * PAGE_SIZE));
    }

    // ---- walk_process_vads ----

    #[test]
    fn walk_process_vads_three_entries() {
        let mem = make_test_memory();
        let result = walk_process_vads(&mem, 0x1000);
        assert_eq!(result.entries.len(), 3);
    }

    #[test]
    fn walk_process_vads_one_suspicious() {
        let mem = make_test_memory();
        let result = walk_process_vads(&mem, 0x1000);
        assert_eq!(result.suspicious_count, 1);
    }

    #[test]
    fn walk_process_vads_find_for_address() {
        let mem = make_test_memory();
        let result = walk_process_vads(&mem, 0x1000);
        let found = result.find_for_address(0x150 * PAGE_SIZE);
        assert!(found.is_some());
    }

    #[test]
    fn walk_process_vads_suspicious_vec() {
        let mem = make_test_memory();
        let result = walk_process_vads(&mem, 0x1000);
        let susps = result.suspicious();
        assert_eq!(susps.len(), 1);
        assert!(susps[0].suspicion_reason.as_ref().unwrap().contains("RWX"));
    }

    // ---- File name helpers ----

    #[test]
    fn vad_file_basename_with_backslash() {
        let path = r"\Device\HarddiskVolume3\Windows\System32\ntdll.dll";
        assert_eq!(vad_file_basename(path), "ntdll.dll");
    }

    #[test]
    fn vad_file_basename_no_separator() {
        let path = "ntdll.dll";
        assert_eq!(vad_file_basename(path), "ntdll.dll");
    }

    #[test]
    fn is_system_module_path_system32() {
        let path = r"\Device\HarddiskVolume3\Windows\System32\kernel32.dll";
        assert!(is_system_module_path(path));
    }

    #[test]
    fn is_system_module_path_not_system() {
        let path = r"\Device\HarddiskVolume3\Users\attacker\payload.dll";
        assert!(!is_system_module_path(path));
    }

    #[test]
    fn is_suspicious_path_temp() {
        let path = r"\Device\HarddiskVolume3\Users\Joe\AppData\Local\Temp\evil.exe";
        assert!(is_suspicious_path(path));
    }

    #[test]
    fn is_suspicious_path_system32_not_suspicious() {
        let path = r"\Device\HarddiskVolume3\Windows\System32\ntdll.dll";
        assert!(!is_suspicious_path(path));
    }

    // ---- resolve_file_name ----

    fn make_file_name_memory() -> FlatMemoryReader {
        // Layout:
        //  0x0000: _SUBSECTION (ControlArea ptr at 0x000 -> 0x1000)
        //  0x1000: _CONTROL_AREA (FilePointer at +0x040 -> 0x2000 with RefCnt=3)
        //  0x2000: _FILE_OBJECT (FileName at +0x058: Length=0x000A (4 bytes LE u32),
        //           Buffer at +0x060 -> 0x3000)
        //  0x3000: UTF-16LE "foo" (6 bytes: f\0o\0o\0)
        let mut mem = FlatMemoryReader::new(vec![0u8; 0x4000], 0);

        // Subsection.ControlArea = 0x1000
        mem.write_u64(0x0000, 0x1000);

        // ControlArea.FilePointer = 0x2003 (0x2000 + RefCnt=3)
        mem.write_u64(0x1000 + CONTROL_AREA_FILE_POINTER_OFFSET as u64, 0x2003);

        // FileObject.FileName: Length=6 (u32 low 16) at +0x058
        // We store it as a u32 where low 16 = byte length of the UTF16 string
        mem.write_u32(0x2000 + FILE_OBJECT_FILE_NAME_OFFSET as u64, 6u32);
        // Buffer pointer at +0x060
        mem.write_u64(0x2000 + FILE_OBJECT_FILE_NAME_BUFFER_OFFSET as u64, 0x3000);

        // UTF-16LE "foo" at 0x3000
        let foo_utf16: Vec<u8> = "foo".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        mem.write_at(0x3000, &foo_utf16);

        mem
    }

    #[test]
    fn resolve_file_name_success() {
        let mem = make_file_name_memory();
        let name = resolve_file_name(&mem, 0x0000);
        assert_eq!(name.as_deref(), Some("foo"));
    }

    #[test]
    fn resolve_file_name_null_subsection() {
        let mem = FlatMemoryReader::from_bytes(vec![0u8; 64]);
        assert!(resolve_file_name(&mem, 0).is_none());
    }

    #[test]
    fn info_line_format() {
        let mem = make_test_memory();
        let result = walk_process_vads(&mem, 0x1000);
        // Just ensure it doesn't panic and returns a non-empty string
        for entry in &result.entries {
            let line = entry.info_line();
            assert!(!line.is_empty());
        }
    }

    #[test]
    fn node_ptr_strips_color_bits() {
        assert_eq!(node_ptr(0xFFFF_F801_1234_5673), 0xFFFF_F801_1234_5670);
        assert_eq!(node_ptr(0xFFFF_F801_1234_5671), 0xFFFF_F801_1234_5670);
    }

    #[test]
    fn vad_entry_protection_rwx() {
        let mem = make_test_memory();
        let result = walk_process_vads(&mem, 0x1000);
        let root_entry = result.entries.iter().find(|e| e.start == 0x100 * PAGE_SIZE).unwrap();
        assert!(root_entry.protection.is_rwx());
    }

    #[test]
    fn max_traverse_depth_guard() {
        // Build a cycle: node at 0x1000 with left_child = 0x1000 (self)
        let buf = make_vad_node_buf(0x100, 0x1FF, 0, 0, 0x1000, 0);
        let reader = FlatMemoryReader::from_bytes(buf);
        let mut out = Vec::new();
        // This must not recurse infinitely
        traverse_vad_tree(&reader, 0, 0, &mut out);
        // At most one node (the root at offset 0, left = 0x1000 which is out of range)
        assert!(out.len() <= 1);
    }

    #[test]
    fn walk_image_sections_empty() {
        let mem = make_test_memory();
        let result = walk_process_vads(&mem, 0x1000);
        // No image sections in our test tree
        assert!(result.image_sections().is_empty());
    }

    #[test]
    fn walk_mapped_files_empty() {
        let mem = make_test_memory();
        let result = walk_process_vads(&mem, 0x1000);
        assert!(result.mapped_files().is_empty());
    }
}
