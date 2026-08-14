//! Process artifact analysis: EPROCESS walk skeleton, handle table analysis,
//! module list, and VAD range analysis for forensic triage.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ProcessArtifactError {
    #[error("invalid EPROCESS at offset {0}")]
    InvalidEprocess(u64),
    #[error("cycle detected in EPROCESS list at pid {0}")]
    ListCycle(u32),
    #[error("handle table corrupt at offset {0}")]
    HandleTableCorrupt(u64),
    #[error("truncated data: need {0} bytes at {1}")]
    Truncated(usize, u64),
}

// ─── EPROCESS offsets ─────────────────────────────────────────────────────────

/// EPROCESS field offsets for Windows 10 x64 (build 19041 baseline).
/// Field names follow the `WinDbg` `dt nt!_EPROCESS` layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EprocessOffsets {
    /// Offset of `ActiveProcessLinks.Flink` (pointer to next EPROCESS).
    pub active_process_links: usize,
    /// Offset of `UniqueProcessId`.
    pub unique_process_id: usize,
    /// Offset of `InheritedFromUniqueProcessId`.
    pub inherited_from_unique_process_id: usize,
    /// Offset of `ImageFileName[15]` (ANSI).
    pub image_file_name: usize,
    /// Offset of `CreateTime` (`LARGE_INTEGER` / FILETIME).
    pub create_time: usize,
    /// Offset of `ExitTime`.
    pub exit_time: usize,
    /// Offset of `VadRoot` (pointer to `RTL_AVL_TREE`).
    pub vad_root: usize,
    /// Offset of `ObjectTable` (pointer to `HANDLE_TABLE`).
    pub object_table: usize,
    /// Offset of `Token` (`EX_FAST_REF`).
    pub token: usize,
    /// Offset of `Peb` (pointer to PEB).
    pub peb: usize,
    /// Offset of `ActiveThreads` (u32).
    pub active_threads: usize,
    /// Offset of `Flags` (u32).
    pub flags: usize,
}

impl EprocessOffsets {
    /// Default offsets for Windows 10 x64 19041.
    #[must_use]
    pub const fn win10_x64() -> Self {
        Self {
            active_process_links: 0x2F0,
            unique_process_id: 0x2E8,
            inherited_from_unique_process_id: 0x3E8,
            image_file_name: 0x450,
            create_time: 0x2C8,
            exit_time: 0x2D0,
            vad_root: 0x7D8,
            object_table: 0x570,
            token: 0x4B8,
            peb: 0x550,
            active_threads: 0x5F0,
            flags: 0x304,
        }
    }

    /// Offsets for Windows 7 x64.
    #[must_use]
    pub const fn win7_x64() -> Self {
        Self {
            active_process_links: 0x188,
            unique_process_id: 0x180,
            inherited_from_unique_process_id: 0x340,
            image_file_name: 0x2E0,
            create_time: 0x168,
            exit_time: 0x170,
            vad_root: 0x448,
            object_table: 0x200,
            token: 0x208,
            peb: 0x338,
            active_threads: 0x2C4,
            flags: 0x26C,
        }
    }
}

// ─── Process flags ────────────────────────────────────────────────────────────

/// Decoded EPROCESS.Flags / Flags2 fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessFlags {
    pub create_reported: bool,
    pub no_debug_inherit: bool,
    pub process_exiting: bool,
    pub process_delete: bool,
    pub wow64_process: bool,
    pub image_notify_done: bool,
    pub deleted: bool,
    pub session_id: u32,
}

impl ProcessFlags {
    #[must_use]
    pub const fn from_raw(flags: u32, session_id: u32) -> Self {
        Self {
            create_reported: flags & 0x0001 != 0,
            no_debug_inherit: flags & 0x0002 != 0,
            process_exiting: flags & 0x0004 != 0,
            process_delete: flags & 0x0008 != 0,
            wow64_process: flags & 0x0010 != 0,
            image_notify_done: flags & 0x0020 != 0,
            deleted: flags & 0x0040 != 0,
            session_id,
        }
    }
}

// ─── EPROCESS entry ───────────────────────────────────────────────────────────

/// A parsed EPROCESS structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EprocessEntry {
    /// Virtual address of this EPROCESS.
    pub address: u64,
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// Image name (up to 15 chars).
    pub image_name: String,
    /// Process creation time (Unix epoch seconds).
    pub create_time: i64,
    /// Process exit time (0 if still running).
    pub exit_time: i64,
    /// Virtual address of PEB.
    pub peb_address: u64,
    /// Virtual address of the VAD root.
    pub vad_root: u64,
    /// Virtual address of the handle table.
    pub object_table: u64,
    /// Active thread count.
    pub active_threads: u32,
    /// Process flags.
    pub flags: ProcessFlags,
    /// Whether the process has exited.
    pub is_exited: bool,
}

impl EprocessEntry {
    /// Returns `true` if this process is a system process (PID 0 or 4).
    #[must_use]
    pub const fn is_system(&self) -> bool {
        self.pid == 0 || self.pid == 4
    }

    /// Returns `true` if the image name looks suspicious.
    #[must_use]
    pub fn has_suspicious_name(&self) -> bool {
        let lower = self.image_name.to_lowercase();
        // Spaces in executable names, single-char names, or known masquerading
        self.image_name.contains(' ') ||
        self.image_name.len() == 1 ||
        lower == "svchost" || // bare svchost without .exe is suspicious
        lower.contains("..") ||
        lower.contains('\x00')
    }
}

// ─── EPROCESS list walker ─────────────────────────────────────────────────────

/// Walks the Windows EPROCESS doubly-linked list.
pub struct EprocessListWalker {
    pub offsets: EprocessOffsets,
    pub max_processes: usize,
}

impl EprocessListWalker {
    #[must_use]
    pub const fn new(offsets: EprocessOffsets) -> Self {
        Self {
            offsets,
            max_processes: 2048,
        }
    }

    /// Walk the EPROCESS list starting at `system_eprocess_addr`.
    /// Returns a list of parsed process entries.
    #[must_use]
    pub fn walk(&self, memory: &[u8], base_addr: u64, start_addr: u64) -> Vec<EprocessEntry> {
        let mut entries = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut current = start_addr;

        for _ in 0..self.max_processes {
            if !visited.insert(current) {
                break; // cycle detected
            }
            if let Some(entry) = self.parse_eprocess(memory, base_addr, current) {
                let flink_off =
                    entry.address + self.offsets.active_process_links as u64 - base_addr;
                if let Some(next_flink) = read_u64(memory, usize::try_from(flink_off).unwrap_or(usize::MAX)) {
                    // Flink points to the ActiveProcessLinks.Flink of the next EPROCESS
                    // So the next EPROCESS address = Flink - active_process_links_offset
                    let next_ep =
                        next_flink.saturating_sub(self.offsets.active_process_links as u64);
                    entries.push(entry);
                    current = next_ep;
                    if current == start_addr {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        entries
    }

    fn parse_eprocess(&self, memory: &[u8], base_addr: u64, addr: u64) -> Option<EprocessEntry> {
        let off = usize::try_from(addr.checked_sub(base_addr)?).unwrap_or(usize::MAX);
        let max_off = off + 0xA00; // typical EPROCESS size
        if max_off > memory.len() {
            return None;
        }

        let pid = read_u32(memory, off + self.offsets.unique_process_id)?;
        let parent_pid = read_u32(memory, off + self.offsets.inherited_from_unique_process_id)?;

        let name_off = off + self.offsets.image_file_name;
        if name_off + 15 > memory.len() {
            return None;
        }
        let name_bytes = &memory[name_off..name_off + 15];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(15);
        let image_name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

        let create_ft = read_u64(memory, off + self.offsets.create_time).unwrap_or(0);
        let exit_ft = read_u64(memory, off + self.offsets.exit_time).unwrap_or(0);
        let create_time = filetime_to_unix(create_ft);
        let exit_time = filetime_to_unix(exit_ft);
        let is_exited = exit_ft > 0;

        let peb_address = read_u64(memory, off + self.offsets.peb).unwrap_or(0);
        let vad_root = read_u64(memory, off + self.offsets.vad_root).unwrap_or(0);
        let object_table = read_u64(memory, off + self.offsets.object_table).unwrap_or(0);
        let active_threads = read_u32(memory, off + self.offsets.active_threads).unwrap_or(0);
        let flags_raw = read_u32(memory, off + self.offsets.flags).unwrap_or(0);
        let flags = ProcessFlags::from_raw(flags_raw, 0);

        Some(EprocessEntry {
            address: addr,
            pid,
            ppid: parent_pid,
            image_name,
            create_time,
            exit_time,
            peb_address,
            vad_root,
            object_table,
            active_threads,
            flags,
            is_exited,
        })
    }
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    if off + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes(data[off..off + 4].try_into().ok()?))
}

fn read_u64(data: &[u8], off: usize) -> Option<u64> {
    if off + 8 > data.len() {
        return None;
    }
    Some(u64::from_le_bytes(data[off..off + 8].try_into().ok()?))
}

const fn filetime_to_unix(ft: u64) -> i64 {
    const EPOCH_DIFF: u64 = 11_644_473_600 * 10_000_000;
    ((ft.saturating_sub(EPOCH_DIFF)) / 10_000_000) .cast_signed()
}

// ─── Handle table ─────────────────────────────────────────────────────────────

/// Windows handle types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandleType {
    Process,
    Thread,
    File,
    Registry,
    Event,
    Mutex,
    Semaphore,
    Section,
    Directory,
    SymbolicLink,
    Token,
    Job,
    Desktop,
    WindowStation,
    Timer,
    IrTimer,
    Unknown(u32),
}

impl HandleType {
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            7 => Self::Process,
            8 => Self::Thread,
            30 => Self::File,
            41 => Self::Registry,
            18 => Self::Event,
            17 => Self::Mutex,
            20 => Self::Semaphore,
            37 => Self::Section,
            3 => Self::Directory,
            4 => Self::SymbolicLink,
            5 => Self::Token,
            16 => Self::Job,
            14 => Self::Desktop,
            35 => Self::WindowStation,
            19 => Self::Timer,
            n => Self::Unknown(n),
        }
    }

    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Process => "Process",
            Self::Thread => "Thread",
            Self::File => "File",
            Self::Registry => "Registry",
            Self::Event => "Event",
            Self::Mutex => "Mutex",
            Self::Semaphore => "Semaphore",
            Self::Section => "Section",
            Self::Directory => "Directory",
            Self::SymbolicLink => "SymbolicLink",
            Self::Token => "Token",
            Self::Job => "Job",
            Self::Desktop => "Desktop",
            Self::WindowStation => "WindowStation",
            Self::Timer => "Timer",
            Self::IrTimer => "IrTimer",
            Self::Unknown(_) => "Unknown",
        }
    }
}

/// A single handle table entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleEntry {
    pub handle_value: u32,
    pub object_ptr: u64,
    pub access_mask: u32,
    pub handle_type: HandleType,
    pub object_name: String,
    pub pid: u32,
}

/// Parse handle table entries from a raw handle table page.
/// Windows `HANDLE_TABLE_ENTRY`: `[object_ptr(8) | access_mask(4) | type(4)]`
pub struct HandleTableParser;

impl HandleTableParser {
    const ENTRY_SIZE: usize = 16;
    const ENTRIES_PER_PAGE: usize = 256;

    /// Maximum number of `HANDLE_TABLE` entries that fit in a single page.
    /// Exposed so callers can pre-size buffers passed to [`Self::parse_page`].
    #[must_use]
    pub const fn entries_per_page() -> usize {
        Self::ENTRIES_PER_PAGE
    }

    #[must_use]
    pub fn parse_page(data: &[u8], pid: u32) -> Vec<HandleEntry> {
        let mut entries = Vec::with_capacity(data.len() / Self::ENTRY_SIZE);
        let mut handle = 4u32; // handles start at 4, increment by 4
        for chunk in data.chunks_exact(Self::ENTRY_SIZE) {
            let object_ptr = u64::from_le_bytes(chunk[0..8].try_into().unwrap_or([0; 8]));
            let access_mask = u32::from_le_bytes(chunk[8..12].try_into().unwrap_or([0; 4]));
            let type_raw = u32::from_le_bytes(chunk[12..16].try_into().unwrap_or([0; 4]));
            // Skip null handles
            if object_ptr == 0 {
                handle += 4;
                continue;
            }
            entries.push(HandleEntry {
                handle_value: handle,
                object_ptr: object_ptr & !0xF, // strip attribute bits
                access_mask,
                handle_type: HandleType::from_u32(type_raw),
                object_name: String::new(),
                pid,
            });
            handle += 4;
        }
        entries
    }

    /// Summarize handle types by count.
    #[must_use]
    pub fn summarize(entries: &[HandleEntry]) -> HashMap<String, usize> {
        let mut counts = HashMap::with_capacity(16);
        for e in entries {
            *counts
                .entry(e.handle_type.as_str().to_string())
                .or_insert(0) += 1;
        }
        counts
    }
}

// ─── Module list (LDR_DATA_TABLE_ENTRY) ──────────────────────────────────────

/// A loaded module entry from the PEB Ldr list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdrModuleEntry {
    pub address: u64,
    pub dll_base: u64,
    pub entry_point: u64,
    pub size_of_image: u32,
    pub full_dll_name: String,
    pub base_dll_name: String,
    pub flags: u32,
    pub load_count: u16,
    pub tls_index: u16,
}

impl LdrModuleEntry {
    /// Returns `true` if the module was loaded from an unusual path.
    #[must_use]
    pub fn is_suspicious_path(&self) -> bool {
        let lower = self.full_dll_name.to_lowercase();
        lower.contains("\\temp\\")
            || lower.contains("\\tmp\\")
            || lower.contains("\\appdata\\local\\temp")
            || lower.contains("\\users\\public")
            || (lower.contains("\\users\\") && lower.contains("\\downloads\\"))
    }

    /// Returns `true` if the module has been manually mapped (no disk backing).
    #[must_use]
    pub const fn is_manually_mapped(&self) -> bool {
        // Flags bit 4: LDRP_PROCESS_ATTACH_CALLED; bit 0x00200000: LDRP_DONT_CALL_FOR_THREADS
        // A manually mapped DLL often has no entry point and zeroed load count.
        self.entry_point == 0 && self.load_count == 0 && self.full_dll_name.is_empty()
    }
}

/// Parse `LDR_DATA_TABLE_ENTRY` records from memory.
pub struct PebLdrScanner;

impl PebLdrScanner {
    /// LDR record sentinel (mock format).
    /// Layout: `b"LDRE"` (4) | `dll_base`(8) | `entry_point`(8) | size(4) |
    ///          `full_name_len`(2) | `full_name` | `base_name_len`(2) | `base_name` | flags(4) | `load_count`(2)
    const TAG: &'static [u8; 4] = b"LDRE";

    #[must_use]
    pub fn scan(data: &[u8]) -> Vec<LdrModuleEntry> {
        let mut modules = Vec::new();
        let mut pos = 0usize;
        while pos + 32 <= data.len() {
            if &data[pos..pos + 4] == Self::TAG {
                let dll_base =
                    u64::from_le_bytes(data[pos + 4..pos + 12].try_into().unwrap_or([0; 8]));
                let entry_point =
                    u64::from_le_bytes(data[pos + 12..pos + 20].try_into().unwrap_or([0; 8]));
                let size =
                    u32::from_le_bytes(data[pos + 20..pos + 24].try_into().unwrap_or([0; 4]));
                let full_len =
                    u16::from_le_bytes(data[pos + 24..pos + 26].try_into().unwrap_or([0; 2]))
                        as usize;
                if pos + 26 + full_len + 2 > data.len() {
                    pos += 4;
                    continue;
                }
                let full_name =
                    String::from_utf8_lossy(&data[pos + 26..pos + 26 + full_len]).to_string();
                let base_off = pos + 26 + full_len;
                let base_len =
                    u16::from_le_bytes(data[base_off..base_off + 2].try_into().unwrap_or([0; 2]))
                        as usize;
                if base_off + 2 + base_len + 6 > data.len() {
                    pos += 4;
                    continue;
                }
                let base_name =
                    String::from_utf8_lossy(&data[base_off + 2..base_off + 2 + base_len])
                        .to_string();
                let flags_off = base_off + 2 + base_len;
                let flags =
                    u32::from_le_bytes(data[flags_off..flags_off + 4].try_into().unwrap_or([0; 4]));
                let load_count = u16::from_le_bytes(
                    data[flags_off + 4..flags_off + 6]
                        .try_into()
                        .unwrap_or([0; 2]),
                );
                modules.push(LdrModuleEntry {
                    address: (pos as u64),
                    dll_base,
                    entry_point,
                    size_of_image: size,
                    full_dll_name: full_name,
                    base_dll_name: base_name,
                    flags,
                    load_count,
                    tls_index: 0,
                });
                pos = flags_off + 6;
            } else {
                pos += 4;
            }
        }
        modules
    }
}

// ─── VAD range analysis ───────────────────────────────────────────────────────

/// A VAD (Virtual Address Descriptor) node from the process VAD tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VadNode {
    pub start_vpn: u64,
    pub end_vpn: u64,
    pub start_addr: u64,
    pub end_addr: u64,
    pub page_protection: VadPageProtection,
    pub vad_type: VadNodeType,
    pub file_object: u64,
    pub file_path: String,
    pub flags: u32,
}

impl VadNode {
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end_addr.saturating_sub(self.start_addr)
    }

    #[must_use]
    pub const fn is_executable(&self) -> bool {
        matches!(
            self.page_protection,
            VadPageProtection::Execute
                | VadPageProtection::ExecuteRead
                | VadPageProtection::ExecuteReadWrite
                | VadPageProtection::ExecuteWriteCopy
        )
    }

    #[must_use]
    pub const fn is_writable(&self) -> bool {
        matches!(
            self.page_protection,
            VadPageProtection::ReadWrite
                | VadPageProtection::WriteCopy
                | VadPageProtection::ExecuteReadWrite
                | VadPageProtection::ExecuteWriteCopy
        )
    }

    /// Returns `true` if this VAD is a suspicious private executable region.
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        self.is_executable()
            && self.is_writable()
            && matches!(self.vad_type, VadNodeType::Private)
            && self.file_path.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VadPageProtection {
    NoAccess,
    Readonly,
    Execute,
    ExecuteRead,
    ReadWrite,
    WriteCopy,
    ExecuteReadWrite,
    ExecuteWriteCopy,
    PageGuard,
    NoCache,
    WriteCombine,
    Unknown(u32),
}

impl VadPageProtection {
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::Readonly,
            2 => Self::Execute,
            4 => Self::ExecuteRead,
            8 => Self::ReadWrite,
            16 => Self::WriteCopy,
            32 => Self::ExecuteReadWrite,
            64 => Self::ExecuteWriteCopy,
            128 => Self::PageGuard,
            n => Self::Unknown(n),
        }
    }

    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::NoAccess => "NO_ACCESS",
            Self::Readonly => "READONLY",
            Self::Execute => "EXECUTE",
            Self::ExecuteRead => "EXECUTE_READ",
            Self::ReadWrite => "READ_WRITE",
            Self::WriteCopy => "WRITE_COPY",
            Self::ExecuteReadWrite => "EXECUTE_READ_WRITE",
            Self::ExecuteWriteCopy => "EXECUTE_WRITE_COPY",
            Self::PageGuard => "PAGE_GUARD",
            Self::NoCache => "NO_CACHE",
            Self::WriteCombine => "WRITE_COMBINE",
            Self::Unknown(_) => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VadNodeType {
    Private,
    Mapped,
    Image,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_eprocess_block(pid: u32, ppid: u32, name: &str) -> Vec<u8> {
        let offs = EprocessOffsets::win10_x64();
        let size = 0xB00usize;
        let mut data = vec![0u8; size];
        data[offs.unique_process_id..offs.unique_process_id + 4]
            .copy_from_slice(&pid.to_le_bytes());
        data[offs.inherited_from_unique_process_id..offs.inherited_from_unique_process_id + 4]
            .copy_from_slice(&ppid.to_le_bytes());
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len().min(15);
        data[offs.image_file_name..offs.image_file_name + name_len]
            .copy_from_slice(&name_bytes[..name_len]);
        data[offs.active_threads..offs.active_threads + 4].copy_from_slice(&5u32.to_le_bytes());
        data
    }

    #[test]
    fn eprocess_walker_parses_entry() {
        let offsets = EprocessOffsets::win10_x64();
        let data = make_eprocess_block(1234, 4, "malware.exe");
        let walker = EprocessListWalker::new(offsets.clone());
        let entry = walker.parse_eprocess(&data, 0, 0).unwrap();
        assert_eq!(entry.pid, 1234);
        assert_eq!(entry.ppid, 4);
        assert_eq!(entry.image_name, "malware.exe");
        assert_eq!(entry.active_threads, 5);
    }

    #[test]
    fn eprocess_system_detection() {
        let e = EprocessEntry {
            address: 0,
            pid: 4,
            ppid: 0,
            image_name: "System".into(),
            create_time: 0,
            exit_time: 0,
            peb_address: 0,
            vad_root: 0,
            object_table: 0,
            active_threads: 100,
            flags: ProcessFlags::from_raw(0, 0),
            is_exited: false,
        };
        assert!(e.is_system());
        assert!(!e.has_suspicious_name());
    }

    #[test]
    fn eprocess_suspicious_name() {
        let e = EprocessEntry {
            address: 0,
            pid: 5678,
            ppid: 1234,
            image_name: "evil cmd".into(), // has space
            create_time: 0,
            exit_time: 0,
            peb_address: 0,
            vad_root: 0,
            object_table: 0,
            active_threads: 2,
            flags: ProcessFlags::from_raw(0, 0),
            is_exited: false,
        };
        assert!(e.has_suspicious_name());
    }

    #[test]
    fn handle_type_from_u32() {
        assert_eq!(HandleType::from_u32(7), HandleType::Process);
        assert_eq!(HandleType::from_u32(30), HandleType::File);
        assert_eq!(HandleType::from_u32(99), HandleType::Unknown(99));
        assert_eq!(HandleType::Process.as_str(), "Process");
    }

    #[test]
    fn handle_table_parser_empty_page() {
        let data = vec![0u8; 256 * 16];
        let entries = HandleTableParser::parse_page(&data, 1234);
        assert!(entries.is_empty());
    }

    #[test]
    fn handle_table_parser_single_entry() {
        let mut data = vec![0u8; 16 * 4];
        // First entry: object_ptr=0x1000, access=FULL, type=Process(7)
        data[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        data[8..12].copy_from_slice(&0x001F_0FFFu32.to_le_bytes());
        data[12..16].copy_from_slice(&7u32.to_le_bytes());
        let entries = HandleTableParser::parse_page(&data, 100);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].handle_type, HandleType::Process);
        assert_eq!(entries[0].handle_value, 4);
    }

    #[test]
    fn handle_table_summarize() {
        let entries = vec![
            HandleEntry {
                handle_value: 4,
                object_ptr: 0x1000,
                access_mask: 0xFFFF,
                handle_type: HandleType::Process,
                object_name: String::new(),
                pid: 1234,
            },
            HandleEntry {
                handle_value: 8,
                object_ptr: 0x2000,
                access_mask: 0xFFFF,
                handle_type: HandleType::File,
                object_name: String::new(),
                pid: 1234,
            },
            HandleEntry {
                handle_value: 12,
                object_ptr: 0x3000,
                access_mask: 0xFFFF,
                handle_type: HandleType::File,
                object_name: String::new(),
                pid: 1234,
            },
        ];
        let summary = HandleTableParser::summarize(&entries);
        assert_eq!(summary["Process"], 1);
        assert_eq!(summary["File"], 2);
    }

    #[test]
    fn ldr_scanner_finds_modules() {
        let mut data = Vec::new();
        data.extend_from_slice(b"LDRE");
        data.extend_from_slice(&0x7FFF_A000_u64.to_le_bytes()); // dll_base
        data.extend_from_slice(&0x7FFF_A100_u64.to_le_bytes()); // entry_point
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // size
        let name = b"ntdll.dll";
        data.extend_from_slice(&(name.len() as u16).to_le_bytes());
        data.extend_from_slice(name);
        let base = b"ntdll.dll";
        data.extend_from_slice(&(base.len() as u16).to_le_bytes());
        data.extend_from_slice(base);
        data.extend_from_slice(&0u32.to_le_bytes()); // flags
        data.extend_from_slice(&1u16.to_le_bytes()); // load_count
        let modules = PebLdrScanner::scan(&data);
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].base_dll_name, "ntdll.dll");
    }

    #[test]
    fn vad_node_suspicious_detection() {
        let node = VadNode {
            start_vpn: 0x100,
            end_vpn: 0x110,
            start_addr: 0x0010_0000,
            end_addr: 0x0011_0000,
            page_protection: VadPageProtection::ExecuteReadWrite,
            vad_type: VadNodeType::Private,
            file_object: 0,
            file_path: String::new(),
            flags: 0,
        };
        assert!(node.is_suspicious());
        assert!(node.is_executable());
        assert!(node.is_writable());
    }

    #[test]
    fn vad_page_protection_as_str() {
        assert_eq!(
            VadPageProtection::ExecuteReadWrite.as_str(),
            "EXECUTE_READ_WRITE"
        );
        assert_eq!(VadPageProtection::Readonly.as_str(), "READONLY");
        assert_eq!(VadPageProtection::from_u32(8), VadPageProtection::ReadWrite);
    }

    #[test]
    fn process_flags_parsing() {
        let flags = ProcessFlags::from_raw(0x0015, 1); // create_reported + process_exiting + wow64
        assert!(flags.create_reported);
        assert!(flags.process_exiting);
        assert!(flags.wow64_process);
        assert!(!flags.deleted);
    }

    #[test]
    fn ldr_module_suspicious_path() {
        let m = LdrModuleEntry {
            address: 0,
            dll_base: 0,
            entry_point: 0,
            size_of_image: 0,
            full_dll_name: r"C:\Users\Public\temp\evil.dll".into(),
            base_dll_name: "evil.dll".into(),
            flags: 0,
            load_count: 1,
            tls_index: 0,
        };
        assert!(m.is_suspicious_path());
    }

    #[test]
    fn eprocess_offsets_win7_sanity() {
        let offs = EprocessOffsets::win7_x64();
        assert_eq!(offs.unique_process_id, 0x180);
        assert_eq!(offs.image_file_name, 0x2E0);
    }
}
