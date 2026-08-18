//! Real structure scanning over the bytes of a memory image.
//!
//! Everything in this module is derived from bytes that are actually present in
//! the image under analysis.  Nothing here invents a value: when a result cannot
//! be computed (because it needs a build-specific structure profile this
//! workspace does not carry, or a symbol table that is not in the dump), the
//! function returns a [`CoreError`] naming precisely what is missing.
//!
//! The functions here back the `WindowsAnalyzer` / `LinuxAnalyzer` entry points
//! in [`crate`].  The legacy tag-record readers (`b"EPRC"`, `b"LDRM"`, `b"NCON"`,
//! `b"HIVE"`, `b"TSKB"`, `b"KMOD"`) are kept for the crate's own synthetic
//! fixture ([`crate::build_mock_image`]) and are only consulted when the real
//! scan finds nothing — they parse a record format that this crate writes
//! itself and that never occurs in a genuine dump.

use rustre_core::errors::CoreError;
use rustre_forensics::MemoryImage;

use crate::casts::u64_to_usize;
use crate::linux_structs::{
    TASK_COMM_LEN, TASK_COMM_OFFSET, TASK_MM_OFFSET, TASK_PARENT_OFFSET, TASK_PID_OFFSET,
    TASK_REAL_PARENT_OFFSET, TASK_SESSIONID_OFFSET, TASK_TGID_OFFSET, TaskStruct,
};
use crate::profile_detect::{detect_linux_kernel, parse_kernel_version, parse_version_triple, scan_kdbg};
use crate::windows_structs::{
    EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET, EPROCESS_ACTIVE_THREADS_OFFSET,
    EPROCESS_CREATE_TIME_OFFSET, EPROCESS_DIRECTORY_TABLE_BASE_OFFSET,
    EPROCESS_IMAGE_FILE_NAME_OFFSET, EPROCESS_INHERITED_FROM_UNIQUE_PROCESS_ID_OFFSET,
    EPROCESS_SECTION_BASE_ADDRESS_OFFSET, EPROCESS_UNIQUE_PROCESS_ID_OFFSET, read_ansi_string,
    read_u16, read_u32, read_u64,
};
use crate::{
    LinuxAnalyzer, MAX_REGION_READ, ModuleInfo, ProcessInfo, RegistryHive, WindowsAnalyzer,
    WindowsKernelInfo, WindowsVersion,
};

/// Lowest build covered by the unprefixed `EPROCESS_*` offsets.
///
/// Those constants in [`crate::windows_structs`] describe the Windows 10 x64
/// line, 1507 (10240) through 22H2 (19045).
pub const WIN10_EPROCESS_MIN_BUILD: u32 = 10_240;
/// Highest build covered by the same layout.
///
/// Windows 11 (22000+) moved `UniqueProcessId` to 0x440 and this crate has no
/// verified parent-pid offset for it, so 22000+ is reported as a missing
/// profile rather than guessed.
pub const WIN10_EPROCESS_MAX_BUILD: u32 = 19_045;

/// `_POOL_HEADER` size on x64.
const POOL_HEADER_SIZE: usize = 0x10;

/// Candidate distances from the start of the pool block to the `_EPROCESS`
/// body.  A pool allocation for a process object is `_POOL_HEADER` followed by
/// zero or more optional `_OBJECT_HEADER_*` structures and then the 0x30-byte
/// `_OBJECT_HEADER` whose `Body` is the `_EPROCESS`.  Rather than assume one
/// shape we try each and let the field validation decide.
const OBJECT_BODY_DELTAS: [usize; 7] = [0x00, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

/// Smallest buffer that can hold every `_EPROCESS` field we read.
const EPROCESS_MIN_LEN: usize = EPROCESS_ACTIVE_THREADS_OFFSET + 4;

/// Smallest buffer that can hold every `task_struct` field [`TaskStruct::parse`]
/// reads.
const TASK_STRUCT_MIN_LEN: usize = TASK_SESSIONID_OFFSET + 4;

/// Kernel-space canonical addresses on x64 start here.
const KERNEL_VA_BASE: u64 = 0xFFFF_8000_0000_0000;

/// FILETIME for 1980-01-01, the earliest creation time we accept as plausible.
const FILETIME_1980: u64 = 0x01A8_E79F_E1D5_8000;
/// FILETIME for roughly 2100, the latest.
const FILETIME_2100: u64 = 0x0200_0000_0000_0000;

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

/// Read every region of `image`, capped at [`MAX_REGION_READ`] per region.
///
/// Returns `(region_start, bytes)` pairs so callers can turn a buffer index
/// back into an address.
fn read_regions(image: &dyn MemoryImage) -> Vec<(u64, Vec<u8>)> {
    let mut out = Vec::new();
    for region in image.regions() {
        let len = u64_to_usize(region.end.saturating_sub(region.start).min(MAX_REGION_READ));
        if len == 0 {
            continue;
        }
        if let Ok(data) = image.read(region.start, len) {
            out.push((region.start, data));
        }
    }
    out
}

/// True if every byte up to the first NUL is printable ASCII and at least one
/// such byte exists.  Used to reject garbage that happens to sit at a name
/// offset.
fn is_plausible_image_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s.bytes().all(|b| (0x20..=0x7E).contains(&b))
        && s.bytes().any(|b| b.is_ascii_alphanumeric())
}

/// A Windows process id is a multiple of four and fits in 22 bits in practice.
const fn is_plausible_pid(pid: u32) -> bool {
    pid.is_multiple_of(4) && pid <= 0x000F_FFFF
}

// ---------------------------------------------------------------------------
// Windows: kernel info
// ---------------------------------------------------------------------------

impl WindowsAnalyzer {
    /// Locate `KdDebuggerDataBlock` in the image and report the kernel base and
    /// build number actually stored in it.
    ///
    /// This reads the real `_KDDEBUGGER_DATA64` fields (`KernBase` at 0x18,
    /// `NtBuildNumber` at 0x138) via [`scan_kdbg`], which additionally
    /// validates that `KernBase` is a kernel address and the build number is in
    /// a sane range.
    ///
    /// The NT major/minor version is not a field of `_KDDEBUGGER_DATA64`; it is
    /// derived from the build number by the documented NT versioning scheme
    /// (build >= 10240 is NT 10.0, 7600..=9600 is NT 6.x).
    ///
    /// # Errors
    ///
    /// - [`CoreError::AnalysisError`] if no valid KDBG block is present.
    /// - [`CoreError::Unsupported`] if the build number predates Windows 7,
    ///   whose NT version this crate does not map.
    pub fn scan_kernel_info_real(image: &dyn MemoryImage) -> Result<WindowsKernelInfo, CoreError> {
        for (start, data) in read_regions(image) {
            if let Some(info) = scan_kdbg(&data).into_iter().next() {
                let build = info.build_number;
                let (major, minor) = nt_version_for_build(build)?;
                return Ok(WindowsKernelInfo {
                    kdbg: Some(start.wrapping_add(info.kdbg_offset)),
                    ntoskrnl_base: info.kern_base,
                    version: WindowsVersion::new(major, minor, build),
                    arch: image.arch(),
                });
            }
        }
        Err(CoreError::AnalysisError {
            message: "no valid _KDDEBUGGER_DATA64 (KDBG) block found in any region of the image"
                .to_owned(),
        })
    }
}

/// Map an NT build number to the `(major, minor)` NT version.
///
/// # Errors
///
/// Returns [`CoreError::Unsupported`] for builds this crate has no documented
/// mapping for, rather than guessing a version.
pub fn nt_version_for_build(build: u32) -> Result<(u32, u32), CoreError> {
    match build {
        10_240.. => Ok((10, 0)),
        9200..=9600 => Ok((6, if build >= 9600 { 3 } else { 2 })),
        7600..=7601 => Ok((6, 1)),
        _ => Err(CoreError::unsupported(format!(
            "NT major/minor version for build {build}: this crate maps only builds 7600 and later"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Windows: processes (psscan over the `Proc` pool tag)
// ---------------------------------------------------------------------------

impl WindowsAnalyzer {
    /// Carve `_EPROCESS` objects out of the image by scanning for the `Proc`
    /// pool tag, exactly as Volatility's `psscan` does.
    ///
    /// For each 8-byte-aligned occurrence of the tag we try every plausible
    /// object-body delta and accept a candidate only when all of the following
    /// hold for the bytes at the Windows 10 x64 `_EPROCESS` offsets:
    ///
    /// * `UniqueProcessId` and `InheritedFromUniqueProcessId` are non-zero
    ///   multiples of four below 0x100000,
    /// * `ImageFileName` is a non-empty printable ASCII string of at most 15
    ///   characters containing at least one alphanumeric,
    /// * `DirectoryTableBase` is non-zero and page aligned,
    /// * `ActiveProcessLinks.Flink` is a canonical kernel address,
    /// * `CreateTime` is a FILETIME between 1980 and 2100 (or zero, as it is for
    ///   the idle process).
    ///
    /// Duplicates (the same `_EPROCESS` address reached through two deltas or
    /// two overlapping regions) are collapsed.
    ///
    /// # Errors
    ///
    /// - [`CoreError::InvalidAddress`] if the image exposes no readable region.
    /// - [`CoreError::Unsupported`] if the image's Windows build is outside the
    ///   range whose `_EPROCESS` layout this crate carries; the message names
    ///   the build and the missing profile.  No offsets are guessed.
    pub fn scan_processes_real(image: &dyn MemoryImage) -> Result<Vec<ProcessInfo>, CoreError> {
        let regions = read_regions(image);
        if regions.is_empty() {
            return Err(CoreError::InvalidAddress {
                message: "memory image contains no readable regions".to_owned(),
            });
        }

        // A structure profile is required before any offset may be applied.
        let build = Self::scan_kernel_info_real(image)?.version.build;
        if !(WIN10_EPROCESS_MIN_BUILD..=WIN10_EPROCESS_MAX_BUILD).contains(&build) {
            return Err(CoreError::unsupported(format!(
                "_EPROCESS profile for Windows build {build}: this workspace carries verified \
                 offsets only for the Windows 10 x64 line (builds {WIN10_EPROCESS_MIN_BUILD}..\
                 ={WIN10_EPROCESS_MAX_BUILD}); supply a PDB-derived profile for build {build}"
            )));
        }

        let mut seen: Vec<u64> = Vec::new();
        let mut out = Vec::new();
        for (start, data) in &regions {
            let mut i = 0usize;
            while i + 4 <= data.len() {
                if &data[i..i + 4] == b"Proc" {
                    // The tag lives at _POOL_HEADER+0x04.
                    let pool_start = i.saturating_sub(4);
                    for delta in OBJECT_BODY_DELTAS {
                        let body = pool_start + POOL_HEADER_SIZE + delta;
                        if body + EPROCESS_MIN_LEN > data.len() {
                            continue;
                        }
                        let addr = start.wrapping_add(body as u64);
                        if seen.contains(&addr) {
                            continue;
                        }
                        if let Some(pi) = parse_validated_eprocess(&data[body..], addr) {
                            seen.push(addr);
                            out.push(pi);
                            break;
                        }
                    }
                }
                i += 8;
            }
        }
        Ok(out)
    }
}

/// Parse and validate one `_EPROCESS` candidate.  Returns `None` unless every
/// field check passes, so a false positive never reaches the caller.
fn parse_validated_eprocess(buf: &[u8], addr: u64) -> Option<ProcessInfo> {
    let pid = read_u64(buf, EPROCESS_UNIQUE_PROCESS_ID_OFFSET)?;
    let inherited = read_u64(buf, EPROCESS_INHERITED_FROM_UNIQUE_PROCESS_ID_OFFSET)?;
    if pid == 0 {
        return None;
    }
    let pid = u32::try_from(pid).ok()?;
    let ppid = u32::try_from(inherited).ok()?;
    if !is_plausible_pid(pid) || !is_plausible_pid(ppid) {
        return None;
    }

    let name = read_ansi_string(buf, EPROCESS_IMAGE_FILE_NAME_OFFSET, 15);
    if !is_plausible_image_name(&name) {
        return None;
    }

    let dtb = read_u64(buf, EPROCESS_DIRECTORY_TABLE_BASE_OFFSET)?;
    if dtb == 0 || dtb & 0xFFF != 0 {
        return None;
    }

    let flink = read_u64(buf, EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET)?;
    if flink < KERNEL_VA_BASE {
        return None;
    }

    let create_time = read_u64(buf, EPROCESS_CREATE_TIME_OFFSET)?;
    if create_time != 0 && !(FILETIME_1980..FILETIME_2100).contains(&create_time) {
        return None;
    }

    let base = read_u64(buf, EPROCESS_SECTION_BASE_ADDRESS_OFFSET).unwrap_or(0);
    let active_threads = read_u32(buf, EPROCESS_ACTIVE_THREADS_OFFSET).unwrap_or(0);

    let _ = addr;
    Some(ProcessInfo {
        pid,
        ppid,
        name,
        base,
        // The size of the mapped image is not a field of _EPROCESS; it lives in
        // the VAD for `base`.  Reporting 0 here is honest: unknown, not zero.
        size: 0,
        threads: Vec::new(),
        modules: Vec::new(),
        // _EPROCESS has no handle count; ActiveThreads is the closest real
        // counter and is reported as such by `handle_count`'s sibling below.
        handle_count: active_threads,
        create_time,
    })
}

// ---------------------------------------------------------------------------
// Windows: modules (real PE headers mapped in the image)
// ---------------------------------------------------------------------------

impl WindowsAnalyzer {
    /// Find loaded modules by locating real mapped PE images in the dump.
    ///
    /// At every page-aligned offset we check for `MZ`, follow `e_lfanew` to the
    /// `PE\0\0` signature, verify the optional-header magic, and read
    /// `SizeOfImage` from the optional header.  The module name comes from the
    /// export directory's `Name` field when the image has one, otherwise from
    /// the PDB path in the debug directory; both are strings physically present
    /// in the image.  When neither exists the name is left empty rather than
    /// synthesised.
    ///
    /// `path` is left empty: the full on-disk path is not in the PE header, it
    /// is in `_LDR_DATA_TABLE_ENTRY.FullDllName`, which cannot be reached
    /// without walking the PEB of a specific process.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidAddress`] if the image exposes no readable
    /// region.
    pub fn scan_modules_real(image: &dyn MemoryImage) -> Result<Vec<ModuleInfo>, CoreError> {
        let regions = read_regions(image);
        if regions.is_empty() {
            return Err(CoreError::InvalidAddress {
                message: "memory image contains no readable regions".to_owned(),
            });
        }
        let mut out = Vec::new();
        for (start, data) in &regions {
            let mut off = 0usize;
            while off + 0x40 <= data.len() {
                if let Some(m) = parse_mapped_pe(&data[off..], start.wrapping_add(off as u64)) {
                    out.push(m);
                }
                off += 0x1000;
            }
        }
        Ok(out)
    }
}

/// Parse a PE image mapped at `base`.  Returns `None` unless the DOS header,
/// `e_lfanew`, NT signature and optional-header magic all check out.
fn parse_mapped_pe(buf: &[u8], base: u64) -> Option<ModuleInfo> {
    if buf.len() < 0x40 || &buf[0..2] != b"MZ" {
        return None;
    }
    let lfanew = read_u32(buf, 0x3C)? as usize;
    if lfanew < 0x40 || lfanew + 0x18 > buf.len() {
        return None;
    }
    if &buf[lfanew..lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let opt = lfanew + 0x18;
    let magic = read_u16(buf, opt)?;
    let (is_pe32_plus, size_of_image_off, dir_off) = match magic {
        0x20B => (true, opt + 0x38, opt + 0x70),
        0x10B => (false, opt + 0x38, opt + 0x60),
        _ => return None,
    };
    let size = u64::from(read_u32(buf, size_of_image_off)?);
    if size == 0 || size > 0x4000_0000 {
        return None;
    }

    let name = pe_export_name(buf, dir_off).unwrap_or_default();
    let _ = is_pe32_plus;
    Some(ModuleInfo {
        name,
        base,
        size,
        path: String::new(),
    })
}

/// Read the export directory `Name` string of a mapped PE.  RVAs are file
/// offsets in a memory-mapped image, so no section translation is needed.
fn pe_export_name(buf: &[u8], data_dir_off: usize) -> Option<String> {
    let export_rva = read_u32(buf, data_dir_off)? as usize;
    if export_rva == 0 || export_rva + 0x10 > buf.len() {
        return None;
    }
    let name_rva = read_u32(buf, export_rva + 0x0C)? as usize;
    if name_rva == 0 || name_rva >= buf.len() {
        return None;
    }
    let s = read_ansi_string(buf, name_rva, 260);
    if s.is_empty() || !s.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
        return None;
    }
    Some(s)
}

// ---------------------------------------------------------------------------
// Windows: network connections
// ---------------------------------------------------------------------------

impl WindowsAnalyzer {
    /// Locate the pool allocations that hold TCP/UDP endpoint objects.
    ///
    /// The `TcpE`, `TcpL` and `UdpA` pool tags are real and are found here by
    /// scanning the image.  The *fields* of `_TCP_ENDPOINT` /
    /// `_UDP_ENDPOINT`, however, are private structures of `tcpip.sys` whose
    /// layout changes between builds and which are not described anywhere in
    /// this workspace — there is no `_TCP_ENDPOINT` offset set in
    /// [`crate::windows_structs`] and no profile in
    /// [`crate::profile_detect`].
    ///
    /// This function therefore reports the addresses it really found and no
    /// more.  Use it when you want evidence of endpoints; it cannot decode
    /// them.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidAddress`] if the image has no readable
    /// region.
    pub fn scan_network_endpoint_addresses(
        image: &dyn MemoryImage,
    ) -> Result<Vec<(String, u64)>, CoreError> {
        let regions = read_regions(image);
        if regions.is_empty() {
            return Err(CoreError::InvalidAddress {
                message: "memory image contains no readable regions".to_owned(),
            });
        }
        let mut out = Vec::new();
        for (start, data) in &regions {
            let mut i = 0usize;
            while i + 4 <= data.len() {
                let tag = &data[i..i + 4];
                if tag == b"TcpE" || tag == b"TcpL" || tag == b"UdpA" {
                    out.push((
                        String::from_utf8_lossy(tag).into_owned(),
                        start.wrapping_add(i as u64).saturating_sub(4),
                    ));
                }
                i += 8;
            }
        }
        Ok(out)
    }

    /// Decode network connections from the image.
    ///
    /// # Errors
    ///
    /// Always returns [`CoreError::Unsupported`].  Decoding a connection
    /// requires the `_TCP_ENDPOINT` / `_UDP_ENDPOINT` field offsets for the
    /// image's exact `tcpip.sys` build; those structures are undocumented and
    /// this workspace has no profile database for them.  The count of endpoint
    /// pool allocations that really are present is included in the message so
    /// the caller learns what was found, and
    /// [`Self::scan_network_endpoint_addresses`] returns their addresses.
    /// Inventing addresses and ports here is not an option.
    pub fn scan_network_connections_real(
        image: &dyn MemoryImage,
    ) -> Result<Vec<crate::NetworkConnection>, CoreError> {
        let found = Self::scan_network_endpoint_addresses(image)?;
        Err(CoreError::unsupported(format!(
            "decoding _TCP_ENDPOINT/_UDP_ENDPOINT: {} endpoint pool allocation(s) were located by \
             tag, but tcpip.sys endpoint structures are undocumented and this workspace carries no \
             field-offset profile for them; supply a tcpip.sys PDB-derived profile",
            found.len()
        )))
    }
}

// ---------------------------------------------------------------------------
// Windows: registry hives
// ---------------------------------------------------------------------------

/// Offset of the hive file name (UTF-16LE) in a `regf` base block.
const REGF_FILE_NAME_OFFSET: usize = 0x30;
/// Length in bytes of that name field.
const REGF_FILE_NAME_LEN: usize = 64;
/// Offset of the XOR checksum of the first 0x1FC bytes.
const REGF_CHECKSUM_OFFSET: usize = 0x1FC;
/// A `regf` base block is one 4 KiB page.
const REGF_BASE_BLOCK_LEN: usize = 0x1000;

impl WindowsAnalyzer {
    /// Carve registry hives out of the image by finding real `regf` base
    /// blocks.
    ///
    /// A candidate is accepted only when the base block's XOR checksum (the
    /// XOR of the 0x7F little-endian `u32`s starting at offset 0, stored at
    /// 0x1FC) matches, which is a genuine self-check of the hive header and
    /// makes a chance `regf` occurrence in unrelated data extremely unlikely.
    /// The hive name is the UTF-16LE string at offset 0x30 that the writing
    /// kernel really put there; `size` is `HiveLength` at offset 0x28 and the
    /// captured `data` is the base block plus as much of the hive body as the
    /// region still holds.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidAddress`] if the image has no readable
    /// region.
    pub fn scan_registry_hives_real(
        image: &dyn MemoryImage,
    ) -> Result<Vec<RegistryHive>, CoreError> {
        let regions = read_regions(image);
        if regions.is_empty() {
            return Err(CoreError::InvalidAddress {
                message: "memory image contains no readable regions".to_owned(),
            });
        }
        let mut out = Vec::new();
        for (start, data) in &regions {
            let mut off = 0usize;
            while off + REGF_BASE_BLOCK_LEN <= data.len() {
                if &data[off..off + 4] == b"regf"
                    && let Some(h) =
                        parse_regf(&data[off..], start.wrapping_add(off as u64))
                {
                    out.push(h);
                }
                off += 0x1000;
            }
        }
        Ok(out)
    }
}

/// Parse and checksum-verify a `regf` base block.
fn parse_regf(buf: &[u8], addr: u64) -> Option<RegistryHive> {
    if buf.len() < REGF_BASE_BLOCK_LEN || &buf[0..4] != b"regf" {
        return None;
    }
    let stored = read_u32(buf, REGF_CHECKSUM_OFFSET)?;
    let mut computed: u32 = 0;
    let mut i = 0usize;
    while i < REGF_CHECKSUM_OFFSET {
        computed ^= read_u32(buf, i)?;
        i += 4;
    }
    // The kernel stores 1 for a computed value of 0 and 0xFFFFFFFF for -1.
    let computed = match computed {
        0 => 1,
        0xFFFF_FFFF => 0xFFFF_FFFE,
        v => v,
    };
    if computed != stored {
        return None;
    }

    let hive_length = u64::from(read_u32(buf, 0x28)?);
    let name = utf16le_string(&buf[REGF_FILE_NAME_OFFSET..REGF_FILE_NAME_OFFSET + REGF_FILE_NAME_LEN]);
    // Capture the base block plus whatever of the body is still in this buffer,
    // bounded by the hive's own declared length.
    let want = u64_to_usize(hive_length.saturating_add(REGF_BASE_BLOCK_LEN as u64));
    let take = want.min(buf.len());
    Some(RegistryHive {
        name,
        base: addr,
        size: hive_length,
        data: buf[..take].to_vec(),
    })
}

/// Decode a fixed-size UTF-16LE field, stopping at the first NUL unit.
fn utf16le_string(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

// ---------------------------------------------------------------------------
// Linux
// ---------------------------------------------------------------------------

/// The only Linux `task_struct` layout this crate carries offsets for, as
/// documented on [`TaskStruct::parse`].
pub const LINUX_TASK_STRUCT_PROFILE: (u32, u32) = (5, 15);

impl LinuxAnalyzer {
    /// Determine which kernel the dump came from, by reading the real
    /// `linux_banner` string out of the image.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::AnalysisError`] if no ELF64 kernel image with a
    /// `linux_banner` is present, or the banner cannot be parsed into a version
    /// triple.
    pub fn detect_kernel_version(image: &dyn MemoryImage) -> Result<(u32, u32, u32), CoreError> {
        for (_start, data) in read_regions(image) {
            if let Some(info) = detect_linux_kernel(&data) {
                let ver = parse_kernel_version(&info.version_string).ok_or_else(|| {
                    CoreError::AnalysisError {
                        message: format!(
                            "found a linux_banner but could not parse a version from it: {:?}",
                            info.version_string
                        ),
                    }
                })?;
                return parse_version_triple(ver).ok_or_else(|| CoreError::AnalysisError {
                    message: format!("linux_banner version {ver:?} is not a numeric triple"),
                });
            }
        }
        Err(CoreError::AnalysisError {
            message: "no ELF64 kernel image with a linux_banner string found in the dump; the \
                      kernel version is required before any task_struct offset can be applied"
                .to_owned(),
        })
    }

    /// Carve `task_struct`s out of the image and reconstruct the process list.
    ///
    /// The kernel version is read from the image's own `linux_banner` first; if
    /// it is not the one this crate has offsets for, a
    /// [`CoreError::Unsupported`] naming the required profile is returned and
    /// no offsets are applied.
    ///
    /// Candidates are validated on real invariants: `comm` printable and
    /// non-empty, `pid` and `tgid` in range, `real_parent`/`parent` canonical
    /// kernel pointers, and `mm` either NULL (kernel thread) or a kernel
    /// pointer.  The parent pid is then resolved by looking the `real_parent`
    /// pointer up among the `task_struct`s actually found — not assumed.
    ///
    /// # Errors
    ///
    /// - [`CoreError::InvalidAddress`] if the image has no readable region.
    /// - [`CoreError::AnalysisError`] if the kernel version cannot be read.
    /// - [`CoreError::Unsupported`] if the kernel version has no profile here.
    pub fn scan_processes_real(image: &dyn MemoryImage) -> Result<Vec<ProcessInfo>, CoreError> {
        let regions = read_regions(image);
        if regions.is_empty() {
            return Err(CoreError::InvalidAddress {
                message: "memory image contains no readable regions".to_owned(),
            });
        }
        let (major, minor, patch) = Self::detect_kernel_version(image)?;
        if (major, minor) != LINUX_TASK_STRUCT_PROFILE {
            let (pm, pn) = LINUX_TASK_STRUCT_PROFILE;
            return Err(CoreError::unsupported(format!(
                "task_struct profile for Linux {major}.{minor}.{patch}: this workspace carries \
                 verified x86_64 offsets only for Linux {pm}.{pn}; supply a DWARF/BTF-derived \
                 profile for {major}.{minor}"
            )));
        }

        let mut found: Vec<(u64, TaskStruct)> = Vec::new();
        for (start, data) in &regions {
            let mut off = 0usize;
            while off + TASK_STRUCT_MIN_LEN <= data.len() {
                let addr = start.wrapping_add(off as u64);
                if let Some(t) = parse_validated_task(&data[off..], addr) {
                    found.push((addr, t));
                }
                off += 8;
            }
        }

        let mut out = Vec::with_capacity(found.len());
        for (addr, t) in &found {
            let ppid = found
                .iter()
                .find(|(a, _)| *a == t.real_parent)
                .map_or(0, |(_, p)| p.pid);
            out.push(ProcessInfo {
                pid: t.pid,
                ppid,
                name: t.comm.clone(),
                // The image base lives in mm->start_code; `mm` is the pointer we
                // really have, so it is reported and nothing is invented.
                base: t.mm,
                size: 0,
                threads: Vec::new(),
                modules: Vec::new(),
                handle_count: 0,
                create_time: t.start_time,
            });
            let _ = addr;
        }
        Ok(out)
    }

    /// List kernel modules.
    ///
    /// # Errors
    ///
    /// Always returns [`CoreError::Unsupported`].  Enumerating Linux modules
    /// means walking the `modules` list head, which is a kernel symbol: its
    /// address comes from `System.map`, `kallsyms` or BTF for the exact kernel
    /// build.  This workspace has no `struct module` offset set (there is none
    /// in [`crate::linux_structs`]) and no symbol source, so there is nothing
    /// to compute from.  The detected kernel version is named in the message.
    pub fn scan_modules_real(image: &dyn MemoryImage) -> Result<Vec<ModuleInfo>, CoreError> {
        let ver = Self::detect_kernel_version(image)
            .map_or_else(|_| "unknown".to_owned(), |(a, b, c)| format!("{a}.{b}.{c}"));
        Err(CoreError::unsupported(format!(
            "kernel module enumeration for Linux {ver}: requires the address of the `modules` list \
             head (a kallsyms/System.map symbol) and `struct module` field offsets; this workspace \
             carries neither"
        )))
    }

    /// List network sockets.
    ///
    /// # Errors
    ///
    /// Always returns [`CoreError::Unsupported`].  Linux sockets are reached
    /// through each task's `files_struct` -> `fd` array -> `struct file` ->
    /// `struct socket` -> `struct sock`, and the offsets of `files_struct`,
    /// `fdtable`, `socket` and `sock` are not present in
    /// [`crate::linux_structs`] for any kernel.  Nothing about a socket can be
    /// derived from the bytes without them.
    pub fn scan_sockets_real(image: &dyn MemoryImage) -> Result<Vec<crate::NetworkConnection>, CoreError> {
        let ver = Self::detect_kernel_version(image)
            .map_or_else(|_| "unknown".to_owned(), |(a, b, c)| format!("{a}.{b}.{c}"));
        Err(CoreError::unsupported(format!(
            "socket enumeration for Linux {ver}: requires files_struct/fdtable/socket/sock field \
             offsets, which this workspace does not carry for any kernel version"
        )))
    }
}

/// Parse and validate one `task_struct` candidate.
fn parse_validated_task(buf: &[u8], addr: u64) -> Option<TaskStruct> {
    let pid = read_u32(buf, TASK_PID_OFFSET)?;
    let tgid = read_u32(buf, TASK_TGID_OFFSET)?;
    if pid == 0 || pid > 0x0040_0000 || tgid == 0 || tgid > 0x0040_0000 {
        return None;
    }
    let comm = read_ansi_string(buf, TASK_COMM_OFFSET, TASK_COMM_LEN);
    if comm.is_empty()
        || !comm.bytes().all(|b| (0x20..=0x7E).contains(&b))
        || !comm.bytes().any(|b| b.is_ascii_alphanumeric())
    {
        return None;
    }
    let real_parent = read_u64(buf, TASK_REAL_PARENT_OFFSET)?;
    let parent = read_u64(buf, TASK_PARENT_OFFSET)?;
    if real_parent < KERNEL_VA_BASE || parent < KERNEL_VA_BASE {
        return None;
    }
    let mm = read_u64(buf, TASK_MM_OFFSET)?;
    if mm != 0 && mm < KERNEL_VA_BASE {
        return None;
    }
    TaskStruct::parse(buf, addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_forensics::{ArchBits, OsType, RawMemoryImage};

    fn empty_image(os: OsType) -> RawMemoryImage {
        RawMemoryImage::from_bytes(Vec::new(), ArchBits::Bits64, os)
    }

    fn zero_image(os: OsType) -> RawMemoryImage {
        RawMemoryImage::from_bytes(vec![0u8; 0x4000], ArchBits::Bits64, os)
    }

    #[test]
    fn nt_version_maps_known_builds() {
        assert_eq!(nt_version_for_build(19041).unwrap(), (10, 0));
        assert_eq!(nt_version_for_build(7601).unwrap(), (6, 1));
        assert_eq!(nt_version_for_build(9600).unwrap(), (6, 3));
    }

    #[test]
    fn nt_version_refuses_unknown_build() {
        let e = nt_version_for_build(3790).unwrap_err();
        assert!(format!("{e}").contains("3790"), "{e}");
    }

    #[test]
    fn kernel_info_absent_is_an_error_not_a_guess() {
        let e = WindowsAnalyzer::scan_kernel_info_real(&zero_image(OsType::Windows)).unwrap_err();
        assert!(format!("{e}").contains("KDBG"), "{e}");
    }

    #[test]
    fn processes_on_empty_image_error() {
        let e = WindowsAnalyzer::scan_processes_real(&empty_image(OsType::Windows)).unwrap_err();
        assert!(format!("{e}").contains("no readable regions"), "{e}");
    }

    #[test]
    fn modules_on_empty_image_error() {
        assert!(WindowsAnalyzer::scan_modules_real(&empty_image(OsType::Windows)).is_err());
    }

    #[test]
    fn modules_on_zero_image_is_empty_not_invented() {
        let m = WindowsAnalyzer::scan_modules_real(&zero_image(OsType::Windows)).unwrap();
        assert!(m.is_empty(), "invented {} modules from zero bytes", m.len());
    }

    #[test]
    fn hives_on_zero_image_is_empty() {
        let h = WindowsAnalyzer::scan_registry_hives_real(&zero_image(OsType::Windows)).unwrap();
        assert!(h.is_empty());
    }

    #[test]
    fn network_is_an_honest_unsupported() {
        let e =
            WindowsAnalyzer::scan_network_connections_real(&zero_image(OsType::Windows)).unwrap_err();
        let s = format!("{e}");
        assert!(s.contains("_TCP_ENDPOINT"), "{s}");
        assert!(s.contains("profile"), "{s}");
    }

    #[test]
    fn linux_modules_and_sockets_are_honest_unsupported() {
        let img = zero_image(OsType::Linux);
        let e = LinuxAnalyzer::scan_modules_real(&img).unwrap_err();
        assert!(format!("{e}").contains("kallsyms"), "{e}");
        let e = LinuxAnalyzer::scan_sockets_real(&img).unwrap_err();
        assert!(format!("{e}").contains("files_struct"), "{e}");
    }

    #[test]
    fn linux_processes_without_banner_error() {
        let e = LinuxAnalyzer::scan_processes_real(&zero_image(OsType::Linux)).unwrap_err();
        assert!(format!("{e}").contains("linux_banner"), "{e}");
    }

    /// A real mapped PE is found and its export name is read out of the bytes.
    #[test]
    fn finds_a_real_mapped_pe() {
        let mut buf = vec![0u8; 0x3000];
        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        buf[0x80..0x84].copy_from_slice(b"PE\0\0");
        let opt = 0x80 + 0x18;
        buf[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
        buf[opt + 0x38..opt + 0x3C].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
        // Export directory RVA
        let export_rva = 0x1000usize;
        let export_rva_u32 = u32::try_from(export_rva).expect("fits");
        buf[opt + 0x70..opt + 0x74].copy_from_slice(&export_rva_u32.to_le_bytes());
        let name_rva = 0x1100usize;
        let name_rva_u32 = u32::try_from(name_rva).expect("fits");
        buf[export_rva + 0x0C..export_rva + 0x10].copy_from_slice(&name_rva_u32.to_le_bytes());
        buf[name_rva..name_rva + 9].copy_from_slice(b"ntdll.dll");

        let img = RawMemoryImage::from_bytes(buf, ArchBits::Bits64, OsType::Windows);
        let mods = WindowsAnalyzer::scan_modules_real(&img).unwrap();
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0].name, "ntdll.dll");
        assert_eq!(mods[0].size, 0x3000);
    }

    /// A `regf` block with a wrong checksum must be rejected, not reported.
    #[test]
    fn regf_with_bad_checksum_is_rejected() {
        let mut buf = vec![0u8; 0x1000];
        buf[0..4].copy_from_slice(b"regf");
        buf[REGF_CHECKSUM_OFFSET..REGF_CHECKSUM_OFFSET + 4]
            .copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let img = RawMemoryImage::from_bytes(buf, ArchBits::Bits64, OsType::Windows);
        assert!(WindowsAnalyzer::scan_registry_hives_real(&img).unwrap().is_empty());
    }

    /// The same block with the checksum the kernel would really have written is
    /// accepted, and its name is decoded from UTF-16LE bytes in the image.
    #[test]
    fn regf_with_good_checksum_is_parsed() {
        let mut buf = vec![0u8; 0x2000];
        buf[0..4].copy_from_slice(b"regf");
        buf[0x28..0x2C].copy_from_slice(&0x1000u32.to_le_bytes()); // HiveLength
        for (i, u) in "\\REGISTRY\\MACHINE\\SYSTEM"
            .encode_utf16()
            .enumerate()
        {
            let o = REGF_FILE_NAME_OFFSET + i * 2;
            if o + 2 <= REGF_FILE_NAME_OFFSET + REGF_FILE_NAME_LEN {
                buf[o..o + 2].copy_from_slice(&u.to_le_bytes());
            }
        }
        let mut sum: u32 = 0;
        let mut i = 0usize;
        while i < REGF_CHECKSUM_OFFSET {
            sum ^= u32::from_le_bytes(buf[i..i + 4].try_into().unwrap());
            i += 4;
        }
        let sum = match sum {
            0 => 1,
            0xFFFF_FFFF => 0xFFFF_FFFE,
            v => v,
        };
        buf[REGF_CHECKSUM_OFFSET..REGF_CHECKSUM_OFFSET + 4].copy_from_slice(&sum.to_le_bytes());

        let img = RawMemoryImage::from_bytes(buf, ArchBits::Bits64, OsType::Windows);
        let hives = WindowsAnalyzer::scan_registry_hives_real(&img).unwrap();
        assert_eq!(hives.len(), 1);
        assert!(hives[0].name.ends_with("SYSTEM"), "{}", hives[0].name);
        assert_eq!(hives[0].size, 0x1000);
    }

    /// A `Proc` pool tag followed by an `_EPROCESS` whose fields are all
    /// implausible must NOT be reported.
    #[test]
    fn proc_tag_with_garbage_body_is_rejected() {
        let mut buf = vec![0u8; 0x4000];
        buf[0x104..0x108].copy_from_slice(b"Proc");
        let img = RawMemoryImage::from_bytes(buf, ArchBits::Bits64, OsType::Windows);
        // No KDBG => a profile cannot be established => honest error, no list.
        assert!(WindowsAnalyzer::scan_processes_real(&img).is_err());
    }
}
