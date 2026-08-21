//! `minidump_analysis` — Windows minidump (.dmp) file parser.
//!
//! Parses the MINIDUMP_HEADER, stream directory, and the most useful streams
//! (ThreadList, ThreadExList, ExceptionStream, ModuleList, MemoryList,
//! SystemInfo, MiscInfo, Memory64List) without any external crate.
//!
//! ## vs WinDbg / x64dbg
//! WinDbg's `.ecxr` / `.lastevent` / `~*kb` surface crash state from a
//! minidump interactively; x64dbg has no native minidump support. This
//! module provides the same crash-state extraction as a queryable index
//! available to an LLM tool-call, offline and without WinDbg installed.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use thiserror::Error;

/// Errors produced by the minidump parser.
#[derive(Debug, Error)]
pub enum MinidumpError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid signature: expected MDMP")]
    BadSignature,
    #[error("invalid version")]
    BadVersion,
    #[error("stream type {0:#x} not found")]
    StreamNotFound(u32),
    #[error("truncated stream at offset {0:#x}")]
    Truncated(u64),
    #[error("unsupported CPU architecture: {0:#x}")]
    UnsupportedArch(u16),
}

// ── low-level binary reader ──────────────────────────────────────────────────

struct Reader<'a> {
    cur: Cursor<&'a [u8]>,
}

impl<'a> Reader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { cur: Cursor::new(data) }
    }

    fn seek(&mut self, pos: u64) -> Result<(), MinidumpError> {
        self.cur.seek(SeekFrom::Start(pos))?;
        Ok(())
    }

    const fn pos(&mut self) -> u64 {
        self.cur.position()
    }

    fn u8(&mut self) -> Result<u8, MinidumpError> {
        let mut buf = [0u8; 1];
        self.cur.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn u16(&mut self) -> Result<u16, MinidumpError> {
        let mut buf = [0u8; 2];
        self.cur.read_exact(&mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    fn u32(&mut self) -> Result<u32, MinidumpError> {
        let mut buf = [0u8; 4];
        self.cur.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn u64(&mut self) -> Result<u64, MinidumpError> {
        let mut buf = [0u8; 8];
        self.cur.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn bytes(&mut self, n: usize) -> Result<Vec<u8>, MinidumpError> {
        let mut buf = vec![0u8; n];
        self.cur.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Read a Windows UTF-16LE `MINIDUMP_STRING` (u32 length-prefix in bytes,
    /// then that many bytes of UTF-16LE chars — NOT null-terminated counted).
    fn minidump_string(&mut self, offset: u32) -> Result<String, MinidumpError> {
        self.seek(u64::from(offset))?;
        let raw_len = self.u32()?;
        // Limit string allocation: raw_len is attacker-controlled.
        const MAX_STRING_BYTES: u32 = 64 * 1024;
        if raw_len > MAX_STRING_BYTES {
            return Err(MinidumpError::Truncated(u64::from(offset)));
        }
        let byte_len = raw_len as usize;
        let bytes = self.bytes(byte_len)?;
        let u16s: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&u16s))
    }
}

// ── stream type constants ────────────────────────────────────────────────────

const STREAM_THREAD_LIST: u32 = 3;
const STREAM_MODULE_LIST: u32 = 4;
const STREAM_MEMORY_LIST: u32 = 5;
const STREAM_EXCEPTION: u32 = 6;
const STREAM_SYSTEM_INFO: u32 = 7;
const STREAM_THREAD_EX_LIST: u32 = 8;
const STREAM_MISC_INFO: u32 = 15;
const STREAM_MEMORY64_LIST: u32 = 9;

// ── public data model ────────────────────────────────────────────────────────

/// CPU architecture extracted from the minidump `SystemInfo` stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CpuArch {
    X86,
    Amd64,
    Arm,
    Arm64,
    Unknown(u16),
}

impl fmt::Display for CpuArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86 => write!(f, "x86"),
            Self::Amd64 => write!(f, "amd64"),
            Self::Arm => write!(f, "arm"),
            Self::Arm64 => write!(f, "arm64"),
            Self::Unknown(v) => write!(f, "unknown({v:#x})"),
        }
    }
}

/// System information extracted from the minidump.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemInfo {
    pub cpu_arch: CpuArch,
    pub cpu_level: u16,
    pub cpu_revision: u16,
    pub number_of_processors: u8,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub platform_id: u32,
}

/// Register snapshot for a single thread.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ThreadContext {
    pub tid: u32,
    pub suspend_count: u32,
    pub priority_class: u32,
    pub priority: u32,
    pub teb: u64,
    /// Named register → value (rip/rsp/rbp/rax/… or eip/esp/… depending on arch).
    pub registers: HashMap<String, u64>,
}

/// Exception record from the `ExceptionStream`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExceptionRecord {
    pub thread_id: u32,
    pub exception_code: u32,
    pub exception_flags: u32,
    pub exception_address: u64,
    pub number_of_parameters: u32,
    pub exception_information: Vec<u64>,
}

/// A loaded module from the `ModuleList` stream.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModuleEntry {
    pub base_address: u64,
    pub size: u32,
    pub checksum: u32,
    pub time_date_stamp: u32,
    pub name: String,
    pub cv_record_offset: u32,
    pub cv_record_size: u32,
}

/// A memory descriptor (raw region) from the `MemoryList` stream.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryDescriptor {
    pub start_address: u64,
    pub size: u32,
    pub file_offset: u32,
}

/// A 64-bit memory descriptor from the `Memory64List` stream.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryDescriptor64 {
    pub start_address: u64,
    pub size: u64,
}

/// Full parsed view of a minidump file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MinidumpView {
    pub flags: u64,
    pub timestamp: u32,
    pub stream_count: u32,
    pub system_info: Option<SystemInfo>,
    pub exception: Option<ExceptionRecord>,
    pub threads: Vec<ThreadContext>,
    pub modules: Vec<ModuleEntry>,
    pub memory_regions: Vec<MemoryDescriptor>,
    pub memory64_regions: Vec<MemoryDescriptor64>,
    /// Process ID from `MiscInfo` (if available).
    pub process_id: Option<u32>,
    /// Machine uptime seconds from `MiscInfo` (if available).
    pub uptime_secs: Option<u32>,
}

impl MinidumpView {
    /// Return the thread context for the crashing thread (the one referenced
    /// by the `ExceptionStream`), if any.
    #[must_use]
    pub fn crashing_thread(&self) -> Option<&ThreadContext> {
        let ex_tid = self.exception.as_ref()?.thread_id;
        self.threads.iter().find(|t| t.tid == ex_tid)
    }

    /// Return the instruction pointer of the crashing thread, whatever this
    /// dump's architecture calls it.
    ///
    /// `pc` was missing from this list, and the parser above stores the `AArch64`
    /// program counter under exactly that name (there is even a test pinning
    /// it). So every Windows-on-ARM64 minidump — a shipping platform, and one
    /// this module parses in full — answered `None`, and
    /// `debug.minidump_analyze` published `"crash_rip": null`: the crash
    /// address, the single most important field of a crash dump, absent from a
    /// dump that contained it.
    #[must_use]
    pub fn crash_pc(&self) -> Option<u64> {
        let t = self.crashing_thread()?;
        ["rip", "eip", "pc"]
            .iter()
            .find_map(|name| t.registers.get(*name))
            .copied()
    }

    /// Architecture-specific alias of [`Self::crash_pc`], kept because callers
    /// outside this crate use this name.
    #[must_use]
    pub fn crash_rip(&self) -> Option<u64> {
        self.crash_pc()
    }

    /// Look up the module that contains `addr`, if any.
    #[must_use]
    pub fn module_at(&self, addr: u64) -> Option<&ModuleEntry> {
        // The end address is never materialised. `base + size` comes straight
        // from the dump — both fields are attacker-controlled — so a base near
        // the top of the address space overflows: a panic in a debug build, and
        // in release a wrapped bound that silently excludes every address the
        // module really covers. Comparing the OFFSET is exact everywhere.
        // Fifth site of the shape first corrected in iter 273.
        self.modules
            .iter()
            .find(|m| addr >= m.base_address && addr - m.base_address < u64::from(m.size))
    }
}

// ── parser ───────────────────────────────────────────────────────────────────

/// How many records of `record_bytes` a stream of `stream_bytes` can really hold.
///
/// Every list stream in a minidump states its length TWICE: once in the stream
/// directory, and once as a `count` inside the stream. The parser trusted the
/// count and discarded the directory size — so a dump declaring 10 000 modules
/// in a stream sized for two was read straight past the end of that stream, into
/// whatever followed (another stream, a context record, raw stack memory), and
/// those bytes came out as MODULES. Reading only stopped at the end of the FILE,
/// so on a large dump the result was a long list of fabricated entries reported
/// as fact.
///
/// Surviving malformed input and telling the truth about it are different
/// properties; this file already tested the first
/// (`parse_never_panics_on_truncated_or_mutated_input`) and not the second.
///
/// Clamping rather than refusing: the records that DO fit were really described
/// by the dump, and a damaged module list should not cost the caller the thread
/// list as well.
const fn records_that_fit(stream_bytes: u32, header_bytes: u32, record_bytes: u32) -> u32 {
    if stream_bytes <= header_bytes || record_bytes == 0 {
        return 0;
    }
    (stream_bytes - header_bytes) / record_bytes
}

/// Parse a Windows minidump file from raw bytes.
///
/// # Errors
/// Returns [`MinidumpError`] for any structural validity problem, truncation,
/// or unsupported encoding.
pub fn parse(data: &[u8]) -> Result<MinidumpView, MinidumpError> {
    let mut r = Reader::new(data);

    // MINIDUMP_HEADER
    let sig = r.u32()?;
    if sig != 0x504d_444d {
        // "MDMP"
        return Err(MinidumpError::BadSignature);
    }
    let version = r.u16()?;
    let _impl_version = r.u16()?;
    if version != 0xa793 {
        // not MINIDUMP_VERSION — be lenient
    }
    let stream_count = r.u32()?;
    let stream_dir_rva = r.u32()?;
    let _checksum = r.u32()?;
    let timestamp = r.u32()?;
    let flags = r.u64()?;

    // Read stream directory: array of MINIDUMP_DIRECTORY { StreamType u32, DataSize u32, Rva u32 }
    let mut streams: HashMap<u32, (u32, u32)> = HashMap::new();
    r.seek(u64::from(stream_dir_rva))?;
    for _ in 0..stream_count {
        let stype = r.u32()?;
        let size = r.u32()?;
        let rva = r.u32()?;
        streams.insert(stype, (size, rva));
    }

    // ── SystemInfo ───────────────────────────────────────────────────────────
    let system_info = if let Some(&(_size, rva)) = streams.get(&STREAM_SYSTEM_INFO) {
        r.seek(u64::from(rva))?;
        let cpu_arch_raw = r.u16()?;
        let cpu_arch = match cpu_arch_raw {
            0 => CpuArch::X86,
            9 => CpuArch::Amd64,
            5 => CpuArch::Arm,
            12 => CpuArch::Arm64,
            other => CpuArch::Unknown(other),
        };
        let cpu_level = r.u16()?;
        let cpu_revision = r.u16()?;
        let number_of_processors = r.u8()?;
        let _product_type = r.u8()?;
        let major_version = r.u32()?;
        let minor_version = r.u32()?;
        let build_number = r.u32()?;
        let platform_id = r.u32()?;
        Some(SystemInfo {
            cpu_arch,
            cpu_level,
            cpu_revision,
            number_of_processors,
            major_version,
            minor_version,
            build_number,
            platform_id,
        })
    } else {
        None
    };

    // ── Exception ────────────────────────────────────────────────────────────
    let exception = if let Some(&(_size, rva)) = streams.get(&STREAM_EXCEPTION) {
        r.seek(u64::from(rva))?;
        let thread_id = r.u32()?;
        let _align = r.u32()?;
        // MINIDUMP_EXCEPTION embedded struct
        let exception_code = r.u32()?;
        let exception_flags = r.u32()?;
        let _exception_record_ptr = r.u64()?;
        let exception_address = r.u64()?;
        let number_of_parameters = r.u32()?;
        let _align2 = r.u32()?;
        let mut exception_information = Vec::new();
        let nparams = (number_of_parameters as usize).min(15);
        for _ in 0..nparams {
            exception_information.push(r.u64()?);
        }
        Some(ExceptionRecord {
            thread_id,
            exception_code,
            exception_flags,
            exception_address,
            number_of_parameters,
            exception_information,
        })
    } else {
        None
    };

    // ── ThreadList / ThreadExList ─────────────────────────────────────────────
    let thread_stream = streams
        .get(&STREAM_THREAD_EX_LIST)
        .or_else(|| streams.get(&STREAM_THREAD_LIST))
        .copied();

    let mut threads: Vec<ThreadContext> = Vec::new();
    if let Some((stream_size, rva)) = thread_stream {
        r.seek(u64::from(rva))?;
        // 4 tid + 4 suspend + 4 priority class + 4 priority + 8 teb
        // + 16 stack descriptor + 8 context descriptor.
        const THREAD_RECORD: u32 = 48;
        let count = r.u32()?.min(records_that_fit(stream_size, 4, THREAD_RECORD));
        for _ in 0..count {
            let tid = r.u32()?;
            let suspend_count = r.u32()?;
            let priority_class = r.u32()?;
            let priority = r.u32()?;
            let teb = r.u64()?;
            // MINIDUMP_MEMORY_DESCRIPTOR (stack): start_of_memory_range u64 + RVA/size
            let _stack_start = r.u64()?;
            let _stack_size = r.u32()?;
            let _stack_rva = r.u32()?;
            // ThreadContext MINIDUMP_LOCATION_DESCRIPTOR
            let ctx_size = r.u32()?;
            let ctx_rva = r.u32()?;

            // Parse CONTEXT structure (architecture-dependent) — we only
            // decode AMD64 CONTEXT here (the overwhelmingly common case on
            // modern Windows crash dumps). For x86/ARM we record the raw
            // address so a caller can read the bytes directly.
            let mut registers: HashMap<String, u64> = HashMap::new();
            let saved = r.pos();
            if ctx_rva != 0 && ctx_size >= 8
                && matches!(r.seek(u64::from(ctx_rva)), Ok(())) {
                    // `ContextFlags` does NOT sit at offset 0 in every CONTEXT.
                    // AMD64's begins with the six `P?Home` slots and puts
                    // ContextFlags at 0x30; only ARM64_NT_CONTEXT has it at 0.
                    // Reading offset 0 for both tested P1Home — a stack pointer
                    // or zero — as if it were the flags word, so on the AMD64
                    // dumps this arm calls "the overwhelmingly common case" the
                    // test almost never passed and the thread came back with an
                    // EMPTY register map: no rip, no rsp. Worse, a P1Home that
                    // happens to have bit 0x400000 set steered an AMD64 context
                    // into the ARM64 arm below, decoding x64 registers at
                    // AArch64 offsets.
                    //
                    // The two candidate words are read at their own offsets and
                    // the architecture from SystemInfo (already parsed above)
                    // decides between them; only when the dump does not say is
                    // each flag word tried against its own layout.
                    const AMD64_CONTEXT_FLAGS_OFF: u64 = 0x30;
                    const CONTEXT_AMD64: u32 = 0x10_0000;
                    const CONTEXT_ARM64: u32 = 0x0040_0000;
                    const CONTEXT_I386: u32 = 0x0001_0000;
                    /// `sizeof(CONTEXT)` for i386: 0xCC of named fields plus
                    /// the 512-byte `ExtendedRegisters` tail.
                    const I386_CONTEXT_SIZE: u32 = 716;

                    let arm64_flags = r.u32()?;
                    let amd64_flags = if ctx_size >= 0x34 {
                        r.seek(u64::from(ctx_rva) + AMD64_CONTEXT_FLAGS_OFF)
                            .ok()
                            .and_then(|()| r.u32().ok())
                            .unwrap_or(0)
                    } else {
                        0
                    };
                    let arch = system_info.as_ref().map(|s| s.cpu_arch);
                    let looks_amd64 = match arch {
                        Some(CpuArch::Amd64) => true,
                        Some(CpuArch::Arm64) => false,
                        _ => amd64_flags & CONTEXT_AMD64 != 0,
                    };
                    let looks_arm64 = match arch {
                        Some(CpuArch::Arm64) => true,
                        Some(CpuArch::Amd64 | CpuArch::X86) => false,
                        _ => arm64_flags & CONTEXT_ARM64 != 0,
                    };
                    // i386 shares ARM64's property of putting ContextFlags at
                    // offset 0, so `arm64_flags` is the right word to test.
                    let looks_i386 = match arch {
                        Some(CpuArch::X86) => true,
                        Some(CpuArch::Amd64 | CpuArch::Arm64) => false,
                        _ => arm64_flags & CONTEXT_I386 == CONTEXT_I386,
                    };
                    let ctx_flags = if looks_amd64 { amd64_flags } else { arm64_flags };
                    if looks_amd64 && ctx_flags & CONTEXT_AMD64 != 0 && ctx_size >= 1232 {
                        // Offsets within AMD64 CONTEXT structure (documented in winnt.h)
                        let amd64_regs: &[(&str, u64)] = &[
                            ("p1home", 8), ("p2home", 16), ("p3home", 24), ("p4home", 32),
                            ("p5home", 40), ("p6home", 48),
                            // ContextFlags already read at +0
                            ("mxcsr", 52),
                            ("cs", 56), ("ds", 58), ("es", 60), ("fs", 62),
                            ("gs", 64), ("ss", 66), ("eflags", 68),
                            ("dr0", 72), ("dr1", 80), ("dr2", 88), ("dr3", 96),
                            ("dr6", 104), ("dr7", 112),
                            ("rax", 120), ("rcx", 128), ("rdx", 136), ("rbx", 144),
                            ("rsp", 152), ("rbp", 160), ("rsi", 168), ("rdi", 176),
                            ("r8", 184), ("r9", 192), ("r10", 200), ("r11", 208),
                            ("r12", 216), ("r13", 224), ("r14", 232), ("r15", 240),
                            ("rip", 248),
                        ];
                        for (name, byte_offset) in amd64_regs {
                            if matches!(r.seek(u64::from(ctx_rva) + byte_offset), Ok(()))
                                && let Ok(val) = r.u64() {
                                    registers.insert((*name).to_string(), val);
                                }
                        }
                    } else if looks_arm64 && arm64_flags & CONTEXT_ARM64 != 0 && ctx_size >= 0x390 {
                        // ARM64_NT_CONTEXT (winnt.h). A completely different
                        // layout from AMD64, which is why the x64 offsets could
                        // not simply be reused: X0..X30 form one array at
                        // 0x008 — so X29 is `fp` at 0x0F0 and X30 is `lr` at
                        // 0x0F8 — with Sp at 0x100 and Pc at 0x108.
                        //
                        // Without this arm on a Windows-on-ARM dump the thread
                        // came back with an EMPTY register map: no pc, no sp,
                        // nothing for post-mortem analysis to start from, and
                        // no indication that anything had been skipped.
                        if matches!(r.seek(u64::from(ctx_rva) + 4), Ok(()))
                            && let Ok(cpsr) = r.u32()
                        {
                            registers.insert("cpsr".to_string(), u64::from(cpsr));
                        }
                        for i in 0..29u64 {
                            if matches!(r.seek(u64::from(ctx_rva) + 8 + i * 8), Ok(()))
                                && let Ok(val) = r.u64()
                            {
                                registers.insert(format!("x{i}"), val);
                            }
                        }
                        // X29/X30 are the frame pointer and link register; name
                        // them as such, matching how the rest of the crate
                        // refers to them (`ios::arm64`, `register_context`).
                        let named: &[(&str, u64)] =
                            &[("fp", 0xF0), ("lr", 0xF8), ("sp", 0x100), ("pc", 0x108)];
                        for (name, off) in named {
                            if matches!(r.seek(u64::from(ctx_rva) + off), Ok(()))
                                && let Ok(val) = r.u64()
                            {
                                registers.insert((*name).to_string(), val);
                            }
                        }
                    } else if looks_i386
                        && arm64_flags & CONTEXT_I386 == CONTEXT_I386
                        && ctx_size >= I386_CONTEXT_SIZE
                    {
                        // The i386 `CONTEXT` had NO arm at all: a 32-bit dump —
                        // still ordinary on Windows, where WOW64 processes and
                        // x86 services are dumped every day — produced a thread
                        // with an empty register map. `crash_pc` has been
                        // looking up "eip" since it was written, so the rest of
                        // the crate already expected a register nothing ever
                        // produced.
                        //
                        // Every field is a DWORD, so these are 4-byte reads, not
                        // the 8-byte ones the other two arms use. Offsets per
                        // winnt.h: the debug registers, then the 112-byte
                        // FLOATING_SAVE_AREA at 0x1C, which is why the general
                        // registers only start at 0x9C.
                        let i386_regs: &[(&str, u64)] = &[
                            ("dr0", 0x04), ("dr1", 0x08), ("dr2", 0x0C), ("dr3", 0x10),
                            ("dr6", 0x14), ("dr7", 0x18),
                            ("gs", 0x8C), ("fs", 0x90), ("es", 0x94), ("ds", 0x98),
                            ("edi", 0x9C), ("esi", 0xA0), ("ebx", 0xA4), ("edx", 0xA8),
                            ("ecx", 0xAC), ("eax", 0xB0), ("ebp", 0xB4), ("eip", 0xB8),
                            ("cs", 0xBC), ("eflags", 0xC0), ("esp", 0xC4), ("ss", 0xC8),
                        ];
                        for (name, off) in i386_regs {
                            if matches!(r.seek(u64::from(ctx_rva) + off), Ok(()))
                                && let Ok(val) = r.u32()
                            {
                                registers.insert((*name).to_string(), u64::from(val));
                            }
                        }
                    }
                }
            let _ = r.seek(saved);

            threads.push(ThreadContext {
                tid,
                suspend_count,
                priority_class,
                priority,
                teb,
                registers,
            });
        }
    }

    // ── ModuleList ───────────────────────────────────────────────────────────
    let mut modules: Vec<ModuleEntry> = Vec::new();
    if let Some(&(stream_size, rva)) = streams.get(&STREAM_MODULE_LIST) {
        r.seek(u64::from(rva))?;
        // 8 base + 4 size + 4 checksum + 4 stamp + 4 name_rva + 68 version
        // + 16 Cv/Misc descriptors + 16 reserved.
        const MODULE_RECORD: u32 = 124;
        let count = r.u32()?.min(records_that_fit(stream_size, 4, MODULE_RECORD));
        for _ in 0..count {
            let base_address = r.u64()?;
            let size = r.u32()?;
            let checksum = r.u32()?;
            let time_date_stamp = r.u32()?;
            let module_name_rva = r.u32()?;
            // VersionInfo (68 bytes) — skip
            let _ = r.bytes(68)?;
            // CvRecord + MiscRecord location descriptors (8 bytes each)
            let cv_size = r.u32()?;
            let cv_rva = r.u32()?;
            let _misc_size = r.u32()?;
            let _misc_rva = r.u32()?;
            // Reserved (16 bytes)
            let _ = r.bytes(16)?;

            // "no name recorded" and "a name we could not read" are different
            // facts, and both used to come out as an empty string.
            //
            // `module_name_rva == 0` is the dump saying it has no name for this
            // module. A FAILED `minidump_string` is the dump claiming a name at
            // an RVA that runs off the end of the file, or a length that does
            // not describe a string — which means the dump is truncated or
            // damaged. That is the single most important thing to tell someone
            // analysing a crash, because every other conclusion drawn from that
            // dump is then suspect.
            //
            // Collapsing them also broke matching in silence: an empty name
            // matches no faulting module and no PDB, and appears in the report
            // as a module with no name and no reason given.
            let name = if module_name_rva == 0 {
                String::new()
            } else {
                let saved = r.pos();
                let read = r.minidump_string(module_name_rva);
                let _ = r.seek(saved);
                read.unwrap_or_else(|_| {
                    // Shaped so it can never be mistaken for a real module name
                    // nor for "unnamed", and carrying the RVA that failed.
                    format!("<unreadable module name at rva {module_name_rva:#x}>")
                })
            };

            modules.push(ModuleEntry {
                base_address,
                size,
                checksum,
                time_date_stamp,
                name,
                cv_record_offset: cv_rva,
                cv_record_size: cv_size,
            });
        }
    }

    // ── MemoryList ───────────────────────────────────────────────────────────
    let mut memory_regions: Vec<MemoryDescriptor> = Vec::new();
    if let Some(&(stream_size, rva)) = streams.get(&STREAM_MEMORY_LIST) {
        r.seek(u64::from(rva))?;
        // 8 start + 4 size + 4 rva.
        const MEMORY_RECORD: u32 = 16;
        let count = r.u32()?.min(records_that_fit(stream_size, 4, MEMORY_RECORD));
        for _ in 0..count {
            let start_address = r.u64()?;
            let mem_size = r.u32()?;
            let file_offset = r.u32()?;
            memory_regions.push(MemoryDescriptor {
                start_address,
                size: mem_size,
                file_offset,
            });
        }
    }

    // ── Memory64List ─────────────────────────────────────────────────────────
    let mut memory64_regions: Vec<MemoryDescriptor64> = Vec::new();
    if let Some(&(stream_size, rva)) = streams.get(&STREAM_MEMORY64_LIST) {
        r.seek(u64::from(rva))?;
        // Different header from the other lists: a 64-bit count AND a 64-bit
        // base RVA before the records, each record being 8 start + 8 size.
        const MEMORY64_RECORD: u32 = 16;
        let count = r.u64()?;
        let _base_rva = r.u64()?;
        let count = count.min(u64::from(records_that_fit(stream_size, 16, MEMORY64_RECORD)));
        for _ in 0..count {
            let start_address = r.u64()?;
            let mem_size = r.u64()?;
            memory64_regions.push(MemoryDescriptor64 {
                start_address,
                size: mem_size,
            });
        }
    }

    // ── MiscInfo ─────────────────────────────────────────────────────────────
    let mut process_id: Option<u32> = None;
    let mut uptime_secs: Option<u32> = None;
    if let Some(&(_size, rva)) = streams.get(&STREAM_MISC_INFO) {
        // MINIDUMP_MISC_INFO is a FIXED layout: every field sits at a constant
        // offset, and Flags1 says which of them the writer filled in — it does
        // NOT say which of them are present. Reading the fields sequentially
        // therefore mis-aligns every later read as soon as one flag is clear:
        // with only the third flag set, the field at offset 24 was read from
        // offset 8, i.e. ProcessId was reported as the uptime. Each field is
        // read at its own offset, so a clear flag skips a field instead of
        // shifting the ones after it.
        const MISC_PROCESS_ID_OFF: u64 = 8;
        const MISC_PROCESS_TIMES_OFF: u64 = 12;
        const MISC_PROCESSOR_INFO_OFF: u64 = 24;

        r.seek(u64::from(rva))?;
        let misc_size = r.u32()?;
        let flags = r.u32()?;
        let base = u64::from(rva);
        if flags & 1 != 0 && misc_size >= 12 {
            r.seek(base + MISC_PROCESS_ID_OFF)?;
            process_id = Some(r.u32()?);
        }
        if flags & 2 != 0 && misc_size >= 24 {
            r.seek(base + MISC_PROCESS_TIMES_OFF)?;
            let _process_create_time = r.u32()?;
            let _process_user_time = r.u32()?;
            let _process_kernel_time = r.u32()?;
        }
        if flags & 4 != 0 && misc_size >= 28 {
            r.seek(base + MISC_PROCESSOR_INFO_OFF)?;
            uptime_secs = Some(r.u32()?);
        }
    }

    Ok(MinidumpView {
        flags,
        timestamp,
        stream_count,
        system_info,
        exception,
        threads,
        modules,
        memory_regions,
        memory64_regions,
        process_id,
        uptime_secs,
    })
}

/// Read raw bytes from a memory region within a minidump.
///
/// `file_data` must be the entire raw file bytes passed to [`parse`].
/// The returned slice spans exactly `desc.size` bytes taken from `file_data`
/// starting at `desc.file_offset`.
///
/// # Errors
/// Returns `MinidumpError::Truncated` if the region extends past the end of
/// the file data.
pub fn read_memory<'a>(
    file_data: &'a [u8],
    desc: &MemoryDescriptor,
) -> Result<&'a [u8], MinidumpError> {
    let start = desc.file_offset as usize;
    // checked_add: both file_offset and size are attacker-controlled u32 fields;
    // their sum could wrap on 32-bit targets.
    let end = start
        .checked_add(desc.size as usize)
        .ok_or(MinidumpError::Truncated(u64::from(desc.file_offset)))?;
    if end > file_data.len() {
        return Err(MinidumpError::Truncated(u64::from(desc.file_offset)));
    }
    Ok(&file_data[start..end])
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal synthetic minidump: `MINIDUMP_HEADER` + 1 stream directory
    /// entry pointing to a `SystemInfo` stream, nothing else.
    /// The clamp itself, including the header each list really has.
    ///
    /// Three of the four list streams put a 4-byte count in front of their
    /// records; `Memory64List` puts a 64-bit count AND a 64-bit base RVA, so its
    /// header is 16 bytes. Using 4 there would allow one record too many —
    /// exactly the off-by-one-record the clamp exists to prevent.
    #[test]
    fn records_that_fit_respects_each_lists_own_header() {
        // 4-byte header (ThreadList, ModuleList, MemoryList).
        assert_eq!(records_that_fit(4 + 124, 4, 124), 1);
        assert_eq!(records_that_fit(4 + 124 * 3, 4, 124), 3);
        // A stream that cannot hold even its own header holds no records.
        assert_eq!(records_that_fit(4, 4, 124), 0);
        assert_eq!(records_that_fit(0, 4, 124), 0);
        // A partial trailing record does not count as one.
        assert_eq!(records_that_fit(4 + 124 + 60, 4, 124), 1);

        // 16-byte header (Memory64List: u64 count + u64 base rva).
        assert_eq!(records_that_fit(16 + 16 * 2, 16, 16), 2);
        // Where the two headers actually diverge. They differ by 12 bytes,
        // which is less than one record, so the wrong header only shows up when
        // the remainder crosses a record boundary — 20 bytes holds NO 16-byte
        // record after a 16-byte header, but appears to hold one after a 4-byte
        // header.
        assert_eq!(records_that_fit(20, 16, 16), 0, "16 header + 4 spare bytes is no record");
        assert_eq!(
            records_that_fit(20, 4, 16),
            1,
            "and this is the phantom record the wrong header would have admitted"
        );
        assert_eq!(records_that_fit(16, 16, 16), 0);

        // A zero record size must answer none rather than divide by zero.
        assert_eq!(records_that_fit(1024, 4, 0), 0);
    }

    /// The record-size constants must match what the parser actually consumes.
    ///
    /// `records_that_fit` bounds each list by the stream size, and that bound is
    /// only right while the per-record byte count next to it agrees with the
    /// fields the loop reads. Those two live a few lines apart and nothing ties
    /// them together: add a field to the module loop and the constant keeps
    /// saying 124, so the clamp lets through one record too many again — the
    /// exact defect the clamp was added to close, reintroduced by an unrelated
    /// edit.
    ///
    /// Measured rather than restated: the reader reports its own position, so
    /// the test asks the parser how far it moved instead of re-deriving the
    /// layout from the same documentation the constant came from.
    #[test]
    fn the_record_size_constants_match_what_the_parser_reads() {
        // One module record, read through the real parser, with the stream
        // sized generously so the clamp cannot be what stops it.
        const DIR: u32 = 32;
        const SYSINFO: u32 = DIR + 24;
        const MODULES: u32 = SYSINFO + 56;

        let mut buf = Vec::new();
        buf.extend_from_slice(b"MDMP");
        buf.extend_from_slice(&0xa793u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&DIR.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&STREAM_SYSTEM_INFO.to_le_bytes());
        buf.extend_from_slice(&56u32.to_le_bytes());
        buf.extend_from_slice(&SYSINFO.to_le_bytes());
        buf.extend_from_slice(&STREAM_MODULE_LIST.to_le_bytes());
        buf.extend_from_slice(&4096u32.to_le_bytes()); // deliberately roomy
        buf.extend_from_slice(&MODULES.to_le_bytes());
        buf.extend_from_slice(&9u16.to_le_bytes());
        buf.extend_from_slice(&[0u8; 54]);

        // TWO modules laid out at exactly 124 bytes apart. If the parser
        // consumed a different number of bytes per record, the second one would
        // be read from the wrong offset and its base address would not come
        // back as written.
        buf.extend_from_slice(&2u32.to_le_bytes());
        for base in [0xAAAA_0000u64, 0xBBBB_0000] {
            let before = buf.len();
            buf.extend_from_slice(&base.to_le_bytes());
            buf.extend_from_slice(&0x100u32.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&[0u8; 68]);
            buf.extend_from_slice(&[0u8; 16]);
            buf.extend_from_slice(&[0u8; 16]);
            assert_eq!(
                buf.len() - before,
                124,
                "this test writes what MODULE_RECORD claims; if the layout changed, change both"
            );
        }

        let a = parse(&buf).expect("structurally valid");
        assert_eq!(a.modules.len(), 2);
        assert_eq!(
            a.modules[1].base_address, 0xBBBB_0000,
            "the second record did not land where a 124-byte stride puts it, so the parser and MODULE_RECORD disagree"
        );
    }

    /// A clear flag must skip a field, not shift the ones after it.
    ///
    /// `MINIDUMP_MISC_INFO` has a FIXED layout — `ProcessId` at 8, the process
    /// times at 12/16/20, the processor block at 24 — and `Flags1` says which
    /// fields the writer FILLED IN, not which are present. Reading them
    /// sequentially made every field's position depend on the flags before it,
    /// so a dump that set only the third flag had the field at offset 24 read
    /// from offset 8. Nothing crashes and nothing looks wrong: a plain u32 is
    /// reported under the wrong name.
    #[test]
    fn a_misc_info_flag_that_is_clear_does_not_shift_the_fields_after_it() {
        const DIR: u32 = 32;
        const SYSINFO: u32 = DIR + 24;
        const MISC: u32 = SYSINFO + 56;

        let mut buf = Vec::new();
        buf.extend_from_slice(b"MDMP");
        buf.extend_from_slice(&0xa793u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&DIR.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&STREAM_SYSTEM_INFO.to_le_bytes());
        buf.extend_from_slice(&56u32.to_le_bytes());
        buf.extend_from_slice(&SYSINFO.to_le_bytes());
        buf.extend_from_slice(&STREAM_MISC_INFO.to_le_bytes());
        buf.extend_from_slice(&32u32.to_le_bytes());
        buf.extend_from_slice(&MISC.to_le_bytes());
        buf.extend_from_slice(&9u16.to_le_bytes());
        buf.extend_from_slice(&[0u8; 54]);

        // SizeOfInfo, then Flags1 = 4 ONLY: the third field is filled in, the
        // two before it are not.
        buf.extend_from_slice(&32u32.to_le_bytes()); // @0  SizeOfInfo
        buf.extend_from_slice(&4u32.to_le_bytes()); // @4  Flags1
        buf.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // @8  ProcessId (NOT filled in)
        buf.extend_from_slice(&0u32.to_le_bytes()); // @12
        buf.extend_from_slice(&0u32.to_le_bytes()); // @16
        buf.extend_from_slice(&0u32.to_le_bytes()); // @20
        buf.extend_from_slice(&0x0000_1234u32.to_le_bytes()); // @24 the flagged field
        buf.extend_from_slice(&0u32.to_le_bytes()); // @28

        let a = parse(&buf).expect("structurally valid");
        assert_eq!(
            a.process_id, None,
            "the ProcessId flag is clear, so no process id may be reported"
        );
        assert_ne!(
            a.uptime_secs,
            Some(0xDEAD_BEEF),
            "the field at offset 24 was read from offset 8"
        );
        assert_eq!(a.uptime_secs, Some(0x0000_1234));
    }

    /// A count larger than the stream can hold must not manufacture records.
    ///
    /// A list stream states its length twice: in the directory (bytes) and
    /// inside the stream (`count`). The parser believed the count and threw the
    /// directory size away, so a dump claiming many modules in a stream sized
    /// for one was read past that stream into whatever followed — other
    /// streams, context records, raw memory — and those bytes were reported as
    /// MODULES. It only stopped at the end of the FILE.
    ///
    /// This is the fidelity half of robustness: the parser already did not
    /// panic here, it just answered with things that were never in the dump.
    #[test]
    fn a_count_larger_than_its_stream_does_not_manufacture_modules() {
        const DIR: u32 = 32;
        const SYSINFO: u32 = DIR + 24;
        const MODULES: u32 = SYSINFO + 56;
        const MODULE_RECORD: usize = 124;

        let mut buf = Vec::new();
        buf.extend_from_slice(b"MDMP");
        buf.extend_from_slice(&0xa793u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&DIR.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&STREAM_SYSTEM_INFO.to_le_bytes());
        buf.extend_from_slice(&56u32.to_le_bytes());
        buf.extend_from_slice(&SYSINFO.to_le_bytes());
        buf.extend_from_slice(&STREAM_MODULE_LIST.to_le_bytes());
        // The directory says: room for the count plus exactly ONE module.
        buf.extend_from_slice(&((4 + MODULE_RECORD) as u32).to_le_bytes());
        buf.extend_from_slice(&MODULES.to_le_bytes());
        buf.extend_from_slice(&9u16.to_le_bytes());
        buf.extend_from_slice(&[0u8; 54]);
        assert_eq!(buf.len(), MODULES as usize);

        // The stream says: FOUR modules.
        buf.extend_from_slice(&4u32.to_le_bytes());
        for base in [0x1000u64, 0x2000, 0x3000, 0x4000] {
            buf.extend_from_slice(&base.to_le_bytes());
            buf.extend_from_slice(&0x100u32.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes()); // name rva 0
            buf.extend_from_slice(&[0u8; 68]);
            buf.extend_from_slice(&[0u8; 16]);
            buf.extend_from_slice(&[0u8; 16]);
        }

        let a = parse(&buf).expect("the dump is structurally parseable");
        assert_eq!(
            a.modules.len(),
            1,
            "the directory says this stream holds one module; the other three were read from bytes outside it"
        );
        assert_eq!(a.modules[0].base_address, 0x1000, "and it must be the one that really fits");
    }

    /// A dump that CLAIMS a module name we cannot read must not look like a
    /// dump that records no name at all.
    ///
    /// Both used to come out as an empty string. They are different facts: a
    /// zero RVA is the dump saying it has no name; a failed read means the RVA
    /// runs off the end of the file or the length does not describe a string —
    /// i.e. the dump is truncated or damaged, which makes every other
    /// conclusion drawn from it suspect. The empty name also silently matched
    /// no faulting module and no PDB.
    #[test]
    fn an_unreadable_module_name_is_not_the_same_as_no_name() {
        // header(32) | dir(2*12) | SystemInfo(56) | ModuleList
        const DIR: u32 = 32;
        const SYSINFO: u32 = DIR + 24;
        const MODULES: u32 = SYSINFO + 56;
        const MODULE_RECORD: usize = 8 + 4 + 4 + 4 + 4 + 68 + 4 + 4 + 4 + 4 + 16;

        let mut buf = Vec::new();
        buf.extend_from_slice(b"MDMP");
        buf.extend_from_slice(&0xa793u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&DIR.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        // directory: SystemInfo, ModuleList
        buf.extend_from_slice(&STREAM_SYSTEM_INFO.to_le_bytes());
        buf.extend_from_slice(&56u32.to_le_bytes());
        buf.extend_from_slice(&SYSINFO.to_le_bytes());
        buf.extend_from_slice(&STREAM_MODULE_LIST.to_le_bytes());
        buf.extend_from_slice(&((4 + 2 * MODULE_RECORD) as u32).to_le_bytes());
        buf.extend_from_slice(&MODULES.to_le_bytes());
        // SystemInfo (56 bytes, contents irrelevant here)
        buf.extend_from_slice(&9u16.to_le_bytes());
        buf.extend_from_slice(&[0u8; 54]);
        assert_eq!(buf.len(), MODULES as usize, "module list must start where the directory says");

        // ModuleList: two modules.
        buf.extend_from_slice(&2u32.to_le_bytes());
        // (1) no name recorded at all: rva 0.
        // (2) a name CLAIMED far past the end of the file.
        for name_rva in [0u32, 0x00FF_0000] {
            buf.extend_from_slice(&0x1000u64.to_le_bytes()); // base
            buf.extend_from_slice(&0x100u32.to_le_bytes()); // size
            buf.extend_from_slice(&0u32.to_le_bytes()); // checksum
            buf.extend_from_slice(&0u32.to_le_bytes()); // timestamp
            buf.extend_from_slice(&name_rva.to_le_bytes());
            buf.extend_from_slice(&[0u8; 68]); // VersionInfo
            buf.extend_from_slice(&[0u8; 16]); // Cv + Misc descriptors
            buf.extend_from_slice(&[0u8; 16]); // Reserved
        }

        let a = parse(&buf).expect("a structurally valid dump still parses");
        assert_eq!(a.modules.len(), 2, "both modules are reported");

        assert_eq!(a.modules[0].name, "", "rva 0 means the dump records no name");
        assert!(
            a.modules[1].name.contains("unreadable"),
            "a name the dump CLAIMS but we cannot read must say so, not read as unnamed: {:?}",
            a.modules[1].name
        );
        assert!(
            a.modules[1].name.contains("ff0000") || a.modules[1].name.contains("0xff0000"),
            "and it must carry the RVA that failed, so the damage can be located: {:?}",
            a.modules[1].name
        );
    }

    fn minimal_minidump() -> Vec<u8> {
        let mut buf = Vec::new();
        // MINIDUMP_HEADER (32 bytes)
        buf.extend_from_slice(b"MDMP"); // Signature
        buf.extend_from_slice(&0xa793u16.to_le_bytes()); // Version
        buf.extend_from_slice(&0x0000u16.to_le_bytes()); // ImplementationVersion
        buf.extend_from_slice(&1u32.to_le_bytes()); // NumberOfStreams
        buf.extend_from_slice(&32u32.to_le_bytes()); // StreamDirectoryRva (right after header)
        buf.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
        buf.extend_from_slice(&0x1234_5678u32.to_le_bytes()); // TimeDateStamp
        buf.extend_from_slice(&0u64.to_le_bytes()); // Flags
        // MINIDUMP_DIRECTORY entry for SystemInfo (12 bytes) at offset 32
        let sys_info_offset = 44u32;
        buf.extend_from_slice(&STREAM_SYSTEM_INFO.to_le_bytes()); // StreamType
        buf.extend_from_slice(&56u32.to_le_bytes()); // DataSize (min SystemInfo)
        buf.extend_from_slice(&sys_info_offset.to_le_bytes()); // Rva
        // SystemInfo at offset 44 (56 bytes)
        buf.extend_from_slice(&9u16.to_le_bytes()); // ProcessorArchitecture = AMD64
        buf.extend_from_slice(&6u16.to_le_bytes()); // ProcessorLevel
        buf.extend_from_slice(&0u16.to_le_bytes()); // ProcessorRevision
        buf.extend_from_slice(&[8u8]); // NumberOfProcessors
        buf.extend_from_slice(&[1u8]); // ProductType
        buf.extend_from_slice(&10u32.to_le_bytes()); // MajorVersion
        buf.extend_from_slice(&0u32.to_le_bytes()); // MinorVersion
        buf.extend_from_slice(&19045u32.to_le_bytes()); // BuildNumber
        buf.extend_from_slice(&2u32.to_le_bytes()); // PlatformId = VER_PLATFORM_WIN32_NT
        buf.extend_from_slice(&0u32.to_le_bytes()); // CSDVersionRva
        buf.extend_from_slice(&0u32.to_le_bytes()); // SuiteMask+Reserved
        // CPU vendor string (12 bytes) + feature info (12 bytes) = 24 bytes filler
        buf.extend_from_slice(&[0u8; 24]);
        buf
    }

    /// Build a minidump for an arm64 target with one thread and a real
    /// `ARM64_NT_CONTEXT`, so the register decoding can be exercised.
    fn arm64_minidump() -> Vec<u8> {
        // Layout: header(32) | dir(2*12) | SystemInfo(56) | ThreadList | CONTEXT
        const DIR: u32 = 32;
        const SYSINFO: u32 = DIR + 24;
        const THREADS: u32 = SYSINFO + 56;
        const CTX: u32 = THREADS + 4 + 48;
        const CTX_SIZE: u32 = 0x390; // sizeof(ARM64_NT_CONTEXT)

        let mut buf = Vec::new();
        buf.extend_from_slice(b"MDMP");
        buf.extend_from_slice(&0xa793u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes()); // two streams
        buf.extend_from_slice(&DIR.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        // directory
        buf.extend_from_slice(&STREAM_SYSTEM_INFO.to_le_bytes());
        buf.extend_from_slice(&56u32.to_le_bytes());
        buf.extend_from_slice(&SYSINFO.to_le_bytes());
        buf.extend_from_slice(&STREAM_THREAD_LIST.to_le_bytes());
        buf.extend_from_slice(&52u32.to_le_bytes());
        buf.extend_from_slice(&THREADS.to_le_bytes());
        // SystemInfo: ProcessorArchitecture = 12 (ARM64)
        buf.extend_from_slice(&12u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.push(8);
        buf.push(1);
        buf.extend_from_slice(&10u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&22621u32.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 24]);
        // ThreadList: count + one MINIDUMP_THREAD (48 bytes)
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&0x1111u32.to_le_bytes()); // tid
        buf.extend_from_slice(&0u32.to_le_bytes());      // suspend
        buf.extend_from_slice(&0u32.to_le_bytes());      // priority class
        buf.extend_from_slice(&0u32.to_le_bytes());      // priority
        buf.extend_from_slice(&0u64.to_le_bytes());      // teb
        buf.extend_from_slice(&0u64.to_le_bytes());      // stack start
        buf.extend_from_slice(&0u32.to_le_bytes());      // stack size
        buf.extend_from_slice(&0u32.to_le_bytes());      // stack rva
        buf.extend_from_slice(&CTX_SIZE.to_le_bytes());  // context size
        buf.extend_from_slice(&CTX.to_le_bytes());       // context rva
        // ARM64_NT_CONTEXT
        assert_eq!(buf.len() as u32, CTX, "context must start where the descriptor says");
        let mut ctx = vec![0u8; CTX_SIZE as usize];
        ctx[0..4].copy_from_slice(&0x0040_0001u32.to_le_bytes()); // CONTEXT_ARM64 | CONTROL
        ctx[4..8].copy_from_slice(&0x6000_0000u32.to_le_bytes()); // Cpsr
        ctx[8..16].copy_from_slice(&0xAAAAu64.to_le_bytes());     // X0  @ 0x008
        ctx[0xF0..0xF8].copy_from_slice(&0x7000u64.to_le_bytes()); // Fp (X29) @ 0x0F0
        ctx[0xF8..0x100].copy_from_slice(&0x4444u64.to_le_bytes());// Lr (X30) @ 0x0F8
        ctx[0x100..0x108].copy_from_slice(&0x7FF0u64.to_le_bytes());// Sp @ 0x100
        ctx[0x108..0x110].copy_from_slice(&0x1000u64.to_le_bytes());// Pc @ 0x108
        buf.extend_from_slice(&ctx);
        buf
    }

    /// Build a minidump for an amd64 target with one thread and a real x64
    /// `CONTEXT` — laid out the way Windows writes it, with the six `P?Home`
    /// slots FIRST and `ContextFlags` at 0x30.
    fn amd64_minidump(p1home: u64) -> Vec<u8> {
        const DIR: u32 = 32;
        const SYSINFO: u32 = DIR + 24;
        const THREADS: u32 = SYSINFO + 56;
        const CTX: u32 = THREADS + 4 + 48;
        const CTX_SIZE: u32 = 1232; // sizeof(CONTEXT) on x64

        let mut buf = Vec::new();
        buf.extend_from_slice(b"MDMP");
        buf.extend_from_slice(&0xa793u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&DIR.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&STREAM_SYSTEM_INFO.to_le_bytes());
        buf.extend_from_slice(&56u32.to_le_bytes());
        buf.extend_from_slice(&SYSINFO.to_le_bytes());
        buf.extend_from_slice(&STREAM_THREAD_LIST.to_le_bytes());
        buf.extend_from_slice(&52u32.to_le_bytes());
        buf.extend_from_slice(&THREADS.to_le_bytes());
        // SystemInfo: ProcessorArchitecture = 9 (AMD64)
        buf.extend_from_slice(&9u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.push(8);
        buf.push(1);
        buf.extend_from_slice(&10u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&22621u32.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 24]);
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&0x2222u32.to_le_bytes()); // tid
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&CTX_SIZE.to_le_bytes());
        buf.extend_from_slice(&CTX.to_le_bytes());
        assert_eq!(buf.len() as u32, CTX, "context must start where the descriptor says");

        let mut ctx = vec![0u8; CTX_SIZE as usize];
        ctx[0..8].copy_from_slice(&p1home.to_le_bytes()); // P1Home @ 0x00
        ctx[0x30..0x34].copy_from_slice(&0x0010_000Bu32.to_le_bytes()); // ContextFlags @ 0x30
        ctx[120..128].copy_from_slice(&0xAAAAu64.to_le_bytes()); // Rax @ 0x78
        ctx[152..160].copy_from_slice(&0x7FF0u64.to_le_bytes()); // Rsp @ 0x98
        ctx[248..256].copy_from_slice(&0x1000u64.to_le_bytes()); // Rip @ 0xF8
        buf.extend_from_slice(&ctx);
        buf
    }

    /// Build a minidump for an i386 target with one thread and a real 32-bit
    /// `CONTEXT`, laid out per winnt.h: debug registers, then the 112-byte
    /// `FLOATING_SAVE_AREA` at 0x1C, then the general registers from 0x9C.
    fn i386_minidump() -> Vec<u8> {
        const DIR: u32 = 32;
        const SYSINFO: u32 = DIR + 24;
        const THREADS: u32 = SYSINFO + 56;
        const CTX: u32 = THREADS + 4 + 48;
        const CTX_SIZE: u32 = 716; // sizeof(CONTEXT) on i386

        let mut buf = Vec::new();
        buf.extend_from_slice(b"MDMP");
        buf.extend_from_slice(&0xa793u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&DIR.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&STREAM_SYSTEM_INFO.to_le_bytes());
        buf.extend_from_slice(&56u32.to_le_bytes());
        buf.extend_from_slice(&SYSINFO.to_le_bytes());
        buf.extend_from_slice(&STREAM_THREAD_LIST.to_le_bytes());
        buf.extend_from_slice(&52u32.to_le_bytes());
        buf.extend_from_slice(&THREADS.to_le_bytes());
        // SystemInfo: ProcessorArchitecture = 0 (INTEL / x86)
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.push(4);
        buf.push(1);
        buf.extend_from_slice(&10u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&19045u32.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 24]);
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&0x3333u32.to_le_bytes()); // tid
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&CTX_SIZE.to_le_bytes());
        buf.extend_from_slice(&CTX.to_le_bytes());
        assert_eq!(buf.len() as u32, CTX, "context must start where the descriptor says");

        let mut ctx = vec![0u8; CTX_SIZE as usize];
        // CONTEXT_i386 | CONTEXT_FULL
        ctx[0x00..0x04].copy_from_slice(&0x0001_0007u32.to_le_bytes());
        ctx[0xA4..0xA8].copy_from_slice(&0x1234_5678u32.to_le_bytes()); // Ebx
        ctx[0xB0..0xB4].copy_from_slice(&0x0000_AAAAu32.to_le_bytes()); // Eax
        ctx[0xB8..0xBC].copy_from_slice(&0x0040_1000u32.to_le_bytes()); // Eip
        ctx[0xC4..0xC8].copy_from_slice(&0x0019_FF00u32.to_le_bytes()); // Esp
        buf.extend_from_slice(&ctx);
        buf
    }

    /// A 32-bit dump must yield registers too — and `crash_pc` must find them.
    ///
    /// There was no i386 arm at all: only AMD64 and ARM64 were decoded, so a
    /// WOW64 or x86 dump — still an everyday thing on Windows — produced a
    /// thread with an EMPTY register map. The gap was visible from inside the
    /// module: `crash_pc` has looked up `"eip"` since it was written, so the
    /// crate already expected a register that nothing ever produced.
    ///
    /// The i386 fields are DWORDs, not QWORDs, and the general registers only
    /// begin at 0x9C because a 112-byte `FLOATING_SAVE_AREA` sits at 0x1C — the
    /// two things a reused x64 arm would have got wrong.
    #[test]
    fn an_i386_thread_context_is_decoded_and_crash_pc_finds_eip() {
        let dump = parse(&i386_minidump()).expect("structurally valid");
        assert_eq!(dump.system_info.as_ref().map(|s| s.cpu_arch), Some(CpuArch::X86));
        let regs = &dump.threads[0].registers;
        assert_eq!(regs.get("eip"), Some(&0x0040_1000), "a 32-bit dump must yield eip");
        assert_eq!(regs.get("esp"), Some(&0x0019_FF00));
        assert_eq!(regs.get("eax"), Some(&0xAAAA));
        assert_eq!(
            regs.get("ebx"),
            Some(&0x1234_5678),
            "ebx sits after the 112-byte FLOATING_SAVE_AREA, not where an x64 layout puts it"
        );
        // A DWORD read must not drag the neighbouring field in with it.
        assert_eq!(regs.get("cs"), Some(&0), "a 4-byte field read as 8 would swallow eflags");
    }

    /// The x64 `CONTEXT` does not begin with its flags word.
    ///
    /// AMD64's `CONTEXT` starts with six `P?Home` slots and puts
    /// `ContextFlags` at 0x30; only `ARM64_NT_CONTEXT` has it at 0. Reading
    /// offset 0 for both tested `P1Home` as if it were the flags word, so the
    /// arm the code itself calls "the overwhelmingly common case" almost never
    /// ran and the thread came back with NO registers at all.
    ///
    /// The second case is the nastier one: a `P1Home` carrying bit 0x400000 —
    /// an ordinary value for a stack address — steered an x64 context into the
    /// ARM64 arm, which would report `x0`/`sp`/`pc` read at `AArch64` offsets
    /// from x64 bytes. Registers under the wrong names, from the wrong places.
    #[test]
    fn an_amd64_thread_context_is_decoded_and_not_mistaken_for_arm64() {
        let dump = parse(&amd64_minidump(0)).expect("structurally valid");
        assert_eq!(dump.system_info.as_ref().map(|s| s.cpu_arch), Some(CpuArch::Amd64));
        let regs = &dump.threads[0].registers;
        assert_eq!(regs.get("rip"), Some(&0x1000), "an amd64 dump must yield rip");
        assert_eq!(regs.get("rsp"), Some(&0x7FF0));
        assert_eq!(regs.get("rax"), Some(&0xAAAA));

        // A P1Home whose bit 0x400000 is set must not be read as CONTEXT_ARM64.
        let dump = parse(&amd64_minidump(0x7FF6_0040_0000)).expect("structurally valid");
        let regs = &dump.threads[0].registers;
        assert_eq!(regs.get("rip"), Some(&0x1000), "P1Home steered the context into the arm64 arm");
        assert!(
            !regs.contains_key("pc") && !regs.contains_key("x0"),
            "an x64 context must not be decoded at AArch64 offsets"
        );
    }

    /// An arm64 crash dump must yield registers, not an empty map.
    ///
    /// The parser recognised `CpuArch::Arm64` in `SystemInfo` but decoded only the
    /// AMD64 `CONTEXT`, so every arm64 dump produced a thread with NO registers:
    /// no pc, no sp, no lr. Post-mortem analysis of a Windows-on-ARM crash had
    /// nothing to work from — and nothing said so, the thread was simply empty.
    ///
    /// `ARM64_NT_CONTEXT` puts X0..X30 at 0x008 (so Fp=X29 at 0x0F0 and
    /// Lr=X30 at 0x0F8), Sp at 0x100 and Pc at 0x108 — a completely different
    /// layout from AMD64, which is why reusing the x64 offsets was never an
    /// option.
    #[test]
    fn an_arm64_thread_context_is_decoded_not_left_empty() {
        let dump = parse(&arm64_minidump()).expect("well-formed arm64 dump");
        assert_eq!(dump.system_info.as_ref().map(|s| s.cpu_arch), Some(CpuArch::Arm64));

        let t = dump.threads.first().expect("one thread");
        assert_eq!(t.registers.get("pc").copied(), Some(0x1000), "Pc lives at 0x108");
        assert_eq!(t.registers.get("sp").copied(), Some(0x7FF0), "Sp lives at 0x100");
        assert_eq!(t.registers.get("lr").copied(), Some(0x4444), "Lr is X30, at 0x0F8");
        assert_eq!(t.registers.get("fp").copied(), Some(0x7000), "Fp is X29, at 0x0F0");
        assert_eq!(t.registers.get("x0").copied(), Some(0xAAAA), "X0 is the first of the array");
    }

    #[test]
    fn parse_minimal_minidump() {
        let data = minimal_minidump();
        let view = parse(&data).expect("parse failed");
        assert_eq!(view.timestamp, 0x1234_5678);
        let si = view.system_info.as_ref().expect("no system_info");
        assert_eq!(si.cpu_arch, CpuArch::Amd64);
        assert_eq!(si.number_of_processors, 8);
        assert_eq!(si.build_number, 19045);
        assert!(view.threads.is_empty());
        assert!(view.modules.is_empty());
        assert!(view.exception.is_none());
        assert!(view.crashing_thread().is_none());
    }

    /// Truncation + single-byte-mutation sweep over a valid minidump.
    /// `parse` consumes a wholly untrusted crash-dump file, so EVERY
    /// malformed input must come back as `Err`, never as a panic — a panic
    /// here takes down the debug server instead of rejecting the file.
    /// No prior audit of this crate has fed malformed bytes systematically
    /// to the pure parsers; this is that sweep.
    #[test]
    fn parse_never_panics_on_truncated_or_mutated_input() {
        let good = minimal_minidump();

        // Every possible truncation, including the empty slice.
        for len in 0..=good.len() {
            let _ = parse(&good[..len]);
        }

        // Every single byte set to each of a few adversarial values —
        // 0xFF in particular turns every length/count/RVA field into a
        // huge value, which is the classic overflow/OOB trigger.
        for i in 0..good.len() {
            for probe in [0x00u8, 0x01, 0x7F, 0x80, 0xFF] {
                let mut m = good.clone();
                m[i] = probe;
                let _ = parse(&m);
            }
        }

        // Whole 4-byte fields blown out to u32::MAX, which single-byte
        // mutation alone reaches only at the top byte.
        for i in 0..good.len().saturating_sub(4) {
            let mut m = good.clone();
            m[i..i + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            let _ = parse(&m);
        }
    }

    #[test]
    fn parse_bad_signature() {
        let bad: Vec<u8> = b"BADD\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec();
        assert!(matches!(parse(&bad), Err(MinidumpError::BadSignature)));
    }

    #[test]
    fn module_at_lookup() {
        let mut view = MinidumpView {
            flags: 0,
            timestamp: 0,
            stream_count: 0,
            system_info: None,
            exception: None,
            threads: vec![],
            modules: vec![ModuleEntry {
                base_address: 0x1000_0000,
                size: 0x10000,
                checksum: 0,
                time_date_stamp: 0,
                name: "test.dll".into(),
                cv_record_offset: 0,
                cv_record_size: 0,
            }],
            memory_regions: vec![],
            memory64_regions: vec![],
            process_id: None,
            uptime_secs: None,
        };
        assert!(view.module_at(0x1000_0000).is_some());
        assert!(view.module_at(0x1000_FFFF).is_some());
        assert!(view.module_at(0x1001_0000).is_none());
        // exercise crashing_thread with no exception
        assert!(view.crashing_thread().is_none());
        view.exception = Some(ExceptionRecord {
            thread_id: 42,
            exception_code: 0xC000_0005,
            exception_flags: 0,
            exception_address: 0x1000_1234,
            number_of_parameters: 0,
            exception_information: vec![],
        });
        assert!(view.crashing_thread().is_none()); // thread 42 not in threads
    }

    fn view_with(tid: u32, regs: &[(&str, u64)], modules: Vec<ModuleEntry>) -> MinidumpView {
        let mut registers = HashMap::new();
        for (k, v) in regs {
            registers.insert((*k).to_string(), *v);
        }
        MinidumpView {
            flags: 0,
            timestamp: 0,
            stream_count: 0,
            system_info: None,
            exception: Some(ExceptionRecord {
                thread_id: tid,
                exception_code: 0xC000_0005,
                exception_flags: 0,
                exception_address: 0x1000,
                number_of_parameters: 0,
                exception_information: vec![],
            }),
            threads: vec![ThreadContext {
                tid,
                suspend_count: 0,
                priority_class: 0,
                priority: 0,
                teb: 0,
                registers,
            }],
            modules,
            memory_regions: vec![],
            memory64_regions: vec![],
            process_id: None,
            uptime_secs: None,
        }
    }

    /// The crash address must be reported whatever the architecture calls it.
    ///
    /// The lookup was rip-then-eip. The parser above stores the `AArch64`
    /// program counter under "pc" - there is a test pinning that - so every
    /// Windows-on-ARM64 dump answered None and `debug.minidump_analyze`
    /// published a null crash address for a dump that contained it.
    #[test]
    fn the_crash_address_is_found_on_arm64_as_well_as_x86() {
        let arm = view_with(7, &[("pc", 0x1_4000_1234), ("sp", 0x7000)], vec![]);
        assert_eq!(arm.crash_pc(), Some(0x1_4000_1234));
        assert_eq!(arm.crash_rip(), arm.crash_pc(), "the legacy name must not answer differently");

        let x64 = view_with(7, &[("rip", 0x7FF6_0000_1000)], vec![]);
        assert_eq!(x64.crash_pc(), Some(0x7FF6_0000_1000));
        let x86 = view_with(7, &[("eip", 0x0040_1000)], vec![]);
        assert_eq!(x86.crash_pc(), Some(0x0040_1000));

        // A thread with no program counter at all still answers honestly.
        let bare = view_with(7, &[("sp", 0x7000)], vec![]);
        assert_eq!(bare.crash_pc(), None);
    }

    /// A module whose base sits near the top of the address space must still
    /// match the addresses it covers.
    ///
    /// `base + size` is computed from two attacker-controlled dump fields: it
    /// panics in a debug build and, in release, wraps to a small bound that
    /// silently excludes every address the module really covers.
    #[test]
    fn module_lookup_does_not_overflow_near_the_top_of_memory() {
        let m = ModuleEntry {
            base_address: u64::MAX - 0x0F,
            size: 0x100,
            checksum: 0,
            time_date_stamp: 0,
            name: "edge.dll".to_string(),
            cv_record_offset: 0,
            cv_record_size: 0,
        };
        let v = view_with(1, &[("rip", 0)], vec![m]);
        assert_eq!(
            v.module_at(u64::MAX - 0x0F).map(|m| m.name.as_str()),
            Some("edge.dll"),
            "the base address itself is inside the module"
        );
        assert_eq!(v.module_at(u64::MAX).map(|m| m.name.as_str()), Some("edge.dll"));
        assert!(v.module_at(u64::MAX - 0x10).is_none(), "one byte below the base is outside");
    }

}
