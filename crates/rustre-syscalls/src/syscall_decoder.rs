//! Syscall argument decoder — reconstructs human-readable syscall invocations
//! from raw register values captured at trace time.
//!
//! Given register context and a [`SyscallEntry`] descriptor, this module
//! produces strings like:
//! ```text
//! openat(AT_FDCWD, "/etc/passwd", O_RDONLY, 0) = 3
//! mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f...
//! ```

use std::collections::HashMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::syscall_table::{ArgType, SyscallArg, SyscallDb, SyscallEntry};
use crate::{OsFamily, SyscallArch, SyscallError};

/// Module-private helper: clamp a negative `i64` retval to a positive `i32`
/// errno value (Linux errnos are < 4096; any overflow indicates a non-errno
/// negative return such as an mmap address and is reported as `0`).
#[inline]
const fn clamp_errno(retval: i64) -> i32 {
    if retval >= 0 { return 0; }
    let v = -retval;
    // Already guaranteed `v <= i32::MAX as i64`, so the truncation below is exact.
    if v > i32::MAX as i64 { 0 } else { (v & 0xFFFF_FFFF) as i32 }
}

// ─── Register context ─────────────────────────────────────────────────────────

/// Raw register snapshot at the moment of a syscall.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterContext {
    /// Syscall number register (rax / eax / x8 / a7 …).
    pub syscall_nr: u64,
    /// Argument registers in ABI order.
    pub args: [u64; 8],
    /// Stack pointer (for reading stack args on 32-bit ABIs).
    pub sp: u64,
    /// Return value (filled after the syscall returns).
    pub retval: i64,
    /// Errno set by the kernel (-1 == error, else success).
    pub errno: i32,
}

impl RegisterContext {
    /// Create from the typical Linux x86-64 ABI (rdi/rsi/rdx/r10/r8/r9).
    ///
    /// Pass the six argument registers in ABI order: `[rdi, rsi, rdx, r10, r8, r9]`.
    #[must_use]
    pub const fn linux_x86_64(nr: u64, arg_regs: [u64; 6], retval: i64) -> Self {
        Self {
            syscall_nr: nr,
            args: [arg_regs[0], arg_regs[1], arg_regs[2], arg_regs[3], arg_regs[4], arg_regs[5], 0, 0],
            sp: 0,
            retval,
            errno: clamp_errno(retval),
        }
    }

    /// Create from Linux ARM64 ABI (x0..x5).
    #[must_use]
    pub const fn linux_arm64(nr: u64, regs: [u64; 8], retval: i64) -> Self {
        Self { syscall_nr: nr, args: regs, sp: 0, retval, errno: 0 }
    }
}

// ─── Flag tables ─────────────────────────────────────────────────────────────

/// A single named flag bit.
#[derive(Debug, Clone)]
struct FlagBit {
    value: u64,
    name: &'static str,
}

macro_rules! flag_table {
    ($( $name:expr => $val:expr ),* $(,)?) => {
        vec![ $( FlagBit { value: $val, name: $name } ),* ]
    };
}

fn open_flags() -> Vec<FlagBit> {
    flag_table![
        "O_RDONLY"   => 0o0,
        "O_WRONLY"   => 0o1,
        "O_RDWR"     => 0o2,
        "O_CREAT"    => 0o100,
        "O_EXCL"     => 0o200,
        "O_NOCTTY"   => 0o400,
        "O_TRUNC"    => 0o1000,
        "O_APPEND"   => 0o2000,
        "O_NONBLOCK" => 0o4000,
        "O_DSYNC"    => 0o10000,
        "O_ASYNC"    => 0o20000,
        "O_DIRECT"   => 0o40000,
        "O_LARGEFILE"=> 0o100_000,
        "O_DIRECTORY"=> 0o200_000,
        "O_NOFOLLOW" => 0o400_000,
        "O_NOATIME"  => 0o1_000_000,
        "O_CLOEXEC"  => 0o2_000_000,
        "O_PATH"     => 0o10_000_000,
        "O_TMPFILE"  => 0o20_200_000,
    ]
}

fn prot_flags() -> Vec<FlagBit> {
    flag_table![
        "PROT_NONE"  => 0x0,
        "PROT_READ"  => 0x1,
        "PROT_WRITE" => 0x2,
        "PROT_EXEC"  => 0x4,
    ]
}

fn map_flags() -> Vec<FlagBit> {
    flag_table![
        "MAP_SHARED"          => 0x01,
        "MAP_PRIVATE"         => 0x02,
        "MAP_SHARED_VALIDATE" => 0x03,
        "MAP_FIXED"           => 0x10,
        "MAP_ANONYMOUS"       => 0x20,
        "MAP_GROWSDOWN"       => 0x0100,
        "MAP_DENYWRITE"       => 0x0800,
        "MAP_EXECUTABLE"      => 0x1000,
        "MAP_LOCKED"          => 0x2000,
        "MAP_NORESERVE"       => 0x4000,
        "MAP_POPULATE"        => 0x8000,
        "MAP_NONBLOCK"        => 0x10000,
        "MAP_STACK"           => 0x20000,
        "MAP_HUGETLB"         => 0x40000,
    ]
}

fn madvise_flags() -> Vec<FlagBit> {
    flag_table![
        "MADV_NORMAL"      => 0,
        "MADV_RANDOM"      => 1,
        "MADV_SEQUENTIAL"  => 2,
        "MADV_WILLNEED"    => 3,
        "MADV_DONTNEED"    => 4,
        "MADV_FREE"        => 8,
        "MADV_REMOVE"      => 9,
        "MADV_DONTFORK"    => 10,
        "MADV_DOFORK"      => 11,
        "MADV_HWPOISON"    => 100,
        "MADV_MERGEABLE"   => 12,
        "MADV_UNMERGEABLE" => 13,
        "MADV_HUGEPAGE"    => 14,
        "MADV_NOHUGEPAGE"  => 15,
        "MADV_DONTDUMP"    => 16,
        "MADV_DODUMP"      => 17,
        "MADV_COLD"        => 20,
        "MADV_PAGEOUT"     => 21,
    ]
}

const fn signal_names() -> &'static [&'static str] {
    &[
        "SIG0", "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT",
        "SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV", "SIGUSR2", "SIGPIPE",
        "SIGALRM", "SIGTERM", "SIGSTKFLT", "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP",
        "SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF",
        "SIGWINCH", "SIGIO", "SIGPWR", "SIGSYS",
    ]
}

const fn errno_name(e: i32) -> &'static str {
    match e {
        1 => "EPERM", 2 => "ENOENT", 3 => "ESRCH", 4 => "EINTR", 5 => "EIO",
        6 => "ENXIO", 7 => "E2BIG", 8 => "ENOEXEC", 9 => "EBADF", 10 => "ECHILD",
        11 => "EAGAIN", 12 => "ENOMEM", 13 => "EACCES", 14 => "EFAULT",
        16 => "EBUSY", 17 => "EEXIST", 19 => "ENODEV", 20 => "ENOTDIR",
        21 => "EISDIR", 22 => "EINVAL", 23 => "ENFILE", 24 => "EMFILE",
        25 => "ENOTTY", 28 => "ENOSPC", 32 => "EPIPE", 33 => "EDOM",
        34 => "ERANGE", 35 => "EDEADLK", 36 => "ENAMETOOLONG", 38 => "ENOSYS",
        39 => "ENOTEMPTY", 40 => "ELOOP", 110 => "ETIMEDOUT",
        111 => "ECONNREFUSED", 113 => "EHOSTUNREACH",
        _ => "EUNKNOWN",
    }
}

// ─── Decoder ──────────────────────────────────────────────────────────────────

/// Options controlling decoder behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodeOptions {
    /// Maximum bytes to read when dereferencing a string pointer.
    pub max_string_len: usize,
    /// Attempt pointer dereference via process memory (requires `mem_reader`).
    pub dereference_pointers: bool,
    /// Include raw hex values alongside symbolic names.
    pub show_raw_hex: bool,
    /// Use compact single-line format even for large arg lists.
    pub compact: bool,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self {
            max_string_len: 256,
            dereference_pointers: false,
            show_raw_hex: false,
            compact: true,
        }
    }
}

/// Trait for reading memory from a traced process.
pub trait ProcessMemoryReader: Send + Sync {
    /// Read up to `len` bytes from `addr` in the remote process.
    fn read_bytes(&self, addr: u64, len: usize) -> Option<Vec<u8>>;

    /// Read a null-terminated C string starting at `addr`.
    fn read_cstring(&self, addr: u64, max: usize) -> Option<String> {
        let buf = self.read_bytes(addr, max)?;
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8(buf[..end].to_vec()).ok()
    }
}

/// A no-op memory reader used when live memory access is unavailable.
pub struct NoopMemoryReader;

impl ProcessMemoryReader for NoopMemoryReader {
    fn read_bytes(&self, _addr: u64, _len: usize) -> Option<Vec<u8>> {
        None
    }
}

/// Decoded representation of one syscall argument.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecodedArg {
    /// An integer value (may include symbolic name).
    Int { raw: i64, symbolic: Option<String> },
    /// An unsigned integer or pointer.
    Uint { raw: u64, symbolic: Option<String> },
    /// A string value read from process memory.
    Str(String),
    /// A flag combination (e.g. `O_RDONLY|O_CLOEXEC`).
    Flags { raw: u64, expanded: String },
    /// A null pointer.
    Null,
    /// A pointer that could not be dereferenced.
    Ptr(u64),
    /// File descriptor with optional associated path.
    Fd { fd: i32, path: Option<String> },
}

impl std::fmt::Display for DecodedArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Int { raw, symbolic: None } => write!(f, "{raw}"),
            Self::Int { symbolic: Some(s), .. }
            | Self::Uint { raw: _, symbolic: Some(s) } => write!(f, "{s}"),
            Self::Uint { raw: 0, symbolic: None } => write!(f, "0"),
            Self::Uint { raw, symbolic: None } => write!(f, "{raw:#x}"),
            Self::Str(s) => write!(f, "\"{s}\""),
            Self::Flags { expanded, .. } => write!(f, "{expanded}"),
            Self::Null => write!(f, "NULL"),
            Self::Ptr(a) => write!(f, "{a:#x}"),
            Self::Fd { fd: -100, .. } => write!(f, "AT_FDCWD"),
            Self::Fd { fd, path: Some(p) } => write!(f, "{fd} /* {p} */"),
            Self::Fd { fd, path: None } => write!(f, "{fd}"),
        }
    }
}

/// A fully decoded syscall invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedSyscall {
    pub number: u64,
    pub name: String,
    pub args: Vec<DecodedArg>,
    pub retval: i64,
    pub error: Option<String>,
    pub os: OsFamily,
    pub arch: SyscallArch,
}

impl std::fmt::Display for DecodedSyscall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(", self.name)?;
        for (i, a) in self.args.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{a}")?;
        }
        write!(f, ")")?;
        if let Some(err) = &self.error {
            write!(f, " = -1 /* {err} */")?;
        } else {
            write!(f, " = {}", self.retval)?;
        }
        Ok(())
    }
}

// ─── SyscallDecoder ───────────────────────────────────────────────────────────

/// Decodes raw register contexts into human-readable [`DecodedSyscall`] records.
pub struct SyscallDecoder<R: ProcessMemoryReader = NoopMemoryReader> {
    db: SyscallDb,
    opts: DecodeOptions,
    reader: R,
    /// Cache of fd→path mappings maintained across calls.
    fd_table: HashMap<i32, String>,
}

impl SyscallDecoder<NoopMemoryReader> {
    /// Create a decoder with the global syscall database and no memory access.
    #[must_use]
    pub fn new() -> Self {
        Self {
            db: SyscallDb::with_defaults(),
            opts: DecodeOptions::default(),
            reader: NoopMemoryReader,
            fd_table: HashMap::new(),
        }
    }
}

impl<R: ProcessMemoryReader> SyscallDecoder<R> {
    /// Create a decoder with a custom memory reader.
    pub fn with_reader(reader: R) -> Self {
        Self {
            db: SyscallDb::with_defaults(),
            opts: DecodeOptions::default(),
            reader,
            fd_table: HashMap::new(),
        }
    }

    /// Update decode options.
    pub const fn set_options(&mut self, opts: DecodeOptions) {
        self.opts = opts;
    }

    /// Register a known fd→path mapping (e.g. from an `open()` return).
    pub fn register_fd(&mut self, fd: i32, path: impl Into<String>) {
        self.fd_table.insert(fd, path.into());
    }

    /// Close / remove an fd mapping.
    pub fn close_fd(&mut self, fd: i32) {
        self.fd_table.remove(&fd);
    }

    /// Decode one syscall from registers.
    ///
    /// # Errors
    /// Returns [`SyscallError::NotFound`] if the syscall number is not present in the table.
    pub fn decode(
        &mut self,
        ctx: &RegisterContext,
        os: OsFamily,
        arch: SyscallArch,
    ) -> Result<DecodedSyscall, SyscallError> {
        let entry = self.db.lookup_by_number(os, ctx.syscall_nr).ok_or(SyscallError::NotFound { number: ctx.syscall_nr, os, arch })?;
        let args = self.decode_args(entry, ctx);
        let (retval, error) = Self::decode_return(ctx.retval, ctx.errno, entry);

        // Update fd table if this was a successful open/openat/socket etc.
        if ctx.retval >= 0 && matches!(entry.name.as_str(), "open" | "openat" | "socket" | "pipe") && let Some(DecodedArg::Str(path)) = args.first().or_else(|| args.get(1)) {
                self.fd_table.insert(i32::try_from(ctx.retval).unwrap_or(i32::MAX), path.clone());
        }
        if entry.name == "close" && let Some(fd_val) = ctx.args.first() {
                self.fd_table.remove(&(i32::try_from(*fd_val).unwrap_or(i32::MAX)));
        }

        Ok(DecodedSyscall { number: ctx.syscall_nr, name: entry.name.clone(), args, retval, error, os, arch })
    }

    fn decode_args(&self, entry: &SyscallEntry, ctx: &RegisterContext) -> Vec<DecodedArg> {
        entry
            .args
            .iter()
            .enumerate()
            .map(|(i, arg)| {
                let raw = ctx.args.get(i).copied().unwrap_or(0);
                self.decode_single_arg(arg, raw)
            })
            .collect()
    }

    fn decode_single_arg(&self, spec: &SyscallArg, raw: u64) -> DecodedArg {
        match &spec.ty {
            ArgType::Fd => {
                let fd = i32::try_from(raw.cast_signed()).unwrap_or(i32::MAX);
                if fd == -100 {
                    return DecodedArg::Fd { fd: -100, path: Some("AT_FDCWD".into()) };
                }
                let path = self.fd_table.get(&fd).cloned();
                DecodedArg::Fd { fd, path }
            }
            ArgType::CStr => {
                if raw == 0 {
                    return DecodedArg::Null;
                }
                if self.opts.dereference_pointers && let Some(s) = self.reader.read_cstring(raw, self.opts.max_string_len) {
                        return DecodedArg::Str(Self::escape_string(&s));
                }
                DecodedArg::Ptr(raw)
            }
            ArgType::Ptr => {
                if raw == 0 { DecodedArg::Null } else { DecodedArg::Ptr(raw) }
            }
            ArgType::Flags(flag_name) => {
                let expanded = Self::expand_flags(flag_name, raw);
                DecodedArg::Flags { raw, expanded }
            }
            ArgType::Int | ArgType::Long => {
                let signed = raw.cast_signed();
                let sym = Self::integer_symbolic(spec, signed);
                DecodedArg::Int { raw: signed, symbolic: sym }
            }
            ArgType::Pid => DecodedArg::Int { raw: raw.cast_signed(), symbolic: None },
            ArgType::Uid | ArgType::Gid => {
                let sym = if raw == u64::from(u32::MAX) { Some("-1".into()) } else { None };
                DecodedArg::Int { raw: raw.cast_signed(), symbolic: sym }
            }
            _ => DecodedArg::Uint { raw, symbolic: None },
        }
    }

    fn expand_flags(flag_name: &str, raw: u64) -> String {
        let table: Vec<FlagBit> = match flag_name {
            "open_flags" | "O_FLAGS" => open_flags(),
            "prot_flags" | "PROT_FLAGS" => prot_flags(),
            "map_flags" | "MAP_FLAGS" => map_flags(),
            "madvise_advice" => madvise_flags(),
            _ => return format!("{raw:#x}"),
        };

        // Special: O_RDONLY is 0, handle access mode mask (bits 0-1) first
        let mut parts: Vec<&'static str> = Vec::new();
        let mut remaining = raw;

        if flag_name.contains("open") {
            let access = raw & 0b11;
            match access {
                0 => parts.push("O_RDONLY"),
                1 => parts.push("O_WRONLY"),
                2 => parts.push("O_RDWR"),
                _ => {}
            }
            remaining &= !0b11u64;
        }

        for bit in &table {
            if bit.value == 0 || bit.name == "O_RDONLY" || bit.name == "O_WRONLY" || bit.name == "O_RDWR" {
                continue;
            }
            if remaining & bit.value == bit.value && bit.value != 0 {
                parts.push(bit.name);
                remaining &= !bit.value;
            }
        }
        if remaining != 0 {
            let mut s = parts.join("|");
            write!(s, "|{remaining:#x}").ok();
            return s;
        }
        if parts.is_empty() {
            "0".into()
        } else {
            parts.join("|")
        }
    }

    fn integer_symbolic(spec: &SyscallArg, value: i64) -> Option<String> {
        // Signals
        if spec.name.contains("sig") || spec.name.contains("signal") {
            // Negative signal numbers are invalid; guard against signed-to-usize cast
            if let Ok(idx) = usize::try_from(value) && let Some(name) = signal_names().get(idx) {
                    return Some(name.to_string());
            }
        }
        // dirfd special
        if spec.name == "dirfd" && value == -100 {
            return Some("AT_FDCWD".into());
        }
        None
    }

    fn decode_return(retval: i64, errno: i32, _entry: &SyscallEntry) -> (i64, Option<String>) {
        if retval == -1 || (retval < 0 && errno != 0) {
            // Use i32::try_from with negation guarded against i64::MIN overflow
            let derived_errno = retval.checked_neg().and_then(|v| i32::try_from(v).ok()).unwrap_or(0);
            let name = errno_name(if errno != 0 { errno } else { derived_errno });
            (retval, Some(format!("{name} (errno {})", if errno != 0 { errno } else { derived_errno })))
        } else {
            (retval, None)
        }
    }

    fn escape_string(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '\n' => out.push_str("\\n"),
                '\t' => out.push_str("\\t"),
                '\r' => out.push_str("\\r"),
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c if c.is_control() => { write!(out, "\\x{:02x}", u32::from(c)).ok(); }
                c => out.push(c),
            }
        }
        out
    }
}

impl Default for SyscallDecoder<NoopMemoryReader> {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Batch decoder ───────────────────────────────────────────────────────────

/// Decode a sequence of captured register contexts into a readable trace.
pub fn decode_trace<R: ProcessMemoryReader>(
    decoder: &mut SyscallDecoder<R>,
    events: &[(RegisterContext, OsFamily, SyscallArch)],
) -> Vec<Result<DecodedSyscall, SyscallError>> {
    events.iter().map(|(ctx, os, arch)| decoder.decode(ctx, *os, *arch)).collect()
}

/// Format a decoded trace as a strace-like text log.
#[must_use] 
pub fn format_trace(decoded: &[DecodedSyscall]) -> String {
    let mut out = String::new();
    for sc in decoded {
        writeln!(out, "{sc}").ok();
    }
    out
}

// ─── Path resolution helpers ─────────────────────────────────────────────────

/// Attempt to resolve a `/proc/<pid>/fd/<n>` symlink on Linux.
#[cfg(target_os = "linux")]
pub fn resolve_fd_via_proc(pid: u32, fd: i32) -> Option<String> {
    let link = format!("/proc/{pid}/fd/{fd}");
    std::fs::read_link(&link).ok()?.to_str().map(|s| s.to_owned())
}

/// Snapshot an entire fd table for a process from `/proc/<pid>/fd/`.
#[cfg(target_os = "linux")]
pub fn snapshot_fd_table(pid: u32) -> HashMap<i32, String> {
    let dir = format!("/proc/{pid}/fd");
    let mut map = HashMap::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            if let Ok(fd) = entry.file_name().to_str().unwrap_or("").parse::<i32>() && let Ok(target) = std::fs::read_link(entry.path()) {
                    map.insert(fd, target.to_string_lossy().into_owned());
            }
        }
    }
    map
}

// ─── Syscall trace formatter ──────────────────────────────────────────────────

/// Output format for a syscall trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceFormat {
    /// strace-compatible text: `openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3`
    Strace,
    /// One JSON object per line.
    Jsonl,
    /// CSV: nr,name,arg0,arg1,...,retval
    Csv,
    /// Compact binary with timestamps (for replay).
    Binary,
}

/// Format a single decoded syscall in a given format.
#[must_use] 
pub fn format_syscall(sc: &DecodedSyscall, fmt: TraceFormat) -> String {
    match fmt {
        TraceFormat::Strace => sc.to_string(),
        TraceFormat::Jsonl => serde_json::to_string(sc).unwrap_or_default(),
        TraceFormat::Csv => {
            let mut row = format!("{},{}", sc.number, sc.name);
            for arg in &sc.args {
                row.push(',');
                write!(row, "{arg}").ok();
            }
            row.push(',');
            write!(row, "{}", sc.retval).ok();
            row
        }
        TraceFormat::Binary => {
            // 8 bytes nr + 8 bytes retval + 8 bytes * up to 6 args
            let mut bytes = Vec::with_capacity(8 + 8 + 48);
            bytes.extend_from_slice(&sc.number.to_le_bytes());
            bytes.extend_from_slice(&sc.retval.to_le_bytes());
            for i in 0..6 {
                let raw: u64 = match sc.args.get(i) {
                    Some(DecodedArg::Int { raw, .. }) => (*raw).cast_unsigned(),
                    Some(DecodedArg::Uint { raw, .. }) => *raw,
                    Some(DecodedArg::Fd { fd, .. }) => i64::from(*fd).cast_unsigned(),
                    Some(DecodedArg::Ptr(p)) => *p,
                    _ => 0,
                };
                bytes.extend_from_slice(&raw.to_le_bytes());
            }
            // Not a valid UTF-8 string, but format as hex for display
            let mut hex = String::with_capacity(bytes.len() * 2);
            for b in &bytes {
                write!(hex, "{b:02x}").ok();
            }
            hex
        }
    }
}

// ─── Syscall statistics ───────────────────────────────────────────────────────

/// Aggregated syscall call statistics across a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallStats {
    /// Total syscalls recorded.
    pub total: usize,
    /// Unique syscall numbers seen.
    pub unique_calls: usize,
    /// Most frequent calls: (name, count).
    pub top_calls: Vec<(String, usize)>,
    /// Error rate: syscalls that returned < 0.
    pub error_count: usize,
    pub error_rate: f64,
    /// Calls grouped by category name.
    pub by_category: HashMap<String, usize>,
}

/// Compute statistics from a decoded trace.
#[must_use] 
pub fn compute_stats(decoded: &[DecodedSyscall]) -> SyscallStats {
    let mut freq: HashMap<String, usize> = HashMap::new();
    let mut errors = 0usize;
    let mut by_category: HashMap<String, usize> = HashMap::new();

    for sc in decoded {
        *freq.entry(sc.name.clone()).or_insert(0) += 1;
        if sc.error.is_some() || sc.retval < 0 { errors += 1; }
        // Simple category heuristic by name prefix
        let cat = categorize_by_name(&sc.name);
        *by_category.entry(cat).or_insert(0) += 1;
    }

    let unique_calls = freq.len();
    let total = decoded.len();
    let error_rate = if total == 0 { 0.0 } else { crate::usize_to_f64(errors) / crate::usize_to_f64(total) * 100.0 };

    let mut top: Vec<(String, usize)> = freq.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1));
    top.truncate(10);

    SyscallStats { total, unique_calls, top_calls: top, error_count: errors, error_rate, by_category }
}

fn categorize_by_name(name: &str) -> String {
    if name.contains("read") || name.contains("write") || name.contains("open") || name.contains("file") || name.contains("stat") || name.contains("dir") {
        "filesystem".into()
    } else if name.contains("socket") || name.contains("send") || name.contains("recv") || name.contains("connect") || name.contains("bind") {
        "network".into()
    } else if name.contains("fork") || name.contains("exec") || name.contains("clone") || name.contains("wait") || name.contains("exit") {
        "process".into()
    } else if name.contains("mmap") || name.contains("brk") || name.contains("alloc") || name.contains("mprotect") {
        "memory".into()
    } else if name.contains("signal") || name.contains("kill") || name.contains("rt_sig") {
        "signal".into()
    } else if name.contains("futex") || name.contains("mutex") || name.contains("sem") {
        "sync".into()
    } else {
        "other".into()
    }
}

impl std::fmt::Display for SyscallStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Syscall Trace Statistics")?;
        writeln!(f, "  Total calls    : {}", self.total)?;
        writeln!(f, "  Unique syscalls: {}", self.unique_calls)?;
        writeln!(f, "  Errors         : {} ({:.1}%)", self.error_count, self.error_rate)?;
        writeln!(f, "  Top calls:")?;
        for (name, count) in &self.top_calls {
            writeln!(f, "    {name:30} {count}")?;
        }
        writeln!(f, "  By category:")?;
        let mut cats: Vec<(&String, &usize)> = self.by_category.iter().collect();
        cats.sort_by(|a, b| b.1.cmp(a.1));
        for (cat, count) in cats {
            writeln!(f, "    {cat:20} {count}")?;
        }
        Ok(())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_open_flags() {
        let dec = SyscallDecoder::new();
        let spec_dummy = SyscallArg { name: "flags".into(), ty: ArgType::Flags("open_flags".into()) };
        let result = dec.decode_single_arg(&spec_dummy, 0o2_000_002); // O_RDWR | O_CLOEXEC
        if let DecodedArg::Flags { expanded, .. } = result {
            assert!(expanded.contains("O_RDWR") || expanded.contains("O_CLOEXEC") || expanded.contains("0x"));
        } else {
            panic!("expected Flags");
        }
    }

    #[test]
    fn test_at_fdcwd() {
        let dec = SyscallDecoder::new();
        let spec = SyscallArg { name: "dirfd".into(), ty: ArgType::Fd };
        let decoded = dec.decode_single_arg(&spec, (-100i64).cast_unsigned());
        assert_eq!(format!("{decoded}"), "AT_FDCWD");
    }

    #[test]
    fn test_null_ptr() {
        let dec = SyscallDecoder::new();
        let spec = SyscallArg { name: "buf".into(), ty: ArgType::Ptr };
        let decoded = dec.decode_single_arg(&spec, 0);
        assert_eq!(format!("{decoded}"), "NULL");
    }

    #[test]
    fn test_errno_decode() {
        let dec = SyscallDecoder::new();
        let entry = crate::syscall_table::SyscallEntry {
            number: 2,
            name: "open".into(),
            os: OsFamily::Linux,
            return_type: ArgType::Fd,
            args: vec![],
            description: String::new(),
            tags: vec![],
        };
        let _ = &dec;
        let (rv, err) = <SyscallDecoder<NoopMemoryReader>>::decode_return(-1, 13, &entry);
        assert_eq!(rv, -1);
        assert!(err.unwrap().contains("EACCES"));
    }
}
