//! `rustre-syscalls`
//!
//! Core syscall abstraction, database, filtering, formatting, tracing API,
//! categorization, parameter decoding, and persistence layer for the `RustRE`
//! reverse-engineering suite.

// The mysql crate (v25) transitively pulls in older versions of base64, getrandom,
// ahash, thiserror, etc. that conflict with newer workspace deps. These duplicate
// versions are transitive and cannot be resolved without upstream crate updates.

pub mod compat_layer;
pub mod syscall_decoder;
pub mod syscall_emulator;
pub mod syscall_filter;
pub mod syscall_hook_detector;
pub mod syscall_table;
pub mod syscall_table_linux;
pub mod syscall_table_win;
pub mod syscall_tracer;
pub mod windows_syscalls;
pub mod syscall_dispatcher;
pub mod syscall_statistics;
pub mod syscall_policy_checker;
pub mod linux_syscall_table;

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::ops::RangeInclusive;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SyscallError {
    #[error("syscall not found: number={number} os={os:?} arch={arch:?}")]
    NotFound {
        number: u64,
        os: OsFamily,
        arch: SyscallArch,
    },
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("mysql error: {0}")]
    Mysql(String),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

// ─── OS / Arch enumerations ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OsFamily {
    Linux,
    Windows,
    MacOs,
    FreeBsd,
    OpenBsd,
}

impl fmt::Display for OsFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Linux => write!(f, "linux"),
            Self::Windows => write!(f, "windows"),
            Self::MacOs => write!(f, "macos"),
            Self::FreeBsd => write!(f, "freebsd"),
            Self::OpenBsd => write!(f, "openbsd"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyscallArch {
    X86,
    X86_64,
    Arm32,
    Arm64,
    Mips,
    Riscv64,
}

impl fmt::Display for SyscallArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86 => write!(f, "x86"),
            Self::X86_64 => write!(f, "x86_64"),
            Self::Arm32 => write!(f, "arm32"),
            Self::Arm64 => write!(f, "arm64"),
            Self::Mips => write!(f, "mips"),
            Self::Riscv64 => write!(f, "riscv64"),
        }
    }
}

// ─── Type system ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyscallType {
    Void,
    Int,
    UInt,
    Long,
    ULong,
    Ptr,
    Handle,
    Bool,
    Fd,
    Pid,
    Tid,
    Size,
    SSize,
    Errno,
    Buffer {
        /// Index (0-based) of the argument that carries the buffer size, if any.
        size_arg: Option<usize>,
    },
    String,
    WString,
    Struct(std::string::String),
    Enum(std::string::String),
    Flags(std::string::String),
    /// A user-space address / pointer (architecture-native width).
    UserPtr,
    /// Kernel-space address.
    KernelPtr,
    /// Network socket address family.
    SaFamily,
    /// File offset (`loff_t`, `off64_t`).
    Offset,
    /// Mode bits (`umode_t`).
    Mode,
    /// Signal number.
    Signal,
    /// Clock ID.
    ClockId,
    /// A list of file descriptors (`int[]`).
    FdArray,
    /// `socklen_t`.
    Socklen,
    /// IP address in network byte order.
    IpAddr,
}

impl fmt::Display for SyscallType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Void => write!(f, "void"),
            Self::Int | Self::Fd | Self::Errno | Self::Signal => write!(f, "int"),
            Self::UInt => write!(f, "unsigned int"),
            Self::Long => write!(f, "long"),
            Self::ULong => write!(f, "unsigned long"),
            Self::Ptr | Self::Buffer { .. } | Self::KernelPtr => write!(f, "void *"),
            Self::Handle => write!(f, "HANDLE"),
            Self::Bool => write!(f, "bool"),
            Self::Pid | Self::Tid => write!(f, "pid_t"),
            Self::Size => write!(f, "size_t"),
            Self::SSize => write!(f, "ssize_t"),
            Self::String => write!(f, "const char *"),
            Self::WString => write!(f, "const wchar_t *"),
            Self::Struct(n) => write!(f, "struct {n} *"),
            Self::Enum(n) => write!(f, "enum {n}"),
            Self::Flags(n) => write!(f, "{n}"),
            Self::UserPtr => write!(f, "uintptr_t"),
            Self::SaFamily => write!(f, "sa_family_t"),
            Self::Offset => write!(f, "loff_t"),
            Self::Mode => write!(f, "umode_t"),
            Self::ClockId => write!(f, "clockid_t"),
            Self::FdArray => write!(f, "int[]"),
            Self::Socklen => write!(f, "socklen_t"),
            Self::IpAddr => write!(f, "uint32_t"),
        }
    }
}

// ─── Argument direction ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArgDirection {
    In,
    Out,
    InOut,
}

impl fmt::Display for ArgDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::In => write!(f, "in"),
            Self::Out => write!(f, "out"),
            Self::InOut => write!(f, "inout"),
        }
    }
}

// ─── Syscall categories ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyscallCategory {
    FileSystem,
    Memory,
    Process,
    Thread,
    Network,
    Ipc,
    Signal,
    Time,
    Device,
    Security,
    System,
    Unknown,
}

impl fmt::Display for SyscallCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileSystem => write!(f, "filesystem"),
            Self::Memory => write!(f, "memory"),
            Self::Process => write!(f, "process"),
            Self::Thread => write!(f, "thread"),
            Self::Network => write!(f, "network"),
            Self::Ipc => write!(f, "ipc"),
            Self::Signal => write!(f, "signal"),
            Self::Time => write!(f, "time"),
            Self::Device => write!(f, "device"),
            Self::Security => write!(f, "security"),
            Self::System => write!(f, "system"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ─── Syscall risk level ───────────────────────────────────────────────────────

/// Security risk level of a syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    /// No special concern.
    Benign = 0,
    /// Low risk — common and expected.
    Low = 1,
    /// Medium risk — could be abused but not unusual.
    Medium = 2,
    /// High risk — frequently used in attacks.
    High = 3,
    /// Critical — almost exclusively used in exploit/malware contexts.
    Critical = 4,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Benign => write!(f, "benign"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ─── Core types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallArg {
    pub name: std::string::String,
    pub ty: SyscallType,
    pub direction: ArgDirection,
    pub optional: bool,
}

impl SyscallArg {
    #[must_use]
    pub fn new(
        name: impl Into<std::string::String>,
        ty: SyscallType,
        direction: ArgDirection,
    ) -> Self {
        Self {
            name: name.into(),
            ty,
            direction,
            optional: false,
        }
    }

    #[must_use]
    pub const fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    /// Decode a raw `u64` value according to this argument's type.
    #[must_use]
    pub fn decode(&self, raw: u64) -> DecodedArg {
        decode_arg_value(&self.ty, raw)
    }
}

/// A decoded argument value with its display representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedArg {
    /// Raw register value.
    pub raw: u64,
    /// Human-readable representation.
    pub display: std::string::String,
    /// Whether this looks like a null pointer.
    pub is_null: bool,
}

impl DecodedArg {
    #[must_use]
    pub fn new(raw: u64, display: impl Into<std::string::String>, is_null: bool) -> Self {
        Self {
            raw,
            display: display.into(),
            is_null,
        }
    }
}

impl fmt::Display for DecodedArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display)
    }
}

/// Reinterpret the low 32 bits of a `u64` as a signed `i32` (bit-cast).
#[inline]
#[must_use]
const fn low32_as_i32(raw: u64) -> i32 {
    let bytes = raw.to_le_bytes();
    i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Reinterpret the low 16 bits of a `u64` as `u16` (bit-cast).
#[inline]
#[must_use]
const fn low16(raw: u64) -> u16 {
    let bytes = raw.to_le_bytes();
    u16::from_le_bytes([bytes[0], bytes[1]])
}

/// Reinterpret the low 32 bits of a `u64` as `u32` (bit-cast).
#[inline]
#[must_use]
const fn low32(raw: u64) -> u32 {
    let bytes = raw.to_le_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Reinterpret a `u64` as `i64` (bit-cast).
#[inline]
#[must_use]
const fn as_i64(raw: u64) -> i64 {
    i64::from_le_bytes(raw.to_le_bytes())
}

/// Convert a `u64` to `f64`, splitting the value into high and low 32-bit
/// halves so the conversion can use the lossless `f64::from(u32)` primitive.
/// This still loses precision for values above 2^53 but mirrors the standard
/// `as f64` behaviour without the lossy single-cast warning.
#[inline]
#[must_use]
pub(crate) fn u64_to_f64(n: u64) -> f64 {
    let high = u32::try_from(n >> 32).unwrap_or(u32::MAX);
    let low = u32::try_from(n & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    f64::from(high) * 4_294_967_296.0_f64 + f64::from(low)
}

/// Convert a `usize` to `f64`. Delegates to [`u64_to_f64`] after a widening
/// conversion which is lossless on 32- and 64-bit targets.
#[inline]
#[must_use]
pub(crate) fn usize_to_f64(n: usize) -> f64 {
    u64_to_f64(u64::try_from(n).unwrap_or(u64::MAX))
}

/// Decode a raw `u64` using type information.
#[must_use]
pub fn decode_arg_value(ty: &SyscallType, raw: u64) -> DecodedArg {
    match ty {
        SyscallType::Bool => {
            let display = if raw == 0 { "false" } else { "true" }.to_string();
            DecodedArg::new(raw, display, false)
        }
        SyscallType::Fd => {
            let v = low32_as_i32(raw);
            let display = if v < 0 {
                format!("{v} /* bad fd */")
            } else if v == 0 {
                "0 /* stdin */".to_string()
            } else if v == 1 {
                "1 /* stdout */".to_string()
            } else if v == 2 {
                "2 /* stderr */".to_string()
            } else {
                format!("{v}")
            };
            DecodedArg::new(raw, display, false)
        }
        SyscallType::Pid | SyscallType::Tid => {
            let v = low32_as_i32(raw);
            let display = match v.cmp(&0) {
                std::cmp::Ordering::Equal => "0 /* self */".to_string(),
                std::cmp::Ordering::Less => format!("{v} /* process group */"),
                std::cmp::Ordering::Greater => format!("{v}"),
            };
            DecodedArg::new(raw, display, false)
        }
        SyscallType::Signal => {
            let display = signal_name(low32(raw)).map_or_else(
                || format!("{}", low32_as_i32(raw)),
                std::string::ToString::to_string,
            );
            DecodedArg::new(raw, display, false)
        }
        SyscallType::Ptr
        | SyscallType::UserPtr
        | SyscallType::KernelPtr
        | SyscallType::Buffer { .. } => {
            if raw == 0 {
                DecodedArg::new(raw, "NULL".to_string(), true)
            } else {
                DecodedArg::new(raw, format!("0x{raw:016x}"), false)
            }
        }
        SyscallType::String | SyscallType::WString => {
            // Without memory access we just display the pointer.
            if raw == 0 {
                DecodedArg::new(raw, "NULL".to_string(), true)
            } else {
                DecodedArg::new(raw, format!("0x{raw:016x}"), false)
            }
        }
        SyscallType::Int | SyscallType::Errno => {
            let v = low32_as_i32(raw);
            if v < 0 {
                let errno_name = errno_name((-v).cast_unsigned()).unwrap_or("?");
                DecodedArg::new(raw, format!("-1 /* -{errno_name} */"), false)
            } else {
                DecodedArg::new(raw, format!("{v}"), false)
            }
        }
        SyscallType::Long | SyscallType::SSize | SyscallType::Offset => {
            DecodedArg::new(raw, format!("{}", as_i64(raw)), false)
        }
        SyscallType::Mode => DecodedArg::new(raw, format!("0o{:04o}", raw & 0o7777), false),
        SyscallType::ClockId => {
            let name = clock_id_name(low32(raw)).unwrap_or("CLOCK_UNKNOWN");
            DecodedArg::new(raw, name.to_string(), false)
        }
        SyscallType::SaFamily => {
            let name = sa_family_name(low16(raw)).unwrap_or("AF_UNKNOWN");
            DecodedArg::new(raw, name.to_string(), false)
        }
        SyscallType::Socklen => DecodedArg::new(raw, format!("{}", low32(raw)), false),
        SyscallType::IpAddr => {
            let b0 = (raw & 0xFF) as u8;
            let b1 = ((raw >> 8) & 0xFF) as u8;
            let b2 = ((raw >> 16) & 0xFF) as u8;
            let b3 = ((raw >> 24) & 0xFF) as u8;
            DecodedArg::new(raw, format!("{b0}.{b1}.{b2}.{b3}"), false)
        }
        _ => DecodedArg::new(raw, format!("{raw}"), false),
    }
}

/// Map a Linux signal number to its name.
#[must_use]
pub const fn signal_name(sig: u32) -> Option<&'static str> {
    match sig {
        1 => Some("SIGHUP"),
        2 => Some("SIGINT"),
        3 => Some("SIGQUIT"),
        4 => Some("SIGILL"),
        5 => Some("SIGTRAP"),
        6 => Some("SIGABRT"),
        7 => Some("SIGBUS"),
        8 => Some("SIGFPE"),
        9 => Some("SIGKILL"),
        10 => Some("SIGUSR1"),
        11 => Some("SIGSEGV"),
        12 => Some("SIGUSR2"),
        13 => Some("SIGPIPE"),
        14 => Some("SIGALRM"),
        15 => Some("SIGTERM"),
        16 => Some("SIGSTKFLT"),
        17 => Some("SIGCHLD"),
        18 => Some("SIGCONT"),
        19 => Some("SIGSTOP"),
        20 => Some("SIGTSTP"),
        21 => Some("SIGTTIN"),
        22 => Some("SIGTTOU"),
        23 => Some("SIGURG"),
        24 => Some("SIGXCPU"),
        25 => Some("SIGXFSZ"),
        26 => Some("SIGVTALRM"),
        27 => Some("SIGPROF"),
        28 => Some("SIGWINCH"),
        29 => Some("SIGIO"),
        30 => Some("SIGPWR"),
        31 => Some("SIGSYS"),
        _ => None,
    }
}

/// Map an errno number to its name.
#[must_use]
pub const fn errno_name(errno: u32) -> Option<&'static str> {
    match errno {
        1 => Some("EPERM"),
        2 => Some("ENOENT"),
        3 => Some("ESRCH"),
        4 => Some("EINTR"),
        5 => Some("EIO"),
        6 => Some("ENXIO"),
        7 => Some("E2BIG"),
        8 => Some("ENOEXEC"),
        9 => Some("EBADF"),
        10 => Some("ECHILD"),
        11 => Some("EAGAIN"),
        12 => Some("ENOMEM"),
        13 => Some("EACCES"),
        14 => Some("EFAULT"),
        15 => Some("ENOTBLK"),
        16 => Some("EBUSY"),
        17 => Some("EEXIST"),
        18 => Some("EXDEV"),
        19 => Some("ENODEV"),
        20 => Some("ENOTDIR"),
        21 => Some("EISDIR"),
        22 => Some("EINVAL"),
        23 => Some("ENFILE"),
        24 => Some("EMFILE"),
        25 => Some("ENOTTY"),
        26 => Some("ETXTBSY"),
        27 => Some("EFBIG"),
        28 => Some("ENOSPC"),
        29 => Some("ESPIPE"),
        30 => Some("EROFS"),
        31 => Some("EMLINK"),
        32 => Some("EPIPE"),
        33 => Some("EDOM"),
        34 => Some("ERANGE"),
        35 => Some("EDEADLK"),
        36 => Some("ENAMETOOLONG"),
        37 => Some("ENOLCK"),
        38 => Some("ENOSYS"),
        39 => Some("ENOTEMPTY"),
        40 => Some("ELOOP"),
        42 => Some("ENOMSG"),
        43 => Some("EIDRM"),
        44 => Some("ECHRNG"),
        60 => Some("ENOSTR"),
        61 => Some("ENODATA"),
        62 => Some("ETIME"),
        63 => Some("ENOSR"),
        67 => Some("ENOLINK"),
        71 => Some("EPROTO"),
        72 => Some("EMULTIHOP"),
        74 => Some("EBADMSG"),
        75 => Some("EOVERFLOW"),
        84 => Some("EILSEQ"),
        88 => Some("ENOTSOCK"),
        89 => Some("EDESTADDRREQ"),
        90 => Some("EMSGSIZE"),
        91 => Some("EPROTOTYPE"),
        92 => Some("ENOPROTOOPT"),
        93 => Some("EPROTONOSUPPORT"),
        94 => Some("ESOCKTNOSUPPORT"),
        95 => Some("EOPNOTSUPP"),
        97 => Some("EAFNOSUPPORT"),
        98 => Some("EADDRINUSE"),
        99 => Some("EADDRNOTAVAIL"),
        100 => Some("ENETDOWN"),
        101 => Some("ENETUNREACH"),
        102 => Some("ENETRESET"),
        103 => Some("ECONNABORTED"),
        104 => Some("ECONNRESET"),
        105 => Some("ENOBUFS"),
        106 => Some("EISCONN"),
        107 => Some("ENOTCONN"),
        110 => Some("ETIMEDOUT"),
        111 => Some("ECONNREFUSED"),
        112 => Some("EHOSTDOWN"),
        113 => Some("EHOSTUNREACH"),
        114 => Some("EALREADY"),
        115 => Some("EINPROGRESS"),
        _ => None,
    }
}

/// Map a clock ID to its name.
#[must_use]
pub const fn clock_id_name(id: u32) -> Option<&'static str> {
    match id {
        0 => Some("CLOCK_REALTIME"),
        1 => Some("CLOCK_MONOTONIC"),
        2 => Some("CLOCK_PROCESS_CPUTIME_ID"),
        3 => Some("CLOCK_THREAD_CPUTIME_ID"),
        4 => Some("CLOCK_MONOTONIC_RAW"),
        5 => Some("CLOCK_REALTIME_COARSE"),
        6 => Some("CLOCK_MONOTONIC_COARSE"),
        7 => Some("CLOCK_BOOTTIME"),
        8 => Some("CLOCK_REALTIME_ALARM"),
        9 => Some("CLOCK_BOOTTIME_ALARM"),
        _ => None,
    }
}

/// Map an address family constant to its name.
#[must_use]
pub const fn sa_family_name(family: u16) -> Option<&'static str> {
    match family {
        0 => Some("AF_UNSPEC"),
        1 => Some("AF_UNIX"),
        2 => Some("AF_INET"),
        3 => Some("AF_AX25"),
        4 => Some("AF_IPX"),
        5 => Some("AF_APPLETALK"),
        6 => Some("AF_NETROM"),
        7 => Some("AF_BRIDGE"),
        8 => Some("AF_ATMPVC"),
        9 => Some("AF_X25"),
        10 => Some("AF_INET6"),
        11 => Some("AF_ROSE"),
        12 => Some("AF_DECnet"),
        16 => Some("AF_NETLINK"),
        17 => Some("AF_PACKET"),
        18 => Some("AF_ASH"),
        19 => Some("AF_ECONET"),
        20 => Some("AF_ATMSVC"),
        22 => Some("AF_SNA"),
        23 => Some("AF_IRDA"),
        24 => Some("AF_PPPOX"),
        25 => Some("AF_WANPIPE"),
        26 => Some("AF_LLC"),
        29 => Some("AF_CAN"),
        30 => Some("AF_TIPC"),
        31 => Some("AF_BLUETOOTH"),
        32 => Some("AF_IUCV"),
        33 => Some("AF_RXRPC"),
        34 => Some("AF_ISDN"),
        36 => Some("AF_PHONET"),
        37 => Some("AF_IEEE802154"),
        38 => Some("AF_CAIF"),
        39 => Some("AF_ALG"),
        40 => Some("AF_NFC"),
        41 => Some("AF_VSOCK"),
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Syscall {
    pub number: u64,
    pub name: std::string::String,
    pub os: OsFamily,
    pub arch: SyscallArch,
    pub args: Vec<SyscallArg>,
    pub return_type: SyscallType,
    pub category: SyscallCategory,
    pub description: std::string::String,
    /// Security risk level of this syscall.
    pub risk: RiskLevel,
    /// Aliases (e.g. `open64` is an alias for `open`).
    pub aliases: Vec<std::string::String>,
    /// Whether this syscall is deprecated / obsolete.
    pub deprecated: bool,
}

/// Target platform identifier combining OS family and architecture.
#[derive(Debug, Clone, Copy)]
pub struct SyscallTarget {
    pub os: OsFamily,
    pub arch: SyscallArch,
}

impl SyscallTarget {
    #[must_use]
    pub const fn new(os: OsFamily, arch: SyscallArch) -> Self {
        Self { os, arch }
    }
}

impl Syscall {
    #[must_use]
    pub fn new(
        number: u64,
        name: impl Into<std::string::String>,
        target: SyscallTarget,
        args: Vec<SyscallArg>,
        return_type: SyscallType,
        category: SyscallCategory,
        description: impl Into<std::string::String>,
    ) -> Self {
        Self {
            number,
            name: name.into(),
            os: target.os,
            arch: target.arch,
            args,
            return_type,
            category,
            description: description.into(),
            risk: RiskLevel::Low,
            aliases: Vec::new(),
            deprecated: false,
        }
    }

    /// Return decoded arguments for a raw argument slice.
    #[must_use]
    pub fn decode_args(&self, raw_args: &[u64]) -> Vec<DecodedArg> {
        self.args
            .iter()
            .enumerate()
            .map(|(i, arg)| {
                let raw = raw_args.get(i).copied().unwrap_or(0);
                arg.decode(raw)
            })
            .collect()
    }

    /// Return a C-like prototype string.
    #[must_use]
    pub fn prototype(&self) -> std::string::String {
        let params: Vec<std::string::String> = self
            .args
            .iter()
            .map(|a| format!("{} {}", a.ty, a.name))
            .collect();
        format!("{} {}({})", self.return_type, self.name, params.join(", "))
    }

    /// Return `true` if this syscall has any `Out` or `InOut` arguments (i.e.,
    /// may modify caller memory).
    #[must_use]
    pub fn has_output_args(&self) -> bool {
        self.args
            .iter()
            .any(|a| matches!(a.direction, ArgDirection::Out | ArgDirection::InOut))
    }

    /// Return the count of input-only arguments.
    #[must_use]
    pub fn input_arg_count(&self) -> usize {
        self.args
            .iter()
            .filter(|a| a.direction == ArgDirection::In)
            .count()
    }
}

// ─── Syscall database ─────────────────────────────────────────────────────────

/// A database of known syscalls indexed by `(OsFamily, SyscallArch, number)`.
#[derive(Debug, Default)]
pub struct SyscallDatabase {
    by_number: HashMap<(OsFamily, SyscallArch, u64), Syscall>,
    /// Index: (os, arch, name) → number for fast name lookups.
    name_index: HashMap<(OsFamily, SyscallArch, std::string::String), u64>,
}

impl SyscallDatabase {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a syscall definition into the database.
    pub fn insert(&mut self, syscall: Syscall) {
        let key = (syscall.os, syscall.arch, syscall.number);
        let name_key = (syscall.os, syscall.arch, syscall.name.clone());
        for alias in &syscall.aliases {
            let alias_key = (syscall.os, syscall.arch, alias.clone());
            self.name_index.insert(alias_key, syscall.number);
        }
        self.name_index.insert(name_key, syscall.number);
        self.by_number.insert(key, syscall);
    }

    /// Merge another database into this one (other takes precedence on conflict).
    pub fn merge(&mut self, other: Self) {
        for (k, v) in other.by_number {
            let name_key = (v.os, v.arch, v.name.clone());
            self.name_index.insert(name_key, v.number);
            self.by_number.insert(k, v);
        }
    }

    #[must_use]
    pub fn lookup(&self, os: OsFamily, arch: SyscallArch, number: u64) -> Option<&Syscall> {
        self.by_number.get(&(os, arch, number))
    }

    #[must_use]
    pub fn lookup_by_name(&self, os: OsFamily, arch: SyscallArch, name: &str) -> Option<&Syscall> {
        let key = (os, arch, name.to_string());
        let number = self.name_index.get(&key)?;
        self.by_number.get(&(os, arch, *number))
    }

    #[must_use]
    pub fn all_for(&self, os: OsFamily, arch: SyscallArch) -> Vec<&Syscall> {
        let mut v: Vec<&Syscall> = self
            .by_number
            .values()
            .filter(|s| s.os == os && s.arch == arch)
            .collect();
        v.sort_by_key(|s| s.number);
        v
    }

    /// Return all syscalls matching a given category.
    #[must_use]
    pub fn all_for_category(
        &self,
        os: OsFamily,
        arch: SyscallArch,
        cat: SyscallCategory,
    ) -> Vec<&Syscall> {
        let mut v: Vec<&Syscall> = self
            .by_number
            .values()
            .filter(|s| s.os == os && s.arch == arch && s.category == cat)
            .collect();
        v.sort_by_key(|s| s.number);
        v
    }

    /// Return all syscalls at or above a given risk level.
    #[must_use]
    pub fn high_risk(&self, os: OsFamily, arch: SyscallArch, min_risk: RiskLevel) -> Vec<&Syscall> {
        let mut v: Vec<&Syscall> = self
            .by_number
            .values()
            .filter(|s| s.os == os && s.arch == arch && s.risk >= min_risk)
            .collect();
        v.sort_by_key(|s| s.number);
        v
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_number.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_number.is_empty()
    }

    /// Return statistics about the database.
    #[must_use]
    pub fn stats(&self) -> DatabaseStats {
        let mut by_category: HashMap<SyscallCategory, usize> = HashMap::new();
        let mut by_risk: HashMap<std::string::String, usize> = HashMap::new();
        for sc in self.by_number.values() {
            *by_category.entry(sc.category).or_default() += 1;
            *by_risk.entry(sc.risk.to_string()).or_default() += 1;
        }
        DatabaseStats {
            total: self.by_number.len(),
            by_category,
            by_risk,
        }
    }
}

/// Aggregate statistics about a [`SyscallDatabase`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStats {
    pub total: usize,
    pub by_category: HashMap<SyscallCategory, usize>,
    pub by_risk: HashMap<std::string::String, usize>,
}

// ─── Recorded syscall call ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallCall {
    pub syscall: Syscall,
    /// Raw register values for each argument (up to 6).
    pub args: Vec<u64>,
    /// Return value (signed to match Linux convention).
    pub ret: i64,
    /// Nanosecond timestamp.
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    /// Optional tag / label (e.g. from a filter rule that matched).
    pub tags: Vec<std::string::String>,
}

impl SyscallCall {
    #[must_use]
    pub const fn new(
        syscall: Syscall,
        args: Vec<u64>,
        ret: i64,
        timestamp: u64,
        pid: u32,
        tid: u32,
    ) -> Self {
        Self {
            syscall,
            args,
            ret,
            timestamp,
            pid,
            tid,
            tags: Vec::new(),
        }
    }

    /// Return `true` if the syscall returned an error (Linux convention: negative).
    #[must_use]
    pub const fn is_error(&self) -> bool {
        self.ret < 0
    }

    /// Return the decoded argument list.
    #[must_use]
    pub fn decoded_args(&self) -> Vec<DecodedArg> {
        self.syscall.decode_args(&self.args)
    }

    /// Elapsed time in microseconds since the given base timestamp.
    #[must_use]
    pub const fn elapsed_us(&self, base_ns: u64) -> u64 {
        self.timestamp.saturating_sub(base_ns) / 1_000
    }

    /// Add a tag to this call record.
    pub fn tag(&mut self, t: impl Into<std::string::String>) {
        self.tags.push(t.into());
    }
}

// ─── Static syscall number tables ────────────────────────────────────────────

/// Linux x86-64 syscall table: (number, name) for NR 0–329.
static LINUX_X86_64_ENTRIES: &[(u64, &str)] = &[
    (0, "read"),
    (1, "write"),
    (2, "open"),
    (3, "close"),
    (4, "stat"),
    (5, "fstat"),
    (6, "lstat"),
    (7, "poll"),
    (8, "lseek"),
    (9, "mmap"),
    (10, "mprotect"),
    (11, "munmap"),
    (12, "brk"),
    (13, "rt_sigaction"),
    (14, "rt_sigprocmask"),
    (15, "rt_sigreturn"),
    (16, "ioctl"),
    (17, "pread64"),
    (18, "pwrite64"),
    (19, "readv"),
    (20, "writev"),
    (21, "access"),
    (22, "pipe"),
    (23, "select"),
    (24, "sched_yield"),
    (25, "mremap"),
    (26, "msync"),
    (27, "mincore"),
    (28, "madvise"),
    (29, "shmget"),
    (30, "shmat"),
    (31, "shmctl"),
    (32, "dup"),
    (33, "dup2"),
    (34, "pause"),
    (35, "nanosleep"),
    (36, "getitimer"),
    (37, "alarm"),
    (38, "setitimer"),
    (39, "getpid"),
    (40, "sendfile"),
    (41, "socket"),
    (42, "connect"),
    (43, "accept"),
    (44, "sendto"),
    (45, "recvfrom"),
    (46, "sendmsg"),
    (47, "recvmsg"),
    (48, "shutdown"),
    (49, "bind"),
    (50, "listen"),
    (51, "getsockname"),
    (52, "getpeername"),
    (53, "socketpair"),
    (54, "setsockopt"),
    (55, "getsockopt"),
    (56, "clone"),
    (57, "fork"),
    (58, "vfork"),
    (59, "execve"),
    (60, "exit"),
    (61, "wait4"),
    (62, "kill"),
    (63, "uname"),
    (64, "semget"),
    (65, "semop"),
    (66, "semctl"),
    (67, "shmdt"),
    (68, "msgget"),
    (69, "msgsnd"),
    (70, "msgrcv"),
    (71, "msgctl"),
    (72, "fcntl"),
    (73, "flock"),
    (74, "fsync"),
    (75, "fdatasync"),
    (76, "truncate"),
    (77, "ftruncate"),
    (78, "getdents"),
    (79, "getcwd"),
    (80, "chdir"),
    (81, "fchdir"),
    (82, "rename"),
    (83, "mkdir"),
    (84, "rmdir"),
    (85, "creat"),
    (86, "link"),
    (87, "unlink"),
    (88, "symlink"),
    (89, "readlink"),
    (90, "chmod"),
    (91, "fchmod"),
    (92, "chown"),
    (93, "fchown"),
    (94, "lchown"),
    (95, "umask"),
    (96, "gettimeofday"),
    (97, "getrlimit"),
    (98, "getrusage"),
    (99, "sysinfo"),
    (100, "times"),
    (101, "ptrace"),
    (102, "getuid"),
    (103, "syslog"),
    (104, "getgid"),
    (105, "setuid"),
    (106, "setgid"),
    (107, "geteuid"),
    (108, "getegid"),
    (109, "setpgid"),
    (110, "getppid"),
    (111, "getpgrp"),
    (112, "setsid"),
    (113, "setreuid"),
    (114, "setregid"),
    (115, "getgroups"),
    (116, "setgroups"),
    (117, "setresuid"),
    (118, "getresuid"),
    (119, "setresgid"),
    (120, "getresgid"),
    (121, "getpgrp"),
    (122, "setfsuid"),
    (123, "setfsgid"),
    (124, "getsid"),
    (125, "capget"),
    (126, "capset"),
    (127, "rt_sigpending"),
    (128, "rt_sigtimedwait"),
    (129, "rt_sigqueueinfo"),
    (130, "rt_sigsuspend"),
    (131, "sigaltstack"),
    (132, "utime"),
    (133, "mknod"),
    (134, "uselib"),
    (135, "personality"),
    (136, "ustat"),
    (137, "statfs"),
    (138, "fstatfs"),
    (139, "sysfs"),
    (140, "getpriority"),
    (141, "setpriority"),
    (142, "sched_setparam"),
    (143, "sched_getparam"),
    (144, "sched_setscheduler"),
    (145, "sched_getscheduler"),
    (146, "sched_get_priority_max"),
    (147, "sched_get_priority_min"),
    (148, "sched_rr_get_interval"),
    (149, "mlock"),
    (150, "munlock"),
    (151, "mlockall"),
    (152, "munlockall"),
    (153, "vhangup"),
    (154, "modify_ldt"),
    (155, "pivot_root"),
    (156, "_sysctl"),
    (157, "prctl"),
    (158, "arch_prctl"),
    (159, "adjtimex"),
    (160, "setrlimit"),
    (161, "chroot"),
    (162, "sync"),
    (163, "acct"),
    (164, "settimeofday"),
    (165, "mount"),
    (166, "umount2"),
    (167, "swapon"),
    (168, "swapoff"),
    (169, "reboot"),
    (170, "sethostname"),
    (171, "setdomainname"),
    (172, "iopl"),
    (173, "ioperm"),
    (174, "create_module"),
    (175, "init_module"),
    (176, "delete_module"),
    (177, "get_kernel_syms"),
    (178, "query_module"),
    (179, "quotactl"),
    (180, "nfsservctl"),
    (181, "getpmsg"),
    (182, "putpmsg"),
    (183, "afs_syscall"),
    (184, "tuxcall"),
    (185, "security"),
    (186, "gettid"),
    (187, "readahead"),
    (188, "setxattr"),
    (189, "lsetxattr"),
    (190, "fsetxattr"),
    (191, "getxattr"),
    (192, "lgetxattr"),
    (193, "fgetxattr"),
    (194, "listxattr"),
    (195, "llistxattr"),
    (196, "flistxattr"),
    (197, "removexattr"),
    (198, "lremovexattr"),
    (199, "fremovexattr"),
    (200, "tkill"),
    (201, "time"),
    (202, "futex"),
    (203, "sched_setaffinity"),
    (204, "sched_getaffinity"),
    (205, "set_thread_area"),
    (206, "io_setup"),
    (207, "io_destroy"),
    (208, "io_getevents"),
    (209, "io_submit"),
    (210, "io_cancel"),
    (211, "get_thread_area"),
    (212, "lookup_dcookie"),
    (213, "epoll_create"),
    (214, "epoll_ctl_old"),
    (215, "epoll_wait_old"),
    (216, "remap_file_pages"),
    (217, "getdents64"),
    (218, "set_tid_address"),
    (219, "restart_syscall"),
    (220, "semtimedop"),
    (221, "fadvise64"),
    (222, "timer_create"),
    (223, "timer_settime"),
    (224, "timer_gettime"),
    (225, "timer_getoverrun"),
    (226, "timer_delete"),
    (227, "clock_settime"),
    (228, "clock_gettime"),
    (229, "clock_getres"),
    (230, "clock_nanosleep"),
    (231, "exit_group"),
    (232, "epoll_wait"),
    (233, "epoll_ctl"),
    (234, "tgkill"),
    (235, "utimes"),
    (236, "vserver"),
    (237, "mbind"),
    (238, "set_mempolicy"),
    (239, "get_mempolicy"),
    (240, "mq_open"),
    (241, "mq_unlink"),
    (242, "mq_timedsend"),
    (243, "mq_timedreceive"),
    (244, "mq_notify"),
    (245, "mq_getsetattr"),
    (246, "kexec_load"),
    (247, "waitid"),
    (248, "add_key"),
    (249, "request_key"),
    (250, "keyctl"),
    (251, "ioprio_set"),
    (252, "ioprio_get"),
    (253, "inotify_init"),
    (254, "inotify_add_watch"),
    (255, "inotify_rm_watch"),
    (256, "migrate_pages"),
    (257, "openat"),
    (258, "mkdirat"),
    (259, "mknodat"),
    (260, "fchownat"),
    (261, "futimesat"),
    (262, "newfstatat"),
    (263, "unlinkat"),
    (264, "renameat"),
    (265, "linkat"),
    (266, "symlinkat"),
    (267, "readlinkat"),
    (268, "fchmodat"),
    (269, "faccessat"),
    (270, "pselect6"),
    (271, "ppoll"),
    (272, "unshare"),
    (273, "set_robust_list"),
    (274, "get_robust_list"),
    (275, "splice"),
    (276, "tee"),
    (277, "sync_file_range"),
    (278, "vmsplice"),
    (279, "move_pages"),
    (280, "utimensat"),
    (281, "epoll_pwait"),
    (282, "signalfd"),
    (283, "timerfd_create"),
    (284, "eventfd"),
    (285, "fallocate"),
    (286, "timerfd_settime"),
    (287, "timerfd_gettime"),
    (288, "accept4"),
    (289, "signalfd4"),
    (290, "eventfd2"),
    (291, "epoll_create1"),
    (292, "dup3"),
    (293, "pipe2"),
    (294, "inotify_init1"),
    (295, "preadv"),
    (296, "pwritev"),
    (297, "rt_tgsigqueueinfo"),
    (298, "perf_event_open"),
    (299, "recvmmsg"),
    (300, "fanotify_init"),
    (301, "fanotify_mark"),
    (302, "prlimit64"),
    (303, "name_to_handle_at"),
    (304, "open_by_handle_at"),
    (305, "clock_adjtime"),
    (306, "syncfs"),
    (307, "sendmmsg"),
    (308, "setns"),
    (309, "getcpu"),
    (310, "process_vm_readv"),
    (311, "process_vm_writev"),
    (312, "kcmp"),
    (313, "finit_module"),
    (314, "sched_setattr"),
    (315, "sched_getattr"),
    (316, "renameat2"),
    (317, "seccomp"),
    (318, "getrandom"),
    (319, "memfd_create"),
    (320, "kexec_file_load"),
    (321, "bpf"),
    (322, "execveat"),
    (323, "userfaultfd"),
    (324, "membarrier"),
    (325, "mlock2"),
    (326, "copy_file_range"),
    (327, "preadv2"),
    (328, "pwritev2"),
    (329, "pkey_mprotect"),
];

/// Linux `AArch64` syscall table: (number, name) for the most common entries.
static LINUX_ARM64_ENTRIES: &[(u64, &str)] = &[
    (0, "io_setup"),
    (1, "io_destroy"),
    (2, "io_submit"),
    (3, "io_cancel"),
    (4, "io_getevents"),
    (5, "setxattr"),
    (6, "lsetxattr"),
    (7, "fsetxattr"),
    (8, "getxattr"),
    (9, "lgetxattr"),
    (10, "fgetxattr"),
    (11, "listxattr"),
    (12, "llistxattr"),
    (13, "flistxattr"),
    (14, "removexattr"),
    (15, "lremovexattr"),
    (16, "fremovexattr"),
    (17, "getcwd"),
    (18, "lookup_dcookie"),
    (19, "eventfd2"),
    (20, "epoll_create1"),
    (21, "epoll_ctl"),
    (22, "epoll_pwait"),
    (23, "dup"),
    (24, "dup3"),
    (25, "fcntl"),
    (26, "inotify_init1"),
    (27, "inotify_add_watch"),
    (28, "inotify_rm_watch"),
    (29, "ioctl"),
    (30, "ioprio_set"),
    (31, "ioprio_get"),
    (32, "flock"),
    (33, "mknodat"),
    (34, "mkdirat"),
    (35, "unlinkat"),
    (36, "symlinkat"),
    (37, "linkat"),
    (38, "renameat"),
    (39, "umount2"),
    (40, "mount"),
    (41, "pivot_root"),
    (42, "nfsservctl"),
    (43, "statfs"),
    (44, "fstatfs"),
    (45, "truncate"),
    (46, "ftruncate"),
    (47, "fallocate"),
    (48, "faccessat"),
    (49, "chdir"),
    (50, "fchdir"),
    (51, "chroot"),
    (52, "fchmod"),
    (53, "fchmodat"),
    (54, "fchownat"),
    (55, "fchown"),
    (56, "openat"),
    (57, "close"),
    (58, "vhangup"),
    (59, "pipe2"),
    (60, "quotactl"),
    (61, "getdents64"),
    (62, "lseek"),
    (63, "read"),
    (64, "write"),
    (65, "readv"),
    (66, "writev"),
    (67, "pread64"),
    (68, "pwrite64"),
    (69, "preadv"),
    (70, "pwritev"),
    (71, "sendfile"),
    (72, "pselect6"),
    (73, "ppoll"),
    (74, "signalfd4"),
    (75, "vmsplice"),
    (76, "splice"),
    (77, "tee"),
    (78, "readlinkat"),
    (79, "newfstatat"),
    (80, "fstat"),
    (81, "sync"),
    (82, "fsync"),
    (83, "fdatasync"),
    (84, "sync_file_range"),
    (85, "timerfd_create"),
    (86, "timerfd_settime"),
    (87, "timerfd_gettime"),
    (88, "utimensat"),
    (89, "acct"),
    (90, "capget"),
    (91, "capset"),
    (92, "personality"),
    (93, "exit"),
    (94, "exit_group"),
    (95, "waitid"),
    (96, "set_tid_address"),
    (97, "unshare"),
    (98, "futex"),
    (99, "set_robust_list"),
    (100, "get_robust_list"),
    (101, "nanosleep"),
    (102, "getitimer"),
    (103, "setitimer"),
    (104, "kexec_load"),
    (105, "init_module"),
    (106, "delete_module"),
    (107, "timer_create"),
    (108, "timer_gettime"),
    (109, "timer_getoverrun"),
    (110, "timer_settime"),
    (111, "timer_delete"),
    (112, "clock_settime"),
    (113, "clock_gettime"),
    (114, "clock_getres"),
    (115, "clock_nanosleep"),
    (116, "syslog"),
    (117, "ptrace"),
    (118, "sched_setparam"),
    (119, "sched_setscheduler"),
    (120, "sched_getscheduler"),
    (121, "sched_getparam"),
    (122, "sched_setaffinity"),
    (123, "sched_getaffinity"),
    (124, "sched_yield"),
    (125, "sched_get_priority_max"),
    (126, "sched_get_priority_min"),
    (127, "sched_rr_get_interval"),
    (128, "restart_syscall"),
    (129, "kill"),
    (130, "tkill"),
    (131, "tgkill"),
    (132, "sigaltstack"),
    (133, "rt_sigsuspend"),
    (134, "rt_sigaction"),
    (135, "rt_sigprocmask"),
    (136, "rt_sigpending"),
    (137, "rt_sigtimedwait"),
    (138, "rt_sigqueueinfo"),
    (139, "rt_sigreturn"),
    (140, "setpriority"),
    (141, "getpriority"),
    (142, "reboot"),
    (143, "setregid"),
    (144, "setgid"),
    (145, "setreuid"),
    (146, "setuid"),
    (147, "setresuid"),
    (148, "getresuid"),
    (149, "setresgid"),
    (150, "getresgid"),
    (151, "setfsuid"),
    (152, "setfsgid"),
    (153, "times"),
    (154, "setpgid"),
    (155, "getpgid"),
    (156, "getsid"),
    (157, "setsid"),
    (158, "getgroups"),
    (159, "setgroups"),
    (160, "uname"),
    (161, "sethostname"),
    (162, "setdomainname"),
    (163, "getrlimit"),
    (164, "setrlimit"),
    (165, "getrusage"),
    (166, "umask"),
    (167, "prctl"),
    (168, "getcpu"),
    (169, "gettimeofday"),
    (170, "settimeofday"),
    (171, "adjtimex"),
    (172, "getpid"),
    (173, "getppid"),
    (174, "getuid"),
    (175, "geteuid"),
    (176, "getgid"),
    (177, "getegid"),
    (178, "gettid"),
    (179, "sysinfo"),
    (180, "mq_open"),
    (181, "mq_unlink"),
    (182, "mq_timedsend"),
    (183, "mq_timedreceive"),
    (184, "mq_notify"),
    (185, "mq_getsetattr"),
    (186, "msgget"),
    (187, "msgctl"),
    (188, "msgrcv"),
    (189, "msgsnd"),
    (190, "semget"),
    (191, "semctl"),
    (192, "semtimedop"),
    (193, "semop"),
    (194, "shmget"),
    (195, "shmctl"),
    (196, "shmat"),
    (197, "shmdt"),
    (198, "socket"),
    (199, "socketpair"),
    (200, "bind"),
    (201, "listen"),
    (202, "accept"),
    (203, "connect"),
    (204, "getsockname"),
    (205, "getpeername"),
    (206, "sendto"),
    (207, "recvfrom"),
    (208, "setsockopt"),
    (209, "getsockopt"),
    (210, "shutdown"),
    (211, "sendmsg"),
    (212, "recvmsg"),
    (213, "readahead"),
    (214, "brk"),
    (215, "munmap"),
    (216, "mremap"),
    (217, "add_key"),
    (218, "request_key"),
    (219, "keyctl"),
    (220, "clone"),
    (221, "execve"),
    (222, "mmap"),
    (223, "fadvise64"),
    (224, "swapon"),
    (225, "swapoff"),
    (226, "mprotect"),
    (227, "msync"),
    (228, "mlock"),
    (229, "munlock"),
    (230, "mlockall"),
    (231, "munlockall"),
    (232, "mincore"),
    (233, "madvise"),
    (234, "remap_file_pages"),
    (235, "mbind"),
    (236, "get_mempolicy"),
    (237, "set_mempolicy"),
    (238, "migrate_pages"),
    (239, "move_pages"),
    (240, "rt_tgsigqueueinfo"),
    (241, "perf_event_open"),
    (242, "accept4"),
    (243, "recvmmsg"),
    (260, "wait4"),
    (261, "prlimit64"),
    (262, "fanotify_init"),
    (263, "fanotify_mark"),
    (264, "name_to_handle_at"),
    (265, "open_by_handle_at"),
    (266, "clock_adjtime"),
    (267, "syncfs"),
    (268, "setns"),
    (269, "sendmmsg"),
    (270, "process_vm_readv"),
    (271, "process_vm_writev"),
    (272, "kcmp"),
    (273, "finit_module"),
    (274, "sched_setattr"),
    (275, "sched_getattr"),
    (276, "renameat2"),
    (277, "seccomp"),
    (278, "getrandom"),
    (279, "memfd_create"),
    (280, "bpf"),
    (281, "execveat"),
    (282, "userfaultfd"),
    (283, "membarrier"),
    (284, "mlock2"),
    (285, "copy_file_range"),
    (286, "preadv2"),
    (287, "pwritev2"),
    (288, "pkey_mprotect"),
    (291, "statx"),
];

/// Windows x64 NT syscall table: (number, name) for the most common entries.
static WINDOWS_X64_ENTRIES: &[(u64, &str)] = &[
    (0x0000, "NtReadFile"),
    (0x0001, "NtWriteFile"),
    (0x0002, "NtClose"),
    (0x0003, "NtQueryInformationProcess"),
    (0x0004, "NtQueryInformationThread"),
    (0x0005, "NtSetInformationProcess"),
    (0x0006, "NtSetInformationThread"),
    (0x0007, "NtTerminateProcess"),
    (0x0008, "NtTerminateThread"),
    (0x0009, "NtSuspendThread"),
    (0x000A, "NtResumeThread"),
    (0x000B, "NtOpenProcess"),
    (0x000C, "NtOpenThread"),
    (0x000D, "NtCreateThread"),
    (0x000E, "NtCreateThreadEx"),
    (0x000F, "NtAllocateVirtualMemory"),
    (0x0010, "NtFreeVirtualMemory"),
    (0x0011, "NtProtectVirtualMemory"),
    (0x0012, "NtReadVirtualMemory"),
    (0x0013, "NtWriteVirtualMemory"),
    (0x0014, "NtQueryVirtualMemory"),
    (0x0015, "NtCreateSection"),
    (0x0016, "NtOpenSection"),
    (0x0017, "NtMapViewOfSection"),
    (0x0018, "NtUnmapViewOfSection"),
    (0x0019, "NtCreateFile"),
    (0x001A, "NtOpenFile"),
    (0x001B, "NtQueryInformationFile"),
    (0x001C, "NtSetInformationFile"),
    (0x001D, "NtQueryDirectoryFile"),
    (0x001E, "NtFlushBuffersFile"),
    (0x001F, "NtDeleteFile"),
    (0x0020, "NtWaitForSingleObject"),
    (0x0021, "NtWaitForMultipleObjects"),
    (0x0022, "NtCreateEvent"),
    (0x0023, "NtOpenEvent"),
    (0x0024, "NtSetEvent"),
    (0x0025, "NtResetEvent"),
    (0x0026, "NtQueryEvent"),
    (0x0027, "NtCreateMutant"),
    (0x0028, "NtReleaseMutant"),
    (0x0029, "NtCreateSemaphore"),
    (0x002A, "NtReleaseSemaphore"),
    (0x002B, "NtCreateKey"),
    (0x002C, "NtOpenKey"),
    (0x002D, "NtQueryKey"),
    (0x002E, "NtSetValueKey"),
    (0x002F, "NtQueryValueKey"),
    (0x0030, "NtDeleteKey"),
    (0x0031, "NtDeleteValueKey"),
    (0x0032, "NtEnumerateKey"),
    (0x0033, "NtEnumerateValueKey"),
    (0x0034, "NtQuerySystemInformation"),
    (0x0035, "NtSetSystemInformation"),
    (0x0036, "NtQuerySystemTime"),
    (0x0037, "NtRaiseHardError"),
    (0x0038, "NtRaiseException"),
    (0x0039, "NtContinue"),
    (0x003A, "NtGetContextThread"),
    (0x003B, "NtSetContextThread"),
    (0x003C, "NtDuplicateObject"),
    (0x003D, "NtOpenKeyEx"),
    (0x003E, "NtCreateKeyTransacted"),
    (0x003F, "NtOpenKeyTransacted"),
    (0x0040, "NtQueryInformationToken"),
    (0x0041, "NtOpenProcessToken"),
    (0x0042, "NtOpenThreadToken"),
    (0x0043, "NtAdjustPrivilegesToken"),
    (0x0044, "NtQueryObject"),
    (0x0045, "NtSetInformationObject"),
    (0x0046, "NtQuerySymbolicLinkObject"),
    (0x0047, "NtOpenSymbolicLinkObject"),
    (0x0048, "NtCreateSymbolicLinkObject"),
    (0x0049, "NtQueryDirectoryObject"),
    (0x004A, "NtOpenDirectoryObject"),
    (0x004B, "NtCreateDirectoryObject"),
    (0x004C, "NtQuerySecurityObject"),
    (0x004D, "NtSetSecurityObject"),
    (0x004E, "NtImpersonateClientOfPort"),
    (0x004F, "NtConnectPort"),
    (0x0050, "NtCreatePort"),
    (0x0051, "NtListenPort"),
    (0x0052, "NtAcceptConnectPort"),
    (0x0053, "NtCompleteConnectPort"),
    (0x0054, "NtRequestPort"),
    (0x0055, "NtRequestWaitReplyPort"),
    (0x0056, "NtReplyPort"),
    (0x0057, "NtReplyWaitReplyPort"),
    (0x0058, "NtReplyWaitReceivePort"),
    (0x0059, "NtQueryInformationJobObject"),
    (0x005A, "NtSetInformationJobObject"),
    (0x005B, "NtCreateTimer"),
    (0x005C, "NtOpenTimer"),
    (0x005D, "NtSetTimer"),
    (0x005E, "NtCancelTimer"),
    (0x005F, "NtQueryTimer"),
    (0x0060, "NtCreateIoCompletion"),
    (0x0061, "NtOpenIoCompletion"),
    (0x0062, "NtSetIoCompletion"),
    (0x0063, "NtRemoveIoCompletion"),
    (0x0064, "NtQueryIoCompletion"),
    (0x0065, "NtCreateProcessEx"),
    (0x0066, "NtCreateUserProcess"),
    (0x0067, "NtDebugActiveProcess"),
    (0x0068, "NtDebugContinue"),
    (0x0069, "NtWaitForDebugEvent"),
    (0x006A, "NtCreateDebugObject"),
    (0x006B, "NtRemoveProcessDebug"),
    (0x006C, "NtQueryDebugFilterState"),
    (0x006D, "NtSetDebugFilterState"),
    (0x006E, "NtSystemDebugControl"),
    (0x006F, "NtQueryPerformanceCounter"),
    (0x0070, "NtQueueApcThread"),
    (0x0071, "NtQueueApcThreadEx"),
    (0x0072, "NtTestAlert"),
    (0x0073, "NtAlertThread"),
    (0x0074, "NtAlertResumeThread"),
    (0x0075, "NtSuspendProcess"),
    (0x0076, "NtResumeProcess"),
    (0x0077, "NtGetCurrentProcessorNumber"),
    (0x0078, "NtFlushInstructionCache"),
    (0x0079, "NtFlushWriteBuffer"),
    (0x007A, "NtPulseEvent"),
    (0x007B, "NtQueryDefaultLocale"),
    (0x007C, "NtSetDefaultLocale"),
    (0x007D, "NtQueryDefaultUILanguage"),
    (0x007E, "NtSetDefaultUILanguage"),
    (0x007F, "NtQueryInstallUILanguage"),
    (0x0080, "NtDeleteAtom"),
    (0x0081, "NtFindAtom"),
    (0x0082, "NtAddAtom"),
    (0x0083, "NtQueryInformationAtom"),
    (0x0084, "NtSetTimerResolution"),
    (0x0085, "NtQueryTimerResolution"),
];

/// Sentinel returned by `SyscallTable::number_to_name` when the number is unknown.
pub const UNKNOWN_SYSCALL: &str = "unknown";

// ─── SyscallTable ─────────────────────────────────────────────────────────────

/// A flat, fixed-size array-backed lookup table mapping syscall number → name.
/// Optimised for architectures with dense numbering (Linux, Windows).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallTable {
    pub os: OsFamily,
    pub arch: SyscallArch,
    /// Entries sorted by number.
    entries: Vec<SyscallTableEntry>,
    max_number: u64,
}

/// A single entry in a [`SyscallTable`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallTableEntry {
    pub number: u64,
    pub name: std::string::String,
    pub category: SyscallCategory,
    pub risk: RiskLevel,
    pub param_count: usize,
}

impl SyscallTable {
    /// Build a `SyscallTable` from a database for the given OS/arch.
    #[must_use]
    pub fn from_database(db: &SyscallDatabase, os: OsFamily, arch: SyscallArch) -> Self {
        let mut entries: Vec<SyscallTableEntry> = db
            .all_for(os, arch)
            .into_iter()
            .map(|sc| SyscallTableEntry {
                number: sc.number,
                name: sc.name.clone(),
                category: sc.category,
                risk: sc.risk,
                param_count: sc.args.len(),
            })
            .collect();
        entries.sort_by_key(|e| e.number);
        let max_number = entries.last().map_or(0, |e| e.number);
        Self {
            os,
            arch,
            entries,
            max_number,
        }
    }

    /// Look up an entry by syscall number (binary search).
    #[must_use]
    pub fn lookup(&self, number: u64) -> Option<&SyscallTableEntry> {
        self.entries
            .binary_search_by_key(&number, |e| e.number)
            .ok()
            .map(|idx| &self.entries[idx])
    }

    /// Look up an entry by name.
    #[must_use]
    pub fn lookup_by_name(&self, name: &str) -> Option<&SyscallTableEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Return all entries.
    #[must_use]
    pub fn entries(&self) -> &[SyscallTableEntry] {
        &self.entries
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the table has no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The highest syscall number in the table.
    #[must_use]
    pub const fn max_number(&self) -> u64 {
        self.max_number
    }

    /// Return entries in a given category.
    #[must_use]
    pub fn by_category(&self, cat: SyscallCategory) -> Vec<&SyscallTableEntry> {
        self.entries.iter().filter(|e| e.category == cat).collect()
    }

    /// Return entries at or above `min_risk`.
    #[must_use]
    pub fn by_risk(&self, min_risk: RiskLevel) -> Vec<&SyscallTableEntry> {
        self.entries.iter().filter(|e| e.risk >= min_risk).collect()
    }

    /// Export the table as a simple TSV string.
    #[must_use]
    pub fn to_tsv(&self) -> std::string::String {
        let mut out = "number\tname\tcategory\trisk\tparams\n".to_string();
        for e in &self.entries {
            writeln!(
                out,
                "{}\t{}\t{}\t{}\t{}",
                e.number, e.name, e.category, e.risk, e.param_count
            )
            .ok();
        }
        out
    }

    // ── Static lookup API ─────────────────────────────────────────────────────

    /// Return the syscall name for a number on the given architecture string.
    ///
    /// `arch` accepts `"x86_64"`, `"arm64"`, `"windows_x64"` (case-insensitive).
    /// Returns [`UNKNOWN_SYSCALL`] when the number is not found.
    #[must_use]
    pub fn number_to_name(n: u64, arch: &str) -> &'static str {
        let table: &[(u64, &str)] = match arch.to_lowercase().as_str() {
            "x86_64" | "linux_x86_64" => LINUX_X86_64_ENTRIES,
            "arm64" | "aarch64" | "linux_arm64" => LINUX_ARM64_ENTRIES,
            "windows_x64" | "win_x64" | "x64" => WINDOWS_X64_ENTRIES,
            _ => return UNKNOWN_SYSCALL,
        };
        // The static tables are sorted by number so binary search is valid.
        table
            .binary_search_by_key(&n, |&(num, _)| num)
            .map_or(UNKNOWN_SYSCALL, |idx| table[idx].1)
    }

    /// Return the syscall number for a name on the given architecture string.
    ///
    /// `arch` accepts `"x86_64"`, `"arm64"`, `"windows_x64"` (case-insensitive).
    /// Returns `None` when the name is not found.
    #[must_use]
    pub fn name_to_number(name: &str, arch: &str) -> Option<u64> {
        let table: &[(u64, &str)] = match arch.to_lowercase().as_str() {
            "x86_64" | "linux_x86_64" => LINUX_X86_64_ENTRIES,
            "arm64" | "aarch64" | "linux_arm64" => LINUX_ARM64_ENTRIES,
            "windows_x64" | "win_x64" | "x64" => WINDOWS_X64_ENTRIES,
            _ => return None,
        };
        table.iter().find(|&&(_, n)| n == name).map(|&(num, _)| num)
    }

    // ── Factory constructors ──────────────────────────────────────────────────

    /// Build a `SyscallTable` pre-populated with the Linux x86-64 syscall table
    /// (330 entries covering NR 0–329).
    #[must_use]
    pub fn linux_x86_64() -> Self {
        Self::from_static(OsFamily::Linux, SyscallArch::X86_64, LINUX_X86_64_ENTRIES)
    }

    /// Build a `SyscallTable` pre-populated with the Linux `AArch64` syscall table.
    #[must_use]
    pub fn linux_arm64() -> Self {
        Self::from_static(OsFamily::Linux, SyscallArch::Arm64, LINUX_ARM64_ENTRIES)
    }

    /// Build a `SyscallTable` pre-populated with the Windows x64 NT syscall table.
    #[must_use]
    pub fn windows_x64() -> Self {
        Self::from_static(OsFamily::Windows, SyscallArch::X86_64, WINDOWS_X64_ENTRIES)
    }

    /// Internal helper: build a `SyscallTable` from a static `(number, name)` slice.
    fn from_static(os: OsFamily, arch: SyscallArch, data: &[(u64, &str)]) -> Self {
        let cat = match os {
            OsFamily::Windows => SyscallCategory::System,
            _ => SyscallCategory::Unknown,
        };
        let mut entries: Vec<SyscallTableEntry> = data
            .iter()
            .map(|&(number, name)| SyscallTableEntry {
                number,
                name: name.to_string(),
                category: cat,
                risk: RiskLevel::Low,
                param_count: 0,
            })
            .collect();
        entries.sort_by_key(|e| e.number);
        let max_number = entries.last().map_or(0, |e| e.number);
        Self {
            os,
            arch,
            entries,
            max_number,
        }
    }
}

// ─── Syscall trace ────────────────────────────────────────────────────────────

/// An ordered sequence of recorded syscall calls forming a trace.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SyscallTrace {
    calls: Vec<SyscallCall>,
    base_ts: Option<u64>,
}

impl SyscallTrace {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a call to the trace.
    pub fn push(&mut self, call: SyscallCall) {
        if self.base_ts.is_none() {
            self.base_ts = Some(call.timestamp);
        }
        self.calls.push(call);
    }

    /// Return all recorded calls.
    #[must_use]
    pub fn calls(&self) -> &[SyscallCall] {
        &self.calls
    }

    /// Return the number of recorded calls.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.calls.len()
    }

    /// Return `true` if the trace has no calls.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.calls.is_empty()
    }

    /// Filter the trace using a predicate, returning a new trace.
    #[must_use]
    pub fn filter<F>(&self, pred: F) -> Self
    where
        F: Fn(&SyscallCall) -> bool,
    {
        let calls: Vec<SyscallCall> = self.calls.iter().filter(|c| pred(c)).cloned().collect();
        Self {
            calls,
            base_ts: self.base_ts,
        }
    }

    /// Apply a [`SyscallFilter`] to produce a new trace.
    #[must_use]
    pub fn apply_filter(&self, filter: &SyscallFilter) -> Self {
        self.filter(|c| filter.matches(c))
    }

    /// Return per-syscall call counts.
    #[must_use]
    pub fn call_counts(&self) -> HashMap<std::string::String, usize> {
        let mut map: HashMap<std::string::String, usize> = HashMap::new();
        for c in &self.calls {
            *map.entry(c.syscall.name.clone()).or_default() += 1;
        }
        map
    }

    /// Return counts grouped by category.
    #[must_use]
    pub fn category_counts(&self) -> HashMap<SyscallCategory, usize> {
        let mut map: HashMap<SyscallCategory, usize> = HashMap::new();
        for c in &self.calls {
            *map.entry(c.syscall.category).or_default() += 1;
        }
        map
    }

    /// Return the top-N most frequently called syscalls.
    #[must_use]
    pub fn top_calls(&self, n: usize) -> Vec<(std::string::String, usize)> {
        let counts = self.call_counts();
        let mut v: Vec<(std::string::String, usize)> = counts.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    /// Return error calls (ret < 0).
    #[must_use]
    pub fn error_calls(&self) -> Vec<&SyscallCall> {
        self.calls.iter().filter(|c| c.is_error()).collect()
    }

    /// Return calls for a specific PID.
    #[must_use]
    pub fn for_pid(&self, pid: u32) -> Vec<&SyscallCall> {
        self.calls.iter().filter(|c| c.pid == pid).collect()
    }

    /// Error rate as a fraction [0.0, 1.0].
    #[must_use]
    pub fn error_rate(&self) -> f64 {
        if self.calls.is_empty() {
            return 0.0;
        }
        usize_to_f64(self.error_calls().len()) / usize_to_f64(self.calls.len())
    }

    /// Compute the time span of the trace in nanoseconds.
    #[must_use]
    pub fn duration_ns(&self) -> u64 {
        let first = self.calls.first().map_or(0, |c| c.timestamp);
        let last = self.calls.last().map_or(0, |c| c.timestamp);
        last.saturating_sub(first)
    }

    /// Compute per-PID call counts.
    #[must_use]
    pub fn per_pid_counts(&self) -> HashMap<u32, usize> {
        let mut map: HashMap<u32, usize> = HashMap::new();
        for c in &self.calls {
            *map.entry(c.pid).or_default() += 1;
        }
        map
    }

    /// Find all unique PIDs in the trace.
    #[must_use]
    pub fn unique_pids(&self) -> Vec<u32> {
        let mut pids: Vec<u32> = self
            .calls
            .iter()
            .map(|c| c.pid)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        pids.sort_unstable();
        pids
    }

    /// Render a human-readable summary of the trace.
    #[must_use]
    pub fn summary(&self) -> std::string::String {
        let counts = self.call_counts();
        let mut top: Vec<(std::string::String, usize)> = counts.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1));
        top.truncate(10);
        let mut out = format!(
            "Trace: {} calls, {} unique, error_rate={:.1}%\n",
            self.calls.len(),
            top.len(),
            self.error_rate() * 100.0
        );
        for (name, count) in &top {
            writeln!(out, "  {name:30} {count}").ok();
        }
        out
    }

    /// Split the trace by PID into per-process sub-traces.
    #[must_use]
    pub fn split_by_pid(&self) -> HashMap<u32, Self> {
        let mut map: HashMap<u32, Self> = HashMap::new();
        for call in &self.calls {
            map.entry(call.pid).or_default().push(call.clone());
        }
        map
    }
}

// ─── Syscall filter ───────────────────────────────────────────────────────────

/// Predicate-based filter for [`SyscallCall`] streams.
#[derive(Debug, Default, Clone)]
pub struct SyscallFilter {
    pub categories: Vec<SyscallCategory>,
    pub name_patterns: Vec<std::string::String>,
    /// `(arg_index, range)` – keeps calls where the named arg falls within range.
    pub arg_ranges: Vec<(usize, RangeInclusive<u64>)>,
    pub pid_filter: Option<u32>,
    pub tid_filter: Option<u32>,
    /// Minimum risk level to include.
    pub min_risk: Option<RiskLevel>,
    /// If `true`, only include error calls.
    pub errors_only: bool,
    /// Exclude calls whose name matches any of these exact names.
    pub name_excludes: Vec<std::string::String>,
}

impl SyscallFilter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_category(mut self, cat: SyscallCategory) -> Self {
        self.categories.push(cat);
        self
    }

    #[must_use]
    pub fn with_name_pattern(mut self, pattern: impl Into<std::string::String>) -> Self {
        self.name_patterns.push(pattern.into());
        self
    }

    #[must_use]
    pub fn with_name_exclude(mut self, name: impl Into<std::string::String>) -> Self {
        self.name_excludes.push(name.into());
        self
    }

    #[must_use]
    pub fn with_arg_range(mut self, arg_idx: usize, range: RangeInclusive<u64>) -> Self {
        self.arg_ranges.push((arg_idx, range));
        self
    }

    #[must_use]
    pub const fn with_pid(mut self, pid: u32) -> Self {
        self.pid_filter = Some(pid);
        self
    }

    #[must_use]
    pub const fn with_tid(mut self, tid: u32) -> Self {
        self.tid_filter = Some(tid);
        self
    }

    #[must_use]
    pub const fn with_min_risk(mut self, risk: RiskLevel) -> Self {
        self.min_risk = Some(risk);
        self
    }

    #[must_use]
    pub const fn errors_only(mut self) -> Self {
        self.errors_only = true;
        self
    }

    /// Returns `true` if the call passes all active filter predicates.
    #[must_use]
    pub fn matches(&self, call: &SyscallCall) -> bool {
        if !self.categories.is_empty() && !self.categories.contains(&call.syscall.category) {
            return false;
        }

        if !self.name_patterns.is_empty() {
            let name = &call.syscall.name;
            let matched = self
                .name_patterns
                .iter()
                .any(|pat| name.contains(pat.as_str()));
            if !matched {
                return false;
            }
        }

        if !self.name_excludes.is_empty() {
            let name = &call.syscall.name;
            if self.name_excludes.iter().any(|ex| ex == name) {
                return false;
            }
        }

        for (idx, range) in &self.arg_ranges {
            if let Some(v) = call.args.get(*idx)
                && !range.contains(v)
            {
                return false;
            }
        }

        if let Some(pid) = self.pid_filter
            && call.pid != pid
        {
            return false;
        }

        if let Some(tid) = self.tid_filter
            && call.tid != tid
        {
            return false;
        }

        if let Some(min_risk) = self.min_risk
            && call.syscall.risk < min_risk
        {
            return false;
        }

        if self.errors_only && !call.is_error() {
            return false;
        }

        true
    }
}

// ─── Syscall formatter ────────────────────────────────────────────────────────

/// Which call prefix (if any) is rendered before the syscall name.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum CallPrefix {
    /// No prefix.
    #[default]
    None,
    /// Print the pid/tid prefix like strace -f.
    Pid,
    /// Print the timestamp prefix.
    Timestamp,
    /// Print both pid and timestamp prefixes.
    Both,
}

impl CallPrefix {
    #[must_use]
    pub const fn show_pid(self) -> bool {
        matches!(self, Self::Pid | Self::Both)
    }

    #[must_use]
    pub const fn show_timestamp(self) -> bool {
        matches!(self, Self::Timestamp | Self::Both)
    }
}

/// Formats a [`SyscallCall`] in strace-style:
/// `open("/etc/passwd", O_RDONLY) = 3`
#[derive(Debug, Default, Clone)]
pub struct SyscallFormatter {
    /// Which prefix to print before the syscall name.
    pub prefix: CallPrefix,
    /// When true, decode argument values using type info.
    pub decode_args: bool,
    /// When true, show the syscall prototype as a comment.
    pub show_prototype: bool,
}

impl SyscallFormatter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_pid(mut self) -> Self {
        self.prefix = match self.prefix {
            CallPrefix::None | CallPrefix::Pid => CallPrefix::Pid,
            CallPrefix::Timestamp | CallPrefix::Both => CallPrefix::Both,
        };
        self
    }

    #[must_use]
    pub const fn with_timestamp(mut self) -> Self {
        self.prefix = match self.prefix {
            CallPrefix::None | CallPrefix::Timestamp => CallPrefix::Timestamp,
            CallPrefix::Pid | CallPrefix::Both => CallPrefix::Both,
        };
        self
    }

    #[must_use]
    pub const fn with_decode(mut self) -> Self {
        self.decode_args = true;
        self
    }

    #[must_use]
    pub const fn with_prototype(mut self) -> Self {
        self.show_prototype = true;
        self
    }

    /// Format a raw argument value using its declared type.
    #[must_use]
    pub fn format_arg(ty: &SyscallType, value: u64) -> std::string::String {
        decode_arg_value(ty, value).display
    }

    #[must_use]
    pub fn format(&self, call: &SyscallCall) -> std::string::String {
        let mut out = std::string::String::new();

        if self.prefix.show_timestamp() {
            write!(out, "{:>16} ", call.timestamp).ok();
        }
        if self.prefix.show_pid() {
            write!(out, "[pid {:>5}] ", call.pid).ok();
        }

        out.push_str(&call.syscall.name);
        out.push('(');

        let arg_strs: Vec<std::string::String> = if self.decode_args {
            call.decoded_args().into_iter().map(|d| d.display).collect()
        } else {
            call.syscall
                .args
                .iter()
                .enumerate()
                .map(|(i, arg)| {
                    let raw = call.args.get(i).copied().unwrap_or(0);
                    Self::format_arg(&arg.ty, raw)
                })
                .collect()
        };

        out.push_str(&arg_strs.join(", "));
        out.push(')');

        let ret_str = if call.ret < 0 {
            let neg = -call.ret;
            let en = u32::try_from(neg).ok().and_then(errno_name).unwrap_or("?");
            format!("-1 /* errno {neg} ({en}) */")
        } else {
            format!("{}", call.ret)
        };
        write!(out, " = {ret_str}").ok();

        if self.show_prototype {
            write!(out, " /* {} */", call.syscall.prototype()).ok();
        }

        out
    }

    /// Format a full trace, one call per line.
    #[must_use]
    pub fn format_trace(&self, trace: &SyscallTrace) -> std::string::String {
        trace
            .calls()
            .iter()
            .map(|c| self.format(c))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ─── Seccomp BPF analysis ─────────────────────────────────────────────────────

/// Action taken by a seccomp BPF rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeccompAction {
    Allow,
    Kill,
    Trap,
    Errno(u16),
    Trace(u16),
    Log,
}

impl fmt::Display for SeccompAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "ALLOW"),
            Self::Kill => write!(f, "KILL"),
            Self::Trap => write!(f, "TRAP"),
            Self::Errno(e) => write!(f, "ERRNO({e})"),
            Self::Trace(t) => write!(f, "TRACE({t})"),
            Self::Log => write!(f, "LOG"),
        }
    }
}

/// A single seccomp filter rule matching a syscall number.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompRule {
    pub syscall_number: u32,
    pub action: SeccompAction,
    pub arch: SyscallArch,
    pub description: std::string::String,
}

impl SeccompRule {
    #[must_use]
    pub fn new(
        syscall_number: u32,
        action: SeccompAction,
        arch: SyscallArch,
        description: impl Into<std::string::String>,
    ) -> Self {
        Self {
            syscall_number,
            action,
            arch,
            description: description.into(),
        }
    }
}

/// A seccomp filter policy — a set of rules evaluated in order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompPolicy {
    pub rules: Vec<SeccompRule>,
    pub default_action: SeccompAction,
    pub name: std::string::String,
}

impl SeccompPolicy {
    #[must_use]
    pub fn new(name: impl Into<std::string::String>, default_action: SeccompAction) -> Self {
        Self {
            rules: Vec::new(),
            default_action,
            name: name.into(),
        }
    }

    /// Add a rule.
    pub fn add_rule(&mut self, rule: SeccompRule) {
        self.rules.push(rule);
    }

    /// Look up the effective action for a syscall number.
    #[must_use]
    pub fn evaluate(&self, syscall_number: u32, arch: SyscallArch) -> SeccompAction {
        for rule in &self.rules {
            if rule.syscall_number == syscall_number && rule.arch == arch {
                return rule.action;
            }
        }
        self.default_action
    }

    /// Return the list of syscall numbers that are allowed.
    #[must_use]
    pub fn allowed_syscalls(&self) -> Vec<u32> {
        self.rules
            .iter()
            .filter(|r| r.action == SeccompAction::Allow)
            .map(|r| r.syscall_number)
            .collect()
    }

    /// Return the list of syscall numbers that are denied.
    #[must_use]
    pub fn denied_syscalls(&self) -> Vec<u32> {
        self.rules
            .iter()
            .filter(|r| matches!(r.action, SeccompAction::Kill | SeccompAction::Errno(_)))
            .map(|r| r.syscall_number)
            .collect()
    }

    /// Check whether a call would pass through this policy.
    #[must_use]
    pub fn would_allow(&self, syscall_number: u32, arch: SyscallArch) -> bool {
        self.evaluate(syscall_number, arch) == SeccompAction::Allow
    }

    /// Count rules by action type.
    #[must_use]
    pub fn rule_counts(&self) -> HashMap<std::string::String, usize> {
        let mut map: HashMap<std::string::String, usize> = HashMap::new();
        for rule in &self.rules {
            *map.entry(rule.action.to_string()).or_default() += 1;
        }
        map
    }
}

// ─── Persistent store ─────────────────────────────────────────────────────────

/// Persist and query [`SyscallCall`] records to `SQLite` and/or `MySQL`.
pub struct SyscallStore {
    sqlite: Option<rusqlite::Connection>,
    mysql_pool: Option<std::sync::Arc<RwLock<mysql::Pool>>>,
}

impl SyscallStore {
    /// Open an SQLite-backed store at `path`.  Use `":memory:"` for in-process.
    ///
    /// # Errors
    /// Returns an error if the database cannot be opened or initialised.
    pub fn open_sqlite(path: &str) -> Result<Self, SyscallError> {
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS syscall_calls (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                number      INTEGER NOT NULL,
                name        TEXT    NOT NULL,
                os          TEXT    NOT NULL,
                arch        TEXT    NOT NULL,
                args_json   TEXT    NOT NULL,
                ret         INTEGER NOT NULL,
                timestamp   INTEGER NOT NULL,
                pid         INTEGER NOT NULL,
                tid         INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_calls_name ON syscall_calls(name);
            CREATE INDEX IF NOT EXISTS idx_calls_pid  ON syscall_calls(pid);
            CREATE INDEX IF NOT EXISTS idx_calls_ts   ON syscall_calls(timestamp);",
        )?;
        Ok(Self {
            sqlite: Some(conn),
            mysql_pool: None,
        })
    }

    /// Open a MySQL-backed store using the given DSN.
    ///
    /// # Errors
    /// Returns an error if the DSN is invalid or the connection pool cannot be created.
    pub fn open_mysql(dsn: &str) -> Result<Self, SyscallError> {
        let pool = mysql::Pool::new(dsn).map_err(|e| SyscallError::Mysql(e.to_string()))?;
        let mut conn = pool
            .get_conn()
            .map_err(|e| SyscallError::Mysql(e.to_string()))?;
        mysql::prelude::Queryable::query_drop(
            &mut conn,
            "CREATE TABLE IF NOT EXISTS syscall_calls (
                id          BIGINT AUTO_INCREMENT PRIMARY KEY,
                number      BIGINT UNSIGNED NOT NULL,
                name        VARCHAR(128)    NOT NULL,
                os          VARCHAR(32)     NOT NULL,
                arch        VARCHAR(32)     NOT NULL,
                args_json   TEXT            NOT NULL,
                ret         BIGINT          NOT NULL,
                timestamp   BIGINT UNSIGNED NOT NULL,
                pid         INT UNSIGNED    NOT NULL,
                tid         INT UNSIGNED    NOT NULL,
                INDEX idx_name (name),
                INDEX idx_pid  (pid),
                INDEX idx_ts   (timestamp)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        )
        .map_err(|e| SyscallError::Mysql(e.to_string()))?;
        Ok(Self {
            sqlite: None,
            mysql_pool: Some(std::sync::Arc::new(RwLock::new(pool))),
        })
    }

    /// Persist a call record.
    ///
    /// # Errors
    /// Returns an error if the insert fails.
    pub fn save(&self, call: &SyscallCall) -> Result<(), SyscallError> {
        let args_json = serde_json::to_string(&call.args)?;
        let os = call.syscall.os.to_string();
        let arch = call.syscall.arch.to_string();

        if let Some(conn) = &self.sqlite {
            conn.execute(
                "INSERT INTO syscall_calls
                 (number, name, os, arch, args_json, ret, timestamp, pid, tid)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    call.syscall.number,
                    call.syscall.name,
                    os,
                    arch,
                    args_json,
                    call.ret,
                    call.timestamp,
                    call.pid,
                    call.tid,
                ],
            )?;
        }

        if let Some(pool_lock) = &self.mysql_pool {
            let mut conn = pool_lock
                .read()
                .get_conn()
                .map_err(|e| SyscallError::Mysql(e.to_string()))?;
            mysql::prelude::Queryable::exec_drop(
                &mut conn,
                "INSERT INTO syscall_calls
                 (number, name, os, arch, args_json, ret, timestamp, pid, tid)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    call.syscall.number,
                    &call.syscall.name,
                    &os,
                    &arch,
                    &args_json,
                    call.ret,
                    call.timestamp,
                    call.pid,
                    call.tid,
                ),
            )
            .map_err(|e| SyscallError::Mysql(e.to_string()))?;
        }

        Ok(())
    }

    /// Persist a full trace.
    ///
    /// # Errors
    /// Returns an error if any insert fails.
    pub fn save_trace(&self, trace: &SyscallTrace) -> Result<(), SyscallError> {
        for call in trace.calls() {
            self.save(call)?;
        }
        Ok(())
    }

    /// Query all stored calls for a given pid.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn query_by_pid(&self, pid: u32) -> Result<Vec<StoredCallRow>, SyscallError> {
        if let Some(conn) = &self.sqlite {
            let mut stmt = conn.prepare(
                "SELECT id, number, name, os, arch, args_json, ret, timestamp, pid, tid
                 FROM syscall_calls WHERE pid = ?1 ORDER BY timestamp",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![pid], StoredCallRow::from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(rows);
        }
        Ok(vec![])
    }

    /// Query all stored calls whose name contains `pattern`.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn query_by_name(&self, pattern: &str) -> Result<Vec<StoredCallRow>, SyscallError> {
        if let Some(conn) = &self.sqlite {
            let like = format!("%{pattern}%");
            let mut stmt = conn.prepare(
                "SELECT id, number, name, os, arch, args_json, ret, timestamp, pid, tid
                 FROM syscall_calls WHERE name LIKE ?1 ORDER BY timestamp",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![like], StoredCallRow::from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(rows);
        }
        Ok(vec![])
    }

    /// Query all calls in a timestamp range.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn query_by_time_range(
        &self,
        start_ns: u64,
        end_ns: u64,
    ) -> Result<Vec<StoredCallRow>, SyscallError> {
        if let Some(conn) = &self.sqlite {
            let mut stmt = conn.prepare(
                "SELECT id, number, name, os, arch, args_json, ret, timestamp, pid, tid
                 FROM syscall_calls WHERE timestamp >= ?1 AND timestamp <= ?2
                 ORDER BY timestamp",
            )?;
            let rows = stmt
                .query_map(
                    rusqlite::params![start_ns.cast_signed(), end_ns.cast_signed()],
                    StoredCallRow::from_row,
                )?
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(rows);
        }
        Ok(vec![])
    }

    /// Count all stored rows.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn count(&self) -> Result<u64, SyscallError> {
        if let Some(conn) = &self.sqlite {
            let n: i64 = conn.query_row("SELECT COUNT(*) FROM syscall_calls", [], |r| r.get(0))?;
            return Ok(n.cast_unsigned());
        }
        Ok(0)
    }

    /// Delete all stored rows.
    ///
    /// # Errors
    /// Returns an error if the delete fails.
    pub fn clear(&self) -> Result<(), SyscallError> {
        if let Some(conn) = &self.sqlite {
            conn.execute("DELETE FROM syscall_calls", [])?;
        }
        Ok(())
    }
}

/// A raw row returned from the persistent store.
#[derive(Debug, Clone)]
pub struct StoredCallRow {
    pub id: i64,
    pub number: u64,
    pub name: std::string::String,
    pub os: std::string::String,
    pub arch: std::string::String,
    pub args_json: std::string::String,
    pub ret: i64,
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
}

impl StoredCallRow {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            number: row.get::<_, i64>(1)?.cast_unsigned(),
            name: row.get(2)?,
            os: row.get(3)?,
            arch: row.get(4)?,
            args_json: row.get(5)?,
            ret: row.get(6)?,
            timestamp: row.get::<_, i64>(7)?.cast_unsigned(),
            pid: u32::try_from(row.get::<_, i64>(8)?.cast_unsigned() & 0xFFFF_FFFF).unwrap_or(0),
            tid: u32::try_from(row.get::<_, i64>(9)?.cast_unsigned() & 0xFFFF_FFFF).unwrap_or(0),
        })
    }
}

// ─── Builder helpers ──────────────────────────────────────────────────────────

/// Convenience builder for quickly constructing `Syscall` entries.
pub struct SyscallBuilder {
    inner: Syscall,
}

impl SyscallBuilder {
    #[must_use]
    pub fn new(
        number: u64,
        name: impl Into<std::string::String>,
        os: OsFamily,
        arch: SyscallArch,
    ) -> Self {
        Self {
            inner: Syscall {
                number,
                name: name.into(),
                os,
                arch,
                args: Vec::new(),
                return_type: SyscallType::Long,
                category: SyscallCategory::Unknown,
                description: std::string::String::new(),
                risk: RiskLevel::Low,
                aliases: Vec::new(),
                deprecated: false,
            },
        }
    }

    #[must_use]
    pub fn arg(
        mut self,
        name: impl Into<std::string::String>,
        ty: SyscallType,
        dir: ArgDirection,
    ) -> Self {
        self.inner.args.push(SyscallArg::new(name, ty, dir));
        self
    }

    #[must_use]
    pub fn opt_arg(
        mut self,
        name: impl Into<std::string::String>,
        ty: SyscallType,
        dir: ArgDirection,
    ) -> Self {
        self.inner
            .args
            .push(SyscallArg::new(name, ty, dir).optional());
        self
    }

    #[must_use]
    pub fn returns(mut self, ty: SyscallType) -> Self {
        self.inner.return_type = ty;
        self
    }

    #[must_use]
    pub const fn category(mut self, cat: SyscallCategory) -> Self {
        self.inner.category = cat;
        self
    }

    #[must_use]
    pub fn description(mut self, desc: impl Into<std::string::String>) -> Self {
        self.inner.description = desc.into();
        self
    }

    #[must_use]
    pub const fn risk(mut self, risk: RiskLevel) -> Self {
        self.inner.risk = risk;
        self
    }

    #[must_use]
    pub fn alias(mut self, name: impl Into<std::string::String>) -> Self {
        self.inner.aliases.push(name.into());
        self
    }

    #[must_use]
    pub const fn deprecated(mut self) -> Self {
        self.inner.deprecated = true;
        self
    }

    #[must_use]
    pub fn build(self) -> Syscall {
        self.inner
    }
}

// ─── Categorization helpers ───────────────────────────────────────────────────

/// Heuristically categorize a syscall by name when no explicit category is set.
#[must_use]
pub fn categorize_by_name(name: &str) -> SyscallCategory {
    if name.contains("read")
        || name.contains("write")
        || name.contains("open")
        || name.contains("close")
        || name.contains("file")
        || name.contains("dir")
        || name.contains("stat")
        || name.contains("link")
        || name.contains("rename")
        || name.contains("mkdir")
        || name.contains("rmdir")
        || name.contains("unlink")
        || name.contains("truncate")
        || name.contains("fsync")
        || name.contains("seek")
        || name.contains("access")
        || name.contains("chown")
        || name.contains("chmod")
        || name.starts_with("vfs")
        || name.contains("fcntl")
        || name.contains("ioctl")
    {
        SyscallCategory::FileSystem
    } else if name.contains("mmap")
        || name.contains("mprotect")
        || name.contains("mlock")
        || name.contains("munmap")
        || name.contains("brk")
        || name.contains("madvise")
        || name.contains("msync")
        || name.contains("alloc")
        || name.contains("virtual")
        || name.contains("heap")
        || name.contains("mremap")
    {
        SyscallCategory::Memory
    } else if name.contains("fork")
        || name.contains("exec")
        || name.contains("exit")
        || name.contains("wait")
        || name.contains("clone")
        || name.contains("process")
        || name.contains("getpid")
        || name.contains("getppid")
        || name.contains("ptrace")
        || name.contains("prctl")
        || name.contains("setpgid")
        || name.contains("setsid")
    {
        SyscallCategory::Process
    } else if name.contains("thread")
        || name.contains("tgkill")
        || name.contains("gettid")
        || name.contains("futex")
        || name.contains("mutex")
        || name.contains("sched")
    {
        SyscallCategory::Thread
    } else {
        categorize_by_name_tail(name)
    }
}

fn categorize_by_name_tail(name: &str) -> SyscallCategory {
    if name.contains("socket")
        || name.contains("bind")
        || name.contains("connect")
        || name.contains("listen")
        || name.contains("accept")
        || name.contains("send")
        || name.contains("recv")
        || name.contains("sock")
        || name.contains("net")
        || name.contains("getsock")
        || name.contains("setsock")
        || name.contains("inet")
    {
        SyscallCategory::Network
    } else if name.contains("pipe")
        || name.contains("shm")
        || name.contains("mq")
        || name.contains("ipc")
        || name.contains("semaphore")
        || name.contains("semop")
        || name.contains("msgsnd")
        || name.contains("msgrcv")
        || name.contains("shmget")
        || name.contains("shmctl")
        || name.contains("shmdt")
    {
        SyscallCategory::Ipc
    } else if name.contains("signal")
        || name.contains("sigaction")
        || name.contains("sigprocmask")
        || name.contains("sigsuspend")
        || name.contains("sigpending")
        || name.contains("kill")
        || name.contains("sigqueue")
        || name.starts_with("rt_sig")
    {
        SyscallCategory::Signal
    } else if name.contains("time")
        || name.contains("clock")
        || name.contains("sleep")
        || name.contains("nanosleep")
        || name.contains("timer")
        || name.contains("alarm")
        || name.contains("setitimer")
        || name.contains("getitimer")
    {
        SyscallCategory::Time
    } else if name.contains("device")
        || name.contains("dev")
        || name.contains("tty")
        || name.contains("console")
        || name.contains("dma")
        || name.contains("pci")
    {
        SyscallCategory::Device
    } else if name.contains("cap")
        || name.contains("priv")
        || name.contains("uid")
        || name.contains("gid")
        || name.contains("setuid")
        || name.contains("setgid")
        || name.contains("getuid")
        || name.contains("getgid")
        || name.contains("cred")
        || name.contains("keyctl")
        || name.contains("seccomp")
        || name.contains("audit")
    {
        SyscallCategory::Security
    } else if name.contains("uname")
        || name.contains("sysinfo")
        || name.contains("reboot")
        || name.contains("mount")
        || name.contains("umount")
        || name.contains("syslog")
        || name.contains("kexec")
        || name.contains("swapon")
        || name.contains("swapoff")
        || name.contains("acct")
        || name.contains("quotactl")
        || name.contains("sync")
        || name.contains("personality")
        || name.contains("sysctl")
    {
        SyscallCategory::System
    } else {
        SyscallCategory::Unknown
    }
}

/// Estimate the risk level of a syscall by name and category.
#[must_use]
pub fn estimate_risk(name: &str, category: SyscallCategory) -> RiskLevel {
    // Critical — direct memory/code injection paths
    if name.contains("ptrace")
        || name.contains("process_vm")
        || name.contains("kexec")
        || name.contains("seccomp")
        || name.contains("keyctl")
    {
        return RiskLevel::Critical;
    }
    // High — execution, privilege, raw memory
    if name.contains("exec")
        || name.contains("mprotect")
        || name.contains("mmap")
        || name.contains("setuid")
        || name.contains("setgid")
        || name.contains("capset")
        || name.contains("mount")
        || name.contains("module")
        || name.contains("bpf")
        || name.contains("perf_event")
    {
        return RiskLevel::High;
    }
    // Medium
    match category {
        SyscallCategory::Network | SyscallCategory::Ipc | SyscallCategory::Device => {
            RiskLevel::Medium
        }
        SyscallCategory::Process | SyscallCategory::Thread => RiskLevel::Medium,
        _ => RiskLevel::Low,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_open_syscall() -> Syscall {
        SyscallBuilder::new(2, "open", OsFamily::Linux, SyscallArch::X86_64)
            .arg("pathname", SyscallType::String, ArgDirection::In)
            .arg("flags", SyscallType::Flags("int".into()), ArgDirection::In)
            .opt_arg("mode", SyscallType::Mode, ArgDirection::In)
            .returns(SyscallType::Fd)
            .category(SyscallCategory::FileSystem)
            .description("Open and possibly create a file")
            .risk(RiskLevel::Low)
            .build()
    }

    fn make_read_syscall() -> Syscall {
        SyscallBuilder::new(0, "read", OsFamily::Linux, SyscallArch::X86_64)
            .arg("fd", SyscallType::Fd, ArgDirection::In)
            .arg(
                "buf",
                SyscallType::Buffer { size_arg: Some(2) },
                ArgDirection::Out,
            )
            .arg("count", SyscallType::Size, ArgDirection::In)
            .returns(SyscallType::SSize)
            .category(SyscallCategory::FileSystem)
            .description("Read from a file descriptor")
            .build()
    }

    fn make_mprotect_syscall() -> Syscall {
        SyscallBuilder::new(10, "mprotect", OsFamily::Linux, SyscallArch::X86_64)
            .arg("addr", SyscallType::UserPtr, ArgDirection::In)
            .arg("len", SyscallType::Size, ArgDirection::In)
            .arg("prot", SyscallType::Flags("int".into()), ArgDirection::In)
            .returns(SyscallType::Long)
            .category(SyscallCategory::Memory)
            .risk(RiskLevel::High)
            .build()
    }

    fn make_db() -> SyscallDatabase {
        let mut db = SyscallDatabase::new();
        db.insert(make_open_syscall());
        db.insert(make_read_syscall());
        db.insert(make_mprotect_syscall());
        db
    }

    // ── Builder ───────────────────────────────────────────────────────────────
    #[test]
    fn test_syscall_builder_fields() {
        let s = make_open_syscall();
        assert_eq!(s.number, 2);
        assert_eq!(s.name, "open");
        assert_eq!(s.os, OsFamily::Linux);
        assert_eq!(s.arch, SyscallArch::X86_64);
        assert_eq!(s.args.len(), 3);
        assert_eq!(s.return_type, SyscallType::Fd);
        assert_eq!(s.category, SyscallCategory::FileSystem);
        assert!(!s.description.is_empty());
    }

    #[test]
    fn test_optional_arg_flag() {
        let s = make_open_syscall();
        assert!(!s.args[0].optional);
        assert!(s.args[2].optional);
    }

    #[test]
    fn test_risk_field() {
        let s = make_mprotect_syscall();
        assert_eq!(s.risk, RiskLevel::High);
    }

    #[test]
    fn test_builder_alias() {
        let s = SyscallBuilder::new(0, "read", OsFamily::Linux, SyscallArch::X86_64)
            .alias("read64")
            .build();
        assert!(s.aliases.contains(&"read64".to_string()));
    }

    #[test]
    fn test_builder_deprecated() {
        let s = SyscallBuilder::new(0, "old_syscall", OsFamily::Linux, SyscallArch::X86)
            .deprecated()
            .build();
        assert!(s.deprecated);
    }

    // ── Database ──────────────────────────────────────────────────────────────
    #[test]
    fn test_database_insert_and_lookup() {
        let db = make_db();
        let found = db.lookup(OsFamily::Linux, SyscallArch::X86_64, 2);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "open");
        let not_found = db.lookup(OsFamily::Linux, SyscallArch::X86_64, 999);
        assert!(not_found.is_none());
    }

    #[test]
    fn test_database_lookup_by_name() {
        let db = make_db();
        let found = db.lookup_by_name(OsFamily::Linux, SyscallArch::X86_64, "open");
        assert!(found.is_some());
        let not_found = db.lookup_by_name(OsFamily::Linux, SyscallArch::X86_64, "missing");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_database_all_for_sorted() {
        let db = make_db();
        let all = db.all_for(OsFamily::Linux, SyscallArch::X86_64);
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].number, 0); // read
        assert_eq!(all[1].number, 2); // open
    }

    #[test]
    fn test_database_is_empty() {
        let db = SyscallDatabase::new();
        assert!(db.is_empty());
    }

    #[test]
    fn test_database_merge() {
        let mut db1 = SyscallDatabase::new();
        db1.insert(make_open_syscall());
        let mut db2 = SyscallDatabase::new();
        db2.insert(make_read_syscall());
        db1.merge(db2);
        assert_eq!(db1.len(), 2);
    }

    #[test]
    fn test_database_all_for_category() {
        let db = make_db();
        let fs = db.all_for_category(
            OsFamily::Linux,
            SyscallArch::X86_64,
            SyscallCategory::FileSystem,
        );
        assert_eq!(fs.len(), 2);
    }

    #[test]
    fn test_database_high_risk() {
        let db = make_db();
        let high = db.high_risk(OsFamily::Linux, SyscallArch::X86_64, RiskLevel::High);
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].name, "mprotect");
    }

    #[test]
    fn test_database_stats() {
        let db = make_db();
        let stats = db.stats();
        assert_eq!(stats.total, 3);
    }

    // ── SyscallTable ──────────────────────────────────────────────────────────
    #[test]
    fn test_table_from_database() {
        let db = make_db();
        let table = SyscallTable::from_database(&db, OsFamily::Linux, SyscallArch::X86_64);
        assert_eq!(table.len(), 3);
        assert!(!table.is_empty());
    }

    #[test]
    fn test_table_lookup() {
        let db = make_db();
        let table = SyscallTable::from_database(&db, OsFamily::Linux, SyscallArch::X86_64);
        let entry = table.lookup(2).unwrap();
        assert_eq!(entry.name, "open");
    }

    #[test]
    fn test_table_lookup_by_name() {
        let db = make_db();
        let table = SyscallTable::from_database(&db, OsFamily::Linux, SyscallArch::X86_64);
        let entry = table.lookup_by_name("read").unwrap();
        assert_eq!(entry.number, 0);
    }

    #[test]
    fn test_table_by_risk() {
        let db = make_db();
        let table = SyscallTable::from_database(&db, OsFamily::Linux, SyscallArch::X86_64);
        let high = table.by_risk(RiskLevel::High);
        assert!(!high.is_empty());
    }

    #[test]
    fn test_table_max_number() {
        let db = make_db();
        let table = SyscallTable::from_database(&db, OsFamily::Linux, SyscallArch::X86_64);
        assert_eq!(table.max_number(), 10);
    }

    #[test]
    fn test_table_tsv_output() {
        let db = make_db();
        let table = SyscallTable::from_database(&db, OsFamily::Linux, SyscallArch::X86_64);
        let tsv = table.to_tsv();
        assert!(tsv.contains("number\tname"));
        assert!(tsv.contains("open"));
    }

    // ── SyscallTrace ──────────────────────────────────────────────────────────
    fn make_call(sc: Syscall, pid: u32, ret: i64, ts: u64) -> SyscallCall {
        SyscallCall::new(sc, vec![0x100, 0, 0], ret, ts, pid, pid)
    }

    #[test]
    fn test_trace_push_and_len() {
        let mut trace = SyscallTrace::new();
        trace.push(make_call(make_open_syscall(), 1, 3, 1000));
        assert_eq!(trace.len(), 1);
        assert!(!trace.is_empty());
    }

    #[test]
    fn test_trace_call_counts() {
        let mut trace = SyscallTrace::new();
        trace.push(make_call(make_open_syscall(), 1, 3, 1000));
        trace.push(make_call(make_open_syscall(), 1, 4, 2000));
        trace.push(make_call(make_read_syscall(), 1, 128, 3000));
        let counts = trace.call_counts();
        assert_eq!(counts["open"], 2);
        assert_eq!(counts["read"], 1);
    }

    #[test]
    fn test_trace_top_calls() {
        let mut trace = SyscallTrace::new();
        for _ in 0..5 {
            trace.push(make_call(make_open_syscall(), 1, 3, 0));
        }
        trace.push(make_call(make_read_syscall(), 1, 128, 0));
        let top = trace.top_calls(2);
        assert_eq!(top[0].0, "open");
        assert_eq!(top[0].1, 5);
    }

    #[test]
    fn test_trace_error_calls() {
        let mut trace = SyscallTrace::new();
        trace.push(make_call(make_open_syscall(), 1, 3, 0));
        trace.push(make_call(make_open_syscall(), 1, -2, 0));
        let errors = trace.error_calls();
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn test_trace_error_rate() {
        let mut trace = SyscallTrace::new();
        trace.push(make_call(make_open_syscall(), 1, 3, 0));
        trace.push(make_call(make_open_syscall(), 1, -2, 0));
        let rate = trace.error_rate();
        assert!((rate - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_trace_filter() {
        let mut trace = SyscallTrace::new();
        trace.push(make_call(make_open_syscall(), 1, 3, 0));
        trace.push(make_call(make_read_syscall(), 1, 100, 0));
        let filtered = trace.filter(|c| c.syscall.name == "open");
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_trace_apply_filter() {
        let mut trace = SyscallTrace::new();
        trace.push(make_call(make_open_syscall(), 1, 3, 0));
        trace.push(make_call(make_mprotect_syscall(), 2, 0, 0));
        let f = SyscallFilter::new().with_pid(1);
        let filtered = trace.apply_filter(&f);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_trace_unique_pids() {
        let mut trace = SyscallTrace::new();
        trace.push(make_call(make_open_syscall(), 10, 3, 0));
        trace.push(make_call(make_open_syscall(), 20, 3, 0));
        let pids = trace.unique_pids();
        assert_eq!(pids, vec![10, 20]);
    }

    #[test]
    fn test_trace_split_by_pid() {
        let mut trace = SyscallTrace::new();
        trace.push(make_call(make_open_syscall(), 1, 3, 0));
        trace.push(make_call(make_open_syscall(), 2, 3, 0));
        trace.push(make_call(make_read_syscall(), 1, 100, 0));
        let split = trace.split_by_pid();
        assert_eq!(split[&1].len(), 2);
        assert_eq!(split[&2].len(), 1);
    }

    #[test]
    fn test_trace_summary_not_empty() {
        let mut trace = SyscallTrace::new();
        trace.push(make_call(make_open_syscall(), 1, 3, 0));
        let s = trace.summary();
        assert!(s.contains("Trace"));
    }

    // ── SyscallFilter ─────────────────────────────────────────────────────────
    #[test]
    fn test_filter_default_matches_all() {
        let call = make_call(make_open_syscall(), 1, 3, 0);
        assert!(SyscallFilter::new().matches(&call));
    }

    #[test]
    fn test_filter_category() {
        let call = make_call(make_open_syscall(), 1, 3, 0);
        assert!(
            SyscallFilter::new()
                .with_category(SyscallCategory::FileSystem)
                .matches(&call)
        );
        assert!(
            !SyscallFilter::new()
                .with_category(SyscallCategory::Network)
                .matches(&call)
        );
    }

    #[test]
    fn test_filter_name_pattern() {
        let call = make_call(make_open_syscall(), 1, 3, 0);
        assert!(
            SyscallFilter::new()
                .with_name_pattern("open")
                .matches(&call)
        );
        assert!(
            !SyscallFilter::new()
                .with_name_pattern("write")
                .matches(&call)
        );
    }

    #[test]
    fn test_filter_name_exclude() {
        let call = make_call(make_open_syscall(), 1, 3, 0);
        assert!(
            !SyscallFilter::new()
                .with_name_exclude("open")
                .matches(&call)
        );
    }

    #[test]
    fn test_filter_pid() {
        let call = make_call(make_open_syscall(), 42, 3, 0);
        assert!(SyscallFilter::new().with_pid(42).matches(&call));
        assert!(!SyscallFilter::new().with_pid(99).matches(&call));
    }

    #[test]
    fn test_filter_errors_only() {
        let good = make_call(make_open_syscall(), 1, 3, 0);
        let bad = make_call(make_open_syscall(), 1, -2, 0);
        let f = SyscallFilter::new().errors_only();
        assert!(!f.matches(&good));
        assert!(f.matches(&bad));
    }

    #[test]
    fn test_filter_min_risk() {
        let high_call = make_call(make_mprotect_syscall(), 1, 0, 0);
        let low_call = make_call(make_open_syscall(), 1, 3, 0);
        let f = SyscallFilter::new().with_min_risk(RiskLevel::High);
        assert!(f.matches(&high_call));
        assert!(!f.matches(&low_call));
    }

    #[test]
    fn test_filter_multiple_categories() {
        let call = make_call(make_open_syscall(), 1, 3, 0);
        let f = SyscallFilter::new()
            .with_category(SyscallCategory::Network)
            .with_category(SyscallCategory::FileSystem);
        assert!(f.matches(&call));
    }

    // ── Formatter ─────────────────────────────────────────────────────────────
    #[test]
    fn test_formatter_basic() {
        let call = make_call(make_open_syscall(), 42, 3, 1000);
        let s = SyscallFormatter::new().format(&call);
        assert!(s.contains("open("));
        assert!(s.contains("= 3"));
    }

    #[test]
    fn test_formatter_error_return() {
        let call = make_call(make_open_syscall(), 42, -2, 1000);
        let s = SyscallFormatter::new().format(&call);
        assert!(s.contains("-1"));
        assert!(s.contains("errno"));
    }

    #[test]
    fn test_formatter_with_pid() {
        let call = make_call(make_open_syscall(), 1234, 3, 0);
        let s = SyscallFormatter::new().with_pid().format(&call);
        assert!(s.contains("1234"));
    }

    #[test]
    fn test_formatter_with_prototype() {
        let call = make_call(make_open_syscall(), 1, 3, 0);
        let s = SyscallFormatter::new().with_prototype().format(&call);
        assert!(s.contains("open("));
    }

    // ── Decode ────────────────────────────────────────────────────────────────
    #[test]
    fn test_decode_bool() {
        assert_eq!(decode_arg_value(&SyscallType::Bool, 0).display, "false");
        assert_eq!(decode_arg_value(&SyscallType::Bool, 1).display, "true");
    }

    #[test]
    fn test_decode_null_ptr() {
        let d = decode_arg_value(&SyscallType::Ptr, 0);
        assert_eq!(d.display, "NULL");
        assert!(d.is_null);
    }

    #[test]
    fn test_decode_fd_stdin() {
        assert!(
            decode_arg_value(&SyscallType::Fd, 0)
                .display
                .contains("stdin")
        );
    }

    #[test]
    fn test_decode_signal_sigkill() {
        assert!(
            decode_arg_value(&SyscallType::Signal, 9)
                .display
                .contains("SIGKILL")
        );
    }

    #[test]
    fn test_decode_clock_realtime() {
        assert!(
            decode_arg_value(&SyscallType::ClockId, 0)
                .display
                .contains("CLOCK_REALTIME")
        );
    }

    #[test]
    fn test_decode_mode_octal() {
        let d = decode_arg_value(&SyscallType::Mode, 0o644);
        assert!(d.display.starts_with("0o"));
    }

    #[test]
    fn test_decode_ip_addr() {
        // 127.0.0.1 in network byte order LE
        let raw = 0x0100_007f_u64; // little-endian bytes: 127, 0, 0, 1
        let d = decode_arg_value(&SyscallType::IpAddr, raw);
        assert!(d.display.contains('.'));
    }

    // ── Categorization / risk ─────────────────────────────────────────────────
    #[test]
    fn test_categorize_by_name_filesystem() {
        assert_eq!(categorize_by_name("open"), SyscallCategory::FileSystem);
        assert_eq!(categorize_by_name("read"), SyscallCategory::FileSystem);
    }

    #[test]
    fn test_categorize_by_name_network() {
        assert_eq!(categorize_by_name("socket"), SyscallCategory::Network);
        assert_eq!(categorize_by_name("connect"), SyscallCategory::Network);
    }

    #[test]
    fn test_categorize_by_name_memory() {
        assert_eq!(categorize_by_name("mmap"), SyscallCategory::Memory);
        assert_eq!(categorize_by_name("mprotect"), SyscallCategory::Memory);
    }

    #[test]
    fn test_estimate_risk_ptrace() {
        assert_eq!(
            estimate_risk("ptrace", SyscallCategory::Process),
            RiskLevel::Critical
        );
    }

    #[test]
    fn test_estimate_risk_mprotect() {
        assert_eq!(
            estimate_risk("mprotect", SyscallCategory::Memory),
            RiskLevel::High
        );
    }

    // ── Seccomp ───────────────────────────────────────────────────────────────
    #[test]
    fn test_seccomp_policy_evaluate() {
        let mut policy = SeccompPolicy::new("test", SeccompAction::Kill);
        policy.add_rule(SeccompRule::new(
            0,
            SeccompAction::Allow,
            SyscallArch::X86_64,
            "read",
        ));
        assert_eq!(
            policy.evaluate(0, SyscallArch::X86_64),
            SeccompAction::Allow
        );
        assert_eq!(
            policy.evaluate(99, SyscallArch::X86_64),
            SeccompAction::Kill
        );
    }

    #[test]
    fn test_seccomp_would_allow() {
        let mut policy = SeccompPolicy::new("test", SeccompAction::Kill);
        policy.add_rule(SeccompRule::new(
            1,
            SeccompAction::Allow,
            SyscallArch::X86_64,
            "write",
        ));
        assert!(policy.would_allow(1, SyscallArch::X86_64));
        assert!(!policy.would_allow(999, SyscallArch::X86_64));
    }

    #[test]
    fn test_seccomp_allowed_denied_lists() {
        let mut policy = SeccompPolicy::new("test", SeccompAction::Allow);
        policy.add_rule(SeccompRule::new(
            0,
            SeccompAction::Allow,
            SyscallArch::X86_64,
            "read",
        ));
        policy.add_rule(SeccompRule::new(
            62,
            SeccompAction::Kill,
            SyscallArch::X86_64,
            "kill",
        ));
        assert!(policy.allowed_syscalls().contains(&0));
        assert!(policy.denied_syscalls().contains(&62));
    }

    #[test]
    fn test_seccomp_action_display() {
        assert_eq!(SeccompAction::Allow.to_string(), "ALLOW");
        assert_eq!(SeccompAction::Kill.to_string(), "KILL");
        assert_eq!(SeccompAction::Errno(13).to_string(), "ERRNO(13)");
    }

    // ── Store ─────────────────────────────────────────────────────────────────
    #[test]
    fn test_store_sqlite_save_and_query() {
        let store = SyscallStore::open_sqlite(":memory:").unwrap();
        let call = make_call(make_open_syscall(), 99, 3, 1000);
        store.save(&call).unwrap();
        let rows = store.query_by_pid(99).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "open");
    }

    #[test]
    fn test_store_query_by_name() {
        let store = SyscallStore::open_sqlite(":memory:").unwrap();
        store
            .save(&make_call(make_open_syscall(), 1, 3, 1))
            .unwrap();
        store
            .save(&make_call(make_read_syscall(), 1, 128, 2))
            .unwrap();
        let rows = store.query_by_name("read").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "read");
    }

    #[test]
    fn test_store_save_trace() {
        let store = SyscallStore::open_sqlite(":memory:").unwrap();
        let mut trace = SyscallTrace::new();
        for i in 0u64..5 {
            trace.push(make_call(make_open_syscall(), 1, 3, i * 1000));
        }
        store.save_trace(&trace).unwrap();
        let rows = store.query_by_pid(1).unwrap();
        assert_eq!(rows.len(), 5);
    }

    #[test]
    fn test_store_count() {
        let store = SyscallStore::open_sqlite(":memory:").unwrap();
        store
            .save(&make_call(make_open_syscall(), 1, 3, 0))
            .unwrap();
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn test_store_clear() {
        let store = SyscallStore::open_sqlite(":memory:").unwrap();
        store
            .save(&make_call(make_open_syscall(), 1, 3, 0))
            .unwrap();
        store.clear().unwrap();
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn test_store_query_by_time_range() {
        let store = SyscallStore::open_sqlite(":memory:").unwrap();
        store
            .save(&make_call(make_open_syscall(), 1, 3, 1000))
            .unwrap();
        store
            .save(&make_call(make_open_syscall(), 1, 3, 5000))
            .unwrap();
        let rows = store.query_by_time_range(0, 2000).unwrap();
        assert_eq!(rows.len(), 1);
    }

    // ── Signal / errno helpers ────────────────────────────────────────────────
    #[test]
    fn test_signal_name() {
        assert_eq!(signal_name(9), Some("SIGKILL"));
        assert_eq!(signal_name(15), Some("SIGTERM"));
        assert!(signal_name(255).is_none());
    }

    #[test]
    fn test_errno_name() {
        assert_eq!(errno_name(2), Some("ENOENT"));
        assert_eq!(errno_name(13), Some("EACCES"));
        assert!(errno_name(0).is_none());
    }

    #[test]
    fn test_sa_family_name() {
        assert_eq!(sa_family_name(2), Some("AF_INET"));
        assert_eq!(sa_family_name(10), Some("AF_INET6"));
    }

    // ── Type display ──────────────────────────────────────────────────────────
    #[test]
    fn test_syscall_type_display() {
        assert_eq!(SyscallType::Void.to_string(), "void");
        assert_eq!(SyscallType::Ptr.to_string(), "void *");
        assert_eq!(SyscallType::String.to_string(), "const char *");
        assert_eq!(
            SyscallType::Struct("stat".into()).to_string(),
            "struct stat *"
        );
        assert_eq!(SyscallType::Mode.to_string(), "umode_t");
    }

    #[test]
    fn test_os_family_display() {
        assert_eq!(OsFamily::Linux.to_string(), "linux");
        assert_eq!(OsFamily::Windows.to_string(), "windows");
    }

    #[test]
    fn test_arch_display() {
        assert_eq!(SyscallArch::X86_64.to_string(), "x86_64");
        assert_eq!(SyscallArch::Arm64.to_string(), "arm64");
    }

    #[test]
    fn test_arg_direction_display() {
        assert_eq!(ArgDirection::In.to_string(), "in");
        assert_eq!(ArgDirection::Out.to_string(), "out");
        assert_eq!(ArgDirection::InOut.to_string(), "inout");
    }

    #[test]
    fn test_category_display() {
        assert_eq!(SyscallCategory::FileSystem.to_string(), "filesystem");
        assert_eq!(SyscallCategory::Memory.to_string(), "memory");
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::Medium > RiskLevel::Low);
        assert!(RiskLevel::Low > RiskLevel::Benign);
    }

    #[test]
    fn test_risk_level_display() {
        assert_eq!(RiskLevel::Critical.to_string(), "critical");
        assert_eq!(RiskLevel::Benign.to_string(), "benign");
    }

    // ── Syscall methods ───────────────────────────────────────────────────────
    #[test]
    fn test_syscall_prototype() {
        let s = make_open_syscall();
        let p = s.prototype();
        assert!(p.contains("open("));
        assert!(p.contains("pathname"));
    }

    #[test]
    fn test_syscall_has_output_args() {
        let read = make_read_syscall();
        assert!(read.has_output_args());
        let open = make_open_syscall();
        // open has no Out args
        assert!(!open.has_output_args());
    }

    #[test]
    fn test_syscall_input_arg_count() {
        let open = make_open_syscall();
        // all three args are In
        assert_eq!(open.input_arg_count(), 3);
    }

    #[test]
    fn test_syscall_call_is_error() {
        let good = make_call(make_open_syscall(), 1, 3, 0);
        let bad = make_call(make_open_syscall(), 1, -2, 0);
        assert!(!good.is_error());
        assert!(bad.is_error());
    }

    #[test]
    fn test_syscall_call_tag() {
        let mut call = make_call(make_open_syscall(), 1, 3, 0);
        call.tag("suspicious");
        assert!(call.tags.contains(&"suspicious".to_string()));
    }

    #[test]
    fn test_trace_category_counts() {
        let mut trace = SyscallTrace::new();
        trace.push(make_call(make_open_syscall(), 1, 3, 0));
        trace.push(make_call(make_mprotect_syscall(), 1, 0, 0));
        let counts = trace.category_counts();
        assert_eq!(counts[&SyscallCategory::FileSystem], 1);
        assert_eq!(counts[&SyscallCategory::Memory], 1);
    }

    #[test]
    fn test_trace_duration_ns() {
        let mut trace = SyscallTrace::new();
        trace.push(make_call(make_open_syscall(), 1, 3, 1_000_000));
        trace.push(make_call(make_open_syscall(), 1, 3, 3_000_000));
        assert_eq!(trace.duration_ns(), 2_000_000);
    }
}
