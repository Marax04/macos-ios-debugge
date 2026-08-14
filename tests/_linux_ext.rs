
// ─── ArgType enum (strace-style rich argument typing) ─────────────────────────

/// Rich argument type for strace-compatible syscall argument decoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArgType {
    Int,
    UInt,
    Long,
    Fd,
    Pid,
    Ptr { inner: Box<ArgType> },
    Buffer { size_arg: u8 },
    Str,
    Flags { flag_set: &'static str },
    Errno,
    Sockaddr,
    IovecArr,
    Mode,
    Off,
    Signal,
    Size,
    Addr,
    RawHex,
}

impl ArgType {
    #[must_use]
    pub fn c_name(&self) -> &'static str {
        match self {
            Self::Int        => "int",
            Self::UInt       => "unsigned int",
            Self::Long       => "long",
            Self::Fd         => "int /*fd*/",
            Self::Pid        => "pid_t",
            Self::Ptr { .. } => "void *",
            Self::Buffer{..} => "void * /*buf*/",
            Self::Str        => "const char *",
            Self::Flags{..}  => "unsigned long /*flags*/",
            Self::Errno      => "long /*errno*/",
            Self::Sockaddr   => "struct sockaddr *",
            Self::IovecArr   => "struct iovec *",
            Self::Mode       => "mode_t",
            Self::Off        => "off_t",
            Self::Signal     => "int /*signal*/",
            Self::Size       => "size_t",
            Self::Addr       => "unsigned long /*addr*/",
            Self::RawHex     => "unsigned long",
        }
    }
}

// ─── Flag bits ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FlagBit {
    pub value: u64,
    pub name: &'static str,
}

impl FlagBit {
    #[must_use]
    pub const fn new(value: u64, name: &'static str) -> Self {
        Self { value, name }
    }
}

#[must_use]
pub fn decode_flags(value: u64, bits: &[FlagBit]) -> String {
    if value == 0 {
        return "0".to_string();
    }
    let mut parts: Vec<&str> = Vec::new();
    let mut remaining = value;
    for bit in bits {
        if bit.value != 0 && (remaining & bit.value) == bit.value {
            parts.push(bit.name);
            remaining &= !bit.value;
        }
    }
    if remaining != 0 {
        parts.push("/* unknown */");
    }
    if parts.is_empty() {
        return "0".to_string();
    }
    parts.join("|")
}

#[must_use]
pub fn decode_flags_by_name(flag_set: &str, value: u64) -> String {
    match flag_set {
        "O_FLAGS"      => decode_flags(value, O_FLAGS),
        "PROT_FLAGS"   => decode_flags(value, PROT_FLAGS),
        "MAP_FLAGS"    => decode_flags(value, MAP_FLAGS),
        "CLONE_FLAGS"  => decode_flags(value, CLONE_FLAGS),
        "AT_FLAGS"     => decode_flags(value, AT_FLAGS),
        "EPOLL_EVENTS" => decode_flags(value, EPOLL_EVENTS),
        "SOCK_FLAGS"   => decode_flags(value, SOCK_FLAGS),
        "WAIT_FLAGS"   => decode_flags(value, WAIT_FLAGS),
        _              => format!("0x{value:x}"),
    }
}

pub static O_FLAGS: &[FlagBit] = &[
    FlagBit::new(0o0,       "O_RDONLY"),
    FlagBit::new(0o1,       "O_WRONLY"),
    FlagBit::new(0o2,       "O_RDWR"),
    FlagBit::new(0o100,     "O_CREAT"),
    FlagBit::new(0o200,     "O_EXCL"),
    FlagBit::new(0o400,     "O_NOCTTY"),
    FlagBit::new(0o1000,    "O_TRUNC"),
    FlagBit::new(0o2000,    "O_APPEND"),
    FlagBit::new(0o4000,    "O_NONBLOCK"),
    FlagBit::new(0o10000,   "O_DSYNC"),
    FlagBit::new(0o20000,   "O_ASYNC"),
    FlagBit::new(0o40000,   "O_DIRECT"),
    FlagBit::new(0o100000,  "O_LARGEFILE"),
    FlagBit::new(0o200000,  "O_DIRECTORY"),
    FlagBit::new(0o400000,  "O_NOFOLLOW"),
    FlagBit::new(0o1000000, "O_NOATIME"),
    FlagBit::new(0o2000000, "O_CLOEXEC"),
    FlagBit::new(0o4010000, "O_SYNC"),
    FlagBit::new(0o10000000,"O_PATH"),
];

pub static PROT_FLAGS: &[FlagBit] = &[
    FlagBit::new(0x0, "PROT_NONE"),
    FlagBit::new(0x1, "PROT_READ"),
    FlagBit::new(0x2, "PROT_WRITE"),
    FlagBit::new(0x4, "PROT_EXEC"),
    FlagBit::new(0x8, "PROT_SEM"),
];

pub static MAP_FLAGS: &[FlagBit] = &[
    FlagBit::new(0x01,    "MAP_SHARED"),
    FlagBit::new(0x02,    "MAP_PRIVATE"),
    FlagBit::new(0x10,    "MAP_FIXED"),
    FlagBit::new(0x20,    "MAP_ANONYMOUS"),
    FlagBit::new(0x40,    "MAP_32BIT"),
    FlagBit::new(0x100,   "MAP_GROWSDOWN"),
    FlagBit::new(0x800,   "MAP_DENYWRITE"),
    FlagBit::new(0x1000,  "MAP_EXECUTABLE"),
    FlagBit::new(0x2000,  "MAP_LOCKED"),
    FlagBit::new(0x4000,  "MAP_NORESERVE"),
    FlagBit::new(0x8000,  "MAP_POPULATE"),
    FlagBit::new(0x10000, "MAP_NONBLOCK"),
    FlagBit::new(0x20000, "MAP_STACK"),
    FlagBit::new(0x40000, "MAP_HUGETLB"),
    FlagBit::new(0x80000, "MAP_SYNC"),
    FlagBit::new(0x100000,"MAP_FIXED_NOREPLACE"),
];

pub static CLONE_FLAGS: &[FlagBit] = &[
    FlagBit::new(0x00000100, "CLONE_VM"),
    FlagBit::new(0x00000200, "CLONE_FS"),
    FlagBit::new(0x00000400, "CLONE_FILES"),
    FlagBit::new(0x00000800, "CLONE_SIGHAND"),
    FlagBit::new(0x00001000, "CLONE_PIDFD"),
    FlagBit::new(0x00002000, "CLONE_PTRACE"),
    FlagBit::new(0x00004000, "CLONE_VFORK"),
    FlagBit::new(0x00008000, "CLONE_PARENT"),
    FlagBit::new(0x00010000, "CLONE_THREAD"),
    FlagBit::new(0x00020000, "CLONE_NEWNS"),
    FlagBit::new(0x00040000, "CLONE_SYSVSEM"),
    FlagBit::new(0x00080000, "CLONE_SETTLS"),
    FlagBit::new(0x00100000, "CLONE_PARENT_SETTID"),
    FlagBit::new(0x00200000, "CLONE_CHILD_CLEARTID"),
    FlagBit::new(0x00400000, "CLONE_DETACHED"),
    FlagBit::new(0x00800000, "CLONE_UNTRACED"),
    FlagBit::new(0x01000000, "CLONE_CHILD_SETTID"),
    FlagBit::new(0x02000000, "CLONE_NEWCGROUP"),
    FlagBit::new(0x04000000, "CLONE_NEWUTS"),
    FlagBit::new(0x08000000, "CLONE_NEWIPC"),
    FlagBit::new(0x10000000, "CLONE_NEWUSER"),
    FlagBit::new(0x20000000, "CLONE_NEWPID"),
    FlagBit::new(0x40000000, "CLONE_NEWNET"),
    FlagBit::new(0x80000000, "CLONE_IO"),
];

pub static AT_FLAGS: &[FlagBit] = &[
    FlagBit::new(0x100,  "AT_SYMLINK_NOFOLLOW"),
    FlagBit::new(0x200,  "AT_REMOVEDIR"),
    FlagBit::new(0x400,  "AT_SYMLINK_FOLLOW"),
    FlagBit::new(0x800,  "AT_NO_AUTOMOUNT"),
    FlagBit::new(0x1000, "AT_EMPTY_PATH"),
];

pub static EPOLL_EVENTS: &[FlagBit] = &[
    FlagBit::new(0x001,       "EPOLLIN"),
    FlagBit::new(0x002,       "EPOLLPRI"),
    FlagBit::new(0x004,       "EPOLLOUT"),
    FlagBit::new(0x008,       "EPOLLERR"),
    FlagBit::new(0x010,       "EPOLLHUP"),
    FlagBit::new(0x020,       "EPOLLNVAL"),
    FlagBit::new(0x040,       "EPOLLRDNORM"),
    FlagBit::new(0x080,       "EPOLLRDBAND"),
    FlagBit::new(0x100,       "EPOLLWRNORM"),
    FlagBit::new(0x200,       "EPOLLWRBAND"),
    FlagBit::new(0x2000,      "EPOLLRDHUP"),
    FlagBit::new(0x10000000,  "EPOLLEXCLUSIVE"),
    FlagBit::new(0x20000000,  "EPOLLWAKEUP"),
    FlagBit::new(0x40000000,  "EPOLLONESHOT"),
    FlagBit::new(0x80000000,  "EPOLLET"),
];

pub static SOCK_FLAGS: &[FlagBit] = &[
    FlagBit::new(1,       "SOCK_STREAM"),
    FlagBit::new(2,       "SOCK_DGRAM"),
    FlagBit::new(3,       "SOCK_RAW"),
    FlagBit::new(4,       "SOCK_RDM"),
    FlagBit::new(5,       "SOCK_SEQPACKET"),
    FlagBit::new(10,      "SOCK_PACKET"),
    FlagBit::new(0x80000, "SOCK_CLOEXEC"),
    FlagBit::new(0x800,   "SOCK_NONBLOCK"),
];

pub static WAIT_FLAGS: &[FlagBit] = &[
    FlagBit::new(0x1,  "WNOHANG"),
    FlagBit::new(0x2,  "WUNTRACED"),
    FlagBit::new(0x4,  "WSTOPPED"),
    FlagBit::new(0x8,  "WCONTINUED"),
    FlagBit::new(0x10, "WNOWAIT"),
    FlagBit::new(0x01000000, "WNOTHREAD"),
    FlagBit::new(0x02000000, "WALL"),
    FlagBit::new(0x04000000, "WCLONE"),
];

// ─── Signal name table ────────────────────────────────────────────────────────

#[must_use]
pub fn signal_name(sig: u32) -> Option<&'static str> {
    match sig {
        1  => Some("SIGHUP"),
        2  => Some("SIGINT"),
        3  => Some("SIGQUIT"),
        4  => Some("SIGILL"),
        5  => Some("SIGTRAP"),
        6  => Some("SIGABRT"),
        7  => Some("SIGBUS"),
        8  => Some("SIGFPE"),
        9  => Some("SIGKILL"),
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
        34 => Some("SIGRTMIN"),
        64 => Some("SIGRTMAX"),
        _  => None,
    }
}

// ─── Sockaddr decoder ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecodedSockaddr {
    Inet  { addr: String, port: u16 },
    Inet6 { addr: String, port: u16, flow_info: u32, scope_id: u32 },
    Unix  { path: String },
    Netlink { pid: u32, groups: u32 },
    Raw   { family: u16, data: Vec<u8> },
}

impl std::fmt::Display for DecodedSockaddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inet { addr, port }         => write!(f, "{addr}:{port}"),
            Self::Inet6 { addr, port, .. }    => write!(f, "[{addr}]:{port}"),
            Self::Unix { path }               => write!(f, "{path:?}"),
            Self::Netlink { pid, groups }     => write!(f, "nl pid={pid} groups={groups}"),
            Self::Raw { family, data }        => write!(f, "sa_family={family} data={}", hex_dump_ext(data, 16)),
        }
    }
}

#[must_use]
pub fn hex_dump_ext(data: &[u8], max_bytes: usize) -> String {
    let n = data.len().min(max_bytes);
    let hex: Vec<String> = data[..n].iter().map(|b| format!("{b:02x}")).collect();
    let s = hex.join(" ");
    if data.len() > max_bytes {
        format!("{s} ... ({} more bytes)", data.len() - max_bytes)
    } else {
        s
    }
}

#[must_use]
pub fn decode_sockaddr(data: &[u8]) -> DecodedSockaddr {
    if data.len() < 2 {
        return DecodedSockaddr::Raw { family: 0, data: data.to_vec() };
    }
    let family = u16::from_le_bytes([data[0], data[1]]);
    match family {
        2 if data.len() >= 8 => {
            let port = u16::from_be_bytes([data[2], data[3]]);
            let addr = format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7]);
            DecodedSockaddr::Inet { addr, port }
        }
        10 if data.len() >= 28 => {
            let port = u16::from_be_bytes([data[2], data[3]]);
            let flow = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let scope = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);
            let words: Vec<String> = (0..8).map(|i| {
                let idx = 8 + i * 2;
                format!("{:x}", u16::from_be_bytes([data[idx], data[idx + 1]]))
            }).collect();
            DecodedSockaddr::Inet6 { addr: words.join(":"), port, flow_info: flow, scope_id: scope }
        }
        1 if data.len() >= 3 => {
            let raw = &data[2..];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            DecodedSockaddr::Unix { path: String::from_utf8_lossy(&raw[..end]).to_string() }
        }
        16 if data.len() >= 12 => {
            let pid    = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
            let groups = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
            DecodedSockaddr::Netlink { pid, groups }
        }
        _ => DecodedSockaddr::Raw { family, data: data.to_vec() },
    }
}

// ─── Decoded argument ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecodedArg {
    Int(i64),
    UInt(u64),
    Str(String),
    Addr(u64),
    Fd(i32, String),
    Flags(u64, String),
    Signal(u32, String),
    Sockaddr(DecodedSockaddr),
    Buffer(Vec<u8>),
    Errno(i64),
    Null,
    RawHex(u64),
}

impl std::fmt::Display for DecodedArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Int(v)        => write!(f, "{v}"),
            Self::UInt(v)       => write!(f, "{v}"),
            Self::Str(s)        => write!(f, "{s:?}"),
            Self::Addr(a)       => write!(f, "0x{a:x}"),
            Self::Fd(n, p)      => {
                if p.is_empty() { write!(f, "{n}") } else { write!(f, "{n}<{p}>") }
            }
            Self::Flags(_, s)   => write!(f, "{s}"),
            Self::Signal(n, s)  => write!(f, "{s}({n})"),
            Self::Sockaddr(sa)  => write!(f, "{{{sa}}}"),
            Self::Buffer(b)     => write!(f, "\"{}\"", hex_dump_ext(b, 64)),
            Self::Errno(e)      => {
                if *e < 0 { write!(f, "-1 /* errno={} */", -e) } else { write!(f, "{e}") }
            }
            Self::Null          => write!(f, "NULL"),
            Self::RawHex(v)     => write!(f, "0x{v:x}"),
        }
    }
}

// ─── SyscallEvent ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub nr: u64,
    pub name: String,
    pub args: Vec<DecodedArg>,
    pub retval: DecodedArg,
    pub elapsed_ns: u64,
    pub is_entry: bool,
}

impl std::fmt::Display for SyscallEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let args: Vec<String> = self.args.iter().map(|a| a.to_string()).collect();
        write!(f, "{}({}) = {}", self.name, args.join(", "), self.retval)
    }
}

impl SyscallEvent {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!("{},{},{},{},{},{}", self.timestamp_ns, self.pid, self.tid, self.name, self.retval, self.elapsed_ns)
    }
}

// ─── FD tracker ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdInfo {
    pub path: String,
    pub flags: u64,
    pub offset: i64,
    pub is_socket: bool,
    pub peer_addr: Option<DecodedSockaddr>,
    pub local_addr: Option<DecodedSockaddr>,
}

impl FdInfo {
    #[must_use]
    pub fn file(path: impl Into<String>, flags: u64) -> Self {
        Self { path: path.into(), flags, offset: 0, is_socket: false, peer_addr: None, local_addr: None }
    }
    #[must_use]
    pub fn socket(family: u16, sock_type: u16, protocol: u16) -> Self {
        Self {
            path: format!("socket:[{family}/{sock_type}/{protocol}]"),
            flags: 0, offset: 0, is_socket: true, peer_addr: None, local_addr: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FdTable {
    map: HashMap<i32, FdInfo>,
}

impl FdTable {
    pub fn insert(&mut self, fd: i32, info: FdInfo) { self.map.insert(fd, info); }
    pub fn remove(&mut self, fd: i32) -> Option<FdInfo> { self.map.remove(&fd) }
    #[must_use] pub fn get(&self, fd: i32) -> Option<&FdInfo> { self.map.get(&fd) }
    pub fn get_mut(&mut self, fd: i32) -> Option<&mut FdInfo> { self.map.get_mut(&fd) }
    pub fn dup(&mut self, src: i32, dst: i32) {
        if let Some(info) = self.map.get(&src).cloned() { self.map.insert(dst, info); }
    }
    #[must_use] pub fn all(&self) -> Vec<(i32, &FdInfo)> {
        let mut v: Vec<_> = self.map.iter().map(|(k, v)| (*k, v)).collect();
        v.sort_by_key(|(k, _)| *k);
        v
    }
    #[must_use] pub fn len(&self) -> usize { self.map.len() }
    #[must_use] pub fn is_empty(&self) -> bool { self.map.is_empty() }
}

// ─── Per-thread state machine ─────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreadSyscallState {
    pub in_syscall: Option<u64>,
    pub entry_ts: u64,
    pub entry_regs: [u64; 7],
    pub stopped: bool,
}

impl ThreadSyscallState {
    pub fn on_entry(&mut self, nr: u64, regs: [u64; 7], ts: u64) {
        self.in_syscall = Some(nr);
        self.entry_regs = regs;
        self.entry_ts   = ts;
        self.stopped    = true;
    }
    pub fn on_exit(&mut self, ts: u64) -> (Option<u64>, u64) {
        let nr      = self.in_syscall.take();
        let elapsed = ts.saturating_sub(self.entry_ts);
        self.stopped = false;
        (nr, elapsed)
    }
}

// ─── Output format ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat { Strace, Json, Csv }

// ─── PtraceOptions ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtraceOptions {
    pub tracee: String,
    pub args: Vec<String>,
    pub output_format: OutputFormat,
    pub show_timing: bool,
    pub show_summary: bool,
    pub include_filter: Vec<String>,
    pub exclude_filter: Vec<String>,
    pub max_string_len: usize,
    pub max_buffer_dump: usize,
    pub follow_forks: bool,
}

impl PtraceOptions {
    #[must_use]
    pub fn spawn(tracee: impl Into<String>) -> Self {
        Self {
            tracee: tracee.into(),
            args: vec![],
            output_format: OutputFormat::Strace,
            show_timing: false,
            show_summary: false,
            include_filter: vec![],
            exclude_filter: vec![],
            max_string_len: 256,
            max_buffer_dump: 64,
            follow_forks: true,
        }
    }
    #[must_use]
    pub fn include<I: IntoIterator<Item = impl Into<String>>>(mut self, names: I) -> Self {
        self.include_filter.extend(names.into_iter().map(Into::into));
        self
    }
    #[must_use]
    pub fn exclude<I: IntoIterator<Item = impl Into<String>>>(mut self, names: I) -> Self {
        self.exclude_filter.extend(names.into_iter().map(Into::into));
        self
    }
    #[must_use]
    pub fn passes_filter(&self, name: &str) -> bool {
        if !self.include_filter.is_empty() && !self.include_filter.iter().any(|f| f == name) {
            return false;
        }
        !self.exclude_filter.iter().any(|f| f == name)
    }
}

// ─── Summary statistics ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallSummaryEntry {
    pub name: String,
    pub count: u64,
    pub total_ns: u64,
    pub min_ns: u64,
    pub max_ns: u64,
    pub error_count: u64,
}

impl SyscallSummaryEntry {
    #[must_use]
    pub fn new(name: impl Into<String>, elapsed_ns: u64, is_error: bool) -> Self {
        Self { name: name.into(), count: 1, total_ns: elapsed_ns, min_ns: elapsed_ns, max_ns: elapsed_ns, error_count: if is_error { 1 } else { 0 } }
    }
    pub fn record(&mut self, elapsed_ns: u64, is_error: bool) {
        self.count += 1;
        self.total_ns += elapsed_ns;
        if elapsed_ns < self.min_ns { self.min_ns = elapsed_ns; }
        if elapsed_ns > self.max_ns { self.max_ns = elapsed_ns; }
        if is_error { self.error_count += 1; }
    }
    #[must_use] pub fn avg_ns(&self) -> u64 { if self.count == 0 { 0 } else { self.total_ns / self.count } }
    #[must_use] pub fn avg_us(&self) -> f64 { self.avg_ns() as f64 / 1000.0 }
    #[must_use] pub fn total_secs(&self) -> f64 { self.total_ns as f64 / 1_000_000_000.0 }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyscallSummary {
    pub entries: HashMap<String, SyscallSummaryEntry>,
}

impl SyscallSummary {
    pub fn record(&mut self, name: &str, elapsed_ns: u64, retval: i64) {
        let is_error = retval < 0;
        self.entries.entry(name.to_string())
            .and_modify(|e| e.record(elapsed_ns, is_error))
            .or_insert_with(|| SyscallSummaryEntry::new(name, elapsed_ns, is_error));
    }
    #[must_use]
    pub fn sorted_by_time(&self) -> Vec<&SyscallSummaryEntry> {
        let mut v: Vec<_> = self.entries.values().collect();
        v.sort_by(|a, b| b.total_ns.cmp(&a.total_ns));
        v
    }
    #[must_use]
    pub fn sorted_by_count(&self) -> Vec<&SyscallSummaryEntry> {
        let mut v: Vec<_> = self.entries.values().collect();
        v.sort_by(|a, b| b.count.cmp(&a.count));
        v
    }
    #[must_use] pub fn total_calls(&self) -> u64 { self.entries.values().map(|e| e.count).sum() }
    #[must_use] pub fn total_ns(&self) -> u64 { self.entries.values().map(|e| e.total_ns).sum() }
    #[must_use]
    pub fn format_table(&self) -> String {
        let mut out = String::new();
        out.push_str("% time     seconds  usecs/call     calls    errors syscall\n");
        out.push_str("------- ----------- ----------- --------- --------- ----------------\n");
        let total_ns = self.total_ns().max(1);
        for e in self.sorted_by_time() {
            let pct = 100.0 * e.total_ns as f64 / total_ns as f64;
            out.push_str(&format!("{pct:7.2} {:11.6} {:11} {:9} {:9} {}\n",
                e.total_secs(), e.avg_ns(), e.count, e.error_count, e.name));
        }
        out.push_str("------- ----------- ----------- --------- --------- ----------------\n");
        out.push_str(&format!("{:7.2} {:11.6} {:>11} {:9}           total\n",
            100.0, total_ns as f64 / 1_000_000_000.0, "", self.total_calls()));
        out
    }
}

// ─── FD resolver helpers ──────────────────────────────────────────────────────

pub const AT_FDCWD: i32 = -100;

#[must_use]
pub fn resolve_fd(pid: u32, fd: i32) -> String {
    if fd == AT_FDCWD { return "AT_FDCWD".to_string(); }
    if fd < 0 { return format!("<bad fd {fd}>"); }
    let path = format!("/proc/{pid}/fd/{fd}");
    std::fs::read_link(&path).map(|p| p.display().to_string()).unwrap_or_else(|_| format!("<fd {fd}>"))
}

#[must_use]
pub fn read_process_memory(pid: u32, addr: u64, max_len: usize) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::OpenOptions::new().read(true).open(format!("/proc/{pid}/mem")).ok()?;
    f.seek(SeekFrom::Start(addr)).ok()?;
    let mut buf = vec![0u8; max_len];
    let n = f.read(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

#[must_use]
pub fn read_cstring(pid: u32, addr: u64) -> Option<String> {
    let buf = read_process_memory(pid, addr, 256)?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8(buf[..end].to_vec()).ok()
}

// ─── Signal/exit formatting ───────────────────────────────────────────────────

#[must_use]
pub fn format_signal_delivery(sig: u32, si_code: i32, si_addr: u64) -> String {
    let name = signal_name(sig).unwrap_or("SIG?");
    let code_str = match (sig, si_code) {
        (11, 1) => "SEGV_MAPERR", (11, 2) => "SEGV_ACCERR",
        (7, 1)  => "BUS_ADRALN",  (7, 2)  => "BUS_ADRERR",
        (8, 1)  => "FPE_INTDIV",  (8, 2)  => "FPE_INTOVF",
        (4, 1)  => "ILL_ILLOPC",  _       => "SI_KERNEL",
    };
    format!("--- {name} {{si_signo={name}, si_code={code_str}, si_addr=0x{si_addr:x}}} ---")
}

#[must_use]
pub fn format_exit_event(pid: u32, code: i32, signal: Option<u32>) -> String {
    let _ = pid;
    match signal {
        Some(sig) => format!("+++ killed by {} +++", signal_name(sig).unwrap_or("SIG?")),
        None      => format!("+++ exited with {code} +++"),
    }
}

// ─── Complete x86_64 syscall table (451 entries, kernel 6.x) ──────────────────

#[derive(Debug, Clone, Copy)]
pub struct StaticSyscall {
    pub nr: u32,
    pub name: &'static str,
    pub argc: u8,
}

impl StaticSyscall {
    #[must_use]
    pub const fn new(nr: u32, name: &'static str, argc: u8) -> Self {
        Self { nr, name, argc }
    }
}

pub static X86_64_SYSCALLS: &[StaticSyscall] = &[
    StaticSyscall::new(0,"read",3), StaticSyscall::new(1,"write",3), StaticSyscall::new(2,"open",3),
    StaticSyscall::new(3,"close",1), StaticSyscall::new(4,"stat",2), StaticSyscall::new(5,"fstat",2),
    StaticSyscall::new(6,"lstat",2), StaticSyscall::new(7,"poll",3), StaticSyscall::new(8,"lseek",3),
    StaticSyscall::new(9,"mmap",6), StaticSyscall::new(10,"mprotect",3), StaticSyscall::new(11,"munmap",2),
    StaticSyscall::new(12,"brk",1), StaticSyscall::new(13,"rt_sigaction",4), StaticSyscall::new(14,"rt_sigprocmask",4),
    StaticSyscall::new(15,"rt_sigreturn",0), StaticSyscall::new(16,"ioctl",3), StaticSyscall::new(17,"pread64",4),
    StaticSyscall::new(18,"pwrite64",4), StaticSyscall::new(19,"readv",3), StaticSyscall::new(20,"writev",3),
    StaticSyscall::new(21,"access",2), StaticSyscall::new(22,"pipe",1), StaticSyscall::new(23,"select",5),
    StaticSyscall::new(24,"sched_yield",0), StaticSyscall::new(25,"mremap",5), StaticSyscall::new(26,"msync",3),
    StaticSyscall::new(27,"mincore",3), StaticSyscall::new(28,"madvise",3), StaticSyscall::new(29,"shmget",3),
    StaticSyscall::new(30,"shmat",3), StaticSyscall::new(31,"shmctl",3), StaticSyscall::new(32,"dup",1),
    StaticSyscall::new(33,"dup2",2), StaticSyscall::new(34,"pause",0), StaticSyscall::new(35,"nanosleep",2),
    StaticSyscall::new(36,"getitimer",2), StaticSyscall::new(37,"alarm",1), StaticSyscall::new(38,"setitimer",3),
    StaticSyscall::new(39,"getpid",0), StaticSyscall::new(40,"sendfile",4), StaticSyscall::new(41,"socket",3),
    StaticSyscall::new(42,"connect",3), StaticSyscall::new(43,"accept",3), StaticSyscall::new(44,"sendto",6),
    StaticSyscall::new(45,"recvfrom",6), StaticSyscall::new(46,"sendmsg",3), StaticSyscall::new(47,"recvmsg",3),
    StaticSyscall::new(48,"shutdown",2), StaticSyscall::new(49,"bind",3), StaticSyscall::new(50,"listen",2),
    StaticSyscall::new(51,"getsockname",3), StaticSyscall::new(52,"getpeername",3), StaticSyscall::new(53,"socketpair",4),
    StaticSyscall::new(54,"setsockopt",5), StaticSyscall::new(55,"getsockopt",5), StaticSyscall::new(56,"clone",5),
    StaticSyscall::new(57,"fork",0), StaticSyscall::new(58,"vfork",0), StaticSyscall::new(59,"execve",3),
    StaticSyscall::new(60,"exit",1), StaticSyscall::new(61,"wait4",4), StaticSyscall::new(62,"kill",2),
    StaticSyscall::new(63,"uname",1), StaticSyscall::new(64,"semget",3), StaticSyscall::new(65,"semop",3),
    StaticSyscall::new(66,"semctl",4), StaticSyscall::new(67,"shmdt",1), StaticSyscall::new(68,"msgget",2),
    StaticSyscall::new(69,"msgsnd",4), StaticSyscall::new(70,"msgrcv",5), StaticSyscall::new(71,"msgctl",3),
    StaticSyscall::new(72,"fcntl",3), StaticSyscall::new(73,"flock",2), StaticSyscall::new(74,"fsync",1),
    StaticSyscall::new(75,"fdatasync",1), StaticSyscall::new(76,"truncate",2), StaticSyscall::new(77,"ftruncate",2),
    StaticSyscall::new(78,"getdents",3), StaticSyscall::new(79,"getcwd",2), StaticSyscall::new(80,"chdir",1),
    StaticSyscall::new(81,"fchdir",1), StaticSyscall::new(82,"rename",2), StaticSyscall::new(83,"mkdir",2),
    StaticSyscall::new(84,"rmdir",1), StaticSyscall::new(85,"creat",2), StaticSyscall::new(86,"link",2),
    StaticSyscall::new(87,"unlink",1), StaticSyscall::new(88,"symlink",2), StaticSyscall::new(89,"readlink",3),
    StaticSyscall::new(90,"chmod",2), StaticSyscall::new(91,"fchmod",2), StaticSyscall::new(92,"chown",3),
    StaticSyscall::new(93,"fchown",3), StaticSyscall::new(94,"lchown",3), StaticSyscall::new(95,"umask",1),
    StaticSyscall::new(96,"gettimeofday",2), StaticSyscall::new(97,"getrlimit",2), StaticSyscall::new(98,"getrusage",2),
    StaticSyscall::new(99,"sysinfo",1), StaticSyscall::new(100,"times",1), StaticSyscall::new(101,"ptrace",4),
    StaticSyscall::new(102,"getuid",0), StaticSyscall::new(103,"syslog",3), StaticSyscall::new(104,"getgid",0),
    StaticSyscall::new(105,"setuid",1), StaticSyscall::new(106,"setgid",1), StaticSyscall::new(107,"geteuid",0),
    StaticSyscall::new(108,"getegid",0), StaticSyscall::new(109,"setpgid",2), StaticSyscall::new(110,"getppid",0),
    StaticSyscall::new(111,"getpgrp",0), StaticSyscall::new(112,"setsid",0), StaticSyscall::new(113,"setreuid",2),
    StaticSyscall::new(114,"setregid",2), StaticSyscall::new(115,"getgroups",2), StaticSyscall::new(116,"setgroups",2),
    StaticSyscall::new(117,"setresuid",3), StaticSyscall::new(118,"getresuid",3), StaticSyscall::new(119,"setresgid",3),
    StaticSyscall::new(120,"getresgid",3), StaticSyscall::new(121,"getpgid",1), StaticSyscall::new(122,"setfsuid",1),
    StaticSyscall::new(123,"setfsgid",1), StaticSyscall::new(124,"getsid",1), StaticSyscall::new(125,"capget",2),
    StaticSyscall::new(126,"capset",2), StaticSyscall::new(127,"rt_sigpending",2), StaticSyscall::new(128,"rt_sigtimedwait",4),
    StaticSyscall::new(129,"rt_sigqueueinfo",3), StaticSyscall::new(130,"rt_sigsuspend",2), StaticSyscall::new(131,"sigaltstack",2),
    StaticSyscall::new(132,"utime",2), StaticSyscall::new(133,"mknod",3), StaticSyscall::new(134,"uselib",1),
    StaticSyscall::new(135,"personality",1), StaticSyscall::new(136,"ustat",2), StaticSyscall::new(137,"statfs",2),
    StaticSyscall::new(138,"fstatfs",2), StaticSyscall::new(139,"sysfs",3), StaticSyscall::new(140,"getpriority",2),
    StaticSyscall::new(141,"setpriority",3), StaticSyscall::new(142,"sched_setparam",2), StaticSyscall::new(143,"sched_getparam",2),
    StaticSyscall::new(144,"sched_setscheduler",3), StaticSyscall::new(145,"sched_getscheduler",1),
    StaticSyscall::new(146,"sched_get_priority_max",1), StaticSyscall::new(147,"sched_get_priority_min",1),
    StaticSyscall::new(148,"sched_rr_get_interval",2), StaticSyscall::new(149,"mlock",2), StaticSyscall::new(150,"munlock",2),
    StaticSyscall::new(151,"mlockall",1), StaticSyscall::new(152,"munlockall",0), StaticSyscall::new(153,"vhangup",0),
    StaticSyscall::new(154,"modify_ldt",3), StaticSyscall::new(155,"pivot_root",2), StaticSyscall::new(156,"_sysctl",1),
    StaticSyscall::new(157,"prctl",5), StaticSyscall::new(158,"arch_prctl",2), StaticSyscall::new(159,"adjtimex",1),
    StaticSyscall::new(160,"setrlimit",2), StaticSyscall::new(161,"chroot",1), StaticSyscall::new(162,"sync",0),
    StaticSyscall::new(163,"acct",1), StaticSyscall::new(164,"settimeofday",2), StaticSyscall::new(165,"mount",5),
    StaticSyscall::new(166,"umount2",2), StaticSyscall::new(167,"swapon",2), StaticSyscall::new(168,"swapoff",1),
    StaticSyscall::new(169,"reboot",4), StaticSyscall::new(170,"sethostname",2), StaticSyscall::new(171,"setdomainname",2),
    StaticSyscall::new(172,"iopl",1), StaticSyscall::new(173,"ioperm",3), StaticSyscall::new(174,"create_module",2),
    StaticSyscall::new(175,"init_module",3), StaticSyscall::new(176,"delete_module",2), StaticSyscall::new(177,"get_kernel_syms",1),
    StaticSyscall::new(178,"query_module",5), StaticSyscall::new(179,"quotactl",4), StaticSyscall::new(180,"nfsservctl",3),
    StaticSyscall::new(181,"getpmsg",5), StaticSyscall::new(182,"putpmsg",5), StaticSyscall::new(183,"afs_syscall",5),
    StaticSyscall::new(184,"tuxcall",3), StaticSyscall::new(185,"security",3), StaticSyscall::new(186,"gettid",0),
    StaticSyscall::new(187,"readahead",3), StaticSyscall::new(188,"setxattr",5), StaticSyscall::new(189,"lsetxattr",5),
    StaticSyscall::new(190,"fsetxattr",5), StaticSyscall::new(191,"getxattr",4), StaticSyscall::new(192,"lgetxattr",4),
    StaticSyscall::new(193,"fgetxattr",4), StaticSyscall::new(194,"listxattr",3), StaticSyscall::new(195,"llistxattr",3),
    StaticSyscall::new(196,"flistxattr",3), StaticSyscall::new(197,"removexattr",2), StaticSyscall::new(198,"lremovexattr",2),
    StaticSyscall::new(199,"fremovexattr",2), StaticSyscall::new(200,"tkill",2), StaticSyscall::new(201,"time",1),
    StaticSyscall::new(202,"futex",6), StaticSyscall::new(203,"sched_setaffinity",3), StaticSyscall::new(204,"sched_getaffinity",3),
    StaticSyscall::new(205,"set_thread_area",1), StaticSyscall::new(206,"io_setup",2), StaticSyscall::new(207,"io_destroy",1),
    StaticSyscall::new(208,"io_getevents",5), StaticSyscall::new(209,"io_submit",3), StaticSyscall::new(210,"io_cancel",3),
    StaticSyscall::new(211,"get_thread_area",1), StaticSyscall::new(212,"lookup_dcookie",3), StaticSyscall::new(213,"epoll_create",1),
    StaticSyscall::new(214,"epoll_ctl_old",4), StaticSyscall::new(215,"epoll_wait_old",4), StaticSyscall::new(216,"remap_file_pages",5),
    StaticSyscall::new(217,"getdents64",3), StaticSyscall::new(218,"set_tid_address",1), StaticSyscall::new(219,"restart_syscall",0),
    StaticSyscall::new(220,"semtimedop",4), StaticSyscall::new(221,"fadvise64",4), StaticSyscall::new(222,"timer_create",3),
    StaticSyscall::new(223,"timer_settime",4), StaticSyscall::new(224,"timer_gettime",2), StaticSyscall::new(225,"timer_getoverrun",1),
    StaticSyscall::new(226,"timer_delete",1), StaticSyscall::new(227,"clock_settime",2), StaticSyscall::new(228,"clock_gettime",2),
    StaticSyscall::new(229,"clock_getres",2), StaticSyscall::new(230,"clock_nanosleep",4), StaticSyscall::new(231,"exit_group",1),
    StaticSyscall::new(232,"epoll_wait",4), StaticSyscall::new(233,"epoll_ctl",4), StaticSyscall::new(234,"tgkill",3),
    StaticSyscall::new(235,"utimes",2), StaticSyscall::new(236,"vserver",4), StaticSyscall::new(237,"mbind",6),
    StaticSyscall::new(238,"set_mempolicy",3), StaticSyscall::new(239,"get_mempolicy",5), StaticSyscall::new(240,"mq_open",4),
    StaticSyscall::new(241,"mq_unlink",1), StaticSyscall::new(242,"mq_timedsend",5), StaticSyscall::new(243,"mq_timedreceive",5),
    StaticSyscall::new(244,"mq_notify",2), StaticSyscall::new(245,"mq_getsetattr",3), StaticSyscall::new(246,"kexec_load",4),
    StaticSyscall::new(247,"waitid",5), StaticSyscall::new(248,"add_key",5), StaticSyscall::new(249,"request_key",4),
    StaticSyscall::new(250,"keyctl",5), StaticSyscall::new(251,"ioprio_set",3), StaticSyscall::new(252,"ioprio_get",2),
    StaticSyscall::new(253,"inotify_init",0), StaticSyscall::new(254,"inotify_add_watch",3), StaticSyscall::new(255,"inotify_rm_watch",2),
    StaticSyscall::new(256,"migrate_pages",4), StaticSyscall::new(257,"openat",4), StaticSyscall::new(258,"mkdirat",3),
    StaticSyscall::new(259,"mknodat",4), StaticSyscall::new(260,"fchownat",5), StaticSyscall::new(261,"futimesat",3),
    StaticSyscall::new(262,"newfstatat",4), StaticSyscall::new(263,"unlinkat",3), StaticSyscall::new(264,"renameat",4),
    StaticSyscall::new(265,"linkat",5), StaticSyscall::new(266,"symlinkat",3), StaticSyscall::new(267,"readlinkat",4),
    StaticSyscall::new(268,"fchmodat",4), StaticSyscall::new(269,"faccessat",3), StaticSyscall::new(270,"pselect6",6),
    StaticSyscall::new(271,"ppoll",5), StaticSyscall::new(272,"unshare",1), StaticSyscall::new(273,"set_robust_list",2),
    StaticSyscall::new(274,"get_robust_list",3), StaticSyscall::new(275,"splice",6), StaticSyscall::new(276,"tee",4),
    StaticSyscall::new(277,"sync_file_range",4), StaticSyscall::new(278,"vmsplice",4), StaticSyscall::new(279,"move_pages",6),
    StaticSyscall::new(280,"utimensat",4), StaticSyscall::new(281,"epoll_pwait",6), StaticSyscall::new(282,"signalfd",3),
    StaticSyscall::new(283,"timerfd_create",2), StaticSyscall::new(284,"eventfd",1), StaticSyscall::new(285,"fallocate",4),
    StaticSyscall::new(286,"timerfd_settime",4), StaticSyscall::new(287,"timerfd_gettime",2), StaticSyscall::new(288,"accept4",4),
    StaticSyscall::new(289,"signalfd4",4), StaticSyscall::new(290,"eventfd2",2), StaticSyscall::new(291,"epoll_create1",1),
    StaticSyscall::new(292,"dup3",3), StaticSyscall::new(293,"pipe2",2), StaticSyscall::new(294,"inotify_init1",1),
    StaticSyscall::new(295,"preadv",5), StaticSyscall::new(296,"pwritev",5), StaticSyscall::new(297,"rt_tgsigqueueinfo",4),
    StaticSyscall::new(298,"perf_event_open",5), StaticSyscall::new(299,"recvmmsg",5), StaticSyscall::new(300,"fanotify_init",2),
    StaticSyscall::new(301,"fanotify_mark",5), StaticSyscall::new(302,"prlimit64",4), StaticSyscall::new(303,"name_to_handle_at",5),
    StaticSyscall::new(304,"open_by_handle_at",3), StaticSyscall::new(305,"clock_adjtime",2), StaticSyscall::new(306,"syncfs",1),
    StaticSyscall::new(307,"sendmmsg",4), StaticSyscall::new(308,"setns",2), StaticSyscall::new(309,"getcpu",3),
    StaticSyscall::new(310,"process_vm_readv",6), StaticSyscall::new(311,"process_vm_writev",6), StaticSyscall::new(312,"kcmp",5),
    StaticSyscall::new(313,"finit_module",3), StaticSyscall::new(314,"sched_setattr",3), StaticSyscall::new(315,"sched_getattr",4),
    StaticSyscall::new(316,"renameat2",5), StaticSyscall::new(317,"seccomp",3), StaticSyscall::new(318,"getrandom",3),
    StaticSyscall::new(319,"memfd_create",2), StaticSyscall::new(320,"kexec_file_load",5), StaticSyscall::new(321,"bpf",3),
    StaticSyscall::new(322,"execveat",5), StaticSyscall::new(323,"userfaultfd",1), StaticSyscall::new(324,"membarrier",3),
    StaticSyscall::new(325,"mlock2",3), StaticSyscall::new(326,"copy_file_range",6), StaticSyscall::new(327,"preadv2",6),
    StaticSyscall::new(328,"pwritev2",6), StaticSyscall::new(329,"pkey_mprotect",4), StaticSyscall::new(330,"pkey_alloc",2),
    StaticSyscall::new(331,"pkey_free",1), StaticSyscall::new(332,"statx",5), StaticSyscall::new(333,"io_pgetevents",6),
    StaticSyscall::new(334,"rseq",4), StaticSyscall::new(424,"pidfd_send_signal",4), StaticSyscall::new(425,"io_uring_setup",2),
    StaticSyscall::new(426,"io_uring_enter",6), StaticSyscall::new(427,"io_uring_register",4), StaticSyscall::new(428,"open_tree",3),
    StaticSyscall::new(429,"move_mount",5), StaticSyscall::new(430,"fsopen",2), StaticSyscall::new(431,"fsconfig",5),
    StaticSyscall::new(432,"fsmount",3), StaticSyscall::new(433,"fspick",3), StaticSyscall::new(434,"pidfd_open",2),
    StaticSyscall::new(435,"clone3",2), StaticSyscall::new(436,"close_range",3), StaticSyscall::new(437,"openat2",4),
    StaticSyscall::new(438,"pidfd_getfd",3), StaticSyscall::new(439,"faccessat2",4), StaticSyscall::new(440,"process_madvise",5),
    StaticSyscall::new(441,"epoll_pwait2",6), StaticSyscall::new(442,"mount_setattr",5), StaticSyscall::new(443,"quotactl_fd",4),
    StaticSyscall::new(444,"landlock_create_ruleset",3), StaticSyscall::new(445,"landlock_add_rule",4),
    StaticSyscall::new(446,"landlock_restrict_self",2), StaticSyscall::new(447,"memfd_secret",1),
    StaticSyscall::new(448,"process_mrelease",2), StaticSyscall::new(449,"futex_waitv",5),
    StaticSyscall::new(450,"set_mempolicy_home_node",4),
];

#[must_use]
pub fn x86_64_syscall_name(nr: u32) -> Option<&'static str> {
    X86_64_SYSCALLS.iter().find(|s| s.nr == nr).map(|s| s.name)
}

#[must_use]
pub fn x86_64_syscall_nr(name: &str) -> Option<u32> {
    X86_64_SYSCALLS.iter().find(|s| s.name == name).map(|s| s.nr)
}

// ─── Additional tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod strace_ext_tests {
    use super::*;

    #[test] fn test_signal_name_sigkill() { assert_eq!(signal_name(9), Some("SIGKILL")); }
    #[test] fn test_signal_name_sigsegv() { assert_eq!(signal_name(11), Some("SIGSEGV")); }
    #[test] fn test_signal_name_unknown() { assert!(signal_name(200).is_none()); }

    #[test]
    fn test_decode_o_wronly_creat_trunc() {
        let f = 0o1 | 0o100 | 0o1000u64;
        let s = decode_flags(f, O_FLAGS);
        assert!(s.contains("O_WRONLY"), "got: {s}");
        assert!(s.contains("O_CREAT"),  "got: {s}");
        assert!(s.contains("O_TRUNC"),  "got: {s}");
    }

    #[test] fn test_decode_flags_zero() { assert_eq!(decode_flags(0, O_FLAGS), "0"); }

    #[test]
    fn test_prot_flags_rwx() {
        let s = decode_flags(0x7, PROT_FLAGS);
        assert!(s.contains("PROT_READ") && s.contains("PROT_WRITE") && s.contains("PROT_EXEC"));
    }

    #[test]
    fn test_map_flags_anon_private() {
        let s = decode_flags(0x22, MAP_FLAGS);
        assert!(s.contains("MAP_PRIVATE") && s.contains("MAP_ANONYMOUS"));
    }

    #[test]
    fn test_clone_flags_thread() {
        let s = decode_flags(0x3d0f00, CLONE_FLAGS);
        assert!(s.contains("CLONE_VM") && s.contains("CLONE_THREAD"));
    }

    #[test]
    fn test_decode_sockaddr_inet_loopback_80() {
        let mut d = vec![0u8; 8];
        d[0]=2; d[1]=0; d[2]=0; d[3]=80; d[4]=127; d[5]=0; d[6]=0; d[7]=1;
        match decode_sockaddr(&d) {
            DecodedSockaddr::Inet { addr, port } => { assert_eq!(addr,"127.0.0.1"); assert_eq!(port,80); }
            o => panic!("expected Inet, got {o:?}"),
        }
    }

    #[test]
    fn test_decode_sockaddr_unix() {
        let mut d = vec![1u8, 0];
        d.extend_from_slice(b"/tmp/x.sock\0");
        match decode_sockaddr(&d) {
            DecodedSockaddr::Unix { path } => assert_eq!(path, "/tmp/x.sock"),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn test_x86_64_full_table_size() { assert_eq!(X86_64_SYSCALLS.len(), 451); }
    #[test] fn test_x86_64_read()    { assert_eq!(x86_64_syscall_name(0),   Some("read")); }
    #[test] fn test_x86_64_write()   { assert_eq!(x86_64_syscall_name(1),   Some("write")); }
    #[test] fn test_x86_64_execve()  { assert_eq!(x86_64_syscall_name(59),  Some("execve")); }
    #[test] fn test_x86_64_openat()  { assert_eq!(x86_64_syscall_name(257), Some("openat")); }
    #[test] fn test_x86_64_clone3()  { assert_eq!(x86_64_syscall_name(435), Some("clone3")); }
    #[test] fn test_x86_64_unknown() { assert!(x86_64_syscall_name(9999).is_none()); }
    #[test] fn test_x86_64_rev_mmap(){ assert_eq!(x86_64_syscall_nr("mmap"), Some(9)); }

    #[test]
    fn test_fd_table_ops() {
        let mut t = FdTable::default();
        t.insert(3, FdInfo::file("/etc/passwd", 0));
        assert!(t.get(3).is_some());
        t.dup(3, 4);
        assert_eq!(t.get(4).unwrap().path, "/etc/passwd");
        t.remove(3);
        assert!(t.get(3).is_none());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn test_fd_info_socket() {
        let i = FdInfo::socket(2, 1, 0);
        assert!(i.is_socket);
        assert!(i.path.contains("socket:"));
    }

    #[test]
    fn test_thread_state_entry_exit() {
        let mut s = ThreadSyscallState::default();
        s.on_entry(1, [1,0,0,0,0,0,0], 1_000_000);
        assert_eq!(s.in_syscall, Some(1));
        let (nr, el) = s.on_exit(1_001_000);
        assert_eq!(nr, Some(1));
        assert_eq!(el, 1_000);
    }

    #[test]
    fn test_summary_sort_by_time() {
        let mut s = SyscallSummary::default();
        s.record("read",  1_000_000, 0);
        s.record("write", 2_000_000, 0);
        s.record("read",    500_000, 0);
        let v = s.sorted_by_time();
        assert_eq!(v[0].name, "write");
    }

    #[test]
    fn test_summary_error_count() {
        let mut s = SyscallSummary::default();
        s.record("open", 100, 0);
        s.record("open", 200, -1);
        assert_eq!(s.entries["open"].error_count, 1);
    }

    #[test]
    fn test_ptrace_filter_include() {
        let o = PtraceOptions::spawn("ls").include(["read","write"]);
        assert!(o.passes_filter("read"));
        assert!(!o.passes_filter("mmap"));
    }

    #[test]
    fn test_ptrace_filter_exclude() {
        let o = PtraceOptions::spawn("ls").exclude(["brk"]);
        assert!(!o.passes_filter("brk"));
        assert!(o.passes_filter("mmap"));
    }

    #[test]
    fn test_format_signal_sigsegv() {
        let s = format_signal_delivery(11, 1, 0xdead);
        assert!(s.contains("SIGSEGV") && s.contains("SEGV_MAPERR") && s.contains("dead"));
    }

    #[test]
    fn test_format_exit_normal() {
        assert!(format_exit_event(1, 0, None).contains("exited with 0"));
    }

    #[test]
    fn test_format_exit_signal() {
        assert!(format_exit_event(1, 0, Some(9)).contains("SIGKILL"));
    }

    #[test]
    fn test_syscall_event_display() {
        let ev = SyscallEvent {
            timestamp_ns: 0, pid: 1, tid: 1, nr: 0,
            name: "read".to_string(),
            args: vec![DecodedArg::Fd(3, "/etc/passwd".to_string()), DecodedArg::Addr(0x7fff0000), DecodedArg::UInt(256)],
            retval: DecodedArg::Int(256),
            elapsed_ns: 500, is_entry: false,
        };
        let s = ev.to_string();
        assert!(s.starts_with("read(") && s.contains("= 256"));
    }

    #[test]
    fn test_syscall_event_csv() {
        let ev = SyscallEvent {
            timestamp_ns: 123, pid: 1, tid: 1, nr: 1,
            name: "write".to_string(), args: vec![],
            retval: DecodedArg::Int(4), elapsed_ns: 99, is_entry: false,
        };
        assert!(ev.to_csv_row().starts_with("123,1,1,write,"));
    }

    #[test]
    fn test_epoll_events_decode() {
        let s = decode_flags(0x05, EPOLL_EVENTS);
        assert!(s.contains("EPOLLIN") && s.contains("EPOLLOUT"));
    }

    #[test]
    fn test_sock_stream() {
        assert!(decode_flags(1, SOCK_FLAGS).contains("SOCK_STREAM"));
    }

    #[test]
    fn test_wait_wnohang() {
        assert!(decode_flags(0x1, WAIT_FLAGS).contains("WNOHANG"));
    }

    #[test]
    fn test_summary_table_has_header() {
        let mut s = SyscallSummary::default();
        s.record("mmap", 50_000_000, 0);
        assert!(s.format_table().contains("% time"));
    }

    #[test]
    fn test_at_fdcwd_constant() {
        assert_eq!(AT_FDCWD, -100);
    }

    #[test]
    fn test_arg_type_c_name_fd() {
        assert_eq!(ArgType::Fd.c_name(), "int /*fd*/");
    }

    #[test]
    fn test_arg_type_c_name_str() {
        assert_eq!(ArgType::Str.c_name(), "const char *");
    }

    #[test]
    fn test_decoded_arg_null() {
        assert_eq!(DecodedArg::Null.to_string(), "NULL");
    }

    #[test]
    fn test_decoded_arg_fd_with_path() {
        assert_eq!(DecodedArg::Fd(3, "/etc/passwd".to_string()).to_string(), "3</etc/passwd>");
    }

    #[test]
    fn test_decoded_arg_flags() {
        assert_eq!(DecodedArg::Flags(1, "O_WRONLY".to_string()).to_string(), "O_WRONLY");
    }

    #[test]
    fn test_hex_dump_ext_truncation() {
        let d: Vec<u8> = (0u8..20).collect();
        let s = hex_dump_ext(&d, 8);
        assert!(s.contains("... (12 more bytes)"));
    }

    #[test]
    fn test_decode_flags_by_name_prot_rw() {
        let s = decode_flags_by_name("PROT_FLAGS", 0x3);
        assert!(s.contains("PROT_READ") && s.contains("PROT_WRITE"));
    }
}
