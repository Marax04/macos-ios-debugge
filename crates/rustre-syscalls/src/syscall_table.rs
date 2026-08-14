//! Unified syscall table: Linux x86-64, Windows NT, macOS BSD.
//!
//! Provides [`SyscallDb`] with lookup by number or name, [`SyscallEntry`]
//! metadata, and [`SyscallArg`] parameter descriptors.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// â"€â"€â"€ Argument types â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// The C-level type of a syscall argument or return value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArgType {
    Int,
    UInt,
    Long,
    ULong,
    SizeT,
    SSizeT,
    Pid,
    Uid,
    Gid,
    Fd,
    Ptr,
    ConstPtr,
    CStr,
    Flags(String),
    Struct(String),
    Void,
    Unknown,
}

impl std::fmt::Display for ArgType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Int => write!(f, "int"),
            Self::UInt => write!(f, "unsigned int"),
            Self::Long => write!(f, "long"),
            Self::ULong => write!(f, "unsigned long"),
            Self::SizeT => write!(f, "size_t"),
            Self::SSizeT => write!(f, "ssize_t"),
            Self::Pid => write!(f, "pid_t"),
            Self::Uid => write!(f, "uid_t"),
            Self::Gid => write!(f, "gid_t"),
            Self::Fd => write!(f, "int /*fd*/"),
            Self::Ptr => write!(f, "void *"),
            Self::ConstPtr => write!(f, "const void *"),
            Self::CStr => write!(f, "const char *"),
            Self::Flags(s) => write!(f, "{s}"),
            Self::Struct(s) => write!(f, "struct {s} *"),
            Self::Void => write!(f, "void"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

// â"€â"€â"€ SyscallArg â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// One argument of a syscall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyscallArg {
    pub name: String,
    pub ty: ArgType,
}

impl SyscallArg {
    #[must_use]
    pub fn new(name: &str, ty: ArgType) -> Self {
        Self {
            name: name.to_string(),
            ty,
        }
    }
}

impl std::fmt::Display for SyscallArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.ty, self.name)
    }
}

// â"€â"€â"€ OsFamily â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

use crate::OsFamily;

// â"€â"€â"€ SyscallEntry â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Full metadata for a single syscall.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEntry {
    /// Syscall number (as returned in rax/eax on x86-64).
    pub number: u64,
    /// Short name (e.g. "read", "write", "`NtCreateFile`").
    pub name: String,
    /// OS family this entry belongs to.
    pub os: OsFamily,
    /// Return type.
    pub return_type: ArgType,
    /// Argument list (up to 6 on Linux, variable on NT).
    pub args: Vec<SyscallArg>,
    /// Brief description.
    pub description: String,
    /// Tags (e.g. "io", "process", "memory", "net").
    pub tags: Vec<String>,
}

impl SyscallEntry {
    /// Render as a C prototype string.
    #[must_use]
    pub fn prototype(&self) -> String {
        let args: Vec<String> = self
            .args
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        format!("{} {}({})", self.return_type, self.name, args.join(", "))
    }

    /// True when this syscall performs I/O (fd-based).
    #[must_use]
    pub fn is_io(&self) -> bool {
        self.tags.iter().any(|t| t == "io")
    }

    /// True when this syscall deals with processes or threads.
    #[must_use]
    pub fn is_process(&self) -> bool {
        self.tags.iter().any(|t| t == "process" || t == "thread")
    }

    /// True when this syscall deals with memory.
    #[must_use]
    pub fn is_memory(&self) -> bool {
        self.tags.iter().any(|t| t == "memory")
    }
}

// â"€â"€â"€ Helper macro â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

macro_rules! entry {
    ($num:expr, $name:expr, $os:expr, $ret:expr, [$($aname:expr => $aty:expr),*], $desc:expr, [$($tag:expr),*]) => {
        SyscallEntry {
            number: $num,
            name: $name.to_string(),
            os: $os,
            return_type: $ret,
            args: vec![$(SyscallArg::new($aname, $aty)),*],
            description: $desc.to_string(),
            tags: vec![$($tag.to_string()),*],
        }
    };
}

// â"€â"€â"€ SyscallDb â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Database holding syscall entries for multiple OS families.
#[derive(Debug, Default)]
pub struct SyscallDb {
    /// All entries indexed by (os, number).
    by_number: HashMap<(OsFamily, u64), SyscallEntry>,
    /// All entries indexed by (os, name).
    by_name: HashMap<(OsFamily, String), SyscallEntry>,
}

impl SyscallDb {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a database pre-populated with known syscalls.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut db = Self::new();
        db.load_linux_x86_64();
        db.load_windows_nt();
        db.load_macos_bsd();
        db
    }

    /// Insert a single entry.
    pub fn insert(&mut self, entry: SyscallEntry) {
        let key_num = (entry.os, entry.number);
        let key_name = (entry.os, entry.name.clone());
        self.by_number.insert(key_num, entry.clone());
        self.by_name.insert(key_name, entry);
    }

    /// Look up by OS and syscall number.
    #[must_use]
    pub fn lookup_by_number(&self, os: OsFamily, number: u64) -> Option<&SyscallEntry> {
        self.by_number.get(&(os, number))
    }

    /// Look up by OS and syscall name.
    #[must_use]
    pub fn lookup_by_name(&self, os: OsFamily, name: &str) -> Option<&SyscallEntry> {
        self.by_name.get(&(os, name.to_string()))
    }

    /// Iterate over all entries for a given OS.
    pub fn entries_for_os(&self, os: OsFamily) -> impl Iterator<Item = &SyscallEntry> {
        self.by_number.values().filter(move |e| e.os == os)
    }

    /// Total number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_number.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_number.is_empty()
    }

    /// All entries with a given tag, across all OS families.
    #[must_use]
    pub fn entries_with_tag(&self, tag: &str) -> Vec<&SyscallEntry> {
        self.by_number
            .values()
            .filter(|e| e.tags.iter().any(|t| t == tag))
            .collect()
    }

    // â"€â"€ Linux x86-64 loader â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn load_linux_x86_64(&mut self) {
        self.load_linux_x86_64_part_a();
        self.load_linux_x86_64_part_a2();
        self.load_linux_x86_64_part_b();
        self.load_linux_x86_64_part_b2();
    }

    fn load_linux_x86_64_part_a(&mut self) {
        use ArgType::{CStr, ConstPtr, Fd, Flags, Int, Long, Ptr, SSizeT, SizeT, Struct, ULong};
        let os = OsFamily::Linux;

        let entries = vec![
            entry!(0, "read", os, SSizeT, ["fd" => Fd, "buf" => Ptr, "count" => SizeT], "Read from file descriptor", ["io"]),
            entry!(1, "write", os, SSizeT, ["fd" => Fd, "buf" => ConstPtr, "count" => SizeT], "Write to file descriptor", ["io"]),
            entry!(2, "open", os, Fd, ["pathname" => CStr, "flags" => Flags("int".into()), "mode" => Flags("mode_t".into())], "Open file", ["io", "fs"]),
            entry!(3, "close", os, Int, ["fd" => Fd], "Close file descriptor", ["io"]),
            entry!(4, "stat", os, Int, ["pathname" => CStr, "statbuf" => Struct("stat".into())], "Get file status", ["fs"]),
            entry!(5, "fstat", os, Int, ["fd" => Fd, "statbuf" => Struct("stat".into())], "Get file status by fd", ["fs"]),
            entry!(6, "lstat", os, Int, ["pathname" => CStr, "statbuf" => Struct("stat".into())], "Get file status (no follow symlink)", ["fs"]),
            entry!(7, "poll", os, Int, ["fds" => Struct("pollfd".into()), "nfds" => ULong, "timeout" => Int], "Wait for events on fds", ["io"]),
            entry!(8, "lseek", os, Long, ["fd" => Fd, "offset" => Long, "whence" => Int], "Reposition file offset", ["io"]),
            entry!(9, "mmap", os, Ptr, ["addr" => Ptr, "length" => SizeT, "prot" => Int, "flags" => Int, "fd" => Fd, "offset" => Long], "Map files into memory", ["memory"]),
            entry!(10, "mprotect", os, Int, ["addr" => Ptr, "len" => SizeT, "prot" => Int], "Set memory protection", ["memory"]),
            entry!(11, "munmap", os, Int, ["addr" => Ptr, "length" => SizeT], "Unmap memory", ["memory"]),
            entry!(12, "brk", os, Ptr, ["addr" => Ptr], "Change program break", ["memory"]),
            entry!(13, "rt_sigaction", os, Int, ["signum" => Int, "act" => Struct("sigaction".into()), "oldact" => Struct("sigaction".into())], "Examine/change signal action", ["signal"]),
            entry!(14, "rt_sigprocmask", os, Int, ["how" => Int, "set" => Struct("sigset_t".into()), "oldset" => Struct("sigset_t".into())], "Examine/change blocked signals", ["signal"]),
            entry!(
                15,
                "rt_sigreturn",
                os,
                Long,
                [],
                "Return from signal handler",
                ["signal"]
            ),
            entry!(16, "ioctl", os, Int, ["fd" => Fd, "request" => ULong, "arg" => Ptr], "I/O control", ["io"]),
            entry!(17, "pread64", os, SSizeT, ["fd" => Fd, "buf" => Ptr, "count" => SizeT, "offset" => Long], "Read from fd at offset", ["io"]),
            entry!(18, "pwrite64", os, SSizeT, ["fd" => Fd, "buf" => ConstPtr, "count" => SizeT, "offset" => Long], "Write to fd at offset", ["io"]),
            entry!(19, "readv", os, SSizeT, ["fd" => Fd, "iov" => Struct("iovec".into()), "iovcnt" => Int], "Read from fd into scatter", ["io"]),
            entry!(20, "writev", os, SSizeT, ["fd" => Fd, "iov" => Struct("iovec".into()), "iovcnt" => Int], "Write from gather to fd", ["io"]),
            entry!(21, "access", os, Int, ["pathname" => CStr, "mode" => Int], "Check file access", ["fs"]),
            entry!(22, "pipe", os, Int, ["pipefd" => Ptr], "Create pipe", ["io"]),
            entry!(23, "select", os, Int, ["nfds" => Int, "readfds" => Ptr, "writefds" => Ptr, "exceptfds" => Ptr, "timeout" => Struct("timeval".into())], "Synchronous I/O multiplexing", ["io"]),
        ];

        for e in entries {
            self.insert(e);
        }
    }

    fn load_linux_x86_64_part_a2(&mut self) {
        use ArgType::{CStr, ConstPtr, Fd, Int, Long, Pid, Ptr, SSizeT, SizeT, Struct, UInt, ULong, Void};
        let os = OsFamily::Linux;

        let entries = vec![
            entry!(
                24,
                "sched_yield",
                os,
                Int,
                [],
                "Yield processor",
                ["process"]
            ),
            entry!(25, "mremap", os, Ptr, ["old_address" => Ptr, "old_size" => SizeT, "new_size" => SizeT, "flags" => Int], "Remap virtual address", ["memory"]),
            entry!(26, "msync", os, Int, ["addr" => Ptr, "length" => SizeT, "flags" => Int], "Sync memory with file", ["memory"]),
            entry!(27, "mincore", os, Int, ["addr" => Ptr, "length" => SizeT, "vec" => Ptr], "Determine page residency", ["memory"]),
            entry!(28, "madvise", os, Int, ["addr" => Ptr, "length" => SizeT, "advice" => Int], "Give memory advice", ["memory"]),
            entry!(32, "dup", os, Fd, ["oldfd" => Fd], "Duplicate fd", ["io"]),
            entry!(33, "dup2", os, Fd, ["oldfd" => Fd, "newfd" => Fd], "Duplicate fd to newfd", ["io"]),
            entry!(34, "pause", os, Int, [], "Wait for signal", ["signal"]),
            entry!(35, "nanosleep", os, Int, ["req" => Struct("timespec".into()), "rem" => Struct("timespec".into())], "High-res sleep", ["time"]),
            entry!(36, "getitimer", os, Int, ["which" => Int, "curr_value" => Struct("itimerval".into())], "Get interval timer", ["time"]),
            entry!(37, "alarm", os, UInt, ["seconds" => UInt], "Set alarm clock", ["signal", "time"]),
            entry!(38, "setitimer", os, Int, ["which" => Int, "new_value" => Struct("itimerval".into()), "old_value" => Struct("itimerval".into())], "Set interval timer", ["time"]),
            entry!(39, "getpid", os, Pid, [], "Get process ID", ["process"]),
            entry!(40, "sendfile", os, SSizeT, ["out_fd" => Fd, "in_fd" => Fd, "offset" => Ptr, "count" => SizeT], "Transfer data between fds", ["io"]),
            entry!(41, "socket", os, Fd, ["domain" => Int, "type" => Int, "protocol" => Int], "Create socket", ["net"]),
            entry!(42, "connect", os, Int, ["sockfd" => Fd, "addr" => Struct("sockaddr".into()), "addrlen" => UInt], "Connect socket", ["net"]),
            entry!(43, "accept", os, Fd, ["sockfd" => Fd, "addr" => Struct("sockaddr".into()), "addrlen" => Ptr], "Accept connection", ["net"]),
            entry!(44, "sendto", os, SSizeT, ["sockfd" => Fd, "buf" => ConstPtr, "len" => SizeT, "flags" => Int, "dest_addr" => Struct("sockaddr".into()), "addrlen" => UInt], "Send datagram", ["net"]),
            entry!(45, "recvfrom", os, SSizeT, ["sockfd" => Fd, "buf" => Ptr, "len" => SizeT, "flags" => Int, "src_addr" => Struct("sockaddr".into()), "addrlen" => Ptr], "Receive datagram", ["net"]),
            entry!(46, "sendmsg", os, SSizeT, ["sockfd" => Fd, "msg" => Struct("msghdr".into()), "flags" => Int], "Send message", ["net"]),
            entry!(47, "recvmsg", os, SSizeT, ["sockfd" => Fd, "msg" => Struct("msghdr".into()), "flags" => Int], "Receive message", ["net"]),
            entry!(48, "shutdown", os, Int, ["sockfd" => Fd, "how" => Int], "Shutdown socket", ["net"]),
            entry!(49, "bind", os, Int, ["sockfd" => Fd, "addr" => Struct("sockaddr".into()), "addrlen" => UInt], "Bind socket to address", ["net"]),
            entry!(50, "listen", os, Int, ["sockfd" => Fd, "backlog" => Int], "Listen for connections", ["net"]),
            entry!(51, "getsockname", os, Int, ["sockfd" => Fd, "addr" => Struct("sockaddr".into()), "addrlen" => Ptr], "Get socket name", ["net"]),
            entry!(52, "getpeername", os, Int, ["sockfd" => Fd, "addr" => Struct("sockaddr".into()), "addrlen" => Ptr], "Get peer socket name", ["net"]),
            entry!(53, "socketpair", os, Int, ["domain" => Int, "type" => Int, "protocol" => Int, "sv" => Ptr], "Create socket pair", ["net"]),
            entry!(54, "setsockopt", os, Int, ["sockfd" => Fd, "level" => Int, "optname" => Int, "optval" => ConstPtr, "optlen" => UInt], "Set socket option", ["net"]),
            entry!(55, "getsockopt", os, Int, ["sockfd" => Fd, "level" => Int, "optname" => Int, "optval" => Ptr, "optlen" => Ptr], "Get socket option", ["net"]),
            entry!(56, "clone", os, Long, ["flags" => ULong, "stack" => Ptr, "parent_tid" => Ptr, "child_tid" => Ptr, "tls" => ULong], "Create child process/thread", ["process", "thread"]),
            entry!(57, "fork", os, Pid, [], "Fork process", ["process"]),
            entry!(
                58,
                "vfork",
                os,
                Pid,
                [],
                "Fork process (vfork)",
                ["process"]
            ),
            entry!(59, "execve", os, Int, ["pathname" => CStr, "argv" => Ptr, "envp" => Ptr], "Execute program", ["process"]),
            entry!(60, "exit", os, Void, ["status" => Int], "Terminate process", ["process"]),
            entry!(61, "wait4", os, Pid, ["pid" => Pid, "wstatus" => Ptr, "options" => Int, "rusage" => Struct("rusage".into())], "Wait for process", ["process"]),
            entry!(62, "kill", os, Int, ["pid" => Pid, "sig" => Int], "Send signal", ["signal", "process"]),
            entry!(63, "uname", os, Int, ["buf" => Struct("utsname".into())], "Get system info", ["info"]),
            entry!(72, "fcntl", os, Int, ["fd" => Fd, "cmd" => Int, "arg" => Long], "File control", ["io", "fs"]),
            entry!(73, "flock", os, Int, ["fd" => Fd, "operation" => Int], "Apply file lock", ["fs"]),
            entry!(74, "fsync", os, Int, ["fd" => Fd], "Synchronize file", ["fs", "io"]),
            entry!(75, "fdatasync", os, Int, ["fd" => Fd], "Synchronize file data", ["fs", "io"]),
            entry!(76, "truncate", os, Int, ["path" => CStr, "length" => Long], "Truncate file", ["fs"]),
            entry!(77, "ftruncate", os, Int, ["fd" => Fd, "length" => Long], "Truncate file by fd", ["fs"]),
            entry!(78, "getdents", os, Int, ["fd" => Fd, "dirp" => Ptr, "count" => UInt], "Get directory entries", ["fs"]),
            entry!(79, "getcwd", os, Ptr, ["buf" => Ptr, "size" => SizeT], "Get working directory", ["fs"]),
            entry!(80, "chdir", os, Int, ["path" => CStr], "Change directory", ["fs"]),
        ];

        for e in entries {
            self.insert(e);
        }
    }

    fn load_linux_x86_64_part_b(&mut self) {
        use ArgType::{CStr, Fd, Flags, Gid, Int, Long, Pid, Ptr, SSizeT, SizeT, Struct, UInt, Uid};
        let os = OsFamily::Linux;

        let entries = vec![
            entry!(81, "fchdir", os, Int, ["fd" => Fd], "Change directory by fd", ["fs"]),
            entry!(82, "rename", os, Int, ["oldpath" => CStr, "newpath" => CStr], "Rename file", ["fs"]),
            entry!(83, "mkdir", os, Int, ["pathname" => CStr, "mode" => Flags("mode_t".into())], "Create directory", ["fs"]),
            entry!(84, "rmdir", os, Int, ["pathname" => CStr], "Remove directory", ["fs"]),
            entry!(85, "creat", os, Fd, ["pathname" => CStr, "mode" => Flags("mode_t".into())], "Create file", ["fs", "io"]),
            entry!(86, "link", os, Int, ["oldpath" => CStr, "newpath" => CStr], "Create hard link", ["fs"]),
            entry!(87, "unlink", os, Int, ["pathname" => CStr], "Remove file", ["fs"]),
            entry!(88, "symlink", os, Int, ["target" => CStr, "linkpath" => CStr], "Create symbolic link", ["fs"]),
            entry!(89, "readlink", os, SSizeT, ["pathname" => CStr, "buf" => Ptr, "bufsiz" => SizeT], "Read symbolic link", ["fs"]),
            entry!(90, "chmod", os, Int, ["pathname" => CStr, "mode" => Flags("mode_t".into())], "Change permissions", ["fs"]),
            entry!(91, "fchmod", os, Int, ["fd" => Fd, "mode" => Flags("mode_t".into())], "Change permissions by fd", ["fs"]),
            entry!(92, "chown", os, Int, ["pathname" => CStr, "owner" => Uid, "group" => Gid], "Change ownership", ["fs"]),
            entry!(93, "fchown", os, Int, ["fd" => Fd, "owner" => Uid, "group" => Gid], "Change ownership by fd", ["fs"]),
            entry!(94, "lchown", os, Int, ["pathname" => CStr, "owner" => Uid, "group" => Gid], "Change ownership (no follow symlink)", ["fs"]),
            entry!(95, "umask", os, Flags("mode_t".into()), ["mask" => Flags("mode_t".into())], "Set file creation mask", ["fs"]),
            entry!(96, "gettimeofday", os, Int, ["tv" => Struct("timeval".into()), "tz" => Struct("timezone".into())], "Get time of day", ["time"]),
            entry!(97, "getrlimit", os, Int, ["resource" => UInt, "rlim" => Struct("rlimit".into())], "Get resource limits", ["process"]),
            entry!(98, "getrusage", os, Int, ["who" => Int, "usage" => Struct("rusage".into())], "Get resource usage", ["process"]),
            entry!(99, "sysinfo", os, Int, ["info" => Struct("sysinfo".into())], "Get system info", ["info"]),
            entry!(100, "times", os, Long, ["buf" => Struct("tms".into())], "Get process times", ["time", "process"]),
            entry!(101, "ptrace", os, Long, ["request" => Long, "pid" => Pid, "addr" => Ptr, "data" => Ptr], "Trace/debug process", ["debug", "process"]),
            entry!(102, "getuid", os, Uid, [], "Get user ID", ["process"]),
            entry!(103, "syslog", os, Int, ["type" => Int, "buf" => Ptr, "len" => Int], "Read/clear kernel ring buffer", ["info"]),
            entry!(104, "getgid", os, Gid, [], "Get group ID", ["process"]),
            entry!(105, "setuid", os, Int, ["uid" => Uid], "Set user ID", ["process"]),
            entry!(106, "setgid", os, Int, ["gid" => Gid], "Set group ID", ["process"]),
            entry!(
                107,
                "geteuid",
                os,
                Uid,
                [],
                "Get effective user ID",
                ["process"]
            ),
            entry!(
                108,
                "getegid",
                os,
                Gid,
                [],
                "Get effective group ID",
                ["process"]
            ),
            entry!(
                110,
                "getppid",
                os,
                Pid,
                [],
                "Get parent process ID",
                ["process"]
            ),
            entry!(
                111,
                "getpgrp",
                os,
                Pid,
                [],
                "Get process group",
                ["process"]
            ),
            entry!(
                112,
                "setsid",
                os,
                Pid,
                [],
                "Create new session",
                ["process"]
            ),
        ];

        for e in entries {
            self.insert(e);
        }
    }

    fn load_linux_x86_64_part_b2(&mut self) {
        use ArgType::{CStr, Fd, Flags, Gid, Int, Long, Pid, Ptr, SSizeT, SizeT, Struct, UInt, ULong, Uid, Void};
        let os = OsFamily::Linux;

        let entries = vec![
            entry!(130, "mlock", os, Int, ["addr" => Ptr, "len" => SizeT], "Lock memory", ["memory"]),
            entry!(131, "munlock", os, Int, ["addr" => Ptr, "len" => SizeT], "Unlock memory", ["memory"]),
            entry!(132, "mlockall", os, Int, ["flags" => Int], "Lock all memory", ["memory"]),
            entry!(
                133,
                "munlockall",
                os,
                Int,
                [],
                "Unlock all memory",
                ["memory"]
            ),
            entry!(158, "arch_prctl", os, Int, ["code" => Int, "addr" => ULong], "Set arch-specific thread state", ["process", "thread"]),
            entry!(
                186,
                "gettid",
                os,
                Pid,
                [],
                "Get thread ID",
                ["thread", "process"]
            ),
            entry!(202, "futex", os, Long, ["uaddr" => Ptr, "futex_op" => Int, "val" => UInt, "timeout" => Struct("timespec".into()), "uaddr2" => Ptr, "val3" => UInt], "Fast userspace mutex", ["thread"]),
            entry!(218, "set_tid_address", os, Pid, ["tidptr" => Ptr], "Set pointer to thread ID", ["thread"]),
            entry!(228, "clock_gettime", os, Int, ["clockid" => Int, "tp" => Struct("timespec".into())], "Get clock time", ["time"]),
            entry!(229, "clock_getres", os, Int, ["clockid" => Int, "res" => Struct("timespec".into())], "Get clock resolution", ["time"]),
            entry!(230, "clock_nanosleep", os, Int, ["clockid" => Int, "flags" => Int, "request" => Struct("timespec".into()), "remain" => Struct("timespec".into())], "High-res sleep with clock", ["time"]),
            entry!(231, "exit_group", os, Void, ["status" => Int], "Exit all threads in group", ["process"]),
            entry!(232, "epoll_wait", os, Int, ["epfd" => Fd, "events" => Struct("epoll_event".into()), "maxevents" => Int, "timeout" => Int], "Wait for epoll events", ["io"]),
            entry!(233, "epoll_ctl", os, Int, ["epfd" => Fd, "op" => Int, "fd" => Fd, "event" => Struct("epoll_event".into())], "Control epoll instance", ["io"]),
            entry!(257, "openat", os, Fd, ["dirfd" => Fd, "pathname" => CStr, "flags" => Int, "mode" => Flags("mode_t".into())], "Open file relative to dir fd", ["io", "fs"]),
            entry!(258, "mkdirat", os, Int, ["dirfd" => Fd, "pathname" => CStr, "mode" => Flags("mode_t".into())], "Create dir relative to dir fd", ["fs"]),
            entry!(260, "fchownat", os, Int, ["dirfd" => Fd, "pathname" => CStr, "owner" => Uid, "group" => Gid, "flags" => Int], "Change ownership relative to dir fd", ["fs"]),
            entry!(262, "newfstatat", os, Int, ["dirfd" => Fd, "pathname" => CStr, "statbuf" => Struct("stat".into()), "flags" => Int], "Get file status relative to dir fd", ["fs"]),
            entry!(263, "unlinkat", os, Int, ["dirfd" => Fd, "pathname" => CStr, "flags" => Int], "Remove file relative to dir fd", ["fs"]),
            entry!(264, "renameat", os, Int, ["olddirfd" => Fd, "oldpath" => CStr, "newdirfd" => Fd, "newpath" => CStr], "Rename relative to dir fds", ["fs"]),
            entry!(269, "faccessat", os, Int, ["dirfd" => Fd, "pathname" => CStr, "mode" => Int, "flags" => Int], "Check access relative to dir fd", ["fs"]),
            entry!(280, "accept4", os, Fd, ["sockfd" => Fd, "addr" => Struct("sockaddr".into()), "addrlen" => Ptr, "flags" => Int], "Accept connection with flags", ["net"]),
            entry!(291, "epoll_create1", os, Fd, ["flags" => Int], "Create epoll instance", ["io"]),
            entry!(292, "dup3", os, Fd, ["oldfd" => Fd, "newfd" => Fd, "flags" => Int], "Duplicate fd with flags", ["io"]),
            entry!(293, "pipe2", os, Int, ["pipefd" => Ptr, "flags" => Int], "Create pipe with flags", ["io"]),
            entry!(316, "renameat2", os, Int, ["olddirfd" => Fd, "oldpath" => CStr, "newdirfd" => Fd, "newpath" => CStr, "flags" => UInt], "Rename with flags", ["fs"]),
            entry!(317, "seccomp", os, Int, ["operation" => UInt, "flags" => UInt, "args" => Ptr], "Seccomp filter", ["security"]),
            entry!(318, "getrandom", os, SSizeT, ["buf" => Ptr, "buflen" => SizeT, "flags" => UInt], "Get random bytes", ["security"]),
            entry!(319, "memfd_create", os, Fd, ["name" => CStr, "flags" => UInt], "Create anonymous file", ["memory", "fs"]),
            entry!(332, "statx", os, Int, ["dirfd" => Fd, "pathname" => CStr, "flags" => Int, "mask" => UInt, "statxbuf" => Struct("statx".into())], "Get extended file status", ["fs"]),
        ];

        for e in entries {
            self.insert(e);
        }
    }

    // â"€â"€ Windows NT loader â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn load_windows_nt(&mut self) {
        use ArgType::{Int, Long, Ptr, SizeT, Struct, ULong};
        let os = OsFamily::Windows;

        let entries = vec![
            entry!(0x0000, "NtReadFile", os, Long, ["FileHandle" => Ptr, "Event" => Ptr, "ApcRoutine" => Ptr, "ApcContext" => Ptr, "IoStatusBlock" => Struct("IO_STATUS_BLOCK".into())], "Read from file", ["io"]),
            entry!(0x0001, "NtWriteFile", os, Long, ["FileHandle" => Ptr, "Event" => Ptr, "ApcRoutine" => Ptr, "ApcContext" => Ptr, "IoStatusBlock" => Struct("IO_STATUS_BLOCK".into())], "Write to file", ["io"]),
            entry!(0x0002, "NtCreateFile", os, Long, ["FileHandle" => Ptr, "DesiredAccess" => ULong, "ObjectAttributes" => Struct("OBJECT_ATTRIBUTES".into()), "IoStatusBlock" => Struct("IO_STATUS_BLOCK".into()), "AllocationSize" => Ptr], "Create/open file", ["io", "fs"]),
            entry!(0x0003, "NtOpenFile", os, Long, ["FileHandle" => Ptr, "DesiredAccess" => ULong, "ObjectAttributes" => Struct("OBJECT_ATTRIBUTES".into()), "IoStatusBlock" => Struct("IO_STATUS_BLOCK".into()), "ShareAccess" => ULong], "Open existing file", ["io", "fs"]),
            entry!(0x0004, "NtClose", os, Long, ["Handle" => Ptr], "Close handle", ["io"]),
            entry!(0x0005, "NtQueryInformationFile", os, Long, ["FileHandle" => Ptr, "IoStatusBlock" => Struct("IO_STATUS_BLOCK".into()), "FileInformation" => Ptr, "Length" => ULong, "FileInformationClass" => Int], "Query file information", ["fs"]),
            entry!(0x0006, "NtSetInformationFile", os, Long, ["FileHandle" => Ptr, "IoStatusBlock" => Struct("IO_STATUS_BLOCK".into()), "FileInformation" => Ptr, "Length" => ULong, "FileInformationClass" => Int], "Set file information", ["fs"]),
            entry!(0x0007, "NtAllocateVirtualMemory", os, Long, ["ProcessHandle" => Ptr, "BaseAddress" => Ptr, "ZeroBits" => ULong, "RegionSize" => Ptr, "AllocationType" => ULong], "Allocate virtual memory", ["memory"]),
            entry!(0x0008, "NtFreeVirtualMemory", os, Long, ["ProcessHandle" => Ptr, "BaseAddress" => Ptr, "RegionSize" => Ptr, "FreeType" => ULong], "Free virtual memory", ["memory"]),
            entry!(0x0009, "NtProtectVirtualMemory", os, Long, ["ProcessHandle" => Ptr, "BaseAddress" => Ptr, "RegionSize" => Ptr, "NewProtect" => ULong, "OldProtect" => Ptr], "Change memory protection", ["memory"]),
            entry!(0x000A, "NtQueryVirtualMemory", os, Long, ["ProcessHandle" => Ptr, "BaseAddress" => Ptr, "MemoryInformationClass" => Int, "MemoryInformation" => Ptr, "MemoryInformationLength" => SizeT], "Query virtual memory", ["memory"]),
            entry!(0x000B, "NtCreateProcess", os, Long, ["ProcessHandle" => Ptr, "DesiredAccess" => ULong, "ObjectAttributes" => Struct("OBJECT_ATTRIBUTES".into()), "ParentProcess" => Ptr, "InheritObjectTable" => Int], "Create process", ["process"]),
            entry!(0x000C, "NtOpenProcess", os, Long, ["ProcessHandle" => Ptr, "DesiredAccess" => ULong, "ObjectAttributes" => Struct("OBJECT_ATTRIBUTES".into()), "ClientId" => Struct("CLIENT_ID".into())], "Open process handle", ["process"]),
            entry!(0x000D, "NtTerminateProcess", os, Long, ["ProcessHandle" => Ptr, "ExitStatus" => Long], "Terminate process", ["process"]),
            entry!(0x000E, "NtCreateThread", os, Long, ["ThreadHandle" => Ptr, "DesiredAccess" => ULong, "ObjectAttributes" => Struct("OBJECT_ATTRIBUTES".into()), "ProcessHandle" => Ptr, "ClientId" => Struct("CLIENT_ID".into())], "Create thread", ["thread"]),
            entry!(0x000F, "NtOpenThread", os, Long, ["ThreadHandle" => Ptr, "DesiredAccess" => ULong, "ObjectAttributes" => Struct("OBJECT_ATTRIBUTES".into()), "ClientId" => Struct("CLIENT_ID".into())], "Open thread handle", ["thread"]),
            entry!(0x0010, "NtTerminateThread", os, Long, ["ThreadHandle" => Ptr, "ExitStatus" => Long], "Terminate thread", ["thread"]),
            entry!(0x0011, "NtQueryInformationProcess", os, Long, ["ProcessHandle" => Ptr, "ProcessInformationClass" => Int, "ProcessInformation" => Ptr, "ProcessInformationLength" => ULong, "ReturnLength" => Ptr], "Query process information", ["process"]),
            entry!(0x0012, "NtSetInformationProcess", os, Long, ["ProcessHandle" => Ptr, "ProcessInformationClass" => Int, "ProcessInformation" => Ptr, "ProcessInformationLength" => ULong], "Set process information", ["process"]),
            entry!(0x0013, "NtQueryInformationThread", os, Long, ["ThreadHandle" => Ptr, "ThreadInformationClass" => Int, "ThreadInformation" => Ptr, "ThreadInformationLength" => ULong, "ReturnLength" => Ptr], "Query thread information", ["thread"]),
            entry!(0x0014, "NtReadVirtualMemory", os, Long, ["ProcessHandle" => Ptr, "BaseAddress" => Ptr, "Buffer" => Ptr, "BufferSize" => SizeT, "NumberOfBytesRead" => Ptr], "Read process memory", ["memory", "debug"]),
            entry!(0x0015, "NtWriteVirtualMemory", os, Long, ["ProcessHandle" => Ptr, "BaseAddress" => Ptr, "Buffer" => Ptr, "BufferSize" => SizeT, "NumberOfBytesWritten" => Ptr], "Write process memory", ["memory", "debug"]),
            entry!(0x0016, "NtWaitForSingleObject", os, Long, ["Handle" => Ptr, "Alertable" => Int, "Timeout" => Struct("LARGE_INTEGER".into())], "Wait for object", ["sync"]),
            entry!(0x0017, "NtSignalAndWaitForSingleObject", os, Long, ["SignalHandle" => Ptr, "WaitHandle" => Ptr, "Alertable" => Int, "Timeout" => Struct("LARGE_INTEGER".into())], "Signal and wait", ["sync"]),
            entry!(0x0018, "NtWaitForMultipleObjects", os, Long, ["Count" => ULong, "Handles" => Ptr, "WaitType" => Int, "Alertable" => Int, "Timeout" => Struct("LARGE_INTEGER".into())], "Wait for multiple objects", ["sync"]),
            entry!(0x0019, "NtCreateMutant", os, Long, ["MutantHandle" => Ptr, "DesiredAccess" => ULong, "ObjectAttributes" => Struct("OBJECT_ATTRIBUTES".into()), "InitialOwner" => Int], "Create mutex", ["sync"]),
            entry!(0x001A, "NtOpenMutant", os, Long, ["MutantHandle" => Ptr, "DesiredAccess" => ULong, "ObjectAttributes" => Struct("OBJECT_ATTRIBUTES".into())], "Open mutex", ["sync"]),
            entry!(0x001B, "NtReleaseMutant", os, Long, ["MutantHandle" => Ptr, "PreviousCount" => Ptr], "Release mutex", ["sync"]),
            entry!(0x001C, "NtCreateEvent", os, Long, ["EventHandle" => Ptr, "DesiredAccess" => ULong, "ObjectAttributes" => Struct("OBJECT_ATTRIBUTES".into()), "EventType" => Int, "InitialState" => Int], "Create event", ["sync"]),
            entry!(0x001D, "NtOpenEvent", os, Long, ["EventHandle" => Ptr, "DesiredAccess" => ULong, "ObjectAttributes" => Struct("OBJECT_ATTRIBUTES".into())], "Open event", ["sync"]),
            entry!(0x001E, "NtSetEvent", os, Long, ["EventHandle" => Ptr, "PreviousState" => Ptr], "Set event", ["sync"]),
            entry!(0x001F, "NtResetEvent", os, Long, ["EventHandle" => Ptr, "PreviousState" => Ptr], "Reset event", ["sync"]),
            entry!(0x0020, "NtCreateSemaphore", os, Long, ["SemaphoreHandle" => Ptr, "DesiredAccess" => ULong, "ObjectAttributes" => Struct("OBJECT_ATTRIBUTES".into()), "InitialCount" => Long, "MaximumCount" => Long], "Create semaphore", ["sync"]),
            entry!(0x0021, "NtReleaseSemaphore", os, Long, ["SemaphoreHandle" => Ptr, "ReleaseCount" => Long, "PreviousCount" => Ptr], "Release semaphore", ["sync"]),
            entry!(0x0022, "NtCreateSection", os, Long, ["SectionHandle" => Ptr, "DesiredAccess" => ULong, "ObjectAttributes" => Struct("OBJECT_ATTRIBUTES".into()), "MaximumSize" => Ptr, "SectionPageProtection" => ULong], "Create section (shared mem)", ["memory"]),
            entry!(0x0023, "NtMapViewOfSection", os, Long, ["SectionHandle" => Ptr, "ProcessHandle" => Ptr, "BaseAddress" => Ptr, "ZeroBits" => ULong, "CommitSize" => SizeT], "Map view of section", ["memory"]),
            entry!(0x0024, "NtUnmapViewOfSection", os, Long, ["ProcessHandle" => Ptr, "BaseAddress" => Ptr], "Unmap view of section", ["memory"]),
            entry!(0x0025, "NtQuerySystemInformation", os, Long, ["SystemInformationClass" => Int, "SystemInformation" => Ptr, "SystemInformationLength" => ULong, "ReturnLength" => Ptr], "Query system information", ["info"]),
            entry!(0x0026, "NtSetSystemInformation", os, Long, ["SystemInformationClass" => Int, "SystemInformation" => Ptr, "SystemInformationLength" => ULong], "Set system information", ["info"]),
            entry!(0x0027, "NtOpenKey", os, Long, ["KeyHandle" => Ptr, "DesiredAccess" => ULong, "ObjectAttributes" => Struct("OBJECT_ATTRIBUTES".into())], "Open registry key", ["registry"]),
            entry!(0x0028, "NtCreateKey", os, Long, ["KeyHandle" => Ptr, "DesiredAccess" => ULong, "ObjectAttributes" => Struct("OBJECT_ATTRIBUTES".into()), "TitleIndex" => ULong, "Class" => Struct("UNICODE_STRING".into())], "Create registry key", ["registry"]),
            entry!(0x0029, "NtDeleteKey", os, Long, ["KeyHandle" => Ptr], "Delete registry key", ["registry"]),
            entry!(0x002A, "NtQueryValueKey", os, Long, ["KeyHandle" => Ptr, "ValueName" => Struct("UNICODE_STRING".into()), "KeyValueInformationClass" => Int, "KeyValueInformation" => Ptr, "Length" => ULong], "Query registry value", ["registry"]),
            entry!(0x002B, "NtSetValueKey", os, Long, ["KeyHandle" => Ptr, "ValueName" => Struct("UNICODE_STRING".into()), "TitleIndex" => ULong, "Type" => ULong, "Data" => Ptr], "Set registry value", ["registry"]),
            entry!(0x002C, "NtDeleteValueKey", os, Long, ["KeyHandle" => Ptr, "ValueName" => Struct("UNICODE_STRING".into())], "Delete registry value", ["registry"]),
            entry!(0x002D, "NtEnumerateKey", os, Long, ["KeyHandle" => Ptr, "Index" => ULong, "KeyInformationClass" => Int, "KeyInformation" => Ptr, "Length" => ULong], "Enumerate registry keys", ["registry"]),
            entry!(0x002E, "NtEnumerateValueKey", os, Long, ["KeyHandle" => Ptr, "Index" => ULong, "KeyValueInformationClass" => Int, "KeyValueInformation" => Ptr, "Length" => ULong], "Enumerate registry values", ["registry"]),
            entry!(0x002F, "NtCreateToken", os, Long, ["TokenHandle" => Ptr, "DesiredAccess" => ULong, "ObjectAttributes" => Struct("OBJECT_ATTRIBUTES".into()), "TokenType" => Int, "AuthenticationId" => Struct("LUID".into())], "Create security token", ["security"]),
            entry!(0x0030, "NtOpenProcessToken", os, Long, ["ProcessHandle" => Ptr, "DesiredAccess" => ULong, "TokenHandle" => Ptr], "Open process token", ["security"]),
            entry!(0x0031, "NtQueryInformationToken", os, Long, ["TokenHandle" => Ptr, "TokenInformationClass" => Int, "TokenInformation" => Ptr, "TokenInformationLength" => ULong, "ReturnLength" => Ptr], "Query token information", ["security"]),
            entry!(0x0032, "NtAdjustPrivilegesToken", os, Long, ["TokenHandle" => Ptr, "DisableAllPrivileges" => Int, "NewState" => Ptr, "BufferLength" => ULong, "PreviousState" => Ptr], "Adjust token privileges", ["security"]),
            entry!(0x0033, "NtDuplicateToken", os, Long, ["ExistingTokenHandle" => Ptr, "DesiredAccess" => ULong, "ObjectAttributes" => Struct("OBJECT_ATTRIBUTES".into()), "EffectiveOnly" => Int, "TokenType" => Int], "Duplicate token", ["security"]),
        ];

        for e in entries {
            self.insert(e);
        }
    }

    // â"€â"€ macOS BSD loader â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn load_macos_bsd(&mut self) {
        self.load_macos_bsd_part_a();
        self.load_macos_bsd_part_a2();
        self.load_macos_bsd_part_b();
    }

    fn load_macos_bsd_part_a(&mut self) {
        use ArgType::{CStr, ConstPtr, Fd, Flags, Gid, Int, Pid, Ptr, SSizeT, SizeT, Struct, UInt, Uid, Void};
        let os = OsFamily::MacOs;

        let entries = vec![
            entry!(1, "exit", os, Void, ["rval" => Int], "Terminate process", ["process"]),
            entry!(2, "fork", os, Pid, [], "Fork process", ["process"]),
            entry!(3, "read", os, SSizeT, ["fd" => Fd, "buf" => Ptr, "nbyte" => SizeT], "Read from file", ["io"]),
            entry!(4, "write", os, SSizeT, ["fd" => Fd, "buf" => ConstPtr, "nbyte" => SizeT], "Write to file", ["io"]),
            entry!(5, "open", os, Fd, ["path" => CStr, "flags" => Int, "mode" => Flags("mode_t".into())], "Open file", ["io", "fs"]),
            entry!(6, "close", os, Int, ["fd" => Fd], "Close file descriptor", ["io"]),
            entry!(7, "wait4", os, Pid, ["pid" => Pid, "status" => Ptr, "options" => Int, "rusage" => Struct("rusage".into())], "Wait for process", ["process"]),
            entry!(9, "link", os, Int, ["path" => CStr, "link" => CStr], "Create hard link", ["fs"]),
            entry!(10, "unlink", os, Int, ["path" => CStr], "Remove file", ["fs"]),
            entry!(12, "chdir", os, Int, ["path" => CStr], "Change directory", ["fs"]),
            entry!(13, "fchdir", os, Int, ["fd" => Fd], "Change directory by fd", ["fs"]),
            entry!(14, "mknod", os, Int, ["path" => CStr, "mode" => Flags("mode_t".into()), "dev" => Int], "Create special file", ["fs"]),
            entry!(15, "chmod", os, Int, ["path" => CStr, "mode" => Flags("mode_t".into())], "Change file permissions", ["fs"]),
            entry!(16, "chown", os, Int, ["path" => CStr, "uid" => Uid, "gid" => Gid], "Change file ownership", ["fs"]),
            entry!(18, "getfsstat", os, Int, ["buf" => Struct("statfs".into()), "bufsize" => Int, "flags" => Int], "Get filesystem statistics", ["fs"]),
            entry!(20, "getpid", os, Pid, [], "Get process ID", ["process"]),
            entry!(23, "setuid", os, Int, ["uid" => Uid], "Set user ID", ["process"]),
            entry!(24, "getuid", os, Uid, [], "Get user ID", ["process"]),
            entry!(
                25,
                "geteuid",
                os,
                Uid,
                [],
                "Get effective user ID",
                ["process"]
            ),
            entry!(26, "ptrace", os, Int, ["req" => Int, "pid" => Pid, "addr" => Ptr, "data" => Int], "Process trace", ["debug", "process"]),
            entry!(27, "recvmsg", os, SSizeT, ["s" => Fd, "msg" => Struct("msghdr".into()), "flags" => Int], "Receive message", ["net"]),
            entry!(28, "sendmsg", os, SSizeT, ["s" => Fd, "msg" => Struct("msghdr".into()), "flags" => Int], "Send message", ["net"]),
            entry!(29, "recvfrom", os, SSizeT, ["s" => Fd, "buf" => Ptr, "len" => SizeT, "flags" => Int, "from" => Struct("sockaddr".into()), "fromlenaddr" => Ptr], "Receive datagram", ["net"]),
            entry!(30, "accept", os, Fd, ["s" => Fd, "addr" => Struct("sockaddr".into()), "addrlen" => Ptr], "Accept connection", ["net"]),
            entry!(31, "getpeername", os, Int, ["fdes" => Fd, "asa" => Struct("sockaddr".into()), "alen" => Ptr], "Get peer name", ["net"]),
            entry!(32, "getsockname", os, Int, ["fdes" => Fd, "asa" => Struct("sockaddr".into()), "alen" => Ptr], "Get socket name", ["net"]),
            entry!(33, "access", os, Int, ["path" => CStr, "flags" => Int], "Check file access", ["fs"]),
            entry!(34, "chflags", os, Int, ["path" => CStr, "flags" => Int], "Set file flags", ["fs"]),
            entry!(35, "fchflags", os, Int, ["fd" => Fd, "flags" => Int], "Set file flags by fd", ["fs"]),
            entry!(36, "sync", os, Void, [], "Sync filesystems", ["fs"]),
            entry!(37, "kill", os, Int, ["pid" => Pid, "signum" => Int], "Send signal", ["signal", "process"]),
            entry!(
                39,
                "getppid",
                os,
                Pid,
                [],
                "Get parent process ID",
                ["process"]
            ),
            entry!(41, "dup", os, Fd, ["fd" => Fd], "Duplicate fd", ["io"]),
            entry!(42, "pipe", os, Int, [], "Create pipe", ["io"]),
            entry!(
                43,
                "getegid",
                os,
                Gid,
                [],
                "Get effective group ID",
                ["process"]
            ),
            entry!(47, "getgid", os, Gid, [], "Get group ID", ["process"]),
            entry!(48, "sigprocmask", os, Int, ["how" => Int, "mask" => Ptr, "omask" => Ptr], "Manipulate signal mask", ["signal"]),
            entry!(49, "getlogin", os, Int, ["namebuf" => Ptr, "namelen" => UInt], "Get login name", ["process"]),
            entry!(50, "setlogin", os, Int, ["namebuf" => CStr], "Set login name", ["process"]),
        ];

        for e in entries {
            self.insert(e);
        }
    }

    fn load_macos_bsd_part_a2(&mut self) {
        use ArgType::{
            CStr, ConstPtr, Fd, Flags, Int, Long, Pid, Ptr, SSizeT, SizeT, Struct, UInt, ULong,
        };
        let os = OsFamily::MacOs;

        let entries = vec![
            entry!(51, "acct", os, Int, ["path" => CStr], "Enable/disable accounting", ["process"]),
            entry!(53, "sigaltstack", os, Int, ["ss" => Struct("stack_t".into()), "oss" => Struct("stack_t".into())], "Set alternate signal stack", ["signal"]),
            entry!(54, "ioctl", os, Int, ["fd" => Fd, "com" => ULong, "data" => Ptr], "I/O control", ["io"]),
            entry!(55, "reboot", os, Int, ["opt" => Int], "Reboot system", ["info"]),
            entry!(56, "revoke", os, Int, ["path" => CStr], "Revoke file access", ["fs"]),
            entry!(57, "symlink", os, Int, ["path" => CStr, "link" => CStr], "Create symbolic link", ["fs"]),
            entry!(58, "readlink", os, SSizeT, ["path" => CStr, "buf" => Ptr, "count" => Int], "Read symbolic link", ["fs"]),
            entry!(59, "execve", os, Int, ["fname" => CStr, "argp" => Ptr, "envp" => Ptr], "Execute program", ["process"]),
            entry!(60, "umask", os, Flags("mode_t".into()), ["newmask" => Flags("mode_t".into())], "Set file creation mask", ["fs"]),
            entry!(61, "chroot", os, Int, ["path" => CStr], "Change root directory", ["fs"]),
            entry!(65, "msync", os, Int, ["addr" => Ptr, "len" => SizeT, "flags" => Int], "Sync memory", ["memory"]),
            entry!(
                66,
                "vfork",
                os,
                Pid,
                [],
                "Fork with shared memory",
                ["process"]
            ),
            entry!(73, "munmap", os, Int, ["addr" => Ptr, "len" => SizeT], "Unmap memory", ["memory"]),
            entry!(74, "mprotect", os, Int, ["addr" => Ptr, "len" => SizeT, "prot" => Int], "Set memory protection", ["memory"]),
            entry!(75, "madvise", os, Int, ["addr" => Ptr, "len" => SizeT, "behav" => Int], "Memory advice", ["memory"]),
            entry!(78, "mincore", os, Int, ["addr" => Ptr, "len" => SizeT, "vec" => Ptr], "Determine page residency", ["memory"]),
            entry!(79, "getgroups", os, Int, ["gidsetsize" => UInt, "gidset" => Ptr], "Get group set", ["process"]),
            entry!(80, "setgroups", os, Int, ["gidsetsize" => UInt, "gidset" => Ptr], "Set group set", ["process"]),
            entry!(81, "getpgrp", os, Pid, [], "Get process group", ["process"]),
            entry!(82, "setpgid", os, Int, ["pid" => Pid, "pgid" => Pid], "Set process group", ["process"]),
            entry!(83, "setitimer", os, Int, ["which" => UInt, "itv" => Struct("itimerval".into()), "oitv" => Struct("itimerval".into())], "Set interval timer", ["time"]),
            entry!(85, "swapon", os, Int, ["name" => CStr], "Start swapping", ["memory"]),
            entry!(86, "getitimer", os, Int, ["which" => UInt, "itv" => Struct("itimerval".into())], "Get interval timer", ["time"]),
            entry!(90, "dup2", os, Fd, ["from" => Fd, "to" => Fd], "Duplicate fd", ["io"]),
            entry!(92, "fcntl", os, Int, ["fd" => Fd, "cmd" => Int, "arg" => Long], "File control", ["io"]),
            entry!(93, "select", os, Int, ["nd" => Int, "in" => Ptr, "ou" => Ptr, "ex" => Ptr, "tv" => Struct("timeval".into())], "I/O multiplexing", ["io"]),
            entry!(95, "fsync", os, Int, ["fd" => Fd], "Sync file", ["fs", "io"]),
            entry!(96, "setpriority", os, Int, ["which" => Int, "who" => Int, "prio" => Int], "Set program priority", ["process"]),
            entry!(97, "socket", os, Fd, ["domain" => Int, "type" => Int, "protocol" => Int], "Create socket", ["net"]),
            entry!(98, "connect", os, Int, ["s" => Fd, "name" => Struct("sockaddr".into()), "namelen" => Int], "Connect socket", ["net"]),
            entry!(100, "getpriority", os, Int, ["which" => Int, "who" => Int], "Get program priority", ["process"]),
            entry!(104, "bind", os, Int, ["s" => Fd, "name" => Struct("sockaddr".into()), "namelen" => Int], "Bind socket", ["net"]),
            entry!(105, "setsockopt", os, Int, ["s" => Fd, "level" => Int, "name" => Int, "val" => ConstPtr, "valsize" => Int], "Set socket option", ["net"]),
            entry!(106, "listen", os, Int, ["s" => Fd, "backlog" => Int], "Listen for connections", ["net"]),
            entry!(116, "gettimeofday", os, Int, ["tp" => Struct("timeval".into()), "tzp" => Struct("timezone".into())], "Get time of day", ["time"]),
            entry!(117, "getrusage", os, Int, ["who" => Int, "rusage" => Struct("rusage".into())], "Get resource usage", ["process"]),
            entry!(118, "getsockopt", os, Int, ["s" => Fd, "level" => Int, "name" => Int, "val" => Ptr, "avalsize" => Ptr], "Get socket option", ["net"]),
            entry!(120, "readv", os, SSizeT, ["fd" => Fd, "iovp" => Struct("iovec".into()), "iovcnt" => UInt], "Scatter read", ["io"]),
            entry!(121, "writev", os, SSizeT, ["fd" => Fd, "iovp" => Struct("iovec".into()), "iovcnt" => UInt], "Gather write", ["io"]),
            entry!(122, "settimeofday", os, Int, ["tv" => Struct("timeval".into()), "tzp" => Struct("timezone".into())], "Set time of day", ["time"]),
        ];

        for e in entries {
            self.insert(e);
        }
    }

    fn load_macos_bsd_part_b(&mut self) {
        use ArgType::{
            CStr, ConstPtr, Fd, Flags, Gid, Int, Long, Ptr, SSizeT, SizeT, Struct, UInt, Uid,
        };
        let os = OsFamily::MacOs;

        let entries = vec![
            entry!(123, "fchown", os, Int, ["fd" => Fd, "uid" => Uid, "gid" => Gid], "Change file ownership by fd", ["fs"]),
            entry!(124, "fchmod", os, Int, ["fd" => Fd, "mode" => Flags("mode_t".into())], "Change file permissions by fd", ["fs"]),
            entry!(126, "setreuid", os, Int, ["ruid" => Uid, "euid" => Uid], "Set real/effective user ID", ["process"]),
            entry!(127, "setregid", os, Int, ["rgid" => Gid, "egid" => Gid], "Set real/effective group ID", ["process"]),
            entry!(128, "rename", os, Int, ["from" => CStr, "to" => CStr], "Rename file", ["fs"]),
            entry!(131, "flock", os, Int, ["fd" => Fd, "how" => Int], "Advisory lock file", ["fs"]),
            entry!(132, "mkfifo", os, Int, ["path" => CStr, "mode" => Flags("mode_t".into())], "Create named pipe", ["fs"]),
            entry!(133, "sendto", os, SSizeT, ["s" => Fd, "buf" => ConstPtr, "len" => SizeT, "flags" => Int, "to" => Struct("sockaddr".into()), "tolen" => Int], "Send datagram", ["net"]),
            entry!(134, "shutdown", os, Int, ["s" => Fd, "how" => Int], "Shutdown socket", ["net"]),
            entry!(135, "socketpair", os, Int, ["domain" => Int, "type" => Int, "protocol" => Int, "rsv" => Ptr], "Create socket pair", ["net"]),
            entry!(136, "mkdir", os, Int, ["path" => CStr, "mode" => Flags("mode_t".into())], "Create directory", ["fs"]),
            entry!(137, "rmdir", os, Int, ["path" => CStr], "Remove directory", ["fs"]),
            entry!(138, "utimes", os, Int, ["path" => CStr, "tptr" => Struct("timeval".into())], "Set file times", ["fs"]),
            entry!(152, "pread", os, SSizeT, ["fd" => Fd, "buf" => Ptr, "nbyte" => SizeT, "offset" => Long], "Positioned read", ["io"]),
            entry!(153, "pwrite", os, SSizeT, ["fd" => Fd, "buf" => ConstPtr, "nbyte" => SizeT, "offset" => Long], "Positioned write", ["io"]),
            entry!(161, "getrlimit", os, Int, ["which" => UInt, "rlp" => Struct("rlimit".into())], "Get resource limits", ["process"]),
            entry!(162, "setrlimit", os, Int, ["which" => UInt, "rlp" => Struct("rlimit".into())], "Set resource limits", ["process"]),
            entry!(169, "poll", os, Int, ["fds" => Struct("pollfd".into()), "nfds" => UInt, "timeout" => Int], "Poll for events", ["io"]),
            entry!(180, "lchown", os, Int, ["path" => CStr, "uid" => Uid, "gid" => Gid], "Change symlink ownership", ["fs"]),
            entry!(197, "mmap", os, Ptr, ["addr" => Ptr, "len" => SizeT, "prot" => Int, "flags" => Int, "fd" => Fd, "pos" => Long], "Map memory", ["memory"]),
            entry!(199, "lseek", os, Long, ["fd" => Fd, "offset" => Long, "whence" => Int], "Reposition file offset", ["io"]),
            entry!(200, "truncate", os, Int, ["path" => CStr, "length" => Long], "Truncate file", ["fs"]),
            entry!(201, "ftruncate", os, Int, ["fd" => Fd, "length" => Long], "Truncate file by fd", ["fs"]),
            entry!(202, "sysctl", os, Int, ["name" => Ptr, "namelen" => UInt, "oldp" => Ptr, "oldlenp" => Ptr, "newp" => Ptr], "Get/set system information", ["info"]),
            entry!(220, "getdirentriesattr", os, Int, ["fd" => Fd, "alist" => Ptr, "buffer" => Ptr, "buffersize" => SizeT], "Get directory entries attributes", ["fs"]),
            entry!(266, "shm_open", os, Fd, ["name" => CStr, "oflag" => Int, "mode" => Flags("mode_t".into())], "Open POSIX shared memory", ["memory"]),
            entry!(267, "shm_unlink", os, Int, ["name" => CStr], "Remove POSIX shared memory", ["memory"]),
            entry!(268, "sem_open", os, Ptr, ["name" => CStr, "oflag" => Int, "mode" => Flags("mode_t".into()), "value" => UInt], "Open POSIX semaphore", ["sync"]),
            entry!(269, "sem_close", os, Int, ["sem" => Ptr], "Close POSIX semaphore", ["sync"]),
            entry!(270, "sem_unlink", os, Int, ["name" => CStr], "Remove POSIX semaphore", ["sync"]),
            entry!(271, "sem_wait", os, Int, ["sem" => Ptr], "Wait on semaphore", ["sync"]),
            entry!(272, "sem_trywait", os, Int, ["sem" => Ptr], "Try wait on semaphore", ["sync"]),
            entry!(273, "sem_post", os, Int, ["sem" => Ptr], "Post semaphore", ["sync"]),
            entry!(274, "sysctlbyname", os, Int, ["name" => CStr, "oldp" => Ptr, "oldlenp" => Ptr, "newp" => Ptr, "newlen" => SizeT], "sysctl by name", ["info"]),
            entry!(286, "pthread_kill", os, Int, ["thread" => Ptr, "sig" => Int], "Send signal to thread", ["signal", "thread"]),
            entry!(287, "pthread_sigmask", os, Int, ["how" => Int, "set" => Ptr, "oset" => Ptr], "Set thread signal mask", ["signal", "thread"]),
            entry!(296, "msleep_continue", os, Int, ["chan" => Ptr, "mtx" => Ptr, "pri" => Int, "wmesg" => CStr, "sbt" => Long], "Sleep on channel", ["sync"]),
            entry!(338, "stat64", os, Int, ["path" => CStr, "ub" => Struct("stat64".into())], "Get file status (64-bit)", ["fs"]),
            entry!(339, "fstat64", os, Int, ["fd" => Fd, "ub" => Struct("stat64".into())], "Get file status by fd (64-bit)", ["fs"]),
            entry!(340, "lstat64", os, Int, ["path" => CStr, "ub" => Struct("stat64".into())], "Get symlink status (64-bit)", ["fs"]),
            entry!(344, "getdirentries64", os, SSizeT, ["fd" => Fd, "buf" => Ptr, "bufsize" => SizeT, "position" => Ptr], "Get directory entries (64-bit)", ["fs"]),
            entry!(345, "statfs64", os, Int, ["path" => CStr, "buf" => Struct("statfs64".into())], "Get filesystem status (64-bit)", ["fs"]),
            entry!(346, "fstatfs64", os, Int, ["fd" => Fd, "buf" => Struct("statfs64".into())], "Get filesystem status by fd (64-bit)", ["fs"]),
            entry!(365, "kqueue", os, Fd, [], "Create kqueue", ["io"]),
            entry!(366, "kevent", os, Int, ["kq" => Fd, "changelist" => Struct("kevent".into()), "nchanges" => Int, "eventlist" => Struct("kevent".into()), "nevents" => Int], "Monitor events", ["io"]),
            entry!(369, "sigaction", os, Int, ["signum" => Int, "act" => Struct("sigaction".into()), "oact" => Struct("sigaction".into())], "Set signal action", ["signal"]),
            entry!(370, "sigpending", os, Int, ["osset" => Ptr], "Get pending signals", ["signal"]),
            entry!(371, "sigprocmask", os, Int, ["how" => Int, "mask" => Ptr, "omask" => Ptr], "Set signal mask", ["signal"]),
            entry!(372, "sigwait", os, Int, ["set" => Ptr, "sig" => Ptr], "Wait for signal", ["signal"]),
            entry!(373, "sigsuspend", os, Int, ["sigmask" => Ptr], "Suspend with signal mask", ["signal"]),
        ];

        for e in entries {
            self.insert(e);
        }
    }
}

// â"€â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    fn make_db() -> SyscallDb {
        SyscallDb::with_defaults()
    }

    #[test]
    fn test_db_not_empty() {
        let db = make_db();
        assert!(db.len() > 50);
    }

    #[test]
    fn test_linux_read() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Linux, 0).unwrap();
        assert_eq!(e.name, "read");
        assert_eq!(e.args.len(), 3);
    }

    #[test]
    fn test_linux_write() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Linux, 1).unwrap();
        assert_eq!(e.name, "write");
    }

    #[test]
    fn test_linux_mmap() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Linux, 9).unwrap();
        assert_eq!(e.name, "mmap");
        assert!(e.is_memory());
    }

    #[test]
    fn test_linux_lookup_by_name() {
        let db = make_db();
        let e = db.lookup_by_name(OsFamily::Linux, "execve").unwrap();
        assert_eq!(e.number, 59);
    }

    #[test]
    fn test_linux_exit_group() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Linux, 231).unwrap();
        assert_eq!(e.name, "exit_group");
    }

    #[test]
    fn test_linux_socket() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Linux, 41).unwrap();
        assert_eq!(e.name, "socket");
        assert!(e.tags.contains(&"net".to_string()));
    }

    #[test]
    fn test_linux_ptrace() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Linux, 101).unwrap();
        assert_eq!(e.name, "ptrace");
        assert!(e.tags.contains(&"debug".to_string()));
    }

    #[test]
    fn test_nt_create_file() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Windows, 0x0002).unwrap();
        assert_eq!(e.name, "NtCreateFile");
    }

    #[test]
    fn test_nt_close() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Windows, 0x0004).unwrap();
        assert_eq!(e.name, "NtClose");
    }

    #[test]
    fn test_nt_allocate_virtual_memory() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Windows, 0x0007).unwrap();
        assert_eq!(e.name, "NtAllocateVirtualMemory");
        assert!(e.is_memory());
    }

    #[test]
    fn test_nt_registry_open_key() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Windows, 0x0027).unwrap();
        assert_eq!(e.name, "NtOpenKey");
        assert!(e.tags.contains(&"registry".to_string()));
    }

    #[test]
    fn test_nt_lookup_by_name() {
        let db = make_db();
        let e = db
            .lookup_by_name(OsFamily::Windows, "NtWriteVirtualMemory")
            .unwrap();
        assert_eq!(e.number, 0x0015);
    }

    #[test]
    fn test_macos_read() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::MacOs, 3).unwrap();
        assert_eq!(e.name, "read");
    }

    #[test]
    fn test_macos_mmap() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::MacOs, 197).unwrap();
        assert_eq!(e.name, "mmap");
    }

    #[test]
    fn test_macos_kqueue() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::MacOs, 365).unwrap();
        assert_eq!(e.name, "kqueue");
    }

    #[test]
    fn test_prototype_format() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Linux, 0).unwrap();
        let proto = e.prototype();
        assert!(proto.contains("read"));
        assert!(proto.contains("fd"));
    }

    #[test]
    fn test_entries_for_os() {
        let db = make_db();
        let linux: Vec<_> = db.entries_for_os(OsFamily::Linux).collect();
        assert!(!linux.is_empty());
        for e in &linux {
            assert_eq!(e.os, OsFamily::Linux);
        }
    }

    #[test]
    fn test_entries_with_tag_memory() {
        let db = make_db();
        let mem = db.entries_with_tag("memory");
        assert!(mem.len() >= 5);
    }

    #[test]
    fn test_entries_with_tag_net() {
        let db = make_db();
        let net = db.entries_with_tag("net");
        assert!(net.len() >= 10);
    }

    #[test]
    fn test_not_found_returns_none() {
        let db = make_db();
        assert!(db.lookup_by_number(OsFamily::Linux, 99999).is_none());
    }

    #[test]
    fn test_arg_type_display() {
        assert_eq!(ArgType::Fd.to_string(), "int /*fd*/");
        assert_eq!(ArgType::Ptr.to_string(), "void *");
        assert_eq!(ArgType::CStr.to_string(), "const char *");
    }

    #[test]
    fn test_syscall_arg_display() {
        let a = SyscallArg::new("buf", ArgType::Ptr);
        assert_eq!(a.to_string(), "void * buf");
    }

    #[test]
    fn test_linux_getrandom() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Linux, 318).unwrap();
        assert_eq!(e.name, "getrandom");
        assert!(e.tags.contains(&"security".to_string()));
    }

    #[test]
    fn test_linux_futex() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Linux, 202).unwrap();
        assert_eq!(e.name, "futex");
        assert!(e.tags.contains(&"thread".to_string()));
    }

    #[test]
    fn test_is_io_flag() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Linux, 0).unwrap();
        assert!(e.is_io());
        let e2 = db.lookup_by_number(OsFamily::Linux, 39).unwrap();
        assert!(!e2.is_io());
    }

    #[test]
    fn test_os_family_display() {
        assert_eq!(OsFamily::Linux.to_string(), "linux");
        assert_eq!(OsFamily::Windows.to_string(), "windows");
        assert_eq!(OsFamily::MacOs.to_string(), "macos");
    }

    #[test]
    fn test_linux_openat() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Linux, 257).unwrap();
        assert_eq!(e.name, "openat");
        assert!(e.is_io());
    }

    #[test]
    fn test_linux_clone() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Linux, 56).unwrap();
        assert_eq!(e.name, "clone");
        assert!(e.is_process());
    }

    #[test]
    fn test_nt_map_view() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Windows, 0x0023).unwrap();
        assert_eq!(e.name, "NtMapViewOfSection");
        assert!(e.is_memory());
    }

    #[test]
    fn test_macos_kqueue_io() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::MacOs, 365).unwrap();
        assert_eq!(e.name, "kqueue");
        assert!(e.is_io());
    }

    #[test]
    fn test_prototype_contains_return_type() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Linux, 1).unwrap();
        let p = e.prototype();
        assert!(p.contains("ssize_t") || p.contains("write"));
    }

    #[test]
    fn test_entries_with_tag_process() {
        let db = make_db();
        let procs = db.entries_with_tag("process");
        assert!(!procs.is_empty());
        for e in &procs {
            assert!(e.tags.contains(&"process".to_string()));
        }
    }

    #[test]
    fn test_db_len_increases_after_insert() {
        let mut db = SyscallDb::new();
        let before = db.len();
        db.insert(entry!(
            9999,
            "test_syscall",
            OsFamily::Linux,
            ArgType::Int,
            [],
            "test",
            []
        ));
        assert_eq!(db.len(), before + 1);
    }

    #[test]
    fn test_linux_statx() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Linux, 332).unwrap();
        assert_eq!(e.name, "statx");
    }

    #[test]
    fn test_nt_read_virtual_memory() {
        let db = make_db();
        let e = db.lookup_by_number(OsFamily::Windows, 0x0014).unwrap();
        assert_eq!(e.name, "NtReadVirtualMemory");
        assert!(e.is_memory());
    }
}
