//! `syscall_emulation` — Syscall interception and emulation layer.
//!
//! Hooks SYSCALL/SYSENTER instructions in the emulator and dispatches them to
//! Rust implementations covering a subset of Linux x86-64 syscalls including
//! memory management, file I/O (virtual FS), process control stubs, and exit.
//! Designed to work with the `Emulator` trait defined in `rustre-emu::lib`.
//!
//! # Relationship to other syscall modules
//!
//! This module is the *register-context layer*. It takes a [`RegisterContext`]
//! snapshot directly and does not require the `crate::Emulator` trait. It owns a
//! [`VirtualFs`] (simple path-keyed store) and a [`VirtualMemory`] (page-granular
//! mmap tracker). Linux x86-64 only.
//!
//! Compare with the other two syscall modules:
//!
//! * **`os_syscall_model`** — multi-OS reference tables, dispatch, interceptors,
//!   and pattern detection; no `Emulator` dependency.
//! * **`os_emulation`** — full `OsEmulator`/`OsEmuSession` integration that reads
//!   and writes real emulator registers and supports multiple architectures.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── Width-narrowing helpers ──────────────────────────────────────────────────
// The syscall ABI passes every argument as a `u64`, but the kernel-level
// semantics are typed (file descriptor = i32, prot/flags = u32, etc.). These
// helpers centralise the narrowing conversion using bitwise mask + `cast_*`
// so the lossy `as` keyword does not appear at hundreds of call sites and
// `clippy::cast_possible_truncation` / `cast_sign_loss` stay green.

/// 64 MiB cap on read/write byte counts to avoid OOM from attacker input.
const SYSCALL_MAX_RW: usize = 64 * 1024 * 1024;

#[inline]
#[must_use]
fn u32_from_arg(arg: u64) -> u32 {
    u32::try_from(arg & 0xFFFF_FFFF).unwrap_or(u32::MAX)
}

#[inline]
#[must_use]
fn i32_from_arg(arg: u64) -> i32 {
    u32_from_arg(arg).cast_signed()
}

#[inline]
#[must_use]
const fn u32_from_i32(v: i32) -> u32 {
    v.cast_unsigned()
}

#[inline]
#[must_use]
fn usize_clamped(arg: u64, cap: usize) -> usize {
    usize::try_from(arg).unwrap_or(cap).min(cap)
}

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SyscallError {
    #[error("unknown syscall: {0}")]
    Unknown(u64),
    #[error("bad file descriptor: {0}")]
    BadFd(i32),
    #[error("no memory available for size {0:#x}")]
    OutOfMemory(u64),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("file not found: {0}")]
    NotFound(String),
    #[error("invalid argument: {0}")]
    InvalidArg(String),
    #[error("not implemented: syscall {0} ({1})")]
    NotImpl(u64, String),
    #[error("process exit: code {0}")]
    Exit(i32),
}

// ─── Linux Syscall Numbers (x86-64) ──────────────────────────────────────────

pub mod linux_x64 {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const OPEN: u64 = 2;
    pub const CLOSE: u64 = 3;
    pub const STAT: u64 = 4;
    pub const FSTAT: u64 = 5;
    pub const LSTAT: u64 = 6;
    pub const MMAP: u64 = 9;
    pub const MPROTECT: u64 = 10;
    pub const MUNMAP: u64 = 11;
    pub const BRK: u64 = 12;
    pub const IOCTL: u64 = 16;
    pub const GETPID: u64 = 39;
    pub const CLONE: u64 = 56;
    pub const FORK: u64 = 57;
    pub const VFORK: u64 = 58;
    pub const EXECVE: u64 = 59;
    pub const EXIT: u64 = 60;
    pub const WAIT4: u64 = 61;
    pub const KILL: u64 = 62;
    pub const UNAME: u64 = 63;
    pub const GETUID: u64 = 102;
    pub const GETGID: u64 = 104;
    pub const GETEUID: u64 = 107;
    pub const GETEGID: u64 = 108;
    pub const ARCH_PRCTL: u64 = 158;
    pub const EXIT_GROUP: u64 = 231;
    pub const OPENAT: u64 = 257;
    pub const NEWFSTATAT: u64 = 262;
}

// ─── Register Context ─────────────────────────────────────────────────────────

/// Snapshot of CPU registers at the point of a syscall.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterContext {
    pub rax: u64, // syscall number on entry, return value on exit
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r8: u64,
    pub r9: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rflags: u64,
}

impl RegisterContext {
    #[must_use] 
    pub const fn syscall_nr(&self) -> u64 {
        self.rax
    }

    #[must_use] 
    pub const fn arg0(&self) -> u64 { self.rdi }
    #[must_use] 
    pub const fn arg1(&self) -> u64 { self.rsi }
    #[must_use] 
    pub const fn arg2(&self) -> u64 { self.rdx }
    #[must_use] 
    pub const fn arg3(&self) -> u64 { self.r10 }
    #[must_use] 
    pub const fn arg4(&self) -> u64 { self.r8 }
    #[must_use] 
    pub const fn arg5(&self) -> u64 { self.r9 }

    pub const fn set_return(&mut self, value: i64) {
        self.rax = value.cast_unsigned();
    }
}

// ─── Syscall Event ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    pub timestamp: u64,
    pub syscall_nr: u64,
    pub name: String,
    pub args: Vec<u64>,
    pub return_value: i64,
    pub address: u64,
}

// ─── Virtual File System ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualFile {
    pub path: String,
    pub content: Vec<u8>,
    pub flags: u32,
    pub mode: u32,
}

#[derive(Debug, Default)]
pub struct VirtualFs {
    files: HashMap<String, VirtualFile>,
    /// Open file descriptor table: fd → (path, offset)
    fds: HashMap<i32, (String, usize)>,
    next_fd: i32,
}

impl VirtualFs {
    #[must_use] 
    pub fn new() -> Self {
        let mut vfs = Self {
            files: HashMap::new(),
            fds: HashMap::new(),
            next_fd: 3, // 0/1/2 = stdin/stdout/stderr
        };
        // Pre-populate some basic Linux files
        vfs.add_file("/proc/self/maps", b"00400000-00401000 r-xp 00000000 00:00 0\n".to_vec());
        vfs.add_file("/etc/hostname", b"sandbox\n".to_vec());
        vfs.add_file("/etc/os-release", b"ID=linux\n".to_vec());
        vfs
    }

    pub fn add_file(&mut self, path: &str, content: Vec<u8>) {
        self.files.insert(path.to_owned(), VirtualFile {
            path: path.to_owned(),
            content,
            flags: 0,
            mode: 0o644,
        });
    }

    /// Open a virtual file.
    ///
    /// # Errors
    /// Returns `SyscallError::NotFound` if the path is unknown.
    pub fn open(&mut self, path: &str, _flags: u32) -> Result<i32, SyscallError> {
        if !self.files.contains_key(path) {
            return Err(SyscallError::NotFound(path.to_owned()));
        }
        let fd = self.next_fd;
        self.next_fd += 1;
        self.fds.insert(fd, (path.to_owned(), 0));
        Ok(fd)
    }

    /// Close a previously opened file descriptor.
    ///
    /// # Errors
    /// Returns `SyscallError::BadFd` if `fd` is not currently open.
    pub fn close(&mut self, fd: i32) -> Result<(), SyscallError> {
        self.fds.remove(&fd).ok_or(SyscallError::BadFd(fd))?;
        Ok(())
    }

    /// Read up to `buf_size` bytes from the open file at `fd`.
    ///
    /// # Errors
    /// Returns `SyscallError::BadFd` if `fd` is not open, or
    /// `SyscallError::NotFound` if the backing file disappeared.
    pub fn read(&mut self, fd: i32, buf_size: usize) -> Result<Vec<u8>, SyscallError> {
        let (path, offset) = self.fds.get_mut(&fd).ok_or(SyscallError::BadFd(fd))?;
        let file = self.files.get(path.as_str()).ok_or_else(|| SyscallError::NotFound(path.clone()))?;
        let start = *offset;
        let end = (start + buf_size).min(file.content.len());
        let data = file.content[start..end].to_vec();
        // Update the mutable borrow via the fd entry again
        if let Some((_, off)) = self.fds.get_mut(&fd) {
            *off += data.len();
        }
        Ok(data)
    }

    /// Write `data` to the open file at `fd`.
    ///
    /// # Errors
    /// Returns `SyscallError::BadFd` if `fd` is not open, or
    /// `SyscallError::NotFound` if the backing file disappeared.
    pub fn write(&mut self, fd: i32, data: &[u8]) -> Result<usize, SyscallError> {
        // Cap virtual file size at 64 MiB to prevent unbounded heap growth
        // driven by attacker-controlled write() calls.
        const MAX_FILE_SIZE: usize = 64 * 1024 * 1024;
        match fd {
            1 | 2 => {
                // stdout/stderr — just record
                Ok(data.len())
            }
            _ => {
                let path = self.fds.get(&fd).ok_or(SyscallError::BadFd(fd))?.0.clone();
                if let Some(file) = self.files.get_mut(&path) {
                    let available = MAX_FILE_SIZE.saturating_sub(file.content.len());
                    let n = data.len().min(available);
                    file.content.extend_from_slice(&data[..n]);
                    Ok(n)
                } else {
                    Err(SyscallError::NotFound(path))
                }
            }
        }
    }

    #[must_use] 
    pub fn stat_size(&self, path: &str) -> Option<u64> {
        self.files.get(path).map(|f| f.content.len()).map(|n| u64::try_from(n).unwrap_or(u64::MAX))
    }
}

// ─── Virtual Memory Allocator ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub prot: u32,
    pub flags: u32,
    pub fd: i32,
    pub offset: u64,
    pub label: String,
}

impl MemoryRegion {
    pub const PROT_NONE: u32 = 0;
    pub const PROT_READ: u32 = 1;
    pub const PROT_WRITE: u32 = 2;
    pub const PROT_EXEC: u32 = 4;
    pub const MAP_ANON: u32 = 0x20;
    pub const MAP_PRIVATE: u32 = 0x02;
    pub const MAP_FIXED: u32 = 0x10;

    #[must_use] 
    pub const fn is_executable(&self) -> bool {
        (self.prot & Self::PROT_EXEC) != 0
    }
}

/// Parameters for `VirtualMemory::mmap`.
///
/// Grouped to keep the function signature within clippy's
/// `too_many_arguments` threshold while preserving the POSIX-style
/// argument set.
#[derive(Debug, Clone, Copy)]
pub struct MmapRequest<'a> {
    pub addr: u64,
    pub length: u64,
    pub prot: u32,
    pub flags: u32,
    pub fd: i32,
    pub offset: u64,
    pub label: &'a str,
}

#[derive(Debug)]
pub struct VirtualMemory {
    regions: Vec<MemoryRegion>,
    /// Next hint address for new allocations.
    next_hint: u64,
    page_size: u64,
    /// Simulated program break.
    brk: u64,
    /// Initial brk.
    initial_brk: u64,
}

impl VirtualMemory {
    #[must_use] 
    pub const fn new(base: u64) -> Self {
        Self {
            regions: Vec::new(),
            next_hint: base,
            page_size: 0x1000,
            brk: base + 0x1_000_000,
            initial_brk: base + 0x1_000_000,
        }
    }

    const fn align_up(addr: u64, align: u64) -> u64 {
        (addr + align - 1) & !(align - 1)
    }

    /// Map a new memory region.
    ///
    /// # Errors
    /// Returns `SyscallError::InvalidArg` for zero-length requests, or
    /// `SyscallError::OutOfMemory` if the request exceeds per-region or
    /// total-region caps.
    pub fn mmap(&mut self, req: MmapRequest<'_>) -> Result<u64, SyscallError> {
        // Cap individual mmap size and total region count to prevent
        // attacker-driven unbounded growth of the `regions` Vec.
        const MAX_MMAP_SIZE: u64 = 1 << 30; // 1 GiB per region
        const MAX_REGIONS: usize = 65536;
        let MmapRequest { addr, length, prot, flags, fd, offset, label } = req;
        if length == 0 {
            return Err(SyscallError::InvalidArg("mmap length=0".to_owned()));
        }
        if length > MAX_MMAP_SIZE {
            return Err(SyscallError::OutOfMemory(length));
        }
        if self.regions.len() >= MAX_REGIONS {
            return Err(SyscallError::OutOfMemory(length));
        }
        let size = Self::align_up(length, self.page_size);
        let base = if addr != 0 && (flags & MemoryRegion::MAP_FIXED) != 0 {
            addr
        } else if addr != 0 {
            // Hint; check if free
            addr
        } else {
            let hint = self.next_hint;
            self.next_hint = hint + size + self.page_size; // leave guard page
            hint
        };

        self.regions.push(MemoryRegion {
            base,
            size,
            prot,
            flags,
            fd,
            offset,
            label: label.to_owned(),
        });
        Ok(base)
    }

    /// Remove regions matching `addr`/`length`.
    ///
    /// # Errors
    /// Currently infallible (returns `Ok(())`); kept as `Result` to match the
    /// POSIX signature and allow future failure modes.
    pub fn munmap(&mut self, addr: u64, length: u64) -> Result<(), SyscallError> {
        let size = Self::align_up(length, self.page_size);
        let before = self.regions.len();
        self.regions.retain(|r| r.base != addr || r.size != size);
        if self.regions.len() == before {
            // Partial unmap — just remove regions that overlap
            self.regions.retain(|r| r.base + r.size <= addr || r.base >= addr + size);
        }
        Ok(())
    }

    /// Change protection on the region at `addr`.
    ///
    /// # Errors
    /// Returns `SyscallError::InvalidArg` if no region exactly matches.
    pub fn mprotect(&mut self, addr: u64, length: u64, prot: u32) -> Result<(), SyscallError> {
        let size = Self::align_up(length, self.page_size);
        for r in &mut self.regions {
            if r.base == addr && r.size == size {
                r.prot = prot;
                return Ok(());
            }
        }
        // Attempt to mprotect non-mapped region
        Err(SyscallError::InvalidArg(format!("mprotect: no region at {addr:#x}")))
    }

    pub const fn brk(&mut self, new_brk: u64) -> u64 {
        if new_brk != 0 && new_brk >= self.initial_brk {
            self.brk = new_brk;
        }
        self.brk
    }

    #[must_use] 
    pub fn find_region(&self, addr: u64) -> Option<&MemoryRegion> {
        self.regions.iter().find(|r| addr >= r.base && addr < r.base + r.size)
    }

    #[must_use] 
    pub fn executable_regions(&self) -> Vec<&MemoryRegion> {
        self.regions.iter().filter(|r| r.is_executable()).collect()
    }
}

// ─── Syscall Dispatcher ───────────────────────────────────────────────────────

/// Result of a syscall: the return value to write into rax.
#[derive(Debug, Clone)]
pub enum SyscallResult {
    Ok(i64),
    Exit(i32),
}

/// The syscall emulation engine.
#[derive(Debug)]
pub struct SyscallEmulator {
    pub vfs: VirtualFs,
    pub vmem: VirtualMemory,
    pub event_log: Vec<SyscallEvent>,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    /// Emulated child process stubs (for clone/fork).
    pub child_pids: Vec<u32>,
    /// Allow list of syscalls — if non-empty, all others → ENOSYS.
    pub allow_list: Vec<u64>,
    /// Whether to log every syscall event.
    pub log_events: bool,
    event_counter: u64,
}

impl SyscallEmulator {
    #[must_use] 
    pub fn new(mem_base: u64) -> Self {
        Self {
            vfs: VirtualFs::new(),
            vmem: VirtualMemory::new(mem_base),
            event_log: Vec::new(),
            pid: 1234,
            uid: 1000,
            gid: 1000,
            child_pids: Vec::new(),
            allow_list: Vec::new(),
            log_events: true,
            event_counter: 0,
        }
    }

    fn log(&mut self, nr: u64, name: &str, args: Vec<u64>, ret: i64, rip: u64) {
        if self.log_events {
            self.event_log.push(SyscallEvent {
                timestamp: self.event_counter,
                syscall_nr: nr,
                name: name.to_owned(),
                args,
                return_value: ret,
                address: rip,
            });
            self.event_counter += 1;
        }
    }

    /// Dispatch a syscall given the register context.
    /// Returns the value to write into rax.
    pub fn dispatch(&mut self, ctx: &RegisterContext) -> SyscallResult {
        let nr = ctx.syscall_nr();
        let rip = ctx.rip;

        // Allow-list check
        if !self.allow_list.is_empty() && !self.allow_list.contains(&nr) {
            self.log(nr, "DENIED", vec![ctx.arg0(), ctx.arg1(), ctx.arg2()], -38, rip);
            return SyscallResult::Ok(-38); // ENOSYS
        }

        match nr {
            linux_x64::READ => self.sys_read(ctx, rip),
            linux_x64::WRITE => self.sys_write(ctx, rip),
            linux_x64::OPEN | linux_x64::OPENAT => self.sys_open(ctx, rip),
            linux_x64::CLOSE => self.sys_close(ctx, rip),
            linux_x64::MMAP => self.sys_mmap(ctx, rip),
            linux_x64::MPROTECT => self.sys_mprotect(ctx, rip),
            linux_x64::MUNMAP => self.sys_munmap(ctx, rip),
            linux_x64::BRK => self.sys_brk(ctx, rip),
            linux_x64::GETPID => {
                let pid = i64::from(self.pid);
                self.log(nr, "getpid", vec![], pid, rip);
                SyscallResult::Ok(pid)
            }
            linux_x64::GETUID | linux_x64::GETEUID => {
                let uid = i64::from(self.uid);
                self.log(nr, "getuid", vec![], uid, rip);
                SyscallResult::Ok(uid)
            }
            linux_x64::GETGID | linux_x64::GETEGID => {
                let gid = i64::from(self.gid);
                self.log(nr, "getgid", vec![], gid, rip);
                SyscallResult::Ok(gid)
            }
            linux_x64::CLONE => self.sys_clone(ctx, rip),
            linux_x64::FORK | linux_x64::VFORK => self.sys_fork(ctx, rip),
            linux_x64::EXIT | linux_x64::EXIT_GROUP => {
                let code = i32_from_arg(ctx.arg0());
                self.log(nr, "exit", vec![ctx.arg0()], 0, rip);
                SyscallResult::Exit(code)
            }
            linux_x64::UNAME => self.sys_uname(ctx, rip),
            linux_x64::ARCH_PRCTL => {
                // Mostly used to set FS_BASE for TLS — return success
                self.log(nr, "arch_prctl", vec![ctx.arg0(), ctx.arg1()], 0, rip);
                SyscallResult::Ok(0)
            }
            linux_x64::STAT | linux_x64::FSTAT | linux_x64::LSTAT | linux_x64::NEWFSTATAT => {
                // Return -ENOENT for now (virtual)
                self.log(nr, "stat", vec![ctx.arg0(), ctx.arg1()], -2, rip);
                SyscallResult::Ok(-2)
            }
            linux_x64::IOCTL => {
                self.log(nr, "ioctl", vec![ctx.arg0(), ctx.arg1(), ctx.arg2()], -25, rip);
                SyscallResult::Ok(-25) // ENOTTY
            }
            linux_x64::KILL => {
                let sig = ctx.arg1();
                self.log(nr, "kill", vec![ctx.arg0(), sig], 0, rip);
                SyscallResult::Ok(0)
            }
            _ => {
                let name = syscall_name(nr);
                self.log(nr, &name, vec![ctx.arg0(), ctx.arg1(), ctx.arg2()], -38, rip);
                SyscallResult::Ok(-38) // ENOSYS
            }
        }
    }

    // ── Syscall implementations ───────────────────────────────────────────────

    fn sys_read(&mut self, ctx: &RegisterContext, rip: u64) -> SyscallResult {
        let fd = i32_from_arg(ctx.arg0());
        let count = usize_clamped(ctx.arg2(), SYSCALL_MAX_RW);
        let count_u64 = u64::try_from(count).unwrap_or(u64::MAX);
        let fd_u64 = u32_from_i32(fd).into();
        match self.vfs.read(fd, count) {
            Ok(data) => {
                let n = i64::try_from(data.len()).unwrap_or(i64::MAX);
                self.log(linux_x64::READ, "read", vec![fd_u64, ctx.arg1(), count_u64], n, rip);
                // In a real emulator we'd write `data` to emulated memory at arg1
                SyscallResult::Ok(n)
            }
            Err(SyscallError::BadFd(_)) => {
                self.log(linux_x64::READ, "read", vec![fd_u64, ctx.arg1(), count_u64], -9, rip);
                SyscallResult::Ok(-9) // EBADF
            }
            Err(_) => SyscallResult::Ok(-5), // EIO
        }
    }

    fn sys_write(&mut self, ctx: &RegisterContext, rip: u64) -> SyscallResult {
        let fd = i32_from_arg(ctx.arg0());
        let count = usize_clamped(ctx.arg2(), SYSCALL_MAX_RW);
        let count_u64 = u64::try_from(count).unwrap_or(u64::MAX);
        let fd_u64 = u32_from_i32(fd).into();
        // In a real emulator we'd read `count` bytes from emulated memory at arg1
        let dummy_data = vec![b'X'; count.min(4096)];
        match self.vfs.write(fd, &dummy_data) {
            Ok(n) => {
                let n_i64 = i64::try_from(n).unwrap_or(i64::MAX);
                self.log(linux_x64::WRITE, "write", vec![fd_u64, ctx.arg1(), count_u64], n_i64, rip);
                SyscallResult::Ok(n_i64) // claim all bytes written
            }
            Err(SyscallError::BadFd(_)) => {
                self.log(linux_x64::WRITE, "write", vec![fd_u64, ctx.arg1(), count_u64], -9, rip);
                SyscallResult::Ok(-9)
            }
            Err(_) => SyscallResult::Ok(-5),
        }
    }

    fn sys_open(&mut self, ctx: &RegisterContext, rip: u64) -> SyscallResult {
        // path is a pointer — use a placeholder name
        let path = format!("/virtual/path_{:#x}", ctx.arg0());
        let flags = u32_from_arg(ctx.arg1());
        match self.vfs.open(&path, flags) {
            Ok(fd) => {
                self.log(linux_x64::OPEN, "open", vec![ctx.arg0(), ctx.arg1(), ctx.arg2()], i64::from(fd), rip);
                SyscallResult::Ok(i64::from(fd))
            }
            Err(SyscallError::NotFound(_)) => {
                self.log(linux_x64::OPEN, "open", vec![ctx.arg0(), ctx.arg1(), ctx.arg2()], -2, rip);
                SyscallResult::Ok(-2) // ENOENT
            }
            Err(_) => SyscallResult::Ok(-13), // EACCES
        }
    }

    fn sys_close(&mut self, ctx: &RegisterContext, rip: u64) -> SyscallResult {
        let fd = i32_from_arg(ctx.arg0());
        let fd_u64 = u32_from_i32(fd).into();
        if matches!(self.vfs.close(fd), Ok(())) {
            self.log(linux_x64::CLOSE, "close", vec![fd_u64], 0, rip);
            SyscallResult::Ok(0)
        } else {
            self.log(linux_x64::CLOSE, "close", vec![fd_u64], -9, rip);
            SyscallResult::Ok(-9)
        }
    }

    fn sys_mmap(&mut self, ctx: &RegisterContext, rip: u64) -> SyscallResult {
        let addr = ctx.arg0();
        let len = ctx.arg1();
        let prot = u32_from_arg(ctx.arg2());
        let flags = u32_from_arg(ctx.arg3());
        let fd = i32_from_arg(ctx.arg4());
        let fd_u64 = u32_from_i32(fd).into();
        let offset = ctx.arg5();

        if let Ok(mapped_addr) = self.vmem.mmap(MmapRequest {
            addr,
            length: len,
            prot,
            flags,
            fd,
            offset,
            label: "mmap",
        }) {
            self.log(linux_x64::MMAP, "mmap", vec![addr, len, u64::from(prot), u64::from(flags), fd_u64, offset], mapped_addr.cast_signed(), rip);
            SyscallResult::Ok(mapped_addr.cast_signed())
        } else {
            self.log(linux_x64::MMAP, "mmap", vec![addr, len], -12, rip);
            SyscallResult::Ok(-12) // ENOMEM
        }
    }

    fn sys_mprotect(&mut self, ctx: &RegisterContext, rip: u64) -> SyscallResult {
        let addr = ctx.arg0();
        let len = ctx.arg1();
        let prot = u32_from_arg(ctx.arg2());
        if matches!(self.vmem.mprotect(addr, len, prot), Ok(())) {
            self.log(linux_x64::MPROTECT, "mprotect", vec![addr, len, u64::from(prot)], 0, rip);
            SyscallResult::Ok(0)
        } else {
            self.log(linux_x64::MPROTECT, "mprotect", vec![addr, len, u64::from(prot)], -22, rip);
            SyscallResult::Ok(-22) // EINVAL
        }
    }

    fn sys_munmap(&mut self, ctx: &RegisterContext, rip: u64) -> SyscallResult {
        let addr = ctx.arg0();
        let len = ctx.arg1();
        if matches!(self.vmem.munmap(addr, len), Ok(())) {
            self.log(linux_x64::MUNMAP, "munmap", vec![addr, len], 0, rip);
            SyscallResult::Ok(0)
        } else {
            self.log(linux_x64::MUNMAP, "munmap", vec![addr, len], -22, rip);
            SyscallResult::Ok(-22)
        }
    }

    fn sys_brk(&mut self, ctx: &RegisterContext, rip: u64) -> SyscallResult {
        let new_brk = ctx.arg0();
        let result = self.vmem.brk(new_brk);
        self.log(linux_x64::BRK, "brk", vec![new_brk], result.cast_signed(), rip);
        SyscallResult::Ok(result.cast_signed())
    }

    fn sys_clone(&mut self, ctx: &RegisterContext, rip: u64) -> SyscallResult {
        // Stub: return a fake child PID
        let extra = u32::try_from(self.child_pids.len()).unwrap_or(u32::MAX);
        let child_pid = self.pid.saturating_add(1).saturating_add(extra);
        self.child_pids.push(child_pid);
        self.log(linux_x64::CLONE, "clone", vec![ctx.arg0(), ctx.arg1(), ctx.arg2()], i64::from(child_pid), rip);
        SyscallResult::Ok(i64::from(child_pid))
    }

    fn sys_fork(&mut self, ctx: &RegisterContext, rip: u64) -> SyscallResult {
        let extra = u32::try_from(self.child_pids.len()).unwrap_or(u32::MAX);
        let child_pid = self.pid.saturating_add(1).saturating_add(extra);
        self.child_pids.push(child_pid);
        let nr = ctx.syscall_nr();
        self.log(nr, "fork", vec![], i64::from(child_pid), rip);
        SyscallResult::Ok(i64::from(child_pid))
    }

    fn sys_uname(&mut self, ctx: &RegisterContext, rip: u64) -> SyscallResult {
        // Return 0 (success) — caller would read struct from emulated memory
        self.log(linux_x64::UNAME, "uname", vec![ctx.arg0()], 0, rip);
        SyscallResult::Ok(0)
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    #[must_use] 
    pub const fn event_count(&self) -> usize {
        self.event_log.len()
    }

    #[must_use] 
    pub fn events_for_syscall(&self, name: &str) -> Vec<&SyscallEvent> {
        self.event_log.iter().filter(|e| e.name == name).collect()
    }

    #[must_use] 
    pub fn mmap_count(&self) -> usize {
        self.event_log.iter().filter(|e| e.name == "mmap").count()
    }

    #[must_use] 
    pub fn executable_maps(&self) -> Vec<&MemoryRegion> {
        self.vmem.executable_regions()
    }

    #[must_use] 
    pub fn has_exited(&self) -> bool {
        self.event_log.iter().any(|e| matches!(e.name.as_str(), "exit" | "exit_group"))
    }

    #[must_use] 
    pub fn exit_code(&self) -> Option<i32> {
        self.event_log.iter()
            .find(|e| matches!(e.name.as_str(), "exit" | "exit_group"))
            .map(|e| i32_from_arg(e.args.first().copied().unwrap_or(0)))
    }
}

fn syscall_name(nr: u64) -> String {
    match nr {
        0 => "read", 1 => "write", 2 => "open", 3 => "close", 9 => "mmap",
        10 => "mprotect", 11 => "munmap", 12 => "brk", 39 => "getpid",
        56 => "clone", 57 => "fork", 58 => "vfork", 59 => "execve",
        60 => "exit", 61 => "wait4", 62 => "kill", 63 => "uname",
        102 => "getuid", 104 => "getgid", 158 => "arch_prctl", 231 => "exit_group",
        _ => "unknown",
    }.to_owned()
}

// ─── Syscall Trace Utilities ──────────────────────────────────────────────────

/// Build a human-readable syscall trace from the event log.
#[must_use] 
pub fn format_trace(events: &[SyscallEvent]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for ev in events {
        let args_str = ev.args.iter()
            .map(|a| format!("{a:#x}"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            out,
            "[{:>6}] {:24} ({}) -> {}",
            ev.address, ev.name, args_str, ev.return_value
        );
    }
    out
}

/// Compute syscall frequency histogram from event log.
#[must_use] 
pub fn syscall_histogram(events: &[SyscallEvent]) -> std::collections::HashMap<String, usize> {
    let mut hist = std::collections::HashMap::new();
    for ev in events {
        *hist.entry(ev.name.clone()).or_default() += 1;
    }
    hist
}

/// Filter events to only those that produced errors (return < 0).
#[must_use] 
pub fn error_syscalls(events: &[SyscallEvent]) -> Vec<&SyscallEvent> {
    events.iter().filter(|e| e.return_value < 0).collect()
}

/// Check if the emulated binary attempted privilege escalation (setuid/setgid calls).
#[must_use] 
pub fn attempted_privilege_escalation(events: &[SyscallEvent]) -> bool {
    events.iter().any(|e| matches!(
        e.name.as_str(),
        "setuid" | "setgid" | "setreuid" | "setresuid" | "capset"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(nr: u64, arg0: u64, arg1: u64, arg2: u64) -> RegisterContext {
        RegisterContext { rax: nr, rdi: arg0, rsi: arg1, rdx: arg2, ..Default::default() }
    }

    #[test]
    fn test_mmap_and_munmap() {
        let mut emu = SyscallEmulator::new(0x7fff_0000_0000);
        let ctx = make_ctx(linux_x64::MMAP, 0, 0x1000, u64::from(MemoryRegion::PROT_READ | MemoryRegion::PROT_WRITE));
        let r = emu.dispatch(&ctx);
        match r {
            SyscallResult::Ok(addr) => {
                assert!(addr > 0);
                let munmap_ctx = make_ctx(linux_x64::MUNMAP, addr.cast_unsigned(), 0x1000, 0);
                let r2 = emu.dispatch(&munmap_ctx);
                assert!(matches!(r2, SyscallResult::Ok(0)));
            }
            SyscallResult::Exit(_) => panic!("Expected Ok"),
        }
    }

    #[test]
    fn test_brk() {
        let mut emu = SyscallEmulator::new(0x0040_0000);
        let ctx = make_ctx(linux_x64::BRK, 0, 0, 0);
        let r = emu.dispatch(&ctx);
        assert!(matches!(r, SyscallResult::Ok(_)));
    }

    #[test]
    fn test_getpid() {
        let mut emu = SyscallEmulator::new(0x0);
        let ctx = make_ctx(linux_x64::GETPID, 0, 0, 0);
        let r = emu.dispatch(&ctx);
        assert!(matches!(r, SyscallResult::Ok(1234)));
    }

    #[test]
    fn test_fork() {
        let mut emu = SyscallEmulator::new(0x0);
        let ctx = make_ctx(linux_x64::FORK, 0, 0, 0);
        let r = emu.dispatch(&ctx);
        assert!(matches!(r, SyscallResult::Ok(p) if p > 0));
        assert_eq!(emu.child_pids.len(), 1);
    }

    #[test]
    fn test_exit() {
        let mut emu = SyscallEmulator::new(0x0);
        let ctx = make_ctx(linux_x64::EXIT, 42, 0, 0);
        let r = emu.dispatch(&ctx);
        assert!(matches!(r, SyscallResult::Exit(42)));
        assert!(emu.has_exited());
    }

    #[test]
    fn test_read_bad_fd() {
        let mut emu = SyscallEmulator::new(0x0);
        let ctx = make_ctx(linux_x64::READ, 999, 0x1000, 64);
        let r = emu.dispatch(&ctx);
        assert!(matches!(r, SyscallResult::Ok(-9))); // EBADF
    }

    #[test]
    fn test_event_log() {
        let mut emu = SyscallEmulator::new(0x0);
        emu.dispatch(&make_ctx(linux_x64::GETPID, 0, 0, 0));
        emu.dispatch(&make_ctx(linux_x64::GETUID, 0, 0, 0));
        assert_eq!(emu.event_count(), 2);
    }

    #[test]
    fn test_allow_list() {
        let mut emu = SyscallEmulator::new(0x0);
        emu.allow_list = vec![linux_x64::GETPID];
        let r1 = emu.dispatch(&make_ctx(linux_x64::GETPID, 0, 0, 0));
        let r2 = emu.dispatch(&make_ctx(linux_x64::GETUID, 0, 0, 0));
        assert!(matches!(r1, SyscallResult::Ok(1234)));
        assert!(matches!(r2, SyscallResult::Ok(-38))); // ENOSYS
    }
}
