//! OS syscall emulation layer.
//!
//! Provides an [`OsEmulator`] trait that maps raw syscall numbers + register
//! arguments to high-level operations (file I/O, memory mapping, process
//! control).  Concrete implementations:
//!
//! * [`LinuxX86_64Emulator`] — Linux ABI (x86-64 syscall numbers).
//! * [`WindowsX86_64Stub`] — Windows stub that logs but does not execute.
//!
//! Supplementary types:
//!
//! * [`FdTable`] — file-descriptor table with stdin/stdout/stderr pre-wired.
//! * [`BumpAllocator`] — simple bump-pointer heap suitable for `brk`/`mmap`.
//! * [`OsProcess`] — aggregates `FdTable` + `BumpAllocator` + output capture.
//!
//! # Relationship to other syscall modules
//!
//! This module is the *integration layer*: it depends on `crate::Emulator` and
//! wires OS syscall handling into the real emulator register file via
//! [`OsEmuSession`]. It supports multiple architectures (x86-64, x86-32, MIPS).
//!
//! The other two syscall modules serve different, non-overlapping purposes:
//!
//! * **`os_syscall_model`** — multi-OS reference tables, syscall number lookup,
//!   `SyscallFilter`, `SyscallInterceptor`, and pattern detection. No `Emulator`
//!   dependency; suitable for static analysis.
//! * **`syscall_emulation`** — a self-contained Linux x86-64 emulator driven by
//!   a [`crate::syscall_emulation::RegisterContext`] snapshot, with its own
//!   `VirtualFs` and `VirtualMemory`. Does not require `crate::Emulator`.

use std::collections::HashMap;
use std::io::Write;

use crate::{Emulator, EmulatorError};

// ─────────────────────────────────────────────────────────────────────────────
// FdTable
// ─────────────────────────────────────────────────────────────────────────────

/// Disposition of a file descriptor.
#[derive(Debug, Clone)]
pub enum FdKind {
    /// Stdin (fd 0). Data comes from the supplied `Vec<u8>` buffer.
    Stdin(Vec<u8>, usize), // (data, read_pos)
    /// Stdout (fd 1). Data accumulates in the `Vec<u8>`.
    Stdout(Vec<u8>),
    /// Stderr (fd 2). Data accumulates in the `Vec<u8>`.
    Stderr(Vec<u8>),
    /// A regular file backed by an in-memory buffer.
    File {
        path: String,
        data: Vec<u8>,
        /// Current read/write position.
        pos: usize,
        /// Writable?
        writable: bool,
    },
    /// Closed / invalid.
    Closed,
}

impl FdKind {
    fn read(&mut self, len: usize) -> Option<Vec<u8>> {
        fn take(data: &[u8], pos: &mut usize, len: usize) -> Vec<u8> {
            let avail = data.len().saturating_sub(*pos);
            let n = len.min(avail);
            let slice = data[*pos..*pos + n].to_vec();
            *pos += n;
            slice
        }
        let result = match self {
            Self::Stdin(d, p)
            | Self::File {
                data: d, pos: p, ..
            } => take(d, p, len),
            Self::Stdout(_) | Self::Stderr(_) | Self::Closed => return None,
        };
        Some(result)
    }

    fn write(&mut self, data: &[u8]) -> usize {
        match self {
            Self::Stdout(buf) | Self::Stderr(buf) => {
                buf.extend_from_slice(data);
                data.len()
            }
            Self::File {
                data: buf,
                pos,
                writable,
                ..
            } => {
                if !*writable {
                    return 0;
                }
                // Extend if necessary
                if *pos + data.len() > buf.len() {
                    buf.resize(*pos + data.len(), 0);
                }
                buf[*pos..*pos + data.len()].copy_from_slice(data);
                *pos += data.len();
                data.len()
            }
            _ => 0,
        }
    }
}

/// File-descriptor table shared by the process.
#[derive(Debug, Default)]
pub struct FdTable {
    fds: HashMap<u32, FdKind>,
    next_fd: u32,
}

impl FdTable {
    /// Create a new table with stdin/stdout/stderr pre-populated.
    #[must_use]
    pub fn new() -> Self {
        let mut t = Self {
            fds: HashMap::new(),
            next_fd: 3,
        };
        t.fds.insert(0, FdKind::Stdin(Vec::new(), 0));
        t.fds.insert(1, FdKind::Stdout(Vec::new()));
        t.fds.insert(2, FdKind::Stderr(Vec::new()));
        t
    }

    /// Replace stdin content (for fuzz input injection).
    pub fn set_stdin(&mut self, data: Vec<u8>) {
        self.fds.insert(0, FdKind::Stdin(data, 0));
    }

    /// Allocate a new fd backed by an in-memory file.
    pub fn open_file(&mut self, path: impl Into<String>, data: Vec<u8>, writable: bool) -> u32 {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.fds.insert(
            fd,
            FdKind::File {
                path: path.into(),
                data,
                pos: 0,
                writable,
            },
        );
        fd
    }

    /// Open an empty writable file.
    pub fn create_file(&mut self, path: impl Into<String>) -> u32 {
        self.open_file(path, Vec::new(), true)
    }

    pub fn close(&mut self, fd: u32) -> bool {
        if let Some(k) = self.fds.get_mut(&fd) {
            *k = FdKind::Closed;
            return true;
        }
        false
    }

    /// Read up to `len` bytes from `fd`. Returns `None` if fd invalid/closed.
    pub fn read(&mut self, fd: u32, len: usize) -> Option<Vec<u8>> {
        self.fds.get_mut(&fd)?.read(len)
    }

    /// Write `data` to `fd`. Returns bytes written (0 on error).
    pub fn write(&mut self, fd: u32, data: &[u8]) -> usize {
        self.fds.get_mut(&fd).map_or(0, |k| k.write(data))
    }

    /// Drain the stdout buffer.
    pub fn take_stdout(&mut self) -> Vec<u8> {
        match self.fds.get_mut(&1) {
            Some(FdKind::Stdout(buf)) => std::mem::take(buf),
            _ => Vec::new(),
        }
    }

    /// Drain the stderr buffer.
    pub fn take_stderr(&mut self) -> Vec<u8> {
        match self.fds.get_mut(&2) {
            Some(FdKind::Stderr(buf)) => std::mem::take(buf),
            _ => Vec::new(),
        }
    }

    /// Return a reference to stdout content without consuming it.
    #[must_use]
    pub fn peek_stdout(&self) -> &[u8] {
        match self.fds.get(&1) {
            Some(FdKind::Stdout(buf)) => buf.as_slice(),
            _ => &[],
        }
    }

    #[must_use]
    pub fn is_valid(&self, fd: u32) -> bool {
        !matches!(self.fds.get(&fd), None | Some(FdKind::Closed))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BumpAllocator
// ─────────────────────────────────────────────────────────────────────────────

/// Bump-pointer heap allocator for `brk` / `mmap anonymous` emulation.
///
/// Allocations are never freed; this is intentional — real fuzzing workloads
/// reset the entire emulator state between runs anyway.
#[derive(Debug, Clone)]
pub struct BumpAllocator {
    /// Lowest address of the heap region.
    pub heap_start: u64,
    /// First unallocated byte (the "program break").
    pub brk: u64,
    /// Highest address the heap is allowed to grow to.
    pub heap_limit: u64,
}

impl BumpAllocator {
    /// Create a new allocator.  `heap_start` must be page-aligned.
    #[must_use]
    pub const fn new(heap_start: u64, heap_size: u64) -> Self {
        Self {
            heap_start,
            brk: heap_start,
            heap_limit: heap_start + heap_size,
        }
    }

    /// Allocate `size` bytes (with 8-byte alignment).  Returns the base
    /// address of the allocation, or `None` if the heap is exhausted.
    pub fn alloc(&mut self, size: u64) -> Option<u64> {
        let aligned = (self.brk + 7) & !7;
        let new_brk = aligned.checked_add(size)?;
        if new_brk > self.heap_limit {
            return None;
        }
        self.brk = new_brk;
        Some(aligned)
    }

    /// Attempt to set the program break to `new_brk`. Returns the resulting
    /// brk (clamped to `heap_limit`).
    pub const fn set_brk(&mut self, new_brk: u64) -> u64 {
        if new_brk >= self.heap_start && new_brk <= self.heap_limit {
            self.brk = new_brk;
        }
        self.brk
    }

    #[must_use]
    pub const fn used_bytes(&self) -> u64 {
        self.brk - self.heap_start
    }
    #[must_use]
    pub const fn remaining_bytes(&self) -> u64 {
        self.heap_limit - self.brk
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OsProcess
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated process state used by OS emulators.
pub struct OsProcess {
    pub fds: FdTable,
    pub heap: BumpAllocator,
    /// Exit code, `None` if process has not exited.
    pub exit_code: Option<i32>,
    /// Recorded syscall log: (number, args).
    pub syscall_log: Vec<(u64, Vec<u64>)>,
}

impl OsProcess {
    #[must_use]
    pub fn new(heap_base: u64, heap_size: u64) -> Self {
        Self {
            fds: FdTable::new(),
            heap: BumpAllocator::new(heap_base, heap_size),
            exit_code: None,
            syscall_log: Vec::new(),
        }
    }

    pub fn log_syscall(&mut self, nr: u64, args: &[u64]) {
        self.syscall_log.push((nr, args.to_vec()));
    }

    #[must_use]
    pub const fn has_exited(&self) -> bool {
        self.exit_code.is_some()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OsEmulator trait
// ─────────────────────────────────────────────────────────────────────────────

/// Result of handling one syscall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyscallResult {
    /// Return value to be placed in the return register.
    Value(u64),
    /// Process should exit with the given code.
    Exit(i32),
    /// Syscall not implemented; caller can decide how to handle.
    Unimplemented(u64),
    /// Error: return `-errno` convention.
    Errno(i64),
}

impl SyscallResult {
    /// Convert to the u64 raw return value placed in `rax`/`v0` etc.
    #[must_use]
    pub fn raw_value(&self) -> u64 {
        match self {
            Self::Value(v) => *v,
            Self::Exit(code) => i64::from(*code).cast_unsigned(),
            Self::Unimplemented(_) => u64::MAX, // -ENOSYS
            Self::Errno(e) => (-e).cast_unsigned(),
        }
    }
}

/// OS syscall dispatcher trait.
pub trait OsEmulator: Send + Sync {
    fn name(&self) -> &str;

    /// Handle a syscall.  `nr` is the syscall number; `args` are the up to 6
    /// argument registers (in ABI order).  The emulator's memory can be
    /// accessed via `emu`.
    fn handle_syscall(
        &mut self,
        nr: u64,
        args: &[u64; 6],
        emu: &mut dyn Emulator,
        proc: &mut OsProcess,
    ) -> SyscallResult;
}

// ─────────────────────────────────────────────────────────────────────────────
// Linux x86-64 syscall numbers
// ─────────────────────────────────────────────────────────────────────────────

pub mod linux_x64_nr {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const OPEN: u64 = 2;
    pub const CLOSE: u64 = 3;
    pub const FSTAT: u64 = 5;
    pub const LSEEK: u64 = 8;
    pub const MMAP: u64 = 9;
    pub const MPROTECT: u64 = 10;
    pub const MUNMAP: u64 = 11;
    pub const BRK: u64 = 12;
    pub const WRITEV: u64 = 20;
    pub const EXIT: u64 = 60;
    pub const EXIT_GROUP: u64 = 231;
    pub const GETRANDOM: u64 = 318;
}

// ─────────────────────────────────────────────────────────────────────────────
// LinuxX86_64Emulator
// ─────────────────────────────────────────────────────────────────────────────

/// Linux x86-64 syscall emulator.
///
/// Implements the most common syscalls needed to run typical binaries:
/// `read`, `write`, `open`/`close`, `mmap` (anonymous), `brk`, and `exit`.
pub struct LinuxX86_64Emulator {
    /// Enable verbose syscall tracing to stderr.
    pub verbose: bool,
}

impl LinuxX86_64Emulator {
    #[must_use]
    pub const fn new() -> Self {
        Self { verbose: false }
    }

    #[must_use]
    pub const fn with_verbose(mut self, v: bool) -> Self {
        self.verbose = v;
        self
    }
}

impl Default for LinuxX86_64Emulator {
    fn default() -> Self {
        Self::new()
    }
}

impl OsEmulator for LinuxX86_64Emulator {
    fn name(&self) -> &'static str {
        "linux-x86_64"
    }

    fn handle_syscall(
        &mut self,
        nr: u64,
        args: &[u64; 6],
        emu: &mut dyn Emulator,
        proc: &mut OsProcess,
    ) -> SyscallResult {
        proc.log_syscall(nr, args);
        if self.verbose {
            eprintln!("[syscall] nr={nr} args={args:?}");
        }
        match nr {
            linux_x64_nr::READ => Self::sys_read(args, emu, proc),
            linux_x64_nr::WRITE => self.sys_write(args, &*emu, proc),
            linux_x64_nr::OPEN => Self::sys_open(args, &*emu, proc),
            linux_x64_nr::CLOSE => Self::sys_close(args, proc),
            linux_x64_nr::BRK => Self::sys_brk(args, emu, proc),
            linux_x64_nr::MMAP => Self::sys_mmap(args, emu, proc),
            linux_x64_nr::MUNMAP | linux_x64_nr::MPROTECT => SyscallResult::Value(0),
            linux_x64_nr::EXIT | linux_x64_nr::EXIT_GROUP => {
                let code = u32::try_from(args[0] & 0xFFFF_FFFF).unwrap_or(u32::MAX).cast_signed();
                proc.exit_code = Some(code);
                SyscallResult::Exit(code)
            }
            linux_x64_nr::WRITEV => Self::sys_writev(args, &*emu, proc),
            linux_x64_nr::GETRANDOM => Self::sys_getrandom(args, emu),
            other => SyscallResult::Unimplemented(other),
        }
    }
}

/// Cap at 64 MiB to avoid OOM from attacker-controlled length.
const SYS_MAX_RW: usize = 64 * 1024 * 1024;
/// Cap iov vectors to prevent unbounded loops/allocations.
const SYS_MAX_IOV: usize = 1024;
/// Cap at 256 bytes; `getrandom` is typically called for small amounts.
const SYS_MAX_GETRANDOM: usize = 256;

impl LinuxX86_64Emulator {
    fn sys_read(args: &[u64; 6], emu: &mut dyn Emulator, proc: &mut OsProcess) -> SyscallResult {
        let fd = u32::try_from(args[0] & 0xFFFF_FFFF).unwrap_or(u32::MAX);
        let buf = args[1];
        let len = usize::try_from(args[2]).unwrap_or(SYS_MAX_RW).min(SYS_MAX_RW);
        proc.fds
            .read(fd, len)
            .map_or(SyscallResult::Errno(9), |data| {
                let n = data.len();
                if emu.write_memory(buf, &data).is_err() {
                    return SyscallResult::Errno(14); // EFAULT
                }
                SyscallResult::Value(u64::try_from(n).unwrap_or(u64::MAX))
            })
    }

    fn sys_write(
        &self,
        args: &[u64; 6],
        emu: &dyn Emulator,
        proc: &mut OsProcess,
    ) -> SyscallResult {
        let fd = u32::try_from(args[0] & 0xFFFF_FFFF).unwrap_or(u32::MAX);
        let buf = args[1];
        let len = usize::try_from(args[2]).unwrap_or(SYS_MAX_RW).min(SYS_MAX_RW);
        match emu.read_memory(buf, len) {
            Ok(data) => {
                let n = proc.fds.write(fd, &data);
                if self.verbose && (fd == 1 || fd == 2) {
                    drop(std::io::stderr().write_all(&data));
                }
                SyscallResult::Value(u64::try_from(n).unwrap_or(u64::MAX))
            }
            Err(_) => SyscallResult::Errno(14), // EFAULT
        }
    }

    fn sys_open(args: &[u64; 6], emu: &dyn Emulator, proc: &mut OsProcess) -> SyscallResult {
        let path_ptr = args[0];
        let flags = args[1];
        let path = read_cstring(emu, path_ptr).unwrap_or_else(|_| "<invalid>".into());
        let writable = flags & 0x3 != 0;
        let fd = proc.fds.open_file(&path, Vec::new(), writable);
        SyscallResult::Value(u64::from(fd))
    }

    fn sys_close(args: &[u64; 6], proc: &mut OsProcess) -> SyscallResult {
        let fd = u32::try_from(args[0] & 0xFFFF_FFFF).unwrap_or(u32::MAX);
        if fd < 3 {
            return SyscallResult::Value(0);
        }
        if proc.fds.close(fd) {
            SyscallResult::Value(0)
        } else {
            SyscallResult::Errno(9)
        }
    }

    fn sys_brk(args: &[u64; 6], emu: &mut dyn Emulator, proc: &mut OsProcess) -> SyscallResult {
        let new_brk = args[0];
        let result = if new_brk == 0 {
            proc.heap.brk
        } else {
            expand_heap(emu, proc, new_brk);
            proc.heap.set_brk(new_brk)
        };
        SyscallResult::Value(result)
    }

    fn sys_mmap(args: &[u64; 6], emu: &mut dyn Emulator, proc: &mut OsProcess) -> SyscallResult {
        let len = args[1];
        let flags = args[3];
        let fd_signed = args[4].cast_signed();
        let anon = flags & 0x20 != 0;
        if anon || fd_signed == -1 {
            match proc.heap.alloc(len) {
                Some(addr) => {
                    expand_heap(emu, proc, proc.heap.brk);
                    SyscallResult::Value(addr)
                }
                None => SyscallResult::Errno(12),
            }
        } else {
            SyscallResult::Errno(22)
        }
    }

    fn sys_writev(args: &[u64; 6], emu: &dyn Emulator, proc: &mut OsProcess) -> SyscallResult {
        let fd = u32::try_from(args[0] & 0xFFFF_FFFF).unwrap_or(u32::MAX);
        let iov = args[1];
        let cnt = usize::try_from(args[2]).unwrap_or(SYS_MAX_IOV).min(SYS_MAX_IOV);
        let ptr_size = u64::try_from(emu.arch().pointer_size()).unwrap_or(8);
        let ptr_size_usize = usize::try_from(ptr_size).unwrap_or(usize::MAX);
        let mut total = 0u64;
        for i in 0..cnt {
            let i64 = u64::try_from(i).unwrap_or(u64::MAX);
            let entry_addr = iov
                .saturating_add(i64.saturating_mul(ptr_size).saturating_mul(2));
            if let Ok(base_bytes) = emu.read_memory(entry_addr, ptr_size_usize)
                && let Ok(len_bytes) = emu.read_memory(entry_addr + ptr_size, ptr_size_usize)
            {
                let base_val = u64_from_le_bytes_any(&base_bytes);
                let len_val =
                    usize::try_from(u64_from_le_bytes_any(&len_bytes)).unwrap_or(SYS_MAX_RW).min(SYS_MAX_RW);
                if let Ok(data) = emu.read_memory(base_val, len_val) {
                    total = total.saturating_add(u64::try_from(proc.fds.write(fd, &data)).unwrap_or(u64::MAX));
                }
            }
        }
        SyscallResult::Value(total)
    }

    fn sys_getrandom(args: &[u64; 6], emu: &mut dyn Emulator) -> SyscallResult {
        use std::hash::{BuildHasher, Hasher};
        let buf = args[0];
        // Without this cap, an attacker-supplied length causes OOM allocation.
        let len = usize::try_from(args[1]).unwrap_or(SYS_MAX_GETRANDOM).min(SYS_MAX_GETRANDOM);
        // Use OS-provided randomness instead of a predictable sequence.
        // The previous implementation used `(i * 0x6B) ^ 0xA5` which is a
        // trivially predictable pattern — emulated code relying on getrandom
        // for key/nonce material would receive entirely non-random output.
        let mut bytes = vec![0u8; len];
        // Fill with bytes from the OS RNG via repeated reads of /dev/urandom
        // semantics using `std::collections::hash_map::DefaultHasher` as a
        // last-resort fallback, but prefer the platform RNG.
        let seed = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish();
        // Xorshift64 seeded from a non-deterministic OS hash seed
        let mut rng_state = seed | 1;
        for chunk in bytes.chunks_mut(8) {
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;
            let word = rng_state.to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&word[..n]);
        }
        drop(emu.write_memory(buf, &bytes));
        SyscallResult::Value(u64::try_from(len).unwrap_or(0))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Windows x86-64 stub
// ─────────────────────────────────────────────────────────────────────────────

/// Windows x86-64 syscall stub. Logs calls but always returns 0 / `STATUS_SUCCESS`.
pub struct WindowsX86_64Stub {
    pub verbose: bool,
}

impl WindowsX86_64Stub {
    #[must_use]
    pub const fn new() -> Self {
        Self { verbose: false }
    }
}

impl Default for WindowsX86_64Stub {
    fn default() -> Self {
        Self::new()
    }
}

impl OsEmulator for WindowsX86_64Stub {
    fn name(&self) -> &'static str {
        "windows-x86_64-stub"
    }

    fn handle_syscall(
        &mut self,
        nr: u64,
        args: &[u64; 6],
        _emu: &mut dyn Emulator,
        proc: &mut OsProcess,
    ) -> SyscallResult {
        proc.log_syscall(nr, args);
        if self.verbose {
            eprintln!("[win-syscall] nr=0x{nr:x} args={args:?}");
        }
        // Return STATUS_SUCCESS (0) for all calls
        SyscallResult::Value(0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OsEmuSession
// ─────────────────────────────────────────────────────────────────────────────

/// High-level wrapper that connects an [`OsEmulator`] to an emulator loop.
///
/// The session intercepts interrupt events (INT 0x80 on x86, SYSCALL on
/// x86-64, `syscall` on MIPS) fired by the underlying interpreter, dispatches
/// them through `handler`, and writes return values back into the appropriate
/// register.
pub struct OsEmuSession {
    pub emu: Box<dyn Emulator>,
    pub proc: OsProcess,
    pub handler: Box<dyn OsEmulator>,
}

impl OsEmuSession {
    /// Create a new session.  The heap lives at `heap_base` with `heap_size`.
    #[must_use]
    pub fn new(
        emu: Box<dyn Emulator>,
        handler: Box<dyn OsEmulator>,
        heap_base: u64,
        heap_size: u64,
    ) -> Self {
        Self {
            emu,
            proc: OsProcess::new(heap_base, heap_size),
            handler,
        }
    }

    /// Dispatch a raw syscall from an interrupt hook.
    ///
    /// Reads argument registers according to the ABI of the current arch,
    /// invokes the handler, and writes the return value back.
    ///
    /// # Errors
    ///
    /// Returns `EmulatorError` if reading or writing registers fails.
    pub fn dispatch_syscall(&mut self) -> Result<(), EmulatorError> {
        use crate::{EmulatorArch, mips_regs, x86_regs};
        let arch = self.emu.arch();
        let (nr, args) = self.read_syscall_args(arch)?;
        let result = self
            .handler
            .handle_syscall(nr, &args, self.emu.as_mut(), &mut self.proc);
        let retval = result.raw_value();
        match arch {
            EmulatorArch::X86_64 => {
                self.emu.write_register(x86_regs::RAX, retval)?;
            }
            EmulatorArch::X86_32 => {
                self.emu.write_register(x86_regs::EAX, retval)?;
            }
            EmulatorArch::Mips32 | EmulatorArch::Mips32El => {
                self.emu.write_register(mips_regs::V0, retval)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn read_syscall_args(
        &self,
        arch: crate::EmulatorArch,
    ) -> Result<(u64, [u64; 6]), EmulatorError> {
        use crate::{EmulatorArch, mips_regs, x86_regs};
        match arch {
            EmulatorArch::X86_64 => {
                let nr = self.emu.read_register(x86_regs::RAX)?;
                let args = [
                    self.emu.read_register(x86_regs::RDI)?,
                    self.emu.read_register(x86_regs::RSI)?,
                    self.emu.read_register(x86_regs::RDX)?,
                    self.emu.read_register(x86_regs::R10)?,
                    self.emu.read_register(x86_regs::R8)?,
                    self.emu.read_register(x86_regs::R9)?,
                ];
                Ok((nr, args))
            }
            EmulatorArch::X86_32 => {
                let nr = self.emu.read_register(x86_regs::EAX)?;
                let args = [
                    self.emu.read_register(x86_regs::EBX)?,
                    self.emu.read_register(x86_regs::ECX)?,
                    self.emu.read_register(x86_regs::EDX)?,
                    self.emu.read_register(x86_regs::ESI)?,
                    self.emu.read_register(x86_regs::EDI)?,
                    self.emu.read_register(x86_regs::EBP)?,
                ];
                Ok((nr, args))
            }
            EmulatorArch::Mips32 | EmulatorArch::Mips32El => {
                let nr = self.emu.read_register(mips_regs::V0)?;
                let args = [
                    self.emu.read_register(mips_regs::A0)?,
                    self.emu.read_register(mips_regs::A1)?,
                    self.emu.read_register(mips_regs::A2)?,
                    self.emu.read_register(mips_regs::A3)?,
                    0,
                    0,
                ];
                Ok((nr, args))
            }
            _ => Ok((0, [0u64; 6])),
        }
    }

    /// Read a null-terminated string from emulator memory.
    ///
    /// # Errors
    ///
    /// Returns `EmulatorError::MemFault` if reading memory at `addr` fails.
    pub fn read_cstring(&self, addr: u64) -> Result<String, EmulatorError> {
        read_cstring(self.emu.as_ref(), addr)
    }

    /// Write a null-terminated string into emulator memory.
    ///
    /// # Errors
    ///
    /// Returns `EmulatorError::MemFault` if writing memory at `addr` fails.
    pub fn write_cstring(&mut self, addr: u64, s: &str) -> Result<(), EmulatorError> {
        let mut bytes = s.as_bytes().to_vec();
        bytes.push(0);
        self.emu.write_memory(addr, &bytes)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility functions
// ─────────────────────────────────────────────────────────────────────────────

/// Read a C-style null-terminated string from emulator memory.
///
/// # Errors
///
/// Returns `EmulatorError::MemFault` if reading memory at `addr` fails.
pub fn read_cstring(emu: &dyn Emulator, mut addr: u64) -> Result<String, EmulatorError> {
    let mut bytes = Vec::with_capacity(64);
    loop {
        let b = emu.read_memory(addr, 1)?;
        if b[0] == 0 {
            break;
        }
        bytes.push(b[0]);
        // Guard against address wrapping past u64::MAX
        addr = addr.checked_add(1).ok_or_else(|| EmulatorError::MemFault {
            addr,
            op: "cstring-overflow".into(),
        })?;
        if bytes.len() > 4096 {
            break;
        } // safety limit
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Convert a little-endian byte slice of length 1/2/4/8 to u64.
#[inline]
fn u64_from_le_bytes_any(bytes: &[u8]) -> u64 {
    match bytes.len() {
        1 => u64::from(bytes[0]),
        2 => u64::from(u16::from_le_bytes([bytes[0], bytes[1]])),
        4 => u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
        8 => u64::from_le_bytes(bytes.try_into().unwrap_or([0u8; 8])),
        _ => 0,
    }
}

/// Ensure that emulator memory covers at least up to `new_brk` by extending
/// the heap region (or mapping a new page) if needed.
fn expand_heap(emu: &mut dyn Emulator, proc: &OsProcess, new_brk: u64) -> bool {
    // Check whether the heap region already covers the new brk
    for r in emu.regions() {
        if r.start <= proc.heap.heap_start && r.start + u64::try_from(r.size).unwrap_or(u64::MAX) >= new_brk {
            return true;
        }
    }
    // Map an extension. We map the entire heap range upfront if not present.
    let heap_size =
        usize::try_from(proc.heap.heap_limit - proc.heap.heap_start).unwrap_or(usize::MAX);
    drop(emu.map_memory(
        proc.heap.heap_start,
        heap_size,
        crate::MemPerms::READ | crate::MemPerms::WRITE,
    ));
    true
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EmulatorArch, EmulatorFactory, MemPerms};

    // ── FdTable ───────────────────────────────────────────────────────────────

    #[test]
    fn test_fd_table_stdin_read() {
        let mut t = FdTable::new();
        t.set_stdin(b"hello".to_vec());
        assert_eq!(t.read(0, 3).unwrap(), b"hel");
        assert_eq!(t.read(0, 10).unwrap(), b"lo");
        assert_eq!(t.read(0, 1).unwrap().len(), 0); // EOF
    }

    #[test]
    fn test_fd_table_stdout_write() {
        let mut t = FdTable::new();
        t.write(1, b"hello world");
        assert_eq!(t.peek_stdout(), b"hello world");
        let out = t.take_stdout();
        assert_eq!(out, b"hello world");
        assert!(t.peek_stdout().is_empty());
    }

    #[test]
    fn test_fd_table_open_close() {
        let mut t = FdTable::new();
        let fd = t.open_file("/tmp/test", b"data".to_vec(), false);
        assert!(t.is_valid(fd));
        let data = t.read(fd, 100).unwrap();
        assert_eq!(data, b"data");
        t.close(fd);
        assert!(!t.is_valid(fd));
    }

    // ── BumpAllocator ─────────────────────────────────────────────────────────

    #[test]
    fn test_bump_alloc() {
        let mut a = BumpAllocator::new(0x1000_0000, 0x100_0000);
        let p1 = a.alloc(16).unwrap();
        let p2 = a.alloc(32).unwrap();
        assert_eq!(p1, 0x1000_0000);
        assert!(p2 > p1);
    }

    #[test]
    fn test_bump_exhausted() {
        let mut a = BumpAllocator::new(0x0, 100);
        let _ = a.alloc(90).unwrap();
        assert!(a.alloc(50).is_none());
    }

    #[test]
    fn test_bump_set_brk() {
        let mut a = BumpAllocator::new(0x1000, 0x1000);
        a.set_brk(0x1100);
        assert_eq!(a.brk, 0x1100);
        a.set_brk(0x100); // below heap_start — no effect
        assert_eq!(a.brk, 0x1100);
    }

    // ── Linux syscall: write ──────────────────────────────────────────────────

    #[test]
    fn test_linux_write_syscall() {
        let mut emu = EmulatorFactory::create(EmulatorArch::X86_64);
        emu.map_memory(0x1000, 0x1000, MemPerms::ALL).unwrap();
        emu.write_memory(0x1000, b"hello\0").unwrap();

        let mut handler = LinuxX86_64Emulator::new();
        let mut proc = OsProcess::new(0x8000_0000, 0x100_0000);

        // write(1, 0x1000, 5)
        let args = [1u64, 0x1000, 5, 0, 0, 0];
        let result = handler.handle_syscall(linux_x64_nr::WRITE, &args, emu.as_mut(), &mut proc);
        assert_eq!(result, SyscallResult::Value(5));
        assert_eq!(proc.fds.peek_stdout(), b"hello");
    }

    // ── Linux syscall: read ───────────────────────────────────────────────────

    #[test]
    fn test_linux_read_syscall() {
        let mut emu = EmulatorFactory::create(EmulatorArch::X86_64);
        emu.map_memory(0x2000, 0x1000, MemPerms::ALL).unwrap();

        let mut handler = LinuxX86_64Emulator::new();
        let mut proc = OsProcess::new(0x8000_0000, 0x100_0000);
        proc.fds.set_stdin(b"world".to_vec());

        // read(0, 0x2000, 5)
        let args = [0u64, 0x2000, 5, 0, 0, 0];
        let result = handler.handle_syscall(linux_x64_nr::READ, &args, emu.as_mut(), &mut proc);
        assert_eq!(result, SyscallResult::Value(5));
        assert_eq!(emu.read_memory(0x2000, 5).unwrap(), b"world");
    }

    // ── Linux syscall: brk ────────────────────────────────────────────────────

    #[test]
    fn test_linux_brk_syscall() {
        let mut emu = EmulatorFactory::create(EmulatorArch::X86_64);
        let mut handler = LinuxX86_64Emulator::new();
        let mut proc = OsProcess::new(0x4000_0000, 0x100_0000);

        // brk(0) → return current brk
        let args = [0u64; 6];
        let result = handler.handle_syscall(linux_x64_nr::BRK, &args, emu.as_mut(), &mut proc);
        assert_eq!(result, SyscallResult::Value(0x4000_0000));

        // brk(new_brk) → advance
        let args2 = [0x4000_1000u64, 0, 0, 0, 0, 0];
        handler.handle_syscall(linux_x64_nr::BRK, &args2, emu.as_mut(), &mut proc);
        assert_eq!(proc.heap.brk, 0x4000_1000);
    }

    // ── Linux syscall: exit ───────────────────────────────────────────────────

    #[test]
    fn test_linux_exit_syscall() {
        let mut emu = EmulatorFactory::create(EmulatorArch::X86_64);
        let mut handler = LinuxX86_64Emulator::new();
        let mut proc = OsProcess::new(0x0, 0x1000);
        let args = [42u64, 0, 0, 0, 0, 0];
        let result = handler.handle_syscall(linux_x64_nr::EXIT, &args, emu.as_mut(), &mut proc);
        assert_eq!(result, SyscallResult::Exit(42));
        assert!(proc.has_exited());
        assert_eq!(proc.exit_code, Some(42));
    }

    // ── OsEmuSession: cstring ─────────────────────────────────────────────────

    #[test]
    fn test_read_cstring() {
        // Test the read_cstring helper via OsEmuSession
        let mut session = OsEmuSession::new(
            EmulatorFactory::create(EmulatorArch::X86_64),
            Box::new(LinuxX86_64Emulator::new()),
            0x8000_0000,
            0x10_0000,
        );
        session
            .emu
            .map_memory(0x3000, 0x100, MemPerms::ALL)
            .unwrap();
        session.write_cstring(0x3000, "test_path").unwrap();
        let s = session.read_cstring(0x3000).unwrap();
        assert_eq!(s, "test_path");
    }

    // ── Windows stub ─────────────────────────────────────────────────────────

    #[test]
    fn test_windows_stub() {
        let mut emu = EmulatorFactory::create(EmulatorArch::X86_64);
        let mut stub = WindowsX86_64Stub::new();
        let mut proc = OsProcess::new(0x0, 0x1000);
        // Any call returns 0
        let args = [0u64; 6];
        let r = stub.handle_syscall(0x1234, &args, emu.as_mut(), &mut proc);
        assert_eq!(r.raw_value(), 0);
    }

    // ── Syscall log ───────────────────────────────────────────────────────────

    #[test]
    fn test_syscall_log() {
        let mut emu = EmulatorFactory::create(EmulatorArch::X86_64);
        let mut h = LinuxX86_64Emulator::new();
        let mut proc = OsProcess::new(0x0, 0x1000);
        let args = [42u64, 0, 0, 0, 0, 0];
        h.handle_syscall(linux_x64_nr::EXIT, &args, emu.as_mut(), &mut proc);
        assert_eq!(proc.syscall_log.len(), 1);
        assert_eq!(proc.syscall_log[0].0, linux_x64_nr::EXIT);
    }
}
