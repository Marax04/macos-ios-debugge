//! Pure-Rust syscall emulation layer.
//!
//! Provides a `SyscallEmulator` that dispatches Linux syscall numbers to
//! registered `SyscallHandler` implementations, without requiring any OS
//! interaction. Useful for analysing binaries in a sandboxed environment.

use std::collections::HashMap;

// ── Error type ───────────────────────────────────────────────────────────────

/// Errors that can arise during emulated syscall execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmulatorError {
    /// No handler registered for this syscall number.
    UnhandledSyscall(u64),
    /// The file descriptor supplied is not open.
    BadFd(i64),
    /// A requested address range is not mapped.
    Unmapped { addr: u64, len: usize },
    /// An argument value is out of the acceptable range.
    InvalidArg(String),
    /// Execution has been requested to stop (e.g. `exit`/`exit_group`).
    Exited(i32),
}

impl std::fmt::Display for EmulatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnhandledSyscall(n) => write!(f, "unhandled syscall {n}"),
            Self::BadFd(fd) => write!(f, "bad file descriptor {fd}"),
            Self::Unmapped { addr, len } => {
                write!(f, "unmapped region 0x{addr:x}+{len}")
            }
            Self::InvalidArg(s) => write!(f, "invalid argument: {s}"),
            Self::Exited(code) => write!(f, "process exited with code {code}"),
        }
    }
}

impl std::error::Error for EmulatorError {}

pub type EmulatorResult<T> = Result<T, EmulatorError>;

// ── Emulated file descriptors ─────────────────────────────────────────────────

/// The backing storage for an emulated file descriptor.
#[derive(Debug, Clone)]
pub enum FdBacking {
    /// In-memory byte buffer (used for stdin/stdout/stderr stubs and opened files).
    Buffer(Vec<u8>),
    /// Special sink – all writes succeed, reads return EOF.
    Null,
}

/// An open emulated file descriptor.
#[derive(Debug, Clone)]
pub struct EmulatedFd {
    /// Human-readable path (for debugging).
    pub path: String,
    /// Access flags (`O_RDONLY = 0`, `O_WRONLY = 1`, `O_RDWR = 2`).
    pub flags: i32,
    /// Current read/write position.
    pub offset: u64,
    /// Backing storage.
    pub backing: FdBacking,
}

impl EmulatedFd {
    /// Create a new in-memory file descriptor with empty contents.
    pub fn new_buffer(path: impl Into<String>, flags: i32) -> Self {
        Self {
            path: path.into(),
            flags,
            offset: 0,
            backing: FdBacking::Buffer(Vec::new()),
        }
    }

    /// Create a new file descriptor backed by pre-existing bytes.
    pub fn with_contents(path: impl Into<String>, flags: i32, data: Vec<u8>) -> Self {
        Self {
            path: path.into(),
            flags,
            offset: 0,
            backing: FdBacking::Buffer(data),
        }
    }

    /// Create a null-sink file descriptor (e.g. `/dev/null`).
    pub fn null(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            flags: 2, // O_RDWR
            offset: 0,
            backing: FdBacking::Null,
        }
    }

    /// Read up to `len` bytes into `buf`, advancing the internal offset.
    pub fn read(&mut self, buf: &mut [u8], len: usize) -> i64 {
        let len = len.min(buf.len());
        match &self.backing {
            FdBacking::Null => 0,
            FdBacking::Buffer(data) => {
                let Ok(start) = usize::try_from(self.offset) else {
                    return 0;
                };
                if start >= data.len() {
                    return 0; // EOF
                }
                // Saturate to avoid integer overflow in the addition
                let end = start.saturating_add(len).min(data.len());
                let n = end - start;
                buf[..n].copy_from_slice(&data[start..end]);
                self.offset += u64::try_from(n).unwrap_or(0);
                i64::try_from(n).unwrap_or(i64::MAX)
            }
        }
    }

    /// Write `data` at the current offset.
    pub fn write(&mut self, data: &[u8]) -> i64 {
        match &mut self.backing {
            FdBacking::Null => i64::try_from(data.len()).unwrap_or(i64::MAX),
            FdBacking::Buffer(buf) => {
                let Ok(off) = usize::try_from(self.offset) else {
                    return 0;
                };
                // Guard against integer overflow when computing end offset
                let end = off.saturating_add(data.len());
                if end > buf.len() {
                    buf.resize(end, 0);
                }
                buf[off..end].copy_from_slice(data);
                self.offset += u64::try_from(data.len()).unwrap_or(0);
                i64::try_from(data.len()).unwrap_or(i64::MAX)
            }
        }
    }
}

// ── Syscall context ───────────────────────────────────────────────────────────

/// The full register set passed to a syscall handler.
///
/// On x86-64 Linux the calling convention is:
/// `rax` = syscall number, `rdi/rsi/rdx/r10/r8/r9` = arguments 0-5,
/// and the return value is placed back in `rax`.
#[derive(Debug, Clone, Default)]
pub struct SyscallContext {
    /// Syscall number (already extracted from `rax`).
    pub nr: u64,
    /// Arguments 0-5.
    pub args: [u64; 6],
}

impl SyscallContext {
    #[must_use]
    pub const fn new(nr: u64, args: [u64; 6]) -> Self {
        Self { nr, args }
    }
}

// ── Handler trait ─────────────────────────────────────────────────────────────

/// A pluggable handler for one or more syscall numbers.
pub trait SyscallHandler: Send + Sync {
    /// Return the syscall numbers this handler supports.
    fn handles(&self) -> &[u64];

    /// Execute the syscall described by `ctx`, using `mem` for memory access
    /// and `fds` for file-descriptor state.
    ///
    /// Returns the `i64` value that should be placed in `rax` after the call,
    /// or an `EmulatorError` if emulation cannot continue.
    ///
    /// # Errors
    /// Implementations return an [`EmulatorError`] when the emulated operation
    /// cannot complete (bad fd, unmapped memory, exited process, etc.).
    fn handle(
        &self,
        ctx: &SyscallContext,
        mem: &mut EmulatedMemory,
        fds: &mut FdTable,
        state: &mut EmulatorState,
    ) -> EmulatorResult<i64>;
}

// ── Memory ────────────────────────────────────────────────────────────────────

/// A very simple flat-memory model backed by `HashMap<u64, u8>`.
///
/// Real emulators would use page-table structures; this model is intentionally
/// simple so it can run in a pure-Rust context without `unsafe`.
#[derive(Debug, Default)]
pub struct EmulatedMemory {
    pages: HashMap<u64, Vec<u8>>,
    /// Next address returned by simulated `brk` / `mmap`.
    pub brk: u64,
    pub mmap_hint: u64,
}

const PAGE_SIZE: u64 = 0x1000;

impl EmulatedMemory {
    #[must_use]
    pub fn new(brk_start: u64) -> Self {
        Self {
            pages: HashMap::new(),
            brk: brk_start,
            mmap_hint: 0x7f00_0000_0000,
        }
    }

    const fn page_key(addr: u64) -> u64 {
        addr & !(PAGE_SIZE - 1)
    }

    /// Map `len` bytes of zeroed memory starting at `addr`.
    pub fn map(&mut self, addr: u64, len: usize) {
        let mut cur = Self::page_key(addr);
        let end = addr.saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
        let page_bytes = usize::try_from(PAGE_SIZE).unwrap_or(usize::MAX);
        while cur < end {
            self.pages
                .entry(cur)
                .or_insert_with(|| vec![0u8; page_bytes]);
            cur += PAGE_SIZE;
        }
    }

    /// Unmap the region.  Ignores pages that were not mapped.
    pub fn unmap(&mut self, addr: u64, len: usize) {
        let mut cur = Self::page_key(addr);
        let end = addr.saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
        while cur < end {
            self.pages.remove(&cur);
            cur += PAGE_SIZE;
        }
    }

    /// Read a single byte, returning `None` if unmapped.
    #[must_use]
    pub fn read_byte(&self, addr: u64) -> Option<u8> {
        let page = self.pages.get(&Self::page_key(addr))?;
        let off = usize::try_from(addr & (PAGE_SIZE - 1)).ok()?;
        Some(page[off])
    }

    /// Write a single byte.  Returns `false` if the page is not mapped.
    pub fn write_byte(&mut self, addr: u64, val: u8) -> bool {
        let key = Self::page_key(addr);
        self.pages.get_mut(&key).is_some_and(|page| {
            let Ok(off) = usize::try_from(addr & (PAGE_SIZE - 1)) else {
                return false;
            };
            page[off] = val;
            true
        })
    }

    /// Copy bytes into `dst` starting at `addr`.
    ///
    /// # Errors
    /// Returns [`EmulatorError::Unmapped`] when any byte in the requested range
    /// falls outside a mapped page.
    pub fn read_bytes(&self, addr: u64, dst: &mut [u8]) -> EmulatorResult<()> {
        for (i, b) in dst.iter_mut().enumerate() {
            let off = u64::try_from(i).unwrap_or(0);
            *b = self.read_byte(addr + off).ok_or(EmulatorError::Unmapped {
                addr: addr + off,
                len: 1,
            })?;
        }
        Ok(())
    }

    /// Copy `src` bytes to `addr`.
    ///
    /// # Errors
    /// Returns [`EmulatorError::Unmapped`] when any byte in the requested range
    /// falls outside a mapped page.
    pub fn write_bytes(&mut self, addr: u64, src: &[u8]) -> EmulatorResult<()> {
        for (i, &b) in src.iter().enumerate() {
            let off = u64::try_from(i).unwrap_or(0);
            if !self.write_byte(addr + off, b) {
                return Err(EmulatorError::Unmapped {
                    addr: addr + off,
                    len: 1,
                });
            }
        }
        Ok(())
    }

    /// Read a NUL-terminated string.  Returns at most 4096 bytes.
    ///
    /// # Errors
    /// Returns [`EmulatorError::Unmapped`] when traversal hits an unmapped
    /// page before encountering a NUL byte.
    pub fn read_cstr(&self, addr: u64) -> EmulatorResult<String> {
        let mut bytes = Vec::new();
        for i in 0..4096u64 {
            let b = self.read_byte(addr + i).ok_or(EmulatorError::Unmapped {
                addr: addr + i,
                len: 1,
            })?;
            if b == 0 {
                break;
            }
            bytes.push(b);
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Read a `u64` little-endian from `addr`.
    ///
    /// # Errors
    /// Returns [`EmulatorError::Unmapped`] when the eight bytes are not fully
    /// mapped.
    pub fn read_u64(&self, addr: u64) -> EmulatorResult<u64> {
        let mut buf = [0u8; 8];
        self.read_bytes(addr, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }
}

// ── FD table ──────────────────────────────────────────────────────────────────

/// The process file-descriptor table.
#[derive(Debug, Default)]
pub struct FdTable {
    fds: HashMap<i64, EmulatedFd>,
    next_fd: i64,
}

impl FdTable {
    #[must_use]
    pub fn new() -> Self {
        let mut t = Self {
            fds: HashMap::new(),
            next_fd: 3,
        };
        // Standard streams
        t.fds.insert(0, EmulatedFd::null("/dev/stdin"));
        t.fds.insert(1, EmulatedFd::null("/dev/stdout"));
        t.fds.insert(2, EmulatedFd::null("/dev/stderr"));
        t
    }

    /// Insert a new fd and return its number.
    pub fn insert(&mut self, fd: EmulatedFd) -> i64 {
        let n = self.next_fd;
        self.fds.insert(n, fd);
        self.next_fd += 1;
        n
    }

    #[must_use]
    pub fn get(&self, fd: i64) -> Option<&EmulatedFd> {
        self.fds.get(&fd)
    }

    pub fn get_mut(&mut self, fd: i64) -> Option<&mut EmulatedFd> {
        self.fds.get_mut(&fd)
    }

    pub fn close(&mut self, fd: i64) -> bool {
        self.fds.remove(&fd).is_some()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.fds.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fds.is_empty()
    }
}

// ── Emulator state ────────────────────────────────────────────────────────────

/// Mutable process-level state shared across handlers.
#[derive(Debug)]
pub struct EmulatorState {
    /// Simulated PID.
    pub pid: u32,
    /// Simulated UID.
    pub uid: u32,
    /// Simulated EUID.
    pub euid: u32,
    /// Current working directory (virtual).
    pub cwd: String,
    /// Number of syscalls executed so far.
    pub syscall_count: u64,
}

impl Default for EmulatorState {
    fn default() -> Self {
        Self {
            pid: 1234,
            uid: 1000,
            euid: 1000,
            cwd: "/".to_string(),
            syscall_count: 0,
        }
    }
}

// ── Handler registry ──────────────────────────────────────────────────────────

/// Maps syscall numbers to handler implementations.
#[derive(Default)]
pub struct HandlerRegistry {
    map: HashMap<u64, std::sync::Arc<Box<dyn SyscallHandler>>>,
}

impl HandlerRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a handler.  Panics if any of its syscall numbers is already
    /// claimed by a different handler.
    ///
    /// # Panics
    /// Panics if `handler.handles()` reports a syscall number that another
    /// handler already owns.
    pub fn register(&mut self, handler: Box<dyn SyscallHandler>) {
        for &nr in handler.handles() {
            assert!(
                !self.map.contains_key(&nr),
                "syscall {nr} already has a registered handler"
            );
            // Safety: we only store one handler per number; the panic above
            // ensures uniqueness.  The cast is safe because `handles()` and
            // `handle()` belong to the same object.
        }
        // Store under the first syscall number; the emulator looks up by nr.
        for &nr in handler.handles() {
            // We need individual Box clones — work around by using Arc internally
            // in the caller, or accept that we store the handler pointer once and
            // alias it.  For simplicity we use a shared-reference trick via
            // unsafe pointer equality: instead, we store a fresh `Box` per entry
            // by requiring `SyscallHandler: Clone` is NOT needed — we just store
            // the box for the first nr and store unit stubs for the rest.
            //
            // Practical approach: the registry stores one Box<dyn SyscallHandler>
            // and individual entries reference it.  Since Box is not Clone we
            // use `std::sync::Arc` internally.
            let _ = nr; // handled below
        }
        // Re-implementation using Arc to allow multiple nr -> same handler.
        let arc = std::sync::Arc::new(handler);
        for &nr in arc.handles() {
            self.map.insert(nr, std::sync::Arc::clone(&arc));
        }
    }

    #[must_use]
    pub fn lookup(&self, nr: u64) -> Option<&dyn SyscallHandler> {
        self.map.get(&nr).map(|b| b.as_ref().as_ref())
    }

    /// Look up a handler and return an owned clone of the registered `Arc`,
    /// releasing the borrow on `self` so the caller can simultaneously hold
    /// mutable borrows of other emulator state while dispatching.
    pub fn lookup_owned(&self, nr: u64) -> Option<std::sync::Arc<Box<dyn SyscallHandler>>> {
        self.map.get(&nr).map(std::sync::Arc::clone)
    }

    #[must_use]
    pub fn registered_count(&self) -> usize {
        self.map.len()
    }
}

/// Wrapper that lets an `Arc<Box<dyn SyscallHandler>>` satisfy `SyscallHandler`.
///
/// Useful when a caller wants to share a single handler across multiple
/// registries or alongside other dispatch tables without paying for a deep
/// clone of the underlying handler state.
pub struct ArcHandler(pub std::sync::Arc<Box<dyn SyscallHandler>>);

impl SyscallHandler for ArcHandler {
    fn handles(&self) -> &[u64] {
        self.0.handles()
    }
    fn handle(
        &self,
        ctx: &SyscallContext,
        mem: &mut EmulatedMemory,
        fds: &mut FdTable,
        state: &mut EmulatorState,
    ) -> EmulatorResult<i64> {
        self.0.handle(ctx, mem, fds, state)
    }
}

// ── Built-in handlers ─────────────────────────────────────────────────────────

/// `read(fd, buf, count)` — syscall 0
pub struct ReadHandler;
impl SyscallHandler for ReadHandler {
    fn handles(&self) -> &[u64] {
        &[0]
    }
    fn handle(
        &self,
        ctx: &SyscallContext,
        mem: &mut EmulatedMemory,
        fds: &mut FdTable,
        _state: &mut EmulatorState,
    ) -> EmulatorResult<i64> {
        // Cap at 16 MiB to prevent OOM from adversarial `count` values
        const MAX_IO: usize = 16 * 1024 * 1024;
        let fd = ctx.args[0].cast_signed();
        let buf_addr = ctx.args[1];
        let count = usize::try_from(ctx.args[2]).unwrap_or(MAX_IO).min(MAX_IO);
        let entry = fds.get_mut(fd).ok_or(EmulatorError::BadFd(fd))?;
        let mut tmp = vec![0u8; count];
        let n = entry.read(&mut tmp, count);
        let n_usize = usize::try_from(n).unwrap_or(0);
        mem.write_bytes(buf_addr, &tmp[..n_usize])?;
        Ok(n)
    }
}

/// `write(fd, buf, count)` — syscall 1
pub struct WriteHandler;
impl SyscallHandler for WriteHandler {
    fn handles(&self) -> &[u64] {
        &[1]
    }
    fn handle(
        &self,
        ctx: &SyscallContext,
        mem: &mut EmulatedMemory,
        fds: &mut FdTable,
        _state: &mut EmulatorState,
    ) -> EmulatorResult<i64> {
        // Cap at 16 MiB to prevent OOM from adversarial `count` values
        const MAX_IO: usize = 16 * 1024 * 1024;
        let fd = ctx.args[0].cast_signed();
        let buf_addr = ctx.args[1];
        let count = usize::try_from(ctx.args[2]).unwrap_or(MAX_IO).min(MAX_IO);
        let mut tmp = vec![0u8; count];
        mem.read_bytes(buf_addr, &mut tmp)?;
        let entry = fds.get_mut(fd).ok_or(EmulatorError::BadFd(fd))?;
        Ok(entry.write(&tmp))
    }
}

/// `open(path, flags, mode)` — syscall 2
pub struct OpenHandler;
impl SyscallHandler for OpenHandler {
    fn handles(&self) -> &[u64] {
        &[2]
    }
    fn handle(
        &self,
        ctx: &SyscallContext,
        mem: &mut EmulatedMemory,
        fds: &mut FdTable,
        _state: &mut EmulatorState,
    ) -> EmulatorResult<i64> {
        let path_addr = ctx.args[0];
        let flags = i32::try_from(ctx.args[1].cast_signed()).unwrap_or(0);
        let path = mem.read_cstr(path_addr)?;
        let fd = EmulatedFd::new_buffer(path, flags);
        Ok(fds.insert(fd))
    }
}

/// `close(fd)` — syscall 3
pub struct CloseHandler;
impl SyscallHandler for CloseHandler {
    fn handles(&self) -> &[u64] {
        &[3]
    }
    fn handle(
        &self,
        ctx: &SyscallContext,
        _mem: &mut EmulatedMemory,
        fds: &mut FdTable,
        _state: &mut EmulatorState,
    ) -> EmulatorResult<i64> {
        let fd = ctx.args[0].cast_signed();
        if fds.close(fd) {
            Ok(0)
        } else {
            Err(EmulatorError::BadFd(fd))
        }
    }
}

/// `getpid()` — syscall 39
pub struct GetpidHandler;
impl SyscallHandler for GetpidHandler {
    fn handles(&self) -> &[u64] {
        &[39]
    }
    fn handle(
        &self,
        _ctx: &SyscallContext,
        _mem: &mut EmulatedMemory,
        _fds: &mut FdTable,
        state: &mut EmulatorState,
    ) -> EmulatorResult<i64> {
        Ok(i64::from(state.pid))
    }
}

/// `brk(addr)` — syscall 12
pub struct BrkHandler;
impl SyscallHandler for BrkHandler {
    fn handles(&self) -> &[u64] {
        &[12]
    }
    fn handle(
        &self,
        ctx: &SyscallContext,
        mem: &mut EmulatedMemory,
        _fds: &mut FdTable,
        _state: &mut EmulatorState,
    ) -> EmulatorResult<i64> {
        let new_brk = ctx.args[0];
        if new_brk == 0 {
            return Ok(mem.brk.cast_signed());
        }
        if new_brk > mem.brk {
            let len = usize::try_from(new_brk - mem.brk).unwrap_or(usize::MAX);
            mem.map(mem.brk, len);
        }
        mem.brk = new_brk;
        Ok(mem.brk.cast_signed())
    }
}

/// `mmap(addr, length, prot, flags, fd, offset)` — syscall 9
pub struct MmapHandler;
impl SyscallHandler for MmapHandler {
    fn handles(&self) -> &[u64] {
        &[9]
    }
    fn handle(
        &self,
        ctx: &SyscallContext,
        mem: &mut EmulatedMemory,
        _fds: &mut FdTable,
        _state: &mut EmulatorState,
    ) -> EmulatorResult<i64> {
        let hint = ctx.args[0];
        let len = usize::try_from(ctx.args[1]).unwrap_or(usize::MAX);
        let addr = if hint == 0 { mem.mmap_hint } else { hint };
        mem.map(addr, len);
        // Advance mmap hint by len rounded up to page.
        let pages = (u64::try_from(len).unwrap_or(u64::MAX) + 0xfff) & !0xfff;
        if hint == 0 {
            mem.mmap_hint += pages;
        }
        Ok(addr.cast_signed())
    }
}

/// `munmap(addr, length)` — syscall 11
pub struct MunmapHandler;
impl SyscallHandler for MunmapHandler {
    fn handles(&self) -> &[u64] {
        &[11]
    }
    fn handle(
        &self,
        ctx: &SyscallContext,
        mem: &mut EmulatedMemory,
        _fds: &mut FdTable,
        _state: &mut EmulatorState,
    ) -> EmulatorResult<i64> {
        let addr = ctx.args[0];
        let len = usize::try_from(ctx.args[1]).unwrap_or(usize::MAX);
        mem.unmap(addr, len);
        Ok(0)
    }
}

/// `mprotect(addr, len, prot)` — syscall 10  (stub: always succeeds)
pub struct MprotectHandler;
impl SyscallHandler for MprotectHandler {
    fn handles(&self) -> &[u64] {
        &[10]
    }
    fn handle(
        &self,
        _ctx: &SyscallContext,
        _mem: &mut EmulatedMemory,
        _fds: &mut FdTable,
        _state: &mut EmulatorState,
    ) -> EmulatorResult<i64> {
        Ok(0)
    }
}

/// `exit(code)` / `exit_group(code)` — syscalls 60, 231
pub struct ExitHandler;
impl SyscallHandler for ExitHandler {
    fn handles(&self) -> &[u64] {
        &[60, 231]
    }
    fn handle(
        &self,
        ctx: &SyscallContext,
        _mem: &mut EmulatedMemory,
        _fds: &mut FdTable,
        _state: &mut EmulatorState,
    ) -> EmulatorResult<i64> {
        Err(EmulatorError::Exited(
            i32::try_from(ctx.args[0].cast_signed()).unwrap_or(0),
        ))
    }
}

/// `getcwd(buf, size)` — syscall 79
pub struct GetcwdHandler;
impl SyscallHandler for GetcwdHandler {
    fn handles(&self) -> &[u64] {
        &[79]
    }
    fn handle(
        &self,
        ctx: &SyscallContext,
        mem: &mut EmulatedMemory,
        _fds: &mut FdTable,
        state: &mut EmulatorState,
    ) -> EmulatorResult<i64> {
        let buf_addr = ctx.args[0];
        let size = usize::try_from(ctx.args[1]).unwrap_or(usize::MAX);
        let cwd = state.cwd.clone();
        let bytes = cwd.as_bytes();
        if bytes.len() + 1 > size {
            return Err(EmulatorError::InvalidArg("buffer too small for cwd".into()));
        }
        mem.write_bytes(buf_addr, bytes)?;
        mem.write_bytes(buf_addr + u64::try_from(bytes.len()).unwrap_or(0), &[0])?;
        Ok(buf_addr.cast_signed())
    }
}

/// `getuid()` — syscall 102; `geteuid()` — syscall 107
pub struct GetuidHandler;
impl SyscallHandler for GetuidHandler {
    fn handles(&self) -> &[u64] {
        &[102, 107]
    }
    fn handle(
        &self,
        ctx: &SyscallContext,
        _mem: &mut EmulatedMemory,
        _fds: &mut FdTable,
        state: &mut EmulatorState,
    ) -> EmulatorResult<i64> {
        Ok(if ctx.nr == 102 {
            i64::from(state.uid)
        } else {
            i64::from(state.euid)
        })
    }
}

// ── Top-level emulator ────────────────────────────────────────────────────────

/// The main syscall emulator.
///
/// Construct with `SyscallEmulator::new()` which pre-registers all built-in
/// handlers, then call `execute()` to dispatch a single syscall.
pub struct SyscallEmulator {
    pub registry: HandlerRegistry,
    pub memory: EmulatedMemory,
    pub fds: FdTable,
    pub state: EmulatorState,
}

impl SyscallEmulator {
    /// Create an emulator with all built-in handlers pre-registered.
    #[must_use]
    pub fn new() -> Self {
        let mut registry = HandlerRegistry::new();
        registry.register(Box::new(ReadHandler));
        registry.register(Box::new(WriteHandler));
        registry.register(Box::new(OpenHandler));
        registry.register(Box::new(CloseHandler));
        registry.register(Box::new(GetpidHandler));
        registry.register(Box::new(BrkHandler));
        registry.register(Box::new(MmapHandler));
        registry.register(Box::new(MunmapHandler));
        registry.register(Box::new(MprotectHandler));
        registry.register(Box::new(ExitHandler));
        registry.register(Box::new(GetcwdHandler));
        registry.register(Box::new(GetuidHandler));

        Self {
            registry,
            memory: EmulatedMemory::new(0x0040_0000),
            fds: FdTable::new(),
            state: EmulatorState::default(),
        }
    }

    /// Dispatch a single syscall described by `ctx`.
    ///
    /// On success returns the `i64` result value.
    /// Returns `EmulatorError::UnhandledSyscall` when no handler is registered.
    /// Returns `EmulatorError::Exited` when an exit syscall is executed.
    ///
    /// # Errors
    /// Propagates any error from the registered handler, plus
    /// [`EmulatorError::UnhandledSyscall`] when the syscall number is unknown.
    pub fn execute(&mut self, ctx: &SyscallContext) -> EmulatorResult<i64> {
        self.state.syscall_count += 1;
        let handler = self
            .registry
            .lookup_owned(ctx.nr)
            .ok_or(EmulatorError::UnhandledSyscall(ctx.nr))?;
        // Borrow on `self.registry` is released — we now hold an owned `Arc`
        // and can mutably borrow the rest of `self` for the call.
        handler.handle(ctx, &mut self.memory, &mut self.fds, &mut self.state)
    }

    /// Convenience: execute using raw (nr, args) without building a context.
    ///
    /// # Errors
    /// See [`Self::execute`].
    pub fn syscall(&mut self, nr: u64, args: [u64; 6]) -> EmulatorResult<i64> {
        self.execute(&SyscallContext::new(nr, args))
    }
}

impl Default for SyscallEmulator {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn emu() -> SyscallEmulator {
        SyscallEmulator::new()
    }

    // ── memory ────────────────────────────────────────────────────────────────

    #[test]
    fn test_memory_map_unmap() {
        let mut m = EmulatedMemory::new(0x1000);
        m.map(0x2000, 0x1000);
        assert!(m.read_byte(0x2000).is_some());
        m.unmap(0x2000, 0x1000);
        assert!(m.read_byte(0x2000).is_none());
    }

    #[test]
    fn test_memory_write_read_byte() {
        let mut m = EmulatedMemory::new(0x1000);
        m.map(0x3000, 0x1000);
        assert!(m.write_byte(0x3042, 0xAB));
        assert_eq!(m.read_byte(0x3042), Some(0xAB));
    }

    #[test]
    fn test_memory_read_bytes_error_on_unmapped() {
        let m = EmulatedMemory::new(0x1000);
        let mut buf = [0u8; 4];
        assert!(m.read_bytes(0xDEAD_0000, &mut buf).is_err());
    }

    #[test]
    fn test_memory_read_cstr() {
        let mut m = EmulatedMemory::new(0x1000);
        m.map(0x5000, 0x1000);
        m.write_bytes(0x5000, b"/etc/passwd\0").unwrap();
        assert_eq!(m.read_cstr(0x5000).unwrap(), "/etc/passwd");
    }

    #[test]
    fn test_memory_read_u64() {
        let mut m = EmulatedMemory::new(0x1000);
        m.map(0x6000, 0x1000);
        m.write_bytes(0x6000, &0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes())
            .unwrap();
        assert_eq!(m.read_u64(0x6000).unwrap(), 0xDEAD_BEEF_CAFE_BABEu64);
    }

    // ── fd table ──────────────────────────────────────────────────────────────

    #[test]
    fn test_fd_table_initial_standard_streams() {
        let t = FdTable::new();
        assert!(t.get(0).is_some());
        assert!(t.get(1).is_some());
        assert!(t.get(2).is_some());
    }

    #[test]
    fn test_fd_insert_and_close() {
        let mut t = FdTable::new();
        let fd = t.insert(EmulatedFd::null("/dev/zero"));
        assert!(t.get(fd).is_some());
        assert!(t.close(fd));
        assert!(t.get(fd).is_none());
    }

    #[test]
    fn test_emulated_fd_read_write() {
        let mut fd = EmulatedFd::with_contents("/tmp/test", 0, b"hello world".to_vec());
        let mut buf = [0u8; 5];
        let n = fd.read(&mut buf, 5);
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn test_emulated_fd_null_read_returns_zero() {
        let mut fd = EmulatedFd::null("/dev/null");
        let mut buf = [0u8; 10];
        assert_eq!(fd.read(&mut buf, 10), 0);
    }

    #[test]
    fn test_emulated_fd_null_write_succeeds() {
        let mut fd = EmulatedFd::null("/dev/null");
        assert_eq!(fd.write(b"anything"), 8);
    }

    // ── built-in syscalls ─────────────────────────────────────────────────────

    #[test]
    fn test_getpid() {
        let mut e = emu();
        let pid = e.syscall(39, [0; 6]).unwrap();
        assert_eq!(pid, 1234);
    }

    #[test]
    fn test_brk_query_returns_current() {
        let mut e = emu();
        let cur = e.memory.brk;
        let ret = e.syscall(12, [0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(ret.cast_unsigned(), cur);
    }

    #[test]
    fn test_brk_extend() {
        let mut e = emu();
        let old = e.memory.brk;
        let new_brk = old + 0x2000;
        let ret = e.syscall(12, [new_brk, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(ret.cast_unsigned(), new_brk);
        assert!(e.memory.read_byte(old).is_some());
    }

    #[test]
    fn test_mmap_returns_address() {
        let mut e = emu();
        let addr = e
            .syscall(9, [0, 0x1000, 3, 34, u64::MAX, 0])
            .unwrap()
            .cast_unsigned();
        assert!(addr != 0);
        assert!(e.memory.read_byte(addr).is_some());
    }

    #[test]
    fn test_munmap_removes_mapping() {
        let mut e = emu();
        let addr = e
            .syscall(9, [0, 0x1000, 3, 34, u64::MAX, 0])
            .unwrap()
            .cast_unsigned();
        e.syscall(11, [addr, 0x1000, 0, 0, 0, 0]).unwrap();
        assert!(e.memory.read_byte(addr).is_none());
    }

    #[test]
    fn test_mprotect_is_nop() {
        let mut e = emu();
        let ret = e.syscall(10, [0x1000, 0x1000, 7, 0, 0, 0]).unwrap();
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_exit_returns_exited_error() {
        let mut e = emu();
        match e.syscall(60, [42, 0, 0, 0, 0, 0]) {
            Err(EmulatorError::Exited(42)) => {}
            other => panic!("expected Exited(42), got {other:?}"),
        }
    }

    #[test]
    fn test_exit_group_returns_exited_error() {
        let mut e = emu();
        assert!(matches!(
            e.syscall(231, [1, 0, 0, 0, 0, 0]),
            Err(EmulatorError::Exited(1))
        ));
    }

    #[test]
    fn test_getuid() {
        let mut e = emu();
        assert_eq!(e.syscall(102, [0; 6]).unwrap(), 1000);
    }

    #[test]
    fn test_geteuid() {
        let mut e = emu();
        assert_eq!(e.syscall(107, [0; 6]).unwrap(), 1000);
    }

    #[test]
    fn test_getcwd() {
        let mut e = emu();
        e.memory.map(0x8000, 0x1000);
        let ret = e.syscall(79, [0x8000, 512, 0, 0, 0, 0]).unwrap();
        assert_eq!(ret.cast_unsigned(), 0x8000);
        assert_eq!(e.memory.read_cstr(0x8000).unwrap(), "/");
    }

    #[test]
    fn test_write_syscall() {
        let mut e = emu();
        e.memory.map(0x9000, 0x1000);
        e.memory.write_bytes(0x9000, b"hello").unwrap();
        // write to stdout (fd=1)
        let n = e.syscall(1, [1, 0x9000, 5, 0, 0, 0]).unwrap();
        assert_eq!(n, 5);
    }

    #[test]
    fn test_open_and_close() {
        let mut e = emu();
        e.memory.map(0xA000, 0x1000);
        e.memory.write_bytes(0xA000, b"/tmp/test.txt\0").unwrap();
        let fd = e.syscall(2, [0xA000, 0, 0, 0, 0, 0]).unwrap();
        assert!(fd >= 3);
        let ret = e.syscall(3, [fd.cast_unsigned(), 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_unhandled_syscall_error() {
        let mut e = emu();
        match e.syscall(999, [0; 6]) {
            Err(EmulatorError::UnhandledSyscall(999)) => {}
            other => panic!("expected UnhandledSyscall(999), got {other:?}"),
        }
    }

    #[test]
    fn test_syscall_count_increments() {
        let mut e = emu();
        e.syscall(39, [0; 6]).unwrap();
        e.syscall(39, [0; 6]).unwrap();
        assert_eq!(e.state.syscall_count, 2);
    }

    #[test]
    fn test_handler_registry_registered_count() {
        let e = emu();
        // ReadHandler(1) + WriteHandler(1) + OpenHandler(1) + CloseHandler(1)
        // + GetpidHandler(1) + BrkHandler(1) + MmapHandler(1) + MunmapHandler(1)
        // + MprotectHandler(1) + ExitHandler(2) + GetcwdHandler(1) + GetuidHandler(2) = 14
        assert!(e.registry.registered_count() >= 12);
    }
}
