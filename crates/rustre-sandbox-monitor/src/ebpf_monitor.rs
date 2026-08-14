//! eBPF-based Linux sandbox monitor stubs.
//!
//! On a real Linux system this module would use the `libbpf-rs` or `aya` crate
//! to load and attach eBPF programs.  The types here provide a complete,
//! portable simulation layer so that higher-level analysis logic can be developed
//! and tested on any platform.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum EbpfError {
    #[error("eBPF not supported on this platform")]
    Unsupported,
    #[error("failed to load eBPF program: {0}")]
    LoadError(String),
    #[error("failed to attach eBPF program to {hook}: {reason}")]
    AttachError { hook: String, reason: String },
    #[error("map operation failed: {0}")]
    MapError(String),
    #[error("session not started")]
    NotStarted,
    #[error("ring buffer error: {0}")]
    RingBufferError(String),
}

// ─── SyscallId ────────────────────────────────────────────────────────────────

/// Linux syscall numbers (`x86_64`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyscallId {
    /// `sys_execve` — execute a program.
    Execve = 59,
    /// `sys_execveat` — execute a program (relative).
    Execveat = 322,
    /// `sys_openat` — open a file descriptor.
    Openat = 257,
    /// `sys_open` — open a file (legacy).
    Open = 2,
    /// `sys_connect` — connect a socket.
    Connect = 42,
    /// `sys_write` — write data.
    Write = 1,
    /// `sys_read` — read data.
    Read = 0,
    /// `sys_socket` — create socket.
    Socket = 41,
    /// `sys_bind` — bind a socket.
    Bind = 49,
    /// `sys_accept` — accept a connection.
    Accept = 43,
    /// `sys_sendto` — send data.
    Sendto = 44,
    /// `sys_recvfrom` — receive data.
    Recvfrom = 45,
    /// `sys_fork` — create a child process.
    Fork = 57,
    /// `sys_clone` — create a child process (flexible).
    Clone = 56,
    /// `sys_mmap` — map files or devices into memory.
    Mmap = 9,
    /// `sys_mprotect` — set memory protection.
    Mprotect = 10,
    /// `sys_ptrace` — process trace.
    Ptrace = 101,
    /// `sys_kill` — send signal to process.
    Kill = 62,
    /// `sys_unlink` — delete a file.
    Unlink = 87,
    /// Unknown syscall.
    Unknown = 0xFFFF,
}

impl SyscallId {
    /// Decode from a raw syscall number.
    #[must_use]
    pub const fn from_nr(nr: u64) -> Self {
        match nr {
            0 => Self::Read,
            1 => Self::Write,
            2 => Self::Open,
            9 => Self::Mmap,
            10 => Self::Mprotect,
            41 => Self::Socket,
            42 => Self::Connect,
            43 => Self::Accept,
            44 => Self::Sendto,
            45 => Self::Recvfrom,
            49 => Self::Bind,
            56 => Self::Clone,
            57 => Self::Fork,
            59 => Self::Execve,
            62 => Self::Kill,
            87 => Self::Unlink,
            101 => Self::Ptrace,
            257 => Self::Openat,
            322 => Self::Execveat,
            _ => Self::Unknown,
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Open => "open",
            Self::Mmap => "mmap",
            Self::Mprotect => "mprotect",
            Self::Socket => "socket",
            Self::Connect => "connect",
            Self::Accept => "accept",
            Self::Sendto => "sendto",
            Self::Recvfrom => "recvfrom",
            Self::Bind => "bind",
            Self::Clone => "clone",
            Self::Fork => "fork",
            Self::Execve => "execve",
            Self::Kill => "kill",
            Self::Unlink => "unlink",
            Self::Ptrace => "ptrace",
            Self::Openat => "openat",
            Self::Execveat => "execveat",
            Self::Unknown => "unknown",
        }
    }

    /// Returns `true` if this syscall is considered high-risk.
    #[must_use]
    pub const fn is_high_risk(self) -> bool {
        matches!(
            self,
            Self::Execve
                | Self::Execveat
                | Self::Ptrace
                | Self::Mprotect
                | Self::Clone
                | Self::Fork
        )
    }
}

// ─── BpfEvent ─────────────────────────────────────────────────────────────────

/// An event captured from an eBPF program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfEvent {
    /// Process ID.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Process name (`comm` in kernel, up to 16 chars).
    pub comm: String,
    /// Syscall identifier.
    pub syscall_id: SyscallId,
    /// Raw syscall arguments (up to 6).
    pub args: [u64; 6],
    /// Return value (0 on entry events).
    pub ret: i64,
    /// Unix nanosecond timestamp.
    pub timestamp_ns: u64,
    /// True if this is a syscall-entry event; false if exit.
    pub is_entry: bool,
    /// UID of the calling process.
    pub uid: u32,
    /// Additional string data (e.g. filename for openat/execve).
    pub str_arg: Option<String>,
}

impl BpfEvent {
    /// Create a syscall entry event.
    #[must_use]
    pub fn new_entry(
        pid: u32,
        tid: u32,
        comm: impl Into<String>,
        syscall_id: SyscallId,
        args: [u64; 6],
    ) -> Self {
        let timestamp_ns = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_nanos(),
        )
        .unwrap_or(u64::MAX);
        Self {
            pid,
            tid,
            comm: comm.into(),
            syscall_id,
            args,
            ret: 0,
            timestamp_ns,
            is_entry: true,
            uid: 0,
            str_arg: None,
        }
    }

    /// Create a syscall exit event.
    #[must_use]
    pub fn new_exit(
        pid: u32,
        tid: u32,
        comm: impl Into<String>,
        syscall_id: SyscallId,
        ret: i64,
    ) -> Self {
        let mut ev = Self::new_entry(pid, tid, comm, syscall_id, [0; 6]);
        ev.is_entry = false;
        ev.ret = ret;
        ev
    }

    /// Builder: set the string argument.
    #[must_use]
    pub fn with_str_arg(mut self, s: impl Into<String>) -> Self {
        self.str_arg = Some(s.into());
        self
    }

    /// Builder: set the UID.
    #[must_use]
    pub const fn with_uid(mut self, uid: u32) -> Self {
        self.uid = uid;
        self
    }

    /// Returns `true` if this event involves a high-risk syscall.
    #[must_use]
    pub const fn is_high_risk(&self) -> bool {
        self.syscall_id.is_high_risk()
    }
}

// ─── EbpfMapType ─────────────────────────────────────────────────────────────

/// eBPF map types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EbpfMapType {
    /// Hash map (`BPF_MAP_TYPE_HASH`).
    Hash,
    /// Array map (`BPF_MAP_TYPE_ARRAY`).
    Array,
    /// Ring buffer (`BPF_MAP_TYPE_RINGBUF`).
    RingBuffer,
    /// Per-CPU hash map.
    PerCpuHash,
    /// LRU hash map.
    LruHash,
}

// ─── EbpfMap ─────────────────────────────────────────────────────────────────

/// Stub for an eBPF map (backed by an in-memory hash map).
#[derive(Debug)]
pub struct EbpfMap {
    pub name: String,
    pub map_type: EbpfMapType,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    data: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

impl EbpfMap {
    /// Create a new in-memory eBPF map stub.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        map_type: EbpfMapType,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    ) -> Self {
        Self {
            name: name.into(),
            map_type,
            key_size,
            value_size,
            max_entries,
            data: RwLock::new(HashMap::new()),
        }
    }

    /// Look up a value by key.
    #[must_use]
    pub fn lookup(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.data.read().get(key).cloned()
    }

    /// Insert or update a key-value pair.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::MapError`] when the map is at capacity and `key` is new.
    pub fn update(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), EbpfError> {
        let mut data = self.data.write();
        if data.len() >= self.max_entries as usize && !data.contains_key(&key) {
            return Err(EbpfError::MapError("map is full".into()));
        }
        data.insert(key, value);
        Ok(())
    }

    /// Delete a key.
    pub fn delete(&self, key: &[u8]) -> bool {
        self.data.write().remove(key).is_some()
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.read().len()
    }

    /// Returns `true` if the map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.read().is_empty()
    }

    /// Return all key-value pairs.
    #[must_use]
    pub fn entries(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.data
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

// ─── EbpfProgramKind ─────────────────────────────────────────────────────────

/// The kind of eBPF program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EbpfProgramKind {
    /// Kprobe / tracepoint.
    Kprobe,
    /// Kretprobe.
    Kretprobe,
    /// Tracepoint.
    Tracepoint,
    /// TP-BTF (typed tracepoint).
    TpBtf,
    /// Socket filter.
    SocketFilter,
    /// XDP program.
    Xdp,
}

// ─── EbpfProgram ─────────────────────────────────────────────────────────────

/// Stub for an eBPF program.  On Linux this would wrap a `libbpf_rs::Program`.
#[derive(Debug)]
pub struct EbpfProgram {
    pub name: String,
    pub kind: EbpfProgramKind,
    pub hook: String,
    pub is_attached: AtomicBool,
    pub invocation_count: AtomicU64,
}

impl EbpfProgram {
    #[must_use]
    pub fn new(name: impl Into<String>, kind: EbpfProgramKind, hook: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind,
            hook: hook.into(),
            is_attached: AtomicBool::new(false),
            invocation_count: AtomicU64::new(0),
        }
    }

    /// Simulate attaching this program.
    ///
    /// # Errors
    ///
    /// Never errors in simulation mode, but returns `Result` for API compatibility.
    pub fn attach(&self) -> Result<(), EbpfError> {
        // On a real Linux system this would call libbpf / aya attach APIs.
        #[cfg(target_os = "linux")]
        {
            self.is_attached.store(true, Ordering::SeqCst);
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.is_attached.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Simulate detaching.
    pub fn detach(&self) {
        self.is_attached.store(false, Ordering::SeqCst);
    }

    /// Simulate a program invocation (increment counter).
    pub fn simulate_invoke(&self) {
        self.invocation_count.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn is_attached(&self) -> bool {
        self.is_attached.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn invocation_count(&self) -> u64 {
        self.invocation_count.load(Ordering::Relaxed)
    }
}

// ─── EbpfMonitorSession ───────────────────────────────────────────────────────

/// A monitoring session built from multiple eBPF programs watching specific hooks.
pub struct EbpfMonitorSession {
    programs: Vec<Arc<EbpfProgram>>,
    event_buf: Arc<Mutex<VecDeque<BpfEvent>>>,
    capacity: usize,
    running: AtomicBool,
    total_events: AtomicU64,
    /// Per-PID event counts.
    pid_counts: RwLock<HashMap<u32, u64>>,
    /// Per-syscall counts.
    syscall_counts: RwLock<HashMap<SyscallId, u64>>,
}

impl EbpfMonitorSession {
    /// Create a new session with the given ring-buffer capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            programs: Vec::new(),
            event_buf: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            capacity,
            running: AtomicBool::new(false),
            total_events: AtomicU64::new(0),
            pid_counts: RwLock::new(HashMap::new()),
            syscall_counts: RwLock::new(HashMap::new()),
        }
    }

    /// Create a pre-configured session with hooks for the four key syscalls.
    #[must_use]
    pub fn default_hooks() -> Self {
        let mut session = Self::new(8192);
        let hooks = [
            (
                "sys_enter_execve",
                EbpfProgramKind::Tracepoint,
                "syscalls/sys_enter_execve",
            ),
            (
                "sys_enter_openat",
                EbpfProgramKind::Tracepoint,
                "syscalls/sys_enter_openat",
            ),
            (
                "sys_enter_connect",
                EbpfProgramKind::Tracepoint,
                "syscalls/sys_enter_connect",
            ),
            (
                "sys_enter_write",
                EbpfProgramKind::Tracepoint,
                "syscalls/sys_enter_write",
            ),
            (
                "sys_enter_fork",
                EbpfProgramKind::Tracepoint,
                "syscalls/sys_enter_fork",
            ),
            (
                "sys_enter_mprotect",
                EbpfProgramKind::Tracepoint,
                "syscalls/sys_enter_mprotect",
            ),
            (
                "sys_enter_ptrace",
                EbpfProgramKind::Tracepoint,
                "syscalls/sys_enter_ptrace",
            ),
        ];
        for (name, kind, hook) in &hooks {
            session.add_program(EbpfProgram::new(*name, *kind, *hook));
        }
        session
    }

    /// Add a program to this session.
    pub fn add_program(&mut self, prog: EbpfProgram) {
        self.programs.push(Arc::new(prog));
    }

    /// Start the session: attach all programs.
    ///
    /// # Errors
    ///
    /// Returns an error if any program fails to attach.
    pub fn start(&self) -> Result<(), EbpfError> {
        for prog in &self.programs {
            prog.attach()?;
        }
        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Stop the session: detach all programs.
    pub fn stop(&self) {
        for prog in &self.programs {
            prog.detach();
        }
        self.running.store(false, Ordering::SeqCst);
    }

    /// Returns `true` if the session is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Inject an event (used in tests or to simulate incoming kernel data).
    pub fn push_event(&self, event: BpfEvent) {
        let pid = event.pid;
        let syscall = event.syscall_id;
        let mut buf = self.event_buf.lock();
        if buf.len() >= self.capacity {
            buf.pop_front();
        }
        buf.push_back(event);
        drop(buf);

        self.total_events.fetch_add(1, Ordering::Relaxed);
        *self.pid_counts.write().entry(pid).or_insert(0) += 1;
        *self.syscall_counts.write().entry(syscall).or_insert(0) += 1;
    }

    /// Drain all buffered events.
    #[must_use]
    pub fn drain_events(&self) -> Vec<BpfEvent> {
        self.event_buf.lock().drain(..).collect()
    }

    /// Peek at all buffered events without consuming them.
    #[must_use]
    pub fn peek_events(&self) -> Vec<BpfEvent> {
        self.event_buf.lock().iter().cloned().collect()
    }

    /// Return events for a specific PID.
    #[must_use]
    pub fn events_for_pid(&self, pid: u32) -> Vec<BpfEvent> {
        self.event_buf
            .lock()
            .iter()
            .filter(|e| e.pid == pid)
            .cloned()
            .collect()
    }

    /// Return events for a specific syscall.
    #[must_use]
    pub fn events_for_syscall(&self, id: SyscallId) -> Vec<BpfEvent> {
        self.event_buf
            .lock()
            .iter()
            .filter(|e| e.syscall_id == id)
            .cloned()
            .collect()
    }

    /// Total events received.
    #[must_use]
    pub fn total_events(&self) -> u64 {
        self.total_events.load(Ordering::Relaxed)
    }

    /// Events buffered (not yet drained).
    #[must_use]
    pub fn buffered_count(&self) -> usize {
        self.event_buf.lock().len()
    }

    /// Event count for a given PID.
    #[must_use]
    pub fn pid_event_count(&self, pid: u32) -> u64 {
        self.pid_counts.read().get(&pid).copied().unwrap_or(0)
    }

    /// Event count for a given syscall.
    #[must_use]
    pub fn syscall_event_count(&self, id: SyscallId) -> u64 {
        self.syscall_counts.read().get(&id).copied().unwrap_or(0)
    }

    /// Top-N PIDs by event count.
    #[must_use]
    pub fn top_pids(&self, n: usize) -> Vec<(u32, u64)> {
        let mut pairs: Vec<_> = self
            .pid_counts
            .read()
            .iter()
            .map(|(&k, &v)| (k, v))
            .collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }

    /// Return all attached program names.
    #[must_use]
    pub fn program_names(&self) -> Vec<&str> {
        self.programs.iter().map(|p| p.name.as_str()).collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(pid: u32, syscall: SyscallId) -> BpfEvent {
        BpfEvent::new_entry(pid, pid, "test", syscall, [0; 6])
    }

    // ── SyscallId ─────────────────────────────────────────────────────────────

    #[test]
    fn syscall_id_from_nr_known() {
        assert_eq!(SyscallId::from_nr(59), SyscallId::Execve);
        assert_eq!(SyscallId::from_nr(257), SyscallId::Openat);
        assert_eq!(SyscallId::from_nr(42), SyscallId::Connect);
        assert_eq!(SyscallId::from_nr(1), SyscallId::Write);
    }

    #[test]
    fn syscall_id_from_nr_unknown() {
        assert_eq!(SyscallId::from_nr(99999), SyscallId::Unknown);
    }

    #[test]
    fn syscall_id_name() {
        assert_eq!(SyscallId::Execve.name(), "execve");
        assert_eq!(SyscallId::Openat.name(), "openat");
        assert_eq!(SyscallId::Connect.name(), "connect");
    }

    #[test]
    fn syscall_id_high_risk() {
        assert!(SyscallId::Execve.is_high_risk());
        assert!(SyscallId::Ptrace.is_high_risk());
        assert!(!SyscallId::Write.is_high_risk());
        assert!(!SyscallId::Read.is_high_risk());
    }

    // ── BpfEvent ─────────────────────────────────────────────────────────────

    #[test]
    fn bpf_event_new_entry() {
        let ev = BpfEvent::new_entry(100, 101, "bash", SyscallId::Execve, [1, 2, 3, 0, 0, 0]);
        assert_eq!(ev.pid, 100);
        assert_eq!(ev.tid, 101);
        assert_eq!(ev.comm, "bash");
        assert!(ev.is_entry);
        assert_eq!(ev.syscall_id, SyscallId::Execve);
    }

    #[test]
    fn bpf_event_new_exit() {
        let ev = BpfEvent::new_exit(200, 200, "cat", SyscallId::Read, 42);
        assert!(!ev.is_entry);
        assert_eq!(ev.ret, 42);
    }

    #[test]
    fn bpf_event_with_str_arg() {
        let ev =
            BpfEvent::new_entry(1, 1, "ls", SyscallId::Openat, [0; 6]).with_str_arg("/etc/passwd");
        assert_eq!(ev.str_arg.as_deref(), Some("/etc/passwd"));
    }

    #[test]
    fn bpf_event_is_high_risk() {
        let ev = make_event(1, SyscallId::Execve);
        assert!(ev.is_high_risk());
        let ev2 = make_event(1, SyscallId::Write);
        assert!(!ev2.is_high_risk());
    }

    // ── EbpfMap ───────────────────────────────────────────────────────────────

    #[test]
    fn ebpf_map_insert_lookup() {
        let map = EbpfMap::new("pid_map", EbpfMapType::Hash, 4, 8, 1024);
        map.update(vec![1, 0, 0, 0], vec![10, 0, 0, 0, 0, 0, 0, 0])
            .unwrap();
        let val = map.lookup(&[1, 0, 0, 0]);
        assert!(val.is_some());
        assert_eq!(val.unwrap()[0], 10);
    }

    #[test]
    fn ebpf_map_delete() {
        let map = EbpfMap::new("m", EbpfMapType::Hash, 4, 4, 10);
        map.update(vec![0; 4], vec![0; 4]).unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.delete(&[0; 4]));
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn ebpf_map_overflow_rejected() {
        let map = EbpfMap::new("small", EbpfMapType::Hash, 4, 4, 2);
        map.update(vec![1; 4], vec![0; 4]).unwrap();
        map.update(vec![2; 4], vec![0; 4]).unwrap();
        let r = map.update(vec![3; 4], vec![0; 4]);
        assert!(r.is_err());
    }

    #[test]
    fn ebpf_map_entries() {
        let map = EbpfMap::new("e", EbpfMapType::Array, 4, 4, 10);
        map.update(vec![1; 4], vec![1; 4]).unwrap();
        map.update(vec![2; 4], vec![2; 4]).unwrap();
        assert_eq!(map.entries().len(), 2);
    }

    // ── EbpfProgram ───────────────────────────────────────────────────────────

    #[test]
    fn ebpf_program_attach_detach() {
        let prog = EbpfProgram::new(
            "p",
            EbpfProgramKind::Tracepoint,
            "syscalls/sys_enter_execve",
        );
        assert!(!prog.is_attached());
        prog.attach().unwrap();
        assert!(prog.is_attached());
        prog.detach();
        assert!(!prog.is_attached());
    }

    #[test]
    fn ebpf_program_invoke_count() {
        let prog = EbpfProgram::new("p", EbpfProgramKind::Kprobe, "do_sys_openat2");
        prog.simulate_invoke();
        prog.simulate_invoke();
        assert_eq!(prog.invocation_count(), 2);
    }

    // ── EbpfMonitorSession ────────────────────────────────────────────────────

    #[test]
    fn session_default_hooks_has_programs() {
        let session = EbpfMonitorSession::default_hooks();
        assert!(!session.program_names().is_empty());
        assert!(session.program_names().contains(&"sys_enter_execve"));
    }

    #[test]
    fn session_start_stop() {
        let session = EbpfMonitorSession::default_hooks();
        assert!(!session.is_running());
        session.start().unwrap();
        assert!(session.is_running());
        session.stop();
        assert!(!session.is_running());
    }

    #[test]
    fn session_push_and_drain() {
        let session = EbpfMonitorSession::new(100);
        session.push_event(make_event(1, SyscallId::Execve));
        session.push_event(make_event(2, SyscallId::Openat));
        assert_eq!(session.buffered_count(), 2);
        let drained = session.drain_events();
        assert_eq!(drained.len(), 2);
        assert_eq!(session.buffered_count(), 0);
    }

    #[test]
    fn session_overflow_drops_oldest() {
        let session = EbpfMonitorSession::new(2);
        session.push_event(make_event(1, SyscallId::Read));
        session.push_event(make_event(2, SyscallId::Write));
        session.push_event(make_event(3, SyscallId::Execve)); // should drop pid=1
        assert_eq!(session.buffered_count(), 2);
        let events = session.peek_events();
        assert!(!events.iter().any(|e| e.pid == 1));
    }

    #[test]
    fn session_events_for_pid() {
        let session = EbpfMonitorSession::new(100);
        session.push_event(make_event(10, SyscallId::Execve));
        session.push_event(make_event(20, SyscallId::Openat));
        session.push_event(make_event(10, SyscallId::Write));
        let evs = session.events_for_pid(10);
        assert_eq!(evs.len(), 2);
    }

    #[test]
    fn session_events_for_syscall() {
        let session = EbpfMonitorSession::new(100);
        session.push_event(make_event(1, SyscallId::Execve));
        session.push_event(make_event(2, SyscallId::Execve));
        session.push_event(make_event(3, SyscallId::Openat));
        let execs = session.events_for_syscall(SyscallId::Execve);
        assert_eq!(execs.len(), 2);
    }

    #[test]
    fn session_total_events() {
        let session = EbpfMonitorSession::new(100);
        for i in 0..5 {
            session.push_event(make_event(i, SyscallId::Write));
        }
        assert_eq!(session.total_events(), 5);
    }

    #[test]
    fn session_pid_event_count() {
        let session = EbpfMonitorSession::new(100);
        session.push_event(make_event(42, SyscallId::Read));
        session.push_event(make_event(42, SyscallId::Write));
        assert_eq!(session.pid_event_count(42), 2);
        assert_eq!(session.pid_event_count(99), 0);
    }

    #[test]
    fn session_syscall_count() {
        let session = EbpfMonitorSession::new(100);
        session.push_event(make_event(1, SyscallId::Execve));
        session.push_event(make_event(2, SyscallId::Execve));
        assert_eq!(session.syscall_event_count(SyscallId::Execve), 2);
        assert_eq!(session.syscall_event_count(SyscallId::Openat), 0);
    }

    #[test]
    fn session_top_pids() {
        let session = EbpfMonitorSession::new(100);
        for _ in 0..5 {
            session.push_event(make_event(1, SyscallId::Write));
        }
        for _ in 0..3 {
            session.push_event(make_event(2, SyscallId::Read));
        }
        let top = session.top_pids(1);
        assert_eq!(top[0].0, 1);
        assert_eq!(top[0].1, 5);
    }

    #[test]
    fn session_peek_does_not_consume() {
        let session = EbpfMonitorSession::new(10);
        session.push_event(make_event(1, SyscallId::Read));
        let _ = session.peek_events();
        assert_eq!(session.buffered_count(), 1);
    }

    #[test]
    fn bpf_event_with_uid() {
        let ev = BpfEvent::new_entry(1, 1, "proc", SyscallId::Execve, [0; 6]).with_uid(1000);
        assert_eq!(ev.uid, 1000);
    }

    #[test]
    fn session_empty_drain() {
        let session = EbpfMonitorSession::new(100);
        let drained = session.drain_events();
        assert!(drained.is_empty());
    }

    #[test]
    fn ebpf_map_is_empty() {
        let map = EbpfMap::new("m", EbpfMapType::Hash, 4, 4, 10);
        assert!(map.is_empty());
        map.update(vec![0; 4], vec![0; 4]).unwrap();
        assert!(!map.is_empty());
    }
}
