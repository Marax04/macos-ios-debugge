//! Trace Linux syscalls using ptrace: `PTRACE_SYSCALL` loop, syscall number and
//! argument extraction from registers, structured entry/exit records.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── SyscallArgs ─────────────────────────────────────────────────────────────

/// The six argument registers for a Linux x86-64 syscall.
///
/// Layout: `rdi, rsi, rdx, r10, r8, r9`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SyscallArgs {
    /// First argument (rdi).
    pub arg0: u64,
    /// Second argument (rsi).
    pub arg1: u64,
    /// Third argument (rdx).
    pub arg2: u64,
    /// Fourth argument (r10).
    pub arg3: u64,
    /// Fifth argument (r8).
    pub arg4: u64,
    /// Sixth argument (r9).
    pub arg5: u64,
}

impl SyscallArgs {
    /// Create `SyscallArgs` from a 6-element array `[arg0..arg5]`.
    #[must_use]
    pub const fn from_array(args: [u64; 6]) -> Self {
        Self {
            arg0: args[0],
            arg1: args[1],
            arg2: args[2],
            arg3: args[3],
            arg4: args[4],
            arg5: args[5],
        }
    }

    /// Return the argument at 0-based `index`, or `None` for index >= 6.
    #[must_use]
    pub const fn get(&self, index: usize) -> Option<u64> {
        match index {
            0 => Some(self.arg0),
            1 => Some(self.arg1),
            2 => Some(self.arg2),
            3 => Some(self.arg3),
            4 => Some(self.arg4),
            5 => Some(self.arg5),
            _ => None,
        }
    }

    /// Iterate all (index, value) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (usize, u64)> {
        let a = [
            self.arg0, self.arg1, self.arg2,
            self.arg3, self.arg4, self.arg5,
        ];
        (0..6).map(move |i| (i, a[i]))
    }
}

impl fmt::Display for SyscallArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
            self.arg0, self.arg1, self.arg2,
            self.arg3, self.arg4, self.arg5
        )
    }
}

// ─── SyscallEntry ─────────────────────────────────────────────────────────────

/// A recorded syscall entry (the "call-in" side).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEntry {
    /// Monotonically increasing sequence number assigned by the tracer.
    pub seq: u64,
    /// PID of the tracee that made this syscall.
    pub pid: u32,
    /// Thread ID (equals PID for single-threaded processes).
    pub tid: u32,
    /// Raw syscall number (as in `orig_rax`).
    pub nr: u64,
    /// Syscall name resolved from the number, if known.
    pub name: Option<String>,
    /// Arguments extracted from registers.
    pub args: SyscallArgs,
    /// Instruction pointer at the time of the syscall.
    pub rip: u64,
    /// Monotonic timestamp (nanoseconds), or 0 if not available.
    pub timestamp_ns: u64,
}

impl SyscallEntry {
    /// Create a new `SyscallEntry`.
    #[must_use]
    pub const fn new(seq: u64, pid: u32, tid: u32, nr: u64, args: SyscallArgs) -> Self {
        Self {
            seq,
            pid,
            tid,
            nr,
            name: None,
            args,
            rip: 0,
            timestamp_ns: 0,
        }
    }

    /// Attach a resolved syscall name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

impl fmt::Display for SyscallEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name.as_deref().unwrap_or("?");
        write!(
            f,
            "[{:6}] pid={} tid={} {}({}) [nr={}]",
            self.seq, self.pid, self.tid, name, self.args, self.nr
        )
    }
}

// ─── SyscallExit ─────────────────────────────────────────────────────────────

/// A recorded syscall exit (the "return" side).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallExit {
    /// Sequence number of the matching `SyscallEntry`.
    pub entry_seq: u64,
    /// PID of the tracee.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Syscall number (same as in the matching entry).
    pub nr: u64,
    /// Raw return value (as in `rax` after the syscall).
    pub return_value: i64,
    /// Monotonic timestamp (nanoseconds), or 0 if not available.
    pub timestamp_ns: u64,
}

impl SyscallExit {
    /// Create a new `SyscallExit`.
    #[must_use]
    pub const fn new(entry_seq: u64, pid: u32, tid: u32, nr: u64, return_value: i64) -> Self {
        Self {
            entry_seq,
            pid,
            tid,
            nr,
            return_value,
            timestamp_ns: 0,
        }
    }

    /// Return `true` if the return value indicates an error (negative, POSIX errno).
    #[must_use]
    pub const fn is_error(&self) -> bool {
        self.return_value < 0
    }

    /// Return the errno value if `is_error()`, otherwise `None`.
    #[must_use]
    pub fn errno(&self) -> Option<u32> {
        if self.is_error() {
            let abs = self.return_value.unsigned_abs();
            Some(u32::try_from(abs).unwrap_or(u32::MAX))
        } else {
            None
        }
    }
}

impl fmt::Display for SyscallExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_error() {
            write!(
                f,
                "  -> error {} (errno={})",
                self.return_value,
                self.errno().unwrap_or(0)
            )
        } else {
            write!(f, "  -> {:#x}", self.return_value)
        }
    }
}

// ─── SyscallRecord ────────────────────────────────────────────────────────────

/// A paired entry+exit record for one complete syscall.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallRecord {
    /// Entry information.
    pub entry: SyscallEntry,
    /// Exit information, if the syscall has returned.
    pub exit: Option<SyscallExit>,
}

impl SyscallRecord {
    /// Create a record with only an entry (exit not yet seen).
    #[must_use]
    pub const fn pending(entry: SyscallEntry) -> Self {
        Self { entry, exit: None }
    }

    /// Complete the record with an exit.
    pub const fn complete(&mut self, exit: SyscallExit) {
        self.exit = Some(exit);
    }

    /// Return `true` if the exit has been recorded.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.exit.is_some()
    }

    /// Return the elapsed nanoseconds between entry and exit, if both timestamps
    /// are non-zero.
    #[must_use]
    pub fn elapsed_ns(&self) -> Option<u64> {
        let exit = self.exit.as_ref()?;
        if self.entry.timestamp_ns == 0 || exit.timestamp_ns == 0 {
            return None;
        }
        Some(exit.timestamp_ns.saturating_sub(self.entry.timestamp_ns))
    }
}

impl fmt::Display for SyscallRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.entry)?;
        if let Some(ref exit) = self.exit {
            write!(f, "{exit}")?;
        } else {
            write!(f, "  -> (pending)")?;
        }
        Ok(())
    }
}

// ─── PtraceSyscallTracer ──────────────────────────────────────────────────────

/// Simulates the book-keeping a `PTRACE_SYSCALL`-based tracer would perform.
///
/// On a real system this struct would wrap the kernel `ptrace(2)` calls; here it
/// provides a pure-Rust model suitable for unit testing and offline analysis.
/// The key operations are:
///
/// * `on_syscall_enter` — called when `ptrace(PTRACE_GETREGS)` shows the
///   process is at a syscall entry (`orig_rax != -1`).
/// * `on_syscall_exit` — called when the tracee returns from the kernel.
/// * `records()` — returns all completed (and in-flight) records.
pub struct PtraceSyscallTracer {
    /// All completed and in-flight records, sorted by entry sequence.
    records: Vec<SyscallRecord>,
    /// In-flight entries keyed by `(pid, tid)` — a thread can have only one
    /// outstanding syscall at a time.
    pending: HashMap<(u32, u32), u64>,
    /// Monotonic sequence counter.
    seq: u64,
    /// Optional name resolver: syscall number → name.
    name_resolver: Option<Box<dyn Fn(u64) -> Option<String> + Send + Sync>>,
}

impl fmt::Debug for PtraceSyscallTracer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PtraceSyscallTracer")
            .field("records", &self.records)
            .field("pending", &self.pending)
            .field("seq", &self.seq)
            .field("name_resolver", &self.name_resolver.as_ref().map(|_| "..."))
            .finish()
    }
}

impl PtraceSyscallTracer {
    /// Create a new, empty tracer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            pending: HashMap::new(),
            seq: 0,
            name_resolver: None,
        }
    }

    /// Attach a name resolver for syscall numbers.
    #[must_use]
    pub fn with_name_resolver<F>(mut self, f: F) -> Self
    where
        F: Fn(u64) -> Option<String> + Send + Sync + 'static,
    {
        self.name_resolver = Some(Box::new(f));
        self
    }

    /// Record a syscall entry from register state.
    ///
    /// `orig_rax` is the syscall number; `args` are the six argument registers.
    pub fn on_syscall_enter(
        &mut self,
        pid: u32,
        tid: u32,
        orig_rax: u64,
        args: SyscallArgs,
        rip: u64,
        timestamp_ns: u64,
    ) {
        self.seq += 1;
        let seq = self.seq;
        let name = self.name_resolver.as_ref().and_then(|f| f(orig_rax));
        let mut entry = SyscallEntry::new(seq, pid, tid, orig_rax, args);
        if let Some(n) = name {
            entry = entry.with_name(n);
        }
        entry.rip = rip;
        entry.timestamp_ns = timestamp_ns;
        self.pending.insert((pid, tid), seq);
        self.records.push(SyscallRecord::pending(entry));
    }

    /// Record a syscall exit.
    ///
    /// `return_value` is the raw `rax` value after the syscall (may be negative
    /// to indicate an error).
    pub fn on_syscall_exit(
        &mut self,
        pid: u32,
        tid: u32,
        nr: u64,
        return_value: i64,
        timestamp_ns: u64,
    ) {
        let Some(entry_seq) = self.pending.remove(&(pid, tid)) else {
            return; // no matching entry (e.g. first stop is an exit)
        };
        let exit = SyscallExit {
            entry_seq,
            pid,
            tid,
            nr,
            return_value,
            timestamp_ns,
        };
        // Find the matching in-flight record and complete it.
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|r| r.entry.seq == entry_seq)
        {
            record.complete(exit);
        }
    }

    /// Return all records (complete and in-flight).
    #[must_use]
    pub fn records(&self) -> &[SyscallRecord] {
        &self.records
    }

    /// Return only completed records.
    #[must_use]
    pub fn completed_records(&self) -> Vec<&SyscallRecord> {
        self.records.iter().filter(|r| r.is_complete()).collect()
    }

    /// Return only in-flight (pending) records.
    #[must_use]
    pub fn pending_records(&self) -> Vec<&SyscallRecord> {
        self.records.iter().filter(|r| !r.is_complete()).collect()
    }

    /// Return all records for a specific PID.
    #[must_use]
    pub fn records_for_pid(&self, pid: u32) -> Vec<&SyscallRecord> {
        self.records
            .iter()
            .filter(|r| r.entry.pid == pid)
            .collect()
    }

    /// Return all records for a specific syscall number.
    #[must_use]
    pub fn records_for_nr(&self, nr: u64) -> Vec<&SyscallRecord> {
        self.records
            .iter()
            .filter(|r| r.entry.nr == nr)
            .collect()
    }

    /// Return aggregate error statistics: nr -> `error_count`.
    #[must_use]
    pub fn error_counts(&self) -> HashMap<u64, u64> {
        let mut map: HashMap<u64, u64> = HashMap::new();
        for rec in self.records.iter().filter(|r| r.is_complete()) {
            if let Some(exit) = &rec.exit
                && exit.is_error()
            {
                *map.entry(rec.entry.nr).or_insert(0) += 1;
            }
        }
        map
    }

    /// Return aggregate call counts: nr -> `call_count`.
    #[must_use]
    pub fn call_counts(&self) -> HashMap<u64, u64> {
        let mut map: HashMap<u64, u64> = HashMap::new();
        for rec in &self.records {
            *map.entry(rec.entry.nr).or_insert(0) += 1;
        }
        map
    }

    /// Return the total number of records (entries seen).
    #[must_use]
    pub const fn total_calls(&self) -> usize {
        self.records.len()
    }

    /// Clear all records and pending state.
    pub fn reset(&mut self) {
        self.records.clear();
        self.pending.clear();
        self.seq = 0;
    }
}

impl Default for PtraceSyscallTracer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Register extraction helpers ─────────────────────────────────────────────

/// Build a `SyscallArgs` from a `user_regs_struct`-like register map.
///
/// On x86-64, syscall arguments are:
/// `rdi, rsi, rdx, r10, r8, r9`.
#[must_use]
pub const fn args_from_regs(rdi: u64, rsi: u64, rdx: u64, r10: u64, r8: u64, r9: u64) -> SyscallArgs {
    SyscallArgs {
        arg0: rdi,
        arg1: rsi,
        arg2: rdx,
        arg3: r10,
        arg4: r8,
        arg5: r9,
    }
}

/// Extract the syscall number from the `orig_rax` field of a stopped tracee's
/// register set.  On x86-64, `orig_rax` holds the syscall number at entry.
#[must_use]
pub const fn syscall_number_from_orig_rax(orig_rax: u64) -> u64 {
    // Cast to u64: the kernel uses `unsigned long` for syscall numbers.
    orig_rax
}

/// Return `true` if `rax` on syscall exit indicates an error (POSIX convention:
/// -4096 < rax < 0, i.e. -(errno) in the range [1, 4095]).
#[must_use]
pub const fn is_error_return(rax: u64) -> bool {
    let signed = rax.cast_signed();
    signed > -4096 && signed < 0
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_args(base: u64) -> SyscallArgs {
        SyscallArgs::from_array([base, base + 1, base + 2, base + 3, base + 4, base + 5])
    }

    #[test]
    fn test_syscall_args_get() {
        let a = dummy_args(10);
        assert_eq!(a.get(0), Some(10));
        assert_eq!(a.get(5), Some(15));
        assert_eq!(a.get(6), None);
    }

    #[test]
    fn test_syscall_args_iter() {
        let a = dummy_args(0);
        let v: Vec<_> = a.iter().collect();
        assert_eq!(v.len(), 6);
        assert_eq!(v[0], (0, 0));
        assert_eq!(v[5], (5, 5));
    }

    #[test]
    fn test_entry_and_exit_pair() {
        let mut tracer = PtraceSyscallTracer::new();
        tracer.on_syscall_enter(1, 1, 1 /* write */, dummy_args(0), 0x0040_0500, 1000);
        tracer.on_syscall_exit(1, 1, 1, 42, 2000);
        assert_eq!(tracer.completed_records().len(), 1);
        let rec = &tracer.records()[0];
        assert_eq!(rec.entry.nr, 1);
        assert_eq!(rec.exit.as_ref().unwrap().return_value, 42);
    }

    #[test]
    fn test_pending_record_not_in_completed() {
        let mut tracer = PtraceSyscallTracer::new();
        tracer.on_syscall_enter(1, 1, 1, dummy_args(0), 0, 0);
        assert_eq!(tracer.pending_records().len(), 1);
        assert!(tracer.completed_records().is_empty());
    }

    #[test]
    fn test_error_return_detection() {
        assert!(is_error_return((-1i64).cast_unsigned()));
        assert!(is_error_return((-4095i64).cast_unsigned()));
        assert!(!is_error_return(0));
        assert!(!is_error_return(42));
    }

    #[test]
    fn test_syscall_exit_errno() {
        let exit = SyscallExit::new(1, 1, 1, 1, -13);
        assert!(exit.is_error());
        assert_eq!(exit.errno(), Some(13));
    }

    #[test]
    fn test_call_counts() {
        let mut tracer = PtraceSyscallTracer::new();
        for _ in 0..3 {
            tracer.on_syscall_enter(1, 1, 0 /* read */, dummy_args(0), 0, 0);
            tracer.on_syscall_exit(1, 1, 0, 10, 0);
        }
        tracer.on_syscall_enter(1, 1, 1 /* write */, dummy_args(0), 0, 0);
        tracer.on_syscall_exit(1, 1, 1, 5, 0);
        let counts = tracer.call_counts();
        assert_eq!(counts[&0], 3);
        assert_eq!(counts[&1], 1);
    }

    #[test]
    fn test_name_resolver_attached() {
        let tracer = PtraceSyscallTracer::new()
            .with_name_resolver(|nr| if nr == 0 { Some("read".to_owned()) } else { None });
        let mut t = tracer;
        t.on_syscall_enter(1, 1, 0, dummy_args(0), 0, 0);
        assert_eq!(t.records()[0].entry.name.as_deref(), Some("read"));
    }

    #[test]
    fn test_elapsed_ns() {
        let mut tracer = PtraceSyscallTracer::new();
        tracer.on_syscall_enter(1, 1, 1, dummy_args(0), 0, 1_000_000);
        tracer.on_syscall_exit(1, 1, 1, 0, 5_000_000);
        let rec = &tracer.records()[0];
        assert_eq!(rec.elapsed_ns(), Some(4_000_000));
    }

    #[test]
    fn test_args_from_regs() {
        let a = args_from_regs(1, 2, 3, 4, 5, 6);
        assert_eq!(a.arg0, 1);
        assert_eq!(a.arg5, 6);
    }
}
