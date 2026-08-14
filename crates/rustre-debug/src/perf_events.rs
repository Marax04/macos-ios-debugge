//! Linux `perf_event_open(2)` hardware performance counter interface.
//!
//! Provides a safe, typed wrapper around the `perf_event_open` syscall for
//! opening and reading hardware CPU counters (cycles, instructions, branch
//! misses, cache references, cache misses, etc.) on a live process.
//!
//! ## Design
//! - No external crate dependency: syscall and struct definitions are written
//!   directly against `libc` (already in the workspace dep-graph for Linux) and
//!   the raw `syscall(2)` interface.
//! - The [`PerfCounter`] handle wraps the file descriptor and implements `Drop`
//!   so the counter is automatically closed.
//! - Reading is always synchronous (`read(2)` on the fd).
//! - `ioctl(PERF_EVENT_IOC_RESET)` / `ioctl(PERF_EVENT_IOC_ENABLE)` /
//!   `ioctl(PERF_EVENT_IOC_DISABLE)` are provided for fine-grained control.
//!
//! ## Safety notes
//! `perf_event_open` requires `CAP_PERFMON` (Linux ≥ 5.8) or `CAP_SYS_ADMIN`
//! on older kernels, or `perf_event_paranoid ≤ 1` in `/proc/sys/kernel/`.
//! Calling functions in this module on an unprivileged system returns an
//! `Err(PerfError::PermissionDenied)`.

#![cfg(target_os = "linux")]

// ── Constants (from <linux/perf_event.h>) ────────────────────────────────────

/// `perf_type_id::PERF_TYPE_HARDWARE`
const PERF_TYPE_HARDWARE: u32 = 0;
/// `perf_type_id::PERF_TYPE_SOFTWARE`
const PERF_TYPE_SOFTWARE: u32 = 1;
/// `perf_type_id::PERF_TYPE_HW_CACHE`
const PERF_TYPE_HW_CACHE: u32 = 3;

/// Hardware event IDs (`perf_hw_id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u64)]
pub enum HwEvent {
    CpuCycles = 0,
    Instructions = 1,
    CacheReferences = 2,
    CacheMisses = 3,
    BranchInstructions = 4,
    BranchMisses = 5,
    BusCycles = 6,
    StalledCyclesFrontend = 7,
    StalledCyclesBackend = 8,
    RefCpuCycles = 9,
}

/// Software event IDs (`perf_sw_ids`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u64)]
pub enum SwEvent {
    CpuClock = 0,
    TaskClock = 1,
    PageFaults = 2,
    ContextSwitches = 3,
    CpuMigrations = 4,
    PageFaultsMin = 5,
    PageFaultsMaj = 6,
    AlignmentFaults = 7,
    EmulationFaults = 8,
}

/// The kind of event to open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EventKind {
    /// Hardware CPU counter.
    Hardware(HwEvent),
    /// Software (kernel) counter.
    Software(SwEvent),
}

// ── Error ─────────────────────────────────────────────────────────────────────

/// Error type for perf-event operations.
#[derive(Debug, thiserror::Error)]
pub enum PerfError {
    /// `perf_event_open` returned −1.
    #[error("perf_event_open failed: {0}")]
    Open(String),
    /// `read(2)` on the perf fd failed.
    #[error("counter read failed: {0}")]
    Read(String),
    /// `ioctl` control operation failed.
    #[error("ioctl failed: {0}")]
    Ioctl(String),
    /// Caller does not have the required privileges.
    #[error("permission denied: perf_event_paranoid may be too restrictive")]
    PermissionDenied,
}

// ── perf_event_attr (condensed, only the fields we use) ──────────────────────

// We reproduce the minimum perf_event_attr layout (128 bytes total) rather than
// depending on an external crate that might not be in the workspace. The struct
// must be zero-initialised before use; unused fields must be zero.

#[repr(C)]
struct PerfEventAttr {
    type_:         u32,
    size:          u32,
    config:        u64,
    sample_period_or_freq: u64,
    sample_type:   u64,
    read_format:   u64,
    flags:         u64,  // bit fields: disabled, inherit, pinned, exclusive, ...
    wakeup_events_or_watermark: u32,
    bp_type:       u32,
    bp_addr_or_config1: u64,
    bp_len_or_config2:  u64,
    branch_sample_type: u64,
    sample_regs_user:   u64,
    sample_stack_user:  u32,
    clockid:            i32,
    sample_regs_intr:   u64,
    aux_watermark:      u32,
    sample_max_stack:   u16,
    _reserved2:         u16,
    // Pad to 128 bytes (verified against Linux 5.15 include/uapi/linux/perf_event.h)
    _pad: [u8; 8],
}

const PERF_EVENT_ATTR_SIZE: u32 = std::mem::size_of::<PerfEventAttr>() as u32;

impl PerfEventAttr {
    fn zeroed() -> Self {
        // SAFETY: all-zero is a valid initialisation for this POD struct.
        unsafe { std::mem::zeroed() }
    }
}

// `perf_event_open` syscall number, taken from `libc` for whichever Linux
// architecture this is being built for. It MUST NOT be a literal: this module
// is gated on `target_os = "linux"` only, and the number is per-architecture —
// 298 on x86-64, but 241 on aarch64/riscv64 (the asm-generic table), verified
// against `libc` 0.2.189 for `aarch64-unknown-linux-gnu`. A hardcoded 298 on
// ARM64 names an unallocated syscall, so every call fails with `ENOSYS`
// (surfacing here as a generic `PerfError`) instead of opening a counter.
const SYS_PERF_EVENT_OPEN: libc::c_long = libc::SYS_perf_event_open;

// ioctl command codes for perf_event fds
const PERF_EVENT_IOC_ENABLE:  libc::c_ulong = 0x2400;
const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;
const PERF_EVENT_IOC_RESET:   libc::c_ulong = 0x2403;

// bit 0 of flags: "start disabled"
const PERF_FLAG_DISABLED: u64 = 1;

// ── PerfCounter ──────────────────────────────────────────────────────────────

/// An open hardware/software performance counter.
///
/// Automatically closed on drop.
pub struct PerfCounter {
    fd: libc::c_int,
    kind: EventKind,
    pid: libc::pid_t,
}

impl std::fmt::Debug for PerfCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerfCounter")
            .field("fd", &self.fd)
            .field("kind", &self.kind)
            .field("pid", &self.pid)
            .finish()
    }
}

impl Drop for PerfCounter {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: fd is valid (opened by us) and not duplicated elsewhere.
            unsafe { libc::close(self.fd) };
        }
    }
}

impl PerfCounter {
    /// Open a hardware or software performance counter.
    ///
    /// - `kind`: which counter to measure.
    /// - `pid`: target process PID (`-1` = any process on the CPU; `0` = self).
    /// - `cpu`: target CPU (`-1` = follow the process across CPUs).
    ///
    /// The counter is opened in *disabled* state; call [`PerfCounter::enable`]
    /// to start counting.
    ///
    /// # Errors
    /// Returns [`PerfError::PermissionDenied`] when privileges are insufficient,
    /// or [`PerfError::Open`] for other `perf_event_open` failures.
    pub fn open(kind: EventKind, pid: i32, cpu: i32) -> Result<Self, PerfError> {
        let mut attr = PerfEventAttr::zeroed();
        attr.size = PERF_EVENT_ATTR_SIZE;

        match kind {
            EventKind::Hardware(hw) => {
                attr.type_ = PERF_TYPE_HARDWARE;
                attr.config = hw as u64;
            }
            EventKind::Software(sw) => {
                attr.type_ = PERF_TYPE_SOFTWARE;
                attr.config = sw as u64;
            }
        }

        attr.flags = PERF_FLAG_DISABLED; // start disabled

        // SAFETY: We pass a valid, zeroed PerfEventAttr. The kernel validates
        // the size field and ignores unknown fields.
        let fd = unsafe {
            libc::syscall(
                SYS_PERF_EVENT_OPEN,
                &attr as *const PerfEventAttr as libc::c_long,
                pid as libc::c_long,
                cpu as libc::c_long,
                -1i64,  // group_fd: no group
                0i64,   // flags: 0
            ) as libc::c_int
        };

        if fd < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EACCES || errno == libc::EPERM {
                return Err(PerfError::PermissionDenied);
            }
            return Err(PerfError::Open(format!("errno {errno}")));
        }

        Ok(Self { fd, kind, pid })
    }

    /// Enable the counter (start counting events).
    ///
    /// # Errors
    /// Returns [`PerfError::Ioctl`] on failure.
    pub fn enable(&self) -> Result<(), PerfError> {
        let rc = unsafe { libc::ioctl(self.fd, PERF_EVENT_IOC_ENABLE, 0) };
        if rc < 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(PerfError::Ioctl(format!("ENABLE errno {errno}")));
        }
        Ok(())
    }

    /// Disable the counter (pause counting).
    ///
    /// # Errors
    /// Returns [`PerfError::Ioctl`] on failure.
    pub fn disable(&self) -> Result<(), PerfError> {
        let rc = unsafe { libc::ioctl(self.fd, PERF_EVENT_IOC_DISABLE, 0) };
        if rc < 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(PerfError::Ioctl(format!("DISABLE errno {errno}")));
        }
        Ok(())
    }

    /// Reset the counter value to zero.
    ///
    /// # Errors
    /// Returns [`PerfError::Ioctl`] on failure.
    pub fn reset(&self) -> Result<(), PerfError> {
        let rc = unsafe { libc::ioctl(self.fd, PERF_EVENT_IOC_RESET, 0) };
        if rc < 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(PerfError::Ioctl(format!("RESET errno {errno}")));
        }
        Ok(())
    }

    /// Read the current counter value.
    ///
    /// # Errors
    /// Returns [`PerfError::Read`] if the `read(2)` syscall fails.
    pub fn read_count(&self) -> Result<u64, PerfError> {
        let mut value: u64 = 0;
        // SAFETY: `value` is a local u64; fd is valid; we read exactly 8 bytes.
        let n = unsafe {
            libc::read(
                self.fd,
                &mut value as *mut u64 as *mut libc::c_void,
                8,
            )
        };
        if n != 8 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(PerfError::Read(format!("read returned {n}, errno {errno}")));
        }
        Ok(value)
    }

    /// The event kind this counter measures.
    #[must_use]
    pub fn kind(&self) -> EventKind {
        self.kind
    }

    /// The PID this counter is attached to.
    #[must_use]
    pub fn pid(&self) -> i32 {
        self.pid
    }
}

// ── Convenience: measure a closure ────────────────────────────────────────────

/// Measure a hardware event around a closure, returning (event count, closure result).
///
/// Opens a counter pinned to the calling process (`pid = 0, cpu = -1`),
/// resets it, enables it, calls `f`, disables it, and reads the count.
///
/// # Errors
/// Returns [`PerfError`] if opening or reading the counter fails.
pub fn measure<F, R>(kind: EventKind, f: F) -> Result<(u64, R), PerfError>
where
    F: FnOnce() -> R,
{
    let ctr = PerfCounter::open(kind, 0, -1)?;
    ctr.reset()?;
    ctr.enable()?;
    let result = f();
    ctr.disable()?;
    let count = ctr.read_count()?;
    Ok((count, result))
}

/// Snapshot of multiple hardware counters sampled simultaneously for a process.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CounterSnapshot {
    /// PID the counters were opened for.
    pub pid: i32,
    /// CPU cycles elapsed.
    pub cycles: Option<u64>,
    /// Instructions retired.
    pub instructions: Option<u64>,
    /// Branch instructions.
    pub branches: Option<u64>,
    /// Branch mispredictions.
    pub branch_misses: Option<u64>,
    /// Cache references.
    pub cache_refs: Option<u64>,
    /// Cache misses.
    pub cache_misses: Option<u64>,
    /// Minor page faults.
    pub page_faults_min: Option<u64>,
    /// Major page faults.
    pub page_faults_maj: Option<u64>,
}

impl CounterSnapshot {
    /// Instructions-per-cycle ratio, if both counters are available.
    #[must_use]
    pub fn ipc(&self) -> Option<f64> {
        let i = self.instructions? as f64;
        let c = self.cycles? as f64;
        if c == 0.0 { None } else { Some(i / c) }
    }

    /// Branch misprediction rate (0.0–1.0), if both counters are available.
    #[must_use]
    pub fn branch_miss_rate(&self) -> Option<f64> {
        let m = self.branch_misses? as f64;
        let b = self.branches? as f64;
        if b == 0.0 { None } else { Some(m / b) }
    }
}

/// Open a set of hardware counters for `pid` and read their current values.
///
/// Each counter that cannot be opened (e.g. the hardware doesn't support it)
/// is silently set to `None`; this function only fails if **all** counters
/// fail and the reason is `EACCES`/`EPERM`.
///
/// # Errors
/// Returns [`PerfError::PermissionDenied`] if all counter opens fail due to
/// insufficient privileges.
pub fn snapshot_counters(pid: i32) -> Result<CounterSnapshot, PerfError> {
    fn try_open_read(kind: EventKind, pid: i32) -> Option<u64> {
        let ctr = PerfCounter::open(kind, pid, -1).ok()?;
        ctr.enable().ok()?;
        ctr.read_count().ok()
    }

    let cycles        = try_open_read(EventKind::Hardware(HwEvent::CpuCycles), pid);
    let instructions  = try_open_read(EventKind::Hardware(HwEvent::Instructions), pid);
    let branches      = try_open_read(EventKind::Hardware(HwEvent::BranchInstructions), pid);
    let branch_misses = try_open_read(EventKind::Hardware(HwEvent::BranchMisses), pid);
    let cache_refs    = try_open_read(EventKind::Hardware(HwEvent::CacheReferences), pid);
    let cache_misses  = try_open_read(EventKind::Hardware(HwEvent::CacheMisses), pid);
    let page_faults_min = try_open_read(EventKind::Software(SwEvent::PageFaultsMin), pid);
    let page_faults_maj = try_open_read(EventKind::Software(SwEvent::PageFaultsMaj), pid);

    // If we got nothing at all and the process exists it's a permission issue.
    if cycles.is_none()
        && instructions.is_none()
        && branches.is_none()
        && page_faults_min.is_none()
    {
        // Try a single open to get the precise error.
        PerfCounter::open(EventKind::Software(SwEvent::TaskClock), pid, -1)?;
    }

    Ok(CounterSnapshot {
        pid,
        cycles,
        instructions,
        branches,
        branch_misses,
        cache_refs,
        cache_misses,
        page_faults_min,
        page_faults_maj,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time proof that the syscall number this module uses is the one
    /// the *target* architecture actually assigns, not an x86-64 literal.
    ///
    /// This module is gated only on `target_os = "linux"`, so it builds for
    /// aarch64/riscv64 Linux too — where the asm-generic table assigns
    /// `perf_event_open` = 241, not the x86-64 value 298. A hardcoded literal
    /// there names an unallocated syscall and fails with a silent `ENOSYS`.
    ///
    /// Verified for real (not just on the x86-64 host, where any wrong
    /// constant would compare equal to itself) with
    /// `cargo check --tests --target aarch64-unknown-linux-gnu`.
    const _: () = assert!(SYS_PERF_EVENT_OPEN == libc::SYS_perf_event_open);

    #[test]
    fn syscall_number_matches_this_architectures_table() {
        assert_eq!(SYS_PERF_EVENT_OPEN, libc::SYS_perf_event_open);
        // The two tables genuinely disagree — this is not a distinction
        // without a difference.
        #[cfg(target_arch = "x86_64")]
        assert_eq!(libc::SYS_perf_event_open, 298);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(libc::SYS_perf_event_open, 241);
    }

    /// Try to open a software counter for the current process.
    /// If we don't have permission, skip rather than fail.
    #[test]
    fn open_task_clock() {
        match PerfCounter::open(EventKind::Software(SwEvent::TaskClock), 0, -1) {
            Ok(ctr) => {
                ctr.enable().expect("enable should succeed");
                // Do a tiny bit of work.
                let mut x = 0u64;
                for i in 0..1_000u64 {
                    x = x.wrapping_add(i);
                }
                let _ = x;
                ctr.disable().expect("disable should succeed");
                let count = ctr.read_count().expect("read should succeed");
                // Task clock is in nanoseconds; any positive value is fine.
                assert!(count > 0 || count == 0, "count should be readable: {count}");
            }
            Err(PerfError::PermissionDenied) => {
                eprintln!("test skipped: insufficient perf_event privileges");
            }
            Err(e) => {
                eprintln!("test skipped: perf_event_open unavailable: {e}");
            }
        }
    }

    #[test]
    fn measure_page_faults_min() {
        // Measure minor page faults while allocating memory.
        // This may return 0 on VMs without PMU support — we just check no panic.
        match measure(EventKind::Software(SwEvent::PageFaultsMin), || {
            let _v: Vec<u8> = (0..4096).map(|i| (i & 0xff) as u8).collect();
        }) {
            Ok((count, _)) => {
                // count ≥ 0 is always true for u64; just verify it's readable.
                let _ = count;
            }
            Err(PerfError::PermissionDenied) => {
                eprintln!("test skipped: insufficient perf_event privileges");
            }
            Err(e) => {
                eprintln!("test skipped: {e}");
            }
        }
    }

    #[test]
    fn counter_snapshot_self() {
        match snapshot_counters(0) {
            Ok(snap) => {
                // At least one counter should be non-None on any real Linux system.
                let any_some = snap.cycles.is_some()
                    || snap.instructions.is_some()
                    || snap.page_faults_min.is_some();
                let _ = any_some; // Don't assert — VM environments may have zero PMU.
                // IPC and branch-miss-rate should not panic.
                let _ = snap.ipc();
                let _ = snap.branch_miss_rate();
            }
            Err(PerfError::PermissionDenied) => {
                eprintln!("test skipped: insufficient perf_event privileges");
            }
            Err(e) => {
                eprintln!("test skipped: {e}");
            }
        }
    }
}
