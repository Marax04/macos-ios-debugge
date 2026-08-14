//! `/proc/<pid>` snapshot reader (Linux-only).
//!
//! Captures a consistent point-in-time view of the live kernel metadata for a
//! traced process without needing a ptrace stop: reads `/proc/<pid>/maps`,
//! `/proc/<pid>/status`, `/proc/<pid>/stat`, `/proc/<pid>/wchan`,
//! `/proc/<pid>/syscall`, and `/proc/<pid>/fd` (file-descriptor table).
//!
//! All reads go through the standard library (`std::fs::read_to_string`) — no
//! unsafe code and no libc calls are needed for the text-format `/proc` files.
//! The only Linux assumption is the existence of `/proc`.

#![cfg(target_os = "linux")]

use std::collections::HashMap;

// ── Public types ─────────────────────────────────────────────────────────────

/// A single virtual memory mapping from `/proc/<pid>/maps`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcMap {
    /// Start address of the region.
    pub start: u64,
    /// End address (exclusive).
    pub end: u64,
    /// Permission string, e.g. `"r-xp"`.
    pub perms: String,
    /// File offset (hex).
    pub offset: u64,
    /// Major:minor device numbers.
    pub dev: String,
    /// Inode (0 for anonymous).
    pub inode: u64,
    /// Pathname or pseudo-name (`[heap]`, `[stack]`, etc.), if any.
    pub pathname: Option<String>,
}

/// Key/value pairs from `/proc/<pid>/status`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcStatus {
    /// Raw key-value map (all entries from the file).
    pub fields: HashMap<String, String>,
}

/// Decoded fields from `/proc/<pid>/stat`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcStat {
    /// Process ID.
    pub pid: i32,
    /// Process name (comm field, without parentheses).
    pub comm: String,
    /// Single-character state: `R`, `S`, `D`, `Z`, `T`, …
    pub state: char,
    /// Parent PID.
    pub ppid: i32,
    /// User-mode time (clock ticks).
    pub utime: u64,
    /// Kernel-mode time (clock ticks).
    pub stime: u64,
    /// Virtual memory size (bytes).
    pub vsize: u64,
    /// Resident set size (pages).
    pub rss: i64,
}

/// Current syscall or "not in syscall" from `/proc/<pid>/syscall`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ProcSyscall {
    /// Process is executing in a syscall.  Fields: number and raw arguments.
    InSyscall {
        /// Syscall number.
        nr: i64,
        /// Up to six raw arguments.
        args: Vec<u64>,
        /// Stack pointer at syscall entry.
        sp: u64,
        /// Program counter at syscall entry.
        pc: u64,
    },
    /// Process is not currently blocked in a syscall.
    NotInSyscall,
    /// `/proc/<pid>/syscall` was not readable (process may have exited).
    Unavailable(String),
}

/// An open file descriptor entry from `/proc/<pid>/fd/<n>`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FdEntry {
    /// File descriptor number.
    pub fd: u32,
    /// Symlink target (path, socket:[ino], pipe:[ino], etc.).
    pub target: String,
}

/// A complete point-in-time snapshot of `/proc/<pid>`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcSnapshot {
    /// PID this snapshot was taken from.
    pub pid: u32,
    /// Monotonic timestamp (nanoseconds since process start of the *reader*).
    pub captured_ns: u64,
    /// Virtual memory map.
    pub maps: Vec<ProcMap>,
    /// Process status fields.
    pub status: ProcStatus,
    /// Process statistics.
    pub stat: Option<ProcStat>,
    /// Current blocking syscall (or not-in-syscall).
    pub syscall: ProcSyscall,
    /// Kernel wait-channel name (`wchan`).
    pub wchan: Option<String>,
    /// Open file descriptors.
    pub fds: Vec<FdEntry>,
}

// ── Error ────────────────────────────────────────────────────────────────────

/// Error type for `/proc` snapshot operations.
#[derive(Debug, thiserror::Error)]
pub enum ProcError {
    /// I/O error reading a `/proc` file.
    #[error("io error reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// A `/proc` file had an unexpected format.
    #[error("parse error in {path}: {detail}")]
    Parse { path: String, detail: String },
}

// ── Internal helpers ─────────────────────────────────────────────────────────

fn read_proc(pid: u32, file: &str) -> Result<String, ProcError> {
    let path = format!("/proc/{pid}/{file}");
    std::fs::read_to_string(&path).map_err(|e| ProcError::Io { path, source: e })
}

/// Parse a hexadecimal field, or `None` when it is not one.
///
/// This used to end in `.unwrap_or(0)`. `/proc/<pid>/maps` is read while the
/// target is free to mutate its own address space, so a short or garbled line
/// is an ordinary event, not a corruption — and every unparsable field became
/// the address **zero**. The result was a `ProcMap { start: 0, end: 0 }`
/// reported among the target's real mappings: a region that does not exist,
/// indistinguishable from one that does, poisoning every "which region holds
/// this address" lookup and every size total built from the list.
fn parse_hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok()
}

fn parse_maps(raw: &str) -> Vec<ProcMap> {
    let mut out = Vec::new();
    for line in raw.lines() {
        // Format: addr_start-addr_end perms offset dev inode [pathname]
        let mut parts = line.splitn(6, ' ').map(str::trim);
        let addrs = match parts.next() {
            Some(a) => a,
            None => continue,
        };
        let perms = match parts.next() {
            Some(p) => p.to_owned(),
            None => continue,
        };
        let offset_str = parts.next().unwrap_or("0");
        let dev = parts.next().unwrap_or("0:0").to_owned();
        let inode: u64 = parts
            .next()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);
        let pathname = parts
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);

        let mut addr_parts = addrs.splitn(2, '-');
        // A line whose range cannot be read is not a mapping this code can
        // describe. Skipping it loses one region; inventing 0x0-0x0 adds a
        // region the process does not have, which is worse in every direction.
        let (Some(start), Some(end), Some(offset)) = (
            addr_parts.next().and_then(parse_hex),
            addr_parts.next().and_then(parse_hex),
            parse_hex(offset_str),
        ) else {
            continue;
        };
        // `/proc` never emits an inverted range; if we read one, we misread the
        // line.
        if end < start {
            continue;
        }

        out.push(ProcMap { start, end, perms, offset, dev, inode, pathname });
    }
    out
}

fn parse_status(raw: &str) -> ProcStatus {
    let mut fields = HashMap::new();
    for line in raw.lines() {
        if let Some((k, v)) = line.split_once(':') {
            fields.insert(k.trim().to_owned(), v.trim().to_owned());
        }
    }
    ProcStatus { fields }
}

fn parse_stat(raw: &str) -> Option<ProcStat> {
    // Format: pid (comm) state ppid pgrp session tty_nr … utime stime …
    // The comm field may contain spaces/parens, so find the last ')'.
    let rpar = raw.rfind(')')?;
    let pid_end = raw.find('(')?;
    let pid: i32 = raw[..pid_end].trim().parse().ok()?;
    let comm = raw[pid_end + 1..rpar].to_owned();
    let rest = raw[rpar + 1..].trim();
    let mut fields = rest.split_whitespace();
    let state = fields.next().and_then(|s| s.chars().next()).unwrap_or('?');
    let ppid: i32 = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    // skip pgrp(5) session(6) tty_nr(7) tpgid(8) flags(9)
    //      minflt(10) cminflt(11) majflt(12) cmajflt(13) — 9 fields
    // then utime(14) stime(15)
    for _ in 0..9 {
        let _ = fields.next();
    }
    let utime: u64 = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let stime: u64 = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    // skip cutime(16) cstime(17) priority(18) nice(19) num_threads(20)
    // itrealvalue(21) starttime(22) — SEVEN fields, then vsize is field 23.
    // This loop used to run 8 times: the extra step ate `vsize` itself, so
    // `vsize` came back holding `rss` (24) and `rss` holding `rsslim` (25),
    // which is normally u64::MAX — a process reported as using 18 exabytes.
    for _ in 0..7 {
        let _ = fields.next();
    }
    let vsize: u64 = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let rss: i64 = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);

    Some(ProcStat { pid, comm, state, ppid, utime, stime, vsize, rss })
}

fn parse_syscall(raw: &str) -> ProcSyscall {
    let raw = raw.trim();
    if raw == "running" {
        return ProcSyscall::NotInSyscall;
    }
    let mut parts = raw.split_whitespace();
    let nr: i64 = match parts.next().and_then(|s| {
        if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            i64::from_str_radix(h, 16).ok()
        } else {
            s.parse().ok()
        }
    }) {
        Some(n) => n,
        None => return ProcSyscall::NotInSyscall,
    };
    let mut args = Vec::new();
    let mut sp = 0u64;
    let mut pc = 0u64;
    let remaining: Vec<&str> = parts.collect();
    // Last two are sp and pc; the rest (up to 6) are args.
    let n = remaining.len();
    if n >= 2 {
        // An unreadable field here means the line is not the six-args-plus-
        // sp-and-pc shape this parser expects. Reporting `NotInSyscall` says
        // "I could not read this", which is true; filling zeros would claim the
        // target is blocked in a syscall with argument 0.
        for a in &remaining[..n.saturating_sub(2)] {
            let Some(v) = parse_hex(a) else {
                return ProcSyscall::NotInSyscall;
            };
            args.push(v);
        }
        let (Some(s_p), Some(p_c)) = (parse_hex(remaining[n - 2]), parse_hex(remaining[n - 1]))
        else {
            return ProcSyscall::NotInSyscall;
        };
        sp = s_p;
        pc = p_c;
    }
    ProcSyscall::InSyscall { nr, args, sp, pc }
}

fn read_fds(pid: u32) -> Vec<FdEntry> {
    let dir = format!("/proc/{pid}/fd");
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let fd_n: u32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(n) => n,
            None => continue,
        };
        let target = std::fs::read_link(entry.path())
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        out.push(FdEntry { fd: fd_n, target });
    }
    out.sort_by_key(|e| e.fd);
    out
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Capture a [`ProcSnapshot`] for `pid`.
///
/// Returns `Err` only if `/proc/<pid>/maps` or `/proc/<pid>/status` cannot
/// be read (indicating the process does not exist or permissions are denied).
/// All other `/proc` files are read best-effort and silently omitted on error.
///
/// # Errors
/// Returns [`ProcError`] if the mandatory `/proc/<pid>/maps` or
/// `/proc/<pid>/status` files cannot be read.
pub fn snapshot(pid: u32) -> Result<ProcSnapshot, ProcError> {
    use std::time::Instant;
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    let captured_ns = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);

    let maps_raw = read_proc(pid, "maps")?;
    let status_raw = read_proc(pid, "status")?;

    let maps = parse_maps(&maps_raw);
    let status = parse_status(&status_raw);

    let stat = read_proc(pid, "stat").ok().and_then(|s| parse_stat(&s));

    let syscall = match read_proc(pid, "syscall") {
        Ok(s) => parse_syscall(&s),
        Err(e) => ProcSyscall::Unavailable(e.to_string()),
    };

    let wchan = read_proc(pid, "wchan")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());

    let fds = read_fds(pid);

    Ok(ProcSnapshot { pid, captured_ns, maps, status, stat, syscall, wchan, fds })
}

/// Return only the virtual memory maps for `pid` (cheaper than a full
/// [`snapshot`] if only the map is needed).
///
/// # Errors
/// Returns [`ProcError`] if `/proc/<pid>/maps` cannot be read.
pub fn maps(pid: u32) -> Result<Vec<ProcMap>, ProcError> {
    let raw = read_proc(pid, "maps")?;
    Ok(parse_maps(&raw))
}

/// Return the list of thread IDs for `pid` by reading `/proc/<pid>/task`.
///
/// # Errors
/// Returns [`ProcError`] if the task directory cannot be read.
pub fn threads(pid: u32) -> Result<Vec<u32>, ProcError> {
    let dir = format!("/proc/{pid}/task");
    let entries = std::fs::read_dir(&dir).map_err(|e| ProcError::Io {
        path: dir.clone(),
        source: e,
    })?;
    let mut tids = Vec::new();
    for entry in entries.flatten() {
        if let Some(tid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) {
            tids.push(tid);
        }
    }
    tids.sort_unstable();
    Ok(tids)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_maps_basic() {
        let raw = "7f1234560000-7f1234570000 r-xp 00000000 08:01 12345  /usr/lib/libc.so.6\n\
                   7fff00000000-7fff00100000 rwxp 00000000 00:00 0      [stack]\n";
        let maps = parse_maps(raw);
        assert_eq!(maps.len(), 2);
        assert_eq!(maps[0].start, 0x7f1234560000);
        assert_eq!(maps[0].perms, "r-xp");
        assert_eq!(maps[0].pathname, Some("/usr/lib/libc.so.6".to_owned()));
        assert_eq!(maps[1].pathname, Some("[stack]".to_owned()));
    }

    #[test]
    fn parse_status_basic() {
        let raw = "Name:\ttest_proc\nPid:\t42\nVmRSS:\t1024 kB\n";
        let st = parse_status(raw);
        assert_eq!(st.fields.get("Name"), Some(&"test_proc".to_owned()));
        assert_eq!(st.fields.get("Pid"), Some(&"42".to_owned()));
    }

    #[test]
    fn parse_stat_basic() {
        // Simplified but realistic /proc/pid/stat line
        let raw = "42 (my process) S 1 42 42 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 1 0 12345 102400 25 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";
        let st = parse_stat(raw).unwrap();
        assert_eq!(st.pid, 42);
        assert_eq!(st.comm, "my process");
        assert_eq!(st.state, 'S');
        assert_eq!(st.ppid, 1);
        assert_eq!(st.utime, 10);
        assert_eq!(st.stime, 5);
    }

    /// `vsize` and `rss` must be the fields `/proc/pid/stat` actually names.
    ///
    /// After `stime` (field 15) the parser skipped 8 fields to reach `vsize`,
    /// but only SEVEN separate it: cutime(16), cstime(17), priority(18),
    /// nice(19), num_threads(20), itrealvalue(21), starttime(22). The comment
    /// above the loop even lists seven names while claiming "(8)".
    ///
    /// The extra skip consumed `vsize` itself, so the struct reported `rss`
    /// (field 24) as the virtual size and `rsslim` (field 25) as the resident
    /// set — and `rsslim` is normally `u64::MAX`, i.e. this debugger showed a
    /// process using 18 exabytes of resident memory.
    ///
    /// The existing `parse_stat_basic` used a realistic line but asserted only
    /// pid/comm/state/ppid/utime/stime, which is why the shift went unnoticed.
    #[test]
    fn parse_stat_reads_vsize_and_rss_from_the_right_fields() {
        // Fields 23/24/25 are vsize=102400, rss=25, rsslim=u64::MAX.
        let raw = "42 (my process) S 1 42 42 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 1 0 12345 102400 25 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";
        let st = parse_stat(raw).unwrap();

        // The fields the old test already pinned must not move.
        assert_eq!(st.utime, 10);
        assert_eq!(st.stime, 5);

        assert_eq!(st.vsize, 102_400, "vsize is field 23");
        assert_eq!(st.rss, 25, "rss is field 24, in pages");
        assert_ne!(
            st.rss, 18_446_744_073_709_551_615u64 as i64,
            "reading rsslim as rss reports a preposterous resident size"
        );
    }

    #[test]
    fn parse_syscall_running() {
        let s = parse_syscall("running");
        assert!(matches!(s, ProcSyscall::NotInSyscall));
    }

    #[test]
    fn parse_syscall_blocked() {
        let raw = "202 0x7fff1234 0x0 0x0 0x0 0x0 0x0 0x7fffffff0000 0x7f0011223344";
        let s = parse_syscall(raw);
        match s {
            ProcSyscall::InSyscall { nr, sp, pc, .. } => {
                assert_eq!(nr, 202);
                assert_eq!(sp, 0x7fffffff0000);
                assert_eq!(pc, 0x7f0011223344);
            }
            _ => panic!("expected InSyscall"),
        }
    }

    #[test]
    fn self_snapshot_maps_not_empty() {
        // Read /proc/self — guaranteed to exist.
        let maps = maps(std::process::id()).unwrap();
        assert!(!maps.is_empty(), "own process should have at least one map");
    }

    #[test]
    fn self_snapshot_status_has_name() {
        let snap = snapshot(std::process::id()).unwrap();
        assert!(snap.status.fields.contains_key("Name"), "status should have Name field");
        assert!(!snap.maps.is_empty());
    }

    #[test]
    fn self_threads_has_self() {
        let tids = threads(std::process::id()).unwrap();
        // At least the main thread must appear.
        assert!(!tids.is_empty());
    }

    /// A malformed maps line must be DROPPED, never turned into a region at
    /// address zero.
    ///
    /// /proc/<pid>/maps is read while the target is free to mutate its own
    /// address space, so a short or garbled line is an ordinary event. Every
    /// unparsable hex field used to become 0, so the list of the target
    /// mappings gained a 0x0-0x0 region that does not exist - and it is
    /// indistinguishable from one that does, poisoning every "which region
    /// holds this address" lookup and every total built from the list.
    #[test]
    fn a_malformed_maps_line_is_dropped_not_turned_into_address_zero() {
        let raw = [
            "55a1f2c00000-55a1f2c01000 r-xp 00001000 08:02 99 /usr/bin/prog",
            "zzzzzz-55a1f2c02000 rw-p 00000000 00:00 0",
            "55a1f2c03000-qqqq rw-p 00000000 00:00 0",
            "7ffd1c000000-7ffd1c021000 rw-p zzzz 00:00 0",
            "truncated",
        ]
        .join("\n");
        let maps = parse_maps(&raw);
        assert_eq!(maps.len(), 1, "only the well-formed line describes a real mapping");
        assert_eq!(maps[0].start, 0x55a1_f2c0_0000);
        assert_eq!(maps[0].end, 0x55a1_f2c0_1000);
        assert!(
            !maps.iter().any(|m| m.start == 0 && m.end == 0),
            "a region at 0x0-0x0 was invented from a line that could not be read"
        );
    }

    /// An inverted range means the line was misread; it is not a mapping.
    #[test]
    fn an_inverted_range_is_refused() {
        let maps = parse_maps("2000-1000 rw-p 00000000 00:00 0");
        assert!(maps.is_empty(), "/proc never emits end < start");
    }

    /// An unreadable syscall line must not be reported as a syscall with
    /// argument zero.
    #[test]
    fn an_unreadable_syscall_line_is_not_reported_as_a_syscall() {
        let ok = parse_syscall("1 0x1 0x2 0x3 0x4 0x5 0x6 0x7fff0000 0x400000");
        match ok {
            ProcSyscall::InSyscall { nr, ref args, sp, pc } => {
                assert_eq!(nr, 1);
                assert_eq!(args.len(), 6);
                assert_eq!(sp, 0x7fff_0000);
                assert_eq!(pc, 0x40_0000);
            }
            other => panic!("expected InSyscall, got {other:?}"),
        }
        let bad = parse_syscall("1 0x1 zzzz 0x3 0x4 0x5 0x6 0x7fff0000 0x400000");
        assert!(
            matches!(bad, ProcSyscall::NotInSyscall),
            "a field that could not be read must not become argument 0, got {bad:?}"
        );
    }

}
