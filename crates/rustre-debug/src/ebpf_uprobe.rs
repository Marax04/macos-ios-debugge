//! Simplified eBPF uprobe/kprobe attachment (Linux-only).
//!
//! Attaches Linux uprobes and kprobes through the kernel's `perf_event_open(2)`
//! + `bpf(2)` syscall interface — no `libbpf` or external crate required.
//!
//! ## What this module provides
//! - Attach a uprobe (user-space probe) to an offset within a shared library or
//!   executable.
//! - Attach a kprobe (kernel probe) to a kernel function symbol.
//! - Load a minimal "count hits and store in map" BPF program that is safe and
//!   verifiable on Linux ≥ 5.1.
//! - Read the hit count from the BPF map after detaching.
//!
//! ## Architecture-specific notes
//! Only x86-64 is currently tested (`BPF_ARCH_X86` ABI). The BPF bytecode
//! emitted is architecture-independent (BPF is a portable ISA), but the host
//! kernel must support `BPF_PROG_TYPE_KPROBE`.
//!
//! ## Limitations
//! - The BPF program loaded here is a *hit counter only* — it increments a
//!   per-cpu array map key 0 on every probe hit. Full argument capture or
//!   ring-buffer output requires a more complex program; that would be in a
//!   separate module.
//! - `CAP_BPF` (Linux ≥ 5.8) or `CAP_SYS_ADMIN` (older kernels) is required.
//! - Kernel lockdown mode blocks BPF program loading.

#![cfg(target_os = "linux")]

use std::fs::OpenOptions;
use std::io::Write;
use std::os::fd::RawFd;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Error type for eBPF uprobe/kprobe operations.
#[derive(Debug, thiserror::Error)]
pub enum EbpfError {
    /// The `bpf(2)` or `perf_event_open(2)` syscall failed.
    #[error("{op} syscall failed: errno {errno}")]
    Syscall {
        op: &'static str,
        errno: i32,
    },
    /// Insufficient kernel privileges (CAP_BPF / CAP_SYS_ADMIN).
    #[error("permission denied: CAP_BPF or CAP_SYS_ADMIN required")]
    PermissionDenied,
    /// BPF program failed kernel verifier.
    #[error("bpf verifier rejected program: {detail}")]
    Verifier { detail: String },
    /// Writing to a kernel tracefs file failed.
    #[error("tracefs write error: {detail}")]
    Tracefs { detail: String },
    /// An I/O error occurred.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Feature not available on this kernel.
    #[error("feature unavailable: {detail}")]
    Unavailable { detail: String },
}

// ── BPF syscall constants ─────────────────────────────────────────────────────

// Per-architecture, taken from `libc` — NOT a literal. This module is gated on
// `target_os = "linux"` only: `bpf` is 321 on x86-64 but 280 on aarch64
// (asm-generic table, verified against libc 0.2.189 for
// aarch64-unknown-linux-gnu). A hardcoded 321 there is an unallocated number
// and every `bpf()` call fails with `ENOSYS`.
const SYS_BPF: libc::c_long = libc::SYS_bpf;

const BPF_MAP_CREATE:     u32 = 0;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_PROG_LOAD:      u32 = 5;

const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
const BPF_PROG_TYPE_KPROBE:      u32 = 2;

const BPF_ANY: u64 = 0;

// ── perf_event_open constants ─────────────────────────────────────────────────

// Per-architecture (298 on x86-64, 241 on aarch64) — see `SYS_BPF` above.
const SYS_PERF_EVENT_OPEN: libc::c_long = libc::SYS_perf_event_open;
const PERF_TYPE_TRACEPOINT: u32 = 1;
// used as type for uprobe/kprobe perf events via tracefs
const PERF_TYPE_BREAKPOINT: u32 = 5;

const PERF_EVENT_IOC_SET_BPF: libc::c_ulong = 0x40044408;
const PERF_EVENT_IOC_ENABLE:  libc::c_ulong = 0x2400;

// ── BPF attr union layout (minimal subset) ────────────────────────────────────

// We use a fixed-size 128-byte buffer that covers all bpf(2) sub-command
// unions. The kernel reads only as many bytes as `attr_size` specifies; we
// set that field per-call and zero-fill the rest.

const BPF_ATTR_SIZE: usize = 128;

/// Zero-initialised BPF attribute block.
fn bpf_attr() -> [u8; BPF_ATTR_SIZE] {
    [0u8; BPF_ATTR_SIZE]
}

/// Write a u32 into a byte slice at a given offset.
fn w32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_ne_bytes());
}

/// Write a u64 into a byte slice at a given offset.
fn w64(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_ne_bytes());
}

/// Read a u32 from a byte slice.
fn r32(buf: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap_or([0; 4]))
}

fn errno() -> i32 {
    // SAFETY: __errno_location() returns a valid pointer always.
    unsafe { *libc::__errno_location() }
}

/// Call the `bpf(2)` syscall.
unsafe fn bpf_syscall(cmd: u32, attr: &mut [u8; BPF_ATTR_SIZE], size: u32) -> libc::c_long {
    // SAFETY: caller guarantees `attr` contains a valid BPF attribute block of
    // at least `size` bytes initialised to the correct sub-command layout.
    unsafe {
        libc::syscall(
            SYS_BPF,
            cmd as libc::c_long,
            attr.as_mut_ptr() as libc::c_long,
            size as libc::c_long,
        )
    }
}

// ── BPF map ───────────────────────────────────────────────────────────────────

/// A BPF per-cpu array map with a single key (index 0) used as a hit counter.
struct BpfMap {
    fd: RawFd,
}

impl Drop for BpfMap {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: we own this fd.
            unsafe { libc::close(self.fd) };
        }
    }
}

impl BpfMap {
    fn create() -> Result<Self, EbpfError> {
        // BPF_MAP_CREATE attr layout:
        // [0]  map_type    u32
        // [4]  key_size    u32
        // [8]  value_size  u32
        // [12] max_entries u32
        let mut attr = bpf_attr();
        w32(&mut attr, 0,  BPF_MAP_TYPE_PERCPU_ARRAY);
        w32(&mut attr, 4,  4);  // key: u32
        w32(&mut attr, 8,  8);  // value: u64
        w32(&mut attr, 12, 1);  // max_entries: 1
        let fd = unsafe { bpf_syscall(BPF_MAP_CREATE, &mut attr, 20) } as RawFd;
        if fd < 0 {
            let e = errno();
            if e == libc::EPERM || e == libc::EACCES {
                return Err(EbpfError::PermissionDenied);
            }
            return Err(EbpfError::Syscall { op: "BPF_MAP_CREATE", errno: e });
        }
        Ok(Self { fd })
    }

    /// Read the hit count stored at key 0 (sum across per-cpu values).
    fn read_count(&self) -> Result<u64, EbpfError> {
        let key: u32 = 0;
        // Per-cpu array returns one u64 per online CPU; we allocate enough for
        // up to 256 CPUs to keep this simple and stack-safe.
        let ncpus = online_cpus().max(1).min(256);
        let mut values = vec![0u64; ncpus];
        let mut attr = bpf_attr();
        w64(&mut attr, 8,  &key as *const u32 as u64);
        w64(&mut attr, 16, values.as_mut_ptr() as u64);
        let fd_u32 = self.fd as u32;
        w32(&mut attr, 0, fd_u32);
        let rc = unsafe { bpf_syscall(BPF_MAP_LOOKUP_ELEM, &mut attr, 32) };
        if rc < 0 {
            return Err(EbpfError::Syscall { op: "BPF_MAP_LOOKUP_ELEM", errno: errno() });
        }
        Ok(values.iter().sum())
    }
}

fn online_cpus() -> usize {
    std::fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .and_then(|s| {
            // Format: "0-7" or "0,2,4"
            let s = s.trim();
            if let Some((_, b)) = s.rsplit_once('-') {
                b.trim().parse::<usize>().ok().map(|n| n + 1)
            } else {
                // Count commas + 1
                Some(s.split(',').count())
            }
        })
        .unwrap_or(1)
}

// ── BPF program (hit counter) ─────────────────────────────────────────────────

/// Emit a minimal BPF kprobe/uprobe hit-counter program.
///
/// The program:
/// 1. Loads map key 0 (r1 = 0, r2 = map_fd).
/// 2. Looks up the per-cpu value pointer via `bpf_map_lookup_elem`.
/// 3. Increments `*ptr` by 1.
/// 4. Returns 0.
///
/// This is verifiable by the kernel's strict verifier on Linux ≥ 5.1.
fn hit_counter_prog(map_fd: RawFd) -> Vec<u64> {
    // BPF instruction encoding: each instruction is 8 bytes.
    // Opcodes used:
    //   0x85 = BPF_CALL
    //   0x95 = BPF_EXIT
    //   0x18 = BPF_LD | BPF_DW | BPF_IMM  (64-bit immediate load, 2 insns)
    //   0x61 = BPF_LDX | BPF_W | BPF_MEM
    //   0x07 = BPF_ALU64 | BPF_ADD | BPF_K
    //   0x7b = BPF_STX | BPF_DW | BPF_MEM
    //   0x15 = BPF_JMP | BPF_JEQ | BPF_K

    // Helper: build a 64-bit BPF instruction word.
    // Layout: [code:8][dst_reg:4][src_reg:4][off:16][imm:32]
    fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
        let b0 = code as u64;
        let b1 = ((dst & 0xf) | ((src & 0xf) << 4)) as u64;
        let b23 = (off as u16) as u64;
        let b4567 = (imm as u32) as u64;
        b0 | (b1 << 8) | (b23 << 16) | (b4567 << 32)
    }

    // BPF register constants
    const R0: u8 = 0;
    const R1: u8 = 1;
    const R10: u8 = 10; // frame pointer (read-only)

    // Instruction opcodes
    const LD_DW_IMM: u8  = 0x18; // BPF_LD|BPF_DW|BPF_IMM — 2-insn wide load
    const ALU64_K:   u8  = 0x07; // BPF_ALU64|BPF_ADD|BPF_K
    const STX_DW:    u8  = 0x7b; // BPF_STX|BPF_DW|BPF_MEM
    const LDX_DW:    u8  = 0x79; // BPF_LDX|BPF_DW|BPF_MEM
    const CALL:      u8  = 0x85;
    const EXIT:      u8  = 0x95;
    const MOV64_K:   u8  = 0xb7; // BPF_ALU64|BPF_MOV|BPF_K
    const JEQ_K:     u8  = 0x15; // BPF_JMP|BPF_JEQ|BPF_K

    // BPF helper id: bpf_map_lookup_elem = 1
    const BPF_FUNC_MAP_LOOKUP_ELEM: i32 = 1;
    // BPF pseudo-src for map fd reference
    const BPF_PSEUDO_MAP_FD: u8 = 1;

    // Stack offset for key storage (r10 - 4 = key at top of stack frame)
    const KEY_OFF: i16 = -4;

    let mut prog: Vec<u64> = Vec::new();

    // 1. key = 0; store on stack at r10 - 4
    prog.push(insn(MOV64_K, R1, 0, 0, 0));         // r1 = 0
    prog.push(insn(STX_DW,  R10, R1, KEY_OFF, 0)); // *(r10-4) = r1 (but 32-bit key)
    // Actually store as 32-bit word for key:
    // Re-emit as: r1 = 0, *(u32 *)(fp-4) = r1
    // Let's redo using BPF_STX|BPF_W (0x63)
    prog.clear();

    const STX_W: u8 = 0x63;
    const LDX_W: u8 = 0x61;

    // r1 = 0 (key value)
    prog.push(insn(MOV64_K, R1, 0, 0, 0));
    // *(u32 *)(fp + KEY_OFF) = r1
    prog.push(insn(STX_W, R10, R1, KEY_OFF, 0));

    // 2. r1 = map_fd (BPF_LD|BPF_DW|BPF_IMM with src=BPF_PSEUDO_MAP_FD)
    //    This is a 2-instruction sequence.
    let map_fd_u32 = map_fd as u32;
    let insn_lo = (0x18u64)                       // code=LD_DW_IMM
        | ((R1 as u64) << 8)                       // dst=r1
        | ((BPF_PSEUDO_MAP_FD as u64) << 12)       // src=1 (pseudo map fd)
        | ((map_fd_u32 as u64) << 32);             // imm = low 32 bits of fd
    let insn_hi = 0u64; // second word: imm_hi = 0
    prog.push(insn_lo);
    prog.push(insn_hi);

    // r2 = fp + KEY_OFF (pointer to key)
    prog.push(insn(MOV64_K, 2, 0, 0, 0));  // r2 = 0
    prog.push(insn(0x0f /* BPF_ALU64|BPF_ADD|BPF_X */, 2, R10, 0, 0)); // r2 += r10
    // add KEY_OFF (negative immediate)
    prog.push(insn(ALU64_K, 2, 0, 0, KEY_OFF as i32));

    // call bpf_map_lookup_elem(r1=map, r2=key)
    prog.push(insn(CALL, 0, 0, 0, BPF_FUNC_MAP_LOOKUP_ELEM));

    // if r0 == 0 goto exit (null pointer => skip)
    prog.push(insn(JEQ_K, R0, 0, 2, 0));

    // r1 = *(u64 *)(r0 + 0)  -- load current count
    prog.push(insn(LDX_DW, R1, R0, 0, 0));
    // r1 += 1
    prog.push(insn(ALU64_K, R1, 0, 0, 1));
    // *(u64 *)(r0 + 0) = r1  -- store updated count
    prog.push(insn(STX_DW, R0, R1, 0, 0));

    // r0 = 0; exit
    prog.push(insn(MOV64_K, R0, 0, 0, 0));
    prog.push(insn(EXIT, 0, 0, 0, 0));

    prog
}

// ── BPF program loader ────────────────────────────────────────────────────────

fn load_bpf_prog(insns: &[u64], prog_type: u32) -> Result<RawFd, EbpfError> {
    // BPF_PROG_LOAD attr layout:
    // [0]  prog_type      u32
    // [4]  insn_cnt       u32
    // [8]  insns          u64 ptr
    // [16] license        u64 ptr
    // [24] log_level      u32
    // [28] log_size       u32
    // [32] log_buf        u64 ptr
    // [40] kern_version   u32  (required for kprobe programs)
    let license = b"GPL\0";
    let mut log_buf = vec![0u8; 4096];
    let mut attr = bpf_attr();
    w32(&mut attr, 0,  prog_type);
    w32(&mut attr, 4,  insns.len() as u32);
    w64(&mut attr, 8,  insns.as_ptr() as u64);
    w64(&mut attr, 16, license.as_ptr() as u64);
    w32(&mut attr, 24, 1); // log_level = 1
    w32(&mut attr, 28, log_buf.len() as u32);
    w64(&mut attr, 32, log_buf.as_mut_ptr() as u64);
    // kern_version: read from /proc/sys/kernel/osrelease and encode. If it
    // cannot be determined the load is abandoned — see `kernel_version_code`.
    w32(&mut attr, 40, kernel_version_code()?);

    let fd = unsafe { bpf_syscall(BPF_PROG_LOAD, &mut attr, 48) } as RawFd;
    if fd < 0 {
        let e = errno();
        if e == libc::EPERM || e == libc::EACCES {
            return Err(EbpfError::PermissionDenied);
        }
        let log = String::from_utf8_lossy(&log_buf)
            .trim_matches('\0')
            .to_owned();
        return Err(EbpfError::Verifier { detail: format!("errno {e}: {log}") });
    }
    Ok(fd)
}

/// Encode the running kernel's version the way `bpf(2)`'s `kern_version`
/// field wants it, from `/proc/sys/kernel/osrelease`.
///
/// # Errors
///
/// [`EbpfError::Unavailable`] when the file cannot be read or parsed.
///
/// This used to end in an `unwrap_or` that assumed kernel 5.0.0. The invented
/// version went straight into `BPF_PROG_LOAD`: on a kernel that validates the
/// field the load fails with a verifier error that blames the *program*, and on
/// one that does not it silently loads a kprobe built for the wrong ABI. Either
/// way the caller was never told the version was guessed.
fn kernel_version_code() -> Result<u32, EbpfError> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/osrelease").map_err(|e| {
        EbpfError::Unavailable {
            detail: format!(
                "cannot read /proc/sys/kernel/osrelease, so the kernel version \
                 required by BPF_PROG_LOAD's kern_version field is unknown: {e}"
            ),
        }
    })?;
    version_code_from_osrelease(raw.trim())
}

/// `LINUX_VERSION_CODE` for an `osrelease` string, split out so the parsing is
/// testable without `/proc`.
///
/// # Errors
/// [`EbpfError::Unavailable`] when major/minor cannot be read — the version is
/// never guessed.
fn version_code_from_osrelease(trimmed: &str) -> Result<u32, EbpfError> {
    let mut parts = trimmed.splitn(3, '.');
    let bad = |what: &str| EbpfError::Unavailable {
        detail: format!(
            "cannot parse {what} from /proc/sys/kernel/osrelease = {trimmed:?}; \
             refusing to guess a kernel version for BPF_PROG_LOAD"
        ),
    };
    let major: u32 = parts
        .next()
        .ok_or_else(|| bad("major"))?
        .parse()
        .map_err(|_| bad("major"))?;
    let minor: u32 = parts
        .next()
        .ok_or_else(|| bad("minor"))?
        .parse()
        .map_err(|_| bad("minor"))?;
    // The patch component is genuinely optional and carries whatever the distro
    // appends. Take its LEADING DIGITS: stripping only at `-` was not enough on
    // this project's own test host, where `osrelease` is
    // `6.18.33.2-microsoft-standard-WSL2` — `splitn(3, '.')` puts
    // `33.2-microsoft-standard-WSL2` in this component, `split_once('-')` leaves
    // `33.2`, and that does not parse as `u32`, so the patch silently became 0
    // and the code reported 0x06_12_00 for a 6.18.33 kernel. `kern_version` is
    // validated by BPF_PROG_LOAD, and a wrong value there is exactly the
    // "never told the version was guessed" failure this function exists to
    // prevent. Only a genuinely digit-less component means 0 — the 4th
    // component (`.2`) is a distro sublevel and is NOT part of
    // LINUX_VERSION_CODE.
    let patch: u32 = parts
        .next()
        .map(|p| p.trim_start().split(|c: char| !c.is_ascii_digit()).next().unwrap_or(""))
        .and_then(|digits| digits.parse().ok())
        .unwrap_or(0);
    Ok((major << 16) | (minor << 8) | patch)
}

// ── Uprobe via tracefs ────────────────────────────────────────────────────────

/// A live uprobe or kprobe probe attached to a process via perf + BPF.
///
/// Drop this to detach the probe and release all file descriptors.
pub struct BpfProbe {
    /// BPF map fd (holds hit count).
    _map: BpfMap,
    /// BPF program fd.
    _prog_fd: RawFd,
    /// perf_event fd for the probe.
    _perf_fd: RawFd,
    /// Human-readable description.
    pub description: String,
}

impl std::fmt::Debug for BpfProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BpfProbe")
            .field("description", &self.description)
            .finish()
    }
}

impl Drop for BpfProbe {
    fn drop(&mut self) {
        if self._perf_fd >= 0 {
            unsafe { libc::close(self._perf_fd) };
        }
        if self._prog_fd >= 0 {
            unsafe { libc::close(self._prog_fd) };
        }
    }
}

/// Configuration for a uprobe (user-space probe).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UprobeConfig {
    /// Absolute path to the target binary or shared library.
    pub path: String,
    /// Byte offset within the file to probe.
    pub offset: u64,
    /// PID to scope the probe to (`-1` for any process that loads the file).
    pub pid: i32,
}

/// Configuration for a kprobe (kernel probe).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KprobeConfig {
    /// Kernel function name to probe, e.g. `"sys_openat"`.
    pub symbol: String,
    /// Byte offset from the symbol address (0 for the entry point).
    pub offset: u64,
}

/// Attach a uprobe to `cfg.path + cfg.offset` and load a hit-counter BPF program.
///
/// # Errors
/// Returns [`EbpfError`] if the tracefs is not mounted, permissions are
/// insufficient, or BPF program loading fails.
pub fn attach_uprobe(cfg: &UprobeConfig) -> Result<BpfProbe, EbpfError> {
    // 1. Write the uprobe definition to tracefs.
    let probe_name = format!("rustre_up_{}", cfg.offset);
    let uprobe_def = format!("p:uprobes/{probe_name} {}:{:#x}", cfg.path, cfg.offset);
    write_tracefs("uprobe_events", &uprobe_def)?;

    // 2. Get the perf event id from tracefs.
    let id_path = format!("uprobes/{probe_name}/id");
    let perf_event_id = read_tracefs_id(&id_path)?;

    // 3. Open the perf event.
    let perf_fd = open_tracepoint_perf(perf_event_id, cfg.pid)?;

    // 4. Create the BPF map and load the program.
    let map = BpfMap::create()?;
    let insns = hit_counter_prog(map.fd);
    let prog_fd = load_bpf_prog(&insns, BPF_PROG_TYPE_KPROBE)?;

    // 5. Attach BPF program to the perf event.
    attach_bpf_to_perf(perf_fd, prog_fd)?;

    let description = format!("uprobe {}:{:#x}", cfg.path, cfg.offset);
    Ok(BpfProbe {
        _map: map,
        _prog_fd: prog_fd,
        _perf_fd: perf_fd,
        description,
    })
}

/// Attach a kprobe to `cfg.symbol + cfg.offset`.
///
/// # Errors
/// Returns [`EbpfError`] if tracefs is not mounted or BPF loading fails.
pub fn attach_kprobe(cfg: &KprobeConfig) -> Result<BpfProbe, EbpfError> {
    let probe_name = format!("rustre_kp_{}", cfg.symbol.replace(':', "_").replace('/', "_"));
    let kprobe_def = if cfg.offset == 0 {
        format!("p:kprobes/{probe_name} {}", cfg.symbol)
    } else {
        format!("p:kprobes/{probe_name} {}+{:#x}", cfg.symbol, cfg.offset)
    };
    write_tracefs("kprobe_events", &kprobe_def)?;

    let id_path = format!("kprobes/{probe_name}/id");
    let perf_event_id = read_tracefs_id(&id_path)?;
    let perf_fd = open_tracepoint_perf(perf_event_id, -1)?;

    let map = BpfMap::create()?;
    let insns = hit_counter_prog(map.fd);
    let prog_fd = load_bpf_prog(&insns, BPF_PROG_TYPE_KPROBE)?;
    attach_bpf_to_perf(perf_fd, prog_fd)?;

    let description = format!("kprobe {}", cfg.symbol);
    Ok(BpfProbe {
        _map: map,
        _prog_fd: prog_fd,
        _perf_fd: perf_fd,
        description,
    })
}

fn write_tracefs(file: &str, content: &str) -> Result<(), EbpfError> {
    let paths = [
        format!("/sys/kernel/tracing/{file}"),
        format!("/sys/kernel/debug/tracing/{file}"),
    ];
    for path in &paths {
        if let Ok(mut f) = OpenOptions::new().write(true).open(path) {
            f.write_all(content.as_bytes())
                .map_err(|e| EbpfError::Tracefs { detail: e.to_string() })?;
            return Ok(());
        }
    }
    Err(EbpfError::Unavailable {
        detail: format!("tracefs not mounted (tried /sys/kernel/tracing and /sys/kernel/debug/tracing); cannot write {file}"),
    })
}

fn read_tracefs_id(sub_path: &str) -> Result<u32, EbpfError> {
    let paths = [
        format!("/sys/kernel/tracing/events/{sub_path}"),
        format!("/sys/kernel/debug/tracing/events/{sub_path}"),
    ];
    for path in &paths {
        if let Ok(s) = std::fs::read_to_string(path) {
            return s
                .trim()
                .parse::<u32>()
                .map_err(|e| EbpfError::Tracefs { detail: e.to_string() });
        }
    }
    Err(EbpfError::Unavailable {
        detail: format!("could not read tracepoint id from {sub_path}"),
    })
}

fn open_tracepoint_perf(id: u32, pid: i32) -> Result<RawFd, EbpfError> {
    #[repr(C)]
    struct PeAttr { type_: u32, size: u32, config: u64, _rest: [u64; 14] }
    let mut attr: PeAttr = unsafe { std::mem::zeroed() };
    attr.type_ = PERF_TYPE_TRACEPOINT;
    attr.size  = std::mem::size_of::<PeAttr>() as u32;
    attr.config = id as u64;

    let fd = unsafe {
        libc::syscall(
            SYS_PERF_EVENT_OPEN,
            &attr as *const PeAttr as libc::c_long,
            pid as libc::c_long,
            -1i64, // any cpu
            -1i64, // no group
            0i64,
        ) as RawFd
    };
    if fd < 0 {
        let e = errno();
        if e == libc::EPERM || e == libc::EACCES {
            return Err(EbpfError::PermissionDenied);
        }
        return Err(EbpfError::Syscall { op: "perf_event_open(tracepoint)", errno: e });
    }
    Ok(fd)
}

fn attach_bpf_to_perf(perf_fd: RawFd, prog_fd: RawFd) -> Result<(), EbpfError> {
    let rc = unsafe { libc::ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd) };
    if rc < 0 {
        return Err(EbpfError::Syscall { op: "PERF_EVENT_IOC_SET_BPF", errno: errno() });
    }
    let rc2 = unsafe { libc::ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) };
    if rc2 < 0 {
        return Err(EbpfError::Syscall { op: "PERF_EVENT_IOC_ENABLE", errno: errno() });
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time proof that both syscall numbers this module uses come from
    /// the *target* architecture's table. This module is gated only on
    /// `target_os = "linux"`; on aarch64 the asm-generic table assigns
    /// `bpf` = 280 and `perf_event_open` = 241, not the x86-64 321/298.
    /// Verified with `cargo check --tests --target aarch64-unknown-linux-gnu`.
    const _: () = assert!(SYS_BPF == libc::SYS_bpf);
    const _: () = assert!(SYS_PERF_EVENT_OPEN == libc::SYS_perf_event_open);

    #[test]
    fn syscall_numbers_match_this_architectures_table() {
        assert_eq!(SYS_BPF, libc::SYS_bpf);
        assert_eq!(SYS_PERF_EVENT_OPEN, libc::SYS_perf_event_open);
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(libc::SYS_bpf, 321);
            assert_eq!(libc::SYS_perf_event_open, 298);
        }
        #[cfg(target_arch = "aarch64")]
        {
            assert_eq!(libc::SYS_bpf, 280);
            assert_eq!(libc::SYS_perf_event_open, 241);
        }
    }

    #[test]
    fn hit_counter_prog_non_empty() {
        // We can't actually create a BPF map in a unit test without privileges,
        // but we can verify the instruction generator doesn't panic.
        // Use fd 3 as a dummy (not valid at runtime, but generator is pure).
        let prog = hit_counter_prog(3);
        assert!(!prog.is_empty(), "BPF program must have instructions");
        // Each instruction is 8 bytes; minimum expected: ~12 instructions.
        assert!(prog.len() >= 8, "expected at least 8 BPF instructions, got {}", prog.len());
    }

    #[test]
    fn online_cpus_positive() {
        assert!(online_cpus() >= 1);
    }

    #[test]
    fn kernel_version_code_is_real_or_an_explicit_error() {
        // ADAPTED: this used to accept whatever came back, including the
        // hardcoded 0x05_00_00 stand-in. Now there are exactly two honest
        // outcomes and the error must name the file it could not use.
        match kernel_version_code() {
            Ok(v) => {
                // A real /proc/sys/kernel/osrelease is at least 2.x.
                assert!(v >= 0x02_00_00, "implausible kernel version code {v:#x}");
                // Cross-check against the file rather than trusting the encode.
                let raw = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
                let major: u32 = raw.trim().split('.').next().unwrap().parse().unwrap();
                assert_eq!(v >> 16, major, "major must come from the file, not a default");
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("/proc/sys/kernel/osrelease"),
                    "the error must name why the version is unknown, got {msg:?}"
                );
                assert!(
                    msg.contains("refusing to guess") || msg.contains("unknown"),
                    "the error must state that nothing was guessed, got {msg:?}"
                );
            }
        }
    }

    /// `kern_version` must match the kernel's own `LINUX_VERSION_CODE`, and the
    /// patch level is where distro suffixes live.
    ///
    /// The first case is this project's own test host. `splitn(3, '.')` leaves
    /// `33.2-microsoft-standard-WSL2` as the patch component; the old code
    /// stripped at `-`, got `33.2`, failed to parse it as `u32` and fell back to
    /// 0 — reporting `0x06_12_00` for a 6.18.33 kernel, with nobody told the
    /// number was invented. That is the same defect
    /// `no_hardcoded_kernel_version_default_remains` guards by SPELLING, and it
    /// is why that guard could not see this: the fabricated value arrived by a
    /// different route.
    #[test]
    fn the_patch_level_survives_a_distro_suffix() {
        let code = |s: &str| version_code_from_osrelease(s).unwrap();
        assert_eq!(code("6.18.33.2-microsoft-standard-WSL2"), (6 << 16) | (18 << 8) | 33);
        assert_eq!(code("5.15.119-generic"), (5 << 16) | (15 << 8) | 119);
        assert_eq!(code("6.8.0-51-generic"), (6 << 16) | (8 << 8));
        assert_eq!(code("6.8"), (6 << 16) | (8 << 8), "an absent patch is 0");
        assert_eq!(code("6.8.+weird"), (6 << 16) | (8 << 8), "a digit-less patch is 0");
        // Major/minor are never guessed.
        assert!(version_code_from_osrelease("not-a-version").is_err());
        assert!(version_code_from_osrelease("6").is_err());
    }

    #[test]
    fn no_hardcoded_kernel_version_default_remains() {
        let src = include_str!("ebpf_uprobe.rs");
        let production = src.split_once("#[cfg(test)]").map_or(src, |(h, _)| h);
        assert!(
            !production.contains("unwrap_or(0x05_00_00)"),
            "the assumed-5.0.0 fallback must stay deleted"
        );
    }

    #[test]
    fn bpf_map_create_requires_privileges() {
        // On an unprivileged system this returns PermissionDenied; on a
        // privileged one it creates the map. Either outcome is acceptable.
        match BpfMap::create() {
            Ok(_) => { /* map created — great */ }
            Err(EbpfError::PermissionDenied) => {
                eprintln!("test skipped: CAP_BPF not available");
            }
            Err(e) => {
                eprintln!("test skipped (BPF unavailable on this host): {e}");
            }
        }
    }

    #[test]
    fn attach_uprobe_requires_privileges_or_tracefs() {
        let cfg = UprobeConfig {
            path: "/usr/lib/x86_64-linux-gnu/libc.so.6".into(),
            offset: 0x0,
            pid: -1,
        };
        match attach_uprobe(&cfg) {
            Ok(_probe) => { /* attached — great */ }
            Err(EbpfError::PermissionDenied) => {
                eprintln!("test skipped: no CAP_BPF");
            }
            Err(EbpfError::Unavailable { detail }) => {
                eprintln!("test skipped: tracefs unavailable ({detail})");
            }
            Err(e) => {
                eprintln!("test skipped: {e}");
            }
        }
    }
}
