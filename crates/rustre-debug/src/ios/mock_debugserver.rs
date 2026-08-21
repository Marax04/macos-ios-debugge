//! In-process mock of Apple's `debugserver`, speaking the GDB Remote Serial
//! Protocol with the lldb extensions.
//!
//! # Why this exists
//!
//! Every other module in this crate has to talk to a real `debugserver` on a
//! real Mac to be exercised end to end. That would make the crate untestable on
//! the Windows hosts this workspace is developed on, and untested Apple code is
//! exactly the "confidently wrong" failure mode this repo punishes. So the mock
//! is not a stub: it is a small but *faithful* implementation of the server side
//! — ARM64 register file, sparse address space, multiple threads, server-managed
//! breakpoints, `T`/`S`/`W` stop replies, paginated `qXfer`, run-length
//! encoding, `QStartNoAckMode`, thread suffixes — plus deliberate fault
//! injection so the client's error paths are reachable too.
//!
//! It also contains a deliberately tiny ARM64 interpreter (8 encodings). That is
//! what makes `continue`/`step`/backtrace tests *mean* something: a breakpoint
//! stop happens because the emulated PC actually reached the address, and a
//! frame-pointer chain exists because emulated `stp x29, x30, [sp, #-16]!`
//! actually wrote to emulated stack memory.
//!
//! # Deliberate limits (documented, never silent)
//!
//! * Only the 8 instruction encodings in [`Arm64Interp::step`] are emulated.
//!   Anything else advances PC by 4 and is *counted* in
//!   [`MockDebugserver::unknown_insn_count`], so a test can assert it executed
//!   what it thought it did instead of drifting through garbage.
//! * `vRun`/`A`-packet process launch creates the process image the caller
//!   preloaded; the mock does not load a Mach-O by itself.
//! * Big-endian and 32-bit targets are rejected with an explicit error rather
//!   than silently mis-decoded.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::ios::arm64;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failure of the mock transport itself (not an RSP `Exx` error reply, which is
/// a perfectly normal in-band response and is returned as bytes).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MockError {
    /// The simulated connection was closed — either by `close_after_n` fault
    /// injection or by a `k`/`D` packet. Mirrors a real socket EOF.
    #[error("mock debugserver connection closed")]
    ConnectionClosed,
    /// The client sent a byte stream the framer cannot make sense of.
    #[error("malformed inbound framing: {0}")]
    Framing(String),
    /// The client's packet had a checksum that does not match its payload.
    #[error("bad checksum from client: expected {expected:02x}, got {got:02x}")]
    BadChecksum { expected: u8, got: u8 },
}

// ---------------------------------------------------------------------------
// Register file
// ---------------------------------------------------------------------------

/// Number of general-purpose `x` registers exposed (`x0`..`x30`; `x30` is `lr`).
pub const NUM_X_REGS: usize = 31;
/// Number of NEON `v` registers exposed (`v0`..`v31`).
pub const NUM_V_REGS: usize = 32;

/// Byte offset of `sp` inside the `g` packet payload.
pub const OFF_SP: usize = NUM_X_REGS * 8;
/// Byte offset of `pc` inside the `g` packet payload.
pub const OFF_PC: usize = OFF_SP + 8;
/// Byte offset of `cpsr` inside the `g` packet payload.
pub const OFF_CPSR: usize = OFF_PC + 8;
/// Byte offset of `v0` inside the `g` packet payload.
pub const OFF_V0: usize = OFF_CPSR + 4;
/// Byte offset of `fpsr` inside the `g` packet payload.
pub const OFF_FPSR: usize = OFF_V0 + NUM_V_REGS * 16;
/// Byte offset of `fpcr` inside the `g` packet payload.
pub const OFF_FPCR: usize = OFF_FPSR + 4;
/// Total size in bytes of the `g` packet payload for this target.
pub const G_PACKET_BYTES: usize = OFF_FPCR + 4;

/// The ARM64 register file of one simulated thread.
///
/// Layout is fixed and mirrors what `debugserver` reports through
/// `qRegisterInfo`, so a client that builds its register map at runtime (the
/// correct way) and one that hardcodes offsets (the trap `rr_backend.rs` fell
/// into) will agree — which is precisely what makes the register-map tests
/// meaningful.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arm64Registers {
    /// `x0`..`x30`. Index 29 is the frame pointer, index 30 the link register.
    pub x: [u64; NUM_X_REGS],
    pub sp: u64,
    pub pc: u64,
    pub cpsr: u32,
    /// `v0`..`v31`, 128-bit each.
    pub v: [u128; NUM_V_REGS],
    pub fpsr: u32,
    pub fpcr: u32,
}

impl Default for Arm64Registers {
    fn default() -> Self {
        Self {
            x: [0; NUM_X_REGS],
            sp: 0,
            pc: 0,
            // EL0, AArch64, interrupts unmasked — what a userspace thread shows.
            cpsr: 0x6000_0000,
            v: [0; NUM_V_REGS],
            fpsr: 0,
            fpcr: 0,
        }
    }
}

impl Arm64Registers {
    /// Frame pointer (`x29`).
    #[must_use]
    pub const fn fp(&self) -> u64 {
        self.x[29]
    }

    /// Link register (`x30`).
    #[must_use]
    pub const fn lr(&self) -> u64 {
        self.x[30]
    }

    /// Encode as the payload of a `g` packet reply (little-endian hex).
    #[must_use]
    pub fn encode_g(&self) -> String {
        let mut out = String::with_capacity(G_PACKET_BYTES * 2);
        for r in &self.x {
            push_hex_le(&mut out, &r.to_le_bytes());
        }
        push_hex_le(&mut out, &self.sp.to_le_bytes());
        push_hex_le(&mut out, &self.pc.to_le_bytes());
        push_hex_le(&mut out, &self.cpsr.to_le_bytes());
        for r in &self.v {
            push_hex_le(&mut out, &r.to_le_bytes());
        }
        push_hex_le(&mut out, &self.fpsr.to_le_bytes());
        push_hex_le(&mut out, &self.fpcr.to_le_bytes());
        out
    }

    /// Decode from the payload of a `G` packet. Returns `None` unless the
    /// payload is hex and exactly [`G_PACKET_BYTES`] long: a short one would
    /// have to be zero-filled (a partially applied register write is worse
    /// than a rejected one) and a long one would have its tail silently
    /// dropped, reporting a full-register write that did not happen.
    #[must_use]
    pub fn decode_g(hex: &str) -> Option<Self> {
        let bytes = decode_hex(hex)?;
        if bytes.len() != G_PACKET_BYTES {
            return None;
        }
        let mut regs = Self::default();
        for (i, r) in regs.x.iter_mut().enumerate() {
            *r = read_u64_le(&bytes[i * 8..]);
        }
        regs.sp = read_u64_le(&bytes[OFF_SP..]);
        regs.pc = read_u64_le(&bytes[OFF_PC..]);
        regs.cpsr = read_u32_le(&bytes[OFF_CPSR..]);
        for (i, r) in regs.v.iter_mut().enumerate() {
            let off = OFF_V0 + i * 16;
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&bytes[off..off + 16]);
            *r = u128::from_le_bytes(buf);
        }
        regs.fpsr = read_u32_le(&bytes[OFF_FPSR..]);
        regs.fpcr = read_u32_le(&bytes[OFF_FPCR..]);
        Some(regs)
    }

    /// Read one register by its `qRegisterInfo` index (the `p` packet operand).
    #[must_use]
    pub fn read_indexed(&self, idx: usize) -> Option<String> {
        let mut out = String::new();
        match idx {
            0..=30 => push_hex_le(&mut out, &self.x[idx].to_le_bytes()),
            31 => push_hex_le(&mut out, &self.sp.to_le_bytes()),
            32 => push_hex_le(&mut out, &self.pc.to_le_bytes()),
            33 => push_hex_le(&mut out, &self.cpsr.to_le_bytes()),
            34..=65 => push_hex_le(&mut out, &self.v[idx - 34].to_le_bytes()),
            66 => push_hex_le(&mut out, &self.fpsr.to_le_bytes()),
            67 => push_hex_le(&mut out, &self.fpcr.to_le_bytes()),
            _ => return None,
        }
        Some(out)
    }

    /// Write one register by its `qRegisterInfo` index (the `P` packet).
    pub fn write_indexed(&mut self, idx: usize, hex: &str) -> bool {
        let Some(bytes) = decode_hex(hex) else {
            return false;
        };
        match idx {
            0..=33 | 66 | 67 => {
                let want = if (0..=32).contains(&idx) { 8 } else { 4 };
                // The value must be exactly the register's width: a short one
                // would be zero-extended, a long one silently truncated.
                if bytes.len() != want {
                    return false;
                }
                match idx {
                    0..=30 => self.x[idx] = read_u64_le(&bytes),
                    31 => self.sp = read_u64_le(&bytes),
                    32 => self.pc = read_u64_le(&bytes),
                    33 => self.cpsr = read_u32_le(&bytes),
                    66 => self.fpsr = read_u32_le(&bytes),
                    _ => self.fpcr = read_u32_le(&bytes),
                }
                true
            }
            34..=65 => {
                if bytes.len() != 16 {
                    return false;
                }
                let mut buf = [0u8; 16];
                buf.copy_from_slice(&bytes[..16]);
                self.v[idx - 34] = u128::from_le_bytes(buf);
                true
            }
            _ => false,
        }
    }
}

/// One row of the `qRegisterInfo<N>` enumeration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterInfo {
    pub name: &'static str,
    pub bitsize: u32,
    pub offset: usize,
    pub encoding: &'static str,
    pub format: &'static str,
    pub set: &'static str,
    pub dwarf_regnum: u32,
    /// `pc`/`sp`/`fp`/`lr`/`arg1`.. — how a client learns which register is
    /// which without hardcoding a layout.
    pub generic: Option<&'static str>,
}

impl RegisterInfo {
    /// Serialise into the `key:value;` form debugserver replies with.
    #[must_use]
    pub fn to_reply(&self) -> String {
        let mut s = format!(
            "name:{};bitsize:{};offset:{};encoding:{};format:{};set:{};dwarf:{};",
            self.name, self.bitsize, self.offset, self.encoding, self.format, self.set,
            self.dwarf_regnum
        );
        if let Some(g) = self.generic {
            let _ = write!(s, "generic:{g};");
        }
        s
    }
}

/// Build the full register-info table in `p`/`P` index order.
#[must_use]
pub fn register_info_table() -> Vec<RegisterInfo> {
    // Leaked names would be the easy way out; instead the 68 names are a static
    // table so the whole thing stays `&'static str` with no allocation games.
    const X_NAMES: [&str; NUM_X_REGS] = [
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
        "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26",
        "x27", "x28", "fp", "lr",
    ];
    const V_NAMES: [&str; NUM_V_REGS] = [
        "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13",
        "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26",
        "v27", "v28", "v29", "v30", "v31",
    ];

    let mut out = Vec::with_capacity(68);
    for (i, name) in X_NAMES.iter().enumerate() {
        let generic = match i {
            0 => Some("arg1"),
            1 => Some("arg2"),
            2 => Some("arg3"),
            3 => Some("arg4"),
            29 => Some("fp"),
            30 => Some("ra"),
            _ => None,
        };
        out.push(RegisterInfo {
            name,
            bitsize: 64,
            offset: i * 8,
            encoding: "uint",
            format: "hex",
            set: "General Purpose Registers",
            dwarf_regnum: u32::try_from(i).unwrap_or(0),
            generic,
        });
    }
    out.push(RegisterInfo {
        name: "sp",
        bitsize: 64,
        offset: OFF_SP,
        encoding: "uint",
        format: "hex",
        set: "General Purpose Registers",
        dwarf_regnum: 31,
        generic: Some("sp"),
    });
    out.push(RegisterInfo {
        name: "pc",
        bitsize: 64,
        offset: OFF_PC,
        encoding: "uint",
        format: "hex",
        set: "General Purpose Registers",
        dwarf_regnum: 32,
        generic: Some("pc"),
    });
    out.push(RegisterInfo {
        name: "cpsr",
        bitsize: 32,
        offset: OFF_CPSR,
        encoding: "uint",
        format: "hex",
        set: "General Purpose Registers",
        dwarf_regnum: 33,
        generic: Some("flags"),
    });
    for (i, name) in V_NAMES.iter().enumerate() {
        out.push(RegisterInfo {
            name,
            bitsize: 128,
            offset: OFF_V0 + i * 16,
            encoding: "vector",
            format: "vector-uint8",
            set: "Floating Point Registers",
            dwarf_regnum: u32::try_from(64 + i).unwrap_or(64),
            generic: None,
        });
    }
    out.push(RegisterInfo {
        name: "fpsr",
        bitsize: 32,
        offset: OFF_FPSR,
        encoding: "uint",
        format: "hex",
        set: "Floating Point Registers",
        dwarf_regnum: 96,
        generic: None,
    });
    out.push(RegisterInfo {
        name: "fpcr",
        bitsize: 32,
        offset: OFF_FPCR,
        encoding: "uint",
        format: "hex",
        set: "Floating Point Registers",
        dwarf_regnum: 97,
        generic: None,
    });
    out
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

/// Page protection of a simulated region, reported through `qMemoryRegionInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Perms {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

impl Perms {
    #[must_use]
    pub const fn rx() -> Self {
        Self { read: true, write: false, exec: true }
    }
    #[must_use]
    pub const fn rw() -> Self {
        Self { read: true, write: true, exec: false }
    }
    #[must_use]
    pub fn to_reply(self) -> String {
        let mut s = String::new();
        if self.read {
            s.push('r');
        }
        if self.write {
            s.push('w');
        }
        if self.exec {
            s.push('x');
        }
        s
    }
}

/// Largest `_M` allocation the mock will attempt. The simulated address space
/// is a handful of small regions, so anything past this is a malformed request
/// and is answered `E01` — as a device would — rather than handed to the
/// allocator, where it would abort the whole test process.
pub const MAX_ALLOC_BYTES: usize = 64 * 1024 * 1024;

/// One mapped region of the simulated address space.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base: u64,
    pub data: Vec<u8>,
    pub perms: Perms,
    pub name: String,
}

impl MemoryRegion {
    #[must_use]
    pub fn new(base: u64, data: Vec<u8>, perms: Perms, name: impl Into<String>) -> Self {
        Self { base, data, perms, name: name.into() }
    }

    /// Zero-filled writable region (a stack, a heap, a BSS).
    #[must_use]
    pub fn zeroed(base: u64, len: usize, perms: Perms, name: impl Into<String>) -> Self {
        Self::new(base, vec![0; len], perms, name)
    }

    #[must_use]
    pub const fn end(&self) -> u64 {
        self.base.wrapping_add(self.data.len() as u64)
    }

    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }
}

/// One data access performed by the emulated instruction stream.
///
/// Recorded so hardware watchpoints can be evaluated against what the program
/// actually touched, rather than guessed from the opcode. Instruction fetch is
/// deliberately *not* recorded: a fetch is not a data access and must not fire
/// a `Z2`/`Z3`/`Z4` watchpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemAccess {
    pub addr: u64,
    pub len: usize,
    /// `true` for a store, `false` for a load.
    pub write: bool,
}

impl MemAccess {
    /// Does this access touch any byte of `[addr, addr + len)`?
    #[must_use]
    pub const fn overlaps(&self, addr: u64, len: usize) -> bool {
        let a_end = self.addr.saturating_add(self.len as u64);
        let b_end = addr.saturating_add(len as u64);
        self.addr < b_end && addr < a_end
    }
}

/// The simulated address space: a sparse set of regions keyed by base address.
#[derive(Debug, Default, Clone)]
pub struct MemorySpace {
    regions: BTreeMap<u64, MemoryRegion>,
    /// Data accesses seen while recording is on. `RefCell` because `read` takes
    /// `&self` — the alternative would be to make every read `&mut`, which the
    /// rest of the crate (and the `MemoryReader` traits) cannot do.
    access_log: RefCell<Vec<MemAccess>>,
    recording: bool,
}

impl MemorySpace {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Map a region. Overlapping maps are rejected — silently letting two
    /// regions overlap would make reads depend on iteration order.
    pub fn map(&mut self, region: MemoryRegion) -> bool {
        if self
            .regions
            .values()
            .any(|r| region.base < r.end() && r.base < region.end())
        {
            return false;
        }
        self.regions.insert(region.base, region);
        true
    }

    #[must_use]
    pub fn region_at(&self, addr: u64) -> Option<&MemoryRegion> {
        self.regions.range(..=addr).next_back().map(|(_, r)| r).filter(|r| r.contains(addr))
    }

    fn region_at_mut(&mut self, addr: u64) -> Option<&mut MemoryRegion> {
        self.regions
            .range_mut(..=addr)
            .next_back()
            .map(|(_, r)| r)
            .filter(|r| r.contains(addr))
    }

    /// Read `len` bytes. Fails (rather than truncating) if the range is not
    /// fully backed by one readable region — a real `mach_vm_read` behaves the
    /// same way and clients must handle it.
    #[must_use]
    pub fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        // Logged only once the access has SUCCEEDED: an access that faulted is
        // not something the program touched — the instruction aborted and the
        // hardware takes a translation fault instead of reporting a watchpoint.
        let out = self.read_untracked(addr, len)?;
        if self.recording {
            self.access_log.borrow_mut().push(MemAccess { addr, len, write: false });
        }
        Some(out)
    }

    /// [`MemorySpace::read`] without touching the access log. Used for
    /// instruction fetch and for debugger-initiated (`m`) reads, neither of
    /// which is a data access by the *target* and so neither of which may fire
    /// a watchpoint.
    #[must_use]
    pub fn read_untracked(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let r = self.region_at(addr)?;
        if !r.perms.read {
            return None;
        }
        let off = usize::try_from(addr - r.base).ok()?;
        let end = off.checked_add(len)?;
        r.data.get(off..end).map(<[u8]>::to_vec)
    }

    /// Start or stop recording data accesses. Turning recording on clears the
    /// log, so a caller always observes exactly one step's worth.
    pub fn set_recording(&mut self, on: bool) {
        self.recording = on;
        self.access_log.borrow_mut().clear();
    }

    /// Drain the recorded accesses.
    pub fn take_accesses(&self) -> Vec<MemAccess> {
        std::mem::take(&mut *self.access_log.borrow_mut())
    }

    /// Write bytes; fails if unmapped, read-only, or not fully contained.
    pub fn write(&mut self, addr: u64, bytes: &[u8]) -> bool {
        let ok = self.write_untracked(addr, bytes);
        // Only an access that COMPLETED is an access the program performed: a
        // faulting store takes the translation fault and its data never reaches
        // the watchpoint comparators, so it must not be logged.
        if ok && self.recording {
            self.access_log.borrow_mut().push(MemAccess {
                addr,
                len: bytes.len(),
                write: true,
            });
        }
        ok
    }

    /// [`MemorySpace::write`] without touching the access log. Used for
    /// debugger-initiated (`M`/`X`) writes, which are not accesses by the
    /// target and so may not fire a watchpoint.
    pub fn write_untracked(&mut self, addr: u64, bytes: &[u8]) -> bool {
        let Some(r) = self.region_at_mut(addr) else {
            return false;
        };
        if !r.perms.write && !r.perms.exec {
            // Executable pages stay writable in the mock so a client can patch
            // in a `BRK` the manual (non-`Z0`) way; pure read-only data cannot.
            return false;
        }
        let Ok(off) = usize::try_from(addr - r.base) else {
            return false;
        };
        let Some(end) = off.checked_add(bytes.len()) else {
            return false;
        };
        match r.data.get_mut(off..end) {
            Some(dst) => {
                dst.copy_from_slice(bytes);
                true
            }
            None => false,
        }
    }

    #[must_use]
    pub fn read_u32(&self, addr: u64) -> Option<u32> {
        self.read(addr, 4).map(|b| read_u32_le(&b))
    }

    #[must_use]
    pub fn read_u64(&self, addr: u64) -> Option<u64> {
        self.read(addr, 8).map(|b| read_u64_le(&b))
    }

    pub fn write_u64(&mut self, addr: u64, v: u64) -> bool {
        self.write(addr, &v.to_le_bytes())
    }

    /// All regions, ordered by base address.
    pub fn iter(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.regions.values()
    }
}

// ---------------------------------------------------------------------------
// Threads and breakpoints
// ---------------------------------------------------------------------------

/// Why a thread is stopped, as reported in `T`/`S`/`W` stop replies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopKind {
    /// Server-managed (`Z0`/`Z1`) breakpoint at this address.
    Breakpoint(u64),
    /// Watchpoint (`Z2`/`Z3`/`Z4`) on this address.
    ///
    /// `kind` is the *registered* watchpoint class, which is what determines
    /// the `watch:`/`rwatch:`/`awatch:` key in the stop reply; `write` says
    /// what the access that tripped it actually was. They differ for an access
    /// watchpoint, and a client that conflates them mis-reports every `Z4` hit.
    Watchpoint { addr: u64, kind: BpKind, write: bool },
    /// Completed a `vCont;s`.
    Step,
    /// Executed a `BRK` instruction (a manually patched breakpoint).
    Brk(u64),
    /// A POSIX signal was delivered.
    Signal(u8),
    /// The process exited; no thread is running any more.
    Exited(u8),
    /// Freshly attached / not yet resumed.
    Attached,
}

impl StopKind {
    /// Signal number reported in the stop reply.
    #[must_use]
    pub const fn signal(&self) -> u8 {
        match self {
            Self::Breakpoint(_) | Self::Watchpoint { .. } | Self::Step | Self::Brk(_)
            | Self::Attached => 5, // SIGTRAP
            Self::Signal(s) => *s,
            Self::Exited(_) => 0,
        }
    }
}

/// One simulated thread.
#[derive(Debug, Clone)]
pub struct MockThread {
    pub tid: u32,
    pub name: String,
    /// GCD dispatch queue label, reported by `jThreadsInfo` only. A real
    /// `debugserver` omits the key entirely for a thread that is not servicing
    /// a queue, which is why this is an `Option` and not an empty string.
    pub queue: Option<String>,
    pub regs: Arm64Registers,
    pub stop: StopKind,
    /// Set once the thread has run off the end of its call chain.
    pub exited: bool,
}

impl MockThread {
    #[must_use]
    pub fn new(tid: u32, name: impl Into<String>) -> Self {
        Self {
            tid,
            name: name.into(),
            queue: None,
            regs: Arm64Registers::default(),
            stop: StopKind::Attached,
            exited: false,
        }
    }

    /// Attach a GCD queue label, as a dispatch-serviced thread would have.
    #[must_use]
    pub fn with_queue(mut self, queue: impl Into<String>) -> Self {
        self.queue = Some(queue.into());
        self
    }

    /// The `jThreadsInfo` `reason` string for this thread's stop kind.
    ///
    /// Mirrors the vocabulary a real `debugserver` uses in both the JSON dump
    /// and the `T` packet, so a client cannot pass one and fail the other.
    #[must_use]
    pub const fn reason_str(&self) -> &'static str {
        match self.stop {
            StopKind::Breakpoint(_) | StopKind::Brk(_) => "breakpoint",
            StopKind::Watchpoint { .. } => "watchpoint",
            StopKind::Step => "trace",
            StopKind::Signal(_) => "signal",
            StopKind::Exited(_) => "exited",
            StopKind::Attached => "none",
        }
    }
}

/// The five `Z`/`z` breakpoint kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpKind {
    Software,
    Hardware,
    WriteWatch,
    ReadWatch,
    AccessWatch,
}

impl BpKind {
    #[must_use]
    pub const fn from_code(c: u8) -> Option<Self> {
        match c {
            0 => Some(Self::Software),
            1 => Some(Self::Hardware),
            2 => Some(Self::WriteWatch),
            3 => Some(Self::ReadWatch),
            4 => Some(Self::AccessWatch),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_watchpoint(self) -> bool {
        matches!(self, Self::WriteWatch | Self::ReadWatch | Self::AccessWatch)
    }

    /// Does an access of this direction trip a watchpoint of this class?
    #[must_use]
    pub const fn fires_on(self, write: bool) -> bool {
        match self {
            Self::WriteWatch => write,
            Self::ReadWatch => !write,
            Self::AccessWatch => true,
            Self::Software | Self::Hardware => false,
        }
    }

    /// Stop-reply key debugserver uses to report a hit of this class.
    #[must_use]
    pub const fn stop_key(self) -> Option<&'static str> {
        match self {
            Self::WriteWatch => Some("watch"),
            Self::ReadWatch => Some("rwatch"),
            Self::AccessWatch => Some("awatch"),
            Self::Software | Self::Hardware => None,
        }
    }
}

/// A registered `Z` packet breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MockBreakpoint {
    pub addr: u64,
    pub kind: BpKind,
    pub len: u64,
    /// Reference count, as a real debugserver keeps one per `(addr, kind)`.
    ///
    /// A second `Z` at an address that already has one does NOT no-op: it
    /// raises the count. A `z` lowers it, and the trap is only removed — and
    /// only stops firing — when the count reaches zero. Without this a doubled
    /// insert followed by a single remove ends in the same state as a matched
    /// pair, which makes every duplicate-insert defect in the client invisible.
    pub refs: u32,
}

// ---------------------------------------------------------------------------
// Fault injection
// ---------------------------------------------------------------------------

/// Deliberate misbehaviour, so a client's recovery paths are reachable from a
/// test instead of only from a bad cable.
#[derive(Debug, Default, Clone)]
pub struct FaultInjection {
    /// Drop this many leading bytes from the next reply (simulates a truncated
    /// TCP segment) and then reset to zero.
    pub drop_bytes: usize,
    /// Corrupt the checksum of the next reply, then reset.
    pub corrupt_checksum: bool,
    /// Close the connection after this many packets have been answered.
    pub close_after_n: Option<usize>,
    /// Split every reply into chunks of at most this many bytes. The chunks are
    /// still returned concatenated by [`MockDebugserver::feed`]; use
    /// [`MockDebugserver::feed_chunked`] to observe them separately.
    pub chunk_size: Option<usize>,
    /// Reply with run-length encoding wherever it shortens the payload.
    pub use_rle: bool,
    /// Answer every `p` packet with only this many BYTES of the register value
    /// (a stub that shortens its reply, or a different register set). The
    /// client must not silently zero-fill the missing high bytes.
    pub truncate_p_to_bytes: Option<usize>,
}

// ---------------------------------------------------------------------------
// The mock server
// ---------------------------------------------------------------------------

/// A simulated Apple `debugserver` attached to a simulated ARM64 process.
#[derive(Debug)]
pub struct MockDebugserver {
    pub pid: u32,
    pub memory: MemorySpace,
    threads: Vec<MockThread>,
    current_g_thread: u32,
    current_c_thread: u32,
    breakpoints: Vec<MockBreakpoint>,
    /// Hardware (`Z1`) breakpoint slots the simulated core implements.
    hw_breakpoint_slots: usize,
    /// Every accepted `Z`/`z` packet is tallied, duplicates included, so a test
    /// can observe that the client sent two inserts even when the resulting
    /// breakpoint list looks identical.
    z_inserts: usize,
    z_removes: usize,
    /// When set, `Z0` is answered with an empty reply, the way a stub that
    /// does not implement server-managed software breakpoints does. Exists so
    /// a client's manual patch-the-instruction fallback is reachable from a
    /// test instead of only against such a stub in the wild.
    refuse_z_software: bool,
    /// When `Some(n)`, the next `n` software `Z0` INSERTS are answered `OK`
    /// and every later one is refused. Models the stub that accepted a trap
    /// while it still had room and refuses the RE-arm after the resource was
    /// given up and taken by something else. `refuse_z_software` cannot reach
    /// that path: it refuses from the very first insert, so the client never
    /// gets a stub-managed trap to re-enable in the first place.
    z_software_budget: Option<usize>,
    /// When set, every `z` REMOVAL is answered `E01` while `Z` insertions keep
    /// working — a stub that refuses to uninstall a trap it still holds. Models
    /// the real refusals debugserver returns for a `z` it cannot honour (wrong
    /// length for the installed trap, target no longer writable), which are the
    /// only way to observe that a client checks the removal reply at all.
    refuse_z_removals: bool,
    /// Let this many `Z0` INSERTS through, then answer every later one with an
    /// empty reply. Distinct from `refuse_z_software`, which refuses from the
    /// first packet: a stub can perfectly well accept the initial insert and
    /// refuse a later one (the page stopped being writable, the image was
    /// unloaded), and that is the only shape in which a client's RE-arm path
    /// can be observed separately from its first-arm path.
    sw_inserts_before_failing: Option<usize>,
    /// Answer memory WRITEs with `E09` once this many have succeeded.
    writes_before_failing: Option<usize>,
    /// Refuse the `g` register-block read with `E09` once this many have
    /// succeeded.
    reg_reads_before_failing: Option<usize>,
    /// Answer `m` with one byte fewer than requested.
    short_reads: bool,
    /// Hardware watchpoint (`Z2`/`Z3`/`Z4`) slots the simulated core implements.
    hw_watchpoint_slots: usize,
    /// Set by `QStartNoAckMode`; when true neither side sends `+`/`-`.
    no_ack_mode: bool,
    thread_suffix_supported: bool,
    list_threads_in_stop_reply: bool,
    /// When set, thread ids are reported in the multiprocess spelling the
    /// `multiprocess+` feature turns on: `qC` answers `QCp<pid>.<tid>` instead
    /// of `QC<tid>`. This client negotiates `multiprocess+` in its handshake,
    /// so a conforming stub is entitled to answer this way.
    multiprocess_ids: bool,
    /// When set, stop replies carry no `thread:` key. The field is optional in
    /// the protocol, so a stub omitting it is legal — and it is the only state
    /// in which a client's `qC` fallback after a stop is reachable at all.
    omit_stop_reply_thread: bool,
    /// When false the server answers `jThreadsInfo` with an empty packet, the
    /// way a stub that predates the extension does — the only way to reach a
    /// client's fallback path from a test.
    jthreads_info_supported: bool,
    /// When false the server answers `QSetWorkingDir`/`QEnvironmentHexEncoded`
    /// with an empty packet, the way a stub without launch-environment support
    /// does.
    launch_env_supported: bool,
    /// `KEY=VALUE` pairs decoded from `QEnvironmentHexEncoded`.
    launch_env: Vec<String>,
    /// Path decoded from `QSetWorkingDir`.
    launch_working_dir: Option<String>,
    /// Loaded images reported by `jGetLoadedDynamicLibrariesInfos`.
    images: Vec<LoadedImage>,
    /// Verbatim image objects appended to the `images` array, for shapes
    /// [`LoadedImage`] cannot express — a stub that omits `load_address`
    /// altogether, or emits it as a hex string rather than a JSON number.
    raw_images: Vec<String>,
    /// Payload served by `qXfer:features:read:target.xml`.
    target_xml: String,
    faults: FaultInjection,
    packets_answered: usize,
    closed: bool,
    /// Cap on emulated instructions per `continue`, so a runaway loop in a test
    /// fails fast instead of hanging the suite.
    pub max_steps_per_continue: usize,
    /// When set, a continue is answered by **nothing at all** — the target is
    /// modelled as still running — and only a `\x03` interrupt produces the
    /// stop reply.
    ///
    /// This is not a convenience: it is the only state in which `pause()` has
    /// any meaning. With the default synchronous emulation a `c` returns a stop
    /// reply before the client can possibly interrupt it, so a test of the
    /// asynchronous path against that would be testing nothing.
    pub run_until_interrupt: bool,
    /// Instructions the interpreter did not recognise (see module docs).
    pub unknown_insn_count: usize,
    /// Every packet the client sent, in order — lets a test assert *how* the
    /// client did something, not just that it worked.
    pub packet_log: Vec<String>,
    /// The last framed reply, kept verbatim so a `-` can be answered the way a
    /// real `debugserver` answers it: re-send those exact bytes, WITHOUT
    /// re-running the command. Stored pre-fault-injection, because the damage
    /// a fault models happens on the wire, not in the stub's memory.
    last_reply: Option<Vec<u8>>,
    /// How many `-` frames the client sent.
    pub nacks_received: usize,
    /// How many of those were answered by re-sending [`Self::last_reply`].
    pub retransmissions: usize,
    inbound: Vec<u8>,
    exit_code: Option<u8>,
    /// Set once a stop reply that ANNOUNCES the death (`X`) has actually gone
    /// out, which is what makes the target unreachable — see `target_is_gone`.
    death_reported: bool,
    /// Signal the target died OF, reported as an `X` stop reply.
    ///
    /// Distinct from `exit_code`: `W` says "exited with status", `X` says
    /// "killed by signal". Both mean the process is gone, and a debugger that
    /// treats only the first as an ending keeps talking to a corpse.
    killed_by: Option<u8>,
    /// Accept this many `Z0` inserts, then answer every further one with an
    /// error. Models a stub that armed a software breakpoint happily and later
    /// cannot re-arm it — the page turned read-only, the slot table filled,
    /// the region was unmapped. A client that never reads the reply cannot
    /// tell that case from a successful re-arm.
    sw_inserts_before_refusing: Option<usize>,
    /// Addresses handed out by `_M` (allocate) and freed by `_m`.
    allocations: BTreeMap<u64, u64>,
    next_alloc: u64,
}

/// A dynamic library image as reported to the client, including its ASLR slide.
#[derive(Debug, Clone)]
pub struct LoadedImage {
    pub path: String,
    pub load_address: u64,
    /// `static_addr + slide == runtime_addr`.
    pub slide: u64,
    pub uuid: [u8; 16],
}

impl MockDebugserver {
    /// A server with an empty address space and a single thread, stopped as if
    /// freshly attached.
    #[must_use]
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            memory: MemorySpace::new(),
            threads: vec![MockThread::new(1, "main")],
            current_g_thread: 1,
            current_c_thread: 1,
            breakpoints: Vec::new(),
            hw_breakpoint_slots: arm64::hw::APPLE_HW_BREAKPOINT_SLOTS,
            z_inserts: 0,
            z_removes: 0,
            refuse_z_software: false,
            z_software_budget: None,
            refuse_z_removals: false,
            sw_inserts_before_failing: None,
            writes_before_failing: None,
            reg_reads_before_failing: None,
            short_reads: false,
            hw_watchpoint_slots: arm64::hw::APPLE_HW_WATCHPOINT_SLOTS,
            no_ack_mode: false,
            thread_suffix_supported: false,
            list_threads_in_stop_reply: false,
            multiprocess_ids: false,
            omit_stop_reply_thread: false,
            jthreads_info_supported: true,
            launch_env_supported: false,
            launch_env: Vec::new(),
            launch_working_dir: None,
            images: Vec::new(),
            raw_images: Vec::new(),
            target_xml: default_target_xml(),
            faults: FaultInjection::default(),
            packets_answered: 0,
            closed: false,
            max_steps_per_continue: 100_000,
            run_until_interrupt: false,
            unknown_insn_count: 0,
            packet_log: Vec::new(),
            last_reply: None,
            nacks_received: 0,
            retransmissions: 0,
            inbound: Vec::new(),
            exit_code: None,
            death_reported: false,
            killed_by: None,
            sw_inserts_before_refusing: None,
            allocations: BTreeMap::new(),
            next_alloc: 0x7000_0000_0000,
        }
    }

    /// Enable `QSetWorkingDir` / `QEnvironmentHexEncoded` support.
    pub const fn set_launch_env_supported(&mut self, on: bool) {
        self.launch_env_supported = on;
    }

    /// `KEY=VALUE` pairs received via `QEnvironmentHexEncoded`.
    #[must_use]
    pub fn launch_env(&self) -> &[String] {
        &self.launch_env
    }

    /// Working directory received via `QSetWorkingDir`.
    #[must_use]
    pub fn launch_working_dir(&self) -> Option<&str> {
        self.launch_working_dir.as_deref()
    }

    /// A ready-to-drive target: 64 KiB of stack at `0x1_6f00_0000`, a text
    /// region at `text_base` holding `code`, thread 1 parked at `text_base`
    /// with `lr == 0` (so returning from the outermost frame exits).
    #[must_use]
    pub fn with_program(pid: u32, text_base: u64, code: &[u32]) -> Self {
        let mut srv = Self::new(pid);
        let mut bytes = Vec::with_capacity(code.len() * 4);
        for insn in code {
            bytes.extend_from_slice(&insn.to_le_bytes());
        }
        assert!(
            srv.memory.map(MemoryRegion::new(text_base, bytes, Perms::rx(), "__TEXT")),
            "text region must map into an empty space"
        );
        const STACK_BASE: u64 = 0x1_6f00_0000;
        const STACK_LEN: usize = 64 * 1024;
        assert!(
            srv.memory.map(MemoryRegion::zeroed(STACK_BASE, STACK_LEN, Perms::rw(), "Stack")),
            "stack region must map into an empty space"
        );
        let t = &mut srv.threads[0];
        t.regs.pc = text_base;
        t.regs.sp = STACK_BASE + STACK_LEN as u64 - 16;
        t.regs.x[29] = 0;
        t.regs.x[30] = 0;
        srv.images.push(LoadedImage {
            path: "/usr/lib/mock.dylib".to_string(),
            load_address: text_base,
            slide: 0,
            uuid: [0xAB; 16],
        });
        srv
    }

    // -- configuration ------------------------------------------------------

    pub fn add_thread(&mut self, thread: MockThread) {
        self.threads.push(thread);
    }

    /// Report thread ids in the multiprocess `p<pid>.<tid>` spelling.
    pub const fn set_multiprocess_ids(&mut self, on: bool) {
        self.multiprocess_ids = on;
    }

    /// Leave the optional `thread:` key out of every stop reply.
    pub const fn set_omit_stop_reply_thread(&mut self, on: bool) {
        self.omit_stop_reply_thread = on;
    }

    /// Park the stub's own notion of the selected thread, the way a real stub
    /// arrives at one on its own before the client has sent any `H`.
    pub const fn set_current_thread(&mut self, tid: u32) {
        self.current_g_thread = tid;
        self.current_c_thread = tid;
    }

    /// Turn the `jThreadsInfo` extension on or off.
    pub const fn set_jthreads_info_supported(&mut self, supported: bool) {
        self.jthreads_info_supported = supported;
    }

    /// Mutable access to one thread, so a test can park it wherever it needs.
    pub fn thread_mut_for_test(&mut self, tid: u32) -> Option<&mut MockThread> {
        self.thread_mut(tid)
    }

    pub fn add_image(&mut self, image: LoadedImage) {
        self.images.push(image);
    }

    /// Append a verbatim JSON object to the `images` array of the
    /// `jGetLoadedDynamicLibrariesInfos` reply.
    ///
    /// Real stubs are not all shaped like [`LoadedImage`]: some omit
    /// `load_address` for an image they could not read, and some spell it as a
    /// hex string. A client must be tested against those replies, and they
    /// cannot be produced by a struct whose field is a plain `u64`.
    pub fn add_raw_image_json(&mut self, object: impl Into<String>) {
        self.raw_images.push(object.into());
    }

    pub fn set_target_xml(&mut self, xml: impl Into<String>) {
        self.target_xml = xml.into();
    }

    pub const fn set_faults(&mut self, faults: FaultInjection) {
        self.faults = faults;
    }

    #[must_use]
    pub const fn faults_mut(&mut self) -> &mut FaultInjection {
        &mut self.faults
    }

    #[must_use]
    pub fn threads(&self) -> &[MockThread] {
        &self.threads
    }

    /// Mutable access to the modelled threads.
    ///
    /// Exists so a test can stage register state the `g` block alone cannot
    /// carry (the 128-bit `v` file), exactly as a live target would present it.
    #[must_use]
    pub fn threads_mut(&mut self) -> &mut [MockThread] {
        &mut self.threads
    }

    #[must_use]
    pub fn thread(&self, tid: u32) -> Option<&MockThread> {
        self.threads.iter().find(|t| t.tid == tid)
    }

    fn thread_mut(&mut self, tid: u32) -> Option<&mut MockThread> {
        self.threads.iter_mut().find(|t| t.tid == tid)
    }

    #[must_use]
    pub fn breakpoints(&self) -> &[MockBreakpoint] {
        &self.breakpoints
    }

    /// `(accepted Z packets, accepted z packets)`, duplicates counted.
    #[must_use]
    pub const fn z_traffic(&self) -> (usize, usize) {
        (self.z_inserts, self.z_removes)
    }

    /// Reference count for `(addr, kind)`, or 0 when no trap is installed.
    #[must_use]
    pub fn breakpoint_refs(&self, addr: u64, kind: BpKind) -> u32 {
        self.breakpoints
            .iter()
            .find(|b| b.addr == addr && b.kind == kind)
            .map_or(0, |b| b.refs)
    }

    /// Program how many hardware slots the simulated core implements, so a
    /// client's exhaustion path is reachable from a test with two slots instead
    /// of needing six.
    pub const fn set_hw_slots(&mut self, breakpoints: usize, watchpoints: usize) {
        self.hw_breakpoint_slots = breakpoints;
        self.hw_watchpoint_slots = watchpoints;
    }

    /// Answer `Z0` with an empty reply, as a stub without server-managed
    /// software breakpoints would.
    /// Make the next resume report the target as KILLED BY `sig` (an `X` stop
    /// reply), rather than exited (`W`).
    pub const fn kill_with_signal(&mut self, sig: u8) {
        self.killed_by = Some(sig);
    }

    pub const fn refuse_software_breakpoints(&mut self) {
        self.refuse_z_software = true;
    }

    /// Accept `n` more `Z0` inserts, then answer every later one with `E22`.
    pub const fn refuse_software_breakpoints_after(&mut self, n: usize) {
        self.sw_inserts_before_refusing = Some(n);
    }

    /// Answer the next `n` software `Z0` inserts `OK` and refuse every later
    /// one, as a stub that ran out of trap slots between the first arm and a
    /// later re-arm does.
    pub const fn accept_software_breakpoints_then_refuse(&mut self, n: usize) {
        self.z_software_budget = Some(n);
    }

    /// Accept `Z` but answer every `z` with `E01`: the trap stays installed in
    /// the target and the stub says so.
    pub const fn refuse_breakpoint_removal(&mut self) {
        self.refuse_z_removals = true;
    }

    /// Accept `n` server-managed `Z0` inserts, then answer every later one with
    /// the empty reply that means "not supported / not honoured". Threshold
    /// rather than on/off because the interesting case needs BOTH: the first
    /// arm must succeed, so the client records a stub-managed trap with no
    /// saved bytes, and the RE-arm must be refused.
    pub const fn fail_software_breakpoint_inserts_after(&mut self, n: usize) {
        self.sw_inserts_before_failing = Some(n);
    }

    /// Refuse the `g` register-block read with `E09`, as a stub whose target
    /// has become unreadable would. Distinct from a bad register NAME, which is
    /// the thing the scripting layer used to blame every register failure on.
    pub const fn fail_register_reads_after(&mut self, n: usize) {
        self.reg_reads_before_failing = Some(n);
    }

    /// Let `n` memory writes through, then refuse every later one with `E09`,
    /// as a stub for a target that became unwritable (or died) would.
    ///
    /// Threshold rather than on/off because the interesting case needs BOTH:
    /// the patch must land, and the RESTORE must fail. Used to prove a failed
    /// restore leaves the breakpoint tracked rather than abandoning the patch.
    pub const fn fail_memory_writes_after(&mut self, n: usize) {
        self.writes_before_failing = Some(n);
    }

    /// Answer `m` with one byte less than was asked for, which the protocol
    /// permits for a partially readable region. Used to prove the client treats
    /// a shortfall as an error rather than as data.
    pub const fn short_read_memory(&mut self) {
        self.short_reads = true;
    }

    /// `(hw breakpoint slots, hw watchpoint slots)`.
    #[must_use]
    pub const fn hw_slots(&self) -> (usize, usize) {
        (self.hw_breakpoint_slots, self.hw_watchpoint_slots)
    }

    #[must_use]
    fn used_slots(&self, watch: bool) -> usize {
        self.breakpoints.iter().filter(|b| b.kind.is_watchpoint() == watch).count()
    }

    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    #[must_use]
    pub const fn no_ack_mode(&self) -> bool {
        self.no_ack_mode
    }

    // -- transport ----------------------------------------------------------

    /// Serve this mock on a freshly bound loopback TCP port, in a thread.
    ///
    /// Why a real socket when [`crate::ios::mock_client::LoopbackTransport`]
    /// already exists: the loopback transport computes the reply *inside*
    /// `send`, so the client is never actually blocked on a read and no second
    /// handle to the peer exists. Asynchronous interrupt delivery is therefore
    /// unrepresentable there — it needs a transport whose write end can be
    /// duplicated and whose reader really does park. A TCP socket is the
    /// smallest thing with both properties, and it is the same
    /// [`crate::ios::rsp::TcpTransport`] a real `debugserver` is reached
    /// through.
    ///
    /// The thread returns the mock so a test can assert on the final simulated
    /// state (including [`Self::packet_log`]).
    ///
    /// # Errors
    /// Propagates bind/`local_addr` failures.
    pub fn spawn_tcp(
        mut self,
    ) -> std::io::Result<(String, std::thread::JoinHandle<Self>)> {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?.to_string();
        let handle = std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let _ = sock.set_nodelay(true);
                let mut buf = [0u8; 4096];
                loop {
                    let n = match sock.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    match self.feed(&buf[..n]) {
                        // An empty reply is legitimate — `run_until_interrupt`
                        // answers a continue with silence — and must NOT be
                        // turned into a zero-length write or a disconnect.
                        Ok(reply) => {
                            if !reply.is_empty() && sock.write_all(&reply).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
            self
        });
        Ok((addr, handle))
    }

    /// Feed raw client bytes in, get raw server bytes out.
    ///
    /// This is the whole transport surface: it deliberately accepts arbitrary
    /// fragmentation (a byte at a time is fine) because that is exactly the
    /// case a single 64 KiB `read()` gets wrong.
    pub fn feed(&mut self, input: &[u8]) -> Result<Vec<u8>, MockError> {
        Ok(self.feed_chunked(input)?.concat())
    }

    /// Same as [`Self::feed`] but preserves the reply chunk boundaries produced
    /// by [`FaultInjection::chunk_size`].
    pub fn feed_chunked(&mut self, input: &[u8]) -> Result<Vec<Vec<u8>>, MockError> {
        if self.closed {
            return Err(MockError::ConnectionClosed);
        }
        self.inbound.extend_from_slice(input);
        let mut out: Vec<Vec<u8>> = Vec::new();

        while let Some(frame) = self.take_frame()? {
            match frame {
                Frame::Ack => {}
                Frame::Nack => {
                    // A real server re-emits its last framed reply byte for
                    // byte and does NOT re-execute the command. Without this
                    // the only client that makes progress after a damaged
                    // reply is one that re-issues the command — i.e. the mock
                    // rewards the very defect it is supposed to expose.
                    //
                    // But ONLY while acks are in use. After `QStartNoAckMode`
                    // the protocol has no acknowledgements at all and Apple's
                    // debugserver ignores a stray `-` completely. Answering it
                    // anyway would be this mock inventing a recovery the real
                    // target does not offer: a client that wrongly nacks in
                    // no-ack mode would be handed a valid reply here and would
                    // hang against a device. That is the opposite failure from
                    // the one above and just as damaging — a mock that makes
                    // green what the real stub makes broken.
                    self.nacks_received += 1;
                    if !self.no_ack_mode
                        && let Some(reply) = self.last_reply.clone()
                    {
                        self.retransmissions += 1;
                        out.push(reply);
                    }
                }
                Frame::Interrupt => {
                    // Ctrl-C: stop the current thread where it stands.
                    let tid = self.current_c_thread;
                    if let Some(t) = self.thread_mut(tid) {
                        t.stop = StopKind::Signal(2); // SIGINT
                    }
                    let reply = self.stop_reply(tid);
                    self.emit(&reply, false, &mut out)?;
                }
                Frame::Packet(payload) => {
                    if !self.no_ack_mode {
                        out.push(b"+".to_vec());
                    }
                    // The log is a human-readable trace, so it is allowed to be
                    // lossy; the dispatcher below is NOT and gets the raw bytes.
                    self.packet_log.push(String::from_utf8_lossy(&payload).to_string());
                    let (reply, no_reply) = self.dispatch_raw(&payload);
                    if !no_reply {
                        self.emit(&reply, true, &mut out)?;
                    }
                    if self.closed {
                        break;
                    }
                }
            }
        }
        Ok(out)
    }

    /// Wrap `payload`, apply fault injection, and append to `out`.
    fn emit(
        &mut self,
        payload: &str,
        count_it: bool,
        out: &mut Vec<Vec<u8>>,
    ) -> Result<(), MockError> {
        // Order matters and is easy to get backwards: escaping first, then RLE
        // over the *escaped* bytes. The other order escapes the `*` that RLE
        // just produced, so the receiver decodes a literal `*` and the run is
        // silently lost — which is exactly the bug the RLE test caught.
        let mut framed = if self.faults.use_rle {
            frame_escaped(&rle_encode_bytes(&escape(payload.as_bytes())))
        } else {
            encode_packet(payload)
        };
        // Remembered BEFORE fault injection: the stub emitted a well-formed
        // reply; the corruption is what the wire did to it.
        self.last_reply = Some(framed.clone());
        if self.faults.corrupt_checksum {
            self.faults.corrupt_checksum = false;
            if let Some(last) = framed.last_mut() {
                *last = if *last == b'0' { b'1' } else { b'0' };
            }
        }
        if self.faults.drop_bytes > 0 {
            let n = self.faults.drop_bytes.min(framed.len());
            self.faults.drop_bytes = 0;
            framed.drain(..n);
        }
        match self.faults.chunk_size {
            Some(n) if n > 0 => {
                for chunk in framed.chunks(n) {
                    out.push(chunk.to_vec());
                }
            }
            _ => out.push(framed),
        }
        if count_it {
            self.packets_answered += 1;
            if let Some(limit) = self.faults.close_after_n
                && self.packets_answered >= limit
            {
                self.closed = true;
            }
        }
        Ok(())
    }

    /// Pull one complete frame out of the inbound buffer, if there is one.
    fn take_frame(&mut self) -> Result<Option<Frame>, MockError> {
        loop {
            let Some(&first) = self.inbound.first() else {
                return Ok(None);
            };
            match first {
                b'+' => {
                    self.inbound.remove(0);
                    return Ok(Some(Frame::Ack));
                }
                b'-' => {
                    self.inbound.remove(0);
                    return Ok(Some(Frame::Nack));
                }
                0x03 => {
                    self.inbound.remove(0);
                    return Ok(Some(Frame::Interrupt));
                }
                b'$' => break,
                _ => {
                    // Garbage before a packet start: a real debugserver drops it.
                    self.inbound.remove(0);
                }
            }
        }
        // Need `$ ... # xx`.
        let Some(hash) = self.inbound.iter().position(|&b| b == b'#') else {
            return Ok(None);
        };
        if self.inbound.len() < hash + 3 {
            return Ok(None);
        }
        let body = self.inbound[1..hash].to_vec();
        let csum_hex = String::from_utf8_lossy(&self.inbound[hash + 1..hash + 3]).to_string();
        self.inbound.drain(..hash + 3);
        let got = hex_u8(&csum_hex)
            .ok_or(())
            .map_err(|()| MockError::Framing(format!("non-hex checksum {csum_hex:?}")))?;
        let expected = checksum(&body);
        if expected != got {
            return Err(MockError::BadChecksum { expected, got });
        }
        // The payload stays RAW. `X` carries binary memory contents, and any
        // byte that is not valid UTF-8 would be rewritten as U+FFFD (`EF BF
        // BD`) by a lossy String conversion here — the mock would then accept a
        // write no device would perform and hand back different bytes than the
        // client sent. Decoding to text is the individual handler's business.
        Ok(Some(Frame::Packet(unescape(&body))))
    }

    // -- command dispatch ---------------------------------------------------

    /// Byte-level entry point of the dispatcher.
    ///
    /// Exactly one packet — `X` — carries a payload that is not text, so it is
    /// routed here, before anything can decode the bytes as UTF-8. Every other
    /// packet is ASCII by construction and goes on to [`Self::dispatch`].
    fn dispatch_raw(&mut self, raw: &[u8]) -> (String, bool) {
        if let Some(rest) = raw.strip_prefix(b"X") {
            if self.target_is_gone() {
                return ("E09".to_string(), false);
            }
            return (self.handle_write_memory_bin(rest), false);
        }
        let pkt = String::from_utf8_lossy(raw).to_string();
        self.dispatch(&pkt)
    }

    /// Returns `(reply, suppress_reply)`.
    #[allow(clippy::too_many_lines)] // A protocol dispatcher is a flat table by nature.
    fn dispatch(&mut self, pkt: &str) -> (String, bool) {
        // Strip the `;thread:xx;` suffix once, centrally, so every handler below
        // sees a clean packet. Ignoring it per-handler is how thread-suffix
        // support silently becomes a lie.
        let (pkt, suffix_tid) = split_thread_suffix(pkt);
        // The suffix is an EXTENSION, and extensions are negotiated. Honouring
        // it before the client sent `QThreadSuffixSupported` lets a client that
        // never negotiates address threads correctly here and address the
        // current thread — silently, wrongly — on a real debugserver, which
        // never strips a suffix it was not told to expect.
        if suffix_tid.is_some() && !self.thread_suffix_supported {
            return ("E01".to_string(), false);
        }
        let target_tid = suffix_tid.unwrap_or(self.current_g_thread);

        // Once the inferior is gone its task port dies with it: on a real
        // device `mach_vm_read`/`mach_vm_write` and the thread-state calls all
        // fail, and debugserver answers `E`. Answering these positively lets a
        // client that missed the `W`/`X` reply keep "reading the target" and
        // look indistinguishable from a correct one.
        if self.target_is_gone() && packet_needs_live_target(pkt) {
            return ("E09".to_string(), false);
        }

        if pkt == "?" {
            return (self.stop_reply(self.current_c_thread), false);
        }
        if let Some(rest) = pkt.strip_prefix("qSupported") {
            let _ = rest;
            return (
                "PacketSize=4000;qXfer:features:read+;qXfer:libraries:read+;\
                 QStartNoAckMode+;QThreadSuffixSupported+;QListThreadsInStopReply+;\
                 qEcho+;hwbreak+;swbreak+"
                    .to_string(),
                false,
            );
        }
        if let Some(rest) = pkt.strip_prefix("QSetWorkingDir:") {
            if !self.launch_env_supported {
                return (String::new(), false);
            }
            return match decode_hex(rest).and_then(|b| String::from_utf8(b).ok()) {
                Some(dir) => {
                    self.launch_working_dir = Some(dir);
                    ("OK".to_string(), false)
                }
                None => ("E01".to_string(), false),
            };
        }
        if let Some(rest) = pkt.strip_prefix("QEnvironmentHexEncoded:") {
            if !self.launch_env_supported {
                return (String::new(), false);
            }
            return match decode_hex(rest).and_then(|b| String::from_utf8(b).ok()) {
                Some(kv) => {
                    self.launch_env.push(kv);
                    ("OK".to_string(), false)
                }
                None => ("E01".to_string(), false),
            };
        }
        if pkt == "QStartNoAckMode" {
            self.no_ack_mode = true;
            return ("OK".to_string(), false);
        }
        if pkt == "QThreadSuffixSupported" {
            self.thread_suffix_supported = true;
            return ("OK".to_string(), false);
        }
        if pkt == "QListThreadsInStopReply" {
            self.list_threads_in_stop_reply = true;
            return ("OK".to_string(), false);
        }
        if pkt == "qHostInfo" {
            // cputype 0x0100000C = CPU_TYPE_ARM64, subtype 2 = ARM64E.
            return (
                "cputype:16777228;cpusubtype:2;ostype:macosx;vendor:apple;\
                     endian:little;ptrsize:8;os_version:14.5.0;watchpoint_exceptions_received:after;".to_string(),
                false,
            );
        }
        if pkt == "qWatchpointSupportInfo" || pkt == "qWatchpointSupportInfo:" {
            return (format!("num:{:x};", self.hw_watchpoint_slots), false);
        }
        if pkt == "qHardwareBreakpointSupportInfo" {
            return (format!("num:{:x};", self.hw_breakpoint_slots), false);
        }
        if pkt == "qProcessInfo" {
            return (
                format!(
                    "pid:{:x};parent-pid:1;real-uid:1f5;real-gid:14;effective-uid:1f5;\
                     effective-gid:14;cputype:100000c;cpusubtype:2;ostype:macosx;\
                     vendor:apple;endian:little;ptrsize:8;",
                    self.pid
                ),
                false,
            );
        }
        if let Some(n) = pkt.strip_prefix("qRegisterInfo") {
            let idx = hex_usize(n).unwrap_or(usize::MAX);
            let table = register_info_table();
            return table
                .get(idx)
                .map_or_else(|| ("E45".to_string(), false), |ri| (ri.to_reply(), false));
        }
        if pkt == "qfThreadInfo" {
            let ids: Vec<String> = self.threads.iter().map(|t| format!("{:x}", t.tid)).collect();
            return (format!("m{}", ids.join(",")), false);
        }
        if pkt == "qsThreadInfo" {
            return ("l".to_string(), false);
        }
        if pkt == "qC" {
            return if self.multiprocess_ids {
                (format!("QCp{:x}.{:x}", self.pid, self.current_g_thread), false)
            } else {
                (format!("QC{:x}", self.current_g_thread), false)
            };
        }
        if let Some(rest) = pkt.strip_prefix("qThreadStopInfo") {
            let tid = hex_u32(rest).unwrap_or(0);
            return if self.thread(tid).is_some() {
                (self.stop_reply(tid), false)
            } else {
                ("E01".to_string(), false)
            };
        }
        if let Some(rest) = pkt.strip_prefix("qThreadExtraInfo,") {
            let tid = hex_u32(rest).unwrap_or(0);
            return self.thread(tid).map_or_else(
                || ("E01".to_string(), false),
                |t| (hex_encode(t.name.as_bytes()), false),
            );
        }
        if let Some(rest) = pkt.strip_prefix("qMemoryRegionInfo:") {
            return (self.memory_region_info(rest), false);
        }
        if pkt.starts_with("qXfer:") {
            return (self.handle_qxfer(pkt), false);
        }
        if pkt == "jThreadsInfo" {
            return if self.jthreads_info_supported {
                (self.threads_info_json(), false)
            } else {
                // Unsupported packets are answered with an empty payload, not
                // with an error — a client must tell those two apart.
                (String::new(), false)
            };
        }
        if pkt.starts_with("jGetLoadedDynamicLibrariesInfos") {
            return (self.loaded_libraries_json(), false);
        }
        if let Some(rest) = pkt.strip_prefix("qEcho:") {
            return (rest.to_string(), false);
        }
        if let Some(rest) = pkt.strip_prefix('H') {
            return (self.handle_h(rest), false);
        }
        if pkt == "g" {
            if let Some(remaining) = self.reg_reads_before_failing.as_mut() {
                if *remaining == 0 {
                    return ("E09".to_string(), false);
                }
                *remaining -= 1;
            }
            return self.thread(target_tid).map_or_else(
                || ("E01".to_string(), false),
                |t| (t.regs.encode_g(), false),
            );
        }
        if let Some(rest) = pkt.strip_prefix('G') {
            return match (Arm64Registers::decode_g(rest), self.thread_mut(target_tid)) {
                (Some(regs), Some(t)) => {
                    t.regs = regs;
                    ("OK".to_string(), false)
                }
                _ => ("E01".to_string(), false),
            };
        }
        if let Some(rest) = pkt.strip_prefix('p') {
            let idx = hex_usize(rest).unwrap_or(usize::MAX);
            let truncate = self.faults.truncate_p_to_bytes;
            return self
                .thread(target_tid)
                .and_then(|t| t.regs.read_indexed(idx))
                .map(|v| match truncate {
                    Some(n) if 2 * n < v.len() => v[..2 * n].to_string(),
                    _ => v,
                })
                .map_or_else(|| ("E01".to_string(), false), |v| (v, false));
        }
        if let Some(rest) = pkt.strip_prefix('P') {
            let Some((n, v)) = rest.split_once('=') else {
                return ("E01".to_string(), false);
            };
            let idx = hex_usize(n).unwrap_or(usize::MAX);
            let ok = self
                .thread_mut(target_tid)
                .is_some_and(|t| t.regs.write_indexed(idx, v));
            return (if ok { "OK" } else { "E01" }.to_string(), false);
        }
        if let Some(rest) = pkt.strip_prefix('m') {
            return (self.handle_read_memory(rest), false);
        }
        if let Some(rest) = pkt.strip_prefix('M') {
            return (self.handle_write_memory_hex(rest), false);
        }
        if pkt.starts_with('Z') || pkt.starts_with('z') {
            return (self.handle_breakpoint(pkt), false);
        }
        if pkt == "vCont?" {
            return ("vCont;c;C;s;S".to_string(), false);
        }
        // A resume that must not answer: the target runs until `\x03`. Stepping
        // is excluded on purpose — a single step always terminates, so leaving
        // it silent would model no real stub.
        if self.run_until_interrupt
            && (pkt == "c" || pkt.starts_with("vCont;c") || pkt.starts_with("vCont;C"))
        {
            return (String::new(), true);
        }
        if let Some(rest) = pkt.strip_prefix("vCont") {
            return (self.handle_vcont(rest), false);
        }
        if pkt == "c" {
            return (self.resume(self.current_c_thread, false), false);
        }
        if pkt == "s" {
            return (self.resume(self.current_c_thread, true), false);
        }
        if let Some(rest) = pkt.strip_prefix("vAttach;") {
            let pid = hex_u32(rest).unwrap_or(0);
            if pid == self.pid {
                return (self.stop_reply(self.current_c_thread), false);
            }
            // ESRCH: this stub holds exactly one process, so a pid it does not
            // have really is a pid that does not exist. It used to answer E01
            // (EPERM), which on a real device means the OPPOSITE — the process
            // is there and task_for_pid was refused, which is now a different
            // DebugError (`attach_reply_error`).
            return ("E03".to_string(), false);
        }
        if pkt.starts_with("vKill") || pkt == "k" {
            self.closed = true;
            self.exit_code = Some(9);
            return ("OK".to_string(), pkt == "k");
        }
        if pkt == "D" {
            self.closed = true;
            return ("OK".to_string(), false);
        }
        if let Some(rest) = pkt.strip_prefix("_M") {
            return (self.handle_alloc(rest), false);
        }
        if let Some(rest) = pkt.strip_prefix("_m") {
            let addr = hex_u64(rest).unwrap_or(0);
            return (
                if self.allocations.remove(&addr).is_some() { "OK" } else { "E01" }.to_string(),
                false,
            );
        }
        if let Some(rest) = pkt.strip_prefix('A') {
            return (validate_a_packet(rest), false);
        }
        // Unknown packet: the empty reply is the protocol's "unsupported".
        (String::new(), false)
    }

    fn handle_h(&mut self, rest: &str) -> String {
        let Some(op) = rest.chars().next() else {
            return "E01".to_string();
        };
        let id = &rest[op.len_utf8()..];
        let tid = if id == "-1" || id == "0" {
            self.threads.first().map_or(0, |t| t.tid)
        } else {
            hex_u32(id.trim_start_matches('p')).unwrap_or(0)
        };
        if self.thread(tid).is_none() {
            return "E01".to_string();
        }
        match op {
            'g' => {
                self.current_g_thread = tid;
                "OK".to_string()
            }
            'c' => {
                self.current_c_thread = tid;
                "OK".to_string()
            }
            _ => "E01".to_string(),
        }
    }

    fn handle_read_memory(&self, rest: &str) -> String {
        let Some((a, l)) = rest.split_once(',') else {
            return "E01".to_string();
        };
        let (Some(addr), Some(len)) = (hex_u64(a), hex_usize(l)) else {
            return "E01".to_string();
        };
        let effective = if self.short_reads { len.saturating_sub(1) } else { len };
        self.memory
            .read(addr, effective)
            .map_or_else(|| "E09".to_string(), |b| hex_encode(&b))
    }

    fn handle_write_memory_hex(&mut self, rest: &str) -> String {
        let Some((head, data)) = rest.split_once(':') else {
            return "E01".to_string();
        };
        let Some((a, l)) = head.split_once(',') else {
            return "E01".to_string();
        };
        let (Some(addr), Some(declared), Some(bytes)) =
            (hex_u64(a), hex_usize(l), decode_hex(data))
        else {
            return "E01".to_string();
        };
        // `M addr,len:` states how many bytes follow. A payload of any other
        // length is a malformed packet, not a shorter write: accepting it hides
        // a client that miscomputes either the length or the hex body, and the
        // device would reject it.
        if bytes.len() != declared {
            return "E01".to_string();
        }
        if let Some(remaining) = self.writes_before_failing.as_mut() {
            if *remaining == 0 {
                return "E09".to_string();
            }
            *remaining -= 1;
        }
        if self.memory.write(addr, &bytes) { "OK".to_string() } else { "E09".to_string() }
    }

    /// `X addr,len:<raw bytes>` — the header is ASCII, the payload is not.
    fn handle_write_memory_bin(&mut self, rest: &[u8]) -> String {
        let Some(colon) = rest.iter().position(|&b| b == b':') else {
            return "E01".to_string();
        };
        // Only the header may be decoded as text; the data after the colon is
        // arbitrary target memory and is written through byte for byte.
        let Ok(head) = std::str::from_utf8(&rest[..colon]) else {
            return "E01".to_string();
        };
        let data = &rest[colon + 1..];
        let Some((a, l)) = head.split_once(',') else {
            return "E01".to_string();
        };
        let (Some(addr), Ok(declared)) = (hex_u64(a), usize::from_str_radix(l, 16)) else {
            return "E01".to_string();
        };
        // `X` carries the same `addr,len:` contract as `M`; only the payload
        // encoding differs. debugserver consumes exactly `len` bytes, so a
        // payload of any other length is a malformed packet, not a short write.
        if data.len() != declared {
            return "E01".to_string();
        }
        // The payload arrived already unescaped by the framer.
        if data.is_empty() {
            // `X addr,0:` is the probe for binary-write support.
            return "OK".to_string();
        }
        // An unwritable target is unwritable through BOTH encodings: `M` and
        // `X` differ only in how the payload is spelled and debugserver funnels
        // both into the same `mach_vm_write`. Gating only `M` would make the
        // injected fault a property of the packet the client happens to choose.
        // The zero-length probe above is exempt on purpose: it writes nothing.
        if let Some(remaining) = self.writes_before_failing.as_mut() {
            if *remaining == 0 {
                return "E09".to_string();
            }
            *remaining -= 1;
        }
        if self.memory.write(addr, data) { "OK".to_string() } else { "E09".to_string() }
    }

    fn handle_breakpoint(&mut self, pkt: &str) -> String {
        let insert = pkt.starts_with('Z');
        let body = &pkt[1..];
        let parts: Vec<&str> = body.split(',').collect();
        if parts.len() < 3 {
            return "E01".to_string();
        }
        let (Some(code), Some(addr), Some(len)) = (
            dec_u8(parts[0]),
            hex_u64(parts[1]),
            hex_u64(parts[2]),
        ) else {
            return "E01".to_string();
        };
        let Some(kind) = BpKind::from_code(code) else {
            return String::new(); // unsupported kind -> empty reply
        };
        if self.refuse_z_software && kind == BpKind::Software {
            return String::new();
        }
        if insert && kind == BpKind::Software && let Some(left) = self.sw_inserts_before_refusing.as_mut() {
            if *left == 0 {
                return "E22".to_string();
            }
            *left -= 1;
        }
        if insert && kind == BpKind::Software && let Some(left) = self.z_software_budget.as_mut() {
            if *left == 0 {
                return String::new();
            }
            *left -= 1;
        }
        if insert && kind == BpKind::Software && let Some(left) = self.sw_inserts_before_failing.as_mut() {
            if *left == 0 {
                return String::new();
            }
            *left -= 1;
        }
        if self.refuse_z_removals && !insert {
            return "E01".to_string();
        }
        if insert {
            // Geometry is a property of the REQUEST, so it is checked before
            // anything else — before the refcount fast path especially. An
            // unencodable request that happens to share an address with an
            // installed trap must not be waved through as a duplicate: that
            // path also ignores `len`, so `Z2,4000,1000` would be answered `OK`
            // and silently refcount an 8-byte watchpoint. `arm64::hw` owns the
            // rule (4-byte aligned DBGBVR for an instruction breakpoint; a
            // 1/2/4/8-byte naturally aligned range inside one 8-byte DBGWCR
            // granule for a watchpoint). Answering OK to anything else models a
            // stub that installs a watchpoint the hardware cannot express, and
            // hides from every client the splitting it must do to cover a wider
            // or misaligned range.
            let encodable = match kind {
                BpKind::Software => true,
                BpKind::Hardware => {
                    arm64::hw::breakpoint(addr, arm64::hw::PrivilegeControl::El0).is_ok()
                }
                _ => usize::try_from(len)
                    .is_ok_and(|size| arm64::hw::watchpoint_bas(addr, size).is_ok()),
            };
            if !encodable {
                return "E09".to_string();
            }
            if let Some(existing) =
                self.breakpoints.iter_mut().find(|b| b.addr == addr && b.kind == kind)
            {
                // Real debugserver refcounts; it does not silently drop the
                // duplicate. The trap now needs two `z` packets to clear.
                existing.refs = existing.refs.saturating_add(1);
                self.z_inserts += 1;
                return "OK".to_string();
            }
            // Software breakpoints are patched into memory and so are unlimited;
            // the other four kinds consume a finite debug-register slot. Running
            // out is reported as an error, never as a silently ignored request.
            if kind == BpKind::Hardware && self.used_slots(false) >= self.hw_breakpoint_slots {
                return "E53".to_string();
            }
            if kind.is_watchpoint() && self.used_slots(true) >= self.hw_watchpoint_slots {
                return "E54".to_string();
            }
            self.breakpoints.push(MockBreakpoint { addr, kind, len, refs: 1 });
            self.z_inserts += 1;
        } else {
            if let Some(existing) =
                self.breakpoints.iter_mut().find(|b| b.addr == addr && b.kind == kind)
            {
                existing.refs = existing.refs.saturating_sub(1);
            }
            // Only a count that reached zero uninstalls the trap.
            self.breakpoints.retain(|b| b.refs > 0);
            self.z_removes += 1;
        }
        "OK".to_string()
    }

    fn handle_vcont(&mut self, rest: &str) -> String {
        // `;c`, `;s:tid`, `;C05`, `;s:1;c`, `;c:2`
        let mut step_tid: Option<u32> = None;
        let mut cont = false;
        // A `c`/`C` action may name its thread exactly like `s` does. Dropping
        // that tid and resuming the current thread instead is invisible in a
        // single-threaded test and wrong on every multi-threaded one.
        let mut cont_tid: Option<u32> = None;
        // `C`/`S` mean "resume DELIVERING signal N to the inferior" — that is
        // the entire difference from `c`/`s`, and `vCont?` advertises both. The
        // hex digits after the verb ARE the signal and are not optional:
        // dropping them makes `C` a synonym for `c`, so a client that forwards
        // SIGSEGV/SIGUSR1 is confirmed working here and silently swallows it
        // against a debugserver that actually delivers it.
        let mut signal: Option<u8> = None;
        for action in rest.split(';').filter(|s| !s.is_empty()) {
            let (verb, tid) = match action.split_once(':') {
                Some((v, t)) => (v, hex_u32(t)),
                None => (action, None),
            };
            let Some(op) = verb.chars().next() else {
                continue;
            };
            let arg = &verb[op.len_utf8()..];
            match op {
                's' | 'S' | 'c' | 'C' => {
                    if op.is_ascii_uppercase() {
                        // A missing or non-hex signal is a malformed action, not
                        // an excuse to resume unsignalled.
                        let Some(sig) = hex_u8(arg) else {
                            return "E01".to_string();
                        };
                        // Signal 0 is the spelling for "no signal".
                        if sig != 0 && signal.is_none() {
                            signal = Some(sig);
                        }
                    } else if !arg.is_empty() {
                        // Lowercase `c`/`s` carry no argument at all.
                        return "E01".to_string();
                    }
                    if op == 's' || op == 'S' {
                        step_tid = tid.or(Some(self.current_c_thread));
                    } else {
                        cont = true;
                        // First matching action wins, as in the vCont spec.
                        if cont_tid.is_none() {
                            cont_tid = tid;
                        }
                    }
                }
                _ => {}
            }
        }
        let (tid, single_step) = if let Some(tid) = step_tid {
            (tid, true)
        } else if cont {
            (cont_tid.unwrap_or(self.current_c_thread), false)
        } else {
            return "E01".to_string();
        };
        if let Some(sig) = signal {
            return self.deliver_signal(tid, sig);
        }
        self.resume(tid, single_step)
    }

    /// Forward a signal named by `vCont;C<sig>` / `vCont;S<sig>` to the thread.
    ///
    /// The mock's interpreter installs no signal handlers, so a delivered
    /// signal stops the thread and is reported as `T<sig>` — which is what
    /// debugserver reports once the inferior takes it. The alternative, running
    /// the thread as if nothing had been delivered, is precisely the defect
    /// this models away.
    fn deliver_signal(&mut self, tid: u32, sig: u8) -> String {
        if self.thread(tid).is_none() {
            return "E01".to_string();
        }
        if let Some(t) = self.thread_mut(tid) {
            t.stop = StopKind::Signal(sig);
        }
        self.stop_reply(tid)
    }

    fn handle_alloc(&mut self, rest: &str) -> String {
        let Some((size_hex, perms_str)) = rest.split_once(',') else {
            return "E01".to_string();
        };
        // The protection the client asked for is the protection it gets. Always
        // mapping `rw` means a client that allocates `rx` and then writes there
        // succeeds in-process and takes EXC_BAD_ACCESS on a device — and an
        // unparseable request is an error, not an excuse to pick a default.
        let Some(perms) = parse_alloc_perms(perms_str) else {
            return "E01".to_string();
        };
        let Some(size) = hex_u64(size_hex) else {
            return "E01".to_string();
        };
        // The size field is untrusted 64-bit input. `mach_vm_allocate` fails
        // for a request the kernel cannot satisfy and debugserver answers `E`;
        // there is no size at which it aborts. Building `vec![0; len]` eagerly
        // would abort this process instead (or panic with "capacity overflow"),
        // so the client bug that produced the bad size could never be observed.
        // Reject above a cap far larger than anything the simulated address
        // space holds, and never attempt the allocation.
        let Ok(len) = usize::try_from(size) else {
            return "E01".to_string();
        };
        if len > MAX_ALLOC_BYTES {
            return "E01".to_string();
        }
        let base = self.next_alloc;
        if !self.memory.map(MemoryRegion::zeroed(base, len, perms, "_M")) {
            return "E01".to_string();
        }
        // Page-align the next handout so consecutive allocations never abut in
        // a way that hides an off-by-one in the client.
        self.next_alloc = base
            .saturating_add((size.saturating_add(0xFFF)) & !0xFFF)
            .saturating_add(0x1000);
        self.allocations.insert(base, size);
        format!("{base:x}")
    }

    fn memory_region_info(&self, addr_hex: &str) -> String {
        let Some(addr) = hex_u64(addr_hex) else {
            return "E01".to_string();
        };
        self.memory.region_at(addr).map_or_else(
            || "error:address is not in a mapped region".to_string(),
            |r| {
                format!(
                    "start:{:x};size:{:x};permissions:{};name:{};",
                    r.base,
                    r.data.len(),
                    r.perms.to_reply(),
                    hex_encode(r.name.as_bytes())
                )
            },
        )
    }

    fn handle_qxfer(&self, pkt: &str) -> String {
        // qXfer:<object>:read:<annex>:<off>,<len>
        // ["qXfer", object, "read", annex, "<off>,<len>"] — the annex is empty
        // for objects like `libraries`, which is why the split must be indexed
        // positionally rather than by counting non-empty fields.
        let parts: Vec<&str> = pkt.split(':').collect();
        if parts.len() < 5 || parts[2] != "read" {
            return "E00".to_string();
        }
        // The annex names WHICH document is wanted, and it is part of the
        // contract: `features` is only defined for `target.xml`, and
        // `libraries` takes no annex at all. Serving any annex means a client
        // that sends the wrong one — or omits it, which shifts every following
        // field one place left — passes every test here and is answered `E00`
        // by the device on its very first descriptor fetch.
        let annex = parts[3];
        // The two failures are NOT the same reply. `E00` is reserved for a
        // malformed request or an invalid annex on an object the stub serves;
        // an object the stub does not serve at all gets the EMPTY reply, the
        // same "unsupported" spelling `jThreadsInfo` uses above. A client
        // probing for an optional object keys its fallback on that difference,
        // so collapsing them makes the probe a hard failure here and a clean
        // capability miss on the device.
        let payload = match parts[1] {
            "features" => {
                if annex != "target.xml" {
                    return "E00".to_string();
                }
                self.target_xml.clone()
            }
            "libraries" => {
                if !annex.is_empty() {
                    return "E00".to_string();
                }
                self.libraries_xml()
            }
            _ => return String::new(),
        };
        let Some((off_s, len_s)) = parts[4].split_once(',') else {
            return "E00".to_string();
        };
        let (Some(off), Some(len)) = (hex_usize(off_s), hex_usize(len_s))
        else {
            return "E00".to_string();
        };
        let bytes = payload.as_bytes();
        if off >= bytes.len() {
            return "l".to_string();
        }
        // `off` and `len` are hex fields under the requester's control, and in
        // release the overflow checks are OFF: `off + len` WRAPS rather than
        // trapping, so `1,ffffffffffffffff` produced end = 0 and the slice
        // `bytes[1..0]` — a panic, and with `panic = "abort"` the death of the
        // process, reachable from the loopback socket `spawn_tcp` opens. A sum
        // that does not exist is a THIRD state, distinct from a length that is
        // merely larger than the payload: refuse it, rather than `saturating_add`
        // inventing an end the client never asked for.
        let Some(end_requested) = off.checked_add(len) else {
            return "E00".to_string();
        };
        let end = end_requested.min(bytes.len());
        let chunk = String::from_utf8_lossy(&bytes[off..end]).to_string();
        // `m` = more follows, `l` = last chunk. Getting this backwards is the
        // classic qXfer bug, so the mock is strict about it.
        if end < bytes.len() { format!("m{chunk}") } else { format!("l{chunk}") }
    }

    fn libraries_xml(&self) -> String {
        let mut s = String::from("<library-list>");
        for img in &self.images {
            let _ = write!(
                s,
                "<library name=\"{}\"><segment address=\"0x{:x}\"/></library>",
                img.path, img.load_address
            );
        }
        s.push_str("</library-list>");
        s
    }

    /// The `jThreadsInfo` reply: every thread with its stop reason and a
    /// register snapshot, keyed by the same `qRegisterInfo` index the `p`
    /// packet uses.
    fn threads_info_json(&self) -> String {
        let mut s = String::from("[");
        for (i, t) in self.threads.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(s, "{{\"tid\":{}", t.tid);
            let _ = write!(s, ",\"name\":\"{}\"", json_escape(&t.name));
            if let Some(q) = &t.queue {
                let _ = write!(s, ",\"queue\":\"{}\"", json_escape(q));
            }
            let _ = write!(s, ",\"reason\":\"{}\"", t.reason_str());
            match &t.stop {
                StopKind::Signal(sig) => {
                    let _ = write!(s, ",\"signo\":{sig}");
                }
                StopKind::Breakpoint(_) | StopKind::Brk(_) => {
                    // EXC_BREAKPOINT / EXC_ARM_BREAKPOINT, as in the T packet.
                    let _ = write!(s, ",\"metype\":6,\"medata\":[1,{}]", t.regs.pc);
                }
                StopKind::Watchpoint { addr, .. } => {
                    let _ = write!(s, ",\"metype\":6,\"medata\":[0,{addr}]");
                }
                StopKind::Step | StopKind::Attached | StopKind::Exited(_) => {}
            }
            s.push_str(",\"registers\":{");
            for (n, value) in t.regs.x.iter().enumerate() {
                if n > 0 {
                    s.push(',');
                }
                let _ = write!(s, "\"{n}\":\"{}\"", hex_le_u64(*value));
            }
            let _ = write!(s, ",\"31\":\"{}\"", hex_le_u64(t.regs.sp));
            let _ = write!(s, ",\"32\":\"{}\"", hex_le_u64(t.regs.pc));
            s.push_str("}}");
        }
        s.push(']');
        s
    }

    fn loaded_libraries_json(&self) -> String {
        // Hand-emitted rather than via serde_json: the shape is fixed and this
        // keeps the mock free of a dependency the rest of the crate may not want.
        let mut s = String::from("{\"images\":[");
        for (i, img) in self.images.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let uuid: String = img.uuid.iter().map(|b| format!("{b:02X}")).collect();
            let _ = write!(
                s,
                "{{\"load_address\":{},\"pathname\":\"{}\",\"uuid\":\"{}\",\
                 \"mach_header\":{{\"magic\":4277009103,\"cputype\":16777228,\
                 \"cpusubtype\":2,\"filetype\":6}},\"slide\":{}}}",
                img.load_address, img.path, uuid, img.slide
            );
        }
        for (i, raw) in self.raw_images.iter().enumerate() {
            if !self.images.is_empty() || i > 0 {
                s.push(',');
            }
            s.push_str(raw);
        }
        s.push_str("]}");
        s
    }

    // -- execution ----------------------------------------------------------

    /// Build the `T`/`W` stop reply for `tid`.
    /// The inferior has exited; nothing about it can be read or written any
    /// more. `killed_by` is NOT part of this test: it is armed BEFORE the
    /// resume that reports the death, so it says "will die", not "is dead".
    const fn target_is_gone(&self) -> bool {
        self.exit_code.is_some() || self.death_reported
    }

    fn stop_reply(&self, tid: u32) -> String {
        if let Some(sig) = self.killed_by
            && self.death_reported
        {
            return format!("X{sig:02x}");
        }
        if let Some(code) = self.exit_code {
            return format!("W{code:02x}");
        }
        let Some(t) = self.thread(tid) else {
            return "E01".to_string();
        };
        if let StopKind::Exited(code) = t.stop {
            return format!("W{code:02x}");
        }
        let sig = t.stop.signal();
        let mut s = if self.omit_stop_reply_thread {
            format!("T{sig:02x}")
        } else {
            format!("T{sig:02x}thread:{:x};", t.tid)
        };
        let _ = write!(s, "name:{};", t.name);
        if self.list_threads_in_stop_reply {
            let ids: Vec<String> = self.threads.iter().map(|t| format!("{:x}", t.tid)).collect();
            let _ = write!(s, "threads:{};", ids.join(","));
        }
        // Expedited registers, keyed by qRegisterInfo index — the same indices
        // `p` uses, so a client can reuse one decoder for both.
        let _ = write!(s, "1d:{};", hex_le_u64(t.regs.x[29]));
        let _ = write!(s, "1e:{};", hex_le_u64(t.regs.x[30]));
        let _ = write!(s, "1f:{};", hex_le_u64(t.regs.sp));
        let _ = write!(s, "20:{};", hex_le_u64(t.regs.pc));
        match &t.stop {
            StopKind::Breakpoint(_) | StopKind::Brk(_) => {
                // metype 6 = EXC_BREAKPOINT, medata 1 = EXC_ARM_BREAKPOINT.
                let _ = write!(s, "metype:6;mecount:2;medata:1;medata:{:x};", t.regs.pc);
                s.push_str("reason:breakpoint;");
            }
            StopKind::Watchpoint { addr, kind, write } => {
                let _ = write!(s, "metype:6;mecount:2;medata:0;medata:{addr:x};");
                if let Some(key) = kind.stop_key() {
                    let _ = write!(s, "{key}:{addr:x};");
                }
                let _ = write!(
                    s,
                    "reason:watchpoint;description:{};",
                    hex_encode(
                        format!("{} at {addr:#x}", if *write { "write" } else { "read" }).as_bytes()
                    )
                );
            }
            StopKind::Step => s.push_str("reason:trace;"),
            StopKind::Signal(n) => {
                let _ = write!(s, "metype:2;mecount:1;medata:{n:x};reason:signal;");
            }
            StopKind::Attached | StopKind::Exited(_) => {}
        }
        s
    }

    /// Run `tid` until it hits a breakpoint, executes a `BRK`, exits, or burns
    /// through `max_steps_per_continue`. Returns the stop reply.
    fn resume(&mut self, tid: u32, single_step: bool) -> String {
        if self.thread(tid).is_none() {
            return "E01".to_string();
        }
        // The armed signal death happens HERE — the resume is what reports it —
        // and from this reply on the target is gone: its task port is dead, so
        // every later read/write/arm must fail exactly as it does after a `W`.
        if let Some(sig) = self.killed_by {
            self.death_reported = true;
            return format!("X{sig:02x}");
        }
        let limit = if single_step { 1 } else { self.max_steps_per_continue };
        // Watchpoints are evaluated from the accesses the emulated instruction
        // actually performed, so recording is only on while the target runs.
        let watching = self.breakpoints.iter().any(|b| b.kind.is_watchpoint());
        if watching {
            self.memory.set_recording(true);
        }
        for stepped in 0..limit {
            let outcome = self.step_one(tid);
            if watching && let Some(hit) = self.check_watchpoints() {
                // `watchpoint_exceptions_received:after` (see `qHostInfo`): the
                // access has completed and PC has moved past the instruction.
                self.memory.set_recording(false);
                if let Some(t) = self.thread_mut(tid) {
                    t.stop = hit;
                }
                return self.stop_reply(tid);
            }
            match outcome {
                // `Unknown` is converted to `Ran` by `step_one`, which owns the
                // decision to skip and count it.
                StepOutcome::Ran | StepOutcome::Unknown => {
                    // A breakpoint traps *before* the instruction at its address
                    // executes, so the check happens after PC has moved.
                    let pc = self.thread(tid).map_or(0, |t| t.regs.pc);
                    if !single_step
                        && self
                            .breakpoints
                            .iter()
                            .any(|b| !b.kind.is_watchpoint() && b.addr == pc)
                    {
                        self.memory.set_recording(false);
                        if let Some(t) = self.thread_mut(tid) {
                            t.stop = StopKind::Breakpoint(pc);
                        }
                        return self.stop_reply(tid);
                    }
                    if single_step && stepped + 1 == limit
                        && let Some(t) = self.thread_mut(tid)
                    {
                        t.stop = StopKind::Step;
                    }
                }
                StepOutcome::Brk(addr) => {
                    self.memory.set_recording(false);
                    if let Some(t) = self.thread_mut(tid) {
                        t.stop = StopKind::Brk(addr);
                    }
                    return self.stop_reply(tid);
                }
                StepOutcome::Exited(code) => {
                    self.memory.set_recording(false);
                    if let Some(t) = self.thread_mut(tid) {
                        t.stop = StopKind::Exited(code);
                        t.exited = true;
                    }
                    if self.threads.iter().all(|t| t.exited) {
                        self.exit_code = Some(code);
                    }
                    return self.stop_reply(tid);
                }
                StepOutcome::Fault => {
                    self.memory.set_recording(false);
                    if let Some(t) = self.thread_mut(tid) {
                        t.stop = StopKind::Signal(11); // SIGSEGV
                    }
                    return self.stop_reply(tid);
                }
            }
        }
        if !single_step {
            // Ran out of budget: report it as a signal rather than pretending a
            // breakpoint was hit. Silence here would look like a hang.
            if let Some(t) = self.thread_mut(tid) {
                t.stop = StopKind::Signal(24); // SIGXCPU
            }
        }
        self.stop_reply(tid)
    }

    /// Match the accesses performed by the instruction just executed against
    /// the registered watchpoints. Returns the stop to record, if any.
    ///
    /// The recorded accesses are drained whether or not one matched, so a later
    /// instruction can never be blamed for an earlier one's access.
    fn check_watchpoints(&mut self) -> Option<StopKind> {
        let accesses = self.memory.take_accesses();
        if accesses.is_empty() {
            return None;
        }
        for acc in &accesses {
            for wp in &self.breakpoints {
                if !wp.kind.is_watchpoint() || !wp.kind.fires_on(acc.write) {
                    continue;
                }
                // A zero-length watchpoint watches nothing; treat it as one byte
                // rather than as "matches everything".
                let len = usize::try_from(wp.len.max(1)).unwrap_or(usize::MAX);
                if acc.overlaps(wp.addr, len) {
                    return Some(StopKind::Watchpoint {
                        addr: wp.addr,
                        kind: wp.kind,
                        write: acc.write,
                    });
                }
            }
        }
        None
    }

    /// Execute exactly one instruction on `tid`.
    fn step_one(&mut self, tid: u32) -> StepOutcome {
        let Some(t) = self.thread(tid) else {
            return StepOutcome::Fault;
        };
        let pc = t.regs.pc;
        let Some(insn) = self.memory.read_untracked(pc, 4).map(|b| read_u32_le(&b)) else {
            return StepOutcome::Fault;
        };
        let mut regs = t.regs.clone();
        let mut outcome = Arm64Interp::step(insn, &mut regs, &mut self.memory);
        if outcome == StepOutcome::Unknown {
            // Unrecognised encoding: advance and *count* it (see module docs).
            // This is a distinct outcome rather than "PC did not move", because
            // `b .` is a legitimate self-branch that would otherwise be
            // misdiagnosed as garbage — and silently skipped.
            self.unknown_insn_count += 1;
            regs.pc = pc.wrapping_add(4);
            outcome = StepOutcome::Ran;
        }
        if let Some(t) = self.thread_mut(tid) {
            t.regs = regs;
        }
        outcome
    }
}

enum Frame {
    /// One unescaped packet payload, as RAW BYTES: `X` is binary and must not
    /// be forced through UTF-8 on the way in.
    Packet(Vec<u8>),
    Ack,
    Nack,
    Interrupt,
}

/// Result of executing one instruction.
#[derive(Debug, PartialEq, Eq)]
pub enum StepOutcome {
    /// PC advanced (or branched) normally.
    Ran,
    /// A `BRK` executed at this address.
    Brk(u64),
    /// Returned past the outermost frame.
    Exited(u8),
    /// Unmapped access.
    Fault,
    /// The encoding is not one of the eight the interpreter knows.
    Unknown,
}

// ---------------------------------------------------------------------------
// Tiny ARM64 interpreter
// ---------------------------------------------------------------------------

/// The eight-encoding ARM64 interpreter that gives the mock real control flow.
pub struct Arm64Interp;

impl Arm64Interp {
    /// `ret` (`ret x30`).
    pub const RET: u32 = 0xD65F_03C0;
    /// `nop`.
    pub const NOP: u32 = 0xD503_201F;
    /// `stp x29, x30, [sp, #-16]!`.
    pub const STP_FP_LR_PRE: u32 = 0xA9BF_7BFD;
    /// `mov x29, sp`.
    pub const MOV_FP_SP: u32 = 0x9100_03FD;
    /// `ldp x29, x30, [sp], #16`.
    pub const LDP_FP_LR_POST: u32 = 0xA8C1_7BFD;

    /// `bl <pc-relative>` for a byte displacement.
    #[must_use]
    pub const fn bl(disp_bytes: i32) -> u32 {
        0x9400_0000 | (((disp_bytes >> 2) as u32) & 0x03FF_FFFF)
    }

    /// `b <pc-relative>` for a byte displacement.
    #[must_use]
    pub const fn b(disp_bytes: i32) -> u32 {
        0x1400_0000 | (((disp_bytes >> 2) as u32) & 0x03FF_FFFF)
    }

    /// `brk #imm16`.
    #[must_use]
    pub const fn brk(imm: u16) -> u32 {
        0xD420_0000 | ((imm as u32) << 5)
    }

    /// `cbz Xt, <pc-relative>` for a byte displacement.
    ///
    /// The interpreter needs one conditional branch to be able to run a
    /// terminating recursion, which is the only shape that can exercise a
    /// return-site trap being hit in a DEEPER frame than the one the user
    /// stepped from.
    #[must_use]
    pub const fn cbz(rt: u32, disp_bytes: i32) -> u32 {
        0xB400_0000 | ((((disp_bytes >> 2) as u32) & 0x7_FFFF) << 5) | (rt & 0x1F)
    }

    /// `sub Xd, Xn, #imm12` (no shift).
    #[must_use]
    pub const fn sub_imm(rd: u32, rn: u32, imm: u16) -> u32 {
        0xD100_0000 | ((imm as u32 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)
    }

    /// `movz xD, #imm16` (no shift).
    #[must_use]
    pub const fn movz(rd: u32, imm: u16) -> u32 {
        0xD280_0000 | ((imm as u32) << 5) | (rd & 0x1F)
    }

    /// Execute one instruction against `regs`/`mem`.
    pub fn step(insn: u32, regs: &mut Arm64Registers, mem: &mut MemorySpace) -> StepOutcome {
        let pc = regs.pc;
        // BRK: check the family before the exact constants so any immediate works.
        if insn & 0xFFE0_001F == 0xD420_0000 {
            return StepOutcome::Brk(pc);
        }
        match insn {
            Self::NOP => {
                regs.pc = pc.wrapping_add(4);
                return StepOutcome::Ran;
            }
            Self::RET => {
                let lr = regs.x[30];
                if lr == 0 {
                    // Returning with a null link register means we ran off the
                    // outermost frame: that is process exit, using x0 as status.
                    return StepOutcome::Exited((regs.x[0] & 0xFF) as u8);
                }
                regs.pc = lr;
                return StepOutcome::Ran;
            }
            Self::STP_FP_LR_PRE => {
                let new_sp = regs.sp.wrapping_sub(16);
                if !mem.write_u64(new_sp, regs.x[29]) || !mem.write_u64(new_sp + 8, regs.x[30]) {
                    return StepOutcome::Fault;
                }
                regs.sp = new_sp;
                regs.pc = pc.wrapping_add(4);
                return StepOutcome::Ran;
            }
            Self::MOV_FP_SP => {
                regs.x[29] = regs.sp;
                regs.pc = pc.wrapping_add(4);
                return StepOutcome::Ran;
            }
            Self::LDP_FP_LR_POST => {
                let (Some(fp), Some(lr)) = (mem.read_u64(regs.sp), mem.read_u64(regs.sp + 8)) else {
                    return StepOutcome::Fault;
                };
                regs.x[29] = fp;
                regs.x[30] = lr;
                regs.sp = regs.sp.wrapping_add(16);
                regs.pc = pc.wrapping_add(4);
                return StepOutcome::Ran;
            }
            _ => {}
        }
        // bl / b: 26-bit signed word displacement.
        if insn & 0xFC00_0000 == 0x9400_0000 || insn & 0xFC00_0000 == 0x1400_0000 {
            let imm26 = insn & 0x03FF_FFFF;
            // Sign-extend 26 bits, then scale by 4.
            let signed = ((imm26 as i32) << 6) >> 6;
            let target = pc.wrapping_add((i64::from(signed) * 4) as u64);
            if insn & 0xFC00_0000 == 0x9400_0000 {
                regs.x[30] = pc.wrapping_add(4);
            }
            regs.pc = target;
            return StepOutcome::Ran;
        }
        // movz xD, #imm16, lsl #0
        if insn & 0xFFE0_0000 == 0xD280_0000 {
            let rd = (insn & 0x1F) as usize;
            let imm = u64::from((insn >> 5) & 0xFFFF);
            if rd < NUM_X_REGS {
                regs.x[rd] = imm;
            }
            regs.pc = pc.wrapping_add(4);
            return StepOutcome::Ran;
        }
        // cbz Xt, <label>: 19-bit signed word displacement.
        if insn & 0xFF00_0000 == 0xB400_0000 {
            let rt = (insn & 0x1F) as usize;
            let imm19 = (insn >> 5) & 0x7_FFFF;
            let signed = ((imm19 as i32) << 13) >> 13;
            let taken = rt < NUM_X_REGS && regs.x[rt] == 0;
            regs.pc = if taken {
                pc.wrapping_add((i64::from(signed) * 4) as u64)
            } else {
                pc.wrapping_add(4)
            };
            return StepOutcome::Ran;
        }
        // sub Xd, Xn, #imm12, lsl #0
        if insn & 0xFFC0_0000 == 0xD100_0000 {
            let rd = (insn & 0x1F) as usize;
            let rn = ((insn >> 5) & 0x1F) as usize;
            let imm = u64::from((insn >> 10) & 0xFFF);
            if rd < NUM_X_REGS && rn < NUM_X_REGS {
                regs.x[rd] = regs.x[rn].wrapping_sub(imm);
            }
            regs.pc = pc.wrapping_add(4);
            return StepOutcome::Ran;
        }
        StepOutcome::Unknown
    }
}

// ---------------------------------------------------------------------------
// Wire helpers (shared with the test client)
// ---------------------------------------------------------------------------

/// RSP checksum: the low byte of the sum of the (escaped) payload bytes.
#[must_use]
pub fn checksum(payload: &[u8]) -> u8 {
    payload.iter().fold(0u8, |a, &b| a.wrapping_add(b))
}

/// Escape `#`, `$`, `}` and `*` as `}` followed by the byte XOR 0x20.
#[must_use]
pub fn escape(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len());
    for &b in payload {
        if matches!(b, b'#' | b'$' | b'}' | b'*') {
            out.push(b'}');
            out.push(b ^ 0x20);
        } else {
            out.push(b);
        }
    }
    out
}

/// Expand run-length `*` runs, on the wire bytes.
///
/// A `*` repeats the preceding **wire** byte, which is not necessarily a
/// decoded one: it may be the second half of an escape pair. Expansion
/// therefore has to happen before escapes are removed.
fn rle_expand(payload: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(payload.len());
    let mut i = 0;
    while i < payload.len() {
        if payload[i] == b'*' && i + 1 < payload.len() {
            // `*` repeats the previous byte (n - 29) additional times.
            let n = payload[i + 1].saturating_sub(29);
            if let Some(&prev) = out.last() {
                for _ in 0..n {
                    out.push(prev);
                }
            }
            i += 2;
        } else {
            out.push(payload[i]);
            i += 1;
        }
    }
    out
}

/// Reverse [`escape`], and expand run-length `*` runs.
///
/// Order matters, and it is the one `rsp.rs` documents for the production
/// client: RLE-expand first, then remove escapes. Doing both in a single
/// left-to-right pass makes `*` repeat the byte already DECODED, so a run
/// following an escape pair repeats the wrong byte — `#` followed by three
/// `0x03` decoded as four `#`, silently corrupting the payload. A test double
/// that decodes differently from the real client is worse than no double: it
/// hides real bugs and invents ones that do not exist.
#[must_use]
pub fn unescape(payload: &[u8]) -> Vec<u8> {
    let expanded = rle_expand(payload);
    let mut out: Vec<u8> = Vec::with_capacity(expanded.len());
    let mut i = 0;
    while i < expanded.len() {
        if expanded[i] == b'}' && i + 1 < expanded.len() {
            out.push(expanded[i + 1] ^ 0x20);
            i += 2;
        } else {
            out.push(expanded[i]);
            i += 1;
        }
    }
    out
}

/// Wrap a payload as `$<escaped>#<csum>`.
#[must_use]
pub fn encode_packet(payload: &str) -> Vec<u8> {
    let esc = escape(payload.as_bytes());
    let mut out = Vec::with_capacity(esc.len() + 4);
    out.push(b'$');
    out.extend_from_slice(&esc);
    out.push(b'#');
    out.extend_from_slice(format!("{:02x}", checksum(&esc)).as_bytes());
    out
}

/// Wrap already-escaped bytes as `$<body>#<csum>` without escaping them again.
#[must_use]
pub fn frame_escaped(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    out.push(b'$');
    out.extend_from_slice(body);
    out.push(b'#');
    out.extend_from_slice(format!("{:02x}", checksum(body)).as_bytes());
    out
}

/// Compress runs of 4..=97 identical bytes using the `*` form.
///
/// Must be applied to *escaped* bytes (see [`MockDebugserver::feed`]'s emit
/// path). Runs of `}` are left alone: `}` introduces an escape pair, so
/// compressing it would move the run boundary relative to the decoded stream.
#[must_use]
pub fn rle_encode_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        let mut run = 1;
        while i + run < bytes.len() && bytes[i + run] == c && run < 97 {
            run += 1;
        }
        out.push(c);
        // One literal byte is already emitted; `*<code>` covers the remainder.
        if run >= 4 && c != b'}' {
            let extra = run - 1;
            let code = u8::try_from(extra + 29).unwrap_or(126);
            // `$`, `#`, `}` and `*` may never appear as the repeat count.
            if !matches!(code, b'$' | b'#' | b'}' | b'*') {
                out.push(b'*');
                out.push(code);
                i += run;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// String convenience wrapper over [`rle_encode_bytes`].
#[must_use]
pub fn rle_encode(s: &str) -> String {
    String::from_utf8_lossy(&rle_encode_bytes(s.as_bytes())).to_string()
}

/// Hex-encode bytes, lowercase, no separators.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode a lowercase/uppercase hex string. `None` on odd length or bad digits.
#[must_use]
pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(u8::try_from(hi * 16 + lo).ok()?);
    }
    Some(out)
}

fn push_hex_le(out: &mut String, bytes: &[u8]) {
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
}

#[must_use]
/// Escape the two characters that would otherwise break a hand-emitted JSON
/// string. Thread names come from the (simulated) target, so they are not
/// assumed to be well behaved.
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn hex_le_u64(v: u64) -> String {
    hex_encode(&v.to_le_bytes())
}

fn read_u64_le(b: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let n = b.len().min(8);
    buf[..n].copy_from_slice(&b[..n]);
    u64::from_le_bytes(buf)
}

fn read_u32_le(b: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    let n = b.len().min(4);
    buf[..n].copy_from_slice(&b[..n]);
    u32::from_le_bytes(buf)
}

/// Does this packet require a live task/thread port to be answered?
///
/// Stated as the invariant rather than as a list of letters somebody happened
/// to think of: every packet here is a `mach_vm_*` or `thread_*` call against
/// the inferior's task port, which dies with the inferior. `mach_vm_allocate`
/// (`_M`), `mach_vm_deallocate` (`_m`), `mach_vm_region` (`qMemoryRegionInfo`)
/// and `task_resume`/`thread_resume` (`c`/`s`/`C`/`S`/`vCont`) all return
/// `KERN_INVALID_TASK` once it is gone, and debugserver answers `E`.
/// `vCont?` is excluded: it is a capability query, answered without the task.
fn packet_needs_live_target(pkt: &str) -> bool {
    if pkt == "vCont?" {
        return false;
    }
    if pkt.starts_with("vCont")
        || pkt.starts_with("_M")
        || pkt.starts_with("_m")
        || pkt.starts_with("qMemoryRegionInfo")
    {
        return true;
    }
    matches!(
        pkt.chars().next(),
        Some('g' | 'G' | 'p' | 'P' | 'm' | 'M' | 'Z' | 'z' | 'c' | 'C' | 's' | 'S')
    )
}

/// Parse the permission field of an `_M size,perms` allocation request.
///
/// `debugserver` accepts any combination of `r`, `w` and `x` (including none)
/// and nothing else; an unrecognised character makes the packet ill-formed.
fn parse_alloc_perms(s: &str) -> Option<Perms> {
    let mut perms = Perms { read: false, write: false, exec: false };
    for c in s.chars() {
        match c {
            'r' => perms.read = true,
            'w' => perms.write = true,
            'x' => perms.exec = true,
            _ => return None,
        }
    }
    Some(perms)
}

/// Split a trailing `;thread:xxxx;` suffix off a packet.
fn split_thread_suffix(pkt: &str) -> (&str, Option<u32>) {
    if let Some(idx) = pkt.rfind(";thread:") {
        let tail = &pkt[idx + ";thread:".len()..];
        let tid_str = tail.strip_suffix(';').unwrap_or(tail);
        if let Some(tid) = hex_u32(tid_str) {
            return (&pkt[..idx], Some(tid));
        }
    }
    (pkt, None)
}

fn default_target_xml() -> String {
    let mut s = String::from(
        "<?xml version=\"1.0\"?><!DOCTYPE target SYSTEM \"gdb-target.dtd\">\
         <target><architecture>aarch64</architecture>\
         <feature name=\"org.gnu.gdb.aarch64.core\">",
    );
    for ri in register_info_table() {
        let _ = write!(
            s,
            "<reg name=\"{}\" bitsize=\"{}\" regnum=\"{}\"/>",
            ri.name, ri.bitsize, ri.dwarf_regnum
        );
    }
    s.push_str("</feature></target>");
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------


/// RSP numeric fields are bare digit runs. `from_str_radix` additionally accepts
/// a leading `+`, which is the acknowledgement byte at the framing layer and is
/// never part of a field: debugserver's reader stops at the first non-digit and
/// rejects the packet. These wrappers restore that, so the mock cannot accept a
/// family of malformed packets the device would refuse.
fn is_hex_run(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn hex_u64(s: &str) -> Option<u64> {
    if is_hex_run(s) { u64::from_str_radix(s, 16).ok() } else { None }
}

fn hex_u32(s: &str) -> Option<u32> {
    if is_hex_run(s) { u32::from_str_radix(s, 16).ok() } else { None }
}

fn hex_usize(s: &str) -> Option<usize> {
    if is_hex_run(s) { usize::from_str_radix(s, 16).ok() } else { None }
}

fn hex_u8(s: &str) -> Option<u8> {
    if is_hex_run(s) { u8::from_str_radix(s, 16).ok() } else { None }
}

fn dec_u8(s: &str) -> Option<u8> {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) { s.parse().ok() } else { None }
}

fn dec_usize(s: &str) -> Option<usize> {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) { s.parse().ok() } else { None }
}

/// Validate an `A` packet: `A<arglen>,<argnum>,<hex-arg>[,<arglen>,…]`.
///
/// Nothing is executed — the mock's process image is whatever the test
/// preloaded, so there is nothing to exec — but the packet is still parsed.
/// debugserver walks every triplet and answers `E` on any malformation before
/// it will launch, so a mock that replies `OK` to whatever follows the letter
/// is the strongest possible form of "always answers positively": a client that
/// builds argv with the wrong length, an odd-length hex body, or a missing
/// separator is never contradicted until it fails to launch on a device.
///
/// `arglen` counts the HEX CHARACTERS of the argument (twice its byte length)
/// and is decimal, exactly as this crate's own `lldb_ext::build_a_packet`
/// emits it and as debugserver's `HandlePacket_A` reads it back.
fn validate_a_packet(rest: &str) -> String {
    if rest.is_empty() {
        return "E01".to_string();
    }
    let fields: Vec<&str> = rest.split(',').collect();
    if !fields.len().is_multiple_of(3) {
        return "E01".to_string();
    }
    for triplet in fields.chunks_exact(3) {
        let (Some(arglen), Some(_argnum)) = (dec_usize(triplet[0]), dec_usize(triplet[1])) else {
            return "E01".to_string();
        };
        let body = triplet[2];
        // The declared length is in characters, and the body must be hex —
        // `decode_hex` also rejects the odd-length case for free.
        if body.len() != arglen || decode_hex(body).is_none() {
            return "E01".to_string();
        }
    }
    "OK".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn one_shot(srv: &mut MockDebugserver, pkt: &str) -> String {
        let out = srv.feed(&encode_packet(pkt)).expect("connection open");
        // Strip a leading ack, then unwrap `$...#xx`.
        let s = String::from_utf8_lossy(&out).to_string();
        let s = s.strip_prefix('+').unwrap_or(&s).to_string();
        let body = s
            .strip_prefix('$')
            .and_then(|r| r.rfind('#').map(|i| r[..i].to_string()))
            .unwrap_or_default();
        String::from_utf8_lossy(&unescape(body.as_bytes())).to_string()
    }

    #[test]
    fn checksum_matches_reference_vector() {
        // "OK" -> 'O'(0x4F) + 'K'(0x4B) = 0x9A
        assert_eq!(checksum(b"OK"), 0x9A);
        assert_eq!(encode_packet("OK"), b"$OK#9a".to_vec());
    }

    #[test]
    fn escape_roundtrip_covers_all_four_specials() {
        let raw = b"a#b$c}d*e";
        let esc = escape(raw);
        assert!(!esc.contains(&b'#'));
        // Unescape of an escaped buffer must be the identity.
        assert_eq!(unescape(&esc), raw.to_vec());
    }

    #[test]
    fn rle_roundtrip() {
        let s = "0000000000abc";
        let enc = rle_encode(s);
        assert!(enc.len() < s.len(), "rle must shorten: {enc}");
        assert_eq!(String::from_utf8_lossy(&unescape(enc.as_bytes())), s);
    }

    #[test]
    fn register_layout_offsets_are_self_consistent() {
        let table = register_info_table();
        assert_eq!(table.len(), 68);
        assert_eq!(table[32].name, "pc");
        assert_eq!(table[32].generic, Some("pc"));
        assert_eq!(table[32].offset, OFF_PC);
        assert_eq!(table[31].generic, Some("sp"));
        assert_eq!(table[29].generic, Some("fp"));
        assert_eq!(table[30].generic, Some("ra"));
        assert_eq!(G_PACKET_BYTES, 31 * 8 + 8 + 8 + 4 + 32 * 16 + 4 + 4);
    }

    #[test]
    fn g_packet_roundtrip() {
        let mut regs = Arm64Registers::default();
        regs.x[0] = 0xDEAD_BEEF_CAFE_0001;
        regs.x[30] = 0x1234;
        regs.sp = 0x7FFF_0000;
        regs.pc = 0x1_0000_4000;
        regs.v[7] = 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10;
        regs.fpcr = 0x0C00_0000;
        let hex = regs.encode_g();
        assert_eq!(hex.len(), G_PACKET_BYTES * 2);
        let back = Arm64Registers::decode_g(&hex).expect("valid g payload");
        assert_eq!(back, regs);
    }

    #[test]
    fn g_packet_rejects_short_payload() {
        assert!(Arm64Registers::decode_g("00112233").is_none());
        assert!(Arm64Registers::decode_g("zz").is_none());
    }

    /// The `G` payload is a fixed-size image of the register context. A client
    /// that appends extra registers (wrong register set, doubled buffer) must
    /// be told so, exactly as a short payload is — silently dropping the tail
    /// reports a successful full-register write that did not happen.
    #[test]
    fn g_packet_rejects_long_payload() {
        let regs = Arm64Registers::default();
        let long = format!("{}00112233445566778899aabbccddeeff", regs.encode_g());
        assert!(
            Arm64Registers::decode_g(&long).is_none(),
            "a payload longer than the register context must be rejected"
        );

        let mut srv = MockDebugserver::new(1);
        assert_eq!(
            one_shot(&mut srv, &format!("G{long}")),
            "E01",
            "the G handler must reject an over-long register block"
        );
    }

    #[test]
    fn indexed_register_access_matches_g_layout() {
        let mut regs = Arm64Registers::default();
        assert!(regs.write_indexed(32, &hex_le_u64(0xABCD)));
        assert_eq!(regs.pc, 0xABCD);
        assert_eq!(regs.read_indexed(32).unwrap(), hex_le_u64(0xABCD));
        assert!(regs.read_indexed(68).is_none());
        assert!(!regs.write_indexed(68, "00"));
        // A too-short value must be rejected, not zero-extended.
        assert!(!regs.write_indexed(0, "ff"));
    }


    #[test]
    fn memory_map_rejects_overlap_and_reads_exactly() {
        let mut m = MemorySpace::new();
        assert!(m.map(MemoryRegion::new(0x1000, vec![1, 2, 3, 4], Perms::rw(), "a")));
        assert!(!m.map(MemoryRegion::new(0x1002, vec![9], Perms::rw(), "b")));
        assert_eq!(m.read(0x1001, 2), Some(vec![2, 3]));
        // Partially out of range must fail rather than truncate.
        assert_eq!(m.read(0x1003, 2), None);
        assert_eq!(m.read(0x2000, 1), None);
        assert!(m.write(0x1000, &[9, 9]));
        assert_eq!(m.read(0x1000, 2), Some(vec![9, 9]));
    }

    #[test]
    fn read_only_region_rejects_writes() {
        let mut m = MemorySpace::new();
        let ro = Perms { read: true, write: false, exec: false };
        assert!(m.map(MemoryRegion::new(0x1000, vec![0; 8], ro, "ro")));
        assert!(!m.write(0x1000, &[1]));
    }

    #[test]
    /// After `QStartNoAckMode` a stray `-` must be IGNORED, not answered.
    ///
    /// The mock retransmits its last reply on `-`, which is right while acks
    /// are in use — without it, the only client that makes progress after a
    /// damaged reply is one that wrongly re-issues the command, so the mock
    /// would reward the defect it exists to expose.
    ///
    /// In no-ack mode the same helpfulness inverts into the opposite hazard.
    /// Apple's debugserver ignores `-` there entirely, so a client that nacks
    /// anyway gets nothing and blocks. A mock that answers would hand it a
    /// valid reply, the test would pass, and the same code would hang against
    /// a real device. Both directions are the same underlying error — the mock
    /// deciding for itself what the target does.
    #[test]
    fn a_stray_nack_is_ignored_once_acks_are_off() {
        let mut srv = MockDebugserver::new(0x1234);
        let _ = one_shot(&mut srv, "qSupported:xmlRegisters=aarch64");

        // While acks ARE in use, `-` must still produce a retransmission —
        // otherwise this test would pass by breaking the useful behaviour.
        assert!(
            !one_shot(&mut srv, "qC").is_empty(),
            "there must be a previous reply for the nack to retransmit"
        );
        let before = srv.retransmissions;
        let out = srv.feed(b"-").unwrap();
        assert_eq!(
            srv.retransmissions,
            before + 1,
            "with acks on, a nack must retransmit the last reply"
        );
        assert!(!out.is_empty(), "the retransmission produced no bytes");

        assert_eq!(one_shot(&mut srv, "QStartNoAckMode"), "OK");
        assert!(srv.no_ack_mode());

        // Now the same `-` must produce nothing at all.
        let before = srv.retransmissions;
        let out = srv.feed(b"-").unwrap();
        assert_eq!(
            srv.retransmissions, before,
            "the mock retransmitted a reply in no-ack mode, where Apple's debugserver ignores \
             `-` — a client that nacks here would be handed a reply by the mock and would hang \
             against a real device"
        );
        assert!(
            out.is_empty(),
            "the mock answered a stray nack in no-ack mode with {out:?}"
        );
        // The nack is still COUNTED: it was received, it just earns no reply.
        assert!(srv.nacks_received >= 2, "the nack should still be observed");
    }

    #[test]
    fn handshake_query_supported_and_no_ack_mode() {
        let mut srv = MockDebugserver::new(0x1234);
        let reply = one_shot(&mut srv, "qSupported:xmlRegisters=aarch64");
        assert!(reply.contains("QStartNoAckMode+"), "{reply}");
        assert!(!srv.no_ack_mode());
        assert_eq!(one_shot(&mut srv, "QStartNoAckMode"), "OK");
        assert!(srv.no_ack_mode());
        // After no-ack mode the server must stop prefixing `+`.
        let raw = srv.feed(&encode_packet("qC")).unwrap();
        assert!(raw.starts_with(b"$"), "unexpected ack: {raw:?}");
    }

    #[test]
    fn host_and_process_info_report_arm64() {
        let mut srv = MockDebugserver::new(0x99);
        let host = one_shot(&mut srv, "qHostInfo");
        assert!(host.contains("cputype:16777228"));
        assert!(host.contains("ptrsize:8"));
        let proc_info = one_shot(&mut srv, "qProcessInfo");
        assert!(proc_info.contains("pid:99;"), "{proc_info}");
    }

    #[test]
    fn register_info_enumeration_terminates_with_e45() {
        let mut srv = MockDebugserver::new(1);
        assert!(one_shot(&mut srv, "qRegisterInfo0").contains("name:x0;"));
        assert!(one_shot(&mut srv, "qRegisterInfo20").contains("generic:pc;"));
        assert_eq!(one_shot(&mut srv, "qRegisterInfo44"), "E45");
    }

    #[test]
    fn thread_enumeration_and_selection() {
        let mut srv = MockDebugserver::new(1);
        srv.add_thread(MockThread::new(0x2a, "worker"));
        assert_eq!(one_shot(&mut srv, "qfThreadInfo"), "m1,2a");
        assert_eq!(one_shot(&mut srv, "qsThreadInfo"), "l");
        assert_eq!(one_shot(&mut srv, "Hg2a"), "OK");
        assert_eq!(one_shot(&mut srv, "qC"), "QC2a");
        assert_eq!(one_shot(&mut srv, "Hg99"), "E01");
    }

    #[test]
    fn per_thread_registers_are_independent() {
        let mut srv = MockDebugserver::new(1);
        let mut t2 = MockThread::new(2, "worker");
        t2.regs.pc = 0xBBBB;
        srv.add_thread(t2);
        srv.threads[0].regs.pc = 0xAAAA;

        let g1 = one_shot(&mut srv, "g");
        assert_eq!(&g1[OFF_PC * 2..OFF_PC * 2 + 16], &hex_le_u64(0xAAAA));
        // Thread suffix must select the other thread without an `Hg` — once it
        // has been negotiated, which is what a real client does at handshake.
        assert_eq!(one_shot(&mut srv, "QThreadSuffixSupported"), "OK");
        let g2 = one_shot(&mut srv, "g;thread:2;");
        assert_eq!(&g2[OFF_PC * 2..OFF_PC * 2 + 16], &hex_le_u64(0xBBBB));
    }

    #[test]
    fn memory_read_write_over_the_wire() {
        let mut srv = MockDebugserver::new(1);
        srv.memory.map(MemoryRegion::zeroed(0x4000, 32, Perms::rw(), "data"));
        assert_eq!(one_shot(&mut srv, "M4000,4:deadbeef"), "OK");
        assert_eq!(one_shot(&mut srv, "m4000,4"), "deadbeef");
        // Unmapped access must be a typed error, not empty data.
        assert_eq!(one_shot(&mut srv, "m9000,4"), "E09");
        assert!(one_shot(&mut srv, "qMemoryRegionInfo:4001").contains("permissions:rw"));
    }

    /// `from_str_radix` accepts a leading `+` for unsigned types, so every hex
    /// field in the dispatcher silently swallows one. debugserver's reader
    /// consumes hex digits only: `+` is the ack byte, never part of a field.
    #[test]
    fn skeptic_hex_fields_reject_leading_plus() {
        let mut srv = MockDebugserver::new(1);
        srv.memory.map(MemoryRegion::zeroed(0x4000, 32, Perms::rw(), "data"));
        assert_eq!(one_shot(&mut srv, "M4000,4:deadbeef"), "OK");

        assert_eq!(one_shot(&mut srv, "m+4000,4"), "E01", "`m` address must reject `+`");
        assert_eq!(one_shot(&mut srv, "m4000,+4"), "E01", "`m` length must reject `+`");
        assert_eq!(one_shot(&mut srv, "Z0,+2008,4"), "E01", "`Z` address must reject `+`");
        assert_eq!(one_shot(&mut srv, "Z+0,2008,4"), "E01", "`Z` kind must reject `+`");
    }

    #[test]
    fn qxfer_pagination_uses_m_and_l_correctly() {
        let mut srv = MockDebugserver::new(1);
        srv.set_target_xml("ABCDEFGHIJ");
        assert_eq!(one_shot(&mut srv, "qXfer:features:read:target.xml:0,4"), "mABCD");
        assert_eq!(one_shot(&mut srv, "qXfer:features:read:target.xml:4,4"), "mEFGH");
        assert_eq!(one_shot(&mut srv, "qXfer:features:read:target.xml:8,4"), "lIJ");
        assert_eq!(one_shot(&mut srv, "qXfer:features:read:target.xml:a,4"), "l");
    }

    #[test]
    fn loaded_libraries_json_reports_slide() {
        let mut srv = MockDebugserver::new(1);
        srv.add_image(LoadedImage {
            path: "/usr/lib/libfoo.dylib".into(),
            load_address: 0x1_0000_0000,
            slide: 0x4000,
            uuid: [0x11; 16],
        });
        let j = one_shot(&mut srv, "jGetLoadedDynamicLibrariesInfos:{\"fetch_all_solibs\":true}");
        assert!(j.contains("\"slide\":16384"), "{j}");
        assert!(j.contains("libfoo.dylib"), "{j}");
        assert!(j.contains("\"uuid\":\"1111"), "{j}");
    }

    #[test]
    fn allocate_and_free_target_memory() {
        let mut srv = MockDebugserver::new(1);
        let addr_hex = one_shot(&mut srv, "_M100,rwx");
        let addr = u64::from_str_radix(&addr_hex, 16).expect("hex address");
        assert!(srv.memory.write(addr, &[7; 4]));
        assert_eq!(one_shot(&mut srv, &format!("_m{addr:x}")), "OK");
        assert_eq!(one_shot(&mut srv, "_m1"), "E01");
    }

    /// The interpreter must build a real frame-pointer chain, because that is
    /// what a backtrace test depends on.
    #[test]
    fn interpreter_builds_a_three_frame_chain() {
        // main:  stp/mov/bl a/ret     @0x1000
        // a:     stp/mov/bl b/ldp/ret @0x1020
        // b:     brk                  @0x1040
        let base = 0x1000u64;
        let code = vec![
            // 0x1000 main
            Arm64Interp::STP_FP_LR_PRE,
            Arm64Interp::MOV_FP_SP,
            Arm64Interp::bl(0x20 - 8),
            Arm64Interp::LDP_FP_LR_POST,
            Arm64Interp::RET,
            Arm64Interp::NOP,
            Arm64Interp::NOP,
            Arm64Interp::NOP,
            // 0x1020 a
            Arm64Interp::STP_FP_LR_PRE,
            Arm64Interp::MOV_FP_SP,
            Arm64Interp::bl(0x40 - 0x28),
            Arm64Interp::LDP_FP_LR_POST,
            Arm64Interp::RET,
            Arm64Interp::NOP,
            Arm64Interp::NOP,
            Arm64Interp::NOP,
            // 0x1040 b
            Arm64Interp::brk(0x8000),
        ];
        let mut srv = MockDebugserver::with_program(1, base, &code);
        let reply = one_shot(&mut srv, "vCont;c");
        assert!(reply.starts_with("T05"), "{reply}");
        assert!(reply.contains("metype:6"), "{reply}");
        assert_eq!(srv.unknown_insn_count, 0, "all encodings must be understood");

        let t = srv.thread(1).unwrap();
        assert_eq!(t.regs.pc, 0x1040);
        // Walk the frame-pointer chain the way an unwinder would.
        let fp0 = t.regs.fp();
        let saved_fp = srv.memory.read_u64(fp0).unwrap();
        let saved_lr = srv.memory.read_u64(fp0 + 8).unwrap();
        assert_eq!(saved_lr, 0x1000 + 3 * 4, "return address into main");
        let outer_lr = srv.memory.read_u64(saved_fp + 8).unwrap();
        assert_eq!(outer_lr, 0, "outermost frame has a null link register");
    }

    #[test]
    fn breakpoint_stops_execution_at_the_right_pc() {
        let base = 0x2000u64;
        let code = vec![
            Arm64Interp::NOP,
            Arm64Interp::NOP,
            Arm64Interp::movz(0, 7),
            Arm64Interp::RET,
        ];
        let mut srv = MockDebugserver::with_program(1, base, &code);
        assert_eq!(one_shot(&mut srv, "Z0,2008,4"), "OK");
        assert_eq!(srv.breakpoints().len(), 1);
        let reply = one_shot(&mut srv, "vCont;c");
        assert!(reply.contains("reason:breakpoint"), "{reply}");
        assert_eq!(srv.thread(1).unwrap().regs.pc, 0x2008);
        // The expedited pc in the stop reply must agree with `p20`.
        assert!(reply.contains(&format!("20:{};", hex_le_u64(0x2008))), "{reply}");

        // Removing the breakpoint lets it run to exit (`ret` with lr == 0).
        assert_eq!(one_shot(&mut srv, "z0,2008,4"), "OK");
        let reply = one_shot(&mut srv, "vCont;c");
        assert_eq!(reply, "W07", "x0 becomes the exit status");
    }

    /// A doubled `Z0` is NOT idempotent: it refcounts, exactly as debugserver
    /// does. One `z0` then leaves the trap installed and the process still
    /// stops at an address the client believes it has cleared.
    ///
    /// Before the refcount the mock dropped the duplicate and removed
    /// unconditionally, so this sequence was byte-identical to a matched
    /// insert/remove pair — every doubled-insert defect in the client was
    /// unobservable in-process.
    #[test]
    fn duplicate_z0_refcounts_and_survives_a_single_z0() {
        let base = 0x2000u64;
        let code = vec![
            Arm64Interp::NOP,
            Arm64Interp::NOP,
            Arm64Interp::movz(0, 7),
            Arm64Interp::RET,
        ];
        let mut srv = MockDebugserver::with_program(1, base, &code);
        assert_eq!(one_shot(&mut srv, "Z0,2008,4"), "OK");
        assert_eq!(one_shot(&mut srv, "Z0,2008,4"), "OK");
        assert_eq!(srv.breakpoints().len(), 1, "one trap, not two");
        assert_eq!(srv.breakpoint_refs(0x2008, BpKind::Software), 2);
        assert_eq!(srv.z_traffic(), (2, 0), "both inserts are tallied");

        assert_eq!(one_shot(&mut srv, "z0,2008,4"), "OK");
        assert_eq!(
            srv.breakpoint_refs(0x2008, BpKind::Software),
            1,
            "one remove cannot clear a count of two"
        );
        let reply = one_shot(&mut srv, "vCont;c");
        assert!(
            reply.contains("reason:breakpoint"),
            "the trap is still installed and must still fire, got {reply}"
        );

        // The balancing remove clears it; only then does the program run out.
        assert_eq!(one_shot(&mut srv, "z0,2008,4"), "OK");
        assert!(srv.breakpoints().is_empty());
        assert_eq!(one_shot(&mut srv, "vCont;c"), "W07");
    }

    /// The debug registers cannot encode every `Z` geometry, and this crate
    /// already models the rule in `arm64::hw`: `breakpoint` refuses an
    /// unaligned instruction address, `watchpoint_bas` refuses a size other
    /// than 1/2/4/8, a misaligned address, and a range crossing the 8-byte
    /// granule. A stub that answers `OK` to any of those hands the client a
    /// watchpoint the hardware cannot install, so client-side splitting and
    /// alignment logic is never exercised in-process.
    #[test]
    fn z_geometry_the_debug_registers_cannot_encode_is_refused() {
        let mut srv = MockDebugserver::with_program(1, 0x2000, &[Arm64Interp::RET]);
        for pkt in [
            "Z1,2002,4",  // unaligned instruction breakpoint
            "Z2,4001,3",  // size 3 is not 1/2/4/8, and 0x4001 is misaligned
            "Z2,4007,8",  // crosses the 8-byte watchpoint granule
            "Z3,4001,4",  // misaligned 4-byte read watchpoint
            "Z4,4000,1000", // far larger than a debug register can cover
        ] {
            let reply = one_shot(&mut srv, pkt);
            assert!(
                reply.starts_with('E'),
                "`{pkt}` is unencodable in DBGBVR/DBGWVR+DBGWCR, the mock answered {reply:?}"
            );
        }
        assert!(
            srv.breakpoints().is_empty(),
            "a refused request must not leave a trap behind: {:?}",
            srv.breakpoints()
        );

        // The encodable neighbours of each refusal still succeed.
        assert_eq!(one_shot(&mut srv, "Z1,2004,4"), "OK");
        assert_eq!(one_shot(&mut srv, "Z2,4000,8"), "OK");
        assert_eq!(one_shot(&mut srv, "Z3,4004,4"), "OK");
        assert_eq!(one_shot(&mut srv, "Z4,4002,2"), "OK");
    }

    #[test]
    fn single_step_advances_exactly_one_instruction() {
        let base = 0x3000u64;
        let code = vec![Arm64Interp::NOP, Arm64Interp::NOP, Arm64Interp::RET];
        let mut srv = MockDebugserver::with_program(1, base, &code);
        let reply = one_shot(&mut srv, "vCont;s:1");
        assert!(reply.contains("reason:trace"), "{reply}");
        assert_eq!(srv.thread(1).unwrap().regs.pc, base + 4);
        one_shot(&mut srv, "s");
        assert_eq!(srv.thread(1).unwrap().regs.pc, base + 8);
    }

    #[test]
    fn unknown_instructions_are_counted_not_hidden() {
        let mut srv = MockDebugserver::with_program(1, 0x5000, &[0xDEAD_BEEF, Arm64Interp::RET]);
        let reply = one_shot(&mut srv, "vCont;c");
        assert_eq!(reply, "W00");
        assert_eq!(srv.unknown_insn_count, 1);
    }

    #[test]
    fn packets_fail_after_the_process_has_exited() {
        let mut srv = MockDebugserver::with_program(1, 0x5000, &[Arm64Interp::RET]);
        assert_eq!(one_shot(&mut srv, "vCont;c"), "W00");
        assert!(
            one_shot(&mut srv, "m5000,4").starts_with('E'),
            "memory read after exit must fail: {}",
            one_shot(&mut srv, "m5000,4")
        );
        assert!(one_shot(&mut srv, "M5000,1:00").starts_with('E'));
        assert!(one_shot(&mut srv, "Z0,5000,4").starts_with('E'));
        assert!(one_shot(&mut srv, "g").starts_with('E'));
    }

    /// The dead-target gate must express "the task port is dead", not a list of
    /// letters somebody remembered. `_M`/`_m` (`mach_vm_allocate`/`_deallocate`),
    /// `qMemoryRegionInfo` (`mach_vm_region`) and the resume packets all target
    /// the same dead task and all fail on a real debugserver.
    #[test]
    fn dead_target_rejects_alloc_region_info_and_resume() {
        let mut srv = MockDebugserver::with_program(1, 0x5000, &[Arm64Interp::RET]);
        assert_eq!(one_shot(&mut srv, "vCont;c"), "W00");

        assert!(
            one_shot(&mut srv, "_M100,rw").starts_with('E'),
            "allocation in a dead task must fail"
        );
        assert!(
            one_shot(&mut srv, "_m5000").starts_with('E'),
            "deallocation in a dead task must fail"
        );
        let region = one_shot(&mut srv, "qMemoryRegionInfo:5000");
        assert!(
            region.starts_with('E'),
            "region info for a dead task must fail, got {region}"
        );

        // The sharpest case: resuming must not execute instructions in a
        // process the mock has already reported as exited.
        let pc_before = srv.thread(1).expect("thread").regs.pc;
        let unknown_before = srv.unknown_insn_count;
        assert!(
            one_shot(&mut srv, "vCont;c").starts_with('E'),
            "resume of a dead task must fail"
        );
        assert!(one_shot(&mut srv, "c").starts_with('E'));
        assert!(one_shot(&mut srv, "s").starts_with('E'));
        assert_eq!(srv.thread(1).expect("thread").regs.pc, pc_before, "PC moved after exit");
        assert_eq!(srv.unknown_insn_count, unknown_before);
    }

    #[test]
    fn runaway_loop_reports_sigxcpu_instead_of_hanging() {
        // `b .` — an infinite self-branch.
        let mut srv = MockDebugserver::with_program(1, 0x6000, &[Arm64Interp::b(0)]);
        srv.max_steps_per_continue = 50;
        let reply = one_shot(&mut srv, "vCont;c");
        assert!(reply.starts_with("T18"), "SIGXCPU expected, got {reply}");
    }

    #[test]
    fn fault_injection_corrupts_checksum_exactly_once() {
        let mut srv = MockDebugserver::new(1);
        srv.faults_mut().corrupt_checksum = true;
        let raw = srv.feed(&encode_packet("qC")).unwrap();
        let s = String::from_utf8_lossy(&raw);
        let body = s.trim_start_matches('+');
        let (payload, csum) = body[1..].split_once('#').unwrap();
        assert_ne!(
            format!("{:02x}", checksum(payload.as_bytes())),
            csum,
            "checksum should be wrong"
        );
        // Only the next reply is corrupted.
        let raw2 = srv.feed(&encode_packet("qC")).unwrap();
        let s2 = String::from_utf8_lossy(&raw2);
        let body2 = s2.trim_start_matches('+');
        let (p2, c2) = body2[1..].split_once('#').unwrap();
        assert_eq!(format!("{:02x}", checksum(p2.as_bytes())), c2);
    }

    #[test]
    fn fault_injection_closes_connection_after_n_packets() {
        let mut srv = MockDebugserver::new(1);
        srv.faults_mut().close_after_n = Some(2);
        assert!(srv.feed(&encode_packet("qC")).is_ok());
        assert!(srv.feed(&encode_packet("qC")).is_ok());
        assert_eq!(srv.feed(&encode_packet("qC")), Err(MockError::ConnectionClosed));
    }

    #[test]
    fn bad_client_checksum_is_reported_not_swallowed() {
        let mut srv = MockDebugserver::new(1);
        let err = srv.feed(b"$qC#00").unwrap_err();
        assert!(matches!(err, MockError::BadChecksum { .. }), "{err:?}");
    }

    #[test]
    fn byte_by_byte_fragmentation_reassembles() {
        let mut srv = MockDebugserver::new(1);
        let pkt = encode_packet("qHostInfo");
        let mut out = Vec::new();
        for b in &pkt {
            out.extend(srv.feed(&[*b]).unwrap());
        }
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("cputype:16777228"), "{s}");
    }

    #[test]
    fn interrupt_byte_stops_the_current_thread() {
        let mut srv = MockDebugserver::with_program(1, 0x7000, &[Arm64Interp::b(0)]);
        let out = srv.feed(&[0x03]).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("T02"), "SIGINT expected: {s}");
    }

    #[test]
    fn run_until_interrupt_answers_a_continue_with_silence() {
        let mut srv = MockDebugserver::with_program(1, 0x7000, &[Arm64Interp::b(0)]);
        srv.run_until_interrupt = true;
        srv.no_ack_mode = true;
        // A running target produces no reply at all — that is what makes the
        // client park and the interrupt meaningful.
        for resume in ["$c#63", "$vCont;c#a8"] {
            let out = srv.feed(resume.as_bytes()).unwrap();
            assert!(
                out.is_empty(),
                "{resume} must not be answered while the target runs, got {:?}",
                String::from_utf8_lossy(&out)
            );
        }
        // Only the interrupt stops it.
        let out = srv.feed(&[0x03]).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("T02"), "SIGINT expected after 0x03: {s}");
        // A step still terminates on its own, interrupt mode or not.
        let out = srv.feed(b"$s#73").unwrap();
        assert!(!out.is_empty(), "a single step must still answer");
    }

    #[test]
    fn detach_closes_the_session() {
        let mut srv = MockDebugserver::new(1);
        assert_eq!(one_shot(&mut srv, "D"), "OK");
        assert!(srv.is_closed());
        assert_eq!(srv.feed(b"+"), Err(MockError::ConnectionClosed));
    }

    #[test]
    fn unknown_packet_gets_the_empty_reply() {
        let mut srv = MockDebugserver::new(1);
        assert_eq!(one_shot(&mut srv, "qWibble"), "");
    }

    #[test]
    fn packet_log_records_client_behaviour() {
        let mut srv = MockDebugserver::new(1);
        one_shot(&mut srv, "qC");
        one_shot(&mut srv, "?");
        assert_eq!(srv.packet_log, vec!["qC".to_string(), "?".to_string()]);
    }

    /// The mock stands in for a real debugserver, so whatever it puts on the
    /// wire must be readable by the PRODUCTION client — and vice versa.
    ///
    /// Two independent implementations of one wire format: `rsp.rs` (used
    /// against a real target) and this mock (used by every Apple-backend test).
    /// If they diverge, the suite passes against the double and the debugger
    /// corrupts memory against the real thing — the failure mode a test double
    /// is supposed to rule out.
    #[test]
    fn the_mock_and_the_production_client_agree_on_the_wire_format() {
        use crate::ios::rsp;

        let mut payloads: Vec<Vec<u8>> = Vec::new();
        for b in [0u8, b'A', b'#', b'$', b'}', b'*', 0x03, 0x04, 0x0A, 0x5D, 0xFF] {
            // Lengths straddling every threshold either encoder special-cases:
            // 4 (compression starts), 7/8 (counts that would spell '#'/'$'),
            // 14 ('*'), 97 (max run), 98 (past it).
            for len in [1usize, 3, 4, 5, 6, 7, 8, 9, 14, 15, 96, 97, 98] {
                payloads.push(vec![b; len]);
                let mut led = vec![b'}'];
                led.extend(std::iter::repeat_n(b, len));
                payloads.push(led);
            }
        }

        for p in &payloads {
            // Mock encodes (as a debugserver would) -> production client decodes.
            let wire = rle_encode_bytes(&escape(p));
            let decoded = rsp::rle_decode(&wire)
                .and_then(|x| rsp::unescape(&x))
                .unwrap_or_else(|e| panic!("production client rejected mock output {p:02x?}: {e}"));
            assert_eq!(&decoded, p, "mock -> production lost data for {p:02x?}");

            // Production client encodes -> mock decodes.
            let wire = rsp::rle_encode(&rsp::escape(p));
            assert_eq!(&unescape(&wire), p, "production -> mock lost data for {p:02x?}");
        }
    }

    /// The exact payload the one-pass decoder corrupted, kept by name.
    ///
    /// `#` escapes to `}`; three literal `0x03` bytes then form a run with
    /// that pair's second half. Decoding in one pass repeated the DECODED `#`
    /// and produced four `#`. The mock and `rsp.rs` must agree byte for byte —
    /// this is the case that proved they did not.
    #[test]
    fn a_run_following_an_escape_pair_repeats_the_wire_byte() {
        let payload = [b'#', 0x03, 0x03, 0x03];
        let wire = rle_encode_bytes(&escape(&payload));
        assert_eq!(
            unescape(&wire),
            payload,
            "the run repeats the on-the-wire byte, not the decoded one"
        );
    }

    /// The wire codec must be lossless for EVERY payload.
    ///
    /// On the wire the order is escape-then-RLE, so the inverse is what
    /// `unescape` performs in one left-to-right pass. That pass has to get the
    /// interaction right: a compressed run may follow an escape pair, and the
    /// byte a `*` repeats is the DECODED previous byte, not the raw one. This
    /// checks the round trip over every byte value at every run length that
    /// can reach, or just miss, the compressor's thresholds.
    #[test]
    fn the_wire_codec_round_trips_every_payload() {
        let roundtrip = |p: &[u8]| unescape(&rle_encode_bytes(&escape(p)));
        for b in 0u8..=255 {
            for len in 1usize..=100 {
                let payload = vec![b; len];
                assert_eq!(
                    roundtrip(&payload),
                    payload,
                    "run of {len} x {b:#04x} did not survive the wire codec"
                );
            }
        }
        // Runs preceded by an escape pair, which is where a one-pass decoder
        // is most likely to repeat the wrong byte.
        for lead in [b'#', b'$', b'}', b'*'] {
            // 0x03/0x04/0x0A/0x5D are the SECOND halves of the escape pairs
            // for `#`/`$`/`*`/`}`. A run of one of those right after an escape
            // pair is exactly where a one-pass decoder repeats the decoded
            // byte instead of the on-the-wire byte.
            for b in [0u8, b'A', b'}', b'*', 0xFF, 0x03, 0x04, 0x0A, 0x5D] {
                for len in [1usize, 3, 4, 7, 8, 14, 97, 98] {
                    let mut payload = vec![lead];
                    payload.extend(std::iter::repeat_n(b, len));
                    assert_eq!(
                        roundtrip(&payload),
                        payload,
                        "{lead:#04x} followed by {len} x {b:#04x} did not survive"
                    );
                }
            }
        }
    }

    /// Feed one packet whose body is arbitrary bytes (not necessarily UTF-8)
    /// and return the raw server output.
    fn one_shot_bytes(srv: &mut MockDebugserver, body: &[u8]) -> String {
        let out = srv.feed(&frame_escaped(&escape(body))).expect("connection open");
        let s = String::from_utf8_lossy(&out).to_string();
        let s = s.strip_prefix('+').unwrap_or(&s).to_string();
        let body = s
            .strip_prefix('$')
            .and_then(|r| r.rfind('#').map(|i| r[..i].to_string()))
            .unwrap_or_default();
        String::from_utf8_lossy(&unescape(body.as_bytes())).to_string()
    }

    /// `X` carries RAW BYTES. Routing them through `String::from_utf8_lossy`
    /// rewrites every non-UTF-8 byte as `EF BF BD`, so a client that writes
    /// machine code (0xFF, lone 0x80 continuation bytes, …) sees the mock
    /// accept a write the device would have taken verbatim — and the memory it
    /// reads back afterwards is not what it sent.
    #[test]
    fn x_packet_writes_binary_bytes_verbatim() {
        let mut srv = MockDebugserver::new(1);
        assert!(srv.memory.map(MemoryRegion::zeroed(0x4000, 16, Perms::rw(), "data")));
        // 0xFF and a lone 0x80 are both invalid UTF-8; `}`/`#`/`$`/`*` exercise
        // the escape path on the way in.
        let payload: Vec<u8> = vec![0xFF, 0x80, b'#', 0x00, b'}', 0xC3, b'*', 0xFE];
        let mut pkt = format!("X4000,{:x}:", payload.len()).into_bytes();
        pkt.extend_from_slice(&payload);

        assert_eq!(one_shot_bytes(&mut srv, &pkt), "OK");
        assert_eq!(
            srv.memory.read(0x4000, payload.len()).expect("mapped"),
            payload,
            "the framer must hand the X handler raw bytes, not a lossy String"
        );
    }

    /// The thread suffix is a NEGOTIATED extension. Honouring it before
    /// `QThreadSuffixSupported` lets a client that never negotiates pass here
    /// and address the wrong thread on a device, where the suffix is not
    /// stripped at all.
    #[test]
    fn thread_suffix_is_only_honoured_after_negotiation() {
        let mut srv = MockDebugserver::new(1);
        let mut t2 = MockThread::new(2, "worker");
        t2.regs.pc = 0xBBBB;
        srv.add_thread(t2);
        srv.threads[0].regs.pc = 0xAAAA;

        // Not negotiated: `g;thread:2;` is not a `g` packet at all.
        assert_eq!(
            one_shot(&mut srv, "g;thread:2;"),
            "E01",
            "an un-negotiated thread suffix must not select a thread"
        );

        assert_eq!(one_shot(&mut srv, "QThreadSuffixSupported"), "OK");
        let g2 = one_shot(&mut srv, "g;thread:2;");
        assert_eq!(&g2[OFF_PC * 2..OFF_PC * 2 + 16], &hex_le_u64(0xBBBB));
    }

    /// `vCont;c:2` names the thread to continue. Continuing the current thread
    /// instead makes every multi-threaded resume test agree with the mock and
    /// disagree with the device.
    #[test]
    fn vcont_continue_resumes_the_thread_named_in_the_action() {
        let base = 0x7000u64;
        let code = vec![Arm64Interp::brk(1), Arm64Interp::brk(2)];
        let mut srv = MockDebugserver::with_program(1, base, &code);
        let mut t2 = MockThread::new(2, "worker");
        t2.regs.pc = base + 4;
        t2.regs.sp = srv.thread(1).expect("thread 1").regs.sp - 0x1000;
        srv.add_thread(t2);

        let reply = one_shot(&mut srv, "vCont;c:2");
        assert!(reply.contains("thread:2;"), "vCont;c:2 must resume thread 2, got {reply}");
        assert_eq!(
            srv.thread(1).expect("thread 1").regs.pc,
            base,
            "thread 1 was not named and must not have executed"
        );
    }

    /// `M addr,len:` declares how many bytes follow. A payload of a different
    /// length is a malformed packet; accepting it hides a client that
    /// miscomputes either half.
    #[test]
    fn m_packet_enforces_its_declared_length() {
        let mut srv = MockDebugserver::new(1);
        assert!(srv.memory.map(MemoryRegion::zeroed(0x4000, 32, Perms::rw(), "data")));

        assert_eq!(one_shot(&mut srv, "M4000,4:dead"), "E01", "2 bytes supplied, 4 declared");
        assert_eq!(one_shot(&mut srv, "M4000,2:deadbeef"), "E01", "4 bytes supplied, 2 declared");
        assert_eq!(
            one_shot(&mut srv, "m4000,4"),
            "00000000",
            "a rejected write must not have touched memory"
        );
        assert_eq!(one_shot(&mut srv, "M4000,4:deadbeef"), "OK");
        assert_eq!(one_shot(&mut srv, "m4000,4"), "deadbeef");
    }

    /// An `_M` request carries an untrusted 64-bit size. `mach_vm_allocate`
    /// fails and a real debugserver answers `E`; it never aborts. Building
    /// `vec![0; len]` eagerly instead takes the whole harness down, so the
    /// client bug that produced the absurd size can never be observed.
    #[test]
    fn an_absurd_allocation_is_refused_not_attempted() {
        let mut srv = MockDebugserver::new(1);
        assert_eq!(
            one_shot(&mut srv, "_Mfffffffffffffff0,rw"),
            "E01",
            "a 16-exabyte request must be answered with an error, not attempted"
        );
        // The mock is still usable afterwards: a sane allocation still works.
        let base = one_shot(&mut srv, "_M100,rw");
        assert!(u64::from_str_radix(&base, 16).is_ok(), "got {base}");
    }

    /// `_M size,perms` asks for a mapping with specific protection. Handing
    /// back `rw` whatever was requested means a client that allocates `rx` and
    /// then writes there succeeds in-process and takes `EXC_BAD_ACCESS` on a
    /// device.
    #[test]
    fn allocation_honours_the_requested_permissions() {
        let mut srv = MockDebugserver::new(1);

        let rx = u64::from_str_radix(&one_shot(&mut srv, "_M100,rx"), 16).expect("hex address");
        assert!(
            one_shot(&mut srv, &format!("qMemoryRegionInfo:{rx:x}")).contains("permissions:rx;"),
            "an rx allocation must be reported as rx"
        );

        // Read-only really is read-only: the write must be refused.
        let ro = u64::from_str_radix(&one_shot(&mut srv, "_M100,r"), 16).expect("hex address");
        assert!(
            one_shot(&mut srv, &format!("qMemoryRegionInfo:{ro:x}")).contains("permissions:r;"),
            "an r allocation must be reported as r"
        );
        assert!(!srv.memory.write(ro, &[1, 2, 3, 4]), "a read-only allocation is not writable");

        let rw = u64::from_str_radix(&one_shot(&mut srv, "_M100,rw"), 16).expect("hex address");
        assert!(srv.memory.write(rw, &[1, 2, 3, 4]), "an rw allocation is writable");

        // A permission string the target cannot honour is an error, not an
        // arbitrary default.
        assert_eq!(one_shot(&mut srv, "_M100,q"), "E01");
    }

    /// `X addr,len:` carries the same length contract as `M`; only the payload
    /// encoding differs. debugserver reads exactly `len` bytes off the packet,
    /// so a payload of any other size is malformed — and an empty payload is
    /// the zero-length probe ONLY when the header declared zero.
    #[test]
    fn x_packet_enforces_its_declared_length() {
        let mut srv = MockDebugserver::new(1);
        assert!(srv.memory.map(MemoryRegion::zeroed(0x4000, 32, Perms::rw(), "data")));

        let short = {
            let mut p = b"X4000,8:".to_vec();
            p.extend_from_slice(&[0xAA, 0xBB]);
            p
        };
        assert_eq!(one_shot_bytes(&mut srv, &short), "E01", "2 bytes supplied, 8 declared");
        assert_eq!(
            one_shot_bytes(&mut srv, b"X4000,10:"),
            "E01",
            "no payload at all, 16 bytes declared — not the zero-length probe"
        );
        assert_eq!(one_shot_bytes(&mut srv, b"X4000,0:"), "OK", "only `,0:` is the probe");
        assert_eq!(
            one_shot(&mut srv, "m4000,4"),
            "00000000",
            "a rejected write must not have touched memory"
        );
    }

    /// `fail_memory_writes_after` models a target that became UNWRITABLE, not
    /// a packet that became unsupported. `M` and `X` differ only in payload
    /// encoding and both land in `mach_vm_write` on a device, so the injected
    /// fault must gate both; exempting `X` makes the fault a property of the
    /// encoding the client happens to pick.
    #[test]
    fn injected_write_failure_gates_the_binary_x_packet_too() {
        let mut srv = MockDebugserver::new(1);
        assert!(srv.memory.map(MemoryRegion::zeroed(0x4000, 32, Perms::rw(), "data")));
        srv.fail_memory_writes_after(1);

        // The one allowed write, spent through `X`.
        assert_eq!(one_shot_bytes(&mut srv, b"X4000,1:\x11"), "OK");
        // Budget exhausted: both encodings must now be refused.
        assert_eq!(one_shot(&mut srv, "M4001,1:22"), "E09", "`M` past the budget");
        assert_eq!(
            one_shot_bytes(&mut srv, b"X4002,1:\x33"),
            "E09",
            "`X` must honour the same injected write failure as `M`"
        );
        assert_eq!(
            one_shot(&mut srv, "m4002,1"),
            "00",
            "a refused write must not have touched memory"
        );
    }

    /// The n=0 boundary of the same knob: a target that is unwritable from the
    /// very first packet, which is what a process that already died looks like.
    /// Kept apart from the threshold test above because the two fail
    /// DIFFERENTLY when `X` is ungated — there the first refused packet is the
    /// `M` that inherited the unspent budget, so the red accuses the encoding
    /// that is innocent; here nothing may succeed, so the first assertion to
    /// blow is the `X` itself. The read-back is the part that matters: an `X`
    /// answered `OK` has also MOVED the byte, and a client that later reads its
    /// patch back finds it installed on a target that cannot be written.
    #[test]
    fn an_unwritable_target_refuses_the_binary_write_too() {
        let mut srv = MockDebugserver::new(1);
        assert!(srv.memory.map(MemoryRegion::zeroed(0x4000, 32, Perms::rw(), "data")));
        srv.fail_memory_writes_after(0); // no write may succeed from here on

        assert_eq!(one_shot(&mut srv, "M4000,1:aa"), "E09", "baseline: `M` is refused");
        assert_eq!(
            one_shot_bytes(&mut srv, b"X4000,1:\xbb"),
            "E09",
            "the same unwritable target must refuse the binary write"
        );
        assert_eq!(
            one_shot(&mut srv, "m4000,2"),
            "0000",
            "no refused write may have landed"
        );
    }

    /// `off + len` are hex fields chosen by the requester. In release the
    /// overflow checks are off, so `off = 1, len = 0xffff_ffff_ffff_ffff`
    /// wrapped the sum to 0 and made the slice `bytes[1..0]` — a panic, and
    /// with `panic = "abort"` the death of the whole process. `spawn_tcp`
    /// exposes this parser on a loopback socket, so the packet arrives from
    /// outside. A length that does not exist is a THIRD state: refuse it with
    /// `E00`, never silently saturate it into a length the client never asked
    /// for.
    #[test]
    fn qxfer_refuses_a_length_whose_end_offset_does_not_exist() {
        let mut srv = MockDebugserver::new(1);
        srv.set_target_xml("ABCDEFGHIJ");

        let reply = one_shot(&mut srv, "qXfer:features:read:target.xml:1,ffffffffffffffff");
        assert!(!reply.is_empty(), "a malformed qXfer must be answered, not fatal");
        assert_eq!(reply, "E00", "an end offset that does not exist is refused, not clamped");

        // The guard must not fire on a length that merely exceeds the payload:
        // that one has a real end offset and is served as the last chunk.
        assert_eq!(
            one_shot(&mut srv, "qXfer:features:read:target.xml:8,100"),
            "lIJ",
            "an oversized but representable length still reads to the end"
        );
    }

    /// `qXfer:<object>:read:<annex>:off,len` — the annex names WHICH document.
    /// `features` is only defined for `target.xml` and `libraries` requires an
    /// empty annex; serving any annex means a client that sends the wrong one
    /// (or omits it, which shifts every following field) passes here and gets
    /// `E00` from the device on its first descriptor fetch.
    #[test]
    fn qxfer_rejects_an_unknown_annex() {
        let mut srv = MockDebugserver::new(1);
        srv.set_target_xml("ABCDEFGHIJ");

        assert_eq!(one_shot(&mut srv, "qXfer:features:read:target.xml:0,4"), "mABCD");
        assert_eq!(
            one_shot(&mut srv, "qXfer:features:read:not-target.xml:0,4"),
            "E00",
            "`features` is defined for target.xml alone"
        );
        assert_eq!(
            one_shot(&mut srv, "qXfer:features:read::0,4"),
            "E00",
            "an omitted annex is not target.xml"
        );
        assert_eq!(
            one_shot(&mut srv, "qXfer:libraries:read:target.xml:0,4"),
            "E00",
            "`libraries` takes no annex"
        );
        // The well-formed library read still works.
        assert!(one_shot(&mut srv, "qXfer:libraries:read::0,4").starts_with(['m', 'l']));
    }

    /// `qXfer:object:read` reserves two DIFFERENT replies: `E00` means the
    /// request was malformed or the annex was invalid, while an EMPTY reply
    /// means the stub does not recognise the object at all. This mock only
    /// advertises `features` and `libraries`; a probe for any other object is
    /// the unsupported case, exactly like `jThreadsInfo` above. Answering
    /// `E00` makes a capability probe look like a hard remote failure here and
    /// like a clean "not supported" on the device — the client's fallback path
    /// keys on precisely that difference.
    #[test]
    fn qxfer_answers_an_unknown_object_with_an_empty_reply() {
        let mut srv = MockDebugserver::new(1);
        srv.set_target_xml("ABCDEFGHIJ");

        assert_eq!(
            one_shot(&mut srv, "qXfer:auxv:read::0,100"),
            "",
            "`auxv` is not an object this stub serves — unsupported, not malformed"
        );
        assert_eq!(
            one_shot(&mut srv, "qXfer:threads:read::0,100"),
            "",
            "`threads` is likewise unrecognised"
        );
        // A *known* object with a bad annex stays an error: the two failures
        // must not collapse into one another in either direction.
        assert_eq!(one_shot(&mut srv, "qXfer:features:read:nope.xml:0,4"), "E00");
        assert_eq!(one_shot(&mut srv, "qXfer:features:read:target.xml:0,4"), "mABCD");
    }

    /// A free debug-register slot is not enough: the geometry must fit the
    /// register too. `arm64::hw` owns that rule, and answering `OK` to a
    /// watchpoint the hardware cannot encode hides from every client the
    /// splitting/alignment work it must do.
    #[test]
    fn z_packets_reject_geometry_the_debug_registers_cannot_encode() {
        let mut srv = MockDebugserver::new(1);

        assert_eq!(one_shot(&mut srv, "Z2,4000,8"), "OK", "aligned 8-byte watchpoint is legal");
        for pkt in ["Z2,4001,3", "Z2,4007,8", "Z2,4000,1000", "Z1,2002,4"] {
            let reply = one_shot(&mut srv, pkt);
            assert!(
                reply.starts_with('E'),
                "{pkt} cannot be encoded into DBGWVR/DBGWCR, got {reply}"
            );
        }
        assert_eq!(
            srv.breakpoints().len(),
            1,
            "only the encodable watchpoint may have been installed: {:?}",
            srv.breakpoints()
        );
    }

    /// `P<n>=<value>` must carry exactly the register's width. A wider value is
    /// silently truncated by a `min`-clamped decoder, so a client with a width
    /// bug in its register map is confirmed correct here and corrupts — or is
    /// rejected by — the device.
    #[test]
    fn p_packet_rejects_a_value_wider_than_the_register() {
        let mut regs = Arm64Registers::default();

        assert!(!regs.write_indexed(33, &hex_encode(&[0u8; 8])), "cpsr is 32-bit");
        assert!(!regs.write_indexed(66, &hex_encode(&[0u8; 8])), "fpsr is 32-bit");
        assert!(!regs.write_indexed(0, &hex_encode(&[0u8; 16])), "x0 is 64-bit");
        assert!(!regs.write_indexed(34, &hex_encode(&[0u8; 32])), "v0 is 128-bit");

        assert!(regs.write_indexed(33, &hex_encode(&[0u8; 4])), "exact width still accepted");
        assert!(regs.write_indexed(0, &hex_encode(&[0u8; 8])), "exact width still accepted");
        assert!(regs.write_indexed(34, &hex_encode(&[0u8; 16])), "exact width still accepted");

        let mut srv = MockDebugserver::new(1);
        // 0x21 = 33 = cpsr, a 32-bit register handed a 64-bit value.
        assert_eq!(one_shot(&mut srv, "P21=0000000000000000"), "E01");
    }

    /// `vCont;C<sig>` means "resume DELIVERING signal <sig>" — that is the whole
    /// difference from `c`. Executing it as a plain continue swallows the signal
    /// while `vCont?` advertises `C`/`S`, so a client that forwards SIGSEGV is
    /// confirmed working here and silently drops it on a device.
    #[test]
    fn vcont_delivers_the_signal_named_in_a_c_action() {
        let base = 0x7000u64;
        let mut srv = MockDebugserver::with_program(1, base, &[Arm64Interp::RET]);
        // Sanity: unsignalled, this program runs off its outermost frame.
        assert_eq!(one_shot(&mut srv, "vCont;c"), "W00", "baseline: runs to exit");

        let mut srv = MockDebugserver::with_program(1, base, &[Arm64Interp::RET]);
        let reply = one_shot(&mut srv, "vCont;C0b");
        assert!(reply.starts_with("T0b"), "SIGSEGV must be delivered, got {reply}");

        let mut srv = MockDebugserver::with_program(1, base, &[Arm64Interp::RET]);
        assert_eq!(
            one_shot(&mut srv, "vCont;Cxx"),
            "E01",
            "a non-hex signal is a malformed action, not a plain continue"
        );
    }

    /// RSP address/length/thread fields are bare hex digit runs. debugserver's
    /// reader consumes hex digits only, so a `+` fails the field parse there —
    /// accepting it here blesses a client that formats through a signed path.
    #[test]
    fn hex_fields_reject_a_sign_prefix() {
        let mut srv = MockDebugserver::new(1);
        assert!(srv.memory.map(MemoryRegion::zeroed(0x4000, 32, Perms::rw(), "data")));

        assert_eq!(one_shot(&mut srv, "m+4000,4"), "E01");
        assert_eq!(one_shot(&mut srv, "Z0,+2008,4"), "E01");
        assert_eq!(one_shot(&mut srv, "Hg+1"), "E01");
        assert_eq!(one_shot(&mut srv, "p+20"), "E01");
        // The unsigned forms are unaffected.
        assert_eq!(one_shot(&mut srv, "m4000,4"), "00000000");
        assert_eq!(one_shot(&mut srv, "Z0,2008,4"), "OK");
    }

    /// `A<arglen>,<argnum>,<hex-arg>,...` is triplet-structured, and `arglen`
    /// counts the HEX CHARACTERS of the argument (this crate's own
    /// `lldb_ext::build_a_packet` emits exactly that). debugserver parses each
    /// triplet and rejects a body whose length disagrees; answering `OK` to
    /// anything at all is the strongest form of "always answers positively".
    #[test]
    fn a_packet_validates_its_triplets() {
        let mut srv = MockDebugserver::new(1);

        // "/bin" = 2f62696e = 8 hex characters, argument index 0.
        assert_eq!(one_shot(&mut srv, "A8,0,2f62696e"), "OK");
        assert_eq!(one_shot(&mut srv, "A8,0,2f62696e,4,1,2d78"), "OK", "two triplets");

        assert_eq!(one_shot(&mut srv, "A"), "E01", "no argv at all");
        assert_eq!(one_shot(&mut srv, "Awibble"), "E01", "not a triplet");
        assert_eq!(one_shot(&mut srv, "A8,0"), "E01", "length and index with no body");
        assert_eq!(one_shot(&mut srv, "A6,0,2f62696e"), "E01", "8 supplied, 6 declared");
        assert_eq!(one_shot(&mut srv, "A7,0,2f62696ez"), "E01", "odd length, non-hex body");
    }
}

#[cfg(test)]
mod retransmission_tests {
    use super::{Arm64Interp, MockDebugserver};
    use super::tests::one_shot;
    use crate::ios::rsp::{RspClient, TcpTransport};
    use std::time::Duration;

    /// The whole point of `last_reply`: a damaged reply must be repairable by
    /// `-` ALONE. If the mock did not retransmit, the only client that could
    /// finish this request is one that re-issues `M…` — writing the target
    /// twice — and that is exactly the defect being guarded against.
    #[test]
    fn nack_retransmits_last_reply_without_re_executing_the_command() {
        let mut srv = MockDebugserver::with_program(1, 0x4000, &[super::Arm64Interp::RET]);
        srv.faults_mut().corrupt_checksum = true;
        let (addr, handle) = srv.spawn_tcp().expect("spawn tcp mock");

        let transport = TcpTransport::connect(&addr, Some(Duration::from_secs(5)))
            .expect("connect");
        let mut client = RspClient::new(transport);
        let reply = client.request(b"M4000,4:1f2003d5").expect("write survives one corrupt reply");
        assert_eq!(reply.data, b"OK");
        drop(client);

        let srv = handle.join().expect("server thread");
        // Executed ONCE, despite two replies going out.
        assert_eq!(srv.packet_log, vec!["M4000,4:1f2003d5".to_string()]);
        assert_eq!(srv.nacks_received, 1, "client must repair with `-`");
        assert_eq!(srv.retransmissions, 1, "server must re-emit, not re-run");
    }
    /// A target the mock reports dead with `X<sig>` must be as unreachable as
    /// one reported dead with `W<code>`.
    #[test]
    fn an_x_stop_reply_latches_the_target_as_gone() {
        let base = 0x4000_u64;
        let mut srv = MockDebugserver::with_program(1, base, &[Arm64Interp::RET]);
        srv.kill_with_signal(9);
        assert_eq!(one_shot(&mut srv, "c"), "X09", "the resume must report the signal death");
        assert_eq!(
            one_shot(&mut srv, &format!("m{base:x},4")),
            "E09",
            "memory of a target reported dead with `X` is still readable"
        );
        assert_eq!(one_shot(&mut srv, "g"), "E09", "registers of an `X`-dead target are still readable");
        assert_eq!(
            one_shot(&mut srv, &format!("Z0,{base:x},4")),
            "E09",
            "a breakpoint can still be armed in an `X`-dead target"
        );
    }

    /// An access that FAULTS never happened: the translation fault is taken and
    /// the data never reaches the watchpoint comparators. The mock logs the
    /// access before it looks the region up, so a store to an unmapped page
    /// covered by a `Z2` reports a fabricated watchpoint hit AND swallows the
    /// SIGSEGV the client's fault path exists to handle.
    #[test]
    fn a_faulting_access_reports_sigsegv_not_a_watchpoint() {
        let mut srv = MockDebugserver::with_program(1, 0x4000, &[Arm64Interp::STP_FP_LR_PRE]);
        // Park sp so that the pre-index store targets an unmapped page.
        srv.thread_mut_for_test(1).unwrap().regs.sp = 0x9000_0000;
        // 0x9000_0000 - 16 is where `stp x29, x30, [sp, #-16]!` writes.
        assert_eq!(one_shot(&mut srv, "Z2,8ffffff0,8"), "OK");

        let reply = one_shot(&mut srv, "vCont;c");
        assert!(
            !reply.contains("reason:watchpoint"),
            "a store to an unmapped page never reached memory; it cannot fire a watchpoint: {reply}"
        );
        assert!(
            reply.starts_with("T0b"),
            "the translation fault must surface as SIGSEGV: {reply}"
        );
    }
}

#[cfg(test)]
mod faulted_access_is_not_a_watchpoint_hit {
    use super::tests::one_shot;
    use super::*;

    /// A store to an unmapped page aborts: on real hardware the translation
    /// fault is taken and no watchpoint is reported. Logging the access before
    /// the region is looked up (and consulting the watchpoints before
    /// `StepOutcome::Fault`) replaced the SIGSEGV with a fabricated
    /// `reason:watchpoint` for an address the target never touched.
    #[test]
    fn a_store_that_faults_reports_sigsegv_not_a_watchpoint() {
        let mut srv = MockDebugserver::with_program(1, 0x5000, &[Arm64Interp::STP_FP_LR_PRE]);
        // STP pre-decrements by 16, so the access goes to 0x9000_0000 — unmapped.
        srv.thread_mut_for_test(1).unwrap().regs.sp = 0x9000_0010;
        assert_eq!(one_shot(&mut srv, "Z2,90000000,8"), "OK");

        let reply = one_shot(&mut srv, "vCont;c");
        assert!(
            !reply.contains("watchpoint"),
            "an access that faulted never happened, so it cannot fire a watchpoint: {reply}"
        );
        assert!(reply.starts_with("T0b"), "the fault must surface as SIGSEGV: {reply}");
    }

    /// The same for a load: `LDP` off an unmapped stack must fault, not read.
    #[test]
    fn a_load_that_faults_reports_sigsegv_not_a_watchpoint() {
        let mut srv = MockDebugserver::with_program(1, 0x5000, &[Arm64Interp::LDP_FP_LR_POST]);
        srv.thread_mut_for_test(1).unwrap().regs.sp = 0x9000_0000;
        assert_eq!(one_shot(&mut srv, "Z3,90000000,8"), "OK");

        let reply = one_shot(&mut srv, "vCont;c");
        assert!(!reply.contains("watchpoint"), "a load that faulted never happened: {reply}");
        assert!(reply.starts_with("T0b"), "the fault must surface as SIGSEGV: {reply}");
    }

    /// The guard must not silence a REAL watchpoint: the same store into mapped
    /// stack memory still stops with `reason:watchpoint`.
    #[test]
    fn a_store_that_succeeds_still_fires_the_watchpoint() {
        let mut srv = MockDebugserver::with_program(1, 0x5000, &[Arm64Interp::STP_FP_LR_PRE]);
        let sp = srv.thread(1).unwrap().regs.sp;
        assert_eq!(one_shot(&mut srv, &format!("Z2,{:x},8", sp - 16)), "OK");
        let reply = one_shot(&mut srv, "vCont;c");
        assert!(reply.contains("reason:watchpoint"), "a completed store must still fire: {reply}");
    }
}
