//! [`AppleDebugger`] — an implementation of `crate::Debugger` that
//! drives a macOS/iOS target through `debugserver`'s Remote Serial Protocol.
//!
//! # Why RSP and not Mach APIs
//!
//! The obvious way to write an Apple debugger is `task_for_pid` +
//! `thread_get_state` + a Mach exception port. That code cannot exist outside
//! macOS, cannot be compiled here, and — as the hub crate's own notes record —
//! a backend that is never compiled accumulates defects that no test can see.
//! `debugserver` speaks a byte protocol, so every layer of this backend is
//! ordinary byte and register math that compiles and is unit-tested on any
//! host. The only genuinely host-bound piece is *opening the connection*, and
//! that is isolated behind [`TransportFactory`].
//!
//! # Concurrency model
//!
//! Every `Debugger` method takes `&self`, so the mutable protocol state lives
//! behind a `parking_lot::Mutex`. The RSP exchange itself is synchronous and
//! must stay that way: framing is stateful and two interleaved requests on one
//! connection corrupt it. The `async` in the trait signature therefore buys
//! nothing here and the work is done inline — deliberately, rather than
//! wrapping a blocking call in `block_in_place`, which panics on a
//! current-thread runtime.
//!
//! # What is deliberately NOT implemented
//!
//! Each of the following returns [`crate::expression_evaluator::DebugError::Unsupported`] with a reason,
//! never a plausible-looking wrong answer:
//! * [`AppleDebugger::pause`] — an asynchronous `\x03` interrupt needs an
//!   out-of-band reader; the strictly request/response [`RspClient`] has none,
//!   and injecting the byte anyway desynchronises the framer.
//! * backtraces on a non-ARM64 target — [`crate::ios::unwind`] implements ARM64
//!   (and only ARM64) frame recovery.
//! * `LaunchOptions::follow_forks` and the stdio redirection flags, which the
//!   `A` packet cannot express.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use parking_lot::{Mutex, RwLock};
use rustre_core::address::Address;
use crate::symbol_resolver::FrameSymbolResolver;
use crate::source_map::SourceRootMapper;
use crate::{
    Breakpoint, BreakpointKind, DebugError, DebugEvent, Debugger, LaunchOptions, MemoryMap,
    ModuleInfo, ProcessId, RegisterSet, RunToReturnStep, StackFrame, StopReason, ThreadId,
    run_to_return_step,
};

use crate::ios::arm64;
use crate::ios::lldb_ext::{self, GenericRole, MemoryRegionInfo, ProcessInfo};
use crate::ios::rsp::{
    RspClient, RspError, RspTransport, StopReply,
    commands::{self, ZKind},
};
use crate::ios::unwind::{AppleUnwinder, Arm64UnwindRegs, MemoryReader, UnwindError};
use crate::ios::hw_breakpoints::{HwBreakpointController, HwError, HwKind};

// ---------------------------------------------------------------------------
// Transport plumbing
// ---------------------------------------------------------------------------

/// Forwarding impl so a session can hold a `Box<dyn RspTransport>` and stay
/// agnostic about whether it is talking to a socket or to
/// [`crate::ios::mock_debugserver`].
impl RspTransport for Box<dyn RspTransport> {
    fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        (**self).send(data)
    }
    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        (**self).recv(buf)
    }
    fn description(&self) -> String {
        (**self).description()
    }
    fn interrupter(&self) -> Option<Arc<dyn crate::ios::rsp::RspInterrupter>> {
        (**self).interrupter()
    }
}

/// Bridge between the crate's two transport traits.
///
/// [`crate::ios::mock_client::LoopbackTransport`] was written against
/// [`crate::ios::mock_client::AppleTransport`]; the debugger is built on
/// [`RspTransport`]. Both traits and the type are local to this crate, so the
/// impl is legal here — and it must live in the library rather than in a test
/// module, because an integration test in `tests/` could not write it (orphan
/// rule) and would otherwise be unable to reach the mock at all.
impl RspTransport for crate::ios::mock_client::LoopbackTransport {
    fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        crate::ios::mock_client::AppleTransport::send(self, data)
    }
    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        crate::ios::mock_client::AppleTransport::recv(self, buf)
    }
    fn description(&self) -> String {
        "loopback-mock-debugserver".to_string()
    }
    // `interrupter()` is left at the default `None`: this transport OWNS the
    // `MockDebugserver` and computes each reply inside `send`, so there is no
    // second handle to write `\x03` through and no window in which the client
    // is blocked. `pause()` over the loopback therefore reports Unsupported
    // with that reason, which is the truth — see `MockDebugserver::spawn_tcp`
    // for the transport shape that does support it.
}

/// A [`TransportFactory`] serving one in-process [`crate::ios::mock_debugserver`].
///
/// This is the whole reason an Apple backend can be verified from a Windows
/// host: the debugger under test is the real one, only the socket is
/// simulated. The server is handed out exactly once — a second connection
/// attempt is an error rather than a silently fresh process, because
/// "reconnecting resurrected my target" is a bug class this would otherwise
/// hide.
pub struct LoopbackFactory {
    server: Mutex<Option<crate::ios::mock_debugserver::MockDebugserver>>,
    chunk: usize,
}

impl LoopbackFactory {
    /// Serve `server`, dribbling `chunk` bytes per `recv` (0 = no limit).
    ///
    /// A small `chunk` is not pedantry: it makes "one `read()` returns one
    /// packet" — the defect already present in this workspace's other RSP
    /// client — impossible to pass.
    #[must_use]
    pub const fn new(server: crate::ios::mock_debugserver::MockDebugserver, chunk: usize) -> Self {
        Self { server: Mutex::new(Some(server)), chunk }
    }
}

impl std::fmt::Debug for LoopbackFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopbackFactory")
            .field("available", &self.server.lock().is_some())
            .field("chunk", &self.chunk)
            .finish()
    }
}

impl TransportFactory for LoopbackFactory {
    fn connect(&self, _request: &ConnectRequest<'_>) -> Result<Box<dyn RspTransport>, DebugError> {
        let server = self.server.lock().take().ok_or_else(|| {
            DebugError::Os("loopback debugserver has already been connected to".to_string())
        })?;
        let mut t = crate::ios::mock_client::LoopbackTransport::new(server);
        if self.chunk > 0 {
            t = t.with_chunk(self.chunk);
        }
        Ok(Box::new(t))
    }

    fn description(&self) -> String {
        "loopback".to_string()
    }
}

/// What the debugger is about to do, so a factory can pick the right endpoint
/// (a launch usually needs a freshly spawned `debugserver`, an attach can reuse
/// a listening one).
#[derive(Debug)]
pub enum ConnectRequest<'a> {
    /// Attach to an already-running process.
    Attach(ProcessId),
    /// Start a new process.
    Launch(&'a LaunchOptions),
}

/// Opens a byte pipe to a `debugserver`.
///
/// This is the crate's single host boundary. Spawning `debugserver` itself is
/// a macOS-only operation (and needs `com.apple.security.cs.debugger` or root),
/// so it lives in the caller's factory rather than being faked here.
pub trait TransportFactory: Send + Sync {
    /// Connect for the given operation.
    ///
    /// # Errors
    /// [`DebugError::LaunchError`] or [`DebugError::Os`] describing why the
    /// connection could not be established.
    fn connect(&self, request: &ConnectRequest<'_>) -> Result<Box<dyn RspTransport>, DebugError>;

    /// Description used in diagnostics.
    fn description(&self) -> String {
        "transport-factory".to_string()
    }
}

/// Connects to a `debugserver` already listening on a TCP endpoint
/// (`debugserver 127.0.0.1:1234 --attach=<pid>`).
#[derive(Debug, Clone)]
pub struct TcpDebugserverFactory {
    addr: String,
    timeout: Option<std::time::Duration>,
}

impl TcpDebugserverFactory {
    /// Target `addr` (`host:port`), with an optional read/write timeout.
    #[must_use]
    pub fn new(addr: impl Into<String>, timeout: Option<std::time::Duration>) -> Self {
        Self { addr: addr.into(), timeout }
    }
}

impl TransportFactory for TcpDebugserverFactory {
    fn connect(&self, _request: &ConnectRequest<'_>) -> Result<Box<dyn RspTransport>, DebugError> {
        let t = crate::ios::rsp::TcpTransport::connect(&self.addr, self.timeout)
            .map_err(|e| DebugError::Os(format!("connect to debugserver at {}: {e}", self.addr)))?;
        Ok(Box::new(t))
    }

    fn description(&self) -> String {
        format!("tcp:{}", self.addr)
    }
}

/// Reaches `debugserver` **on an iOS device over USB**, through usbmuxd.
///
/// Without this, [`crate::ios::transport::UsbmuxRspTransport`] was unreachable
/// from a live session: `AppleDebugger` is built only from a
/// [`TransportFactory`], and the only one that existed opened a TCP socket. A
/// device connected by cable could not be driven at all.
///
/// The daemon is either the host's own (`\\.\pipe\iTunes`, `/var/run/usbmuxd`,
/// with the documented TCP fallback) or an explicit TCP endpoint
/// ([`Self::at_daemon`] — `usbmuxd -t`, `usbfluxd`, an SSH forward).
#[derive(Debug, Clone)]
pub struct UsbmuxDebugserverFactory {
    /// `None` = the host's own usbmuxd; `Some` = a TCP-reachable one.
    daemon_addr: Option<String>,
    /// `None` = whichever device is attached; `Some` = exactly this UDID.
    udid: Option<String>,
    /// Device-side TCP port `debugserver` listens on.
    port: u16,
}

impl UsbmuxDebugserverFactory {
    /// Use the host's usbmuxd; `udid` selects a device (`None` = the first).
    #[must_use]
    pub fn new(udid: Option<String>, port: u16) -> Self {
        Self { daemon_addr: None, udid, port }
    }

    /// Use a usbmuxd reachable at `addr` instead of the host's own.
    #[must_use]
    pub fn at_daemon(addr: impl Into<String>, udid: Option<String>, port: u16) -> Self {
        Self { daemon_addr: Some(addr.into()), udid, port }
    }
}

impl TransportFactory for UsbmuxDebugserverFactory {
    fn connect(&self, _request: &ConnectRequest<'_>) -> Result<Box<dyn RspTransport>, DebugError> {
        // Launching a process on the device is `debugserver`'s job on the
        // far side; this factory only opens the tunnel, so Attach and Launch
        // take the same path.
        let udid = self.udid.as_deref();
        let transport = match self.daemon_addr.as_deref() {
            Some(addr) => crate::ios::transport::open_device_port_at(addr, udid, self.port),
            None => crate::ios::transport::open_device_port(udid, self.port),
        }
        .map_err(|e| DebugError::Os(format!("usbmux tunnel to {}: {e}", self.description())))?;
        Ok(Box::new(transport))
    }

    fn description(&self) -> String {
        let daemon = self.daemon_addr.as_deref().unwrap_or("host-usbmuxd");
        let device = self.udid.as_deref().unwrap_or("first-device");
        format!("usbmux:{daemon}/{device}:{}", self.port)
    }
}

// ---------------------------------------------------------------------------
// Register map
// ---------------------------------------------------------------------------

/// The target's register layout, discovered at runtime via `qRegisterInfo`.
///
/// Discovering it is not ceremony: `arm64` and `arm64e` and `x86_64` have
/// different `g`-packet layouts, and every backend that hardcoded one has
/// eventually read the wrong bytes. Nothing in this module assumes an offset.
#[derive(Debug, Clone, Default)]
pub struct RegisterMap {
    pub(crate) regs: Vec<lldb_ext::RegisterInfo>,
}

impl RegisterMap {
    /// Registers in `p`/`P` index order.
    #[must_use]
    pub fn entries(&self) -> &[lldb_ext::RegisterInfo] {
        &self.regs
    }

    /// Look a register up by name or alternate name (case-insensitive).
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&lldb_ext::RegisterInfo> {
        self.regs.iter().find(|r| {
            r.name.eq_ignore_ascii_case(name)
                || r.alt_name.as_deref().is_some_and(|a| a.eq_ignore_ascii_case(name))
        })
    }

    /// Look a register up by the role the stub assigned it.
    #[must_use]
    pub fn by_generic(&self, role: GenericRole) -> Option<&lldb_ext::RegisterInfo> {
        lldb_ext::find_generic(&self.regs, role)
    }

    /// The register holding a role, falling back to a conventional name when
    /// the stub tagged nothing (some stubs omit `generic:` entirely).
    fn role_or_name(&self, role: GenericRole, name: &str) -> Option<&lldb_ext::RegisterInfo> {
        self.by_generic(role).or_else(|| self.by_name(name))
    }

    /// Minimum `g`-packet length implied by the map, in bytes.
    #[must_use]
    pub fn g_packet_bytes(&self) -> usize {
        self.regs
            .iter()
            .filter_map(|r| r.offset.map(|o| o as usize + r.byte_size() as usize))
            .max()
            .unwrap_or(0)
    }

    /// Decode a raw `g` block into the hub crate's [`RegisterSet`].
    ///
    /// Registers wider than 64 bits (the `v` file) are skipped rather than
    /// truncated: a silently halved `v0` is worse than an absent one.
    fn decode(&self, block: &[u8]) -> RegisterSet {
        let mut set = RegisterSet::new();
        for r in &self.regs {
            let (Some(off), size) = (r.offset, r.byte_size() as usize) else {
                continue;
            };
            if size == 0 || size > 8 {
                continue;
            }
            let off = off as usize;
            let Some(raw) = block.get(off..off + size) else {
                continue;
            };
            let mut buf = [0u8; 8];
            buf[..size].copy_from_slice(raw);
            set.set(&r.name, u64::from_le_bytes(buf));
        }
        set.pc = self
            .role_or_name(GenericRole::Pc, "pc")
            .and_then(|r| set.get(&r.name))
            .unwrap_or(0);
        set.sp = self
            .role_or_name(GenericRole::Sp, "sp")
            .and_then(|r| set.get(&r.name))
            .unwrap_or(0);
        set.fp = self.role_or_name(GenericRole::Fp, "fp").and_then(|r| set.get(&r.name));
        set.lr = self.role_or_name(GenericRole::Ra, "lr").and_then(|r| set.get(&r.name));
        set
    }

    /// Overlay a [`RegisterSet`] onto an existing raw `g` block.
    ///
    /// Starting from the block that was just read (rather than from zeroes) is
    /// what keeps the vector and floating-point state intact through a
    /// read-modify-write of two integer registers.
    /// Returns the names it could NOT place, so the caller can refuse instead of
    /// reporting a write that never happened.
    ///
    /// Three ways a name goes nowhere: the target has no such register, the
    /// register is not part of the `g` block (reachable only through `p`/`P`),
    /// or it is wider than 64 bits. All three used to be silent `return`s, so
    /// `set_registers` answered `Ok(())` having written nothing — while
    /// `set_register`, the singular door, correctly calls the same name unknown.
    /// A round trip cannot trip this: `decode` fills the set using exactly these
    /// placeability rules, so everything it produced can be put back.
    fn encode_into(&self, set: &RegisterSet, block: &mut [u8]) -> Vec<String> {
        let mut dropped = Vec::new();
        let mut apply = |name: &str, value: u64, dropped: &mut Vec<String>| {
            let Some(r) = self.by_name(name) else {
                dropped.push(name.to_string());
                return;
            };
            let (Some(off), size) = (r.offset, r.byte_size() as usize) else {
                dropped.push(name.to_string());
                return;
            };
            if size == 0 || size > 8 {
                dropped.push(name.to_string());
                return;
            }
            let off = off as usize;
            if let Some(dst) = block.get_mut(off..off + size) {
                dst.copy_from_slice(&value.to_le_bytes()[..size]);
            } else {
                dropped.push(name.to_string());
            }
        };
        for (name, value) in &set.regs {
            apply(name, *value, &mut dropped);
        }
        // The generic PC/SP fields are resolved through the map, so a target
        // that names them differently is served correctly and one that has
        // neither is not reported as a failure of the caller's request.
        if let Some(r) = self.role_or_name(GenericRole::Pc, "pc") {
            let name = r.name.clone();
            apply(&name, set.pc, &mut dropped);
        }
        if let Some(r) = self.role_or_name(GenericRole::Sp, "sp") {
            let name = r.name.clone();
            apply(&name, set.sp, &mut dropped);
        }
        dropped
    }
}

// ---------------------------------------------------------------------------
// Architecture
// ---------------------------------------------------------------------------

/// `CPU_TYPE_ARM64` from `<mach/machine.h>` (`CPU_ARCH_ABI64 | CPU_TYPE_ARM`).
pub const CPU_TYPE_ARM64: u32 = 0x0100_000C;
/// `CPU_TYPE_X86_64`.
pub const CPU_TYPE_X86_64: u32 = 0x0100_0007;

/// The architecture of the attached target, as reported by `qProcessInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetArch {
    /// ARM64 without pointer authentication.
    Arm64,
    /// ARM64e — return addresses carry a PAC and must be stripped.
    Arm64e,
    /// Intel.
    X86_64,
    /// Something this backend has no register or unwind model for.
    Other(u32),
}

impl TargetArch {
    /// Classify a Mach-O `(cputype, cpusubtype)` pair.
    #[must_use]
    pub const fn from_cpu(cputype: u32, cpusubtype: u32) -> Self {
        match cputype {
            CPU_TYPE_ARM64 => {
                if cpusubtype & 0x00FF_FFFF == lldb_ext::CPU_SUBTYPE_ARM64E {
                    Self::Arm64e
                } else {
                    Self::Arm64
                }
            }
            CPU_TYPE_X86_64 => Self::X86_64,
            other => Self::Other(other),
        }
    }

    /// Name used by `supported_architectures`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Arm64 => "arm64",
            Self::Arm64e => "arm64e",
            Self::X86_64 => "x86_64",
            Self::Other(_) => "unknown",
        }
    }

    /// `true` for the two ARM64 flavours, which share a register file, a
    /// breakpoint encoding and an unwinder.
    #[must_use]
    pub const fn is_arm64(self) -> bool {
        matches!(self, Self::Arm64 | Self::Arm64e)
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Everything that only exists while a target is attached.
pub(crate) struct Session {
    pub(crate) client: RspClient<Box<dyn RspTransport>>,
    pub(crate) regs: RegisterMap,
    pid: ProcessId,
    /// Thread that reported the most recent stop.
    pub(crate) current_tid: ThreadId,
    arch: TargetArch,
}

pub(crate) fn rsp_err(context: &str, e: &RspError) -> DebugError {
    match e {
        // EACCES from the stub is a permission problem (SIP, missing
        // com.apple.security.cs.debugger), not a generic OS failure.
        RspError::Remote(0x0D) => DebugError::PermissionDenied(format!("{context}: {e}")),
        _ => DebugError::Os(format!("{context}: {e}")),
    }
}

impl Session {
    /// Ask the stub what it supports, turn off acks, and learn the register
    /// layout and architecture. Everything after this point is data-driven.
    fn establish(transport: Box<dyn RspTransport>) -> Result<Self, DebugError> {
        let mut client = RspClient::new(transport);
        client
            .handshake(&["xmlRegisters=i386,arm,arm64", "multiprocess+", "swbreak+", "hwbreak+"])
            .map_err(|e| rsp_err("qSupported handshake", &e))?;

        let regs = Self::discover_registers(&mut client)?;
        let info = Self::process_info(&mut client)?;
        let arch = TargetArch::from_cpu(info.cputype, info.cpusubtype);
        let pid = ProcessId(u32::try_from(info.pid).unwrap_or(0));

        Ok(Self { client, regs, pid, current_tid: ThreadId(0), arch })
    }

    /// Enumerate `qRegisterInfo0..` until the stub answers `E45`.
    ///
    /// The bound exists because a stub that never terminates the enumeration
    /// would otherwise hang the attach; 1024 is far beyond any real Apple
    /// register file (arm64 reports 68).
    fn discover_registers(
        client: &mut RspClient<Box<dyn RspTransport>>,
    ) -> Result<RegisterMap, DebugError> {
        const MAX_REGISTERS: u32 = 1024;
        let mut out = Vec::new();
        for n in 0..MAX_REGISTERS {
            let reply = client
                .request(lldb_ext::RegisterInfo::command(n).as_bytes())
                .map_err(|e| rsp_err("qRegisterInfo", &e))?;
            let text = reply.as_str().into_owned();
            if text.is_empty() {
                break;
            }
            match lldb_ext::RegisterInfo::parse(n, &text) {
                Ok(info) => out.push(info),
                // `E45` is the documented end-of-list marker, not a failure.
                Err(lldb_ext::LldbExtError::ErrorReply { .. }) => break,
                Err(e) => {
                    return Err(DebugError::RegisterError(format!(
                        "qRegisterInfo{n:x} reply not understood: {e}"
                    )));
                }
            }
        }
        if out.is_empty() {
            return Err(DebugError::RegisterError(
                "stub advertised no registers via qRegisterInfo; this backend refuses to \
                 guess a g-packet layout"
                    .to_string(),
            ));
        }
        Ok(RegisterMap { regs: out })
    }

    fn process_info(
        client: &mut RspClient<Box<dyn RspTransport>>,
    ) -> Result<ProcessInfo, DebugError> {
        let reply = client
            .request(ProcessInfo::COMMAND.as_bytes())
            .map_err(|e| rsp_err("qProcessInfo", &e))?;
        ProcessInfo::parse(&reply.as_str())
            .map_err(|e| DebugError::Os(format!("qProcessInfo reply not understood: {e}")))
    }

    /// Send a raw packet and return the reply text.
    pub(crate) fn text(&mut self, payload: &[u8], what: &str) -> Result<String, DebugError> {
        let reply = self.client.request(payload).map_err(|e| rsp_err(what, &e))?;
        Ok(reply.as_str().into_owned())
    }

    /// Point `Hg`/`Hc` at `tid`, so a subsequent register or resume packet acts
    /// on the thread the caller named rather than on whatever was last stopped.
    pub(crate) fn select_thread(&mut self, tid: ThreadId) -> Result<(), DebugError> {
        if tid.0 == 0 {
            return Ok(());
        }
        for op in [commands::HOp::General, commands::HOp::Continue] {
            let reply = self.text(&commands::set_thread(op, Some(u64::from(tid.0))), "H")?;
            if !reply.starts_with("OK") {
                return Err(DebugError::Os(format!(
                    "stub rejected thread selection for {tid}: {reply}"
                )));
            }
        }
        Ok(())
    }

    fn read_register_set(&mut self, tid: ThreadId) -> Result<RegisterSet, DebugError> {
        self.select_thread(tid)?;
        let block = self.client.read_registers().map_err(|e| rsp_err("g", &e))?;
        if block.len() < self.regs.g_packet_bytes() {
            return Err(DebugError::RegisterError(format!(
                "g packet is {} bytes but qRegisterInfo describes {}",
                block.len(),
                self.regs.g_packet_bytes()
            )));
        }
        Ok(self.regs.decode(&block))
    }
}

// ---------------------------------------------------------------------------
// Breakpoint bookkeeping
// ---------------------------------------------------------------------------

/// Number of bytes an A64 software breakpoint occupies.
const A64_BP_LEN: u32 = 4;

/// Which finite resource a breakpoint occupies at an address.
///
/// An execution trap in the code and a debug register watching that same
/// location are INDEPENDENT: a caller may legitimately hold both, to stop when
/// a function is entered and again when a variable it owns is written. Keying
/// the tracking map by address alone made the second request fail with
/// `BreakpointExists`, which is true about the address and wrong about the
/// resource — the debugger refusing something the hardware allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum BpClass {
    /// `Z0`/`Z1` — a trap in the instruction stream.
    Code,
    /// `Z2`/`Z3`/`Z4` — a debug register watching data.
    Data,
}

impl BpClass {
    const fn of(kind: BreakpointKind) -> Self {
        match kind {
            BreakpointKind::Software | BreakpointKind::Hardware => Self::Code,
            _ => Self::Data,
        }
    }
}

#[derive(Debug, Clone)]
struct BpRecord {
    bp: Breakpoint,
    /// Original instruction bytes, set only when the stub did not support `Z0`
    /// and this backend had to patch `BRK` in itself.
    saved: Option<Vec<u8>>,
    /// Width, in bytes, this resource occupies in the debug registers, for the
    /// hardware kinds only. Recorded because re-enabling a disabled watchpoint
    /// has to re-arm the SAME width: without it the re-arm fell back to the
    /// generic 8 bytes from `z_kind_for`, silently widening a 4-byte watchpoint
    /// over its neighbour — the exact defect
    /// `a_sized_watchpoint_covers_exactly_the_requested_width` exists to catch,
    /// reached through the disable/enable door instead of the set door.
    hw_size: Option<usize>,
}

const fn z_kind_for(kind: BreakpointKind) -> (ZKind, u32) {
    match kind {
        BreakpointKind::Software => (ZKind::Software, A64_BP_LEN),
        BreakpointKind::Hardware => (ZKind::Hardware, A64_BP_LEN),
        // Watchpoint "size" is the watched region, not an instruction length.
        BreakpointKind::DataRead => (ZKind::ReadWatch, 8),
        BreakpointKind::DataWrite => (ZKind::WriteWatch, 8),
        BreakpointKind::DataReadWrite => (ZKind::AccessWatch, 8),
    }
}

/// The debug-register class a `BreakpointKind` occupies, or `None` for a
/// software breakpoint (which consumes no debug register and is therefore not
/// the slot table's business).
const fn hw_kind_for(kind: BreakpointKind) -> Option<HwKind> {
    match kind {
        BreakpointKind::Software => None,
        BreakpointKind::Hardware => Some(HwKind::Breakpoint),
        BreakpointKind::DataRead => Some(HwKind::ReadWatch),
        BreakpointKind::DataWrite => Some(HwKind::WriteWatch),
        BreakpointKind::DataReadWrite => Some(HwKind::AccessWatch),
    }
}

/// Map a slot-table failure onto the hub crate's error, PRESERVING the
/// distinction the `HwError` variants exist to draw. In particular the
/// exhaustion message ("no hardware breakpoint slot free (N implemented …)")
/// is this side's own statement of fact, made before any packet is sent — it
/// must not be flattened into the generic "stub does not support …" that used
/// to be the only thing a caller ever saw.
fn hw_err(e: HwError) -> DebugError {
    match e {
        HwError::Duplicate { addr, .. } => DebugError::BreakpointExists(addr),
        HwError::NotFound { addr, .. } => DebugError::BreakpointNotFound(addr),
        HwError::Rsp(ref inner) => rsp_err("hardware breakpoint", inner),
        other => DebugError::Unsupported(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Memory reader bridging RSP into the unwinder
// ---------------------------------------------------------------------------

/// Adapts a live RSP connection to [`MemoryReader`].
///
/// The `Mutex` is not for cross-thread sharing — it is the only way to satisfy
/// `MemoryReader::read(&self, ..)` while `RspClient::read_memory` needs
/// `&mut self`. The lock is uncontended by construction: the session mutex is
/// already held by the caller.
struct RspMemory<'a> {
    client: Mutex<&'a mut RspClient<Box<dyn RspTransport>>>,
}

impl MemoryReader for RspMemory<'_> {
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<(), UnwindError> {
        let data = self
            .client
            .lock()
            .read_memory(addr, buf.len())
            .map_err(|_| UnwindError::MemoryRead { addr, len: buf.len() })?;
        if data.len() != buf.len() {
            return Err(UnwindError::MemoryRead { addr, len: buf.len() });
        }
        buf.copy_from_slice(&data);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The debugger
// ---------------------------------------------------------------------------

/// A `crate::Debugger` backed by an Apple `debugserver`.
///
/// Construct with a [`TransportFactory`]; the debugger owns no socket until
/// [`Debugger::launch`] or [`Debugger::attach`] is called.
pub struct AppleDebugger {
    factory: Arc<dyn TransportFactory>,
    session: Mutex<Option<Session>>,
    /// Address-keyed so `remove`/`enable`/`disable` are O(log n) and the
    /// enumeration order is deterministic (a `HashMap` made one backend's
    /// `breakpoints()` output shuffle between calls).
    /// Keyed by `(address, class)`: see [`BpClass`]. One address can carry
    /// a code trap AND a data watchpoint at the same time.
    breakpoints: RwLock<BTreeMap<(u64, BpClass), BpRecord>>,
    /// Out-of-band write handle for the live session's transport.
    ///
    /// Held *outside* `session` on purpose: `resume` owns the session mutex for
    /// the entire time the target is running, which is precisely when `pause`
    /// needs to write. Cloned out of the client at attach/launch time (the last
    /// moment `&RspClient` is reachable without contending with a runner) and
    /// dropped at detach/kill.
    interrupter: RwLock<Option<Arc<dyn crate::ios::rsp::RspInterrupter>>>,
    /// `true` while a resume packet is outstanding — i.e. while the target is
    /// running and a reader is parked on the transport.
    ///
    /// This flag is what keeps `pause` from desynchronising the framer. `\x03`
    /// sent when no resume is outstanding makes the stub emit a stop reply that
    /// no request is waiting for, and the *next* command reads it as its own
    /// answer — a silently wrong result, the worst failure shape available
    /// here. It lives under its own mutex, never the session mutex, which the
    /// runner is holding for the whole run.
    resume_in_flight: Mutex<bool>,
    /// Lock-free mirror of "is there a session", and of its pid.
    ///
    /// Same reasoning as `interrupter` and `resume_in_flight` above, applied to
    /// the STATUS queries: `resume` holds the session mutex for as long as the
    /// target runs, so anything that answers by locking it stops answering the
    /// moment the target starts. `is_attached`, `target_pid` and even the
    /// `Debug` impl did exactly that — a `{:?}` on a running debugger blocked
    /// the formatting thread until the run ended, which turns a log line into a
    /// hang. These two are written at attach/detach and only read elsewhere.
    attached: AtomicBool,
    /// Target pid, or 0 when detached. Meaningful only while `attached`.
    pid: AtomicU32,
    resolver: RwLock<Option<Arc<dyn FrameSymbolResolver>>>,
    /// When set, the first `backtrace()` of a session with no resolver builds
    /// one from the target's own images. Off means frames stay nameless unless
    /// the caller installs a resolver itself.
    auto_load_symbols: AtomicBool,
    /// Latch: reading every loaded image out of the target is expensive, so the
    /// automatic load is attempted at most once per session — including when it
    /// fails, otherwise a stub without `jGetLoadedDynamicLibrariesInfos` would
    /// pay for the attempt on every single backtrace.
    auto_load_attempted: AtomicBool,
    /// How many times the automatic load actually read the target. Observable
    /// so a test can prove "lazily, and once" rather than assume it.
    auto_load_attempts: AtomicUsize,
    /// Set when the resolver in `resolver` is the auto-built one.
    auto_installed: AtomicBool,
    /// dSYMs the caller offered for this target, in the order offered.
    ///
    /// They are held rather than attached immediately because a dSYM can only
    /// be VERIFIED against an image, and the images are not known until a
    /// session exists. Each one is matched by `LC_UUID` when the symbol load
    /// runs; a bundle that matches nothing loaded is refused there and its
    /// error recorded in `dsym_errors`, never approximated onto a near-miss
    /// image.
    dsyms: RwLock<Vec<crate::ios::dsym::DsymBundle>>,
    /// Source-root substitutions applied to the paths the DWARF carries, so a
    /// build-machine path can be pointed at the local checkout.
    source_roots: RwLock<SourceRootMapper>,
    /// Why each offered dSYM was not used, from the most recent symbol load.
    /// Empty when every one attached.
    dsym_errors: RwLock<Vec<String>>,
    /// Cap on `step_out` iterations, so a runaway loop surfaces as an error
    /// rather than as a hang.
    max_step_out_instructions: usize,
    /// Accounting for the target's FINITE `DBGBVR`/`DBGWVR` files.
    ///
    /// Before this existed every hardware breakpoint and watchpoint went out as
    /// a bare `Z1`/`Z2`/`Z3`/`Z4` with no idea how many debug registers the core
    /// has, so exhaustion was whatever the stub happened to say — one stub
    /// answers `E..`, another silently accepts and drops the oldest, and a third
    /// (`debugserver` on a device where the request outruns the hardware)
    /// reports a breakpoint that never fires. The slot table makes this side
    /// know: allocation happens here, refusal happens BEFORE a packet is sent,
    /// and removal frees the slot for reuse.
    ///
    /// `None` until the first hardware request, because the capacity comes from
    /// the target (`qHardwareBreakpointSupportInfo` /
    /// `qWatchpointSupportInfo`) and there is no target at construction time.
    /// Reset at detach/kill together with the breakpoint table.
    hw: Mutex<Option<HwBreakpointController>>,
    /// Name→runtime-address table used by [`AppleDebugger::evaluate`].
    ///
    /// Filled from the target's own images by `load_symbols_from_target`, and
    /// cleared when the session ends: a table built from the departed process
    /// describes nothing about a later one, and an expression resolved against
    /// it would be confidently wrong rather than merely unresolved.
    expr_symbols: RwLock<crate::ios::expr::AppleSymbols>,
}

/// Sets [`AppleDebugger::resume_in_flight`] for its lifetime.
struct ResumeGuard<'a> {
    flag: &'a Mutex<bool>,
}

impl Drop for ResumeGuard<'_> {
    fn drop(&mut self) {
        *self.flag.lock() = false;
    }
}

impl std::fmt::Debug for AppleDebugger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleDebugger")
            .field("transport", &self.factory.description())
            .field("attached", &self.attached.load(Ordering::SeqCst))
            .field("breakpoints", &self.breakpoints.read().len())
            .finish()
    }
}

impl Drop for AppleDebugger {
    /// Best-effort cleanup for a session that goes out of scope still attached.
    ///
    /// Same contract the other three backends grew in iters 249-250: a
    /// debugger that disappears must leave the target running, not carrying
    /// the instructions this backend patched into it. Only the manual
    /// fallback breakpoints are ours to undo — the `Z0` ones belong to the
    /// stub, which drops them when the connection does.
    ///
    /// After an explicit `detach()`/`kill()` there is no session left and this
    /// is a no-op, which is correct.
    fn drop(&mut self) {
        let mut guard = self.session.lock();
        let Some(session) = guard.as_mut() else { return };
        for record in self.breakpoints.read().values() {
            let Some(saved) = record.saved.as_ref() else { continue };
            let _ = session.client.write_memory(record.bp.address.as_u64(), saved);
        }
    }
}

impl AppleDebugger {
    /// Build a debugger that reaches its target through `factory`.
    #[must_use]
    pub fn new(factory: Arc<dyn TransportFactory>) -> Self {
        Self {
            factory,
            session: Mutex::new(None),
            breakpoints: RwLock::new(BTreeMap::new()),
            interrupter: RwLock::new(None),
            resume_in_flight: Mutex::new(false),
            attached: AtomicBool::new(false),
            pid: AtomicU32::new(0),
            resolver: RwLock::new(None),
            auto_load_symbols: AtomicBool::new(true),
            auto_load_attempted: AtomicBool::new(false),
            auto_load_attempts: AtomicUsize::new(0),
            auto_installed: AtomicBool::new(false),
            dsyms: RwLock::new(Vec::new()),
            source_roots: RwLock::new(SourceRootMapper::new()),
            dsym_errors: RwLock::new(Vec::new()),
            max_step_out_instructions: 200_000,
            hw: Mutex::new(None),
            expr_symbols: RwLock::new(crate::ios::expr::AppleSymbols::new()),
        }
    }

    /// Reach a `debugserver` listening on `addr` (`host:port`).
    #[must_use]
    pub fn tcp(addr: impl Into<String>, timeout: Option<std::time::Duration>) -> Self {
        Self::new(Arc::new(TcpDebugserverFactory::new(addr, timeout)))
    }

    /// Reach `debugserver` on a USB-connected iOS device through usbmuxd.
    #[must_use]
    pub fn usbmux(udid: Option<String>, port: u16) -> Self {
        Self::new(Arc::new(UsbmuxDebugserverFactory::new(udid, port)))
    }

    /// As [`Self::usbmux`], but against a usbmuxd reachable at `daemon_addr`.
    #[must_use]
    pub fn usbmux_at(daemon_addr: impl Into<String>, udid: Option<String>, port: u16) -> Self {
        Self::new(Arc::new(UsbmuxDebugserverFactory::at_daemon(
            daemon_addr,
            udid,
            port,
        )))
    }

    /// Override the `step_out` instruction budget.
    #[must_use]
    pub const fn with_max_step_out_instructions(mut self, n: usize) -> Self {
        self.max_step_out_instructions = n;
        self
    }

    /// Turn the automatic first-backtrace symbol load on or off at build time.
    #[must_use]
    pub fn with_auto_load_symbols(self, enabled: bool) -> Self {
        self.auto_load_symbols.store(enabled, Ordering::SeqCst);
        self
    }

    /// Turn the automatic first-backtrace symbol load on or off on a live
    /// debugger. Enabling it re-arms the once-per-session latch, so a caller
    /// that switched it off before the first backtrace still gets one load.
    pub fn set_auto_load_symbols(&self, enabled: bool) {
        self.auto_load_symbols.store(enabled, Ordering::SeqCst);
        if enabled {
            self.auto_load_attempted.store(false, Ordering::SeqCst);
        }
    }

    /// Offer a dSYM for this target's images.
    ///
    /// It is not attached here: a dSYM is bound to an image by `LC_UUID`, and
    /// the loaded images are only known once a session exists and its symbols
    /// have been read. The binding — and the refusal when no loaded image
    /// carries that UUID — happens in [`Self::load_symbols_from_target`].
    ///
    /// Offering the same bundle twice is not silently deduplicated: the second
    /// attach is reported as a duplicate through [`Self::dsym_attach_errors`],
    /// because "I gave it two dSYMs and it used one" is a fact the caller
    /// should see.
    pub fn add_dsym(&self, bundle: crate::ios::dsym::DsymBundle) {
        self.dsyms.write().push(bundle);
    }

    /// Open a `.dSYM` bundle directory (or a bare DWARF payload) and offer it.
    ///
    /// # Errors
    /// Propagates the dSYM/Mach-O parse failure. A path that is not a usable
    /// dSYM is an error at the call site rather than a bundle that silently
    /// never matches anything.
    pub fn add_dsym_path(&self, path: &std::path::Path) -> Result<(), DebugError> {
        let bundle = crate::ios::dsym::DsymBundle::open_bundle(path)
            .or_else(|_| crate::ios::dsym::DsymBundle::open_payload(path))
            .map_err(|e| DebugError::Os(format!("dSYM {}: {e}", path.display())))?;
        self.add_dsym(bundle);
        Ok(())
    }

    /// How many dSYMs have been offered (not how many matched an image).
    #[must_use]
    pub fn dsym_count(&self) -> usize {
        self.dsyms.read().len()
    }

    /// Replace the source-root substitutions applied to DWARF paths.
    pub fn set_source_roots(&self, roots: SourceRootMapper) {
        *self.source_roots.write() = roots;
    }

    /// Why each offered dSYM was rejected by the most recent symbol load.
    ///
    /// Empty means every offered dSYM was bound to an image. This is the
    /// honest-failure channel: a rejected dSYM contributes no line numbers at
    /// all, and this says which one and why.
    #[must_use]
    pub fn dsym_attach_errors(&self) -> Vec<String> {
        self.dsym_errors.read().clone()
    }

    /// Whether the automatic first-backtrace symbol load is armed.
    #[must_use]
    pub fn auto_load_symbols_enabled(&self) -> bool {
        self.auto_load_symbols.load(Ordering::SeqCst)
    }

    /// Whether the resolver currently installed is the one the automatic load
    /// built. A resolver the CALLER installed is theirs and is left alone
    /// across sessions; the auto-built one describes a specific process and is
    /// dropped with it.
    #[must_use]
    pub fn auto_installed_resolver(&self) -> bool {
        self.auto_installed.load(Ordering::SeqCst)
    }

    /// How many times the automatic load has read the target in this session.
    /// It is capped at one; a second reading is a bug, not a tuning question.
    #[must_use]
    pub fn auto_load_attempts(&self) -> usize {
        self.auto_load_attempts.load(Ordering::SeqCst)
    }

    /// Re-arm the automatic load. Called when a session begins or ends, since
    /// a resolver built from one process describes nothing about the next.
    fn reset_auto_load(&self) {
        self.auto_load_attempted.store(false, Ordering::SeqCst);
        self.auto_load_attempts.store(0, Ordering::SeqCst);
        // Symbols of a process this debugger is no longer talking to.
        *self.expr_symbols.write() = crate::ios::expr::AppleSymbols::new();
        if self.auto_installed.swap(false, Ordering::SeqCst) {
            *self.resolver.write() = None;
        }
    }

    /// Install a resolver built from the target's images, at most once per
    /// session, and only when nothing else has claimed the resolver slot.
    ///
    /// Errors are deliberately swallowed: a `backtrace()` that recovered real
    /// frames must not be turned into a failure because the stub cannot
    /// enumerate its images. The latch is set either way, so the failure is
    /// paid for once.
    async fn maybe_auto_load_symbols(&self) {
        if !self.auto_load_symbols.load(Ordering::SeqCst) {
            return;
        }
        if self.resolver.read().is_some() {
            return;
        }
        if self.auto_load_attempted.swap(true, Ordering::SeqCst) {
            return;
        }
        self.auto_load_attempts.fetch_add(1, Ordering::SeqCst);
        if self.load_symbols_from_target().await.is_ok() {
            self.auto_installed.store(true, Ordering::SeqCst);
        }
    }

    /// The target architecture, once attached.
    #[must_use]
    pub fn target_arch(&self) -> Option<TargetArch> {
        self.session.lock().as_ref().map(|s| s.arch)
    }

    /// The runtime-discovered register layout, once attached.
    #[must_use]
    pub fn register_map(&self) -> Option<RegisterMap> {
        self.session.lock().as_ref().map(|s| s.regs.clone())
    }

    /// Run `f` with the live session, or fail with [`DebugError::NotAttached`].
    pub(crate) fn with_session<R>(
        &self,
        f: impl FnOnce(&mut Session) -> Result<R, DebugError>,
    ) -> Result<R, DebugError> {
        let mut guard = self.session.lock();
        let session = guard.as_mut().ok_or(DebugError::NotAttached)?;
        f(session)
    }

    /// Run `f` with the hardware slot table and the live session's client.
    ///
    /// The table is built on first use from what the TARGET reports, not from
    /// the Apple defaults, because an over-estimate turns into a stub rejection
    /// at the worst possible moment and an under-estimate refuses a slot that
    /// exists. The `hw` mutex is only ever taken while the session mutex is
    /// held, so the pair has a single lock order and cannot invert.
    pub(crate) fn with_hw<R>(
        &self,
        f: impl FnOnce(
            &mut HwBreakpointController,
            &mut RspClient<Box<dyn RspTransport>>,
        ) -> Result<R, DebugError>,
    ) -> Result<R, DebugError> {
        self.with_session(|s| {
            let mut guard = self.hw.lock();
            if guard.is_none() {
                *guard = Some(HwBreakpointController::from_target(&mut s.client).map_err(hw_err)?);
            }
            let controller = guard.as_mut().expect("initialised immediately above");
            f(controller, &mut s.client)
        })
    }

    /// Turn a stop reply into the hub crate's event, consulting the breakpoint
    /// table so a `SIGTRAP` at a registered address is reported as a
    /// breakpoint hit rather than as a bare signal.
    fn classify(&self, session: &mut Session, reply: &StopReply) -> Result<DebugEvent, DebugError> {
        let pid = session.pid;
        match reply {
            StopReply::Exited { status } => {
                // The process is gone, and every byte this backend patched into
                // it went with it. Keeping the records hands the NEXT target a
                // table of breakpoints that exist nowhere: `set_breakpoint`
                // answers `BreakpointExists` for an address with nothing
                // planted, and `detach`'s restore sweep would write "saved
                // originals" into a process that never had them. `kill()`
                // already drops the table for exactly this reason — a natural
                // exit needs it just as much, and is the far commoner way for a
                // target to end.
                //
                // Unlike Windows/Linux (iter 287) the SESSION is not retired
                // here: the debugserver connection outlives the process, so
                // "the target exited" and "the session is over" are different
                // facts on this transport, and only the first one is known.
                self.breakpoints.write().clear();
                // The debug registers went with the process; keeping the slot
                // table would refuse a breakpoint on the NEXT target because a
                // dead one's watchpoints still "occupy" its registers.
                *self.hw.lock() = None;
                Ok(DebugEvent::new(
                    pid,
                    session.current_tid,
                    StopReason::ProcessExit { exit_code: i32::from(*status) },
                ))
            }
            // KILLED BY A SIGNAL — an ENDING, not a stop.
            //
            // `X` means the process died of that signal, and `StopReply::is_exit`
            // says exactly that one layer down. Reporting it as
            // `StopReason::Signal` told the caller the target had merely stopped
            // and could be resumed, so every `while !ev.reason.is_exit()` loop
            // went on resuming a corpse — and the tables the `W` branch above
            // clears stayed populated, handing the NEXT target breakpoints that
            // exist nowhere and debug-register slots occupied by a dead process.
            //
            // Both unix backends already encode a signal death as
            // `ProcessExit { exit_code: -signal }`; this uses the same encoding
            // rather than inventing a fourth convention.
            StopReply::Terminated { signal } => {
                self.breakpoints.write().clear();
                *self.hw.lock() = None;
                Ok(DebugEvent::new(
                    pid,
                    session.current_tid,
                    StopReason::ProcessExit { exit_code: -i32::from(*signal) },
                ))
            }
            StopReply::Signal { signal } | StopReply::SignalWithInfo { signal, .. } => {
                if let StopReply::SignalWithInfo { thread: Some(tid), .. } = reply {
                    session.current_tid = ThreadId(u32::try_from(*tid).unwrap_or(0));
                }
                let reason_field = match reply {
                    StopReply::SignalWithInfo { pairs, .. } => pairs
                        .iter()
                        .find(|(k, _)| k == "reason")
                        .map(|(_, v)| v.clone()),
                    StopReply::Signal { .. } => None,
                    _ => unreachable!("outer match restricts this arm to signal replies"),
                };
                // Read the PC back rather than trusting the expedited register
                // list: which registers are expedited is stub-dependent, and a
                // breakpoint misattributed to the wrong address is worse than
                // one extra round trip.
                //
                // And when that round trip FAILS there is no PC — `unwrap_or(0)`
                // fabricated one, which is the very misattribution the sentence
                // above refuses: a stop at a registered breakpoint was looked up
                // at address 0, found nothing, and came back as a bare signal
                // with `address: Some(0)`, its hit uncounted, while the caller
                // was handed a program counter the target never had. An
                // unreadable register block is a real failure of this stop's
                // classification and is reported as one.
                let tid = session.current_tid;
                let pc = session.read_register_set(tid).map(|r| r.pc).map_err(|e| {
                    DebugError::RegisterError(format!(
                        "stop reply for {tid} could not be classified: reading the program \
                         counter failed: {e}"
                    ))
                })?;
                let pairs_slice: &[(String, String)] = match reply {
                    StopReply::SignalWithInfo { pairs, .. } => pairs,
                    _ => &[],
                };
                Ok(DebugEvent::new(
                    pid,
                    tid,
                    self.stop_reason_at(pc, *signal, reason_field.as_deref(), pairs_slice),
                ))
            }
        }
    }

    fn stop_reason_at(
        &self,
        pc: u64,
        signal: u8,
        reason: Option<&str>,
        pairs: &[(String, String)],
    ) -> StopReason {
        let addr = Address::new(pc);
        if let Some(rec) = self.breakpoints.write().get_mut(&(pc, BpClass::Code)) {
            if rec.bp.enabled {
                rec.bp.hit_count += 1;
                return StopReason::Breakpoint { address: addr, bp: rec.bp.clone() };
            }
        }
        // A WATCHPOINT hit names the address that was TOUCHED, and the stub
        // already says which one: lldb's stop reply carries `watch:`, `rwatch:`
        // or `awatch:` with the watched address. All three were thrown away and
        // the reply was built from the PC instead, so the caller was told the
        // program had touched the address of the instruction — the one thing a
        // watchpoint report exists to answer, answered with the wrong number.
        // The direction was hard-wired to `is_write: true` as well, so every
        // read watch was reported as a write.
        //
        // The hit is COUNTED here too, on the DATA record: `breakpoints()`
        // publishes `hit_count`, and a watchpoint that stops the program over
        // and over was reporting zero hits forever.
        //
        // The PC is deliberately NOT rewound for these — it is the data address
        // that is being reported, and writing it into the PC would send the
        // target off to execute its own variables.
        if let Some((watched, key)) = pairs.iter().find_map(|(k, v)| {
            matches!(k.as_str(), "watch" | "rwatch" | "awatch")
                .then(|| {
                    u64::from_str_radix(v.trim().trim_start_matches("0x"), 16)
                        .ok()
                        .map(|a| (a, k.as_str()))
                })
                .flatten()
        }) {
            if let Some(rec) = self.breakpoints.write().get_mut(&(watched, BpClass::Data)) {
                if rec.bp.enabled {
                    rec.bp.hit_count += 1;
                }
            }
            // `rwatch` is a read watch and can only have fired on a read.
            // `awatch` fires on either and the reply does not say which, so it
            // keeps the write-ish default rather than claiming a read.
            return StopReason::AccessViolation {
                address: Address::new(watched),
                is_write: key != "rwatch",
            };
        }
        match reason {
            Some("trace") => StopReason::SingleStep { address: addr },
            // `reason:watchpoint` with no address key: the stub says a watchpoint
            // fired but not which. The PC is the only address in hand and is
            // reported as before — wrong, but no longer the common case, and
            // inventing an address from our own table would be a guess.
            Some("watchpoint") => StopReason::AccessViolation { address: addr, is_write: true },
            _ => StopReason::Signal {
                signum: i32::from(signal),
                signame: signal_name(signal).to_string(),
                address: Some(addr),
            },
        }
    }

    /// Mark a resume as outstanding for as long as the guard lives.
    ///
    /// A guard rather than two assignments so an early `?` or a panic inside
    /// the resume cannot leave the flag stuck at `true` — which would make
    /// every later `pause()` fire `\x03` at a stopped target.
    fn resume_guard(&self) -> ResumeGuard<'_> {
        *self.resume_in_flight.lock() = true;
        ResumeGuard { flag: &self.resume_in_flight }
    }

    /// Resume and wait, with `vCont` and a `c`/`s` fallback for stubs that do
    /// not advertise `vCont`.
    /// Step off a trap this backend patched in itself, so the target can get
    /// past its own breakpoint.
    ///
    /// On AArch64 a `BRK` exception is PRECISE: the program counter stays on the
    /// trap. Resuming therefore re-executes it and stops again at the same
    /// address, forever — the target could not pass any breakpoint it hit. The
    /// three native backends grew this step-off long ago; this fourth `Debugger`
    /// impl never had it.
    ///
    /// Only for SELF-PATCHED records: a `Z0` the stub installed is the stub's to
    /// step off, and doing it here as well would restore bytes over memory we
    /// never patched.
    ///
    /// Returns the stop event when the single step was actually taken, so the
    /// caller can hand it straight back for a `single_step` request or notice
    /// that the target died mid-step.
    fn step_off_planted_breakpoint(
        &self,
        tid: Option<ThreadId>,
    ) -> Result<Option<DebugEvent>, DebugError> {
        // The session's own idea of the selected thread when the caller named
        // none. Not `current_thread()`, which is async and may issue `qC`: this
        // runs on the resume path and must not add a round trip.
        let t = match tid {
            Some(t) => t,
            None => match self.with_session(|s| Ok(s.current_tid)) {
                Ok(t) if t.0 != 0 => t,
                _ => return Ok(None),
            },
        };
        let Ok(pc) = self.with_session(|s| s.read_register_set(t)).map(|r| r.pc) else {
            return Ok(None);
        };
        let saved = {
            let guard = self.breakpoints.read();
            match guard.get(&(pc, BpClass::Code)) {
                Some(rec) if rec.bp.enabled => rec.saved.clone(),
                _ => None,
            }
        };
        let Some(original) = saved else { return Ok(None) };

        // Uncover the instruction, take exactly one step, put the trap back.
        self.with_session(|s| {
            s.client
                .write_memory(pc, &original)
                .map(drop)
                .map_err(|e| DebugError::MemoryError(pc, format!("unpatch to step off: {e}")))
        })?;
        let stepped = self.resume_raw(Some(t), true);
        // Re-plant even when the step failed: leaving the breakpoint uncovered
        // would silently disarm it while it is still listed as enabled. Skipped
        // only if the record disappeared meanwhile.
        let still_tracked = self
            .breakpoints
            .read()
            .get(&(pc, BpClass::Code))
            .is_some_and(|rec| rec.bp.enabled && rec.saved.is_some());
        if still_tracked {
            let _ = self.with_session(|s| {
                s.client
                    .write_memory(pc, &arm64::brk_bytes(0))
                    .map(drop)
                    .map_err(|e| DebugError::MemoryError(pc, format!("replant BRK: {e}")))
            });
        }
        stepped.map(Some)
    }

    /// Resume, stepping off a self-planted trap at the program counter first.
    fn resume(&self, tid: Option<ThreadId>, step: bool) -> Result<DebugEvent, DebugError> {
        if let Some(ev) = self.step_off_planted_breakpoint(tid)? {
            // The step-off IS the single step the caller asked for; running a
            // second one would silently execute two instructions.
            if step {
                return Ok(ev);
            }
            // And if that one instruction ended the process or faulted, there is
            // nothing left to continue.
            if ev.reason.is_exit() || !matches!(ev.reason, StopReason::SingleStep { .. }) {
                return Ok(ev);
            }
        }
        self.resume_raw(tid, step)
    }

    /// The resume itself, with no breakpoint bookkeeping.
    fn resume_raw(&self, tid: Option<ThreadId>, step: bool) -> Result<DebugEvent, DebugError> {
        let reply = self.with_session(|s| {
            // Thread selection happens BEFORE the flag is raised: an `\x03`
            // landing during `H` would have its stop reply mistaken for the
            // `H` acknowledgement.
            if let Some(t) = tid {
                s.select_thread(t)?;
            }
            let verb = if step { "s" } else { "c" };
            let action: (&str, Option<u64>) = (verb, tid.map(|t| u64::from(t.0)));
            let running = self.resume_guard();
            let text = s.text(&commands::vcont(&[action]), "vCont")?;
            let raw = if text.is_empty() {
                // Empty reply == "packet unsupported"; fall back to the legacy
                // single-letter resume rather than reporting a phantom stop.
                let legacy = if step { commands::step(None) } else { commands::cont(None) };
                s.text(&legacy, verb)?
            } else {
                text
            };
            drop(running);
            StopReply::parse(raw.as_bytes())
                .map_err(|e| DebugError::StepError(format!("stop reply {raw:?}: {e}")))
        })?;
        let mut guard = self.session.lock();
        let session = guard.as_mut().ok_or(DebugError::NotAttached)?;
        self.classify(session, &reply)
    }

    /// Replace this backend's own planted traps with the bytes they cover.
    ///
    /// Only the SELF-PATCHED records (`saved: Some`), taken when the stub
    /// refused `Z0`. A trap the stub planted is the stub's to hide, and masking
    /// it here as well would write bytes over memory we never patched.
    fn mask_self_planted_traps(&self, base: u64, buf: &mut [u8]) {
        let guard = self.breakpoints.read();
        crate::unpatch_planted_breakpoints(base, buf, |a| {
            guard.iter().find_map(|((bp_base, _), rec)| {
                if !rec.bp.enabled {
                    return None;
                }
                let orig = rec.saved.as_ref()?;
                let off = usize::try_from(a.checked_sub(*bp_base)?).ok()?;
                orig.get(off).copied()
            })
        });
    }

    /// Read the 4-byte A64 instruction at `pc`.
    ///
    /// MASKED, and that is the whole point: this is called by `step_over` on the
    /// instruction the target is stopped at — which, after a breakpoint hit, is
    /// precisely where one of our own `BRK #0` words sits. Reading raw memory
    /// decoded the TRAP instead of the instruction, `BranchKind::decode` saw no
    /// call, and `step_over` quietly degraded to a plain single step: stepping
    /// over a `bl` at a breakpoint address stepped INTO the function. Silent,
    /// and exactly at the moment breakpoints are being used.
    fn instruction_at(&self, pc: u64) -> Result<u32, DebugError> {
        let mut bytes = self.with_session(|s| {
            s.client
                .read_memory(pc, 4)
                .map_err(|e| DebugError::MemoryError(pc, format!("read instruction: {e}")))
        })?;
        self.mask_self_planted_traps(pc, &mut bytes);
        let bytes = bytes;
        arm64::word_from_le(&bytes)
            .ok_or_else(|| DebugError::MemoryError(pc, "short instruction read".to_string()))
    }

    fn require_arm64(&self, what: &str) -> Result<(), DebugError> {
        let arch = self
            .session
            .lock()
            .as_ref()
            .map(|s| s.arch)
            .ok_or(DebugError::NotAttached)?;
        if arch.is_arm64() {
            Ok(())
        } else {
            Err(DebugError::Unsupported(format!(
                "{what} is implemented for arm64/arm64e only; target reports {}",
                arch.name()
            )))
        }
    }

    /// Walk the address space with `qMemoryRegionInfo`.
    ///
    /// Seeded rather than swept from zero on purpose: the reply for an unmapped
    /// address carries no hole size, so a blind forward walk cannot skip a gap
    /// and would stop at the first one. Seeding from the loaded images and the
    /// current thread's PC/SP finds the regions that actually matter, and each
    /// seed is then followed forward while the regions stay contiguous.
    fn walk_memory_regions(&self, seeds: &[u64]) -> Result<Vec<MemoryMap>, DebugError> {
        const MAX_REGIONS: usize = 4096;
        let mut out: BTreeMap<u64, MemoryMap> = BTreeMap::new();
        self.with_session(|s| {
            for seed in seeds {
                let mut addr = *seed;
                while out.len() < MAX_REGIONS {
                    let text = s.text(MemoryRegionInfo::command(addr).as_bytes(), "qMemoryRegionInfo")?;
                    let Ok(info) = MemoryRegionInfo::parse(&text) else { break };
                    if !info.is_mapped() {
                        break;
                    }
                    let end = info.end();
                    if out.contains_key(&info.start) {
                        // Already walked from another seed — following it again
                        // would loop over the same tail.
                        break;
                    }
                    out.insert(
                        info.start,
                        MemoryMap {
                            base: Address::new(info.start),
                            size: info.size,
                            readable: info.readable,
                            writable: info.writable,
                            executable: info.executable,
                            name: info.name.clone(),
                            file_path: info.name,
                            file_offset: 0,
                        },
                    );
                    if end <= addr {
                        break; // Degenerate reply; refuse to spin.
                    }
                    addr = end;
                }
            }
            Ok(())
        })?;
        Ok(out.into_values().collect())
    }
}

/// Names for the handful of signals an Apple stop reply actually carries.
const fn signal_name(sig: u8) -> &'static str {
    match sig {
        2 => "SIGINT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGBUS",
        11 => "SIGSEGV",
        24 => "SIGXCPU",
        _ => "SIG?",
    }
}

impl AppleDebugger {
    /// Release a resume that is parked on the socket, so an operation that
    /// needs the session mutex does not have to wait for the stub to speak
    /// first.
    ///
    /// `resume` owns the session mutex for as long as the target runs, so any
    /// caller that opens with `self.session.lock()` blocks until the parked
    /// read times out — 30 s in the tests, and unbounded on a transport
    /// configured without a read timeout. `detach` and `kill` are exactly the
    /// operations a user reaches for *because* the target is running.
    ///
    /// The gate is held across the write, for the reason `resume_in_flight`
    /// documents: released first, the runner could finish in between and the
    /// `` would arrive with no request outstanding — the stub would then
    /// answer with a stop reply nothing is waiting for, and the next command
    /// would read it as its own.
    ///
    /// Best-effort: a transport with no out-of-band handle waits exactly as it
    /// did before, which is no worse than not calling this at all.
    fn release_parked_resume(&self) {
        let gate = self.resume_in_flight.lock();
        if *gate {
            if let Some(interrupter) = self.interrupter.read().clone() {
                let _ = interrupter.interrupt();
            }
        }
    }

    /// Disarm EVERY breakpoint this backend armed, on the wire, while the
    /// connection is still up.
    ///
    /// The self-patched `BRK` words are written back (that much this sweep
    /// always did), and — new — the stub-managed `Z0` traps get their `z0`,
    /// and the hardware resources get their `z1`/`z2`/`z3`/`z4`. The old
    /// justification for skipping those ("the stub's to undo … it drops them
    /// when the connection does") was an assumption about the peer that was
    /// never tested: against the one stub this backend can be exercised
    /// against, a `D` after two `Z` packets leaves both traps installed with a
    /// refcount of 1. It is also wrong for the transport this backend targets:
    /// a debugserver reached through a persistent usbmux tunnel outlives the
    /// `D`, so a re-attach inherits stale traps and occupied debug registers
    /// while the fresh `hw` table believes every slot is free — and then hands
    /// one out.
    ///
    /// Best-effort by design: a target that is already gone cannot be written
    /// to or spoken to, and failing here must not turn a successful detach into
    /// an error.
    fn disarm_all_breakpoints(&self, session: &mut Session) {
        let records: Vec<BpRecord> = self.breakpoints.read().values().cloned().collect();
        let mut hw = self.hw.lock();
        for record in records {
            let a = record.bp.address.as_u64();
            // A self-patched word is ours to put back, armed or not: the
            // unconditional write is what this sweep has always done.
            if let Some(saved) = record.saved.as_ref() {
                let _ = session.client.write_memory(a, saved);
                continue;
            }
            // A disabled breakpoint is not installed in the target, so it has
            // nothing on the wire to undo.
            if !record.bp.enabled {
                continue;
            }
            if let Some(hk) = hw_kind_for(record.bp.kind) {
                if let Some(controller) = hw.as_mut() {
                    let _ = match hk {
                        HwKind::Breakpoint => {
                            controller.clear_breakpoint(&mut session.client, a).map(|_| ())
                        }
                        _ => controller.clear_watchpoint(&mut session.client, hk, a).map(|_| ()),
                    };
                }
            } else {
                let (zkind, size) = z_kind_for(record.bp.kind);
                let _ = session.text(&commands::remove_breakpoint(zkind, a, size), "z");
            }
        }
    }

    /// Plant a temporary software breakpoint at `addr`, with the same fallback
    /// [`Debugger::set_breakpoint`] uses: a stub without server-managed
    /// software breakpoints answers `Z0` with an empty reply, and the A64
    /// `BRK #0` is then patched in by hand.
    ///
    /// Returns the saved original bytes when the fallback was taken, so the
    /// caller can restore them; `None` means the stub owns the breakpoint.
    ///
    /// `step_over` used to plant its return-site breakpoint with a bare
    /// `client.insert_breakpoint`, which maps an empty `Z0` reply to a framing
    /// error — so stepping over a call failed outright against exactly the
    /// stubs this backend already knew how to handle everywhere else.
    ///
    /// # Errors
    /// Transport failures, or a memory read/write refused by the stub.
    fn plant_temp_breakpoint(&self, addr: u64) -> Result<Option<Vec<u8>>, DebugError> {
        let accepted = self.with_session(|s| {
            let text = s.text(&commands::insert_breakpoint(ZKind::Software, addr, A64_BP_LEN), "Z")?;
            Ok(text.starts_with("OK"))
        })?;
        if accepted {
            return Ok(None);
        }
        let original = self.with_session(|s| {
            let orig = s
                .client
                .read_memory(addr, 4)
                .map_err(|e| DebugError::MemoryError(addr, format!("save original: {e}")))?;
            s.client
                .write_memory(addr, &arm64::brk_bytes(0))
                .map_err(|e| DebugError::MemoryError(addr, format!("patch BRK: {e}")))?;
            Ok(orig)
        })?;
        Ok(Some(original))
    }

    /// Undo a [`Self::plant_temp_breakpoint`]. Best-effort: the target may
    /// already be gone, and a failure here must not mask the stop event the
    /// caller is returning.
    fn unplant_temp_breakpoint(&self, addr: u64, saved: Option<Vec<u8>>) {
        let _ = match saved {
            Some(orig) => self.with_session(|s| {
                s.client
                    .write_memory(addr, &orig)
                    .map(drop)
                    .map_err(|e| DebugError::MemoryError(addr, format!("unpatch BRK: {e}")))
            }),
            None => self.with_session(|s| {
                s.client
                    .remove_breakpoint(ZKind::Software, addr, A64_BP_LEN)
                    .map_err(|e| rsp_err("z0", &e))
            }),
        };
    }

    /// Fully-qualified Swift type name of the instance at `ptr`.
    ///
    /// A Swift class instance keeps its type-metadata pointer in its first
    /// word, exactly where an Objective-C object keeps its `isa`, so this is
    /// the Swift counterpart of [`Self::describe_objc_object`].
    ///
    /// `swift_runtime` previously had only a TRANSITIVE path to a live target
    /// (through `ObjcMemoryAdapter` over an `ObjcMemory`); no method on this
    /// backend actually used it, so in practice nothing drove it.
    ///
    /// # Errors
    /// Read failures, or `NotNominal` for kinds with no descriptor — tuples,
    /// functions and existentials have structural rather than nominal names
    /// and are reported as such rather than given an invented one.
    pub async fn describe_swift_object(&self, ptr: u64) -> Result<String, DebugError> {
        use crate::ios::objc_runtime::ReaderMemory;
        use crate::ios::swift_runtime::{type_name, ObjcMemoryAdapter, SwiftMemoryReader};

        let mem = ReaderMemory(|addr: u64, len: usize| {
            crate::scripting_api::block_on(self.read_memory(Address(addr), len)).ok()
        });
        let reader = ObjcMemoryAdapter(&mem);
        let metadata = reader
            .read_u64(ptr)
            .map_err(|e| DebugError::Os(format!("swift metadata at {ptr:#x}: {e}")))?;
        type_name(&reader, metadata)
            .map_err(|e| DebugError::Os(format!("swift type at {ptr:#x}: {e}")))
    }

    /// Describe an Objective-C object living in the target, the way a
    /// debugger's `po` would.
    ///
    /// This is the first live path into `objc_runtime` (and, through
    /// `ObjcMemoryAdapter`, into `swift_runtime`): both read through abstract
    /// memory traits whose only implementor was an in-process test container,
    /// so neither could be pointed at a real process however complete they
    /// were.
    ///
    /// Reads are served straight from the session. A tagged pointer needs no
    /// memory at all and is decoded from the value itself.
    ///
    /// # Errors
    /// Propagates the runtime's own read/parse failures — an unmapped isa or
    /// a class chain that does not lead anywhere is reported, never guessed at.
    pub async fn describe_objc_object(&self, ptr: u64) -> Result<String, DebugError> {
        use crate::ios::objc_runtime::{ObjcAbi, ObjcRuntime, ReaderMemory};

        // The runtime walks pointer chains, so it cannot be handed a
        // pre-fetched window: reads are demand-driven. `block_on` is safe here
        // for the same reason the rest of this backend blocks on the session —
        // there is no true async I/O underneath, only a channel round-trip.
        let mem = ReaderMemory(|addr: u64, len: usize| {
            crate::scripting_api::block_on(self.read_memory(Address(addr), len)).ok()
        });
        ObjcRuntime::new(&mem, ObjcAbi::Arm64)
            .describe(ptr)
            .map_err(|e| DebugError::Os(format!("objc describe {ptr:#x}: {e}")))
    }

    /// The target's per-image unwind tables, or an empty set when the stub
    /// cannot enumerate its images.
    ///
    /// Empty is a legitimate answer, not an error: the unwinder degrades to
    /// the frame-pointer walk, which is exactly the behaviour that existed
    /// before — never worse, sometimes much better.
    async fn unwind_images(&self) -> Vec<crate::ios::unwind::ImageUnwindTables> {
        let Ok(modules) = self.modules().await else { return Vec::new() };
        let mut chunks: Vec<(u64, usize, Option<Vec<u8>>)> = Vec::new();
        for m in &modules {
            let base = m.base.as_u64();
            let Ok(len) = usize::try_from(m.size) else { continue };
            if len == 0 {
                continue;
            }
            chunks.push((base, len, self.read_memory(Address(base), len).await.ok()));
        }
        crate::ios::unwind::unwind_images_from_modules(&modules, |addr, len| {
            chunks
                .iter()
                .find(|(b, l, _)| *b == addr && *l == len)
                .and_then(|(_, _, bytes)| bytes.clone())
        })
    }

    /// Build a symbolicator from the target's own loaded images and install
    /// it as this session's frame resolver.
    ///
    /// Without this the Apple symbol engine was reachable in principle (it
    /// implements [`crate::symbol_resolver::FrameSymbolResolver`]) but nothing ever built one from a
    /// live target, so `backtrace()` frames stayed nameless unless the caller
    /// assembled the images by hand.
    ///
    /// Returns how many images produced usable symbols. Zero is a legitimate
    /// answer — a fully stripped target has no symbols to find — and is
    /// reported as such rather than as an error.
    ///
    /// # Errors
    /// Propagates the failure of `modules()` when the stub cannot enumerate
    /// its loaded images at all.
    pub async fn load_symbols_from_target(&self) -> Result<usize, DebugError> {
        let modules = self.modules().await?;
        let mut chunks: Vec<(u64, usize, Option<Vec<u8>>)> = Vec::new();
        for m in &modules {
            let base = m.base.as_u64();
            let Ok(len) = usize::try_from(m.size) else { continue };
            if len == 0 {
                continue;
            }
            let bytes = self.read_memory(Address(base), len).await.ok();
            chunks.push((base, len, bytes));
        }
        let engine = crate::ios::symbolication::symbolicator_from_modules(&modules, |addr, len| {
            chunks
                .iter()
                .find(|(b, l, _)| *b == addr && *l == len)
                .and_then(|(_, _, bytes)| bytes.clone())
        });
        let count = engine.image_count();
        // The same images that name backtrace frames also answer `p symbol` in
        // an expression, so the table is built here rather than by a second,
        // independently-drifting read of the target.
        *self.expr_symbols.write() = crate::ios::expr::symbols_from_symbolicator(&engine);
        // Join the symbol table to the dSYMs, so a live backtrace can carry
        // `file:line`. Without this the bare `Symbolicator` went in and its
        // `FrameSymbolResolver` impl reports `file`/`line` as `None` by
        // construction — the whole DWARF path was unreachable from a session.
        let bundles = self.dsyms.read().clone();
        if bundles.is_empty() {
            self.dsym_errors.write().clear();
            // Infallible on this backend: the override below always accepts.
            let _ = self.set_symbol_resolver(Arc::new(engine));
            return Ok(count);
        }
        let mut resolver = crate::ios::frame_resolver::AppleFrameResolver::new(engine);
        let mut errors = Vec::new();
        {
            let roots = self.source_roots.read();
            for bundle in &bundles {
                // A refusal is recorded and the bundle dropped. It is NEVER
                // downgraded to "attach it anyway": a dSYM from another build
                // parses fine and yields precise, plausible, wrong lines.
                if let Err(e) = resolver.attach_dsym(bundle, &roots) {
                    errors.push(e.to_string());
                }
            }
        }
        *self.dsym_errors.write() = errors;
        let _ = self.set_symbol_resolver(Arc::new(resolver));
        Ok(count)
    }

    /// Evaluate a C-like expression against the LIVE target.
    ///
    /// Registers come from `tid`'s current stop (`ThreadId(0)` means "the
    /// thread that reported the last stop"), every dereference is an `m` packet
    /// to the target, and symbols are the ones `load_symbols_from_target` read
    /// out of the target's own images — which this call triggers on first use
    /// exactly like `backtrace()` does, when automatic loading is enabled.
    ///
    /// Nothing here is stubbed and nothing is defaulted: an unmapped address is
    /// a [`DebugError::MemoryError`], not a zero, and an unknown name is an
    /// error rather than address 0. That asymmetry is the whole point — a
    /// debugger that prints a plausible wrong value is worse than one that
    /// refuses to print.
    ///
    /// # Errors
    /// [`DebugError::NotAttached`] with no session, [`DebugError::Unsupported`]
    /// on a non-ARM64 target or an expression the evaluator rejects,
    /// [`DebugError::MemoryError`] when a dereference cannot be satisfied, and
    /// [`DebugError::RegisterError`] for an unknown register.
    pub async fn evaluate(&self, tid: ThreadId, expr: &str) -> Result<crate::expression_evaluator::TypedValue, DebugError> {
        self.maybe_auto_load_symbols().await;
        let symbols = self.expr_symbols.read().clone();
        self.with_session(|s| {
            if !s.arch.is_arm64() {
                return Err(DebugError::Unsupported(format!(
                    "expression evaluation on this backend models the ARM64 register file;                      target reports {}",
                    s.arch.name()
                )));
            }
            let tid = if tid.0 == 0 { s.current_tid } else { tid };
            let set = s.read_register_set(tid)?;
            let view = crate::ios::expr::register_view_from_set(&set);
            let session = crate::ios::expr::AppleExprSession::new(
                view,
                crate::ios::expr::TargetMemory::new(&mut s.client),
                symbols,
            );
            session.evaluate(expr).map_err(eval_err)
        })
    }

    /// [`Self::evaluate`], formatted the way a debugger prints a value.
    ///
    /// # Errors
    /// As [`Self::evaluate`].
    pub async fn evaluate_pretty(&self, tid: ThreadId, expr: &str) -> Result<String, DebugError> {
        self.maybe_auto_load_symbols().await;
        let symbols = self.expr_symbols.read().clone();
        self.with_session(|s| {
            if !s.arch.is_arm64() {
                return Err(DebugError::Unsupported(format!(
                    "expression evaluation on this backend models the ARM64 register file;                      target reports {}",
                    s.arch.name()
                )));
            }
            let tid = if tid.0 == 0 { s.current_tid } else { tid };
            let set = s.read_register_set(tid)?;
            let view = crate::ios::expr::register_view_from_set(&set);
            let session = crate::ios::expr::AppleExprSession::new(
                view,
                crate::ios::expr::TargetMemory::new(&mut s.client),
                symbols,
            );
            session.evaluate_pretty(expr).map_err(eval_err)
        })
    }

}

/// Map an evaluator failure onto the hub error, PRESERVING which kind of
/// failure it was: a failed target read stays a `MemoryError` carrying the
/// address, so a caller can tell "your expression is malformed" from "that
/// address is not mapped".
fn eval_err(e: crate::expression_evaluator::EvalError) -> DebugError {
    use crate::expression_evaluator::EvalError as E;
    match e {
        E::MemoryReadError { addr, ref reason } => DebugError::MemoryError(addr, reason.clone()),
        E::UndefinedRegister(ref r) => DebugError::RegisterError(format!("undefined register ${r}")),
        other => DebugError::Unsupported(other.to_string()),
    }
}

impl AppleDebugger {
    // Per-resource helpers for the breakpoint API. They live outside the
    // `Debugger` impl because the trait speaks only of addresses, while an
    // address here can carry both a code trap and a data watchpoint.


    /// Re-enable the one resource of `class` at `addr` — see [`Self::disable_one`].
    /// Target memory exactly as it stands, traps included.
    ///
    /// The twin of `read_memory`, which MASKS the traps this backend planted
    /// itself so a caller never sees `BRK #0` where an instruction belongs. The
    /// three native backends have carried this pair for a long time; this one
    /// grew the masking later and needed the raw door with it, for the few
    /// places that genuinely want the patched image — checking that a patch
    /// actually landed being the obvious one.
    ///
    /// # Errors
    /// Whatever the stub's memory read reports.
    pub async fn read_memory_raw(&self, addr: Address, size: usize) -> Result<Vec<u8>, DebugError> {
        self.with_session(|s| {
            s.client
                .read_memory(addr.as_u64(), size)
                .map_err(|e| DebugError::MemoryError(addr.as_u64(), e.to_string()))
        })
    }

    async fn enable_one(&self, addr: Address, class: BpClass) -> Result<(), DebugError> {
        let a = addr.as_u64();
        let (kind, was_enabled, saved, hw_size) = {
            let guard = self.breakpoints.read();
            let rec = guard
                .get(&(a, class))
                .ok_or(DebugError::BreakpointNotFound(a))?;
            (rec.bp.kind, rec.bp.enabled, rec.saved.is_some(), rec.hw_size)
        };
        if was_enabled {
            return Ok(());
        }
        let (zkind, size) = z_kind_for(kind);
        // Re-arming a hardware resource takes a slot back, so it goes through
        // the table: `disable_breakpoint` gave the slot up, and a re-enable that
        // skipped the table would have the debugger tracking one fewer used
        // register than the target actually has — the accounting drifts in the
        // permissive direction, which is how a request gets sent that the
        // hardware cannot honour.
        if !saved
            && let Some(hk) = hw_kind_for(kind)
        {
            let width = hw_size.unwrap_or(usize::try_from(size).unwrap_or(8));
            self.with_hw(|hw, client| {
                match hk {
                    HwKind::Breakpoint => hw.set_breakpoint(client, a).map(|_| ()),
                    _ => hw.set_watchpoint(client, hk, a, width).map(|_| ()),
                }
                .map_err(hw_err)
            })?;
        } else {
            self.with_session(|s| {
                if saved {
                    s.client
                        .write_memory(a, &arm64::brk_bytes(0))
                        .map_err(|e| DebugError::MemoryError(a, format!("re-patch BRK: {e}")))?;
                } else {
                    s.text(&commands::insert_breakpoint(zkind, a, size), "Z")?;
                }
                Ok(())
            })?;
        }
        // One guard, both classes: taking the write lock twice inside an
        // `or_else` would borrow from a temporary that dies at the end of the
        // expression.
        let mut guard = self.breakpoints.write();
        if let Some(rec) = guard.get_mut(&(a, class)) {
            rec.bp.enabled = true;
        }
        Ok(())
    }

    /// Disable the one resource of `class` at `addr`.
    ///
    /// Split out from the trait method because an address can carry both a
    /// code trap and a data watchpoint. Acting on whichever the lookup found
    /// first left the OTHER one armed and, worse, unreachable: a second
    /// `disable_breakpoint` re-found the already-disabled record, saw
    /// `was_enabled == false` and returned `Ok` — so the second resource
    /// could never be disabled through the public API at all.
    async fn disable_one(&self, addr: Address, class: BpClass) -> Result<(), DebugError> {
        let a = addr.as_u64();
        let (kind, was_enabled, saved) = {
            let guard = self.breakpoints.read();
            let rec = guard
                .get(&(a, class))
                .ok_or(DebugError::BreakpointNotFound(a))?;
            (rec.bp.kind, rec.bp.enabled, rec.saved.clone())
        };
        if !was_enabled {
            return Ok(());
        }
        let (zkind, size) = z_kind_for(kind);
        // Disabling a hardware resource genuinely releases its debug register
        // on the target, so the slot must be released here too — otherwise a
        // disabled watchpoint would go on occupying a register it no longer
        // uses, and this side would refuse a request the hardware could take.
        if saved.is_none()
            && let Some(hk) = hw_kind_for(kind)
        {
            self.with_hw(|hw, client| {
                match hk {
                    HwKind::Breakpoint => hw.clear_breakpoint(client, a).map(|_| ()),
                    _ => hw.clear_watchpoint(client, hk, a).map(|_| ()),
                }
                .map_err(hw_err)
            })?;
        } else {
            self.with_session(|s| {
                if let Some(orig) = &saved {
                    s.client
                        .write_memory(a, orig)
                        .map_err(|e| DebugError::MemoryError(a, format!("unpatch BRK: {e}")))?;
                } else {
                    s.text(&commands::remove_breakpoint(zkind, a, size), "z")?;
                }
                Ok(())
            })?;
        }
        if let Some(rec) = self.breakpoints.write().get_mut(&(a, class)) {
            rec.bp.enabled = false;
        }
        Ok(())
    }

    /// Remove the one resource of `class` at `addr`.
    ///
    /// Per-class for the reason `disable_one` is: an address can carry a code
    /// trap and a data watchpoint. Un-arming one while untracking BOTH — which
    /// is what the address-keyed version did once coexistence became possible
    /// — leaves the other armed in the target with nothing that knows about
    /// it. `detach`'s restore sweep walks this same map, so it would never
    /// find it: a debug register held, or a `BRK #0` left in the code, for the
    /// life of the process.
    async fn remove_one(&self, addr: Address, class: BpClass) -> Result<(), DebugError> {
        let a = addr.as_u64();
        // Look up, do NOT remove yet — the rule the other three backends carry
        // and this one never got. Removing first means a failed un-patch
        // returns with the record already gone, so the `BRK #0` (or the stub's
        // `Z0`) stays in the target with nothing left that knows about it.
        // `detach`'s restore sweep walks THIS map, so it would skip the
        // abandoned patch silently, and on ARM64 a stray `BRK #0` raises
        // SIGTRAP with no debugger attached — which kills the process. Same
        // defect class as iter 245, reached through a different door.
        let (kind, enabled, saved) = {
            let guard = self.breakpoints.read();
            let rec = guard.get(&(a, class)).ok_or(DebugError::BreakpointNotFound(a))?;
            (rec.bp.kind, rec.bp.enabled, rec.saved.clone())
        };
        let (zkind, size) = z_kind_for(kind);
        // Only a breakpoint that is actually armed needs undoing. A DISABLED
        // one already had its original word written back by
        // `disable_breakpoint`, and re-writing it is not merely pointless: on a
        // target that has died or become unwritable the write fails, so
        // removing an already-disabled breakpoint reported an error for a
        // breakpoint that needed no action at all — and, since a failed
        // un-patch now (correctly) keeps the record, it could never be removed
        // again either. The other three backends state this rule in
        // `remove_breakpoint` as "a disabled breakpoint's byte is already back
        // in place […] would fail needlessly on a dead process"; this backend
        // applied it only to the stub-managed branch.
        if enabled {
            // A hardware resource goes back through the slot table, which is
            // the whole point of removal: the debug register it held becomes
            // available again. Dropping the record without telling the table
            // would leak the slot and make the debugger refuse a breakpoint the
            // hardware can perfectly well take.
            if saved.is_none()
                && let Some(hk) = hw_kind_for(kind)
            {
                self.with_hw(|hw, client| {
                    match hk {
                        HwKind::Breakpoint => hw.clear_breakpoint(client, a).map(|_| ()),
                        _ => hw.clear_watchpoint(client, hk, a).map(|_| ()),
                    }
                    .map_err(hw_err)
                })?;
            } else {
                self.with_session(|s| {
                    if let Some(orig) = &saved {
                        s.client.write_memory(a, orig).map_err(|e| {
                            DebugError::MemoryError(a, format!("restore original: {e}"))
                        })?;
                    } else {
                        s.text(&commands::remove_breakpoint(zkind, a, size), "z")?;
                    }
                    Ok(())
                })?;
            }
        }
        // Untracked only now that the target is demonstrably clean, and only
        // the class we actually un-armed.
        self.breakpoints.write().remove(&(a, class));
        Ok(())
    }

    /// Every resource at `addr`, in a fixed order.
    fn classes_at(&self, a: u64) -> Vec<BpClass> {
        let guard = self.breakpoints.read();
        [BpClass::Code, BpClass::Data]
            .into_iter()
            .filter(|c| guard.contains_key(&(a, *c)))
            .collect()
    }
}

#[async_trait::async_trait]
impl Debugger for AppleDebugger {
    fn name(&self) -> &str {
        crate::ios::BACKEND_NAME
    }

    fn supported_architectures(&self) -> Vec<String> {
        crate::ios::supported_architectures()
    }

    // -- lifecycle ----------------------------------------------------------

    async fn launch(&self, opts: LaunchOptions) -> Result<ProcessId, DebugError> {
        if self.session.lock().is_some() {
            return Err(DebugError::LaunchError(
                "already attached; detach before launching another target".to_string(),
            ));
        }
        if opts.follow_forks || opts.redirect.stdout || opts.redirect.stderr {
            return Err(DebugError::Unsupported(
                "follow_forks and stdio redirection are not expressible in the debugserver `A` \
                 packet; launch debugserver with the redirection already applied"
                    .to_string(),
            ));
        }
        let transport = self.factory.connect(&ConnectRequest::Launch(&opts))?;
        let mut session = Session::establish(transport)?;

        // `A` carries argv; argv[0] is the executable.
        let mut argv = vec![opts.executable.clone()];
        argv.extend(opts.args.iter().cloned());
        let reply = session.text(lldb_ext::build_a_packet(&argv).as_bytes(), "A")?;
        if !reply.starts_with("OK") {
            return Err(DebugError::LaunchError(format!(
                "stub rejected `A` packet for {}: {reply}",
                opts.executable
            )));
        }
        // Refresh: the pid learned during `establish` predates the exec.
        let info = Session::process_info(&mut session.client)?;
        session.pid = ProcessId(u32::try_from(info.pid).unwrap_or(0));
        session.arch = TargetArch::from_cpu(info.cputype, info.cpusubtype);

        let stop = session.text(&commands::halt_reason(), "?")?;
        if let Ok(StopReply::SignalWithInfo { thread: Some(t), .. }) = StopReply::parse(stop.as_bytes())
        {
            session.current_tid = ThreadId(u32::try_from(t).unwrap_or(0));
        }
        let pid = session.pid;
        // Last point at which the client is reachable without contending with a
        // runner; after this the session mutex may be held for a whole `vCont`.
        *self.interrupter.write() = session.client.interrupter();
        // Publish the status mirror while the session is installed, so
        // `is_attached`/`target_pid`/`Debug` never need the mutex.
        self.pid.store(session.pid.0, Ordering::SeqCst);
        *self.session.lock() = Some(session);
        self.attached.store(true, Ordering::SeqCst);
        self.reset_auto_load();
        Ok(pid)
    }

    async fn attach(&self, pid: ProcessId) -> Result<(), DebugError> {
        if self.session.lock().is_some() {
            return Err(DebugError::LaunchError(
                "already attached; detach first".to_string(),
            ));
        }
        let transport = self.factory.connect(&ConnectRequest::Attach(pid))?;
        let mut session = Session::establish(transport)?;

        let reply = session.text(format!("vAttach;{:x}", pid.0).as_bytes(), "vAttach")?;
        if reply.is_empty() || reply.starts_with('E') {
            return Err(DebugError::ProcessNotFound(pid.0));
        }
        let stop = StopReply::parse(reply.as_bytes())
            .map_err(|e| DebugError::Os(format!("vAttach stop reply {reply:?}: {e}")))?;
        if let StopReply::SignalWithInfo { thread: Some(t), .. } = stop {
            session.current_tid = ThreadId(u32::try_from(t).unwrap_or(0));
        }
        if session.current_tid.0 == 0 {
            // Fall back to the stub's notion of "current thread".
            let qc = session.text(b"qC", "qC")?;
            if let Some(hex) = qc.strip_prefix("QC") {
                session.current_tid = ThreadId(u32::from_str_radix(hex, 16).unwrap_or(0));
            }
        }
        session.pid = pid;
        *self.interrupter.write() = session.client.interrupter();
        // Publish the status mirror while the session is installed, so
        // `is_attached`/`target_pid`/`Debug` never need the mutex.
        self.pid.store(session.pid.0, Ordering::SeqCst);
        *self.session.lock() = Some(session);
        self.attached.store(true, Ordering::SeqCst);
        self.reset_auto_load();
        Ok(())
    }

    async fn detach(&self) -> Result<(), DebugError> {
        // Stop the target before reaching for the session mutex. A resume
        // parked on the socket owns that mutex for as long as the stub stays
        // silent, so "stop debugging" issued while the target runs used to
        // block until the read timed out — and on a transport configured
        // without a read timeout, forever. The same out-of-band byte `pause`
        // uses makes the runner return, which releases the mutex.
        //
        // The gate is held across the write for the reason `resume_in_flight`
        // documents: releasing it first would let the runner finish in between,
        // and the `\x03` would then arrive with no request outstanding — the
        // stub would answer with a stop reply that nothing is waiting for, and
        // the `D` below would read it as its own answer.
        //
        // Best-effort by design: a transport with no out-of-band handle waits
        // exactly as it did before, which is no worse than the old behaviour.
        self.release_parked_resume();
        let mut guard = self.session.lock();
        let session = guard.as_mut().ok_or(DebugError::NotAttached)?;
        // Restore BEFORE the `D`: once the stub has detached, the target is
        // no longer writable through this connection.
        self.disarm_all_breakpoints(session);
        let reply = session
            .text(&commands::detach(), "D")
            .map_err(|e| DebugError::DetachError(e.to_string()))?;
        *guard = None;
        self.attached.store(false, Ordering::SeqCst);
        self.pid.store(0, Ordering::SeqCst);
        // The interrupt handle names a socket that is gone; keeping it would let
        // a later `pause()` write 0x03 into a closed descriptor and report
        // success.
        *self.interrupter.write() = None;
        *self.resume_in_flight.lock() = false;
        // A resolver built from the departed process describes nothing about a
        // later one; `reset_auto_load` drops it (and only it — a resolver the
        // caller installed stays).
        self.reset_auto_load();
        // Breakpoints belong to the departed process; keeping them would make
        // a later attach report a table that the new target never installed.
        //
        // Every one of them — self-patched `BRK`, stub-managed `Z0`, hardware
        // resource — was disarmed on the wire by `disarm_all_breakpoints`
        // above, BEFORE the `D`. Clearing the table without that made the
        // records the only thing that went away: an A64 `BRK #0` left behind
        // raises SIGTRAP with no debugger left to handle it (which terminates
        // the process), and a stub-managed trap left behind is inherited by
        // the next attach through a tunnel that outlived the `D`.
        self.breakpoints.write().clear();
        *self.hw.lock() = None;
        if reply.starts_with("OK") || reply.is_empty() {
            Ok(())
        } else {
            Err(DebugError::DetachError(format!("stub answered {reply:?} to D")))
        }
    }

    async fn kill(&self) -> Result<(), DebugError> {
        // Same trap as `detach`, and worse: `kill` is the emergency exit, so
        // "terminate while it runs" is its main use, not an edge case.
        self.release_parked_resume();
        let mut guard = self.session.lock();
        let session = guard.as_mut().ok_or(DebugError::NotAttached)?;
        let pid = session.pid;
        // `vKill` is answered; bare `k` is not (the stub dies mid-reply), so it
        // is only used as a fallback and its silence is expected.
        let reply = session.text(format!("vKill;{:x}", pid.0).as_bytes(), "vKill");
        let killed: Result<(), DebugError> = match reply {
            Ok(r) if r.starts_with("OK") => Ok(()),
            _ => {
                // The expected silence is about the REPLY, not about the write.
                // Discarding the `io::Result` of the send made `kill` report
                // success on the strength of a byte that never left this
                // process: the caller then tears its own state down, stops
                // watching, and leaves a live target behind. Whether `k`
                // reached the wire is the only evidence this fallback has, so
                // it is the evidence that decides.
                session
                    .client
                    .transport_mut()
                    .send(&crate::ios::rsp::RspPacket::new(commands::kill()).encode())
                    .map_err(|e| {
                        DebugError::Os(format!(
                            "the target was not killed: `vKill` did not succeed and the `k` \
                             fallback could not be written: {e}"
                        ))
                    })
            }
        };
        *guard = None;
        self.attached.store(false, Ordering::SeqCst);
        self.pid.store(0, Ordering::SeqCst);
        // The interrupt handle names a socket that is gone; keeping it would let
        // a later `pause()` write 0x03 into a closed descriptor and report
        // success.
        *self.interrupter.write() = None;
        *self.resume_in_flight.lock() = false;
        // A resolver built from the departed process describes nothing about a
        // later one; `reset_auto_load` drops it (and only it — a resolver the
        // caller installed stays).
        self.reset_auto_load();
        self.breakpoints.write().clear();
        *self.hw.lock() = None;
        // The teardown above happens either way — this connection is finished
        // whatever the target did — but the RESULT still says whether the
        // target was actually killed.
        killed
    }

    fn is_attached(&self) -> bool {
        // Deliberately NOT `self.session.lock().is_some()`: see the `attached`
        // field. A status query must keep answering while the target runs.
        self.attached.load(Ordering::SeqCst)
    }

    fn target_pid(&self) -> Option<ProcessId> {
        self.attached
            .load(Ordering::SeqCst)
            .then(|| ProcessId(self.pid.load(Ordering::SeqCst)))
    }

    // -- execution ----------------------------------------------------------

    async fn continue_execution(&self) -> Result<DebugEvent, DebugError> {
        self.resume(None, false)
    }

    async fn single_step(&self, tid: ThreadId) -> Result<DebugEvent, DebugError> {
        self.resume(Some(tid), true)
    }

    async fn step_over(&self, tid: ThreadId) -> Result<DebugEvent, DebugError> {
        self.require_arm64("step_over")?;
        let pc = self.with_session(|s| s.read_register_set(tid))?.pc;
        let insn = self.instruction_at(pc)?;
        let is_call = arm64::BranchKind::decode(insn).is_some_and(arm64::BranchKind::is_call);
        if !is_call {
            // Fixed-width ISA: anything that is not a call steps over exactly
            // as it steps into.
            return self.resume(Some(tid), true);
        }
        // Plant a temporary breakpoint at the return site and run to it. The
        // breakpoint is removed even when the run stops somewhere else (a
        // fault, a nested breakpoint), which is why the removal is not
        // conditional on the outcome.
        let ret = pc.wrapping_add(arm64::INSTRUCTION_SIZE);
        // "Is there already an ARMED EXECUTION trap here", not "is this address
        // in my map". A DISABLED record has had its `z0` sent and stops
        // nothing; a data watchpoint never traps on execution at all. Treating
        // either as a usable trap suppressed the only thing that would stop the
        // resume, so `step_over` issued a free `vCont;c` and reported whatever
        // the process did next — up to and including running to exit — as the
        // step result.
        let already_there = self.breakpoints.read().get(&(ret, BpClass::Code)).is_some_and(|rec| {
            rec.bp.enabled
                && matches!(rec.bp.kind, BreakpointKind::Software | BreakpointKind::Hardware)
        });
        // Planted through the shared helper so a stub without server-managed
        // software breakpoints gets the same `BRK #0` fallback `set_breakpoint`
        // gets, instead of a framing error.
        let planted = if already_there {
            None
        } else {
            Some(self.plant_temp_breakpoint(ret)?)
        };
        let event = self.resume(Some(tid), false);
        if let Some(saved) = planted {
            self.unplant_temp_breakpoint(ret, saved);
        }
        event
    }

    async fn step_out(&self, tid: ThreadId) -> Result<DebugEvent, DebugError> {
        self.require_arm64("step_out")?;
        let start = self.with_session(|s| s.read_register_set(tid))?;
        let Some(target) = start.lr else {
            return Err(DebugError::StepError(
                "link register is unknown, so the return address cannot be identified".to_string(),
            ));
        };
        let min_sp = start.sp;
        let mut event = self.single_step(tid).await?;
        for _ in 0..self.max_step_out_instructions {
            // Ordering matters and is not ours to re-derive: the hub crate owns
            // this decision precisely because it has been got wrong twice.
            let regs = self.with_session(|s| s.read_register_set(tid)).ok().map(|r| (r.pc, r.sp));
            match run_to_return_step(event.reason.is_exit(), regs, target, min_sp) {
                RunToReturnStep::Done => return Ok(event),
                RunToReturnStep::KeepGoing => {}
            }
            event = self.single_step(tid).await?;
        }
        Err(DebugError::StepError(format!(
            "did not return to {target:#x} within {} instructions",
            self.max_step_out_instructions
        )))
    }

    /// Send the asynchronous `\x03` interrupt.
    ///
    /// # How the request/response client tolerates this
    ///
    /// The byte does not go through [`RspClient`] at all — it goes through the
    /// transport's [`crate::ios::rsp::RspInterrupter`], a second, send-only
    /// handle taken at attach time. That is the minimum the transport had to
    /// grow: `send`/`recv` need `&mut self`, and while the target runs the
    /// runner thread holds both the session mutex and that borrow, so no
    /// in-band path can exist. The stop reply the stub produces is *not* an
    /// extra packet — it is the answer the parked `vCont` was already waiting
    /// for, so the framer stays in step and the resume returns a real
    /// `SIGINT` event.
    ///
    /// # When nothing is sent
    ///
    /// If no resume is outstanding the target is already stopped and this is a
    /// no-op success. Sending anyway would produce a stop reply that no request
    /// is waiting for, and the next command would consume it as its own answer.
    /// `resume_in_flight` is checked *while holding its mutex across the write*,
    /// so a resume cannot finish between the check and the byte leaving.
    ///
    /// # Errors
    /// * [`DebugError::NotAttached`] with no session.
    /// * [`crate::expression_evaluator::DebugError::Unsupported`] when the transport has no out-of-band
    ///   write handle (the usbmux tunnel and the in-process loopback), naming
    ///   which transport it was.
    /// * [`DebugError::Os`] if the write itself fails.
    async fn pause(&self) -> Result<(), DebugError> {
        // NOTHING here may take the session mutex. `resume` runs its whole
        // exchange inside `with_session`, so while a target is running that
        // mutex is held for as long as the stub stays silent — which is
        // precisely the only situation `pause` exists for. The first line of
        // this function used to be `is_attached()`, which is
        // `self.session.lock().is_some()`: it blocked until the parked resume
        // gave up on its own read timeout, so the `\x03` was never written and
        // `pause` could not interrupt a running target at all. Every layer
        // below is sound — transport, wire ordering and `RspClient::request`
        // each round-trip an interrupt correctly (see the three tests in
        // `ios::rsp::tests`) — the defect was only ever this lock.
        let interrupter = self.interrupter.read().clone();
        let Some(interrupter) = interrupter else {
            // No interrupter means either "not attached" or "attached over a
            // transport with no out-of-band write". Telling them apart must
            // also not block: a session that is locked is by definition a
            // session that exists, so only a lock we can take AND find empty
            // proves detachment.
            let detached = self.session.try_lock().is_some_and(|g| g.is_none());
            return Err(if detached {
                DebugError::NotAttached
            } else {
                DebugError::Unsupported(format!(
                    "transport {} cannot be written to out of band, so the asynchronous \
                     interrupt (\\x03) cannot be delivered while the target runs; reach the \
                     same debugserver over TCP, or stop the target with a breakpoint",
                    self.factory.description()
                ))
            });
        };
        let gate = self.resume_in_flight.lock();
        if !*gate {
            // Already stopped: nothing to interrupt, and injecting the byte
            // would leave an unmatched stop reply behind.
            return Ok(());
        }
        interrupter.interrupt().map_err(|e| {
            DebugError::Os(format!(
                "sending \\x03 through {}: {e}",
                interrupter.description()
            ))
        })?;
        drop(gate);
        Ok(())
    }

    // -- threads ------------------------------------------------------------

    async fn threads(&self) -> Result<Vec<ThreadId>, DebugError> {
        self.with_session(|s| {
            let ids = s.client.thread_ids().map_err(|e| rsp_err("qfThreadInfo", &e))?;
            Ok(ids
                .into_iter()
                .map(|t| ThreadId(u32::try_from(t).unwrap_or(0)))
                .collect())
        })
    }

    async fn current_thread(&self) -> Result<ThreadId, DebugError> {
        self.with_session(|s| {
            if s.current_tid.0 != 0 {
                return Ok(s.current_tid);
            }
            let qc = s.text(b"qC", "qC")?;
            let tid = qc
                .strip_prefix("QC")
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .ok_or_else(|| DebugError::Os(format!("qC reply not understood: {qc:?}")))?;
            s.current_tid = ThreadId(tid);
            Ok(s.current_tid)
        })
    }

    // -- registers ----------------------------------------------------------

    async fn get_registers(&self, tid: ThreadId) -> Result<RegisterSet, DebugError> {
        self.with_session(|s| s.read_register_set(tid))
    }

    async fn set_registers(&self, tid: ThreadId, regs: RegisterSet) -> Result<(), DebugError> {
        self.with_session(|s| {
            s.select_thread(tid)?;
            // Read-modify-write: the `G` packet is all-or-nothing, so writing a
            // block built from only the integer registers would zero the vector
            // file.
            let mut block = s.client.read_registers().map_err(|e| rsp_err("g", &e))?;
            let dropped = s.regs.encode_into(&regs, &mut block);
            // Refuse rather than report a write that did not happen. Silently
            // dropping a name the `g` block cannot carry told the caller its
            // change had landed while the target kept its old value — the same
            // defect `set_register` is guarded against on the singular path.
            if !dropped.is_empty() {
                return Err(DebugError::RegisterError(format!(
                    "these registers cannot be written through the register block and were not applied: {}",
                    dropped.join(", ")
                )));
            }
            s.client.write_registers(&block).map_err(|e| rsp_err("G", &e))
        })
    }

    async fn get_register(&self, tid: ThreadId, name: &str) -> Result<u64, DebugError> {
        self.with_session(|s| {
            s.select_thread(tid)?;
            let info = s
                .regs
                .by_name(name)
                .ok_or_else(|| DebugError::RegisterError(format!("no register named {name:?}")))?;
            let (regnum, size) = (info.regnum, info.byte_size() as usize);
            if size > 8 {
                return Err(DebugError::RegisterError(format!(
                    "{name} is {} bits wide and does not fit a u64",
                    info.bitsize
                )));
            }
            let text = s.text(&commands::read_register(regnum), "p")?;
            let bytes = crate::ios::rsp::hex_decode(text.as_bytes())
                .map_err(|e| DebugError::RegisterError(format!("p{regnum:x} reply: {e}")))?;
            let mut buf = [0u8; 8];
            let n = size.min(bytes.len());
            buf[..n].copy_from_slice(&bytes[..n]);
            Ok(u64::from_le_bytes(buf))
        })
    }

    async fn set_register(&self, tid: ThreadId, name: &str, value: u64) -> Result<(), DebugError> {
        self.with_session(|s| {
            s.select_thread(tid)?;
            let info = s
                .regs
                .by_name(name)
                .ok_or_else(|| DebugError::RegisterError(format!("no register named {name:?}")))?;
            let (regnum, size) = (info.regnum, info.byte_size() as usize);
            if size > 8 {
                return Err(DebugError::RegisterError(format!(
                    "{name} is {} bits wide; write it through set_registers",
                    info.bitsize
                )));
            }
            let text = s.text(&commands::write_register(regnum, &value.to_le_bytes()[..size]), "P")?;
            if text.starts_with("OK") {
                Ok(())
            } else {
                Err(DebugError::RegisterError(format!(
                    "stub rejected P{regnum:x} ({name}): {text:?}"
                )))
            }
        })
    }

    // -- memory -------------------------------------------------------------

    async fn read_memory(&self, addr: Address, size: usize) -> Result<Vec<u8>, DebugError> {
        let mut bytes = self.with_session(|s| {
            s.client
                .read_memory(addr.as_u64(), size)
                .map_err(|e| DebugError::MemoryError(addr.as_u64(), e.to_string()))
        })?;
        // Hide the traps THIS backend planted itself.
        //
        // Without this the caller was handed `BRK #0` where the real
        // instruction is — and on AArch64 that is FOUR bytes, so a whole
        // instruction was falsified rather than one byte of it. Every reader is
        // affected the same way: a disassembly view, a step that measures an
        // instruction's length, a conditional-breakpoint expression reading
        // memory. The three native backends have masked since the defect was
        // found there; this one never did.
        //
        // Only the SELF-PATCHED records (`saved: Some`), which is the fallback
        // taken when the stub refused `Z0`. A trap the stub planted is the
        // stub's to hide: `debugserver` already serves the original bytes for
        // its own breakpoints, and masking it here a second time would restore
        // bytes over memory we never patched.
        self.mask_self_planted_traps(addr.as_u64(), &mut bytes);
        Ok(bytes)
    }

    async fn write_memory(&self, addr: Address, data: &[u8]) -> Result<usize, DebugError> {
        // Route the write AROUND those same traps. Letting it through has two
        // wrong outcomes at once: it overwrites the `BRK`, so a breakpoint still
        // listed as enabled silently stops firing, and the bytes it replaced
        // stay recorded as "the original", so removing the breakpoint later
        // restores stale bytes and quietly undoes the caller's write.
        let (to_write, new_originals) = {
            let guard = self.breakpoints.read();
            crate::redirect_writes_over_breakpoints(addr.as_u64(), data, |a| {
                guard.iter().find_map(|((base, _), rec)| {
                    if !rec.bp.enabled || rec.saved.is_none() {
                        return None;
                    }
                    let off = usize::try_from(a.checked_sub(*base)?).ok()?;
                    // The byte of OUR trap that belongs at this address, taken
                    // from the same encoder that planted it.
                    arm64::brk_bytes(0).get(off).copied()
                })
            })
        };
        let written = self.with_session(|s| {
            s.client
                .write_memory(addr.as_u64(), &to_write)
                .map_err(|e| DebugError::MemoryError(addr.as_u64(), e.to_string()))
        })?;
        // Record the new originals only for bytes the target actually took: a
        // short write must not leave us claiming a byte that never landed.
        if !new_originals.is_empty() {
            let mut guard = self.breakpoints.write();
            for (a, byte) in new_originals {
                if a.wrapping_sub(addr.as_u64()) >= written as u64 {
                    continue;
                }
                for ((base, _), rec) in guard.iter_mut() {
                    let Some(orig) = rec.saved.as_mut() else { continue };
                    let Some(off) = a.checked_sub(*base).and_then(|o| usize::try_from(o).ok())
                    else {
                        continue;
                    };
                    // Patch the byte at its OFFSET inside the four-byte trap
                    // rather than replacing the record: a one-byte write must
                    // not shrink what removal will restore.
                    if let Some(slot) = orig.get_mut(off) {
                        *slot = byte;
                    }
                }
            }
        }
        Ok(written)
    }

    async fn memory_maps(&self) -> Result<Vec<MemoryMap>, DebugError> {
        let mut seeds = vec![0u64];
        if let Ok(mods) = self.modules().await {
            seeds.extend(mods.iter().map(|m| m.base.as_u64()));
        }
        if let Ok(tid) = self.current_thread().await
            && let Ok(regs) = self.get_registers(tid).await
        {
            seeds.push(regs.pc);
            seeds.push(regs.sp);
        }
        self.walk_memory_regions(&seeds)
    }

    // -- breakpoints --------------------------------------------------------

    async fn set_breakpoint(&self, addr: Address, kind: BreakpointKind) -> Result<(), DebugError> {
        let a = addr.as_u64();
        // Same CLASS, not merely same address: a code trap and a data
        // watchpoint are independent resources and may coexist here.
        if self.breakpoints.read().contains_key(&(a, BpClass::of(kind))) {
            return Err(DebugError::BreakpointExists(a));
        }
        if kind == BreakpointKind::Software || kind == BreakpointKind::Hardware {
            arm64::check_instruction_alignment(a).map_err(|e| {
                DebugError::Unsupported(format!("breakpoint at {a:#x} is not A64-aligned: {e}"))
            })?;
        }
        let (zkind, size) = z_kind_for(kind);
        // A hardware breakpoint goes through the slot table, which refuses on
        // THIS side when the debug registers are all taken instead of letting
        // the request out and reading whatever the stub says back as gospel.
        // Identical `Z1` on the wire — accounting added, protocol unchanged.
        // Kept in the same position as the software arming below so the
        // "arm before tracking" invariant (`lib.rs`) still reads in order.
        // EVERY hardware kind goes through the table, not just `Hardware`.
        // Routing only execution breakpoints here left the three data kinds on
        // the raw-`Z` branch with no table entry, while `remove_breakpoint` and
        // `disable_breakpoint` dispatch on `hw_kind_for(kind)` — which answers
        // `Some` for them. They looked the entry up, did not find it, and
        // returned `BreakpointNotFound` through `?` BEFORE untracking: a data
        // watchpoint set through this method could never be removed or
        // disabled, and its `Z2`/`Z3`/`Z4` stayed armed in the target. Arming
        // and disarming must agree on which bookkeeping owns an address.
        let accepted = if let Some(hk) = hw_kind_for(kind) {
            let width = usize::try_from(size).unwrap_or(0).max(1);
            self.with_hw(|hw, client| {
                match hk {
                    HwKind::Breakpoint => hw.set_breakpoint(client, a).map(|_| ()),
                    _ => hw.set_watchpoint(client, hk, a, width).map(|_| ()),
                }
                .map(|()| true)
                .map_err(hw_err)
            })?
        } else {
            self.with_session(|s| {
                let text = s.text(&commands::insert_breakpoint(zkind, a, size), "Z")?;
                Ok(text.starts_with("OK"))
            })?
        };

        let mut record = BpRecord {
            // Record the width for every hardware kind, not only execution
            // breakpoints: `enable_breakpoint` re-arms from this field, and a
            // `None` here made it fall back to 8 bytes, silently re-encoding a
            // watchpoint at a width the caller never asked for.
            hw_size: match kind {
                BreakpointKind::Hardware => Some(arm64::INSTRUCTION_SIZE as usize),
                BreakpointKind::Software => None,
                _ => Some(usize::try_from(size).unwrap_or(0).max(1)),
            },
            bp: match kind {
                BreakpointKind::Software => Breakpoint::new_software(addr),
                BreakpointKind::Hardware => Breakpoint::new_hardware(addr),
                other => Breakpoint::new_watchpoint(addr, other),
            },
            saved: None,
        };

        if !accepted {
            if kind != BreakpointKind::Software {
                return Err(DebugError::Unsupported(format!(
                    "stub does not support {kind:?} breakpoints (Z{})",
                    zkind.code()
                )));
            }
            // Fallback: install the A64 `BRK #0` ourselves, keeping the four
            // original bytes so the patch is exactly reversible. `Breakpoint`
            // only models a single `original_byte` (an x86 `int3` assumption),
            // so the full word is kept here and the first byte mirrored there
            // for the hub crate's benefit.
            let original = self.with_session(|s| {
                let orig = s
                    .client
                    .read_memory(a, 4)
                    .map_err(|e| DebugError::MemoryError(a, format!("save original: {e}")))?;
                s.client
                    .write_memory(a, &arm64::brk_bytes(0))
                    .map_err(|e| DebugError::MemoryError(a, format!("patch BRK: {e}")))?;
                Ok(orig)
            })?;
            record.bp.original_byte = original.first().copied();
            record.saved = Some(original);
        }

        self.breakpoints.write().insert((a, BpClass::of(kind)), record);
        Ok(())
    }

    /// Honours the requested width: the `Z2`/`Z3`/`Z4` length is `size`, not the
    /// fixed 8 bytes `z_kind_for` hands out when no width is known.
    async fn set_watchpoint_sized(
        &self,
        addr: Address,
        kind: BreakpointKind,
        size: u8,
    ) -> Result<(), DebugError> {
        let a = addr.as_u64();
        if matches!(kind, BreakpointKind::Software | BreakpointKind::Hardware) {
            // Not a data watchpoint: width is the instruction length.
            return self.set_breakpoint(addr, kind).await;
        }
        if size == 0 {
            return Err(DebugError::Unsupported(
                "a watchpoint covering zero bytes watches nothing".to_string(),
            ));
        }
        // Same CLASS, not merely same address: a code trap and a data
        // watchpoint are independent resources and may coexist here.
        if self.breakpoints.read().contains_key(&(a, BpClass::of(kind))) {
            return Err(DebugError::BreakpointExists(a));
        }
        let hk = hw_kind_for(kind).ok_or_else(|| {
            DebugError::Unsupported(format!("{kind:?} is not a data watchpoint"))
        })?;
        // Same `Z2`/`Z3`/`Z4` as before, but the watchpoint file is accounted
        // for: exhaustion is refused here, with the capacity named, rather than
        // discovered from a stub reply that some targets do not even give.
        self.with_hw(|hw, client| {
            hw.set_watchpoint(client, hk, a, usize::from(size))
                .map(|_| ())
                .map_err(hw_err)
        })?;
        self.breakpoints.write().insert(
            (a, BpClass::Data),
            BpRecord {
                bp: Breakpoint::new_watchpoint(addr, kind),
                saved: None,
                hw_size: Some(usize::from(size)),
            },
        );
        Ok(())
    }

    async fn remove_breakpoint(&self, addr: Address) -> Result<(), DebugError> {
        // EVERY resource at the address. Un-arming one and untracking both
        // left the other live in the target and invisible to `detach`'s sweep.
        let classes = self.classes_at(addr.as_u64());
        if classes.is_empty() {
            return Err(DebugError::BreakpointNotFound(addr.as_u64()));
        }
        for class in classes {
            self.remove_one(addr, class).await?;
        }
        Ok(())
    }

    async fn enable_breakpoint(&self, addr: Address) -> Result<(), DebugError> {
        // EVERY resource at the address, not merely the first one found.
        let classes = self.classes_at(addr.as_u64());
        if classes.is_empty() {
            return Err(DebugError::BreakpointNotFound(addr.as_u64()));
        }
        for class in classes {
            self.enable_one(addr, class).await?;
        }
        Ok(())
    }

    async fn disable_breakpoint(&self, addr: Address) -> Result<(), DebugError> {
        // EVERY resource at the address. Disabling only the first left the
        // other armed AND unreachable: a second call re-found the
        // already-disabled one and returned `Ok` without touching it.
        let classes = self.classes_at(addr.as_u64());
        if classes.is_empty() {
            return Err(DebugError::BreakpointNotFound(addr.as_u64()));
        }
        for class in classes {
            self.disable_one(addr, class).await?;
        }
        Ok(())
    }

    async fn breakpoints(&self) -> Result<Vec<Breakpoint>, DebugError> {
        Ok(self.breakpoints.read().values().map(|r| r.bp.clone()).collect())
    }

    // -- modules ------------------------------------------------------------

    async fn modules(&self) -> Result<Vec<ModuleInfo>, DebugError> {
        let json = self.with_session(|s| {
            s.text(b"jGetLoadedDynamicLibrariesInfos:{\"fetch_all_solibs\":true}", "jGetLoadedDynamicLibrariesInfos")
        })?;
        if json.is_empty() {
            return Err(DebugError::Unsupported(
                "stub does not implement jGetLoadedDynamicLibrariesInfos; this backend will not \
                 fabricate a module list"
                    .to_string(),
            ));
        }
        let root: serde_json::Value = serde_json::from_str(&json)
            .map_err(|e| DebugError::Os(format!("jGetLoadedDynamicLibrariesInfos: {e}")))?;
        let images = root
            .get("images")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| DebugError::Os("image list has no `images` array".to_string()))?;

        let mut out = Vec::with_capacity(images.len());
        for img in images {
            let base = img.get("load_address").and_then(serde_json::Value::as_u64).unwrap_or(0);
            let path = img
                .get("pathname")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string();
            let filetype = img
                .get("mach_header")
                .and_then(|h| h.get("filetype"))
                .and_then(serde_json::Value::as_u64);
            // Size is not in the reply. Rather than reporting 0 as if it were
            // measured, take it from the region the header sits in.
            let size = self
                .with_session(|s| {
                    let text = s.text(MemoryRegionInfo::command(base).as_bytes(), "qMemoryRegionInfo")?;
                    Ok(MemoryRegionInfo::parse(&text).ok().filter(MemoryRegionInfo::is_mapped).map_or(0, |r| r.size))
                })
                .unwrap_or(0);
            out.push(ModuleInfo {
                name: path.rsplit('/').next().unwrap_or(&path).to_string(),
                path,
                base: Address::new(base),
                size,
                // The reply carries no entry point; inventing one would be the
                // exact kind of confident wrongness this repo punishes.
                entry_point: None,
                is_main: filetype == Some(2), // MH_EXECUTE
            });
        }
        Ok(out)
    }

    // -- stack --------------------------------------------------------------

    async fn backtrace(&self, tid: ThreadId) -> Result<Vec<StackFrame>, DebugError> {
        self.require_arm64("backtrace")?;
        let regs = self.get_registers(tid).await?;
        let unwind_regs = Arm64UnwindRegs::from(&regs);
        // Feed the unwinder the target's own images so the CompactUnwind and
        // EhFrame strategies can actually run: with none, only the
        // frame-pointer walk was ever reachable, which on arm64 misses the
        // majority of functions.
        let images = self.unwind_images().await;
        let mut frames: Vec<StackFrame> = self.with_session(|s| {
            let unwinder = images
                .into_iter()
                .fold(AppleUnwinder::new(), AppleUnwinder::with_image);
            let mem = RspMemory { client: Mutex::new(&mut s.client) };
            Ok(unwinder
                .backtrace(unwind_regs, &mem)
                .iter()
                .map(crate::ios::unwind::UnwindFrame::to_stack_frame)
                .collect())
        })?;
        // `load_symbols_from_target()` existed but had to be called by hand, so
        // in practice frames stayed nameless. Do it here, lazily (only when a
        // backtrace is actually wanted) and once (reading every image out of
        // the target is expensive).
        self.maybe_auto_load_symbols().await;
        if let Some(resolver) = self.resolver.read().clone() {
            crate::symbol_resolver::enrich_frames(&mut frames, resolver.as_ref());
        }
        Ok(frames)
    }

    fn set_symbol_resolver(&self, resolver: Arc<dyn FrameSymbolResolver>) -> Result<(), DebugError> {
        *self.resolver.write() = Some(resolver);
        // Whatever is in the slot now came from outside this backend (or from
        // `load_symbols_from_target()` called by hand), so it is not the
        // auto-built resolver and must not be dropped on detach.
        self.auto_installed.store(false, Ordering::SeqCst);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ios::mock_debugserver::MockDebugserver;

    const TEXT_BASE: u64 = 0x1_0000_4000;

    /// A tiny A64 program: a leaf that stores to the stack, called from a
    /// frame-pointer-establishing caller, so a backtrace has something real to
    /// walk.
    ///
    /// ```text
    /// 0x…4000  stp  x29, x30, [sp, #-16]!   (caller prologue)
    /// 0x…4004  mov  x29, sp
    /// 0x…4008  bl   +0x10  -> 0x…4018
    /// 0x…400c  ldp  x29, x30, [sp], #16
    /// 0x…4010  ret
    /// 0x…4014  brk  #0
    /// 0x…4018  stp  x29, x30, [sp, #-16]!   (callee prologue)
    /// 0x…401c  mov  x29, sp
    /// 0x…4020  movz x0, #0x2a               (callee body — breakpoint target)
    /// 0x…4024  ldp  x29, x30, [sp], #16
    /// 0x…4028  ret
    /// ```
    ///
    /// The callee establishes a frame of its own on purpose. Without a
    /// prologue, `x29` at the breakpoint would still belong to the *caller*,
    /// and walking it would skip a frame rather than recover one — which is
    /// exactly the shape that makes a backtrace test pass while the unwinder
    /// is wrong.
    fn program() -> Vec<u32> {
        vec![
            0xA9BF_7BFD, // stp x29, x30, [sp, #-16]!
            0x9100_03FD, // mov x29, sp
            0x9400_0004, // bl #+0x10
            0xA8C1_7BFD, // ldp x29, x30, [sp], #16
            0xD65F_03C0, // ret
            0xD420_0000, // brk #0
            0xA9BF_7BFD, // stp x29, x30, [sp, #-16]!
            0x9100_03FD, // mov x29, sp
            0xD280_0540, // movz x0, #0x2a
            0xA8C1_7BFD, // ldp x29, x30, [sp], #16
            0xD65F_03C0, // ret
        ]
    }

    fn debugger() -> AppleDebugger {
        let srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        // 7 bytes per recv: a prime chunk size, so any assumption that one
        // read yields one packet fails immediately.
        AppleDebugger::new(Arc::new(LoopbackFactory::new(srv, 7)))
    }

    /// When the stub has no server-managed software breakpoints, this backend
    /// falls back to patching an A64 `BRK #0` into the target itself and keeps
    /// the original word so the patch is reversible.
    ///
    /// `remove_breakpoint` writes that word back; `detach()` did NOT — it
    /// cleared its table and abandoned the `BRK` in the target's code, where
    /// it raises SIGTRAP with no debugger left to handle it and terminates the
    /// process. The same defect fixed for the other three backends in iter
    /// 245, in a FOURTH `Debugger` impl the source guards never covered.
    ///
    /// The loopback factory serves exactly one connection, so the state after
    /// `detach` cannot be re-read here; this proves the patch/restore
    /// mechanism detach now uses, and
    /// `every_backend_undoes_its_own_patches_on_detach` guards the ordering.
    /// A watchpoint hit must name the WATCHED address, its direction, and be counted.
    ///
    /// Three defects in one reply. The stub says which address tripped, in a
    /// `watch:` / `rwatch:` / `awatch:` key; all three keys were discarded and
    /// the report was built from the PC — so the caller was told the program had
    /// touched the address of the instruction, which is the one question a
    /// watchpoint exists to answer. The direction was hard-wired to `is_write:
    /// true`, so a read watch was reported as a write. And nothing counted the
    /// hit, so `breakpoints()` published zero hits for a watchpoint that stops
    /// the program over and over.
    ///
    /// The PC must NOT be rewound onto the watched address either: that is a
    /// data address, and putting it in the PC sends the target off to execute
    /// its own variables.
    #[tokio::test]
    async fn a_watchpoint_hit_names_the_watched_address_not_the_program_counter() {
        let dbg = debugger();
        dbg.attach(ProcessId(4242)).await.expect("attach");
        let tid = dbg.current_thread().await.expect("current thread");

        // The program opens with `stp x29, x30, [sp, #-16]!` and later reloads
        // that pair with `ldp x29, x30, [sp], #16`. A READ watch on the slot
        // therefore stays quiet through the store and fires on the load, which
        // is what makes the direction observable: a write watch would have
        // fired first and proved nothing about `is_write`.
        let sp = dbg.get_registers(tid).await.expect("registers").sp;
        let watched = sp - 16;
        dbg.set_breakpoint(Address::new(watched), BreakpointKind::DataRead)
            .await
            .expect("read watchpoint");

        let mut hit = None;
        for _ in 0..16 {
            let ev = dbg.continue_execution().await.expect("continue");
            if let StopReason::AccessViolation { address, is_write } = ev.reason {
                hit = Some((address.as_u64(), is_write));
                break;
            }
            if ev.reason.is_exit() {
                break;
            }
        }
        let (address, is_write) = hit.expect(
            "the read watch never fired, so this test says nothing about how a hit is reported",
        );
        assert_eq!(
            address, watched,
            "the hit was reported at the program counter instead of the watched address"
        );
        assert!(
            !is_write,
            "a READ watch was reported as a write: the direction is hard-wired instead of read from the stop reply"
        );

        let listed = dbg.breakpoints().await.expect("breakpoints");
        let wp = listed
            .iter()
            .find(|b| b.address.as_u64() == watched)
            .expect("the watchpoint must still be listed");
        assert_eq!(
            wp.hit_count, 1,
            "the hit was not counted, so breakpoints() reports zero hits for a watchpoint that just stopped the program"
        );
    }

    /// `set_registers` must refuse a register it cannot actually write.
    ///
    /// The plural door dropped silently what the singular door rejects loudly.
    /// Three names go nowhere through the `g` block: one the target does not
    /// have, one reachable only via `p`/`P` (no offset in the block), and one
    /// wider than 64 bits. All three used to be skipped, and `set_registers`
    /// then answered `Ok(())` — the caller believed its change had landed while
    /// the target kept its old value.
    ///
    /// The round trip must keep working, and that is the other half of this
    /// test: `decode` fills the set by exactly the same placeability rules, so
    /// read-modify-write cannot start failing because of the new refusal.
    #[tokio::test]
    async fn set_registers_refuses_a_name_it_cannot_actually_write() {
        let dbg = debugger();
        dbg.attach(ProcessId(4242)).await.expect("attach");
        let tid = dbg.current_thread().await.expect("current thread");

        // Read-modify-write still succeeds: everything decode produced is
        // placeable by construction.
        let mut regs = dbg.get_registers(tid).await.expect("get_registers");
        regs.set("x0", 0x1234);
        dbg.set_registers(tid, regs.clone()).await.expect("a round trip must still work");
        assert_eq!(
            dbg.get_register(tid, "x0").await.expect("x0"),
            0x1234,
            "the write must really reach the target, or the refusal below proves nothing"
        );

        // A name the target does not have must be refused, not dropped.
        let mut bogus = regs;
        bogus.set("not_a_register", 7);
        let err = dbg.set_registers(tid, bogus).await;
        assert!(
            err.is_err(),
            "set_registers accepted a register the target does not have, wrote nothing for it, and reported success"
        );
    }

    /// A target KILLED by a signal is gone, and must be reported as gone.
    ///
    /// RSP has two endings: `W` (exited with a status) and `X` (killed by a
    /// signal). Only the first was treated as one. `X` came back as
    /// `StopReason::Signal`, which says "stopped, resumable" — so every
    /// `while !ev.reason.is_exit()` loop went on resuming a corpse, and the
    /// tables the `W` path clears stayed populated: the next target inherited
    /// breakpoints that exist nowhere and debug-register slots held by a dead
    /// process. `StopReply::is_exit` in the protocol layer already said `X` was
    /// an ending; the classification above it disagreed.
    #[tokio::test]
    async fn a_target_killed_by_a_signal_is_reported_as_gone() {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        srv.kill_with_signal(9); // SIGKILL, as an `X` stop reply
        let dbg = AppleDebugger::new(Arc::new(LoopbackFactory::new(srv, 7)));
        dbg.attach(ProcessId(4242)).await.expect("attach");
        dbg.set_breakpoint(Address::new(TEXT_BASE), BreakpointKind::Software)
            .await
            .expect("set_breakpoint");
        assert_eq!(
            dbg.breakpoints().await.expect("breakpoints").len(),
            1,
            "the breakpoint must be tracked first, or the assertion about clearing proves nothing"
        );

        let ev = dbg.continue_execution().await.expect("continue");
        assert!(
            ev.reason.is_exit(),
            "a target killed by a signal was reported as a resumable stop ({:?}) — every loop that runs until the target exits keeps resuming a dead process",
            ev.reason
        );
        assert!(
            matches!(ev.reason, StopReason::ProcessExit { exit_code: -9 }),
            "a signal death must carry the signal, encoded as the two unix backends already encode it, but was {:?}",
            ev.reason
        );
        assert!(
            dbg.breakpoints().await.expect("breakpoints").is_empty(),
            "the dead target's breakpoints are still tracked: the next target inherits traps that exist nowhere"
        );
    }

    /// The target must be able to get PAST a breakpoint it is standing on.
    ///
    /// On AArch64 a `BRK` exception is precise: the program counter stays on the
    /// trap. So resuming from a stop caused by one of our own self-patched
    /// breakpoints re-executes it and stops again at the same address, forever —
    /// the target can never pass its own breakpoint. The three native backends
    /// grew a step-off for exactly this in iteration 357; this fourth `Debugger`
    /// impl never had one.
    ///
    /// Observed ON THE WIRE, because that is where the difference lives: a
    /// correct resume writes the original word back, takes ONE step, puts the
    /// `BRK` back, and only then continues. The mock's packet log shows all four
    /// in order; without the step-off it shows only the continue.
    #[tokio::test]
    async fn resuming_from_a_self_patched_breakpoint_steps_off_it_first() {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        srv.refuse_software_breakpoints(); // force the self-patching fallback
        let (addr, server) = srv.spawn_tcp().expect("spawn tcp mock");
        {
            let dbg = AppleDebugger::tcp(addr, Some(std::time::Duration::from_secs(30)));
            dbg.attach(ProcessId(4242)).await.expect("attach");
            dbg.set_breakpoint(Address::new(TEXT_BASE), BreakpointKind::Software)
                .await
                .expect("set_breakpoint");
            let _ = dbg.continue_execution().await;
        } // the socket closes here, ending the server loop
        let srv = server.join().expect("mock server thread");

        let steps = srv.packet_log.iter().filter(|p| p.starts_with("vCont;s")).count();
        assert!(
            steps >= 1,
            "the resume issued no single step, so the target was told to continue while standing on its own BRK — it stops again at the same address, forever. Packets seen: {:?}",
            srv.packet_log
        );
        // And the trap must be back afterwards: a step-off that forgets to
        // re-plant disarms a breakpoint the debugger still lists as enabled.
        let writes = srv.packet_log.iter().filter(|p| p.starts_with('M')).count();
        assert!(
            writes >= 3,
            "expected the original word written back, then the BRK re-planted, on top of the initial patch — only {writes} memory writes reached the target. Packets seen: {:?}",
            srv.packet_log
        );
    }

    /// `step_over` must decode the instruction, not the trap sitting on it.
    ///
    /// `instruction_at` fed `step_over`'s call detection, and it read RAW memory.
    /// After a breakpoint hit — the normal moment to step over something — the
    /// word at `pc` is one of our own `BRK #0`s, so the decode saw no call and
    /// `step_over` degraded to a plain single step. Stepping over a `bl` at a
    /// breakpoint address therefore stepped INTO the function, silently, exactly
    /// when breakpoints are in use.
    ///
    /// The third instruction of the mock program is a `bl`, which makes the two
    /// behaviours distinguishable: masked it decodes as a call, unmasked it
    /// decodes as `BRK`.
    #[tokio::test]
    async fn the_instruction_under_a_planted_trap_is_still_decoded_correctly() {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        srv.refuse_software_breakpoints(); // force the self-patching fallback
        let dbg = AppleDebugger::new(Arc::new(LoopbackFactory::new(srv, 7)));
        dbg.attach(ProcessId(4242)).await.expect("attach");

        // The `bl` at offset 8.
        let call_site = TEXT_BASE + 8;
        let before = dbg.instruction_at(call_site).expect("decode before planting");
        assert!(
            crate::ios::arm64::BranchKind::decode(before)
                .is_some_and(crate::ios::arm64::BranchKind::is_call),
            "the fixture must really hold a call here, or this test proves nothing"
        );

        dbg.set_breakpoint(Address(call_site), BreakpointKind::Software)
            .await
            .expect("set_breakpoint");
        assert_eq!(
            dbg.read_memory_raw(Address(call_site), 4).await.expect("raw"),
            crate::ios::arm64::brk_bytes(0),
            "the trap must really be planted, or the assertion below is vacuous"
        );

        let after = dbg.instruction_at(call_site).expect("decode after planting");
        assert_eq!(
            after, before,
            "the instruction decoded under a planted breakpoint is the trap, not the instruction — step_over sees no call and steps INTO the callee instead of over it"
        );
    }

    /// A caller must never see this backend's own `BRK` in the memory it reads,
    /// and a write over one must not destroy it.
    ///
    /// On AArch64 the trap is FOUR bytes, so an unmasked read does not corrupt a
    /// byte of the caller's view — it replaces a whole instruction with a
    /// different one. Everything downstream is misled in the same breath: a
    /// disassembly, a step that measures instruction length, an expression that
    /// reads code. The three native backends have masked since the defect was
    /// found on them; this fourth `Debugger` impl never did.
    ///
    /// The write half is the one with two failure modes at once: it overwrites
    /// the trap, so a breakpoint still listed as enabled stops firing, and the
    /// bytes it replaced become the recorded "original", so removal later
    /// restores stale bytes and silently undoes the caller's own write.
    #[tokio::test]
    async fn a_self_patched_breakpoint_is_hidden_from_reads_and_survives_writes() {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        srv.refuse_software_breakpoints(); // force the self-patching fallback
        let dbg = AppleDebugger::new(Arc::new(LoopbackFactory::new(srv, 7)));
        dbg.attach(ProcessId(4242)).await.expect("attach");

        let addr = Address(TEXT_BASE);
        let original = dbg.read_memory(addr, 8).await.expect("read original");
        dbg.set_breakpoint(addr, BreakpointKind::Software).await.expect("set_breakpoint");

        // The trap is really there...
        assert_eq!(
            dbg.read_memory_raw(addr, 4).await.expect("raw read"),
            crate::ios::arm64::brk_bytes(0),
            "the fallback must really patch the target, or this test proves nothing"
        );
        // ...and the caller must not be able to tell.
        assert_eq!(
            dbg.read_memory(addr, 8).await.expect("masked read"),
            original,
            "read_memory handed back BRK #0 where the instruction is — on AArch64 that is a whole instruction replaced, not one byte of one"
        );

        // A write landing on the trap must leave the trap standing and take the
        // new bytes as what removal will restore.
        let patch = [0x11u8, 0x22, 0x33, 0x44];
        dbg.write_memory(addr, &patch).await.expect("write over the breakpoint");
        assert_eq!(
            dbg.read_memory_raw(addr, 4).await.expect("raw read after write"),
            crate::ios::arm64::brk_bytes(0),
            "the write went through unrouted and wiped the trap: the breakpoint is still listed as enabled and will never fire again"
        );
        assert_eq!(
            dbg.read_memory(addr, 4).await.expect("masked read after write"),
            patch,
            "the caller's own write is not visible through the mask, so the saved original is stale and removing the breakpoint would undo it"
        );
    }

    #[tokio::test]
    async fn a_self_patched_breakpoint_is_reversible() {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        srv.refuse_software_breakpoints(); // force the manual fallback
        let dbg = AppleDebugger::new(Arc::new(LoopbackFactory::new(srv, 7)));
        dbg.attach(ProcessId(4242)).await.expect("attach");

        let addr = Address(TEXT_BASE);
        let original = dbg.read_memory(addr, 4).await.expect("read original");
        dbg.set_breakpoint(addr, BreakpointKind::Software).await.expect("set_breakpoint");

        // RAW on purpose: `read_memory` now masks this backend's own traps, so
        // the masked view would (correctly) show the original word and this
        // assertion would be checking the mask instead of the patch.
        let patched = dbg.read_memory_raw(addr, 4).await.expect("read patched");
        assert_ne!(patched, original, "the fallback must really patch the target");
        assert_eq!(
            patched,
            crate::ios::arm64::brk_bytes(0),
            "the fallback must plant an A64 BRK #0"
        );

        dbg.remove_breakpoint(addr).await.expect("remove_breakpoint");
        assert_eq!(
            dbg.read_memory(addr, 4).await.expect("read restored"),
            original,
            "a self-patched breakpoint must be exactly reversible"
        );
        dbg.detach().await.ok();
    }

    #[test]
    fn arch_classification_separates_arm64e() {
        assert_eq!(TargetArch::from_cpu(CPU_TYPE_ARM64, 0), TargetArch::Arm64);
        assert_eq!(TargetArch::from_cpu(CPU_TYPE_ARM64, 2), TargetArch::Arm64e);
        assert_eq!(TargetArch::from_cpu(CPU_TYPE_X86_64, 3), TargetArch::X86_64);
        assert!(matches!(TargetArch::from_cpu(12, 9), TargetArch::Other(12)));
        assert!(TargetArch::Arm64e.is_arm64());
        assert!(!TargetArch::X86_64.is_arm64());
    }

    #[test]
    fn z_kind_mapping_is_total_and_distinct() {
        let kinds = [
            BreakpointKind::Software,
            BreakpointKind::Hardware,
            BreakpointKind::DataRead,
            BreakpointKind::DataWrite,
            BreakpointKind::DataReadWrite,
        ];
        let codes: Vec<u8> = kinds.iter().map(|k| z_kind_for(*k).0.code()).collect();
        assert_eq!(codes, vec![0, 1, 3, 2, 4]);
        // Instruction breakpoints are 4 bytes; watchpoints size a region.
        assert_eq!(z_kind_for(BreakpointKind::Software).1, 4);
        assert_eq!(z_kind_for(BreakpointKind::DataWrite).1, 8);
    }

    #[tokio::test]
    async fn unattached_calls_report_not_attached_rather_than_panicking() {
        let dbg = debugger();
        assert!(!dbg.is_attached());
        assert!(dbg.target_pid().is_none());
        assert!(matches!(dbg.threads().await, Err(DebugError::NotAttached)));
        assert!(matches!(
            dbg.read_memory(Address::new(TEXT_BASE), 4).await,
            Err(DebugError::NotAttached)
        ));
        assert!(matches!(dbg.detach().await, Err(DebugError::NotAttached)));
        assert!(matches!(dbg.pause().await, Err(DebugError::NotAttached)));
    }

    // -- asynchronous interrupt (`pause`) ---------------------------------

    /// A transport that cannot be written to out of band must SAY SO.
    ///
    /// The in-process loopback owns the `MockDebugserver` and computes each
    /// reply inside `send`, so there is no second handle and no window in which
    /// the client is parked. The one answer that would be a bug is `Ok(())`:
    /// that would claim an interrupt was delivered to a target that never saw
    /// a byte.
    #[tokio::test]
    async fn pause_on_a_transport_without_an_out_of_band_handle_is_explicit() {
        let dbg = debugger();
        dbg.attach(ProcessId(4242)).await.expect("attach");
        match dbg.pause().await {
            Err(DebugError::Unsupported(msg)) => {
                assert!(
                    msg.contains("out of band"),
                    "reason must name the missing capability, got {msg:?}"
                );
                assert!(msg.contains("loopback"), "reason must name the transport, got {msg:?}");
            }
            other => panic!("expected an explicit Unsupported, got {other:?}"),
        }
    }

    /// With a real socket, `pause()` must deliver `\x03` **while the target is
    /// running** and the resume must come back as a SIGINT stop.
    ///
    /// This is the test the feature exists for, and it can only be written
    /// against a transport with two properties the loopback lacks: a
    /// duplicable write end, and a reader that really parks. The mock is put in
    /// `run_until_interrupt` mode so a continue is answered by silence — the
    /// only state in which an asynchronous interrupt means anything.
    ///
    /// Before the transport grew `RspInterrupter`, `pause()` returned
    /// `Unsupported` unconditionally and this could not pass at all.
    // Multi-threaded on purpose: `continue_execution` blocks inline on a socket
    // read (the RSP exchange is synchronous by design), so on the default
    // current-thread runtime the spawned runner would monopolise the only
    // worker and the poll loop below could never run.
    /// A watchpoint must cover the width the caller asked for.
    ///
    /// `BreakpointKind` carries no size, so `set_breakpoint` left the watched
    /// region to the backend and this one sent a fixed 8 bytes for every
    /// watchpoint. A caller watching a 4-byte struct field was told its field
    /// was covered while the region also spanned the NEXT field: a write to the
    /// neighbour reported this field as changed. The stub records the `Z`
    /// length, so the width that actually went on the wire can be measured
    /// rather than assumed.
    #[tokio::test]
    async fn a_sized_watchpoint_covers_exactly_the_requested_width() {
        let srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        let (addr, server) = srv.spawn_tcp().expect("spawn tcp mock");
        let dbg = AppleDebugger::tcp(addr, Some(std::time::Duration::from_secs(30)));
        dbg.attach(ProcessId(4242)).await.expect("attach");

        dbg.set_watchpoint_sized(Address::new(TEXT_BASE + 0x20), BreakpointKind::DataWrite, 4)
            .await
            .expect("a 4-byte watchpoint");

        // Close the connection so the stub thread hands the server back.
        drop(dbg);
        let srv = server.join().expect("stub thread");
        let planted = srv.breakpoints();
        let wp = planted
            .iter()
            .find(|b| b.addr == TEXT_BASE + 0x20)
            .expect("the watchpoint reached the stub");
        assert_eq!(
            wp.len, 4,
            "the stub was asked to watch {} bytes for a 4-byte field",
            wp.len
        );
    }

    /// Hardware breakpoint slots are FINITE, and this side is the one that
    /// knows it.
    ///
    /// `ios/hw_breakpoints.rs` models the `DBGBVR`/`DBGBCR` file with a slot
    /// table and full tests, but `apple_debugger.rs` never imported it: every
    /// `set_breakpoint(Hardware)` went out as a bare `Z1` and exhaustion was
    /// whatever the remote stub happened to answer. That is the "confidently
    /// wrong" shape this crate keeps punishing — a stub that accepts the fifth
    /// `Z1` on a four-register core leaves the caller holding a breakpoint that
    /// will never fire, and a stub that refuses gives back a message about the
    /// PACKET rather than about the resource, so nobody can tell "free a slot"
    /// from "this target has no hardware breakpoints at all".
    ///
    /// The assertion is on the *provenance* of the refusal: the slot table's
    /// own wording, naming the capacity, and explicitly NOT the stub-rejection
    /// wording. Then a removal must hand the register back, so the arm that was
    /// refused a moment ago succeeds.
    ///
    /// Not vacuous: deleting the `with_hw` branch in `set_breakpoint` (one
    /// line — restoring the old `commands::insert_breakpoint` path) makes the
    /// third arm fail with "stub does not support Hardware breakpoints (Z1)"
    /// and the first assertion fires. Deleting the `clear_breakpoint` call in
    /// `remove_breakpoint` instead leaks the slot and the final arm fails.
    /// Arming must put a `Z` packet ON THE WIRE, not just in a table.
    ///
    /// Every existing test for the hardware path asserts bookkeeping: the slot
    /// table's counts, the tracked records, the error wording. None of them
    /// asserts that anything reaches the target. The adversarial review of the
    /// change that wired the slot table found the hole and named the mutation:
    /// replacing `hw.set_breakpoint(client, a)` with
    /// `hw.table_mut().insert_breakpoint(a)` compiles, sends NO packet, arms
    /// nothing in the process under debug — and leaves every one of those tests
    /// green. A debugger whose breakpoints exist only in its own bookkeeping is
    /// the most expensive way to be wrong, because the session looks healthy.
    ///
    /// The mock records every packet it receives, so this closes the hole by
    /// looking at what the target actually got. Dropping the debugger closes
    /// the socket, which ends the server thread and hands the mock back.
    #[tokio::test]
    async fn arming_hardware_breakpoints_really_sends_z_packets() {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        srv.set_hw_slots(4, 4);
        let (addr, server) = srv.spawn_tcp().expect("spawn tcp mock");

        {
            let dbg = AppleDebugger::tcp(addr, Some(std::time::Duration::from_secs(30)));
            dbg.attach(ProcessId(4242)).await.expect("attach");
            dbg.set_breakpoint(Address::new(TEXT_BASE), BreakpointKind::Hardware)
                .await
                .expect("hardware breakpoint");
            dbg.set_breakpoint(Address::new(TEXT_BASE + 0x40), BreakpointKind::DataWrite)
                .await
                .expect("data watchpoint");
            dbg.remove_breakpoint(Address::new(TEXT_BASE)).await.expect("remove");
        } // the socket closes here, ending the server loop

        let srv = server.join().expect("mock server thread");
        let sent = |prefix: &str| srv.packet_log.iter().any(|p| p.starts_with(prefix));

        assert!(
            sent("Z1,"),
            "no `Z1` reached the target: the hardware breakpoint exists only in this \
             debugger's own table. Packets seen: {:?}",
            srv.packet_log
        );
        assert!(
            sent("Z2,"),
            "no `Z2` reached the target: the write watchpoint was never armed. \
             Packets seen: {:?}",
            srv.packet_log
        );
        assert!(
            sent("z1,"),
            "no `z1` reached the target: removal freed the slot in the table while the \
             breakpoint stayed armed in the process. Packets seen: {:?}",
            srv.packet_log
        );
    }

    /// `detach` must disarm what it armed, in the TARGET, not only in its own
    /// table.
    ///
    /// The sweep before the `D` wrote back the self-patched `BRK` words and
    /// stopped there; the stub-managed `Z0` and the hardware `Z2` were left
    /// installed on the reasoning that "the stub drops them when the connection
    /// does". That is an assumption about the peer, and against the one stub
    /// this backend can be run against it is false: two `Z` packets and zero
    /// `z` packets, both traps still installed with a refcount of 1 after the
    /// `D`. A debugserver reached over a persistent usbmux tunnel behaves the
    /// same way, so the next attach inherits traps it never set and debug
    /// registers its fresh `hw` table hands out as free.
    ///
    /// Not vacuous: reverting `disarm_all_breakpoints` to the old
    /// write-back-`saved`-only body leaves this red on the very first
    /// assertion, and the refcounts are read from the server's own state
    /// rather than from this debugger's bookkeeping.
    #[tokio::test]
    async fn detach_disarms_stub_managed_and_hardware_breakpoints_in_the_target() {
        use crate::ios::mock_debugserver::BpKind;

        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        srv.set_hw_slots(4, 4);
        let (addr, server) = srv.spawn_tcp().expect("spawn tcp mock");

        {
            let dbg = AppleDebugger::tcp(addr, Some(std::time::Duration::from_secs(30)));
            dbg.attach(ProcessId(4242)).await.expect("attach");
            dbg.set_breakpoint(Address::new(TEXT_BASE), BreakpointKind::Software)
                .await
                .expect("software breakpoint");
            dbg.set_breakpoint(Address::new(TEXT_BASE + 0x40), BreakpointKind::DataWrite)
                .await
                .expect("data watchpoint");
            dbg.detach().await.expect("detach");
        } // socket closes, server loop ends

        let srv = server.join().expect("mock server thread");
        assert_eq!(
            srv.breakpoint_refs(TEXT_BASE, BpKind::Software),
            0,
            "the stub-managed `Z0` is still armed in the target after `D`. Packets: {:?}",
            srv.packet_log
        );
        assert_eq!(
            srv.breakpoint_refs(TEXT_BASE + 0x40, BpKind::WriteWatch),
            0,
            "the hardware write watchpoint is still armed in the target after `D`. \
             Packets: {:?}",
            srv.packet_log
        );
        let (inserts, removes) = srv.z_traffic();
        assert_eq!(
            (inserts, removes),
            (2, 2),
            "arming and disarming must be symmetric on the wire. Packets: {:?}",
            srv.packet_log
        );
    }

    /// Removing an address must UN-ARM both resources, not just untrack them.
    ///
    /// The worst shape of the coexistence family. The address-keyed version
    /// un-armed whichever resource the lookup found first and then dropped
    /// BOTH map entries, so the other stayed armed in the target — a debug
    /// register held, or a `Z0` still inserted — with nothing left that knew
    /// about it. `detach`'s restore sweep walks this same map, so it could
    /// never find it either: the leak lasts for the life of the process, and
    /// on ARM64 an abandoned `BRK #0` raises SIGTRAP with no debugger attached,
    /// which kills the target.
    ///
    /// The mock's `z_traffic()` counts inserts and removes on the wire, which
    /// is what makes "was it really un-armed" observable rather than inferred
    /// from our own bookkeeping.
    #[tokio::test]
    async fn removing_an_address_unarms_every_resource_on_the_wire() {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        srv.set_hw_slots(4, 4);
        let (addr, server) = srv.spawn_tcp().expect("spawn tcp mock");

        {
            let dbg = AppleDebugger::tcp(addr, Some(std::time::Duration::from_secs(30)));
            dbg.attach(ProcessId(4242)).await.expect("attach");
            let a = Address::new(TEXT_BASE + 0x40);
            dbg.set_breakpoint(a, BreakpointKind::Software).await.expect("code trap");
            dbg.set_breakpoint(a, BreakpointKind::DataWrite).await.expect("data watchpoint");
            dbg.remove_breakpoint(a).await.expect("remove_breakpoint");
            assert!(
                dbg.breakpoints().await.expect("breakpoints").is_empty(),
                "the tracking map still holds something after removing the only address"
            );
        }

        let srv = server.join().expect("mock server thread");
        let (inserts, removes) = srv.z_traffic();
        assert_eq!(
            inserts, removes,
            "{inserts} resources were armed on the wire and only {removes} un-armed — the \
             leftover stays in the target, and `detach` walks the map we just cleared, so \
             nothing will ever free it. Packets: {:?}",
            srv.packet_log
        );
        assert!(inserts >= 2, "both resources must really have been armed, got {inserts}");
    }

    /// Disabling an address must disable BOTH resources on it.
    ///
    /// Once the two kinds were allowed to coexist (previous iteration),
    /// `disable_breakpoint` still acted on whichever the lookup found first —
    /// `Code`, when both were present. That left the watchpoint armed, and
    /// made it UNREACHABLE: a second call re-found the already-disabled code
    /// trap, saw `enabled == false`, and returned `Ok` without touching the
    /// other. There was no sequence of public calls that could disable it.
    ///
    /// The pattern this session keeps meeting: making something expressible
    /// creates obligations on the methods next to it.
    #[tokio::test]
    async fn disabling_an_address_disables_every_resource_on_it() {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        srv.set_hw_slots(4, 4);
        let (addr, _server) = srv.spawn_tcp().expect("spawn tcp mock");
        let dbg = AppleDebugger::tcp(addr, Some(std::time::Duration::from_secs(30)));
        dbg.attach(ProcessId(4242)).await.expect("attach");

        let a = Address::new(TEXT_BASE + 0x40);
        dbg.set_breakpoint(a, BreakpointKind::Software).await.expect("code trap");
        dbg.set_breakpoint(a, BreakpointKind::DataWrite).await.expect("data watchpoint");
        assert_eq!(
            dbg.breakpoints().await.expect("breakpoints").iter().filter(|b| b.enabled).count(),
            2,
            "both resources must start enabled, or this test proves nothing"
        );

        dbg.disable_breakpoint(a).await.expect("disable_breakpoint");

        let listed = dbg.breakpoints().await.expect("breakpoints");
        let still_on: Vec<_> = listed.iter().filter(|b| b.address == a && b.enabled).collect();
        assert!(
            still_on.is_empty(),
            "disable left {} resource(s) armed at the address: {still_on:?} — and a second \
             disable cannot reach them, because it re-finds the one already disabled",
            still_on.len()
        );

        // And enabling must bring both back, not just one.
        dbg.enable_breakpoint(a).await.expect("enable_breakpoint");
        assert_eq!(
            dbg.breakpoints().await.expect("breakpoints").iter().filter(|b| b.enabled).count(),
            2,
            "enable restored only one of the two resources"
        );
    }

    /// A code trap and a data watchpoint may share one address.
    ///
    /// They are independent resources: a trap in the instruction stream and a
    /// debug register watching that location. Stopping when a function is
    /// entered AND when a variable at the same address is written is an
    /// ordinary thing to ask for, and the hardware allows it.
    ///
    /// The tracking map was keyed by address alone, so the second request
    /// failed with `BreakpointExists` — true about the address, wrong about the
    /// resource. The debugger refused what the target permits.
    #[tokio::test]
    async fn a_code_trap_and_a_data_watchpoint_can_share_an_address() {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        srv.set_hw_slots(4, 4);
        let (addr, _server) = srv.spawn_tcp().expect("spawn tcp mock");
        let dbg = AppleDebugger::tcp(addr, Some(std::time::Duration::from_secs(30)));
        dbg.attach(ProcessId(4242)).await.expect("attach");

        let a = Address::new(TEXT_BASE + 0x40);
        dbg.set_breakpoint(a, BreakpointKind::Software).await.expect("code trap");
        dbg.set_breakpoint(a, BreakpointKind::DataWrite)
            .await
            .expect("a data watchpoint must be allowed alongside a code trap at one address");

        // Both must be LISTED: a caller that cannot see the second one cannot
        // remove it either.
        let listed = dbg.breakpoints().await.expect("breakpoints");
        let at_a: Vec<_> = listed.iter().filter(|b| b.address == a).collect();
        assert_eq!(at_a.len(), 2, "both resources must be listed, got {at_a:?}");
        assert!(at_a.iter().any(|b| matches!(b.kind, BreakpointKind::Software)));
        assert!(at_a.iter().any(|b| matches!(b.kind, BreakpointKind::DataWrite)));

        // A second request of the SAME class is still refused: coexistence is
        // about distinct resources, not about duplicates.
        assert!(
            dbg.set_breakpoint(a, BreakpointKind::Software).await.is_err(),
            "a duplicate code trap at one address must still be refused"
        );

        // Removal by address clears both, leaving nothing tracked there.
        dbg.remove_breakpoint(a).await.expect("remove_breakpoint");
        assert!(
            !dbg.breakpoints().await.expect("breakpoints").iter().any(|b| b.address == a),
            "removing the address left one of the two resources tracked"
        );
    }

    /// A data watchpoint set through `set_breakpoint` must be removable.
    ///
    /// Arming routed only `BreakpointKind::Hardware` through the slot table,
    /// while `remove_breakpoint`/`disable_breakpoint` dispatch on
    /// `hw_kind_for(kind)` — which answers `Some` for the three data kinds too.
    /// So a `DataWrite` set here had no table entry, the removal looked for one
    /// and returned `BreakpointNotFound` through `?` BEFORE untracking: the
    /// record stayed in the map and the `Z2`/`Z3`/`Z4` stayed armed in the
    /// target. Unremovable and unlistable-as-gone, which is the leak class the
    /// comments in this file claim to have fixed.
    ///
    /// Found by the adversarial review of the change that introduced it, not
    /// by a test — which is why this one exists.
    #[tokio::test]
    async fn a_data_watchpoint_set_through_set_breakpoint_can_be_removed() {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        srv.set_hw_slots(2, 2);
        let (addr, _server) = srv.spawn_tcp().expect("spawn tcp mock");
        let dbg = AppleDebugger::tcp(addr, Some(std::time::Duration::from_secs(30)));
        dbg.attach(ProcessId(4242)).await.expect("attach");

        let watched = Address::new(TEXT_BASE + 0x40);
        dbg.set_breakpoint(watched, BreakpointKind::DataWrite)
            .await
            .expect("a data watchpoint must be settable through set_breakpoint");

        dbg.remove_breakpoint(watched).await.unwrap_or_else(|e| {
            panic!(
                "a DataWrite set through set_breakpoint could not be removed: {e} — the record \
                 stays tracked and the watchpoint stays armed in the target"
            )
        });
        assert!(
            !dbg.breakpoints().await.expect("breakpoints").iter().any(|b| b.address == watched),
            "the watchpoint is still tracked after a successful removal"
        );

        // The slot it held must be reusable: two watchpoint slots exist, and a
        // leaked one would show up as an exhaustion here.
        for i in 0..2u64 {
            dbg.set_breakpoint(Address::new(TEXT_BASE + 0x80 + i * 8), BreakpointKind::DataWrite)
                .await
                .unwrap_or_else(|e| panic!("watchpoint {i} after the removal freed a slot: {e}"));
        }
    }

    #[tokio::test]
    async fn hardware_breakpoint_slots_are_accounted_here_not_guessed_from_the_stub() {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        // A core with exactly two instruction debug registers. The stub reports
        // this through `qHardwareBreakpointSupportInfo`, which is where the
        // controller learns the capacity.
        srv.set_hw_slots(2, 2);
        let (addr, _server) = srv.spawn_tcp().expect("spawn tcp mock");
        let dbg = AppleDebugger::tcp(addr, Some(std::time::Duration::from_secs(30)));
        dbg.attach(ProcessId(4242)).await.expect("attach");

        for i in 0..2u64 {
            dbg.set_breakpoint(Address::new(TEXT_BASE + i * 4), BreakpointKind::Hardware)
                .await
                .unwrap_or_else(|e| panic!("hw breakpoint {i} within capacity: {e}"));
        }

        let err = dbg
            .set_breakpoint(Address::new(TEXT_BASE + 8), BreakpointKind::Hardware)
            .await
            .expect_err("a third hardware breakpoint on a two-slot core must be refused");
        let text = err.to_string();
        assert!(
            text.contains("no hardware breakpoint slot free") && text.contains("2 implemented"),
            "the refusal must come from this side's slot table, naming the capacity, \
             got: {text}"
        );
        assert!(
            !text.contains("stub does not support"),
            "exhaustion was reported as a stub rejection, i.e. the slot table is still \
             not in the path: {text}"
        );

        // Freeing a register makes it available again — the other half of
        // owning the accounting.
        dbg.remove_breakpoint(Address::new(TEXT_BASE))
            .await
            .expect("remove the first hardware breakpoint");
        dbg.set_breakpoint(Address::new(TEXT_BASE + 8), BreakpointKind::Hardware)
            .await
            .expect("the slot freed by the removal must be reusable");
    }

    /// When the target exits, its breakpoint records must go with it.
    ///
    /// The patched bytes died with the process, so a surviving record is a
    /// claim about memory that no longer exists. On the next `attach` it is
    /// inherited whole: `set_breakpoint` answers `BreakpointExists` for an
    /// address where nothing is planted, `breakpoints()` lists a breakpoint the
    /// target never had, and `detach`'s restore sweep writes "saved originals"
    /// into a process that never carried them. `kill()` already clears the
    /// table for precisely this reason — a natural exit is the far commoner
    /// way for a target to end, and it did not.
    #[tokio::test]
    async fn a_process_exit_drops_the_breakpoint_table() {
        // `ret` with a null link register is how this stub models process exit,
        // so the target ends on its first instruction; the `nop` after it only
        // gives the breakpoint somewhere to live that is never executed.
        let prog = vec![0xD65F_03C0u32, 0xD503_201F];
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &prog);
        srv.refuse_software_breakpoints(); // self-patched, so `saved` is populated
        let dbg = AppleDebugger::new(Arc::new(LoopbackFactory::new(srv, 7)));
        dbg.attach(ProcessId(4242)).await.unwrap();

        dbg.set_breakpoint(Address::new(TEXT_BASE + 4), BreakpointKind::Software)
            .await
            .unwrap();
        assert_eq!(dbg.breakpoints().await.unwrap().len(), 1);

        let event = dbg.continue_execution().await.expect("continue to exit");
        assert!(
            event.reason.is_exit(),
            "expected the target to exit, got {:?}",
            event.reason
        );
        assert!(
            dbg.breakpoints().await.unwrap().is_empty(),
            "breakpoint records outlived the process they were patched into"
        );
    }

    /// Removing an already-DISABLED breakpoint must not touch the target.
    ///
    /// `disable_breakpoint` has already written the original word back, so the
    /// removal has nothing to undo. This backend wrote it again anyway, and the
    /// write is not harmless: against a target that has died or become
    /// unwritable it fails, so removing a breakpoint that needed no action at
    /// all reported an error — and, with a failed un-patch now correctly
    /// keeping the record (iter 285), that breakpoint could never be removed
    /// again either. The other three backends carry this rule explicitly:
    /// "a disabled breakpoint's byte is already back in place […] would fail
    /// needlessly on a dead process".
    #[tokio::test]
    async fn removing_a_disabled_breakpoint_does_not_touch_the_target() {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        srv.refuse_software_breakpoints(); // self-patched BRK path
        // Two writes are legitimate: the patch, then `disable`'s restore.
        // Everything after that must not be needed at all.
        srv.fail_memory_writes_after(2);
        let dbg = AppleDebugger::new(Arc::new(LoopbackFactory::new(srv, 7)));
        dbg.attach(ProcessId(4242)).await.unwrap();
        let addr = Address::new(TEXT_BASE + 0x10);

        dbg.set_breakpoint(addr, BreakpointKind::Software).await.unwrap();
        dbg.disable_breakpoint(addr).await.unwrap();

        dbg.remove_breakpoint(addr)
            .await
            .expect("removing a disabled breakpoint must not write to the target");
        assert!(
            dbg.breakpoints().await.unwrap().is_empty(),
            "the breakpoint should be gone once removed"
        );
    }

    /// A `remove_breakpoint` whose un-patch FAILS must leave the breakpoint
    /// tracked.
    ///
    /// The record used to be taken out of the map first and the target written
    /// afterwards, so a failed write returned with the bookkeeping already
    /// gone. What stays behind is a live `BRK #0` in the target's code that
    /// nothing knows about: `detach`'s restore sweep walks this same map, so it
    /// skips the abandoned patch, and on ARM64 a stray `BRK #0` raises SIGTRAP
    /// with no debugger attached — the process dies. The other three backends
    /// carry an explicit "look up, don't remove yet" comment for exactly this;
    /// this backend, the fifth `Debugger` impl, never got it.
    #[tokio::test]
    async fn a_failed_unpatch_keeps_the_breakpoint_tracked() {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        srv.refuse_software_breakpoints(); // force the self-patched BRK path
        // The patch itself must land; only the RESTORE is refused, which is
        // what a target that died between the two looks like.
        srv.fail_memory_writes_after(1);
        let dbg = AppleDebugger::new(Arc::new(LoopbackFactory::new(srv, 7)));
        dbg.attach(ProcessId(4242)).await.unwrap();
        let addr = Address::new(TEXT_BASE + 0x10);
        dbg.set_breakpoint(addr, BreakpointKind::Software).await.unwrap();
        assert_eq!(dbg.breakpoints().await.unwrap().len(), 1);

        let err = dbg.remove_breakpoint(addr).await;
        assert!(err.is_err(), "an un-patch that cannot write must not report success");
        assert_eq!(
            dbg.breakpoints().await.unwrap().len(),
            1,
            "the breakpoint was untracked while its BRK is still in the target"
        );
    }

    /// `kill` must work while the target is running — it is the emergency exit.
    ///
    /// Same opening as `detach` (`self.session.lock()`), same trap: the mutex
    /// belongs to the parked resume for the whole run, so "terminate" waited
    /// for the read timeout instead of terminating. Fourth member of the
    /// family; found by checking the candidate iteration 282 wrote down rather
    /// than by assuming it was the same.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn kill_does_not_block_behind_a_running_target() {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        srv.run_until_interrupt = true;
        let (addr, _server) = srv.spawn_tcp().expect("spawn tcp mock");
        let dbg = Arc::new(AppleDebugger::tcp(
            addr,
            Some(std::time::Duration::from_secs(30)),
        ));
        dbg.attach(ProcessId(4242)).await.expect("attach");

        let runner = Arc::clone(&dbg);
        let running = tokio::task::spawn(async move { runner.continue_execution().await });
        let mut waited = 0u32;
        while !*dbg.resume_in_flight.lock() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            waited += 1;
            assert!(waited < 2000, "the continue never became outstanding");
        }

        let killer = Arc::clone(&dbg);
        let killing = tokio::task::spawn(async move { killer.kill().await });
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), killing)
            .await
            .expect("kill must not wait for the target to stop on its own")
            .expect("kill task");
        outcome.expect("kill should succeed");

        assert!(!dbg.is_attached(), "the session must be gone after kill");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), running)
            .await
            .expect("the parked resume must be released, not stranded");
    }

    /// "Stop debugging" must work while the target is running.
    ///
    /// `detach` opened with `self.session.lock()`, the mutex a parked resume
    /// owns for the whole run, so it blocked until that read timed out — 30 s
    /// here, and unbounded on a transport configured without a read timeout,
    /// which is the realistic production setting. Third member of the family
    /// found in iters 280-281, and the one a user meets first: the button that
    /// is supposed to get you out is the one that hangs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn detach_does_not_block_behind_a_running_target() {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        srv.run_until_interrupt = true;
        let (addr, _server) = srv.spawn_tcp().expect("spawn tcp mock");
        let dbg = Arc::new(AppleDebugger::tcp(
            addr,
            Some(std::time::Duration::from_secs(30)),
        ));
        dbg.attach(ProcessId(4242)).await.expect("attach");

        let runner = Arc::clone(&dbg);
        let running = tokio::task::spawn(async move { runner.continue_execution().await });
        let mut waited = 0u32;
        while !*dbg.resume_in_flight.lock() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            waited += 1;
            assert!(waited < 2000, "the continue never became outstanding");
        }

        let closer = Arc::clone(&dbg);
        let detaching = tokio::task::spawn(async move { closer.detach().await });
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), detaching)
            .await
            .expect("detach must not wait for the target to stop on its own")
            .expect("detach task");
        outcome.expect("detach should succeed");

        assert!(!dbg.is_attached(), "the session must be gone after detach");
        // The runner is released too — either with the interrupt's stop reply
        // or with an error because the session went away under it. Both are
        // acceptable; hanging is not.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), running)
            .await
            .expect("the parked resume must be released, not stranded");
    }

    /// Status queries must keep answering while the target is running.
    ///
    /// `resume` holds the session mutex for the whole run, so every method that
    /// answered by locking it stopped answering the moment the target started:
    /// `is_attached`, `target_pid`, and — worst of the three — the `Debug` impl,
    /// which means a single `{:?}` in a log line blocked the logging thread
    /// until the run ended. Same class as the `pause` deadlock fixed one
    /// iteration earlier, and found by looking for the rest of its family.
    ///
    /// Bounded on a helper thread rather than awaited: before the fix these
    /// calls never return, and a test that hangs is worse than one that fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn status_queries_keep_answering_while_the_target_runs() {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        srv.run_until_interrupt = true;
        let (addr, _server) = srv.spawn_tcp().expect("spawn tcp mock");
        let dbg = Arc::new(AppleDebugger::tcp(
            addr,
            Some(std::time::Duration::from_secs(30)),
        ));
        dbg.attach(ProcessId(4242)).await.expect("attach");

        let runner = Arc::clone(&dbg);
        let running = tokio::task::spawn(async move { runner.continue_execution().await });
        let mut waited = 0u32;
        while !*dbg.resume_in_flight.lock() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            waited += 1;
            assert!(waited < 2000, "the continue never became outstanding");
        }

        // The runner now owns the session mutex. Ask the three status questions
        // from another thread and require an answer.
        let probe = Arc::clone(&dbg);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let answers = (
                probe.is_attached(),
                probe.target_pid(),
                format!("{probe:?}"),
            );
            let _ = tx.send(answers);
        });
        let (attached, pid, rendered) = rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("status queries must not block behind a running target");

        assert!(attached, "still attached while running");
        assert_eq!(pid, Some(ProcessId(4242)));
        assert!(
            rendered.contains("attached: true"),
            "Debug must render without taking the session mutex, got {rendered}"
        );

        // Let the runner finish so the mock thread can wind down.
        dbg.pause().await.expect("pause");
        let _ = running.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pause_interrupts_a_running_target_over_a_real_socket() {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        srv.run_until_interrupt = true;
        let (addr, server) = srv.spawn_tcp().expect("spawn tcp mock");

        // A read timeout only so a regression fails instead of hanging the
        // suite; the passing path never reaches it.
        let dbg = Arc::new(AppleDebugger::tcp(
            addr,
            Some(std::time::Duration::from_secs(30)),
        ));
        dbg.attach(ProcessId(4242)).await.expect("attach");
        assert!(
            dbg.interrupter.read().is_some(),
            "a TCP transport must expose an out-of-band write handle"
        );

        let runner = Arc::clone(&dbg);
        let running = tokio::task::spawn(async move { runner.continue_execution().await });

        // Wait until the resume is genuinely outstanding. Polling the same flag
        // `pause` consults is deliberate: it proves the interrupt is sent in
        // the running state rather than racing an already-stopped target.
        let mut waited = 0u32;
        while !*dbg.resume_in_flight.lock() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            waited += 1;
            assert!(waited < 2000, "the continue never became outstanding");
        }

        dbg.pause().await.expect("pause must be supported over TCP");

        let event = running
            .await
            .expect("runner task")
            .expect("the parked continue must return the interrupt's stop reply");
        match event.reason {
            StopReason::Signal { signum, .. } => assert_eq!(
                signum, 2,
                "expected SIGINT from the interrupt, got signal {signum} ({:?})",
                event.reason
            ),
            other => panic!("expected a SIGINT signal stop, got {other:?}"),
        }
        assert!(
            !*dbg.resume_in_flight.lock(),
            "the run flag must be cleared once the stop reply arrives"
        );

        // And a second `pause` with nothing running is a no-op success, not a
        // stray `\x03` whose stop reply would be misread as the next answer.
        dbg.pause().await.expect("pause on a stopped target is a no-op");
        let regs = dbg.get_registers(ThreadId(1)).await.expect("registers still in step");
        assert!(regs.pc >= TEXT_BASE, "pc {:#x} is not in the program", regs.pc);

        drop(dbg);
        let _ = server.join();
    }

    /// The out-of-band handle is dropped with the session.
    ///
    /// A stale handle names a closed socket, and `pause()` writing into it
    /// would report success for an interrupt nobody received.
    #[tokio::test]
    async fn detach_drops_the_out_of_band_handle() {
        let srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        let (addr, server) = srv.spawn_tcp().expect("spawn tcp mock");
        let dbg = AppleDebugger::tcp(addr, Some(std::time::Duration::from_secs(30)));
        dbg.attach(ProcessId(4242)).await.expect("attach");
        assert!(dbg.interrupter.read().is_some());
        dbg.detach().await.expect("detach");
        assert!(
            dbg.interrupter.read().is_none(),
            "the interrupt handle outlived its session"
        );
        assert!(matches!(dbg.pause().await, Err(DebugError::NotAttached)));
        // The client socket must close before the join: the server thread is
        // parked in `read()` and only the FIN releases it.
        drop(dbg);
        let _ = server.join();
    }

    #[tokio::test]
    async fn attach_discovers_registers_and_architecture() {
        let dbg = debugger();
        dbg.attach(ProcessId(4242)).await.unwrap();
        assert!(dbg.is_attached());
        assert_eq!(dbg.target_pid(), Some(ProcessId(4242)));
        assert_eq!(dbg.target_arch(), Some(TargetArch::Arm64e));
        let map = dbg.register_map().unwrap();
        // 31 x-regs + sp + pc + cpsr + 32 v-regs + fpsr + fpcr.
        assert_eq!(map.entries().len(), 68);
        assert_eq!(map.by_generic(GenericRole::Pc).unwrap().name, "pc");
        assert_eq!(map.by_name("x0").unwrap().regnum, 0);
    }

    #[tokio::test]
    async fn wrong_pid_is_process_not_found() {
        let dbg = debugger();
        assert!(matches!(
            dbg.attach(ProcessId(1)).await,
            Err(DebugError::ProcessNotFound(1))
        ));
    }

    #[tokio::test]
    async fn registers_round_trip_through_g_and_p() {
        let dbg = debugger();
        dbg.attach(ProcessId(4242)).await.unwrap();
        let tid = dbg.current_thread().await.unwrap();

        let regs = dbg.get_registers(tid).await.unwrap();
        assert_eq!(regs.pc, TEXT_BASE);
        assert!(regs.sp > 0);

        dbg.set_register(tid, "x5", 0xDEAD_BEEF_1234).await.unwrap();
        assert_eq!(dbg.get_register(tid, "x5").await.unwrap(), 0xDEAD_BEEF_1234);

        let mut whole = dbg.get_registers(tid).await.unwrap();
        whole.set("x6", 0x55AA);
        dbg.set_registers(tid, whole).await.unwrap();
        assert_eq!(dbg.get_register(tid, "x6").await.unwrap(), 0x55AA);
        // The read-modify-write must not have clobbered the other register.
        assert_eq!(dbg.get_register(tid, "x5").await.unwrap(), 0xDEAD_BEEF_1234);

        assert!(matches!(
            dbg.get_register(tid, "nonexistent").await,
            Err(DebugError::RegisterError(_))
        ));
    }

    #[tokio::test]
    async fn memory_round_trips_and_unmapped_reads_fail() {
        let dbg = debugger();
        dbg.attach(ProcessId(4242)).await.unwrap();
        let insn = dbg.read_memory(Address::new(TEXT_BASE), 4).await.unwrap();
        assert_eq!(u32::from_le_bytes(insn.try_into().unwrap()), program()[0]);

        // The stack is writable; prove a write is observable.
        let sp = dbg.get_registers(dbg.current_thread().await.unwrap()).await.unwrap().sp;
        let scratch = Address::new(sp - 64);
        assert_eq!(dbg.write_memory(scratch, &[1, 2, 3, 4]).await.unwrap(), 4);
        assert_eq!(dbg.read_memory(scratch, 4).await.unwrap(), vec![1, 2, 3, 4]);

        assert!(matches!(
            dbg.read_memory(Address::new(0xDEAD_0000), 4).await,
            Err(DebugError::MemoryError(0xDEAD_0000, _))
        ));
    }

    #[tokio::test]
    async fn breakpoint_lifecycle_is_enforced() {
        let dbg = debugger();
        dbg.attach(ProcessId(4242)).await.unwrap();
        let addr = Address::new(TEXT_BASE + 0x18);

        dbg.set_breakpoint(addr, BreakpointKind::Software).await.unwrap();
        assert!(matches!(
            dbg.set_breakpoint(addr, BreakpointKind::Software).await,
            Err(DebugError::BreakpointExists(_))
        ));
        assert_eq!(dbg.breakpoints().await.unwrap().len(), 1);

        dbg.disable_breakpoint(addr).await.unwrap();
        assert!(!dbg.breakpoints().await.unwrap()[0].enabled);
        dbg.enable_breakpoint(addr).await.unwrap();
        assert!(dbg.breakpoints().await.unwrap()[0].enabled);

        dbg.remove_breakpoint(addr).await.unwrap();
        assert!(dbg.breakpoints().await.unwrap().is_empty());
        assert!(matches!(
            dbg.remove_breakpoint(addr).await,
            Err(DebugError::BreakpointNotFound(_))
        ));

        // A misaligned A64 breakpoint is rejected, not silently rounded.
        assert!(matches!(
            dbg.set_breakpoint(Address::new(TEXT_BASE + 1), BreakpointKind::Software).await,
            Err(DebugError::Unsupported(_))
        ));
    }

    #[tokio::test]
    async fn hardware_breakpoints_use_z1() {
        let dbg = debugger();
        dbg.attach(ProcessId(4242)).await.unwrap();
        let addr = Address::new(TEXT_BASE + 0x18);
        dbg.set_breakpoint(addr, BreakpointKind::Hardware).await.unwrap();
        let bps = dbg.breakpoints().await.unwrap();
        assert_eq!(bps[0].kind, BreakpointKind::Hardware);
        dbg.remove_breakpoint(addr).await.unwrap();
    }

    #[tokio::test]
    async fn single_step_advances_one_instruction() {
        let dbg = debugger();
        dbg.attach(ProcessId(4242)).await.unwrap();
        let tid = dbg.current_thread().await.unwrap();
        let before = dbg.get_registers(tid).await.unwrap().pc;
        let event = dbg.single_step(tid).await.unwrap();
        assert!(matches!(event.reason, StopReason::SingleStep { .. }), "{:?}", event.reason);
        assert_eq!(dbg.get_registers(tid).await.unwrap().pc, before + 4);
    }

    #[tokio::test]
    async fn step_over_a_call_lands_after_it() {
        let dbg = debugger();
        dbg.attach(ProcessId(4242)).await.unwrap();
        let tid = dbg.current_thread().await.unwrap();
        // Park on the `bl`.
        dbg.set_register(tid, "pc", TEXT_BASE + 8).await.unwrap();
        dbg.step_over(tid).await.unwrap();
        assert_eq!(dbg.get_registers(tid).await.unwrap().pc, TEXT_BASE + 0xC);
        // The temporary return-site breakpoint must not survive.
        assert!(dbg.breakpoints().await.unwrap().is_empty());
    }

    /// A stub is allowed to answer `m` with fewer bytes than were asked for.
    /// `RspClient::read_memory` used to hand that shortfall back as if it were
    /// the whole read, and the software-breakpoint fallback then saved a SHORT
    /// original word before patching `BRK #0` — so the restore wrote back fewer
    /// bytes than it overwrote and left part of the `BRK` in the target's code.
    /// That is the iter-245 defect (an abandoned `BRK` raises SIGTRAP with no
    /// debugger left and kills the process) reached by a different road.
    ///
    /// With the shortfall reported, `set_breakpoint` fails BEFORE it writes,
    /// so the target is left untouched — which is what this asserts.
    #[tokio::test]
    async fn a_short_read_cannot_leave_a_half_restored_breakpoint() {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        srv.refuse_software_breakpoints(); // force the read-then-patch fallback
        srv.short_read_memory();
        let dbg = AppleDebugger::new(Arc::new(LoopbackFactory::new(srv, 7)));
        dbg.attach(ProcessId(4242)).await.unwrap();
        let addr = Address::new(TEXT_BASE + 0x10);

        let err = dbg
            .set_breakpoint(addr, BreakpointKind::Software)
            .await
            .expect_err("a short save must not be accepted as the original word");
        assert!(
            format!("{err}").contains("short read"),
            "wrong failure mode: {err}"
        );
        // Nothing was patched, so no breakpoint is recorded and the target's
        // code is still its own.
        assert!(dbg.breakpoints().await.unwrap().is_empty());
    }

    /// `step_over` asked only "is this address in my breakpoint map" before
    /// deciding not to plant its own return-site trap. A *disabled* record is
    /// in the map and has already had its `z0` sent, and a data watchpoint
    /// never traps on execution — so in both cases the guard suppressed the
    /// only thing that would stop the resume, `step_over` issued a free
    /// `vCont;c`, and returned whatever the process did next (here: running to
    /// exit) as if it were the step result.
    ///
    /// The mock's `packet_log` names the cause exactly: no `Z0` at the return
    /// site ever went out.
    #[tokio::test]
    async fn step_over_plants_a_trap_even_when_a_disabled_record_sits_at_the_return_site() {
        let srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        let (addr, server) = srv.spawn_tcp().expect("spawn tcp mock");
        let dbg = AppleDebugger::tcp(addr, Some(std::time::Duration::from_secs(30)));
        dbg.attach(ProcessId(4242)).await.expect("attach");
        let tid = dbg.current_thread().await.expect("current thread");

        let ret = Address::new(TEXT_BASE + 0xC);
        dbg.set_breakpoint(ret, BreakpointKind::Software).await.expect("set");
        dbg.disable_breakpoint(ret).await.expect("disable");

        // Park on the `bl` and step over it.
        dbg.set_register(tid, "pc", TEXT_BASE + 8).await.expect("park on the bl");
        let event = dbg.step_over(tid).await.expect("step_over");

        assert!(
            !matches!(event.reason, StopReason::ProcessExit { .. }),
            "step_over ran the target to completion instead of stepping: {:?}",
            event.reason
        );
        assert_eq!(
            dbg.get_registers(tid).await.expect("registers").pc,
            TEXT_BASE + 0xC,
            "step_over must land on the return site"
        );
        // The caller's own record is untouched: still there, still disabled.
        let bps = dbg.breakpoints().await.expect("breakpoints");
        assert_eq!(bps.len(), 1, "the temporary trap must not survive as a record");
        assert!(!bps[0].enabled, "the caller's breakpoint must stay disabled");

        drop(dbg);
        let srv = server.join().expect("stub thread");
        assert!(
            srv.packet_log.iter().any(|p| p.starts_with("Z0,10000400c")),
            "no return-site trap was ever planted; Z/z traffic was {:?}",
            srv.packet_log
                .iter()
                .filter(|p| p.starts_with('Z') || p.starts_with('z'))
                .collect::<Vec<_>>()
        );
    }

    /// The same guard, reached through a record that can never trap on
    /// execution at all: a data watchpoint at the return site.
    #[tokio::test]
    async fn step_over_plants_a_trap_even_when_a_watchpoint_sits_at_the_return_site() {
        let dbg = debugger();
        dbg.attach(ProcessId(4242)).await.expect("attach");
        let tid = dbg.current_thread().await.expect("current thread");
        // 4 bytes, so the address is aligned to the watched width.
        dbg.set_watchpoint_sized(Address::new(TEXT_BASE + 0xC), BreakpointKind::DataWrite, 4)
            .await
            .expect("watchpoint at the return site");

        dbg.set_register(tid, "pc", TEXT_BASE + 8).await.expect("park on the bl");
        let event = dbg.step_over(tid).await.expect("step_over");

        assert!(
            !matches!(event.reason, StopReason::ProcessExit { .. }),
            "step_over ran the target to completion instead of stepping: {:?}",
            event.reason
        );
        assert_eq!(
            dbg.get_registers(tid).await.expect("registers").pc,
            TEXT_BASE + 0xC,
            "step_over must land on the return site"
        );
    }

    /// The same step-over, against a stub with no server-managed software
    /// breakpoints — the case `set_breakpoint` has always handled by patching
    /// `BRK #0` itself.
    ///
    /// `step_over` planted its return-site breakpoint with a bare
    /// `client.insert_breakpoint`, which turns the empty `Z0` reply into
    /// `RspError::Framing` — so stepping over a call failed outright on stubs
    /// this backend otherwise fully supported. The gap was invisible because
    /// every other step_over test runs against the permissive mock.
    #[tokio::test]
    async fn step_over_falls_back_when_the_stub_refuses_z0() {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        srv.refuse_software_breakpoints();
        let dbg = AppleDebugger::new(Arc::new(LoopbackFactory::new(srv, 7)));
        dbg.attach(ProcessId(4242)).await.unwrap();
        let tid = dbg.current_thread().await.unwrap();
        dbg.set_register(tid, "pc", TEXT_BASE + 8).await.unwrap();

        dbg.step_over(tid).await.expect("step_over must fall back to a self-patched BRK");
        assert_eq!(dbg.get_registers(tid).await.unwrap().pc, TEXT_BASE + 0xC);
        assert!(
            dbg.breakpoints().await.unwrap().is_empty(),
            "the temporary return-site breakpoint must not survive"
        );
        // And the patch must be undone: the original word is back, so the
        // return site is executable code again rather than a stray `BRK #0`.
        let after = dbg.read_memory(Address::new(TEXT_BASE + 0xC), 4).await.unwrap();
        assert_ne!(
            after,
            arm64::brk_bytes(0).to_vec(),
            "unplant left the BRK in the target"
        );
    }

    #[tokio::test]
    async fn continue_stops_at_the_breakpoint_and_counts_the_hit() {
        let dbg = debugger();
        dbg.attach(ProcessId(4242)).await.unwrap();
        let target = Address::new(TEXT_BASE + 0x18);
        dbg.set_breakpoint(target, BreakpointKind::Software).await.unwrap();

        let event = dbg.continue_execution().await.unwrap();
        match &event.reason {
            StopReason::Breakpoint { address, bp } => {
                assert_eq!(*address, target);
                assert_eq!(bp.hit_count, 1);
            }
            other => panic!("expected a breakpoint stop, got {other:?}"),
        }
        let tid = dbg.current_thread().await.unwrap();
        assert_eq!(dbg.get_registers(tid).await.unwrap().pc, target.as_u64());
    }

    #[tokio::test]
    async fn modules_and_memory_maps_come_from_the_stub() {
        let dbg = debugger();
        dbg.attach(ProcessId(4242)).await.unwrap();

        let mods = dbg.modules().await.unwrap();
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0].name, "mock.dylib");
        assert_eq!(mods[0].base.as_u64(), TEXT_BASE);
        // Size is measured from the mapped region, never guessed.
        assert_eq!(mods[0].size, program().len() as u64 * 4);
        assert!(!mods[0].is_main, "the mock image is a dylib (filetype 6)");

        let maps = dbg.memory_maps().await.unwrap();
        let text = maps.iter().find(|m| m.base.as_u64() == TEXT_BASE).expect("__TEXT");
        assert!(text.executable && !text.writable);
        assert!(maps.iter().any(|m| m.writable && m.name.as_deref() == Some("Stack")));
    }

    #[tokio::test]
    async fn threads_are_enumerated() {
        let dbg = debugger();
        dbg.attach(ProcessId(4242)).await.unwrap();
        let threads = dbg.threads().await.unwrap();
        assert_eq!(threads, vec![ThreadId(1)]);
        assert_eq!(dbg.current_thread().await.unwrap(), ThreadId(1));
    }

    #[tokio::test]
    async fn backtrace_walks_the_frame_pointer_chain() {
        let dbg = debugger();
        dbg.attach(ProcessId(4242)).await.unwrap();
        let tid = dbg.current_thread().await.unwrap();
        // Stop inside the callee, past its prologue, so its own frame record
        // is on the stack.
        dbg.set_breakpoint(Address::new(TEXT_BASE + 0x20), BreakpointKind::Software)
            .await
            .unwrap();
        dbg.continue_execution().await.unwrap();

        let frames = dbg.backtrace(tid).await.unwrap();
        assert!(!frames.is_empty());
        assert_eq!(frames[0].index, 0);
        assert_eq!(frames[0].pc.as_u64(), TEXT_BASE + 0x20);
        // The caller's prologue saved x29/x30, so the chain reaches it.
        assert!(
            frames.len() >= 2,
            "expected the caller frame to be recovered, got {frames:?}"
        );
        assert_eq!(frames[1].pc.as_u64(), TEXT_BASE + 0xC);
    }

    /// Drive to a stop inside the callee so there is a real stack to walk.
    async fn stopped_in_callee(dbg: &AppleDebugger) -> ThreadId {
        dbg.attach(ProcessId(4242)).await.unwrap();
        let tid = dbg.current_thread().await.unwrap();
        dbg.set_breakpoint(Address::new(TEXT_BASE + 0x20), BreakpointKind::Software)
            .await
            .unwrap();
        dbg.continue_execution().await.unwrap();
        tid
    }

    /// A resolver that names nothing, used only to occupy the slot.
    #[derive(Debug)]
    struct InertResolver;
    impl FrameSymbolResolver for InertResolver {
        fn resolve_frame(&self, _pc: u64) -> Option<crate::symbol_resolver::ResolvedFrameSymbol> {
            None
        }
    }

    #[tokio::test]
    async fn first_backtrace_installs_a_resolver_from_the_target_once() {
        let dbg = debugger();
        let tid = stopped_in_callee(&dbg).await;
        assert_eq!(dbg.auto_load_attempts(), 0, "nothing should load before a backtrace is asked for");
        assert!(dbg.resolver.read().is_none());

        let frames = dbg.backtrace(tid).await.unwrap();
        assert!(!frames.is_empty());
        assert_eq!(
            dbg.auto_load_attempts(),
            1,
            "the first backtrace must build a resolver from the target"
        );
        assert!(
            dbg.resolver.read().is_some(),
            "resolver slot still empty after an automatic load"
        );

        // Reading every image is expensive: the second and third backtrace must
        // reuse what the first built.
        dbg.backtrace(tid).await.unwrap();
        dbg.backtrace(tid).await.unwrap();
        assert_eq!(
            dbg.auto_load_attempts(),
            1,
            "automatic load ran more than once (attempts={})",
            dbg.auto_load_attempts()
        );
    }

    #[tokio::test]
    async fn auto_load_can_be_switched_off() {
        let dbg = debugger().with_auto_load_symbols(false);
        assert!(!dbg.auto_load_symbols_enabled());
        let tid = stopped_in_callee(&dbg).await;
        let frames = dbg.backtrace(tid).await.unwrap();
        assert!(!frames.is_empty(), "disabling the load must not break the walk");
        assert_eq!(dbg.auto_load_attempts(), 0);
        assert!(
            dbg.resolver.read().is_none(),
            "a disabled auto-load installed a resolver anyway"
        );

        // Re-arming mid-session works, and then it loads on the next backtrace.
        dbg.set_auto_load_symbols(true);
        dbg.backtrace(tid).await.unwrap();
        assert_eq!(dbg.auto_load_attempts(), 1);
    }

    #[tokio::test]
    async fn a_caller_installed_resolver_is_never_replaced_or_dropped() {
        let dbg = debugger();
        let tid = stopped_in_callee(&dbg).await;
        let mine: Arc<dyn FrameSymbolResolver> = Arc::new(InertResolver);
        dbg.set_symbol_resolver(Arc::clone(&mine)).expect("this backend must accept a resolver");
        dbg.backtrace(tid).await.unwrap();
        assert_eq!(
            dbg.auto_load_attempts(),
            0,
            "the automatic load ran despite a resolver already being installed"
        );
        // And detaching leaves the caller's resolver where they put it, while
        // the auto-built one would have been dropped.
        dbg.detach().await.unwrap();
        assert!(dbg.resolver.read().is_some(), "caller's resolver was dropped on detach");
    }

    #[tokio::test]
    async fn detach_drops_the_auto_built_resolver_and_re_arms_the_latch() {
        let dbg = debugger();
        let tid = stopped_in_callee(&dbg).await;
        dbg.backtrace(tid).await.unwrap();
        assert_eq!(dbg.auto_load_attempts(), 1);
        dbg.detach().await.unwrap();
        assert!(
            dbg.resolver.read().is_none(),
            "a resolver describing the departed process survived detach"
        );
        assert_eq!(dbg.auto_load_attempts(), 0, "latch not re-armed for the next session");
    }

    #[tokio::test]
    async fn detach_clears_state_and_is_not_repeatable() {
        let dbg = debugger();
        dbg.attach(ProcessId(4242)).await.unwrap();
        dbg.set_breakpoint(Address::new(TEXT_BASE), BreakpointKind::Software).await.unwrap();
        dbg.detach().await.unwrap();
        assert!(!dbg.is_attached());
        assert!(dbg.breakpoints().await.unwrap().is_empty());
        assert!(matches!(dbg.detach().await, Err(DebugError::NotAttached)));
    }

    #[tokio::test]
    async fn launch_rejects_options_it_cannot_honour() {
        let dbg = debugger();
        let mut opts = LaunchOptions::new("/usr/bin/true");
        opts.follow_forks = true;
        assert!(matches!(dbg.launch(opts).await, Err(DebugError::Unsupported(_))));
        assert!(!dbg.is_attached(), "a rejected launch must not leave a session");
    }

    #[tokio::test]
    async fn launch_sends_argv_and_reports_the_pid() {
        let dbg = debugger();
        let opts = LaunchOptions::new("/usr/bin/true").with_args(vec!["-x".to_string()]);
        assert_eq!(dbg.launch(opts).await.unwrap(), ProcessId(4242));
        assert!(dbg.is_attached());
    }

    #[tokio::test]
    async fn backtrace_on_a_non_arm64_target_is_an_explicit_error() {
        // Force the recorded architecture to Intel and confirm the unwinder is
        // refused rather than run with an ARM64 model.
        let dbg = debugger();
        dbg.attach(ProcessId(4242)).await.unwrap();
        if let Some(s) = dbg.session.lock().as_mut() {
            s.arch = TargetArch::X86_64;
        }
        assert!(matches!(
            dbg.backtrace(ThreadId(1)).await,
            Err(DebugError::Unsupported(_))
        ));
        assert!(matches!(
            dbg.step_out(ThreadId(1)).await,
            Err(DebugError::Unsupported(_))
        ));
    }

    #[tokio::test]
    async fn register_map_decodes_the_g_block_by_discovered_offsets() {
        let dbg = debugger();
        dbg.attach(ProcessId(4242)).await.unwrap();
        let map = dbg.register_map().unwrap();
        // 31*8=248 (x0..x30) + 8 sp + 8 pc + 4 cpsr = 268, then 32*16=512 of
        // vector state, then fpsr and fpcr: 268 + 512 + 4 + 4 = 788.
        assert_eq!(map.g_packet_bytes(), 788);
        let mut block = vec![0u8; map.g_packet_bytes()];
        let mut set = RegisterSet::new();
        set.set("x3", 0x1122_3344);
        set.pc = 0xABCD;
        map.encode_into(&set, &mut block);
        let back = map.decode(&block);
        assert_eq!(back.get("x3"), Some(0x1122_3344));
        assert_eq!(back.pc, 0xABCD);
        // Vector registers are skipped, not truncated into the name space.
        assert!(back.get("v0").is_none());
    }

    // -- expression evaluation against the live session ----------------------

    /// Base at which the synthetic symbol-bearing image is mapped in the mock.
    const SYM_IMAGE_BASE: u64 = 0x2_0000_0000;
    /// Static `__TEXT` vmaddr of that image, so the slide is non-zero and a
    /// static address would be visibly wrong.
    const SYM_IMAGE_STATIC_BASE: u64 = 0x1000;
    /// Static address of the probe symbol inside it.
    const SYM_PROBE_STATIC: u64 = 0x1010;

    /// Build a minimal but valid arm64 Mach-O carrying one external symbol
    /// named `_expr_probe` at [`SYM_PROBE_STATIC`].
    fn symbol_image() -> Vec<u8> {
        const LC_SEGMENT_64: u32 = 0x19;
        const LC_SYMTAB: u32 = 0x02;
        const LC_DYSYMTAB: u32 = 0x0B;
        const LC_UUID: u32 = 0x1B;
        const N_SECT: u8 = 0x0E;
        const N_EXT: u8 = 0x01;

        fn seg_name(name: &str) -> [u8; 16] {
            let mut out = [0u8; 16];
            let b = name.as_bytes();
            out[..b.len()].copy_from_slice(b);
            out
        }

        let name = "_expr_probe";
        let mut strtab = vec![0u8];
        let strx = u32::try_from(strtab.len()).unwrap();
        strtab.extend_from_slice(name.as_bytes());
        strtab.push(0);

        let seg_cmdsize: u32 = 72 + 80;
        let sizeofcmds = seg_cmdsize + 24 + 80 + 24;
        let header_size: u32 = 32;
        let symoff = header_size + sizeofcmds;
        let nsyms = 1u32;
        let stroff = symoff + nsyms * 16;
        let strsize = u32::try_from(strtab.len()).unwrap();
        let text_size: u64 = 0x1000;

        let mut b = Vec::new();
        b.extend_from_slice(&0xFEED_FACFu32.to_le_bytes());
        b.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&6u32.to_le_bytes()); // MH_DYLIB
        b.extend_from_slice(&4u32.to_le_bytes()); // ncmds
        b.extend_from_slice(&sizeofcmds.to_le_bytes());
        b.extend_from_slice(&0x0020_0085u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());

        b.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        b.extend_from_slice(&seg_cmdsize.to_le_bytes());
        b.extend_from_slice(&seg_name("__TEXT"));
        b.extend_from_slice(&SYM_IMAGE_STATIC_BASE.to_le_bytes());
        b.extend_from_slice(&text_size.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&text_size.to_le_bytes());
        b.extend_from_slice(&7u32.to_le_bytes());
        b.extend_from_slice(&5u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&seg_name("__text"));
        b.extend_from_slice(&seg_name("__TEXT"));
        b.extend_from_slice(&SYM_IMAGE_STATIC_BASE.to_le_bytes());
        b.extend_from_slice(&text_size.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&4u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0x8000_0400u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());

        b.extend_from_slice(&LC_SYMTAB.to_le_bytes());
        b.extend_from_slice(&24u32.to_le_bytes());
        b.extend_from_slice(&symoff.to_le_bytes());
        b.extend_from_slice(&nsyms.to_le_bytes());
        b.extend_from_slice(&stroff.to_le_bytes());
        b.extend_from_slice(&strsize.to_le_bytes());

        b.extend_from_slice(&LC_DYSYMTAB.to_le_bytes());
        b.extend_from_slice(&80u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&nsyms.to_le_bytes());
        b.extend_from_slice(&nsyms.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        for _ in 0..12 {
            b.extend_from_slice(&0u32.to_le_bytes());
        }

        b.extend_from_slice(&LC_UUID.to_le_bytes());
        b.extend_from_slice(&24u32.to_le_bytes());
        b.extend_from_slice(&[0x33u8; 16]);

        assert_eq!(b.len(), symoff as usize);
        b.extend_from_slice(&strx.to_le_bytes());
        b.push(N_SECT | N_EXT);
        b.push(1);
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&SYM_PROBE_STATIC.to_le_bytes());
        assert_eq!(b.len(), stroff as usize);
        b.extend_from_slice(&strtab);
        b
    }

    /// The usual mock, plus a second image that actually carries a symbol
    /// table, mapped at a base whose slide is non-zero.
    fn debugger_with_symbols() -> AppleDebugger {
        use crate::ios::mock_debugserver::{LoadedImage, MemoryRegion, Perms};
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        let image = symbol_image();
        assert!(srv.memory.map(MemoryRegion::new(
            SYM_IMAGE_BASE,
            image,
            Perms { read: true, write: false, exec: true },
            "SymImage",
        )));
        srv.add_image(LoadedImage {
            path: "/usr/lib/libprobe.dylib".into(),
            load_address: SYM_IMAGE_BASE,
            slide: SYM_IMAGE_BASE - SYM_IMAGE_STATIC_BASE,
            uuid: [0x33; 16],
        });
        AppleDebugger::new(Arc::new(LoopbackFactory::new(srv, 7)))
    }

    /// The Apple expression evaluator is bound to the LIVE session: one
    /// expression mixing a register, a dereference and a symbol must take all
    /// three from the target, not from a stub or a default.
    ///
    /// This is what makes the binding falsifiable rather than decorative:
    /// * the register term changes when the register is written, so a
    ///   zero/default register file fails it;
    /// * the dereferenced word is one this test wrote into the target's stack,
    ///   so a snapshot or a zero-fill fails it;
    /// * the symbol resolves to the image's RUNTIME address, so dropping the
    ///   ASLR slide fails it by exactly the slide.
    #[tokio::test]
    async fn evaluate_mixes_register_memory_and_symbol_from_the_live_target() {
        let dbg = debugger_with_symbols();
        dbg.attach(ProcessId(4242)).await.unwrap();
        let tid = dbg.current_thread().await.unwrap();

        let sp = dbg.get_registers(tid).await.unwrap().sp;
        let scratch = sp - 64;
        let word: u64 = 0x1122_3344_5566_7788;
        dbg.write_memory(Address::new(scratch), &word.to_le_bytes()).await.unwrap();
        dbg.set_register(tid, "x3", 64).await.unwrap();

        let probe_runtime = SYM_IMAGE_BASE + (SYM_PROBE_STATIC - SYM_IMAGE_STATIC_BASE);

        let value = dbg
            .evaluate(tid, "*(uint64_t*)($sp - $x3) + expr_probe")
            .await
            .expect("evaluation against the live session");
        assert_eq!(
            value.value,
            word.wrapping_add(probe_runtime),
            "expected the target's stack word plus the symbol's RUNTIME address"
        );

        // The register really is read per call: move x3 and the same
        // expression must read a different word.
        let other: u64 = 0xAAAA_BBBB_CCCC_DDDD;
        dbg.write_memory(Address::new(sp - 128), &other.to_le_bytes()).await.unwrap();
        dbg.set_register(tid, "x3", 128).await.unwrap();
        let value2 = dbg.evaluate(tid, "*(uint64_t*)($sp - $x3) + expr_probe").await.unwrap();
        assert_eq!(value2.value, other.wrapping_add(probe_runtime));

        // The underscored Mach-O spelling resolves to the same address.
        let raw = dbg.evaluate(tid, "_expr_probe").await.unwrap();
        assert_eq!(raw.value, probe_runtime);
    }

    /// A dereference of an unmapped address is an ERROR, never a plausible
    /// zero. The address is preserved so the caller can say which read failed.
    #[tokio::test]
    async fn evaluate_reports_an_unmapped_dereference_instead_of_zero() {
        let dbg = debugger_with_symbols();
        dbg.attach(ProcessId(4242)).await.unwrap();
        let tid = dbg.current_thread().await.unwrap();

        let err = dbg
            .evaluate(tid, "*(uint64_t*)0xDEAD0000")
            .await
            .expect_err("an unmapped read must not evaluate to 0");
        match err {
            DebugError::MemoryError(addr, _) => assert_eq!(addr, 0xDEAD_0000),
            other => panic!("expected a memory error naming the address, got {other:?}"),
        }

        // And an unknown name is refused rather than resolved to address 0.
        assert!(
            dbg.evaluate(tid, "no_such_symbol_here").await.is_err(),
            "an unknown symbol must not evaluate to 0"
        );
    }

    /// Evaluation needs a session: with none, it says so.
    #[tokio::test]
    async fn evaluate_without_a_session_is_not_attached() {
        let dbg = debugger_with_symbols();
        assert!(matches!(dbg.evaluate(ThreadId(0), "1 + 1").await, Err(DebugError::NotAttached)));
    }

    // -- a transport that can refuse to WRITE -------------------------------
    //
    // The mock debugserver can refuse to ANSWER (`E09`), but a whole class of
    // defect lives one layer lower: a write that never reaches the wire whose
    // `io::Result` is discarded. Nothing in this crate could express that, so
    // the tests below wrap the loopback transport in one that fails `send` for
    // the packets a test names. The debugger under test is untouched — only the
    // socket lies, which is exactly the failure a real half-closed connection
    // produces.

    type PacketPredicate = Arc<dyn Fn(&str) -> bool + Send + Sync>;

    struct CensoringTransport {
        inner: Box<dyn RspTransport>,
        refuse: PacketPredicate,
    }

    impl RspTransport for CensoringTransport {
        fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
            let text = String::from_utf8_lossy(data).into_owned();
            if (self.refuse)(&text) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    format!("transport refused to write {text:?}"),
                ));
            }
            self.inner.send(data)
        }
        fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.recv(buf)
        }
        fn description(&self) -> String {
            self.inner.description()
        }
        fn interrupter(&self) -> Option<Arc<dyn crate::ios::rsp::RspInterrupter>> {
            self.inner.interrupter()
        }
    }

    struct CensoringFactory {
        inner: LoopbackFactory,
        refuse: PacketPredicate,
    }

    impl TransportFactory for CensoringFactory {
        fn connect(
            &self,
            request: &ConnectRequest<'_>,
        ) -> Result<Box<dyn RspTransport>, DebugError> {
            Ok(Box::new(CensoringTransport {
                inner: self.inner.connect(request)?,
                refuse: Arc::clone(&self.refuse),
            }))
        }
        fn description(&self) -> String {
            "censoring-loopback".to_string()
        }
    }

    fn censoring_debugger(refuse: PacketPredicate) -> AppleDebugger {
        let srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        AppleDebugger::new(Arc::new(CensoringFactory {
            inner: LoopbackFactory::new(srv, 7),
            refuse,
        }))
    }

    /// `kill` must report a kill that never reached the target.
    ///
    /// `vKill` is answered and its reply is checked; the bare `k` fallback is
    /// not answered — the stub dies mid-reply — and that silence is genuinely
    /// expected. What is NOT expected, and what the comment above it does not
    /// justify, is discarding the `io::Result` of the WRITE: `let _ =
    /// transport.send(...)` followed by `killed = true` says the target was
    /// terminated on the strength of a byte that never left the process. The
    /// caller then tears down its own state, stops watching, and leaves a live
    /// target behind. The same class was fixed four times elsewhere in this
    /// crate; the emergency exit kept it.
    ///
    /// Both packets are refused here because both are the kill: if `vKill`
    /// could still be written the target would really die and the fallback
    /// would never run.
    #[tokio::test]
    async fn kill_reports_failure_when_the_kill_packet_never_reaches_the_target() {
        let dbg = censoring_debugger(Arc::new(|pkt: &str| {
            pkt.contains("vKill") || pkt.contains("$k#")
        }));
        dbg.attach(ProcessId(4242)).await.expect("attach");

        let outcome = dbg.kill().await;
        assert!(
            outcome.is_err(),
            "kill reported success although neither `vKill` nor `k` could be written: \
             the caller now believes a live target is dead"
        );
    }

    /// A stop whose program counter cannot be read must not be classified from
    /// a fabricated `pc = 0`.
    ///
    /// `classify` reads the PC back deliberately — its own comment says the
    /// expedited register list is stub-dependent and "a breakpoint
    /// misattributed to the wrong address is worse than one extra round trip".
    /// The `unwrap_or(0)` under that comment does exactly what it forbids: when
    /// the read fails the stop is attributed to address 0, so a stop AT a
    /// registered breakpoint comes back as a bare signal, its hit is not
    /// counted, and the caller is handed a program counter the target never had.
    ///
    /// The `g` block is refused only from the resume onward, so attaching and
    /// planting the breakpoint work normally and the failure lands exactly on
    /// the classification round trip this test is about.
    #[tokio::test]
    async fn a_stop_is_not_classified_from_a_fabricated_program_counter() {
        let fail_g = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&fail_g);
        let dbg = censoring_debugger(Arc::new(move |pkt: &str| {
            flag.load(Ordering::SeqCst) && pkt.contains("$g#")
        }));
        dbg.attach(ProcessId(4242)).await.expect("attach");
        let target = Address::new(TEXT_BASE + 0x18);
        dbg.set_breakpoint(target, BreakpointKind::Software).await.expect("breakpoint");

        fail_g.store(true, Ordering::SeqCst);
        match dbg.continue_execution().await {
            // Honest: the PC could not be read, so the stop was not classified.
            Err(_) => {}
            // Also honest: the address was recovered from the stop reply itself.
            Ok(ev) => match ev.reason {
                StopReason::Breakpoint { address, .. } if address == target => {}
                other => panic!(
                    "the program counter could not be read, yet the stop was reported as \
                     {other:?} — classified from a fabricated pc instead of failing or \
                     recovering the real address {target:?}"
                ),
            },
        }
    }
}
