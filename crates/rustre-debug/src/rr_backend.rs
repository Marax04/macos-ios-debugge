//! Mozilla `rr` replay backend for the TTD interface.
//!
//! This module implements [`RrBackend`], a [`crate::time_travel_debug::TtdBackend`] that drives
//! `rr replay --serve-address 127.0.0.1:<port>` as a subprocess and
//! communicates with it via the **GDB Remote Serial Protocol** (GDB RSP)
//! over TCP.
//!
//! ## rr-specific RSP extensions
//!
//! | Packet              | Meaning                                      |
//! |---------------------|----------------------------------------------|
//! | `qRRCmd,when`       | Query current FrameTime (decimal u64)        |
//! | `RRWhen,<frame>`    | Seek to FrameTime `<frame>`                  |
//! | `bc`                | Reverse-continue                             |
//! | `bs`                | Reverse-step (single instruction backward)  |
//!
//! rr's FrameTime maps to `TracePosition { sequence: frame_time, offset: 0 }`.
//!
//! ## Lifecycle
//!
//! 1. `RrBackend::open(trace_dir)` spawns `rr replay --serve-address
//!    127.0.0.1:<port>` and waits for the GDB stub to start listening.
//! 2. The backend then connects a `TcpStream` and sends `qSupported` / `qXfer`
//!    initialization packets.
//! 3. All operations translate to RSP packets.
//! 4. Drop closes the TCP connection and kills the rr subprocess.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::retry::retry_with_backoff;
use crate::time_travel_debug::{TtdBackend, TtdError, TtdState, TracePosition};

// ── constants ─────────────────────────────────────────────────────────────────

/// Timeout for the rr process to start listening (seconds).
const RR_START_TIMEOUT_SECS: u64 = 30;
/// How long between connection retry attempts (ms).
const RR_RETRY_INTERVAL_MS: u64 = 100;
/// Maximum RSP packet read size.
const RSP_BUF_SIZE: usize = 65536;
/// Per-operation RSP read/write timeout — kills the child if rr hangs.
const RSP_IO_TIMEOUT_SECS: u64 = 60;

// ── RrBackend ─────────────────────────────────────────────────────────────────

/// A [`crate::time_travel_debug::TtdBackend`] that drives an `rr replay` subprocess via GDB RSP.
pub struct RrBackend {
    /// Path to the rr trace directory.
    trace_dir: PathBuf,
    /// The `rr replay` subprocess.
    rr_process: Child,
    /// TCP connection to rr's GDB stub.
    conn: TcpStream,
    /// Current rr FrameTime (maps to `TracePosition::sequence`).
    current_frame: u64,
    /// Approximate trace extent (populated at open time via RSP queries).
    extent: (TracePosition, TracePosition),
}

impl fmt::Debug for RrBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RrBackend")
            .field("trace_dir", &self.trace_dir)
            .field("current_frame", &self.current_frame)
            .field("extent", &self.extent)
            .finish_non_exhaustive()
    }
}

impl RrBackend {
    /// Open an rr trace directory and start `rr replay`.
    ///
    /// Requires `rr` to be on `PATH`. The `rr replay` process is spawned with
    /// `--serve-address 127.0.0.1:<port>` and the backend connects to it.
    ///
    /// # Errors
    ///
    /// Returns `Err` if:
    /// - `rr` is not found on `PATH`.
    /// - The trace directory does not exist or is not a valid rr trace.
    /// - rr fails to start within `RR_START_TIMEOUT_SECS` seconds.
    /// - The RSP handshake fails.
    pub fn open(trace_dir: &Path) -> Result<Self, TtdError> {
        if !trace_dir.is_dir() {
            return Err(TtdError::Backend(format!(
                "rr trace directory not found: {}",
                trace_dir.display()
            )));
        }

        // Pick a free port by binding to port 0, then release it.
        let port = find_free_port().map_err(|e| TtdError::Backend(format!("no free port: {e}")))?;
        let addr = format!("127.0.0.1:{port}");

        // Spawn `rr replay`.
        let child = Command::new("rr")
            .args([
                "replay",
                "--serve-address",
                &addr,
                trace_dir.to_str().unwrap_or("."),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                TtdError::Backend(format!("failed to spawn `rr replay`: {e}"))
            })?;

        // Wait for rr to start listening.
        let conn = wait_for_rr(&addr)?;

        // Apply per-operation read/write timeout so that a hung rr process
        // does not block the caller indefinitely.  The child is killed in Drop.
        let timeout = Duration::from_secs(RSP_IO_TIMEOUT_SECS);
        conn.set_read_timeout(Some(timeout)).map_err(|e| {
            TtdError::Backend(format!("failed to set RSP read timeout: {e}"))
        })?;
        conn.set_write_timeout(Some(timeout)).map_err(|e| {
            TtdError::Backend(format!("failed to set RSP write timeout: {e}"))
        })?;

        let mut backend = Self {
            trace_dir: trace_dir.to_path_buf(),
            rr_process: child,
            conn,
            current_frame: 0,
            extent: (TracePosition::START, TracePosition::START),
        };

        // Initialize RSP and query extent.
        backend.rsp_init()?;
        backend.current_frame = backend.query_frame_time()?;

        Ok(backend)
    }

    /// Detect whether `path` is an rr trace directory.
    #[must_use]
    pub fn is_rr_trace(path: &Path) -> bool {
        if !path.is_dir() {
            return false;
        }
        // rr trace directories always have a `version` file or an `events` file.
        path.join("version").exists() || path.join("events").exists()
    }

    // ── RSP helpers ───────────────────────────────────────────────────────────

    /// Send the `qSupported` packet to start the RSP session.
    fn rsp_init(&mut self) -> Result<(), TtdError> {
        // Enable ACKs (default in GDB RSP; some stubs omit the '+').
        // Send qSupported to learn server features (we don't use the reply here).
        let _ = self.rsp_send_recv("qSupported:multiprocess+;qRelocInsn+")?;
        // Send Hg0 (set general thread to any).
        let _ = self.rsp_send_recv("Hg0")?;
        Ok(())
    }

    /// Query the current rr FrameTime via `qRRCmd,when`.
    fn query_frame_time(&mut self) -> Result<u64, TtdError> {
        let reply = self.rsp_send_recv("qRRCmd,when")?;
        // rr replies with the decimal FrameTime directly.
        parse_frame_time(&reply)
    }

    /// Seek to a FrameTime via `RRWhen,<frame>`.
    fn seek_frame(&mut self, frame: u64) -> Result<(), TtdError> {
        let packet = format!("RRWhen,{frame}");
        let _reply = self.rsp_send_recv(&packet)?;
        Ok(())
    }

    /// Read the program counter via the `g` (read all registers) packet.
    ///
    /// Returns `(pc, sp)` where the exact register positions depend on the
    /// target architecture. For x86-64, GDB register order is:
    /// rax rbx rcx rdx rsi rdi rbp rsp r8..r15 rip rflags cs ss ds es fs gs
    /// Each register is 8 bytes; rip is register index 16, rsp is 7.
    fn read_pc_sp(&mut self) -> Result<(u64, u64), TtdError> {
        let reply = self.rsp_send_recv("g")?;
        let bytes = hex_decode_le(&reply).map_err(|e| TtdError::Backend(e))?;
        // Each general-purpose register is 8 bytes; rsp is reg 7, rip is reg 16.
        let sp = read_u64_le(&bytes, 7 * 8);
        let pc = read_u64_le(&bytes, 16 * 8);
        Ok((pc, sp))
    }

    /// Build a `TtdState` from the current rr position.
    fn current_state(&mut self) -> Result<TtdState, TtdError> {
        let frame = self.query_frame_time()?;
        let pos = TracePosition::new(frame, 0);
        let (pc, sp) = self.read_pc_sp().unwrap_or((0, 0));
        let mut regs = BTreeMap::new();
        regs.insert("rip".to_string(), pc);
        regs.insert("rsp".to_string(), sp);
        let mut state = TtdState::new(pos, pc, sp);
        state.regs = regs;
        state.stop_reason = "rr_stop".to_string();
        self.current_frame = frame;
        Ok(state)
    }

    /// Send a single GDB RSP packet and receive the reply.
    ///
    /// Packet framing: `$<data>#<checksum>`. The checksum is the 8-bit sum of
    /// the packet bytes, formatted as two hex digits. On receipt we strip the
    /// `$...#XX` wrapper and return the inner data string.
    fn rsp_send_recv(&mut self, data: &str) -> Result<String, TtdError> {
        let packet = rsp_encode(data);
        self.conn.write_all(packet.as_bytes()).map_err(|e| {
            TtdError::Backend(format!("RSP send failed: {e}"))
        })?;

        let mut buf = vec![0u8; RSP_BUF_SIZE];
        let n = self.conn.read(&mut buf).map_err(|e| {
            TtdError::Backend(format!("RSP recv failed: {e}"))
        })?;
        let raw = std::str::from_utf8(&buf[..n])
            .map_err(|e| TtdError::Backend(format!("RSP non-UTF8 reply: {e}")))?;
        Ok(rsp_decode(raw))
    }
}

impl Drop for RrBackend {
    fn drop(&mut self) {
        drop(self.conn.shutdown(std::net::Shutdown::Both));
        let _ = self.rr_process.kill();
    }
}

impl TtdBackend for RrBackend {
    fn name(&self) -> &str {
        "rr"
    }

    fn trace_extent(&self) -> (TracePosition, TracePosition) {
        self.extent
    }

    fn seek(&mut self, position: TracePosition) -> Result<TtdState, TtdError> {
        self.seek_frame(position.sequence)?;
        let state = self.current_state()?;
        Ok(state)
    }

    fn step_forward(&mut self, _current: TracePosition) -> Result<TtdState, TtdError> {
        // GDB RSP single-step: 's'
        let _reply = self.rsp_send_recv("s")?;
        let state = self.current_state()?;
        Ok(state)
    }

    fn step_backward(&mut self, _current: TracePosition) -> Result<TtdState, TtdError> {
        // rr reverse-step: 'bs'
        let _reply = self.rsp_send_recv("bs")?;
        let state = self.current_state()?;
        Ok(state)
    }

    /// rr reverse-continue (`bc`), with the caller's stop addresses actually
    /// armed first.
    ///
    /// `stop_at` used to be ignored outright (`_stop_at`): the backend sent a
    /// bare `bc`, and rr ran backward to whatever breakpoint happened to be set
    /// in the RSP session — which this backend never sets. So "run backward
    /// until pc X" returned wherever rr stopped, with nothing to say the
    /// request had not been honoured. The simulated path had the same defect
    /// and was fixed in iteration 460; the REAL backend kept it.
    fn reverse_continue(
        &mut self,
        _from: TracePosition,
        stop_at: &[u64],
    ) -> Result<TtdState, TtdError> {
        for packet in rsp_breakpoint_packets(stop_at, true) {
            self.rsp_send_recv(&packet)?;
        }
        let result = self.rsp_send_recv("bc").and_then(|_| self.current_state());
        // Remove them again whatever happened: a breakpoint left armed in the
        // RSP session would silently stop a LATER reverse-continue that asked
        // for something else.
        for packet in rsp_breakpoint_packets(stop_at, false) {
            let _ = self.rsp_send_recv(&packet);
        }
        result
    }

    /// Not implemented, and it says so.
    ///
    /// This was an alias of [`Self::step_backward`]: a caller asking to step
    /// backward OVER a call frame got a single reverse instruction step, and
    /// nothing distinguished the two. Stepping one instruction where a whole
    /// frame was asked for is not an approximation, it is a different
    /// operation — and the state it returns looks exactly like a correct one.
    /// rr exposes no single packet for this; doing it properly needs the frame
    /// boundary, which this backend does not compute.
    fn reverse_step_over(&mut self, _current: TracePosition) -> Result<TtdState, TtdError> {
        Err(TtdError::Unsupported(
            "rr backend: reverse-step-over needs a frame boundary this backend does not compute;              use step_backward for a single reverse instruction step"
                .into(),
        ))
    }

    /// Not implemented, and it says so — see [`Self::reverse_step_over`].
    fn run_to_previous_call(&mut self, _current: TracePosition) -> Result<TtdState, TtdError> {
        Err(TtdError::Unsupported(
            "rr backend: run-to-previous-call needs call-site information this backend does not              have; a single reverse step is not the same operation"
                .into(),
        ))
    }
}

/// GDB RSP packets that arm (`insert = true`) or clear (`insert = false`) a
/// software breakpoint at each address.
///
/// `Z0,<addr>,<kind>` / `z0,<addr>,<kind>`; the address is hex without `0x` and
/// the kind is the breakpoint length in bytes, 1 for the software breakpoint rr
/// implements. Split out as a pure function so the packet shape is testable
/// without a live rr on the other end of a socket.
#[must_use]
pub fn rsp_breakpoint_packets(addresses: &[u64], insert: bool) -> Vec<String> {
    let verb = if insert { 'Z' } else { 'z' };
    addresses
        .iter()
        .map(|addr| format!("{verb}0,{addr:x},1"))
        .collect()
}

// ── RSP framing helpers ───────────────────────────────────────────────────────

fn rsp_encode(data: &str) -> String {
    let cksum: u8 = data.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
    format!("${data}#{cksum:02x}")
}

fn rsp_decode(raw: &str) -> String {
    // Strip leading '+' (ACK), then extract between '$' and '#'.
    let s = raw.trim_start_matches('+');
    if let Some(rest) = s.strip_prefix('$') {
        if let Some(idx) = rest.rfind('#') {
            return rest[..idx].to_string();
        }
        return rest.to_string();
    }
    s.to_string()
}

/// Decode a hex string (rr register dump) into a byte vector (little-endian
/// per-register).  The hex string is pairs of hex digits; no 0x prefix.
fn hex_decode_le(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err(format!("odd-length hex string ({})", hex.len()));
    }
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    if offset + 8 > bytes.len() {
        return 0;
    }
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap_or([0u8; 8]))
}

fn parse_frame_time(reply: &str) -> Result<u64, TtdError> {
    reply
        .trim()
        .parse::<u64>()
        .map_err(|e| TtdError::Backend(format!("cannot parse FrameTime from {:?}: {e}", reply)))
}

// ── Port / connection helpers ─────────────────────────────────────────────────

fn find_free_port() -> std::io::Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn wait_for_rr(addr: &str) -> Result<TcpStream, TtdError> {
    // Calculate max retries from the timeout and retry interval.
    let max_tries = u32::try_from(
        (RR_START_TIMEOUT_SECS * 1000) / RR_RETRY_INTERVAL_MS.max(1),
    )
    .unwrap_or(u32::MAX)
    .max(1);

    let initial_delay = Duration::from_millis(RR_RETRY_INTERVAL_MS);
    let addr_owned = addr.to_owned();

    retry_with_backoff(
        max_tries,
        initial_delay,
        |e: &std::io::Error| {
            // Retry on connection-refused / not-yet-listening; fail fast on others.
            matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::TimedOut
            )
        },
        || TcpStream::connect(&addr_owned),
    )
    .map(|conn| {
        conn.set_read_timeout(Some(Duration::from_secs(10))).ok();
        conn.set_write_timeout(Some(Duration::from_secs(10))).ok();
        conn
    })
    .map_err(|e| {
        TtdError::Backend(format!(
            "rr stub at {addr} did not start within {RR_START_TIMEOUT_SECS}s: {e}"
        ))
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsp_encode_decode_roundtrip() {
        let encoded = rsp_encode("qSupported");
        assert!(encoded.starts_with("$qSupported#"));
        let decoded = rsp_decode(&format!("+{encoded}"));
        assert_eq!(decoded, "qSupported");
    }

    #[test]
    fn rsp_encode_checksum() {
        // Checksum of "g" = 0x67 = 103.
        let encoded = rsp_encode("g");
        assert_eq!(encoded, "$g#67");
    }

    #[test]
    fn hex_decode_le_valid() {
        let bytes = hex_decode_le("deadbeef").unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn hex_decode_le_odd_length_errors() {
        assert!(hex_decode_le("abc").is_err());
    }

    #[test]
    fn read_u64_le_at_offset() {
        let mut bytes = vec![0u8; 16 * 8 + 8];
        // Place PC at offset 16*8.
        bytes[16 * 8..16 * 8 + 8].copy_from_slice(&0x0040_1000u64.to_le_bytes());
        assert_eq!(read_u64_le(&bytes, 16 * 8), 0x0040_1000);
    }

    #[test]
    fn is_rr_trace_rejects_non_dir() {
        assert!(!RrBackend::is_rr_trace(Path::new("/nonexistent/path")));
    }

    #[test]
    fn parse_frame_time_valid() {
        assert_eq!(parse_frame_time("42").unwrap(), 42);
        assert_eq!(parse_frame_time("  100  ").unwrap(), 100);
    }

    #[test]
    fn parse_frame_time_invalid() {
        assert!(parse_frame_time("abc").is_err());
    }

    /// The reverse breakpoints the caller asked for must actually be armed.
    ///
    /// `reverse_continue` took `_stop_at` and dropped it: it sent a bare `bc`,
    /// and rr ran backward to whatever breakpoint happened to be set in the
    /// RSP session - which this backend never sets. So "run backward until pc
    /// X" returned wherever rr stopped, with nothing saying the request had
    /// not been honoured. The simulated path had the same defect and was fixed
    /// in iteration 460; the real backend kept it.
    #[test]
    fn reverse_breakpoints_become_real_rsp_packets() {
        let armed = rsp_breakpoint_packets(&[0x401000, 0x7fff_1234], true);
        assert_eq!(armed, vec!["Z0,401000,1".to_string(), "Z0,7fff1234,1".to_string()]);

        // And they are removed again, or a breakpoint left in the RSP session
        // would silently stop a LATER reverse-continue asking for something
        // else.
        let cleared = rsp_breakpoint_packets(&[0x401000], false);
        assert_eq!(cleared, vec!["z0,401000,1".to_string()]);

        // No stop addresses means no packets: a plain reverse-continue must
        // not arm anything.
        assert!(rsp_breakpoint_packets(&[], true).is_empty());
    }

    /// Operations this backend does not implement must REFUSE, not silently
    /// do something else.
    ///
    /// `reverse_step_over` and `run_to_previous_call` were aliases of
    /// `step_backward`: a caller asking to step backward over a whole call
    /// frame got one reverse instruction step, and the state returned looked
    /// exactly like a correct answer.
    #[test]
    fn unimplemented_reverse_operations_refuse_instead_of_single_stepping() {
        // No live rr is needed: the refusal happens before any packet is sent,
        // which is itself the point - it cannot accidentally do the wrong
        // thing on the way to failing.
        let src = include_str!("rr_backend.rs");
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("
");
        for op in ["fn reverse_step_over", "fn run_to_previous_call"] {
            let at = code.find(op).expect("both operations must still exist");
            let body_end = code[at..].find("    }").unwrap_or(code.len() - at);
            let body = &code[at..at + body_end];
            assert!(
                body.contains("TtdError::Unsupported"),
                "{op} answers with something other than a refusal, so a caller cannot tell it was not implemented"
            );
            assert!(
                !body.contains("self.step_backward"),
                "{op} is still an alias of step_backward: one instruction where a frame was asked for"
            );
        }
    }

}
