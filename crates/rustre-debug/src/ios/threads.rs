//! Multi-thread enumeration and per-thread stack recovery for an Apple target.
//!
//! `debugserver` exposes four packets that together describe every thread of a
//! stopped process, and this module is the only place in the crate that knows
//! how to combine them:
//!
//! | packet | what it gives |
//! |---|---|
//! | `jThreadsInfo` | JSON: every thread, its stop reason *and* a register snapshot, in one round trip |
//! | `H` (`Hg`/`Hc`) | selects the thread subsequent register/resume packets act on |
//! | `qThreadStopInfo<tid>` | the `T` stop reply of one specific thread |
//! | `qThreadExtraInfo,<tid>` | hex-encoded human-readable thread name/description |
//!
//! `jThreadsInfo` is preferred because it is atomic: enumerating threads with
//! `qfThreadInfo` and then asking each one for its stop reason is N+1 round
//! trips over a state that is only guaranteed consistent while the process is
//! stopped. But it is an lldb extension, so a stub that does not implement it
//! answers with an empty packet; the fallback path here reconstructs the same
//! [`ThreadDescription`] list from `qfThreadInfo` + `qThreadStopInfo` +
//! `qThreadExtraInfo`, and records which route was taken in
//! [`ThreadDescription::source`] so a caller is never left guessing whether a
//! missing field means "the thread has no queue" or "this stub cannot say".
//!
//! Nothing here is gated on the host OS: every function is either pure parsing
//! or a packet exchange over [`crate::ios::rsp::RspTransport`], so the whole module
//! is exercised against [`crate::ios::mock_debugserver`] on Windows.
//!
//! # Trust
//! Every field arrives from a process being debugged and is therefore hostile
//! input. Thread ids are parsed with checked radix conversion, register
//! payloads through [`crate::ios::lldb_ext::ThreadInfo::register_u64`] (which
//! refuses to truncate a vector register), and `qThreadExtraInfo` hex through a
//! decoder that rejects odd lengths and non-hex digits. There is no `unwrap`
//! on target data in this file.

use std::fmt;

use crate::{DebugError, StackFrame, ThreadId};

use crate::ios::apple_debugger::{AppleDebugger, RegisterMap, Session, rsp_err};
use crate::ios::lldb_ext::{self, GenericRole, ThreadInfo};
use crate::ios::rsp::StopReply;

// ---------------------------------------------------------------------------
// Packet builders
// ---------------------------------------------------------------------------

/// Command text for the one-shot JSON thread dump.
pub const JTHREADS_INFO: &str = "jThreadsInfo";

/// Build `qThreadStopInfo<tid>` (tid in hex, no separator — this packet is the
/// odd one out; `qThreadExtraInfo` uses a comma).
#[must_use]
pub fn thread_stop_info_command(tid: u64) -> String {
    format!("qThreadStopInfo{tid:x}")
}

/// Build `qThreadExtraInfo,<tid>` (tid in hex, comma-separated).
#[must_use]
pub fn thread_extra_info_command(tid: u64) -> String {
    format!("qThreadExtraInfo,{tid:x}")
}

/// Decode the hex-encoded ASCII payload of a `qThreadExtraInfo` reply.
///
/// Returns `Ok(None)` for an empty reply (packet unsupported) and for `OK`,
/// which some stubs send when they have nothing to say.
///
/// # Errors
/// [`DebugError::Os`] when the stub answered `Exx`, or when the payload is not
/// valid hex — a silently truncated name is worse than a reported failure.
pub fn parse_thread_extra_info(reply: &str) -> Result<Option<String>, DebugError> {
    let trimmed = reply.trim();
    if trimmed.is_empty() || trimmed == "OK" {
        return Ok(None);
    }
    if is_error_reply(trimmed) {
        return Err(DebugError::Os(format!(
            "qThreadExtraInfo rejected by stub: {trimmed}"
        )));
    }
    if trimmed.len() % 2 != 0 {
        return Err(DebugError::Os(format!(
            "qThreadExtraInfo payload has odd length {}: {trimmed:?}",
            trimmed.len()
        )));
    }
    let mut bytes = Vec::with_capacity(trimmed.len() / 2);
    let raw = trimmed.as_bytes();
    for pair in raw.chunks_exact(2) {
        let hex = std::str::from_utf8(pair).map_err(|_| {
            DebugError::Os("qThreadExtraInfo payload is not ASCII hex".to_string())
        })?;
        let byte = u8::from_str_radix(hex, 16)
            .map_err(|_| DebugError::Os(format!("qThreadExtraInfo payload not hex: {hex:?}")))?;
        bytes.push(byte);
    }
    // Trailing NULs are common; the name is C-string-ish on the wire.
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

/// A stub error reply, not a payload.
///
/// The protocol defines TWO shapes and both must be recognised here:
/// * `Exx` — `xx` hex digits, the numeric form;
/// * `E.errtext` — the textual form `rsp::RspPacket::error_text` already
///   handles. Missing it turned a plain "packet unsupported" answer into a
///   fatal `jThreadsInfo` parse error instead of the intended fallback.
///
/// `E.` cannot collide with a hex payload: `.` is not a hex digit.
fn is_error_reply(reply: &str) -> bool {
    let rest = match reply.strip_prefix('E') {
        Some(r) => r,
        None => return false,
    };
    if rest.starts_with('.') {
        return true;
    }
    !rest.is_empty() && rest.len() <= 2 && rest.bytes().all(|b| b.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------
// Stop reasons
// ---------------------------------------------------------------------------

/// Why one thread is stopped.
///
/// Kept distinct from `crate::StopReason` on purpose: that type
/// describes the *process-level* event that ended a resume, whereas after a
/// stop every thread has its own reason and all but one of them are usually
/// `NotStopped`/`Signal(0)`. Flattening the two hid, in an earlier backend,
/// the case where a second thread had faulted at the same moment.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ThreadStopReason {
    /// The stub reported no reason for this thread (it was merely suspended
    /// along with the process).
    #[default]
    Unspecified,
    /// Hit a breakpoint.
    Breakpoint,
    /// Hit a watchpoint.
    Watchpoint,
    /// Completed a single step.
    Trace,
    /// A POSIX signal was delivered.
    Signal(u32),
    /// A Mach exception, with its type and data words.
    Exception { metype: u64, medata: Vec<u64> },
    /// The process exited.
    Exited(u8),
    /// The process was *killed* by a signal (`Xnn`).
    ///
    /// Deliberately not [`Self::Signal`]: that one means the thread is stopped
    /// *with* a signal pending and is still there to be inspected, whereas this
    /// one means the process is gone and its registers, stack and memory no
    /// longer exist. Collapsing the two made a terminated target look like a
    /// live thread that had merely faulted.
    Terminated(u32),
    /// A reason string this crate does not model. Preserved verbatim rather
    /// than mapped to `Unspecified`, so nothing is silently lost.
    Other(String),
}

impl fmt::Display for ThreadStopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => f.write_str("unspecified"),
            Self::Breakpoint => f.write_str("breakpoint"),
            Self::Watchpoint => f.write_str("watchpoint"),
            Self::Trace => f.write_str("trace"),
            Self::Signal(s) => write!(f, "signal {s}"),
            Self::Exception { metype, medata } => {
                write!(f, "mach exception {metype} {medata:?}")
            }
            Self::Exited(code) => write!(f, "exited {code}"),
            Self::Terminated(sig) => write!(f, "terminated by signal {sig}"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

impl ThreadStopReason {
    /// `true` when this thread is the one that caused the process to stop.
    #[must_use]
    pub const fn is_stopping_reason(&self) -> bool {
        matches!(
            self,
            Self::Breakpoint | Self::Watchpoint | Self::Trace | Self::Exception { .. }
        ) || matches!(self, Self::Signal(s) if *s != 0)
    }

    /// `true` when this reason says the process no longer exists.
    ///
    /// Both ends of a process are covered — a clean `exit()` ([`Self::Exited`])
    /// and a fatal signal ([`Self::Terminated`]) — because a caller deciding
    /// whether it may still read registers cares only that the target is gone,
    /// not how it left.
    #[must_use]
    pub const fn is_process_gone(&self) -> bool {
        matches!(self, Self::Exited(_) | Self::Terminated(_))
    }

    /// Map a textual `reason:` field, plus the numeric detail that came with
    /// it, to a reason.
    fn from_parts(
        reason: Option<&str>,
        signo: Option<u32>,
        metype: Option<u64>,
        medata: &[u64],
    ) -> Self {
        match reason {
            Some("breakpoint") => Self::Breakpoint,
            Some("watchpoint") => Self::Watchpoint,
            Some("trace") => Self::Trace,
            Some("signal") => Self::Signal(signo.unwrap_or(0)),
            Some("exception") => metype.map_or_else(
                || Self::Other("exception".to_string()),
                |metype| Self::Exception { metype, medata: medata.to_vec() },
            ),
            Some(other) if !other.is_empty() => Self::Other(other.to_string()),
            _ => match (metype, signo) {
                (Some(metype), _) => Self::Exception { metype, medata: medata.to_vec() },
                (None, Some(s)) if s != 0 => Self::Signal(s),
                _ => Self::Unspecified,
            },
        }
    }

    /// Derive a reason from a `jThreadsInfo` entry.
    #[must_use]
    pub fn from_thread_info(info: &ThreadInfo) -> Self {
        Self::from_parts(info.reason.as_deref(), info.signo, info.metype, &info.medata)
    }

    /// Derive a reason from a `qThreadStopInfo` (`T`/`W`/`X`/`S`) reply.
    #[must_use]
    pub fn from_stop_reply(reply: &StopReply) -> Self {
        match reply {
            StopReply::Exited { status } => Self::Exited(*status),
            StopReply::Terminated { signal } => Self::Terminated(u32::from(*signal)),
            StopReply::Signal { signal } => {
                if *signal == 0 {
                    Self::Unspecified
                } else {
                    Self::Signal(u32::from(*signal))
                }
            }
            StopReply::SignalWithInfo { signal, pairs, .. } => {
                let get = |k: &str| pairs.iter().find(|(pk, _)| pk == k).map(|(_, v)| v.as_str());
                let metype = get("metype").and_then(|v| u64::from_str_radix(v, 16).ok());
                let medata: Vec<u64> = pairs
                    .iter()
                    .filter(|(k, _)| k == "medata")
                    .filter_map(|(_, v)| u64::from_str_radix(v, 16).ok())
                    .collect();
                let signo = if *signal == 0 { None } else { Some(u32::from(*signal)) };
                Self::from_parts(get("reason"), signo, metype, &medata)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Thread descriptions
// ---------------------------------------------------------------------------

/// Which packet produced a [`ThreadDescription`].
///
/// Recorded because the two routes carry different amounts of information: the
/// fallback route cannot report a GCD queue at all, so `queue == None` means
/// "unknown", not "no queue", when `source` is [`Self::Fallback`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadInfoSource {
    /// One `jThreadsInfo` round trip.
    JThreadsInfo,
    /// `qfThreadInfo` + `qThreadStopInfo` + `qThreadExtraInfo` per thread.
    Fallback,
}

/// The unwind-relevant registers of a thread, as far as they are known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrameRegisters {
    pub pc: Option<u64>,
    pub sp: Option<u64>,
    pub fp: Option<u64>,
    pub lr: Option<u64>,
}

impl FrameRegisters {
    /// Pull pc/sp/fp/lr out of a `jThreadsInfo` register snapshot using the
    /// runtime-discovered register map.
    ///
    /// The map is consulted rather than hardcoding arm64 numbers because the
    /// same code must work for an x86-64 target, where the generic roles map to
    /// entirely different indices.
    #[must_use]
    pub fn from_snapshot(info: &ThreadInfo, regs: &RegisterMap) -> Self {
        let get = |role: GenericRole| -> Option<u64> {
            let entry = regs.by_generic(role)?;
            info.register_u64(entry.regnum)
        };
        Self {
            pc: get(GenericRole::Pc),
            sp: get(GenericRole::Sp),
            fp: get(GenericRole::Fp),
            lr: get(GenericRole::Ra),
        }
    }

    /// `true` when nothing at all was recovered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pc.is_none() && self.sp.is_none() && self.fp.is_none() && self.lr.is_none()
    }
}

/// Everything known about one thread of a stopped Apple target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadDescription {
    pub tid: ThreadId,
    /// Thread name (`pthread_setname_np`, or `qThreadExtraInfo` text).
    pub name: Option<String>,
    /// GCD dispatch queue label, when the thread is servicing one.
    /// Only ever populated on the [`ThreadInfoSource::JThreadsInfo`] route.
    pub queue: Option<String>,
    pub stop_reason: ThreadStopReason,
    pub frame: FrameRegisters,
    /// `true` for the thread the stub currently has selected (`Hg`).
    pub is_current: bool,
    pub source: ThreadInfoSource,
}

impl ThreadDescription {
    /// A description carrying nothing but an id — the floor every route can
    /// reach even when the stub answers nothing else.
    #[must_use]
    pub fn bare(tid: ThreadId, source: ThreadInfoSource) -> Self {
        Self {
            tid,
            name: None,
            queue: None,
            stop_reason: ThreadStopReason::Unspecified,
            frame: FrameRegisters::default(),
            is_current: false,
            source,
        }
    }

    /// Build from a `jThreadsInfo` entry.
    ///
    /// # Errors
    /// [`DebugError::Os`] when the tid does not fit the hub crate's 32-bit
    /// [`ThreadId`] — reporting a wrapped id would attach a backtrace to the
    /// wrong thread.
    pub fn from_thread_info(info: &ThreadInfo, regs: &RegisterMap) -> Result<Self, DebugError> {
        let tid = u32::try_from(info.tid).map_err(|_| {
            DebugError::Os(format!("stub reported thread id {} which exceeds 32 bits", info.tid))
        })?;
        Ok(Self {
            tid: ThreadId(tid),
            name: info.name.clone().filter(|s| !s.is_empty()),
            queue: info.queue.clone().filter(|s| !s.is_empty()),
            stop_reason: ThreadStopReason::from_thread_info(info),
            frame: FrameRegisters::from_snapshot(info, regs),
            is_current: false,
            source: ThreadInfoSource::JThreadsInfo,
        })
    }

    /// A short one-line rendering, for logs and `debug_*` MCP tools.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut s = format!("tid {}", self.tid.0);
        if let Some(name) = &self.name {
            s.push_str(&format!(" \"{name}\""));
        }
        if let Some(queue) = &self.queue {
            s.push_str(&format!(" queue={queue}"));
        }
        s.push_str(&format!(" [{}]", self.stop_reason));
        if let Some(pc) = self.frame.pc {
            s.push_str(&format!(" pc={pc:#x}"));
        }
        if self.is_current {
            s.push_str(" *current*");
        }
        s
    }
}

/// One thread's reconstructed call stack.
#[derive(Debug, Clone)]
pub struct ThreadBacktrace {
    pub thread: ThreadDescription,
    /// `Ok` frames, or the error that stopped the walk. A failure on one
    /// thread does not discard the other threads' stacks — which is the whole
    /// point of collecting them per thread.
    pub frames: Result<Vec<StackFrame>, String>,
}

// ---------------------------------------------------------------------------
// Session-level packet exchanges
// ---------------------------------------------------------------------------

/// Ask for `jThreadsInfo` and parse it.
///
/// `Ok(None)` means the stub does not implement the packet (empty reply); the
/// caller is expected to fall back rather than to fail.
fn query_jthreads_info(
    session: &mut Session,
    regs: &RegisterMap,
) -> Result<Option<Vec<ThreadDescription>>, DebugError> {
    let reply = session.text(JTHREADS_INFO.as_bytes(), JTHREADS_INFO)?;
    if reply.trim().is_empty() || is_error_reply(reply.trim()) {
        return Ok(None);
    }
    let infos = lldb_ext::parse_threads_info(&reply).map_err(|e| {
        DebugError::Os(format!("jThreadsInfo reply not understood: {e}"))
    })?;
    let mut out = Vec::with_capacity(infos.len());
    for info in &infos {
        out.push(ThreadDescription::from_thread_info(info, regs)?);
    }
    Ok(Some(out))
}

/// Rebuild the same list without `jThreadsInfo`.
fn query_threads_the_slow_way(session: &mut Session) -> Result<Vec<ThreadDescription>, DebugError> {
    let ids = session
        .client
        .thread_ids()
        .map_err(|e| rsp_err("qfThreadInfo", &e))?;
    let mut out = Vec::with_capacity(ids.len());
    for raw in ids {
        let Ok(tid32) = u32::try_from(raw) else {
            return Err(DebugError::Os(format!(
                "stub reported thread id {raw} which exceeds 32 bits"
            )));
        };
        let mut desc = ThreadDescription::bare(ThreadId(tid32), ThreadInfoSource::Fallback);

        let stop = session.text(
            thread_stop_info_command(raw).as_bytes(),
            "qThreadStopInfo",
        )?;
        let stop = stop.trim();
        if !stop.is_empty() && !is_error_reply(stop) {
            match StopReply::parse(stop.as_bytes()) {
                Ok(reply) => {
                    desc.stop_reason = ThreadStopReason::from_stop_reply(&reply);
                    if let StopReply::SignalWithInfo { pairs, .. } = &reply {
                        for (k, v) in pairs {
                            if k == "name" && !v.is_empty() {
                                desc.name = Some(v.clone());
                            }
                        }
                    }
                }
                // A stub that answers this packet with garbage should not sink
                // the whole enumeration; the id is still true.
                Err(e) => {
                    desc.stop_reason =
                        ThreadStopReason::Other(format!("unparsable stop reply: {e}"));
                }
            }
        }

        if desc.name.is_none() {
            let extra = session.text(
                thread_extra_info_command(raw).as_bytes(),
                "qThreadExtraInfo",
            )?;
            // An unsupported/refused qThreadExtraInfo is not fatal: a nameless
            // thread is still a thread.
            if let Ok(name) = parse_thread_extra_info(&extra) {
                desc.name = name;
            }
        }
        out.push(desc);
    }
    Ok(out)
}

/// The thread the stub has selected, via `qC`.
///
/// Deliberately does *not* short-circuit on `Session::current_tid`: that field
/// records the thread which reported the most recent stop, which is a different
/// thing from the thread `Hg` currently points at. Reading registers of another
/// thread moves the selection without producing a stop, and trusting the cache
/// made `is_current` name the wrong thread in exactly that case.
fn query_current_tid(session: &mut Session) -> Result<Option<ThreadId>, DebugError> {
    let qc = session.text(b"qC", "qC")?;
    let qc = qc.trim();
    let Some(hex) = qc.strip_prefix("QC") else {
        // No `qC` support: the last stop is the best answer available.
        return Ok(if session.current_tid.0 == 0 { None } else { Some(session.current_tid) });
    };
    parse_qc_tid(hex)
        .map(crate::ios::apple_debugger::thread_id_from_stub)
        .transpose()
}

/// Decode the thread id out of the body of a `qC` reply — the text AFTER the
/// `QC` prefix.
///
/// Two spellings are legal, and which one arrives depends on a feature this
/// client itself negotiates: with `multiprocess+` (see the `handshake` call in
/// `apple_debugger.rs`) debugserver answers `QCp<pid>.<tid>`, otherwise plain
/// `QC<tid>`. Returning `None` for anything else is the point: every caller
/// must be able to tell "id 0" from "could not parse", because 0 is this
/// backend's "leave the stub's selection alone" wildcard.
///
/// All three `qC` ports go through here — `query_current_tid` above, the
/// fallback inside `AppleDebugger::attach`, and `Debugger::current_thread`.
/// The last two used to decode inline with `from_str_radix` over the whole
/// body and did not know the `p<pid>.<tid>` spelling; that is why the doc of
/// the unit test below now also has an end-to-end companion,
/// `multiprocess_qc_reply_drives_attach_and_current_thread`.
///
/// Returns the RAW id: the >32-bit refusal lives in `thread_id_from_stub`, so
/// "too wide" stays distinguishable from "not understood".
pub(crate) fn parse_qc_tid(body: &str) -> Option<u64> {
    let body = body.trim();
    // `p<pid>.<tid>`: the tid is the part after the dot; a pid-less `p<tid>`
    // has no dot, in which case the whole body minus the `p` is the tid.
    let tail = body.rsplit('.').next().unwrap_or(body);
    let tail = tail.strip_prefix('p').unwrap_or(tail);
    u64::from_str_radix(tail, 16).ok()
}

// ---------------------------------------------------------------------------
// Public debugger API
// ---------------------------------------------------------------------------

impl AppleDebugger {
    /// Describe every thread of the stopped target, preferring the single
    /// `jThreadsInfo` round trip and falling back to per-thread packets.
    ///
    /// # Errors
    /// [`DebugError::NotAttached`] when there is no session, or
    /// [`DebugError::Os`] when the stub's reply cannot be trusted.
    pub async fn thread_descriptions(&self) -> Result<Vec<ThreadDescription>, DebugError> {
        self.with_session(|session| {
            let regs = session.regs.clone();
            let mut threads = match query_jthreads_info(session, &regs)? {
                Some(list) if !list.is_empty() => list,
                // Empty JSON array from a live process is nonsense; treat it
                // like an unsupported packet rather than reporting "no threads".
                _ => query_threads_the_slow_way(session)?,
            };
            if let Some(current) = query_current_tid(session)? {
                for t in &mut threads {
                    t.is_current = t.tid == current;
                }
            }
            threads.sort_by_key(|t| t.tid.0);
            Ok(threads)
        })
    }

    /// Point the stub's `Hg`/`Hc` at `tid`.
    ///
    /// Every register and resume packet is implicitly addressed to the selected
    /// thread, so this is the operation that makes "inspect thread N" possible
    /// at all.
    ///
    /// # Errors
    /// [`DebugError::NotAttached`], or [`DebugError::Os`] when the stub refuses
    /// the selection (typically because the thread has exited).
    pub async fn select_thread(&self, tid: ThreadId) -> Result<(), DebugError> {
        self.with_session(|session| {
            session.select_thread(tid)?;
            session.current_tid = tid;
            Ok(())
        })
    }

    /// The stop reason of one specific thread, via `qThreadStopInfo`.
    ///
    /// # Errors
    /// [`DebugError::NotAttached`], or [`DebugError::Os`] when the stub does
    /// not implement the packet or rejects the thread id.
    pub async fn thread_stop_reason(&self, tid: ThreadId) -> Result<ThreadStopReason, DebugError> {
        self.with_session(|session| {
            let reply = session.text(
                thread_stop_info_command(u64::from(tid.0)).as_bytes(),
                "qThreadStopInfo",
            )?;
            let reply = reply.trim();
            if reply.is_empty() {
                return Err(DebugError::Unsupported(
                    "stub does not implement qThreadStopInfo".to_string(),
                ));
            }
            if is_error_reply(reply) {
                return Err(DebugError::Os(format!(
                    "qThreadStopInfo for {tid} rejected by stub: {reply}"
                )));
            }
            let parsed = StopReply::parse(reply.as_bytes()).map_err(|e| {
                DebugError::Os(format!("qThreadStopInfo reply {reply:?} not understood: {e}"))
            })?;
            Ok(ThreadStopReason::from_stop_reply(&parsed))
        })
    }

    /// The human-readable name of one thread, via `qThreadExtraInfo`.
    ///
    /// `Ok(None)` when the stub has no name for it.
    ///
    /// # Errors
    /// [`DebugError::NotAttached`], or [`DebugError::Os`] on a malformed reply.
    pub async fn thread_name(&self, tid: ThreadId) -> Result<Option<String>, DebugError> {
        self.with_session(|session| {
            let reply = session.text(
                thread_extra_info_command(u64::from(tid.0)).as_bytes(),
                "qThreadExtraInfo",
            )?;
            parse_thread_extra_info(&reply)
        })
    }

    /// Walk the stack of every thread.
    ///
    /// Thread selection is re-established before each walk and the thread that
    /// was current on entry is restored afterwards, so enumerating stacks is
    /// not observable as a side effect by the next register access.
    ///
    /// # Errors
    /// [`DebugError::NotAttached`], or an error from the enumeration itself. A
    /// failure to unwind a *single* thread is reported inside that thread's
    /// [`ThreadBacktrace::frames`], not as an overall error.
    pub async fn backtrace_all_threads(&self) -> Result<Vec<ThreadBacktrace>, DebugError> {
        use crate::Debugger as _;

        let threads = self.thread_descriptions().await?;
        let previous = threads.iter().find(|t| t.is_current).map(|t| t.tid);

        let mut out = Vec::with_capacity(threads.len());
        for thread in threads {
            let frames = self
                .backtrace(thread.tid)
                .await
                .map_err(|e| e.to_string());
            out.push(ThreadBacktrace { thread, frames });
        }
        if let Some(tid) = previous {
            // Best effort: if restoring fails the enumeration still succeeded,
            // and the caller's next explicit selection will fix it.
            let _ = self.select_thread(tid).await;
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ios::apple_debugger::LoopbackFactory;
    use crate::ios::mock_debugserver::{MockDebugserver, MockThread, StopKind};
    use rustre_core::address::Address;
    use crate::{BreakpointKind, Debugger, ProcessId};
    use std::sync::Arc;

    /// Pure-parsing guard for the one `qC` decoder. The end-to-end attach test
    /// below covers the wiring; this pins the shapes themselves, so a rewrite
    /// of the decoder cannot quietly drop the `multiprocess+` spelling that
    /// `Session::establish` asks debugserver for.
    #[test]
    fn parse_qc_tid_accepts_plain_and_multiprocess_bodies() {
        // Compile-anchored: a rename cannot leave this test guarding nothing.
        let decode: fn(&str) -> Option<u64> = parse_qc_tid;
        assert_eq!(decode("2a"), Some(0x2a));
        assert_eq!(decode("p1f4.2b3"), Some(0x2b3), "multiprocess `p<pid>.<tid>` must decode");
        assert_eq!(decode("p2b3"), Some(0x2b3), "pid-less `p<tid>` must decode");
        assert_eq!(decode("p1f4.2b3
"), Some(0x2b3));
        // Undecodable must stay `None`: 0 is this backend's "leave the stub's
        // selection alone" wildcard, so it may never stand in for a failure.
        assert_eq!(decode("zz"), None);
        assert_eq!(decode(""), None);
    }

    const TEXT_BASE: u64 = 0x1_0000_4000;

    /// Same program shape as the `apple_debugger` tests: a caller that
    /// establishes a frame record and a callee, so an unwind has something to
    /// walk on every thread we park inside it.
    fn program() -> Vec<u32> {
        vec![
            0xA9BF_7BFD, // stp x29, x30, [sp, #-16]!
            0x910003FD, // mov x29, sp
            0x9400_0004, // bl +0x10
            0xA8C1_7BFD, // ldp x29, x30, [sp], #16
            0xD65F_03C0, // ret
            0xD503_201F, // nop  (padding)
            0xD503_201F, // nop
            0xD503_201F, // nop
            0xD10043FF, // sub sp, sp, #0x10  (callee)
            0x910043FF, // add sp, sp, #0x10
            0xD65F_03C0, // ret
        ]
    }

    /// A server with three threads: `main` parked at the text base, plus two
    /// workers with distinct names, queues and stop reasons.
    fn multi_thread_server() -> MockDebugserver {
        let mut srv = MockDebugserver::with_program(4242, TEXT_BASE, &program());
        let main_regs = srv.threads()[0].regs.clone();

        let mut worker = MockThread::new(0x2A, "worker-a");
        worker.queue = Some("com.apple.root.default-qos".to_string());
        worker.regs = main_regs.clone();
        worker.regs.pc = TEXT_BASE + 0x20;
        worker.stop = StopKind::Signal(11);
        srv.add_thread(worker);

        let mut idle = MockThread::new(0x2B, "worker-b");
        idle.regs = main_regs;
        idle.regs.pc = TEXT_BASE + 0x10;
        idle.stop = StopKind::Attached;
        srv.add_thread(idle);
        srv
    }

    fn debugger_with(srv: MockDebugserver) -> AppleDebugger {
        AppleDebugger::new(Arc::new(LoopbackFactory::new(srv, 0)))
    }

    // -- pure parsing ------------------------------------------------------

    #[test]
    fn packet_builders_use_the_documented_separators() {
        assert_eq!(thread_stop_info_command(0x2a), "qThreadStopInfo2a");
        assert_eq!(thread_extra_info_command(0x2a), "qThreadExtraInfo,2a");
        assert_eq!(JTHREADS_INFO, "jThreadsInfo");
    }

    #[test]
    fn extra_info_hex_round_trips_and_rejects_garbage() {
        // "main"
        assert_eq!(parse_thread_extra_info("6d61696e").unwrap().as_deref(), Some("main"));
        // trailing NUL is stripped
        assert_eq!(parse_thread_extra_info("6d61696e00").unwrap().as_deref(), Some("main"));
        assert_eq!(parse_thread_extra_info("").unwrap(), None);
        assert_eq!(parse_thread_extra_info("OK").unwrap(), None);
        assert_eq!(parse_thread_extra_info("00").unwrap(), None);
        assert!(parse_thread_extra_info("E01").is_err());
        assert!(parse_thread_extra_info("6d6").is_err(), "odd length must fail");
        assert!(parse_thread_extra_info("zz").is_err(), "non-hex must fail");
    }

    #[test]
    fn error_reply_detection_does_not_swallow_payloads() {
        assert!(is_error_reply("E01"));
        assert!(is_error_reply("E4"));
        // "E" followed by hex-looking *payload* longer than 2 is a payload.
        assert!(!is_error_reply("E0102"));
        assert!(!is_error_reply("E"));
        assert!(!is_error_reply("6d61696e"));
    }

    #[test]
    fn error_reply_detection_covers_textual_form() {
        // The protocol defines TWO error replies: `E NN` and `E.errtext`.
        // `rsp::RspPacket::error_text` already handles the textual one; this
        // predicate must agree, otherwise the jThreadsInfo fallback path turns
        // a plain "unsupported" into a fatal parse error.
        assert!(is_error_reply("E.unsupported packet"));
        assert!(is_error_reply("E.thread id is bogus"));
        assert!(is_error_reply("E."));
        // `.` is not a hex digit, so a hex payload can never be mistaken for it.
        assert!(!is_error_reply("6d61696e"));
        assert!(!is_error_reply("Efoo"));
        // The guard is anchored to the identifier under test, not to a string.
        let _guard: fn(&str) -> bool = is_error_reply;
    }

    #[test]
    fn stop_reason_maps_every_documented_field() {
        let mut info = ThreadInfo { tid: 1, ..ThreadInfo::default() };
        assert_eq!(ThreadStopReason::from_thread_info(&info), ThreadStopReason::Unspecified);

        info.reason = Some("breakpoint".to_string());
        assert_eq!(ThreadStopReason::from_thread_info(&info), ThreadStopReason::Breakpoint);

        info.reason = Some("watchpoint".to_string());
        assert_eq!(ThreadStopReason::from_thread_info(&info), ThreadStopReason::Watchpoint);

        info.reason = Some("trace".to_string());
        assert_eq!(ThreadStopReason::from_thread_info(&info), ThreadStopReason::Trace);

        info.reason = Some("signal".to_string());
        info.signo = Some(11);
        assert_eq!(ThreadStopReason::from_thread_info(&info), ThreadStopReason::Signal(11));

        info.reason = Some("exception".to_string());
        info.metype = Some(6);
        info.medata = vec![1, 0x4000];
        assert_eq!(
            ThreadStopReason::from_thread_info(&info),
            ThreadStopReason::Exception { metype: 6, medata: vec![1, 0x4000] }
        );

        info.reason = Some("nonsense-from-the-target".to_string());
        assert_eq!(
            ThreadStopReason::from_thread_info(&info),
            ThreadStopReason::Other("nonsense-from-the-target".to_string()),
            "an unmodelled reason must be preserved, not dropped"
        );
    }

    #[test]
    fn stop_reason_from_t_packet_reads_metype_and_reason() {
        let reply = StopReply::parse(
            b"T05thread:2a;metype:6;mecount:2;medata:1;medata:4000;reason:breakpoint;",
        )
        .unwrap();
        assert_eq!(ThreadStopReason::from_stop_reply(&reply), ThreadStopReason::Breakpoint);

        let reply = StopReply::parse(b"T0bthread:2a;metype:1;medata:2;").unwrap();
        assert_eq!(
            ThreadStopReason::from_stop_reply(&reply),
            ThreadStopReason::Exception { metype: 1, medata: vec![2] }
        );

        assert_eq!(
            ThreadStopReason::from_stop_reply(&StopReply::parse(b"W03").unwrap()),
            ThreadStopReason::Exited(3)
        );
        assert_eq!(
            ThreadStopReason::from_stop_reply(&StopReply::parse(b"S00").unwrap()),
            ThreadStopReason::Unspecified
        );
        assert_eq!(
            ThreadStopReason::from_stop_reply(&StopReply::parse(b"S0b").unwrap()),
            ThreadStopReason::Signal(11)
        );
    }

    #[test]
    fn killed_by_a_signal_is_not_the_same_as_stopped_by_one() {
        // `Xnn` says the process was TERMINATED by signal nn: it is gone, and
        // nothing about it can be inspected any more. `Snn` says a thread is
        // STOPPED with signal nn pending: it is alive and its registers and
        // stack are readable. Reporting the first as the second invites a
        // caller to unwind a corpse.
        let killed = ThreadStopReason::from_stop_reply(&StopReply::parse(b"X0b").unwrap());
        let stopped = ThreadStopReason::from_stop_reply(&StopReply::parse(b"S0b").unwrap());

        assert_ne!(
            killed, stopped,
            "X0b (killed by SIGSEGV) must not decay into S0b (stopped by SIGSEGV)"
        );
        assert_eq!(killed, ThreadStopReason::Terminated(11));
        assert_eq!(killed.to_string(), "terminated by signal 11");

        // A dead process has no culprit thread, exactly like `Wnn`.
        assert!(
            !killed.is_stopping_reason(),
            "a terminated process must not be reported as the thread that stopped it"
        );
        // ...and it is an end-of-process reason, unlike a plain signal stop.
        assert!(killed.is_process_gone());
        assert!(ThreadStopReason::Exited(3).is_process_gone());
        assert!(!stopped.is_process_gone());

        // The signal number still survives — nothing is lost by the fix.
        assert_eq!(
            ThreadStopReason::from_stop_reply(&StopReply::parse(b"X09").unwrap()),
            ThreadStopReason::Terminated(9)
        );
    }

    #[test]
    fn is_stopping_reason_separates_the_culprit_from_the_bystanders() {
        assert!(ThreadStopReason::Breakpoint.is_stopping_reason());
        assert!(ThreadStopReason::Signal(11).is_stopping_reason());
        assert!(!ThreadStopReason::Signal(0).is_stopping_reason());
        assert!(!ThreadStopReason::Unspecified.is_stopping_reason());
        assert!(!ThreadStopReason::Exited(0).is_stopping_reason());
    }

    #[test]
    fn oversized_thread_id_is_refused_rather_than_wrapped() {
        let info = ThreadInfo { tid: u64::from(u32::MAX) + 1, ..ThreadInfo::default() };
        let map = RegisterMap { regs: Vec::new() };
        assert!(ThreadDescription::from_thread_info(&info, &map).is_err());
    }

    // -- against the mock --------------------------------------------------

    /// The two REAL `qC` ports — the fallback inside `attach` and
    /// `Debugger::current_thread` — against a stub that answers in the
    /// `multiprocess+` spelling this client itself negotiates.
    ///
    /// Both used to run `from_str_radix` over the WHOLE body, which the
    /// `p<pid>.<tid>` spelling is not: measured red was
    /// `Err(Os("qC reply not understood: \"QCp1092.2a\""))` from
    /// `current_thread`, while the attach fallback silently left `current_tid`
    /// at 0 — this backend's "leave the stub's selection alone" wildcard, so
    /// every later per-thread operation acted on whatever thread the stub had
    /// selected. Both now go through `parse_qc_tid`, the one decoder.
    #[tokio::test]
    async fn multiprocess_qc_reply_drives_attach_and_current_thread() {
        let mut srv = multi_thread_server();
        srv.set_multiprocess_ids(true);
        // No `thread:` key in the stop reply, so attach must fall back to `qC`.
        srv.set_omit_stop_reply_thread(true);
        srv.set_current_thread(0x2A);

        let dbg = debugger_with(srv);
        dbg.attach(ProcessId(4242)).await.unwrap();

        // Compile-anchored on the production entry point, not a local copy.
        let tid = <AppleDebugger as Debugger>::current_thread(&dbg)
            .await
            .expect("qC in multiprocess spelling must decode");
        assert_eq!(tid, ThreadId(0x2A), "the tid is the part after the dot");
        assert_ne!(tid, ThreadId(0), "0 is the wildcard and may never stand in for a parse failure");
    }

    #[tokio::test]
    async fn jthreads_info_describes_every_thread_in_one_round_trip() {
        let dbg = debugger_with(multi_thread_server());
        dbg.attach(ProcessId(4242)).await.unwrap();

        let threads = dbg.thread_descriptions().await.unwrap();
        assert_eq!(threads.len(), 3, "{threads:#?}");
        assert!(
            threads.iter().all(|t| t.source == ThreadInfoSource::JThreadsInfo),
            "the mock advertises jThreadsInfo, so the fallback must not be used"
        );

        let ids: Vec<u32> = threads.iter().map(|t| t.tid.0).collect();
        assert_eq!(ids, vec![1, 0x2A, 0x2B], "sorted by tid");

        let main = &threads[0];
        assert_eq!(main.name.as_deref(), Some("main"));
        assert!(main.is_current, "thread 1 is the selected one");
        assert_eq!(main.frame.pc, Some(TEXT_BASE));
        assert!(main.frame.sp.is_some_and(|sp| sp != 0));

        let worker = &threads[1];
        assert_eq!(worker.name.as_deref(), Some("worker-a"));
        assert_eq!(worker.queue.as_deref(), Some("com.apple.root.default-qos"));
        assert_eq!(worker.stop_reason, ThreadStopReason::Signal(11));
        assert_eq!(worker.frame.pc, Some(TEXT_BASE + 0x20));
        assert!(!worker.is_current);

        assert_eq!(threads[2].name.as_deref(), Some("worker-b"));
        assert!(threads[2].summary().contains("tid 43"));
    }

    #[tokio::test]
    async fn descriptions_survive_a_stub_without_jthreads_info() {
        let mut srv = multi_thread_server();
        srv.set_jthreads_info_supported(false);
        let dbg = debugger_with(srv);
        dbg.attach(ProcessId(4242)).await.unwrap();

        let threads = dbg.thread_descriptions().await.unwrap();
        assert_eq!(threads.len(), 3);
        assert!(threads.iter().all(|t| t.source == ThreadInfoSource::Fallback));
        // Names still arrive, through qThreadExtraInfo / the T packet.
        assert_eq!(threads[1].name.as_deref(), Some("worker-a"));
        assert_eq!(threads[1].stop_reason, ThreadStopReason::Signal(11));
        // The queue is genuinely unavailable on this route — and is reported as
        // unknown rather than invented.
        assert_eq!(threads[1].queue, None);
    }

    #[tokio::test]
    async fn h_packet_selects_the_thread_registers_are_read_from() {
        let dbg = debugger_with(multi_thread_server());
        dbg.attach(ProcessId(4242)).await.unwrap();

        dbg.select_thread(ThreadId(0x2A)).await.unwrap();
        assert_eq!(dbg.current_thread().await.unwrap(), ThreadId(0x2A));
        let regs = dbg.get_registers(ThreadId(0x2A)).await.unwrap();
        assert_eq!(regs.pc, TEXT_BASE + 0x20);

        let other = dbg.get_registers(ThreadId(0x2B)).await.unwrap();
        assert_eq!(other.pc, TEXT_BASE + 0x10, "H must have re-pointed the g packet");

        let threads = dbg.thread_descriptions().await.unwrap();
        let current: Vec<u32> =
            threads.iter().filter(|t| t.is_current).map(|t| t.tid.0).collect();
        assert_eq!(current, vec![0x2B], "exactly one thread is current");
    }

    #[tokio::test]
    async fn selecting_a_dead_thread_is_an_error_not_a_silent_no_op() {
        let dbg = debugger_with(multi_thread_server());
        dbg.attach(ProcessId(4242)).await.unwrap();
        assert!(dbg.select_thread(ThreadId(0x999)).await.is_err());
    }

    #[tokio::test]
    async fn per_thread_stop_info_and_name_are_addressable_individually() {
        let dbg = debugger_with(multi_thread_server());
        dbg.attach(ProcessId(4242)).await.unwrap();

        assert_eq!(
            dbg.thread_stop_reason(ThreadId(0x2A)).await.unwrap(),
            ThreadStopReason::Signal(11)
        );
        assert_eq!(
            dbg.thread_name(ThreadId(0x2A)).await.unwrap().as_deref(),
            Some("worker-a")
        );
        assert_eq!(dbg.thread_name(ThreadId(1)).await.unwrap().as_deref(), Some("main"));
        assert!(dbg.thread_stop_reason(ThreadId(0x999)).await.is_err());
    }

    #[tokio::test]
    async fn breakpoint_hit_is_attributed_to_the_thread_that_hit_it() {
        let dbg = debugger_with(multi_thread_server());
        dbg.attach(ProcessId(4242)).await.unwrap();
        dbg.set_breakpoint(Address::new(TEXT_BASE + 0x8), BreakpointKind::Software)
            .await
            .unwrap();
        dbg.continue_execution().await.unwrap();

        let threads = dbg.thread_descriptions().await.unwrap();
        let main = threads.iter().find(|t| t.tid == ThreadId(1)).unwrap();
        assert_eq!(main.stop_reason, ThreadStopReason::Breakpoint);
        assert!(main.stop_reason.is_stopping_reason());
        // The other threads did not move and must not be reported as culprits.
        let worker = threads.iter().find(|t| t.tid == ThreadId(0x2B)).unwrap();
        assert!(!worker.stop_reason.is_stopping_reason(), "{:?}", worker.stop_reason);
    }

    #[tokio::test]
    async fn every_thread_gets_its_own_stack() {
        let mut srv = multi_thread_server();
        // Park a worker inside the callee with a real frame record on the
        // stack, so its unwind produces more than one frame and is visibly
        // different from main's.
        {
            let main_sp = srv.threads()[0].regs.sp;
            let frame = main_sp - 0x200;
            srv.memory.write(frame, &0u64.to_le_bytes()); // saved fp = 0 (chain end)
            srv.memory.write(frame + 8, &(TEXT_BASE + 0xC).to_le_bytes()); // saved lr
            let t = srv.thread_mut_for_test(0x2A).expect("worker exists");
            t.regs.x[29] = frame;
            t.regs.sp = frame;
            t.regs.pc = TEXT_BASE + 0x20;
        }
        let dbg = debugger_with(srv);
        dbg.attach(ProcessId(4242)).await.unwrap();

        let stacks = dbg.backtrace_all_threads().await.unwrap();
        assert_eq!(stacks.len(), 3);
        for st in &stacks {
            let frames = st.frames.as_ref().unwrap_or_else(|e| {
                panic!("thread {} failed to unwind: {e}", st.thread.tid.0)
            });
            assert!(!frames.is_empty(), "thread {} has no frames", st.thread.tid.0);
            assert_eq!(frames[0].index, 0);
        }
        let worker = stacks.iter().find(|s| s.thread.tid == ThreadId(0x2A)).unwrap();
        let frames = worker.frames.as_ref().unwrap();
        assert_eq!(frames[0].pc.as_u64(), TEXT_BASE + 0x20);
        assert!(frames.len() >= 2, "frame record should yield a caller: {frames:?}");
        assert_eq!(frames[1].pc.as_u64(), TEXT_BASE + 0xC);

        // Enumeration restored the originally selected thread.
        assert_eq!(dbg.current_thread().await.unwrap(), ThreadId(1));
    }

    #[tokio::test]
    async fn thread_apis_report_not_attached_instead_of_panicking() {
        let dbg = debugger_with(multi_thread_server());
        assert!(matches!(
            dbg.thread_descriptions().await,
            Err(DebugError::NotAttached)
        ));
        assert!(matches!(
            dbg.select_thread(ThreadId(1)).await,
            Err(DebugError::NotAttached)
        ));
        assert!(matches!(
            dbg.thread_name(ThreadId(1)).await,
            Err(DebugError::NotAttached)
        ));
        assert!(matches!(
            dbg.backtrace_all_threads().await,
            Err(DebugError::NotAttached)
        ));
    }
}
