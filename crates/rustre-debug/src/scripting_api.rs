//! Scripting API (Tier 2, item 5 of `rustre_debug_enhancement_plan.md`).
//!
//! Designed as an LLM tool-call surface from day one (ChatDBG-style, per the
//! plan's research-refresh addendum), not bolted on after the fact: every
//! capability is a flat, JSON-serializable [`ScriptRequest`] variant with a
//! matching [`ScriptResponse`] variant, so a tool-calling harness can expose
//! each variant as one tool with a typed schema, dispatch the model's call
//! through [`dispatch`], and hand the typed response straight back.
//!
//! Modeled on GDB's Python API (`gdb.Breakpoint`, memory/register access,
//! type info) but typed end-to-end, and it exposes the Tier-1 omniscient
//! `who_wrote`/`trace_origin` query as first-class tool calls — the single
//! most differentiating capability this debugger has over GDB/LLDB scripting.
//!
//! This module is backend-agnostic: it defines the request/response contract
//! and a [`ScriptContext`] trait; a real session (live `Debugger` backend +
//! `OmniscientIndex` + `watchpoint_engine::TypeRegistry`) implements the
//! trait to answer calls. [`MockScriptContext`] is a test double.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::omniscient_query::{MemoryWrite, OmniscientIndex, OriginHop};
use crate::watchpoint_engine::{TypeFieldWatchError, TypeRegistry, WatchpointType};
use crate::coredump_triage::{self, CrashCluster, CrashDump};
use crate::binary_diff::{self, BinaryDiff, BreakpointMigration};
use crate::race_detector::{self, MemoryAccess, RaceCandidate};
use crate::execution_heatmap::ExecutionHeatmap;
use crate::root_cause_assistant::{self, RootCauseReport};
use crate::provenance_classifier::{self, ModuleBaselineSpec};
use crate::time_travel_debug::TracePosition;
use crate::nl_query::{self, NlQueryResult};

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors surfaced back to the calling LLM tool-call harness. Kept small and
/// serializable so an agent can reason about *why* a call failed and retry
/// with a corrected argument, rather than seeing an opaque failure.
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptError {
    #[error("not attached to a process")]
    NotAttached,
    #[error("memory read error at {0:#x}")]
    MemoryRead(u64),
    #[error("memory write error at {0:#x}")]
    MemoryWrite(u64),
    #[error("unknown register: {0}")]
    UnknownRegister(String),
    #[error("breakpoint not found: id {0}")]
    BreakpointNotFound(u64),
    #[error("type-aware watchpoint error: {0}")]
    TypeWatch(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("dataflow query error: {0}")]
    DataflowQuery(String),
}

/// Translate a backend error into the scripting vocabulary WITHOUT inventing a
/// reason.
///
/// The call sites used to collapse every failure onto one variant — a failed
/// `remove_breakpoint` was reported as `BreakpointNotFound`, which is a
/// specific and false claim: the breakpoint is still there, still armed, and a
/// caller told "not found" concludes the opposite and moves on. A restore that
/// the target refused (a dead or unwritable process) is exactly that case.
/// Widest region a watchpoint planted through [`crate::Debugger::set_breakpoint`]
/// can be relied on to cover.
///
/// `BreakpointKind` carries no size, so the width is the backend's choice rather
/// than the caller's — the Apple backend uses 8 bytes (`z_kind_for`), and the
/// x86 debug registers top out at 8 as well. Until the trait can carry a width,
/// this is the honest ceiling: a request for more cannot be served, and pretending
/// otherwise would mean watching part of a field while reporting the whole.
pub const MAX_TRAIT_WATCHPOINT_BYTES: u64 = 8;

pub(crate) fn script_error_from(e: &crate::DebugError, fallback_addr: u64) -> ScriptError {
    match e {
        crate::DebugError::NotAttached => ScriptError::NotAttached,
        crate::DebugError::BreakpointNotFound(_) => ScriptError::BreakpointNotFound(fallback_addr),
        crate::DebugError::MemoryError(addr, _) => ScriptError::MemoryWrite(*addr),
        other => ScriptError::Unsupported(other.to_string()),
    }
}

#[cfg(test)]
mod error_mapping_tests {
    use super::*;
    use crate::ios::apple_debugger::{AppleDebugger, LoopbackFactory};
    use crate::ios::mock_debugserver::MockDebugserver;
    use crate::{Debugger, ProcessId, ThreadId};
    use std::sync::Arc;

    /// A field too wide for the trait's watchpoint must be refused, not
    /// half-watched.
    ///
    /// `BreakpointKind` carries no width, so each backend picks one (the Apple
    /// backend hard-codes 8 bytes). `set_type_field_watchpoint` resolved the
    /// field's real size, handed it back to the caller, and then planted a
    /// watchpoint of the backend's width regardless. For a 16-byte field that
    /// means half of it is unwatched while the caller is told the field is
    /// covered: a write into the tail is missed with nothing to notice — a
    /// false NEGATIVE, which is the one failure a watchpoint user cannot detect.
    #[test]
    fn a_field_wider_than_the_watchpoint_is_refused_rather_than_half_watched() {
        let dbg = AppleDebugger::new(Arc::new(LoopbackFactory::new(
            MockDebugserver::with_program(4242, 0x1_0000_4000, &[0xD503_201Fu32]),
            7,
        )));
        let mut types = TypeRegistry::new();
        // 16-byte field: twice what any current backend watches.
        types.register(
            "Blob",
            crate::watchpoint_engine::TypeLayout::new(32).with_field("payload", 0, 16),
        );
        let mut ctx = LiveScriptContext::new(
            Box::new(dbg),
            ThreadId(1),
            types,
            OmniscientIndex::from_writes(Vec::new()),
        );

        let err = ctx
            .set_type_field_watchpoint("Blob", 0x2000, "payload", true)
            .expect_err("a 16-byte field cannot be covered by an 8-byte watchpoint");
        let msg = err.to_string();
        assert!(
            msg.contains("16 bytes") && msg.contains("missed"),
            "the refusal must say what it cannot cover: {msg}"
        );
    }

    /// A detached session must be reported as detached, whatever was asked of
    /// it.
    ///
    /// This context reaches the backend directly — no `current_tid` guard in
    /// front, unlike its twin in `live_script_context` — so with nothing
    /// attached a register read returned `UnknownRegister("pc")` and a memory
    /// read returned `MemoryRead(0x1000)`. Both are specific and false: the
    /// register name is spelled correctly and the address was never consulted.
    /// An agent told the register does not exist looks for a typo; told the
    /// read failed, it retries other addresses. Neither attaches, which is the
    /// one thing that would have worked.
    ///
    /// Iteration 291 tried to prove this same defect on the sibling context and
    /// could not: there `current_tid` fails first and the mapping under test is
    /// never reached. Comparing the twins is what produced both the bug and a
    /// place where it is reachable.
    #[test]
    fn a_detached_session_is_not_blamed_on_the_register_name_or_the_address() {
        let dbg = AppleDebugger::new(Arc::new(LoopbackFactory::new(
            MockDebugserver::with_program(4242, 0x1_0000_4000, &[0xD503_201Fu32]),
            7,
        )));
        // Deliberately NOT attached.
        let ctx = LiveScriptContext::new(
            Box::new(dbg),
            ThreadId(1),
            TypeRegistry::new(),
            OmniscientIndex::from_writes(Vec::new()),
        );

        let reg = ctx.read_register("pc").expect_err("nothing is attached");
        assert!(
            matches!(reg, ScriptError::NotAttached),
            "a detached session was blamed on the register name: {reg}"
        );

        let mem = ctx.read_memory(0x1000, 4).expect_err("nothing is attached");
        assert!(
            matches!(mem, ScriptError::NotAttached),
            "a detached session was reported as a failed read at an address: {mem}"
        );
    }

    /// A removal the target refused must not be reported as "breakpoint not
    /// found".
    ///
    /// The scripting layer collapsed EVERY backend error onto
    /// `BreakpointNotFound(id)`. That is not a vague answer, it is a specific
    /// false one: when a restore fails the breakpoint is still installed and
    /// still armed, and a caller told "not found" concludes the opposite and
    /// stops looking — an LLM driving these tools reports the breakpoint
    /// removed and moves on, leaving a live patch in the target.
    #[test]
    fn a_refused_removal_is_not_reported_as_a_missing_breakpoint() {
        const BASE: u64 = 0x1_0000_4000;
        // `nop; ret` — the code never runs here, only the breakpoint matters.
        let prog = vec![0xD503_201Fu32, 0xD65F_03C0];
        let mut srv = MockDebugserver::with_program(4242, BASE, &prog);
        srv.refuse_software_breakpoints(); // self-patched, so removal must WRITE
        srv.fail_memory_writes_after(1); // the patch lands; the restore is refused
        let dbg = AppleDebugger::new(Arc::new(LoopbackFactory::new(srv, 7)));
        block_on(dbg.attach(ProcessId(4242))).expect("attach");

        let mut ctx = LiveScriptContext::new(
            Box::new(dbg),
            ThreadId(1),
            TypeRegistry::new(),
            OmniscientIndex::from_writes(Vec::new()),
        );
        let id = ctx.set_breakpoint(BASE).expect("set_breakpoint");

        let err = ctx.remove_breakpoint(id).expect_err("the restore is refused");
        assert!(
            !matches!(err, ScriptError::BreakpointNotFound(_)),
            "a refused write was reported as a missing breakpoint: {err}"
        );
        assert!(
            matches!(err, ScriptError::MemoryWrite(_)),
            "expected the real reason (a refused memory write), got {err}"
        );
    }

    /// The companion property: a genuinely unknown id still says so.
    #[test]
    fn an_unknown_id_still_reports_breakpoint_not_found() {
        let dbg = AppleDebugger::new(Arc::new(LoopbackFactory::new(
            MockDebugserver::with_program(4242, 0x1_0000_4000, &[0xD503_201Fu32]),
            7,
        )));
        let mut ctx = LiveScriptContext::new(
            Box::new(dbg),
            ThreadId(1),
            TypeRegistry::new(),
            OmniscientIndex::from_writes(Vec::new()),
        );
        assert!(matches!(
            ctx.remove_breakpoint(99).expect_err("no such id"),
            ScriptError::BreakpointNotFound(99)
        ));
    }
}

impl From<TypeFieldWatchError> for ScriptError {
    fn from(e: TypeFieldWatchError) -> Self {
        Self::TypeWatch(e.to_string())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Request / Response — one variant per tool-callable capability
// ─────────────────────────────────────────────────────────────────────────────

/// One tool call an LLM debugging agent can issue. Each variant is meant to
/// be exposed as an individually-named tool (e.g. `read_memory`,
/// `who_wrote`) with this variant's fields as the tool's typed arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptRequest {
    /// Read `size` bytes starting at `address`.
    ReadMemory { address: u64, size: u32 },
    /// Write `bytes` starting at `address`.
    WriteMemory { address: u64, bytes: Vec<u8> },
    /// Read a single named register.
    ReadRegister { name: String },
    /// Write a single named register.
    WriteRegister { name: String, value: u64 },
    /// Set a software breakpoint at `address`.
    SetBreakpoint { address: u64 },
    /// Remove the breakpoint with the given ID.
    RemoveBreakpoint { id: u64 },
    /// Set a type-aware data watchpoint: `type_name.field_path` at an
    /// instance base address, e.g. `type_name="Entity"`, `field_path="hp"`.
    /// This is the Tier-1 type-aware breakpoint capability exposed as a tool.
    SetTypeFieldWatchpoint {
        type_name: String,
        base_address: u64,
        field_path: String,
        watch_write: bool,
    },
    /// Look up the layout (fields + offsets) of a registered type — lets the
    /// agent discover valid `field_path` values before calling
    /// [`ScriptRequest::SetTypeFieldWatchpoint`].
    DescribeType { type_name: String },
    /// Omniscient query: every write that touched `address` at or before
    /// `at_time`, most-recent-first. The Tier-1 Pernosco-style capability.
    WhoWrote { address: u64, at_time: u64 },
    /// Omniscient query: walk the writer chain backward for `address`
    /// starting at `at_time` until a write with no known source is reached.
    TraceOrigin { address: u64, at_time: u64 },
    /// List all currently registered breakpoints.
    ListBreakpoints,
    /// Run a declarative dataflow query (see [`crate::dataflow_dsl`]), e.g.
    /// `"TRACE 0x2000 BACKWARD UNTIL PC 0x401000"` or
    /// `"FIND WRITES TO 0x3000 BEFORE 42"`. Lets an LLM agent express a
    /// backward-dataflow question as one string instead of composing
    /// `WhoWrote`/`TraceOrigin` calls by hand.
    DataflowQuery { query: String },
    /// Coredump-farm triage: cluster a batch of already-symbolicated crash
    /// dumps by stack-hash signature (top `depth` frames) and rank by
    /// frequency. See [`crate::coredump_triage`].
    TriageCrashes { dumps: Vec<CrashDump>, depth: usize },
    /// Cross-run binary diffing: correlate two builds' symbol tables by name.
    /// See [`crate::binary_diff`].
    DiffBinaries { old: Vec<crate::Symbol>, new: Vec<crate::Symbol> },
    /// Migrate a batch of breakpoint addresses from an old build to a new one
    /// via [`crate::binary_diff::migrate_breakpoints`].
    MigrateBreakpoints { addresses: Vec<u64>, old: Vec<crate::Symbol>, new: Vec<crate::Symbol> },
    /// Race-condition/concurrency replay: scan a chronological, thread-tagged
    /// memory-access trace for candidate races. See [`crate::race_detector`].
    DetectRaces { accesses: Vec<MemoryAccess> },
    /// Execution heatmap/flamegraph: bucket a TTD position-history sample
    /// (as `(sequence, offset, pc)` triples) into `num_buckets` chronological
    /// windows. See [`crate::execution_heatmap`].
    BuildHeatmap { history: Vec<(u64, u64, u64)>, num_buckets: usize },
    /// AI root-cause assistant: combine the exact causal slice for a bad
    /// value observation with a Bayesian-ranked suspect list of writer PCs,
    /// comparing a bad run's writes against a good-baseline run's writes.
    /// See [`crate::root_cause_assistant`].
    RootCause { bad_writes: Vec<MemoryWrite>, bad_address: u64, bad_time: u64, good_writes: Vec<MemoryWrite> },
    /// Cheat-aware watchpoints: classify one PC's provenance (original
    /// baselined module, tampered module, or foreign/injected code) against
    /// a set of module baselines. See [`crate::provenance_classifier`].
    ClassifyProvenance { pc: u64, modules: Vec<ModuleBaselineSpec> },
    /// Retroactive print: evaluate `expression` at every write to `address`
    /// at or before `before`, returning a timeline of rendered values.
    /// See [`crate::retroactive_print`].
    RetroPrint {
        address: u64,
        format: String,
        args: Vec<String>,
        before: Option<u64>,
    },
    /// Auto-detect and open a TTD trace at `path`, returning the detected format.
    /// See [`crate::ttd_open`].
    TtdOpen { path: String },
    /// Natural-language debugger query: translate `question` using
    /// [`crate::nl_query::translate`] and execute against the omniscient index.
    /// Requires dispatching via [`nl_query_dispatch`].
    NlQuery { question: String },
}

/// The typed result of a [`ScriptRequest`], returned by [`dispatch`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScriptResponse {
    Memory { address: u64, bytes: Vec<u8> },
    BytesWritten { address: u64, count: u32 },
    Register { name: String, value: u64 },
    RegisterWritten { name: String, value: u64 },
    BreakpointSet { id: u64, address: u64 },
    BreakpointRemoved { id: u64 },
    WatchpointSet { id: u64, address: u64, size: u8 },
    TypeDescription { type_name: String, alloc_size: u64, fields: Vec<(String, u64, u8)> },
    Writers { address: u64, writes: Vec<MemoryWrite> },
    Origin { address: u64, hops: Vec<OriginHop> },
    Breakpoints { ids: Vec<u64> },
    CrashClusters { clusters: Vec<CrashCluster> },
    BinaryDiffResult { diff: BinaryDiff },
    BreakpointMigrations { results: Vec<BreakpointMigration> },
    RaceCandidates { races: Vec<RaceCandidate> },
    Heatmap { heatmap: ExecutionHeatmap },
    RootCause { report: RootCauseReport },
    ProvenanceResult { provenance: provenance_classifier::Provenance },
    /// Result of a [`ScriptRequest::RetroPrint`] call: one entry per write to
    /// the annotated address, most-recent-first.
    ///
    /// Each tuple is `(sequence, writer_pc_or_zero, rendered_string)`.
    RetroPrintTimeline {
        address: u64,
        entries: Vec<(u64, u64, String)>,
    },
    /// Result of a [`ScriptRequest::TtdOpen`] call.
    TtdOpened { path: String, kind: String },
    /// Result of a [`ScriptRequest::NlQuery`] call.
    NlQueryResponse { question: String, result: NlQueryResult },
}

// ─────────────────────────────────────────────────────────────────────────────
// ScriptContext — backend the dispatcher calls into
// ─────────────────────────────────────────────────────────────────────────────

/// The live session surface a [`ScriptRequest`] is dispatched against.
///
/// A real implementation wires this to a [`crate::Debugger`] backend, the
/// Tier-1 `OmniscientIndex`, and a `watchpoint_engine::WatchpointEngine` +
/// `TypeRegistry`. Kept as a trait (rather than a concrete struct) so the
/// scripting layer has zero dependency on any particular backend crate.
pub trait ScriptContext {
    fn read_memory(&self, address: u64, size: u32) -> Result<Vec<u8>, ScriptError>;
    fn write_memory(&mut self, address: u64, bytes: &[u8]) -> Result<u32, ScriptError>;
    fn read_register(&self, name: &str) -> Result<u64, ScriptError>;
    fn write_register(&mut self, name: &str, value: u64) -> Result<(), ScriptError>;
    fn set_breakpoint(&mut self, address: u64) -> Result<u64, ScriptError>;
    fn remove_breakpoint(&mut self, id: u64) -> Result<(), ScriptError>;
    fn set_type_field_watchpoint(
        &mut self,
        type_name: &str,
        base_address: u64,
        field_path: &str,
        watch_write: bool,
    ) -> Result<(u64, u64, u8), ScriptError>;
    fn describe_type(&self, type_name: &str) -> Result<(u64, Vec<(String, u64, u8)>), ScriptError>;
    fn who_wrote(&self, address: u64, at_time: u64) -> Vec<MemoryWrite>;
    fn trace_origin(&self, address: u64, at_time: u64) -> Vec<OriginHop>;
    fn list_breakpoints(&self) -> Vec<u64>;
}

/// Dispatch one [`ScriptRequest`] against `ctx`, returning the matching
/// [`ScriptResponse`].
///
/// # Errors
/// Propagates whatever [`ScriptError`] the underlying [`ScriptContext`] call
/// produces.
pub fn dispatch(ctx: &mut dyn ScriptContext, req: ScriptRequest) -> Result<ScriptResponse, ScriptError> {
    match req {
        ScriptRequest::ReadMemory { address, size } => {
            let bytes = ctx.read_memory(address, size)?;
            Ok(ScriptResponse::Memory { address, bytes })
        }
        ScriptRequest::WriteMemory { address, bytes } => {
            let count = ctx.write_memory(address, &bytes)?;
            Ok(ScriptResponse::BytesWritten { address, count })
        }
        ScriptRequest::ReadRegister { name } => {
            let value = ctx.read_register(&name)?;
            Ok(ScriptResponse::Register { name, value })
        }
        ScriptRequest::WriteRegister { name, value } => {
            ctx.write_register(&name, value)?;
            Ok(ScriptResponse::RegisterWritten { name, value })
        }
        ScriptRequest::SetBreakpoint { address } => {
            let id = ctx.set_breakpoint(address)?;
            Ok(ScriptResponse::BreakpointSet { id, address })
        }
        ScriptRequest::RemoveBreakpoint { id } => {
            ctx.remove_breakpoint(id)?;
            Ok(ScriptResponse::BreakpointRemoved { id })
        }
        ScriptRequest::SetTypeFieldWatchpoint { type_name, base_address, field_path, watch_write } => {
            let (id, address, size) = ctx.set_type_field_watchpoint(&type_name, base_address, &field_path, watch_write)?;
            Ok(ScriptResponse::WatchpointSet { id, address, size })
        }
        ScriptRequest::DescribeType { type_name } => {
            let (alloc_size, fields) = ctx.describe_type(&type_name)?;
            Ok(ScriptResponse::TypeDescription { type_name, alloc_size, fields })
        }
        ScriptRequest::WhoWrote { address, at_time } => {
            Ok(ScriptResponse::Writers { address, writes: ctx.who_wrote(address, at_time) })
        }
        ScriptRequest::TraceOrigin { address, at_time } => {
            Ok(ScriptResponse::Origin { address, hops: ctx.trace_origin(address, at_time) })
        }
        ScriptRequest::ListBreakpoints => Ok(ScriptResponse::Breakpoints { ids: ctx.list_breakpoints() }),
        ScriptRequest::DataflowQuery { query } => {
            let cmd = crate::dataflow_dsl::parse(&query).map_err(|e| ScriptError::DataflowQuery(e.to_string()))?;
            match cmd {
                crate::dataflow_dsl::DslCommand::FindWrites { address, before } => {
                    let address = address.as_u64();
                    Ok(ScriptResponse::Writers { address, writes: ctx.who_wrote(address, before) })
                }
                crate::dataflow_dsl::DslCommand::TraceBackward { address, at_time, until_pc } => {
                    let address = address.as_u64();
                    let mut hops = ctx.trace_origin(address, at_time);
                    if let Some(pc) = until_pc
                        && let Some(cut) = hops.iter().position(|h| h.write.writer_pc == Some(pc)) {
                            hops.truncate(cut + 1);
                        }
                    Ok(ScriptResponse::Origin { address, hops })
                }
            }
        }
        ScriptRequest::TriageCrashes { dumps, depth } => {
            Ok(ScriptResponse::CrashClusters { clusters: coredump_triage::triage(&dumps, depth) })
        }
        ScriptRequest::DiffBinaries { old, new } => {
            Ok(ScriptResponse::BinaryDiffResult { diff: binary_diff::diff_binaries(&old, &new) })
        }
        ScriptRequest::MigrateBreakpoints { addresses, old, new } => {
            let addrs: Vec<rustre_core::address::Address> = addresses.into_iter().map(rustre_core::address::Address).collect();
            Ok(ScriptResponse::BreakpointMigrations { results: binary_diff::migrate_breakpoints(&addrs, &old, &new) })
        }
        ScriptRequest::DetectRaces { accesses } => {
            Ok(ScriptResponse::RaceCandidates { races: race_detector::detect_races(&accesses) })
        }
        ScriptRequest::BuildHeatmap { history, num_buckets } => {
            let history: Vec<(TracePosition, u64)> =
                history.into_iter().map(|(seq, off, pc)| (TracePosition::new(seq, off), pc)).collect();
            Ok(ScriptResponse::Heatmap { heatmap: ExecutionHeatmap::from_ttd_history(&history, num_buckets) })
        }
        ScriptRequest::RootCause { bad_writes, bad_address, bad_time, good_writes } => {
            let bad_index = OmniscientIndex::from_writes(bad_writes);
            let good_index = OmniscientIndex::from_writes(good_writes);
            let report = root_cause_assistant::root_cause(
                &bad_index,
                rustre_core::address::Address(bad_address),
                bad_time,
                &good_index,
            );
            Ok(ScriptResponse::RootCause { report })
        }
        ScriptRequest::ClassifyProvenance { pc, modules } => {
            let provenance = provenance_classifier::classify_from_specs(rustre_core::address::Address(pc), &modules);
            Ok(ScriptResponse::ProvenanceResult { provenance })
        }
        ScriptRequest::RetroPrint { .. } => {
            // RetroPrint requires direct access to OmniscientIndex and
            // SnapshotReplayBackend, which are outside the ScriptContext trait.
            // Use `retro_print_dispatch` instead, which takes those directly.
            Err(ScriptError::Unsupported(
                "RetroPrint must be dispatched via retro_print_dispatch(), not dispatch()".into(),
            ))
        }
        ScriptRequest::TtdOpen { .. } => {
            // TtdOpen doesn't need a ScriptContext; use `ttd_open_dispatch`.
            Err(ScriptError::Unsupported(
                "TtdOpen must be dispatched via ttd_open_dispatch(), not dispatch()".into(),
            ))
        }
        ScriptRequest::NlQuery { .. } => {
            // NlQuery needs an OmniscientIndex; use `nl_query_dispatch`.
            Err(ScriptError::Unsupported(
                "NlQuery must be dispatched via nl_query_dispatch(), not dispatch()".into(),
            ))
        }
    }
}

/// Dispatch a [`ScriptRequest::RetroPrint`] against the given index and replay
/// backend, returning a [`ScriptResponse::RetroPrintTimeline`].
///
/// # Errors
///
/// Returns [`ScriptError::Unsupported`] if `req` is not a `RetroPrint` variant.
pub fn retro_print_dispatch(
    index: &crate::omniscient_query::OmniscientIndex,
    replay: &crate::time_travel_debug::SnapshotReplayBackend,
    req: ScriptRequest,
) -> Result<ScriptResponse, ScriptError> {
    let ScriptRequest::RetroPrint { address, format, args, before } = req else {
        return Err(ScriptError::Unsupported("retro_print_dispatch requires RetroPrint variant".into()));
    };
    let ann = crate::retroactive_print::RetroAnnotation { address, format, args };
    let before_seq = before.unwrap_or(u64::MAX);
    let entries = crate::retroactive_print::retro_print(index, replay, &ann, before_seq);
    let result = entries.into_iter().map(|e| {
        let seq = e.write.sequence;
        let pc  = e.writer_pc.unwrap_or(0);
        (seq, pc, e.rendered)
    }).collect();
    Ok(ScriptResponse::RetroPrintTimeline { address: ann.address, entries: result })
}

/// Dispatch a [`ScriptRequest::TtdOpen`] by detecting the trace format at the
/// given path and attempting to open it.
///
/// # Errors
///
/// Returns [`ScriptError::Unsupported`] if `req` is not a `TtdOpen` variant,
/// or [`ScriptError::Unsupported`] with a description if the path is not a
/// recognised trace format or opening fails.
pub fn ttd_open_dispatch(req: ScriptRequest) -> Result<ScriptResponse, ScriptError> {
    let ScriptRequest::TtdOpen { path } = req else {
        return Err(ScriptError::Unsupported("ttd_open_dispatch requires TtdOpen variant".into()));
    };
    let p = std::path::Path::new(&path);
    let kind_str = match crate::ttd_open::detect_trace_kind(p) {
        Some(crate::ttd_open::TraceKind::WinDbgTtd) => "WinDbgTtd",
        Some(crate::ttd_open::TraceKind::Rr)        => "Rr",
        None => return Err(ScriptError::Unsupported(format!("unrecognised trace format at: {path}"))),
    };
    // Attempt to open the trace; propagate backend errors as Unsupported.
    crate::ttd_open::open_trace(p)
        .map_err(|e| ScriptError::Unsupported(e.to_string()))?;
    Ok(ScriptResponse::TtdOpened { path, kind: kind_str.to_string() })
}

/// Dispatch a [`ScriptRequest::NlQuery`] against the given omniscient index:
/// translate the natural-language question and execute it.
///
/// # Errors
///
/// Returns [`ScriptError::Unsupported`] if `req` is not an `NlQuery` variant,
/// or [`ScriptError::DataflowQuery`] if translation fails.
pub fn nl_query_dispatch(
    index: &crate::omniscient_query::OmniscientIndex,
    req: ScriptRequest,
) -> Result<ScriptResponse, ScriptError> {
    let ScriptRequest::NlQuery { question } = req else {
        return Err(ScriptError::Unsupported("nl_query_dispatch requires NlQuery variant".into()));
    };
    let query = nl_query::translate(&question)
        .map_err(|e| ScriptError::DataflowQuery(e.to_string()))?;
    let result = nl_query::execute(&query, index);
    Ok(ScriptResponse::NlQueryResponse { question, result })
}

// ─────────────────────────────────────────────────────────────────────────────
// MockScriptContext — in-memory test double
// ─────────────────────────────────────────────────────────────────────────────

/// A minimal in-memory [`ScriptContext`] for **tests only**.
///
/// # Never use this to answer a caller
///
/// Every read it serves comes from its own `HashMap`s, and a `ScriptResponse`
/// built from them is byte-identical to one built from a live process. It has
/// no `live` flag and no provenance, so once serialised there is nothing for a
/// caller to check.
///
/// It cannot be `#[cfg(test)]`: integration tests in `tests/` are separate
/// crates and cannot see a cfg-gated item. What keeps it honest instead is the
/// guard `no_production_code_constructs_a_mock_or_fake_backend` in `lib.rs`,
/// which fails the build if any shipping source in `src/` constructs one. The
/// earlier wording here ("for prototyping tool schemas before a real backend is
/// wired in") invited exactly the use the guard now forbids.
///
/// For a real target use [`crate::live_script_context::LiveScriptContext`].
#[derive(Debug, Default)]
pub struct MockScriptContext {
    pub memory: HashMap<u64, Vec<u8>>,
    pub registers: HashMap<String, u64>,
    pub breakpoints: HashMap<u64, u64>, // id -> address
    next_bp_id: u64,
    pub writes: Vec<MemoryWrite>,
    pub types: HashMap<String, (u64, Vec<(String, u64, u8)>)>, // name -> (alloc_size, fields)
}

impl MockScriptContext {
    #[must_use]
    pub fn new() -> Self {
        Self { next_bp_id: 1, ..Self::default() }
    }
}

impl ScriptContext for MockScriptContext {
    fn read_memory(&self, address: u64, size: u32) -> Result<Vec<u8>, ScriptError> {
        let bytes = self.memory.get(&address).ok_or(ScriptError::MemoryRead(address))?;
        let size = size as usize;
        if bytes.len() < size {
            return Err(ScriptError::MemoryRead(address));
        }
        Ok(bytes[..size].to_vec())
    }

    fn write_memory(&mut self, address: u64, bytes: &[u8]) -> Result<u32, ScriptError> {
        self.memory.insert(address, bytes.to_vec());
        Ok(u32::try_from(bytes.len()).unwrap_or(u32::MAX))
    }

    fn read_register(&self, name: &str) -> Result<u64, ScriptError> {
        self.registers.get(name).copied().ok_or_else(|| ScriptError::UnknownRegister(name.to_owned()))
    }

    fn write_register(&mut self, name: &str, value: u64) -> Result<(), ScriptError> {
        self.registers.insert(name.to_owned(), value);
        Ok(())
    }

    fn set_breakpoint(&mut self, address: u64) -> Result<u64, ScriptError> {
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        self.breakpoints.insert(id, address);
        Ok(id)
    }

    fn remove_breakpoint(&mut self, id: u64) -> Result<(), ScriptError> {
        self.breakpoints.remove(&id).map(|_| ()).ok_or(ScriptError::BreakpointNotFound(id))
    }

    fn set_type_field_watchpoint(
        &mut self,
        type_name: &str,
        base_address: u64,
        field_path: &str,
        _watch_write: bool,
    ) -> Result<(u64, u64, u8), ScriptError> {
        let (_, fields) = self.types.get(type_name)
            .ok_or_else(|| ScriptError::TypeWatch(format!("unknown type: {type_name}")))?;
        let (_, offset, size) = fields.iter().find(|(n, _, _)| n == field_path)
            .ok_or_else(|| ScriptError::TypeWatch(format!("unknown field '{field_path}' on '{type_name}'")))?;
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        let address = base_address.saturating_add(*offset);
        self.breakpoints.insert(id, address);
        Ok((id, address, *size))
    }

    fn describe_type(&self, type_name: &str) -> Result<(u64, Vec<(String, u64, u8)>), ScriptError> {
        self.types.get(type_name).cloned()
            .ok_or_else(|| ScriptError::TypeWatch(format!("unknown type: {type_name}")))
    }

    fn who_wrote(&self, address: u64, at_time: u64) -> Vec<MemoryWrite> {
        self.writes.iter().filter(|w| w.sequence <= at_time && w.address.as_u64() == address).cloned().collect()
    }

    fn trace_origin(&self, _address: u64, _at_time: u64) -> Vec<OriginHop> {
        Vec::new()
    }

    fn list_breakpoints(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self.breakpoints.keys().copied().collect();
        ids.sort_unstable();
        ids
    }
}

/// Convenience: map a [`bool`] "watch on write" flag to a
/// [`WatchpointType`], for callers building a
/// [`ScriptRequest::SetTypeFieldWatchpoint`] response from a real engine.
#[must_use]
pub const fn watch_type_for(watch_write: bool) -> WatchpointType {
    if watch_write { WatchpointType::Write } else { WatchpointType::Read }
}

// ─────────────────────────────────────────────────────────────────────────────
// LiveScriptContext — binds a real `Box<dyn Debugger>` session to the API
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal executor: drive a future to completion on the current thread by
/// park/unpark, touching no async runtime.
///
/// This is sound for the concrete backends (`WindowsDebugger`/`LinuxDebugger`)
/// because each of their `async fn`s is a thin wrapper over a synchronous,
/// blocking `std::sync::mpsc` `recv()` — the future resolves to `Ready` on its
/// first `poll`, needing no tokio reactor/timer. It therefore works whether or
/// not the caller is already inside a tokio runtime (nesting `Runtime::block_on`
/// would panic; this does not), which matters because the MCP surface dispatches
/// these calls from an async context.
pub fn block_on<F: core::future::Future>(mut fut: F) -> F::Output {
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE)
    }
    fn wake(p: *const ()) {
        // SAFETY: `p` is the `&Thread` we passed into the waker below.
        unsafe { (*p.cast::<std::thread::Thread>()).unpark() }
    }
    fn wake_by_ref(p: *const ()) {
        // SAFETY: as above.
        unsafe { (*p.cast::<std::thread::Thread>()).unpark() }
    }
    const fn drop_(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop_);

    let handle = std::thread::current();
    let raw = RawWaker::new(std::ptr::addr_of!(handle).cast(), &VTABLE);
    // SAFETY: `handle` outlives the waker (both live to the end of this fn),
    // and the vtable functions only ever call `Thread::unpark`, which is safe
    // to invoke from any thread.
    let waker = unsafe { Waker::from_raw(raw) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` is never moved after being pinned here.
    let mut fut = unsafe { core::pin::Pin::new_unchecked(&mut fut) };
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::park(),
        }
    }
}

/// A live [`ScriptContext`] backed by a real [`crate::Debugger`] session.
///
/// Bridges the synchronous, LLM-tool-call-shaped scripting surface to the
/// async [`crate::Debugger`] trait (via [`block_on`]), and folds in the two
/// non-debugger data sources the scripting contract also exposes:
/// - a [`TypeRegistry`] for [`ScriptContext::describe_type`] /
///   [`ScriptContext::set_type_field_watchpoint`] (offset/size resolution), and
/// - an [`crate::omniscient_query::OmniscientIndex`] for [`ScriptContext::who_wrote`] /
///   [`ScriptContext::trace_origin`] (backward-dataflow queries over a recorded
///   session), since a live process has no retroactive write history of its own.
///
/// Register/backtrace operations act on `tid`, the thread the session is
/// currently stopped on; update it via [`LiveScriptContext::set_thread`] when a
/// debug event reports a different stopping thread.
pub struct LiveScriptContext {
    dbg: Box<dyn crate::Debugger>,
    tid: crate::ThreadId,
    types: TypeRegistry,
    omni: OmniscientIndex,
    /// Scripting breakpoint id → live breakpoint address. The `Debugger` trait
    /// keys breakpoints by address; the scripting API hands out opaque `u64`
    /// ids, so this maps between them.
    bp_ids: HashMap<u64, rustre_core::address::Address>,
    next_bp_id: u64,
}

impl LiveScriptContext {
    /// Bind a live debugger session, currently stopped on `tid`.
    ///
    /// `types` and `omni` may be empty ([`TypeRegistry::new`] /
    /// [`OmniscientIndex::from_writes(Vec::new())`](OmniscientIndex::from_writes)):
    /// memory/register/breakpoint calls work without them; only the type-aware
    /// and omniscient-query calls need them populated.
    #[must_use]
    pub fn new(
        dbg: Box<dyn crate::Debugger>,
        tid: crate::ThreadId,
        types: TypeRegistry,
        omni: OmniscientIndex,
    ) -> Self {
        Self { dbg, tid, types, omni, bp_ids: HashMap::new(), next_bp_id: 1 }
    }

    /// Update the thread that register/backtrace calls act on (e.g. after a
    /// debug event reports a new stopping thread).
    pub const fn set_thread(&mut self, tid: crate::ThreadId) {
        self.tid = tid;
    }

    /// The thread register/backtrace calls currently act on.
    #[must_use]
    pub const fn thread(&self) -> crate::ThreadId {
        self.tid
    }
}

impl ScriptContext for LiveScriptContext {
    fn read_memory(&self, address: u64, size: u32) -> Result<Vec<u8>, ScriptError> {
        block_on(self.dbg.read_memory(rustre_core::address::Address(address), size as usize))
            .map_err(|e| script_error_from(&e, address))
    }

    fn write_memory(&mut self, address: u64, bytes: &[u8]) -> Result<u32, ScriptError> {
        let n = block_on(self.dbg.write_memory(rustre_core::address::Address(address), bytes))
            .map_err(|e| script_error_from(&e, address))?;
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }

    fn read_register(&self, name: &str) -> Result<u64, ScriptError> {
        // NOT a blanket `UnknownRegister`. Unlike the sibling context this one
        // has no `current_tid` guard in front, so a detached session reaches the
        // backend and came back as "unknown register: pc" — sending the caller
        // to hunt a typo in a name that is spelled correctly, instead of
        // attaching. The backend has no distinct error for a bad NAME; when the
        // name really is wrong it says so in its own message, which
        // `script_error_from` carries through.
        block_on(self.dbg.get_register(self.tid, name))
            .map_err(|e| script_error_from(&e, 0))
    }

    fn write_register(&mut self, name: &str, value: u64) -> Result<(), ScriptError> {
        block_on(self.dbg.set_register(self.tid, name, value))
            .map_err(|e| script_error_from(&e, 0))
    }

    fn set_breakpoint(&mut self, address: u64) -> Result<u64, ScriptError> {
        let addr = rustre_core::address::Address(address);
        block_on(self.dbg.set_breakpoint(addr, crate::BreakpointKind::Software))
            .map_err(|e| script_error_from(&e, address))?;
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        self.bp_ids.insert(id, addr);
        Ok(id)
    }

    fn remove_breakpoint(&mut self, id: u64) -> Result<(), ScriptError> {
        let addr = *self.bp_ids.get(&id).ok_or(ScriptError::BreakpointNotFound(id))?;
        // NOT a blanket `BreakpointNotFound`: see `script_error_from`. The
        // breakpoint is still installed when the removal fails, and saying it
        // is missing is the one answer that makes a caller stop looking.
        block_on(self.dbg.remove_breakpoint(addr))
            .map_err(|e| script_error_from(&e, id))?;
        self.bp_ids.remove(&id);
        Ok(())
    }

    fn set_type_field_watchpoint(
        &mut self,
        type_name: &str,
        base_address: u64,
        field_path: &str,
        watch_write: bool,
    ) -> Result<(u64, u64, u8), ScriptError> {
        let (address, size) = crate::watchpoint_engine::resolve_field_address(
            &self.types, type_name, base_address, field_path,
        )
        .map_err(|e| ScriptError::TypeWatch(e.to_string()))?;
        // A field watchpoint is realized as a hardware data breakpoint at the
        // resolved absolute address; fall back to Software if hardware is
        // unavailable, mirroring the trait's breakpoint model.
        // A watchpoint planted through the `Debugger` trait carries no width:
        // `BreakpointKind` has no size field, so each backend picks one (the
        // Apple backend hard-codes 8 bytes in `z_kind_for`). For a field NARROWER
        // than that the effect is a false positive — a write to the neighbouring
        // field reports this one as changed — which is at least visible. For a
        // field WIDER than that the effect is a false NEGATIVE: the tail of the
        // field is not watched at all and a write there is silently missed, with
        // nothing to notice. Refuse that case rather than hand back a size this
        // layer does not honour.
        if u64::from(size) > MAX_TRAIT_WATCHPOINT_BYTES {
            return Err(ScriptError::Unsupported(format!(
                "field '{field_path}' of '{type_name}' is {size} bytes, but a watchpoint set                  through the Debugger trait covers at most {MAX_TRAIT_WATCHPOINT_BYTES}; the                  tail of the field would not be watched and writes to it would be missed                  silently"
            )));
        }
        let kind = if watch_write {
            crate::BreakpointKind::DataWrite
        } else {
            crate::BreakpointKind::DataReadWrite
        };
        let addr = rustre_core::address::Address(address);
        // The resolved field width is passed through, so the watchpoint covers
        // the field and nothing else. `set_breakpoint` carries no width and left
        // the region to the backend.
        block_on(self.dbg.set_watchpoint_sized(addr, kind, size))
            .map_err(|e| ScriptError::TypeWatch(e.to_string()))?;
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        self.bp_ids.insert(id, addr);
        Ok((id, address, size))
    }

    fn describe_type(&self, type_name: &str) -> Result<(u64, Vec<(String, u64, u8)>), ScriptError> {
        let layout = self.types.get(type_name)
            .ok_or_else(|| ScriptError::TypeWatch(format!("unknown type: {type_name}")))?;
        let mut fields: Vec<(String, u64, u8)> = layout.fields.iter()
            .map(|(name, f)| (name.clone(), f.offset, f.size))
            .collect();
        fields.sort_by_key(|(_, offset, _)| *offset);
        Ok((layout.alloc_size, fields))
    }

    fn who_wrote(&self, address: u64, at_time: u64) -> Vec<MemoryWrite> {
        self.omni
            .who_wrote(rustre_core::address::Address(address), at_time)
            .into_iter()
            .cloned()
            .collect()
    }

    fn trace_origin(&self, address: u64, at_time: u64) -> Vec<OriginHop> {
        self.omni.trace_origin(rustre_core::address::Address(address), at_time)
    }

    fn list_breakpoints(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self.bp_ids.keys().copied().collect();
        ids.sort_unstable();
        ids
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;
    use crate::ThreadId;

    #[test]
    fn read_write_memory_round_trip() {
        let mut ctx = MockScriptContext::new();
        dispatch(&mut ctx, ScriptRequest::WriteMemory { address: 0x1000, bytes: vec![1, 2, 3, 4] }).unwrap();
        let resp = dispatch(&mut ctx, ScriptRequest::ReadMemory { address: 0x1000, size: 4 }).unwrap();
        assert_eq!(resp, ScriptResponse::Memory { address: 0x1000, bytes: vec![1, 2, 3, 4] });
    }

    #[test]
    fn read_memory_unmapped_errors() {
        let mut ctx = MockScriptContext::new();
        let err = dispatch(&mut ctx, ScriptRequest::ReadMemory { address: 0x9999, size: 4 }).unwrap_err();
        assert_eq!(err, ScriptError::MemoryRead(0x9999));
    }

    #[test]
    fn register_round_trip() {
        let mut ctx = MockScriptContext::new();
        dispatch(&mut ctx, ScriptRequest::WriteRegister { name: "rax".into(), value: 0xdead }).unwrap();
        let resp = dispatch(&mut ctx, ScriptRequest::ReadRegister { name: "rax".into() }).unwrap();
        assert_eq!(resp, ScriptResponse::Register { name: "rax".into(), value: 0xdead });
    }

    #[test]
    fn unknown_register_errors() {
        let mut ctx = MockScriptContext::new();
        let err = dispatch(&mut ctx, ScriptRequest::ReadRegister { name: "nope".into() }).unwrap_err();
        assert_eq!(err, ScriptError::UnknownRegister("nope".into()));
    }

    #[test]
    fn breakpoint_lifecycle() {
        let mut ctx = MockScriptContext::new();
        let resp = dispatch(&mut ctx, ScriptRequest::SetBreakpoint { address: 0x0040_1000 }).unwrap();
        let ScriptResponse::BreakpointSet { id, address } = resp else { panic!("wrong variant") };
        assert_eq!(address, 0x0040_1000);

        let list = dispatch(&mut ctx, ScriptRequest::ListBreakpoints).unwrap();
        assert_eq!(list, ScriptResponse::Breakpoints { ids: vec![id] });

        dispatch(&mut ctx, ScriptRequest::RemoveBreakpoint { id }).unwrap();
        let list = dispatch(&mut ctx, ScriptRequest::ListBreakpoints).unwrap();
        assert_eq!(list, ScriptResponse::Breakpoints { ids: vec![] });
    }

    #[test]
    fn remove_unknown_breakpoint_errors() {
        let mut ctx = MockScriptContext::new();
        let err = dispatch(&mut ctx, ScriptRequest::RemoveBreakpoint { id: 999 }).unwrap_err();
        assert_eq!(err, ScriptError::BreakpointNotFound(999));
    }

    #[test]
    fn describe_type_and_set_type_field_watchpoint() {
        let mut ctx = MockScriptContext::new();
        ctx.types.insert("Entity".into(), (20, vec![("hp".into(), 16, 4)]));

        let desc = dispatch(&mut ctx, ScriptRequest::DescribeType { type_name: "Entity".into() }).unwrap();
        assert_eq!(desc, ScriptResponse::TypeDescription {
            type_name: "Entity".into(), alloc_size: 20, fields: vec![("hp".into(), 16, 4)],
        });

        let resp = dispatch(&mut ctx, ScriptRequest::SetTypeFieldWatchpoint {
            type_name: "Entity".into(), base_address: 0x2000, field_path: "hp".into(), watch_write: true,
        }).unwrap();
        assert_eq!(resp, ScriptResponse::WatchpointSet { id: 1, address: 0x2010, size: 4 });
    }

    #[test]
    fn set_type_field_watchpoint_unknown_type_errors() {
        let mut ctx = MockScriptContext::new();
        let err = dispatch(&mut ctx, ScriptRequest::SetTypeFieldWatchpoint {
            type_name: "Ghost".into(), base_address: 0, field_path: "x".into(), watch_write: true,
        }).unwrap_err();
        assert!(matches!(err, ScriptError::TypeWatch(_)));
    }

    #[test]
    fn who_wrote_via_dispatch() {
        let mut ctx = MockScriptContext::new();
        ctx.writes.push(MemoryWrite {
            sequence: 3,
            address: Address::new(0x1000),
            size: 8,
            tid: ThreadId(1),
            writer_pc: Some(Address::new(0x0040_1000)),
            source_address: None,
        });
        let resp = dispatch(&mut ctx, ScriptRequest::WhoWrote { address: 0x1000, at_time: 100 }).unwrap();
        let ScriptResponse::Writers { writes, .. } = resp else { panic!("wrong variant") };
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].sequence, 3);
    }

    #[test]
    fn dataflow_query_find_writes_via_dispatch() {
        let mut ctx = MockScriptContext::new();
        ctx.writes.push(MemoryWrite {
            sequence: 3,
            address: Address::new(0x1000),
            size: 8,
            tid: ThreadId(1),
            writer_pc: Some(Address::new(0x0040_1000)),
            source_address: None,
        });
        let resp = dispatch(&mut ctx, ScriptRequest::DataflowQuery { query: "FIND WRITES TO 0x1000 BEFORE 100".into() }).unwrap();
        let ScriptResponse::Writers { writes, address } = resp else { panic!("wrong variant") };
        assert_eq!(address, 0x1000);
        assert_eq!(writes.len(), 1);
    }

    #[test]
    fn dataflow_query_invalid_syntax_errors() {
        let mut ctx = MockScriptContext::new();
        let err = dispatch(&mut ctx, ScriptRequest::DataflowQuery { query: "BOGUS QUERY".into() }).unwrap_err();
        assert!(matches!(err, ScriptError::DataflowQuery(_)));
    }

    #[test]
    fn trace_origin_via_dispatch_empty_by_default() {
        let mut ctx = MockScriptContext::new();
        let resp = dispatch(&mut ctx, ScriptRequest::TraceOrigin { address: 0x1000, at_time: 100 }).unwrap();
        assert_eq!(resp, ScriptResponse::Origin { address: 0x1000, hops: vec![] });
    }

    #[test]
    fn watch_type_for_maps_bool_flag() {
        assert!(matches!(watch_type_for(true), WatchpointType::Write));
        assert!(matches!(watch_type_for(false), WatchpointType::Read));
    }

    #[test]
    fn requests_serialize_round_trip_json() {
        let req = ScriptRequest::WhoWrote { address: 0x1000, at_time: 42 };
        let json = serde_json::to_string(&req).unwrap();
        let back: ScriptRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    fn frame(pc: u64, name: Option<&str>) -> crate::StackFrame {
        crate::StackFrame {
            index: 0, pc: Address(pc), sp: Address(0), fp: None,
            function_name: name.map(String::from), module: None, offset: None,
            source_file: None, source_line: None,
        }
    }

    #[test]
    fn triage_crashes_via_dispatch() {
        let mut ctx = MockScriptContext::new();
        let dumps = vec![
            CrashDump { id: "a".into(), frames: vec![frame(0x1000, Some("boom"))], signal: Some(11) },
            CrashDump { id: "b".into(), frames: vec![frame(0x1000, Some("boom"))], signal: Some(11) },
        ];
        let resp = dispatch(&mut ctx, ScriptRequest::TriageCrashes { dumps, depth: 1 }).unwrap();
        let ScriptResponse::CrashClusters { clusters } = resp else { panic!("wrong variant") };
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].count(), 2);
    }

    #[test]
    fn diff_binaries_via_dispatch() {
        let mut ctx = MockScriptContext::new();
        let old = vec![crate::Symbol::new("f", 0x1000)];
        let new = vec![crate::Symbol::new("f", 0x2000)];
        let resp = dispatch(&mut ctx, ScriptRequest::DiffBinaries { old, new }).unwrap();
        let ScriptResponse::BinaryDiffResult { diff } = resp else { panic!("wrong variant") };
        assert_eq!(diff.moved.len(), 1);
    }

    #[test]
    fn migrate_breakpoints_via_dispatch() {
        let mut ctx = MockScriptContext::new();
        let mut old_sym = crate::Symbol::new("f", 0x1000);
        old_sym.size = 0x10;
        let mut new_sym = crate::Symbol::new("f", 0x5000);
        new_sym.size = 0x10;
        let resp = dispatch(&mut ctx, ScriptRequest::MigrateBreakpoints {
            addresses: vec![0x1004], old: vec![old_sym], new: vec![new_sym],
        }).unwrap();
        let ScriptResponse::BreakpointMigrations { results } = resp else { panic!("wrong variant") };
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], crate::binary_diff::BreakpointMigration::Migrated { .. }));
    }

    #[test]
    fn detect_races_via_dispatch() {
        let mut ctx = MockScriptContext::new();
        let accesses = vec![
            MemoryAccess { sequence: 0, address: Address(0x1000), size: 4, tid: ThreadId(1), kind: crate::race_detector::AccessKind::Write },
            MemoryAccess { sequence: 1, address: Address(0x1000), size: 4, tid: ThreadId(2), kind: crate::race_detector::AccessKind::Write },
        ];
        let resp = dispatch(&mut ctx, ScriptRequest::DetectRaces { accesses }).unwrap();
        let ScriptResponse::RaceCandidates { races } = resp else { panic!("wrong variant") };
        assert_eq!(races.len(), 1);
    }

    #[test]
    fn build_heatmap_via_dispatch() {
        let mut ctx = MockScriptContext::new();
        let history = vec![(0, 0, 0xA), (5, 0, 0xB)];
        let resp = dispatch(&mut ctx, ScriptRequest::BuildHeatmap { history, num_buckets: 2 }).unwrap();
        let ScriptResponse::Heatmap { heatmap } = resp else { panic!("wrong variant") };
        assert_eq!(heatmap.total_hits(), 2);
    }

    #[test]
    fn root_cause_via_dispatch() {
        let mut ctx = MockScriptContext::new();
        let bad_writes = vec![MemoryWrite {
            sequence: 0, address: Address(0x1000), size: 4, tid: ThreadId(1),
            writer_pc: Some(Address(0x100)), source_address: None,
        }];
        let resp = dispatch(&mut ctx, ScriptRequest::RootCause {
            bad_writes, bad_address: 0x1000, bad_time: 10, good_writes: vec![],
        }).unwrap();
        let ScriptResponse::RootCause { report } = resp else { panic!("wrong variant") };
        assert!(report.top_suspect().is_some());
    }

    /// Cross-cutting scenario: build a synthetic trace with writes to address X,
    /// set a `retroactive_print` annotation via `retro_print_dispatch`, then ask
    /// `nl_query_dispatch` "who wrote to X" — verify the NL result cites the
    /// same writes that the `retro_print` annotation observed.
    #[test]
    fn nl_query_and_retro_print_cross_scenario() {
        use crate::nl_query::NlQueryResult;
        use crate::ThreadId;
        use crate::omniscient_query::MemoryWrite;
        use crate::time_travel_debug::{SnapshotReplayBackend, TtdState, TracePosition};
        use rustre_core::address::Address;

        const ADDR: u64 = 0x4000;

        // --- Build a synthetic trace ---
        let index = OmniscientIndex::from_writes(vec![
            MemoryWrite { sequence: 3, address: Address(ADDR), size: 8,
                          tid: ThreadId(1), writer_pc: Some(Address(0x0040_1000)), source_address: None },
            MemoryWrite { sequence: 7, address: Address(ADDR), size: 8,
                          tid: ThreadId(1), writer_pc: Some(Address(0x0040_1010)), source_address: None },
        ]);

        // --- retroactive_print: annotate address ADDR, render rax at each write ---
        let mut replay = SnapshotReplayBackend::new();
        let mut st3 = TtdState::new(TracePosition::new(3, 0), 0x0040_1000, 0x7000);
        st3.regs.insert("rax".into(), 0xAA);
        let mut st7 = TtdState::new(TracePosition::new(7, 0), 0x0040_1010, 0x7000);
        st7.regs.insert("rax".into(), 0xBB);
        replay.record(st3);
        replay.record(st7);

        let ann = crate::retroactive_print::RetroAnnotation {
            address: ADDR,
            format: "rax={0}".into(),
            args: vec!["rax".into()],
        };
        let retro_resp = retro_print_dispatch(
            &index,
            &replay,
            ScriptRequest::RetroPrint { address: ADDR, format: ann.format.clone(), args: ann.args, before: None },
        ).unwrap();

        // The retro_print timeline must cover both writes (most-recent first).
        let ScriptResponse::RetroPrintTimeline { entries, .. } = retro_resp else {
            panic!("expected RetroPrintTimeline");
        };
        assert_eq!(entries.len(), 2, "retro_print must see both writes");
        assert_eq!(entries[0].0, 7, "most-recent write is seq 7");
        assert_eq!(entries[1].0, 3);
        assert!(entries[0].2.contains("0xbb"), "rendered value for seq 7: {}", entries[0].2);
        assert!(entries[1].2.contains("0xaa"), "rendered value for seq 3: {}", entries[1].2);

        // --- nl_query: "who wrote to ADDR" must surface the same two writes ---
        let nl_resp = nl_query_dispatch(
            &index,
            ScriptRequest::NlQuery { question: format!("who wrote to {ADDR:#x}") },
        ).unwrap();

        let ScriptResponse::NlQueryResponse { result, .. } = nl_resp else {
            panic!("expected NlQueryResponse");
        };
        let NlQueryResult::Writes { address: _, writes, explanation } = result else {
            panic!("expected Writes result from NL query");
        };
        assert_eq!(writes.len(), 2, "nl_query must find both writes to {ADDR:#x}; explanation: {explanation}");
        // Both writes are for address ADDR.
        assert!(writes.iter().all(|w| w.address.0 == ADDR));
    }

    #[test]
    fn classify_provenance_via_dispatch() {
        let mut ctx = MockScriptContext::new();
        let modules = vec![ModuleBaselineSpec { name: "game.exe".into(), start: 0x1000, end: 0x2000, hash_checks: vec![] }];
        let resp = dispatch(&mut ctx, ScriptRequest::ClassifyProvenance { pc: 0x1500, modules }).unwrap();
        let ScriptResponse::ProvenanceResult { provenance } = resp else { panic!("wrong variant") };
        // No hash checks were supplied, so containment is all that is known:
        // Unverified, not Original (iter 464).
        assert_eq!(provenance, provenance_classifier::Provenance::Unverified { module: "game.exe".into() });
    }

    /// Exhaustively matches every [`ScriptRequest`] variant so this test fails
    /// to *compile* (not just fails at runtime) the moment a new variant is
    /// added without a corresponding entry here — the surest way to keep this
    /// completeness check from silently going stale as the API grows.
    fn one_of_every_request() -> Vec<ScriptRequest> {
        fn exhaustiveness_guard(req: &ScriptRequest) {
            match req {
                ScriptRequest::ReadMemory { .. }
                | ScriptRequest::WriteMemory { .. }
                | ScriptRequest::ReadRegister { .. }
                | ScriptRequest::WriteRegister { .. }
                | ScriptRequest::SetBreakpoint { .. }
                | ScriptRequest::RemoveBreakpoint { .. }
                | ScriptRequest::SetTypeFieldWatchpoint { .. }
                | ScriptRequest::DescribeType { .. }
                | ScriptRequest::WhoWrote { .. }
                | ScriptRequest::TraceOrigin { .. }
                | ScriptRequest::ListBreakpoints
                | ScriptRequest::DataflowQuery { .. }
                | ScriptRequest::TriageCrashes { .. }
                | ScriptRequest::DiffBinaries { .. }
                | ScriptRequest::MigrateBreakpoints { .. }
                | ScriptRequest::DetectRaces { .. }
                | ScriptRequest::BuildHeatmap { .. }
                | ScriptRequest::RootCause { .. }
                | ScriptRequest::ClassifyProvenance { .. }
                | ScriptRequest::RetroPrint { .. }
                | ScriptRequest::TtdOpen { .. }
                | ScriptRequest::NlQuery { .. } => {}
            }
        }

        let reqs = vec![
            ScriptRequest::ReadMemory { address: 0x1000, size: 4 },
            ScriptRequest::WriteMemory { address: 0x1000, bytes: vec![1, 2, 3, 4] },
            ScriptRequest::ReadRegister { name: "rax".into() },
            ScriptRequest::WriteRegister { name: "rax".into(), value: 1 },
            ScriptRequest::SetBreakpoint { address: 0x0040_1000 },
            ScriptRequest::RemoveBreakpoint { id: 1 },
            ScriptRequest::SetTypeFieldWatchpoint { type_name: "Entity".into(), base_address: 0x2000, field_path: "hp".into(), watch_write: true },
            ScriptRequest::DescribeType { type_name: "Entity".into() },
            ScriptRequest::WhoWrote { address: 0x1000, at_time: 10 },
            ScriptRequest::TraceOrigin { address: 0x1000, at_time: 10 },
            ScriptRequest::ListBreakpoints,
            ScriptRequest::DataflowQuery { query: "FIND WRITES TO 0x1000 BEFORE 10".into() },
            ScriptRequest::TriageCrashes { dumps: vec![], depth: 4 },
            ScriptRequest::DiffBinaries { old: vec![], new: vec![] },
            ScriptRequest::MigrateBreakpoints { addresses: vec![], old: vec![], new: vec![] },
            ScriptRequest::DetectRaces { accesses: vec![] },
            ScriptRequest::BuildHeatmap { history: vec![], num_buckets: 4 },
            ScriptRequest::RootCause { bad_writes: vec![], bad_address: 0x1000, bad_time: 10, good_writes: vec![] },
            ScriptRequest::ClassifyProvenance { pc: 0x1000, modules: vec![] },
            ScriptRequest::RetroPrint { address: 0x1000, format: "{0}".into(), args: vec!["rax".into()], before: None },
            ScriptRequest::TtdOpen { path: "foo.run".into() },
            ScriptRequest::NlQuery { question: "who wrote to 0x1000".into() },
        ];
        for req in &reqs {
            exhaustiveness_guard(req);
        }
        reqs
    }

    #[test]
    fn every_request_variant_dispatches_without_panicking() {
        let mut ctx = MockScriptContext::new();
        ctx.types.insert("Entity".into(), (20, vec![("hp".into(), 16, 4)]));
        ctx.registers.insert("rax".into(), 0);
        ctx.memory.insert(0x1000, vec![0, 0, 0, 0]);

        for req in one_of_every_request() {
            // Every variant on empty/minimal input must return a well-formed
            // Result, never panic — errors (e.g. unknown type) are fine.
            let _ = dispatch(&mut ctx, req);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Live tests — drive `LiveScriptContext` against a real `WindowsDebugger`
// ─────────────────────────────────────────────────────────────────────────────
//
// Mirrors `windows_debugger::live_tests`: this is the first proof that the
// scripting/tool-call surface actually reaches a live process end to end,
// closing the "nothing wires a live `Box<dyn Debugger>` into `ScriptContext`"
// gap flagged in `rustre_debug_os_backend_gap.md`.
#[cfg(all(test, windows))]
mod live_tests {
    use super::*;
    use crate::windows_debugger::WindowsDebugger;
    use crate::{Debugger, LaunchOptions, OutputRedirect, StopReason, ThreadId};
    use crate::watchpoint_engine::{TypeLayout, TypeRegistry};

    fn cmd_launch_options(args: &[&str]) -> LaunchOptions {
        LaunchOptions {
            executable: "C:\\Windows\\System32\\cmd.exe".to_string(),
            args: args.iter().map(|s| (*s).to_string()).collect(),
            env: std::collections::HashMap::new(),
            working_dir: None,
            stop_at_entry: false,
            follow_forks: false,
            redirect: OutputRedirect::default(),
        }
    }

    /// Launch a real `cmd.exe`, run to the initial system breakpoint, then drive
    /// the scripting API's `dispatch` against a `LiveScriptContext` wrapping the
    /// live backend: read a register, read memory at the live PC, set/list/remove
    /// a breakpoint, and describe a registered type — all through the exact same
    /// `ScriptRequest`/`ScriptResponse` path an LLM tool-call harness would use.
    #[tokio::test]
    async fn dispatch_drives_a_live_windows_session() {
        let dbg = WindowsDebugger::new();
        dbg.launch(cmd_launch_options(&["/C", "exit", "0"]))
            .await
            .expect("launch should succeed");

        // Run to the initial system breakpoint so registers/memory are live.
        let mut stopped_tid = None;
        let mut live_pc = 0u64;
        for _ in 0..50 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if let StopReason::Breakpoint { address, .. } = event.reason {
                stopped_tid = Some(event.tid);
                live_pc = address.as_u64();
                break;
            }
            if event.reason.is_exit() {
                break;
            }
        }
        let tid = stopped_tid.expect("should reach the initial breakpoint");

        // Build the live context with a small type registry to exercise
        // `DescribeType` against real backend plumbing.
        let mut types = TypeRegistry::new();
        types.register("Entity", TypeLayout::new(20).with_field("hp", 16, 4));
        let omni = OmniscientIndex::from_writes(Vec::new());
        let mut ctx = LiveScriptContext::new(Box::new(dbg), tid, types, omni);

        // read_register via dispatch
        // The PC register is NAMED per architecture. Hardcoding the x86
        // spelling made this fail on ubuntu-24.04-arm with `unknown register
        // rip`, against a register set publishing x0-x30/pc. `pc_key` is the
        // crate's existing answer and already carries a test forbidding it to
        // invent an x86 name on ARM64. Asking it keeps this test about the
        // DISPATCH path, which is what it exists to check.
        let pc = crate::instr_step::pc_key(crate::instr_step::native_arch());
        match dispatch(&mut ctx, ScriptRequest::ReadRegister { name: pc.into() }).unwrap() {
            ScriptResponse::Register { value, .. } => {
                assert_eq!(value, live_pc + 1, "rip should read one byte past the foreign int3");
            }
            other => panic!("expected Register, got {other:?}"),
        }

        // read_memory via dispatch
        match dispatch(&mut ctx, ScriptRequest::ReadMemory { address: live_pc, size: 8 }).unwrap() {
            ScriptResponse::Memory { bytes, .. } => assert_eq!(bytes.len(), 8),
            other => panic!("expected Memory, got {other:?}"),
        }

        // set → list → remove a software breakpoint via dispatch
        let bp_id = match dispatch(&mut ctx, ScriptRequest::SetBreakpoint { address: live_pc }).unwrap() {
            ScriptResponse::BreakpointSet { id, .. } => id,
            other => panic!("expected BreakpointSet, got {other:?}"),
        };
        match dispatch(&mut ctx, ScriptRequest::ListBreakpoints).unwrap() {
            ScriptResponse::Breakpoints { ids } => assert!(ids.contains(&bp_id)),
            other => panic!("expected Breakpoints, got {other:?}"),
        }
        match dispatch(&mut ctx, ScriptRequest::RemoveBreakpoint { id: bp_id }).unwrap() {
            ScriptResponse::BreakpointRemoved { id } => assert_eq!(id, bp_id),
            other => panic!("expected BreakpointRemoved, got {other:?}"),
        }

        // describe_type via dispatch (pure registry, but through the live ctx)
        match dispatch(&mut ctx, ScriptRequest::DescribeType { type_name: "Entity".into() }).unwrap() {
            ScriptResponse::TypeDescription { alloc_size, fields, .. } => {
                assert_eq!(alloc_size, 20);
                assert_eq!(fields, vec![("hp".to_string(), 16, 4)]);
            }
            other => panic!("expected TypeDescription, got {other:?}"),
        }

        // Removing an unknown id must surface a typed error, not panic.
        assert!(matches!(
            dispatch(&mut ctx, ScriptRequest::RemoveBreakpoint { id: 9999 }),
            Err(ScriptError::BreakpointNotFound(9999))
        ));

        // Drain to exit so the debug thread terminates cleanly.
        let _ = ThreadId(0);
        for _ in 0..2000 {
            match ctx.dbg.continue_execution().await {
                Ok(event) if event.reason.is_exit() => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    }
}

// Linux mirror of `live_tests`: same proof for the `ptrace`-based backend —
// the scripting/tool-call surface reaches a live `/bin/sh` process end to end
// through `LiveScriptContext`. Gated on Linux so it runs under WSL/Ubuntu, the
// same environment `linux_debugger::live_tests` is verified in.
#[cfg(all(test, target_os = "linux"))]
mod live_tests_linux {
    use super::*;
    use crate::linux_debugger::LinuxDebugger;
    use crate::{Debugger, LaunchOptions, OutputRedirect, ThreadId};
    use crate::watchpoint_engine::{TypeLayout, TypeRegistry};

    fn sh_launch_options(args: &[&str]) -> LaunchOptions {
        LaunchOptions {
            executable: "/bin/sh".to_string(),
            args: args.iter().map(|s| (*s).to_string()).collect(),
            env: std::collections::HashMap::new(),
            working_dir: None,
            stop_at_entry: false,
            follow_forks: false,
            redirect: OutputRedirect::default(),
        }
    }

    /// Launch a real `/bin/sh`, which `do_launch` leaves stopped at the
    /// post-execve `SIGTRAP`, then drive `dispatch()` against a
    /// `LiveScriptContext` wrapping the live `LinuxDebugger`: read a register,
    /// read memory at the live PC, set/list/remove a breakpoint, describe a
    /// registered type, and confirm the unknown-id error path — the exact
    /// `ScriptRequest`/`ScriptResponse` path an LLM tool-call harness uses.
    #[tokio::test]
    async fn dispatch_drives_a_live_linux_session() {
        let dbg = LinuxDebugger::new();
        dbg.launch(sh_launch_options(&["-c", "exit 0"]))
            .await
            .expect("launch should succeed against /bin/sh");

        // The tracee is already stopped at the post-execve SIGTRAP, so its
        // registers/memory are live immediately — no continue loop needed.
        let tid = dbg.target_pid().map(|p| ThreadId(p.0)).expect("expected a live pid");
        let live_pc = dbg
            .get_registers(tid)
            .await
            .expect("get_registers should succeed while stopped")
            .pc;
        assert_ne!(live_pc, 0, "a freshly-exec'd process should have a non-zero pc");

        let mut types = TypeRegistry::new();
        types.register("Entity", TypeLayout::new(20).with_field("hp", 16, 4));
        let omni = OmniscientIndex::from_writes(Vec::new());
        let mut ctx = LiveScriptContext::new(Box::new(dbg), tid, types, omni);

        // read_register via dispatch
        // The PC register is NAMED per architecture. Hardcoding the x86
        // spelling made this fail on ubuntu-24.04-arm with `unknown register
        // rip`, against a register set publishing x0-x30/pc. `pc_key` is the
        // crate's existing answer and already carries a test forbidding it to
        // invent an x86 name on ARM64. Asking it keeps this test about the
        // DISPATCH path, which is what it exists to check.
        let pc = crate::instr_step::pc_key(crate::instr_step::native_arch());
        match dispatch(&mut ctx, ScriptRequest::ReadRegister { name: pc.into() }).unwrap() {
            ScriptResponse::Register { value, .. } => assert_eq!(value, live_pc),
            other => panic!("expected Register, got {other:?}"),
        }

        // read_memory via dispatch
        match dispatch(&mut ctx, ScriptRequest::ReadMemory { address: live_pc, size: 8 }).unwrap() {
            ScriptResponse::Memory { bytes, .. } => assert_eq!(bytes.len(), 8),
            other => panic!("expected Memory, got {other:?}"),
        }

        // set → list → remove a software breakpoint via dispatch
        let bp_id = match dispatch(&mut ctx, ScriptRequest::SetBreakpoint { address: live_pc }).unwrap() {
            ScriptResponse::BreakpointSet { id, .. } => id,
            other => panic!("expected BreakpointSet, got {other:?}"),
        };
        match dispatch(&mut ctx, ScriptRequest::ListBreakpoints).unwrap() {
            ScriptResponse::Breakpoints { ids } => assert!(ids.contains(&bp_id)),
            other => panic!("expected Breakpoints, got {other:?}"),
        }
        match dispatch(&mut ctx, ScriptRequest::RemoveBreakpoint { id: bp_id }).unwrap() {
            ScriptResponse::BreakpointRemoved { id } => assert_eq!(id, bp_id),
            other => panic!("expected BreakpointRemoved, got {other:?}"),
        }

        // describe_type via dispatch
        match dispatch(&mut ctx, ScriptRequest::DescribeType { type_name: "Entity".into() }).unwrap() {
            ScriptResponse::TypeDescription { alloc_size, fields, .. } => {
                assert_eq!(alloc_size, 20);
                assert_eq!(fields, vec![("hp".to_string(), 16, 4)]);
            }
            other => panic!("expected TypeDescription, got {other:?}"),
        }

        // Unknown breakpoint id must surface a typed error, not panic.
        assert!(matches!(
            dispatch(&mut ctx, ScriptRequest::RemoveBreakpoint { id: 9999 }),
            Err(ScriptError::BreakpointNotFound(9999))
        ));

        let _ = ctx.dbg.kill().await;
    }
}
