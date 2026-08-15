//! Wires a live [`crate::Debugger`] backend (e.g.
//! `WindowsDebugger`/`LinuxDebugger`)
//! into the [`crate::scripting_api::ScriptContext`] trait, so an LLM
//! tool-calling agent driving [`crate::scripting_api::dispatch`] can actually
//! read/write memory, read/write registers, and set/remove breakpoints on a
//! real running process — not just a [`crate::scripting_api::MockScriptContext`].
//!
//! Closes the gap the 2026-07-14 OS-backend audit flagged as the last piece
//! between "a concrete `Debugger` impl exists" and "an agent can drive a live
//! debug session through the scripting/MCP surface": both concrete backends
//! and the scripting dispatch table existed, but nothing connected them.
//!
//! `ScriptContext` is a plain synchronous trait (so the scripting layer stays
//! decoupled from any particular async runtime), while every [`crate::Debugger`]
//! method is `async`. Every existing backend's `async fn` body is, in
//! practice, a synchronous blocking channel `recv()` under the hood (see
//! `windows_debugger`'s/`linux_debugger`'s dedicated-thread design) — it never
//! actually suspends on a real I/O readiness event — so bridging with a
//! single-poll executor (no full async runtime needed) is both correct and
//! the simplest option that keeps this crate's dependency footprint small.

use std::collections::HashMap;
use std::future::Future;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use rustre_core::address::Address;

use crate::scripting_api::ScriptError;
use crate::{BreakpointKind, Debugger, ThreadId};
use crate::omniscient_query::{MemoryWrite, OmniscientIndex, OriginHop};
use crate::time_travel_debug::SnapshotReplayBackend;
use crate::retroactive_print::{RetroAnnotation, RetroPrintEntry, retro_print};
use crate::nl_query::{self, NlQueryResult};

const NOOP_VTABLE: RawWakerVTable = RawWakerVTable::new(
    |_| RawWaker::new(std::ptr::null(), &NOOP_VTABLE),
    |_| {},
    |_| {},
    |_| {},
);

fn noop_waker() -> Waker {
    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &NOOP_VTABLE)) }
}

/// Poll `fut` to completion without a full async runtime. Every current
/// [`crate::Debugger`] backend resolves synchronously on the first poll (see
/// module docs), so this loop is a defensive fallback, not the expected path
/// — if a future genuinely goes `Pending`, spin (bounded) rather than busy
/// loop forever or silently deadlock.
fn block_on_sync<F: Future>(fut: F) -> F::Output {
    let mut fut = Box::pin(fut);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    for _ in 0..10_000 {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::yield_now(),
        }
    }
    panic!(
        "live_script_context: a Debugger future stayed Pending for 10,000 polls — this backend \
         is no longer purely synchronous under the hood and needs a real async bridge instead \
         of block_on_sync"
    );
}

/// Bridges a live `&dyn Debugger` session into [`crate::scripting_api::ScriptContext`].
///
/// Breakpoint IDs are a simple local counter mapped to the address actually
/// passed to the backend (the `Debugger` trait indexes breakpoints by
/// address, not by an opaque ID) — mirrors `MockScriptContext`'s own
/// `id -> address` bookkeeping so the two implementations behave identically
/// from a caller's perspective.
///
/// Optionally holds an [`crate::omniscient_query::OmniscientIndex`] (for omniscient/retroactive queries)
/// and a [`crate::time_travel_debug::SnapshotReplayBackend`] (for [`retro_print`] expression evaluation).
/// Both are empty by default; populate them from a recorded TTD trace to enable
/// the retroactive and NL-query paths.
pub struct LiveScriptContext<'a> {
    debugger: &'a dyn Debugger,
    next_bp_id: u64,
    bp_ids: HashMap<u64, u64>,
    /// Omniscient write index, populated from a recorded TTD trace.
    omni: OmniscientIndex,
    /// Snapshot replay backend for expression evaluation at historical positions.
    replay: SnapshotReplayBackend,
}

impl<'a> LiveScriptContext<'a> {
    /// Create with an empty omniscient index and replay backend.
    #[must_use]
    pub fn new(debugger: &'a dyn Debugger) -> Self {
        Self {
            debugger,
            next_bp_id: 1,
            bp_ids: HashMap::new(),
            omni: OmniscientIndex::from_writes(Vec::new()),
            replay: SnapshotReplayBackend::new(),
        }
    }

    /// Create with a pre-populated omniscient index and replay backend from a
    /// recorded TTD trace.  Enables [`Self::execute_nl_query`] and
    /// [`Self::retro_print`] as well as the [`crate::scripting_api::ScriptContext`]
    /// `who_wrote`/`trace_origin` methods.
    #[must_use]
    pub fn new_with_trace(
        debugger: &'a dyn Debugger,
        omni: OmniscientIndex,
        replay: SnapshotReplayBackend,
    ) -> Self {
        Self { debugger, next_bp_id: 1, bp_ids: HashMap::new(), omni, replay }
    }

    fn current_tid(&self) -> Result<ThreadId, ScriptError> {
        block_on_sync(self.debugger.current_thread())
            .map_err(|e| crate::scripting_api::script_error_from(&e, 0))
    }

    /// Execute a natural-language query against the omniscient index.
    ///
    /// Translates `question` via [`nl_query::translate`] and then executes it
    /// with [`nl_query::execute`] against the recorded trace index.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError::DataflowQuery`] when the question cannot be parsed.
    pub fn execute_nl_query(&self, question: &str) -> Result<NlQueryResult, ScriptError> {
        let query = nl_query::translate(question)
            .map_err(|e| ScriptError::DataflowQuery(e.to_string()))?;
        Ok(nl_query::execute(&query, &self.omni))
    }

    /// Retroactively print the annotated address over the recorded trace.
    ///
    /// Delegates to [`retro_print`] using the stored omniscient index and replay
    /// backend.  Returns one [`RetroPrintEntry`] per write, most-recent-first.
    #[must_use]
    pub fn retro_print(&self, ann: &RetroAnnotation, before: u64) -> Vec<RetroPrintEntry> {
        retro_print(&self.omni, &self.replay, ann, before)
    }
}

impl crate::scripting_api::ScriptContext for LiveScriptContext<'_> {
    fn read_memory(&self, address: u64, size: u32) -> Result<Vec<u8>, ScriptError> {
        if !self.debugger.is_attached() {
            return Err(ScriptError::NotAttached);
        }
        block_on_sync(self.debugger.read_memory(Address(address), size as usize))
            .map_err(|_| ScriptError::MemoryRead(address))
    }

    fn write_memory(&mut self, address: u64, bytes: &[u8]) -> Result<u32, ScriptError> {
        if !self.debugger.is_attached() {
            return Err(ScriptError::NotAttached);
        }
        block_on_sync(self.debugger.write_memory(Address(address), bytes))
            .map(|n| n as u32)
            .map_err(|_| ScriptError::MemoryWrite(address))
    }

    fn read_register(&self, name: &str) -> Result<u64, ScriptError> {
        let tid = self.current_tid()?;
        // NOT a blanket `UnknownRegister`: the backend has no distinct error for
        // a bad register NAME, so claiming one for a detached target or a dead
        // transport sends the caller hunting for a typo in a name that is
        // perfectly valid. When the name really is wrong the backend says so in
        // its own message, which `script_error_from` carries through.
        block_on_sync(self.debugger.get_register(tid, name))
            .map_err(|e| crate::scripting_api::script_error_from(&e, 0))
    }

    fn write_register(&mut self, name: &str, value: u64) -> Result<(), ScriptError> {
        let tid = self.current_tid()?;
        block_on_sync(self.debugger.set_register(tid, name, value))
            .map_err(|e| crate::scripting_api::script_error_from(&e, 0))
    }

    fn set_breakpoint(&mut self, address: u64) -> Result<u64, ScriptError> {
        if !self.debugger.is_attached() {
            return Err(ScriptError::NotAttached);
        }
        block_on_sync(self.debugger.set_breakpoint(Address(address), BreakpointKind::Software))
            .map_err(|e| ScriptError::Unsupported(e.to_string()))?;
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        self.bp_ids.insert(id, address);
        Ok(id)
    }

    fn remove_breakpoint(&mut self, id: u64) -> Result<(), ScriptError> {
        // Look up, do NOT drop the id yet. Removing it first meant a backend
        // failure — a target that has died or become unwritable, which is
        // exactly when a removal fails — took the id with it: the breakpoint is
        // still installed in the process, but the script can no longer name it,
        // retry the removal, or even see it in `list_breakpoints`. The sibling
        // context in `scripting_api` already gets this right; the two disagreed.
        let address = *self.bp_ids.get(&id).ok_or(ScriptError::BreakpointNotFound(id))?;
        block_on_sync(self.debugger.remove_breakpoint(Address(address)))
            .map_err(|e| crate::scripting_api::script_error_from(&e, id))?;
        self.bp_ids.remove(&id);
        Ok(())
    }

    fn set_type_field_watchpoint(
        &mut self,
        _type_name: &str,
        _base_address: u64,
        _field_path: &str,
        _watch_write: bool,
    ) -> Result<(u64, u64, u8), ScriptError> {
        // Needs a `TypeRegistry` (DWARF/CodeView field-offset resolution)
        // wired to this session, which no `Debugger` backend provides on its
        // own — tracked as a follow-up, same as `describe_type` below.
        Err(ScriptError::Unsupported(
            "set_type_field_watchpoint: no TypeRegistry wired to this live session yet".into(),
        ))
    }

    fn describe_type(&self, _type_name: &str) -> Result<(u64, Vec<(String, u64, u8)>), ScriptError> {
        Err(ScriptError::Unsupported("describe_type: no TypeRegistry wired to this live session yet".into()))
    }

    fn who_wrote(&self, address: u64, at_time: u64) -> Vec<MemoryWrite> {
        self.omni
            .who_wrote(Address(address), at_time)
            .into_iter()
            .cloned()
            .collect()
    }

    fn trace_origin(&self, address: u64, at_time: u64) -> Vec<OriginHop> {
        self.omni.trace_origin(Address(address), at_time)
    }

    fn list_breakpoints(&self) -> Vec<u64> {
        // Sorted, like the sibling context in `scripting_api`. `HashMap::keys`
        // yields whatever order the randomly-seeded hasher produces, so this
        // returned a different permutation on every RUN of the same session:
        // an agent driving these tools cannot reproduce its own steps, and
        // anything that reaches for "the first breakpoint" gets a different one
        // each time. The two implementations of this one tool also disagreed,
        // which is how it was found.
        let mut ids: Vec<u64> = self.bp_ids.keys().copied().collect();
        ids.sort_unstable();
        ids
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests (no live process required)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod unit_tests {
    use super::*;

    /// `list_breakpoints` must answer in a stable order.
    ///
    /// It returned `HashMap::keys()` directly, and Rust seeds its hasher
    /// randomly per process — so the same session listed its breakpoints in a
    /// different permutation on every run. The consumer here is an LLM driving
    /// tool calls: non-deterministic output makes a session impossible to
    /// reproduce, and any step that reaches for "the first breakpoint" picks a
    /// different one each time. The sibling context in `scripting_api` already
    /// sorted, so the two implementations of the same tool disagreed — which is
    /// exactly how this was found.
    ///
    /// 32 ids: a shuffled iteration coming out in ascending order by accident
    /// has probability 1/32!, which is zero for any practical purpose.
    #[test]
    fn list_breakpoints_is_ordered_not_hash_ordered() {
        use crate::ios::apple_debugger::{AppleDebugger, LoopbackFactory};
        use crate::ios::mock_debugserver::MockDebugserver;
        use crate::ProcessId;
        use std::sync::Arc;

        const BASE: u64 = 0x1_0000_4000;
        let srv = MockDebugserver::with_program(4242, BASE, &[0xD503_201Fu32, 0xD65F_03C0]);
        let dbg = AppleDebugger::new(Arc::new(LoopbackFactory::new(srv, 7)));
        block_on_sync(dbg.attach(ProcessId(4242))).expect("attach");

        let mut ctx = LiveScriptContext::new(&dbg);
        for i in 0..32u64 {
            ctx.set_breakpoint(BASE + i * 4).expect("set_breakpoint");
        }

        let listed = ctx.list_breakpoints();
        let mut expected = listed.clone();
        expected.sort_unstable();
        assert_eq!(
            listed, expected,
            "breakpoint ids came back in hash order, so the same session lists them \
             differently on every run"
        );
    }

    /// A removal the backend refuses must not make the breakpoint id vanish.
    ///
    /// The id was dropped from the map BEFORE the backend was asked, so a
    /// failure took it with it: the breakpoint is still installed in the target,
    /// but the script can no longer name it, retry the removal, or see it in
    /// `list_breakpoints`. Same shape as the backend defect of iter 284, one
    /// layer up — and the sibling context in `scripting_api` already did it the
    /// right way round, so the two implementations disagreed about the same
    /// operation.
    #[test]
    fn a_refused_removal_does_not_lose_the_breakpoint_id() {
        use crate::ios::apple_debugger::{AppleDebugger, LoopbackFactory};
        use crate::ios::mock_debugserver::MockDebugserver;
        use crate::ProcessId;
        use std::sync::Arc;

        const BASE: u64 = 0x1_0000_4000;
        let mut srv = MockDebugserver::with_program(4242, BASE, &[0xD503_201Fu32, 0xD65F_03C0]);
        srv.refuse_software_breakpoints(); // self-patched, so removal must WRITE
        srv.fail_memory_writes_after(1); // the patch lands; the restore is refused
        let dbg = AppleDebugger::new(Arc::new(LoopbackFactory::new(srv, 7)));
        block_on_sync(dbg.attach(ProcessId(4242))).expect("attach");

        let mut ctx = LiveScriptContext::new(&dbg);
        let id = ctx.set_breakpoint(BASE).expect("set_breakpoint");

        ctx.remove_breakpoint(id).expect_err("the restore is refused");

        // The breakpoint is still in the target, so the id must still name it.
        let second = ctx.remove_breakpoint(id).expect_err("still refused");
        assert!(
            !matches!(second, ScriptError::BreakpointNotFound(_)),
            "the id was forgotten by the failed attempt, so the live breakpoint              became unreachable: {second}"
        );
    }
    use crate::scripting_api::{ScriptContext, ScriptRequest, ScriptResponse, dispatch};
    use crate::omniscient_query::MemoryWrite;
    use crate::time_travel_debug::{SnapshotReplayBackend, TtdState, TracePosition};
    use crate::retroactive_print::RetroAnnotation;
    use crate::ThreadId;
    use rustre_core::address::Address;

    /// A minimal `Debugger` stub that always returns `NotAttached` errors so
    /// the scenario tests can exercise the trace-backed paths without launching
    /// a real process.
    struct StubDebugger;

    #[async_trait::async_trait]
    impl crate::Debugger for StubDebugger {
        fn name(&self) -> &str { "stub" }
        fn supported_architectures(&self) -> Vec<String> { vec![] }
        fn is_attached(&self) -> bool { false }
        fn target_pid(&self) -> Option<crate::ProcessId> { None }

        async fn launch(&self, _opts: crate::LaunchOptions) -> Result<crate::ProcessId, crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn attach(&self, _pid: crate::ProcessId) -> Result<(), crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn detach(&self) -> Result<(), crate::DebugError> { Err(crate::DebugError::NotAttached) }
        async fn kill(&self) -> Result<(), crate::DebugError> { Err(crate::DebugError::NotAttached) }
        async fn continue_execution(&self) -> Result<crate::DebugEvent, crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn single_step(&self, _tid: ThreadId) -> Result<crate::DebugEvent, crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn step_over(&self, _tid: ThreadId) -> Result<crate::DebugEvent, crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn step_out(&self, _tid: ThreadId) -> Result<crate::DebugEvent, crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn pause(&self) -> Result<(), crate::DebugError> { Err(crate::DebugError::NotAttached) }
        async fn threads(&self) -> Result<Vec<ThreadId>, crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn current_thread(&self) -> Result<ThreadId, crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn get_registers(&self, _tid: ThreadId) -> Result<crate::RegisterSet, crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn set_registers(&self, _tid: ThreadId, _regs: crate::RegisterSet) -> Result<(), crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn get_register(&self, _tid: ThreadId, _name: &str) -> Result<u64, crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn set_register(&self, _tid: ThreadId, _name: &str, _value: u64) -> Result<(), crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn read_memory(&self, _addr: Address, _size: usize) -> Result<Vec<u8>, crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn write_memory(&self, _addr: Address, _data: &[u8]) -> Result<usize, crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn memory_maps(&self) -> Result<Vec<crate::MemoryMap>, crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn set_breakpoint(&self, _addr: Address, _kind: crate::BreakpointKind) -> Result<(), crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn remove_breakpoint(&self, _addr: Address) -> Result<(), crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn enable_breakpoint(&self, _addr: Address) -> Result<(), crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn disable_breakpoint(&self, _addr: Address) -> Result<(), crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn breakpoints(&self) -> Result<Vec<crate::Breakpoint>, crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn modules(&self) -> Result<Vec<crate::ModuleInfo>, crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
        async fn backtrace(&self, _tid: ThreadId) -> Result<Vec<crate::StackFrame>, crate::DebugError> {
            Err(crate::DebugError::NotAttached)
        }
    }

    fn make_write(seq: u64, addr: u64, pc: u64) -> MemoryWrite {
        MemoryWrite {
            sequence: seq,
            address: Address(addr),
            size: 8,
            tid: ThreadId(1),
            writer_pc: Some(Address(pc)),
            source_address: None,
        }
    }

    /// Cross-cutting scenario:
    /// 1. Build a synthetic trace with two writes to address 0x5000.
    /// 2. Attach a `RetroAnnotation` → `retro_print` renders rax at each write.
    /// 3. Ask `execute_nl_query "who wrote to 0x5000"` → result cites the same 2 writes.
    /// 4. Exercise `ScriptContext::who_wrote` via `dispatch(WhoWrote)` through
    ///    the live context backed by the synthetic index.
    #[test]
    fn cross_scenario_retro_print_and_nl_query_agree() {
        const ADDR: u64 = 0x5000;

        // Synthetic trace: two writes to ADDR.
        let writes = vec![
            make_write(2, ADDR, 0x401000),
            make_write(8, ADDR, 0x401010),
        ];
        let omni = OmniscientIndex::from_writes(writes);

        // Replay states for expression evaluation.
        let mut replay = SnapshotReplayBackend::new();
        let mut st2 = TtdState::new(TracePosition::new(2, 0), 0x401000, 0x7000);
        st2.regs.insert("rax".into(), 0xAA);
        let mut st8 = TtdState::new(TracePosition::new(8, 0), 0x401010, 0x7000);
        st8.regs.insert("rax".into(), 0xBB);
        replay.record(st2);
        replay.record(st8);

        let stub = StubDebugger;
        let ctx = LiveScriptContext::new_with_trace(&stub, omni, replay);

        // --- retroactive_print path ---
        let ann = RetroAnnotation { address: ADDR, format: "rax={0}".into(), args: vec!["rax".into()] };
        let retro_entries = ctx.retro_print(&ann, u64::MAX);
        assert_eq!(retro_entries.len(), 2, "retro_print must see both writes");
        // Most-recent-first: seq 8 before seq 2.
        assert_eq!(retro_entries[0].write.sequence, 8);
        assert_eq!(retro_entries[1].write.sequence, 2);
        assert!(retro_entries[0].rendered.contains("0xbb"), "rendered: {}", retro_entries[0].rendered);
        assert!(retro_entries[1].rendered.contains("0xaa"), "rendered: {}", retro_entries[1].rendered);

        // --- nl_query path ---
        let nl_result = ctx.execute_nl_query(&format!("who wrote to {ADDR:#x}")).unwrap();
        let NlQueryResult::Writes { address: _, writes, explanation } = nl_result else {
            panic!("expected Writes result from nl_query");
        };
        assert_eq!(writes.len(), 2, "nl_query must find both writes; explanation: {explanation}");
        assert!(writes.iter().all(|w| w.address.0 == ADDR));

        // --- ScriptContext::who_wrote through dispatch (proves the trait impl uses omni) ---
        // Re-create a ctx — we can't use the moved one above.
        let omni2 = OmniscientIndex::from_writes(vec![
            make_write(2, ADDR, 0x401000),
            make_write(8, ADDR, 0x401010),
        ]);
        let stub2 = StubDebugger;
        let mut ctx2 = LiveScriptContext::new_with_trace(&stub2, omni2, SnapshotReplayBackend::new());
        let resp = dispatch(&mut ctx2, ScriptRequest::WhoWrote { address: ADDR, at_time: u64::MAX }).unwrap();
        let ScriptResponse::Writers { writes: disp_writes, .. } = resp else {
            panic!("expected Writers response");
        };
        assert_eq!(disp_writes.len(), 2, "dispatch(WhoWrote) must return both writes from the synthetic index");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Live integration test — real Debugger backend driven through dispatch()
// ─────────────────────────────────────────────────────────────────────────────
//
// Proves the actual end-to-end path an LLM tool-calling agent would exercise:
// scripting_api::dispatch(ScriptRequest) -> LiveScriptContext -> a live
// Debugger backend -> a real process. Everything below this point (both
// concrete Debugger backends, and now this bridge) previously had unit-level
// plausibility but no proof the pieces actually compose correctly together.
#[cfg(all(test, windows))]
mod live_tests {
    use super::*;
    use crate::scripting_api::{ScriptRequest, ScriptResponse, dispatch};
    use crate::windows_debugger::WindowsDebugger;
    use crate::{Debugger, LaunchOptions, OutputRedirect};

    #[tokio::test]
    async fn dispatch_drives_a_real_process_through_the_scripting_surface() {
        let dbg = WindowsDebugger::new();
        dbg.launch(LaunchOptions {
            executable: "C:\\Windows\\System32\\cmd.exe".to_string(),
            args: vec!["/C".to_string(), "exit".to_string(), "0".to_string()],
            env: std::collections::HashMap::new(),
            working_dir: None,
            stop_at_entry: false,
            follow_forks: false,
            redirect: OutputRedirect::default(),
        })
        .await
        .expect("launch should succeed");

        // Reach the initial breakpoint so there's a live, stopped thread to
        // read registers/memory from and a valid address to set a breakpoint
        // at — mirrors `windows_debugger::live_tests`' own setup.
        let mut bp_addr = None;
        for _ in 0..50 {
            let event = dbg.continue_execution().await.expect("continue_execution should not error");
            if let crate::StopReason::Breakpoint { address, .. } = event.reason {
                bp_addr = Some(address.as_u64());
                break;
            }
            if event.reason.is_exit() {
                break;
            }
        }
        let bp_addr = bp_addr.expect("expected the initial system breakpoint");

        let mut ctx = LiveScriptContext::new(&dbg);

        // ReadRegister through the full dispatch path.
        // The PC register is NAMED per architecture. Hardcoding the x86
        // spelling made this fail on ubuntu-24.04-arm with `unknown register
        // rip`, against a register set publishing x0-x30/pc. `pc_key` is the
        // crate's existing answer and already carries a test forbidding it to
        // invent an x86 name on ARM64. Asking it keeps this test about the
        // DISPATCH path, which is what it exists to check.
        let pc = crate::instr_step::pc_key(crate::instr_step::native_arch());
        match dispatch(&mut ctx, ScriptRequest::ReadRegister { name: pc.to_string() }) {
            Ok(ScriptResponse::Register { value, .. }) => assert_ne!(value, 0, "{pc} should be non-zero on a live thread"),
            other => panic!("unexpected ReadRegister response: {other:?}"),
        }

        // ReadMemory through the full dispatch path.
        match dispatch(&mut ctx, ScriptRequest::ReadMemory { address: bp_addr, size: 8 }) {
            Ok(ScriptResponse::Memory { bytes, .. }) => assert_eq!(bytes.len(), 8),
            other => panic!("unexpected ReadMemory response: {other:?}"),
        }

        // SetBreakpoint / ListBreakpoints / RemoveBreakpoint through the full
        // dispatch path — proves the id<->address bookkeeping round-trips.
        let id = match dispatch(&mut ctx, ScriptRequest::SetBreakpoint { address: bp_addr }) {
            Ok(ScriptResponse::BreakpointSet { id, address }) => {
                assert_eq!(address, bp_addr);
                id
            }
            other => panic!("unexpected SetBreakpoint response: {other:?}"),
        };
        match dispatch(&mut ctx, ScriptRequest::ListBreakpoints) {
            Ok(ScriptResponse::Breakpoints { ids }) => assert!(ids.contains(&id)),
            other => panic!("unexpected ListBreakpoints response: {other:?}"),
        }
        match dispatch(&mut ctx, ScriptRequest::RemoveBreakpoint { id }) {
            Ok(ScriptResponse::BreakpointRemoved { .. }) => {}
            other => panic!("unexpected RemoveBreakpoint response: {other:?}"),
        }

        drop(ctx);
        let _ = dbg.kill().await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Linux equivalent of the live integration test above — same end-to-end
// dispatch() path, never previously exercised against the Linux backend at
// all (this file had exactly one live test, `#[cfg(all(test, windows))]`-
// only). Found via the same Windows-vs-Linux live-test coverage audit that
// caught this session's three real bugs (DR-registers, SIGTRAP
// misclassification, current_thread staleness) — this module was the one
// remaining spot with zero Linux coverage of its own.
#[cfg(all(test, target_os = "linux"))]
mod linux_live_tests {
    use super::*;
    use crate::scripting_api::{ScriptRequest, ScriptResponse, dispatch};
    use crate::linux_debugger::LinuxDebugger;
    use crate::{Debugger, LaunchOptions, OutputRedirect, ThreadId};

    #[tokio::test]
    async fn dispatch_drives_a_real_process_through_the_scripting_surface() {
        let dbg = LinuxDebugger::new();
        dbg.launch(LaunchOptions {
            executable: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), "exit 0".to_string()],
            env: std::collections::HashMap::new(),
            working_dir: None,
            stop_at_entry: false,
            follow_forks: false,
            redirect: OutputRedirect::default(),
        })
        .await
        .expect("launch should succeed");

        // Unlike Windows (which needs a continue-loop to reach an initial
        // system breakpoint), `do_launch` already reaps the post-execve
        // stop, so the tracee is immediately ready — same pattern as every
        // other Linux live test in this crate.
        let tid = dbg.target_pid().map(|p| ThreadId(p.0)).expect("expected a live pid");
        let regs = dbg.get_registers(tid).await.expect("get_registers should succeed");
        let bp_addr = regs.pc;

        let mut ctx = LiveScriptContext::new(&dbg);

        // ReadRegister through the full dispatch path.
        // The PC register is NAMED per architecture. Hardcoding the x86
        // spelling made this fail on ubuntu-24.04-arm with `unknown register
        // rip`, against a register set publishing x0-x30/pc. `pc_key` is the
        // crate's existing answer and already carries a test forbidding it to
        // invent an x86 name on ARM64. Asking it keeps this test about the
        // DISPATCH path, which is what it exists to check.
        let pc = crate::instr_step::pc_key(crate::instr_step::native_arch());
        match dispatch(&mut ctx, ScriptRequest::ReadRegister { name: pc.to_string() }) {
            Ok(ScriptResponse::Register { value, .. }) => assert_ne!(value, 0, "{pc} should be non-zero on a live thread"),
            other => panic!("unexpected ReadRegister response: {other:?}"),
        }

        // ReadMemory through the full dispatch path.
        match dispatch(&mut ctx, ScriptRequest::ReadMemory { address: bp_addr, size: 8 }) {
            Ok(ScriptResponse::Memory { bytes, .. }) => assert_eq!(bytes.len(), 8),
            other => panic!("unexpected ReadMemory response: {other:?}"),
        }

        // SetBreakpoint / ListBreakpoints / RemoveBreakpoint through the full
        // dispatch path — proves the id<->address bookkeeping round-trips.
        let id = match dispatch(&mut ctx, ScriptRequest::SetBreakpoint { address: bp_addr }) {
            Ok(ScriptResponse::BreakpointSet { id, address }) => {
                assert_eq!(address, bp_addr);
                id
            }
            other => panic!("unexpected SetBreakpoint response: {other:?}"),
        };
        match dispatch(&mut ctx, ScriptRequest::ListBreakpoints) {
            Ok(ScriptResponse::Breakpoints { ids }) => assert!(ids.contains(&id)),
            other => panic!("unexpected ListBreakpoints response: {other:?}"),
        }
        match dispatch(&mut ctx, ScriptRequest::RemoveBreakpoint { id }) {
            Ok(ScriptResponse::BreakpointRemoved { .. }) => {}
            other => panic!("unexpected RemoveBreakpoint response: {other:?}"),
        }

        drop(ctx);
        let _ = dbg.kill().await;
    }
}
