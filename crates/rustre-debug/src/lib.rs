//! `rustre-debug`
//!
//! Base debugger trait definitions, shared types, and a session-state wrapper for the
//! `RustRE` Suite debugger subsystem. OS-specific [`Debugger`] backends (e.g.
//! [`windows_debugger::WindowsDebugger`]) live directly in this crate, calling the
//! native OS debug API only (Win32 debug API, ptrace, ...) — per project policy this
//! hub crate must never depend on another debugger implementation/sub-crate, only on
//! OS APIs.

// Safety lint: every `unsafe` operation inside an `unsafe fn` must be
// individually annotated with a SAFETY comment.
#![deny(unsafe_op_in_unsafe_fn)]

pub use rustre_mem;

/// Exponential-backoff retry helper for transient external-service errors
/// (rr TCP connect, PDB HTTP download).
pub mod retry;

/// Circuit breaker for external services (PDB symbol server): after a
/// configurable number of failures within a time window, stops issuing requests
/// for a cooldown period.
pub mod circuit_breaker;

/// CodeView / PDB parser (absorbed from former rustre-symbols-codeview crate on 2026-07-12).
pub mod codeview;

/// Architecture-dependent software-breakpoint trap facts (`int3` vs `BRK #0`).
/// Pure data; not yet wired into the OS backends.
pub mod arch_breakpoint;

/// Cross-platform debugger abstractions: unified [`crate::cross_platform_debug::DebugTarget`], platform /
/// architecture enumerations, software/hardware [`Breakpoint`] descriptors, and
/// the shared [`crate::cross_platform_debug::CrossDebugError`] type — used by all OS-specific backends.
///
/// # Example
/// ```no_run
/// use rustre_debug::cross_platform_debug::{DebugTarget, Platform, Architecture};
/// let target = DebugTarget::local(1234, Platform::Windows, Architecture::X86_64);
/// assert_eq!(target.pid, 1234);
/// ```
pub mod cross_platform_debug;
/// Expression evaluator for debugger contexts: parse and evaluate C-like
/// expressions (`a + b`, `*(u32*)ptr`, `((Foo*)p)->field`) against a live or
/// recorded session's register/memory/type state.
///
/// # Example
/// ```
/// use rustre_debug::expression_evaluator::{parse_expression, TypeSystem};
/// let _types = TypeSystem::with_primitives();
/// let _expr = parse_expression("rax + 4").expect("a well-formed expression");
/// ```
///
/// Not `ignore`d, on purpose. The previous version of this example was, and it
/// named a type `Expr` that does not exist and a method `TypeSystem::parse`
/// that does not either — two compile errors for anyone who copied it, hidden
/// because an `ignore`d example is never built. Documentation that is not
/// compiled is documentation that drifts.
///
/// # Errors
/// Returns a parse error for malformed expressions; evaluation errors when the
/// referenced register or memory address is inaccessible.
pub mod expression_evaluator;
/// Source-map helpers: map binary virtual addresses back to source file + line
/// numbers, and forward source locations to binary address ranges.
///
/// Reads DWARF `.debug_line` sections and, on Windows, PDB line-number streams.
///
/// # Example
/// ```
/// use rustre_debug::source_map::SourceLocation;
/// // A `SourceMap` is built from a parsed line table via
/// // `SourceMap::from_line_table`; this is the location type it yields.
/// let loc = SourceLocation::new("src/main.rs", 42);
/// assert_eq!(loc.line, 42);
/// ```
pub mod source_map;
/// Symbol resolver: given a virtual address, produce a human-readable name
/// from any combination of PDB / CodeView records, DWARF `.debug_info` symbols,
/// ELF symbol tables, and user-defined labels.
///
/// # Example
/// ```
/// use rustre_debug::symbol_resolver::{FrameSymbolResolver, ResolvedFrameSymbol};
/// struct Fixed;
/// impl FrameSymbolResolver for Fixed {
///     fn resolve_frame(&self, _pc: u64) -> Option<ResolvedFrameSymbol> {
///         Some(ResolvedFrameSymbol {
///             function: Some("main".to_string()),
///             file: None,
///             line: None,
///             // `true` only when containment is demonstrable; see the field docs.
///             bounded: true,
///             // The function start, when the source knows it: what turns
///             // `main` into `main+0x1c` in a rendered frame.
///             start: Some(0x1400_1000),
///         })
///     }
/// }
/// assert_eq!(Fixed.resolve_frame(0x1400_1000).unwrap().function.as_deref(), Some("main"));
/// ```
///
/// # Errors
/// Returns `None` (or a `SymbolError`) when no symbol covers the address.
pub mod symbol_resolver;
/// Debug session manager.
///
/// Includes DebugSessionManager, DebugSession, SessionPool,
/// SessionEvent, DebugTarget (pid/process/remote/core), SessionRecorder.
pub mod debug_session_manager;
/// Multi-target coordinator: attach to several processes or remote targets
/// simultaneously, multiplexing events across all of them onto a single event
/// bus.  Useful for debugging client–server pairs or multi-process applications
/// that fork worker subprocesses.
///
/// # Example
/// ```
/// use rustre_debug::multi_target_debugger::MultiTargetDebugger;
/// let mt = MultiTargetDebugger::new();
/// assert!(mt.sync_breakpoints.is_empty());
/// ```
pub mod multi_target_debugger;
/// Advanced hardware/software watchpoint engine.
///
/// Covers DR0–DR3 on x86, DBGWVR/DBGWCR on ARM64, software page-protect
/// fallback, conditional watchpoints, one-shot watchpoints, and hit counting.
pub mod watchpoint_engine;
/// Time-travel debugging interface.
///
/// Provides step-backward, reverse-continue, reverse-step-over,
/// run-to-previous-call, snapshot-based simulation, and integration hooks for
/// the `rustre-ttd` crate.
pub mod time_travel_debug;
/// Runtime memory layout view.
///
/// Includes heap chunk enumeration (ptmalloc2/jemalloc/tcmalloc/Windows NT
/// heap), live stack-frame unwinding, mapped region view with ASLR offsets,
/// and guard-page detection.
pub mod memory_layout_view;
/// Async event loop for a single debug session: polls the underlying
/// [`Debugger`] for [`StopReason`] events and dispatches them to registered
/// callback handlers (breakpoint, watchpoint, exception, module-load, exit).
///
/// # Example
/// ```
/// use rustre_debug::debugger_event_loop::DebuggerEventLoop;
/// // The queue capacity bounds how many events may be buffered before the
/// // producer has to wait.
/// let _bounded = DebuggerEventLoop::new(64);
/// let _default = DebuggerEventLoop::default_capacity();
/// ```
pub mod debugger_event_loop;
/// CPU register context for a debugged thread: stores all architectural registers
/// (GPRs, flags, segment regs, debug regs, XMM/YMM) and formats them for display.
///
/// See [`register_context::RegisterContext`] and [`register_context::RegisterSet`].
///
/// # Example
/// ```
/// use rustre_debug::register_context::{Architecture, RegValue, RegisterContext};
/// let mut ctx = RegisterContext::new(Architecture::X86_64, 1234);
/// ctx.set("rax", RegValue::U64(0xdead_beef)).unwrap();
/// assert_eq!(ctx.get("rax").unwrap(), RegValue::U64(0xdead_beef));
/// ```
pub mod register_context;
/// Memory search over a live process or recorded memory snapshot: scan for byte
/// patterns, UTF-8/UTF-16 strings, integer values, and cross-reference candidates
/// within a given address range.
///
/// # Example
/// ```
/// use rustre_debug::memory_search::SearchPattern;
/// // Patterns are matched over a snapshot plus its region table by
/// // `search_all_regions`.
/// let pattern = SearchPattern::Bytes(vec![0x90, 0x90]);
/// assert!(matches!(pattern, SearchPattern::Bytes(_)));
/// ```
pub mod memory_search;
/// Conditional breakpoints: attach a boolean expression predicate to a breakpoint
/// address so the target is only interrupted when the expression evaluates true
/// (e.g. `rdi == 0`, `*(u32*)(rbp-4) > 10`).
///
/// Evaluated by [`expression_evaluator`] at each hit, resuming automatically
/// when the condition is false — no debugger round-trip to the IDE.
///
/// # Errors
/// Returns an error if the condition expression fails to parse or cannot be
/// evaluated against the current register/memory state.
pub mod conditional_breakpoint;
/// High-level watchpoint manager: wraps [`watchpoint_engine`] with named-slot
/// allocation, enable/disable, and a report of the currently active watchpoints.
///
/// Tracks per-slot metadata (address, size, type, condition, hit count) and
/// provides a unified `set` / `remove` / `list` API for both hardware and
/// software watchpoints.
pub mod watchpoint_manager;
/// Deterministic capture/replay session recorder: records every debug event
/// (register snapshots, memory snapshots, user annotations) to a bounded,
/// seekable `VecDeque`-backed log so a session can be rewound and replayed
/// step-by-step for post-mortem analysis.
///
/// Intentionally distinct from [`debug_session_manager`], which is the live
/// session controller.
pub mod debug_session_recorder;
/// Omniscient backward-dataflow query layer (Pernosco-style `who_wrote`/
/// `trace_origin`) built on top of `time_travel_debug` + `debug_session_recorder`.
pub mod omniscient_query;
/// Scripting API surface designed for LLM tool-calling (ChatDBG-style),
/// exposing breakpoints/memory/registers/type info/the omniscient query.
pub mod scripting_api;
/// Bridges a live [`Debugger`] backend into [`scripting_api::ScriptContext`],
/// so `scripting_api::dispatch` can drive a real process, not just
/// `scripting_api::MockScriptContext`.
pub mod live_script_context;
/// Execution heatmap/flamegraph over a session log or TTD timeline: buckets
/// stop/breakpoint/watchpoint hits by address across chronological windows.
pub mod execution_heatmap;
/// AI root-cause assistant: causal slices (via `omniscient_query::trace_origin`)
/// plus a Bayesian pre-filter ranking writer PCs against a good-run baseline.
pub mod root_cause_assistant;
/// Coredump-farm triage: cluster batch-ingested crash backtraces by
/// stack-hash signature and rank by frequency.
pub mod coredump_triage;
/// Cross-run patch/binary diffing: correlate symbol tables across two builds
/// and migrate breakpoint addresses from an old binary to a new one.
pub mod binary_diff;
/// Race-condition/concurrency replay: post-hoc, ThreadSanitizer-style conflict
/// detection over a recorded chronological memory-access trace.
pub mod race_detector;
/// Cheat-aware watchpoints: classify `who_wrote` results by writer provenance
/// (original baselined module vs. tampered/foreign code).
pub mod provenance_classifier;
/// Retroactive print (Pernosco-style): annotate an address with a format string
/// and expression args; replay the trace and render one output line per write
/// without re-running the target.
pub mod retroactive_print;
/// Live invariant tracking: evaluate predicate expressions (`value OP rhs`)
/// against every write to a watched address across a recorded trace, returning
/// every violation event.  Unique: no shipping debugger (WinDbg, GDB, rr,
/// x64dbg, IDA) combines watchpoints with expression predicates and scans
/// history rather than interrupting execution on every write.
pub mod live_invariant;
/// Semantic diff between two execution traces: find the globally earliest
/// divergence point (address + writer PC) between a reference run and a
/// second run.  No shipping debugger compares two traces; closest prior
/// work is Chronon (academic, unavailable as a tool).
pub mod semantic_run_diff;
/// Causal contribution ranking: annotate each write in a backward causal
/// slice with a numeric contribution score (Wang et al. depth/fan-in/terminal
/// heuristic), so the user sees not just *what* wrote a bad value but *how
/// much* each write is responsible.
pub mod causal_contribution;
/// Windows minidump (.dmp) file parser: threads, registers, exception record,
/// module list, memory regions — extracted from raw bytes without WinDbg.
pub mod minidump_analysis;
/// x64 SEH / `.pdata` parser: enumerates RUNTIME_FUNCTION entries, decodes
/// UNWIND_INFO (prolog codes, handler kind, chained unwind), and builds a
/// searchable `SehIndex` — equivalent to WinDbg `.fnent` but for entire PEs.
pub mod seh_traversal;
/// Microsoft Symbol Server PDB downloader: resolves `PdbIdentity` from a PE's
/// CodeView RSDS record and downloads the matching PDB to a local cache,
/// mirroring WinDbg's `.symfix`/`.reload /f` without a live debug session.
pub mod pdb_symbol_server;
/// Windows heap allocation tracker: instruments `RtlAllocateHeap`,
/// `RtlFreeHeap`, and `RtlReAllocateHeap` breakpoints to build a live
/// allocation map with call stacks — equivalent to `!heap -p` but chronological
/// and available to any `Debugger` backend via LLM tool-calls.
pub mod heap_tracker;
/// Declarative dataflow query DSL over the omniscient index
/// (`TRACE ... BACKWARD [UNTIL PC ...]`, `FIND WRITES TO ... BEFORE ...`).
pub mod dataflow_dsl;
/// Natural-language query front-end: translates free-form questions into typed
/// debug queries and executes them against an [`omniscient_query::OmniscientIndex`].
/// Rule-based translator handles ~10 common patterns; optional LLM-assisted
/// path (feature `nl-query-llm`) routes unmatched questions to the Anthropic API.
pub mod nl_query;
/// Pure DWARF CFI (`.eh_frame`) parsing — CIE/FDE headers, LEB128, and a
/// bounded unwind-opcode interpreter, used by [`linux_debugger`]'s
/// `backtrace` to unwind past frames without a preserved frame pointer
/// (mirrors the x64 `UNWIND_INFO` interpreter `windows_debugger` uses for
/// the same purpose). No OS-specific code — deliberately NOT `cfg`-gated
/// to `target_os = "linux"` like `linux_debugger` itself, so its pure
/// byte-buffer parsers stay unit-testable on every host this crate builds
/// on, not just Linux.
pub mod dwarf_cfi;
/// Architecture-aware next-instruction address and program-counter naming —
/// the shared primitive a single-step / step-over path needs so it cannot be
/// written per-backend against a hardcoded x86-64 assumption (A64 is a fixed
/// 4 bytes; the x86 length decoder on A64 bytes returns something else).
/// Compiled on every platform, so it is testable everywhere.
pub mod instr_step;
/// Linux `/proc/<pid>` snapshot reader: maps, status, stat, wchan, syscall,
/// and open file-descriptor table — captured at-rest without a ptrace stop.
#[cfg(target_os = "linux")]
pub mod proc_snapshot;
/// Mozilla `rr` record/replay trace directory parser: lists trace sessions,
/// reads format version, task TIDs, captured binary names, and event-stream
/// sizes without running `rr`.
#[cfg(target_os = "linux")]
pub mod rr_trace;
/// Linux `perf_event_open(2)` hardware performance counter interface:
/// CPU cycles, instructions, cache misses, branch mispredictions, page faults —
/// Breakpoints on modules that are not mapped yet, armed at load time
/// (gdb/lldb "pending breakpoints", WinDbg `bu`).
pub mod pending_breakpoint;
/// with a `measure()` convenience wrapper and a multi-counter snapshot API.
#[cfg(target_os = "linux")]
pub mod perf_events;
/// Simplified eBPF uprobe/kprobe attachment: load a BPF hit-counter program
/// and attach it to a user-space or kernel probe via tracefs + perf_event_open,
/// without requiring `libbpf` or external crates.
#[cfg(target_os = "linux")]
pub mod ebpf_uprobe;
/// Concrete Windows [`Debugger`] backend using the native Win32 debug API
/// directly (`DebugActiveProcess`/`WaitForDebugEvent`/`ReadProcessMemory`/...) —
/// no sub-crate dependency, per project policy: this hub crate must not depend
/// on other debugger implementations, only on OS APIs.
#[cfg(windows)]
pub mod windows_debugger;
/// Concrete Linux [`Debugger`] backend using `ptrace(2)` directly — same
/// no-sub-crate-dependency rule as [`windows_debugger`].
#[cfg(target_os = "linux")]
pub mod linux_debugger;
/// Concrete macOS [`Debugger`] backend: BSD `ptrace(2)` for lifecycle/
/// stepping + Mach `task_for_pid`/VM/thread APIs for memory and registers.
/// Same no-sub-crate-dependency rule as [`windows_debugger`]/[`linux_debugger`].
/// **Unverified — no macOS host in this environment; see the module doc.**
#[cfg(target_os = "macos")]
pub mod macos_debugger;
/// Pure Mach-O image-size arithmetic used by [`macos_debugger`]. Deliberately
/// NOT `cfg`-gated: `macos_debugger` is `#![cfg(target_os = "macos")]`, so its
/// own `#[cfg(test)] mod tests` never compiles off macOS. Hosting this logic
/// here is what makes it — and its tests — actually run on Windows and Linux.
pub mod macho_image_size;
/// Pure stop-classification and map-labelling logic used by [`macos_debugger`],
/// hosted here for exactly the same reason as [`macho_image_size`]: outside
/// this module it would live behind `#![cfg(target_os = "macos")]` and never
/// be compiled, let alone tested, on any host in this environment.
pub mod macos_debugger_pure;

/// Opt-4: memory-mapped session snapshot files — zero-copy load of large
/// serialised session recordings via `memmap2`.
pub mod snapshot_mmap;

/// WinDbg TTD `.run` / `.idx` trace backend — parses the on-disk format and
/// implements [`time_travel_debug::TtdBackend`] for real WinDbg TTD traces.
pub mod windbg_ttd_backend;

/// Mozilla `rr` replay backend — spawns `rr replay --serve-address` and speaks
/// GDB Remote Serial Protocol over TCP to implement
/// [`time_travel_debug::TtdBackend`].
pub mod rr_backend;

/// Auto-detection and opening of TTD traces — detects WinDbg TTD vs rr and
/// returns the appropriate boxed [`time_travel_debug::TtdBackend`].
pub mod ttd_open;

/// Apple (macOS/iOS) debugger backend, migrated in-tree from the former
/// `rustre-debug-apple` crate. Nothing here is gated on
/// `cfg(target_os = "macos")`: it is byte/register math plus an RSP wire
/// layer, so it compiles and unit-tests on any host.
pub mod ios;

/// Architecture-aware software-breakpoint implant primitives (patch bytes,
/// alignment, PC-rewind rule). Pure functions over `Architecture`, with no
/// `cfg`, so they compile and are tested on every host — unlike the three OS
/// backends, which write the literal x86 `0xCC` under an OS gate (iter 332).
pub mod trap_implant;

/// Historical registry sketch — kept for reference only, permanently
/// disabled, and **stale**: it names a `rustre-debug-registry` sibling crate
/// and per-OS sub-crates (`rustre-debug-linux`, `rustre-debug-macos`,
/// `rustre-debug-windows`, ...) that no longer exist in the active
/// workspace (see `oldcreates/rustre-debug-registry`, disabled 2026-07-12
/// per the root `Cargo.toml`'s workspace-members comment).
///
/// **The actual, current, single dispatch point is
/// `rustre-mcp-tools/src/tools/debug.rs::make_backend()`** — it directly
/// constructs the right in-hub backend
/// (`windows_debugger::WindowsDebugger` / `linux_debugger::LinuxDebugger` /
/// `macos_debugger::MacosDebugger`) behind a `#[cfg(...)]` per OS, same
/// pattern this module's dead code was sketching before the sub-crates were
/// retired. Add new OS arms there, not here.
// Kept disabled via `cfg(any())`: pulling the (nonexistent) sub-crates back
// in here would re-introduce the workspace path-dep cycle that motivated
// retiring them (each sub-crate depended on this hub for the `Debugger`
// trait).
#[cfg(any())]
pub mod registry {
    use super::Debugger;
    use rustre_debug_frida::FridaDebugSession;
    use rustre_debug_gdb::GdbDebugger;
    use rustre_debug_kgdb::KgdbSession;
    use rustre_debug_linux::LinuxDebugger;
    use rustre_debug_macos::MacosDebugger;
    use rustre_debug_unicorn::UnicornDebugger;
    use rustre_debug_windbg::WinDbgSession;
    use rustre_debug_windows::WindowsDebugger;

    /// Construct one boxed instance of every wired backend.
    ///
    /// Callers can iterate over the returned vector to query
    /// [`Debugger::name`] / [`Debugger::supported_architectures`] and pick
    /// the appropriate backend for their target.
    #[must_use]
    pub fn all() -> Vec<Box<dyn Debugger>> {
        vec![
            Box::new(FridaDebugSession::default()),
            Box::new(GdbDebugger::default()),
            Box::new(KgdbSession::default()),
            Box::new(LinuxDebugger::default()),
            Box::new(MacosDebugger::default()),
            Box::new(UnicornDebugger::default()),
            Box::new(WinDbgSession::default()),
            Box::new(WindowsDebugger::default()),
        ]
    }
}

/// Which `DR0`-`DR3` slot fired, from `DR6`.
///
/// A hardware watchpoint hit does NOT arrive as its own event on x86: the CPU
/// raises the same trap as a single step (`EXCEPTION_SINGLE_STEP` on Windows,
/// `SIGTRAP` on Linux), and only `DR6`'s low four bits say which slot — or
/// none, for a real single step. Without consulting it, an armed watchpoint
/// fires and is reported as a plain single step: the debugger watches the
/// address correctly and then throws the answer away.
///
/// Bits 0-3 are `B0`-`B3`. The lowest set bit wins when several fired at once;
/// reporting one hit is honest, inventing a combined one is not.
pub(crate) fn x86_watchpoint_hit_slot(dr6: u64) -> Option<u8> {
    (0u8..4).find(|n| dr6 & (1u64 << u32::from(*n)) != 0)
}

/// What kind of access slot `slot` was armed for, read back from `DR7`.
///
/// `None` when the slot is not enabled — a `B` bit set for a disabled slot is
/// stale hardware state, not a hit, and must not be reported as one.
pub(crate) fn x86_watchpoint_kind_from_dr7(dr7: u64, slot: u8) -> Option<BreakpointKind> {
    if slot > 3 || dr7 & (1u64 << (2 * u32::from(slot))) == 0 {
        return None;
    }
    match (dr7 >> (16 + 4 * u32::from(slot))) & 0b11 {
        0b00 => Some(BreakpointKind::Hardware),
        0b01 => Some(BreakpointKind::DataWrite),
        // 0b10 is I/O access, which is not something this debugger arms; it is
        // reported as read-or-write rather than guessed at.
        _ => Some(BreakpointKind::DataReadWrite),
    }
}

/// The bytes that make a software breakpoint on THIS architecture.
///
/// Every native backend hard-codes the single x86 byte `0xCC`, and each one
/// refuses outright when built for anything else — an honest refusal, but it
/// means the macOS backend cannot plant a single breakpoint on Apple Silicon,
/// which is most Macs in use. The knowledge was never missing: `ios::arm64`
/// has encoded `BRK #0` all along. What was missing is that the implant path
/// is written around ONE byte: the tracking map stores a `u8`, so a 4-byte
/// trap has nowhere to record what it replaced.
///
/// This is the single place that answers "what is a trap here, and how wide is
/// it", so the implant path has one definition instead of a literal per
/// backend.
///
/// AArch64 traps are `BRK #0` = `0xD420_0000`, little-endian on the wire, and
/// instructions are 4-byte aligned — which is why a 1-byte patch corrupts one
/// rather than replacing it.
///
/// **Stale claim removed (iteration 478):** this comment used to say the
/// tracking map "stores a `u8`, so a 4-byte trap has nowhere to record what it
/// replaced". All three backends have held `HashMap<u64, Vec<u8>>` for some
/// time; the width is no longer the blocker, and leaving the sentence in place
/// would send the next reader to fix something already fixed.
#[cfg(target_arch = "aarch64")]
const ARM64_HOST_TRAP: [u8; 4] = crate::ios::arm64::brk_bytes(0);

/// Turn the byte count a raw memory write returned into a checked result.

///
/// `write_memory_raw` returns how many bytes actually landed, and the
/// breakpoint machinery threw that number away: `?` catches an `Err` but a
/// short `Ok(n)` reads as complete success.
///
/// On x86 a trap is one byte, so a partial write cannot happen. On AArch64 it
/// is FOUR, and a page boundary, a protection change, or a target that dies
/// mid-write can land some of them. The half-written cases are the bad ones in
/// both directions:
/// - planting: part of a `BRK` over part of the original instruction is
///   neither the original nor a trap, and the caller was told the breakpoint
///   is set;
/// - restoring: `remove_breakpoint` untracks the address right after, so the
///   leftover trap bytes become a landmine with nothing left tracking them —
///   the exact hazard that function documents for the failure case, reached
///   through the success path instead.
///
/// `write_memory` already refuses a short write on the public API; this is the
/// same rule for the internal path that the public one is built on.
///
/// # Errors
///
/// [`DebugError::MemoryError`] when fewer than `wanted` bytes landed.
pub fn require_full_write(addr: u64, wrote: usize, wanted: usize) -> Result<(), DebugError> {
    if wrote < wanted {
        return Err(DebugError::MemoryError(
            addr,
            format!("partial write: {wrote} of {wanted} bytes landed"),
        ));
    }
    Ok(())
}

/// The read counterpart of [`require_full_write`].
///
/// Added with the AArch64 trap-length fix: `set_breakpoint` now saves
/// `host_trap_bytes().len()` bytes as the original, and a SHORT read would give
/// a short "original" that `remove_breakpoint` then restores — leaving the tail
/// of the trap in place. That is the same permanent corruption the length fix
/// exists to prevent, arriving through the other door.
///
/// # Errors
/// Returns [`DebugError::MemoryError`] when fewer bytes were read than asked for.
include!(concat!(env!("OUT_DIR"), "/embedded_sources.rs"));

pub fn require_full_read(addr: u64, read: usize, wanted: usize) -> Result<(), DebugError> {
    if read < wanted {
        return Err(DebugError::MemoryError(
            addr,
            format!("partial read: {read} of {wanted} bytes available"),
        ));
    }
    Ok(())
}

#[must_use]
pub(crate) const fn host_trap_bytes() -> &'static [u8] {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        &[0xCC]
    }
    #[cfg(target_arch = "aarch64")]
    {
        // DERIVED, not re-spelled. The literal that used to sit here was
        // justified by "that module is Apple-only" — which is not true:
        // `ios::arm64` is pure arithmetic behind no `cfg`, and
        // `trap_implant`/`arch_breakpoint` both call it from every host and
        // every target this crate builds for. A fourth spelling of one
        // encoding, kept alive by a reason that does not hold.
        &ARM64_HOST_TRAP
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
    {
        &[]
    }
}

/// Alignment a software breakpoint must respect on this architecture.
///
/// x86 instructions are unaligned, so any address is a legal implant site.
/// AArch64 instructions are 4-byte aligned: patching an unaligned address
/// would straddle two instructions and corrupt both.
#[must_use]
pub(crate) const fn host_trap_alignment() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        4
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        1
    }
}

/// Encode one x86 hardware watchpoint into a new `DR7` value.
///
/// The three native backends can already read and write `DR0`–`DR7`, but
/// nothing ever programmed them: `set_watchpoint_sized` fell through to the
/// trait default, which forwards to `set_breakpoint`, which rejects everything
/// that is not `Software`. So every hardware watchpoint request failed with
/// "only software breakpoints are implemented" — an honest error, but a real
/// enterprise gap on all three platforms at once.
///
/// `DR7` layout (Intel SDM Vol. 3B §17.2.4), per slot `n` in `0..=3`:
/// - `L{n}` local-enable at bit `2n`;
/// - `R/W{n}` at bits `16 + 4n`: `01` write-only, `11` read-or-write,
///   `00` execute;
/// - `LEN{n}` at bits `18 + 4n`: `00` = 1 byte, `01` = 2, `11` = 4, `10` = 8.
///
/// `LEN` is NOT the byte count, and the 4/8 encodings are deliberately out of
/// order — writing the count there would arm a watchpoint of the wrong width
/// that still looks armed.
///
/// # Errors
/// [`DebugError::Unsupported`] for a slot above 3, a width other than 1/2/4/8,
/// an address not aligned to its width (the hardware requires it and silently
/// misbehaves otherwise), or a kind that is not a data watchpoint.
pub(crate) fn x86_encode_watchpoint_dr7(
    current_dr7: u64,
    slot: u8,
    addr: u64,
    kind: BreakpointKind,
    size: u8,
) -> Result<u64, DebugError> {
    if slot > 3 {
        return Err(DebugError::Unsupported(format!(
            "x86 has only 4 debug-register slots (DR0-DR3); slot {slot} does not exist"
        )));
    }
    let len_bits: u64 = match size {
        1 => 0b00,
        2 => 0b01,
        4 => 0b11,
        8 => 0b10,
        other => {
            return Err(DebugError::Unsupported(format!(
                "x86 hardware watchpoints cover 1, 2, 4 or 8 bytes, not {other}"
            )));
        }
    };
    if addr % u64::from(size) != 0 {
        return Err(DebugError::Unsupported(format!(
            "a {size}-byte hardware watchpoint must be {size}-byte aligned, but {addr:#x} is not"
        )));
    }
    let rw_bits: u64 = match kind {
        BreakpointKind::DataWrite => 0b01,
        BreakpointKind::DataRead | BreakpointKind::DataReadWrite => 0b11,
        BreakpointKind::Hardware => 0b00,
        BreakpointKind::Software => {
            return Err(DebugError::Unsupported(
                "a software breakpoint is not programmed into the debug registers".into(),
            ));
        }
    };
    // The hardware's rules for these two fields are NARROWER than "a valid LEN
    // and a valid R/W".
    //
    // Intel SDM Vol. 3, Table 17-2: with `R/W = 00` — break on instruction
    // EXECUTION — `LEN` must be `00`. Every other length is documented as
    // undefined, not as "wider". Nothing tied the two together, so
    // `set_watchpoint_sized(addr, BreakpointKind::Hardware, 4)` passed the size
    // validator, encoded as `R/W = 00, LEN = 11`, and went into DR7: a
    // configuration the manual does not define, reachable straight from the
    // public API and from the MCP `kind: "execute"` surface.
    //
    // Refusing beats silently narrowing to one byte: a caller who asked to trap
    // execution across four bytes has misunderstood what the hardware does, and
    // quietly giving them one byte would look like it worked.
    if rw_bits == 0b00 && size != 1 {
        return Err(DebugError::Unsupported(format!(
            "an execution hardware breakpoint covers exactly one byte on x86 (Intel SDM Vol. 3, Table 17-2: R/W=00 requires LEN=00), so a {size}-byte one cannot be programmed"
        )));
    }
    // `LEN = 10` (eight bytes) exists only when the processor is running in
    // 64-bit mode; on a 32-bit target it is reserved, and writing a reserved
    // value into a control register is not a smaller version of working.
    if size == 8 && !cfg!(target_pointer_width = "64") {
        return Err(DebugError::Unsupported(
            "an 8-byte hardware watchpoint needs the 64-bit debug-register encoding (LEN=10), which is reserved on a 32-bit target".into(),
        ));
    }
    let shift = 16 + 4 * u32::from(slot);
    // Clear this slot's old R/W and LEN before writing the new ones, or a
    // re-armed slot ORs into whatever the previous watchpoint left behind.
    let mut dr7 = current_dr7 & !(0b1111u64 << shift);
    dr7 |= rw_bits << shift;
    dr7 |= len_bits << (shift + 2);
    dr7 |= 1u64 << (2 * u32::from(slot));
    Ok(dr7)
}

/// The first `DR0`–`DR3` slot whose local-enable bit is clear in `dr7`.
///
/// `None` when all four are in use — the caller must report that rather than
/// silently overwriting somebody else's watchpoint.
pub(crate) fn x86_free_watchpoint_slot(dr7: u64) -> Option<u8> {
    (0u8..4).find(|n| dr7 & (1u64 << (2 * u32::from(*n))) == 0)
}

/// Encode an AArch64 watchpoint control register (`DBGWCR<n>_EL1`).
///
/// Apple Silicon has no `DR0`-`DR7`. Its hardware watchpoints are 16 pairs of
/// `DBGWVR` (the address) and `DBGWCR` (the control word), reached on Darwin
/// through `thread_get_state(ARM_DEBUG_STATE64)`. The control word this builds:
///
/// * bit 0 — `E`, enable.
/// * bits 2:1 — `PAC`, privilege access control. `0b10` = EL0, i.e. watch the
///   USER-mode accesses of the traced program. `0b00` would arm a watchpoint
///   that no userspace access can ever trigger — armed and silent, the failure
///   mode this crate hunts.
/// * bits 4:3 — `LSC`, load/store control: `01` load, `10` store, `11` both.
/// * bits 12:5 — `BAS`, byte address select: one bit per byte of the aligned
///   doubleword the watchpoint covers. This is what carries the caller's WIDTH,
///   and it is a mask, not a length code — the x86 `LEN` field's encoding does
///   not transfer.
///
/// Returns `None` for a request the hardware cannot express, rather than a
/// nearby approximation: silently watching 8 bytes because 3 were asked for
/// would report a hit the caller never asked about, and silently watching 1
/// would miss the rest.
pub(crate) fn arm64_encode_watchpoint_wcr(
    addr: u64,
    kind: BreakpointKind,
    size: u8,
) -> Option<u64> {
    let lsc: u64 = match kind {
        BreakpointKind::DataRead => 0b01,
        BreakpointKind::DataWrite => 0b10,
        BreakpointKind::DataReadWrite => 0b11,
        // Execution is a BREAKpoint (`DBGBVR`/`DBGBCR`), a different register
        // file entirely; answering with a watchpoint word would arm the wrong
        // hardware.
        BreakpointKind::Software | BreakpointKind::Hardware => return None,
    };
    if !matches!(size, 1 | 2 | 4 | 8) {
        return None;
    }
    // The watched region must not straddle the aligned doubleword `BAS`
    // indexes: a 4-byte watch at offset 6 has no representable mask.
    let offset = addr & 7;
    if offset % u64::from(size) != 0 {
        return None;
    }
    let bas = ((1u64 << size) - 1) << offset;
    Some(1 | (0b10 << 1) | (lsc << 3) | (bas << 5))
}

/// The address register that goes with [`arm64_encode_watchpoint_wcr`].
///
/// `DBGWVR` holds the DOUBLEWORD-aligned base; the low three bits are RES0 and
/// the byte within it is selected by `BAS`. Writing the caller's unaligned
/// address straight in is the classic way to arm a watchpoint that never fires.
pub(crate) const fn arm64_watchpoint_wvr(addr: u64) -> u64 {
    addr & !7
}

/// Program an AArch64 EXECUTION breakpoint pair from a `dr` slot.
///
/// The twin of [`arm64_watchpoint_from_dr_slot`], for the case that one
/// deliberately refuses: `rw == 0b00` in `DR7` is an execution breakpoint on
/// x86, and AArch64 puts those in `DBGBVR`/`DBGBCR` — a different register
/// file, reached through a different regset (`NT_ARM_HW_BREAK`).
///
/// Returns `None` when the slot is disabled in `DR7`, when it is a DATA slot
/// (which belongs to the watchpoint pair, not here), or when the address is not
/// 4-byte aligned. That last one is a refusal and not a rounding: `DBGBVR`'s
/// low two bits are RES0, so quietly aligning it down would arm a breakpoint on
/// a different instruction than the caller named.
pub(crate) fn arm64_breakpoint_from_dr_slot(addr: u64, dr7: u64, slot: u8) -> Option<(u64, u64)> {
    if dr7 & (1u64 << (2 * u32::from(slot))) == 0 {
        return None;
    }
    let shift = 16 + 4 * u32::from(slot);
    if (dr7 >> shift) & 0b11 != 0b00 {
        // A data slot. The watchpoint pair expresses it; this one must not,
        // or the same slot would be armed twice in two register files.
        return None;
    }
    if addr & 0b11 != 0 {
        return None;
    }
    use crate::ios::arm64::hw::bits as f;
    // ENABLE, PRIV = EL0 (unprivileged), BAS = all four bytes of the
    // instruction, BT = 0 (unlinked address match). Byte-address-select is
    // `0b1111` for a breakpoint, four bits wide, where a watchpoint's is eight.
    let bcr = u64::from(f::ENABLE | (0b10 << f::PRIV_SHIFT) | (0b1111 << f::BAS_SHIFT));
    Some((addr, bcr))
}

/// The inverse: describe an armed `DBGBVR`/`DBGBCR` pair in the `dr`
/// vocabulary.
///
/// Same contract as [`dr_slot_from_arm64_watchpoint`] and for the same reason:
/// the engine reads `DR7` to find a free slot and to recognise what it already
/// armed, so a read-back that does not match the write would make `set` keep
/// allocating slots and `disarm` never recognise its own work.
pub(crate) fn dr_slot_from_arm64_breakpoint(bvr: u64, bcr: u64, slot: u8) -> Option<(u64, u64)> {
    if bcr & 1 == 0 {
        return None;
    }
    // Enabled, `rw = 0b00` (execute), `len = 0b00` (one byte). x86 requires an
    // execution breakpoint to be encoded with exactly that length; anything
    // else is an invalid DR7 the engine would not have written.
    let enable = 1u64 << (2 * u32::from(slot));
    Some((bvr, enable))
}

/// First disabled slot among the 16 `DBGWCR` values, or `None` if all are armed.
pub(crate) fn arm64_free_watchpoint_slot(wcr: &[u64]) -> Option<usize> {
    wcr.iter().position(|w| w & 1 == 0)
}

/// Which slot, if any, already watches `addr`.
///
/// Re-arming an address must re-use its slot; without this the same address
/// would consume a second of the sixteen and the first would stay armed with
/// nothing tracking it — the defect the x86 path already fixed.
pub(crate) fn arm64_watchpoint_slot_for(wvr: &[u64], wcr: &[u64], addr: u64) -> Option<usize> {
    let base = arm64_watchpoint_wvr(addr);
    wcr.iter()
        .zip(wvr.iter())
        .position(|(c, v)| c & 1 != 0 && *v == base)
}

/// Translate one x86 debug-register slot into the AArch64 pair that means the
/// same thing.
///
/// The watchpoint engine in every backend speaks `dr0`-`dr3` + `DR7`. Apple
/// Silicon has no such registers, but it has the same IDEA: an address plus a
/// control word saying enabled / read-or-write / how wide. Rather than fork the
/// engine — `set_watchpoint_sized`, `disarm_watchpoint_registers`,
/// `disarm_all_hardware_watchpoints` and `rearm_watchpoints_on_new_threads` are
/// all shared, byte-identical across the backends, and forking them is exactly
/// the divergence this crate keeps paying for — the macOS backend translates at
/// the register boundary and everything above it stays common.
///
/// Returns `None` when the slot is disabled in `DR7`, which is how the caller
/// distinguishes "clear this pair" from "program it".
pub(crate) fn arm64_watchpoint_from_dr_slot(
    addr: u64,
    dr7: u64,
    slot: u8,
) -> Option<(u64, u64)> {
    if dr7 & (1u64 << (2 * u32::from(slot))) == 0 {
        return None;
    }
    let shift = 16 + 4 * u32::from(slot);
    let rw = (dr7 >> shift) & 0b11;
    let len = (dr7 >> (shift + 2)) & 0b11;
    // x86 encodes the width as a code, not a count: 00=1, 01=2, 11=4, 10=8.
    // Reading it as a length is the classic mistake and produces a watchpoint
    // four times too narrow.
    let size: u8 = match len {
        0b00 => 1,
        0b01 => 2,
        0b11 => 4,
        _ => 8,
    };
    let kind = match rw {
        0b01 => BreakpointKind::DataWrite,
        0b11 => BreakpointKind::DataReadWrite,
        // 0b00 is an EXECUTION breakpoint on x86. AArch64 puts those in
        // `DBGBVR`/`DBGBCR`, so there is no watchpoint pair that expresses it;
        // saying so beats arming a data watchpoint that would fire on the
        // wrong events.
        _ => return None,
    };
    let wcr = arm64_encode_watchpoint_wcr(addr, kind, size)?;
    Some((arm64_watchpoint_wvr(addr), wcr))
}

/// The inverse: describe an armed AArch64 pair in the `dr` vocabulary.
///
/// The engine reads `DR7` to find a free slot and to recognise the address it
/// already watches, so what it reads back must match what it wrote — otherwise
/// `set` would keep allocating new slots for the same address and `disarm`
/// would never recognise its own work.
pub(crate) fn dr_slot_from_arm64_watchpoint(wvr: u64, wcr: u64, slot: u8) -> Option<(u64, u64)> {
    if wcr & 1 == 0 {
        return None;
    }
    let bas = (wcr >> 5) & 0xff;
    let size = bas.count_ones();
    let offset = bas.trailing_zeros();
    let len: u64 = match size {
        1 => 0b00,
        2 => 0b01,
        4 => 0b11,
        8 => 0b10,
        _ => return None,
    };
    // This register came from the HARDWARE, not from us.
    //
    // `count_ones` and `trailing_zeros` describe ANY bit pattern, and a
    // watchpoint this crate did not arm — one left by another debugger, an
    // earlier session, or the OS — can hold a `BAS` we would never produce.
    // Without these two checks the function answered anyway:
    //
    // * `BAS = 0b1000_0001` (bytes 0 AND 7) counts as two bytes at offset 0 and
    //   came back as a 2-byte watchpoint on bytes 0-1 — a range the hardware is
    //   not watching;
    // * `BAS = 0b0011_1100` (bytes 2-5) is contiguous but not naturally
    //   aligned, and `DR7` has no spelling for it: an x86 4-byte watchpoint is
    //   4-byte aligned by construction.
    //
    // The answer flows into the engine AS `DR7`, which uses it to pick free
    // slots and to recognise the watchpoints it owns, so a plausible wrong
    // description is acted on. Refusing is the same honest answer this function
    // already gives a load-only watchpoint just below.
    if bas != (((1u64 << size) - 1) << offset) {
        return None;
    }
    if offset % size != 0 {
        return None;
    }
    let rw: u64 = match (wcr >> 3) & 0b11 {
        0b10 => 0b01,
        0b11 => 0b11,
        // A load-only watchpoint has no x86 spelling: `DR7`'s `RW` offers
        // write-only and read-or-write, never read-only. Reporting it as
        // read/write would be a lie the engine then acts on.
        _ => return None,
    };
    let shift = 16 + 4 * u32::from(slot);
    let bits = (1u64 << (2 * u32::from(slot))) | (rw << shift) | (len << (shift + 2));
    Some((wvr | u64::from(offset), bits))
}

/// Keeps an address registered in a set for as long as the guard lives.
///
/// The backends mark the address `run_to_return` is waiting for so a user's
/// breakpoint condition cannot filter out a stop the DEBUGGER arranged. Marking
/// it with a plain insert/remove pair leaks: `run_to_return` propagates errors
/// out of its wait loop with `?`, and a target that dies mid-step therefore
/// leaves the address marked FOREVER — from then on the user's condition at that
/// address is silently ignored, which is the same silent-disabling defect the
/// condition work exists to prevent.
///
/// A guard rather than two statements, for the reason `ios::apple_debugger`'s
/// `ResumeGuard` already documents: an early `?` or a panic must not be able to
/// leave the flag stuck.
pub(crate) struct AddressGuard<'a> {
    set: &'a parking_lot::Mutex<std::collections::HashSet<u64>>,
    addr: u64,
}

impl<'a> AddressGuard<'a> {
    /// Insert `addr` now; remove it when the guard drops.
    pub(crate) fn new(
        set: &'a parking_lot::Mutex<std::collections::HashSet<u64>>,
        addr: u64,
    ) -> Self {
        set.lock().insert(addr);
        Self { set, addr }
    }
}

impl Drop for AddressGuard<'_> {
    fn drop(&mut self) {
        self.set.lock().remove(&self.addr);
    }
}

/// Route a caller's write around the software breakpoints it overlaps.
///
/// The dual of [`unpatch_planted_breakpoints`]. A write covering an address
/// where our `0xCC` sits has two wrong outcomes if it goes through unchanged:
/// it overwrites the trap, so a breakpoint still listed as enabled silently
/// stops firing; and the byte it replaced is still recorded as "the original",
/// so removing the breakpoint later restores the STALE byte and quietly undoes
/// the caller's write.
///
/// The fix is what GDB and LLDB do: the new byte becomes the saved original —
/// what the target will see once the breakpoint is gone — while `0xCC` stays
/// planted so the breakpoint keeps working.
///
/// Returns the buffer to actually write and the `(address, byte)` pairs whose
/// saved original must be updated. `is_planted` reports whether an ENABLED
/// breakpoint of ours sits at that address.
pub(crate) fn redirect_writes_over_breakpoints(
    base: u64,
    data: &[u8],
    trap_byte_at: impl Fn(u64) -> Option<u8>,
) -> (Vec<u8>, Vec<(u64, u8)>) {
    let mut to_write = data.to_vec();
    let mut new_originals = Vec::new();
    for (i, slot) in to_write.iter_mut().enumerate() {
        let a = base.wrapping_add(i as u64);
        // The TRAP BYTE FOR THIS ADDRESS, supplied by the caller, not a
        // hard-coded `0xCC`.
        //
        // A literal int3 is right only on x86. An AArch64 trap is the four
        // bytes of `BRK #0`, so writing `0xCC` over one of them left three
        // quarters of a `BRK` and one byte of garbage: an instruction that is
        // no longer a trap, in a breakpoint the debugger still lists as
        // enabled and still believes it can remove. The bug was invisible here
        // because the hosts this crate is developed on are x86 — the two
        // Apple targets and any AArch64 Linux would have hit it.
        if let Some(trap) = trap_byte_at(a) {
            new_originals.push((a, *slot));
            *slot = trap;
        }
    }    (to_write, new_originals)
}

/// Undo software-breakpoint patches in a buffer just read from the target.
///
/// A planted software breakpoint replaces the first byte of an instruction
/// with `0xCC`, and `read_memory` returns exactly what is in the process — the
/// patch included. Any code that DECODES those bytes therefore decodes `int3`
/// (a one-byte instruction) instead of the real one. `step_over` does exactly
/// that to compute the return address, so a breakpoint sitting on the
/// instruction being stepped over turned a 5-byte `call` into a length of 1
/// and put the return breakpoint one byte into the middle of it.
///
/// It never fails and never reports: an address with no planted breakpoint is
/// left untouched, so callers can apply it unconditionally.
///
/// `original_at` returns the byte a breakpoint replaced at that address, or
/// `None` when nothing of ours is planted there.
pub(crate) fn unpatch_planted_breakpoints(
    base: u64,
    buf: &mut [u8],
    original_at: impl Fn(u64) -> Option<u8>,
) {
    for (i, slot) in buf.iter_mut().enumerate() {
        // `wrapping_add` so a buffer read at the very top of the address
        // space cannot panic here; a wrapped address simply matches nothing.
        if let Some(original) = original_at(base.wrapping_add(i as u64)) {
            *slot = original;
        }
    }
}


use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as FmtWrite;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Instant;

use parking_lot::RwLock;
use rustre_core::address::Address;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by any [`Debugger`] implementation.
#[derive(Debug, thiserror::Error)]
pub enum DebugError {
    #[error("not attached to process")]
    NotAttached,
    #[error("process not found: pid {0}")]
    ProcessNotFound(u32),
    #[error("breakpoint already exists at {0:#x}")]
    BreakpointExists(u64),
    #[error("breakpoint not found at {0:#x}")]
    BreakpointNotFound(u64),
    #[error("memory access error at {0:#x}: {1}")]
    MemoryError(u64, String),
    #[error("register access error: {0}")]
    RegisterError(String),
    #[error("step error: {0}")]
    StepError(String),
    #[error("launch error: {0}")]
    LaunchError(String),
    #[error("detach error: {0}")]
    DetachError(String),
    #[error("unsupported operation: {0}")]
    Unsupported(String),
    #[error("os error: {0}")]
    Os(String),
    #[error("timeout")]
    Timeout,
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    /// The trace file is corrupt or unreadable.
    #[error("trace corrupt: {0}")]
    TraceCorrupt(String),
    /// The PDB/symbol server is unreachable.
    #[error("symbol server unreachable: {0}")]
    SymbolServerUnreachable(String),
    /// The `rr` tool is not installed or not on PATH.
    #[error("rr not installed: {0}")]
    RrNotInstalled(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// Process / Thread identifiers
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque process identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct ProcessId(pub u32);

/// Opaque thread identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct ThreadId(pub u32);

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PID({})", self.0)
    }
}

impl fmt::Display for ThreadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TID({})", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegisterSet
// ─────────────────────────────────────────────────────────────────────────────

/// Architecture-agnostic snapshot of all registers for one thread.
#[derive(Debug, Clone, Default)]
pub struct RegisterSet {
    /// Named register → 64-bit value.
    pub regs: HashMap<String, u64>,
    /// Program counter.
    pub pc: u64,
    /// Stack pointer.
    pub sp: u64,
    /// Frame pointer (if available on this architecture).
    pub fp: Option<u64>,
    /// Link / return-address register (e.g. LR on ARM).
    pub lr: Option<u64>,
}

/// Every sub-register name [`sub_register_of`] understands.
///
/// Used to populate a condition-evaluation context: the map holds only the
/// full-width names a backend read from the OS, so the narrow names have to be
/// derived from them or a condition naming one cannot be evaluated at all.
pub const SUB_REGISTER_NAMES: &[&str] = &[
    "eax", "ax", "al", "ah", "ebx", "bx", "bl", "bh", "ecx", "cx", "cl", "ch", "edx", "dx", "dl",
    "dh", "esi", "si", "edi", "di", "ebp", "bp", "esp", "sp", "r8d", "r8w", "r8b", "r9d", "r9w",
    "r9b", "r10d", "r10w", "r10b", "r11d", "r11w", "r11b", "r12d", "r12w", "r12b", "r13d", "r13w",
    "r13b", "r14d", "r14w", "r14b", "r15d", "r15w", "r15b", "w0", "w1", "w2", "w3", "w4", "w5",
    "w6", "w7", "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15", "w16", "w17", "w18", "w19",
    "w20", "w21", "w22", "w23", "w24", "w25", "w26", "w27", "w28", "w29", "w30",
];

/// Resolve a sub-register name to `(full-width parent, shift, mask)`.
///
/// The shift is what makes this more than a table of masks: `ah`, `bh`, `ch`
/// and `dh` are bits **15:8**, not the low byte. Treating them as another name
/// for `al`/`bl`/`ch`… returns a plausible byte that belongs to a different
/// half of the register — the kind of answer that is never questioned because
/// it looks like data.
#[must_use]
/// One thing a backend can or cannot do, with the reason it cannot.
///
/// `supported: false` is the point of this type. A capability that is simply
/// absent from an API is indistinguishable from one that is present and never
/// triggered, and a caller cannot wait correctly for either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendCapability {
    /// Stable identifier, e.g. `"thread_events"`.
    pub name: &'static str,
    /// Whether this backend can do it AT ALL on this host.
    pub supported: bool,
    /// Why not, in the caller's terms. Empty when supported.
    ///
    /// Not a log line: this is what an operator reads instead of waiting for
    /// an event that cannot arrive, so it names the platform reason.
    pub because: &'static str,
}

/// What the backend compiled into this binary can and cannot do.
///
/// Every entry is MEASURED, not aspirational. Where a capability is missing the
/// reason is a platform fact, not a to-do: publishing "not yet implemented"
/// where the truth is "the OS has no such notification" would send a caller
/// looking for a workaround that does not exist.
///
/// Deliberately compiled per target rather than probed at runtime: these are
/// properties of the backend that IS built, and a runtime probe would have to
/// invent an answer before a process is attached.
#[must_use]
pub fn backend_capabilities() -> &'static [BackendCapability] {
    #[cfg(target_os = "windows")]
    {
        &[
            BackendCapability {
                name: "thread_events",
                supported: true,
                because: "",
            },
            // GATED, because the backend gates it. `set_watchpoint_sized`
            // refuses off x86 — "this backend programs the x86 debug
            // registers" — while this list declared `true` unconditionally, so
            // on Windows-on-ARM the API promised what the next call refuses.
            //
            // Same defect as the macOS `fault_address` corrected in 595, and
            // both were introduced together in 577. Declared with `cfg!`, which
            // reads the architecture this binary was compiled for exactly as
            // the backend does, so the two cannot drift by construction rather
            // than by anyone remembering to keep them in step.
            //
            // Windows-on-ARM CAN do this — its ARM64 CONTEXT carries
            // Bcr/Bvr/Wcr/Wvr, and Linux (570) and macOS both translate to
            // their equivalents. It is not implemented yet, and until it is,
            // saying so is the honest answer.
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            BackendCapability {
                name: "hardware_watchpoints",
                supported: true,
                because: "",
            },
            #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
            BackendCapability {
                name: "hardware_watchpoints",
                supported: false,
                because: "this backend programs the x86 debug registers, which this                           architecture does not have. Windows-on-ARM exposes Bcr/Bvr/Wcr/Wvr                           in its ARM64 CONTEXT and the translation is not written yet; poll                           or use a software breakpoint instead of waiting on a watchpoint                           that cannot be armed.",
            },
            BackendCapability {
                name: "fault_address",
                supported: true,
                because: "",
            },
        ]
    }
    #[cfg(target_os = "linux")]
    {
        &[
            BackendCapability {
                name: "thread_events",
                supported: true,
                because: "",
            },
            BackendCapability {
                name: "hardware_watchpoints",
                supported: true,
                because: "",
            },
            BackendCapability {
                name: "fault_address",
                supported: true,
                because: "",
            },
        ]
    }
    #[cfg(target_os = "macos")]
    {
        &[
            // Measured, not assumed: `StopReason::ThreadCreate` appears 5 times
            // in the Windows backend, 18 in the Linux one and ZERO here.
            BackendCapability {
                name: "thread_events",
                supported: false,
                because: "Mach has no equivalent of PTRACE_O_TRACECLONE, so no stop is                           delivered when a thread is created. A client must poll threads()                           instead of waiting for an event that cannot arrive.",
            },
            BackendCapability {
                name: "hardware_watchpoints",
                supported: true,
                because: "",
            },
            // CORRECTED IN 595. 577 published this as unsupported, reasoning
            // that the struct "would come from __far via thread_get_state,
            // which mach2 does not expose". The premise held; the conclusion
            // did not — this backend already hand-declares what mach2 omits,
            // `ArmDebugState64` being the precedent — so the capability was
            // reachable by the file's own pattern and I had declared it absent.
            // A false "unsupported" is worse than an unimplemented feature:
            // this list exists so a caller can trust it.
            BackendCapability {
                name: "fault_address",
                supported: true,
                because: "",
            },
        ]
    }
    // iOS is a REAL backend here (`src/ios`, GDB Remote Serial Protocol to
    // debugserver), not an unsupported host. Iteration 577 shipped only three
    // arms, so this target fell through to the empty slice below and published
    // NOTHING — the exact silence 577 existed to remove, on the platform where
    // an operator can least afford it. Measured red on the iOS-simulator CI
    // row, which is why that row went from 1923/0 to a failure.
    #[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos"))]
    {
        &[
            // Measured: `StopReason::ThreadCreate` appears ZERO times in
            // `src/ios`. The RSP stub reports stops, and thread creation is not
            // one of them.
            BackendCapability {
                name: "thread_events",
                supported: false,
                because: "debugserver's RSP stop-replies do not announce thread creation, so no                           stop arrives when a thread is born. A client must poll threads().",
            },
            BackendCapability {
                name: "hardware_watchpoints",
                supported: true,
                because: "",
            },
            // Supported, with a limit the backend itself documents: when the
            // stub answers `reason:watchpoint` WITHOUT an address key, the PC
            // is reported instead of the datum. Saying "supported" flatly would
            // overstate it; saying "unsupported" would understate it.
            BackendCapability {
                name: "fault_address",
                supported: true,
                because: "reported from the stub's watch address; in the rarer reply that omits                           it, the PC is returned instead of the datum touched.",
            },
        ]
    }
    #[cfg(not(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos"
    )))]
    {
        &[]
    }
}

pub fn sub_register_of(name: &str) -> Option<(&'static str, u32, u64)> {
    const M8: u64 = 0xFF;
    const M16: u64 = 0xFFFF;
    const M32: u64 = 0xFFFF_FFFF;
    // x86-64: the four legacy registers carry a high-byte alias, the rest do
    // not (there is no `sih`).
    let legacy = [
        ("a", "rax"),
        ("b", "rbx"),
        ("c", "rcx"),
        ("d", "rdx"),
    ];
    for (letter, parent) in legacy {
        if name == format!("e{letter}x") {
            return Some((parent, 0, M32));
        }
        if name == format!("{letter}x") {
            return Some((parent, 0, M16));
        }
        if name == format!("{letter}l") {
            return Some((parent, 0, M8));
        }
        if name == format!("{letter}h") {
            return Some((parent, 8, M8));
        }
    }
    for (short, parent) in [
        ("esi", "rsi"),
        ("edi", "rdi"),
        ("ebp", "rbp"),
        ("esp", "rsp"),
    ] {
        if name == short {
            return Some((parent, 0, M32));
        }
    }
    for (short, parent) in [("si", "rsi"), ("di", "rdi"), ("bp", "rbp"), ("sp", "rsp")] {
        // `sp` is a REAL register name on AArch64, so it must never be
        // rewritten into `rsp` there; the exact-match branch in
        // `get_narrowed` already served it, and this path is only reached
        // when the map has no `sp` of its own.
        if name == short {
            return Some((parent, 0, M16));
        }
    }
    // r8..r15 with d/w/b suffixes.
    for n in 8..=15u32 {
        let parent: &'static str = match n {
            8 => "r8",
            9 => "r9",
            10 => "r10",
            11 => "r11",
            12 => "r12",
            13 => "r13",
            14 => "r14",
            _ => "r15",
        };
        if name == format!("{parent}d") {
            return Some((parent, 0, M32));
        }
        if name == format!("{parent}w") {
            return Some((parent, 0, M16));
        }
        if name == format!("{parent}b") {
            return Some((parent, 0, M8));
        }
    }
    // AArch64: `w<n>` is the low 32 bits of `x<n>`.
    if let Some(rest) = name.strip_prefix('w')
        && let Ok(n) = rest.parse::<u32>()
        && n <= 30
    {
        return Some((
            match n {
                0 => "x0",
                1 => "x1",
                2 => "x2",
                3 => "x3",
                4 => "x4",
                5 => "x5",
                6 => "x6",
                7 => "x7",
                8 => "x8",
                9 => "x9",
                10 => "x10",
                11 => "x11",
                12 => "x12",
                13 => "x13",
                14 => "x14",
                15 => "x15",
                16 => "x16",
                17 => "x17",
                18 => "x18",
                19 => "x19",
                20 => "x20",
                21 => "x21",
                22 => "x22",
                23 => "x23",
                24 => "x24",
                25 => "x25",
                26 => "x26",
                27 => "x27",
                28 => "x28",
                29 => "x29",
                _ => "x30",
            },
            0,
            M32,
        ));
    }
    None
}

impl RegisterSet {
    /// Create an empty [`RegisterSet`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Retrieve a named register value.  Returns `None` when the register is
    /// not present in the map.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<u64> {
        self.regs.get(name).copied()
    }

    /// Insert or update a named register value.
    pub fn set(&mut self, name: &str, value: u64) {
        self.regs.insert(name.to_owned(), value);
        // Keep the typed view in step with the map.
        //
        // `pc`, `sp` and `fp` are populated by every backend when a register
        // set is READ, and the crate's own comment says callers use them
        // "instead of the named-register map" — `backtrace`, `step_over` and
        // `step_out` all read them. But nothing kept them current: setting
        // `rip` through this method left `pc` holding the value the thread had
        // BEFORE the write, so code that set a register and then consulted the
        // typed field read a stale number that looked perfectly plausible.
        let arch = crate::instr_step::native_arch();
        if name == crate::instr_step::pc_key(arch) {
            self.pc = value;
        } else if name == crate::instr_step::sp_key(arch) {
            self.sp = value;
        } else if crate::instr_step::is_fp_name(arch, name) {
            // Both AArch64 spellings, because both are in live use — see
            // `is_fp_name`. Matching only `fp_key` let `set("fp", …)` update
            // the map while leaving the typed `fp` field stale.
            self.fp = Some(value);
        }
    }

    /// Push `pc`/`sp`/`fp` back into the named map under this build's register
    /// names, so a write through the typed fields is not silently dropped.
    ///
    /// The asymmetry this closes: every backend POPULATES `pc`/`sp`/`fp` when
    /// reading a thread, and every backend's `apply_register_set` writes back
    /// from the named map ONLY. So the obvious use of the public API —
    ///
    /// ```ignore
    /// let mut r = dbg.get_registers(tid).await?;
    /// r.pc = new_pc;
    /// dbg.set_registers(tid, r).await?;   // returns Ok, changes nothing
    /// ```
    ///
    /// left the thread at the old program counter and reported success. The
    /// fields are the documented, architecture-independent view; they were a
    /// live read path and a dead write path.
    ///
    /// Precedence is coherent because [`Self::set`] now updates both: whichever
    /// of the two a caller wrote LAST is the one that survives.
    pub fn sync_map_from_special(&mut self) {
        let arch = crate::instr_step::native_arch();
        self.regs.insert(crate::instr_step::pc_key(arch).to_owned(), self.pc);
        self.regs.insert(crate::instr_step::sp_key(arch).to_owned(), self.sp);
        if let Some(fp) = self.fp {
            self.regs.insert(crate::instr_step::fp_key(arch).to_owned(), fp);
        }
    }

    /// Retrieve a register by a **sub-register** name, narrowed to that name's
    /// real width — `eax`, `ax`, `al`, `ah`, `w0`, `r8d`, …
    ///
    /// Falls back to an exact match first, so a backend that already stores the
    /// narrow name wins over any derivation.
    ///
    /// Why this exists: the map holds only the full-width names a backend
    /// reads from the OS, so a breakpoint condition written the way people
    /// actually write them — `al == 0` to test a boolean return, `eax > 4` for
    /// an `int` — asked for a register that was simply absent. Evaluation then
    /// failed, and by this crate's fail-open rule the target stopped on EVERY
    /// hit: the condition was not wrong, it was not applied, and nothing said
    /// so.
    ///
    /// The narrowing is not cosmetic either. Comparing `al` against a full
    /// 64-bit `rax` makes `al == 0` false whenever any higher byte is set —
    /// a condition that quietly answers the wrong question.
    #[must_use]
    pub fn get_narrowed(&self, name: &str) -> Option<u64> {
        if let Some(v) = self.regs.get(name) {
            return Some(*v);
        }
        let (parent, shift, mask) = sub_register_of(name)?;
        let full = self.regs.get(parent).copied()?;
        Some((full >> shift) & mask)
    }

    /// Return the program counter as an [`Address`].
    #[must_use]
    pub const fn get_pc(&self) -> Address {
        Address::new(self.pc)
    }

    /// Return the stack pointer as an [`Address`].
    #[must_use]
    pub const fn get_sp(&self) -> Address {
        Address::new(self.sp)
    }

    /// All register names present in the map, in sorted order.
    #[must_use]
    pub fn all_names(&self) -> Vec<String> {
        let mut names: Vec<String> = Vec::with_capacity(self.regs.len());
        names.extend(self.regs.keys().cloned());
        names.sort();
        names
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Breakpoint
// ─────────────────────────────────────────────────────────────────────────────

/// Distinguishes how a breakpoint is implemented in the target process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointKind {
    /// Software breakpoint implemented by patching `0xCC` (INT3) on x86.
    Software,
    /// Hardware execution breakpoint (DR0–DR3 on x86).
    Hardware,
    /// Hardware watchpoint – fires on any read.
    DataRead,
    /// Hardware watchpoint – fires on any write.
    DataWrite,
    /// Hardware watchpoint – fires on read or write.
    DataReadWrite,
}

/// A single breakpoint or watchpoint in the target process.
#[derive(Debug, Clone)]
pub struct Breakpoint {
    /// Address at which the breakpoint is set.
    pub address: Address,
    /// How the breakpoint is implemented.
    pub kind: BreakpointKind,
    /// Whether the breakpoint is currently active.
    pub enabled: bool,
    /// Running count of how many times this breakpoint has been hit.
    pub hit_count: u64,
    /// Optional expression condition: only stop when this evaluates to true.
    pub condition: Option<String>,
    /// Original byte overwritten by a software breakpoint.
    pub original_byte: Option<u8>,
    /// User-visible label for this breakpoint.
    pub label: Option<String>,
    /// Remaining hits to skip before stopping again (gdb's `ignore N`).
    ///
    /// Published because it is one of only two reasons an ENABLED breakpoint at
    /// a reached address does not stop, and the other is [`Self::only_thread`].
    /// Without them the listing cannot distinguish "restricted, and the
    /// restriction is why you are not stopping" from "the program never gets
    /// here" — and the debugger accepts both restrictions happily, so a caller
    /// can set one and then have no way to see it.
    pub ignore_count: u64,
    /// Thread this breakpoint is restricted to, if any (gdb's
    /// `break … thread N`). `None` means every thread stops.
    ///
    /// A wrong-thread crossing is deliberately NOT counted in
    /// [`Self::hit_count`], so a thread-restricted breakpoint being crossed
    /// constantly by other threads looks exactly like one that is never
    /// reached. This field is the only thing that tells them apart.
    pub only_thread: Option<ThreadId>,
    /// Width in bytes of the region a DATA watchpoint covers, or `None` for an
    /// execution breakpoint, where the concept does not apply.
    ///
    /// `set_watchpoint_sized` takes a width and the backends store it, and the
    /// listing then destructured it as `&(kind, _size)` and threw it away — so
    /// an 8-byte watchpoint and a 1-byte one were indistinguishable in the only
    /// listing the debugger publishes. That is not cosmetic: the width is
    /// exactly what a caller needs to re-arm the same watchpoint after listing
    /// it, and re-arming an 8-byte region as 1 byte misses seven bytes out of
    /// eight without reporting anything.
    pub byte_size: Option<u8>,
}

impl Breakpoint {
    /// Create an enabled software (INT3) breakpoint at `address`.
    #[must_use]
    pub const fn new_software(address: Address) -> Self {
        Self {
            address,
            kind: BreakpointKind::Software,
            enabled: true,
            hit_count: 0,
            condition: None,
            original_byte: None,
            label: None,
            ignore_count: 0,
            only_thread: None,
            byte_size: None,
        }
    }

    /// Create an enabled hardware execution breakpoint at `address`.
    #[must_use]
    pub const fn new_hardware(address: Address) -> Self {
        Self {
            address,
            kind: BreakpointKind::Hardware,
            enabled: true,
            hit_count: 0,
            condition: None,
            original_byte: None,
            label: None,
            ignore_count: 0,
            only_thread: None,
            byte_size: None,
        }
    }

    /// Create an enabled hardware watchpoint at `address` with the given
    /// access `kind`.  Only `DataRead`, `DataWrite`, and `DataReadWrite` are
    /// meaningful here; other kinds are accepted but treated as `DataReadWrite`.
    #[must_use]
    pub const fn new_watchpoint(address: Address, kind: BreakpointKind) -> Self {
        Self {
            address,
            kind,
            enabled: true,
            hit_count: 0,
            condition: None,
            original_byte: None,
            label: None,
            ignore_count: 0,
            only_thread: None,
            byte_size: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StopReason
// ─────────────────────────────────────────────────────────────────────────────

/// The reason a traced process stopped and control was returned to the debugger.
#[derive(Debug, Clone)]
pub enum StopReason {
    /// Execution reached a breakpoint.
    Breakpoint { address: Address, bp: Breakpoint },
    /// A single-step trace trap fired.
    SingleStep { address: Address },
    /// The process received a signal.
    Signal {
        signum: i32,
        signame: String,
        address: Option<Address>,
    },
    /// A hardware/OS exception occurred.
    Exception {
        code: u32,
        address: Option<Address>,
        description: String,
    },
    /// The process exited normally or via signal.
    ProcessExit { exit_code: i32 },
    /// A new thread was created.
    ThreadCreate { tid: ThreadId },
    /// A thread exited.
    ThreadExit { tid: ThreadId, exit_code: i32 },
    /// A shared library was mapped.
    LibraryLoad { path: String, base: Address },
    /// A shared library was unmapped.
    LibraryUnload { path: String },
    /// A child process was created (follow-forks mode).
    ProcessCreate { pid: ProcessId },
    /// An invalid memory access occurred.
    AccessViolation { address: Address, is_write: bool },
    /// Any other stop reason.
    Unknown { description: String },
}

/// `SIGBUS` for the target this crate is compiled for.
///
/// 7 on Linux, 10 on BSD and macOS. Named rather than inlined because the two
/// numbers each mean something ELSE on the other platform (`SIGUSR1` and
/// `SIGEMT`), so a reader meeting a bare 7 or 10 cannot tell a deliberate
/// choice from a copied constant.
#[cfg(target_os = "linux")]
const SIGBUS_ON_THIS_TARGET: i32 = 7;
#[cfg(not(target_os = "linux"))]
const SIGBUS_ON_THIS_TARGET: i32 = 10;

/// What is known about a memory fault, with the unknowns spelled as unknown.
///
/// Every field is an `Option` on purpose. A backend that cannot tell the
/// direction of the access says `None` rather than guessing `false`, and one
/// that cannot report the address says `None` rather than `0` — a plausible
/// wrong answer is the failure mode this crate treats as worse than an absent
/// one, because a caller cannot tell it from a real reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessFault {
    /// The address the target tried to touch, when the OS reports it.
    ///
    /// Windows: `ExceptionInformation[1]`. Linux: `si_addr` via
    /// `PTRACE_GETSIGINFO`. macOS: `None` — see `backend_capabilities`.
    pub address: Option<Address>,
    /// `true` write, `false` read, `None` when the OS does not say.
    ///
    /// Only Windows reports this, through `ExceptionInformation[0]`. It is NOT
    /// derivable from `si_addr` on Linux, and defaulting it to `false` would
    /// turn "unknown" into "it was a read".
    pub is_write: Option<bool>,
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Breakpoint { address, .. } => {
                write!(f, "breakpoint at {address}")
            }
            Self::SingleStep { address } => write!(f, "single step at {address}"),
            Self::Signal {
                signum,
                signame,
                address,
            } => match address {
                Some(a) => write!(f, "signal {signame} ({signum}) at {a}"),
                None => write!(f, "signal {signame} ({signum})"),
            },
            Self::Exception {
                code,
                address,
                description,
            } => match address {
                Some(a) => write!(f, "exception {code:#x} at {a}: {description}"),
                None => write!(f, "exception {code:#x}: {description}"),
            },
            Self::ProcessExit { exit_code } => write!(f, "process exited ({exit_code})"),
            Self::ThreadCreate { tid } => write!(f, "thread created: {tid}"),
            Self::ThreadExit { tid, exit_code } => {
                write!(f, "thread {tid} exited ({exit_code})")
            }
            Self::LibraryLoad { path, base } => {
                write!(f, "library loaded: {path} at {base}")
            }
            Self::LibraryUnload { path } => write!(f, "library unloaded: {path}"),
            Self::ProcessCreate { pid } => write!(f, "process created: {pid}"),
            Self::AccessViolation { address, is_write } => {
                let access = if *is_write { "write" } else { "read" };
                write!(f, "access violation ({access}) at {address}")
            }
            Self::Unknown { description } => write!(f, "unknown: {description}"),
        }
    }
}

impl StopReason {
    /// Was this stop a memory fault, and what is known about it?
    ///
    /// ONE question with one portable answer. The same crash reaches a caller
    /// as `AccessViolation` on Windows and as `Signal { SIGSEGV, .. }` on Linux
    /// and macOS, because those kernels report a signal where Windows reports a
    /// structured exception. `AccessViolation` is CONSTRUCTED only by the
    /// Windows backend, so the obvious `match` arm for it is silently dead on
    /// the other two: the crash happens and the handler never runs.
    ///
    /// This reads whichever shape arrived and reports what that backend
    /// actually knows. It deliberately does NOT normalise them into one shape:
    /// `is_write` cannot be derived from `si_addr`, and manufacturing it would
    /// be the invented answer this crate refuses everywhere else.
    ///
    /// `SIGBUS` counts too. It is a different fault from `SIGSEGV` — misaligned
    /// or unbacked rather than unmapped — but it is still "the target died
    /// touching memory", which is the question being asked.
    #[must_use]
    pub fn access_fault(&self) -> Option<AccessFault> {
        match self {
            Self::AccessViolation { address, is_write } => Some(AccessFault {
                address: Some(*address),
                is_write: Some(*is_write),
            }),
            // Chosen PER TARGET, not unioned.
            //
            // `SIGSEGV` is 11 everywhere, but `SIGBUS` is 7 on Linux and 10 on
            // BSD/macOS -- and those numbers are not free on the other side:
            // 10 is `SIGUSR1` on Linux and 7 is `SIGEMT` on macOS. Accepting
            // `11 | 10 | 7` everywhere, as this did for one iteration, reported
            // an ordinary `SIGUSR1` as a memory fault on Linux and `SIGEMT` on
            // macOS: a false positive in the very predicate written so callers
            // would not have to guess. The union of two platforms' constants is
            // not a portable constant.
            Self::Signal { signum, address, .. }
                if *signum == 11 || *signum == SIGBUS_ON_THIS_TARGET =>
            {
                Some(AccessFault { address: *address, is_write: None })
            }
            _ => None,
        }
    }

    /// The address of the CODE, when this stop has one.
    ///
    /// `None` for `AccessViolation` and `Signal`: their address is the datum
    /// the target touched, and returning it here would be the confusion this
    /// method exists to remove. The code location for those stops is the
    /// program counter, which the caller reads from the register set — a
    /// different source, correctly.
    ///
    /// Use this to disassemble, symbolicate, or look a module up. Use
    /// [`Self::address`] only to display whatever the stop happens to carry.
    #[must_use]
    pub const fn code_address(&self) -> Option<Address> {
        match self {
            Self::Breakpoint { address, .. } | Self::SingleStep { address } => Some(*address),
            Self::LibraryLoad { base, .. } => Some(*base),
            // Deliberately NOT `Exception`: on Windows its address is the
            // faulting instruction, but the variant is also used for stops
            // whose address the backend filled from elsewhere, so promising
            // "this is code" would be a guarantee this type cannot keep.
            _ => None,
        }
    }

    /// Returns `true` if this stop represents process termination.
    #[must_use]
    pub const fn is_exit(&self) -> bool {
        matches!(self, Self::ProcessExit { .. })
    }

    /// Return this variant's address field, WHATEVER KIND it is.
    ///
    /// The old sentence here was *"the address associated with this stop
    /// event"*, which promises one kind of value and delivers two:
    ///
    /// - `Breakpoint`, `SingleStep` — the program counter: a CODE address.
    /// - `LibraryLoad` — a module base: a code region.
    /// - `AccessViolation`, `Signal` — the DATUM the target touched, which has
    ///   nothing to do with where the code was.
    ///
    /// A caller who believed the sentence and disassembled from it got the
    /// instruction stream for a breakpoint and a data pointer for a segfault,
    /// with nothing to signal the difference.
    ///
    /// This method is kept, because "give me whatever address this stop
    /// carries" is a legitimate question for logging and display. For the other
    /// question — "where was the code?" — use [`Self::code_address`], which
    /// answers `None` rather than handing back a datum.
    #[must_use]
    pub const fn address(&self) -> Option<Address> {
        match self {
            Self::Breakpoint { address, .. }
            | Self::SingleStep { address }
            | Self::AccessViolation { address, .. } => Some(*address),
            Self::Signal { address, .. } | Self::Exception { address, .. } => *address,
            Self::LibraryLoad { base, .. } => Some(*base),
            Self::ProcessExit { .. }
            | Self::ThreadCreate { .. }
            | Self::ThreadExit { .. }
            | Self::LibraryUnload { .. }
            | Self::ProcessCreate { .. }
            | Self::Unknown { .. } => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DebugEvent
// ─────────────────────────────────────────────────────────────────────────────

/// A single debugger event: a process stopped and the reason it stopped.
#[derive(Debug, Clone)]
pub struct DebugEvent {
    /// The process that stopped.
    pub pid: ProcessId,
    /// The thread that caused the stop.
    pub tid: ThreadId,
    /// Why the process stopped.
    pub reason: StopReason,
    /// Monotonic nanosecond timestamp.
    pub timestamp: u64,
}

/// Process-start anchor for monotonic timestamps in [`DebugEvent`].
static PROCESS_START: OnceLock<Instant> = OnceLock::new();

impl DebugEvent {
    /// Create a new event, filling in a monotonic nanosecond timestamp.
    ///
    /// The timestamp is nanoseconds elapsed since the first call to this
    /// function within the process lifetime, using [`Instant`] (monotonic)
    /// rather than `SystemTime` (wall-clock, subject to NTP jumps).
    #[must_use]
    pub fn new(pid: ProcessId, tid: ThreadId, reason: StopReason) -> Self {
        let start = PROCESS_START.get_or_init(Instant::now);
        let timestamp = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        Self {
            pid,
            tid,
            reason,
            timestamp,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryMap
// ─────────────────────────────────────────────────────────────────────────────

/// Information about a single virtual memory region in the traced process.
#[derive(Debug, Clone)]
pub struct MemoryMap {
    /// Starting address of the region.
    pub base: Address,
    /// Size in bytes.
    pub size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    /// Human-readable name: module filename, `[heap]`, `[stack]`, etc.
    pub name: Option<String>,
    /// Full path to the backing file, if any.
    pub file_path: Option<String>,
    /// Offset within the backing file.
    pub file_offset: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// ModuleInfo
// ─────────────────────────────────────────────────────────────────────────────

/// A shared library or executable module loaded into the traced process.
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Short name (basename).
    pub name: String,
    /// Full path on disk.
    pub path: String,
    /// Load base address.
    pub base: Address,
    /// Total in-memory size.
    pub size: u64,
    /// Entry-point address, if known.
    pub entry_point: Option<Address>,
    /// `true` for the main executable.
    pub is_main: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// LaunchOptions
// ─────────────────────────────────────────────────────────────────────────────

/// Controls which child output streams to capture.
#[derive(Debug, Clone, Default)]
pub struct OutputRedirect {
    /// Capture the child's standard output.
    ///
    /// **Not yet implemented by either concrete backend** (`windows_debugger`/
    /// `linux_debugger`): both spawn the child with inherited stdio and never
    /// read this field. Setting it to `true` is silently a no-op today —
    /// found via a live-test/coverage audit that also caught the
    /// `sess.tid`/`current_thread` staleness bugs in this crate's history;
    /// flagged rather than left to mislead a caller into thinking output is
    /// captured when it isn't.
    pub stdout: bool,
    /// Capture the child's standard error. Same "not yet implemented" caveat
    /// as `stdout` above.
    pub stderr: bool,
}

/// Configuration for starting a new process under the debugger.
#[derive(Debug, Clone)]
pub struct LaunchOptions {
    /// Path to the executable to launch.
    pub executable: String,
    /// Command-line arguments (not including `argv[0]`).
    pub args: Vec<String>,
    /// Additional environment variables.
    pub env: HashMap<String, String>,
    /// Working directory for the child process.
    pub working_dir: Option<String>,
    /// Stop at the program entry point before running any user code.
    pub stop_at_entry: bool,
    /// Follow child processes created by `fork`/`clone`.
    ///
    /// **Not yet implemented by either concrete backend**: neither
    /// `windows_debugger`/`linux_debugger`'s `launch()` reads this field —
    /// `linux_debugger` never sets `PTRACE_O_TRACEFORK`, and
    /// `windows_debugger` doesn't distinguish `DEBUG_PROCESS` from
    /// `DEBUG_ONLY_THIS_PROCESS`. Setting it to `true` is silently a no-op
    /// today. Flagged rather than left to mislead a caller.
    pub follow_forks: bool,
    /// Output stream capture settings.
    pub redirect: OutputRedirect,
}

impl LaunchOptions {
    /// Create a minimal [`LaunchOptions`] for the given executable path.
    pub fn new(executable: impl Into<String>) -> Self {
        Self {
            executable: executable.into(),
            args: Vec::new(),
            env: HashMap::new(),
            working_dir: None,
            stop_at_entry: false,
            follow_forks: false,
            redirect: OutputRedirect::default(),
        }
    }

    /// Replace the argument list.
    #[must_use]
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Add or override a single environment variable.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.env.insert(key.into(), val.into());
        self
    }

    /// Enable stopping at the program entry point.
    #[must_use]
    pub const fn stop_at_entry(mut self) -> Self {
        self.stop_at_entry = true;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StackFrame
// ─────────────────────────────────────────────────────────────────────────────

/// One frame in a call-stack backtrace.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StackFrame {
    /// Zero-based frame index (0 = innermost / most recent).
    pub index: usize,
    /// Program counter for this frame.
    pub pc: Address,
    /// Stack pointer for this frame.
    pub sp: Address,
    /// Frame pointer, if available.
    pub fp: Option<Address>,
    /// Demangled function name, if resolved.
    pub function_name: Option<String>,
    /// Module that contains this frame.
    pub module: Option<String>,
    /// Byte offset from the start of the function.
    pub offset: Option<u64>,
    /// Source file path, if DWARF/STABS data is available.
    pub source_file: Option<String>,
    /// 1-based source line number.
    pub source_line: Option<u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared run-to-return loop decision
// ─────────────────────────────────────────────────────────────────────────────

/// What a `run_to_return` event-loop iteration should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunToReturnStep {
    /// Stop and hand this event back to the caller.
    Done,
    /// Not there yet — pump another debug event.
    KeepGoing,
}

/// Decide whether a `run_to_return` loop iteration is finished.
///
/// Every backend implements the same loop, and the ordering inside it has now
/// been wrong twice, in ways that only a live process could reveal:
///
/// 1. Reading registers BEFORE testing `is_exit` makes the exit test
///    unreachable — once the process is gone the read fails and the error is
///    propagated, so a natural `ProcessExit` surfaces as a spurious `Err`
///    (fixed for Windows/Linux in iters 156/157).
/// 2. Testing `is_exit` is necessary but NOT sufficient: the followed thread
///    can die while the process is still alive, so the register read fails
///    with `is_exit` false — and propagating that discards the `ProcessExit`
///    about to arrive on the next iteration (iter 241; it presented as a
///    ~1-in-6 flake, not a constant failure).
///
/// `macos_debugger.rs` had defect 1 for as long as it has existed, because it
/// cannot be compiled or live-tested on the hosts this crate is developed on,
/// so neither fix ever reached it. Centralising the decision here means the
/// rule is stated once, unit-tested on every host, and cannot silently
/// diverge per backend again.
///
/// `regs` is `None` when the register read failed — that is a vanished
/// thread, not a failure of `run_to_return`.
#[must_use]
pub fn run_to_return_step(
    event_is_exit: bool,
    regs: Option<(u64, u64)>,
    target: u64,
    min_sp: u64,
) -> RunToReturnStep {
    if event_is_exit {
        return RunToReturnStep::Done;
    }
    match regs {
        Some((pc, sp)) if pc == target && sp >= min_sp => RunToReturnStep::Done,
        _ => RunToReturnStep::KeepGoing,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Debugger trait
// ─────────────────────────────────────────────────────────────────────────────

/// The core interface every OS/architecture-specific debugger backend must
/// implement.  All methods are `async` to allow long-running kernel operations
/// (like `waitpid`) to be driven by a Tokio executor without blocking threads.
#[async_trait::async_trait]
pub trait Debugger: Send + Sync {
    /// Short human-readable name, e.g. `"linux-ptrace"`.
    fn name(&self) -> &str;
    /// List of architecture names this backend can debug.
    fn supported_architectures(&self) -> Vec<String>;

    // ── Process lifecycle ────────────────────────────────────────────────────

    /// Launch a new process under the debugger.
    async fn launch(&self, opts: LaunchOptions) -> Result<ProcessId, DebugError>;
    /// Attach to an already-running process.
    async fn attach(&self, pid: ProcessId) -> Result<(), DebugError>;
    /// Detach from the current process (which continues running).
    async fn detach(&self) -> Result<(), DebugError>;
    /// Send SIGKILL (or equivalent) to the traced process.
    async fn kill(&self) -> Result<(), DebugError>;
    /// Returns `true` when a process is currently attached/launched.
    fn is_attached(&self) -> bool;
    /// The PID of the currently traced process, if any.
    fn target_pid(&self) -> Option<ProcessId>;

    // ── Execution control ────────────────────────────────────────────────────

    /// Resume execution and block until the next stop event.
    async fn continue_execution(&self) -> Result<DebugEvent, DebugError>;
    /// Execute exactly one machine instruction on `tid`.
    async fn single_step(&self, tid: ThreadId) -> Result<DebugEvent, DebugError>;
    /// Step over the current instruction (handles `call` instructions).
    async fn step_over(&self, tid: ThreadId) -> Result<DebugEvent, DebugError>;
    /// Run until the current function returns.
    async fn step_out(&self, tid: ThreadId) -> Result<DebugEvent, DebugError>;
    /// Interrupt a running process (equivalent to Ctrl-C).
    async fn pause(&self) -> Result<(), DebugError>;

    // ── Thread management ────────────────────────────────────────────────────

    /// List all currently live threads.
    ///
    /// **Linux caveat**: `threads()` enumerates every real thread of the
    /// process (via `/proc/<pid>/task`), but only the originally launched/
    /// attached thread is actually `PTRACE_ATTACH`ed — this backend does not
    /// yet auto-attach newly created threads (would need `PTRACE_SEIZE` +
    /// `PTRACE_O_TRACECLONE`). Calling [`Debugger::get_registers`]/
    /// [`Debugger::set_registers`]/[`Debugger::single_step`] with a `tid`
    /// other than the attached one will correctly return an error rather
    /// than silently operating on the wrong thread (fixed 2026-07-20 — see
    /// `ENHANCEMENT_LOG.md` iter 168), but real per-thread control of a
    /// genuinely multi-threaded Linux target is not yet implemented.
    async fn threads(&self) -> Result<Vec<ThreadId>, DebugError>;
    /// Return the thread that last caused a stop event.
    async fn current_thread(&self) -> Result<ThreadId, DebugError>;

    // ── Register access ──────────────────────────────────────────────────────

    /// Read all registers for `tid`. See the Linux caveat on [`Debugger::threads`].
    async fn get_registers(&self, tid: ThreadId) -> Result<RegisterSet, DebugError>;
    /// Write back a full register set for `tid`.
    async fn set_registers(&self, tid: ThreadId, regs: RegisterSet) -> Result<(), DebugError>;
    /// Read a single named register from `tid`.
    async fn get_register(&self, tid: ThreadId, name: &str) -> Result<u64, DebugError>;
    /// Write a single named register on `tid`.
    async fn set_register(&self, tid: ThreadId, name: &str, value: u64) -> Result<(), DebugError>;

    // ── Memory access ────────────────────────────────────────────────────────

    /// Read `size` bytes from the target's virtual address space.
    async fn read_memory(&self, addr: Address, size: usize) -> Result<Vec<u8>, DebugError>;
    /// Write `data` into the target's virtual address space; returns bytes written.
    async fn write_memory(&self, addr: Address, data: &[u8]) -> Result<usize, DebugError>;
    /// Return the current virtual memory layout of the target process.
    async fn memory_maps(&self) -> Result<Vec<MemoryMap>, DebugError>;

    // ── Breakpoints ──────────────────────────────────────────────────────────

    /// Insert a breakpoint of the given kind at `addr`.
    async fn set_breakpoint(&self, addr: Address, kind: BreakpointKind) -> Result<(), DebugError>;

    /// Insert a DATA watchpoint at `addr` covering exactly `size` bytes.
    ///
    /// [`BreakpointKind`] carries no width, so [`Self::set_breakpoint`] leaves
    /// the watched region to the backend — the Apple backend used a fixed 8
    /// bytes for every watchpoint. A caller that resolved a 4-byte struct field
    /// was therefore told its field was watched while the watchpoint also
    /// covered the next one (spurious hits), and a caller with a field wider
    /// than the backend's choice had its tail silently unwatched.
    ///
    /// The default implementation forwards to [`Self::set_breakpoint`] and
    /// IGNORES `size`, which is exactly today's behaviour: a backend that has
    /// not overridden this is no worse than before, and
    /// `tests_expanded::watchpoint_width_support_is_declared_not_assumed`
    /// records which backends honour the width so the gap stays visible instead
    /// of being assumed closed.
    ///
    /// # Errors
    /// Whatever the backend reports, plus [`crate::expression_evaluator::DebugError::Unsupported`] when the
    /// requested width cannot be represented.
    async fn set_watchpoint_sized(
        &self,
        addr: Address,
        kind: BreakpointKind,
        size: u8,
    ) -> Result<(), DebugError> {
        let _ = size;
        self.set_breakpoint(addr, kind).await
    }
    /// Remove the breakpoint at `addr`.
    async fn remove_breakpoint(&self, addr: Address) -> Result<(), DebugError>;
    /// Re-enable a previously disabled breakpoint.
    async fn enable_breakpoint(&self, addr: Address) -> Result<(), DebugError>;
    /// Disable (but do not remove) the breakpoint at `addr`.
    async fn disable_breakpoint(&self, addr: Address) -> Result<(), DebugError>;
    /// Return a snapshot of all currently registered breakpoints.
    async fn breakpoints(&self) -> Result<Vec<Breakpoint>, DebugError>;

    // ── Modules ──────────────────────────────────────────────────────────────

    /// Return information about all loaded modules/libraries.
    async fn modules(&self) -> Result<Vec<ModuleInfo>, DebugError>;

    // ── Stack ────────────────────────────────────────────────────────────────

    /// Unwind the call stack for `tid`.
    async fn backtrace(&self, tid: ThreadId) -> Result<Vec<StackFrame>, DebugError>;

    // ── Breakpoint conditions ────────────────────────────────────────────────

    /// Attach a condition to the breakpoint at `addr`, or clear it with `None`.
    ///
    /// The expression is the textual form [`crate::conditional_breakpoint::BreakpointCondition::parse`]
    /// reads (`rax == 0`, `mem4[0x1000] > 5`, `$limit != 3`).
    ///
    /// # Errors
    /// `BreakpointNotFound` if nothing is set at `addr`; `Unsupported` from a
    /// backend that cannot hold conditions.
    ///
    /// The default REFUSES rather than accepting and forgetting: a caller that
    /// attaches a condition and is then stopped on every hit would conclude the
    /// condition is false-positive-prone, when in fact nobody ever read it. Same
    /// rule as `set_symbol_resolver` and `set_registers` — an operation that did
    /// not happen must not report success.
    async fn set_breakpoint_condition(
        &self,
        _addr: Address,
        _expr: Option<String>,
    ) -> Result<(), DebugError> {
        Err(DebugError::Unsupported(
            "this backend does not hold breakpoint conditions, so one attached here would never be evaluated"
                .into(),
        ))
    }

    /// Stop at `addr` only for thread `tid` (gdb's `break … thread N`).
    /// `None` clears the restriction.
    ///
    /// Crossings by other threads are neither reported nor counted: they are
    /// not hits of this breakpoint, and they must not consume a pass count set
    /// with [`Self::set_breakpoint_ignore_count`].
    ///
    /// # Errors
    /// `BreakpointNotFound` if nothing is set at `addr`; `Unsupported` from a
    /// backend that cannot hold thread filters.
    ///
    /// The default REFUSES: a caller told the filter is in place, who then
    /// keeps stopping on every worker thread, cannot tell that from a filter
    /// that simply does not work.
    async fn set_breakpoint_thread_filter(
        &self,
        _addr: Address,
        _tid: Option<ThreadId>,
    ) -> Result<(), DebugError> {
        Err(DebugError::Unsupported(
            "this backend does not hold thread filters, so one set here would never be applied"
                .into(),
        ))
    }

    /// Skip the next `count` hits of the breakpoint at `addr` before stopping
    /// again (gdb's `ignore N`, WinDbg's `bp /N`). `0` clears it.
    ///
    /// The skipped hits are still COUNTED — an ignore count consumes hits by
    /// definition, and a count that never decreases never expires.
    ///
    /// # Errors
    /// `BreakpointNotFound` if nothing is set at `addr`; `Unsupported` from a
    /// backend that cannot hold pass counts.
    ///
    /// The default REFUSES: a caller told "ignore 1000 set" who then stops on
    /// the very next hit would conclude the debugger is broken, when in fact
    /// the request was accepted and dropped.
    async fn set_breakpoint_ignore_count(
        &self,
        _addr: Address,
        _count: u64,
    ) -> Result<(), DebugError> {
        Err(DebugError::Unsupported(
            "this backend does not hold pass counts, so hits here would never be skipped".into(),
        ))
    }

    /// Request a breakpoint at `offset` inside `module`, whether or not it is
    /// mapped yet.
    ///
    /// If the module is already loaded the trap is armed now; otherwise it is
    /// armed the moment a `LibraryLoad` event names that module, and re-armed
    /// after every unload/reload at the new base.
    ///
    /// # Errors
    /// `Unsupported` from a backend that does not track module loads.
    ///
    /// The default REFUSES for the same reason `set_breakpoint_condition`
    /// does: a caller told "pending breakpoint set" who then watches the
    /// module load and nothing happen concludes the debugger missed the hit,
    /// when in fact the request was accepted and forgotten.
    async fn set_pending_breakpoint(
        &self,
        _module: &str,
        _offset: u64,
    ) -> Result<(), DebugError> {
        Err(DebugError::Unsupported(
            "this backend does not track module loads, so a pending breakpoint would never be armed"
                .into(),
        ))
    }

    /// Requests still waiting for their module to be mapped.
    ///
    /// # Errors
    /// `Unsupported` from a backend without a pending table.
    async fn pending_breakpoints(
        &self,
    ) -> Result<Vec<crate::pending_breakpoint::PendingRequest>, DebugError> {
        Err(DebugError::Unsupported(
            "this backend does not track module loads".into(),
        ))
    }

    // ── Symbol resolver ──────────────────────────────────────────────────────

    /// Install a symbol resolver so `backtrace` can enrich frames with
    /// function names and source locations.
    ///
    /// # Errors
    /// `Unsupported` from any backend that cannot hold one.
    ///
    /// The default REFUSES instead of silently dropping the resolver. It used to
    /// take it, discard it and return `()`: a caller holding a `&dyn Debugger`
    /// installed symbolication, got no error, and then read backtrace after
    /// backtrace with every `function_name` empty — with nothing at runtime to
    /// distinguish "this backend cannot symbolicate" from "these frames have no
    /// symbols". A doc comment saying "the default is a no-op" is not something a
    /// caller can branch on.
    ///
    /// Same rule this crate applies to `set_registers` (a name the register block
    /// cannot carry is an error, not a skipped write) and to short reads and
    /// partial writes: an operation that did not happen must not report success.
    fn set_symbol_resolver(
        &self,
        _resolver: std::sync::Arc<dyn crate::symbol_resolver::FrameSymbolResolver>,
    ) -> Result<(), DebugError> {
        Err(DebugError::Unsupported(
            "this backend holds no symbol resolver, so backtraces cannot be enriched with function names"
                .into(),
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Async timeout utility
// ─────────────────────────────────────────────────────────────────────────────

/// Run a [`Debugger`] future with a wall-clock timeout.
///
/// # Errors
/// Returns `Err(DebugError::Timeout)` if the future does not complete within
/// `dur`, otherwise forwards the inner result unchanged.
pub async fn with_timeout<F, T>(
    dur: std::time::Duration,
    fut: F,
) -> Result<T, DebugError>
where
    F: std::future::Future<Output = Result<T, DebugError>>,
{
    tokio::time::timeout(dur, fut)
        .await
        .unwrap_or(Err(DebugError::Timeout))
}

// ─────────────────────────────────────────────────────────────────────────────
// DebugSession — shared state
// ─────────────────────────────────────────────────────────────────────────────

/// Shared, thread-safe container for the state that persists across a single
/// debug session.  Backends hold a clone of this and mutate it through the
/// provided methods; the UI reads it for display.
#[derive(Debug, Clone)]
pub struct DebugSession {
    inner: Arc<RwLock<DebugSessionInner>>,
}

#[derive(Debug)]
struct DebugSessionInner {
    pid: Option<ProcessId>,
    current_tid: Option<ThreadId>,
    breakpoints: HashMap<u64, Breakpoint>,
    modules: Vec<ModuleInfo>,
    is_running: bool,
    events: Vec<DebugEvent>,
}

impl DebugSession {
    /// Create a fresh, empty session.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(DebugSessionInner {
                pid: None,
                current_tid: None,
                breakpoints: HashMap::new(),
                modules: Vec::new(),
                is_running: false,
                events: Vec::new(),
            })),
        }
    }

    /// Return the PID of the attached process, if any.
    #[must_use]
    pub fn pid(&self) -> Option<ProcessId> {
        self.inner.read().pid
    }

    /// Append a debug event to the history log.
    pub fn record_event(&self, event: DebugEvent) {
        self.inner.write().events.push(event);
    }

    /// Return a snapshot of all recorded events.
    #[must_use]
    pub fn event_history(&self) -> Vec<DebugEvent> {
        self.inner.read().events.clone()
    }

    /// Register a loaded module.
    pub fn add_module(&self, m: ModuleInfo) {
        self.inner.write().modules.push(m);
    }

    /// Return a snapshot of all known modules.
    #[must_use]
    pub fn modules(&self) -> Vec<ModuleInfo> {
        self.inner.read().modules.clone()
    }

    /// Insert or replace a breakpoint.
    pub fn add_breakpoint(&self, bp: Breakpoint) {
        let key = bp.address.as_u64();
        self.inner.write().breakpoints.insert(key, bp);
    }

    /// Remove the breakpoint at `addr`.  Returns `true` if one was present.
    #[must_use]
    pub fn remove_breakpoint(&self, addr: Address) -> bool {
        self.inner
            .write()
            .breakpoints
            .remove(&addr.as_u64())
            .is_some()
    }

    /// Look up a breakpoint by address.
    #[must_use]
    pub fn get_breakpoint(&self, addr: Address) -> Option<Breakpoint> {
        self.inner.read().breakpoints.get(&addr.as_u64()).cloned()
    }

    /// Return a snapshot of all current breakpoints.
    #[must_use]
    pub fn all_breakpoints(&self) -> Vec<Breakpoint> {
        self.inner.read().breakpoints.values().cloned().collect()
    }

    /// Set the "is running" flag.
    pub fn set_running(&self, running: bool) {
        self.inner.write().is_running = running;
    }

    /// Return `true` if the target is currently executing.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.inner.read().is_running
    }

    /// Store the PID for the session.
    pub fn set_pid(&self, pid: ProcessId) {
        self.inner.write().pid = Some(pid);
    }

    /// Reset all session state (call on detach/process-exit).
    pub fn clear(&self) {
        let mut g = self.inner.write();
        g.pid = None;
        g.current_tid = None;
        g.breakpoints.clear();
        g.modules.clear();
        g.is_running = false;
        g.events.clear();
    }
}

impl Default for DebugSession {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// v2 — spec-compliant simplified debugger API
// ─────────────────────────────────────────────────────────────────────────────

/// Simplified debugger abstraction as specified by the `RustRE` Suite spec.
pub mod v2 {
    use std::collections::HashMap;
    use std::fmt;

    // ── DebugError ───────────────────────────────────────────────────────────

    /// Simplified error type for the v2 debugger API.
    #[derive(Debug, thiserror::Error)]
    pub enum DebugError {
        /// Attach failed for the given PID.
        #[error("attach failed for pid {0}")]
        AttachFailed(u32),
        /// No process is currently attached.
        #[error("not attached")]
        NotAttached,
        /// Memory read error at the given address.
        #[error("memory read error at {0:#x}")]
        MemRead(u64),
        /// Memory write error at the given address.
        #[error("memory write error at {0:#x}")]
        MemWrite(u64),
        /// Register access error.
        #[error("register error: {0}")]
        RegError(String),
        /// Platform-specific error.
        #[error("platform error: {0}")]
        Platform(String),
    }

    // ── BreakpointKind ───────────────────────────────────────────────────────

    /// How a breakpoint is implemented in the target.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BreakpointKind {
        /// Software breakpoint (e.g. INT3 on x86).
        Software,
        /// Hardware execution breakpoint.
        Hardware,
        /// Hardware watchpoint — fires on any read.
        WatchRead,
        /// Hardware watchpoint — fires on any write.
        WatchWrite,
        /// Hardware watchpoint — fires on read or write.
        WatchReadWrite,
    }

    impl fmt::Display for BreakpointKind {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Software => write!(f, "software"),
                Self::Hardware => write!(f, "hardware"),
                Self::WatchRead => write!(f, "watch-read"),
                Self::WatchWrite => write!(f, "watch-write"),
                Self::WatchReadWrite => write!(f, "watch-read-write"),
            }
        }
    }

    // ── Breakpoint ───────────────────────────────────────────────────────────

    /// A single breakpoint or watchpoint in the target process (v2 API).
    #[derive(Debug, Clone)]
    pub struct Breakpoint {
        /// Unique identifier assigned at creation.
        pub id: u32,
        /// Address at which the breakpoint is set.
        pub addr: u64,
        /// How the breakpoint is implemented.
        pub kind: BreakpointKind,
        /// Whether the breakpoint is currently active.
        pub enabled: bool,
        /// Running count of how many times this breakpoint has been hit.
        pub hit_count: u32,
    }

    impl Breakpoint {
        /// Create a new enabled breakpoint.
        #[must_use]
        pub const fn new(id: u32, addr: u64, kind: BreakpointKind) -> Self {
            Self {
                id,
                addr,
                kind,
                enabled: true,
                hit_count: 0,
            }
        }

        /// Returns `true` when this is a watchpoint (read, write, or both).
        #[must_use]
        pub const fn is_watchpoint(&self) -> bool {
            matches!(
                self.kind,
                BreakpointKind::WatchRead
                    | BreakpointKind::WatchWrite
                    | BreakpointKind::WatchReadWrite
            )
        }
    }

    // ── StopReason ───────────────────────────────────────────────────────────

    /// Why the target process stopped.
    #[derive(Debug, Clone)]
    pub enum StopReason {
        /// Stopped at a breakpoint with the given ID.
        Breakpoint(u32),
        /// Single-step trap fired.
        SingleStep,
        /// A hardware or OS exception occurred.
        Exception {
            /// Exception / fault code.
            code: u32,
            /// Address at which the fault occurred.
            addr: u64,
        },
        /// The process exited with the given exit code.
        ProcessExit(i32),
        /// The process received a signal with the given number.
        Signal(u32),
        /// A watchpoint with the given ID fired at the given address.
        Watchpoint {
            /// Watchpoint breakpoint ID.
            id: u32,
            /// Address that was accessed.
            addr: u64,
        },
        /// No specific stop reason (e.g. from a simulated step).
        None,
    }

    impl fmt::Display for StopReason {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Breakpoint(id) => write!(f, "breakpoint #{id}"),
                Self::SingleStep => write!(f, "single step"),
                Self::Exception { code, addr } => {
                    write!(f, "exception {code:#x} at {addr:#x}")
                }
                Self::ProcessExit(code) => write!(f, "process exit ({code})"),
                Self::Signal(sig) => write!(f, "signal {sig}"),
                Self::Watchpoint { id, addr } => {
                    write!(f, "watchpoint #{id} at {addr:#x}")
                }
                Self::None => write!(f, "none"),
            }
        }
    }

    // ── DebugSession ─────────────────────────────────────────────────────────

    /// Simple debug session state (v2 API).
    #[derive(Debug)]
    pub struct DebugSession {
        /// Process ID being debugged.
        pub pid: u32,
        /// All registered breakpoints.
        pub breakpoints: Vec<Breakpoint>,
        /// The most recent stop reason.
        pub stop_reason: StopReason,
        /// Whether the target is currently executing.
        pub running: bool,
        /// Counter for assigning unique breakpoint IDs.
        next_id: u32,
    }

    impl DebugSession {
        /// Create a fresh session for the given PID.
        #[must_use]
        pub const fn new(pid: u32) -> Self {
            Self {
                pid,
                breakpoints: Vec::new(),
                stop_reason: StopReason::None,
                running: false,
                next_id: 1,
            }
        }

        /// Add a new breakpoint at `addr` of the given `kind`.
        ///
        /// Returns the assigned breakpoint ID.
        #[must_use]
        pub fn add_breakpoint(&mut self, addr: u64, kind: BreakpointKind) -> u32 {
            let id = self.next_id;
            self.next_id += 1;
            self.breakpoints.push(Breakpoint::new(id, addr, kind));
            id
        }

        /// Remove the breakpoint with the given ID.
        ///
        /// Returns `true` when a breakpoint was removed.
        pub fn remove_breakpoint(&mut self, id: u32) -> bool {
            let before = self.breakpoints.len();
            self.breakpoints.retain(|bp| bp.id != id);
            self.breakpoints.len() != before
        }

        /// Enable the breakpoint with the given ID.
        ///
        /// Returns `true` when the breakpoint was found and enabled.
        pub fn enable_bp(&mut self, id: u32) -> bool {
            if let Some(bp) = self.breakpoints.iter_mut().find(|b| b.id == id) {
                bp.enabled = true;
                true
            } else {
                false
            }
        }

        /// Disable the breakpoint with the given ID without removing it.
        ///
        /// Returns `true` when the breakpoint was found and disabled.
        pub fn disable_bp(&mut self, id: u32) -> bool {
            if let Some(bp) = self.breakpoints.iter_mut().find(|b| b.id == id) {
                bp.enabled = false;
                true
            } else {
                false
            }
        }

        /// Returns the total number of breakpoints (enabled and disabled).
        #[must_use]
        pub const fn bp_count(&self) -> usize {
            self.breakpoints.len()
        }

        /// Returns references to all currently enabled breakpoints.
        #[must_use]
        pub fn enabled_bps(&self) -> Vec<&Breakpoint> {
            self.breakpoints.iter().filter(|bp| bp.enabled).collect()
        }
    }

    // ── Debugger trait ────────────────────────────────────────────────────────

    /// Core interface for v2 debugger backends.
    pub trait Debugger: Send + Sync {
        /// Short human-readable name for the backend.
        fn name(&self) -> &str;
        /// Attach to the process with the given PID.
        ///
        /// # Errors
        /// Returns a [`crate::expression_evaluator::DebugError`] if the attach fails.
        fn attach(&mut self, pid: u32) -> Result<DebugSession, DebugError>;
        /// Detach from the process described by `session`.
        ///
        /// # Errors
        /// Returns a [`crate::expression_evaluator::DebugError`] if the detach fails.
        fn detach(&mut self, s: &DebugSession) -> Result<(), DebugError>;
        /// Read `size` bytes from `addr` in the attached process.
        ///
        /// # Errors
        /// Returns a [`crate::expression_evaluator::DebugError`] if the memory read fails.
        fn read_memory(
            &self,
            s: &DebugSession,
            addr: u64,
            size: usize,
        ) -> Result<Vec<u8>, DebugError>;
        /// Write `data` to `addr` in the attached process. Returns bytes written.
        ///
        /// # Errors
        /// Returns a [`crate::expression_evaluator::DebugError`] if the memory write fails.
        fn write_memory(
            &self,
            s: &DebugSession,
            addr: u64,
            data: &[u8],
        ) -> Result<usize, DebugError>;
        /// Read all registers for the current thread.
        ///
        /// # Errors
        /// Returns a [`crate::expression_evaluator::DebugError`] if register reading fails.
        fn read_registers(&self, s: &DebugSession) -> Result<HashMap<String, u64>, DebugError>;
        /// Execute a single machine instruction and return the stop reason.
        ///
        /// # Errors
        /// Returns a [`crate::expression_evaluator::DebugError`] if the step fails.
        fn step(&self, s: &mut DebugSession) -> Result<StopReason, DebugError>;
        /// Resume execution and return when the process stops again.
        ///
        /// # Errors
        /// Returns a [`crate::expression_evaluator::DebugError`] if the continue fails.
        fn cont(&self, s: &mut DebugSession) -> Result<StopReason, DebugError>;
    }

    // ── MockDebugger ─────────────────────────────────────────────────────────

    /// An in-memory mock debugger for **testing only** (v2 API).
    ///
    /// # Never use this to answer a caller
    ///
    /// This type exists so unit and integration tests can exercise the
    /// [`Debugger`] shape without a real process. It must never appear on a
    /// path that serves a user or an agent: it invents registers, memory and
    /// stop reasons that are indistinguishable from real ones once serialised.
    ///
    /// The MCP `debug.*` surface used to fall back to it whenever a session id
    /// was unknown, so `debug.read_registers` on a dead session returned a
    /// plausible `rip`/`rsp` with no way for the caller to tell. Those
    /// fallbacks were removed: an unknown session is now an error. Keep it that
    /// way — a debugger that lies is worse than one that refuses to answer.
    pub struct MockDebugger {
        /// Display name returned by [`Debugger::name`].
        pub name: String,
        /// Simulated memory: base address → byte vector.
        pub mem: HashMap<u64, Vec<u8>>,
        /// Simulated register values.
        pub regs: HashMap<String, u64>,
    }

    impl MockDebugger {
        /// Create a new mock debugger with the given name.
        #[must_use]
        pub fn new(name: impl Into<String>) -> Self {
            Self {
                name: name.into(),
                mem: HashMap::new(),
                regs: HashMap::new(),
            }
        }
    }

    impl Debugger for MockDebugger {
        fn name(&self) -> &str {
            &self.name
        }

        fn attach(&mut self, pid: u32) -> Result<DebugSession, DebugError> {
            Ok(DebugSession::new(pid))
        }

        fn detach(&mut self, _s: &DebugSession) -> Result<(), DebugError> {
            Ok(())
        }

        fn read_memory(
            &self,
            _s: &DebugSession,
            addr: u64,
            size: usize,
        ) -> Result<Vec<u8>, DebugError> {
            for (&base, page) in &self.mem {
                if addr >= base && addr < base + page.len() as u64 {
                    let offset = usize::try_from(addr - base).unwrap_or(usize::MAX);
                    let end = offset + size;
                    if end > page.len() {
                        return Err(DebugError::MemRead(addr));
                    }
                    return Ok(page[offset..end].to_vec());
                }
            }
            Err(DebugError::MemRead(addr))
        }

        fn write_memory(
            &self,
            _s: &DebugSession,
            addr: u64,
            data: &[u8],
        ) -> Result<usize, DebugError> {
            for (&base, page) in &self.mem {
                if addr >= base && addr < base + page.len() as u64 {
                    let offset = usize::try_from(addr - base).unwrap_or(usize::MAX);
                    let end = offset + data.len();
                    if end > page.len() {
                        return Err(DebugError::MemWrite(addr));
                    }
                    // MockDebugger uses shared references; writes succeed if in range
                    return Ok(data.len());
                }
            }
            Err(DebugError::MemWrite(addr))
        }

        fn read_registers(&self, _s: &DebugSession) -> Result<HashMap<String, u64>, DebugError> {
            Ok(self.regs.clone())
        }

        fn step(&self, s: &mut DebugSession) -> Result<StopReason, DebugError> {
            s.stop_reason = StopReason::None;
            Ok(StopReason::None)
        }

        fn cont(&self, s: &mut DebugSession) -> Result<StopReason, DebugError> {
            s.stop_reason = StopReason::None;
            Ok(StopReason::None)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── DebugSession ─────────────────────────────────────────────────────────

    #[test]
    fn session_starts_empty() {
        let s = DebugSession::new();
        assert!(s.pid().is_none());
        assert!(!s.is_running());
        assert!(s.all_breakpoints().is_empty());
        assert!(s.modules().is_empty());
        assert!(s.event_history().is_empty());
    }

    #[test]
    fn session_set_and_clear_pid() {
        let s = DebugSession::new();
        s.set_pid(ProcessId(1234));
        assert_eq!(s.pid(), Some(ProcessId(1234)));
        s.clear();
        assert!(s.pid().is_none());
    }

    #[test]
    fn session_add_remove_breakpoints() {
        let s = DebugSession::new();
        let bp = Breakpoint::new_software(Address::new(0x4000));
        s.add_breakpoint(bp);
        assert_eq!(s.all_breakpoints().len(), 1);
        assert!(s.get_breakpoint(Address::new(0x4000)).is_some());
        assert!(s.remove_breakpoint(Address::new(0x4000)));
        assert!(s.all_breakpoints().is_empty());
        assert!(!s.remove_breakpoint(Address::new(0x4000)));
    }

    #[test]
    fn session_record_events() {
        let s = DebugSession::new();
        let ev = DebugEvent::new(
            ProcessId(10),
            ThreadId(10),
            StopReason::SingleStep {
                address: Address::new(0x1000),
            },
        );
        s.record_event(ev.clone());
        s.record_event(ev);
        assert_eq!(s.event_history().len(), 2);
        s.clear();
        assert!(s.event_history().is_empty());
    }

    #[test]
    fn session_module_management() {
        let s = DebugSession::new();
        s.add_module(ModuleInfo {
            name: "libc.so.6".into(),
            path: "/lib/x86_64-linux-gnu/libc.so.6".into(),
            base: Address::new(0x7fff_0000_0000),
            size: 0x20_0000,
            entry_point: None,
            is_main: false,
        });
        let mods = s.modules();
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0].name, "libc.so.6");
        s.clear();
        assert!(s.modules().is_empty());
    }

    #[test]
    fn session_running_flag() {
        let s = DebugSession::new();
        assert!(!s.is_running());
        s.set_running(true);
        assert!(s.is_running());
        s.set_running(false);
        assert!(!s.is_running());
    }

    // ── RegisterSet ──────────────────────────────────────────────────────────

    #[test]
    fn register_set_get_set() {
        let mut r = RegisterSet::new();
        assert!(r.get("rax").is_none());
        r.set("rax", 0xdead_beef);
        assert_eq!(r.get("rax"), Some(0xdead_beef));
        r.set("rax", 0xcafe);
        assert_eq!(r.get("rax"), Some(0xcafe));
    }

    #[test]
    fn register_set_pc_sp() {
        let mut r = RegisterSet::new();
        r.pc = 0x0040_1000;
        r.sp = 0x7fff_0000;
        assert_eq!(r.get_pc(), Address::new(0x0040_1000));
        assert_eq!(r.get_sp(), Address::new(0x7fff_0000));
    }

    #[test]
    fn register_set_all_names_sorted() {
        let mut r = RegisterSet::new();
        r.set("rcx", 1);
        r.set("rax", 2);
        r.set("rbx", 3);
        let names = r.all_names();
        assert_eq!(names, vec!["rax", "rbx", "rcx"]);
    }

    // ── Breakpoint constructors ───────────────────────────────────────────────

    #[test]
    fn breakpoint_new_software() {
        let bp = Breakpoint::new_software(Address::new(0x1000));
        assert_eq!(bp.kind, BreakpointKind::Software);
        assert!(bp.enabled);
        assert_eq!(bp.hit_count, 0);
        assert!(bp.original_byte.is_none());
    }

    #[test]
    fn breakpoint_new_hardware() {
        let bp = Breakpoint::new_hardware(Address::new(0x2000));
        assert_eq!(bp.kind, BreakpointKind::Hardware);
        assert!(bp.enabled);
    }

    #[test]
    fn breakpoint_new_watchpoint() {
        let bp = Breakpoint::new_watchpoint(Address::new(0x3000), BreakpointKind::DataWrite);
        assert_eq!(bp.kind, BreakpointKind::DataWrite);
        assert!(bp.enabled);
    }

    // ── StopReason ───────────────────────────────────────────────────────────

    #[test]
    fn stop_reason_is_exit() {
        let exit = StopReason::ProcessExit { exit_code: 0 };
        assert!(exit.is_exit());
        let step = StopReason::SingleStep {
            address: Address::new(0),
        };
        assert!(!step.is_exit());
    }

    #[test]
    fn stop_reason_address() {
        let addr = Address::new(0x5000);
        let bp = Breakpoint::new_software(addr);
        let r = StopReason::Breakpoint { address: addr, bp };
        assert_eq!(r.address(), Some(addr));

        let r2 = StopReason::ProcessExit { exit_code: 1 };
        assert!(r2.address().is_none());
    }

    #[test]
    fn stop_reason_display() {
        let r = StopReason::ProcessExit { exit_code: 42 };
        assert!(r.to_string().contains("42"));

        let r2 = StopReason::SingleStep {
            address: Address::new(0x1234),
        };
        assert!(r2.to_string().contains("single step"));

        let r3 = StopReason::Signal {
            signum: 11,
            signame: "SIGSEGV".into(),
            address: Some(Address::new(0xdead)),
        };
        assert!(r3.to_string().contains("SIGSEGV"));
    }

    // ── LaunchOptions builder ────────────────────────────────────────────────

    #[test]
    fn launch_options_builder() {
        let opts = LaunchOptions::new("/bin/ls")
            .with_args(vec!["-la".into()])
            .with_env("HOME", "/tmp")
            .stop_at_entry();

        assert_eq!(opts.executable, "/bin/ls");
        assert_eq!(opts.args, vec!["-la"]);
        assert_eq!(opts.env.get("HOME"), Some(&"/tmp".to_string()));
        assert!(opts.stop_at_entry);
    }

    // ── DebugEvent construction ───────────────────────────────────────────────

    #[test]
    fn debug_event_fields() {
        let ev = DebugEvent::new(
            ProcessId(99),
            ThreadId(100),
            StopReason::Unknown {
                description: "test".into(),
            },
        );
        assert_eq!(ev.pid, ProcessId(99));
        assert_eq!(ev.tid, ThreadId(100));

        // `timestamp` is nanoseconds elapsed since the process-lifetime-first
        // `DebugEvent::new` call (see its doc comment) — on a coarse-
        // resolution clock (observed under WSL) this test can legitimately
        // be that very first call, where `elapsed()` reads back as exactly
        // 0ns. Assert monotonicity against a second event instead of
        // strict positivity of a single sample.
        let later = DebugEvent::new(
            ProcessId(99),
            ThreadId(100),
            StopReason::Unknown {
                description: "test2".into(),
            },
        );
        assert!(later.timestamp >= ev.timestamp, "timestamps should be monotonically non-decreasing");
    }

    // ── ProcessId / ThreadId Display ─────────────────────────────────────────

    #[test]
    fn pid_tid_display() {
        assert_eq!(ProcessId(42).to_string(), "PID(42)");
        assert_eq!(ThreadId(7).to_string(), "TID(7)");
    }

    // ── v2 API tests ─────────────────────────────────────────────────────────

    mod v2_tests {
        use super::super::v2::{
            Breakpoint, BreakpointKind, DebugError, DebugSession, Debugger, MockDebugger,
            StopReason,
        };
        use std::collections::HashMap;

        fn make_mock() -> MockDebugger {
            let mut m = MockDebugger::new("test");
            m.mem.insert(0x1000, vec![0x90u8; 64]);
            m.regs.insert("rax".into(), 0xdead_beef);
            m.regs.insert("rip".into(), 0x1000);
            m
        }

        #[test]
        fn breakpoint_kind_display() {
            assert_eq!(BreakpointKind::Software.to_string(), "software");
            assert_eq!(BreakpointKind::Hardware.to_string(), "hardware");
            assert_eq!(BreakpointKind::WatchRead.to_string(), "watch-read");
            assert_eq!(BreakpointKind::WatchWrite.to_string(), "watch-write");
            assert_eq!(
                BreakpointKind::WatchReadWrite.to_string(),
                "watch-read-write"
            );
        }

        #[test]
        fn breakpoint_new_sets_fields() {
            let bp = Breakpoint::new(7, 0x4000, BreakpointKind::Software);
            assert_eq!(bp.id, 7);
            assert_eq!(bp.addr, 0x4000);
            assert_eq!(bp.kind, BreakpointKind::Software);
            assert!(bp.enabled);
            assert_eq!(bp.hit_count, 0);
        }

        #[test]
        fn breakpoint_is_watchpoint() {
            assert!(!Breakpoint::new(1, 0, BreakpointKind::Software).is_watchpoint());
            assert!(!Breakpoint::new(1, 0, BreakpointKind::Hardware).is_watchpoint());
            assert!(Breakpoint::new(1, 0, BreakpointKind::WatchRead).is_watchpoint());
            assert!(Breakpoint::new(1, 0, BreakpointKind::WatchWrite).is_watchpoint());
            assert!(Breakpoint::new(1, 0, BreakpointKind::WatchReadWrite).is_watchpoint());
        }

        #[test]
        fn debug_session_new() {
            let s = DebugSession::new(1234);
            assert_eq!(s.pid, 1234);
            assert_eq!(s.bp_count(), 0);
            assert!(!s.running);
        }

        #[test]
        fn debug_session_add_remove_bp() {
            let mut s = DebugSession::new(1);
            let id = s.add_breakpoint(0x1000, BreakpointKind::Software);
            assert_eq!(s.bp_count(), 1);
            assert!(s.remove_breakpoint(id));
            assert_eq!(s.bp_count(), 0);
            assert!(!s.remove_breakpoint(id));
        }

        #[test]
        fn debug_session_enable_disable() {
            let mut s = DebugSession::new(1);
            let id = s.add_breakpoint(0x2000, BreakpointKind::Hardware);
            s.disable_bp(id);
            assert_eq!(s.enabled_bps().len(), 0);
            s.enable_bp(id);
            assert_eq!(s.enabled_bps().len(), 1);
        }

        #[test]
        fn debug_session_enabled_bps() {
            let mut s = DebugSession::new(1);
            let id1 = s.add_breakpoint(0x1000, BreakpointKind::Software);
            let _id2 = s.add_breakpoint(0x2000, BreakpointKind::Hardware);
            s.disable_bp(id1);
            assert_eq!(s.enabled_bps().len(), 1);
        }

        #[test]
        fn debug_session_bp_count() {
            let mut s = DebugSession::new(1);
            assert_eq!(s.bp_count(), 0);
            let _ = s.add_breakpoint(0x1000, BreakpointKind::Software);
            let _ = s.add_breakpoint(0x2000, BreakpointKind::Hardware);
            assert_eq!(s.bp_count(), 2);
        }

        #[test]
        fn stop_reason_display() {
            assert!(StopReason::Breakpoint(3).to_string().contains('3'));
            assert_eq!(StopReason::SingleStep.to_string(), "single step");
            assert!(
                StopReason::Exception {
                    code: 0xc0,
                    addr: 0x1000
                }
                .to_string()
                .contains("0xc0")
            );
            assert!(StopReason::ProcessExit(-1).to_string().contains("-1"));
            assert!(StopReason::Signal(11).to_string().contains("11"));
            assert!(
                StopReason::Watchpoint {
                    id: 2,
                    addr: 0x3000
                }
                .to_string()
                .contains("#2")
            );
            assert_eq!(StopReason::None.to_string(), "none");
        }

        #[test]
        fn mock_debugger_name() {
            let m = MockDebugger::new("mock");
            assert_eq!(m.name(), "mock");
        }

        #[test]
        fn mock_debugger_attach() {
            let mut m = make_mock();
            let s = m.attach(42).unwrap();
            assert_eq!(s.pid, 42);
        }

        #[test]
        fn mock_debugger_detach() {
            let mut m = make_mock();
            let s = m.attach(1).unwrap();
            assert!(m.detach(&s).is_ok());
        }

        #[test]
        fn mock_debugger_read_memory_ok() {
            let m = make_mock();
            let s = DebugSession::new(1);
            let bytes = m.read_memory(&s, 0x1000, 4).unwrap();
            assert_eq!(bytes.len(), 4);
        }

        #[test]
        fn mock_debugger_read_memory_unmapped() {
            let m = make_mock();
            let s = DebugSession::new(1);
            let err = m.read_memory(&s, 0xdead_0000, 4).unwrap_err();
            assert!(matches!(err, DebugError::MemRead(_)));
        }

        #[test]
        fn mock_debugger_write_memory() {
            let m = make_mock();
            let s = DebugSession::new(1);
            let n = m.write_memory(&s, 0x1000, &[0xCC; 4]).unwrap();
            assert_eq!(n, 4);
        }

        #[test]
        fn mock_debugger_read_registers() {
            let m = make_mock();
            let s = DebugSession::new(1);
            let regs = m.read_registers(&s).unwrap();
            assert_eq!(regs.get("rax"), Some(&0xdead_beef));
        }

        #[test]
        fn mock_debugger_step() {
            let m = make_mock();
            let mut s = DebugSession::new(1);
            let reason = m.step(&mut s).unwrap();
            assert!(matches!(reason, StopReason::None));
        }

        #[test]
        fn mock_debugger_cont() {
            let m = make_mock();
            let mut s = DebugSession::new(1);
            let reason = m.cont(&mut s).unwrap();
            assert!(matches!(reason, StopReason::None));
        }

        #[test]
        fn debug_error_display() {
            assert!(DebugError::AttachFailed(99).to_string().contains("99"));
            assert!(DebugError::NotAttached.to_string().contains("not attached"));
            assert!(DebugError::MemRead(0x1234).to_string().contains("0x1234"));
            assert!(DebugError::MemWrite(0x5678).to_string().contains("0x5678"));
            assert!(
                DebugError::RegError("rax".into())
                    .to_string()
                    .contains("rax")
            );
            assert!(
                DebugError::Platform("os error".into())
                    .to_string()
                    .contains("os error")
            );
        }

        #[test]
        fn mock_debugger_mem_preset() {
            let mut m = MockDebugger::new("x");
            m.mem.insert(0x4000, vec![0xCC; 16]);
            let s = DebugSession::new(1);
            let bytes = m.read_memory(&s, 0x4000, 4).unwrap();
            assert_eq!(bytes, vec![0xCC; 4]);
        }

        #[test]
        fn mock_debugger_regs_preset() {
            let mut m = MockDebugger::new("x");
            m.regs.insert("rbx".into(), 0x1234);
            let s = DebugSession::new(1);
            let regs: HashMap<String, u64> = m.read_registers(&s).unwrap();
            assert_eq!(regs["rbx"], 0x1234);
        }

        #[test]
        fn debug_session_enable_nonexistent_bp() {
            let mut s = DebugSession::new(1);
            assert!(!s.enable_bp(99));
            assert!(!s.disable_bp(99));
        }

        #[test]
        fn debug_session_multiple_bps_ids_unique() {
            let mut s = DebugSession::new(1);
            let id1 = s.add_breakpoint(0x1000, BreakpointKind::Software);
            let id2 = s.add_breakpoint(0x2000, BreakpointKind::Software);
            let id3 = s.add_breakpoint(0x3000, BreakpointKind::WatchWrite);
            assert_ne!(id1, id2);
            assert_ne!(id2, id3);
        }

        #[test]
        fn debug_session_stop_reason_stored() {
            let mut s = DebugSession::new(1);
            s.stop_reason = StopReason::Breakpoint(5);
            assert!(matches!(s.stop_reason, StopReason::Breakpoint(5)));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Register groups
// ─────────────────────────────────────────────────────────────────────────────

/// A logical group of registers, e.g. "general-purpose", "floating-point".
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum RegisterGroup {
    /// Integer general-purpose registers (rax, rbx, … on x86-64).
    GeneralPurpose,
    /// Floating-point / MMX / x87 registers.
    FloatingPoint,
    /// SIMD vector registers (xmm, ymm, zmm on x86; q0–q31 on ARM).
    Vector,
    /// Control, debug, segment, and other privileged registers.
    System,
    /// A user-defined group with a custom name.
    Custom(String),
}

impl std::fmt::Display for RegisterGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GeneralPurpose => write!(f, "general-purpose"),
            Self::FloatingPoint => write!(f, "floating-point"),
            Self::Vector => write!(f, "vector"),
            Self::System => write!(f, "system"),
            Self::Custom(n) => write!(f, "{n}"),
        }
    }
}

/// Metadata about a single register.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegisterInfo {
    /// The canonical name, e.g. `"rax"`.
    pub name: String,
    /// Alternate or short names, e.g. `["eax", "ax", "al"]`.
    pub aliases: Vec<String>,
    /// Width in bits.
    pub bit_width: u32,
    /// Which group this register belongs to.
    pub group: RegisterGroup,
    /// Architecture-specific numeric ID used in protocol messages.
    pub dwarf_id: Option<u32>,
    /// Human-readable description.
    pub description: String,
}

impl RegisterInfo {
    /// Create a new [`RegisterInfo`].
    #[must_use]
    pub fn new(name: impl Into<String>, bit_width: u32, group: RegisterGroup) -> Self {
        Self {
            name: name.into(),
            aliases: Vec::new(),
            bit_width,
            group,
            dwarf_id: None,
            description: String::new(),
        }
    }

    /// Add an alias name.
    #[must_use]
    pub fn with_alias(mut self, alias: impl Into<String>) -> Self {
        self.aliases.push(alias.into());
        self
    }

    /// Set the DWARF register number.
    #[must_use]
    pub const fn with_dwarf_id(mut self, id: u32) -> Self {
        self.dwarf_id = Some(id);
        self
    }

    /// Set a human-readable description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

/// A registry of all known registers for one architecture.
#[derive(Debug, Clone, Default)]
pub struct RegisterSchema {
    registers: Vec<RegisterInfo>,
    name_to_index: HashMap<String, usize>,
}

impl RegisterSchema {
    /// Create an empty schema.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a register definition. Duplicate names are silently overwritten.
    pub fn add(&mut self, info: RegisterInfo) {
        let idx = self.registers.len();
        self.name_to_index.insert(info.name.clone(), idx);
        for alias in &info.aliases {
            self.name_to_index.insert(alias.clone(), idx);
        }
        self.registers.push(info);
    }

    /// Look up a register by (possibly aliased) name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&RegisterInfo> {
        self.name_to_index
            .get(name)
            .and_then(|&i| self.registers.get(i))
    }

    /// Return all registers belonging to a particular group.
    #[must_use]
    pub fn by_group(&self, group: &RegisterGroup) -> Vec<&RegisterInfo> {
        self.registers
            .iter()
            .filter(|r| &r.group == group)
            .collect()
    }

    /// Return the total register count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.registers.len()
    }

    /// Returns `true` when no registers have been added yet.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.registers.is_empty()
    }

    /// Build the standard x86-64 register schema.
    #[must_use]
    pub fn x86_64() -> Self {
        let mut s = Self::new();
        // General-purpose
        for (name, aliases, dwarf) in &[
            ("rax", vec!["eax", "ax", "al", "ah"], 0u32),
            ("rbx", vec!["ebx", "bx", "bl", "bh"], 3),
            ("rcx", vec!["ecx", "cx", "cl", "ch"], 2),
            ("rdx", vec!["edx", "dx", "dl", "dh"], 1),
            ("rsi", vec!["esi", "si", "sil"], 4),
            ("rdi", vec!["edi", "di", "dil"], 5),
            ("rsp", vec!["esp", "sp", "spl"], 7),
            ("rbp", vec!["ebp", "bp", "bpl"], 6),
            ("r8", vec!["r8d", "r8w", "r8b"], 8),
            ("r9", vec!["r9d", "r9w", "r9b"], 9),
            ("r10", vec!["r10d", "r10w", "r10b"], 10),
            ("r11", vec!["r11d", "r11w", "r11b"], 11),
            ("r12", vec!["r12d", "r12w", "r12b"], 12),
            ("r13", vec!["r13d", "r13w", "r13b"], 13),
            ("r14", vec!["r14d", "r14w", "r14b"], 14),
            ("r15", vec!["r15d", "r15w", "r15b"], 15),
            ("rip", vec!["eip"], 16),
            ("rflags", vec!["eflags"], 49),
        ] {
            let mut info =
                RegisterInfo::new(*name, 64, RegisterGroup::GeneralPurpose).with_dwarf_id(*dwarf);
            for alias in aliases {
                info = info.with_alias(*alias);
            }
            s.add(info);
        }
        // Segment registers
        for name in &["cs", "ds", "es", "fs", "gs", "ss"] {
            s.add(RegisterInfo::new(*name, 16, RegisterGroup::System));
        }
        // SSE/AVX
        for i in 0u32..16 {
            let name = format!("xmm{i}");
            s.add(RegisterInfo::new(name, 128, RegisterGroup::Vector).with_dwarf_id(17 + i));
        }
        s
    }

    /// Build the standard ARM64 (`AArch64`) register schema.
    #[must_use]
    pub fn aarch64() -> Self {
        let mut s = Self::new();
        for i in 0u32..31 {
            let name = format!("x{i}");
            let alias = format!("w{i}");
            let mut info = RegisterInfo::new(name, 64, RegisterGroup::GeneralPurpose)
                .with_alias(alias)
                .with_dwarf_id(i);
            // AAPCS64 role names. These are ALIASES, not separate registers:
            // the rest of the crate (`register_context.rs`, the ARM64 minidump
            // CONTEXT decoder) refers to x29/x30 as `fp`/`lr`, and adding them
            // as distinct entries would create two registers with one DWARF id.
            info = match i {
                29 => info.with_alias("fp"),
                30 => info.with_alias("lr"),
                _ => info,
            };
            s.add(info);
        }
        s.add(RegisterInfo::new("sp", 64, RegisterGroup::GeneralPurpose).with_dwarf_id(31));
        s.add(RegisterInfo::new("pc", 64, RegisterGroup::GeneralPurpose).with_dwarf_id(32));
        s.add(RegisterInfo::new("xzr", 64, RegisterGroup::GeneralPurpose));
        for i in 0u32..32 {
            let name = format!("v{i}");
            let alias = format!("q{i}");
            let info = RegisterInfo::new(name, 128, RegisterGroup::Vector)
                .with_alias(alias)
                .with_dwarf_id(64 + i);
            s.add(info);
        }
        s
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Expression evaluator
// ─────────────────────────────────────────────────────────────────────────────

/// A token produced by the expression lexer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExprToken {
    /// A decimal, hex (`0x…`), or octal (`0…`) integer literal.
    Number(u64),
    /// A bare identifier (register name or symbol).
    Ident(String),
    /// `+`
    Plus,
    /// `-`
    Minus,
    /// `*`
    Star,
    /// `/`
    Slash,
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `[` — memory dereference open.
    LBracket,
    /// `]` — memory dereference close.
    RBracket,
    /// `&` — bitwise AND or address-of.
    Ampersand,
    /// `|` — bitwise OR.
    Pipe,
    /// `^` — bitwise XOR.
    Caret,
    /// `~` — bitwise NOT.
    Tilde,
    /// `<<`
    ShiftLeft,
    /// `>>`
    ShiftRight,
}

/// Errors produced during expression lexing or evaluation.
#[derive(Debug, thiserror::Error)]
pub enum ExprError {
    #[error("unexpected character: {0:?}")]
    UnexpectedChar(char),
    #[error("unexpected end of expression")]
    UnexpectedEnd,
    #[error("unknown register or symbol: {0}")]
    UnknownIdent(String),
    #[error("division by zero")]
    DivisionByZero,
    #[error("memory read failed at {0:#x}: {1}")]
    MemoryRead(u64, String),
    #[error("parse error: {0}")]
    Parse(String),
}

fn lex_number(
    first: char,
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Result<ExprToken, ExprError> {
    let mut s = String::from(first);
    while let Some(&d) = chars.peek() {
        if d.is_ascii_alphanumeric() { s.push(d); chars.next(); } else { break; }
    }
    let val = if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|e| ExprError::Parse(e.to_string()))?
    } else if s.starts_with('0') && s.len() > 1 {
        u64::from_str_radix(&s[1..], 8).map_err(|e| ExprError::Parse(e.to_string()))?
    } else {
        s.parse::<u64>().map_err(|e| ExprError::Parse(e.to_string()))?
    };
    Ok(ExprToken::Number(val))
}

fn lex_ident(
    first: char,
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> ExprToken {
    let mut s = String::from(first);
    while let Some(&d) = chars.peek() {
        if d.is_alphanumeric() || d == '_' { s.push(d); chars.next(); } else { break; }
    }
    ExprToken::Ident(s)
}

/// Tokenise an expression string into a flat [`Vec<ExprToken>`].
///
/// # Errors
/// Returns [`ExprError::UnexpectedChar`] on any unrecognised character.
pub fn tokenise(input: &str) -> Result<Vec<ExprToken>, ExprError> {
    let mut tokens = Vec::with_capacity(input.len() / 4 + 1);
    let mut chars = input.chars().peekable();
    while let Some(&ch) = chars.peek() {
        match ch {
            ' ' | '\t' | '\r' | '\n' => {
                chars.next();
            }
            '0'..='9' => {
                chars.next();
                tokens.push(lex_number(ch, &mut chars)?);
            }
            'a'..='z' | 'A'..='Z' | '_' => {
                chars.next();
                tokens.push(lex_ident(ch, &mut chars));
            }
            '+' => {
                chars.next();
                tokens.push(ExprToken::Plus);
            }
            '-' => {
                chars.next();
                tokens.push(ExprToken::Minus);
            }
            '*' => {
                chars.next();
                tokens.push(ExprToken::Star);
            }
            '/' => {
                chars.next();
                tokens.push(ExprToken::Slash);
            }
            '(' => {
                chars.next();
                tokens.push(ExprToken::LParen);
            }
            ')' => {
                chars.next();
                tokens.push(ExprToken::RParen);
            }
            '[' => {
                chars.next();
                tokens.push(ExprToken::LBracket);
            }
            ']' => {
                chars.next();
                tokens.push(ExprToken::RBracket);
            }
            '&' => {
                chars.next();
                tokens.push(ExprToken::Ampersand);
            }
            '|' => {
                chars.next();
                tokens.push(ExprToken::Pipe);
            }
            '^' => {
                chars.next();
                tokens.push(ExprToken::Caret);
            }
            '~' => {
                chars.next();
                tokens.push(ExprToken::Tilde);
            }
            '<' => {
                chars.next();
                if chars.peek() == Some(&'<') {
                    chars.next();
                    tokens.push(ExprToken::ShiftLeft);
                } else {
                    return Err(ExprError::UnexpectedChar('<'));
                }
            }
            '>' => {
                chars.next();
                if chars.peek() == Some(&'>') {
                    chars.next();
                    tokens.push(ExprToken::ShiftRight);
                } else {
                    return Err(ExprError::UnexpectedChar('>'));
                }
            }
            other => return Err(ExprError::UnexpectedChar(other)),
        }
    }
    Ok(tokens)
}

/// A simple recursive-descent evaluator for debugger watch expressions.
///
/// Supports: integer literals, register reads, bitwise ops, arithmetic,
/// parenthesisation, and memory dereferences `[addr]`.
/// Borrowed memory-reader callback used by `ExprEvaluator`.
pub type MemReader<'a> = &'a dyn Fn(u64, usize) -> Result<Vec<u8>, String>;

pub struct ExprEvaluator<'a> {
    tokens: Vec<ExprToken>,
    pos: usize,
    regs: &'a RegisterSet,
    mem_reader: Option<MemReader<'a>>,
}

impl<'a> ExprEvaluator<'a> {
    /// Create an evaluator that reads registers from `regs`.
    ///
    /// Memory dereferences will fail unless `with_mem_reader` is called.
    ///
    /// # Errors
    /// Returns an [`ExprError`] if the input expression fails to tokenise.
    pub fn new(input: &str, regs: &'a RegisterSet) -> Result<Self, ExprError> {
        let tokens = tokenise(input)?;
        Ok(Self {
            tokens,
            pos: 0,
            regs,
            mem_reader: None,
        })
    }

    /// Attach a memory-reader closure so that `[addr]` dereferences work.
    #[must_use]
    pub fn with_mem_reader(mut self, f: &'a dyn Fn(u64, usize) -> Result<Vec<u8>, String>) -> Self {
        self.mem_reader = Some(f);
        self
    }

    /// Evaluate the expression and return the 64-bit result.
    ///
    /// # Errors
    /// Returns an error on unknown identifiers, division by zero, or memory
    /// access failures.
    pub fn evaluate(&mut self) -> Result<u64, ExprError> {
        let v = self.parse_bitor()?;
        if self.pos != self.tokens.len() {
            return Err(ExprError::Parse("trailing tokens".into()));
        }
        Ok(v)
    }

    fn peek(&self) -> Option<&ExprToken> {
        self.tokens.get(self.pos)
    }

    fn next_tok(&mut self) -> Option<ExprToken> {
        let t = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn parse_bitor(&mut self) -> Result<u64, ExprError> {
        let mut v = self.parse_bitxor()?;
        while self.peek() == Some(&ExprToken::Pipe) {
            self.pos += 1;
            v |= self.parse_bitxor()?;
        }
        Ok(v)
    }

    fn parse_bitxor(&mut self) -> Result<u64, ExprError> {
        let mut v = self.parse_bitand()?;
        while self.peek() == Some(&ExprToken::Caret) {
            self.pos += 1;
            v ^= self.parse_bitand()?;
        }
        Ok(v)
    }

    fn parse_bitand(&mut self) -> Result<u64, ExprError> {
        let mut v = self.parse_shift()?;
        while self.peek() == Some(&ExprToken::Ampersand) {
            self.pos += 1;
            v &= self.parse_shift()?;
        }
        Ok(v)
    }

    fn parse_shift(&mut self) -> Result<u64, ExprError> {
        let mut v = self.parse_add()?;
        loop {
            match self.peek() {
                Some(ExprToken::ShiftLeft) => {
                    self.pos += 1;
                    let s = self.parse_add()?;
                    v = shift_left_64(v, s);
                }
                Some(ExprToken::ShiftRight) => {
                    self.pos += 1;
                    let s = self.parse_add()?;
                    v = shift_right_64(v, s);
                }
                _ => break,
            }
        }
        Ok(v)
    }

    fn parse_add(&mut self) -> Result<u64, ExprError> {
        let mut v = self.parse_mul()?;
        loop {
            match self.peek() {
                Some(ExprToken::Plus) => {
                    self.pos += 1;
                    v = v.wrapping_add(self.parse_mul()?);
                }
                Some(ExprToken::Minus) => {
                    self.pos += 1;
                    v = v.wrapping_sub(self.parse_mul()?);
                }
                _ => break,
            }
        }
        Ok(v)
    }

    fn parse_mul(&mut self) -> Result<u64, ExprError> {
        let mut v = self.parse_unary()?;
        loop {
            match self.peek() {
                Some(ExprToken::Star) => {
                    self.pos += 1;
                    v = v.wrapping_mul(self.parse_unary()?);
                }
                Some(ExprToken::Slash) => {
                    self.pos += 1;
                    let d = self.parse_unary()?;
                    if d == 0 {
                        return Err(ExprError::DivisionByZero);
                    }
                    v /= d;
                }
                _ => break,
            }
        }
        Ok(v)
    }

    fn parse_unary(&mut self) -> Result<u64, ExprError> {
        match self.peek().cloned() {
            Some(ExprToken::Minus) => {
                self.pos += 1;
                Ok(self.parse_primary()?.wrapping_neg())
            }
            Some(ExprToken::Tilde) => {
                self.pos += 1;
                Ok(!self.parse_primary()?)
            }
            _ => self.parse_primary(),
        }
    }

    fn parse_primary(&mut self) -> Result<u64, ExprError> {
        match self.peek().cloned() {
            Some(ExprToken::Number(n)) => {
                self.pos += 1;
                Ok(n)
            }
            Some(ExprToken::Ident(name)) => {
                self.pos += 1;
                if let Some(v) = self.regs.get(&name) {
                    return Ok(v);
                }
                // Try PC / SP shorthands
                if name == "pc" {
                    return Ok(self.regs.pc);
                }
                if name == "sp" {
                    return Ok(self.regs.sp);
                }
                if name == "fp" {
                    return Ok(self.regs.fp.unwrap_or(0));
                }
                Err(ExprError::UnknownIdent(name))
            }
            Some(ExprToken::LParen) => {
                self.pos += 1;
                let v = self.parse_bitor()?;
                if self.next_tok() != Some(ExprToken::RParen) {
                    return Err(ExprError::Parse("expected ')'".into()));
                }
                Ok(v)
            }
            Some(ExprToken::LBracket) => {
                self.pos += 1;
                let addr = self.parse_bitor()?;
                if self.next_tok() != Some(ExprToken::RBracket) {
                    return Err(ExprError::Parse("expected ']'".into()));
                }
                let reader = self
                    .mem_reader
                    .ok_or_else(|| ExprError::MemoryRead(addr, "no reader".into()))?;
                let bytes = reader(addr, 8).map_err(|e| ExprError::MemoryRead(addr, e))?;
                if bytes.len() < 8 {
                    return Err(ExprError::MemoryRead(addr, "short read".into()));
                }
                let val = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                Ok(val)
            }
            _ => Err(ExprError::UnexpectedEnd),
        }
    }
}

/// Evaluate a watch-expression string against a register set.
///
/// # Errors
/// Returns `ExprError` on any lexical or evaluation failure.
/// Does `event` answer a step that was asked of `tid`?
///
/// A debug loop waits on the whole PROCESS: `WaitForDebugEvent` and `waitpid`
/// both report whichever thread stops first. So `single_step(tid)` can come
/// back with an event belonging to another thread — a loader thread, a worker,
/// anything the target runs — and the requested thread has not moved at all.
///
/// `step_over`/`step_out` then read `get_registers(tid)`, see a stack pointer
/// that did not change, conclude "not a call, the step is done", and report
/// success for a step that never happened. Measured in iteration 475: the same
/// interference made a live test fail twice under a loaded parallel suite.
///
/// An EXIT always answers: the process is gone, so no further event can ever
/// belong to `tid`, and hiding it would be worse than the confusion it avoids.
#[must_use]
pub fn step_result_belongs_to(event: &DebugEvent, tid: ThreadId) -> bool {
    event.tid == tid || event.reason.is_exit()
}

/// Logical left shift of a 64-bit value, with a shift count that is NOT masked.
///
/// Rust silently reduces a shift count modulo 64, so `x << 64` returns `x` and
/// `x >> 100` returns `x >> 36`. In a debugger expression that is the most
/// misleading result available: shifting a value by its own full width visibly
/// ought to clear it, and instead the original number comes back looking like a
/// computed answer. Both evaluators in this crate did it, with two DIFFERENT
/// fabricated fallbacks for a huge count (`unwrap_or(63)` in one,
/// `unwrap_or(u32::MAX)` in the other).
///
/// The answer here is not a guess: every bit has been shifted out of a 64-bit
/// value, so the result is zero — which is also what gdb prints.
#[must_use]
pub const fn shift_left_64(value: u64, count: u64) -> u64 {
    if count >= 64 { 0 } else { value << count }
}

/// Logical right shift of a 64-bit value, with a shift count that is NOT masked.
///
/// See [`shift_left_64`].
#[must_use]
pub const fn shift_right_64(value: u64, count: u64) -> u64 {
    if count >= 64 { 0 } else { value >> count }
}

pub fn eval_expr(expr: &str, regs: &RegisterSet) -> Result<u64, ExprError> {
    let mut ev = ExprEvaluator::new(expr, regs)?;
    ev.evaluate()
}

// ─────────────────────────────────────────────────────────────────────────────
// Conditional / logging / tracepoint breakpoints
// ─────────────────────────────────────────────────────────────────────────────

/// Action to perform when a breakpoint is hit.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum BreakpointAction {
    /// Stop the target and notify the debugger (classic breakpoint).
    Stop,
    /// Evaluate and log `expr` without stopping.
    Log { expr: String },
    /// Execute a list of debugger commands without stopping.
    Commands { commands: Vec<String> },
    /// Silently record a trace point: capture registers at hit time.
    Trace,
    /// Automatically continue after evaluating `expr`.
    ContinueIf { condition: String },
}

/// An advanced breakpoint with condition, pass count, and action.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdvancedBreakpoint {
    /// Unique identifier.
    pub id: u64,
    /// Virtual address.
    pub address: u64,
    /// Condition expression (evaluated before firing).
    pub condition: Option<String>,
    /// Skip the first `ignore_count` hits.
    pub ignore_count: u64,
    /// What to do when the breakpoint fires.
    pub action: BreakpointAction,
    /// Total hit count.
    pub hit_count: u64,
    /// Whether this breakpoint is armed.
    pub enabled: bool,
    /// Human-readable label.
    pub label: Option<String>,
}

impl AdvancedBreakpoint {
    /// Create a new enabled "Stop" breakpoint at `address`.
    #[must_use]
    pub const fn new_stop(id: u64, address: u64) -> Self {
        Self {
            id,
            address,
            condition: None,
            ignore_count: 0,
            action: BreakpointAction::Stop,
            hit_count: 0,
            enabled: true,
            label: None,
        }
    }

    /// Create a logging tracepoint that doesn't stop the target.
    #[must_use]
    pub fn new_log(id: u64, address: u64, expr: impl Into<String>) -> Self {
        Self {
            id,
            address,
            condition: None,
            ignore_count: 0,
            action: BreakpointAction::Log { expr: expr.into() },
            hit_count: 0,
            enabled: true,
            label: None,
        }
    }

    /// Arm a condition expression that must evaluate to non-zero for the
    /// breakpoint to fire.
    #[must_use]
    pub fn with_condition(mut self, cond: impl Into<String>) -> Self {
        self.condition = Some(cond.into());
        self
    }

    /// Set the number of initial hits to ignore.
    #[must_use]
    pub const fn with_ignore_count(mut self, n: u64) -> Self {
        self.ignore_count = n;
        self
    }

    /// Set a label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Should the breakpoint fire on this hit, given the current register set?
    ///
    /// Returns `true` when the breakpoint should cause a stop or action.
    ///
    /// A condition that **cannot be evaluated** stops the target. That is the
    /// same rule the live path applies in
    /// [`crate::conditional_breakpoint::should_stop_for_condition`] and in each
    /// backend's `condition_allows_stop`, and this type had the opposite one: a
    /// typo'd register name, an unsupported operator, a memory operand that
    /// could not be read — anything that made evaluation fail — silently turned
    /// the breakpoint off. The user then watches their program run past a line
    /// they are breakpointed on and concludes the code never reaches it: a
    /// wrong conclusion about their PROGRAM, drawn from a fault in their
    /// CONDITION, with nothing on screen connecting the two.
    ///
    /// Stopping is merely noisy, and the user is standing at the breakpoint
    /// where they can see why. Two opposite answers to the same question in one
    /// crate is the part that could not stay.
    #[must_use]
    pub fn should_fire(&self, regs: &RegisterSet) -> bool {
        if !self.enabled {
            return false;
        }
        if self.hit_count < self.ignore_count {
            return false;
        }
        if let Some(cond) = &self.condition {
            match eval_expr(cond, regs) {
                Ok(0) => return false,
                // Err => fall through and stop. See the note above.
                Ok(_) | Err(_) => {}
            }
        }
        true
    }

    /// Record one hit; returns `true` when the breakpoint should actually fire.
    ///
    /// The pass count is tested against the hits BEFORE this one. Incrementing
    /// first made `ignore_count = N` skip only `N - 1` hits: a user asking to
    /// skip 100 iterations stopped on the 100th and debugged the wrong one,
    /// with nothing to say so — and it contradicted this field's own
    /// documented contract ("skip the first `ignore_count` hits") as well as
    /// gdb's `ignore`.
    pub fn record_hit(&mut self, regs: &RegisterSet) -> bool {
        let within_ignore = self.hit_count < self.ignore_count;
        self.hit_count += 1;
        if within_ignore {
            return false;
        }
        self.should_fire(regs)
    }
}

/// A registry of [`AdvancedBreakpoint`]s.
#[derive(Debug, Default)]
pub struct BreakpointRegistry {
    breakpoints: Vec<AdvancedBreakpoint>,
    next_id: u64,
}

impl BreakpointRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a breakpoint; returns its assigned ID.
    pub fn add(&mut self, mut bp: AdvancedBreakpoint) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        bp.id = id;
        self.breakpoints.push(bp);
        id
    }

    /// Add a plain stop breakpoint at `address`.
    pub fn add_stop(&mut self, address: u64) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.breakpoints
            .push(AdvancedBreakpoint::new_stop(id, address));
        id
    }

    /// Add a logging tracepoint.
    pub fn add_log(&mut self, address: u64, expr: impl Into<String>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.breakpoints
            .push(AdvancedBreakpoint::new_log(id, address, expr));
        id
    }

    /// Remove breakpoint by ID. Returns `true` if removed.
    pub fn remove(&mut self, id: u64) -> bool {
        let before = self.breakpoints.len();
        self.breakpoints.retain(|b| b.id != id);
        self.breakpoints.len() != before
    }

    /// Look up a breakpoint by ID.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<&AdvancedBreakpoint> {
        self.breakpoints.iter().find(|b| b.id == id)
    }

    /// Mutable look-up by ID.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut AdvancedBreakpoint> {
        self.breakpoints.iter_mut().find(|b| b.id == id)
    }

    /// Find all breakpoints at a given address.
    #[must_use]
    pub fn at_address(&self, addr: u64) -> Vec<&AdvancedBreakpoint> {
        self.breakpoints
            .iter()
            .filter(|b| b.address == addr)
            .collect()
    }

    /// Return the total number of breakpoints.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.breakpoints.len()
    }

    /// Returns `true` when there are no breakpoints.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.breakpoints.is_empty()
    }

    /// Enable a breakpoint by ID. Returns `true` when found.
    pub fn enable(&mut self, id: u64) -> bool {
        if let Some(bp) = self.get_mut(id) {
            bp.enabled = true;
            true
        } else {
            false
        }
    }

    /// Disable a breakpoint by ID (without removing it). Returns `true` when found.
    pub fn disable(&mut self, id: u64) -> bool {
        if let Some(bp) = self.get_mut(id) {
            bp.enabled = false;
            true
        } else {
            false
        }
    }

    /// Return a snapshot of all breakpoints.
    #[must_use]
    pub fn all(&self) -> Vec<&AdvancedBreakpoint> {
        self.breakpoints.iter().collect()
    }

    /// Serialise the registry to JSON.
    ///
    /// # Errors
    /// Propagates `serde_json` serialisation errors.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.breakpoints)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Watchpoint
// ─────────────────────────────────────────────────────────────────────────────

/// What kind of memory access should trigger a watchpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WatchpointKind {
    /// Fire on any read.
    Read,
    /// Fire on any write.
    Write,
    /// Fire on read or write.
    ReadWrite,
    /// Fire when the value at the address changes.
    Change,
}

impl std::fmt::Display for WatchpointKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
            Self::ReadWrite => write!(f, "read/write"),
            Self::Change => write!(f, "change"),
        }
    }
}

/// A hardware or software watchpoint on a memory range.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Watchpoint {
    /// Unique identifier.
    pub id: u64,
    /// Start of the watched region.
    pub address: u64,
    /// Number of bytes to watch.
    pub byte_size: usize,
    /// Access type that triggers the watchpoint.
    pub kind: WatchpointKind,
    /// Whether the watchpoint is armed.
    pub enabled: bool,
    /// Running hit count.
    pub hit_count: u64,
    /// Optional condition expression.
    pub condition: Option<String>,
    /// Last observed value (used for `Change` detection).
    pub last_value: Option<Vec<u8>>,
    /// Human label.
    pub label: Option<String>,
}

impl Watchpoint {
    /// Create a new enabled write watchpoint.
    #[must_use]
    pub const fn new(id: u64, address: u64, byte_size: usize, kind: WatchpointKind) -> Self {
        Self {
            id,
            address,
            byte_size,
            kind,
            enabled: true,
            hit_count: 0,
            condition: None,
            last_value: None,
            label: None,
        }
    }

    /// Detect whether a new memory value should fire this watchpoint.
    ///
    /// Returns `true` when `new_value` triggers the watchpoint.
    #[must_use]
    pub fn should_fire_on_value(&self, new_value: &[u8]) -> bool {
        if !self.enabled {
            return false;
        }
        match self.kind {
            WatchpointKind::Change => self.last_value.as_ref().is_none_or(|prev| prev != new_value),
            _ => true,
        }
    }

    /// Record a hit, updating `last_value` to `new_value`.
    pub fn record_hit(&mut self, new_value: Vec<u8>) {
        self.hit_count += 1;
        self.last_value = Some(new_value);
    }
}

/// Registry of active watchpoints.
#[derive(Debug, Default)]
pub struct WatchpointRegistry {
    watchpoints: Vec<Watchpoint>,
    next_id: u64,
}

impl WatchpointRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a watchpoint; returns its ID.
    pub fn add(&mut self, address: u64, size: usize, kind: WatchpointKind) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.watchpoints
            .push(Watchpoint::new(id, address, size, kind));
        id
    }

    /// Remove by ID. Returns `true` when found.
    pub fn remove(&mut self, id: u64) -> bool {
        let before = self.watchpoints.len();
        self.watchpoints.retain(|w| w.id != id);
        self.watchpoints.len() != before
    }

    /// Look up by ID.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<&Watchpoint> {
        self.watchpoints.iter().find(|w| w.id == id)
    }

    /// Mutable look-up by ID.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut Watchpoint> {
        self.watchpoints.iter_mut().find(|w| w.id == id)
    }

    /// Return the count of active watchpoints.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.watchpoints.len()
    }

    /// Returns `true` when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.watchpoints.is_empty()
    }

    /// Return all watchpoints covering an address range `[addr, addr+size)`.
    #[must_use]
    pub fn covering(&self, addr: u64, size: usize) -> Vec<&Watchpoint> {
        let len = size as u64;
        self.watchpoints
            .iter()
            .filter(|w| {
                // Two half-open ranges intersect iff the offset between their
                // starts is shorter than the earlier one's length. Computing an
                // end with `saturating_add` instead reports `u64::MAX` for a
                // region ending at `u64::MAX + 1`, and the strict `<` then
                // excludes the very last byte of the address space — a
                // watchpoint armed over it would never match (iter 273's shape,
                // missed by that sweep).
                let wlen = w.byte_size as u64;
                // An empty range on either side touches nothing; the offset
                // form below would otherwise report an intersection for it.
                if len == 0 || wlen == 0 {
                    return false;
                }
                if addr <= w.address {
                    w.address - addr < len
                } else {
                    addr - w.address < wlen
                }
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory search utilities
// ─────────────────────────────────────────────────────────────────────────────

/// A match found during a memory scan.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemoryMatch {
    /// Virtual address of the match start.
    pub address: u64,
    /// Matched bytes.
    pub bytes: Vec<u8>,
}

/// Options controlling a memory search.
#[derive(Debug, Clone)]
pub struct MemorySearchOptions {
    /// Only search within a specific memory region.  `None` = all mapped memory.
    pub region_filter: Option<std::ops::Range<u64>>,
    /// Maximum number of results to return.
    pub max_results: Option<usize>,
    /// Allow unaligned matches (default: `true`).
    pub allow_unaligned: bool,
    /// Alignment requirement in bytes (1 = any address).
    pub alignment: usize,
}

impl Default for MemorySearchOptions {
    fn default() -> Self {
        Self {
            region_filter: None,
            max_results: None,
            allow_unaligned: true,
            alignment: 1,
        }
    }
}

/// Search `haystack` for literal byte `needle` using a simple vectorised loop.
///
/// Returns a list of byte offsets within `haystack`.
#[must_use]
pub fn search_bytes_literal(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    let first = needle[0];
    let mut results = Vec::new();
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if haystack[i] == first && &haystack[i..i + needle.len()] == needle {
            results.push(i);
        }
        i += 1;
    }
    results
}

/// Search `haystack` for a pattern with wildcard bytes (0xFF in `mask` = match
/// any; 0x00 = must match `pattern` exactly).
///
/// Returns a list of byte offsets.
///
/// # Panics
/// Panics if `pattern` and `mask` have different lengths.
#[must_use]
pub fn search_bytes_masked(haystack: &[u8], pattern: &[u8], mask: &[u8]) -> Vec<usize> {
    assert_eq!(
        pattern.len(),
        mask.len(),
        "pattern and mask must be the same length"
    );
    if pattern.is_empty() {
        return Vec::new();
    }
    let mut results = Vec::new();
    'outer: for i in 0..haystack.len().saturating_sub(pattern.len() - 1) {
        for j in 0..pattern.len() {
            if mask[j] == 0 && haystack[i + j] != pattern[j] {
                continue 'outer;
            }
        }
        results.push(i);
    }
    results
}

/// Search for an integer value (`u8`/`u16`/`u32`/`u64`) in `haystack`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntWidth {
    /// 1 byte.
    U8,
    /// 2 bytes, little-endian.
    U16Le,
    /// 4 bytes, little-endian.
    U32Le,
    /// 8 bytes, little-endian.
    U64Le,
    /// 2 bytes, big-endian.
    U16Be,
    /// 4 bytes, big-endian.
    U32Be,
    /// 8 bytes, big-endian.
    U64Be,
}

/// Search `haystack` for all occurrences of `value` with the given width and
/// endianness.
///
/// Returns a list of byte offsets.
#[must_use]
pub fn search_int(haystack: &[u8], value: u64, width: IntWidth) -> Vec<usize> {
    let mut buf = [0u8; 8];
    let le = value.to_le_bytes();
    let len: usize = match width {
        IntWidth::U8    => { buf[0] = le[0]; 1 }
        IntWidth::U16Le => { buf[..2].copy_from_slice(&le[..2]); 2 }
        IntWidth::U32Le => { buf[..4].copy_from_slice(&le[..4]); 4 }
        IntWidth::U64Le => { buf.copy_from_slice(&le); 8 }
        IntWidth::U16Be => { buf[0] = le[1]; buf[1] = le[0]; 2 }
        IntWidth::U32Be => { buf[..4].copy_from_slice(&[le[3], le[2], le[1], le[0]]); 4 }
        IntWidth::U64Be => { buf.copy_from_slice(&value.to_be_bytes()); 8 }
    };
    search_bytes_literal(haystack, &buf[..len])
}

// ─────────────────────────────────────────────────────────────────────────────
// Call-stack unwinding
// ─────────────────────────────────────────────────────────────────────────────

/// Strategy used to unwind the call stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwindStrategy {
    /// Use DWARF `.debug_frame` / `.eh_frame` CFI records.
    Dwarf,
    /// Follow the frame-pointer chain (rbp on x86-64).
    FramePointer,
    /// Scan the stack for plausible return addresses.
    StackScan,
    /// Try DWARF first, fall back to frame-pointer, then stack-scan.
    Auto,
}

impl std::fmt::Display for UnwindStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dwarf => write!(f, "dwarf"),
            Self::FramePointer => write!(f, "frame-pointer"),
            Self::StackScan => write!(f, "stack-scan"),
            Self::Auto => write!(f, "auto"),
        }
    }
}

/// Trait for call-stack unwinders.
pub trait StackUnwinder: Send + Sync {
    /// Name of this unwinding strategy.
    fn strategy(&self) -> UnwindStrategy;
    /// Unwind `regs` given the memory image `mem` (base, data).
    ///
    /// # Errors
    /// Returns a description string on failure.
    fn unwind(&self, regs: &RegisterSet, mem: &[(u64, Vec<u8>)])
    -> Result<Vec<StackFrame>, String>;
}

/// A simple frame-pointer–based unwinder for x86-64.
pub struct FramePointerUnwinder;

impl StackUnwinder for FramePointerUnwinder {
    fn strategy(&self) -> UnwindStrategy {
        UnwindStrategy::FramePointer
    }

    fn unwind(
        &self,
        regs: &RegisterSet,
        mem: &[(u64, Vec<u8>)],
    ) -> Result<Vec<StackFrame>, String> {
        let mut frames = Vec::with_capacity(16);
        let mut fp = regs.fp.unwrap_or(0);
        let mut pc = regs.pc;
        let mut idx = 0usize;

        // Helper closure to read 8 bytes at a virtual address from mem image
        let read_u64 = |addr: u64| -> Option<u64> {
            for (base, data) in mem {
                // `addr + 8` wraps for an address near `u64::MAX`, which made
                // this bounds test pass, produced an enormous offset and
                // panicked on the slice. The frame pointer comes out of the
                // debuggee's memory, so it can be any value at all.
                let Some(off) = addr.checked_sub(*base).and_then(|d| usize::try_from(d).ok())
                else {
                    continue;
                };
                let Some(end) = off.checked_add(8) else { continue };
                if end <= data.len() {
                    let bytes: [u8; 8] = data[off..end].try_into().ok()?;
                    return Some(u64::from_le_bytes(bytes));
                }
            }
            None
        };

        loop {
            frames.push(StackFrame {
                index: idx,
                pc: Address::new(pc),
                sp: Address::new(regs.sp),
                fp: Some(Address::new(fp)),
                function_name: None,
                module: None,
                offset: None,
                source_file: None,
                source_line: None,
            });
            if fp == 0 || idx > 64 {
                break;
            }
            let Some(saved_fp) = read_u64(fp) else { break };
            let Some(ret_addr) = fp.checked_add(8).and_then(read_u64) else {
                break;
            };
            // The chain must move monotonically up a downward-growing stack.
            // Rejecting only `saved_fp == fp` let a two-node cycle A -> B -> A
            // run to the frame cap, reporting fabricated frames as a real call
            // chain. The twin unwinder in `memory_layout_view` already required
            // this; this one did not.
            if ret_addr == 0 || saved_fp <= fp {
                break;
            }
            fp = saved_fp;
            pc = ret_addr;
            idx += 1;
        }
        Ok(frames)
    }
}

/// A stub DWARF-based unwinder (not fully implemented — delegates to frame-pointer).
pub struct DwarfUnwinder;

impl StackUnwinder for DwarfUnwinder {
    fn strategy(&self) -> UnwindStrategy {
        UnwindStrategy::Dwarf
    }

    fn unwind(
        &self,
        regs: &RegisterSet,
        mem: &[(u64, Vec<u8>)],
    ) -> Result<Vec<StackFrame>, String> {
        // Full DWARF CFI parsing is architecture-specific; fall back.
        FramePointerUnwinder.unwind(regs, mem)
    }
}

/// An `Auto` unwinder that tries DWARF first, then frame-pointer.
pub struct AutoUnwinder;

impl StackUnwinder for AutoUnwinder {
    fn strategy(&self) -> UnwindStrategy {
        UnwindStrategy::Auto
    }

    fn unwind(
        &self,
        regs: &RegisterSet,
        mem: &[(u64, Vec<u8>)],
    ) -> Result<Vec<StackFrame>, String> {
        if let Ok(frames) = DwarfUnwinder.unwind(regs, mem)
            && !frames.is_empty()
        {
            return Ok(frames);
        }
        FramePointerUnwinder.unwind(regs, mem)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Debug session state machine
// ─────────────────────────────────────────────────────────────────────────────

/// High-level state of a debug session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SessionState {
    /// No process attached; waiting to launch or attach.
    Idle,
    /// A process has been launched/attached and is now stopped.
    Stopped,
    /// The target is executing; waiting for a stop event.
    Running,
    /// Single-stepping or stepping over.
    Stepping,
    /// Detaching from the process (transitional).
    Detaching,
    /// The process exited; session is over.
    Terminated,
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Stopped => write!(f, "stopped"),
            Self::Running => write!(f, "running"),
            Self::Stepping => write!(f, "stepping"),
            Self::Detaching => write!(f, "detaching"),
            Self::Terminated => write!(f, "terminated"),
        }
    }
}

impl SessionState {
    /// Returns `true` when the target can be commanded (stopped states).
    #[must_use]
    pub const fn can_command(&self) -> bool {
        matches!(self, Self::Stopped | Self::Stepping)
    }

    /// Returns `true` when the session is in an active (live) state.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        !matches!(self, Self::Idle | Self::Terminated)
    }

    /// Transition to `next`, returning `Err` if the transition is invalid.
    ///
    /// # Errors
    /// Returns the disallowed transition pair as a `String`.
    pub fn transition(self, next: Self) -> Result<Self, String> {
        use SessionState::{Detaching, Idle, Running, Stepping, Stopped, Terminated};
        let ok = matches!((self, next), (Idle, Stopped) | (Stopped, Running | Stepping | Detaching | Terminated) | (Running | Stepping, Stopped | Terminated) | (Detaching, Idle | Terminated));
        if ok {
            Ok(next)
        } else {
            Err(format!("invalid transition: {self} → {next}"))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Event dispatcher
// ─────────────────────────────────────────────────────────────────────────────

/// A callback function invoked on every [`DebugEvent`].
pub type EventCallback = Box<dyn Fn(&DebugEvent) + Send + Sync>;

/// A thread-safe event dispatcher: subscribers register callbacks and are
/// notified whenever a debug event is dispatched.
pub struct EventDispatcher {
    callbacks: parking_lot::RwLock<Vec<EventCallback>>,
}

impl EventDispatcher {
    /// Create an empty dispatcher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            callbacks: parking_lot::RwLock::new(Vec::new()),
        }
    }

    /// Register a callback to be called for every event.
    pub fn subscribe(&self, cb: EventCallback) {
        self.callbacks.write().push(cb);
    }

    /// Dispatch `event` to all registered callbacks.
    pub fn dispatch(&self, event: &DebugEvent) {
        for cb in self.callbacks.read().iter() {
            cb(event);
        }
    }

    /// Return the number of registered callbacks.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.callbacks.read().len()
    }
}

impl Default for EventDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for EventDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EventDispatcher({})", self.subscriber_count())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Debug snapshot
// ─────────────────────────────────────────────────────────────────────────────

/// A point-in-time snapshot of a thread's state, suitable for post-mortem
/// analysis or "time-travel" replay.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThreadSnapshot {
    /// Thread ID.
    pub tid: u32,
    /// Register values at capture time.
    pub registers: HashMap<String, u64>,
    /// PC at capture time.
    pub pc: u64,
    /// SP at capture time.
    pub sp: u64,
    /// Frame pointer at capture time, if available.
    pub fp: Option<u64>,
    /// Captured stack frames.
    pub frames: Vec<SnapshotFrame>,
}

/// A single frame within a [`ThreadSnapshot`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotFrame {
    /// Zero-based index.
    pub index: usize,
    /// Program counter.
    pub pc: u64,
    /// Stack pointer.
    pub sp: u64,
    /// Frame pointer, if available.
    pub fp: Option<u64>,
    /// Resolved function name.
    pub function_name: Option<String>,
    /// Module containing this frame.
    pub module: Option<String>,
}

/// A full process snapshot capturing memory regions, threads, and modules.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DebugSnapshot {
    /// Process ID.
    pub pid: u32,
    /// Nanosecond timestamp.
    pub timestamp: u64,
    /// Snapshot of each thread.
    pub threads: Vec<ThreadSnapshot>,
    /// Loaded module list.
    pub modules: Vec<SnapshotModule>,
    /// Captured memory regions (address, bytes).
    pub memory_regions: Vec<SnapshotMemoryRegion>,
    /// Why the process stopped at snapshot time.
    pub stop_reason: String,
}

/// Module entry in a debug snapshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotModule {
    /// Short name.
    pub name: String,
    /// Load base address.
    pub base: u64,
    /// Size in bytes.
    pub size: u64,
}

/// A captured slice of virtual memory.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotMemoryRegion {
    /// Start address.
    pub base: u64,
    /// Raw bytes.
    pub data: Vec<u8>,
    /// Whether the region was readable, writable, executable.
    pub flags: String,
}

impl DebugSnapshot {
    /// Create a new snapshot for `pid` at the current system time.
    #[must_use]
    pub fn new(pid: u32, stop_reason: impl Into<String>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| {
                let s = d.as_secs().saturating_mul(1_000_000_000);
                s.saturating_add(u64::from(d.subsec_nanos()))
            });
        Self {
            pid,
            timestamp,
            threads: Vec::new(),
            modules: Vec::new(),
            memory_regions: Vec::new(),
            stop_reason: stop_reason.into(),
        }
    }

    /// Add a thread snapshot.
    pub fn add_thread(&mut self, thread: ThreadSnapshot) {
        self.threads.push(thread);
    }

    /// Add a module entry.
    pub fn add_module(&mut self, module: SnapshotModule) {
        self.modules.push(module);
    }

    /// Add a memory region.
    pub fn add_memory_region(&mut self, region: SnapshotMemoryRegion) {
        self.memory_regions.push(region);
    }

    /// Find a thread by its TID.
    #[must_use]
    pub fn thread(&self, tid: u32) -> Option<&ThreadSnapshot> {
        self.threads.iter().find(|t| t.tid == tid)
    }

    /// Total bytes captured in all memory regions.
    #[must_use]
    pub fn total_memory_bytes(&self) -> usize {
        self.memory_regions.iter().map(|r| r.data.len()).sum()
    }

    /// Serialise to JSON.
    ///
    /// # Errors
    /// Propagates `serde_json` errors.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialise from JSON.
    ///
    /// # Errors
    /// Propagates `serde_json` errors.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Build a [`ThreadSnapshot`] from a [`RegisterSet`] and a list of stack frames.
    #[must_use]
    pub fn capture_thread(tid: u32, regs: &RegisterSet, frames: &[StackFrame]) -> ThreadSnapshot {
        let snapshot_frames = frames
            .iter()
            .map(|f| SnapshotFrame {
                index: f.index,
                pc: f.pc.as_u64(),
                sp: f.sp.as_u64(),
                fp: f.fp.map(rustre_core::Address::as_u64),
                function_name: f.function_name.clone(),
                module: f.module.clone(),
            })
            .collect();
        ThreadSnapshot {
            tid,
            registers: regs.regs.clone(),
            pc: regs.pc,
            sp: regs.sp,
            fp: regs.fp,
            frames: snapshot_frames,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Symbol resolver
// ─────────────────────────────────────────────────────────────────────────────

/// A resolved symbol: a name + address + optional size.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Symbol {
    /// Demangled name.
    pub name: String,
    /// Virtual address of the symbol start.
    pub address: u64,
    /// Size in bytes (0 when unknown).
    pub size: u64,
    /// Which module/section defines this symbol.
    pub module: Option<String>,
}

impl Symbol {
    /// Create a new symbol.
    #[must_use]
    pub fn new(name: impl Into<String>, address: u64) -> Self {
        Self {
            name: name.into(),
            address,
            size: 0,
            module: None,
        }
    }

    /// Returns `true` when `addr` falls within `[address, address+size)`.
    ///
    /// The end is never materialised. `address + size` wraps for a symbol at
    /// the top of the address space, and the comparison then reports that the
    /// symbol contains NOTHING — not even its own start. `saturating_add` is
    /// not the fix either: it caps at `u64::MAX`, which an exclusive upper
    /// bound then excludes, losing the very last byte. Comparing the OFFSET
    /// is exact everywhere, and cannot underflow after the lower-bound check.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        if self.size == 0 {
            return addr == self.address;
        }
        addr >= self.address && addr - self.address < self.size
    }
}

/// An in-memory symbol table with fast address and name lookups.
#[derive(Debug, Default)]
pub struct SymbolTable {
    symbols: Vec<Symbol>,
    by_name: HashMap<String, usize>,
}

impl SymbolTable {
    /// Create an empty symbol table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a symbol. If a symbol with the same name already exists, it is
    /// overwritten.
    pub fn add(&mut self, sym: Symbol) {
        let idx = self.symbols.len();
        self.by_name.insert(sym.name.clone(), idx);
        self.symbols.push(sym);
    }

    /// Look up a symbol by exact name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&Symbol> {
        self.by_name.get(name).and_then(|&i| self.symbols.get(i))
    }

    /// Resolve a virtual address to the best-matching symbol.
    ///
    /// Prefers exact matches, then the symbol whose range contains `addr`.
    #[must_use]
    pub fn resolve(&self, addr: u64) -> Option<&Symbol> {
        let mut best: Option<&Symbol> = None;
        for sym in &self.symbols {
            if sym.contains(addr) {
                match best {
                    None => best = Some(sym),
                    Some(b) if sym.address > b.address => best = Some(sym),
                    _ => {}
                }
            }
        }
        best
    }

    /// All symbols whose name contains `substr` (case-insensitive).
    #[must_use]
    pub fn search(&self, substr: &str) -> Vec<&Symbol> {
        let lower = substr.to_lowercase();
        self.symbols
            .iter()
            .filter(|s| s.name.to_lowercase().contains(&lower))
            .collect()
    }

    /// Return the total number of symbols.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Returns `true` when the table is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Disassembly line (architecture-agnostic)
// ─────────────────────────────────────────────────────────────────────────────

/// Mnemonic category for a disassembly line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InsnCategory {
    /// Arithmetic / logical.
    Alu,
    /// Load / store.
    Memory,
    /// Branch (conditional or unconditional).
    Branch,
    /// Call instruction.
    Call,
    /// Return instruction.
    Return,
    /// System call / interrupt.
    Syscall,
    /// Privileged / ring-0 instruction.
    Privileged,
    /// Unknown / unclassified.
    Other,
}

/// One decoded instruction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DisasmLine {
    /// Virtual address.
    pub address: u64,
    /// Raw bytes.
    pub bytes: Vec<u8>,
    /// Mnemonic string (e.g. `"mov"`).
    pub mnemonic: String,
    /// Operand string (e.g. `"rax, qword ptr [rbx+8]"`).
    pub operands: String,
    /// High-level category.
    pub category: InsnCategory,
    /// Whether the debugger has a breakpoint at this address.
    pub has_breakpoint: bool,
    /// Whether the PC is currently pointing here.
    pub is_current_pc: bool,
    /// Resolved symbol for this address, if any.
    pub symbol: Option<String>,
}

impl DisasmLine {
    /// Return the display string `"<mnemonic>  <operands>"`.
    #[must_use]
    pub fn display(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.clone()
        } else {
            format!("{:<10} {}", self.mnemonic, self.operands)
        }
    }

    /// Return the instruction length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` when the instruction is a zero-byte placeholder.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// A range of decoded instructions (a "disassembly listing").
#[derive(Debug, Default, Clone)]
pub struct DisasmListing {
    /// Instructions in address order.
    pub lines: Vec<DisasmLine>,
}

impl DisasmListing {
    /// Create an empty listing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up the instruction at `address`.
    #[must_use]
    pub fn at(&self, address: u64) -> Option<&DisasmLine> {
        self.lines.iter().find(|l| l.address == address)
    }

    /// Return the instruction count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.lines.len()
    }

    /// Returns `true` when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Render the listing as a formatted string, annotating `pc` and any
    /// breakpoints in `bps`.
    #[must_use]
    pub fn render(&self, pc: u64, bps: &[u64]) -> String {
        let mut out = String::new();
        for line in &self.lines {
            let bp_marker = if bps.contains(&line.address) {
                "●"
            } else {
                " "
            };
            let pc_marker = if line.address == pc { "→" } else { " " };
            let addr_str = format!("{:#018x}", line.address);
            let bytes_str: String = line
                .bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let sym = line
                .symbol
                .as_deref()
                .map(|s| format!(" <{s}>"))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "{pc_marker}{bp_marker} {addr_str}  {bytes_str:<24}  {}{sym}",
                line.display()
            );
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Source-level information
// ─────────────────────────────────────────────────────────────────────────────

/// A source file with content lines cached.
#[derive(Debug, Clone)]
pub struct SourceFile {
    /// Absolute path on the host system.
    pub path: String,
    /// Cached source lines (may be empty when content is not available).
    pub lines: Vec<String>,
    /// Language hint for syntax highlighting.
    pub language: Option<String>,
}

impl SourceFile {
    /// Create from path only (no cached content).
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            lines: Vec::new(),
            language: None,
        }
    }

    /// Return the 1-based line at `lineno`, or `None` when out of range.
    #[must_use]
    pub fn line(&self, lineno: usize) -> Option<&str> {
        self.lines.get(lineno.saturating_sub(1)).map(String::as_str)
    }

    /// Return a snippet `[start, end]` (1-based, inclusive).
    #[must_use]
    pub fn snippet(&self, start: usize, end: usize) -> Vec<(usize, &str)> {
        let lo = start.saturating_sub(1);
        let hi = end.min(self.lines.len());
        self.lines[lo..hi]
            .iter()
            .enumerate()
            .map(|(i, l)| (lo + i + 1, l.as_str()))
            .collect()
    }

    /// Line count.
    #[must_use]
    pub const fn line_count(&self) -> usize {
        self.lines.len()
    }
}

/// Source-level breakpoint (before address resolution).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SourceBreakpoint {
    /// Unique identifier.
    pub id: u64,
    /// Source file path.
    pub path: String,
    /// 1-based line number.
    pub line: u32,
    /// Optional column (1-based).
    pub column: Option<u32>,
    /// Whether the breakpoint has been successfully bound to an address.
    pub resolved: bool,
    /// Resolved virtual address, if any.
    pub address: Option<u64>,
}

impl SourceBreakpoint {
    /// Create an unresolved source breakpoint.
    #[must_use]
    pub fn new(id: u64, path: impl Into<String>, line: u32) -> Self {
        Self {
            id,
            path: path.into(),
            line,
            column: None,
            resolved: false,
            address: None,
        }
    }

    /// Bind this breakpoint to a virtual address.
    pub const fn resolve(&mut self, address: u64) {
        self.resolved = true;
        self.address = Some(address);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tracing helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Log a debug event with the `tracing` crate (INFO level).
pub fn trace_event(ev: &DebugEvent) {
    tracing::info!(
        pid = ev.pid.0,
        tid = ev.tid.0,
        ts  = ev.timestamp,
        reason = %ev.reason,
        "debug event"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Expanded tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_expanded {
    /// Byte offset just past the line that closes a body.
    ///
    /// Replaces a `find` for a hard-coded newline terminator that these guards
    /// used for a long time. MEASURED when the silent fallback was turned into a
    /// panic: the terminator never matched — these sources are CRLF and the
    /// literal was not — and `map_or(rest.len(), ...)` handed back the WHOLE REST
    /// OF THE FILE instead. SEVEN guards were passing while checking nothing,
    /// including ones that had already caught real defects when written.
    ///
    /// So: no escape sequences, no assumed line ending, and a panic rather than a
    /// fallback when the closing line is missing. A guard that cannot find its
    /// body must fail loudly, never quietly widen its gaze.
    /// The line separator used when re-joining stripped source lines.
    ///
    /// Its own function so nothing in these guards has to spell an escape
    /// sequence, which is how a real newline once ended up inside a comment and
    /// broke the file in a place rustc reported hundreds of lines away.
    fn nl_of_source() -> &'static str {
        "
"
    }

    fn body_end(rest: &str, closing: &str) -> usize {
        let mut at = 0usize;
        for line in rest.split_inclusive(char::from(10)) {
            at += line.len();
            if line.trim_end() == closing {
                return at;
            }
        }
        panic!("no closing line for this body: the extraction would have swallowed the rest of the file")
    }

    use super::*;

    // ── RegisterSchema ────────────────────────────────────────────────────────

    /// Sub-register names must resolve, and must be NARROWED.
    ///
    /// Two distinct failures are pinned here, and the second is the one that
    /// looks like data:
    /// * an absent name (al) made a condition unevaluable, so the fail-open
    ///   rule stopped the target on every hit — the condition was never
    ///   applied and nothing said so;
    /// * a name resolved WITHOUT narrowing compares the whole 64-bit parent,
    ///   so al == 0 is false whenever any higher byte happens to be set.
    #[test]
    fn sub_registers_resolve_and_are_narrowed_to_their_own_width() {
        let mut regs = RegisterSet::new();
        regs.set("rax", 0x1122_3344_5566_7788);
        assert_eq!(regs.get_narrowed("rax"), Some(0x1122_3344_5566_7788));
        assert_eq!(regs.get_narrowed("eax"), Some(0x5566_7788));
        assert_eq!(regs.get_narrowed("ax"), Some(0x7788));
        assert_eq!(regs.get_narrowed("al"), Some(0x88));
        // The trap: ah is bits 15:8, NOT another spelling of al.
        assert_eq!(
            regs.get_narrowed("ah"),
            Some(0x77),
            "ah is the SECOND byte; returning the low byte gives a plausible value from the wrong half of the register"
        );
        // Zero low byte with non-zero high bytes: the case where an
        // un-narrowed comparison silently answers the wrong question.
        regs.set("rbx", 0xFFFF_FFFF_FFFF_FF00);
        assert_eq!(regs.get_narrowed("bl"), Some(0));
        assert_eq!(regs.get_narrowed("bh"), Some(0xFF));

        regs.set("r9", 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(regs.get_narrowed("r9d"), Some(0xCAFE_BABE));
        assert_eq!(regs.get_narrowed("r9w"), Some(0xBABE));
        assert_eq!(regs.get_narrowed("r9b"), Some(0xBE));

        let mut a = RegisterSet::new();
        a.set("x0", 0x0102_0304_0506_0708);
        assert_eq!(a.get_narrowed("w0"), Some(0x0506_0708));
        a.set("x30", 1 << 40);
        assert_eq!(a.get_narrowed("w30"), Some(0));

        // An exact entry always wins over a derivation: a backend that stores
        // the narrow name itself knows better than this table.
        let mut exact = RegisterSet::new();
        exact.set("rax", 0);
        exact.set("al", 0x5A);
        assert_eq!(exact.get_narrowed("al"), Some(0x5A));

        // Unknown names stay unknown — no guessing.
        assert_eq!(regs.get_narrowed("not_a_register"), None);
        assert_eq!(regs.get_narrowed("w99"), None);
    }

    /// Every name the condition context populates must actually resolve, or
    /// the loop that fills it is quietly doing nothing for that entry.
    #[test]
    fn every_advertised_sub_register_name_resolves() {
        for name in SUB_REGISTER_NAMES {
            assert!(
                sub_register_of(name).is_some(),
                "{name} is advertised to condition contexts but resolves to nothing"
            );
        }
    }

    /// A shift count of 64 or more clears the value; it is never masked.
    ///
    /// Rust reduces a shift count modulo 64, so `x << 64` came back as `x` and
    /// `x >> 100` as `x >> 36`. For a debugger expression that is the most
    /// misleading answer available: the value looks computed and is simply the
    /// input. The two evaluators in this crate also disagreed on the huge-count
    /// fallback (one fabricated 63, the other u32::MAX), so the same expression
    /// had two wrong answers depending on which path evaluated it.
    #[test]
    fn a_shift_of_sixty_four_or_more_clears_the_value_instead_of_wrapping() {
        assert_eq!(shift_left_64(1, 63), 1u64 << 63);
        assert_eq!(shift_left_64(1, 64), 0, "shifting every bit out yields zero, not the input");
        assert_eq!(shift_left_64(0xFFFF_FFFF_FFFF_FFFF, 100), 0);
        assert_eq!(shift_left_64(3, u64::MAX), 0);
        assert_eq!(shift_right_64(0x8000_0000_0000_0000, 63), 1);
        assert_eq!(shift_right_64(0x8000_0000_0000_0000, 64), 0);
        assert_eq!(shift_right_64(0xDEAD_BEEF, 1_000_000), 0);
        // Ordinary counts are untouched.
        assert_eq!(shift_left_64(0xAB, 8), 0xAB00);
        assert_eq!(shift_right_64(0xAB00, 8), 0xAB);
    }

    /// Both evaluators must give that same answer: a condition that means one
    /// thing through `eval_expr` and another through the richer evaluator is a
    /// worse defect than either result on its own.
    #[test]
    fn both_expression_evaluators_agree_on_an_oversized_shift() {
        let regs = RegisterSet::new();
        for expr in ["1 << 64", "1 << 100", "255 >> 64", "255 >> 71"] {
            let simple = eval_expr(expr, &regs).expect("the lib evaluator must handle this");
            assert_eq!(simple, 0, "{expr} shifts every bit out, so it is zero");
        }
        assert_eq!(eval_expr("1 << 63", &regs).unwrap(), 1u64 << 63);
    }

    /// A step result must belong to the thread the step was asked of.
    ///
    /// The debug loop waits on the whole PROCESS, so `single_step(tid)` can
    /// return an event from a loader or worker thread while `tid` has not
    /// moved. `step_over` then read `tid`s registers, saw an unchanged stack
    /// pointer, concluded "not a call, done", and reported a completed
    /// step-over that never happened.
    #[test]
    fn a_step_result_from_another_thread_is_not_our_result() {
        let ours = ThreadId(7);
        let theirs = ThreadId(9);

        let mine = DebugEvent {
            reason: StopReason::SingleStep { address: Address(0x1000) },
            tid: ours,
            pid: ProcessId(1),
            timestamp: 0,
        };
        assert!(step_result_belongs_to(&mine, ours));

        let foreign = DebugEvent {
            reason: StopReason::Breakpoint {
                address: Address(0x2000),
                bp: Breakpoint::new_software(Address(0x2000)),
            },
            tid: theirs,
            pid: ProcessId(1),
            timestamp: 0,
        };
        assert!(
            !step_result_belongs_to(&foreign, ours),
            "another thread stopping is a real event, but it is not the answer to OUR step"
        );

        // An exit always answers: the process is gone, so no later event can
        // ever belong to `tid`, and hiding it would be worse than the
        // confusion it avoids.
        let gone = DebugEvent {
            reason: StopReason::ProcessExit { exit_code: 0 },
            tid: theirs,
            pid: ProcessId(1),
            timestamp: 0,
        };
        assert!(step_result_belongs_to(&gone, ours));
    }

    #[test]
    fn register_schema_x86_64_has_rax() {
        let s = RegisterSchema::x86_64();
        let info = s.get("rax").expect("rax must exist");
        assert_eq!(info.bit_width, 64);
        assert_eq!(info.group, RegisterGroup::GeneralPurpose);
    }

    #[test]
    fn register_schema_alias_lookup() {
        let s = RegisterSchema::x86_64();
        let via_alias = s.get("eax");
        assert!(via_alias.is_some(), "eax alias must resolve");
        assert_eq!(via_alias.unwrap().name, "rax");
    }

    #[test]
    fn register_schema_by_group_vector() {
        let s = RegisterSchema::x86_64();
        let vregs = s.by_group(&RegisterGroup::Vector);
        assert!(!vregs.is_empty(), "xmm registers must exist");
        for r in vregs {
            assert_eq!(r.bit_width, 128);
        }
    }

    #[test]
    fn register_schema_aarch64_sp_exists() {
        let s = RegisterSchema::aarch64();
        assert!(s.get("sp").is_some());
        assert!(s.get("x0").is_some());
        assert!(s.get("w0").is_some()); // alias
    }

    #[test]
    fn register_schema_custom_group() {
        let mut s = RegisterSchema::new();
        s.add(
            RegisterInfo::new("msr", 64, RegisterGroup::Custom("msr".into()))
                .with_description("Model-specific register"),
        );
        let found = s.get("msr").unwrap();
        assert_eq!(found.description, "Model-specific register");
    }

    // ── ExprEvaluator ─────────────────────────────────────────────────────────

    #[test]
    fn expr_literal_hex() {
        let regs = RegisterSet::new();
        assert_eq!(eval_expr("0x1234", &regs).unwrap(), 0x1234);
    }

    #[test]
    fn expr_add_sub() {
        let regs = RegisterSet::new();
        assert_eq!(eval_expr("10 + 3 - 2", &regs).unwrap(), 11);
    }

    #[test]
    fn expr_mul_div() {
        let regs = RegisterSet::new();
        assert_eq!(eval_expr("6 * 7 / 2", &regs).unwrap(), 21);
    }

    #[test]
    fn expr_bitwise_or() {
        let regs = RegisterSet::new();
        assert_eq!(eval_expr("0xF0 | 0x0F", &regs).unwrap(), 0xFF);
    }

    #[test]
    fn expr_bitwise_and() {
        let regs = RegisterSet::new();
        assert_eq!(eval_expr("0xFF & 0x0F", &regs).unwrap(), 0x0F);
    }

    #[test]
    fn expr_bitwise_xor() {
        let regs = RegisterSet::new();
        assert_eq!(eval_expr("0xFF ^ 0xF0", &regs).unwrap(), 0x0F);
    }

    #[test]
    fn expr_shift_left_right() {
        let regs = RegisterSet::new();
        assert_eq!(eval_expr("1 << 8", &regs).unwrap(), 256);
        assert_eq!(eval_expr("256 >> 4", &regs).unwrap(), 16);
    }

    #[test]
    fn expr_bitwise_not() {
        let regs = RegisterSet::new();
        assert_eq!(eval_expr("~0u64", &regs).unwrap_or(u64::MAX), u64::MAX);
        // simpler: ~0x00FF == 0xFFFFFFFFFFFFFF00
        assert_eq!(eval_expr("~0", &regs).unwrap(), u64::MAX);
    }

    #[test]
    fn expr_register_read() {
        let mut regs = RegisterSet::new();
        regs.set("rax", 0xABCD);
        assert_eq!(eval_expr("rax", &regs).unwrap(), 0xABCD);
    }

    #[test]
    fn expr_register_arithmetic() {
        let mut regs = RegisterSet::new();
        regs.set("rax", 100);
        assert_eq!(eval_expr("rax + 5", &regs).unwrap(), 105);
        assert_eq!(eval_expr("rax * 2", &regs).unwrap(), 200);
    }

    #[test]
    fn expr_division_by_zero() {
        let regs = RegisterSet::new();
        assert!(matches!(
            eval_expr("10 / 0", &regs),
            Err(ExprError::DivisionByZero)
        ));
    }

    #[test]
    fn expr_unknown_register() {
        let regs = RegisterSet::new();
        assert!(matches!(
            eval_expr("zz_unknown", &regs),
            Err(ExprError::UnknownIdent(_))
        ));
    }

    #[test]
    fn expr_parentheses() {
        let regs = RegisterSet::new();
        assert_eq!(eval_expr("(2 + 3) * 4", &regs).unwrap(), 20);
    }

    // ── AdvancedBreakpoint / BreakpointRegistry ───────────────────────────────

    #[test]
    fn advanced_bp_no_condition_fires() {
        let bp = AdvancedBreakpoint::new_stop(0, 0x1000);
        let regs = RegisterSet::new();
        assert!(bp.should_fire(&regs));
    }

    #[test]
    fn advanced_bp_condition_zero_doesnt_fire() {
        let bp = AdvancedBreakpoint::new_stop(0, 0x1000).with_condition("0");
        let regs = RegisterSet::new();
        assert!(!bp.should_fire(&regs));
    }

    #[test]
    fn advanced_bp_condition_nonzero_fires() {
        let bp = AdvancedBreakpoint::new_stop(0, 0x1000).with_condition("1");
        let regs = RegisterSet::new();
        assert!(bp.should_fire(&regs));
    }

    /// A condition that cannot be EVALUATED must stop the target, not silence
    /// the breakpoint.
    ///
    /// This type used to answer the opposite of the live path: an unparsable or
    /// unevaluable condition made `should_fire` return `false`, so the
    /// breakpoint quietly stopped existing. The user watches the program run
    /// past a line they are breakpointed on and concludes their code never
    /// reaches it — a wrong conclusion about the PROGRAM, caused by a fault in
    /// the CONDITION, with nothing tying the two together on screen.
    ///
    /// The assertion is paired with the working cases above on purpose: a
    /// version that simply returned `true` always would pass this test and fail
    /// `advanced_bp_condition_zero_doesnt_fire`, so the two together pin the
    /// policy rather than one direction of it.
    #[test]
    fn advanced_bp_an_unevaluable_condition_stops_instead_of_silencing_the_breakpoint() {
        let regs = RegisterSet::new();
        for broken in ["rax ?? 3", "$$$", "no_such_register_name_at_all", ""] {
            let bp = AdvancedBreakpoint::new_stop(0, 0x1000).with_condition(broken);
            assert!(
                bp.should_fire(&regs),
                "condition {broken:?} cannot be evaluated, so the stop must happen and the \
                 user must get the chance to see why — silently not firing reports a fault \
                 in the condition as a fact about the program"
            );
        }
        // And the same rule the live path states, in the live path's own words:
        // an unparsable condition there also stops.
        let ctx = crate::conditional_breakpoint::MapEvalContext::new();
        assert!(crate::conditional_breakpoint::should_stop_for_condition(
            Some("rax ?? 3"),
            &ctx
        ));
    }

    #[test]
    fn advanced_bp_ignore_count() {
        let mut bp = AdvancedBreakpoint::new_stop(0, 0x1000).with_ignore_count(2);
        let regs = RegisterSet::new();
        // "Skip the first 2 hits" means exactly two are skipped. The previous
        // version incremented before comparing and skipped only one, so
        // `ignore 2` stopped on the second hit — off by one, and silently: the
        // user sees a plausible stop at the wrong iteration.
        assert!(!bp.record_hit(&regs), "hit 1 is the first of the two skipped");
        assert!(!bp.record_hit(&regs), "hit 2 is the second of the two skipped");
        assert!(bp.record_hit(&regs), "hit 3 is the first that must stop");
        assert!(bp.record_hit(&regs));
        assert_eq!(bp.hit_count, 4, "skipped hits are still counted");
    }

    #[test]
    fn advanced_bp_disabled_never_fires() {
        let mut bp = AdvancedBreakpoint::new_stop(0, 0x1000);
        bp.enabled = false;
        let regs = RegisterSet::new();
        assert!(!bp.should_fire(&regs));
    }

    #[test]
    fn breakpoint_registry_add_remove() {
        let mut reg = BreakpointRegistry::new();
        let id = reg.add_stop(0x1000);
        assert_eq!(reg.len(), 1);
        assert!(reg.remove(id));
        assert!(reg.is_empty());
    }

    #[test]
    fn breakpoint_registry_at_address() {
        let mut reg = BreakpointRegistry::new();
        let _id1 = reg.add_stop(0x2000);
        let _id2 = reg.add_log(0x2000, "rax");
        let _id3 = reg.add_stop(0x3000);
        let at = reg.at_address(0x2000);
        assert_eq!(at.len(), 2);
    }

    #[test]
    fn breakpoint_registry_enable_disable() {
        let mut reg = BreakpointRegistry::new();
        let id = reg.add_stop(0x4000);
        assert!(reg.disable(id));
        assert!(!reg.get(id).unwrap().enabled);
        assert!(reg.enable(id));
        assert!(reg.get(id).unwrap().enabled);
    }

    #[test]
    fn breakpoint_registry_to_json() {
        let mut reg = BreakpointRegistry::new();
        reg.add_stop(0x5000);
        let json = reg.to_json().unwrap();
        // serde serialises u64 as decimal; 0x5000 == 20480
        assert!(json.contains("20480") || json.contains("5000"));
    }

    // ── WatchpointRegistry ────────────────────────────────────────────────────

    #[test]
    fn watchpoint_registry_add_remove() {
        let mut r = WatchpointRegistry::new();
        let id = r.add(0x8000, 4, WatchpointKind::Write);
        assert_eq!(r.len(), 1);
        assert!(r.remove(id));
        assert!(r.is_empty());
    }

    #[test]
    fn watchpoint_covering() {
        let mut r = WatchpointRegistry::new();
        r.add(0x1000, 8, WatchpointKind::Write);
        r.add(0x2000, 4, WatchpointKind::Read);
        // 0x1000..0x1008 overlaps with first
        let c = r.covering(0x1004, 4);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].address, 0x1000);
    }

    #[test]
    fn watchpoint_change_detection() {
        let mut w = Watchpoint::new(1, 0x9000, 4, WatchpointKind::Change);
        // First hit always fires (no previous value)
        assert!(w.should_fire_on_value(&[0xAA; 4]));
        w.record_hit(vec![0xAA; 4]);
        // Same value → no fire
        assert!(!w.should_fire_on_value(&[0xAA; 4]));
        // Different value → fire
        assert!(w.should_fire_on_value(&[0xBB; 4]));
    }

    // ── Memory search ─────────────────────────────────────────────────────────

    #[test]
    fn search_bytes_literal_found() {
        let data = b"hello world";
        let offsets = search_bytes_literal(data, b"world");
        assert_eq!(offsets, vec![6]);
    }

    #[test]
    fn search_bytes_literal_not_found() {
        let data = b"hello";
        assert!(search_bytes_literal(data, b"xyz").is_empty());
    }

    #[test]
    fn search_bytes_literal_multiple() {
        let data = b"abcabcabc";
        let offsets = search_bytes_literal(data, b"abc");
        assert_eq!(offsets, vec![0, 3, 6]);
    }

    #[test]
    fn search_bytes_masked_wildcard() {
        let data: Vec<u8> = vec![0x55, 0x48, 0x89, 0xE5, 0x48];
        let pattern = vec![0x55, 0x00, 0x89, 0xE5];
        let mask = vec![0x00, 0xFF, 0x00, 0x00];
        let offsets = search_bytes_masked(&data, &pattern, &mask);
        assert_eq!(offsets, vec![0]);
    }

    #[test]
    fn search_int_u32_le() {
        let data: Vec<u8> = vec![0x00, 0x00, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12];
        let offsets = search_int(&data, 0x1234_5678, IntWidth::U32Le);
        assert_eq!(offsets, vec![4]);
    }

    #[test]
    fn search_int_u8() {
        let data = vec![0x00u8, 0x90, 0x90, 0x01];
        let offsets = search_int(&data, 0x90, IntWidth::U8);
        assert_eq!(offsets, vec![1, 2]);
    }

    // ── SessionState machine ──────────────────────────────────────────────────

    #[test]
    fn session_state_transitions_valid() {
        use SessionState::*;
        assert!(Idle.transition(Stopped).is_ok());
        assert!(Stopped.transition(Running).is_ok());
        assert!(Running.transition(Stopped).is_ok());
        assert!(Stopped.transition(Detaching).is_ok());
        assert!(Detaching.transition(Idle).is_ok());
    }

    #[test]
    fn session_state_transitions_invalid() {
        use SessionState::*;
        assert!(Idle.transition(Running).is_err());
        assert!(Terminated.transition(Stopped).is_err());
        assert!(Running.transition(Idle).is_err());
    }

    #[test]
    fn session_state_can_command() {
        use SessionState::*;
        assert!(Stopped.can_command());
        assert!(Stepping.can_command());
        assert!(!Running.can_command());
        assert!(!Idle.can_command());
    }

    #[test]
    fn no_backend_silently_ignores_a_debug_register_write() {
        // Hardware watchpoints are armed by writing `dr0`-`dr7` through
        // `set_registers`. A backend that cannot program them must SAY SO,
        // not drop them and reply `Ok(())` — otherwise the watchpoint engine
        // believes it armed a watchpoint that can never fire, which is the
        // confidently-wrong failure mode this crate hunts hardest.
        //
        // Windows honours them via `CONTEXT_DEBUG_REGISTERS`; Linux via
        // `PTRACE_PEEKUSER`/`POKEUSER` (iter 124, which fixed exactly this
        // silent no-op); macOS cannot — Darwin needs the separate
        // `x86_DEBUG_STATE64` flavor — so it must reject the write (iter 252).
        //
        // Source-level so it covers macOS, which cannot be compiled here.
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let code: String = src
                .lines()
                .filter(|l| !l.trim_start().starts_with("//") && !l.trim_start().starts_with("///"))
                .collect::<Vec<_>>()
                .join("
");
            // Either it reads/writes the registers by name, or it refuses.
            let honours = code.contains("\"dr0\"") || code.contains("dr{idx}");
            let refuses = code.contains("cannot program x86 debug registers");
            assert!(
                honours || refuses,
                "{name}: neither programs `dr0`-`dr7` nor rejects a write to them — a                  hardware watchpoint armed through this backend would silently never fire"
            );
        }
    }

    #[test]
    fn every_debugger_backend_is_covered_by_the_source_guards() {
        // Iter 263 found a FOURTH `impl Debugger` that none of the then-seven
        // guards listed, and it carried a real bug they would have caught.
        // The lesson was written down; this makes it automatic, so a FIFTH
        // backend cannot appear unguarded.
        //
        // Both spellings must be searched: three backends write
        // `impl crate::Debugger for`, the Apple one writes `impl Debugger for`.
        // Looking for only one form finds half of them — which is exactly how
        // a gap like this hides.
        const COVERED: &[&str] = &[
            "windows_debugger.rs",
            "linux_debugger.rs",
            "macos_debugger.rs",
            "apple_debugger.rs",
        ];
        // `lib.rs` defines `MockDebugger`, which implements `Debugger` and is
        // NOT behind `#[cfg(test)]` — it has to be `pub` because integration
        // tests in `tests/` are separate crates and cannot see a cfg(test)
        // item. It is a test-support type, not a backend, so the cross-backend
        // guards rightly do not cover it.
        //
        // Its own doc says it "must never appear on a path that serves a
        // user". Nothing enforces that: being ungated and public, any crate in
        // the workspace can reach it, and at least one does
        // (`rustre-script-rhai/src/rhai_debug_api.rs`). Recorded here so the
        // exception stays a deliberate, visible decision rather than an
        // oversight this guard silently blesses.
        const TEST_SUPPORT: &[&str] = &["lib.rs"];

        // The COMPILE-time list, same as every other source guard.
        //
        // This walked `src/` itself until iteration 553 — a SECOND copy of the
        // discovery that `production_sources` already does. Iteration 549
        // converted that one and missed this one, so four guards started
        // working outside the repository and this one did not: it was the only
        // test still red on the iOS Simulator, for a reason that had nothing to
        // do with what it checks.
        //
        // This crate names the hazard elsewhere in its own words — "two parsers
        // of one format is how iteration 344's field-shift bug happened" — and
        // this was the same shape: two readers of one directory, one of them
        // fixed.
        let files: &[(&str, &str)] = EMBEDDED_SOURCES;
        assert!(!files.is_empty(), "build.rs embedded no sources");

        let mut backends = Vec::new();
        for (name, text) in files {
            let text: &str = text;
            let name = (*name).to_string();
            // Only PRODUCTION impls count. Cut at the test MODULE, not at the
            // first `#[cfg(test)]`: that attribute also gates individual
            // helpers — `linux_debugger.rs` has one at line ~792, hundreds of
            // lines above its real `impl` — and cutting there hid a genuine
            // backend from this very guard on the first attempt.
            //
            // Deliberately NOT special-casing `lib.rs` by name: if its
            // `MockDebugger` ever escaped `#[cfg(test)]` this guard should
            // shout, because a fake backend reachable in production is the
            // confidently-wrong surface this crate exists to avoid.
            let lines: Vec<&str> = text.lines().collect();
            let test_mod = lines.iter().enumerate().position(|(i, l)| {
                l.trim_start().starts_with("#[cfg(test)]")
                    && lines
                        .get(i + 1)
                        .is_some_and(|n| n.trim_start().starts_with("mod ")
                            || n.trim_start().starts_with("pub mod "))
            });
            let production: String = match test_mod {
                Some(cut) => lines[..cut].join("
"),
                None => text.to_string(),
            };
            let implements = production
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .any(|l| {
                    l.contains("impl Debugger for") || l.contains("impl crate::Debugger for")
                });
            if implements && !TEST_SUPPORT.contains(&name.as_str()) {
                backends.push(name);
            }
        }

        assert!(
            backends.len() >= COVERED.len(),
            "found fewer backends ({backends:?}) than the guards claim to cover — did one              get renamed? The guards' include_str! would still compile against a stale path"
        );
        for b in &backends {
            assert!(
                COVERED.contains(&b.as_str()),
                "`{b}` implements Debugger but no source guard lists it. Every guard that                  encodes a cross-backend invariant must name it, or it will silently miss                  the next family fix — which is precisely what happened in iters 242-246                  and again in 263."
            );
        }
    }

    /// Walk `src/` and return `(file_name, production_source)` for every `.rs`
    /// file, where `production_source` is the text ABOVE the `#[cfg(test)] mod`
    /// boundary — i.e. the code that actually ships.
    ///
    /// Cutting at the test MODULE and not at the first `#[cfg(test)]` matters:
    /// that attribute also gates individual helpers hundreds of lines earlier,
    /// and cutting there once hid a real backend from a sibling guard.
    fn production_sources() -> Vec<(String, String)> {
        // Embedded at COMPILE time by `build.rs`, not walked at run time.
        //
        // This used to `read_dir("src")`, which works only when the test binary
        // runs with the crate root as its working directory. It does not under
        // `xcrun simctl spawn`: five guards failed at once the first time this
        // suite ran for an Apple triple, because the simulator sandbox has no
        // repository at any path. `build.rs` explains why a generated list and
        // not a hand-written one.
        let files: &[(&str, &str)] = crate::EMBEDDED_SOURCES;
        assert!(!files.is_empty(), "build.rs embedded no sources");

        let mut out = Vec::new();
        for (name, text) in files {
            let text: &str = text;
            let name = (*name).to_string();
            // Strip the SPAN of every test module, rather than truncating at the
            // first one. Truncating was wrong, and silently so: `lib.rs` has a
            // test module at ~1611 and another at ~3992 with real production
            // code between them (`pub enum RegisterGroup`), and
            // `execution_heatmap.rs` defines `pub struct TraceHitBitmap` after
            // its first test module. Cutting at the first `#[cfg(test)] mod`
            // hid ~2400 lines of `lib.rs` from every guard built on this
            // helper. A blind region is worse than no guard: it reads as
            // coverage.
            let lines: Vec<&str> = text.lines().collect();
            let mut kept: Vec<&str> = Vec::new();
            let mut i = 0usize;
            while i < lines.len() {
                let opens_test_mod = lines[i].trim_start().starts_with("#[cfg(test)]")
                    && lines.get(i + 1).is_some_and(|n| {
                        let t = n.trim_start();
                        t.starts_with("mod ") || t.starts_with("pub mod ")
                    });
                if !opens_test_mod {
                    kept.push(lines[i]);
                    i += 1;
                    continue;
                }
                i += 1; // skip the attribute; `i` now sits on the `mod …` line
                let mut depth = 0i32;
                let mut seen_brace = false;
                while i < lines.len() {
                    // Braces inside char/string literals must not count.
                    // `rsp.rs` defines the RSP escape byte as `b'}'`, and
                    // counting that closed the test module ~120 lines early —
                    // the tail then leaked back in as "production" and the mock
                    // guard reported 7 phantom violations. Same trap the
                    // decompiler's brace-balance check documents: strip the
                    // literals first.
                    let cs: Vec<char> = lines[i].chars().collect();
                    let mut in_str = false;
                    let mut k = 0usize;
                    while k < cs.len() {
                        let ch = cs[k];
                        if in_str {
                            match ch {
                                '\\' => k += 1, // skip the escaped char
                                '"' => in_str = false,
                                _ => {}
                            }
                            k += 1;
                            continue;
                        }
                        match ch {
                            '"' => in_str = true,
                            // `'` opens a char literal only when a closing
                            // quote sits where one belongs; otherwise it is a
                            // LIFETIME (`&'a str`), and treating that as a
                            // literal would swallow the rest of the line.
                            '\'' => {
                                let lit_end = if cs.get(k + 1) == Some(&'\\') {
                                    cs.iter().skip(k + 2).position(|&c| c == '\'').map(|p| k + 2 + p)
                                } else if cs.get(k + 2) == Some(&'\'') {
                                    Some(k + 2)
                                } else {
                                    None
                                };
                                if let Some(end) = lit_end {
                                    k = end; // jump past the literal
                                }
                            }
                            '/' if cs.get(k + 1) == Some(&'/') => break, // comment
                            '{' => {
                                depth += 1;
                                seen_brace = true;
                            }
                            '}' => depth -= 1,
                            _ => {}
                        }
                        k += 1;
                    }
                    i += 1;
                    if seen_brace && depth <= 0 {
                        break;
                    }
                }
            }
            let production = kept.join("\n");
            out.push((name, production));
        }
        out
    }

    /// Guards the guards. Every source-level guard in this module trusts
    /// `production_sources()` to hand it the code that ships; if that helper
    /// drops production code, the guards report clean over a region nothing
    /// ever looked at. It did: it used to truncate the file at the first
    /// `#[cfg(test)] mod`, and two files in this crate define public items
    /// AFTER one. Those two items are the canary — they must be visible, and
    /// the test bodies must still be gone.
    /// Same overflow class as
    /// `watchpoint_engine::tests::a_watchpoint_at_the_top_of_the_address_space_still_fires`:
    /// `address + size` wraps for a symbol at the end of the address space, so
    /// `contains` reported that the symbol covered nothing at all — not even
    /// its own first byte. Symbolication of a kernel-space address then finds
    /// no symbol and the frame is reported as unknown.
    #[test]
    fn a_symbol_at_the_top_of_the_address_space_contains_its_own_range() {
        let mut sym = Symbol::new("kernel_tail", u64::MAX - 15);
        sym.size = 16;
        assert!(sym.contains(u64::MAX - 15), "does not contain its own start");
        assert!(sym.contains(u64::MAX), "does not contain its last byte");
        assert!(!sym.contains(u64::MAX - 16), "contains the byte before it");
    }

    #[test]
    fn the_source_guards_do_not_skip_production_code_after_a_test_module() {
        let sources = production_sources();
        let body = |file: &str| -> String {
            sources
                .iter()
                .find(|(name, _)| name == file)
                .map(|(_, text)| text.clone())
                .unwrap_or_else(|| panic!("{file} not among the scanned sources"))
        };

        let lib = body("lib.rs");
        assert!(
            lib.contains("pub enum RegisterGroup"),
            "`pub enum RegisterGroup` ships from lib.rs but production_sources() \
             did not return it — the helper is dropping production code, so every \
             guard built on it is blind to that region"
        );
        let heatmap = body("execution_heatmap.rs");
        assert!(
            heatmap.contains("pub struct TraceHitBitmap"),
            "`pub struct TraceHitBitmap` ships from execution_heatmap.rs but \
             production_sources() did not return it"
        );

        // …and the stripping still works: this very test lives in a
        // `#[cfg(test)]` module, so it must NOT come back as production.
        assert!(
            !lib.contains("fn the_source_guards_do_not_skip_production_code_after_a_test_module"),
            "production_sources() returned test-module code — the span stripping \
             is broken in the other direction, which would make the mock guard \
             fire on its own test fixtures"
        );
    }

    /// Which backends honour a watchpoint's requested WIDTH — declared, never
    /// assumed.
    ///
    /// [`Debugger::set_watchpoint_sized`] has a default implementation that
    /// forwards to `set_breakpoint` and drops `size`, so a backend that does not
    /// override it watches whatever width IT picks while the caller believes it
    /// asked for another. That is tolerable only for as long as it stays
    /// visible, which is this guard's whole job: adding a backend, or losing an
    /// override, fails here instead of quietly widening the gap.
    ///
    /// Every `Debugger` impl must be listed in exactly one of the two sets — a
    /// new backend cannot be forgotten, because an unclassified one fails.
    ///
    /// This test is named by the doc comment on `set_watchpoint_sized`, and
    /// when that comment was written (iter 298) it pointed at nothing: the test
    /// did not exist. That is precisely the defect iter 296 found in five
    /// documented APIs, committed here by the same hand one iteration later —
    /// which is why the doc now points at something that runs.
    /// Every cross-backend guard must name every backend, or say why it cannot.
    ///
    /// `every_debugger_backend_is_covered_by_the_source_guards` checks that each
    /// `Debugger` impl appears in a hand-kept `COVERED` list. That is an
    /// assurance given by the LIST, not by the guards: seven guards iterate
    /// `windows`/`linux`/`macos` and never look at the Apple backend at all, so
    /// their invariants were unverified there while the meta-guard reported it
    /// as covered.
    ///
    /// That gap is not hypothetical. `every_backend_orders_breakpoint_tracking_after_the_memory_write`
    /// pins one half of the tracking rule; its other half — look up, do not
    /// remove, until the un-patch has succeeded — was broken in the Apple
    /// backend and stayed broken until iter 285 found it by hand.
    ///
    /// So each such guard is classified here. Extending one to the Apple
    /// backend is the better fix wherever the property applies; where it cannot
    /// (x86 debug registers, the command-channel design the RSP session does not
    /// use), the reason is written down and stays visible.
    #[test]
    fn every_cross_backend_guard_names_apple_or_declares_why_not() {
        /// Guards that legitimately cannot look at the Apple backend, with why.
        const DECLARED_EXCLUSIONS: &[(&str, &str)] = &[
            (
                "no_backend_silently_ignores_a_debug_register_write",
                "x86 DR0-DR7: the Apple backend arms watchpoints with Z2/Z3/Z4 packets                  and never writes a debug register itself",
            ),
            (
                "no_backend_releases_the_command_lock_before_receiving_its_reply",
                "the three OS backends share one command channel guarded by a mutex;                  the RSP session has no such channel — its equivalent is the session                  mutex held across `with_session`",
            ),
        ];
        /// Guards whose property DOES apply to the Apple backend and which do
        /// not yet check it. Each is a known, accepted gap — shrinking this list
        /// is real work, and adding to it must be a deliberate act.
        const UNCHECKED_ON_APPLE: &[&str] = &[
            "every_backend_restores_breakpoints_when_dropped",
            "every_backend_records_the_stopping_thread_after_a_step_too",
        ];

        // The two lists above ARE the record: which cross-backend guards read
        // the Apple backend, and which do not. What this test enforces is that
        // the record cannot rot — every name must still be a test in this file.
        //
        // It deliberately does NOT try to derive the lists by scanning lib.rs.
        // Three attempts did, and all three were VACUOUS: splitting on the next
        // `fn` swallowed the following test's doc comment (which names the Apple
        // backend), and delimiting bodies by an indented closing brace
        // desynchronised the walk, because one of the guards being scanned
        // contains exactly that text inside a string literal. Each version
        // reported success while examining almost nothing. A guard that scans
        // the file it lives in is scanning code that scans files — the
        // delimiters collide. A list that is checked for existence is small,
        // exact, and cannot silently look at nothing.
        let src = include_str!("lib.rs");
        let mut missing = Vec::new();
        for name in DECLARED_EXCLUSIONS
            .iter()
            .map(|(n, _)| *n)
            .chain(UNCHECKED_ON_APPLE.iter().copied())
        {
            if !src.contains(&format!("fn {name}(")) {
                missing.push(name);
            }
        }
        assert!(
            missing.is_empty(),
            "these guards are recorded as skipping the Apple backend but no longer exist:              {missing:?}. If one was renamed, rename it here too; if it was extended to the              Apple backend, delete its entry — an entry that names nothing records nothing."
        );
    }

    /// No source guard may detect a backend by the SHORT `impl` spelling alone.
    ///
    /// The three native backends write `impl crate::Debugger for`; only the Apple
    /// one writes `impl Debugger for`. A guard that greps for the short form
    /// therefore silently inspects ONE backend out of four while its name and its
    /// assertion messages claim to speak for all of them — the exact failure this
    /// crate calls vacuous, and the worst kind, because a blind guard reads as
    /// coverage.
    ///
    /// It happened: `watchpoint_width_support_is_declared_not_assumed` skipped
    /// Windows, Linux and macOS, which is why its `USES_THE_DEFAULT` list could go
    /// on naming three backends that had overridden `set_watchpoint_sized` many
    /// iterations earlier. Nothing contradicted it because nothing looked.
    ///
    /// The needles are assembled at runtime so this guard does not match itself.
    /// The AArch64 watchpoint control word must be right bit for bit.
    ///
    /// Nothing on this host can run it, and an Apple Silicon Mac cannot tell a
    /// wrong encoding from a right one either: a bad `PAC` or a bad `BAS` gives a
    /// watchpoint that arms cleanly and never fires. So the encoding is pinned
    /// here, against the field layout in the ARM ARM (`DBGWCR<n>_EL1`).
    /// Apple Silicon must actually reach the AArch64 watchpoint registers.
    ///
    /// The x86 plumbing landed first; on ARM Macs `set_watchpoint_sized` still
    /// bailed out at its architecture gate, so a whole platform kept answering
    /// `Unsupported`. Source-level, because this host compiles that file for
    /// `aarch64-apple-darwin` but can never run it.
    /// A watchpoint hit must be REPORTED as one, in every backend.
    ///
    /// On all three systems a hardware watchpoint fires as an ordinary trap:
    /// SIGTRAP on the unixes, `EXCEPTION_SINGLE_STEP` on Windows. Only the debug
    /// STATUS register tells it apart from a genuine single step. Windows and
    /// Linux have read it for a long time; macOS never did — it armed the
    /// watchpoint, took the trap, and then classified every hit as a step,
    /// throwing away the one fact the caller set the watchpoint to learn.
    ///
    /// The status register is also STICKY: whoever reads it must clear it, or the
    /// first hit repeats itself on every later step for the life of the process.
    /// That is asserted here too, because forgetting it turns one true report
    /// into an endless stream of false ones.
    /// Register access must reach the thread the caller NAMED.
    ///
    /// The macOS backend resolved every register operation through
    /// `first_thread_port`, ignoring its `tid` — the command handlers spelled the
    /// parameter `_tid`, which is how it survived review. On a single-threaded
    /// target that is invisible. On any real one it is a debugger that answers
    /// confidently about the wrong thread: `get_registers(t5)` returned thread 0s
    /// program counter, `set_registers` wrote thread 0, and `backtrace` walked a
    /// stack that was not the one asked about.
    ///
    /// It also silently defeated the hardware watchpoints. `set_watchpoint_sized`
    /// loops over every thread precisely because x86 debug registers are
    /// per-thread and a watchpoint must fire whichever thread touches the
    /// address; with the tid discarded, that loop armed thread 0 once per
    /// iteration and left every other thread watching nothing, while reporting
    /// success.
    ///
    /// Source-level: this host compiles that file for both Apple targets and can
    /// never run it.
    /// A short memory read is a FAILURE in every backend, never a smaller answer.
    ///
    /// `read_memory(addr, n)` promises n bytes. All three operating systems can
    /// hand back fewer — the range runs off the end of a mapping, or crosses into
    /// an unreadable page. Windows checks `read == size` and Linux uses
    /// `read_exact_at`, so both refuse. macOS truncated the buffer and returned
    /// `Ok`, which is the same defect class this crate keeps finding: a caller
    /// asked for a struct and got its first half with nothing to say so, a
    /// disassembly stopped early and read as a function that ends there.
    ///
    /// The asymmetry mattered more than the individual bug: the same shared code
    /// above these backends was working against two different contracts
    /// depending on which OS it ran on.
    /// A partial memory WRITE is a failure in every backend too.
    ///
    /// The twin of the short-read guard below, and the more dangerous half.
    /// `WriteProcessMemory` returns TRUE having written fewer bytes than asked
    /// when the range runs into memory it cannot touch, and Windows handed that
    /// count back as `Ok`. Every caller in this crate discards the count:
    /// `detach()` and `remove_breakpoint` restore a breakpoint's original byte
    /// and check only for an error. A half-completed restore therefore reported
    /// success and left the `0xCC` in the target — the landmine `detach` exists
    /// to remove — while the bookkeeping that could have found it again was
    /// cleared on the strength of that same `Ok`.
    ///
    /// Linux (`write_all_at`) and macOS (`mach_vm_write`, all-or-nothing) already
    /// refuse. Comments are stripped so a guard cannot pass on its own prose.
    /// A ptrace backend knows its current thread the moment it attaches.
    ///
    /// Both unix backends reap the initial stop inside `do_launch`/`do_attach`
    /// and refuse to return unless the tracee is `WIFSTOPPED`, and both model the
    /// thread id as the pid. So immediately after a successful launch or attach
    /// the thread is stopped AND identified — but macOS left `current_tid` empty
    /// until somebody happened to call `continue_execution` first, so
    /// `current_thread()` answered `NotAttached` about a process it was demonstrably
    /// attached to. Everything that resolves "the current thread" internally
    /// (`LiveScriptContext`, `backtrace`, expression evaluation) was unusable in
    /// that window. Linux fixed it at iteration 137; the fix never crossed over.
    ///
    /// Windows is deliberately excluded: it learns its first thread id only from
    /// a subsequent `WaitForDebugEvent`, and one of its live tests pins
    /// `NotAttached` as the CORRECT answer right after launch. Asserting the same
    /// thing there would demand a lie.
    /// The signal or exception that stopped the target must reach the target.
    ///
    /// All three backends swallowed it. The ptrace pair passed a zero signal to
    /// `PTRACE_CONT`/`PT_CONTINUE`, so a SIGSEGV, SIGBUS, SIGFPE, SIGILL or an
    /// application-defined SIGUSR1 was reported to the caller and then dropped;
    /// Windows acknowledged every exception with `DBG_CONTINUE`, which means
    /// "handled", so a first-chance access violation never reached the program.
    ///
    /// The consequence is the same everywhere and it is the worst kind: the
    /// program behaves differently under the debugger than on its own. Its crash
    /// handler stays silent, its `__try` block never runs, a SIGSEGV-driven GC
    /// barrier or guard page never fires, and the faulting instruction simply
    /// re-executes. Observation changes the result.
    ///
    /// Traps the debugger causes itself are the exception to the rule and must
    /// still be swallowed: our `int3`, a single step, a debug register. Handing
    /// one of those to the target would deliver a signal it never received.
    /// ...but never the SIGSTOP the debugger itself sent.
    ///
    /// The companion of the guard below, and a defect that guard's own fix
    /// created. Both ptrace backends implement `pause()` by sending SIGSTOP, so
    /// with blanket re-injection that signal came straight back on the next
    /// resume and dropped the target into a job-control stop nobody asked for:
    /// `pause` then `continue` resumed nothing and the process sat at `T`, the
    /// same stuck state `detach` already sends a SIGCONT to undo.
    ///
    /// gdb draws exactly this line: a signal the debugger raised to gain control
    /// is not part of the program's behaviour and must not be delivered to it.
    /// A killed target must be REAPED, not left as a zombie.
    ///
    /// The unix backends launch the target themselves, which makes the debugger
    /// its parent: a corpse nobody waits on stays in the process table for the
    /// whole life of the debugger. A tool that launches and kills many targets
    /// leaks one pid per target. Linux reaps with a blocking wait, its comment
    /// recording a live test that failed when the wait was made non-blocking;
    /// macOS issued `PT_KILL` and returned immediately, so it leaked the corpse
    /// AND replied `Ok` while the kernel was still tearing the process down —
    /// so a caller that checked liveness or relaunched right afterwards raced it.
    ///
    /// Windows is excluded on purpose: `TerminateProcess` plus closing the handle
    /// leaves nothing to reap, there being no wait-for-child model there.
    #[test]
    fn both_ptrace_backends_reap_the_process_they_kill() {
        for (name, src) in [
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let start = src
                .find("Command::Kill =>")
                .unwrap_or_else(|| panic!("{name}: no Kill handler"));
            // Bounded by the module-level helper, so a handler that lost its
            // closing line fails loudly instead of widening to the rest of the
            // file (iteration 403).
            let rest = &src[start..];
            // COMMENTS STRIPPED. Measured: without this the guard passed with
            // the reap deleted, because the explanatory comment right above it
            // spells `waitpid(...)` out twice. A guard that can be satisfied by
            // its own prose checks nothing.
            let handler: String = rest[..body_end(rest, "            }")]
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join(nl_of_source());
            assert!(
                handler.contains("waitpid("),
                "{name}: the kill path never waits on the corpse, so the target stays a zombie for the life of the debugger and kill() returns before the process is actually gone"
            );
            // At least one BLOCKING wait. `WNOHANG` is legitimate for draining
            // sibling threads afterwards — Linux does exactly that — but if
            // EVERY wait is non-blocking then kill() can still return while the
            // kernel is mid-teardown, the race Linux measured and documented.
            let has_blocking_wait = handler
                .lines()
                .any(|l| l.contains("waitpid(") && !l.contains("WNOHANG"));
            assert!(
                has_blocking_wait,
                "{name}: every reap in the kill path is non-blocking, so kill() can return before the process is actually gone"
            );
        }
    }

    #[test]
    fn no_ptrace_backend_reinjects_the_sigstop_it_sent_itself() {
        for (name, src) in [
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let code: String = src
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join(" ");
            assert!(
                code.contains("libc::SIGSTOP") && code.contains("pause"),
                "{name}: pause() no longer stops the target with SIGSTOP, so the exclusion below may be guarding the wrong signal"
            );
            assert!(
                code.contains("if *signum != libc::SIGSTOP => *signum"),
                "{name}: the pause SIGSTOP is re-injected on resume, so pause() followed by continue() stops the target again instead of resuming it"
            );
        }
    }

    #[test]
    fn every_backend_delivers_the_signal_that_stopped_the_target() {
        for (name, src) in [
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let code: String = src
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join(" ");
            assert!(
                code.contains("let mut pending_signal"),
                "{name}: nothing remembers the signal the tracee stopped by, so the resume delivers zero and the signal is swallowed"
            );
            assert!(
                // The arm gained a guard clause when the pause SIGSTOP was
                // excluded (see the guard above); the needle follows it. What is
                // checked is unchanged: the pending signal comes from the stop
                // event and not from thin air.
                code.contains("StopReason::Signal { signum, .. } if *signum != libc::SIGSTOP => *signum"),
                "{name}: the pending signal is never taken from the stop event, so it can only ever be zero"
            );
            assert!(
                code.contains("let deliver = pending_signal;"),
                "{name}: the resume path no longer hands the pending signal to ptrace"
            );
        }

        let windows: String = include_str!("windows_debugger.rs")
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            windows.contains("fn continue_status_for("),
            "windows: nothing decides between DBG_CONTINUE and DBG_EXCEPTION_NOT_HANDLED, so every exception is answered as handled and the application never sees its own faults"
        );
        assert!(
            windows.contains("DBG_EXCEPTION_NOT_HANDLED"),
            "windows: the pass-it-to-the-application status is gone"
        );
        assert!(
            !windows.contains("ContinueDebugEvent(pid, last_tid, DBG_CONTINUE)"),
            "windows: an acknowledgement is hard-wired to DBG_CONTINUE again, which swallows the application's own exceptions"
        );
    }

    #[test]
    fn both_ptrace_backends_know_their_current_thread_right_after_launch_and_attach() {
        // Escape-free on purpose. These sources are CRLF, and the usual
        // terminator search finds nothing in them: the fallback then hands back
        // the whole rest of the file, and this guard passed with the very line it
        // protects deleted (measured, before it ever ran in anger). `lines()`
        // handles both endings, and running out of lines without a closing brace
        // is a panic rather than a silently oversized body.
        fn body(src: &str, f: &str) -> String {
            let start = src.find(f).unwrap_or_else(|| panic!("missing {f}"));
            let mut out = String::new();
            let mut closed = false;
            for line in src[start..].lines() {
                out.push_str(line);
                out.push(' ');
                if line == "    }" {
                    closed = true;
                    break;
                }
            }
            assert!(closed, "no closing brace for {f}: the extraction would have swallowed the rest of the file");
            out
        }

        for (name, src) in [
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            for entry in ["async fn launch(", "async fn attach("] {
                let b = body(src, entry);
                assert!(
                    b.len() > 200 && b.len() < 4000,
                    "{name}: the extraction for `{entry}` degenerated, so this guard would be checking nothing"
                );
                assert!(
                    b.contains("*self.current_tid.lock() = Some("),
                    "{name}: `{entry}` leaves current_tid empty, so current_thread() reports NotAttached for a process that is stopped and whose thread id is already known — and every API that resolves the current thread internally fails until the caller happens to continue first"
                );
            }
        }
    }

    #[test]
    fn every_backend_refuses_a_partial_memory_write() {
        for (name, src, needle) in [
            ("windows", include_str!("windows_debugger.rs"), "written == data.len()"),
            ("linux", include_str!("linux_debugger.rs"), "write_all_at("),
            ("macos", include_str!("macos_debugger.rs"), "mach_vm_write("),
        ] {
            let code: String = src
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("
");
            assert!(
                code.contains(needle),
                "{name}: write_memory no longer guarantees that every byte was written, so a half-finished breakpoint restore reports success and leaves a trap in the target"
            );
        }
    }

    #[test]
    fn every_backend_refuses_a_short_memory_read() {
        for (name, src, needle) in [
            ("windows", include_str!("windows_debugger.rs"), "read == size"),
            ("linux", include_str!("linux_debugger.rs"), "read_exact_at("),
            ("macos", include_str!("macos_debugger.rs"), "out_size as usize != size"),
        ] {
            let code: String = src
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("
");
            assert!(
                code.contains(needle),
                "{name}: read_memory no longer checks that it got every byte it was asked for, so a partial read is reported as a successful smaller one"
            );
        }

        // And macOS must not go back to quietly shrinking the buffer.
        let macos: String = include_str!("macos_debugger.rs")
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("
");
        assert!(
            !macos.contains("buf.truncate(out_size as usize)"),
            "macos: the buffer is being truncated to whatever was readable again, which is exactly how the short read used to pass for success"
        );
    }

    #[test]
    fn the_macos_backend_reads_the_registers_of_the_thread_it_was_asked_about() {
        let src = include_str!("macos_debugger.rs");
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("
");

        assert!(
            code.contains("fn thread_port_for("),
            "macos: nothing resolves a ThreadId to its Mach port, so every register operation lands on whatever thread happens to be first"
        );
        assert!(
            !code.contains("Command::GetRegisters(_tid)") && !code.contains("Command::SetRegisters(_tid,"),
            "macos: a register handler still discards its tid — the underscore is the whole defect, and it reads as deliberate"
        );
        assert!(
            code.contains("read_thread_state(task, Some(tid))") && code.contains("write_thread_state(task, Some(tid),"),
            "macos: the register handlers no longer pass the caller tid down to the thread state"
        );
        // A tid that matches no live thread must be an error. Falling back to the
        // first thread is precisely how the original defect looked correct.
        assert!(
            code.contains("no live thread with id"),
            "macos: an unknown tid silently resolves to some other thread instead of failing"
        );
    }

    /// Installing a symbol resolver must not silently do nothing.
    ///
    /// The trait default took the resolver, dropped it and returned `()`. A
    /// caller holding a `&dyn Debugger` therefore switched symbolication on, got
    /// no error, and read backtrace after backtrace with every `function_name`
    /// empty — with nothing at runtime to tell "this backend cannot symbolicate"
    /// apart from "these frames have no symbols". A doc comment saying "the
    /// default is a no-op" is not something a caller can branch on.
    ///
    /// Same rule this crate applies to `set_registers` (a name the register
    /// block cannot carry is an error, not a skipped write), to short reads and
    /// to partial writes: an operation that did not happen must not report
    /// success.
    #[test]
    fn a_backend_that_cannot_symbolicate_says_so_instead_of_dropping_the_resolver() {
        // Source-level for the default itself: no type in THIS crate takes it
        // today (the four backends all override), so there is nothing to call.
        // The guard exists for the next implementor — and for anyone tempted to
        // put the silent `{}` back.
        let lib: String = include_str!("lib.rs")
            .lines()
            .filter(|l| !l.trim_start().starts_with("//") && !l.trim_start().starts_with("///"))
            .collect::<Vec<_>>()
            .join(" ");
        let at = lib
            .find("fn set_symbol_resolver(")
            .expect("the trait must still declare set_symbol_resolver");
        let default_body = &lib[at..(at + 400).min(lib.len())];
        assert!(
            default_body.contains("Result<(), DebugError>"),
            "the default returns nothing again, so a backend that cannot symbolicate accepts a resolver and reports success"
        );
        assert!(
            default_body.contains("DebugError::Unsupported"),
            "the default no longer refuses: it takes the resolver, drops it, and the caller reads unsymbolicated backtraces with no way to know why"
        );

        // And every real backend must accept one, or the guard above would be
        // describing the whole crate rather than the default.
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
            ("apple", include_str!("ios/apple_debugger.rs")),
        ] {
            let code: String = src
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join(" ");
            assert!(
                code.contains("fn set_symbol_resolver"),
                "{name}: no longer overrides set_symbol_resolver, so it now inherits the refusing default and can never symbolicate a backtrace"
            );
        }
    }

    /// A breakpoint condition must be CONSULTED on the stop path.
    ///
    /// Storing the expression is half the feature; until `continue_execution`
    /// reads it, a conditional breakpoint stops on every hit — worse than not
    /// having the feature, because the caller believes the filter is applied.
    ///
    /// Source-level, and deliberately so: a live test was written for this and
    /// MEASURED not to discriminate (the loader breakpoint is executed once, so
    /// "never stopped there again" is true whether or not the condition is read).
    /// It was deleted rather than kept as false comfort — the same call this crate
    /// made for the partial-write test in iteration 401.
    #[test]
    fn every_backend_consults_the_breakpoint_condition_before_reporting_a_stop() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let code: String = src
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join(" ");
            assert!(
                code.contains("async fn condition_allows_stop("),
                "{name}: nothing evaluates a breakpoint condition, so an attached expression is stored and never read"
            );
            assert!(
                code.contains("if !self.condition_allows_stop(ev).await {"),
                "{name}: continue_execution no longer consults the condition, so a conditional breakpoint stops on every hit"
            );
            // The skipped stop must be un-counted, or the hit statistics
            // contradict what the user is watching happen.
            assert!(
                code.contains("*n = n.saturating_sub(1);"),
                "{name}: a stop filtered out by its condition is still counted as a hit"
            );
        }
    }

    /// A step must act on the thread the CALLER named.
    ///
    /// `step_off_planted_breakpoint` read `current_tid` unconditionally. That was
    /// harmless while its result was discarded; once `single_step` began
    /// RETURNING that event (iteration 435), asking to step thread B while thread
    /// A sat on a planted trap stepped **A** and handed the event back as the
    /// answer for B. The caller is told its thread advanced when a different one
    /// did — and nothing in the reply says otherwise.
    ///
    /// Source-level, and honestly so: a live test was written for this and
    /// MEASURED not to discriminate — with the injected loop the wrong thread
    /// returns to the same address either way, so neither its pc nor its
    /// accumulator separates the two behaviours reliably. The live test is kept
    /// for what it does cover, and this guard is the evidence for the fix.
    #[test]
    fn every_backend_steps_the_thread_the_caller_named() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let code: String = src
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join(" ");
            assert!(
                code.contains("step_off_planted_breakpoint(&self, who: Option<ThreadId>)"),
                "{name}: the step-off no longer takes the thread to act on, so it falls back to whichever thread last stopped"
            );
            assert!(
                code.contains("who.or(*self.current_tid.lock())"),
                "{name}: the step-off ignores the thread it was given"
            );
            assert!(
                code.contains("step_off_planted_breakpoint(Some(tid))"),
                "{name}: single_step does not pass its own tid to the step-off, so it can step a different thread and return that as its answer"
            );
            assert!(
                code.contains("step_off_planted_breakpoint(None)"),
                "{name}: continue_execution must keep using the thread that stopped, which is what None means here"
            );
        }
    }

    #[test]
    fn every_backend_reports_a_watchpoint_hit_instead_of_calling_it_a_step() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let code: String = src
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("
");
            assert!(
                code.contains("x86_watchpoint_hit_slot("),
                "{name}: nothing decodes the debug status register, so every watchpoint hit is reported as a plain single step and the watched address is lost"
            );
            assert!(
                code.contains("x86_watchpoint_kind_from_dr7("),
                "{name}: the hit is detected but its access kind is not recovered, so a read and a write report identically"
            );
            assert!(
                code.contains("new_hardware("),
                "{name}: the hit is decoded and then not turned into a hardware Breakpoint stop reason"
            );
        }

        // The sticky status register must be cleared by whoever reads it.
        for (name, src, needle) in [
            ("windows", include_str!("windows_debugger.rs"), "ctx.Dr6 = 0"),
            ("linux", include_str!("linux_debugger.rs"), "write_debug_reg(pid, 6, 0)"),
            ("macos", include_str!("macos_debugger.rs"), "cleared.dr[6] = 0"),
        ] {
            assert!(
                src.contains(needle),
                "{name}: DR6 is read and never cleared — it is sticky, so the first hit would masquerade as a hit on every subsequent trap"
            );
        }
    }

    #[test]
    fn the_macos_backend_reaches_the_arm64_watchpoint_registers() {
        let src = include_str!("macos_debugger.rs");
        assert!(
            src.contains("const ARM_DEBUG_STATE64: libc::c_int = 15"),
            "macos: the AArch64 debug-state flavor is gone; a wrong or missing flavor makes thread_get_state fail on a host nothing here can test"
        );
        assert!(
            src.contains("assert!(ARM_DEBUG_STATE64_COUNT == 130)"),
            "macos: the compile-time word-count check on the hand-declared ArmDebugState64 is gone, so a layout drift would be read silently"
        );
        assert!(
            src.contains("dr_slot_from_arm64_watchpoint") && src.contains("arm64_watchpoint_from_dr_slot"),
            "macos: the dr <-> DBGWVR/DBGWCR translation is gone, so the shared watchpoint engine addresses registers that do not exist on this CPU"
        );
        let gate = src
            .find("hardware watchpoints need either the x86 debug registers")
            .map(|at| &src[at.saturating_sub(400)..at]);
        assert!(
            gate.is_some_and(|g| g.contains("target_arch = \"aarch64\"")),
            "macos: set_watchpoint_sized refuses AArch64 again — the translation layer exists but nothing above it can be reached, which is a gap dressed as a feature"
        );
    }

    #[test]
    fn the_arm64_watchpoint_control_word_is_encoded_field_by_field() {
        use crate::{arm64_encode_watchpoint_wcr as wcr, arm64_watchpoint_wvr as wvr};

        // 8 bytes, aligned, write: E=1, PAC=0b10 (EL0), LSC=0b10, BAS=0xff.
        let w = wcr(0x1000, BreakpointKind::DataWrite, 8).expect("8-byte write is encodable");
        assert_eq!(w & 1, 1, "E must be set or the watchpoint is armed-but-off");
        assert_eq!((w >> 1) & 0b11, 0b10, "PAC must be EL0 - EL1 never sees the tracee");
        assert_eq!((w >> 3) & 0b11, 0b10, "LSC must say store");
        assert_eq!((w >> 5) & 0xff, 0xff, "BAS must cover all eight bytes");

        // BAS is a MASK positioned by the offset, not a length code.
        let one = wcr(0x1003, BreakpointKind::DataRead, 1).expect("1 byte at offset 3");
        assert_eq!((one >> 5) & 0xff, 0b0000_1000, "the mask must sit at byte 3");
        assert_eq!((one >> 3) & 0b11, 0b01, "LSC must say load");
        let four = wcr(0x1004, BreakpointKind::DataReadWrite, 4).expect("4 bytes at offset 4");
        assert_eq!((four >> 5) & 0xff, 0b1111_0000);
        assert_eq!((four >> 3) & 0b11, 0b11, "LSC must say load and store");

        // Refusals, each one a watchpoint that would otherwise arm and lie.
        assert!(wcr(0x1002, BreakpointKind::DataWrite, 4).is_none(), "a 4-byte watch at offset 2 straddles the BAS doubleword and has no encoding");
        assert!(wcr(0x1000, BreakpointKind::DataWrite, 3).is_none(), "3 is not a representable width");
        assert!(wcr(0x1000, BreakpointKind::Software, 8).is_none(), "software breakpoints are not watchpoints");
        assert!(wcr(0x1000, BreakpointKind::Hardware, 8).is_none(), "execution breakpoints live in DBGBVR/DBGBCR, a different register file");

        // The address register drops the byte offset; BAS carries it instead.
        assert_eq!(wvr(0x1007), 0x1000);
    }

    /// Slot bookkeeping for the sixteen AArch64 watchpoint registers.
    #[test]
    fn arm64_watchpoint_slots_are_reused_before_they_are_allocated() {
        use crate::{arm64_free_watchpoint_slot as free, arm64_watchpoint_slot_for as slot_for};

        let mut wcr = [0u64; 16];
        let wvr = {
            let mut v = [0u64; 16];
            v[0] = 0x2000;
            v
        };
        assert_eq!(free(&wcr), Some(0));

        wcr[0] = 1;
        assert_eq!(free(&wcr), Some(1), "an armed slot must not be handed out again");
        assert_eq!(slot_for(&wvr, &wcr, 0x2004), Some(0), "the same doubleword must re-use its slot, or one address burns two of sixteen and the first stays armed with nothing tracking it");
        assert_eq!(slot_for(&wvr, &wcr, 0x3000), None);

        // A slot whose control word is disabled is free, even if its address
        // register still holds the old value.
        wcr[0] = 0;
        assert_eq!(free(&wcr), Some(0));
        assert_eq!(slot_for(&wvr, &wcr, 0x2000), None, "a disabled slot must not be reported as watching anything");

        let full = [1u64; 16];
        assert_eq!(free(&full), None, "all sixteen armed must be refused, not silently wrapped to slot 0");
    }

    /// The `dr` <-> AArch64 translation must round-trip, or the engine loses track.
    ///
    /// Every backend's watchpoint engine speaks `dr0`-`dr3` + `DR7`; on Apple
    /// Silicon those registers do not exist and the macOS backend translates at
    /// the register boundary instead of forking the engine. The translation is
    /// only safe if what the engine reads back equals what it wrote: `DR7` is how
    /// it finds a free slot, and the address register is how it recognises the
    /// watchpoint it must disarm. A lossy round trip would make `set` allocate a
    /// fresh slot on every call and `disarm` never find its own work.
    /// The same round-trip property for EXECUTION slots, added with the
    /// `NT_ARM_HW_BREAK` transport in iteration 571.
    ///
    /// The property is the one that makes the whole `dr` abstraction safe on
    /// AArch64, and it is not "the bits look right": what the engine reads back
    /// must EQUAL what it wrote. `DR7` is how it finds a free slot and the
    /// address register is how it recognises the breakpoint it must disarm, so
    /// a lossy trip would make `set` allocate a fresh slot every call and
    /// `disarm` never find its own work.
    ///
    /// This runs on any host: it is arithmetic over two integers, no ARM
    /// hardware involved. That matters, because everything else about the 571
    /// transport can only be answered by `ubuntu-24.04-arm`.
    #[test]
    fn the_dr_to_arm64_breakpoint_translation_round_trips() {
        use crate::{arm64_breakpoint_from_dr_slot as to_arm, dr_slot_from_arm64_breakpoint as to_dr};

        for (slot, addr) in [(0u8, 0x1000u64), (1, 0x2004), (3, 0x400_0000)] {
            // Execution breakpoint: `RW` = 00, `LEN` = 00, slot enabled. The
            // Intel manual requires exactly that pairing, so this is also the
            // only DR7 the engine is entitled to have written.
            let dr7 = 1u64 << (2 * u32::from(slot));
            let (bvr, bcr) = to_arm(addr, dr7, slot).expect("an enabled execution slot must translate");
            assert_eq!(bvr, addr, "DBGBVR holds the instruction address unmodified");
            assert_eq!(bcr & 1, 1, "the pair must come out ENABLED");
            assert_eq!((bcr >> 5) & 0xF, 0b1111, "BAS must select all four bytes of the instruction");

            let (back_addr, back_dr7) = to_dr(bvr, bcr, slot).expect("an armed pair must translate back");
            assert_eq!(back_addr, addr, "the address must survive the round trip");
            assert_eq!(back_dr7, dr7, "DR7 must come back identical, bit for bit");
        }

        // A disabled slot is not a breakpoint in either direction.
        assert!(to_arm(0x1000, 0, 0).is_none());
        assert!(to_dr(0x1000, 0, 0).is_none());

        // A DATA slot belongs to the watchpoint file. Translating it here as
        // well would arm one `dr` slot in BOTH register files, and a later
        // disarm would clear one of them and report success.
        let data_dr7 = 1u64 | (0b01 << 16);
        assert!(
            to_arm(0x1000, data_dr7, 0).is_none(),
            "RW=01 is a data watchpoint and must not also become an execution breakpoint"
        );

        // AArch64 instructions are 4-byte aligned and `DBGBVR`s low two bits
        // are RES0. Refusing beats aligning down: quietly arming a breakpoint
        // one or two bytes earlier would stop on a different instruction than
        // the caller named, which is worse than an error.
        assert!(
            to_arm(0x1002, 1, 0).is_none(),
            "an unaligned execution breakpoint must be refused, not rounded"
        );
    }

    #[test]
    fn the_dr_to_arm64_watchpoint_translation_round_trips() {
        use crate::{arm64_watchpoint_from_dr_slot as to_arm, dr_slot_from_arm64_watchpoint as to_dr};

        for (slot, addr, size_code, size) in
            [(0u8, 0x1000u64, 0b10u64, 8u32), (1, 0x2004, 0b11, 4), (3, 0x3002, 0b01, 2)]
        {
            let shift = 16 + 4 * u32::from(slot);
            // Write watchpoint (`RW` = 01) of the given width, slot enabled.
            let dr7 = (1u64 << (2 * u32::from(slot))) | (0b01 << shift) | (size_code << (shift + 2));
            let (wvr, wcr) = to_arm(addr, dr7, slot).expect("an enabled write slot must translate");
            assert_eq!(wvr, addr & !7, "DBGWVR holds the doubleword base");
            assert_eq!(((wcr >> 5) & 0xff).count_ones(), size, "BAS must cover exactly the requested width");

            let (back_addr, back_dr7) = to_dr(wvr, wcr, slot).expect("an armed pair must translate back");
            assert_eq!(back_addr, addr, "the byte offset must survive the trip through BAS");
            assert_eq!(back_dr7, dr7, "DR7 must come back identical, bit for bit");
        }

        // A disabled slot is not a watchpoint in either direction.
        assert!(to_arm(0x1000, 0, 0).is_none());
        assert!(to_dr(0x1000, 0, 0).is_none());

        // An execution breakpoint (`RW` = 00) has no watchpoint pair: AArch64
        // puts those in DBGBVR/DBGBCR. Arming a data watchpoint instead would
        // fire on the wrong events.
        assert!(to_arm(0x1000, 1, 0).is_none(), "RW=00 is execution and must be refused, not approximated");

        // A load-only AArch64 watchpoint has no DR7 spelling; saying so beats
        // widening it to read/write behind the caller's back.
        let load_only = crate::arm64_encode_watchpoint_wcr(0x1000, BreakpointKind::DataRead, 8)
            .expect("load-only is encodable on ARM");
        assert!(to_dr(0x1000, load_only, 0).is_none());
    }

    #[test]
    fn no_source_guard_detects_a_backend_by_the_short_impl_spelling_alone() {
        let src = include_str!("lib.rs");
        let short = format!("contains(\"impl {}\")", "Debugger for");
        let long = format!("impl crate::{}", "Debugger for");
        let mut lonely = Vec::new();
        for (at, _) in src.match_indices(&short) {
            // Same statement, give or take: the two spellings are always tested
            // next to each other when done right.
            let lo = at.saturating_sub(400);
            let hi = (at + 400).min(src.len());
            let window = &src[lo..hi];
            if !window.contains(&long) {
                lonely.push(src[..at].lines().count() + 1);
            }
        }
        assert!(
            lonely.is_empty(),
            "these lines of lib.rs detect a Debugger impl by the short spelling only, so they see the Apple backend and none of the three native ones: {lonely:?}"
        );
    }

    #[test]
    fn watchpoint_width_support_is_declared_not_assumed() {
        /// Backends that send the caller's width to the target.
        ///
        /// All four, as of the moment this guard stopped skipping three of them.
        /// Windows and Linux have programmed the width into `DR7`'s LEN field for
        /// many iterations and macOS joined them when its `x86_DEBUG_STATE64`
        /// plumbing landed; the list said otherwise only because the guard could
        /// not see those files and nothing contradicted it.
        const HONOURS_WIDTH: &[&str] =
            &["apple_debugger.rs", "windows_debugger.rs", "linux_debugger.rs", "macos_debugger.rs"];
        /// Backends still on the default, i.e. the width is theirs to choose.
        /// Empty on purpose: every backend now honours it. Kept rather than
        /// deleted because a new backend starts here, and the guard must have a
        /// place to put it.
        const USES_THE_DEFAULT: &[&str] = &[];
        /// Not a backend: `lib.rs` carries the in-crate test double, which is
        /// `pub` (integration tests need it) and therefore lands in the
        /// production slice. `every_debugger_backend_is_covered_by_the_source_guards`
        /// excludes it for the same reason.
        const TEST_SUPPORT: &[&str] = &["lib.rs"];

        let sources = production_sources();
        let mut unclassified = Vec::new();
        for (name, text) in &sources {
            let stripped: String = text
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            // BOTH spellings. The three native backends write
            // `impl crate::Debugger for`, only the Apple one writes
            // `impl Debugger for` — a trap this crate had already documented at
            // `every_debugger_backend_is_covered_by_the_source_guards`, and which
            // this guard nonetheless fell into: matching the short form alone, it
            // skipped Windows, Linux and macOS entirely and had been checking a
            // single backend while reading as if it covered all four. That is how
            // `USES_THE_DEFAULT` could keep listing three backends that have
            // overridden `set_watchpoint_sized` for many iterations.
            let is_backend = stripped.contains("impl Debugger for")
                || stripped.contains("impl crate::Debugger for");
            if !is_backend || TEST_SUPPORT.contains(&name.as_str()) {
                continue;
            }
            let overrides = stripped.contains("fn set_watchpoint_sized");
            match (HONOURS_WIDTH.contains(&name.as_str()), USES_THE_DEFAULT.contains(&name.as_str())) {
                (true, false) => assert!(
                    overrides,
                    "{name} is declared to honour the watchpoint width but does not override \
                     set_watchpoint_sized"
                ),
                (false, true) => assert!(
                    !overrides,
                    "{name} now overrides set_watchpoint_sized — move it to HONOURS_WIDTH so the \
                     declaration keeps matching reality"
                ),
                _ => unclassified.push(name.clone()),
            }
        }
        assert!(
            unclassified.is_empty(),
            "these `Debugger` impls are in neither set, so nobody has decided whether they honour \
             a watchpoint's width: {unclassified:?}"
        );
    }

    #[test]
    fn no_production_code_constructs_a_mock_or_fake_backend() {
        // "The debugger must be live at 100%": a mock is allowed to EXIST for
        // tests, but nothing that ships may build one. This guard is the thing
        // that makes that claim checkable instead of aspirational — the doc on
        // `MockDebugger` has said "never use this to answer a caller" for many
        // iterations while `ttd_open::open_trace_or_mock` did exactly that in
        // production, unnoticed, because nothing looked.
        //
        // Construction sites, not mere mentions: a doc comment or an error
        // string may name a mock, and forbidding that would only teach the next
        // author to stop writing the word.
        const FORBIDDEN_CONSTRUCTORS: &[&str] = &[
            "MockDebugger::new",
            "MockDebugger {",
            "MockScriptContext::new",
            "MockScriptContext {",
            "MockTtdBackend::new",
            "MockTtdBackend {",
            "MockTransport::new",
            "MockMuxd::new",
            "StubDebugger",
        ];

        // The ONE deliberate exception, and why it is safe:
        //
        // `ios/apple_debugger.rs` holds `LoopbackFactory` and the
        // `RspTransport for LoopbackTransport` bridge. Both must live in the
        // library rather than a test module because an integration test in
        // `tests/` is a separate crate and the orphan rule forbids it writing
        // that impl. Crucially neither FABRICATES anything: `LoopbackFactory`
        // serves a `MockDebugserver` its caller constructed and handed in, so a
        // production caller that never builds one can never receive one.
        //
        // `ios/mock_debugserver.rs` and `ios/mock_client.rs` are the mock
        // itself; they are excluded because "does the mock build the mock" is
        // not the question this guard asks.
        const ALLOWED_FILES: &[&str] =
            &["apple_debugger.rs", "mock_debugserver.rs", "mock_client.rs"];

        let mut offenders: Vec<String> = Vec::new();
        for (name, production) in production_sources() {
            if ALLOWED_FILES.contains(&name.as_str()) {
                continue;
            }
            for (i, line) in production.lines().enumerate() {
                let t = line.trim_start();
                if t.starts_with("//") {
                    continue;
                }
                // A DEFINITION is not a construction. `pub struct MockDebugger
                // {`, `impl MockDebugger {` and `impl Debugger for MockDebugger
                // {` are what makes the type available to tests at all; the
                // question is whether shipping code ever calls one.
                if t.starts_with("struct ")
                    || t.starts_with("pub struct ")
                    || t.starts_with("impl ")
                    || t.starts_with("pub enum ")
                    || t.starts_with("enum ")
                {
                    continue;
                }
                for needle in FORBIDDEN_CONSTRUCTORS {
                    if line.contains(needle) {
                        offenders.push(format!("{name}:{}: {needle} in `{}`", i + 1, t.trim()));
                    }
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "production code must never construct a mock/fake/stub debugger \
             backend — found {} site(s):\n  {}",
            offenders.len(),
            offenders.join("\n  ")
        );
    }

    #[test]
    fn no_production_code_falls_back_to_a_non_live_substitute() {
        // The shape this crate keeps regrowing: a `*_or_mock` / `*_or_fake`
        // helper that turns a real backend's failure into a plausible answer,
        // signalling the difference only through a boolean the caller is free
        // to drop. Naming the shape is what stops it coming back.
        let mut offenders: Vec<String> = Vec::new();
        for (name, production) in production_sources() {
            if name == "lib.rs" {
                continue; // this guard's own text
            }
            for (i, line) in production.lines().enumerate() {
                let t = line.trim_start();
                if t.starts_with("//") {
                    continue;
                }
                for needle in ["_or_mock(", "_or_fake(", "_or_stub(", "_or_dummy("] {
                    if line.contains(needle) {
                        offenders.push(format!("{name}:{}: {}", i + 1, t.trim()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "a failed live backend must become an ERROR naming the reason, not a \
             non-live substitute — found:\n  {}",
            offenders.join("\n  ")
        );
    }

    #[test]
    fn the_unverified_macos_backend_says_so_in_its_own_header() {
        // Two macOS-capable backends exist and they are not equally proven.
        // `make_backend()` picks this one on a macOS host, silently, and it
        // has never been compiled by any compiler — so a reader arriving at
        // the file must be told, in the file, rather than having to dig
        // through nine guards and a handoff log to discover it.
        //
        // Pinned as a test because a status banner nobody checks is a comment
        // that rots: the very failure mode this crate keeps finding.
        let src = include_str!("macos_debugger.rs");
        let header: String = src
            .lines()
            .take_while(|l| l.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("
");
        assert!(
            header.contains("STATUS: UNVERIFIED"),
            "macos_debugger.rs must declare its unverified status in its own header"
        );
        assert!(
            header.contains("apple_debugger"),
            "the header must point at the backend to prefer when one is available"
        );
    }

    #[test]
    fn every_ptrace_backend_distinguishes_a_single_step_trap_from_a_breakpoint() {
        // A `waitpid`-driven backend gets ONE signal number for every trap:
        // SIGTRAP covers a software breakpoint, a genuine single step, and a
        // hardware-watchpoint hit alike. Only a breakpoint leaves `rip` one
        // past a planted `0xCC`; the other two leave `rip` untouched. A
        // backend that skips the byte check reports `Breakpoint{rip-1}` for
        // all three — a fabricated address no breakpoint was planted at, and
        // the reason a hardware watchpoint would be unusable here even once
        // it could be armed.
        //
        // Linux found and fixed this with a live test
        // (`classify_status`/`byte_at`); macOS silently kept the defect,
        // because it cannot be compiled or run on these hosts. Windows is
        // deliberately NOT listed: it is event-driven, not `waitpid`-driven,
        // and gets `EXCEPTION_BREAKPOINT` vs `EXCEPTION_SINGLE_STEP` from the
        // OS, so it has no heuristic to get wrong.
        //
        // Bodies are delimited by the START of the next function, never by a
        // closing brace: these sources have MIXED line endings, and a
        // brace-plus-newline terminator matches nothing in the CRLF ones and
        // silently runs to end of file.
        for (name, start_marker, src) in [
            ("linux", "fn classify_status(", include_str!("linux_debugger.rs")),
            ("macos", "fn wait_for_stop(", include_str!("macos_debugger.rs")),
        ] {
            let start = src
                .find(start_marker)
                .unwrap_or_else(|| panic!("{name}: no `{start_marker}` to check"));
            let rest = &src[start..];
            let end = rest
                .find("fn signal_name(")
                .unwrap_or_else(|| panic!("{name}: no `fn signal_name(` after {start_marker}"));
            // Comment lines go first. The explanatory comments in BOTH of
            // these functions quote `0xCC` verbatim, so matching the raw body
            // would accept a backend that only TALKS about the byte check —
            // which is precisely the state macOS was in, and a deliberate
            // mutation confirmed this guard passed on it before the strip.
            let body: String = rest[..end]
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            let body = body.as_str();
            // The classifier must CONSULT the trap encoding, and for the
            // architecture it was built for.
            //
            // This assertion used to demand the literal `0xCC`, which made the
            // guard itself carry the defect it existed to prevent: `int3` is one
            // byte and the CPU reports the address AFTER it, while AArch64 traps
            // with a four-byte `BRK #0` reported AT it. Both ptrace backends
            // spelled the x86 form inline, so on arm64 neither could ever
            // recognise its own breakpoints — every hit would be classified as a
            // single step, silently. Fixed in iteration 546; the guard now
            // requires the derived route and goes red if either backend returns
            // to a hard-coded byte.
            assert!(
                body.contains("trap_at_reported_pc("),
                "{name}: its SIGTRAP classifier does not consult `arch_breakpoint` to locate the \
                 trap, so it is back to assuming a one-byte x86 `int3` at `pc-1` — always false \
                 on arm64, where every breakpoint hit would be reported as a single step"
            );
            assert!(
                body.contains("StopReason::SingleStep"),
                "{name}: its SIGTRAP classifier can never produce `SingleStep`, so a real \
                 single step (and a hardware-watchpoint hit) is misreported as a breakpoint"
            );
        }
    }

    #[test]
    fn the_macos_backend_refuses_hardware_watchpoints_in_all_three_places() {
        // NOT a regression guard — nothing is broken today, and this test is
        // declared new-on-correct-state on purpose. Its job is to make a HALF
        // implementation impossible tomorrow.
        //
        // macOS refuses hardware watchpoints in three independent places:
        //   1. `set_breakpoint` rejects every non-`Software` kind;
        //   2. `Command::SetRegisters` rejects writes to `dr0`-`dr7` with the
        //      message `no_backend_silently_ignores_a_debug_register_write`
        //      keys on — which is why that message must NOT be reworded;
        //   3. it does not override `set_watchpoint_sized`, so it is listed
        //      under `USES_THE_DEFAULT` in
        //      `watchpoint_width_support_is_declared_not_assumed`.
        //
        // Arming without disarming would be a deliberate resource leak: the
        // disarm path runs through `remove_breakpoint`, which is one of the
        // twenty methods frozen byte-identical across the three backends by
        // `the_logic_shared_by_the_three_backends_stays_identical`, so it
        // cannot be changed in one backend alone. Until that is lifted, the
        // three refusals must agree with each other.
        let src = include_str!("macos_debugger.rs");
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//") && !l.trim_start().starts_with("///"))
            .collect::<Vec<_>>()
            .join("\n");

        let refuses_debug_registers = code.contains("cannot program x86 debug registers");
        let arms_watchpoints = code.contains("async fn set_watchpoint_sized(");
        let refuses_non_software_breakpoints = code.contains("BreakpointKind::Software");

        if refuses_debug_registers {
            assert!(
                !arms_watchpoints,
                "macos: `Command::SetRegisters` still refuses `dr0`-`dr7` (\"cannot program x86 \
                 debug registers\") while `set_watchpoint_sized` claims to arm a hardware \
                 watchpoint — the two cannot both be true, and the watchpoint could never fire"
            );
            assert!(
                refuses_non_software_breakpoints,
                "macos: refuses debug-register writes but `set_breakpoint` no longer gates on \
                 `BreakpointKind::Software` — a hardware breakpoint would be accepted and then \
                 silently never armed"
            );
        } else {
            assert!(
                arms_watchpoints,
                "macos: the debug-register refusal was removed but nothing arms a hardware \
                 watchpoint in its place. Either keep the refusal (and its exact wording, which \
                 `no_backend_silently_ignores_a_debug_register_write` matches on) or override \
                 `set_watchpoint_sized` — and if you add arming, add disarming with it: \
                 `remove_breakpoint` must free the DR slot, or every removed watchpoint leaks \
                 one of the four until detach"
            );
        }
    }

    /// The macOS backtrace doc must describe the walk it PERFORMS.
    ///
    /// This guard used to assert the opposite: it pinned the words
    /// "FP-CHAIN ONLY" and "ARM64-only" into the doc, because for a long time
    /// that was the truth and nothing in the file said whether the truncation
    /// was deliberate. Iter 447 gave the backend a real CFI continuation, and
    /// this guard then went on holding the STALE sentence in place — a test
    /// enforcing documentation that had become false. It is re-aimed rather
    /// than deleted: the risk it was written for is still real, only inverted.
    ///
    /// A source guard because this file is `#![cfg(target_os = "macos")]` and
    /// compiles nowhere here, so it is the only check available at all.
    #[test]
    fn the_macos_backtrace_doc_describes_the_walk_it_actually_performs() {
        let src = include_str!("macos_debugger.rs");
        let start = src
            .find("async fn backtrace")
            .expect("macos_debugger.rs must still define backtrace");
        let block_start = src[..start].rfind("async fn modules").unwrap_or(0);
        let rest = &src[block_start..];
        let end = rest
            .find("fn set_symbol_resolver")
            .expect("expected set_symbol_resolver to follow backtrace");
        let block = &rest[..end];
        assert!(
            block.len() > 400,
            "the extracted backtrace block is suspiciously short ({} bytes) — the \
             delimiters are wrong and the assertions below would fail for the \
             WRONG reason",
            block.len()
        );
        // What the walk does now, in the doc AND in the code.
        for needle in ["eh_frame", "frame-pointer", "best-effort"] {
            assert!(
                block.contains(needle),
                "macos_debugger::backtrace must document the walk it performs: missing \
                 {needle:?} — it walks the frame-pointer chain and then continues with \
                 DWARF CFI from __TEXT,__eh_frame"
            );
        }
        // And must not re-assert the limit it no longer has. A doc that
        // announces a truncation the code does not perform sends the next
        // maintainer to fix something that is already fixed — or worse, to
        // 'restore consistency' by deleting the continuation.
        let doc_only: String = block
            .lines()
            .filter(|l| l.trim_start().starts_with("///"))
            .collect::<Vec<_>>()
            .join("
");
        assert!(
            !doc_only.contains("**FP-CHAIN ONLY**"),
            "the doc still declares the walk to be frame-pointer-only, which stopped \
             being true when the CFI continuation landed"
        );
    }

    #[test]
    fn the_macos_memory_reader_never_zero_pads_a_short_read() {
        // `MemoryReader` is the unwinder's input. Zero-padding a short read
        // there does not produce an error, it produces a plausible-looking
        // saved-fp/saved-lr pair of zeros — i.e. confident wrong frames, the
        // failure mode this crate keeps paying for. `RspMemory` in
        // `ios/apple_debugger.rs` already gets this right; the macOS adapter
        // must not drift from it.
        //
        // A source guard rather than a real test because this file is
        // `#![cfg(target_os = "macos")]` and compiles nowhere here — stated
        // plainly: there is no test that could have failed before this
        // adapter existed, and the guard is all the protection available.
        let src = include_str!("macos_debugger.rs");
        let start = src
            .find("struct SendMemory")
            .expect("macos_debugger.rs must define the SendMemory adapter");
        let rest = &src[start..];
        let end = rest
            .find("impl crate::Debugger for MacosDebugger")
            .expect("expected the Debugger impl to follow SendMemory");
        let block = &rest[..end];
        assert!(
            block.len() > 200,
            "extracted SendMemory block is only {} bytes — delimiters are wrong \
             and the assertions below would fail for the WRONG reason",
            block.len()
        );
        assert!(
            block.contains("data.len() != buf.len()"),
            "SendMemory::read must reject a short read outright (all-or-nothing)"
        );
        assert!(
            block.contains("copy_from_slice"),
            "SendMemory::read must fill the caller's buffer from the reply"
        );
        for banned in ["resize(", "extend_from_slice(&[0", "fill(0)"] {
            assert!(
                !block.contains(banned),
                "SendMemory::read must never pad a short read — found {banned:?}"
            );
        }
    }

    #[test]
    fn the_apple_backend_keeps_its_breakpoint_bookkeeping_invariants() {
        // Iter 263 showed the guards above never listed `ios/apple_debugger.rs`,
        // and it had a real bug they would have caught. Auditing the rest of
        // its bookkeeping by hand (iter 264) found it already CORRECT on every
        // invariant the other three had to be fixed for — but nothing guarded
        // that, and this backend has no live test against a real device: its
        // whole suite runs against a mock. These are the four properties that
        // audit established, pinned so they cannot silently regress.
        let src = include_str!("ios/apple_debugger.rs");
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//") && !l.trim_start().starts_with("///"))
            .collect::<Vec<_>>()
            .join("
");

        fn body<'a>(code: &'a str, f: &str) -> &'a str {
            let start = code.find(f).unwrap_or_else(|| panic!("apple: missing {f}"));
            let rest = &code[start..];
            let end = body_end(rest, "    }");
            &rest[..end]
        }

        // 1. Track only AFTER the target has actually been patched/armed —
        //    a failed write must not leave a phantom entry (iter 244).
        let set = body(&code, "async fn set_breakpoint(");
        let insert = set.find("breakpoints.write().insert").expect("apple: never tracks");
        let arm = set.find("insert_breakpoint").expect("apple: never arms anything");
        assert!(arm < insert, "apple: set_breakpoint tracks before arming the target");

        // 2. kill() drops the dead process's table, or the NEXT process
        //    inherits it and re-arming silently no-ops (iter 251).
        assert!(
            body(&code, "async fn kill(").contains("breakpoints.write().clear()"),
            "apple: kill leaves the dead process's breakpoints tracked"
        );

        // 3. A disabled breakpoint stays listed as disabled instead of
        //    vanishing, so `enabled` can actually be false (iter 255).
        // The work moved into `disable_one`, which acts on ONE resource class:
        // an address can carry a code trap and a data watchpoint at once, and
        // `disable_breakpoint` now loops over both. Disabling only the first
        // left the other armed and unreachable — a second call re-found the
        // already-disabled one and returned `Ok`. The invariant checked here is
        // unchanged: the entry stays, marked disabled, so `enabled` can be
        // false instead of the record vanishing.
        let dis = body(&code, "async fn disable_one(");
        assert!(
            dis.contains("enabled = false") && !dis.contains("remove(&(a"),
            "apple: disable must keep the entry, not remove it"
        );
        let dis_pub = body(&code, "async fn disable_breakpoint(");
        assert!(
            dis_pub.contains("for class in classes"),
            "apple: disable_breakpoint acts on a single resource, so the other one at the same \
             address stays armed and cannot be reached by any later call"
        );

        // 4. Hits are counted, because `debug.breakpoints` publishes the
        //    number and a permanently-zero counter is worse than none (iter 254).
        assert!(
            code.contains("hit_count += 1"),
            "apple: hit_count is published but never incremented"
        );
    }

    #[test]
    fn every_backend_undoes_its_own_patches_on_detach() {
        // A FOURTH `Debugger` impl lives in `ios/apple_debugger.rs`, and the
        // guards above never listed it. It normally delegates breakpoints to
        // the stub via `Z0`, but falls back to patching an A64 `BRK #0`
        // itself when the stub has none — and `detach()` used to clear its
        // table without writing the saved words back, abandoning a `BRK` that
        // kills the target on SIGTRAP. Same defect as iter 245, found in
        // iter 263.
        let src = include_str!("ios/apple_debugger.rs");
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//") && !l.trim_start().starts_with("///"))
            .collect::<Vec<_>>()
            .join("
");

        assert!(
            code.contains("impl Drop for AppleDebugger"),
            "apple: no Drop — a session dropped while attached leaves its own BRK patches behind"
        );

        let start = code
            .find("async fn detach(")
            .expect("apple: no detach to check");
        let body = &code[start..];
        let end = body.find("
    }
").map_or(body.len(), |e| e + 6);
        let body = &body[..end];

        let restore = body
            // Renamed from `restore_patched_breakpoints` when the sweep grew
            // to cover stub-managed `Z0`/`Z2` and the hardware slots too —
            // detach used to leave those armed in the target (measured:
            // two inserts, ZERO removals). The invariant this guard states is
            // unchanged and now covers more: undo everything BEFORE the `D`,
            // because once the stub detaches the target is no longer
            // writable through this connection.
            .find("disarm_all_breakpoints")
            .expect("apple: detach never disarms what it armed in the target");
        let send_d = body
            .find("commands::detach()")
            .expect("apple: detach never issues the D packet");
        assert!(
            restore < send_d,
            "apple: detach must restore its patches BEFORE detaching — afterwards the              target is no longer writable through this connection"
        );
    }

    #[test]
    fn every_backend_restores_breakpoints_when_dropped() {
        // Closes the family started in iter 243. Dropping an attached
        // debugger must not leave `0xCC` bytes in the target: the kernel (or
        // Windows) detaches and resumes it, so it runs into an int3 with no
        // debugger left to handle the trap and dies. Proved with live tests
        // on Windows (iter 249) and Linux (iter 250, where the target came
        // back as a zombie every time).
        //
        // Source-level so it also covers macOS, which cannot be compiled or
        // live-tested on these hosts and had silently missed four family
        // fixes in a row before these guards existed.
        fn body<'a>(src: &'a str, f: &str) -> &'a str {
            let start = src.find(f).unwrap_or_else(|| panic!("missing {f}"));
            let rest = &src[start..];
            let end = body_end(rest, "}");
            &rest[..end]
        }

        for (name, ty, src) in [
            ("windows", "impl Drop for WindowsDebugger", include_str!("windows_debugger.rs")),
            ("linux", "impl Drop for LinuxDebugger", include_str!("linux_debugger.rs")),
            ("macos", "impl Drop for MacosDebugger", include_str!("macos_debugger.rs")),
        ] {
            assert!(
                src.contains(ty),
                "{name}: no `{ty}` — dropping an attached debugger leaves its                  breakpoints planted and kills the target"
            );
            let d: String = body(src, ty)
                .lines()
                .filter(|l| !l.trim_start().starts_with("//") && !l.trim_start().starts_with("///"))
                .collect::<Vec<_>>()
                .join("
");
            let restore = d.find("Command::WriteMemory").unwrap_or_else(|| {
                panic!("{name}: Drop never restores the original bytes")
            });
            let detach = d.find("Command::Detach")
                .unwrap_or_else(|| panic!("{name}: Drop never detaches"));
            assert!(
                restore < detach,
                "{name}: Drop detaches before restoring the patched bytes"
            );
        }
    }

    #[test]
    fn no_backend_releases_the_command_lock_before_receiving_its_reply() {
        // `send()` is one request/reply transaction over a SINGLE shared
        // channel pair. Releasing the command lock after the send lets two
        // concurrent callers interleave and receive each other's replies —
        // and when both commands return the same `Reply` variant that is a
        // silent data swap, not an error. All three backends shipped the
        // same `drop(guard)` (iter 247).
        //
        // Checked at source level so it also covers macOS, which cannot be
        // compiled or live-tested on these hosts.
        fn body<'a>(src: &'a str, f: &str) -> &'a str {
            let start = src.find(f).unwrap_or_else(|| panic!("missing {f}"));
            let rest = &src[start..];
            let end = body_end(rest, "    }");
            &rest[..end]
        }

        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            // Strip comment lines first: the explanatory comments in these
            // functions quote `drop(guard)` verbatim, and matching that text
            // would flag correct code as broken.
            let f: String = body(src, "fn send(&self, cmd: Command)")
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("
");
            let f = f.as_str();
            let send = f.find("tx.send(cmd)")
                .unwrap_or_else(|| panic!("{name}: send() never sends"));
            let recv = f.find("rx.recv()")
                .unwrap_or_else(|| panic!("{name}: send() never receives"));
            // The command guard must not be dropped between the two.
            if let Some(d) = f.find("drop(guard)") {
                assert!(
                    d > recv,
                    "{name}: send() releases the command lock at byte {d}, before the                      reply is received at {recv} (sent at {send}) — concurrent callers                      can swap replies"
                );
            }
        }
    }

    #[test]
    fn every_backend_records_the_stopping_thread_after_a_step_too() {
        // `continue_execution` and `single_step` must BOTH record the thread
        // that stopped. If only the former does, `current_thread()` reports a
        // stale tid after a step — or `NotAttached` if no continue ever ran.
        //
        // That is not cosmetic: the MCP layer calls `current_thread()` through
        // `initial_stop_tid` immediately after launch/attach, and a `None`
        // there makes the whole session fall back to the MOCK debugger
        // instead of driving the real process (traced on Linux in iter 142).
        // Source-level because macOS cannot be compiled or live-tested here.
        fn body<'a>(src: &'a str, f: &str) -> &'a str {
            let start = src.find(f).unwrap_or_else(|| panic!("missing {f}"));
            let rest = &src[start..];
            let end = body_end(rest, "    }");
            &rest[..end]
        }

        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            for method in ["async fn continue_execution(", "async fn single_step("] {
                assert!(
                    body(src, method).contains("*self.current_tid.lock() = Some(ev.tid)"),
                    "{name}: {method}…) does not record the stopping thread, so                      current_thread() goes stale after it"
                );
            }
        }
    }

    #[test]
    fn every_backend_resolves_a_module_entry_point() {
        // `ModuleInfo::entry_point` is the answer to "where does this module
        // begin executing?" — the starting point for anyone setting a
        // breakpoint on a freshly loaded image. Windows resolves it from the
        // PE optional header and Linux from the ELF header, both after a fix;
        // macOS was left emitting a hardcoded `entry_point: None` for every
        // module long after the other two were corrected, and nothing
        // noticed, because the divergence is invisible from any single
        // platform.
        //
        // Checked at source level for the usual reason: macOS cannot be
        // compiled or run on either host in this environment, so a guard on
        // the text is the only mechanism that can see the field being
        // abandoned again. Each backend must name a resolver — asserting the
        // absence of the literal `entry_point: None` would be wrong, since
        // Windows legitimately initialises it to `None` and fills it in a
        // second pass a few lines later.
        // What must be true is that some line FEEDS `entry_point` with the
        // resolver — not merely that the resolver appears somewhere in the file.
        //
        // Every backend also DEFINES its resolver (`fn pe_entry_point` at
        // windows_debugger.rs:146, `fn elf_entry_point` at
        // linux_debugger.rs:984, `fn mach_o_entry_point_at` at
        // macos_debugger.rs:1261), and a whole-file `contains` is satisfied by
        // that definition alone. This guard used to do exactly that, so
        // deleting the CALL while leaving the helper — the precise regression
        // it exists to catch — kept it green. Proven by injecting
        // `module.entry_point = None` into the Windows walk: the old form
        // still passed.
        //
        // Scoping it to the body of `modules` instead would be too NARROW: the
        // macOS backend delegates to `walk_dyld_images`, which builds the
        // `ModuleInfo` values a few hundred lines earlier. The call site is
        // what matters, wherever it lives — so the check is per LINE, skipping
        // the resolver's own signature (note `entry_point` is a substring of
        // `pe_entry_point`, so a naive line match would accept the definition).
        for (name, src, resolver) in [
            ("windows", include_str!("windows_debugger.rs"), "pe_entry_point("),
            ("linux", include_str!("linux_debugger.rs"), "elf_entry_point("),
            ("macos", include_str!("macos_debugger.rs"), "mach_o_entry_point_at("),
        ] {
            let feeds_the_field = src.lines().any(|l| {
                let t = l.trim_start();
                !t.starts_with("fn ")
                    && !t.starts_with("async fn ")
                    && !t.starts_with("//")
                    && l.contains(resolver)
                    && (l.contains("entry_point:") || l.contains("entry_point ="))
            });
            assert!(
                feeds_the_field,
                "{name}: no line feeds ModuleInfo::entry_point from `{resolver}` — this                  backend has stopped resolving it and now reports None for every module.                  (Defining the helper is not enough: it has to be called.)"
            );
        }
    }

    #[test]
    fn every_backend_detach_restores_breakpoint_bytes_first() {
        // The severest member of this family. A software breakpoint is a
        // `0xCC` patched into the target's own code. Detaching without
        // restoring it leaves an int3 that raises SIGTRAP on the next
        // execution — and with no tracer attached, the default action for an
        // unhandled SIGTRAP is to KILL the process. Detaching would kill the
        // very process being debugged.
        //
        // Found on Linux via a live test; Windows has the same sweep; macOS
        // had none at all until iter 245. Checked at source level because
        // that backend cannot be compiled or live-tested on these hosts.
        fn body<'a>(src: &'a str, f: &str) -> &'a str {
            let start = src.find(f).unwrap_or_else(|| panic!("missing {f}"));
            let rest = &src[start..];
            let end = body_end(rest, "    }");
            &rest[..end]
        }

        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let d = body(src, "async fn detach(");
            let restore = d.find("write_memory_raw(Address(addr), &original)").unwrap_or_else(|| {
                panic!("{name}: detach does not restore breakpoint bytes — detaching                         leaves an int3 that kills the target on its next execution")
            });
            let clear = d.find("breakpoints.lock().clear()")
                .unwrap_or_else(|| panic!("{name}: detach never clears its breakpoint map"));
            let send = d.find("Command::Detach")
                .unwrap_or_else(|| panic!("{name}: detach never issues the detach command"));
            // Two separate properties, and only the first is the severe one.
            //
            // `restore < send` is the life-or-death ordering this guard was
            // written for: the bytes must go back while the target is still
            // ours to write to.
            //
            // `send < clear` was the OPPOSITE of what this guard used to
            // demand, and the old direction was a bug (iter 284). `send` can
            // fail — it does whenever the debug loop is gone, e.g. the target
            // died and the user then hits detach — and it fails through `?`,
            // so anything cleared before it is lost while `pid`/`cmd_tx` still
            // say "attached". The debugger then reports an EMPTY breakpoint
            // table for a process that still carries the patches: a retried
            // detach restores nothing and `remove_breakpoint` finds nothing.
            // Bookkeeping may only be dropped once the detach has actually
            // happened.
            assert!(
                restore < send,
                "{name}: detach must restore breakpoint bytes BEFORE detaching                  (restore@{restore}, detach@{send})"
            );
            assert!(
                send < clear,
                "{name}: detach must clear its tracking only AFTER the detach succeeds,                  or a failed detach silently loses the table (detach@{send}, clear@{clear})"
            );
        }

        // The Apple backend, whose idioms differ: it restores through
        // `restore_patched_breakpoints`, detaches with `commands::detach()` and
        // clears an `RwLock` map. Same three properties, checked with its own
        // spelling — it was left out of this guard entirely, and the sibling
        // half of this very rule (remove_breakpoint's ordering) was broken there
        // until iter 285 found it by hand.
        {
            let d = body(include_str!("ios/apple_debugger.rs"), "async fn detach(");
            let restore = d.find("disarm_all_breakpoints(session)").unwrap_or_else(|| {
                panic!("apple: detach does not restore its self-patched breakpoints — an                         abandoned `BRK #0` raises SIGTRAP with no debugger attached and kills                         the target")
            });
            let send = d
                .find("commands::detach()")
                .unwrap_or_else(|| panic!("apple: detach never issues the `D` packet"));
            let clear = d
                .find("breakpoints.write().clear()")
                .unwrap_or_else(|| panic!("apple: detach never clears its breakpoint map"));
            assert!(
                restore < send,
                "apple: detach must restore the patched words BEFORE the `D` — once the stub                  has detached, the target is no longer writable through this connection                  (restore@{restore}, detach@{send})"
            );
            assert!(
                send < clear,
                "apple: detach must clear its tracking only AFTER the detach succeeds                  (detach@{send}, clear@{clear})"
            );
        }
    }

    /// `kill()` must clear the hardware-watchpoint map, exactly as it already
    /// clears the software breakpoints — and it did not, in any of the three
    /// backends.
    ///
    /// `detach()` clears the map as a side effect of
    /// `disarm_all_hardware_watchpoints`. `kill()` has no such sweep (the
    /// process is dead, its registers with it) and so simply never cleared it.
    /// The entries outlived the process, and `launch()` is permitted again the
    /// moment `pid` is `None`, so the next process inherited them: `breakpoints()`
    /// chains this map into its answer and listed watchpoints belonging to no
    /// live process, while `rearm_watchpoints_on_new_threads` — called from
    /// `continue_execution` — walks the same map and burned debug registers of
    /// the FRESH process on addresses nobody asked to watch. Both are the
    /// confidently-wrong failure mode, not untidiness.
    ///
    /// Source-level because `macos_debugger.rs` cannot be compiled or live-tested
    /// on this host, and it is the backend that has repeatedly kept a defect its
    /// twins had fixed.
    /// Arming a hardware watchpoint must leave it marked ENABLED.
    ///
    /// `set_breakpoint` clears the `disabled` flag when it re-plants a
    /// tracked-but-disabled breakpoint; `set_watchpoint_sized` did not, so
    /// `set` -> `disable` -> `set` left the address armed in the debug registers
    /// while `breakpoints()` reported it disabled — and `disable_breakpoint`
    /// short-circuits on that stale flag, so nothing short of `remove` could
    /// switch the watchpoint off again. Proved live on Windows
    /// (`re_arming_a_disabled_watchpoint_reports_it_enabled_again`); this guard
    /// keeps Linux, whose implementation is the same shape, from drifting.
    ///
    /// `macos_debugger.rs` is deliberately absent: it has no
    /// `set_watchpoint_sized` at all (its `hw_watchpoints` map is always empty),
    /// so there is nothing here to keep honest yet.
    /// The macOS backend must really program the x86 debug registers, not refuse them.
    ///
    /// Everything above this line in the watchpoint stack already existed on
    /// Darwin — slot allocation, `DR7` encoding, the disarm sweep, the re-arm of
    /// threads created later. What did not exist was the plumbing: Darwin keeps
    /// `dr0`-`dr7` in `x86_DEBUG_STATE64`, a different thread-state flavor from
    /// the `x86_THREAD_STATE64` this backend reads, so `regs.get(\"dr7\")`
    /// answered `None` forever and `SetRegisters` returned an error naming its
    /// own gap. The whole feature was therefore unreachable on one of the three
    /// target platforms.
    ///
    /// This host can compile that file for both Apple targets but can never RUN
    /// it, so the guard is source-level: it checks the two ends of the plumbing
    /// and the entry point, which is exactly what was missing.
    #[test]
    fn the_macos_backend_programs_the_x86_debug_registers_instead_of_refusing_them() {
        let src = include_str!("macos_debugger.rs");
        assert!(
            src.contains("fn read_debug_state(") && src.contains("fn write_debug_state("),
            "macos: the x86_DEBUG_STATE64 accessors are gone — dr0-dr7 are unreachable\
             again and every watchpoint here silently watches nothing"
        );
        assert!(
            src.contains("const X86_DEBUG_STATE64: libc::c_int = 11"),
            "macos: the debug-state flavor constant must stay 11; a wrong flavor makes\
             thread_get_state fail at runtime on a host nothing here can test"
        );
        assert!(
            src.contains("assert!(X86_DEBUG_STATE64_COUNT == 16)"),
            "macos: the compile-time check on the hand-declared struct's word count is\
             gone — a layout drift would then read the wrong number of words silently"
        );
        assert!(
            // The call now carries the thread id as well (iteration 399): the
            // needle follows the signature, the invariant it guards is unchanged.
            src.contains("merge_debug_state(task, Some(tid), &mut regs)"),
            "macos: GetRegisters no longer reports dr0-dr7, so the disarm and re-arm\
             sweeps read a DR7 that is permanently zero and do nothing"
        );
        assert!(
            src.contains("write_debug_registers(task, Some(tid), &regs)"),
            "macos: SetRegisters no longer routes the debug registers anywhere"
        );
        assert!(
            src.contains("async fn set_watchpoint_sized("),
            "macos: without this override the trait default forwards to set_breakpoint,\
             which rejects every kind that is not Software — so hardware watchpoints\
             fail outright on this platform"
        );
    }

    #[test]
    fn arming_a_watchpoint_clears_its_disabled_flag_in_every_backend_that_has_one() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
        ] {
            let start = src
                .find("async fn set_watchpoint_sized(")
                .unwrap_or_else(|| panic!("{name}: no set_watchpoint_sized()"));
            let rest = &src[start..];
            let end = body_end(rest, "    }");
            let body = &rest[..end];
            let track = body
                .find("hw_watchpoints.lock().insert(")
                .unwrap_or_else(|| panic!("{name}: set_watchpoint_sized never tracks it"));
            let undisable = body.find("disabled.lock().remove(").unwrap_or_else(|| {
                panic!(
                    "{name}: arming a watchpoint leaves a stale disabled flag — it is live\
                     in the debug registers, reported as off, and disable_breakpoint will\
                     short-circuit so it can never be switched off again"
                )
            });
            assert!(
                undisable > track,
                "{name}: the disabled flag is cleared before the arming is confirmed, so a\
                 failed arm would report an enabled watchpoint that does not exist"
            );
        }
    }

    #[test]
    fn every_backend_clears_hardware_watchpoints_when_the_process_is_killed() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let start = src
                .find("async fn kill(")
                .unwrap_or_else(|| panic!("{name}: no kill()"));
            let rest = &src[start..];
            let end = body_end(rest, "    }");
            let kill = &rest[..end];
            assert!(
                kill.contains("breakpoints.lock().clear()"),
                "{name}: kill() no longer clears the software breakpoints — the guard
                 below would then be checking a body that moved"
            );
            assert!(
                kill.contains("hw_watchpoints.lock().clear()"),
                "{name}: kill() leaves the hardware-watchpoint map populated after the
                 process is gone, so the next launch on this debugger inherits
                 watchpoints it never set and re-arms them on its own threads"
            );
        }
    }
    #[test]
    fn every_backend_orders_breakpoint_tracking_after_the_memory_write() {
        // Source-level, for the same reason as the `step_over` guard below:
        // `macos_debugger.rs` cannot be compiled or live-tested here, and has
        // now three times kept a defect its twins had fixed. These are the
        // breakpoint-bookkeeping invariants, each proved by a live test on
        // Linux when it was originally found:
        //   * `set_breakpoint` must be idempotent — a second call at the same
        //     address would otherwise read back the `0xCC` it planted itself
        //     and store that as the "original" byte.
        //   * tracking must happen AFTER the write is confirmed, or a failed
        //     write leaves a phantom entry for a breakpoint never installed.
        //   * untracking must happen AFTER the restore is confirmed, or a
        //     failed restore leaves a patched byte that `detach`'s cleanup
        //     sweep will skip.
        fn body<'a>(src: &'a str, f: &str) -> &'a str {
            let start = src.find(f).unwrap_or_else(|| panic!("missing {f}"));
            let rest = &src[start..];
            let end = body_end(rest, "    }");
            &rest[..end]
        }

        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let set = body(src, "async fn set_breakpoint(");
            assert!(
                set.contains("contains_key(&addr.as_u64())"),
                "{name}: set_breakpoint has no idempotency guard"
            );
            let write = set.find("write_memory_raw(addr, crate::host_trap_bytes())")
                .unwrap_or_else(|| panic!("{name}: set_breakpoint never writes 0xCC"));
            let track = set.find("insert(addr.as_u64()")
                .unwrap_or_else(|| panic!("{name}: set_breakpoint never tracks the breakpoint"));
            assert!(
                write < track,
                "{name}: set_breakpoint tracks the breakpoint BEFORE confirming the write"
            );

            let rm = body(src, "async fn remove_breakpoint(");
            let restore = rm.find("write_memory_raw(addr, &original)")
                .unwrap_or_else(|| panic!("{name}: remove_breakpoint never restores the byte"));
            let untrack = rm.find("remove(&addr.as_u64())")
                .unwrap_or_else(|| panic!("{name}: remove_breakpoint never untracks"));
            assert!(
                restore < untrack,
                "{name}: remove_breakpoint untracks BEFORE confirming the restore"
            );
        }

        // The Apple backend, in its own spelling. This is the guard whose OTHER
        // half — untrack after the restore — was broken exactly here and stayed
        // broken until iter 285 found it by hand, precisely because this loop
        // never looked at it. Extending it pins the fix.
        {
            let src = include_str!("ios/apple_debugger.rs");
            let set = body(src, "async fn set_breakpoint(");
            // The key gained a CLASS: a code trap and a data watchpoint are
            // independent resources and may share an address, so the guard
            // asks "is one of THIS class already here" rather than "is this
            // address taken". The invariant — refuse a duplicate before
            // touching the target — is unchanged; only what counts as a
            // duplicate got more precise.
            assert!(
                set.contains("breakpoints.read().contains_key(&(a, BpClass::of(kind)))"),
                "apple: set_breakpoint has no idempotency guard, or it no longer discriminates \
                 by resource class"
            );
            let arm = set
                .find("commands::insert_breakpoint(zkind, a, size)")
                .unwrap_or_else(|| panic!("apple: set_breakpoint never arms the breakpoint"));
            let track = set
                // Keyed by `(address, class)` since the two resource kinds were
                // allowed to share an address; the ordering invariant below is
                // what this guard is really about and is unchanged.
                .find("breakpoints.write().insert((a, BpClass::of(kind)), record)")
                .unwrap_or_else(|| panic!("apple: set_breakpoint never tracks the breakpoint"));
            assert!(
                arm < track,
                "apple: set_breakpoint tracks the breakpoint BEFORE arming it, so a refused                  arm would leave a phantom entry for a breakpoint that was never installed"
            );

            // The work moved into `remove_one`, which un-arms ONE resource
            // class: an address can carry a code trap and a data watchpoint,
            // and `remove_breakpoint` loops over both. Un-arming one while
            // untracking BOTH left the other live in the target and invisible
            // to `detach`, which walks this same map. The ordering invariant
            // below — restore, THEN untrack — is unchanged.
            let rm = body(src, "async fn remove_one(");
            let restore = rm
                .find("write_memory(a, orig)")
                .unwrap_or_else(|| panic!("apple: remove_breakpoint never restores the word"));
            let untrack = rm
                .find("breakpoints.write().remove(&(a, class))")
                .unwrap_or_else(|| panic!("apple: remove_breakpoint never untracks"));
            assert!(
                restore < untrack,
                "apple: remove_breakpoint untracks BEFORE confirming the restore — the `BRK`                  stays in the target and `detach`'s sweep, which walks this same map, skips it"
            );
        }
    }

    /// A watchpoint on the last bytes of the address space still covers them.
    ///
    /// `covering` materialised both ends with `saturating_add`, so a region
    /// ending at `u64::MAX` reported an end of `u64::MAX` where the true
    /// exclusive end is `u64::MAX + 1`. The strict `<` then excluded the final
    /// byte: a watchpoint armed over it never matched an access to it.
    ///
    /// Iters 273/310/311 swept this exact shape across the crate and the sweep
    /// was recorded as complete — it was not. Comparing the OFFSET between the
    /// two starts is exact everywhere and cannot overflow.
    #[test]
    fn a_watchpoint_at_the_end_of_the_address_space_still_covers_its_last_byte() {
        let mut set = WatchpointRegistry::new();
        // Watches the final four bytes: MAX-3, MAX-2, MAX-1, MAX.
        set.add(u64::MAX - 3, 4, WatchpointKind::Write);

        for probe in [u64::MAX - 3, u64::MAX - 1, u64::MAX] {
            assert_eq!(
                set.covering(probe, 1).len(),
                1,
                "an access at {probe:#x} falls inside the watched region and must match"
            );
        }
        // Just below the region, and a zero-length probe, must still not match.
        assert!(set.covering(u64::MAX - 4, 1).is_empty());
        assert!(set.covering(u64::MAX, 0).is_empty(), "an empty range touches nothing");

        // An ordinary region keeps behaving exactly as before.
        let mut ordinary = WatchpointRegistry::new();
        ordinary.add(0x1000, 4, WatchpointKind::Write);
        assert_eq!(ordinary.covering(0x1003, 1).len(), 1);
        assert!(ordinary.covering(0x1004, 1).is_empty(), "end is exclusive");
        assert!(ordinary.covering(0x0FFF, 1).is_empty());
        assert_eq!(ordinary.covering(0x0FFF, 2).len(), 1, "a range overlapping the start matches");
    }

    /// No backend may plant an x86 `int3` without first checking it is running
    /// on x86.
    ///
    /// All three backends write the literal byte `0xCC` to implant a software
    /// breakpoint, and none of them is gated on the host architecture — only on
    /// the OS (`cfg(target_os = ...)`). On AArch64 `0xCC` is not a trap: it is
    /// an arbitrary byte overwriting one quarter of a 4-byte instruction. The
    /// target does not stop, it executes corrupted code.
    ///
    /// How much this can actually bite is worth stating precisely, so nobody
    /// "fixes" it and believes more was fixed than was: Linux and macOS are
    /// x86-only at COMPILE time (`linux_debugger` reads `regs.rip` of
    /// `libc::user_regs_struct`, absent on aarch64; `macos_debugger` reads
    /// `x86_thread_state64_t`), so the trap byte is the last link in a broken
    /// chain, not the first. The runtime refusal below is defence in depth, not
    /// the only defence. The real prerequisite for AArch64 support is porting
    /// `read_regs`/`regs_to_register_set`, not the implant.
    ///
    /// Implanting the correct AArch64 `BRK #0` is a much larger change (the
    /// crate already has `ios::arm64::encode_brk`, but the whole
    /// read-modify-write path assumes a 1-byte patch). Refusing loudly is the
    /// part that can be done correctly today: a clear `Unsupported` beats
    /// wrecking the process under inspection.
    #[test]
    fn no_backend_plants_an_x86_trap_byte_without_checking_the_host_arch() {
        for (name, src) in [
            ("linux", include_str!("linux_debugger.rs")),
            ("windows", include_str!("windows_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            // Stated as a POSITIVE requirement on every backend. The earlier
            // form skipped any file not containing the literal `&[0xCC]`, which
            // meant a backend could go vacuous simply by spelling the patch
            // differently — the guard would have reported success while
            // checking nothing at all.
            // `host_trap_bytes()` joined the accepted spellings in 569, when
            // the blanket refusal was removed. The requirement is unchanged and
            // is the one that always mattered: NEVER plant a hardcoded x86 byte
            // without asking the host. Deriving the trap from the architecture
            // satisfies that more completely than refusing to run does — a
            // refusal keeps the backend honest by keeping it useless.
            let refuses = src.contains("X86_TRAP_BYTE_IS_VALID_HERE");
            let arch_aware =
                src.contains("trap_implant::") || src.contains("host_trap_bytes()");
            assert!(
                refuses || arch_aware,
                "{name}: implants a software breakpoint without accounting for the host \
                 architecture. Use the arch-aware API (`trap_implant::plan_implant`) or \
                 declare the refusal (`X86_TRAP_BYTE_IS_VALID_HERE`). Writing the x86 \
                 `int3` byte 0xCC on an arm64 host overwrites a quarter of an instruction \
                 instead of trapping, so the debuggee runs corrupted code with no error."
            );
        }
    }

    /// The logic the three OS backends share must stay byte-identical.
    ///
    /// Twenty `Debugger` methods are pure logic over per-platform primitives and
    /// are currently duplicated, verbatim, in `linux_debugger.rs`,
    /// `windows_debugger.rs` and `macos_debugger.rs`. That duplication is the
    /// single most recurrent defect source in this crate: a fix lands on the two
    /// backends the development hosts can build and silently misses the third.
    /// The file comments record it happening at iters 137, 156, 157 and 242, and
    /// iters 320 and 329 found two more.
    ///
    /// Freezing the identity here turns that silent, long-lived divergence into
    /// an immediate failure. Seven methods genuinely differ per platform
    /// (`attach`, `launch`, `threads`, `modules`, `memory_maps`, `backtrace`,
    /// `pause` — ptrace vs Mach vs Win32) and are listed as explicit exceptions,
    /// so the list is a decision, not an omission.
    #[test]
    fn the_logic_shared_by_the_three_backends_stays_identical() {
        /// Genuinely platform-specific: different syscalls, not divergent logic.
        const PER_PLATFORM: &[&str] = &[
            "attach", "launch", "threads", "modules", "memory_maps", "backtrace", "pause",
            // Different HARDWARE, not divergent logic: Windows and Linux program
            // the x86 debug registers, macOS accepts AArch64 as well because its
            // register layer translates `dr0`-`dr3` + `DR7` to the
            // `ARM_DEBUG_STATE64` watchpoint pairs. The body above that
            // architecture gate is still deliberately the same text in all three.
            "set_watchpoint_sized",
            // `set_pending_breakpoint` USED to be excepted here: Windows
            // accepted a not-yet-mapped module because it classifies
            // `LOAD_DLL_DEBUG_EVENT`, while Linux and macOS refused because
            // they construct no such event. The note left with that exception
            // said it "must be deleted — the three converge again" once the
            // other two could honour the request.
            //
            // They can now, and not by gaining the event: `arm_pending_breakpoints`
            // re-reads `modules()` at every stop while anything is pending, on
            // all three backends, so the request arms at the first stop after
            // the module appears. The three bodies are identical again and the
            // exception is gone (iteration 531).
        ];

        /// Balanced-brace body starting at `from`, skipping string/char literals
        /// and comments. Getting this wrong is the classic way these source
        /// guards go vacuous, so `shared` below also asserts each body is big
        /// enough to be a real one.
        fn body(src: &str, from: usize) -> Option<&str> {
            let b = src.as_bytes();
            let (mut i, mut depth) = (from, 0i32);
            while i < b.len() {
                match b[i] {
                    b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                        while i < b.len() && b[i] != b'\n' {
                            i += 1;
                        }
                        continue;
                    }
                    b'"' => {
                        i += 1;
                        while i < b.len() && b[i] != b'"' {
                            i += if b[i] == b'\\' { 2 } else { 1 };
                        }
                    }
                    b'\'' => {
                        // char literal only if it closes within 3 bytes;
                        // otherwise it is a lifetime and must not be skipped.
                        let close = (1..=3).find(|k| i + k < b.len() && b[i + k] == b'\'');
                        if let Some(k) = close {
                            i += k;
                        }
                    }
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(&src[from..=i]);
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            None
        }

        fn normalise(s: &str) -> String {
            s.lines()
                .map(|l| l.split("//").next().unwrap_or("").trim())
                .filter(|l| !l.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        }

        /// Bodies of every `async fn` defined outside the test modules.
        fn methods(src: &str) -> std::collections::BTreeMap<String, String> {
            let mut out = std::collections::BTreeMap::new();
            let mut at = 0usize;
            while let Some(rel) = src[at..].find("    async fn ") {
                let start = at + rel + "    async fn ".len();
                at = start;
                let Some(name_end) = src[start..].find(['(', '<']) else { break };
                let name = src[start..start + name_end].trim().to_string();
                let Some(open) = src[start..].find('{') else { break };
                let Some(b) = body(src, start + open) else { break };
                // A test module's methods are indented deeper; keep the first
                // definition of each name, which is the production one.
                out.entry(name).or_insert_with(|| normalise(b));
            }
            out
        }

        /// Production code only: drop every `#[cfg(test)]` module, body and all.
        /// Without this the guard compares TEST functions across backends, which
        /// legitimately differ, and reports them as divergences.
        fn strip_tests(src: &str) -> String {
            let mut out = String::with_capacity(src.len());
            let mut at = 0usize;
            while let Some(rel) = src[at..].find("#[cfg(test)]") {
                let start = at + rel;
                out.push_str(&src[at..start]);
                let Some(open) = src[start..].find('{') else { break };
                match body(src, start + open) {
                    Some(b) => at = start + open + b.len(),
                    None => break,
                }
            }
            out.push_str(&src[at..]);
            out
        }

        let linux = methods(&strip_tests(include_str!("linux_debugger.rs")));
        let windows = methods(&strip_tests(include_str!("windows_debugger.rs")));
        let macos = methods(&strip_tests(include_str!("macos_debugger.rs")));

        // A method that exists on TWO backends and not the third is the very
        // defect this guard was written for — "the fix reached one backend and
        // not the other" — and it was invisible to it: the comparison iterates
        // over Linux's methods and skips silently when the other backend has no
        // such name (`else { continue }`). A family fix that ADDS a method to
        // two backends therefore passed unnoticed, which is exactly how macOS
        // ended up without `retire_session_after_exit` (see the test below).
        //
        // Checked over the UNION of the three name sets, so it does not matter
        // which backend is missing it.
        {
            /// Genuinely one-backend-only: PE is a Windows file format, and
            /// these read it. Anything else present on two backends and absent
            /// on the third is a gap, not a platform difference.
            const BACKEND_ONLY: &[&str] = &["pe_entry_point", "pe_exception_directory"];

            let sets: [(&str, &std::collections::BTreeMap<String, String>); 3] =
                [("linux", &linux), ("windows", &windows), ("macos", &macos)];
            let mut names: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
            for (_, m) in sets {
                names.extend(m.keys().map(String::as_str));
            }
            for name in names {
                if BACKEND_ONLY.contains(&name) {
                    continue;
                }
                let present: Vec<&str> =
                    sets.iter().filter(|(_, m)| m.contains_key(name)).map(|(n, _)| *n).collect();
                let missing: Vec<&str> =
                    sets.iter().filter(|(_, m)| !m.contains_key(name)).map(|(n, _)| *n).collect();
                assert!(
                    present.len() < 2 || missing.is_empty(),
                    "`{name}` is implemented on {present:?} but not on {missing:?}. Either the \
                     change missed a backend — the recurring defect, and the one this crate's \
                     development hosts cannot compile is the usual victim — or it is genuinely \
                     one-backend-only and belongs in BACKEND_ONLY."
                );
            }
        }

        let mut shared = 0usize;
        for (name, l) in &linux {
            if PER_PLATFORM.contains(&name.as_str()) {
                continue;
            }
            for (other_name, other) in [("windows", &windows), ("macos", &macos)] {
                let Some(o) = other.get(name) else { continue };
                assert!(
                    l.len() > 40 && o.len() > 40,
                    "extraction degenerated for `{name}` ({} / {} chars) — the guard would \
                     be comparing nothing",
                    l.len(),
                    o.len()
                );
                assert_eq!(
                    l, o,
                    "`{name}` differs between linux and {other_name}. Either the fix reached \
                     one backend and not the other (the recurring defect this guards), or the \
                     difference is deliberate and `{name}` belongs in PER_PLATFORM."
                );
                shared += 1;
            }
        }
        assert!(
            shared >= 30,
            "only {shared} shared method pairs compared — the extraction silently stopped \
             matching, so this guard is no longer checking what it claims"
        );
    }

    /// Every backend must clear its session state once the target exits.
    ///
    /// Linux and Windows both call `retire_session_after_exit` on the exit path
    /// of `continue_execution`/`single_step`, dropping pid, command channel,
    /// current thread and the breakpoint bookkeeping. The macOS backend had
    /// neither the function nor the calls, so after a target exited normally its
    /// `pid` stayed set — and `launch` refuses to run while `pid` is `Some`
    /// (the guard added for the orphaned-process leak). A perfectly ordinary
    /// exit therefore left that debugger permanently unusable, with stale
    /// breakpoints still reported by `breakpoints()`.
    ///
    /// This is the same failure mode the macOS backend already carries comments
    /// about (iter 157, iter 242): a family fix lands on the two backends the
    /// development hosts can compile, and silently misses the third. Source
    /// text is the only check available for a backend that cannot be built
    /// here, so that is what this asserts.
    #[test]
    fn every_backend_retires_its_session_after_the_target_exits() {
        for (name, src) in [
            ("linux", include_str!("linux_debugger.rs")),
            ("windows", include_str!("windows_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            assert!(
                src.contains("fn retire_session_after_exit(&self)"),
                "{name}: no `retire_session_after_exit` — a target that exits leaves pid/cmd_tx \
                 set, and `launch` then refuses to start another process"
            );
            // Declaring it is not enough: it has to run on the exit path.
            let calls = src.matches("self.retire_session_after_exit();").count();
            assert!(
                calls >= 2,
                "{name}: `retire_session_after_exit` is called {calls} time(s); both the \
                 continue and the single-step exit paths must retire the session"
            );
        }
    }

    #[test]
    fn every_backend_step_over_tests_exit_before_reading_registers() {
        // Source-level check on purpose. `macos_debugger.rs` cannot be
        // compiled or live-tested on the hosts this crate is developed on, so
        // it has now twice silently kept a defect the other two backends had
        // fixed (`run_to_return`, iter 242; `step_over`, iter 243). A test
        // that only exercises the compiled backends can never catch that.
        //
        // The invariant: after `single_step`, `step_over` must test
        // `is_exit()` BEFORE reading registers. Once the process is gone the
        // read fails, and propagating that error masks a valid `ProcessExit`.
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let Some(start) = src.find("async fn step_over(") else {
                panic!("{name}: no step_over to check");
            };
            let body = &src[start..];
            let step = body.find("self.single_step(tid).await?")
                .unwrap_or_else(|| panic!("{name}: step_over does not single_step"));
            let read = body.find("let after = self.get_registers(tid).await?")
                .unwrap_or_else(|| panic!("{name}: step_over does not read registers after the step"));
            let exit = body.find("event.reason.is_exit()")
                .unwrap_or_else(|| panic!("{name}: step_over has NO is_exit() guard at all"));
            assert!(
                step < exit && exit < read,
                "{name}: step_over must check is_exit() between single_step and the                  register read (single_step@{step}, is_exit@{exit}, read@{read})"
            );
        }

        // The Apple backend expresses the SAME property through a different
        // shape, so the x86 sequence above cannot be applied literally: its
        // `step_over` plants a temporary breakpoint at the return site and
        // resumes instead of single-stepping and re-reading registers.
        //
        // Bodies are delimited by the START of the next function, never by an
        // indented closing brace. These sources are CRLF, so an escaped newline
        // in a terminator matches nothing and the slice runs to the END OF THE
        // FILE — the first version of this block did exactly that and blamed
        // `step_over` for a register read that lives in `step_out`, several
        // functions below. Two plain-text anchors have no such trap.
        {
            let src = include_str!("ios/apple_debugger.rs");
            let over_at = src.find("async fn step_over(").expect("apple: no step_over");
            let out_at = src.find("async fn step_out(").expect("apple: no step_out");
            assert!(over_at < out_at, "apple: step_out no longer follows step_over");
            let over = &src[over_at..out_at];
            if let Some(resume_at) = over.find("self.resume(Some(tid), false)") {
                assert!(
                    !over[resume_at..].contains("read_register_set"),
                    "apple: step_over reads registers after resuming without testing is_exit() first, so a target that just exited would fail the read and mask a valid ProcessExit"
                );
            }
            assert!(
                src[out_at..].contains("run_to_return_step(event.reason.is_exit()"),
                "apple: step_out must hand the exit/registers decision to the shared run_to_return_step, which encodes this ordering once for every backend instead of leaving each one to re-derive it (and get it wrong twice)"
            );
        }
    }

    #[test]
    fn run_to_return_step_encodes_both_historical_defects() {
        use super::{run_to_return_step, RunToReturnStep::*};
        const TARGET: u64 = 0x1000;

        // Defect 1 (iters 156/157): an exit must win even though the
        // register read could not have produced a match. macOS ordered the
        // register read first, which made this case unreachable.
        assert_eq!(run_to_return_step(true, None, TARGET, 0), Done);
        // ...and it must win even if registers WERE readable and matched
        // nothing, which is the shape the exit event actually arrives in.
        assert_eq!(run_to_return_step(true, Some((0xDEAD, 0)), TARGET, 0), Done);

        // Defect 2 (iter 241): a vanished thread (regs unreadable) while the
        // process is still alive means keep pumping events — NOT an error,
        // and NOT done.
        assert_eq!(run_to_return_step(false, None, TARGET, 0), KeepGoing);

        // Normal operation is unchanged: reaching the target above min_sp is
        // done, anything else keeps going.
        assert_eq!(run_to_return_step(false, Some((TARGET, 0x50)), TARGET, 0x10), Done);
        assert_eq!(run_to_return_step(false, Some((TARGET, 0x08)), TARGET, 0x10), KeepGoing);
        assert_eq!(run_to_return_step(false, Some((0x2000, 0x50)), TARGET, 0x10), KeepGoing);
    }

    #[test]
    fn session_state_is_live() {
        use SessionState::*;
        assert!(Stopped.is_live());
        assert!(Running.is_live());
        assert!(!Idle.is_live());
        assert!(!Terminated.is_live());
    }

    #[test]
    fn session_state_display() {
        assert_eq!(SessionState::Idle.to_string(), "idle");
        assert_eq!(SessionState::Stopped.to_string(), "stopped");
        assert_eq!(SessionState::Running.to_string(), "running");
        assert_eq!(SessionState::Stepping.to_string(), "stepping");
    }

    // ── EventDispatcher ───────────────────────────────────────────────────────

    #[test]
    fn event_dispatcher_subscribe_dispatch() {
        use std::sync::{Arc, Mutex};
        let d = EventDispatcher::new();
        let received: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let recv_clone = Arc::clone(&received);
        d.subscribe(Box::new(move |ev| {
            recv_clone.lock().unwrap_or_else(|p| p.into_inner()).push(ev.pid.0);
        }));
        assert_eq!(d.subscriber_count(), 1);
        let ev = DebugEvent::new(
            ProcessId(42),
            ThreadId(1),
            StopReason::Unknown {
                description: "test".into(),
            },
        );
        d.dispatch(&ev);
        assert_eq!(*received.lock().unwrap_or_else(|p| p.into_inner()), vec![42u32]);
    }

    #[test]
    fn event_dispatcher_no_subscribers() {
        let d = EventDispatcher::new();
        let ev = DebugEvent::new(
            ProcessId(1),
            ThreadId(1),
            StopReason::ProcessExit { exit_code: 0 },
        );
        d.dispatch(&ev); // should not panic
        assert_eq!(d.subscriber_count(), 0);
    }

    // ── DebugSnapshot ─────────────────────────────────────────────────────────

    #[test]
    fn debug_snapshot_json_roundtrip() {
        let mut snap = DebugSnapshot::new(1234, "breakpoint");
        snap.add_module(SnapshotModule {
            name: "test.so".into(),
            base: 0x7000_0000,
            size: 0x1000,
        });
        let json = snap.to_json().unwrap();
        let back = DebugSnapshot::from_json(&json).unwrap();
        assert_eq!(back.pid, 1234);
        assert_eq!(back.modules[0].name, "test.so");
    }

    #[test]
    fn debug_snapshot_total_memory_bytes() {
        let mut snap = DebugSnapshot::new(1, "test");
        snap.add_memory_region(SnapshotMemoryRegion {
            base: 0x1000,
            data: vec![0u8; 256],
            flags: "r-x".into(),
        });
        snap.add_memory_region(SnapshotMemoryRegion {
            base: 0x2000,
            data: vec![0u8; 512],
            flags: "rw-".into(),
        });
        assert_eq!(snap.total_memory_bytes(), 768);
    }

    #[test]
    fn debug_snapshot_capture_thread() {
        let mut regs = RegisterSet::new();
        regs.pc = 0x4000;
        regs.sp = 0x7FFF;
        regs.set("rax", 42);
        let frames = vec![StackFrame {
            index: 0,
            pc: Address::new(0x4000),
            sp: Address::new(0x7FFF),
            fp: None,
            function_name: Some("main".into()),
            module: Some("app".into()),
            offset: None,
            source_file: None,
            source_line: None,
        }];
        let ts = DebugSnapshot::capture_thread(7, &regs, &frames);
        assert_eq!(ts.tid, 7);
        assert_eq!(ts.pc, 0x4000);
        assert_eq!(ts.frames[0].function_name, Some("main".into()));
    }

    // ── SymbolTable ───────────────────────────────────────────────────────────

    #[test]
    fn symbol_table_lookup_by_name() {
        let mut t = SymbolTable::new();
        t.add(Symbol::new("main", 0x4000));
        let sym = t.by_name("main").unwrap();
        assert_eq!(sym.address, 0x4000);
    }

    #[test]
    fn symbol_table_resolve_by_address() {
        let mut t = SymbolTable::new();
        let mut s = Symbol::new("foo", 0x1000);
        s.size = 0x100;
        t.add(s);
        let found = t.resolve(0x1050).unwrap();
        assert_eq!(found.name, "foo");
        assert!(t.resolve(0x2000).is_none());
    }

    #[test]
    fn symbol_table_search() {
        let mut t = SymbolTable::new();
        t.add(Symbol::new("malloc", 0xABC0));
        t.add(Symbol::new("free", 0xBBC0));
        t.add(Symbol::new("realloc", 0xCC00));
        let results = t.search("alloc");
        assert_eq!(results.len(), 2); // malloc and realloc
    }

    #[test]
    fn symbol_contains() {
        let mut s = Symbol::new("fn_foo", 0x5000);
        s.size = 0x80;
        assert!(s.contains(0x5000));
        assert!(s.contains(0x507F));
        assert!(!s.contains(0x5080));
    }

    // ── FramePointerUnwinder ──────────────────────────────────────────────────

    /// A corrupt frame pointer must degrade, never panic or spin.
    ///
    /// This unwinder is the fallback every backend falls back TO, so its
    /// robustness is the debugger's robustness. Two problems, both driven by
    /// data read out of the debuggee (which may be corrupt or hostile):
    ///
    /// * `read_u64` tested `addr + 8 <= base + len` — that addition wraps for
    ///   an `addr` near `u64::MAX`, so the bounds test passed, the computed
    ///   offset was enormous, and slicing it panicked the debugger.
    /// * Only `saved_fp == fp` was rejected, so a two-node cycle A -> B -> A
    ///   was walked until the 64-frame cap, reporting 64 fabricated frames as
    ///   if they were a real call chain. The twin in `memory_layout_view`
    ///   already required the chain to move monotonically up the stack.
    #[test]
    fn a_corrupt_frame_pointer_neither_panics_nor_fabricates_a_chain() {
        let mem = vec![(0x7F00u64, vec![0u8; 0x40])];

        // A frame pointer near the top of the address space: the bounds check
        // must reject it rather than wrap and index out of bounds.
        let mut regs = RegisterSet::new();
        regs.pc = 0x4000;
        regs.sp = 0x7EF0;
        regs.fp = Some(u64::MAX - 3);
        let frames = FramePointerUnwinder.unwind(&regs, &mem).expect("must not fail");
        assert_eq!(frames.len(), 1, "an unreadable frame pointer yields only the initial frame");

        // A two-node cycle: [0x7F00] -> 0x7F20, [0x7F20] -> 0x7F00.
        let mut cyc = vec![0u8; 0x40];
        cyc[0..8].copy_from_slice(&0x7F20u64.to_le_bytes());
        cyc[8..16].copy_from_slice(&0x4010u64.to_le_bytes());
        cyc[0x20..0x28].copy_from_slice(&0x7F00u64.to_le_bytes());
        cyc[0x28..0x30].copy_from_slice(&0x4020u64.to_le_bytes());
        let mut regs = RegisterSet::new();
        regs.pc = 0x4000;
        regs.sp = 0x7EF0;
        regs.fp = Some(0x7F00);
        let frames = FramePointerUnwinder.unwind(&regs, &vec![(0x7F00u64, cyc)]).unwrap();
        assert!(
            frames.len() <= 3,
            "a frame-pointer cycle must stop as soon as the chain stops moving up the              stack, not run to the frame cap: got {} frames",
            frames.len()
        );
    }

    #[test]
    fn frame_pointer_unwind_simple() {
        // Construct a two-frame synthetic stack in memory:
        // frame[0]: fp=0x7F00, saved_fp at [0x7F00]=0x7F20, ret_addr at [0x7F08]=0x4010
        // frame[1]: fp=0x7F20, saved_fp at [0x7F20]=0x0000, ret_addr at [0x7F28]=0x3000
        let mut mem_data = vec![0u8; 0x40];
        // [0x7F00..0x7F08] = saved_fp = 0x7F20
        mem_data[0..8].copy_from_slice(&0x7F20u64.to_le_bytes());
        // [0x7F08..0x7F10] = ret_addr = 0x4010
        mem_data[8..16].copy_from_slice(&0x4010u64.to_le_bytes());
        // [0x7F20..0x7F28] = saved_fp = 0x0000
        mem_data[0x20..0x28].copy_from_slice(&0u64.to_le_bytes());
        // [0x7F28..0x7F30] = ret_addr = 0x3000
        mem_data[0x28..0x30].copy_from_slice(&0x3000u64.to_le_bytes());

        let mut regs = RegisterSet::new();
        regs.pc = 0x4000;
        regs.sp = 0x7EF0;
        regs.fp = Some(0x7F00);

        let mem = vec![(0x7F00u64, mem_data)];
        let unwinder = FramePointerUnwinder;
        let frames = unwinder.unwind(&regs, &mem).unwrap();
        // Should have at least 2 frames
        assert!(frames.len() >= 2);
        assert_eq!(frames[0].pc, Address::new(0x4000));
    }

    // ── DisasmListing ─────────────────────────────────────────────────────────

    #[test]
    fn disasm_listing_at_address() {
        let mut listing = DisasmListing::new();
        listing.lines.push(DisasmLine {
            address: 0x1000,
            bytes: vec![0x90],
            mnemonic: "nop".into(),
            operands: String::new(),
            category: InsnCategory::Other,
            has_breakpoint: false,
            is_current_pc: false,
            symbol: None,
        });
        assert!(listing.at(0x1000).is_some());
        assert!(listing.at(0x1001).is_none());
    }

    #[test]
    fn disasm_listing_render() {
        let mut listing = DisasmListing::new();
        listing.lines.push(DisasmLine {
            address: 0x4000,
            bytes: vec![0x55],
            mnemonic: "push".into(),
            operands: "rbp".into(),
            category: InsnCategory::Memory,
            has_breakpoint: true,
            is_current_pc: true,
            symbol: Some("main".into()),
        });
        let out = listing.render(0x4000, &[0x4000]);
        assert!(out.contains("push"));
        assert!(out.contains("rbp"));
        assert!(out.contains("main"));
    }

    // ── SourceFile ────────────────────────────────────────────────────────────

    #[test]
    fn source_file_line_access() {
        let mut sf = SourceFile::new("/src/main.c");
        sf.lines = vec!["int main() {".into(), "  return 0;".into(), "}".into()];
        assert_eq!(sf.line(1), Some("int main() {"));
        assert_eq!(sf.line(3), Some("}"));
        assert!(sf.line(4).is_none());
        assert_eq!(sf.line_count(), 3);
    }

    #[test]
    fn source_file_snippet() {
        let mut sf = SourceFile::new("/src/foo.c");
        sf.lines = (1u32..=10).map(|i| format!("line {i}")).collect();
        let snip = sf.snippet(3, 5);
        assert_eq!(snip.len(), 3);
        assert_eq!(snip[0], (3, "line 3"));
        assert_eq!(snip[2], (5, "line 5"));
    }

    // ── SourceBreakpoint ──────────────────────────────────────────────────────

    #[test]
    fn source_breakpoint_resolve() {
        let mut sbp = SourceBreakpoint::new(1, "/src/main.c", 42);
        assert!(!sbp.resolved);
        sbp.resolve(0x12345);
        assert!(sbp.resolved);
        assert_eq!(sbp.address, Some(0x12345));
    }

    // ── WatchpointKind Display ────────────────────────────────────────────────

    #[test]
    fn watchpoint_kind_display() {
        assert_eq!(WatchpointKind::Read.to_string(), "read");
        assert_eq!(WatchpointKind::Write.to_string(), "write");
        assert_eq!(WatchpointKind::ReadWrite.to_string(), "read/write");
        assert_eq!(WatchpointKind::Change.to_string(), "change");
    }

    // ── UnwindStrategy Display ────────────────────────────────────────────────

    #[test]
    fn unwind_strategy_display() {
        assert_eq!(UnwindStrategy::Dwarf.to_string(), "dwarf");
        assert_eq!(UnwindStrategy::FramePointer.to_string(), "frame-pointer");
        assert_eq!(UnwindStrategy::StackScan.to_string(), "stack-scan");
        assert_eq!(UnwindStrategy::Auto.to_string(), "auto");
    }

    // ── InsnCategory ─────────────────────────────────────────────────────────

    #[test]
    fn disasm_line_display() {
        let l = DisasmLine {
            address: 0,
            bytes: vec![0x48, 0x89, 0xC0],
            mnemonic: "mov".into(),
            operands: "rax, rax".into(),
            category: InsnCategory::Alu,
            has_breakpoint: false,
            is_current_pc: false,
            symbol: None,
        };
        assert_eq!(l.display(), "mov        rax, rax");
        assert_eq!(l.len(), 3);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryPermissions — readable permission flags for a memory region
// ─────────────────────────────────────────────────────────────────────────────

/// Access permissions for a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct MemoryPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl MemoryPermissions {
    /// Create `r--` permissions.
    #[must_use]
    pub const fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            execute: false,
        }
    }

    /// Create `rw-` permissions.
    #[must_use]
    pub const fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
        }
    }

    /// Create `r-x` permissions.
    #[must_use]
    pub const fn read_exec() -> Self {
        Self {
            read: true,
            write: false,
            execute: true,
        }
    }

    /// Create `rwx` permissions.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
        }
    }

    /// Create `---` permissions (inaccessible).
    #[must_use]
    pub const fn none() -> Self {
        Self {
            read: false,
            write: false,
            execute: false,
        }
    }

    /// Parse from a Unix-style string like `"r-x"` or `"rwx"`.
    #[must_use]
    pub fn from_unix_str(s: &str) -> Self {
        let chars: Vec<char> = s.chars().collect();
        Self {
            read: chars.first().is_some_and(|c| *c == 'r'),
            write: chars.get(1).is_some_and(|c| *c == 'w'),
            execute: chars.get(2).is_some_and(|c| *c == 'x'),
        }
    }

    /// Format as a Unix-style string.
    #[must_use]
    pub fn to_unix_str(&self) -> String {
        format!(
            "{}{}{}",
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.execute { 'x' } else { '-' },
        )
    }

    /// Returns `true` if executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.execute
    }

    /// Returns `true` if writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.write
    }

    /// Returns `true` if readable.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.read
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryRegionInfo — metadata about a mapped memory region
// ─────────────────────────────────────────────────────────────────────────────

/// Information about a single mapped memory region.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryRegionInfo {
    /// Start address.
    pub base: u64,
    /// Size in bytes.
    pub size: u64,
    /// Access permissions.
    pub perms: MemoryPermissions,
    /// Backing file path, if any.
    pub file: Option<String>,
    /// File offset.
    pub file_offset: u64,
    /// Friendly label.
    pub label: Option<String>,
}

impl MemoryRegionInfo {
    /// Create a new region.
    #[must_use]
    pub const fn new(base: u64, size: u64, perms: MemoryPermissions) -> Self {
        Self {
            base,
            size,
            perms,
            file: None,
            file_offset: 0,
            label: None,
        }
    }

    /// End address (exclusive).
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.base + self.size
    }

    /// Returns `true` if `addr` is within `[base, base + size)`.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }

    /// Attach a label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Attach a backing file.
    #[must_use]
    pub fn with_file(mut self, path: impl Into<String>, offset: u64) -> Self {
        self.file = Some(path.into());
        self.file_offset = offset;
        self
    }
}

/// A structured map of `MemoryRegionInfo` entries.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RegionMap {
    regions: Vec<MemoryRegionInfo>,
}

impl RegionMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a region.
    pub fn add(&mut self, region: MemoryRegionInfo) {
        self.regions.push(region);
        self.regions.sort_by_key(|r| r.base);
    }

    /// Find regions containing `addr`.
    #[must_use]
    pub fn find(&self, addr: u64) -> Vec<&MemoryRegionInfo> {
        self.regions.iter().filter(|r| r.contains(addr)).collect()
    }

    /// All executable regions.
    #[must_use]
    pub fn executable_regions(&self) -> Vec<&MemoryRegionInfo> {
        self.regions.iter().filter(|r| r.perms.execute).collect()
    }

    /// All writable regions.
    #[must_use]
    pub fn writable_regions(&self) -> Vec<&MemoryRegionInfo> {
        self.regions.iter().filter(|r| r.perms.write).collect()
    }

    /// Number of regions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.regions.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Total mapped bytes.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.regions.iter().map(|r| r.size).sum()
    }

    /// All regions, sorted by base.
    #[must_use]
    pub fn all(&self) -> &[MemoryRegionInfo] {
        &self.regions
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DebugEventFilter — predicate-based event filtering
// ─────────────────────────────────────────────────────────────────────────────

/// A filter for debug events.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DebugEventFilter {
    /// Process ID filter (if `Some`, only pass events from this PID).
    pub pid: Option<u32>,
    /// Thread ID filter.
    pub tid: Option<u32>,
    /// Only pass breakpoint stops.
    pub breakpoints_only: bool,
    /// Only pass single-step stops.
    pub singlestep_only: bool,
    /// Pass all events through.
    pub pass_all: bool,
}

impl DebugEventFilter {
    /// Create a pass-all filter.
    #[must_use]
    pub const fn pass_all() -> Self {
        Self {
            pid: None,
            tid: None,
            breakpoints_only: false,
            singlestep_only: false,
            pass_all: true,
        }
    }

    /// Create a filter that only passes events from a specific PID.
    #[must_use]
    pub const fn for_pid(pid: u32) -> Self {
        Self {
            pid: Some(pid),
            tid: None,
            breakpoints_only: false,
            singlestep_only: false,
            pass_all: false,
        }
    }

    /// Returns `true` if the event passes this filter.
    #[must_use]
    pub const fn accepts(&self, event: &DebugEvent) -> bool {
        if self.pass_all {
            return true;
        }
        if let Some(pid) = self.pid
            && event.pid.0 != pid
        {
            return false;
        }
        if let Some(tid) = self.tid
            && event.tid.0 != tid
        {
            return false;
        }
        if self.breakpoints_only {
            return matches!(event.reason, StopReason::Breakpoint { .. });
        }
        if self.singlestep_only {
            return matches!(event.reason, StopReason::SingleStep { .. });
        }
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConditionExpression — simple expression evaluator for conditional breaks
// ─────────────────────────────────────────────────────────────────────────────

/// A simple condition expression for conditional breakpoints.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ConditionExpr {
    /// `reg == value`
    RegEq { reg: String, value: u64 },
    /// `reg != value`
    RegNe { reg: String, value: u64 },
    /// `reg > value`
    RegGt { reg: String, value: u64 },
    /// `reg < value`
    RegLt { reg: String, value: u64 },
    /// `expr1 && expr2`
    And(Box<Self>, Box<Self>),
    /// `expr1 || expr2`
    Or(Box<Self>, Box<Self>),
    /// `!expr`
    Not(Box<Self>),
    /// Always true.
    True,
    /// Always false.
    False,
}

impl ConditionExpr {
    /// Evaluate this expression given a register set.
    #[must_use]
    pub fn evaluate(&self, regs: &RegisterSet) -> bool {
        match self {
            Self::RegEq { reg, value } => regs.get(reg).is_some_and(|v| v == *value),
            Self::RegNe { reg, value } => regs.get(reg).is_some_and(|v| v != *value),
            Self::RegGt { reg, value } => regs.get(reg).is_some_and(|v| v > *value),
            Self::RegLt { reg, value } => regs.get(reg).is_some_and(|v| v < *value),
            Self::And(a, b) => a.evaluate(regs) && b.evaluate(regs),
            Self::Or(a, b) => a.evaluate(regs) || b.evaluate(regs),
            Self::Not(e) => !e.evaluate(regs),
            Self::True => true,
            Self::False => false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for new debug types
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_extra {
    /// A marked address must be unmarked even when the caller leaves early.
    ///
    /// `run_to_return` marks the address it is waiting for so a user's condition
    /// cannot filter out a stop the DEBUGGER arranged (iteration 433). Marking it
    /// with a plain insert/remove pair leaks: the wait loop propagates errors
    /// with `?`, so a target that dies mid-step leaves the address marked
    /// FOREVER — and from then on the user's condition there is silently ignored,
    /// which is the very defect the condition work exists to prevent.
    ///
    /// Drop is the only mechanism that survives `?`, a panic, and every future
    /// early return somebody adds to that function.
    #[test]
    fn a_marked_address_is_unmarked_on_every_exit_path() {
        let set = parking_lot::Mutex::new(std::collections::HashSet::new());

        {
            let _g = crate::AddressGuard::new(&set, 0x1000);
            assert!(set.lock().contains(&0x1000), "the address must be marked while the guard lives");
        }
        assert!(!set.lock().contains(&0x1000), "a normal return left the address marked");

        // The case the pair got wrong: an early exit through `?`.
        fn early(set: &parking_lot::Mutex<std::collections::HashSet<u64>>) -> Result<(), ()> {
            let _g = crate::AddressGuard::new(set, 0x2000);
            Err(())
        }
        let _ = early(&set);
        assert!(
            !set.lock().contains(&0x2000),
            "an error path left the address marked: the user's condition at that address is now silently ignored for the rest of the session"
        );

        // And a panic, which no amount of care in the function body covers.
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = crate::AddressGuard::new(&set, 0x3000);
            panic!("boom");
        }));
        assert!(panicked.is_err());
        assert!(!set.lock().contains(&0x3000), "a panic left the address marked");
    }
    use super::*;

    // ── RegisterSchema: AArch64 ABI names ────────────────────────────────────

    /// The rest of the crate refers to the AArch64 frame pointer and link
    /// register by their AAPCS64 names (`fp`, `lr`), not by `x29`/`x30`:
    /// `register_context.rs` names them that way, and `minidump_analysis.rs`
    /// decodes the ARM64 CONTEXT into keys `"fp"`/`"lr"`. The schema must
    /// resolve those names, exactly like the x86-64 schema resolves `esp`→`rsp`.
    #[test]
    fn aarch64_schema_resolves_the_names_the_rest_of_the_crate_uses() {
        let c = RegisterSchema::aarch64();
        assert_eq!(
            c.get("lr").map(|r| r.name.as_str()),
            Some("x30"),
            "`lr` must alias x30"
        );
        assert_eq!(
            c.get("fp").map(|r| r.name.as_str()),
            Some("x29"),
            "`fp` must alias x29"
        );
        // …and they must be ALIASES, not separate registers sharing a DWARF id.
        assert_eq!(c.get("lr").unwrap().dwarf_id, Some(30));
        assert_eq!(c.get("fp").unwrap().dwarf_id, Some(29));
        // Same RegisterInfo instance, reached from either name.
        assert_eq!(c.get("lr").unwrap().name, c.get("x30").unwrap().name);
        assert_eq!(c.get("fp").unwrap().name, c.get("x29").unwrap().name);
    }

    /// Negative control: the fix must not leak names across architectures.
    #[test]
    fn aarch64_and_x86_schemas_do_not_borrow_each_others_names() {
        assert!(RegisterSchema::aarch64().get("rip").is_none());
        assert!(RegisterSchema::x86_64().get("lr").is_none());
        assert!(RegisterSchema::x86_64().get("x29").is_none());
    }

    // ── MemoryPermissions ─────────────────────────────────────────────────────

    #[test]
    fn mem_perms_unix_str_roundtrip() {
        let perms = MemoryPermissions::read_exec();
        let s = perms.to_unix_str();
        assert_eq!(s, "r-x");
        let back = MemoryPermissions::from_unix_str(&s);
        assert_eq!(back, perms);
    }

    #[test]
    fn mem_perms_all() {
        let p = MemoryPermissions::all();
        assert!(p.is_readable());
        assert!(p.is_writable());
        assert!(p.is_executable());
        assert_eq!(p.to_unix_str(), "rwx");
    }

    #[test]
    fn mem_perms_none() {
        let p = MemoryPermissions::none();
        assert!(!p.is_readable());
        assert_eq!(p.to_unix_str(), "---");
    }

    #[test]
    fn mem_perms_from_unix_partial() {
        let p = MemoryPermissions::from_unix_str("r");
        assert!(p.is_readable());
        assert!(!p.is_writable());
    }

    // ── MemoryRegionInfo ──────────────────────────────────────────────────────

    #[test]
    fn region_contains() {
        let r = MemoryRegionInfo::new(0x1000, 0x1000, MemoryPermissions::read_exec());
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1FFF));
        assert!(!r.contains(0x2000));
    }

    #[test]
    fn region_end() {
        let r = MemoryRegionInfo::new(0x4000, 0x100, MemoryPermissions::read_only());
        assert_eq!(r.end(), 0x4100);
    }

    #[test]
    fn region_with_file() {
        let r = MemoryRegionInfo::new(0, 0x1000, MemoryPermissions::read_exec())
            .with_file("/lib/x86_64-linux-gnu/libc.so.6", 0);
        assert_eq!(r.file.as_deref(), Some("/lib/x86_64-linux-gnu/libc.so.6"));
    }

    // ── MemoryMap ─────────────────────────────────────────────────────────────

    #[test]
    fn memory_map_find() {
        let mut mm = RegionMap::new();
        mm.add(MemoryRegionInfo::new(
            0x1000,
            0x1000,
            MemoryPermissions::read_exec(),
        ));
        mm.add(MemoryRegionInfo::new(
            0x3000,
            0x1000,
            MemoryPermissions::read_write(),
        ));
        let found = mm.find(0x1500);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].base, 0x1000);
        assert!(mm.find(0x2000).is_empty());
    }

    #[test]
    fn memory_map_executable() {
        let mut mm = RegionMap::new();
        mm.add(MemoryRegionInfo::new(
            0x1000,
            0x100,
            MemoryPermissions::read_exec(),
        ));
        mm.add(MemoryRegionInfo::new(
            0x2000,
            0x100,
            MemoryPermissions::read_write(),
        ));
        assert_eq!(mm.executable_regions().len(), 1);
        assert_eq!(mm.writable_regions().len(), 1);
    }

    #[test]
    fn memory_map_total_size() {
        let mut mm = RegionMap::new();
        mm.add(MemoryRegionInfo::new(
            0x1000,
            0x100,
            MemoryPermissions::read_only(),
        ));
        mm.add(MemoryRegionInfo::new(
            0x2000,
            0x200,
            MemoryPermissions::read_only(),
        ));
        assert_eq!(mm.total_size(), 0x300);
    }

    // ── DebugEventFilter ──────────────────────────────────────────────────────

    #[test]
    fn event_filter_pass_all() {
        let f = DebugEventFilter::pass_all();
        let ev = DebugEvent::new(
            ProcessId(1),
            ThreadId(1),
            StopReason::SingleStep {
                address: Address::new(0),
            },
        );
        assert!(f.accepts(&ev));
    }

    #[test]
    fn event_filter_pid_match() {
        let f = DebugEventFilter::for_pid(42);
        let ev_match = DebugEvent::new(
            ProcessId(42),
            ThreadId(1),
            StopReason::SingleStep {
                address: Address::new(0),
            },
        );
        let ev_miss = DebugEvent::new(
            ProcessId(99),
            ThreadId(1),
            StopReason::SingleStep {
                address: Address::new(0),
            },
        );
        assert!(f.accepts(&ev_match));
        assert!(!f.accepts(&ev_miss));
    }

    #[test]
    fn event_filter_breakpoints_only() {
        let f = DebugEventFilter {
            pid: None,
            tid: None,
            breakpoints_only: true,
            singlestep_only: false,
            pass_all: false,
        };
        let bp_ev = DebugEvent::new(
            ProcessId(1),
            ThreadId(1),
            StopReason::Breakpoint {
                address: Address::new(0x1000),
                bp: Breakpoint::new_software(Address::new(0x1000)),
            },
        );
        let ss_ev = DebugEvent::new(
            ProcessId(1),
            ThreadId(1),
            StopReason::SingleStep {
                address: Address::new(0),
            },
        );
        assert!(f.accepts(&bp_ev));
        assert!(!f.accepts(&ss_ev));
    }

    // ── ConditionExpr ─────────────────────────────────────────────────────────

    #[test]
    fn condition_reg_eq_true() {
        let mut regs = RegisterSet::new();
        regs.set("rax", 42);
        let cond = ConditionExpr::RegEq {
            reg: "rax".into(),
            value: 42,
        };
        assert!(cond.evaluate(&regs));
    }

    #[test]
    fn condition_reg_eq_false() {
        let mut regs = RegisterSet::new();
        regs.set("rbx", 0);
        let cond = ConditionExpr::RegEq {
            reg: "rbx".into(),
            value: 99,
        };
        assert!(!cond.evaluate(&regs));
    }

    #[test]
    fn condition_reg_ne() {
        let mut regs = RegisterSet::new();
        regs.set("rcx", 5);
        let cond = ConditionExpr::RegNe {
            reg: "rcx".into(),
            value: 4,
        };
        assert!(cond.evaluate(&regs));
    }

    #[test]
    fn condition_and() {
        let mut regs = RegisterSet::new();
        regs.set("rax", 1);
        regs.set("rbx", 2);
        let cond = ConditionExpr::And(
            Box::new(ConditionExpr::RegGt {
                reg: "rax".into(),
                value: 0,
            }),
            Box::new(ConditionExpr::RegGt {
                reg: "rbx".into(),
                value: 1,
            }),
        );
        assert!(cond.evaluate(&regs));
    }

    #[test]
    fn condition_or_one_true() {
        let mut regs = RegisterSet::new();
        regs.set("rax", 0);
        regs.set("rbx", 5);
        let cond = ConditionExpr::Or(
            Box::new(ConditionExpr::RegGt {
                reg: "rax".into(),
                value: 10,
            }),
            Box::new(ConditionExpr::RegGt {
                reg: "rbx".into(),
                value: 3,
            }),
        );
        assert!(cond.evaluate(&regs));
    }

    #[test]
    fn condition_not() {
        let regs = RegisterSet::new();
        let cond = ConditionExpr::Not(Box::new(ConditionExpr::True));
        assert!(!cond.evaluate(&regs));
        let cond2 = ConditionExpr::Not(Box::new(ConditionExpr::False));
        assert!(cond2.evaluate(&regs));
    }

    #[test]
    fn condition_missing_reg() {
        let regs = RegisterSet::new();
        let cond = ConditionExpr::RegEq {
            reg: "unknown_reg".into(),
            value: 0,
        };
        assert!(!cond.evaluate(&regs));
    }

    // ---------------------------------------------------------------------
    // macOS backend source guards.
    //
    // `macos_debugger.rs` is `#![cfg(target_os = "macos")]`, so it is never
    // compiled — let alone run — on this project's Windows and Linux hosts.
    // These tests therefore verify STRUCTURAL properties of its source text
    // rather than behaviour. That is a real and deliberate limitation: a
    // guard proves the corrected shape is still present, not that the code
    // works on a Mac. It exists because the alternative for this file is no
    // verification at all.
    // ---------------------------------------------------------------------

    /// Strip line comments so a guard matches real code, never prose that
    /// happens to quote the pattern being searched for.
    fn code_only(src: &str) -> String {
        src.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Re-enabling a watchpoint that could not be re-armed must not answer
    /// `Ok(())`.
    ///
    /// `enable_breakpoint` has already been fixed TWICE for reporting success
    /// without doing the work — both times on the software half, and both
    /// comments are still in the function. The hardware half kept the defect:
    /// `rearm_watchpoints_on_new_threads()` was called with its result thrown
    /// away, so a debug-register write that did not land left the address in
    /// `hw_watchpoints` (the caller is still told it is watched) with no
    /// register holding it. That is the "silent miss, not an error" this crate
    /// condemns in `set_watchpoint_sized`.
    ///
    /// The resume paths deliberately still discard the list — they run on every
    /// stop and must not fail there. `enable_breakpoint` is the one caller that
    /// asked for the re-arm and can answer for it.
    #[test]
    fn re_enabling_a_watchpoint_that_could_not_be_armed_is_not_reported_as_success() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let stripped = code_only(src);

            // The re-arm must hand back what it failed to arm…
            let rearm = item_body(
                &stripped,
                "async fn rearm_watchpoints_on_new_threads(&self) -> Vec<u64> {",
                &[NEXT_FN, NEXT_ASYNC_FN],
            );
            assert!(
                !rearm.contains("let _ = self.set_registers"),
                "{name}: the re-arm discards the register write, so a thread left unwatched is \
                 indistinguishable from one that was armed"
            );

            // …and the caller that requested it must act on that.
            let enable = item_body(
                &stripped,
                "async fn enable_breakpoint(&self, addr: Address) -> Result<(), DebugError> {",
                &[NEXT_FN, NEXT_ASYNC_FN],
            );
            assert!(
                !enable.contains("let _ = self.rearm_watchpoints_on_new_threads"),
                "{name}: enable_breakpoint throws away whether the watchpoint was actually re-armed"
            );
            assert!(
                enable.contains("could not be re-armed"),
                "{name}: enable_breakpoint has no failure path for a watchpoint it could not re-arm"
            );
        }
    }

    /// A disarm that could not clear the debug registers must SAY so — the
    /// hardware half of the test below.
    ///
    /// `disarm_all_hardware_watchpoints` describes the stake in its own body:
    /// a DR7 left armed makes the target trap with no debugger to take the
    /// trap, "and the kernel's default action for an unhandled SIGTRAP is to
    /// kill it". Yet the write that clears it was `let _ =`, the function
    /// returned `()`, and `hw_watchpoints` was cleared regardless — so a failed
    /// disarm left the registers armed AND erased the only record of them,
    /// while `detach` went on to report success.
    ///
    /// Iteration 533 fixed the software half (restoring `0xCC` bytes) and named
    /// this one; it is the same defect one layer down.
    #[test]
    fn a_disarm_that_cannot_clear_the_debug_registers_does_not_report_success() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let stripped = code_only(src);
            let body = item_body(
                &stripped,
                "async fn disarm_all_hardware_watchpoints(&self) -> Result<(), DebugError> {",
                &[NEXT_FN, NEXT_ASYNC_FN],
            );
            assert!(
                !body.contains("let _ = self.set_registers"),
                "{name}: the debug-register clear discards its result, so a failed disarm passes \
                 for a clean one and the target is left trapping after the detach"
            );
            assert!(
                body.contains("DebugError::DetachError"),
                "{name}: disarm_all_hardware_watchpoints has no failure path"
            );

            // And the bookkeeping must not be wiped on the failing path: it is
            // the only record of what is still armed, so a retry needs it.
            let clear_at = body.find("hw_watchpoints.lock().clear()");
            let fail_at = body.find("return Err(DebugError::DetachError");
            assert!(
                matches!((clear_at, fail_at), (Some(c), Some(f)) if f < c),
                "{name}: hw_watchpoints is cleared before the failure path returns, erasing the \
                 record of registers that are still armed"
            );

            // The caller must not swallow it either.
            let detach = item_body(
                &stripped,
                "async fn detach(&self) -> Result<(), DebugError> {",
                &[NEXT_FN, NEXT_ASYNC_FN],
            );
            assert!(
                detach.contains("disarm_all_hardware_watchpoints().await?"),
                "{name}: detach ignores whether the debug registers were actually disarmed"
            );
        }
    }

    /// A detach that could not un-plant its traps must SAY so.
    ///
    /// `detach` restores every planted `0xCC` before letting go, and the
    /// comment on that loop states the stake plainly: the default action for an
    /// unhandled SIGTRAP is to kill the process, so a trap left behind is a
    /// landmine in the very process being debugged. But the result of each
    /// restore was discarded (`let _ = self.write_memory_raw(...)`), so a write
    /// that did not land produced a detach reporting `Ok(())` and a target that
    /// dies later for no visible reason.
    ///
    /// Asked of all three backends at once: this is shared logic, not a
    /// platform difference, and iteration 530 is the reminder of what happens
    /// when such a change lands on one backend only.
    #[test]
    fn a_detach_that_cannot_restore_a_breakpoint_does_not_report_success() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let stripped = code_only(src);
            let body = item_body(
                &stripped,
                "async fn detach(&self) -> Result<(), DebugError> {",
                &[NEXT_FN, NEXT_ASYNC_FN],
            );
            // The restore loop must still be there…
            assert!(
                body.contains("write_memory_raw"),
                "{name}: detach no longer restores the original bytes at all"
            );
            // …and its outcome must reach a decision instead of the floor.
            assert!(
                !body.contains("let _ = self.write_memory_raw"),
                "{name}: detach discards the result of restoring a planted breakpoint, so a failed \
                 restore is reported as a clean detach and the target is left to die on a trap"
            );
            assert!(
                body.contains("DebugError::DetachError"),
                "{name}: detach has no failure path for a restore that did not land"
            );
        }
    }

    /// Body of the item introduced by `start`, delimited by the START of the
    /// next item rather than a closing brace — the sources use mixed LF/CRLF
    /// line endings and nested braces make brace-counting unreliable.
    fn item_body<'a>(code: &'a str, start: &str, next_markers: &[&str]) -> &'a str {
        let from = code.find(start).unwrap_or_else(|| panic!("`{start}` not found — the guard is no longer anchored to real code"));
        let rest = &code[from + start.len()..];
        // No end marker matched: the body would be "everything after the
        // anchor", which contains every needle any caller could look for. That
        // silently turns every guard built on this helper green at once — the
        // failure mode of iteration 315 (a terminator matching nothing) applied
        // to five guards from a single point. Refuse instead.
        //
        // The last item in a file legitimately has no following marker, so the
        // refusal is conditioned on the leftover being implausibly large for
        // one function: no item in this crate approaches 20k characters.
        let end = match next_markers.iter().filter_map(|m| rest.find(m)).min() {
            Some(e) => e,
            None => {
                assert!(
                    rest.len() < 20_000,
                    "`{start}`: no end marker matched and {} characters remain — the                      delimiters are stale, and the extracted body would contain every                      needle the guard could search for",
                    rest.len()
                );
                rest.len()
            }
        };
        &rest[..end]
    }

    /// A watchpoint hit must be told apart from a single step.
    ///
    /// On x86 a hit raises the SAME trap as a single step
    /// (`EXCEPTION_SINGLE_STEP` / `SIGTRAP`); only `DR6` says which slot
    /// fired. Both backends reported every hit as a plain `SingleStep`, so
    /// the watchpoint was armed correctly (iterations 361-363) and the answer
    /// was then thrown away at the moment it arrived.
    #[test]
    fn a_watchpoint_hit_is_decoded_from_dr6_not_mistaken_for_a_step() {
        // No B bit: a genuine single step, not a hit.
        assert_eq!(x86_watchpoint_hit_slot(0), None);
        // DR6 always has reserved high bits set on real hardware; they must
        // not be read as a hit.
        assert_eq!(x86_watchpoint_hit_slot(0xFFFF_0FF0), None);

        assert_eq!(x86_watchpoint_hit_slot(0b0001), Some(0));
        assert_eq!(x86_watchpoint_hit_slot(0b1000), Some(3));
        // Several at once: report the lowest. Reporting one hit is honest,
        // inventing a combined one is not.
        assert_eq!(x86_watchpoint_hit_slot(0b1010), Some(1));

        // The kind comes from DR7, so a read watch is not reported as a write.
        let dr7 = x86_encode_watchpoint_dr7(0, 0, 0x1000, BreakpointKind::DataWrite, 4)
            .expect("valid");
        assert!(matches!(
            x86_watchpoint_kind_from_dr7(dr7, 0),
            Some(BreakpointKind::DataWrite)
        ));
        let dr7 = x86_encode_watchpoint_dr7(0, 2, 0x1000, BreakpointKind::DataReadWrite, 8)
            .expect("valid");
        assert!(matches!(
            x86_watchpoint_kind_from_dr7(dr7, 2),
            Some(BreakpointKind::DataReadWrite)
        ));

        // A B bit set for a slot that is NOT enabled is stale hardware state,
        // not a hit — reporting it would fabricate a watchpoint the caller
        // never armed.
        assert!(x86_watchpoint_kind_from_dr7(0, 0).is_none());
        assert!(x86_watchpoint_kind_from_dr7(dr7, 1).is_none(), "slot 1 was never armed");
        assert!(x86_watchpoint_kind_from_dr7(dr7, 9).is_none(), "no such slot");
    }

    /// Both backends must consult DR6 when a trap arrives, and clear it.
    #[test]
    fn every_backend_classifies_watchpoint_hits_and_clears_dr6() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
        ] {
            assert!(
                src.contains("x86_watchpoint_hit_slot"),
                "{name}: nothing consults DR6, so an armed watchpoint fires and is \
                 reported as an ordinary single step"
            );
            let hit = item_body(
                src,
                "fn watchpoint_hit(",
                &["\nfn ", "\nasync fn ", "\npub fn "],
            );
            // DR6 is sticky: leaving it set makes every later step look like
            // the same hit forever.
            assert!(
                hit.contains("Dr6 = 0") || hit.contains("write_debug_reg(pid, 6, 0)"),
                "{name}: DR6 is never cleared, so one hit masquerades as a hit on every \
                 subsequent trap"
            );
        }
    }

    /// The DR7 encoding must match the hardware, not the byte count.
    ///
    /// `LEN` is not the width: 4 bytes encodes as `0b11` and 8 as `0b10`, out
    /// of order on purpose. Writing the count there arms a watchpoint of the
    /// WRONG width that still reads back as armed — it would watch 2 bytes
    /// where 8 were asked for and never report the misses.
    #[test]
    fn hardware_watchpoint_encoding_matches_the_intel_layout() {
        use BreakpointKind::{DataRead, DataReadWrite, DataWrite, Hardware, Software};

        // Slot 0, 4-byte write watch: L0 set, R/W0 = 01, LEN0 = 11.
        let dr7 = x86_encode_watchpoint_dr7(0, 0, 0x1000, DataWrite, 4).expect("valid");
        assert_eq!(dr7 & 1, 1, "L0 must enable the slot");
        assert_eq!((dr7 >> 16) & 0b11, 0b01, "R/W0 must say write");
        assert_eq!((dr7 >> 18) & 0b11, 0b11, "LEN0 for 4 bytes is 0b11, not 4");

        // 8 bytes encodes as 0b10 — the case a byte-count encoding gets wrong.
        let dr7 = x86_encode_watchpoint_dr7(0, 0, 0x1000, DataWrite, 8).expect("valid");
        assert_eq!((dr7 >> 18) & 0b11, 0b10, "LEN0 for 8 bytes is 0b10");

        // Slot 3 lands on its own bits and leaves the others alone.
        let dr7 = x86_encode_watchpoint_dr7(0, 3, 0x2000, DataReadWrite, 2).expect("valid");
        assert_eq!((dr7 >> 6) & 1, 1, "L3 is bit 6");
        assert_eq!((dr7 >> 28) & 0b11, 0b11, "R/W3 read-or-write");
        assert_eq!((dr7 >> 30) & 0b11, 0b01, "LEN3 for 2 bytes");
        assert_eq!(dr7 & 1, 0, "slot 3 must not enable slot 0");

        // Re-arming a slot must not OR into the previous width/kind.
        let first = x86_encode_watchpoint_dr7(0, 1, 0x1000, DataReadWrite, 8).expect("valid");
        let second = x86_encode_watchpoint_dr7(first, 1, 0x1000, DataWrite, 1).expect("valid");
        assert_eq!((second >> 20) & 0b11, 0b01, "R/W1 must be replaced, not merged");
        assert_eq!((second >> 22) & 0b11, 0b00, "LEN1 must be replaced, not merged");

        // Reads are watched via read-or-write: x86 has no read-only encoding,
        // and 0b10 there means I/O, not "read".
        let dr7 = x86_encode_watchpoint_dr7(0, 0, 0x1000, DataRead, 1).expect("valid");
        assert_eq!((dr7 >> 16) & 0b11, 0b11);

        // Execution breakpoints are R/W = 00.
        let dr7 = x86_encode_watchpoint_dr7(0, 0, 0x1000, Hardware, 1).expect("valid");
        assert_eq!((dr7 >> 16) & 0b11, 0b00);

        // Refusals, each of which would otherwise arm a wrong watchpoint that
        // still looks armed.
        assert!(x86_encode_watchpoint_dr7(0, 0, 0x1000, DataWrite, 3).is_err(), "3 bytes");
        assert!(x86_encode_watchpoint_dr7(0, 0, 0x1001, DataWrite, 4).is_err(), "misaligned");
        assert!(x86_encode_watchpoint_dr7(0, 4, 0x1000, DataWrite, 4).is_err(), "no slot 4");
        assert!(x86_encode_watchpoint_dr7(0, 0, 0x1000, Software, 1).is_err(), "not a hw kind");
        // 8 bytes at a 4-byte-aligned address is still misaligned.
        assert!(x86_encode_watchpoint_dr7(0, 0, 0x1004, DataWrite, 8).is_err());
    }

    /// Slot allocation must find a free slot and refuse when there is none.
    #[test]
    fn watchpoint_slots_are_allocated_not_overwritten() {
        assert_eq!(x86_free_watchpoint_slot(0), Some(0));
        // L0 taken → next free is 1.
        assert_eq!(x86_free_watchpoint_slot(0b1), Some(1));
        // L0 and L2 taken → 1 is still free and must be preferred over 3.
        assert_eq!(x86_free_watchpoint_slot(0b1_0001), Some(1));
        // All four enabled: refusing is the only correct answer — picking one
        // anyway would silently disarm somebody else's watchpoint.
        assert_eq!(x86_free_watchpoint_slot(0b0101_0101), None);
    }

    /// A DISABLED breakpoint must not make `run_to_return` skip its trap.
    ///
    /// The guard asked `breakpoints.contains_key(target)` — "is this address
    /// in my map". That is also true for a breakpoint the caller DISABLED,
    /// whose original byte is back in the target: there is no trap there at
    /// all. So `run_to_return` planted nothing, resumed freely, and returned
    /// whatever the process did next as though it were the step result.
    /// `step_over`/`step_out` silently became "continue" — the target runs to
    /// exit and the call reports success, with nothing to tell the caller.
    ///
    /// Found by a workflow against `ios/apple_debugger.rs`; all three native
    /// backends carried the same shape.
    ///
    /// A source guard rather than a live test on purpose: the observable
    /// (whether a trap was planted) exists only WHILE the target runs, and
    /// once it exits the session is retired and the tables are cleared — a
    /// live test written against them reads an empty map either way. That was
    /// tried first and could not fail for the right reason.
    #[test]
    fn run_to_return_arms_a_target_whose_breakpoint_is_only_disabled() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let body = item_body(
                src,
                "async fn run_to_return(",
                &["\n    fn ", "\n    async fn ", "\n    pub async fn "],
            );
            assert!(
                body.contains("disabled.lock()"),
                "{name}: run_to_return decides whether to plant its trap from the tracking \
                 map alone, so a DISABLED breakpoint at the target makes it plant nothing and \
                 the step degrades into a free-running continue"
            );
            // Re-arming somebody else's disabled breakpoint is fine; deleting
            // it is not. The cleanup must put it back, not remove it.
            assert!(
                body.contains("disable_breakpoint(target)"),
                "{name}: run_to_return re-arms a breakpoint the caller had disabled and never \
                 restores that state, so the step silently enables it"
            );
        }
    }

    /// Every backend must refuse a trap the hardware cannot place.
    ///
    /// `host_trap_alignment()` existed from the moment the multi-byte trap was
    /// introduced and NOTHING consulted it — it was referenced only by its own
    /// unit test. On x86 that is invisible, because the alignment is 1. On
    /// AArch64 it means a breakpoint at an unaligned address plants four bytes
    /// across an instruction boundary: the tail of one instruction and the
    /// head of the next are both destroyed, and removal writes the original
    /// four bytes back across the same boundary as though nothing were wrong.
    ///
    /// A rule with no caller is not a rule. This is the guard that gives it
    /// one, and it checks the ORDER too: a refusal issued after the memory has
    /// been patched is not a refusal.
    #[test]
    fn every_backend_refuses_a_misaligned_trap_before_touching_memory() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let body = item_body(
                src,
                "async fn set_breakpoint(",
                &["\n    fn ", "\n    async fn ", "\n    pub async fn "],
            );
            let checks = body.find("host_trap_alignment()").unwrap_or_else(|| {
                panic!(
                    "{name}: set_breakpoint() never consults host_trap_alignment(), so on \
                     aarch64 it will happily plant a 4-byte trap across an instruction \
                     boundary and corrupt two instructions instead of replacing one"
                )
            });
            let writes = body.find("write_memory_raw").unwrap_or_else(|| {
                panic!("{name}: set_breakpoint() no longer writes the trap at all")
            });
            assert!(
                checks < writes,
                "{name}: the alignment check runs AFTER memory is patched — the bytes are \
                 already across the boundary by the time the caller is told no"
            );
        }
    }

    /// No backend may hard-code a one-byte trap any more.
    ///
    /// The tracking map used to be `HashMap<u64, u8>` and every implant site
    /// wrote the literal `[0xCC]`. That shape is why all three backends simply
    /// REFUSED to arm a breakpoint on AArch64: a 4-byte `BRK #0` had nowhere
    /// to record the four bytes it replaced. Widening the map to `Vec<u8>` and
    /// routing every implant through `host_trap_bytes()` is what makes an
    /// Apple Silicon breakpoint expressible at all.
    ///
    /// This guards the shape, not the behaviour: a literal creeping back into
    /// one backend would compile and pass every x86 test, and only break on
    /// the platform none of us can run here.
    #[test]
    fn no_backend_hard_codes_a_single_byte_trap() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            // Cut at the TEST MODULE, not at the first `#[cfg(test)]`.
            //
            // The obvious `split("#[cfg(test)]").next()` is wrong here and was
            // caught being wrong: `linux_debugger.rs` and `macos_debugger.rs`
            // both carry a `#[cfg(test)]` attribute on an item at line ~1149 /
            // ~1566, long BEFORE `set_breakpoint` at ~2047 / ~2100. Splitting
            // there threw away the very code this guard exists to inspect, so
            // it passed on two backends out of three no matter what they
            // contained — verified by reintroducing the literal and watching
            // it stay green.
            let cut = ["mod tests {", "mod live_tests {"]
                .iter()
                .filter_map(|m| src.find(m))
                .min()
                .unwrap_or(src.len());
            let code = &src[..cut];
            assert!(
                code.contains("async fn set_breakpoint("),
                "{name}: the production slice does not even contain set_breakpoint — the cut is \
                 in the wrong place and this guard is inspecting nothing"
            );
            assert!(
                !code.contains("&[0xCC]"),
                "{name}: still writes the literal one-byte x86 trap; on AArch64 that patches \
                 a quarter of an instruction instead of replacing it"
            );
            assert!(
                code.contains("host_trap_bytes()"),
                "{name}: does not take its trap from host_trap_bytes(), so the encoding is \
                 decided in three places instead of one"
            );
            assert!(
                code.contains("HashMap<u64, Vec<u8>>"),
                "{name}: the breakpoint map still stores a single byte, which cannot record \
                 what a 4-byte trap replaced"
            );
        }
    }

    /// The host trap must be the right instruction, and the right width.
    ///
    /// A one-byte `0xCC` on AArch64 does not trap: it overwrites a quarter of
    /// a 4-byte instruction and the target runs corrupted code. So the width
    /// is not decoration — it is the difference between stopping a process
    /// and silently breaking it. This pins both the bytes and the alignment
    /// rule they imply.
    #[test]
    fn the_host_trap_is_the_right_instruction_for_this_architecture() {
        let trap = host_trap_bytes();
        assert!(!trap.is_empty(), "no trap encoding for this architecture");

        if cfg!(any(target_arch = "x86_64", target_arch = "x86")) {
            assert_eq!(trap, [0xCC], "x86 software breakpoints are int3");
            assert_eq!(host_trap_alignment(), 1, "x86 instructions are unaligned");
        } else if cfg!(target_arch = "aarch64") {
            // `BRK #0` = 0xD420_0000, little-endian on the wire.
            assert_eq!(trap, [0x00, 0x00, 0x20, 0xD4], "aarch64 traps are BRK #0");
            assert_eq!(host_trap_alignment(), 4, "aarch64 instructions are 4-byte aligned");
        }

        // Whatever the architecture, the trap must be a whole number of
        // instructions wide: a trap narrower than the alignment cannot
        // replace an instruction, it can only damage one.
        let width = u64::try_from(trap.len()).expect("trap width fits");
        assert_eq!(
            width % host_trap_alignment(),
            0,
            "a {width}-byte trap cannot sit in {}-byte instruction slots",
            host_trap_alignment()
        );
    }

    /// The trap this crate implants must be the one its own tables describe.
    ///
    /// `host_trap_bytes` now DERIVES the AArch64 encoding instead of spelling
    /// it out, so a test comparing it against the same encoder would prove
    /// nothing. What is still worth pinning is that the value the backends
    /// actually write agrees with the two tables that describe implanting
    /// (`trap_implant`, and through it `arch_breakpoint`) — three modules, one
    /// answer.
    ///
    /// Runs on every host: the encoder and both tables are pure arithmetic.
    #[test]
    fn the_implanted_trap_agrees_with_the_tables_that_describe_it() {
        let native = crate::trap_implant::host_arch()
            .expect("this crate models the architecture it is built for");
        let spec = crate::trap_implant::for_arch(native)
            .expect("a modelled architecture has a trap spec");
        assert_eq!(
            host_trap_bytes(),
            spec.patch(),
            "the bytes the backends implant are not the ones trap_implant describes"
        );
        assert_eq!(
            host_trap_alignment(),
            spec.align(),
            "the alignment the implant path enforces disagrees with the trap spec"
        );
        assert_eq!(
            crate::ios::arm64::INSTRUCTION_SIZE,
            4,
            "host_trap_alignment assumes 4-byte AArch64 instructions"
        );
    }

    /// The architecture check must come BEFORE any byte is written.
    ///
    /// A software breakpoint here is the x86 `int3`, a single `0xCC`. On
    /// AArch64 that is not a trap: it overwrites one byte of a 4-byte
    /// instruction and the target runs corrupted code instead of stopping.
    /// All three backends refuse it — but refusing is only worth anything if
    /// nothing has been written yet. Reordering the check after the original
    /// byte is read and patched would leave an `0xCC` in the process of every
    /// Apple Silicon Mac, silently, with the call still returning an error.
    ///
    /// Today the order is correct in all three; nothing pinned it. macOS is
    /// the one that matters most: it is the only backend that can actually be
    /// built for arm64 (since iteration 382), and the only one no live test
    /// can reach.
    #[test]
    fn the_architecture_check_precedes_the_implant_in_every_backend() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let body = item_body(
                src,
                "async fn set_breakpoint(",
                &["\n    fn ", "\n    async fn ", "\n    pub async fn "],
            );
            // Anchored on the ALIGNMENT gate since 569. The blanket
            // architecture refusal this used to find was removed there, but the
            // property is untouched and still worth enforcing: a refusal that
            // has already patched memory is not a refusal, so whatever
            // architecture-dependent gate remains must precede the write.
            let guard = body.find("host_trap_alignment").unwrap_or_else(|| {
                panic!(
                    "{name}: set_breakpoint() no longer checks the host architecture before \
                     planting an x86 int3"
                )
            });
            let write = body.find("write_memory_raw").unwrap_or_else(|| {
                panic!("{name}: set_breakpoint() no longer writes the trap byte at all")
            });
            assert!(
                guard < write,
                "{name}: the architecture check runs AFTER the byte is written — on arm64 the \
                 `0xCC` lands in the target and corrupts a 4-byte instruction, and the caller \
                 is handed an error that says it did not happen"
            );
        }
    }

    /// No backend may define the same method twice.
    ///
    /// Rust rejects duplicate associated items with E0592 — but only when a
    /// compiler actually looks at the file, and NOTHING in this environment
    /// compiles `macos_debugger.rs`: it sits behind `#[cfg(target_os = "macos")]`
    /// and there is no macOS host here. A duplicate `read_memory_raw` sat in it
    /// undetected, pasted in while copying a block of methods across backends,
    /// and would have been the very first error that file ever produced.
    ///
    /// For the other two backends this guard is redundant, since they are
    /// compiled constantly — which is exactly the point: it costs nothing
    /// there and is the only compiler macOS has. Every cross-backend copy is a
    /// fresh chance to repeat this.
    #[test]
    fn no_backend_defines_the_same_method_twice() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            // Method definitions only: a `fn` indented exactly four spaces, and
            // only before `#[cfg(test)]`, where helper names legitimately repeat
            // across separate test modules.
            let code = src.split("#[cfg(test)]").next().unwrap_or(src);
            // Counted PER `impl` BLOCK, not per file: the same method name may
            // legitimately appear in an inherent `impl` and in a trait `impl`
            // (`set_symbol_resolver` does exactly that on Windows). Only a
            // repeat inside ONE block is the compile error.
            fn flush<'a>(seen: &mut HashMap<&'a str, usize>, dupes: &mut Vec<&'a str>) {
                for (f, n) in seen.iter() {
                    if *n > 1 {
                        dupes.push(f);
                    }
                }
                seen.clear();
            }
            let mut seen: HashMap<&str, usize> = HashMap::new();
            let mut dupes: Vec<&str> = Vec::new();
            for line in code.lines() {
                if line.starts_with("impl ") || line.starts_with("#[async_trait") {
                    flush(&mut seen, &mut dupes);
                    continue;
                }
                let Some(rest) = line.strip_prefix("    ") else { continue };
                if rest.starts_with(' ') {
                    continue; // deeper indentation: a closure or a nested item
                }
                let rest = rest.strip_prefix("pub ").unwrap_or(rest);
                let rest = rest.strip_prefix("async ").unwrap_or(rest);
                let Some(sig) = rest.strip_prefix("fn ") else { continue };
                let Some(fname) = sig.split('(').next() else { continue };
                *seen.entry(fname.trim()).or_insert(0) += 1;
            }
            flush(&mut seen, &mut dupes);
            dupes.sort_unstable();
            assert!(
                dupes.is_empty(),
                "{name}: {dupes:?} defined twice in the SAME impl block — a hard compile error \
                 (E0592) the moment anything compiles this file"
            );
        }
    }

    /// `set_register` must refuse exactly what `get_register` refuses.
    ///
    /// `RegisterSet::set` accepts any name into its map, and the backends
    /// apply only the names they recognise when writing the thread context,
    /// so an unknown name was silently dropped and reported as success while
    /// reading the same name answered "unknown register". Checked on all
    /// three: the method is shared logic, not per-platform.
    #[test]
    fn every_backend_refuses_to_write_a_register_it_does_not_know() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let body = item_body(
                src,
                "async fn set_register(&self, tid: ThreadId, name: &str, value: u64)",
                &["\n    fn ", "\n    async fn ", "\n    pub async fn "],
            );
            assert!(
                body.contains("unknown register"),
                "{name}: set_register() accepts a name the backend cannot write, drops it, \
                 and reports success — while get_register() calls the same name unknown"
            );
            // The rejection must come BEFORE the write, or the register set is
            // mutated and pushed to the target anyway.
            let rejects = body.find("unknown register").unwrap_or(usize::MAX);
            let writes = body.find("regs.set(name, value)").unwrap_or(usize::MAX);
            assert!(
                rejects < writes,
                "{name}: set_register() validates AFTER mutating the register set"
            );
        }
    }

    /// A watchpoint hit must be counted, and must NOT rewind the PC.
    ///
    /// Two invariants in one place, because they pull in opposite directions.
    /// Counting: `breakpoints()` publishes `hit_count`, so an uncounted
    /// watchpoint reports zero hits while stopping the program repeatedly.
    /// Not rewinding: for a watchpoint the event address is the WATCHED DATA
    /// address, not the PC — the obvious "simplification" of dropping the
    /// early return would write a data address into the PC and send the
    /// target off to execute its own variables.
    #[test]
    fn every_backend_counts_watchpoint_hits_without_rewinding_the_pc() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let body = item_body(
                src,
                // Anchored WITHOUT the trailing brace: the signature gained a
                // return type in iteration 540 and this anchor broke, failing
                // two guards for a reason unrelated to what they check.
                "async fn rewind_past_own_breakpoint(&self, event: &DebugEvent)",
                &["\n    fn ", "\n    async fn ", "\n    pub async fn "],
            );
            assert!(
                body.contains("hw_watchpoints"),
                "{name}: a hardware watchpoint hit is never counted, so it reports zero hits \
                 forever while stopping the program"
            );
            // The counting must sit BEFORE the rewind and return, never share
            // its path.
            let counts = body.find("hw_watchpoints").unwrap_or(usize::MAX);
            let rewinds = body.find("regs.pc = address").unwrap_or(usize::MAX);
            assert!(
                counts < rewinds,
                "{name}: the watchpoint path reaches the PC rewind, which would write the \
                 watched DATA address into the program counter"
            );
        }
    }

    /// A rewind that FAILED must not be reported as a stop that succeeded.
    ///
    /// The CPU leaves the PC one byte past an executed `int3`, so after our own
    /// breakpoint fires the PC must be pulled back to the breakpoint address
    /// before the target can be resumed. If that write fails and the failure is
    /// discarded, the caller still receives `Ok(Breakpoint { address })` — a
    /// stop event that is TRUE about what happened and FALSE about the state it
    /// left behind. Resuming from there restarts the target one byte into an
    /// instruction, which is not "a wrong value" but arbitrary execution.
    ///
    /// This is the third time in this crate that a comment justifying an action
    /// was used to justify discarding its outcome (iterations 536/537/538), and
    /// the reason the pattern is now checked on the source of all three
    /// backends: it is the only lens that also covers macOS, where nothing is
    /// ever executed.
    #[test]
    fn every_backend_reports_a_failed_breakpoint_rewind_instead_of_discarding_it() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let body = item_body(
                src,
                "async fn rewind_past_own_breakpoint(&self, event: &DebugEvent)",
                &["\n    fn ", "\n    async fn ", "\n    pub async fn "],
            );
            assert!(
                !body.contains("let _ = self.set_registers"),
                "{name}: rewind_past_own_breakpoint discards the result of set_registers, so a \
                 failed rewind leaves the PC one byte inside an instruction while the event \
                 still claims a clean breakpoint stop"
            );
            // Reporting it requires a channel to report it THROUGH: a function
            // returning `()` has nowhere to put the failure, so the signature
            // is part of the invariant, not a separate style preference.
            assert!(
                src.contains(
                    "async fn rewind_past_own_breakpoint(&self, event: &DebugEvent) -> Result<(), DebugError>"
                ),
                "{name}: rewind_past_own_breakpoint returns (), so it has no way to tell its \
                 caller the target is not resumable"
            );
        }
    }

    /// A backend must save exactly as many bytes as its trap overwrites.
    ///
    /// All three read **one** byte as the "original" and then write
    /// `host_trap_bytes()`, which is one byte on x86 and **four** on AArch64.
    /// Removing the breakpoint restores what was saved, so on ARM64 that
    /// restores one byte and leaves **three bytes of `BRK`** behind — the
    /// instruction stream is corrupted permanently, in a process the user asked
    /// only to observe.
    ///
    /// `arch_breakpoint::trap_len` exists for exactly this, and its own doc
    /// names the failure: *"the single most damaging thing a naive port does is
    /// save one byte on ARM64"*. The saving code was the one place that did not
    /// ask.
    ///
    /// This is also why `X86_TRAP_BYTE_IS_VALID_HERE` must stay for now. That
    /// refusal looks stale — the implant derives its bytes from the host arch,
    /// and `macos_debugger` is no longer x86-only at compile time (`thread_pc`
    /// is cfg'd per architecture). It is not stale: it is the last line of
    /// defence in front of THIS defect. Removing it before this is fixed would
    /// be the "fix that believes more was fixed than was" the guard on that
    /// constant explicitly warns about.
    ///
    /// On x86 the derived length is 1, so nothing changes there — which is why
    /// this can be fixed on a host that cannot run the architecture it matters
    /// on.
    #[test]
    fn every_backend_saves_as_many_bytes_as_its_trap_overwrites() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let body = item_body(
                src,
                "async fn set_breakpoint(",
                &["\n    fn ", "\n    async fn ", "\n    pub async fn "],
            );
            assert!(
                body.contains("host_trap_bytes()"),
                "guard is misanchored: `{name}`'s set_breakpoint no longer plants \
                 `host_trap_bytes()`"
            );
            assert!(
                !body.contains("read_memory(addr, 1)"),
                "{name}: set_breakpoint saves ONE byte and then writes `host_trap_bytes()`, \
                 which is four on AArch64. Removing the breakpoint would restore one byte and \
                 leave three bytes of BRK in the instruction stream — permanent corruption of \
                 a process the caller asked only to inspect"
            );
        }
    }

    /// The macOS backend must recognise its own breakpoints on Apple Silicon.
    ///
    /// Two places decided "is this thread sitting on one of our traps?" the x86
    /// way: take the reported PC, subtract **one**, and look for `0xCC`. That is
    /// correct on x86, where `int3` is a single byte and the CPU reports the
    /// address *after* it. On AArch64 it is wrong twice over — the trap is a
    /// four-byte `BRK #0`, and the PC reported is the address *of* it, not after
    /// it. So the test never matched:
    ///
    ///   * `wait_for_stop` never classified a stop as `StopReason::Breakpoint`,
    ///     and every software breakpoint hit arrived as something else;
    ///   * `identify_stopped_thread` never found the trapping thread and always
    ///     fell back to "the first thread I can name".
    ///
    /// Both silently, and on the architecture macOS actually runs on. Found by
    /// an adversarial reviewer during the Apple audit of 2026-08-15, who noted
    /// that the fix shipped for the second site "is substantially ineffective on
    /// arm64, and this is not said".
    ///
    /// `arch_breakpoint` already holds both facts — `trap_bytes` and
    /// `pc_after_trap`, whose doc is exactly "program counter of the trapping
    /// instruction, given the PC reported on trap". The rule this guard encodes
    /// is that the backend must ASK, not assume.
    #[test]
    fn the_macos_backend_finds_its_traps_by_architecture_not_by_assuming_x86() {
        let code = code_only(include_str!("macos_debugger.rs"));
        assert!(
            !code.contains("byte_is_int3("),
            "macos_debugger.rs still asks `byte_is_int3`: a name that can only be true on x86, \
             used to decide whether a thread is sitting on a breakpoint. On arm64 the trap is a \
             four-byte BRK and the answer is always no"
        );
        assert!(
            code.contains("pc_after_trap("),
            "macos_debugger.rs no longer routes the reported PC through \
             `arch_breakpoint::pc_after_trap`, so it is back to guessing where the trap is"
        );
        assert!(
            code.contains("trap_bytes("),
            "macos_debugger.rs no longer compares against `arch_breakpoint::trap_bytes`, so it \
             is back to a hard-coded encoding that is right on one architecture"
        );
    }

    /// The PAC mask must be published BEFORE anything that can bail out.
    ///
    /// Iteration 591 moved the `NT_ARM_PAC_MASK` read onto the tracer thread,
    /// because 573 had called ptrace from an async body where it always
    /// answered ESRCH. That was the right diagnosis and the fix STILL never
    /// ran: it was placed at the END of `merge_debug_state`, and that function
    /// opens with
    ///
    /// ```text
    /// let Ok(watch) = read_arm_hw_regset(pid, NT_ARM_HW_WATCH) else { return };
    /// ```
    ///
    /// Sixty-seven lines earlier. On `ubuntu-24.04-arm` the debug-register
    /// tests are red, which is evidence that read does fail there — so the mask
    /// is never published, the unwinder never strips, and
    /// `backtrace_unwinds_past_the_first_frame_via_dwarf_cfi` stayed red
    /// through both 573 and 591.
    ///
    /// Two fixes in a row that were present in the source and dead on the
    /// machine that mattered, by two different mechanisms: the wrong thread,
    /// then an unrelated early return. The addresses confirm the target was
    /// always right — `0x56aabdc2615c0c` strips to `0xaabdc2615c0c`, which is
    /// exactly where ARM64 Linux maps a PIE executable.
    ///
    /// Pointer authentication has NOTHING to do with the watchpoint register
    /// file. Coupling them was the defect; the guard keeps them independent.
    #[test]
    fn the_pac_mask_is_read_before_anything_that_can_return_early() {
        let src = include_str!("linux_debugger.rs");
        let start = src
            .find("fn merge_debug_state(")
            .expect("merge_debug_state must exist for this guard to mean anything");
        let body = &src[start..];
        let pac = body
            .find("PAC_INSN_MASK_KEY, mask")
            .expect("the PAC mask must be published somewhere in this function");
        let bail = body.find("else { return }").unwrap_or(usize::MAX);
        assert!(
            pac < bail,
            "linux: the PAC mask is published AFTER an early return that fires when an              unrelated regset is unavailable, so on a host where that read fails the mask is              never set and the unwinder never strips. Read it first: pointer authentication              does not depend on the watchpoint registers"
        );
    }

    /// `resolve_symbol` refuses while the answer is already mapped.
    ///
    /// From the live audit: asking for a symbol before `debug.load_symbols`
    /// gives
    ///
    /// ```text
    /// no symbols loaded; call debug.load_symbols first
    /// ```
    ///
    /// The message is honest about what it did, and the tool is useless cold
    /// for a class of names that needs no PDB at all. `RtlUserThreadStart` —
    /// the symbol that appears in this backend's own backtraces — lives in
    /// `ntdll.dll`'s EXPORT table, which is mapped into every Windows process
    /// and readable without any symbol server.
    ///
    /// Nothing new has to be written to use it. `rustre-mcp-tools` already
    /// depends on `rustre-loader-pe`, that crate already parses export
    /// directories and exposes `export_by_name`, `debug.modules` already
    /// reports every loaded module with its path, and `symbol_resolver.rs`
    /// already names "PE exports" as a legitimate `SymbolTable` source in its
    /// own documentation. Four pieces present and not joined.
    ///
    /// A PDB still answers more — statics, locals, line numbers, anything not
    /// exported — so this is a FALLBACK and not a replacement. The refusal was
    /// right that it had no symbols; it was wrong that there was nothing to
    /// say.
    #[test]
    fn resolve_symbol_falls_back_to_the_exports_already_mapped() {
        let src = include_str!("../../rustre-mcp-tools/src/tools/debug.rs");
        assert!(
            src.contains("resolve_via_module_exports"),
            "mcp: `resolve_symbol` refuses cold while every loaded module's export table is on              disk and rustre-loader-pe is already a dependency that parses it. A name like              RtlUserThreadStart needs no PDB, and this backend prints it in its own backtraces"
        );
    }

    /// One concept, one name — and where two names exist, both must work.
    ///
    /// From a live audit of 16 debug tools: three failed on the first attempt
    /// purely on parameter naming, costing a round-trip each.
    ///
    /// Measured across `tools/debug.rs`: the ADDRESS is consistent — `addr`,
    /// twelve times, no exceptions. The QUANTITY is not: `size` twice, `len`
    /// once, `n` once, for the same concept in adjacent tools. `read_memory`
    /// wants `len` while `set_watchpoint` beside it wants `size`, and nothing
    /// tells a caller which is which except failing.
    ///
    /// Renaming them would break every existing caller, so the fix is to ACCEPT
    /// the synonyms. A tool that understands what was meant and answers is
    /// better than one that is right about its schema and useless — and this
    /// costs a caller nothing, since a request that was already correct takes
    /// the same path.
    ///
    /// Guarded here rather than in `rustre-mcp-tools` because that crate cannot
    /// currently be built in this tree — two unrelated crates are mid-edit by
    /// other actors — and the property is a source fact either way.
    #[test]
    fn the_mcp_accepts_the_synonyms_its_own_tools_disagree_on() {
        let src = include_str!("../../rustre-mcp-tools/src/tools/debug.rs");
        assert!(
            src.contains("fn u64_arg_aliased("),
            "mcp: `len`, `size` and `n` all name the same quantity across adjacent debug tools,              and a caller who picks the wrong one is simply refused. Accept the synonyms: the              schema stays as documented, and a request that guessed the neighbour's spelling              is answered instead of bounced"
        );
    }

    /// A `LibraryLoad` reaching a HUMAN must name the library.
    ///
    /// From a live audit of the Windows backend on `notepad.exe`:
    /// `LibraryLoad { path: "", base: Address(140736485130240) }`.
    ///
    /// The first reading of this was wrong and worth recording. The backend
    /// looks like it never resolves the path, and it does — in
    /// `continue_execution`, after the event is acknowledged, gated on whether
    /// any pending breakpoint is waiting for a module. The comment there states
    /// the trade deliberately: "the path stays empty rather than being paid for
    /// by every caller who did not ask for it", because filling it costs a
    /// whole `modules()` enumeration on every DLL load.
    ///
    /// Resolving it INSIDE `classify_event` — which was the obvious fix and the
    /// one I tried — is forbidden by
    /// `classify_event_does_not_query_the_traced_process`, a guard established
    /// BY BISECTION: a psapi query in that window broke hardware watchpoint
    /// hits outright, `DR6` no longer reading as set. It would have traded a
    /// cosmetic empty string for a broken watchpoint engine.
    ///
    /// So the gap is real but it is not in the engine: it is at the surface a
    /// person reads. `debug.continue` hands a user a library with no name, and
    /// there the `modules()` call is paid once, by someone who is looking.
    #[test]
    fn the_mcp_names_a_loaded_library() {
        let src = include_str!("../../rustre-mcp-tools/src/tools/debug.rs");
        assert!(
            src.contains("resolve_library_path"),
            "mcp: a LibraryLoad stop is published with whatever path the backend happened to              fill — empty unless a pending breakpoint was waiting — so a user is told a library              loaded and never which one. The backend is right not to pay for it in the hot              loop; the surface a human reads is where it should be paid"
        );
    }

    /// A trap left in the target on `Drop` must not be left in SILENCE.
    ///
    /// Every backend's `Drop` restores the original bytes before letting go,
    /// which is right. Each does it like this:
    ///
    /// ```text
    /// let _ = self.send(Command::WriteMemory(addr, original));
    /// ```
    ///
    /// `Drop` cannot return an error, so discarding the `Result` is the only
    /// thing to do with the VALUE. It is not the only thing to do with the
    /// FACT. If that write fails the target keeps a trap in its code — `0xCC`
    /// on x86, a `BRK` on AArch64 — and will die on it later, in a process the
    /// debugger has already let go of, with nothing anywhere connecting the two.
    ///
    /// This is the shape 568 dealt with in the resume paths and the same
    /// resolution applies: a path that may not FAIL must still not stay quiet.
    /// There the fact was recorded in a field; here the object is being
    /// destroyed, so the only place left is the log — and the crate already
    /// depends on `tracing`.
    ///
    /// Not hypothetical: the write goes through a channel to the ptrace thread,
    /// which during teardown may already be gone, and a target whose memory has
    /// been unmapped refuses it outright.
    #[test]
    fn a_drop_that_cannot_restore_a_trap_says_so() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            // Searched over the WHOLE file rather than an extracted `impl Drop`
            // body. The first spelling extracted an `impl Drop for` body with a
            // newline-brace-newline end marker and the helper REFUSED it — "no
            // end marker matched
            // and 352536 characters remain" — because the working copy is CRLF
            // and the delimiter was not. The helper was right to refuse: a body
            // that silently ran to end-of-file would have contained every
            // needle this guard looks for and passed no matter what.
            //
            // The needle is specific enough not to need the scope: restoring an
            // original byte through the command channel happens in exactly one
            // place per backend.
            assert!(
                !src.contains("let _ = self.send(Command::WriteMemory"),
                "{name}: `Drop` discards the outcome of restoring an implanted trap. The value                  has nowhere to go — `Drop` cannot fail — but the FACT does: a target left                  with a trap in its code will die on it later with nothing to connect the two"
            );
        }
    }

    /// A capability gated by architecture must be DECLARED that way.
    ///
    /// `windows_debugger.rs` refuses hardware watchpoints off x86:
    ///
    /// ```text
    /// if !cfg!(any(target_arch = "x86_64", target_arch = "x86")) {
    ///     return Err(Unsupported("hardware watchpoints on this backend
    ///                            program the x86 debug registers, ..."))
    /// }
    /// ```
    ///
    /// and `backend_capabilities()` declares `hardware_watchpoints: true` for
    /// Windows with no gate at all. On Windows-on-ARM the API therefore
    /// promises a capability the backend refuses in the next breath.
    ///
    /// Same class as the macOS `fault_address` corrected in 595, and I put both
    /// there in 577: a capability list is only worth having if a caller can act
    /// on it, and one that disagrees with the backend on a whole architecture
    /// is worse than none. `supported: false` carries a reason a caller can
    /// read; `supported: true` where the answer is `Unsupported` sends them to
    /// a call that cannot work.
    ///
    /// The declaration is per-target — `cfg!` reads the architecture this
    /// binary is compiled for, exactly as the backend does — so the two cannot
    /// drift by construction rather than by remembering.
    #[test]
    fn a_capability_is_declared_with_the_same_gate_the_backend_enforces() {
        let caps = crate::backend_capabilities();
        let hw = caps
            .iter()
            .find(|c| c.name == "hardware_watchpoints")
            .expect("every backend publishes this capability");

        // What the backend will ACTUALLY do on this host, spelled from the same
        // condition `set_watchpoint_sized` uses.
        #[cfg(target_os = "windows")]
        let backend_can = cfg!(any(target_arch = "x86_64", target_arch = "x86"));
        // Linux translates through NT_ARM_HW_WATCH (570) and macOS through
        // ARM_DEBUG_STATE64, so both answer on either architecture.
        #[cfg(not(target_os = "windows"))]
        let backend_can = true;

        assert_eq!(
            hw.supported, backend_can,
            "the capability list says hardware_watchpoints = {}, and this backend will actually              answer {backend_can} on this architecture. A caller cannot act on a list that              disagrees with the code it describes",
            hw.supported
        );
        if !hw.supported {
            assert!(
                !hw.because.is_empty(),
                "an unsupported capability must carry the reason, or the caller learns only                  that something is missing and not what to do instead"
            );
        }
    }

    /// macOS can report the faulting address, and said it could not.
    ///
    /// Iteration 577 published `fault_address: supported: false` for macOS with
    /// the reason *"would come from __far via thread_get_state, which mach2
    /// does not expose"*. The reason is TRUE and the conclusion does not follow:
    /// this backend already hand-declares what `mach2` omits. `ArmDebugState64`
    /// is written out by hand precisely because the crate lacks it, with a
    /// compile-time size assert to catch drift, and `THREAD_STATE_FLAVOR` picks
    /// the right flavour per architecture.
    ///
    /// So the capability was reachable by the file's own established pattern,
    /// and I declared it absent. That is worse than an unimplemented feature:
    /// `backend_capabilities()` exists so a caller can trust what it says, and
    /// a false "unsupported" sends them looking for a workaround they do not
    /// need.
    ///
    /// The flavours are `x86_EXCEPTION_STATE64` (5) with `faultvaddr`, and
    /// `ARM_EXCEPTION_STATE64` (7) with `far` — sixteen bytes each, which is
    /// four `natural_t`, the unit Mach counts in.
    #[test]
    fn macos_reads_the_faulting_address_it_can_actually_get() {
        let src = include_str!("macos_debugger.rs");
        assert!(
            src.contains("EXCEPTION_STATE_FLAVOR"),
            "macos: the backend never asks for the exception state, so a SIGSEGV is reported              with no address at all — while the file already hand-declares ArmDebugState64 for              exactly the reason this capability was declared unreachable"
        );
        assert!(
            src.contains("fn faulting_address("),
            "macos: nothing turns the exception state into an address, so reaching the flavour              would not by itself answer the caller's question"
        );
    }

    /// `ptrace` may only be called from the thread that attached.
    ///
    /// This file already states the rule for `PTRACE_POKEUSER` — "only valid
    /// from the tracer thread" — and iteration 591 found it broken anyway, in
    /// code I had written eighteen rounds earlier. 573 read `NT_ARM_PAC_MASK`
    /// by calling `libc::ptrace` straight from the async `backtrace`. From any
    /// other thread ptrace answers ESRCH, so the helper returned `None` every
    /// time, no address was ever stripped, and the ARM test stayed red while
    /// the fix looked present in the source.
    ///
    /// That is the worst shape a defect can take here: it compiles, it runs, it
    /// is silently a no-op, and ONLY on the architecture nobody can execute
    /// locally. No compiler and no x86 test can catch it — which is why it is
    /// worth a source guard rather than a comment.
    ///
    /// The helpers below are the ones that issue `ptrace` directly. Each is
    /// correct when called from `ptrace_loop`, `do_launch` or `do_attach`, and
    /// wrong from anywhere `async` — because the async surface runs on the
    /// caller's executor thread, not on the tracer.
    #[test]
    fn no_async_body_calls_ptrace_behind_the_command_channels_back() {
        // COMMENTS STRIPPED FIRST, and this guard needed it on its own first
        // run: it flagged `run_to_return` for calling `byte_at()`, and the only
        // occurrence there is inside a doc comment reading "This used to be
        // spelled inline as `byte_at(pid, rip - 1)`". A guard anchored to a
        // string that can appear in prose reports a defect that is not there —
        // the mirror of the vacuous-green version of the same mistake, and the
        // reason this crate now insists on anchoring to something the compiler
        // must see.
        let raw = include_str!("linux_debugger.rs");
        let src: String = raw
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("
");
        let src = src.as_str();
        // Helpers that issue ptrace themselves. Named explicitly: deriving the
        // list by scanning for `libc::ptrace` would silently shrink if one were
        // renamed, and a guard that quietly checks less is the failure mode
        // this crate has already been bitten by twice.
        const TRACER_ONLY: &[&str] = &[
            "byte_at(",
            "trap_at_reported_pc(",
            "read_debug_reg(",
            "write_debug_reg(",
            "signal_fault_address(",
            "read_regs(",
            "write_regs(",
            "read_arm_hw_regset(",
            "write_arm_hw_regset(",
            "pac_insn_mask(",
        ];
        // Every `async fn` body in the file, cut at the next item at the same
        // indentation. Crude on purpose: it over-approximates the body, so it
        // can only ever report MORE than the truth, never less.
        for (i, chunk) in src.split("
    async fn ").enumerate().skip(1) {
            let body = chunk.split("
    }
").next().unwrap_or(chunk);
            let name = body.split('(').next().unwrap_or("?");
            for helper in TRACER_ONLY {
                assert!(
                    !body.contains(helper),
                    "linux: async fn `{name}` (body #{i}) calls `{helper})` directly. That                      helper issues ptrace, which is only valid from the tracer thread; from an                      async body it answers ESRCH and the call becomes a silent no-op. Route it                      through the command channel, as `merge_debug_state` does for the PAC mask."
                );
            }
        }
    }

    /// A tool must not advertise a timeout it never reads.
    ///
    /// `debug.continue_until` declares in its JSON schema:
    ///
    /// ```text
    /// "timeout_ms": { "description": "Wall-clock timeout in milliseconds (default 30000)" }
    /// ```
    ///
    /// and never reads it. Measured: `timeout_ms` appears twice in `debug.rs`,
    /// both times inside a schema, and zero times in code. The loop resumes the
    /// target with no deadline at all.
    ///
    /// So a caller passes `timeout_ms: 5000`, the parameter is ACCEPTED — it is
    /// in the schema, so nothing rejects it — and the call still blocks
    /// forever. A promise that cannot fail loudly, which is this repo's most
    /// frequent defect: the same file already records `download_http` claiming
    /// to follow HTTP redirects while sending every 3xx into the error branch.
    ///
    /// It is also iteration 585's defect moved to the user-facing surface. An
    /// unbounded wait for a stop that may never come cost 87 minutes of CI and
    /// two lost measurements there; here it hangs an operator's session, with
    /// no way to interrupt it.
    #[test]
    fn a_declared_timeout_is_a_timeout_that_is_read() {
        let src = include_str!("../../rustre-mcp-tools/src/tools/debug.rs");
        let declared = src.matches("\"timeout_ms\"").count();
        // Anchored on the CALL, not on a substring of the name. The first
        // spelling of this counted `timeout_ms")` and stayed red after the fix,
        // because the real read is `opt_u64(&args, "timeout_ms", 30_000)` —
        // the quote is followed by a comma, not a paren. Third time this
        // session that a string-anchored assertion has meant something other
        // than intended; `opt_u64(` must exist for the file to compile.
        let read = src.matches("opt_u64(&args, \"timeout_ms\"").count();
        assert!(
            read > 0,
            "`timeout_ms` is declared in {declared} schema(s) and read {read} times: the tool \
             accepts the parameter and ignores it, so a bounded call blocks forever anyway"
        );
    }

    /// "The address" is two different things, and the doc said one.
    ///
    /// `StopReason::address()` is documented as *"the address associated with
    /// this stop event"* — a phrase that promises one kind of value. It returns
    /// two:
    ///
    /// | variante | kind |
    /// |---|---|
    /// | `Breakpoint`, `SingleStep` | the PC: a CODE address |
    /// | `LibraryLoad` | a module base: code region |
    /// | `AccessViolation`, `Signal` | the DATUM the target touched |
    ///
    /// A caller who believes the sentence and disassembles from it gets the
    /// instruction stream for a breakpoint and a data pointer for a segfault.
    /// Nothing errors; the disassembly is simply garbage.
    ///
    /// Iteration 581 sharpened this rather than causing it — `Signal` already
    /// returned `si_addr` — but by making `AccessViolation` report the datum it
    /// removed the last variant where the two kinds happened to coincide.
    ///
    /// **Stated honestly: no caller misuses it today.** The only consumers in
    /// this workspace are tests. This is a latent trap in a public API, closed
    /// preventively — but the FALSE SENTENCE is a present defect, and this
    /// session has now hit that family six times.
    #[test]
    fn a_code_address_is_never_confused_with_a_touched_datum() {
        use crate::{Address, StopReason};

        let bp = StopReason::Breakpoint {
            address: Address(0x1000),
            bp: crate::Breakpoint::new_software(Address(0x1000)),
        };
        let av = StopReason::AccessViolation { address: Address(0xDEAD), is_write: true };
        let sig = StopReason::Signal {
            signum: 11,
            signame: "SIGSEGV".to_string(),
            address: Some(Address(0xBEEF)),
        };

        assert_eq!(
            bp.code_address(),
            Some(Address(0x1000)),
            "a breakpoint's address IS a code location"
        );
        assert!(
            av.code_address().is_none(),
            "an access violation's address is the DATUM touched, not code — handing it to a \
             disassembler yields garbage, and the caller cannot tell"
        );
        assert!(
            sig.code_address().is_none(),
            "si_addr is the datum, not the instruction"
        );
    }

    /// A signal number means different things on different kernels.
    ///
    /// MY OWN DEFECT, introduced one iteration earlier. `access_fault` matched
    /// `11 | 10 | 7` on every platform, reasoning that `libc::SIGBUS` differs
    /// between targets. It does — and accepting both spellings is how you get
    /// it wrong on BOTH platforms instead of one:
    ///
    /// | number | Linux | macOS |
    /// |---|---|---|
    /// | 7  | `SIGBUS` | **`SIGEMT`** |
    /// | 10 | **`SIGUSR1`** | `SIGBUS` |
    /// | 11 | `SIGSEGV` | `SIGSEGV` |
    ///
    /// So a `SIGUSR1` — a signal programs use for their own purposes, and which
    /// this crate's own comments cite as an ordinary occurrence — was reported
    /// to every caller as a memory fault on Linux, and `SIGEMT` likewise on
    /// macOS. A false positive in the exact predicate written to stop callers
    /// guessing.
    ///
    /// The union of two platforms' constants is not a portable constant. The
    /// numbers must be chosen per target, which is what `cfg!` is for.
    #[test]
    fn a_signal_number_is_read_against_the_right_kernel() {
        use crate::{Address, StopReason};

        let sig = |n: i32| StopReason::Signal {
            signum: n,
            signame: format!("SIG{n}"),
            address: Some(Address(0x2000)),
        };

        assert!(sig(11).access_fault().is_some(), "SIGSEGV is 11 on both");

        #[cfg(target_os = "linux")]
        {
            assert!(sig(7).access_fault().is_some(), "linux: 7 is SIGBUS");
            assert!(
                sig(10).access_fault().is_none(),
                "linux: 10 is SIGUSR1, a signal programs use on purpose — reporting it as a \
                 memory fault is a false positive in the predicate that exists to prevent \
                 guessing"
            );
        }
        #[cfg(target_os = "macos")]
        {
            assert!(sig(10).access_fault().is_some(), "macos: 10 is SIGBUS");
            assert!(sig(7).access_fault().is_none(), "macos: 7 is SIGEMT, not a memory fault");
        }
    }

    /// One question — "did it fault, and where?" — must have one portable answer.
    ///
    /// The same crash arrives in three shapes, measured:
    ///
    /// | backend | shape |
    /// |---|---|
    /// | Windows | `AccessViolation { address, is_write }` |
    /// | Linux   | `Signal { SIGSEGV, address: Some(si_addr) }` |
    /// | macOS   | `Signal { SIGSEGV, address: None }` |
    ///
    /// `AccessViolation` is CONSTRUCTED only by the Windows backend — in the
    /// Linux one the name appears solely inside comments. So a caller writing
    /// the obvious `match ev.reason { StopReason::AccessViolation { .. } => …
    /// }` handles crashes on Windows and silently never fires on the other two,
    /// where the crash did happen. Nothing errors; the arm is simply dead.
    ///
    /// The fix must not be to make Linux emit `AccessViolation`: `is_write` is
    /// not derivable from `si_addr`, and inventing it would be exactly the
    /// fabricated answer this crate refuses. Nor to drop the Windows variant,
    /// which carries a fact the others genuinely lack.
    ///
    /// So the answer is a predicate over what each backend ALREADY reports,
    /// with the unknowns spelled as unknown — the same discipline
    /// `backend_capabilities` applies to a whole backend, applied to one event.
    #[test]
    fn a_fault_is_recognisable_without_knowing_which_backend_produced_it() {
        use crate::{Address, StopReason};

        let win = StopReason::AccessViolation { address: Address(0x1000), is_write: true };
        let lin = StopReason::Signal {
            signum: 11,
            signame: "SIGSEGV".to_string(),
            address: Some(Address(0x1000)),
        };
        let mac = StopReason::Signal {
            signum: 11,
            signame: "SIGSEGV".to_string(),
            address: None,
        };
        let not_a_fault = StopReason::Signal {
            signum: 2,
            signame: "SIGINT".to_string(),
            address: None,
        };

        let w = win.access_fault().expect("windows reports a fault");
        assert_eq!(w.address, Some(Address(0x1000)));
        assert_eq!(w.is_write, Some(true), "windows knows the direction");

        let l = lin.access_fault().expect("linux reports the same fault");
        assert_eq!(l.address, Some(Address(0x1000)));
        assert_eq!(l.is_write, None, "linux cannot tell the direction, and must say so");

        let m = mac.access_fault().expect("macos reports the same fault");
        assert_eq!(m.address, None, "macos knows neither, and must not invent one");
        assert_eq!(m.is_write, None);

        assert!(
            not_a_fault.access_fault().is_none(),
            "a SIGINT is not a memory fault; widening the predicate to any signal would make \
             it useless"
        );
    }

    /// `AccessViolation.address` must be the DATA address, on every backend.
    ///
    /// Windows built it from `ExceptionRecord.ExceptionAddress`, which is the
    /// address of the INSTRUCTION that faulted. The address the program tried
    /// to touch is `ExceptionInformation[1]` — a different number, and the one
    /// a caller wants. Linux reports `si_addr`, which IS the data address.
    ///
    /// So the same crash answered with two different KINDS of address depending
    /// on the OS, under one field name. That is family 2 (shared meaning
    /// drifting between backends) producing family 1 (a confidently wrong
    /// answer): nothing errors, the field is populated, and a caller comparing
    /// it against a buffer range gets the code address instead.
    ///
    /// The variant settles which one is meant. It carries exactly ONE address
    /// and an `is_write` flag beside it, and `is_write` describes the DATA
    /// access — `ExceptionInformation[0]`. An address that is not the datum
    /// that `is_write` talks about makes the pair self-contradictory.
    ///
    /// The instruction address is not lost: it is the program counter, which
    /// every caller can read from the register set at the same stop.
    #[test]
    fn an_access_violation_reports_the_address_that_was_touched() {
        let src = include_str!("windows_debugger.rs");
        let body = item_body(
            src,
            "0xC000_0005 => StopReason::AccessViolation {",
            &["\n                other =>", "\n            }"],
        );
        assert!(
            body.contains("ExceptionInformation[1]"),
            "windows: the reported address is `ExceptionAddress`, i.e. the faulting \
             INSTRUCTION, while Linux reports the faulting DATUM via si_addr. One field name, \
             two meanings, and the `is_write` flag beside it describes the datum — so the pair \
             contradicts itself"
        );
    }

    /// macOS must make a code page writable before implanting a trap.
    ///
    /// Measured on `macos-15-intel` (1c70fff), where the live test fails with
    ///
    /// ```text
    /// Intel must accept a software breakpoint;
    /// got Err(MemoryError(4532346880, "mach_vm_write failed: kern_return 1"))
    /// ```
    ///
    /// `kern_return 1` is `KERN_INVALID_ADDRESS`. The address is fine — the
    /// PAGE is not writable. A `__TEXT` page is mapped `r-x`, and Mach refuses
    /// the write rather than silently succeeding.
    ///
    /// So software breakpoints have never worked on macOS. Not "work with a
    /// caveat": `set_breakpoint` cannot put its byte in the target at all, on
    /// either architecture, and the failure was invisible because the live
    /// tests run in a `continue-on-error` step whose result never reached the
    /// job (fixed in 578).
    ///
    /// The missing call is `mach_vm_protect`. `VM_PROT_*` constants are already
    /// declared in that backend and used only to REPORT region permissions;
    /// nothing ever changes them. lldb does exactly this: raise the page to
    /// writable, poke, restore — and `VM_PROT_COPY` matters, because a shared
    /// page must become a private copy rather than have the change escape into
    /// every other process mapping that library.
    #[test]
    fn macos_makes_a_page_writable_before_implanting_a_trap() {
        let src = include_str!("macos_debugger.rs");
        assert!(
            src.contains("mach_vm_protect("),
            "macos: nothing ever changes page protection, so `mach_vm_write` into a read-only \
             __TEXT page fails with KERN_INVALID_ADDRESS and software breakpoints do not work \
             at all — measured on macos-15-intel, not predicted"
        );
        assert!(
            src.contains("VM_PROT_COPY"),
            "macos: the page is made writable without VM_PROT_COPY, so a trap planted in a \
             SHARED library page would be written through to every process mapping it instead \
             of into a private copy"
        );
    }

    /// A backend must publish what it CANNOT do, not only what it is called.
    ///
    /// `debug.health` reports the backend name and nothing about its
    /// capabilities. That is not a cosmetic gap: the macOS backend emits
    /// `StopReason::ThreadCreate` exactly ZERO times — measured, `grep -c`
    /// gives 5 on Windows, 18 on Linux, 0 on macOS — because Mach has no
    /// equivalent of `PTRACE_O_TRACECLONE`. An MCP client that waits for a
    /// thread-creation event on macOS waits forever, and nothing in the API
    /// says so. Silence about a limit reads as support for it.
    ///
    /// The fix is NOT to synthesise the event. Linux and Windows get a real
    /// kernel stop — the CLONE birth-stop, `CREATE_THREAD_DEBUG_EVENT` — so
    /// `ThreadCreate` there means "we stopped BECAUSE a thread was born".
    /// Diffing `task_threads()` on macOS would mean "one appeared meanwhile",
    /// which is a different claim wearing the same name: an answer invented to
    /// fill a signature, which this crate holds to be worse than a refusal.
    ///
    /// So the honest move is to publish the absence.
    #[test]
    fn every_backend_publishes_its_own_limits() {
        assert!(
            crate::backend_capabilities().iter().any(|c| c.name == "thread_events"),
            "no backend capability is published, so a caller cannot tell a limitation from a \
             silence — on macOS `ThreadCreate` never arrives and the API does not say so"
        );
    }

    /// The Linux unwinder must strip PAC, and must ASK the kernel for the mask.
    ///
    /// Measured on `ubuntu-24.04-arm` (1c70fff): the live test
    /// `backtrace_unwinds_past_the_first_frame_via_dwarf_cfi` fails with
    ///
    /// ```text
    /// unwound frame pc 0x31ab6b12435c0c should fall inside a loaded module
    /// ```
    ///
    /// That is a pointer-authentication code in the high bits — the same shape
    /// as the address iteration 559 fixed. 559 stripped PAC in the SHARED
    /// frame-pointer unwinder (`memory_layout_view.rs`), and this crate then
    /// recorded the defect as closed. It is not: the Linux backend unwinds
    /// through its own DWARF CFI path, which never goes through that code.
    /// A fix in one unwinder was read as a fix for unwinding.
    ///
    /// **The mask must come from the kernel, not from a constant.**
    /// `ios::arm64::strip_pac` hardcodes `VA_BITS = 47`, which is Apple's user
    /// address split. Linux arm64 is normally 48-bit (and can be 52), so
    /// reusing that constant here would strip one bit too many and could turn
    /// a legitimate address into a bogus one — trading a visible failure for a
    /// silent corruption, which is the worse of the two.
    ///
    /// `PTRACE_GETREGSET` with `NT_ARM_PAC_MASK` reports the exact instruction
    /// and data masks for the traced process, so there is nothing left to
    /// assume. The transport for it already exists: iterations 570 and 571
    /// wrote it for `NT_ARM_HW_WATCH` / `NT_ARM_HW_BREAK`.
    #[test]
    fn the_linux_unwinder_strips_pac_using_the_kernels_own_mask() {
        let src = include_str!("linux_debugger.rs");
        assert!(
            src.contains("NT_ARM_PAC_MASK"),
            "linux: the DWARF unwinder does not ask the kernel for the PAC mask, so a signed \
             return address is compared against module ranges as-is and falls inside none of \
             them — measured on ubuntu-24.04-arm, not predicted"
        );
        // The `(` is load-bearing, and this is the THIRD time in three rounds
        // that a string-anchored assertion has meant something other than what
        // it said. 571's guard went vacuously GREEN because `NT_ARM_HW_BREAK`
        // appeared inside a refusal message; this one went falsely RED because
        // `ios::arm64::strip_pac` appears in the doc comments that explain why
        // this backend does NOT use it. Matching the call syntax distinguishes
        // a use from a mention, which is the distinction actually intended.
        assert!(
            !src.contains("ios::arm64::strip_pac("),
            "linux: PAC is being stripped with Apple's hardcoded VA_BITS = 47. Linux arm64 is \
             normally 48-bit, so that removes one bit too many and can corrupt a valid address \
             — a silent wrong answer in place of a visible failure"
        );
    }

    /// An execution slot must reach `DBGBVR`/`DBGBCR`, not be silently zeroed.
    ///
    /// Iteration 570 brought hardware DATA watchpoints to ARM64 Linux. It did
    /// not bring hardware BREAKpoints, and the difference is invisible from the
    /// outside: a slot with `rw == 0b00` in `DR7` — an execution breakpoint on
    /// x86 — falls into the `None` arm of `arm64_watchpoint_from_dr_slot`, and
    /// `write_debug_registers` clears the pair. The caller asked for a hardware
    /// breakpoint, got `Ok`, and nothing is armed.
    ///
    /// That `None` is CORRECT and was correct before 570: AArch64 really does
    /// put execution breakpoints in a different register file, and arming a
    /// data watchpoint instead would fire on the wrong events. What changed is
    /// what it MEANS. Before 570 it said "not supported on this platform";
    /// after 570 it says "supported, behind the other regset" — the same
    /// unchanged line, given a new meaning by the code around it.
    ///
    /// Everything needed is already here: `ios::arm64::hw_breakpoints` holds
    /// the `DBGBCR` field layout, and iteration 570 wrote the `NT_ARM_HW_WATCH`
    /// transport whose only differences here are the regset id and the struct
    /// field.
    ///
    /// Mapping note, because it is the one real design decision: x86 has four
    /// slots shared between breakpoints and watchpoints, AArch64 has two
    /// SEPARATE files each with its own slots. Slot `n` is therefore programmed
    /// into exactly one of them according to `rw`, and the other is cleared —
    /// so a slot never means two things at once.
    ///
    /// As with 570, this guard is a source-level statement. `ubuntu-24.04-arm`
    /// is what proves the registers are programmed correctly.
    #[test]
    fn an_execution_slot_reaches_the_arm64_breakpoint_registers() {
        assert!(
            crate::arm64_breakpoint_from_dr_slot(0x1000, 0b1, 0).is_some(),
            "an execution slot (rw == 0b00) has no translation to DBGBVR/DBGBCR, so a hardware \
             breakpoint request on AArch64 is accepted and then silently zeroed"
        );
        let src = include_str!("linux_debugger.rs");
        // NOT `contains("NT_ARM_HW_BREAK")`. That was the first spelling of
        // this assertion and it was VACUOUS: the string already appeared in
        // the text of a refusal MESSAGE, so the guard passed while no transport
        // existed. Anchoring on the translation call instead ties the assertion
        // to something that cannot be satisfied by prose.
        assert!(
            src.contains("dr_slot_from_arm64_breakpoint")
                && src.contains("arm64_breakpoint_from_dr_slot"),
            "linux: the dr <-> DBGBVR/DBGBCR translation is not reached from this backend, so a \
             hardware breakpoint on AArch64 is accepted and then silently zeroed"
        );
    }

    /// Linux must reach the AArch64 watchpoint registers, not refuse them
    /// while the crate already holds the translation.
    ///
    /// `set_watchpoint_sized` on the Linux backend answers:
    ///
    /// ```text
    /// "hardware watchpoints on this backend program the x86 debug registers,
    ///  which this host architecture does not have"
    /// ```
    ///
    /// The second half is true — ptrace on AArch64 does not expose `DR0`-`DR7`.
    /// What makes it a gap rather than a fact is that the hard half of the work
    /// is already done and sits in the SHARED crate root, not in a backend:
    /// `arm64_watchpoint_from_dr_slot` / `dr_slot_from_arm64_watchpoint`
    /// (lib.rs) translate the engine's `dr0`-`dr3` + `DR7` vocabulary to
    /// `DBGWVR`/`DBGWCR` and back, and they are already exercised. macOS uses
    /// them. Linux declines, citing the absence of something this crate owns.
    ///
    /// What Linux genuinely still needs is TRANSPORT: `PTRACE_GETREGSET` /
    /// `PTRACE_SETREGSET` with `NT_ARM_HW_WATCH` and the kernel's
    /// `user_hwdebug_state` layout. The `iovec` plumbing for that already
    /// exists too — iteration 552 wrote it for `NT_PRSTATUS`.
    ///
    /// So this is family 2 of the three this crate produces: shared logic
    /// present, one backend wired to it, another refusing.
    ///
    /// **This guard is a source-level statement, not a proof.** Whether the
    /// registers are programmed CORRECTLY can only be answered by
    /// `ubuntu-24.04-arm`, which executes this path on real ARM hardware. The
    /// layout in particular is the dangerous part: a struct that drifts is read
    /// in silence and yields a watchpoint that looks armed and watches the
    /// wrong address — which is why the macOS side carries
    /// `assert!(ARM_DEBUG_STATE64_COUNT == 130)` at compile time and why the
    /// Linux side must carry the equivalent size assertion.
    #[test]
    fn linux_reaches_the_arm64_watchpoint_registers() {
        let src = include_str!("linux_debugger.rs");
        assert!(
            src.contains("dr_slot_from_arm64_watchpoint")
                && src.contains("arm64_watchpoint_from_dr_slot"),
            "linux: the dr <-> DBGWVR/DBGWCR translation is not reached from this backend, so \
             the shared watchpoint engine addresses registers that do not exist on this CPU — \
             while the translation itself sits ready in lib.rs and macOS already uses it"
        );
        assert!(
            src.contains("NT_ARM_HW_WATCH"),
            "linux: no `NT_ARM_HW_WATCH` transport, so there is no way to carry a translated \
             watchpoint to the kernel even once it is computed"
        );
        assert!(
            src.contains("size_of::<UserHwdebugState>() == 264"),
            "linux: the compile-time size check on the hand-declared `user_hwdebug_state` is \
             missing. A layout drift there is read in SILENCE and arms a watchpoint on the \
             wrong address — the macOS side carries the same check for the same reason"
        );
    }

    /// A backend that implants `host_trap_bytes()` must not refuse on the
    /// grounds that it implants the x86 `int3`.
    ///
    /// `set_breakpoint` on the Linux backend refuses outright off x86:
    ///
    /// ```text
    /// const X86_TRAP_BYTE_IS_VALID_HERE: bool = cfg!(any(target_arch = "x86_64", ...));
    /// if !X86_TRAP_BYTE_IS_VALID_HERE {
    ///     return Err(Unsupported("software breakpoints on this backend implant
    ///                             the x86 int3 (0xCC), which is not a breakpoint
    ///                             on this host architecture"))
    /// }
    /// ```
    ///
    /// The refusal describes an implant this function no longer performs.
    /// Twenty lines below it writes `crate::host_trap_bytes()`, which is
    /// `BRK #0` on AArch64 — derived from this crate's single arm64 encoder,
    /// four bytes wide per `trap_len`, with `pc_after_trap` already accounting
    /// for the x86-vs-ARM difference in the reported PC. The alignment check
    /// immediately above it already asks `host_trap_alignment()`.
    ///
    /// So the refusal was true when it was written and was made false by the
    /// architecture-derived trap work: the backend would now plant a correct
    /// `BRK` and declines to, citing a `0xCC` it no longer writes.
    ///
    /// This is the MIRROR of lesson 14. There, a defence looked stale and was
    /// protecting something real. Here the defence really is stale — and the
    /// difference between the two cases is not judgement but evidence: the
    /// `ubuntu-24.04-arm` CI row EXECUTES this path on real ARM hardware. This
    /// guard states the contradiction; that runner is what proves the removal.
    ///
    /// Deliberately scoped to Linux. The same refusal sits in the Windows and
    /// macOS backends, and macOS aarch64 is a real and common host — but no
    /// machine reachable from here can run those paths on ARM, and removing a
    /// defence where nothing can answer is predicting, not measuring. That is
    /// the mistake iteration 561 was withdrawn for.
    #[test]
    fn linux_does_not_refuse_a_trap_it_would_now_plant_correctly() {
        let src = include_str!("linux_debugger.rs");
        assert!(
            !src.contains("X86_TRAP_BYTE_IS_VALID_HERE"),
            "linux: `set_breakpoint` refuses off x86 because it implants the x86 int3, but it \
             implants `host_trap_bytes()` — `BRK #0` on AArch64. The refusal outlived the \
             reason for it"
        );
    }

    /// The resume paths may decline to FAIL on a missed re-arm; they may not
    /// discard the fact.
    ///
    /// ```text
    /// let _ = self.rearm_watchpoints_on_new_threads().await;
    /// ```
    ///
    /// The comment beside it justifies not failing, and it is right to: a
    /// resume must not break because a watchpoint could not be re-armed on a
    /// thread that appeared. But `let _ =` does not discard the FAILURE, it
    /// discards the INFORMATION. After such a resume the watchpoint has stopped
    /// watching the new threads and nothing will ever say so — which is the
    /// precise failure mode a watchpoint exists to rule out.
    ///
    /// Round 567 made this function report every miss instead of one in four.
    /// That work is wasted on the two callers that throw the answer away.
    #[test]
    fn a_resume_may_decline_to_fail_on_a_missed_rearm_but_not_to_record_it() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let discarded = src
                .matches("let _ = self.rearm_watchpoints_on_new_threads().await;")
                .count();
            assert_eq!(
                discarded, 0,
                "{name}: {discarded} resume path(s) discard the list of watchpoints that could \
                 not be re-armed, so a watchpoint silently stops watching threads that appeared \
                 and no caller can ever learn it"
            );
        }
    }

    /// Every way of leaving a thread unwatched must reach `unarmed`.
    ///
    /// `rearm_watchpoints_on_new_threads` already decided how to report a miss:
    /// it returns the addresses that are NOT armed, and `enable_breakpoint`
    /// answers on that list. Its own comment states the rule — *"A re-arm that
    /// did not land leaves this thread UNWATCHED ... the caller was still told
    /// it was watched"*.
    ///
    /// But only ONE of the four ways to leave a thread unwatched reached that
    /// list (the failed `set_registers`). The other three were silent:
    ///
    /// - `let Ok(mut regs) = self.get_registers(tid).await else { continue }`
    ///   — the thread was never inspected, so it is certainly not armed;
    /// - `let Some(slot) = x86_free_watchpoint_slot(dr7) else { break }`
    ///   — all four debug registers are occupied, so this watchpoint and every
    ///     one after it in `wanted` do not fit on this thread;
    /// - `let Ok(new_dr7) = x86_encode_watchpoint_dr7(..) else { continue }`
    ///   — the encoding was rejected, so nothing was programmed.
    ///
    /// In all three the address stays in `hw_watchpoints` — the caller is told
    /// it is watched — while no debug register on that thread holds it. That is
    /// the "silent miss, not an error" this crate condemns, sitting in the
    /// siblings of the line that condemns it.
    #[test]
    fn every_way_of_leaving_a_thread_unwatched_is_reported_not_swallowed() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let body = item_body(
                src,
                "async fn rearm_watchpoints_on_new_threads(",
                &["\n    fn ", "\n    async fn ", "\n    pub async fn "],
            );
            assert!(
                !body.contains("self.get_registers(tid).await else { continue }"),
                "{name}: a thread whose registers cannot be read is skipped without reaching \
                 `unarmed`, so it is reported as watched while nothing watches it"
            );
            // The write-failure path is one. A body that still reports only
            // through it has not learned about the other three.
            let reported = body.matches("unarmed.extend").count()
                + body.matches("unarmed.push").count();
            assert!(
                reported >= 2,
                "{name}: only {reported} path(s) record into `unarmed`, but there are four \
                 distinct ways for this function to leave a thread unwatched"
            );
        }
    }

    /// A failed disarm must not be reported as "there was nothing to disarm".
    ///
    /// `disarm_watchpoint_registers` documents its `bool` as *"whether a slot
    /// was actually holding this address"*, and computed it as:
    ///
    /// ```text
    /// if cleared_here && self.set_registers(tid, regs).await.is_ok() {
    ///     found = true;
    /// }
    /// ```
    ///
    /// So a write that FAILED left `found` at `false` — the same answer as a
    /// watchpoint that was never armed. The caller cannot tell "it was not
    /// there" from "it was there and I could not clear it".
    ///
    /// Its caller then makes that indistinguishability expensive:
    /// `remove_hardware_watchpoint` clears `hw_watchpoints` and `disabled`
    /// UNCONDITIONALLY. A failed disarm therefore removes the debugger's only
    /// record of a watchpoint that is still live in the CPU's debug registers:
    /// it keeps firing, and nothing knows what it is.
    ///
    /// Sibling of the defect in `disarm_all_hardware_watchpoints`, and the same
    /// rule: a step that could not be performed is not a step that found
    /// nothing to do.
    #[test]
    fn a_failed_watchpoint_disarm_is_not_reported_as_nothing_to_disarm() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let body = item_body(
                src,
                "async fn disarm_watchpoint_registers(",
                &["\n    fn ", "\n    async fn ", "\n    pub async fn "],
            );
            assert!(
                !body.contains("if cleared_here && self.set_registers(tid, regs).await.is_ok()"),
                "{name}: a failed register write leaves `found` false, which is the same answer \
                 as a watchpoint that was never armed — and the caller clears its bookkeeping on \
                 that answer, forgetting a watchpoint still live in the debug registers"
            );
            assert!(
                !body.contains("self.get_registers(tid).await else { continue }"),
                "{name}: a thread whose registers cannot be read is skipped silently, so a \
                 watchpoint armed on exactly that thread is reported as absent"
            );
        }
    }

    /// «Non ho potuto controllare» non è «ho verificato che è pulito».
    ///
    /// `disarm_all_hardware_watchpoints` states its own contract in its error
    /// text: *"debug registers still armed on thread(s) …; detaching now would
    /// leave the target trapping with no debugger to take the trap"*. It must
    /// therefore guarantee that no thread is left armed — and it reported
    /// success down two paths where it had verified nothing:
    ///
    /// ```text
    /// let Ok(tids) = self.threads().await else { return Ok(()) };
    /// let Ok(mut regs) = self.get_registers(tid).await else { continue };
    /// ```
    ///
    /// The first returns "all clear" without having examined a single thread.
    /// The second skips a thread whose registers could not be read — exactly
    /// the thread most likely to be in a bad state. A target detached after
    /// either one keeps a live `DR7`, traps on its next watched access, and
    /// finds no debugger attached to take the trap: it dies from having been
    /// inspected.
    ///
    /// Identical in all three backends, so this is shared logic that drifted
    /// once and stayed drifted.
    #[test]
    fn disarming_watchpoints_does_not_report_success_it_never_verified() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let body = item_body(
                src,
                "async fn disarm_all_hardware_watchpoints(",
                &["\n    fn ", "\n    async fn ", "\n    pub async fn "],
            );
            assert!(
                !body.contains("else { return Ok(()) }"),
                "{name}: disarm_all_hardware_watchpoints answers Ok when it could not even list \
                 the threads, so it promises every debug register is clear without having read one"
            );
            assert!(
                !body.contains("self.get_registers(tid).await else { continue }"),
                "{name}: a thread whose registers cannot be read is SKIPPED, so it is reported \
                 clear while it may still be armed — and it is the likeliest thread to be in a \
                 bad state"
            );
        }
    }

    /// Neither must `kill`.
    ///
    /// Same shape as the `detach` guard below, found by asking where else a
    /// literal `Ok(())` survived. All three backends issue their kill — Windows
    /// `TerminateProcess`, Linux `SIGKILL`, macOS `PT_KILL` + `SIGKILL` — and
    /// then answer with a constant:
    ///
    /// * Windows discards the BOOL from `TerminateProcess` entirely;
    /// * macOS stores `waitpid`'s result in `_already_reaped` and never reads
    ///   it, which is a discard wearing a name.
    ///
    /// Iteration 538 made the MCP layer stop claiming "the process was killed"
    /// without checking. This is what it had to check against: nothing.
    ///
    /// As with `detach`, the fix is not "propagate everything". A process that
    /// is already gone cannot be killed and does not need to be — `ESRCH` is
    /// the successful outcome spelled as an error. `EPERM` is not: it says the
    /// target is still running and still not ours.
    #[test]
    fn kill_does_not_claim_success_without_checking_it() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let start = src
                .find("Command::Kill => {")
                .unwrap_or_else(|| panic!("{name}: no Kill arm to check"));
            let arm = &src[start..];
            let end = arm.find("\n            }").unwrap_or(arm.len());
            let arm = &arm[..end];
            assert!(
                !arm.contains("Reply::Ack(Ok(()))"),
                "{name}: the Kill arm answers with a literal Ok — the kill syscall's result is \
                 discarded, so `kill()` reports success for a process that may still be running"
            );
        }
    }

    /// `detach` must not answer with a constant.
    ///
    /// All three backends issued their detach syscalls — `DebugActiveProcessStop`
    /// on Windows, `PTRACE_DETACH` per thread on Linux, `PT_DETACH` on macOS —
    /// discarded every return value, and then replied `Reply::Ack(Ok(()))`. The
    /// answer was a literal: it said "detached" whether or not anything had
    /// been.
    ///
    /// Not cosmetic, and worst on Windows: a process stays debugged if
    /// `DebugActiveProcessStop` fails, and Windows KILLS a debuggee when its
    /// debugger exits unless told otherwise. So the caller is told it has let
    /// the target go, and the target dies with the debugger instead.
    ///
    /// This is the same rule the MCP layer already follows one level up — every
    /// status field it publishes is DERIVED, never constant (iterations
    /// 536-539). It just had nothing truthful underneath to derive from.
    #[test]
    fn detach_does_not_claim_success_without_checking_it() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let start = src
                .find("Command::Detach => {")
                .unwrap_or_else(|| panic!("{name}: no Detach arm to check"));
            let arm = &src[start..];
            // The arm ends at the first line that closes it at match-arm
            // indentation; `return;` sits just above it.
            let end = arm.find("\n            }").unwrap_or(arm.len());
            let arm = &arm[..end];
            assert!(
                !arm.contains("Reply::Ack(Ok(()))"),
                "{name}: the Detach arm answers with a literal Ok — every detach syscall's \
                 result is discarded, so `detach()` reports success for a target that may \
                 still be attached"
            );
        }
    }

    /// Restoring a breakpoint to DISABLED must not fail silently.
    ///
    /// `step_over`/`step_out` re-arm a breakpoint the caller had explicitly
    /// disabled, because the step cannot work through a disabled trap. Putting
    /// it back is therefore part of the operation, not tidying up: if it fails
    /// and the failure is discarded, the caller is told the step succeeded
    /// while the target is left with an ARMED trap at an address the user
    /// turned off. The program then stops at a breakpoint that, as far as the
    /// API is concerned, does not exist.
    ///
    /// The excuse written above that line — "writing to a dead process blocks
    /// on a channel whose debug thread is gone" — is real, and it is why the
    /// SIBLING branch guards its `?` with an exit check. But this branch
    /// already excludes the exit case in its own `if` condition, so by the time
    /// the discard happens the process is known to be alive. The two adjacent
    /// branches were doing opposite things in the same situation.
    ///
    /// macOS is not checked here YET: another engineer holds
    /// `macos_debugger.rs` while this is written, and a guard that fails
    /// because a file is mid-edit reports the wrong thing. It carries the
    /// identical block (verified byte-for-byte) and must be added to this list
    /// as soon as the file is free.
    #[test]
    fn a_failed_restore_of_a_disabled_breakpoint_is_not_discarded() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            assert!(
                !src.contains("let _ = self.disable_breakpoint(target).await;"),
                "{name}: step_over/step_out re-arms a disabled breakpoint and discards the result \
                 of putting it back, so a failed restore leaves an armed trap in a live target \
                 while the step is reported as successful"
            );
        }
    }

    /// The callers of the rewind must not throw that answer away either.
    ///
    /// Separate from the test above on purpose: giving the function a return
    /// type and then calling it as a bare statement restores the exact defect
    /// with the guard passing, because the discard has merely moved one level
    /// out.
    #[test]
    fn every_backend_acts_on_the_result_of_the_breakpoint_rewind() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            for (lineno, line) in src.lines().enumerate() {
                let trimmed = line.trim();
                if !trimmed.contains("rewind_past_own_breakpoint(") || trimmed.starts_with("//") {
                    continue;
                }
                // The definition and doc references are not call sites.
                if trimmed.starts_with("async fn") || trimmed.starts_with("///") {
                    continue;
                }
                assert!(
                    !trimmed.starts_with("self.rewind_past_own_breakpoint(")
                        && !trimmed.starts_with("let _ = self.rewind_past_own_breakpoint("),
                    "{name}:{}: the rewind's result is discarded at the call site — the target \
                     may be left mid-instruction while this event is handed back as a normal stop",
                    lineno + 1
                );
            }
        }
    }

    /// What `breakpoints()` lists, `remove_breakpoint` must be able to remove.
    ///
    /// The two are a pair: listing hardware watchpoints (iteration 368)
    /// without accepting them here left the API answering "here it is" and
    /// "it does not exist" about the same address, with the debug register
    /// still armed. Checked on all three backends because both methods are
    /// shared logic, not per-platform.
    #[test]
    fn every_backend_can_remove_the_hardware_watchpoints_it_lists() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let body = item_body(
                src,
                "async fn remove_breakpoint(&self, addr: Address) -> Result<(), DebugError> {",
                &["\n    fn ", "\n    async fn ", "\n    pub async fn "],
            );
            assert!(
                body.contains("remove_hardware_watchpoint"),
                "{name}: remove_breakpoint() refuses an address that breakpoints() lists as \
                 armed, so a watchpoint discovered through the list cannot be removed"
            );
            // The honest error must survive: turning every unknown address
            // into success would "fix" this by making removal meaningless.
            assert!(
                body.contains("BreakpointNotFound"),
                "{name}: remove_breakpoint() no longer reports an address that was never set"
            );
        }
    }

    /// `breakpoints()` must not omit hardware watchpoints.
    ///
    /// They live in their own map, so the software-only listing was not wrong
    /// about what it showed — it was wrong about being the set of what is
    /// armed. All three backends share this method (it is not in
    /// `PER_PLATFORM`), so all three are checked, macOS included, where the
    /// map is structurally empty and the chain is a harmless no-op.
    #[test]
    fn every_backend_lists_hardware_watchpoints_among_its_breakpoints() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let body = item_body(
                src,
                "async fn breakpoints(&self) -> Result<Vec<Breakpoint>, DebugError> {",
                &["\n    fn ", "\n    async fn ", "\n    pub async fn "],
            );
            assert!(
                body.contains("hw_watchpoints"),
                "{name}: breakpoints() lists only software breakpoints, so an armed hardware \
                 watchpoint is invisible to the caller that armed it"
            );
        }
    }

    /// A watchpoint must survive threads appearing after it was armed.
    ///
    /// The debug registers are per-thread and are not inherited, so a thread
    /// the target spawns later watches nothing. Both backends reconcile on
    /// resume; macOS is absent for the same reason as the arming guard.
    #[test]
    fn every_backend_rearms_watchpoints_on_threads_created_later() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
        ] {
            let resume = item_body(
                src,
                "async fn continue_execution(&self) -> Result<DebugEvent, DebugError> {",
                &["\n    fn ", "\n    async fn ", "\n    pub async fn "],
            );
            assert!(
                resume.contains("rearm_watchpoints_on_new_threads()"),
                "{name}: resuming does not re-arm watchpoints, so every thread the target \
                 spawns from now on watches nothing"
            );
            // The registry is what makes re-arming possible at all: without
            // recording the armed watchpoints there is nothing to re-apply.
            let arm = item_body(
                src,
                "async fn set_watchpoint_sized(",
                &["\n    fn ", "\n    async fn ", "\n    pub async fn "],
            );
            assert!(
                arm.contains("hw_watchpoints.lock().insert("),
                "{name}: an armed watchpoint is not recorded, so nothing can re-apply it \
                 to a thread created later"
            );
            // Forgetting the watchpoint stayed in `remove_hardware_watchpoint`
            // even after the register sweep moved out of it: only REMOVAL
            // drops the registry entry, while `disable` deliberately keeps it.
            let disarm = item_body(
                src,
                "pub async fn remove_hardware_watchpoint(",
                &["\n    fn ", "\n    async fn ", "\n    pub async fn "],
            );
            assert!(
                disarm.contains("hw_watchpoints.lock().remove("),
                "{name}: a removed watchpoint stays in the registry and gets re-armed on \
                 the next resume — removal would not stick"
            );
        }
    }

    /// Both backends that CAN program the debug registers must do so.
    ///
    /// macOS is deliberately absent: its `Command::SetRegisters` refuses
    /// `dr0`-`dr7` outright ("cannot program x86 debug registers"), so an
    /// override there would claim to arm a watchpoint that could never fire.
    /// That coherence is held by
    /// `tests_expanded::the_macos_backend_refuses_hardware_watchpoints_in_all_three_places`,
    /// which is what caught the attempt to add one here.
    #[test]
    fn every_backend_programs_the_debug_registers_for_watchpoints() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
        ] {
            let body = item_body(
                src,
                "async fn set_watchpoint_sized(",
                &["
    fn ", "
    async fn ", "
    pub async fn "],
            );
            assert!(
                body.contains("x86_encode_watchpoint_dr7"),
                "{name}: set_watchpoint_sized() does not program DR7, so it falls back                  to set_breakpoint and every hardware watchpoint request fails"
            );
            // Encode before writing DR0-DR3, or a rejected request leaves the
            // registers half-programmed.
            let encode = body.find("x86_encode_watchpoint_dr7");
            let write = body.find("self.set_registers");
            assert!(encode < write, "{name}: writes the debug registers before validating");
            // The debug registers are per-thread: arming only the stopped
            // thread is a watchpoint that silently never fires elsewhere.
            assert!(
                body.contains("self.threads()"),
                "{name}: set_watchpoint_sized() arms a single thread, so a write from any \
                 other thread is missed while the caller believes the address is watched"
            );
            // Arming without disarming leaks one of the four slots per removed
            // watchpoint until detach — the risk the macOS guard names.
            assert!(
                src.contains("pub async fn remove_hardware_watchpoint("),
                "{name}: arms hardware watchpoints but never frees the DR slot"
            );
            // The sweep moved out of `remove_hardware_watchpoint` and into
            // `disarm_watchpoint_registers` when `disable_breakpoint` needed to
            // clear the registers WITHOUT forgetting the watchpoint. The
            // invariant is unchanged, so the needle follows the logic rather
            // than the old method name.
            let disarm = item_body(
                src,
                "async fn disarm_watchpoint_registers(",
                &["\n    fn ", "\n    async fn ", "\n    pub async fn "],
            );
            assert!(
                disarm.contains("self.threads()"),
                "{name}: the disarm covers fewer threads than the arm, so the watchpoint \
                 stays live on the others and its slot never comes back"
            );
        }
    }

    /// Writing over a planted breakpoint must not disarm it or lose the write.
    ///
    /// The dual of the read-masking guard. An unrouted write has two wrong
    /// outcomes at once: it overwrites the `0xCC`, so a breakpoint still
    /// listed as enabled stops firing, and the byte it replaced stays recorded
    /// as "the original", so removing the breakpoint later restores the stale
    /// byte and silently undoes the write.
    #[test]
    fn writes_over_a_planted_breakpoint_update_the_saved_byte_not_the_trap() {
        let base = 0x1000u64;
        let data = [0xAAu8, 0xBB, 0xCC, 0xDD];

        // Breakpoint on the second byte: the trap survives, the new byte
        // becomes what the target will see once the breakpoint is gone.
        let (to_write, originals) =
            redirect_writes_over_breakpoints(base, &data, |a| (a == base + 1).then_some(0xCC));
        assert_eq!(to_write, [0xAA, 0xCC, 0xCC, 0xDD], "the trap must stay planted");
        assert_eq!(originals, [(base + 1, 0xBB)], "the written byte becomes the saved original");

        // No breakpoint in range: the write goes through untouched and
        // nothing is recorded.
        let (to_write, originals) = redirect_writes_over_breakpoints(base, &data, |_| None);
        assert_eq!(to_write, data);
        assert!(originals.is_empty());

        // Every byte covered — the buffer becomes all traps, and every byte is
        // remembered in order.
        let (to_write, originals) = redirect_writes_over_breakpoints(base, &data, |_| Some(0xCC));
        assert_eq!(to_write, [0xCC; 4]);
        assert_eq!(
            originals,
            [(base, 0xAA), (base + 1, 0xBB), (base + 2, 0xCC), (base + 3, 0xDD)]
        );

        // A write at the top of the address space must not panic.
        let (to_write, _) = redirect_writes_over_breakpoints(u64::MAX - 1, &data, |_| None);
        assert_eq!(to_write, data);

        // A WIDE trap keeps each of its own bytes, not a fixed `0xCC`.
        //
        // The AArch64 trap is the four bytes of `BRK #0`. Hard-coding an int3
        // here left three quarters of a `BRK` and one byte of garbage: an
        // instruction that is no longer a trap, in a breakpoint the debugger
        // still lists as enabled and still believes it can remove. Invisible on
        // the x86 hosts this crate is developed on, real on both Apple targets
        // and on AArch64 Linux.
        let brk = [0x00u8, 0x00, 0x20, 0xD4];
        let (to_write, originals) =
            redirect_writes_over_breakpoints(base, &data, |a| {
                let off = usize::try_from(a - base).ok()?;
                (off < brk.len()).then(|| brk[off])
            });
        assert_eq!(
            to_write, brk,
            "each byte of a four-byte trap must be preserved at its own offset"
        );
        assert_eq!(originals.len(), 4, "and every overwritten byte is still remembered");
    }

    /// Every backend must route writes around its own breakpoints.
    #[test]
    fn every_backend_routes_writes_around_planted_breakpoints() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let body = item_body(
                src,
                "async fn write_memory(&self, addr: Address, data: &[u8]) -> Result<usize, DebugError> {",
                &["
    fn ", "
    async fn ", "
    pub async fn "],
            );
            assert!(
                body.contains("redirect_writes_over_breakpoints"),
                "{name}: write_memory() writes straight through, so a write over a                  planted breakpoint disarms it and is later undone by removing it"
            );
            assert!(
                body.contains("write_memory_raw"),
                "{name}: write_memory() no longer writes through write_memory_raw"
            );
        }
    }

    /// Every backend must hide its own breakpoints from `read_memory`.
    ///
    /// Proved on a live Windows process by
    /// `read_memory_hides_our_breakpoints_and_raw_still_shows_them`; the code
    /// shape is identical in all three, and macOS is compiled by no host here.
    /// Scoped to the body of `read_memory` on purpose: the un-patch helper
    /// being used elsewhere in the file (`step_over` does, since iteration
    /// 358) is exactly what the unmasked version already looked like.
    #[test]
    fn every_backend_masks_its_breakpoints_in_read_memory() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let body = item_body(
                src,
                "async fn read_memory(&self, addr: Address, size: usize) -> Result<Vec<u8>, DebugError> {",
                &["
    fn ", "
    async fn ", "
    pub async fn "],
            );
            assert!(
                body.contains("unpatch_planted_breakpoints"),
                "{name}: read_memory() hands the caller the process image verbatim,                  so every decode and comparison downstream sees our own 0xCC"
            );
            // The masked read must be the one built on the raw read, not a
            // second independent path that could drift from it.
            assert!(
                body.contains("read_memory_raw"),
                "{name}: read_memory() no longer reads through read_memory_raw"
            );
        }
    }

    /// Decoding instruction bytes must not measure our own `0xCC`.
    ///
    /// `step_over` reads the instruction at the PC to compute where it
    /// returns. `read_memory` hands back the process's memory verbatim,
    /// breakpoint patches included, so with a breakpoint planted on that
    /// instruction all three backends decoded `int3` — one byte — instead of
    /// the real instruction. A 5-byte `call` became a length of 1 and the
    /// return breakpoint landed one byte inside it: not an error, just a wrong
    /// address, which is the same confidently-wrong shape as iteration 356.
    #[test]
    fn instruction_bytes_are_unpatched_before_their_length_is_measured() {
        // A 5-byte `call rel32` with our breakpoint planted on its first byte.
        let real: [u8; 5] = [0xE8, 0x11, 0x22, 0x33, 0x44];
        let mut as_read = real;
        as_read[0] = 0xCC;

        let base = 0x1000u64;
        let mut buf = as_read;
        unpatch_planted_breakpoints(base, &mut buf, |a| (a == base).then_some(real[0]));
        assert_eq!(buf, real, "the planted byte must be restored before decoding");

        // A breakpoint further into the buffer is restored too — it belongs to
        // the NEXT instruction, and leaving it patched would corrupt any decode
        // that reads past the first one.
        let mut buf = real;
        buf[3] = 0xCC;
        unpatch_planted_breakpoints(base, &mut buf, |a| (a == base + 3).then_some(real[3]));
        assert_eq!(buf, real);

        // Addresses with nothing planted are left exactly as read, so callers
        // can apply this unconditionally.
        let mut buf = real;
        unpatch_planted_breakpoints(base, &mut buf, |_| None);
        assert_eq!(buf, real);

        // A buffer at the very top of the address space must not panic.
        let mut buf = [0xCCu8; 4];
        unpatch_planted_breakpoints(u64::MAX - 1, &mut buf, |_| None);
        assert_eq!(buf, [0xCC; 4]);
    }

    /// The live condition path and the richer evaluator must order values the
    /// same way.
    ///
    /// They did not: `conditional_breakpoint` compared `u64`, while
    /// `expression_evaluator` compares `i64` — so `rax < 0` was unsatisfiable on
    /// the path that actually decides whether the target stops, and `rax > 0`
    /// was true for `rax == -1`. Same expression, two verdicts, decided by which
    /// evaluator happened to run it. gdb and lldb both treat a register as a
    /// signed 64-bit quantity, so the live path was also the one disagreeing
    /// with every other debugger.
    ///
    /// This is a behavioural check, not a source grep: it evaluates the same
    /// comparison through both implementations and requires the same answer.
    #[test]
    fn both_condition_evaluators_order_negative_values_the_same_way() {
        use crate::conditional_breakpoint::{
            BreakpointCondition, MapEvalContext, evaluate_condition,
        };
        let mut ctx = MapEvalContext::new();
        ctx.set_reg("rax", u64::MAX); // -1
        let mut regs = RegisterSet::new();
        regs.set("rax", u64::MAX);

        for (text, expected) in [("rax < 0", true), ("rax > 0", false)] {
            let cond = BreakpointCondition::parse(text).expect("the live parser must accept this");
            let live = evaluate_condition(&cond, &ctx).expect("the live path must evaluate this");
            assert_eq!(
                live, expected,
                "{text}: the live condition path orders -1 the wrong way round"
            );
        }
    }

    /// No expression evaluator may mask a shift count.
    ///
    /// Rust's `wrapping_shl`/`wrapping_shr` reduce the count modulo 64, so
    /// `x >> 64` returns `x`: the input handed back as if it were a computed
    /// result. Both evaluators did it, and with two DIFFERENT fabricated
    /// fallbacks for a count too large for `u32` — one invented 63, the other
    /// `u32::MAX` — so the same expression had two wrong answers depending on
    /// which path evaluated it.
    ///
    /// Needles assembled rather than written whole: this guard reads `lib.rs`,
    /// where a literal copy would match itself (the trap measured in iter 449).
    #[test]
    fn no_expression_evaluator_masks_a_shift_count() {
        let shl = ["wrapping", "shl"].join("_");
        let shr = ["wrapping", "shr"].join("_");
        let masked = ["ru", "&", "63"].join(" ");
        for (name, raw) in [
            ("lib.rs", include_str!("lib.rs")),
            ("expression_evaluator.rs", include_str!("expression_evaluator.rs")),
        ] {
            let code = code_only(raw);
            for bad in [shl.as_str(), shr.as_str(), masked.as_str()] {
                assert!(
                    !code.contains(bad),
                    "{name}: `{bad}` masks the shift count modulo 64, so an oversized shift \
                     returns the operand instead of zero"
                );
            }
            assert!(
                code.contains("shift_left_64") && code.contains("shift_right_64"),
                "{name}: no longer routes shifts through the shared, unmasked helpers"
            );
        }
    }

    /// Every backend must offer sub-register names to a breakpoint condition.
    ///
    /// The register map a backend reads from the OS holds full-width names
    /// only, so a condition written the way people actually write them —
    /// `al == 0` for a boolean return, `eax > 4` for an `int` — named something
    /// the context did not contain. Evaluation failed, and the fail-open rule
    /// (iter 449) then stopped the target on EVERY hit: the condition was not
    /// wrong and was not applied, and nothing on screen said which.
    #[test]
    fn every_backend_offers_sub_register_names_to_a_condition() {
        for (name, raw) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let code = code_only(raw);
            let body = item_body(
                &code,
                "async fn condition_allows_stop(&self, event: &DebugEvent) -> bool {",
                &["\n    fn ", "\n    async fn "],
            );
            assert!(
                body.contains("SUB_REGISTER_NAMES") && body.contains("get_narrowed"),
                "{name}: condition_allows_stop() builds its context from the full-width \
                 names only, so a condition naming `al` or `eax` cannot be evaluated at all"
            );
        }
    }

    /// No breakpoint-condition site in the crate may treat "could not evaluate"
    /// as "do not stop".
    ///
    /// The crate held both answers to this question at once: the live path
    /// stops (`should_stop_for_condition`, and each backend's
    /// `condition_allows_stop`), while `AdvancedBreakpoint::should_fire`
    /// silently disabled the breakpoint. Fail-closed is the dangerous one,
    /// because its symptom is invisible: the program runs past a line the user
    /// is breakpointed on, and the debugger reports a fault in the CONDITION as
    /// a fact about the PROGRAM.
    ///
    /// Comments stripped first — the very prose explaining this rule quotes the
    /// pattern being searched for, and iter 448 shipped a guard that passed on
    /// Every backend must refuse to read a foreign thread event as its own
    /// step result.
    ///
    /// The debug loop waits on the whole process, so `single_step(tid)` can
    /// return an event from a loader or worker thread. `step_over` then read
    /// the registers of `tid` — untouched, because `tid` never ran — saw an
    /// unchanged stack pointer, concluded "not a call, the step is done", and
    /// reported a completed step-over that never happened. The interference is
    /// not theoretical: it made a live test fail twice under a loaded parallel
    /// suite (iterations 463, 474, diagnosed in 475).
    #[test]
    fn every_backend_checks_the_step_event_belongs_to_the_stepped_thread() {
        for (name, raw) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let code = code_only(raw);
            let body = item_body(
                &code,
                "async fn step_over(&self, tid: ThreadId) -> Result<DebugEvent, DebugError> {",
                &["\n    fn ", "\n    async fn "],
            );
            assert!(
                body.contains("step_result_belongs_to"),
                "{name}: step_over treats whatever event arrives as the result of its own step, so another thread stopping is reported as a completed step-over"
            );
        }
    }

    /// No backend may write the program counter under a hardcoded
    /// architecture-specific name.
    ///
    /// `rewind_past_own_breakpoint` set the PC with a literal `rip` key. On
    /// AArch64 the register map is keyed by `pc`: the write landed on a key
    /// nothing reads, `apply_register_set` took the OLD `pc` from the map, and
    /// the rewind did nothing at all on Apple Silicon. Silent, because
    /// `regs.pc` — the struct field, which the same code does set — is not
    /// what gets written back to the thread.
    ///
    /// `instr_step::pc_key` has been the shared answer since iteration 443;
    /// this guard is what stops the hardcoded name from coming back.
    #[test]
    fn no_backend_writes_the_program_counter_by_a_hardcoded_name() {
        // Assembled, never written whole: this guard reads `lib.rs` too.
        let forbidden = ["regs.set(", "\"", "rip"].concat();
        for (name, raw) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let code = code_only(raw);
            let body = item_body(
                &code,
                // Anchored WITHOUT the trailing brace: the signature gained a
                // return type in iteration 540 and this anchor broke, failing
                // two guards for a reason unrelated to what they check.
                "async fn rewind_past_own_breakpoint(&self, event: &DebugEvent)",
                &["\n    fn ", "\n    async fn "],
            );
            assert!(
                !body.contains(forbidden.as_str()),
                "{name}: rewind_past_own_breakpoint writes the PC under a name that does not exist on AArch64, so the rewind silently does nothing there"
            );
            assert!(
                body.contains("instr_step::pc_key"),
                "{name}: rewind_past_own_breakpoint no longer routes the PC name through the shared arch-aware helper"
            );
        }
    }

    /// the strength of exactly such a sentence.
    #[test]
    fn no_condition_evaluator_treats_a_failure_as_a_reason_not_to_stop() {
        for (name, raw) in [
            ("lib.rs", include_str!("lib.rs")),
            ("conditional_breakpoint.rs", include_str!("conditional_breakpoint.rs")),
            ("windows_debugger.rs", include_str!("windows_debugger.rs")),
            ("linux_debugger.rs", include_str!("linux_debugger.rs")),
            ("macos_debugger.rs", include_str!("macos_debugger.rs")),
        ] {
            let code = code_only(raw);
            // Needles ASSEMBLED, never written whole: this guard reads
            // `lib.rs`, so a literal copy of the forbidden pattern in its own
            // source would make it fail on itself.
            let err_arm = ["Err(_)", "=>", "return", "false"].join(" ");
            let both_arm = format!("Ok(0) | {err_arm}");
            for bad in [both_arm.as_str(), err_arm.as_str()] {
                assert!(
                    !code.contains(bad),
                    "{name}: `{bad}` makes an unevaluable condition silence the breakpoint \
                     instead of stopping — the opposite of the rule the live path follows"
                );
            }
            // The fail-open shape must be recognisable where evaluation is
            // actually resolved, so this guard is not merely an absence check.
            if name == "conditional_breakpoint.rs" {
                assert!(
                    code.contains("unwrap_or(true)"),
                    "{name}: should_stop_for_condition no longer defaults to stopping"
                );
            }
        }
    }

    /// A backend whose `pause()` creates a job-control stop must clear it on
    /// detach.
    ///
    /// `SIGSTOP` is not a ptrace-stop. `PTRACE_DETACH`/`PT_DETACH` resume the
    /// tracee from the ptrace-stop and nothing else, so a `pause()` implemented
    /// with `SIGSTOP` survives the detach: the target stays frozen forever, and
    /// the caller — now detached — holds nothing that could un-stick it. The
    /// call returns `Ok(())` while leaving the inspected process dead in the
    /// water, which is the worst kind of success.
    ///
    /// Linux found this on a live target (`/proc/<pid>/stat` stuck at `T`) and
    /// fixed it; macOS, which no host here compiles, kept the defect.
    ///
    /// Not vacuous: the loop asserts it actually examined a backend that uses
    /// `SIGSTOP`, and checks separately that the Windows backend does not — its
    /// `pause()` is `DebugBreakProcess`, a debug event the detach path already
    /// continues, so requiring a SIGCONT there would be nonsense.
    #[test]
    fn a_backend_that_sigstops_to_pause_must_sigcont_when_it_detaches() {
        let mut checked = 0;
        for (name, raw) in [
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            // Comments stripped FIRST. Both files discuss SIGCONT in prose —
            // macOS quotes "the same stuck state `detach` already sends a
            // SIGCONT to undo" while its Detach handler sent none — so a guard
            // reading raw text passes on the strength of a sentence describing
            // the very behaviour that is missing. Measured: the first version
            // of this guard did exactly that.
            let owned = code_only(raw);
            let src: &str = &owned;
            let pause = item_body(
                src,
                "async fn pause(&self) -> Result<(), DebugError> {",
                &["\n    fn ", "\n    async fn "],
            );
            assert!(
                pause.contains("SIGSTOP"),
                "{name}: pause() no longer uses SIGSTOP — re-aim this guard rather than \
                 letting it pass on a backend it no longer describes"
            );
            let detach = item_body(
                src,
                "Command::Detach => {",
                &["\n            Command::", "\n        }"],
            );
            assert!(
                detach.contains("SIGCONT"),
                "{name}: the Detach handler never sends SIGCONT, so `pause()` followed by \
                 `detach()` leaves the target stopped forever with nobody attached to \
                 resume it"
            );
            checked += 1;
        }
        assert_eq!(checked, 2, "both SIGSTOP-based backends must be examined");

        let win = code_only(include_str!("windows_debugger.rs"));
        let win_pause = item_body(
            &win,
            "async fn pause(&self) -> Result<(), DebugError> {",
            &["\n    fn ", "\n    async fn "],
        );
        assert!(
            win_pause.contains("DebugBreakProcess"),
            "windows: pause() no longer raises a debug event — if it ever starts creating \
             a stop the detach path does not continue, it belongs in the loop above"
        );
    }

    /// Every backend must continue unwinding past the frame-pointer chain,
    /// with the unwind data its own platform emits.
    ///
    /// A frame-pointer-only backtrace does not fail: it returns a SHORT stack
    /// that looks complete. On optimized code — and on macOS's own x86-64
    /// system libraries — the chain breaks after a frame or two, and the caller
    /// receives a call stack that appears to begin in the middle of libsystem,
    /// with no error and no marker to say frames are missing. Windows has used
    /// `.pdata` and Linux `.eh_frame` for this since much earlier; macOS was
    /// the one backend still stopping where the chain did.
    #[test]
    fn every_backend_unwinds_past_the_frame_pointer_chain() {
        for (name, src, evidence) in [
            ("windows", include_str!("windows_debugger.rs"), "find_runtime_function"),
            ("linux", include_str!("linux_debugger.rs"), "cfi_unwind_one_frame"),
            ("macos", include_str!("macos_debugger.rs"), "unwind_one_frame_with_cfi"),
        ] {
            let body = item_body(
                src,
                "async fn backtrace(&self, tid: ThreadId) -> Result<Vec<StackFrame>, DebugError> {",
                &["\n    fn ", "\n    async fn "],
            );
            assert!(
                body.contains("FramePointerUnwinder"),
                "{name}: backtrace() no longer walks the frame-pointer chain at all"
            );
            assert!(
                body.contains(evidence),
                "{name}: backtrace() stops where the frame-pointer chain stops — it never \
                 reaches for {evidence}, so a stack through code without a frame pointer \
                 is silently truncated"
            );
        }
    }

    /// Item delimiters for [`item_body`], kept as consts so the guard below
    /// reads as one expression per line.
    const NEXT_FN: &str = "
    fn ";
    const NEXT_ASYNC_FN: &str = "
    async fn ";
    /// Delimiter for a TOP-LEVEL item, for guards that read a free function
    /// instead of a method.
    const NEXT_FN_TOP: &str = "
fn ";

    /// A pending breakpoint must resolve, or say it cannot — never report
    /// success and do nothing.
    ///
    /// The chain was complete except for its first link. `PendingBreakpoints`
    /// is careful and well tested, `arm_pending_breakpoints` is wired into
    /// `continue_execution` in all three backends, and an existing guard checks
    /// exactly that wiring — while `StopReason::LibraryLoad`, the event the
    /// whole mechanism hangs off, is **matched in three places and constructed
    /// in none**. `loaded` was therefore always empty, `add` always answered
    /// "not yet", and `set_pending_breakpoint` returned `Ok(())` for a
    /// breakpoint that could never exist.
    ///
    /// A guard that only checks the wiring passes on a dead feature; this one
    /// checks that the answer can be reached.
    #[test]
    fn a_pending_breakpoint_either_resolves_or_refuses() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let stripped = code_only(src);
            let body = item_body(
                &stripped,
                "async fn set_pending_breakpoint(&self, module: &str, offset: u64) -> Result<(), DebugError> {",
                &[NEXT_FN, NEXT_ASYNC_FN],
            );
            assert!(body.contains("note_module_loaded("), "{name}: set_pending_breakpoint never seeds the pending table from modules(), so it asks a table that only a LibraryLoad event fills — and a backend that does not construct that event would make every request wait forever");
            // Whether the not-yet-mapped case must REFUSE depends on whether
            // this backend can report a library load, so that half lives in
            // `only_backends_that_report_library_load_accept_a_not_yet_loaded_module`
            // where the capability is the thing being asserted.
        }
    }

    /// A failure of an OS call must carry what the OS said.
    ///
    /// `ReadProcessMemory` and `WriteProcessMemory` are the two calls a
    /// debugging session makes most, and both reported a bare
    /// "ReadProcessMemory failed" — one sentence for causes the user must act
    /// on differently:
    ///
    /// * `ERROR_PARTIAL_COPY` (299): the range runs into unmapped memory, so
    ///   the address is nearly right and the LENGTH is wrong;
    /// * `ERROR_ACCESS_DENIED` (5): protection, so no length will help;
    /// * `ERROR_INVALID_HANDLE` (6): the process is gone and every later call
    ///   will fail the same way.
    ///
    /// The same file already interpolates `GetLastError()` into seventeen other
    /// errors, so this was an inconsistency INSIDE one backend rather than a
    /// missing convention — which is why the guard checks the two named sites
    /// rather than counting occurrences.
    #[test]
    fn the_memory_calls_report_what_the_os_said() {
        let src = code_only(include_str!("windows_debugger.rs"));
        for call in ["ReadProcessMemory failed", "WriteProcessMemory failed"] {
            let at = src
                .find(call)
                .unwrap_or_else(|| panic!("guard misanchored: no {call} error site"));
            // The message is built where the error is constructed, so the
            // `GetLastError` that belongs to it is within the same expression.
            let window = &src[at..(at + 260).min(src.len())];
            assert!(
                window.contains("GetLastError"),
                "{call} is reported without the OS error code, so a partial copy, a protection failure and a dead process all read identically"
            );
        }
    }

    /// The AArch64 -> `dr` translation reads HARDWARE, so it must not describe
    /// a pattern it could not have produced.
    ///
    /// `merge_debug_state` on macOS calls this on the debug state read back
    /// from a thread. That state is not necessarily ours: another debugger, an
    /// earlier session, or the OS can leave a `BAS` outside the set this crate
    /// emits. `count_ones`/`trailing_zeros` describe any pattern at all, so the
    /// function answered for every one of them — and the answer flows into the
    /// engine as `DR7`, which uses it to pick free slots and to recognise its
    /// own watchpoints.
    #[test]
    fn the_arm64_to_dr_translation_refuses_patterns_it_could_not_have_written() {
        use crate::dr_slot_from_arm64_watchpoint as to_dr;
        // Enabled, store-only (`LSC = 0b10`), varying BAS.
        let wcr = |bas: u64| 1 | (0b10 << 1) | (0b10 << 3) | (bas << 5);

        // Two separate bytes, 0 and 7. Two bits set, so the old code called it
        // a 2-byte watchpoint at offset 0 — a range the hardware is not
        // watching.
        assert!(
            to_dr(0x1000, wcr(0b1000_0001), 0).is_none(),
            "a non-contiguous BAS has no DR7 spelling and must be refused, not averaged into one"
        );

        // Contiguous but straddling the aligned 4-byte region: DR7 cannot
        // express a 4-byte watchpoint at offset 2.
        assert!(
            to_dr(0x1000, wcr(0b0011_1100), 0).is_none(),
            "a contiguous but unaligned BAS still has no DR7 spelling"
        );

        // Everything this crate actually emits still translates.
        for (size, offset) in [(1u32, 0u32), (1, 5), (2, 0), (2, 6), (4, 0), (4, 4), (8, 0)] {
            let bas = ((1u64 << size) - 1) << offset;
            let (addr, dr7) = to_dr(0x1000, wcr(bas), 0)
                .unwrap_or_else(|| panic!("size {size} at offset {offset} is one we emit and must translate"));
            assert_eq!(addr, 0x1000 + u64::from(offset), "the byte offset must survive");
            assert_ne!(dr7, 0, "an armed slot must be enabled in DR7");
        }
    }

    /// An execution breakpoint covers exactly one byte, and the encoder must
    /// say so instead of encoding a combination the hardware does not define.
    ///
    /// Intel SDM Vol. 3, Table 17-2: `R/W = 00` (break on instruction execution)
    /// requires `LEN = 00`. The size validator accepted 1, 2, 4 and 8 for every
    /// kind, so an execution breakpoint of four bytes encoded cleanly as
    /// `R/W = 00, LEN = 11` and was written straight into DR7 — undefined by the
    /// manual, and reachable from `set_watchpoint_sized` and from the MCP
    /// `kind: "execute"` surface.
    ///
    /// It refuses rather than narrowing to one byte: quietly giving a caller a
    /// quarter of what they asked for looks like it worked.
    #[test]
    fn an_execution_breakpoint_is_one_byte_or_it_is_refused() {
        // The one width the hardware defines for R/W=00 still works.
        let dr7 = x86_encode_watchpoint_dr7(0, 0, 0x1000, BreakpointKind::Hardware, 1)
            .expect("a 1-byte execution breakpoint is exactly what the hardware allows");
        assert_eq!((dr7 >> 16) & 0b11, 0b00, "R/W must be 00 for execution");
        assert_eq!((dr7 >> 18) & 0b11, 0b00, "LEN must be 00 for execution");

        for size in [2u8, 4, 8] {
            let err = x86_encode_watchpoint_dr7(0, 0, 0x1000, BreakpointKind::Hardware, size)
                .expect_err("an execution breakpoint wider than one byte is undefined on x86");
            let msg = err.to_string();
            assert!(
                msg.contains("one byte"),
                "the refusal must say what the hardware actually allows: {msg}"
            );
        }

        // Data watchpoints are unaffected: their widths are the point.
        for (size, len) in [(1u8, 0b00u64), (2, 0b01), (4, 0b11), (8, 0b10)] {
            let dr7 = x86_encode_watchpoint_dr7(0, 0, 0x1000, BreakpointKind::DataWrite, size)
                .expect("data watchpoints keep every width the hardware defines");
            assert_eq!((dr7 >> 18) & 0b11, len, "{size} bytes must encode as LEN {len:#04b}");
        }
    }

    /// The 8-byte encoding is a 64-bit-mode feature, not a universal one.
    #[test]
    fn the_eight_byte_length_is_only_offered_where_it_exists() {
        let r = x86_encode_watchpoint_dr7(0, 0, 0x1000, BreakpointKind::DataWrite, 8);
        if cfg!(target_pointer_width = "64") {
            let dr7 = r.expect("64-bit targets have LEN=10");
            assert_eq!((dr7 >> 18) & 0b11, 0b10);
        } else {
            let msg = r.expect_err("LEN=10 is reserved on 32-bit").to_string();
            assert!(msg.contains("32-bit"), "the refusal must name the reason: {msg}");
        }
    }

    /// Every OS resource handed to this crate must be given back.
    ///
    /// Two leaks of the same shape, one per platform, both invisible until the
    /// relevant table runs out:
    ///
    /// - Windows hands a file handle with `LOAD_DLL_DEBUG_INFO::hFile` and
    ///   `CREATE_PROCESS_DEBUG_INFO::hFile`, documented as the debugger's to
    ///   close. `hFile` appeared nowhere in the backend, so one handle leaked
    ///   per image the target loaded, for the whole session.
    /// - macOS resolves a task port in `ptrace_loop` and never released it.
    ///   `task_for_pid` adds a send right on every call — this crate says so
    ///   itself, in the comment on `threads()`, which releases the port it
    ///   resolves for exactly that reason. Twelve `return` paths, no release.
    ///
    /// The Windows half is also covered behaviourally by
    /// `library_load_handles_are_returned_to_windows`, which measures this
    /// process's own handle count. macOS has no executed tests at all, so the
    /// structural check is the only thing standing between that leak and a
    /// release.
    #[test]
    fn os_resources_handed_to_the_debugger_are_given_back() {
        let win = code_only(include_str!("windows_debugger.rs"));
        assert!(
            win.contains("fn event_file_handle("),
            "windows: nothing takes ownership of the file handle Windows attaches to a debug event, so one leaks per image load"
        );
        assert!(
            win.contains("owed_handle.take()") && win.contains("CloseHandle(h)"),
            "windows: the event file handle is identified but never closed"
        );
        // It must be closed AFTER the event is acknowledged, never inside the
        // window where the target is stopped on an unacknowledged event —
        // iteration 504 proved by bisection that calling into the OS there
        // breaks hardware watchpoint hit detection.
        let ack = win.find("ContinueDebugEvent(pid, last_tid, continue_status);");
        let close = win.find("owed_handle.take()");
        let (ack, close) = (ack.expect("the acknowledge site is gone"), close.expect("the close site is gone"));
        assert!(
            ack < close,
            "windows: the event file handle is closed BEFORE ContinueDebugEvent acknowledges the event, which is the window iteration 504 showed is not safe to call into"
        );

        let mac = code_only(include_str!("macos_debugger.rs"));
        assert!(
            mac.contains("struct OwnedTaskPort"),
            "macos: ptrace_loop resolves a task port with no owner, and task_for_pid adds a send right on every call — one leaks per session"
        );
        assert!(
            mac.contains("impl Drop for OwnedTaskPort") && mac.contains("release_port(self.0)"),
            "macos: OwnedTaskPort does not actually give the send right back"
        );
    }

    /// `classify_event` must not ask the OS about the traced process.
    ///
    /// It runs on the debug-loop thread while the target is stopped on an event
    /// that has NOT been acknowledged with `ContinueDebugEvent` yet. A psapi
    /// query in that window broke hardware watchpoint hits outright: all three
    /// of `a_debug_register_hit_is_reported_as_a_breakpoint_not_a_single_step`
    /// and its siblings went red, every hit arriving as a plain single step
    /// because `DR6` no longer read as set.
    ///
    /// Established by bisection, not by reasoning: the identical match arm
    /// emitting the identical `LibraryLoad` variant with a CONSTANT path leaves
    /// all 81 live tests green. The variant, the match and the downstream
    /// `resolve_on_load` branch are all innocent; the query is not.
    ///
    /// The rule is narrow on purpose. `classify_event` may read the event
    /// structure itself — that is just memory the OS already handed us — but it
    /// must not call back into the OS about the process.
    #[test]
    fn classify_event_does_not_query_the_traced_process() {
        let src = code_only(include_str!("windows_debugger.rs"));
        let body = item_body(&src, "fn classify_event(ev: &DEBUG_EVENT) -> StopReason {", &[NEXT_FN_TOP]);
        for call in ["GetMappedFileNameW", "CreateToolhelp32Snapshot", "OpenProcess", "ReadProcessMemory"] {
            assert!(!body.contains(call), "windows: classify_event queries the OS about the traced process. That runs on the debug-loop thread with the event not yet acknowledged, and it breaks hardware watchpoint hit detection: every hit comes back classified as an ordinary single step because DR6 no longer reads as set. Proved by bisection in iteration 504.");
        }
        // And it must still classify the load, or the pending mechanism has no
        // first link at all (the dead feature iteration 502 found).
        assert!(
            body.contains("LOAD_DLL_DEBUG_EVENT =>"),
            "windows: classify_event no longer classifies library loads, so pending breakpoints are dead again"
        );
    }

    /// The name has to be filled in somewhere, and that somewhere is the async side.
    #[test]
    fn a_library_load_is_named_after_the_event_is_delivered() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let stripped = code_only(src);
            let body = item_body(
                &stripped,
                "async fn arm_pending_breakpoints(&self, event: &mut DebugEvent) {",
                &[NEXT_FN, NEXT_ASYNC_FN],
            );
            assert!(body.contains("self.modules().await"), "{name}: arm_pending_breakpoints does not name a library load, so the pending table is matched against an empty path and nothing can ever resolve");
            // An unresolvable base must leave the path empty, never invent one:
            // a fabricated name matches no request, or the wrong one.
            assert!(
                body.contains("path.is_empty()"),
                "{name}: arm_pending_breakpoints overwrites a path it was given instead of only filling an empty one"
            );
        }
    }

    /// Which backends can honour a request for a module that is NOT mapped yet.
    ///
    /// A pending breakpoint can only arm if something constructs
    /// `StopReason::LibraryLoad`. Iteration 502 found that NOBODY did, on any
    /// OS, while `set_pending_breakpoint` returned `Ok(())` — so the refusal it
    /// added is correct exactly where the event is still missing, and wrong
    /// where it now exists.
    ///
    /// The 502 version of this test could not fire. Its predicate asked whether
    /// the file contained `StopReason::LibraryLoad {` and NOT the match arm —
    /// but a backend that constructs the variant also still MATCHES it in
    /// `arm_pending_breakpoints`, so both halves were true and the guard stayed
    /// green through the very change it was written to detect. Counting is what
    /// separates the two uses: more mentions than match arms means at least one
    /// of them builds the value.
    #[test]
    fn only_backends_that_report_library_load_accept_a_not_yet_loaded_module() {
        for (name, src, should_emit) in [
            ("windows", include_str!("windows_debugger.rs"), true),
            ("linux", include_str!("linux_debugger.rs"), false),
            ("macos", include_str!("macos_debugger.rs"), false),
        ] {
            let stripped = code_only(src);
            // Do not enumerate the syntactic forms — that has now failed three
            // times, each time because a later change added a use nobody had
            // listed: the match arm, then the `matches!` resume filter, then
            // the `if let ... = &mut event.reason` that names the load.
            //
            // Ask a structural question instead. `arm_pending_breakpoints` is
            // the one function that CONSUMES this variant; outside it, only a
            // backend that PRODUCES the variant has any reason to name it. So
            // cut that body out and look at what is left.
            let consumer = item_body(
                &stripped,
                "async fn arm_pending_breakpoints(&self, event: &mut DebugEvent) {",
                &[NEXT_FN, NEXT_ASYNC_FN],
            );
            let outside = stripped.replace(consumer, "");
            let emits = outside.contains("StopReason::LibraryLoad");
            assert_eq!(
                emits, should_emit,
                "{name}: emits LibraryLoad = {emits}, expected {should_emit}. If a backend just started emitting it, relax the refusal in its set_pending_breakpoint and flip the flag here."
            );

            // The refusal used to be tied to `should_emit`: only a backend that
            // could deliver the event was allowed to accept the request.
            //
            // That tie was broken deliberately (iteration 531). Emitting
            // `LibraryLoad` is no longer what makes a pending breakpoint
            // armable — `arm_pending_breakpoints` re-reads `modules()` at every
            // stop while anything is pending, which every backend can do. So
            // the capability the refusal must match is "can this backend ever
            // arm a pending request", and the answer is now yes everywhere:
            // NONE of them may refuse.
            //
            // `should_emit` above still records the honest fact that only
            // Windows constructs the event — that has not changed, and a
            // backend that starts emitting it will still be caught there.
            let body = item_body(
                &stripped,
                "async fn set_pending_breakpoint(&self, module: &str, offset: u64) -> Result<(), DebugError> {",
                &[NEXT_FN, NEXT_ASYNC_FN],
            );
            assert!(
                !body.contains("DebugError::Unsupported"),
                "{name}: set_pending_breakpoint refuses a not-yet-mapped module, but this backend can arm it from the per-stop module re-read"
            );
        }
    }

    /// "Armed" must mean the register holds it, not that the write call
    /// returned `Ok`.
    ///
    /// `set_watchpoint_sized` counted `armed += 1` for every `set_registers`
    /// that did not error. That is not the same fact. This crate already
    /// records why: a `SetThreadContext(CONTEXT_DEBUG_REGISTERS)` issued from
    /// the wrong thread on Windows "is accepted and silently does nothing".
    /// The call returns `Ok`, no debug register changes, and the caller is told
    /// the address is watched.
    ///
    /// Same family as iteration 493, one step earlier: there the DISARM
    /// trusted our bookkeeping instead of the machine; here the ARM trusted the
    /// return code instead of the machine.
    #[test]
    fn arming_a_watchpoint_verifies_the_registers_took_it() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let stripped = code_only(src);
            // Anchored on the arming loop itself, not on a signature: several
            // methods in this file share the same one.
            let full = &stripped;
            let loop_at = full
                .find("let mut armed = 0usize;")
                .unwrap_or_else(|| panic!("{name}: the arming loop is gone — guard misanchored"));
            let end = full[loop_at..]
                .find("if armed == 0 {")
                .unwrap_or_else(|| panic!("{name}: the arming loop no longer ends in the armed==0 check"));
            let arming = &full[loop_at..loop_at + end];
            assert!(arming.contains("self.get_registers(tid).await"), "{name}: set_watchpoint_sized counts a successful set_registers call as an armed thread, so a write the OS accepted and dropped still reports the address as watched");
            assert!(
                arming.contains("armed += 1")
                    && arming.contains("dr7 & (1u64 << (2 * u32::from(slot)))"),
                "{name}: set_watchpoint_sized reads the registers back but does not gate `armed` on what it found, so the verification is decoration"
            );
        }
    }

    /// The idempotency guard must be checked and ACTED ON without an `await`
    /// in between.
    ///
    /// `set_breakpoint` used to check `breakpoints.contains_key`, then await a
    /// `read_memory` and a `write_memory_raw`, and only then record the
    /// address. Two calls for one address can both pass a check made that far
    /// ahead of the act, and the interleaving is the one the guard's own
    /// comment describes: the loser reads back the winner's trap byte and
    /// stores it as "the original", so `remove_breakpoint` restores `0xCC`
    /// forever.
    ///
    /// The fix reserves the address under one lock BEFORE the write, and
    /// removes the reservation on every failure path — so the property the old
    /// ordering existed to protect (no phantom entry for a write that failed)
    /// still holds.
    ///
    /// Structural on purpose: the live twin
    /// `two_concurrent_set_breakpoints_do_not_corrupt_the_original_byte` passes
    /// against the old ordering too, so ordering is the only thing that can be
    /// pinned honestly here.
    #[test]
    fn set_breakpoint_records_the_address_before_it_plants_the_trap() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let stripped = code_only(src);
            let body = item_body(
                &stripped,
                "async fn set_breakpoint(&self, addr: Address, kind: BreakpointKind) -> Result<(), DebugError> {",
                &[NEXT_FN, NEXT_ASYNC_FN],
            );
            let reserve = body.find("planted.insert(addr.as_u64(), original)");
            // The LAST trap write in the body: the re-arm of a disabled
            // breakpoint legitimately writes before this point.
            let plant = body.rfind("write_memory_raw(addr, crate::host_trap_bytes())");
            let reserve = reserve.unwrap_or_else(|| panic!("{name}: set_breakpoint plants the trap before recording the address, so the idempotency guard is checked and acted on either side of two await points"));
            let plant = plant.expect("guard misanchored: set_breakpoint no longer plants a trap");
            assert!(reserve < plant, "{name}: set_breakpoint plants the trap before recording the address, so the idempotency guard is checked and acted on either side of two await points");
            // And the reservation must be undone when the plant fails, or the
            // fix trades one defect for the phantom entry the old ordering
            // was written to avoid.
            assert!(
                body.matches("self.breakpoints.lock().remove(&addr.as_u64())").count() >= 2,
                "{name}: set_breakpoint does not roll the reservation back on both failure paths, so a failed plant leaves a phantom breakpoint"
            );
        }
    }

    /// A stop event must report the breakpoint the session TRACKS, not a new one.
    ///
    /// The event is classified on the debug-loop thread, which has no `&self`,
    /// so the only breakpoint it can build is `Breakpoint::new_software` /
    /// `new_hardware` — every field at its default. Consumers of
    /// `StopReason::Breakpoint { bp }` therefore saw `enabled: true`,
    /// `hit_count: 0`, `condition: None` and (since 491/492) `ignore_count: 0`,
    /// `only_thread: None`, `byte_size: None` for a breakpoint that may be
    /// conditional, thread-restricted, hit fifty times and eight bytes wide.
    ///
    /// Fabricated rather than missing: plausible values, uniformly wrong.
    #[test]
    fn a_stop_event_reports_the_tracked_breakpoint_not_a_fresh_one() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let stripped = code_only(src);
            // Both funnels that hand an event to the caller.
            for fn_ in [
                "async fn continue_execution(&self) -> Result<DebugEvent, DebugError> {",
                "async fn single_step_raw(&self, tid: ThreadId) -> Result<DebugEvent, DebugError> {",
            ] {
                let body = item_body(&stripped, fn_, &[NEXT_FN, NEXT_ASYNC_FN]);
                assert!(body.contains("enrich_event_breakpoint("), "{name}: {fn_} returns the event without enriching its breakpoint record, so the caller reads a fabricated all-defaults breakpoint");
            }
            // And the enrichment must cover every field a caller can read,
            // not the two that were easy.
            let body = item_body(
                &stripped,
                "fn enrich_event_breakpoint(&self, ev: &mut DebugEvent) {",
                &[NEXT_FN, NEXT_ASYNC_FN],
            );
            for field in [
                "original_byte", "byte_size", "hit_count", "enabled", "condition",
                "ignore_count", "only_thread",
            ] {
                assert!(body.contains(field), "{name}: enrich_event_breakpoint does not fill `{field}`, so that field of the reported breakpoint is a default rather than what the session tracks");
            }
        }
    }

    /// The destructor must do the same teardown on all three backends.
    ///
    /// `Drop` is the teardown nobody calls on purpose, which is why it drifts:
    /// Windows and Linux disarmed the debug registers there, macOS did not, and
    /// nothing noticed because macOS is the backend whose tests never run.
    ///
    /// Dropping an attached `MacosDebugger` with a watchpoint armed therefore
    /// detached the process and left the watchpoint programmed. The target
    /// keeps trapping, no debugger is left to take the trap, and the kernel
    /// kills it — the defect iteration 493 closed for the explicit `detach()`
    /// path, still open on the implicit one.
    #[test]
    fn every_destructor_tears_the_session_down_the_same_way() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let stripped = code_only(src);
            let body = item_body(&stripped, "fn drop(&mut self) {", &[NEXT_FN, NEXT_ASYNC_FN]);
            assert!(body.contains("Command::WriteMemory"), "{name}: Drop no longer restores the planted bytes — guard misanchored");
            // The disarm, recognised by the register write rather than by any
            // one helper name: the three backends reach the threads by
            // different routes and only the effect has to match.
            assert!(
                body.contains(r#"regs.set(name, 0)"#) && body.contains(r#""dr7""#),
                "{name}: Drop does not disarm the debug registers, so dropping an attached debugger leaves the target trapping with nothing to take the trap — the kernel then kills it"
            );
            assert!(body.contains("hw_watchpoints.lock().clear()"), "{name}: Drop does not clear `hw_watchpoints`, the eighth per-address map");
        }
    }

    /// `pc`/`sp`/`fp` were a live READ path and a dead WRITE path.
    ///
    /// Every backend fills those three fields when a register set is read, and
    /// this crate's own comment says callers use them "instead of the
    /// named-register map" — `backtrace`, `step_over` and `step_out` all do.
    /// But every `apply_register_set` writes back from the MAP only, so the
    /// obvious use of the public API set a program counter that never took
    /// effect and returned `Ok(())` for it.
    #[test]
    fn set_registers_reconciles_the_typed_register_view() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let stripped = code_only(src);
            let body = item_body(
                &stripped,
                "async fn set_registers(&self, tid: ThreadId, mut regs: RegisterSet) -> Result<(), DebugError> {",
                &[NEXT_FN, NEXT_ASYNC_FN],
            );
            assert!(body.contains("sync_map_from_special()"), "{name}: set_registers() does not reconcile the typed pc/sp/fp view into the map, so a caller that writes regs.pc gets Ok(()) and a thread that never moved");
        }
    }

    /// Writing the typed field must reach the map, and writing the named
    /// register must reach the typed field. Both directions, because the bug
    /// existed in both.
    #[test]
    fn the_typed_view_and_the_named_map_stay_in_step() {
        let arch = crate::instr_step::native_arch();
        let (pc_key, sp_key, fp_key) = (
            crate::instr_step::pc_key(arch),
            crate::instr_step::sp_key(arch),
            crate::instr_step::fp_key(arch),
        );

        // Typed -> map.
        let mut r = RegisterSet::new();
        r.pc = 0x1111;
        r.sp = 0x2222;
        r.fp = Some(0x3333);
        r.sync_map_from_special();
        assert_eq!(r.get(pc_key), Some(0x1111), "regs.pc never reached the map");
        assert_eq!(r.get(sp_key), Some(0x2222));
        assert_eq!(r.get(fp_key), Some(0x3333));

        // Map -> typed.
        let mut r = RegisterSet::new();
        r.set(pc_key, 0xAAAA);
        r.set(sp_key, 0xBBBB);
        r.set(fp_key, 0xCCCC);
        assert_eq!(r.pc, 0xAAAA, "setting {pc_key} left regs.pc stale");
        assert_eq!(r.sp, 0xBBBB);
        assert_eq!(r.fp, Some(0xCCCC));

        // Last writer wins, in either direction — the precedence rule the
        // reconciliation depends on.
        let mut r = RegisterSet::new();
        r.set(pc_key, 1);
        r.pc = 2;
        r.sync_map_from_special();
        assert_eq!(r.get(pc_key), Some(2), "the later typed write must win");

        // An absent frame pointer must stay absent, not become 0 — a frame
        // pointer of zero is a value, and unwinders act on it.
        let mut r = RegisterSet::new();
        r.fp = None;
        r.sync_map_from_special();
        assert_eq!(r.get(fp_key), None, "a missing frame pointer must not be materialised as 0");
    }

    /// Every name a backend WRITES the frame pointer under must reach the
    /// typed field.
    ///
    /// The frame pointer is the one register this crate spells two ways, and
    /// both spellings are in live use: `macos_debugger` does `set("fp", …)`
    /// AND `set("x29", …)` on the same read, then reads back with
    /// `get("x29").or_else(|| get("fp"))`. `set` matched only `fp_key`, which
    /// on AArch64 is `"x29"` — so `set("fp", …)` updated the map and left the
    /// typed `fp` field untouched, and `backtrace`/`step_out`, which the
    /// crate's own comment says consult the typed fields, saw NO frame
    /// pointer.
    ///
    /// Asked across the seam rather than restated: the names come from what
    /// the backends actually write, not from re-deriving the table.
    #[test]
    fn both_spellings_of_the_frame_pointer_reach_the_typed_field() {
        use crate::instr_step::{StepArch, fp_key, is_fp_name, native_arch};

        // On AArch64 both names denote the frame pointer; on x86 the ARM name
        // must NOT be accepted, or an unrelated register would be mistaken for
        // it.
        assert!(is_fp_name(StepArch::Aarch64, "x29"));
        assert!(is_fp_name(StepArch::Aarch64, "fp"));
        assert!(is_fp_name(StepArch::X86_64, "rbp"));
        assert!(!is_fp_name(StepArch::X86_64, "fp"), "x86-64 has no register called fp");
        assert!(!is_fp_name(StepArch::X86, "fp"));

        // And the reason it matters, on this build's own architecture.
        let arch = native_arch();
        let mut r = RegisterSet::new();
        r.set(fp_key(arch), 0x1000);
        assert_eq!(r.fp, Some(0x1000));

        if matches!(arch, StepArch::Aarch64) {
            let mut r = RegisterSet::new();
            r.set("fp", 0x2000);
            assert_eq!(
                r.fp,
                Some(0x2000),
                "a backend writing the frame pointer as `fp` left the typed field stale"
            );
        }
    }

    /// A short write is not a small success.
    ///
    /// `write_memory_raw` returns the byte COUNT, and every breakpoint
    /// plant/restore threw it away: `?` catches an `Err`, but a short `Ok(n)`
    /// went straight through. `write_memory` has refused short writes on the
    /// public API for a long time; the internal path it is built on did not.
    ///
    /// On x86 the trap is one byte and this cannot bite. On AArch64 it is FOUR,
    /// and a partly written `BRK` is neither the original instruction nor a
    /// trap — while `remove_breakpoint` untracks the address immediately after,
    /// turning a half-restore into a landmine with nothing left tracking it.
    #[test]
    fn breakpoint_writes_refuse_to_land_only_partly() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let stripped = code_only(src);
            for site in [
                "async fn set_breakpoint(&self, addr: Address, kind: BreakpointKind) -> Result<(), DebugError> {",
                "async fn remove_breakpoint(&self, addr: Address) -> Result<(), DebugError> {",
                "async fn disable_breakpoint(&self, addr: Address) -> Result<(), DebugError> {",
            ] {
                let body = item_body(&stripped, site, &[NEXT_FN, NEXT_ASYNC_FN]);
                let writes = body.matches("write_memory_raw(").count();
                let checks = body.matches("require_full_write(").count();
                assert!(writes > 0, "{name}: {site} no longer writes memory — guard misanchored");
                assert_eq!(checks, writes, "{name}: {site} ignores how many bytes write_memory_raw actually wrote, so a partly written trap reads as a breakpoint that is set and a partly restored instruction reads as one that is clean");
            }
        }
    }

    /// The helper itself: short is an error, exact and over are not.
    #[test]
    fn require_full_write_only_refuses_short_writes() {
        assert!(require_full_write(0x1000, 4, 4).is_ok());
        // A driver that reports MORE than asked is odd but has not lost data;
        // refusing it would turn a harmless surprise into a failed breakpoint.
        assert!(require_full_write(0x1000, 5, 4).is_ok());
        let e = require_full_write(0x1000, 1, 4).expect_err("1 of 4 bytes is not a success");
        let msg = e.to_string();
        assert!(msg.contains("1 of 4"), "the error must say how much landed: {msg}");
        // Zero is the common real case (a dead target) and must not be special.
        assert!(require_full_write(0x1000, 0, 1).is_err());
    }

    /// Disarming hardware must be driven by the MACHINE, not by our model of it.
    ///
    /// `disarm_all_hardware_watchpoints` opened with
    /// `if self.hw_watchpoints.lock().is_empty() { return; }`. That map is our
    /// bookkeeping; what kills the detached target is DR7 inside the target,
    /// and the two are not the same object.
    ///
    /// The gap is demonstrated, not imagined: `set_registers` is a public trait
    /// method, and our own MCP `debug.set_watchpoint` tool arms DR0-3/DR7
    /// through it from a separate per-session `WatchpointEngine`. Every
    /// watchpoint set that way left `hw_watchpoints` empty, so this function
    /// returned having cleared nothing, and the process kept trapping after the
    /// detach with no debugger to take the trap — the SIGTRAP hazard `detach`
    /// already documents for the software half, reappearing one layer down.
    ///
    /// The per-thread `dr7 == 0` skip inside the loop is the correct place for
    /// the fast path, because it asks the target instead of asking us.
    #[test]
    fn disarming_hardware_watchpoints_is_not_gated_on_our_own_bookkeeping() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let stripped = code_only(src);
            let body = item_body(
                &stripped,
                "async fn disarm_all_hardware_watchpoints(&self) -> Result<(), DebugError> {",
                &[NEXT_FN, NEXT_ASYNC_FN],
            );
            assert!(
                !body.contains("hw_watchpoints.lock().is_empty()"),
                "{name}: disarm_all_hardware_watchpoints() returns early when `hw_watchpoints` is empty, so debug registers armed without going through set_watchpoint_sized survive the detach and the target is killed by its own trap"
            );
            // It must still actually walk the threads and clear the registers —
            // a guard that only forbids the early return would pass on a body
            // that had been emptied entirely.
            assert!(
                body.contains("self.threads().await") && body.contains("regs.set(\"dr7\", 0)"),
                "{name}: disarm_all_hardware_watchpoints() no longer walks the threads clearing DR7"
            );
        }
    }

    /// A listing must not NARROW a value it already holds.
    ///
    /// Different defect from the missing-field one below: `hw_watchpoints` maps
    /// an address to `(kind, size)`, the listing had both in hand, and the
    /// rendering bound the width to `_size` and dropped it. Every watchpoint was
    /// therefore published without the one attribute that says how much memory
    /// it covers.
    ///
    /// It bites on the round trip. `set_watchpoint_sized` takes a width; a
    /// caller that lists the watchpoints and arms them again — a session
    /// restore, or a second target being brought into line with the first —
    /// gets the address right and the extent wrong. Re-arming an 8-byte region
    /// as 1 byte watches one eighth of it and reports success.
    #[test]
    fn the_listing_does_not_discard_the_watchpoint_width() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let stripped = code_only(src);
            let body = item_body(
                &stripped,
                "async fn breakpoints(&self) -> Result<Vec<Breakpoint>, DebugError> {",
                &[NEXT_FN, NEXT_ASYNC_FN],
            );
            assert!(body.contains("byte_size: Some(size)"), "{name}: breakpoints() destructures the watchpoint width and discards it, so an 8-byte watchpoint lists identically to a 1-byte one and cannot be re-armed from the listing");
            // And the discarding destructure must be gone, not merely joined
            // by the right one elsewhere in the body. The needle is the exact
            // pattern, not the bare "_size" — that is a substring of
            // "byte_size" and the guard would fail on its own fix.
            assert!(
                !body.contains("(kind, _size)"),
                "{name}: breakpoints() still binds the watchpoint width to a discarded name"
            );
        }
    }

    /// An execution breakpoint has no width, and must not claim one.
    #[test]
    fn only_data_watchpoints_carry_a_width() {
        assert_eq!(Breakpoint::new_software(Address(0x10)).byte_size, None);
        assert_eq!(Breakpoint::new_hardware(Address(0x10)).byte_size, None);
    }

    /// A breakpoint listing must publish EVERY reason an enabled breakpoint
    /// does not stop.
    ///
    /// `breakpoints()` reported the address, the kind, the enabled flag, the hit
    /// count, the original byte and the condition — and neither the ignore count
    /// nor the thread restriction. Both are accepted by the API, both silently
    /// suppress a stop, and neither could be read back.
    ///
    /// The thread filter is the worse omission of the two. A wrong-thread
    /// crossing is deliberately not added to `hit_count`, so a breakpoint that
    /// other threads cross constantly presents as `hit_count: 0` on an enabled
    /// breakpoint — indistinguishable from an address the program never
    /// reaches. That blind spot is precisely what let the stale-filter defect of
    /// iteration 489 survive: there was no listing that could have shown it.
    ///
    /// Both listings must report both: `condition_allows_stop` applies the two
    /// gates to hardware watchpoints exactly as it does to software breakpoints,
    /// so a watchpoint whose entry is only in the second chain would still be
    /// listed without them.
    #[test]
    fn the_breakpoint_listing_publishes_every_reason_a_stop_is_suppressed() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let stripped = code_only(src);
            let body = item_body(
                &stripped,
                "async fn breakpoints(&self) -> Result<Vec<Breakpoint>, DebugError> {",
                &[NEXT_FN, NEXT_ASYNC_FN],
            );
            for map in ["ignore_counts", "thread_filters"] {
                let needle = format!("self.{map}.lock().get(&addr)");
                assert!(body.contains(&needle), "{name}: breakpoints() never reads `{map}`, so a caller can set that restriction and then has no way to observe it");
                assert!(body.matches(&needle).count() >= 2, "{name}: breakpoints() reads `{map}` only once, so only one of the software and hardware listings reports it");
            }
        }
    }

    /// The two new fields must default to "no restriction" on every
    /// constructor, so a breakpoint nobody restricted never reads as restricted.
    #[test]
    fn a_fresh_breakpoint_carries_no_restriction() {
        for bp in [
            Breakpoint::new_software(Address(0x1000)),
            Breakpoint::new_hardware(Address(0x1000)),
            Breakpoint::new_watchpoint(Address(0x1000), BreakpointKind::DataWrite),
        ] {
            assert_eq!(bp.ignore_count, 0, "{:?} starts with hits to skip", bp.kind);
            assert_eq!(bp.only_thread, None, "{:?} starts restricted to a thread", bp.kind);
        }
    }

    /// The same "N of N+1" defect, at the OTHER sweep site: session retirement.
    ///
    /// `retire_session_after_exit` runs when the debuggee exits on its own —
    /// the third way a session ends, alongside `detach` and `kill`, and the one
    /// nobody calls. It cleared seven of the eight per-address maps on all three
    /// backends; `hw_watchpoints` was the eighth.
    ///
    /// That one is not passive bookkeeping. `rearm_watchpoints_on_new_threads`
    /// reads it on every resume and programs the debug registers from it, so a
    /// surviving entry does not merely describe a watchpoint that is gone: the
    /// first resume of the NEXT process arms DR0-DR3 at an address from a
    /// program that no longer exists.
    #[test]
    fn session_retirement_forgets_every_per_address_map() {
        let maps = [
            "breakpoints", "hit_counts", "ignore_counts", "disabled", "conditions",
            "thread_filters", "pending", "hw_watchpoints",
        ];
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            // Comments stripped first: the fix names `hw_watchpoints` in prose
            // right beside the line this guard looks for.
            let stripped = code_only(src);
            let op = "fn retire_session_after_exit(&self) {";
            let body = item_body(&stripped, op, &[NEXT_FN, NEXT_ASYNC_FN]);
            for map in maps {
                let needle = format!("self.{map}.lock().clear()");
                assert!(body.contains(&needle), "{name}: {op} never clears `{map}`, so the entry outlives the process it described and is inherited by the next one");
            }
        }
    }

    /// `remove_breakpoint` must forget EVERY per-address map, not five of six.
    ///
    /// The five that were swept — hit counts, ignore counts, the disabled set,
    /// the condition, the hardware watchpoint — are all keyed by address, and
    /// the source already spells out why each must go: leaving one behind
    /// attaches it to whatever breakpoint is set at that address NEXT. The
    /// thread filter was added later and never joined the sweep, so it
    /// outlived its breakpoint on all three backends at once.
    ///
    /// Its survival is the worst of the six. `condition_allows_stop` gates the
    /// thread filter FIRST and deliberately does not count a wrong-thread
    /// crossing, so the replacement breakpoint does not look like one that
    /// keeps being skipped — it looks like one the program never reaches.
    #[test]
    fn remove_breakpoint_forgets_every_per_address_map() {
        let maps = [
            "hit_counts", "ignore_counts", "disabled", "conditions", "thread_filters",
        ];
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            // Comments stripped FIRST: the fix carries a comment naming the
            // very map this guard looks for, which would make it vacuous.
            let stripped = code_only(src);
            let body = item_body(
                &stripped,
                "async fn remove_breakpoint(&self, addr: Address) -> Result<(), DebugError> {",
                &[NEXT_FN, NEXT_ASYNC_FN],
            );
            for map in maps {
                let needle = format!("self.{map}.lock().remove(&addr.as_u64())");
                assert!(body.contains(&needle), "{name}: remove_breakpoint() never clears `{map}` for the address it removes, so the entry outlives its breakpoint and silently applies to the next breakpoint set at the same address");
            }
        }
    }

    /// Every backend must apply a thread restriction, and must apply it BEFORE
    /// the pass count.
    ///
    /// The order is the whole point. A crossing by another thread is not a hit
    /// of a thread-restricted breakpoint at all; if it reaches the pass-count
    /// gate first it consumes one of the skips, so `ignore 3` on thread 7 is
    /// spent by three crossings of threads 2, 5 and 9 and the debugger stops on
    /// thread 7's FIRST crossing — the opposite of what was asked, with a
    /// perfectly plausible-looking stop to show for it.
    ///
    /// The wrong-thread crossing is also un-counted, unlike a pass-count skip:
    /// `breakpoints()` publishes `hit_count`, and counting other threads there
    /// would contradict what the user is watching happen.
    #[test]
    fn every_backend_applies_the_thread_filter_before_the_pass_count() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            assert!(
                src.contains("async fn set_breakpoint_thread_filter("),
                "{name}: does not implement set_breakpoint_thread_filter, so the trait \
                 default refuses and this backend has no thread-restricted breakpoints"
            );
            let body = item_body(
                src,
                "async fn condition_allows_stop(&self, event: &DebugEvent) -> bool {",
                &["\n    fn ", "\n    async fn "],
            );
            let thread_gate = body.find("thread_filters").unwrap_or_else(|| {
                panic!(
                    "{name}: condition_allows_stop() never reads the thread filters, so a \
                     breakpoint restricted to one thread stops for every thread"
                )
            });
            let ignore_gate = body
                .find("ignore_counts")
                .expect("the pass-count gate is checked by its own guard");
            assert!(
                thread_gate < ignore_gate,
                "{name}: the thread filter runs AFTER the pass count, so crossings by \
                 threads the caller excluded still consume the skips"
            );
            assert!(
                src.contains("self.thread_filters.lock().clear();"),
                "{name}: thread filters outlive the session and would silence a \
                 breakpoint in the next process, whose thread ids are unrelated"
            );
        }
    }

    /// Every backend must actually CONSULT its pass counts when a breakpoint
    /// fires, and must not un-count a hit it skipped for that reason.
    ///
    /// The second half is the subtle one. `condition_allows_stop` deliberately
    /// DECREMENTS the hit count for a stop filtered by a condition — that hit
    /// did not fire. Applying the same treatment to an ignore count would make
    /// the running total never grow past it, so "skip the next 3" would become
    /// "never stop again": a breakpoint that reports itself as set, armed, and
    /// simply never reached.
    #[test]
    fn every_backend_consults_pass_counts_without_un_counting_the_skipped_hit() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            assert!(
                src.contains("async fn set_breakpoint_ignore_count("),
                "{name}: does not implement set_breakpoint_ignore_count, so the trait \
                 default refuses and this backend has no pass counts"
            );
            let body = item_body(
                src,
                "async fn condition_allows_stop(&self, event: &DebugEvent) -> bool {",
                &["\n    fn ", "\n    async fn "],
            );
            assert!(
                body.contains("ignore_counts"),
                "{name}: condition_allows_stop() never reads the pass counts, so a hit \
                 the caller asked to skip stops anyway"
            );
            let gate = body
                .find("ignore_counts")
                .expect("checked just above");
            // `rfind`: the thread filter added in iter 446 un-counts too, and
            // it sits BEFORE the pass-count gate by design. The branch this
            // guard is about is the condition path's, which is the last one in
            // the function.
            let uncount = body
                .rfind("saturating_sub(1)")
                .expect("the condition path must still un-count its own skipped stop");
            assert!(
                gate < uncount,
                "{name}: the pass-count gate runs AFTER the un-counting branch, so a \
                 skipped hit is subtracted again and the ignore count never expires"
            );
            assert!(
                src.contains("self.ignore_counts.lock().clear();"),
                "{name}: pass counts outlive the session and would silence a breakpoint \
                 in the next process"
            );
        }
    }

    /// Every backend must actually CONSULT its pending-breakpoint table when a
    /// library loads.
    ///
    /// A table that is written by `set_pending_breakpoint` and never read at
    /// load time is the "accepted and forgotten" shape this crate keeps
    /// finding: the call returns `Ok`, the module loads, and the trap is never
    /// armed — indistinguishable, from the caller's seat, from a breakpoint
    /// that was armed and never hit.
    ///
    /// Scoped to the body of `continue_execution` on purpose: the resolver
    /// merely EXISTING in the file is exactly what the unwired version looked
    /// like.
    #[test]
    fn every_backend_arms_pending_breakpoints_when_a_library_loads() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            assert!(
                src.contains("async fn set_pending_breakpoint("),
                "{name}: does not implement set_pending_breakpoint, so the trait \
                 default refuses and this backend has no pending breakpoints"
            );
            let body = item_body(
                src,
                "async fn continue_execution(&self) -> Result<DebugEvent, DebugError> {",
                &["\n    fn ", "\n    async fn "],
            );
            assert!(
                body.contains("arm_pending_breakpoints"),
                "{name}: continue_execution() never consults the pending table, so a \
                 LibraryLoad arms nothing and set_pending_breakpoint reports a success \
                 that never happens"
            );
            assert!(
                src.contains("self.pending.lock().clear();"),
                "{name}: the pending table outlives the session, so the next process's \
                 request would resolve at the previous process's load base"
            );
        }
    }

    /// Every backend must un-patch before measuring, not just one.
    #[test]
    fn every_backend_unpatches_instruction_bytes_in_step_over() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let body = item_body(
                src,
                "async fn step_over(&self, tid: ThreadId) -> Result<DebugEvent, DebugError> {",
                &["
    fn ", "
    async fn "],
            );
            let unpatches = body.find("unpatch_planted_breakpoints");
            // Iter 443 moved the measurement itself behind the arch-correct
            // primitive, so the site to order against is whichever one the
            // backend uses; requiring one of them keeps the guard non-vacuous
            // if a backend ever stops measuring at all.
            let measures = body
                .find("step_over_return_addr")
                .or_else(|| body.find("instr_length"));
            assert!(
                measures.is_some(),
                "{name}: step_over() no longer measures the instruction at all, \
                 so its return address cannot be right"
            );
            assert!(
                unpatches.is_some(),
                "{name}: step_over() measures instruction length straight from                  read_memory — with a breakpoint planted it measures int3"
            );
            // Order matters: un-patching after the measurement fixes nothing.
            assert!(
                unpatches < measures,
                "{name}: step_over() un-patches AFTER measuring the instruction                  length, which is too late to affect the length"
            );
        }
    }

    /// Every backend must step off a planted breakpoint before resuming.
    ///
    /// A hit software breakpoint leaves the PC on the breakpoint address with
    /// our `0xCC` still planted, so resuming re-executes the trap and the
    /// target never advances past the first breakpoint it hits. Proved on a
    /// live Windows process by
    /// `continuing_from_a_planted_breakpoint_does_not_re_trap_at_the_same_address`;
    /// the code shape is identical in all three backends, and macOS is
    /// compiled by no host here, so the guard checks all three at the source.
    ///
    /// It is scoped to the body of `continue_execution` on purpose: the helper
    /// merely EXISTING in the file is what the defective version already
    /// looked like once the helper was written but not called.
    #[test]
    fn every_backend_steps_off_a_planted_breakpoint_before_resuming() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let body = item_body(
                src,
                "async fn continue_execution(&self) -> Result<DebugEvent, DebugError> {",
                &["
    fn ", "
    async fn "],
            );
            assert!(
                // L'ago segue la firma: il metodo ora prende il thread su cui
                // agire (None = quello che si e' fermato). L'invariante che
                // questa guard protegge non cambia.
                body.contains("step_off_planted_breakpoint(None)"),
                "{name}: continue_execution() resumes without stepping off a planted                  breakpoint — the target re-traps at the same address forever"
            );
        }
    }

    /// A local backend must not claim an architecture it was not built for.
    ///
    /// All three native backends drive processes on THIS machine through the
    /// local kernel interface (ptrace, the Windows debug API, mach), so the
    /// only architecture each can actually debug is its own build target.
    /// All three answered the hard-coded constant `x86_64` regardless, which
    /// on an aarch64 build (Apple Silicon, Linux ARM, Windows-on-ARM) is a
    /// confidently wrong answer to a question about itself. It is not
    /// cosmetic: `Debugger::supported_architectures` is documented as the
    /// value callers use to PICK a backend, so the wrong string propagates
    /// into backend selection.
    ///
    /// The runtime half checks the backend compiled for THIS host; the source
    /// half covers macOS, which no compiler on this machine builds. The
    /// source half looks for the absence of the literal AND the presence of
    /// the real resolver, because either check alone passes for the wrong
    /// reason — a body with neither would satisfy the first.
    #[test]
    fn no_backend_claims_an_architecture_it_was_not_built_for() {
        for (name, src) in [
            ("windows", include_str!("windows_debugger.rs")),
            ("linux", include_str!("linux_debugger.rs")),
            ("macos", include_str!("macos_debugger.rs")),
        ] {
            let body = item_body(
                src,
                "fn supported_architectures(&self) -> Vec<String> {",
                &["
    fn ", "
    async fn "],
            );
            assert!(
                !body.contains("vec![\"x86_64\""),
                "{name}: supported_architectures() still hard-codes x86_64 — an                  aarch64 build of this backend would advertise an architecture                  it cannot debug"
            );
            assert!(
                body.contains("env::consts::ARCH"),
                "{name}: supported_architectures() no longer derives its answer                  from the build target"
            );
        }
    }

    /// The backend built for this host must name this host's architecture.
    ///
    /// iOS is handled explicitly rather than left to fall off the end of the
    /// list. With only the three arms below, `dbg` was never bound on
    /// `target_os = "ios"`, the bare name then resolved to the std `dbg!`
    /// macro, and the crate did not COMPILE:
    ///
    /// ```text
    /// error[E0423]: expected value, found macro `dbg`
    ///   --> crates/rustre-debug/src/lib.rs:11859:22
    ///       let arches = dbg.supported_architectures();
    /// ```
    ///
    /// That error appeared the first time this crate was ever built for
    /// `aarch64-apple-ios-sim` (CI, 2026-08-14) — iOS is a platform this
    /// project targets, so it must not be able to disappear from a list in
    /// silence.
    #[tokio::test]
    async fn the_native_backend_reports_the_running_architecture() {
        // No LOCAL backend exists here, so there is no architecture claim to
        // check. On iOS the Apple backend drives a REMOTE target across a
        // transport (`ios::AppleDebugger` over RSP) rather than debugging the
        // process it runs inside, which is a different question from the one
        // this test asks.
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            return;
        }

        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        {
            #[cfg(windows)]
            let dbg = crate::windows_debugger::WindowsDebugger::default();
            #[cfg(target_os = "linux")]
            let dbg = crate::linux_debugger::LinuxDebugger::default();
            #[cfg(target_os = "macos")]
            let dbg = crate::macos_debugger::MacosDebugger::default();

            let arches = dbg.supported_architectures();
            assert!(
                arches.contains(&std::env::consts::ARCH.to_string()),
                "backend `{}` runs on {} but advertises {arches:?}",
                dbg.name(),
                std::env::consts::ARCH
            );
        }
    }

    /// `item_body` must not silently hand back the rest of the file.
    ///
    /// Five guards delimit a function body with it, and they are the only
    /// verification the macOS backend gets — it compiles on no host here. The
    /// helper panics when the START anchor is missing, but when no END marker
    /// matches it returns everything from the anchor onward. A body that spans
    /// the remaining file contains every needle any guard could look for, so a
    /// stale end-marker turns all five green at once, permanently and silently.
    ///
    /// That is the same shape as iteration 315 (a terminator that matched
    /// nothing, sliced to end-of-file) and of iteration 354's vacuous guard,
    /// and it is worse here because it degrades FIVE guards from one place.
    #[test]
    fn item_body_refuses_to_return_the_whole_rest_of_the_file() {
        // Normal case: the body stops at the next item.
        let code = "fn a() {
    let x = 1;
}

fn b() {
    needle();
}
";
        let body = item_body(code, "fn a(", &["
fn ", "
async fn "]);
        assert!(!body.contains("needle("), "`a`'s body must not reach into `b`");

        // Stale end marker on a file of realistic size — every source this
        // helper is pointed at is well over 20k characters. The helper must
        // refuse rather than return the remainder, because that remainder
        // contains every needle a guard could search for.
        let big = format!(
            "fn a() {{
{}
}}

fn b() {{
    needle();
}}
",
            "    // filler
".repeat(2_000)
        );
        let panicked = std::panic::catch_unwind(|| {
            item_body(&big, "fn a(", &["
THIS_MARKER_NO_LONGER_EXISTS"]).len()
        })
        .is_err();
        assert!(
            panicked,
            "with no end marker matching and 20k+ characters left, `item_body` must refuse:              returning the remainder makes every guard built on it vacuous"
        );

        // A short file with no following item is legitimate (the last item in
        // a file) and must still work.
        let tail = item_body("fn only() {
    body();
}
", "fn only(", &["
fn "]);
        assert!(tail.contains("body("), "the last item in a file has no successor");
    }

    /// Every `waitpid` return value must be inspected.
    ///
    /// A bare `libc::waitpid(pid, &mut status, 0);` discards the return code
    /// and leaves `status` at its initialised `0` when the call fails
    /// (ECHILD/EINTR). On Darwin `WIFEXITED(0)` is TRUE and `WEXITSTATUS(0)`
    /// is `0`, so the failure was laundered into a fabricated, entirely
    /// clean `ProcessExit { exit_code: 0 }` — the debugger reporting a
    /// healthy exit for a process it learned nothing about.
    #[test]
    fn waitpid_failures_are_not_reported_as_a_clean_exit() {
        let code = code_only(include_str!("macos_debugger.rs"));
        let total = code.matches("libc::waitpid(").count();
        assert!(total >= 3, "expected the three known `waitpid` call sites, found {total}");
        let checked = code.matches("let rc = unsafe { libc::waitpid(").count();
        assert_eq!(
            checked, total,
            "{} of {total} `libc::waitpid(` call sites in macos_debugger.rs still discard the \
             return value (bare `unsafe {{ libc::waitpid(...); }}`). On Darwin a failed wait \
             leaves `status` at 0, and `WIFEXITED(0)` is true — the caller is handed a \
             fabricated `ProcessExit {{ exit_code: 0 }}`",
            total - checked
        );
        // And the value must actually be branched on, not merely bound.
        assert!(
            code.contains("if rc < 0"),
            "macos_debugger.rs binds the `waitpid` return but never tests it for failure"
        );
    }

    /// All three backends must refuse a second launch/attach while a process
    /// is still live.
    ///
    /// Without the guard, `spawn_loop` overwrites `cmd_tx`/`pid` with the new
    /// process's, discarding the only channel that could reach the first
    /// ptrace thread and orphaning that process with no pid left anywhere to
    /// find it. Linux and Windows gained this after a live test proved the
    /// leak; macOS could not inherit it because `launch`/`attach` are
    /// per-platform methods, which the shared-logic guard deliberately does
    /// not police. Checking all three also blocks the reverse regression.
    #[test]
    fn every_backend_refuses_a_second_launch_while_a_process_is_live() {
        let backends = [
            ("linux", code_only(include_str!("linux_debugger.rs"))),
            ("windows", code_only(include_str!("windows_debugger.rs"))),
            ("macos", code_only(include_str!("macos_debugger.rs"))),
        ];
        let next = ["    async fn ", "    fn "];
        for (name, code) in &backends {
            for entry in ["async fn launch(", "async fn attach("] {
                let body = item_body(code, entry, &next);
                assert!(
                    body.contains("self.pid.lock().is_some()"),
                    "{name}: `{entry}` does not reject a second call while `self.pid` is still \
                     set — the previously attached process is orphaned with its command channel \
                     overwritten and unreachable"
                );
            }
        }
    }

    /// `walk_vm_regions` must not wrap around the address space.
    ///
    /// `address.wrapping_add(size)` on a region ending at the very top of the
    /// 64-bit space wraps back to a low address and re-walks forever, only
    /// stopping at the 1M-region backstop — which then blames a
    /// "likely struct-layout mismatch" for what is really a normal
    /// end-of-address-space.
    #[test]
    fn walk_vm_regions_stops_at_address_space_overflow() {
        let code = code_only(include_str!("macos_debugger.rs"));
        let body = item_body(&code, "fn walk_vm_regions(", &["\nfn ", "\nasync fn "]);
        assert!(
            !body.contains("wrapping_add"),
            "walk_vm_regions still advances with `wrapping_add`: a region reaching the top of \
             the address space wraps to 0 and the walk restarts forever"
        );
        assert!(
            body.contains("checked_add"),
            "walk_vm_regions no longer advances with `checked_add` — overflow must end the walk"
        );
    }

    /// A real Mach failure must not be reported as a complete memory map.
    ///
    /// `KERN_INVALID_ADDRESS` is the documented end-of-address-space
    /// terminator and is a normal loop exit. Treating EVERY non-success
    /// return as that terminator meant a target dying part-way through
    /// enumeration (KERN_INVALID_TASK / MACH_SEND_INVALID_DEST) returned
    /// `Ok` with however many regions had been collected — a silently
    /// truncated address space indistinguishable from a complete one.
    /// (Missing entitlements are NOT this case: `resolve_task_port` already
    /// fails earlier.)
    #[test]
    fn walk_vm_regions_distinguishes_end_of_address_space_from_a_real_mach_error() {
        let code = code_only(include_str!("macos_debugger.rs"));
        let body = item_body(&code, "fn walk_vm_regions(", &["\nfn ", "\nasync fn "]);
        assert!(
            body.contains("KERN_INVALID_ADDRESS"),
            "walk_vm_regions treats every non-KERN_SUCCESS return as end-of-regions, so a target \
             that dies mid-enumeration yields a silently partial map reported as complete"
        );
        assert!(
            body.contains("return Err("),
            "walk_vm_regions never returns an error — a genuine Mach failure is still swallowed"
        );
    }

    /// Mach send rights must be released by whoever acquires them.
    ///
    /// `task_threads` and `task_for_pid` each hand back ports carrying a send
    /// right refcounted against the CALLING task. `mach_vm_deallocate` frees
    /// only the array those ports arrived in, not the rights themselves, so
    /// dropping the array leaks one right per port per call — unbounded
    /// growth of this process's ipc space for a debugger that polls
    /// `threads()`/`memory_maps()`/`modules()`.
    ///
    /// STRUCTURAL ONLY: this asserts the release calls are present in the
    /// functions that acquire the rights. It cannot observe a refcount, and
    /// nothing on a non-macOS host can.
    #[test]
    fn mach_port_rights_are_released_where_they_are_acquired() {
        let code = code_only(include_str!("macos_debugger.rs"));
        assert!(
            code.contains("mach_port_deallocate"),
            "macos_debugger.rs never calls `mach_port_deallocate`: every port from `task_threads` \
             and `task_for_pid` leaks its send right"
        );
        let next = ["\nfn ", "\nasync fn "];
        for acquirer in ["fn first_thread_port(", "fn list_thread_ids("] {
            let body = item_body(&code, acquirer, &next);
            assert!(
                body.contains("task_threads("),
                "guard is misanchored: `{acquirer}` no longer calls `task_threads`"
            );
            assert!(
                body.contains("release_port("),
                "{acquirer} calls `task_threads` but releases no port's send right — \
                 `mach_vm_deallocate` frees only the array, never the rights"
            );
        }
        // The three per-call `task_for_pid` consumers must release too.
        for consumer in ["async fn threads(", "async fn memory_maps(", "async fn modules("] {
            let body = item_body(&code, consumer, &["    async fn ", "    fn "]);
            assert!(
                body.contains("resolve_task_port("),
                "guard is misanchored: `{consumer}` no longer resolves a task port"
            );
            assert!(
                body.contains("release_port(task_port)"),
                "{consumer} resolves a fresh task port on every call but never releases it — \
                 repeated polling grows this process's ipc space without bound"
            );
        }

        // The two register paths, checked on ORDER and not merely on presence.
        //
        // These were leaking a thread send right per `GetRegisters` /
        // `SetRegisters` — the highest-frequency calls a debugger makes, so the
        // leak grew with every step. Fixed in the Apple audit of 2026-08-15,
        // and this is what makes that fix survive: an adversarial reviewer
        // pointed out that a guard asserting `release_port(` is merely PRESENT
        // cannot tell a release on every path from a release on the happy path
        // only, which is exactly the shape the defect comes back in.
        //
        // `write_thread_state` acquires, calls `thread_set_state`, releases,
        // and only THEN inspects `kr` and may `return Err`. Move the release
        // below that return and the error path leaks again while the guard
        // stays green — unless the guard checks the order, which is what the
        // index comparison below does.
        for reg_path in ["fn read_thread_state(", "fn write_thread_state("] {
            let body = item_body(&code, reg_path, &next);
            assert!(
                body.contains("thread_port_for("),
                "guard is misanchored: `{reg_path}` no longer takes a thread port"
            );
            let released = body
                .find("release_port(")
                .unwrap_or_else(|| panic!("{reg_path} takes a thread send right and never releases it"));
            // A `return Err` before the release is a leak on the error path.
            if let Some(returns) = body.find("return Err(") {
                assert!(
                    released < returns,
                    "{reg_path}: the thread send right is released AFTER an early `return Err`, \
                     so every failing call leaks a Mach port right"
                );
            }
        }
    }
}
