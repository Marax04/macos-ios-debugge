# RustRE Crate Analysis: Fuzz / Trace / TTD / Diff Subsystems

**Analysed:** 2026-07-01  
**Crates covered:** 19 crates across four subsystems

---

## Table of Contents

1. [Fuzz Subsystem (6 crates)](#1-fuzz-subsystem)
   - rustre-fuzz · rustre-fuzz-afl · rustre-fuzz-libfuzzer
   - rustre-fuzz-cov · rustre-fuzz-sanitizers · rustre-fuzz-net
2. [Trace Subsystem (5 crates)](#2-trace-subsystem)
   - rustre-trace · rustre-trace-pt · rustre-trace-coresight
   - rustre-trace-coverage · rustre-trace-navigate
3. [TTD Subsystem (5 crates)](#3-ttd-time-travel-debugging-subsystem)
   - rustre-ttd · rustre-ttd-recorder · rustre-ttd-replay
   - rustre-ttd-replayer · rustre-ttd-query
4. [Diff Subsystem (3 crates)](#4-diff-subsystem)
   - rustre-diff · rustre-diff-bindiff · rustre-diff-semantic
5. [Cross-subsystem Integration Map](#5-cross-subsystem-integration-map)
6. [Dependency Graph Summary](#6-dependency-graph-summary)
7. [Gap Analysis and Priority Fixes](#7-gap-analysis-and-priority-fixes)

---

## 1. Fuzz Subsystem

The fuzzing subsystem follows a hub-and-spoke architecture. `rustre-fuzz` is the hub providing shared primitives; backend crates (`rustre-fuzz-afl`, `rustre-fuzz-libfuzzer`, etc.) all depend on the hub. The hub may optionally re-export backends via the `backends` feature, but does not hard-depend on any backend to avoid cargo cycles.

### 1.1 rustre-fuzz (hub)

| | |
|---|---|
| **Purpose** | Shared primitives and traits for all fuzzing backends |
| **Status** | **COMPLETE** — no stubs, all types fully implemented |
| **Key external deps** | `parking_lot`, `serde`, `thiserror` |
| **Optional deps** | `rustre-fuzz-cov` (feature `backends`), `rustre-fuzz-sanitizers` (feature `backends`) |

**Public API surface**

| Type / Trait | Description |
|---|---|
| `FuzzInput` | Raw bytes + genealogy (id, parent, generation, origin) |
| `FuzzResult` | `Interesting(Vec<u8>)` / `Crash{input,signal,address}` / `Timeout` / `Normal` |
| `ExecutionStatus` | Low-level: `Normal` / `Crash{signal,fault_addr}` / `Timeout` / `Hang` |
| `ExecutionResult` | `status`, `coverage_hash`, `execution_time`, `new_coverage_bits` |
| `TargetExecutor` trait | `fn execute(&mut self, input: &[u8]) -> Result<ExecutionResult, FuzzError>` |
| `CoverageMap` | AFL-style bitmap with hit counters; `update()`, `merge()`, `hash()`, `active_edges()` |
| `InputQueue` | Priority queue with favoured over-sampling (1-in-3 favoured selection) |
| `FuzzerStats` / `FuzzStats` | Execution counters, crash rates, `execs_per_sec()` via monotonic `Instant` |
| `Corpus` / `CorpusEntry` / `CorpusMeta` | Interesting + crash inputs with metadata; dedup by coverage hash |
| `CrashRecord` / `CrashDeduplicator` | Stack-hash or coverage-hash based dedup; `submit()` returns bool novelty |
| `MutationStrategy` | 13 strategies: `BitFlip`, `ByteFlip`, `Arithmetic`, `InterestingValue`, `Dictionary`, `Splice`, `Havoc`, `Insert`, `Delete`, `Shuffle`, `Repeat`, `XorBlock`, `Reverse` |
| `MutationEngine` | Applies strategies; adaptive strategy-hit tracking; seed: xorshift-64 `FuzzRng` |
| `Dictionary` | Token list with AFL-format parser (bare / `"..."` / `x"..."` hex) |
| `FuzzError` | `ExecutionError`, `CoverageError`, `InputError`, `Timeout`, `CorpusError`, `MinimizationError` |
| `fnv1a(data: &[u8]) -> u64` | FNV-1a 64-bit hash, used everywhere for dedup keys |

**Sub-modules**

| Module | Role |
|---|---|
| `registry` | Plugin registry for fuzzer backend dispatch |
| `campaign` | Campaign lifecycle management |
| `fuzz_orchestrator` | Multi-backend orchestration |
| `fuzzer_coordinator` | Parallel fuzzer coordination |
| `mutation_scheduler` | Per-strategy scheduling |
| `mutation_engine` | Extended mutation engine |
| `corpus_manager` | Corpus I/O helpers |
| `crash_analyzer` | Post-crash triage |
| `crash_dedup` | Crash deduplication (extends `CrashDeduplicator`) |
| `grammar_fuzzer` | Grammar-based fuzzing |
| `structured_fuzzer` | Structured/typed fuzzing |
| `smart_seed_scheduler` | Energy-based seed selection |
| `seed_minimizer` | Delta-debugging minimization |
| `coverage_guided_fuzzer` | Coverage-guided main loop |

---

### 1.2 rustre-fuzz-afl

| | |
|---|---|
| **Purpose** | AFL++-style coverage-guided fuzzing engine |
| **Status** | **COMPLETE** — full AFL++ feature set in pure Rust |
| **Key external deps** | `rustre-fuzz`, `anyhow`, `thiserror`, `serde`, `rayon` |

**Core types**

| Type | Description |
|---|---|
| `AflFuzzer` | Main fuzzer: executor + queue + coverage + mutators + stats + fork server + cmplog |
| `AflQueue` / `AflQueueEntry` | Power-schedule queue with `score()`, `select_best()`, `compute_favorites()` |
| `AflShmCoverage` | 64 KiB AFL bitmap (portably `Vec<u8>`); AFL-style hit-count bucketing |
| `ForkServer` | State machine: `Idle -> Ready -> Running -> Done/Crashed -> Ready` |
| `PersistentMode` | Persistent-mode loop management (up to `max_iterations` before restart) |
| `CmplogEntry` / `CmplogMap` | CMPLOG comparison recording; `colorize_mutations()` for Redqueen-style mutations |
| `AflStats` | Parses/serializes AFL `fuzzer_stats` text format |
| `AflError` | `ShmError`, `ForkServerError`, `InvalidDict`, `StatsParseError` |

**Mutator traits and implementations**

```rust
pub trait Mutator: Send + Sync {
    fn mutate(&self, input: &[u8], rng: &mut dyn RngCore) -> Vec<u8>;
    fn name(&self) -> &'static str { "unknown" }
}
pub trait RngCore {
    fn next_u64(&mut self) -> u64;
    // + next_u32, next_usize, one_in, next_u8
}
pub struct XorShiftRng { state: u64 }  // xorshift64
```

Concrete mutators: `BitFlipMutator`, `ByteFlipMutator`, `ArithmeticMutator`, `InterestingValueMutator`, `DictionaryMutator`, `SpliceMutator`, `InsertMutator`, `DeleteMutator`, `XorBlockMutator`, `HavocMutator` (all as `Box<dyn Mutator>` in `AflFuzzer`).

**Key method: `AflFuzzer::fuzz_one()`**

```rust
pub fn fuzz_one(&mut self) -> Result<Option<FuzzInput>, FuzzError>
// select -> mutate -> execute -> triage crashes -> update coverage -> add to queue
```

**Sub-modules**: `afl_analysis`, `afl_corpus_manager`, `afl_mutators`, `afl_bitmap`, `afl_queue`, `afl_trimmer`, `afl_queue_reader`, `afl_coverage_map`, `afl_crash_triager`, `persistent_mode`, `qemu_mode`, `cmplog`, `redqueen_engine`, `afl_fork_server`.

---

### 1.3 rustre-fuzz-libfuzzer

| | |
|---|---|
| **Purpose** | In-process libFuzzer-style fuzzer |
| **Status** | **COMPLETE** — full harness, corpus management, persistent mode |
| **Key external deps** | `rustre-fuzz`, `rustre-fuzz-afl`, `parking_lot`, `rayon`, `bitflags`, `thiserror`, `serde` |

**Key traits**

```rust
pub trait FuzzTarget: Send {
    fn run(&mut self, input: &[u8]) -> FuzzTargetResult;
    fn name(&self) -> &'static str { "unnamed_target" }
    fn max_input_size(&self) -> Option<usize> { None }
    fn setup(&mut self) {}
    fn teardown(&mut self) {}
}

pub trait CustomMutator: Send {
    fn mutate(&mut self, input: &[u8], seed: u64, max_size: usize)
        -> Result<Vec<u8>, LibFuzzerError>;
    fn name(&self) -> &str;
}
```

**Key types**

| Type | Description |
|---|---|
| `InProcessFuzzer` | Core fuzzer: target + corpus + coverage + signal handler + corpus manager |
| `LibFuzzerHarness` | High-level: bundles `InProcessFuzzer` + `PersistentModeHarness` |
| `FuzzCorpusManager` | Corpus with novelty dedup; `save()` / `load()` / `prune_to()` / `merge_from()` |
| `CoverageAccumulator` | Thread-safe `Arc<RwLock<CoverageMap>>` wrapper |
| `CrashSignalHandler` | `Arc<Mutex<bool>>` crash flag; `inject_crash()` / `is_crashed()` / `clear()` |
| `CoverageFilter` | Novelty gate: `is_interesting(&[u8]) -> bool` |
| `StructuredInput` | Named-field structured input; `serialize()` (2-byte length prefix) / `deserialize()` with DoS guards (4096 field cap, 64 MiB total cap) |
| `HarnessStats` | executions, crashes, hangs, corpus_size, coverage_bits, exec_per_sec |
| `FuzzSession` | Serializable session record |
| `PersistentModeHarness` | Iteration counter + `advance() -> bool` |
| `DefaultHavocMutator` | `CustomMutator` wrapping AFL's `HavocMutator` |

**Sub-modules**: `corpus_manager`, `coverage_feedback`, `crash_deduplicator`, `crash_triage`, `custom_mutator`, `harness_generator`, `in_process`, `libfuzzer_corpus`, `libfuzzer_corpus_minimizer`, `libfuzzer_crash_reproducer`, `libfuzzer_harness`, `mutation_engine`, `mutation_strategies`, `mutator`.

---

### 1.4 rustre-fuzz-cov

| | |
|---|---|
| **Purpose** | Coverage tracking: DRcov/LCOV parsing, edge/block bitmaps, SanitizerCoverage, coverage diffs |
| **Status** | **PARTIAL** — data types and parsers complete; PT integration and QEMU TCG coverage are structural stubs |
| **Key external deps** | `thiserror`, `serde`, `serde_json`, `serde_bytes`, `rayon` |
| **Note** | `unsafe_code = "allow"` for `extern "C"` SanitizerCoverage entry points |

**Key types**

| Type | Description |
|---|---|
| `DrcovModule` / `DrcovBbEntry` / `DrcovFile` | DynamoRIO DRcov format: module table + BB table + parser |
| `LcovRecord` | LCOV `.info` coverage record |
| `CoverageDatabase` | Multi-run aggregation with dedup |
| `EdgeCoverage` | Edge-pair (src_block, dst_block) hit tracking |
| `BlockCoverage` | Single basic-block hit tracking |
| `CoverageStats` | Aggregate statistics over a coverage map |
| `CovError` | `Parse`, `Io`, `UnsupportedVersion`, `Overflow`, `EmptyInput` |

**Sub-modules**: `casts`, `block_coverage_tracker`, `edge_coverage`, `edge_coverage_tracker`, `coverage_feedback`, `coverage_guide`, `coverage_minimizer`, `coverage_persistence`, `coverage_statistics`, `coverage_diff`, `coverage_diff_reporter`, `coverage_map_merger`, `source_coverage_mapper`, `source_coverage_tracker`, `lcov_export`, `pt_integration`, `qemu_tcg_cov`, `sancov_instrumentation`.

**Known gaps**: `pt_integration` and `qemu_tcg_cov` represent integration points with `rustre-trace-pt` and QEMU TCG instrumentation that are declared but not yet wired to live PT/TCG data sources.

---

### 1.5 rustre-fuzz-sanitizers

| | |
|---|---|
| **Purpose** | Pure-Rust logic equivalents to ASan, MSan, UBSan (no LLVM sanitizer required) |
| **Status** | **PARTIAL** — shadow memory model and violation detection complete; crash dedup and dashboard partially implemented |
| **Key external deps** | `anyhow`, `thiserror`, `serde`, `serde_json`, `parking_lot` |

**Key types**

| Type | Description |
|---|---|
| `SanitizerKind` | `MemoryUninit`, `HeapOverflow`, `UseAfterFree`, `DoubleFree`, `NullDeref`, `IntOverflow`, `Misaligned`, `DivByZero`, `HeapUnderflow` |
| `SanitizerReport` | kind + message + stack_trace + address + size |
| `ShadowMemory` | Byte-granular shadow memory tracking for MSan-style uninit detection |
| `AsanRuntime` / `AsanAnalyzer` | Heap allocation tracking, overflow / UAF detection |
| `MsanModel` / `MsanTracker` | Shadow-byte tracking for uninitialized reads |
| `TsanModel` | Thread-safety violation detection model |
| `UbsanChecks` | Arithmetic overflow / division by zero / misalignment checks |
| `SanitizerDashboard` | Aggregated view of all active sanitizer reports |

**Sub-modules**: `cast`, `asan_analyzer`, `asan_runtime`, `asan_report_parser`, `coverage_guided_fuzzer`, `crash_deduplicator`, `msan_model`, `msan_tracker`, `msan_report_parser`, `sanitizer_runtime`, `shadow_memory`, `tsan_model`, `tsan_report_parser`, `ubsan_checks`, `ubsan_report_parser`, `sanitizer_crash_deduplicator`, `sanitizer_dashboard`.

---

### 1.6 rustre-fuzz-net

| | |
|---|---|
| **Purpose** | Network/stateful protocol fuzzer (Boofuzz-inspired); async I/O via Tokio |
| **Status** | **PARTIAL** — protocol model, state machine, and mutation engine complete; real socket transport is a trait stub |
| **Key external deps** | `rustre-fuzz`, `rustre-fuzz-afl`, `thiserror`, `serde`, `tokio`, `async-trait` |

**Key types**

| Type | Description |
|---|---|
| `FieldType` | `Static(Vec<u8>)`, `Fuzzable{min,max}`, `SizeOf(field_name)`, `Ascii(len)`, `Delimited{...}` |
| `ProtocolMessage` | Named ordered fields; `serialize()` with SizeOf resolution |
| `ProtocolState` / `ProtocolStateMachine` | State-machine transitions between protocol states |
| `NetworkSession` | Async connection abstraction (trait-based) |
| `ProtocolFuzzer` | Drives the state machine, mutates fuzzable fields |
| `TransportError` / `FuzzNetError` | Error hierarchy with async and payload-size variants |
| `ReplayEngine` | Replays recorded sessions for crash reproduction |
| `CrashDetector` | Detects target crashes via connection drops / unexpected responses |

**Sub-modules**: `protocol_model`, `crash_analyzer`, `dns_fuzzer`, `grammar_fuzzer`, `mutation_engine`, `network_harness`, `network_state_machine`, `coverage_guided_fuzzer`, `protocol_fuzzer`, `tls_fuzzer`, `protocol_state_fuzzer`, `packet_mutator`, `crash_detector`, `protocol_state_machine`, `replay_engine`.

**Known gap**: The `NetworkSession` transport trait has no real TCP/UDP implementation; tests mock it. `tls_fuzzer` and `dns_fuzzer` have specialised logic but no live protocol harnesses.

---

## 2. Trace Subsystem

The trace subsystem uses the same hub-and-spoke pattern as fuzz. `rustre-trace` aggregates four sub-crates via its `registry` module. Each sub-crate avoids a back-dependency on `rustre-trace` to prevent workspace cycles.

### 2.1 rustre-trace (hub)

| | |
|---|---|
| **Purpose** | Unified trace abstraction hub — aggregates PT, CoreSight, Coverage, and Navigate backends |
| **Status** | **COMPLETE** — hub wiring is complete; completeness depends on sub-crates |
| **Key external deps** | `rustre-core`, `rustre-trace-{pt,coresight,coverage,navigate}`, `serde`, `rusqlite`, `parking_lot` |

**Public API surface**

```rust
// registry module
pub enum TraceEngine {
    CoreSight(CoreSightDecoder),
    Coverage(CoverageSession),
    Navigate(Box<TraceNavigator>),
    Pt(PtDecoder),
}
impl TraceEngine {
    pub fn name(&self) -> &'static str  // "coresight" | "coverage" | "navigate" | "pt"
}
pub fn all_engines() -> Vec<TraceEngine>

// Re-exported from sub-crates via registry:
pub use rustre_trace_pt::{
    PtDecoder, PtError, PtEvent, PtFlow, PtFlowReconstructor, PtPacket,
    PtPacketKind, PtTrace, SidebandInfo, TimingInfo, IpCompression,
    pt_block_decoder, pt_coverage_reporter, pt_decoder, pt_filter,
    pt_flow_reconstruction, pt_instruction_decoder, pt_packet_decoder,
    pt_perf_integration, pt_sideband, pt_snapshot, pt_timing,
    pt_timing_analyzer, pt_trace_builder,
};
pub use rustre_trace_coresight::CoreSightDecoder;
pub use rustre_trace_coverage::CoverageSession;
pub use rustre_trace_navigate::TraceNavigator;
```

**Sub-modules** (internal trace analysis types): `trace_analysis`, `trace_annotation`, `trace_annotator`, `trace_compressor`, `trace_database`, `trace_export`, `trace_filter`, `trace_format`, `trace_hot_spots`, `trace_importer`, `trace_index`, `trace_indexer`, `trace_serializer`, `trace_statistics`.

Key exported types from the hub's own lib: `TraceFilter`, `TraceEvent` (used by `rustre-ttd-query`).

---

### 2.2 rustre-trace-pt

| | |
|---|---|
| **Purpose** | Intel Processor Trace (PT) packet decode, control flow reconstruction, timing |
| **Status** | **PARTIAL** — packet decoder and data model complete; CPUID capability detection uses `unsafe`; live `perf` integration is structural |
| **Key external deps** | `anyhow`, `thiserror`, `serde`, `libc` (`unsafe_code = "allow"`) |

**Key types**

| Type | Description |
|---|---|
| `PtPacketKind` | Full PT packet taxonomy: PSB, TNT, TIP, FUP, OVF, MODE, CYC, MTC, TSC, TMA, PIP, CBR, PAD, EXSTOP, PWRE/X |
| `PtPacket` | `kind: PtPacketKind` + `offset: usize` |
| `IpCompression` | `SEXT48`, `UPDATE32`, `UPDATE16`, `SUPPR`, `FULL` |
| `PtFlow` | Reconstructed control flow entry: `ip`, `kind` (Call/Ret/Branch/...), `taken`, `tsc` |
| `PtTrace` | Collection of raw PT bytes + metadata |
| `PtDecoder` | Top-level: `decode_packets()` / `reconstruct_flow()` / `build_coverage()` |
| `PtFlowReconstructor` | Stateful flow reconstruction using PT TNT bits |
| `SidebandInfo` | Kernel sideband event: image loads, CR3 changes, etc. |
| `TimingInfo` | TSC/MTC/CYC timing reconstruction |
| `PtError` | `InvalidPacket`, `TruncatedPacket`, `UnknownOpcode`, `IpCompression`, `FlowReconstruction`, `Sideband`, `Timing`, `Overflow` |

**Sub-modules**: `pt_decoder`, `pt_packet_decoder`, `pt_instruction_decoder`, `pt_block_decoder`, `pt_flow_reconstruction`, `pt_filter`, `pt_sideband`, `pt_snapshot`, `pt_timing`, `pt_timing_analyzer`, `pt_trace_builder`, `pt_perf_integration`, `pt_coverage_reporter`, `cast_helpers`.

---

### 2.3 rustre-trace-coresight

| | |
|---|---|
| **Purpose** | ARM CoreSight ETM4/ETE/PTM/STM trace decode; CoreSight topology discovery |
| **Status** | **PARTIAL** — data types and packet decoders complete; ROM table topology discovery is structural |
| **Key external deps** | `anyhow`, `thiserror`, `serde`, `parking_lot`, `libc` |

**Key types**

| Type | Description |
|---|---|
| `ExceptionType` | ARM exception types for ETM exception packets: Reset, Undefined, Svc, PrefetchAbort, DataAbort, IRQ, FIQ, HVC, SMC, SError, Debug |
| `EtmVersion` | `Etm3`, `Etm4`, `Ete` |
| `EtmConfig` | Core ISA string + ETM version configuration |
| `CoreSightDecoder` | Top-level decoder: `decode()` / `reconstruct_trace()` |
| `CsError` | `InvalidPacket`, `TruncatedBuffer`, `SyncLost`, `UnsupportedIsa`, `RomTable`, `DataTrace` |
| `EtmPackets` | ETM4 packet definitions (atom, address, exception, cycle count, ...) |
| `TpiuSink` | TPIU de-framer for ARM trace port interface |

**Sub-modules**: `coresight_packets`, `coresight_topology`, `ptm_decoder`, `cs_analysis`, `etm_decoder`, `etm_packets`, `stm_decoder`, `timestamp_decoder`, `tpiu_sink`, `trace_reconstructor`, `ptt_trace_parser`, `coresight_etm_decoder`, `coresight_stm_decoder`.

---

### 2.4 rustre-trace-coverage

| | |
|---|---|
| **Purpose** | Lighthouse-style code coverage: DRcov/LCOV import, BB/edge/branch/function hit maps, diff, heatmap, HTML export |
| **Status** | **COMPLETE** — all data types and algorithms implemented |
| **Key external deps** | `thiserror`, `serde`, `serde_json` (no rustre-trace dependency — avoids cycle) |

**Key types**

| Type | Description |
|---|---|
| `CoverageData` | Multi-run coverage container: `HashMap<String, CoverageRun>` |
| `CoverageRun` | Per-run: BB hit map (`HashMap<u64, u64>`), edge map, metadata |
| `CoverageSession` | Active session: accumulate hits, compute diffs |
| `CoverageBitmap` | Dense byte bitmap for fast merge/diff |
| `BbHeatmap` | `Vec<(u64, u64)>` sorted by count for gradient coloring |
| `FunctionCoverage` | Per-function: total BB count, covered BB count, coverage % |
| `BranchCoverage` | Per-branch: taken/not-taken counts |
| `DifferentialCoverage` | A-only, B-only, A intersect B sets |
| `CoverageTimeline` | Coverage growth over time (run-indexed) |
| `CoverageMap` | AFL-style bitmap with merge/diff operations |
| `CovError` | `SizeMismatch`, `InvalidIndex`, `SourceNotFound`, `IncompatibleCoverage`, `Serialization`, `Parse` |

**Sub-modules**: `cast_helpers`, `bb_heatmap`, `coverage_bitmap`, `coverage_bitmap_ext`, `coverage_diff`, `coverage_guided_analysis`, `coverage_map`, `coverage_merge`, `coverage_report`, `coverage_timeline`, `coverage_visualizer`, `differential_coverage`, `drcov_import`, `function_coverage`, `branch_coverage`, `lighthouse_compat`, `path_coverage`, `source_mapping`.

---

### 2.5 rustre-trace-navigate

| | |
|---|---|
| **Purpose** | Tenet-style bidirectional execution trace navigation: step/jump, memory timeline, register history, call tree, coverage |
| **Status** | **PARTIAL** — core navigator and data types complete; async replay controller (Tokio) is partially wired |
| **Key external deps** | `anyhow`, `thiserror`, `serde`, `petgraph`, `tokio`, `tokio-util`, `async-trait`, `rusqlite`, `bincode` |

**Key types**

| Type | Description |
|---|---|
| `TraceEntry` | `index`, `ip`, `kind: EntryKind`, registers, memory accesses |
| `EntryKind` | `Instruction` / `MemRead` / `MemWrite` / `Call` / `Return` / `Syscall` / `Exception` |
| `ExecutionTrace` | `Vec<TraceEntry>` with index helpers |
| `TraceNavigator` | Bidirectional cursor: `step_forward()`, `step_backward()`, `jump_to()`, `run_until()`, `run_until_reverse()`, `step_over()`, `step_out()` |
| `Bookmark` | Named position in the trace |
| `StackFrame` | Reconstructed call stack frame: `return_addr`, `fn_addr`, `name` |
| `CoverageStats` | Visited block count, hot block map, call frequency |
| `NavError` | `OutOfBounds`, `Empty`, `BookmarkNotFound`, `NoMatch`, `ExecError` |
| `Address` | `type Address = u64` |
| `RegId` | `type RegId = u32` |

**Sub-modules**: `address_timeline`, `backward_nav`, `bookmark_manager`, `call_tree_navigator`, `step_navigator`, `trace_index`, `tenet_navigation`, `time_travel_search`, `execution_graph_builder`, `time_travel_navigator`, `trace_search_engine`, `trace_diff_engine`, `trace_replay_controller`, `trace_slice_extractor`, `function_call_navigator`, `memory_access_navigator`, `trace_bookmark_manager`.

---

## 3. TTD (Time Travel Debugging) Subsystem

The TTD subsystem models Windows TTD / Mozilla rr: record a process execution to a trace file, then replay it deterministically with full forward/backward stepping and memory/register state reconstruction. SQLite (`rusqlite`) is used for indexing throughout.

### 3.1 rustre-ttd (core)

| | |
|---|---|
| **Purpose** | Core TTD data model: trace positions, event log, session cursor, SQLite index, watchpoints, syscall summary |
| **Status** | **PARTIAL** — data model and SQLite index complete; Nirvana format parsing partially done |
| **Key external deps** | `rusqlite`, `parking_lot`, `serde`, `serde-big-array`, `thiserror` |

**Key types**

| Type | Description |
|---|---|
| `TracePosition` | `(seq: u64, step: u64)` with `Ord` (lexicographic), `Display` (`seq:step`) |
| `EventKind` | `Instruction`, `MemRead`, `MemWrite`, `Call{callee}`, `Return{ret_val}`, `Syscall{nr}`, `Exception{code}`, `ThreadCreate/Exit`, `ModuleLoad/Unload` |
| `TraceEvent` | `position: TracePosition`, `kind: EventKind`, `thread_id: u32` |
| `TraceMetadata` | Process info, module list, record timestamps |
| `TtdTrace` | Thread-safe event log: `Arc<RwLock<Vec<TraceEvent>>>` + metadata |
| `TtdSession` | Forward/backward cursor; `step_forward()`, `step_backward()`, `run_until()` |
| `TtdIndex` | SQLite-backed index for position / event-type / address-range queries |
| `MemoryMap` | Address space reconstruction from `MemWrite` events |
| `CallStack` | Per-thread call stack from `Call`/`Return` events |
| `TraceFilter` | Composable predicates: by event kind, thread, address range, position range |
| `TraceStats` | `total_events`, `instructions`, `calls`, `syscalls`, `memory_writes`, `exceptions` |
| `TraceExporter` | Newline-delimited JSON serialization |
| `TraceImporter` | Newline-delimited JSON deserialization |
| `Watchpoint` | Data-access watchpoint matched against `MemWrite` events |
| `SyscallSummary` | Per-syscall-number call count aggregation |
| `TtdError` | `TraceNotOpen`, `InvalidPosition`, `ReadError`, `IoError`, `CorruptTrace`, `UnsupportedVersion`, `DatabaseError`, `SerdeError` |

**Sub-modules**: `call_monitor`, `nirvana_format`, `position`, `replay_position`, `replay_query_lang`, `trace_index`, `ttd_index`, `ttd_index_builder`, `ttd_position`, `ttd_query_language`, `ttd_thread_context`, `ttd_breakpoint_engine`, `ttd_heap_tracker`.

---

### 3.2 rustre-ttd-recorder

| | |
|---|---|
| **Purpose** | TTD recording: ETW event tracing, ring buffer, snapshot management, trace file writing, chacha20poly1305 encryption |
| **Status** | **PARTIAL** — API surface complete; real OS-level recording (ptrace/ETW kernel hooks) is Linux-conditional; Windows hooks are stubs |
| **Key external deps** | `rustre-core`, `rustre-ttd`, `rustre-trace`, `anyhow`, `bincode`, `tokio`, `parking_lot`, `rusqlite`, `async-trait`, `chacha20poly1305` |
| **Platform deps** | `nix` (ptrace, signal, process) + `libc` on Linux only |

**Key types**

| Type | Description |
|---|---|
| `TtdPosition` | `(major: u64, minor: u64)` position inside a recording |
| `TtdRecordError` | `NotAvailable`, `ProcessNotFound`, `InsufficientPrivileges`, `OutputPathError`, `CompressionError`, `RecordingFailed` |
| `RecorderEngine` | Core: attach to process, start/pause/resume/stop recording |
| `RecordingSessionManager` | Manages multiple concurrent recording sessions |
| `RecordingPolicy` | Configuration: max trace size, compression, encryption settings |
| `EtwRecorder` | Windows ETW-based trace collection (structural) |
| `EtwTraceSession` | ETW session lifetime management |
| `KernelTraceHooks` | Kernel-level trace hooks (Linux ptrace-backed) |
| `EmulatorRecorder` | Records from an emulator rather than a real process |
| `SnapshotManager` | Periodic process snapshot management |
| `ThreadContextRecorder` | Per-thread register state recording |
| `TraceWriter` | Writes events to the trace file format |
| `TtdRingBuffer` | Lock-free ring buffer for high-throughput event capture |
| `TtdIndexBuilder` | Builds the SQLite position index incrementally as events arrive |

**Known gap**: `EtwRecorder` and `KernelTraceHooks` on Windows return `TtdRecordError::NotAvailable`. Real recording requires the Windows TTD.exe SDK or ptrace on Linux.

---

### 3.3 rustre-ttd-replay

| | |
|---|---|
| **Purpose** | Deterministic replay: restore process state at any trace position; forward and backward stepping; watchpoints and breakpoints |
| **Status** | **PARTIAL** — replay engine and stepper logic complete; actual CPU emulation is placeholder |
| **Key external deps** | `rustre-ttd`, `thiserror`, `serde`, `rusqlite`, `bitflags` |

**Key types**

| Type | Description |
|---|---|
| `ReplayError` | `InvalidTrace`, `PositionNotFound`, `StateRestoreError`, `EmulationError`, `DatabaseError`, `IoError` |
| `ReplayStopReason` | `BreakpointHit{bp_id, position}`, `WatchpointHit{wp_id, old_value, new_value}`, `End`, `Start` |
| `ReplayEngine` | Trait + implementation: `step()`, `step_back()`, `run_until()`, `run_until_reverse()` |
| `MemorySnapshot` | Page-granular (4 KiB) snapshot with dirty-page diffing |
| `CallStack` | Call stack at a replay position |
| `ForwardStepper` | Applies events forward from last checkpoint |
| `BackwardStepper` | Reverts events backward to target position |
| `ReplayStateManager` | Manages checkpoints to bound backward-replay cost |
| `TtdBreakpointManager` | Software breakpoints on addresses or position ranges |
| `TtdWatchpointManager` | Memory watchpoints; fires `WatchpointHit` on matching writes |
| `TtdReplayEngine` | Extended engine with execution graph construction |

**Sub-modules**: `call_stack`, `execution_graph`, `memory_snapshot`, `replay_analysis`, `replay_engine`, `thread_replay`, `time_travel_queries`, `ttd_format`, `watchpoints`, `forward_stepper`, `backward_stepper`, `replay_state_manager`, `ttd_replay_engine`, `ttd_breakpoint_manager`, `ttd_watchpoint_manager`.

---

### 3.4 rustre-ttd-replayer

| | |
|---|---|
| **Purpose** | High-level time-travel replayer: register/memory timeline, root-cause analysis, query DSL, differential replay |
| **Status** | **PARTIAL** — complete data model and query DSL; memory reconstruction replays events from `TtdTrace` |
| **Key external deps** | `rustre-ttd`, `thiserror`, `serde`, `parking_lot` |

**Key types**

| Type | Description |
|---|---|
| `TtdReplayer` | Stateful cursor; `seek_to_tick()`, `step_forward()`, `step_backward()` |
| `ReplayState` | Current register file (`HashMap<String, u64>`) + memory pages |
| `MemWriteRecord` | One contiguous write: `addr`, `data: Vec<u8>` |
| `TraceSnapshot` | Full state checkpoint at a specific tick |
| `TtdQuery` | Parsed query: `execute(trace) -> Vec<TraceEvent>` |
| `RootCauseReport` | Result of root-cause analysis |
| `RegisterTimeline` | History of a specific register across all ticks |
| `MemoryDiffViewer` | Side-by-side diff of memory state between two ticks |
| `DifferentialReplay` | Replay two traces in parallel, highlight divergence |
| `ApiCallTracker` | Records all Win32 API calls during replay |
| `TtdDatabase` | SQLite-backed persistent replay state |
| `PositionEngine` | Maps tick numbers to trace positions |

**Sub-modules**: `api_call_tracker`, `memory_diff_viewer`, `memory_reconstructor`, `register_timeline`, `replay_engine`, `replay_stats`, `differential_replay`, `snapshot_manager`, `replay_scheduler`, `trace_diff`, `ttd_call_recorder`, `ttd_memory_provider`, `ttd_trace_loader`, `ttd_database`, `position_engine`, `replay_controller`, `timeline`.

Constants: `DEFAULT_SNAPSHOT_INTERVAL = 256`, `MAX_MEM_WRITES_PER_EVENT = 1024`, `REPLAY_PAGE_SIZE = 4096`.

---

### 3.5 rustre-ttd-query

| | |
|---|---|
| **Purpose** | Rich TTD trace query engine: composable filters, SQL engine, temporal queries, multi-format export |
| **Status** | **PARTIAL** — query language and optimizer complete; SQL engine delegates to SQLite; export formats partially implemented |
| **Key external deps** | `rustre-core`, `rustre-ttd`, `rustre-trace`, `rustre-trace-navigate`, `anyhow`, `rusqlite`, `parking_lot` |

**Key types**

| Type | Description |
|---|---|
| `QueryError` | `InvalidQuery`, `TraceError`, `ParseError`, `DatabaseError`, `IoError`, `ExportError` |
| `TimeRange` | `start: TracePosition`, `end: TracePosition`; `contains()` |
| `QueryEngine` | Central dispatcher: `tenet_navigator()`, `execute_sql()`, execute typed queries |
| `TemporalQuery` | Query against a time range in the trace |
| `TtdSqlEngine` | SQLite-backed event query; build index, query by type/address/position |
| `BTreeIndex` | In-memory B-tree index for fast position lookups |
| `MemoryTimeline` | All writes/reads to a specific address across the trace |
| `RegisterHistory` | All values written to a specific register |
| `TtdMemoryQuery` | Query memory accesses: reads/writes at address range |
| `TtdCallQuery` | Query function calls by address or name pattern |
| `TtdCallStackQuery` | Reconstruct call stack at any position |
| `TtdEventQuery` | Generic event-kind query with filtering |
| `TtdExceptionQuery` | Query exception events by code or address |

**Integration**: The query engine integrates `rustre_trace_navigate::TraceNavigator` (via `tenet_navigator()`) with `rustre_ttd::TtdTrace`, bridging the TTD and Trace subsystems. Re-exports: `TenetBookmark`, `TenetCoverageStats`, `TenetNavError`, `TenetNavEvent`, `TenetStackFrame`.

---

## 4. Diff Subsystem

### 4.1 rustre-diff (core)

| | |
|---|---|
| **Purpose** | Binary diff core primitives: function fingerprinting, structural diff, instruction-level diff, patch detection |
| **Status** | **PARTIAL** — fingerprinting, structural diff, instruction diff, and matching complete; patch generator is partial |
| **Key external deps** | `thiserror`, `serde`, `ahash`, `crc32fast`, `hex` |

**Public API (re-exported from lib.rs)**

```rust
pub use basic_block_diff::{BasicBlock, BasicBlockDiffer, BlockDiff, BlockMatch, BlockMatchKind};
pub use instruction_diff::{DiffInstr, InstrDiff, InstrDiffEntry, InstrDiffKind, InstrDiffer,
    OperandDiff, operand_changes};
pub use structural::{DiffFunction, DiffReport, StructuralDiffer, StructuralMatch,
    StructuralMatchKind, histogram_cosine, jaccard, ratio};
```

**Key types**

| Type | Description |
|---|---|
| `FuncFingerprint` | address, name, size, hash (FNV), call_count, block_count, edge_count, cyclomatic complexity, byte histogram |
| `BinaryDiff` | Input pair (old functions, new functions); produces `DiffReport` |
| `DiffEngine` | Trait for diff algorithms |
| `FuncMatch` | Matched pair with similarity score |
| `DiffError` | `EmptyInput`, `HashError`, `Other` |
| `StructuralDiffer` | `jaccard()` / `histogram_cosine()` / `ratio()` similarities on fingerprints |
| `BasicBlockDiffer` | LCS-based block matching |
| `InstrDiffer` | Instruction-level diff with `InstrDiffKind`: Equal/Modified/Added/Removed |

**Sub-modules**: `basic_block_diff`, `binary_diff`, `bindiff_engine`, `bindiff_format`, `diff_algorithm`, `diff_visualizer`, `function_diff`, `function_hasher`, `function_matching`, `instruction_diff`, `patch_classifier`, `patch_detector`, `patch_diff`, `patch_generator`, `semantic_diff`, `signature_diff`, `structural`, `structural_diff`.

---

### 4.2 rustre-diff-bindiff

| | |
|---|---|
| **Purpose** | BinDiff-style structural binary diffing: CFG topology hashing, multi-phase function matching, call-graph diff |
| **Status** | **PARTIAL** — all algorithms implemented; `petgraph`-backed CFG diff is complete; final reporting partially done |
| **Key external deps** | `rustre-diff`, `rustre-core`, `petgraph`, `serde` |

**Key algorithms and types**

| Type / Function | Description |
|---|---|
| `CfgHasher::hash_cfg(adjacency)` | Weisfeiler-Lehman (WL) graph hash, 3 iterations; topology-invariant |
| `CfgHasher::wl_hash(adjacency, iters)` | WL with configurable iteration count |
| `CfgHasher::hash_linear(n)` | Fast hash for linear-chain CFGs |
| `PrimeProductHash` | Function hash via prime-product of instruction opcodes |
| `SimilarityMatrix` | Pairwise similarity matrix between function sets |
| `HungarianMatcher` | Hungarian algorithm for optimal bipartite matching on similarity scores |
| `FunctionMatcher` | Multi-phase matcher: exact hash -> name hash -> CFG propagation -> heuristic |
| `BasicBlockHasher` | Per-block structural hash |
| `BbMatching` | Block-to-block matching within matched function pairs |
| `CallGraphDiff` | Call-graph level diff: `FunctionNode`, `CallEdge`, node similarity |
| `DiffReporter` | Generates diff output: matched/unmatched/modified function lists |

**Matching pipeline**:
1. Exact-hash match (same CFG topology + instruction bytes)
2. CFG topology hash match (WL hash, byte-independent)
3. Name-based match (symbol names)
4. Call-graph propagation (matched callers propagate to callees)
5. Heuristic similarity (block count, instruction count, string refs)
6. Hungarian assignment on remaining unmatched pairs

---

### 4.3 rustre-diff-semantic

| | |
|---|---|
| **Purpose** | Semantic / behavioural binary diff: match functions by feature vectors, IR normalization, SMT equivalence, type diff |
| **Status** | **PARTIAL** — feature extraction and similarity scoring complete; SMT-based equivalence proving is structural (no solver integration) |
| **Key external deps** | `rustre-diff`, `rustre-core`, `anyhow`, `thiserror`, `serde`, `petgraph` |

**Key types**

| Type | Description |
|---|---|
| `SemanticFeatures` | call_sites, string_refs, constant_pool, mnemonic_histogram, syscall_numbers, loop_count, branch_count, arithmetic_ops, memory_ops |
| `SemanticHash` | Locality-sensitive hash of a semantic feature vector |
| `SemanticEquivalenceChecker` | Structural + SMT-based equivalence (SMT solver not integrated) |
| `NormalizedIL` | Alpha-renamed / constant-folded IR form for comparison |
| `IrSemanticDiff` | IR-level semantic diff |
| `MlilDiff` | MLIL (medium-level IL) diff |
| `AstDiffer` | AST-level diff for decompiled output |
| `TypeDiff` | Struct/type layout diff |
| `VariableDiff` | Variable name/type diff |
| `ControlFlowDiff` | CFG structural equivalence check |
| `CallSiteDiff` | Diff of call sites between functions |
| `SemanticDiffError` | `NormalizationFailed`, `Diff(anyhow::Error)` |

**Key method**:

```rust
impl SemanticFeatures {
    pub fn similarity(&self, other: &Self) -> f64
    // Weighted cosine similarity over feature vector fields
}
```

---

## 5. Cross-subsystem Integration Map

```
rustre-fuzz-cov  --pt_integration-->  rustre-trace-pt   (coverage from PT trace — DECLARED, NOT WIRED)
rustre-fuzz-cov  <------------------  rustre-fuzz        (optional "backends" feature)

rustre-ttd-query  -->  rustre-trace-navigate   (tenet_navigator())
rustre-ttd-query  -->  rustre-trace            (TraceFilter type)
rustre-ttd-query  -->  rustre-ttd              (TtdTrace, EventKind)

rustre-ttd-recorder  -->  rustre-ttd           (TraceEvent, TtdTrace)
rustre-ttd-recorder  -->  rustre-trace         (indirect via rustre-core)
rustre-ttd-replay    -->  rustre-ttd           (TracePosition, TtdTrace)

rustre-diff-bindiff   -->  rustre-diff         (FuncFingerprint, DiffEngine)
rustre-diff-bindiff   -->  rustre-core         (Address type)
rustre-diff-semantic  -->  rustre-diff         (BinaryDiff, FuncMatch)
rustre-diff-semantic  -->  rustre-core         (Instruction, Operand, InstrFlags)

rustre-fuzz-net       -->  rustre-fuzz-afl     (RngCore, XorShiftRng, mutators)
rustre-fuzz-libfuzzer -->  rustre-fuzz-afl     (HavocMutator, Mutator, RngCore)
```

**Missing integration links (known gaps)**:
- `rustre-fuzz-cov::pt_integration` -> `rustre-trace-pt` — declared module but not wired; no live PT data feeds into fuzzing coverage
- `rustre-diff` -> `rustre-ttd-replay` — diff could use replay to extract function bytes at trace positions; not connected
- `rustre-fuzz` -> `rustre-ttd` — snapshot-based fuzzing (record on crash, replay to minimize) is not implemented

---

## 6. Dependency Graph Summary

| Crate | Intra-workspace deps | Key external deps |
|---|---|---|
| `rustre-fuzz` | `rustre-fuzz-cov` (opt), `rustre-fuzz-sanitizers` (opt) | `parking_lot`, `serde`, `thiserror` |
| `rustre-fuzz-afl` | `rustre-fuzz` | `anyhow`, `thiserror`, `serde`, `rayon` |
| `rustre-fuzz-libfuzzer` | `rustre-fuzz`, `rustre-fuzz-afl` | `parking_lot`, `rayon`, `bitflags`, `thiserror` |
| `rustre-fuzz-cov` | none | `serde`, `rayon`, `serde_bytes` |
| `rustre-fuzz-sanitizers` | none | `anyhow`, `parking_lot`, `serde` |
| `rustre-fuzz-net` | `rustre-fuzz`, `rustre-fuzz-afl` | `tokio`, `async-trait`, `serde` |
| `rustre-trace` | `rustre-core`, all four trace sub-crates | `rusqlite`, `parking_lot`, `serde` |
| `rustre-trace-pt` | none | `anyhow`, `serde`, `libc` |
| `rustre-trace-coresight` | none | `anyhow`, `parking_lot`, `libc`, `serde` |
| `rustre-trace-coverage` | none | `serde`, `thiserror` |
| `rustre-trace-navigate` | none | `petgraph`, `tokio`, `rusqlite`, `bincode`, `async-trait` |
| `rustre-ttd` | none | `rusqlite`, `parking_lot`, `serde`, `serde-big-array` |
| `rustre-ttd-recorder` | `rustre-core`, `rustre-ttd`, `rustre-trace` | `bincode`, `tokio`, `chacha20poly1305`, `rusqlite` |
| `rustre-ttd-replay` | `rustre-ttd` | `rusqlite`, `bitflags`, `serde` |
| `rustre-ttd-replayer` | `rustre-ttd` | `parking_lot`, `serde` |
| `rustre-ttd-query` | `rustre-core`, `rustre-ttd`, `rustre-trace`, `rustre-trace-navigate` | `rusqlite`, `parking_lot` |
| `rustre-diff` | none | `ahash`, `crc32fast`, `serde`, `hex` |
| `rustre-diff-bindiff` | `rustre-diff`, `rustre-core` | `petgraph`, `serde` |
| `rustre-diff-semantic` | `rustre-diff`, `rustre-core` | `petgraph`, `anyhow`, `serde` |

---

## 7. Gap Analysis and Priority Fixes

### Implementation Status Summary

| Crate | Status | Notes |
|---|---|---|
| `rustre-fuzz` | COMPLETE | Core primitives fully implemented |
| `rustre-fuzz-afl` | COMPLETE | Full AFL++ feature set |
| `rustre-fuzz-libfuzzer` | COMPLETE | Full libFuzzer harness |
| `rustre-fuzz-cov` | PARTIAL | Data types OK; PT/QEMU integration not wired |
| `rustre-fuzz-sanitizers` | PARTIAL | Model complete; real process integration missing |
| `rustre-fuzz-net` | PARTIAL | Protocol model OK; real TCP/UDP transport missing |
| `rustre-trace` | COMPLETE (hub) | Hub wiring done; depends on sub-crates |
| `rustre-trace-pt` | PARTIAL | Packet decoder + flow done; perf integration structural |
| `rustre-trace-coresight` | PARTIAL | Decoders done; ROM table topology structural |
| `rustre-trace-coverage` | COMPLETE | Full data types and algorithms |
| `rustre-trace-navigate` | PARTIAL | Navigator done; async replay controller partial |
| `rustre-ttd` | PARTIAL | Data model + SQLite index done; Nirvana format partial |
| `rustre-ttd-recorder` | PARTIAL | API complete; Windows ETW hooks are stubs |
| `rustre-ttd-replay` | PARTIAL | Engine done; CPU emulation is placeholder |
| `rustre-ttd-replayer` | PARTIAL | Types complete; memory reconstruction needs wiring |
| `rustre-ttd-query` | PARTIAL | Query language done; SQL/export partial |
| `rustre-diff` | PARTIAL | Core algorithms done; patch generator partial |
| `rustre-diff-bindiff` | PARTIAL | WL hash + Hungarian + pipeline done; reporting partial |
| `rustre-diff-semantic` | PARTIAL | Feature extraction done; SMT prover not wired |

**Observation**: No `todo!` or `unimplemented!` macros found anywhere in these 19 crates. Stubs return empty collections or zero values silently, making them indistinguishable from complete implementations without live end-to-end testing.

### Priority Gaps

**P1 — PT -> Fuzzing Coverage Feedback** (`rustre-fuzz-cov::pt_integration`): The module is declared but not wired. Connect `PtFlowReconstructor::build_coverage()` output to `CoverageDatabase::merge()` so that Intel PT drives AFL-style coverage-guided fuzzing without compile-time instrumentation.

**P2 — Corpus Persistence** (`rustre-fuzz-libfuzzer`): `FuzzCorpusManager::load()` returns in-memory `VecDeque` contents — the `directory: PathBuf` field is stored but never used for real disk I/O. Add `std::fs` read/write to make corpus restart functional across sessions.

**P3 — CPU Emulation in Replay** (`rustre-ttd-replay`): `ForwardStepper` and `BackwardStepper` step through events but do not emulate CPU instructions to reconstruct register state at arbitrary positions. Wiring to `unicorn-engine` or a custom x86/ARM emulation layer is the critical path for full register timeline reconstruction.

**P4 — TTD Recorder on Windows** (`rustre-ttd-recorder`): `EtwRecorder` and `KernelTraceHooks` return `TtdRecordError::NotAvailable` on Windows. Integrate with the WinDbg TTD.exe SDK or implement a minimal PT-based alternative for Windows.

**P5 — Protocol Transport** (`rustre-fuzz-net`): `NetworkSession` trait has no real TCP/UDP backend. Adding a `tokio::net::TcpStream`-backed implementation would make `ProtocolFuzzer` functional for live target fuzzing.

**P6 — SMT Equivalence** (`rustre-diff-semantic`): `SemanticEquivalenceChecker` models an SMT prover interface but has no actual solver backend. Integration with the `z3` crate would enable exact behavioral equivalence checking beyond similarity scoring.

### How These Subsystems Fit the RE Pipeline

```
Binary input
   |
   v
[rustre-diff-bindiff]   -- Structural/CFG diff between two binary versions
[rustre-diff-semantic]  -- Behavioural equivalence across compiler variants
   |
   v
[rustre-fuzz-afl]       -- AFL++-guided test generation targeting diff regions
[rustre-fuzz-libfuzzer] -- In-process libFuzzer harness for targeted fuzzing
[rustre-fuzz-net]       -- Protocol-state-machine fuzzing for network targets
   |
   v
[rustre-trace-pt]            -- Record execution via Intel PT (no instrumentation)
[rustre-trace-coresight]     -- Record execution via ARM CoreSight ETM
[rustre-trace-coverage]      -- Accumulate block/edge/branch coverage
[rustre-trace-navigate]      -- Tenet-style bidirectional navigation over traces
   |
   v
[rustre-ttd]                 -- Record full execution to TTD trace (rr/WinDbg-style)
[rustre-ttd-recorder]        -- OS-level recording via ptrace (Linux) or ETW (Windows)
[rustre-ttd-replay]          -- Deterministic replay to crash point
[rustre-ttd-replayer]        -- Time-travel: step forward/back, reconstruct state
[rustre-ttd-query]           -- Query memory/register/call history at any tick
   |
   v
MCP server tools (rustre-mcp)  -- All capabilities exposed as tool wrappers
```

The four subsystems form a natural progression from static comparison (`diff`) through dynamic test generation (`fuzz`) to trace recording (`trace`) to full time-travel replay (`ttd`). The primary coupling point is `rustre-ttd-query`, which bridges TTD traces with Tenet-style navigation from `rustre-trace-navigate`.
