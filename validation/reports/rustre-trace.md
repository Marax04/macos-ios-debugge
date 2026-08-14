# rustre-trace

Core execution tracing abstraction for the RustRE workspace. Provides unified
trace recording, replay, diff, slicing, coverage, merging, filtering,
indexing, compression, and visualization data types — and aggregates the
specialized backend crates (`rustre-trace-coresight`, `rustre-trace-coverage`,
`rustre-trace-navigate`, `rustre-trace-pt`) under a single `registry` hub.

## Cargo.toml

- **name**: `rustre-trace`
- **version**: `0.1.0`
- **edition**: `2024`
- **license / description / repo / readme / keywords / categories / authors**:
  inherited from workspace
- **lints**: workspace

### Dependencies

| Crate | Notes |
|---|---|
| `rustre-core` | path `../rustre-core` — canonical `Address` type |
| `rustre-trace-coresight` | path — ARM CoreSight ETM decoder |
| `rustre-trace-coverage` | path — Lighthouse-style coverage sessions |
| `rustre-trace-navigate` | path — Tenet-style trace navigation |
| `rustre-trace-pt` | path — Intel Processor Trace decoder/flow |
| `anyhow` | workspace |
| `thiserror` | workspace — `TraceError` variants |
| `serde` + `serde_json` | workspace — serialization of records/sessions |
| `rusqlite` | workspace — `TraceStore` persistent backend |
| `parking_lot` | workspace — `Mutex` around the SQLite connection |

No `[features]`, no `[dev-dependencies]` declared at the crate level (tests
rely on workspace-provided utilities).

## Source layout

Modules declared in `src/lib.rs`:

- `trace_analysis`
- `trace_annotation`
- `trace_annotator`
- `trace_compressor`
- `trace_database`
- `trace_export`
- `trace_filter`
- `trace_format`
- `trace_hot_spots`
- `trace_importer`
- `trace_index`
- `trace_indexer`
- `trace_serializer`
- `trace_statistics`

Integration tests: `tests/blitz.rs`, `tests/blitz2.rs`.

The crate exposes ~219 public functions/methods in `lib.rs` alone (plus more
across the submodules). The summary below covers the public API actually
declared inside `lib.rs`.

## `registry` — backend hub

Re-exports the primary engine types of every trace sub-crate so downstream
consumers depend only on `rustre-trace`:

- `CoreSightDecoder` (from `rustre-trace-coresight`)
- `CoverageSession` (from `rustre-trace-coverage`)
- `TraceNavigator` (from `rustre-trace-navigate`)
- `PtDecoder`, `PtError`, `PtEvent`, `PtFlow`, `PtFlowReconstructor`,
  `PtPacket`, `PtPacketKind`, `PtTrace`, `SidebandInfo`, `TimingInfo`,
  `IpCompression` and the full set of `pt_*` submodules (block/instruction/
  packet decoders, flow reconstruction, sideband correlation, snapshotting,
  perf integration, timing, coverage reporting, filtering, trace builder)
  (from `rustre-trace-pt`)

### `enum TraceEngine`

Variants: `CoreSight(CoreSightDecoder)`, `Coverage(CoverageSession)`,
`Navigate(Box<TraceNavigator>)`, `Pt(PtDecoder)`.

- `pub const fn name(&self) -> &'static str` — static engine name
  (`"coresight"`, `"coverage"`, `"navigate"`, `"pt"`).

### Free functions

- `pub fn all_engines() -> Vec<TraceEngine>` — construct one instance of every
  registered engine using sensible defaults (ETMv4 / arm64 / default coverage
  / empty nav trace / fresh PT decoder).
- `pub fn engine_names() -> Vec<&'static str>` — static names of all
  registered engines.

## Errors

### `enum TraceError` (`#[derive(Debug, Error)]`)

- `AlreadyRunning` — provider already started.
- `NotRunning` — provider not started.
- `Io(String)` — I/O or backing-store failure.
- `Unsupported(String)` — operation not supported by a backend.
- `NotFound(u64)` — trace record id missing.
- `Store(#[from] rusqlite::Error)` — wrapped SQL error.
- `SliceOutOfBounds { start, end, len }` — invalid slice range.
- `MergeMismatch(String)` — incompatible sessions for merge (e.g. arch).
- `Serialization(String)` / `Deserialization(String)`.
- `Other(#[from] anyhow::Error)` — escape hatch.

## Events and records

### `enum TraceEvent`

Variants: `Instruction { addr, size }`, `MemRead { addr, size, value }`,
`MemWrite { addr, size, value }`, `Call { from, to }`, `Return { from, to }`,
`Exception { code, addr }`, `Syscall { number, args }`,
`Branch { from, to, taken }`, `ModuleLoad { base, size, name }`,
`RegisterChange { name, old_value, new_value }`.

Public API:

- `pub const fn primary_addr(&self) -> u64`
- `pub const fn type_name(&self) -> &'static str` (e.g. `"Instruction"`)
- `pub const fn is_instruction(&self) -> bool`
- `pub const fn is_memory_access(&self) -> bool`
- `pub const fn is_control_flow(&self) -> bool`
- `pub const fn is_syscall(&self) -> bool`
- `pub const fn is_exception(&self) -> bool`
- `impl Display` — pretty event formatter.

### `struct TraceRecord { seq, event, thread_id, timestamp_ns }`

- `pub const fn new(seq, event, thread_id, timestamp_ns) -> Self`
- `impl Display` — `"[seq] tid=… t=…ns <event>"`.

### `struct TraceFrame { record, registers: HashMap<String,u64>, call_depth }`

- `pub fn new(record: TraceRecord) -> Self`
- `pub const fn seq(&self) -> u64`
- `pub const fn thread_id(&self) -> u32`
- `pub const fn timestamp_ns(&self) -> u64`
- `pub const fn instruction_pointer(&self) -> Option<u64>`
- `pub fn set_register(&mut self, name: impl Into<String>, value: u64)`
- `pub fn get_register(&self, name: &str) -> Option<u64>`

## Filtering

### `struct TraceFilter`

Fields: `min_addr`, `max_addr`, `thread_id`, `event_types: Vec<String>`,
`kinds: Vec<String>` (alias of `event_types`), `min_timestamp_ns`,
`max_timestamp_ns`, `seq_range: Option<(u64,u64)>`.

- `pub fn new() -> Self`
- `pub fn instructions_only() -> Self`
- `pub fn for_thread(tid: u32) -> Self`
- `pub fn address_range(min: u64, max: u64) -> Self`
- `pub fn core_address_range(min: CoreAddress, max: CoreAddress) -> Self`
  (bridges `rustre_core::address::Address`)
- `pub fn time_range(min_ns: u64, max_ns: u64) -> Self`
- `pub fn matches(&self, rec: &TraceRecord) -> bool`
- `pub fn apply<'a>(&self, records: &'a [TraceRecord]) -> Vec<&'a TraceRecord>`
- `pub const fn is_empty(&self) -> bool`
- `pub fn validate(&self) -> Result<(), String>` — errors if both
  `event_types` and `kinds` are set (the latter would be silently dropped).

## Sessions and recorders

### `struct TraceSession { records, name, arch, next_seq (private) }`

- `pub fn new(name, arch) -> Self`
- `pub fn push(&mut self, event, thread_id, timestamp_ns)`
- `pub fn push_event(...)` — alias for `push`
- `pub fn filter(&self, &TraceFilter) -> Vec<&TraceRecord>`
- `pub fn instruction_count(&self) -> usize`
- `pub fn unique_pcs(&self) -> HashSet<u64>`
- `pub fn unique_addresses(&self) -> HashSet<u64>` (alias of `unique_pcs`)
- `pub const fn record_count(&self) -> usize`
- `pub fn slice(&self, start, end) -> Result<Vec<&TraceRecord>, TraceError>`
- `pub fn merge(&mut self, other: &Self) -> Result<(), TraceError>` —
  requires matching `arch`; re-sequences imported records.
- `pub fn thread_ids(&self) -> HashSet<u32>`
- `pub fn event_type_counts(&self) -> HashMap<&'static str, usize>`
- `pub fn duration_ns(&self) -> u64`
- `pub fn build_heat_map(&self) -> HeatMap`
- `pub fn build_index(&self) -> Result<TraceIndex, TraceError>`
- `pub fn records_for_thread(&self, tid) -> Vec<&TraceRecord>`
- `pub fn coverage_set(&self) -> HashSet<u64>`
- `pub fn first_record(&self) / last_record(&self) -> Option<&TraceRecord>`

### `struct TraceRecorder`

Fields: private `session`, `pub event_count`, `pub max_events`, private
`flushed_count`.

- `pub fn new(name, arch) -> Self`
- `pub fn with_max_events(name, arch, max) -> Self`
- `pub fn record(&mut self, event, thread_id, ts_ns)`
- `pub fn record_instruction / record_mem_read / record_mem_write /
   record_call / record_return / record_exception / record_syscall`
- `pub fn finish(self) -> TraceSession`
- `pub const fn flushed_count(&self) -> u64`
- `pub const fn is_full(&self) -> bool`
- `pub const fn session(&self) -> &TraceSession`

### `struct TracePlayer { session (priv), pub cursor, pub speed }`

- `pub const fn new(session) -> Self`
- `pub fn next(&mut self) -> Option<&TraceRecord>`
- `pub fn peek(&self) -> Option<&TraceRecord>`
- `pub const fn reset(&mut self)`
- `pub fn seek_to_seq(&mut self, seq: u64) -> bool`
- `pub const fn is_done(&self) -> bool`
- `pub const fn remaining(&self) -> usize`
- `pub fn peek_all_remaining(&self) -> &[TraceRecord]`
- `pub const fn step_back(&mut self) -> bool`
- `pub const fn total(&self) -> usize`
- `pub fn progress(&self) -> f64`

## Diff, coverage, index

### `struct TraceDiff { only_in_left, only_in_right, common_count }`

- `pub fn compute(left, right: &TraceSession) -> Self`
- `pub const fn is_identical(&self) -> bool`
- `pub const fn total_unique(&self) -> usize`
- `pub fn similarity(&self) -> f64` — Jaccard-style on `(type, primary_addr)`.

### `struct CoverageMap { counts: BTreeMap<u64,u64>, total_addresses }`

- `pub fn new() -> Self` / `pub const fn with_total(total) -> Self`
- `pub fn record_hit(&mut self, addr)` / `record_hits(&mut self, addr, n)`
- `pub fn hit_count(&self, addr) -> u64`
- `pub fn unique_addresses_hit(&self) -> usize`
- `pub fn total_hits(&self) -> u64`
- `pub fn coverage_ratio(&self) -> f64`
- `pub fn merge(&mut self, other: &Self)`
- `pub fn hottest_addresses(&self, n) -> Vec<(u64,u64)>` (uses
  `select_nth_unstable_by` for partial top-N selection)
- `pub fn uncovered_in_range(&self, start, end, step) -> Vec<u64>`
- `pub fn from_session(session: &TraceSession) -> Self`

### `struct TraceIndex`

In-memory index of `addr → seqs`, `tid → seqs`, `type → seqs`, `seq → idx`.

- `pub fn new() -> Self`
- `pub fn insert_record(&mut self, rec: &TraceRecord)`
- `pub fn seqs_at_addr(&self, addr) -> &[u64]`
- `pub fn seqs_for_thread(&self, tid) -> &[u64]`
- `pub fn seqs_by_type(&self, name: &str) -> &[u64]`
- `pub fn all_addresses(&self) -> Vec<u64>`
- `pub fn all_thread_ids(&self) -> Vec<u32>`
- `pub fn all_event_types(&self) -> Vec<&'static str>`
- `pub fn total_indexed(&self) -> usize`

## Providers

### `trait TraceProvider: Send + Sync`

- `fn name(&self) -> &str`
- `fn start(&mut self) -> Result<(), TraceError>`
- `fn stop(&mut self) -> Result<TraceSession, TraceError>`

### `struct InMemoryTraceProvider`

Replays a pre-recorded `Vec<TraceEvent>` when `start`/`stop` is called. Fields
`pub name`, `pub running`, plus private `session` and `pre_recorded`.

- `pub fn with_pre_recorded(name, arch, records) -> Self`
- `pub fn with_events(name, arch, events) -> Self` (alias)
- Implements `TraceProvider` (events are pushed with `tid=1` and synthetic
  `i * 100 ns` timestamps; the buffer is cloned, not drained, so the provider
  can be reused across cycles).

## High-level facade

### `struct Trace { session, description }`

- `pub const fn new(session) -> Self`
- `pub fn with_description(session, description) -> Self`
- `pub const fn len(&self) -> usize` / `pub const fn is_empty(&self) -> bool`
- `pub fn records(&self) -> &[TraceRecord]`
- `pub fn name(&self) / arch(&self) -> &str`
- `pub fn coverage_map(&self) -> CoverageMap`
- `pub fn diff(&self, other: &Self) -> TraceDiff`
- `pub fn to_json(&self) -> Result<Vec<u8>, TraceError>`
- `pub fn to_json_pretty(&self) -> Result<String, TraceError>`
- `pub fn from_json(data: &[u8]) -> Result<Self, TraceError>`
- `pub fn to_binary(&self) -> Result<Vec<u8>, TraceError>` — length-prefixed
  (u32 LE) JSON envelope with overflow check.
- `pub fn from_binary(data: &[u8]) -> Result<Self, TraceError>`
- `pub fn visualization_data(&self) -> TraceVisualizationData`
- `pub fn player(&self) -> TracePlayer`
- `pub fn filtered(&self, &TraceFilter) -> Self`

### `struct TraceVisualizationData`

Aggregate snapshot for UIs: `total_events`, `unique_addresses`,
`event_type_counts: HashMap<String,usize>`, `thread_activity: HashMap<u32,usize>`,
`hot_addresses: Vec<(u64,u64)>` (top 20 from `CoverageMap::hottest_addresses`),
`time_range: (u64,u64)`, `thread_count`.

- `pub fn from_trace(trace: &Trace) -> Self`

## Compression

### `struct TraceCompressor` + `struct CompressedBlock`

Run-length compression by `(event, thread_id)` adjacency.

- `pub fn compress(session: &TraceSession) -> Vec<CompressedBlock>`
- `pub fn decompress(blocks, name, arch) -> TraceSession`
- `pub fn compression_ratio(original_count, block_count) -> f64`

`CompressedBlock { start_seq, event, count, thread_id, first_timestamp_ns }`.

## Legacy types (kept for downstream)

- `struct MemAccess { address, size, value }`
- `struct SyscallRecord { number, name, args, ret }`
- `struct LegacyTraceRecord { id, address, thread_id, timestamp, registers,
   mem_reads, mem_writes, syscall }`
  - `pub fn new(id, address, thread_id, timestamp) -> Self`
  - `pub const fn has_memory_access(&self) -> bool`
  - `pub const fn has_syscall(&self) -> bool`
  - `pub fn add_mem_read / add_mem_write(&mut self, address, size, value)`
  - `pub fn set_register(&mut self, name, value)`

## Persistent storage

### `struct TraceStore` (SQLite-backed)

Wraps `Arc<Mutex<rusqlite::Connection>>` (`parking_lot::Mutex`).

- `pub fn open(path: &str) -> Result<Self, TraceError>` — opens/creates DB
  and initializes the schema.
- `pub fn open_memory() -> Result<Self, TraceError>` — in-memory DB
  convenience.
- Additional persistence methods follow in the rest of the file (insert,
  query, drop, etc.) — see `lib.rs` from line 1856 onward and the
  `trace_database` / `trace_serializer` modules for the full surface.

## Auxiliary types referenced by the surface

- `HeatMap` — produced by `TraceSession::build_heat_map()`; declared further
  down in `lib.rs` (`trace_hot_spots` module also exposes related utilities).

## Submodules (public)

Each is `pub mod`, contributing additional surface beyond what is documented
here:

- `trace_analysis` — higher-level analyses over sessions.
- `trace_annotation`, `trace_annotator` — event/trace annotation.
- `trace_compressor` — extended compression strategies beyond RLE.
- `trace_database` — schema/queries for `TraceStore`.
- `trace_export`, `trace_importer`, `trace_format`, `trace_serializer` —
  I/O and interchange formats.
- `trace_filter` — extended filter combinators.
- `trace_hot_spots` — hotspot detection.
- `trace_index`, `trace_indexer` — index builders.
- `trace_statistics` — descriptive statistics.

## Notes for callers

- `TraceFilter` exposes both `event_types` and `kinds`; if both are populated
  `event_types` wins and `kinds` is silently ignored — call `validate()` to
  catch this.
- `TraceSession::merge` re-sequences imported records (sequence numbers in
  the source session are not preserved).
- `Trace::to_binary` / `from_binary` is a length-prefixed JSON envelope — not
  a true binary format.
- `InMemoryTraceProvider` clones (does not drain) its pre-recorded buffer at
  `stop`, so it can be cycled multiple times.
- The `registry` module is the recommended entry point for code that wants to
  use any tracing backend without taking a direct path-dependency on the
  sub-crates.
