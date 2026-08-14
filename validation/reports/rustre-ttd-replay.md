# rustre-ttd-replay

Deterministic replay engine for TTD (Time-Travel Debugging) traces. Analogous to WinDbg TTD backward-stepping or Mozilla rr replay. Restores process state at any position in a TTD trace.

## Cargo.toml

- **name**: `rustre-ttd-replay`
- **version**: `0.1.0`
- **edition**: `2024`
- **license/description/repository/readme/keywords/categories/authors**: inherited from workspace
- **lints**: workspace

### Dependencies
- `rustre-ttd` (path = `../rustre-ttd`) — core TTD trace types
- `thiserror` (workspace)
- `serde`, `serde_json` (workspace)
- `rusqlite` (workspace) — DB-backed indices
- `bitflags` (workspace)

## Modules (`pub mod`)

- `call_stack` — Call-stack reconstruction at any replay position
- `execution_graph`
- `memory_snapshot` — Page-granular memory snapshot diffing
- `replay_analysis`
- `replay_engine` — Trait + in-process replay engine implementation
- `thread_replay` — Per-thread state, register files, context switches
- `time_travel_queries`
- `ttd_format` — Binary TTD file format parser (`.run`, `.idx`, records)
- `watchpoints` — Data-breakpoint / memory watchpoint system
- `forward_stepper`
- `backward_stepper`
- `replay_state_manager`
- `ttd_replay_engine`
- `ttd_breakpoint_manager`
- `ttd_watchpoint_manager`

## Top-level public items (lib.rs)

### Constants
- `PAGE_SIZE` (private, `4096`)
- `RECORDING_MAGIC` = `b"RSTRETTD"`, `RECORDING_VERSION` = `1` (private)

### Errors / enums
- `enum ReplayError` — `InvalidTrace`, `PositionNotFound`, `StateRestoreError`, `EmulationError`, `DatabaseError(rusqlite::Error)`, `SerializationError`, `IoError(std::io::Error)`
- `enum ReplayStopReason` — `BreakpointHit { bp_id, position }`, `WatchpointHit { wp_id, position, old_value, new_value }`, `End`, `Start`, `StepComplete { position }`, `ConditionMet { position }`, `EventKindMatch { position }`. Implements `Display`.
- `enum BreakpointCondition` — `Always`, `RegisterEquals { reg, value }`, `MemoryEquals { addr, value }`, `HitCountMultiple(u64)`
- `enum WatchpointKind` — `Read`, `Write`, `ReadWrite`

### Structs

#### `ReplayBreakpoint { id, address, condition, enabled, hit_count }`
- `const fn new(id: u32, address: u64) -> Self`
- `fn with_condition(self, cond: BreakpointCondition) -> Self`
- `fn fires(&self, rip: u64, registers: &HashMap<String,u64>, mem: &MemoryState) -> bool`
- `Display`

#### `Watchpoint { id, address, size, kind, enabled }`
- `const fn new(id, address, size, kind) -> Self`
- `const fn overlaps(&self, addr: u64, len: usize) -> bool`
- `Display`

#### `MemDiff { address, before, after }` — `Display`
#### `MemPage { base, data, dirty }`
- `fn new(base: u64) -> Self`

#### `MemoryState { pages: BTreeMap<u64, MemPage> }`
- `fn new() -> Self`
- `fn apply_write(&mut self, addr: u64, data: &[u8])`
- `fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>>`
- `fn diff(&self, other: &Self) -> Vec<MemDiff>`
- `fn page_count(&self) -> usize`

#### `Snapshot { position, memory, registers }`
- `const fn new(position, memory, registers) -> Self`

#### `SnapshotCache { interval, snapshots }`
- `const fn new(interval: u64) -> Self`
- `fn insert(&mut self, snapshot: Snapshot)`
- `fn nearest_before(&self, pos: TracePosition) -> Option<&Snapshot>`
- `fn snapshot_count(&self) -> usize`
- `fn clear(&mut self)`
- `fn contains(&self, pos: TracePosition) -> bool`
- `Debug`

#### `ReplayState { position, registers, memory_pages, thread_id }` (legacy)
- `Default`, `Display`

#### `MemoryDelta { address, before, after }` — `Display`
#### `ReplayCheckpoint { position, state }` — `Display`

#### `WatchAddress { addr, size }` — `Display`
#### `WatchpointSet { watchpoints: Vec<WatchAddress> }` (legacy)
- `fn new() -> Self`
- `fn add(&mut self, addr, size)`
- `fn remove(&mut self, addr) -> bool`
- `fn matches(&self, addr, size) -> bool`
- `Display`

#### `DeltaCompressor` (unit struct)
- `fn compute_delta(address, before, after) -> MemoryDelta`
- `fn apply_delta(base: &[u8], delta: &MemoryDelta) -> Vec<u8>`

#### `ReplayEngine` — Full deterministic replay engine
Constructors:
- `fn new(trace: Arc<TtdTrace>) -> Self`
- `fn with_snapshot_interval(trace, interval: u64) -> Self`

Accessors:
- `const fn current_position(&self) -> TracePosition`
- `const fn memory_state(&self) -> &MemoryState`
- `const fn register_state(&self) -> &HashMap<u32, HashMap<String,u64>>`
- `fn breakpoints(&self) -> &[ReplayBreakpoint]`
- `fn watchpoints(&self) -> &[Watchpoint]`
- `fn history(&self) -> &[TracePosition]`
- `const fn snapshot_cache(&self) -> &SnapshotCache`

Breakpoints:
- `fn add_breakpoint(&mut self, address: u64) -> u32`
- `fn add_breakpoint_with_condition(&mut self, address, cond) -> u32`
- `fn remove_breakpoint(&mut self, id) -> bool`
- `fn enable_breakpoint(&mut self, id) -> bool`
- `fn disable_breakpoint(&mut self, id) -> bool`

Watchpoints:
- `fn add_watchpoint(&mut self, address, size, kind) -> u32`
- `fn remove_watchpoint(&mut self, id) -> bool`
- `fn set_watchpoints(&mut self, ws: WatchpointSet)`

Navigation:
- `fn step_forward(&mut self) -> Result<ReplayStopReason, ReplayError>`
- `fn step_backward(&mut self) -> Result<ReplayStopReason, ReplayError>`
- `fn run_forward_to_position(&mut self, pos) -> Result<ReplayStopReason, ReplayError>`
- `fn run_backward_to_position(&mut self, pos) -> Result<ReplayStopReason, ReplayError>`
- `fn run_to_breakpoint_forward(&mut self) -> Result<ReplayStopReason, ReplayError>`
- `fn run_to_breakpoint_backward(&mut self) -> Result<ReplayStopReason, ReplayError>`
- `fn run_to_next_event_of_kind(&mut self, &dyn Fn(&EventKind)->bool) -> Result<ReplayStopReason, ReplayError>`
- `fn go_to_start(&mut self) -> Result<ReplayStopReason, ReplayError>`
- `fn go_to_end(&mut self) -> Result<ReplayStopReason, ReplayError>`

Query APIs:
- `fn find_first_write_to(&self, addr) -> Option<TracePosition>`
- `fn find_last_write_to(&self, addr) -> Option<TracePosition>`
- `fn find_all_writes_to(&self, addr) -> Vec<(TracePosition, Vec<u8>)>`
- `fn find_all_reads_from(&self, addr) -> Vec<TracePosition>`
- `fn find_all_calls_to(&self, target) -> Vec<TracePosition>`
- `fn find_all_calls_from(&self, site) -> Vec<TracePosition>`
- `fn find_value_at(&self, addr, value: &[u8]) -> Vec<TracePosition>`
- `fn get_memory_at(&self, pos, addr, len) -> Option<Vec<u8>>`
- `fn get_register_at(&self, pos, tid, reg) -> Option<u64>`

Bulk / legacy:
- `fn build_snapshot_index(&mut self)`
- `fn current_state(&self) -> ReplayState`
- `fn step_forward_state(&mut self) -> Result<ReplayState, ReplayError>`
- `fn step_backward_state(&mut self) -> Result<ReplayState, ReplayError>`
- `fn goto(&mut self, pos) -> Result<ReplayState, ReplayError>`
- `fn save_checkpoint(&self) -> ReplayCheckpoint`
- `fn restore_checkpoint(&mut self, cp) -> Result<(), ReplayError>`
- `fn apply_event_to_state(state: &mut ReplayState, event: &TraceEvent)` (associated)
- `Debug`

#### `TtdRecordingFile { metadata: TraceMetadata, events: Vec<TraceEvent> }`
- `const fn new(metadata) -> Self`
- `fn from_trace(trace: &TtdTrace) -> Self`
- `fn write_to<W: Write>(&self, w: &mut W) -> Result<(), ReplayError>` — binary format `[magic(8)][version u32le][meta_len u32le][meta_json][event_count u64le][evt_len u32le][evt_json]...`
- `fn read_from<R: Read>(r: &mut R) -> Result<Self, ReplayError>` — validates magic `RSTRETTD`, version `1`, caps metadata at 64 MiB

## Testability
The crate exposes a `tests/` directory and a wide public surface (engine constructors, query APIs, serialization). All major types are `Serialize`/`Deserialize` where applicable, navigation methods return structured `ReplayStopReason`, and the binary recording format has a well-defined header — fully testable in isolation.
