# rustre-ttd

Time Travel Debugging (TTD) core for RustRE — analogous to WinDbg TTD or Mozilla `rr`.
Records process execution into a trace and supports deterministic forward/backward replay.

## Cargo.toml

```toml
[package]
name = "rustre-ttd"
version = "0.1.0"
edition = "2024"
license.workspace = true
description.workspace = true
repository.workspace = true
readme.workspace = true
keywords.workspace = true
categories.workspace = true
authors.workspace = true

[dependencies]
thiserror      = { workspace = true }
serde          = { workspace = true }
serde_json     = { workspace = true }
serde-big-array = "0.5"
rusqlite       = { workspace = true }
parking_lot    = { workspace = true }

[lints]
workspace = true
```

## Module layout (`src/`)

- `lib.rs` — core types (trace, session, index, filters, stats, export/import, watchpoints, syscalls)
- `call_monitor.rs` — call/return event monitoring
- `nirvana_format.rs` — Windows Nirvana trace-format support
- `position.rs`, `replay_position.rs`, `ttd_position.rs` — position cursors
- `replay_query_lang.rs`, `ttd_query_language.rs` — query DSLs over traces
- `trace_index.rs`, `ttd_index.rs`, `ttd_index_builder.rs` — indexing backends
- `ttd_thread_context.rs` — per-thread CPU context
- `ttd_breakpoint_engine.rs` — breakpoint matching over recorded events
- `ttd_heap_tracker.rs` — heap allocation tracking

## Public API (lib.rs)

### Errors
- `enum TtdError` — `TraceNotOpen`, `InvalidPosition{seq,step}`, `ReadError`, `IoError`, `CorruptTrace`, `UnsupportedVersion`, `DatabaseError`, `SerdeError`.

### `TracePosition` — `seq:step` cursor (WinDbg-style)
- `new(sequence, step)`, `start()`, `next_sequence()`, `next_step()`
- `is_before(&Self)`, `is_after(&Self)`, `in_range(start, end)`
- `as_u128()`, `from_u128(v)` — compact encoding
- `Display`, `Default`, `Ord`, `Hash`, `Serialize`, `Deserialize`

### `MemorySnapshot` — bytes at an address
- `new(address, data)`, `end_address()`, `contains(addr)`
- `read_u8/u16_le/u32_le/u64_le(addr)`
- `apply_write(write_addr, &[u8]) -> usize`

### `ThreadState` — register snapshot
- `new(tid)`, `set_register(name, val)`, `get_register(name) -> Option<u64>`
- Fields: `tid`, `registers`, `stack_pointer`, `instruction_pointer`

### `EventKind` — recorded event variants
- Variants: `MemRead{addr,len}`, `MemWrite{addr,data}`, `Call{from,to}`, `Return{from,to}`,
  `SyscallEnter{nr,args[6]}`, `SyscallExit{nr,ret}`, `Exception{code,addr}`,
  `ThreadCreate{tid}`, `ThreadExit{tid,code}`, `Breakpoint{addr}`
- `is_memory_access()`, `is_control_flow()`, `is_syscall()`, `is_thread_lifecycle()`
- `address() -> Option<u64>`

### `TraceEvent`
- `new(position, thread_id, kind)`, fields: `position`, `thread_id`, `kind`

### `TraceMetadata`
- Fields: `version`, `process_name`, `pid`, `arch`, `start_time`, `end_time`, `thread_count`, `start_position`, `end_position`, `thread_ids`
- `Default` impl (x86_64, version 1)

### `TtdTrace` — append-only event log (RwLock-protected)
- `new(metadata)`, `add_event(event)`, `push_event(&mut self, event)`
- Queries: `events_at_position(pos)`, `events_for_thread(tid)`, `events_in_range(start, end)`,
  `events_of_kind(name)`, `all_events()`, `event_count()`, `last_position()`,
  `thread_ids()`, `sort_events()`

### `TtdSession` — cursor over a trace
- `open(Arc<TtdTrace>)`
- `step_forward() -> Result<&TraceEvent, TtdError>`
- `step_back() -> Result<TracePosition, TtdError>`
- `goto_position(pos) -> Result<(), TtdError>`
- `current_position()`, `is_at_end()`, `is_at_start()`, `peek_next()`
- `skip_while(predicate) -> Result<usize, TtdError>`
- `remaining_events()`, `trace() -> &Arc<TtdTrace>`

### `TtdIndex` — SQLite-backed event index
- `open_in_memory() -> Result<Self, TtdError>`
- `index_trace(&TtdTrace) -> Result<()>`
- `find_events_near(&pos)`, `find_events_by_kind_in_range(kind, start_seq, end_seq)`
- `event_count_by_thread() -> HashMap<u32,u64>`
- `event_count_by_kind() -> HashMap<String,u64>`
- `total_event_count() -> u64`, `clear()`

### `MemoryRegion` / `MemoryMap`
- `MemoryRegion::new(start, end, label)`, `contains(addr)`, `size()`; fields include `executable`, `writable`
- `MemoryMap::new()`, `add_region(r)`, `region_at(addr)`, `regions()`
- `MemoryMap::from_trace(&TtdTrace)` — derives 4 KiB pages from `MemWrite` events

### `CallFrame` / `CallStack`
- `CallFrame { call_site, callee, position }`
- `CallStack::new/push/pop/depth/top/frames`
- `CallStack::from_trace(trace, tid, up_to_pos)` — replays call/return events

### `TraceFilter` — composable predicates
- Variants: `ByThread(u32)`, `ByKind(String)`, `ByRange(TracePosition,TracePosition)`,
  `ByAddressRange(u64,u64)`, `And`, `Or`, `Not`
- `matches(&TraceEvent) -> bool`, `apply(&[TraceEvent]) -> Vec<TraceEvent>`
- Combinators: `.and(other)`, `.or(other)`, `!filter` (via `Not` impl)

### `TraceStats`
- Fields: `total_events`, `mem_reads`, `mem_writes`, `calls`, `returns`, `syscall_enters`, `exceptions`, `bytes_written`, `bytes_read`, `thread_count`
- `TraceStats::compute(&TtdTrace) -> Self`

### `TraceExporter` / `TraceImporter` — NDJSON serialization
- `TraceExporter::export<W: Write>(&TtdTrace, W) -> Result<()>`
- `TraceExporter::export_to_string(&TtdTrace) -> Result<String>`
- `TraceImporter::import<R: BufRead>(R) -> Result<TtdTrace>`
- `TraceImporter::import_from_str(&str) -> Result<TtdTrace>`

### `Watchpoint`
- `WatchpointKind`: `Read | Write | ReadWrite`
- `Watchpoint::new(address, size, kind)`, `.with_label(s)`
- `triggered_by(&TraceEvent) -> bool` (overlap test, saturating)
- `find_hits(&TtdTrace) -> Vec<TraceEvent>`

### `SyscallInfo` / `SyscallSummary`
- `SyscallSummary::from_trace(&TtdTrace)` — pairs Enter/Exit per thread
- `total_calls() -> u64`, `top_syscalls() -> Vec<&SyscallInfo>` (sorted desc)

## Testability

- Pure-Rust core, no FFI; all I/O is in-memory or via supplied `Read`/`Write`.
- `TtdIndex::open_in_memory()` enables hermetic SQLite tests.
- `TtdTrace` uses `RwLock<Vec<_>>` — safe for concurrent unit tests.
- Round-trip testable via `TraceExporter` → `TraceImporter`.
- A `tests/` directory is present in the crate.

Source: `C:\Users\Fra\Desktop\RustRE\crates\rustre-ttd\src\lib.rs` (3274 lines; this report covers the lib.rs public surface; submodules listed above expose additional APIs).
