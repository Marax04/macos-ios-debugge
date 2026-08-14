# rustre-ttd-replayer

Time-Travel Debug (TTD) replay engine: deterministic forward/backward stepping over a recorded execution trace, memory and register state reconstruction at arbitrary ticks, root-cause analysis, and a small query DSL.

## Cargo.toml

- name: `rustre-ttd-replayer`
- version: `0.1.0`
- edition: `2024`
- license/description/repository/readme/keywords/categories/authors: from workspace

Dependencies:
- `rustre-ttd` (path `../rustre-ttd`)
- `thiserror`, `serde`, `serde_json`, `parking_lot` (workspace)

Lints: workspace.

## Modules (`pub mod`)

`api_call_tracker`, `memory_diff_viewer`, `memory_reconstructor`, `register_timeline`, `replay_engine`, `replay_stats`, `differential_replay`, `snapshot_manager`, `replay_scheduler`, `trace_diff`, `ttd_call_recorder`, `ttd_memory_provider`, `ttd_trace_loader`, `ttd_database`, `position_engine`, `replay_controller`, `timeline`.

## Public constants (lib.rs)

- `DEFAULT_SNAPSHOT_INTERVAL: u64 = 256`
- `MAX_MEM_WRITES_PER_EVENT: usize = 1024`
- `REPLAY_PAGE_SIZE: usize = 4096`

## Core types

### `ReplayError` (enum, `thiserror::Error`)
Variants: `TickOutOfRange(u64,u64)`, `NoSnapshot(u64)`, `AddressNotMapped(u64,u64)`, `ReadOverflow{addr,size,tick}`, `AtStart`, `AtEnd`, `QueryParse(String)`, `QueryExec(String)`, `MalformedTrace(String)`, `Internal(String)`.

### `MemWriteRecord { addr: u64, data: Vec<u8> }`
- `const fn new(addr, data)`
- `const fn size()`, `const fn end_addr()`
- `const fn overlaps(addr, size)`
- `fn bytes_in_range(addr, size) -> Vec<u8>`
- `Display`

### `TraceEvent` (enum)
- `SyscallEntry { tick, nr, args: [u64;6] }`
- `SyscallExit { tick, retval: i64, mem_writes: Vec<MemWriteRecord> }`
- `SignalDelivered { tick, signal: i32, pc: u64 }`

Methods: `const fn tick()`, `const fn kind_name()`, `const fn has_mem_writes()`, `const fn mem_writes() -> &[MemWriteRecord]`, `const fn syscall_nr() -> Option<u64>`, `Display`.

### `TraceSnapshot { tick, regs: HashMap<String,u64>, mem_pages: HashMap<u64,Vec<u8>> }`
- `fn new(tick)`
- `fn set_reg(name, value)`, `fn get_reg(name) -> Option<u64>`
- `fn write_mem(addr, &[u8])`, `fn read_mem(addr, size) -> Option<Vec<u8>>`
- `fn page_count()`, `fn memory_footprint()`

### `TtdTrace { events, snapshots, tick_index }`
- `const fn new()`, `Default`
- `fn from_parts(events, snapshots)`
- `fn push_event(event)`, `fn push_snapshot(snap)`
- `fn rebuild_tick_index()`
- `fn max_tick()`, `fn min_tick()`
- `fn first_event_at_or_after(target) -> Option<usize>`
- `fn last_event_at_or_before(target) -> Option<usize>`
- `fn nearest_snapshot_before(target) -> Option<&TraceSnapshot>`
- `fn events_in_range(from, to) -> impl Iterator`
- `fn event_counts() -> HashMap<&'static str, usize>`
- `fn all_writes_touching(addr, size) -> Vec<(u64, &MemWriteRecord)>`
- `const fn is_empty()`, `const fn len()`

### `ReplayState { regs, mem }`
- `fn new()`, `Default`
- `fn load_snapshot(&TraceSnapshot)`
- `fn reg(name) -> u64`, `fn set_reg(name, value)`
- `fn apply_write(&MemWriteRecord)`
- `fn read(addr, size) -> Option<Vec<u8>>`
- `fn footprint()`, `fn program_counter() -> Option<u64>`

### `TtdReplayer { trace, current_tick, state, .. }`
- `fn new(trace) -> Self`
- `fn goto(target_tick) -> Result<(), ReplayError>`
- `fn step_forward() -> Result<&TraceEvent, ReplayError>`
- `fn step_backward() -> Result<&TraceEvent, ReplayError>`
- `fn find_all_writes_to(addr, size) -> Vec<(u64, Vec<u8>)>`
- `fn read_memory_at_tick(tick, addr, size) -> Result<Vec<u8>, ReplayError>`
- `fn find_last_write_before(addr, tick) -> Option<(u64, Vec<u8>)>`
- `fn find_last_write_range_before(addr, size, tick) -> Option<(u64, Vec<u8>)>`
- `fn pc() -> Option<u64>`
- `const fn at_end()`, `const fn at_start()`
- `fn reset()`, `const fn remaining_events()`

### `QueryValue` (enum)
`Int(u64)`, `SignedInt(i64)`, `Bytes(Vec<u8>)`, `WriteList(Vec<(u64,Vec<u8>)>)`, `EventList(Vec<TraceEvent>)`, `Text(String)`, `Null`. Implements `Display`.

### `QueryAst` (enum)
`ReadMem{tick,addr,size}`, `FindWrites{addr,size}`, `LastWrite{addr,tick}`, `ListSyscalls{nr:Option<u64>}`, `ListSignals`, `ReadReg{tick,reg}`, `CountEvents{kind}`, `RootCause{crash_tick,crash_addr}`, `MaxTick`, `MinTick`.

### `TtdQuery { ast, text }`
DSL:
```
read_mem <tick> <addr_hex> <size>
find_writes <addr_hex> <size>
last_write <addr_hex> <tick>
list_syscalls [nr]
list_signals
read_reg <tick> <reg_name>
count_events <kind>
root_cause <crash_tick> <crash_addr_hex>
max_tick
min_tick
```
- `fn parse(text) -> Result<Self, ReplayError>` (caps `read_mem`/`find_writes` size at 256 MiB)
- `fn execute(&mut TtdReplayer) -> Result<QueryValue, ReplayError>`

### Root-cause analysis
- `CausalStep { tick, description, addr, data }` with `new`, `with_addr`, `with_data`.
- `RootCauseReport { crash_tick, crash_addr, chain, summary, confidence }` with `new`, `push_step`, `earliest_cause`, `Display`.
- `fn find_root_cause(&mut TtdReplayer, crash_tick, crash_addr) -> Result<RootCauseReport, ReplayError>` — walks backward: last write to crash_addr -> preceding syscall -> follow pointer target -> last preceding signal; assigns confidence by chain length.

### `TraceBuilder`
- `fn new(snapshot_interval)`
- `fn syscall_entry(nr, args) -> u64`
- `fn syscall_exit(retval, mem_writes) -> u64`
- `fn signal(signal, pc) -> u64`
- `fn snapshot(regs, mem_pages)`
- `fn build() -> TtdTrace`
- `const fn snapshot_interval()`
- `fn next_tick_is_snapshot_boundary() -> bool`

### `TraceStats`
Fields: `total_events`, `syscall_entries`, `syscall_exits`, `signals`, `total_bytes_written`, `unique_write_addrs`, `min_tick`, `max_tick`, `snapshot_count`, `syscall_freq: HashMap<u64,usize>`. Constructor `fn compute(&TtdTrace) -> Self`.

## Submodules of interest

`ttd_trace_loader` defines on-disk trace format: `TRACE_MAGIC = 0x0052_554e_0044_5454`, `SUPPORTED_VERSION_MAJOR = 2`, `HEADER_SIZE = 128`, `FRAME_SIZE = 32`, kind tags (`KIND_SYSCALL_ENTRY/EXIT/SIGNAL/SNAPSHOT/MODULE_LOAD/END`), and public types `LoadError`, `TraceArch`, `ModuleEntry`, `TraceHeader`, `PositionIndex`, `LoadOptions`, `LoadResult`.

Other modules (`api_call_tracker`, `memory_diff_viewer`, `memory_reconstructor`, `register_timeline`, `replay_engine`, `replay_stats`, `differential_replay`, `snapshot_manager`, `replay_scheduler`, `trace_diff`, `ttd_call_recorder`, `ttd_memory_provider`, `ttd_database`, `position_engine`, `replay_controller`, `timeline`) provide higher-level orchestration on top of these primitives.

## Tests
Integration tests present: `tests/blitz.rs`, `tests/blitz2.rs` — the crate is testable via `cargo test -p rustre-ttd-replayer`.
