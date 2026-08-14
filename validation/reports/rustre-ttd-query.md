# rustre-ttd-query

Rich query engine for TTD (Time-Travel Debugging) traces: composable filters,
typed DSL, indexing, aggregation, analysis, and multi-format export.

## Cargo.toml

- **name**: `rustre-ttd-query`
- **version**: 0.1.0
- **edition**: 2024
- **license/description/repository/readme/keywords/categories/authors**: inherited from workspace
- **lints**: workspace

### Dependencies

| Crate | Purpose |
|-------|---------|
| `rustre-core` (path) | Core address abstraction (`CoreAddress`) |
| `rustre-ttd` (path) | `TtdTrace`, `TraceEvent`, `EventKind`, `TracePosition` |
| `rustre-trace` (path) | `TraceFilter` bridging |
| `rustre-trace-navigate` (path) | Tenet-style bidirectional navigator (re-exported) |
| `anyhow`, `thiserror` | Error handling |
| `serde`, `serde_json` | DSL serialization |
| `rusqlite` | SQL engine backend |
| `parking_lot` | RwLock primitives |

## Modules

- `btree_index` — B-Tree index structure for events.
- `query_language` — Parser/typed DSL for queries.
- `query_optimizer` — Query plan optimizer.
- `ttd_sql_engine` — SQL-over-trace engine (rusqlite-backed).
- `trace_index` — Index structures for fast lookup.
- `temporal_query` — Temporal query primitives.
- `memory_timeline` — Memory timeline reconstruction.
- `register_history` — Register history reconstruction.
- `ttd_memory_query`, `ttd_call_stack_query`, `ttd_event_query`,
  `ttd_call_query`, `ttd_exception_query` — Specialized query helpers.

## Re-exports

From `rustre_trace_navigate`: `TenetBookmark`, `TenetCoverageStats`,
`TenetNavError`, `TenetNavEvent`, `TenetStackFrame`.

## Public API (lib.rs)

### Errors

- `QueryError` — variants: `InvalidQuery`, `TraceError`, `ParseError`,
  `DatabaseError(rusqlite)`, `IoError(std::io)`, `ExportError`.

### Core Types

- `TimeRange { start, end }` — pos-range with `new`, `contains`, `Display`.
- `QueryFilter` (legacy) — variants: `MemoryRead`, `MemoryWrite`, `Thread`,
  `CallTo`, `CallFrom`, `SyscallNumber`, `InTimeRange`, `ExceptionCode`,
  `ThreadCreate`, `ThreadExit`. Methods: `matches(&TraceEvent)`.
- `QueryLogic` (legacy) — `And/Or/Not/Single`. Methods: `matches`.
- `MemAccessKind` — `Read | Write | Any`.
- `EventPattern` — 18 pattern variants (AnyMemRead/Write/Call/Return/Syscall,
  MemReadAt/MemWriteAt, CallTo/CallFrom, ReturnFrom/ReturnTo, SyscallNr,
  Exception, ThreadId, InPositionRange, MemWriteWithData, AnyException,
  Breakpoint). Method `matches`.
- `EventKindFilter` — kind discriminator with `matches_kind`.

### Query DSL

- `Query` enum: `EventsOfKind`, `EventsInRange`, `CallChain`, `DataFlow`,
  `Loops`, `Sequence`, `Before`, `After`, `And`, `Or`, `Not`, `Pattern`,
  `Thread`, `InTimeRange`, `AllEvents`.

### Results

- `MatchContext { before, after }` — `empty`, `with_context`.
- `QueryMatch { position, event, context }`.
- `QueryResult { matches, execution_time_ms, events_scanned }` — `is_empty`,
  `len`, `positions`.
- `QueryPlan { description, estimated_events, uses_index }`.

### Indexing

- `EventIndexKind` — Read/Write/CallFrom/CallTo/ReturnFrom/ReturnTo/
  Breakpoint/Exception.
- `QueryIndex` — `build(events)`, `calls_to_address`, `calls_from_address`,
  `syscalls_for_nr`, `accesses_to_address`, `events_for_thread`. Fields:
  `by_address`, `calls_from`, `calls_to`, `syscalls`, `by_thread`.

### QueryEngine

Wraps `Arc<TtdTrace>` and a `QueryIndex`. Public methods:

| Method | Purpose |
|--------|---------|
| `new(trace)` | Construct engine, build index |
| `execute(&Query)` | Evaluate query, return `QueryResult` |
| `execute_in_core_address_range(start, end, kind)` | Bridge via `CoreAddress` |
| `execute_with_trace_filter(&TraceFilter)` | Bridge via `rustre-trace` filter |
| `explain(&Query)` | Return `QueryPlan` |
| `execute_logic(&QueryLogic)` | Legacy `LegacyQueryResult` |
| `count(&QueryFilter)` | Count matches |
| `first_occurrence`, `last_occurrence` | Find first/last matching event |
| `execute_filter(&QueryFilter, events)` | Filter event slice |
| `analyze_memory_access_patterns(start, end)` | `MemoryAccessReport` |
| `analyze_call_frequency()` | `Vec<(addr, count)>` sorted desc |
| `find_recursive_calls()` | `Vec<RecursiveCallChain>` |
| `detect_heap_operations()` | `HeapOperationsReport` |
| `find_string_accesses()` | `Vec<StringAccess>` |
| `summarize_syscalls()` | `HashMap<u32, SyscallStats>` |
| `find_data_races_heuristic()` | `Vec<DataRaceCandidate>` |
| `compute_code_coverage(&[(u64,u64)])` | `CoverageReport` |
| `event_histogram_by_kind()` | `HashMap<String,u64>` |
| `event_histogram_by_thread()` | `HashMap<u32,u64>` |
| `event_histogram_over_time(bucket)` | `Vec<(pos, count)>` |
| `most_accessed_addresses(n)` | Top-N by access count |
| `most_called_functions(n)` | Top-N by call count |
| `export_to_csv_writer(w, filter?)` | CSV export |
| `export_call_graph_dot(w)` | Graphviz DOT export |
| `export_timeline_json(w, filter?)` | JSON timeline |
| `filter_by_address_range(start, end)` | Range filter |
| `tenet_navigator()` | Build a Tenet-style bidirectional navigator |
| (plus SQL/temporal/memory-timeline/register-history helpers) |

### Reports / Aggregate Structs

`MemoryAccessReport`, `RecursiveCallChain`, `HeapOp`, `HeapOperationsReport`,
`StringAccess`, `SyscallStats`, `DataRaceCandidate`, `CoverageReport`,
`LegacyQueryResult`.

## Statistics

- ~148 `pub` items in `lib.rs` alone (148 public symbols, including struct
  fields, methods, modules, re-exports).
- 14 submodules.
- 5326 lines in `lib.rs`.

## Testability

The crate is **testable**: pure-functional query evaluation over
in-memory `TtdTrace`. Unit tests can construct synthetic `TraceEvent` vectors
and exercise `QueryFilter`, `EventPattern`, `Query` DSL, `QueryIndex::build`,
and all analysis methods deterministically. Export functions accept any
`io::Write` (in-memory `Vec<u8>` works). The SQL engine uses in-memory
rusqlite connections.

## Path

`C:\Users\Fra\Desktop\RustRE\crates\rustre-ttd-query`
