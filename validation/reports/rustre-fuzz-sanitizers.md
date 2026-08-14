# rustre-fuzz-sanitizers

Pure-Rust sanitizer framework providing logic equivalents to ASan, MSan, UBSan,
TSan and LSan. No actual LLVM sanitizer infrastructure is used; the crate tracks
heap allocations, shadow memory, and arithmetic operations in software, and
parses sanitizer log text into structured reports.

## Cargo.toml

- name: `rustre-fuzz-sanitizers`
- version/edition/license/...: from workspace
- dependencies: `anyhow`, `thiserror`, `serde`, `serde_json`, `parking_lot`
- Note (Cargo.toml comment): `rustre-fuzz` (the umbrella) depends on this crate,
  not the reverse.

## Modules (declared in `src/lib.rs`)

`cast`, `asan_analyzer`, `asan_runtime`, `coverage_guided_fuzzer`,
`crash_deduplicator`, `msan_model`, `msan_tracker`, `sanitizer_runtime`,
`shadow_memory`, `tsan_model`, `ubsan_checks`, `asan_report_parser`,
`ubsan_report_parser`, `sanitizer_crash_deduplicator`, `msan_report_parser`,
`tsan_report_parser`, `sanitizer_dashboard`.

Approx. 465 `pub fn` items across the crate (490 including methods in
non-`pub fn` syntax variations).

## Top-level API (`lib.rs`)

### Enums / kinds

- `SanitizerKind`: `MemoryUninit | HeapOverflow | UseAfterFree | DoubleFree |
  NullDeref | IntOverflow | Misaligned | DivByZero | HeapUnderflow`. Implements
  `Display`.
- `ArithOp`: `Add | Sub | Mul`.
- `SanitizerTool`: `ASan | MSan | UBSan | LSan | TSan | Unknown` (serde + Display).
- `AccessType`: `Read | Write` (serde + Display).
- `CrashSeverity`: `Info | Low | Medium | High | Critical` (Ord + serde + Display).
- `SanitizerResult`: `Clean | HeapOverflow{addr,size,alloc_base,alloc_size} |
  UseAfterFree{addr,freed_at} | DoubleFree{addr} | HeapUnderflow{addr}`.

### Reports

- `SanitizerReport { kind, message, stack_trace }`
  - `new(kind, message: impl Into<String>, stack_trace: Vec<u64>) -> Self`
- `ParsedStackFrame { index, address, function, file, line, column }`
  - `empty(index) -> Self`
  - `display(&self) -> String` -> `"#N 0xADDR in func file:line"`
- `ParsedCrashReport { tool, error_type, access_type, access_size, address,
  thread, stack_frames, allocation_frames, deallocation_frames, raw_text,
  severity }`
  - `summary(&self) -> String`
  - `top_function(&self) -> Option<&str>`

### Shadow memory & MSan

- `ShadowMemory { bits: HashMap<u64, Vec<u8>> }` (256-byte pages, 1 bit/byte).
  - `new()`, `mark_defined(addr,len)`, `mark_undefined(addr,len)`,
    `check_defined(addr,len) -> bool`.
- `MemorySanitizer { shadow }`
  - `new()`, `mark_defined`, `mark_undefined`,
    `check(addr,len) -> Result<(), SanitizerReport>`.

### Heap tracking & ASan

- `Allocation { addr, size, freed, freed_at }`
- `HeapTracking { allocations, freed, quarantine }`
  - `new()`, `track_alloc(addr,size)`, `track_free(addr) -> SanitizerResult`,
    `check_heap_access(addr,size) -> SanitizerResult` (covers overflow,
    underflow, UAF for interior bytes, double-free).
- `AddressSanitizer { heap }`
  - `new()`, `track_alloc`, `track_free`,
    `check(addr,size) -> Result<(), SanitizerReport>`.

### UBSan

- `UbSanitizer` (ZST).
  - `new() -> Self` (const)
  - `check_signed_overflow(a,b,op) -> bool` (const)
  - `check_null_deref(ptr) -> bool` (const)
  - `check_misaligned(addr, alignment) -> bool` (const; non-power-of-two
    alignment treated as always-aligned)
  - `check_division(divisor) -> bool` (const)
  - `checked_add(a,b) -> Result<i64, SanitizerReport>`
  - `checked_mul(a,b) -> Result<i64, SanitizerReport>`
  - `check_access(ptr, alignment) -> Result<(), SanitizerReport>`
    (null + misalignment).

### Log parser

- `SanitizerLogParser` (stateless).
  - `parse(text: &str) -> ParsedCrashReport` (first report; `Unknown` when none).
  - `parse_all(text: &str) -> Vec<ParsedCrashReport>` (splits on
    `==PID==ERROR:` headers; capped at `MAX_LINES = 1_000_000` to avoid DoS).
- `parse_hex_u64(s: &str) -> Option<u64>` (free fn; handles `0x` / `0X`).
- `classify_crash_severity(error_type: &str) -> CrashSeverity` (free fn):
  - `heap-buffer-overflow`, `global-buffer-overflow`, `stack-buffer-overflow`,
    `double-free`, `stack-overflow`, `bad-free`, `alloc-dealloc-mismatch` -> High
  - `use-after-free`, `heap-use-after-free` -> Critical
  - `integer-overflow`, `undefined-behavior`, `initialization-order-fiasco`,
    `odr-violation` -> Low
  - `memory-leak`, `leak` -> Info
  - default -> Medium

### Crash deduplication

- `CrashDeduplicator { stack_depth, ignore_addresses, ignore_offsets }`
  - `Default` / `new() -> Self` (defaults: `stack_depth=5`,
    `ignore_addresses=true`, `ignore_offsets=true`).
  - `dedup_key(&self, report) -> String` (key = error_type | access | top-N
    function names, optionally stripping `+0x...` offsets).
  - `are_duplicates(a,b) -> bool`
  - `deduplicate(Vec<ParsedCrashReport>) -> Vec<DeduplicatedCrash>` (preserves
    insertion order).
- `DeduplicatedCrash { representative, duplicate_count, all_addresses }`
  - `is_recurring(&self) -> bool` (count > 1).

### Coverage

- `CoverageMap { edges: HashMap<(u64,u64), u64>, blocks: HashMap<u64,u64> }`
  - `new()`, `record_edge(from,to)`, `record_block(pc)`, `merge(&other)`,
    `total_edges()`, `total_blocks()`, `new_edges_since(baseline) -> usize`,
    `coverage_ratio(total_known) -> f64` (clamped `[0,1]`).

## Submodules (highlights)

- `ubsan_report_parser`: `UbKind`, `SourceLocation`, `UbReport`, `RuntimeValue`,
  `UbsanReportParser`, `UbsanReportBatch`, `parse_ubsan_output(text) -> Vec<UbReport>`.
- `ubsan_checks`: `UbsanViolation`, `ArithOp`, `RecoveryMode`, `UbsanRuntime`,
  `UbsanSummary`, trait `UbsanCheck: Send + Sync`.
- `tsan_report_parser`: `AccessDirection`, `RaceLocation`, `DataRace`,
  `TsanStackFrame`, parsers for ThreadSanitizer text logs.
- `asan_report_parser`, `msan_report_parser`: per-tool dedicated parsers
  (complements `SanitizerLogParser` in `lib.rs`).
- `asan_analyzer`, `asan_runtime`, `msan_model`, `msan_tracker`, `tsan_model`,
  `shadow_memory`: model/runtime helpers backing the top-level types.
- `coverage_guided_fuzzer`, `crash_deduplicator`,
  `sanitizer_crash_deduplicator`, `sanitizer_runtime`, `sanitizer_dashboard`:
  higher-level fuzz loop, dedup engines and reporting dashboard.

## Behavior summary

- All "sanitizers" operate as pure-Rust logical models: ASan keeps a
  `HashMap`-based heap registry with a quarantine queue; MSan keeps per-page
  256-bit defined/undefined bitmaps; UBSan is a stateless collection of
  arithmetic/pointer predicates and `checked_*` helpers.
- The log parser is a forgiving text-based pipeline: it detects `==ERROR:` /
  Sanitizer headers, extracts tool, error-type, access (READ/WRITE + size +
  address), thread, and three stack-frame sections (crash, allocation,
  deallocation). It tolerates missing addresses, missing locations, and
  Windows drive letters (`C:\...`).
- Severity classification + dedup key generation are pure functions, suitable
  for embedding in reproducer pipelines.
- `serde::{Serialize, Deserialize}` is implemented on the report and coverage
  types so they can be persisted to JSON.

## I/O

- All entry points are in-memory: `&str` text in, structured types out. No file
  or process I/O at this crate level (no `std::fs`, no `Command`, no network).
- Heap/shadow trackers operate purely on `u64` addresses and `usize` lengths
  supplied by the caller; the crate never reads target-process memory itself.

## Testability

- Extensive in-file unit tests in `lib.rs` cover ShadowMemory, MemorySanitizer,
  HeapTracking/AddressSanitizer (overflow, UAF, double-free, underflow,
  realloc), and UbSanitizer (overflow, null, misaligned, div-by-zero,
  `checked_add`, `check_access`).
- Pure functions and small structs -> easy to property-test and fuzz.
- A `tests/` directory exists for integration tests.

testable: true
