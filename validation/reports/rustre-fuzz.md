# rustre-fuzz

Core fuzzing framework crate providing shared primitives consumed by `rustre-fuzz-afl`, `rustre-fuzz-libfuzzer`, `rustre-fuzz-net`, `rustre-fuzz-cov`, `rustre-fuzz-sanitizers`.

## Cargo.toml

- **Package**: `rustre-fuzz`, workspace-inherited version/edition/license.
- **Dependencies**: `thiserror`, `serde`, `serde_json`, `parking_lot`.
- **Optional backend deps** (gated by `backends` feature):
  - `rustre-fuzz-cov` (path)
  - `rustre-fuzz-sanitizers` (path)
- **Features**:
  - `default = []`
  - `backends = ["dep:rustre-fuzz-cov", "dep:rustre-fuzz-sanitizers"]`
- **Explicit non-deps** (to avoid cargo dep cycles): `rustre-fuzz-afl`, `rustre-fuzz-libfuzzer`, `rustre-fuzz-net` — they depend on this crate; downstream binaries pull them directly.

## Modules

`registry`, `campaign`, `crash_dedup`, `fuzz_orchestrator`, `mutation_scheduler`, `structured_fuzzer`, `smart_seed_scheduler`, `coverage_guided_fuzzer`, `grammar_fuzzer`, `mutation_engine`, `corpus_manager`, `crash_analyzer`, `fuzzer_coordinator`, `seed_minimizer`.

Function count: ~584 `pub fn` declarations across 15 source files (lib.rs alone: 117).

## Public API (lib.rs)

### Error

```rust
pub enum FuzzError {
    ExecutionError(String),
    CoverageError(String),
    InputError(String),
    Timeout,
    CorpusError(String),
    MinimizationError(String),
}
```

### FuzzInput — genealogy-tracked fuzzing input

Fields: `data: Vec<u8>`, `id: u64`, `parent: Option<u64>`, `generation: u32`, `origin: Option<String>`.

- `new(id, data)`, `new_with_origin(id, data, origin)`
- `derive(&self, id, data) -> Self`, `derive_with_origin(...)`
- `data_hash() -> u64` (FNV-1a), `len()`, `is_empty()`

### Hash

- `pub fn fnv1a(data: &[u8]) -> u64` — FNV-1a 64-bit.

### Results / Status

```rust
pub enum FuzzResult { Interesting(Vec<u8>), Crash{input,signal,address}, Timeout, Normal }
pub enum ExecutionStatus { Normal, Crash{signal,fault_addr}, Timeout, Hang }
pub struct ExecutionResult { status, coverage_hash, execution_time, new_coverage_bits }
```

Helpers: `is_crash`, `is_interesting`, `is_normal`, `is_hang`, `ExecutionResult::normal(dur)`, `::crash(sig, addr, dur)`.

### TargetExecutor trait

```rust
pub trait TargetExecutor: Send {
    fn execute(&mut self, input: &[u8]) -> Result<ExecutionResult, FuzzError>;
}
```

### CoverageMap — AFL-style bitmap

- `new(size)`, `update(&[u8]) -> u32` (returns newly-set bits), `merge(&Self) -> u32`
- `total_bits_set`, `bits_set_since_last_reset` (alias `cumulative_bits_set`), `hash`, `reset`
- `is_empty`, `hot_edges`, `edge_hit_count(usize)`, `active_edges() -> Vec<(usize, u8)>`

### InputQueue

- `new`, `next_id`, `add(input, is_interesting)`, `remove(id)`
- `select() -> &FuzzInput` — round-robin over-sampling favored (every 3rd call); panics if empty.
- `select_cursor()`, `is_empty`, `len`, `favored_count`, `clear`

### FuzzerStats (alias `FuzzStats`)

`executions`, `crashes`, `hangs`, `unique_crashes`, `last_crash_time`, `start_time`, `start_instant` (monotonic, `#[serde(skip)]`), `corpus_size`, `interesting_inputs`, `max_input_len`, `total_bytes_generated`.

API: `new`, `execs_per_sec`, `elapsed_secs`, `crash_rate`, `record_execution(input_len)`.

### CorpusMeta / CorpusEntry / Corpus

- `CorpusMeta::new(hash, coverage_bits, execution_time)`, `record_selection`
- `Corpus::new`, `add_input(input, meta) -> bool` (true = novel), `add_crash(...)`, `len`, `is_empty`, `unique_coverage_hashes`, `get_entry(id)`, `prune(min_coverage_bits) -> usize`, `sorted_by_coverage() -> Vec<&FuzzInput>`

Behavior: deduplicates by coverage hash; `prune` always retains parentless (root) inputs.

### CrashRecord / CrashDeduplicator

- `CrashRecord::new(id, input, signal, fault_addr, coverage_hash)`, `set_stack_hash(&[u64])`, `increment`, `dedup_key()` (stack_hash else coverage_hash)
- `CrashDeduplicator::new`, `submit(input, signal, fault_addr, cov_hash) -> bool`, `unique_count`, `iter`, `all_crashes`, `most_common`, `clear`

### MutationStrategy enum

13 variants: BitFlip, ByteFlip, Arithmetic, InterestingValue, Dictionary, Splice, Havoc, Insert, Delete, Shuffle, Repeat, XorBlock, Reverse.
API: `name()`, `all()`, `Display`.

### Dictionary

- `new`, `named(name)`, `add(Vec<u8>)`, `add_str(&str)`, `len`, `is_empty`, `get_wrapping(idx)`
- `load_from_text(text) -> Result<usize, FuzzError>` — supports `# comments`, bare tokens, `"quoted"`, hex `x"de ad be ef"`.

### FuzzRng — xorshift64

- `new(seed)` (0 maps to `0xdeadbeefcafebabe`), `next_u64`, `next_usize(n)`, `next_u8`, `one_in(n)`

### MutationEngine

Public fields: `dictionary`, `max_size` (default 1 MiB), `min_size` (default 1), `total_mutations`. Private RNG and per-strategy hit counters.

- `new()`, `with_seed(u64)`
- `mutate(&[u8], MutationStrategy) -> Vec<u8>` — dispatches to internal strategy impls.
- `splice_two(a, b) -> Vec<u8>`
- `record_hit(strategy)`, `best_strategy() -> Option<MutationStrategy>`

Internal strategy fns enforce `max_size`/`min_size` and handle empty inputs gracefully (return clone).

## I/O Behavior

- **No file I/O** in public lib.rs surface (other than `Dictionary::load_from_text` which takes an in-memory `&str`).
- All inputs/outputs are `Vec<u8>` and `&[u8]`.
- Serde-serializable types: `FuzzInput`, `FuzzerStats`, `CorpusMeta`, `CrashRecord`, `MutationStrategy`.
- `TargetExecutor` is the integration seam — backends provide their own implementations.

## Behavior Notes

- Coverage merging uses AFL-style novel-bit detection; per-edge hit counts saturate at 255.
- `InputQueue::select` and `select_cursor` panic on empty queue (documented).
- `FuzzerStats::execs_per_sec` uses monotonic `Instant` (immune to wall-clock skew).
- `Corpus::prune` is conservative: never removes root (parentless) seeds.
- `CrashDeduplicator::submit` returns false (and increments) on duplicate dedup keys.
- `FuzzRng` is deterministic; seed 0 is remapped.

## Testability

The crate is testable in isolation:
- Pure-Rust primitives with no system dependencies.
- `tests/` directory present.
- `TargetExecutor` trait can be mock-implemented.
- All mutation/coverage/corpus primitives are deterministic given a fixed `FuzzRng` seed.
