# rustre-fuzz-libfuzzer

## Overview

In-process libFuzzer-style fuzzer built on top of the `rustre-fuzz` base framework.
Provides coverage-guided greybox fuzzing, structured mutation, corpus management,
crash deduplication/triage, persistent-mode harness scaffolding, and signal handling.

- **Edition / version**: inherited from workspace
- **Path**: `crates/rustre-fuzz-libfuzzer`

## Cargo.toml

### Dependencies
- `rustre-fuzz` (path) — base fuzz framework
- `rustre-fuzz-afl` (path) — AFL backend integration
- `thiserror`, `serde`, `serde_json`, `parking_lot`, `rayon`, `bitflags` (workspace)

### Dev-dependencies
- `tempfile`

### Lints
- Workspace lints inherited.

Note: per the Cargo.toml comment, `rustre-fuzz` is an umbrella crate that depends
*on* this crate (not the other way), preventing a dependency cycle.

## Module map (`lib.rs`)

| Module | Purpose |
|---|---|
| `corpus_manager` | `CorpusEntry`, `CorpusManager`, coverage-guided seed selection, corpus shrinking |
| `coverage_feedback` | Coverage feedback & edge tracking |
| `crash_deduplicator` | Crash hashing / dedup |
| `crash_triage` | Crash classification & severity |
| `custom_mutator` | User-pluggable mutator FFI/trait surface |
| `harness_generator` | Boilerplate harness generation |
| `in_process` | `LibFuzzerHarnessExt`, `HarnessRunner`, `SanitizerCoverage`, `SignalHandler`, `TimeoutHandler` |
| `libfuzzer_corpus` | libFuzzer-format corpus I/O |
| `libfuzzer_corpus_minimizer` | Corpus minimization (`-merge` style) |
| `libfuzzer_crash_reproducer` | Reproduce a crash from input file |
| `libfuzzer_harness` | High-level harness wrapper |
| `mutation_engine` | Orchestrates mutation rounds |
| `mutation_strategies` | `MutationStrategy` enum, dictionary entries, RNG |
| `mutator` | `MutatorPlugin` trait + standard plugins (ByteFlip, BitFlip, Insert, Delete, Splice, DictEntry, Arithmetic, InterestingValue, ChunkCopy, MutatorChain) |
| `cast` | Internal const numeric-cast helpers (`u64_to_f64`, `usize_to_u32`, etc.) |

## Public API surface

`pub fn` count across `src/*.rs` (associated + free): **~434**
Top contributors:
- `lib.rs` — 85 (mostly `cast::*` numeric helpers)
- `coverage_feedback.rs` — 36
- `libfuzzer_corpus.rs` — 34
- `corpus_manager.rs` — 34
- `crash_deduplicator.rs` — 30
- `in_process.rs` — 25
- `libfuzzer_harness.rs` — 25
- `custom_mutator.rs` — 22
- `crash_triage.rs` — 18
- `harness_generator.rs` — 18
- `libfuzzer_crash_reproducer.rs` — 19
- `mutation_engine.rs` — 17
- `libfuzzer_corpus_minimizer.rs` — 15

### Key types (from `mutator.rs`)
- `MutatorError` (enum, `#[derive(thiserror::Error)]`)
- `MutatorPlugin: Send + Sync + Debug` — pluggable mutator trait
- `MutationStrategy` (enum) — strategy selector
- `DictionaryEntry` — token/keyword dictionary record
- `Rng` — deterministic RNG state
- Built-in plugins: `ByteFlipMutator`, `BitFlipMutator`, `InsertMutator`,
  `DeleteMutator`, `SpliceMutator`, `DictEntryMutator`, `ArithmeticMutator`,
  `InterestingValueMutator`, `ChunkCopyMutator`
- `MutatorChain` — sequential composition of plugins

### Key types (from `in_process.rs`)
- `LibFuzzerHarnessExt` trait
- `HarnessRunner`
- `SanitizerCoverage`
- `SignalHandler`, `TimeoutHandler`

### Key types (from `corpus_manager.rs`)
- `CorpusEntry`, `CorpusManager` (coverage-guided selection, shrinking)

### `cast` helpers
Lossless / saturating numeric conversions isolated in one module so cast sites
remain explicit: `u64_to_f64`, `usize_to_f64`, `i64_to_f64`, `u32_to_f64`,
`u64_to_usize`, `u64_to_u32`, `u64_to_u16`, `u64_to_u8`, `u128_to_u64`,
`usize_to_u32`, `usize_to_u16`, `usize_to_u8`, `usize_to_i32`, …

## I/O behavior

- **Inputs**: byte buffers `&[u8]` fed to harness targets; corpus files on disk
  (libFuzzer format), optional dictionaries (`DictionaryEntry`).
- **Outputs**: crash artifacts (deduplicated, triaged), minimized corpora,
  coverage feedback (edge maps), serialized reports via `serde`/`serde_json`.
- **Concurrency**: `parking_lot` mutexes; `rayon` for parallel corpus
  operations; mutator plugins are `Send + Sync`.
- **Failure mode**: `MutatorError` via `thiserror`; signal/timeout handling via
  `in_process::{SignalHandler, TimeoutHandler}`.

## Behavior notes

- In-process fuzzing: target function called in the fuzzer's own process,
  libFuzzer style — fastest iteration rate but a crash kills the process unless
  caught by `SignalHandler`.
- Coverage-guided: `coverage_feedback` tracks edge hits, `CorpusManager`
  promotes inputs that hit new edges.
- Structured mutation: `MutatorChain` composes plugins; `MutationStrategy`
  selects per-iteration tactics; dictionaries inject domain tokens.
- Persistent-mode and harness-generator modules scaffold long-running fuzz
  campaigns and emit per-target driver code.
- AFL interop: pulls `rustre-fuzz-afl` to share corpus/seed formats.

## Testability

- `dev-dependencies` include `tempfile`, indicating I/O-touching tests.
- All major modules expose constructors and pure methods (mutators, RNG,
  dictionary, cast helpers) that are unit-testable without external processes.
- Signal/timeout/sanitizer paths are platform-sensitive but the data layer
  (corpus, dedup, triage) is testable in isolation.

**Verdict: testable.**
