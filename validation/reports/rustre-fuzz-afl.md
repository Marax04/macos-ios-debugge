# rustre-fuzz-afl

AFL++ style coverage-guided fuzzing backend for the RustRE fuzzing platform. Leaf crate that depends on `rustre-fuzz` (shared primitives: `Corpus`, `CoverageMap`, `FuzzInput`, `TargetExecutor`, fnv1a) and is re-exported by the `rustre-fuzz` hub via its optional `backends` feature.

## Cargo

- name: `rustre-fuzz-afl`
- edition/version/license: workspace inherited
- deps: `rustre-fuzz` (no default features), `anyhow`, `thiserror`, `serde`, `rayon`
- No `[lib]`/`[[bin]]` overrides; pure library crate.

## Module Map (src/)

| Module | Purpose |
|---|---|
| `lib.rs` | Root: `RngCore`/`XorShiftRng`/`SimpleRng`, `Mutator` trait + 10 concrete mutators, `AflError`, `AflShmCoverage`, `ForkServer`/`ForkServerState`, `CmplogMap`, `AflQueue`/`AflQueueEntry`, `AflStats`, `PersistentMode`, **`AflFuzzer`** (main entry), `ExtAflFuzzer`, deterministic stages (`stage_bit_flip_*`, `stage_arith_*`, `stage_interesting_*`, `stage_dictionary`, `stage_havoc`, `stage_splice`), `CovBitmap` + `cov_classify_count`, `AflMutEngine`, `BitmapQueue`/`BitmapFuzzer` pipeline. |
| `afl_bitmap.rs` | `AflBitmap` (64KiB), `VirginBits`, `BitmapStats`; free fns `has_new_coverage`, `hamming_distance`, `jaccard_similarity`. |
| `afl_coverage_map.rs` | `AflCoverageMap` (`AFL_MAP_SIZE = 65536`), `MapEntry`, `merge_maps`, `MapComparisonReport`, `CoverageMapDatabase`. |
| `afl_corpus_manager.rs` | `CorpusEntry`, `FavoriteEntry`, `CorpusTrimmer`, `CrashCorpus`/`CrashEntry`, `QueueEntry`, `SortCriterion`, `PathSorter`, `AflCorpusManager`. |
| `afl_queue.rs` | `AflQueue` with `QueueConfig`, `FavorAlgorithm`, `QueueEntry`, `QueueStats`, `QueueError`. |
| `afl_queue_reader.rs` | Parses on-disk AFL queue dirs: `AflQueueReader`, `QueueAnalyzer`, `QueueStats`, free fn `load_queue_dir`. |
| `afl_mutators.rs` | `INTERESTING_8/16/32`, `MutationContext`, `BitFlip1Iter`, `DeterministicMutations`, `HavocStrategy`, `HavocMutations`, `SpliceMutation`, `DictToken`, `DictionaryMutator`, `RadamsaMutator`, top-level `AflMutator`, `AflStage`. |
| `afl_fork_server.rs` | `ForkServerController` (Unix-style fork-server FSM), `ShmConfig`, `ChildExitStatus`, `ForkServerStats`, `PersistentModeConfig`, `InputChannel`, `InMemoryFuzzLoop`, `ForkServerError`. |
| `afl_trimmer.rs` | Input minimisation: `TrimOracle` trait, `TrimStrategy`, `TrimResult`, `TrimmerConfig`, `TrimmerStats`, `EffectivenessMap`, `AflTrimmer`, `ByteFrequencyProfile`, free fn `minimal_covering_set`. |
| `afl_crash_triager.rs` | `AflCrashTriager`, `TriagedCrash`, `MinimizeResult`, `TriageReport`, `CrashSignal`, free fn `triage_crash_dir`. |
| `afl_analysis.rs` | Post-run analytics: `CrashAnalyzer`, `HangAnalyzer`, `CoverageAnalyzer`, `QueueAnalyzer`, `StatisticsParser`, `AflReport`, `AflAnalysis`, related enums (`CrashSeverity`, `CrashKind`), error type `AnalysisError`. |
| `cmplog.rs` | RedQueen-style I2S: `CmpSize`, `CmplogEntry`, `CmplogMap`, `I2sTransformer`/`I2sResult`, `ColorizeMap`/`Colorizer`, `CmplogCollector`, `MultiByteI2s`. |
| `redqueen_engine.rs` | `RedqueenEngine` with `RedqueenConfig`, `MagicPattern`/`MagicDatabase`, `RedqueenMutation`, `NestedBranchSolver`, `ArithmeticSolver`, `PatternMatcher`. |
| `persistent_mode.rs` | Persistent-mode protocol: `PersistentConfig`, `PersistentLoop`, `IterationResult`, `ForkServerStatus`, `ForkServerProtocol`, `DeferredForkServer`. |
| `qemu_mode.rs` | Black-box binary fuzzing via QEMU: `TargetArch`, `QemuModeConfig`, `QemuCoverageMap`, `QemuForkServer`. |

## API Surface

Approx **434 `pub fn` items** across 15 modules, ~140 public types (structs/enums/traits/consts). Highlights below.

### Core entry types

- **`AflFuzzer`** (`lib.rs:1414`) — main user-facing fuzzer (mutation + coverage + queue + fork-server orchestrator). Largest impl (~1000 lines of methods).
- **`ExtAflFuzzer`** (`lib.rs:3159`) — extended variant with `ExtFuzzStats`, `IterResult`, `FuzzReport`.
- **`BitmapFuzzer`** (`lib.rs:4746`) — alternative pipeline driven by `BitmapQueue`/`BitmapForkServer`/`BitmapFuzzerConfig`/`BitmapFuzzerStats`/`BitmapExecStatus`.
- **`AflMutEngine`** (`lib.rs:4097`) — standalone mutation engine wired to AFL-style interesting tables (`AFL_INTERESTING_8/16/32`).

### `Mutator` trait + impls (`lib.rs`)

```rust
pub trait Mutator: Send + Sync {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore);
    fn name(&self) -> &'static str;
}
```

Implementations: `BitFlipMutator`, `ByteFlipMutator`, `ArithmeticMutator`, `InterestingValueMutator`, `DictionaryMutator`, `SpliceMutator`, `InsertMutator`, `DeleteMutator`, `XorBlockMutator`, `HavocMutator`. Dictionary loading via `Dictionary`.

### `RngCore` (`lib.rs:40`)

`XorShiftRng` (deterministic, seedable) and `SimpleRng` (`lib.rs:2436`) both implement it. RNGs are passed by `&mut dyn RngCore` to mutators and stages.

### Deterministic stages (free functions, `lib.rs:2727+`)

`stage_bit_flip_1/2/4`, `stage_byte_flip_1`, `stage_arith_8/16/32`, `stage_interesting_8/16/32`, `stage_dictionary`, `stage_havoc`, `stage_splice`. All take `&[u8]` → `Vec<Vec<u8>>` (corpus expansion) except `stage_splice` (`&[u8],&[u8]` → `Vec<u8>`). `STAGE_INPUT_MAX_BYTES = 4096`.

### Coverage

Two parallel implementations:

- `AflBitmap` (`afl_bitmap.rs`, `BITMAP_SIZE = 1<<16`) + `VirginBits` + similarity metrics.
- `AflCoverageMap` (`afl_coverage_map.rs`, `AFL_MAP_SIZE = 65536`) + `MapEntry`/`merge_maps`/`CoverageMapDatabase`.
- `CovBitmap(pub Box<[u8]>)` (`lib.rs:3914`) + `cov_classify_count(c: u8) -> u8` (AFL log2-style bucket classifier, `const fn`).
- `AflShmCoverage` (`lib.rs:708`) — shared-memory wrapper for the fork-server hand-off.

### Fork server / persistent / QEMU

- `ForkServer` + `ForkServerState` (`lib.rs`) — minimal model.
- `ForkServerController` (`afl_fork_server.rs:298`) — full FSM with `ShmConfig`, `ChildExitStatus`, `InputChannel`, `PersistentModeConfig`, `InMemoryFuzzLoop`. Errors via `ForkServerError`.
- `PersistentLoop` / `DeferredForkServer` / `ForkServerProtocol` (`persistent_mode.rs`) — implements the AFL persistent-mode handshake (`__AFL_LOOP`).
- `QemuForkServer` + `QemuModeConfig` + `QemuCoverageMap` (`qemu_mode.rs`) — black-box binary harness for `TargetArch::{X86_64, Aarch64, …}`.

### Queue management

- `AflQueue` (`lib.rs:1084`) — primary queue with favoring.
- `AflQueue` (`afl_queue.rs:172`) — alternate queue with `QueueConfig` / `FavorAlgorithm` / `QueueStats`.
- `BitmapQueue` / `BitmapQueueEntry` (`lib.rs:4500/4460`) — variant keyed on coverage hash.
- `AflQueueReader` (`afl_queue_reader.rs`) — read on-disk queues + analyser.

### Trimming / minimisation

`AflTrimmer` driven by `TrimOracle` (user-provided coverage callback) with selectable `TrimStrategy`, producing `TrimResult` + `TrimmerStats`. `minimal_covering_set(inputs, coverage_hashes)` is a free helper (greedy set-cover).

### Crash triage

`AflCrashTriager` consumes raw crash dirs, produces `TriagedCrash` (with `CrashSignal`), supports `MinimizeResult`, summarises into `TriageReport`. Convenience: `triage_crash_dir(...)`.

### Analytics

`AflAnalysis` aggregates `CrashAnalyzer` / `HangAnalyzer` / `CoverageAnalyzer` / `QueueAnalyzer` / `StatisticsParser` into an `AflReport`. Errors via `AnalysisError`. Crash classification: `CrashKind`, `CrashSeverity`.

### RedQueen / CmpLog

- `CmplogMap` + `CmplogEntry` + `CmplogCollector` (`cmplog.rs`) record observed compares; `I2sTransformer` solves Input-to-State substitutions; `Colorizer`/`ColorizeMap` perform input colourisation; `MultiByteI2s` for multi-byte magic values.
- `RedqueenEngine` (`redqueen_engine.rs`) — full RedQueen pipeline with `MagicDatabase`, `NestedBranchSolver`, `ArithmeticSolver`, `PatternMatcher`.

## I/O

Pure-Rust in-memory APIs throughout. Filesystem touch-points:

- `AflQueueReader` / `load_queue_dir` — read AFL queue directories.
- `AflCrashTriager` / `triage_crash_dir` — read crash dirs.
- `AflCorpusManager` / `CrashCorpus` — load and persist corpora.
- `QemuForkServer` — invokes external `qemu-afl-*` binary.
- `ForkServerController` — spawns a target process and communicates via FDs/shared memory (Unix model; on Windows the FSM exists but the exec primitives are stubbed/in-memory).

No network I/O. Serialization via `serde` (stats, configs, reports). Parallelism via `rayon` (corpus scoring, trimming, queue analysis).

## Behaviour

- Coverage model: AFL++ edge-bitmap (64 KiB) with log2 hit-count bucketing (`cov_classify_count`) and virgin-bits diff (`has_new_coverage`).
- Mutation pipeline mirrors AFL stages: deterministic (bit/byte flip, arith, interesting) → dictionary → havoc → splice, with optional RedQueen/CmpLog Input-to-State boosts.
- Queue favouring follows AFL's small-and-fast preference; alternate `FavorAlgorithm` variants are exposed via `QueueConfig`.
- Fork-server and persistent-mode protocols are modelled as state machines (`ForkServerState`, `ForkServerStatus`) so they can be unit-tested without a real child process.
- Crash de-duplication uses coverage signatures (stack-hash + bitmap hash) and minimises via `AflTrimmer` driven by a `TrimOracle`.
- The crate is `no_std`-friendly only at the type level — actual fork-server / fs paths require `std`.
- Determinism: all randomness routes through `RngCore`; seeding `XorShiftRng`/`SimpleRng` yields reproducible runs.

## Testability

Testable: **true**. The crate is library-only, all public types are constructible without external processes (fork-server/QEMU paths have in-memory loops and protocol state machines that can be exercised directly), and helpers like `stage_*`, `merge_maps`, `minimal_covering_set`, `hamming_distance`, `jaccard_similarity`, `cov_classify_count` are pure functions over byte slices. Deterministic RNGs make property tests straightforward.
