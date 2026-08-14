# rustre-ttd-recorder

Full TTD (Time-Travel Debugging) trace recording API: configures, starts, pauses, stops and validates recordings, with authenticated trace encryption.

## Cargo.toml

- **package**: `rustre-ttd-recorder` v0.1.0, edition 2024
- **workspace inherits**: license, description, repository, readme, keywords, categories, authors, lints
- **dependencies**:
  - workspace crates: `rustre-core`, `rustre-ttd`, `rustre-trace`
  - errors: `anyhow`, `thiserror`
  - serialization: `serde`, `serde_json`, `bincode`
  - async/concurrency: `tokio`, `async-trait`, `parking_lot`
  - storage: `rusqlite`
  - crypto: `chacha20poly1305` (authenticated AEAD)
- **target linux**: `nix` (ptrace, signal, process, user, event), `libc`

## Module layout (`src/lib.rs`)

Public submodules: `emulator_recorder`, `etw_recorder`, `etw_trace_session`, `kernel_trace_hooks`, `recorder_engine`, `recording_policy`, `recording_session_manager`, `snapshot_manager`, `thread_context_recorder`, `trace_writer`, `ttd_index_builder`, `ttd_ring_buffer`.

## Top-level public API (`lib.rs`)

### Errors
- `enum TtdRecordError`: `NotAvailable`, `ProcessNotFound`, `InsufficientPrivileges`, `OutputPathError(String)`, `CompressionError(String)`, `RecordingFailed(String)`, `Io(std::io::Error)`. Implements `From<CoreError>` mapping permission/IO into appropriate variants.
- `enum RecorderError` (legacy): `AlreadyRecording`, `NotRecording`, `SpawnError`, `TraceWriteError`, `Io`, `InvalidConfig`, `Serde`.

### Position / status types
- `struct TtdPosition { major, minor }` with `new`, `start`, `is_before`, `earliest`, `to_trace_position`, `Display`.
- `enum CompressionLevel`: `None | Fast | Default | Best` (`Display`).
- `enum TtdTarget`: `ProcessId(u32) | ProcessName(String) | Executable { path, args } | Spawn { cmd }` (`Display`).
- `enum RecordingStatus`: `Initializing | Injecting | Recording | Paused | Stopping | Stopped | Error(String)` (`Display`).

### Config & filters
- `struct TtdRecordConfig { target_process, output_dir, max_recording_size_mb, compression, encrypt, ring_buffer_mb, timeout_secs, follow_children, record_heap, full_heap }`
  - `fn for_pid(pid, output_dir) -> Self`
  - `fn validate(&self) -> Result<(), String>`
- `struct TtdRecordFilter { include_modules, exclude_modules, include_threads, exclude_threads, record_only_from_address, stop_at_address }`
  - `fn pass_all()`, `fn thread_allowed(tid)`, `fn module_allowed(name)`, `fn compile() -> CompiledTtdFilter`
- `struct CompiledTtdFilter` (HashSet-backed O(1) filter)
  - `fn thread_allowed`, `fn module_allowed`; `From<&TtdRecordFilter>`

### Metrics, checkpoints, result
- `struct RecordingMetrics { events_recorded, file_size_bytes, compressed_size_bytes, elapsed_secs, instructions_recorded, memory_events, thread_count }` with `fn summary()`.
- `struct TtdCheckpoint { name, position, timestamp }` with `fn new`.
- `struct TtdRecordResult { output_file, metrics, checkpoints, warnings }` with `fn is_clean()`.

### Recording session
- `struct TtdRecordSession`
  - `fn new(config) -> Self`
  - `fn start(&mut self) -> Result<(), TtdRecordError>`
  - `fn pause(&self) -> Result<(), TtdRecordError>` (atomic CAS on status)
  - `fn resume(&self) -> Result<(), TtdRecordError>`
  - `fn stop(&mut self) -> Result<TtdRecordResult, TtdRecordError>` (idempotent)
  - `fn status() -> RecordingStatus`
  - `fn metrics() -> RecordingMetrics`
  - `fn add_checkpoint(name) -> Result<TtdCheckpoint, _>` (single-lock counter)
  - `fn wait_for_completion(&mut self) -> Result<TtdRecordResult, _>`
  - `fn trace() -> Arc<TtdTrace>`

### Recorder front-ends
- `struct TtdLaunchRecorder { config }` — launch executable from first instruction. `fn new(exe_path, output_dir)`, `fn with_args(args)`, `fn record() -> Result<TtdRecordSession, _>`.
- `struct TtdAttachRecorder { pid, output_dir }` — attach to running PID. `fn new`, `fn record()`.
- `struct TtdKernelRecorder { driver_name, output_dir }` — simulation stub (`#[doc(hidden)]`); only accepts `"test"`. `fn new`, `fn record()`.

### Authenticated encryption
- `struct TtdRecordEncryptor` — ChaCha20-Poly1305 AEAD with 32-byte key, 8-byte random salt, 32-bit atomic counter (96-bit nonce = salt ‖ counter). Key zeroed on drop via `compiler_fence` + `black_box`.
  - `fn new(key: Vec<u8>) -> Result<Self, _>` (validates 32-byte key)
  - `fn encrypt(data) -> Result<Vec<u8>, _>` (output: `nonce ‖ ciphertext ‖ tag`)
  - `fn decrypt(data) -> Result<Vec<u8>, _>` (verifies tag)
  - `fn is_valid_key() -> bool`

### Validation
- `struct ValidationResult { is_valid, version, position_range, warnings }` with `fn is_perfect()`.
- `struct TtdTraceValidation` (static): `fn validate(path)`, `fn is_valid_extension(path)`.

### Legacy / generic recorder
- `struct RecorderConfig { output_path, max_events, record_memory, record_threads, pid_filter }` (`Default`).
- `struct RecordingSession { config, pid, event_count, start_time }` with `fn new`.
- `#[async_trait] trait Recorder`: `start`, `stop`, `attach`.
- `struct InProcessRecorder` implementing `Recorder` with synthetic trace generation.
- `struct TraceSerializer`: `fn serialize(&TtdTrace) -> Result<Vec<u8>, _>`, `fn deserialize(&[u8]) -> Result<Arc<TtdTrace>, _>` (JSON via serde).

### Stats & utilities
- `struct ModuleStats { name, event_count, loaded_at_start }`.
- `struct RecordingStats { total_events, events_per_thread, module_stats, duration_secs }` with `fn from_trace`, `fn hottest_thread`.
- `struct RingBufferRecorder { capacity, events }` — bounded VecDeque. `fn new`, `fn push`, `fn snapshot`, `fn len`, `fn is_empty`, `fn clear`.
- `struct RecordingSchedule { start_address, stop_address, start_position, stop_position, max_duration }` with `fn record_all`, `fn for_duration`, `fn should_stop`.
- `struct TraceFileInfo { path, size_bytes, ... }` (further fields below line 1570).

## Testability

The crate exposes deterministic, synchronous APIs (config validation, position arithmetic, filter compilation, ring buffer, schedule decisions, encryption roundtrip, JSON ser/de, status transitions) plus a synthetic in-memory recording path. All can be exercised without real TTD infrastructure. The `tests/` directory exists.
