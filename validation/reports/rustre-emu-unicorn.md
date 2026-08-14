# rustre-emu-unicorn

## Overview
Pure-Rust wrapper modeling the Unicorn Engine CPU emulator API. Ships with no-op stubs by default; real libunicorn FFI is gated behind the `native` Cargo feature (currently the `unicorn-engine` dependency is commented out in Cargo.toml, so even `native` builds compile against the in-crate stubs/model).

## Cargo manifest
- **Package**: `rustre-emu-unicorn`
- **Dependencies**: `rustre-emu` (path), `thiserror`, `serde`, `serde_json`, `parking_lot`
- **Features**:
  - `default = []`
  - `native` — intended to enable real libunicorn FFI bindings (requires CMake + C toolchain). The `unicorn-engine = "2"` dep line is commented out, so today this feature flag is a no-op placeholder.

## Public modules (from `lib.rs`)
- `arch_backends` — per-architecture register tables + `UcArchBackend` trait
- `arch_register_maps` — register name/id maps for x86, ARM, ARM64, MIPS, etc.
- `coverage_hooks` — AFL bitmap, block/edge maps, drcov export
- `hook_manager` — typed hook dispatch with priority + reentrancy guard
- `instruction_trace` — per-instruction trace records
- `memory_model` — pure-Rust memory map / regions
- `os_hooks` — Linux & Windows syscall emulation
- `snapshot_manager` — snapshot lifecycle management
- `unicorn_arch_support` — arch capability queries
- `unicorn_bindings` — safe C API stubs (FFI under `native`)
- `unicorn_context_manager` — CPU-context save/restore
- `unicorn_coverage` — coverage bitmap integration
- `unicorn_filesystem_emu` — virtual filesystem for syscall emulation
- `unicorn_hooks` — code/block/mem/intr hook installation
- `unicorn_os_emulator` — high-level OS emulation driver
- `unicorn_os_hooks` — OS-level intercept registration
- `unicorn_snapshot` — register + memory snapshots
- `unicorn_syscall_linux` — Linux syscall dispatcher and trace

## Core types (lib.rs)
- `enum Arch { X86, Arm, Arm64, Mips, Sparc, RiscV, M68K, Ppc, S390X }`
- `enum Mode { X86_16, X86_32, X86_64, ArmMode, ThumbMode, Arm64Mode, Mips32LE/BE, Mips64LE/BE, Sparc32/64, RiscV32/64, M68K, Ppc32/64, S390X }`

## Public API surface
Approximately 641 `pub fn` declarations across 19 source files. Highlights:

### `unicorn_syscall_linux`
- `SyscallTable::new() -> Self`
- `register_handler(&mut self, handler: Box<dyn SyscallHandler>)`
- `syscall_dispatch(&mut self, emu: &mut dyn LinuxSyscallEmu, arch: Arch) -> i64`
- `trace(&self) -> &[SyscallTrace]`
- `clear_trace(&mut self)`
- `handled_syscalls(&self) -> Vec<u64>`
- `trace_summary(&self, last_n: usize) -> String`

### `unicorn_snapshot`
- `SnapshotLabel::new(label: impl Into<String>) -> Self`
- `SnapshotLabel::auto(counter: u64) -> Self`
- `RegisterSnapshot::new(arch: ArchTag) -> Self`
- `set(&mut self, name: impl Into<String>, value: u64)`
- `get(&self, name: &str) -> u64`
- `register_count(&self) -> usize`

### File-level public-function counts
| File | `pub fn` count |
| --- | --- |
| arch_backends.rs | 1 |
| arch_register_maps.rs | 48 |
| coverage_hooks.rs | 29 |
| hook_manager.rs | 19 |
| instruction_trace.rs | 23 |
| lib.rs | 93 |
| memory_model.rs | 45 |
| os_hooks.rs | 15 |
| snapshot_manager.rs | 30 |
| unicorn_arch_support.rs | 21 |
| unicorn_bindings.rs | 40 |
| unicorn_context_manager.rs | 26 |
| unicorn_coverage.rs | 48 |
| unicorn_filesystem_emu.rs | 24 |
| unicorn_hooks.rs | 28 |
| unicorn_os_emulator.rs | 12 |
| unicorn_os_hooks.rs | 38 |
| unicorn_snapshot.rs | 33 |
| unicorn_syscall_linux.rs | 8 |
| **Total** | **~641** |

## I/O behavior
- **Input**: caller-supplied bytecode/memory regions via `memory_model`, register writes via snapshot/context managers, hook callbacks via `hook_manager`/`unicorn_hooks`, syscall numbers + register state via `unicorn_syscall_linux`.
- **Output**: emulation state changes (registers, memory), instruction/syscall traces (`SyscallTrace`, instruction_trace records), coverage bitmaps (AFL-compatible) and drcov files via `coverage_hooks` / `unicorn_coverage`, snapshots serializable through `serde`/`serde_json`.
- **Side effects**: none external by default (pure-Rust model). With a real libunicorn build (currently disabled) it would issue FFI calls into the native engine.

## Behavior notes
- Without the `native` feature the crate is a self-contained software model: all `unicorn_bindings` entry points are stubs, suitable for unit-testing higher-level orchestration without a C toolchain.
- Thread-safety provided via `parking_lot` mutexes and `Arc<Mutex<...>>` in lib.rs.
- Syscall dispatcher returns an `i64` result and records each call into a ring trace buffer (`trace`, `trace_summary`, `clear_trace`).
- Coverage module exposes AFL bitmap + drcov export, intended for fuzzing harness integration.
- Testable: yes — the crate builds with `default` features (no native deps) and exposes deterministic pure-Rust APIs (snapshots, coverage, syscall trace) that can be exercised in unit tests without libunicorn.

## Files
- `C:\Users\Fra\Desktop\RustRE\crates\rustre-emu-unicorn\Cargo.toml`
- `C:\Users\Fra\Desktop\RustRE\crates\rustre-emu-unicorn\src\lib.rs`
