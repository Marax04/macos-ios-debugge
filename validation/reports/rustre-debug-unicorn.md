# rustre-debug-unicorn

## Purpose
Pure-Rust simulation of the Unicorn CPU emulator API (no FFI/C library) used as an emulation-based debugger backend for the RustRE Suite. Implements the `rustre-debug::Debugger` trait, providing memory mapping, hook installation, register state, breakpoints, snapshots, code coverage, call tracing and OS/API hook emulation across multiple architectures.

## Cargo
- name: `rustre-debug-unicorn` v0.1.0, edition 2024
- deps: `rustre-debug`, `rustre-core`, `anyhow`, `thiserror`, `tokio`, `async-trait`, `parking_lot`, `serde`, `bitflags`
- dev-deps: `serde_json`, `tokio` (macros, rt-multi-thread)

## Modules (pub mod)
- `emulation_session` — session state container
- `hook_manager` — generic hook registry
- `memory_map_builder` — fluent builder for memory layout
- `os_emu_hooks` — emulated OS-level syscalls/interrupts
- `unicorn_engine_wrapper` — low-level engine abstraction
- `unicorn_extended` — extended emulator features
- `unicorn_hooks` — hook dispatch/registration
- `unicorn_memory_map` — region map types
- `unicorn_snapshot` — save/restore emulator state
- `unicorn_api_hooks` — `ApiHookLibrary`, `MockLibcHooks` (malloc/free/strlen/memcpy/printf/…), `MockKernel32Hooks` (VirtualAlloc/LoadLibrary/GetProcAddress/…), `HookStats`
- `unicorn_debugger` — higher-level debugger facade
- `unicorn_breakpoint_manager` — breakpoint store
- `unicorn_call_tracer` — function-call tracing
- `unicorn_memory_inspector` — read/diff helpers
- `unicorn_register_inspector` — register diff/print
- `unicorn_code_coverage` — coverage collector

## Top-level API (`lib.rs`)

### Errors
- `UnicornDbgError`: `EmulationError(String)`, `InvalidArch(String)`, `MemMapError(String)`, `HookError(String)`, `Debug(#[from] DebugError)`.

### Types
- `UnicornArch` enum: X86_64, X86_32, Arm, Arm64, Mips, Mips64, Riscv32, Riscv64 (impl Display).
- `MemRegion { addr, size, perms }` with `readable()`, `writable()`, `executable()` (perms bit0=R, bit1=W, bit2=X).
- `HookType`: Code, MemRead, MemWrite, MemInvalid, Interrupt.
- `HookRecord { hook_id, hook_type, address, size }`.

### `UnicornDebugger` (v1)
Constructors / config:
- `new(arch: UnicornArch) -> Self`, `Default = X86_64`.
- `arch() -> UnicornArch`.
- `set_max_steps(n: u64)`; `step_count() -> u64`.
- `debug_session() -> &DebugSession`.

Memory / hooks:
- `map_memory(addr, size, perms) -> Result<(), UnicornDbgError>` — rejects zero size, sizes > 256 TiB, and overlapping regions (uses saturating arithmetic).
- `write_memory_direct(addr, &[u8]) -> Result<(), UnicornDbgError>` — bypasses permission checks; errors if address not mapped or write would cross page end.
- `add_hook(HookType, addr) -> u64` — returns monotonically increasing id starting at 1.
- `mem_regions() -> &[MemRegion]`, `installed_hooks() -> &[HookRecord]`.

Emulation:
- `emulate(begin, until, steps) -> Result<u64, UnicornDbgError>` — requires attached, requires `begin != until`. Advances PC by per-arch stride (1 for x86, 4 otherwise), stops at `until`, after `steps`, or at `max_steps`. Returns final PC. Updates arch-specific PC register (rip/eip/pc).

### `Debugger` trait impl (async)
- `name() -> "unicorn"`; `supported_architectures()` returns the 8 arch strings.
- `launch(_) -> Err(Unsupported)` — Unicorn emulates images; use `attach`.
- `attach(pid)` sets pid + `running=true`; errors if already running.
- `detach()`, `kill()` clear session; `detach` errors if not attached.
- `is_attached()`, `target_pid()`.
- `continue_execution()` returns a `SingleStep` event at current PC (no actual run).
- `single_step(tid)` / `step_over` / `step_out` all advance PC by stride and return event.
- `pause()` no-op when attached.
- `threads() -> [ThreadId(1)]`, `current_thread() -> ThreadId(1)`.
- `get_registers/set_registers/get_register/set_register` — RwLock-backed map with arch-specific defaults (e.g. x86_64 rip=0x401000, rsp=0x7fff_ffff_f000).
- `read_memory/write_memory` — page-walk lookup; write errors on unmapped addr to keep `memory`/`mem_regions` in sync; read clamps length to page end.
- `memory_maps()` — exposes mapped regions as `MemoryMap` with name `uc_<addr>`.
- Breakpoints: `set_breakpoint`, `remove_breakpoint`, `enable_breakpoint`, `disable_breakpoint`, `breakpoints()` — stored in `DebugSession`; duplicate set errors.
- `modules() -> session.modules()`.
- `backtrace(_)` returns single synthetic frame from current PC/SP.

### Module `v2` (spec-compliant API)
- `UnicornError`: MemNotMapped(u64), RegNotFound(String), EmulationFailed(String), HookError(String).
- `UnicornArch`: X86, X86_64, Arm, Arm64, Mips, Sparc; `pointer_size()` (4 or 8).
- `UnicornMode`: Mode16/32/64, Thumb, LittleEndian, BigEndian.
- `UnicornConfig { arch, mode, stack_size, timeout_ms }` with presets `x86_64()`, `arm64()`, `arm_thumb()`.
- `HookType`: Code, MemRead, MemWrite, Block, Interrupt, Invalid.
- `EmulatorHook { id, hook_type, address, size, callback_desc }`.
- `EmulationResult { instructions, mem_reads, mem_writes, exit_addr, error }` + `success()`.
- `UnicornDebugger { config, memory, registers, hooks, next_hook_id }` (all pub fields):
  - `new(UnicornConfig)`, `map_memory(base, Vec<u8>)`, `set_reg/get_reg`, `read_memory(addr, size) -> Option<Vec<u8>>`, `add_hook(HookType, desc) -> u32`, `emulate(start, end) -> EmulationResult` (stride 1 for x86, 4 otherwise; capped at 10_000 insn; `start==end` returns error result), `hook_count()`.

## Submodule API summary (counts of pub items)
- `unicorn_debugger`: 102 — higher-level orchestration facade.
- `unicorn_hooks`: 75 — hook registration + dispatch helpers.
- `unicorn_extended`: 76 — extra emulator capabilities.
- `unicorn_engine_wrapper`: 73 — engine abstraction layer.
- `os_emu_hooks`: 60 — emulated OS syscall/IRQ handlers.
- `unicorn_memory_map`: 54 — region/permission model.
- `hook_manager`: 45 — generic hook registry.
- `emulation_session`: 43 — session lifecycle/state.
- `unicorn_snapshot`: 38 — save/restore emulator state.
- `unicorn_memory_inspector`: 36 — memory diff/print helpers.
- `unicorn_code_coverage`: 36 — coverage tracking.
- `unicorn_call_tracer`: 33 — call/return tracing.
- `unicorn_breakpoint_manager`: 32 — breakpoint store.
- `unicorn_register_inspector`: 30 — register diff/print.
- `unicorn_api_hooks`: 25 — `ApiHookLibrary`, `HookedApi`, `MockLibcHooks`, `MockKernel32Hooks`, `HookStats`.
- `memory_map_builder`: 23 — fluent layout builder.

## Expected behaviour
- Pure simulation: instruction execution is modeled as PC advancement by an arch-stride; no real CPU semantics. Memory and registers are honest stores.
- All state mutations are interior-mutable (`AtomicBool` + `parking_lot::RwLock`) so the async `Debugger` trait works through `&self`.
- Memory invariants: `memory` map keyed by region base and `mem_regions` are kept in sync; write_memory rejects unmapped addrs.
- Suitable for harness/tests: attach → map_memory → write_memory_direct (code) → set registers/breakpoints → emulate/single_step → inspect.

## Testability
- Built-in `#[cfg(test)]` suite covers construction, arch display, attach/detach/kill/launch, memory map (overlap/zero-size), direct write, emulate stop conditions, hook id uniqueness, register get/set, single_step stride per-arch, breakpoint set/remove/duplicate, backtrace, MemRegion perms, HookType/HookRecord display, Debug format, and full v2 sub-API.
- Async tests via `tokio::test`; sync code paths via `#[test]`.
- No external services or FFI required — fully self-contained, deterministic.

**testable: true**
