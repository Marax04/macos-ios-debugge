# rustre-debug-windbg

## Package
- name: `rustre-debug-windbg`
- version: 0.1.0
- edition: 2024
- description: WinDbg / DbgEng integration for the RustRE Suite. Provides a simulated WinDbg session modeling the DbgEng API surface (breakpoints, modules, threads, registers, extension commands) and a full implementation of the `rustre_debug::Debugger` trait. No real Windows APIs invoked; state is simulated in Rust (windows-sys is declared as a target-specific dep but the library logic is simulation-based).

## Dependencies
- internal: `rustre-debug`, `rustre-core`
- external: `thiserror`, `tokio`, `async-trait`, `parking_lot`, `serde`, `serde_json`, `bitflags`, `byteorder`
- windows-only: `windows-sys 0.59` (Diagnostics_Debug, Threading, Foundation, Memory, Kernel)

## Modules (16)
- `crash_dump_analyzer`, `minidump`, `kdump_analyzer` — dump file inspection
- `windbg_command_parser`, `windbg_commands`, `windbg_command_runner` — command lexing/dispatch
- `windbg_extensions`, `windbg_extension_api`, `winext_api` — extension/EXT API simulation
- `windbg_script_runner`, `windbg_scripting` — script execution
- `windbg_kd_protocol` — kernel-debug protocol model
- `windbg_stack_walker`, `windbg_heap_analyzer` — stack/heap inspection helpers
- `v2` (inline) — spec-compliant simplified API: `WinDbgClient` trait + `MockWinDbgClient`

## Public API surface
- pub fn / async fn count: ~420 across 16 files (lib.rs alone: 45)
- Top-level public types in `lib.rs`:
  - `WinDbgError` (thiserror enum: DbgEngError, NotInitialized, CommandError, SymbolError, Debug)
  - `ExecutionStatus` enum (Break, Go, StepOver, StepInto, StepBranch, Reverse, NoDebuggee) — mirrors `DEBUG_STATUS_*`
  - `DbgModule { name, base, size, timestamp, checksum, path }`
  - `WinDbgThread { thread_id, system_id, teb_addr, start_addr, state }`
  - `ExtensionResult { command, output, success }`
  - `DbgEngStatus` enum (numeric, mirrors DEBUG_STATUS_*)
  - `WinDbgSession` — main type, implements `Debugger`

### `WinDbgSession` inherent methods
- `new() -> Self` / `default()` — seeded with 5 default modules (ntdll, kernel32, kernelbase, user32, combase), 4 default threads, simulated MZ page at 0x7fff_d000_0000
- `status() -> ExecutionStatus`
- `modules() -> &[DbgModule]` / `threads() -> &[WinDbgThread]`
- `execute_command(&mut self, cmd: &str) -> Result<ExtensionResult, WinDbgError>` — supports k/kb/kp, r, u, db, lm/.modules, ~, !peb, !teb, bp, bl, bc, q/.detach; unknown command yields CommandError
- `command_history() -> Vec<String>`
- `set_symbol_path(&mut self, &str) -> Result<(), WinDbgError>` / `symbol_path() -> Option<String>`
- `debug_session() -> &DebugSession`

### `Debugger` trait impl (async, from `rustre-debug`)
- lifecycle: `launch(opts) -> ProcessId` (fixed PID 0x1000), `attach(pid)`, `detach`, `kill`, `is_attached`, `target_pid`
- metadata: `name()` -> `"windbg"`, `supported_architectures()` -> [x86_64, x86, arm64]
- execution: `continue_execution`, `single_step` (rip += 1), `step_over`, `step_out`, `pause`
- threads: `threads()`, `current_thread()`
- registers: `get_registers`, `set_registers`, `get_register`, `set_register` (HashMap-backed, x64 regs preseeded)
- memory: `read_memory(addr, size)` (page lookup, errors on unmapped/short), `write_memory(addr, data)` (overwrite or insert new page), `memory_maps()` (returns memory pages + module ranges)
- breakpoints: `set_breakpoint` (Software/Hardware/Watchpoint), `remove_breakpoint`, `enable_breakpoint`, `disable_breakpoint`, `breakpoints()`
- modules: `modules()` -> `Vec<ModuleInfo>`
- backtrace: `backtrace(tid)` returns 2 synthetic frames (simulated_function + ntdll!RtlUserThreadStart)

### `v2` submodule (spec-compliant)
- `WinDbgError` enum: NotConnected, CommandFailed, Parse, Timeout
- `WinDbgCommand` enum (Go, StepIn, StepOver, StepOut, BreakIn, Evaluate(String), DumpStack, DumpLocals, ListModules, ShowRegisters, SetBreakpoint(u64), Command(String)) — Display renders WinDbg command strings (g/t/p/gu/.break/?/k/dv/lm/r/bp/<raw>)
- `OutputSource` enum: Debuggee, Debugger, Extension, Event
- `WinDbgOutput { text, is_error, source }` with `ok` / `err` constructors
- `WinDbgSession { id, target_pid, connected, log }` with `new`, `add_log`, `log_count`
- `WinDbgClient` trait: `attach(pid) -> WinDbgSession`, `execute(&mut session, cmd) -> WinDbgOutput`, `detach(&mut session)`
- `MockWinDbgClient { outputs: Mutex<Vec<WinDbgOutput>> }` with `new` / `default`; `execute` pops queued outputs (LIFO) or echoes command text

### Submodules (winext_api etc.)
- `winext_api`: `WinExtError` enum, `ExtResult<T>`, structs `ExtOutput`, `ExtGetExpression`, `VirtualMemory`, `ExtReadVirtual<'a>`, `ExtWriteVirtual<'a>`, `DebugClient`, `DebugControl`, `SymbolInfo`, `DebugSymbols`, `ExtensionLoader`; trait `WinExtension`
- `windbg_stack_walker`: `FrameKind`, `StackFrame`, `SymbolMap`, `WindbgStackWalker`
- Other submodules expose ~10–60 pub fns each (parsers, runners, analyzers) — all simulation-level helpers per the crate-level doc.

## Behavior summary (expected)
- Construction yields an "initialized" session with synthetic OS state but `NoDebuggee` status until `launch`/`attach`.
- `attach` / `launch` set pid and map a 4 KiB NOP page at 0x0000_0001_4001_0000.
- Memory read/write operate on page table (HashMap base->Vec<u8>); reads error if page not mapped or request extends past page, writes create a new page if address miss.
- Breakpoints stored in shared `DebugSession`; duplicate set returns `BreakpointExists`; enable/disable removes+reinserts toggled copy.
- `continue_execution` checks if rip matches any enabled breakpoint to produce `Breakpoint` stop reason, else `SingleStep`.
- `execute_command` is a small built-in interpreter producing canned WinDbg-style text; unknown verbs error.
- v2 API provides a transport-agnostic abstraction with a mock for tests.

## Tests
- Embedded `#[cfg(test)] mod tests` exercising construction, attach/detach, registers, memory, breakpoints, command dispatch, symbol path, threads, backtrace, Display/Debug, and `v2` mock client (~50 test fns).
- Integration tests directory: `tests/blitz.rs`, `tests/blitz2.rs`.

## Notes
- Pure simulation: claims in crate docs explicitly state "No actual Windows APIs are used"; despite windows-sys dependency, behavior is deterministic and platform-independent in tests.
- Async surface uses `async_trait`; runtime `tokio` (multi-thread/macros via workspace).
- Heavy duplication of "WinDbgSession"/"WinDbgError" between top-level (Debugger-impl) and `v2` (client/mock) — intentional dual API.
