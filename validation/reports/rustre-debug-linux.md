# rustre-debug-linux

## Purpose
Linux ptrace(2)-based debugger backend implementing the `Debugger` trait from `rustre-debug`. On non-Linux targets every method returns `DebugError::Unsupported`. Provides process launch/attach, software breakpoints, stepping, register/memory access, thread enumeration, module listing, and a frame-pointer backtrace walker. Also exposes a rich set of submodules for advanced Linux-specific debugging (syscall tracing, perf_event sampling, /proc reading, ELF coredump parsing, signal handling, watchpoints).

## Cargo.toml
- name: `rustre-debug-linux` v0.1.0, edition 2024
- deps: `rustre-debug`, `rustre-core`, `nix 0.29` (ptrace/signal/process), `tokio`, `async-trait`, `thiserror`, `parking_lot`, `serde`, `tracing`, `bitflags`
- tests: `tests/blitz.rs`, `tests/blitz2.rs`

## Public Modules
- `breakpoint_manager` — soft/hard breakpoints, watchpoints, conditional expressions, DB
- `coredump` — ELF coredump reader/builder, PRSTATUS/PRPSINFO/AUXV/MemoryMap
- `perf_events` — perf_event_open wrapper, HW/SW events, breakpoint type, counter groups, samples
- `perf_event_debug` — PMU counter collection, PEBS sampling, per-step counter snapshots, hotspots
- `syscall_tracer` — strace-like output, syscall events/filters/statistics/timelines, suspicious-pattern detection
- `ptrace_advanced` — PTRACE_SYSCALL/SINGLEBLOCK/GET_SYSCALL_INFO, seccomp BPF, child tracking, basic blocks
- `ptrace_engine` — alternative engine with own arch enum, regs, memory ops, breakpoint manager
- `ptrace_wrapper` — typed PtraceRequest/Event/Options enums, WaitStatus, regs, session wrapper
- `proc_fs_reader` — ProcState/MemMapEntry/FdEntry/ProcessInfo + reader
- `elf_coredump_parser` — PT_LOAD/PT_NOTE walking, NT_PRSTATUS, NT_FILE, AUXV, LoadSegment, 32/64 LE/BE
- `linux_signal_handler` — SignalNumber/SigCode/SigAction/SignalInfo, `format_signal_event`, `LinuxSignalHandler`

## Top-Level Public API (`lib.rs`)

### `ProcMapsParser` (struct)
- `parse(content: &str) -> Vec<MemoryMap>` — parse `/proc/<pid>/maps` text
- `parse_line(line: &str) -> Option<MemoryMap>` — parse one line; returns None on garbage

Behavior: extracts addr range, permissions (r/w/x), file offset, optional pathname; bracketed names (`[stack]`, `[heap]`, `[vdso]`) treated as name without file_path; for file paths, name = basename.

### `LinuxDebugger` (struct)
- `new() -> Self` — detached instance
- `default() -> Self`
- `session(&self) -> &DebugSession` — access underlying session state

Implements `rustre_debug::Debugger` trait (async). On Linux only; non-Linux build returns `DebugError::Unsupported` for every async op.

#### Trait methods (Linux behavior)
- `name() -> &str` -> `"linux-ptrace"`
- `supported_architectures() -> Vec<String>` -> `["x86_64", "x86"]`
- `launch(LaunchOptions) -> Result<ProcessId>` — forks child, `PTRACE_TRACEME`, execves; honors `stop_at_entry`; rejects double-launch; inherits current env merged with `opts.env`
- `attach(ProcessId) -> Result<()>` — `PTRACE_ATTACH` + wait for SIGSTOP; rejects double-attach
- `detach() -> Result<()>` — restores all software breakpoints, `PTRACE_DETACH`, clears session
- `kill() -> Result<()>` — sends SIGKILL, clears session
- `is_attached() -> bool`, `target_pid() -> Option<ProcessId>`
- `continue_execution() -> Result<DebugEvent>` — handles BP fix-up (restore byte, rewind RIP, single-step, re-arm INT3); detects mid-step exit/signal
- `single_step(ThreadId) -> Result<DebugEvent>` — `PTRACE_SINGLESTEP`
- `step_over(ThreadId) -> Result<DebugEvent>` — for x86 near CALL (opcode 0xE8) installs temporary BP at PC+5; otherwise falls back to single-step
- `step_out(ThreadId) -> Result<DebugEvent>` — reads return address from [rsp], temp BP, continue
- `pause() -> Result<()>` — send SIGSTOP
- `threads() -> Result<Vec<ThreadId>>` — enumerates `/proc/<pid>/task/`
- `current_thread() -> Result<ThreadId>`
- `get_registers / set_registers / get_register / set_register` — x86_64 via `PTRACE_GETREGS/SETREGS`; synthetic `pc/rip`, `sp/rsp`, `fp/rbp`
- `read_memory / write_memory` — word-sized `PTRACE_PEEKDATA/POKEDATA`; partial-word writes use read-modify-write
- `memory_maps() -> Result<Vec<MemoryMap>>` — parses `/proc/<pid>/maps`
- `set_breakpoint(addr, kind)` — Software: install INT3 (0xCC), save original byte; Hardware / Data*: `Unsupported`
- `remove_breakpoint / enable_breakpoint / disable_breakpoint` — restore byte, sync session record
- `breakpoints() -> Result<Vec<Breakpoint>>`
- `modules() -> Result<Vec<ModuleInfo>>` — groups contiguous file-backed mappings; main detected via `/proc/<pid>/exe`
- `backtrace(ThreadId) -> Result<Vec<StackFrame>>` — frame-pointer chain walk up to 64 frames; reads saved rbp and return address

### Free function
- `parse_proc_maps(content: &str) -> Vec<ProcMapsEntry>` (alternative parser with richer entry type defined inline in lib.rs)

### Other top-level public types (selection)
`ProcMapsEntry`, `ProcStatus`, `ProcStat`, `Dr7` (+ `Dr7Condition`, `Dr7Length`), `HardwareBreakpointManager`, `SyscallRecord`, `SyscallInfo`, `SyscallPhase`, `LinuxError`, `AllocType`, `InjectConfig`, `LinkerInfo`, `AuxEntry`, `AuxVec`, `LinuxSignal`, `PtraceEventType`, `ThreadState`, `SigSet(pub u64)`, `PtraceOptions(pub u32)`, `MemRange`, `AuxvReader`, `TraceLog`/`TraceLogEntry`, `BreakpointCondition`/`CmpOp`, `SignalPolicy`/`SignalFilter`, `ThreadSnapshot`, `ProcessSnapshot`, `ElfNoteType`, `ElfNote`.

## Inputs / Outputs (high-level)
- Input: target executable path + args + env (launch), or existing PID (attach); addresses, register names, byte buffers.
- Output: `DebugEvent` with `StopReason` (ProcessExit, Signal, Breakpoint, SingleStep, Unknown), `RegisterSet`, `Vec<MemoryMap>`, `Vec<ModuleInfo>`, `Vec<StackFrame>`, `Vec<ThreadId>`.
- Errors: `DebugError::{NotAttached, Os, RegisterError, MemoryError, BreakpointExists, BreakpointNotFound, LaunchError, DetachError, StepError, Unsupported}`.

## Expected Behavior Summary
Provides a complete, ptrace-driven Linux debugger backend that the higher-level RustRE debug stack can consume through the `Debugger` trait. Software breakpoint lifecycle (install, hit detection, fix-up, re-arm) is fully managed. Stepping covers single-step, step-over (for direct near-CALL only), and step-out via temp breakpoint at saved return address. Memory access uses word-aligned PEEK/POKE with partial-word RMW. Module enumeration groups contiguous file-backed mappings. Backtrace uses frame-pointer walking (requires `-fno-omit-frame-pointer` targets). Hardware breakpoints / data watchpoints at the trait level are stubbed `Unsupported`, but submodules `breakpoint_manager` and `perf_event_debug` contain hardware-BP infrastructure usable independently.

## Testability
Yes — testable. `lib.rs` already contains an extensive `#[cfg(test)] mod tests` (parser unit tests pass on any OS; non-Linux stub tests verify `Unsupported`). Two additional integration test files in `tests/`. Parser and construction paths are platform-independent; ptrace flows require a Linux runtime.

## Counts
- fn_count (top-level + impl pub fns + trait methods, lib.rs): ~38 (LinuxDebugger trait methods ~28, ProcMapsParser 2, LinuxDebugger inherent 3, parse_proc_maps 1, plus auxiliary type ctors).
- Total pub items across crate (structs/enums/fns/traits): ~140.
