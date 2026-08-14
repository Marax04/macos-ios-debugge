# rustre-debug-macos

## Purpose
macOS debugger backend for the RustRE platform. Implements the `Debugger` trait
from `rustre-debug` using Mach port APIs (`task_for_pid`, `vm_read_overwrite`,
`vm_write`, `task_threads`, `thread_get_state/set_state`, `task/thread suspend/resume`)
and BSD `ptrace` (PT_ATTACHEXC / PT_DETACH / PT_CONTINUE / PT_STEP) for process
control. On non-macOS targets every async Debugger method returns
`DebugError::Unsupported`, so the crate is buildable on all platforms.
Also exposes portable Mach-O header parsing types and a collection of
auxiliary submodules covering dSYM, dyld, exception ports, Mach VM, Mach port
management, DTrace, LLDB compat/integration, crash analysis, and iOS support.

## Dependencies
- `rustre-debug` (Debugger trait, types, errors)
- `rustre-core` (Address)
- async-trait, tokio, parking_lot, serde, serde_json, thiserror
- `libc 0.2` (target_os = "macos" only)

## Public API (lib.rs)

### Types
- `BreakpointManager { breakpoints: HashMap<u64,u8> }` — tracks original bytes
  overwritten by software (0xCC) breakpoints.
  - `new() -> Self`
  - `insert(&mut self, addr: u64, original_byte: u8)`
  - `remove(&mut self, addr: u64) -> Option<u8>`
  - `contains(&self, addr: u64) -> bool`
  - `all(&self) -> Vec<u64>`
- `MacosProcess { pid: ProcessId, task_port: u32, thread_ports: Vec<u32> }` —
  Clone/Debug, holds Mach task & thread ports for an attached process.
- `MacosArch { X86_64, Arm64 }` — Copy/PartialEq enum used to select thread-state flavour.
- `MacosRegisterSet` (zero-sized helper):
  - `x86_64_index(name: &str) -> Option<usize>` — maps register name to index in
    x86_THREAD_STATE64 array (rax..gs, rip=16, rflags=17). None for unknown names.
  - `arm64_index(name: &str) -> Option<usize>` — maps to ARM_THREAD_STATE64 array
    (x0..x28, fp/x29=29, lr/x30=30, sp=31, pc=32, cpsr=33). None otherwise.
- `MacosDebugger` — main backend.
  - `new() -> Self` (also `Default`)
  - Implements `rustre_debug::Debugger`: `launch`, `attach`, `detach`, `kill`,
    `is_attached`, `target_pid`, `continue_execution`, `single_step`,
    `step_over`, `step_out`, `pause`, `threads`, `current_thread`,
    `get_registers`, `set_registers`, `get_register`, `set_register`,
    `read_memory`, `write_memory`, `memory_maps`, `set_breakpoint`,
    `remove_breakpoint`, `enable_breakpoint`, `disable_breakpoint`,
    `breakpoints`, `modules`, `backtrace`. `name()` returns "macos-mach";
    `supported_architectures()` returns `["x86_64", "arm64"]`.

### Behavior (macOS path)
- `launch`: spawns `LaunchOptions.executable` with args/env/cwd via
  `std::process::Command`, then `task_for_pid` + `PT_ATTACHEXC`, enumerates
  threads, stores `Child` handle to avoid zombies.
- `attach`: `task_for_pid(pid)` + `PT_ATTACHEXC`, enumerate threads.
- `detach` / `kill`: ptrace detach or SIGKILL, then waits child if launched.
- `continue_execution` / `single_step`: PT_CONTINUE / PT_STEP then
  `waitpid` on a `tokio::task::spawn_blocking`, decodes status into
  `StopReason::Exited|Signal|SingleStep` with PC captured for single-step.
- `step_over` / `step_out`: currently delegate to `single_step` (simplified).
- `pause`: sends SIGSTOP to pid.
- `threads`: maps Mach thread ports to sequential `ThreadId(i)`.
- `get/set_registers`, `get/set_register`: `thread_get_state` /
  `thread_set_state` with X86_THREAD_STATE64 (count 42) or ARM_THREAD_STATE64
  (count 68); converted via internal `state_to_register_set` /
  `register_set_to_state`. Setting `rip`/`pc`/`rsp`/`sp` also updates
  `RegisterSet.pc/sp` mirrors.
- `read_memory`: `vm_read_overwrite`, caps requests at 256 MiB (returns
  `MemoryError`). `write_memory`: `vm_write` (caps at u32::MAX).
- `memory_maps`, `modules`: stubbed to empty vec (safe no-op).
- `set_breakpoint`: TOCTOU-safe — locks state, checks not present, reads
  original byte, writes 0xCC, records original.
- `remove_breakpoint`: restores original byte and removes record.
- `enable_breakpoint` / `disable_breakpoint`: re-patch 0xCC or restore byte
  for an existing record (errors with `BreakpointNotFound` if absent).
- `breakpoints`: returns `Vec<Breakpoint>` with `original_byte` populated.
- `backtrace`: walks frame-pointer chain from current PC/SP/FP using
  `read_memory`, up to 64 frames.

### Non-macOS path
All async Debugger methods return `DebugError::Unsupported("macos-mach requires macOS")`.
`is_attached()` returns false, `target_pid()` returns None. `name()` and
`supported_architectures()` still return their normal values.

### Portable Mach-O parsing (compiled on all targets)
- `macho_magic` module: `MH_MAGIC`, `MH_CIGAM`, `MH_MAGIC_64`, `MH_CIGAM_64`,
  `FAT_MAGIC`, `FAT_CIGAM` u32 constants.
- `CpuType` enum (I386, X86_64, Arm, Arm64, Ppc, Ppc64, Unknown):
  - `from_u32(v: u32) -> Self`
  - `name(self) -> &'static str`
- `MachoFileType` enum (Execute, DyLib, Bundle, DyLinker, Core, Object, Unknown):
  - `from_u32(v: u32) -> Self`
  - `name(self) -> &'static str`
- `MachoHeader { magic, cpu_type, cpu_subtype, file_type, n_cmds,
  size_of_cmds, flags, is_64 }` — parsed representation (additional parsing
  helpers exist further in the file, not enumerated here).

## Submodules (each `pub mod`)
Public functions are platform-specific helpers and analyzers; not all
inspected line-by-line here:

| Module | pub fn count | Scope |
|---|---|---|
| `lib.rs` (root) | 136 | core debugger + Mach-O types |
| `mach_debugger` | 77 | low-level Mach task/thread control |
| `exception_ports` | 49 | EXC_BAD_ACCESS / Mach exception port wiring |
| `dtrace_probe_manager` | 39 | DTrace probe registration |
| `dtrace_integration` | 38 | DTrace script/session glue |
| `ios_debugger` | 34 | iOS device debugging support |
| `lldb_integration` | 34 | LLDB remote/embedded driver |
| `macos_crash_analyzer` | 33 | .crash / spindump parsing |
| `mach_exception_handler` | 32 | exception-thread message loop |
| `mach_vm` | 30 | vm_region / vm_protect helpers |
| `mach_port_manager` | 20 | Mach port lifetime mgmt |
| `mach_port_debug` | 19 | introspection on Mach ports |
| `lldb_compat` | 16 | LLDB compat shims |
| `dyld_info` | 15 | dyld image list / shared cache |
| `dsym_reader` | 10 | .dSYM bundle parsing |
| `dyld_debugger` | 10 | dyld notification breakpoints |

Total public fn across crate: 592.

## Testability
- Crate ships with `#[cfg(test)]` unit tests covering `BreakpointManager`,
  `MacosRegisterSet` (x86_64 + arm64), `MacosArch`, `MacosProcess`,
  `MacosDebugger` construction/name/archs, and non-macOS stub
  `Unsupported` returns. Plus integration tests in `tests/`.
- Pure-data helpers (Mach-O parsing, register-name → index, BreakpointManager)
  are fully testable on any platform.
- Live debugging paths (launch/attach/read/write/breakpoint/step) require
  macOS + entitlements (`task_for_pid` needs `com.apple.security.cs.debugger`
  or root) and a real target process. They are not exercisable on Windows/Linux,
  but their non-macOS stubs (return `Unsupported`) are testable cross-platform.

Verdict: testable cross-platform for the portable surface and the stub
behaviour; live behaviour testable only on macOS hosts with proper entitlements.
