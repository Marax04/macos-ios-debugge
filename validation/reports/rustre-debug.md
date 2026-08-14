# rustre-debug

## Scopo
Hub crate del sottosistema debugger di RustRE Suite. Definisce trait, tipi condivisi e wrapper di stato di sessione utilizzati da tutti i backend OS/arch-specifici (linux, macos, windows, gdb, windbg, frida, unicorn, kgdb), implementati in sub-crate separate. Non contiene logica OS-specifica: solo astrazioni (`Debugger` trait async + `v2::Debugger` trait sync) e moduli per session manager, watchpoint engine, time-travel, memory layout, register context, source map, expression evaluator, conditional breakpoints.

## Dipendenze chiave
- `rustre-core` (Address)
- `rustre-mem` (re-export pubblico)
- `async-trait`, `tokio`, `parking_lot`, `thiserror`, `serde`, `tracing`

NOTE: il crate hub NON dipende dai sub-crate `rustre-debug-*` (ciclo workspace). L'aggregazione concreta vive in `rustre-debug-registry`.

## Moduli pubblici
- `cross_platform_debug`, `expression_evaluator`, `source_map`
- `debug_session_manager` (DebugSessionManager, DebugSession, SessionPool, SessionEvent, DebugTarget, SessionRecorder)
- `multi_target_debugger`
- `watchpoint_engine` (DR0-DR3 x86, DBGWVR/DBGWCR ARM64, page-protect fallback, conditional/one-shot/hit-count)
- `time_travel_debug` (step-backward, reverse-continue, snapshot-based)
- `memory_layout_view` (heap chunks ptmalloc2/jemalloc/tcmalloc/NT, stack unwind, mapped regions, guard pages)
- `debugger_event_loop`, `register_context`, `memory_search`
- `conditional_breakpoint`, `watchpoint_manager`, `debug_session_recorder`
- `v2` (API semplificata spec-compliant)

## Tipi pubblici principali
- `DebugError` (enum thiserror: NotAttached, ProcessNotFound, BreakpointExists/NotFound, MemoryError, RegisterError, StepError, LaunchError, DetachError, Unsupported, Os, Timeout, PermissionDenied)
- `ProcessId(u32)`, `ThreadId(u32)` con `Display`
- `RegisterSet { regs: HashMap<String,u64>, pc, sp, fp, lr }`
- `BreakpointKind` (Software, Hardware, DataRead, DataWrite, DataReadWrite)
- `Breakpoint { address, kind, enabled, hit_count, condition, original_byte, label }`
- `StopReason` (Breakpoint, SingleStep, Signal, Exception, ProcessExit, ThreadCreate/Exit, LibraryLoad/Unload, ProcessCreate, AccessViolation, Unknown) con `Display`, `is_exit()`, `address()`
- `DebugEvent { pid, tid, reason, timestamp }` (timestamp ns monotonico via `Instant`/`OnceLock`)
- `MemoryMap { base, size, readable, writable, executable, name, file_path, file_offset }`
- `ModuleInfo { name, path, base, size, entry_point, is_main }`
- `OutputRedirect { stdout, stderr }`
- `LaunchOptions { executable, args, env, working_dir, stop_at_entry, follow_forks, redirect }` builder pattern
- `StackFrame { index, pc, sp, fp, function_name, module, offset, source_file, source_line }`
- `DebugSession` (Arc<RwLock<...>> shared state)
- `v2::{DebugError, BreakpointKind, Breakpoint, StopReason, DebugSession, Debugger, MockDebugger}`

## Funzioni / metodi pubblici

### Funzioni libere
- `with_timeout(dur, fut) -> Result<T, DebugError>` — wrap di future con `tokio::time::timeout`, converte timeout in `DebugError::Timeout`

### `RegisterSet`
- `new()`, `get(name)`, `set(name, value)`, `get_pc() -> Address`, `get_sp() -> Address`, `all_names() -> Vec<String>` (ordinati)

### `Breakpoint`
- `new_software(addr)`, `new_hardware(addr)`, `new_watchpoint(addr, kind)`

### `StopReason`
- `is_exit() -> bool`, `address() -> Option<Address>`

### `DebugEvent`
- `new(pid, tid, reason)` — assegna timestamp ns monotonico

### `LaunchOptions`
- `new(exe)`, `with_args(args)`, `with_env(k, v)`, `stop_at_entry()`

### `DebugSession`
- `new()`, `pid()`, `set_pid(pid)`, `record_event(ev)`, `event_history()`, `add_module(m)`, `modules()`, `add_breakpoint(bp)`, `remove_breakpoint(addr) -> bool`, `get_breakpoint(addr)`, `all_breakpoints()`, `set_running(b)`, `is_running()`, `clear()`

### Trait `Debugger` (async, Send+Sync)
- `name()`, `supported_architectures()`
- Lifecycle: `launch(opts)`, `attach(pid)`, `detach()`, `kill()`, `is_attached()`, `target_pid()`
- Execution: `continue_execution()`, `single_step(tid)`, `step_over(tid)`, `step_out(tid)`, `pause()`
- Threads: `threads()`, `current_thread()`
- Registers: `get_registers(tid)`, `set_registers(tid, regs)`, `get_register(tid, name)`, `set_register(tid, name, val)`
- Memory: `read_memory(addr, size)`, `write_memory(addr, data)`, `memory_maps()`
- Breakpoints: `set_breakpoint(addr, kind)`, `remove_breakpoint(addr)`, `enable_breakpoint(addr)`, `disable_breakpoint(addr)`, `breakpoints()`
- Modules: `modules()`
- Stack: `backtrace(tid)`

### `v2::DebugSession`
- `new(pid)`, `add_breakpoint(addr, kind) -> u32`, `remove_breakpoint(id) -> bool`, `enable_bp(id) -> bool`, `disable_bp(id) -> bool`, `bp_count()`, `enabled_bps() -> Vec<&Breakpoint>`

### `v2::Breakpoint`
- `new(id, addr, kind)`, `is_watchpoint() -> bool`

### `v2::Debugger` (trait sync)
- `name()`, `attach(pid)`, `detach(s)`, `read_memory(s, addr, size)`, `write_memory(s, addr, data)`, `read_registers(s)`, `step(s)`, `cont(s)`

### `v2::MockDebugger`
- `new(name)` + impl `Debugger` per testing in-memory (mem: HashMap<u64,Vec<u8>>, regs: HashMap<String,u64>)

## Ground truth verificabile esternamente
- **Test inline** in `lib.rs` (`#[cfg(test)] mod tests`) — coprono DebugSession, RegisterSet, Breakpoint constructors, StopReason Display/is_exit/address, LaunchOptions builder, DebugEvent, ProcessId/ThreadId Display, e l'intero modulo `v2` incluso `MockDebugger`. Eseguibili con `cargo test -p rustre-debug`.
- **Directory `tests/`** presente (test di integrazione).
- I tipi semplici (`ProcessId(42).to_string() == "PID(42)"`, `BreakpointKind::WatchRead.to_string() == "watch-read"`, ecc.) sono verificabili senza target reale.
- `with_timeout` verificabile con un future che dorme oltre il timeout.
- Trait `Debugger` non testabile direttamente senza backend OS-specifico; usare i sub-crate `rustre-debug-{linux,macos,windows,gdb,windbg,frida,unicorn,kgdb}` o `MockDebugger` v2.
- Confronto esterno: confrontare semantica con GDB/MI, LLDB SB API, WinDbg DbgEng, Frida Stalker per validare completezza superficie API.

## Tool MCP esistenti correlati
- `mcp__rustre-mcp__debug_attach`, `debug_launch`, `debug_continue`, `debug_step_into`, `debug_step_over`, `debug_backtrace`
- `mcp__rustre-mcp__debug_set_breakpoint`, `debug_remove_breakpoint`
- `mcp__rustre-mcp__debug_read_memory`, `debug_write_memory`, `debug_read_registers`, `debug_evaluate`

Questi tool MCP corrispondono direttamente ai metodi del trait `Debugger` esposto da questo crate — la superficie MCP è una proiezione 1:1 del trait, quindi rustre-debug è la fonte canonica per la loro semantica.
