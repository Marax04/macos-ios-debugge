# rustre-debug-windows

## Purpose
Windows-specific debugger back-end for the `rustre-debug` framework. Implements the `Debugger` trait via the Win32 Debug API (`CreateProcess`/`DebugActiveProcess`/`WaitForDebugEvent`/`ContinueDebugEvent`) and provides extensive surrounding tooling: PE loader simulation, process memory scanning, PEB/TEB internals, SEH/VEH exception handling, heap (PageHeap/HeapWalk) debugging, module-load tracking, symbol/PDB resolution, and WoW64 (32-bit-on-64-bit) support. Non-Windows builds compile but every operation returns `DebugError::Unsupported`.

## Dependencies
- `rustre-debug` (trait + types: `Debugger`, `DebugSession`, `DebugEvent`, `StopReason`, `Breakpoint`, `RegisterSet`, `MemoryMap`, `LaunchOptions`, `ModuleInfo`, etc.)
- `rustre-core` (`Address`)
- `rustre-sysinternals` (re-exported)
- `windows-sys` 0.59 (Debug, Threading, Memory, ProcessStatus, ToolHelp, Security, LibraryLoader)
- `tokio`, `async-trait`, `thiserror`, `parking_lot`, `serde`, `ahash`

Crate-level: `unsafe_code = "allow"` (Win32 wrappers), `unused_must_use = "deny"`.

## Modules (public)
- `win32_debug_api` — high-level Win32 debug-API surface (~72 pub fn)
- `windows_internals` — PEB/TEB/CriticalSection/HandleTable/ExceptionRecord/CONTEXT (x86/x64/ARM64), LoadedModuleList (~37 pub fn)
- `win_exception_handler` — exception classification, first/second chance, SEH chain unwind, VEH, callstack capture, per-code filters (~27 pub fn)
- `win_heap_debug` — PageHeap full/light, HeapWalk, corruption detection (double-free, overflow, UAF, header), arena tracking, HPDA (~27 pub fn)
- `win_module_events` — DLL load/unload notifications, LoadLibrary/FreeLibrary intercept, rebase detection, IAT-hook scan, PE section mapping, anomaly detection (~26 pub fn)
- `debug_event_handler` — richer typed event kinds with per-event metadata (~27 pub fn)
- `pe_loader_simulation` — pure-Rust PE loader: section mapping, base relocation, IAT patching, TLS callbacks (~15 pub fn)
- `process_memory_api` — typed wrappers on `VirtualQueryEx`/`ReadProcessMemory`/`WriteProcessMemory` with `PageState`/`PageType`/`PageProtection` enums (~31 pub fn)
- `process_memory_scanner` — AOB/pattern scan (exact, masked, wildcard) with parser for `"48 8B ? ? 90 CC"` (~23 pub fn)
- `win_symbol_resolver` — PE export-table walker, RSDS/CodeView debug dir parser, PDB-path extractor, symbol cache (~26 pub fn)
- `win32` (in `lib.rs`) — thin safe wrappers around raw Win32 calls

## Public API in `lib.rs` (top-level)

### Error / constants
- `enum WindowsDebugError { Win32(u32,String), InvalidHandle, AccessDenied, NotInitialized }` with `From<WindowsDebugError> for DebugError`.
- Constants exported: `PAGE_NOACCESS`, `PAGE_READONLY`, `PAGE_READWRITE`, `PAGE_WRITECOPY`, `PAGE_EXECUTE`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`, `PAGE_EXECUTE_WRITECOPY`, `PAGE_GUARD`, `MEM_COMMIT`, `MEM_RESERVE`, `MEM_FREE`, `MEM_IMAGE`, `MEM_MAPPED`, `MEM_PRIVATE`, and Windows exception codes (`EXCEPTION_ACCESS_VIOLATION`, `EXCEPTION_BREAKPOINT`, `EXCEPTION_SINGLE_STEP`, `EXCEPTION_STACK_OVERFLOW`, `EXCEPTION_ARRAY_BOUNDS_EXCEEDED`, `EXCEPTION_DATATYPE_MISALIGNMENT`, `EXCEPTION_FLT_DIVIDE_BY_ZERO`, `EXCEPTION_INT_DIVIDE_BY_ZERO`, `EXCEPTION_INT_OVERFLOW`, `EXCEPTION_ILLEGAL_INSTRUCTION`, `EXCEPTION_PRIV_INSTRUCTION`, `EXCEPTION_IN_PAGE_ERROR`, `EXCEPTION_GUARD_PAGE`, `EXCEPTION_INVALID_HANDLE`, `EXCEPTION_NONCONTINUABLE`).

### `MemoryRegionInfo` (decoded `MEMORY_BASIC_INFORMATION`)
Fields: `base, size, state, protect, type_ : u64/u32`.
Methods:
- `is_readable(&self) -> bool` — committed and protect allows read.
- `is_writable(&self) -> bool` — committed and protect allows write.
- `is_executable(&self) -> bool` — committed and protect allows execute.
- `is_committed(&self) -> bool` — state == MEM_COMMIT.
- `to_memory_map(&self) -> MemoryMap` — convert to neutral type, populates rwx flags.
- `protect_name(&self) -> &'static str` — name of effective protection (PAGE_GUARD stripped).

### `ProcessEntry { pid, name, parent_pid, thread_count }` — from EnumProcesses snapshot.
### `ModuleEntry { base, size, path, name }` — from EnumProcessModules.

### `DebugEventDecoder` (stateless)
- `decode_exception(code,address,is_first_chance,pid,tid) -> StopReason` — maps to `Breakpoint`/`SingleStep`/`AccessViolation`/`Exception{...}`.
- `exception_name(code) -> &'static str` — human-readable.
- `decode_exit_process(exit_code,pid,tid) -> StopReason::ProcessExit`.
- `decode_load_dll(base,path,pid,tid) -> StopReason::LibraryLoad`.
- `decode_unload_dll(base,pid,tid) -> StopReason::LibraryUnload`.
- `decode_create_thread(tid,pid) -> StopReason::ThreadCreate`.
- `decode_exit_thread(tid,exit_code,pid) -> StopReason::ThreadExit`.

### `mod win32` — safe wrappers (Windows-only, `#[cfg(windows)]`)
- `get_last_error() -> u32`
- `format_error(code: u32) -> String` — FormatMessageW UTF-16 → UTF-8.
- `read_process_memory(handle, addr, size) -> Result<Vec<u8>, WindowsDebugError>` — buffer truncated to actual bytes read.
- `write_process_memory(handle, addr, &[u8]) -> Result<usize, WindowsDebugError>` — returns bytes written.
- `suspend_thread(handle) -> Result<u32,...>` / `resume_thread(handle) -> Result<u32,...>` — previous suspend count.
- `get_thread_context_x64(handle) -> Result<RegisterSet,...>` — RAX..R15, RIP, RSP, RBP, RFLAGS; populates `pc`/`sp`/`fp`.
- `set_thread_context_x64(handle, &RegisterSet) -> Result<(),...>` — reads current first, applies only named fields.
- `virtual_query_ex(handle, base) -> Option<MemoryRegionInfo>`.
- `enumerate_memory_regions(handle) -> Vec<MemoryRegionInfo>` — walks entire VA space.
- `open_process_debug(pid) -> Result<isize,...>` — PROCESS_ALL_ACCESS, maps ACCESS_DENIED.
- `close_handle(handle) -> bool`.
- `enumerate_processes() -> Vec<ProcessEntry>`.
- `enumerate_modules(handle) -> Vec<ModuleEntry>`.
- `open_thread(tid) -> Result<isize,...>` — THREAD_ALL_ACCESS.
- `is_committed(state) -> bool` — utility.
- `is_wow64_process(handle) -> bool` (windows + non-windows stub returns false).
- `get_wow64_context(handle) -> Result<Wow64Context,...>`.
- `set_wow64_context(handle, &Wow64Context) -> Result<(),...>`.

### `Wow64Context` — 32-bit register context (mirrors WOW64_CONTEXT)
Fields: `context_flags, dr0..dr3, dr6, dr7, eax, ecx, edx, ebx, esp, ebp, esi, edi, eip, eflags : u32`.
- `trap_flag(&self) -> bool` — TF bit set in EFLAGS.
- `set_trap_flag(&mut self, bool)` — toggle TF.
- `to_register_set(&self) -> RegisterSet` — populated with eax..eflags, dr*, pc/sp/fp.

### Top-level WoW64 free functions (Windows + stub variants)
- `is_wow64_process(handle) -> bool`.
- `get_wow64_context(thread) -> Result<Wow64Context, WindowsDebugError>`.
- `set_wow64_context(thread, &Wow64Context) -> Result<(), WindowsDebugError>`.

### `WindowsDebugger` (main type)
State (all under `parking_lot::RwLock`): `session: DebugSession`, `process_handle: Option<isize>`, `thread_handles: AHashMap<u32,isize>`, `sw_breakpoints: AHashMap<u64,u8>` (addr → original byte), `debug_active: bool`, `is_wow64: bool`, `last_event_ids: (u32,u32)` (last pid/tid for ContinueDebugEvent).
- `new() -> Self` / `Default`.
- `session(&self) -> &DebugSession`.
- `get_instruction_pointer(&self, tid: u32) -> Result<u64, DebugError>` — WoW64-aware; reads RIP or zero-extended EIP.
- `is_32bit_process(&self) -> bool` — true after CREATE_PROCESS_DEBUG_EVENT identifies WoW64.

Implements `Debugger` (`#[async_trait]`):
- `name() -> "windows-debug-api"`, `supported_architectures() -> ["x86_64","x86"]`.
- `is_attached()`, `target_pid()`.
- `async launch(LaunchOptions) -> Result<ProcessId, DebugError>` — `CreateProcessW` with `DEBUG_ONLY_THIS_PROCESS`; stores process/thread handles; sets `debug_active`. Errors: `Os("already debugging…")`, `LaunchError(format_error)`.
- (Remaining `Debugger` methods — attach, detach, kill, step, continue, set/remove breakpoint, read/write memory, registers, threads, modules, memory map, backtrace, wait-for-event — are implemented further in the file using the private helpers: `handle_or_err`, `install_int3`/`restore_byte` (overwrite/restore `0xCC` and original byte), `wait_for_debug_event(timeout_ms)` (decodes all 7 `DEBUG_EVENT` codes via `DebugEventDecoder`, tracks WoW64 on process create, records `last_event_ids`), `continue_debug_event(pid,tid,status)`.)

Breakpoint behavior: software breakpoints implemented as INT3 (`0xCC`) byte patches; original byte saved in `sw_breakpoints` map; removed by writing back. `EXCEPTION_BREAKPOINT` maps to `StopReason::Breakpoint`. Single-step done via TF flag in EFLAGS/RFLAGS.

## Input / Output summary
- Inputs: PIDs, TIDs (u32), addresses (u64), memory buffers (&[u8]), `LaunchOptions { executable, args, ... }`, `Breakpoint`, `RegisterSet`.
- Outputs: `Result<…, DebugError>` for fallible ops; rich event stream as `DebugEvent { pid, tid, reason: StopReason }`; lists of `ProcessEntry`/`ModuleEntry`/`MemoryRegionInfo`/`MemoryMap`.
- Errors: every Win32 failure surfaces as `WindowsDebugError::Win32(code, FormatMessageW text)` then converted to `DebugError::Os` (or `PermissionDenied` for ACCESS_DENIED). Non-Windows: `DebugError::Unsupported`.

## Behavior summary
1. Caller constructs `WindowsDebugger::new()`.
2. `launch` (CreateProcessW + DEBUG_ONLY_THIS_PROCESS) or attach (DebugActiveProcess via `Debugger` trait method) starts a debug session.
3. The OS sends debug events; `wait_for_debug_event` blocks (with timeout → `DebugError::Timeout` on 121/ERROR_SEM_TIMEOUT) and decodes into `DebugEvent`/`StopReason`. On `CREATE_PROCESS_DEBUG_EVENT` it stores the process handle, detects WoW64, and records the main thread handle. On thread create it records the thread handle.
4. Caller inspects/modifies state through `read_process_memory`, `write_process_memory`, register get/set (x64 or WoW64), virtual_query_ex, enumerate_modules, sets INT3 software breakpoints.
5. `continue_debug_event(pid,tid,DBG_CONTINUE)` resumes execution.
6. WoW64 path is transparent: `get_instruction_pointer` and register access dispatch on `is_wow64`.
7. Symbol resolution for backtraces leverages `win_symbol_resolver` (PE exports + PDB path from CodeView debug dir + cache).
8. Auxiliary tooling (heap, exception, module-event, pattern scanner, PE loader simulation) is exposed as separate modules and not driven by the `Debugger` trait; they target advanced RE workflows.

## Testability
- Crate has a `tests/` directory (integration tests).
- Unit-testable items independent of Windows: `MemoryRegionInfo` rwx/protect logic, `DebugEventDecoder::*` (pure decode), `Wow64Context::trap_flag`/`to_register_set`, the pattern-string parser in `process_memory_scanner`, and the pure-Rust PE loader simulation. These work on any host.
- Win32-bound functions in `win32::*` and `WindowsDebugger`'s `Debugger` impl require Windows + a debuggable target process; on non-Windows they compile but every entry returns `DebugError::Unsupported`. Live-debug behavior requires admin/SeDebugPrivilege for many targets.

## Public fn counts (per file)
lib.rs 184, win32_debug_api 72, process_memory_api 31, win_symbol_resolver 26, win_module_events 26, win_heap_debug 27, win_exception_handler 27, debug_event_handler 27, windows_internals 37, process_memory_scanner 23, pe_loader_simulation 15. Total ≈ **495 pub fn**.
