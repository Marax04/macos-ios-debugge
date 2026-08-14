# Debug & Emulation Subsystem — Deep Analysis

> **Crates covered:** `rustre-debug`, `rustre-debug-registry`, `rustre-debug-windows`,
> `rustre-debug-linux`, `rustre-debug-macos`, `rustre-debug-gdb`, `rustre-debug-windbg`,
> `rustre-debug-kgdb`, `rustre-debug-frida`, `rustre-debug-unicorn`, `rustre-emu`,
> `rustre-emu-unicorn`, `rustre-emu-qiling`, `rustre-emu-shellcode`, `rustre-adb`

---

## 1. Architecture Overview

The debug and emulation subsystem follows a strict two-layer pattern:

```
                   ┌─────────────────────────────────────────┐
                   │           rustre-debug-registry          │  ← composition crate
                   │  all() → Vec<Box<dyn Debugger>>         │
                   └───────┬───────────────────────┬─────────┘
                           │ depends on             │ depends on
          ┌────────────────▼──┐               ┌────▼───────────────┐
          │   rustre-debug    │               │  backend crates:   │
          │  (hub/trait def)  │←─── dep ──────│  *-windows         │
          │  Debugger trait   │               │  *-linux           │
          │  DebugSession     │               │  *-macos           │
          │  RegisterSet etc. │               │  *-gdb             │
          └───────────────────┘               │  *-windbg          │
                                              │  *-kgdb            │
                                              │  *-frida           │
                                              │  *-unicorn         │
                                              └────────────────────┘

                   ┌──────────────────────────────────────────┐
                   │              rustre-emu                   │  ← emulation hub
                   │  Emulator trait, SimpleInterpreter (x86) │
                   └──────────┬───────────────────────────────┘
                              │ dep
                   ┌──────────▼───────────┐
                   │  rustre-emu-unicorn   │  ← full Unicorn model (no native FFI default)
                   │  rustre-emu-qiling    │  ← Qiling-inspired OS layer
                   │  rustre-emu-shellcode │  ← sandboxed shellcode analysis
                   └──────────────────────┘

                   ┌──────────────────────────────────────────┐
                   │              rustre-adb                   │  standalone Android client
                   └──────────────────────────────────────────┘
```

**Key design rule:** `rustre-debug` (the hub) must **not** depend on any `rustre-debug-*`
sub-crate (which all depend on it), to avoid workspace dependency cycles. Aggregation lives
exclusively in `rustre-debug-registry`.

---

## 2. `rustre-debug` — Core Trait Hub

| Item | Value |
|------|-------|
| Path | `crates/rustre-debug/` |
| Source files | 15 |
| External deps | `async-trait`, `tokio`, `thiserror`, `parking_lot`, `serde`, `serde_json`, `tracing` |
| Intra-workspace deps | `rustre-core`, `rustre-mem` |
| Status | **Complete** (pure trait/type definitions, no OS calls) |

### 2.1 Public Types

| Type | Description |
|------|-------------|
| `DebugError` | 11-variant enum covering attach/bp/memory/register/OS/timeout/permission errors |
| `ProcessId(u32)` | Newtype process identifier |
| `ThreadId(u32)` | Newtype thread identifier |
| `RegisterSet` | Architecture-agnostic register snapshot: `HashMap<String, u64>` + `pc`, `sp`, `fp`, `lr` |
| `Breakpoint` | Address + `BreakpointKind` + enabled flag + hit count + condition + label |
| `BreakpointKind` | `Software` / `Hardware` / `DataRead` / `DataWrite` / `DataReadWrite` |
| `StopReason` | 12-variant enum: `Breakpoint`, `SingleStep`, `Signal`, `Exception`, `ProcessExit`, `ThreadCreate`, `ThreadExit`, `LibraryLoad`, `LibraryUnload`, `ProcessCreate`, `AccessViolation`, `Unknown` |
| `DebugEvent` | `(pid, tid, reason, timestamp_ns)` — monotonic nanoseconds via `OnceLock<Instant>` |
| `MemoryMap` | One virtual memory region: base, size, rwx, name, file path, file offset |
| `ModuleInfo` | Loaded library: name, path, base, size, entry point, is_main flag |
| `LaunchOptions` | Executable path, args, env, working_dir, stop_at_entry, follow_forks, redirect |
| `StackFrame` | Frame index, pc, sp, fp, function name, module, offset, source file/line |
| `DebugSession` | `Arc<RwLock<Inner>>` shared state: PID, current TID, breakpoints map, modules list, events log |

### 2.2 `Debugger` Trait

```rust
#[async_trait::async_trait]
pub trait Debugger: Send + Sync {
    fn name(&self) -> &str;
    fn supported_architectures(&self) -> Vec<String>;

    // Process lifecycle
    async fn launch(&self, opts: LaunchOptions) -> Result<ProcessId, DebugError>;
    async fn attach(&self, pid: ProcessId) -> Result<(), DebugError>;
    async fn detach(&self) -> Result<(), DebugError>;
    async fn kill(&self) -> Result<(), DebugError>;
    fn is_attached(&self) -> bool;
    fn target_pid(&self) -> Option<ProcessId>;

    // Execution control
    async fn continue_execution(&self) -> Result<DebugEvent, DebugError>;
    async fn single_step(&self, tid: ThreadId) -> Result<DebugEvent, DebugError>;
    async fn step_over(&self, tid: ThreadId) -> Result<DebugEvent, DebugError>;
    async fn step_out(&self, tid: ThreadId) -> Result<DebugEvent, DebugError>;
    async fn pause(&self) -> Result<(), DebugError>;

    // Thread management
    async fn threads(&self) -> Result<Vec<ThreadId>, DebugError>;
    async fn current_thread(&self) -> Result<ThreadId, DebugError>;

    // Registers
    async fn get_registers(&self, tid: ThreadId) -> Result<RegisterSet, DebugError>;
    async fn set_registers(&self, tid: ThreadId, regs: RegisterSet) -> Result<(), DebugError>;
    async fn get_register(&self, tid: ThreadId, name: &str) -> Result<u64, DebugError>;
    async fn set_register(&self, tid: ThreadId, name: &str, value: u64) -> Result<(), DebugError>;

    // Memory
    async fn read_memory(&self, addr: Address, size: usize) -> Result<Vec<u8>, DebugError>;
    async fn write_memory(&self, addr: Address, data: &[u8]) -> Result<usize, DebugError>;
    async fn memory_maps(&self) -> Result<Vec<MemoryMap>, DebugError>;

    // Breakpoints
    async fn set_breakpoint(&self, addr: Address, kind: BreakpointKind) -> Result<(), DebugError>;
    async fn remove_breakpoint(&self, addr: Address) -> Result<(), DebugError>;
    async fn enable_breakpoint(&self, addr: Address) -> Result<(), DebugError>;
    async fn disable_breakpoint(&self, addr: Address) -> Result<(), DebugError>;
    async fn breakpoints(&self) -> Result<Vec<Breakpoint>, DebugError>;

    // Modules & stack
    async fn modules(&self) -> Result<Vec<ModuleInfo>, DebugError>;
    async fn backtrace(&self, tid: ThreadId) -> Result<Vec<StackFrame>, DebugError>;
}
```

### 2.3 Modules

| Module | Purpose |
|--------|---------|
| `cross_platform_debug` | Cross-platform helpers for the Debugger trait |
| `expression_evaluator` | Debug expression evaluation (watch windows, conditions) |
| `source_map` | Source-level mapping (DWARF paths, line numbers) |
| `debug_session_manager` | `DebugSessionManager`, `SessionPool`, `SessionEvent`, `DebugTarget` (pid/process/remote/core) |
| `multi_target_debugger` | Multiplexed debugging of multiple simultaneous targets |
| `watchpoint_engine` | DR0–DR3 (x86), DBGWVR/DBGWCR (ARM64), software page-protect fallback, conditional/one-shot/counting watchpoints |
| `time_travel_debug` | Step-backward, reverse-continue, snapshot-based simulation, `rustre-ttd` hook |
| `memory_layout_view` | Heap chunk enumeration (ptmalloc2/jemalloc/tcmalloc/NT heap), stack unwinding, ASLR offset view, guard-page detection |
| `debugger_event_loop` | Async event dispatch loop |
| `register_context` | Register context save/restore |
| `memory_search` | Pattern scanning over process memory |
| `conditional_breakpoint` | Condition evaluation for breakpoints |
| `watchpoint_manager` | High-level watchpoint lifecycle manager |
| `debug_session_recorder` | Session playback/recording |

### 2.4 Utility

```rust
pub async fn with_timeout<F, T>(dur: Duration, fut: F) -> Result<T, DebugError>
```
Wraps any `Debugger` future in a `tokio::time::timeout`; returns `DebugError::Timeout` on expiry.

---

## 3. `rustre-debug-registry` — Composition Crate

| Item | Value |
|------|-------|
| Path | `crates/rustre-debug-registry/` |
| Source files | 1 (single `lib.rs`) |
| Intra-workspace deps | `rustre-debug` + all 8 backend crates |
| Status | **Complete** — thin wiring crate only |

Sole export:

```rust
pub fn all() -> Vec<Box<dyn Debugger>> {
    vec![
        Box::new(FridaDebugSession::default()),
        Box::new(GdbDebugger::default()),
        Box::new(KgdbSession::default()),
        Box::new(LinuxDebugger::default()),
        Box::new(MacosDebugger::default()),
        Box::new(UnicornDebugger::default()),
        Box::new(WinDbgSession::default()),
        Box::new(WindowsDebugger::default()),
    ]
}
```

This is the canonical entry point for any consumer (MCP server, UI, CLI) that wants to
enumerate available debugger backends. The `registry` module inside `rustre-debug` itself is
permanently disabled via `#[cfg(any())]` to avoid the cycle; this sibling crate is the
correct place.

---

## 4. `rustre-debug-windows` — Win32 Debugger Backend

| Item | Value |
|------|-------|
| Path | `crates/rustre-debug-windows/` |
| Source files | 11 |
| External deps | `windows-sys 0.59` (Win32 Debug, Threading, Memory, ProcessStatus, ToolHelp, Security, LibraryLoader), `ahash`, `parking_lot` |
| Intra-workspace deps | `rustre-debug`, `rustre-core`, `rustre-sysinternals` |
| Platform gate | `#[cfg(windows)]` on all real implementations; non-Windows returns `DebugError::Unsupported` |
| `unsafe` policy | `unsafe_code = "allow"` at package level (raw Win32 FFI: `ReadProcessMemory`, `WaitForDebugEvent`, `DebugActiveProcess`, etc.) |
| Status | **Partial** — Win32 API calls are real on Windows; non-Windows stubs return `Unsupported` |

### 4.1 Modules

| Module | Contents |
|--------|----------|
| `win32_debug_api` | Raw Win32 debug API wrappers with safe helpers |
| `windows_internals` | PEB/TEB parser, `HeapEntry`/`walk_heap`, `CriticalSection`, `HandleTable`, `ExceptionRecord`, `ContextRecord` (x86/x64/ARM64), `LoadedModuleList` |
| `win_exception_handler` | SEH classification, first/second-chance, SEH chain unwind, VEH, per-code filters |
| `win_heap_debug` | PageHeap (full/light), `HeapWalk` enumeration, corruption detection (double-free, overflow, UAF, header check), HPDA |
| `win_module_events` | DLL load/unload notifications, rebase detection, IAT hook scan, PE section mapping, PE anomaly detection |
| `debug_event_handler` | Typed debug event kinds and per-event metadata (supersedes thin `DebugEventDecoder`) |
| `pe_loader_simulation` | Pure-Rust PE section mapping, base relocation, IAT patching, TLS callbacks (static analysis, no live process) |
| `process_memory_api` | `VirtualQueryEx`/`ReadProcessMemory`/`WriteProcessMemory` wrappers; `PageState`, `PageType`, `PageProtection` enums |
| `process_memory_scanner` | AOB/pattern scan (exact, masked, wildcard `"48 8B ? ? 90 CC"`) over process memory |
| `win_symbol_resolver` | PE export-table walker, RSDS/CodeView PDB path extractor, symbol cache for `backtrace()` |

### 4.2 Key Types

```rust
pub struct WindowsDebugger { ... }  // implements Debugger

pub enum WindowsDebugError {
    Win32(u32, String),
    InvalidHandle,
    AccessDenied,
    NotInitialized,
}

// PAGE_* constants defined unconditionally (tests build cross-platform)
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_GUARD: u32 = 0x100;
```

### 4.3 Implementation Status

On Windows: `DebugActiveProcess`, `WaitForDebugEvent`, `ReadProcessMemory`, `GetThreadContext`,
`FormatMessageW` are called directly. Non-Windows fallback methods return
`DebugError::Unsupported("Windows only")`. The Win32 API surface is extensive but some
advanced methods (e.g., `step_over`, `step_out` logic) delegate their full implementation
to the `DebugSession` state machine rather than native single-step traps. **Status: partial**
— basic attach/detach/breakpoints/read-write are real; advanced stepping may be simulated.

---

## 5. `rustre-debug-linux` — ptrace Backend

| Item | Value |
|------|-------|
| Path | `crates/rustre-debug-linux/` |
| Source files | 12 |
| External deps | `nix 0.29` (ptrace, signal, process), `bitflags`, `tracing` |
| Platform gate | `#[cfg(target_os = "linux")]` on real code |
| Status | **Partial** — real `ptrace` calls on Linux; `Unsupported` on other targets |

### 5.1 Modules

| Module | Contents |
|--------|----------|
| `breakpoint_manager` | Software INT3 breakpoint lifecycle |
| `coredump` | Core dump generation/analysis |
| `perf_events` | Linux perf_event counter integration |
| `syscall_tracer` | `PTRACE_SYSCALL` entry/exit interception |
| `ptrace_advanced` | `PTRACE_SINGLEBLOCK` BB-tracing, `PTRACE_GET_SYSCALL_INFO`, seccomp BPF inspection, fork/clone/exec tracking |
| `perf_event_debug` | PMU counters during debug, PEBS/IPEA precise-IP sampling, per-step counter snapshots |
| `proc_fs_reader` | `/proc/<pid>/` reader: ProcState, FdInfo, kallsyms |
| `elf_coredump_parser` | `PT_LOAD`/`PT_NOTE` segment walk, `NT_PRSTATUS` register extraction, `NT_FILE` decoded, 32/64-bit LE/BE |
| `linux_signal_handler` | `SignalNumber` enum, `SigInfo`, signal classification |
| `ptrace_wrapper` | Typed `ptrace(2)` API, `PtraceRequest` enum, wait-status decoding |
| `ptrace_engine` | Alternative `PtraceEngine` with own error type and arch enum |

### 5.2 Notable Type

```rust
pub struct ProcMapsParser;

impl ProcMapsParser {
    pub fn parse(content: &str) -> Vec<MemoryMap>;
    pub fn parse_line(line: &str) -> Option<MemoryMap>;
}
```

Parses `/proc/<pid>/maps` lines (format: `addr-addr perms offset dev inode [path]`) into
`MemoryMap` entries used by `memory_maps()`. This is one of the few fully implemented,
testable pieces that does not require a live process.

### 5.3 `LinuxDebugger`

On Linux: `nix::sys::ptrace` calls drive attach/detach/step. On non-Linux: all async methods
return `DebugError::Unsupported`. Tests verify `launch_returns_unsupported_on_non_linux`.

---

## 6. `rustre-debug-macos` — Mach Port Backend

| Item | Value |
|------|-------|
| Path | `crates/rustre-debug-macos/` |
| Source files | 16 |
| External deps | `libc 0.2` (macOS only) |
| Platform gate | `#[cfg(target_os = "macos")]` |
| Status | **Partial** — Mach port structures defined; actual `task_for_pid` / `mach_vm_read` calls behind platform gate |

### 6.1 Modules

| Module | Contents |
|--------|----------|
| `mach_debugger` | Core Mach task debugger |
| `mach_port_debug` | Mach port manipulation for debugging |
| `mach_port_manager` | Port lifecycle (send/recv rights, port sets) |
| `mach_vm` | `mach_vm_read`/`mach_vm_write`/`mach_vm_protect` wrappers |
| `mach_exception_handler` | Mach exception port registration and dispatch |
| `exception_ports` | Exception port setup and delegation |
| `ios_debugger` | iOS-specific debugging over Mach (simulator and device) |
| `lldb_compat` | LLDB compatibility layer (register index mapping) |
| `lldb_integration` | LLDB protocol/RPC integration hooks |
| `dsym_reader` | `.dSYM` bundle reader for symbol resolution |
| `dtrace_integration` | DTrace provider/probe activation |
| `dtrace_probe_manager` | DTrace probe lifecycle |
| `dyld_debugger` | `dyld` shared-library event tracking |
| `dyld_info` | `dyld_info` command output parser |
| `macos_crash_analyzer` | Crash log (`.crash`/`ips`) parser and analyzer |

### 6.2 Shared Types (all targets)

```rust
pub struct BreakpointManager { pub breakpoints: HashMap<u64, u8> }
pub struct MacosProcess { pub pid: ProcessId, pub task_port: u32, pub thread_ports: Vec<u32> }
pub enum MacosArch { X86_64, Arm64 }
pub struct MacosRegisterSet;
impl MacosRegisterSet {
    pub fn x86_64_index(name: &str) -> Option<usize>;   // thread-state array index
    pub fn arm64_index(name: &str) -> Option<usize>;
}
```

The register name→index tables (`rax`→0, `rbx`→1, … matching `x86_THREAD_STATE64`) are
complete and platform-independent.

---

## 7. `rustre-debug-gdb` — GDB Remote Serial Protocol

| Item | Value |
|------|-------|
| Path | `crates/rustre-debug-gdb/` |
| Source files | 16 |
| External deps | `tokio` (TCP I/O) |
| Status | **Partial-to-Complete** — RSP framing and most commands implemented; some vFile/qXfer paths return `Unsupported` |

### 7.1 Architecture (from crate doc)

```
GdbDebugger  (implements Debugger trait)
  └─ GdbConnection   (TCP stream + ACK state)
       └─ GdbPacket  (encode / decode  $data#XX)

GdbTargetXml       ← parses target.xml register layout
GdbRegisterCodec   ← encodes/decodes 'g'/'G'/'p'/'P' payloads
GdbStopReplyParser ← parses 'T'/'S'/'W'/'X' stop packets
GdbMemoryOps       ← builds 'm'/'M'/'X' command strings
GdbBreakpointOps   ← builds 'Z'/'z' command strings
```

### 7.2 Modules

| Module | Contents |
|--------|----------|
| `gdb_client` | Async TCP RSP client |
| `gdb_commands` | Command string builders |
| `gdb_mi_parser` | GDB/MI output parser |
| `gdb_remote_target` | Remote target abstraction |
| `gdb_rsp_extensions` | Extended RSP: qXfer, vFile, qRcmd, qSupported, QPassSignals, QCatchSyscalls; `RspEncoder`/`RspDecoder` |
| `gdb_value_formatter` | Value pretty-printing |
| `gdb_python_api` | GDB Python API bridge |
| `gdb_session` | `GdbSession`, `GdbTarget`, `GdbBreakpoint`, `GdbWatchpoint`, `GdbFrame`, `GdbThread`, `GdbVariable`, `SessionLog` |
| `xml_target_desc` | GDB XML target description parse/render; built-in targets for i386/x86-64/arm/aarch64/mips |
| `gdb_thread_manager` | Thread enumeration and focus management |
| `gdb_breakpoint_manager` | ID-based breakpoints with conditions, ignore counts, catchpoints |
| `gdb_packet_protocol` | Complete RSP packet layer with RLE, command builders, decoders |
| `gdb_register_set` | Per-architecture canonical register set definitions |
| `gdb_symbol_lookup` | MI-based symbol index with glob search, completion, demangling |
| `remote_target` | Multi-transport target with feature negotiation and flash write |

### 7.3 Error Type

```rust
pub enum GdbRspError {
    BadChecksum { expected: u8, got: u8 },
    FramingError(String),
    ConnectionError(String),
    UnsupportedCommand(String),
    TargetError(String),
    Timeout,
    Io(String),
}
impl From<GdbRspError> for DebugError { ... }
```

### 7.4 Notable Detail — `unsafe` Usage

`GdbPacket::escape_data` uses `String::from_utf8_unchecked` because RSP wire data is
byte-oriented and may contain bytes ≥ 0x80 after escaping. `from_utf8` would fail;
`from_utf8_lossy` would corrupt them. This is the single unsafe block; `#![allow(unsafe_code)]`
is declared at crate level with explicit justification in the doc comment.

---

## 8. `rustre-debug-windbg` — WinDbg / DbgEng Simulation

| Item | Value |
|------|-------|
| Path | `crates/rustre-debug-windbg/` |
| Source files | 16 |
| External deps | `byteorder 1.5`, `windows-sys 0.59` (debug/thread/memory; Windows only) |
| Status | **Simulated** — "No actual Windows APIs are used — all state is simulated in Rust" (doc comment) |

### 8.1 Modules

| Module | Contents |
|--------|----------|
| `windbg_command_parser` | WinDbg command string parser |
| `windbg_commands` | Built-in command implementations (dq, db, bp, bl, k, …) |
| `windbg_extensions` | Extension DLL simulation (!analyze, !heap, !locks, …) |
| `windbg_script_runner` | Script execution engine |
| `windbg_scripting` | Scripting API surface |
| `winext_api` | `IDebugControl`/`IDebugSymbols` method simulation |
| `windbg_kd_protocol` | Kernel debug KD protocol packets |
| `kdump_analyzer` | `.dmp` kernel crash dump analysis |
| `windbg_extension_api` | Extension API traits |
| `windbg_command_runner` | Async command dispatch |
| `windbg_stack_walker` | Stack unwind simulation |
| `windbg_heap_analyzer` | Heap corruption analysis |
| `crash_dump_analyzer` | User-mode crash dump analysis |
| `minidump` | Minidump format reader |

### 8.2 Key Types

```rust
pub struct WinDbgSession { ... }  // implements Debugger

pub enum WinDbgError {
    DbgEngError(String),
    NotInitialized,
    CommandError(String),
    SymbolError(String),
    Debug(#[from] DebugError),
}

pub enum ExecutionStatus {
    Break, Go, StepOver, StepInto, StepBranch, Reverse, NoDebuggee
}

pub struct DbgModule {
    pub name: String, pub base: u64, pub size: u64,
    pub timestamp: u32, pub checksum: u32, pub path: String,
}
```

Because `WinDbgSession` is entirely in-memory, it is fully cross-platform and testable on
Linux/macOS. The simulation is useful for testing WinDbg command parsers and script logic
without a Windows machine.

---

## 9. `rustre-debug-kgdb` — Linux Kernel Debugger

| Item | Value |
|------|-------|
| Path | `crates/rustre-debug-kgdb/` |
| Source files | 18 |
| External deps | `hex`, `serde_json` |
| Status | **Simulated** — "models the GDB RSP packet exchange a real KGDB connection would perform" |

### 9.1 Modules

| Module | Contents |
|--------|----------|
| `kd_protocol` | KD protocol packet definitions |
| `kernel_modules` | Kernel module enumeration (`/proc/modules` parser) |
| `windbg_kd` | WinDbg KD protocol compatibility |
| `kgdb_protocol` | KGDB GDB RSP transport |
| `kernel_symbols` | `/proc/kallsyms` reader |
| `kernel_memory` | Kernel memory access (physical/virtual) |
| `kernel_struct_parser` | `dt`-equivalent: EPROCESS/ETHREAD/PEB/TEB/KPCR/KPRCB parser |
| `kernel_debugging` | Kernel debug session management |
| `kernel_structures` | Windows EPROCESS (Win7/Win10/Win11), ETHREAD, DRIVER_OBJECT, DEVICE_OBJECT, TOKEN, ACCESS_TOKEN |
| `kernel_memory_reader` | Safe kernel memory read abstraction |
| `kgdb_breakpoint_manager` | Kernel breakpoint lifecycle |
| `kgdb_packet_handler` | GDB RSP packet receive/send |
| `kernel_symbol_resolver` | Symbol lookup from kallsyms |
| `kgdb_watchpoint` | Kernel hardware watchpoints |
| `kgdb_memory_access` | Kernel memory read/write operations |
| `kgdb_register_access` | Register get/set in kernel context |
| `kgdb_thread_enumerator` | Kernel thread enumeration |

### 9.2 `GdbPacket` (local copy)

KGDB has its own `GdbPacket` (independent of `rustre-debug-gdb`'s) implementing the same
`$data#XX` framing with a clean `parse()` / `to_wire()` split and checksum verification:

```rust
pub struct GdbPacket { pub data: String, pub checksum: u8 }

impl GdbPacket {
    pub fn new(data: String) -> Self;
    pub fn to_wire(&self) -> String;    // "$data#XX"
    pub fn parse(raw: &str) -> Result<Self, KgdbError>;
}
```

---

## 10. `rustre-debug-frida` — Frida Dynamic Instrumentation

| Item | Value |
|------|-------|
| Path | `crates/rustre-debug-frida/` |
| Source files | 12 |
| Features | `frida-gum` (optional) — enables `frida-gum-sys 0.14` with `auto-download` |
| Platform deps | `nix 0.29` on Unix (ptrace/signal for fallback injection) |
| Status | **Simulated** by default; `frida-gum-sys` FFI available behind feature flag |

### 10.1 Modules

| Module | Contents |
|--------|----------|
| `frida_agent` | Agent lifecycle (inject, resume, detach) |
| `frida_scripts` | JS script generation: `FridaScriptBuilder`, `HookScript`, `MemoryScanScript`, `StalkerScript`, `AntiAntiDebugScript`, 30+ `ScriptTemplates`, `ScriptOptimizer` |
| `frida_stalker` | Stalker code-coverage integration |
| `stalker_engine` | Pure-Rust binary tracing: block/call/return/exec callbacks, self-modifying code detection, JIT region tracking, exclude ranges, call-graph, BB heat maps |
| `interceptor_engine` | Prolog/epilog hooking, argument inspection, return-value modification, function replacement, `NativeFunction`/`NativeCallback`, transaction support |
| `memory_patcher` | Byte-level writes with permission management, NOP fill, jump/call redirection (x86/ARM64), ret insertion, undo/redo stack, scan-and-patch |
| `frida_script_builder` | Fluent script builder |
| `frida_rpc_client` | Frida RPC call client |
| `frida_trace_analyzer` | Trace data analysis |
| `frida_message_handler` | Frida `send`/`recv` message dispatch |
| `frida_stalker_controller` | Stalker start/stop/pause |

### 10.2 Key Types

```rust
pub struct FridaDebugSession { ... }  // implements Debugger

pub struct FridaHook {
    pub address: u64,
    pub script: String,
    pub hook_id: u64,
}

pub struct InterceptorRecord {
    pub hook_id: u64, pub address: u64, pub thread_id: u32,
    pub args: Vec<u64>, pub return_value: Option<u64>,
}
```

`FridaDebugSession` also exposes `install_hook(address, script) -> hook_id` beyond the base
`Debugger` trait.

---

## 11. `rustre-debug-unicorn` — Unicorn Emulation Debugger

| Item | Value |
|------|-------|
| Path | `crates/rustre-debug-unicorn/` |
| Source files | 17 |
| External deps | `anyhow`, `bitflags` |
| Status | **Simulated** — pure-Rust model of Unicorn API, no FFI |

This crate wraps the `rustre-emu` emulation layer and presents it as a `Debugger`
implementation. It is the bridge between the debug subsystem and the emulation subsystem.

### 11.1 Modules

| Module | Contents |
|--------|----------|
| `emulation_session` | Unicorn emulation session lifecycle |
| `hook_manager` | Typed hook dispatch |
| `memory_map_builder` | Helper for building memory maps for emulation |
| `os_emu_hooks` | OS API hooks during emulation |
| `unicorn_engine_wrapper` | Thin safe wrapper over the emulator API |
| `unicorn_extended` | Extended emulation capabilities |
| `unicorn_hooks` | Code/memory/interrupt hook types |
| `unicorn_memory_map` | Memory region management |
| `unicorn_snapshot` | State snapshot/restore |
| `unicorn_api_hooks` | `ApiHookLibrary` for libc/kernel32/ntdll; `MockLibcHooks` (malloc/free/strlen/memcpy/printf), `MockKernel32Hooks` (VirtualAlloc/LoadLibrary/GetProcAddress) |
| `unicorn_debugger` | `UnicornDebugger` struct |
| `unicorn_breakpoint_manager` | Breakpoint lifecycle within the emulator |
| `unicorn_call_tracer` | Function call trace recording |
| `unicorn_memory_inspector` | Memory state inspection |
| `unicorn_register_inspector` | Register dump utilities |
| `unicorn_code_coverage` | Code coverage bitmap |

### 11.2 Arch Enum

```rust
pub enum UnicornArch {
    X86_64, X86_32, Arm, Arm64, Mips, Mips64, Riscv32, Riscv64
}
```

### 11.3 MemRegion

```rust
pub struct MemRegion {
    pub addr: u64,
    pub size: u64,
    pub readable: bool, pub writable: bool, pub executable: bool,
}
```

---

## 12. `rustre-emu` — Emulation Framework Hub

| Item | Value |
|------|-------|
| Path | `crates/rustre-emu/` |
| Source files | 17 |
| External deps | `thiserror`, `serde`, `serde_json`, `bitflags` |
| Intra-workspace deps | `rustre-mem` |
| Status | **Partial-to-Complete** — `Emulator` trait complete; `SimpleInterpreter` (x86) partially implemented |

### 12.1 `EmulatorArch`

```rust
pub enum EmulatorArch {
    X86_16, X86_32, X86_64,
    Arm, ArmThumb, Arm64,
    Mips32, Mips64, Mips32El,
    RiscV32, RiscV64,
    Sparc32, Sparc64,
}
impl EmulatorArch {
    pub const fn pointer_size(self) -> usize;
    pub const fn name(self) -> &'static str;
    pub const fn is_64bit(self) -> bool;
    pub const fn is_x86(self) -> bool;
}
```

### 12.2 `MemPerms`

```rust
bitflags! {
    pub struct MemPerms: u32 {
        const READ  = 1;
        const WRITE = 2;
        const EXEC  = 4;
        const ALL   = 7;
    }
}
// Aliases: R, W, X, RW, RX, RWX
```

### 12.3 `Emulator` Trait

```rust
pub trait Emulator: Send + Sync {
    fn arch(&self) -> EmulatorArch;
    fn map_memory(&mut self, addr: u64, size: usize, perms: MemPerms) -> Result<(), EmulatorError>;
    fn unmap_memory(&mut self, addr: u64) -> Result<(), EmulatorError>;
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), EmulatorError>;
    fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>, EmulatorError>;
    fn read_register(&self, reg: u32) -> Result<u64, EmulatorError>;
    fn write_register(&mut self, reg: u32, value: u64) -> Result<(), EmulatorError>;
    fn start(&mut self, begin: u64, until: u64, timeout_ms: u64, count: u64) -> Result<(), EmulatorError>;
    fn stop(&mut self) -> Result<(), EmulatorError>;
    fn add_code_hook(&mut self, begin: u64, end: u64, callback: Box<dyn Fn(u64, u32) + Send + Sync>) -> Result<HookHandle, EmulatorError>;
    fn add_mem_hook(&mut self, kind: HookKind, callback: Box<dyn Fn(u64, usize, u64) + Send + Sync>) -> Result<HookHandle, EmulatorError>;
    fn remove_hook(&mut self, handle: HookHandle) -> Result<(), EmulatorError>;
    fn context_save(&self) -> Result<Vec<u8>, EmulatorError>;
    fn context_restore(&mut self, ctx: &[u8]) -> Result<(), EmulatorError>;
    fn regions(&self) -> Vec<MemRegion>;
}
```

### 12.4 `EmulatorBackend` Factory Trait

```rust
pub trait EmulatorBackend: Send + Sync {
    fn name(&self) -> &str;
    fn supported_arches(&self) -> Vec<EmulatorArch>;
    fn create(&self, arch: EmulatorArch) -> Box<dyn Emulator>;
}
```

### 12.5 `SimpleInterpreter` (inline x86 interpreter)

A pure-Rust x86/x86-64 interpreter is embedded in `lib.rs`. It implements a partial x86
instruction set via `step_x86`, `step_x86_arith`, `step_x86_cmp`, `step_x86_cf`,
`step_x86_two_byte`, `step_x86_push_reg`, `step_x86_pop_reg`, `step_x86_mov_imm32`. This
is sufficient for shellcode analysis but is not a full ISA.

### 12.6 Modules

| Module | Contents |
|--------|----------|
| `arm_interpreter` | Pure-Rust ARM Thumb/Thumb-2 interpreter |
| `mips_interpreter` | Pure-Rust MIPS32 (LE/BE) interpreter |
| `os_emulation` | Linux x86-64 + Windows x86-64 syscall emulation |
| `os_syscall_model` | Syscall number tables |
| `fuzzing_integration` | AFL-style coverage bitmap, corpus management, snapshot-reset fuzz loop, coverage-guided random mutator |
| `taint_emulation` | Taint-tracking wrapper for any `Emulator` impl |
| `heap_emulator` | Guest heap allocator simulation (malloc/free) |
| `jit_compiler` | JIT stub (framework, not a real JIT) |
| `library_stub` | Stub shared library simulation for import resolution |
| `structured_execution` | Structured execution tracing |
| `syscall_emulation` | Syscall dispatch table |
| `emu_device_model` | Virtual device model (MMIO) |
| `emu_interrupt_controller` | Interrupt/exception dispatch |
| `emu_execution_statistics` | Instruction counts, coverage statistics |
| `backends_registry` | Enumerate registered `EmulatorBackend` implementations |
| `mem_provider` | `EmuMemoryProvider`, `EmuVirtualMemoryProvider`, `EmuCompositeMemoryProvider` |

### 12.7 Memory Provider Traits (re-exported)

```rust
pub use mem_provider::{
    EmuCompositeMemoryProvider,
    EmuMemoryProvider,
    EmuVirtualMemoryProvider,
};
```

---

## 13. `rustre-emu-unicorn` — Unicorn Engine Wrapper

| Item | Value |
|------|-------|
| Path | `crates/rustre-emu-unicorn/` |
| Source files | 19 |
| Features | `native` (off by default) — enables real `libunicorn` FFI; without it, no-op stubs compile |
| Note | `unicorn-engine = "2"` is commented out in Cargo.toml; `native` feature enables FFI bindings |
| Status | **Simulated** by default; `native` feature enables real emulation |

### 13.1 Arch/Mode Enums

```rust
pub enum Arch { X86, Arm, Arm64, Mips, Sparc, RiscV, M68K, Ppc, S390X }
pub enum Mode {
    X86_16, X86_32, X86_64,
    ArmMode, ThumbMode, Arm64Mode,
    Mips32LE, Mips32BE, Mips64LE, Mips64BE,
    Sparc32, Sparc64, RiscV32, RiscV64,
    M68K, Ppc32, Ppc64, S390X,
}
impl Mode {
    pub const fn ptr_size(&self) -> usize;
    pub const fn is_little_endian(&self) -> bool;
}
```

### 13.2 Error Type

```rust
pub enum UnicornEmuError {
    InvalidMemoryAccess { addr: u64, size: usize },
    UnmappedMemory { addr: u64 },
    MemoryAlreadyMapped { addr: u64, size: usize },
    InvalidInstruction { addr: u64 },
    HookAlreadyExists(HookId),
    HookNotFound(HookId),
    InvalidArchMode,
    Timeout,
    SyscallError(String),
    ApiHookError(String),
    ContextSaveError(String),
    EmulationError(String),
    AllocError(String),
    OsError(String),
    IoError(String),
}
```

### 13.3 Modules

| Module | Contents |
|--------|----------|
| `unicorn_bindings` | C API stubs / safe wrappers (`native` feature for real FFI) |
| `hook_manager` | Typed hook dispatch with priority + reentrancy guard |
| `os_hooks` | Linux & Windows syscall emulation |
| `arch_backends` | Per-architecture register tables + `UcArchBackend` trait |
| `arch_register_maps` | x86/ARM/MIPS/etc. register name→ID maps |
| `coverage_hooks` | AFL bitmap, block/edge maps, drcov export |
| `instruction_trace` | Instruction-level trace recording |
| `memory_model` | Virtual memory management |
| `unicorn_arch_support` | Arch-specific helpers |
| `snapshot_manager` | Context save/restore |
| `unicorn_coverage` | Coverage data collection |
| `unicorn_os_hooks` | OS-level hook wiring |
| `unicorn_hooks` | Hook type definitions |
| `unicorn_os_emulator` | OS emulator combining syscall + memory model |
| `unicorn_snapshot` | Full emulator snapshot |
| `unicorn_context_manager` | Context lifecycle |
| `unicorn_filesystem_emu` | Guest filesystem simulation |
| `unicorn_syscall_linux` | Linux syscall implementations |

---

## 14. `rustre-emu-qiling` — Qiling-Inspired OS Emulation Layer

| Item | Value |
|------|-------|
| Path | `crates/rustre-emu-qiling/` |
| Source files | 15 |
| External deps | `anyhow`, `serde_json` |
| Intra deps | `rustre-emu` |
| Status | **Partial** — comprehensive type system and module skeleton; syscall dispatch partially implemented |

### 14.1 Architecture

`QilingEmulator` wraps a `rustre-emu` `Emulator` (accessed via trait object) and layers:
- **Rootfs sandboxing** (`RootfsPath`) — guest-to-host path translation with dot-dot rejection
- **Syscall dispatch** (`SyscallTable`) — per-OS/arch handler map
- **File descriptor table** (`FdTable`) — guest open files
- **Process environment** (`ProcessEnv`) — argv, envp, auxiliary vectors
- **Binary loader** (`BinaryLoader` / `ElfLoaderStub`) — ELF/PE placement into guest memory

### 14.2 Key Types

```rust
pub enum OsTarget { Linux, Windows, MacOs, FreeBsd, BareMetal }
pub enum EmulationMode { Full, Partial, None }

pub struct RootfsPath { root: PathBuf }
impl RootfsPath {
    pub fn new(root: impl Into<PathBuf>) -> Self;
    pub fn host_path(&self, path: &str) -> PathBuf;  // dot-dot safe
    pub fn exists(&self, path: &str) -> bool;
}
```

### 14.3 Modules

| Module | Contents |
|--------|----------|
| `os_syscall_emu` | Syscall number tables + handler dispatch |
| `qiling_analysis` | Post-execution analysis |
| `qiling_backend` | `QilingEmulator` struct |
| `qiling_memory` | Memory management integration |
| `qiling_coverage` | Coverage data |
| `qiling_result_parser` | Execution result parsing |
| `qiling_script_gen` | Script generation for Qiling Python interop |
| `rootfs_manager` | Rootfs setup/teardown |
| `fs_manager` | File system operation interception |
| `os_posix_emulation` | POSIX syscall implementations |
| `qiling_hook_manager` | Hook lifecycle |
| `qiling_posix` | POSIX-specific emulation |
| `qiling_windows` | Windows ABI emulation |

Re-exports from `rustre-emu`: `CoverageMap`, `EmuStats`.

---

## 15. `rustre-emu-shellcode` — Sandboxed Shellcode Analyzer

| Item | Value |
|------|-------|
| Path | `crates/rustre-emu-shellcode/` |
| Source files | 18 |
| External deps | none (only `rustre-emu`) |
| Status | **Partial** — type system and module structure complete; emulation delegates to `rustre-emu::SimpleInterpreter` |

### 15.1 Constants

```rust
pub const SHELLCODE_BASE: u64 = 0x0000_1000;
pub const STACK_BASE: u64    = 0x0010_0000;
pub const STACK_SIZE: usize  = 0x0010_0000;  // 1 MB
pub const HEAP_BASE: u64     = 0x0020_0000;
pub const HEAP_SIZE: usize   = 0x0040_0000;  // 4 MB
```

### 15.2 Key Types

```rust
pub struct MemAccess { pub address: u64, pub size: usize, pub value: Vec<u8>, pub pc: u64 }
pub struct ApiCall { pub address: u64, pub name: Option<String>, pub args: Vec<u64>, pub ret: u64 }
pub struct ExecutionLog { pub calls: Vec<ApiCall>, pub memory_reads/writes: Vec<MemAccess>, pub instructions_executed: u64 }
pub enum ExitReason { RetInstruction, MaxInstructions, Timeout, InvalidMemoryAccess, InvalidInstruction }
pub struct ExecutionResult { pub log: ExecutionLog, pub final_regs: HashMap<u32, u64>, pub memory_snapshot: Vec<(u64, Vec<u8>)>, pub exit_reason: ExitReason }

pub struct ShellcodeRunner {
    pub arch: EmulatorArch,
    pub memory_size: usize,
    pub max_instructions: u64,  // default 100_000
    pub timeout_ms: u64,        // default 5_000
}
impl ShellcodeRunner {
    pub const fn new(arch: EmulatorArch) -> Self;
    pub const fn with_max_instructions(self, n: u64) -> Self;
    pub const fn with_timeout_ms(self, ms: u64) -> Self;
}
```

### 15.3 Modules

| Module | Contents |
|--------|----------|
| `api_emulation` | API stub implementation (VirtualAlloc, CreateFile, etc.) |
| `api_resolver_emu` | API hash resolution (common shellcode loaders) |
| `shellcode_analysis` | Pattern detection (XOR loops, hash-based imports, etc.) |
| `shellcode_classifier` | Shellcode family classification |
| `shellcode_decoder` | Decoding loop simulation |
| `shellcode_emulator` | Core emulation entry point |
| `shellcode_heuristics` | Behavioral heuristics (network calls, exec, etc.) |
| `shellcode_loader` | Shellcode loading and relocation |
| `shellcode_tracer` | Instruction-level tracer |
| `x86_emulator` | x86 emulator integration |
| `x86_emulator_hooks` | x86-specific hook implementations |
| `payload_extractor` | Extracted payload data |
| `api_call_tracer` | API call recording |
| `memory_layout_tracker` | Runtime memory layout tracking |
| `shellcode_unpacker` | Packing layer removal |
| `network_behavior_simulator` | Network call simulation (connect/send/recv stubs) |
| `shellcode_report_generator` | Analysis report output |

---

## 16. `rustre-adb` — Android Debug Bridge Client

| Item | Value |
|------|-------|
| Path | `crates/rustre-adb/` |
| Source files | 17 |
| External deps | `bytes`, `tokio`, `serde_json`, `bitflags`, `parking_lot` |
| Status | **Partial-to-Complete** — real async TCP protocol implementation; some advanced features may be stubs |

### 16.1 Protocol Implementation

`rustre-adb` implements the ADB host wire protocol (length-prefixed text commands
`XXXX<cmd>` over TCP to `localhost:5037`) and the low-level USB/transport protocol
(24-byte `AdbMessage` headers). It does **not** wrap the `adb` CLI tool.

```rust
pub const ADB_VERSION: u32 = 0x0100_0000;
pub const ADB_MAX_PAYLOAD: u32 = 256 * 1024;

pub enum AdbError {
    Connection(#[from] std::io::Error),
    Protocol(String),
    DeviceNotFound { serial: String },
    CommandFailed(String),
    Timeout,
    Sync(String),
    LogcatParse(String),
    AuthFailed(String),
}
```

### 16.2 Module Map

| Module | Re-exported key items |
|--------|----------------------|
| `protocol` | `AdbFeature`, `AdbRsaKey`, `AuthType`, `HandshakeDriver`, `HandshakeState`, `LocalId`, `RemoteId`; `build_banner`, `make_auth_*`, `make_connect/open/okay/close/write`, `parse_features`, `read_message`, `write_message` |
| `device` | `DeviceEvent`, `DeviceInfo`, `DeviceList`, `DeviceMonitor`, `DeviceSelector`, `SharedDeviceList`, `TransportType`; `new_shared_device_list`, `parse_devices_output` |
| `shell` | `CommandBuilder`, `ShellOutput`, `ShellSession`, `TerminalSize`, `build_shell_command`, `cmd_am_*`, `cmd_dumpsys`, `cmd_getprop`, `cmd_logcat`, `cmd_pm_*`, `shell_escape` |
| `sync` | `SyncSession`, `DirEntry`, `StatEntry`, `FileType`; `push_file`, `pull_file`, `list_dir`, `stat_file`, `quit_sync` |
| `logcat` | `LogcatReader`, `LogcatFilter`, `LogcatEntry`, `LogcatFormat`, `LogcatStats`, `Priority`; parsers for threadtime/brief/binary formats |
| `package` | `AdbPackageManager`, `PackageDetails`, `PackageFlags`, `InstallLocation`; `parse_pm_list_output`, `parse_pm_dump`, `build_install_command` |
| `adb_protocol` | Low-level message codec |
| `android_shell` | Android-specific shell helpers |
| `device_manager` | Device lifecycle management |
| `file_transfer` | High-level file push/pull API |
| `shell_executor` | Async command execution |
| `adb_file_sync` | Sync protocol helpers |
| `android_package_analyzer` | APK static analysis |
| `logcat_parser` | Extended logcat parsing |
| `apk_installer` | APK install workflow |
| `device_profiler` | Device capability profiling |

### 16.3 Real Implementation Evidence

The following functions accept `&mut TcpStream` and perform real async I/O:

```rust
pub async fn pull_file(stream: &mut TcpStream, remote: &str) -> Result<Vec<u8>>;
pub async fn stat_remote(stream: &mut TcpStream, remote: &str) -> Result<StatEntry>;
pub async fn list_remote_dir(stream: &mut TcpStream, remote: &str) -> Result<Vec<DirEntry>>;
```

RSA authentication (`make_auth_public_key`, `make_auth_signature`, `make_auth_token`) is
defined in `protocol`, indicating the full ADB auth handshake is modelled.

---

## 17. Dependency Graph

```
rustre-core ←─ rustre-debug ←── rustre-debug-{windows,linux,macos,gdb,windbg,kgdb,frida,unicorn}
                                         ↑
rustre-mem  ←─ rustre-debug ←── rustre-debug-registry ──────────────────────────────────┘

rustre-mem  ←─ rustre-emu  ←── rustre-emu-unicorn
                           ←── rustre-emu-qiling
                           ←── rustre-emu-shellcode

rustre-debug-unicorn ──────────── (uses rustre-emu indirectly via its own engine wrapper)

rustre-adb  (standalone, no debug/emu deps)
```

---

## 18. Implementation Status Summary

| Crate | Status | Notes |
|-------|--------|-------|
| `rustre-debug` | **Complete** | Trait/type definitions, no OS calls |
| `rustre-debug-registry` | **Complete** | Single `all()` function wiring |
| `rustre-debug-windows` | **Partial** | Real Win32 on Windows; `Unsupported` fallback elsewhere |
| `rustre-debug-linux` | **Partial** | Real `ptrace`/`nix` on Linux; `Unsupported` elsewhere |
| `rustre-debug-macos` | **Partial** | Mach port types defined; real calls behind `#[cfg(macos)]` |
| `rustre-debug-gdb` | **Partial** | RSP framing complete; some `qXfer`/`vFile` return `Unsupported` |
| `rustre-debug-windbg` | **Simulated** | Pure in-memory state machine, explicitly no Win32 calls |
| `rustre-debug-kgdb` | **Simulated** | Models KGDB RSP exchange; no real serial/network transport |
| `rustre-debug-frida` | **Simulated** | `frida-gum-sys` optional; default build is pure Rust |
| `rustre-debug-unicorn` | **Simulated** | Wraps `rustre-emu` SimpleInterpreter |
| `rustre-emu` | **Partial** | Trait complete; x86 interpreter partial ISA coverage |
| `rustre-emu-unicorn` | **Simulated** | `native` feature off by default (no C library link) |
| `rustre-emu-qiling` | **Partial** | Type system/modules present; syscall dispatch partial |
| `rustre-emu-shellcode` | **Partial** | Module skeleton present; depends on SimpleInterpreter |
| `rustre-adb` | **Partial** | Real async TCP I/O; some advanced features may be stubs |

---

## 19. Known Gaps and Priority Work

1. **`rustre-debug-windows` non-Windows stubs** — Every `Debugger` method on non-Windows
   returns `DebugError::Unsupported("Windows only")`. If cross-platform testing is needed,
   consider adding a simulation mode analogous to `rustre-debug-windbg`.

2. **`rustre-emu-unicorn` native feature** — The `unicorn-engine = "2"` crate is commented
   out; the `native` feature flag exists but `unicorn_bindings` module has no-op stubs by
   default. Wiring in the real FFI requires CMake + C toolchain and is the primary gap for
   real emulation capability.

3. **`SimpleInterpreter` ISA coverage** — The inline x86 interpreter in `rustre-emu` covers
   arithmetic, compare, branches, push/pop, and some two-byte instructions. Full SSE, AVX,
   system instructions, and 32-bit legacy encodings are missing. This limits shellcode
   analysis for modern payloads.

4. **`rustre-debug-frida` real injection** — The `frida-gum` feature is optional and no
   activation path is wired into the MCP server. The `stalker_engine` and `interceptor_engine`
   are pure-Rust simulations that would need to call real Frida GumJS APIs for production use.

5. **`rustre-emu-qiling` syscall completeness** — `os_posix_emulation` and `qiling_windows`
   have many syscall stubs that are not fully implemented. The rootfs and fd-table
   infrastructure is solid but syscall coverage is limited.

6. **`rustre-adb` RSA authentication** — The RSA key generation functions are declared but
   depend on having an RSA key pair available. Integration with Android devices requiring
   host-key approval has not been tested.

7. **`rustre-debug-gdb` `step_over` / `step_out`** — These return `Unsupported` in some
   code paths when the remote stub does not implement `vCont;s` or the response cannot be
   interpreted. A software single-step fallback (compute next-PC, set temp breakpoint) is
   not yet present.

---

## 20. Integration Points with the Broader RE Pipeline

| Subsystem | Integration |
|-----------|-------------|
| `rustre-mcp-server` | Should enumerate `rustre-debug-registry::all()` to expose debugger tools; currently unclear if wired |
| `rustre-ttd` | `time_travel_debug` module in `rustre-debug` declares integration hooks; `rustre-ttd` crate would provide the snapshot backend |
| `rustre-il` / `rustre-decompiler` | `rustre-emu` emulation could drive concolic/taint analysis of lifted IL |
| `rustre-analysis` | `rustre-emu-shellcode::ShellcodeAnalysis` produces reports consumable by the broader analysis layer |
| `rustre-sysinternals` | Re-exported from `rustre-debug-windows` via `pub use rustre_sysinternals` |
| `rustre-mem` | Re-exported from `rustre-debug` via `pub use rustre_mem`; all memory access in debugger backends flows through this |
| Android targets | `rustre-adb` is standalone; an MCP tool layer sitting on top would provide Android RE capabilities |
