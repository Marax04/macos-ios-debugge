# rustre-emu

## Purpose
Multi-architecture CPU emulation and dynamic-analysis framework for the RustRE reverse-engineering platform. Provides interpreters (x86 simple, ARM/Thumb, MIPS32/MIPS32EL), an IL-based JIT compiler, OS/syscall emulation (Linux x86_64, Windows stub, macOS model), structured function-call emulation, taint tracking, heap emulation with vulnerability detection, library function stubs, fuzzing integration (coverage-guided), and a device/interrupt/MMIO model.

Depends on `rustre-mem` for the underlying memory provider abstraction; uses `thiserror`, `serde`, `serde_json`, `bitflags`.

## Public API (signatures, by module)

### `lib.rs` — core abstractions
- `enum EmulatorArch` — supported architectures (X86/ARM/MIPS/etc).
- `struct MemRegion` — base/size/perm descriptor.
- `enum EmulatorError` — top-level error type.
- `enum HookKind`, `struct HookHandle(pub u64)` — hook identity.
- `struct SnapshotId(pub u64)`.
- `trait Emulator: Send + Sync` — central interface (read/write reg & mem, run, step, hook, snapshot).
- `trait EmulatorBackend: Send + Sync` — factory trait for backends.
- `struct EmulatorRegistry` — register/lookup backends by name/arch.
- `struct CpuState` — generic register/PC snapshot.
- `struct SimpleInterpreter` — minimal reference x86-ish interpreter implementing `Emulator`.
- `struct EmulatorFactory` — static constructors.
- `enum ExitReason` — why a `run` stopped.
- `struct MemAccess`, `struct SyscallEntry`, `struct ExecutionResult` — run telemetry.
- `enum OsType`.
- `struct Trace`, `struct EmuStats`, `struct CoverageMap`, `struct EmuCoverageTracker`, `struct CoverageCollector`, `struct MemoryDumper`.
- `trait IoPortHandler`, `struct IoPortMap`.
- `trait MmioDevice`, `struct MmioRegion`, `struct MmioMap`.
- `struct InterruptVector`, `struct InterruptController`.
- `enum ExceptionKind`, `struct CpuException`.
- `trait EmulatedDevice`, `struct NullDevice`.
- `struct RegisterFile`, `struct FlatMemory`.
- `struct SnapshotManager`, `struct EmuSnapshot`, `struct EmuCheckpointManager`.
- `struct TraceEntry`, `struct InsnTrace`.
- `struct CoverageEmu<'a>` — wraps an emulator collecting basic-block coverage.
- `struct EmuSession` — high-level session combining emu + hooks + trace.
- `enum HookAction`, `struct EmuHookManager`.

### `arm_interpreter.rs`
- `struct ArmRegFile` — r0..r15, CPSR.
- `struct ArmThumbInterpreter` — implements `Emulator` for ARM/Thumb.

### `mips_interpreter.rs`
- `struct MipsRegFile`, `struct Mips32Interpreter`, `struct Mips32ElInterpreter(pub Mips32Interpreter)`.
- `const fn encode_rtype(opcode, rs, rt, rd, shamt, funct) -> u32`
- `fn encode_itype(opcode, rs, rt, imm) -> u32`
- `const fn encode_jtype(opcode, target) -> u32`

### `jit_compiler.rs`
- `enum IlOp` — IL opcodes for JIT.
- `struct JitBlock`, `struct JitCache`, `struct JitStats`, `struct JitCodegen`.
- `struct DirectDispatch`, `struct IndirectDispatch`.
- `struct JitCompiler` — IL block compile/execute pipeline with cache.

### `structured_execution.rs`
- `enum StructuredEmuError`, `enum EmuValue` — typed values for arg/return marshalling.
- `enum CallingConvention` — SystemV, MS x64, cdecl, etc.
- `struct MemSnapshot`, `struct MemoryDiff`, `struct ExecTraceEntry`, `struct ExecTrace`.
- `struct LoopDetector`, `struct EmuMemory`, `struct EmuSession`.
- `struct FunctionCallResult`, `struct FunctionEmulator` — call a function with structured args.
- `struct StringEmulator` — high-level string-routine harness.
- `struct TracingEmulator` — wrapping emulator with full trace.

### `os_emulation.rs`
- `enum FdKind`, `struct FdTable`, `struct BumpAllocator`, `struct OsProcess`.
- `enum SyscallResult`.
- `trait OsEmulator: Send + Sync` — dispatch syscalls.
- `struct LinuxX86_64Emulator`, `struct WindowsX86_64Stub`, `struct OsEmuSession`.
- `fn read_cstring(emu: &dyn Emulator, addr: u64) -> Result<String, EmulatorError>`.

### `os_syscall_model.rs`
- `enum SyscallError`, `enum SyscallOs`, `enum SyscallGroup`.
- `struct SyscallInfo`, `struct SyscallArguments`, `struct SyscallResult`.
- Zero-sized tables: `LinuxSyscalls`, `WindowsSyscalls`, `MacOsSyscalls`.
- `struct SyscallDispatch`, `struct SyscallEmulator`, `struct SyscallTrace`, `struct OsSyscallModel`.
- `struct SyscallFilter`, `struct SyscallStats`, `struct SyscallConvention`.
- `struct SyscallInterception`, `struct SyscallInterceptor`, `struct SyscallPatternDetector`.
- `fn linux_syscall_group(name: &str) -> SyscallGroup`.

### `syscall_emulation.rs` (lower-level)
- `enum SyscallError`, `struct RegisterContext`, `struct SyscallEvent`.
- `struct VirtualFile`, `struct VirtualFs`.
- `struct MemoryRegion`, `struct MmapRequest<'a>`, `struct VirtualMemory`.
- `enum SyscallResult`, `struct SyscallEmulator`.
- Helpers: `format_trace(&[SyscallEvent]) -> String`, `syscall_histogram(...) -> HashMap<String,usize>`, `error_syscalls(...) -> Vec<&SyscallEvent>`, `attempted_privilege_escalation(...) -> bool`.

### `taint_emulation.rs`
- `type TaintLabel = u64`.
- `struct TaintSource`, `struct MemTaintMap`, `struct RegTaintMap`.
- `enum TaintEvent`.
- bitflags `TaintPropagationFlags`, `TaintDetectionFlags`, `TaintPolicyFlags`.
- `struct TaintPolicy`, `struct TaintEmulator`, `struct TaintSummary`, `struct TaintReport`.

### `heap_emulator.rs`
- `enum HeapError`, `enum BlockState`, `enum HeapEventType`, `enum HeapErrorKind`, `enum CanaryKind`.
- `struct HeapBlock`, `struct HeapEvent`, `struct HeapState`, `struct HeapEmulator`, `struct HeapVulnerabilityReport`.
- `struct ChunkAllocator`, `struct CanaryManager`, `struct CanaryViolation`.
- `fn visualise_heap(emulator: &HeapEmulator, width: usize) -> String`.

### `fuzzing_integration.rs`
- `struct CorpusEntry`, `struct Corpus`, `struct FuzzCoverage`.
- `type InputInjector = ...` (closure injecting bytes into the emulator).
- `struct FuzzRunResult`, `struct FuzzSession`, `struct Rng(u64)`.
- `enum MutationKind`, `struct Mutator`, `struct CoverageGuidedFuzzer`, `struct FuzzStats`.

### `library_stub.rs`
- `enum StubError`, `enum SideEffect`.
- `struct StubArgs`, `struct StubReturn`, `struct StubLogEntry`.
- `struct VirtualRegistry`, `struct LibraryStubEngine`.
- `const STUBBED_FUNCTIONS: &[&str]`.
- `fn is_stubbed(function: &str) -> bool`, `fn stub_module(function: &str) -> &'static str`.

### `emu_device_model.rs`
- `enum DeviceKind`; `trait EmuDevice: Send + Sync`.
- Devices: `NullDevice`, `RamDevice`, `RomDevice`, `UartDevice`, `TimerDevice`.
- `struct EmuDeviceModel` — registry/bus dispatch.

### `emu_interrupt_controller.rs`
- `enum InterruptState`, `enum InterruptTrigger`, `enum IrqEventKind`.
- `struct InterruptLine`, `struct IrqEvent`, `struct EmuInterruptController`.

### `emu_execution_statistics.rs`
- `struct InsnCount`, `struct BranchStats`, `struct MemAccessStats`, `struct LoopDetector`, `struct StatsReport`, `struct EmuExecutionStatistics`.

### `backends_registry.rs`
- `struct BackendDescriptor { name, arch, ... }`.
- `const ALL: &[BackendDescriptor]`; `const fn all() -> &'static [BackendDescriptor]`; `fn find(name: &str) -> Option<&'static BackendDescriptor>`.

### `mem_provider.rs`
- `struct MemProviderDescriptor`; `const ALL`.
- `fn new_virtual() -> EmuVirtualMemoryProvider`; `fn new_composite() -> EmuCompositeMemoryProvider`; `fn find(name: &str) -> Option<&'static MemProviderDescriptor>`.

## Inputs / Outputs (expected behavior)

- **Construction**: callers pick a backend via `EmulatorRegistry`/`EmulatorFactory` or directly instantiate `SimpleInterpreter`, `ArmThumbInterpreter`, `Mips32Interpreter`. A memory provider (`new_virtual()` / `new_composite()` / `rustre-mem` types) is attached.
- **Loading**: callers map regions (`MemRegion`) with R/W/X perms and write code/data bytes.
- **Execution**: `Emulator::run`/`step` advance PC, returning `ExecutionResult` / `ExitReason`. Hooks (`HookKind`, `EmuHookManager`) intercept code, memory, syscalls and may return `HookAction` to continue/stop/skip.
- **OS layer**: `OsEmulator` impls translate guest syscalls into `SyscallResult`, updating `FdTable`, `VirtualFs`, `VirtualMemory`. Events accumulate in `SyscallTrace`.
- **Structured calls**: `FunctionEmulator` marshals `EmuValue` args via a `CallingConvention`, runs until return, yields `FunctionCallResult` (return value + memory diff + trace).
- **Taint**: `TaintEmulator` propagates `TaintLabel`s across register/memory ops per `TaintPolicy`; emits `TaintEvent`s and a `TaintReport`.
- **Heap**: `HeapEmulator` models malloc/free with canaries, detecting UAF, double-free, OOB into `HeapVulnerabilityReport`.
- **JIT**: `JitCompiler` lowers IL (`IlOp`) into cached `JitBlock`s dispatched via direct/indirect tables, with `JitStats`.
- **Fuzzing**: `CoverageGuidedFuzzer` mutates `Corpus` inputs via `Mutator`, injects via `InputInjector` closure, records `FuzzCoverage`/`FuzzStats`, returns `FuzzRunResult` per execution.
- **Stats/coverage**: `EmuExecutionStatistics`, `CoverageEmu`, `EmuCoverageTracker` accumulate instruction counts, branches, basic-block hits, loops; serialized via `StatsReport`/`CoverageMap`.
- **Devices & IRQ**: MMIO/IO-port maps and the `EmuInterruptController` route reads/writes to `EmuDevice` impls and raise pending IRQs delivered at instruction boundaries.

All public types derive serde where appropriate so traces, reports and snapshots can be serialized to JSON.

## Counts
- 17 source files, ~455 `pub fn` (incl. methods).
- Tests present: `tests/blitz.rs`, `tests/blitz2.rs` (integration tests) → crate is testable via `cargo test -p rustre-emu`.
