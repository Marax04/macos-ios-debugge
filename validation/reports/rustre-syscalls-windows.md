# rustre-syscalls-windows

Windows-specific syscall, NT API, and Win32 API monitoring/analysis library for the RustRE platform.

## Cargo.toml

- **name**: `rustre-syscalls-windows`
- **version**: 0.1.0
- **edition**: 2024
- **license/description/repo/readme/keywords/categories/authors**: inherited from workspace

### Dependencies
- `rustre-syscalls` (path = `../rustre-syscalls`) — base cross-platform syscall types
- `anyhow` (workspace) — error handling
- `thiserror` (workspace) — typed errors (`WinSyscallError`, `SyscallTableError`)
- `serde` + `serde_json` (workspace) — serialization of records/events
- `parking_lot` (workspace) — fast mutexes for shared state (monitors, registries)

### Lints
- `[lints] workspace = true`

## Modules (`pub mod`)
Declared in `src/lib.rs`:
- `api_monitor` — high-level API call monitor scaffolding
- `nt_syscalls` — NT syscall metadata helpers
- `windows_events` — Windows event records (`WinEventRecord`, `WinEventLevel`)
- `nt_syscall_table` — SSN <-> entry lookup table
- `etw_event_parser` — ETW event parsing + flat record helpers
- `api_monitor_hooks` — hook descriptor builders
- `nt_object_manager` — NT object/handle/pipe metadata
- `win32_api_monitor` — Win32 API monitoring entry points
- `registry_monitor` — registry path classification helpers

## Public functions

### `lib.rs`
- `analyse_stub(name: &str, ssn: u32, arch: WinArch, stub: &[u8]) -> HookAnalysis` — classifies a syscall stub (clean vs hooked) and returns analysis metadata.
- `build_version_ssn_table() -> Vec<VersionSsn>` — returns a static mapping of Windows versions to NT SSN tables.
- `lookup_win32_api(name: &str) -> Option<&'static Win32ApiEntry>` — finds a Win32 API entry by name in `WIN32_API_DB_V2`.
- `win32_apis_by_module(module: &str) -> Vec<&'static Win32ApiEntry>` — filters Win32 API DB by DLL/module.
- `win32_apis_by_category(cat: ApiCategoryV2) -> Vec<&'static Win32ApiEntry>` — filters Win32 API DB by category.
- `format_ntstatus(code: u32) -> String` — formats an `NTSTATUS` code into "0xNNN (NAME)".
- `nt_to_win32_path(nt_path: &str) -> String` — converts `\??\C:\…` style NT paths to Win32 paths.
- `is_system_path(path: &str) -> bool` — true if the path lies under a system directory.
- `decode_file_access(access: u32) -> String` — decodes a file `ACCESS_MASK` into a flag string.
- `decode_alloc_type(alloc_type: u32) -> String` — decodes `MEM_*` allocation flags.
- `build_x86_v2() -> Vec<WinNtSyscall>` — builds the x86 NT syscall metadata vector (v2).
- `is_clean_x64_stub(stub: &[u8], expected_ssn: u32) -> bool` — checks for the canonical x64 syscall stub prefix (`4C 8B D1 B8 ssn…`).
- `is_clean_x86_stub(stub: &[u8], expected_ssn: u32) -> bool` — checks for canonical x86 stub.
- `detect_hook_type(stub: &[u8]) -> HookKind` — heuristically detects inline hook / IAT hook / clean.
- `is_dangerous_privilege(name: &str) -> bool` — flags privileges considered dangerous (SeDebug, SeTcb, …).
- `nt_to_win32_reg_path(nt_path: &str) -> String` — converts NT registry paths (`\REGISTRY\MACHINE\…`) to `HKLM\…`.
- `is_persistence_registry_key(path: &str) -> bool` — true if the registry key is a known persistence location (Run, Services, etc.).
- `decode_ntstatus(code: u32) -> &'static str` *(const fn)* — short name for an NTSTATUS code.
- `ntstatus_name(code: u32) -> Option<&'static str>` *(const fn)* — optional NTSTATUS name lookup.
- `winsock_error_name(code: i32) -> Option<&'static str>` *(const fn)* — Winsock error code name.

### `nt_syscall_table.rs`
- `syscall_by_number(number: u32) -> Result<NtSyscallEntry, SyscallTableError>` — lookup entry by SSN.
- `syscall_args(number: u32) -> Result<u8, SyscallTableError>` — argument count for an SSN.

### `etw_event_parser.rs`
- `nt_kernel_logger_guid() -> Guid` — well-known NT Kernel Logger GUID.
- `security_auditing_guid() -> Guid` — Security Auditing provider GUID.
- `build_flat_record(params: &FlatRecordParams, user_data: &[u8]) -> Vec<u8>` — assembles a flat ETW record buffer.

### `api_monitor_hooks.rs`
- `build_standard_hooks() -> ApiMonitorHooks` — returns the default Win32/NT hook descriptor set.

## Public surface (other items)

Key public types (non-exhaustive, declared in `lib.rs` unless noted):
- Errors / enums: `WinSyscallError`, `WinArch`, `WinVersion`, `ParamDirection`, `NtSyscallCategory`, `PageProtect`, `HookKind`, `ArgType`, `SyscallCategory`, `ApiCategory`, `ApiCategoryV2`, `WinDecodedArg`, `SuspiciousPattern`, `WinEventLevel`, `IntegrityLevel`, `PipeDirection`, `InjectionStrategy`, `PipeMessageType`.
- Syscall / API metadata: `WinSyscallParam`, `WinNtSyscall`, `NtdllExport`, `SyscallEntry`, `WinApiEntry`, `Win32ApiEntry`, `VersionSsn`, `WinSyscallDb`, `WinSyscallResolver`.
- NT structures: `ObjectAttributes`, `IoStatusBlock`, `ClientId`, `UnicodeString`, `MemoryBasicInformation`, `SystemProcessInfo`, `SystemModuleEntry`, `Peb`, `PeHeaders`.
- Monitoring: `SyscallCapture`, `SyscallFilter`, `SyscallMonitor`, `NtTraceCollector`, `ApiCallRecord`, `ApiCallOrigin`, `ApiCallStream`, `ApiEvent`, `ApiEventFilter`, `WinApiSummary`, `WinApiStat`, `WinApiStatV2`, `WinApiStats`, `PatternDetector`.
- Hooks: `HookAnalysis`, `InlineHookDescriptor`, `HookRegistry`, `IatHookDescriptor`, `InlineHookRecord`.
- Misc: `InjectionParams`, `PipeMessageHeader`, `WinTaintProcess`, `WinTaintPersistence`, `WinTaintMisc`, `WinTaintFlags`, `HandleInfo`, `HandleTable`, `WinEventRecord`, `ProcessEntry`, `ProcessTree`, `NamedPipeInfo`.
- Static tables / constants: `WINDOWS_SYSCALL_TABLE`, `WIN32_API_DB`, `WIN32_API_DB_V2`, `WINDOWS_PRIVILEGES`, `CLEAN_X64_STUB_PREFIX`, `MZ_MAGIC`, `PE_MAGIC`, `PE32_MAGIC`, `PE32_PLUS_MAGIC`, `MONITOR_PIPE_NAME`, `TRAMPOLINE_MAX_BYTES`, `SIZE_T`, `ULONG_PTR`.

## Testability
The library is testable: pure-function helpers (`analyse_stub`, `is_clean_x64_stub`, `is_clean_x86_stub`, `detect_hook_type`, `format_ntstatus`, `decode_ntstatus`, `ntstatus_name`, `winsock_error_name`, `nt_to_win32_path`, `nt_to_win32_reg_path`, `is_system_path`, `is_persistence_registry_key`, `is_dangerous_privilege`, `decode_file_access`, `decode_alloc_type`, `lookup_win32_api`, `win32_apis_by_module`, `win32_apis_by_category`, `syscall_by_number`, `syscall_args`, `build_x86_v2`, `build_version_ssn_table`, `build_standard_hooks`, `build_flat_record`) are deterministic and unit-testable on any host (no Windows runtime required). Live monitoring types (`SyscallMonitor`, `NtTraceCollector`, `ApiCallStream`, `HookRegistry`) require integration tests on Windows targets.
