# rustre-emu-qiling

Qiling-inspired emulation backend layered on top of `rustre-emu`. Provides OS abstraction (syscalls, libcalls), rootfs sandboxing, fd table, library stubs, hooks, coverage, and ready-made emulator factories.

## Cargo.toml

- Name: `rustre-emu-qiling`
- Workspace-versioned package metadata.
- Dependencies: `rustre-emu` (path = `../rustre-emu`), `anyhow`, `thiserror`, `serde`, `serde_json`, `parking_lot`.
- No optional features; workspace lints applied.

## Modules

`lib.rs` re-exports `CoverageMap` and `EmuStats` from `rustre-emu` and declares the following public modules:

- `os_syscall_emu` — generic OS syscall emulation glue.
- `os_posix_emulation` — POSIX-flavoured syscall behaviour.
- `qiling_analysis` — analysis driver/observer over an emulator session.
- `qiling_backend` — backend wrapper around `Emulator`/`EmulatorFactory`.
- `qiling_memory` — memory-map helpers and guest-memory utilities.
- `qiling_coverage` — coverage recording (block/edge) on top of `CoverageMap`.
- `qiling_result_parser` — parses emulation run results.
- `qiling_script_gen` — generates equivalent Qiling Python scripts.
- `qiling_hook_manager` — typed hook registration / dispatcher (includes free `make_hook`).
- `qiling_posix` — POSIX syscall numbers/handlers.
- `qiling_windows` — Windows NTSTATUS/Win32 error consts and Win32 emulation hooks.
- `rootfs_manager` — `RootfsProfile`, `RootfsPath`, `RootfsValidator`, `DllStub(s)`, `RootfsManager`.
- `fs_manager` — guest filesystem / fd-table manager.
- `anti_evasion` — `standard_bypasses()` returning canned anti-debug/anti-vm patches.

## Free public functions

| Function | Signature | Behaviour |
|---|---|---|
| `default_linux_x86_64_table` | `() -> SyscallTable` | Returns a populated Linux x86_64 syscall dispatch table. |
| `linux_x86_64` | `(rootfs: impl Into<PathBuf>) -> Result<QilingEmulator>` | Convenience factory: Linux x86_64 emulator bound to a host rootfs directory. |
| `shellcode_runner` | `(arch: EmulatorArch, shellcode: &[u8]) -> Result<QilingEmulator>` | Sets up a minimal emulator preloaded with raw shellcode for the given arch. |
| `qiling_hook_manager::make_hook` | `<F>(label: impl Into<String>, f: F) -> Box<dyn HookCallback>` | Boxes a closure as a labelled `HookCallback`. |
| `anti_evasion::standard_bypasses` | `() -> Vec<EvasionBypass>` | Returns the built-in set of evasion bypasses (anti-debug, RDTSC, timing, VM checks, etc.). |

## Key public types (`lib.rs`)

- `OsTarget` (`Linux`, `Windows`, `MacOs`, `FreeBsd`, `BareMetal`) — with `name()` const accessor.
- `QilingEmulator` — main façade wrapping a `rustre-emu::SimpleInterpreter`, an `OsLayer`, rootfs, fd table, and process env.
- `OsLayer` — pluggable OS ABI (syscall + libcall dispatch).
- `SyscallTable` / `FdTable` / `ProcessEnv` — runtime state objects.
- `BinaryLoader` / `ElfLoaderStub` — loader abstraction for guest memory layout.

## API surface (counts)

Per-module method counts (`pub fn` inside `impl` blocks):

| Module | Methods |
|---|---|
| lib.rs | 145 |
| qiling_windows | 39 |
| qiling_memory | 46 |
| qiling_hook_manager | 17 |
| qiling_coverage | 24 |
| qiling_backend | 26 |
| qiling_analysis | 51 |
| qiling_posix | 9 |
| qiling_result_parser | 7 |
| qiling_script_gen | 15 |
| rootfs_manager | 26 |
| fs_manager | 39 |
| os_syscall_emu | 11 |
| os_posix_emulation | 29 |
| anti_evasion | 22 |
| **Total methods** | **506** |
| Free functions | 5 |
| **Grand total pub fn** | **511** |

`qiling_windows` additionally exposes a large set of NTSTATUS / Win32 error `pub const` codes (e.g. `STATUS_SUCCESS`, `STATUS_ACCESS_DENIED`, `ERROR_SUCCESS`, …).

## I/O model

- **Inputs**: guest binary bytes, optional rootfs path on host, syscall/libcall hook registrations, environment vars / argv, shellcode buffers.
- **Outputs**: `anyhow::Result<…>` everywhere; structured emulation results parsed via `qiling_result_parser`; coverage via re-exported `CoverageMap`; runtime metrics via `EmuStats`; optional generated Qiling Python scripts.
- **Side effects**: reads from host rootfs only via `RootfsPath` mapping (sandbox); no host write-back unless explicitly configured by `FdTable`/`fs_manager`.

## Behaviour summary

1. Caller picks an OS target and arch, builds a `QilingEmulator` (directly or via `linux_x86_64` / `shellcode_runner`).
2. `RootfsManager` validates the host rootfs, optionally registering DLL stubs.
3. `OsLayer` dispatches guest syscalls through `SyscallTable` (POSIX numbers in `qiling_posix`, NTSTATUS/Win32 codes in `qiling_windows`).
4. Hooks (via `qiling_hook_manager::make_hook`) intercept instructions, blocks, memory, syscalls, libcalls.
5. `anti_evasion::standard_bypasses()` patches well-known evasion checks.
6. Coverage is accumulated through `qiling_coverage`; results are parsed by `qiling_result_parser`; equivalent Qiling Python can be exported by `qiling_script_gen`.

## Testability

The crate has integration tests in `tests/blitz.rs` and `tests/blitz2.rs`, plus an inline test suite. Public constructors (`linux_x86_64`, `shellcode_runner`, `default_linux_x86_64_table`, `standard_bypasses`) are trivially callable without external services, making the crate testable in isolation.
