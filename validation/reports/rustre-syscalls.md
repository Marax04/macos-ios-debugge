# rustre-syscalls

Core syscall abstraction, database, filtering, formatting, tracing API, categorization, parameter decoding, and persistence layer for the RustRE suite.

## Cargo.toml

- **name**: `rustre-syscalls` v0.1.0, edition 2024
- **lints**: `unsafe_code = warn`, `unused_must_use = deny`, plus clippy `all`/`pedantic`/`nursery`/`cargo` at warn (multiple_crate_versions allowed due to `mysql` v25 transitive duplicates).
- **dependencies**: `anyhow`, `thiserror`, `serde`, `serde_json`, `rusqlite`, `mysql`, `parking_lot` (all from workspace).

## Modules (`src/lib.rs`)

- `compat_layer`
- `syscall_decoder`
- `syscall_emulator`
- `syscall_filter`
- `syscall_hook_detector`
- `syscall_table`, `syscall_table_linux`, `syscall_table_win`, `linux_syscall_table`
- `syscall_tracer`
- `windows_syscalls`
- `syscall_dispatcher`
- `syscall_statistics`
- `syscall_policy_checker`

## Public API surface (lib.rs root)

### Error & enums
- `enum SyscallError` (thiserror): `NotFound`, `Database`, `Mysql`, `Serde`, `Other`.
- `enum OsFamily`: Linux, Windows, MacOs, FreeBsd, OpenBsd — `Display`.
- `enum SyscallArch`: X86, X86_64, Arm32, Arm64, Mips, Riscv64 — `Display`.
- `enum SyscallType`: Void, Int, UInt, Long, ULong, Ptr, Handle, Bool, Fd, Pid, Tid, Size, SSize, Errno, Buffer{size_arg}, String, WString, Struct(name), Enum(name), Flags(name), UserPtr, KernelPtr, SaFamily, Offset, Mode, Signal, ClockId, FdArray, Socklen, IpAddr.
- `enum ArgDirection`: In, Out, InOut.
- `enum SyscallCategory`: FileSystem, Memory, Process, Thread, Network, Ipc, Signal, Time, Device, Security, System, Unknown.
- `enum RiskLevel`: Benign, Low, Medium, High, Critical (Ord).

### Core types
- `struct SyscallArg { name, ty, direction, optional }` — `new`, `optional`, `decode`.
- `struct DecodedArg { raw, display, is_null }` — `new`, `Display`.
- `struct Syscall { number, name, os, arch, args, return_type, category, description, risk, aliases, deprecated }` — `new(num, name, SyscallTarget, args, ret, cat, desc)`, `decode_args(&[u64])`, `prototype()`, `has_output_args()`, `input_arg_count()`.
- `struct SyscallTarget { os, arch }` — `new(os, arch)`.
- `struct SyscallCall { syscall, args, ret, timestamp, pid, tid, tags }` — `new`, `is_error`, `decoded_args`, `elapsed_us(base_ns)`, `tag`.

### Database
- `struct SyscallDatabase` — `new`, `insert(Syscall)`, `merge(other)`, `lookup(os, arch, number)`, `lookup_by_name(os, arch, name)`, `all_for(os, arch)`, `all_for_category(os, arch, cat)`, `high_risk(os, arch, min_risk)`, `len`, `is_empty`, `stats() -> DatabaseStats`.
- `struct DatabaseStats { total, by_category, by_risk }`.

### Free functions
- `decode_arg_value(&SyscallType, u64) -> DecodedArg`
- `signal_name(u32) -> Option<&'static str>` (SIGHUP..SIGSYS)
- `errno_name(u32) -> Option<&'static str>` (EPERM..EINPROGRESS)
- `clock_id_name(u32) -> Option<&'static str>` (CLOCK_REALTIME..CLOCK_BOOTTIME_ALARM)
- `sa_family_name(u16) -> Option<&'static str>` (AF_UNSPEC..AF_VSOCK)

### Static tables (private but exposed via modules)
- `LINUX_X86_64_ENTRIES` (NR 0–329)
- `LINUX_ARM64_ENTRIES` (most common AArch64 NRs)
- `WINDOWS_X64_ENTRIES` (NT syscall numbers)

## Submodule public function counts (`^pub fn`)

| Module | pub fn |
|---|---|
| `lib.rs` (root) | 7 |
| `compat_layer` | 9 |
| `syscall_decoder` | 6 |
| `syscall_filter` | 6 |
| `syscall_tracer` | 2 |
| `windows_syscalls` | 1 |
| `syscall_policy_checker` | 1 |
| `linux_syscall_table` | 1 |
| **Total** | **33** |

(Additional modules `syscall_emulator`, `syscall_table`, `syscall_table_linux`, `syscall_table_win`, `syscall_hook_detector`, `syscall_dispatcher`, `syscall_statistics` expose types/impls rather than free pub fns.)

## Testability

The crate is **testable**: pure-Rust core (enums, decoders, database, formatting) has no I/O dependencies and can be unit-tested directly. The `rusqlite` and `mysql` backends require live DBs for integration tests but the API around them is decoupled. No `#[cfg(test)]` modules were found in the root file scanned.
