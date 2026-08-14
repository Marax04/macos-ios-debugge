# rustre-syscalls-linux

Linux-specific syscall database, ptrace tracing, seccomp profile generation, and syscall interception for x86_64 and aarch64.

## Cargo.toml

- name: `rustre-syscalls-linux` v0.1.0, edition 2024
- dependencies: `rustre-syscalls` (path), `thiserror`, `serde`, `serde_json`, `rusqlite` (all workspace)
- workspace-inherited: license, description, repository, readme, keywords, categories, authors, lints

## Modules (src/lib.rs)

- `ptrace_tracer` — ptrace-based tracing primitives
- `syscall_intercept` — runtime syscall interception/modification rules
- `syscall_statistics` — sample aggregation, hot syscalls, patterns, timeline, strace-like formatting
- `ptrace_syscall_tracer` — register-level syscall entry/exit capture
- `seccomp_profile_generator` — BPF seccomp profile builder with sandbox/anti-debug presets
- `linux_syscall_table_x86_64` — static x86_64 syscall table with lookups

## Public API highlights

### lib.rs root
- Errors: `LinuxSyscallError`
- Models: `SyscallParam`, `LinuxSyscall`, `LinuxSyscallDb`, `SyscallResolver`, `SyscallStore`, `LinuxSyscallEntry`, `SyscallEvent`, `SyscallTrace`, `SyscallEventV2`, `SyscallSummary`/`V2`, `SyscallStat`, `SyscallSummaryEntry`
- Categories: `SyscallCategory`, `SyscallEntryCategory`, `SecuritySeverity`, `ArgType`, `FlagBit`, `DecodedArg`, `DecodedSockaddr`, `OutputFormat`, `FdKind`, `FdInfo`, `FdTable`, `PtraceOptions`/`V2`, `PtraceEvent`, `SeccompAction`, `SignalEvent`, `WaitStatus`, `TaintFlags`, `MapsEntry`, `ProcStatus`, `StaticSyscall`, `JsonEventLog`, `CsvEventLog`, `TraceSession`, `ThreadSyscallState`, `FdTracker`, `ChildTracker`, `SyscallTraceFilter`
- Lookup fns: `lookup_x86_64_entry(nr)`, `x86_64_syscall_name/_nr`, `aarch64_syscall_name/_v2/_nr`, `syscall_security_severity`, `syscall_category`
- Decoders: `decode_open_flags`, `decode_mmap_prot`, `decode_mmap_flags`, `decode_flags`, `decode_flags_by_name`, `decode_sockaddr`, `format_mmap_args`, `format_open_flags`, `format_retval`, `format_signal_delivery`, `format_exit_event`, `hex_dump_ext`
- Names: `errno_name`/`_v2`, `signal_name`/`_v2`, `ioctl_name`, `ptrace_request_name`, `sockopt_name`, `af_name`
- Proc utils: `parse_proc_maps`, `parse_proc_status`, `resolve_fd`, `read_process_memory`, `read_cstring`
- Const: `AT_FDCWD`, `AARCH64_SPECIFIC_SYSCALLS`

### linux_syscall_table_x86_64
- `syscall_by_number(nr)`, `syscall_by_name(name)`, `search_by_name(needle)`, `by_arg_count(n)`
- `build_number_index()`, `build_name_index()`
- Types: `SyscallArg`, `SyscallInfo`

### ptrace_syscall_tracer
- `PtraceSyscallTracer`, `SyscallArgs`, `SyscallEntry`, `SyscallExit`, `SyscallRecord`
- const fns: `args_from_regs`, `syscall_number_from_orig_rax`, `is_error_return`

### ptrace_tracer
- `PtraceTracer`, `TraceSession`, `TracedProcess`, `TracedThread`, `ThreadTracker`
- `SyscallEntry`, `SyscallExit`, `TraceEvent`
- Type aliases: `Pid`, `Tid`

### syscall_intercept
- `SyscallInterceptor`, `InterceptRule`, `InterceptEvent`
- `InterceptPoint`, `SyscallFilter`, `InterceptAction`
- `ArgModifier`, `ReturnModifier`

### syscall_statistics
- `SyscallStatistics`, `SyscallSample`, `PerSyscallStats`, `HotSyscall`, `SyscallPattern`, `Timeline`, `StraceLikeFormatter`

### seccomp_profile_generator
- `SeccompProfileGenerator`, `SeccompRule`, `BpfFilter`
- `PolicyKind`, `ArgFilter`, `SeccompAction`
- Presets: `minimal_sandbox_profile()`, `anti_debug_profile()`

## Tests
Integration tests present: `tests/blitz.rs`, `tests/blitz2.rs`.
