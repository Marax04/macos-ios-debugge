# rustre-forensics-mem

OS-specific memory structure analysis for Windows and Linux memory images. Walks kernel data structures inside a `MemoryImage` to reconstruct live system state: processes, modules, threads, network connections, registry hives, heap allocations, VAD trees, timelines, and artifacts.

## Cargo.toml

- **Package**: `rustre-forensics-mem` v0.1.0, edition 2024
- **Dependencies**: `rustre-forensics` (path), `rustre-core` (path), `anyhow`, `thiserror`, `serde`, `serde_json`, `parking_lot`
- **Lints**: workspace inherited

## Module Layout

| Module | Purpose |
|---|---|
| `lib.rs` | Top-level types: `WindowsAnalyzer`, `LinuxAnalyzer`, `MemoryForensicsScanner`, `build_mock_image`, kernel/version/process/network/registry types |
| `artifact_extractor` | Extract files, registry, event-log, browser artifacts from memory |
| `casts` (pub(crate)) | Safe u64→u32 / u64→usize narrowing |
| `heap_analysis` | NT/glibc heap walking, allocation tracking |
| `kernel_forensics` | Kernel object scanning (drivers, DPCs, callbacks) |
| `linux_structs` | Linux kernel offsets and parsers (`task_struct`, modules) |
| `memory_forensics` | High-level memory triage helpers |
| `process_dump_analysis` | Minidump / core dump parsing |
| `process_tree` | Build parent/child PID trees |
| `profile_detect` | Identify OS, kernel build, profile from raw image |
| `strings_extractor` | ASCII / UTF-16LE string extraction with addresses |
| `timeline_builder` | Aggregate events into chronological timeline |
| `vad_tree` | Walk Windows VAD (Virtual Address Descriptor) tree |
| `windows_structs` | Windows kernel offsets and binary readers |

## Public Types

### Version / Kernel
- `WindowsVersion { major, minor, build: u32 }` — `new`, `display()`
- `WindowsKernelInfo { kdbg: Option<u64>, ntoskrnl_base: u64, version, arch: ArchBits }`
- `KernelSymbols { ... }` — `_EPROCESS`, `_ETHREAD`, `_PEB`, `_RTL_USER_PROCESS_PARAMETERS` field offsets

### Process / Thread
- `ThreadState` enum (Initialized, Ready, Running, Standby, Terminated, Wait, Transition, DeferredReady, Unknown) — `from_u8`
- `ThreadInfo { tid, start_addr, teb, state }`
- `ProcessInfo { pid, ppid, name, base, size, threads, modules, handle_count, create_time }` — `name_matches(pattern)` case-insensitive

### Module
- `ModuleInfo { name, base, size, path }`

### Network
- `NetProtocol` (TcpV4/TcpV6/UdpV4/UdpV6) — `as_str()`
- `ConnectionState` (Listen, Established, CloseWait, TimeWait, Closed, SynSent, SynReceived, FinWait1, FinWait2, LastAck, Unknown) — `from_u8`
- `NetworkConnection { protocol, local_addr, local_port, remote_addr, remote_port, state, pid }`

### Registry
- `RegistryValue { name, data: Vec<u8>, value_type: u32 }`
- `RegistryKey { name, values, subkeys }`
- `RegistryHive { name, base, size, data }` — `parse_key(path) -> Option<RegistryKey>` (requires `regf` signature)

### Heap
- `HeapAllocation { addr, size }`

## Public APIs

### `WindowsAnalyzer` (unit struct)
- `find_processes(image: &dyn MemoryImage) -> Vec<ProcessInfo>` — scans for `b"EPRC"` magic + 56-byte record
- `try_find_processes(image) -> Result<Vec<ProcessInfo>, CoreError>` — errors `InvalidAddress` if no regions
- `find_modules(image, pid: u32) -> Vec<ModuleInfo>` — scans `b"LDRM"` + 116-byte record
- `find_network_connections(image) -> Vec<NetworkConnection>` — scans `b"NCON"` + 48-byte record
- `extract_registry_hives(image) -> Vec<RegistryHive>` — scans `b"HIVE"` + 52-byte record
- `find_kernel_info(image) -> Option<WindowsKernelInfo>` — searches `b"KDBG"` signature, reads ntoskrnl base + version

### `LinuxAnalyzer` (unit struct)
- `find_processes(image) -> Vec<ProcessInfo>` — scans `b"TSKB"` task_struct records
- `find_modules(image) -> Vec<ModuleInfo>` — scans `b"KMOD"` records
- `find_sockets(image) -> Vec<NetworkConnection>` — delegates to Windows NCON scan

### `MemoryForensicsScanner` (unit struct, raw-slice scanners)
- `scan_pe_headers(memory: &[u8], base_addr: u64) -> Vec<u64>` — MZ + e_lfanew in [0x40,0x1000] + `PE\0\0`
- `scan_stack_canaries(memory) -> Vec<u64>` — DEADBEEF, ABABABAB, FEEEFEEE, CDCDCDCD, BAADF00D at 4-byte alignment
- `scan_heap_allocations(memory) -> Vec<HeapAllocation>` — NT 8-byte HEAP_ENTRY with BUSY flag, size in granules
- `find_unicode_strings(memory, min_len) -> Vec<(u64, String)>` — UTF-16LE printable ASCII runs

### Helper
- `build_mock_image(os: OsType) -> RawMemoryImage` — constructs a 4 KiB image embedding KDBG, two processes, one module, one connection, one hive. Used by tests and downstream crates.

### Submodule exports (selected)
- `windows_structs::{read_u8, read_u16, read_u32, read_u64, read_ansi_string}` and offset constants (`EPROCESS_*`, `ETHREAD_*`, `PEB_*`)
- `linux_structs`: 13 pub fn parsers for `task_struct`, `mm_struct`, `vm_area_struct`
- `vad_tree`: 19 pub fn walkers/builders for VAD tree traversal
- `heap_analysis`: 7 pub fn heap walk helpers
- `kernel_forensics`: 21 pub fn (drivers, modules, callbacks, hooks)
- `artifact_extractor`: 30 pub fn (files, hives, event logs, browser artifacts)
- `process_dump_analysis`: 28 pub fn (minidump streams, regions)
- `process_tree`: 9 pub fn (tree building, ancestor queries)
- `profile_detect`: 27 pub fn (OS/kernel/build detection)
- `strings_extractor`: 6 pub fn (ASCII/Unicode/encoded strings)
- `timeline_builder`: 37 pub fn (event aggregation, ordering)
- `memory_forensics`: 24 pub fn (triage façade)

## I/O Contract

- **Inputs**: implementors of `rustre_forensics::MemoryImage` (provides `regions()`, `read(addr, len)`, `arch()`); or raw `&[u8]` for `MemoryForensicsScanner`.
- **Outputs**: pure data (`Vec<ProcessInfo>`, etc.), all `serde`-serializable.
- **No I/O side effects**: nothing reads or writes the filesystem; all parsing is in-memory.

## Behavior / Safety

- **DoS guard**: `MAX_REGION_READ = 64 MiB` caps per-region reads; `MAX_HIVE_DATA = 16 MiB` caps hive allocation. Protects against corrupt/adversarial images reporting `end == u64::MAX`.
- **Signature-driven scanning**: each analyzer scans every region for ASCII magic tags (`EPRC`, `LDRM`, `NCON`, `HIVE`, `KDBG`, `TSKB`, `KMOD`). Record layouts are fixed-size little-endian.
- **Step**: scanner advances 4 bytes when no match, full record size on match.
- **Failure mode**: parse errors (truncated buffer, bad `try_into`) silently skip the record. `try_find_processes` is the only path that yields `Result`; everything else returns empty `Vec` / `Option::None`.
- **Endianness**: all integer fields little-endian.
- **Name fields**: null-terminated, truncated to field width, decoded with `from_utf8_lossy`.
- **IPv4/IPv6**: `bytes_to_ip` produces `a.b.c.d` for v4 and 8-group lowercase hex for v6.
- **Registry**: `RegistryHive::parse_key` only validates the `regf` signature and returns a synthetic key populated with metadata — not a full hive walk.

## Tests

- 40+ unit tests inline in `lib.rs` (`cargo test -p rustre-forensics-mem`).
- Integration tests in `tests/blitz.rs`, `tests/blitz2.rs`.
- `build_mock_image` enables deterministic, allocator-free fixtures for both OS branches.
- **Testable**: yes — pure functions over byte slices and trait objects; mock builder provided.

## Function count

Approximately **279 public functions** across 14 source files (counts: lib 32, artifact_extractor 30, heap_analysis 7, kernel_forensics 21, linux_structs 13, memory_forensics 24, process_dump_analysis 28, process_tree 9, profile_detect 27, strings_extractor 6, timeline_builder 37, vad_tree 19, windows_structs 18, casts 8).
