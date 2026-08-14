# rustre-mem

Memory provider abstractions and analysis utilities for RustRE.

## Cargo.toml

- **name**: `rustre-mem` v0.1.0, edition 2024
- **deps**: `rustre-core`, `async-trait`, `bitflags`, `parking_lot`, `thiserror`, `serde`, `serde_json`
- **target deps (windows)**: `windows-sys 0.59` (Win32 Foundation/Debug/Memory/Threading)
- **dev-deps**: `tokio`, `serde_json`
- **features**: default = []

## Modules (pub)

`access_log`, `arena`, `cache`, `cache_layer`, `composite_memory`, `composite_provider`, `cow`, `diff`,
`emulated_memory`, `entropy`, `fault`, `file_memory`, `helpers`, `memory_access_log`, `memory_analysis`,
`memory_diff`, `memory_layout_analyzer`, `memory_provider`, `null_memory`, `patched_memory`,
`patched_provider`, `permissions_model`, `phys`, `process_memory`, `provider`, `region`, `search`,
`snapshot`, `snapshot_diff`, `sparse`, `trace_memory`, `trace_provider`, `virtual_memory`, `vmmap`.

## Public API (re-exports from lib.rs)

### Core trait & types (`memory_provider`)
- `trait MemoryProvider` + `MemoryProviderExt` — read/write/regions/stats
- `MemError` (thiserror): `NotMapped(Address)`, `PermissionDenied(Address)`, `Io(io::Error)`, ...
- `MemoryRegion { range, perms, name, source }`, `RegionSource`, `SnapshotId(u64)`
- `ProviderMemoryStats { total_mapped, readable_bytes, writable_bytes, executable_bytes }`
- `ReadOnlyWrapper`
- free fns: `find_bytes`, `read_cstring`, `read_u16_le`, `read_u32_le/be`, `read_u64_le/be`

### Providers
- `VirtualMemoryProvider` — in-memory synthetic regions (`map`, `unmap`, `read`, `write`, `regions`)
- `NullMemoryProvider` — always returns NotMapped
- `FileMemoryProvider` — backed by a file on disk
- `CompositeMemoryProvider` / `EnhancedCompositeProvider` — layered providers with priority; `WriteStrategy`, `LayerOverlap`, `ProviderLayer`, `RegionMerger`
- `CowMemoryProvider` — copy-on-write overlay
- `PatchedMemoryProvider` + `Patch` / `EnhancedPatchedMemoryProvider` + `PatchConflict`, `PatchDiffEntry`, `PatchExport`, `PatchOverlay`
- `EmulatedMemoryProvider` / `StandaloneEmulatedMemoryProvider` + `EmulatedRegion`, `PERM_READ/WRITE/EXEC`
- `ProcessMemoryProvider` / `StandaloneProcessMemoryProvider` + `MemRegion` — live process (Windows via windows-sys)
- `TraceMemoryProvider` / `StandaloneTraceMemoryProvider` / `EnhancedTraceMemoryProvider` + `TraceTickMemory`, `TraceSnapshot`, `TracePosition`, `TraceMemorySnapshot`, `SnapshotCache`, `MemoryDelta`, `DeltaReplay`
- `SparseMemoryProvider`, `LargeWindowProvider`
- `LoggingMemoryProvider` (+ `AccessKind`, `AccessLog`, `AccessRecord`)
- `FaultingMemoryProvider` (+ `FaultError`, `FaultKind`, `FaultPolicy`, `FaultRule`, `FaultStats`)

### Cache / arena
- `PageCache::new(page_size, capacity)`, `read::<E, F>(addr, len, fetch_page)`, `is_empty`, `len`; `CacheStats`
- `MemoryArena` + `ArenaAlloc`, `ArenaError`, `ArenaMark`, `ArenaStats`

### Physical / layout
- `FlatPhysMemory`, `PhysicalMemory` (trait), `MemMap`, `MemMapError`, `PageFlags`, `PageInfo`, `PhysAddr`, `VirtAddr`
- `ExtendedRegion`, `RegionAttributes`, `RegionKind`, `RegionSet`
- `page_align_down`, `page_align_up`, `page_containing`, `page_index`, `page_range_indices`

### Permissions
- `ExtendedPerms`, `PermissionAuditLog`, `PermissionChange`, `RelroStatus`, `infer_relro_status`

### Search
- `MemorySearcher`, `BytePattern`, `PatternByte`, `SearchResult`, `search_with_context`

### Snapshots & diff
- `SnapshotStore`, `SnapshotRecord`, `SnapshotDelta` (= `snapshot::SnapshotDiff`), `diff_snapshots`
- `MemorySnapshot`, `MemoryStats`, `MemoryChange`, `SnapshotDiff`, `diff_memory`, `diff_memory_lenient`
- `DiffSpan { range, old_bytes, new_bytes }`, `diff_providers(a, b, AddressRange) -> Vec<DiffSpan>`

### Entropy
- `shannon_entropy(&[u8]) -> f64`
- `EntropyBlock { address, entropy }`, `entropy::entropy_blocks(provider, block_size)`

### Typed read/write helpers (`helpers`)
- `read_u8_at`, `read_u16_le_at`, `read_u16_be_at`, `read_u32_le_at`, `read_u32_be_at`, `read_u64_le_at`, `read_u64_be_at`
- `read_i8_at`, `read_i16_le_at`, `read_i32_le_at`, `read_i64_le_at`
- `read_f32_le_at`, `read_f64_le_at`
- `write_u8_at`, `write_u16_le_at`, `write_u32_le_at`, `write_u64_le_at`
- `search_bytes_with_mask(provider, pattern, mask, range) -> Vec<Address>`

## I/O Model

- **Input**: `Address` (from `rustre-core::address`), byte slices, `Permissions` flags, `AddressRange`
- **Output**: `Result<Vec<u8>, MemError>` for reads; `Result<(), MemError>` for writes; `Option<T>` for typed helpers; `Vec<MemoryRegion>` for regions
- **Errors**: `MemError::{NotMapped, PermissionDenied, Io, ...}`
- **Side effects**: Windows `ProcessMemoryProvider` opens live processes via Win32; `FileMemoryProvider` reads from disk

## Testability

Self-contained unit tests (lib.rs lines 134-913) covering all major providers (Virtual, Null, Patched, Composite, PageCache), entropy, diff, helpers, search, permissions, errors. No external binaries required — uses synthetic `VirtualMemoryProvider` regions.
