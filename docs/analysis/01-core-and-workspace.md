# RustRE Workspace — Core & Infrastructure Crate Analysis

**Date:** 2026-07-01  
**Scope:** rustre-core, rustre-events, rustre-db, rustre-knowledge, rustre-mem, rustre-project, rustre-daemon  
**Note:** `rustre-bin` and `rustre-cli` do not exist as separate crates. The CLI binary lives inside `rustre-daemon/src/main.rs`.

---

## Table of Contents

1. [Dependency Graph](#1-dependency-graph)
2. [rustre-core](#2-rustre-core)
3. [rustre-events](#3-rustre-events)
4. [rustre-db](#4-rustre-db)
5. [rustre-knowledge](#5-rustre-knowledge)
6. [rustre-mem](#6-rustre-mem)
7. [rustre-project](#7-rustre-project)
8. [rustre-daemon](#8-rustre-daemon)
9. [Cross-Crate Integration Map](#9-cross-crate-integration-map)
10. [Implementation Status Summary](#10-implementation-status-summary)
11. [Known Gaps & TODOs](#11-known-gaps--todos)

---

## 1. Dependency Graph

```
rustre-daemon ──► rustre-core ──► rustre-events
              ──► rustre-mcp-server       │
                                          ▼
rustre-project ──► rustre-core    rustre-db
rustre-mem     ──► rustre-core
rustre-core    ──► rustre-events
               ──► rustre-knowledge
               ──► rustre-db
```

**External crates (key):**

| Crate | Purpose |
|---|---|
| `tokio` | Async runtime (`sync`, `net`, `rt-multi-thread`) |
| `parking_lot` | Fast `RwLock`/`Mutex` (all crates) |
| `serde` / `serde_json` | Serialization |
| `thiserror` | Error derive macros |
| `rusqlite` | SQLite bindings (rustre-db, rustre-project) |
| `bitflags` | Permission/flag enums |
| `async-trait` | Async trait objects |
| `hyper` / `hyper-util` / `http-body-util` | HTTP server (daemon) |
| `clap` | CLI parsing (daemon) |
| `tracing` / `tracing-subscriber` | Structured logging |
| `sha2` / `hex` | SHA-256 for binary fingerprinting |
| `uuid` | UUID generation (knowledge, daemon) |
| `windows-sys` | Windows process/memory APIs (mem, daemon) |
| `once_cell` | Lazy statics (events) |

---

## 2. rustre-core

**Path:** `crates/rustre-core/`  
**Status:** COMPLETE — fully implemented with comprehensive integration tests.

### Purpose

The foundational crate. Every other crate in the workspace depends on it (directly or transitively). It defines all core RE abstractions: binary representation, architecture model, type system, analysis pass infrastructure, event bus, plugin host, and workspace management.

### Module Inventory

| Module | Key Types | Description |
|---|---|---|
| `address` | `Address`, `VirtualAddress`, `PhysicalAddress`, `FileOffset`, `RVA`, `AddressRange`, `SegmentMapping`, `AddressSpace` | Typed address newtypes; `SegmentMapping::va_to_file_offset` / `file_offset_to_va` |
| `arch` | `Architecture` (trait), `Instruction`, `Operand`, `RegisterInfo`, `RegisterKind`, `BranchInfo`, `BranchKind`, `CallingConvention`, `ArchitectureRegistry` | Architecture abstraction; `disassemble(&[u8]) -> Result<Instruction>` |
| `binary_view` | `BinaryView`, `Memory`, `Segment` | In-memory binary representation with `RwLock<Memory>` |
| `binary_view_impl` | `BinaryViewFull`, `BinaryViewBuilder`, `BinaryUri`, `ArchHandle`, `FunctionTable`, `TypeSystem`, `XrefIndex`, `PatchSet`, `CommentStore`, `BookmarkSet` | Rich `BinaryView` implementation; builder pattern for construction |
| `endian` | `Endian`, `EndianBuf`, `EndianReader`, `EndianWriter`, LEB128 encode/decode | Byte-order-aware I/O; SLEB128/ULEB128 codec |
| `errors` | `CoreError`, `Result<T>`, `ErrorContext`, `ResultExt`, macros `bail_core!`/`ensure_core!` | Central error type with `is_io()`, `is_transient()` methods |
| `ids` | `FunctionId`, `SymbolId`, `TypeId`, `ViewId`, …, `IdAllocator`, `IdPool`, `IdMap` | Typed ID newtypes; `IdPool` for reclaim/reuse |
| `loader` | `Loader` (trait), `LoaderRegistry`, `LoaderInput`, `LoadResult`, `LoaderOptions`, `BinaryType`, `HintSet` | Async loader trait; `can_load(&[u8])` + `load(input)` |
| `permissions` | `Permissions` (bitflags), `MemoryProtection`, `PermissionPolicy`, `PermissionRule`, `InheritFlags` | `READ`/`WRITE`/`EXECUTE` flags; `as_rwx_string()` |
| `patches` | `PatchSet`, `Patch`, `PatchKind`, `CommentStore`, `Comment`, `BookmarkSet`, `Bookmark`, `BookmarkColor` | Mutation tracking with undo support |
| `symbols` | `SymbolIndex`, `SymbolEntry`, `SymbolBinding`, `XrefStore`, `XrefRecord`, `XrefKind`, `FunctionRegistry`, `FunctionRecord`, `BasicBlock`, `BBEdge` | Symbol table + xref graph + function CFG |
| `types` | `TypeStore`, `TypeDef`, `TypeKind`, `TypeId`, `FunctionSignature`, `StructField`, `EnumMember` | Type system with define/lookup/resolve |
| `type_system_full` | `TypeSystem`, `TypeLayout`, `TypePrinter`, `DwarfTypeImporter` | Full type system with layout computation and C-style printing |
| `analysis` | `AnalysisPass` (trait), `PassManager`, `AnalysisPassInfo`, `PassDependency`, `PassResult` | Dependency-ordered pass manager with cycle detection |
| `analysis_pipeline` | `AnalysisPipeline`, `PassScheduler`, `BuiltinPassKind`, `AutoAnalysis`, `AnalysisProgress` | Pass scheduling and progress reporting |
| `analysis_session` | `AnalysisSession`, `SessionState`, `SessionConfig`, `SessionLog`, `SessionExport`, `SessionRestore` | Per-view session lifecycle |
| `event_bus` | `EventBus`, `Event` (trait), `EventKind`, `Subscription` | Per-view event bus (not the global one) |
| `plugin` | `PluginContext`, `PluginId`, `PluginRegistry`, `PluginState` | Per-view plugin state storage |
| `plugin_context` | `ViewPlugin` (trait), `PluginContext`, `PluginAction`, `ActionHistory`, `PluginInterop` | Plugin lifecycle and action history |
| `plugin_registry` | `Plugin` (trait), `PluginMetadata`, `PluginRegistry` | Global plugin registration |
| `traits` | `MemoryProvider`, `BinaryViewTrait`, `FormatParser`, `Demangler`, `Decompiler`, `Debugger`, `ScriptEngine`, `Visualizer`, `PluginHost` | Cross-crate trait contract (spec §2) |
| `workspace_manager` | `WorkspaceManager`, `Workspace`, `WorkspaceConfig` | Multi-project workspace orchestration |
| `disasm_style` | `DisasmStyle`, `SyntaxFlavor` (Intel/ATT), `MnemonicCase`, `ImmediateStyle` | Disassembly display configuration |
| `arch_mode` | `Mode` (X86_16/32/64, Thumb, Aarch64, MIPS16/32/64, …) | Multi-mode arch enumeration with `pointer_size()` |
| `platform_event_bus` | `platform_bus()`, `platform_dispatcher()`, `platform_logger()`, `publish()`, `register_hook()` | Process-wide event bus singletons (wraps rustre-events) |

### Key Public API (excerpt)

```rust
// Loader trait — every binary format implements this.
#[async_trait]
pub trait Loader: Debug + Send + Sync {
    fn name(&self) -> &'static str;
    fn can_load(&self, input: &LoaderInput) -> bool;
    async fn load(&self, input: LoaderInput) -> Result<LoadResult>;
    async fn find_nested(&self, input: &LoaderInput) -> Result<Vec<NestedBinary>>;
}

// Architecture trait.
pub trait Architecture: Debug + Send + Sync {
    fn name(&self) -> &'static str;
    fn pointer_size(&self) -> usize;
    fn endian(&self) -> Endian;
    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction>;
    fn get_branches(&self, instr: &Instruction) -> Vec<BranchInfo>;
    fn registers(&self) -> Vec<RegisterInfo>;
    fn calling_conventions(&self) -> Vec<CallingConvention>;
}

// Address newtype with arithmetic.
pub struct Address(pub u64);
pub struct AddressRange { start: Address, end: Address }
impl AddressRange {
    pub fn iter(&self) -> impl Iterator<Item = Address>;
    pub fn contains(&self, a: Address) -> bool;
    pub fn overlaps(&self, other: &Self) -> bool;
}

// SegmentMapping — VA <-> file-offset translation.
impl SegmentMapping {
    pub fn va_to_file_offset(&self, va: Address) -> Option<FileOffset>;
    pub fn file_offset_to_va(&self, fo: FileOffset) -> Option<Address>;
}

// PassManager — topological analysis pass ordering with cycle detection.
impl PassManager {
    pub fn register_pass(&mut self, info: AnalysisPassInfo);
    pub fn topological_order(&self) -> Result<Vec<&str>>;
}

// Platform-wide singletons (available anywhere without Arc threading).
pub fn platform_bus() -> &'static EventBus;
pub fn platform_dispatcher() -> &'static HookDispatcher;
pub fn platform_logger() -> &'static EventLogger;
pub fn publish_platform_event(event: CoreEvent);
```

### Intra-Workspace Re-exports

`rustre-core` re-exports `rustre_events`, `rustre_knowledge`, and `rustre_db` wholesale at its crate root, making them available transitively to all dependents without additional `Cargo.toml` entries.

### Integration Points

- All analysis crates (`rustre-il-*`, `rustre-analysis-*`) receive a `BinaryView` and fire `CoreEvent`s.
- `rustre-mcp-server` exposes `rustre-core` types over the MCP protocol.
- `rustre-project` wraps `rustre-core`'s `BinaryView` inside persistent SQLite storage.
- `rustre-mem` implements `MemoryProvider` from `rustre-core::traits`.

---

## 3. rustre-events

**Path:** `crates/rustre-events/`  
**Status:** COMPLETE — rich implementation, no stubs found.

### Purpose

Platform-wide event bus for decoupled subsystem communication. All subsystems (loaders, debuggers, analysis passes, AI agents) publish `CoreEvent` values; consumers subscribe without tight coupling.

### Key Types

| Type | Description |
|---|---|
| `CoreEvent` (enum, `#[non_exhaustive]`) | ~50 variants covering every observable RE operation |
| `EventKind` | Coarse category: View, Analysis, Function, Symbol, Debugger, Memory, Type, Patch, Annotation, Agent, CrossRef, Script, Plugin, Custom |
| `EventBus` | `tokio::sync::broadcast` channel with capacity 1024; per-variant counter map |
| `FilteredSubscription` | Wraps a receiver with a `Fn(&CoreEvent) -> bool` predicate |
| `EventFilter` | Composable predicate with `and()`, `or()`, `negate()` |
| `EventHook` | Synchronous callback triggered on matching events |
| `HookDispatcher` | Manages a `Vec<EventHook>` under `RwLock` |
| `EventLogger` | Ring-buffer (VecDeque) audit trail; `start_logging()` spawns Tokio background task |
| `EventReplay` | Record + replay events onto any bus |
| `EventCorrelator` | Groups events by user-supplied key (e.g. `by_view()`, `by_variant()`) |
| `EventStats` | Per-variant and per-kind counters |
| `SpecEventBus` | Spec §2.10 bus: wraps broadcast channel + 1000-event history ring-buffer |
| `SpecCoreEvent` | Spec §2.10 variant set with exact field names (`addr`, `path`, …) |

### CoreEvent Variant Categories

```
View lifecycle:       ViewOpened, ViewClosed, ViewSaved
Analysis:             AnalysisStarted, AnalysisProgress, AnalysisCompleted, AnalysisFailed
Functions:            FunctionDefined, FunctionRenamed, FunctionDeleted, FunctionCommented, FunctionTagged
Symbols:              SymbolDefined, SymbolDeleted, SymbolImported
Debugger:             DebuggerAttached/Detached, BreakpointHit/Set/Cleared, ProcessExited,
                      ThreadCreated/Exited, StepComplete, RegisterChanged
Memory:               MemoryRead, MemoryWritten, MemoryPatched, MemoryMapped
Types:                TypeDefined, TypeUpdated, TypeDeleted, TypeImported
Patches:              PatchApplied, PatchReverted
Annotations:          CommentAdded/Removed, BookmarkAdded/Removed
AI/Agent:             AgentAction, AgentError, AgentStarted, AgentStopped
Cross-references:     XrefAdded, XrefRemoved
Script:               ScriptExecuted
Plugin:               PluginLoaded, PluginUnloaded, PluginError
Custom:               Custom { event_type, payload: Value }
```

### Convenience API

```rust
let bus = EventBus::new_default();  // capacity = 1024
let mut rx = bus.subscribe();       // broadcast::Receiver<CoreEvent>

bus.send_function_defined(view_id, 0x1000, "main".into());
bus.send_analysis_progress(view_id, "cfg-build".into(), 50);

// Filtered subscription — only events for a specific view.
let mut filtered = view_subscription(&bus, 42);
let event = filtered.recv_filtered().await; // skips all other views

// Hook: synchronous callback for critical path.
let hook = EventHook::new("log-functions",
    |e| matches!(e, CoreEvent::FunctionDefined { .. }),
    |e| println!("new function: {e}"),
);
```

### Sub-modules

- `bus_impl` — alternative bus implementation
- `event_driven_analysis` — analysis triggers wired to events
- `event_filter` — composable filter types
- `event_dispatcher` — async dispatcher
- `event_recorder` — structured recording
- `event_replay` / `event_replay_advanced` — replay infrastructure
- `event_schema` — schema validation helpers
- `event_types` — additional type definitions

---

## 4. rustre-db

**Path:** `crates/rustre-db/`  
**Status:** COMPLETE — full SQLite layer with migrations, event sourcing, indexes, query builder.

### Purpose

SQLite-backed persistence layer. Provides a connection pool, versioned schema migrations, an append-only event store, an index manager, and a composable query builder. Used by `rustre-project` for all on-disk state.

### Public API

| Export | Description |
|---|---|
| `Database` | Connection pool; `DbConfig` controls path and pool size |
| `DbLocation` | `InMemory` or `File(PathBuf)` |
| `Connection` | RAII connection handle |
| `Transaction` | RAII transaction with commit/rollback |
| `DbError` | Unified error type (wraps `rusqlite::Error`) |
| `DbMigrationManager` | Runs versioned `Migration` steps; `MigrationReport` |
| `run_migrations(conn)` | Free function entry point for schema setup |
| `base_migrations()` | Base knowledge-graph schema (nodes, edges tables) |
| `apply_base_schema(conn)` | Convenience wrapper |
| `EventStore` | Append-only event table; `NewEvent` to `StoredEvent` |
| `DbIndexManager` | Create/drop indexes by `IndexDef`; `IndexKind` (BTree/Hash/FTS5) |
| `create_index(conn, def)` | Free function |
| `DbQueryBuilder` | Composable `SELECT ... WHERE ... ORDER BY ... LIMIT` |
| `build_select(table, params)` | Free function |

### Schema (base)

The base schema (from `db_schema`) provides:
- `knowledge_nodes(id, kind, label, metadata_json, created_at, updated_at)`
- `knowledge_edges(id, from_node, to_node, relation, weight, created_at)`
- `events(id, kind, payload_json, created_at)`

The `rustre-project` crate layered its own richer schema on top (see section 7).

### Integration

Used directly by `rustre-knowledge` (`KnowledgeStore` with `JsonBackend`) and `rustre-project` (its own SQLite schema with 4 migration versions). `rustre-core` re-exports the entire crate.

---

## 5. rustre-knowledge

**Path:** `crates/rustre-knowledge/`  
**Status:** COMPLETE — knowledge graph entities, store, query, import/export/merge.

### Purpose

In-process knowledge graph (P4 layer). Stores reverse-engineering entities as nodes and directed edges. Provides import (JSON), export (JSON/other formats), merge (conflict resolution), and query primitives.

### Core Graph Types

```rust
pub struct KnowledgeNode {
    pub id: String,
    pub label: String,
    pub kind: String,                          // "function", "type", "variable", "module"
    pub metadata: HashMap<String, Value>,
}

pub struct KnowledgeEdge {
    pub from: String,
    pub to: String,
    pub relation: String,                      // "calls", "references", "contains"
    pub weight: Option<u32>,
}

pub struct KnowledgeGraph {
    pub nodes: HashMap<String, KnowledgeNode>,
    pub edges: Vec<KnowledgeEdge>,
}

impl KnowledgeGraph {
    pub fn add_node(&mut self, node: KnowledgeNode);
    pub fn add_edge(&mut self, edge: KnowledgeEdge);
    pub fn outgoing(&self, node_id: &str) -> Vec<&KnowledgeEdge>;
    pub fn incoming(&self, node_id: &str) -> Vec<&KnowledgeEdge>;
}
```

### RE-Specific Entity Types (from `entities` module)

```rust
pub struct Function { pub id: EntityId, pub address: Address, pub name: String, … }
pub struct Symbol   { pub id: EntityId, pub address: Address, pub name: String, pub scope: SymbolScope, … }
pub struct TypeDef  { pub id: EntityId, pub name: String, pub kind: TypeKind, … }
pub struct Xref     { pub from: Address, pub to: Address, pub kind: XrefKind, … }
pub struct Comment  { pub address: Address, pub text: String, pub scope: CommentScope, … }
pub struct Bookmark { pub address: Address, pub label: String, … }
pub struct Patch    { pub address: Address, pub original: Vec<u8>, pub patched: Vec<u8>, … }
```

### Store / Persistence

```rust
pub trait PersistBackend: Send + Sync {
    fn load(&self) -> Result<KnowledgeGraph, StoreError>;
    fn save(&self, graph: &KnowledgeGraph) -> Result<(), StoreError>;
}

pub struct JsonBackend { path: PathBuf }   // serializes to .json file
pub struct NullBackend;                    // no-op (in-memory only)

pub struct KnowledgeStore<B: PersistBackend> { graph, backend }
pub struct Transaction { … }              // batched mutation + commit
```

### Import / Export / Merge

```rust
// Import
pub fn import_from_json(json: &str) -> Result<KnowledgeGraph, …>;

// Export
pub enum ExportFormat { Json, Dot, Csv }
pub fn export_to_json(graph: &KnowledgeGraph) -> Result<String, …>;

// Merge
pub enum MergeStrategy { LastWins, FirstWins, Union }
pub fn merge_graphs(base: KnowledgeGraph, incoming: KnowledgeGraph, strategy: MergeStrategy)
    -> Result<MergeResult, …>;
```

### Event Log

```rust
pub struct KnowledgeEvent { pub id: Uuid, pub kind: EventPayload, pub timestamp: … }
pub enum EventPayload {
    NodeAdded(KnowledgeNode), EdgeAdded(KnowledgeEdge),
    NodeRemoved(String), EdgeRemoved { from: String, to: String },
    MetadataUpdated { node_id: String, key: String, value: Value },
}
pub struct EventLog { events: Vec<KnowledgeEvent> }
```

---

## 6. rustre-mem

**Path:** `crates/rustre-mem/`  
**Status:** COMPLETE — 35 modules covering every memory abstraction needed by a RE platform.

### Purpose

Memory provider abstraction layer: virtual/physical/process/emulated/trace memory with CoW overlays, patches, caching, snapshots, entropy, search, and diff. Implements `MemoryProvider` from `rustre-core::traits`.

### Module Map

| Module | Key Types | Description |
|---|---|---|
| `memory_provider` | `MemoryProvider` (trait), `MemoryRegion`, `MemError`, `RegionSource`, `SnapshotId` | Core trait: `read()`, `write()`, `regions()` |
| `virtual_memory` | `VirtualMemoryProvider` | BTreeMap-backed synthetic regions; `map()`, `unmap()` |
| `process_memory` | `ProcessMemoryProvider` | Live process memory via OS APIs |
| `emulated_memory` | `EmulatedMemoryProvider` | Emulator-backed memory |
| `file_memory` | `FileMemoryProvider` | Memory-mapped file backend |
| `null_memory` | `NullMemoryProvider` | Always-fails provider (sentinel) |
| `patched_memory` | `PatchedMemoryProvider`, `Patch` | Intercept reads with patch overlay |
| `composite_memory` | `CompositeMemoryProvider` | Priority-ordered provider list (first wins) |
| `cow` | `CowMemoryProvider` | Copy-on-write overlay |
| `sparse` | `SparseMemoryProvider`, `LargeWindowProvider` | Sparse address space |
| `cache` / `cache_layer` | `PageCache`, `CacheStats` | LRU page cache |
| `snapshot` / `snapshot_diff` | `SnapshotStore`, `MemorySnapshot`, `SnapshotDiff`, `MemoryChange` | Point-in-time snapshots and diffs |
| `trace_memory` / `trace_provider` | `TraceMemoryProvider`, `TracePosition`, `SnapshotCache`, `DeltaReplay` | TTD-style time-travel memory |
| `search` | `MemorySearcher`, `BytePattern`, `PatternByte`, `SearchResult` | Byte pattern search with wildcards |
| `entropy` | `EntropyBlock`, `shannon_entropy()`, `entropy_blocks()` | Shannon entropy per region/block |
| `diff` | `DiffSpan`, `diff_providers()` | Compare two providers byte-by-byte |
| `region` | `RegionSet`, `ExtendedRegion`, `RegionKind`, `RegionAttributes` | Region classification |
| `access_log` | `AccessLog`, `AccessRecord`, `AccessKind`, `LoggingMemoryProvider` | Audit trail of read/write accesses |
| `arena` | `MemoryArena`, `ArenaAlloc`, `ArenaMark` | Bump allocator over a provider |
| `phys` | `PhysicalMemory`, `FlatPhysMemory`, `MemMap`, `PageInfo`, `PageFlags` | Physical memory map |
| `permissions_model` | `ExtendedPerms`, `RelroStatus`, `PermissionAuditLog`, `infer_relro_status()` | Extended permission model |
| `memory_analysis` | `MemoryAnalysis`, `RegionClassifier`, `StringScanner`, `PointerScanner` | High-level memory analysis |
| `memory_diff` | `MemoryDiff`, `DiffEntry`, `DiffRegion` | Structured diff |
| `memory_layout_analyzer` | `MemoryLayoutAnalyzer`, `LayoutReport` | Layout pattern recognition |
| `composite_provider` | `EnhancedCompositeProvider`, `ProviderLayer`, `WriteStrategy` | Advanced composite with write strategies |
| `patched_provider` | `EnhancedPatchedMemoryProvider`, `PatchOverlay`, `PatchExport`, `PatchConflict` | Enhanced patch provider |
| `helpers` | `read_u8_at`, `read_u16_le_at` through `write_u64_le_at`, `search_bytes_with_mask` | Typed accessor helpers |

### Core Trait

```rust
pub trait MemoryProvider: Send + Sync {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError>;
    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError>;
    fn regions(&self) -> Vec<MemoryRegion>;
}

// Extension trait (blanket impl):
pub trait MemoryProviderExt: MemoryProvider {
    fn read_u32_le(&self, addr: Address) -> Option<u32>;
    fn read_u64_le(&self, addr: Address) -> Option<u64>;
    fn find_bytes(&self, pattern: &[u8], start: Address) -> Option<Address>;
    fn stats(&self) -> MemoryStats;
}
```

### Windows-Specific Dependencies

The `process_memory` module conditionally links `windows-sys` with:
- `Win32_Foundation`, `Win32_System_Diagnostics_Debug`, `Win32_System_Memory`, `Win32_System_Threading`

### Integration Points

- `rustre-debug-*` crates use `MemoryProvider` to read debugged-process memory.
- `rustre-il-lift` reads instruction bytes from a provider.
- `rustre-forensics-mem` wraps process/physical memory providers.
- `rustre-symb-*` use providers for symbolic analysis.

---

## 7. rustre-project

**Path:** `crates/rustre-project/`  
**Status:** COMPLETE — fully functional SQLite-backed project management.

### Purpose

Persists all RE session state to disk inside a `.rustre-project/` directory. Manages binaries, functions, xrefs, symbols, types, comments, bookmarks, strings, patches, scripts, notes, layout, undo log, triage results, and version snapshots. Provides collaborative delta export/import.

### Project Directory Layout

```
<root>/
  .rustre-project/
    meta.json          -- ProjectMetadata + ProjectConfig (JSON)
    project.db         -- SQLite DB (WAL mode, foreign keys ON)
    recordings/        -- TTD recordings
    sandbox/           -- sandbox execution artifacts
    attachments/       -- binary files
    workflows/         -- agent workflows
    scripts/           -- saved scripts
    reports/           -- generated reports
    views/             -- per-binary view state
    snapshots/         -- SQLite snapshot blobs
```

### Database Schema (4 migration versions)

**Version 1 — Core tables:**

| Table | Key Columns |
|---|---|
| `binaries` | `id, sha256, path, format, arch, size_bytes, entry_point, base_addr` |
| `functions` | `id, binary_id, addr, name, size_bytes, is_thunk, calling_conv, return_type, flags` |
| `basic_blocks` | `id, function_id, addr, size_bytes, flags` |
| `edges` | `binary_id, src_addr, dst_addr, edge_type` |
| `xrefs` | `binary_id, from_addr, to_addr, xref_type` |
| `symbols` | `binary_id, addr, name, symbol_type, source, mangled` |
| `types` | `binary_id, name, kind, definition, size_bytes` |
| `variables` | `function_id, name, var_type, storage, offset` |
| `comments` | `binary_id, addr, body, comment_type, author` |
| `bookmarks` | `binary_id, addr, label, color` |
| `strings` | `binary_id, addr, value, encoding, length` |
| `annotations` | `binary_id, addr, kind, body, author` |
| `events` | `binary_id, kind, payload, occurred_at` |
| `undo_log` | `session_id, seq, table_name, operation, row_id, before_json, after_json` |
| `scripts` | `name, language, body` |
| `notes` | `title, body` |
| `patches` | `binary_id, addr, original_bytes, patched_bytes` |
| `version_history` | `binary_id, snapshot_data (BLOB), description` (max 10 snapshots per binary) |
| `layout_state` | Singleton row, `layout_json` |

**Version 2:** Performance indexes on all foreign keys and name columns.  
**Version 3:** FTS5 virtual table `strings_fts` with INSERT/DELETE/UPDATE triggers for full-text string search.  
**Version 4:** `triage_results(binary_id, scanner, verdict, score, details)`.

### Public API (Project struct)

```rust
pub struct Project { root_dir, metadata, config, db_conn: Arc<Mutex<Connection>>, … }

impl Project {
    pub fn new(name, root_dir) -> Result<Self>;
    pub fn open(root_dir) -> Result<Self>;
    pub fn save(&self) -> Result<()>;
    pub fn maybe_autosave(&mut self) -> Result<bool>;      // 5-min interval by default

    // Binary management
    pub fn add_binary_from_path(&self, path) -> Result<BinaryEntry>;
    pub fn list_binaries(&self) -> Vec<BinaryEntry>;
    pub fn find_binary_by_sha256(&self, sha256) -> Result<Option<BinaryEntry>>;
    pub fn remove_binary(&self, binary_id) -> Result<bool>;
    pub fn import_binary_with_debug(&self, path) -> Result<BinaryEntry>;  // stub: auto-finds .pdb/.dSYM

    // Function management
    pub fn add_function_record(&self, binary_id, addr, name) -> Result<u64>;
    pub fn get_function_by_addr(&self, binary_id, addr) -> Result<Option<FunctionEntry>>;
    pub fn list_functions(&self, binary_id) -> Vec<FunctionEntry>;
    pub fn rename_function(&self, binary_id, addr, new_name) -> Result<bool>;

    // Annotations
    pub fn add_comment_record(&self, binary_id, addr, text) -> Result<()>;
    pub fn add_bookmark(&self, binary_id, addr, label, color) -> Result<()>;

    // Xrefs
    pub fn add_xref_record(&self, binary_id, from, to, kind) -> Result<()>;
    pub fn xrefs_to(&self, binary_id, addr) -> Vec<(u64, u64, String)>;
    pub fn xrefs_from(&self, binary_id, addr) -> Vec<(u64, u64, String)>;

    // Strings (FTS5)
    pub fn add_string(&self, binary_id, addr, value, encoding) -> Result<()>;
    pub fn search_strings_fts(&self, binary_id, query) -> Vec<(u64, String)>;

    // Symbols
    pub fn add_symbol(&self, binary_id, addr, name, symbol_type, source) -> Result<()>;
    pub fn search_symbols(&self, binary_id, prefix) -> Vec<(u64, String, String)>;

    // Patches
    pub fn add_patch(&self, binary_id, addr, original, patched, description) -> Result<()>;
    pub fn list_patches(&self, binary_id) -> Vec<(u64, Vec<u8>, Vec<u8>, String)>;

    // Version history (max 10 snapshots, auto-pruned)
    pub fn save_version_snapshot(&self, binary_id, data, description) -> Result<u64>;
    pub fn list_version_snapshots(&self, binary_id) -> Vec<(u64, u64, Option<String>)>;

    // Triage
    pub fn upsert_triage_result(&self, binary_id, scanner, verdict, score, details) -> Result<u64>;
    pub fn list_triage_results(&self, binary_id) -> Vec<TriageResult>;

    // Scripts & notes
    pub fn save_script(&self, name, language, body) -> Result<u64>;
    pub fn get_script(&self, name) -> Result<Option<(String, String)>>;
    pub fn save_note(&self, title, body) -> Result<u64>;

    // Undo log
    pub fn append_undo_entry(&self, session_id, seq, table, op, row_id, before, after) -> Result<()>;

    // Collaboration
    pub fn export_delta(&self, since_ts: u64) -> Vec<EventEntry>;
    pub fn import_delta(&self, events: &[EventEntry]) -> Result<u64>;

    // Layout
    pub fn save_layout(&self, layout_json) -> Result<()>;
    pub fn load_layout(&self) -> Result<Option<String>>;

    // Stats
    pub fn binary_stats(&self, binary_id) -> BinaryStats;
    pub fn export_json(&self, binary_id) -> Result<String>;
}
```

### Supporting Types

```rust
pub struct ProjectMetadata { name, created_at: u64, created_at_iso, version, description, tags, author }
pub struct ProjectConfig   { kg_backend: KgBackend, default_arch, plugins, wal_mode, undo_limit, autosave_interval_secs }
pub enum   KgBackend       { Sqlite { path }, Memory }
pub struct BinaryStats     { function_count, xref_count, symbol_count, comment_count, string_count, bookmark_count }
```

### Sub-modules

| Module | Purpose |
|---|---|
| `analysis_cache` | Cache analysis pass results per binary |
| `annotation_store` | In-memory annotation layer |
| `collaboration` | Real-time collaboration deltas |
| `export` | Multi-format project export (JSON, ZIP) |
| `plugin_manager` | Per-project plugin lifecycle |
| `project_db_extended` | Extended SQL helpers |
| `project_diff` | Structural project diffing |
| `project_migrator` | Schema migration runner |
| `project_serializer` | Serialize project to portable format |
| `project_templates` | New-project templates |
| `search` | Cross-entity full-text search |
| `session` / `session_management` | Session state and multi-session support |
| `workspace` | Multi-project workspace |

---

## 8. rustre-daemon

**Path:** `crates/rustre-daemon/`  
**Status:** COMPLETE — both sync IPC layer and async HTTP/JSON-RPC server fully implemented.

### Note on rustre-bin / rustre-cli

There are **no separate `rustre-bin` or `rustre-cli` crates**. The single binary entry point is `crates/rustre-daemon/src/main.rs`, which supports:

```
rustre-daemon status        -- IPC layer status query
rustre-daemon graph-smoke   -- in-memory KnowledgeGraph smoke test
rustre-daemon serve [FLAGS] -- §35.1 headless HTTP/JSON-RPC server
```

### Architecture

The crate contains two distinct layers.

**Layer 1 — Sync IPC (legacy, `lib.rs`):**

- `Daemon` struct: state machine (`Stopped → Starting → Running → Stopping → Failed`), PID file, signal bus, health checks
- `IpcServer` + `IpcMessage` + `IpcResponse`: TCP line-delimited JSON protocol on port 7777
- `DaemonClient`: reconnecting client helper with `ping()`, `command()`, `request()`
- `LogRotator`: size-triggered log rotation (default 10 MiB, 5 rotated files)
- `HealthCheck` + `HealthCheckResult` + `CheckItem`: pluggable health probes
- `SignalBus`: in-process signal posting (POSIX signal stubs for portability)
- `is_process_running(pid)`: cross-platform (Unix `kill(pid,0)`, Windows `OpenProcess + GetExitCodeProcess`)
- `PidFile`: RAII PID file management with stale-file detection

**Layer 2 — Async HTTP/JSON-RPC (§35.1, `lib.rs` continuation):**

```rust
pub struct HttpDaemonConfig {      // clap-derived + serde
    pub bind_addr: String,         // default "127.0.0.1:7878", env RUSTRE_BIND
    pub mcp_bind: Option<String>,  // env RUSTRE_MCP_BIND
    pub log_level: String,         // env RUSTRE_LOG
    pub project_dir: Option<PathBuf>,
    pub max_connections: u32,      // default 16
    pub auth_token: Option<String>,// env RUSTRE_AUTH_TOKEN
    pub workers: usize,            // tokio threads; 0 = num_cpus
}
```

**JSON-RPC 2.0 methods dispatched:**

| Method | Parameters | Description |
|---|---|---|
| `project.open` | `{ path: string }` | Open project directory; returns `project_id` |
| `project.close` | `{ project_id: string }` | Close an open project |
| `binary.list` | `{ project_id?: string }` | List binaries (scoped or global) |
| `status` | — | Server uptime, project count, request stats |
| `shutdown` | — | Graceful shutdown via broadcast channel |

**ServerState:**
```rust
pub struct ServerState {
    config: HttpDaemonConfig,
    projects: HashMap<String, ProjectHandle>,
    active_sessions: u32,
    total_requests: u64,
    rpc_errors: u64,
    start_time: Instant,
}
```

### Sub-modules

| Module | Purpose |
|---|---|
| `analysis_worker` | Background worker threads with priority queue |
| `api_handler` | HTTP route handlers |
| `auth_manager` | Bearer token auth middleware (`subtle` crate for constant-time compare) |
| `client_handler` | Per-connection handler |
| `config` | Unified config loader (TOML/JSON + CLI merge) |
| `daemon_config` | Extended daemon configuration |
| `daemon_scheduler` | Scheduled task runner |
| `grpc_server` | gRPC server stub (no tonic dep yet) |
| `health_monitor` | Continuous health probing background task |
| `rest_api` | REST endpoint definitions |
| `rpc_server` | JSON-RPC 2.0 over TCP (lower-level, separate from HTTP layer) |
| `session_manager` | Analysis session pool |
| `session_server` | Session multiplexer |

### Dependency on rustre-mcp-server

`Daemon::list_capabilities()` calls `rustre_mcp_server::build_tool_catalog()` to enumerate all MCP tools. This is the primary integration point between the daemon and the MCP layer.

---

## 9. Cross-Crate Integration Map

```
+------------------------------------------------------------------+
|                      rustre-daemon (binary)                       |
|  HTTP/JSON-RPC · IPC server · PID file · health checks           |
+--------+-----------------------+----------------------------------+
         |                       |
         v                       v
+------------------+    +---------------------+
|  rustre-core     |    |  rustre-mcp-server  |
|  (all types)     |<---+  (tool catalog)     |
+------+-----------+    +---------------------+
       |  re-exports
       +------------------+------------------+
       v                  v                  v
+-----------+  +------------------+  +-------------+
| r-events  |  | r-knowledge      |  | r-db        |
| (bus)     |  | (graph + store)  |  | (SQLite)    |
+-----------+  +------------------+  +-------------+
       ^                                    ^
       | fires events                       | backend
       |                            +-------+
+------+---------+                  |
| rustre-project |<-----------------+
| (.rustre-project/ dir)            |
+------+---------+                  |
       | wraps                      |
       v                            |
+-------------+                     |
| rustre-mem  +---------------------+
| (35 modules)|
+-------------+
```

**Event flow (example — binary loaded):**

```
Loader::load() creates BinaryView
  -> platform_event_bus::publish(CoreEvent::ViewOpened)
     -> EventLogger records (ring buffer)
     -> HookDispatcher fires matching hooks
     -> FilteredSubscription receivers unblock
  -> rustre-project::Project::add_binary_from_path() -> SQLite INSERT
  -> AutoAnalysis schedules passes
     -> AnalysisStarted / AnalysisProgress / AnalysisCompleted events fired
```

---

## 10. Implementation Status Summary

| Crate | Source Files | Status | Test Coverage |
|---|---|---|---|
| `rustre-core` | 27 | COMPLETE | Extensive (35+ integration tests in `lib.rs`) |
| `rustre-events` | 11 | COMPLETE | ~40 tests in `lib.rs` |
| `rustre-db` | 7 | COMPLETE | Dev-dep tests with UUID |
| `rustre-knowledge` | 8 | COMPLETE | Functional |
| `rustre-mem` | 35 | COMPLETE | Extensive unit tests in `lib.rs` |
| `rustre-project` | 15 | COMPLETE | Integration tests (tempfile) |
| `rustre-daemon` | 15 + binary | COMPLETE | Unit tests (tempfile) |
| `rustre-bin` | — | DOES NOT EXIST | — |
| `rustre-cli` | — | DOES NOT EXIST | — |

No `todo!()`, `unimplemented!()`, or clearly empty function bodies were found in any of the seven analyzed crates. Implementation is substantive throughout.

---

## 11. Known Gaps & TODOs

### rustre-core

- `traits::Decompiler` and `traits::Debugger` are defined but their implementations in `rustre-decompiler-ghidra` / `rustre-debug-*` are not yet connected to `BinaryView` via any registry.
- `workspace_manager` module exists but is not exposed via the MCP tool catalog.
- `DwarfTypeImporter` in `type_system_full` — integration with `rustre-symbols-dwarf` needs verification.

### rustre-events

- `SpecCoreEvent` duplicates many variants from `CoreEvent` but there are no `From` impl bridges between the two. Code using both buses must manually map variants.
- `event_driven_analysis` module suggests analysis passes should fire reactively on events; whether this is wired into `analysis_pipeline` is unverified.

### rustre-db

- `rustre-project` uses a single `Arc<Mutex<Connection>>` (not a pool). Concurrent writes serialize on the mutex — a pool (e.g. `r2d2`) would be needed for production throughput.
- `EventStore` in `rustre-db` and the `events` table in `rustre-project` are parallel event stores with no synchronization between them.

### rustre-knowledge

- `KnowledgeStore` backends are `JsonBackend` (flat file) and `NullBackend`. An SQLite-backed backend via `rustre-db` is not yet implemented despite the base schema existing.
- `KnowledgeGraph::outgoing()` / `incoming()` are O(E) linear scans — no adjacency index for large graphs.

### rustre-mem

- `process_memory` on Windows uses `windows-sys` raw FFI but is not yet connected to any debugger adapter crate.
- `trace_provider` implements TTD-style replay but integration with `rustre-ttd` / `rustre-ttd-replay` is not verified.
- `memory_layout_analyzer` — no unit tests visible in `lib.rs`; may be partial.

### rustre-project

- `import_binary_with_debug`: PDB/dSYM auto-detection is present but the actual symbol import is a stub (`let _ = pdb_path;` — explicit `rustre-symbols-codeview` call missing).
- `layout_state` table: the `save_layout` SQL references `updated_at` column which is absent from the migration v1 DDL; will fail at runtime.
- Collaboration `import_delta` uses `INSERT OR IGNORE` keyed on `occurred_at` only — not a stable deduplication key across collaborators.
- `BinaryProject` trait is defined but `Project` does not implement it; the separate CRUD methods are the actual API.

### rustre-daemon

- `grpc_server` module exists but `tonic` is absent from `Cargo.toml` — it is a stub skeleton.
- `binary.list` JSON-RPC method returns a stub `ProjectHandle` payload rather than calling `rustre-project::Project::list_binaries()`. The daemon holds project metadata but not live `Project` instances.
- MCP SSE server (`mcp_bind`) is in `HttpDaemonConfig` but the SSE listener code is not present in `lib.rs` — it must live in `rustre-mcp-server`.
- The `http-body-util` / `hyper` HTTP layer is complete; the `rest_api` sub-module likely extends the JSON-RPC surface with pure-REST endpoints not yet documented.
