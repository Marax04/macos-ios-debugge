# rustre-core — Analysis Report

## Purpose
Foundational/infrastructure crate for the RustRE platform. Defines core abstractions
(traits, ID newtypes, address types, error types, event bus, plugin/loader/architecture
registries, binary view model, type system, symbol/xref/function tables, patch/comment/bookmark
stores, analysis-pass pipeline, workspace manager). It does NOT itself implement binary
loaders, disassemblers, or decompilers — it defines the contracts they implement and the
in-memory containers they populate.

Most public items are **types, traits, and small constructors/accessors**, not algorithmic
functions. Only a handful of pure functions are externally verifiable against ground truth.

## Public Surface (modules / re-exports)
- `address` — `Address`, `AddressRange`, `RVA`, `FileOffset`, `SegmentMapping`, translations VA<->file-offset
- `arch` — `Architecture` trait, `Instruction`, `RegisterInfo`, `BranchInfo`, `CallingConvention`, `ArchitectureRegistry`
- `arch_mode` — `Mode` enum (X86_64, X86_32, X86_16, Arm32, Thumb, Aarch64, Mips16, ...)
- `binary_view` / `binary_view_impl` — `BinaryView`, `Memory`, `Segment`, `BinaryViewBuilder`, `FunctionTable`, `XrefIndex`, `PatchSet`, `CommentStore`, `BookmarkSet`, `TypeSystem`
- `endian` — `Endian`, `EndianBuf`, `EndianReader/Writer`, swap helpers, **LEB128 encode/decode**
- `errors` — `CoreError`, `Result<T>`, `ResultExt::attach_context`, `bail_core!`, `ensure_core!`
- `ids` — `FunctionId`, `BasicBlockId`, `SymbolId`, …, `IdAllocator`, `IdPool`, `IdMap`
- `loader` — `Loader` async trait, `LoaderRegistry`, `LoaderInput`, `LoaderOptions`, `BinaryType`, `HintSet`
- `permissions` — `Permissions` bitflags (R/W/X), `MemoryProtection`, `PermissionPolicy`, `InheritFlags`
- `patches` — `Patch`, `PatchSet`, `Comment`, `CommentStore`, `Bookmark`, `BookmarkSet`
- `events` / `event_bus` / `platform_event_bus` — `EventBus`, `CoreEvent`, `EventFilter`, platform singletons (`platform_bus`, `publish`)
- `types` / `type_system_full` — `TypeId`, `TypeKind`, `TypeDef`, `TypeStore`, `TypeSystem` (define/lookup/resolve/merge), `TypeLayout`, `TypePrinter`, `DwarfTypeImporter`
- `symbols` — `SymbolIndex`, `FunctionRegistry`, `BasicBlock`, `XrefStore`, `XrefRecord`, `XrefKind`
- `analysis` / `analysis_pipeline` — `AnalysisPass` trait, `PassManager` (topo-sort + cycle detect), `AnalysisPipeline`, `AutoAnalysis`, `BuiltinPassKind`
- `plugin` / `plugin_context` / `plugin_registry` — `PluginRegistry`, `Plugin`, `PluginContext`, `ViewPlugin`, `PluginMetadata`, `ActionHistory`
- `workspace_manager` — `WorkspaceManager`, `Workspace`, `WorkspaceConfig`, `open_workspace`, `save_workspace`
- `traits` — cross-crate contracts: `MemoryProvider`, `BinaryViewTrait`, `FormatParser`, `Demangler`, `TypeSystem`, `Decompiler`, `Debugger`, `ScriptEngine`, `Visualizer`, `PluginHost`
- `disasm_style` — `DisasmStyle`, `SyntaxFlavor` (Intel/AT&T), `MnemonicCase`
- Constant: `VERSION: &str`

## Externally Verifiable Pure Functions
These are the only items in rustre-core whose output can be checked against an independent
oracle (Python / known-spec); everything else is structural plumbing tested by exercising
the type API.

| Function | Input (semantic) | Output (semantic) | Behavior | Ground truth |
|---|---|---|---|---|
| `encode_uleb128(v: u64)` | unsigned 64-bit int | bytes | DWARF/LEB128 unsigned varint | Python `leb128.u.encode` |
| `decode_uleb128(buf, off)` | bytes + offset | (u64, bytes consumed) | inverse of encode_uleb128 | Python `leb128.u.decode` |
| `encode_sleb128(v: i64)` | signed 64-bit int | bytes | DWARF/LEB128 signed varint | Python `leb128.i.encode` |
| `decode_sleb128(buf, off)` | bytes + offset | (i64, bytes consumed) | inverse of encode_sleb128 | Python `leb128.i.decode` |
| `swap_endian_u16/u32/u64/u128(v)` | unsigned int | byte-swapped int | reverses byte order | Python `int.from_bytes(v.to_bytes(N,'little'),'big')` |
| `EndianBuf::write_u*/read_u*` | int + endian | bytes / int | byte-order-aware I/O | Python `struct.pack/unpack` with `<`/`>` |
| `RVA::resolve(base)` | RVA + base VA | VA | `base + rva` | trivial arithmetic |
| `SegmentMapping::va_to_file_offset` / `file_offset_to_va` | VA or file offset within segment | the other | linear translation across mapped range | trivial arithmetic |
| `Permissions::as_rwx_string()` | bitflags | `"rwx"`-style string | standard r/w/x rendering | spec |
| `MemoryProtection::to_permissions()` | OS protection enum | `Permissions` | platform-specific mapping (e.g. LinuxReadExec → R+X) | platform docs |
| `PassManager::topological_order()` | set of passes with deps | ordered name list or cycle error | Kahn/DFS topo-sort + cycle detect | reference topo-sort |
| `VERSION` | — | crate version string | matches Cargo.toml | trivial |

Non-verifiable-by-oracle but unit-testable via API contract (already covered by in-crate
tests): `PatchSet` add/remove, `CommentStore` add/at/remove, `BookmarkSet` insert/at/remove,
`SymbolIndex::symbols_in_range`, `FunctionRegistry::in_range`, `XrefStore::callers_of/callees_of`,
`IdAllocator`/`IdPool` reuse semantics, `AddressRange::iter`, `DisassemblyContext` IT-block
state machine, `LoaderRegistry::probe`, registries (`register`/`find_by_name`).

## Existing MCP Tools
No MCP tool in `rustre-mcp-tools/src/wire_tools.rs` exposes a rustre-core function
directly. The 21 references are all **type imports** (`Address`, `AddressRange`, `Memory`,
`Segment`, `Permissions`, `FunctionTable`, `FunctionDef`, `Architecture` trait bound) used
to construct test fixtures or parameterize generic helpers in higher-level tools.
rustre-core is consumed as a library substrate, not surfaced as MCP endpoints.

## Validator Strategy
1. **Property-test the verifiable pure functions** against Python oracles:
   - LEB128 encode/decode roundtrip + cross-check vs `leb128` PyPI package across
     boundary values (0, 0x7F, 0x80, 0x3FFF, 0x4000, u64::MAX, i64::MIN/MAX, ±1).
   - Endian swap functions vs `int.from_bytes`/`to_bytes` with reversed order.
   - `EndianBuf` read/write vs Python `struct.pack("<Q", v)` / `struct.pack(">Q", v)`.
2. **Algebraic/inverse checks** (no oracle needed): `SegmentMapping` VA↔file roundtrip,
   `RVA::resolve` linearity, `AddressRange::iter` length == range size.
3. **API-contract tests** for stores/registries: assert documented behaviors (insert →
   contains, remove → !contains, range queries return only intersecting items,
   `PassManager` returns error on cycles, deterministic topo order on DAGs).
4. **Out of scope** for external validation: trait definitions, event-bus plumbing,
   plugin/workspace managers — these are validated by integration with downstream crates
   (rustre-loader, rustre-arch-*, rustre-analysis, etc.).
