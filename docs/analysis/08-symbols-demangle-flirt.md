# RustRE — Symbols, Demangle & FLIRT Subsystem Analysis

**Date:** 2026-07-01  
**Crates covered:** `rustre-symbols`, `rustre-symbols-pdb`, `rustre-symbols-dwarf`,
`rustre-symbols-codeview`, `rustre-symbols-stabs`, `rustre-symb`, `rustre-symb-engine`,
`rustre-symb-taint`, `rustre-symb-z3`, `rustre-demangle`, `rustre-flirt`,
`rustre-flirt-apply`, `rustre-flirt-gen`

---

## 1. Architectural Overview

These 13 crates form three conceptual layers of the reverse-engineering pipeline:

```
┌─────────────────────────────────────────────────────────────┐
│  Layer A — Symbol Extraction (debug-format readers)         │
│  rustre-symbols (shared types + SymbolProvider trait)       │
│  └── rustre-symbols-pdb   (MSF/PDB pure-Rust parser)        │
│  └── rustre-symbols-dwarf (DWARF 4/5 pure-Rust parser)      │
│  └── rustre-symbols-codeview (CodeView 4/7, CV8)            │
│  └── rustre-symbols-stabs  (STABS, ELF .stab/.stabstr)      │
├─────────────────────────────────────────────────────────────┤
│  Layer B — Symbol Analysis (demangling / FLIRT matching)    │
│  rustre-demangle  (multi-ABI demangler)                     │
│  rustre-flirt     (core types, CRC, trie, .sig parser)      │
│  └── rustre-flirt-apply  (apply sigs to a binary)           │
│  └── rustre-flirt-gen    (generate sigs from libraries)     │
├─────────────────────────────────────────────────────────────┤
│  Layer C — Symbolic Execution                               │
│  rustre-symb        (SymExpr AST, SymbolicState, SymEngine) │
│  └── rustre-symb-engine  (worklist executor, VulnDetector)  │
│  └── rustre-symb-taint   (taint bitmask analysis)           │
│  └── rustre-symb-z3      (Z3 SMT backend)                   │
└─────────────────────────────────────────────────────────────┘
```

**Key architectural decision:** `rustre-symbols` deliberately does **not** depend on
any of the `rustre-symbols-*` sub-crates (the note in its Cargo.toml explains the
cycle-breaking rationale). Consumers depend on sub-crates directly and wire them into a
`SymbolTable` at runtime. The `backends::registry()` function provides a descriptor
table for introspection only.

---

## 2. `rustre-symbols` — Unified Symbol Infrastructure

### Purpose
Canonical home for all symbol-related types shared across the workspace. Defines the
`SymbolProvider` trait that every debug-format reader implements, plus the rich
`UnifiedSymbol`/`UnifiedSymbolTable` (spec §7) hierarchy.

### Key Public Types

| Type | Description |
|------|-------------|
| `Symbol` | Low-level canonical record (ELF-style fields: id, name, demangled_name, address, size, kind, binding, visibility, section_index, file_offset, source, source_file, source_line, ordinal, tags) |
| `UnifiedSymbol` | Spec §7 higher-level record adds `module`, `type_id`, `is_external`, `SymbolSource` priority |
| `UnifiedSymbolTable` | BTreeMap<addr, Vec<UnifiedSymbol>> primary + HashMap name index; supports `add_or_upgrade` priority merge |
| `SymbolProvider` (trait) | `name()`, `lookup_name()`, `lookup_address()`, `lookup_nearest()`, `all_symbols()`, `all_functions()`, `source_line_for_address()` |
| `SymbolTable` | Thread-safe aggregator (`RwLock<Vec<Box<dyn SymbolProvider>>>`) with LRU address cache |
| `SymbolStore` | BTreeMap+HashMap in-process store; `insert`, `upsert`, `remove`, `rename`, floor lookup, CSV/MAP export |
| `SymbolFilter` | Builder for filtered queries (addr range, kinds, name prefix, sources, section, max results) |
| `AddressToSymbolMap` | Sorted `Vec<(u64, Symbol)>` with binary-search `lookup_exact` / `lookup_floor` |
| `SymbolCache` | Manual LRU cache (Vec-based, O(n) touch; suitable for small hot sets) |
| `SymbolResolver` | Chain of providers, first-match semantics |
| `SymbolConflictResolver` | Strategies: `PreferDebug`, `PreferExport`, `KeepFirst`, `KeepLast`, `KeepAll` |
| `SyntheticSymbolGen` | Generates `sub_XXXX` / `byte_XXXX` placeholder names |
| `SymbolExporter` | Serializes to JSON, CSV, IDA-IDC `.idc`, `.map` |
| `SymbolStats` | Per-kind counts (functions, data, labels, sections, …) |
| `ExportTable` / `ImportTable` | Filtered views, ordinal/name lookup |
| `SectionSymbols` | Symbols grouped by section index |
| `FunctionBoundary` | Half-open `[start, end)` range with `contains` / `overlaps` |
| `TypeInfo` | Recursive type enum (Void, Int, Float, Pointer, Array, Struct, Enum, Function, Named, Unknown) |
| `SourceLocation` | file:line:col |
| `SymbolSource` | Enum with `priority()` method (Manual=100, PDB/DWARF/CodeView=90, Stabs=80, Flirt=70, …) |

### Module Structure (18 public modules)

```
rustre-symbols/src/
  lib.rs                   — all core types (2870 lines)
  codeview_provider.rs     — CodeView SymbolProvider adapter
  dwarf_provider.rs        — DWARF SymbolProvider adapter
  elf_provider.rs          — ELF symbol table SymbolProvider
  pdb_provider.rs          — PDB SymbolProvider adapter
  stabs_provider.rs        — STABS SymbolProvider adapter
  symbol_cross_ref.rs      — cross-reference tracking
  symbol_demangler.rs      — demangling pipeline wrapper
  symbol_merger.rs         — merge/dedup helpers
  symbol_resolution.rs     — resolution strategies
  symbol_table_builder.rs  — builder pattern for SymbolTable
  symbol_exporter.rs       — export formats
  symbol_importer.rs       — import from external formats
  symbol_search.rs         — search/query helpers
  symbol_versioning.rs     — versioned symbols (ELF versioning)
  symbol_address_resolver.rs — address→symbol resolution
  symbol_enrichment.rs     — enrichment pipeline
  pdb_discovery.rs         — auto-locate .pdb for a .exe
```

### Implementation Status: **COMPLETE (core) / PARTIAL (modules)**

The core `lib.rs` is fully implemented with working code and comprehensive tests.
Provider adapters in the individual modules delegate to the sub-crates. The
`DemanglerPipeline` referenced in the doc-comment is present as `symbol_demangler.rs`
but its connection to `rustre-demangle` is through the adapter modules, not a direct dep.

### Notable Design Points
- `SymbolSource::priority()` drives `UnifiedSymbolTable::add_or_upgrade` — PDB/DWARF
  always wins over Flirt or inferred names.
- `SymbolCache` is a naive LRU (linear scan); acceptable for hot-100 use, not for
  mass lookups. `SymbolStore` is the right structure for that.
- `backends::registry()` returns descriptors but **no actual types** due to the dep-cycle
  break; consumers must import sub-crates directly.

---

## 3. `rustre-symbols-pdb` — Pure-Rust PDB/MSF Parser

### Purpose
Parse Microsoft PDB (Program Database) files without the `pdb` crate. Implements the
full MSF (Multi-Stream File) container, DBI, TPI, and per-module symbol streams.

### Internal Architecture

```
parse_superblock()          MSF v7 magic + block directory
  └── build_stream_map()    Reassemble all named streams from block lists
       ├── PDB Info (s1)    GUID, Age via parse_info_stream()
       ├── TPI (s2)         Type records via parse_tpi_stream()
       ├── DBI (s3)         parse_dbi_header() + parse_dbi_modules_ext()
       │    └── per-module streams → extract_procs_from_module_stream()
       └── Global Symbol s  parse_symbols_from_stream() / parse_symbols_with_segment_from_stream()
```

### Key Types

| Type | Fields |
|------|--------|
| `PdbReader` | `streams: HashMap<u32, Vec<u8>>`, `guid: PdbGuid`, `age: PdbAge` |
| `PdbSymbol` | `name, address: u64, size: u32, kind: SymbolKind` |
| `PdbType` | `name, kind: TypeKind, size: u32` |
| `PdbModule` | `name, object_file, stream_index: u16` |
| `PdbModuleProc` | `name, segment: u16, code_offset: u32, code_size: u32` |
| `PdbGuid` | `data: [u8; 16]` + `to_string_fmt()` |
| `PdbStreamInfo` | Version, signature, age, GUID (from `PdbStreamReader`) |

### Symbol Record Support

| CV Record | Parsed |
|-----------|--------|
| `S_PUB32` (0x110E) | Yes — flags + offset + segment + name |
| `S_GPROC32` (0x1110) | Yes — size, offset, segment, name |
| `S_LPROC32` (0x1108) | Yes |
| `S_GPROC32_ID` (0x1147) | Yes (Rust MSVC backend emits these) |
| `S_LPROC32_ID` (0x1146) | Yes |
| `S_GDATA32` (0x110D) | Yes |
| `S_LDATA32` (0x1107) | Yes |
| `S_LABEL32` (0x1105) | Yes |
| `S_THUNK32` (0x1102) | Yes (incl. in module streams) |

### Key API

```rust
let reader = PdbReader::open(Path::new("foo.pdb"))?;
let symbols   = reader.symbols();                // global symbol stream
let seg_syms  = reader.symbols_with_segment();   // (seg, offset, name, kind)
let mod_procs = reader.module_proc_symbols();    // per-module S_GPROC32 etc.
let types     = reader.types();                  // TPI stream
let modules   = reader.modules();                // DBI module list
```

`symbols_with_segment()` and `module_proc_symbols()` return the segment+offset pair
that the caller must convert to VA using the binary's section table. The MCP wire
layer handles this conversion in `rustre-mcp-server`.

### TPI Type Records

| LF code | Parsed |
|---------|--------|
| `LF_STRUCTURE` / `LF_CLASS` | Struct with field count + name |
| `LF_UNION` | Union |
| `LF_ENUM` | Enum with variant count |
| `LF_POINTER` | Pointer (generic) |
| `LF_ARRAY` | Array (generic) |
| `LF_PROCEDURE` | Function type |
| Primitives (0x01–0xFF) | void, bool, i8–i64, u8–u64, f32, f64 |

**Known gap:** Field types and member names are not extracted per-field; struct fields
are synthesised as `field_0 .. field_N`. Full field layout reconstruction is a
future TODO.

### Additional Modules (16 total)
`build_info`, `global_symbols`, `gsi_stream`, `line_info`, `pdb_stream_parser`,
`pdb_dbi_stream`, `pdb_gsi`, `module_symbols`, `pdb_type_info`, `section_contributions`,
`stream_reader`, `tpi_types`, `type_info`, `pdb_dbi_reader`, `pdb_publics_reader`,
`pdb_source_lines`, `pdb_line_info`, `pdb_omap`, `pdb_symbol_info`

### Implementation Status: **PARTIAL → COMPLETE for symbol extraction**
Core path (`symbols_with_segment` + `module_proc_symbols`) is complete and tested.
OMAP address translation (`pdb_omap`), section-contribution tables, and per-field
type member resolution are partial/stub.

---

## 4. `rustre-symbols-dwarf` — Pure-Rust DWARF Parser

### Purpose
Parse DWARF 4/5 debug information from ELF binaries (32-bit and 64-bit LE).
Extracts functions, variables, types, and source-line mappings without the `gimli`
crate in the main parsing path (though `gimli` is listed as a dependency and used
for the `DwarfSymbolProvider` in the parent crate's adapter).

### Implementation: Full Custom Parser

The `lib.rs` (3853 lines) implements the entire DWARF parsing stack from scratch:

- **ELF section extractor** — 32/64-bit LE ELF section headers
- **Abbreviation table parser** — ULEB128 codes, tag/attr pairs, `DW_FORM_implicit_const`
- **Attribute value reader** — all standard `DW_FORM_*` variants including EXPRLOC, BLOCK*, INDIRECT, STRP, LINE_STRP, ADDRX, STRX
- **DIE tree builder** — recursive descent with `DieParseCtx`, handles has_children
- **Function extractor** — `DW_TAG_subprogram` → `DwarfFunction` (low_pc, high_pc, params, return_type)
- **Variable extractor** — `DW_TAG_variable` / `DW_TAG_formal_parameter` with `DW_AT_LOCATION` decode
- **Type extractor** — base/pointer/typedef/struct/union/array types
- **Line program** — full DWARF line-number state machine (standard + extended + special opcodes), DWARF 4 `max_ops_per_insn`

**Notable unsafe:** Two `unsafe` blocks for the `gimli`-backed `DwarfSymbolProvider`
(stored alongside its `Box<[u8]>` buffer, with documented drop order invariant).

### Key Types

| Type | Description |
|------|-------------|
| `DwarfReader` | Main entry point; `open(path)`, `from_bytes(raw)`, `from_sections(map)` |
| `DwarfFunction` | `name, low_pc, high_pc, parameters: Vec<DwarfVariable>, return_type: Option<String>` |
| `DwarfVariable` | `name, type_name, location: DwarfLocation` |
| `DwarfType` | `name, byte_size, tag: DwarfTypeTag` |
| `LineEntry` | `address, file, line, column` |
| `DwarfLocation` | `Register(u32)`, `MemoryOffset{register,offset}`, `Constant(u64)`, `Unknown` |

### Key API

```rust
let reader = DwarfReader::open(path)?;
let fns    = reader.functions();   // Vec<DwarfFunction>
let vars   = reader.variables();   // Vec<DwarfVariable>
let types  = reader.types();       // Vec<DwarfType>
let lines  = reader.line_info();   // Vec<LineEntry>
```

### Additional Modules (14)
`dwarf_abbrev`, `dwarf_call_frame`, `dwarf_expression_evaluator`, `dwarf_line_program`,
`dwarf_location_expr`, `dwarf_type_decoder/parser/reader`, `dwarf_unwind`,
`line_program`, `location_expr`, `split_dwarf`, `type_units`, `casts`

### Implementation Status: **COMPLETE for ELF/DWARF 4/5 LE**
Gaps: Mach-O support absent; DWARF 5 `.debug_addr` / `.debug_loclists` not fully
integrated; `DW_AT_SPECIFICATION` cross-reference resolution is noted but deferred.

---

## 5. `rustre-symbols-codeview` — CodeView Parser

### Purpose
Parse CodeView 4.0/7.0 and CV8 debug streams (found in PE `.debug$S` sections and
embedded in PDB module streams). Implements `SymbolProvider` directly.

### Supported Structures
- Signatures: NB09 (CV 4.1), NB10 (CV 5.0), NB11 (CV 7.0), RSDS/PDB 7.0, CV8
- Symbol records: `S_PUB32`, `S_LPROC32`, `S_GPROC32`, `S_GDATA32`, `S_LDATA32`,
  `S_LOCAL`, `S_REGREL32`, `S_COMPILE3`, `S_LABEL32`, `S_THUNK32`
- Type records: `LF_CLASS`, `LF_STRUCTURE`, `LF_ENUM`, `LF_PROCEDURE`, `LF_POINTER`,
  `LF_ARRAY`, `LF_MODIFIER`, `LF_BITFIELD`, `LF_UNION`, `LF_ARGLIST`, `LF_FIELDLIST`,
  `LF_MEMBER`, `LF_ENUMERATE`
- CV8 line-number tables, source-file name tables
- Full `SymbolProvider` implementation

### Key Types

```rust
pub enum CvSignature { Cv41, Cv50, Cv70, Pdb70, Cv8 }
pub enum CodeViewError { InvalidSignature(u32), UnsupportedVersion(u32),
    RecordTooShort, TruncatedStream, InvalidRecord, TypeIndexOob(u32), … }
pub struct CodeViewProvider  // implements SymbolProvider
```

### Module Structure (13 modules)
`codeview_parser`, `cv_function_info`, `cv_lineinfo`, `cv_stream_parser`,
`cv_symbol_records`, `cv_symbols`, `cv_type_records`, `cv_types`,
`codeview_type_parser`, `codeview_symbol_parser`, `pdb_tpi_reader`, `codeview_types`, `casts`

### Implementation Status: **PARTIAL**
The `CodeViewProvider` implementing `SymbolProvider` exists; full CV8 line-info
integration and type field member extraction are marked as in-progress across the
sub-modules.

---

## 6. `rustre-symbols-stabs` — STABS Parser

### Purpose
Parse the legacy STABS debug format (stored in ELF `.stab` / `.stabstr` sections,
also XCOFF). Targets GCC-compiled Unix/Linux binaries.

### STAB Type Codes Supported
`N_FUN` (0x24), `N_GSYM` (0x20), `N_STSYM` (0x26), `N_SO` (0x64), `N_SOL` (0x84),
`N_SLINE` (0x44), `N_LSYM` (0x80), `N_RSYM` (0x40), `N_PSYM` (0xA0), plus all
remaining standard codes as a 40+ variant `StabType` enum.

### Key Types
```rust
pub enum StabType { NUndf, NGsym, NFun, NStsym, … }  // 40+ variants
pub enum StabsError { InvalidRecord(usize), StringTable(String), Parse(String), TypeParse(String) }
pub struct StabsProvider  // implements SymbolProvider
```

### Module Structure (21 modules)
`stabs_cfparser`, `stabs_complete`, `stabs_full_parser`, `stabs_line_info`,
`stabs_lineinfo`, `stabs_reconstruct`, `stabs_type_reconstructor`, `stabs_types`,
`xcoff_stabs`, `stabs_parser`, `stabs_type_decoder`, `stabs_to_dwarf`,
`stabs_type_parser`, `stabs_scope_tracker`, `stabs_source_mapper`,
`stabs_type_resolver`, `stabs_to_dwarf_converter`

Depends on `rustre-core` and `goblin` for ELF section extraction.

### Implementation Status: **PARTIAL**
STAB record parsing is present; the type descriptor string parser (C++-style
`(N,M):=…` descriptors) is spread across `stabs_cfparser` / `stabs_type_parser`.
The `stabs_to_dwarf_converter` module is a notable addition — it translates STABS
data to a DWARF-like intermediate representation for unified downstream consumption.

---

## 7. `rustre-demangle` — Multi-ABI Symbol Demangler

### Purpose
Unified demangling across all major ABIs. Used by `rustre-symbols-pdb` and the MCP
symbol-lookup tools.

### Supported ABIs

| ABI | Detector | Implementation |
|-----|----------|----------------|
| Itanium (GCC/Clang) | `_Z` / `__Z` prefix | `cpp_demangle` crate + custom normalizer |
| MSVC | `?` prefix | Full manual recursive-descent parser (`MsvcParser`) |
| Rust v0 | `_R` prefix | `rustc-demangle` crate |
| Rust legacy | `_ZN…17h…E` | `rustc-demangle` crate |
| Swift | `_T0` / `$s` / `$S` prefix | Heuristic length-prefix decoder |
| D | (in `d_demangler` module) | Module present |
| Go | (in `go_demangler` module) | Module present |
| Borland | (in `demangler_registry`) | Registry entry |

### Key Types

```rust
pub trait Demangler: Send + Sync {
    fn detect(&self, mangled: &str) -> bool;
    fn demangle(&self, mangled: &str) -> Option<DemanglingResult>;
}

pub struct DemanglingResult {
    pub original: String,
    pub demangled: String,
    pub abi: ManglingAbi,
    pub namespace: Option<String>,
    pub class: Option<String>,
    pub function: String,
    pub args: Vec<String>,
    pub return_type: Option<String>,
}

pub struct AutoDemangler { demanglers: Vec<Box<dyn Demangler>> }
// default order: Rust → Itanium → MSVC → Swift
```

### MSVC Parser Detail
The handwritten `MsvcParser` handles:
- Qualified names with backref compression (0..9)
- Type backref compression (0..9)
- All standard operator encodings (30+ two-char codes)
- RTTI: vftable, vbtable, typeinfo, VTT, `??_R*`
- Calling conventions: `__cdecl`, `__stdcall`, `__thiscall`, `__fastcall`, `__vectorcall`, `__clrcall`
- Pointer/reference/rvalue-ref qualifiers with CV modifiers
- Ctor/dtor name synthesis

The Itanium parser is a full recursive-descent implementation (`ItaniumParser`) with
substitution tables (`S_`, `S0_`, …), operator names, special names (vtable, VTT,
typeinfo), ctor/dtor, cv-qualifiers, template args. It complements the `cpp_demangle`
crate which handles the majority of cases.

### Convenience API
```rust
// Single-call demangling via AutoDemangler
pub fn demangle(s: &str) -> Option<DemanglingResult>

// Parallel bulk demangling (rayon + AHashMap cache)
pub struct BulkDemangler  // in demangler_registry
pub struct DemanglerCache // LRU, in demangler_cache
```

### Module Structure (10 modules)
`cpp_demangler`, `d_demangler`, `demangler_cache`, `demangler_dispatcher`,
`demangler_registry`, `go_demangler`, `itanium_full`, `msvc_demangler`, `msvc_full`,
`rust_demangler`, `swift_demangler`, `demangler_benchmark`

### Implementation Status: **COMPLETE (core paths)**
Itanium + MSVC + Rust (both schemes) are fully working. Swift is heuristic.
D and Go demangling modules exist but are partial. The `demangler_benchmark` module
provides perf measurement infrastructure.

---

## 8. `rustre-flirt` — FLIRT Signature Engine Core

### Purpose
Core types, CRC functions, trie indexer, `.sig` file parser (IDA v5–v10), library
serialization, and the high-level `FlirtMatcher`. All consumers depend on this crate.

### Key Types

| Type | Description |
|------|-------------|
| `FlirtPattern` | `initial_bytes: Vec<PatternByte>`, `crc16`, `crc_length`, `pattern_length`, `names`, `tail_bytes`, `referenced_names` |
| `PatternByte` | `Exact(u8)` or `Wildcard` |
| `FlirtName` | `name, offset: u16, is_public, is_local` |
| `TailByte` | `offset: u16, value: u8` |
| `ReferencedName` | `offset: u16, name: String` |
| `FlirtLibrary` | Named collection with `arch: FlirtArch`, `os: FlirtOs`, `patterns: Vec<FlirtPattern>` |
| `FlirtDatabase` | Modules + 4-byte prefix HashMap index; `candidate_modules(code) → Vec<(module_idx, pat_idx)>` |
| `FlirtTrie` | Recursive trie over `PatternByte` sequences; `find_candidates(buf) → Vec<usize>` |
| `FlirtMatcher` | `add_library`, `match_function(addr, bytes) → Vec<FlirtMatch>`, `match_all`, `best_match` |
| `FlirtMatch` | `address, name, offset, library, confidence: f32, is_public` |
| `SigHeader` | IDA `.sig` header: version, arch, file_types, crc16, library_name, n_functions |
| `FlirtSigFile` | `header + functions: Vec<(SigPattern, SigLeafNode)>` |
| `FlirtArch` | 50+ CPU architectures (X86, X64, ARM, ARM64, MIPS, RISCV, …) |
| `FlirtFileType` | Bitflags: PE, ELF, AR, COFF, … |

### CRC Functions
```rust
pub fn crc16_flirt(data: &[u8]) -> u16  // reversed poly 0x8408, init 0xFFFF
pub fn crc16_ibm(data: &[u8]) -> u16    // poly 0xA001 (IDA .sig files)
```

### Matching Pipeline
```
FlirtMatcher::match_function(addr, bytes)
  → for each library:
      FlirtTrie::find_candidates(bytes) — trie walk, returns Vec<usize>
      for each candidate:
          FlirtPattern::matches_initial(bytes)  — first 32 bytes
          FlirtPattern::matches_crc16(bytes)    — CRC-16 of next N bytes
          FlirtPattern::matches_tail(bytes)     — tail byte discriminators
          → confidence = 1.0 if crc_length > 0, else 0.9
          → emit FlirtMatch per name entry
```

### Library Serialization Format
Text format: header block (FLIRT version, name, arch, os, desc, ---) then one pattern
per line: `<hex> <CRC16> <crc_len> <pat_len> <names> [tail:…] [ref:…]`

```
FLIRT 1
name msvcrt-140
arch x86_64
os windows
desc MSVC runtime CRT
---
55 8B EC .. .. 1234 16 64 memcpy@0+pub
```

### Module Structure (19 modules)
`flirt_engine`, `flirt_library_database`, `function_recognition`, `library_detector`,
`pat_parser`, `signature_matcher`, `signature_matcher_new`, `version_info`,
`flirt_matcher_v2`, `flirt_database`, `flirt_auto_apply`, `pat_parser_v2`,
`sig_matcher`, `flirt_db_builder`, `flirt_signature_writer`, `function_hasher`,
`flirt_index`

### Implementation Status: **PARTIAL**
The core types, CRC, trie, `FlirtMatcher`, library serialize/deserialize, and `.sig`
header parser are **complete**. The `.sig` tree walker (`FlirtSigFile::walk_tree`)
is a **stub** — it uses a heuristic leaf detection and does not recursively decode
the full IDA patricia tree format. Full IDA `.sig` binary tree parsing is a known gap.

---

## 9. `rustre-flirt-apply` — Apply FLIRT Signatures to Binaries

### Purpose
Consume a `FlirtLibrary` (or `.sig` file) and apply it to a binary image, producing
renamed symbols in an `AppliedNamesStore`.

### Key Public Types

```rust
pub struct SignaturePack         // one or more loaded libraries
pub struct AppliedNamesStore     // addr → AppliedName, with CommitStats
pub struct AppliedName { pub name, pub origin: NameOrigin, pub confidence: f32 }
pub struct NamePropagator        // propagate names via XrefGraph
pub struct XrefGraph             // petgraph DiGraph for call-graph name spreading
pub struct FlirtPattern { bytes: Vec<Option<u8>>, name, library }  // local copy
```

### Module Structure (29 modules)
`apply_engine`, `bulk_applier`, `collision_resolution`, `disambig`, `ida_sig_compat`,
`match_scorer`, `pat_parser`, `recognition_session`, `rename_propagator`, `sig_pack`,
`sig_parser`, `sig_priority`, `trie_index`, `flirt_applicator`, `match_validator`,
`batch_applicator`, `name_propagator`, `confidence_scorer`, `batch_applier`,
`applied_names_store`, `match_conflict_resolver`, `sig_file_loader`, `casts`

Notable: `name_propagator` builds an `XrefGraph` (call-graph edges) to spread known
names to unresolved callees — a significant feature beyond simple pattern matching.

### Implementation Status: **PARTIAL**
`AppliedNamesStore`, `NamePropagator`, `SignaturePack`, and `NameConflictResolver`
are structurally complete. The `apply_engine` and `batch_applicator` execution paths
need wire-up to the MCP server's binary-image access.

---

## 10. `rustre-flirt-gen` — Generate FLIRT Signatures from Libraries

### Purpose
Take object files / static libraries on disk and produce `FlirtLibrary` / `.pat` files.
Provides two CLI tools: `rust-stdlib-sigs` and `msvcrt-sigs`.

### Key Types

```rust
pub struct PatternGenerator {
    pub initial_length: usize,  // default 32
    pub crc_length: usize,      // default 16
}
impl PatternGenerator {
    pub fn generate(name, bytes, relocations) -> Result<FlirtPattern, GenError>
    pub fn generate_batch(entries) -> Vec<FlirtPattern>
}

pub struct RelocationEntry { pub offset: u16, pub size: u8 }
pub struct FunctionSample  // (name, bytes, relocations) from library_scanner
```

### Pattern Generation Logic
```rust
PatternGenerator::generate(name, bytes, relocations):
  1. Take initial_length bytes, wildcard relocation ranges
  2. Compute crc16_flirt over bytes[initial_length .. initial_length + crc_length]
  3. Set pattern_length = bytes.len()
  4. Attach FlirtName { name, offset=0, is_public=true, is_local=false }
```

### Module Structure (21 modules + 2 binaries)
`batch_processor`, `compiler_profile`, `pattern_extractor`, `sig_writer`,
`lib_crawler`, `database_builder`, `lib_analyzer`, `library_scanner`,
`pat_sig_format`, `pat_writer`, `pattern_optimizer`, `serializer`, `sig_database`,
`sig_generator`, `signature_extractor`, `signature_index`, `trie_structure`,
`variance_analyzer`, `pat_file_writer`, `signature_deduplicator`

Binaries: `rust-stdlib-sigs` (generate sigs from Rust stdlib), `msvcrt-sigs` (MSVC CRT)

Depends on `object` + `goblin` for ELF/PE/archive parsing, `rustc-demangle` for
Rust symbol normalization.

### Implementation Status: **PARTIAL**
`PatternGenerator` core is complete. `library_scanner`, `lib_crawler`, and
`database_builder` are partially implemented. The two CLI binaries exist but their
internal pipeline completeness varies.

---

## 11. `rustre-symb` — Symbolic Execution Core

### Purpose
Foundational types for symbolic execution: expression AST, type system, symbolic
state (registers + memory + path condition), and the `SymEngine` dispatch trait.

### Key Types

```rust
pub enum SymType { Bool, BitVec(u32), Pointer, Array { elem_ty, len } }

pub enum SymExpr {
    // Literals
    Const(u64, u32),              // value, bit-width
    Var(String, u32),             // name, bit-width
    // Bitvector arithmetic: Add, Sub, Mul, UDiv, SDiv, URem, SRem, Neg
    // Bitwise: And, Or, Xor, Not
    // Shifts: Shl, Lshr, Ashr, Rotl, Rotr
    // Comparisons: Eq, Ne, Ult, Ule, Ugt, Uge, Slt, Sle, Sgt, Sge
    // Extension/extraction: ZeroExt, SignExt, Extract { lo, hi }, Concat
    // Conditional: Ite { cond, then, else_ }
    // Memory: Load { mem, addr, width }, Store { mem, addr, val }
    // Calls: Call { target, args }
}

pub struct SymbolicState {
    pub regs: HashMap<String, SymExpr>,
    pub memory: HashMap<u64, SymExpr>,
    pub path_condition: Vec<SymExpr>,
    pub pc: u64,
}

pub trait SymEngine {
    fn step(&mut self, state: &mut SymbolicState, insn: &Instruction) -> Result<Vec<SymbolicState>, SymbolicError>;
}

pub struct SymExprSimplifier  // algebraic rewrites
```

### Module Structure (18 modules)
`symbolic_memory_model`, `concolic`, `concolic_execution`, `concolic_executor`,
`constraint_propagator`, `explosion_mitigation`, `formula_simplifier`,
`memory_model`, `path_explorer`, `path_explosion`, `smt_formula`,
`vulnerability_finder`, `summary_cache`, `symbolic_execution_engine`,
`symbolic_value`, `symbolic_state`, `constraint_solver`

Feature flag `subcrates` re-exports `rustre_symb_engine::SymbolicExecutor`,
`rustre_symb_taint::TaintState`, `rustre_symb_z3::Z3Solver`.

### SMT Formula Module
`smt_formula.rs` generates SMT-LIB 2.6 output directly from `SymExpr` trees — no
solver dependency required.

### Implementation Status: **PARTIAL**
Core `SymExpr` AST and `SymbolicState` are fully defined. `SymEngine` trait and
`SymExprSimplifier` exist. Concrete implementations live in `rustre-symb-engine`.
The `constraint_solver` module provides a pure-Rust bit-blasting fallback.

---

## 12. `rustre-symb-engine` — Symbolic Execution Engine

### Purpose
Orchestrate multi-state symbolic execution with worklist management, configurable
strategy, vulnerability detection, and function summarization.

### Key Types

```rust
pub enum SolverType { BitBlasting, SmtLib2, Z3 }
pub enum ExplorationStrategy { Dfs, Bfs, RandomWalk, CoverageGuided }

pub struct ExecutorConfig {
    pub max_states: usize,     // default 1024
    pub max_depth: u32,        // default 512
    pub state_merging: bool,
    pub solver: SolverType,
    pub timeout_ms: u64,
    pub strategy: ExplorationStrategy,
}

pub struct SymbolicExecutor { config, state_manager, … }
pub struct StateManager      // VecDeque / BinaryHeap worklist
pub struct VulnDetector      // detect overflow, use-after-free, …
pub struct FunctionSummary   // pre/post-condition pairs
pub struct ReachabilityQuery // can we reach address X?
```

### Module Structure (12 modules)
`concolic_engine`, `exploit_finding`, `loop_summarizer`, `state_manager`,
`path_condition_engine`, `path_manager`, `state_merger`, `path_explorer`,
`symbolic_store`, `symbolic_memory`, `path_condition`, `symbolic_executor`

### Implementation Status: **PARTIAL**
Config types and top-level structs are defined. The `symbolic_executor` and
`state_manager` modules have core infrastructure. Concrete instruction semantics
(x86-64 transfer functions) are the missing link — they depend on `rustre-core`
providing decoded instructions but the wiring is incomplete.

---

## 13. `rustre-symb-taint` — Taint Analysis

### Purpose
Track taint (data provenance) through registers and memory using a u64 bitmask
(64 simultaneous taint sources). Detects dangerous sinks (buffer overflows, format
strings, SQL injection, etc.).

### Taint Bit Definitions
```rust
pub mod taint_bits {
    pub const USER_INPUT: u64   = 1 << 0;
    pub const NETWORK: u64      = 1 << 1;
    pub const FILE: u64         = 1 << 2;
    pub const ENVIRONMENT: u64  = 1 << 3;
    pub const COMMAND_LINE: u64 = 1 << 4;
    pub const REGISTRY: u64     = 1 << 5;
    pub const CUSTOM_BASE: u64  = 1 << 6;  // bits 6–63 for user-defined sources
}
pub type TaintId = u64;
```

### Key Types

```rust
pub struct TaintSourceDef { pub id: TaintId, pub name, pub description }
pub struct TaintState     // regs: HashMap<String, TaintId>, mem: BTreeMap<u64, TaintId>
pub struct TaintSink      // address + sink kind + required taint bits
pub struct TaintGraph     // petgraph DiGraph<TaintNode, TaintEdge>
pub struct TaintReport    // detected flows to sinks
```

### Module Structure (22 modules)
`data_flow_tracker`, `dataflow_taint`, `heap_taint`, `interprocedural`,
`taint_policy`, `taint_propagation_rules`, `taint_report_extended`, `taint_sinks`,
`vuln_reporter`, `taint_sinks_full`, `taint_propagator`, `taint_sink_detector`,
`taint_summary`, `taint_graph`, `sanitizer_detector`, `taint_report_generator`

### Implementation Status: **PARTIAL**
Taint type system and bitmask infrastructure are complete. `TaintGraph` (petgraph-based)
is defined. Propagation rules (`taint_propagation_rules`) and sink detection
(`taint_sink_detector`) exist but need instruction-level wiring.

---

## 14. `rustre-symb-z3` — Z3 SMT Backend

### Purpose
Bridge `SymExpr` expressions to Z3 (via the `z3` crate) for satisfiability checking
and constraint solving. Provides an `async`-capable solver wrapper.

### Key Types

```rust
pub enum SymExpr { Const(u64, usize), Symbol(SymId, usize, String),
    Add, Sub, Mul, UDiv, SDiv, URem, SRem, Neg,
    And, Or, Xor, Not, Shl, Shr, LShr, AShr, Rol, Ror,
    Eq, Ne, Lt, Le, Ult, Ule, Ugt, Uge, Slt, Sle, Sgt, Sge,
    ZeroExt, SignExt, Extract, Concat, Ite, … }

pub struct Z3Solver        // wraps z3::Solver
pub struct PathCondition   // Vec<SymExpr> conjunction
pub struct ConstraintSynthesizer  // infer constraints from observed IO
```

Note: `rustre-symb-z3` defines its **own local `SymExpr`** enum, mirroring (but
slightly differing from) the one in `rustre-symb`. This is a known integration gap —
there is no conversion path between them yet.

### Module Structure (21 modules)
`bitvector_theory`, `constraint_synthesizer`, `formula_cache`, `path_condition`,
`path_condition_manager`, `path_explorer`, `quantifier_elim`, `simplifier`,
`smt_lib_generator`, `symbolic_memory`, `symbolic_state`,
`taint_constraint_tracker`, `theory_array`, `z3_expr_builder`, `z3_integration`,
`z3_formula_builder`, `z3_solver_wrapper`, `z3_expression_simplifier`

### Implementation Status: **STUB/PARTIAL**
The `z3` crate is a workspace dependency and is pulled in. The type definitions and
module scaffolding are present. The actual Z3 solver invocations (`z3_solver_wrapper`,
`z3_integration`) are partial — much of the expression-to-Z3-AST conversion is
written but not wired into the `rustre-symb-engine` executor.

---

## 15. Dependency Graph Summary

```
rustre-core
  └── rustre-symb (SymEngine uses Instruction)
      ├── rustre-symb-engine
      ├── rustre-symb-taint (also → rustre-core)
      └── rustre-symb-z3    (z3 crate, tokio)

rustre-loader-pe
  └── rustre-symbols (SymbolProvider trait + all core types)
      ├── rustre-symbols-pdb     (→ rustre-pe-tools, rustre-demangle)
      ├── rustre-symbols-dwarf   (gimli, object)
      ├── rustre-symbols-codeview
      └── rustre-symbols-stabs   (→ rustre-core, goblin)

rustre-core
  └── rustre-flirt  (Address type)
      ├── rustre-flirt-apply (aho-corasick, ahash)
      └── rustre-flirt-gen   (object, goblin, rustc-demangle)

rustre-demangle (cpp_demangle, rustc-demangle, rayon, ahash, parking_lot)
  └── used by rustre-symbols-pdb
```

---

## 16. Integration Points with Other Subsystems

| Integration | How |
|-------------|-----|
| MCP server (`rustre-mcp-server`) | Calls `PdbReader::symbols_with_segment` + `module_proc_symbols`; calls `AutoDemangler::demangle`; calls `FlirtMatcher::match_all` |
| `rustre-pe-tools` | Provides section table for segment→VA conversion in PDB reader |
| `rustre-loader-pe` | `rustre-symbols` depends on it for PE export/import parsing |
| `rustre-core` | `Address` type consumed by `rustre-flirt`; `Instruction` consumed by `rustre-symb` |
| GUI (`rustre-gui`) | Depends directly on `rustre-symbols-pdb`, `rustre-symbols-dwarf`, etc. |
| `rustre-il` / IL layer | `rustre-symb-engine` will consume IL-lifted instructions; currently wired to `rustre-core::Instruction` |

---

## 17. Known Gaps and Priority TODOs

| Gap | Crate | Severity |
|-----|-------|----------|
| IDA `.sig` binary tree walker is a stub | `rustre-flirt` | HIGH — prevents loading real IDA sigs |
| `rustre-symb-z3` `SymExpr` duplicates `rustre-symb`; no conversion bridge | `rustre-symb-z3` | HIGH — Z3 solver unusable from engine |
| PDB TPI field member names are synthesised (`field_0..N`), not decoded | `rustre-symbols-pdb` | MEDIUM |
| DWARF `DW_AT_SPECIFICATION` cross-reference resolution deferred | `rustre-symbols-dwarf` | MEDIUM |
| `rustre-symb-engine` missing x86-64 instruction transfer functions | `rustre-symb-engine` | HIGH |
| `rustre-flirt-apply` not wired to MCP binary image access | `rustre-flirt-apply` | MEDIUM |
| Mach-O support absent in DWARF reader | `rustre-symbols-dwarf` | LOW (no macOS target binaries) |
| `SymbolCache` uses linear-scan LRU (O(n)); replace with `lru` crate for large workloads | `rustre-symbols` | LOW |
| `backends::registry()` returns descriptors only — no runtime factory | `rustre-symbols` | LOW (by design) |

---

## 18. Implementation Status Summary

| Crate | Status | Notes |
|-------|--------|-------|
| `rustre-symbols` | COMPLETE (core) | 2870-line lib.rs, fully tested |
| `rustre-symbols-pdb` | COMPLETE (symbol extraction) | 1909-line lib.rs, 40+ tests; TPI fields partial |
| `rustre-symbols-dwarf` | COMPLETE (ELF/DWARF 4/5) | 3853-line lib.rs; no Mach-O |
| `rustre-symbols-codeview` | PARTIAL | Provider implemented; CV8 line-info partial |
| `rustre-symbols-stabs` | PARTIAL | Parser present; type reconstruction in progress |
| `rustre-demangle` | COMPLETE (Itanium/MSVC/Rust) | Swift heuristic; D/Go stubs |
| `rustre-flirt` | PARTIAL | Core + trie + library format complete; .sig tree walker stub |
| `rustre-flirt-apply` | PARTIAL | Store + propagator complete; apply engine needs wiring |
| `rustre-flirt-gen` | PARTIAL | Generator complete; CLI binaries partial |
| `rustre-symb` | PARTIAL | AST + state complete; SymEngine concrete impl in engine crate |
| `rustre-symb-engine` | PARTIAL | Config + worklist defined; transfer functions absent |
| `rustre-symb-taint` | PARTIAL | Type system + graph complete; propagation rules need wiring |
| `rustre-symb-z3` | STUB/PARTIAL | Scaffolding present; Z3 bridge incomplete; SymExpr duplication |
