# rustre-loader — Validation Analysis

## Purpose
Root loader coordination hub for the RustRE Suite. Provides:
1. Magic-byte / heuristic binary format detection (no I/O, pure byte-slice operations).
2. A coordinator + registry for pluggable async `Loader` implementations (re-exported from `rustre-core`).
3. A synchronous `MultiFormatLoader` registry that returns rich structured metadata (`RichLoadResult`) with sections, symbols, imports, exports.
4. Cryptographic content digests (SHA-256, MD5) used as the canonical hashes by triage / loader pipelines.
5. Sub-module facades for specialty loaders (fat binary, firmware image, minidump, raw, Intel HEX, S-record, overlay, multi-arch, address resolution, relocation, section analysis/merging, symbol table, cache, config validation).

## Public Functions / APIs (semantic view)

### Format detection
- **`FormatDetector::detect(data: bytes) -> BinaryFormat`** — coarse format from magic bytes. Recognizes ELF, PE (MZ), Mach-O (LE/BE 32/64), Mach-O Fat vs Java class (disambiguated by Java major version 44..=80), ZIP/JAR (PK\x03\x04 or PK\x05\x06), WebAssembly (\x00asm). Returns `Unknown` otherwise. Verifiable: feed known file headers and check enum.
- **`FormatDetector::is_elf / is_pe / is_macho / is_java_class(data) -> bool`** — boolean shortcuts derived from `detect`.
- **`AutoLoader::detect_format(bytes) -> DetectedFormat`** — fine-grained: splits ELF by class (32/64) and endian (LE/BE) from e_ident[4..6]; identifies Pe, MachoLe32/64, MachoBe32/64, FatMacho, Wasm, LuaBytecode(version_byte), LuaJit, Pdf, Zip, OleCompoundDoc, AndroidDex, IntelHex (first byte ':'), MotorolaSrec ('S' + ascii digit). Returns `Unknown` otherwise.
- **`AutoLoader::is_elf / is_macho(bytes) -> bool`** — boolean shortcuts.

### Hash helpers (standalone module-level fns)
- **`sha256(data: bytes) -> String`** — lowercase hex SHA-256 of bytes. Ground truth: Python `hashlib.sha256(data).hexdigest()`.
- **`md5(data: bytes) -> String`** — lowercase hex MD5 of bytes. Ground truth: Python `hashlib.md5(data).hexdigest()`. Also exposed as MCP tool `loader_core_md5`.
- **`RichLoadResult::sha256() / md5() -> String`** — same digests over `self.data`.

### Coordinator (async multi-loader orchestration)
- **`LoaderCoordinator::new() / new_with_registry(reg)`** — construct.
- **`register(loader)`** — add a `Loader` trait object; increments internal count.
- **`auto_load(input: LoaderInput) -> BinaryView`** *(async)* — probe registry, pick first matching loader, run it, return its `BinaryView`. Errors: `NoLoader` if zero candidates; `Load` on loader failure.
- **`auto_load_with_id(input) -> (ViewId, BinaryView)`** *(async)* — same plus the assigned view id.
- **`probe_all(&input) -> Vec<Arc<dyn Loader>>`** — list every loader that claims it can handle the input.
- **`loader_count() -> usize`** — exact count of registered loaders (monotonic).

### Batch / Pipeline
- **`BatchLoader::load_all(Vec<LoaderInput>) -> Vec<BatchLoadOutcome>`** *(async)* — sequentially auto-loads each input; never panics, failures captured as `error: Some(...)`. Each outcome carries uri, detected format, optional view, optional error.
- **`LoaderPipeline::new(name)` / `add_loader` / `detect_format(bytes)` / `run(input) -> (BinaryFormat, BinaryView)` / `loader_count()`** — named pipeline bundling a `FormatDetector` + `LoaderCoordinator`.

### MultiFormat registry (sync, returns RichLoadResult)
- **`MultiFormatLoader` trait** — implementers expose `name()`, `extensions()`, `probe(bytes) -> u8` confidence (0=no, 128=heuristic, 255=magic match), `description()`, `load(bytes) -> RichLoadResult`.
- **`MultiFormatRegistry::register / register_arc`** — add loaders.
- **`probe_all(data) -> Vec<(name, confidence)>`** — sorted descending by confidence, filters out 0.
- **`auto_load(data) -> RichLoadResult`** — pick highest-confidence loader and run it.

### Data carriers (with builders)
- **`RichLoadResult::new(data)`, builder setters** (`with_format/arch/bits/endian/entry_point/base_address/section/symbol/import/export`), **`total_virtual_size()`** (sum of section virtual sizes), **`section_at(va) -> Option<&SectionInfo>`** (find section whose `[virtual_addr, virtual_addr+virtual_size)` range contains the address).
- **`SectionInfo::new`, `SymbolInfo::new`, `ImportInfo::named / ordinal`, `ExportInfo::named / forwarded`** — plain constructors.

### Input source
- **`MultiLoaderInput::to_bytes() -> Vec<u8>`** — for `Bytes` and `Memory` variants returns the inner buffer; for `File(path)` performs `std::fs::read`. Errors only on I/O failure.

### Sub-modules (each is a `pub mod`)
`address_resolver`, `binary_view`, `format_detector`, `multi_arch_loader`, `probe_cascade`, `relocation_engine`, `section_analysis`, `section_merger`, `loader_registry`, `symbol_table`, `loader_cache`, `fat_binary_loader`, `firmware_image_loader`, `minidump_loader`, `raw_binary_loader`, `ihex_loader`, `srec_loader`, `fat_binary_splitter`, `overlay_detector`, `loader_config_validator`. Each provides additional specialty functionality (not analyzed in depth here — see crate-level analysis if needed).

## Existing MCP Tools

Grep over `crates/rustre-mcp-tools/src/wire_tools.rs` finds the following surface that exercises `rustre-loader`:

- **`loader_core_md5`** (gap G, line 44–82) — direct wrapper around `rustre_loader::md5(bytes)`. Input: arbitrary bytes (base64 or path-loaded). Output: `{ md5_hex, source: "rustre_loader::md5" }`.
- **Indirect usage via `rustre_loader_pe::PeInfo::parse`** and `rustre_loader::RichLoadResult` consumption inside higher-level analysis tools (`analyze_full` and related, line ~2427, 3989, 4641 — `loader_val` block). These are not single-purpose loader tools but consume `RichLoadResult` for the analysis report.

No dedicated MCP tool currently exposes:
- `FormatDetector::detect` / `AutoLoader::detect_format` (magic-byte detection as a standalone tool).
- `sha256` companion to `loader_core_md5`.
- `LoaderCoordinator::probe_all` / `auto_load` (async generic loader probe).
- `MultiFormatRegistry::probe_all` / `auto_load` (sync rich loader probe).

## Testable Functions (clear external ground truth)

| Function | Ground truth source |
|----------|---------------------|
| `sha256(bytes)` | Python `hashlib.sha256(bytes).hexdigest()` |
| `md5(bytes)` / MCP `loader_core_md5` | Python `hashlib.md5(bytes).hexdigest()` |
| `RichLoadResult::sha256() / md5()` | Same as above over `result.data`. |
| `FormatDetector::detect` | `file(1)` / `magic(5)` database; known fixtures (ELF=`\x7fELF`, PE=`MZ`, Mach-O magics, WASM=`\0asm`, ZIP=`PK\x03\x04`). |
| `AutoLoader::detect_format` | Same fixtures + ELF e_ident class/endian bytes (validated against `readelf -h`). |
| `AutoLoader::is_elf / is_macho`, `FormatDetector::is_*` | Boolean projection of `detect_format` — assert equivalence on fixtures. |
| `RichLoadResult::total_virtual_size` | `sum(s.virtual_size for s in sections)` — synthesize via builder, compare. |
| `RichLoadResult::section_at(va)` | Construct sections with known ranges, probe in/out-of-range VAs. |
| `MultiLoaderInput::to_bytes` (Bytes/Memory) | Identity over input vec; for `File`, compare to `std::fs::read` result of fixture file. |
| `MultiFormatRegistry::probe_all` ordering | Register mock loaders with known confidences, assert descending order and filtering of zero. |
| `LoaderCoordinator::loader_count` | Increments by exactly 1 per `register` call. |

## Less Testable (need fixture binaries / loader plugins)
- `LoaderCoordinator::auto_load` and `BatchLoader::load_all` — require an actual registered `Loader` impl and real binaries to probe; useful as integration tests but not isolated unit checks.
- `LoaderPipeline::run` — same.
- The `MultiFormatLoader` trait itself — verified via implementers in sister crates (rustre-loader-pe etc.).

## Validator Strategy

**Two-tier validation**:

1. **Pure-function oracle tests (high-confidence, fully external)** — for `sha256`, `md5`, `FormatDetector::detect`, `AutoLoader::detect_format`. Drive via the MCP tool `loader_core_md5` where available; for the rest, write a tiny Rust harness in `validation/` that calls the functions on a curated fixture set and compares against precomputed expected values (Python `hashlib` digests, hand-checked magic-byte expectations). Fixtures: a few-byte synthetic blobs (one per format) plus the project's own `cargo-zyphora.exe` (PE) and any ELF in the workspace.

2. **Builder / projection invariants (in-process unit checks)** — `total_virtual_size`, `section_at`, `MultiFormatRegistry::probe_all` ordering, `LoaderCoordinator::loader_count`, `MultiLoaderInput::to_bytes`. These don't need an external oracle; the invariant itself is the oracle (sum equality, ordering monotonicity, identity round-trip, count == register call count). Write as `#[test]` cases or driver-style asserts under `validation/`.

3. **Integration smoke (advisory only)** — for `auto_load` / pipeline, drive via existing MCP analysis tools that already exercise the loader path (e.g. `analyze_full` on the IDA-baseline binary `cargo-zyphora.exe`) and verify the returned `loader` block has plausible `sections != 0`, `base_address != 0`, `arch == "x86_64"`. This re-uses the project's IDA ground truth from memory.

Output report should record: per-tool {input fixture, computed value, expected value, pass/fail}, with the hash tests being the strictest pass/fail gate.
