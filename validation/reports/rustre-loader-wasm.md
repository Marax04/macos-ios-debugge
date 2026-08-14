# rustre-loader-wasm

Production-grade WebAssembly binary loader for the RustRE suite. Implements a spec-compliant Wasm 1.0 binary parser (LEB128, all standard sections, name custom section), a cross-linked `WasmModule` model, and a `WasmLoader` implementing `rustre_core::loader::Loader`.

## Cargo.toml

- **Name:** `rustre-loader-wasm`
- **Version:** 0.1.0
- **Edition:** 2024
- **Dependencies:** `rustre-core` (path), `tokio`, `async-trait`, `thiserror`, `serde`, `anyhow`
- **Dev-deps:** `serde_json`

## Modules (pub)

- `wasm_analyzer`, `wasm_binary_parser`, `wasm_component_model`, `wasm_disassembler`, `wasm_module_loader`, `wasm_name_section`, `wasm_optimization_hints`, `wasm_security`, `wasm_disasm`, `wasm_validator`, `wasm_section_parser`, `wasm_type_decoder`, `wasm_import_export`

## Constants

- `WASM_MAGIC = [0x00, 0x61, 0x73, 0x6D]`
- `WASM_VERSION = 1`
- `MAX_SECTION_SIZE = 256 MiB`

## Public API (lib.rs)

### Error

`WasmError` (thiserror) — `InvalidMagic`, `UnsupportedVersion(u32)`, `InvalidSection(u8)`, `Leb128Error(usize)`, `UnexpectedEof(usize)`, `InvalidUtf8`, `SectionTooLarge(u32)`, `Core(String)`. Converts to `CoreError::InvalidFormat`.

### `Leb128Decoder<'a>`

Cursor-based LEB128 decoder.

| Method | I/O |
|---|---|
| `new(&[u8]) -> Self` | input bytes |
| `offset() -> usize` | current cursor |
| `remaining() -> usize` | bytes left |
| `is_done() -> bool` | EOF |
| `read_u32/read_i32/read_u64/read_i64 -> Result<.., WasmError>` | LEB128 decode |
| `read_u8 -> Result<u8>` | raw byte |
| `read_bytes(n) -> Result<&'a [u8]>` | n raw bytes |
| `read_name() -> Result<String>` | length-prefixed UTF-8 |
| `slice(start, end) -> &'a [u8]` | sub-slice |

### Value/type model

- `WasmValType` enum: `I32/I64/F32/F64/V128/FuncRef/ExternRef`. Methods: `from_byte(u8) -> Option<Self>`, `name() -> &'static str`, `byte_size() -> usize`. Serde + Display.
- `WasmFuncType { params: Vec<WasmValType>, results: Vec<WasmValType> }` (Display)
- `WasmLimits { min: u32, max: Option<u32> }`
- `WasmTableType { elem_type, limits }`
- `WasmGlobalType { val_type, mutable }`

### Import/export

- `WasmImportDesc`: `Function(u32) | Table(WasmTableType) | Memory(WasmLimits) | Global(WasmGlobalType)`
- `WasmImport { module: String, name: String, desc: WasmImportDesc }`
- `WasmExportDesc`: `Function(u32) | Table(u32) | Memory(u32) | Global(u32)`
- `WasmExport { name: String, desc: WasmExportDesc }`

### Function body

- `WasmLocal { count: u32, val_type: WasmValType }`
- `WasmCodeEntry = (Vec<WasmLocal>, Vec<u8>, u32, u32)` (locals, code, offset_in_file, entry_size)
- `WasmFunction { index, type_index, func_type: Option<WasmFuncType>, locals, code: Vec<u8>, offset_in_file: u32, size: u32, name: Option<String> }`
  - `local_count() -> u32`, `code_size() -> usize`

### Globals/data/custom

- `WasmGlobal { index, ty: WasmGlobalType, init_bytes: Vec<u8> }`
- `WasmDataSegment { index, memory_index, offset_bytes: Vec<u8>, data: Vec<u8> }`
- `WasmCustomSection { name: String, data: Vec<u8> }` — `is_dwarf()`, `is_name()`

### Name section

`WasmNameSection { module_name: Option<String>, function_names: HashMap<u32,String>, local_names: HashMap<u32, HashMap<u32,String>> }`

- `parse(data: &[u8]) -> Result<Self, WasmError>`

### `WasmModule`

Top-level parsed module:

```
version, types, imports, functions, tables, memories, globals,
exports, start_function, data_segments, custom_sections, name_section,
total_function_count, defined_function_count, import_function_count
```

Methods:
- `function_type(func_idx: u32) -> Option<&WasmFuncType>`
- `exported_function(name: &str) -> Option<&WasmFunction>`
- `exported_function_names() -> Vec<&str>`
- `function_name(func_idx: u32) -> Option<&str>` (name section or unique export)
- `imports_from(module: &str) -> Vec<&WasmImport>`
- `memory_pages_min() -> u32`
- `has_start_function() -> bool`

### `WasmParser`

- `parse(bytes: &[u8]) -> Result<WasmModule, WasmError>` — validates magic+version, walks all sections (0–12), parses name custom section, links function types and export-derived names.

### `WasmStats`

Aggregate counters (`function_count`, `import_count`, `export_count`, `data_size`, `code_size`, `global_count`, `memory_count`, `table_count`, `custom_section_count`, `has_name_section`, `has_dwarf`, `most_complex_function: Option<u32>`).

- `compute(module: &WasmModule) -> Self`

### `WasmLoader` (impl `rustre_core::loader::Loader`)

Async loader using `async_trait`.

| Method | Input | Output |
|---|---|---|
| `name()` | — | `"wasm"` |
| `can_load(&LoaderInput)` | bytes | `true` if starts with WASM magic |
| `load(LoaderInput) -> Result<LoadResult, CoreError>` | full Wasm bytes + URI | `BinaryView` with `WasmArch`, function bytecodes mapped as R+X segments starting at `0x1000` (16-byte aligned), entry points = start function + exported functions |
| `find_nested(&LoaderInput)` | — | `Ok(vec![])` (no nesting) |

Architecture stub `WasmArch` (private): name `"wasm"`, pointer size 4, little-endian, placeholder `disassemble` (delegated to `rustre-arch-wasm`).

### `WasmOpcode(pub u8)`

Wasm opcode wrapper with `mnemonic(self) -> &'static str` covering the full Wasm 1.0 opcode table (0x00–0xC4 range).

## I/O Summary

- **Input:** raw `&[u8]` of a `.wasm` binary (or `LoaderInput` for the `Loader` trait), spec Wasm 1.0.
- **Output:** structured `WasmModule` / `WasmStats`, or a `BinaryView` (via `LoadResult`) with mapped code segments and entry points.
- **Errors:** all parser paths return `Result<_, WasmError>`; loader paths return `Result<_, CoreError>` via `From<WasmError>`.

## Testability

The crate is testable: pure parsing functions (`WasmParser::parse`, `WasmNameSection::parse`, `Leb128Decoder`) take in-memory byte slices and return structured `Result`s without external state. `WasmLoader::load` is async but driven by `tokio` (dev/runtime) and accepts an in-memory `LoaderInput`. `serde_json` is already a dev-dependency for fixture-driven tests.
