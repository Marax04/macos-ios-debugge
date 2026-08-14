# rustre-arch-wasm

## Purpose
WebAssembly architecture backend for RustRE. Provides a disassembler/decoder for the Wasm MVP bytecode plus extensions (sign-extension, reference types, bulk memory, saturating truncation, SIMD via 0xFD prefix, threads/atomics via 0xFE prefix), and parsers for the Wasm binary module format (header, sections, value types, function types, limits, globals, tables, memories). Implements the `rustre_core::arch::Architecture` trait so Wasm bytecode can be analyzed through the same pipeline as native architectures. Also contains companion modules for validation, type system, lifting to LLIL-style IR, memory/table models, import analysis, and a Wasm decompiler.

## Public Functions / Items (top-level lib.rs)

### `WasmArch` (struct, impl Architecture)
- `WasmArch::new() -> WasmArch`
- `Architecture::name()` -> `"wasm"`
- `Architecture::pointer_size()` -> `4` (wasm32)
- `Architecture::endian()` -> `Little`
- `Architecture::disassemble(address, bytes)` -> `Instruction`
  - Input: virtual address, byte slice starting with a Wasm opcode.
  - Output: decoded `Instruction { mnemonic, operands, size, flags, bytes }`.
  - Behavior: matches the first opcode byte, reads any LEB128/immediate operands, returns mnemonic such as `i32.const`, `call`, `br_if`, `i32.load`, etc., with flags (`BRANCH`, `CALL`, `READ_MEM`, `WRITE_MEM`, `RET`, `BARRIER`, `CONDITIONAL`, `INDIRECT`).
  - Ground truth: verifiable against the official Wasm binary spec or `wasmparser`/`wabt`'s `wasm-objdump -d`.
- `Architecture::get_branches(instr)` -> `Vec<BranchInfo>`
  - Returns structured-branch info (label depths, not absolute addresses).
- `Architecture::registers()` -> `vec![]` (stack VM).
- `Architecture::calling_conventions()` -> single `"wasm"` convention with no register args.

### Constants
- `WASM_MAGIC: [u8;4] = [0x00, 0x61, 0x73, 0x6D]` ("\0asm")
- `WASM_VERSION: [u8;4] = [0x01, 0x00, 0x00, 0x00]` (MVP version 1)
- Ground truth: Wasm core spec §5.

### `WasmValueType` enum
- Variants: I32, I64, F32, F64, V128, FuncRef, ExternRef
- `from_byte(b: u8) -> Option<Self>` — decode encoding byte (0x7F..0x6F).
- `name() -> &'static str` — text name ("i32", ...).
- `byte() -> u8` — encoding byte.
- `is_numeric() -> bool`
- `is_reference() -> bool`
- Ground truth: Wasm spec value type encoding (0x7F=i32, 0x7E=i64, 0x7D=f32, 0x7C=f64, 0x7B=v128, 0x70=funcref, 0x6F=externref).

### `WasmSectionId` enum
- Custom(0), Type(1), Import(2), Function(3), Table(4), Memory(5), Global(6), Export(7), Start(8), Element(9), Code(10), Data(11), DataCount(12)
- `from_byte(b)`, `name()`.
- Ground truth: Wasm spec section IDs.

### `WasmExternalKind` enum
- Function(0), Table(1), Memory(2), Global(3) — `from_byte`, `name`.

### `WasmMutability` enum
- Const(0), Mutable(1) — `from_byte`.

### `WasmLimits { min: u64, max: Option<u64> }`
- `decode(bytes) -> (Self, usize)` — kind byte 0=min-only, 1=min+max.

### `WasmFuncType { params, results }`
- `decode(bytes) -> Self` — expects leading 0x60, then uleb count + value-type bytes for params and results. Caps at 32_768 to prevent allocation DoS.
- `arity() -> (usize, usize)`.

### `WasmModuleHeader { magic, version }`
- `parse(&[u8]) -> Result<Self>` — validates first 8 bytes equal magic + MVP version.

### `WasmGlobalType { content_type, mutability }`
- `decode(bytes) -> (Self, usize)`.

### `WasmTableType { element_type, limits }`
- `decode(bytes) -> (Self, usize)`.

### `WasmMemoryType { limits }`
- (decode likely follows past truncation point).

### Submodules (each exposes additional public API; not the focus of comparison MCP tool)
- `atomics`, `simd_decoder` — prefix decoders for 0xFE / 0xFD opcodes.
- `wasm_analysis`, `wasm_decompiler`, `wasm_lifter` — higher-level analyzers (CFG, decompile, IR lifting).
- `wasm_validator` — module/function type checking (`ModuleValidator`, `FunctionValidator`, `ValidationReport`).
- `wasm_type_system` — alternative type system layer with `WasmValType`, `ResultType`, `WasmFuncType`, `TypeRegistry`, plus `encode_uleb128`/`decode_uleb128`/`encode_sleb128`/`decode_sleb128` standalone codec helpers.
- `wasm_memory_model`, `wasm_table_model` — runtime models (`WasmMemory`, `WasmTable`, `MemoryLimits`, etc.).
- `wasm_import_analyzer` — classifies imports by module (WASI, env, ...).
- `wasm_execution_model` — abstract stack-machine execution.

## Existing MCP Tools
- `analysis_disasm_at_path_wasm` (in `rustre-mcp-tools/src/wire_tools.rs` line 7519) — disassembles bytes at a given file offset using `WasmArch::new()`.
- `analysis_disasm_at_path` accepts `arch = "wasm"` parameter as fallback dispatch.
- No dedicated MCP tools for module-header parsing, function-type decode, validator, or lifter.

## Testable Functions (externally verifiable)
- `WasmArch::disassemble` — compare mnemonic+size+operands against `wasm-objdump -d` for known opcode byte sequences.
- `read_uleb128` / `read_sleb128` (crate-private, but reachable via disasm operand checks; the public counterparts `decode_uleb128`/`decode_sleb128` in `wasm_type_system` are directly testable against Python `leb128` package).
- `WasmModuleHeader::parse` — accept `[0,'a','s','m',1,0,0,0]`; reject other magic/version. Verifiable against any `.wasm` file's first 8 bytes.
- `WasmValueType::from_byte` / `byte` round-trip — known constants from spec.
- `WasmSectionId::from_byte` / `name` — known constants from spec.
- `WasmFuncType::decode` — feed known bytes (e.g. `[0x60,0x02,0x7f,0x7f,0x01,0x7f]` = `(i32,i32)->i32`) and check arity, types. Verifiable against `wasmparser` (Rust) or `wabt`.
- `WasmLimits::decode` — `[0x00,n]` and `[0x01,min,max]`. Verifiable against spec / `wasmparser`.
- `WasmGlobalType::decode`, `WasmTableType::decode` — analogous.

## Validator Strategy
Build a small set of golden-input vectors derived from the Wasm specification and from canonical `.wasm` files produced by `wat2wasm` (WABT):

1. **Opcode disasm matrix**: for each opcode the crate claims to support, hand-craft the minimal byte sequence (from the spec / WABT) and assert `(mnemonic, size, flags)` triple. Cross-check by running `wasm-objdump -d` on a `.wasm` containing the same instructions inside a function body.
2. **LEB128 codec**: parametric tests against Python `leb128` library — random `u64`/`i64` values encoded then decoded by `decode_uleb128`/`decode_sleb128` must round-trip, and lengths must match.
3. **Header / section / valtype constants**: literal byte comparisons against the spec table.
4. **FuncType decode**: generate `(params, results)` permutations, encode via `wat2wasm`, extract the type section, feed bytes to `WasmFuncType::decode`, compare with the original signature.
5. **Limits / GlobalType / TableType**: encode via known `.wat` snippets through `wat2wasm`, extract bytes, decode, compare to wat source.
6. **Negative tests**: truncated inputs, oversized counts (>32_768 params, >65_536 br_table entries), invalid magic/version, unknown opcodes — assert structured `CoreError::InvalidFormat`.
7. **MCP path**: call `analysis_disasm_at_path_wasm` on a real `.wasm` file at known code offsets and verify the output stream matches `wasm-objdump -d` for the same byte range.
