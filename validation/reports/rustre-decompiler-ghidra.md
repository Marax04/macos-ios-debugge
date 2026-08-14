# rustre-decompiler-ghidra

## Purpose
Ghidra P-Code based decompiler backend for RustRE. Provides both a pure-Rust P-Code lifter (graceful-degradation path) and an optional integration that spawns a real Ghidra `analyzeHeadless` subprocess to recover high-quality pseudo-C. Also bundles type-database, symbol importer, XML parser, and a mock RPC client/server for talking to Ghidra services.

## Dependencies
- `rustre-core` (Instruction, Address)
- `rustre-decompiler` (DecompilerBackend trait, DecompiledFunction, IrLevel, DecompVariable, VarStorage, DecompilerError)
- anyhow, thiserror, serde, serde_json, tokio

## Module layout (`src/`)
- `lib.rs` — core types, `PCodeTranslator`, `PCodeLifter`, `GhidraBackend`, server/project/script/RPC mocks, importers, type DB
- `ast_printer.rs` — AstNode/BinOpKind/UnOpKind enums, PrettyPrinter, AstPrinter, helper constructors (ident/lit/binop/call/assign/block/ret)
- `ghidra_ast.rs` — TypeBase, StructField, UnionVariant and related AST nodes
- `ghidra_bridge.rs` — bridge into the rustre-decompiler IR
- `ghidra_client.rs` — client for an external Ghidra service
- `ghidra_headless.rs` — `GhidraConfig::detect`, temp-project creation, script execution, JSON parsing of decompilation output
- `ghidra_pcode.rs` — richer P-Code modeling
- `ghidra_type_recovery.rs` — type inference over P-Code
- `ghidra_types.rs`, `ghidra_types_db.rs` — Ghidra DataType model + parser/exporter (XML), windows.gdt/clib.gdt library mappings
- `pcode_analysis.rs` — analyses over lifted P-Code
- `pcode_importer.rs` — import P-Code from external sources
- `pcode_interpreter.rs` — execute / interpret P-Code
- `pcode_lifter.rs` — higher-level lifter
- `decompiler_ir_bridge.rs` — convert Ghidra results into rustre IR
- `result_merger.rs` — combine multi-source decompilation results

## Public API (lib.rs root)

### Errors
- `enum GhidraDecompError { NotAvailable, PCodeError, TranslationError, Decompiler(#[from] DecompilerError) }`

### P-Code model
- `enum PCodeOp` — full opcode set: Copy/Load/Store; Branch/CBranch/BranchInd/Call/CallInd/CallOther/Return; IntEqual/NotEqual/SLess/SLessEqual/Less/LessEqual; IntAdd/Sub/Mult/Div/SDiv/Rem/SRem; IntOr/And/Xor/Negate/Not/LeftShift/RightShift/SRightShift; BoolNegate/Xor/And/Or; FloatAdd/Sub/Mult/Div/Neg/Abs/Sqrt; PieceConcat/Subpiece/PopCount/Ptradd/Ptrsub. Implements Display.
- `enum PCodeVarnode { Register{space,offset,size}, Const{value,size}, Ram{offset,size}, Unique{offset,size} }` — Display formatted.
- `struct PCodeInstr { op, output: Option<PCodeVarnode>, inputs: Vec<PCodeVarnode>, seq_num }` — Display.

### Translator / Lifter
- `struct PCodeTranslator`
  - `const fn new(arch: String) -> Self`
  - `fn translate(&self, instr: &Instruction) -> Vec<PCodeInstr>` — converts a single x86-ish mnemonic (nop/ret/call/jmp/jcc/push/pop/mov/add/sub/xor/and/or, fallback Copy) into P-Code ops
  - `fn arch(&self) -> &str`
- `struct PCodeLifter`
  - `const fn new(arch: String) -> Self`
  - `fn lift_to_pseudo_c(&self, address: u64, instructions: &[Instruction], name: &str) -> DecompiledFunction` — emits pseudo-C with P-Code commentary, extracts variables and call sites, confidence 65, IrLevel::PseudoC

### Backend
- `struct GhidraBackend` — implements `DecompilerBackend`
  - `fn new(arch: String) -> Self`, `fn for_x86_64()`, `fn for_arm64()`, `fn arch() -> &str`
  - `fn try_headless_ghidra(binary_path: &str, func_addr: u64) -> Option<String>` — opportunistically runs real Ghidra; returns None on any failure
  - Trait impl: `name() -> "ghidra-pcode"`, `supported_archs() -> [x86_64, x86, aarch64, arm, mips]`, `target_level() -> IrLevel::PseudoC`, `decompile_function(...)` — uses `RUSTRE_BINARY_PATH` env var to try real Ghidra (confidence 90), else falls back to the pure-Rust lifter

### Server / project / scripting / RPC
- `struct GhidraServerConfig { host, port, timeout_ms, use_tls }` + `Default` (127.0.0.1:18001, 30s, no TLS)
- `struct GhidraServer` — mock connection state: `new`, `localhost(port)`, `connect`, `disconnect`, `is_connected`, `config`
- `struct GhidraProject { name, path, binary_path }` — `new`, `with_binary`, `project_file()` -> `<path>/<name>.gpr`
- `struct GhidraScript { name, args, timeout_ms }` — builder: `new`, `arg`, `timeout`, `command_line()`
- `struct GhidraDecompileRequest { function_address, function_name, simplify, include_types }`
- `struct GhidraDecompileResponse { function_address, c_code, pcode_ops, variables, confidence }` + `stub(addr, name)` (confidence 50)
- `struct GhidraRpcClient` — `new(config)`, `decompile(req) -> Result<GhidraDecompileResponse, _>` (mock — increments request counter, returns stub), `request_count`, `config`, `endpoint() -> "host:port"`

### Memory map / importers / type DB
- `struct GhidraMemoryMap` + `GhidraSegment { name, start, size, r/w/x }` — `add_segment`, `segment_at(addr)`, `executable_segments()`, `segment_count()`
- `struct GhidraSymbolImporter` — `add_symbol/add_import/add_export`, `resolve(addr)`, `symbol_count/import_count/export_count`
- `struct GhidraTypeImporter` — `add_type`, `get_c_decl`, `type_count`, `import_windows_types()` (DWORD/WORD/BYTE/BOOL/HANDLE/LPVOID/LPCSTR)
- `struct GhidraXmlParser` — `parse(xml)` scans for `<FUNCTION NAME="...">` and `<TYPE_DEF NAME="...">` tags; accessors `function_count`, `functions`, `type_count`, `parsed_types`
- `struct GhidraDataTypeDb` + `GhidraDataType { name, category, size_bytes, c_representation }` — `add`, `get`, `count`, `load_builtins()` (void/char/short/int/long/longlong + unsigned variants, float, double, pointer)

## Expected behavior
- Default `decompile_function`: when `RUSTRE_BINARY_PATH` is set and Ghidra is installed, spawns headless Ghidra and returns its pseudo-C with confidence 90; otherwise emits the in-process P-Code lifted pseudo-C with confidence 65. Never errors on missing Ghidra.
- `try_headless_ghidra` is fully best-effort: any IO/parse/subprocess failure returns `None`.
- `PCodeTranslator` is a deliberately simplified x86-style lifter (register offsets are synthetic 0x00..0x80 slots, sizes default to 8 bytes) suitable for prototype P-Code IR rather than faithful SLEIGH semantics.
- RPC/Server types are mocks (no socket I/O) and always succeed.
- XML parser is a tag-scanner stub, not a validating parser.

## Public symbol counts
- pub fns across `src/`: ~463 occurrences (Grep `^\s*pub (async )?fn`), spread across 16 modules; lib.rs root surfaces ~58.
- Tests: two `#[cfg(test)] mod` blocks in lib.rs (`tests`, `extended_ghidra_tests`) plus a `tests/` directory at crate root.

## Testability
Yes — testable in isolation. The in-process P-Code path (`PCodeTranslator`, `PCodeLifter`, `GhidraBackend` fallback) is fully deterministic and requires no external Ghidra installation. Server/RPC/project/script types are mocks with no external dependencies. Headless Ghidra integration is opt-in via env var and degrades to `None`, so unit tests can run without Ghidra installed. The crate already ships an internal test module exercising all major surfaces (errors, opcodes, varnodes, translator mnemonics, lifter, backend, server, RPC).
