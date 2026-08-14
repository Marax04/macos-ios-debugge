# rustre-loader-luajit

Full LuaJIT 2.0/2.1 bytecode loader: header parsing, proto chain, instruction decoding, KGC/KN constants, upvalues, debug info.

## Cargo.toml

- name: `rustre-loader-luajit` v0.1.0, edition 2024
- deps: `rustre-core`, `rustre-arch-luajit`, `serde`, `thiserror`, `bitflags`, `tokio` (full)
- dev-deps: `tokio`, `serde_json`
- tests/: `blitz.rs`, `blitz2.rs`

## Modules (pub)

`bytecode_format`, `constant_tables`, `instruction_decoder`, `liftable_functions`, `luajit_decompiler`, `luajit_opcode_table`, `luajit_parser`, `luajit_profiler_data`, `luajit_vm_analysis`, `upvalue_analysis`, `luajit_bytecode_analyzer`, `luajit_string_extractor`, `luajit_cfg_builder`.

Re-exports from `luajit_vm_analysis`: `IrConst`, `IrInstruction`, `IrOp`, `IrSnapshot`, `JitOptimization`, `LjError`, `LuaJitVmAnalysis`, `SnapshotEntry`, `TraceIr`.

## Public API (lib.rs)

### Constants / detection
- `LJ_MAGIC: [u8; 3]` = `[0x1B, 'L', 'J']`
- `LJ_OPCODES: &[&str]` — 97 mnemonics indexed by opcode byte
- `fn is_luajit(data: &[u8]) -> bool`

### LEB128
- `fn read_uleb128(data: &[u8], pos: usize) -> Option<(u64, usize)>`
- `fn read_sleb128(data: &[u8], pos: usize) -> Option<(i64, usize)>`

### Error
- `enum LjLoaderError`: `InvalidMagic`, `UnsupportedVersion(u8)`, `ParseError(String)`, `TruncatedData`, `Leb128Overflow`

### Version & flags
- `enum LjVersion`: `Lj20`, `Lj21`, `Unknown(u8)` — `from_byte`, `is_known`, `as_byte`
- `LjFlags` (bitflags u8): `BE`, `STRIP`, `FFI`, `FR2`
- `LjProtoFlags` (bitflags u8): `CHILD`, `VARARG`, `FFI`, `NOJIT`, `ILOOP`

### Header
- `struct LjHeader { version, flags, debug_name }`
  - `fn parse(data: &[u8]) -> Result<(Self, usize), LjLoaderError>`

### Instruction
- `struct LjInstr(pub u32)` — accessors: `opcode/a/b/c/d/jump_offset/mnemonic`; predicates: `is_call/is_return/is_branch/is_compare/is_load_const/is_table_op/is_upvalue_op/is_loop/is_function_header/is_arith`

### Constants
- `struct LjUpvalue { slot, is_local, name }`
- `enum KGC`: `Child(Box<LjProto>)`, `Tab`, `I64(i64)`, `U64(u64)`, `Complex(f64,f64)`, `String(String)`, `Unknown(u32)` — `as_str/is_child/is_string/kind_name`
- `enum KNumConst`: `Int(i32)`, `Float(f64)`
- `enum LjConst` (legacy): `Nil`, `Bool`, `Int`, `Num`, `Str`, `Upval(u16)`, `Proto(u32)`

### Debug info
- `struct VarName { name, start_pc, end_pc }` — `is_live_at(pc)`
- `struct LjLocalVar { name, start_pc, end_pc }`
- `struct DebugInfo { source_name, first_line, num_lines, line_info, local_vars, upvalue_names }` — `is_empty`, `source_line_for_pc(pc)`, `locals_at(pc)`

### Prototype
- `struct LjProto { flags, num_params, frame_size, num_upvalues, is_vararg, instructions, upvalues, kgc, kn, constants, instruction_count, debug_info, source_name, first_line, num_lines, line_info, local_vars, upvalue_names }`
  - `fn mock() -> Self`
  - `fn parse(data: &[u8], offset: usize, is_be: bool) -> Option<(Self, usize)>`
  - `source_line(pc)`, `string_constants()`, `kgc_strings()`, `call_count/return_count/branch_count`, `has_loops`, `upvalue_name(idx)`, `locals_at_pc(pc)`, `string_at_pc(pc)`

### Bytecode container
- `struct LjBytecode { header, protos }`
  - `fn parse(data: &[u8]) -> Result<Self, LjLoaderError>`
  - `total_instructions`, `all_strings`, `protos_referencing_string(target)`

### Module
- `struct LjModule { header, root_proto }`
  - `all_protos`, `total_instructions`, `string_constants`, `source_name`, `is_stripped`, `is_big_endian`, `version`, `uses_ffi`, `uses_fr2`

### Loader
- `struct LuaJitLoader` (impl `Loader` from rustre-core)
  - `fn new() -> Self`
  - `fn load(data: &[u8]) -> Result<LjModule, LjLoaderError>`
  - `fn can_load(data: &[u8]) -> bool`
  - `fn load_all(data: &[u8]) -> Result<LjBytecode, LjLoaderError>`

### Stats / disassembly
- `struct ProtoStats { total, calls, returns, branches, compares, arith, loads, table_ops, upvalue_ops, loop_instrs, opcode_freq }`
  - `fn compute(proto: &LjProto) -> Self`
- `struct LjDisassembler`
  - `new`, `disassemble_proto(proto)`, `disassemble_all(module)`, `disassemble_bytecode(bc)`, `format_instr(pc, instr, proto)`

## I/O

- Input: raw `&[u8]` LuaJIT bytecode dump (starts with `0x1B 'L' 'J'`, version byte 1 (LJ2.0) or 2 (LJ2.1), header flags ULEB128, optional debug-name length+bytes, then a chain of prototypes each prefixed by ULEB128 proto-size; chain ends on a 0-size sentinel).
- Output: `LjModule` (single root proto) via `LuaJitLoader::load`, or full `LjBytecode { header, protos: Vec<LjProto> }` via `load_all` / `LjBytecode::parse`. Each `LjProto` exposes decoded `LjInstr` words, upvalue descriptors, KGC + KN constant tables, optional `DebugInfo` (line table, locals, upvalue names, source name). Errors: `LjLoaderError` variants. Also implements `Loader` trait for integration with rustre-core `LoaderInput`/`LoadResult`.

Testable: yes (existing integration tests `tests/blitz.rs`, `tests/blitz2.rs`; pure `&[u8]` -> `Result` API; `LjProto::mock()` helper).
