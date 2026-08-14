# rustre-loader-lua

Comprehensive loader/parser for compiled Lua bytecode (Lua 5.0/5.1/5.2/5.3/5.4) and LuaJIT.

## Cargo.toml

- **name**: `rustre-loader-lua` v0.1.0, edition 2024
- **dependencies**: `rustre-core` (path), `anyhow`, `serde`, `serde_json`, `thiserror`, `tokio` (full), `rayon`
- **dev-dependencies**: `tokio`, `serde_json`
- **tests**: `tests/blitz.rs`, `tests/blitz2.rs`

## Modules (src/)

- `lua50_format`, `lua51_format`, `lua52_53_format` — per-version format specifics
- `lua_analysis` — bytecode analysis
- `lua_bytecode_parser` — raw parser
- `lua_constant_pool` — constant pool handling
- `lua_debug` — debug info (line, locals, upvalues)
- `lua_decompiler_full` — full decompiler (AST, statements, expressions)
- `lua_function_graph` — function graph
- `lua_proto_analyzer` — prototype analysis
- `lua_string_extractor` — string extraction
- `lua_upvalue_analyzer` — upvalue analysis
- `lua_version_detector` — version detection
- `luajit_loader` — LuaJIT bytecode loader

## Public API (lib.rs)

### Constants
- `LUA_MAGIC: &[u8;4] = b"\x1bLua"`

### Error
- `enum LuaLoaderError`: `InvalidMagic`, `UnsupportedVersion(u8)`, `ParseError(String)`, `TruncatedData`, `Overflow` (impls `thiserror::Error`)

### Detection
- `fn is_lua_bytecode(data: &[u8]) -> bool`

### Types

- `enum LuaVersion`: `Lua51 | Lua52 | Lua53 | Lua54 | Unknown(u8)`
  - `from_byte(u8)`, `is_known()`, `as_byte()`, `minor()`, `major()`, `Display`
- `enum LuaEndian`: `Be | Le`
  - `from_byte(u8)`, `to_core_endian() -> Endian`, `is_le()`, `Display`
- `struct LuaIntSize { size: u8 }` (Display)
- `struct LuaHeader` { version, format, endian, int_size, ptr_size, inst_size, num_size, is_integer_num, lua_integer_size, lua_float_size }
  - `const MIN_SIZE = 12`
  - `parse(data) -> Result<(Self, usize), LuaLoaderError>` (returns header + end offset; verifies LUAC_DATA for 5.4)
  - `to_endian()`, `is_official_format()`, `Display`
- `enum LuaConst`: `Nil | Bool(bool) | Number(f64) | Integer(i64) | Str(String) | LongStr(String)`
  - Tag constants: `TAG_NIL=0`, `TAG_BOOL=1`, `TAG_NUMBER=3`, `TAG_SHORT_STR=4`, `TAG_LONG_STR=20`, `TAG_INT=0x13`, `TAG_FLOAT=0x03`
  - `is_string()`, `as_str() -> Option<&str>`, `Display`
- `struct LuaInstr(pub u32)` — 32-bit decoded VM instruction
  - `opcode()`, `a()`, `b()`, `c()`, `bx()`, `sbx()`, `writes_a()`, `Display`
- `struct LuaLocalVar { name, start_pc, end_pc }` (Display)
- `struct LuaUpvalue { in_stack: bool, idx: u8, name: Option<String> }` (Display)
- `struct LuaProto` (full function prototype: name, lines, params, vararg, max_stack, instructions, constants, upvalues, protos, line_info, locals, version)
  - `mock(version)`, `total_instructions()`, `all_strings() -> Vec<&str>`, `source_line(pc)`, `constant_type_counts() -> HashMap<&'static str, usize>`, `Display`
- `struct LuaChunk` — light descriptor (backward-compat)
  - `from_proto(&LuaProto)`, `mock(name)`, `Display`
- `struct LuaBytecode { header, top_level }`
  - `parse(data) -> Result<Self, LuaLoaderError>`, `total_instructions()`, `all_strings()`

### Opcode tables
- `static LUA51_OPCODES`, `LUA52_OPCODES`, `LUA53_OPCODES`, `LUA54_OPCODES: &[&str]`
- `fn opcode_name(version: LuaVersion, opcode: u8) -> &'static str`

### Architecture stub
- `struct LuaArch` (impls `rustre_core::arch::Architecture`)
  - `new(version)`, `Default` → Lua54
  - `name()`, `pointer_size()=8`, `endian()=Little`, `disassemble(addr, &[u8]) -> Instruction`, `get_branches()`, `registers()` (r0..r15), `calling_conventions()` ("lua")

### Loader
- `struct LuaLoader` (impls `rustre_core::Loader` via `async_trait`)
  - `new()`
  - `name() = "lua"`
  - `can_load(&LoaderInput) -> bool` (via `is_lua_bytecode`)
  - `async load(LoaderInput) -> Result<LoadResult, CoreError>` — builds `BinaryView` with single RX segment at base hint, arch = `LuaArch`, 64-bit, little-endian
  - `async find_nested(...)` → empty

### Standalone parsers (spec §3.8 API)
- `fn read_string_lua(data, &mut offset, size_t_size) -> Result<String, LuaLoaderError>` — length-prefixed Lua string (incl. NUL terminator)
- `type LocalVar = LuaLocalVar`
- `struct UpvalueDesc { name: String, in_stack: u8, idx: u8 }` with `from_upvalue(&LuaUpvalue)`, Display
- `fn parse_proto_51(data, &mut offset, endian: bool, int_size: u8) -> Result<LuaProto, LuaLoaderError>`
- (further parsers `parse_proto_52/53/54` likely follow in unread portion of lib.rs — file is 3281 lines, only first 1598 read)

### Re-exports from `lua_decompiler_full`
- `BasicBlock`, `BinOp`, `ControlFlow`, `DecompError`, `ExpressionTree`, `FunctionAst`, `LuaAst`, `LuaConst as LuaConstDecomp`, `LuaDecompilerFull`, `Statement`, `StatementList`, `TableField`, `UnOp`, `render_expr`

## I/O Contract

**Input**:
- Primary: `LoaderInput` (from `rustre_core`) with `data: Vec<u8>` containing Lua bytecode (magic `\x1bLua` + version byte 0x51/0x52/0x53/0x54), optional base address hint, `uri`.
- Lower-level: raw `&[u8]` slices for `LuaBytecode::parse`, `LuaHeader::parse`, `read_string_lua`, `parse_proto_51`.

**Output**:
- `LoadResult` containing a `BinaryView` (single RX segment covering full input, LuaArch matching detected version, entry = base).
- `LuaBytecode` with full `LuaHeader` + recursive `LuaProto` tree (instructions, constants, upvalues, nested protos, debug info).
- Errors via `LuaLoaderError`.

**Endianness**: header-controlled (`LuaEndian`); BinaryView is hard-coded Little.

## Testability

- Public mock builders: `LuaProto::mock(version)`, `LuaChunk::mock(name)`.
- Pure parsing functions on `&[u8]` (no I/O) → unit-testable.
- Existing integration tests: `tests/blitz.rs`, `tests/blitz2.rs`.
- `Loader::load` is `async` → requires tokio runtime.

Crate is **testable**.

## Source paths

- `C:\Users\Fra\Desktop\RustRE\crates\rustre-loader-lua\Cargo.toml`
- `C:\Users\Fra\Desktop\RustRE\crates\rustre-loader-lua\src\lib.rs`
- `C:\Users\Fra\Desktop\RustRE\crates\rustre-loader-lua\tests\blitz.rs`, `blitz2.rs`
