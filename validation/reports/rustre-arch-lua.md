# rustre-arch-lua

## Scopo
Backend architettura per il **VM bytecode di Lua** (versioni 5.1, 5.2, 5.3, 5.4). Fornisce decoder di istruzioni, parser di header chunk, disassembler, costruzione CFG/basic-block, decompilatore, modello semantico VM (LuaValue/LuaTable/metatable/upvalue closing/yield-resume), inference di tipi, tracker di upvalue/closure, pattern matcher per offuscazione, e printer di prototype. Parte della suite RustRE.

## Funzioni pubbliche principali
- **Decoding istruzioni**
  - `decode_lua54_insn(word, address) -> Result<Lua54Insn, Lua54Error>`
  - `decode_lua_legacy(...)` — 5.1/5.2/5.3
  - `decode_lua51 / decode_lua52 / decode_lua53(...)`
  - `decode_by_version(version, word, addr)`
- **Header / chunk parsing**
  - `parse_chunk_header(data: &[u8]) -> Result<LuaChunkHeader, ChunkHeaderError>`
  - `parse_lua54_header(data) -> Result<Lua54Header, Lua54Error>` + variante `_anyhow`
  - `detect_version(data: &[u8]) -> Option<LuaVersion>`
- **Disassembly**
  - `disassemble_chunk(...)` / `disassemble_chunk_lossy(arch, base, bytes) -> Vec<Instruction>`
  - `disassemble_lua54_file(path) -> Result<String>`
  - `format_instruction(&Instruction) -> String`, `format_listing(&[Instruction]) -> String`
- **Opcode tables / query**
  - `opcode_name(version, opcode) -> Option<&'static str>`
  - `find_opcodes(version, needle) -> Vec<(u8, &str)>`
  - `opcode_format(code) -> OpcodeFormat`, `classify_opcode(mnemonic) -> OpcodeCategory`
- **Instruction encoders (testabili round-trip)**
  - `make_iasbx`, `make_isj`, `make_legacy_iasbx`, `make_loadf`, `make_loadi`
- **CFG / analisi**
  - `split_basic_blocks(arch, instrs) -> Vec<LuaFlatBlock>`
  - `analyze_function(...)`, `annotate_instructions(...)`
- **Constants / proto**
  - `parse_const_pool_51`, `parse_const_pool_53`, `extract_constants_from_proto(code, version)`
- **Naming / semantica**
  - `generate_local_var_names`, `generate_param_names`, `generate_upvalue_names`
  - `upvalue_at_index(...)`, `find_table_accesses(...)`
- **VM step / obfuscation**
  - `vm_step(state, instruction) -> VmStepResult`
  - `check_magic(data) -> Option<ObfuscationPattern>`

## Input / Output
- Input: byte slice di un chunk Lua compilato (`.luac` o blob bytecode) + `LuaVersion`.
- Output: strutture tipizzate (`LuaChunkHeader`, `Lua54Header`, `Instruction`, `LuaFlatBlock`, `LuaConst`, `Lua54Insn`) e stringhe formattate per disassembly.

## Ground truth verificabile esternamente
- **Header magic Lua**: `1B 4C 75 61` (`\x1bLua`) seguito da version byte (`0x51`/`0x52`/`0x53`/`0x54`). Riferimento: sorgente ufficiale `lundump.c`.
- **Layout istruzioni**:
  - Lua 5.1—5.3: `iABC [B:9][C:9][A:8][OP:6]`, `iABx [Bx:18][A:8][OP:6]`, `iAsBx` con bias `MAXARG_sBx = 131071`.
  - Lua 5.4: `iABC [C:8][B:8][k:1][A:8][OP:7]`, `iABx [Bx:17][A:8][OP:7]`, `iAx [Ax:25][OP:7]`, `isJ [sJ:25][OP:7]`.
- **Opcode counts**: 5.1 = 38 (0—37), 5.2 = 41, 5.3 = 47, 5.4 = 83. Verificabili con `lopcodes.h` upstream.
- **Confronto disasm**: `luac -l file.luac` ufficiale produce listing canonico confrontabile con `disassemble_lua54_file`.
- **Round-trip encoder/decoder**: `decode_*(make_*(...))` deve restituire i campi originali — proprietà testabile in unit test.

## Tool MCP esistenti correlati
- `mcp__rustre-mcp__analysis_disasm_at_path` (generico) — non specifico Lua.
- `mcp__rustre-mcp__binary_info`, `binary_hexdump`, `binary_search_bytes` — utili per verificare magic header `1B 4C 75 61`.
- `mcp__rustre-mcp__project_open` / `analyze_full` — pipeline standard.
- Nessun tool MCP dedicato `lua_*` esposto attualmente: il crate è consumato internamente da `rustre-core` / loader come arch backend.

## Testabilità
TRUE — encoder/decoder con proprietà round-trip, parser di header confrontabile a `luac` ufficiale, opcode tables verificabili contro sorgenti Lua upstream.
