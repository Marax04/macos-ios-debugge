# rustre-arch-luajit

## Scopo
Architecture backend per LuaJIT 2 VM bytecode (sia 2.0 versione=1 che 2.1 versione=2). Fornisce:
- Decoder istruzioni LuaJIT a 32-bit fixed-width (formati ABC, AD, AD-signed, A, None).
- Parser dump bytecode (`.ljbc`): magic `1B 4C 4A`, header flags, ULEB128, catena di protos child-before-parent, costanti GC + numeriche (ULEB128-33).
- Implementa il trait `rustre_core::arch::Architecture` (`name=luajit`, pointer_size=8, little endian, instruction_alignment=4).
- Disassembly, branch-info, basic-block finder, def-use chain per analisi statica.
- Sottomoduli ausiliari: opcodes table, IR/trace IR disasm, JIT/mcode analyzer, proto deep-analyzer, security (SandboxEscape/FFIAbuse/JitBypass/ROP), bytecode optimizer (constant folding, DCE, copy-prop, jump chaining), assembler con label/register/constant tables, LJ 2.1 compat layer.

## Public functions / API (lib.rs root)

### Costanti
- `LJ_MAGIC: [u8; 3]` = `[0x1b, 0x4c, 0x4a]`
- `LJ_VERSION_20: u8 = 1`, `LJ_VERSION_21: u8 = 2`

### Enum `LjOp` (97 opcodes 0..=96, da ISLT a FUNCCW)
- `LjOp::from_u8(v: u8) -> Option<Self>`
- `LjOp::mnemonic(self) -> &'static str` (uppercase canonico)
- `LjOp::category(self) -> InstrCategory`

### Enum `InstrCategory`
Comparison, Arithmetic, LoadConst, Upvalue, TableGet, TableSet, Call, Return, Branch, FuncHeader, Other.

### Enum `LjFmt`
Abc, Ad, AdSigned, A, None.

### Struct `LuaJitArch` (impl `Architecture`)
- `LuaJitArch::new() -> Self`
- `branch_kind(&self, &Instruction) -> Option<BranchKind>`
- `detail(&self, idx: usize, words: &[u32]) -> Option<LjInstrDetail>`
- `disassemble_block(&self, base: Address, words: &[u32]) -> Vec<Result<Instruction, CoreError>>`
- trait Architecture: `name()="luajit"`, `pointer_size()=8`, `endian()=Little`, `disassemble(addr, bytes) -> Result<Instruction>`, `get_branches(&Instruction) -> Vec<BranchInfo>`, `registers() -> Vec<RegisterInfo>` (R0..R15), `calling_conventions() -> Vec<CallingConvention>`, `instruction_alignment()=4`, `max_instruction_length()=4`.

### Struct `LjInstrDetail`
Campi: index, raw u32, op, a, b, c, d (u32), d_signed (i32), fmt, category, branch_target (Option<i64>).
- `mnemonic(&self) -> String` (lowercase)
- `reads_reg(&self, reg: u8) -> bool`
- `writes_reg(&self, reg: u8) -> bool` (gestisce stores TSET*/USET*/GSET dove A è source non dest)

### Enum `LjConst`
Integer(i64), Float(f64), String(Vec<u8>), Bool(bool), Nil.

### Struct `LjUpvalue` { on_stack: bool, idx: u8 }

### Struct `LuaJitProto` (Default)
Campi: instructions: Vec<u32>, upvalues, constants, protos (children), params, framesize, flags, source, first_line, num_lines.
- `instr_count() -> usize`
- `is_vararg() -> bool` (flags & 0x02)
- `has_children() -> bool`
- `iter_instructions() -> impl Iterator<Item=(usize,u32)>`
- `category_histogram() -> [usize; 11]`
- `used_opcodes() -> Vec<u8>`
- `branches() -> Vec<LjInstrDetail>`
- `string_constants() -> Vec<&[u8]>`

### Struct `DumpFlags(u8)`
- `from_byte(b: u8) -> Self`
- `strip()`, `be()`, `ffi()`, `fr2()` -> bool (bits 0x02, 0x01, 0x04, 0x08)

### Struct `LuaJitBytecode { version: u8, flags: DumpFlags, chunk: LuaJitProto }`
- `LuaJitBytecode::parse(data: &[u8]) -> Result<Self, ParseError>`
- `is_lj21() -> bool`
- `total_instructions() -> usize`

### Enum `ParseError`
UnexpectedEof, BadMagic, Overflow, BadUleb (impl Display).

### Pretty printer
- `format_instruction(idx: usize, word: u32) -> String` (es. `0004  ADDVV   R0, R1, R2`)
- `disassemble_listing(words: &[u32]) -> String`

### Encoding helpers
- `make_lj_abc(op, a, b, c) -> u32`
- `make_lj_ad(op, a, d: u16) -> u32`
- `make_lj_ad_signed(op, a, d_signed: i16) -> u32`
- `instr_op(word) -> u8`, `instr_a`, `instr_b`, `instr_c`, `instr_d -> u16`, `instr_d_signed -> i16`

### Struct `BasicBlock { start, end }`
- `len()`, `is_empty()`
- `find_basic_blocks(words: &[u32]) -> Vec<BasicBlock>` (leader detection: target rami + fallthrough + post-return)

### Struct `RegAccess { instr_idx, reg, is_def }`
- `collect_reg_accesses(words: &[u32]) -> Vec<RegAccess>`

### Sottomoduli pubblici
`luajit21_compat`, `luajit_jit_analysis`, `trace_ir`, `luajit_security`, `bc_optimizer`, `luajit_assembler`, `luajit_ir_disasm`, `luajit_mcode_analyzer`, `luajit_proto_analyzer`, `luajit_opcodes`, `luajit_ir`, `luajit_trace_info`.

## Input / Output
- Input principale: byte slice di un dump `.ljbc` (LuaJIT 2.0/2.1) o slice di parole istruzione `&[u32]`.
- Output: `LuaJitBytecode` strutturato; `Instruction` (rustre-core) con flags BRANCH/CALL/RET/CONDITIONAL; liste di basic block, branch, def-use; disassembly testuale.

## Ground truth verificabile esternamente
- **Magic e versione**: `1B 4C 4A` + version byte 0x01 (LJ 2.0) o 0x02 (LJ 2.1). Documentato in `src/lj_bcdump.h` upstream di LuaJIT.
- **Tabella opcode 0..96**: ordine e nomi corrispondono a `lj_bc.h` (`BCDEF_*` macro). Confrontabile con `luajit -bl file.lua` (disassembler ufficiale).
- **Header proto**: `flags(1) params(1) framesize(1) #uv(1) #kgc(uleb) #kn(uleb) #bc(uleb)` — vedi `lj_bcwrite.c` / `lj_bcread.c` upstream.
- **ULEB128-33** per number constants (bit0=sign/float-marker), GC types `0`=child, `1`=tab, `2`=I64, `3`=U64, `4`=complex, `>=5`=stringa di lunghezza `n-5`.
- **DumpFlags bits**: 0x01=BE, 0x02=strip, 0x04=ffi, 0x08=fr2 (LJ 2.1+).
- **BIAS=0x8000** per offset signed dei branch.
- **Tool esterno di confronto**: `luajit -b -l file.lua` produce un listing che deve corrispondere mnemonic-per-mnemonic a `disassemble_listing`.

## Tool MCP esistenti correlati
- `mcp__rustre-mcp__analysis_disasm_at_path` (generico per architetture supportate — luajit instradabile se l'arch è registrata in rustre-core).
- `mcp__rustre-mcp__analysis_fn_detect_functions_path`, `analysis_basic_blocks_path`, `analysis_loops_path`, `analysis_dominators_path` (consumano l'output di Architecture).
- `mcp__rustre-mcp__decompile_function_path` (richiede lifter IL per luajit, non garantito presente).
- Nessun tool MCP dedicato a `.ljbc` parsing diretto (non esistono `analysis_disasm_at_path_luajit` o `loader_luajit`); il parsing dump è esposto solo via libreria.

## Testabilità
Sì. Test verificabili con:
1. Round-trip encode/decode: `make_lj_abc/ad/ad_signed` + `instr_op/a/b/c/d/d_signed`.
2. `LuaJitBytecode::parse` su un file `.ljbc` generato con `luajit -b script.lua out.ljbc` e confronto con `luajit -bl script.lua`.
3. `categorize` e `LjOp::from_u8` esaustivi su 0..=96.
4. `find_basic_blocks` su sequenze sintetiche con JMP/comparison/RET.
5. `disassemble_listing` confronto con disassembler ufficiale.

File: `C:\Users\Fra\Desktop\RustRE\crates\rustre-arch-luajit\src\lib.rs` (5693 lines totali, qui analizzate righe 1-1469; resto contiene helper privati e moduli aggiuntivi).
