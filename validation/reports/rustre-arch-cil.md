# rustre-arch-cil — Analysis

## Purpose
`.NET CIL / MSIL` bytecode architecture for the RustRE Suite. Decodes the ~220 ECMA-335 Partition III opcodes (1–6 byte variable-length, including 0xFE-prefixed forms), exposes a stack-based VM model, plus higher-level helpers: metadata reader, IL lifter, exception-handler tables, obfuscation detection, type-system / signature parser, abstract execution engine, pattern recognizer (string-encryption / reflection / anti-debug / P/Invoke), basic-block / call-graph / stack-tracker analysis.

## Public API (selected — semantic descriptions)

### Core decoder (`lib.rs`)
- **`CilInstr::decode(bytes: byte slice) -> (CilInstr, bytes_consumed)`**
  Decode a single CIL instruction at the start of the slice. Returns the decoded mnemonic, operand string, raw bytes, semantic flags (BRANCH/CALL/RET/READ_MEM/WRITE_MEM/CONDITIONAL/INDIRECT/BARRIER), plus the number of bytes consumed. Errors: Truncated, UnknownOpcode, UnknownPrefixedOpcode.
  *Ground truth*: ECMA-335 Partition III opcode table (e.g. `0x00`→nop, `0x2A`→ret, `0xFE 0x01`→ceq, `0x20 <i32>`→ldc.i4, `0x28 <tok>`→call). Verifiable against ildasm / dnSpy / Mono.Cecil disassembly.

- **`CilArch::new_64() / new_32() / default()`** — construct architecture with given pointer bitness. Implements `Architecture` (name "cil64"/"cil32", little-endian, pointer_size 8/4, `disassemble`, `get_branches`, `registers`, `calling_conventions`).
  *Ground truth*: pointer_size = bitness/8. Branch target = next_address + signed_offset.

- **`CilLinearDisassembler::new(arch, bytes, base_address)`** — iterator producing successive `Instruction`s linearly through a method body.
  *Ground truth*: sum of `Instruction.size` over the stream equals input length when stream contains no decode errors.

### Opcode tables / helpers
- **`lookup_cil_opcode(byte1) -> Option<&CilOpcodeRef>`** — metadata lookup for single-byte opcode.
- **`lookup_cil_fe_opcode(byte2) -> Option<&CilOpcodeRef>`** — same for 0xFE-prefixed.
  *Ground truth*: returns Some for every byte handled in the decoder switch, None for reserved bytes.

### Basic blocks / CFG
- **`cil_find_blocks(code: byte slice) -> Vec<CilBasicBlock>`** — split a method body into basic blocks at branch targets / after branches.
  *Ground truth*: block start offsets coincide with leader instructions (branch targets and instructions following branches/returns).
- **`cil_cfg_text(blocks) -> String`** — textual CFG dump (DOT-like).

### Stack-effect / verification
- **`stack_effect_of(instr: &CilInstr) -> StackEffect`** — operand pop/push count for one instruction.
- **`cil_net_stack_delta(instr) -> Option<i32>`** — net stack delta.
  *Ground truth*: per ECMA-335 Partition III stack transition diagrams (e.g., `dup` => +1, `pop` => -1, `add` => -1, `ret` => -1 for non-void).

### Idioms / metrics
- **`identify_cil_idiom(&[CilInstr]) -> CilIdiom`** — pattern label (e.g. getter/setter/init).
- **`CilComplexityMetrics`** — cyclomatic / nesting metrics.
- **`cil_inline_hint(code) -> CilInlineHint`** — inlining heuristic.
- **`cil_max_local_slot(code) -> u8`** — highest local variable index referenced.
  *Ground truth*: max of N over all ldloc[.N]/ldloca/stloc instructions.

### Compressed integers (ECMA-335 II.23.2)
- **`decode_compressed_uint(data) -> (u32, usize)`**
- **`decode_compressed_int(data) -> (i32, usize)`**
  *Ground truth*: canonical ECMA encoding — single byte 0x00–0x7F = value; two-byte 0x80xx = 14-bit; four-byte 0xC0xxxxxx = 29-bit. Verifiable with Mono.Cecil / System.Reflection.Metadata.

### Constant folding
- **`cil_fold_i32(mne, a, b) -> Option<i32>`**, **`cil_fold_unary_i32(mne, a) -> Option<i32>`** — fold add/sub/mul/div/and/or/xor/shl/shr/neg/not at compile time.
  *Ground truth*: matches Rust/.NET i32 wrapping arithmetic.

### Submodules (high-level)
- **`cil_metadata`** — `CilMetadataReader` parses #~ / #Strings / #US / #Blob / #GUID streams from a PE's metadata root. Verifiable vs `System.Reflection.Metadata`.
- **`cil_lifter`** — `CilLifter` lowers CIL to typed IL expressions (`CilILExpr`, `CilILInsn`, BinOp/UnOp/BranchCond).
- **`exception_handlers`** — `MethodExceptionTable::parse`, `ExceptionFlowAnalyzer`. Verifiable vs ECMA-335 II.25.4.6 (small/fat EH headers).
- **`cil_type_system`** — `parse_method_sig`, `parse_sig_type`, `type_size_in_bytes`. Verifiable vs ECMA-335 II.23.2.
- **`cil_obfuscation`** — RenameObfuscation / ControlFlowObfuscation / StringEncryption / VirtualMachineObf / ObfuscationScore.
- **`cil_stack_tracker`** — abstract stack with type tags, `StackVerifier`.
- **`cil_execution_engine`** — abstract `EvalStack`, `LocalVars`, `Arguments`, `CilValue`.
- **`cil_pattern_recognition`** — `CilPatternRecognizer::scan` → string-encryption / reflection / anti-debug / P/Invoke `PatternMatch`es.
- **`cil_call_graph`** — call-graph construction.
- **`cil_branch_analyzer`** — branch resolution.
- **`wide_prefix`** — `decode_wide_prefix`, `lookup_wide` for 0xFE prefix table.
- **`cil_metadata` — `lookup_dotnet_type(full_name)`** — well-known BCL type lookup.

## Existing MCP tools
Only **one** indirect reference in `rustre-mcp-tools/src/wire_tools.rs:7528`:
`rustre_arch_cil::CilArch::default()` — used as the architecture instance when dispatching disasm/CFG/etc. tools to a `cil`-tagged binary. No dedicated `cil_*` MCP tool is exposed; the crate is reachable only through generic arch-aware tools (`analysis_disasm_at_path_cil`, generic disasm/CFG/call-graph) that select CilArch by architecture string.

## Testable functions (deterministic, externally verifiable)
1. **`CilInstr::decode`** — table-driven test against ECMA-335 opcode bytes; cross-check with ildasm output on a known DLL.
2. **`CilArch::disassemble` + `get_branches`** — verify branch target = `next_addr + signed_offset` for br.s/br/beq/leave.
3. **`decode_compressed_uint` / `decode_compressed_int`** — round-trip vs `System.Reflection.Metadata.BlobReader.ReadCompressedInteger`.
4. **`cil_find_blocks`** — verify leader set on a hand-built body.
5. **`stack_effect_of` / `cil_net_stack_delta`** — vs ECMA-335 stack table.
6. **`cil_max_local_slot`** — vs hand-counted body.
7. **`cil_fold_i32` / `cil_fold_unary_i32`** — vs Rust i32 wrapping ops.
8. **`type_size_in_bytes`** — vs `Marshal.SizeOf` for primitive `CorElementType`s.
9. **`MethodExceptionTable::parse`** — vs known EH header layout (small/fat).
10. **`CilLinearDisassembler`** — round-trip: sum of consumed sizes = body length on a clean body.

## Validator strategy
Build a Rust integration test in `crates/rustre-arch-cil/tests/validator.rs` that:
- Feeds curated opcode-byte fixtures (one per opcode family) and asserts (mnemonic, size, flags) against a hard-coded ECMA-335 table.
- Encodes/decodes compressed integers across the three canonical ranges (1B, 2B, 4B) and the boundary values (0x7F, 0x80, 0x3FFF, 0x4000, 0x1FFFFFFF).
- Disassembles a tiny pre-assembled CIL body (built with the existing `CilMethodBuilder`) and checks: (a) `CilLinearDisassembler` consumes exactly all bytes; (b) `cil_find_blocks` produces the expected leader offsets; (c) net stack delta equals 0 across a balanced body; (d) `get_branches` yields the expected absolute target.
- For a sample of small open-source .NET DLLs (e.g. trivial Hello-World compiled with `dotnet`), cross-reference method header / EH-table parsing against `ildasm`/`Mono.Cecil` JSON dumps stored in `validation/fixtures/`.
- Property test: for random byte sequences feeding `CilInstr::decode`, decoder must either succeed and report `consumed <= bytes.len()` or return one of the three documented errors (no panics).
