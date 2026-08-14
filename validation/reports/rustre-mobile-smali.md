# rustre-mobile-smali

Smali / Dalvik bytecode toolkit: types, lexer, parser, disassembler, assembler, printer,
optimizer, patcher, type resolver, annotation parser, control-flow, and analysis.

## Cargo.toml

- name: `rustre-mobile-smali` v0.1.0, edition 2024
- deps: `serde`, `serde_json`, `thiserror`, `anyhow`, `bitflags` (all workspace)
- lints: workspace
- license/authors/etc. inherited from workspace

## Module map (`src/lib.rs`)

```
assembler           disassembler        lexer              parser            printer
smali_analysis      smali_analyzer      smali_assembler    smali_optimizer   smali_parser
smali_patcher       smali_type_resolver smali_annotation_parser              smali_control_flow
```

## Core types (lib.rs)

| Item | Kind | Purpose |
|---|---|---|
| `SmaliError` | enum (thiserror) | `ParseError(String)`, `InvalidOp(String)`, `InvalidReg(u8)` |
| `SmaliReg { num: u8 }` | struct | `v<n>` if `<64`, else `p<n-64>` |
| `SmaliOp` | enum | High-level mnemonic set + `Other(String)` |
| `SmaliOperand` | enum | `Reg`, `Literal(i64)`, `Str`, `TypeRef`, `FieldRef`, `MethodRef` |
| `SmaliInstr { op, operands, label }` | struct | `fn to_text() -> String` |
| `SmaliAccess: u32` | bitflags | PUBLIC/PRIVATE/PROTECTED/STATIC/FINAL/CONSTRUCTOR/NATIVE/ABSTRACT |
| `SmaliField { name, type_desc, access, initial }` | struct | |
| `SmaliMethod { name, class, signature, access, registers, instructions }` | struct | `is_constructor()`, `instr_count()` |
| `SmaliClass { name, super_class, access, methods, fields, interfaces }` | struct | `mock(name)`, `find_method(name)`, `static_methods()` |
| `DalvikOpcode` | `#[repr(u8)]` enum | Full Dalvik 0x00–0xFF set; `from_byte(u8) -> Self`, `as_byte() -> u8` |
| `opcode_to_smali(DalvikOpcode) -> &'static str` | const fn | mnemonic mapping |
| `instruction_size_bytes(DalvikOpcode) -> usize` | const fn | byte size of encoded instr |
| `DexContext` | struct | DEX string/type/method pools for disasm |
| `SmaliInstruction` | struct | rich disasm instr (offset, opcode, mnemonic, operands) |
| `SmaliDisassembler` | struct | decodes DEX bytecode to `SmaliInstruction` list |
| `SmaliTextMethod`, `SmaliTextClass` | structs | text-level parse outputs |
| `SmaliClassParser` | struct | parse smali class source text |
| `SmaliSearch` | struct | search utilities over parsed classes |
| `parse_type_descriptor(&str) -> String` | fn | `Ljava/lang/String;` -> readable |
| `parse_method_descriptor(&str) -> (Vec<String>, String)` | fn | (params, return) |
| `DalvikAssembler`, `DalvikDisassembler` | structs | bytecode <-> textual smali |

## Submodule public API (selected)

### assembler.rs
- `DalvikInstr`, `MethodCode` structs
- `assemble(method: &SmaliMethod) -> Result<MethodCode, SmaliError>`

### disassembler.rs
- `Format` enum, `OpcodeDesc` struct, `OPCODE_TABLE: &[OpcodeDesc]` (const)
- `lookup_opcode(u8) -> Option<&'static OpcodeDesc>`
- `DisasmInstr`, `DisasmStats`
- `disassemble(code: &[u8]) -> Result<Vec<DisasmInstr>, SmaliError>`
- `disassemble_words(words: &[u16]) -> Result<Vec<DisasmInstr>, SmaliError>`

### lexer.rs
- `Token`, `RegisterKind`, `Spanned`, `Lexer<'a>`
- `tokenize(src: &str) -> Result<Vec<Spanned>, SmaliError>`
- `tokenize_flat(src: &str) -> Result<Vec<Token>, SmaliError>`

### parser.rs
- `SmaliFile`, `SmaliAnnotation`, `SmaliAnnotationValue`
- `parse(tokens: Vec<Spanned>) -> Result<SmaliFile, SmaliError>`
- `parse_str(src: &str) -> Result<SmaliFile, SmaliError>`

### printer.rs
- `PrintOptions`, `ClassDiff`
- `print_class`, `print_class_opts`, `print_field`, `print_method`, `print_method_opts`,
  `print_instr`, `print_operand`, `print_reg`
- `access_string(SmaliAccess) -> String`, `escape_string(&str) -> String`
- `diff_classes(old: &SmaliClass, new: &SmaliClass) -> ClassDiff`

### smali_parser.rs
- `Token`, `Lexer<'a>`, `SmaliParser`
- `ParsedInstruction`, `ParsedLabel`, `ParsedMethod`, `ParsedField`, `ParsedClass`,
  `TryCatchBlock`, `ExceptionHandler`
- `mnemonic_to_opcode(&str) -> DalvikOpcode`
- `parse_smali(source: &str) -> Result<ParsedClass>`

### smali_assembler.rs
- Consts: `DEX_MAGIC`, `HEADER_SIZE`, `ENDIAN_CONSTANT`, `NO_INDEX`
- `lo32_u64(u64) -> u32`
- Pool builders: `StringTable`, `TypeTable`, `ProtoId`/`ProtoTable`, `FieldId`/`FieldTable`,
  `MethodId`/`MethodTable`
- `encode_instruction(insn: &ParsedInstruction) -> Vec<u8>`
- `MethodBytecode`, `TryItem`, `EncodedCatchHandler`, `DexWriter` (writes a DEX file)

### smali_optimizer.rs
- `OptimizationStats`, `ConstantValue`, `RegisterFile`, `BasicBlock`,
  `OptimizerConfig`, `SmaliOptimizer`
- `build_cfg(...)`, `liveness_analysis(...)`, `find_dead_instructions(...)`,
  `remove_nops(...)`, `remove_trivial_moves(...)`, `remove_dead_code(...)`,
  `constant_propagation(...)`
- `estimate_bytecode_size(&[ParsedInstruction]) -> usize`

### smali_patcher.rs
- `PatchError`, `SmaliLine`, `PatchOp`
- `MethodPatcher`, `SecurityBypass`, `ApkPatcher`
- `ApkPatchConfig`, `KeystoreConfig`, `ApkPatchResult`
- `parse_method_body(&str) -> Vec<SmaliLine>`
- `find_methods_in_smali(&str) -> Vec<(String, usize, usize)>` (name, start, end)
- `patch_smali_file(...)`

### smali_type_resolver.rs
- `SmaliType` enum, `MethodSignature`, `FieldDescriptor`, `MethodDescriptor`, `TypeStats`
- `parse_type_str(&str) -> Option<SmaliType>`
- `SmaliTypeResolver`

### smali_annotation_parser.rs
- `AnnotationVisibility`, `AnnotationValue`, `AnnotationElement`, `SmaliAnnotation`
- `SmaliAnnotationParser`, `AnnotationIndex`

### smali_control_flow.rs
- `SmaliEdgeKind`, `SmaliEdge`, `SmaliBlock`, `SmaliCfg`, `CfgStats`
- `build_cfg(method: &SmaliMethod) -> SmaliCfg`

### smali_analysis.rs
- `SmaliCallGraph`, `SmaliXref`, `ApiUsage`, `StringUsage`, `ObfuscationScore`,
  `SmaliReport`, `SmaliAnalysis`

### smali_analyzer.rs
- `SmaliAnalysisError`, `SuspiciousPatternKind`, `SuspiciousFinding`
- `SmaliMethodNode`, `CallEdge`, `InvokeKind`
- `SuspiciousPatternScanner`, `SmaliCallGraph`, `SmaliClassAnalysis`
- `DataFlowFact`, `DataFlowSource`
- `parse_smali_method(class: &str, method_text: &str) -> SmaliMethodNode`
- `intra_method_data_flow(method_text: &str) -> Vec<DataFlowFact>`

## I/O summary

- **Inputs**: smali source text (`&str`), token streams (`Vec<Spanned>`), raw DEX bytecode
  (`&[u8]` / `&[u16]`), `SmaliMethod`/`SmaliClass` structures, opcode bytes (`u8`).
- **Outputs**: parsed ASTs (`ParsedClass`, `SmaliFile`, `SmaliTextClass`), disassembled
  instructions (`Vec<DisasmInstr>`, `Vec<SmaliInstruction>`), encoded bytecode
  (`Vec<u8>` per instr, full DEX via `DexWriter`), printed smali text, CFG/call-graph/
  analysis reports, patched smali files.
- **Errors**: `SmaliError` (parse/op/reg), `PatchError`, `SmaliAnalysisError`, `anyhow::Result`.
- No filesystem or network I/O at the library boundary; pure in-memory transforms
  (callers handle file I/O).

## Tests
Integration tests present: `tests/blitz.rs`, `tests/blitz2.rs`.
