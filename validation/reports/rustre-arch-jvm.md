# rustre-arch-jvm — Analysis Report

## Purpose
JVM bytecode architecture implementation for RustRE. Decodes all ~200 JVM opcodes
(variable-length 1-5 bytes, big-endian, stack-based) per the JVM Specification,
plus class-file structures (constant pool, attributes, code attribute, stack-map
frames, descriptors), a stack-to-virtual-register lifter, a type-checking
bytecode verifier, security-pattern analysis, and invokedynamic handling.

Implements `rustre_core::arch::Architecture` so a JVM `.class` body can be fed
to the generic disassembler/CFG/xref pipeline of the RustRE suite.

## Public API (semantic)

### Decoding — `lib.rs`
- **`JvmInstr::decode(bytes) -> (JvmInstr, usize)`**
  Input: raw bytecode slice. Output: one decoded instruction (mnemonic, operands
  text, semantic InstrFlags, raw bytes) and number of bytes consumed.
  Errors: Truncated / Reserved (0xCA..=0xFF) / UnknownOpcode (invalid wide sub).
- **`JvmInstr::decode_at(bytes, pc_offset)`** — same, but `pc_offset` lets
  `tableswitch`/`lookupswitch` apply the correct 4-byte alignment padding required
  by the JVM spec.
- **`JvmArch`** — `Architecture` impl: `name()="jvm"`, pointer_size=4,
  endian=Big, provides `disassemble`, `get_branches` (resolves 2-byte signed
  for normal branches, 4-byte for goto_w/jsr_w, returns empty for switches),
  exposes local0-local3 as conventional registers.
- **`JvmLinearDisassembler`** — iterator decoding linearly from a base Address,
  advancing by instruction size (or 1 on error to recover).

### Class-file structures
- **`ConstantPoolTag::from_u8 / name / is_wide`** — tag byte ↔ name, marks
  Long/Double as 2-slot.
- **`AttributeKind::from_name`** — string ↔ predefined attribute enum.
- **`VerificationType::decode`** — stack-map frame verification type item.
- **`ClassFileHeader::decode(bytes)`** — parses 0xCAFEBABE magic + minor/major
  version (validates magic).
- **`FieldDescriptor::parse(s)`** — parses one field descriptor char/string
  (e.g. `"I"`, `"Ljava/lang/String;"`, `"[I"`).
- **`parse_method_descriptor(s)`** — parses `(args)return` JVM method descriptor
  into (Vec<FieldDescriptor>, return string).
- **`parse_method_descriptor_typed(s)`** — typed variant returning JvmTypeDesc.
- **`opcode_info(op)`** — static table: mnemonic, length, stack delta, flags
  per opcode.
- **`ExceptionHandler::decode` / `LineNumberEntry::decode` / `CodeAttribute::decode`**
  — parses Code attribute sub-structures.
- **`CodeAttribute::disassemble()`** — disassembles the embedded `code[]`.
- **`MethodStats::from_bytes(code)`** — counts opcodes, branches, invocations,
  allocations from a method body.

### Analysis helpers
- **`jvm_build_cfg(bytecode) -> Vec<JvmBlock>`** — basic-block CFG from a
  method's code array.
- **`jvm_max_stack_depth(bytecode) -> i32`** — symbolic max stack depth.
- **`jvm_count_invocations(bytecode) -> usize`** — count of invoke* opcodes.
- **`jvm_count_allocations(bytecode) -> usize`** — count of new/newarray/
  anewarray/multianewarray.
- **`jvm_cyclomatic_complexity(bytecode) -> u32`** — McCabe complexity from
  branch count.

### Submodules (high-level)
- `wide_opcodes` — focused decoders: `decode_wide`, `decode_tableswitch`,
  `decode_lookupswitch`, `decode_multianewarray`, `decode_invoke*`, plus
  `OpcodeMeta::lookup(opcode)` returning static metadata.
- `jvm_lifter` — `JvmLifter::lift_method(bytecode)` produces a Vec of
  `LiftedInstr` (stack-machine ops → 3-address-style ops with virtual slots).
- `jvm_bytecode_verifier` — `verify_method(...)` / `JvmBytecodeVerifier` runs
  data-flow type checking over the bytecode and returns VerifyResult.
- `jvm_attribute_parser` — full attribute parser: `JvmAttributeParser::parse_all`
  / `parse_code_attr`, including StackMapFrames and annotations.
- `jvm_constant_pool` / `constant_pool_analysis` — `ConstantPool` (push/get/
  utf8/class_name), `CpReferences` (ref counts / unreferenced detection),
  `ConstantPoolOptimizer`, `CpBytecodeScanner::scan`.
- `jvm_invoke_dynamic` — `MethodHandle`, `BootstrapMethod` with detectors for
  `LambdaMetafactory` and `StringConcatFactory`.
- `jvm_security` — pattern matchers for SecurityManager checks, doPrivileged,
  ClassLoader abuse, Serialization risks, Reflection misuse; `JvmSecurity`
  facade aggregating findings with a risk score.

## Existing MCP tools
- `analysis_disasm_at_path_jvm` (wire_tools.rs line 3601/7531) — wraps
  `rustre_arch_jvm::JvmArch` for the generic "disasm at path" tool, identical
  shape to the WASM / CIL / ARM64 / RISC-V / MIPS siblings.

No other MCP tool exposes constant-pool, verifier, lifter, security analysis,
or class-file header parsing.

## Externally verifiable functions (ground truth)

| Function | Ground truth tool |
|---|---|
| `JvmInstr::decode` mnemonic + size | `javap -c -p ClassName` on a known `.class`, or Python `dis` over a hand-built bytecode |
| `ClassFileHeader::decode` magic/version | `od -An -tx4` first 8 bytes of any `.class`; magic must be `0xCAFEBABE` |
| `parse_method_descriptor("(IJLjava/lang/String;)V")` | JVM spec §4.3.3 — args `[I, J, Ljava/lang/String;]`, return `V` |
| `FieldDescriptor::parse("[I")` | JVM spec §4.3.2 |
| `JvmArch::endian / pointer_size / name` | constants ("jvm", Big, 4) per spec |
| `jvm_count_invocations` / `_allocations` | `javap -c` then grep `invoke|new`; or count opcode bytes in {0xB6..0xBA, 0xBB, 0xBC, 0xBD, 0xC5} |
| `jvm_cyclomatic_complexity` | edges − nodes + 2 on the CFG produced by `jvm_build_cfg`, or "branches + 1" |
| `tableswitch` / `lookupswitch` padding | spec: default/low/high words must start at offset ≡ 0 mod 4 from method start |
| `ConstantPoolTag::is_wide(Long|Double)` | spec §4.4.5: Long/Double take 2 slots |
| `goto_w` / `jsr_w` branch target arithmetic | spec: signed 4-byte offset from instruction start |

## Validator strategy
Two complementary layers:

1. **Synthetic bytecode unit oracles** (no JDK required): construct small byte
   slices for every opcode family — constants, loads/stores, arithmetic,
   branches (signed 16-bit offsets), `goto_w`, `tableswitch` with PC offsets 0,
   1, 2, 3 to verify alignment padding, `lookupswitch`, `wide` + sub-opcode,
   `invokeinterface` (5 bytes), reserved 0xCA..=0xFF (must error),
   truncated buffers (must error). Compare `(mnemonic, size, flags)` against
   a Python reference table built from the JVM spec opcode list.
2. **Real .class oracle** (if a JDK is on PATH): compile a small Java fixture,
   diff `JvmInstr::decode` walk against `javap -c -p -v Fixture.class` output
   (parse the disassembly listing). Verify `ClassFileHeader::decode` against
   the first 8 bytes and `javap -v` "major version" / "minor version" lines.
   Verify `parse_method_descriptor` against the method descriptors printed by
   `javap`.

For numerical helpers (`jvm_cyclomatic_complexity`,
`jvm_count_invocations/_allocations`, `jvm_max_stack_depth`) the validator
generates random valid bytecode sequences and checks invariants:
- complexity == branch_count + 1
- count_invocations == number of 0xB6..0xBA bytes at instruction starts
  (recompute by re-walking via `JvmInstr::decode`)
- max_stack_depth never negative; bounded by `Code.max_stack` when a Code
  attribute is parsed.

Verifier and lifter are checked end-to-end: lift a verified method, then
re-verify that every `LiftedInstr` has consistent slot categories; cross-check
that `JvmBytecodeVerifier::verify_method` accepts `javap -v`-verified methods
and rejects mutated/truncated ones.
