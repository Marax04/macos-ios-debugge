# rustre-arch-mips

## Purpose
MIPS architecture backend for the RustRE platform: provides MIPS32/MIPS64 decoder, linear disassembler, instruction encoder, ABI/calling-convention metadata, delay-slot analysis, LLIL lifter, basic-block/CFG construction, prologue/epilogue detection, hazard detection, TLB/COP0 helpers, and segment/virtual-address utilities. Backs the MCP tool `analysis_disasm_at_path_mips`.

## Public Functions (semantic)

### Architecture constructors / decoder (`MipsArch`)
- `MipsArch::mips32_le/mips32_be/mips64_le/mips64_be()` -> MipsArch preset. Verifiable: returned bit-width and endian fields match the constructor.
- `MipsArch::custom(bits, endian, abi)` -> custom-configured arch.
- `MipsArch::read_word(bytes)` -> Option<u32>: reads one 32-bit word respecting arch endian. Ground truth: `int.from_bytes(b[:4], 'big'|'little')`.
- `MipsArch::decode_word(addr, word, raw)` -> `Instruction`: decode one MIPS word into mnemonic+operands. Ground truth: compare with capstone-mips on the same word.

### Encoders (instruction synthesis)
- `encode_rtype/itype/jtype(...)` -> u32: build raw MIPS instruction word from fields. Verifiable: round-trip through `decode_word` should yield the expected mnemonic.
- `encode_nop/addu/subu/and/or/xor/nor/slt/sltu/mult/div/mfhi/mflo/jr/jalr/jal/j/lui/addiu/lw/sw/beq/bne/syscall(...)` -> u32: each builds the canonical encoding for that mnemonic. Ground truth: `gas`/`capstone` produces identical 32-bit word.

### Branch target math
- `branch_target_i(address, simm16)` -> u64: PC-relative I-type branch target = (address+4) + (simm16<<2). Verifiable arithmetically.
- `branch_target_j(address, target26)` -> u64: J-type target = ((address+4) & 0xF0000000) | (target26<<2). Verifiable arithmetically.

### Word utilities
- `swap32(u32)/swap16(u16)` -> byte-swapped value. Ground truth: Python `int.from_bytes(x.to_bytes(...,'big'),'little')`.
- `read_be32/read_le32(bytes, off)` -> Option<u32>. Trivial verify.
- `write_be32/write_le32(bytes, off, word)` -> writes 4 bytes. Trivial verify.
- `is_valid_mips_word(word)` -> bool: heuristic for plausible MIPS encoding.
- `patch_instr(bytes, off, word, endian)`: in-place word patch.
- `patch_branch(...)`: rewrite a branch's target offset.

### Register / ABI helpers
- `gpr(idx)` -> &str: GPR alias name ($zero, $at, $v0...). Ground truth: O32 register name table.
- `gpr_role_o32(idx)/gpr_role_n64(idx)` -> `GprRole`: arg/return/saved/temp/sp/ra classification per ABI. Verifiable against MIPS ABI docs.
- `hi_lo_effect(mnemonic)` -> `HiLoEffect`: whether instruction writes/reads HI/LO. Verifiable against MIPS ISA.
- `rdhwr_reg_desc(reg)` -> &str: rdhwr hardware register description.

### Disassembler / formatter
- `MipsLinearDisassembler::new/offset/current_address/is_done`: stateful linear scanner.
- `lookup_mips_instr(mnemonic)` -> Option<&MipsInstrEntry>: ISA metadata lookup.
- `format_instruction(...)/format_disassembly(...)` -> String: pretty-print. Verifiable by string compare.
- `print_instr(instr, style)` -> String.

### Analysis
- `DelaySlotAnalyzer::has_delay_slot(instr)` -> bool; `::tag_delay_slots(instrs)` -> Vec<bool>. Ground truth: branch/jump opcodes from ISA.
- `MipsBasicBlock::find_blocks(arch, bytes, base)` -> Vec<MipsBasicBlock>: split bytes into basic blocks. Verifiable: block boundaries at branches/targets.
- `MipsCodeStats::from_bytes(...)` -> stats summary.
- `lift_to_llil(instr)` -> Vec<LlilOp>: lift one MIPS instr to LLIL.
- `detect_mips_prologue(instrs)` -> Option<i64>: stack-frame size if prologue recognized. Ground truth: `addiu $sp, $sp, -N` pattern.
- `detect_mips_epilogue(instrs)` -> bool.
- `infer_signature(arch, bytes, base)` -> `InferredSignature`: arg/return inference.
- `build_call_graph(arch, bytes, base)` -> Vec<CallEdge>: jal/jalr edges.
- `is_exception_handler(instrs)` -> bool.
- `StackFrame::from_prologue(instrs)` / `is_leaf()`.
- `find_pattern(instrs, patterns)` -> Vec<usize>: pattern matching.
- `MipsFeatures::detect(arch, bytes, base)`: feature-flag detection (FPU, DSP, MIPS16, etc.).
- `MipsClass::from_mnemonic/is_memory/is_control`.
- `reorder_for_delay_slots(...)`.
- `find_dependencies(instrs)` -> Vec<RegDep>.
- `MipsFields::decode(word)`: split a word into rs/rt/rd/shamt/funct/imm/target.
- `BranchPredictor::update/predict_taken/len/is_empty`.
- `find_hazards(instrs)` -> Vec<(idx, PipelineHazard)>.
- `DisassemblyReport::generate/summary`.
- `build_cfg(arch, bytes, base)` -> Vec<CfgNode>.
- `MipsHistogram::build/top_n/total/count`: mnemonic frequency.
- `scan_constant_pool(arch, bytes, base)` -> constant-pool entries.
- `detect_preamble(bytes)` -> Option<&str>: detect known boot/ELF preambles.

### Memory map / COP0
- `virt_to_phys(vaddr)/phys_to_kseg0/phys_to_kseg1/segment_name(vaddr)`: KSEG0/KSEG1/USEG translation. Ground truth: MIPS memory map constants (KSEG0=0x80000000, KSEG1=0xA0000000).
- `TlbEntry::map_4k/translate`.
- COP0 Status/Cause: `test(status,bit)/is_kernel_mode/exc_code/exc_name/in_delay_slot`. Verifiable against MIPS COP0 spec.

## Existing MCP tools
- `analysis_disasm_at_path_mips` (registered in `wire_tools.rs` line 7507-7510 via `AnalysisDisasmAtPathMipsTool`, uses `rustre_arch_mips::MipsArch::default()`) — linear MIPS disassembly at a given file offset/VA.

## Testable functions (highest external-ground-truth)
1. `MipsArch::decode_word` — vs capstone-mips.
2. All `encode_*` functions — vs gas/capstone assembled bytes.
3. `branch_target_i / branch_target_j` — arithmetic formula.
4. `swap32/swap16, read_be32/read_le32` — Python byteorder.
5. `gpr, gpr_role_o32/n64` — O32/N64 ABI tables.
6. `virt_to_phys, phys_to_kseg0/kseg1, segment_name` — MIPS memory map constants.
7. `exc_code, exc_name, is_kernel_mode` — COP0 spec.
8. `detect_mips_prologue` — synthetic `addiu $sp,$sp,-N; sw $ra,K($sp)` patterns.
9. `hi_lo_effect, lookup_mips_instr` — ISA table compare.

## Validator strategy
Drive validation through three layers:
- (a) Pure-math/bit functions (encoders, branch targets, swaps, segment math): assert against Python-computed reference values for randomized inputs.
- (b) Decoder vs capstone-mips: assemble a corpus with `keystone`/`gas`, decode with `MipsArch::decode_word`, compare mnemonic+operand structure to `capstone` output. Round-trip: encode_* -> decode_word.
- (c) ABI/COP0/segment metadata: assert returned tables against canonical MIPS reference constants (KSEG0=0x80000000, KSEG1=0xA0000000, exc codes 0..31, O32 arg regs $a0-$a3, etc.).
End-to-end smoke: call MCP `analysis_disasm_at_path_mips` on a known MIPS ELF and diff against `objdump -d -m mips`.
