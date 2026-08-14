# rustre-arch-x86 — analysis

## Purpose
Production-quality x86/x86-64/x86-16 disassembler and LLIL lifter built on top of `iced-x86`. Provides an `Architecture` implementation (decode, branch extraction, register info, calling conventions, lifting) and a streaming `LinearDisassembler` iterator. Also exposes module-level decoders for opcode tables, instruction database, SIMD/AVX, prefixes, and CFG construction.

## Public functions (semantic, not Rust-literal)

### `X86Arch::new_16bit() / new_32bit() / new_64bit()`
- Input: none
- Output: architecture descriptor configured for that bitness
- Behavior: constructor selecting target mode
- Ground truth: `bits()` returns 16/32/64

### `X86Arch::bits(&self) -> u32`
- Output: bitness (16/32/64)
- Ground truth: trivially asserted against constructor used

### `X86Arch::lift(address, bytes) -> (Vec<LlilAnnotatedInstr>, length)`
- Input: virtual address, raw byte slice
- Output: list of LLIL ops representing semantics of one decoded x86 instruction, plus the byte length consumed
- Behavior: decodes ONE instruction at the given address using iced-x86, then lifts it to LLIL
- Ground truth: length must match the encoded instruction length per Intel SDM / iced-x86. For example `0x90` (NOP) → length=1; `0x48 0x89 0xC3` (mov rbx, rax) → length=3.

### `X86Arch::disassemble(address, bytes) -> Instruction` (Architecture trait)
- Output: structured Instruction { address, length, mnemonic (GAS/AT&T syntax), operands string, raw bytes, flow flags }
- Behavior: decode one instruction, format with GAS formatter
- Ground truth: comparable against `objdump -d -M att` or `iced-x86` reference. E.g. bytes `[0x90]` → mnemonic `"nop"`, length 1. Bytes `[0xC3]` → mnemonic `"ret"`, RET flag set.

### `X86Arch::get_branches(instr) -> Vec<BranchInfo>`
- Output: list of static branch targets (call/jmp/jcc near-targets)
- Ground truth: For `E8 xx xx xx xx` CALL rel32, branch target = address + 5 + sign_ext(rel32). For `EB xx` JMP rel8, target = address + 2 + sign_ext(xx). Verifiable with Python.

### `X86Arch::registers() -> Vec<RegisterInfo>`
- Output: list of architectural register descriptions for the configured bitness
- Ground truth: x86_64 must include RAX..R15, RIP, RSP, RBP, XMM0..15 etc.; x86_32 has EAX..EDI; x86_16 has AX..DI. Counts and pointer widths well-defined.

### `X86Arch::pointer_size() / endian() / name()`
- Output: 2/4/8 bytes; little-endian; "x86_16"/"x86_32"/"x86_64"
- Ground truth: trivially asserted

### `X86Arch::calling_conventions() -> Vec<CallingConvention>`
- Output: list of calling conventions for the bitness (System V / Win64 / cdecl / stdcall etc.)
- Ground truth: 16-bit returns empty; 32-bit and 64-bit are non-empty

### `LinearDisassembler::new(arch, bytes, base_addr)` + `Iterator::next() -> Result<Instruction>`
- Behavior: iterates decoding one instruction at a time advancing offset by each instruction's length
- Ground truth: total decoded length over a valid stream equals stream length; number of instructions matches objdump-derived count.

### `LinearDisassembler::offset() / current_address() / is_done()`
- Output: progress accessors
- Ground truth: monotonic increase; `is_done()` ⇔ offset == bytes.len()

### `lift_to_llil(iced_instr) -> Vec<LlilAnnotatedInstr>`
- Behavior: lifts a single already-decoded iced instruction to LLIL (assumes 64-bit context)
- Ground truth: produces non-empty op list for non-NOP instructions; preserves IP

### `disassemble_and_lift(bytes, ip, bits) -> Vec<(ip, Vec<LlilAnnotatedInstr>)>`
- Behavior: decode + lift entire stream; stop at first invalid encoding
- Ground truth: number of entries == number of valid instructions; first IP == initial `ip`; subsequent IPs are previous + length

### `ArchX86Lifter::new(bits) / lift_instruction(iced) / arch_name()`
- Behavior: thin OO wrapper around `lift_to_llil`
- Ground truth: `arch_name()` returns canonical string per bitness

### `X86LiftAdapter::new(bits) / bits() / decode_one_iced(bits, bytes, ip) / reg_id(reg) / adapt_iced_to_llil(iced, ctx)`
- Behavior: lower-level helpers used by the trait `lift` impl; `decode_one_iced` returns `Some(iced_instr)` if bytes decode, else None; `reg_id` maps iced register enum to a stable u32 ID; `adapt_iced_to_llil` does the iced→LLIL translation
- Ground truth: `decode_one_iced(64, [0x90], 0).is_some()`; `decode_one_iced(64, [], 0).is_none()`; invalid encodings yield None.

### `registers_64bit() -> Vec<RegisterInfo>` (and 32/16 variants in module)
- Output: canonical x86_64 register table
- Ground truth: contains RAX, RIP, RSP; cardinality matches Intel SDM register count

### Sub-modules (re-exported public items)
- `render::{render_instruction, render_instruction_with_syntax, Syntax}` — format an iced instruction as text in Intel/GAS syntax. Ground truth: compare to objdump output.
- `lift::iced_bytes`, `lift::X86Lifter` — low-level lifter primitives.
- `x86_decode_table`, `x86_instruction_database`, `x86_simd_decoder`, `x86_prefix_analyzer`, `x86_control_flow_graph` — opcode/operand metadata, SIMD decoding, prefix parsing, CFG construction.

## Existing MCP tools
Grep on `wire_tools.rs` shows `rustre_arch_x86::X86LiftAdapter::decode_one_iced` is used in two call sites (lines 6330, 6676) inside higher-level MCP tools (likely `analysis_disasm_at_path` / `decompile_*`). No MCP tool is dedicated specifically to this crate; the crate is consumed transitively by disasm/decompile/CFG MCP tools.

## Testable functions (externally verifiable ground truth)
1. `X86Arch::disassemble` — verifiable against `objdump -d -M att` / `capstone` / `iced-x86` reference: mnemonic, operands, length.
2. `X86Arch::lift` / `disassemble_and_lift` — length per instruction matches Intel SDM encoding length; sum of lengths == input bytes for valid streams.
3. `X86Arch::get_branches` — branch target = pc + insn_len + signed displacement; computable with Python.
4. `LinearDisassembler` iteration — instruction count and per-instr lengths match objdump.
5. `X86Arch::pointer_size / endian / name / bits` — pure constants.
6. `registers_*()` — fixed table, asserts on presence/absence and count.
7. `X86LiftAdapter::decode_one_iced` — None on empty/invalid, Some on valid encoding.

## Validator strategy
Build a fixed corpus of known x86_64 encodings with ground-truth (mnemonic, length, branch target if any) computed by Python (manual decode for trivial cases) or by parallel disassembly through an independent library (capstone via `capstone` Python bindings, or pre-recorded objdump output committed as JSON fixtures). For each fixture:
- Call `X86Arch::disassemble` → assert length, mnemonic family (e.g. starts with "mov"/"call"/"ret"), and flow-control flags.
- Call `get_branches` → assert resolved target matches Python-computed `pc + len + disp`.
- Drive a `LinearDisassembler` over a multi-instruction blob → assert (count, sum-of-lengths) match capstone reference.
- Constant checks for `pointer_size`/`endian`/`name`/`bits` and register-table cardinality per bitness.
- Negative tests: empty slice and `0x06` (invalid in 64-bit) → expect `PluginError` and `decode_one_iced` returning None.
