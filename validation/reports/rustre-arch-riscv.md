# rustre-arch-riscv — Analysis

## Purpose
RISC-V architecture backend for RustRE: instruction decoding (standard + compressed C ext + V vector ext), LLIL lifting, CSR/exception/SBI/syscall tables, ABI register info, prologue detection, and arch trait impl (`RiscvArch`) consumed by core disassembler.

## Public functions (semantic)

### Decoding
- **decode_compressed(hw: u16, xlen, addr) -> Result<Instruction>** — expand a 16-bit RVC halfword into a full decoded Instruction for the given XLEN (32/64). Ground truth: compare mnemonic/operands vs `riscv64-unknown-elf-objdump -M no-aliases` for the same halfword.
- **decode_rvv(addr, word: u32, bytes) -> Option<Instruction>** — decode a 32-bit RISC-V Vector extension instruction. Ground truth: objdump with `-march=rv64gcv`.
- **expand_compressed(...)** (compressed_decoder) — expand RVC into equivalent 32-bit encoding. Ground truth: spec Table "C-extension Mapping".
- **decode_stream(bytes, rv64) -> Vec<(offset, Result<CompressedInsn>)>** — sweep-decode a byte buffer as RVC. Ground truth: objdump linear sweep.

### Lifting (LLIL IR)
- **rv_lift_word(pc, word: u32, xlen) -> Vec<LlilOp>** — lift a 32-bit instruction to a list of LLIL micro-ops. Verifiable structurally (e.g. `add x1,x2,x3` → an Add expr writing x1).
- **rv_lift_compressed(pc, hw: u16, xlen) -> Vec<LlilOp>** — same for RVC.

### Lookup tables (pure, deterministic)
- **rv_csr_ext_lookup(addr: u16) -> Option<&RvCsrEntry>** — CSR by number. Ground truth: RISC-V Privileged Spec CSR table (e.g. 0x300=mstatus, 0x305=mtvec, 0xC00=cycle).
- **rv_exc_cause_lookup(code, is_interrupt) -> Option<&RvExcCause>** — mcause decoding. Spec Table 3.6 (e.g. code=2 exc = illegal instruction).
- **rv_cpu_lookup(name) -> Option<&RvCpu>** — CPU profile by name (e.g. "sifive-u54").
- **rv_instr_lookup(mnemonic) -> Option<&RvInstrEntry>** — instruction metadata by mnemonic.
- **sbi_lookup(eid, fid) -> Option<&SbiCall>** — SBI call by (extension id, function id). Ground truth: SBI spec.
- **rv_syscall_lookup(nr) -> Option<&RvSyscall>** — Linux RISC-V syscall by number. Ground truth: kernel `unistd.h` riscv table.
- **rv_soc_lookup(name) -> Option<&RvSoc>** — SoC profile.
- **rv_qemu_region_lookup(addr: u64) -> Option<&RvMmioRegion>** — QEMU virt MMIO region containing addr (e.g. 0x10000000 → UART). Ground truth: QEMU `hw/riscv/virt.c`.
- **csr_name(addr: u16) -> String**, **csr_privilege(addr) -> CsrPrivilege**, **csr_access(addr) -> CsrAccess** (riscv_csr_map) — symbolic CSR info.

### Decoding helpers
- **mcause_decode(cause, xlen) -> TrapCause** / **mcause_decode(...)->(bool,u64,&str)** — split mcause into interrupt bit + code + name. Ground truth: spec — MSB of mcause is interrupt flag.
- **rv_c_classify(hw: u16) -> &'static str** — classify a 16-bit halfword as RVC quadrant/opcode family. Ground truth: bits[1:0] != 11 ⇒ compressed; quadrant from bits[1:0].
- **rv_fp_rm_str(rm: u8) -> &'static str** — FP rounding mode name (0=RNE,1=RTZ,2=RDN,3=RUP,4=RMM,7=DYN).
- **rv_fclass_bit_name(bit: u8) -> &'static str** — name of one of the 10 FCLASS result bits.
- **rv_brev8_32(val: u32) -> u32** — bit-reverse each byte (Zbkb brev8). Ground truth: reversible per byte → trivially testable in Python: for b in u32.to_bytes: int(f"{b:08b}"[::-1],2).

### ABI
- **rv_abi_reg_lookup(name) -> Option<&RvAbiReg>** — map ABI name (e.g. "sp","a0","ra") to register info.
- **rv_fp_abi_reg_lookup(name)** — FP ABI variant ("ft0","fa0",...).
- **rv_callee_saved_regs() -> Vec<&RvAbiReg>** — list callee-saved set (s0–s11, sp, ra ABI-dependent). Ground truth: RISC-V psABI doc.
- **rv_arg_regs() -> Vec<&RvAbiReg>** — a0–a7.
- **rv_fp_arg_regs() -> Vec<&RvAbiReg>** — fa0–fa7.
- **rv_detect_prologue(words: &[u32]) -> (Option<frame_size>, Vec<RvSpillEntry>)** — scan instructions for stack-frame allocation + callee-saved spills. Ground truth: hand-crafted prologue (addi sp,sp,-N; sd ra,off(sp); …) decoded externally.

## Existing MCP tools
- **analysis_disasm_at_path_riscv** (`AnalysisDisasmAtPathRiscvTool` in `rustre-mcp-tools/src/wire_tools.rs:7513`) — disassemble RISC-V at a path/offset using `RiscvArch::default()`.
- Generic disasm path also accepts `arch="riscv"`.
- No dedicated MCP tools for CSR/SBI/syscall lookup, lifter, prologue detector — only the disasm tool.

## Testable functions (externally verifiable ground truth)
1. **rv_brev8_32** — pure bit op, Python reference.
2. **decode_compressed / decode_stream / expand_compressed** — `riscv64-unknown-elf-objdump` on raw bytes.
3. **decode_rvv** — objdump with `-march=…v`.
4. **rv_csr_ext_lookup / csr_name** — RISC-V Privileged Spec CSR table (well-known constants).
5. **rv_exc_cause_lookup / mcause_decode** — Privileged Spec mcause table.
6. **sbi_lookup** — SBI spec (e.g. eid=0x10 base, fid=0 sbi_get_spec_version).
7. **rv_syscall_lookup** — Linux unistd_64 / riscv generic syscall numbers.
8. **rv_qemu_region_lookup** — QEMU virt platform memory map.
9. **rv_arg_regs / rv_callee_saved_regs / rv_abi_reg_lookup** — psABI spec.
10. **rv_fp_rm_str, rv_fclass_bit_name, rv_c_classify** — direct spec table lookup.
11. **rv_detect_prologue** — synthesize a prologue instruction sequence and check detected frame size + spill list.
12. **rv_lift_word / rv_lift_compressed** — structural assertions per opcode family.

## Validator strategy
Two-tier:
- **Tier A (pure tables, no toolchain)** — embed a corpus of known (input → expected) pairs from public RISC-V specs: CSRs, mcause codes, SBI calls, syscall numbers, QEMU MMIO regions, ABI register sets, FP rounding modes, FCLASS bits. Run Rust unit assertions; reference values come straight from the spec text. Also test `rv_brev8_32` against a Python one-liner reference over random u32 inputs.
- **Tier B (decoder / disassembler oracle)** — drive `riscv64-unknown-elf-objdump` (or LLVM `llvm-objdump --triple=riscv64`) as ground truth: assemble or hand-build byte sequences (RV32I/RV64I + C + V), feed them to `decode_compressed`/`decode_rvv`/the `RiscvArch` disasm path, normalize mnemonic+operands, and diff against objdump. For `rv_detect_prologue`, assemble a real prologue with gcc `-Os`, extract the first N words from the .text, and assert detected frame_size matches the immediate of the `addi sp,sp,-N`. For lifters, run word-by-word and assert invariants (writes to expected reg, correct opcode kind, branch targets equal PC+imm).
