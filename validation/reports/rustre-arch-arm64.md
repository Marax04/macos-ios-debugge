# rustre-arch-arm64 — Crate Analysis

## Purpose
Production-grade ARM64/AArch64 architecture support for RustRE. Provides:
- A64 instruction decoding (4-byte fixed words, little-endian) via `yaxpeax-arm`.
- Flag classification (BRANCH/CALL/RET/CONDITIONAL/INDIRECT/READ_MEM/WRITE_MEM/BARRIER).
- Branch-target extraction for direct/conditional branches and calls.
- Full register table (250+: X/W, V/Q/D/S/H/B, system regs).
- AAPCS64 + Apple ARM64 calling conventions.
- Linear streaming disassembler.
- Mnemonic-based instruction category classifier.
- Static tables: system registers, LSE atomics, exception vectors, ESR classes, PMU events, CPU IDs, ISA extensions, TLBI/DC/IC/AT system ops, HINT encodings, barrier options, SCTLR/TCR/FPCR field maps.
- Bit-level helpers: B/CBZ/TBZ offset decoders, MOVZ/ADD-imm immediate extractors, logical-imm decoder, NZCV add/sub flags, PAC pointer tag get/set/strip, page alignment.
- Submodules: NEON decoder + lifter, SVE/SVE2 decoder + lifter, PAC analyzer, jump-table detector, exception-level table, feature detector, calling-conv registry.

## Public functions (key, externally verifiable)

### Architecture trait (`Arm64Arch`)
- `Arm64Arch::new() -> Arm64Arch` — zero-sized constructor.
- `Architecture::name(&self) -> "aarch64"`.
- `Architecture::pointer_size(&self) -> 8`.
- `Architecture::endian(&self) -> Endian::Little`.
- `Architecture::disassemble(addr, bytes) -> Instruction`
  - Input: VA + ≥4 bytes (LE A64 word).
  - Output: `Instruction { mnemonic, operands, size=4, bytes, flags }`.
  - Ground truth: cross-check against `llvm-objdump -d --triple=aarch64` / Capstone for any A64 word.
- `Architecture::get_branches(instr) -> Vec<BranchInfo>`
  - For B/BL: PC + signed 26-bit imm × 4.
  - For B.cond/CBZ/CBNZ/TBZ/TBNZ: PC + signed 19/14-bit imm × 4, conditional.
  - For RET/ERET: terminator entries, no target.
  - Ground truth: compute target manually from the encoding; compare with Capstone.

### Linear disassembler
- `Arm64LinearDisassembler::new(bytes, base)` / `offset()` / `current_address()` / `is_done()`.
- `Iterator<Item = Result<Instruction>>` — yields one instruction per 4 bytes.
- Ground truth: count = `bytes.len() / 4`; addresses are `base + 4*i`.

### Category classifier
- `Arm64InstrCategory::classify(mnemonic) -> {DataProcessing|LoadStore|Branch|FloatSimd|System|Barrier|AtomicMemory|Miscellaneous}`.
- Ground truth: per-mnemonic spec table; "add"→DataProc, "ldr"→LoadStore, "b"/"bl"/"ret"→Branch, "dmb"→Barrier, "ldxr"→AtomicMemory.

### Bit-level encoding helpers (pure functions — directly verifiable)
- `a64_b_offset(word) -> i64` — sign-extended 26-bit imm × 4.
- `a64_b_target(pc, word) -> u64` — pc + offset.
- `a64_b19_offset(word) -> i64` — for B.cond/CBZ/CBNZ (19-bit × 4).
- `a64_b14_offset(word) -> i64` — for TBZ/TBNZ (14-bit × 4).
- `a64_add_imm(word) -> (imm12, shift)`; `a64_add_imm_value(word) -> u64`.
- `a64_mov_imm(word) -> (imm16, shift)`; `a64_movz_value(word) -> u64`.
- `a64_ls_uoff(word, size) -> u32` — unsigned LDR/STR offset scaled by size.
- `a64_group(word) -> A64Group` — top-level decode group.
- `is_bl/is_b/is_cbz/is_cbnz/is_ret(word) -> bool` — opcode mask checks.
- `decode_logical_imm(n, immr, imms, reg_size) -> Option<u64>` — ARM logical-immediate decoder (spec'd algorithm — verifiable against ARM ARM tables).
- `add64_nzcv(a,b)` / `sub64_nzcv(a,b) -> Nzcv` — NZCV flag computation. Ground truth: bit-test against expected N/Z/C/V.

### Pointer authentication / tagging helpers
- `get_ptr_tag(ptr) -> u8` — bits 56..64.
- `set_ptr_tag(ptr, tag) -> u64`.
- `strip_ptr_tag(ptr) -> u64`.
- `canonical_address(va) -> u64` — sign-extend bit 55.
- `pac_strip_mask(va_bits)` / `pac_strip_pointer(ptr, va_bits)`.

### Page helpers
- `page_base_4k`/`page_offset_4k`/`page_base_64k`/`page_offset_64k`.
- `align_up(val, align)` / `align_down(val, align)`.

### Encoding constructors (PAC)
- `encode_pacia(rd, rn)`, `encode_autia(rd, rn)`, `encode_xpaci(rd)`, `encode_retaa()` — fixed-form A64 word constants.

### Lookup tables (return `Option<&'static T>`)
- `arm64_sysreg_lookup(name)`, `lse_lookup`, `dp_lookup`, `ls_lookup`, `simd_fp_lookup`, `sys_instr_lookup`.
- `esr_class_lookup(ec)`, `a64_exc_vector_at(offset)`, `barrier_option_lookup(opt)`, `hint_lookup(enc)`.
- `pmu_event_lookup(num)`, `arm64_cpu_lookup(impl, part)`, `isa_ext_lookup(name)`.
- `tlbi_op_lookup`, `dc_op_lookup`, `at_op_lookup`.

### Calling convention / role
- `aapcs64_role(n) -> Aapcs64Role` — X0..X30 role per AAPCS64.
- `aapcs64_fp_role(n) -> Aapcs64FpRole`.

### Submodule entry points
- `aarch64_neon::NeonDecoder`, `NeonLifter`, `neon_register_map()`.
- `aarch64_pac::decode_pac_instruction(addr, raw) -> Option<PacInstruction>`; `PacAnalyzer`.
- `aarch64_sve::AArch64Sve`, `SveLifter`, `SveInstrStats`.
- `arm64_sve_decoder::decode_sve(word) -> Option<SveInsn>`.
- `arm64_pac_analyzer::classify_pac_mnemonic(m)`, `Arm64PacAnalyzer`.
- `arm64_jump_table::detect_jump_tables(instrs) -> Vec<JumpTableInfo>`.
- `arm64_exception_levels::sysreg_for_el(el)`, `el_name(el)`, `ElTable`.
- `arm64_feature_detector::Arm64FeatureDetector`, `FeatureSet`.
- `arm64_calling_conventions::Arm64CallingConvention`, `CallingConventionRegistry`.

## Existing MCP tools
- `analysis_disasm_at_path_arm64` (wire_tools.rs:7477-7480) — wraps `Arm64Arch::new()` for path-based disassembly.
- Also referenced indirectly by `crypto_scan` / feature detector tools when `arch=arm64`.

## Testable / Ground-truth strategy
| Function | Validator |
|---|---|
| `disassemble` | Compare mnemonic+operands against Capstone (`capstone-engine` py) for known A64 words (NOP D503201F, RET D65F03C0, BL 94000001, etc.) |
| `get_branches` target | Manually compute `pc + sign_extend(imm26)*4`; verify match |
| `a64_b_offset / a64_b19_offset / a64_b14_offset` | Encode known offsets, decode, assert equality |
| `a64_movz_value`, `a64_add_imm_value` | Re-derive from raw bits |
| `decode_logical_imm` | Cross-check against published ARM ARM `DecodeBitMasks` reference (e.g. table in LLVM tests) |
| `add64_nzcv / sub64_nzcv` | Compare against u64/i64 wrapping arithmetic + manual flag bit derivation |
| `get_ptr_tag / set_ptr_tag / strip_ptr_tag` | Bit-shift identities |
| `align_up / align_down / page_base_*` | Trivial arithmetic identities |
| `aapcs64_role(n)` | AAPCS64 spec table: X0–X7 args, X8 indirect-result, X9–X15 caller-saved, X16–X17 IP0/IP1, X18 platform, X19–X28 callee-saved, X29 FP, X30 LR |
| Linear disassembler | `count == bytes.len()/4`; addresses arithmetic |
| Lookup tables | Spot-check entries against ARM ARM (e.g. SCTLR_EL1 = op0=3,op1=0,CRn=1,CRm=0,op2=0; encoded == 0xC080) |
| `is_b / is_bl / is_ret` masks | Apply mask to known encodings |
| `encode_pacia / encode_retaa` | Compare against ARM ARM fixed encodings |

## Validator strategy
1. **Pure-arithmetic helpers** → property tests in Python (no external tool): bit-pack random inputs, run via PyO3/ctypes binding or a tiny Rust test harness, compare against reference Python implementation of the same spec algorithm (logical-imm, NZCV, offsets).
2. **Decoder** → corpus of ~50 hand-crafted A64 words covering each Opcode arm in `flags_for`; assert mnemonic + flag set matches Capstone output.
3. **Lookup tables** → assert encoded() values & lookup roundtrip for ~10 canonical entries from ARM ARM (SCTLR_EL1, NZCV, TPIDR_EL0, HCR_EL2, SCR_EL3).
4. **Branch math** → for B/BL/B.cond/CBZ/TBZ encode imm with random sign-extended values, decode via `a64_b*_offset`, assert equality.
5. **AAPCS64 roles** → static table-vs-spec assertion.
