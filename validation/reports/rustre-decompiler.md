# rustre-decompiler — Crate analysis

## Purpose
Glue crate that turns a binary file + a function VA into a `DecompiledFunction`
(pseudo-C, recovered signature, locals, structs). It is the orchestration layer
on top of the loader, x86 disassembler, callconv detector, signature recovery,
SSA, type recovery, control-flow structuring (cfs) and the C emitter
(rustre-decompiler-c). It also exposes lower-level building blocks
(disassemble-only, SSA construct, signature recovery, type recovery,
register-width helpers, statement sequencing) so MCP tools and tests can use
pieces of the pipeline independently.

## Public functions (semantic view)

### binary_entry.rs (top-level entry points)
- `load_binary(path) -> RichLoadResult`
  - In: filesystem path to a PE/ELF/Mach-O.
  - Out: parsed binary (sections, symbols, exports, arch, bits, base, raw bytes).
  - Behavior: read file, dispatch to multi-format loader registry.
  - External ground truth: `pefile`/`lief`/`objdump` should report the same
    arch, bits, base address, and section count for a given input.

- `slice_at_va(load, va) -> Option<(base_va, &bytes)>`
  - In: loaded binary, virtual address.
  - Out: slice of bytes backing that VA (None if unmapped).
  - Truth: VA→file-offset conversion matches `objdump -h` section mapping.

- `disassemble_function_x86(bytes, ip, bits, max_bytes, max_instr) -> Vec<Instruction>`
  - In: code bytes, start IP, x86 bit mode (16/32/64), bounds.
  - Out: decoded instruction list, stopping at first RET/invalid/limit.
  - Truth: per-instruction mnemonics + lengths verifiable with `capstone`,
    `iced-x86`, or `objdump -d` on the same bytes.

- `decompile_function_from_binary(path, fn_va, opts) -> DecompiledFunction`
  - In: binary path, function VA, decompiler options.
  - Out: full decompiled function (C pseudocode string, signature, vars).
  - Truth: comparable to IDA Hex-Rays / Ghidra decompilation of the same VA
    (structurally: arg count, local count, return-detected behavior).

- `decompile_function_in_load(load, fn_va, opts) -> DecompiledFunction`
  - Same as above but reuses a preloaded `RichLoadResult` (batch hot path).

- `detect_functions_in_load(load) -> Vec<FunctionBoundary>`
  - In: loaded binary.
  - Out: list of detected function start/end VAs.
  - Truth: function count and starts comparable to IDA `list_funcs` / Ghidra
    `getFunctions()` for the same binary (kg/IDA baseline says 1456 funcs on
    cargo-zyphora.exe).

- `standard_pipeline_arc(opts) -> Arc<DecompilerPipeline>` — factory.

### callconv_bridge.rs
- `lift_mnemonic(mnemonic, operands) -> Vec<DetectInstr>` — single-insn lift to callconv detector form.
- `lift_mnemonic_stream(iter) -> Vec<DetectInstr>` — streaming variant.
- `lift_instructions(&[Instruction]) -> Vec<DetectInstr>` — slice variant.
- `detect(detect_instrs, arch, os) -> CallConvInference` — guess calling convention.
  - Truth: for a function known to be MSVC x64 (e.g. PE x64), result should be `Microsoftx64`/`Win64`.
- `arch_from_str(str) -> Arch` — pure string parsing.
- `detect_with_label(...)` / `label_from_pattern(pattern) -> String` — labeling helpers.

### mem_operand.rs
- `parse_mem_operands(operands: &str) -> Vec<MemOperand>`
  - In: textual operand string from disassembler (e.g. `qword ptr [rbp-0x10]`).
  - Out: structured base/index/scale/disp.
  - Truth: deterministic parser; easy unit-test with known strings.

### pseudocode_generator.rs
- `is_c_keyword(name) -> bool` — pure lookup vs C keyword list. Trivial truth.

### signature_recovery.rs
- `detect_calling_convention(...)` — wrapper.
- `analyze_stack_frame(instructions) -> StackFrame`
  - Out: prologue size, locals size, saved regs.
  - Truth: matches `sub rsp, N` prologue read directly from disasm.
- `recover_signature(...) -> RecoveredSignature` — args/return type inference.
- `recover_signature_auto(...)`, `recover_signature_with_noreturn(...)` — variants.
- `render_c_signature(sig, name) -> String`
  - Out: C-style declaration text.
  - Truth: deterministic formatting from a known sig.

### ssa.rs
- `construct_ssa(input) -> SsaForm`
  - In: instructions + CFG-ish input.
  - Out: SSA form with phi insertion.
  - Truth: well-defined CS algorithm; properties testable (each def unique,
    every use dominated by its def).

### stack_locals.rs
- `detect_struct_candidates(engine) -> Vec<StructOnStackCandidate>`.
- `mask_prologue(insns) -> Range<u64>` / `mask_epilogue(insns) -> Range<u64>`
  - Truth: returned ranges should bound the typical `push rbp; mov rbp,rsp; sub rsp,N` / `leave; ret` sequences.
- `build_report(...)` — structured report.

### statement_sequencer.rs
- `sequence_block(stmts) -> SequenceResult`
- `sequence_blocks(blocks) -> SequenceResult`
  - Truth: stable, idempotent ordering; round-trip property tests possible.

### type_recovery_engine.rs
- `recover_types(constraints) -> Vec<InferredType>`
  - Truth: for a known constraint set (e.g. "var used as u32 add"), output type
    should be `u32`.
- `detect_heap_bases(instructions) -> Vec<(idx, name)>`
  - Truth: locates calls to known allocators (malloc/HeapAlloc/etc.) at the
    given instruction indices — verifiable by string search of mnemonics.

### variable_recovery_engine.rs
- `recover_vars(...)` — produces named local variables from stack/regs.

### x86_register_width.rs — PURE FUNCTIONS, IDEAL TRUTH TARGETS
- `register_width_bytes(reg: &str) -> Option<u8>` — e.g. `"rax"→8`, `"eax"→4`, `"ax"→2`, `"al"→1`. Truth: Intel SDM.
- `register_canonical(reg: &str) -> String` — e.g. `"eax"→"rax"` (on 64-bit). Truth: Intel SDM aliasing table.
- `width_hint_from_instr(mnemonic, operands) -> Option<u8>` — e.g. `"mov"`,`"dword ptr [...]"` → 4.

### lib.rs (re-exports + helpers)
- `infer_register_sign_hints(insns) -> HashMap<String, SignHint>` — signed-vs-unsigned hint per register based on `movsx`/`movzx`/`idiv`/`div` etc. Truth: deterministic from instruction set.

### pipeline_coordinator.rs
- `standard_pass_specs() -> Vec<PassSpec>` — returns the canonical pass list; truth: stable known set.

## Existing MCP tools (wire_tools.rs)
- `decompiler_core_batch_decompile` (uses `batch_decompiler::BatchDecompiler`)
- `decompiler_recover_structs` (uses `decompile_function_in_load` + struct_recovery)
- `decompiler_stack_frame_report` (uses `decompile_function_in_load` + stack analysis)
- `decompile_function_path` (PDB-aware; uses `decompile_function_from_binary`)
- Internal helpers also call: `load_binary`, `slice_at_va`, `detect_functions_in_load`, `decompile_function_in_load`, `DecompOptions`, `VarStorage`.

Not exposed via MCP (gap candidates): `disassemble_function_x86` as a
standalone tool, `analyze_stack_frame`, `recover_signature*`,
`render_c_signature`, `construct_ssa`, `recover_types`,
`detect_heap_bases`, `register_width_bytes`/`register_canonical`/
`width_hint_from_instr`, `parse_mem_operands`, `infer_register_sign_hints`,
`standard_pass_specs`.

## Externally testable functions (best validator targets)
1. `register_width_bytes`, `register_canonical`, `width_hint_from_instr`
   — pure, Intel-SDM-grounded, table-comparable.
2. `is_c_keyword` — pure C-spec lookup.
3. `parse_mem_operands` — deterministic parser, golden strings.
4. `disassemble_function_x86` — cross-validate vs capstone/iced-x86 on same bytes.
5. `load_binary` — cross-validate sections/arch/bits/base vs `pefile`/`lief`.
6. `slice_at_va` — cross-validate vs `pefile.get_offset_from_rva` + image_base.
7. `detect_functions_in_load` — cross-validate count vs IDA baseline (1456 on
   cargo-zyphora.exe per MEMORY.md).
8. `analyze_stack_frame` — derivable from prologue bytes.
9. `detect_heap_bases` — find call sites to known allocator names.
10. `arch_from_str` — pure lookup.
11. `render_c_signature` — string format from known input.
12. `decompile_function_from_binary` — structural checks (returns non-empty
    pseudocode, signature has plausible arg count) vs IDA Hex-Rays.

## Validator strategy
Two tiers:

- Tier A (pure / table-driven): build a Python validator using a known
  ground-truth dictionary (register widths from Intel SDM, C keyword list,
  golden mem-operand strings, golden arch strings). Call each Rust pure
  function via a thin CLI/test harness or via `cargo test` JSON output and
  diff against the dict. 100% deterministic.

- Tier B (binary-grounded): pick `cargo-zyphora.exe` (already in IDA baseline)
  plus a small handcrafted PE.
  * `load_binary` → compare sections/arch/bits/base with `pefile` (Python).
  * `slice_at_va` → compare a sample of VAs with `pefile.get_offset_from_rva`.
  * `disassemble_function_x86` → for each of N known function starts, decode
    first 16 bytes and compare mnemonic sequence with `capstone`/`iced-x86`.
  * `detect_functions_in_load` → compare count + start-set with IDA baseline
    (1456); accept ±tolerance band.
  * `decompile_function_from_binary` → smoke test: non-empty pseudocode,
    signature present, no panic on a curated VA list from the baseline.

Run both tiers through `pytest`, emitting a JSON report under
`validation/reports/` next to this file.

## Output JSON
{
  "crate": "rustre-decompiler",
  "purpose": "Binary path + VA -> DecompiledFunction orchestration",
  "public_functions": [
    "load_binary", "slice_at_va", "disassemble_function_x86",
    "decompile_function_from_binary", "decompile_function_in_load",
    "detect_functions_in_load", "standard_pipeline_arc",
    "lift_mnemonic", "lift_mnemonic_stream", "lift_instructions",
    "detect (callconv)", "arch_from_str", "detect_with_label",
    "label_from_pattern", "parse_mem_operands", "standard_pass_specs",
    "is_c_keyword", "detect_calling_convention", "analyze_stack_frame",
    "recover_signature", "recover_signature_auto",
    "recover_signature_with_noreturn", "render_c_signature",
    "construct_ssa", "detect_struct_candidates", "mask_prologue",
    "mask_epilogue", "build_report", "sequence_block", "sequence_blocks",
    "recover_types", "detect_heap_bases", "recover_vars",
    "register_width_bytes", "register_canonical", "width_hint_from_instr",
    "infer_register_sign_hints"
  ],
  "existing_mcp_tools": [
    "decompiler_core_batch_decompile",
    "decompiler_recover_structs",
    "decompiler_stack_frame_report",
    "decompile_function_path"
  ],
  "testable_functions": [
    "register_width_bytes", "register_canonical", "width_hint_from_instr",
    "is_c_keyword", "parse_mem_operands", "arch_from_str",
    "disassemble_function_x86", "load_binary", "slice_at_va",
    "detect_functions_in_load", "analyze_stack_frame",
    "detect_heap_bases", "render_c_signature",
    "decompile_function_from_binary"
  ],
  "validator_strategy": "Two-tier pytest: (A) pure functions vs Intel-SDM/C-spec dictionaries; (B) cargo-zyphora.exe baseline vs pefile+capstone+IDA ground truth."
}
