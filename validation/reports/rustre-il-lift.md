# rustre-il-lift

## Purpose
Multi-architecture instruction lifter: converts decoded machine instructions (from `rustre-core::arch::Instruction` and `iced_x86::Instruction`) into RustRE's intermediate language (IR effects / LLIL ops) defined in `rustre-il`. Provides per-architecture lifters (x86/x64, ARM32, AArch64, MIPS32/64, RISC-V, PPC, SPARC, M68k, AVR, Z80, BPF, WASM, CIL, DEX) plus registry, batching, caching, streaming, verification, and pipeline orchestration around them. Also exposes x86 IR utilities: optimizer, pattern matcher, type recovery, ABI/calling-convention recovery, pretty-printer, evaluator (concrete execution of IR), deobfuscator.

## Public functions (semantic, selected)

### Core lift orchestration
- `LifterRegistry::new` / `with_defaults` / `register` / `get(arch) -> Option<&dyn ArchLifter>` / `supports(arch) -> bool` / `arch_names() -> Vec<&str>` — registry of named arch lifters; `with_defaults` should register every architecture in this crate.
- `LifterRegistry::lift_instr(arch, &Instruction) -> Result<LiftedInstr>` — dispatch a single instruction to the right backend.
- `BatchLifter::lift_batch(&[Instruction]) -> Result<LiftResult>` — lift a sequence; aggregates stats and per-address errors.
- `BatchLifter::lift_single(&Instruction) -> Result<LiftedInstr>` — single-instruction wrapper.
- `LiftCoordinator::lift_block(&[Instruction]) -> Vec<LiftedInstr>` / `lift_block_all` / `lift_batch` — block-level lifting that filters or preserves errors.
- `register_all_lifters(&mut LifterRegistry)` — populate a registry with every backend in this crate.

### Cache
- `LiftCache::new(max_entries)` / `default_capacity` — bounded cache keyed by VA.
- `LiftCache::get(addr) -> Option<LiftedInstr>` / `insert(addr, instr)` / `clear` / `len` / `hits` / `misses` / `hit_rate` — read-through cache semantics; hit_rate = hits / (hits + misses).
- `LruLiftCache` mirror of above but LRU eviction.
- `X86LiftCache::lift_with_cache(&X86Lifter, addr, bytes) -> &[LlilOp]` — decode-and-lift with memoisation per VA.

### Results / inspection
- `LiftStats::success_rate -> f64` — successful / total.
- `LiftResult::success_rate` / `failed_addresses() -> Vec<u64>`.
- `LiftedInstr::is_terminator` / `has_side_effects` / `written_registers` / `read_registers` — IR introspection.
- `IrExpr::node_count` / `registers_used` — recursive sums on the IR tree.
- `Effect::written_registers` / `read_registers`.
- `LiftFilter::terminators` / `with_side_effects` / `writing_register` / `at_level` / `count_stubs` / `partition_by_effects` — pure filter helpers over slices of `LiftedInstr`.

### Address map / diff / verification
- `AddressMap::insert/get/contains/addresses/iter/instructions/from_lift_result/merge_from/range(start,end)` — sparse VA→LiftedInstr map.
- `diff_address_maps(left, right) -> LiftDiff` — set diff between two address maps (added/removed/changed addresses).
- `LiftVerifier::verify(&LiftedInstr, &LiftedInstr) -> VerificationResult` / `verify_batch` / `all_equivalent` — semantic equivalence check between two lifts of the same instr.

### Streaming / pipeline / session
- `StreamingLifter::feed(&Instruction)` / `finish() -> PartialLiftResult` / `snapshot() -> LiftResult` — incremental lifting.
- `LiftPipeline::add_stage` / `stage_names` / `run(&[Instruction]) -> Result<LiftResult>` — multi-stage pipeline.
- `LiftSession::lift(...) -> ...` / `total_stats` / `reset` — stateful per-arch session.

### x86 LLIL backend (X86Lifter)
Each `lift_*` returns a `Vec<LlilOp>` modelling the side effects of one instruction:
- `lift_mov`, `lift_add`, `lift_sub`, `lift_and`, `lift_or`, `lift_xor` — dst = op(dst, src) with appropriate flag updates.
- `lift_push` — RSP -= width; mem[RSP] = src.
- `lift_pop` — dst = mem[RSP]; RSP += width.
- `lift_call` — push return address; jump to target.
- `lift_ret` — pop return address into PC.
- `lift_jmp` — unconditional branch to target.
- `lift_jcc` — conditional branch based on flag predicate.
- `lift_cmp` — flag-only subtract (no dst write).
- `lift_test` — flag-only AND.
- `lift_lea` — dst = effective-address(src) without memory access.
- `lift_syscall` — model syscall side effect.
- `X86Lifter::decode_and_lift(bytes, ip) -> Option<Vec<LlilOp>>` and `lift_instruction(bytes, ip) -> Result<Vec<LlilOp>>` — decode iced-x86 then lift.

### ARM64 backend (`Arm64Lifter` impl block, ops are textual)
- `lift_mov`/`lift_add`/`lift_sub`/`lift_and`/`lift_orr`/`lift_eor` — ALU ops on register operand strings.
- `lift_ldr`/`lift_str` — memory load/store.
- `lift_b` — unconditional branch.
- `lift_bcond(cond, ops)` — conditional branch.
- `lift_bl`/`lift_blr` — call (link).
- `lift_ret` — return.
- `lift_svc` — supervisor call.

### x86 IR utilities (re-exported)
- `optimise_effects` / `simplify_expr` / `simplify_effect` — constant folding & simplification on IR; `OptStats` reports reductions.
- `eval_expr` / `fold_expr` / `exec_effects` over `X86CpuState` / `EvalValue` — concrete IR interpreter.
- `lower_to_intrinsic` / `scan_for(kind)` / `scan_pseudos` — recognize idioms (`PseudoKind`) and replace with intrinsics.
- `x86_lift_instruction` (`x86_handlers::lift_instruction`) — handler dispatch.

## Existing MCP tools
None. `grep` over `crates/rustre-mcp-tools/src` finds zero references to `rustre_il_lift` / `il-lift` / `X86Lifter` / `LifterRegistry`. The crate is wired into other internal crates (`rustre-arch-x86`, `rustre-il-llil`, `rustre-il-mlil`, `rustre-symb-engine`, `rustre-script-rhai`) but has no direct MCP wire surface.

## Testable functions (external ground truth available)
1. `LiftCache::hit_rate` / `LruLiftCache::hit_rate` — pure arithmetic; ground truth = hits / (hits + misses).
2. `LiftStats::success_rate`, `LiftResult::success_rate` — successful / total.
3. `LiftCache::insert + get + len + hits + misses` — basic map invariants vs Python dict reference.
4. `AddressMap::insert/get/contains/addresses/range(start,end)` — sorted-map semantics, range yields entries with `start <= addr < end`.
5. `diff_address_maps(a, b)` — set arithmetic on VA keys: added = keys(b)\keys(a), removed = keys(a)\keys(b), changed = keys ∩ where instr differs. Verifiable by Python sets.
6. `LifterRegistry::with_defaults().arch_names()` — must contain the documented architectures (x86, x86_64, arm, aarch64, mips, mips64, riscv, ppc, sparc, m68k, avr, z80, bpf, wasm, cil, dex). Verifiable by enumeration.
7. `IrExpr::node_count` — recursive node count; can be cross-checked by reconstructing the expression tree and counting nodes.
8. `LiftFilter::terminators` — filter equals `instrs.iter().filter(|i| i.is_terminator())`.
9. `X86Lifter::lift_push` / `lift_pop` — must always emit an RSP adjust + a mem effect; verifiable by inspecting `LlilOp` sequence shape.
10. `X86Lifter::lift_ret` — must emit a branch effect to popped value; structural check.
11. `X86Lifter::lift_lea(reg, [base+disp])` — must NOT contain a memory-load effect (only address computation). Structural check.
12. `lift_xor reg, reg` after `simplify_effect` — should fold to `reg = 0`; verifiable by inspecting simplified IR.
13. `eval_expr` / `exec_effects` — given a known CPU state and IR sequence, the final register/memory state is deterministic; verifiable against a hand-computed reference (e.g. mov+add+sub).

## Validator strategy
Two-pronged:

A. Pure/structural (no binary needed) — Python harness using `pyo3` is overkill; instead build a Rust integration test binary that exposes each pure function via stdin JSON and compares to a Python reference script that computes the same arithmetic / set operations. Targets: hit_rate, success_rate, AddressMap range/diff, IrExpr::node_count, LifterRegistry::arch_names membership.

B. Semantic lift checks — feed a tiny corpus of x86 byte sequences (`90` nop, `48 31 C0` xor rax,rax, `48 89 D8` mov rax,rbx, `C3` ret, `55` push rbp, `5D` pop rbp, `E8 .. .. .. ..` call rel32, `8D 04 1A` lea eax,[rdx+rbx]) through `X86Lifter::lift_instruction`, then assert structural invariants on the returned `Vec<LlilOp>`:
- `nop` → empty or single no-effect op.
- `xor rax,rax` after `optimise_effects` → assignment of constant 0 to rax + flag updates.
- `ret` → control-flow terminator.
- `push` → stack-pointer decrement + memory store.
- `lea` → no memory-load op.
- `call rel32` → push of return address + branch.
Ground truth = handwritten reference table; the validator just shape-checks each lift and counts mismatches.

C. Semantic equivalence — for the same byte sequence, run `LiftVerifier::verify(a, b)` with `a == b` and assert `Equivalent`; flip a register name in `b` and assert non-equivalent. Validates the verifier itself.

No external library reference exists for the IR semantics (it's project-internal), so ground truth is a frozen golden table inside the validator. For arithmetic helpers (rates, sets) Python is the oracle.
