# rustre-deobf-vm

## Purpose
VM-based obfuscation analysis library: detection of virtualization (VMProtect, Themida, Enigma),
identification of VM dispatchers and handlers, extraction of VM bytecode, lifting of bytecode to
semantic operations, recovery of virtual ISAs, handler clustering, p-code abstraction, concolic
execution, virtual CFG reconstruction, and deobfuscated IL output.

## Cargo.toml
- name: `rustre-deobf-vm` v0.1.0, edition 2024
- deps: `rustre-deobf`, `rustre-core`, `anyhow`, `thiserror`, `serde`, `serde_json`, `petgraph`

## Module map (src/)
- `lib.rs` — core types: `VirtualMachineState`, `VmDispatcher`/`VmDispatcherDetector`,
  `VmHandler`/`HandlerKind`, `VmDetector`/`VmDetectionResult`/`VmConfidence`, `VmBytecode`,
  `VmSemanticOp`, `VmLifter`/`VmLifterConfig`, `HandlerCluster`/`HandlerClusterer`, `VmArch`,
  `PcodeInsn`/`PcodeOp`/`PcodeVarnode`. Re-exports submodules.
- `concolic_lifter` — concolic execution for handler semantic recovery.
- `deobfuscated_output` — LLIL-equivalent deobfuscated IL output.
- `dispatcher_detection` — full CFG-based dispatcher detection with confidence scoring.
- `isa_reconstruction` — `VirtualInstruction`, `VirtualIsa`, reconstructs virtual ISAs.
- `pattern_db` — 50+ VM handler pattern database with fuzzy matching.
- `themida_handler` — Themida-specific handler patterns.
- `vm_bytecode_recovery` — extraction of VM bytecode buffers.
- `vm_cfg` — virtual control-flow graph reconstruction.
- `vm_emulator` — configurable interpreter (`VmEmulator`, `VmIsaConfig`, `EmulationTrace`).
- `vm_handler_analysis` — handler pattern analysis for major protectors.
- `vm_state_tracker` — VM state tracking across execution steps.
- `vmprotect_handler` — VMProtect-specific handler patterns.

## Key public API (signatures, behavior only)

### Primitive helpers (lib.rs)
- `read_u64_le(&[u8]) -> u64`, `read_u32_le(&[u8]) -> u32`, `read_u16_le(&[u8]) -> u16` —
  safe LE reads, return 0 if slice too short.

### VirtualMachineState
Guest CPU state: 8x u32 regs, u64 pc, Vec<u32> stack, u32 flags, HashMap<u64,u8> memory.
- `new()`, `default()`, `reset(&mut)`, `push(v)`, `pop() -> Option<u32>`,
  `mem_read_byte/u32(addr)`, `mem_write_byte/u32(addr, v)`, flag accessors
  `zero_flag()`/`carry_flag()`/`set_zero_flag(result)`.

### VmDispatcherDetector
Byte-level fast scanner. `new()`, `detect_dispatcher(&[Vec<u8>]) -> Option<VmDispatcher>`,
`detect(blocks) -> Option<VmDispatcher>`. Matches two signatures
(`31 C0 FF 24`, `48 81 C3 FF`), parses entry/handler-table/handler-count as little-endian u64.
Handler count capped at 65536.

### VmHandler / HandlerKind
- `HandlerKind`: Arithmetic, Logic, Load, Store, ControlFlow, StackOp, Compare, Unknown.
- `VmHandler::new(index, address, prologue, kind, description, stack_inputs, stack_outputs)`.
- `is_arithmetic()`, `is_control_flow()`, `prologue_entropy() -> f64` (Shannon).

### VmDetector
High-level facade. `new()`, `detect(&[u8]) -> VmDetectionResult` with fields
`confidence` (None/Low/Medium/High/Definitive), `dispatcher_count`, `handler_count`,
`arch_hints` (VMProtect/Themida/Enigma/CPUID/RDTSC markers), `dispatcher_offset`.
Heuristics scan for indirect-jump dispatcher (`FF 24/E0/E1/E2/E3/D0`) and PUSH-reg handler entries.

### VmBytecode
`new(bytes, start_address, opcode_width)` computes `distinct_opcodes` + Shannon `entropy`.
`looks_encrypted()` true if entropy > 7.0. `len()`, `is_empty()`, `is_non_empty()`.

### VmSemanticOp
Enum of lifted ops: PushImm/PushReg/PopReg, Add/Sub/Mul/And/Or/Xor/Not/Neg/Shl/Shr,
Load32/Store32, Jmp/Jz/Call/Ret, Nop/Halt, Unknown(u8).
- `is_control_flow()`, `is_alu()`, `stack_delta() -> i32`.

### VmLifter / VmLifterConfig
Static decoder for an abstract fixed-opcode-table ISA. Config: `opcode_width`,
`little_endian`, `max_instructions` (default 65536).
- `new()`, `with_opcode_map(HashMap<u8,u8>)`, `remap(opcode)`.
- `lift(&[u8]) -> Result<Vec<VmSemanticOp>>` — opcode table: 0x00=Nop, 0x01=PushImm(i32 LE),
  0x02=PushReg, 0x03=PopReg, 0x10-0x19=ALU, 0x20=Load32, 0x21=Store32,
  0x30=Jmp, 0x31=Jz, 0x32=Call, 0x33=Ret, 0xFF=Halt. Errors on truncated operands.
- `simulate(&[VmSemanticOp], VirtualMachineState) -> Result<VirtualMachineState>` —
  single-pass interpreter, errors on stack underflow; breaks on Jmp/Ret/Halt/Unknown.

### HandlerCluster / HandlerClusterer
Group handlers by HandlerKind. `cluster(&[VmHandler]) -> Vec<HandlerCluster>` sorted by label,
computes per-cluster avg prologue entropy.

### VmArch
Recovered virtual arch summary. Constructors `stack_machine(opcode_count)`,
`register_machine(register_count, opcode_count)` (complexity_score derived). `summary() -> String`.

### Pcode (PcodeVarnode, PcodeOp, PcodeInsn)
Ghidra-style p-code IR. Varnodes: Unique/Register/Const/Ram, each with byte size.
Ops cover Copy/Load/Store/branches/Int*/Float*/PhiNode. `PcodeInsn::new(op, output, inputs, seq)`,
`is_branch()`.

## Pub fn counts per file
- lib.rs: 71, vm_state_tracker: 54, dispatcher_detection: 67, vm_bytecode_recovery: 58,
  vm_handler_analysis: 24, isa_reconstruction: 39, concolic_lifter: 38, vm_cfg: 36,
  deobfuscated_output: 33, pattern_db: 30, vm_emulator: 20, vmprotect_handler: 18,
  themida_handler: 18.
- Total `pub fn` (incl. const/async): ~506 across 13 source files.

## Tests
`tests/blitz.rs`, `tests/blitz2.rs` present — crate is testable end-to-end.

## Expected behavior summary
Given raw program bytes or pre-split basic blocks, the crate offers two layered pipelines:
1. **Fast byte-level**: `VmDispatcherDetector` + `VmDetector` give a quick confidence verdict
   on whether a binary is VM-obfuscated and where the dispatcher likely sits.
2. **Full analysis**: `dispatcher_detection`, `vm_handler_analysis`, `vm_bytecode_recovery`,
   `isa_reconstruction`, `vm_cfg`, `concolic_lifter`, `vm_emulator`, `vm_state_tracker`,
   `pattern_db` work together to identify handlers, lift bytecode to `VmSemanticOp` / p-code,
   reconstruct the virtual ISA, and emit a deobfuscated IL representation via
   `deobfuscated_output`. Protector-specific modules (`vmprotect_handler`, `themida_handler`)
   provide tailored signature matching.

All public types implement Debug/Clone, most also Serialize/Deserialize for JSON pipelines.
