# Analysis: rustre-deobf-string, rustre-deobf-smc, rustre-deobf-vm, rustre-deobf-vmlift

> Generated 2026-07-02 — covers `src/lib.rs` plus all submodule files.

---

## 1. Crate Overview

| Crate | Lines (lib.rs) | Total source lines | Role in pipeline |
|---|---|---|---|
| `rustre-deobf-string` | 2 811 | ~9 000 | String decryption / recovery |
| `rustre-deobf-smc` | 3 795 | ~15 000 | Self-modifying code unpacking |
| `rustre-deobf-vm` | 3 025 | ~16 000 | VM detection + handler analysis |
| `rustre-deobf-vmlift` | 1 628 | ~12 000 | VM bytecode → IR lifting |

All four implement (or are consumed by) the `DeobfPass` trait from `rustre-deobf`.  
The dependency chain is:

```
rustre-deobf (trait + pipeline)
  ├── rustre-deobf-string   (deps: rustre-il-llil)
  ├── rustre-deobf-smc      (deps: rustre-deobf only)
  ├── rustre-deobf-vm       (deps: rustre-core, petgraph)
  └── rustre-deobf-vmlift   (deps: rustre-core, rustre-deobf-vm, petgraph)
```

`rustre-deobf::backends::all()` (feature `subcrates`) instantiates all four and
returns them as a `Vec<Box<dyn DeobfPass>>`.

---

## 2. `rustre-deobf-string`

### 2.1 Purpose

Detects and decrypts obfuscated strings in compiled binaries.  Covers the full
spectrum from trivial XOR to stream ciphers (RC4, ChaCha20), stack-string
reconstruction from LLIL, and AI-assisted recovery.

### 2.2 Submodules

| Module | Purpose |
|---|---|
| `xor_decryptor` / `xor_string_decoder` / `xor_string_decryptor` | XOR constant, cyclic, rolling |
| `stack_string_recovery` / `stack_string_decoder` / `stack_string_reconstructor` / `stack_string_asm_detector` | Stack string reconstruction from LLIL |
| `crypto_string_decrypt` | RC4 and block cipher string decryption |
| `chacha20` | ChaCha20 stream cipher |
| `deobf_pipeline` | Batch deobfuscation pass orchestration |
| `pattern_matcher` | Regex / byte-pattern scanner for known decryptors |
| `string_annotation` | Knowledge-graph annotation output |
| `string_classifier` | Classify `StringAlgorithm` from entropy / structure |
| `encoding_detector` / `custom_encoding_detector` | Base64 variant and custom-alphabet detection |
| `unicode_deobf` / `unicode_obfuscation_detector` | Unicode homoglyph / confusable stripping |
| `string_encryption_bruteforcer` | Systematic brute-force over key space |
| `ai_string_recovery` | LLM-assisted recovery for unknown encodings |

### 2.3 Core Types

```rust
pub enum StringAlgorithm {
    XorConstant, XorCyclic, XorRolling,
    Rc4, ChaCha20, RotN, Base64, HexEncoded,
    StackString, SplitString,
    AddConstant, SubConstant, RolConstant, RorConstant,
    Unknown,
}

pub struct DecodedString {
    pub addr: u64,
    pub original_bytes: Vec<u8>,
    pub decoded_value: String,
    pub algorithm: StringAlgorithm,
    pub confidence: u8,       // 0–100
}

pub struct StringDeobfuscator {
    pub min_printable_ratio: f64,
    pub min_length: usize,
    pub max_brute_key_len: usize,
    pub try_rc4: bool,
    pub try_xor: bool,
}
```

### 2.4 Public API

| Symbol | Signature | Notes |
|---|---|---|
| `xor_brute_force_top3` | `(data: &[u8]) -> Vec<XorBruteforceCandidate>` | All 256 1-byte keys, ranked |
| `recover_multibyte_xor` | `(data: &[u8], max_key_len: usize) -> Vec<MultiByteXorResult>` | IC-based key-length detection |
| `detect_rc4_ksa_in_mlil` | `(instructions: &[LlilInstruction]) -> Vec<Rc4KsaPattern>` | Structural RC4 KSA detection |
| `rc4_inverse_ksa` | `(s_final: &[u8; 256]) -> Vec<Vec<u8>>` | **Returns empty** — known limitation (see §2.6) |
| `detect_base64_variant` | `(data: &[u8]) -> Option<Base64Variant>` | Std / URL-safe / Custom |
| `decode_base64_custom` | `(input, alphabet) -> Result<Vec<u8>>` | Custom 64-char alphabet |
| `caesar_brute_force` | `(input: &str) -> Vec<CaesarBruteforceResult>` | All 25 rotations + English score |
| `detect_arith_obf_in_mlil` | `(instructions, ciphertext) -> Vec<ArithDeobfResult>` | ADD/SUB/ROL/ROR from LLIL |
| `detect_mlil_stack_strings` | `(instructions: &[LlilInstruction]) -> Vec<MlilStackString>` | Consecutive byte-store grouping |
| `detect_string_decoder_helpers` | `(func_addr, instructions) -> Vec<StringDecoderSignature>` | Heuristic: XOR count + loop size |
| `batch_decrypt_string_table` | `(entries, data_provider, algorithm)` | Batch over XOR/RC4 |
| `compute_confidence` | `(decrypted: &[u8]) -> u8` | Printability + URL/null-term bonuses |
| `detect_stack_strings` (re-export) | `(instrs) -> Vec<StackStringHit>` | From `stack_string_asm_detector` |
| `StringDeobfuscator::run` | `(&self, data: &[u8]) -> Vec<StringResult>` | Combined XOR + RC4 brute force |
| `Rc4::ksa` / `Rc4::prga` / `Rc4::decrypt` | complete RC4 impl | Full KSA + PRGA |
| `Rc4::brute_force_1byte` / `brute_force_2byte` | brute force | Printability scoring |
| `XorDecryptor::decrypt_constant/cyclic/rolling` | direct decryption | — |
| `XorDecryptor::recover_key` / `recover_key_2byte` | key recovery | Brute force |

### 2.5 Architecture

Detection → Algorithm classification → Key recovery → Decryption → Confidence scoring → Annotation

The LLIL integration (`rustre-il-llil`) is the distinguishing feature: the crate
decodes `LlilInstruction` / `LlilExpr` AST nodes to find:
- Stack offsets relative to `rsp`/`rbp` for stack-string reconstruction.
- RC4 KSA structural patterns (add-and-swap counts).
- ADD/SUB/ROL/ROR constants extracted from instruction operands.

### 2.6 Completeness

**Rating: PARTIAL → COMPLETE** (core algorithms complete; AI / ChaCha20 thin)

| Feature | Status |
|---|---|
| XOR brute force (1-byte, 2-byte, multi-byte IC) | Complete |
| RC4 KSA/PRGA | Complete |
| RC4 key recovery from S-box only | Intentionally empty (`rc4_inverse_ksa` returns `[]`) |
| ADD/SUB/ROL/ROR arith deobf | Complete |
| Caesar / ROT-N | Complete |
| Base64 std / URL-safe / custom | Complete |
| Stack-string LLIL reconstruction | Complete |
| ChaCha20 module | Present (thin wrapper, needs verification) |
| AI-assisted recovery | Module exists; depth unknown without submodule read |
| `DeobfPass` impl (`XorDecryptor::run`) | Complete — registered in `backends::all()` |

No `todo!()` or `unimplemented!()` macros found across the entire crate.

### 2.7 Gaps

- `rc4_inverse_ksa` is a documented stub; callers wanting to recover RC4 keys
  without a known plaintext must use `Rc4::brute_force_1byte/2byte` instead.
- Multi-byte RC4 key brute-force not present; maximum tested key length is 2.
- The `ai_string_recovery` module is not read in detail but likely requires
  external LLM calls and may not be functional in offline mode.

---

## 3. `rustre-deobf-smc`

### 3.1 Purpose

Detects, decrypts, and patches self-modifying code (SMC) regions.  Handles
single-byte and rolling ciphers applied to code sections, multi-layer packers,
and PE-specific unpacking.

### 3.2 Submodules

| Module | Purpose |
|---|---|
| `smc_detector` | Pattern-based SMC region discovery |
| `smc_decryptor_extractor` | Isolates the decryptor code responsible for a region |
| `smc_emulator` | Lightweight emulator for decryptor stubs |
| `smc_monitor` / `smc_write_tracker` / `smc_region_tracker` | Track write-then-execute events |
| `smc_reconstructor` / `smc_patched_code_reconstructor` | Output patched binary |
| `smc_payload_extractor` | Extract payload after decryption |
| `decryption_loop_analyzer` | Identify decryption loops via heuristics |
| `key_recovery` | Recover key material from decryptor stub |
| `layer_extractor` | Multi-layer SMC iteration |
| `pe_unpacker` | PE-specific unpacking support |
| `unpacker_engine` | High-level unpacking orchestration |
| `emulation_harness` | Bridge to emulation backend |
| `deobf_pass_smc` | `DeobfPass` wrapper for pipeline integration |
| `write_monitor` | Monitor write instructions during emulation |

### 3.3 Core Types

```rust
pub enum SmcKey {
    Constant(u64),
    Derived,
    FromMemory(u64),
    FromRegister(String),
}

pub enum SmcAlgorithm {
    Xor, Add, Sub, Rol, Ror,
    XorRolling,   // byte ^= key; key = byte
    AddRolling,   // byte += key; key = byte
    Custom(Vec<u8>),  // micro-VM: [op, arg] pairs
}

pub struct SmcRegion {
    pub start: u64, pub end: u64,
    pub decryptor_addr: u64,
    pub key: SmcKey,
    pub algorithm: SmcAlgorithm,
}
```

### 3.4 Public API

| Symbol | Notes |
|---|---|
| `SmcDetector::detect(data)` | Scans raw bytes for 4 patterns: XOR loop, ADD loop, rolling XOR, PUSHAD/POPAD frame |
| `SmcDecryptor::decrypt(data, region)` | Applies `SmcAlgorithm` to bytes; Custom uses a 3-op micro-VM |
| `SmcPatcher::build_patches(data, region, file_offset)` | Returns `Vec<Patch>` for the decrypted region |
| `LayeredSmc::decrypt_all(data)` | Iterates up to `max_layers` (default 8) until no more regions found |
| `SmcPass` (impl `DeobfPass`) | Pipeline entry point; registered in `backends::all()` |

### 3.5 Detection Patterns

```
Pattern A (XOR loop):   B9 ?? ?? ?? ??  +  80 34 0F ??
Pattern B (ADD loop):   80 0x?? imm8  (ADD byte ptr [reg])
Pattern C (Rolling XOR): 8A 06  32 C3  88 07  (MOV AL,[ESI]; XOR AL,BL; MOV [EDI],AL)
Pattern D (PUSH/POP):   0x60 ... 0x61  (PUSHAD...POPAD frame)
```

Key extraction: all patterns scan ahead for `MOV reg, imm32` (B8–BF) to
recover the destination address.

### 3.6 Completeness

**Rating: PARTIAL → COMPLETE** (patterns cover common cases; emulation depth thin)

| Feature | Status |
|---|---|
| Static byte-pattern SMC detection | Complete (4 patterns) |
| Single-byte XOR/ADD/SUB/ROL/ROR decryption | Complete |
| Rolling XOR / rolling ADD | Complete |
| Custom micro-VM (3-op) | Complete |
| Multi-layer iteration | Complete |
| PE unpacking | Module exists; depth requires submodule read |
| Dynamic emulation harness | Module exists; likely calls `rustre-emu` |
| Key recovery for `Derived` / `FromRegister` | Returns zero-key (limitation) |
| `DeobfPass::run` | Complete |

No `todo!()` or `unimplemented!()` found.

### 3.7 Gaps

- `SmcKey::Derived` and `SmcKey::FromRegister` both decrypt with key byte `0x00`,
  silently producing wrong output.  Caller must resolve these before decryption.
- Pattern detection operates on raw bytes, not disassembly; multi-byte opcode
  sequences straddling instruction boundaries may be missed.
- The `emulation_harness` and `pe_unpacker` modules are not inspected in detail;
  their completeness depends on `rustre-emu` integration readiness.

---

## 4. `rustre-deobf-vm`

### 4.1 Purpose

Virtual machine obfuscation analysis: detects VM-protected binaries
(VMProtect, Themida, Enigma), identifies dispatcher loops, classifies handlers,
extracts VM bytecode, and lifts it to `VmSemanticOp` sequences.

### 4.2 Submodules

| Module | Size (lines) | Purpose |
|---|---|---|
| `dispatcher_detection` | 1 422 | CFG-based dispatcher analysis with confidence scoring |
| `vm_handler_analysis` | 1 475 | Handler clustering for VMProtect / Themida / Enigma / Code Virtualizer / Obsidium |
| `vm_bytecode_recovery` | 1 412 | Extract VM bytecode from handler traces |
| `isa_reconstruction` | 1 371 | Reconstruct virtual ISA from handler semantics |
| `concolic_lifter` | 1 317 | Concolic execution for handler semantic recovery |
| `vm_cfg` | 1 056 | Virtual control-flow graph reconstruction |
| `vmprotect_handler` | 1 143 | VMProtect-specific handler analysis |
| `themida_handler` | ~700 | Themida/WinLicense-specific analysis |
| `vm_state_tracker` | 1 116 | State tracking across emulation steps |
| `vm_emulator` | ~800 | Configurable interpreter with trace recording |
| `pattern_db` | ~800 | 50+ handler pattern database with fuzzy matching |
| `deobfuscated_output` | ~500 | LLIL-equivalent deobfuscated output |

### 4.3 Core Types

```rust
pub struct VirtualMachineState {
    pub regs: [GuestReg; 8],   // 8×u32 general-purpose
    pub pc: u64,
    pub stack: Vec<GuestReg>,
    pub flags: u32,            // ZF=bit0, CF=bit1, SF=bit2, OF=bit3
    pub memory: HashMap<u64, u8>,
}

pub struct VmHandler {
    pub index: u32,
    pub address: Address,
    pub prologue: Vec<u8>,
    pub kind: HandlerKind,     // Arithmetic|Logic|Load|Store|ControlFlow|StackOp|Compare|Unknown
    pub stack_inputs: u8,
    pub stack_outputs: u8,
}

pub struct VmDispatcher {
    pub entry: Address,
    pub handler_table_base: Address,
    pub handler_count: usize,
}

pub enum VmConfidence { None, Low, Medium, High, Definitive }

pub enum VmSemanticOp {
    PushImm(i64), PushReg(u8), PopReg(u8),
    Add, Sub, Mul, And, Or, Xor, Not, Neg, Shl, Shr,
    Load32, Store32, Jmp, Jz, Call, Ret, Nop, Halt,
    Unknown(u8),
}

pub struct VmLifterConfig {
    pub opcode_width: u8,       // default 1
    pub little_endian: bool,    // default true
    pub max_instructions: usize, // default 65536
}
```

### 4.4 Public API (key symbols)

| Symbol | Notes |
|---|---|
| `VmDetector::detect(data)` | Byte-level scan: dispatcher pattern, handler regions, arch hints (VMProtect/Themida string search, CPUID/RDTSC opcodes). Returns `VmDetectionResult` with `VmConfidence` |
| `VmDispatcherDetector::detect(blocks)` | Pre-scanner operating on `&[Vec<u8>]` basic blocks; matches two binary signatures |
| `VmHandler::prologue_entropy()` | Shannon entropy of handler prologue for quality scoring |
| `VmBytecode::new(bytes, start, opcode_width)` | Computes `distinct_opcodes` and `entropy` |
| `VmBytecode::looks_encrypted()` | Returns `true` if entropy > 7.0 |
| `VmLifter::lift(bytecode)` | Decodes opcode table (0x00–0xFF) → `Vec<VmSemanticOp>` with opcode remapping |
| `VmLifter::simulate(ops, state)` | Single-pass simulation on `VirtualMachineState` |
| `HandlerClusterer::cluster(handlers)` | Groups handlers by `HandlerKind` |
| `VmProtectorDetector::detect(data)` | Returns `VmDetection` with protector name + confidence |
| `VmDeobfPipeline::run(ctx)` | Full pipeline: detect → extract → lift → cluster |
| `VmDetector` (impl `DeobfPass`) | Pipeline entry; registered in `backends::all()` |

### 4.5 Dual-Layer Dispatcher Design

The crate intentionally provides two complementary detectors:

- `VmDispatcherDetector` (lib.rs): byte-level, operates on raw `&[Vec<u8>]` blocks,
  matches two hardcoded signatures (`31 C0 FF 24` and `48 81 C3 FF`).
  Fast first-pass filter.

- `dispatcher_detection::DispatcherDetector`: full CFG-based analysis with
  confidence scoring, VPC detection, signature database, and protector
  classification.  Production-quality analysis.

### 4.6 Completeness

**Rating: PARTIAL → COMPLETE** (detection and model complete; concolic depth uncertain)

| Feature | Status |
|---|---|
| VM presence detection (byte-level + CFG) | Complete |
| Handler classification (8 kinds) | Complete |
| VMProtect / Themida-specific analysis | Modules present and substantial |
| VM ISA reconstruction | Module `isa_reconstruction` present (1 371 lines) |
| Concolic execution for handler semantics | Module present (1 317 lines); relies on external emulator |
| Virtual CFG reconstruction | Complete (`vm_cfg`, 1 056 lines) |
| Opcode remapping (custom opcode tables) | Complete via `VmLifter::opcode_map` |
| `VmSemanticOp` stack-delta tracking | Complete |
| `DeobfPass::run` | Complete |

No `todo!()` or `unimplemented!()` found.

### 4.7 Gaps

- `VmDetector::find_handler_regions` is extremely coarse (any `PUSH reg` byte
  at offset `n` where `data[n+1] != 0x50`); high false-positive rate without
  CFG context.
- `VmDispatcherDetector::detect` matches exactly two hardcoded binary signatures;
  other protector patterns are only covered by the submodule detector.
- The `concolic_lifter` calls out to an external emulator (integration via
  `rustre-emu`); if that crate is not functional the concolic path silently
  degrades.

---

## 5. `rustre-deobf-vmlift`

### 5.1 Purpose

Lifts VM bytecode (as extracted by `rustre-deobf-vm`) to a host IR suitable for
static analysis, ultimately targeting `rustre-il-llil`.  Also identifies specific
protectors (VMProtect, Tigress, custom VMs) and synthesizes a virtual ISA.

### 5.2 Submodules

| Module | Size (lines) | Purpose |
|---|---|---|
| `handler_semantic_db` | 2 070 | Semantic database for 50+ VM handler patterns |
| `virtualized_function` | 1 315 | Virtualized function representation + CFG |
| `protector_patterns` | 1 109 | Per-protector byte/structural patterns (VMP, Tigress, Obsidium, etc.) |
| `vm_isa_complete` | 1 106 | Complete virtual ISA description |
| `vm_handler_analyzer` | ~900 | Handler analysis pipeline |
| `vm_bytecode_lifter` | ~800 | Bytecode → IR lifting |
| `lifter_to_llil` | ~700 | IR → `rustre-il-llil` translation |
| `vm_dispatcher_finder` | ~600 | Dispatcher discovery (extends `rustre-deobf-vm`) |
| `vm_isa_recovery` | ~600 | ISA synthesis from handler traces |
| `isa_synthesizer` | ~500 | Infer virtual ISA from dispatcher + handler graph |
| `lifted_ir_optimizer` | ~500 | Peephole optimizer over lifted IR |
| `tigress_lifter` | ~400 | Tigress-specific lifting |
| `dispatcher_detector` | ~300 | Dispatcher detection (reuses `rustre-deobf-vm`) |
| `handler_inferrer` | ~200 | Infer handler semantics from byte patterns |
| `bytecode_finder` | ~200 | Locate bytecode in binary |
| `custom_vm_identifier` | ~200 | Identify custom (non-standard) VMs |
| `vm_protection_analysis` | ~100 | High-level protection analysis report |

### 5.3 Core Types (lib.rs)

```rust
pub enum GuestOpcode { Add, Sub, Push, Pop, Load, Store, Halt }

pub struct GuestInstruction {
    pub opcode: GuestOpcode,
    pub reg_dst: Option<usize>,
    pub reg_src: Option<usize>,
    pub imm: Option<u32>,
}

// Bytecode encoding (VmLifter::lift_to_instructions):
//   0x01 = Add    reg_dst u8, reg_src u8
//   0x02 = Sub    reg_dst u8, reg_src u8
//   0x03 = Push   reg_src u8
//   0x04 = Pop    reg_dst u8
//   0x05 = Load   reg_dst u8, reg_src u8, imm u32 (LE)
//   0x06 = Store  reg_dst u8, reg_src u8, imm u32 (LE)
//   0x07 = Halt
//   0x08 = LoadImm reg_dst u8, imm u32 (LE)
//   0x09 = PushImm imm u32 (LE)
```

`VmLifter::lift_to_instructions` is a decoder for this concrete bytecode format.
This is distinct from (and more concrete than) the abstract `VmSemanticOp` lifter
in `rustre-deobf-vm`.

`VmDispatcherDetector` (lib.rs) adds three patterns on top of the `rustre-deobf-vm`
base:

| Pattern | Bytes | Description |
|---|---|---|
| `IndirectIndexedJmp` | `FF 24 CD xx xx xx xx` | `jmp [reg*8 + disp32]` |
| `ComputedJmp` | `FF E0` / `FF E1` | `jmp rax` / `jmp rcx` |
| `CallPopAddChain` | `call $+5; pop reg; add reg, imm` | VM IP-fixup stub |

Jump-table entries are extracted from the binary when the displacement maps into
the buffer.  Capped at 4096 dispatcher sites per pattern to prevent memory
exhaustion.

### 5.4 Public API

| Symbol | Notes |
|---|---|
| `VmLifter::lift_to_instructions(bytecode)` | Concrete 9-opcode bytecode decoder |
| `VmLifter::to_pseudo_il(instrs)` | Returns `Vec<String>` pseudo-IL lines |
| `VmDispatcherDetector::detect_in_bytes(code, base)` | Byte-level, returns `Vec<VmDispatcher>` |
| `VmLifter::new()` (impl `DeobfPass`) | Registered in `backends::all()` |
| Submodule APIs | `isa_synthesizer`, `lifter_to_llil`, etc. require submodule read |

### 5.5 Relationship to `rustre-deobf-vm`

`rustre-deobf-vmlift` depends on `rustre-deobf-vm` (Cargo.toml) and re-uses:
- `dispatcher_detector::VmDispatcher` (imported directly in lib.rs)
- `dispatcher_detector::DispatcherKind`, `RegisterRole`, `DispatcherFlags`,
  `VmRegister` (used in `VmDispatcherDetector::detect_in_bytes`)

The separation is:
- `rustre-deobf-vm`: detection, handler analysis, model types, abstract lifting
- `rustre-deobf-vmlift`: concrete bytecode decoding, ISA synthesis, LLIL emission

### 5.6 Completeness

**Rating: PARTIAL** (concrete lifter complete; ISA synthesis and LLIL output depth uncertain)

| Feature | Status |
|---|---|
| Concrete 9-opcode bytecode decoder | Complete |
| Dispatcher pattern detection (3 patterns) | Complete |
| Jump-table extraction | Complete |
| Handler semantic DB | Large (2 070 lines); likely substantial |
| Tigress-specific lifting | Module present |
| ISA synthesis | Module present; detail unknown |
| `lifter_to_llil` (LLIL emission) | Module present; integration with `rustre-il-llil` unknown |
| `lifted_ir_optimizer` | Module present |
| `DeobfPass::run` | `VmLifter::new()` registered; runtime depth unclear |

No `todo!()` or `unimplemented!()` found.

### 5.7 Gaps

- `GuestOpcode` and `GuestInstruction` define only 7 ops (Add/Sub/Push/Pop/Load/Store/Halt);
  no MUL/DIV/AND/OR/XOR/NOT/shift/compare/branch instructions.  These must
  appear in the submodule ISA types.
- The concrete bytecode format (opcodes 0x01–0x09) is a synthetic encoding
  internal to RustRE, not tied to any real-world protector's bytecode.  Actual
  VM bytecode requires the per-protector handlers in `vm_handler_analyzer` to
  map real opcodes.
- `lifter_to_llil`: the connection point to the IL layer is present as a module
  but its public surface and completeness could not be fully read.

---

## 6. Deobfuscation Pipeline Integration

```
Binary bytes
    │
    ▼
rustre-deobf::DeobfPipeline::run_all()
    │
    ├─ SmcPass (rustre-deobf-smc)
    │     detect SMC → decrypt → patch binary → continue
    │
    ├─ XorDecryptor (rustre-deobf-string)
    │     scan for encrypted strings → recover → annotate
    │
    ├─ VmDetector (rustre-deobf-vm)
    │     detect VM → extract handlers + bytecode → lift to VmSemanticOp
    │
    └─ VmLifter (rustre-deobf-vmlift)
          concrete bytecode decode → ISA synthesis → LLIL emission
```

`DeobfContext` carries `binary_data: Vec<u8>`, `patches: Vec<Patch>`, and
metadata.  Each pass reads context, appends patches and annotations, and
returns a `DeobfResult`.  `DeobfPipeline::apply_patches()` applies all patches
in offset order after all passes complete.

---

## 7. Cross-Crate Gaps and Priority Work

| Gap | Crate | Severity |
|---|---|---|
| `rc4_inverse_ksa` intentionally empty; multi-byte RC4 brute-force missing | string | Medium |
| `SmcKey::Derived/FromRegister` decrypt with key=0 silently | smc | High |
| SMC detector works on raw bytes; misses obfuscated decryptors that do not match 4 patterns | smc | Medium |
| `VmDetector::find_handler_regions` is coarse (PUSH byte heuristic) | vm | Medium |
| `VmDispatcherDetector` (lib.rs) only matches 2 hardcoded signatures | vm | Low |
| Concolic lifter depends on `rustre-emu` availability | vm | Medium |
| `GuestOpcode` covers only 7 ops in vmlift lib.rs; full ISA in submodules | vmlift | Low |
| `lifter_to_llil` integration completeness unverified | vmlift | Medium |

---

## 8. Completeness Summary

| Crate | Rating | Reasoning |
|---|---|---|
| `rustre-deobf-string` | **PARTIAL→COMPLETE** | All major algorithms implemented; RC4 inverse KSA stub; AI module thin |
| `rustre-deobf-smc` | **PARTIAL→COMPLETE** | Detection + decryption complete; emulation harness / PE unpacker depth uncertain |
| `rustre-deobf-vm` | **PARTIAL→COMPLETE** | Rich model types; concolic and handler-analysis modules substantial but emulator-dependent |
| `rustre-deobf-vmlift` | **PARTIAL** | Concrete bytecode lifter complete; ISA synthesis and LLIL emission require submodule verification |
