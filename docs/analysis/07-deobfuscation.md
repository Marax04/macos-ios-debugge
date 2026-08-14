# Deobfuscation Subsystem — Unified Analysis

> This document merges the three sub-analyses that cover the full deobfuscation
> subsystem of RustRE.  Read it as one coherent reference; the section numbering
> follows each source file.
>
> **Sub-files (kept for individual reference):**
> - `07a-deobf-core-cff-opaque.md` — core framework, CFF removal, opaque predicate elimination, anti-anti-analysis
> - `07b-deobf-mba-iadl-mhcde.md` — MBA simplification, iterative adversarial loop, mixed honig dead-code elimination
> - `07c-deobf-string-smc-vm.md` — string decryption, self-modifying code, VM detection and lifting

---

# Part A — Core Framework, CFF, Opaque Predicates, Anti-Anti-Analysis

# Deobfuscation Subsystem Analysis
## Crates: `rustre-deobf`, `rustre-deobf-cff`, `rustre-deobf-opaque`, `rustre-deobf-antianti`

**Date:** 2026-07-02  
**Analyzer:** Claude (automated)

---

## 1. Overview

The RustRE deobfuscation subsystem is a layered plugin architecture. One core crate
(`rustre-deobf`) defines the shared contract; every domain-specific technique lives in a
dedicated sibling crate that implements the `DeobfPass` trait and registers with the
pipeline.

```
rustre-deobf  (core: traits, context, pipeline, utility decryptors)
  └── rustre-deobf-cff       (control-flow flattening)
  └── rustre-deobf-opaque    (opaque predicate removal)
  └── rustre-deobf-antianti  (anti-debug / anti-VM / anti-sandbox)
  └── rustre-deobf-{mba,iadl,smc,string,vm,vmlift,mhcde}  (other passes)
```

When the workspace feature flag `subcrates` is enabled, `rustre-deobf::backends::all()`
instantiates one of each pass and returns them as `Vec<Box<dyn DeobfPass>>`.

---

## 2. `rustre-deobf` — Core Framework

### 2.1 Purpose

Defines every shared abstraction: the `DeobfPass` trait, `DeobfContext`, `Patch`,
`DeobfPipeline`, `PassRegistry`, and a large collection of utility decryptors that are
reused by sub-crates and by higher-level MCP tools.

### 2.2 Source Layout

| File | Responsibility |
|---|---|
| `lib.rs` | `DeobfPass` trait, `DeobfContext`, `Patch`, `DeobfPipeline`, `PassRegistry`, `XorDecryptor`, `RolRorDecryptor`, `SimpleSubstitution`, `Base64Decoder`, `StringDecryptor`, `Rc4Decryptor`, `ChaCha20Decryptor`, `Adler32`, `Crc32`, `PatternMatcher`, `DeobfReport`, `ObfuscationType` |
| `deobf_pipeline.rs` | Additional pipeline helpers |
| `deobf_pass_registry.rs` | Named pass registry variant |
| `deobf_registry.rs` | Global registry singleton utilities |
| `deobf_report.rs` | Structured reporting types |
| `deobf_report_extended.rs` | Extended report with per-technique fields |
| `cfg_normalizer.rs` | Generic CFG normalization helpers |
| `control_flow_normalization.rs` | Higher-level CFN pass |
| `dead_code_eliminator.rs` | Generic dead-code removal pass |
| `junk_code_remover.rs` | Junk instruction removal |
| `pass_manager.rs` | Ordered pass execution with dependency tracking |
| `pattern_recognition.rs` | Higher-level pattern matching helpers |
| `report.rs` | Report serialization |
| `constant_folding_pass.rs` | `BinaryConstantFoldPass` implementing `DeobfPass` |
| `opaque_predicate_resolver.rs` | Thin resolver adapter |
| `casts.rs` | Internal numeric cast helpers (pub(crate)) |

### 2.3 Public API — Key Types

```rust
// The central trait every pass must implement.
pub trait DeobfPass: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn run(&self, ctx: &mut DeobfContext) -> Result<DeobfResult, DeobfError>;
    fn is_applicable(&self, ctx: &DeobfContext) -> bool;
}

// Shared mutable state passed to every pass.
pub struct DeobfContext {
    pub binary: Vec<u8>,
    pub address_map: HashMap<u64, u64>,       // VA → file offset (legacy)
    pub segment_mappings: Vec<SegmentMapping>, // structured mappings
    pub patches: Vec<Patch>,
    pub metadata: HashMap<String, serde_json::Value>,
}

// A binary diff record produced by a pass.
pub struct Patch {
    pub offset: usize,
    pub original: Vec<u8>,
    pub patched: Vec<u8>,
    pub reason: String,
}

// Aggregate per-pass output.
pub struct DeobfResult {
    pub patches_applied: usize,
    pub transformations: Vec<String>,
    pub modified_bytes: usize,
    pub confidence: f32,
}
```

`DeobfContext::apply_patches()` materializes all accumulated `Patch` records onto a copy
of `binary` in order, relaxing the original-byte check to tolerate stacked passes.

`DeobfContext::va_to_file_offset()` first walks `segment_mappings` (structured), then
falls back to the legacy `address_map` flat lookup.

### 2.4 Utility Decryptors (all in `lib.rs`)

| Type | Algorithm | Notable method |
|---|---|---|
| `XorDecryptor` | XOR (constant / cyclic / rolling) | `recover_single_byte_key`, `decrypt_rolling` |
| `RolRorDecryptor` | Byte ROL/ROR | `recover_rotation` |
| `SimpleSubstitution` | Frequency analysis | `build_substitution_table` |
| `Base64Decoder` | RFC 4648 Base-64 | `find_all` (1 MiB cap, dos-guard) |
| `StringDecryptor` | XOR brute-force heuristic | `try_xor_constant`, `try_xor_rolling` |
| `Rc4Decryptor` | RC4 (KSA + PRGA) | `brute_force_short_key` (1- and 2-byte keys) |
| `ChaCha20Decryptor` | RFC 8439 ChaCha20 | `block`, `crypt` |
| `Adler32` | Adler-32 checksum | `checksum` |
| `Crc32` | CRC-32/IEEE | `checksum` |

### 2.5 Pipeline Execution

```
DeobfPipeline::run_all(ctx)
  for each pass:
    if pass.is_applicable(ctx):
      match pass.run(ctx):
        Ok(r)  → merge into total, record in pass_results
        Err(e) → log to stderr, push to error_messages (non-fatal)
  return PipelineResult { pass_results, total, error_messages }
```

`PassRegistry` supports named lookup and `run_selection(&[name], ctx)`.

### 2.6 Dependencies

```toml
rustre-core    # Address, SegmentMapping
anyhow
thiserror
serde, serde_json
```

### 2.7 Completeness: **COMPLETE**

- No `todo!` or `unimplemented!` macros found.
- Three internal `panic!` calls are in private helpers with documented preconditions.
- Extensive blitz tests cover all public types.

### 2.8 Gaps

- `DeobfPipeline::with_options` accepts `DeobfOptions` but ignores it (`_options`);
  parallel-pass execution is not implemented.
- `XorDecryptor::recover_single_byte_key` returns the key that maximizes printable-ASCII
  coverage over the entire buffer; per-segment detection is left to callers.
- `DeobfReport::add_obfuscation` encodes confidence as a formatted float in the
  `techniques_detected` string vec, making downstream parsing fragile.

---

## 3. `rustre-deobf-cff` — Control-Flow Flattening Removal

### 3.1 Purpose

Detects and reverses control-flow flattening (CFF) obfuscation as produced by OLLVM and
similar tools. The dispatcher-loop pattern (all basic blocks routed through a central
switch on a state variable) is identified, the original CFG edges are reconstructed, and
the dispatcher block is logically removed.

### 3.2 Source Layout

| File | Responsibility |
|---|---|
| `lib.rs` | `CffDetector`, `CffRecoverer`, `CffDeobfuscationPass`, `CffDeflattener`, `CffDispatcherDetector`; shared types: `StateVariable`, `CffPattern`, `CffCandidate`, `BlockMapping`, `RecoveredEdge`, `RecoveredCfg`, `SimpleCfg`, `SimpleBb` |
| `ollvm.rs` | OLLVM-specific: `OllvmDetector`, `OllvmDeobfuscationPass`, `StateVarTracker`, `patch_cff_function` |
| `flattening_detector.rs` | Secondary structural detector |
| `dispatcher_analysis.rs` | Dispatcher block analysis helpers |
| `dispatcher_rewriter.rs` | Byte-level patch generation for dispatcher removal |
| `cfg_reconstruction.rs` | Edge reconstruction from recovered state graphs |
| `state_variable_recovery.rs` | State variable tracking across blocks |
| `state_machine_extractor.rs` | State machine extraction |
| `state_machine_recovery.rs` | Recovery of original state machine semantics |
| `cff_decompiler.rs` | IR-level decompilation of CFF constructs |
| `cff_deobfuscator.rs` | High-level orchestrator |
| `cff_pattern_matcher.rs` | CFF-specific pattern matching |
| `cff_recovery.rs` | Recovery utilities and re-exports |
| `cff_state_machine.rs` | State machine data structures |
| `constant_propagator_cff.rs` | Constant propagation specialized for CFF |
| `vm_handler_analyzer.rs` | VM handler analysis for nested CFF/VM |

### 3.3 Detection Pipeline (`CffDetector`)

```
CffDetector::detect(cfg: &SimpleCfg, function_start) → Option<CffCandidate>
  1. Reject if cfg.blocks.len() < min_block_count (default 5)
  2. find_dispatcher(cfg) → (dispatcher_idx, prelim_confidence)
     heuristic: block with highest predecessor_count
  3. compute_confidence(cfg, dispatcher_idx) → weighted score
     weights: pred_ratio(0.35) + back_ratio(0.25) + succ≥2(0.20) 
              + avg_instr(0.10) + indirect_jump(0.10)
  4. Reject if score < min_confidence (default 0.6)
  5. identify_state_variable → StateVariable (most-written register)
  6. classify_pattern → CffPattern (Dispatcher/JumpTable/LinearSearch/NestedDispatch)
```

### 3.4 Recovery Pipeline (`CffRecoverer`)

```
CffRecoverer::recover(candidate, cfg) → RecoveredCfg
  build_block_mapping:
    for each predecessor of dispatcher:
      1. Use SimpleBb::state_const if populated (from LLIL or scan_block_state_const)
      2. Else: low-32 bits of block address (symbolic eval mode)
      3. Else: sequential seed
    propagate_states (symbolic eval) up to max_state_trace_depth (32)
  reconstruct_edges:
    for each non-dispatcher edge:
      if to == dispatcher: replace with block_for_state(state)
      else: keep as-is
  return RecoveredCfg { blocks (dispatcher excluded), edges, ... }
```

`CffRecoverer::scan_block_state_const(bytes)` decodes raw x86 bytes to find the last
`MOV reg, imm` before a jump — recognizes `B8+r imm32`, `REX.W B8+r imm64`, and
`C7 /0 imm32` encodings.

### 3.5 Raw-Byte Pass (`CffDispatcherDetector`)

For binaries without a disassembler, `CffDispatcherDetector::detect(code, base_va)`
scans for runs of `CMP [rip+disp32], imm` + short conditional branch pairs. Five or more
consecutive pairs classify as a dispatcher. `CffDeflattener::estimate_cff_confidence()`
combines dispatcher density (0.50), compare-branch pair density (0.30), and Shannon
entropy (0.20).

### 3.6 OLLVM Sub-module (`ollvm.rs`)

Exports `OllvmDetector`, `OllvmDeobfuscationPass`, `StateVarTracker`, `patch_cff_function`,
and `OllvmPatch`. Provides OLLVM-specific signature matching and patch generation.

### 3.7 Key Exported Types

| Type | Description |
|---|---|
| `CffDetector` | Configurable structural detector |
| `CffRecoverer` | CFG edge reconstructor |
| `CffDeobfuscationPass` | One-shot combined pass (detect + recover) |
| `CffDeflattener` | State-graph → edge list converter |
| `CffDispatcherDetector` | Raw-byte dispatcher scanner |
| `BlockMapping` | Bidirectional state↔block mapping (uses `AHashMap`) |
| `RecoveredCfg` | De-flattened CFG with successors/predecessors helpers |
| `SimpleCfg` / `SimpleBb` | Architecture-agnostic CFG primitives |
| `OllvmDeobfuscationPass` | OLLVM-specific pass (re-exported from `ollvm`) |

### 3.8 Dependencies

```toml
rustre-deobf   # DeobfPass, DeobfContext, ...
rustre-core    # Address
serde
ahash          # AHashMap (dos-hash-collision mitigation)
```

`ahash` is explicitly chosen over `std::HashMap` because block addresses and state values
come from untrusted binary input and a deterministic attacker could craft adversarial key
sets.

### 3.9 Completeness: **COMPLETE**

No `todo!` or `unimplemented!`. Extensive tests in `tests/blitz.rs` and `tests/blitz2.rs`
cover `CffDetector`, `CffRecoverer`, `CffDeobfuscationPass`, `BlockMapping`, `CffDispatcherDetector`,
and the `OllvmDeobfuscationPass`.

### 3.10 Gaps and Integration Notes

- `CffDeobfuscationPass` operates on `SimpleCfg` — a caller-constructed, architecture-
  agnostic graph. The crate does **not** include a disassembler; the MCP server or IL
  layer must populate `SimpleBb::state_const` from LLIL before calling `recover()` for
  full accuracy.
- When `state_const` is absent, synthetic address-derived states are used; these produce
  correct topology but incorrect state values, which may matter for downstream patch
  generation.
- `CffDeobfuscationPass` does not implement `rustre_deobf::DeobfPass` directly; callers
  working through the pipeline must adapt it (e.g. via `OllvmDeobfuscationPass` which
  does implement the trait).
- `dispatcher_rewriter.rs` generates patches but is not wired into `CffDeobfuscationPass`;
  the rewriter is available but requires explicit invocation.

---

## 4. `rustre-deobf-opaque` — Opaque Predicate Elimination

### 4.1 Purpose

Detects and removes opaque predicates — conditional branches whose outcome is statically
fixed (always-taken or never-taken) — from a simplified CFG representation.

### 4.2 Source Layout

| File | Responsibility |
|---|---|
| `lib.rs` | `OpaqueExpr` AST, `TruthTableChecker`, `KnownOpaquePattern`, `build_known_patterns` (24 patterns), `OpaqueDetector`, `OpaqueEliminator`, `OpaqueDeobfPass`, `SimpleBranchCfg` |
| `predicate_detector.rs` | Additional detector helpers |
| `predicate_evaluator.rs` | Evaluation utilities |
| `predicate_simplifier.rs` | AST simplification pass |
| `constant_propagator.rs` | Constant propagation into predicate expressions |
| `dead_branch_eliminator.rs` | Dead-branch removal after opaque detection |
| `opaque_cfg_cleaner.rs` | CFG cleanup after elimination |
| `opaque_rewriter.rs` | Rewrites the CFG in-place |
| `pattern_library.rs` | Extended pattern library |
| `polynomial_check.rs` | Polynomial identity checker |
| `sat_checker.rs` | Lightweight SAT-like checker |
| `smt_prover.rs` | SMT-style prover (pure Rust, no external solver) |
| `tautology_db.rs` | Static database of known tautologies |
| `conditional_simplifier.rs` | Simplification of conditional expressions |
| `junk_code_remover.rs` | Junk code removal tied to dead branches |

### 4.3 Expression Tree (`OpaqueExpr`)

A recursive `enum` covering integer arithmetic and comparisons with wrapping `i64`
semantics:

```rust
pub enum OpaqueExpr {
    Const(i64), Var(String),
    Add, Sub, Mul, Div, Mod, And, Or, Xor, Not, Neg, Shl, Shr,
    Eq, Ne, Lt, Le, Gt, Ge,
    BitCount, Abs, Square,
}
```

`eval(&HashMap<String,i64>) → Option<i64>` with a depth cap of 512 nodes (dos guard).
`simplify()` performs constant folding and algebraic simplifications (identity, zero,
commutativity). `is_trivially_equal(other)` enables structural identity detection without
evaluation.

### 4.4 Pattern Database (`build_known_patterns`)

24 patterns implemented as closures over `OpaqueExpr`:

| # | Pattern | Kind | Value |
|---|---|---|---|
| 1 | `x == x` | TrivialIdentity | AlwaysTrue |
| 2 | `x != x` | TrivialIdentity | AlwaysFalse |
| 3 | `(x-x) == 0` | TrivialIdentity | AlwaysTrue |
| 4 | `x*(x-1) % 2 == 0` | MathematicalInvariant | AlwaysTrue |
| 5 | `x^2 >= 0` | MathematicalInvariant | AlwaysTrue |
| 6 | `x*(x+1) % 2 == 0` | MathematicalInvariant | AlwaysTrue |
| 7 | `x \| ~x == -1` | MathematicalInvariant | AlwaysTrue |
| 8 | `x & ~x == 0` | MathematicalInvariant | AlwaysTrue |
| 9 | `x XOR x == 0` | TrivialIdentity | AlwaysTrue |
| 10 | `const == const` | ConstantExpr | computed |
| 11 | `x < x` | TrivialIdentity | AlwaysFalse |
| 12 | `x > x` | TrivialIdentity | AlwaysFalse |
| 13 | `x <= x` | TrivialIdentity | AlwaysTrue |
| 14 | `x >= x` | TrivialIdentity | AlwaysTrue |
| 15 | `(x & 0) == 0` | MathematicalInvariant | AlwaysTrue |
| 16–24 | Various `(x\|1)`, `x+x`, `popcnt`, odd-product variants | MathematicalInvariant | mixed |

### 4.5 Detection and Elimination

```
OpaqueDetector::detect(cfg: &SimpleBranchCfg) → Vec<OpaqueBranch>
  for each branch in cfg:
    1. pattern match via build_known_patterns()
    2. truth-table sampling via TruthTableChecker (configurable samples)
    3. classify as AlwaysTrue / AlwaysFalse / Unknown

OpaqueEliminator::eliminate(cfg: &mut SimpleBranchCfg) → EliminationResult
  for each OpaqueBranch:
    remove dead edge, mark dead block if it becomes unreachable
  return { branches_eliminated, dead_blocks_identified }

OpaqueDeobfPass::run(cfg: &mut SimpleBranchCfg) → OpaquePassResult
  candidates = detector.detect(cfg)
  elim_result = eliminator.eliminate(cfg)
  return { candidates_found, eliminated, dead_blocks, confidence_scores }
```

`TruthTableChecker` evaluates an `OpaqueExpr` across a configurable sample of integer
values for each variable, classifying the outcome.

### 4.6 CFG Representation (`SimpleBranchCfg`)

`SimpleBranchCfg` is separate from `rustre-deobf-cff`'s `SimpleCfg` — it is oriented
toward branch predicates rather than state-machine topology. Callers must translate
between representations if using both passes.

### 4.7 Dependencies

```toml
rustre-deobf   # shared types
rustre-core    # Address
serde
```

No external SAT/SMT solver dependency; all checking is pure Rust.

### 4.8 Completeness: **COMPLETE**

No `todo!` or `unimplemented!` macros. Inline unit tests cover `OpaqueExpr::eval`,
`simplify`, `is_trivially_equal`, the truth-table checker, and basic CFG elimination
scenarios.

### 4.9 Gaps

- `OpaqueDeobfPass` does not implement `rustre_deobf::DeobfPass`; it operates on
  `SimpleBranchCfg`, not `DeobfContext`. A bridge adapter is required to plug it into the
  standard pipeline.
- The `smt_prover.rs` module exists but is a pure-Rust lightweight prover; it cannot
  handle the full theory of bit-vectors that real obfuscated predicates sometimes require.
- No inter-pass communication: constant values discovered by the constant propagation
  pass (`constant_propagator.rs`) are not fed back into `CffRecoverer`.
- `build_known_patterns()` is called fresh on every `detect()` invocation, allocating 24
  closures each time.

---

## 5. `rustre-deobf-antianti` — Anti-Analysis Neutralization

### 5.1 Purpose

Detects and patches anti-debugging, anti-VM, and anti-sandbox techniques embedded in
binary data. Operates entirely at the byte level (no disassembler required) via a
pattern-matching signature database.

### 5.2 Source Layout

| File | Responsibility |
|---|---|
| `lib.rs` | Technique enums, `TechniqueSignature`, `signature_database` (14 signatures), `AntiAntiPass`, `generate_frida_script`, `AntiDebugDetector` |
| `detector.rs` | Structured multi-category detector |
| `anti_debug_patcher.rs` | Patch generation for anti-debug techniques |
| `antidbg_bypass.rs` | Bypass helpers |
| `bypasser.rs` | Generic bypass orchestrator |
| `anti_analysis_patterns.rs` | Extended pattern definitions |
| `evasion_patterns.rs` | Evasion-specific patterns |
| `environment_spoofer.rs` | Environment spoofing logic |
| `vm_detection.rs` | VM detection data |
| `vm_detection_bypass.rs` | VM detection bypass |
| `vm_check_neutralizer.rs` | VM check neutralization |
| `vm_detection_neutralizer.rs` | Higher-level VM neutralizer |
| `timing_check_detector.rs` | Timing-check detection |
| `timing_bypass.rs` | Timing bypass strategies |
| `timing_patchers.rs` | Byte patches for timing checks |
| `timing_attack_neutralizer.rs` | Orchestrates timing neutralization |
| `exception_based_antidebug.rs` | SEH / exception-based anti-debug |

### 5.3 Technique Taxonomy

Three enums classify covered techniques:

**`AntiDebugTechnique`** (23 variants): `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`,
`NtQueryInformationProcess`, `DebugBreak`, `OutputDebugString`, `CloseInvalidHandle`,
`NtGlobalFlag`, `HeapFlags`, `ProcessHeap`, `BeingDebugged`, `GetTickCount`,
`QueryPerformanceCounter`, `Rdtsc`, `HardwareBreakpoints`, `DrRegisterCheck`,
`SehChain`, `ParentProcess`, `TracerPid`, `Ptrace`, `ProcStatus`, `SelfMaps`,
`ExceptionBasedChecks`, `TimingDelays`, `TimingCheck`.

**`AntiVmTechnique`** (12 variants): `VmwarePortCheck`, `VmwareCpuid`, `VboxRegistry`,
`HyperVCpuid`, `QemuCpuid`, `SandboxArtifacts`, `SuspiciousProcessList`,
`NetworkAdapterCheck`, `CpuCountCheck`, `DiskSizeCheck`, `UptimeCheck`,
`MouseMovementCheck`.

**`AntiSandboxTechnique`** (7 variants): `SleepSkip`, `UserInteractionCheck`,
`RecentFileCheck`, `NetworkConnectivity`, `ScreenResolution`, `UsernameCheck`,
`DomainCheck`.

### 5.4 Signature Database (14 entries)

| Signature name | Pattern | Strategy |
|---|---|---|
| `rdtsc` | `0F 31` | Nop |
| `peb-being-debugged-x86` | `64 A1 30 00 00 00` | ForceFalse |
| `peb-being-debugged-x64` | `65 48 8B 04 25 60 00 00 00` | ForceFalse |
| `nt-global-flag-x86` | `64 A1 68 00 00 00` | ReturnZero |
| `heap-flags-x86` | `64 A1 18 00 00 00` | Nop |
| `debug-break-int3` | `CC` | Nop |
| `close-invalid-handle` | `6A FF FF 15 ?? ?? ?? ??` | Nop |
| `vmware-port-backdoor` | `B8 58 56 00 00` | Nop |
| `cpuid-hypervisor-leaf` | `B8 00 00 00 40 0F A2` | Nop |
| `sleep-large-value` | `68 60 EA 00 00` | ReturnZero |
| `seh-trap-flag` | `9C 58 A9 00 01 00 00` | ForceFalse |
| `ptrace-traceme-x86` | `B8 65 00 00 00` | ReturnZero |
| `gettickcount-timing` | `FF D0 8B F8 FF D0 2B C7` | Nop |
| `dr-register-check` | `0F 21 C0` (mask `FF FF F8`) | ReturnZero |

String literals (`IsDebuggerPresent`, VM artifact names) are scanned separately and
produce detection-only hits (no `patch_bytes`).

### 5.5 `AntiAntiPass` as `DeobfPass`

```rust
impl DeobfPass for AntiAntiPass {
    fn name() -> "anti-anti-analysis"
    fn is_applicable(ctx) → ctx.binary.len() >= 4
    fn run(ctx) → Result<DeobfResult, DeobfError>:
      hits = self.scan(&ctx.binary)
      for hit in hits:
        if hit.patch_bytes.is_empty(): record as detection
        else: push Patch { offset, original, patched=patch_bytes, reason }
      confidence = 0.85 if any hits else 0.0
}
```

### 5.6 Frida Script Generation

`generate_frida_script(hits)` produces a JavaScript Frida hook targeting detected APIs
(`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`) and
inline patterns (RDTSC, PEB). This is the only crate in the four analyzed that produces
dynamic instrumentation output.

### 5.7 Dependencies

```toml
rustre-deobf   # DeobfPass, DeobfContext, PatternMatcher, Patch
thiserror
serde, serde_json
```

Note: does **not** depend on `rustre-core`, making it the most self-contained of the four
crates analyzed.

### 5.8 Completeness: **COMPLETE**

No `todo!` or `unimplemented!`. `AntiAntiPass` fully implements `DeobfPass` and is wired
into `backends::all()`.

### 5.9 Gaps

- The `debug-break-int3` signature (`0xCC`) has an extremely high false-positive rate
  (any `INT3` instruction matches, including legitimate breakpoints and padding).
  No minimum-context or function-boundary guard is applied.
- `sleep-large-value` hardcodes the 60,000 ms value (`0xEA60`); Sleep calls with other
  large values (e.g. 300,000 ms) are not detected.
- `gettickcount-timing` pattern assumes a specific register sequence (`edi`); indirect
  calls through different registers will not match.
- String-literal hits carry empty `patch_bytes` — the caller cannot batch-apply them
  via `ctx.apply_patches()`; they require a separate handling path.
- Frida script generator (`generate_frida_script`) does not cover VM or sandbox
  techniques — only anti-debug API hooks and PEB clearing.
- The `vm_detection_neutralizer.rs`, `timing_attack_neutralizer.rs`, and
  `exception_based_antidebug.rs` modules exist as architecture but their integration into
  the main `AntiAntiPass::run()` path is not visible from `lib.rs`; they may be stubs or
  available only via `detector.rs`.

---

## 6. Pipeline Integration Summary

```
MCP server / rustre-mcp
  │
  └── DeobfPipeline (rustre-deobf)
        ├── AntiAntiPass          [rustre-deobf-antianti]  ← fully wired
        ├── CffDeobfuscationPass  [rustre-deobf-cff]       ← adapter needed
        │   (OllvmDeobfuscationPass implements DeobfPass directly)
        ├── OpaqueDeobfPass       [rustre-deobf-opaque]    ← adapter needed
        │   (operates on SimpleBranchCfg, not DeobfContext)
        └── ... (MBA, IADL, SMC, String, VM, VMLift, MHCDE)
```

The two gaps are:

1. `CffDeobfuscationPass` does not implement `DeobfPass`. The `OllvmDeobfuscationPass`
   in `ollvm.rs` does, but it is OLLVM-specific. A generic `CffDeobfPass` adapter that
   wraps `CffDeobfuscationPass` and serializes the `RecoveredCfg` result into
   `ctx.metadata` is missing.

2. `OpaqueDeobfPass` operates on `SimpleBranchCfg`, not `DeobfContext`. An adapter that
   lifts the branch predicates from the binary (or from a companion IL pass) into
   `SimpleBranchCfg`, calls `OpaqueDeobfPass::run()`, and writes the eliminated-branch
   patches back into `ctx.patches` is missing.

---

## 7. Dependency Graph

```
rustre-core
    └─ rustre-deobf
            ├─ rustre-deobf-cff
            ├─ rustre-deobf-opaque
            └─ rustre-deobf-antianti
```

All four crates are `edition = "2024"` with `workspace.lints`. No circular dependencies.

---

## 8. Completeness Matrix

| Crate | Stubs | `todo!`/`unimplemented!` | Integration | Overall |
|---|---|---|---|---|
| `rustre-deobf` | None | None | Full (trait + utilities) | **Complete** |
| `rustre-deobf-cff` | None | None | Partial (no `DeobfPass` on `CffDeobfuscationPass`) | **Complete / integration gap** |
| `rustre-deobf-opaque` | None | None | Partial (`SimpleBranchCfg` not `DeobfContext`) | **Complete / integration gap** |
| `rustre-deobf-antianti` | None | None | Full (implements `DeobfPass`) | **Complete** |

---

# Part B — MBA, IADL, MHCDE

# Analysis: rustre-deobf-mba, rustre-deobf-iadl, rustre-deobf-mhcde

> Generated 2026-07-01. All three crates are sub-passes in the `rustre-deobf` pipeline.
> No `todo!` / `unimplemented!` macros were found in any crate.

---

## 1. rustre-deobf-mba

### 1.1 Purpose

Mixed Boolean Arithmetic (MBA) deobfuscation. MBA obfuscation uses identities
that mix linear arithmetic (`+`, `-`, `*`) with bitwise operations (`&`, `|`,
`^`, `~`) to hide simple computations behind high-complexity expression trees.
This crate provides the expression IR, simplification engine, truth-table
verifier, pattern database, and the batch analysis pass.

### 1.2 Dependencies

| Dependency | Role |
|---|---|
| `rustre-deobf` | `DeobfPass` / `DeobfContext` / `Patch` traits |
| `serde` | Serialize / Deserialize on result types |

No runtime external dependencies (no rayon, no petgraph). All work is
single-threaded and purely symbolic.

### 1.3 Source Modules

| Module | Responsibility |
|---|---|
| `lib.rs` (7 006 lines) | `MbaExpr`, `MbaSimplifier`, `TruthTableVerifier`, `MbaPatternDb`, rule database |
| `mba_detector.rs` | Heuristic detection of MBA expressions in instruction streams |
| `mba_simplifier.rs` | Additional simplifier helpers |
| `mba_simplification.rs` | Simplification pass infrastructure |
| `mba_rewriter.rs` | Rewrites expressions after simplification |
| `mba_oracle.rs` | Oracle-based equivalence check (concrete evaluation) |
| `mba_normalization.rs` | Canonical form normalization before rule application |
| `mba_complexity_scorer.rs` | Scores expression trees by node count / depth |
| `bitwise_arithmetic_folder.rs` | Constant folding for bitwise+arithmetic mixed nodes |
| `boolean_algebra_simplifier.rs` | Boolean-algebra laws (De Morgan, absorption, etc.) |
| `boolean_normalization.rs` | Boolean normal form (CNF/DNF approximation) |
| `nonlinear_mba_solver.rs` | Attempts to solve non-linear MBA via linearisation |
| `deobf_mba_pass.rs` | High-level `DeobfPass` adapter |

### 1.4 Core Types

```rust
// Expression IR — covers all MBA-relevant operations
pub enum MbaExpr {
    Const(i64), Var(String),
    Add(Box<Self>, Box<Self>), Sub(..), Mul(..), Neg(..),
    And(..), Or(..), Xor(..), Not(..),
    Shl(Box<Self>, u8), Shr(Box<Self>, u8), Sar(Box<Self>, u8),
}

// Rule-driven engine
pub struct MbaSimplifier {
    pub rules: Vec<SimplificationRule>,
    pub max_iterations: usize,   // default 100
    pub use_truth_table: bool,   // default true
}

// Exhaustive equivalence checker (up to 8-bit domain, ≤4 vars)
pub struct TruthTableVerifier { pub bits: u32, pub max_vars: usize, .. }

// Rewrite result with full trace
pub struct SimplificationResult {
    pub original: MbaExpr,
    pub simplified: MbaExpr,
    pub steps: Vec<SimplificationStep>,
    pub complexity_before / after: usize,
    pub rules_applied: Vec<String>,
    pub verified: bool,
    pub converged: bool,
}
```

### 1.5 Rule Database

`build_rule_database()` returns an ordered `Vec<SimplificationRule>`, composed
of named sub-groups applied in priority order:

| Group | Example rules |
|---|---|
| Constant folding | `const-add`, `const-xor`, `const-neg`, … |
| MBA core identities | `and-plus-or`, `xor-plus-2and`, `or-minus-and`, `sum-minus-and`, `and-plus-xor`, `xor-of-xor-and` |
| Extended MBA rules | (in `extended_mba_rules()`) |
| Additive identities | `add-zero-r/l`, `add-neg-self` |
| Subtractive identities | `sub-zero`, `sub-self`, `zero-sub`, `sub-as-add-neg` |
| Multiplicative identities | `mul-one-r/l`, `mul-zero-r/l` |
| XOR identities | `xor-self`, `xor-zero-r/l` |
| AND identities | `and-self`, `and-zero-r/l`, `and-allones-r/l` |
| OR identities | `or-self`, `or-zero-r/l`, `or-allones-r/l` |
| NOT identities | `double-not` |
| NEG identities | `neg-of-not` (`-(~x) → x+1`), `double-neg` |

Key MBA semantic rules (examples):

```
(x & y) + (x | y)   →  x + y          [and-plus-or]
(x ^ y) + 2*(x & y) →  x + y          [xor-plus-2and]
(x | y) - (x & y)   →  x ^ y          [or-minus-and]
(x + y) - (x & y)   →  x | y          [sum-minus-and]
(x & y) + (x ^ y)   →  x | y          [and-plus-xor]
(x ^ y) ^ (x & y)   →  x | y          [xor-of-xor-and]
```

### 1.6 Truth-Table Verifier

After simplification, `MbaSimplifier` calls `TruthTableVerifier::verify_equivalent`
using an 8-bit domain (256 values per variable, capped at 4 variables = 4 294 967 296
worst-case combinations but internally capped at 15-bit effective domain for
performance). The verifier returns a `VerificationResult` with a counterexample
if the rewrite was unsound.

### 1.7 Public API Summary

| Symbol | Kind | Description |
|---|---|---|
| `MbaExpr` | enum | Symbolic expression tree |
| `MbaSimplifier::new()` | constructor | Full rule-set simplifier |
| `MbaSimplifier::simplify(expr)` | method | Returns `SimplificationResult` with trace |
| `MbaSimplifier::simplify_tree(expr)` | method | Returns simplified `MbaExpr` only |
| `TruthTableVerifier::verify_equivalent(a, b)` | method | Exhaustive equivalence check |
| `build_rule_database()` | fn | Returns all rewrite rules |
| `MbaPatternDb` | struct | Known pattern lookup |
| `MbaExprParser` | struct | Text-format parser (for tests/tooling) |

### 1.8 Completeness

**COMPLETE.** No `todo!` or `unimplemented!`. The lib.rs alone is 7 006 lines,
implementing the full MBA pipeline. The simplification engine converges, the
verifier is functional, and the `DeobfPass` adapter (`deobf_mba_pass.rs`)
connects to the shared pipeline.

### 1.9 Gaps / Limitations

- Truth-table verifier is capped at 15-bit effective domain; 64-bit MBA
  equivalences require random sampling (the `use_random` field exists but
  random sampling is not wired to any RNG — always false in practice).
- Non-linear MBA solver (`nonlinear_mba_solver.rs`) is a separate module;
  its integration with the main `MbaSimplifier` is not visible from `lib.rs`
  and warrants inspection.
- No IL/IR integration: `MbaExpr` trees must be constructed by the caller
  from lifted IL; there is no automatic extraction from `rustre-il`.

---

## 2. rustre-deobf-iadl

### 2.1 Purpose

Iterative Adversarial Deobfuscation Loop (IADL). A two-layer architecture:

1. **Generic IADL core** — a deterministic hypothesis-scoring loop framework
   applicable to any deobfuscation problem that can be modelled as "choose the
   best hypothesis among candidates, accept if improvement exceeds threshold,
   repeat until convergence."

2. **Binary IADL** — a specialisation that scans raw binaries for known
   protection layers (UPX packer, VM obfuscation, anti-debug, string
   encryption, CFF, opaque predicates) and orchestrates hypothesis passes
   via `rayon`-parallel evaluation.

3. **Dynamic API resolution detection** — `IadlDetector` scans for hash
   constants and `LoadLibrary`/`GetProcAddress` call patterns to identify
   binaries that resolve imports at runtime.

### 2.2 Dependencies

| Dependency | Role |
|---|---|
| `rustre-deobf` | Shared deobf types |
| `rustre-core` | Core binary representation |
| `anyhow` / `thiserror` | Error handling |
| `serde` / `serde_json` | Report serialisation |
| `petgraph` | (available, used by sub-modules) |
| `rayon` | Parallel hypothesis evaluation in `BinaryIadlOrchestrator` |
| `tracing` | Diagnostic logging |

### 2.3 Source Modules

| Module | Responsibility |
|---|---|
| `lib.rs` (3 220 lines) | Generic `IadlOrchestrator`, `BinaryIadlOrchestrator`, built-in hypotheses, `IadlDetector` |
| `iadl_orchestrator.rs` | Additional orchestrator helpers |
| `adversarial_loop.rs` | Core adversarial iteration logic |
| `adversarial_tester.rs` | Property-testing harness for hypothesis quality |
| `call_graph_builder.rs` | Builds call graphs for strategy selection |
| `constraint_propagation.rs` | Constraint propagation during analysis |
| `convergence_detector.rs` | Detects loop convergence |
| `deobf_strategy_selector.rs` | Selects deobfuscation strategy from analysis |
| `indirect_target_resolver.rs` | Resolves indirect call/jump targets |
| `ir_transform.rs` | IR-level transformations within the loop |
| `loop_analysis.rs` | Loop structure analysis |
| `loop_orchestrator.rs` | Loop-level deobfuscation orchestration |
| `obfuscation_classifier.rs` | Classifies obfuscation techniques |
| `perturbation.rs` | Generates perturbations for adversarial testing |
| `strategy_selector.rs` | High-level strategy selection |

### 2.4 Core Types

```rust
// Generic loop state
pub struct IadlState {
    pub iteration: u32,
    pub global_score: f64,
    pub complexity: u64,
    pub score_components: BTreeMap<String, f64>,
}

// Hypothesis trait (generic)
pub trait Hypothesis: Send + Sync {
    fn id(&self) -> &str;
    fn prior(&self, state: &IadlState) -> f64;      // default 0.5
    fn apply(&self, state: &IadlState) -> TentativeState;
}

// Scorer trait
pub trait Scorer: Send + Sync {
    fn name(&self) -> &str;
    fn weight(&self) -> f64;
    fn score(&self, tentative: &TentativeState, baseline: &IadlState) -> f64;
}

// Binary-specific state
pub struct BinaryIadlState {
    pub binary_size: usize,
    pub function_count: u32,
    pub identified_layers: Vec<ProtectionLayer>,
    pub high_entropy_sections: Vec<String>,
    ..
}
```

### 2.5 Built-in Binary Hypotheses

| Hypothesis | Prior logic | Cost estimate |
|---|---|---|
| `UPXUnpackHypothesis` | 0.8 if UPX0/UPX1 sections present, else 0.1 | 200 ms |
| `CflFlatteningHypothesis` | 0.7 if `function_count > 50`, else 0.2 | 2 s |
| `OpaquePredicateHypothesis` | 0.6 if fn density > 2.0/KiB, else 0.25 | 3 s |
| `StringDecryptHypothesis` | 0.5 if high-entropy sections + `fn_count > 20` | 800 ms |
| `AntiDebugHypothesis` | 0.9 if anti-debug API name strings present | 100 ms |
| `VmObfuscationHypothesis` | 0.6 if fn density < 0.5 and ≥2 high-entropy sections | 10 s |

### 2.6 Binary Scanner

`analyze_binary_for_protections(data: &[u8]) -> BinaryIadlState` provides a
quick static scan that:
- Computes Shannon entropy in 256-byte windows (threshold > 7.0).
- Searches for UPX marker bytes (`UPX0`, `UPX1`, `UPX!`).
- Searches for anti-debug API name strings.
- Counts x86/x64 function prologues (`55 8B EC` / `55 48 89 E5`).

### 2.7 Dynamic API Resolution

`IadlDetector` provides three methods:

| Method | Description |
|---|---|
| `scan_hash_constants(&[u8])` | Finds 32-bit values with ≥8 set bits (likely hash constants) |
| `detect_loadlib_pattern(&[u8])` | Finds `FF D0`, `FF D2`, `FF 15` (indirect call patterns) |
| `identify_algorithm(&[u64])` | Correlates hashes against built-in API name table for Djb2/FNV1a/CRC32/SDBM/Adler32 |
| `analyze(&[u8], base)` | Full pipeline: scan → identify → resolve → return `Vec<ApiResolution>` |

Built-in API name table: 10 common names (`LoadLibraryA`, `GetProcAddress`,
`VirtualAlloc`, `VirtualProtect`, `CreateThread`, `WinExec`, `ExitProcess`,
`GetModuleHandleA`, `InternetOpenA`, `WSAStartup`).

### 2.8 Loop Mechanics

The generic `IadlOrchestrator::run()`:
1. Iterates up to `max_iterations` (default 64).
2. Each iteration evaluates all hypotheses via rayon parallel map.
3. Scores via weighted average of registered `Scorer` implementations, adjusted by hypothesis prior.
4. Complexity penalty: `final_score = scorer_score * prior - complexity * penalty`.
5. Accepts best candidate if `final_score > current + min_improvement` (default 1e-6).
6. Stops after `max_no_progress` (default 3) consecutive non-improving iterations.

### 2.9 Public API Summary

| Symbol | Kind | Description |
|---|---|---|
| `IadlOrchestrator::new(config)` | constructor | Generic loop engine |
| `IadlOrchestrator::run(state, hypotheses, scorers)` | method | Run loop, return `IadlReport` |
| `BinaryIadlOrchestrator::new()` | constructor | Pre-wired with 6 built-in hypotheses |
| `BinaryIadlOrchestrator::run(&[u8])` | method | Scan + loop, return `BinaryIadlReport` |
| `analyze_binary_for_protections(&[u8])` | fn | Quick static scan |
| `IadlDetector::analyze(&[u8], base)` | method | Dynamic API resolution pipeline |
| `ProtectionLayer` | enum | 7 protection technique variants |
| `BinaryIadlReport::to_json()` | method | JSON serialisation |

### 2.10 Completeness

**COMPLETE** at the library level. No `todo!` or `unimplemented!`. Both the
generic and binary orchestrators are functional. The per-hypothesis `apply()`
implementations return heuristic `BinaryTentativeState` structs with
descriptions but do not execute actual binary transformations — they describe
what should be done, with estimated quality scores.

### 2.11 Gaps / Limitations

- Hypothesis `apply()` methods return descriptions and heuristic scores only;
  they do not mutate binaries. Actual unpacking (UPX), CFF removal, etc. must
  be delegated to other crates (`rustre-deobf-cff`, `rustre-deobf-opaque`, etc.).
- Hash resolution table is limited to 10 API names; real-world shellcode uses
  hundreds. No external hash database integration.
- `RorHash` (common in shellcode) appears in the `HashAlgorithm` enum but is
  not in the brute-force identification loop.
- Sub-module content (`adversarial_tester.rs`, `perturbation.rs`, etc.) is not
  visible from `lib.rs` — these may implement additional functionality not
  surfaced in the public API.

---

## 3. rustre-deobf-mhcde

### 3.1 Purpose

"Mixed Honig Control-flow & Dead-code Elimination." Operates at the raw binary
byte level to:
- Detect and NOP opaque predicates (12 hardcoded x86 patterns).
- Detect junk / no-op instruction sequences (13 patterns).
- Detect control-flow flattening (indirect-jump dispatcher heuristic).
- Eliminate unreachable basic blocks (BFS reachability).
- Apply a non-overlapping NOP patch plan to the binary.
- Implement `DeobfPass` so it slots into the standard pipeline.

### 3.2 Dependencies

| Dependency | Role |
|---|---|
| `rustre-deobf` | `DeobfPass`, `DeobfContext`, `Patch` |
| `thiserror` | Error types |
| `serde` / `serde_json` | Analysis result serialisation; CFF metadata via `ctx.set_meta` |
| `petgraph` | `DiGraph` for CFG-level dead-code BFS (in `DeadCodeEliminator::build_graph`) |
| `ahash` | `AHashMap` for O(1) offset lookups |

### 3.3 Source Modules

| Module | Responsibility |
|---|---|
| `lib.rs` (3 069 lines) | All core detectors, orchestrator, `MhcdePass` |
| `mhcde_passes.rs` | Additional pass sub-steps |
| `control_flow_graph_builder.rs` | CFG construction helpers |
| `dataflow_propagator.rs` | Dataflow for dead-code analysis |
| `deobf_orchestrator.rs` | Pipeline orchestration |
| `deobf_oracle.rs` | Oracle for patch correctness |
| `entropy_scorer.rs` | Entropy-based scoring helpers |
| `feature_extractor.rs` | Feature extraction for ML-style classification |
| `hypothesis_combiner.rs` | Combines hypothesis results |
| `hypothesis_engine.rs` | Hypothesis evaluation engine |
| `hypothesis_generator.rs` | Generates deobfuscation hypotheses |
| `hypothesis_manager.rs` | Manages hypothesis lifecycle |
| `hypothesis_validator.rs` | Validates hypotheses before application |
| `multi_stage_deobf.rs` | Multi-stage pipeline execution |
| `combination_solver.rs` | Solves combined deobfuscation problems |
| `concurrent_deobf_executor.rs` | Concurrent execution of passes |

### 3.4 Core Detectors

#### OpaquePredicateDetector

12 hardcoded x86 byte patterns (all operating on EAX/ECX):

| # | Pattern | Type | Bytes |
|---|---|---|---|
| 1 | `31 C0 85 C0 74 xx` | xor eax,eax; test eax,eax; jz | AlwaysTrue / 5 |
| 2 | `31 C0 85 C0 75 xx` | xor eax,eax; test eax,eax; jnz | AlwaysFalse / 5 |
| 3 | `B0 01 84 C0 74 xx` | mov al,1; test al,al; jz | AlwaysFalse / 5 |
| 4 | `83 C8 FF 85 C0 75 xx` | or eax,-1; test eax,eax; jnz | AlwaysTrue / 6 |
| 5 | `83 E0 00 85 C0 74 xx` | and eax,0; test eax,eax; jz | AlwaysTrue / 6 |
| 6 | `33 C0 74 xx` | xor eax,eax; jz (condensed) | AlwaysTrue / 3 |
| 7 | `33 C9 E3 xx` | xor ecx,ecx; jecxz | AlwaysTrue / 3 |
| 8 | `31 C0 39 C0 74 xx` | xor eax,eax; cmp eax,eax; jz | AlwaysTrue / 5 |
| 9 | `B8 00..00 85 C0 74 xx` | mov eax,0; test eax,eax; jz | AlwaysTrue / 7 |
| 10 | `F9 72 xx` | stc; jc | AlwaysTrue / 2 |
| 11 | `F8 73 xx` | clc; jnc | AlwaysTrue / 2 |
| 12 | `31 C0 83 C8 01 85 C0 75 xx` | xor; or 1; test; jnz | AlwaysTrue / 7 |

#### JunkCodeDetector

13 patterns:

| Pattern | Bytes |
|---|---|
| NOP sled (≥2 × `0x90`) | variable |
| push reg; pop same reg | 2 |
| xor reg, 0 (`83 F0+r 00`) | 3 |
| add reg, 0 (`83 C0+r 00`) | 3 |
| sub reg, 0 (`83 E8+r 00`) | 3 |
| mov reg, reg (same src/dst, ModRM `0xC0`) | 2 |
| lea reg, [reg+0] (`8D 40+r 00`) | 3 |
| or reg, 0 (`83 C8+r 00`) | 3 |
| and reg, -1 (`83 E0+r FF`) | 3 |
| xchg eax,eax (`87 C0`) | 2 |
| clc; stc (`F8 F9`) | 2 |
| 16-bit NOP (`66 90`) | 2 |
| 3-byte NOP (`0F 1F 00`) | 3 |
| 4-byte NOP (`0F 1F 40 00`) | 4 |

#### ControlFlowFlattener

Heuristic: finds `FF 24` / `FF E0` / `FF E3` (indirect jump) in byte stream,
scans back ≤64 bytes for block start, scans forward to collect body blocks (up
to 64), extracts a state variable from `MOV eax, [imm32]` (`A1` opcode).

#### DeadCodeEliminator

BFS reachability from `entry_offset` over `CfgBlock.successors`. Builds a
petgraph `DiGraph` for `bfs_order()`, uses a manual BFS with `AHashMap` for
`reachable_blocks()` (avoids graph allocation on hot path).

#### EntropyAnalyzer

Sliding-window Shannon entropy. Methods:
- `analyze(data)` — returns `Vec<EntropyWindow>` at `window_size/2` step.
- `high_entropy_windows(data, threshold)` — encrypted/packed regions (>7.0).
- `low_entropy_windows(data, threshold)` — padding/junk (<2.0).
- `mean_entropy(data)` — summary metric.

#### ConstantFoldingHeuristic

Folds small x86 sequences to a `u32` constant without a disassembler:
`MOV EAX, imm32`, `XOR EAX,EAX`, `OR EAX,-1`, `AND EAX,0`, `MOV AL, imm8`.

### 3.5 Orchestration

```
MhcdeOrchestrator::analyze(data) → MhcdeAnalysis {
    opaque_predicates: Vec<OpaquePredicate>,
    junk_regions:      Vec<JunkCodeRegion>,
    cff:               Option<CffDetectionResult>,
    patch_plan:        Vec<PlannedPatch>,   // non-overlapping, sorted by offset
    score:             MhcdeScore,
}
```

Patch planning enforces non-overlap via a `claimed: Vec<(usize, usize)>` linear
scan. Opaque predicate patches have confidence 0.9; junk patches have 0.75.

`MhcdeScore` fields:

| Field | Meaning |
|---|---|
| `confidence` | `0.55 + 0.35 * (patches/findings)` + 0.10 if CFF detected |
| `risk` | `unfixed_findings * 0.08 + modified_bytes/4096 * 0.05` |
| `modified_bytes` | Total NOP bytes proposed |
| `finding_count` | Predicates + junk regions + (1 if CFF) |

### 3.6 DeobfPass Integration

`MhcdePass` implements `DeobfPass`:
- `name()` → `"mhcde"`
- `is_applicable(ctx)` → `ctx.binary.len() >= 8`
- `run(ctx)` — Calls `MhcdeOrchestrator::analyze`, pushes `Patch` objects into
  `ctx.patches`, and stores CFF dispatcher offset / body block count as JSON
  metadata via `ctx.set_meta`. Returns `DeobfResult` with transformation log.

### 3.7 Public API Summary

| Symbol | Kind | Description |
|---|---|---|
| `MhcdePass::new()` | constructor | Full MHCDE pass (implements `DeobfPass`) |
| `MhcdeOrchestrator::analyze(&[u8])` | method | Detect + plan, return `MhcdeAnalysis` |
| `MhcdeOrchestrator::analyze_and_patch(&[u8])` | method | Detect + patch copy |
| `OpaquePredicateDetector::detect(&[u8])` | method | Returns `Vec<OpaquePredicate>` |
| `JunkCodeDetector::detect(&[u8])` | method | Returns `Vec<JunkCodeRegion>` |
| `ControlFlowFlattener::detect(&[u8])` | method | Returns `Option<CffDetectionResult>` |
| `DeadCodeEliminator::eliminate(blocks, entry)` | method | Reachability filter |
| `EntropyAnalyzer::analyze(&[u8])` | method | Sliding-window entropy |
| `PatchApplicator::apply_nop_patches(data, plan)` | method | In-place NOP fill |

### 3.8 Completeness

**COMPLETE.** No `todo!` or `unimplemented!`. All detectors, the orchestrator,
the patch planner, and the `DeobfPass` adapter are implemented and functional.

### 3.9 Gaps / Limitations

- Opaque predicate patterns are x86-only and cover only 12 hardcoded sequences.
  Real obfuscators use far more varied patterns; symbolic evaluation (SMT/z3)
  is not used here.
- CFF detection is a single heuristic (indirect jump pattern). A real CFF
  removal also needs to reconstruct the original CFG edges and rewrite the
  binary, which is not done — only the dispatcher offset and block count are
  stored as metadata.
- `JunkCodeDetector` does not handle REX-prefixed 64-bit equivalents
  (`48 89 C0` = MOV RAX,RAX, etc.), limiting effectiveness on x64 code.
- `ConstantFoldingHeuristic` is minimal (6 patterns). It is not integrated
  with the simplification pipeline of `rustre-deobf-mba`.

---

## 4. Pipeline Integration

```
Binary input
    │
    ▼
rustre-deobf-iadl  ─ BinaryIadlOrchestrator::run()
    │  Quick static scan → identifies protection layers
    │  Recommends which passes to apply
    │
    ├─► rustre-deobf-mhcde ─ MhcdePass::run()
    │       Removes opaque predicates + junk code (byte-level)
    │       Flags CFF dispatcher location as metadata
    │
    ├─► rustre-deobf-mba ─ MbaDeobfuscationPass (via deobf_mba_pass.rs)
    │       Simplifies MBA expressions in lifted IL
    │       Verified by TruthTableVerifier
    │
    └─► [other passes: rustre-deobf-cff, rustre-deobf-opaque, ...]
```

### 4.1 Integration Points

| Crate | Consumes | Produces |
|---|---|---|
| `rustre-deobf-iadl` | Raw `&[u8]` binary | `BinaryIadlReport`, `Vec<ApiResolution>` |
| `rustre-deobf-mhcde` | `DeobfContext` (owns `binary: Vec<u8>`) | NOP patches in `ctx.patches`, CFF metadata in `ctx.meta` |
| `rustre-deobf-mba` | `MbaExpr` trees (must be constructed by caller from IL) | `SimplificationResult`, verified simplified trees |

Neither `rustre-deobf-mba` nor `rustre-deobf-mhcde` currently consume the
output of the other directly. A plausible integration gap: after MHCDE removes
opaque predicates, IL should be re-lifted and fed through MBA simplification,
but this chaining is not wired in any of the three crates — it would need to
be implemented in the caller (e.g. `rustre-deobf` root or `rustre-deobf-vm`).

---

## 5. Summary Table

| Crate | Lines (lib.rs) | Completeness | `todo!` | Key gap |
|---|---|---|---|---|
| `rustre-deobf-mba` | 7 006 | Complete | 0 | MBA → IL bridge not automated; random sampling in verifier not wired |
| `rustre-deobf-iadl` | 3 220 | Complete | 0 | Hypothesis `apply()` describes but does not execute; hash DB is minimal |
| `rustre-deobf-mhcde` | 3 069 | Complete | 0 | x86-32 only; CFF reconstruction is informational only; no x64 junk patterns |

---

# Part C — String Decryption, SMC, VM Detection and Lifting

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
