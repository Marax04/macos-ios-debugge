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
