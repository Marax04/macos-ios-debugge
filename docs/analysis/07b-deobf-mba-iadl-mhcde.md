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
