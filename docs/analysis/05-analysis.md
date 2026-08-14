# 05 — Analysis Subsystem

> Workspace root: `C:/Users/Fra/Desktop/RustRE`
> Crates covered: `rustre-analysis`, `rustre-analysis-fn`, `rustre-analysis-cfg`,
> `rustre-analysis-callconv`, `rustre-analysis-dataflow`, `rustre-analysis-string`,
> `rustre-analysis-type`, `rustre-analysis-typerecov`, `rustre-analysis-vsa`,
> `rustre-analysis-vtable`, `rustre-analysis-xref`.

---

## 1. Architecture Overview

The analysis subsystem is a layered stack of eleven crates:

```
┌────────────────────────────────────────────────────────────┐
│              rustre-analysis   (core infrastructure)        │
│  AnalysisPass trait · AnalysisPipeline · PassScheduler      │
│  AnalysisEventBus · CrossReferenceDb · AnalysisDb          │
└───────────────────────┬────────────────────────────────────┘
                        │ intra-workspace dep
        ┌───────────────┼───────────────────┐
        │               │                   │
   analysis-fn      analysis-cfg     analysis-xref
   (function      (CFG / dominator   (xref database,
    detection)     trees / loops)     call graph)
        │               │
        └───────┬───────┘
                │
   ┌────────────┼──────────────────────────┐
   │            │                          │
callconv    dataflow                    string
(ABI          (lattice /              (scanner /
 detection)    worklist)               classify)
   │            │
   └────────────┼──────────────────────────┐
                │                          │
             type ──── typerecov       vsa · vtable
           (TypeFact   (constraint    (ValueSet /
            / union-   pipeline)       C++ RTTI)
             find)
```

All leaf crates depend on `rustre-analysis` for the `AnalysisPass` trait and shared
types (`AnalysisKind`, `AnalysisResult`, `AnalysisError`, `AnalysisConfig`).
`rustre-core` provides the address primitives (`Address`, `AddressRange`) and
`BinaryView` used everywhere.

---

## 2. `rustre-analysis` — Core Infrastructure

**Path:** `crates/rustre-analysis`
**Status:** COMPLETE — full implementation, no stubs.

### Purpose

Defines the shared vocabulary of the entire analysis system:
the `AnalysisPass` async trait, the `AnalysisPipeline` coordinator, dependency-ordered
`PassScheduler`, `AnalysisEventBus` pub-sub system, and the `CrossReferenceDb` /
`AnalysisDb` storage types.

### Key Public API

| Item | Kind | Description |
|------|------|-------------|
| `AnalysisKind` | enum | Category tag: `LinearSweep`, `DataFlow`, `TypeRecovery`, `VtableAnalysis`, …, `Custom(String)` |
| `AnalysisConfig` | struct | Per-run config: kind, max depth, timeout, start address, opaque options map |
| `AnalysisResult` | struct | Aggregated counts: functions found, xrefs, strings, duration, warnings |
| `AnalysisError` | enum (thiserror) | `PassNotFound`, `Failed`, `Timeout`, `InsufficientData` |
| `AnalysisPass` | async trait | `name()`, `kind()`, `description()`, `run(&BinaryView, &AnalysisConfig)`, `supports_arch()`, `priority()` |
| `AnalysisPipeline` | struct | `register()`, `find()`, `passes_for_kind()`, `run_all()`, `run_all_parallel()`, `remove()` |
| `PassDescriptor` | struct | Name + dependency list + priority for scheduler |
| `PassScheduler` | struct | Topological sort: `schedule()` → `Vec<String>`, `schedule_groups()` → `Vec<Vec<String>>` (parallel groups) |
| `AnalysisEventBus` | struct | Subscribe/publish `AnalysisEvent` callbacks |
| `AnalysisEvent` | enum | `FunctionDiscovered`, `StringRecovered`, `XrefFound`, `PassStarted`, `PassFinished`, `Warning`, `Error` |
| `AnalysisContext` | struct | Bundles `Arc<BinaryView>` + `Arc<AnalysisEventBus>` + `Arc<Mutex<AnalysisStats>>` |
| `AnalysisDb` | struct | In-memory JSON-keyed record store; `insert()`, `query_by_pass()`, `query_functions()`, `query_xrefs()`, `export_json()` |
| `CrossReferenceDb` | struct | Dual-indexed (`from_index`, `to_index`) `HashMap<u64, Vec<Xref>>`; `add()`, `xrefs_to()`, `xrefs_from()`, `calls()`, `call_targets()` |
| `Xref` / `XrefType` | struct/enum | `Call`, `Jump`, `DataRead`, `DataWrite`, `StringRef`, `Unknown` |
| `FunctionBoundary` / `BoundaryMethod` | struct/enum | Start, end, confidence 0–100, source method |
| `FunctionBoundaryAnalysis` | struct | `scan_prologues(base, bytes)`, `scan_call_targets(base, bytes)` — x86-64 only |
| `LinearSweepAnalyzer` | struct | `sweep(base, bytes)` — combines prologue + call-target passes |
| `AnalysisReport` | struct | `build(uri, outcomes)`, `summary()` |
| `NoOpAnalysisPass` / `CountingAnalysisPass` | struct | Test doubles |

### Internal Modules

| Module | Content |
|--------|---------|
| `analysis_context` | `AnalysisContext` extended implementation |
| `analysis_index` | Indexing helpers |
| `analysis_pipeline` | `AnalysisPipeline` extras |
| `analysis_scheduler` | `PassScheduler` implementation |
| `analysis_cache` | Result caching |
| `analysis_metrics` | Timing / metrics collection |
| `binary_analysis_report` | Report generation |
| `binary_analysis_suite` | High-level suite runner |
| `control_flow_analysis` | Basic CFG primitives re-exported here |
| `findings` | Typed finding records |
| `pass_registry` | Named pass registry beyond `AnalysisPipeline` |
| `runner` | `DependencyRunner`, `PassOutcome`, `RunReport` |
| `interprocedural_analysis` | `CallGraph`, `SummaryDatabase`, bottom-up / top-down |
| `vulnerability_scanner` | Vulnerability pattern detector |

### Integration

Every analysis pass in the other crates implements `AnalysisPass` and is registered
into `AnalysisPipeline`. The `PassScheduler` runs a Kahn's topological sort +
priority ordering so independent passes may execute concurrently via
`run_all_parallel()`.

---

## 3. `rustre-analysis-fn` — Function Detection

**Path:** `crates/rustre-analysis-fn`
**Status:** COMPLETE — rich multi-strategy implementation.

### Purpose

Locates function boundaries in raw binary memory via three complementary strategies:
prologue-pattern scanning (x86-64, x86-32, ARM64), CALL-target collection, and gap
analysis. Also provides callgraph construction, FLIRT library propagation, function
fingerprinting and clustering.

### Dependencies

| Crate | Role |
|-------|------|
| `rustre-analysis` | `AnalysisPass` trait, `AnalysisResult` |
| `rustre-loader-pe` | PE parsing: machine type, sections, `.pdata` `RUNTIME_FUNCTION` |
| `rustre-loader-elf` | ELF segment enumeration |
| `rustre-core` | `Address`, `AddressRange` |
| `rustre-il-llil` | LLIL instructions consumed by higher-level passes |
| `rustre-flirt-apply` | FLIRT signature matching for library function propagation |
| `petgraph` | Call graph representation |

### Key Public API

| Item | Description |
|------|-------------|
| `Confidence` | `Low=1`, `Medium=2`, `High=3`, `Certain=4` |
| `DetectionSource` | `EntryPoint`, `CallTarget`, `ProloguePattern`, `ExceptionHandler`, `SymbolTable`, `Flirt`, `HeuristicGap`, `User` |
| `FunctionBoundary` | `start: Address`, `end: Option<Address>`, `confidence`, `source`, `name` |
| `MemorySlice<'a>` | Address-aware byte view: `read_u8/u16/u32/u64_le`, `slice_at`, `contains` |
| `ProloguePattern` | Wildcard byte pattern with per-pattern confidence |
| `x86_64_prologue_patterns()` | 6 patterns: push_rbp_mov, endbr64, sub_rsp_imm8/32, push callee-saved regs |
| `x86_32_prologue_patterns()` | 7 patterns incl. endbr32 |
| `arm64_prologue_patterns()` | 6 patterns: stp x29/x30, sub sp, pacibsp, pacisp, mov x29 sp |
| `CallTargetCollector` | `collect_x86_calls()` / `collect_arm64_calls()` with range filter |
| `GapAnalyzer` | `find_gaps()`, `first_code_byte()` — discovers functions hidden in NOP/INT3 padding |
| `FunctionDetector` | `analyze(mem, hints)` — combines all three strategies, deduplicates |
| `FunctionBoundarySet` | Result container with `DetectionStats` |
| `detect_functions(arch, mem)` | Primary entry-point |
| `detect_functions_at(arch, base, bytes)` | Convenience wrapper |
| `detect_functions_from_path(path)` | Full PE/ELF binary scan with `.pdata` augmentation |
| `detect_functions_from_path_segments(path, arch)` | Per-section scan returning `Vec<DetectedFunction>` |
| `FunctionDetectionPass` | `AnalysisPass` implementation wiring above into the pipeline |
| `callgraph_from()`, `render_callgraph_dot()` | `petgraph`-backed call graph + DOT output |
| `callees()` / `CalleeRecord` | Per-function callee list with `CalleeKind` classification |
| `apply_library_marks()` | FLIRT-driven library function name propagation |
| `StrategyEngine` / `StrategyInputs` | Multi-strategy merge with `CandidateEvidence` scoring |

### Key Implementation Detail: `.pdata` augmentation

`detect_functions_from_path()` uses `rustre-loader-pe`'s `exception_functions` list
(the PE `.pdata` RUNTIME_FUNCTION table) to supplement heuristic results. This is
critical for leaf functions and optimised code that lack classical prologues —
matching IDA's ground truth behaviour.

### Internal Modules (21 total)

`function_classifier`, `function_entropy`, `function_similarity`, `yara_from_function`,
`stack_frame_analyzer`, `advanced_function_detection`, `function_clustering`,
`function_discovery`, `function_fingerprint`, `function_splitting`, `heuristics`,
`prologue_db`, `prologue_scanner`, `recursive_detection`, `strategies`, `function_splitter`,
`noreturn_detector`, `function_size_estimator`, `library_propagation`, `callgraph`, `callees`.

### Known Gaps

- `detect_functions_from_path()` falls back to whole-image scan when no `.text` section
  is found; ELF `.pdata` equivalent (`eh_frame` FDE parsing) lives in `strategies`
  but integration with `detect_functions_from_path` for ELF is partial.
- `estimate_end_x86` has a simplified instruction length model (single-byte stepping)
  and may misidentify function ends for multi-byte instructions that happen to have
  a `0xC3` byte in their encoding.

---

## 4. `rustre-analysis-cfg` — Control Flow Graphs

**Path:** `crates/rustre-analysis-cfg`
**Status:** COMPLETE — full algorithms implemented.

### Purpose

Builds and analyses per-function control flow graphs from lifted LLIL instruction
sequences. Provides basic block splitting, CFG construction, dominator and
post-dominator tree computation (Cooper et al. 2001 algorithm), natural loop
detection, back-edge identification, RPO/post-order traversal, cyclomatic complexity,
reducibility testing, Lengauer-Tarjan dominator algorithm, jump table decoding,
Graphviz DOT output, and CFG simplification.

### Dependencies

| Crate | Role |
|-------|------|
| `rustre-analysis` | `AnalysisPass` trait |
| `rustre-core` | `Address` |
| `rustre-il-llil` | `LlilInstruction` — CFG is built over lifted IL |
| `petgraph` | Used in `to_petgraph()` export |
| `anyhow` / `thiserror` | Error handling |

### Key Public API

| Item | Description |
|------|-------------|
| `BasicBlock` | `start: Address`, `end: Address`, `instructions: Vec<LlilInstruction>` |
| `EdgeKind` | `Unconditional`, `TrueBranch`, `FalseBranch`, `Fallthrough` |
| `CfgEdge` | `from`, `to`, `kind` |
| `DominatorTree` | `idom`, `children`, `frontiers`; `dominates()`, `strictly_dominates()`, `dominated_by()`, `dominance_frontier()`, `depth()` |
| `PostDominatorTree` | Reverse-graph Cooper et al.; `post_dominates()` |
| `NaturalLoop` | `header`, `back_edge_src`, `body: HashSet<Address>`, `exits`, `is_innermost` |
| `ControlFlowGraph` | Aggregate: blocks + edges + entry + dom_tree + post_dom_tree + loops |
| `CfgStats` | `cyclomatic_complexity`, `max_loop_depth`, `entry_blocks`, `exit_blocks` |
| `CfgDotPrinter` | `print(cfg) -> String` — Graphviz with loop highlighting and back-edge styling |
| `analyze_cfg(instrs)` | Full 7-step build: leaders → blocks → edges → entry → dom → post-dom → loops |
| `try_analyze_cfg(instrs)` | Fallible version returning `anyhow::Result<ControlFlowGraph>` |
| `find_natural_loops(cfg)` | Back-edge BFS loop body computation |
| `cyclomatic_complexity(cfg)` | `E - N + 2P` accounting for unreachable components |
| `cfg_to_dot(cfg)` | Convenience DOT wrapper |
| `is_reducible(cfg)` | Reducibility check via `ReducibilityTest::test()` |
| `LtDomTree` / `compute_lt()` | Lengauer-Tarjan O(n α(n)) algorithm (alternative to Cooper) |
| `FullPostDomTree` | Extended post-dominator from `post_dominator` module |
| `JumpTable` / `JumpTableKind` / `SwitchStatement` | Jump table decoding (absolute/relative tables) |
| `CfgSimplifier` / `SimplifyResult` | CFG simplification and dead-block removal |

### Internal Modules (16 total)

`back_edge`, `cfg_algorithms`, `cfg_dominators`, `cfg_reconstruction`, `edges`,
`exception_cfg`, `irreducible_cfg`, `jump_table`, `lengauer_tarjan`, `loop_analysis`,
`loop_detection`, `path_query`, `post_dominator`, `reducibility_analysis`, `simplify`,
`cfg_loop_analyzer`, `cfg_simplifier`.

### Known Gaps

- CFG is built from LLIL only; indirect-jump (`JumpDest` with non-const expr) leaves a
  missing edge — callers must supplement with VSA-based target resolution.
- Exception-handling CFG edges (SEH/C++ EH unwind paths) are handled in
  `exception_cfg` but not automatically merged into `ControlFlowGraph`.

---

## 5. `rustre-analysis-callconv` — Calling Convention Detection

**Path:** `crates/rustre-analysis-callconv`
**Status:** COMPLETE — rich multi-ABI database.

### Purpose

Identifies how a function receives arguments and returns values. Uses register-use
heuristics on the function prologue/epilogue to classify into named ABIs, backed by
a static database covering 20+ calling conventions.

### Key Types

| Type | Description |
|------|-------------|
| `Arch` | `X86`, `X86_64`, `Arm32`, `Arm64`, `Mips32/64`, `Ppc32/64`, `RiscV32/64`, `Other` |
| `CallConvError` | `NoMatch`, `Ambiguous`, `UnknownKey`, `TooShort`, `UnknownRegister`, `Json` |
| `ArgRegisterProfile` | Which registers are live on entry (argument registers) |
| `PreservationReport` | Which callee-saved regs are pushed/popped |
| `StackCleanup` | `Caller` vs. `Callee` (stdcall vs. cdecl distinction) |
| `CallConvVerdict` | Named CC + confidence score |
| `CcRegistry` | Database of `CallingConvention` descriptors keyed by arch/OS |

### CC Database Constants (re-exported)

`CC_CDECL_X86`, `CC_STDCALL_X86`, `CC_FASTCALL_X86`, `CC_THISCALL_X86`,
`CC_VECTORCALL_X64`, `CC_REGCALL_X64/X86`, `CC_SYSV_AMD64`, `CC_MS_X64`,
`CC_AAPCS32`, `CC_AAPCS32_VFP`, `CC_AAPCS64`, `CC_SWIFT_X64/ARM64`,
`CC_RUST_X64/ARM64`, `CC_MIPS_O32/N64`, `CC_RISCV32_ILP32D`, `CC_RISCV64_LP64D`,
`CC_SYSV_X86`.

### Key Functions

| Function | Description |
|----------|-------------|
| `profile_arg_registers(instrs, arch)` | Determine which arg registers are read before write |
| `analyze_preservation(instrs, arch)` | Identify callee-saved register saves/restores |
| `classify_stack_cleanup(instrs, arch)` | Detect `RETN imm16` for callee cleanup |
| `default_callee_saved(arch)` | Per-arch expected callee-saved set |
| `abis_are_compatible(a, b)` | Check if two CC descriptors share enough registers |
| `shared_arg_registers(a, b)` | Intersection of argument register sets |
| `function_info_from_observed(observed, arch)` | Build `PropagationResult` from call-site evidence |
| `infer_params_from_observed(observed)` | Recover parameter types from observed registers |

### Internal Modules

`abi_analyzer`, `cc_database`, `cc_detector`, `cc_detector_advanced`, `heuristics`,
`propagation`, `register_colouring`, `return_type_recovery`, `variadic_analyzer`,
`variadic_detection`, `argument_tracker`, `return_type_analyzer`, `stack_cleanup_analyzer`,
`vararg_detector`.

---

## 6. `rustre-analysis-dataflow` — Data Flow Analysis Framework

**Path:** `crates/rustre-analysis-dataflow`
**Status:** COMPLETE — generic lattice framework with multiple classic analyses.

### Purpose

Generic worklist-based forward/backward data flow analyses over CFGs. Provides the
`Lattice` trait, `BitSetLattice<T>`, classic analyses (live variables, reaching
definitions, available expressions, very busy expressions), SSA construction,
def-use/use-def chains, constant propagation, Andersen-style pointer analysis, and
value-range analysis.

### Key Types

| Type | Description |
|------|-------------|
| `Lattice` trait | `join`, `meet`, `bottom`, `top`, `leq` |
| `BitSetLattice<T>` | `HashSet`-backed; join = union, meet = intersection; supports `Top` |
| `DataFlowError` | `NodeNotFound`, `NoConvergence`, `EmptyCfg` |
| `DefUseChains` | Def-use/use-def chain database |
| `LiveInterval` / `LinearScan` | Live range computation for register allocation |
| `ProgramPoint` | Instruction-granular position in the CFG |

### Internal Modules

| Module | Content |
|--------|---------|
| `alias_analysis` | May-alias / must-alias queries |
| `cfg_dom` | Dominator info adapted for data flow |
| `constant_propagation` | Sparse CP over SSA |
| `def_use` / `def_use_analysis` / `du_chains` | Def-use chains, use-def chains, linear-scan live ranges |
| `live_ranges` | Live variable analysis |
| `reaching_definitions` / `reaching_defs` | Two implementations |
| `ssa` | SSA construction (phi placement via dominance frontiers) |
| `value_range` | Interval/range domains |
| `pointer_analysis` | Andersen constraint graph: `AddressOf`, `Assign`, `Load`, `Store`; `WorklistSolver`, `PointsToSets` |
| `ssa_optimizer` | Redundant-phi elimination, copy propagation |
| `available_expressions` | AE bit-set analysis |
| `constant_propagator` | Worklist CP over non-SSA CFG |

### Integration

`rustre-analysis-vsa` builds on the lattice/worklist patterns established here.
`rustre-analysis-cfg`'s dominance frontiers are required for SSA phi placement.
The `def_use` chains are consumed by `rustre-analysis-callconv`'s propagation module.

---

## 7. `rustre-analysis-string` — String Detection

**Path:** `crates/rustre-analysis-string`
**Status:** COMPLETE — multi-encoding scanner with rich classification.

### Purpose

Finds ASCII, UTF-8, UTF-16 LE/BE, UTF-32 LE/BE, Latin-1, and Shift-JIS strings in
raw binary data. Provides a queryable string database, obfuscation/encryption
detection, XOR/ROT/Base64 decoding, string classification (URLs, IPs, emails,
format strings, crypto constants), and edit-distance clustering.

### Key Public API

| Item | Description |
|------|-------------|
| `StringEncoding` | 8-variant enum: Ascii, Utf8, Utf16Le/Be, Utf32Le/Be, Latin1, ShiftJis |
| `StringRecord` | Address, length, encoding, decoded value |
| `StringXref` | `string_xrefs(binary, strings)` — which code addresses reference each string |
| `EncodingDetector` / `EncodingKind` | XOR key candidates, Base64/hex detection |
| `detect_xor_single_byte()` / `xor_decode_single()` / `xor_decode_multibyte()` | XOR decryption |
| `detect_rot13()` / `rot_decode()` | ROT-N decryption |
| `detect_base64()` / `base64_decode()` | Base64 detection and decode |
| `BulkDecryptor` / `StringDecryptionConfig` | Multi-algorithm batch decryption |
| `auto_decrypt(bytes)` | Auto-try all decryption algorithms |
| `StringClassifier` / `StringClass` | `Url`, `Ip`, `Email`, `FormatString`, `CryptoKey`, `Obfuscated`, … |
| `detect_crypto_constant()` / `CryptoConstant` | Known cryptographic constants |
| `ObfuscationSignal` | Entropy and pattern-based obfuscation indicators |
| `shannon_entropy(bytes)` | Information-theoretic byte entropy |
| `levenshtein()` / `jaro_winkler()` / `jaccard_ngram()` | String similarity metrics |
| `cluster_strings()` | Agglomerative clustering of similar strings |
| `extract_template()` | Common prefix/suffix template extraction |
| `StackString` / `reconstruct_stack_strings()` | Stack-built string reconstruction from IL |
| `reconstruct_stack_strings_from_llil()` | LLIL-based stack string recovery |

### Internal Modules

`classify`, `decrypt`, `patterns`, `encoded_string_decoder`, `encoding_detect`,
`similarity`, `stackstring`, `string_deobfuscator`, `string_recovery`, `string_xref`,
`unicode_detector`, `string_clusterer`, `string_decoder`, `string_pattern_library`,
`string_classifier`, `string_obf_detector`, `string_context_extractor`.

---

## 8. `rustre-analysis-type` — Type System and Propagation

**Path:** `crates/rustre-analysis-type`
**Status:** COMPLETE — constraint-based type recovery with union-find.

### Purpose

Recovers C-like types from stripped binaries via constraint collection and
union-find unification. The `TypePropagator` walks the call graph to propagate
argument and return-value types across function boundaries. Includes a builtin
type catalog (WinAPI types, C stdlib signatures).

### Key Types

| Type | Description |
|------|-------------|
| `TypeFact` | `Sized(n)`, `Pointer(Box<Self>)`, `Array{element,length}`, `Struct{fields}`, `SignedInt/UnsignedInt/Float(n)`, `Bool`, `Char`, `Unknown` |
| `TypeError` | `UnificationConflict`, `UnknownVariable`, `CyclicConstraint` |
| `TypeClass` | Abstract type class in the lattice (numeric, pointer, aggregate, …) |
| `TypeLevel` | Refinement level of a type fact in the lattice |
| `RefinementCell` | Mutable cell holding a `TypeFact` with monotone update |
| `TypeRecord` / `BuiltinField` | Entries in the builtin type catalog |

### Key Functions

| Function | Description |
|----------|-------------|
| `lookup_builtin_type(name)` | Look up a WinAPI/stdlib type by name |
| `list_builtin_types()` | Enumerate all registered builtin types |

### Internal Modules

| Module | Content |
|--------|---------|
| `constraints` | Type constraint definitions |
| `inference` | Constraint collection from IL |
| `lattice` | `TypeClass` / `TypeLevel` / `RefinementCell` |
| `primitive_types` | Concrete primitive type representations |
| `propagation` | Inter-function propagation |
| `struct_builder` | Struct shape construction from field accesses |
| `struct_layout_recovery` | Alignment/padding-aware layout recovery |
| `type_inference_engine` | Union-find over type variables |
| `type_inference_full` | Full constraint-based inference pipeline |
| `type_propagation` | Call-graph propagation |
| `vtable` | Vtable-specific type constraints |
| `cpp_type_recovery` | C++ class hierarchy type constraints |
| `interprocedural` | Interprocedural summary types |
| `builtin_catalog` | WinAPI + C stdlib type database |

---

## 9. `rustre-analysis-typerecov` — Type Recovery Pipeline

**Path:** `crates/rustre-analysis-typerecov`
**Status:** COMPLETE — thin pipeline crate composing `analysis-type`.

### Purpose

Three-stage constraint-based type recovery pipeline:
1. **`type_constraint_generator`** — walk the IL (via `iced-x86` for x86 decoding) and
   emit typed constraints.
2. **`type_unifier`** — unify constraints via union-find (wrapping
   `rustre-analysis-type`'s engine).
3. **`struct_recovery_engine`** — recover struct shapes from field accesses.

Also maintains a global `SIGNATURE_REGISTRY: Mutex<HashMap<u64, FunctionSignatureRecord>>`
for per-address signature storage, shared with the binary loading layer.

### Key Types

| Type | Description |
|------|-------------|
| `TypeConstraint` / `ConstraintKind` | Typed constraints emitted from IL walk |
| `TypeConstraintGenerator` | IL walker producing constraints |
| `TypeUnifier` / `UnifyError` / `UnificationResult` | Union-find unification |
| `RecoveredStruct` / `FieldAccess` | Output of struct recovery |
| `StructRecoveryEngine` | Groups field accesses into structs |
| `ArgSpec` | `name: String`, `ty: String` — one recovered argument |
| `Confidence` | `Low`, `Medium`, `High` |
| `InferredSignature` | Full recovered signature: CC, return type, args, confidence |
| `FunctionSignatureRecord` | Optional CC + return type + args stored per address |

### Key Functions

| Function | Description |
|----------|-------------|
| `register_function_signature(addr, record)` | Store a recovered signature |
| `infer_function_signature(addr)` | Retrieve and classify (Low/Medium/High confidence) |

### Confidence Rules

- `High` — calling convention known AND every argument has a concrete (non-Unknown) type.
- `Medium` — only calling convention is known.
- `Low` — neither CC nor any argument type is known.

### Dependencies

`rustre-analysis`, `rustre-analysis-type`, `iced-x86` (for x86 instruction decoding
in the constraint generator), `thiserror`, `serde`.

---

## 10. `rustre-analysis-vsa` — Value Set Analysis

**Path:** `crates/rustre-analysis-vsa`
**Status:** COMPLETE — strided-interval abstract domain with taint analysis.

### Purpose

Over-approximates the set of concrete values at each program point using strided
intervals. Enables pointer analysis, indirect call/jump resolution, out-of-bounds
detection, and taint tracking.

### Key Types

| Type | Description |
|------|-------------|
| `ValueSet` | `Bottom`, `Concrete(Vec<u64>)`, `Range{lo,hi,stride}`, `Top` |
| `VsaError` | `UnknownVariable`, `NoConvergence`, `EmptyProgram` |
| `AbstractPointer` / `PointerRegion` | Abstract pointer with base region |
| `PointerEnvironment` | Map from variables to `AbstractPointer` |
| `PointerAnalysisConfig` / `PointerAnalysisResult` | VSA-based pointer analysis |
| `PointsToSet` / `PtrBlock` / `PtrCfg` / `PtrInstr` | Points-to abstract domain |
| `JumpTableBounds` / `TableImage` | Jump table analysis results |
| `TaintAnalyzer` / `TaintConfig` | Taint propagation engine |
| `TaintLabel` / `TaintSource` / `TaintSink` / `TaintSanitizer` | Taint tagging |
| `TaintState` / `TaintFlow` / `TaintReport` | Taint analysis results |
| `ConstPropState` / `ConstValue` | Constant propagation state interleaved with taint |

### Key Functions

| Function | Description |
|----------|-------------|
| `run_pointer_analysis(cfg, config)` | Full VSA pointer analysis |
| `may_alias(p, q, env)` | May-alias query |
| `must_alias(p, q, env)` | Must-alias query |
| `resolve_indirect_targets(vs)` | Enumerate concrete targets from a `ValueSet` |
| `resolve_switch(vs, bounds)` | Switch/jump table target resolution |
| `bound_jump_table(vs, min, max)` | Bound-check a jump table value set |
| `widen_envs(a, b)` | Join two pointer environments with widening |

### Internal Modules

`abstract_interpretation`, `alias_analysis`, `jumptable`, `pointer`, `value_regions`,
`strided_interval`, `strided_intervals`, `taint`, `value_set_operations`.

### Integration

VSA results are used by `rustre-analysis-cfg` to resolve indirect jumps and by
`rustre-analysis-xref` to find indirect call targets. The taint analysis is exposed
through MCP tools for vulnerability-class detection.

---

## 11. `rustre-analysis-vtable` — C++ Vtable and RTTI Recovery

**Path:** `crates/rustre-analysis-vtable`
**Status:** COMPLETE — both MSVC and Itanium ABI supported.

### Purpose

Recovers C++ virtual dispatch tables and RTTI class hierarchy information. Scans
data sections for pointer arrays pointing into executable sections (vtable heuristic),
decodes both MSVC `__RTTICompleteObjectLocator` and Itanium `__cxa_type_info`
structures, builds an inheritance graph, and resolves virtual dispatch sites.

### Key Types

| Type | Description |
|------|-------------|
| `VtableEntry` | Slot offset + target address + optional function name |
| `Vtable` | Address, class name hint, entries, pointer size |
| `VtableError` | `AddressOutOfRange`, `MalformedRtti`, `UnsupportedPointerSize`, `SectionNotFound`, `InvalidString` |
| `ClassNode` | Node in the inheritance graph |
| `InheritanceGraph` | `petgraph`-backed directed class hierarchy |
| `VirtualDispatchSite` | Call-site + resolved callee set |
| `HierarchyStats` | Depth, fan-out, abstract/concrete class counts |
| `OverrideMap` / `MethodSlot` / `OverrideDiff` | Per-slot virtual method tracking |
| `VtableCluster` / `VirtualSlot` / `SlotMap` | Cluster analysis for vtable similarity |

### Key Functions

| Function | Description |
|----------|-------------|
| `demangle(name)` | Auto-detect and demangle Itanium or MSVC mangled name |
| `demangle_itanium(name)` | Itanium ABI demangling |
| `demangle_msvc(name)` | MSVC ABI demangling |
| `is_itanium_mangled(name)` / `is_msvc_mangled(name)` | ABI detection |
| `build_dispatch_table(graph)` | Build virtual dispatch table from hierarchy |
| `resolve_virtual_dispatch(site, graph)` | Resolve call targets for a virtual call site |
| `compute_hierarchy_stats(graph)` | Summarise the class hierarchy |
| `cluster_vtables(vtables)` | Group vtables by structural similarity |
| `infer_derivations(clusters)` | Infer inheritance from vtable structure |
| `all_slot_overriders(slot, graph)` | All classes that override a given virtual slot |
| `reconstruct_override_chain(slot, class, graph)` | Trace override chain upward |

### Internal Modules

`class_hierarchy`, `rtti_parser`, `virtual_dispatch_analyzer`, `vtable_finder`,
`vtable_reconstructor`, `cluster`, `cpp_class_hierarchy`, `demangler`, `hierarchy`,
`msvc_rtti`, `override_map`, `rtti_recovery`, `virtual_override_map`, `vtable_integrity`,
`vtable_recovery`, `vtable_validator`, `inheritance_grapher`.

---

## 12. `rustre-analysis-xref` — Cross-Reference Analysis

**Path:** `crates/rustre-analysis-xref`
**Status:** COMPLETE — bidirectional xref database with call graph.

### Purpose

Builds and queries cross-references (code-to-code calls/jumps, code-to-data reads/writes,
data pointers, import references, string references, type references). Provides an
x86/x64 byte-level scanner, a bidirectional persistent database, a `petgraph`-backed
xref graph, transitive closure, and call hierarchy reconstruction.

### Key Types

| Type | Description |
|------|-------------|
| `XrefKind` | 13 variants: `CodeCall`, `CodeJump`, `CodeReturn`, `DataRead/Write/Address/Pointer`, `ImportByName/Ordinal`, `StringRef`, `TypeRef`, `ThunkCall` |
| `XrefEntry` / `XrefEntryKind` | Record in the persistent xref index |
| `XrefIndexDb` (re-exported `XrefIndex`) | O(1) bidirectional index; `xrefs_to()`, `xrefs_from()` |
| `XrefDb` / `XrefRecord` / `XrefDbStats` | Full xref database with query/merge |
| `XrefContext` / `XrefQuery` / `XrefMerge` | Query and merge operations |
| `XrefType` | Typed xref classification in the database layer |
| `Region` / `RegionClass` / `RegionMap` | Memory region categorization |
| `CallGraph` / `CallGraphMetrics` | `petgraph`-backed call graph |
| `TransitiveClosure` | Reachability closure over the call graph |
| `XrefQueryEngine` | High-level query engine |

### Key Functions

| Function | Description |
|----------|-------------|
| `extract_all(binary)` | Full extraction: code+data xrefs + import xrefs |
| `extract_code_to_code(binary, sections)` | CALL/JMP scanner in code sections |
| `extract_code_to_data_riprel(binary, sections)` | x86-64 RIP-relative data references |
| `extract_data_pointers(binary)` | Data-section pointer extraction |
| `build_xref_db_from_path(path)` | Load PE binary and build full xref database |
| `add_xref_entry(index, entry)` | Add a typed xref to the persistent index |

### Internal Modules

`call_graph_builder`, `data_flow_xrefs`, `string_xref_finder`, `xref_database`,
`data_xref`, `extract`, `global_xref_analysis`, `import_xref`, `string_xref`,
`transitive_closure`, `xref_graph`, `xref_heuristics`, `xref_query`,
`xref_call_graph`, `xref_query_engine`, `indirect_call_resolver`, `xref_index`,
`call_hierarchy`.

---

## 13. Dependency Graph Summary

```
rustre-core ─────────────────────────────────────────────────────────┐
rustre-il-llil ──────────────────────────────┐                       │
rustre-loader-pe/elf ────────────────┐        │                       │
rustre-flirt-apply ──────────┐       │        │                       │
                              │       │        │                       │
rustre-analysis               │       │        │   (no deps above core)│
  └─ rustre-core              │       │        │                       │
                              │       │        │                       │
rustre-analysis-fn            │       │        │                       │
  ├─ rustre-analysis          │       │        │                       │
  ├─ rustre-loader-pe ────────┘       │        │                       │
  ├─ rustre-loader-elf ───────────────┘        │                       │
  ├─ rustre-core                               │                       │
  ├─ rustre-il-llil ──────────────────────────┘                       │
  └─ rustre-flirt-apply ──────────────────────────────────────────────┘

rustre-analysis-cfg
  ├─ rustre-analysis
  ├─ rustre-core
  └─ rustre-il-llil

rustre-analysis-callconv
  ├─ rustre-analysis
  └─ rustre-core

rustre-analysis-dataflow
  ├─ rustre-analysis
  └─ rustre-core

rustre-analysis-string
  ├─ rustre-analysis
  ├─ rustre-core
  └─ rustre-il-llil

rustre-analysis-type
  ├─ rustre-analysis
  └─ rustre-core

rustre-analysis-typerecov
  ├─ rustre-analysis
  ├─ rustre-analysis-type
  └─ iced-x86

rustre-analysis-vsa
  ├─ rustre-analysis
  └─ rustre-core

rustre-analysis-vtable
  ├─ rustre-analysis
  └─ rustre-core

rustre-analysis-xref
  ├─ rustre-analysis
  ├─ rustre-core
  └─ rustre-loader-pe
```

---

## 14. Implementation Status Matrix

| Crate | Status | Notes |
|-------|--------|-------|
| `rustre-analysis` | COMPLETE | No stubs; all modules populated |
| `rustre-analysis-fn` | COMPLETE | 21 sub-modules; `.pdata` integration |
| `rustre-analysis-cfg` | COMPLETE | Full dominator, loop, reducibility, LT |
| `rustre-analysis-callconv` | COMPLETE | 20+ ABIs; propagation pipeline |
| `rustre-analysis-dataflow` | COMPLETE | SSA, pointer analysis, reaching defs |
| `rustre-analysis-string` | COMPLETE | 8 encodings; XOR/ROT/B64 decryption |
| `rustre-analysis-type` | COMPLETE | Union-find + builtin catalog |
| `rustre-analysis-typerecov` | COMPLETE | 3-stage pipeline; signature registry |
| `rustre-analysis-vsa` | COMPLETE | Strided intervals; taint analysis |
| `rustre-analysis-vtable` | COMPLETE | MSVC + Itanium RTTI; inheritance graph |
| `rustre-analysis-xref` | COMPLETE | 13 xref kinds; O(1) bidirectional index |

All crates use `edition = "2024"` and the workspace `[lints]` table.
No `todo!()` or `unimplemented!()` markers were observed in the lib.rs entry points
of any crate. Inner module bodies should be audited separately for any remaining stubs.

---

## 15. Reverse-Engineering Pipeline Position

The analysis crates occupy the middle tier of the RustRE pipeline:

```
[Binary on disk]
      │
      ▼
[rustre-loader-pe / rustre-loader-elf]   ← parsing & section mapping
      │
      ▼
[rustre-core BinaryView]
      │
      ▼
[rustre-il-llil lifter]                  ← x86/ARM → LLIL
      │
      ▼
[rustre-analysis-fn]                     ← function boundary detection
      │
      ▼
[rustre-analysis-cfg]                    ← per-function CFG
      │
      ├──→ [rustre-analysis-dataflow]    ← SSA / reaching defs / CP
      │
      ├──→ [rustre-analysis-callconv]    ← ABI identification
      │
      ├──→ [rustre-analysis-string]      ← string recovery
      │
      ├──→ [rustre-analysis-vsa]         ← value set / taint
      │
      ├──→ [rustre-analysis-type]        ← type facts
      │         └──→ [rustre-analysis-typerecov]  ← signature recovery
      │
      ├──→ [rustre-analysis-vtable]      ← C++ vtable / RTTI
      │
      └──→ [rustre-analysis-xref]        ← cross-references / call graph
                    │
                    ▼
             [rustre-mcp-server]         ← MCP tool surface exposed to LLM
```

The entire subsystem is surfaced through `rustre-mcp-server` as MCP tools, where
each analysis domain maps to one or more MCP tool categories
(function list, CFG query, xref query, string list, type recovery, vtable list, etc.).
