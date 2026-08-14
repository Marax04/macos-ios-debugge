# rustre-analysis-vsa

## Scopo
Value Set Analysis (VSA) per la suite RustRE. Sopra-approssima l'insieme dei valori concreti che ciascuna variabile/registro puo' assumere in ogni punto del programma, usando strided intervals `[lo, hi] / stride`. Abilita:

- Pointer analysis (Andersen-style, regioni Stack/Heap/Global/Code).
- Resolution di indirect call e jump table (switch).
- Detection di out-of-bounds e buffer overflow.
- Taint analysis + constant propagation.
- Memoria astratta con strong/weak update.
- Region analysis (mod/ref summaries).
- Fixpoint dataflow con widening/narrowing.

Dipende da `rustre-analysis` e `rustre-core`. Usa `petgraph` per i grafi (points-to / region).

## Moduli pubblici
- `abstract_interpretation` - trait `AbstractDomain`, `ConstantDomain`, `IntervalDomain`, `SignDomain`, `Fixpoint`, `TransferFunction`.
- `alias_analysis` - Andersen-style points-to: `AndersenSolver`, `PointsToGraph`, `AliasResult`, `query_alias`, `may_alias`, `must_alias`, `classify_pointer`, `is_stack_only`, `is_heap_only`, `is_global_only`, `different_regions`, `PtrArithTracker`.
- `jumptable` - `bound_jump_table`, `resolve_indirect_targets`, `resolve_switch`, `scale`, `offset`, `widen`, `JumpTableBounds`, `TableImage`.
- `pointer` - `AbstractPointer`, `PointerEnvironment`, `PointsToSet`, `PointerRegion`, `run_pointer_analysis`, `ptr_add`, `ptr_sub`, `may_alias`, `must_alias`, `widen`, `widen_envs`, `PtrCfg/Block/Instr`.
- `value_regions` (alias `region_analysis`) - `Region`, `RegionId`, `RegionKind`, `RegionGraph`, `RegionAnalysis`, `AccessPath`, `ModRefInfo`, `RegionSummary`.
- `strided_interval` - enum `StridedInterval`, `WideningThresholds`.
- `strided_intervals` - struct `StridedInterval`, `WrappedInterval`, `ValueSet`, `IntervalAnalysis`, `si_add/sub/mul/and/or/xor/shl/shr`, `widen`, `narrow`.
- `taint` - `TaintLabel`, `TaintValue`, `TaintState`, `TaintSource/Sink/Sanitizer`, `TaintConfig`, `TaintAnalyzer`, `TaintFlow`, `TaintReport`, `ConstValue`, `ConstPropState`, `TaintStatistic`.
- `value_set_operations` - `run_vsa`, `AbstractInterpreter`, `AbstractMemory`, `FunctionSummary`, `SummaryDatabase`, `refine_lt`, `refine_geq`, `VsaResult`, `VsaStats`.

## Tipi/funzioni pubbliche chiave (lib.rs)
- `ValueSet`: enum `Bottom | Concrete(Vec<u64>) | Range{lo,hi,stride} | Top`.
  - Costruttori: `singleton`, `top`, `bottom`, `interval`, `strided`.
  - Lattice: `join`, `meet`, `widen`, `leq`, `contains`, `is_top`, `is_bottom`.
  - Aritmetica: `add`, `sub`, `bitwise_and`, `bitwise_or` (wrapping u64).
  - `concretize(limit) -> Option<Vec<u64>>`.
- `VsaState { vars: HashMap<String, ValueSet> }`: `new/get/set/join/leq/widen`.
- `VsaInstr`: `Const|Copy|Add|Sub|And|Or|Load|Store|Phi|IndirectCall`.
- `VsaBlock { id, instrs }`, `VsaCfg { blocks, successors, predecessors, entry }::new`.
- `MemoryModel`: cells `Vec<(ValueSet, ValueSet)>`, `store/load`, cap `MAX_CELLS = 65_536`.
- `VsaAnalyzer { initial_state }`: `new`, `transfer(block, state, mem)`, `run(cfg) -> Result<Vec<VsaState>, VsaError>` (worklist + widening soglia 3 visite, iter cap 100k, blocks cap 1M).
- `AddressClass { Stack|Heap|Global|ReadOnly|Code|Unknown }` + `AddressClassifier::{classify_addr, classify}`.
- `IndirectCallResolver { states, classifier }::resolve(cfg) -> Vec<IndirectCallResolution{block_id,target_var,resolved_targets,is_imprecise}>`.
- `StridedInterval` (struct, separata): `BOTTOM/TOP`, `new`, `singleton`, `interval`, `is_bottom/top/singleton`, `contains`, `join/meet/widen`, `add/sub/bitwise_and/bitwise_or`, `concretize`.
- `is_definitely_null(&StridedInterval) -> bool`.
- `may_be_out_of_bounds(&StridedInterval, (base,limit)) -> bool`.
- `MemoryAbstraction`: cells `Vec<(StridedInterval, StridedInterval)>`, `store/load/join/leq/cell_count`, cap `MAX_CELLS = 65_536`.
- `RegisterState { regs }`: `get/set/join/widen/leq`.
- `VsaEngine` + `VsaEngineCfg/Block/Instr`, `VsaConfig`, `VsaEngineResult`, `VsaEngineV2`, `VsaTransfer`, `VsaAnalysisPass`.
- Lifting da LLIL: `LlilExpr`, `LlilInstruction`, `LlilBlock`, `LlilCfg`.
- API consumer-level:
  - `resolve_jump_table(...)`
  - `resolve_indirect_calls(...)`
  - `detect_buffer_overflows(...)`
  - `query_point(result, addr, target) -> PointQueryResult { PointValue, PointConfidence }`
  - `strided_interval_to_value_set(si) -> ValueSet`
- Memory binary: `trait BinaryMemory: Send + Sync`, `MapBinaryMemory(HashMap<u64,u8>)`, `MemRegionId`, `RegionValueSet`, `VsaStateV2`, `JumpTableInfo`.
- Errors: `VsaError::{UnknownVariable, NoConvergence, EmptyProgram}`.

## Input / Output
- Input principale: `VsaCfg` o `VsaEngineCfg` (CFG di basic block con `VsaInstr`/lift LLIL), opzionale `AddressClassifier` con range Stack/Heap/Global/RO/Code, opzionale `BinaryMemory` per leggere costanti dal binario.
- Output: vettore di `VsaState`/`VsaStateV2` per block entry, `IndirectCallResolution[]`, `JumpTableInfo`, points-to graph, taint `TaintReport`, region summaries.
- Errori: `VsaError`.

## Ground truth verificabile esternamente
1. **Algebra strided-interval / lattice laws**: join e' lub, meet e' glb, widen termina ascendenti. Verificabile con property-test (proptest/quickcheck) e confronto con implementazioni di riferimento (BAP `Bap.Std.Bil`, angr `claripy` SI, Jakstab strided-interval domain).
2. **Indirect call resolution**: su binari con switch table noti (es. clang/gcc dense switch), confrontare `resolve_indirect_targets` / `resolve_jump_table` vs Ghidra "Switch table analyzer", IDA Pro "jump table from indirect", Binary Ninja `MediumLevelILIndirectBranch` resolution. Esempi standard: coreutils `ls.c` parser, sqlite VDBE dispatch.
3. **Points-to / alias**: confronto vs LLVM `-aa-eval` (CFLAA / BasicAA), SVF / PAG, IDA Hex-Rays microcode. Suite test: SPEC CPU, NIST Juliet C/C++.
4. **Taint flow**: confronto su Juliet CWE-78/89/120 vs LibFuzzer/SymCC/AFL++ taint, libdft64, Triton.
5. **Buffer overflow / OOB**: NIST Juliet CWE-121/122/124/126/127. Confronto vs CodeQL `cpp/unsafe-strcat`, Coverity, Klee.
6. **Constant propagation / interval refinement**: confronto vs Souffle/IFDS, GCC `-fdump-tree-vrp`, LLVM `-passes=ipsccp,early-cse`.
7. **Determinismo**: stesso CFG -> stesso output (no HashMap order dipendenza in serializzazione). Verificabile con snapshot test.

## Tool MCP esistenti correlati
Nel server `rustre-mcp` (vedi `mcp__rustre-mcp__*`) NON c'e' un tool VSA dedicato. Tool correlati che potrebbero usare/esporre questa crate:

- `analysis_trace_data_flow_path` / `trace_data_flow` - flow tracking (taint-like).
- `analysis_xref_call_graph*`, `analysis_xref_callees` - risoluzione indiretti grezza (non VSA).
- `analysis_recover_structs_path`, `analysis_infer_types_path` - usano pointer/region info.
- `analysis_fn_cfg_path`, `analysis_loops_path`, `analysis_dominators_path` - CFG su cui VSA opera.
- `decompiler_stack_frame_report` - consumatore naturale di region/alias.
- `noreturn_infer` - consumatore di constant propagation.

Tool MCP comparabili in altri server: IDA `mcp__ida-pro-mcp__trace_data_flow`, `analysis_basic_blocks_path`; Ghidra `mcp__ghidra__decompile_function` (Hex-Rays/Decompiler hanno VSA interno).

**Gap**: nessun tool MCP espone direttamente `run_vsa`, `resolve_jump_table`, `resolve_indirect_calls`, `detect_buffer_overflows`, `query_point`, `TaintAnalyzer`. Buon candidato per nuovi endpoint MCP.

## Testabilita'
Si. Esiste `tests/` nella crate. Le API sono pure (CFG in, stati/risoluzioni out), idonee a:
- property-based testing su lattice/aritmetica.
- snapshot test su CFG sintetici.
- corpus benchmark (Juliet, coreutils) per ground truth esterna.
