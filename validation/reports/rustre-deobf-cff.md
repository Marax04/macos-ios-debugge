# rustre-deobf-cff — Public API

Control Flow Flattening (CFF) deobfuscation pass: detects CFF-protected functions, recovers original CFG, supports OLLVM/Hikari patterns, state-machine recovery, dispatcher rewriting, SMT-backed symbolic eval, and dataflow-based constant propagation.

## lib.rs (top-level)

### Types
- `enum StateVariable { Register(String), StackSlot(i32), GlobalMemory(Address), Unknown }` — location of CFF state var.
- `enum CffPattern { Dispatcher, JumpTable, LinearSearch, NestedDispatch, Unknown }` — dispatcher classification.
- `struct CffCandidate` — detected CFF candidate (function_start, dispatcher_address, state_variable, block_count, confidence, pattern).
- `struct BlockMapping` — bidirectional `state ↔ block` map (AHashMap).
- `enum RecoveredEdgeType { Unconditional, TrueBranch, FalseBranch, CallReturn }`
- `struct RecoveredEdge` — reconstructed CFG edge with optional `state_value`.
- `struct RecoveredCfg` — de-flattened CFG.
- `enum EdgeType { Unconditional, TrueBranch, FalseBranch }`
- `struct SimpleBb` — architecture-agnostic basic block.
- `struct SimpleCfg { blocks, edges }` — simplified CFG.
- `struct CffDetector` — detection tunables.
- `struct CffRecoverer` — recovery tunables.
- `enum ConstLattice { Top, Const(u64), Bottom }` — constant-propagation lattice.
- `struct CffVerifyResult` — verification statistics.
- `struct CffVerifier` — validates RecoveredCfg.
- `struct DeobfResult` — aggregate pass result.
- `struct CffDeobfuscationPass { detector, recoverer }` — high-level entry point.
- `struct CffDispatcher` — raw-bytes-detected dispatcher (addr, state_var_addr, handler_count).
- `struct CffDispatcherDetector` (`const MIN_HANDLER_COUNT: u32 = 5`).
- `struct StateGraph` — state-transition graph (u32 ids).
- `struct StateTransitionAnalyzer`, `struct CfgEdge`, `struct CffDeflattener`.
- `enum SmtSort`, `struct SmtVar`, `struct SmtConstraintBuilder`.
- `enum MlilInstruction`, `struct BasicBlock` (MLIL), `enum AssignmentType`, `struct ZStateTransition`, `enum DispType`, `struct DispatcherBlock`.
- `struct CffSymEval` — symbolic state evaluator.
- `struct MlilFunction`, `struct CfgRewriter`.
- `struct CffScore`, `struct DispatcherCandidate`, `struct CffAnalysis`, `struct OllvmDetectorV2`.

### Methods / functions

**BlockMapping**
- `new() -> Self`
- `insert(&mut self, state: u64, block: Address)`
- `block_for_state(&self, state: u64) -> Option<Address>`
- `states_for_block(&self, addr: Address) -> &[u64]`
- `block_count(&self) -> usize`
- `is_complete(&self) -> bool` — every state resolves to a known block.

**RecoveredCfg**
- `successors(&self, addr: Address) -> Vec<Address>`
- `predecessors(&self, addr: Address) -> Vec<Address>`
- `is_entry(&self, addr: Address) -> bool`
- `block_count(&self) -> usize`
- `edge_count(&self) -> usize`

**SimpleCfg**
- `recompute_predecessor_counts(&mut self)` — re-derive predecessor counts from edge list.

**CffDetector**
- `new() -> Self`
- `with_min_blocks(self, n: usize) -> Self`
- `with_min_confidence(self, c: f64) -> Self`
- `detect(&self, cfg: &SimpleCfg, function_start: Address) -> Option<CffCandidate>` — main detection.
- `find_dispatcher(&self, cfg: &SimpleCfg) -> Option<(usize, f64)>` — dispatcher index + preliminary confidence.
- `compute_confidence(&self, cfg: &SimpleCfg, dispatcher_idx: usize) -> f64` — weighted score in `[0,1]`.
- `identify_state_variable(&self, cfg: &SimpleCfg, dispatcher_idx: usize) -> StateVariable`

**CffRecoverer**
- `new() -> Self`
- `recover(&self, candidate: &CffCandidate, cfg: &SimpleCfg) -> RecoveredCfg` — full de-flattening.
- `build_block_mapping(&self, candidate: &CffCandidate, cfg: &SimpleCfg) -> BlockMapping`
- `scan_block_state_const(bytes: &[u8]) -> Option<u64>` — scan raw x86 for last `MOV reg, imm` before terminator.
- `trace_state(&self, state: u64, mapping: &BlockMapping) -> Option<Address>`
- `reconstruct_edges(&self, candidate, mapping, cfg) -> Vec<RecoveredEdge>`
- `fold_state_expr(value: u64, mapping: &BlockMapping) -> Option<u64>`
- `recover_with_dataflow(&self, candidate: &CffCandidate, cfg: &SimpleCfg) -> RecoveredCfg` — dataflow-backed variant.

**ConstLattice**
- `meet(self, other: ConstLattice) -> ConstLattice`
- `as_const(self) -> Option<u64>`

**StateVarTracker** (extended in lib.rs)
- `propagate_dataflow(&mut self, cfg: &SimpleCfg, dispatcher_addr: Address) -> AHashMap<u64, ConstLattice>` — worklist constant propagation.

**CffVerifyResult**
- `is_clean(&self) -> bool`

**CffVerifier**
- `new() -> Self`
- `verify(&self, recovered: &RecoveredCfg) -> CffVerifyResult` — structural soundness check.

**CffDeobfuscationPass**
- `new() -> Self`
- `run_on_function(&self, cfg: &SimpleCfg, function_start: Address) -> Option<RecoveredCfg>`
- `run_on_binary(&self, cfgs: Vec<(Address, SimpleCfg)>) -> DeobfResult`

**CffDispatcherDetector**
- `new() -> Self`
- `detect(code: &[u8], base: u64) -> Vec<CffDispatcher>` — scan raw bytes for compare-branch runs.

**StateGraph**
- `new() -> Self`
- `add_edge(&mut self, from: u32, to: u32, condition: Option<bool>)`
- `transitions(&self, state: u32) -> &[(u32, Option<bool>)]`
- `state_count(&self) -> usize`
- `is_empty(&self) -> bool`
- `all_targets(&self) -> HashSet<u32>`

**StateTransitionAnalyzer**
- `new() -> Self`
- `analyze(dispatcher: &CffDispatcher, code: &[u8]) -> StateGraph`

**CffDeflattener**
- `new() -> Self`
- `deflaten(dispatcher: &CffDispatcher, state_graph: &StateGraph) -> Vec<CfgEdge>`
- `estimate_cff_confidence(code: &[u8]) -> f32`

**SmtSort**
- `to_smtlib2(&self) -> String`

**SmtVar**
- `bitvec(name: impl Into<String>, bits: u32) -> Self`
- `bool_var(name: impl Into<String>) -> Self`
- `declaration(&self) -> String`

**SmtConstraintBuilder**
- `new() -> Self`
- `declare_var(&mut self, name: &str, bits: u32) -> String`
- `declare_bool(&mut self, name: &str) -> String`
- `assert_eq(&mut self, var: &str, val: u64, bits: u32)`
- `assert_expr_eq(&mut self, expr: &str, val: u64, bits: u32)`
- `add_assertion(&mut self, assertion: &str)`
- `to_smtlib2(&self) -> String`
- `solve_with_subprocess(&mut self) -> Option<HashMap<String, u64>>` — invokes Z3.
- `solve_concrete(&self, env: &HashMap<String, u64>) -> bool`
- `parse_z3_model(output: &str) -> HashMap<String, u64>`

**BasicBlock (MLIL)**
- `new(address: u64) -> Self`
- `push(&mut self, instr: MlilInstruction)`
- `terminator(&self) -> Option<&MlilInstruction>`

**DispatcherBlock (MLIL)**
- `new(address: u64, dispatch_type: DispType) -> Self`
- `add_case(&mut self, state_value: u64, target: u64)`
- `resolve(&self, state_value: u64) -> Option<u64>`
- `case_count(&self) -> usize`

**CffSymEval**
- `new(state_var: impl Into<String>, initial: u64) -> Self`
- `eval_block_transitions(...)` — symbolic execution of state transitions per block.
- `solve_dispatcher_mapping(&self, dispatcher: &DispatcherBlock) -> HashMap<u64, u64>`
- `find_state_var_assignments(&self, bb: &BasicBlock) -> Vec<(u32, AssignmentType)>`

**MlilFunction**
- `new(entry: u64) -> Self`
- `add_block(&mut self, bb: BasicBlock)`
- `add_edge(&mut self, from: u64, to: u64, is_true_branch: bool)`
- `block_at(&self, addr: u64) -> Option<&BasicBlock>`
- `block_at_mut(&mut self, addr: u64) -> Option<&mut BasicBlock>`
- `successors_of(&self, addr: u64) -> Vec<u64>`
- `predecessors_of(&self, addr: u64) -> Vec<u64>`
- `block_count(&self) -> usize`
- `edge_count(&self) -> usize`

**CfgRewriter**
- `rewrite_cff_cfg(...)` — apply recovered edges to MlilFunction.
- `eliminate_dead_blocks(...)`
- `eliminate_state_variable(func: &mut MlilFunction, state_var: &str) -> u32`

**CffScore**
- `is_likely_cff(&self) -> bool`

**OllvmDetectorV2**
- `score_function(func: &MlilFunction) -> CffScore`
- `find_dispatcher_candidates(func: &MlilFunction) -> Vec<DispatcherCandidate>`
- `verify_cff_structure(...)`

---

## ollvm.rs

- `struct OllvmSignature` — OLLVM detection result.
- `struct OllvmDetector`
  - `new() -> Self`
  - `with_min_back_edges(self, n: usize) -> Self`
  - `detect(&self, cfg: &SimpleCfg, function_start: Address) -> Option<OllvmSignature>`
- `struct StateAssignment`
- `struct StateVarTracker`
  - `new() -> Self`
  - `record(&mut self, block: Address, value: u64, is_conditional: bool)`
  - `blocks_for_state(&self, value: u64) -> &[Address]`
  - `all_states(&self) -> Vec<u64>`
  - `is_empty(&self) -> bool`
  - `merge(&mut self, other: Self)`
  - `to_block_mapping(&self) -> BlockMapping`
  - `writer_count(&self) -> usize`
- `struct SubDispatcherMap`
  - `new() -> Self`
  - `add(&mut self, parent: Address, sub: Address)`
  - `parent_of(&self, sub: Address) -> Option<Address>`
  - `is_sub_dispatcher(&self, addr: Address) -> bool`
  - `sub_count(&self) -> usize`
- `struct OllvmPatch`
  - `nop_out(address: Address, size: usize, description: impl Into<String>) -> Self`
  - `make_unconditional(address: Address, target: Address) -> Self`
- `fn patch_cff_function(candidate: &CffCandidate, recovered: &RecoveredCfg) -> Vec<OllvmPatch>` — emit binary patches.
- `struct OllvmDeobfResult`
- `struct OllvmDeobfuscationPass`
  - `new() -> Self`
  - `run_on_function(...)`
  - `run_on_binary(&self, cfgs: Vec<(Address, SimpleCfg)>) -> OllvmDeobfResult`

---

## vm_handler_analyzer.rs

VM/handler analysis for VM-protected binaries.

- `enum VmError`
- `enum HandlerSemantics`
  - `is_control_flow(&self) -> bool`
  - `is_memory_op(&self) -> bool`
  - `is_arithmetic(&self) -> bool`
- `struct VmReg`
  - `new(name: impl Into<String>, offset: i32, size: u8) -> Self`
- `struct VmHandler`
  - `new(addr: u64, opcode: u8) -> Self`
- `struct VmDispatchLoop`
- `struct LiftedOp`
- `enum LiftedOperand`
- `struct VmLiftedProgram`
  - `op_count(&self) -> usize`
  - `unique_opcodes(&self) -> Vec<u8>`
  - `control_flow_ops(&self) -> Vec<&LiftedOp>`
- `struct RawInstruction`
  - `new(addr: u64, mnemonic: impl Into<String>) -> Self`
- `struct VmHandlerAnalyzer`
  - `new() -> Self`
  - `add_block(&mut self, addr: u64, insns: Vec<RawInstruction>)`
  - `set_dispatch_table(&mut self, table: HashMap<u8, u64>)`
  - `add_vm_reg(&mut self, reg: VmReg)`
  - `identify_dispatch_loop(&self) -> Result<VmDispatchLoop, VmError>`
  - `extract_handlers(&self, max_insns: usize) -> Result<HashMap<u8, VmHandler>, VmError>`
  - `lift_handler_to_semantics(...)`
  - `lift_bytecode_trace(...)`
  - `build_lifted_program(...) -> VmLiftedProgram`

---

## state_variable_recovery.rs

- `type StateValue = u64`
- `struct CffBlock`
  - `new(address: Address, end_address: Address) -> Self`
  - `size(&self) -> u64`
  - `is_routing_only(&self) -> bool`
- `struct StateTransition`
- `struct StateMapping`
  - `new() -> Self`
  - `add(&mut self, state: StateValue, block: Address)`
  - `coverage(&self, total_states: usize) -> f32`
- `struct StateVariableRecoveryResult`
  - `new() -> Self`
  - `legitimate_transition_count(&self) -> usize`
- `struct StateVariableRecoverer`
  - `new() -> Self`
  - `with_min_confidence(self, t: f32) -> Self`
  - `identify_dispatcher<'a>(&self, blocks: &'a [CffBlock]) -> Option<&'a CffBlock>`
  - `identify_state_var(&self, blocks: &[CffBlock]) -> StateVariable`
  - `extract_state_values(&self, blocks: &[CffBlock]) -> Vec<StateValue>`
  - `build_transitions(&self, blocks: &[CffBlock]) -> Vec<StateTransition>`
  - `compute_predecessors(...)`
  - `build_state_mapping(...) -> StateMapping`
  - `filter_obfuscated_transitions<'a>(...)`
  - `recover(&self, blocks: &[CffBlock]) -> StateVariableRecoveryResult`

---

## state_machine_recovery.rs

- `struct StateVariable` (local)
  - `new(name: impl Into<String>, initial_value: u64) -> Self`
  - `with_frame_offset(self, off: i32) -> Self`
- `struct State`
  - `new(id: u64) -> Self`
- `struct Transition`
- `enum TransitionCondition`
- `struct StateMachine`
  - `new() -> Self`
  - `add_state(&mut self, state: State) -> u64`
  - `add_transition(&mut self, t: Transition)`
  - `successors(&self, state_id: u64) -> Vec<u64>`
  - `predecessors(&self, state_id: u64) -> Vec<u64>`
  - `state_count(&self) -> usize`
  - `transition_count(&self) -> usize`
  - `to_dot(&self) -> String`
  - `validate(&self) -> Vec<String>`
- `struct TransitionMap`
  - `from_machine(sm: &StateMachine) -> Self`
  - `get(&self, state_id: u64) -> &[Transition]`
  - `sources(&self) -> impl Iterator<Item = u64>`
  - `len(&self) -> usize`
  - `is_empty(&self) -> bool`
- `struct StructuredState`
- `enum HighLevelStructure` — Sequence/Loop/IfElse/Switch.
- `struct StateElimination`
  - `eliminatable_states(sm: &StateMachine) -> HashSet<u64>`
  - `apply(sm: &mut StateMachine) -> usize`
- `struct StateGraphExport`
  - `to_dot(sm: &StateMachine) -> String`
  - `to_json(sm: &StateMachine) -> String`
  - `to_mermaid(sm: &StateMachine) -> String`
- `struct StateMachineRecovery`
  - `new() -> Self`
  - `recover_from_pairs(...) -> StateMachine`
  - `annotate(&self, sm: &StateMachine) -> Vec<StructuredState>`
  - `reachable_states(&self, sm: &StateMachine) -> HashSet<u64>`

---

## state_machine_extractor.rs

- `type StateValue = u64`
- `enum StateAssignment`
- `struct StateMapping`
  - `new() -> Self`
  - `insert(&mut self, state_val: StateValue, block_id: u64)`
  - `block_for(&self, state_val: StateValue) -> Option<u64>`
  - `state_for_block(&self, block_id: u64) -> Option<StateValue>`
  - `len(&self) -> usize`
  - `is_empty(&self) -> bool`
- `struct StateTransition`
  - `is_conditional(&self) -> bool` (const)
  - `is_terminal(&self) -> bool` (const)
- `struct FlatBlock`
  - `new(id: u64) -> Self` (const)
- `struct FlatFunction`
  - `new(dispatcher_id: u64, entry_id: u64, entry_state: StateValue) -> Self`
  - `add_block(&mut self, block: FlatBlock)`
- `struct RecoveredBlock`
- `struct RecoveredCfg` (extractor-specific)
  - `block_count(&self) -> usize`
  - `edge_count(&self) -> usize`
  - `bfs_order(&self) -> Vec<u64>`
  - `is_dag(&self) -> bool`
- `struct CffStateMachine`
  - `state_count(&self) -> usize` (const)
  - `transition_count(&self) -> usize` (const)
  - `is_deterministic(&self) -> bool`
- `struct StateMachineExtractor`
  - `new() -> Self` (const)
  - `extract(&self, func: &FlatFunction) -> RecoveredCfg`
  - `build_state_machine(&self, func: &FlatFunction) -> CffStateMachine`
  - `state_machine_to_cfg(&self, sm: &CffStateMachine, func: &FlatFunction) -> RecoveredCfg`
  - `reachable_states(&self, sm: &CffStateMachine) -> HashSet<StateValue>`

---

## flattening_detector.rs

- `type BlockId = u64`
- `struct BasicBlock`
  - `new(id: BlockId) -> Self` (const)
  - `out_degree(&self) -> usize` (const)
  - `in_degree(&self) -> usize` (const)
- `struct SimpleCfg` (local)
  - `new() -> Self`
  - `add_block(&mut self, block: BasicBlock)`
  - `add_edge(&mut self, from: BlockId, to: BlockId)`
  - `block_count(&self) -> usize`
  - `max_out_degree(&self) -> usize`
  - `highest_out_degree_block(&self) -> Option<&BasicBlock>`
  - `reachable_from(&self, start: BlockId) -> usize`
  - `dominators(&self, entry: BlockId) -> HashMap<BlockId, HashSet<BlockId>>`
- `struct StateVarCandidate`
  - `new(name: impl Into<String>) -> Self`
  - `compute_confidence(&mut self)`
- `struct DispatcherBlock`
- `enum CffScheme`
- `struct FlatteningScore`
  - `is_flattened(&self) -> bool` (const)
  - `label(&self) -> &'static str`
- `struct FlatteningReport`
  - `is_obfuscated(&self) -> bool` (const)
- `struct FlatteningDetector`
  - `new() -> Self` (const)
  - `analyse(&self, cfg: &SimpleCfg) -> FlatteningReport`

---

## dispatcher_rewriter.rs

- `struct BasicBlock`
  - `new(addr: u64) -> Self` (const)
- `struct Cfg`
  - `new(entry: u64) -> Self`
  - `add_block(&mut self, block: BasicBlock)`
  - `add_edge(&mut self, from: u64, to: u64)`
  - `remove_edge(&mut self, from: u64, to: u64)`
  - `edges(&self) -> Vec<(u64, u64)>`
  - `reachable_from_entry(&self) -> HashSet<u64>`
- `enum RewriteAction`
- `struct RewriteResult`
  - `new() -> Self`
  - `add_action(&mut self, action: RewriteAction)`
- `struct CfgSnapshot`
  - `capture(cfg: &Cfg) -> Self`
- `struct DispatcherRewriter`
  - `new() -> Self` (const)
  - `find_dispatcher_blocks(&self, cfg: &Cfg) -> Vec<u64>`
  - `find_state_blocks(&self, cfg: &Cfg, dispatcher_addr: u64) -> Vec<u64>`
  - `remove_dispatcher_block(...)`
  - `inline_state_sequence(&self, cfg: &Cfg) -> RewriteResult`
  - `apply_actions(&self, cfg: &mut Cfg, actions: &[RewriteAction]) -> bool`
  - `validate_result(&self, cfg: &Cfg) -> Vec<String>`
  - `diff_snapshots(...)`

---

## dispatcher_analysis.rs

- `struct Addr(pub u64)` — local address newtype
  - `new(v: u64) -> Self` (const)
  - `as_u64(self) -> u64` (const)
- `struct CaseTransition`
  - `new(state_value: u64, target_block: Addr) -> Self` (const)
  - `with_loop_back(self) -> Self` (const)
  - `with_confidence(self, c: u8) -> Self`
- `struct StateWrite`
  - `constant(instr_addr: Addr, value: u64, location: impl Into<String>) -> Self`
  - `unknown(instr_addr: Addr, location: impl Into<String>) -> Self`
- `struct StateVariableTracker`
  - `new() -> Self`
  - `record(&mut self, block_addr: Addr, value: u64, is_propagated: bool)`
  - `record_unknown(&mut self, block_addr: Addr)`
  - `resolved_value(&self, block_addr: Addr) -> Option<u64>`
  - `resolved_count(&self) -> usize`
  - `is_resolved(&self, block_addr: Addr) -> bool`
  - `constant_writes(&self) -> Vec<&StateWrite>`
  - `propagate_simple(&mut self, edges: &[(u64, u64)])`
- `struct DispatcherBlock`
  - `new(address: Addr, state_var_location: impl Into<String>) -> Self`
  - `add_case(&mut self, transition: CaseTransition)`
  - `case_for_state(&self, state: u64) -> Option<&CaseTransition>`
  - `loop_back_cases(&self) -> Vec<&CaseTransition>`
  - `average_case_confidence(&self) -> f64`
  - `sync_case_count(&mut self)` (const)
- `struct DispatcherGraph`
  - `new() -> Self`
  - `add_dispatcher(&mut self, db: DispatcherBlock)`
  - `target_for(&self, dispatcher: Addr, state: u64) -> Option<Addr>`
  - `unique_target_count(&self) -> usize`
  - `sorted_dispatcher_addrs(&self) -> Vec<Addr>`
  - `total_cases(&self) -> usize`
  - `is_empty(&self) -> bool`
  - `busiest_dispatcher(&self) -> Option<&DispatcherBlock>`
- `struct FlattenedRegion`
  - `new(dispatcher: Addr) -> Self` (const)
  - `add_block(&mut self, addr: Addr)`
  - `add_edge(&mut self, from: Addr, to: Addr)`
  - `note_unresolved(&mut self)` (const)
  - `recovery_rate(&self) -> f64`
  - `is_fully_recovered(&self) -> bool` (const)
- `struct DispatcherAnalysis`
  - `new() -> Self`
  - `with_min_back_edges(self, n: usize) -> Self` (const)
  - `analyze(...)`
- `struct StateVarCandidate`
  - `new(register: impl Into<String>, write_count: usize, cmp_count: usize) -> Self`
  - `is_strong(&self) -> bool` (const)
- `struct StateVariableCandidateFinder`
  - `new() -> Self` (const)
  - `rank(...) -> Vec<StateVarCandidate>`
  - `top_candidate(...) -> Option<...>`
- `struct BackEdge`
- `struct BackEdgeAnalyzer`
  - `find_back_edges(entry: Addr, adj: &HashMap<Addr, Vec<Addr>>) -> Vec<BackEdge>`
  - `back_edge_count_map(back_edges: &[BackEdge]) -> HashMap<Addr, usize>`
- `struct DispatcherQualityScorer`
- `struct DispatcherQuality`
  - `score(&self, graph: &DispatcherGraph, regions: &[FlattenedRegion]) -> DispatcherQuality`
- `struct CaseRangeAnalyzer`
- `struct CaseRange`
  - `analyze(db: &DispatcherBlock) -> CaseRange`

---

## cfg_reconstruction.rs

- `enum BlockKind`
- `struct AnnotatedBlock`
  - `new(address: Address, end_address: Address) -> Self` (const)
  - `size(&self) -> u64` (const)
- `struct ReconstructedCfg`
  - `empty(entry: Address) -> Self` (const)
  - `block_count(&self) -> usize` (const)
  - `edge_count(&self) -> usize`
  - `block(&self, addr: Address) -> Option<&AnnotatedBlock>`
  - `predecessors_of(&self, addr: Address) -> Vec<Address>`
- `struct RawBlock`
  - `size(&self) -> u64` (const)
  - `is_likely_routing(&self) -> bool` (const)
  - `is_likely_dispatcher(&self) -> bool` (const)
- `struct CfgReconstructor`
  - `new() -> Self` (const)
  - `with_min_confidence(self, t: f64) -> Self` (const)
  - `reconstruct(&self, raw_blocks: &[RawBlock]) -> ReconstructedCfg`
  - `reconstruct_simple(...) -> ReconstructedCfg`

---

## cff_state_machine.rs

- `enum SmError`
- `enum StateMachinePattern`
- `struct DispatcherInfo`
- `struct StateBlock`
- `struct CffReport`
- `struct BasicBlock`
- `struct DispatchRead`
  - `new(addr: u64) -> Self` (const)
- `struct CffStateMachine`
  - `new() -> Self`
  - `with_min_cases(self, n: usize) -> Self` (const)
  - `add_block(&mut self, block: BasicBlock)`
  - `detect_dispatcher(&self) -> Result<DispatcherInfo, SmError>`
  - `extract_state_variable(&self, dispatcher_addr: u64) -> Option<DispatchRead>`
  - `build_state_transition_graph(...)`
  - `compute_state_sequence(...)`
  - `build_state_blocks(&self, dispatcher: &DispatcherInfo) -> Vec<StateBlock>`
  - `analyse(&self) -> CffReport`
- `fn compute_predecessors<S: BuildHasher>(...)`
- `fn find_back_edges<S: BuildHasher>(...)`

---

## cff_pattern_matcher.rs

- `enum CffVariant` — OllvmFlat, OllvmConditional, NestedDispatchers, IndirectLookupTable, Hikari, GenericSwitch, Unknown.
- `struct CfgMetrics`
  - `new() -> Self` (const)
- `struct PatternMatchResult`
  - `new(variant: CffVariant, confidence: f32) -> Self` (const)
  - `with_evidence(self, e: impl Into<String>) -> Self`
- `struct CffPatternMatcher`
  - `new() -> Self` (const)
  - `with_min_confidence(self, t: f32) -> Self` (const)
  - `compute_metrics(...) -> CfgMetrics`
  - `match_ollvm_flat(&self, m: &CfgMetrics) -> PatternMatchResult`
  - `match_ollvm_conditional(&self, m: &CfgMetrics) -> PatternMatchResult`
  - `match_nested_dispatchers(...) -> PatternMatchResult`
  - `match_indirect_lookup_table(...) -> PatternMatchResult`
  - `match_hikari(&self, m: &CfgMetrics) -> PatternMatchResult`
  - `match_generic_switch(&self, m: &CfgMetrics) -> PatternMatchResult`
  - `match_all(...) -> Vec<PatternMatchResult>`
  - `best_match(...) -> Option<PatternMatchResult>`

---

## cff_decompiler.rs

- `enum DecompState`
- `struct RecoveredBlockAnnotated`
- `struct LoopRecovery`
- `struct IfElseRecovery`
- `struct DecompiledFunction`
  - `block_count(&self) -> usize`
  - `loop_count(&self) -> usize` (const)
  - `if_count(&self) -> usize` (const)
- `struct CffDecompiler`
  - `new() -> Self` (const)
  - `decompile(&self, cfg: &RecoveredCfg) -> DecompiledFunction` — structured decompilation from a recovered CFG.

---

## cff_recovery.rs

- `type LibCffSignature = CffSignature`
- `struct CaseBlock`
  - `new(state_value: u64, start_address: u64) -> Self` (const)
  - `is_conditional(&self) -> bool` (const)
  - `successors(&self) -> Vec<u64>`
- `struct FlattenedFunction`
  - `new(function_address: u64, dispatcher_address: u64) -> Self` (const)
  - `case_count(&self) -> usize` (const)
  - `find_case(&self, state: u64) -> Option<&CaseBlock>`
  - `entry_case(&self) -> Option<&CaseBlock>`
- `struct StateVariableInfo`
  - `from_state_var(sv: &StateVariable) -> Self`
  - `add_known_value(&mut self, v: u64)`
  - `value_count(&self) -> usize` (const)
- `enum StructuredStatement`
- `struct StructuredOutput`
  - `new() -> Self` (const)
  - `add(&mut self, stmt: StructuredStatement)`
  - `statement_count(&self) -> usize` (const)
  - `has_loops(&self) -> bool`
  - `has_conditionals(&self) -> bool`
- `struct CffSignature`
  - `new(name: impl Into<String>, pattern: Vec<u8>, confidence: f32) -> Self`
  - `matches(&self, data: &[u8], offset: usize) -> bool`
  - `scan(&self, data: &[u8]) -> Vec<usize>`
- `fn builtin_cff_signatures() -> Vec<CffSignature>` — built-in OLLVM/Hikari byte signatures.
- `struct CffRecovery`
  - `new() -> Self`
  - `with_min_confidence(self, c: f64) -> Self` (const)
  - `add_signature(&mut self, sig: CffSignature)`
  - `scan_signatures(&self, data: &[u8], base_addr: u64) -> Vec<(String, u64, f32)>`
  - `recover_from_cfg(...)`
  - `build_flattened_function(...) -> FlattenedFunction`
  - `build_structured_output(&self, recovered: &RecoveredCfg) -> StructuredOutput`

---

## cff_deobfuscator.rs

- `enum DeobfError`
- `enum CondExpr`
- `struct StateAssignment`
- `struct DeobfConfig`
- `struct DeobfResult` (local)
- `struct RebuiltCfg`
  - `block_count(&self) -> usize`
- `struct CffDeobfuscator`
  - `new() -> Self`
  - `with_config(config: DeobfConfig) -> Self`
  - `add_block(&mut self, block: BasicBlock)`
  - `set_state_assignments(...)`
  - `remove_flattening(&self) -> Result<(RebuiltCfg, DeobfResult), DeobfError>`
  - `recover_original_edges(...)`
  - `solve_constant_state(...)`
  - `rebuild_cfg_without_dispatcher(...)`
  - `remove_flattening_iterative(...)`

---

## constant_propagator_cff.rs

- `enum VarId`
- `enum BinOpKind`
- `enum AbstractValue { Undefined, Concrete(i64), Unknown }`
  - `join(self, other: Self) -> Self` (const)
  - `is_concrete(self) -> bool` (const)
  - `as_concrete(self) -> Option<i64>` (const)
- `struct PropagationState`
  - `new() -> Self`
  - `get(&self, var: VarId) -> AbstractValue`
  - `set_concrete(&mut self, var: VarId, val: i64)`
  - `set_unknown(&mut self, var: VarId)`
  - `set_undefined(&mut self, var: VarId)`
  - `join_with(&mut self, other: &Self) -> bool`
- `fn transfer_assign(dst: VarId, val: AbstractValue, state: &mut PropagationState)`
- `fn transfer_phi(...)`
- `fn transfer_binary(...)`
- `fn eval_binary(op: BinOpKind, a: AbstractValue, b: AbstractValue) -> AbstractValue`
- `struct DispatcherInfo`
  - `new(state_var: VarId) -> Self`
  - `register_state(&mut self, value: i64, block_addr: u64)`
- `fn resolve_state_variable(...)` — resolve dispatcher state using propagation results.
- `enum MicroInsn`
- `struct PropBlock`
  - `new(addr: u64) -> Self` (const)
- `struct ConstantPropagatorCff`
  - `new(entry: u64) -> Self`
  - `add_block(&mut self, block: PropBlock)`
  - `propagate_worklist(&mut self, initial: PropagationState)` — worklist constant propagation.
  - `out_state(&self, addr: u64) -> Option<&PropagationState>`
