# rustre-deobf-iadl — Public API

Iterative Adversarial Deobfuscation Loop. Hypothesis evaluation, scoring, convergence detection, strategy selection, IR transforms, indirect target / call-graph / constraint propagation analysis, adversarial testing.

Below: only public functions (free fns + inherent methods + trait methods). Struct/enum/trait declarations omitted per request.

---

## `lib.rs`

### `IadlState`
- `new(global_score: f64, complexity: u64) -> Self` — construct initial loop state.

### `TentativeState`
- `new(hypothesis_id: impl Into<String>, score: f64, complexity: u64, rationale: impl Into<String>) -> Self` — build candidate produced by a hypothesis.

### trait `Hypothesis`
- `id(&self) -> &str`
- `prior(&self, state: &IadlState) -> f64` — default 0.5.
- `apply(&self, state: &IadlState) -> TentativeState`

### trait `Scorer`
- `name(&self) -> &str`
- `weight(&self) -> f64`
- `score(&self, tentative: &TentativeState, baseline: &IadlState) -> f64`

### `IadlOrchestrator`
- `default_config() -> Self`
- `new(config: IadlConfig) -> Self`
- `config(&self) -> IadlConfig`
- `run(&self, state: IadlState, hypotheses: &[Box<dyn Hypothesis>], scorers: &[Box<dyn Scorer>]) -> IadlReport` — main loop until no-progress or budget.
- `evaluate_all(&self, state: &IadlState, hypotheses: &[Box<dyn Hypothesis>], scorers: &[Box<dyn Scorer>]) -> Vec<CandidateEvaluation>` — evaluate+sort candidates.

### `ProtectionLayer`
- `name(&self) -> &'static str`
- `removal_cost(&self) -> u32`

### `BinaryIadlState`
- `new(binary_size: usize, function_count: u32) -> Self`
- `is_high_entropy(&self, section: &str) -> bool`
- `has_packer(&self) -> bool`

### `BinaryTentativeState`
- `combined_score(&self) -> f64` — 0.6*naturalness + 0.4*complexity_reduction.

### trait `BinaryHypothesis`
- `id(&self) -> u64`
- `name(&self) -> &str`
- `prior(&self, state: &BinaryIadlState) -> f64`
- `apply(&self, state: &BinaryIadlState) -> BinaryTentativeState`
- `cost_estimate(&self) -> std::time::Duration`

### Built-in `BinaryHypothesis` impls
`UPXUnpackHypothesis`, `CflFlatteningHypothesis`, `OpaquePredicateHypothesis`, `StringDecryptHypothesis`, `AntiDebugHypothesis`, `VmObfuscationHypothesis` — implement trait with technique-specific priors/actions.

### `NaturalnessScorer`
- `score(state: &BinaryTentativeState) -> f64`

### `BinaryIadlReport`
- `has_progress(&self) -> bool`
- `top_recommendation(&self) -> Option<&str>`
- `to_json(&self) -> Result<String, serde_json::Error>`
- `from_json(s: &str) -> Result<Self, serde_json::Error>`

### `BinaryIadlOrchestrator`
- `new() -> Self`
- `register(&mut self, hypothesis: Box<dyn BinaryHypothesis>)`
- `run_state(&mut self, state: BinaryIadlState) -> BinaryIadlReport`
- `run(&mut self, binary: &[u8]) -> BinaryIadlReport` — scan + loop.

### Free functions
- `analyze_binary_for_protections(data: &[u8]) -> BinaryIadlState` — entropy + UPX + antidebug + prologue scan.
- `compute_hash(data: &[u8], algorithm: HashAlgorithm) -> u64` — djb2/fnv1a/sdbm/crc32/adler32/ror.

### `HashAlgorithm`
- `name(self) -> &'static str`
- `is_known(self) -> bool`

### `ApiHash`
- `new(hash: u64, algorithm: HashAlgorithm, file_offset: u64) -> Self`
- `with_name(self, name: impl Into<String>) -> Self`
- `with_dll(self, dll: impl Into<String>) -> Self`
- `is_fully_resolved(&self) -> bool`
- `is_resolved(&self) -> bool`

### `ApiResolution`
- `new(api_hash: ApiHash, call_site: u64) -> Self`
- `with_address(self, addr: u64) -> Self`
- `with_confidence(self, conf: u32) -> Self`
- `is_high_confidence(&self) -> bool`

### `IadlDetector`
- `new() -> Self`
- `scan_hash_constants(&self, data: &[u8]) -> Vec<(u64, usize)>`
- `detect_loadlib_pattern(&self, data: &[u8]) -> Vec<usize>` — CALL EAX/EDX/[addr] offsets.
- `identify_algorithm(&self, hashes: &[u64]) -> (HashAlgorithm, usize)`
- `analyze(&self, data: &[u8], call_base: u64) -> Vec<ApiResolution>`

### `HashTable`
- `new(algorithm: HashAlgorithm) -> Self`
- `build(names: &[&str], algorithm: HashAlgorithm) -> Self`
- `insert(&mut self, name: impl Into<String>)`
- `resolve(&self, hash: u64) -> Option<&str>`
- `len(&self) -> usize`
- `is_empty(&self) -> bool`
- `entries(&self) -> Vec<(u64, &str)>`

### `ChainStep`
- `new(offset: u64, call_type: impl Into<String>) -> Self`
- `with_argument(self, arg: impl Into<String>) -> Self`

### `LoadLibraryChain`
- `new() -> Self`
- `push(&mut self, step: ChainStep)`
- `len(&self) -> usize`
- `is_empty(&self) -> bool`
- `is_complete(&self) -> bool`

### `ComplexityScorer`
- `new(weight: f64) -> Self`

### `ImprovementScorer`
- `new(weight: f64) -> Self`

### `ConstantHypothesis`
- `new(id: impl Into<String>, score: f64, complexity: u64, rationale: impl Into<String>) -> Self`
- `with_prior(self, prior: f64) -> Self`

### `IncrementalHypothesis`
- `new(id: impl Into<String>, factor: f64) -> Self`

### `ResolutionStats`
- `from_resolutions(resolutions: &[ApiResolution]) -> Self`
- `is_good_coverage(&self) -> bool`

### `IadlDeobfPass`
- `new(name: impl Into<String>, config: IadlConfig) -> Self`
- `run(&self, initial_score: f64, initial_complexity: u64, hypotheses: &[Box<dyn Hypothesis>], scorers: &[Box<dyn Scorer>]) -> IadlReport`
- `name(&self) -> &str`

### `HypothesisRegistry`
- `new() -> Self`
- `register(&mut self, hypothesis: Box<dyn Hypothesis>) -> bool`
- `ids(&self) -> Vec<String>`
- `len(&self) -> usize`
- `is_empty(&self) -> bool`
- `all(&self) -> Vec<&dyn Hypothesis>`

---

## `strategy_selector.rs`

### `IadlStrategy`
- `name(self) -> &'static str`
- `base_cost(self) -> f64`
- `base_precision(self) -> f64`
- `all() -> &'static [Self]`

### `StrategyScore`
- `utility(&self) -> f64`

### `StrategyScorer`
- `score_all(features: &ObservedFeatures) -> Vec<StrategyScore>`
- `score_strategy(strategy: IadlStrategy, features: &ObservedFeatures) -> StrategyScore`

### `StrategyRecord`
- `new(strategy: IadlStrategy, score: f64, success: bool, iteration: u32) -> Self`
- `with_duration(self, d: Duration) -> Self`

### `StrategyHistory`
- `new() -> Self`
- `push(&mut self, record: StrategyRecord)`
- `attempt_count(&self, strategy: IadlStrategy) -> usize`
- `best_score(&self, strategy: IadlStrategy) -> Option<f64>`
- `average_score(&self, strategy: IadlStrategy) -> Option<f64>`
- `last_strategy(&self) -> Option<IadlStrategy>`
- `untried_strategies(&self) -> Vec<IadlStrategy>`
- `ranked_by_performance(&self) -> Vec<(IadlStrategy, f64)>`
- `any_success(&self) -> bool`
- `len(&self) -> usize`
- `is_empty(&self) -> bool`

### `StrategySelector`
- `new() -> Self`
- `with_weights(history_weight: f64, scorer_weight: f64, repeat_penalty: f64) -> Self`
- `select(&self, features: &ObservedFeatures, history: &StrategyHistory) -> IadlStrategy`
- `rank(&self, features: &ObservedFeatures, history: &StrategyHistory) -> Vec<(IadlStrategy, f64)>`
- `top_n(&self, features: &ObservedFeatures, history: &StrategyHistory, n: usize) -> Vec<IadlStrategy>`

### `AdaptiveSelector`
- `new(stagnation_threshold: u32) -> Self`
- `current_or_pick(&mut self, features: &ObservedFeatures) -> IadlStrategy`
- `pick(&mut self, features: &ObservedFeatures) -> IadlStrategy`
- `report_iteration(&mut self, strategy: IadlStrategy, score: f64, success: bool, iteration: u32)`
- `performance_summary(&self) -> HashMap<IadlStrategy, f64>`
- `is_stagnated(&self) -> bool`

---

## `perturbation.rs`

### `PerturbationType`
- `name(&self) -> &'static str`
- `is_reversible(&self) -> bool`
- `aggressiveness(&self) -> u8`

### `Perturbation`
- `new(kind: PerturbationType) -> Self`
- `record_application(&mut self, iteration: u32, effect: f64)`

### `PerturbationEffect`
- `is_beneficial(&self) -> bool`

### Free functions
- `apply_perturbation(data: &[u8], perturbation: &Perturbation) -> Vec<u8>`
- `measure_effect(data: &[u8], perturbation: &Perturbation) -> PerturbationEffect`
- `rank_perturbations(data: &[u8], perturbations: &[Perturbation]) -> Vec<(usize, f64)>`

---

## `obfuscation_classifier.rs`

### `Confidence`
- `new(v: f64) -> Self`
- `value(self) -> f64`
- `is_high(self) -> bool`
- `is_medium(self) -> bool`
- `is_low(self) -> bool`

### `TechniqueResult`
- `new(technique: ObfuscationTechnique, confidence: Confidence, evidence_count: usize) -> Self`
- `add_evidence(&mut self, addr: u64)`
- `suggest(&mut self, pass: DeobfPass)`

### `ClassificationResult`
- `new() -> Self`
- `add_technique(&mut self, tr: TechniqueResult)`
- `high_confidence_techniques(&self) -> Vec<&TechniqueResult>`
- `has_technique(&self, tech: &ObfuscationTechnique) -> bool`

### `FunctionMetrics`
- `new(addr: u64) -> Self`

### `BinaryStats`
- `new(function_count: u32, binary_size: u64) -> Self`

### `ObfuscationClassifier`
- `new() -> Self`
- `with_config(config: ClassifierConfig) -> Self`
- `classify(&self, functions: &[FunctionMetrics], stats: &BinaryStats) -> ClassificationResult`

### `ObfuscationReport`
- `build(result: &ClassificationResult, functions: &[FunctionMetrics], stats: &BinaryStats) -> Self`
- `summary_text(&self) -> String`

---

## `loop_orchestrator.rs`

### `DeobfIteration`
- `new(index: u32, strategy: impl Into<String>, score_before: f64, complexity_before: u64) -> Self`
- `complete(&mut self, score_after: f64, complexity_after: u64)`
- `delta(&self) -> f64`
- `complexity_reduction(&self) -> i64`

### `IterationResult` (enum)
- `is_beneficial(&self) -> bool`
- `should_stop(&self) -> bool`
- `delta(&self) -> f64`

### `QualityDelta`
- `new(before_score: f64, after_score: f64, before_complexity: u64, after_complexity: u64, strategy: impl Into<String>) -> Self`
- `is_improvement(&self) -> bool`
- `is_no_change(&self) -> bool`

### `StrategySwitchReason`
- `label(&self) -> &'static str`

### `OrchestratorStats`
- `new() -> Self`
- `total_improvement(&self) -> f64`
- `improvement_rate(&self) -> f64`
- `record(&mut self, result: &IterationResult, strategy: &str, elapsed_us: u64)`
- `summary(&self) -> String`

### `LoopReport`
- `new() -> Self`
- `best_strategy(&self) -> Option<&str>`
- `record_iteration(&mut self, iter: DeobfIteration)`
- `top_improvements(&self, n: usize) -> Vec<&QualityDelta>`

### `DeobfProgressTracker`
- `new() -> Self`
- `record(&mut self, score: f64, complexity: u64, strategy: impl Into<String>)`
- `total_improvement(&self) -> f64`
- `improving_fraction(&self) -> f64`
- `is_converged(&self, epsilon: f64) -> bool`
- `len(&self) -> usize`
- `is_empty(&self) -> bool`

### `IterationHistory`
- `new() -> Self`
- `with_limit(self, n: usize) -> Self`
- `record(&mut self, score: f64, complexity: u64)`
- `mean_score(&self) -> f64`
- `max_score(&self) -> f64`
- `min_score(&self) -> f64`
- `is_monotone(&self, n: usize) -> bool`
- `len(&self) -> usize`
- `is_empty(&self) -> bool`

### `StrategyBudget`
- `new(name: impl Into<String>, budget: usize) -> Self`
- `consume(&mut self) -> bool`
- `reset(&mut self)`
- `is_exhausted(&self) -> bool`

### `IterationScheduler`
- `new() -> Self`
- `add(&mut self, name: impl Into<String>, budget: usize)`
- `next_available(&mut self) -> Option<&str>`
- `reset_all(&mut self)`
- `all_exhausted(&self) -> bool`
- `total_budget(&self) -> usize`

### trait `Strategy: Send + Sync`
- application interface for loop strategies.

### `LoopState`
- `new(score: f64, complexity: u64) -> Self`
- `set_meta(&mut self, key: impl Into<String>, value: f64)`
- `get_meta(&self, key: &str) -> Option<f64>`

### `FixedDeltaStrategy`
- `new(name: impl Into<String>, score_delta: f64, complexity_delta: i64) -> Self`

### `ConvergenceDetector` (module-local)
- `new() -> Self`
- `with_window(self, n: usize) -> Self`
- `with_epsilon(self, e: f64) -> Self`
- `update(&mut self, delta: f64) -> bool`
- `is_converged(&self) -> bool`
- `mean_delta(&self) -> f64`
- `reset(&mut self)`

### `LoopOrchestrator`
- `new() -> Self`
- `with_max_iterations(self, n: usize) -> Self`
- `with_stagnation_threshold(self, n: usize) -> Self`
- `run(&self, strategies: &[Box<dyn Strategy>], initial_state: LoopState) -> LoopReport`

---

## `loop_analysis.rs`

### `StateSnapshot`
- `zeroed(iteration: u32) -> Self`
- `is_low_entropy(&self) -> bool`
- `set_metric(&mut self, name: impl Into<String>, value: f64)`
- `get_metric(&self, name: &str) -> Option<f64>`

### `ProgressDelta`
- `compute(before: &StateSnapshot, after: &StateSnapshot) -> Self`
- `has_progress(&self) -> bool`
- `score(&self) -> f64`
- `is_monotone(&self) -> bool`

### `LoopIteration`
- `new(index: u32, before: StateSnapshot, after: StateSnapshot, strategy: impl Into<String>) -> Self`
- `made_progress(&self) -> bool`
- `progress_score(&self) -> f64`
- `duration_ms(&self) -> Option<u64>`

### `StagnationDetector`
- `new(window: u32) -> Self`
- `with_threshold(window: u32, min_progress_score: f64) -> Self`
- `record(&mut self, score: f64) -> bool`
- `is_stagnated(&self) -> bool`
- `reset(&mut self)`
- `average_score(&self) -> f64`
- `best_recent_score(&self) -> f64`

### `LoopBudget`
- `unlimited() -> Self`
- `check_iterations(&self, current: u32) -> Result<(), LoopAnalysisError>`
- `check_time(&self, start: Instant) -> Result<(), LoopAnalysisError>`
- `check_memory(&self, current_bytes: u64) -> Result<(), LoopAnalysisError>`

### `LoopProgressAnalyzer`
- `new() -> Self`
- `record(&mut self, iter: LoopIteration)`
- `iteration_count(&self) -> usize`
- `last_n_no_progress(&self, n: usize) -> bool`
- `best_iteration(&self) -> Option<&LoopIteration>`
- `average_score(&self) -> f64`
- `last_snapshot(&self) -> Option<&StateSnapshot>`
- `trend(&self, window: usize) -> f64`
- `progressing_iterations(&self) -> Vec<&LoopIteration>`
- `stagnant_iterations(&self) -> Vec<&LoopIteration>`
- `progress_ratio(&self) -> f64`

### `LoopController`
- `new(budget: LoopBudget, stagnation_window: u32) -> Self`
- `begin_iteration(&mut self) -> Result<u32, LoopAnalysisError>`
- `end_iteration(&mut self, ...) -> ...` — see source for full signature.
- `elapsed(&self) -> Duration`
- `summary(&self) -> String`

---

## `iadl_orchestrator.rs`

### `PhaseId`
- `name(&self) -> &'static str`
- `default_max_iter(&self) -> u32`

### `DeobfIteration`
- `initial(phase: PhaseId) -> Self`

### `IterationResult`
- `is_good(&self, threshold: f64) -> bool`
- `phase_history(&self, phase: PhaseId) -> Vec<&DeobfIteration>`
- `avg_improvement(&self) -> f64`

### `OrchConfig`
- `max_iter_for(&self, phase: PhaseId) -> u32`

### trait `PhaseHandler: Send`
- phase implementation interface.

### Free functions
- `convergence_check(previous: f64, current: f64, threshold: f64) -> bool`
- `stall_check(history: &[f64], stall_limit: usize, threshold: f64) -> bool`

### `DeobfOrchestrator`
- `new(config: OrchConfig) -> Self`
- `register_phase(&mut self, phase: PhaseId, handler: Box<dyn PhaseHandler>)`
- `remove_phase(&mut self, phase: PhaseId) -> Option<Box<dyn PhaseHandler>>`
- `run(&mut self, initial_score: f64, initial_complexity: u64) -> IterationResult`
- `config(&self) -> &OrchConfig`
- `config_mut(&mut self) -> &mut OrchConfig`

---

## `ir_transform.rs`

### `DeobfuscationPipeline`
- `new() -> Self`
- `add_pass(self, pass: Box<dyn TransformPass>) -> Self`
- `standard() -> Self` — default pipeline with all standard passes.
- `run_all(&mut self, func: &mut IrFunction) -> PipelineStats`

### trait `TransformPass: Send`
- `name(&self) -> &'static str`
- `run(&mut self, func: &mut IrFunction) -> usize`

### Pass impls
`ConstantFoldingPass`, `DeadCodeElimination`, `CopyPropagation`, `CommonSubexpressionElim`, `BooleanSimplification`, `XorChainSimplifier`, `MbaSimplifier`, `OpaquePredicateElim`, `BlockMerging`, `PhiElimination` — each impl `TransformPass`.

---

## `adversarial_loop.rs`

### `ProgressMetric`
- `compute(before: &[u8], after: &[u8], patches: usize) -> Self`
- `zero() -> Self`
- `has_progress(&self, threshold: f64) -> bool`

### trait `IadlPass: Send + Sync`
- pass application interface.

### `IadlLoopReport`
- `total_patches(&self) -> usize`
- `progressive_iterations(&self) -> usize`
- `summary(&self) -> String`

### `IadlLoop`
- `new(config: IadlLoopConfig, passes: Vec<Box<dyn IadlPass>>) -> Self`
- `add_perturbation(&mut self, p: Perturbation)`
- `run(&mut self, initial_binary: &[u8]) -> Result<IadlLoopReport, IadlLoopError>`

---

## `deobf_strategy_selector.rs`

### `StrategyFeature`
- `name(&self) -> &'static str`
- `as_f64(&self) -> f64`

### `FeatureVector`
- `new() -> Self`
- `push(&mut self, feature: StrategyFeature)`
- `get_f64(&self, name: &str) -> Option<f64>`
- `iter(&self) -> impl Iterator<Item = &StrategyFeature>`
- `len(&self) -> usize`
- `is_empty(&self) -> bool`
- `as_map(&self) -> BTreeMap<&str, f64>`

### `DeobfStrategy`
- `name(&self) -> &'static str`
- `all() -> &'static [DeobfStrategy]`

### `DeobfStrategySelector`
- `new() -> Self`
- `set_rule_weight(&mut self, w: f64)`
- `score_all(&self, features: &FeatureVector) -> Vec<StrategyScore>`
- `select_best(&self, features: &FeatureVector) -> DeobfStrategy`
- `select_top_n(&self, features: &FeatureVector, n: usize) -> Vec<DeobfStrategy>`
- `record_outcome(&mut self, strategy: DeobfStrategy, outcome: f64)`
- `avg_outcome(&self, strategy: DeobfStrategy) -> f64`
- `reset_history(&mut self)`

---

## `adversarial_tester.rs`

### `TestCase`
- `seed(id: u64, input: Vec<u8>, expected_output: Vec<u8>) -> Self`
- `derived(parent_id: u64, id: u64, input: Vec<u8>, expected_output: Vec<u8>, mutation: MutationOp) -> Self`
- `input_len(&self) -> usize`

### `Equivalence`
- `pass(test_case_id: u64, output: Vec<u8>) -> Self`
- `fail(test_case_id: u64, expected: &[u8], actual: Vec<u8>) -> Self`

### `MutationOp`
- `apply(&self, input: &[u8]) -> Vec<u8>`

### `AdversarialScore`
- `from_verdicts(verdicts: &[Equivalence]) -> Self`
- `summary(&self) -> String`

### Free function
- `adversarial_score(verdicts: &[Equivalence]) -> f64`

### trait `DeobfOracle: Send`
- oracle invocation interface.

### `AdversarialTester`
- `new(config: TesterConfig) -> Self`
- `add_seed(&mut self, input: Vec<u8>, expected_output: Vec<u8>) -> u64`
- `run_round(&mut self, oracle: &dyn DeobfOracle) -> AdversarialScore`
- `run_until_pass(&mut self, oracle: &dyn DeobfOracle) -> Vec<AdversarialScore>`
- `corpus_size(&self) -> usize`
- `history(&self) -> &[AdversarialScore]`
- `reset(&mut self)`

---

## `convergence_detector.rs`

### `ConvergenceState`
- `should_continue(self) -> bool`
- `is_terminal(self) -> bool`

### `ConvergenceDetector`
- `new(max_iterations: usize) -> Self`
- `with_config(config: ConvergenceConfig) -> Self`
- `config(&self) -> &ConvergenceConfig`
- `reset(&mut self)`
- `check(&mut self, history: &VecDeque<f64>) -> ConvergenceState`
- `check_pure(&self, history: &VecDeque<f64>) -> ConvergenceState`

### Free functions
- `find_plateau_start(history: &[f64], window: usize, threshold: f64) -> Option<usize>`
- `moving_average(history: &[f64], window: usize) -> Vec<f64>`
- `exponential_moving_average(history: &[f64], alpha: f64) -> Vec<f64>`
- `trend_slope(history: &[f64]) -> f64`

---

## `indirect_target_resolver.rs`

### `ValueSet` (VSA lattice)
- `bottom() -> Self`
- `top() -> Self`
- `singleton(v: u64) -> Self`
- `from_values(vals: impl IntoIterator<Item = u64>) -> Self`
- `strided_interval(lower: u64, upper: u64, stride: u64) -> Self`
- `join(&self, other: &Self) -> Self`
- `contains(&self, v: u64) -> bool`
- `concrete_values(&self) -> Vec<u64>`
- `is_empty(&self) -> bool`
- `size(&self) -> usize`

### `TaintState`
- `new() -> Self`
- `taint_register(&mut self, reg: impl Into<String>, label: TaintLabel)`
- `taint_memory(&mut self, addr: u64, label: TaintLabel)`
- `is_register_tainted(&self, reg: &str) -> bool`
- `is_memory_tainted(&self, addr: u64) -> bool`
- `propagate_reg_to_reg(&mut self, src: &str, dst: impl Into<String>)`
- `clear_register(&mut self, reg: &str)`
- `merge(&mut self, other: &Self)`

### `VtableCandidate`
- `new(vtable_addr: u64, slot_index: u32, target_addr: u64) -> Self`
- `with_symbol(self, name: impl Into<String>) -> Self`
- `with_class(self, class: impl Into<String>) -> Self`
- `with_confidence(self, c: f64) -> Self`

### `IndirectTarget`
- `site_address(&self) -> Address`
- `target_addresses(&self) -> Vec<Address>`
- `new(site_addr: u64, is_call: bool) -> Self`
- `add_target(&mut self, addr: u64, method: ResolutionMethod, confidence: f64)`
- `is_monomorphic(&self) -> bool`
- `is_polymorphic(&self) -> bool`

### `RopChainAnalysis`
- `new(chain_start: u64) -> Self`
- `has_gadgets(&self) -> bool`

### `AbstractInstr`
- `new(addr: u64, mnemonic: impl Into<String>) -> Self`
- `is_indirect_transfer(&self) -> bool`
- `is_const_move(&self) -> bool`

### `IndirectTargetResolver`
- `new() -> Self`
- `with_config(config: ResolverConfig) -> Self`
- `load_instructions(&mut self, instrs: Vec<AbstractInstr>)`
- `register_vtable(&mut self, vtable_addr: u64, slots: Vec<(u32, u64)>)`
- `register_iat_entry(&mut self, iat_addr: u64, symbol: impl Into<String>)`
- `add_external_hint(&mut self, site: u64, target: u64)`
- `resolve_all(&mut self) -> Vec<IndirectTarget>`
- `resolve_site(&self, site_addr: u64, is_call: bool) -> IndirectTarget`
- `results(&self) -> &HashMap<u64, IndirectTarget>`
- `high_confidence_results(&self) -> Vec<&IndirectTarget>`
- `statistics(&self) -> ResolutionStats`

---

## `call_graph_builder.rs`

### `CallEdge`
- `new(caller: u64, callee: u64, call_site: u64, kind: EdgeKind) -> Self`
- `with_confidence(self, c: f64) -> Self`
- `as_dynamic(self) -> Self`

### `CallSite`
- `new(addr: u64, function: u64, kind: EdgeKind) -> Self`
- `add_target(&mut self, target: u64)`
- `is_monomorphic(&self) -> bool`

### `CallGraph`
- `new() -> Self`
- `add_node(&mut self, addr: u64)`
- `add_edge(&mut self, edge: CallEdge)`
- `add_call_site(&mut self, site: CallSite)`
- `set_symbol(&mut self, addr: u64, name: impl Into<String>)`
- `mark_library_stub(&mut self, addr: u64)`
- `mark_unresolvable(&mut self, addr: u64)`
- `callees_of(&self, func: u64) -> Vec<&CallEdge>`
- `callers_of(&self, func: u64) -> Vec<&CallEdge>`
- `fan_out(&self, func: u64) -> usize`
- `fan_in(&self, func: u64) -> usize`
- `node_count(&self) -> usize`
- `edge_count(&self) -> usize`
- `name_of(&self, addr: u64) -> String`
- `metrics(&self) -> CallGraphMetrics`
- `compute_sccs(&self) -> Vec<Vec<u64>>`
- `topological_order(&self) -> Vec<u64>`
- `reachable_from(&self, start: u64) -> HashSet<u64>`
- `entry_points(&self) -> Vec<u64>`
- `leaf_functions(&self) -> Vec<u64>`
- `to_dot(&self) -> String`

### `FunctionInfo`
- `new(start: u64, size: u32) -> Self`
- `with_name(self, name: impl Into<String>) -> Self`

### `CallInstruction`
- `direct(addr: u64, target: u64) -> Self`
- `indirect(addr: u64, targets: Vec<u64>) -> Self`
- `tail(self) -> Self`

### `CallGraphBuilder`
- `new() -> Self`
- `with_config(config: CgBuilderConfig) -> Self`
- `add_function(&mut self, func: FunctionInfo)`
- `add_iat_stub(&mut self, stub_addr: u64, symbol: impl Into<String>)`
- `add_dynamic_hint(&mut self, hint: DynamicHint)`
- `add_stub_range(&mut self, start: u64, end: u64)`
- `build(self) -> CallGraph`

---

## `constraint_propagation.rs`

### `ValueRange` (interval lattice)
- `top() -> Self`
- `bottom() -> Self`
- `constant(v: i64) -> Self`
- `bounded(lo: i64, hi: i64) -> Self`
- `join(&self, other: &Self) -> Self`
- `meet(&self, other: &Self) -> Self`
- `is_constant(&self) -> bool`
- `constant_value(&self) -> Option<i64>`
- `contains(&self, v: i64) -> bool`
- `width(&self) -> Option<u64>`
- `add(&self, rhs: &Self) -> Self`

### `DeobfConstraint`
- `primary_var(&self) -> &str`
- `derive_range(&self, env: &HashMap<String, ValueRange>) -> Option<ValueRange>`

### `ConstraintGraph`
- `add(&mut self, c: DeobfConstraint) -> usize`
- `constraints_for(&self, var: &str) -> impl Iterator<Item = usize> + '_`
- `len(&self) -> usize`
- `is_empty(&self) -> bool`

### `PropagationResult`
- `is_consistent(&self) -> bool`
- `range_of(&self, var: &str) -> &ValueRange`

### `ConstraintSolver`
- `new() -> Self`
- `with_max_iterations(n: usize) -> Self`
- `solve(&self, graph: &ConstraintGraph, initial: HashMap<String, ValueRange>) -> PropagationResult` — fixpoint solver.

### `ConstraintPropagation`
- `new() -> Self`
- `propagate(&self, graph: &ConstraintGraph, initial: HashMap<String, ValueRange>) -> PropagationResult`
- `propagate_equality(&self, var: &str, value: i64) -> PropagationResult`
