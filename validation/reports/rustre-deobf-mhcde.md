# rustre-deobf-mhcde — Public API Report

Crate path: `crates/rustre-deobf-mhcde`
Purpose: Mixed Honig Control-flow & Dead-code Elimination — detects/removes opaque predicates, junk code, control-flow flattening, unreachable blocks; provides hypothesis framework, oracles, dataflow, CFG building, multi-stage deobfuscation.

Signatures grouped per file/modulo. Receiver e impl-owner annotati dove necessario.

---

## src/lib.rs

### `OpaquePredicateDetector`
- `new() -> Self` — costruttore const.
- `detect(&self, data: &[u8]) -> Vec<OpaquePredicate>` — scansiona pattern x86 (xor/test/jz, mov al,1; test; jz, stc/jc, ecc.) e ritorna i predicati opachi trovati con offset/lunghezza/tipo.
- `count_by_type(&self, data: &[u8]) -> HashMap<OpaquePredicateType, usize>` — conteggio per categoria.
- `total_patch_bytes(&self, data: &[u8]) -> usize` — somma byte da nopare.

### `JunkCodeDetector`
- `new() -> Self`.
- `detect(&self, data: &[u8]) -> Vec<JunkCodeRegion>` — riconosce NOP sled, push/pop stesso reg, xor/add/sub/or reg,0, mov reg,reg identità, lea [reg+0], xchg eax,eax, multi-byte NOP.
- `total_junk_bytes(&self, data: &[u8]) -> usize`.
- `junk_density(&self, data: &[u8]) -> f32` — rapporto junk/totale.

### `ControlFlowFlattener`
- `new() -> Self`.
- `detect(&self, data: &[u8]) -> Option<CffDetectionResult>` — euristica: trova jmp indiretto come dispatcher, individua state variable e body blocks.
- `dispatcher_fan_out(result: &CffDetectionResult) -> f32` — metrica fan-out del dispatcher.

### `BogusControlFlowRemover`
- `new() -> Self`.
- `remove_bogus_blocks<'a>(&self, blocks: &'a [CfgBlock], junk_offsets: &HashSet<usize>) -> Vec<&'a CfgBlock>` — filtra dispatcher e blocchi junk.
- `junk_offset_set(regions: &[JunkCodeRegion]) -> HashSet<usize>`.
- `dispatcher_blocks<'a>(&self, blocks: &'a [CfgBlock]) -> Vec<&'a CfgBlock>`.

### `DeadCodeEliminator`
- `new() -> Self`.
- `build_graph(&self, blocks: &[CfgBlock]) -> (DiGraph<usize, ()>, AHashMap<usize, NodeIndex>)`.
- `reachable_blocks(&self, blocks: &[CfgBlock], entry_offset: usize) -> HashSet<usize>` — BFS sui successori.
- `eliminate<'a>(&self, blocks: &'a [CfgBlock], entry_offset: usize) -> Vec<&'a CfgBlock>` — solo blocchi raggiungibili.
- `dead_blocks<'a>(&self, blocks: &'a [CfgBlock], entry_offset: usize) -> Vec<&'a CfgBlock>`.
- `bfs_order(&self, blocks: &[CfgBlock], entry_offset: usize) -> Vec<usize>`.
- `dead_block_ratio(&self, blocks: &[CfgBlock], entry_offset: usize) -> f32`.

### `ConstantFoldingHeuristic`
- `new() -> Self`.
- `try_fold(&self, data: &[u8], offset: usize) -> Option<FoldResult>` — folds MOV/XOR/OR/AND di costanti su EAX/AL.
- `fold_all(&self, data: &[u8]) -> AHashMap<usize, FoldResult>` — applica fold ricorrente sui byte.

### `EntropyAnalyzer`
- `new(window_size: usize) -> Self`.
- `entropy(data: &[u8]) -> f32` — Shannon entropy (associata).
- `analyze(&self, data: &[u8]) -> Vec<EntropyWindow>` — sliding window.
- `high_entropy_windows(&self, data: &[u8], threshold: f32) -> Vec<EntropyWindow>`.
- `low_entropy_windows(&self, data: &[u8], threshold: f32) -> Vec<EntropyWindow>`.
- `mean_entropy(&self, data: &[u8]) -> f32`.

### `PatchApplicator`
- `new() -> Self`.
- `apply_nop_patches(&self, data: &mut [u8], plan: &[PlannedPatch]) -> usize` — riempie con 0x90 in-place.
- `apply_fill_patches(&self, data: &mut [u8], plan: &[PlannedPatch], fill: u8) -> usize`.
- `patched_copy(&self, data: &[u8], plan: &[PlannedPatch]) -> Vec<u8>`.
- `validate_plan(plan: &[PlannedPatch], data_len: usize) -> bool`.

### `MhcdeScore`
- `is_highly_obfuscated(&self) -> bool` — confidence ≥0.75 e ≥3 findings.
- `confidence_tier(&self) -> &'static str` — "very high"/"high"/"medium"/"low"/"none".

### `MhcdeAnalysis`
- `total_findings(&self) -> usize`.
- `is_clean(&self) -> bool`.
- `patch_offsets(&self) -> Vec<usize>` — offset ordinati.
- `high_confidence_patches(&self, min_confidence: f32) -> Vec<&PlannedPatch>`.

### `MhcdeOrchestrator`
- `new() -> Self`.
- `analyze(&self, data: &[u8]) -> MhcdeAnalysis` — esegue tutti i detector e produce score + patch plan.
- `analyze_and_patch(&self, data: &[u8]) -> (Vec<u8>, MhcdeAnalysis)`.

### `MhcdePass`
- `new() -> Self`.
- `analyze(&self, data: &[u8]) -> MhcdeAnalysis`.
- Implementa `DeobfPass` (name/description/is_applicable/run su `DeobfContext`).

### `ScoreModel` (statics)
- `naturalness_score(code: &[u8]) -> f64` — combina entropia, nop-ratio, distribuzione opcode.
- `complexity_score(basic_blocks: usize, edges: usize) -> f64` — complessità ciclomatica normalizzata.

### `HypothesisResult`
- `new(name: impl Into<String>, naturalness: f64, complexity: f64) -> Self`.
- `with_transformed(self, bytes: Vec<u8>) -> Self`.
- `with_meta(self, key: impl Into<String>, value: impl Into<String>) -> Self`.
- `combined_score(&self) -> f64` — media geometrica.
- `is_viable(&self) -> bool` — soglia 0.6.

### Trait `Hypothesis`
- `name(&self) -> &str`.
- `run(&self, code: &[u8]) -> HypothesisResult`.

Implementazioni built-in: `IdentityHypothesis`, `NopStripHypothesis`, `XorFixedKeyHypothesis` (key 0x42), `XorBestKeyHypothesis` (cerca chiave migliore).

### `HypothesisRunner` (statics)
- `new() -> Self`.
- `run_all_in_parallel(code: &[u8], hypotheses: &[Box<dyn Hypothesis>]) -> Vec<HypothesisResult>`.
- `run_parallel(code: &[u8], hypotheses: &[Box<dyn Hypothesis>]) -> Vec<HypothesisResult>`.
- `select_best(results: &[HypothesisResult]) -> Option<&HypothesisResult>`.
- `best(code: &[u8], hypotheses: &[Box<dyn Hypothesis>]) -> Option<HypothesisResult>`.
- `default_hypotheses() -> Vec<Box<dyn Hypothesis>>`.
- `ranked(results: Vec<HypothesisResult>) -> Vec<HypothesisResult>`.

---

## src/mhcde_passes.rs

### `Confidence`
- `is_reliable(self) -> bool`.

### `PassTransform`
- `nop(offset: usize, length: usize, description: impl Into<String>, conf: Confidence) -> Self` — costruisce un patch NOP.
- `apply(&self, buf: &mut [u8]) -> bool` — applica in-place.

### `PassResult`
- `new(pass_name: impl Into<String>) -> Self`.
- `push(&mut self, t: PassTransform)`.
- `note(&mut self, s: impl Into<String>)`.
- `total_bytes(&self) -> usize`.

### Pass (struct, ciascuna con `run`)
- `OpaquePredicatePass::run(&self, data: &[u8]) -> PassResult`.
- `HandlerCfgPass::run(&self, data: &[u8], base: Addr) -> Option<HandlerCfgResult>`.
- `UnflattenPass::run(&self, data: &[u8], base: Addr) -> Option<UnflattenResult>`.
- `JunkRemovalPass::run(&self, data, ...) -> ...` (line 698) — esegue rimozione junk.
- `MhcdePipelineResult::apply_all(&self, buf: &mut [u8]) -> usize`.

### Free
- `run_mhcde_pipeline(...)` — entry-point della pipeline combinata.

---

## src/multi_stage_deobf.rs

### `StageKind`
- `name(self) -> &'static str`.
- `is_xor_based(self) -> bool`.

### `Stage`
- `new(name: impl Into<String>, kind: StageKind, key: Vec<u8>, confidence: f32) -> Self`.
- `apply(&self, data: &[u8]) -> Option<Vec<u8>>` — applica lo stage al buffer.

### `StageResult`
- `new(stage_name: String, input: &[u8], output: Vec<u8>, confidence: f32) -> Self`.
- `looks_decoded(&self) -> bool`.

### `LayerStack`
- `new() -> Self`.
- `push(&mut self, result: StageResult)`.
- `final_bytes(&self) -> &[u8]`.
- `depth(&self) -> usize`.
- `total_entropy_reduction(&self) -> f64`.

### `StageDetector`
- `new() -> Self`.
- `detect(&self, data: &[u8]) -> Vec<Stage>`.

### `MultiStageDeobf`
- `new() -> Self`.
- `with_max_depth(self, n: usize) -> Self`.
- `with_min_confidence(self, c: f32) -> Self`.
- `apply_stage(&self, data: &[u8], stage: &Stage) -> Option<StageResult>`.
- `deobfuscate_auto(&self, data: &[u8]) -> LayerStack` — auto-detect + chain.
- `deobfuscate_stages(&self, data: &[u8], stages: &[Stage]) -> LayerStack`.
- `compute_hash(data: &[u8]) -> String`.

### `VtClient`
- `new() -> Self`.
- `with_api_key(self, key: impl Into<String>) -> Self`.
- `register_malicious(&mut self, hash: impl Into<String>)`.
- `check(&mut self, data: &[u8]) -> VtResult`.

### `VtResult`
- `detection_ratio(&self) -> f32`.

---

## src/hypothesis_validator.rs

### `ValidationCriteria`
- `lenient() -> Self`, `strict() -> Self`, `for_kind(kind: HypothesisKind) -> Self`.

### `ValidationResult`
- `is_high_quality(&self) -> bool`, `is_acceptable(&self) -> bool`.

### `HypothesisValidator`
- `new(criteria: ValidationCriteria) -> Self`, `default() -> Self`, `for_kind(kind: HypothesisKind) -> Self`.
- `validate(&self, output: &[u8], kind: HypothesisKind) -> ValidationResult`.
- `select_best<'a>(...) -> ...` — sceglie il miglior validato.

### Free
- `is_valid_code(data: &[u8]) -> bool`.
- `is_plausible_code(data: &[u8]) -> bool`.
- `quality_score(data: &[u8]) -> f64`.

### `BatchValidator`
- `new() -> Self`, `with_criteria(criteria: ValidationCriteria) -> Self`.
- `validate_all<'a>(...) -> ...`.
- `pass_count(&self, results: &[ValidationResult]) -> usize`.
- `mean_quality(&self, results: &[ValidationResult]) -> f64`.

---

## src/hypothesis_manager.rs

### `DeobfPassSpec`
- `new(name: impl Into<String>, category: impl Into<String>) -> Self`.
- `with_param(self, key, value) -> Self`.

### `QualityMetrics`
- `compute(output: &[u8]) -> Self`, `is_promising(&self) -> bool`.

### `Hypothesis` (modulo)
- `new(id: HypothesisId, passes: Vec<DeobfPassSpec>) -> Self`.
- `fork(&self, extra_pass: DeobfPassSpec, new_id: HypothesisId) -> Self`.
- `complete(&mut self, output: Vec<u8>)`, `fail(&mut self, error: impl Into<String>)`.
- `composite_score(&self) -> f64`.

### `HypothesisManager`
- `new(top_k: usize, min_score: f64) -> Self`.
- `create(&mut self, passes: Vec<DeobfPassSpec>) -> HypothesisId`.
- `fork(&mut self, parent_id: HypothesisId, extra_pass: DeobfPassSpec) -> Option<HypothesisId>`.
- `complete(&self, id: HypothesisId, output: Vec<u8>) -> bool`.
- `fail(&self, id: HypothesisId, error: impl Into<String>) -> bool`.
- `prune(&mut self) -> Vec<HypothesisId>` — taglia ipotesi scadenti.
- `best(&self) -> Option<Hypothesis>`.
- `by_state(&self, state: HypothesisState) -> Vec<Hypothesis>`.
- `pending_ids(&self) -> Vec<HypothesisId>`.
- `status_summary(&self) -> HashMap<String, usize>`.

### `HypothesisGenerator` (helper)
- `generate(&self, manager: &mut HypothesisManager) -> Vec<HypothesisId>`.

---

## src/hypothesis_generator.rs

### `HypothesisKind`
- `label(self) -> &'static str`, `base_prior(self) -> f64`.

### `Hypothesis` (modulo)
- `new(...)` — costruisce ipotesi.
- `with_parameter(self, param) -> Self`, `with_evidence(self, ev) -> Self`.
- `with_priority(self, p: u32) -> Self`.
- `posterior(prior: f64, likelihood: f64) -> f64` — Bayes update.
- `is_viable(&self) -> bool`.

### `HypothesisGenerator`
- `new(config: HypothesisGeneratorConfig) -> Self`, `default() -> Self`.
- `generate(&mut self, data: &[u8]) -> Vec<Hypothesis>`.
- `confidence_map(&mut self, data: &[u8]) -> HashMap<HypothesisKind, f64>`.

### Free
- `confidence_score(data: &[u8]) -> f64`.
- `top_hypothesis_kind(data: &[u8]) -> Option<HypothesisKind>`.
- `viable_hypotheses(data: &[u8]) -> Vec<Hypothesis>`.

---

## src/hypothesis_engine.rs

### `Algorithm`
- `name(&self) -> String`, `cost_estimate(&self) -> u32`.

### `ParamSet`
- `new() -> Self`.
- `set_str(&mut self, key, value)`, `set_int(&mut self, key, value: i64)`, `set_float(&mut self, key, value: f64)`.
- `get_float(&self, key: &str) -> Option<f64>`, `get_int(&self, key) -> Option<i64>`, `get_str(&self, key) -> Option<&str>`.

### `Hypothesis`
- `new(id: u64, label, algorithm: Algorithm, confidence: f64) -> Self`.
- `with_param(self, key, value: serde_json::Value) -> Self`.
- `with_evidence(self, tag) -> Self`.
- `with_confidence(self, c: f64) -> Self`, `with_generation(self, g: u32) -> Self`.
- `priority_score(&self) -> f64`.

### `HypothesisPool`
- `new() -> Self`.
- `insert(&mut self, h: Hypothesis) -> Result<(), HypothesisEngineError>`.
- `next_id(&mut self) -> u64`.
- `peek_best(&self) -> Option<&Hypothesis>`, `pop_best(&mut self) -> Option<Hypothesis>`.
- `top_n(&self, n: usize) -> Vec<&Hypothesis>`.
- `len(&self) -> usize`, `is_empty(&self) -> bool`.
- `remove(&mut self, id: u64) -> bool`.
- `boost_confidence(&mut self, id: u64, delta: f64) -> Result<(), HypothesisEngineError>`.
- `all_sorted(&self) -> Vec<&Hypothesis>`.

### `HypothesisEngine`
- `new(min_confidence: f64) -> Self`.
- `add_hypothesis(...)` — registra ipotesi.
- `generate_from_features(&mut self, features: &FeatureObservation) -> Vec<u64>`.
- `combine_top_k(&mut self, k: usize) -> Result<Hypothesis, HypothesisEngineError>`.
- `pool(&self) -> &HypothesisPool`, `pool_mut(&mut self) -> &mut HypothesisPool`.

### `FeatureObservation`
- `from_bytes(data: &[u8]) -> Self`.

---

## src/hypothesis_combiner.rs

### `CombinationConstraint`
- `min_weight(strategy: impl Into<String>, min: f64) -> Self`.
- `max_weight(strategy: impl Into<String>, max: f64) -> Self`.
- `is_satisfied(&self, cs: &CombinedStrategy) -> bool`.

### Free
- `validate_constraints(cs: &CombinedStrategy, constraints: &[CombinationConstraint]) -> bool`.

### `EvaluationHistory`
- `new() -> Self`.
- `push(&mut self, weights: HashMap<String, f64>, quality: f64, accepted: bool)`.
- `len(&self) -> usize`, `is_empty(&self) -> bool`.
- `mean_quality(&self) -> f64`, `best_quality(&self) -> f64`, `accepted_count(&self) -> usize`.
- `sorted_by_quality(&self) -> Vec<&EvaluationRecord>`.

### `Strategy`
- `new(name: impl Into<String>, weight: f64) -> Self`.
- `disabled(self) -> Self`.
- `is_significant(&self) -> bool`.

### `CombinedStrategy`
- `uniform(names: &[&str]) -> Self`.
- `from_map(map: HashMap<String, f64>) -> Self`.
- `normalise(&mut self)`.
- `weight_for(&self, name: &str) -> f64`.
- `active_names(&self) -> Vec<&str>`.
- `is_valid(&self) -> bool`, `active_count(&self) -> usize`.

### `CombinedResult`
- `new(strategy: CombinedStrategy, quality: f64) -> Self`.
- `set_strategy_quality(&mut self, name: impl Into<String>, q: f64)`.
- `dominant_strategy(&self) -> Option<&str>`.
- `summary(&self) -> String`.

### `CombinedResultPool`
- `new() -> Self`, `push(&mut self, result: CombinedResult)`, `best(&self) -> Option<&CombinedResult>`.
- `len(&self) -> usize`, `is_empty(&self) -> bool`.
- `sorted_by_quality(&self) -> Vec<&CombinedResult>`.
- `above_threshold(&self, threshold: f64) -> Vec<&CombinedResult>`.

### `BestCombination`
- `new() -> Self`, `update(&mut self, result: CombinedResult) -> bool`.
- `best_quality(&self) -> f64`, `has_result(&self) -> bool`.

### `WeightMap`
- `new(entries: Vec<(String, f64)>) -> Self`.
- `normalise(&mut self)`, `get(&self, name: &str) -> f64`.
- `to_combined_strategy(&self) -> CombinedStrategy`.
- `l2_distance(&self, other: &Self) -> f64`.

### `StrategyMetric`
- `new(name: impl Into<String>) -> Self`, `record(&mut self, quality: f64)`.

### `StrategyRegistry`
- `new() -> Self`.
- `register(&mut self, name: impl Into<String>)`.
- `record(&mut self, strategy: &str, quality: f64)`.
- `update_recommendations(&mut self)`.
- `recommended(&self) -> Vec<&str>`, `best_strategy(&self) -> Option<&str>`.
- `len(&self) -> usize`, `is_empty(&self) -> bool`.

### `GridSearchSolver`
- `new<F>(strategies: Vec<String>, oracle: F) -> Self`.
- `find_best(&self) -> Option<(CombinedResult, Vec<String>)>`.

### `EvolutionarySolver`
- `new<F>(strategies: Vec<String>, oracle: F) -> Self`.
- `evolve(&self) -> Option<CombinedResult>`.

### `HillClimber`
- `new<F>(strategies: Vec<String>, oracle: F) -> Self`.
- `with_step_size(self, s: f64) -> Self`, `with_max_iterations(self, n: usize) -> Self`.
- `run(&self) -> (BestCombination, CombinationHistory)`.

### `OracleEvaluator`
- `evaluate(&self, strategy: &CombinedStrategy) -> CombinedResult`.
- `best_single_strategy(&self) -> Option<(&str, f64)>`.

---

## src/concurrent_deobf_executor.rs

### `ExecutionResult`
- `is_high_quality(&self) -> bool`.

### `BestResult`
- `best_output<'a>(&'a self, original: &'a [u8]) -> &'a [u8]`.

### `ConcurrentDeobfExecutor`
- `new(config: ExecutorConfig) -> Self`, `default() -> Self`.
- `execute(&self, data: &[u8], hypotheses: Vec<Hypothesis>) -> BestResult`.
- `execute_top_n(...)` — esegue solo le prime N ipotesi.
- `config(&self) -> &ExecutorConfig`.

### Free
- `executor_pool(threads: usize) -> ConcurrentDeobfExecutor`.
- `fast_executor() -> ConcurrentDeobfExecutor`.
- `thorough_executor() -> ConcurrentDeobfExecutor`.

### `ResultAggregator`
- `new() -> Self`, `push(&mut self, result: ExecutionResult)`.
- `extend_from_best(&mut self, best: BestResult)`.
- `best(&self) -> Option<&ExecutionResult>`.
- `viable(&self) -> Vec<&ExecutionResult>`.
- `by_kind(&self) -> HashMap<HypothesisKind, Vec<&ExecutionResult>>`.
- `mean_score(&self) -> f64`.
- `len(&self) -> usize`, `is_empty(&self) -> bool`, `clear(&mut self)`.

---

## src/control_flow_graph_builder.rs

### `BasicBlock`
- `new(start: Addr, end: Addr, term: TermKind) -> Self`.
- `len(&self) -> u64`, `is_entry(&self) -> bool`, `contains(&self, addr: Addr) -> bool`.

### `ControlFlowGraph`
- `size(&self) -> usize`.
- `iter_blocks(&self) -> impl Iterator<Item = &BasicBlock>`.
- `block(&self, addr: Addr) -> Option<&BasicBlock>`.
- `back_edges(&self) -> Vec<(Addr, Addr)>`.
- `dominates(&self, a: Addr, b: Addr) -> bool`.
- `block_count(&self) -> usize`, `edge_count(&self) -> usize`.
- `reverse_post_order(&self) -> Vec<Addr>`.

### Decoder helpers (associate)
- `estimate_len(data: &[u8], off: usize) -> usize`.
- `classify_terminator(...) -> ...`.

### `CfgBuilder`
- `new(base: Addr) -> Self`.
- `build(&self, data: &[u8], entry: Addr) -> ControlFlowGraph`.

### `Dominators`
- `compute(cfg: &ControlFlowGraph) -> Self`.

---

## src/deobf_orchestrator.rs

### `PassCategory`
- `cost(self) -> u32`.

### `PassDescriptor`
- `new(spec: DeobfPassSpec, category: PassCategory) -> Self`.
- `with_prereq(self, prereq: PassCategory) -> Self`.
- `with_gain(self, gain: f32) -> Self`.
- `repeatable(self, max: u32) -> Self`.

### `PassRegistry`
- `default_registry() -> Self`.
- `add(&mut self, desc: PassDescriptor)`.
- `find(&self, name: &str) -> Option<&PassDescriptor>`.
- `sorted_by_gain(&self) -> Vec<&PassDescriptor>`.

### `DeobfOrchestrator`
- `new(config: OrchestratorConfig) -> Self`.
- `register_pass(&mut self, desc: PassDescriptor)`.
- `run(&mut self, initial_data: Vec<u8>) -> OrchestrationReport` — esegue la pipeline.

### `OrchestrationReport`
- `summary(&self) -> String`, `score_delta(&self) -> f64`.

---

## src/combination_solver.rs

### `QualityMeasurement`
- `from_bytes(data: &[u8]) -> Self`.
- `is_better_than(&self, other: &Self) -> bool`.
- `improvement_over(&self, other: &Self) -> f64`.

### `CombinationResult`
- `improved(&self) -> bool`, `summary(&self) -> String`.

### `HypothesisApplier`
- `apply(&self, data: &[u8], hypothesis: &Hypothesis) -> Option<Vec<u8>>`.

### `CombinationSolver`
- `new() -> Self`.
- `with_settings(min_improvement: f64, max_hypotheses: usize) -> Self`.
- `solve(...)` — greedy.
- `solve_exhaustive(...)` — brute force.
- `solve_windowed(...)` — sliding-window.

---

## src/dataflow_propagator.rs

### `VarId`
- `reg(name: impl Into<String>) -> Self`, `stack(off: i64) -> Self`.

### `Lattice`
- `meet(self, other: Self) -> Self`.
- `is_const(self) -> bool`, `const_val(self) -> Option<u64>`.

### `ReachingDefsBlock`
- `new(var: VarId) -> Self`.
- `is_single_def(&self) -> bool`, `is_dead(&self) -> bool`.
- `constant_value(&self) -> Option<u64>`.
- `compute_out(&mut self)`.
- `merge_predecessor(&mut self, pred_out: &HashMap<VarId, BTreeSet<Addr>>) -> bool`.

### `ReachingDefsAnalysis`
- `analyze(...)` — esegue analisi.
- `reaching_defs_at(&self, block: Addr, var: &VarId) -> BTreeSet<Addr>`.

### `Expr`
- `binary(lhs: VarId, op, rhs: VarId) -> Self`.
- `unary(lhs: VarId, op) -> Self`.
- `with_folded(self, val: u64) -> Self`.
- `is_constant(&self) -> bool`, `vars(&self) -> Vec<&VarId>`.

### `AvailableExpressions`
- `compute_out(&mut self)`, `analyze(...)`.
- `available_at(&self, block: Addr) -> &HashSet<Expr>`.

### `ConstantState`
- `meet(&self, other: &Self) -> Self`.
- `set(&mut self, var: VarId, val: Lattice)`.
- `get(&self, var: &VarId) -> Lattice`.

### `ConstantPropagation`
- `run(...)` — propagazione costanti.
- `constants_at_entry(&self, block: Addr) -> Vec<(VarId, u64)>`.

### `LiveVariables`
- `compute_live_in(&mut self)`.
- `analyze(...)`.
- `live_in(&self, addr: Addr) -> BTreeSet<VarId>`.
- `dead_defs_in(&self, addr: Addr) -> Vec<VarId>`.

### `DefUseAnalysis`
- `run(...)`, `build(...) -> ...`.

### Free
- `dead_variables(chains: &HashMap<VarId, DefUseChain>) -> Vec<&VarId>`.
- `single_const_defs(chains: &HashMap<VarId, DefUseChain>) -> Vec<(&VarId, u64)>`.

---

## src/feature_extractor.rs

### `FeatureVector`
- `distance(&self, other: &Self) -> f64`.
- `cosine_similarity(&self, other: &Self) -> f64`.
- `obfuscation_score(&self) -> f64`.
- `to_table(&self) -> String`.

### `FeatureNormalizer`
- `identity() -> Self`.
- `normalize(&self, v: &FeatureVector) -> FeatureVector`.
- `fit(vectors: &[FeatureVector]) -> Self`.

### `FeatureExtractor`
- `new() -> Self`.
- `with_normalizer(normalizer: FeatureNormalizer) -> Self`.
- `extract(&self, data: &[u8]) -> FeatureVector`.
- `extract_raw(data: &[u8]) -> FeatureVector`.

### Free
- `extract_windows(data: &[u8], window_size: usize, step: usize) -> Vec<FeatureVector>`.
- `mean_feature_vector(vectors: &[FeatureVector]) -> FeatureVector`.

---

## src/deobf_oracle.rs

### Strategie XOR/ADD/ROT
- `XorStrategy::new(key: u8) -> Self`.
- `AddStrategy::new(delta: u8) -> Self`.
- `RotStrategy::new(rotation: u8) -> Self`.

### `OracleResult`
- `score(&self) -> f32`.
- `is_good(&self, threshold: f32) -> bool`.

### `OracleConfig`
- `unlimited() -> Self`.
- `with_min_quality(self, q: f32) -> Self`.
- `with_top_k(self, k: usize) -> Self`.

### `DeobfOracle`
- `new() -> Self`, `empty() -> Self`.
- `with_config(config: OracleConfig) -> Self`.
- `register(&mut self, strategy: Arc<dyn OracleStrategy>)`.
- `register_defaults(&mut self)`.
- `query(&self, input: &[u8]) -> Vec<OracleResult>` — tutte le strategie.
- `best(&self, input: &[u8]) -> Option<OracleResult>`.
- `strategy_count(&self) -> usize`.
- `scorer(&self) -> &EntropyScorer`, `config(&self) -> &OracleConfig`.

### `CachedOracle`
- `new(capacity: usize) -> Self`.
- `from_oracle(oracle: DeobfOracle, capacity: usize) -> Self`.
- `best(&self, input: &[u8]) -> Option<OracleResult>`.
- `cache_size(&self) -> usize`, `clear_cache(&self)`.
- `oracle(&self) -> &DeobfOracle`.

---

## src/entropy_scorer.rs

### `EntropyScorer`
- `new() -> Self`.
- `shannon_entropy(data: &[u8]) -> f64`.

### `PrintableScorer`
- `new() -> Self`, `with_target(target_ratio: f32) -> Self`.
- `printable_count(data: &[u8]) -> usize`, `printable_ratio(data: &[u8]) -> f32`.

### `StructureScorer`
- `new() -> Self`.
- `detect_structures(data: &[u8]) -> Vec<StructureHit>`.

### `CompositeScore`
- `is_good(&self, threshold: f32) -> bool`.
- `component(&self, name: &str) -> Option<f32>`.
- `tier(&self) -> &'static str`.

### `CompositeScorer`
- `new() -> Self`, `empty() -> Self`.
- `add_metric(&mut self, metric: Box<dyn DeobfMetric>)`.
- `score(&self, data: &[u8]) -> CompositeScore`.
- `is_better(&self, a: &[u8], b: &[u8]) -> bool`.
- `metric_count(&self) -> usize`.

### `ScoreHistory`
- `new(capacity: usize) -> Self`.
- `push(&mut self, score: f32)`.
- `latest(&self) -> Option<f32>`, `best(&self) -> Option<f32>`, `average(&self) -> f32`.
- `is_improving(&self) -> bool`.
- `is_stagnant(&self, window: usize, delta: f32) -> bool`.
- `len(&self) -> usize`, `is_empty(&self) -> bool`, `clear(&mut self)`, `all(&self) -> Vec<f32>`.
