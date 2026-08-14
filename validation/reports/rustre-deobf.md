# rustre-deobf — Public API

Crate dedicato a deobfuscation: pipeline di pass, riconoscimento pattern, normalizzazione CFG, costant folding, dead-code elimination, opaque predicates, junk code removal, decifratura crypto leggera, reportistica.

## casts.rs — conversioni numeriche checked
- `usize_to_f64(x: usize) -> f64` — cast lossy controllato.
- `usize_to_f32(x: usize) -> f32` — cast lossy controllato.
- `u64_to_f64(x: u64) -> f64` — cast con troncamento.
- `u64_to_f32(x: u64) -> f32` — cast con troncamento.
- `f64_to_u32(x: f64) -> u32` — cast con saturazione.
- `u128_to_u64(x: u128) -> u64` — troncamento basso 64-bit.
- `usize_to_u32(x: usize) -> u32` — troncamento.
- `usize_to_u8(x: usize) -> u8` — troncamento.

## lib.rs — API principale

### Pass registry / pipeline
- `DeobfPassSet::all() -> Vec<Box<dyn DeobfPass>>` — elenco di tutti i pass built-in.
- `Patch::new(...) -> Self` — costruisce un patch (offset/dati/metadata).
- `Patch::apply(&self, data: &mut [u8]) -> Result<(), DeobfError>` — applica un patch in-place.
- `DeobfContext::new(binary: Vec<u8>) -> Self` — crea contesto da binario.
- `DeobfContext::va_to_file_offset(&self, va: u64) -> Option<u64>` — converte VA→offset file.
- `DeobfContext::add_segment(&mut self, mapping: SegmentMapping)` — registra mapping segmento.
- `DeobfContext::apply_patches(&self) -> Result<Vec<u8>, DeobfError>` — produce binario patchato.
- `DeobfContext::set_meta(&mut self, key, value: serde_json::Value)` — meta-dato libero.
- `DeobfContext::get_meta(&self, key: &str) -> Option<&serde_json::Value>` — lettura meta.
- `PipelineResult::merge(&mut self, other: &Self)` — fonde due risultati.
- `DeobfPipeline::new() -> Self` / `with_options(DeobfOptions) -> Self`.
- `DeobfPipeline::add_pass(&mut self, pass: Box<dyn DeobfPass>)`.
- `DeobfPipeline::run_all(&self, ctx: &mut DeobfContext) -> PipelineResult`.
- `DeobfPipeline::pass_count(&self) -> usize`.
- `DeobfPipeline::run(&self, ctx: &mut DeobfContext) -> Result<DeobfPipelineResult, DeobfError>`.
- `DeobfPipeline::add_pass_arc(&mut self, pass: Arc<dyn DeobfPass>)`.

### Pattern matching
- `PatternScanner::add_pattern(&mut self, name, pattern: Vec<u8>)`.
- `PatternScanner::add_masked_pattern(&mut self, name, pattern, mask: Vec<u8>)`.
- `PatternScanner::scan(&self, data: &[u8]) -> Vec<PatternMatch>` — pattern mascherato.

### Crypto helpers
- `entropy(data: &[u8]) -> f64` — entropia Shannon.
- `recover_single_byte_key(data: &[u8]) -> (u8, Vec<u8>)` — brute key XOR singolo byte.
- `decrypt_constant(data, key: u8) -> Vec<u8>` — XOR singolo byte.
- `decrypt_cyclic(data, key: &[u8]) -> Vec<u8>` — XOR ciclico.
- `decrypt_rolling(data, initial_key: u8) -> Vec<u8>` — XOR rolling.
- `rol(byte, n) -> u8` / `ror(byte, n) -> u8` — rotazioni bit.
- `decrypt_rol(data, rotation) -> Vec<u8>` / `decrypt_ror(data, rotation) -> Vec<u8>`.
- `recover_rotation(data) -> (u8, bool, Vec<u8>)` — inferisce rotazione.
- `most_frequent_byte(data) -> u8`.
- `build_substitution_table(data, assumed_plaintext: u8) -> [u8; 256]`.
- `apply_table(data, table: &[u8; 256]) -> Vec<u8>` — sostituzione mono-alfabetica.
- `Base64::decode(input) -> Option<Vec<u8>>`.
- `Base64::find_all(data) -> Vec<Base64Find>` — scova stringhe base64.
- `try_xor_constant(data, min_length) -> Vec<DecryptedString>`.
- `try_xor_rolling(data, min_length) -> Vec<DecryptedString>`.

### Registry secondario
- `Registry::new()`, `register(pass) -> Option<Box<dyn DeobfPass>>`, `get(name)`, `len`, `is_empty`, `names`.
- `Registry::run_selection(...)` — esegue subset di pass.

### Report / ObfuscationProfile
- `DeobfReport::from_pipeline(PipelineResult) -> Self`.
- `DeobfReport::log_transform(TransformResult)`.
- `DeobfReport::applied_count() -> usize`.
- `ObfuscationProfile::new(binary_name) -> Self`.
- `ObfuscationProfile::add_obfuscation(ty: ObfuscationType, confidence: f64)`.
- `ObfuscationProfile::summary() -> String`.

### RC4 / ChaCha / checksums
- `Rc4::ksa(key) -> [u8; 256]` — key-scheduling.
- `Rc4::prga(s, length) -> Vec<u8>` — keystream.
- `Rc4::decrypt(data, key) -> Vec<u8>`.
- `Rc4::brute_force_short_key(data) -> (Vec<u8>, Vec<u8>)`.
- `ChaCha20::block(key, nonce, counter: u32) -> Result<[u8;64], DeobfError>`.
- `ChaCha20::crypt(data, key, nonce) -> Result<Vec<u8>, DeobfError>`.
- `Crc32::checksum(data) -> u32`, `Adler32::checksum(data) -> u32`, `Fletcher32::checksum_table(data) -> u32`.

### Entropy / Patch / HexDump / NopSled
- `EntropyScanner::new()`, `scan(data) -> Vec<EntropyRegion>`, `max_entropy_region(data) -> Option<EntropyRegion>`.
- `Section::new(name, va: u64, data: Vec<u8>) -> Self`.
- `PatchSet::new()`, `insert(patch) -> bool`, `patches() -> &[Patch]`, `into_patches() -> Vec<Patch>`, `apply_to(data) -> Result<Vec<u8>, DeobfError>`.
- `HexDumper::new()`, `dump(data) -> String`, `hex_only(data) -> String`.
- `NopSledDetector::new()`, `find_sleds(data) -> Vec<(usize, usize)>`.

### Registry per nome (Arc)
- `ArcRegistry::new()`, `register(Arc<dyn DeobfPass>)`, `get(name) -> Option<Arc<dyn DeobfPass>>`, `count`, `names`, `build_pipeline(names, options) -> DeobfPipeline`.

### Job / PipelineGroup
- `Job::new(id, pipeline) -> Self`, `run_on(ctx) -> Result<(), DeobfError>`, `patches_per_pass() -> f64`.
- `PipelineGroup::add_pipeline(p)`, `run(data) -> Result<Vec<u8>, DeobfError>`.

### Heuristic detection
- `Heuristics::add_signature(sig)`, `entropy(data) -> f64`, `is_likely_obfuscated(data) -> bool`.
- `Classifier::new()`, `classify(data)`, `detections() -> &[(ObfuscationType,f64)]`, `most_likely() -> Option<ObfuscationType>`.

### Persistence store
- `Store::new()`, `save_patches(binary_id, Vec<Patch>)`, `save_report(DeobfReport)`, `patches_for(binary_id) -> &[Patch]`.
- `(top-level) run(&self, data: Vec<u8>) -> Result<(Vec<u8>, usize), DeobfError>` — esegue pipeline composta.

## cfg_normalizer.rs
- `CfgNormalizer::is_useless_jump(src_block: &CfgBlock) -> bool` — euristica jump ridondante.
- `CfgBlock::with_label(self, label) -> Self`.
- `NormalizedCfg::block_at(offset) -> Option<&CfgBlock>`.
- `NormalizedCfg::successors_of(offset) -> Vec<usize>`.
- `NormalizedCfg::bfs_order() -> Vec<usize>`.
- `CfgNormalizer::new() -> Self`.
- `CfgNormalizer::normalize(blocks: Vec<CfgBlock>, entry: usize) -> NormalizedCfg` — entry-point normalizzazione.

## constant_folding_pass.rs
- `FoldableExpr::depth() -> usize` — profondità AST.
- `FoldableExpr::node_count() -> usize`.
- `eval_binop(op: BinOp, lhs: i64, rhs: i64) -> Option<i64>` — eval safe.
- `eval_unop(op: UnOp, val: i64) -> i64`.
- `fold_expr(expr, env: &HashMap<String,i64,S>) -> FoldResult` — propagazione costanti.
- `rewrite_expr(expr, env) -> FoldableExpr` — riscrive AST.
- `IrBlock::new(label) -> Self`, `push(target, expr)`.
- `ConstantFolder::new() -> Self`, `with_seeds(HashMap<String,i64>) -> Self`, `fold_function(blocks: &mut [IrBlock]) -> FoldStats`.

## control_flow_normalization.rs
- `BasicBlock::add_successor(target: Addr, kind: EdgeKind)`.
- `NormalizationReport::new() -> Self`, `note(msg)`, `summary() -> String`.
- `JumpThreader::resolve_target(addr, blocks) -> Addr`, `run(blocks, report)`.
- `ReachabilityAnalyzer::reachable(entry, blocks) -> HashSet<Addr>`, `run(...)`.
- `DeadBlockRemover::run(blocks, report)`.
- `NopFolder::new() -> Self`, `is_nop_block(bb) -> bool`, `run(blocks, report)`.
- `recompute_predecessors(blocks: &mut HashMap<Addr,BasicBlock>)`.
- `ControlFlowNormalizer::run(blocks) -> NormalizationReport` — orchestra tutti i sub-pass.
- `Dominators::compute(entry, blocks) -> Self`, `idom_of(block) -> Option<Addr>`, `dominates(dom, block) -> bool`.
- `build_cfg(...)` — costruisce CFG iniziale.

## dead_code_eliminator.rs
- `IrInstr::defs() -> Vec<&Var>` / `uses() -> Vec<&Var>`.
- `DeadInstruction::description() -> String`.
- `LivenessAnalyzer::analyze(blocks) -> HashMap<usize, LivenessSets>`.
- `LivenessAnalyzer::live_before(...)` — set live entrante.
- `DceReport::nops()`, `constant_branches()`, `unused_assignments()` — iteratori.
- `DeadCodeEliminator::eliminate(...)` — rimuove instr morte.
- `DeadCodeEliminator::dfs_reachable(blocks, entry) -> HashSet<usize>`.
- `DeadCodeEliminator::bfs_order(...) -> Vec<usize>`.
- `DeadCodeEliminator::dead_block_count(...) -> usize`.

## deobf_pass_registry.rs
- `PassMetadata::new(...)`, `with_patterns`, `with_dependencies`, `with_version` — builder.
- `PassEntry::new(pass, metadata) -> Self`, `name`, `matches_pattern(pattern) -> bool`.
- `DeobfPassRegistry::new()`, `register(...)`, `register_simple(...)`, `get`, `get_mut`, `get_passes_for_pattern`, `get_by_category`, `set_enabled(name, enabled) -> bool`, `names`.
- `run_pass(name, ctx) -> Result<DeobfResult, DeobfError>`.
- `run_all(...)` — esegue tutti i pass abilitati.
- `stats() -> RegistryStats`.
- `dependents_of(name) -> Vec<&str>`, `validate_dependencies() -> Vec<String>`, `topological_order() -> Option<Vec<&str>>`.
- `get_pass_for_pattern(...)` — lookup top-level.
- `default_registry() -> DeobfPassRegistry` — registry preconfigurato.

## deobf_pipeline.rs
- `PassId::new(id) -> Self`, `as_str() -> &str`.
- `PassResult::failure(pass_id, error, elapsed) -> Self`, `with_snapshot(Vec<u8>) -> Self`, `snapshot() -> Option<&[u8]>`.
- `PipelineConfig::new()`, `disable_pass(id) -> Self`.
- `PipelineResult::record(&PassResult)`, `results_by_confidence`, `failures`, `summary -> String`.
- `Pipeline::new()`, `with_config(config) -> Self`, `add_pass(Box<dyn DeobfPass>)`, `pass_count`, `pass_names`, `run(binary: Vec<u8>) -> PipelineResult`, `dry_run(binary) -> Vec<(String,bool)>`.
- `NopRemoverPass::new(id) -> Self`, `JumpThreaderPass::new(id) -> Self`, `XorDecryptPass::new(id, key: u8) -> Self`.

## deobf_registry.rs
- `PassMetadata::new(...)`, `with_capability`, `with_dependency`, `has_capability`.
- `PassEntry::new(metadata) -> Self`, `with_trigger(metadata, f)`, `triggers_on(binary) -> bool`.
- `DeobfRegistry::new()`, `with_builtins()`, `register(entry) -> Option<PassEntry>`, `register_metadata(meta)`, `deregister(name)`, `get`, `len`, `is_empty`, `names`, `by_category`, `by_capability`, `all_by_priority`, `default_enabled`, `enable`, `disable`.
- `SelectionResult::summary() -> String`.
- `DeobfRegistry::select(binary) -> SelectionResult` — selezione automatica.
- `select_by_category(...)`.

## deobf_report.rs
- `TransformStat::new(category, description) -> Self`.
- `PassSummary::new(pass_id, pass_name) -> Self`, `mark_skipped(reason)`, `add_transform(stat)`, `add_note(note)`, `total_transforms() -> u64`, `bytes_delta() -> i64`, `compression_ratio() -> f64`.
- `Metrics::compute(...)` — calcola metriche.
- `Metrics::score_pct() -> f64`, `improvement_over(baseline) -> f64`.
- `DeobfReport::new(binary_name, binary_size_bytes) -> Self`, `set_hash(sha256)`, `add_pass(PassSummary)`, `add_note`, `add_warning`, `executed_passes`, `failed_passes`, `skipped_passes`, `score_improvement -> f64`, `export(format: ReportFormat) -> String`.
- `ReportBuilder::new(...)`, `hash`, `pass`, `note`, `warning`, `build -> DeobfReport`.
- `MultiReport::add(report)`, `total_strings_recovered`, `total_instructions_modified`, `average_score_improvement`, `most_effective_pass`, `summary_text`.

## deobf_report_extended.rs
- `DeobfTimeline::new(technique, pass_name) -> Self`, `bytes_changed() -> usize`.
- `RecoveredAsset::new(...)`, `with_value(v) -> Self`.
- `ConfidenceMatrix::new()`, `set_detection`, `set_removal`, `detection_for`, `removal_for`, `avg_detection`, `avg_removal`.
- `DeobfReportExtended::new(binary_name, size) -> Self`, `add_technique(t, det, rem)`, `add_timeline(entry)`, `add_asset(asset)`, `compute_overall_confidence`, `asset_count(kind) -> usize`, `techniques_by_category`.
- `MarkdownExporter::generate(report) -> String`.
- `HtmlExporter::generate(report) -> String`.

## junk_code_remover.rs
- `JunkScorer::new()`, `score(pattern) -> u8`, `explain(pattern) -> String`, `merge(other)`.
- `JunkDb::build() -> Self`, `len`, `is_empty`, `get(name)`, `iter`, `insert(entry)`, `scan_bytes(data) -> Vec<(String,usize)>`.
- `JunkCodeRemover::new(threshold) -> Self`, `with_scorer(threshold, scorer) -> Self`, `remove_from_bytes(data) -> (Vec<u8>, RemovalResult)`, `remove_patterns(Vec<JunkPattern>) -> RemovalResult`, `count_removable(data) -> usize`.

## opaque_predicate_resolver.rs
- `ResolutionResult::new(...)`, `is_high_confidence() -> bool`.
- `SymExpr::eq(l,r) -> Self`, `band(l,r)`, `xor(l,r)`, `sym_mul(l,r)`, `sym_rem(l,r)`.
- `is_self_xor_zero(expr) -> bool`, `is_mul_by_zero(expr) -> bool`, `is_always_true_or(expr) -> bool`, `is_consecutive_product_even(expr) -> bool`.
- `eval_const_expr(expr) -> Option<i64>`.
- `OpaquePredicateResolver::new()`, `with_config(ResolverConfig) -> Self`, `reset`, `results -> &[ResolutionResult]`, `classify_symbolic(...)`, `scan_bytes(data) -> Vec<ResolutionResult>`, `apply_hash_heuristic(data)`, `report -> String`.

## pass_manager.rs
- `PassResult::patches_applied() -> usize`, `confidence() -> f32`.
- `PassManager::new()`, `set_listener(f)`, `register(pass) -> Result<(), PassManagerError>`, `add_dependency(...)`, `set_enabled(name, enabled)`, `invalidate_cache`, `len`, `is_empty`, `topological_order -> Result<Vec<String>, PassManagerError>`, `run(ctx) -> Result<PassManagerReport, PassManagerError>`.
- `PassManagerReport::total_patches`, `successful_passes`, `skipped_passes`, `failed_passes`, `average_confidence`, `slowest_passes(n)`.

## pattern_recognition.rs
- `PatternConfidence::with_evidence(ev) -> Self`, `exceeds(threshold) -> bool`.
- `RecognitionResult::score_for(pattern) -> f64`, `patterns_above(threshold) -> Vec<ObfuscationPattern>`, `dominant_pattern() -> Option<ObfuscationPattern>`, `score_map() -> HashMap<&str,f64>`.
- `PatternRecognizer::new()`, `recognize(data) -> RecognitionResult`.

## report.rs
- `PassSummary::from_heuristics(confidence: f32, patches: usize) -> Self`.
- `Finding::new(...)`, `with_meta(key, value) -> Self`.
- `DeobfReport::total_finding_bytes -> usize`, `high_severity_count -> usize`.
- `DeobfReportBuilder::new(binary_name)`, `add_pass(summary) -> Self`, `metadata(key, value: serde_json::Value) -> Self`, `build -> DeobfReport`.
- `PassSummaryBuilder::new(name)`, `finding(Finding) -> Self`, `build -> PassSummary`.
- `DeobfReport::findings_by_severity(min) -> Vec<&Finding>`, `findings_by_confidence -> Vec<&Finding>`, `total_findings -> usize`, `to_json -> Result<String, ReportError>`, `to_json_pretty`, `to_html`, `summary_line -> String`.
