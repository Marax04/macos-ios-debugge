# rustre-yara-engine — Public API

Pure-Rust YARA-compatible rule matching engine, plus `yara-x`-backed scanner, profiler, distributed scanning, PE module, and VM.

Public function count: **347** (inherent `impl` methods, free `pub fn`, and associated constructors across all `src/*.rs`).

Listed below are public function signatures grouped by file. Inherent methods note the owning type. Trait impls, `Default`/`Display`/`Debug` impls, and private helpers are excluded.

---

## src/lib.rs

### `impl YaraRule`
- `new(name: String) -> Self` — construct rule with default namespace.
- `with_tag(self, tag: String) -> Self` — append a tag (builder).
- `with_meta(self, key: String, value: MetaValue) -> Self` — insert metadata.
- `with_string(self, s: YaraString) -> Self` — append a string pattern.
- `with_condition(self, condition: Condition) -> Self` — set condition AST.

### `impl YaraScanner` (pure-Rust scanner)
- `const new() -> Self` — empty scanner.
- `add_rule(&self, rule: YaraRule)` — push a rule under RwLock.
- `rule_count(&self) -> usize` — number of loaded rules.
- `scan(&self, data: &[u8]) -> Vec<RuleMatch>` — evaluate all rules over bytes.
- `scan_names(&self, data: &[u8]) -> Vec<String>` — same as scan but returns names only.

### `impl YaraParser`
- `const new() -> Self`
- `parse_rule(&self, text: &str) -> Result<YaraRule, YaraError>` — parse one rule (subset of YARA syntax).
- `parse_rules(&self, text: &str) -> Result<Vec<YaraRule>, YaraError>` — split text by `rule` blocks.

### `impl YaraRuleDefinition` (yara-x backing form)
- `new(id: impl Into<String>, source: impl Into<String>) -> Self`
- `parse_name_from_source(src: &str) -> Option<String>` — pull `rule NAME` from source.
- `with_namespace(self, ns: impl Into<String>) -> Self`
- `with_tag(self, tag: impl Into<String>) -> Self`
- `with_meta(self, key, value: impl Into<String>) -> Self`

### `impl YaraRuleSet`
- `const new() -> Self`
- `add_rule(&mut self, source: &str) -> Result<(), YaraError>` — push raw source.
- `add_file(&mut self, path: &Path) -> Result<u32, YaraError>` — load .yar(a) file; returns parsed rule count.
- `add_directory(&mut self, dir: &Path) -> Result<u32, YaraError>` — recursive .yar(a) loader.
- `compile(&mut self) -> Result<(), YaraError>` — invoke yara-x compiler.
- `const len(&self) -> usize`
- `const is_empty(&self) -> bool`
- `const is_compiled(&self) -> bool`

### `impl YaraEngineScanner` (yara-x backed)
- `new(ruleset: &mut YaraRuleSet) -> Result<Self, YaraError>` — compile if needed, take ownership of compiled rules.
- `scan_bytes(&self, data: &[u8]) -> Vec<YaraMatch>`
- `scan_file(&self, path: &Path) -> Result<Vec<YaraMatch>, YaraError>`
- `scan_directory(&self, dir: &Path) -> Result<HashMap<PathBuf, Vec<YaraMatch>>, YaraError>` — walk + scan.
- `scan_process(&self, _pid: u32) -> Result<Vec<YaraMatch>, YaraError>` — process scan stub.
- `rules_arc(&self) -> Arc<yara_x::Rules>` — share compiled rules.

### `impl RuleSetBuilder`
- `new() -> Self`
- `add(&mut self, name, source: impl Into<String>) -> &mut Self`
- `enable(&mut self, name: &str) -> &mut Self`
- `disable(&mut self, name: &str) -> &mut Self`
- `contains(&self, name: &str) -> bool`
- `const len(&self) -> usize`
- `const is_empty(&self) -> bool`
- `enabled_count(&self) -> usize`
- `compile_enabled(&self) -> Result<YaraEngineScanner, YaraError>`
- `builtin_rules() -> Self` — preset built-in ruleset.

### Region scanning
- `RegionScanResult::new(region_id: impl Into<String>, matches: Vec<YaraMatch>) -> Self`
- `RegionScanResult::const has_matches(&self) -> bool`
- `RegionScanResult::total_patterns(&self) -> usize`
- `ScanConfig::with_concurrency(self, n: usize) -> Self`
- `ScanConfig::const with_max_region_size(self, sz: usize) -> Self`
- `ScanConfig::const with_min_region_size(self, sz: usize) -> Self`
- `ScanConfig::const should_scan(&self, size: usize) -> bool`

### `impl ExternalSymbol`
- `bool(name: impl Into<String>, value: bool) -> Self`
- `int(name: impl Into<String>, value: i64) -> Self`
- `float(name: impl Into<String>, value: f64) -> Self`
- `str(name: impl Into<String>, value: impl Into<String>) -> Self`

### PE/ELF/Mach-O module inspectors (built-in symbol sources)
- `PeInfo::from_bytes(data: &[u8]) -> Self`
- `PeInfo::to_external_symbols(&self) -> Vec<ExternalSymbol>`
- `ElfInfo::from_bytes(data: &[u8]) -> Self`
- `ElfInfo::to_external_symbols(&self) -> Vec<ExternalSymbol>`
- `MachoInfo::from_bytes(data: &[u8]) -> Self`
- `MachoInfo::to_external_symbols(&self) -> Vec<ExternalSymbol>`
- `pub fn compute_entropy(data: &[u8]) -> f64` — Shannon entropy free function.

### Rule cache
- `RuleCache::new() -> Self`
- `RuleCache::hash_sources(sources: &[&str]) -> u64`
- `RuleCache::get(&self, hash: u64) -> Option<Arc<yara_x::Rules>>`
- `RuleCache::insert(&self, hash: u64, rules: Arc<yara_x::Rules>)`
- `RuleCache::clear(&self)`
- `RuleCache::len(&self) -> usize`
- `RuleCache::is_empty(&self) -> bool`
- `RuleCache::get_or_compile(&self, sources: &[&str]) -> Result<Arc<yara_x::Rules>, YaraError>`

### Process region scanning
- `ProcessRegion::new(base: u64, size: usize, protection: impl Into<String>) -> Self`
- `ProcessRegion::with_module(self, module: impl Into<String>) -> Self`
- `ProcessScanner::new(ruleset: &mut YaraRuleSet) -> Result<Self, YaraError>`
- `ProcessScanner::scan_regions(&self, regions: &[(ProcessRegion, Vec<u8>)]) -> Vec<RegionScanResult>`
- `ProcessScanner::scan_region(&self, region: &ProcessRegion, data: &[u8]) -> RegionScanResult`
- `ProcessScanner::const engine_scanner(&self) -> &YaraEngineScanner`

---

## src/yara_vm.rs — bytecode VM for compiled conditions

### `impl StackValue`
- `as_bool(&self) -> bool` — coerce to truthiness.
- `as_int(&self) -> i64`
- `as_float(&self) -> f64`
- `const is_undefined(&self) -> bool`

### `impl Stack`
- `const new() -> Self`
- `push(&mut self, val: StackValue) -> Result<(), VmError>`
- `pop(&mut self) -> Result<StackValue, VmError>`
- `peek(&self) -> Option<&StackValue>`
- `const depth(&self) -> usize`
- `const is_empty(&self) -> bool`

### `impl Variables`
- `new() -> Self`
- `load(&self, name: &str) -> StackValue`
- `store(&mut self, name: impl Into<String>, val: StackValue)`
- `increment(&mut self, name: &str)`
- `len(&self) -> usize`
- `is_empty(&self) -> bool`

### `impl MatchState`
- `new(file_size: u64) -> Self`
- `set_matches(&mut self, id: impl Into<String>, offsets: Vec<u64>)`
- `matched(&self, id: &str) -> bool`
- `count(&self, id: &str) -> u64`
- `offset(&self, id: &str, n: u32) -> Option<u64>`
- `all_matched(&self) -> bool`
- `any_matched(&self) -> bool`

### `impl YaraVm`
- `const new() -> Self`
- `const with_limit(limit: usize) -> Self`
- `execute(...)` — execute bytecode against match state.
- `run(...)` — full run entry point.

### `impl VmDebugger`
- `const new() -> Self`
- `set_breakpoint(&mut self, ip: u32)`
- `clear_breakpoints(&mut self)`
- `trace_execute(...)` — execute with trace recording.
- `disassemble(program: &[YaraInstruction]) -> String`
- `const trace_len(&self) -> usize`

### `impl OptimizedVm`
- `const new() -> Self`
- `execute(...)`

### Free helpers
- `compile_any_of(patterns: &[&str]) -> Vec<YaraInstruction>`
- `compile_all_of(patterns: &[&str]) -> Vec<YaraInstruction>`
- `compile_filesize_gt(threshold: i64) -> Vec<YaraInstruction>`

---

## src/rule_compiler.rs

### Multi-pattern matcher
- `build(patterns: &[Vec<u8>]) -> Self` — build automaton.
- `search(&self, data: &[u8]) -> Vec<(usize, usize)>` — returns (offset, pattern_id).

### Literal matcher
- `from_literal(pattern: &[u8]) -> Self`
- `run(&self, data: &[u8]) -> Vec<usize>` — return match offsets.

### `impl RuleCompiler`
- `new() -> Self`
- `with_options(options: CompilerOptions) -> Self`
- `compile_rules(&mut self, rules: &[YaraRule]) -> Result<Vec<CompiledRule>, YaraError>`
- `compile_rule(&mut self, rule: &YaraRule) -> Result<CompiledRule, YaraError>`

### Free functions
- `serialize_to_cache(rules: &[CompiledRule]) -> Result<Vec<u8>, YaraError>` — bincode persistence.
- `deserialize_from_cache(data: &[u8]) -> Result<Vec<CompiledRule>, YaraError>`
- `parse_yara_text(source: &str) -> Result<Vec<YaraRule>, YaraError>` — top-level parser entry.

---

## src/performance_profiler.rs

### `impl Timer`
- `const new() -> Self`
- `start(&mut self)`
- `stop(&mut self) -> Duration`
- `const total(&self) -> Duration`
- `average(&self) -> Duration`
- `const samples(&self) -> u64`
- `const reset(&mut self)`

### `impl RuleProfile`
- `new(rule_name: impl Into<String>) -> Self`
- `const avg_ns(&self) -> u64`
- `match_rate(&self) -> f64`
- `throughput_mb_s(&self) -> f64`
- `slowest_string(&self) -> Option<(&str, u64)>`
- `record_string(&mut self, ident: &str, elapsed_ns: u64, matched: bool)`

### `impl CacheStats`
- `hit_rate(&self) -> f64`
- `fill_rate(&self) -> f64`
- `const record_hit(&mut self)`
- `const record_miss(&mut self)`
- `const reset(&mut self)`

### `impl PerformanceProfiler`
- `new() -> Self`
- `begin_rule(&mut self, rule_name: &str)`
- `end_rule(&mut self, rule_name: &str, matched: bool, bytes: usize)`
- `begin_string(&mut self, rule_name: &str, string_id: &str)`
- `end_string(&mut self, rule_name: &str, string_id: &str, matched: bool)`
- `const cache_hit(&mut self)` / `const cache_miss(&mut self)` / `const set_cache_size(&mut self, n: usize)`
- `record_file(&mut self, bytes: usize)`
- `const set_session_ns(&mut self, ns: u64)`
- `slowest_rules(&self, n: usize) -> Vec<&RuleProfile>`
- `hottest_strings(&self, n: usize) -> Vec<HotString>`
- `suggestions(&self) -> Vec<OptimizationSuggestion>` — heuristic optimization tips.
- `session_throughput_mb_s(&self) -> f64`
- `summary_report(&self) -> String`
- `reset(&mut self)`

### `impl ProfilerSession`
- `new() -> Self`
- `finish(self) -> PerformanceProfiler`

---

## src/string_match_engine.rs

### `impl ModifierSet` (bitset)
- `const new() -> Self`
- `const set(self, m: Self) -> Self`
- `const has(self, m: Self) -> bool`
- `const nocase/wide/ascii/fullword/base64/xor(self) -> bool` — accessor predicates.

### `impl HexClass`
- `const to_flag(&self) -> ModifierSet`
- `const matches(&self, byte: u8) -> bool`

### `impl HexPattern`
- `parse(src: &str) -> Result<Self, String>` — parse hex syntax.
- `match_at(&self, data: &[u8], offset: usize) -> Option<usize>` — returns match length.

### `impl YaraString` (engine flavour, builders)
- `new_text(id, text: impl Into<String>, mods: ModifierSet) -> Self`
- `new_hex(id: impl Into<String>, pat: HexPattern, mods: ModifierSet) -> Self`
- `new_regex(id, regex: impl Into<String>, mods: ModifierSet) -> Self`

### `impl ContextWindow`
- `const new(offset: usize, before: usize, after: usize) -> Self`
- `extract<'a>(&self, buf: &'a [u8], match_len: usize) -> &'a [u8]`

### `impl StringMatchEngine`
- `const new() -> Self`
- `const with_max_matches(self, n: usize) -> Self`
- `find_all(&self, ys: &YaraString, data: &[u8]) -> Vec<StringMatch>`
- `match_with_context<'a>(...)` — returns matches with surrounding bytes.

### `impl MultiStringMatcher`
- `new() -> Self`
- `add_string(&mut self, s: YaraString)`
- `match_all(&self, data: &[u8]) -> HashMap<String, Vec<StringMatch>>`
- `total_matches(&self, data: &[u8]) -> usize`
- `matched_ids(&self, data: &[u8]) -> Vec<String>`

### Free
- `parse_modifiers(keywords: &[&str]) -> Result<(ModifierSet, Option<(u8, u8)>), String>` — modifier keywords and optional xor key range.

---

## src/scan_engine.rs

### `impl ScanEngine`
- `new(rules: Vec<YaraRule>, options: ScanOptions) -> Self`
- `with_progress(self, cb: ProgressCallback) -> Self`
- `scan(&self, targets: Vec<ScanTarget>) -> ScanReport` — runs scan campaign over multiple targets.

---

## src/rule_parser_ext.rs

### `impl Lexer<'a>`
- `const new(src: &'a str) -> Self`
- `next_token(&mut self) -> Token`
- `tokenize(&mut self) -> Vec<Token>`

### `impl RuleAst`
- `const has_strings(&self) -> bool`
- `is_trivial(&self) -> bool` — true if condition is `true`.

### `impl BytecodeEmitter`
- `const new() -> Self`
- `emit(cond: &AstCondition, out: &mut Vec<Bytecode>)`
- `emit_rule(&self, cond: &AstCondition, out: &mut Vec<Bytecode>)`

### `impl ExtendedParser`
- `const new() -> Self`
- `compile(&self, src: &str) -> Result<CompiledRule, String>` — single rule.
- `compile_all(&self, src: &str) -> Vec<Result<CompiledRule, String>>` — all rules in source.

---

## src/string_modifier_engine.rs

### `impl ModifierContext` (constructors)
- `nocase() -> Self`, `wide() -> Self`, `wide_ascii() -> Self`, `fullword() -> Self`
- `xor_all() -> Self`, `xor_range(min: u8, max: u8) -> Self`, `base64() -> Self`

### `impl ModifierEngine`
- `generate_candidates(raw_bytes: &[u8], ctx: &ModifierContext) -> Vec<MatchCandidate>` — expand modifiers into byte variants.
- `filter_fullword(...)` — keep only word-boundary aligned matches.

### Transforms
- `nocase_transform(bytes: &[u8]) -> Vec<u8>` — lowercase ASCII.
- `nocase_wide_transform(wide: &[u8]) -> Vec<u8>`
- `to_wide(ascii: &[u8]) -> Vec<u8>` — ASCII → UTF-16LE.
- `from_wide(wide: &[u8]) -> Vec<u8>`
- `xor_bytes(input: &[u8], key: u8) -> Vec<u8>`
- `all_xor_variants(input: &[u8]) -> Vec<(u8, Vec<u8>)>` — 256 keys.
- `xor_range_variants(input: &[u8], min: u8, max: u8) -> Vec<(u8, Vec<u8>)>`
- `detect_xor_key(plaintext: &[u8], data: &[u8]) -> (u8, usize)` — heuristic key + count.
- `base64_encode(input: &[u8], variant: u8, custom: Option<&[u8; 64]>) -> Vec<u8>`
- `base64_decode_standard(input: &[u8]) -> Option<Vec<u8>>`
- `base64_decode(input: &[u8], alpha: &[u8; 64]) -> Option<Vec<u8>>`
- `scan(data: &[u8], pattern: &[u8], nocase: bool) -> Vec<usize>` — substring scan helper.

### `impl ModifierScanner`
- `const new(ctx: ModifierContext) -> Self`
- `scan_all(&self, pattern: &[u8], data: &[u8]) -> Vec<ScanHit>` — scan with all modifier-expanded variants.
- `xor_key_count(&self) -> usize`

### `impl ModifierStatistics`
- `compute(pattern: &[u8], ctx: &ModifierContext) -> Self` — counts variants and complexity.

---

## src/module_pe.rs — PE inspector accessible from conditions

### `impl PeMachine`
- `const from_u16(v: u16) -> Self`
- `const name(&self) -> &'static str`

### `impl PeSubsystem`
- `const from_u16(v: u16) -> Self`
- `const name(&self) -> &'static str`

### `impl PeSection`
- `const is_executable/is_writable/is_readable(&self) -> bool`

### `impl PeModule`
- `new() -> Self`
- `parse(&mut self, data: &[u8]) -> Result<(), PeModuleError>` — parse DOS+NT headers, sections, imports, exports.
- `const machine_type(&self) -> PeMachine`
- `const subsystem_type(&self) -> PeSubsystem`
- `const has_aslr/has_nx/has_cfg(&self) -> bool`
- `export_by_name(&self, name: &str) -> Option<&PeExport>`
- `imports_from_dll(&self, dll: &str) -> Option<&Vec<PeImport>>`
- `const section_count(&self) -> usize`

---

## src/condition_evaluator.rs

### `impl StringPattern` (wildcard pattern, e.g. `$a*`)
- `matches(&self, name: &str) -> bool`

### `impl EvaluationContext<'_>`
- `const new(...)` — multi-arg constructor wrapping data, file size, matches.
- `resolve_set(&self, set: &StringSet) -> Vec<String>` — expand `them`/wildcards.
- `count(&self, ident: &str) -> usize`
- `present(&self, ident: &str) -> bool`
- `at(&self, ident: &str, offset: u64) -> bool`
- `within(&self, ident: &str, lo: u64, hi: u64) -> bool`

### Evaluator entry points
- `Evaluator::eval(expr: &Expr, ctx: &EvaluationContext<'_>) -> bool`
- `Evaluator::eval_value(expr: &Expr, ctx: &EvaluationContext<'_>) -> Value`
- `Evaluator::eval_legacy(...)` — old AST path.

### Quantifiers
- `eval_n_of(...)`
- `eval_for_n_of(...)`
- `eval_for_all_of(results: &[bool]) -> bool`
- `eval_for_any_of(results: &[bool]) -> bool`
- `eval_for_none_of(results: &[bool]) -> bool`
- `expand_wildcard(pattern: &StringPattern, strings: &[YaraString]) -> Vec<String>`

### Other condition helpers
- `Conditions::eval(...)` — top-level boolean dispatch.
- `at(ident: &str, offset: u64, ctx: &EvaluationContext<'_>) -> bool`
- `in_range(ident: &str, lo: u64, hi: u64, ctx: &EvaluationContext<'_>) -> bool`
- `offsets_in_range(...)`
- `compare(data_len: usize, op: CompOp, value: u64) -> bool` — filesize-style compare.
- `parse_size(s: &str) -> Option<u64>` — parse `1KB`/`2MB` suffixed sizes.

---

## src/string_matcher.rs

### `impl MatcherConfig`
- `ascii_only() -> Self`
- `wide_and_ascii() -> Self`
- `describe(&self) -> String`

### `impl MatchResult`
- `new(offset: usize, matched_bytes: Vec<u8>, string_id: impl Into<String>) -> Self`
- `xor_match(...)` — variant carrying the recovered XOR key.

### Encoding helpers
- `to_wide(ascii: &[u8]) -> Vec<u8>`
- `from_wide(wide: &[u8]) -> Vec<u8>`
- `is_wide_at(data: &[u8], offset: usize, len: usize) -> bool`

### Multi-pattern matcher
- `MultiPatternMatcher::const new(patterns: Vec<(String, Vec<u8>)>) -> Self`
- `find_all(&self, data: &[u8]) -> Vec<(String, usize)>`
- `const pattern_count(&self) -> usize`

### `impl StringMatcher` (high level)
- `new() -> Self`
- `add_text(...)` / `add_hex(...)` / `add_regex(...)` — register patterns of each kind.
- `scan(&self, data: &[u8]) -> Vec<PatternMatch>`
- `scan_one(&self, data: &[u8], id: &str) -> Vec<PatternMatch>`
- `string_count(&self) -> usize`

---

## src/distributed_scan.rs

### `impl ScanJob`
- `new_memory(label: impl Into<String>, data: Vec<u8>) -> Self`
- `new_file(path: impl Into<String>) -> Self`
- `const with_priority(self, p: Priority) -> Self`
- `with_tag(self, key, value: impl Into<String>) -> Self`
- `is_expired(&self) -> bool`

### `impl WorkerNode`
- `local(id: impl Into<String>) -> Self`
- `remote(id, address: impl Into<String>) -> Self`

### `impl JobQueue`
- `new() -> Self`
- `submit(&self, job: ScanJob) -> Option<JobId>`
- `drain_expired(&self) -> u64`
- `pop(&self) -> Option<ScanJob>`
- `record_result(&self, result: JobResult)`
- `get_result(&self, job_id: JobId) -> Option<Arc<JobResult>>`
- `pending(&self) -> usize`
- `stats_snapshot(&self) -> (u64, u64, u64)` — (submitted, completed, expired).

### `impl DistributedScanner`
- `new(rules: Vec<YaraRule>, workers: Vec<WorkerNode>) -> Self`
- `submit(&self, job: ScanJob) -> Option<JobId>`
- `submit_batch(&self, jobs: Vec<ScanJob>) -> (usize, usize)` — (accepted, rejected).
- `run_local(&self) -> AggregatedReport` — drain queue using local worker.
- `get_result(&self, job_id: JobId) -> Option<Arc<JobResult>>`
- `pending(&self) -> usize`
- `shutdown(&self)`
- `is_shutdown(&self) -> bool`

### Result dedup
- `pub fn deduplicate_results(results: &[JobResult]) -> Vec<UniqueMatch>` — merge duplicate matches across jobs.

### `impl RemoteWorkerClient`
- `new(base_url: impl Into<String>) -> Self`
- `with_api_key(self, key: impl Into<String>) -> Self`
- `submit_remote(&self, job: &ScanJob) -> Result<JobId, String>`
- `poll_result(&self, job_id: JobId) -> Result<Option<JobResult>, String>`

---

## src/match_context.rs

### `impl SectionRange`
- `const contains_offset(&self, offset: u64) -> bool`
- `const is_executable(&self) -> bool`
- `const is_data(&self) -> bool`

### `impl MatchedBytes`
- `as_utf8(&self) -> Option<&str>`

### `impl EntropyStats`
- `compute(data: &[u8], offset: u64, length: usize) -> Self` — Shannon entropy in window.
- `is_high_entropy_context(&self) -> bool`

### `impl DisasmHint`
- `display(&self) -> String`
- `pub fn disasm_hint(...) -> Option<DisasmHint>` — free helper classifying bytes around a match.

### `impl MatchContextBuilder`
- `build(...)` — assemble `MatchContext` from data + offset + length.
- `add_capture(&mut self, grp: CaptureGroup)`
- `set_meta(&mut self, key, value: impl Into<String>)`
- `is_in_code_section(&self) -> bool`
- `const is_in_overlay(&self) -> bool`
- `summary(&self) -> String`

### PE classifiers (free)
- `classify_pe_offset(...)` — return `SectionRange` for offset.
- `parse_pe_sections(data: &[u8]) -> Vec<PeSectionRange>`

### `impl ContextEngine`
- `for_pe(data: &[u8], arch: DisasmArch) -> Self`
- `const for_raw(arch: DisasmArch) -> Self`
- `build(...)` — produce a `MatchContext`.
- `sections(&self) -> &[PeSectionRange]`

---

## src/condition_expr_eval.rs

### `impl StringMatchState`
- `new() -> Self`
- `add_matches(&mut self, id: &str, offsets: Vec<u64>)`
- `string_matched(&self, id: &str) -> bool`
- `string_count(&self, id: &str) -> u64`
- `string_at(&self, id: &str, offset: u64) -> bool`
- `string_in(&self, id: &str, from: u64, to: u64) -> bool`

### `impl ExprValue`
- `const as_int(&self) -> Option<i64>`
- `const as_bool(&self) -> Option<bool>`

### `impl EvalResult`
- `const as_bool(&self) -> Option<bool>`
- `as_int(&self) -> Option<i64>`
- `const is_undefined(&self) -> bool`

### `impl ConditionEvaluator`
- `new() -> Self`
- `with_file_bytes(self, bytes: Vec<u8>) -> Self`
- `eval(&self, expr: &ConditionExpr, ctx: &EvalContext) -> EvalResult` — full expression evaluator.

### `impl CompiledCondition`
- `new(rule_name: impl Into<String>, condition: ConditionExpr) -> Self`
- `evaluate(&self, eval: &ConditionEvaluator, ctx: &EvalContext) -> bool`

---

## Summary

- Total public functions/methods (across all modules): **347**.
- Primary entry points: `YaraScanner` (pure Rust), `YaraEngineScanner` / `YaraRuleSet` (yara-x backed), `RuleSetBuilder`, `DistributedScanner`, `ProcessScanner`.
- Supporting subsystems: bytecode VM (`yara_vm`), rule compiler / cache, performance profiler, string/modifier engines, condition AST evaluator, PE module + match context analyser.
