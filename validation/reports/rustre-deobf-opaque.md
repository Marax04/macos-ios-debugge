# rustre-deobf-opaque — Public API Reference

## Purpose
Production-grade opaque predicate detection and elimination pass for the RustRE Suite. An opaque predicate is a conditional branch whose outcome is statically constant but appears non-trivial — used by obfuscators to confuse CFG reconstruction. The crate provides symbolic expression modeling, a static pattern database, truth-table verification, SAT/SMT helpers, CFG cleaners, and a high-level one-shot pass.

## Dependencies
- `rustre-deobf`, `rustre-core` (workspace path deps)
- `serde`

## Modules (15)
`lib` (root) + `constant_propagator`, `dead_branch_eliminator`, `opaque_cfg_cleaner`, `opaque_rewriter`, `pattern_library`, `polynomial_check`, `predicate_simplifier`, `sat_checker`, `smt_prover`, `predicate_detector`, `tautology_db`, `predicate_evaluator`, `conditional_simplifier`, `junk_code_remover`.

---

## lib.rs — Core types & high-level pass

### Types
- `enum PredicateValue` — outcome: AlwaysTrue / AlwaysFalse / DataDependent.
- `enum OpaquePredicateKind` — categoria predicato opaco.
- `enum OpaqueKind` — classificazione fine.
- `enum OpaqueExpr` — AST espressioni simboliche (Const, Var, Add/Sub/Mul/Div/Mod, And/Or/Xor, Not/Neg, Shl/Shr, Eq/Ne/Lt/Le/Gt/Ge, BitCount, Abs, Square).
- `struct KnownOpaquePattern` — voce statica DB pattern.
- `struct TruthTableChecker` — verifica esaustiva/campionata su domini variabili.
- `struct OpaqueBranch`, `struct SimpleBranch`, `struct SimpleBranchCfg` — descrittori CFG semplificato.
- `struct OpaqueDetector`, `struct OpaqueEliminator`, `struct EliminationResult`.
- `struct OpaquePassResult`, `struct OpaqueDeobfPass` — pass one-shot.
- `struct ConstFact`, `struct PropagationResult`, `struct ConstantPropagator`.
- `struct MbaIdentity`, `struct MbaOpaqueDetector` — identità Mixed Boolean-Arithmetic.
- `struct BranchFrequency`, `struct StatisticalOpaqueDetector`.
- `struct OpaqueDbEntry`, `enum OpaqueCategory`, `struct OpaquePredicateDatabase`.
- `struct DetailedFinding`, `struct OpaquePredicateReport`.
- `enum BranchOutcome`, `struct BranchSimplifier`.

### Funzioni / metodi pubblici
- `OpaqueExpr::eval(vars: &HashMap<String,i64>) -> Option<i64>` — valuta AST, None su unbound/div0/shift≥64/depth>512.
- `OpaqueExpr::is_const() -> Option<i64>` — collassa a costante se senza variabili.
- `OpaqueExpr::vars() -> Vec<String>` — variabili libere (sorted, dedup).
- `OpaqueExpr::simplify() -> Self` — semplificazione algebrica single-pass.
- `OpaqueExpr::is_trivially_equal(other: &Self) -> bool` — uguaglianza strutturale.
- `build_known_patterns() -> Vec<KnownOpaquePattern>` — DB statico (24+ pattern).
- `TruthTableChecker::new() -> Self`.
- `TruthTableChecker::is_always_true(expr: &OpaqueExpr) -> bool`.
- `TruthTableChecker::is_always_false(expr: &OpaqueExpr) -> bool`.
- `TruthTableChecker::classify(expr: &OpaqueExpr) -> PredicateValue`.
- `TruthTableChecker::counterexample_true(expr) -> Option<HashMap<String,i64>>`.
- `TruthTableChecker::counterexample_false(expr) -> Option<HashMap<String,i64>>`.
- `TruthTableChecker::enumerate_values(vars: &[String], bits: u32) -> Vec<HashMap<String,i64>>`.
- `SimpleBranchCfg::new(start: Address) -> Self`.
- `SimpleBranchCfg::add_branch(branch: SimpleBranch)`.
- `SimpleBranchCfg::add_block_size(addr: Address, size: usize)`.
- `OpaqueDetector::new() -> Self`.
- `OpaqueDetector::detect(cfg: &SimpleBranchCfg) -> Vec<OpaqueBranch>`.
- `OpaqueDetector::classify_condition(...)` — classifica condizione di branch.
- `OpaqueDetector::classify_with_kind(expr: &OpaqueExpr) -> OpaqueKind`.
- `OpaqueDetector::check_known_patterns(...)`.
- `OpaqueDetector::check_trivial_identity(expr) -> Option<PredicateValue>`.
- `OpaqueDetector::check_constant_expr(expr) -> Option<PredicateValue>`.
- `OpaqueEliminator::new() -> Self`.
- `OpaqueEliminator::eliminate(cfg: &mut SimpleBranchCfg) -> EliminationResult`.
- `OpaqueEliminator::make_unconditional(branch: &mut SimpleBranch, target: Address)`.
- `OpaqueDeobfPass::new() -> Self`.
- `OpaqueDeobfPass::run(cfg: &mut SimpleBranchCfg) -> OpaquePassResult` — pass completo.
- `ConstantPropagator::new() -> Self`.
- `ConstantPropagator::add_fact(fact: ConstFact)`.
- `ConstantPropagator::propagate(findings: &[OpaqueBranch]) -> PropagationResult`.
- `MbaOpaqueDetector::new() -> Self`.
- `MbaOpaqueDetector::check_identity(expr: &OpaqueExpr) -> Option<i64>`.
- `MbaOpaqueDetector::check_known_mba_patterns(expr) -> Option<MbaIdentity>`.
- `BranchFrequency::true_fraction() -> f64`, `false_fraction() -> f64`.
- `StatisticalOpaqueDetector::classify(freqs: &[BranchFrequency]) -> Vec<(Address,PredicateValue)>`.
- `OpaquePredicateDatabase::new() / with_builtins() / add(...) / by_category(cat) / by_value(val) / high_confidence(threshold: u8)`.
- `DetailedFinding::from_finding(finding: OpaqueBranch) -> Self`.
- `DetailedFinding::with_statistical_confirmation(self) -> Self`.
- `OpaquePredicateReport::new(findings, elim_result) -> Self`.
- `OpaquePredicateReport::high_confidence_findings() / always_true_findings() / always_false_findings() -> Vec<&DetailedFinding>`.
- `BranchSimplifier::new() / set_outcome(addr,outcome) / get_outcome(addr) / load_from_elimination(result) / known_addresses() / count()`.

---

## conditional_simplifier
- Types: `struct DeadBranch`, `enum SimplifyResult`, `struct ConditionalBranch`, `struct ConditionalSimplifier`.
- `SimplifyResult::is_simplified() -> bool`, `live_branch() -> Option<u64>`, `dead_target() -> Option<u64>`.
- `ConditionalSimplifier::new() / simplify_branch(&ConditionalBranch) -> &SimplifyResult / simplify_all(...) / result_for(u64) -> Option<&SimplifyResult> / dead_targets() -> &[u64] / all_results() -> impl Iterator`.
- `fn live_branch(branch: &ConditionalBranch) -> Option<u64>` — helper standalone.

## constant_propagator
- Types: `enum ConstLattice`, `enum IrInstr`, `enum BinOpKind`, `enum UnOpKind`, `enum CmpKind`, `enum FoldResult`, `struct InvariantCond`, `struct BasicBlock`, `struct PropState`, `struct ConstPropPass`, `struct ConstPropResult`.
- `ConstLattice::join(self,other) -> Self / meet(self,other) -> Self / is_less_than(self,other) -> bool`.
- `InvariantCond::is_opaque_true() -> bool / is_opaque_false() -> bool`.
- `BasicBlock::new(id: u32) / add_instr(IrInstr) / with_address(u64) -> Self`.
- `PropState::new() / get(VarId) -> ConstLattice / set(VarId, ConstLattice) / join_with(&Self) -> bool / const_count() -> usize`.
- `ConstPropPass::new() / with_initial(var,val) / with_max_iterations(n) / run(blocks: &[BasicBlock]) -> ConstPropResult / fold_instruction(instr,state) -> FoldResult`.
- `ConstPropResult::value_at_exit(block_pos,var) -> ConstLattice / value_at_entry(...) / constants_at_exit(...) -> Vec<(VarId,i64)> / opaque_true_count() / opaque_false_count() -> usize`.
- `fn single_block_cfg(instrs: Vec<IrInstr>) -> Vec<BasicBlock>`.
- `fn link_cfg(blocks: &mut Vec<BasicBlock>)`.

## dead_branch_eliminator
- Types: `struct DeadBranch`, `struct BranchPatch`, `struct UnreachableBlock`, `enum UnreachableReason`, `struct CfgPatch`, `struct EliminationResult`, `enum CfgInstr`, `struct CfgBlock`, `struct Cfg`, `struct DeadBranchEliminator`.
- `CfgPatch::new() / is_empty() / total_changes() -> usize`.
- `EliminationResult::changed() -> bool`.
- `CfgInstr::is_branch() -> bool / successors() -> Vec<u32>`.
- `CfgBlock::new(id) / with_address(u64) / add_instr(CfgInstr) / branch_instr_idx() -> Option<usize>`.
- `Cfg::new(entry) / add_block(CfgBlock) / rebuild_edges()`.
- `DeadBranchEliminator::new() / without_transitive() / without_remove_blocks() / eliminate(cfg: &mut Cfg, dead: &[DeadBranch]) -> EliminationResult / plan(cfg, dead) -> CfgPatch`.
- `fn two_branch_cfg() -> Cfg`, `fn chain_with_dead_branch() -> Cfg` — fixture builders.

## junk_code_remover
- Types: `struct DeadInstruction`, `enum DeadReason`, `struct BasicBlock`, `struct RemoveResult`, `struct JunkCodeRemover`.
- `BasicBlock::new(start: u64) / push_insn(addr,size,bytes) / add_successor(target) / byte_span() -> u64 / last_address() -> Option<u64>`.
- `RemoveResult::is_clean() -> bool / dead_addresses() -> Vec<u64>`.
- `JunkCodeRemover::new() / add_block(BasicBlock) / add_live_entry(addr) / add_dead_seed(addr) / add_dead_seeds(&[u64]) / remove() -> RemoveResult / scan_obfuscator_nops(...) / block_count() -> usize`.

## opaque_cfg_cleaner
- Types: `struct CfgPatch`, `enum PatchKind`, `struct OpaqueBlock`, `struct CFGSimplifier`, `struct BlockMerger`, `struct UnreachableBlockRemover`, `struct CleanedCFG`, `struct OpaqueCfgCleaner`.
- `CfgPatch::patch_description() -> String`.
- `CFGSimplifier::add_patch(CfgPatch) / apply_patches(edges: &[(u64,u64)]) -> Vec<(u64,u64)> / patch_count(PatchKind) -> usize`.
- `BlockMerger::find_mergeable(edges) -> Vec<Vec<u64>> / merge(edges) -> Vec<(u64,u64)>`.
- `UnreachableBlockRemover::reachable_from(entry,edges) -> HashSet<u64> / remove_unreachable(entry,edges) -> Vec<(u64,u64)> / count_unreachable(entry, all_blocks, edges) -> usize`.
- `CleanedCFG::new(entry) / reduction_ratio(original) -> f32 / summary() -> String`.
- `OpaqueCfgCleaner::new() / detect_opaque_blocks(cfg: &SimpleBranchCfg) -> Vec<OpaqueBlock> / clean(...)`.

## opaque_rewriter
- Types: `enum RewriteKind`, `struct OpaqueRewrite`, `struct RewriterBlock`, `struct RewriteResult`, `struct ProvenOpaquePredicate`, `struct OpaqueRewriter`.
- `RewriterBlock::new(addr: Address) / successors() -> Vec<Address> / is_conditional() -> bool`.
- `RewriteResult::empty() / rewrite_count() / dead_block_count() -> usize`.
- `OpaqueRewriter::new() / with_min_confidence(f32) / with_max_dce_passes(u32) / apply_one(...) / eliminate_dead_blocks(...) / propagate_constants(...) / rewrite_all(...) / build_report(&RewriteResult) -> String`.

## pattern_library
- Types: `enum PatternCategory`, `enum MatchMode`, `struct PatternEntry`, `enum PredicateDesc`, `struct PatternLibrary`, `struct LibraryStats`.
- `PatternLibrary::new() / pattern_count() -> usize / by_category(cat) -> Vec<&PatternEntry> / by_id(id) -> Option<&PatternEntry> / by_value(val) -> Vec<&PatternEntry> / match_descriptor(desc) -> Option<(&PatternEntry,f32)> / classify_no_smt(desc) -> Option<(PredicateValue,f32)> / classify_many(...) / stats() -> LibraryStats`.

## polynomial_check
- Types: `struct PolynomialInvariant`, `struct ZnRingCalculator`, `struct BitwideInvariantDb`, `struct BitwideEntry`, `struct PolynomialChecker`.
- `PolynomialInvariant::new(...) / eval_poly(x: i64) -> i64 / eval(x) -> i64 / holds(x) -> bool / verify_range(samples: u32) -> bool`.
- `fn check_polynomial_invariant(inv: &PolynomialInvariant, samples: u32) -> bool`.
- `fn consecutive_product_invariant() -> PolynomialInvariant`.
- `fn consecutive_pred_product_invariant() -> PolynomialInvariant`.
- `fn square_plus_n_invariant() -> PolynomialInvariant`.
- `fn triangular_mod6_invariant() -> PolynomialInvariant`.
- `ZnRingCalculator::new(n: i64) / inv(a) -> Option<i64> / div(a,b) -> Option<i64> / eval_poly(terms: &[(i64,u32)], x) -> i64`.
- `BitwideInvariantDb::build() / check(expr: &OpaqueExpr) -> Option<(&'static str,bool)>`.
- `PolynomialChecker::new(modulus: i64) / check(expr) -> Option<bool> / verify_poly(inv) -> bool / standard_invariants() -> Vec<PolynomialInvariant>`.

## predicate_detector
- Types: `enum BoolValue`, `enum PredicateKind`, `struct PredicatePattern`, `enum PredicateExpr`, `struct OpaquePredicate`, `struct DetectionResult`, `struct TruthSampler`, `struct PredicateDetector`.
- `PredicateExpr::variables() -> Vec<String> / eval(vars) -> Option<i64> / structurally_equal(other) -> bool / as_const() -> Option<i64> / simplify() -> Self`.
- `DetectionResult::new() / always_true_count() / always_false_count() -> usize / with_min_confidence(f64) -> Vec<&OpaquePredicate>`.
- `fn build_patterns() -> Vec<PredicatePattern>`.
- `TruthSampler::new() / with_bits(u32) / with_max_samples(usize) / classify(expr) -> BoolValue`.
- `PredicateDetector::new() / with_min_confidence(f64) / without_sampler() / without_patterns() / classify_expr(expr) -> (BoolValue,PredicateKind,f64,Option<String>) / detect(branches: &[(u64,PredicateExpr)]) -> DetectionResult / detect_high_confidence(...) -> Vec<OpaquePredicate>`.

## predicate_evaluator
- Types: `enum PredicateResult`, `struct AlwaysTrue`, `struct AlwaysFalse`, `enum Expr`, `struct Interval`, `struct PredicateEvaluator`.
- `fn is_determined(r: PredicateResult) -> bool`.
- `Expr::const_fold(env: &HashMap<String,i64>) -> Option<i64>`.
- `Interval::add(other) -> Self / sub(other) -> Self`.
- `fn pattern_power_of_two_and(x: i64) -> bool`.
- `fn pattern_consecutive_product_is_even(x: i64) -> bool`.
- `fn pattern_xor_same_zero(x: i64) -> bool`.
- `PredicateEvaluator::new() / bind(name, value: i64) / evaluate(expr: &Expr, branch_address: u64) -> PredicateResult / cache_size() -> usize / cached(addr) -> Option<PredicateResult> / clear_cache()`.
- `fn evaluate_with_smt(...)`.

## predicate_simplifier
- Types: `struct SimplificationResult`, `struct IlBasicBlock`, `struct PredicateSimplifier`, `struct DeadCodeEliminator`, `struct IlCfg`, `struct SimplificationStats`.
- `SimplificationResult::is_eliminated() -> bool / summary() -> String`.
- `IlBasicBlock::add_successor(target: Address, conditional: bool)`.
- `PredicateSimplifier::new() / run(cfg: &SimpleBranchCfg) -> Vec<SimplificationResult> / simplify_expr(expr: &OpaqueExpr) -> (OpaqueExpr, PredicateValue) / apply_to_blocks(...)`.
- `DeadCodeEliminator::mark_reachable(entry, blocks: &mut HashMap<u64,IlBasicBlock>) / eliminate(blocks) -> usize / count_dead(blocks) -> usize`.
- `IlCfg::new() / set_entry(addr) / add_block(IlBasicBlock) / add_branch(SimpleBranch) / simplify() -> SimplificationStats / block_count() / reachable_count() -> usize`.
- `SimplificationStats::simplification_rate() -> f64`.

## sat_checker
- Types: `struct OpaquePredicateCandidate`, `struct SatChecker`, `struct SatCheckerStats`, `struct PatternDb`.
- `SatChecker::new() / verify_opaque(expr: &OpaqueExpr) -> PredicateValue / verify_candidate(&mut Candidate) / batch_verify(&mut [Candidate]) / filter_opaque(...)`.
- `PatternDb::build() / check(expr) -> Option<PredicateValue> / len() -> usize / is_empty() -> bool / add(name: &'static str, f: fn(&OpaqueExpr) -> Option<PredicateValue>)`.

## smt_prover
- Types: `enum SmtExpr`, `enum SmtBinOp`, `enum SmtUnaryOp`, `enum SmtCmpOp`, `enum SmtResult`, `struct SmtProver`.
- `SmtExpr` costruttori: `constant(i64) / var(name, width: u8) / add/sub/mul/and/or/xor(lhs,rhs) / not(inner) / neg(inner) / square(inner) / eq/ne/sge/uge(lhs,rhs)`.
- `SmtExpr::free_vars() -> Vec<(String,u8)> / eval(env: &HashMap<String,i64>) -> Option<i64>`.
- `SmtResult::is_sat() / is_unsat() / is_unknown() -> bool`.
- `SmtProver::new() / with_timeout(ms: u64) / with_sample_count(u32) / check(predicate: &SmtExpr) -> (PredicateValue,f32,SmtResult) / classify(predicate) -> PredicateValue / is_tautology(predicate) -> bool / is_contradiction(predicate) -> bool`.

## tautology_db
- Types: `enum TautologyValue`, `enum TautologyExpr`, `struct TautologyEvaluator`, `enum TautologyClassification`, `struct TautologyPattern`, `struct TautologyStatistics`, `struct TautologyDb`, `struct ConfidenceScore`, `struct TautologyPatch`, `struct TautologyPatchGenerator`, `struct TautologyOptimizer`, `struct TautologyMatcher`, `struct TautologyReport`.
- `TautologyExpr` costruttori: `var(s) / and/or/xor/add/sub/mul/eq/ne/lt/le(a,b) / not(a) / neg(a)`.
- `TautologyExpr::eval(env) -> Option<i64> / vars() -> Vec<String> / node_count() -> usize`.
- `TautologyEvaluator::new() / classify(expr) -> TautologyClassification`.
- `TautologyPattern::new(...) / verify_sampled(bits: u32, samples: usize) -> bool`.
- `TautologyStatistics::from_db(&TautologyDb) -> Self / summary() -> String`.
- `TautologyDb::new() / get(name) -> Option<&TautologyPattern> / always_true_patterns() -> Vec<&TautologyPattern> / contradictions() -> Vec<&TautologyPattern> / with_var_count(n) -> Vec<&TautologyPattern>`.
- `ConfidenceScore::new(pattern_conf: u8, sampling_conf: u8, node_count: usize) / overall() -> u8 / is_patchable() -> bool`.
- `TautologyPatchGenerator::always_taken_patch(offset, original_jcc: &[u8]) -> Option<TautologyPatch> / never_taken_patch(offset, original_jcc) -> Option<TautologyPatch> / generate_from_map(...)`.
- `TautologyOptimizer::prioritize(...)`.
- `TautologyMatcher::new() / match_expr(expr: &TautologyExpr) -> Option<(&TautologyPattern, ConfidenceScore)>`.
- `TautologyReport::new() / record(pattern, address: u64, confidence: u8)`.

---

## Approximate public-fn count per module
- lib.rs: ~67
- tautology_db: ~47
- smt_prover: ~27
- constant_propagator: ~27
- polynomial_check: ~27
- opaque_cfg_cleaner: ~23
- predicate_simplifier: ~22
- predicate_detector: ~21
- predicate_evaluator: ~20
- dead_branch_eliminator: ~20
- sat_checker: ~15
- junk_code_remover: ~15
- opaque_rewriter: ~14
- conditional_simplifier: ~12
- pattern_library: ~9

Total ≈ **366** public functions / constructors / methods.
