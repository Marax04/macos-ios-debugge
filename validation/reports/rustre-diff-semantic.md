# rustre-diff-semantic

Semantic diffing crate: AST, behavior, call site, control flow, function signature, IR, MLIL, patch analysis, semantic hash/equivalence/similarity, type/variable diffing.

## Modules (16)
- ast_differ — AstNode, AstDiff, AstDiffer, compute_node_hash, node_similarity
- behavior_diff — External/Network/File/Registry/Process/Crypto/Ipc interactions, ApiCall, BehaviorSignature, SecurityRelevantDiff, BehaviorDiff
- call_site_diff — CallSite, CallSiteDiff(er), MatchStrategy, BatchCallSiteDiff, diff_batch
- control_flow_diff — BasicBlock, ControlFlowGraph, BlockDiff, LoopDiff, DominanceDiff, ControlFlowDiff(er), AlignmentStrategy, BatchCfgDiff, diff_batch
- function_diff — FunctionSignature, FunctionDiff, ParameterDiff, LocalVarDiff, TypeChangeDiff, PatchCharacterizer, DiffReport, diff_signatures
- ir_semantic_diff — IrExpr, IrStmt, IrBasicBlock, IrFunction, Normaliser, SemanticHash, SemanticEquivalenceChecker, IrSemanticDiff(er), SemanticDiffReport, make_simple_func
- mlil_diff
- patch_analysis
- semantic_comparison, semantic_equivalence, semantic_hash, similarity, similarity_score
- type_diff, variable_diff

## Pub item counts
ast_differ:5, behavior_diff:23, call_site_diff:17, control_flow_diff:17, function_diff:12, ir_semantic_diff:15, lib:35, mlil_diff:12, patch_analysis:14, semantic_comparison:9, semantic_equivalence:9, semantic_hash:20, similarity:9, similarity_score:6, type_diff:6, variable_diff:8.

Total ~215 pub items across 16 modules.

## Key public functions
- `compute_node_hash(node: &AstNode) -> u64`
- `node_similarity(a: &AstNode, b: &AstNode) -> f64`
- `CallSiteDiffer::diff_batch(...)` → BatchCallSiteDiff
- `ControlFlowDiffer::diff_batch(pairs, strategy)` → BatchCfgDiff
- `diff_signatures(...)` (function_diff)
- `make_simple_func(addr, stmts)` → IrFunction
