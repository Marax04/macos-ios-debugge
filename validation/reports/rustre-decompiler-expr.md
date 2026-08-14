# rustre-decompiler-expr

## Purpose
Expression-layer decompiler library: defines the core `Expr`/`Stmt` IR, plus
analysis/transformation passes for constant folding, simplification,
normalization, type propagation, pattern matching, peephole optimization,
DAG-based CSE, and C re-emission. Consumed by `rustre-decompiler` (one-way
dependency to avoid cycles). Dependencies: `thiserror`, `serde`.

## Modules
- `lib.rs` — IR core: `Expr`, `Stmt`, `BinOp`, `UnOp`, `IntWidth`, `SsaAssign`,
  `DefUseChain`, `ExprError`. Passes/printers: `ExprFolder`, `ExprSimplifier`,
  `ExprNormalizer`, `ExprComparator`, `ExprPrinter`, `ExprPattern`,
  `ExprRewriter`, `ExprEvaluator`, `ConstantFolder`, `StrengthReducer`,
  `BitwidthAnalyzer`, `SignednessInference`, `CommonSubexprElim`,
  `CopyPropagation`, `ExprCanonicalizer`, `BooleanSimplifier`,
  `ComparisonNormalizer`, `PointerArithmeticRecovery`, `StringLiteralDetector`,
  `VtableCallDetector`, `NullCheckEliminator`, `DeadExprElim`,
  `BitwiseSimplifier`, `SequentialFolder`, `CExprRebuilder`, `ExprToC`,
  `ExprTypeChecker`, `InferredType`, `AffineForm`, `FoldConfig`,
  `ExprComplexity`/`Analyzer`, `ExprPrintOptions`.
  Free fns: `has_side_effects`, `is_safe_to_inline`, `contains_load`,
  `contains_call`, `recognize_affine`, `c_binop_precedence`, plus
  C-precedence constants.
- `casts.rs` — checked/wrapping integer/float cast helpers (`i64_as_u64`,
  `u64_as_i64`, narrow casts to u8/16/32/i8/16/32, `usize_to_u32`,
  `u64_to_f64`, `usize_to_f64`). All pure.
- `expr_precedence.rs` — `Associativity`, `PrecedenceLevel`, `ParenConfig`,
  `MinimalParenPrinter`; `binop_precedence`, `unop_precedence`,
  `needs_parens(parent, child, is_right)`, `has_side_effects`, `can_reorder`,
  `precedence_table`.
- `expr_pattern_matcher.rs` — `ExprPat`, `Captures`, `ExprTemplate`,
  `RewriteRule`, `MatchResult`, `ExprPatternMatcher`. Fns:
  `match_pattern(pat, expr, &mut captures) -> bool`,
  `expand_template(tmpl, captures) -> Option<Expr>`,
  `replace_pattern(expr, pat, repl) -> usize` (count of substitutions).
- `expr_reconstruction.rs` — high-level pattern recovery: `CompoundAssign`,
  `TernaryPattern`, `LazyPattern`, `ReconstructedAssign`, `ExprReconstructor`.
  Fns: `detect_compound_assign(lhs, expr) -> Option<CompoundAssign>`,
  `collapse_casts(expr) -> Expr`, `detect_ternary(phi, cond) -> Option<...>`,
  `remove_ptr_int_roundtrip(expr) -> Expr`, `detect_lazy_pattern(&expr)`.
- `expr_simplification.rs` — `SimplificationFlags` (bitfield),
  `SimplificationConfig`, `ExpressionSimplifier`; free `simplify(expr) -> Expr`.
- `expr_simplifier.rs` — alternative simplifier with `SimplifyPass` enum,
  `SimplifyStats`, `ExprSimplifier` configurable per-pass.
- `expr_type_propagator.rs` — `TypeAnnotation`, `TypeEnvironment`,
  `PropagationResult`, `ExprTypePropagator`, `TypePropagationPipeline`:
  forward/backward type inference on expression trees.
- `expression_recovery.rs` — high-level recovery passes:
  `FactorOutCommonSubexpr`, `DistributivityOpt`, `ShiftToMul`,
  `BitFieldRecovery`, `ConditionalExpr`, `RecoveryOptions`,
  `ExpressionRecovery`, `ExprComplexity` (local).
- `pattern_library.rs` — `PatternId` enum, `PatternMatch`, `PatternMatcher`,
  `PatternDescriptor`, `all_pattern_descriptors() -> Vec<PatternDescriptor>`:
  catalogue of named idiom patterns.
- `peephole_optimizer.rs` — `PeepholeRule` trait, `OptimizationStats`,
  `PeepholeConfig`, `PeepholeOptimizer`, `default_rules() -> Vec<Box<dyn ...>>`.
- `dag_simplifier.rs` — value-numbering DAG: `DagArena`, `DagNode`,
  `DagNodeId`, `DagHash`, `BinOpKind`, `UnOpKind`, `CommonSubexpr`,
  `DeadNode`, `ConstantFolding`, `BitwiseSimplify`, `DagSimplifier`,
  `DagPrinter`, `DagStatistics`, `CommutativeNormalizer`,
  `ConstantEvaluator`, `ReachableNodes`; helper `hash64`.

## API surface
- ~115 public `fn`/`const fn` items across 12 files
- ~80 public types (enums/structs/traits)
- 1 public type alias (`ExprRewriteRule`)
- 3 public constants (`C_UNARY_PRECEDENCE`, `C_POSTFIX_PRECEDENCE`, ...)

## Expected behavior
- IR ownership: `Expr`/`Stmt` are the canonical decompiler-side expression
  IR. All passes are pure transforms `Expr -> Expr` or mutate a builder
  context; no I/O.
- Folding/simplification passes should be idempotent and never change
  observable C semantics (side effects preserved per `has_side_effects` and
  `is_safe_to_inline`).
- Pattern matcher: `match_pattern` returns false without polluting captures;
  `expand_template` returns `None` on missing captures.
- Cast helpers in `casts.rs` are `const fn` where possible and document
  wrap-around vs. truncation behavior at the call site.
- Peephole/DAG passes report stats (`OptimizationStats`, `DagStatistics`,
  `SimplifyStats`) so callers can detect fixpoint.
- Type propagator runs to fixpoint over `TypeEnvironment` and returns a
  `PropagationResult` summarising changed bindings.

## Inputs / Outputs
- Inputs: caller-built `Expr`/`Stmt` trees, optional `DefUseChain`,
  configuration structs (`FoldConfig`, `ParenConfig`, `RecoveryOptions`,
  `SimplificationConfig`, `PeepholeConfig`, `ExprPrintOptions`).
- Outputs: transformed `Expr`/`Stmt`, printed C strings (`ExprPrinter`,
  `ExprToC`, `CExprRebuilder`), pattern match descriptors, or stats structs.
- Errors: `ExprError` (thiserror-derived) for evaluator / typechecker
  failures; most transforms are infallible.

## Testability
Self-contained pure library with no FS/network dependencies and existing
`tests/` directory. All passes operate on owned `Expr` values and return
deterministic results, so unit-testing folding, simplification, pattern
match/replace, precedence printing, cast helpers, and DAG CSE is
straightforward.
