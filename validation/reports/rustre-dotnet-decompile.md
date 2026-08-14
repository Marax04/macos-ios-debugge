# rustre-dotnet-decompile

## Purpose
High-level C# decompiler for .NET assemblies. Lifts CIL bytecode to HLIL (high-level IL), recovers C# language constructs (async/await, LINQ, lambdas, properties, pattern matching, switch expressions, anonymous types, nullable references), and emits C# source. Depends on `rustre-dotnet` and `rustre-dotnet-metadata`.

## Crate layout
- `Cargo.toml` — edition 2024, deps: ahash, anyhow, thiserror, serde, rustre-dotnet, rustre-dotnet-metadata; dev: serde_json
- `src/lib.rs` (~9300 lines) — main decompiler pipeline, CIL opcodes, HLIL AST, CFG, SSA, constant folding, type inference, emitter
- `src/async_recovery.rs` — async state-machine pattern recovery
- `src/linq_recovery.rs` — LINQ chain detection from call sites
- `src/linq_recovery_full.rs` — full LINQ operation recovery (Select/Where/GroupBy/OrderBy/Join)
- `src/csharp_patterns.rs` — pattern catalog (async/await, LINQ, delegates, anonymous classes, nullable, switch expressions, pattern matching)

## Public API surface (signatures only)

### lib.rs — pipeline & core types
- `struct DecompilerOptions` — knobs for decompilation passes
- `struct CSharpDecompiler` — entry-point decompiler
- `struct DecompilationPipeline` — orchestrates passes
- `struct CilDisassembler` — disassembles CIL bytecode stream
- `struct CilOpcodeRegistry`, `struct CilOpcodeInfo`, `enum OperandKind` — opcode metadata
- HLIL AST: `enum HlilExpression`, `enum HlilStatement`, `struct HlilBlock`, `struct HlilMethod`, `enum BinaryOp`, `enum UnaryOp`, `enum TypeKind`
- CFG/SSA: `struct ControlFlowGraph`, `struct CfgBlock`, `enum CfgEdgeKind`, `struct SsaBuilder`, `struct SsaDef`, `struct UseDefChains`, `struct UseDefEntry`
- Analysis passes: `struct StackAnalysis`, `struct PatternRecogniser`, `struct ConstantFolder`, `enum FoldResult`, `struct TypeAnnotationPass`, `enum InferredType`
- Emission: `struct CSharpEmitter`, `struct TypeDefEmitter`, `struct TypeEmitOptions`, `struct TypeOutputFlags`, `struct TypeStyleFlags`
- Recovery: `struct AsyncStateMachineDetector`, `struct RecoveredAsyncMethod`, `struct AwaitPoint`, `struct LambdaReconstructor`, `struct ReconstructedLambda`, `struct PropertyReconstructor`, `struct PropertyDef`, `struct LinqReconstructor`, `enum LinqStyle`, `struct StringLiteralDecoder`, `struct AttributeDecoder`, `struct DecodedAttribute`, `enum AttributeArg`, `struct AttributeNamedArg`, `struct GenericInstantiator`, `enum TypeSig`, `struct StringTable`, `struct RecoveredRegion`, `enum RecoveredRegionKind`
- Free functions:
  - `pub fn stack_effect(opcode: &str) -> Option<StackEffect>`
  - `pub const fn infer_type_from_element(et: u8) -> InferredType`
  - `pub fn detect_yield_return(method: &DotnetMethod) -> bool`
  - `pub fn detect_async(method: &DotnetMethod) -> bool`
  - `pub fn hlil_remove_nops(block: &HlilBlock) -> HlilBlock`
  - `pub fn simplify_expr(expr: &str) -> String`
- Metrics: `struct DecompilerMetrics`, `struct DetectedPatterns`, `enum StackDelta`, `struct StackEffect`

### async_recovery.rs
- Errors: `enum AsyncRecoveryError`, `type Result<T>`
- Inputs (mock-friendly): `struct MethodDef`, `struct TypeDef`, `struct FieldDef`, `struct ILInsnAt`, `enum ILInstruction`, `struct EHClause`, `enum EHClauseKind`
- Outputs: `enum Statement`, `enum Expr`, `struct AsyncFunction`, `struct AsyncParam`, `struct AsyncStateMachinePattern`, `struct StateMachineCase`, `struct AwaitPoint`, `struct TryCatchBlock`, `struct CatchClause`
- Functions:
  - `find_state_machine_attribute(method: &MethodDef) -> Option<&str>`
  - `find_state_switch(insns: &[ILInsnAt]) -> Option<(usize, Vec<u32>)>`
  - `find_state_field(sm: &TypeDef) -> Option<&FieldDef>`
  - `extract_case_block(...)` — slices state-machine cases
  - `detect_awaiter_pattern(...)` — finds await suspension points
  - `lift_case_blocks(cases: &[StateMachineCase]) -> Vec<Statement>`
  - `reconstruct_exception_handling(...) -> ...`
  - `decompile_async(method, state_machine) -> Result<AsyncFunction>` — main entry
  - `recover_all_async_methods(...)` — bulk scan
  - `mock_state_machine(name, num_awaits) -> TypeDef`, `mock_async_method(name, ret) -> MethodDef` — testing helpers

### linq_recovery.rs
- Errors: `enum LinqRecoveryError`, `type Result<T>`
- Lambda AST: `struct LambdaExpr`, `struct LambdaParam`, `enum LambdaBody`, `enum LambdaExprNode`, `enum LambdaStatement`, `struct CapturedVar`, `enum DelegateInferenceSource`, `struct ClosureField`
- LINQ AST: `enum LinqOperator`, `struct LinqStep`, `struct LinqChain`, `enum QueryClause`, `struct LinqQuery`, `struct ForeachPattern`, `struct CallSite`, `struct MethodLinqSummary`
- Functions:
  - `is_closure_class(name: &str) -> bool` — detects `<>c__DisplayClass` names
  - `extract_captures(fields: &[ClosureField]) -> Vec<CapturedVar>`
  - `infer_delegate_type(...)`
  - `detect_linq_chains(call_sites: &[CallSite]) -> Vec<LinqChain>`
  - `detect_foreach_patterns(call_sites: &[CallSite]) -> Vec<ForeachPattern>`
  - `chain_to_query(chain: &LinqChain) -> Option<LinqQuery>` — method-syntax to query-syntax
  - `infer_linq_lambda_delegate(...)`
  - `recover_linq_summary(...) -> MethodLinqSummary`
  - `mock_lambda(...)`, `mock_linq_call(...)` — testing helpers

### linq_recovery_full.rs
- `enum LinqOperation`, `struct RecoveredQuery`, `struct QuerySyntax`, `struct LinqRecovery` — high-level driver
- Per-operator recoverers: `struct SelectRecovery`, `struct WhereRecovery`, `struct GroupByRecovery`, `struct OrderByRecovery`, `struct JoinRecovery`

### csharp_patterns.rs
- `enum PatternConfidence`, `struct PatternLocation`
- Pattern catalog: `struct AsyncAwaitPattern`, `enum LinqOperator`, `struct LinqPattern`, `struct DelegatePattern`, `struct AnonymousClass`, `enum NullableKind`, `struct NullablePattern`, `struct SwitchExpression`, `struct SwitchArm`, `enum MatchPatternKind`, `struct PatternMatching`
- Aggregate: `enum CsharpPattern`, `struct CsharpPatterns` — collection of detected patterns

## Public surface counts
- Free `pub fn`: ~26
- Methods on impl blocks (`    pub fn`): ~174
- Total public functions: ~200
- Public structs/enums/types: ~95

## Input/Output behavior
- **Input**: `DotnetMethod` / CIL bytecode streams (from `rustre-dotnet` parser), `MethodDef`/`TypeDef` metadata, opcode lists.
- **Pipeline**: CIL disassembly -> stack analysis -> SSA construction -> CFG building -> constant folding -> pattern recognition (async/LINQ/lambdas/properties) -> type annotation -> HLIL emission -> C# source via `CSharpEmitter`.
- **Output**: `HlilMethod`/`HlilBlock` trees, `AsyncFunction`, `LinqQuery`, `ReconstructedLambda`, `PropertyDef`, `RecoveredRegion`, `DecodedAttribute`, and finally C# textual source through emitters. Detected pattern catalog via `CsharpPatterns`. Metrics via `DecompilerMetrics`/`DetectedPatterns`.

## Testability
- `tests/` directory present.
- Module exposes mock helpers (`mock_state_machine`, `mock_async_method`, `mock_lambda`, `mock_linq_call`) and pure data-in/data-out functions (`detect_linq_chains`, `find_state_switch`, `stack_effect`, `simplify_expr`, `infer_type_from_element`, `is_closure_class`) that are deterministic and testable without I/O.
- `dev-dependencies`: serde_json — implies JSON fixture-based tests.
- Verdict: **testable**.
