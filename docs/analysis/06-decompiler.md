# Decompiler Subsystem — In-Depth Analysis

*Workspace: `C:/Users/Fra/Desktop/RustRE` — analysed 2026-07-01*

---

## 0. Overview and Pipeline Position

The RustRE decompiler subsystem converts disassembled x86-64 machine code into
readable C-like pseudo-code.  It is organised as six focused crates with a
strict layering rule (no upward dependencies):

```
Binary bytes
    │
    ▼  (rustre-loader + rustre-arch-x86)
Vec<Instruction>           ← raw decoded instructions
    │
    ▼  rustre-decompiler   ← COORDINATOR  (this is the facade)
    │   ├── rustre-decompiler-cfs   ← CFG structuring (DREAM algorithm)
    │   ├── rustre-decompiler-expr  ← expression trees & simplification
    │   ├── rustre-decompiler-type  ← type system & inference
    │   └── rustre-decompiler-c     ← C code emission
    │
    ▼  rustre-decompiler-ghidra     ← optional Ghidra P-Code back-end
    │   (depends on rustre-decompiler, not below it)
    │
    ▼  rustre-mcp-tools / rustre-gui / rustre-mcp-server
         (public consumers)
```

Total source across all six crates: **≈ 106 000 lines of Rust**.

---

## 1. `rustre-decompiler` — Central Coordinator

### 1.1 Purpose

Facade crate that orchestrates the complete decompilation pipeline:
`LLIL → MLIL/SSA → HLIL → CFS → TypeInfer → PseudoC`.
All MCP tools and the GUI depend exclusively on this crate, never on the
sub-crates directly.

### 1.2 Source files

| File | Role |
|---|---|
| `lib.rs` | All core types + `DecompilerPipeline` + inline instruction lifter (~6 900 lines) |
| `binary_entry.rs` | Loader integration: file → `RichLoadResult` → `DecompiledFunction` |
| `batch_decompiler.rs` | Rayon-parallel batch decompilation with priority scheduling |
| `function_decompiler.rs` | Single-function entry point, call-site classification |
| `pipeline_coordinator.rs` | Pass dependency graph, telemetry, retry/fallback |
| `pass_pipeline.rs` | Higher-level accumulation pass interface (`StackVarReport`) |
| `ast_builder.rs` | Builds `StructuredAst` from `DecompilerContext` |
| `hlil_builder.rs` | HLIL node types: `HlilExpr` (20+ variants), `HlilStmt`, `HlilFunction`, `HlilPrinter`, `HlilOptimizer` |
| `ir_to_hlil_bridge.rs` | Bridges low-level IR → HLIL |
| `control_flow_recovery.rs` | CFG reconstruction from linear instruction stream |
| `expression_cleanup.rs` | Post-pass expression cleanup |
| `statement_sequencer.rs` | Sequences statements for structured emission |
| `pseudocode_generator.rs` | Top-level pseudo-C string builder |
| `ssa.rs` | Cytron et al. SSA construction (standalone, trait-based) |
| `signature_recovery.rs` | Calling-convention-aware function signature recovery |
| `callconv_bridge.rs` | Bridges to `rustre-analysis-callconv` |
| `variable_recovery.rs` | Variable collection pass |
| `variable_recovery_engine.rs` | Stack slot / struct-on-stack recovery |
| `stack_locals.rs` | Stack frame report: `StackLocal`, `StackFrameReport`, prologue/epilogue masking |
| `struct_field_recovery_pass.rs` | Struct field recovery decompiler pass |
| `type_recovery_engine.rs` | Thin wrapper around `rustre-decompiler-type` |
| `mem_operand.rs` | Memory operand parsing helpers |
| `decompiler_cache.rs` | LRU result cache (`Arc<RwLock<…>>`) |
| `x86_register_width.rs` | Sub-register canonicalization tables |

### 1.3 Key public types

```rust
// Error hierarchy
pub enum DecompilerError {
    FunctionNotFound(u64),
    LiftError(String),
    AnalysisError(String),
    BackendError(String),
    UnsupportedArch(String),
    PassTimeout { pass: String, elapsed_ms: u64 },
    PassError  { pass: String, message: String },
    FunctionTooLarge(u64),
    Other(String),
}

// IR abstraction levels — ordered (Llil < MlilSsa < Hlil < PseudoC)
pub enum IrLevel { Llil, MlilSsa, Hlil, PseudoC }

// Variable storage locations
pub enum VarStorage { Register(String), Stack(i64), Global(u64), Immediate(u64) }

// Decompiled variable descriptor
pub struct DecompVariable {
    pub name: String, pub type_str: String,
    pub is_parameter: bool, pub storage: VarStorage,
}

// Primary result type
pub struct DecompiledFunction {
    pub address: u64, pub name: String, pub pseudo_code: String,
    pub ir_level: IrLevel, pub confidence: u8,
    pub variables: Vec<DecompVariable>, pub call_sites: Vec<u64>,
}

// Configuration — grouped into analysis / opt / pass flag sub-structs
pub struct DecompOptions {
    pub target_level: IrLevel,
    pub analysis: DecompAnalysisFlags,  // rename_variables, infer_types, type_propagation
    pub opt:      DecompOptFlags,       // aggressive_inlining, eliminate_phi, constant_propagation
    pub passes:   DecompPassFlags,      // dead_code_elimination, detect_loops, emit_struct_fields
    pub max_function_size: usize,       // default 10 000 instructions
    pub timeout_ms: u64,
    pub min_variable_confidence: u8,
    pub verbosity: u8, pub name_recovery: bool,
    pub backend: DecompilerBackendKind,
}
pub type DecompilerConfig = DecompOptions;
```

### 1.4 Core traits

```rust
// Back-end plug-in interface
pub trait DecompilerBackend: Send + Sync + fmt::Debug {
    fn name(&self) -> &str;
    fn supported_archs(&self) -> Vec<String>;
    fn target_level(&self) -> IrLevel;
    fn decompile_function(
        &self, address: u64, instructions: &[Instruction], func_name: &str,
    ) -> Result<DecompiledFunction, DecompilerError>;
    fn decompile_range(...) -> Result<Vec<DecompiledFunction>, DecompilerError>;
    fn supports_arch(&self, arch: &str) -> bool;  // default impl
}

// Instruction-level pass (operates on raw Instruction slice + context)
pub trait DecompilerPass: Send + Sync + fmt::Debug {
    fn name(&self) -> &str;
    fn run(&self, ctx: &mut DecompilerContext, address: u64,
           instructions: &[Instruction]) -> Result<(), DecompilerError>;
    fn is_enabled(&self, opts: &DecompOptions) -> bool;
    fn description(&self) -> &'static str { "" }
}

// Optional symbol name resolver (attached to a pipeline)
pub trait SymbolResolver: Send + Sync {
    fn resolve(&self, addr: u64) -> Option<String>;
}
```

### 1.5 `DecompilerContext` — per-function mutable accumulator

Passes operate on a `DecompilerContext` passed `&mut`:

```rust
pub struct DecompilerContext {
    pub address: u64, pub func_name: String,
    pub options: DecompOptions,
    pub pseudo_code_lines: Vec<String>,
    pub ir_level: IrLevel, pub confidence: u8,
    pub variables: Vec<DecompVariable>, pub call_sites: Vec<u64>,
    pub annotations: HashMap<String, String>,
    pub pass_times: Vec<(String, Duration)>,
}
```

Key methods: `emit_line`, `annotate`, `advance_ir_level`, `add_variable`,
`add_call_site`, `finish() -> DecompiledFunction`.

Two CFG construction helpers used by the structured emitter:

- `build_cfg(&self) -> Vec<BasicBlock>` — heuristic: converts existing
  `pseudo_code_lines` + call sites into a rough CFG.
- `build_cfg_from_instructions(&self, instrs: &[Instruction]) -> Vec<BasicBlock>`
  — preferred path: lifts each x86 instruction to a real `Statement` variant
  (`Assign`, `Return`, `Branch`, or `Raw`), then applies a sequence of micro-
  passes: `simplify_xor_self`, `hide_callee_saved_push_pop`, `fuse_cmp_branch`,
  `fuse_standalone_cmov`, `propagate_register_copies`, `recover_stack_locals`,
  `collapse_stack_frame`, `infer_call_arguments`, `rewrite_tail_call`,
  `rewrite_call_return`.

### 1.6 `DecompilerPipeline`

```rust
pub struct DecompilerPipeline {
    passes: Vec<Arc<dyn DecompilerPass>>,
    options: DecompOptions,
    symbol_resolver: Option<Arc<dyn SymbolResolver>>,
}

impl DecompilerPipeline {
    pub fn builder(options: DecompOptions) -> PipelineBuilder;
    pub fn run(&self, address: u64, func_name: &str,
               instructions: &[Instruction]) -> Result<DecompiledFunction, DecompilerError>;
    pub fn run_with_structured_emit(...) -> Result<DecompiledFunction, DecompilerError>;
    pub fn emit_structured_code(func_name: &str, blocks: Vec<BasicBlock>,
                                variables: &[DecompVariable]) -> Option<String>;
}
```

`run` executes passes sequentially, enforcing per-pass timeouts (post-hoc) and
recording telemetry. `run_with_structured_emit` additionally invokes
`build_cfg_from_instructions` and routes through `ControlFlowStructurer` →
`CPrinter`.

### 1.7 `DecompilerBackendKind`

Four registered kinds: `Internal` (pure Rust), `Ghidra`, `BinaryNinja`,
`RetDec`. Only `Internal` and `Ghidra` are wired; `BinaryNinja` and `RetDec`
are stubs (no implementing `DecompilerBackend` structs in the workspace).

### 1.8 Binary-level integration points

```rust
// Load a binary and return a rich descriptor
pub fn load_binary(path: &Path) -> Result<RichLoadResult, DecompilerError>;

// Locate byte slice at a virtual address
pub fn slice_at_va(load: &RichLoadResult, va: u64) -> Option<(u64, &[u8])>;

// Decompile one function by VA from an already-loaded binary
pub fn decompile_function_in_load(load: &RichLoadResult, va: u64,
    opts: &DecompOptions) -> Result<DecompiledFunction, DecompilerError>;

// Convenience: load + decompile in one call
pub fn decompile_function_from_binary(path: &Path, va: u64,
    opts: &DecompOptions) -> Result<DecompiledFunction, DecompilerError>;

// Enumerate all functions in a loaded binary
pub fn detect_functions_in_load(load: &RichLoadResult)
    -> Result<Vec<FunctionBoundary>, DecompilerError>;

// Build the standard pipeline as an Arc (shared by batch workers)
pub fn standard_pipeline_arc(opts: DecompOptions) -> Arc<DecompilerPipeline>;
```

### 1.9 SSA construction (`ssa.rs`)

Full Cytron et al. implementation with trait-based input:

```rust
pub trait SsaInput {
    fn block_ids(&self) -> Vec<BlockId>;
    fn successors(&self, b: BlockId) -> Vec<BlockId>;
    fn predecessors(&self, b: BlockId) -> Vec<BlockId>;
    fn variables_defined_in(&self, b: BlockId) -> Vec<VarId>;
    fn variables_used_in(&self, b: BlockId) -> Vec<VarId>;
    fn entry_block(&self) -> BlockId;
    fn var_count(&self) -> usize;
}

pub fn construct_ssa<I: SsaInput>(input: &I) -> SsaForm;
```

`SsaForm` carries phi-node placement and a rename mapping per block.
Decoupled from all other sub-crates — can be unit-tested independently.

### 1.10 Intra-workspace dependencies

| Dependency | Why |
|---|---|
| `rustre-core` | `Instruction`, `Architecture`, `Address` |
| `rustre-decompiler-cfs` | `BasicBlock`, `ControlFlowStructurer`, `Statement` |
| `rustre-decompiler-c` | `CPrinter`, `CFormat`, `FunctionSignature`, `VarDecl` |
| `rustre-decompiler-type` | `DecompType`, `TypeEnvironment`, `TypeAwareRenamer` |
| `rustre-analysis-typerecov` | type recovery pass |
| `rustre-analysis-fn` | `FunctionDetector`, `NoreturnDetector` |
| `rustre-analysis-callconv` | calling convention detection |
| `rustre-loader` | binary format loading |
| `rustre-arch-x86` | x86/x86-64 disassembler |

External: `anyhow`, `thiserror`, `serde`/`serde_json`, `parking_lot`, `rayon`.

### 1.11 Implementation status: **PARTIAL → nearly complete**

The pure-Rust path (load → disassemble → lift → structure → emit C) is fully
wired for x86-64. No `todo!` or `unimplemented!` macros in this crate.
The BinaryNinja and RetDec backend kinds are declared but no `impl
DecompilerBackend` exists for them — dead enum arms.
SSA construction is complete but not yet connected to the pass pipeline
(the existing passes operate on `Instruction` slices, not SSA form).

---

## 2. `rustre-decompiler-cfs` — Control-Flow Structuring

### 2.1 Purpose

Converts a low-level CFG (directed graph of `BasicBlock`s) into a structured
`StructuredAst` using the DREAM / "No More Gotos" algorithm.  No dependency
on the coordinator crate (cycle prevention enforced in `Cargo.toml`).

### 2.2 Key types

```rust
pub struct BlockId(pub u32);

// Statement inside a basic block
pub enum Statement {
    Raw(String),
    Assign { lhs: String, rhs: String },
    Return(Option<String>),
    Branch(String),
}

pub struct BasicBlock {
    pub id: BlockId,
    pub stmts: Vec<Statement>,
    pub successors: Vec<BlockId>,
}

// Output AST nodes
pub enum StructuredNode {
    BasicBlock { id: BlockId, stmts: Vec<Statement> },
    Sequence(Vec<Self>),
    If       { condition: String, then_branch: Box<Self> },
    IfElse   { condition: String, then_branch: Box<Self>, else_branch: Box<Self> },
    Loop     { kind: LoopKind, condition: String, body: Box<Self> },
    Switch   { expr: String, cases: Vec<SwitchCase> },
    Goto(BlockId),          // irreducible residue
    Break, Continue,
    Return(Option<String>),
}

pub enum LoopKind { While, DoWhile, For }

pub struct StructuredAst {
    pub root: StructuredNode,
    pub goto_count: usize,
    pub node_count: usize,
}
```

### 2.3 Algorithm (`ControlFlowStructurer`)

```rust
pub struct ControlFlowStructurer {
    blocks: Vec<BasicBlock>,
}

impl ControlFlowStructurer {
    pub fn new(blocks: Vec<BasicBlock>) -> Self;
    pub fn structure(&self, entry: BlockId) -> Result<StructuredAst, StructureError>;
}
```

Steps inside `structure`:
1. Build `petgraph::DiGraph` from `BasicBlock.successors`.
2. Tarjan SCC to find back-edges (natural loop headers).
3. Cooper et al. iterative dominator computation → `DomTree`.
4. Post-order dominator-tree traversal: attempt canonical patterns
   (sequence, if, if-else, while, do-while, switch).
5. Residual back-edges become `StructuredNode::Goto`.

### 2.4 Supporting structures

| Type | Purpose |
|---|---|
| `CfgGraph` | petgraph-backed directed graph with block-map lookup |
| `DomTree` / `PostDomTree` | immediate dominator / post-dominator trees |
| `LoopDetector` + `NaturalLoop` | back-edge discovery and loop member sets |
| `GotoEliminator` | tries to convert `goto` into `break`/`continue` |
| `SwitchRecovery` | detects jump-table patterns in basic blocks |
| `CriticalEdgeSplitter` | splits critical edges before structuring |
| `EmptyBlockEliminator` | prunes empty pass-through blocks |
| `IrreducibleLoopHandler` | detects and handles irreducible loops |
| `CfsValidator` | post-structure sanity checker |
| `RegionTree` / `Region` | hierarchical region abstraction |

### 2.5 Sub-modules

| Module | Role |
|---|---|
| `dream_algorithm` | Core DREAM structuring implementation |
| `loop_detector` | SCC-based back-edge discovery |
| `loop_structurer` | Promotes loop regions to `StructuredNode::Loop` |
| `goto_elimination` | First-pass goto removal |
| `goto_reducer` | Second-pass: reduce remaining gotos |
| `switch_recovery` | Jump-table → `Switch` pattern |
| `condition_recovery` | `CmpOp` extraction, `jcc_to_condition` mapping |
| `structural_regions` | Region tree construction (re-exported as `region_analysis`) |
| `region_tree_builder` | Builds `RegionTree` from dominator info |
| `ast_postpass` | Final AST cleanup passes |

### 2.6 Implementation status: **PARTIAL → substantial**

The core structuring algorithm is complete.  `petgraph::tarjan_scc` drives SCC,
dominator tree is Cooper et al., and the DREAM post-order traversal covers
if/if-else/while/do-while/switch.  No `todo!`/`unimplemented!` macros.
Known gap: `IrreducibleLoopHandler::is_irreducible` is a structural placeholder
— it detects irreducibility but the duplication/node-splitting remedy is not
implemented, so irreducible loops fall back to `Goto` residue (same as Hex-Rays
fallback behaviour).

---

## 3. `rustre-decompiler-expr` — Expression Trees

### 3.1 Purpose

Expression reconstruction from SSA-like temporary assignments.  Provides the
expression tree (`Expr`), folding (inline single-use temps), simplification
(constant folding, algebraic identities), normalization, pattern matching, and
a C-like printer.

### 3.2 Key types

```rust
pub enum IntWidth { I8, I16, I32, I64, U8, U16, U32, U64 }

pub enum BinOp {
    Add, Sub, Mul, Div, Rem,
    And, Or, Xor, Shl, Shr, Sar,
    Eq, Ne, Lt, Le, Gt, Ge,
    LAnd, LOr,
}

pub enum UnOp { Neg, Not, LNot, Deref, AddrOf }

pub enum Expr {
    Const(i64, IntWidth),
    Var(String),
    BinOp(BinOp, Box<Self>, Box<Self>),
    UnOp(UnOp, Box<Self>),
    Cast(Box<Self>, IntWidth),
    Call { callee: String, args: Vec<Self> },
    Index { base: Box<Self>, idx: Box<Self> },
    Member { base: Box<Self>, field: String },
    ArrowMember { base: Box<Self>, field: String },
    Phi(Vec<String>),         // SSA phi node
    Undefined,
}
```

`Expr` implements `depth()`, `node_count()`, `referenced_vars()`,
`substitute(var, replacement)`, `contains_var()`, `is_constant_expr()`, and a
C-like `Display`.

### 3.3 SSA assignment form

```rust
pub struct SsaAssign { pub name: String, pub expr: Expr }

pub struct DefUseChain {
    defs: HashMap<String, usize>,
    uses: HashMap<String, usize>,
}
impl DefUseChain {
    pub fn from_assignments(assigns: &[SsaAssign]) -> Self;
    pub fn def_count(&self, name: &str) -> usize;
    pub fn use_count(&self, name: &str) -> usize;
    pub fn is_dead(&self, name: &str) -> bool;
    pub fn is_single_def_use(&self, name: &str) -> bool;
    pub fn dead_vars(&self) -> Vec<&str>;
}
```

### 3.4 Transformation components

```rust
// Inline single-use temporaries
pub struct ExprFolder { ... }
impl ExprFolder {
    pub fn with_assignments(assigns: &[SsaAssign]) -> Self;
    pub fn fold_expressions(&self, assigns: &[SsaAssign]) -> Result<Vec<SsaAssign>, ExprError>;
    pub fn fold_expr(&self, expr: Expr) -> Result<Expr, ExprError>;
}

// Algebraic simplification (constant folding, identities, De Morgan)
pub struct ExprSimplifier {
    apply_demorgan: bool,
    max_iterations: usize,
    const_fold: bool,
}
impl ExprSimplifier {
    pub fn simplify(&self, expr: Expr) -> Expr;
    pub fn simplify_assignments(&self, assigns: Vec<SsaAssign>) -> Vec<SsaAssign>;
}

// Canonical form (commutative operand sorting, redundant-cast removal)
pub struct ExprNormalizer;
impl ExprNormalizer {
    pub fn normalize(&self, expr: Expr) -> Expr;
}

// Structural / semantic comparison
pub struct ExprComparator { ... }
impl ExprComparator {
    pub fn equivalent(&self, a: &Expr, b: &Expr) -> bool;
    pub fn syntactically_equal(&self, a: &Expr, b: &Expr) -> bool;
    pub fn similarity(&self, a: &Expr, b: &Expr) -> f64;
}

// C-like string emission
pub struct ExprPrinter { opts: ExprPrintOptions }
impl ExprPrinter {
    pub fn print(&self, expr: &Expr) -> String;
}

// Rewrite rule engine
pub struct ExprRewriter { rules: Vec<Box<dyn Fn(&Expr) -> Option<Expr> + ...>> }
impl ExprRewriter {
    pub fn add_rule<F: Fn(&Expr) -> Option<Expr> + Send + Sync + 'static>(&mut self, rule: F);
    pub fn rewrite(&self, expr: Expr) -> Expr;
}

// Pattern predicates
pub struct ExprPattern;
impl ExprPattern {
    pub fn is_binop_var_const(expr: &Expr) -> bool;
    pub fn is_var_comparison(expr: &Expr) -> bool;
    pub fn is_array_index(expr: &Expr) -> bool;
    pub fn extract_array_index(expr: &Expr) -> Option<(&Expr, &Expr, u64)>;
}
```

### 3.5 Sub-modules

| Module | Role |
|---|---|
| `dag_simplifier` | DAG-form simplification (sharing-aware) |
| `expr_reconstruction` | Reconstructs `Expr` from linear IL |
| `expr_simplification` | Algebraic rules table |
| `expr_simplifier` | Simplifier orchestration |
| `expr_type_propagator` | Type propagation through expression tree |
| `expression_recovery` | Top-level expression recovery from IL |
| `pattern_library` | Reusable pattern predicates (two stub entries at lines 1035, 1435) |
| `peephole_optimizer` | 40+ targeted peephole rules |
| `expr_precedence` | C operator precedence for bracket insertion |
| `expr_pattern_matcher` | Pattern-matching utilities |
| `casts` | Cast-related helpers (deliberate truncation boundaries) |

### 3.6 Implementation status: **PARTIAL → substantial**

Core `Expr`, `ExprFolder`, `ExprSimplifier`, `ExprNormalizer`, and `ExprPrinter`
are complete.  Two functions in `pattern_library.rs` (lines 1035 and 1435)
return `None // stub` — these are pattern predicates that are defined but not
yet filled in.  The `expr_type_propagator` exists but the bridge connecting it
to the main type recovery path is through the `rustre-decompiler-type` crate,
not directly called by the coordinator yet.

---

## 4. `rustre-decompiler-type` — Type System and Inference

### 4.1 Purpose

Complete C-like type system for decompiler output: struct/union/enum/array/
pointer/function-pointer types, a type environment, typed expression emission
(rewriting raw pointer arithmetic into `ptr->field` / `arr[i]` forms), and
variable renaming from inferred types.

### 4.2 Core types

```rust
pub enum DecompType {
    Void, Bool,
    Int(IntWidth),          // I8/I16/I32/I64/U8/U16/U32/U64
    Float32, Float64,
    Ptr(Box<Self>),
    Array(Box<Self>, u64),
    Struct(Box<StructType>),
    FnPtr { ret: Box<Self>, params: Vec<Self> },
    CStr,
    Enum { name: String, variants: Vec<EnumVariant>, backing: IntWidth },
    Unknown,
}

pub struct StructType {
    pub name: String, pub fields: Vec<StructField>, pub total_size: u64,
}
pub struct StructField { pub offset: u64, pub name: String, pub ty: DecompType }

pub struct TypeEnvironment {
    vars: HashMap<String, DecompType>,
    structs: HashMap<String, StructType>,
}
impl TypeEnvironment {
    pub fn set(&mut self, var: impl Into<String>, ty: DecompType);
    pub fn get(&self, var: &str) -> Option<&DecompType>;
    pub fn add_struct(&mut self, st: StructType);
    pub fn struct_named(&self, name: &str) -> Option<&StructType>;
    pub fn resolve_struct<'a>(&'a self, ty: &'a DecompType) -> Option<&'a StructType>;
}
```

### 4.3 Expression emission

```rust
pub struct TypedExprEmitter<'a> {
    env: &'a TypeEnvironment,
    // ...
}
impl TypedExprEmitter<'_> {
    pub fn emit(&self, expr: &Expr) -> Result<String, TypeError>;
}
```

Rewrites `*(base + offset)` → `base->field_name` when `base`'s type resolves
to a known struct and `offset` matches a field.  Handles arrays, nested
structs, and enums.

### 4.4 Variable renaming

```rust
pub struct TypeAwareRenamer { /* counter maps per type prefix */ }
impl TypeAwareRenamer {
    pub fn rename(&mut self, ty: &DecompType) -> String;
    pub fn rename_with_hint(&mut self, hint: &str, ty: &DecompType) -> String;
    pub fn rename_all(&mut self, vars: &[(String, DecompType)]) -> HashMap<String, String>;
    pub fn rename_variables(&mut self, code: &str, env: &TypeEnvironment) -> String;
}
```

Produces names like `p_node`, `arr_u32`, `fn_ptr` based on type structure.

### 4.5 Type inference components

| Type | Purpose |
|---|---|
| `TypeConstraint` | `lhs: String`, `rhs: String`, `reason: String` — unification constraint |
| `TypeUnifier` | Union-find unification over constraint sets |
| `TypeInference` | Accumulates constraints from assignments and pointer dereferences |
| `TypeLayout` | Struct field layout with padding computation |
| `QualifiedType` + `TypeQualifier` | `const`/`volatile`/`restrict` bits |
| `UnionType` | Union with named members |
| `FunctionType` + `CallingConvention` | Function pointer type with prototype emission |

### 4.6 Sub-modules

| Module | Role |
|---|---|
| `aggregate_recovery` | Aggregate (struct/union) type recovery from memory access patterns |
| `andersen_pta` | Andersen-style points-to analysis |
| `array_detector` | Detects array access patterns (`base + i * stride`) |
| `c_type_layout` | C ABI layout rules (alignment, padding) |
| `pointer_analysis` | Pointer alias analysis for type propagation |
| `struct_recovery` | Struct field layout recovery from dereferences |
| `type_flow_lattice` | Lattice for dataflow-based type propagation |
| `type_printer_advanced` | Advanced C type string emission with qualifiers |
| `type_propagation` | Interprocedural type propagation |
| `type_propagator` | Intraprocedural type propagator (dataflow) |
| `type_reconstruction` | Holistic type reconstruction from all evidence |
| `type_recovery_engine` | Coordinates all sub-passes |
| `type_recovery_heuristics` | Heuristic rules (e.g. `strlen` return → `usize`) |
| `type_unification` | Union-find constraint solver |

### 4.7 Implementation status: **PARTIAL → substantial**

`DecompType`, `TypeEnvironment`, `TypedExprEmitter`, and `TypeAwareRenamer` are
complete and tested.  The more sophisticated passes (`andersen_pta`,
`type_flow_lattice`, `pointer_analysis`) are fully modelled but their outputs
are not yet plumbed into the top-level `TypeRecoveryEngine` call chain called
from the coordinator.  No `todo!`/`unimplemented!` macros in this crate.

---

## 5. `rustre-decompiler-c` — C Pseudocode Emitter

### 5.1 Purpose

Final output stage: takes a `StructuredAst` (from `rustre-decompiler-cfs`) and
a `TypeEnvironment` (from `rustre-decompiler-type`) and emits formatted C
pseudocode.

### 5.2 Configuration

```rust
pub struct CFormat {
    pub indent: IndentStyle,         // Spaces(u8) | Tabs
    pub braces: BraceStyle,          // KAndR | Allman
    pub const_notation: ConstNotation, // Auto | Decimal | Hex | HexPrefixed
    pub var_naming: VarNaming,       // TypeBased | Raw | Sequential
    pub emit_block_comments: bool,
    pub emit_prototype: bool,
}
```

### 5.3 Key types

```rust
// Function parameter for prototype emission
pub struct FunctionParam { pub name: String, pub ty: DecompType }

// Function signature for prototype header
pub struct FunctionSignature {
    pub name: String,
    pub return_type: DecompType,
    pub params: Vec<FunctionParam>,
    pub is_variadic: bool,
}

// Local variable declaration
pub struct VarDecl { pub name: String, pub ty: DecompType }

// Emission statistics
pub struct EmitStats {
    pub goto_count: usize, pub variable_count: usize, pub lines: usize,
    pub if_count: usize, pub loop_count: usize, pub switch_count: usize,
}

// Final output
pub struct DecompiledFunction { pub name: String, pub source_code: String, pub stats: EmitStats }

pub struct CPrinter { format: CFormat }
impl CPrinter {
    pub fn new(format: CFormat) -> Self;
    pub fn print(&self, func_name: &str, sig: &FunctionSignature,
                 locals: &[VarDecl], ast: &StructuredAst,
                 env: &TypeEnvironment) -> Result<DecompiledFunction, EmitError>;
}
```

### 5.4 Sub-modules

| Module | Role |
|---|---|
| `c_printer` | Core `CPrinter` recursive AST walker |
| `c_output_full` | Full-function output assembly (signature + locals + body) |
| `c_postprocess` | Post-emission cleanup (trailing whitespace, blank line normalization) |
| `c_simplifier` | Source-level simplification (redundant casts, double-not) |
| `c_goto_removal` | Source-level goto→structured elimination |
| `c_typeinfer` | Lightweight type inference for untyped variables |
| `c_quality` | Quality scorer: goto density, nesting depth, line count |
| `c_annotation` | Inline annotation injection (address comments, confidence) |
| `c_comment_gen` | Comment generation (function headers, field names) |
| `c_diff_emit` | Diff-format output for before/after comparisons |
| `c_macro_detection` | Detects patterns that look like inlined macros |
| `c_recovery` | Recovery from partially structured ASTs |
| `type_formatter` | `DecompType` → C type string formatting |

### 5.5 Implementation status: **PARTIAL → complete for basic cases**

`CPrinter` handles all `StructuredNode` variants (Sequence, If, IfElse, Loop,
Switch, Goto, Break, Continue, Return, BasicBlock).  `c_goto_removal` handles
residual gotos.  No `todo!`/`unimplemented!` macros.  The `c_typeinfer` module
provides lightweight inference for variables whose type is `DecompType::Unknown`
rather than the full `rustre-decompiler-type` engine — gap for complex types.

---

## 6. `rustre-decompiler-ghidra` — Ghidra P-Code Backend

### 6.1 Purpose

Optional decompiler back-end that either spawns real Ghidra headless
(`analyzeHeadless`) and parses its JSON output, or falls back to a pure-Rust
P-Code lifter when Ghidra is unavailable.  Implements `DecompilerBackend` from
`rustre-decompiler`.

### 6.2 Key types

```rust
// P-Code operation mnemonics (50+ variants)
pub enum PCodeOp {
    Copy, Load, Store, Branch, CBranch, BranchInd, Call, CallInd, CallOther, Return,
    IntEqual, IntNotEqual, IntSLess, IntSLessEqual, IntLess, IntLessEqual,
    IntAdd, IntSub, IntMult, IntDiv, IntSDiv, IntRem, IntSRem,
    IntOr, IntAnd, IntXor, IntNegate, IntNot, IntLeftShift, IntRightShift, IntSRightShift,
    BoolNegate, BoolXor, BoolAnd, BoolOr,
    FloatAdd, FloatSub, FloatMult, FloatDiv, FloatNeg, FloatAbs, FloatSqrt,
    PieceConcat, Subpiece, PopCount, Ptradd, Ptrsub,
}

// P-Code value node
pub enum PCodeVarnode {
    Register { space: String, offset: u64, size: u8 },
    Const { value: u64, size: u8 },
    Unique { offset: u64, size: u8 },
    Ram { address: u64, size: u8 },
    Stack { offset: i64, size: u8 },
}

pub struct PCodeInstr { pub op: PCodeOp, pub inputs: Vec<PCodeVarnode>, pub output: Option<PCodeVarnode> }
```

### 6.3 Architecture: dual-path `GhidraBackend`

```rust
pub struct GhidraBackend { arch: String, lifter: PCodeLifter }

impl GhidraBackend {
    pub fn for_x86_64() -> Self;
    pub fn for_arm64() -> Self;
    pub fn try_headless_ghidra(binary_path: &str, func_addr: u64) -> Option<String>;
}

impl DecompilerBackend for GhidraBackend {
    fn name(&self) -> &'static str { "ghidra-pcode" }
    fn supported_archs(&self) -> Vec<String> {
        // x86_64, x86, aarch64, arm, mips
    }
    fn decompile_function(&self, address, instructions, func_name)
        -> Result<DecompiledFunction, DecompilerError>
    {
        // 1. Try RUSTRE_BINARY_PATH env-var + try_headless_ghidra
        // 2. Fallback: self.lifter.lift_to_pseudo_c(...)
    }
}
```

**Headless Ghidra path** (`try_headless_ghidra`):
1. `GhidraConfig::detect()` locates Ghidra installation.
2. Creates a temp `GhidraFfiProject`, imports the binary.
3. Writes a decompile script to a temp file.
4. Calls `project.run_script(script, [addr, out_path])`.
5. Parses JSON output via `parse_decompiled_function_json`.
6. Returns formatted pseudo-C.

**Pure-Rust fallback** (`PCodeLifter::lift_to_pseudo_c`): translates each
`Instruction` to P-Code via `PCodeTranslator`, then emits pseudo-C from P-Code
operations.

### 6.4 Infrastructure types

| Type | Role |
|---|---|
| `PCodeTranslator` | Instruction → `Vec<PCodeInstr>` (x86 pattern matching) |
| `PCodeLifter` | Orchestrates P-Code lifting → pseudo-C emission |
| `GhidraConfig` | Locates Ghidra install dir and `analyzeHeadless` binary |
| `GhidraFfiProject` | Temp Ghidra project creation and script runner |
| `GhidraServerConfig` / `GhidraServer` | HTTP/gRPC mock (real impl: connects to running Ghidra server) |
| `GhidraProject` | Project file descriptor |
| `GhidraScript` | Script descriptor with argument list |
| `GhidraDecompileRequest` / `GhidraDecompileResponse` | Request/response for network bridge |
| `GhidraMemoryMap` / `GhidraSegment` | Memory layout for Ghidra analysis |
| `GhidraSymbolImporter` | Feeds symbols (imports/exports) into Ghidra projects |
| `GhidraTypeImporter` | Feeds type definitions into Ghidra type database |
| `GhidraXmlParser` | Parses Ghidra XML export (function lists, types) |
| `GhidraRpcClient` | Client for running Ghidra as a service |
| `GhidraDataTypeDb` | Local mirror of Ghidra type database |

Additional sub-modules: `ghidra_types_db`, `ghidra_ast`, `ghidra_pcode`,
`pcode_interpreter`, `decompiler_ir_bridge`, `ghidra_type_recovery`,
`pcode_analysis`, `result_merger`.

### 6.5 `result_merger` — combining Ghidra + internal output

`ResultMerger` holds a `GhidraBackend` and an `InternalBackend` and produces a
merged `DecompiledFunction` by selecting whichever result has higher confidence
or merging variable lists.  Tests (including the two `// stub output` lines)
verify merge logic when one or both backends fail.

### 6.6 Implementation status: **PARTIAL**

The `PCodeTranslator` covers common x86 mnemonics for a functional fallback.
The real Ghidra headless path is fully coded but requires an external Ghidra
installation; without it, `try_headless_ghidra` returns `None` gracefully.
`GhidraServer` / `GhidraRpcClient` contain `// In a real implementation this
would open a socket` comments — the network bridge is a structural skeleton.
`pcode_interpreter` and `pcode_analysis` are modelled but not exercised by the
main pipeline.

---

## 7. Dependency Graph Summary

```
rustre-decompiler-expr   (no intra-workspace deps)
         ▲
rustre-decompiler-type   (← expr)
         ▲
rustre-decompiler-cfs    (no intra-workspace deps)
         ▲
rustre-decompiler-c      (← cfs, expr, type)
         ▲
rustre-decompiler        (← cfs, c, type, + rustre-core, analysis-*, loader, arch-x86)
         ▲
rustre-decompiler-ghidra (← decompiler, rustre-core)
         ▲
rustre-mcp-tools, rustre-mcp-server, rustre-gui
```

External dependency matrix:

| Crate | petgraph | rayon | parking_lot | tokio | serde |
|---|---|---|---|---|---|
| rustre-decompiler | — | yes | yes | — | yes |
| rustre-decompiler-cfs | yes | — | — | — | yes |
| rustre-decompiler-expr | — | — | — | — | yes |
| rustre-decompiler-type | — | — | — | — | yes |
| rustre-decompiler-c | — | — | — | — | yes |
| rustre-decompiler-ghidra | — | — | — | yes | yes |

---

## 8. Integration Points with Other Subsystems

| Subsystem | How it connects |
|---|---|
| `rustre-loader` | `load_binary` / `default_multi_format_registry` → `RichLoadResult` which carries byte image, section table, arch/bits |
| `rustre-arch-x86` | `X86Arch::disassemble` decodes byte slices into `Vec<Instruction>` used by the pipeline |
| `rustre-analysis-fn` | `FunctionDetector` enumerates functions; `NoreturnDetector` annotates call sites |
| `rustre-analysis-callconv` | `detect_calling_convention_auto` identifies win64/sysv/cdecl and maps register args |
| `rustre-analysis-typerecov` | External type recovery pass plugged into the coordinator pass list |
| `rustre-mcp-tools` | Calls `decompile_function_from_binary`, `decompile_function_in_load`, `detect_functions_in_load`; also uses `GhidraBackend` directly for the Ghidra MCP tool |
| `rustre-gui` | Uses `DecompilerPipeline`, `CPrinter`, `CFormat`, `TypeEnvironment` for the decompile panel |

---

## 9. Known Gaps and TODOs

| Gap | Crate | Severity |
|---|---|---|
| SSA form not connected to pass pipeline — `construct_ssa` exists but no pass calls it; expression recovery operates on raw instructions | rustre-decompiler | HIGH |
| `BinaryNinja` and `RetDec` `DecompilerBackendKind` variants have no implementing struct | rustre-decompiler | MEDIUM |
| Timeout enforcement is post-hoc (checks after pass completes, does not preempt) | rustre-decompiler | MEDIUM |
| Two stub pattern predicates in `pattern_library.rs` (lines 1035, 1435) return `None` unconditionally | rustre-decompiler-expr | LOW |
| `andersen_pta` / `type_flow_lattice` / `pointer_analysis` modules are modelled but outputs not wired into `TypeRecoveryEngine` | rustre-decompiler-type | MEDIUM |
| `IrreducibleLoopHandler` detects irreducible loops but does not perform node-splitting — falls back to raw `Goto` | rustre-decompiler-cfs | MEDIUM |
| `GhidraServer` / `GhidraRpcClient` network bridge is a structural skeleton (`// In a real implementation this would open a socket`) | rustre-decompiler-ghidra | MEDIUM |
| `pcode_interpreter` and `pcode_analysis` modules exist but are not called from the main Ghidra path | rustre-decompiler-ghidra | LOW |
| `c_typeinfer` does lightweight inference only; does not call the full `rustre-decompiler-type` engine for `DecompType::Unknown` variables | rustre-decompiler-c | LOW |

---

## 10. Pipeline End-to-End Walkthrough

```
1.  MCP tool calls: decompile_function_from_binary(path, va, opts)
2.  binary_entry.rs: load_binary(path)  →  RichLoadResult
3.  binary_entry.rs: slice_at_va(load, va)  →  (base_va, &bytes)
4.  arch-x86: X86Arch::disassemble(bytes, va, bits)  →  Vec<Instruction>
                  (stops at RET or after MAX_FN_INSTRUCTIONS)
5.  standard_pipeline_arc(opts)  →  Arc<DecompilerPipeline>
6.  pipeline.run_with_structured_emit(va, name, &instructions)
    a. DecompilerContext::new(va, name, opts)
    b. For each DecompilerPass in pipeline:
         pass.run(&mut ctx, va, &instructions)
         [VariableCollectionPass, CallConvPass, TypeRecoveryPass, …]
    c. ctx.build_cfg_from_instructions(&instructions)
         → micro-passes: simplify_xor_self, hide_callee_saved_push_pop,
                         fuse_cmp_branch, propagate_register_copies,
                         recover_stack_locals, rewrite_tail_call, …
         → Vec<BasicBlock>
    d. ControlFlowStructurer::new(blocks).structure(entry)
         → StructuredAst  (DREAM algorithm)
    e. TypeEnvironment from collected variables
    f. CPrinter::new(CFormat::default()).print(name, sig, locals, &ast, &env)
         → DecompiledFunction { source_code: String, stats: EmitStats }
7.  Return DecompiledFunction to MCP tool
8.  MCP tool serialises to JSON response
```

---

## 11. Implementation Status Summary

| Crate | Lines | Status | Notes |
|---|---|---|---|
| rustre-decompiler | 26 943 | **PARTIAL-COMPLETE** | Full pipeline wired for x86-64; SSA not connected; 2 backend kinds unimplemented |
| rustre-decompiler-cfs | 16 337 | **PARTIAL-COMPLETE** | DREAM algorithm complete; irreducible loop splitting missing |
| rustre-decompiler-expr | 16 044 | **PARTIAL-COMPLETE** | Core transforms complete; 2 stub predicates; type-propagator bridge missing |
| rustre-decompiler-type | 15 369 | **PARTIAL-COMPLETE** | Type system + TypedExprEmitter complete; advanced analyses not wired |
| rustre-decompiler-c | 15 287 | **PARTIAL-COMPLETE** | CPrinter handles all AST nodes; type inference lightweight only |
| rustre-decompiler-ghidra | 16 467 | **PARTIAL** | Headless Ghidra path coded; network bridge skeleton; pcode interpreter unused |
