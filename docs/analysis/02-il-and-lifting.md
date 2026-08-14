# 02 — IL Stack and Lifting Pipeline

> Analysis date: 2026-07-01
> Crates covered: `rustre-il`, `rustre-il-llil`, `rustre-il-mlil`, `rustre-il-hlil`, `rustre-il-lift`, `rustre-il-passes`

---

## 1. Overview

RustRE implements a four-tier Intermediate Language (IL) pipeline that closely mirrors Binary Ninja's architecture (Lift → LLIL → MLIL SSA → HLIL). The stack is designed to be architecture-independent above the `Lift` tier; all arch-specific knowledge is encapsulated in `rustre-il-lift`, which consumes `rustre-core` disassembly objects and produces generic IR trees that feed into the rest of the pipeline.

### Pipeline diagram

```
Binary bytes
     │
     ▼  rustre-arch-* (disassembly)
rustre-core::Instruction
     │
     ▼  rustre-il-lift  (ArchLifter trait, per-arch modules)
IrExpr / Effect / LiftedInstr          ← Lift tier
     │
     ▼  rustre-il-llil  (llil_builder, llil_to_mlil_bridge)
LlilFunction / LlilInstruction / LlilExpr  ← LLIL tier
     │
     ▼  rustre-il-mlil  (ssa_reconstruction, phi_placement)
MlilFunction / MlilInstruction / MlilExpr / SsaVar  ← MLIL SSA tier
     │
     ▼  rustre-il-hlil  (hlil_control_flow_recovery, hlil_decompiler)
HlilFunction / HlilStatement / HlilExpr  ← HLIL tier
     │
     ▼  rustre-decompiler (rustre-decompiler-c, etc.)
Decompiled C-like output
```

`rustre-il-passes` can operate on the LLIL tier and, through bridge structures, influence MLIL. `rustre-il` is the shared foundation crate that all tiers depend on for cross-cutting definitions.

---

## 2. `rustre-il` — Foundation Types

### Purpose
Provides the minimal shared vocabulary that every IL tier agrees on: tier identity tags, tier-ordering relations, and cross-tier error types. It carries no instruction or expression types; those live in the tier-specific crates.

### Cargo.toml dependencies
| Dependency | Role |
|---|---|
| `serde` | Tier serialization |
| `thiserror` | `IlError` derivation |

No intra-workspace dependencies.

### Public API

#### `IlTier`
```rust
pub enum IlTier { Lift, Llil, Mlil, Hlil }

impl IlTier {
    pub const fn tag(self) -> &'static str;    // "lift", "llil", "mlil", "hlil"
    pub const fn next(self) -> Option<Self>;   // Lift→Llil→Mlil→Hlil→None
}
```
Used by passes and adapter code to reason about tier provenance without importing the concrete instruction types.

#### `IlError`
```rust
pub enum IlError {
    Unsupported { tier: IlTier, op: String },
    TierMismatch { expected: IlTier, actual: IlTier },
    Invalid(String),
}
```

### Implementation status: **Complete**
All code is real; the unit tests cover tier ordering and tag strings. No stubs.

---

## 3. `rustre-il-llil` — Low-Level IL

### Purpose
The architecture-independent LLIL sits one step above raw machine instructions. Each machine instruction lifts to one or more `LlilInstruction`s tagged with the original `Address` and byte-length. Memory reads/writes are explicit `Load`/`Store` nodes, enabling data-flow analysis without architecture-specific logic.

### Cargo.toml dependencies
| Dependency | Role |
|---|---|
| `rustre-il` | `IlTier`, `IlError` |
| `rustre-core` | `address::Address` |
| `rustre-il-lift` | `IrExpr`, `Effect`, `LiftedInstr` consumed by bridge |
| `petgraph` | CFG as `DiGraph` |
| `ahash` | Fast hash maps keyed by `Address` |
| `bitflags` | `LlilBlockFlags` |
| `serde`, `serde_json` | Serialization |
| `anyhow`, `thiserror` | Error handling |

### Module structure

| Module | Role |
|---|---|
| `lib.rs` | `Size`, `LlilRegister`, `LlilExpr`, `LlilInstruction`, `LlilAnnotatedInstr`, `LlilBlock`, `LlilFunction`, `LlilCfg` |
| `llil_builder` | Fluent builders: `InstrBuilder`, `BlockBuilder`, `FunctionBuilder`, `LlilBuilder`, `LlilValidator`, `LlilPrinter` |
| `llil_interpreter` | Concrete-value interpreter for LLIL functions |
| `llil_optimizer` | Peephole optimizer operating on LLIL expression trees |
| `llil_semantics` | Flag-semantics lowering |
| `llil_to_mlil_bridge` | LLIL→MLIL elevation (calling convention + stack frame + SSA prep) |
| `llil_verification` | Structural correctness checks |
| `verifier` | Extended verifier variant |
| `llil_branch_resolver` | Resolves indirect jump targets |
| `llil_register_allocator` | Register allocation pass for re-materialised code paths |
| `llil_stack_analyzer` | Stack-frame layout analysis |
| `x86_opcode_lift` | Legacy x86 single-opcode lifter (used by tests) |

### Key types

#### `Size`
```rust
pub enum Size { Byte, Word, DWord, QWord, OWord }
impl Size {
    pub const fn bytes(self) -> usize;
    pub const fn bits(self) -> usize;
}
impl TryFrom<usize> for Size { ... }  // 1/2/4/8/16 bytes
```
Width token carried by every expression and instruction node.

#### `LlilRegister`
```rust
pub enum LlilRegister {
    Concrete(String),   // "rax", "xmm0"
    Temporary(u32),     // tmp0, tmp1 (lifter-allocated)
}
```

#### `LlilExpr` (selected variants)
```rust
pub enum LlilExpr {
    // constants / registers
    Const { value: u64, size: Size },
    RegisterRef { reg: LlilRegister, size: Size },
    Register { id: u32, size: Size },        // optimizer form
    Load { addr: Box<Self>, size: Size },

    // arithmetic — dual (tuple + struct) forms
    AddT(Box<Self>, Box<Self>, Size),
    Add { left: Box<Self>, right: Box<Self>, size: Size },
    // Sub, Mul, DivU, DivS, ModU, ModS, Neg ...
    // Bitwise: And, Or, Xor, Not, Shl/ShlT, Shr, Sar, Rol, Ror

    // comparisons (result is always Size::Byte)
    CmpEq(Box<Self>, Box<Self>), CmpNe, CmpSlt, CmpUlt, CmpSle, CmpUle,
    CmpSgt, CmpUgt, CmpSge, CmpUge,

    // extension / truncation
    ZeroExtend { expr, from: Size, to: Size },
    SignExtend  { expr, from: Size, to: Size },
    LowPart    { expr, to: Size },

    // floating-point
    FAdd, FSub, FMul, FDiv, FNeg, FCmpEq, FCmpLt, FCmpGt,
    IntToFloat { expr, to: Size },
    FloatToInt { expr, to: Size },

    // misc
    StackPointer(Size),
    Flag(String),                              // "carry", "zero"
    CondExpr { cond, true_val, false_val, size },
    Undefined(Size),
    Intrinsic { name: String, args: Vec<Self>, result_size: Size },
}
```
Note: the "dual form" duplication (e.g. `AddT` vs `Add { .. }`) is a legacy artifact where the builder uses tuple forms and the optimizer uses struct forms. This is a known technical debt — it doubles pattern-match arms in passes and visitors.

#### `LlilInstruction` (selected variants)
```rust
pub enum LlilInstruction {
    Nop,
    SetReg { dest: LlilRegister, size: Size, value: LlilExpr },
    SetRegSplit { high, low: LlilRegister, src: LlilExpr },
    Load  { dest: LlilRegister, size: Size, addr: LlilExpr },
    Store { addr: LlilExpr, size: Size, value: LlilExpr },
    SetFlag { name: String, src: LlilExpr },
    Push { size: Size, src: LlilExpr },
    Pop  { dest: LlilRegister, size: Size },
    Jump(LlilExpr),          // unconditional (builder form)
    JumpDest { dest: LlilExpr },  // unconditional (optimizer form)
    JumpTo { dest: LlilExpr, targets: Vec<Address> },  // indirect + hint
    Call(LlilExpr),
    CallDest { dest: LlilExpr },
    ConditionalJump { cond: LlilExpr, true_target: Address, false_target: Address },
    CondJump { cond, true_dest, false_dest: Address },
    TailCall { dest: LlilExpr },
    Ret,
    Return { value: Option<LlilExpr> },
    CondCall { cond: LlilExpr, dest: LlilExpr },
    Trap { code: u64 },
    SysCall,
    Breakpoint,
    Intrinsic { name: String, args: Vec<LlilExpr> },
    Undefined,
    UnimplementedRaw { bytes: Vec<u8>, address: Address },
    Unimplemented { mnemonic: String },
}
```
`LlilInstruction` has the same dual-form issue (e.g. `Jump` vs `JumpDest`, `Call` vs `CallDest`, `CondJump` vs `ConditionalJump`).

Key methods on `LlilInstruction`:
- `is_terminator() -> bool` — does this end a basic block?
- `successors() -> Vec<Address>` — statically-known successors
- `reads_flag(flag: &str) -> bool` / `writes_flag(flag: &str) -> bool`
- `reads_reg(reg: &LlilRegister) -> bool` / `writes_reg(reg: &LlilRegister) -> bool`

### `llil_to_mlil_bridge.rs`

Performs the LLIL → MLIL elevation in four passes:
1. **Calling-convention resolution** — maps physical registers (rdi/rsi/rdx… or a0/a1…) to named parameters.
2. **Stack frame analysis** — `[rsp+N]` accesses become `local_N` named variables.
3. **Flag semantics lifting** — replaces raw flag reads with typed condition expressions derived from the last flag-defining instruction.
4. **SSA preparation** — renames registers for the Braun online SSA constructor in `rustre-il-mlil::ssa_reconstruction`.

Calling conventions hard-coded in the bridge module:
- `sysv_amd64` (Linux/macOS x86-64)
- `ms_x64` (Windows x64)
- `arm64_aapcs`
- `riscv64_lp64d`

### Implementation status: **Partial**

| Component | Status | Notes |
|---|---|---|
| `LlilExpr` / `LlilInstruction` types | Complete | Full coverage, typed, Display impl |
| `llil_builder` | Complete | Fluent API, validator, printer |
| `llil_optimizer` | Complete | Peephole, constant folding |
| `llil_interpreter` | Complete | Concrete evaluation |
| `llil_branch_resolver` | Partial | Static targets only; dynamic targets unresolved |
| `llil_register_allocator` | Partial | Basic liveness, no spilling |
| `llil_stack_analyzer` | Partial | Frame detection; multi-level frames incomplete |
| `llil_to_mlil_bridge` | Partial | 4 calling conventions; x86 flag lifting partial |
| `x86_opcode_lift` | Partial | 10 `todo!` hits |

Known gap: dual-form variants (`AddT`/`Add`, `Jump`/`JumpDest`, etc.) should be unified — requires a coordinated refactor of builder, optimizer, and pass consumers.

---

## 4. `rustre-il-mlil` — Medium-Level IL (SSA)

### Purpose
MLIL is the SSA form of LLIL. It replaces registers and temporaries with SSA variables (name + version), inserts PHI nodes at dominance-frontier join points, and enables precise data-flow analysis.

### Cargo.toml dependencies
| Dependency | Role |
|---|---|
| `rustre-il` | `IlTier` |
| `rustre-core` | `Address` |
| `rustre-il-llil` | `LlilExpr`, `LlilInstruction`, `LlilFunction` (input to SSA construction) |
| `rustre-il-lift` | `LiftedInstr` (for inter-crate diagnostics) |
| `ahash` | Hash maps for SSA renaming tables |
| `serde`, `serde_json` | Serialization |
| `anyhow`, `thiserror` | Errors |

### Module structure

| Module | Role |
|---|---|
| `lib.rs` | `SsaVar`, `MlilExpr`, `MlilInstruction`, `MlilAnnotatedInstr`, `MlilBasicBlock`, `MlilFunction` |
| `mlil_ssa` | `MlilSsa`, `SsaPhiNode`, `SsaMemoryVersion`, `SsaDefUse`, `SsaDominance`, `SsaConstProp` |
| `mlil_ssa_builder` | Incremental SSA construction utilities |
| `ssa_reconstruction` | Braun online SSA construction algorithm |
| `phi_placement` | Dominance frontier computation and phi-node placement |
| `mlil_analysis` | General data-flow queries on `MlilFunction` |
| `mlil_alias_analysis` | May-alias / must-alias for memory SSA |
| `mlil_call_analysis` | Call site resolution and callee summary propagation |
| `mlil_optimizer` | SSA-level optimizations (copy propagation, DCE) |
| `mlil_dead_store_eliminator` | Dead store elimination over memory SSA |
| `mlil_verification` | SSA structural invariant checks |
| `calling_convention_db` | Calling convention database (cross-tier) |
| `type_recovery_mlil` | Type-constraint solving at MLIL level |

### Key types

#### `SsaVar`
```rust
pub struct SsaVar { pub name: String, pub version: u32 }
impl SsaVar {
    pub fn new(name, version) -> Self;
    pub fn initial(name) -> Self;      // version 0
    pub fn next_version(&self) -> Self; // +1
}
// Display: "rax#3", "local_0#1"
```

#### `MlilExpr` (selected variants)
```rust
pub enum MlilExpr {
    Const { value: u64, size: Size },
    Var   { var: SsaVar, size: Size },
    Load  { addr: Box<Self>, size: Size },
    Add(Box<Self>, Box<Self>, Size), Sub, Mul, DivU, DivS,
    And, Or, Xor, Shl, Shr, Sar, Neg, Not,
    ZeroExtend { expr, from, to: Size },
    SignExtend  { expr, from, to: Size },
    CmpEq, CmpNe, CmpSlt, CmpUlt, CmpSle, CmpUle,
    FAdd, FSub, FMul, FDiv, FNeg, IntToFloat, FloatToInt,
    Select { cond, true_val, false_val, size },
    Undefined(Size), StackPointer(Size), Flag { name },
    Call { dest: Box<Self>, args: Vec<Self>, return_size: Size },
}
impl MlilExpr {
    pub const fn result_size(&self) -> Size;
    pub fn uses_var(&self, var: &SsaVar) -> bool;
}
```
Notably cleaner than `LlilExpr`: no dual forms, one canonical variant per operation.

#### `MlilInstruction`
```rust
pub enum MlilInstruction {
    Nop,
    Assign  { dest: SsaVar, size: Size, src: MlilExpr },
    Store   { addr: MlilExpr, size: Size, src: MlilExpr },
    Jump    { dest: MlilExpr },
    CondJump { cond: MlilExpr, true_dest: Address, false_dest: Address },
    Call    { dest: MlilExpr, args: Vec<MlilExpr>, ret_vars: Vec<SsaVar> },
    TailCall { dest: MlilExpr, args: Vec<MlilExpr> },
    Ret     { values: Vec<MlilExpr> },
    Phi     { dest: SsaVar, sources: Vec<SsaVar> },  // SSA φ-node
    Trap    { code: u64 },
    SysCall { args: Vec<MlilExpr>, ret_vars: Vec<SsaVar> },
    Undefined,
}
impl MlilInstruction {
    pub const fn is_terminator(&self) -> bool;
    pub const fn is_phi(&self) -> bool;
    pub fn defined_var(&self) -> Option<&SsaVar>;
    pub fn uses_var(&self, v: &SsaVar) -> bool;
}
```

#### `MlilSsa` (from `mlil_ssa.rs`)
Wraps an `MlilFunction` and maintains:
- `def_use: SsaDefUse` — maps each `SsaVar` to the set of instructions that use it
- `use_def: HashMap<SsaVar, usize>` — instruction that defines each `SsaVar`
- `phi_nodes: Vec<SsaPhiNode>` — explicit phi records
- `dominance: SsaDominance` — dominator tree + dominance frontier
- `memory_versions: Vec<SsaMemoryVersion>` — memory SSA versioning

`SsaConstProp` implements sparse conditional constant propagation (SCCP) over `MlilSsa`.

### Implementation status: **Partial**

| Component | Status | Notes |
|---|---|---|
| `MlilExpr` / `MlilInstruction` types | Complete | Clean, no dual forms |
| `SsaVar`, `SsaPhiNode` | Complete | |
| `phi_placement` | Partial | Dominance frontier done; phi pruning incomplete |
| `ssa_reconstruction` | Partial | Braun algorithm; degenerate loops have known issues |
| `mlil_optimizer` | Partial | Copy propagation done; global value numbering absent |
| `mlil_dead_store_eliminator` | Partial | Single-function scope only |
| `mlil_alias_analysis` | Partial | May-alias only; field-sensitivity absent |
| `mlil_call_analysis` | Partial | Direct calls resolved; vtable / indirect stubs incomplete |
| `type_recovery_mlil` | Partial | Constraint system skeleton; solver incomplete |
| `mlil_verification` | Complete | 7 `todo!` hits in `lib.rs` for edge cases |

---

## 5. `rustre-il-hlil` — High-Level IL

### Purpose
HLIL is the structured, C-like representation of decompiled code elevated from MLIL SSA. It introduces loops, conditionals, switch statements, typed variables, and nested expressions. This is the tier consumed by `rustre-decompiler`.

### Cargo.toml dependencies
| Dependency | Role |
|---|---|
| `rustre-il` | `IlTier` |
| `rustre-core` | `Address` |
| `rustre-il-mlil` | `MlilExpr`, `MlilFunction`, `MlilInstruction`, `SsaVar`, `Size` |
| `petgraph` | Control-flow graph for structured recovery |
| `serde`, `serde_json` | Serialization |
| `anyhow`, `thiserror` | Errors |

### Module structure

| Module | Role |
|---|---|
| `lib.rs` | `HlilType`, `HlilVar`, `HlilExpr`, `HlilInstruction`, `HlilFunction`, `HlilStatement` |
| `hlil_types` | Additional type-system utilities |
| `hlil_analysis` | HLIL data-flow and reaching-definitions queries |
| `hlil_control_flow_recovery` | Structured control flow (if/while/for/switch) recovery from MLIL CFG |
| `hlil_decompiler` | MLIL → HLIL lowering driver |
| `hlil_expression_normalizer` | Simplification and canonicalization of HLIL expressions |
| `hlil_optimization` | HLIL-level optimization passes |
| `hlil_variable_recovery` | Out-of-SSA variable naming and coalescing |

### Key types

#### `HlilType`
```rust
pub enum HlilType {
    Unknown, Void, Bool,
    Int   { signed: bool, bits: u32 },
    Float { bits: u32 },
    Pointer { pointee: Box<Self>, bits: u32 },
    Array   { elem: Box<Self>, count: Option<u64> },
    Struct  { name: String },
    Enum    { name: String },
    Function { ret: Box<Self>, params: Vec<Self> },
}
impl HlilType {
    // Convenience ctors: i8(), i16(), i32(), i64(), u8(), u16(), u32(), u64()
    pub fn ptr(pointee: Self, bits: u32) -> Self;
    pub fn byte_size(&self) -> Option<u32>;
    pub fn is_pointer(&self) -> bool;
    pub fn is_integer(&self) -> bool;
}
// Display: "int32_t", "uint8_t *", "float", "struct Foo", etc.
```
Notably, types imported from MLIL `Size` tokens are converted through `from_mlil_size(s: Size) -> HlilType`, always producing unsigned integer types (caller must apply signedness).

#### `HlilVar`
```rust
pub struct HlilVar {
    pub name: String,
    pub ty: HlilType,
    pub is_param: bool,
    pub stack_offset: Option<i64>,
    pub version: u32,   // SSA version (0 = non-SSA)
    pub is_ssa: bool,
}
```

#### `HlilExpr` (selected variants)
```rust
pub enum HlilExpr {
    Const { value: i64, ty: HlilType },
    Float { value: f64, ty: HlilType },
    Var { var: HlilVar },
    Deref { addr: Box<Self>, ty: HlilType },
    AddressOf { var: HlilVar },
    FieldAccess { base: Box<Self>, field: String, ty: HlilType },
    Index { base, idx: Box<Self>, ty: HlilType },
    Add/Sub/Mul/Div/Mod(Box<Self>, Box<Self>, HlilType),
    And/Or/Xor/Not/Shl/Shr(Box<Self>, Box<Self>, HlilType),
    CmpEq/CmpNe/CmpLt/CmpGt/CmpLe/CmpGe(Box<Self>, Box<Self>),
    LogicalAnd/LogicalOr(Box<Self>, Box<Self>),
    Cast { expr, to: HlilType },
    Call { func, args, ret_ty },
    Ternary { cond, then, else_, ty },
    SizeOf { ty },
    // optimizer alternate forms: BitOr, BitAnd, BitXor, BoolAnd, BoolOr,
    //   BoolNot, DivU, DivS, ModU, ModS, Sar, ArrayIndex, ...
}
```

#### `HlilInstruction` (linear flat form, for optimizer passes)
```rust
pub enum HlilInstruction {
    Assign { dest: HlilVar, value: HlilExpr },
    Return(Option<HlilExpr>),
    If { condition, then_block, else_block: Vec<Self> },
    While { condition, body: Vec<Self> },
    Call { target: Box<HlilExpr>, args: Vec<HlilExpr> },
}
```
Separate from `HlilStatement`, which is the full recursive structured form used by the decompiler.

### Implementation status: **Partial**

| Component | Status | Notes |
|---|---|---|
| `HlilType`, `HlilVar`, `HlilExpr` | Complete | No stubs; `Display` impl present |
| `HlilInstruction` | Complete | Flat linear form |
| `hlil_control_flow_recovery` | Partial | If/while recovered; switch detection not wired to MLIL |
| `hlil_decompiler` | Partial | Basic MLIL→HLIL lowering; no out-of-SSA coalescing yet |
| `hlil_variable_recovery` | Partial | Name generation done; liveness-based coalescing incomplete |
| `hlil_expression_normalizer` | Partial | Identity/constant fold done; strength reduction absent |
| `hlil_optimization` | Partial | Skeleton; dead-code elimination not yet connected to CFG |
| `hlil_analysis` | Partial | Reaching definitions; constant-range analysis absent |

Zero `todo!` / `unimplemented!` calls in HLIL source — instead, unfinished algorithms return conservative/incomplete results silently. Watch for under-construction paths returning `Default::default()` or empty collections.

---

## 6. `rustre-il-lift` — Architecture Lifting Coordinator

### Purpose
The entry point from raw disassembly into the IL pipeline. Provides:
- The `ArchLifter` trait for per-architecture lifting implementations.
- A second, lower-level IR (`IrExpr` / `Effect`) for the lifters to emit.
- `LiftedInstr`, `LiftResult`, `LiftStats`, `LiftCache`, `LiftContext` for lifecycle management.
- A `GenericLlilLifter` for common x86/x64 mnemonics.
- `ErrorRecoveryLifter` wrapper that stubs failures as `Intrinsic` effects.
- A registry of 20+ per-architecture lifters.
- Cross-cutting x86-specific infrastructure: context, flags, operand parsing, SIMD, ABI recovery, optimizer, pattern matcher, deobfuscator.

### Cargo.toml dependencies
| Dependency | Role |
|---|---|
| `rustre-il` | `IlTier` |
| `rustre-core` | `arch::Instruction`, `arch::Operand` |
| `parking_lot` | `RwLock`/`Mutex` for `LiftCache` and `LiftContext` |
| `serde` | `LiftLevel`, `LiftedInstr`, `LiftStats` serialization |
| `thiserror` | `LiftError` |
| `iced-x86 = "1.21"` | x86 disassembly/decode (external) |

No dependency on `rustre-il-llil` or higher tiers; it feeds into them.

### IR types in `lib.rs`

#### `IrExpr`
Simpler than `LlilExpr`: no `Size` annotation, no separate struct/tuple forms, no floating-point. Aimed at fast lifter emission.
```rust
pub enum IrExpr {
    Const(u64), Reg(String),
    Add/Sub/Mul/Or/And/Xor/Shl/Shr(Box<Self>, Box<Self>),
    Not(Box<Self>),
    Deref(Box<Self>, u8),        // memory[addr]:size_bytes
    CmpEqZero/Parity(Box<Self>), // flag helpers
    CmpEq/CmpLt/CmpGt/Eq/Ne(Box<Self>, Box<Self>),
    IfThenElse(Box<Self>, Box<Self>, Box<Self>),
    Undef,
}
impl IrExpr {
    pub fn node_count(&self) -> usize;      // capped at depth 1024
    pub fn registers_used(&self) -> Vec<String>;
}
```

#### `Effect`
```rust
pub enum Effect {
    RegWrite { reg: String, value: IrExpr },
    MemWrite { addr: IrExpr, value: IrExpr, size: u8 },
    MemRead  { addr: IrExpr, dest: String, size: u8 },
    Call     { target: IrExpr },
    Branch   { target: IrExpr, condition: Option<IrExpr> },
    Return   { value: Option<IrExpr> },
    Syscall  { nr: IrExpr },
    Intrinsic { name: String, args: Vec<IrExpr> },
    Trap     { vector: u8 },
    ConditionalTrap { condition: IrExpr, vector: u8 },
    NoReturn,
}
```

#### `LiftedInstr`
```rust
pub struct LiftedInstr {
    pub address: u64,
    pub original_mnemonic: String,
    pub ir_text: String,
    pub il_level: LiftLevel,
    pub effects: Vec<Effect>,
}
```

#### `ArchLifter` trait
```rust
pub trait ArchLifter: Send + Sync + fmt::Debug {
    fn arch_name(&self) -> &str;
    fn lift_level(&self) -> LiftLevel;
    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError>;
    fn lift_block(&self, instrs: &[Instruction]) -> Vec<Result<LiftedInstr, LiftError>>;
    fn description(&self) -> &'static str { "generic lifter" }
    fn supports_mnemonic(&self, mnemonic: &str) -> bool { true }
}
```

#### `LiftContext`
Thread-safe configuration object shared across a lifting session. Builder pattern:
```rust
LiftContext::new("x86_64")
    .with_level(LiftLevel::Llil)
    .without_cache()
    .strict()
    .with_batch_limit(5000)
```
Contains an `Arc<LiftCache>` (RwLock-based LRU, default 4096 entries) and accumulates `LiftStats`.

### Architecture lifter coverage

| Lifter struct | Architecture | Status |
|---|---|---|
| `X86LifterV2` / `X86CompleteLifter` | x86 / x86-64 | Partial-high (277 todo!/panic hits in x86 modules) |
| `Arm32Lifter` | ARM32 (A32/T32) | Partial (15 todo!) |
| `AArch64AdvancedLifter` / `AArch64NeonLifter` | AArch64 + NEON | Partial (2 todo!) |
| `RiscvLifter` / `RiscV64Lifter` / `RiscvExtLifter` | RISC-V 32/64 + ext | Partial (21 todo!) |
| `MipsLifter` / `Mips32Lifter` | MIPS | Partial (7 todo!) |
| `PpcLifter` | PowerPC | Partial (16 todo!) |
| `M68kLifter` | Motorola 68000 | Partial (25 todo!) |
| `SparcLifter` | SPARC | Partial (20 todo!) |
| `AvrLifter` | AVR | Partial (6 todo!) |
| `BpfLifter` | eBPF | Partial (minimal todo!) |
| `Z80Lifter` | Z80 | Partial (38 todo!) |
| `CilLifter` | .NET CIL | Partial (40 todo!) |
| `DexLifter` | Android DEX | Partial (36 todo!) |
| `WasmLifter` | WebAssembly | Partial (33 todo!) |

x86/x86-64 is the primary target; the rest are scaffolded but substantially incomplete.

### x86 lifting subsystem (specialized)

Several x86-specific modules are published as part of `rustre-il-lift`:

| Module / export | Role |
|---|---|
| `X86LiftCtx` (`x86_context`) | Per-instruction lift state: 16/32/64-bit mode, segment overrides |
| `ConditionCode` (`x86_flags`) | Typed condition-code enum for all `Jcc` variants |
| `x86_lift_instruction` (`x86_handlers`) | Dispatch table: `lift_instruction(ctx, instr) -> Vec<Effect>` |
| `X86SimdLifter` (`x86_simd_lift`) | SSE/AVX/AVX-512 lifting (EVEX flags, rounding modes) |
| `X86CompleteLifter` (`x86_complete_lift`) | MOV/MOVZX/MOVSX/LEA/XCHG/CMPXCHG/PUSH/POP/XADD |
| `fold_expr` / `eval_expr` / `exec_effects` (`x86_eval`) | Constant-folding evaluator over `IrExpr` / `Effect` |
| `CallingConventionRegistry` (`x86_calling_conv`) | `Cdecl`, `Stdcall`, `Fastcall`, `MsX64`, `SysVAmd64` |
| `deobf_function` / `detect_xor_decrypt_loops` (`x86_deobf`) | IL-level MBA / opaque predicate removal |
| `recover_abi` / `score_conventions` (`x86_abi_recovery`) | Evidence-based ABI recovery |
| `InsnDb` (`x86_insn_db`) | Instruction metadata (category, latency tier, encoding) |
| `TypeEnv` / `recover_types` (`x86_type_recovery`) | Type recovery from usage patterns |

### Implementation status: **Partial (High for x86)**

The x86 subsystem is the most developed with ABI recovery, SIMD lifting, deobfuscation, and an evaluator all present. Other architectures are 30–70% complete, with many opcode handlers stubbed. Total `todo!`/`unimplemented!` count in this crate: **277 occurrences across 21 files**.

---

## 7. `rustre-il-passes` — Analysis and Optimization Passes

### Purpose
A standalone pass framework operating on `LlilFunction`. Passes implement the `AnalysisPass` trait and are orchestrated by `PassManager`. Results are threaded through `PassContext`.

### Cargo.toml dependencies
| Dependency | Role |
|---|---|
| `rustre-il` | `IlTier` |
| `rustre-core` | `Address` |
| `rustre-il-llil` | `LlilFunction`, `LlilInstruction`, `LlilExpr`, `LlilCfg`, `LlilAnnotatedInstr` |
| `serde` | Pass metadata serialization |

No dependency on MLIL or HLIL: passes are pure LLIL consumers.

### Module structure

| Module | Role |
|---|---|
| `lib.rs` | `PassStats`, `PassContext`, `AnalysisPass` trait, `ExprVisitor` trait, `walk_expr_mut` |
| `constant_propagation` | Constant folding + propagation pass |
| `interprocedural_passes` | Summary-based interprocedural analysis |
| `loop_analysis` | Natural loop detection and loop variable analysis |
| `memory_access_patterns` | Memory access pattern classification |
| `optimization_pipeline` | `PassManager`, `OptimizationPipeline` (ordered pass execution) |
| `pass_dependency_graph` | Pass dependency DAG ensuring ordering constraints |
| `pass_metrics` | Timing and efficiency metrics per pass |
| `switch_detection` | Jump-table / switch-statement detection |
| `type_recovery_pass` | Type recovery pass operating on LLIL |

### Key types

#### `AnalysisPass` trait
```rust
pub trait AnalysisPass: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn run(&self, func: &mut LlilFunction, ctx: &mut PassContext);
    fn is_idempotent(&self) -> bool { true }
}
```

#### `ExprVisitor` + `walk_expr_mut`
```rust
pub trait ExprVisitor {
    fn visit_expr(&mut self, expr: &LlilExpr) -> Option<LlilExpr>;
}

pub fn walk_expr_mut(expr: LlilExpr, visitor: &mut dyn ExprVisitor) -> LlilExpr;
```
Bottom-up expression tree transformer with depth cap at 512 to prevent stack overflow on adversarially deep trees from binary input.

#### `PassContext`
```rust
pub struct PassContext {
    pub changed: bool,
    pub stats: PassStats,
    pub warnings: Vec<String>,
}
// PassStats: instrs_visited, instrs_modified, instrs_removed,
//            const_folded, exprs_simplified, dead_removed
```

### Implementation status: **Partial**

| Pass | Status | Notes |
|---|---|---|
| `ExprVisitor` / `walk_expr_mut` | Complete | Depth-bounded, full coverage of `LlilExpr` variants including dual forms |
| `constant_propagation` | Partial | 2 `todo!` hits; conditional branch folding incomplete |
| `loop_analysis` | Partial | Dominator-based loop detection; induction variable analysis absent |
| `switch_detection` | Partial | Jump-table pattern matching; multi-level switches unhandled |
| `memory_access_patterns` | Partial | Reads/writes classified; stride analysis incomplete |
| `type_recovery_pass` | Partial | Width inference; struct field detection absent |
| `interprocedural_passes` | Stub | 1 `todo!` — summary propagation skeleton only |
| `optimization_pipeline` | Partial | Ordered scheduling; convergence loop present but untested |
| `pass_dependency_graph` | Partial | DAG build done; cycle detection untested |
| `pass_metrics` | Complete | Timing and counters |

Total `todo!`/`unimplemented!` in passes: **17 occurrences across 3 files**.

---

## 8. Cross-Crate Integration Points

| From | To | Mechanism |
|---|---|---|
| `rustre-arch-*` | `rustre-il-lift` | Produces `rustre-core::Instruction` consumed by `ArchLifter::lift()` |
| `rustre-il-lift` | `rustre-il-llil` | `LlilBuilder` consumes `Effect` lists from `LiftedInstr` |
| `rustre-il-llil` | `rustre-il-mlil` | `llil_to_mlil_bridge::elevate()` takes `&LlilFunction` |
| `rustre-il-mlil` | `rustre-il-hlil` | `hlil_decompiler` takes `&MlilFunction` |
| `rustre-il-hlil` | `rustre-decompiler` | `HlilFunction` consumed by `rustre-decompiler-c` |
| `rustre-il-passes` | `rustre-il-llil` | Passes take `&mut LlilFunction` in-place |
| `rustre-il-lift` | `rustre-il-passes` | Deobfuscation passes in `x86_deobf` operate on `Effect` lists, parallel to LLIL |
| `rustre-analysis-cfg` | `rustre-il-llil` | `LlilCfg` (petgraph) used for CFG analysis |
| `rustre-mcp-tools` | `rustre-il-lift` | MCP `decompile` tool invokes `LiftContext` |

---

## 9. Known Gaps and Priority Work Items

### P1 — Structural
1. **Dual-form `LlilExpr`/`LlilInstruction` variants** — `AddT`/`Add`, `Jump`/`JumpDest`, `Call`/`CallDest`, `CondJump`/`ConditionalJump` are redundant. Every new pass must handle both. Unify to canonical struct forms and migrate builder to emit those.

2. **`llil_to_mlil_bridge` completeness** — Flag-lifting for x86 (`OF`, `SF`, `AF`, `PF`) is partially stubbed. Until this is complete, MLIL SSA will have unresolved `Flag("carry")` etc. references leaking into expressions.

3. **Out-of-SSA in HLIL** — `hlil_variable_recovery` generates names but does not yet do liveness-based coalescing. Variables unnecessarily remain in SSA form in the decompiler output.

4. **Switch recovery** — `switch_detection` in passes and `hlil_control_flow_recovery` are both partial; they don't interoperate yet. Jump tables are detected at LLIL but not propagated as structured `switch` nodes to HLIL.

### P2 — Coverage
5. **Architecture completeness** — 13 of 15 arch lifters have substantial `todo!` coverage (277 total hits). RISC-V and ARM32 are most impactful for embedded RE. Priority order by impact: ARM32/THUMB, RISC-V, MIPS, PowerPC.

6. **MLIL alias analysis** — Only may-alias is implemented; field-sensitivity is absent, limiting dead-store elimination and the type-recovery constraint solver.

7. **Interprocedural passes** — The `interprocedural_passes.rs` module is a skeleton. Without cross-function summaries, constant propagation terminates at call boundaries.

### P3 — Quality
8. **`IrExpr` vs `LlilExpr` impedance** — The lift tier emits `IrExpr`/`Effect` which the bridge must translate to `LlilExpr`/`LlilInstruction`. Some information is lost (e.g. float widths, signed/unsigned division distinction). Consider merging the two expression types or making `IrExpr` a subset of `LlilExpr`.

9. **MCP tool coverage for IL** — The MCP server currently exposes only `LiftLevel::Raw` and `LiftLevel::Llil` results. MLIL and HLIL are not yet surfaced as MCP tools; decompiler integration is pending HLIL stability.

---

## 10. Implementation Status Summary

| Crate | Tier | Status | `todo!/unimpl` count |
|---|---|---|---|
| `rustre-il` | Foundation | Complete | 0 |
| `rustre-il-llil` | LLIL | Partial | 12 |
| `rustre-il-mlil` | MLIL SSA | Partial | 7 |
| `rustre-il-hlil` | HLIL | Partial | 0 (silent stubs) |
| `rustre-il-lift` | Lift (arch) | Partial | 277 |
| `rustre-il-passes` | Passes | Partial | 17 |

The IL type system (`LlilExpr`, `MlilExpr`, `HlilExpr`, `HlilType`) is production-quality and complete. The scaffolding infrastructure (`LiftContext`, `LiftCache`, `PassContext`, `PassManager`, `AnalysisPass`) is solid. The primary gaps are in: (a) x86 opcode completeness in the lift layer, (b) SSA construction edge cases, (c) out-of-SSA / control-flow recovery for HLIL, and (d) interprocedural analysis.
