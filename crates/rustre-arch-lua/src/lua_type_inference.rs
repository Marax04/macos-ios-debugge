//! Lua type inference engine.
//!
//! Infers types of Lua registers from usage patterns, tracks type propagation
//! through assignments, detects table.field access patterns, infers function
//! signatures, and detects number/string/table/function/boolean types.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// LuaType
// ─────────────────────────────────────────────────────────────────────────────

/// The inferred Lua type of a register or expression.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LuaType {
    /// Unknown / not yet inferred.
    Unknown,
    /// The singleton nil value.
    Nil,
    /// Boolean (`true` or `false`).
    Boolean,
    /// Integer number (Lua 5.3+).
    Integer,
    /// Floating-point number.
    Float,
    /// Either integer or float (Lua 5.1/5.2 "number").
    Number,
    /// String value.
    String,
    /// Table value, optionally with known field types.
    Table(TableShape),
    /// Function value, optionally with a known signature.
    Function(Box<FunctionSig>),
    /// Userdata value.
    Userdata,
    /// Thread (coroutine).
    Thread,
    /// Union of two or more types (phi-node merge result).
    Union(Vec<Self>),
}

impl LuaType {
    /// Returns `true` if this type is definitely numeric.
    #[must_use] 
    pub const fn is_numeric(&self) -> bool {
        matches!(self, Self::Integer | Self::Float | Self::Number)
    }

    /// Returns `true` if this type might be nil.
    #[must_use] 
    pub fn may_be_nil(&self) -> bool {
        match self {
            Self::Nil => true,
            Self::Union(variants) => variants.iter().any(Self::may_be_nil),
            _ => false,
        }
    }

    /// Returns `true` if this type is definitely a table.
    #[must_use] 
    pub const fn is_table(&self) -> bool {
        matches!(self, Self::Table(_))
    }

    /// Returns `true` if this type is definitely a function.
    #[must_use] 
    pub const fn is_function(&self) -> bool {
        matches!(self, Self::Function(_))
    }

    /// Merge two types at a control-flow join point.
    #[must_use] 
    pub fn join(a: Self, b: Self) -> Self {
        if a == b {
            return a;
        }
        match (a, b) {
            (Self::Unknown, other) | (other, Self::Unknown) => other,
            (Self::Integer, Self::Float)
            | (Self::Float, Self::Integer) => Self::Number,
            (Self::Integer, Self::Number)
            | (Self::Number, Self::Integer) => Self::Number,
            (Self::Float, Self::Number)
            | (Self::Number, Self::Float) => Self::Number,
            (Self::Union(mut v), other) | (other, Self::Union(mut v)) => {
                if !v.contains(&other) {
                    v.push(other);
                }
                Self::Union(v)
            }
            (a, b) => Self::Union(vec![a, b]),
        }
    }

    /// Returns the "most general" type — used when widening for iteration.
    #[must_use] 
    pub fn widen(&self) -> Self {
        match self {
            Self::Integer | Self::Float => Self::Number,
            other => other.clone(),
        }
    }
}

impl fmt::Display for LuaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "?"),
            Self::Nil => write!(f, "nil"),
            Self::Boolean => write!(f, "boolean"),
            Self::Integer => write!(f, "integer"),
            Self::Float => write!(f, "float"),
            Self::Number => write!(f, "number"),
            Self::String => write!(f, "string"),
            Self::Table(_) => write!(f, "table"),
            Self::Function(_) => write!(f, "function"),
            Self::Userdata => write!(f, "userdata"),
            Self::Thread => write!(f, "thread"),
            Self::Union(v) => {
                let parts: Vec<String> = v.iter().map(std::string::ToString::to_string).collect();
                write!(f, "{}", parts.join("|"))
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TableShape / FieldType
// ─────────────────────────────────────────────────────────────────────────────

/// Known shape of a table: its field names and their inferred types.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct TableShape {
    /// Named string-keyed fields.
    pub fields: Vec<(String, LuaTypeRef)>,
    /// Whether the table is used as an array (integer keys).
    pub is_array: bool,
    /// Inferred element type for array usage.
    pub element_type: Option<LuaTypeRef>,
}

impl TableShape {
    /// Create an empty table shape.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or update a field type.
    pub fn set_field(&mut self, name: impl Into<String>, ty: LuaTypeRef) {
        let name = name.into();
        if let Some(slot) = self.fields.iter_mut().find(|(k, _)| k == &name) {
            slot.1 = ty;
        } else {
            self.fields.push((name, ty));
        }
    }

    /// Get the inferred type of a field by name.
    #[must_use] 
    pub fn get_field(&self, name: &str) -> Option<&LuaTypeRef> {
        self.fields.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }
}

/// Indirection to avoid recursive type blowup.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LuaTypeRef(pub Box<LuaType>);

impl LuaTypeRef {
    #[must_use] 
    pub fn new(ty: LuaType) -> Self {
        Self(Box::new(ty))
    }
    #[must_use] 
    pub fn get(&self) -> &LuaType {
        &self.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionSig
// ─────────────────────────────────────────────────────────────────────────────

/// Inferred function signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct FunctionSig {
    /// Types of the parameters (positional).
    pub params: Vec<LuaType>,
    /// Types of the return values (positional).
    pub returns: Vec<LuaType>,
    /// Whether the function is variadic (`...`).
    pub is_variadic: bool,
}

impl FunctionSig {
    /// Create a new empty signature.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a fixed-arity signature.
    #[must_use] 
    pub const fn fixed(params: Vec<LuaType>, returns: Vec<LuaType>) -> Self {
        Self {
            params,
            returns,
            is_variadic: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeConstraint
// ─────────────────────────────────────────────────────────────────────────────

/// A constraint relating two register slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeConstraint {
    /// Register `dst` must have exactly type `ty`.
    Is { reg: u32, ty: LuaType },
    /// Register `dst` must be a subtype of `ty`.
    SubtypeOf { reg: u32, ty: LuaType },
    /// Register `dst` has the same type as `src`.
    SameAs { dst: u32, src: u32 },
    /// Register `dst` is assigned from `src`, possibly widened.
    AssignFrom { dst: u32, src: u32 },
    /// Register `dst` is the result of an arithmetic operation on `a` and `b`.
    ArithResult { dst: u32, a: u32, b: u32 },
    /// Register `dst` is the result of a string concatenation.
    ConcatResult { dst: u32, a: u32, b: u32 },
    /// Register `dst` is the result of a table get field operation.
    TableGet { dst: u32, table: u32, field: String },
    /// Register `table` is a table and field `field` is set to `src`.
    TableSet { table: u32, field: String, src: u32 },
    /// Register `dst` is the result of calling `callee` with `argc` arguments.
    CallResult { dst: u32, callee: u32, argc: u32 },
    /// Register `dst` holds the length of `src`.
    LenOf { dst: u32, src: u32 },
    /// Register `dst` is the negation of `src`.
    NotOf { dst: u32, src: u32 },
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeEnv
// ─────────────────────────────────────────────────────────────────────────────

/// Type environment: maps register numbers to their inferred types.
#[derive(Debug, Clone, Default)]
pub struct TypeEnv {
    /// Mapping from register number to inferred type.
    types: HashMap<u32, LuaType>,
    /// Constraints accumulated for this environment.
    constraints: Vec<TypeConstraint>,
}

impl TypeEnv {
    /// Create a new empty type environment.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the type of a register.
    #[must_use] 
    pub fn get(&self, reg: u32) -> &LuaType {
        self.types.get(&reg).unwrap_or(&LuaType::Unknown)
    }

    /// Set the type of a register.
    pub fn set(&mut self, reg: u32, ty: LuaType) {
        self.types.insert(reg, ty);
    }

    /// Add a constraint.
    pub fn add_constraint(&mut self, c: TypeConstraint) {
        self.constraints.push(c);
    }

    /// Merge another environment into this one at a control-flow join.
    pub fn join_with(&mut self, other: &Self) {
        let all_regs: HashSet<u32> = self
            .types
            .keys()
            .chain(other.types.keys())
            .copied()
            .collect();
        for reg in all_regs {
            let a = self.get(reg).clone();
            let b = other.get(reg).clone();
            let merged = LuaType::join(a, b);
            self.types.insert(reg, merged);
        }
    }

    /// Number of registers with known types.
    #[must_use] 
    pub fn known_count(&self) -> usize {
        self.types
            .values()
            .filter(|t| **t != LuaType::Unknown)
            .count()
    }

    /// Iterate over all (register, type) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (u32, &LuaType)> {
        self.types.iter().map(|(&r, t)| (r, t))
    }

    /// Returns the number of constraints.
    #[must_use] 
    pub const fn constraint_count(&self) -> usize {
        self.constraints.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InferenceResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of running the type inferencer over a function.
#[derive(Debug, Default)]
pub struct InferenceResult {
    /// Final type environment after inference.
    pub env: TypeEnv,
    /// Inferred function signature.
    pub signature: FunctionSig,
    /// Table shapes discovered during inference.
    pub tables: HashMap<u32, TableShape>,
    /// Number of inference passes performed.
    pub passes: u32,
    /// Whether inference reached a fixed point.
    pub converged: bool,
    /// Registers whose types could not be determined.
    pub unresolved: Vec<u32>,
}

impl InferenceResult {
    /// Return the inferred type of register `reg`.
    #[must_use] 
    pub fn type_of(&self, reg: u32) -> &LuaType {
        self.env.get(reg)
    }

    /// Return `true` if all registers have a non-Unknown type.
    #[must_use] 
    pub const fn is_fully_typed(&self) -> bool {
        self.unresolved.is_empty()
    }

    /// Summary string for reporting.
    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "InferenceResult: passes={}, converged={}, known={}, unresolved={}",
            self.passes,
            self.converged,
            self.env.known_count(),
            self.unresolved.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction snapshot for inference (decoupled from arch crate)
// ─────────────────────────────────────────────────────────────────────────────

/// Lightweight instruction descriptor used by the type inferencer.
///
/// The inferencer does not depend on `rustre_arch` types directly; callers
/// translate their instruction representation into this form.
#[derive(Debug, Clone)]
pub struct TypeInferInstr {
    /// Mnemonic (lowercase).
    pub mnemonic: String,
    /// Destination register, if any.
    pub dst: Option<u32>,
    /// First source register, if any.
    pub src_a: Option<u32>,
    /// Second source register, if any.
    pub src_b: Option<u32>,
    /// Immediate integer operand, if any.
    pub imm_int: Option<i64>,
    /// Immediate float operand, if any.
    pub imm_float: Option<f64>,
    /// Immediate string operand, if any.
    pub imm_str: Option<String>,
    /// Whether a constant-index (`k`) flag is set.
    pub k_flag: bool,
}

impl TypeInferInstr {
    /// Create a simple move instruction.
    #[must_use] 
    pub fn mov(dst: u32, src: u32) -> Self {
        Self {
            mnemonic: "move".into(),
            dst: Some(dst),
            src_a: Some(src),
            src_b: None,
            imm_int: None,
            imm_float: None,
            imm_str: None,
            k_flag: false,
        }
    }

    /// Create a load-integer instruction.
    #[must_use] 
    pub fn loadi(dst: u32, val: i64) -> Self {
        Self {
            mnemonic: "loadi".into(),
            dst: Some(dst),
            src_a: None,
            src_b: None,
            imm_int: Some(val),
            imm_float: None,
            imm_str: None,
            k_flag: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeInferencer
// ─────────────────────────────────────────────────────────────────────────────

/// Main type inference engine for a single Lua function.
pub struct TypeInferencer {
    /// Maximum number of passes before giving up.
    max_passes: u32,
    /// Whether to propagate types through upvalue references.
    track_upvalues: bool,
}

impl Default for TypeInferencer {
    fn default() -> Self {
        Self {
            max_passes: 16,
            track_upvalues: false,
        }
    }
}

impl TypeInferencer {
    /// Create a new inferencer with default settings.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum number of passes.
    #[must_use] 
    pub const fn with_max_passes(mut self, n: u32) -> Self {
        self.max_passes = n;
        self
    }

    /// Enable upvalue tracking.
    #[must_use] 
    pub const fn with_upvalue_tracking(mut self) -> Self {
        self.track_upvalues = true;
        self
    }

    /// Run type inference over a sequence of instructions.
    ///
    /// Uses a simple worklist / fixed-point iteration.
    #[must_use] 
    pub fn infer(&self, instrs: &[TypeInferInstr]) -> InferenceResult {
        let mut result = InferenceResult::default();
        let mut changed = true;
        let mut pass = 0u32;

        while changed && pass < self.max_passes {
            changed = false;
            pass += 1;
            for instr in instrs {
                let updated = self.process_instr(instr, &mut result.env, &mut result.tables);
                if updated {
                    changed = true;
                }
            }
        }

        result.passes = pass;
        result.converged = !changed;

        // Collect unresolved registers.
        let all_regs: HashSet<u32> = instrs
            .iter()
            .flat_map(|i| [i.dst, i.src_a, i.src_b].into_iter().flatten())
            .collect();
        for reg in all_regs {
            if *result.env.get(reg) == LuaType::Unknown {
                result.unresolved.push(reg);
            }
        }
        result.unresolved.sort_unstable();

        // Infer signature from register types at function entry/exit.
        result.signature = self.infer_signature(instrs, &result.env);

        result
    }

    /// Process a single instruction and update the environment.
    ///
    /// Returns `true` if the environment changed.
    fn process_instr(
        &self,
        instr: &TypeInferInstr,
        env: &mut TypeEnv,
        tables: &mut HashMap<u32, TableShape>,
    ) -> bool {
        let dst = match instr.dst {
            Some(d) => d,
            None => return false,
        };
        let old = env.get(dst).clone();
        let new_ty = self.infer_instr_type(instr, env, tables);
        if new_ty == old {
            false
        } else {
            env.set(dst, new_ty);
            true
        }
    }

    /// Infer the type produced by an instruction.
    fn infer_instr_type(
        &self,
        instr: &TypeInferInstr,
        env: &TypeEnv,
        tables: &mut HashMap<u32, TableShape>,
    ) -> LuaType {
        match instr.mnemonic.as_str() {
            // Load immediate integer.
            "loadi" => LuaType::Integer,
            // Load immediate float.
            "loadf" => LuaType::Float,
            // Load boolean false.
            "loadfalse" | "loadbool" => LuaType::Boolean,
            // Load true.
            "loadtrue" => LuaType::Boolean,
            // Load nil.
            "loadnil" => LuaType::Nil,
            // Load from constant pool; type depends on whether we have imm_int/float/str.
            "loadk" | "loadkx" => {
                if instr.imm_int.is_some() {
                    LuaType::Integer
                } else if instr.imm_float.is_some() {
                    LuaType::Float
                } else if instr.imm_str.is_some() {
                    LuaType::String
                } else {
                    LuaType::Unknown
                }
            }
            // Move: same type as source.
            "move" => {
                instr.src_a.map_or(LuaType::Unknown, |src| env.get(src).clone())
            }
            // Arithmetic: integer × integer → integer, else number.
            "add" | "sub" | "mul" | "mod" | "idiv" | "addi" | "addk" | "subk" | "mulk"
            | "modk" | "idivk" => {
                let ta = instr.src_a.map_or(&LuaType::Unknown, |r| env.get(r));
                let tb = instr.src_b.map_or(&LuaType::Unknown, |r| env.get(r));
                infer_arith_result(ta, tb)
            }
            // Division always produces float.
            "div" | "divk" => LuaType::Float,
            // Power always produces float.
            "pow" | "powk" => LuaType::Float,
            // Unary minus: integer → integer, float → float, else number.
            "unm" => {
                instr.src_a.map_or(LuaType::Number, |src| match env.get(src) {
                        LuaType::Integer => LuaType::Integer,
                        LuaType::Float => LuaType::Float,
                        LuaType::Number => LuaType::Number,
                        _ => LuaType::Number,
                    })
            }
            // Bitwise ops: integer → integer.
            "band" | "bor" | "bxor" | "shl" | "shr" | "bandk" | "bork" | "bxork"
            | "shri" | "shli" | "bnot" => LuaType::Integer,
            // Length operator: integer.
            "len" => LuaType::Integer,
            // Logical not: boolean.
            "not" => LuaType::Boolean,
            // Concatenation: string.
            "concat" => LuaType::String,
            // New table.
            "newtable" => {
                let dst_id = instr.dst.unwrap_or(0);
                tables.entry(dst_id).or_default();
                LuaType::Table(TableShape::new())
            }
            // Get table field.
            "gettable" | "gettabup" | "getfield" | "geti" => LuaType::Unknown,
            // Self: table + method lookup.
            "self" => LuaType::Unknown,
            // Call result: unknown unless we track call targets.
            "call" | "tailcall" => LuaType::Unknown,
            // Get upvalue.
            "getupval" => LuaType::Unknown,
            // For loop index variable: number.
            "forprep" | "forloop" | "tforprep" | "tforcall" | "tforloop" => LuaType::Unknown,
            // Closure: function type.
            "closure" => LuaType::Function(Box::new(FunctionSig::new())),
            // Vararg: unknown tuple.
            "vararg" | "varargprep" => LuaType::Unknown,
            _ => LuaType::Unknown,
        }
    }

    /// Infer a function signature from the instruction sequence.
    fn infer_signature(
        &self,
        instrs: &[TypeInferInstr],
        env: &TypeEnv,
    ) -> FunctionSig {
        // Collect the highest parameter register referenced as a source before
        // being assigned — these are the function parameters.
        let mut assigned: HashSet<u32> = HashSet::new();
        let mut params: Vec<u32> = Vec::new();
        for instr in instrs {
            for &src in [instr.src_a, instr.src_b]
                .iter()
                .flatten()
            {
                if !assigned.contains(&src) && src < 255
                    && !params.contains(&src) {
                        params.push(src);
                    }
            }
            if let Some(d) = instr.dst {
                assigned.insert(d);
            }
        }
        params.sort_unstable();

        // Infer param types.
        let param_types: Vec<LuaType> = params.iter().map(|&r| env.get(r).clone()).collect();

        // Heuristic return types: look at src registers for RETURN instructions.
        let ret_types: Vec<LuaType> = instrs
            .iter()
            .filter(|i| i.mnemonic == "return" || i.mnemonic == "return1")
            .filter_map(|i| i.src_a)
            .map(|r| env.get(r).clone())
            .collect();

        // Detect vararg from VARARG or VARARGPREP.
        let is_variadic = instrs.iter().any(|i| i.mnemonic == "vararg" || i.mnemonic == "varargprep");

        FunctionSig {
            params: param_types,
            returns: ret_types,
            is_variadic,
        }
    }

    /// Infer types for a whole module represented as a flat instruction stream
    /// and return a map from function index to `InferenceResult`.
    #[must_use] 
    pub fn infer_module(
        &self,
        functions: &[Vec<TypeInferInstr>],
    ) -> Vec<InferenceResult> {
        functions.iter().map(|f| self.infer(f)).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Infer the result type of an arithmetic operation given operand types.
const fn infer_arith_result(a: &LuaType, b: &LuaType) -> LuaType {
    match (a, b) {
        (LuaType::Integer, LuaType::Integer) => LuaType::Integer,
        (LuaType::Float, _) | (_, LuaType::Float) => LuaType::Float,
        (LuaType::Number, _) | (_, LuaType::Number) => LuaType::Number,
        (LuaType::Integer, LuaType::Unknown)
        | (LuaType::Unknown, LuaType::Integer) => LuaType::Integer,
        _ => LuaType::Number,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TableAccessPattern
// ─────────────────────────────────────────────────────────────────────────────

/// A single table field access pattern found in the bytecode.
#[derive(Debug, Clone)]
pub struct TableAccessPattern {
    /// Register holding the table.
    pub table_reg: u32,
    /// Field name accessed (may be empty for integer-keyed access).
    pub field: String,
    /// Whether this is a write (true) or read (false).
    pub is_write: bool,
    /// Instruction index where the pattern was found.
    pub instr_idx: usize,
}

/// Scan a sequence of instructions for table field access patterns.
#[must_use] 
pub fn find_table_accesses(instrs: &[TypeInferInstr]) -> Vec<TableAccessPattern> {
    let mut patterns = Vec::new();
    for (idx, instr) in instrs.iter().enumerate() {
        match instr.mnemonic.as_str() {
            "gettable" | "gettabup" | "getfield" | "geti" => {
                let table_reg = instr.src_a.unwrap_or(0);
                let field = instr.imm_str.clone().unwrap_or_default();
                patterns.push(TableAccessPattern {
                    table_reg,
                    field,
                    is_write: false,
                    instr_idx: idx,
                });
            }
            "settable" | "settabup" | "setfield" | "seti" => {
                let table_reg = instr.dst.unwrap_or(0);
                let field = instr.imm_str.clone().unwrap_or_default();
                patterns.push(TableAccessPattern {
                    table_reg,
                    field,
                    is_write: true,
                    instr_idx: idx,
                });
            }
            _ => {}
        }
    }
    patterns
}

// ─────────────────────────────────────────────────────────────────────────────
// UpvalueTypeTracker
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks upvalue types across function boundaries.
pub struct UpvalueTypeTracker {
    /// Map from upvalue index to inferred type.
    upvalue_types: HashMap<u32, LuaType>,
}

impl UpvalueTypeTracker {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            upvalue_types: HashMap::new(),
        }
    }

    /// Record that upvalue `idx` has type `ty`.
    pub fn set(&mut self, idx: u32, ty: LuaType) {
        self.upvalue_types.insert(idx, ty);
    }

    /// Get the inferred type of upvalue `idx`.
    #[must_use] 
    pub fn get(&self, idx: u32) -> &LuaType {
        self.upvalue_types.get(&idx).unwrap_or(&LuaType::Unknown)
    }

    /// Merge another tracker into this one.
    pub fn merge(&mut self, other: &Self) {
        for (&idx, ty) in &other.upvalue_types {
            let current = self.get(idx).clone();
            let merged = LuaType::join(current, ty.clone());
            self.upvalue_types.insert(idx, merged);
        }
    }
}

impl Default for UpvalueTypeTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstraintSolver
// ─────────────────────────────────────────────────────────────────────────────

/// Solves type constraints to produce a refined type environment.
pub struct ConstraintSolver {
    max_iterations: usize,
}

impl Default for ConstraintSolver {
    fn default() -> Self {
        Self { max_iterations: 64 }
    }
}

impl ConstraintSolver {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub const fn with_max_iterations(mut self, n: usize) -> Self {
        self.max_iterations = n;
        self
    }

    /// Solve the constraints in `env` and return a refined environment.
    #[must_use] 
    pub fn solve(&self, env: &TypeEnv) -> TypeEnv {
        let mut result = env.clone();
        let mut queue: VecDeque<&TypeConstraint> =
            env.constraints.iter().collect();
        let mut iterations = 0;

        while let Some(constraint) = queue.pop_front() {
            if iterations >= self.max_iterations {
                break;
            }
            iterations += 1;
            self.apply_constraint(constraint, &mut result);
        }

        result
    }

    fn apply_constraint(&self, constraint: &TypeConstraint, env: &mut TypeEnv) {
        match constraint {
            TypeConstraint::Is { reg, ty } => {
                let current = env.get(*reg).clone();
                if current == LuaType::Unknown {
                    env.set(*reg, ty.clone());
                }
            }
            TypeConstraint::SubtypeOf { reg, ty } => {
                let current = env.get(*reg).clone();
                if current == LuaType::Unknown {
                    env.set(*reg, ty.clone());
                }
            }
            TypeConstraint::SameAs { dst, src } => {
                let src_ty = env.get(*src).clone();
                let dst_ty = env.get(*dst).clone();
                if dst_ty == LuaType::Unknown && src_ty != LuaType::Unknown {
                    env.set(*dst, src_ty);
                }
            }
            TypeConstraint::AssignFrom { dst, src } => {
                let src_ty = env.get(*src).clone();
                if src_ty != LuaType::Unknown {
                    env.set(*dst, src_ty);
                }
            }
            TypeConstraint::ArithResult { dst, a, b } => {
                let ta = env.get(*a).clone();
                let tb = env.get(*b).clone();
                let result_ty = infer_arith_result(&ta, &tb);
                if result_ty != LuaType::Unknown {
                    env.set(*dst, result_ty);
                }
            }
            TypeConstraint::ConcatResult { dst, .. } => {
                env.set(*dst, LuaType::String);
            }
            TypeConstraint::LenOf { dst, .. } => {
                env.set(*dst, LuaType::Integer);
            }
            TypeConstraint::NotOf { dst, .. } => {
                env.set(*dst, LuaType::Boolean);
            }
            TypeConstraint::TableGet { dst, table, .. } => {
                let table_ty = env.get(*table).clone();
                if !matches!(table_ty, LuaType::Table(_)) {
                    env.set(*table, LuaType::Table(TableShape::new()));
                }
                if *env.get(*dst) == LuaType::Unknown {
                    env.set(*dst, LuaType::Unknown);
                }
            }
            TypeConstraint::TableSet { table, .. } => {
                let table_ty = env.get(*table).clone();
                if !matches!(table_ty, LuaType::Table(_)) {
                    env.set(*table, LuaType::Table(TableShape::new()));
                }
            }
            TypeConstraint::CallResult { dst, .. } => {
                let current = env.get(*dst).clone();
                if current == LuaType::Unknown {
                    // Cannot determine without call graph; leave unknown.
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lua_type_join_same() {
        assert_eq!(LuaType::join(LuaType::Integer, LuaType::Integer), LuaType::Integer);
    }

    #[test]
    fn test_lua_type_join_int_float() {
        assert_eq!(LuaType::join(LuaType::Integer, LuaType::Float), LuaType::Number);
    }

    #[test]
    fn test_lua_type_join_unknown() {
        assert_eq!(LuaType::join(LuaType::Unknown, LuaType::String), LuaType::String);
    }

    #[test]
    fn test_infer_loadi() {
        let inferencer = TypeInferencer::new();
        let instrs = vec![TypeInferInstr::loadi(0, 42)];
        let result = inferencer.infer(&instrs);
        assert_eq!(*result.type_of(0), LuaType::Integer);
    }

    #[test]
    fn test_infer_move_propagates_type() {
        let inferencer = TypeInferencer::new();
        let instrs = vec![
            TypeInferInstr::loadi(0, 10),
            TypeInferInstr::mov(1, 0),
        ];
        let result = inferencer.infer(&instrs);
        assert_eq!(*result.type_of(1), LuaType::Integer);
    }

    #[test]
    fn test_infer_concat_is_string() {
        let inferencer = TypeInferencer::new();
        let instrs = vec![TypeInferInstr {
            mnemonic: "concat".into(),
            dst: Some(2),
            src_a: Some(0),
            src_b: Some(1),
            imm_int: None,
            imm_float: None,
            imm_str: None,
            k_flag: false,
        }];
        let result = inferencer.infer(&instrs);
        assert_eq!(*result.type_of(2), LuaType::String);
    }

    #[test]
    fn test_type_env_join() {
        let mut env1 = TypeEnv::new();
        let mut env2 = TypeEnv::new();
        env1.set(0, LuaType::Integer);
        env2.set(0, LuaType::Float);
        env1.join_with(&env2);
        assert_eq!(*env1.get(0), LuaType::Number);
    }

    #[test]
    fn test_constraint_solver_is() {
        let mut env = TypeEnv::new();
        env.add_constraint(TypeConstraint::Is {
            reg: 0,
            ty: LuaType::String,
        });
        let solver = ConstraintSolver::new();
        let result = solver.solve(&env);
        assert_eq!(*result.get(0), LuaType::String);
    }

    #[test]
    fn test_table_shape_set_get_field() {
        let mut shape = TableShape::new();
        shape.set_field("x", LuaTypeRef::new(LuaType::Integer));
        assert_eq!(
            shape.get_field("x").map(super::LuaTypeRef::get),
            Some(&LuaType::Integer)
        );
    }

    #[test]
    fn test_find_table_accesses() {
        let instrs = vec![
            TypeInferInstr {
                mnemonic: "gettable".into(),
                dst: Some(1),
                src_a: Some(0),
                src_b: None,
                imm_str: Some("x".into()),
                imm_int: None,
                imm_float: None,
                k_flag: false,
            },
            TypeInferInstr {
                mnemonic: "settable".into(),
                dst: Some(0),
                src_a: Some(1),
                src_b: None,
                imm_str: Some("y".into()),
                imm_int: None,
                imm_float: None,
                k_flag: false,
            },
        ];
        let accesses = find_table_accesses(&instrs);
        assert_eq!(accesses.len(), 2);
        assert!(!accesses[0].is_write);
        assert!(accesses[1].is_write);
    }
}
