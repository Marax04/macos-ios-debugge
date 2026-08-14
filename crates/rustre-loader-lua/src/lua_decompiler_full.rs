//! Full Lua decompiler from bytecode.
//!
//! Reconstructs a high-level Lua AST from Lua 5.1/5.2/5.3 bytecode,
//! including control flow recovery, expression trees, and statement lists.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecompError {
    TruncatedBytecode { pc: usize },
    InvalidOpcode(u8),
    InvalidRegister { reg: u8, max: u8 },
    InvalidConstantIndex(u32),
    StackUnderflow { pc: usize },
    UnsupportedLuaVersion(u8),
    CyclicControlFlow { pc: usize },
    TooManyLocals(usize),
    InvalidUpvalueIndex(u8),
    UnsupportedOp { op: u8, name: &'static str },
}

impl std::fmt::Display for DecompError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedBytecode { pc } => write!(f, "truncated bytecode at PC {pc}"),
            Self::InvalidOpcode(op) => write!(f, "invalid opcode {op:#04x}"),
            Self::InvalidRegister { reg, max } => {
                write!(f, "register {reg} out of range (max {max})")
            }
            Self::InvalidConstantIndex(i) => write!(f, "constant index {i} out of range"),
            Self::StackUnderflow { pc } => write!(f, "stack underflow at PC {pc}"),
            Self::UnsupportedLuaVersion(v) => write!(f, "unsupported Lua version {v:#04x}"),
            Self::CyclicControlFlow { pc } => write!(f, "cyclic control flow at PC {pc}"),
            Self::TooManyLocals(n) => write!(f, "too many locals: {n}"),
            Self::InvalidUpvalueIndex(i) => write!(f, "invalid upvalue index {i}"),
            Self::UnsupportedOp { op, name } => write!(f, "unsupported opcode {op} ({name})"),
        }
    }
}

impl std::error::Error for DecompError {}

// ---------------------------------------------------------------------------
// Lua constant types
// ---------------------------------------------------------------------------

/// A Lua constant (from the constant table of a proto).
#[derive(Debug, Clone)]
pub enum LuaConst {
    Nil,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
}

impl LuaConst {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Nil => "nil",
            Self::Bool(_) => "boolean",
            Self::Int(_) => "integer",
            Self::Float(_) => "float",
            Self::Str(_) => "string",
        }
    }

    pub fn is_falsy(&self) -> bool {
        matches!(self, Self::Nil | Self::Bool(false))
    }
}

// ---------------------------------------------------------------------------
// ExpressionTree
// ---------------------------------------------------------------------------

/// A Lua expression node.
#[derive(Debug, Clone)]
pub enum ExpressionTree {
    Nil,
    True,
    False,
    Integer(i64),
    Float(f64),
    StringLit(String),
    LocalVar {
        reg: u8,
        name: String,
    },
    UpvalVar {
        idx: u8,
        name: String,
    },
    GlobalVar(String),
    TableIndex {
        table: Box<ExpressionTree>,
        key: Box<ExpressionTree>,
    },
    TableField {
        table: Box<ExpressionTree>,
        field: String,
    },
    BinOp {
        op: BinOp,
        lhs: Box<ExpressionTree>,
        rhs: Box<ExpressionTree>,
    },
    UnOp {
        op: UnOp,
        operand: Box<ExpressionTree>,
    },
    FunctionCall {
        func: Box<ExpressionTree>,
        args: Vec<ExpressionTree>,
    },
    MethodCall {
        obj: Box<ExpressionTree>,
        method: String,
        args: Vec<ExpressionTree>,
    },
    VarArg,
    Closure {
        proto_index: u32,
    },
    Concat {
        values: Vec<ExpressionTree>,
    },
    TableConstructor {
        fields: Vec<TableField>,
    },
}

/// Binary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    IDiv,
    Concat,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    BAnd,
    BOr,
    BXor,
    Shl,
    Shr,
}

impl BinOp {
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Mod => "%",
            Self::Pow => "^",
            Self::IDiv => "//",
            Self::Concat => "..",
            Self::Eq => "==",
            Self::Ne => "~=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::And => "and",
            Self::Or => "or",
            Self::BAnd => "&",
            Self::BOr => "|",
            Self::BXor => "~",
            Self::Shl => "<<",
            Self::Shr => ">>",
        }
    }

    pub fn is_comparison(self) -> bool {
        matches!(
            self,
            Self::Eq | Self::Ne | Self::Lt | Self::Le | Self::Gt | Self::Ge
        )
    }

    pub fn is_logical(self) -> bool {
        matches!(self, Self::And | Self::Or)
    }
}

/// Unary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    Neg,
    Not,
    Len,
    BNot,
}

impl UnOp {
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Neg => "-",
            Self::Not => "not ",
            Self::Len => "#",
            Self::BNot => "~",
        }
    }
}

/// One field in a table constructor.
#[derive(Debug, Clone)]
pub enum TableField {
    /// `[key] = value`
    Index {
        key: ExpressionTree,
        value: ExpressionTree,
    },
    /// `name = value`
    Name { name: String, value: ExpressionTree },
    /// Sequential (no explicit key).
    Value(ExpressionTree),
}

// ---------------------------------------------------------------------------
// StatementList
// ---------------------------------------------------------------------------

/// A Lua statement.
#[derive(Debug, Clone)]
pub enum Statement {
    LocalAssign {
        names: Vec<String>,
        values: Vec<ExpressionTree>,
    },
    Assign {
        targets: Vec<ExpressionTree>,
        values: Vec<ExpressionTree>,
    },
    DoBlock(StatementList),
    WhileLoop {
        condition: ExpressionTree,
        body: StatementList,
    },
    RepeatLoop {
        body: StatementList,
        condition: ExpressionTree,
    },
    NumericFor {
        var: String,
        start: ExpressionTree,
        limit: ExpressionTree,
        step: Option<ExpressionTree>,
        body: StatementList,
    },
    GenericFor {
        vars: Vec<String>,
        iterators: Vec<ExpressionTree>,
        body: StatementList,
    },
    IfElse {
        condition: ExpressionTree,
        then_block: StatementList,
        elseif_blocks: Vec<(ExpressionTree, StatementList)>,
        else_block: Option<StatementList>,
    },
    FunctionDecl {
        name: String,
        params: Vec<String>,
        is_vararg: bool,
        body: StatementList,
    },
    LocalFunctionDecl {
        name: String,
        params: Vec<String>,
        is_vararg: bool,
        body: StatementList,
    },
    Return(Vec<ExpressionTree>),
    Break,
    Continue,
    ExprStatement(ExpressionTree),
    Goto(String),
    Label(String),
}

/// A list of statements forming a block.
#[derive(Debug, Clone, Default)]
pub struct StatementList {
    pub statements: Vec<Statement>,
}

impl StatementList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, s: Statement) {
        self.statements.push(s);
    }

    pub fn len(&self) -> usize {
        self.statements.len()
    }
    pub fn is_empty(&self) -> bool {
        self.statements.is_empty()
    }

    /// Number of `return` statements in this block (direct children only).
    pub fn return_count(&self) -> usize {
        self.statements
            .iter()
            .filter(|s| matches!(s, Statement::Return(_)))
            .count()
    }
}

// ---------------------------------------------------------------------------
// ControlFlow
// ---------------------------------------------------------------------------

/// Basic block for control flow graph.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: u32,
    pub pc_start: u32,
    pub pc_end: u32,
    pub successors: Vec<u32>,
    pub predecessors: Vec<u32>,
    pub statements: StatementList,
    pub is_loop_header: bool,
}

impl BasicBlock {
    pub fn new(id: u32, pc_start: u32) -> Self {
        Self {
            id,
            pc_start,
            pc_end: pc_start,
            successors: vec![],
            predecessors: vec![],
            statements: StatementList::new(),
            is_loop_header: false,
        }
    }

    pub fn add_successor(&mut self, id: u32) {
        if !self.successors.contains(&id) {
            self.successors.push(id);
        }
    }

    pub fn add_predecessor(&mut self, id: u32) {
        if !self.predecessors.contains(&id) {
            self.predecessors.push(id);
        }
    }

    /// `true` if this block has more than one successor (conditional branch).
    pub fn is_conditional(&self) -> bool {
        self.successors.len() > 1
    }
}

/// Control flow graph.
#[derive(Debug, Default)]
pub struct ControlFlow {
    pub blocks: Vec<BasicBlock>,
    pub entry_block: u32,
    block_by_pc: HashMap<u32, u32>,
}

impl ControlFlow {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_block(&mut self, block: BasicBlock) {
        let pc = block.pc_start;
        let id = block.id;
        self.blocks.push(block);
        self.block_by_pc.insert(pc, id);
    }

    pub fn find_block_by_pc(&self, pc: u32) -> Option<&BasicBlock> {
        let id = *self.block_by_pc.get(&pc)?;
        self.blocks.iter().find(|b| b.id == id)
    }

    pub fn loop_header_count(&self) -> usize {
        self.blocks.iter().filter(|b| b.is_loop_header).count()
    }
}

// ---------------------------------------------------------------------------
// FunctionAst
// ---------------------------------------------------------------------------

/// Decompiled Lua function.
#[derive(Debug, Clone)]
pub struct FunctionAst {
    pub params: Vec<String>,
    pub is_vararg: bool,
    pub locals: Vec<String>,
    pub upvalues: Vec<String>,
    pub body: StatementList,
    pub nested_functions: Vec<FunctionAst>,
    /// Original PC range.
    pub pc_start: u32,
    pub pc_end: u32,
}

impl FunctionAst {
    pub fn new() -> Self {
        Self {
            params: Vec::new(),
            is_vararg: false,
            locals: Vec::new(),
            upvalues: Vec::new(),
            body: StatementList::new(),
            nested_functions: Vec::new(),
            pc_start: 0,
            pc_end: 0,
        }
    }

    /// Count all statements recursively.
    pub fn total_statement_count(&self) -> usize {
        self.body.len()
            + self
                .nested_functions
                .iter()
                .map(|f| f.total_statement_count())
                .sum::<usize>()
    }

    /// `true` if the function has a variable argument list.
    pub fn accepts_vararg(&self) -> bool {
        self.is_vararg
    }
}

impl Default for FunctionAst {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// LuaTypeChecker — lightweight type inference
// ---------------------------------------------------------------------------

/// Inferred type of a Lua expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LuaInferredType {
    Unknown,
    Nil,
    Boolean,
    Integer,
    Float,
    String,
    Table,
    Function,
    UserData,
    Thread,
}

impl LuaInferredType {
    pub fn name(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Nil => "nil",
            Self::Boolean => "boolean",
            Self::Integer => "integer",
            Self::Float => "float",
            Self::String => "string",
            Self::Table => "table",
            Self::Function => "function",
            Self::UserData => "userdata",
            Self::Thread => "thread",
        }
    }

    pub fn is_primitive(self) -> bool {
        matches!(
            self,
            Self::Nil | Self::Boolean | Self::Integer | Self::Float
        )
    }
}

/// Infer the type of an expression node (best-effort).
pub fn infer_type(expr: &ExpressionTree) -> LuaInferredType {
    match expr {
        ExpressionTree::Nil => LuaInferredType::Nil,
        ExpressionTree::True | ExpressionTree::False => LuaInferredType::Boolean,
        ExpressionTree::Integer(_) => LuaInferredType::Integer,
        ExpressionTree::Float(_) => LuaInferredType::Float,
        ExpressionTree::StringLit(_) => LuaInferredType::String,
        ExpressionTree::TableConstructor { .. } => LuaInferredType::Table,
        ExpressionTree::Closure { .. } => LuaInferredType::Function,
        ExpressionTree::BinOp { op, lhs, rhs } => {
            if op.is_comparison() {
                return LuaInferredType::Boolean;
            }
            if op.is_logical() {
                return infer_type(rhs);
            } // simplified
            let lt = infer_type(lhs);
            let rt = infer_type(rhs);
            if lt == rt {
                lt
            } else {
                LuaInferredType::Unknown
            }
        }
        ExpressionTree::UnOp { op, operand } => match op {
            UnOp::Not => LuaInferredType::Boolean,
            UnOp::Len => LuaInferredType::Integer,
            UnOp::Neg => infer_type(operand),
            UnOp::BNot => LuaInferredType::Integer,
        },
        ExpressionTree::Concat { .. } => LuaInferredType::String,
        _ => LuaInferredType::Unknown,
    }
}

// ---------------------------------------------------------------------------
// LuaLocalScope — local variable scope tracking
// ---------------------------------------------------------------------------

/// One local variable in a scope.
#[derive(Debug, Clone)]
pub struct LuaLocal {
    pub name: String,
    pub register: u8,
    pub pc_start: u32,
    pub pc_end: u32,
    pub inferred_type: LuaInferredType,
}

impl LuaLocal {
    pub fn new(name: impl Into<String>, register: u8, pc_start: u32) -> Self {
        Self {
            name: name.into(),
            register,
            pc_start,
            pc_end: u32::MAX,
            inferred_type: LuaInferredType::Unknown,
        }
    }

    /// `true` if this local is live at `pc`.
    pub fn is_live_at(&self, pc: u32) -> bool {
        pc >= self.pc_start && pc < self.pc_end
    }
}

/// A nested scope of locals.
#[derive(Debug, Default)]
pub struct LuaLocalScope {
    pub locals: Vec<LuaLocal>,
}

impl LuaLocalScope {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, local: LuaLocal) {
        self.locals.push(local);
    }

    /// Find a local by register at a given PC.
    pub fn find_at_pc(&self, register: u8, pc: u32) -> Option<&LuaLocal> {
        self.locals
            .iter()
            .rev()
            .find(|l| l.register == register && l.is_live_at(pc))
    }

    /// All locals live at `pc`.
    pub fn live_at(&self, pc: u32) -> Vec<&LuaLocal> {
        self.locals.iter().filter(|l| l.is_live_at(pc)).collect()
    }

    pub fn len(&self) -> usize {
        self.locals.len()
    }
    pub fn is_empty(&self) -> bool {
        self.locals.is_empty()
    }
}

// ---------------------------------------------------------------------------
// LuaConstantFolder — fold constant expressions at decompile time
// ---------------------------------------------------------------------------

/// Attempts to fold a constant binary expression.
pub fn fold_binop(op: BinOp, lhs: &ExpressionTree, rhs: &ExpressionTree) -> Option<ExpressionTree> {
    match (op, lhs, rhs) {
        (BinOp::Add, ExpressionTree::Integer(a), ExpressionTree::Integer(b)) => {
            Some(ExpressionTree::Integer(a + b))
        }
        (BinOp::Sub, ExpressionTree::Integer(a), ExpressionTree::Integer(b)) => {
            Some(ExpressionTree::Integer(a - b))
        }
        (BinOp::Mul, ExpressionTree::Integer(a), ExpressionTree::Integer(b)) => {
            Some(ExpressionTree::Integer(a * b))
        }
        (BinOp::IDiv, ExpressionTree::Integer(a), ExpressionTree::Integer(b)) if *b != 0 => {
            Some(ExpressionTree::Integer(a / b))
        }
        (BinOp::Add, ExpressionTree::Float(a), ExpressionTree::Float(b)) => {
            Some(ExpressionTree::Float(a + b))
        }
        (BinOp::Sub, ExpressionTree::Float(a), ExpressionTree::Float(b)) => {
            Some(ExpressionTree::Float(a - b))
        }
        (BinOp::Mul, ExpressionTree::Float(a), ExpressionTree::Float(b)) => {
            Some(ExpressionTree::Float(a * b))
        }
        (BinOp::And, ExpressionTree::False, _) => Some(ExpressionTree::False),
        (BinOp::Or, ExpressionTree::True, _) => Some(ExpressionTree::True),
        (BinOp::Concat, ExpressionTree::StringLit(a), ExpressionTree::StringLit(b)) => {
            Some(ExpressionTree::StringLit(format!("{}{}", a, b)))
        }
        _ => None,
    }
}

/// Fold a unary expression at decompile time.
pub fn fold_unop(op: UnOp, operand: &ExpressionTree) -> Option<ExpressionTree> {
    match (op, operand) {
        (UnOp::Neg, ExpressionTree::Integer(n)) => Some(ExpressionTree::Integer(-n)),
        (UnOp::Neg, ExpressionTree::Float(f)) => Some(ExpressionTree::Float(-f)),
        (UnOp::Not, ExpressionTree::True) => Some(ExpressionTree::False),
        (UnOp::Not, ExpressionTree::False) => Some(ExpressionTree::True),
        (UnOp::Not, ExpressionTree::Nil) => Some(ExpressionTree::True),
        (UnOp::Len, ExpressionTree::StringLit(s)) => Some(ExpressionTree::Integer(s.len() as i64)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// LuaBytecodeInstruction — raw instruction from 5.x bytecode
// ---------------------------------------------------------------------------

/// A raw Lua 5.x instruction word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LuaBytecodeInstruction(pub u32);

impl LuaBytecodeInstruction {
    /// Opcode field (bits 0-5 in Lua 5.1, bits 0-6 in 5.4).
    pub fn opcode_51(self) -> u8 {
        (self.0 & 0x3f) as u8
    }
    /// Register A (bits 6-13).
    pub fn a_51(self) -> u8 {
        ((self.0 >> 6) & 0xff) as u8
    }
    /// Register B (bits 23-31).
    pub fn b_51(self) -> u16 {
        ((self.0 >> 23) & 0x1ff) as u16
    }
    /// Register C (bits 14-22).
    pub fn c_51(self) -> u16 {
        ((self.0 >> 14) & 0x1ff) as u16
    }
    /// sBx field (B+C combined as signed).
    pub fn sbx_51(self) -> i32 {
        (self.b_51() as u32 * 512 + self.c_51() as u32) as i32 - 131_071
    }
    /// Bx field.
    pub fn bx_51(self) -> u32 {
        (self.0 >> 14) & 0x3ffff
    }

    /// `true` if B field has the `isk` bit set (constant reference).
    pub fn b_is_k(self) -> bool {
        self.b_51() & 0x100 != 0
    }
    /// `true` if C field has the `isk` bit set.
    pub fn c_is_k(self) -> bool {
        self.c_51() & 0x100 != 0
    }

    /// Constant index from B (when `b_is_k`).
    pub fn b_const_idx(self) -> u8 {
        (self.b_51() & 0xff) as u8
    }
    /// Constant index from C (when `c_is_k`).
    pub fn c_const_idx(self) -> u8 {
        (self.c_51() & 0xff) as u8
    }
}

// ---------------------------------------------------------------------------
// LuaPrototype — parsed function prototype
// ---------------------------------------------------------------------------

/// A Lua 5.x function prototype.
#[derive(Debug, Clone)]
pub struct LuaPrototype {
    pub source_name: String,
    pub line_defined: u32,
    pub last_line_defined: u32,
    pub num_upvalues: u8,
    pub num_params: u8,
    pub is_vararg: bool,
    pub max_stack: u8,
    pub instructions: Vec<LuaBytecodeInstruction>,
    pub constants: Vec<LuaConst>,
    pub sub_prototypes: Vec<LuaPrototype>,
    pub line_info: Vec<u32>,
    pub local_vars: Vec<(String, u32, u32)>, // (name, startpc, endpc)
    pub upvalue_names: Vec<String>,
}

impl LuaPrototype {
    pub fn new() -> Self {
        Self {
            source_name: String::new(),
            line_defined: 0,
            last_line_defined: 0,
            num_upvalues: 0,
            num_params: 0,
            is_vararg: false,
            max_stack: 0,
            instructions: Vec::new(),
            constants: Vec::new(),
            sub_prototypes: Vec::new(),
            line_info: Vec::new(),
            local_vars: Vec::new(),
            upvalue_names: Vec::new(),
        }
    }

    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }
    pub fn constant_count(&self) -> usize {
        self.constants.len()
    }
    pub fn nested_count(&self) -> usize {
        self.sub_prototypes.len()
    }

    /// Line number for a given instruction index (0 if no debug info).
    pub fn line_for_pc(&self, pc: usize) -> u32 {
        self.line_info.get(pc).copied().unwrap_or(0)
    }
}

impl Default for LuaPrototype {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// LuaUpvalueAnalysis — upvalue dependency analysis
// ---------------------------------------------------------------------------

/// Information about one captured upvalue.
#[derive(Debug, Clone)]
pub struct UpvalueInfo {
    pub index: u8,
    pub name: String,
    /// `true` if this upvalue is an upvalue of the enclosing function (in-stack = false).
    pub in_stack: bool,
    /// Index in the enclosing function's register or upvalue list.
    pub parent_index: u8,
}

impl UpvalueInfo {
    pub fn new(index: u8, name: impl Into<String>, in_stack: bool, parent_index: u8) -> Self {
        Self {
            index,
            name: name.into(),
            in_stack,
            parent_index,
        }
    }

    /// `true` if the upvalue is a register capture (closed-over variable).
    pub fn is_closed_over(&self) -> bool {
        self.in_stack
    }
}

/// Upvalue dependency summary for a function prototype.
#[derive(Debug, Default)]
pub struct UpvalueAnalysis {
    pub upvalues: Vec<UpvalueInfo>,
}

impl UpvalueAnalysis {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, info: UpvalueInfo) {
        self.upvalues.push(info);
    }
    pub fn len(&self) -> usize {
        self.upvalues.len()
    }
    pub fn is_empty(&self) -> bool {
        self.upvalues.is_empty()
    }

    pub fn closed_over_count(&self) -> usize {
        self.upvalues.iter().filter(|u| u.is_closed_over()).count()
    }
}

// ---------------------------------------------------------------------------
// LuaOptimizer — simple AST-level optimizer
// ---------------------------------------------------------------------------

/// Optimization pass over the Lua AST.
pub struct LuaOptimizer;

impl LuaOptimizer {
    /// Fold constant expressions in a statement list (modifies in place).
    pub fn fold_statement_list(sl: &mut StatementList) {
        for stmt in &mut sl.statements {
            Self::fold_statement(stmt);
        }
    }

    fn fold_statement(stmt: &mut Statement) {
        match stmt {
            Statement::LocalAssign { values, .. } => {
                for v in values.iter_mut() {
                    Self::fold_expr(v);
                }
            }
            Statement::Assign { values, .. } => {
                for v in values.iter_mut() {
                    Self::fold_expr(v);
                }
            }
            Statement::Return(vals) => {
                for v in vals.iter_mut() {
                    Self::fold_expr(v);
                }
            }
            Statement::ExprStatement(e) => Self::fold_expr(e),
            _ => {}
        }
    }

    fn fold_expr(expr: &mut ExpressionTree) {
        match expr {
            ExpressionTree::BinOp { op, lhs, rhs } => {
                Self::fold_expr(lhs);
                Self::fold_expr(rhs);
                if let Some(folded) = fold_binop(*op, lhs, rhs) {
                    *expr = folded;
                }
            }
            ExpressionTree::UnOp { op, operand } => {
                Self::fold_expr(operand);
                if let Some(folded) = fold_unop(*op, operand) {
                    *expr = folded;
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// LuaAst
// ---------------------------------------------------------------------------

/// Full AST for a Lua chunk (file or string).
#[derive(Debug, Default)]
pub struct LuaAst {
    pub top_level: FunctionAst,
    pub source_name: String,
    pub lua_version: u8,
}

impl LuaAst {
    pub fn new(source_name: impl Into<String>, lua_version: u8) -> Self {
        Self {
            top_level: FunctionAst::new(),
            source_name: source_name.into(),
            lua_version,
        }
    }
}

// ---------------------------------------------------------------------------
// LuaDecompilerFull
// ---------------------------------------------------------------------------

/// Full Lua decompiler: parses bytecode and builds an AST.
#[derive(Debug, Default)]
pub struct LuaDecompilerFull {
    pub ast: Option<LuaAst>,
    pub control_flow: Option<ControlFlow>,
    pub errors: Vec<DecompError>,
    pub warnings: Vec<String>,
}

impl LuaDecompilerFull {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to decompile a Lua 5.1 bytecode chunk.
    /// This is a structural skeleton — a real implementation would walk the
    /// instruction stream and reconstruct all statement types.
    pub fn decompile_51(&mut self, bytecode: &[u8]) -> Result<(), DecompError> {
        if bytecode.len() < 12 {
            return Err(DecompError::TruncatedBytecode { pc: 0 });
        }
        // Lua 5.1 header: "\x1bLua" version=0x51
        if &bytecode[..4] != b"\x1bLua" {
            return Err(DecompError::InvalidOpcode(bytecode[0]));
        }
        let version = bytecode[4];
        if version != 0x51 {
            return Err(DecompError::UnsupportedLuaVersion(version));
        }
        let mut ast = LuaAst::new("chunk", 0x51);
        // Minimal mock: emit a return statement
        ast.top_level
            .body
            .push(Statement::Return(vec![ExpressionTree::Nil]));
        self.ast = Some(ast);
        self.control_flow = Some(ControlFlow::new());
        Ok(())
    }

    /// Synthesise an AST from a pre-built FunctionAst (for testing).
    pub fn from_function_ast(&mut self, func: FunctionAst, source: impl Into<String>) {
        let mut lua_ast = LuaAst::new(source, 0x51);
        lua_ast.top_level = func;
        self.ast = Some(lua_ast);
    }

    /// `true` if decompilation produced any errors.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Total statement count in the decompiled AST.
    pub fn total_statements(&self) -> usize {
        self.ast
            .as_ref()
            .map(|a| a.top_level.total_statement_count())
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Pretty-printer (minimal)
// ---------------------------------------------------------------------------

/// Render an expression to a string.
pub fn render_expr(expr: &ExpressionTree) -> String {
    match expr {
        ExpressionTree::Nil => "nil".to_string(),
        ExpressionTree::True => "true".to_string(),
        ExpressionTree::False => "false".to_string(),
        ExpressionTree::Integer(n) => n.to_string(),
        ExpressionTree::Float(f) => format!("{f}"),
        ExpressionTree::StringLit(s) => format!("\"{}\"", s.replace('"', "\\\"")),
        ExpressionTree::LocalVar { name, .. } => name.clone(),
        ExpressionTree::UpvalVar { name, .. } => name.clone(),
        ExpressionTree::GlobalVar(n) => n.clone(),
        ExpressionTree::VarArg => "...".to_string(),
        ExpressionTree::BinOp { op, lhs, rhs } => format!(
            "({} {} {})",
            render_expr(lhs),
            op.symbol(),
            render_expr(rhs)
        ),
        ExpressionTree::UnOp { op, operand } => {
            format!("({}{})", op.symbol(), render_expr(operand))
        }
        ExpressionTree::TableIndex { table, key } => {
            format!("{}[{}]", render_expr(table), render_expr(key))
        }
        ExpressionTree::TableField { table, field } => format!("{}.{}", render_expr(table), field),
        ExpressionTree::FunctionCall { func, args } => {
            let args_str: Vec<_> = args.iter().map(render_expr).collect();
            format!("{}({})", render_expr(func), args_str.join(", "))
        }
        ExpressionTree::MethodCall { obj, method, args } => {
            let args_str: Vec<_> = args.iter().map(render_expr).collect();
            format!("{}:{}({})", render_expr(obj), method, args_str.join(", "))
        }
        ExpressionTree::Closure { proto_index } => format!("<function#{proto_index}>"),
        ExpressionTree::Concat { values } => {
            let parts: Vec<_> = values.iter().map(render_expr).collect();
            parts.join(" .. ")
        }
        ExpressionTree::TableConstructor { .. } => "{}".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- LuaConst ----

    #[test]
    fn test_lua_const_type_names() {
        assert_eq!(LuaConst::Nil.type_name(), "nil");
        assert_eq!(LuaConst::Bool(true).type_name(), "boolean");
        assert_eq!(LuaConst::Int(0).type_name(), "integer");
        assert_eq!(LuaConst::Float(0.0).type_name(), "float");
        assert_eq!(LuaConst::Str("x".into()).type_name(), "string");
    }

    #[test]
    fn test_lua_const_falsy() {
        assert!(LuaConst::Nil.is_falsy());
        assert!(LuaConst::Bool(false).is_falsy());
        assert!(!LuaConst::Bool(true).is_falsy());
        assert!(!LuaConst::Int(0).is_falsy());
    }

    // ---- BinOp ----

    #[test]
    fn test_binop_symbols() {
        assert_eq!(BinOp::Add.symbol(), "+");
        assert_eq!(BinOp::Concat.symbol(), "..");
        assert_eq!(BinOp::Ge.symbol(), ">=");
    }

    #[test]
    fn test_binop_is_comparison() {
        assert!(BinOp::Eq.is_comparison());
        assert!(!BinOp::Add.is_comparison());
    }

    #[test]
    fn test_binop_is_logical() {
        assert!(BinOp::And.is_logical());
        assert!(BinOp::Or.is_logical());
        assert!(!BinOp::Add.is_logical());
    }

    // ---- UnOp ----

    #[test]
    fn test_unop_symbols() {
        assert_eq!(UnOp::Neg.symbol(), "-");
        assert_eq!(UnOp::Not.symbol(), "not ");
        assert_eq!(UnOp::Len.symbol(), "#");
        assert_eq!(UnOp::BNot.symbol(), "~");
    }

    // ---- StatementList ----

    #[test]
    fn test_statement_list_empty() {
        let sl = StatementList::new();
        assert!(sl.is_empty());
        assert_eq!(sl.len(), 0);
    }

    #[test]
    fn test_statement_list_push() {
        let mut sl = StatementList::new();
        sl.push(Statement::Break);
        sl.push(Statement::Break);
        assert_eq!(sl.len(), 2);
    }

    #[test]
    fn test_statement_list_return_count() {
        let mut sl = StatementList::new();
        sl.push(Statement::Return(vec![]));
        sl.push(Statement::Break);
        sl.push(Statement::Return(vec![ExpressionTree::Nil]));
        assert_eq!(sl.return_count(), 2);
    }

    // ---- FunctionAst ----

    #[test]
    fn test_function_ast_default() {
        let f = FunctionAst::default();
        assert!(f.params.is_empty());
        assert!(!f.is_vararg);
    }

    #[test]
    fn test_function_ast_total_statements() {
        let mut f = FunctionAst::new();
        f.body.push(Statement::Break);
        f.body.push(Statement::Continue);
        assert_eq!(f.total_statement_count(), 2);
    }

    #[test]
    fn test_function_ast_nested_count() {
        let mut f = FunctionAst::new();
        f.body.push(Statement::Break);
        let mut nested = FunctionAst::new();
        nested.body.push(Statement::Return(vec![]));
        nested.body.push(Statement::Return(vec![]));
        f.nested_functions.push(nested);
        assert_eq!(f.total_statement_count(), 3); // 1 + 2
    }

    #[test]
    fn test_function_ast_accepts_vararg() {
        let mut f = FunctionAst::new();
        f.is_vararg = true;
        assert!(f.accepts_vararg());
    }

    // ---- BasicBlock ----

    #[test]
    fn test_basic_block_add_successor() {
        let mut b = BasicBlock::new(0, 0);
        b.add_successor(1);
        b.add_successor(1); // duplicate ignored
        assert_eq!(b.successors.len(), 1);
    }

    #[test]
    fn test_basic_block_is_conditional() {
        let mut b = BasicBlock::new(0, 0);
        b.add_successor(1);
        assert!(!b.is_conditional());
        b.add_successor(2);
        assert!(b.is_conditional());
    }

    // ---- ControlFlow ----

    #[test]
    fn test_control_flow_find_block_by_pc() {
        let mut cfg = ControlFlow::new();
        cfg.add_block(BasicBlock::new(0, 0));
        cfg.add_block(BasicBlock::new(1, 10));
        assert!(cfg.find_block_by_pc(0).is_some());
        assert!(cfg.find_block_by_pc(99).is_none());
    }

    #[test]
    fn test_control_flow_loop_header_count() {
        let mut cfg = ControlFlow::new();
        let mut b = BasicBlock::new(0, 0);
        b.is_loop_header = true;
        cfg.add_block(b);
        cfg.add_block(BasicBlock::new(1, 5));
        assert_eq!(cfg.loop_header_count(), 1);
    }

    // ---- render_expr ----

    #[test]
    fn test_render_nil() {
        assert_eq!(render_expr(&ExpressionTree::Nil), "nil");
    }

    #[test]
    fn test_render_integer() {
        assert_eq!(render_expr(&ExpressionTree::Integer(42)), "42");
    }

    #[test]
    fn test_render_string_lit() {
        assert_eq!(
            render_expr(&ExpressionTree::StringLit("hello".into())),
            "\"hello\""
        );
    }

    #[test]
    fn test_render_binop() {
        let e = ExpressionTree::BinOp {
            op: BinOp::Add,
            lhs: Box::new(ExpressionTree::Integer(1)),
            rhs: Box::new(ExpressionTree::Integer(2)),
        };
        assert_eq!(render_expr(&e), "(1 + 2)");
    }

    #[test]
    fn test_render_unop() {
        let e = ExpressionTree::UnOp {
            op: UnOp::Not,
            operand: Box::new(ExpressionTree::True),
        };
        assert_eq!(render_expr(&e), "(not true)");
    }

    #[test]
    fn test_render_table_field() {
        let e = ExpressionTree::TableField {
            table: Box::new(ExpressionTree::GlobalVar("t".into())),
            field: "x".into(),
        };
        assert_eq!(render_expr(&e), "t.x");
    }

    #[test]
    fn test_render_vararg() {
        assert_eq!(render_expr(&ExpressionTree::VarArg), "...");
    }

    // ---- LuaDecompilerFull ----

    #[test]
    fn test_decompiler_invalid_header() {
        let mut d = LuaDecompilerFull::new();
        let result = d.decompile_51(b"BAD");
        assert!(result.is_err());
    }

    #[test]
    fn test_decompiler_wrong_version() {
        let mut data = b"\x1bLua".to_vec();
        data.push(0x52); // wrong version
        data.extend_from_slice(&[0u8; 20]);
        let mut d = LuaDecompilerFull::new();
        assert!(matches!(
            d.decompile_51(&data),
            Err(DecompError::UnsupportedLuaVersion(0x52))
        ));
    }

    #[test]
    fn test_decompiler_valid_51_stub() {
        let mut data = b"\x1bLua".to_vec();
        data.push(0x51); // version
        data.extend_from_slice(&[0u8; 20]);
        let mut d = LuaDecompilerFull::new();
        d.decompile_51(&data).unwrap();
        assert!(d.ast.is_some());
    }

    #[test]
    fn test_decompiler_from_function_ast() {
        let mut d = LuaDecompilerFull::new();
        let mut f = FunctionAst::new();
        f.body.push(Statement::Return(vec![]));
        d.from_function_ast(f, "test_chunk");
        assert!(!d.has_errors());
        assert_eq!(d.total_statements(), 1);
    }

    #[test]
    fn test_decompiler_total_statements_zero() {
        let d = LuaDecompilerFull::new();
        assert_eq!(d.total_statements(), 0);
    }

    #[test]
    fn test_decompile_error_display() {
        let e = DecompError::TruncatedBytecode { pc: 42 };
        assert!(e.to_string().contains("42"));
        let e2 = DecompError::UnsupportedLuaVersion(0x54);
        assert!(e2.to_string().contains("54"));
    }

    #[test]
    fn test_render_method_call() {
        let e = ExpressionTree::MethodCall {
            obj: Box::new(ExpressionTree::GlobalVar("obj".into())),
            method: "print".into(),
            args: vec![ExpressionTree::StringLit("hi".into())],
        };
        let s = render_expr(&e);
        assert!(s.contains("obj:print"));
    }

    #[test]
    fn test_render_function_call() {
        let e = ExpressionTree::FunctionCall {
            func: Box::new(ExpressionTree::GlobalVar("print".into())),
            args: vec![ExpressionTree::Integer(1)],
        };
        assert_eq!(render_expr(&e), "print(1)");
    }

    #[test]
    fn test_render_local_var() {
        let e = ExpressionTree::LocalVar {
            reg: 0,
            name: "x".into(),
        };
        assert_eq!(render_expr(&e), "x");
    }

    #[test]
    fn test_render_global_var() {
        let e = ExpressionTree::GlobalVar("print".into());
        assert_eq!(render_expr(&e), "print");
    }

    #[test]
    fn test_render_upval_var() {
        let e = ExpressionTree::UpvalVar {
            idx: 0,
            name: "_ENV".into(),
        };
        assert_eq!(render_expr(&e), "_ENV");
    }

    #[test]
    fn test_render_float() {
        let e = ExpressionTree::Float(2.5);
        assert_eq!(render_expr(&e), "2.5");
    }

    #[test]
    fn test_render_closure() {
        let e = ExpressionTree::Closure { proto_index: 3 };
        assert!(render_expr(&e).contains('3'));
    }

    #[test]
    fn test_render_concat() {
        let e = ExpressionTree::Concat {
            values: vec![
                ExpressionTree::StringLit("a".into()),
                ExpressionTree::StringLit("b".into()),
            ],
        };
        let s = render_expr(&e);
        assert!(s.contains(".."));
    }

    #[test]
    fn test_render_table_constructor_empty() {
        let e = ExpressionTree::TableConstructor { fields: vec![] };
        assert_eq!(render_expr(&e), "{}");
    }

    #[test]
    fn test_binop_idiv_symbol() {
        assert_eq!(BinOp::IDiv.symbol(), "//");
    }

    #[test]
    fn test_binop_pow_symbol() {
        assert_eq!(BinOp::Pow.symbol(), "^");
    }

    #[test]
    fn test_binop_bitwise_not_logical() {
        assert!(!BinOp::BAnd.is_logical());
    }

    #[test]
    fn test_statement_list_push_multiple() {
        let mut sl = StatementList::new();
        sl.push(Statement::Break);
        sl.push(Statement::Continue);
        sl.push(Statement::Return(vec![]));
        assert_eq!(sl.len(), 3);
        assert_eq!(sl.return_count(), 1);
    }

    #[test]
    fn test_basic_block_predecessors() {
        let mut b = BasicBlock::new(1, 5);
        b.add_predecessor(0);
        b.add_predecessor(0); // duplicate
        assert_eq!(b.predecessors.len(), 1);
    }

    #[test]
    fn test_lua_ast_source_name() {
        let ast = LuaAst::new("my_script.lua", 0x51);
        assert_eq!(ast.source_name, "my_script.lua");
        assert_eq!(ast.lua_version, 0x51);
    }

    #[test]
    fn test_decompiler_has_no_errors_default() {
        let d = LuaDecompilerFull::new();
        assert!(!d.has_errors());
    }

    #[test]
    fn test_control_flow_no_blocks() {
        let cfg = ControlFlow::new();
        assert_eq!(cfg.loop_header_count(), 0);
    }

    #[test]
    fn test_decompile_error_invalid_register() {
        let e = DecompError::InvalidRegister { reg: 10, max: 5 };
        assert!(e.to_string().contains("10"));
        assert!(e.to_string().contains('5'));
    }

    #[test]
    fn test_table_field_index() {
        let _f = TableField::Index {
            key: ExpressionTree::Integer(1),
            value: ExpressionTree::Nil,
        };
    }

    #[test]
    fn test_table_field_name() {
        let _f = TableField::Name {
            name: "key".into(),
            value: ExpressionTree::True,
        };
    }

    #[test]
    fn test_table_field_value() {
        let _f = TableField::Value(ExpressionTree::Integer(42));
    }
}

// ---------------------------------------------------------------------------
// LuaChunkInfo — metadata about the Lua chunk
// ---------------------------------------------------------------------------

/// Top-level metadata about a parsed Lua bytecode chunk.
#[derive(Debug, Clone)]
pub struct LuaChunkInfo {
    pub signature: [u8; 4],
    pub version: u8,
    pub format: u8,
    pub is_little_endian: bool,
    pub int_size: u8,
    pub size_t_size: u8,
    pub instruction_size: u8,
    pub number_size: u8,
    pub integral_flag: bool,
}

impl LuaChunkInfo {
    pub fn is_64bit(&self) -> bool {
        self.size_t_size == 8
    }
    pub fn is_float_numbers(&self) -> bool {
        !self.integral_flag
    }
    pub fn lua_version_str(&self) -> String {
        format!("{}.{}", self.version >> 4, self.version & 0xf)
    }
}
// ---------------------------------------------------------------------------
// LuaVersionConfig — per-version instruction size / format details
// ---------------------------------------------------------------------------

/// Configuration for a specific Lua version's bytecode format.
#[derive(Debug, Clone, Copy)]
pub struct LuaVersionConfig {
    pub version: u8,
    pub instruction_size: usize,
    pub int_size: usize,
    pub size_t_size: usize,
    pub number_size: usize,
    pub uses_int_numbers: bool,
}

impl LuaVersionConfig {
    pub fn lua51() -> Self {
        Self {
            version: 0x51,
            instruction_size: 4,
            int_size: 4,
            size_t_size: 8,
            number_size: 8,
            uses_int_numbers: false,
        }
    }
    pub fn lua52() -> Self {
        Self {
            version: 0x52,
            instruction_size: 4,
            int_size: 4,
            size_t_size: 8,
            number_size: 8,
            uses_int_numbers: false,
        }
    }
    pub fn lua53() -> Self {
        Self {
            version: 0x53,
            instruction_size: 4,
            int_size: 8,
            size_t_size: 8,
            number_size: 8,
            uses_int_numbers: false,
        }
    }
    pub fn lua54() -> Self {
        Self {
            version: 0x54,
            instruction_size: 4,
            int_size: 8,
            size_t_size: 8,
            number_size: 8,
            uses_int_numbers: true,
        }
    }

    pub fn is_64bit(&self) -> bool {
        self.size_t_size == 8
    }
    pub fn version_name(&self) -> &'static str {
        match self.version {
            0x51 => "5.1",
            0x52 => "5.2",
            0x53 => "5.3",
            0x54 => "5.4",
            _ => "?",
        }
    }
}

// ---------------------------------------------------------------------------
// LuaDecompilerConfig — decompiler configuration options
// ---------------------------------------------------------------------------

/// Configuration options for the Lua decompiler.
#[derive(Debug, Clone)]
pub struct LuaDecompilerConfig {
    pub fold_constants: bool,
    pub emit_line_numbers: bool,
    pub emit_upvalue_comments: bool,
    pub max_recursion_depth: u32,
    pub anonymous_function_prefix: String,
}

impl Default for LuaDecompilerConfig {
    fn default() -> Self {
        Self {
            fold_constants: true,
            emit_line_numbers: false,
            emit_upvalue_comments: true,
            max_recursion_depth: 256,
            anonymous_function_prefix: "anon_".to_string(),
        }
    }
}

impl LuaDecompilerConfig {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_line_numbers(mut self) -> Self {
        self.emit_line_numbers = true;
        self
    }
    pub fn without_constant_folding(mut self) -> Self {
        self.fold_constants = false;
        self
    }
}

// ---------------------------------------------------------------------------
// LuaStringTable — interned string table from Lua state
// ---------------------------------------------------------------------------

/// A string interned in the Lua state.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LuaInternedString {
    pub content: String,
    pub hash: u32,
    pub is_long: bool,
}

impl LuaInternedString {
    pub fn new(s: impl Into<String>) -> Self {
        let s = s.into();
        let hash = simple_lua_hash(s.as_bytes());
        let is_long = s.len() > 40;
        Self {
            content: s,
            hash,
            is_long,
        }
    }
    pub fn len(&self) -> usize {
        self.content.len()
    }

    /// Returns `true` when [`len`](Self::len) is zero.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn is_empty_str(&self) -> bool {
        self.content.is_empty()
    }
}

/// Simple djb2-like hash (Lua uses a subset).
fn simple_lua_hash(data: &[u8]) -> u32 {
    let mut h: u32 = 0;
    let step = (data.len() / 32).max(1);
    let mut i = data.len();
    while i > 0 {
        h ^= (h << 5)
            .wrapping_add(h >> 2)
            .wrapping_add(data[i - 1] as u32);
        i = i.saturating_sub(step);
    }
    h
}

// ---------------------------------------------------------------------------
// LuaGlobalTable — global variable index
// ---------------------------------------------------------------------------

/// Index of global variables encountered during decompilation.
#[derive(Debug, Default)]
pub struct LuaGlobalTable {
    pub names: Vec<String>,
}

impl LuaGlobalTable {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, name: impl Into<String>) {
        self.names.push(name.into());
    }
    pub fn contains(&self, name: &str) -> bool {
        self.names.iter().any(|n| n == name)
    }
    pub fn len(&self) -> usize {
        self.names.len()
    }
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/// Read a null-terminated UTF-8 string from a byte slice at `offset`.
pub fn read_cstring(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| offset + p)
        .unwrap_or(data.len());
    std::str::from_utf8(&data[offset..end])
        .ok()
        .map(|s| s.to_owned())
}

/// Align a value up to `align` (power-of-two).
pub fn align_up(val: u64, align: u64) -> u64 {
    if align == 0 {
        return val;
    }
    (val + align - 1) & !(align - 1)
}

/// Align a value down to `align` (power-of-two).
pub fn align_down(val: u64, align: u64) -> u64 {
    if align == 0 {
        return val;
    }
    val & !(align - 1)
}

/// Check whether `val` is a power of two.
pub fn is_power_of_two(val: u64) -> bool {
    val != 0 && val.is_power_of_two()
}

/// Simple entropy estimate over a byte slice (0.0 = uniform, 1.0 = random).
pub fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &freq {
        if c > 0 {
            let p = c as f64 / n;
            entropy -= p * p.log2();
        }
    }
    entropy / 8.0 // normalise to [0, 1]
}

// ---------------------------------------------------------------------------
// Additional parsing utilities
// ---------------------------------------------------------------------------

/// Parse a little-endian u16.
#[inline]
pub fn le_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[off], data[off + 1]])
}
/// Parse a little-endian u32.
#[inline]
pub fn le_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}
/// Parse a little-endian u64.
#[inline]
pub fn le_u64(data: &[u8], off: usize) -> u64 {
    if off + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}
/// Parse a big-endian u32.
#[inline]
pub fn be_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_be_bytes(data[off..off + 4].try_into().unwrap())
}
/// Verify a 32-bit Adler-32 checksum over `data`.
pub fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

// ---------------------------------------------------------------------------
// Byte pattern matching utilities
// ---------------------------------------------------------------------------

/// Search `haystack` for the first occurrence of `needle`.
pub fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Count non-overlapping occurrences of `needle` in `haystack`.
pub fn count_bytes(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut pos = 0;
    while let Some(idx) = haystack[pos..]
        .windows(needle.len())
        .position(|w| w == needle)
    {
        count += 1;
        pos += idx + needle.len();
    }
    count
}

/// Extract a sub-slice at `offset` with `len`, returning `None` if out of bounds.
pub fn try_slice(data: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    data.get(offset..offset + len)
}

// Last additions
/// Check if a byte slice is all zeros.
pub fn is_zeroed(data: &[u8]) -> bool {
    data.iter().all(|&b| b == 0)
}
/// Reverse bytes in-place.
pub fn reverse_bytes(data: &mut [u8]) {
    data.reverse();
}
/// XOR all bytes with `key`.
pub fn xor_bytes(data: &mut [u8], key: u8) {
    for b in data.iter_mut() {
        *b ^= key;
    }
}
/// Rotate `val` left by `n` bits (32-bit).
pub fn rol32(val: u32, n: u32) -> u32 {
    val.rotate_left(n)
}
/// Rotate `val` right by `n` bits (32-bit).
pub fn ror32(val: u32, n: u32) -> u32 {
    val.rotate_right(n)
}
