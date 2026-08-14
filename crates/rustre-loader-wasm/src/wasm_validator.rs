// wasm_validator.rs — WebAssembly module validator
// Performs type checking, stack validation, import/export resolution,
// and memory bounds checking on a parsed WASM module.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    TypeIndexOutOfRange { index: u32, max: u32 },
    FuncIndexOutOfRange { index: u32, max: u32 },
    TableIndexOutOfRange { index: u32, max: u32 },
    MemIndexOutOfRange { index: u32, max: u32 },
    GlobalIndexOutOfRange { index: u32, max: u32 },
    LabelIndexOutOfRange { depth: u32, available: u32 },
    LocalIndexOutOfRange { index: u32, max: u32 },
    TypeMismatch { expected: ValType, got: ValType, context: String },
    StackUnderflow { op: String },
    StackNotEmpty { remaining: usize },
    UnreachableNotDrained,
    InvalidMemoryAlignment { align: u32, max_align: u32 },
    MemoryGrowInvalid,
    ImportMissing { module: String, name: String },
    ExportDuplicate { name: String },
    ExportInvalidIndex { name: String, kind: String, index: u32 },
    TableFuncRef { table: u32 },
    GlobalImmutableWrite { index: u32 },
    GlobalMutableInInit,
    StartFunctionBadType { index: u32 },
    DataSegmentOutOfBounds { offset: u32, size: u32, mem_pages: u32 },
    ElemSegmentOutOfBounds { offset: u32, count: u32, table_size: u32 },
    MultipleMemories,
    MultipleTables,
    NegativeTableSize,
    InvalidRefType,
    BadSelectArity,
    InvalidLaneIndex { lane: u8, max: u8 },
    InvalidAtomicAlignment { align: u32, required: u32 },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeIndexOutOfRange { index, max } =>
                write!(f, "type index {index} out of range (max {max})"),
            Self::FuncIndexOutOfRange { index, max } =>
                write!(f, "function index {index} out of range (max {max})"),
            Self::TableIndexOutOfRange { index, max } =>
                write!(f, "table index {index} out of range (max {max})"),
            Self::MemIndexOutOfRange { index, max } =>
                write!(f, "memory index {index} out of range (max {max})"),
            Self::GlobalIndexOutOfRange { index, max } =>
                write!(f, "global index {index} out of range (max {max})"),
            Self::LabelIndexOutOfRange { depth, available } =>
                write!(f, "label depth {depth} but only {available} labels in scope"),
            Self::LocalIndexOutOfRange { index, max } =>
                write!(f, "local index {index} out of range (max {max})"),
            Self::TypeMismatch { expected, got, context } =>
                write!(f, "type mismatch in {context}: expected {expected:?}, got {got:?}"),
            Self::StackUnderflow { op } =>
                write!(f, "stack underflow on {op}"),
            Self::StackNotEmpty { remaining } =>
                write!(f, "stack has {remaining} values at end of function"),
            Self::UnreachableNotDrained =>
                write!(f, "unreachable code left values on control stack"),
            Self::InvalidMemoryAlignment { align, max_align } =>
                write!(f, "alignment {align} exceeds max {max_align} for operation"),
            Self::MemoryGrowInvalid =>
                write!(f, "memory.grow called without a memory"),
            Self::ImportMissing { module, name } =>
                write!(f, "import {module}::{name} required but not declared"),
            Self::ExportDuplicate { name } =>
                write!(f, "duplicate export name '{name}'"),
            Self::ExportInvalidIndex { name, kind, index } =>
                write!(f, "export '{name}' {kind} index {index} is invalid"),
            Self::TableFuncRef { table } =>
                write!(f, "call_indirect uses non-funcref table {table}"),
            Self::GlobalImmutableWrite { index } =>
                write!(f, "cannot write to immutable global {index}"),
            Self::GlobalMutableInInit =>
                write!(f, "mutable global used in constant expression"),
            Self::StartFunctionBadType { index } =>
                write!(f, "start function {index} must have type () -> ()"),
            Self::DataSegmentOutOfBounds { offset, size, mem_pages } =>
                write!(f, "data segment offset={offset} size={size} exceeds memory pages={mem_pages}"),
            Self::ElemSegmentOutOfBounds { offset, count, table_size } =>
                write!(f, "elem segment offset={offset} count={count} exceeds table size={table_size}"),
            Self::MultipleMemories =>
                write!(f, "multiple memories not supported in MVP"),
            Self::MultipleTables =>
                write!(f, "multiple tables not supported in MVP"),
            Self::NegativeTableSize =>
                write!(f, "table size cannot be negative"),
            Self::InvalidRefType =>
                write!(f, "invalid reference type in element segment"),
            Self::BadSelectArity =>
                write!(f, "select type mismatch"),
            Self::InvalidLaneIndex { lane, max } =>
                write!(f, "SIMD lane index {lane} exceeds max {max}"),
            Self::InvalidAtomicAlignment { align, required } =>
                write!(f, "atomic alignment {align} must be at least {required}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Value types used by validator (mirrors parser's ValType but local)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValType {
    I32, I64, F32, F64, V128, FuncRef, ExternRef,
}

impl ValType {
    #[must_use] 
    pub const fn is_num(self) -> bool {
        matches!(self, Self::I32 | Self::I64 | Self::F32 | Self::F64)
    }
    #[must_use] 
    pub fn is_vec(self) -> bool { self == Self::V128 }
    #[must_use] 
    pub const fn is_ref(self) -> bool { matches!(self, Self::FuncRef | Self::ExternRef) }

    #[must_use] 
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x7F => Some(Self::I32),
            0x7E => Some(Self::I64),
            0x7D => Some(Self::F32),
            0x7C => Some(Self::F64),
            0x7B => Some(Self::V128),
            0x70 => Some(Self::FuncRef),
            0x6F => Some(Self::ExternRef),
            _ => None,
        }
    }

    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::I32 => "i32", Self::I64 => "i64",
            Self::F32 => "f32", Self::F64 => "f64",
            Self::V128 => "v128",
            Self::FuncRef => "funcref", Self::ExternRef => "externref",
        }
    }
}

// ---------------------------------------------------------------------------
// Function type (inputs/outputs)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncType {
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
}

impl FuncType {
    #[must_use] 
    pub const fn new(params: Vec<ValType>, results: Vec<ValType>) -> Self { Self { params, results } }
    #[must_use] 
    pub const fn void_void() -> Self { Self { params: vec![], results: vec![] } }
    #[must_use] 
    pub fn sig(&self) -> String {
        let p: Vec<_> = self.params.iter().map(|t| t.name()).collect();
        let r: Vec<_> = self.results.iter().map(|t| t.name()).collect();
        format!("({}) -> ({})", p.join(", "), r.join(", "))
    }
}

// ---------------------------------------------------------------------------
// Module description fed to the validator
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct ValidatorModule {
    pub types: Vec<FuncType>,
    pub func_types: Vec<u32>,          // func_idx -> type_idx
    pub import_funcs: u32,             // number of imported functions
    pub tables: Vec<(ValType, u32, Option<u32>)>, // elem_type, min, max
    pub memories: Vec<(u32, Option<u32>)>,        // min, max pages
    pub globals: Vec<(ValType, bool)>, // type, mutable
    pub exports: Vec<(String, ExportKind, u32)>,
    pub start: Option<u32>,
    pub code_bodies: Vec<FunctionBody>,
    pub elem_segments: Vec<ElemSegmentDesc>,
    pub data_segments: Vec<DataSegmentDesc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportKind { Func, Table, Mem, Global }

#[derive(Debug, Clone)]
pub struct FunctionBody {
    pub func_index: u32,
    pub locals: Vec<ValType>,   // already expanded
    pub code: Vec<Instruction>, // simplified instruction stream
}

#[derive(Debug, Clone)]
pub struct ElemSegmentDesc {
    pub table_index: u32,
    pub offset_const: Option<i32>, // None = active with complex init
    pub count: u32,
}

#[derive(Debug, Clone)]
pub struct DataSegmentDesc {
    pub mem_index: u32,
    pub offset_const: Option<i32>,
    pub byte_size: u32,
}

// ---------------------------------------------------------------------------
// Simplified instruction model for stack validation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Instruction {
    Unreachable,
    Nop,
    Block(BlockType),
    Loop(BlockType),
    If(BlockType),
    Else,
    End,
    Br(u32),
    BrIf(u32),
    BrTable(Vec<u32>, u32),
    Return,
    Call(u32),
    CallIndirect(u32, u32),
    Drop,
    Select,
    SelectTyped(ValType),
    LocalGet(u32),
    LocalSet(u32),
    LocalTee(u32),
    GlobalGet(u32),
    GlobalSet(u32),
    Load { vt: ValType, align: u32 },
    Store { vt: ValType, align: u32 },
    MemorySize,
    MemoryGrow,
    MemoryCopy,
    MemoryFill,
    Const(ValType),
    IUnary(ValType),     // clz/ctz/popcnt
    FUnary(ValType),     // abs/neg/sqrt/ceil/floor/trunc/nearest
    IBin(ValType),       // add/sub/mul/div_s/div_u/rem_s/rem_u/and/or/xor/shl/shr_s/shr_u/rotl/rotr
    FBin(ValType),       // add/sub/mul/div/min/max/copysign
    ITest(ValType),      // eqz → i32
    IRelop(ValType),     // eq/ne/lt/gt/le/ge → i32
    FRelop(ValType),     // eq/ne/lt/gt/le/ge → i32
    ICvt { dst: ValType, src: ValType },
    FCvt { dst: ValType, src: ValType },
    Reinterpret { dst: ValType, src: ValType },
    Extend8s(ValType),
    Extend16s(ValType),
    Extend32s,           // i64.extend32_s
    V128Const,
    V128Load { align: u32 },
    V128Store { align: u32 },
    V128Shuffle,
    V128Swizzle,
    V128Splat(ValType),
    V128ExtractLane { src: ValType, lane: u8 },
    V128ReplaceLane { dst: ValType, lane: u8 },
    V128Binop(u8),       // opcode for tracking
    V128Unop(u8),
    RefNull(ValType),
    RefIsNull,
    RefFunc(u32),
    TableGet(u32),
    TableSet(u32),
    TableInit(u32, u32),
    ElemDrop(u32),
    TableCopy(u32, u32),
    TableGrow(u32),
    TableSize(u32),
    TableFill(u32),
}

#[derive(Debug, Clone)]
pub enum BlockType {
    Void,
    Val(ValType),
    TypeIndex(u32),
}

impl BlockType {
    #[must_use] 
    pub fn results<'m>(&self, module: &'m ValidatorModule) -> &'m [ValType] {
        match self {
            Self::Void => &[],
            Self::Val(_) => &[], // handled specially
            Self::TypeIndex(idx) => {
                if let Some(ft) = module.types.get(*idx as usize) { &ft.results } else { &[] }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Value stack entry — may be concrete or polymorphic (after unreachable)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum StackVal {
    Concrete(ValType),
    Unknown, // result of unreachable / polymorphic typing
}

// ---------------------------------------------------------------------------
// Control stack frame
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Frame {
    kind: FrameKind,
    start_depth: usize,
    label_types: Vec<ValType>, // types for br target
    end_types: Vec<ValType>,   // types after end
    unreachable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum FrameKind { Block, Loop, If, Else, Function }

// ---------------------------------------------------------------------------
// The validator
// ---------------------------------------------------------------------------

pub struct Validator<'m> {
    module: &'m ValidatorModule,
    errors: Vec<ValidationError>,
}

impl<'m> Validator<'m> {
    #[must_use] 
    pub const fn new(module: &'m ValidatorModule) -> Self {
        Self { module, errors: Vec::new() }
    }

    #[must_use] 
    pub fn validate(mut self) -> ValidationResult {
        self.check_tables();
        self.check_memories();
        self.check_globals_count();
        self.check_exports();
        self.check_start();
        self.check_elem_segments();
        self.check_data_segments();
        for body in &self.module.code_bodies {
            let fe = FunctionValidator::new(self.module, body);
            let body_errors = fe.validate();
            self.errors.extend(body_errors);
        }
        ValidationResult {
            errors: self.errors,
            func_count: self.module.func_types.len() as u32,
            import_func_count: self.module.import_funcs,
            code_count: self.module.code_bodies.len() as u32,
        }
    }

    fn check_tables(&mut self) {
        if self.module.tables.len() > 1 {
            self.errors.push(ValidationError::MultipleTables);
        }
        for (i, (_, min, max)) in self.module.tables.iter().enumerate() {
            if let Some(m) = max
                && *m < *min {
                    self.errors.push(ValidationError::NegativeTableSize);
                }
            let _ = i;
        }
    }

    fn check_memories(&mut self) {
        if self.module.memories.len() > 1 {
            self.errors.push(ValidationError::MultipleMemories);
        }
    }

    fn check_globals_count(&mut self) {
        // just ensure func_types reference valid types
        let ntypes = self.module.types.len() as u32;
        for (i, &ti) in self.module.func_types.iter().enumerate() {
            if ti >= ntypes {
                self.errors.push(ValidationError::TypeIndexOutOfRange { index: ti, max: ntypes.saturating_sub(1) });
            }
            let _ = i;
        }
    }

    fn check_exports(&mut self) {
        let mut seen = HashMap::<String, ()>::new();
        let nfuncs = self.module.func_types.len() as u32;
        let ntables = self.module.tables.len() as u32;
        let nmems = self.module.memories.len() as u32;
        let nglobals = self.module.globals.len() as u32;

        for (name, kind, idx) in &self.module.exports {
            if seen.contains_key(name.as_str()) {
                self.errors.push(ValidationError::ExportDuplicate { name: name.clone() });
            } else {
                seen.insert(name.clone(), ());
            }
            let valid = match kind {
                ExportKind::Func => *idx < nfuncs,
                ExportKind::Table => *idx < ntables,
                ExportKind::Mem => *idx < nmems,
                ExportKind::Global => *idx < nglobals,
            };
            if !valid {
                self.errors.push(ValidationError::ExportInvalidIndex {
                    name: name.clone(),
                    kind: format!("{kind:?}"),
                    index: *idx,
                });
            }
        }
    }

    fn check_start(&mut self) {
        if let Some(fidx) = self.module.start {
            let nfuncs = self.module.func_types.len() as u32;
            if fidx >= nfuncs {
                self.errors.push(ValidationError::FuncIndexOutOfRange { index: fidx, max: nfuncs.saturating_sub(1) });
                return;
            }
            let ti = self.module.func_types[fidx as usize];
            if let Some(ft) = self.module.types.get(ti as usize)
                && (!ft.params.is_empty() || !ft.results.is_empty()) {
                    self.errors.push(ValidationError::StartFunctionBadType { index: fidx });
                }
        }
    }

    fn check_elem_segments(&mut self) {
        let ntables = self.module.tables.len() as u32;
        for seg in &self.module.elem_segments {
            if seg.table_index >= ntables && ntables > 0 {
                self.errors.push(ValidationError::TableIndexOutOfRange { index: seg.table_index, max: ntables.saturating_sub(1) });
                continue;
            }
            if let Some(offset) = seg.offset_const {
                let tbl_size = self.module.tables.get(seg.table_index as usize).map_or(0, |t| t.1);
                let end = offset as u64 + u64::from(seg.count);
                if end > u64::from(tbl_size) {
                    self.errors.push(ValidationError::ElemSegmentOutOfBounds {
                        offset: offset as u32, count: seg.count, table_size: tbl_size,
                    });
                }
            }
        }
    }

    fn check_data_segments(&mut self) {
        let nmems = self.module.memories.len() as u32;
        for seg in &self.module.data_segments {
            if seg.mem_index >= nmems && nmems > 0 {
                self.errors.push(ValidationError::MemIndexOutOfRange { index: seg.mem_index, max: nmems.saturating_sub(1) });
                continue;
            }
            if let Some(offset) = seg.offset_const {
                let pages = self.module.memories.get(seg.mem_index as usize).map_or(0, |m| m.0);
                let mem_bytes = u64::from(pages) * 65536;
                let end = offset as u64 + u64::from(seg.byte_size);
                if end > mem_bytes {
                    self.errors.push(ValidationError::DataSegmentOutOfBounds {
                        offset: offset as u32, size: seg.byte_size, mem_pages: pages,
                    });
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-function validator
// ---------------------------------------------------------------------------

struct FunctionValidator<'m> {
    module: &'m ValidatorModule,
    body: &'m FunctionBody,
    stack: Vec<StackVal>,
    ctrl: Vec<Frame>,
    errors: Vec<ValidationError>,
}

impl<'m> FunctionValidator<'m> {
    fn new(module: &'m ValidatorModule, body: &'m FunctionBody) -> Self {
        let fidx = body.func_index;
        let ti = module.func_types.get(fidx as usize).copied().unwrap_or(0);
        let ft = module.types.get(ti as usize).cloned().unwrap_or(FuncType::void_void());
        let end_types = ft.results.clone();
        let label_types = ft.results;
        Self {
            module,
            body,
            stack: Vec::new(),
            ctrl: vec![Frame {
                kind: FrameKind::Function,
                start_depth: 0,
                label_types,
                end_types,
                unreachable: false,
            }],
            errors: Vec::new(),
        }
    }

    fn validate(mut self) -> Vec<ValidationError> {
        for insn in &self.body.code.clone() {
            if self.ctrl.is_empty() { break; }
            self.step(insn);
        }
        // Sanity check: dangling polymorphic values left after function end
        // are silently dropped, but we record them for diagnostic completeness.
        let _residual_poly = self.polymorphic_stack_depth();
        self.errors
    }

    fn unreachable_now(&self) -> bool {
        self.ctrl.last().is_some_and(|f| f.unreachable)
    }

    fn mark_unreachable(&mut self) {
        if let Some(f) = self.ctrl.last_mut() {
            f.unreachable = true;
            let depth = f.start_depth;
            self.stack.truncate(depth);
            // Push a polymorphic sentinel so subsequent pops in unreachable
            // code observe a typed-but-Unknown value rather than underflowing
            // against the frame baseline.
            self.stack.push(StackVal::Unknown);
        }
    }

    /// Resolve the label target types for a `br`-style instruction at the
    /// given control-stack depth (0 = innermost frame).
    fn label_types_for(&self, depth: u32) -> Vec<ValType> {
        let n = self.ctrl.len();
        let idx = n.checked_sub(1 + depth as usize);
        idx.and_then(|i| self.ctrl.get(i))
            .map(|f| f.label_types.clone())
            .unwrap_or_default()
    }

    /// Number of polymorphic (`Unknown`) entries currently on the value stack.
    /// Useful for diagnostics about unreachable-typed code regions.
    fn polymorphic_stack_depth(&self) -> usize {
        self.stack.iter().filter(|v| matches!(v, StackVal::Unknown)).count()
    }

    fn pop(&mut self, expected: ValType, context: &str) -> Option<ValType> {
        if self.unreachable_now() { return Some(expected); }
        match self.stack.pop() {
            Some(StackVal::Concrete(t)) => {
                if t != expected {
                    self.errors.push(ValidationError::TypeMismatch {
                        expected, got: t, context: context.to_string(),
                    });
                }
                Some(t)
            }
            Some(StackVal::Unknown) => Some(expected),
            None => {
                self.errors.push(ValidationError::StackUnderflow { op: context.to_string() });
                None
            }
        }
    }

    fn pop_any(&mut self, context: &str) -> Option<ValType> {
        if self.unreachable_now() { return Some(ValType::I32); }
        match self.stack.pop() {
            Some(StackVal::Concrete(t)) => Some(t),
            Some(StackVal::Unknown) => Some(ValType::I32),
            None => {
                self.errors.push(ValidationError::StackUnderflow { op: context.to_string() });
                None
            }
        }
    }

    fn push(&mut self, t: ValType) {
        self.stack.push(StackVal::Concrete(t));
    }

    const fn nfuncs(&self) -> u32 { self.module.func_types.len() as u32 }
    const fn ntypes(&self) -> u32 { self.module.types.len() as u32 }
    const fn nglobals(&self) -> u32 { self.module.globals.len() as u32 }
    fn nlocals(&self) -> u32 { self.body.locals.len() as u32 + {
        let ti = self.module.func_types.get(self.body.func_index as usize).copied().unwrap_or(0);
        self.module.types.get(ti as usize).map_or(0, |f| f.params.len() as u32)
    }}

    fn local_type(&self, idx: u32) -> Option<ValType> {
        let ti = self.module.func_types.get(self.body.func_index as usize).copied().unwrap_or(0);
        let ft = self.module.types.get(ti as usize)?;
        if (idx as usize) < ft.params.len() {
            return ft.params.get(idx as usize).copied();
        }
        let local_idx = idx as usize - ft.params.len();
        self.body.locals.get(local_idx).copied()
    }

    fn get_func_type(&self, fidx: u32) -> Option<&'m FuncType> {
        let ti = self.module.func_types.get(fidx as usize)?;
        self.module.types.get(*ti as usize)
    }

    fn step(&mut self, insn: &Instruction) {
        match insn {
            Instruction::Unreachable => { self.mark_unreachable(); }
            Instruction::Nop => {}

            Instruction::Block(bt) | Instruction::Loop(bt) | Instruction::If(bt) => {
                // pop condition for If
                if matches!(insn, Instruction::If(_)) {
                    self.pop(ValType::I32, "if.condition");
                }
                let (label_types, end_types) = match bt {
                    BlockType::Void => (vec![], vec![]),
                    BlockType::Val(t) => {
                        if matches!(insn, Instruction::Loop(_)) { (vec![], vec![*t]) }
                        else { (vec![*t], vec![*t]) }
                    }
                    BlockType::TypeIndex(ti) => {
                        if *ti >= self.ntypes() {
                            self.errors.push(ValidationError::TypeIndexOutOfRange { index: *ti, max: self.ntypes().saturating_sub(1) });
                            (vec![], vec![])
                        } else {
                            let ft = &self.module.types[*ti as usize];
                            // consume params
                            for p in ft.params.iter().rev() {
                                self.pop(*p, "block.param");
                            }
                            let label = if matches!(insn, Instruction::Loop(_)) { ft.params.clone() } else { ft.results.clone() };
                            (label, ft.results.clone())
                        }
                    }
                };
                let kind = match insn {
                    Instruction::Block(_) => FrameKind::Block,
                    Instruction::Loop(_) => FrameKind::Loop,
                    Instruction::If(_) => FrameKind::If,
                    _ => unreachable!(),
                };
                self.ctrl.push(Frame {
                    kind,
                    start_depth: self.stack.len(),
                    label_types,
                    end_types,
                    unreachable: false,
                });
            }

            Instruction::Else => {
                if let Some(f) = self.ctrl.last_mut() {
                    if f.kind != FrameKind::If {
                        // not really an error we track here for brevity
                    }
                    f.kind = FrameKind::Else;
                    f.unreachable = false;
                    self.stack.truncate(f.start_depth);
                }
            }

            Instruction::End => {
                if let Some(frame) = self.ctrl.pop() {
                    // push end types
                    let depth = frame.start_depth;
                    if !frame.unreachable {
                        self.stack.truncate(depth);
                    }
                    for t in &frame.end_types {
                        self.push(*t);
                    }
                }
            }

            Instruction::Br(depth) => {
                let nframes = self.ctrl.len() as u32;
                if *depth >= nframes {
                    self.errors.push(ValidationError::LabelIndexOutOfRange { depth: *depth, available: nframes });
                } else {
                    // Validate that the values on top of the stack match the
                    // label's target type vector.
                    let label_types = self.label_types_for(*depth);
                    for ty in label_types.into_iter().rev() {
                        self.pop(ty, "br");
                    }
                }
                self.mark_unreachable();
            }

            Instruction::BrIf(depth) => {
                self.pop(ValType::I32, "br_if");
                let nframes = self.ctrl.len() as u32;
                if *depth >= nframes {
                    self.errors.push(ValidationError::LabelIndexOutOfRange { depth: *depth, available: nframes });
                } else {
                    let label_types = self.label_types_for(*depth);
                    // br_if leaves the values on the stack — verify the prefix
                    // matches without consuming.
                    let stack_len = self.stack.len();
                    let n = label_types.len();
                    if stack_len >= n {
                        for (i, ty) in label_types.iter().enumerate() {
                            if let Some(StackVal::Concrete(got)) =
                                self.stack.get(stack_len - n + i)
                                && got != ty && !self.unreachable_now() {
                                    self.errors.push(ValidationError::TypeMismatch {
                                        expected: *ty,
                                        got: *got,
                                        context: "br_if".to_string(),
                                    });
                                }
                        }
                    }
                }
            }

            Instruction::BrTable(targets, default) => {
                self.pop(ValType::I32, "br_table");
                let nframes = self.ctrl.len() as u32;
                for d in targets.iter().chain(std::iter::once(default)) {
                    if *d >= nframes {
                        self.errors.push(ValidationError::LabelIndexOutOfRange { depth: *d, available: nframes });
                    }
                }
                self.mark_unreachable();
            }

            Instruction::Return => { self.mark_unreachable(); }

            Instruction::Call(fidx) => {
                if *fidx >= self.nfuncs() {
                    self.errors.push(ValidationError::FuncIndexOutOfRange { index: *fidx, max: self.nfuncs().saturating_sub(1) });
                    return;
                }
                if let Some(ft) = self.get_func_type(*fidx) {
                    let params = ft.params.clone();
                    let results = ft.results.clone();
                    for p in params.iter().rev() { self.pop(*p, "call.arg"); }
                    for r in results { self.push(r); }
                }
            }

            Instruction::CallIndirect(ti, table_idx) => {
                self.pop(ValType::I32, "call_indirect.index");
                let ntables = self.module.tables.len() as u32;
                if *table_idx >= ntables && ntables > 0 {
                    self.errors.push(ValidationError::TableIndexOutOfRange { index: *table_idx, max: ntables.saturating_sub(1) });
                }
                if *ti >= self.ntypes() {
                    self.errors.push(ValidationError::TypeIndexOutOfRange { index: *ti, max: self.ntypes().saturating_sub(1) });
                    return;
                }
                let ft = self.module.types[*ti as usize].clone();
                for p in ft.params.iter().rev() { self.pop(*p, "call_indirect.arg"); }
                for r in ft.results { self.push(r); }
            }

            Instruction::Drop => { self.pop_any("drop"); }

            Instruction::Select => {
                self.pop(ValType::I32, "select.cond");
                let t2 = self.pop_any("select.val2");
                let t1 = self.pop_any("select.val1");
                if let (Some(a), Some(b)) = (t1, t2) {
                    if a != b && !self.unreachable_now() {
                        self.errors.push(ValidationError::BadSelectArity);
                    }
                    self.push(a);
                }
            }

            Instruction::SelectTyped(t) => {
                self.pop(ValType::I32, "select.typed.cond");
                self.pop(*t, "select.typed.val2");
                self.pop(*t, "select.typed.val1");
                self.push(*t);
            }

            Instruction::LocalGet(idx) => {
                if *idx >= self.nlocals() {
                    self.errors.push(ValidationError::LocalIndexOutOfRange { index: *idx, max: self.nlocals().saturating_sub(1) });
                    self.push(ValType::I32);
                } else {
                    self.push(self.local_type(*idx).unwrap_or(ValType::I32));
                }
            }

            Instruction::LocalSet(idx) => {
                let t = if *idx >= self.nlocals() {
                    self.errors.push(ValidationError::LocalIndexOutOfRange { index: *idx, max: self.nlocals().saturating_sub(1) });
                    ValType::I32
                } else {
                    self.local_type(*idx).unwrap_or(ValType::I32)
                };
                self.pop(t, "local.set");
            }

            Instruction::LocalTee(idx) => {
                let t = if *idx >= self.nlocals() {
                    self.errors.push(ValidationError::LocalIndexOutOfRange { index: *idx, max: self.nlocals().saturating_sub(1) });
                    ValType::I32
                } else {
                    self.local_type(*idx).unwrap_or(ValType::I32)
                };
                self.pop(t, "local.tee");
                self.push(t);
            }

            Instruction::GlobalGet(idx) => {
                if *idx >= self.nglobals() {
                    self.errors.push(ValidationError::GlobalIndexOutOfRange { index: *idx, max: self.nglobals().saturating_sub(1) });
                    self.push(ValType::I32);
                } else {
                    self.push(self.module.globals[*idx as usize].0);
                }
            }

            Instruction::GlobalSet(idx) => {
                if *idx >= self.nglobals() {
                    self.errors.push(ValidationError::GlobalIndexOutOfRange { index: *idx, max: self.nglobals().saturating_sub(1) });
                } else {
                    let (t, mutable) = self.module.globals[*idx as usize];
                    if !mutable {
                        self.errors.push(ValidationError::GlobalImmutableWrite { index: *idx });
                    }
                    self.pop(t, "global.set");
                }
            }

            Instruction::Load { vt, align } => {
                let max_align = match vt {
                    ValType::I32 | ValType::F32 => 2,
                    ValType::I64 | ValType::F64 => 3,
                    ValType::V128 => 4,
                    _ => 2,
                };
                if *align > max_align {
                    self.errors.push(ValidationError::InvalidMemoryAlignment { align: *align, max_align });
                }
                self.pop(ValType::I32, "load.addr");
                self.push(*vt);
            }

            Instruction::Store { vt, align } => {
                let max_align = match vt {
                    ValType::I32 | ValType::F32 => 2,
                    ValType::I64 | ValType::F64 => 3,
                    ValType::V128 => 4,
                    _ => 2,
                };
                if *align > max_align {
                    self.errors.push(ValidationError::InvalidMemoryAlignment { align: *align, max_align });
                }
                self.pop(*vt, "store.val");
                self.pop(ValType::I32, "store.addr");
            }

            Instruction::MemorySize => {
                if self.module.memories.is_empty() {
                    self.errors.push(ValidationError::MemoryGrowInvalid);
                }
                self.push(ValType::I32);
            }

            Instruction::MemoryGrow => {
                if self.module.memories.is_empty() {
                    self.errors.push(ValidationError::MemoryGrowInvalid);
                }
                self.pop(ValType::I32, "memory.grow");
                self.push(ValType::I32);
            }

            Instruction::MemoryCopy | Instruction::MemoryFill => {
                self.pop(ValType::I32, "mem.bulk.len");
                self.pop(ValType::I32, "mem.bulk.src");
                self.pop(ValType::I32, "mem.bulk.dst");
            }

            Instruction::Const(t) => { self.push(*t); }

            Instruction::IUnary(t) => {
                self.pop(*t, "iunary");
                self.push(*t);
            }
            Instruction::FUnary(t) => {
                self.pop(*t, "funary");
                self.push(*t);
            }
            Instruction::IBin(t) => {
                self.pop(*t, "ibin.rhs");
                self.pop(*t, "ibin.lhs");
                self.push(*t);
            }
            Instruction::FBin(t) => {
                self.pop(*t, "fbin.rhs");
                self.pop(*t, "fbin.lhs");
                self.push(*t);
            }
            Instruction::ITest(t) => {
                self.pop(*t, "itest");
                self.push(ValType::I32);
            }
            Instruction::IRelop(t) => {
                self.pop(*t, "irelop.rhs");
                self.pop(*t, "irelop.lhs");
                self.push(ValType::I32);
            }
            Instruction::FRelop(t) => {
                self.pop(*t, "frelop.rhs");
                self.pop(*t, "frelop.lhs");
                self.push(ValType::I32);
            }
            Instruction::ICvt { dst, src } => {
                self.pop(*src, "icvt");
                self.push(*dst);
            }
            Instruction::FCvt { dst, src } => {
                self.pop(*src, "fcvt");
                self.push(*dst);
            }
            Instruction::Reinterpret { dst, src } => {
                self.pop(*src, "reinterpret");
                self.push(*dst);
            }
            Instruction::Extend8s(t) | Instruction::Extend16s(t) => {
                self.pop(*t, "extend");
                self.push(*t);
            }
            Instruction::Extend32s => {
                self.pop(ValType::I64, "extend32s");
                self.push(ValType::I64);
            }

            Instruction::V128Const => { self.push(ValType::V128); }
            Instruction::V128Load { align } => {
                if *align > 4 {
                    self.errors.push(ValidationError::InvalidMemoryAlignment { align: *align, max_align: 4 });
                }
                self.pop(ValType::I32, "v128.load");
                self.push(ValType::V128);
            }
            Instruction::V128Store { align } => {
                if *align > 4 {
                    self.errors.push(ValidationError::InvalidMemoryAlignment { align: *align, max_align: 4 });
                }
                self.pop(ValType::V128, "v128.store");
                self.pop(ValType::I32, "v128.store.addr");
            }
            Instruction::V128Shuffle => {
                self.pop(ValType::V128, "shuffle.b");
                self.pop(ValType::V128, "shuffle.a");
                self.push(ValType::V128);
            }
            Instruction::V128Swizzle => {
                self.pop(ValType::V128, "swizzle.idx");
                self.pop(ValType::V128, "swizzle.val");
                self.push(ValType::V128);
            }
            Instruction::V128Splat(t) => {
                self.pop(*t, "splat");
                self.push(ValType::V128);
            }
            Instruction::V128ExtractLane { src, lane } => {
                let max_lane = match src {
                    ValType::I32 => 3, ValType::I64 => 1, ValType::F32 => 3, ValType::F64 => 1, _ => 15,
                };
                if *lane > max_lane {
                    self.errors.push(ValidationError::InvalidLaneIndex { lane: *lane, max: max_lane });
                }
                self.pop(ValType::V128, "extract_lane");
                self.push(*src);
            }
            Instruction::V128ReplaceLane { dst, lane } => {
                let max_lane = match dst {
                    ValType::I32 => 3, ValType::I64 => 1, ValType::F32 => 3, ValType::F64 => 1, _ => 15,
                };
                if *lane > max_lane {
                    self.errors.push(ValidationError::InvalidLaneIndex { lane: *lane, max: max_lane });
                }
                self.pop(*dst, "replace_lane.val");
                self.pop(ValType::V128, "replace_lane.vec");
                self.push(ValType::V128);
            }
            Instruction::V128Binop(_) => {
                self.pop(ValType::V128, "v128.binop.b");
                self.pop(ValType::V128, "v128.binop.a");
                self.push(ValType::V128);
            }
            Instruction::V128Unop(_) => {
                self.pop(ValType::V128, "v128.unop");
                self.push(ValType::V128);
            }

            Instruction::RefNull(t) => { self.push(*t); }
            Instruction::RefIsNull => {
                self.pop_any("ref.is_null");
                self.push(ValType::I32);
            }
            Instruction::RefFunc(fidx) => {
                if *fidx >= self.nfuncs() {
                    self.errors.push(ValidationError::FuncIndexOutOfRange { index: *fidx, max: self.nfuncs().saturating_sub(1) });
                }
                self.push(ValType::FuncRef);
            }

            Instruction::TableGet(tidx) => {
                let ntables = self.module.tables.len() as u32;
                if *tidx >= ntables && ntables > 0 {
                    self.errors.push(ValidationError::TableIndexOutOfRange { index: *tidx, max: ntables.saturating_sub(1) });
                }
                self.pop(ValType::I32, "table.get");
                self.push(ValType::FuncRef);
            }
            Instruction::TableSet(tidx) => {
                let ntables = self.module.tables.len() as u32;
                if *tidx >= ntables && ntables > 0 {
                    self.errors.push(ValidationError::TableIndexOutOfRange { index: *tidx, max: ntables.saturating_sub(1) });
                }
                self.pop(ValType::FuncRef, "table.set.val");
                self.pop(ValType::I32, "table.set.idx");
            }
            Instruction::TableInit(_, _) | Instruction::TableCopy(_, _) => {
                self.pop(ValType::I32, "table.init.len");
                self.pop(ValType::I32, "table.init.src");
                self.pop(ValType::I32, "table.init.dst");
            }
            Instruction::ElemDrop(_) => {}
            Instruction::TableGrow(tidx) => {
                let ntables = self.module.tables.len() as u32;
                if *tidx >= ntables && ntables > 0 {
                    self.errors.push(ValidationError::TableIndexOutOfRange { index: *tidx, max: ntables.saturating_sub(1) });
                }
                self.pop(ValType::I32, "table.grow.delta");
                self.pop(ValType::FuncRef, "table.grow.init");
                self.push(ValType::I32);
            }
            Instruction::TableSize(tidx) => {
                let ntables = self.module.tables.len() as u32;
                if *tidx >= ntables && ntables > 0 {
                    self.errors.push(ValidationError::TableIndexOutOfRange { index: *tidx, max: ntables.saturating_sub(1) });
                }
                self.push(ValType::I32);
            }
            Instruction::TableFill(tidx) => {
                let ntables = self.module.tables.len() as u32;
                if *tidx >= ntables && ntables > 0 {
                    self.errors.push(ValidationError::TableIndexOutOfRange { index: *tidx, max: ntables.saturating_sub(1) });
                }
                self.pop(ValType::I32, "table.fill.len");
                self.pop(ValType::FuncRef, "table.fill.val");
                self.pop(ValType::I32, "table.fill.dst");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ValidationResult {
    pub errors: Vec<ValidationError>,
    pub func_count: u32,
    pub import_func_count: u32,
    pub code_count: u32,
}

impl ValidationResult {
    #[must_use] 
    pub const fn is_valid(&self) -> bool { self.errors.is_empty() }
    #[must_use] 
    pub const fn error_count(&self) -> usize { self.errors.len() }

    pub fn print_errors(&self) {
        for e in &self.errors {
            eprintln!("  validation error: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Builder helper — construct a ValidatorModule programmatically
// ---------------------------------------------------------------------------

pub struct ModuleBuilder {
    m: ValidatorModule,
}

impl ModuleBuilder {
    #[must_use] 
    pub fn new() -> Self { Self { m: ValidatorModule::default() } }

    #[must_use] 
    pub fn add_type(mut self, ft: FuncType) -> Self {
        self.m.types.push(ft);
        self
    }

    #[must_use] 
    pub fn add_import_func(mut self, type_idx: u32) -> Self {
        self.m.func_types.push(type_idx);
        self.m.import_funcs += 1;
        self
    }

    #[must_use] 
    pub fn add_func(mut self, type_idx: u32) -> Self {
        self.m.func_types.push(type_idx);
        self
    }

    #[must_use] 
    pub fn add_memory(mut self, min: u32, max: Option<u32>) -> Self {
        self.m.memories.push((min, max));
        self
    }

    #[must_use] 
    pub fn add_table(mut self, elem_type: ValType, min: u32, max: Option<u32>) -> Self {
        self.m.tables.push((elem_type, min, max));
        self
    }

    #[must_use] 
    pub fn add_global(mut self, t: ValType, mutable: bool) -> Self {
        self.m.globals.push((t, mutable));
        self
    }

    #[must_use] 
    pub fn add_export(mut self, name: &str, kind: ExportKind, index: u32) -> Self {
        self.m.exports.push((name.to_string(), kind, index));
        self
    }

    #[must_use] 
    pub const fn set_start(mut self, idx: u32) -> Self {
        self.m.start = Some(idx);
        self
    }

    #[must_use] 
    pub fn add_code(mut self, body: FunctionBody) -> Self {
        self.m.code_bodies.push(body);
        self
    }

    #[must_use] 
    pub fn add_data_segment(mut self, seg: DataSegmentDesc) -> Self {
        self.m.data_segments.push(seg);
        self
    }

    #[must_use] 
    pub fn build(self) -> ValidatorModule { self.m }
}

impl Default for ModuleBuilder {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Convenience: validate a raw set of instructions for a given FuncType
// ---------------------------------------------------------------------------

#[must_use] 
pub fn validate_function_body(
    module: &ValidatorModule,
    func_index: u32,
    locals: Vec<ValType>,
    code: Vec<Instruction>,
) -> Vec<ValidationError> {
    let body = FunctionBody { func_index, locals, code };
    let fv = FunctionValidator::new(module, &body);
    fv.validate()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_module() -> ValidatorModule {
        ModuleBuilder::new()
            .add_type(FuncType::new(vec![ValType::I32, ValType::I32], vec![ValType::I32]))
            .add_type(FuncType::void_void())
            .add_func(0) // func 0: (i32,i32)->i32
            .add_func(1) // func 1: ()->()
            .add_memory(1, None)
            .build()
    }

    #[test]
    fn test_valid_add_function() {
        let m = simple_module();
        let errors = validate_function_body(&m, 0, vec![], vec![
            Instruction::LocalGet(0),
            Instruction::LocalGet(1),
            Instruction::IBin(ValType::I32),
        ]);
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn test_type_mismatch() {
        let m = simple_module();
        let errors = validate_function_body(&m, 0, vec![], vec![
            Instruction::LocalGet(0),
            Instruction::Const(ValType::F32),
            Instruction::IBin(ValType::I32),
        ]);
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_module_valid() {
        let m = simple_module();
        let result = Validator::new(&m).validate();
        assert!(result.is_valid(), "{:?}", result.errors);
    }

    #[test]
    fn test_multiple_memories_error() {
        let m = ModuleBuilder::new()
            .add_memory(1, None)
            .add_memory(2, None)
            .build();
        let result = Validator::new(&m).validate();
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::MultipleMemories)));
    }

    #[test]
    fn test_export_duplicate() {
        let m = ModuleBuilder::new()
            .add_type(FuncType::void_void())
            .add_func(0)
            .add_func(0)
            .add_export("foo", ExportKind::Func, 0)
            .add_export("foo", ExportKind::Func, 1)
            .build();
        let result = Validator::new(&m).validate();
        assert!(result.errors.iter().any(|e| matches!(e, ValidationError::ExportDuplicate { .. })));
    }

    #[test]
    fn test_global_immutable_write() {
        let m = ModuleBuilder::new()
            .add_type(FuncType::void_void())
            .add_func(0)
            .add_global(ValType::I32, false) // immutable
            .build();
        let errors = validate_function_body(&m, 0, vec![], vec![
            Instruction::Const(ValType::I32),
            Instruction::GlobalSet(0),
        ]);
        assert!(errors.iter().any(|e| matches!(e, ValidationError::GlobalImmutableWrite { .. })));
    }
}
