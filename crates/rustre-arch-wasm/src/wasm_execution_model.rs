//! WebAssembly execution model: value stack simulation, frame stack, label stack
//! for structured control flow (block/loop/if), locals array, operand type
//! tracking, branch depth handling, and trap conditions.

use std::fmt;

use crate::wasm_type_system::WasmValType;

// ── WasmValue ─────────────────────────────────────────────────────────────────

/// A concrete runtime value on the Wasm operand stack.
#[derive(Debug, Clone, PartialEq)]
pub enum WasmValue {
    /// 32-bit integer.
    I32(i32),
    /// 64-bit integer.
    I64(i64),
    /// 32-bit float.
    F32(f32),
    /// 64-bit float.
    F64(f64),
    /// 128-bit SIMD vector (stored as raw u128).
    V128(u128),
    /// Function reference (index into function table, or null).
    FuncRef(Option<u32>),
    /// External reference (opaque host value index, or null).
    ExternRef(Option<u32>),
}

impl WasmValue {
    /// Return the `WasmValType` corresponding to this runtime value.
    #[must_use]
    pub const fn val_type(&self) -> WasmValType {
        match self {
            Self::I32(_) => WasmValType::I32,
            Self::I64(_) => WasmValType::I64,
            Self::F32(_) => WasmValType::F32,
            Self::F64(_) => WasmValType::F64,
            Self::V128(_) => WasmValType::V128,
            Self::FuncRef(_) => WasmValType::FuncRef,
            Self::ExternRef(_) => WasmValType::ExternRef,
        }
    }

    /// Return the default (zero/null) value for a `WasmValType`.
    #[must_use]
    pub const fn default_for(vt: WasmValType) -> Self {
        match vt {
            WasmValType::I32 => Self::I32(0),
            WasmValType::I64 => Self::I64(0),
            WasmValType::F32 => Self::F32(0.0),
            WasmValType::F64 => Self::F64(0.0),
            WasmValType::V128 => Self::V128(0),
            WasmValType::FuncRef => Self::FuncRef(None),
            WasmValType::ExternRef => Self::ExternRef(None),
        }
    }

    /// Try to unwrap as an i32.
    #[must_use]
    pub const fn as_i32(&self) -> Option<i32> {
        if let Self::I32(v) = self { Some(*v) } else { None }
    }

    /// Try to unwrap as an i64.
    #[must_use]
    pub const fn as_i64(&self) -> Option<i64> {
        if let Self::I64(v) = self { Some(*v) } else { None }
    }

    /// Try to unwrap as an f32.
    #[must_use]
    pub const fn as_f32(&self) -> Option<f32> {
        if let Self::F32(v) = self { Some(*v) } else { None }
    }

    /// Try to unwrap as an f64.
    #[must_use]
    pub const fn as_f64(&self) -> Option<f64> {
        if let Self::F64(v) = self { Some(*v) } else { None }
    }

    /// Return `true` if this is a null reference.
    #[must_use]
    pub const fn is_null_ref(&self) -> bool {
        matches!(self, Self::FuncRef(None) | Self::ExternRef(None))
    }
}

impl fmt::Display for WasmValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::I32(v) => write!(f, "i32:{v}"),
            Self::I64(v) => write!(f, "i64:{v}"),
            Self::F32(v) => write!(f, "f32:{v}"),
            Self::F64(v) => write!(f, "f64:{v}"),
            Self::V128(v) => write!(f, "v128:{v:#018x}"),
            Self::FuncRef(Some(idx)) => write!(f, "funcref:{idx}"),
            Self::FuncRef(None) => write!(f, "funcref:null"),
            Self::ExternRef(Some(idx)) => write!(f, "externref:{idx}"),
            Self::ExternRef(None) => write!(f, "externref:null"),
        }
    }
}

// ── WasmTrap ──────────────────────────────────────────────────────────────────

/// A WebAssembly trap condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasmTrap {
    /// Integer overflow during division.
    IntegerOverflow,
    /// Division or remainder by zero.
    DivisionByZero,
    /// Integer-to-float conversion out of range.
    InvalidConversionToInt,
    /// Null reference dereference.
    NullDereference,
    /// Out-of-bounds memory access.
    OutOfBoundsMemory { offset: u64, size: u32 },
    /// Out-of-bounds table access.
    OutOfBoundsTable { index: u32 },
    /// Indirect call type mismatch.
    IndirectCallTypeMismatch,
    /// Unreachable instruction executed.
    Unreachable,
    /// Stack overflow (too many nested calls).
    StackOverflow,
    /// Explicit trap from `memory.grow` failure or similar.
    Other(String),
}

impl fmt::Display for WasmTrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntegerOverflow => write!(f, "integer overflow"),
            Self::DivisionByZero => write!(f, "integer divide by zero"),
            Self::InvalidConversionToInt => write!(f, "invalid conversion to integer"),
            Self::NullDereference => write!(f, "null dereference"),
            Self::OutOfBoundsMemory { offset, size } => {
                write!(f, "out of bounds memory access: offset={offset} size={size}")
            }
            Self::OutOfBoundsTable { index } => {
                write!(f, "out of bounds table access: index={index}")
            }
            Self::IndirectCallTypeMismatch => write!(f, "indirect call type mismatch"),
            Self::Unreachable => write!(f, "unreachable"),
            Self::StackOverflow => write!(f, "call stack exhausted"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

// ── ExecStack (operand stack) ─────────────────────────────────────────────────

/// The WebAssembly operand (value) stack used during execution.
///
/// Tracks both the runtime values and their types for validation.
#[derive(Debug, Clone, Default)]
pub struct ExecStack {
    /// Stack of runtime values.
    values: Vec<WasmValue>,
    /// Maximum depth ever reached.
    max_depth: usize,
}

impl ExecStack {
    /// Create an empty operand stack.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a value onto the stack.
    pub fn push(&mut self, value: WasmValue) {
        self.values.push(value);
        if self.values.len() > self.max_depth {
            self.max_depth = self.values.len();
        }
    }

    /// Pop a value from the stack.
    ///
    /// Returns `Err(WasmTrap)` if the stack is empty.
    pub fn pop(&mut self) -> Result<WasmValue, WasmTrap> {
        self.values
            .pop()
            .ok_or(WasmTrap::Other("stack underflow".into()))
    }

    /// Pop a value of a specific expected type.
    ///
    /// Returns `Err` if the stack is empty or the type does not match.
    pub fn pop_typed(&mut self, expected: WasmValType) -> Result<WasmValue, WasmTrap> {
        let v = self.pop()?;
        if v.val_type() != expected {
            return Err(WasmTrap::Other(format!(
                "type mismatch: expected {expected}, got {}",
                v.val_type()
            )));
        }
        Ok(v)
    }

    /// Peek at the top value without consuming it.
    #[must_use]
    pub fn peek(&self) -> Option<&WasmValue> {
        self.values.last()
    }

    /// Current stack depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.values.len()
    }

    /// Maximum depth ever reached.
    #[must_use]
    pub const fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// Return `true` when the stack is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Truncate the stack to `depth` values (discarding the top).
    pub fn truncate(&mut self, depth: usize) {
        self.values.truncate(depth);
    }

    /// Return a slice of all values, bottom first.
    #[must_use]
    pub fn as_slice(&self) -> &[WasmValue] {
        &self.values
    }

    /// Type sequence from bottom to top.
    #[must_use]
    pub fn type_stack(&self) -> Vec<WasmValType> {
        self.values.iter().map(WasmValue::val_type).collect()
    }
}

// ── LabelKind / Label ─────────────────────────────────────────────────────────

/// The kind of structured control flow construct that opened a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelKind {
    /// `block` — branch target is the *end* of the block.
    Block,
    /// `loop` — branch target is the *beginning* of the loop.
    Loop,
    /// `if` — branch target is `else` (or end if no else).
    If,
    /// Function body implicit label.
    Function,
}

/// An entry on the label stack, representing one level of structured control.
#[derive(Debug, Clone)]
pub struct Label {
    /// Kind of construct.
    pub kind: LabelKind,
    /// Stack depth when this label was entered (for branch unwinding).
    pub stack_depth: usize,
    /// Expected result arity of this block.
    pub result_arity: usize,
    /// Whether the block has been marked unreachable by a `br`/`return`.
    pub unreachable: bool,
    /// Byte offset of the instruction that opened this label (for debugging).
    pub open_offset: usize,
}

impl Label {
    /// Create a new label.
    #[must_use]
    pub const fn new(
        kind: LabelKind,
        stack_depth: usize,
        result_arity: usize,
        open_offset: usize,
    ) -> Self {
        Self {
            kind,
            stack_depth,
            result_arity,
            unreachable: false,
            open_offset,
        }
    }
}

// ── LabelStack ────────────────────────────────────────────────────────────────

/// Stack of labels for structured control flow in WebAssembly.
#[derive(Debug, Clone, Default)]
pub struct LabelStack {
    labels: Vec<Label>,
}

impl LabelStack {
    /// Create an empty label stack.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a new label.
    pub fn push(&mut self, label: Label) {
        self.labels.push(label);
    }

    /// Pop the innermost label.
    ///
    /// Returns `None` when the stack is empty.
    pub fn pop(&mut self) -> Option<Label> {
        self.labels.pop()
    }

    /// Look at the label at relative `depth` (0 = innermost).
    #[must_use]
    pub fn get(&self, depth: u32) -> Option<&Label> {
        let depth = depth as usize;
        if depth >= self.labels.len() {
            return None;
        }
        self.labels.get(self.labels.len() - 1 - depth)
    }

    /// Mutable access to the label at depth (0 = innermost).
    pub fn get_mut(&mut self, depth: u32) -> Option<&mut Label> {
        let depth = depth as usize;
        let len = self.labels.len();
        if depth >= len {
            return None;
        }
        self.labels.get_mut(len - 1 - depth)
    }

    /// Current nesting depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.labels.len()
    }

    /// Returns `true` when no labels are open.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    /// Mark the innermost label as unreachable (after `br`/`return`).
    pub fn mark_unreachable(&mut self) {
        if let Some(top) = self.labels.last_mut() {
            top.unreachable = true;
        }
    }

    /// Return `true` when the current code position is unreachable.
    #[must_use]
    pub fn is_unreachable(&self) -> bool {
        self.labels.last().map(|l| l.unreachable).unwrap_or(false)
    }
}

// ── CallFrame ─────────────────────────────────────────────────────────────────

/// A frame on the Wasm call stack representing one function activation.
#[derive(Debug, Clone)]
pub struct CallFrame {
    /// Index of the function being executed.
    pub func_index: u32,
    /// Local variables (includes parameters at the front).
    pub locals: Vec<WasmValue>,
    /// The program counter within the function's code (byte offset).
    pub pc: usize,
    /// Operand stack at the time of this call (for nested simulation).
    pub saved_stack_depth: usize,
    /// Number of expected return values.
    pub return_arity: usize,
}

impl CallFrame {
    /// Create a new call frame.
    #[must_use]
    pub const fn new(func_index: u32, locals: Vec<WasmValue>, return_arity: usize) -> Self {
        Self {
            func_index,
            locals,
            pc: 0,
            saved_stack_depth: 0,
            return_arity,
        }
    }

    /// Read a local variable.
    ///
    /// Returns `None` for out-of-bounds index.
    #[must_use]
    pub fn get_local(&self, index: u32) -> Option<&WasmValue> {
        self.locals.get(index as usize)
    }

    /// Write a local variable.
    ///
    /// Returns `false` when the index is out of bounds.
    pub fn set_local(&mut self, index: u32, value: WasmValue) -> bool {
        if let Some(slot) = self.locals.get_mut(index as usize) {
            *slot = value;
            true
        } else {
            false
        }
    }

    /// Number of locals in this frame.
    #[must_use]
    pub const fn local_count(&self) -> usize {
        self.locals.len()
    }
}

// ── FrameStack ────────────────────────────────────────────────────────────────

/// The call-frame stack for the Wasm execution model.
#[derive(Debug, Clone, Default)]
pub struct FrameStack {
    frames: Vec<CallFrame>,
    max_depth: usize,
}

impl FrameStack {
    /// Maximum call-frame nesting allowed before a stack-overflow trap.
    pub const MAX_DEPTH: usize = 512;

    /// Create an empty frame stack.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a new frame, returning `Err(WasmTrap::StackOverflow)` if too deep.
    pub fn push(&mut self, frame: CallFrame) -> Result<(), WasmTrap> {
        if self.frames.len() >= Self::MAX_DEPTH {
            return Err(WasmTrap::StackOverflow);
        }
        self.frames.push(frame);
        if self.frames.len() > self.max_depth {
            self.max_depth = self.frames.len();
        }
        Ok(())
    }

    /// Pop the current frame.
    pub fn pop(&mut self) -> Option<CallFrame> {
        self.frames.pop()
    }

    /// Return a reference to the current (innermost) frame.
    #[must_use]
    pub fn current(&self) -> Option<&CallFrame> {
        self.frames.last()
    }

    /// Return a mutable reference to the current frame.
    pub fn current_mut(&mut self) -> Option<&mut CallFrame> {
        self.frames.last_mut()
    }

    /// Current nesting depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.frames.len()
    }

    /// Maximum depth ever reached.
    #[must_use]
    pub const fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// Returns `true` when no frames are active.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

// ── WasmExecutor ──────────────────────────────────────────────────────────────

/// A simulator for the WebAssembly execution model.
///
/// Combines the operand stack, label stack, and frame stack into a single
/// structure suitable for abstract interpretation, validation, or lightweight
/// simulation.
///
/// This is intentionally a *type-level* simulator — it tracks value types on
/// the operand stack but does not execute memory operations against real memory.
#[derive(Debug, Clone)]
pub struct WasmExecutor {
    /// Operand stack.
    pub stack: ExecStack,
    /// Label stack (structured control flow).
    pub labels: LabelStack,
    /// Call-frame stack.
    pub frames: FrameStack,
    /// Number of instructions executed since creation.
    pub instr_count: u64,
    /// Whether the executor has encountered a trap.
    pub trap: Option<WasmTrap>,
}

impl WasmExecutor {
    /// Create a new executor with an empty state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stack: ExecStack::new(),
            labels: LabelStack::new(),
            frames: FrameStack::new(),
            instr_count: 0,
            trap: None,
        }
    }

    /// Push a value onto the operand stack.
    pub fn push_value(&mut self, v: WasmValue) {
        self.stack.push(v);
    }

    /// Pop a value from the operand stack, setting a trap on underflow.
    pub fn pop_value(&mut self) -> Option<WasmValue> {
        match self.stack.pop() {
            Ok(v) => Some(v),
            Err(t) => {
                self.trap = Some(t);
                None
            }
        }
    }

    /// Pop a value of an expected type, setting a trap on mismatch.
    pub fn pop_typed(&mut self, expected: WasmValType) -> Option<WasmValue> {
        match self.stack.pop_typed(expected) {
            Ok(v) => Some(v),
            Err(t) => {
                self.trap = Some(t);
                None
            }
        }
    }

    /// Enter a `block` construct.
    pub fn enter_block(&mut self, result_arity: usize, offset: usize) {
        let depth = self.stack.depth();
        self.labels
            .push(Label::new(LabelKind::Block, depth, result_arity, offset));
    }

    /// Enter a `loop` construct.
    pub fn enter_loop(&mut self, result_arity: usize, offset: usize) {
        let depth = self.stack.depth();
        self.labels
            .push(Label::new(LabelKind::Loop, depth, result_arity, offset));
    }

    /// Enter an `if` construct.
    pub fn enter_if(&mut self, result_arity: usize, offset: usize) {
        let depth = self.stack.depth();
        self.labels
            .push(Label::new(LabelKind::If, depth, result_arity, offset));
    }

    /// Exit the current structured control flow construct.
    pub fn exit_block(&mut self) -> Option<Label> {
        self.labels.pop()
    }

    /// Perform a branch to depth `depth`.
    ///
    /// Unwinds the stack to the label's recorded depth, preserving the
    /// label's result arity values on top.
    pub fn branch(&mut self, depth: u32) -> bool {
        let label = match self.labels.get(depth) {
            Some(l) => l.clone(),
            None => {
                self.trap = Some(WasmTrap::Other(format!(
                    "branch depth {depth} out of range"
                )));
                return false;
            }
        };
        let keep = label.result_arity;
        let target_depth = label.stack_depth;
        let current_depth = self.stack.depth();
        if current_depth >= keep && current_depth - keep >= target_depth {
            let save: Vec<WasmValue> = (0..keep)
                .filter_map(|_| self.stack.pop().ok())
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            self.stack.truncate(target_depth);
            for v in save {
                self.stack.push(v);
            }
        }
        self.labels.mark_unreachable();
        true
    }

    /// Perform an unreachable trap.
    pub fn trap_unreachable(&mut self) {
        self.trap = Some(WasmTrap::Unreachable);
    }

    /// Returns `true` when a trap has been set.
    #[must_use]
    pub const fn has_trap(&self) -> bool {
        self.trap.is_some()
    }

    /// Call a function by pushing a new frame.
    pub fn call_function(
        &mut self,
        func_index: u32,
        param_types: &[WasmValType],
        return_arity: usize,
    ) -> bool {
        let mut locals: Vec<WasmValue> = Vec::with_capacity(param_types.len());
        // Pop parameters in reverse order (stack top = last param).
        for &pt in param_types.iter().rev() {
            match self.stack.pop_typed(pt) {
                Ok(v) => locals.push(v),
                Err(t) => {
                    self.trap = Some(t);
                    return false;
                }
            }
        }
        locals.reverse();
        let saved = self.stack.depth();
        let mut frame = CallFrame::new(func_index, locals, return_arity);
        frame.saved_stack_depth = saved;
        match self.frames.push(frame) {
            Ok(()) => true,
            Err(t) => {
                self.trap = Some(t);
                false
            }
        }
    }

    /// Return from the current function.
    pub fn return_function(&mut self) -> Option<CallFrame> {
        let frame = self.frames.pop()?;
        // Keep the top `return_arity` values, restore stack to saved depth.
        let keep = frame.return_arity;
        let target = frame.saved_stack_depth;
        let current = self.stack.depth();
        if current >= keep {
            let save: Vec<WasmValue> = (0..keep)
                .filter_map(|_| self.stack.pop().ok())
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            self.stack.truncate(target);
            for v in save {
                self.stack.push(v);
            }
        }
        Some(frame)
    }

    /// Increment the instruction counter.
    pub const fn tick(&mut self) {
        self.instr_count += 1;
    }

    /// Reset executor state.
    pub fn reset(&mut self) {
        self.stack = ExecStack::new();
        self.labels = LabelStack::new();
        self.frames = FrameStack::new();
        self.instr_count = 0;
        self.trap = None;
    }
}

impl Default for WasmExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// ── BranchDepthResolver ───────────────────────────────────────────────────────

/// Utility for validating branch depths against the current label stack.
pub struct BranchDepthResolver<'a> {
    labels: &'a LabelStack,
}

impl<'a> BranchDepthResolver<'a> {
    /// Create a resolver backed by the given label stack.
    #[must_use]
    pub const fn new(labels: &'a LabelStack) -> Self {
        Self { labels }
    }

    /// Return `true` if `depth` is a valid branch depth.
    #[must_use]
    pub fn is_valid(&self, depth: u32) -> bool {
        (depth as usize) < self.labels.depth()
    }

    /// Return the result arity at branch depth `depth`.
    #[must_use]
    pub fn result_arity(&self, depth: u32) -> Option<usize> {
        self.labels.get(depth).map(|l| l.result_arity)
    }

    /// Return the label kind at branch depth `depth`.
    #[must_use]
    pub fn label_kind(&self, depth: u32) -> Option<LabelKind> {
        self.labels.get(depth).map(|l| l.kind)
    }

    /// Validate a `br_table` instruction's label vector.
    ///
    /// All labels must be valid and their result arities must be uniform.
    #[must_use]
    pub fn validate_br_table(&self, labels: &[u32]) -> bool {
        if labels.is_empty() {
            return false;
        }
        let first_arity = match self.result_arity(labels[0]) {
            Some(a) => a,
            None => return false,
        };
        labels.iter().all(|&d| {
            self.is_valid(d)
                && self.result_arity(d).map_or(false, |a| a == first_arity)
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_value_type() {
        assert_eq!(WasmValue::I32(42).val_type(), WasmValType::I32);
        assert_eq!(WasmValue::F64(1.0).val_type(), WasmValType::F64);
        assert_eq!(WasmValue::FuncRef(None).val_type(), WasmValType::FuncRef);
    }

    #[test]
    fn test_wasm_value_default_for() {
        assert_eq!(WasmValue::default_for(WasmValType::I32), WasmValue::I32(0));
        assert!(WasmValue::default_for(WasmValType::FuncRef).is_null_ref());
    }

    #[test]
    fn test_exec_stack_push_pop() {
        let mut s = ExecStack::new();
        s.push(WasmValue::I32(1));
        s.push(WasmValue::I64(2));
        assert_eq!(s.depth(), 2);
        assert_eq!(s.pop().unwrap(), WasmValue::I64(2));
        assert_eq!(s.depth(), 1);
    }

    #[test]
    fn test_exec_stack_underflow() {
        let mut s = ExecStack::new();
        assert!(s.pop().is_err());
    }

    #[test]
    fn test_exec_stack_pop_typed_mismatch() {
        let mut s = ExecStack::new();
        s.push(WasmValue::I32(1));
        assert!(s.pop_typed(WasmValType::F32).is_err());
    }

    #[test]
    fn test_exec_stack_max_depth() {
        let mut s = ExecStack::new();
        for i in 0..10 {
            s.push(WasmValue::I32(i));
        }
        for _ in 0..5 {
            s.pop().unwrap();
        }
        assert_eq!(s.max_depth(), 10);
        assert_eq!(s.depth(), 5);
    }

    #[test]
    fn test_label_stack_depth() {
        let mut ls = LabelStack::new();
        ls.push(Label::new(LabelKind::Block, 0, 0, 0));
        ls.push(Label::new(LabelKind::Loop, 0, 1, 5));
        assert_eq!(ls.depth(), 2);
        assert_eq!(ls.get(0).unwrap().kind, LabelKind::Loop);
        assert_eq!(ls.get(1).unwrap().kind, LabelKind::Block);
    }

    #[test]
    fn test_label_stack_mark_unreachable() {
        let mut ls = LabelStack::new();
        ls.push(Label::new(LabelKind::Block, 0, 0, 0));
        assert!(!ls.is_unreachable());
        ls.mark_unreachable();
        assert!(ls.is_unreachable());
    }

    #[test]
    fn test_frame_stack_overflow() {
        let mut fs = FrameStack::new();
        let limit = FrameStack::MAX_DEPTH;
        for i in 0..limit {
            fs.push(CallFrame::new(i as u32, vec![], 0)).unwrap();
        }
        let result = fs.push(CallFrame::new(999, vec![], 0));
        assert!(matches!(result, Err(WasmTrap::StackOverflow)));
    }

    #[test]
    fn test_call_frame_locals() {
        let locals = vec![WasmValue::I32(10), WasmValue::F64(3.14)];
        let mut frame = CallFrame::new(1, locals, 0);
        assert_eq!(frame.get_local(0).unwrap().as_i32(), Some(10));
        frame.set_local(0, WasmValue::I32(99));
        assert_eq!(frame.get_local(0).unwrap().as_i32(), Some(99));
        assert!(!frame.set_local(5, WasmValue::I32(0)));
    }

    #[test]
    fn test_executor_push_pop() {
        let mut exec = WasmExecutor::new();
        exec.push_value(WasmValue::I32(7));
        exec.push_value(WasmValue::I64(99));
        exec.tick();
        exec.tick();
        assert_eq!(exec.instr_count, 2);
        let v = exec.pop_value().unwrap();
        assert_eq!(v.as_i64(), Some(99));
    }

    #[test]
    fn test_executor_branch_unwind() {
        let mut exec = WasmExecutor::new();
        exec.enter_block(1, 0);
        exec.push_value(WasmValue::I32(100));
        exec.push_value(WasmValue::I32(200));
        // Branch to depth 0 (the block), keeping 1 result.
        exec.branch(0);
        // Stack should have 1 value.
        assert_eq!(exec.stack.depth(), 1);
    }

    #[test]
    fn test_executor_trap_unreachable() {
        let mut exec = WasmExecutor::new();
        exec.trap_unreachable();
        assert!(exec.has_trap());
        assert_eq!(exec.trap, Some(WasmTrap::Unreachable));
    }

    #[test]
    fn test_executor_reset() {
        let mut exec = WasmExecutor::new();
        exec.push_value(WasmValue::I32(1));
        exec.instr_count = 100;
        exec.reset();
        assert!(exec.stack.is_empty());
        assert_eq!(exec.instr_count, 0);
        assert!(!exec.has_trap());
    }

    #[test]
    fn test_branch_depth_resolver() {
        let mut ls = LabelStack::new();
        ls.push(Label::new(LabelKind::Block, 0, 0, 0));
        ls.push(Label::new(LabelKind::Loop, 0, 1, 0));
        let r = BranchDepthResolver::new(&ls);
        assert!(r.is_valid(0));
        assert!(r.is_valid(1));
        assert!(!r.is_valid(2));
        assert_eq!(r.result_arity(0), Some(1));
        assert_eq!(r.result_arity(1), Some(0));
        assert_eq!(r.label_kind(0), Some(LabelKind::Loop));
    }

    #[test]
    fn test_wasm_trap_display() {
        assert_eq!(format!("{}", WasmTrap::DivisionByZero), "integer divide by zero");
        assert_eq!(
            format!("{}", WasmTrap::OutOfBoundsMemory { offset: 0x100, size: 4 }),
            "out of bounds memory access: offset=256 size=4"
        );
    }
}
