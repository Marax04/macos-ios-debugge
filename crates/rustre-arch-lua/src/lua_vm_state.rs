//! `lua_vm_state` — Lua VM runtime state model for static analysis.
//!
//! Provides [`LuaVmState`], [`LuaStack`], [`CallInfo`], and [`vm_step`] for
//! simulating Lua 5.1/5.4 bytecode execution within a reverse engineering context.
//!
//! # Relationship to `lua_vm_semantics`
//!
//! This module and [`crate::lua_vm_semantics`] both define a `LuaValue` type, but
//! they operate at different layers and serve different purposes:
//!
//! - **`lua_vm_state`** (this module): a lightweight *static-analysis interpreter*.
//!   Its `LuaValue` includes an `Unknown` variant (for values that cannot be
//!   determined statically) and an `Upvalue(u32)` reference, but has no GC model,
//!   no coroutine state, and no metamethod dispatch.  The [`vm_step`] function
//!   drives a simulated execution loop used for dataflow and constant propagation.
//!
//! - **`lua_vm_semantics`**: a complete *semantic model* of the Lua runtime.
//!   Its `LuaValue` includes `Userdata` and `Thread` variants, a full
//!   `LuaTable` with array/hash parts, metamethod dispatch via `LuaMetatable`,
//!   tri-colour GC (`GcSemantics`), and coroutine yield/resume (`YieldResume`).
//!   No bytecode interpreter is present; it models *what the VM does*, not *how
//!   to drive it instruction by instruction*.
//!
//! The two `LuaValue` enums are intentionally kept separate: merging them would
//! couple GC overhead into the static-analysis path and add `Unknown` noise to
//! the semantic model.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write;

// ─────────────────────────────────────────────────────────────────────────────
// LuaValue
// ─────────────────────────────────────────────────────────────────────────────

/// A simplified Lua runtime value for static analysis.
#[derive(Debug, Clone, PartialEq)]
pub enum LuaValue {
    Nil,
    Boolean(bool),
    Integer(i64),
    Float(f64),
    String(String),
    /// Table reference (numeric ID in analysis context).
    Table(u32),
    /// Function reference (proto index).
    Function(u32),
    /// Upvalue reference.
    Upvalue(u32),
    /// Unknown / unresolved value.
    Unknown,
}

impl LuaValue {
    /// Return `true` if this value is Lua-truthy.
    #[must_use]
    pub const fn is_truthy(&self) -> bool {
        !matches!(self, Self::Nil | Self::Boolean(false))
    }

    /// Return `true` if this is nil.
    #[must_use]
    pub const fn is_nil(&self) -> bool {
        matches!(self, Self::Nil)
    }

    /// Attempt to get an integer value.
    #[must_use]
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(i) => Some(*i),
            Self::Float(f) => crate::f64_to_exact_i64(*f),
            _ => None,
        }
    }

    /// Attempt to get a float value.
    #[must_use]
    pub fn as_float(&self) -> Option<f64> {
        match self {
            Self::Float(f) => Some(*f),
            Self::Integer(i) => Some(crate::lua_int_to_f64(*i)),
            _ => None,
        }
    }

    /// Type name string (mirrors Lua's `type()` function).
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Nil => "nil",
            Self::Boolean(_) => "boolean",
            Self::Integer(_) | Self::Float(_) => "number",
            Self::String(_) => "string",
            Self::Table(_) => "table",
            Self::Function(_) | Self::Upvalue(_) => "function",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for LuaValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nil => write!(f, "nil"),
            Self::Boolean(b) => write!(f, "{b}"),
            Self::Integer(i) => write!(f, "{i}"),
            Self::Float(n) => write!(f, "{n}"),
            Self::String(s) => write!(f, "\"{s}\""),
            Self::Table(id) => write!(f, "table:{id:#010x}"),
            Self::Function(id) => write!(f, "function:{id:#010x}"),
            Self::Upvalue(id) => write!(f, "upvalue:{id:#010x}"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaStack
// ─────────────────────────────────────────────────────────────────────────────

/// A Lua value stack (register file + value stack).
#[derive(Debug, Clone)]
pub struct LuaStack {
    /// Stack slots (register file).
    slots: Vec<LuaValue>,
    /// Base pointer for the current activation frame.
    base: usize,
}

impl LuaStack {
    /// Create an empty stack with `capacity` slots pre-allocated.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            slots: vec![LuaValue::Nil; capacity],
            base: 0,
        }
    }

    /// Return the current base pointer.
    #[must_use]
    pub const fn base(&self) -> usize {
        self.base
    }

    /// Set the base pointer.
    pub fn set_base(&mut self, base: usize) {
        if base > self.slots.len() {
            self.slots.resize(base + 64, LuaValue::Nil);
        }
        self.base = base;
    }

    /// Read register `reg` relative to the current base.
    #[must_use]
    pub fn get(&self, reg: usize) -> &LuaValue {
        let idx = self.base + reg;
        self.slots.get(idx).unwrap_or(&LuaValue::Nil)
    }

    /// Maximum absolute slot index accepted by [`set`] (prevents OOM on
    /// attacker-supplied register indices decoded from untrusted bytecode).
    pub const MAX_SLOT_INDEX: usize = 1 << 16; // 64 Ki slots

    /// Write a value to register `reg` relative to the current base.
    ///
    /// Writes beyond [`MAX_SLOT_INDEX`] are silently dropped: the static
    /// analysis model treats out-of-range registers as Unknown anyway.
    pub fn set(&mut self, reg: usize, value: LuaValue) {
        let idx = self.base.saturating_add(reg);
        if idx > Self::MAX_SLOT_INDEX {
            return; // deny OOM from malicious bytecode operands
        }
        if idx >= self.slots.len() {
            self.slots.resize(idx + 1, LuaValue::Nil);
        }
        self.slots[idx] = value;
    }

    /// Clear registers `from..=to` (set to nil).
    pub fn clear_range(&mut self, from: usize, to: usize) {
        for r in from..=to {
            self.set(r, LuaValue::Nil);
        }
    }

    /// Return the total number of slots.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.slots.len()
    }

    /// Return `true` if the stack is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Return all slots from the current base as a slice.
    #[must_use]
    pub fn frame_slots(&self) -> &[LuaValue] {
        if self.base < self.slots.len() {
            &self.slots[self.base..]
        } else {
            &[]
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Information about one activation record (call frame).
#[derive(Debug, Clone)]
pub struct CallInfo {
    /// Proto (function) index this frame is executing.
    pub proto_index: u32,
    /// Saved program counter (instruction index within the proto).
    pub saved_pc: usize,
    /// Stack base for this frame.
    pub frame_base: usize,
    /// Number of expected results (-1 = variable).
    pub n_results: i32,
    /// Whether this was a tail call.
    pub is_tail: bool,
    /// Depth of this call frame (0 = top-level).
    pub depth: usize,
}

impl CallInfo {
    /// Create a new call frame.
    #[must_use]
    pub const fn new(proto_index: u32, frame_base: usize, depth: usize) -> Self {
        Self {
            proto_index,
            saved_pc: 0,
            frame_base,
            n_results: -1,
            is_tail: false,
            depth,
        }
    }
}

impl fmt::Display for CallInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CallInfo(proto={}, pc={}, base={}, depth={})",
            self.proto_index, self.saved_pc, self.frame_base, self.depth
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmStepResult
// ─────────────────────────────────────────────────────────────────────────────

/// The result of a single VM step (instruction execution).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmStepResult {
    /// Normal execution; `pc` was advanced.
    Continue,
    /// A branch was taken; `pc` jumped to `target`.
    Branch { target: usize },
    /// A function call was initiated.
    Call { proto: u32, base: usize },
    /// A return statement was executed.
    Return { n_values: usize },
    /// The VM yielded.
    Yield,
    /// The instruction was not recognized or cannot be simulated.
    Unsupported,
}

// ─────────────────────────────────────────────────────────────────────────────
// vm_step
// ─────────────────────────────────────────────────────────────────────────────

/// Execute a single Lua 5.4 instruction word against `state`.
///
/// This is a simplified interpreter for static analysis — side effects like
/// table allocations are modelled symbolically.  Returns how the VM stepped.
#[must_use]
pub fn vm_step(state: &mut LuaVmState, instruction: u32) -> VmStepResult {
    let opcode = (instruction & 0x7F) as u8;
    let reg_a = ((instruction >> 7) & 0xFF) as usize;
    let reg_b = ((instruction >> 16) & 0xFF) as usize;
    let reg_c = ((instruction >> 24) & 0xFF) as usize;
    let bx = ((instruction >> 15) & 0x1FFFF) as usize;
    let sbx = i32::try_from(bx).unwrap_or(i32::MAX) - 0xFFFF;

    match opcode {
        // MOVE
        0 => {
            let v = state.stack.get(reg_b).clone();
            state.stack.set(reg_a, v);
            state.pc += 1;
            VmStepResult::Continue
        }
        // LOADI
        1 => {
            state.stack.set(reg_a, LuaValue::Integer(i64::from(sbx)));
            state.pc += 1;
            VmStepResult::Continue
        }
        // LOADK
        3 => {
            let v = state.get_constant(bx).clone();
            state.stack.set(reg_a, v);
            state.pc += 1;
            VmStepResult::Continue
        }
        // LOADFALSE
        5 => {
            state.stack.set(reg_a, LuaValue::Boolean(false));
            state.pc += 1;
            VmStepResult::Continue
        }
        // LOADTRUE
        7 => {
            state.stack.set(reg_a, LuaValue::Boolean(true));
            state.pc += 1;
            VmStepResult::Continue
        }
        // LOADNIL
        8 => {
            state.stack.clear_range(reg_a, reg_a + reg_b);
            state.pc += 1;
            VmStepResult::Continue
        }
        // Arithmetic, comparison and control-flow opcodes.
        _ => vm_step_alu_control(state, opcode, reg_a, reg_b, reg_c, bx, sbx),
    }
}

/// Execute the arithmetic, comparison and control-flow half of one Lua 5.4
/// instruction. Split out of `vm_step` so each half stays readable.
fn vm_step_alu_control(
    state: &mut LuaVmState,
    opcode: u8,
    reg_a: usize,
    reg_b: usize,
    reg_c: usize,
    bx: usize,
    sbx: i32,
) -> VmStepResult {
    match opcode {
        // ADD
        38 => {
            let lhs = state.stack.get(reg_b).as_float();
            let rhs = state.stack.get(reg_c).as_float();
            let result = match (lhs, rhs) {
                (Some(l), Some(r)) => LuaValue::Float(l + r),
                _ => LuaValue::Unknown,
            };
            state.stack.set(reg_a, result);
            state.pc += 1;
            VmStepResult::Continue
        }
        // SUB
        39 => {
            let lhs = state.stack.get(reg_b).as_float();
            let rhs = state.stack.get(reg_c).as_float();
            let result = match (lhs, rhs) {
                (Some(l), Some(r)) => LuaValue::Float(l - r),
                _ => LuaValue::Unknown,
            };
            state.stack.set(reg_a, result);
            state.pc += 1;
            VmStepResult::Continue
        }
        // MUL
        40 => {
            let lhs = state.stack.get(reg_b).as_float();
            let rhs = state.stack.get(reg_c).as_float();
            let result = match (lhs, rhs) {
                (Some(l), Some(r)) => LuaValue::Float(l * r),
                _ => LuaValue::Unknown,
            };
            state.stack.set(reg_a, result);
            state.pc += 1;
            VmStepResult::Continue
        }
        // NOT
        55 => {
            let truthy = state.stack.get(reg_b).is_truthy();
            state.stack.set(reg_a, LuaValue::Boolean(!truthy));
            state.pc += 1;
            VmStepResult::Continue
        }
        // JMP (isJ format — sJ encoded differently but we use sbx for simplicity)
        60 => {
            let offset = sbx;
            let raw = i64::try_from(state.pc).unwrap_or(i64::MAX) + 1 + i64::from(offset);
            let target = usize::try_from(raw).unwrap_or(0);
            state.pc = target;
            VmStepResult::Branch { target }
        }
        // EQ
        61 => {
            let lhs = state.stack.get(reg_a).clone();
            let rhs = state.stack.get(reg_b).clone();
            let eq = lhs == rhs;
            state.pc += if eq { 2 } else { 1 };
            VmStepResult::Continue
        }
        // CALL
        72 => {
            let func = state.stack.get(reg_a).clone();
            if let LuaValue::Function(proto) = func {
                let new_base = state.stack.base() + reg_a + 1;
                state.pc += 1;
                state.call_stack.push(CallInfo::new(proto, new_base, state.call_stack.len()));
                return VmStepResult::Call { proto, base: new_base };
            }
            state.pc += 1;
            VmStepResult::Unsupported
        }
        // RETURN / RETURN0 / RETURN1
        74..=76 => {
            let n = if opcode == 75 { 0 } else if opcode == 76 { 1 } else { reg_b };
            if let Some(_frame) = state.call_stack.pop() {
                // Restore pc from saved frame in reg_a real interpreter; here just mark.
            }
            VmStepResult::Return { n_values: n }
        }
        // CLOSURE
        82 => {
            state
                .stack
                .set(reg_a, LuaValue::Function(u32::try_from(bx).unwrap_or(u32::MAX)));
            state.pc += 1;
            VmStepResult::Continue
        }
        _ => {
            state.pc += 1;
            VmStepResult::Unsupported
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaVmState
// ─────────────────────────────────────────────────────────────────────────────

/// Complete Lua VM state for one execution context.
pub struct LuaVmState {
    /// The register file / value stack.
    pub stack: LuaStack,
    /// Program counter (instruction index).
    pub pc: usize,
    /// Active call stack.
    pub call_stack: Vec<CallInfo>,
    /// Constant pool (loaded per-proto).
    pub constants: Vec<LuaValue>,
    /// Upvalue table (flat for analysis).
    pub upvalues: Vec<LuaValue>,
    /// Global environment (name → value).
    pub globals: HashMap<String, LuaValue>,
    /// Number of instructions executed (for cycle limit).
    pub steps: u64,
}

impl LuaVmState {
    /// Create a new VM state with an empty register file.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stack: LuaStack::new(256),
            pc: 0,
            call_stack: Vec::new(),
            constants: Vec::new(),
            upvalues: Vec::new(),
            globals: HashMap::new(),
            steps: 0,
        }
    }

    /// Load constants for the current proto.
    pub fn load_constants(&mut self, constants: Vec<LuaValue>) {
        self.constants = constants;
    }

    /// Get a constant by index; returns `Unknown` if out of range.
    #[must_use]
    pub fn get_constant(&self, idx: usize) -> &LuaValue {
        self.constants.get(idx).unwrap_or(&LuaValue::Unknown)
    }

    /// Set a global variable.
    pub fn set_global(&mut self, name: impl Into<String>, value: LuaValue) {
        self.globals.insert(name.into(), value);
    }

    /// Get a global variable.
    #[must_use]
    pub fn get_global(&self, name: &str) -> &LuaValue {
        self.globals.get(name).unwrap_or(&LuaValue::Nil)
    }

    /// Execute `instructions` for at most `limit` steps.  Returns steps taken.
    pub fn run(&mut self, instructions: &[u32], limit: u64) -> u64 {
        let mut taken = 0u64;
        while self.pc < instructions.len() && taken < limit {
            let instr = instructions[self.pc];
            let result = vm_step(self, instr);
            taken += 1;
            self.steps += 1;
            match result {
                VmStepResult::Return { .. } | VmStepResult::Yield => break,
                _ => {}
            }
        }
        taken
    }

    /// Reset the VM to its initial state.
    pub fn reset(&mut self) {
        self.stack = LuaStack::new(256);
        self.pc = 0;
        self.call_stack.clear();
        self.constants.clear();
        self.upvalues.clear();
        self.globals.clear();
        self.steps = 0;
    }

    /// Return the current call depth.
    #[must_use]
    pub const fn call_depth(&self) -> usize {
        self.call_stack.len()
    }

    /// Dump the current top-of-stack frame values as a debug string.
    #[must_use]
    pub fn dump_frame(&self, n_regs: usize) -> String {
        let mut out = String::new();
        for i in 0..n_regs {
            let v = self.stack.get(i);
            let _ = writeln!(out, "  R[{i:2}] = {v}");
        }
        out
    }
}

impl Default for LuaVmState {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for LuaVmState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LuaVmState")
            .field("pc", &self.pc)
            .field("stack_size", &self.stack.len())
            .field("call_depth", &self.call_stack.len())
            .field("steps", &self.steps)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_abc(op: u8, a: u8, b: u8, c: u8) -> u32 {
        u32::from(op) | (u32::from(a) << 7) | (u32::from(b) << 16) | (u32::from(c) << 24)
    }

    fn encode_asbx(op: u8, a: u8, sbx: i32) -> u32 {
        let bx = (sbx + 0xFFFF).cast_unsigned();
        u32::from(op) | (u32::from(a) << 7) | (bx << 15)
    }

    #[test]
    fn lua_value_type_name() {
        assert_eq!(LuaValue::Nil.type_name(), "nil");
        assert_eq!(LuaValue::Integer(1).type_name(), "number");
        assert_eq!(LuaValue::String("x".into()).type_name(), "string");
    }

    #[test]
    fn lua_value_truthy() {
        assert!(LuaValue::Integer(0).is_truthy());
        assert!(!LuaValue::Nil.is_truthy());
        assert!(!LuaValue::Boolean(false).is_truthy());
        assert!(LuaValue::Boolean(true).is_truthy());
    }

    #[test]
    fn lua_value_as_integer() {
        assert_eq!(LuaValue::Integer(42).as_integer(), Some(42));
        assert_eq!(LuaValue::Float(3.0).as_integer(), Some(3));
        assert_eq!(LuaValue::Float(3.5).as_integer(), None);
        assert_eq!(LuaValue::Nil.as_integer(), None);
    }

    #[test]
    fn stack_get_set() {
        let mut stack = LuaStack::new(16);
        stack.set(0, LuaValue::Integer(99));
        assert_eq!(stack.get(0), &LuaValue::Integer(99));
        assert_eq!(stack.get(1), &LuaValue::Nil);
    }

    #[test]
    fn stack_clear_range() {
        let mut stack = LuaStack::new(8);
        stack.set(0, LuaValue::Integer(1));
        stack.set(1, LuaValue::Integer(2));
        stack.clear_range(0, 1);
        assert_eq!(stack.get(0), &LuaValue::Nil);
        assert_eq!(stack.get(1), &LuaValue::Nil);
    }

    #[test]
    fn stack_base_pointer() {
        let mut stack = LuaStack::new(16);
        stack.set_base(4);
        stack.set(0, LuaValue::Integer(7)); // absolute slot 4
        assert_eq!(stack.get(0), &LuaValue::Integer(7));
    }

    #[test]
    fn vm_step_move() {
        let mut state = LuaVmState::new();
        state.stack.set(1, LuaValue::Integer(42));
        let instr = encode_abc(0, 0, 1, 0); // MOVE R[0] R[1]
        let res = vm_step(&mut state, instr);
        assert_eq!(res, VmStepResult::Continue);
        assert_eq!(state.stack.get(0), &LuaValue::Integer(42));
        assert_eq!(state.pc, 1);
    }

    #[test]
    fn vm_step_loadi() {
        let mut state = LuaVmState::new();
        let instr = encode_asbx(1, 0, 100); // LOADI R[0] 100
        let _ = vm_step(&mut state, instr);
        // sBx = Bx - 0xFFFF; Bx = 100 + 0xFFFF
        // Just check pc advanced and that it's integer.
        assert_eq!(state.pc, 1);
        assert!(matches!(state.stack.get(0), LuaValue::Integer(_)));
    }

    #[test]
    fn vm_step_loadnil() {
        let mut state = LuaVmState::new();
        state.stack.set(0, LuaValue::Integer(1));
        state.stack.set(1, LuaValue::Integer(2));
        let instr = encode_abc(8, 0, 1, 0); // LOADNIL R[0] 1
        let _ = vm_step(&mut state, instr);
        assert_eq!(state.stack.get(0), &LuaValue::Nil);
        assert_eq!(state.stack.get(1), &LuaValue::Nil);
    }

    #[test]
    fn vm_step_loadfalse_true() {
        let mut state = LuaVmState::new();
        let _ = vm_step(&mut state, encode_abc(5, 0, 0, 0)); // LOADFALSE R[0]
        assert_eq!(state.stack.get(0), &LuaValue::Boolean(false));
        let _ = vm_step(&mut state, encode_abc(7, 1, 0, 0)); // LOADTRUE R[1]
        assert_eq!(state.stack.get(1), &LuaValue::Boolean(true));
    }

    #[test]
    fn vm_step_not() {
        let mut state = LuaVmState::new();
        state.stack.set(1, LuaValue::Boolean(true));
        let _ = vm_step(&mut state, encode_abc(55, 0, 1, 0)); // NOT R[0] R[1]
        assert_eq!(state.stack.get(0), &LuaValue::Boolean(false));
    }

    #[test]
    fn vm_step_add_integers() {
        let mut state = LuaVmState::new();
        state.stack.set(1, LuaValue::Float(3.0));
        state.stack.set(2, LuaValue::Float(4.0));
        let _ = vm_step(&mut state, encode_abc(38, 0, 1, 2)); // ADD R[0] R[1] R[2]
        assert_eq!(state.stack.get(0), &LuaValue::Float(7.0));
    }

    #[test]
    fn vm_step_add_unknown() {
        let mut state = LuaVmState::new();
        state.stack.set(1, LuaValue::Unknown);
        state.stack.set(2, LuaValue::Float(1.0));
        let _ = vm_step(&mut state, encode_abc(38, 0, 1, 2));
        assert_eq!(state.stack.get(0), &LuaValue::Unknown);
    }

    #[test]
    fn vm_step_return0() {
        let mut state = LuaVmState::new();
        let res = vm_step(&mut state, encode_abc(75, 0, 0, 0)); // RETURN0
        assert_eq!(res, VmStepResult::Return { n_values: 0 });
    }

    #[test]
    fn vm_step_closure() {
        let mut state = LuaVmState::new();
        // CLOSURE R[0] Bx=3  — encode_abc won't encode Bx; build manually
        let bx: u32 = 3;
        let instr: u32 = 0x52 | (bx << 15);
        let _ = vm_step(&mut state, instr);
        assert_eq!(state.stack.get(0), &LuaValue::Function(3));
    }

    #[test]
    fn vm_state_constants() {
        let mut state = LuaVmState::new();
        state.load_constants(vec![LuaValue::Integer(100), LuaValue::String("hello".into())]);
        assert_eq!(state.get_constant(0), &LuaValue::Integer(100));
        assert_eq!(state.get_constant(99), &LuaValue::Unknown);
    }

    #[test]
    fn vm_state_globals() {
        let mut state = LuaVmState::new();
        state.set_global("x", LuaValue::Integer(42));
        assert_eq!(state.get_global("x"), &LuaValue::Integer(42));
        assert_eq!(state.get_global("y"), &LuaValue::Nil);
    }

    #[test]
    fn vm_state_run_limit() {
        let mut state = LuaVmState::new();
        // infinite MOVE loop
        let prog: Vec<u32> = vec![encode_abc(0, 0, 0, 0); 1000]; // MOVE R[0] R[0]
        let steps = state.run(&prog, 10);
        assert_eq!(steps, 10);
    }

    #[test]
    fn vm_state_reset() {
        let mut state = LuaVmState::new();
        state.pc = 10;
        state.steps = 100;
        state.stack.set(0, LuaValue::Integer(1));
        state.reset();
        assert_eq!(state.pc, 0);
        assert_eq!(state.steps, 0);
        assert_eq!(state.stack.get(0), &LuaValue::Nil);
    }

    #[test]
    fn call_info_display() {
        let ci = CallInfo::new(1, 4, 2);
        let s = ci.to_string();
        assert!(s.contains("proto=1"));
        assert!(s.contains("depth=2"));
    }

    #[test]
    fn vm_state_debug() {
        let state = LuaVmState::new();
        let s = format!("{state:?}");
        assert!(s.contains("LuaVmState"));
    }

    #[test]
    fn vm_state_dump_frame() {
        let mut state = LuaVmState::new();
        state.stack.set(0, LuaValue::Integer(1));
        state.stack.set(1, LuaValue::String("test".into()));
        let dump = state.dump_frame(2);
        assert!(dump.contains("R[ 0]"));
        assert!(dump.contains("\"test\""));
    }
}
