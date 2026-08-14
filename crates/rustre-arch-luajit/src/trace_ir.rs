//! `LuaJIT` trace IR (intermediate representation) types and printer.
//!
//! The `LuaJIT` JIT compiler compiles hot traces to an SSA-based IR before
//! emitting machine code.  This module defines:
//! - [`IrOp`]          — all 60+ trace IR opcodes
//! - [`IrType`]        — IR value types
//! - [`IrInstruction`] — one IR instruction (op + two operand refs + type)
//! - [`SideExit`]      — an exit from the trace back to the interpreter
//! - [`IrTrace`]       — a complete trace IR listing
//! - [`TraceIrPrinter`] — renders the trace to a human-readable listing

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write as _;

// ── IrType ────────────────────────────────────────────────────────────────────

/// IR value type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IrType {
    /// No type (e.g., NOP).
    Void,
    /// Any Lua value (tagged).
    Any,
    /// Boolean.
    Bool,
    /// Lua integer (`GCint`, maps to `int32_t` in `LuaJIT` 2.0, `int64_t` in 2.1).
    Int,
    /// Lua number (double).
    Num,
    /// Pointer-sized integer.
    PtrInt,
    /// Pointer.
    Ptr,
    /// String GC object pointer.
    Str,
    /// Table GC object pointer.
    Tab,
    /// Function / proto GC object pointer.
    Func,
    /// Userdata GC object pointer.
    Udata,
    /// Thread GC object pointer.
    Thread,
    /// Cdata (FFI).
    Cdata,
    /// `uint8_t`.
    U8,
    /// `int8_t`.
    I8,
    /// `uint16_t`.
    U16,
    /// `int16_t`.
    I16,
    /// `uint32_t`.
    U32,
    /// `int32_t`.
    I32,
    /// `uint64_t`.
    U64,
    /// `int64_t`.
    I64,
    /// `float`.
    F32,
    /// `float64` / `double`.
    F64,
}

impl IrType {
    #[must_use] 
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Void => "void",
            Self::Any => "any",
            Self::Bool => "bool",
            Self::Int => "int",
            Self::Num => "num",
            Self::PtrInt => "ptr_int",
            Self::Ptr => "ptr",
            Self::Str => "str",
            Self::Tab => "tab",
            Self::Func => "func",
            Self::Udata => "udata",
            Self::Thread => "thr",
            Self::Cdata => "cdata",
            Self::U8 => "u8",
            Self::I8 => "i8",
            Self::U16 => "u16",
            Self::I16 => "i16",
            Self::U32 => "u32",
            Self::I32 => "i32",
            Self::U64 => "u64",
            Self::I64 => "i64",
            Self::F32 => "f32",
            Self::F64 => "f64",
        }
    }
}

// ── IrRef ────────────────────────────────────────────────────────────────────

/// A reference to an IR instruction.
///
/// Value 0 means "no operand" / constant null.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IrRef(pub u32);

impl IrRef {
    /// The null / absent reference.
    pub const NONE: Self = Self(0);

    /// `true` if this is the null reference.
    #[must_use] 
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }

    /// `true` if this is a valid (non-null) reference.
    #[must_use] 
    pub const fn is_some(self) -> bool {
        self.0 != 0
    }
}

impl std::fmt::Display for IrRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_none() {
            write!(f, "none")
        } else {
            write!(f, "ir{}", self.0)
        }
    }
}

// ── IrOp ─────────────────────────────────────────────────────────────────────

/// All `LuaJIT` trace IR opcodes.
///
/// The names follow the `LuaJIT` source (`lj_ir.h`) as closely as possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IrOp {
    // ── Constants ─────────────────────────────────────────────────────────
    /// Load integer constant.
    Kint,
    /// Load 64-bit integer constant.
    Kint64,
    /// Load FP number constant.
    Knum,
    /// Load generic pointer constant.
    Kptr,
    /// Load GC object constant.
    Kgc,
    /// Load `nil` constant.
    Knil,
    /// Load boolean constant.
    Kpri,

    // ── Arithmetic ────────────────────────────────────────────────────────
    /// Integer / FP addition.
    Add,
    /// Integer / FP subtraction.
    Sub,
    /// Integer / FP multiplication.
    Mul,
    /// Integer / FP division.
    Div,
    /// Integer modulo.
    Mod,
    /// FP exponentiation / power.
    Pow,
    /// Negate.
    Neg,
    /// Absolute value.
    Abs,
    /// Square root.
    Sqrt,
    /// Floating-point floor.
    Floor,
    /// Floating-point ceiling.
    Ceil,
    /// Truncate to integer.
    Trunc,

    // ── Bitwise ──────────────────────────────────────────────────────────
    /// Bitwise AND.
    Band,
    /// Bitwise OR.
    Bor,
    /// Bitwise XOR.
    Bxor,
    /// Bitwise NOT.
    Bnot,
    /// Bit shift left.
    Bshl,
    /// Bit shift right (logical).
    Bshr,
    /// Bit shift right (arithmetic).
    Bsar,
    /// Bit rotate left.
    Brol,
    /// Bit rotate right.
    Bror,

    // ── Comparison ───────────────────────────────────────────────────────
    /// Less-than.
    Lt,
    /// Greater-than.
    Gt,
    /// Less-than-or-equal.
    Le,
    /// Greater-than-or-equal.
    Ge,
    /// Equal.
    Eq,
    /// Not-equal.
    Ne,
    /// Universal equality (handles nil/false).
    Eqp,
    /// Universal inequality.
    Nep,

    // ── Memory ───────────────────────────────────────────────────────────
    /// Load value from memory.
    Load,
    /// Store value to memory.
    Store,
    /// Store 8-bit value.
    Store8,
    /// Store 16-bit value.
    Store16,
    /// Fused load + conversion.
    Xload,
    /// Fused store + conversion.
    Xstore,
    /// Get table value by string key.
    TGet,
    /// Set table value by string key.
    TSet,
    /// Get table value by integer key.
    AGet,
    /// Set table value by integer key.
    ASet,
    /// Get table value by hash.
    HGet,
    /// Set table value by hash.
    HSet,
    /// New table allocation.
    TNew,

    // ── Type conversions ──────────────────────────────────────────────────
    /// Convert integer to FP number.
    Conv,
    /// Narrow (widen) integer type.
    Narrow,
    /// To string conversion.
    ToStr,

    // ── Calls ────────────────────────────────────────────────────────────
    /// Call a C function with one argument.
    Call,
    /// Call a C function, no return value.
    CallVoid,
    /// Call a Lua function.
    LuaCall,
    /// Tail call.
    TailCall,

    // ── Guards (side exits) ───────────────────────────────────────────────
    /// Guard: exit if condition is false.
    Guard,
    /// Guard: exit if not integer.
    GuardInt,
    /// Guard: exit if not float.
    GuardFloat,
    /// Guard: exit if not string.
    GuardStr,
    /// Guard: exit if not table.
    GuardTab,
    /// Guard: exit if pointer is nil.
    GuardNil,
    /// Guard: table is not modified.
    GuardNotMod,

    // ── Loop / control ────────────────────────────────────────────────────
    /// Loop back-edge (marks hot loop start).
    Loop,
    /// Phi node (for loop-variable SSA form).
    Phi,
    /// Rename (for SSA renaming across loop).
    Rename,
    /// No operation.
    Nop,
    /// Get base pointer of current Lua frame.
    Base,
    /// Load upvalue.
    UGet,
    /// Store upvalue.
    USet,
    /// Snapshot reference (for deoptimisation).
    Snap,

    // ── Misc ─────────────────────────────────────────────────────────────
    /// Fence (memory barrier).
    Fence,
    /// Get current Lua thread.
    LuaState,
    /// Type tag extraction.
    TypeTag,
    /// Unknown / custom opcode.
    Other(u8),
}

impl IrOp {
    /// Human-readable name.
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::Kint => "KINT",
            Self::Kint64 => "KINT64",
            Self::Knum => "KNUM",
            Self::Kptr => "KPTR",
            Self::Kgc => "KGC",
            Self::Knil => "KNIL",
            Self::Kpri => "KPRI",
            Self::Add => "ADD",
            Self::Sub => "SUB",
            Self::Mul => "MUL",
            Self::Div => "DIV",
            Self::Mod => "MOD",
            Self::Pow => "POW",
            Self::Neg => "NEG",
            Self::Abs => "ABS",
            Self::Sqrt => "SQRT",
            Self::Floor => "FLOOR",
            Self::Ceil => "CEIL",
            Self::Trunc => "TRUNC",
            Self::Band => "BAND",
            Self::Bor => "BOR",
            Self::Bxor => "BXOR",
            Self::Bnot => "BNOT",
            Self::Bshl => "BSHL",
            Self::Bshr => "BSHR",
            Self::Bsar => "BSAR",
            Self::Brol => "BROL",
            Self::Bror => "BROR",
            Self::Lt => "LT",
            Self::Gt => "GT",
            Self::Le => "LE",
            Self::Ge => "GE",
            Self::Eq => "EQ",
            Self::Ne => "NE",
            Self::Eqp => "EQP",
            Self::Nep => "NEP",
            Self::Load => "LOAD",
            Self::Store => "STORE",
            Self::Store8 => "STORE8",
            Self::Store16 => "STORE16",
            Self::Xload => "XLOAD",
            Self::Xstore => "XSTORE",
            Self::TGet => "TGET",
            Self::TSet => "TSET",
            Self::AGet => "AGET",
            Self::ASet => "ASET",
            Self::HGet => "HGET",
            Self::HSet => "HSET",
            Self::TNew => "TNEW",
            Self::Conv => "CONV",
            Self::Narrow => "NARROW",
            Self::ToStr => "TOSTR",
            Self::Call => "CALL",
            Self::CallVoid => "CALLV",
            Self::LuaCall => "LCALL",
            Self::TailCall => "TCALL",
            Self::Guard => "GUARD",
            Self::GuardInt => "GINT",
            Self::GuardFloat => "GFLT",
            Self::GuardStr => "GSTR",
            Self::GuardTab => "GTAB",
            Self::GuardNil => "GNIL",
            Self::GuardNotMod => "GNMOD",
            Self::Loop => "LOOP",
            Self::Phi => "PHI",
            Self::Rename => "RENAME",
            Self::Nop => "NOP",
            Self::Base => "BASE",
            Self::UGet => "UGET",
            Self::USet => "USET",
            Self::Snap => "SNAP",
            Self::Fence => "FENCE",
            Self::LuaState => "LSTATE",
            Self::TypeTag => "TTAG",
            Self::Other(_) => "?OP",
        }
    }

    /// `true` if this op produces a value.
    #[must_use] 
    pub const fn has_result(self) -> bool {
        !matches!(
            self,
            Self::Store
                | Self::Store8
                | Self::Store16
                | Self::Xstore
                | Self::TSet
                | Self::ASet
                | Self::HSet
                | Self::USet
                | Self::CallVoid
                | Self::Guard
                | Self::GuardInt
                | Self::GuardFloat
                | Self::GuardStr
                | Self::GuardTab
                | Self::GuardNil
                | Self::GuardNotMod
                | Self::Nop
                | Self::Snap
                | Self::Fence
                | Self::Loop
        )
    }

    /// `true` if this op is a guard that may cause a side exit.
    #[must_use] 
    pub const fn is_guard(self) -> bool {
        matches!(
            self,
            Self::Guard
                | Self::GuardInt
                | Self::GuardFloat
                | Self::GuardStr
                | Self::GuardTab
                | Self::GuardNil
                | Self::GuardNotMod
        )
    }

    /// `true` if this op is a constant load.
    #[must_use] 
    pub const fn is_const(self) -> bool {
        matches!(
            self,
            Self::Kint
                | Self::Kint64
                | Self::Knum
                | Self::Kptr
                | Self::Kgc
                | Self::Knil
                | Self::Kpri
        )
    }

    /// `true` if this op reads from memory (heap or stack).
    #[must_use] 
    pub const fn is_load(self) -> bool {
        matches!(
            self,
            Self::Load | Self::Xload | Self::TGet | Self::AGet | Self::HGet | Self::UGet
        )
    }

    /// `true` if this op writes to memory.
    #[must_use] 
    pub const fn is_store(self) -> bool {
        matches!(
            self,
            Self::Store
                | Self::Store8
                | Self::Store16
                | Self::Xstore
                | Self::TSet
                | Self::ASet
                | Self::HSet
                | Self::USet
        )
    }
}

// ── IrInstruction ─────────────────────────────────────────────────────────────

/// A single trace IR instruction.
///
/// The IR is in SSA form: each instruction defines at most one value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrInstruction {
    /// Instruction index (0-based).
    pub index: u32,
    /// Opcode.
    pub op: IrOp,
    /// First operand reference (or `IrRef::NONE`).
    pub op1: IrRef,
    /// Second operand reference (or `IrRef::NONE`).
    pub op2: IrRef,
    /// Result type.
    pub ty: IrType,
    /// Optional numeric literal embedded in the instruction (for Kint etc.).
    pub literal: Option<i64>,
    /// Human-readable annotation (optional; used for debugging output).
    pub annotation: Option<String>,
}

impl IrInstruction {
    /// Create a new instruction.
    #[must_use] 
    pub const fn new(index: u32, op: IrOp, op1: IrRef, op2: IrRef, ty: IrType) -> Self {
        Self {
            index,
            op,
            op1,
            op2,
            ty,
            literal: None,
            annotation: None,
        }
    }

    /// Create a constant integer instruction.
    #[must_use] 
    pub const fn kint(index: u32, value: i64) -> Self {
        Self {
            index,
            op: IrOp::Kint,
            op1: IrRef::NONE,
            op2: IrRef::NONE,
            ty: IrType::Int,
            literal: Some(value),
            annotation: None,
        }
    }

    /// Create a constant FP instruction.
    #[must_use] 
    pub fn knum(index: u32, value_bits: u64) -> Self {
        let f = f64::from_bits(value_bits);
        let lit = value_bits.cast_signed();
        Self {
            index,
            op: IrOp::Knum,
            op1: IrRef::NONE,
            op2: IrRef::NONE,
            ty: IrType::Num,
            literal: Some(lit),
            annotation: Some(format!("{f:.6}")),
        }
    }

    /// Create a NOP.
    #[must_use] 
    pub const fn nop(index: u32) -> Self {
        Self::new(index, IrOp::Nop, IrRef::NONE, IrRef::NONE, IrType::Void)
    }

    /// Attach an annotation.
    #[must_use]
    pub fn with_annotation(mut self, ann: impl Into<String>) -> Self {
        self.annotation = Some(ann.into());
        self
    }

    /// Return `true` if this instruction has a result.
    #[must_use] 
    pub const fn has_result(&self) -> bool {
        self.op.has_result()
    }

    /// Return the definition reference for this instruction.
    #[must_use] 
    pub const fn def(&self) -> IrRef {
        if self.has_result() {
            IrRef(self.index + 1)
        } else {
            IrRef::NONE
        }
    }
}

// ── SideExit ──────────────────────────────────────────────────────────────────

/// A side exit from the trace back to the interpreter.
///
/// Side exits are triggered by guard failures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideExit {
    /// Index of the guard instruction that triggers this exit.
    pub guard_index: u32,
    /// Bytecode PC to resume at.
    pub resume_pc: u32,
    /// Saved Lua stack registers at exit time (slot → value type).
    pub live_regs: HashMap<u32, IrType>,
    /// Human-readable description.
    pub description: String,
}

impl SideExit {
    pub fn new(guard_index: u32, resume_pc: u32, description: impl Into<String>) -> Self {
        Self {
            guard_index,
            resume_pc,
            live_regs: HashMap::new(),
            description: description.into(),
        }
    }
}

// ── IrTrace ───────────────────────────────────────────────────────────────────

/// A complete trace IR listing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IrTrace {
    /// Trace number assigned by the JIT.
    pub trace_id: u32,
    /// The bytecode PC at the start of the trace.
    pub start_pc: u32,
    /// All IR instructions in order.
    pub instructions: Vec<IrInstruction>,
    /// Side exit map: guard instruction index → side exit record.
    pub side_exits: HashMap<u32, SideExit>,
    /// Whether the trace ends in a loop-back (is a loop trace).
    pub is_loop: bool,
}

impl IrTrace {
    /// Create an empty trace.
    #[must_use] 
    pub fn new(trace_id: u32, start_pc: u32) -> Self {
        Self {
            trace_id,
            start_pc,
            instructions: Vec::new(),
            side_exits: HashMap::new(),
            is_loop: false,
        }
    }

    /// Append an instruction, assigning it the next index.
    ///
    /// # Panics
    /// Panics if the instruction count exceeds `u32::MAX`.
    pub fn push(&mut self, mut instr: IrInstruction) -> IrRef {
        instr.index = u32::try_from(self.instructions.len()).expect("IR instruction count fits in u32");
        let r = instr.def();
        self.instructions.push(instr);
        r
    }

    /// Return the number of instructions.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Return `true` if the trace is empty.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Count instructions of a given opcode.
    #[must_use] 
    pub fn count_op(&self, op: IrOp) -> usize {
        self.instructions.iter().filter(|i| i.op == op).count()
    }

    /// Return all guard instructions.
    #[must_use] 
    pub fn guards(&self) -> Vec<&IrInstruction> {
        self.instructions
            .iter()
            .filter(|i| i.op.is_guard())
            .collect()
    }

    /// Return all constant-load instructions.
    #[must_use] 
    pub fn constants(&self) -> Vec<&IrInstruction> {
        self.instructions
            .iter()
            .filter(|i| i.op.is_const())
            .collect()
    }

    /// Return all memory-read instructions.
    #[must_use] 
    pub fn loads(&self) -> Vec<&IrInstruction> {
        self.instructions
            .iter()
            .filter(|i| i.op.is_load())
            .collect()
    }

    /// Return all memory-write instructions.
    #[must_use] 
    pub fn stores(&self) -> Vec<&IrInstruction> {
        self.instructions
            .iter()
            .filter(|i| i.op.is_store())
            .collect()
    }

    /// Add a side exit for a guard instruction.
    pub fn add_side_exit(&mut self, exit: SideExit) {
        self.side_exits.insert(exit.guard_index, exit);
    }
}

// ── TraceIrPrinter ────────────────────────────────────────────────────────────

/// Renders a [`IrTrace`] as a human-readable listing.
pub struct TraceIrPrinter;

impl TraceIrPrinter {
    /// Print a trace to a multi-line string.
    #[must_use] 
    pub fn print(trace: &IrTrace) -> String {
        let mut out = String::new();
        writeln!(out,
            "---- TRACE {} (start_pc={}, {}) ----",
            trace.trace_id,
            trace.start_pc,
            if trace.is_loop { "loop" } else { "function" },
        ).expect("writing to String is infallible");

        for instr in &trace.instructions {
            let def_str = if instr.has_result() {
                format!("ir{:04} ", instr.index + 1)
            } else {
                "       ".to_owned()
            };

            let op1_str = if instr.op1.is_some() {
                format!("{}", instr.op1)
            } else {
                String::new()
            };
            let op2_str = if instr.op2.is_some() {
                format!("{}", instr.op2)
            } else {
                String::new()
            };

            let operands = match (op1_str.as_str(), op2_str.as_str()) {
                ("", "") => String::new(),
                (a, "") => format!("  {a}"),
                (a, b) => format!("  {a}, {b}"),
            };

            let lit_str = instr.literal.map_or_else(String::new, |lit| format!("  #{lit}"));

            let ann_str = instr.annotation.as_ref().map_or_else(String::new, |ann| format!("  ; {ann}"));

            let exit_str = if instr.op.is_guard() {
                trace.side_exits.get(&instr.index).map_or_else(String::new, |exit| format!("  -> exit(pc={})", exit.resume_pc))
            } else {
                String::new()
            };

            writeln!(out,
                "  {def_str}= {:<8} {}{}{}{}{}",
                instr.op.name(),
                instr.ty.as_str(),
                operands,
                lit_str,
                ann_str,
                exit_str,
            ).expect("writing to String is infallible");
        }

        out.push_str("---- END TRACE ----\n");
        out
    }

    /// Print a compact summary of the trace.
    #[must_use] 
    pub fn summary(trace: &IrTrace) -> String {
        format!(
            "Trace {} | {} instrs | {} guards | {} side exits | {} consts | {}",
            trace.trace_id,
            trace.len(),
            trace.guards().len(),
            trace.side_exits.len(),
            trace.constants().len(),
            if trace.is_loop {
                "loop"
            } else {
                "straight-line"
            },
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_simple_trace() -> IrTrace {
        let mut t = IrTrace::new(1, 100);
        let k1 = t.push(IrInstruction::kint(0, 10));
        let k2 = t.push(IrInstruction::kint(0, 20));
        let _ = t.push(IrInstruction::new(0, IrOp::Add, k1, k2, IrType::Int));
        t
    }

    #[test]
    fn test_ir_trace_new() {
        let t = IrTrace::new(1, 0);
        assert!(t.is_empty());
        assert_eq!(t.trace_id, 1);
    }

    #[test]
    fn test_ir_trace_push() {
        let mut t = IrTrace::new(1, 0);
        let r = t.push(IrInstruction::kint(0, 42));
        assert!(r.is_some());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn test_ir_trace_kint() {
        let instr = IrInstruction::kint(0, 99);
        assert_eq!(instr.op, IrOp::Kint);
        assert_eq!(instr.literal, Some(99));
        assert_eq!(instr.ty, IrType::Int);
    }

    #[test]
    fn test_ir_trace_knum() {
        let instr = IrInstruction::knum(0, 3.14f64.to_bits());
        assert_eq!(instr.op, IrOp::Knum);
        assert_eq!(instr.ty, IrType::Num);
        assert!(instr.annotation.is_some());
    }

    #[test]
    fn test_ir_instruction_nop() {
        let n = IrInstruction::nop(0);
        assert_eq!(n.op, IrOp::Nop);
        assert!(!n.has_result());
    }

    #[test]
    fn test_ir_instruction_has_result() {
        let a = IrInstruction::new(0, IrOp::Add, IrRef::NONE, IrRef::NONE, IrType::Int);
        assert!(a.has_result());

        let s = IrInstruction::new(0, IrOp::Store, IrRef::NONE, IrRef::NONE, IrType::Void);
        assert!(!s.has_result());
    }

    #[test]
    fn test_ir_op_is_guard() {
        assert!(IrOp::Guard.is_guard());
        assert!(IrOp::GuardInt.is_guard());
        assert!(!IrOp::Add.is_guard());
    }

    #[test]
    fn test_ir_op_is_const() {
        assert!(IrOp::Kint.is_const());
        assert!(IrOp::Knum.is_const());
        assert!(!IrOp::Add.is_const());
    }

    #[test]
    fn test_ir_op_is_load() {
        assert!(IrOp::Load.is_load());
        assert!(IrOp::TGet.is_load());
        assert!(!IrOp::Store.is_load());
    }

    #[test]
    fn test_ir_op_is_store() {
        assert!(IrOp::Store.is_store());
        assert!(IrOp::HSet.is_store());
        assert!(!IrOp::Load.is_store());
    }

    #[test]
    fn test_ir_op_name_all_variants() {
        let ops = [
            IrOp::Kint,
            IrOp::Add,
            IrOp::Mul,
            IrOp::Guard,
            IrOp::Loop,
            IrOp::Phi,
            IrOp::Rename,
            IrOp::Nop,
            IrOp::TGet,
            IrOp::ASet,
        ];
        for op in ops {
            assert!(!op.name().is_empty(), "op {op:?} has empty name");
        }
    }

    #[test]
    fn test_ir_type_as_str() {
        assert_eq!(IrType::Int.as_str(), "int");
        assert_eq!(IrType::Num.as_str(), "num");
        assert_eq!(IrType::Str.as_str(), "str");
    }

    #[test]
    fn test_ir_ref_display_none() {
        assert_eq!(format!("{}", IrRef::NONE), "none");
    }

    #[test]
    fn test_ir_ref_display_some() {
        assert_eq!(format!("{}", IrRef(5)), "ir5");
    }

    #[test]
    fn test_ir_trace_count_op() {
        let t = make_simple_trace();
        assert_eq!(t.count_op(IrOp::Kint), 2);
        assert_eq!(t.count_op(IrOp::Add), 1);
    }

    #[test]
    fn test_ir_trace_constants() {
        let t = make_simple_trace();
        assert_eq!(t.constants().len(), 2);
    }

    #[test]
    fn test_ir_trace_guards_empty() {
        let t = make_simple_trace();
        assert!(t.guards().is_empty());
    }

    #[test]
    fn test_ir_trace_guards_present() {
        let mut t = IrTrace::new(2, 0);
        t.push(IrInstruction::new(
            0,
            IrOp::Guard,
            IrRef::NONE,
            IrRef::NONE,
            IrType::Bool,
        ));
        assert_eq!(t.guards().len(), 1);
    }

    #[test]
    fn test_side_exit() {
        let exit = SideExit::new(3, 200, "type guard failed");
        assert_eq!(exit.guard_index, 3);
        assert_eq!(exit.resume_pc, 200);
    }

    #[test]
    fn test_ir_trace_add_side_exit() {
        let mut t = IrTrace::new(1, 0);
        let g_ref = t.push(IrInstruction::new(
            0,
            IrOp::Guard,
            IrRef::NONE,
            IrRef::NONE,
            IrType::Bool,
        ));
        let guard_idx = g_ref.0.saturating_sub(1);
        t.add_side_exit(SideExit::new(guard_idx, 100, "guard exit"));
        assert_eq!(t.side_exits.len(), 1);
    }

    #[test]
    fn test_trace_ir_printer_output() {
        let t = make_simple_trace();
        let s = TraceIrPrinter::print(&t);
        assert!(s.contains("TRACE 1"), "output: {s}");
        assert!(s.contains("KINT"), "output: {s}");
        assert!(s.contains("ADD"), "output: {s}");
    }

    #[test]
    fn test_trace_ir_printer_summary() {
        let t = make_simple_trace();
        let s = TraceIrPrinter::summary(&t);
        assert!(s.contains("Trace 1"), "summary: {s}");
    }

    #[test]
    fn test_ir_instruction_with_annotation() {
        let i = IrInstruction::kint(0, 7).with_annotation("loop counter");
        assert_eq!(i.annotation.as_deref(), Some("loop counter"));
    }

    #[test]
    fn test_ir_trace_is_loop_flag() {
        let mut t = IrTrace::new(1, 0);
        t.is_loop = true;
        assert!(t.is_loop);
    }
}
