//! `LuaJIT` trace IR: opcodes, types, references, constants, instructions.

// â”€â”€ IR type system â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// `LuaJIT` IR value types.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum IrType {
    /// No value / void.
    None,
    /// Nil constant.
    Nil,
    /// Boolean.
    Bool,
    /// Lightweight userdata (integer-typed pointer).
    Lud,
    /// Interned string GC reference.
    Str,
    /// Lua table GC reference.
    Tab,
    /// Userdata GC reference.
    Udata,
    /// Function / closure GC reference.
    Func,
    /// Thread / coroutine GC reference.
    Thread,
    /// Any GC-managed reference (union of the above).
    Gcr,
    /// Pointer-sized integer (for C interop / FFI).
    Ptr,
    /// Native machine integer (32-bit).
    Int,
    /// Unsigned 32-bit integer.
    U32,
    /// 64-bit integer.
    I64,
    /// Unsigned 64-bit integer.
    U64,
    /// Double-precision float.
    Num,
    /// Float (32-bit) â€” primarily for FFI.
    Float,
    /// `LuaJIT` tagged value (`TValue`).
    Tagged,
}

impl IrType {
    /// True for GC-managed reference types.
    #[must_use]
    pub const fn is_gcref(self) -> bool {
        matches!(self,
            Self::Str | Self::Tab | Self::Udata | Self::Func |
            Self::Thread | Self::Gcr)
    }

    /// True for integer types (including pointer-sized).
    #[must_use]
    pub const fn is_integer(self) -> bool {
        matches!(self, Self::Int | Self::U32 | Self::I64 | Self::U64 | Self::Ptr | Self::Lud)
    }

    /// True for floating-point types.
    #[must_use]
    pub const fn is_float(self) -> bool {
        matches!(self, Self::Num | Self::Float)
    }

    /// Size in bytes (0 = unknown / variable).
    #[must_use]
    pub const fn byte_size(self) -> usize {
        match self {
            Self::Bool | Self::Nil | Self::None => 0,
            Self::Int | Self::U32 | Self::Float => 4,
            Self::Num | Self::I64 | Self::U64 | Self::Ptr |
            Self::Lud | Self::Gcr | Self::Str | Self::Tab |
            Self::Udata | Self::Func | Self::Thread | Self::Tagged => 8,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None | Self::Nil => "nil",
            Self::Bool   => "bool",
            Self::Lud    => "lud",
            Self::Str    => "str",
            Self::Tab    => "tab",
            Self::Udata  => "udata",
            Self::Func   => "func",
            Self::Thread => "thr",
            Self::Gcr    => "gcr",
            Self::Ptr    => "ptr",
            Self::Int    => "int",
            Self::U32    => "u32",
            Self::I64    => "i64",
            Self::U64    => "u64",
            Self::Num    => "num",
            Self::Float  => "flt",
            Self::Tagged => "tv",
        }
    }
}

impl core::fmt::Display for IrType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

// â”€â”€ IR reference â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A reference to an IR instruction or constant.
///
/// `LuaJIT` uses a 16-bit ref field.  Refs below ``IRBIAS`` point into the
/// constant pool (encoded as `IRBIAS - ref`); refs at or above ``IRBIAS`` are
/// instruction indices.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IrRef(pub u16);

/// The bias that separates constants (<IRBIAS) from instructions (>=`IRBIAS`).
pub const IR_BIAS: u16 = 0x8000;

impl IrRef {
    pub const NULL: Self = Self(0);

    /// True if this ref points to an instruction (not a constant).
    #[must_use]
    pub const fn is_instr(self) -> bool { self.0 >= IR_BIAS }

    /// True if this ref is a constant reference.
    #[must_use]
    pub const fn is_const(self) -> bool { self.0 < IR_BIAS && self.0 != 0 }

    /// Return the instruction index (0-based from `IRBIAS`).
    #[must_use]
    pub const fn instr_index(self) -> Option<u16> {
        if self.is_instr() { Some(self.0 - IR_BIAS) } else { None }
    }

    /// Return the constant index (`IRBIAS` - ref - 1).
    #[must_use]
    pub const fn const_index(self) -> Option<u16> {
        if self.is_const() { Some(IR_BIAS - self.0 - 1) } else { None }
    }
}

impl core::fmt::Debug for IrRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_instr() {
            write!(f, "IR#{}", self.0 - IR_BIAS)
        } else if self.is_const() {
            write!(f, "K#{}", IR_BIAS - self.0 - 1)
        } else {
            f.write_str("IR#NULL")
        }
    }
}

impl core::fmt::Display for IrRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

// â”€â”€ Constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// An IR constant value.
#[derive(Clone, Debug, PartialEq)]
pub enum IrConst {
    Nil,
    Bool(bool),
    Int(i32),
    U32(u32),
    I64(i64),
    U64(u64),
    Num(f64),
    /// Pointer / light-userdata (address as u64).
    Ptr(u64),
    /// String constant (stored as index into the prototype's string table).
    Str(u32),
}

impl IrConst {
    /// Return the IR type for this constant.
    #[must_use]
    pub const fn ir_type(&self) -> IrType {
        match self {
            Self::Nil    => IrType::Nil,
            Self::Bool(_)=> IrType::Bool,
            Self::Int(_) => IrType::Int,
            Self::U32(_) => IrType::U32,
            Self::I64(_) => IrType::I64,
            Self::U64(_) => IrType::U64,
            Self::Num(_) => IrType::Num,
            Self::Ptr(_) => IrType::Ptr,
            Self::Str(_) => IrType::Str,
        }
    }

    /// Try to convert to a 64-bit integer for arithmetic.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(i64::from(*v)),
            Self::I64(v) => Some(*v),
            Self::U32(v) => Some(i64::from(*v)),
            Self::U64(v) => Some((*v).cast_signed()),
            _ => None,
        }
    }
}

impl core::fmt::Display for IrConst {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Nil      => f.write_str("nil"),
            Self::Bool(b)  => write!(f, "{b}"),
            Self::Int(v)   => write!(f, "{v}i"),
            Self::U32(v)   => write!(f, "{v}u"),
            Self::I64(v)   => write!(f, "{v}i64"),
            Self::U64(v)   => write!(f, "{v}u64"),
            Self::Num(v)   => write!(f, "{v}"),
            Self::Ptr(p)   => write!(f, "0x{p:x}p"),
            Self::Str(i)   => write!(f, "str#{i}"),
        }
    }
}

// â”€â”€ IR opcode â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// `LuaJIT` trace IR opcodes (major subset used in analysis).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum IrOpcode {
    // Constants
    KNil, KInt, KNum, KGcr, KPtr, KI64,
    // Integer arithmetic
    Add, Sub, Mul, Div, Mod, Pow, Neg, Abs,
    // Integer bit ops
    Band, Bor, Bxor, Bshl, Bshr, Bsar, Bnot,
    // Floating-point
    FAdd, FSub, FMul, FDiv, FMod, FNeg, FAbs, FPow,
    // Conversions
    ConvNum, ConvInt, ConvI64, ConvU64,
    // Comparisons
    Eq, Ne, Lt, Ge, Le, Gt, EqN, NeN, LtN, GeN, LeN, GtN,
    // Memory / GC
    Alloc, NewStr, NewTab, NewArr,
    ALoad, AStore, HLoad, HStore, ULoad, UStore,
    // Control flow
    Loop, Guard, Phi, Snapshot, JmpFwd, JmpBack,
    // Calls
    Call, CCall, CallXs,
    // Upvalue / global
    UGet, USet, GGet, GSet,
    // Table access
    TGet, TSet, ARef, HRef,
    // Type checks
    TypeCheck, IsType, IsNil, IsFalse,
    // String ops
    StrLen, StrCoerce,
    // Math intrinsics
    MathSin, MathCos, MathSqrt, MathFloor, MathCeil,
    // Miscellaneous
    Nop, Ret,
}

impl IrOpcode {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::KNil    => "KNIL",   Self::KInt    => "KINT",
            Self::KNum    => "KNUM",   Self::KGcr    => "KGCR",
            Self::KPtr    => "KPTR",   Self::KI64    => "KI64",
            Self::Add     => "ADD",    Self::Sub     => "SUB",
            Self::Mul     => "MUL",    Self::Div     => "DIV",
            Self::Mod     => "MOD",    Self::Pow     => "POW",
            Self::Neg     => "NEG",    Self::Abs     => "ABS",
            Self::Band    => "BAND",   Self::Bor     => "BOR",
            Self::Bxor    => "BXOR",  Self::Bshl    => "BSHL",
            Self::Bshr    => "BSHR",  Self::Bsar    => "BSAR",
            Self::Bnot    => "BNOT",
            Self::FAdd    => "FADD",   Self::FSub    => "FSUB",
            Self::FMul    => "FMUL",   Self::FDiv    => "FDIV",
            Self::FMod    => "FMOD",   Self::FNeg    => "FNEG",
            Self::FAbs    => "FABS",   Self::FPow    => "FPOW",
            Self::ConvNum => "CONV.N", Self::ConvInt => "CONV.I",
            Self::ConvI64 => "CONV.I64", Self::ConvU64 => "CONV.U64",
            Self::Eq      => "EQ",     Self::Ne      => "NE",
            Self::Lt      => "LT",     Self::Ge      => "GE",
            Self::Le      => "LE",     Self::Gt      => "GT",
            Self::EqN     => "EQN",    Self::NeN     => "NEN",
            Self::LtN     => "LTN",    Self::GeN     => "GEN",
            Self::LeN     => "LEN",    Self::GtN     => "GTN",
            Self::Alloc   => "ALLOC",  Self::NewStr  => "NEWSTR",
            Self::NewTab  => "NEWTAB", Self::NewArr  => "NEWARR",
            Self::ALoad   => "ALOAD",  Self::AStore  => "ASTORE",
            Self::HLoad   => "HLOAD",  Self::HStore  => "HSTORE",
            Self::ULoad   => "ULOAD",  Self::UStore  => "USTORE",
            Self::Loop    => "LOOP",   Self::Guard   => "GUARD",
            Self::Phi     => "PHI",    Self::Snapshot=> "SNAP",
            Self::JmpFwd  => "JFWD",   Self::JmpBack => "JBACK",
            Self::Call    => "CALL",   Self::CCall   => "CCALL",
            Self::CallXs  => "CALLXS",
            Self::UGet    => "UGET",   Self::USet    => "USET",
            Self::GGet    => "GGET",   Self::GSet    => "GSET",
            Self::TGet    => "TGET",   Self::TSet    => "TSET",
            Self::ARef    => "AREF",   Self::HRef    => "HREF",
            Self::TypeCheck=>"TYCHK",  Self::IsType  => "ISTP",
            Self::IsNil   => "ISNIL",  Self::IsFalse => "ISF",
            Self::StrLen  => "STRLEN", Self::StrCoerce=>"STRCO",
            Self::MathSin => "SIN",    Self::MathCos => "COS",
            Self::MathSqrt=> "SQRT",   Self::MathFloor=>"FLOOR",
            Self::MathCeil=> "CEIL",
            Self::Nop     => "NOP",    Self::Ret     => "RET",
        }
    }

    /// True for constant-producing opcodes.
    #[must_use]
    pub const fn is_const(self) -> bool {
        matches!(self, Self::KNil | Self::KInt | Self::KNum |
                       Self::KGcr | Self::KPtr | Self::KI64)
    }

    /// True for comparison opcodes.
    #[must_use]
    pub const fn is_cmp(self) -> bool {
        matches!(self,
            Self::Eq | Self::Ne | Self::Lt | Self::Ge |
            Self::Le | Self::Gt | Self::EqN | Self::NeN |
            Self::LtN| Self::GeN| Self::LeN | Self::GtN
        )
    }

    /// True for arithmetic opcodes.
    #[must_use]
    pub const fn is_arith(self) -> bool {
        matches!(self,
            Self::Add | Self::Sub | Self::Mul | Self::Div |
            Self::Mod | Self::Pow | Self::Neg | Self::Abs |
            Self::FAdd| Self::FSub| Self::FMul| Self::FDiv |
            Self::FMod| Self::FNeg| Self::FAbs| Self::FPow
        )
    }

    /// True for memory load opcodes.
    #[must_use]
    pub const fn is_load(self) -> bool {
        matches!(self, Self::ALoad | Self::HLoad | Self::ULoad |
                       Self::TGet | Self::GGet | Self::UGet)
    }

    /// True for memory store opcodes.
    #[must_use]
    pub const fn is_store(self) -> bool {
        matches!(self, Self::AStore | Self::HStore | Self::UStore |
                       Self::TSet | Self::GSet | Self::USet)
    }
}

impl core::fmt::Display for IrOpcode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

// â”€â”€ IR instruction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A single `LuaJIT` trace IR instruction.
#[derive(Clone, Debug)]
pub struct IrInstr {
    /// Reference slot for this instruction (>= `IR_BIAS`).
    pub ref_: IrRef,
    /// Opcode.
    pub op: IrOpcode,
    /// Value type produced by this instruction.
    pub ty: IrType,
    /// First operand reference (or `IrRef::NULL`).
    pub op1: IrRef,
    /// Second operand reference (or `IrRef::NULL`).
    pub op2: IrRef,
    /// Optional third operand or auxiliary data.
    pub aux: u32,
    /// Optional constant folded from this instruction.
    pub folded: Option<IrConst>,
}

impl IrInstr {
    /// Create a new IR instruction with two operands.
    #[must_use]
    pub const fn new(ref_: IrRef, op: IrOpcode, ty: IrType, op1: IrRef, op2: IrRef) -> Self {
        Self { ref_, op, ty, op1, op2, aux: 0, folded: None }
    }

    /// Create a constant instruction.
    #[must_use]
    pub const fn const_instr(ref_: IrRef, c: IrConst) -> Self {
        let ty = c.ir_type();
        Self { ref_, op: IrOpcode::KInt, ty, op1: IrRef::NULL, op2: IrRef::NULL, aux: 0, folded: Some(c) }
    }

    /// True if this instruction produces a value.
    #[must_use]
    pub const fn has_result(&self) -> bool {
        !matches!(self.ty, IrType::None)
    }

    /// True if this instruction has side effects.
    #[must_use]
    pub const fn has_side_effects(&self) -> bool {
        self.op.is_store() || matches!(self.op,
            IrOpcode::Guard | IrOpcode::Snapshot | IrOpcode::Call |
            IrOpcode::CCall | IrOpcode::CallXs | IrOpcode::Ret |
            IrOpcode::NewStr | IrOpcode::NewTab | IrOpcode::NewArr | IrOpcode::Alloc
        )
    }

    /// Return the constant value if this instruction is a folded constant.
    #[must_use]
    pub const fn const_val(&self) -> Option<&IrConst> { self.folded.as_ref() }
}

impl core::fmt::Display for IrInstr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:<8} {:<6}  ", format!("{}", self.ref_), format!("{}", self.ty))?;
        write!(f, "{:<8}", self.op.name())?;
        if self.op1 != IrRef::NULL { write!(f, " {}", self.op1)?; }
        if self.op2 != IrRef::NULL { write!(f, " {}", self.op2)?; }
        if let Some(c) = &self.folded { write!(f, " [={c}]")?; }
        Ok(())
    }
}

// â”€â”€ Tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ir_type_sizes() {
        assert_eq!(IrType::Int.byte_size(), 4);
        assert_eq!(IrType::Num.byte_size(), 8);
        assert_eq!(IrType::Bool.byte_size(), 0);
    }

    #[test]
    fn ir_type_predicates() {
        assert!(IrType::Tab.is_gcref());
        assert!(!IrType::Int.is_gcref());
        assert!(IrType::Int.is_integer());
        assert!(IrType::Num.is_float());
    }

    #[test]
    fn irref_instr_vs_const() {
        let instr = IrRef(IR_BIAS + 5);
        assert!(instr.is_instr());
        assert_eq!(instr.instr_index(), Some(5));
        let cref = IrRef(IR_BIAS - 1);
        assert!(cref.is_const());
        assert_eq!(cref.const_index(), Some(0));
    }

    #[test]
    fn irref_null() {
        assert!(!IrRef::NULL.is_instr());
        assert!(!IrRef::NULL.is_const());
    }

    #[test]
    fn const_type() {
        assert_eq!(IrConst::Int(42).ir_type(), IrType::Int);
        assert_eq!(IrConst::Num(3.14).ir_type(), IrType::Num);
        assert_eq!(IrConst::Nil.ir_type(), IrType::Nil);
    }

    #[test]
    fn const_as_i64() {
        assert_eq!(IrConst::Int(-1).as_i64(), Some(-1));
        assert_eq!(IrConst::U32(100).as_i64(), Some(100));
        assert_eq!(IrConst::Num(1.0).as_i64(), None);
    }

    #[test]
    fn ir_instr_display() {
        let ref_ = IrRef(IR_BIAS);
        let i = IrInstr::new(ref_, IrOpcode::Add, IrType::Int, IrRef(IR_BIAS + 1), IrRef(IR_BIAS + 2));
        let s = format!("{i}");
        assert!(s.contains("ADD"));
        assert!(s.contains("int"));
    }

    #[test]
    fn ir_instr_const() {
        let ref_ = IrRef(IR_BIAS);
        let i = IrInstr::const_instr(ref_, IrConst::Int(99));
        assert!(i.const_val().is_some());
        assert_eq!(i.ty, IrType::Int);
    }

    #[test]
    fn opcodes_predicates() {
        assert!(IrOpcode::KInt.is_const());
        assert!(IrOpcode::Add.is_arith());
        assert!(IrOpcode::Eq.is_cmp());
        assert!(IrOpcode::HLoad.is_load());
        assert!(IrOpcode::AStore.is_store());
    }
}
