//! `LuaJIT` 2.x bytecode opcode table: all ~92 opcodes, operand formats, stack deltas.

// ── Operand format ────────────────────────────────────────────────────────────

/// How the A, B, C / D fields of a `LuaJIT` instruction are interpreted.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum LjOperandFmt {
    /// ABC format: A = register/result, B = operand, C = operand.
    Abc,
    /// AD format: A = register/result, D = 16-bit unsigned immediate / slot.
    Ad,
    /// ADs format: A = register/result, D = 16-bit signed offset (D - BIAS).
    AdS,
    /// No operands (unused / NOP-like).
    None,
}

// ── Stack delta ───────────────────────────────────────────────────────────────

/// How an instruction changes the Lua stack top.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum LjStackDelta {
    /// Stack is unchanged.
    None,
    /// Stack top increases by a fixed amount.
    Push(i8),
    /// Stack top decreases by a fixed amount.
    Pop(i8),
    /// Effect depends on the B operand at runtime.
    Dynamic,
    /// Instruction terminates the current function / loop.
    Terminates,
}

// ── Branch direction ─────────────────────────────────────────────────────────

/// For conditional branch opcodes: expected branch direction for prediction.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum LjBranchDir {
    /// Not a branch.
    NoBranch,
    /// Forward (skip) branch.
    Forward,
    /// Backward (loop) branch.
    Backward,
    /// Either direction depending on operand.
    Either,
}

// ── The opcode enum ───────────────────────────────────────────────────────────

/// All `LuaJIT` 2.1 bytecode opcodes in canonical order.
/// The discriminant matches the byte value in the bytecode stream.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(u8)]
pub enum LjOpcode {
    // Comparison (A unused, D = register, C = register or type constant)
    IsLT  = 0x00,
    IsGE  = 0x01,
    IsLE  = 0x02,
    IsGT  = 0x03,
    IsEQ  = 0x04,
    IsNE  = 0x05,
    IsEQN = 0x06,
    IsNEN = 0x07,
    IsEQP = 0x08,
    IsNEP = 0x09,

    // Unary tests and copies
    IsT   = 0x0A,
    IsF   = 0x0B,
    IsType= 0x0C,
    IsNum = 0x0D,
    Mov   = 0x0E,
    Not   = 0x0F,
    Unm   = 0x10,
    Len   = 0x11,

    // Binary ops (A = dst, B = lhs, C = rhs)
    AddVN = 0x12,
    SubVN = 0x13,
    MulVN = 0x14,
    DivVN = 0x15,
    ModVN = 0x16,
    AddNV = 0x17,
    SubNV = 0x18,
    MulNV = 0x19,
    DivNV = 0x1A,
    ModNV = 0x1B,
    AddVV = 0x1C,
    SubVV = 0x1D,
    MulVV = 0x1E,
    DivVV = 0x1F,
    ModVV = 0x20,
    Pow   = 0x21,
    Cat   = 0x22,

    // Constant loads
    KStr  = 0x23,
    KCData= 0x24,
    KShort= 0x25,
    KNum  = 0x26,
    KPri  = 0x27,
    KNil  = 0x28,

    // Upvalue and function environment
    UGet  = 0x29,
    USet  = 0x2A,
    USetV = 0x2B,
    USetS = 0x2C,
    USetN = 0x2D,
    USetP = 0x2E,
    UClo  = 0x2F,
    FNUV  = 0x30,

    // Table ops
    TnEW  = 0x31,
    TDup  = 0x32,
    HDup  = 0x33,
    GGet  = 0x34,
    GSet  = 0x35,
    TGet  = 0x36,
    TSet  = 0x37,
    TGetB = 0x38,
    TSetB = 0x39,
    TGetV = 0x3A,
    TSetV = 0x3B,
    TSetM = 0x3C,
    TGetS = 0x3D,
    TSetS = 0x3E,

    // Calls and vararg handling
    CallM = 0x3F,
    Call  = 0x40,
    CallMT= 0x41,
    CallT = 0x42,
    IterC = 0x43,
    IterM = 0x44,

    // Returns
    RetM  = 0x45,
    Ret   = 0x46,
    Ret0  = 0x47,
    Ret1  = 0x48,

    // Loops and branches
    FLop  = 0x49,
    FLopN = 0x4A,
    FLopV = 0x4B,
    Loop  = 0x4C,
    JLoop = 0x4D,
    JFLop = 0x4E,
    JFLopN= 0x4F,
    JFLopV= 0x50,
    JIterC= 0x51,
    JIterM= 0x52,
    // Unconditional jump
    Jump  = 0x53,
    // Traced-loop variants
    JFord = 0x54,
    JFordN= 0x55,
    // Function headers
    FuncF = 0x56,
    FuncV = 0x57,
    FuncC = 0x58,
    FuncM = 0x59,
    // No-op
    Nop   = 0x5A,
    // Panic
    Panic = 0x5B,
}

impl LjOpcode {
    /// Decode a raw byte to an opcode.  Returns `None` for unknown values.
    #[must_use] 
    pub const fn from_byte(b: u8) -> Option<Self> {
        use LjOpcode::{IsLT, IsGE, IsLE, IsGT, IsEQ, IsNE, IsEQN, IsNEN, IsEQP, IsNEP, IsT, IsF, IsType, IsNum, Mov, Not, Unm, Len, AddVN, SubVN, MulVN, DivVN, ModVN, AddNV, SubNV, MulNV, DivNV, ModNV, AddVV, SubVV, MulVV, DivVV, ModVV, Pow, Cat, KStr, KCData, KShort, KNum, KPri, KNil, UGet, USet, USetV, USetS, USetN, USetP, UClo, FNUV, TnEW, TDup, HDup, GGet, GSet, TGet, TSet, TGetB, TSetB, TGetV, TSetV, TSetM, TGetS, TSetS, CallM, Call, CallMT, CallT, IterC, IterM, RetM, Ret, Ret0, Ret1, FLop, FLopN, FLopV, Loop, JLoop, JFLop, JFLopN, JFLopV, JIterC, JIterM, Jump, JFord, JFordN, FuncF, FuncV, FuncC, FuncM, Nop, Panic};
        Some(match b {
            0x00 => IsLT, 0x01 => IsGE, 0x02 => IsLE, 0x03 => IsGT,
            0x04 => IsEQ, 0x05 => IsNE, 0x06 => IsEQN, 0x07 => IsNEN,
            0x08 => IsEQP, 0x09 => IsNEP,
            0x0A => IsT, 0x0B => IsF, 0x0C => IsType, 0x0D => IsNum,
            0x0E => Mov, 0x0F => Not, 0x10 => Unm, 0x11 => Len,
            0x12 => AddVN, 0x13 => SubVN, 0x14 => MulVN, 0x15 => DivVN,
            0x16 => ModVN, 0x17 => AddNV, 0x18 => SubNV, 0x19 => MulNV,
            0x1A => DivNV, 0x1B => ModNV, 0x1C => AddVV, 0x1D => SubVV,
            0x1E => MulVV, 0x1F => DivVV, 0x20 => ModVV, 0x21 => Pow,
            0x22 => Cat,
            0x23 => KStr, 0x24 => KCData, 0x25 => KShort, 0x26 => KNum,
            0x27 => KPri, 0x28 => KNil,
            0x29 => UGet, 0x2A => USet, 0x2B => USetV, 0x2C => USetS,
            0x2D => USetN, 0x2E => USetP, 0x2F => UClo, 0x30 => FNUV,
            0x31 => TnEW, 0x32 => TDup, 0x33 => HDup, 0x34 => GGet,
            0x35 => GSet, 0x36 => TGet, 0x37 => TSet, 0x38 => TGetB,
            0x39 => TSetB, 0x3A => TGetV, 0x3B => TSetV, 0x3C => TSetM,
            0x3D => TGetS, 0x3E => TSetS,
            0x3F => CallM, 0x40 => Call, 0x41 => CallMT, 0x42 => CallT,
            0x43 => IterC, 0x44 => IterM,
            0x45 => RetM, 0x46 => Ret, 0x47 => Ret0, 0x48 => Ret1,
            0x49 => FLop, 0x4A => FLopN, 0x4B => FLopV, 0x4C => Loop,
            0x4D => JLoop, 0x4E => JFLop, 0x4F => JFLopN, 0x50 => JFLopV,
            0x51 => JIterC, 0x52 => JIterM,
            0x53 => Jump, 0x54 => JFord, 0x55 => JFordN,
            0x56 => FuncF, 0x57 => FuncV, 0x58 => FuncC, 0x59 => FuncM,
            0x5A => Nop, 0x5B => Panic,
            _ => return None,
        })
    }

    /// Mnemonic string (matches the `LuaJIT` source names).
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::IsLT   => "ISLT",   Self::IsGE   => "ISGE",
            Self::IsLE   => "ISLE",   Self::IsGT   => "ISGT",
            Self::IsEQ   => "ISEQ",   Self::IsNE   => "ISNE",
            Self::IsEQN  => "ISEQN",  Self::IsNEN  => "ISNEN",
            Self::IsEQP  => "ISEQP",  Self::IsNEP  => "ISNEP",
            Self::IsT    => "IST",    Self::IsF    => "ISF",
            Self::IsType => "ISTYPE", Self::IsNum  => "ISNUM",
            Self::Mov    => "MOV",    Self::Not    => "NOT",
            Self::Unm    => "UNM",    Self::Len    => "LEN",
            Self::AddVN  => "ADDVN",  Self::SubVN  => "SUBVN",
            Self::MulVN  => "MULVN",  Self::DivVN  => "DIVVN",
            Self::ModVN  => "MODVN",  Self::AddNV  => "ADDNV",
            Self::SubNV  => "SUBNV",  Self::MulNV  => "MULNV",
            Self::DivNV  => "DIVNV",  Self::ModNV  => "MODNV",
            Self::AddVV  => "ADDVV",  Self::SubVV  => "SUBVV",
            Self::MulVV  => "MULVV",  Self::DivVV  => "DIVVV",
            Self::ModVV  => "MODVV",  Self::Pow    => "POW",
            Self::Cat    => "CAT",
            Self::KStr   => "KSTR",   Self::KCData => "KCDATA",
            Self::KShort => "KSHORT", Self::KNum   => "KNUM",
            Self::KPri   => "KPRI",   Self::KNil   => "KNIL",
            Self::UGet   => "UGET",   Self::USet   => "USET",
            Self::USetV  => "USETV",  Self::USetS  => "USETS",
            Self::USetN  => "USETN",  Self::USetP  => "USETP",
            Self::UClo   => "UCLO",   Self::FNUV   => "FNUV",
            Self::TnEW   => "TNEW",   Self::TDup   => "TDUP",
            Self::HDup   => "HDUP",   Self::GGet   => "GGET",
            Self::GSet   => "GSET",   Self::TGet   => "TGET",
            Self::TSet   => "TSET",   Self::TGetB  => "TGETB",
            Self::TSetB  => "TSETB",  Self::TGetV  => "TGETV",
            Self::TSetV  => "TSETV",  Self::TSetM  => "TSETM",
            Self::TGetS  => "TGETS",  Self::TSetS  => "TSETS",
            Self::CallM  => "CALLM",  Self::Call   => "CALL",
            Self::CallMT => "CALLMT", Self::CallT  => "CALLT",
            Self::IterC  => "ITERC",  Self::IterM  => "ITERM",
            Self::RetM   => "RETM",   Self::Ret    => "RET",
            Self::Ret0   => "RET0",   Self::Ret1   => "RET1",
            Self::FLop   => "FORI",   Self::FLopN  => "FORL",
            Self::FLopV  => "FORV",   Self::Loop   => "LOOP",
            Self::JLoop  => "JLOOP",  Self::JFLop  => "JFORI",
            Self::JFLopN => "JFORL",  Self::JFLopV => "JFORV",
            Self::JIterC => "JITERC", Self::JIterM => "JITERM",
            Self::Jump   => "JMP",    Self::JFord  => "JFORD",
            Self::JFordN => "JFORDN",
            Self::FuncF  => "FUNCF",  Self::FuncV  => "FUNCV",
            Self::FuncC  => "FUNCC",  Self::FuncM  => "FUNCM",
            Self::Nop    => "NOP",    Self::Panic  => "PANIC",

        }
    }

    /// Operand format for this opcode.
    #[must_use] 
    pub const fn fmt(self) -> LjOperandFmt {
        match self {
            Self::KStr | Self::KCData | Self::KNum |
            Self::KShort | Self::KPri | Self::KNil |
            Self::UGet | Self::GGet | Self::GSet |
            Self::UClo | Self::TDup | Self::HDup |
            Self::Mov  | Self::Not  | Self::Unm |
            Self::Len  | Self::IsT  | Self::IsF |
            Self::IsNum| Self::Jump | Self::JLoop |
            Self::Loop | Self::FLop |
            Self::FLopV| Self::JFLop |
            Self::JFLopV | Self::JFord | Self::JFordN => LjOperandFmt::Ad,

            Self::FLopN | Self::JFLopN => LjOperandFmt::AdS,

            Self::Nop | Self::Panic |
            Self::Ret0 | Self::FuncF |
            Self::FuncV | Self::FuncC | Self::FuncM => LjOperandFmt::None,

            _ => LjOperandFmt::Abc,
        }
    }

    /// Stack delta for this opcode.
    #[must_use] 
    pub const fn stack_delta(self) -> LjStackDelta {
        match self {
            Self::Call | Self::CallM => LjStackDelta::Dynamic,
            Self::Ret | Self::Ret0 | Self::Ret1 | Self::RetM => LjStackDelta::Terminates,
            Self::KStr | Self::KNum | Self::KShort |
            Self::KPri | Self::KNil | Self::KCData |
            Self::Mov  | Self::Not  | Self::Unm | Self::Len |
            Self::AddVV | Self::SubVV | Self::MulVV | Self::DivVV |
            Self::ModVV | Self::Pow   | Self::AddVN | Self::SubVN |
            Self::MulVN | Self::DivVN | Self::ModVN | Self::AddNV |
            Self::SubNV | Self::MulNV | Self::DivNV | Self::ModNV => LjStackDelta::Push(1),
            _ => LjStackDelta::None,
        }
    }

    /// True if this opcode is a comparison (followed by a JMP).
    #[must_use] 
    pub const fn is_comparison(self) -> bool {
        matches!(self,
            Self::IsLT | Self::IsGE | Self::IsLE | Self::IsGT |
            Self::IsEQ | Self::IsNE | Self::IsEQN | Self::IsNEN |
            Self::IsEQP| Self::IsNEP | Self::IsT | Self::IsF
        )
    }

    /// True for CALL/CALLM/CALLT/CALLMT.
    #[must_use] 
    pub const fn is_call(self) -> bool {
        matches!(self, Self::Call | Self::CallM | Self::CallT | Self::CallMT)
    }

    /// True for RET/RETM/RET0/RET1.
    #[must_use] 
    pub const fn is_return(self) -> bool {
        matches!(self, Self::Ret | Self::RetM | Self::Ret0 | Self::Ret1)
    }

    /// True for loop opcodes (FORI/FORL/FORV and their JIT variants).
    #[must_use] 
    pub const fn is_loop(self) -> bool {
        matches!(self, Self::FLop | Self::FLopN | Self::FLopV |
                       Self::JFLop | Self::JFLopN | Self::JFLopV |
                       Self::Loop | Self::JLoop)
    }

    /// True for function header opcodes.
    #[must_use] 
    pub const fn is_funcheader(self) -> bool {
        matches!(self, Self::FuncF | Self::FuncV | Self::FuncC | Self::FuncM)
    }

    /// True for table access opcodes.
    #[must_use] 
    pub const fn is_table_access(self) -> bool {
        matches!(self, Self::TGet | Self::TSet | Self::TGetB |
                       Self::TSetB | Self::TGetV | Self::TSetV |
                       Self::TGetS | Self::TSetS | Self::TSetM |
                       Self::GGet | Self::GSet | Self::TnEW | Self::TDup)
    }
}

impl core::fmt::Display for LjOpcode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

// ── OpcodeInfo: compile-time metadata ────────────────────────────────────────

/// Static metadata record for a single opcode.
#[derive(Clone, Debug)]
pub struct OpcodeInfo {
    pub opcode: LjOpcode,
    pub name: &'static str,
    pub fmt: LjOperandFmt,
    pub stack_delta: LjStackDelta,
    pub branch_dir: LjBranchDir,
    pub has_side_effects: bool,
    pub description: &'static str,
}

impl OpcodeInfo {
    #[must_use] 
    pub const fn for_opcode(op: LjOpcode) -> Self {
        let branch_dir = branch_direction(op);
        Self {
            opcode: op,
            name: op.name(),
            fmt: op.fmt(),
            stack_delta: op.stack_delta(),
            branch_dir,
            has_side_effects: has_side_effects(op),
            description: opcode_description(op),
        }
    }
}

const fn branch_direction(op: LjOpcode) -> LjBranchDir {
    match op {
        LjOpcode::Jump => LjBranchDir::Either,
        LjOpcode::FLop | LjOpcode::JFLop |
        LjOpcode::FLopN | LjOpcode::JFLopN |
        LjOpcode::FLopV | LjOpcode::JFLopV |
        LjOpcode::Loop | LjOpcode::JLoop => LjBranchDir::Backward,
        op if op.is_comparison() => LjBranchDir::Forward,
        _ => LjBranchDir::NoBranch,
    }
}

const fn has_side_effects(op: LjOpcode) -> bool {
    op.is_call() || op.is_return() ||
    matches!(op,
        LjOpcode::USet | LjOpcode::USetV | LjOpcode::USetS | LjOpcode::USetN | LjOpcode::USetP |
        LjOpcode::GSet | LjOpcode::TSet | LjOpcode::TSetB | LjOpcode::TSetV |
        LjOpcode::TSetS | LjOpcode::TSetM | LjOpcode::Panic
    )
}

const fn opcode_description(op: LjOpcode) -> &'static str {
    match op {
        LjOpcode::IsLT  => "A = (B < D)",
        LjOpcode::IsGE  => "A = (B >= D)",
        LjOpcode::IsLE  => "A = (B <= D)",
        LjOpcode::IsGT  => "A = (B > D)",
        LjOpcode::IsEQ  => "A = (B == D)",
        LjOpcode::IsNE  => "A = (B ~= D)",
        LjOpcode::Mov   => "A = D",
        LjOpcode::Not   => "A = not D",
        LjOpcode::Unm   => "A = -D",
        LjOpcode::Len   => "A = #D",
        LjOpcode::AddVV => "A = B + C",
        LjOpcode::SubVV => "A = B - C",
        LjOpcode::MulVV => "A = B * C",
        LjOpcode::DivVV => "A = B / C",
        LjOpcode::ModVV => "A = B % C",
        LjOpcode::Pow   => "A = B ^ C",
        LjOpcode::Cat   => "A = B .. C",
        LjOpcode::KStr  => "A = stringconst[D]",
        LjOpcode::KNum  => "A = numconst[D]",
        LjOpcode::KShort=> "A = tonum(D)",
        LjOpcode::KPri  => "A = prim(D)",
        LjOpcode::KNil  => "A[A..D] = nil",
        LjOpcode::GGet  => "A = _G[const[D]]",
        LjOpcode::GSet  => "_G[const[D]] = A",
        LjOpcode::TGetV => "A = B[C]",
        LjOpcode::TSetV => "B[C] = A",
        LjOpcode::TGetS => "A = B.field",
        LjOpcode::TSetS => "B.field = A",
        LjOpcode::TGetB => "A = B[C]  (integer key)",
        LjOpcode::TSetB => "B[C] = A  (integer key)",
        LjOpcode::Call  => "A, ..., A+C-2 = A(A+1, ..., A+B-1)",
        LjOpcode::Ret   => "return A, ..., A+D-2",
        LjOpcode::Ret0  => "return",
        LjOpcode::Ret1  => "return A",
        LjOpcode::Jump  => "goto target",
        LjOpcode::Loop  => "loop header (nop at runtime)",
        LjOpcode::FLop  => "numeric for init (integer)",
        LjOpcode::FLopN => "numeric for step (integer)",
        LjOpcode::FLopV => "numeric for init (float)",
        LjOpcode::Nop   => "no operation",
        LjOpcode::Panic => "unreachable / panic",
        _ => "see LuaJIT source: lj_bc.h",
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_roundtrip() {
        for b in 0..=LjOpcode::Panic as u8 {
            let op = LjOpcode::from_byte(b).expect("all bytes 0..Panic valid");
            assert_eq!(op as u8, b);
        }
    }

    #[test]
    fn unknown_byte() {
        assert!(LjOpcode::from_byte(0xFF).is_none());
    }

    #[test]
    fn names_nonempty() {
        assert_eq!(LjOpcode::Nop.name(), "NOP");
        assert_eq!(LjOpcode::Jump.name(), "JMP");
        assert_eq!(LjOpcode::Call.name(), "CALL");
        assert_eq!(LjOpcode::Ret0.name(), "RET0");
    }

    #[test]
    fn is_call_return() {
        assert!(LjOpcode::Call.is_call());
        assert!(LjOpcode::Ret.is_return());
        assert!(!LjOpcode::Mov.is_call());
    }

    #[test]
    fn is_comparison() {
        assert!(LjOpcode::IsLT.is_comparison());
        assert!(!LjOpcode::Mov.is_comparison());
    }

    #[test]
    fn is_table_access() {
        assert!(LjOpcode::TGetV.is_table_access());
        assert!(LjOpcode::GSet.is_table_access());
        assert!(!LjOpcode::Call.is_table_access());
    }

    #[test]
    fn opcode_info() {
        let info = OpcodeInfo::for_opcode(LjOpcode::Call);
        assert!(info.has_side_effects);
        assert_eq!(info.name, "CALL");
    }

    #[test]
    fn funcheader() {
        assert!(LjOpcode::FuncF.is_funcheader());
        assert!(!LjOpcode::Nop.is_funcheader());
    }

    #[test]
    fn branch_direction_jump() {
        let info = OpcodeInfo::for_opcode(LjOpcode::Jump);
        assert_eq!(info.branch_dir, LjBranchDir::Either);
    }

    #[test]
    fn stack_delta_return() {
        assert!(matches!(LjOpcode::Ret.stack_delta(), LjStackDelta::Terminates));
    }
}
