//! `rustre-mobile-smali` — Smali assembly types, lexer, parser, disassembler, and printer.

pub mod assembler;
pub mod disassembler;
pub mod lexer;
pub mod parser;
pub mod printer;
pub mod smali_analysis;
pub mod smali_analyzer;
pub mod smali_assembler;
pub mod smali_optimizer;
pub mod smali_parser;
pub mod smali_patcher;
pub mod smali_type_resolver;
pub mod smali_annotation_parser;
pub mod smali_control_flow;
/// Real DEX → smali decoding (no synthesised classes).
pub mod dex_to_smali;

use std::fmt;

use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SmaliError {
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("invalid op: {0}")]
    InvalidOp(String),
    #[error("invalid register: {0}")]
    InvalidReg(u8),
}

// ─── SmaliReg ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SmaliReg {
    pub num: u8,
}

impl fmt::Display for SmaliReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.num < 64 {
            write!(f, "v{}", self.num)
        } else {
            write!(f, "p{}", self.num - 64)
        }
    }
}

// ─── SmaliOp ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmaliOp {
    Nop,
    Move,
    MoveWide,
    MoveObject,
    MoveResult,
    ReturnVoid,
    Return,
    Const4,
    Const16,
    Const,
    ConstString,
    Goto,
    IfEq,
    IfNe,
    IfLt,
    IfGe,
    IfGt,
    IfLe,
    IfEqz,
    IfNez,
    IGet,
    IPut,
    SGet,
    SPut,
    InvokeVirtual,
    InvokeSuper,
    InvokeDirect,
    InvokeStatic,
    InvokeInterface,
    NewInstance,
    ArrayLength,
    CheckCast,
    Other(String),
}

impl fmt::Display for SmaliOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nop => write!(f, "nop"),
            Self::Move => write!(f, "move"),
            Self::MoveWide => write!(f, "move-wide"),
            Self::MoveObject => write!(f, "move-object"),
            Self::MoveResult => write!(f, "move-result"),
            Self::ReturnVoid => write!(f, "return-void"),
            Self::Return => write!(f, "return"),
            Self::Const4 => write!(f, "const/4"),
            Self::Const16 => write!(f, "const/16"),
            Self::Const => write!(f, "const"),
            Self::ConstString => write!(f, "const-string"),
            Self::Goto => write!(f, "goto"),
            Self::IfEq => write!(f, "if-eq"),
            Self::IfNe => write!(f, "if-ne"),
            Self::IfLt => write!(f, "if-lt"),
            Self::IfGe => write!(f, "if-ge"),
            Self::IfGt => write!(f, "if-gt"),
            Self::IfLe => write!(f, "if-le"),
            Self::IfEqz => write!(f, "if-eqz"),
            Self::IfNez => write!(f, "if-nez"),
            Self::IGet => write!(f, "iget"),
            Self::IPut => write!(f, "iput"),
            Self::SGet => write!(f, "sget"),
            Self::SPut => write!(f, "sput"),
            Self::InvokeVirtual => write!(f, "invoke-virtual"),
            Self::InvokeSuper => write!(f, "invoke-super"),
            Self::InvokeDirect => write!(f, "invoke-direct"),
            Self::InvokeStatic => write!(f, "invoke-static"),
            Self::InvokeInterface => write!(f, "invoke-interface"),
            Self::NewInstance => write!(f, "new-instance"),
            Self::ArrayLength => write!(f, "array-length"),
            Self::CheckCast => write!(f, "check-cast"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

// ─── SmaliOperand ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmaliOperand {
    Reg(SmaliReg),
    Literal(i64),
    Str(String),
    TypeRef(String),
    FieldRef(String),
    MethodRef(String),
}

impl fmt::Display for SmaliOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reg(r) => write!(f, "{r}"),
            Self::Literal(n) => {
                if *n < 0 {
                    write!(f, "-{:#x}", i128::from(*n).unsigned_abs())
                } else {
                    write!(f, "{n:#x}")
                }
            }
            Self::Str(s) => write!(f, "\"{s}\""),
            Self::TypeRef(t) => write!(f, "{t}"),
            Self::FieldRef(field) => write!(f, "{field}"),
            Self::MethodRef(m) => write!(f, "{m}"),
        }
    }
}

// ─── SmaliInstr ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmaliInstr {
    pub op: SmaliOp,
    pub operands: Vec<SmaliOperand>,
    pub label: Option<String>,
}

impl SmaliInstr {
    /// Convert the instruction to its textual Smali representation.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        if let Some(lbl) = &self.label {
            s.push_str(lbl);
            s.push('\n');
        }
        s.push_str(&self.op.to_string());
        for (i, op) in self.operands.iter().enumerate() {
            if i == 0 {
                s.push(' ');
            } else {
                s.push_str(", ");
            }
            s.push_str(&op.to_string());
        }
        s
    }
}

// ─── SmaliAccess bitflags ─────────────────────────────────────────────────────

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SmaliAccess: u32 {
        const PUBLIC      = 0x0001;
        const PRIVATE     = 0x0002;
        const PROTECTED   = 0x0004;
        const STATIC      = 0x0008;
        const FINAL       = 0x0010;
        const CONSTRUCTOR = 0x0020;
        const NATIVE      = 0x0040;
        const ABSTRACT    = 0x0080;
    }
}

// ─── SmaliField ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmaliField {
    pub name: String,
    pub type_desc: String,
    pub access: SmaliAccess,
    pub initial: Option<i64>,
}

// ─── SmaliMethod ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmaliMethod {
    pub name: String,
    pub class: String,
    pub signature: String,
    pub access: SmaliAccess,
    pub registers: u8,
    pub instructions: Vec<SmaliInstr>,
}

impl SmaliMethod {
    /// Returns `true` if this method is a constructor (`<init>` or `<clinit>`).
    #[must_use]
    pub fn is_constructor(&self) -> bool {
        self.name == "<init>" || self.name == "<clinit>"
    }

    /// Returns the number of instructions.
    #[must_use]
    pub const fn instr_count(&self) -> usize {
        self.instructions.len()
    }
}

// ─── SmaliClass ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmaliClass {
    pub name: String,
    pub super_class: String,
    pub access: SmaliAccess,
    pub methods: Vec<SmaliMethod>,
    pub fields: Vec<SmaliField>,
    pub interfaces: Vec<String>,
}

impl SmaliClass {
    /// A class carrying only what a bare class *name* can justify: the name
    /// itself and the implicit `java.lang.Object` superclass.
    ///
    /// A name is not a program, so no methods, fields or interfaces are
    /// reported — inventing them is exactly the defect this replaces. To get
    /// the real members, decode real bytes with
    /// [`crate::dex_to_smali::class_from_dex_bytes`].
    #[must_use]
    pub fn mock(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            super_class: "Ljava/lang/Object;".to_string(),
            access: SmaliAccess::empty(),
            methods: Vec::new(),
            fields: Vec::new(),
            interfaces: Vec::new(),
        }
    }

    /// A hand-written class used as a fixture by this crate's own tests.
    ///
    /// It is *not* derived from any input and must never be reported as
    /// analysis of a real APK; it exists so the printer, analyser and
    /// assembler have a stable, known-shaped class to exercise.
    #[must_use]
    pub fn synthetic_fixture(name: impl Into<String>) -> Self {
        let class_name = name.into();
        Self {
            name: class_name.clone(),
            super_class: "Ljava/lang/Object;".to_string(),
            access: SmaliAccess::PUBLIC,
            methods: vec![
                SmaliMethod {
                    name: "<init>".to_string(),
                    class: class_name.clone(),
                    signature: "()V".to_string(),
                    access: SmaliAccess::PUBLIC | SmaliAccess::CONSTRUCTOR,
                    registers: 1,
                    instructions: vec![
                        SmaliInstr {
                            op: SmaliOp::InvokeDirect,
                            operands: vec![
                                SmaliOperand::Reg(SmaliReg { num: 64 }),
                                SmaliOperand::MethodRef(
                                    "Ljava/lang/Object;-><init>()V".to_string(),
                                ),
                            ],
                            label: None,
                        },
                        SmaliInstr {
                            op: SmaliOp::ReturnVoid,
                            operands: vec![],
                            label: None,
                        },
                    ],
                },
                SmaliMethod {
                    name: "execute".to_string(),
                    class: class_name.clone(),
                    signature: "()V".to_string(),
                    access: SmaliAccess::PUBLIC | SmaliAccess::STATIC,
                    registers: 2,
                    instructions: vec![
                        SmaliInstr {
                            op: SmaliOp::ConstString,
                            operands: vec![
                                SmaliOperand::Reg(SmaliReg { num: 0 }),
                                SmaliOperand::Str("hello".to_string()),
                            ],
                            label: None,
                        },
                        SmaliInstr {
                            op: SmaliOp::ReturnVoid,
                            operands: vec![],
                            label: None,
                        },
                    ],
                },
                SmaliMethod {
                    name: "nativeOp".to_string(),
                    class: class_name,
                    signature: "(I)I".to_string(),
                    access: SmaliAccess::PUBLIC | SmaliAccess::NATIVE,
                    registers: 0,
                    instructions: vec![],
                },
            ],
            fields: vec![SmaliField {
                name: "count".to_string(),
                type_desc: "I".to_string(),
                access: SmaliAccess::PRIVATE,
                initial: Some(0),
            }],
            interfaces: vec![],
        }
    }

    /// Find a method by name.
    #[must_use]
    pub fn find_method(&self, name: &str) -> Option<&SmaliMethod> {
        self.methods.iter().find(|m| m.name == name)
    }

    /// Return all static methods.
    #[must_use]
    pub fn static_methods(&self) -> Vec<&SmaliMethod> {
        self.methods
            .iter()
            .filter(|m| m.access.contains(SmaliAccess::STATIC))
            .collect()
    }
}

// ─── DalvikOpcode ─────────────────────────────────────────────────────────────

/// Comprehensive enumeration of the Dalvik bytecode instruction set.
/// Values correspond to the 8-bit opcode byte used in DEX bytecode.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DalvikOpcode {
    // 0x00–0x0d: Move / return / exception
    Nop = 0x00,
    Move = 0x01,
    MoveFrom16 = 0x02,
    Move16 = 0x03,
    MoveWide = 0x04,
    MoveWideFrom16 = 0x05,
    MoveWide16 = 0x06,
    MoveObject = 0x07,
    MoveObjectFrom16 = 0x08,
    MoveObject16 = 0x09,
    MoveResult = 0x0a,
    MoveResultWide = 0x0b,
    MoveResultObject = 0x0c,
    MoveException = 0x0d,
    // 0x0e–0x11: Return
    ReturnVoid = 0x0e,
    Return = 0x0f,
    ReturnWide = 0x10,
    ReturnObject = 0x11,
    // 0x12–0x1c: Constants
    Const4 = 0x12,
    Const16 = 0x13,
    Const = 0x14,
    ConstHigh16 = 0x15,
    ConstWide16 = 0x16,
    ConstWide32 = 0x17,
    ConstWide = 0x18,
    ConstWideHigh16 = 0x19,
    ConstString = 0x1a,
    ConstStringJumbo = 0x1b,
    ConstClass = 0x1c,
    // 0x1d–0x26: Monitors / casts / arrays
    MonitorEnter = 0x1d,
    MonitorExit = 0x1e,
    CheckCast = 0x1f,
    InstanceOf = 0x20,
    ArrayLength = 0x21,
    NewInstance = 0x22,
    NewArray = 0x23,
    FilledNewArray = 0x24,
    FilledNewArrayRange = 0x25,
    FillArrayData = 0x26,
    // 0x27–0x2c: Exceptions / goto / switch
    Throw = 0x27,
    Goto = 0x28,
    Goto16 = 0x29,
    Goto32 = 0x2a,
    PackedSwitch = 0x2b,
    SparseSwitch = 0x2c,
    // 0x2d–0x31: Comparisons
    CmplFloat = 0x2d,
    CmpgFloat = 0x2e,
    CmplDouble = 0x2f,
    CmpgDouble = 0x30,
    CmpLong = 0x31,
    // 0x32–0x3d: If
    IfEq = 0x32,
    IfNe = 0x33,
    IfLt = 0x34,
    IfGe = 0x35,
    IfGt = 0x36,
    IfLe = 0x37,
    IfEqz = 0x38,
    IfNez = 0x39,
    IfLtz = 0x3a,
    IfGez = 0x3b,
    IfGtz = 0x3c,
    IfLez = 0x3d,
    // 0x3e–0x43: unused
    Unused3e = 0x3e,
    Unused3f = 0x3f,
    Unused40 = 0x40,
    Unused41 = 0x41,
    Unused42 = 0x42,
    Unused43 = 0x43,
    // 0x44–0x51: aget/aput
    Aget = 0x44,
    AgetWide = 0x45,
    AgetObject = 0x46,
    AgetBoolean = 0x47,
    AgetByte = 0x48,
    AgetChar = 0x49,
    AgetShort = 0x4a,
    Aput = 0x4b,
    AputWide = 0x4c,
    AputObject = 0x4d,
    AputBoolean = 0x4e,
    AputByte = 0x4f,
    AputChar = 0x50,
    AputShort = 0x51,
    // 0x52–0x5f: iget/iput
    Iget = 0x52,
    IgetWide = 0x53,
    IgetObject = 0x54,
    IgetBoolean = 0x55,
    IgetByte = 0x56,
    IgetChar = 0x57,
    IgetShort = 0x58,
    Iput = 0x59,
    IputWide = 0x5a,
    IputObject = 0x5b,
    IputBoolean = 0x5c,
    IputByte = 0x5d,
    IputChar = 0x5e,
    IputShort = 0x5f,
    // 0x60–0x6d: sget/sput
    Sget = 0x60,
    SgetWide = 0x61,
    SgetObject = 0x62,
    SgetBoolean = 0x63,
    SgetByte = 0x64,
    SgetChar = 0x65,
    SgetShort = 0x66,
    Sput = 0x67,
    SputWide = 0x68,
    SputObject = 0x69,
    SputBoolean = 0x6a,
    SputByte = 0x6b,
    SputChar = 0x6c,
    SputShort = 0x6d,
    // 0x6e–0x72: invoke (non-range)
    InvokeVirtual = 0x6e,
    InvokeSuper = 0x6f,
    InvokeDirect = 0x70,
    InvokeStatic = 0x71,
    InvokeInterface = 0x72,
    // 0x73: unused
    Unused73 = 0x73,
    // 0x74–0x78: invoke (range)
    InvokeVirtualRange = 0x74,
    InvokeSuperRange = 0x75,
    InvokeDirectRange = 0x76,
    InvokeStaticRange = 0x77,
    InvokeInterfaceRange = 0x78,
    // 0x79–0x7a: unused
    Unused79 = 0x79,
    Unused7a = 0x7a,
    // 0x7b–0x8f: unary ops
    NegInt = 0x7b,
    NotInt = 0x7c,
    NegLong = 0x7d,
    NotLong = 0x7e,
    NegFloat = 0x7f,
    NegDouble = 0x80,
    IntToLong = 0x81,
    IntToFloat = 0x82,
    IntToDouble = 0x83,
    LongToInt = 0x84,
    LongToFloat = 0x85,
    LongToDouble = 0x86,
    FloatToInt = 0x87,
    FloatToLong = 0x88,
    FloatToDouble = 0x89,
    DoubleToInt = 0x8a,
    DoubleToLong = 0x8b,
    DoubleToFloat = 0x8c,
    IntToByte = 0x8d,
    IntToChar = 0x8e,
    IntToShort = 0x8f,
    // 0x90–0xaf: binary ops (two-register)
    AddInt = 0x90,
    SubInt = 0x91,
    MulInt = 0x92,
    DivInt = 0x93,
    RemInt = 0x94,
    AndInt = 0x95,
    OrInt = 0x96,
    XorInt = 0x97,
    ShlInt = 0x98,
    ShrInt = 0x99,
    UshrInt = 0x9a,
    AddLong = 0x9b,
    SubLong = 0x9c,
    MulLong = 0x9d,
    DivLong = 0x9e,
    RemLong = 0x9f,
    AndLong = 0xa0,
    OrLong = 0xa1,
    XorLong = 0xa2,
    ShlLong = 0xa3,
    ShrLong = 0xa4,
    UshrLong = 0xa5,
    AddFloat = 0xa6,
    SubFloat = 0xa7,
    MulFloat = 0xa8,
    DivFloat = 0xa9,
    RemFloat = 0xaa,
    AddDouble = 0xab,
    SubDouble = 0xac,
    MulDouble = 0xad,
    DivDouble = 0xae,
    RemDouble = 0xaf,
    // 0xb0–0xcf: binary ops /2addr
    AddInt2addr = 0xb0,
    SubInt2addr = 0xb1,
    MulInt2addr = 0xb2,
    DivInt2addr = 0xb3,
    RemInt2addr = 0xb4,
    AndInt2addr = 0xb5,
    OrInt2addr = 0xb6,
    XorInt2addr = 0xb7,
    ShlInt2addr = 0xb8,
    ShrInt2addr = 0xb9,
    UshrInt2addr = 0xba,
    AddLong2addr = 0xbb,
    SubLong2addr = 0xbc,
    MulLong2addr = 0xbd,
    DivLong2addr = 0xbe,
    RemLong2addr = 0xbf,
    AndLong2addr = 0xc0,
    OrLong2addr = 0xc1,
    XorLong2addr = 0xc2,
    ShlLong2addr = 0xc3,
    ShrLong2addr = 0xc4,
    UshrLong2addr = 0xc5,
    AddFloat2addr = 0xc6,
    SubFloat2addr = 0xc7,
    MulFloat2addr = 0xc8,
    DivFloat2addr = 0xc9,
    RemFloat2addr = 0xca,
    AddDouble2addr = 0xcb,
    SubDouble2addr = 0xcc,
    MulDouble2addr = 0xcd,
    DivDouble2addr = 0xce,
    RemDouble2addr = 0xcf,
    // 0xd0–0xd7: binary ops /lit16
    AddIntLit16 = 0xd0,
    RsubIntLit16 = 0xd1,
    MulIntLit16 = 0xd2,
    DivIntLit16 = 0xd3,
    RemIntLit16 = 0xd4,
    AndIntLit16 = 0xd5,
    OrIntLit16 = 0xd6,
    XorIntLit16 = 0xd7,
    // 0xd8–0xe2: binary ops /lit8
    AddIntLit8 = 0xd8,
    RsubIntLit8 = 0xd9,
    MulIntLit8 = 0xda,
    DivIntLit8 = 0xdb,
    RemIntLit8 = 0xdc,
    AndIntLit8 = 0xdd,
    OrIntLit8 = 0xde,
    XorIntLit8 = 0xdf,
    ShlIntLit8 = 0xe0,
    ShrIntLit8 = 0xe1,
    UshrIntLit8 = 0xe2,
    // 0xe3–0xff: unused / extended / odex
    UnusedE3 = 0xe3,
    UnusedE4 = 0xe4,
    UnusedE5 = 0xe5,
    UnusedE6 = 0xe6,
    UnusedE7 = 0xe7,
    UnusedE8 = 0xe8,
    UnusedE9 = 0xe9,
    UnusedEa = 0xea,
    UnusedEb = 0xeb,
    UnusedEc = 0xec,
    UnusedEd = 0xed,
    UnusedEe = 0xee,
    UnusedEf = 0xef,
    UnusedF0 = 0xf0,
    UnusedF1 = 0xf1,
    UnusedF2 = 0xf2,
    UnusedF3 = 0xf3,
    UnusedF4 = 0xf4,
    UnusedF5 = 0xf5,
    UnusedF6 = 0xf6,
    UnusedF7 = 0xf7,
    UnusedF8 = 0xf8,
    UnusedF9 = 0xf9,
    InvokePolymorphic = 0xfa,
    InvokePolymorphicRange = 0xfb,
    InvokeCustom = 0xfc,
    InvokeCustomRange = 0xfd,
    ConstMethodHandle = 0xfe,
    ConstMethodType = 0xff,
}

impl DalvikOpcode {
    /// Decode a raw opcode byte into a `DalvikOpcode`.
    ///
    /// # Panics
    ///
    /// Panics if the byte does not correspond to a known Dalvik opcode. Since
    /// every value in `0x00..=0xff` is mapped, this branch is unreachable in
    /// practice but the compiler cannot prove exhaustiveness.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        if b >= 0x80 {
            return Self::from_byte_high(b);
        }
        if b >= 0x40 {
            return Self::from_byte_mid(b);
        }
        match b {
            0x00 => Self::Nop,
            0x01 => Self::Move,
            0x02 => Self::MoveFrom16,
            0x03 => Self::Move16,
            0x04 => Self::MoveWide,
            0x05 => Self::MoveWideFrom16,
            0x06 => Self::MoveWide16,
            0x07 => Self::MoveObject,
            0x08 => Self::MoveObjectFrom16,
            0x09 => Self::MoveObject16,
            0x0a => Self::MoveResult,
            0x0b => Self::MoveResultWide,
            0x0c => Self::MoveResultObject,
            0x0d => Self::MoveException,
            0x0e => Self::ReturnVoid,
            0x0f => Self::Return,
            0x10 => Self::ReturnWide,
            0x11 => Self::ReturnObject,
            0x12 => Self::Const4,
            0x13 => Self::Const16,
            0x14 => Self::Const,
            0x15 => Self::ConstHigh16,
            0x16 => Self::ConstWide16,
            0x17 => Self::ConstWide32,
            0x18 => Self::ConstWide,
            0x19 => Self::ConstWideHigh16,
            0x1a => Self::ConstString,
            0x1b => Self::ConstStringJumbo,
            0x1c => Self::ConstClass,
            0x1d => Self::MonitorEnter,
            0x1e => Self::MonitorExit,
            0x1f => Self::CheckCast,
            0x20 => Self::InstanceOf,
            0x21 => Self::ArrayLength,
            0x22 => Self::NewInstance,
            0x23 => Self::NewArray,
            0x24 => Self::FilledNewArray,
            0x25 => Self::FilledNewArrayRange,
            0x26 => Self::FillArrayData,
            0x27 => Self::Throw,
            0x28 => Self::Goto,
            0x29 => Self::Goto16,
            0x2a => Self::Goto32,
            0x2b => Self::PackedSwitch,
            0x2c => Self::SparseSwitch,
            0x2d => Self::CmplFloat,
            0x2e => Self::CmpgFloat,
            0x2f => Self::CmplDouble,
            0x30 => Self::CmpgDouble,
            0x31 => Self::CmpLong,
            0x32 => Self::IfEq,
            0x33 => Self::IfNe,
            0x34 => Self::IfLt,
            0x35 => Self::IfGe,
            0x36 => Self::IfGt,
            0x37 => Self::IfLe,
            0x38 => Self::IfEqz,
            0x39 => Self::IfNez,
            0x3a => Self::IfLtz,
            0x3b => Self::IfGez,
            0x3c => Self::IfGtz,
            0x3d => Self::IfLez,
            0x3e => Self::Unused3e,
            0x3f => Self::Unused3f,
            // Unreachable: caller guarantees `b < 0x40`. `unreachable!()` is
            // used without a message because this is a `const fn` and the
            // format-macro variant is not allowed in const context.
            _ => unreachable!(),
        }
    }

    /// Mid-range (`0x40..=0x7f`) opcode decoding split out of [`Self::from_byte`].
    #[must_use]
    const fn from_byte_mid(b: u8) -> Self {
        match b {
            0x40 => Self::Unused40,
            0x41 => Self::Unused41,
            0x42 => Self::Unused42,
            0x43 => Self::Unused43,
            0x44 => Self::Aget,
            0x45 => Self::AgetWide,
            0x46 => Self::AgetObject,
            0x47 => Self::AgetBoolean,
            0x48 => Self::AgetByte,
            0x49 => Self::AgetChar,
            0x4a => Self::AgetShort,
            0x4b => Self::Aput,
            0x4c => Self::AputWide,
            0x4d => Self::AputObject,
            0x4e => Self::AputBoolean,
            0x4f => Self::AputByte,
            0x50 => Self::AputChar,
            0x51 => Self::AputShort,
            0x52 => Self::Iget,
            0x53 => Self::IgetWide,
            0x54 => Self::IgetObject,
            0x55 => Self::IgetBoolean,
            0x56 => Self::IgetByte,
            0x57 => Self::IgetChar,
            0x58 => Self::IgetShort,
            0x59 => Self::Iput,
            0x5a => Self::IputWide,
            0x5b => Self::IputObject,
            0x5c => Self::IputBoolean,
            0x5d => Self::IputByte,
            0x5e => Self::IputChar,
            0x5f => Self::IputShort,
            0x60 => Self::Sget,
            0x61 => Self::SgetWide,
            0x62 => Self::SgetObject,
            0x63 => Self::SgetBoolean,
            0x64 => Self::SgetByte,
            0x65 => Self::SgetChar,
            0x66 => Self::SgetShort,
            0x67 => Self::Sput,
            0x68 => Self::SputWide,
            0x69 => Self::SputObject,
            0x6a => Self::SputBoolean,
            0x6b => Self::SputByte,
            0x6c => Self::SputChar,
            0x6d => Self::SputShort,
            0x6e => Self::InvokeVirtual,
            0x6f => Self::InvokeSuper,
            0x70 => Self::InvokeDirect,
            0x71 => Self::InvokeStatic,
            0x72 => Self::InvokeInterface,
            0x73 => Self::Unused73,
            0x74 => Self::InvokeVirtualRange,
            0x75 => Self::InvokeSuperRange,
            0x76 => Self::InvokeDirectRange,
            0x77 => Self::InvokeStaticRange,
            0x78 => Self::InvokeInterfaceRange,
            0x79 => Self::Unused79,
            0x7a => Self::Unused7a,
            0x7b => Self::NegInt,
            0x7c => Self::NotInt,
            0x7d => Self::NegLong,
            0x7e => Self::NotLong,
            0x7f => Self::NegFloat,
            _ => Self::Nop, // Unreachable for `b < 0x40` or `b >= 0x80`.
        }
    }

    /// Decode an opcode byte in the high range (`0x80..=0xff`). Split out from
    /// [`Self::from_byte`] to keep individual functions under the
    /// `too_many_lines` threshold.
    #[must_use]
    const fn from_byte_high(b: u8) -> Self {
        if b >= 0xc0 {
            return Self::from_byte_higher(b);
        }
        match b {
            0x80 => Self::NegDouble,
            0x81 => Self::IntToLong,
            0x82 => Self::IntToFloat,
            0x83 => Self::IntToDouble,
            0x84 => Self::LongToInt,
            0x85 => Self::LongToFloat,
            0x86 => Self::LongToDouble,
            0x87 => Self::FloatToInt,
            0x88 => Self::FloatToLong,
            0x89 => Self::FloatToDouble,
            0x8a => Self::DoubleToInt,
            0x8b => Self::DoubleToLong,
            0x8c => Self::DoubleToFloat,
            0x8d => Self::IntToByte,
            0x8e => Self::IntToChar,
            0x8f => Self::IntToShort,
            0x90 => Self::AddInt,
            0x91 => Self::SubInt,
            0x92 => Self::MulInt,
            0x93 => Self::DivInt,
            0x94 => Self::RemInt,
            0x95 => Self::AndInt,
            0x96 => Self::OrInt,
            0x97 => Self::XorInt,
            0x98 => Self::ShlInt,
            0x99 => Self::ShrInt,
            0x9a => Self::UshrInt,
            0x9b => Self::AddLong,
            0x9c => Self::SubLong,
            0x9d => Self::MulLong,
            0x9e => Self::DivLong,
            0x9f => Self::RemLong,
            0xa0 => Self::AndLong,
            0xa1 => Self::OrLong,
            0xa2 => Self::XorLong,
            0xa3 => Self::ShlLong,
            0xa4 => Self::ShrLong,
            0xa5 => Self::UshrLong,
            0xa6 => Self::AddFloat,
            0xa7 => Self::SubFloat,
            0xa8 => Self::MulFloat,
            0xa9 => Self::DivFloat,
            0xaa => Self::RemFloat,
            0xab => Self::AddDouble,
            0xac => Self::SubDouble,
            0xad => Self::MulDouble,
            0xae => Self::DivDouble,
            0xaf => Self::RemDouble,
            0xb0 => Self::AddInt2addr,
            0xb1 => Self::SubInt2addr,
            0xb2 => Self::MulInt2addr,
            0xb3 => Self::DivInt2addr,
            0xb4 => Self::RemInt2addr,
            0xb5 => Self::AndInt2addr,
            0xb6 => Self::OrInt2addr,
            0xb7 => Self::XorInt2addr,
            0xb8 => Self::ShlInt2addr,
            0xb9 => Self::ShrInt2addr,
            0xba => Self::UshrInt2addr,
            0xbb => Self::AddLong2addr,
            0xbc => Self::SubLong2addr,
            0xbd => Self::MulLong2addr,
            0xbe => Self::DivLong2addr,
            0xbf => Self::RemLong2addr,
            _ => Self::Nop, // Unreachable: `b >= 0xc0` handled by `from_byte_higher`.
        }
    }

    /// Decode an opcode byte in the highest range (`0xc0..=0xff`). Split out
    /// from [`Self::from_byte_high`] to keep individual functions under the
    /// `too_many_lines` threshold.
    #[must_use]
    const fn from_byte_higher(b: u8) -> Self {
        match b {
            0xc0 => Self::AndLong2addr,
            0xc1 => Self::OrLong2addr,
            0xc2 => Self::XorLong2addr,
            0xc3 => Self::ShlLong2addr,
            0xc4 => Self::ShrLong2addr,
            0xc5 => Self::UshrLong2addr,
            0xc6 => Self::AddFloat2addr,
            0xc7 => Self::SubFloat2addr,
            0xc8 => Self::MulFloat2addr,
            0xc9 => Self::DivFloat2addr,
            0xca => Self::RemFloat2addr,
            0xcb => Self::AddDouble2addr,
            0xcc => Self::SubDouble2addr,
            0xcd => Self::MulDouble2addr,
            0xce => Self::DivDouble2addr,
            0xcf => Self::RemDouble2addr,
            0xd0 => Self::AddIntLit16,
            0xd1 => Self::RsubIntLit16,
            0xd2 => Self::MulIntLit16,
            0xd3 => Self::DivIntLit16,
            0xd4 => Self::RemIntLit16,
            0xd5 => Self::AndIntLit16,
            0xd6 => Self::OrIntLit16,
            0xd7 => Self::XorIntLit16,
            0xd8 => Self::AddIntLit8,
            0xd9 => Self::RsubIntLit8,
            0xda => Self::MulIntLit8,
            0xdb => Self::DivIntLit8,
            0xdc => Self::RemIntLit8,
            0xdd => Self::AndIntLit8,
            0xde => Self::OrIntLit8,
            0xdf => Self::XorIntLit8,
            0xe0 => Self::ShlIntLit8,
            0xe1 => Self::ShrIntLit8,
            0xe2 => Self::UshrIntLit8,
            0xe3 => Self::UnusedE3,
            0xe4 => Self::UnusedE4,
            0xe5 => Self::UnusedE5,
            0xe6 => Self::UnusedE6,
            0xe7 => Self::UnusedE7,
            0xe8 => Self::UnusedE8,
            0xe9 => Self::UnusedE9,
            0xea => Self::UnusedEa,
            0xeb => Self::UnusedEb,
            0xec => Self::UnusedEc,
            0xed => Self::UnusedEd,
            0xee => Self::UnusedEe,
            0xef => Self::UnusedEf,
            0xf0 => Self::UnusedF0,
            0xf1 => Self::UnusedF1,
            0xf2 => Self::UnusedF2,
            0xf3 => Self::UnusedF3,
            0xf4 => Self::UnusedF4,
            0xf5 => Self::UnusedF5,
            0xf6 => Self::UnusedF6,
            0xf7 => Self::UnusedF7,
            0xf8 => Self::UnusedF8,
            0xf9 => Self::UnusedF9,
            0xfa => Self::InvokePolymorphic,
            0xfb => Self::InvokePolymorphicRange,
            0xfc => Self::InvokeCustom,
            0xfd => Self::InvokeCustomRange,
            0xfe => Self::ConstMethodHandle,
            0xff => Self::ConstMethodType,
            _ => Self::Nop, // Unreachable for `b >= 0xc0` since all bytes are listed above.
        }
    }

    /// Return the raw byte value of the opcode.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

// ─── opcode_to_smali ──────────────────────────────────────────────────────────

/// Maps a `DalvikOpcode` to its canonical smali mnemonic string.
#[must_use]
pub const fn opcode_to_smali(op: DalvikOpcode) -> &'static str {
    match op {
        DalvikOpcode::Move => "move",
        DalvikOpcode::MoveFrom16 => "move/from16",
        DalvikOpcode::Move16 => "move/16",
        DalvikOpcode::MoveWide => "move-wide",
        DalvikOpcode::MoveWideFrom16 => "move-wide/from16",
        DalvikOpcode::MoveWide16 => "move-wide/16",
        DalvikOpcode::MoveObject => "move-object",
        DalvikOpcode::MoveObjectFrom16 => "move-object/from16",
        DalvikOpcode::MoveObject16 => "move-object/16",
        DalvikOpcode::MoveResult => "move-result",
        DalvikOpcode::MoveResultWide => "move-result-wide",
        DalvikOpcode::MoveResultObject => "move-result-object",
        DalvikOpcode::MoveException => "move-exception",
        DalvikOpcode::ReturnVoid => "return-void",
        DalvikOpcode::Return => "return",
        DalvikOpcode::ReturnWide => "return-wide",
        DalvikOpcode::ReturnObject => "return-object",
        DalvikOpcode::Const4 => "const/4",
        DalvikOpcode::Const16 => "const/16",
        DalvikOpcode::Const => "const",
        DalvikOpcode::ConstHigh16 => "const/high16",
        DalvikOpcode::ConstWide16 => "const-wide/16",
        DalvikOpcode::ConstWide32 => "const-wide/32",
        DalvikOpcode::ConstWide => "const-wide",
        DalvikOpcode::ConstWideHigh16 => "const-wide/high16",
        DalvikOpcode::ConstString => "const-string",
        DalvikOpcode::ConstStringJumbo => "const-string/jumbo",
        DalvikOpcode::ConstClass => "const-class",
        DalvikOpcode::MonitorEnter => "monitor-enter",
        DalvikOpcode::MonitorExit => "monitor-exit",
        DalvikOpcode::CheckCast => "check-cast",
        DalvikOpcode::InstanceOf => "instance-of",
        DalvikOpcode::ArrayLength => "array-length",
        DalvikOpcode::NewInstance => "new-instance",
        DalvikOpcode::NewArray => "new-array",
        DalvikOpcode::FilledNewArray => "filled-new-array",
        DalvikOpcode::FilledNewArrayRange => "filled-new-array/range",
        DalvikOpcode::FillArrayData => "fill-array-data",
        DalvikOpcode::Throw => "throw",
        DalvikOpcode::Goto => "goto",
        DalvikOpcode::Goto16 => "goto/16",
        DalvikOpcode::Goto32 => "goto/32",
        DalvikOpcode::PackedSwitch => "packed-switch",
        DalvikOpcode::SparseSwitch => "sparse-switch",
        DalvikOpcode::CmplFloat => "cmpl-float",
        DalvikOpcode::CmpgFloat => "cmpg-float",
        DalvikOpcode::CmplDouble => "cmpl-double",
        DalvikOpcode::CmpgDouble => "cmpg-double",
        DalvikOpcode::CmpLong => "cmp-long",
        DalvikOpcode::IfEq => "if-eq",
        DalvikOpcode::IfNe => "if-ne",
        DalvikOpcode::IfLt => "if-lt",
        DalvikOpcode::IfGe => "if-ge",
        DalvikOpcode::IfGt => "if-gt",
        DalvikOpcode::IfLe => "if-le",
        DalvikOpcode::IfEqz => "if-eqz",
        DalvikOpcode::IfNez => "if-nez",
        DalvikOpcode::IfLtz => "if-ltz",
        DalvikOpcode::IfGez => "if-gez",
        DalvikOpcode::IfGtz => "if-gtz",
        DalvikOpcode::IfLez => "if-lez",
        DalvikOpcode::Aget => "aget",
        DalvikOpcode::AgetWide => "aget-wide",
        DalvikOpcode::AgetObject => "aget-object",
        DalvikOpcode::AgetBoolean => "aget-boolean",
        DalvikOpcode::AgetByte => "aget-byte",
        DalvikOpcode::AgetChar => "aget-char",
        DalvikOpcode::AgetShort => "aget-short",
        DalvikOpcode::Aput => "aput",
        DalvikOpcode::AputWide => "aput-wide",
        DalvikOpcode::AputObject => "aput-object",
        DalvikOpcode::AputBoolean => "aput-boolean",
        DalvikOpcode::AputByte => "aput-byte",
        DalvikOpcode::AputChar => "aput-char",
        DalvikOpcode::AputShort => "aput-short",
        // Field/static access + invokes — delegated to a helper to stay below
        // the `too_many_lines` threshold.
        other @ (DalvikOpcode::Iget
        | DalvikOpcode::IgetWide
        | DalvikOpcode::IgetObject
        | DalvikOpcode::IgetBoolean
        | DalvikOpcode::IgetByte
        | DalvikOpcode::IgetChar
        | DalvikOpcode::IgetShort
        | DalvikOpcode::Iput
        | DalvikOpcode::IputWide
        | DalvikOpcode::IputObject
        | DalvikOpcode::IputBoolean
        | DalvikOpcode::IputByte
        | DalvikOpcode::IputChar
        | DalvikOpcode::IputShort
        | DalvikOpcode::Sget
        | DalvikOpcode::SgetWide
        | DalvikOpcode::SgetObject
        | DalvikOpcode::SgetBoolean
        | DalvikOpcode::SgetByte
        | DalvikOpcode::SgetChar
        | DalvikOpcode::SgetShort
        | DalvikOpcode::Sput
        | DalvikOpcode::SputWide
        | DalvikOpcode::SputObject
        | DalvikOpcode::SputBoolean
        | DalvikOpcode::SputByte
        | DalvikOpcode::SputChar
        | DalvikOpcode::SputShort) => opcode_to_smali_field(other),
        DalvikOpcode::InvokeVirtual => "invoke-virtual",
        DalvikOpcode::InvokeSuper => "invoke-super",
        DalvikOpcode::InvokeDirect => "invoke-direct",
        DalvikOpcode::InvokeStatic => "invoke-static",
        DalvikOpcode::InvokeInterface => "invoke-interface",
        DalvikOpcode::InvokeVirtualRange => "invoke-virtual/range",
        DalvikOpcode::InvokeSuperRange => "invoke-super/range",
        DalvikOpcode::InvokeDirectRange => "invoke-direct/range",
        DalvikOpcode::InvokeStaticRange => "invoke-static/range",
        DalvikOpcode::InvokeInterfaceRange => "invoke-interface/range",
        // Delegate the remainder (arithmetic, conversion, lit, etc.) to keep
        // each match below the `too_many_lines` threshold.
        other => opcode_to_smali_tail(other),
    }
}

/// Field accessor and static accessor mnemonics — split out of
/// [`opcode_to_smali`] to keep individual functions below the
/// `too_many_lines` threshold.
#[must_use]
const fn opcode_to_smali_field(op: DalvikOpcode) -> &'static str {
    match op {
        DalvikOpcode::Iget => "iget",
        DalvikOpcode::IgetWide => "iget-wide",
        DalvikOpcode::IgetObject => "iget-object",
        DalvikOpcode::IgetBoolean => "iget-boolean",
        DalvikOpcode::IgetByte => "iget-byte",
        DalvikOpcode::IgetChar => "iget-char",
        DalvikOpcode::IgetShort => "iget-short",
        DalvikOpcode::Iput => "iput",
        DalvikOpcode::IputWide => "iput-wide",
        DalvikOpcode::IputObject => "iput-object",
        DalvikOpcode::IputBoolean => "iput-boolean",
        DalvikOpcode::IputByte => "iput-byte",
        DalvikOpcode::IputChar => "iput-char",
        DalvikOpcode::IputShort => "iput-short",
        DalvikOpcode::Sget => "sget",
        DalvikOpcode::SgetWide => "sget-wide",
        DalvikOpcode::SgetObject => "sget-object",
        DalvikOpcode::SgetBoolean => "sget-boolean",
        DalvikOpcode::SgetByte => "sget-byte",
        DalvikOpcode::SgetChar => "sget-char",
        DalvikOpcode::SgetShort => "sget-short",
        DalvikOpcode::Sput => "sput",
        DalvikOpcode::SputWide => "sput-wide",
        DalvikOpcode::SputObject => "sput-object",
        DalvikOpcode::SputBoolean => "sput-boolean",
        DalvikOpcode::SputByte => "sput-byte",
        DalvikOpcode::SputChar => "sput-char",
        DalvikOpcode::SputShort => "sput-short",
        _ => "nop", // Unreachable: caller only routes field/static opcodes here.
    }
}

/// Tail half of [`opcode_to_smali`] — arithmetic/conversion/lit/misc opcodes.
#[must_use]
const fn opcode_to_smali_tail(op: DalvikOpcode) -> &'static str {
    match op {
        DalvikOpcode::NegInt => "neg-int",
        DalvikOpcode::NotInt => "not-int",
        DalvikOpcode::NegLong => "neg-long",
        DalvikOpcode::NotLong => "not-long",
        DalvikOpcode::NegFloat => "neg-float",
        DalvikOpcode::NegDouble => "neg-double",
        DalvikOpcode::IntToLong => "int-to-long",
        DalvikOpcode::IntToFloat => "int-to-float",
        DalvikOpcode::IntToDouble => "int-to-double",
        DalvikOpcode::LongToInt => "long-to-int",
        DalvikOpcode::LongToFloat => "long-to-float",
        DalvikOpcode::LongToDouble => "long-to-double",
        DalvikOpcode::FloatToInt => "float-to-int",
        DalvikOpcode::FloatToLong => "float-to-long",
        DalvikOpcode::FloatToDouble => "float-to-double",
        DalvikOpcode::DoubleToInt => "double-to-int",
        DalvikOpcode::DoubleToLong => "double-to-long",
        DalvikOpcode::DoubleToFloat => "double-to-float",
        DalvikOpcode::IntToByte => "int-to-byte",
        DalvikOpcode::IntToChar => "int-to-char",
        DalvikOpcode::IntToShort => "int-to-short",
        DalvikOpcode::AddInt => "add-int",
        DalvikOpcode::SubInt => "sub-int",
        DalvikOpcode::MulInt => "mul-int",
        DalvikOpcode::DivInt => "div-int",
        DalvikOpcode::RemInt => "rem-int",
        DalvikOpcode::AndInt => "and-int",
        DalvikOpcode::OrInt => "or-int",
        DalvikOpcode::XorInt => "xor-int",
        DalvikOpcode::ShlInt => "shl-int",
        DalvikOpcode::ShrInt => "shr-int",
        DalvikOpcode::UshrInt => "ushr-int",
        DalvikOpcode::AddLong => "add-long",
        DalvikOpcode::SubLong => "sub-long",
        DalvikOpcode::MulLong => "mul-long",
        DalvikOpcode::DivLong => "div-long",
        DalvikOpcode::RemLong => "rem-long",
        DalvikOpcode::AndLong => "and-long",
        DalvikOpcode::OrLong => "or-long",
        DalvikOpcode::XorLong => "xor-long",
        DalvikOpcode::ShlLong => "shl-long",
        DalvikOpcode::ShrLong => "shr-long",
        DalvikOpcode::UshrLong => "ushr-long",
        DalvikOpcode::AddFloat => "add-float",
        DalvikOpcode::SubFloat => "sub-float",
        DalvikOpcode::MulFloat => "mul-float",
        DalvikOpcode::DivFloat => "div-float",
        DalvikOpcode::RemFloat => "rem-float",
        DalvikOpcode::AddDouble => "add-double",
        DalvikOpcode::SubDouble => "sub-double",
        DalvikOpcode::MulDouble => "mul-double",
        DalvikOpcode::DivDouble => "div-double",
        DalvikOpcode::RemDouble => "rem-double",
        other @ (DalvikOpcode::AddInt2addr
        | DalvikOpcode::SubInt2addr
        | DalvikOpcode::MulInt2addr
        | DalvikOpcode::DivInt2addr
        | DalvikOpcode::RemInt2addr
        | DalvikOpcode::AndInt2addr
        | DalvikOpcode::OrInt2addr
        | DalvikOpcode::XorInt2addr
        | DalvikOpcode::ShlInt2addr
        | DalvikOpcode::ShrInt2addr
        | DalvikOpcode::UshrInt2addr
        | DalvikOpcode::AddLong2addr
        | DalvikOpcode::SubLong2addr
        | DalvikOpcode::MulLong2addr
        | DalvikOpcode::DivLong2addr
        | DalvikOpcode::RemLong2addr
        | DalvikOpcode::AndLong2addr
        | DalvikOpcode::OrLong2addr
        | DalvikOpcode::XorLong2addr
        | DalvikOpcode::ShlLong2addr
        | DalvikOpcode::ShrLong2addr
        | DalvikOpcode::UshrLong2addr
        | DalvikOpcode::AddFloat2addr
        | DalvikOpcode::SubFloat2addr
        | DalvikOpcode::MulFloat2addr
        | DalvikOpcode::DivFloat2addr
        | DalvikOpcode::RemFloat2addr
        | DalvikOpcode::AddDouble2addr
        | DalvikOpcode::SubDouble2addr
        | DalvikOpcode::MulDouble2addr
        | DalvikOpcode::DivDouble2addr
        | DalvikOpcode::RemDouble2addr) => opcode_to_smali_2addr(other),
        // Literal-suffixed arithmetic mnemonics — delegated to a helper.
        other @ (DalvikOpcode::AddIntLit16
        | DalvikOpcode::RsubIntLit16
        | DalvikOpcode::MulIntLit16
        | DalvikOpcode::DivIntLit16
        | DalvikOpcode::RemIntLit16
        | DalvikOpcode::AndIntLit16
        | DalvikOpcode::OrIntLit16
        | DalvikOpcode::XorIntLit16
        | DalvikOpcode::AddIntLit8
        | DalvikOpcode::RsubIntLit8
        | DalvikOpcode::MulIntLit8
        | DalvikOpcode::DivIntLit8
        | DalvikOpcode::RemIntLit8
        | DalvikOpcode::AndIntLit8
        | DalvikOpcode::OrIntLit8) => opcode_to_smali_lit(other),
        DalvikOpcode::XorIntLit8 => "xor-int/lit8",
        DalvikOpcode::ShlIntLit8 => "shl-int/lit8",
        DalvikOpcode::ShrIntLit8 => "shr-int/lit8",
        DalvikOpcode::UshrIntLit8 => "ushr-int/lit8",
        DalvikOpcode::InvokePolymorphic => "invoke-polymorphic",
        DalvikOpcode::InvokePolymorphicRange => "invoke-polymorphic/range",
        DalvikOpcode::InvokeCustom => "invoke-custom",
        DalvikOpcode::InvokeCustomRange => "invoke-custom/range",
        DalvikOpcode::ConstMethodHandle => "const-method-handle",
        DalvikOpcode::ConstMethodType => "const-method-type",
        // All unused / reserved opcodes (and Nop itself)
        _ => "nop",
    }
}

/// Returns the smali mnemonic for `/2addr` arithmetic opcodes.
const fn opcode_to_smali_2addr(op: DalvikOpcode) -> &'static str {
    match op {
        DalvikOpcode::AddInt2addr => "add-int/2addr",
        DalvikOpcode::SubInt2addr => "sub-int/2addr",
        DalvikOpcode::MulInt2addr => "mul-int/2addr",
        DalvikOpcode::DivInt2addr => "div-int/2addr",
        DalvikOpcode::RemInt2addr => "rem-int/2addr",
        DalvikOpcode::AndInt2addr => "and-int/2addr",
        DalvikOpcode::OrInt2addr => "or-int/2addr",
        DalvikOpcode::XorInt2addr => "xor-int/2addr",
        DalvikOpcode::ShlInt2addr => "shl-int/2addr",
        DalvikOpcode::ShrInt2addr => "shr-int/2addr",
        DalvikOpcode::UshrInt2addr => "ushr-int/2addr",
        DalvikOpcode::AddLong2addr => "add-long/2addr",
        DalvikOpcode::SubLong2addr => "sub-long/2addr",
        DalvikOpcode::MulLong2addr => "mul-long/2addr",
        DalvikOpcode::DivLong2addr => "div-long/2addr",
        DalvikOpcode::RemLong2addr => "rem-long/2addr",
        DalvikOpcode::AndLong2addr => "and-long/2addr",
        DalvikOpcode::OrLong2addr => "or-long/2addr",
        DalvikOpcode::XorLong2addr => "xor-long/2addr",
        DalvikOpcode::ShlLong2addr => "shl-long/2addr",
        DalvikOpcode::ShrLong2addr => "shr-long/2addr",
        DalvikOpcode::UshrLong2addr => "ushr-long/2addr",
        DalvikOpcode::AddFloat2addr => "add-float/2addr",
        DalvikOpcode::SubFloat2addr => "sub-float/2addr",
        DalvikOpcode::MulFloat2addr => "mul-float/2addr",
        DalvikOpcode::DivFloat2addr => "div-float/2addr",
        DalvikOpcode::RemFloat2addr => "rem-float/2addr",
        DalvikOpcode::AddDouble2addr => "add-double/2addr",
        DalvikOpcode::SubDouble2addr => "sub-double/2addr",
        DalvikOpcode::MulDouble2addr => "mul-double/2addr",
        DalvikOpcode::DivDouble2addr => "div-double/2addr",
        DalvikOpcode::RemDouble2addr => "rem-double/2addr",
        _ => "nop",
    }
}

/// Returns the smali mnemonic for literal-suffixed arithmetic opcodes (lit8/lit16).
const fn opcode_to_smali_lit(op: DalvikOpcode) -> &'static str {
    match op {
        DalvikOpcode::AddIntLit16 => "add-int/lit16",
        DalvikOpcode::RsubIntLit16 => "rsub-int",
        DalvikOpcode::MulIntLit16 => "mul-int/lit16",
        DalvikOpcode::DivIntLit16 => "div-int/lit16",
        DalvikOpcode::RemIntLit16 => "rem-int/lit16",
        DalvikOpcode::AndIntLit16 => "and-int/lit16",
        DalvikOpcode::OrIntLit16 => "or-int/lit16",
        DalvikOpcode::XorIntLit16 => "xor-int/lit16",
        DalvikOpcode::AddIntLit8 => "add-int/lit8",
        DalvikOpcode::RsubIntLit8 => "rsub-int/lit8",
        DalvikOpcode::MulIntLit8 => "mul-int/lit8",
        DalvikOpcode::DivIntLit8 => "div-int/lit8",
        DalvikOpcode::RemIntLit8 => "rem-int/lit8",
        DalvikOpcode::AndIntLit8 => "and-int/lit8",
        DalvikOpcode::OrIntLit8 => "or-int/lit8",
        _ => "nop",
    }
}

// ─── instruction_size_bytes ───────────────────────────────────────────────────

/// Returns the encoded size of a Dalvik instruction in bytes.
///
/// Dalvik instructions are encoded in 16-bit code units; this function returns
/// the byte count (always a multiple of 2).  Most instructions are 2 bytes
/// (one 16-bit code unit).  Instructions that carry 32-bit or 64-bit immediates,
/// or 32-bit offsets, are larger.
#[must_use]
pub const fn instruction_size_bytes(op: DalvikOpcode) -> usize {
    match op {
        // 4 bytes (two 16-bit code units)
        DalvikOpcode::MoveFrom16
        | DalvikOpcode::MoveWideFrom16
        | DalvikOpcode::MoveObjectFrom16
        | DalvikOpcode::Const16
        | DalvikOpcode::ConstHigh16
        | DalvikOpcode::ConstWide16
        | DalvikOpcode::ConstWideHigh16
        | DalvikOpcode::ConstString
        | DalvikOpcode::ConstClass
        | DalvikOpcode::CheckCast
        | DalvikOpcode::NewInstance
        | DalvikOpcode::Goto16
        | DalvikOpcode::PackedSwitch
        | DalvikOpcode::SparseSwitch
        | DalvikOpcode::IfEq
        | DalvikOpcode::IfNe
        | DalvikOpcode::IfLt
        | DalvikOpcode::IfGe
        | DalvikOpcode::IfGt
        | DalvikOpcode::IfLe
        | DalvikOpcode::IfEqz
        | DalvikOpcode::IfNez
        | DalvikOpcode::IfLtz
        | DalvikOpcode::IfGez
        | DalvikOpcode::IfGtz
        | DalvikOpcode::IfLez
        | DalvikOpcode::Aget
        | DalvikOpcode::AgetWide
        | DalvikOpcode::AgetObject
        | DalvikOpcode::AgetBoolean
        | DalvikOpcode::AgetByte
        | DalvikOpcode::AgetChar
        | DalvikOpcode::AgetShort
        | DalvikOpcode::Aput
        | DalvikOpcode::AputWide
        | DalvikOpcode::AputObject
        | DalvikOpcode::AputBoolean
        | DalvikOpcode::AputByte
        | DalvikOpcode::AputChar
        | DalvikOpcode::AputShort
        | DalvikOpcode::Iget
        | DalvikOpcode::IgetWide
        | DalvikOpcode::IgetObject
        | DalvikOpcode::IgetBoolean
        | DalvikOpcode::IgetByte
        | DalvikOpcode::IgetChar
        | DalvikOpcode::IgetShort
        | DalvikOpcode::Iput
        | DalvikOpcode::IputWide
        | DalvikOpcode::IputObject
        | DalvikOpcode::IputBoolean
        | DalvikOpcode::IputByte
        | DalvikOpcode::IputChar
        | DalvikOpcode::IputShort
        | DalvikOpcode::Sget
        | DalvikOpcode::SgetWide
        | DalvikOpcode::SgetObject
        | DalvikOpcode::SgetBoolean
        | DalvikOpcode::SgetByte
        | DalvikOpcode::SgetChar
        | DalvikOpcode::SgetShort
        | DalvikOpcode::Sput
        | DalvikOpcode::SputWide
        | DalvikOpcode::SputObject
        | DalvikOpcode::SputBoolean
        | DalvikOpcode::SputByte
        | DalvikOpcode::SputChar
        | DalvikOpcode::SputShort
        | DalvikOpcode::NewArray
        | DalvikOpcode::InstanceOf
        | DalvikOpcode::ArrayLength
        | DalvikOpcode::FillArrayData
        | DalvikOpcode::AddIntLit16
        | DalvikOpcode::RsubIntLit16
        | DalvikOpcode::MulIntLit16
        | DalvikOpcode::DivIntLit16
        | DalvikOpcode::RemIntLit16
        | DalvikOpcode::AndIntLit16
        | DalvikOpcode::OrIntLit16
        | DalvikOpcode::XorIntLit16
        | DalvikOpcode::AddIntLit8
        | DalvikOpcode::RsubIntLit8
        | DalvikOpcode::MulIntLit8
        | DalvikOpcode::DivIntLit8
        | DalvikOpcode::RemIntLit8
        | DalvikOpcode::AndIntLit8
        | DalvikOpcode::OrIntLit8
        | DalvikOpcode::XorIntLit8
        | DalvikOpcode::ShlIntLit8
        | DalvikOpcode::ShrIntLit8
        | DalvikOpcode::UshrIntLit8
        | DalvikOpcode::ConstMethodHandle
        | DalvikOpcode::ConstMethodType => 4,

        // 6 bytes (three 16-bit code units)
        DalvikOpcode::Move16
        | DalvikOpcode::MoveWide16
        | DalvikOpcode::MoveObject16
        | DalvikOpcode::Const
        | DalvikOpcode::ConstWide32
        | DalvikOpcode::ConstStringJumbo
        | DalvikOpcode::Goto32
        | DalvikOpcode::InvokeVirtual
        | DalvikOpcode::InvokeSuper
        | DalvikOpcode::InvokeDirect
        | DalvikOpcode::InvokeStatic
        | DalvikOpcode::InvokeInterface
        | DalvikOpcode::InvokeVirtualRange
        | DalvikOpcode::InvokeSuperRange
        | DalvikOpcode::InvokeDirectRange
        | DalvikOpcode::InvokeStaticRange
        | DalvikOpcode::InvokeInterfaceRange
        | DalvikOpcode::FilledNewArray
        | DalvikOpcode::FilledNewArrayRange
        | DalvikOpcode::InvokePolymorphic
        | DalvikOpcode::InvokePolymorphicRange
        | DalvikOpcode::InvokeCustom
        | DalvikOpcode::InvokeCustomRange => 6,

        // 10 bytes (five 16-bit code units)
        DalvikOpcode::ConstWide => 10,

        // Default: 2 bytes (one 16-bit code unit). Note: const-method-handle /
        // const-method-type are also 4 bytes, merged with the 4-byte arm above.
        _ => 2,
    }
}

// ─── DexContext ───────────────────────────────────────────────────────────────

/// Optional DEX string/type/method/field tables used for name resolution during
/// disassembly.  Pass `None` (or `DexContext::dummy()`) when no DEX metadata is
/// available.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DexContext {
    pub strings: Vec<String>,
    pub types: Vec<String>,
    pub methods: Vec<String>,
    pub fields: Vec<String>,
}

impl DexContext {
    /// Create an empty context (no name resolution available).
    #[must_use]
    pub fn dummy() -> Self {
        Self::default()
    }

    /// Look up a string by index, returning a placeholder if out of range.
    #[must_use]
    pub fn string(&self, idx: u32) -> String {
        self.strings
            .get(idx as usize)
            .cloned()
            .unwrap_or_else(|| format!("<string@{idx:#x}>"))
    }

    /// Look up a type descriptor by index.
    #[must_use]
    pub fn type_desc(&self, idx: u32) -> String {
        self.types
            .get(idx as usize)
            .cloned()
            .unwrap_or_else(|| format!("<type@{idx:#x}>"))
    }

    /// Look up a method reference by index.
    #[must_use]
    pub fn method(&self, idx: u32) -> String {
        self.methods
            .get(idx as usize)
            .cloned()
            .unwrap_or_else(|| format!("<method@{idx:#x}>"))
    }

    /// Look up a field reference by index.
    #[must_use]
    pub fn field(&self, idx: u32) -> String {
        self.fields
            .get(idx as usize)
            .cloned()
            .unwrap_or_else(|| format!("<field@{idx:#x}>"))
    }
}

// ─── SmaliInstruction ─────────────────────────────────────────────────────────

/// A single decoded Dalvik bytecode instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmaliInstruction {
    /// Byte offset from the start of the method's code array.
    pub offset: usize,
    /// Decoded opcode.
    pub op: DalvikOpcode,
    /// Register operands (vN numbers, not encoded register byte).
    pub regs: Vec<u8>,
    /// String index (for const-string, etc.).
    pub string_idx: Option<u32>,
    /// Type index (for new-instance, check-cast, etc.).
    pub type_idx: Option<u32>,
    /// Field index (for iget/iput/sget/sput).
    pub field_idx: Option<u32>,
    /// Method index (for invoke-*).
    pub method_idx: Option<u32>,
    /// Literal integer / float / wide constant.
    pub literal: Option<i64>,
    /// Branch target as signed byte offset from the current instruction.
    pub branch_target: Option<i32>,
}

// ─── SmaliDisassembler ────────────────────────────────────────────────────────

/// Stateless Dalvik bytecode disassembler.
pub struct SmaliDisassembler;

impl SmaliDisassembler {
    /// Decode a slice of DEX bytecode starting at `offset` within the method.
    ///
    /// DEX bytecode is stored as an array of 16-bit little-endian code units.
    /// `code` must be a byte slice whose length is a multiple of 2.
    #[must_use]
    pub fn disassemble_bytecode(code: &[u8], offset: usize) -> Vec<SmaliInstruction> {
        let mut result = Vec::new();
        let mut pos = 0usize;

        while pos + 1 < code.len() {
            let raw_byte = code[pos];
            let op = DalvikOpcode::from_byte(raw_byte);
            let high_byte = code[pos + 1]; // second byte of first code unit

            let mut instr = SmaliInstruction {
                offset: offset + pos,
                op,
                regs: Vec::new(),
                string_idx: None,
                type_idx: None,
                field_idx: None,
                method_idx: None,
                literal: None,
                branch_target: None,
            };

            // Decode operands based on opcode format
            if Self::is_format_12x(op) {
                instr.regs.push(high_byte & 0x0f);
                instr.regs.push((high_byte >> 4) & 0x0f);
            } else if Self::is_format_11x(op) {
                instr.regs.push(high_byte);
            } else {
                match op {
                    // Format 11n: const/4 vA, #+B
                    DalvikOpcode::Const4 => {
                        instr.regs.push(high_byte & 0x0f);
                        let lit = (high_byte >> 4).cast_signed() >> 4;
                        instr.literal = Some(i64::from(lit));
                    }
                    // Format 21s: vAA, #+BBBB
                    DalvikOpcode::Const16 | DalvikOpcode::ConstWide16 => {
                        Self::decode_const_21s(&mut instr, code, pos, high_byte);
                    }
                    // Format 21h: vAA, #+BBBB0000
                    DalvikOpcode::ConstHigh16 | DalvikOpcode::ConstWideHigh16 => {
                        Self::decode_const_21h(&mut instr, code, pos, high_byte);
                    }
                    // Format 31i: vAA, #+BBBBBBBB (also const-wide/32)
                    DalvikOpcode::Const | DalvikOpcode::ConstWide32 => {
                        Self::decode_const_31i(&mut instr, code, pos, high_byte);
                    }
                    // Format 51l: const-wide vAA, #+BBBBBBBBBBBBBBBB
                    DalvikOpcode::ConstWide => {
                        Self::decode_const_51l(&mut instr, code, pos, high_byte);
                    }
                    // Format 21c: const-string vAA, string@BBBB
                    DalvikOpcode::ConstString => {
                        Self::decode_const_string(&mut instr, code, pos, high_byte);
                    }
                    // Format 31c: const-string/jumbo vAA, string@BBBBBBBB
                    DalvikOpcode::ConstStringJumbo => {
                        Self::decode_const_string_jumbo(&mut instr, code, pos, high_byte);
                    }
                    DalvikOpcode::ConstClass
                    | DalvikOpcode::CheckCast
                    | DalvikOpcode::NewInstance => {
                        Self::decode_type_21c(&mut instr, code, pos, high_byte);
                    }
                    // Format 22c: instance-of/new-array vA, vB, type@CCCC
                    DalvikOpcode::InstanceOf | DalvikOpcode::NewArray => {
                        Self::decode_type_22c(&mut instr, code, pos, high_byte);
                    }
                    // Format 35c: filled-new-array {vC..vG}, type@BBBB
                    DalvikOpcode::FilledNewArray => {
                        Self::decode_filled_new_array(&mut instr, code, pos, high_byte);
                    }
                    // Format 3rc: filled-new-array/range {vCCCC..vNNNN}, type@BBBB
                    DalvikOpcode::FilledNewArrayRange => {
                        Self::decode_filled_new_array_range(&mut instr, code, pos, high_byte);
                    }
                    // Format 10t: goto +AA
                    DalvikOpcode::Goto => {
                        instr.branch_target = Some(i32::from(high_byte.cast_signed()));
                    }
                    // Format 20t: goto/16 +AAAA
                    DalvikOpcode::Goto16 => Self::decode_goto16(&mut instr, code, pos),
                    // Format 30t: goto/32 +AAAAAAAA
                    DalvikOpcode::Goto32 => Self::decode_goto32(&mut instr, code, pos),
                    // Format 31t: packed-switch / sparse-switch / fill-array-data
                    DalvikOpcode::PackedSwitch
                    | DalvikOpcode::SparseSwitch
                    | DalvikOpcode::FillArrayData => {
                        Self::decode_31t(&mut instr, code, pos, high_byte);
                    }
                    DalvikOpcode::IfEq
                    | DalvikOpcode::IfNe
                    | DalvikOpcode::IfLt
                    | DalvikOpcode::IfGe
                    | DalvikOpcode::IfGt
                    | DalvikOpcode::IfLe => Self::decode_if_22t(&mut instr, code, pos, high_byte),
                    DalvikOpcode::IfEqz
                    | DalvikOpcode::IfNez
                    | DalvikOpcode::IfLtz
                    | DalvikOpcode::IfGez
                    | DalvikOpcode::IfGtz
                    | DalvikOpcode::IfLez => Self::decode_if_21t(&mut instr, code, pos, high_byte),
                    op if Self::is_format_iget_iput(op) => {
                        Self::decode_iget_iput(&mut instr, code, pos, high_byte);
                    }
                    op if Self::is_format_sget_sput(op) => {
                        Self::decode_sget_sput(&mut instr, code, pos, high_byte);
                    }

                    op if Self::is_format_invoke_35c(op) => {
                        Self::decode_invoke_35c(&mut instr, code, pos, high_byte);
                    }
                    op if Self::is_format_invoke_3rc(op) => {
                        Self::decode_invoke_3rc(&mut instr, code, pos, high_byte);
                    }
                    op if Self::is_format_lit16(op) => {
                        Self::decode_binop_lit16(&mut instr, code, pos, high_byte);
                    }
                    op if Self::is_format_lit8(op) => {
                        Self::decode_binop_lit8(&mut instr, code, pos, high_byte);
                    }
                    op if Self::is_format_23x(op) => {
                        Self::decode_binop_23x(&mut instr, code, pos, high_byte);
                    }
                    // Move/from16 variants: vAA, vBBBB
                    DalvikOpcode::MoveFrom16
                    | DalvikOpcode::MoveWideFrom16
                    | DalvikOpcode::MoveObjectFrom16 => {
                        Self::decode_move_from16(&mut instr, code, pos, high_byte);
                    }
                    // Fallback: treat as no-operand
                    _ => {}
                }
            }

            let size = instruction_size_bytes(op);
            result.push(instr);
            pos += size;
        }

        result
    }

    const fn is_format_12x(op: DalvikOpcode) -> bool {
        matches!(
            op,
            DalvikOpcode::Move
                | DalvikOpcode::MoveWide
                | DalvikOpcode::MoveObject
                | DalvikOpcode::NegInt
                | DalvikOpcode::NotInt
                | DalvikOpcode::NegLong
                | DalvikOpcode::NotLong
                | DalvikOpcode::NegFloat
                | DalvikOpcode::NegDouble
                | DalvikOpcode::IntToLong
                | DalvikOpcode::IntToFloat
                | DalvikOpcode::IntToDouble
                | DalvikOpcode::LongToInt
                | DalvikOpcode::LongToFloat
                | DalvikOpcode::LongToDouble
                | DalvikOpcode::FloatToInt
                | DalvikOpcode::FloatToLong
                | DalvikOpcode::FloatToDouble
                | DalvikOpcode::DoubleToInt
                | DalvikOpcode::DoubleToLong
                | DalvikOpcode::DoubleToFloat
                | DalvikOpcode::IntToByte
                | DalvikOpcode::IntToChar
                | DalvikOpcode::IntToShort
                | DalvikOpcode::ArrayLength
                | DalvikOpcode::MonitorEnter
                | DalvikOpcode::MonitorExit
                | DalvikOpcode::AddInt2addr
                | DalvikOpcode::SubInt2addr
                | DalvikOpcode::MulInt2addr
                | DalvikOpcode::DivInt2addr
                | DalvikOpcode::RemInt2addr
                | DalvikOpcode::AndInt2addr
                | DalvikOpcode::OrInt2addr
                | DalvikOpcode::XorInt2addr
                | DalvikOpcode::ShlInt2addr
                | DalvikOpcode::ShrInt2addr
                | DalvikOpcode::UshrInt2addr
                | DalvikOpcode::AddLong2addr
                | DalvikOpcode::SubLong2addr
                | DalvikOpcode::MulLong2addr
                | DalvikOpcode::DivLong2addr
                | DalvikOpcode::RemLong2addr
                | DalvikOpcode::AndLong2addr
                | DalvikOpcode::OrLong2addr
                | DalvikOpcode::XorLong2addr
                | DalvikOpcode::ShlLong2addr
                | DalvikOpcode::ShrLong2addr
                | DalvikOpcode::UshrLong2addr
                | DalvikOpcode::AddFloat2addr
                | DalvikOpcode::SubFloat2addr
                | DalvikOpcode::MulFloat2addr
                | DalvikOpcode::DivFloat2addr
                | DalvikOpcode::RemFloat2addr
                | DalvikOpcode::AddDouble2addr
                | DalvikOpcode::SubDouble2addr
                | DalvikOpcode::MulDouble2addr
                | DalvikOpcode::DivDouble2addr
                | DalvikOpcode::RemDouble2addr
        )
    }

    const fn is_format_invoke_35c(op: DalvikOpcode) -> bool {
        matches!(
            op,
            DalvikOpcode::InvokeVirtual
                | DalvikOpcode::InvokeSuper
                | DalvikOpcode::InvokeDirect
                | DalvikOpcode::InvokeStatic
                | DalvikOpcode::InvokeInterface
        )
    }

    const fn is_format_invoke_3rc(op: DalvikOpcode) -> bool {
        matches!(
            op,
            DalvikOpcode::InvokeVirtualRange
                | DalvikOpcode::InvokeSuperRange
                | DalvikOpcode::InvokeDirectRange
                | DalvikOpcode::InvokeStaticRange
                | DalvikOpcode::InvokeInterfaceRange
        )
    }

    const fn is_format_lit16(op: DalvikOpcode) -> bool {
        matches!(
            op,
            DalvikOpcode::AddIntLit16
                | DalvikOpcode::RsubIntLit16
                | DalvikOpcode::MulIntLit16
                | DalvikOpcode::DivIntLit16
                | DalvikOpcode::RemIntLit16
                | DalvikOpcode::AndIntLit16
                | DalvikOpcode::OrIntLit16
                | DalvikOpcode::XorIntLit16
        )
    }

    const fn is_format_lit8(op: DalvikOpcode) -> bool {
        matches!(
            op,
            DalvikOpcode::AddIntLit8
                | DalvikOpcode::RsubIntLit8
                | DalvikOpcode::MulIntLit8
                | DalvikOpcode::DivIntLit8
                | DalvikOpcode::RemIntLit8
                | DalvikOpcode::AndIntLit8
                | DalvikOpcode::OrIntLit8
                | DalvikOpcode::XorIntLit8
                | DalvikOpcode::ShlIntLit8
                | DalvikOpcode::ShrIntLit8
                | DalvikOpcode::UshrIntLit8
        )
    }

    const fn is_format_iget_iput(op: DalvikOpcode) -> bool {
        matches!(
            op,
            DalvikOpcode::Iget
                | DalvikOpcode::IgetWide
                | DalvikOpcode::IgetObject
                | DalvikOpcode::IgetBoolean
                | DalvikOpcode::IgetByte
                | DalvikOpcode::IgetChar
                | DalvikOpcode::IgetShort
                | DalvikOpcode::Iput
                | DalvikOpcode::IputWide
                | DalvikOpcode::IputObject
                | DalvikOpcode::IputBoolean
                | DalvikOpcode::IputByte
                | DalvikOpcode::IputChar
                | DalvikOpcode::IputShort
        )
    }

    const fn is_format_sget_sput(op: DalvikOpcode) -> bool {
        matches!(
            op,
            DalvikOpcode::Sget
                | DalvikOpcode::SgetWide
                | DalvikOpcode::SgetObject
                | DalvikOpcode::SgetBoolean
                | DalvikOpcode::SgetByte
                | DalvikOpcode::SgetChar
                | DalvikOpcode::SgetShort
                | DalvikOpcode::Sput
                | DalvikOpcode::SputWide
                | DalvikOpcode::SputObject
                | DalvikOpcode::SputBoolean
                | DalvikOpcode::SputByte
                | DalvikOpcode::SputChar
                | DalvikOpcode::SputShort
        )
    }

    const fn is_format_23x(op: DalvikOpcode) -> bool {
        matches!(
            op,
            DalvikOpcode::AddInt
                | DalvikOpcode::SubInt
                | DalvikOpcode::MulInt
                | DalvikOpcode::DivInt
                | DalvikOpcode::RemInt
                | DalvikOpcode::AndInt
                | DalvikOpcode::OrInt
                | DalvikOpcode::XorInt
                | DalvikOpcode::ShlInt
                | DalvikOpcode::ShrInt
                | DalvikOpcode::UshrInt
                | DalvikOpcode::AddLong
                | DalvikOpcode::SubLong
                | DalvikOpcode::MulLong
                | DalvikOpcode::DivLong
                | DalvikOpcode::RemLong
                | DalvikOpcode::AndLong
                | DalvikOpcode::OrLong
                | DalvikOpcode::XorLong
                | DalvikOpcode::ShlLong
                | DalvikOpcode::ShrLong
                | DalvikOpcode::UshrLong
                | DalvikOpcode::AddFloat
                | DalvikOpcode::SubFloat
                | DalvikOpcode::MulFloat
                | DalvikOpcode::DivFloat
                | DalvikOpcode::RemFloat
                | DalvikOpcode::AddDouble
                | DalvikOpcode::SubDouble
                | DalvikOpcode::MulDouble
                | DalvikOpcode::DivDouble
                | DalvikOpcode::RemDouble
                | DalvikOpcode::CmplFloat
                | DalvikOpcode::CmpgFloat
                | DalvikOpcode::CmplDouble
                | DalvikOpcode::CmpgDouble
                | DalvikOpcode::CmpLong
                | DalvikOpcode::Aget
                | DalvikOpcode::AgetWide
                | DalvikOpcode::AgetObject
                | DalvikOpcode::AgetBoolean
                | DalvikOpcode::AgetByte
                | DalvikOpcode::AgetChar
                | DalvikOpcode::AgetShort
                | DalvikOpcode::Aput
                | DalvikOpcode::AputWide
                | DalvikOpcode::AputObject
                | DalvikOpcode::AputBoolean
                | DalvikOpcode::AputByte
                | DalvikOpcode::AputChar
                | DalvikOpcode::AputShort
        )
    }

    const fn is_format_11x(op: DalvikOpcode) -> bool {
        matches!(
            op,
            DalvikOpcode::MoveResult
                | DalvikOpcode::MoveResultWide
                | DalvikOpcode::MoveResultObject
                | DalvikOpcode::MoveException
                | DalvikOpcode::Return
                | DalvikOpcode::ReturnWide
                | DalvikOpcode::ReturnObject
                | DalvikOpcode::Throw
        )
    }

    fn decode_const_string(instr: &mut SmaliInstruction, code: &[u8], pos: usize, high_byte: u8) {
        instr.regs.push(high_byte);
        if pos + 3 < code.len() {
            let idx = u16::from_le_bytes([code[pos + 2], code[pos + 3]]);
            instr.string_idx = Some(u32::from(idx));
        }
    }

    fn decode_const_string_jumbo(
        instr: &mut SmaliInstruction,
        code: &[u8],
        pos: usize,
        high_byte: u8,
    ) {
        instr.regs.push(high_byte);
        if pos + 5 < code.len() {
            let idx =
                u32::from_le_bytes([code[pos + 2], code[pos + 3], code[pos + 4], code[pos + 5]]);
            instr.string_idx = Some(idx);
        }
    }

    fn decode_type_21c(instr: &mut SmaliInstruction, code: &[u8], pos: usize, high_byte: u8) {
        instr.regs.push(high_byte);
        if pos + 3 < code.len() {
            let idx = u16::from_le_bytes([code[pos + 2], code[pos + 3]]);
            instr.type_idx = Some(u32::from(idx));
        }
    }

    fn decode_type_22c(instr: &mut SmaliInstruction, code: &[u8], pos: usize, high_byte: u8) {
        instr.regs.push(high_byte & 0x0f);
        instr.regs.push((high_byte >> 4) & 0x0f);
        if pos + 3 < code.len() {
            let idx = u16::from_le_bytes([code[pos + 2], code[pos + 3]]);
            instr.type_idx = Some(u32::from(idx));
        }
    }

    fn decode_filled_new_array(
        instr: &mut SmaliInstruction,
        code: &[u8],
        pos: usize,
        high_byte: u8,
    ) {
        let reg_count = (high_byte >> 4) & 0x0f;
        if pos + 5 < code.len() {
            let idx = u16::from_le_bytes([code[pos + 2], code[pos + 3]]);
            instr.type_idx = Some(u32::from(idx));
            let reg_byte = code[pos + 4];
            let reg_byte2 = code[pos + 5];
            let v_c = reg_byte & 0x0f;
            let v_d = (reg_byte >> 4) & 0x0f;
            let v_e = reg_byte2 & 0x0f;
            let v_f = (reg_byte2 >> 4) & 0x0f;
            let v_g = high_byte & 0x0f;
            let all = [v_c, v_d, v_e, v_f, v_g];
            let take = (reg_count as usize).min(all.len());
            instr.regs.extend_from_slice(&all[..take]);
        }
    }

    fn decode_filled_new_array_range(
        instr: &mut SmaliInstruction,
        code: &[u8],
        pos: usize,
        high_byte: u8,
    ) {
        let reg_count = high_byte;
        if pos + 5 < code.len() {
            let idx = u16::from_le_bytes([code[pos + 2], code[pos + 3]]);
            instr.type_idx = Some(u32::from(idx));
            let first = u16::from_le_bytes([code[pos + 4], code[pos + 5]]);
            let first_lo = u8::try_from(first & 0xff).unwrap_or(0);
            for i in 0..reg_count {
                instr.regs.push(first_lo.wrapping_add(i));
            }
        }
    }

    fn decode_invoke_35c(instr: &mut SmaliInstruction, code: &[u8], pos: usize, high_byte: u8) {
        let reg_count = (high_byte >> 4) & 0x0f;
        if pos + 5 < code.len() {
            let idx = u16::from_le_bytes([code[pos + 2], code[pos + 3]]);
            instr.method_idx = Some(u32::from(idx));
            let reg_byte = code[pos + 4];
            let reg_byte2 = code[pos + 5];
            let v_c = reg_byte & 0x0f;
            let v_d = (reg_byte >> 4) & 0x0f;
            let v_e = reg_byte2 & 0x0f;
            let v_f = (reg_byte2 >> 4) & 0x0f;
            let v_g = high_byte & 0x0f;
            let all = [v_c, v_d, v_e, v_f, v_g];
            let take = (reg_count as usize).min(all.len());
            instr.regs.extend_from_slice(&all[..take]);
        }
    }

    fn decode_invoke_3rc(instr: &mut SmaliInstruction, code: &[u8], pos: usize, high_byte: u8) {
        let reg_count = high_byte;
        if pos + 5 < code.len() {
            let idx = u16::from_le_bytes([code[pos + 2], code[pos + 3]]);
            instr.method_idx = Some(u32::from(idx));
            let first = u16::from_le_bytes([code[pos + 4], code[pos + 5]]);
            let first_lo = u8::try_from(first & 0xff).unwrap_or(0);
            for i in 0..reg_count {
                instr.regs.push(first_lo.wrapping_add(i));
            }
        }
    }

    fn decode_const_21s(instr: &mut SmaliInstruction, code: &[u8], pos: usize, high_byte: u8) {
        instr.regs.push(high_byte);
        if pos + 3 < code.len() {
            let imm = i16::from_le_bytes([code[pos + 2], code[pos + 3]]);
            instr.literal = Some(i64::from(imm));
        }
    }

    fn decode_const_21h(instr: &mut SmaliInstruction, code: &[u8], pos: usize, high_byte: u8) {
        instr.regs.push(high_byte);
        if pos + 3 < code.len() {
            let imm = u16::from_le_bytes([code[pos + 2], code[pos + 3]]);
            instr.literal = Some(i64::from(imm) << 16);
        }
    }

    fn decode_const_31i(instr: &mut SmaliInstruction, code: &[u8], pos: usize, high_byte: u8) {
        instr.regs.push(high_byte);
        if pos + 5 < code.len() {
            let imm =
                i32::from_le_bytes([code[pos + 2], code[pos + 3], code[pos + 4], code[pos + 5]]);
            instr.literal = Some(i64::from(imm));
        }
    }

    fn decode_const_51l(instr: &mut SmaliInstruction, code: &[u8], pos: usize, high_byte: u8) {
        instr.regs.push(high_byte);
        if pos + 9 < code.len() {
            let imm = i64::from_le_bytes([
                code[pos + 2],
                code[pos + 3],
                code[pos + 4],
                code[pos + 5],
                code[pos + 6],
                code[pos + 7],
                code[pos + 8],
                code[pos + 9],
            ]);
            instr.literal = Some(imm);
        }
    }

    fn decode_goto16(instr: &mut SmaliInstruction, code: &[u8], pos: usize) {
        if pos + 3 < code.len() {
            let off = i16::from_le_bytes([code[pos + 2], code[pos + 3]]);
            instr.branch_target = Some(i32::from(off));
        }
    }

    fn decode_goto32(instr: &mut SmaliInstruction, code: &[u8], pos: usize) {
        if pos + 5 < code.len() {
            let off =
                i32::from_le_bytes([code[pos + 2], code[pos + 3], code[pos + 4], code[pos + 5]]);
            instr.branch_target = Some(off);
        }
    }

    fn decode_31t(instr: &mut SmaliInstruction, code: &[u8], pos: usize, high_byte: u8) {
        instr.regs.push(high_byte);
        if pos + 5 < code.len() {
            let off =
                i32::from_le_bytes([code[pos + 2], code[pos + 3], code[pos + 4], code[pos + 5]]);
            instr.branch_target = Some(off);
        }
    }

    fn decode_if_22t(instr: &mut SmaliInstruction, code: &[u8], pos: usize, high_byte: u8) {
        instr.regs.push(high_byte & 0x0f);
        instr.regs.push((high_byte >> 4) & 0x0f);
        if pos + 3 < code.len() {
            let off = i16::from_le_bytes([code[pos + 2], code[pos + 3]]);
            instr.branch_target = Some(i32::from(off));
        }
    }

    fn decode_if_21t(instr: &mut SmaliInstruction, code: &[u8], pos: usize, high_byte: u8) {
        instr.regs.push(high_byte);
        if pos + 3 < code.len() {
            let off = i16::from_le_bytes([code[pos + 2], code[pos + 3]]);
            instr.branch_target = Some(i32::from(off));
        }
    }

    fn decode_iget_iput(instr: &mut SmaliInstruction, code: &[u8], pos: usize, high_byte: u8) {
        instr.regs.push(high_byte & 0x0f);
        instr.regs.push((high_byte >> 4) & 0x0f);
        if pos + 3 < code.len() {
            let idx = u16::from_le_bytes([code[pos + 2], code[pos + 3]]);
            instr.field_idx = Some(u32::from(idx));
        }
    }

    fn decode_sget_sput(instr: &mut SmaliInstruction, code: &[u8], pos: usize, high_byte: u8) {
        instr.regs.push(high_byte);
        if pos + 3 < code.len() {
            let idx = u16::from_le_bytes([code[pos + 2], code[pos + 3]]);
            instr.field_idx = Some(u32::from(idx));
        }
    }

    fn decode_binop_lit16(instr: &mut SmaliInstruction, code: &[u8], pos: usize, high_byte: u8) {
        instr.regs.push(high_byte & 0x0f);
        instr.regs.push((high_byte >> 4) & 0x0f);
        if pos + 3 < code.len() {
            let lit = i16::from_le_bytes([code[pos + 2], code[pos + 3]]);
            instr.literal = Some(i64::from(lit));
        }
    }

    fn decode_binop_lit8(instr: &mut SmaliInstruction, code: &[u8], pos: usize, high_byte: u8) {
        instr.regs.push(high_byte);
        if pos + 3 < code.len() {
            instr.regs.push(code[pos + 2]);
            instr.literal = Some(i64::from(code[pos + 3].cast_signed()));
        }
    }

    fn decode_binop_23x(instr: &mut SmaliInstruction, code: &[u8], pos: usize, high_byte: u8) {
        instr.regs.push(high_byte);
        if pos + 3 < code.len() {
            instr.regs.push(code[pos + 2]);
            instr.regs.push(code[pos + 3]);
        }
    }

    fn decode_move_from16(instr: &mut SmaliInstruction, code: &[u8], pos: usize, high_byte: u8) {
        instr.regs.push(high_byte);
        if pos + 3 < code.len() {
            let r = u16::from_le_bytes([code[pos + 2], code[pos + 3]]);
            instr.regs.push(u8::try_from(r & 0xff).unwrap_or(0));
        }
    }

    /// Format a labeled branch target like `":goto_004f"`. Falls back to a
    /// "????" placeholder when no target is known.
    fn format_branch_label(
        prefix: &str,
        branch_target: Option<i32>,
        addr_of: &dyn Fn(i32) -> u32,
    ) -> String {
        branch_target.map_or_else(
            || format!(":{prefix}_????"),
            |t| format!(":{prefix}_{:04x}", addr_of(t)),
        )
    }

    /// Format a single `SmaliInstruction` as a smali text line.
    ///
    /// Uses `dex_ctx` for name resolution when available.
    #[must_use]
    pub fn to_smali_text(instr: &SmaliInstruction, dex_ctx: Option<&DexContext>) -> String {
        let dummy = DexContext::dummy();
        let ctx = dex_ctx.unwrap_or(&dummy);

        let mnemonic = opcode_to_smali(instr.op);

        // Helper to format a register as v<N>
        let fmt_reg = |r: u8| -> String { format!("v{r}") };

        // Build register list e.g. "{v0, v1, v2}"
        let reg_list_braced = || -> String {
            if instr.regs.is_empty() {
                "{}".to_string()
            } else {
                let inner: Vec<String> = instr.regs.iter().map(|&r| fmt_reg(r)).collect();
                format!("{{{}}}", inner.join(", "))
            }
        };

        let reg_list_plain = || -> String {
            instr
                .regs
                .iter()
                .map(|&r| fmt_reg(r))
                .collect::<Vec<_>>()
                .join(", ")
        };

        // Compute a branch label target as the wrapping sum of `instr.offset` and `t`.
        let branch_target_addr = |t: i32| -> u32 {
            let base = u32::try_from(instr.offset).unwrap_or(u32::MAX);
            base.wrapping_add(t.cast_unsigned())
        };

        let operands: String = match instr.op {
            // return-void — no operands
            DalvikOpcode::ReturnVoid | DalvikOpcode::Nop => String::new(),

            // const-string vAA, "..."
            DalvikOpcode::ConstString | DalvikOpcode::ConstStringJumbo => {
                let r = instr.regs.first().copied().unwrap_or(0);
                let s = instr.string_idx.map_or_else(|| "<?>".to_string(), |i| ctx.string(i));
                format!("{}, \"{}\"", fmt_reg(r), s)
            }

            // const-class / check-cast / new-instance: type ref
            DalvikOpcode::ConstClass | DalvikOpcode::CheckCast | DalvikOpcode::NewInstance => {
                let r = instr.regs.first().copied().unwrap_or(0);
                let t = instr.type_idx.map_or_else(|| "<?>".to_string(), |i| ctx.type_desc(i));
                format!("{}, {}", fmt_reg(r), t)
            }

            // instance-of / new-array: vA, vB, type@
            DalvikOpcode::InstanceOf | DalvikOpcode::NewArray => {
                let t = instr.type_idx.map_or_else(|| "<?>".to_string(), |i| ctx.type_desc(i));
                format!("{}, {}", reg_list_plain(), t)
            }

            // filled-new-array {vC..vG}, type@
            DalvikOpcode::FilledNewArray | DalvikOpcode::FilledNewArrayRange => {
                let t = instr.type_idx.map_or_else(|| "<?>".to_string(), |i| ctx.type_desc(i));
                format!("{}, {}", reg_list_braced(), t)
            }

            // iget/iput / sget/sput vA(,vB), field@
            op if Self::is_format_iget_iput(op) || Self::is_format_sget_sput(op) => {
                let f = instr.field_idx.map_or_else(|| "<?>".to_string(), |i| ctx.field(i));
                format!("{}, {}", reg_list_plain(), f)
            }

            // invoke-* {regs}, method@
            op if Self::is_format_invoke_35c(op) || Self::is_format_invoke_3rc(op) => {
                let m = instr.method_idx.map_or_else(|| "<?>".to_string(), |i| ctx.method(i));
                format!("{}, {}", reg_list_braced(), m)
            }

            // goto / goto16 / goto32 — branch target only
            DalvikOpcode::Goto | DalvikOpcode::Goto16 | DalvikOpcode::Goto32 => {
                Self::format_branch_label("goto", instr.branch_target, &branch_target_addr)
            }

            // if-* vA, vB, :label
            DalvikOpcode::IfEq | DalvikOpcode::IfNe | DalvikOpcode::IfLt
            | DalvikOpcode::IfGe | DalvikOpcode::IfGt | DalvikOpcode::IfLe
            // if-*z vAA, :label
            | DalvikOpcode::IfEqz | DalvikOpcode::IfNez | DalvikOpcode::IfLtz
            | DalvikOpcode::IfGez | DalvikOpcode::IfGtz | DalvikOpcode::IfLez => {
                let lbl = Self::format_branch_label("cond", instr.branch_target, &branch_target_addr);
                format!("{}, {}", reg_list_plain(), lbl)
            }

            // packed-switch / sparse-switch vAA, :label
            DalvikOpcode::PackedSwitch | DalvikOpcode::SparseSwitch => {
                let lbl = Self::format_branch_label("swtch", instr.branch_target, &branch_target_addr);
                format!("{}, {}", reg_list_plain(), lbl)
            }

            // const/4, const/16, const, const-wide/* — literal
            DalvikOpcode::Const4 | DalvikOpcode::Const16 | DalvikOpcode::Const
            | DalvikOpcode::ConstHigh16 | DalvikOpcode::ConstWide16
            | DalvikOpcode::ConstWide32 | DalvikOpcode::ConstWide
            | DalvikOpcode::ConstWideHigh16 => {
                let r = instr.regs.first().copied().unwrap_or(0);
                let lit = instr.literal.unwrap_or(0);
                format!("{}, {:#x}", fmt_reg(r), lit)
            }

            // binop/lit16 vA, vB, #+CC
            DalvikOpcode::AddIntLit16 | DalvikOpcode::RsubIntLit16
            | DalvikOpcode::MulIntLit16 | DalvikOpcode::DivIntLit16
            | DalvikOpcode::RemIntLit16 | DalvikOpcode::AndIntLit16
            | DalvikOpcode::OrIntLit16  | DalvikOpcode::XorIntLit16
            | DalvikOpcode::AddIntLit8  | DalvikOpcode::RsubIntLit8
            | DalvikOpcode::MulIntLit8  | DalvikOpcode::DivIntLit8
            | DalvikOpcode::RemIntLit8  | DalvikOpcode::AndIntLit8
            | DalvikOpcode::OrIntLit8   | DalvikOpcode::XorIntLit8
            | DalvikOpcode::ShlIntLit8  | DalvikOpcode::ShrIntLit8
            | DalvikOpcode::UshrIntLit8 => {
                let lit = instr.literal.unwrap_or(0);
                format!("{}, {:#x}", reg_list_plain(), lit)
            }

            // Default: just print registers
            _ => reg_list_plain(),
        };

        if operands.is_empty() {
            format!("    {mnemonic}")
        } else {
            format!("    {mnemonic} {operands}")
        }
    }
}

// ─── SmaliTextMethod ─────────────────────────────────────────────────────────

/// A Smali method as parsed from a text `.smali` file.
///
/// This is a higher-level, text-oriented representation used by
/// `SmaliClassParser` and `SmaliSearch`.  It is distinct from the lower-level
/// `SmaliMethod` (which uses bitflags and structured `SmaliInstr` operands).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmaliTextMethod {
    /// Simple method name (e.g. `onCreate`).
    pub name: String,
    /// Dalvik type descriptor including parameters and return type
    /// (e.g. `(Landroid/os/Bundle;)V`).
    pub descriptor: String,
    /// Access modifier tokens as they appear in the `.method` directive
    /// (e.g. `["public", "static"]`).
    pub access: Vec<String>,
    /// Raw instruction lines (trimmed), excluding the `.method`/`.end method`
    /// boundary lines.
    pub instructions: Vec<String>,
}

// ─── SmaliTextClass ───────────────────────────────────────────────────────────

/// A Smali class as parsed from a text `.smali` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmaliTextClass {
    /// Dalvik internal type name (e.g. `Lcom/example/Foo;`).
    pub name: String,
    /// Dalvik internal type name of the superclass.
    pub superclass: String,
    /// Dalvik internal type names of implemented interfaces.
    pub interfaces: Vec<String>,
    /// Methods declared in this class.
    pub methods: Vec<SmaliTextMethod>,
}

// ─── SmaliClassParser ─────────────────────────────────────────────────────────

/// Parses the text form of a Smali `.smali` class file into a `SmaliTextClass`.
pub struct SmaliClassParser;

impl SmaliClassParser {
    /// Parse a complete Smali class text and return a `SmaliTextClass`.
    ///
    /// Unrecognised directives are silently ignored.  If a required field
    /// (`.class`, `.super`) is missing, sensible defaults (`"Lunknown;"`) are
    /// used so that a value is always returned.
    #[must_use]
    pub fn parse_class(smali_text: &str) -> SmaliTextClass {
        let mut name = "Lunknown;".to_string();
        let mut superclass = "Ljava/lang/Object;".to_string();
        let mut interfaces = Vec::new();
        let mut methods = Vec::new();

        let mut in_method = false;
        let mut current_method: Option<SmaliTextMethod> = None;

        for raw_line in smali_text.lines() {
            let line = raw_line.trim();

            if line.starts_with(".class") {
                // .class [modifiers] Lsome/Class;
                if let Some(t) = line.split_whitespace().last() {
                    name = t.to_string();
                }
            } else if line.starts_with(".super") {
                // .super Ljava/lang/Object;
                if let Some(t) = line.split_whitespace().nth(1) {
                    superclass = t.to_string();
                }
            } else if line.starts_with(".implements") {
                // .implements Lsome/Interface;
                if let Some(t) = line.split_whitespace().nth(1) {
                    interfaces.push(t.to_string());
                }
            } else if line.starts_with(".method") && !in_method {
                // .method [access] name(desc)RetType
                in_method = true;
                let tokens: Vec<&str> = line.split_whitespace().collect();
                // Last token is "name(desc)RetType"
                let (method_name, descriptor, access) = Self::split_method_directive(&tokens[1..]);
                current_method = Some(SmaliTextMethod {
                    name: method_name,
                    descriptor,
                    access,
                    instructions: Vec::new(),
                });
            } else if line.starts_with(".end method") && in_method {
                in_method = false;
                if let Some(m) = current_method.take() {
                    methods.push(m);
                }
            } else if in_method
                && let Some(ref mut m) = current_method
                && !line.is_empty()
                && !line.starts_with('#')
            {
                m.instructions.push(line.to_string());
            }
        }

        // Handle unclosed .method blocks gracefully
        if let Some(m) = current_method {
            methods.push(m);
        }

        SmaliTextClass {
            name,
            superclass,
            interfaces,
            methods,
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────

    /// Split a `.method` directive token list into `(name, descriptor, access)`.
    ///
    /// Tokens are all words after `.method`, e.g.:
    /// `["public", "static", "final", "onCreate(Landroid/os/Bundle;)V"]`
    fn split_method_directive(tokens: &[&str]) -> (String, String, Vec<String>) {
        if tokens.is_empty() {
            return ("unknown".to_string(), "()V".to_string(), vec![]);
        }
        // Last token is the name+descriptor
        let last = tokens[tokens.len() - 1];
        let access: Vec<String> = tokens[..tokens.len() - 1]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();

        // Split on '(' to separate name from descriptor
        if let Some(paren) = last.find('(') {
            let method_name = last[..paren].to_string();
            let descriptor = last[paren..].to_string();
            (method_name, descriptor, access)
        } else {
            (last.to_string(), "()V".to_string(), access)
        }
    }
}

// ─── SmaliSearch ──────────────────────────────────────────────────────────────

/// Utility methods for searching across collections of parsed Smali classes.
pub struct SmaliSearch;

impl SmaliSearch {
    /// Find all methods named `name` across the given class list.
    ///
    /// Returns a `Vec` of `(&SmaliTextClass, &SmaliTextMethod)` pairs so the
    /// caller can inspect both the declaring class and the method.
    #[must_use]
    pub fn find_method_by_name<'a>(
        classes: &'a [SmaliTextClass],
        name: &str,
    ) -> Vec<(&'a SmaliTextClass, &'a SmaliTextMethod)> {
        classes
            .iter()
            .flat_map(|cls| {
                cls.methods
                    .iter()
                    .filter(|m| m.name == name)
                    .map(move |m| (cls, m))
            })
            .collect()
    }

    /// Return the indices of all instructions in `method` that contain `api`
    /// as a substring.
    ///
    /// This is useful for locating `invoke-*` calls to a particular Android
    /// API, e.g. `"Ljavax/crypto/Cipher;->getInstance"`.
    #[must_use]
    pub fn find_api_calls(method: &SmaliTextMethod, api: &str) -> Vec<usize> {
        method
            .instructions
            .iter()
            .enumerate()
            .filter(|(_, instr)| instr.contains(api))
            .map(|(i, _)| i)
            .collect()
    }

    /// Return the indices of all instructions in `method` that reference the
    /// string literal `s` (i.e. `const-string` lines containing `s`).
    #[must_use]
    pub fn find_string_refs(method: &SmaliTextMethod, s: &str) -> Vec<usize> {
        method
            .instructions
            .iter()
            .enumerate()
            .filter(|(_, instr)| {
                (instr.contains("const-string") || instr.contains("const/string"))
                    && instr.contains(s)
            })
            .map(|(i, _)| i)
            .collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smali_reg_display_v() {
        let r = SmaliReg { num: 0 };
        assert_eq!(r.to_string(), "v0");
    }

    #[test]
    fn test_smali_reg_display_v_max() {
        let r = SmaliReg { num: 63 };
        assert_eq!(r.to_string(), "v63");
    }

    #[test]
    fn test_smali_reg_display_p() {
        let r = SmaliReg { num: 64 };
        assert_eq!(r.to_string(), "p0");
    }

    #[test]
    fn test_smali_reg_display_p1() {
        let r = SmaliReg { num: 65 };
        assert_eq!(r.to_string(), "p1");
    }

    #[test]
    fn test_smali_op_display_nop() {
        assert_eq!(SmaliOp::Nop.to_string(), "nop");
    }

    #[test]
    fn test_smali_op_display_invoke_virtual() {
        assert_eq!(SmaliOp::InvokeVirtual.to_string(), "invoke-virtual");
    }

    #[test]
    fn test_smali_op_display_other() {
        assert_eq!(
            SmaliOp::Other("custom-op".to_string()).to_string(),
            "custom-op"
        );
    }

    #[test]
    fn test_smali_op_display_const_string() {
        assert_eq!(SmaliOp::ConstString.to_string(), "const-string");
    }

    #[test]
    fn test_smali_operand_display_reg() {
        let op = SmaliOperand::Reg(SmaliReg { num: 3 });
        assert_eq!(op.to_string(), "v3");
    }

    #[test]
    fn test_smali_operand_display_literal() {
        let op = SmaliOperand::Literal(255);
        assert_eq!(op.to_string(), "0xff");
    }

    #[test]
    fn test_smali_operand_display_str() {
        let op = SmaliOperand::Str("hello".to_string());
        assert_eq!(op.to_string(), "\"hello\"");
    }

    #[test]
    fn test_smali_instr_to_text_no_operands() {
        let i = SmaliInstr {
            op: SmaliOp::ReturnVoid,
            operands: vec![],
            label: None,
        };
        assert_eq!(i.to_text(), "return-void");
    }

    #[test]
    fn test_smali_instr_to_text_with_label() {
        let i = SmaliInstr {
            op: SmaliOp::Nop,
            operands: vec![],
            label: Some(":label_0".to_string()),
        };
        assert!(i.to_text().contains(":label_0"));
        assert!(i.to_text().contains("nop"));
    }

    #[test]
    fn test_smali_instr_to_text_with_operands() {
        let i = SmaliInstr {
            op: SmaliOp::Move,
            operands: vec![
                SmaliOperand::Reg(SmaliReg { num: 0 }),
                SmaliOperand::Reg(SmaliReg { num: 1 }),
            ],
            label: None,
        };
        assert_eq!(i.to_text(), "move v0, v1");
    }

    #[test]
    fn test_smali_access_flags() {
        let flags = SmaliAccess::PUBLIC | SmaliAccess::STATIC;
        assert!(flags.contains(SmaliAccess::PUBLIC));
        assert!(flags.contains(SmaliAccess::STATIC));
        assert!(!flags.contains(SmaliAccess::PRIVATE));
    }

    #[test]
    fn test_smali_method_is_constructor_init() {
        let m = SmaliMethod {
            name: "<init>".to_string(),
            class: "Lfoo;".to_string(),
            signature: "()V".to_string(),
            access: SmaliAccess::PUBLIC | SmaliAccess::CONSTRUCTOR,
            registers: 1,
            instructions: vec![],
        };
        assert!(m.is_constructor());
    }

    #[test]
    fn test_smali_method_is_constructor_clinit() {
        let m = SmaliMethod {
            name: "<clinit>".to_string(),
            class: "Lfoo;".to_string(),
            signature: "()V".to_string(),
            access: SmaliAccess::STATIC | SmaliAccess::CONSTRUCTOR,
            registers: 0,
            instructions: vec![],
        };
        assert!(m.is_constructor());
    }

    #[test]
    fn test_smali_method_is_not_constructor() {
        let m = SmaliMethod {
            name: "execute".to_string(),
            class: "Lfoo;".to_string(),
            signature: "()V".to_string(),
            access: SmaliAccess::PUBLIC,
            registers: 2,
            instructions: vec![],
        };
        assert!(!m.is_constructor());
    }

    #[test]
    fn test_smali_method_instr_count() {
        let m = SmaliMethod {
            name: "foo".to_string(),
            class: "Lfoo;".to_string(),
            signature: "()V".to_string(),
            access: SmaliAccess::PUBLIC,
            registers: 1,
            instructions: vec![
                SmaliInstr {
                    op: SmaliOp::Nop,
                    operands: vec![],
                    label: None,
                },
                SmaliInstr {
                    op: SmaliOp::ReturnVoid,
                    operands: vec![],
                    label: None,
                },
            ],
        };
        assert_eq!(m.instr_count(), 2);
    }

    #[test]
    fn mock_from_a_bare_name_invents_nothing() {
        let c = SmaliClass::mock("Lcom/example/Foo;");
        assert_eq!(c.name, "Lcom/example/Foo;");
        assert!(c.methods.is_empty(), "a class name cannot imply methods");
        assert!(c.fields.is_empty(), "a class name cannot imply fields");
        assert!(c.interfaces.is_empty());
    }

    #[test]
    fn test_smali_class_mock() {
        let c = SmaliClass::synthetic_fixture("Lcom/example/Foo;");
        assert_eq!(c.name, "Lcom/example/Foo;");
    }

    #[test]
    fn test_smali_class_find_method() {
        let c = SmaliClass::synthetic_fixture("Lcom/example/Foo;");
        let m = c.find_method("<init>");
        assert!(m.is_some());
        assert!(m.unwrap().is_constructor());
    }

    #[test]
    fn test_smali_class_find_method_not_found() {
        let c = SmaliClass::synthetic_fixture("Lcom/example/Foo;");
        assert!(c.find_method("nonexistent").is_none());
    }

    #[test]
    fn test_smali_class_static_methods() {
        let c = SmaliClass::synthetic_fixture("Lcom/example/Foo;");
        let statics = c.static_methods();
        assert!(!statics.is_empty());
        assert!(
            statics
                .iter()
                .all(|m| m.access.contains(SmaliAccess::STATIC))
        );
    }

    #[test]
    fn test_smali_error_parse() {
        let e = SmaliError::ParseError("bad token".to_string());
        assert!(e.to_string().contains("bad token"));
    }

    #[test]
    fn test_smali_error_invalid_op() {
        let e = SmaliError::InvalidOp("??".to_string());
        assert!(e.to_string().contains("??"));
    }

    #[test]
    fn test_smali_error_invalid_reg() {
        let e = SmaliError::InvalidReg(255);
        assert!(e.to_string().contains("255"));
    }

    #[test]
    fn test_smali_class_serialization() {
        let c = SmaliClass::synthetic_fixture("Lfoo;");
        let json = serde_json::to_string(&c).unwrap();
        let decoded: SmaliClass = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.name, c.name);
    }

    #[test]
    fn test_smali_op_all_variants_display() {
        let ops = [
            SmaliOp::Nop,
            SmaliOp::Move,
            SmaliOp::MoveWide,
            SmaliOp::MoveObject,
            SmaliOp::MoveResult,
            SmaliOp::ReturnVoid,
            SmaliOp::Return,
            SmaliOp::Const4,
            SmaliOp::Const16,
            SmaliOp::Const,
            SmaliOp::ConstString,
            SmaliOp::Goto,
            SmaliOp::IfEq,
            SmaliOp::IfNe,
            SmaliOp::IfLt,
            SmaliOp::IfGe,
            SmaliOp::IfGt,
            SmaliOp::IfLe,
            SmaliOp::IfEqz,
            SmaliOp::IfNez,
            SmaliOp::IGet,
            SmaliOp::IPut,
            SmaliOp::SGet,
            SmaliOp::SPut,
            SmaliOp::InvokeVirtual,
            SmaliOp::InvokeSuper,
            SmaliOp::InvokeDirect,
            SmaliOp::InvokeStatic,
            SmaliOp::InvokeInterface,
            SmaliOp::NewInstance,
            SmaliOp::ArrayLength,
            SmaliOp::CheckCast,
        ];
        for op in &ops {
            assert!(!op.to_string().is_empty());
        }
    }

    // ── DalvikOpcode tests ────────────────────────────────────────────────────

    #[test]
    fn test_dalvik_opcode_from_byte_spot_check() {
        assert_eq!(DalvikOpcode::from_byte(0x00), DalvikOpcode::Nop);
        assert_eq!(DalvikOpcode::from_byte(0x01), DalvikOpcode::Move);
        assert_eq!(DalvikOpcode::from_byte(0x0e), DalvikOpcode::ReturnVoid);
        assert_eq!(DalvikOpcode::from_byte(0x1a), DalvikOpcode::ConstString);
        assert_eq!(DalvikOpcode::from_byte(0x6e), DalvikOpcode::InvokeVirtual);
        assert_eq!(DalvikOpcode::from_byte(0x90), DalvikOpcode::AddInt);
        assert_eq!(DalvikOpcode::from_byte(0xd8), DalvikOpcode::AddIntLit8);
    }

    #[test]
    fn test_dalvik_opcode_as_byte_roundtrip() {
        for b in 0u8..=255 {
            assert_eq!(DalvikOpcode::from_byte(b).as_byte(), b);
        }
    }

    #[test]
    fn test_opcode_to_smali_mnemonics() {
        assert_eq!(opcode_to_smali(DalvikOpcode::Nop), "nop");
        assert_eq!(
            opcode_to_smali(DalvikOpcode::InvokeVirtual),
            "invoke-virtual"
        );
        assert_eq!(opcode_to_smali(DalvikOpcode::InvokeStatic), "invoke-static");
        assert_eq!(opcode_to_smali(DalvikOpcode::ConstString), "const-string");
        assert_eq!(opcode_to_smali(DalvikOpcode::ReturnVoid), "return-void");
        assert_eq!(opcode_to_smali(DalvikOpcode::AddInt), "add-int");
        assert_eq!(opcode_to_smali(DalvikOpcode::AddIntLit8), "add-int/lit8");
        assert_eq!(opcode_to_smali(DalvikOpcode::ShlIntLit8), "shl-int/lit8");
        assert_eq!(opcode_to_smali(DalvikOpcode::IfEq), "if-eq");
        assert_eq!(opcode_to_smali(DalvikOpcode::IfEqz), "if-eqz");
        assert_eq!(opcode_to_smali(DalvikOpcode::CmplFloat), "cmpl-float");
        assert_eq!(opcode_to_smali(DalvikOpcode::CmpLong), "cmp-long");
        assert_eq!(opcode_to_smali(DalvikOpcode::MoveFrom16), "move/from16");
        assert_eq!(
            opcode_to_smali(DalvikOpcode::MoveResultObject),
            "move-result-object"
        );
        assert_eq!(opcode_to_smali(DalvikOpcode::CheckCast), "check-cast");
        assert_eq!(opcode_to_smali(DalvikOpcode::NewInstance), "new-instance");
        assert_eq!(opcode_to_smali(DalvikOpcode::Goto16), "goto/16");
        assert_eq!(opcode_to_smali(DalvikOpcode::Goto32), "goto/32");
        assert_eq!(opcode_to_smali(DalvikOpcode::PackedSwitch), "packed-switch");
        assert_eq!(opcode_to_smali(DalvikOpcode::SparseSwitch), "sparse-switch");
        assert_eq!(opcode_to_smali(DalvikOpcode::NegInt), "neg-int");
        assert_eq!(opcode_to_smali(DalvikOpcode::IntToLong), "int-to-long");
        assert_eq!(opcode_to_smali(DalvikOpcode::AddInt2addr), "add-int/2addr");
        assert_eq!(
            opcode_to_smali(DalvikOpcode::InvokePolymorphic),
            "invoke-polymorphic"
        );
        assert_eq!(
            opcode_to_smali(DalvikOpcode::ConstMethodHandle),
            "const-method-handle"
        );
    }

    #[test]
    fn test_instruction_size_nop() {
        assert_eq!(instruction_size_bytes(DalvikOpcode::Nop), 2);
    }

    #[test]
    fn test_instruction_size_const_string() {
        assert_eq!(instruction_size_bytes(DalvikOpcode::ConstString), 4);
    }

    #[test]
    fn test_instruction_size_invoke_virtual() {
        assert_eq!(instruction_size_bytes(DalvikOpcode::InvokeVirtual), 6);
    }

    #[test]
    fn test_instruction_size_const_wide() {
        assert_eq!(instruction_size_bytes(DalvikOpcode::ConstWide), 10);
    }

    #[test]
    fn test_instruction_size_const() {
        assert_eq!(instruction_size_bytes(DalvikOpcode::Const), 6);
    }

    #[test]
    fn test_instruction_size_goto() {
        assert_eq!(instruction_size_bytes(DalvikOpcode::Goto), 2);
        assert_eq!(instruction_size_bytes(DalvikOpcode::Goto16), 4);
        assert_eq!(instruction_size_bytes(DalvikOpcode::Goto32), 6);
    }

    // ── DexContext tests ──────────────────────────────────────────────────────

    #[test]
    fn test_dex_context_dummy_empty() {
        let ctx = DexContext::dummy();
        assert!(ctx.strings.is_empty());
        assert!(ctx.types.is_empty());
        assert!(ctx.methods.is_empty());
        assert!(ctx.fields.is_empty());
    }

    #[test]
    fn test_dex_context_string_lookup() {
        let ctx = DexContext {
            strings: vec!["Hello World".to_string()],
            ..DexContext::default()
        };
        assert_eq!(ctx.string(0), "Hello World");
        // Out of range should return placeholder
        assert!(ctx.string(99).contains("string@"));
    }

    #[test]
    fn test_dex_context_type_lookup() {
        let ctx = DexContext {
            types: vec!["Ljava/lang/String;".to_string()],
            ..DexContext::default()
        };
        assert_eq!(ctx.type_desc(0), "Ljava/lang/String;");
        assert!(ctx.type_desc(5).contains("type@"));
    }

    #[test]
    fn test_dex_context_method_lookup() {
        let ctx = DexContext {
            methods: vec!["Ljava/io/PrintStream;->println(Ljava/lang/String;)V".to_string()],
            ..DexContext::default()
        };
        assert!(ctx.method(0).contains("println"));
        assert!(ctx.method(99).contains("method@"));
    }

    #[test]
    fn test_dex_context_field_lookup() {
        let ctx = DexContext {
            fields: vec!["Lcom/example/Foo;->count:I".to_string()],
            ..DexContext::default()
        };
        assert!(ctx.field(0).contains("count"));
        assert!(ctx.field(99).contains("field@"));
    }

    // ── SmaliDisassembler tests ───────────────────────────────────────────────

    #[test]
    fn test_disassemble_return_void() {
        // 0x0e 0x00 = return-void
        let code = [0x0eu8, 0x00];
        let instrs = SmaliDisassembler::disassemble_bytecode(&code, 0);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].op, DalvikOpcode::ReturnVoid);
        assert_eq!(instrs[0].offset, 0);
    }

    #[test]
    fn test_disassemble_nop() {
        let code = [0x00u8, 0x00];
        let instrs = SmaliDisassembler::disassemble_bytecode(&code, 0);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].op, DalvikOpcode::Nop);
    }

    #[test]
    fn test_disassemble_const4() {
        // const/4 v0, #1  — opcode=0x12, high=0x10 (vA=0, B=1)
        let code = [0x12u8, 0x10];
        let instrs = SmaliDisassembler::disassemble_bytecode(&code, 0);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].op, DalvikOpcode::Const4);
        assert_eq!(instrs[0].regs[0], 0); // vA
    }

    #[test]
    fn test_disassemble_multiple_instructions() {
        // nop + return-void
        let code = [0x00u8, 0x00, 0x0e, 0x00];
        let instrs = SmaliDisassembler::disassemble_bytecode(&code, 0);
        assert_eq!(instrs.len(), 2);
        assert_eq!(instrs[0].op, DalvikOpcode::Nop);
        assert_eq!(instrs[1].op, DalvikOpcode::ReturnVoid);
        assert_eq!(instrs[1].offset, 2);
    }

    #[test]
    fn test_disassemble_const_string() {
        // const-string v0, string@0001
        // bytes: 0x1a, 0x00, 0x01, 0x00
        let code = [0x1au8, 0x00, 0x01, 0x00];
        let instrs = SmaliDisassembler::disassemble_bytecode(&code, 0);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].op, DalvikOpcode::ConstString);
        assert_eq!(instrs[0].regs[0], 0);
        assert_eq!(instrs[0].string_idx, Some(1));
    }

    #[test]
    fn test_disassemble_goto() {
        // goto +4  (0x28, 0x04)
        let code = [0x28u8, 0x04];
        let instrs = SmaliDisassembler::disassemble_bytecode(&code, 0);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].op, DalvikOpcode::Goto);
        assert_eq!(instrs[0].branch_target, Some(4));
    }

    #[test]
    fn test_disassemble_with_offset() {
        let code = [0x00u8, 0x00];
        let instrs = SmaliDisassembler::disassemble_bytecode(&code, 0x100);
        assert_eq!(instrs[0].offset, 0x100);
    }

    #[test]
    fn test_to_smali_text_return_void() {
        let instr = SmaliInstruction {
            offset: 0,
            op: DalvikOpcode::ReturnVoid,
            regs: vec![],
            string_idx: None,
            type_idx: None,
            field_idx: None,
            method_idx: None,
            literal: None,
            branch_target: None,
        };
        let text = SmaliDisassembler::to_smali_text(&instr, None);
        assert_eq!(text, "    return-void");
    }

    #[test]
    fn test_to_smali_text_const_string_with_ctx() {
        let ctx = DexContext {
            strings: vec!["Hello World".to_string()],
            ..DexContext::default()
        };
        let instr = SmaliInstruction {
            offset: 0,
            op: DalvikOpcode::ConstString,
            regs: vec![0],
            string_idx: Some(0),
            type_idx: None,
            field_idx: None,
            method_idx: None,
            literal: None,
            branch_target: None,
        };
        let text = SmaliDisassembler::to_smali_text(&instr, Some(&ctx));
        assert_eq!(text, "    const-string v0, \"Hello World\"");
    }

    #[test]
    fn test_to_smali_text_invoke_virtual_with_ctx() {
        let ctx = DexContext {
            methods: vec!["Ljava/io/PrintStream;->println(Ljava/lang/String;)V".to_string()],
            ..DexContext::default()
        };
        let instr = SmaliInstruction {
            offset: 0,
            op: DalvikOpcode::InvokeVirtual,
            regs: vec![0, 1],
            string_idx: None,
            type_idx: None,
            field_idx: None,
            method_idx: Some(0),
            literal: None,
            branch_target: None,
        };
        let text = SmaliDisassembler::to_smali_text(&instr, Some(&ctx));
        assert!(text.contains("invoke-virtual"));
        assert!(text.contains("{v0, v1}"));
        assert!(text.contains("println"));
    }

    #[test]
    fn test_to_smali_text_goto_label() {
        let instr = SmaliInstruction {
            offset: 0,
            op: DalvikOpcode::Goto,
            regs: vec![],
            string_idx: None,
            type_idx: None,
            field_idx: None,
            method_idx: None,
            literal: None,
            branch_target: Some(8),
        };
        let text = SmaliDisassembler::to_smali_text(&instr, None);
        assert!(text.contains("goto"));
        assert!(text.contains(":goto_"));
    }

    #[test]
    fn test_to_smali_text_add_int() {
        let instr = SmaliInstruction {
            offset: 0,
            op: DalvikOpcode::AddInt,
            regs: vec![0, 1, 2],
            string_idx: None,
            type_idx: None,
            field_idx: None,
            method_idx: None,
            literal: None,
            branch_target: None,
        };
        let text = SmaliDisassembler::to_smali_text(&instr, None);
        assert!(text.contains("add-int"));
        assert!(text.contains("v0, v1, v2"));
    }

    #[test]
    fn test_to_smali_text_if_eq() {
        let instr = SmaliInstruction {
            offset: 0,
            op: DalvikOpcode::IfEq,
            regs: vec![0, 1],
            string_idx: None,
            type_idx: None,
            field_idx: None,
            method_idx: None,
            literal: None,
            branch_target: Some(4),
        };
        let text = SmaliDisassembler::to_smali_text(&instr, None);
        assert!(text.contains("if-eq"));
        assert!(text.contains("v0, v1"));
        assert!(text.contains(":cond_"));
    }

    #[test]
    fn test_dalvik_opcode_serialization() {
        let op = DalvikOpcode::InvokeVirtual;
        let json = serde_json::to_string(&op).unwrap();
        let decoded: DalvikOpcode = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, DalvikOpcode::InvokeVirtual);
    }

    #[test]
    fn test_smali_instruction_serialization() {
        let instr = SmaliInstruction {
            offset: 42,
            op: DalvikOpcode::ConstString,
            regs: vec![0],
            string_idx: Some(3),
            type_idx: None,
            field_idx: None,
            method_idx: None,
            literal: None,
            branch_target: None,
        };
        let json = serde_json::to_string(&instr).unwrap();
        let decoded: SmaliInstruction = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.offset, 42);
        assert_eq!(decoded.op, DalvikOpcode::ConstString);
        assert_eq!(decoded.string_idx, Some(3));
    }

    // ── SmaliClassParser ──────────────────────────────────────────────────

    #[test]
    fn test_parse_class_basic() {
        let smali = r"
.class public Lcom/example/Foo;
.super Ljava/lang/Object;
.implements Ljava/io/Serializable;

.method public constructor <init>()V
    return-void
.end method
";
        let cls = SmaliClassParser::parse_class(smali);
        assert_eq!(cls.name, "Lcom/example/Foo;");
        assert_eq!(cls.superclass, "Ljava/lang/Object;");
        assert_eq!(cls.interfaces, vec!["Ljava/io/Serializable;"]);
        assert_eq!(cls.methods.len(), 1);
        let m = &cls.methods[0];
        assert_eq!(m.name, "<init>");
        assert_eq!(m.descriptor, "()V");
        assert!(m.access.contains(&"public".to_string()));
        assert!(m.access.contains(&"constructor".to_string()));
    }

    #[test]
    fn test_parse_class_multiple_methods() {
        let smali = r"
.class public Lcom/example/Bar;
.super Ljava/lang/Object;

.method public static doSomething(Ljava/lang/String;)Z
    const/4 v0, 0x0
    return v0
.end method

.method private helper()V
    return-void
.end method
";
        let cls = SmaliClassParser::parse_class(smali);
        assert_eq!(cls.methods.len(), 2);
        assert_eq!(cls.methods[0].name, "doSomething");
        assert_eq!(cls.methods[0].descriptor, "(Ljava/lang/String;)Z");
        assert!(cls.methods[0].access.contains(&"static".to_string()));
        assert_eq!(cls.methods[1].name, "helper");
        assert!(cls.methods[1].access.contains(&"private".to_string()));
    }

    #[test]
    fn test_parse_class_empty_input() {
        let cls = SmaliClassParser::parse_class("");
        assert_eq!(cls.name, "Lunknown;");
        assert_eq!(cls.superclass, "Ljava/lang/Object;");
        assert!(cls.methods.is_empty());
    }

    // ── SmaliSearch ───────────────────────────────────────────────────────

    #[test]
    fn test_find_method_by_name() {
        let cls1 = SmaliClassParser::parse_class(
            ".class public LA;\n.super Ljava/lang/Object;\n.method public foo()V\nreturn-void\n.end method\n",
        );
        let cls2 = SmaliClassParser::parse_class(
            ".class public LB;\n.super Ljava/lang/Object;\n.method public bar()V\nreturn-void\n.end method\n",
        );
        let classes = vec![cls1, cls2];
        let results = SmaliSearch::find_method_by_name(&classes, "foo");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.name, "LA;");
    }

    #[test]
    fn test_find_api_calls() {
        let method = SmaliTextMethod {
            name: "test".to_string(),
            descriptor: "()V".to_string(),
            access: vec![],
            instructions: vec![
                "invoke-virtual {v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V".to_string(),
                "invoke-static {v1}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;".to_string(),
                "return-void".to_string(),
            ],
        };
        let hits = SmaliSearch::find_api_calls(&method, "Ljavax/crypto/Cipher;->getInstance");
        assert_eq!(hits, vec![1]);
    }

    #[test]
    fn test_find_string_refs() {
        let method = SmaliTextMethod {
            name: "test".to_string(),
            descriptor: "()V".to_string(),
            access: vec![],
            instructions: vec![
                "const-string v0, \"hello\"".to_string(),
                "const-string v1, \"world\"".to_string(),
                "return-void".to_string(),
            ],
        };
        let hits = SmaliSearch::find_string_refs(&method, "hello");
        assert_eq!(hits, vec![0]);
        let all = SmaliSearch::find_string_refs(&method, "const-string");
        assert_eq!(all.len(), 2);
    }
}

// ─── Dalvik type descriptor parser ───────────────────────────────────────────

/// Convert a JVM/Dalvik field type descriptor to a human-readable Java name.
///
/// Handles:
/// - Primitive types: `B C D F I J S Z`
/// - Object references: `Lpackage/ClassName;` → `package.ClassName`
/// - Array types: `[T` → `T[]`, `[[T` → `T[][]`
/// - Method descriptors: `(params)return` → split into param list + return type
#[must_use]
pub fn parse_type_descriptor(desc: &str) -> String {
    parse_one_type(desc.as_bytes(), &mut 0)
}

fn parse_one_type(bytes: &[u8], pos: &mut usize) -> String {
    if *pos >= bytes.len() {
        return "void".to_string();
    }
    let b = bytes[*pos];
    *pos += 1;
    match b {
        b'B' => "byte".to_string(),
        b'C' => "char".to_string(),
        b'D' => "double".to_string(),
        b'F' => "float".to_string(),
        b'I' => "int".to_string(),
        b'J' => "long".to_string(),
        b'S' => "short".to_string(),
        b'Z' => "boolean".to_string(),
        b'V' => "void".to_string(),
        b'[' => {
            let inner = parse_one_type(bytes, pos);
            format!("{inner}[]")
        }
        b'L' => {
            // Object reference: Lfoo/bar/Baz; → foo.bar.Baz
            let start = *pos;
            while *pos < bytes.len() && bytes[*pos] != b';' {
                *pos += 1;
            }
            let class_bytes = &bytes[start..*pos];
            if *pos < bytes.len() {
                *pos += 1; // consume ';'
            }
            let class_name = std::str::from_utf8(class_bytes).unwrap_or("?");
            class_name.replace('/', ".")
        }
        other => {
            // Unknown — return raw character
            String::from(other as char)
        }
    }
}

/// Parse a full Dalvik method descriptor `(params)return` into param type list + return type.
///
/// Returns `(Vec<String>, String)` where the first element is the list of
/// parameter type names and the second is the return type name.
#[must_use]
pub fn parse_method_descriptor(desc: &str) -> (Vec<String>, String) {
    let bytes = desc.as_bytes();
    if bytes.is_empty() || bytes[0] != b'(' {
        return (vec![], "void".to_string());
    }
    let mut pos = 1usize; // skip '('
    let mut params = Vec::new();
    while pos < bytes.len() && bytes[pos] != b')' {
        params.push(parse_one_type(bytes, &mut pos));
    }
    pos += 1; // skip ')'
    let ret = if pos < bytes.len() {
        parse_one_type(bytes, &mut pos)
    } else {
        "void".to_string()
    };
    (params, ret)
}

// ─── Smali round-trip assembler/disassembler stubs ──────────────────────────

/// A Dalvik bytecode assembler that converts `SmaliInstruction` streams to raw
/// Dalvik bytecode bytes (little-endian 16-bit code units).
///
/// This is a best-effort assembler supporting the most common instruction
/// formats.  Instructions with variable-length encoding (e.g. switch payloads)
/// are emitted as raw NOP padding and must be replaced by the caller.
pub struct DalvikAssembler;

impl DalvikAssembler {
    /// Assemble a single `SmaliInstruction` into its raw Dalvik bytes.
    ///
    /// Returns the encoded bytes for the instruction.  Unknown or unimplemented
    /// encodings fall back to a two-byte NOP (`0x00 0x00`).
    #[must_use]
    pub fn encode(instr: &SmaliInstruction) -> Vec<u8> {
        let op = instr.op.as_byte();
        let size = instruction_size_bytes(instr.op);

        // Tiny instructions: 2-byte NOP / return-void / nop
        if size == 2 {
            Self::encode_2(instr, op)
        } else if size == 4 {
            // 4-byte instructions
            match instr.op {
                DalvikOpcode::Const16 => {
                    let va = instr.regs.first().copied().unwrap_or(0);
                    let lit = i16::try_from(
                        instr
                            .literal
                            .unwrap_or(0)
                            .clamp(i64::from(i16::MIN), i64::from(i16::MAX)),
                    )
                    .unwrap_or(0);
                    let [lo, hi] = lit.to_le_bytes();
                    vec![0x13, va, lo, hi]
                }
                DalvikOpcode::Goto16 => {
                    let off = i16::try_from(
                        instr
                            .branch_target
                            .unwrap_or(0)
                            .clamp(i32::from(i16::MIN), i32::from(i16::MAX)),
                    )
                    .unwrap_or(0);
                    let [lo, hi] = off.to_le_bytes();
                    vec![0x29, 0x00, lo, hi]
                }
                DalvikOpcode::ConstString => {
                    let va = instr.regs.first().copied().unwrap_or(0);
                    let idx = u16::try_from(instr.string_idx.unwrap_or(0) & 0xffff).unwrap_or(0);
                    let [lo, hi] = idx.to_le_bytes();
                    vec![0x1A, va, lo, hi]
                }
                DalvikOpcode::NewInstance => {
                    let va = instr.regs.first().copied().unwrap_or(0);
                    let idx = u16::try_from(instr.type_idx.unwrap_or(0) & 0xffff).unwrap_or(0);
                    let [lo, hi] = idx.to_le_bytes();
                    vec![0x22, va, lo, hi]
                }
                DalvikOpcode::IfEq
                | DalvikOpcode::IfNe
                | DalvikOpcode::IfLt
                | DalvikOpcode::IfGe
                | DalvikOpcode::IfGt
                | DalvikOpcode::IfLe => {
                    let va = instr.regs.first().copied().unwrap_or(0) & 0x0F;
                    let vb = instr.regs.get(1).copied().unwrap_or(0) & 0x0F;
                    let off = i16::try_from(
                        instr
                            .branch_target
                            .unwrap_or(0)
                            .clamp(i32::from(i16::MIN), i32::from(i16::MAX)),
                    )
                    .unwrap_or(0);
                    let [lo, hi] = off.to_le_bytes();
                    vec![op, (vb << 4) | va, lo, hi]
                }
                DalvikOpcode::IfEqz
                | DalvikOpcode::IfNez
                | DalvikOpcode::IfLtz
                | DalvikOpcode::IfGez
                | DalvikOpcode::IfGtz
                | DalvikOpcode::IfLez => {
                    let va = instr.regs.first().copied().unwrap_or(0);
                    let off = i16::try_from(
                        instr
                            .branch_target
                            .unwrap_or(0)
                            .clamp(i32::from(i16::MIN), i32::from(i16::MAX)),
                    )
                    .unwrap_or(0);
                    let [lo, hi] = off.to_le_bytes();
                    vec![op, va, lo, hi]
                }
                _ => {
                    let va = instr.regs.first().copied().unwrap_or(0);
                    let idx_raw = instr
                        .type_idx
                        .or(instr.method_idx)
                        .or(instr.field_idx)
                        .or(instr.string_idx)
                        .unwrap_or(0);
                    let idx = u16::try_from(idx_raw & 0xffff).unwrap_or(0);
                    let [lo, hi] = idx.to_le_bytes();
                    vec![op, va, lo, hi]
                }
            }
        } else if size == 6 {
            // 6-byte invoke instructions
            let method_idx = u16::try_from(instr.method_idx.unwrap_or(0) & 0xffff).unwrap_or(0);
            let [m_lo, m_hi] = method_idx.to_le_bytes();
            let reg_count = u8::try_from(instr.regs.len() & 0xff).unwrap_or(0);
            let r0 = instr.regs.first().copied().unwrap_or(0) & 0x0F;
            let r1 = instr.regs.get(1).copied().unwrap_or(0) & 0x0F;
            let r2 = instr.regs.get(2).copied().unwrap_or(0) & 0x0F;
            let r3 = instr.regs.get(3).copied().unwrap_or(0) & 0x0F;
            let r4 = instr.regs.get(4).copied().unwrap_or(0) & 0x0F;
            vec![
                op,
                (reg_count << 4) | r4,
                m_lo,
                m_hi,
                (r1 << 4) | r0,
                (r3 << 4) | r2,
            ]
        } else {
            // Fallback: emit NOP
            vec![0x00, 0x00]
        }
    }

    fn encode_2(instr: &SmaliInstruction, op: u8) -> Vec<u8> {
        match instr.op {
            DalvikOpcode::Nop => vec![0x00, 0x00],
            DalvikOpcode::ReturnVoid => vec![0x0E, 0x00],
            DalvikOpcode::Return => {
                let va = instr.regs.first().copied().unwrap_or(0);
                vec![0x0F, va]
            }
            DalvikOpcode::ReturnObject => {
                let va = instr.regs.first().copied().unwrap_or(0);
                vec![0x11, va]
            }
            DalvikOpcode::Move
            | DalvikOpcode::MoveWide
            | DalvikOpcode::MoveObject
            | DalvikOpcode::NegInt
            | DalvikOpcode::NotInt
            | DalvikOpcode::NegLong
            | DalvikOpcode::NotLong
            | DalvikOpcode::NegFloat
            | DalvikOpcode::NegDouble
            | DalvikOpcode::IntToLong
            | DalvikOpcode::IntToFloat
            | DalvikOpcode::IntToDouble
            | DalvikOpcode::LongToInt
            | DalvikOpcode::LongToFloat
            | DalvikOpcode::LongToDouble
            | DalvikOpcode::FloatToInt
            | DalvikOpcode::FloatToLong
            | DalvikOpcode::FloatToDouble
            | DalvikOpcode::DoubleToInt
            | DalvikOpcode::DoubleToLong
            | DalvikOpcode::DoubleToFloat
            | DalvikOpcode::IntToByte
            | DalvikOpcode::IntToChar
            | DalvikOpcode::IntToShort => {
                let va = instr.regs.first().copied().unwrap_or(0) & 0x0F;
                let vb = instr.regs.get(1).copied().unwrap_or(0) & 0x0F;
                vec![op, (vb << 4) | va]
            }
            DalvikOpcode::Const4 => {
                let va = instr.regs.first().copied().unwrap_or(0) & 0x0F;
                let lit = u8::try_from(instr.literal.unwrap_or(0) & 0x0F).unwrap_or(0);
                vec![0x12, (lit << 4) | va]
            }
            DalvikOpcode::Goto => {
                let off = u8::try_from(instr.branch_target.unwrap_or(0) & 0xFF).unwrap_or(0);
                vec![0x28, off]
            }
            _ => vec![op, 0x00],
        }
    }

    /// Assemble a slice of `SmaliInstruction`s into a flat byte vector.
    #[must_use]
    pub fn assemble(instrs: &[SmaliInstruction]) -> Vec<u8> {
        let mut out = Vec::new();
        for instr in instrs {
            out.extend_from_slice(&Self::encode(instr));
        }
        out
    }
}

/// A Dalvik bytecode disassembler that converts raw bytes to `SmaliInstruction`s.
pub struct DalvikDisassembler;

impl DalvikDisassembler {
    /// Disassemble `bytes` starting at `base_offset`.
    ///
    /// Each 16-bit code unit is consumed and mapped to a `SmaliInstruction`.
    /// Instructions that span multiple code units (e.g. `const-wide`) consume
    /// the correct number of bytes before the next instruction.
    #[must_use]
    pub fn disassemble(bytes: &[u8], ctx: &DexContext) -> Vec<SmaliInstruction> {
        let mut instrs = Vec::new();
        let mut off = 0usize;

        while off + 1 < bytes.len() {
            let opcode_byte = bytes[off];
            let op = DalvikOpcode::from_byte(opcode_byte);
            let size = instruction_size_bytes(op);

            if off + size > bytes.len() {
                break;
            }

            let raw = &bytes[off..off + size];
            let instr = Self::decode_instruction(op, raw, off, ctx);
            instrs.push(instr);
            off += size.max(2);
        }

        instrs
    }

    fn decode_instruction(
        op: DalvikOpcode,
        raw: &[u8],
        offset: usize,
        ctx: &DexContext,
    ) -> SmaliInstruction {
        // Helper to read u16 LE from raw[i..i+2]
        let u16_at = |i: usize| -> u16 {
            if i + 1 < raw.len() {
                u16::from_le_bytes([raw[i], raw[i + 1]])
            } else {
                0
            }
        };

        let mut regs = Vec::new();
        let mut string_idx = None;
        let mut type_idx = None;
        let mut field_idx = None;
        let mut method_idx = None;
        let mut literal = None;
        let mut branch_target = None;

        match op {
            DalvikOpcode::Nop | DalvikOpcode::ReturnVoid => {}
            DalvikOpcode::Return | DalvikOpcode::ReturnObject | DalvikOpcode::ReturnWide => {
                regs.push(raw.get(1).copied().unwrap_or(0));
            }
            DalvikOpcode::Move | DalvikOpcode::MoveWide | DalvikOpcode::MoveObject => {
                let byte1 = raw.get(1).copied().unwrap_or(0);
                regs.push(byte1 & 0x0F);
                regs.push((byte1 >> 4) & 0x0F);
            }
            DalvikOpcode::Const4 => {
                let byte1 = raw.get(1).copied().unwrap_or(0);
                regs.push(byte1 & 0x0F);
                literal = Some(i64::from((byte1 >> 4).cast_signed()));
            }
            DalvikOpcode::Const16 => {
                regs.push(raw.get(1).copied().unwrap_or(0));
                literal = Some(i64::from(i16::from_le_bytes([
                    raw.get(2).copied().unwrap_or(0),
                    raw.get(3).copied().unwrap_or(0),
                ])));
            }
            DalvikOpcode::ConstString => {
                regs.push(raw.get(1).copied().unwrap_or(0));
                let idx = u16_at(2);
                string_idx = Some(u32::from(idx));
                let _ = ctx.string(u32::from(idx)); // resolve for side-effect
            }
            DalvikOpcode::NewInstance | DalvikOpcode::CheckCast => {
                regs.push(raw.get(1).copied().unwrap_or(0));
                let idx = u16_at(2);
                type_idx = Some(u32::from(idx));
            }
            DalvikOpcode::Goto => {
                let off_byte = raw.get(1).copied().unwrap_or(0).cast_signed();
                branch_target = Some(i32::from(off_byte));
            }
            DalvikOpcode::Goto16 => {
                let off16 = i16::from_le_bytes([
                    raw.get(2).copied().unwrap_or(0),
                    raw.get(3).copied().unwrap_or(0),
                ]);
                branch_target = Some(i32::from(off16));
            }
            DalvikOpcode::IfEq
            | DalvikOpcode::IfNe
            | DalvikOpcode::IfLt
            | DalvikOpcode::IfGe
            | DalvikOpcode::IfGt
            | DalvikOpcode::IfLe => {
                let byte1 = raw.get(1).copied().unwrap_or(0);
                regs.push(byte1 & 0x0F);
                regs.push((byte1 >> 4) & 0x0F);
                let off16 = i16::from_le_bytes([
                    raw.get(2).copied().unwrap_or(0),
                    raw.get(3).copied().unwrap_or(0),
                ]);
                branch_target = Some(i32::from(off16));
            }
            DalvikOpcode::IfEqz
            | DalvikOpcode::IfNez
            | DalvikOpcode::IfLtz
            | DalvikOpcode::IfGez
            | DalvikOpcode::IfGtz
            | DalvikOpcode::IfLez => {
                regs.push(raw.get(1).copied().unwrap_or(0));
                let off16 = i16::from_le_bytes([
                    raw.get(2).copied().unwrap_or(0),
                    raw.get(3).copied().unwrap_or(0),
                ]);
                branch_target = Some(i32::from(off16));
            }
            DalvikOpcode::InvokeVirtual
            | DalvikOpcode::InvokeSuper
            | DalvikOpcode::InvokeDirect
            | DalvikOpcode::InvokeStatic
            | DalvikOpcode::InvokeInterface => {
                Self::decode_instr_invoke_35c(raw, &mut regs, &mut method_idx);
            }
            DalvikOpcode::Iget
            | DalvikOpcode::IgetWide
            | DalvikOpcode::IgetObject
            | DalvikOpcode::Iput
            | DalvikOpcode::IputWide
            | DalvikOpcode::IputObject
            | DalvikOpcode::Sget
            | DalvikOpcode::SgetWide
            | DalvikOpcode::SgetObject
            | DalvikOpcode::Sput
            | DalvikOpcode::SputWide
            | DalvikOpcode::SputObject => {
                Self::decode_instr_field(raw, &mut regs, &mut field_idx);
            }
            _ => {
                // Generic fallback: push first reg byte, first u16 as literal
                if raw.len() > 1 {
                    regs.push(raw[1]);
                }
                if raw.len() >= 4 {
                    literal = Some(i64::from(u16_at(2)));
                }
            }
        }

        SmaliInstruction {
            offset,
            op,
            regs,
            string_idx,
            type_idx,
            field_idx,
            method_idx,
            literal,
            branch_target,
        }
    }

    fn decode_instr_invoke_35c(raw: &[u8], regs: &mut Vec<u8>, method_idx: &mut Option<u32>) {
        if raw.len() >= 6 {
            let reg_count = (raw[1] >> 4) as usize;
            let idx = u16::from_le_bytes([raw[2], raw[3]]);
            *method_idx = Some(u32::from(idx));
            let regs_byte4 = raw[4];
            let regs_byte5 = raw[5];
            let all_regs: [u8; 4] = [
                regs_byte4 & 0x0F,
                (regs_byte4 >> 4) & 0x0F,
                regs_byte5 & 0x0F,
                (regs_byte5 >> 4) & 0x0F,
            ];
            for &reg in all_regs.iter().take(reg_count.min(4)) {
                regs.push(reg);
            }
        }
    }

    fn decode_instr_field(raw: &[u8], regs: &mut Vec<u8>, field_idx: &mut Option<u32>) {
        if raw.len() >= 4 {
            let byte1 = raw[1];
            regs.push(byte1 & 0x0F);
            regs.push((byte1 >> 4) & 0x0F);
            *field_idx = Some(u32::from(u16::from_le_bytes([raw[2], raw[3]])));
        }
    }

    /// Disassemble and render as smali text (one instruction per line).
    #[must_use]
    pub fn disassemble_to_text(bytes: &[u8], ctx: &DexContext) -> String {
        Self::disassemble(bytes, ctx)
            .iter()
            .map(|i| Self::instr_to_smali(i, ctx))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Render a single `SmaliInstruction` as smali text.
    #[must_use]
    pub fn instr_to_smali(instr: &SmaliInstruction, ctx: &DexContext) -> String {
        let mnemonic = opcode_to_smali(instr.op);
        let mut parts: Vec<String> = instr.regs.iter().map(|r| format!("v{r}")).collect();

        if let Some(idx) = instr.method_idx {
            parts.push(ctx.method(idx));
        } else if let Some(idx) = instr.type_idx {
            parts.push(ctx.type_desc(idx));
        } else if let Some(idx) = instr.field_idx {
            parts.push(ctx.field(idx));
        } else if let Some(idx) = instr.string_idx {
            parts.push(format!("\"{}\"", ctx.string(idx)));
        } else if let Some(lit) = instr.literal {
            parts.push(format!("{lit:#x}"));
        } else if let Some(tgt) = instr.branch_target {
            parts.push(format!("{tgt:+}"));
        }

        if parts.is_empty() {
            mnemonic.to_string()
        } else {
            format!("{mnemonic} {}", parts.join(", "))
        }
    }
}

// ─── Round-trip correctness tests ────────────────────────────────────────────

#[cfg(test)]
mod roundtrip_tests {
    use super::*;

    #[test]
    fn test_return_void_roundtrip() {
        let instr = SmaliInstruction {
            offset: 0,
            op: DalvikOpcode::ReturnVoid,
            regs: vec![],
            string_idx: None,
            type_idx: None,
            field_idx: None,
            method_idx: None,
            literal: None,
            branch_target: None,
        };
        let bytes = DalvikAssembler::encode(&instr);
        assert_eq!(bytes, vec![0x0E, 0x00]);
        let ctx = DexContext::dummy();
        let decoded = DalvikDisassembler::disassemble(&bytes, &ctx);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].op, DalvikOpcode::ReturnVoid);
    }

    #[test]
    fn test_nop_roundtrip() {
        let instr = SmaliInstruction {
            offset: 0,
            op: DalvikOpcode::Nop,
            regs: vec![],
            string_idx: None,
            type_idx: None,
            field_idx: None,
            method_idx: None,
            literal: None,
            branch_target: None,
        };
        let bytes = DalvikAssembler::encode(&instr);
        assert_eq!(bytes, vec![0x00, 0x00]);
        let ctx = DexContext::dummy();
        let decoded = DalvikDisassembler::disassemble(&bytes, &ctx);
        assert_eq!(decoded[0].op, DalvikOpcode::Nop);
    }

    #[test]
    fn test_const4_encode() {
        let instr = SmaliInstruction {
            offset: 0,
            op: DalvikOpcode::Const4,
            regs: vec![0],
            string_idx: None,
            type_idx: None,
            field_idx: None,
            method_idx: None,
            literal: Some(7),
            branch_target: None,
        };
        let bytes = DalvikAssembler::encode(&instr);
        assert_eq!(bytes[0], 0x12);
        // bits 7:4 = literal=7, bits 3:0 = reg=0 → 0x70
        assert_eq!(bytes[1], 0x70);
    }

    #[test]
    fn test_goto_encode() {
        let instr = SmaliInstruction {
            offset: 0,
            op: DalvikOpcode::Goto,
            regs: vec![],
            string_idx: None,
            type_idx: None,
            field_idx: None,
            method_idx: None,
            literal: None,
            branch_target: Some(10),
        };
        let bytes = DalvikAssembler::encode(&instr);
        assert_eq!(bytes[0], 0x28);
        assert_eq!(bytes[1], 10);
    }

    #[test]
    fn test_const_string_encode_decode() {
        let instr = SmaliInstruction {
            offset: 0,
            op: DalvikOpcode::ConstString,
            regs: vec![3],
            string_idx: Some(5),
            type_idx: None,
            field_idx: None,
            method_idx: None,
            literal: None,
            branch_target: None,
        };
        let bytes = DalvikAssembler::encode(&instr);
        assert_eq!(bytes[0], 0x1A);
        assert_eq!(bytes[1], 3);
        let mut ctx = DexContext::dummy();
        ctx.strings.push("hello".to_string());
        ctx.strings.push("world".to_string());
        ctx.strings.push("a".to_string());
        ctx.strings.push("b".to_string());
        ctx.strings.push("c".to_string());
        ctx.strings.push("test_string".to_string()); // idx=5
        let decoded = DalvikDisassembler::disassemble(&bytes, &ctx);
        assert_eq!(decoded[0].op, DalvikOpcode::ConstString);
        assert_eq!(decoded[0].regs[0], 3);
        assert_eq!(decoded[0].string_idx, Some(5));
    }

    #[test]
    fn test_new_instance_encode() {
        let instr = SmaliInstruction {
            offset: 0,
            op: DalvikOpcode::NewInstance,
            regs: vec![0],
            type_idx: Some(2),
            string_idx: None,
            field_idx: None,
            method_idx: None,
            literal: None,
            branch_target: None,
        };
        let bytes = DalvikAssembler::encode(&instr);
        assert_eq!(bytes[0], 0x22);
        assert_eq!(bytes[2], 2); // type_idx lo byte
        assert_eq!(bytes[3], 0); // type_idx hi byte
    }

    #[test]
    fn test_disassemble_multiple_instrs() {
        let bytes = vec![0x0Eu8, 0x00, 0x0E, 0x00]; // 2× return-void
        let ctx = DexContext::dummy();
        let instrs = DalvikDisassembler::disassemble(&bytes, &ctx);
        assert_eq!(instrs.len(), 2);
        assert!(instrs.iter().all(|i| i.op == DalvikOpcode::ReturnVoid));
    }

    #[test]
    fn test_disassemble_to_text() {
        let bytes = vec![0x0Eu8, 0x00]; // return-void
        let ctx = DexContext::dummy();
        let text = DalvikDisassembler::disassemble_to_text(&bytes, &ctx);
        assert_eq!(text.trim(), "return-void");
    }
}

// ─── Type descriptor parser tests ─────────────────────────────────────────────

#[cfg(test)]
mod descriptor_tests {
    use super::*;

    #[test]
    fn test_primitive_int() {
        assert_eq!(parse_type_descriptor("I"), "int");
    }

    #[test]
    fn test_primitive_boolean() {
        assert_eq!(parse_type_descriptor("Z"), "boolean");
    }

    #[test]
    fn test_primitive_long() {
        assert_eq!(parse_type_descriptor("J"), "long");
    }

    #[test]
    fn test_object_ref_string() {
        assert_eq!(
            parse_type_descriptor("Ljava/lang/String;"),
            "java.lang.String"
        );
    }

    #[test]
    fn test_object_ref_nested() {
        assert_eq!(
            parse_type_descriptor("Landroid/app/Activity;"),
            "android.app.Activity"
        );
    }

    #[test]
    fn test_szarray_int() {
        assert_eq!(parse_type_descriptor("[I"), "int[]");
    }

    #[test]
    fn test_szarray_string() {
        assert_eq!(
            parse_type_descriptor("[Ljava/lang/String;"),
            "java.lang.String[]"
        );
    }

    #[test]
    fn test_2d_array() {
        assert_eq!(parse_type_descriptor("[[I"), "int[][]");
    }

    #[test]
    fn test_method_descriptor_no_args_void() {
        let (params, ret) = parse_method_descriptor("()V");
        assert!(params.is_empty());
        assert_eq!(ret, "void");
    }

    #[test]
    fn test_method_descriptor_single_arg() {
        let (params, ret) = parse_method_descriptor("(I)Z");
        assert_eq!(params, vec!["int"]);
        assert_eq!(ret, "boolean");
    }

    #[test]
    fn test_method_descriptor_multiple_args() {
        let (params, ret) = parse_method_descriptor("(ILjava/lang/String;Z)V");
        assert_eq!(params.len(), 3);
        assert_eq!(params[0], "int");
        assert_eq!(params[1], "java.lang.String");
        assert_eq!(params[2], "boolean");
        assert_eq!(ret, "void");
    }

    #[test]
    fn test_method_descriptor_array_param() {
        let (params, ret) = parse_method_descriptor("([B)I");
        assert_eq!(params, vec!["byte[]"]);
        assert_eq!(ret, "int");
    }

    #[test]
    fn test_method_descriptor_empty_string() {
        let (params, ret) = parse_method_descriptor("");
        assert!(params.is_empty());
        assert_eq!(ret, "void");
    }

    #[test]
    fn test_opcode_from_byte_nop() {
        assert_eq!(DalvikOpcode::from_byte(0x00), DalvikOpcode::Nop);
    }

    #[test]
    fn test_opcode_from_byte_return_void() {
        assert_eq!(DalvikOpcode::from_byte(0x0E), DalvikOpcode::ReturnVoid);
    }

    #[test]
    fn test_opcode_from_byte_invoke_virtual() {
        assert_eq!(DalvikOpcode::from_byte(0x6E), DalvikOpcode::InvokeVirtual);
    }

    #[test]
    fn test_opcode_to_smali_nop() {
        assert_eq!(opcode_to_smali(DalvikOpcode::Nop), "nop");
    }

    #[test]
    fn test_opcode_to_smali_invoke_static() {
        assert_eq!(opcode_to_smali(DalvikOpcode::InvokeStatic), "invoke-static");
    }

    #[test]
    fn test_instruction_size_nop() {
        assert_eq!(instruction_size_bytes(DalvikOpcode::Nop), 2);
    }

    #[test]
    fn test_instruction_size_const_wide() {
        assert_eq!(instruction_size_bytes(DalvikOpcode::ConstWide), 10);
    }

    #[test]
    fn test_instruction_size_invoke_virtual() {
        assert_eq!(instruction_size_bytes(DalvikOpcode::InvokeVirtual), 6);
    }

    #[test]
    fn test_dex_context_string_placeholder() {
        let ctx = DexContext::dummy();
        assert!(ctx.string(99).contains("0x63"));
    }

    #[test]
    fn test_dex_context_string_resolved() {
        let mut ctx = DexContext::dummy();
        ctx.strings.push("hello".to_string());
        assert_eq!(ctx.string(0), "hello");
    }

    #[test]
    fn test_dex_context_type_resolved() {
        let mut ctx = DexContext::dummy();
        ctx.types.push("Ljava/lang/Object;".to_string());
        assert_eq!(ctx.type_desc(0), "Ljava/lang/Object;");
    }

    #[test]
    fn test_assemble_empty() {
        assert!(DalvikAssembler::assemble(&[]).is_empty());
    }

    #[test]
    fn test_assemble_two_nops() {
        let instrs = vec![
            SmaliInstruction {
                offset: 0,
                op: DalvikOpcode::Nop,
                regs: vec![],
                string_idx: None,
                type_idx: None,
                field_idx: None,
                method_idx: None,
                literal: None,
                branch_target: None,
            },
            SmaliInstruction {
                offset: 2,
                op: DalvikOpcode::Nop,
                regs: vec![],
                string_idx: None,
                type_idx: None,
                field_idx: None,
                method_idx: None,
                literal: None,
                branch_target: None,
            },
        ];
        let bytes = DalvikAssembler::assemble(&instrs);
        assert_eq!(bytes, vec![0x00, 0x00, 0x00, 0x00]);
    }
}
