//! JVM bytecode disassembler.
//!
//! Decodes the bytecode from a `Code` attribute into a sequence of
//! [`JvmInstr`] values and computes per-instruction stack deltas.
//!
//! # Instruction encoding
//!
//! Most JVM opcodes are 1–4 bytes.  Exceptions:
//!
//! * `tableswitch` — variable length, 4-byte aligned
//! * `lookupswitch` — variable length, 4-byte aligned
//! * `wide` — prefix that extends the operand width of the next opcode
//!
//! # References
//!
//! JVMS §6 — The Java Virtual Machine Instruction Set

use std::fmt;
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Opcode table
// ─────────────────────────────────────────────────────────────────────────────

/// All JVM opcodes (JVMS Table 6.x).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum JvmOp {
    Nop           = 0x00,
    AconstNull    = 0x01,
    IconstM1      = 0x02,
    Iconst0       = 0x03,
    Iconst1       = 0x04,
    Iconst2       = 0x05,
    Iconst3       = 0x06,
    Iconst4       = 0x07,
    Iconst5       = 0x08,
    Lconst0       = 0x09,
    Lconst1       = 0x0a,
    Fconst0       = 0x0b,
    Fconst1       = 0x0c,
    Fconst2       = 0x0d,
    Dconst0       = 0x0e,
    Dconst1       = 0x0f,
    Bipush        = 0x10,
    Sipush        = 0x11,
    Ldc           = 0x12,
    LdcW          = 0x13,
    Ldc2W         = 0x14,
    Iload         = 0x15,
    Lload         = 0x16,
    Fload         = 0x17,
    Dload         = 0x18,
    Aload         = 0x19,
    Iload0        = 0x1a,
    Iload1        = 0x1b,
    Iload2        = 0x1c,
    Iload3        = 0x1d,
    Lload0        = 0x1e,
    Lload1        = 0x1f,
    Lload2        = 0x20,
    Lload3        = 0x21,
    Fload0        = 0x22,
    Fload1        = 0x23,
    Fload2        = 0x24,
    Fload3        = 0x25,
    Dload0        = 0x26,
    Dload1        = 0x27,
    Dload2        = 0x28,
    Dload3        = 0x29,
    Aload0        = 0x2a,
    Aload1        = 0x2b,
    Aload2        = 0x2c,
    Aload3        = 0x2d,
    Iaload        = 0x2e,
    Laload        = 0x2f,
    Faload        = 0x30,
    Daload        = 0x31,
    Aaload        = 0x32,
    Baload        = 0x33,
    Caload        = 0x34,
    Saload        = 0x35,
    Istore        = 0x36,
    Lstore        = 0x37,
    Fstore        = 0x38,
    Dstore        = 0x39,
    Astore        = 0x3a,
    Istore0       = 0x3b,
    Istore1       = 0x3c,
    Istore2       = 0x3d,
    Istore3       = 0x3e,
    Lstore0       = 0x3f,
    Lstore1       = 0x40,
    Lstore2       = 0x41,
    Lstore3       = 0x42,
    Fstore0       = 0x43,
    Fstore1       = 0x44,
    Fstore2       = 0x45,
    Fstore3       = 0x46,
    Dstore0       = 0x47,
    Dstore1       = 0x48,
    Dstore2       = 0x49,
    Dstore3       = 0x4a,
    Astore0       = 0x4b,
    Astore1       = 0x4c,
    Astore2       = 0x4d,
    Astore3       = 0x4e,
    Iastore       = 0x4f,
    Lastore       = 0x50,
    Fastore       = 0x51,
    Dastore       = 0x52,
    Aastore       = 0x53,
    Bastore       = 0x54,
    Castore       = 0x55,
    Sastore       = 0x56,
    Pop           = 0x57,
    Pop2          = 0x58,
    Dup           = 0x59,
    DupX1         = 0x5a,
    DupX2         = 0x5b,
    Dup2          = 0x5c,
    Dup2X1        = 0x5d,
    Dup2X2        = 0x5e,
    Swap          = 0x5f,
    Iadd          = 0x60,
    Ladd          = 0x61,
    Fadd          = 0x62,
    Dadd          = 0x63,
    Isub          = 0x64,
    Lsub          = 0x65,
    Fsub          = 0x66,
    Dsub          = 0x67,
    Imul          = 0x68,
    Lmul          = 0x69,
    Fmul          = 0x6a,
    Dmul          = 0x6b,
    Idiv          = 0x6c,
    Ldiv          = 0x6d,
    Fdiv          = 0x6e,
    Ddiv          = 0x6f,
    Irem          = 0x70,
    Lrem          = 0x71,
    Frem          = 0x72,
    Drem          = 0x73,
    Ineg          = 0x74,
    Lneg          = 0x75,
    Fneg          = 0x76,
    Dneg          = 0x77,
    Ishl          = 0x78,
    Lshl          = 0x79,
    Ishr          = 0x7a,
    Lshr          = 0x7b,
    Iushr         = 0x7c,
    Lushr         = 0x7d,
    Iand          = 0x7e,
    Land          = 0x7f,
    Ior           = 0x80,
    Lor           = 0x81,
    Ixor          = 0x82,
    Lxor          = 0x83,
    Iinc          = 0x84,
    I2l           = 0x85,
    I2f           = 0x86,
    I2d           = 0x87,
    L2i           = 0x88,
    L2f           = 0x89,
    L2d           = 0x8a,
    F2i           = 0x8b,
    F2l           = 0x8c,
    F2d           = 0x8d,
    D2i           = 0x8e,
    D2l           = 0x8f,
    D2f           = 0x90,
    I2b           = 0x91,
    I2c           = 0x92,
    I2s           = 0x93,
    Lcmp          = 0x94,
    Fcmpl         = 0x95,
    Fcmpg         = 0x96,
    Dcmpl         = 0x97,
    Dcmpg         = 0x98,
    Ifeq          = 0x99,
    Ifne          = 0x9a,
    Iflt          = 0x9b,
    Ifge          = 0x9c,
    Ifgt          = 0x9d,
    Ifle          = 0x9e,
    IfIcmpeq      = 0x9f,
    IfIcmpne      = 0xa0,
    IfIcmplt      = 0xa1,
    IfIcmpge      = 0xa2,
    IfIcmpgt      = 0xa3,
    IfIcmple      = 0xa4,
    IfAcmpeq      = 0xa5,
    IfAcmpne      = 0xa6,
    Goto          = 0xa7,
    Jsr           = 0xa8,
    Ret           = 0xa9,
    Tableswitch   = 0xaa,
    Lookupswitch  = 0xab,
    Ireturn       = 0xac,
    Lreturn       = 0xad,
    Freturn       = 0xae,
    Dreturn       = 0xaf,
    Areturn       = 0xb0,
    Return        = 0xb1,
    Getstatic     = 0xb2,
    Putstatic     = 0xb3,
    Getfield      = 0xb4,
    Putfield      = 0xb5,
    Invokevirtual = 0xb6,
    Invokespecial = 0xb7,
    Invokestatic  = 0xb8,
    Invokeinterface = 0xb9,
    Invokedynamic = 0xba,
    New           = 0xbb,
    Newarray      = 0xbc,
    Anewarray     = 0xbd,
    Arraylength   = 0xbe,
    Athrow        = 0xbf,
    Checkcast     = 0xc0,
    Instanceof    = 0xc1,
    Monitorenter  = 0xc2,
    Monitorexit   = 0xc3,
    Wide          = 0xc4,
    Multianewarray = 0xc5,
    Ifnull        = 0xc6,
    Ifnonnull     = 0xc7,
    GotoW         = 0xc8,
    JsrW          = 0xc9,
    Unknown(u8),
}

impl JvmOp {
    #[must_use] 
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Nop, 0x01 => Self::AconstNull,
            0x02 => Self::IconstM1, 0x03 => Self::Iconst0,
            0x04 => Self::Iconst1, 0x05 => Self::Iconst2,
            0x06 => Self::Iconst3, 0x07 => Self::Iconst4,
            0x08 => Self::Iconst5, 0x09 => Self::Lconst0,
            0x0a => Self::Lconst1, 0x0b => Self::Fconst0,
            0x0c => Self::Fconst1, 0x0d => Self::Fconst2,
            0x0e => Self::Dconst0, 0x0f => Self::Dconst1,
            0x10 => Self::Bipush, 0x11 => Self::Sipush,
            0x12 => Self::Ldc, 0x13 => Self::LdcW, 0x14 => Self::Ldc2W,
            0x15 => Self::Iload, 0x16 => Self::Lload, 0x17 => Self::Fload,
            0x18 => Self::Dload, 0x19 => Self::Aload,
            0x1a => Self::Iload0, 0x1b => Self::Iload1,
            0x1c => Self::Iload2, 0x1d => Self::Iload3,
            0x1e => Self::Lload0, 0x1f => Self::Lload1,
            0x20 => Self::Lload2, 0x21 => Self::Lload3,
            0x22 => Self::Fload0, 0x23 => Self::Fload1,
            0x24 => Self::Fload2, 0x25 => Self::Fload3,
            0x26 => Self::Dload0, 0x27 => Self::Dload1,
            0x28 => Self::Dload2, 0x29 => Self::Dload3,
            0x2a => Self::Aload0, 0x2b => Self::Aload1,
            0x2c => Self::Aload2, 0x2d => Self::Aload3,
            0x2e => Self::Iaload, 0x2f => Self::Laload,
            0x30 => Self::Faload, 0x31 => Self::Daload,
            0x32 => Self::Aaload, 0x33 => Self::Baload,
            0x34 => Self::Caload, 0x35 => Self::Saload,
            0x36 => Self::Istore, 0x37 => Self::Lstore,
            0x38 => Self::Fstore, 0x39 => Self::Dstore, 0x3a => Self::Astore,
            0x3b => Self::Istore0, 0x3c => Self::Istore1,
            0x3d => Self::Istore2, 0x3e => Self::Istore3,
            0x3f => Self::Lstore0, 0x40 => Self::Lstore1,
            0x41 => Self::Lstore2, 0x42 => Self::Lstore3,
            0x43 => Self::Fstore0, 0x44 => Self::Fstore1,
            0x45 => Self::Fstore2, 0x46 => Self::Fstore3,
            0x47 => Self::Dstore0, 0x48 => Self::Dstore1,
            0x49 => Self::Dstore2, 0x4a => Self::Dstore3,
            0x4b => Self::Astore0, 0x4c => Self::Astore1,
            0x4d => Self::Astore2, 0x4e => Self::Astore3,
            0x4f => Self::Iastore, 0x50 => Self::Lastore,
            0x51 => Self::Fastore, 0x52 => Self::Dastore,
            0x53 => Self::Aastore, 0x54 => Self::Bastore,
            0x55 => Self::Castore, 0x56 => Self::Sastore,
            0x57 => Self::Pop, 0x58 => Self::Pop2,
            0x59 => Self::Dup, 0x5a => Self::DupX1,
            0x5b => Self::DupX2, 0x5c => Self::Dup2,
            0x5d => Self::Dup2X1, 0x5e => Self::Dup2X2, 0x5f => Self::Swap,
            0x60 => Self::Iadd, 0x61 => Self::Ladd,
            0x62 => Self::Fadd, 0x63 => Self::Dadd,
            0x64 => Self::Isub, 0x65 => Self::Lsub,
            0x66 => Self::Fsub, 0x67 => Self::Dsub,
            0x68 => Self::Imul, 0x69 => Self::Lmul,
            0x6a => Self::Fmul, 0x6b => Self::Dmul,
            0x6c => Self::Idiv, 0x6d => Self::Ldiv,
            0x6e => Self::Fdiv, 0x6f => Self::Ddiv,
            0x70 => Self::Irem, 0x71 => Self::Lrem,
            0x72 => Self::Frem, 0x73 => Self::Drem,
            0x74 => Self::Ineg, 0x75 => Self::Lneg,
            0x76 => Self::Fneg, 0x77 => Self::Dneg,
            0x78 => Self::Ishl, 0x79 => Self::Lshl,
            0x7a => Self::Ishr, 0x7b => Self::Lshr,
            0x7c => Self::Iushr, 0x7d => Self::Lushr,
            0x7e => Self::Iand, 0x7f => Self::Land,
            0x80 => Self::Ior, 0x81 => Self::Lor,
            0x82 => Self::Ixor, 0x83 => Self::Lxor,
            0x84 => Self::Iinc,
            0x85 => Self::I2l, 0x86 => Self::I2f, 0x87 => Self::I2d,
            0x88 => Self::L2i, 0x89 => Self::L2f, 0x8a => Self::L2d,
            0x8b => Self::F2i, 0x8c => Self::F2l, 0x8d => Self::F2d,
            0x8e => Self::D2i, 0x8f => Self::D2l, 0x90 => Self::D2f,
            0x91 => Self::I2b, 0x92 => Self::I2c, 0x93 => Self::I2s,
            0x94 => Self::Lcmp,
            0x95 => Self::Fcmpl, 0x96 => Self::Fcmpg,
            0x97 => Self::Dcmpl, 0x98 => Self::Dcmpg,
            0x99 => Self::Ifeq, 0x9a => Self::Ifne,
            0x9b => Self::Iflt, 0x9c => Self::Ifge,
            0x9d => Self::Ifgt, 0x9e => Self::Ifle,
            0x9f => Self::IfIcmpeq, 0xa0 => Self::IfIcmpne,
            0xa1 => Self::IfIcmplt, 0xa2 => Self::IfIcmpge,
            0xa3 => Self::IfIcmpgt, 0xa4 => Self::IfIcmple,
            0xa5 => Self::IfAcmpeq, 0xa6 => Self::IfAcmpne,
            0xa7 => Self::Goto,
            0xa8 => Self::Jsr, 0xa9 => Self::Ret,
            0xaa => Self::Tableswitch, 0xab => Self::Lookupswitch,
            0xac => Self::Ireturn, 0xad => Self::Lreturn,
            0xae => Self::Freturn, 0xaf => Self::Dreturn,
            0xb0 => Self::Areturn, 0xb1 => Self::Return,
            0xb2 => Self::Getstatic, 0xb3 => Self::Putstatic,
            0xb4 => Self::Getfield, 0xb5 => Self::Putfield,
            0xb6 => Self::Invokevirtual, 0xb7 => Self::Invokespecial,
            0xb8 => Self::Invokestatic, 0xb9 => Self::Invokeinterface,
            0xba => Self::Invokedynamic,
            0xbb => Self::New, 0xbc => Self::Newarray, 0xbd => Self::Anewarray,
            0xbe => Self::Arraylength, 0xbf => Self::Athrow,
            0xc0 => Self::Checkcast, 0xc1 => Self::Instanceof,
            0xc2 => Self::Monitorenter, 0xc3 => Self::Monitorexit,
            0xc4 => Self::Wide, 0xc5 => Self::Multianewarray,
            0xc6 => Self::Ifnull, 0xc7 => Self::Ifnonnull,
            0xc8 => Self::GotoW, 0xc9 => Self::JsrW,
            other => Self::Unknown(other),
        }
    }

    #[must_use] 
    pub const fn mnemonic(&self) -> &str {
        match self {
            Self::Nop => "nop", Self::AconstNull => "aconst_null",
            Self::IconstM1 => "iconst_m1", Self::Iconst0 => "iconst_0",
            Self::Iconst1 => "iconst_1", Self::Iconst2 => "iconst_2",
            Self::Iconst3 => "iconst_3", Self::Iconst4 => "iconst_4",
            Self::Iconst5 => "iconst_5",
            Self::Bipush => "bipush", Self::Sipush => "sipush",
            Self::Ldc => "ldc", Self::LdcW => "ldc_w", Self::Ldc2W => "ldc2_w",
            Self::Iload => "iload", Self::Lload => "lload",
            Self::Fload => "fload", Self::Dload => "dload", Self::Aload => "aload",
            Self::Iload0 => "iload_0", Self::Iload1 => "iload_1",
            Self::Iload2 => "iload_2", Self::Iload3 => "iload_3",
            Self::Return => "return", Self::Ireturn => "ireturn",
            Self::Lreturn => "lreturn", Self::Freturn => "freturn",
            Self::Dreturn => "dreturn", Self::Areturn => "areturn",
            Self::Iadd => "iadd", Self::Isub => "isub",
            Self::Imul => "imul", Self::Idiv => "idiv",
            Self::Invokevirtual => "invokevirtual",
            Self::Invokespecial => "invokespecial",
            Self::Invokestatic  => "invokestatic",
            Self::Invokeinterface => "invokeinterface",
            Self::Invokedynamic => "invokedynamic",
            Self::Getstatic => "getstatic", Self::Putstatic => "putstatic",
            Self::Getfield => "getfield", Self::Putfield => "putfield",
            Self::New => "new",
            Self::Goto => "goto", Self::GotoW => "goto_w",
            Self::Tableswitch => "tableswitch", Self::Lookupswitch => "lookupswitch",
            Self::Ifeq => "ifeq", Self::Ifne => "ifne",
            Self::Iflt => "iflt", Self::Ifge => "ifge",
            Self::Ifgt => "ifgt", Self::Ifle => "ifle",
            Self::IfIcmpeq => "if_icmpeq", Self::IfIcmpne => "if_icmpne",
            Self::Pop => "pop", Self::Pop2 => "pop2",
            Self::Dup => "dup", Self::DupX1 => "dup_x1",
            Self::Athrow => "athrow",
            Self::Checkcast => "checkcast", Self::Instanceof => "instanceof",
            Self::Unknown(_) => "unknown",
            _ => "?",
        }
    }
}

/// Net stack depth change for a given opcode (simplified: ignores wide/category-2).
#[derive(Debug, Clone, Copy)]
pub struct StackDelta {
    pub pop: i8,
    pub push: i8,
}

impl StackDelta {
    #[must_use] 
    pub const fn net(&self) -> i8 { self.push - self.pop }

    fn from_op(op: JvmOp) -> Self {
        let (pop, push) = match op {
            JvmOp::Nop => (0, 0),
            JvmOp::AconstNull | JvmOp::IconstM1
            | JvmOp::Iconst0 | JvmOp::Iconst1 | JvmOp::Iconst2
            | JvmOp::Iconst3 | JvmOp::Iconst4 | JvmOp::Iconst5
            | JvmOp::Bipush | JvmOp::Sipush
            | JvmOp::Ldc | JvmOp::LdcW => (0, 1),
            JvmOp::Lconst0 | JvmOp::Lconst1 | JvmOp::Ldc2W
            | JvmOp::Fconst0 | JvmOp::Fconst1 | JvmOp::Fconst2
            | JvmOp::Dconst0 | JvmOp::Dconst1 => (0, 1),
            JvmOp::Iload | JvmOp::Lload | JvmOp::Fload | JvmOp::Dload | JvmOp::Aload
            | JvmOp::Iload0 | JvmOp::Iload1 | JvmOp::Iload2 | JvmOp::Iload3
            | JvmOp::Lload0 | JvmOp::Lload1 | JvmOp::Lload2 | JvmOp::Lload3
            | JvmOp::Fload0 | JvmOp::Fload1 | JvmOp::Fload2 | JvmOp::Fload3
            | JvmOp::Dload0 | JvmOp::Dload1 | JvmOp::Dload2 | JvmOp::Dload3
            | JvmOp::Aload0 | JvmOp::Aload1 | JvmOp::Aload2 | JvmOp::Aload3 => (0, 1),
            JvmOp::Istore | JvmOp::Lstore | JvmOp::Fstore | JvmOp::Dstore | JvmOp::Astore
            | JvmOp::Istore0 | JvmOp::Istore1 | JvmOp::Istore2 | JvmOp::Istore3
            | JvmOp::Lstore0 | JvmOp::Lstore1 | JvmOp::Lstore2 | JvmOp::Lstore3
            | JvmOp::Fstore0 | JvmOp::Fstore1 | JvmOp::Fstore2 | JvmOp::Fstore3
            | JvmOp::Dstore0 | JvmOp::Dstore1 | JvmOp::Dstore2 | JvmOp::Dstore3
            | JvmOp::Astore0 | JvmOp::Astore1 | JvmOp::Astore2 | JvmOp::Astore3 => (1, 0),
            JvmOp::Pop => (1, 0), JvmOp::Pop2 => (2, 0),
            JvmOp::Dup | JvmOp::DupX1 => (1, 2),
            JvmOp::Dup2 | JvmOp::Dup2X1 => (2, 4),
            JvmOp::Iadd | JvmOp::Ladd | JvmOp::Fadd | JvmOp::Dadd
            | JvmOp::Isub | JvmOp::Lsub | JvmOp::Fsub | JvmOp::Dsub
            | JvmOp::Imul | JvmOp::Lmul | JvmOp::Fmul | JvmOp::Dmul
            | JvmOp::Idiv | JvmOp::Ldiv | JvmOp::Fdiv | JvmOp::Ddiv
            | JvmOp::Irem | JvmOp::Lrem | JvmOp::Frem | JvmOp::Drem
            | JvmOp::Iand | JvmOp::Land | JvmOp::Ior | JvmOp::Lor
            | JvmOp::Ixor | JvmOp::Lxor => (2, 1),
            JvmOp::Ineg | JvmOp::Lneg | JvmOp::Fneg | JvmOp::Dneg => (1, 1),
            JvmOp::Ifeq | JvmOp::Ifne | JvmOp::Iflt | JvmOp::Ifge
            | JvmOp::Ifgt | JvmOp::Ifle => (1, 0),
            JvmOp::IfIcmpeq | JvmOp::IfIcmpne | JvmOp::IfIcmplt
            | JvmOp::IfIcmpge | JvmOp::IfIcmpgt | JvmOp::IfIcmple
            | JvmOp::IfAcmpeq | JvmOp::IfAcmpne => (2, 0),
            JvmOp::Getstatic => (0, 1), JvmOp::Putstatic => (1, 0),
            JvmOp::Getfield  => (1, 1), JvmOp::Putfield  => (2, 0),
            JvmOp::Return => (0, 0),
            JvmOp::Ireturn | JvmOp::Freturn | JvmOp::Areturn => (1, 0),
            JvmOp::Lreturn | JvmOp::Dreturn => (1, 0),
            JvmOp::New => (0, 1),
            JvmOp::Athrow => (1, 0),
            _ => (0, 0),
        };
        Self { pop: i8::try_from(pop).unwrap_or(i8::MAX), push: i8::try_from(push).unwrap_or(i8::MAX) }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JvmInstr — a decoded instruction
// ─────────────────────────────────────────────────────────────────────────────

/// Switch table (tableswitch / lookupswitch).
#[derive(Debug, Clone)]
pub struct SwitchTable {
    pub default_offset: i32,
    /// For tableswitch: `(low, high, offsets)`.
    pub tableswitch: Option<(i32, i32, Vec<i32>)>,
    /// For lookupswitch: `(match_value, offset)` pairs.
    pub lookupswitch: Option<Vec<(i32, i32)>>,
}

/// A single decoded JVM instruction.
#[derive(Debug, Clone)]
pub struct JvmInstr {
    pub pc: u32,
    pub op: JvmOp,
    pub operands: Vec<i32>,
    pub switch: Option<SwitchTable>,
    pub size: u32,
    pub stack_delta: StackDelta,
}

impl JvmInstr {
    #[must_use] 
    pub const fn is_branch(&self) -> bool {
        matches!(self.op,
            JvmOp::Goto | JvmOp::GotoW
            | JvmOp::Ifeq | JvmOp::Ifne | JvmOp::Iflt | JvmOp::Ifge
            | JvmOp::Ifgt | JvmOp::Ifle
            | JvmOp::IfIcmpeq | JvmOp::IfIcmpne | JvmOp::IfIcmplt
            | JvmOp::IfIcmpge | JvmOp::IfIcmpgt | JvmOp::IfIcmple
            | JvmOp::IfAcmpeq | JvmOp::IfAcmpne
            | JvmOp::Tableswitch | JvmOp::Lookupswitch
            | JvmOp::Jsr | JvmOp::JsrW | JvmOp::Ifnull | JvmOp::Ifnonnull
        )
    }

    #[must_use] 
    pub const fn is_return(&self) -> bool {
        matches!(self.op,
            JvmOp::Return | JvmOp::Ireturn | JvmOp::Lreturn
            | JvmOp::Freturn | JvmOp::Dreturn | JvmOp::Areturn | JvmOp::Athrow
        )
    }

    #[must_use] 
    pub fn branch_target(&self) -> Option<u32> {
        if !self.is_branch() { return None; }
        let off = i64::from(*self.operands.first()?);
        u32::try_from(i64::from(self.pc) + off).ok()
    }
}

impl fmt::Display for JvmInstr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:4}: {}", self.pc, self.op.mnemonic())?;
        for op in &self.operands {
            write!(f, " {op}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BcDisassembler
// ─────────────────────────────────────────────────────────────────────────────

/// Disassembles a JVM bytecode array into [`JvmInstr`] values.
pub struct BcDisassembler;

impl BcDisassembler {
    /// Disassemble an entire bytecode array.
    #[must_use] 
    pub fn disassemble(bytecode: &[u8]) -> Vec<JvmInstr> {
        let mut instrs = Vec::new();
        let mut pc = 0usize;
        while pc < bytecode.len() {
            match Self::decode_at(bytecode, pc) {
                Some(instr) => { pc += instr.size as usize; instrs.push(instr); }
                None => break,
            }
        }
        instrs
    }

    /// Decode a single instruction at `pc`.
    #[must_use] 
    pub fn decode_at(code: &[u8], pc: usize) -> Option<JvmInstr> {
        if pc >= code.len() { return None; }
        let byte = code[pc];
        let op = JvmOp::from_byte(byte);
        let sd = StackDelta::from_op(op);

        macro_rules! u8 { ($off:expr) => { i32::from(*code.get(pc + $off)?) } }
        macro_rules! i8 { ($off:expr) => { i32::from((*code.get(pc + $off)?).cast_signed()) } }
        macro_rules! u16 { ($off:expr) => {
            (i32::from(*code.get(pc + $off)?) << 8) | i32::from(*code.get(pc + $off + 1)?)
        } }
        macro_rules! i16 { ($off:expr) => {
            i32::from(((u16::from(*code.get(pc + $off)?) << 8) | u16::from(*code.get(pc + $off + 1)?)).cast_signed())
        } }
        macro_rules! i32 { ($off:expr) => {
            (i32::from(*code.get(pc + $off)?)     << 24)
            | (i32::from(*code.get(pc + $off + 1)?) << 16)
            | (i32::from(*code.get(pc + $off + 2)?) << 8)
            | i32::from(*code.get(pc + $off + 3)?)
        } }

        let (operands, size) = match op {
            JvmOp::Bipush => (vec![i8!(1)], 2),
            JvmOp::Sipush => (vec![i16!(1)], 3),
            JvmOp::Ldc  => (vec![u8!(1)], 2),
            JvmOp::LdcW | JvmOp::Ldc2W => (vec![u16!(1)], 3),
            JvmOp::Iload | JvmOp::Lload | JvmOp::Fload | JvmOp::Dload | JvmOp::Aload
            | JvmOp::Istore | JvmOp::Lstore | JvmOp::Fstore | JvmOp::Dstore | JvmOp::Astore
            | JvmOp::Ret => (vec![u8!(1)], 2),
            JvmOp::Iinc => (vec![u8!(1), i8!(2)], 3),
            JvmOp::Ifeq | JvmOp::Ifne | JvmOp::Iflt | JvmOp::Ifge
            | JvmOp::Ifgt | JvmOp::Ifle
            | JvmOp::IfIcmpeq | JvmOp::IfIcmpne | JvmOp::IfIcmplt
            | JvmOp::IfIcmpge | JvmOp::IfIcmpgt | JvmOp::IfIcmple
            | JvmOp::IfAcmpeq | JvmOp::IfAcmpne
            | JvmOp::Goto | JvmOp::Jsr
            | JvmOp::Ifnull | JvmOp::Ifnonnull => (vec![i16!(1)], 3),
            JvmOp::GotoW | JvmOp::JsrW => (vec![i32!(1)], 5),
            JvmOp::Getstatic | JvmOp::Putstatic | JvmOp::Getfield | JvmOp::Putfield
            | JvmOp::Invokevirtual | JvmOp::Invokespecial | JvmOp::Invokestatic
            | JvmOp::New | JvmOp::Anewarray | JvmOp::Checkcast | JvmOp::Instanceof => (vec![u16!(1)], 3),
            JvmOp::Invokeinterface | JvmOp::Invokedynamic => (vec![u16!(1), u8!(3), u8!(4)], 5),
            JvmOp::Newarray => (vec![u8!(1)], 2),
            JvmOp::Multianewarray => (vec![u16!(1), u8!(3)], 4),
            JvmOp::Wide => {
                // wide modifies the *next* opcode's operand width
                let wide_op = JvmOp::from_byte(*code.get(pc + 1)?);
                match wide_op {
                    JvmOp::Iinc => (vec![u16!(2), i16!(4)], 6),
                    _ => (vec![u16!(2)], 4),
                }
            }
            JvmOp::Tableswitch => {
                let pad = (4 - ((pc + 1) % 4)) % 4;
                let base = pc + 1 + pad;
                if base + 12 > code.len() { return None; }
                let default = i32!((base - pc));
                let low  = i32!((base - pc + 4));
                let high = i32!((base - pc + 8));
                // `high - low + 1` in i32 overflows for adversarial bounds (e.g.
                // high = i32::MAX, low < 0): that panics in debug builds and wraps
                // silently in release. Widen to i64 so the range is always exact.
                let count = usize::try_from((i64::from(high) - i64::from(low) + 1).max(0))
                    .unwrap_or(0);
                let total = match count.checked_mul(4).and_then(|n| n.checked_add(12)) {
                    Some(t) => t,
                    None => return None,
                };
                if base + total > code.len() { return None; }
                let mut offsets = Vec::with_capacity(count);
                for k in 0..count {
                    offsets.push(i32!((base - pc + 12 + k * 4)));
                }
                let sw = SwitchTable {
                    default_offset: default,
                    tableswitch: Some((low, high, offsets)),
                    lookupswitch: None,
                };
                return Some(JvmInstr {
                    pc: u32::try_from(pc).unwrap_or(u32::MAX), op, operands: vec![default], switch: Some(sw),
                    size: u32::try_from(1 + pad + total).unwrap_or(u32::MAX), stack_delta: StackDelta { pop: 1, push: 0 },
                });
            }
            JvmOp::Lookupswitch => {
                let pad = (4 - ((pc + 1) % 4)) % 4;
                let base = pc + 1 + pad;
                if base + 8 > code.len() { return None; }
                let default = i32!((base - pc));
                let npairs  = usize::try_from(i32!((base - pc + 4)).max(0)).unwrap_or(0);
                let total = match npairs.checked_mul(8).and_then(|n| n.checked_add(8)) {
                    Some(t) => t,
                    None => return None,
                };
                if base + total > code.len() { return None; }
                let mut pairs = Vec::with_capacity(npairs);
                for k in 0..npairs {
                    let mv = i32!((base - pc + 8 + k * 8));
                    let off= i32!((base - pc + 12 + k * 8));
                    pairs.push((mv, off));
                }
                let sw = SwitchTable {
                    default_offset: default,
                    tableswitch: None,
                    lookupswitch: Some(pairs),
                };
                return Some(JvmInstr {
                    pc: u32::try_from(pc).unwrap_or(u32::MAX), op, operands: vec![default], switch: Some(sw),
                    size: u32::try_from(1 + pad + total).unwrap_or(u32::MAX), stack_delta: StackDelta { pop: 1, push: 0 },
                });
            }
            _ => (vec![], 1),
        };

        Some(JvmInstr { pc: u32::try_from(pc).unwrap_or(u32::MAX), op, operands, switch: None, size: size as u32, stack_delta: sd })
    }

    /// Build a pc → instruction index map.
    #[must_use] 
    pub fn build_pc_map(instrs: &[JvmInstr]) -> HashMap<u32, usize> {
        instrs.iter().enumerate().map(|(i, ins)| (ins.pc, i)).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nop() {
        let code = [0x00u8];
        let instrs = BcDisassembler::disassemble(&code);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].op, JvmOp::Nop);
        assert_eq!(instrs[0].size, 1);
    }

    #[test]
    fn test_bipush() {
        let code = [0x10u8, 0x2a]; // bipush 42
        let instrs = BcDisassembler::disassemble(&code);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].op, JvmOp::Bipush);
        assert_eq!(instrs[0].operands[0], 42);
        assert_eq!(instrs[0].size, 2);
    }

    #[test]
    fn test_ifeq_branch_target() {
        // ifeq +5
        let code = [0x99u8, 0x00, 0x05];
        let instrs = BcDisassembler::disassemble(&code);
        assert!(instrs[0].is_branch());
        assert_eq!(instrs[0].branch_target(), Some(5));
    }

    #[test]
    fn test_return() {
        let code = [0xb1u8];
        let instrs = BcDisassembler::disassemble(&code);
        assert_eq!(instrs[0].op, JvmOp::Return);
        assert!(instrs[0].is_return());
    }

    #[test]
    fn test_invokevirtual() {
        let code = [0xb6u8, 0x00, 0x05];
        let instrs = BcDisassembler::disassemble(&code);
        assert_eq!(instrs[0].op, JvmOp::Invokevirtual);
        assert_eq!(instrs[0].operands[0], 5);
        assert_eq!(instrs[0].size, 3);
    }

    #[test]
    fn test_multiple_instructions() {
        let code = [0x03u8, 0x04, 0x60, 0xac]; // iconst_0 iconst_1 iadd ireturn
        let instrs = BcDisassembler::disassemble(&code);
        assert_eq!(instrs.len(), 4);
        assert_eq!(instrs[0].op, JvmOp::Iconst0);
        assert_eq!(instrs[1].op, JvmOp::Iconst1);
        assert_eq!(instrs[2].op, JvmOp::Iadd);
        assert_eq!(instrs[3].op, JvmOp::Ireturn);
    }

    #[test]
    fn test_pc_map() {
        let code = [0x03u8, 0x04, 0x60, 0xac];
        let instrs = BcDisassembler::disassemble(&code);
        let map = BcDisassembler::build_pc_map(&instrs);
        assert_eq!(map[&0], 0);
        assert_eq!(map[&1], 1);
        assert_eq!(map[&2], 2);
        assert_eq!(map[&3], 3);
    }

    #[test]
    fn test_stack_delta_iadd() {
        let code = [0x60u8];
        let instrs = BcDisassembler::disassemble(&code);
        assert_eq!(instrs[0].stack_delta.net(), -1); // pop 2, push 1
    }

    #[test]
    fn test_iinc() {
        let code = [0x84u8, 0x01, 0x05]; // iinc 1 5
        let instrs = BcDisassembler::disassemble(&code);
        assert_eq!(instrs[0].op, JvmOp::Iinc);
        assert_eq!(instrs[0].operands, vec![1, 5]);
        assert_eq!(instrs[0].size, 3);
    }
}
