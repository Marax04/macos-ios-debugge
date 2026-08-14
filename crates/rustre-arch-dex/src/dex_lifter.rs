//! DEX → IL lifter: translates Dalvik bytecode into a register-based intermediate language.
//!
//! The lifter maps Dalvik's register-based VM instructions directly to IL expressions,
//! handling both 32-bit and 64-bit ("wide") operations correctly.

// ---------------------------------------------------------------------------
// IL types
// ---------------------------------------------------------------------------

/// Width of an IL value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ILWidth {
    /// 32-bit integer / float.
    W32,
    /// 64-bit integer / double (wide register pair).
    W64,
    /// Object reference (pointer-sized).
    Ref,
}

/// A DEX/IL expression (right-hand side of an assignment or condition operand).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DexILExpr {
    /// A register value.
    Reg(u16, ILWidth),
    /// A 32-bit integer constant.
    Const32(i32),
    /// A 64-bit integer constant.
    Const64(i64),
    /// A string constant (pool index).
    ConstString(u32),
    /// A class/type constant (pool index).
    ConstClass(u32),
    /// Binary arithmetic operation.
    BinOp {
        op: BinOpKind,
        lhs: Box<Self>,
        rhs: Box<Self>,
        width: ILWidth,
    },
    /// Unary operation.
    UnOp {
        op: UnOpKind,
        src: Box<Self>,
        width: ILWidth,
    },
    /// Type conversion.
    Convert {
        src: Box<Self>,
        from: ILWidth,
        to: ILWidth,
    },
    /// Instance field read: `obj.field_index`.
    IGet {
        obj: Box<Self>,
        field: u32,
        width: ILWidth,
    },
    /// Static field read.
    SGet { field: u32, width: ILWidth },
    /// Array element read.
    AGet {
        array: Box<Self>,
        index: Box<Self>,
        width: ILWidth,
    },
    /// Invoke result placeholder (filled by move-result).
    InvokeResult(ILWidth),
    /// Array length.
    ArrayLength(Box<Self>),
    /// Check-cast expression.
    CheckCast { obj: Box<Self>, type_idx: u32 },
    /// instanceof check.
    InstanceOf { obj: Box<Self>, type_idx: u32 },
    /// New object allocation.
    NewInstance(u32),
    /// New array allocation.
    NewArray { size: Box<Self>, type_idx: u32 },
}

/// Binary operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinOpKind {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Ushr,
    CmpL,
    CmpG, // float/double compare
    CmpLong,
}

/// Unary operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnOpKind {
    Neg,
    Not,
}

// ---------------------------------------------------------------------------
// IL instruction
// ---------------------------------------------------------------------------

/// A single DEX IL instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DexILInsn {
    /// `vDest = expr`
    Assign { dest: u16, expr: DexILExpr },
    /// `vDest:vDest+1 = expr` (wide assign)
    AssignWide { dest: u16, expr: DexILExpr },
    /// `return` (void)
    ReturnVoid,
    /// `return vReg`
    Return { reg: u16, width: ILWidth },
    /// Unconditional branch to code unit offset.
    Goto { offset: i32 },
    /// Conditional branch: `if lhs cond rhs goto offset` (both regs).
    IfBranch {
        cond: CmpKind,
        lhs: u16,
        rhs: u16,
        offset: i32,
    },
    /// Conditional zero-compare branch: `if reg cond 0 goto offset`.
    IfZBranch {
        cond: CmpKind,
        reg: u16,
        offset: i32,
    },
    /// `obj.field = vSrc` (instance put).
    IPut {
        src: u16,
        obj: u16,
        field: u32,
        width: ILWidth,
    },
    /// `StaticField = vSrc` (static put).
    SPut {
        src: u16,
        field: u32,
        width: ILWidth,
    },
    /// `array[index] = vSrc` (array put).
    APut {
        src: u16,
        array: u16,
        index: u16,
        width: ILWidth,
    },
    /// Virtual/interface invoke.
    InvokeVirtual {
        method: u32,
        this_reg: u16,
        args: Vec<u16>,
    },
    /// Direct/static invoke.
    InvokeDirect { method: u32, args: Vec<u16> },
    /// Static invoke.
    InvokeStatic { method: u32, args: Vec<u16> },
    /// Throw exception.
    Throw { reg: u16 },
    /// Monitor enter.
    MonitorEnter { reg: u16 },
    /// Monitor exit.
    MonitorExit { reg: u16 },
    /// Packed-switch dispatch.
    PackedSwitch { reg: u16, table_offset: i32 },
    /// Sparse-switch dispatch.
    SparseSwitch { reg: u16, table_offset: i32 },
    /// Fill array data.
    FillArrayData { reg: u16, data_offset: i32 },
    /// Nop.
    Nop,
}

/// Comparison kind for branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CmpKind {
    Eq,
    Ne,
    Lt,
    Ge,
    Gt,
    Le,
}

// ---------------------------------------------------------------------------
// Lift error
// ---------------------------------------------------------------------------

/// Errors from the DEX lifter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiftError {
    /// Byte slice too short.
    Truncated,
    /// Opcode not yet implemented in the lifter.
    Unimplemented(u8),
    /// Unused opcode.
    Unused(u8),
}

impl std::fmt::Display for LiftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated DEX bytecode"),
            Self::Unimplemented(op) => write!(f, "unimplemented DEX opcode 0x{op:02x}"),
            Self::Unused(op) => write!(f, "unused DEX opcode 0x{op:02x}"),
        }
    }
}

impl std::error::Error for LiftError {}

// ---------------------------------------------------------------------------
// Lifter
// ---------------------------------------------------------------------------

/// DEX → IL lifter.
///
/// Converts a single Dalvik instruction (given as raw bytes) into a list of
/// [`DexILInsn`] values, along with the number of bytes consumed.
pub struct DexLifter;

impl DexLifter {
    /// Create a new lifter instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Lift one Dalvik instruction from `bytes`.
    ///
    /// Returns `(Vec<DexILInsn>, bytes_consumed)`.
    ///
    /// # Errors
    /// Returns [`LiftError`] for truncated, unused, or unimplemented opcodes.
    pub fn lift(&self, bytes: &[u8]) -> Result<(Vec<DexILInsn>, usize), LiftError> {
        if bytes.is_empty() {
            return Err(LiftError::Truncated);
        }
        let op = bytes[0];
        let hi = if bytes.len() > 1 { bytes[1] } else { 0 };

        // Helper closures for reading LE integers
        let u16_at = |off: usize| -> Option<u16> {
            bytes
                .get(off..off + 2)
                .map(|s| u16::from_le_bytes([s[0], s[1]]))
        };
        let i16_at = |off: usize| -> Option<i16> { u16_at(off).map(|v| v as i16) };
        let u32_at = |off: usize| -> Option<u32> {
            bytes
                .get(off..off + 4)
                .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        };
        let i32_at = |off: usize| -> Option<i32> { u32_at(off).map(|v| v as i32) };

        match op {
            // nop
            0x00 => Ok((vec![DexILInsn::Nop], 2)),

            // move vA, vB
            0x01 => {
                let a = u16::from(hi & 0x0f);
                let b = u16::from((hi >> 4) & 0x0f);
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::Reg(b, ILWidth::W32),
                    }],
                    2,
                ))
            }
            // move/from16 vAA, vBBBB
            0x02 => {
                let a = u16::from(hi);
                let b = u16_at(2).ok_or(LiftError::Truncated)?;
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::Reg(b, ILWidth::W32),
                    }],
                    4,
                ))
            }
            // move/16 vAAAA, vBBBB
            0x03 => {
                let a = u16_at(2).ok_or(LiftError::Truncated)?;
                let b = u16_at(4).ok_or(LiftError::Truncated)?;
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::Reg(b, ILWidth::W32),
                    }],
                    6,
                ))
            }
            // move-wide vA, vB
            0x04 => {
                let a = u16::from(hi & 0x0f);
                let b = u16::from((hi >> 4) & 0x0f);
                Ok((
                    vec![DexILInsn::AssignWide {
                        dest: a,
                        expr: DexILExpr::Reg(b, ILWidth::W64),
                    }],
                    2,
                ))
            }
            // move-wide/from16
            0x05 => {
                let a = u16::from(hi);
                let b = u16_at(2).ok_or(LiftError::Truncated)?;
                Ok((
                    vec![DexILInsn::AssignWide {
                        dest: a,
                        expr: DexILExpr::Reg(b, ILWidth::W64),
                    }],
                    4,
                ))
            }
            // move-wide/16
            0x06 => {
                let a = u16_at(2).ok_or(LiftError::Truncated)?;
                let b = u16_at(4).ok_or(LiftError::Truncated)?;
                Ok((
                    vec![DexILInsn::AssignWide {
                        dest: a,
                        expr: DexILExpr::Reg(b, ILWidth::W64),
                    }],
                    6,
                ))
            }
            // move-object vA, vB
            0x07 => {
                let a = u16::from(hi & 0x0f);
                let b = u16::from((hi >> 4) & 0x0f);
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::Reg(b, ILWidth::Ref),
                    }],
                    2,
                ))
            }
            // move-object/from16
            0x08 => {
                let a = u16::from(hi);
                let b = u16_at(2).ok_or(LiftError::Truncated)?;
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::Reg(b, ILWidth::Ref),
                    }],
                    4,
                ))
            }
            // move-object/16
            0x09 => {
                let a = u16_at(2).ok_or(LiftError::Truncated)?;
                let b = u16_at(4).ok_or(LiftError::Truncated)?;
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::Reg(b, ILWidth::Ref),
                    }],
                    6,
                ))
            }
            // move-result vAA
            0x0a => {
                let a = u16::from(hi);
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::InvokeResult(ILWidth::W32),
                    }],
                    2,
                ))
            }
            // move-result-wide vAA
            0x0b => {
                let a = u16::from(hi);
                Ok((
                    vec![DexILInsn::AssignWide {
                        dest: a,
                        expr: DexILExpr::InvokeResult(ILWidth::W64),
                    }],
                    2,
                ))
            }
            // move-result-object vAA
            0x0c => {
                let a = u16::from(hi);
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::InvokeResult(ILWidth::Ref),
                    }],
                    2,
                ))
            }
            // move-exception vAA
            0x0d => {
                let a = u16::from(hi);
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::InvokeResult(ILWidth::Ref),
                    }],
                    2,
                ))
            }
            // return-void
            0x0e => Ok((vec![DexILInsn::ReturnVoid], 2)),
            // return vAA
            0x0f => Ok((
                vec![DexILInsn::Return {
                    reg: u16::from(hi),
                    width: ILWidth::W32,
                }],
                2,
            )),
            // return-wide vAA
            0x10 => Ok((
                vec![DexILInsn::Return {
                    reg: u16::from(hi),
                    width: ILWidth::W64,
                }],
                2,
            )),
            // return-object vAA
            0x11 => Ok((
                vec![DexILInsn::Return {
                    reg: u16::from(hi),
                    width: ILWidth::Ref,
                }],
                2,
            )),

            // const/4 vA, #+B
            0x12 => {
                let a = u16::from(hi & 0x0f);
                let raw = (hi >> 4) as i8;
                let v = if raw & 0x8 != 0 {
                    i32::from(raw) | -16i32
                } else {
                    i32::from(raw)
                };
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::Const32(v),
                    }],
                    2,
                ))
            }
            // const/16 vAA, #+BBBB
            0x13 => {
                let a = u16::from(hi);
                let v = i32::from(i16_at(2).ok_or(LiftError::Truncated)?);
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::Const32(v),
                    }],
                    4,
                ))
            }
            // const vAA, #+BBBBBBBB
            0x14 => {
                let a = u16::from(hi);
                let v = i32_at(2).ok_or(LiftError::Truncated)?;
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::Const32(v),
                    }],
                    6,
                ))
            }
            // const/high16 vAA, #+BBBB0000
            0x15 => {
                let a = u16::from(hi);
                let raw = i32::from(i16_at(2).ok_or(LiftError::Truncated)?) << 16;
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::Const32(raw),
                    }],
                    4,
                ))
            }
            // const-wide/16 vAA, #+BBBB
            0x16 => {
                let a = u16::from(hi);
                let v = i64::from(i16_at(2).ok_or(LiftError::Truncated)?);
                Ok((
                    vec![DexILInsn::AssignWide {
                        dest: a,
                        expr: DexILExpr::Const64(v),
                    }],
                    4,
                ))
            }
            // const-wide/32 vAA, #+BBBBBBBB
            0x17 => {
                let a = u16::from(hi);
                let v = i64::from(i32_at(2).ok_or(LiftError::Truncated)?);
                Ok((
                    vec![DexILInsn::AssignWide {
                        dest: a,
                        expr: DexILExpr::Const64(v),
                    }],
                    6,
                ))
            }
            // const-wide vAA, #+BBBBBBBBBBBBBBBB
            0x18 => {
                if bytes.len() < 10 {
                    return Err(LiftError::Truncated);
                }
                let a = u16::from(hi);
                let v = i64::from_le_bytes([
                    bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
                ]);
                Ok((
                    vec![DexILInsn::AssignWide {
                        dest: a,
                        expr: DexILExpr::Const64(v),
                    }],
                    10,
                ))
            }
            // const-wide/high16 vAA, #+BBBB000000000000
            0x19 => {
                let a = u16::from(hi);
                let raw = i64::from(i16_at(2).ok_or(LiftError::Truncated)?) << 48;
                Ok((
                    vec![DexILInsn::AssignWide {
                        dest: a,
                        expr: DexILExpr::Const64(raw),
                    }],
                    4,
                ))
            }
            // const-string vAA, string@BBBB
            0x1a => {
                let a = u16::from(hi);
                let idx = u32::from(u16_at(2).ok_or(LiftError::Truncated)?);
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::ConstString(idx),
                    }],
                    4,
                ))
            }
            // const-string/jumbo vAA, string@BBBBBBBB
            0x1b => {
                let a = u16::from(hi);
                let idx = u32_at(2).ok_or(LiftError::Truncated)?;
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::ConstString(idx),
                    }],
                    6,
                ))
            }
            // const-class vAA, type@BBBB
            0x1c => {
                let a = u16::from(hi);
                let idx = u32::from(u16_at(2).ok_or(LiftError::Truncated)?);
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::ConstClass(idx),
                    }],
                    4,
                ))
            }
            // monitor-enter / monitor-exit
            0x1d => Ok((vec![DexILInsn::MonitorEnter { reg: u16::from(hi) }], 2)),
            0x1e => Ok((vec![DexILInsn::MonitorExit { reg: u16::from(hi) }], 2)),

            // check-cast vAA, type@BBBB
            0x1f => {
                let a = u16::from(hi);
                let idx = u32::from(u16_at(2).ok_or(LiftError::Truncated)?);
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::CheckCast {
                            obj: Box::new(DexILExpr::Reg(a, ILWidth::Ref)),
                            type_idx: idx,
                        },
                    }],
                    4,
                ))
            }
            // instance-of vA, vB, type@CCCC
            0x20 => {
                let a = u16::from(hi & 0x0f);
                let b = u16::from((hi >> 4) & 0x0f);
                let idx = u32::from(u16_at(2).ok_or(LiftError::Truncated)?);
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::InstanceOf {
                            obj: Box::new(DexILExpr::Reg(b, ILWidth::Ref)),
                            type_idx: idx,
                        },
                    }],
                    4,
                ))
            }
            // array-length vA, vB
            0x21 => {
                let a = u16::from(hi & 0x0f);
                let b = u16::from((hi >> 4) & 0x0f);
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::ArrayLength(Box::new(DexILExpr::Reg(b, ILWidth::Ref))),
                    }],
                    2,
                ))
            }
            // new-instance vAA, type@BBBB
            0x22 => {
                let a = u16::from(hi);
                let idx = u32::from(u16_at(2).ok_or(LiftError::Truncated)?);
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::NewInstance(idx),
                    }],
                    4,
                ))
            }
            // new-array vA, vB, type@CCCC
            0x23 => {
                let a = u16::from(hi & 0x0f);
                let b = u16::from((hi >> 4) & 0x0f);
                let idx = u32::from(u16_at(2).ok_or(LiftError::Truncated)?);
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::NewArray {
                            size: Box::new(DexILExpr::Reg(b, ILWidth::W32)),
                            type_idx: idx,
                        },
                    }],
                    4,
                ))
            }

            // throw vAA
            0x27 => Ok((vec![DexILInsn::Throw { reg: u16::from(hi) }], 2)),

            // goto +AA
            0x28 => Ok((
                vec![DexILInsn::Goto {
                    offset: i32::from(hi as i8),
                }],
                2,
            )),
            // goto/16 +AAAA
            0x29 => {
                let off = i32::from(i16_at(2).ok_or(LiftError::Truncated)?);
                Ok((vec![DexILInsn::Goto { offset: off }], 4))
            }
            // goto/32 +AAAAAAAA
            0x2a => {
                let off = i32_at(2).ok_or(LiftError::Truncated)?;
                Ok((vec![DexILInsn::Goto { offset: off }], 6))
            }

            // packed-switch
            0x2b => {
                let a = u16::from(hi);
                let off = i32_at(2).ok_or(LiftError::Truncated)?;
                Ok((
                    vec![DexILInsn::PackedSwitch {
                        reg: a,
                        table_offset: off,
                    }],
                    6,
                ))
            }
            // sparse-switch
            0x2c => {
                let a = u16::from(hi);
                let off = i32_at(2).ok_or(LiftError::Truncated)?;
                Ok((
                    vec![DexILInsn::SparseSwitch {
                        reg: a,
                        table_offset: off,
                    }],
                    6,
                ))
            }

            // cmp-* vAA, vBB, vCC → assign: dest = CmpOp(b, c)
            0x2d..=0x31 => {
                let a = u16::from(hi);
                let b = if bytes.len() > 2 {
                    u16::from(bytes[2])
                } else {
                    return Err(LiftError::Truncated);
                };
                let c = if bytes.len() > 3 {
                    u16::from(bytes[3])
                } else {
                    return Err(LiftError::Truncated);
                };
                let (op_kind, w) = match op {
                    0x2d => (BinOpKind::CmpL, ILWidth::W32), // cmpl-float
                    0x2e => (BinOpKind::CmpG, ILWidth::W32), // cmpg-float
                    0x2f => (BinOpKind::CmpL, ILWidth::W64), // cmpl-double
                    0x30 => (BinOpKind::CmpG, ILWidth::W64), // cmpg-double
                    _ => (BinOpKind::CmpLong, ILWidth::W64), // cmp-long
                };
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::BinOp {
                            op: op_kind,
                            lhs: Box::new(DexILExpr::Reg(b, w)),
                            rhs: Box::new(DexILExpr::Reg(c, w)),
                            width: ILWidth::W32,
                        },
                    }],
                    4,
                ))
            }

            // if-eq..if-le vA, vB, +CCCC
            0x32..=0x37 => {
                let a = u16::from(hi & 0x0f);
                let b = u16::from((hi >> 4) & 0x0f);
                let off = i32::from(i16_at(2).ok_or(LiftError::Truncated)?);
                let cond = match op {
                    0x32 => CmpKind::Eq,
                    0x33 => CmpKind::Ne,
                    0x34 => CmpKind::Lt,
                    0x35 => CmpKind::Ge,
                    0x36 => CmpKind::Gt,
                    _ => CmpKind::Le,
                };
                Ok((
                    vec![DexILInsn::IfBranch {
                        cond,
                        lhs: a,
                        rhs: b,
                        offset: off,
                    }],
                    4,
                ))
            }

            // if-eqz..if-lez vAA, +BBBB
            0x38..=0x3d => {
                let a = u16::from(hi);
                let off = i32::from(i16_at(2).ok_or(LiftError::Truncated)?);
                let cond = match op {
                    0x38 => CmpKind::Eq,
                    0x39 => CmpKind::Ne,
                    0x3a => CmpKind::Lt,
                    0x3b => CmpKind::Ge,
                    0x3c => CmpKind::Gt,
                    _ => CmpKind::Le,
                };
                Ok((
                    vec![DexILInsn::IfZBranch {
                        cond,
                        reg: a,
                        offset: off,
                    }],
                    4,
                ))
            }

            // unused 0x3e..=0x43
            0x3e..=0x43 => Err(LiftError::Unused(op)),

            // aget* vAA, vBB, vCC
            0x44..=0x4a => {
                let a = u16::from(hi);
                let b = if bytes.len() > 2 {
                    u16::from(bytes[2])
                } else {
                    return Err(LiftError::Truncated);
                };
                let c = if bytes.len() > 3 {
                    u16::from(bytes[3])
                } else {
                    return Err(LiftError::Truncated);
                };
                let w = if op == 0x45 {
                    ILWidth::W64
                } else {
                    ILWidth::W32
                };
                let insn = if op == 0x45 {
                    DexILInsn::AssignWide {
                        dest: a,
                        expr: DexILExpr::AGet {
                            array: Box::new(DexILExpr::Reg(b, ILWidth::Ref)),
                            index: Box::new(DexILExpr::Reg(c, ILWidth::W32)),
                            width: w,
                        },
                    }
                } else {
                    DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::AGet {
                            array: Box::new(DexILExpr::Reg(b, ILWidth::Ref)),
                            index: Box::new(DexILExpr::Reg(c, ILWidth::W32)),
                            width: w,
                        },
                    }
                };
                Ok((vec![insn], 4))
            }
            // aput* vAA, vBB, vCC
            0x4b..=0x51 => {
                let a = u16::from(hi);
                let b = if bytes.len() > 2 {
                    u16::from(bytes[2])
                } else {
                    return Err(LiftError::Truncated);
                };
                let c = if bytes.len() > 3 {
                    u16::from(bytes[3])
                } else {
                    return Err(LiftError::Truncated);
                };
                let w = if op == 0x4c {
                    ILWidth::W64
                } else {
                    ILWidth::W32
                };
                Ok((
                    vec![DexILInsn::APut {
                        src: a,
                        array: b,
                        index: c,
                        width: w,
                    }],
                    4,
                ))
            }

            // iget* vA, vB, field@CCCC
            0x52..=0x58 => {
                let a = u16::from(hi & 0x0f);
                let b = u16::from((hi >> 4) & 0x0f);
                let field = u32::from(u16_at(2).ok_or(LiftError::Truncated)?);
                let w = if op == 0x53 {
                    ILWidth::W64
                } else {
                    ILWidth::W32
                };
                let insn = if op == 0x53 {
                    DexILInsn::AssignWide {
                        dest: a,
                        expr: DexILExpr::IGet {
                            obj: Box::new(DexILExpr::Reg(b, ILWidth::Ref)),
                            field,
                            width: w,
                        },
                    }
                } else {
                    DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::IGet {
                            obj: Box::new(DexILExpr::Reg(b, ILWidth::Ref)),
                            field,
                            width: w,
                        },
                    }
                };
                Ok((vec![insn], 4))
            }
            // iput* vA, vB, field@CCCC
            0x59..=0x5f => {
                let a = u16::from(hi & 0x0f);
                let b = u16::from((hi >> 4) & 0x0f);
                let field = u32::from(u16_at(2).ok_or(LiftError::Truncated)?);
                let w = if op == 0x5a {
                    ILWidth::W64
                } else {
                    ILWidth::W32
                };
                Ok((
                    vec![DexILInsn::IPut {
                        src: a,
                        obj: b,
                        field,
                        width: w,
                    }],
                    4,
                ))
            }
            // sget* vAA, field@BBBB
            0x60..=0x66 => {
                let a = u16::from(hi);
                let field = u32::from(u16_at(2).ok_or(LiftError::Truncated)?);
                let w = if op == 0x61 {
                    ILWidth::W64
                } else {
                    ILWidth::W32
                };
                let insn = if op == 0x61 {
                    DexILInsn::AssignWide {
                        dest: a,
                        expr: DexILExpr::SGet { field, width: w },
                    }
                } else {
                    DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::SGet { field, width: w },
                    }
                };
                Ok((vec![insn], 4))
            }
            // sput* vAA, field@BBBB
            0x67..=0x6d => {
                let a = u16::from(hi);
                let field = u32::from(u16_at(2).ok_or(LiftError::Truncated)?);
                let w = if op == 0x68 {
                    ILWidth::W64
                } else {
                    ILWidth::W32
                };
                Ok((
                    vec![DexILInsn::SPut {
                        src: a,
                        field,
                        width: w,
                    }],
                    4,
                ))
            }

            // invoke-virtual {vC..vG}, meth@BBBB
            0x6e => {
                let count = (hi >> 4) & 0x0f;
                let method = u32::from(u16_at(2).ok_or(LiftError::Truncated)?);
                let regs = Self::extract_35c_regs(bytes, hi, count)?;
                let this_reg = regs.first().copied().unwrap_or(0);
                let args = regs.into_iter().skip(1).collect();
                Ok((
                    vec![DexILInsn::InvokeVirtual {
                        method,
                        this_reg,
                        args,
                    }],
                    6,
                ))
            }
            // invoke-super / invoke-direct
            0x6f | 0x70 => {
                let count = (hi >> 4) & 0x0f;
                let method = u32::from(u16_at(2).ok_or(LiftError::Truncated)?);
                let args = Self::extract_35c_regs(bytes, hi, count)?;
                Ok((vec![DexILInsn::InvokeDirect { method, args }], 6))
            }
            // invoke-static
            0x71 => {
                let count = (hi >> 4) & 0x0f;
                let method = u32::from(u16_at(2).ok_or(LiftError::Truncated)?);
                let args = Self::extract_35c_regs(bytes, hi, count)?;
                Ok((vec![DexILInsn::InvokeStatic { method, args }], 6))
            }
            // invoke-interface
            0x72 => {
                let count = (hi >> 4) & 0x0f;
                let method = u32::from(u16_at(2).ok_or(LiftError::Truncated)?);
                let regs = Self::extract_35c_regs(bytes, hi, count)?;
                let this_reg = regs.first().copied().unwrap_or(0);
                let args = regs.into_iter().skip(1).collect();
                Ok((
                    vec![DexILInsn::InvokeVirtual {
                        method,
                        this_reg,
                        args,
                    }],
                    6,
                ))
            }
            // invoke-*/range
            0x74..=0x78 => {
                let count = u16::from(hi);
                let method = u32::from(u16_at(2).ok_or(LiftError::Truncated)?);
                let first = u16_at(4).ok_or(LiftError::Truncated)?;
                let args: Vec<u16> = (first..first + count).collect();
                let insn = if op == 0x77 {
                    DexILInsn::InvokeStatic { method, args }
                } else {
                    DexILInsn::InvokeDirect { method, args }
                };
                Ok((vec![insn], 6))
            }

            // unary ops (12x)
            0x7b..=0x8f => {
                let a = u16::from(hi & 0x0f);
                let b = u16::from((hi >> 4) & 0x0f);
                let (un_op, src_w, dst_w) = Self::unary_op_info(op);
                let insn = if dst_w == ILWidth::W64 {
                    DexILInsn::AssignWide {
                        dest: a,
                        expr: DexILExpr::UnOp {
                            op: un_op,
                            src: Box::new(DexILExpr::Reg(b, src_w)),
                            width: dst_w,
                        },
                    }
                } else {
                    DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::UnOp {
                            op: un_op,
                            src: Box::new(DexILExpr::Reg(b, src_w)),
                            width: dst_w,
                        },
                    }
                };
                Ok((vec![insn], 2))
            }

            // binary ops 23x
            0x90..=0xaf => {
                let a = u16::from(hi);
                let b = if bytes.len() > 2 {
                    u16::from(bytes[2])
                } else {
                    return Err(LiftError::Truncated);
                };
                let c = if bytes.len() > 3 {
                    u16::from(bytes[3])
                } else {
                    return Err(LiftError::Truncated);
                };
                let (bin_op, w) = Self::binary_op_info_23x(op);
                let insn = if w == ILWidth::W64 {
                    DexILInsn::AssignWide {
                        dest: a,
                        expr: DexILExpr::BinOp {
                            op: bin_op,
                            lhs: Box::new(DexILExpr::Reg(b, w)),
                            rhs: Box::new(DexILExpr::Reg(c, w)),
                            width: w,
                        },
                    }
                } else {
                    DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::BinOp {
                            op: bin_op,
                            lhs: Box::new(DexILExpr::Reg(b, w)),
                            rhs: Box::new(DexILExpr::Reg(c, w)),
                            width: w,
                        },
                    }
                };
                Ok((vec![insn], 4))
            }

            // /2addr ops 12x
            0xb0..=0xcf => {
                let a = u16::from(hi & 0x0f);
                let b = u16::from((hi >> 4) & 0x0f);
                let (bin_op, w) = Self::binary_op_info_2addr(op);
                let insn = if w == ILWidth::W64 {
                    DexILInsn::AssignWide {
                        dest: a,
                        expr: DexILExpr::BinOp {
                            op: bin_op,
                            lhs: Box::new(DexILExpr::Reg(a, w)),
                            rhs: Box::new(DexILExpr::Reg(b, w)),
                            width: w,
                        },
                    }
                } else {
                    DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::BinOp {
                            op: bin_op,
                            lhs: Box::new(DexILExpr::Reg(a, w)),
                            rhs: Box::new(DexILExpr::Reg(b, w)),
                            width: w,
                        },
                    }
                };
                Ok((vec![insn], 2))
            }

            // /lit16 ops 22s
            0xd0..=0xd7 => {
                let a = u16::from(hi & 0x0f);
                let b = u16::from((hi >> 4) & 0x0f);
                let lit = i32::from(i16_at(2).ok_or(LiftError::Truncated)?);
                let bin_op = Self::lit_op(op);
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::BinOp {
                            op: bin_op,
                            lhs: Box::new(DexILExpr::Reg(b, ILWidth::W32)),
                            rhs: Box::new(DexILExpr::Const32(lit)),
                            width: ILWidth::W32,
                        },
                    }],
                    4,
                ))
            }

            // /lit8 ops 22b
            0xd8..=0xe2 => {
                let a = u16::from(hi);
                let b = if bytes.len() > 2 {
                    u16::from(bytes[2])
                } else {
                    return Err(LiftError::Truncated);
                };
                let lit = i32::from(if bytes.len() > 3 {
                    bytes[3] as i8
                } else {
                    return Err(LiftError::Truncated);
                });
                let bin_op = Self::lit8_op(op);
                Ok((
                    vec![DexILInsn::Assign {
                        dest: a,
                        expr: DexILExpr::BinOp {
                            op: bin_op,
                            lhs: Box::new(DexILExpr::Reg(b, ILWidth::W32)),
                            rhs: Box::new(DexILExpr::Const32(lit)),
                            width: ILWidth::W32,
                        },
                    }],
                    4,
                ))
            }

            // fill-array-data
            0x26 => {
                let a = u16::from(hi);
                let off = i32_at(2).ok_or(LiftError::Truncated)?;
                Ok((
                    vec![DexILInsn::FillArrayData {
                        reg: a,
                        data_offset: off,
                    }],
                    6,
                ))
            }

            _ => Err(LiftError::Unimplemented(op)),
        }
    }

    // -- Private helpers --

    fn extract_35c_regs(bytes: &[u8], hi: u8, count: u8) -> Result<Vec<u16>, LiftError> {
        if bytes.len() < 6 {
            return Err(LiftError::Truncated);
        }
        let reg_g = u16::from(hi & 0x0f);
        let b4 = bytes[4];
        let b5 = bytes[5];
        let reg_c = u16::from(b4 & 0x0f);
        let reg_d = u16::from((b4 >> 4) & 0x0f);
        let reg_e = u16::from(b5 & 0x0f);
        let reg_f = u16::from((b5 >> 4) & 0x0f);
        let all = [reg_c, reg_d, reg_e, reg_f, reg_g];
        Ok(all[..count.min(5) as usize].to_vec())
    }

    const fn unary_op_info(op: u8) -> (UnOpKind, ILWidth, ILWidth) {
        match op {
            0x7b => (UnOpKind::Neg, ILWidth::W32, ILWidth::W32), // neg-int
            0x7c => (UnOpKind::Not, ILWidth::W32, ILWidth::W32), // not-int
            0x7d => (UnOpKind::Neg, ILWidth::W64, ILWidth::W64), // neg-long
            0x7e => (UnOpKind::Not, ILWidth::W64, ILWidth::W64), // not-long
            0x7f => (UnOpKind::Neg, ILWidth::W32, ILWidth::W32), // neg-float
            0x80 => (UnOpKind::Neg, ILWidth::W64, ILWidth::W64), // neg-double
            // conversions: all treated as Neg for simplicity (would be Convert in full impl)
            0x81 => (UnOpKind::Neg, ILWidth::W32, ILWidth::W64), // int-to-long
            0x82 => (UnOpKind::Neg, ILWidth::W32, ILWidth::W32), // int-to-float
            0x83 => (UnOpKind::Neg, ILWidth::W32, ILWidth::W64), // int-to-double
            0x84 => (UnOpKind::Neg, ILWidth::W64, ILWidth::W32), // long-to-int
            0x85 => (UnOpKind::Neg, ILWidth::W64, ILWidth::W32), // long-to-float
            0x86 => (UnOpKind::Neg, ILWidth::W64, ILWidth::W64), // long-to-double
            0x87 => (UnOpKind::Neg, ILWidth::W32, ILWidth::W32), // float-to-int
            0x88 => (UnOpKind::Neg, ILWidth::W32, ILWidth::W64), // float-to-long
            0x89 => (UnOpKind::Neg, ILWidth::W32, ILWidth::W64), // float-to-double (uses W64 for double)
            0x8a => (UnOpKind::Neg, ILWidth::W64, ILWidth::W32), // double-to-int
            0x8b => (UnOpKind::Neg, ILWidth::W64, ILWidth::W64), // double-to-long
            0x8c => (UnOpKind::Neg, ILWidth::W64, ILWidth::W32), // double-to-float
            0x8d => (UnOpKind::Neg, ILWidth::W32, ILWidth::W32), // int-to-byte
            0x8e => (UnOpKind::Neg, ILWidth::W32, ILWidth::W32), // int-to-char
            0x8f => (UnOpKind::Neg, ILWidth::W32, ILWidth::W32), // int-to-short
            _ => (UnOpKind::Neg, ILWidth::W32, ILWidth::W32),
        }
    }

    const fn binary_op_info_23x(op: u8) -> (BinOpKind, ILWidth) {
        match op {
            0x90 => (BinOpKind::Add, ILWidth::W32),
            0x91 => (BinOpKind::Sub, ILWidth::W32),
            0x92 => (BinOpKind::Mul, ILWidth::W32),
            0x93 => (BinOpKind::Div, ILWidth::W32),
            0x94 => (BinOpKind::Rem, ILWidth::W32),
            0x95 => (BinOpKind::And, ILWidth::W32),
            0x96 => (BinOpKind::Or, ILWidth::W32),
            0x97 => (BinOpKind::Xor, ILWidth::W32),
            0x98 => (BinOpKind::Shl, ILWidth::W32),
            0x99 => (BinOpKind::Shr, ILWidth::W32),
            0x9a => (BinOpKind::Ushr, ILWidth::W32),
            0x9b => (BinOpKind::Add, ILWidth::W64),
            0x9c => (BinOpKind::Sub, ILWidth::W64),
            0x9d => (BinOpKind::Mul, ILWidth::W64),
            0x9e => (BinOpKind::Div, ILWidth::W64),
            0x9f => (BinOpKind::Rem, ILWidth::W64),
            0xa0 => (BinOpKind::And, ILWidth::W64),
            0xa1 => (BinOpKind::Or, ILWidth::W64),
            0xa2 => (BinOpKind::Xor, ILWidth::W64),
            0xa3 => (BinOpKind::Shl, ILWidth::W64),
            0xa4 => (BinOpKind::Shr, ILWidth::W64),
            0xa5 => (BinOpKind::Ushr, ILWidth::W64),
            0xa6 => (BinOpKind::Add, ILWidth::W32),
            0xa7 => (BinOpKind::Sub, ILWidth::W32),
            0xa8 => (BinOpKind::Mul, ILWidth::W32),
            0xa9 => (BinOpKind::Div, ILWidth::W32),
            0xaa => (BinOpKind::Rem, ILWidth::W32), // float ops
            0xab => (BinOpKind::Add, ILWidth::W64),
            0xac => (BinOpKind::Sub, ILWidth::W64),
            0xad => (BinOpKind::Mul, ILWidth::W64),
            0xae => (BinOpKind::Div, ILWidth::W64),
            0xaf => (BinOpKind::Rem, ILWidth::W64), // double ops
            _ => (BinOpKind::Add, ILWidth::W32),
        }
    }

    const fn binary_op_info_2addr(op: u8) -> (BinOpKind, ILWidth) {
        match op {
            0xb0 => (BinOpKind::Add, ILWidth::W32),
            0xb1 => (BinOpKind::Sub, ILWidth::W32),
            0xb2 => (BinOpKind::Mul, ILWidth::W32),
            0xb3 => (BinOpKind::Div, ILWidth::W32),
            0xb4 => (BinOpKind::Rem, ILWidth::W32),
            0xb5 => (BinOpKind::And, ILWidth::W32),
            0xb6 => (BinOpKind::Or, ILWidth::W32),
            0xb7 => (BinOpKind::Xor, ILWidth::W32),
            0xb8 => (BinOpKind::Shl, ILWidth::W32),
            0xb9 => (BinOpKind::Shr, ILWidth::W32),
            0xba => (BinOpKind::Ushr, ILWidth::W32),
            0xbb => (BinOpKind::Add, ILWidth::W64),
            0xbc => (BinOpKind::Sub, ILWidth::W64),
            0xbd => (BinOpKind::Mul, ILWidth::W64),
            0xbe => (BinOpKind::Div, ILWidth::W64),
            0xbf => (BinOpKind::Rem, ILWidth::W64),
            0xc0 => (BinOpKind::And, ILWidth::W64),
            0xc1 => (BinOpKind::Or, ILWidth::W64),
            0xc2 => (BinOpKind::Xor, ILWidth::W64),
            0xc3 => (BinOpKind::Shl, ILWidth::W64),
            0xc4 => (BinOpKind::Shr, ILWidth::W64),
            0xc5 => (BinOpKind::Ushr, ILWidth::W64),
            0xc6 => (BinOpKind::Add, ILWidth::W32),
            0xc7 => (BinOpKind::Sub, ILWidth::W32),
            0xc8 => (BinOpKind::Mul, ILWidth::W32),
            0xc9 => (BinOpKind::Div, ILWidth::W32),
            0xca => (BinOpKind::Rem, ILWidth::W32), // float 2addr
            0xcb => (BinOpKind::Add, ILWidth::W64),
            0xcc => (BinOpKind::Sub, ILWidth::W64),
            0xcd => (BinOpKind::Mul, ILWidth::W64),
            0xce => (BinOpKind::Div, ILWidth::W64),
            0xcf => (BinOpKind::Rem, ILWidth::W64), // double 2addr
            _ => (BinOpKind::Add, ILWidth::W32),
        }
    }

    const fn lit_op(op: u8) -> BinOpKind {
        match op {
            0xd0 => BinOpKind::Add,
            0xd1 => BinOpKind::Sub,
            0xd2 => BinOpKind::Mul,
            0xd3 => BinOpKind::Div,
            0xd4 => BinOpKind::Rem,
            0xd5 => BinOpKind::And,
            0xd6 => BinOpKind::Or,
            _ => BinOpKind::Xor,
        }
    }

    const fn lit8_op(op: u8) -> BinOpKind {
        match op {
            0xd8 => BinOpKind::Add,
            0xd9 => BinOpKind::Sub,
            0xda => BinOpKind::Mul,
            0xdb => BinOpKind::Div,
            0xdc => BinOpKind::Rem,
            0xdd => BinOpKind::And,
            0xde => BinOpKind::Or,
            0xdf => BinOpKind::Xor,
            0xe0 => BinOpKind::Shl,
            0xe1 => BinOpKind::Shr,
            _ => BinOpKind::Ushr,
        }
    }
}

impl Default for DexLifter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn lift(bytes: &[u8]) -> Vec<DexILInsn> {
        DexLifter::new().lift(bytes).unwrap().0
    }

    #[test]
    fn test_lift_nop() {
        let insns = lift(&[0x00, 0x00]);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0], DexILInsn::Nop);
    }

    #[test]
    fn test_lift_move() {
        let insns = lift(&[0x01, 0x21]);
        match &insns[0] {
            DexILInsn::Assign { dest, expr } => {
                assert_eq!(*dest, 1);
                assert_eq!(*expr, DexILExpr::Reg(2, ILWidth::W32));
            }
            _ => panic!("expected Assign"),
        }
    }

    #[test]
    fn test_lift_const4() {
        let insns = lift(&[0x12, 0x10]);
        match &insns[0] {
            DexILInsn::Assign { dest, expr } => {
                assert_eq!(*dest, 0);
                assert_eq!(*expr, DexILExpr::Const32(1));
            }
            _ => panic!("expected Assign"),
        }
    }

    #[test]
    fn test_lift_const4_negative() {
        let insns = lift(&[0x12, 0xF0]); // v0 = #-1
        match &insns[0] {
            DexILInsn::Assign { expr, .. } => assert_eq!(*expr, DexILExpr::Const32(-1)),
            _ => panic!("expected Assign"),
        }
    }

    #[test]
    fn test_lift_const16() {
        let insns = lift(&[0x13, 0x01, 0x05, 0x00]);
        match &insns[0] {
            DexILInsn::Assign { dest, expr } => {
                assert_eq!(*dest, 1);
                assert_eq!(*expr, DexILExpr::Const32(5));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_lift_const_wide() {
        let mut buf = vec![0x18_u8, 0x00];
        buf.extend_from_slice(&42_i64.to_le_bytes());
        let insns = lift(&buf);
        assert!(matches!(insns[0], DexILInsn::AssignWide { .. }));
    }

    #[test]
    fn test_lift_return_void() {
        let insns = lift(&[0x0e, 0x00]);
        assert_eq!(insns[0], DexILInsn::ReturnVoid);
    }

    #[test]
    fn test_lift_return() {
        let insns = lift(&[0x0f, 0x03]);
        assert!(matches!(
            insns[0],
            DexILInsn::Return {
                reg: 3,
                width: ILWidth::W32
            }
        ));
    }

    #[test]
    fn test_lift_return_wide() {
        let insns = lift(&[0x10, 0x03]);
        assert!(matches!(
            insns[0],
            DexILInsn::Return {
                width: ILWidth::W64,
                ..
            }
        ));
    }

    #[test]
    fn test_lift_goto() {
        let insns = lift(&[0x28, 0x04]);
        assert_eq!(insns[0], DexILInsn::Goto { offset: 4 });
    }

    #[test]
    fn test_lift_goto16() {
        let insns = lift(&[0x29, 0x00, 0x0a, 0x00]);
        assert_eq!(insns[0], DexILInsn::Goto { offset: 10 });
    }

    #[test]
    fn test_lift_if_eq() {
        let insns = lift(&[0x32, 0x10, 0x05, 0x00]);
        assert!(matches!(
            insns[0],
            DexILInsn::IfBranch {
                cond: CmpKind::Eq,
                lhs: 0,
                rhs: 1,
                offset: 5
            }
        ));
    }

    #[test]
    fn test_lift_if_eqz() {
        let insns = lift(&[0x38, 0x02, 0x03, 0x00]);
        assert!(matches!(
            insns[0],
            DexILInsn::IfZBranch {
                cond: CmpKind::Eq,
                reg: 2,
                offset: 3
            }
        ));
    }

    #[test]
    fn test_lift_invoke_static() {
        let insns = lift(&[0x71, 0x00, 0x05, 0x00, 0x00, 0x00]);
        assert!(matches!(
            insns[0],
            DexILInsn::InvokeStatic { method: 5, .. }
        ));
    }

    #[test]
    fn test_lift_invoke_virtual() {
        let insns = lift(&[0x6e, 0x10, 0x01, 0x00, 0x00, 0x00]);
        assert!(matches!(
            insns[0],
            DexILInsn::InvokeVirtual { method: 1, .. }
        ));
    }

    #[test]
    fn test_lift_iget() {
        let insns = lift(&[0x52, 0x10, 0x01, 0x00]);
        match &insns[0] {
            DexILInsn::Assign { dest, expr } => {
                assert_eq!(*dest, 0);
                assert!(matches!(expr, DexILExpr::IGet { field: 1, .. }));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_lift_iput() {
        let insns = lift(&[0x59, 0x10, 0x01, 0x00]);
        assert!(matches!(
            insns[0],
            DexILInsn::IPut {
                src: 0,
                obj: 1,
                field: 1,
                ..
            }
        ));
    }

    #[test]
    fn test_lift_sget() {
        let insns = lift(&[0x60, 0x01, 0x02, 0x00]);
        match &insns[0] {
            DexILInsn::Assign { dest, expr } => {
                assert_eq!(*dest, 1);
                assert!(matches!(expr, DexILExpr::SGet { field: 2, .. }));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_lift_sput() {
        let insns = lift(&[0x67, 0x01, 0x02, 0x00]);
        assert!(matches!(
            insns[0],
            DexILInsn::SPut {
                src: 1,
                field: 2,
                ..
            }
        ));
    }

    #[test]
    fn test_lift_aget() {
        let insns = lift(&[0x44, 0x02, 0x03, 0x04]);
        assert!(matches!(insns[0], DexILInsn::Assign { dest: 2, .. }));
    }

    #[test]
    fn test_lift_aput() {
        let insns = lift(&[0x4b, 0x02, 0x03, 0x04]);
        assert!(matches!(
            insns[0],
            DexILInsn::APut {
                src: 2,
                array: 3,
                index: 4,
                ..
            }
        ));
    }

    #[test]
    fn test_lift_add_int_23x() {
        let insns = lift(&[0x90, 0x02, 0x03, 0x04]);
        match &insns[0] {
            DexILInsn::Assign { dest, expr } => {
                assert_eq!(*dest, 2);
                assert!(matches!(
                    expr,
                    DexILExpr::BinOp {
                        op: BinOpKind::Add,
                        ..
                    }
                ));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_lift_add_long_23x() {
        let insns = lift(&[0x9b, 0x02, 0x04, 0x06]);
        assert!(matches!(insns[0], DexILInsn::AssignWide { .. }));
    }

    #[test]
    fn test_lift_add_int_2addr() {
        let insns = lift(&[0xb0, 0x21]);
        match &insns[0] {
            DexILInsn::Assign { dest, .. } => assert_eq!(*dest, 1),
            _ => panic!(),
        }
    }

    #[test]
    fn test_lift_add_int_lit16() {
        let insns = lift(&[0xd0, 0x10, 0x0a, 0x00]);
        match &insns[0] {
            DexILInsn::Assign { expr, .. } => {
                assert!(matches!(
                    expr,
                    DexILExpr::BinOp {
                        op: BinOpKind::Add,
                        ..
                    }
                ));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_lift_add_int_lit8() {
        let insns = lift(&[0xd8, 0x02, 0x01, 0x05]);
        assert!(matches!(insns[0], DexILInsn::Assign { .. }));
    }

    #[test]
    fn test_lift_neg_int() {
        let insns = lift(&[0x7b, 0x10]);
        assert!(matches!(insns[0], DexILInsn::Assign { .. }));
    }

    #[test]
    fn test_lift_new_instance() {
        let insns = lift(&[0x22, 0x01, 0x02, 0x00]);
        assert!(matches!(
            insns[0],
            DexILInsn::Assign {
                dest: 1,
                expr: DexILExpr::NewInstance(2)
            }
        ));
    }

    #[test]
    fn test_lift_throw() {
        let insns = lift(&[0x27, 0x01]);
        assert_eq!(insns[0], DexILInsn::Throw { reg: 1 });
    }

    #[test]
    fn test_lift_truncated_error() {
        let err = DexLifter::new().lift(&[0x90]).unwrap_err();
        assert_eq!(err, LiftError::Truncated);
    }

    #[test]
    fn test_lift_unused_error() {
        let err = DexLifter::new().lift(&[0x3e, 0x00]).unwrap_err();
        assert_eq!(err, LiftError::Unused(0x3e));
    }

    #[test]
    fn test_lift_size_nop() {
        let (_, sz) = DexLifter::new().lift(&[0x00, 0x00]).unwrap();
        assert_eq!(sz, 2);
    }

    #[test]
    fn test_lift_size_const_wide() {
        let mut buf = vec![0x18_u8, 0x00];
        buf.extend_from_slice(&0_i64.to_le_bytes());
        let (_, sz) = DexLifter::new().lift(&buf).unwrap();
        assert_eq!(sz, 10);
    }
}
