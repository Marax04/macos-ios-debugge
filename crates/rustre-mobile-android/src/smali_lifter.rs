//! Dalvik bytecode lifter.
//!
//! Converts Dalvik / DEX opcodes (as parsed from a `.dex` file) into a
//! higher-level SSA-like intermediate representation suitable for further
//! analysis such as data-flow, control-flow reconstruction, and taint
//! tracking.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Dalvik opcode table (subset)
// ---------------------------------------------------------------------------

/// Dalvik opcode identifiers (single-byte opcodes only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DalvikOpcode {
    Nop = 0x00,
    Move = 0x01,
    MoveFrom16 = 0x02,
    Move16 = 0x03,
    MoveWide = 0x04,
    MoveWideFrom16 = 0x05,
    MoveWide16 = 0x06,
    MoveObject = 0x07,
    MoveResult = 0x0A,
    MoveResultWide = 0x0B,
    MoveResultObject = 0x0C,
    ReturnVoid = 0x0E,
    Return = 0x0F,
    ReturnWide = 0x10,
    ReturnObject = 0x11,
    Const4 = 0x12,
    Const16 = 0x13,
    Const = 0x14,
    ConstHigh16 = 0x15,
    ConstWide16 = 0x16,
    ConstString = 0x1A,
    ConstClass = 0x1C,
    MonitorEnter = 0x1D,
    MonitorExit = 0x1E,
    CheckCast = 0x1F,
    InstanceOf = 0x20,
    ArrayLength = 0x21,
    NewInstance = 0x22,
    NewArray = 0x23,
    FilledNewArray = 0x24,
    FillArrayData = 0x26,
    Throw = 0x27,
    Goto = 0x28,
    Goto16 = 0x29,
    Goto32 = 0x2A,
    PackedSwitch = 0x2B,
    SparseSwitch = 0x2C,
    IGet = 0x52,
    IPut = 0x59,
    SGet = 0x60,
    SPut = 0x67,
    InvokeVirtual = 0x6E,
    InvokeSuper = 0x6F,
    InvokeDirect = 0x70,
    InvokeStatic = 0x71,
    InvokeInterface = 0x72,
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
    Aget = 0x44,
    Aput = 0x4B,
    IfEq = 0x32,
    IfNe = 0x33,
    IfLt = 0x34,
    IfGe = 0x35,
    IfGt = 0x36,
    IfLe = 0x37,
    IfEqz = 0x38,
    IfNez = 0x39,
    Unknown = 0xFF,
}

impl DalvikOpcode {
    /// Decode from a raw byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Nop,
            0x01 => Self::Move,
            0x02 => Self::MoveFrom16,
            0x03 => Self::Move16,
            0x04 => Self::MoveWide,
            0x05 => Self::MoveWideFrom16,
            0x06 => Self::MoveWide16,
            0x07 => Self::MoveObject,
            0x0A => Self::MoveResult,
            0x0B => Self::MoveResultWide,
            0x0C => Self::MoveResultObject,
            0x0E => Self::ReturnVoid,
            0x0F => Self::Return,
            0x10 => Self::ReturnWide,
            0x11 => Self::ReturnObject,
            0x12 => Self::Const4,
            0x13 => Self::Const16,
            0x14 => Self::Const,
            0x15 => Self::ConstHigh16,
            0x16 => Self::ConstWide16,
            0x1A => Self::ConstString,
            0x1C => Self::ConstClass,
            0x1D => Self::MonitorEnter,
            0x1E => Self::MonitorExit,
            0x1F => Self::CheckCast,
            0x20 => Self::InstanceOf,
            0x21 => Self::ArrayLength,
            0x22 => Self::NewInstance,
            0x23 => Self::NewArray,
            0x24 => Self::FilledNewArray,
            0x26 => Self::FillArrayData,
            0x27 => Self::Throw,
            0x28 => Self::Goto,
            0x29 => Self::Goto16,
            0x2A => Self::Goto32,
            0x2B => Self::PackedSwitch,
            0x2C => Self::SparseSwitch,
            0x32 => Self::IfEq,
            0x33 => Self::IfNe,
            0x34 => Self::IfLt,
            0x35 => Self::IfGe,
            0x36 => Self::IfGt,
            0x37 => Self::IfLe,
            0x38 => Self::IfEqz,
            0x39 => Self::IfNez,
            0x44 => Self::Aget,
            0x4B => Self::Aput,
            0x52 => Self::IGet,
            0x59 => Self::IPut,
            0x60 => Self::SGet,
            0x67 => Self::SPut,
            0x6E => Self::InvokeVirtual,
            0x6F => Self::InvokeSuper,
            0x70 => Self::InvokeDirect,
            0x71 => Self::InvokeStatic,
            0x72 => Self::InvokeInterface,
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
            _ => Self::Unknown,
        }
    }

    /// Returns `true` if this opcode terminates a basic block.
    #[must_use]
    pub const fn is_terminator(&self) -> bool {
        matches!(
            self,
            Self::ReturnVoid
                | Self::Return
                | Self::ReturnWide
                | Self::ReturnObject
                | Self::Goto
                | Self::Goto16
                | Self::Goto32
                | Self::IfEq
                | Self::IfNe
                | Self::IfLt
                | Self::IfGe
                | Self::IfGt
                | Self::IfLe
                | Self::IfEqz
                | Self::IfNez
                | Self::Throw
                | Self::PackedSwitch
                | Self::SparseSwitch
        )
    }

    /// Returns `true` if this is an invoke-kind opcode.
    #[must_use]
    pub const fn is_invoke(&self) -> bool {
        matches!(
            self,
            Self::InvokeVirtual
                | Self::InvokeSuper
                | Self::InvokeDirect
                | Self::InvokeStatic
                | Self::InvokeInterface
        )
    }
}

// ---------------------------------------------------------------------------
// DalvikInstr —" raw decoded instruction
// ---------------------------------------------------------------------------

/// A raw Dalvik instruction decoded from the bytecode stream.
///
/// Dalvik uses 16-bit code units; all fields are in units of 16-bit words.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DalvikInstr {
    /// Byte offset within the method code buffer.
    pub offset: u32,
    /// Decoded opcode.
    pub opcode: DalvikOpcode,
    /// Destination register (vA), if applicable.
    pub v_a: Option<u16>,
    /// Source register (vB), if applicable.
    pub v_b: Option<u16>,
    /// Second source register or literal (vC), if applicable.
    pub v_c: Option<i32>,
    /// Index operand (method/field/type/string reference).
    pub index: Option<u32>,
    /// Branch target offset (signed, in code units from instruction start).
    pub branch_offset: Option<i32>,
    /// Raw code units of this instruction.
    pub code_units: u8,
}

impl DalvikInstr {
    /// Returns `true` if this instruction terminates its basic block.
    #[must_use]
    pub const fn is_terminator(&self) -> bool {
        self.opcode.is_terminator()
    }

    /// Returns `true` if this is an unconditional branch.
    #[must_use]
    pub const fn is_unconditional_branch(&self) -> bool {
        matches!(
            self.opcode,
            DalvikOpcode::Goto | DalvikOpcode::Goto16 | DalvikOpcode::Goto32
        )
    }

    /// Returns `true` if this is a return instruction.
    #[must_use]
    pub const fn is_return(&self) -> bool {
        matches!(
            self.opcode,
            DalvikOpcode::ReturnVoid
                | DalvikOpcode::Return
                | DalvikOpcode::ReturnWide
                | DalvikOpcode::ReturnObject
        )
    }
}

// ---------------------------------------------------------------------------
// DalvikBlock —" a linear sequence of instructions with one entry and at most
// two exits.
// ---------------------------------------------------------------------------

/// A basic block in the lifted Dalvik CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DalvikBlock {
    /// Block ID (typically the byte offset of the first instruction).
    pub id: u32,
    /// Instructions in this block (all non-terminating + the terminator).
    pub instrs: Vec<DalvikInstr>,
    /// Fall-through successor block ID, if any.
    pub fall_through: Option<u32>,
    /// Branch successor block ID (for conditional branches / goto), if any.
    pub branch_target: Option<u32>,
}

impl DalvikBlock {
    /// Returns `true` if this block ends with an unconditional branch.
    #[must_use]
    pub fn is_unconditional(&self) -> bool {
        self.instrs
            .last()
            .is_some_and(DalvikInstr::is_unconditional_branch)
    }

    /// Returns `true` if this block ends with a return.
    #[must_use]
    pub fn is_exit(&self) -> bool {
        self.instrs.last().is_some_and(DalvikInstr::is_return)
    }

    /// Returns the terminating instruction, if any.
    #[must_use]
    pub fn terminator(&self) -> Option<&DalvikInstr> {
        self.instrs.last().filter(|i| i.is_terminator())
    }
}

// ---------------------------------------------------------------------------
// Lifted IR value types
// ---------------------------------------------------------------------------

/// An SSA-like value produced by a lifted instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IrValue {
    /// A Dalvik virtual register (vN).
    Reg(u16),
    /// An integer constant.
    Const(i64),
    /// A string constant.
    StringConst(String),
    /// A class/type reference (descriptor string).
    ClassRef(String),
    /// The result of the immediately preceding invoke.
    InvokeResult,
    /// An unresolved / unknown value.
    Unknown,
}

/// A lifted IR instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrInstr {
    /// Original Dalvik instruction offset.
    pub offset: u32,
    /// High-level operation kind.
    pub kind: IrKind,
    /// Destination (SSA lvalue), if any.
    pub dest: Option<u16>,
    /// Operands.
    pub operands: Vec<IrValue>,
}

/// High-level IR operation kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IrKind {
    /// Register-to-register copy.
    Copy,
    /// Load integer constant.
    LoadConst,
    /// Load string constant.
    LoadString,
    /// Binary arithmetic / bitwise operation.
    BinOp(BinOp),
    /// Field read (instance or static).
    FieldGet { is_static: bool },
    /// Field write (instance or static).
    FieldPut { is_static: bool },
    /// Array element read.
    ArrayGet,
    /// Array element write.
    ArrayPut,
    /// Object allocation (`new-instance`).
    NewObject,
    /// Array allocation (`new-array`).
    NewArray,
    /// Method invocation.
    Invoke { kind: InvokeKind },
    /// Conditional or unconditional branch.
    Branch { cond: Option<BranchCond> },
    /// Return from method.
    Return,
    /// Throw exception.
    Throw,
    /// Any other opcode not explicitly lifted.
    Other,
}

/// Binary operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinOp {
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
}

/// Method invocation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvokeKind {
    Virtual,
    Super,
    Direct,
    Static,
    Interface,
}

/// Branch condition kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BranchCond {
    Eq,
    Ne,
    Lt,
    Ge,
    Gt,
    Le,
    EqZ,
    NeZ,
}

// ---------------------------------------------------------------------------
// LiftedMethod —" the result of lifting a single Dalvik method
// ---------------------------------------------------------------------------

/// A fully lifted Dalvik method with CFG and IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiftedMethod {
    /// Method descriptor (e.g. `Lcom/example/Foo;->bar(I)V`).
    pub descriptor: String,
    /// Basic blocks, indexed by block ID (start offset).
    pub blocks: HashMap<u32, DalvikBlock>,
    /// Entry block ID (always 0 for standard methods).
    pub entry: u32,
    /// Number of registers declared in the code header.
    pub register_count: u16,
    /// Number of in-parameters.
    pub ins_count: u16,
    /// Lifted IR instructions (flat, parallel to the raw instruction stream).
    pub ir: Vec<IrInstr>,
}

impl LiftedMethod {
    /// Number of basic blocks.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// All invoke IR instructions.
    #[must_use]
    pub fn invocations(&self) -> Vec<&IrInstr> {
        self.ir
            .iter()
            .filter(|i| matches!(i.kind, IrKind::Invoke { .. }))
            .collect()
    }

    /// All string constants loaded by this method.
    #[must_use]
    pub fn string_constants(&self) -> Vec<&str> {
        self.ir
            .iter()
            .filter_map(|i| {
                if matches!(&i.kind, IrKind::LoadString) {
                    i.operands.iter().find_map(|op| {
                        if let IrValue::StringConst(s) = op {
                            Some(s.as_str())
                        } else {
                            None
                        }
                    })
                } else {
                    None
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// SmaliLifter
// ---------------------------------------------------------------------------

/// Lifts raw Dalvik bytecode into [`LiftedMethod`] IR.
///
/// The lifter works in two passes:
/// 1. **Decode pass**: decode all Dalvik instructions into [`DalvikInstr`]s.
/// 2. **Partition pass**: split the instruction stream into [`DalvikBlock`]s
///    at every branch target and every terminator.
///
/// The CFG edges are computed from branch target offsets during the partition
/// pass.  Full SSA renaming is *not* performed; register numbers are preserved
/// as-is to keep the lifter lightweight.
pub struct SmaliLifter {
    /// String pool for resolving constant-string references.
    strings: Vec<String>,
    /// Type pool for class/type references.
    types: Vec<String>,
    /// Method pool for method references (index â†' "class->method(sig)ret").
    methods: Vec<String>,
}

impl SmaliLifter {
    /// Create a lifter with empty pools.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            strings: Vec::new(),
            types: Vec::new(),
            methods: Vec::new(),
        }
    }

    /// Register the string pool.
    pub fn set_strings(&mut self, strings: Vec<String>) {
        self.strings = strings;
    }

    /// Register the type pool.
    pub fn set_types(&mut self, types: Vec<String>) {
        self.types = types;
    }

    /// Register the method pool.
    pub fn set_methods(&mut self, methods: Vec<String>) {
        self.methods = methods;
    }

    /// Lift a raw method code buffer.
    ///
    /// `code` is the raw bytes of the `code_item` starting at the first
    /// instruction (i.e. after the `registers_size`, `ins_size`, `outs_size`,
    /// `tries_size`, `debug_info_off`, and `insns_size` header fields).
    ///
    /// `register_count` and `ins_count` are taken from the `code_item` header.
    #[must_use]
    pub fn lift(
        &self,
        descriptor: impl Into<String>,
        code: &[u8],
        register_count: u16,
        ins_count: u16,
    ) -> LiftedMethod {
        let descriptor = descriptor.into();
        let instrs = self.decode_instructions(code);
        let ir = self.lower_to_ir(&instrs);
        let blocks = self.build_cfg(instrs);
        LiftedMethod {
            descriptor,
            blocks,
            entry: 0,
            register_count,
            ins_count,
            ir,
        }
    }

    /// Decode the instruction stream into a flat list of [`DalvikInstr`]s.
    fn decode_instructions(&self, code: &[u8]) -> Vec<DalvikInstr> {
        let mut result = Vec::new();
        let mut pos = 0usize; // byte position

        while pos < code.len() {
            let opcode_byte = code[pos];
            let op = DalvikOpcode::from_byte(opcode_byte);

            // Most Dalvik instructions are 1-3 code units (2-6 bytes).
            let (instr, size_bytes) = decode_one(op, code, pos, &self.strings, &self.types, &self.methods);
            result.push(instr);
            pos += size_bytes;
        }

        result
    }

    /// Partition a decoded instruction list into basic blocks.
    fn build_cfg(&self, instrs: Vec<DalvikInstr>) -> HashMap<u32, DalvikBlock> {
        if instrs.is_empty() {
            return HashMap::new();
        }

        // Collect all block entry points (branch targets + method entry).
        let mut entries: std::collections::HashSet<u32> = std::collections::HashSet::new();
        entries.insert(0);
        for i in &instrs {
            if let Some(off) = i.branch_offset {
                let target = (i64::from(i.offset) + i64::from(off)) as u32;
                entries.insert(target);
                // Instruction after a conditional branch is also an entry.
                let fall = i.offset + u32::from(i.code_units) * 2;
                entries.insert(fall);
            }
        }

        // Group instructions into blocks.
        let mut blocks: HashMap<u32, DalvikBlock> = HashMap::new();
        let mut current_id = 0u32;
        let mut current_instrs: Vec<DalvikInstr> = Vec::new();

        for instr in instrs {
            if entries.contains(&instr.offset) && !current_instrs.is_empty() {
                // Flush current block.
                let fall = current_instrs
                    .last()
                    .map(|i| i.offset + u32::from(i.code_units) * 2);
                let branch = current_instrs.last().and_then(|i| {
                    i.branch_offset
                        .map(|off| (i64::from(i.offset) + i64::from(off)) as u32)
                });
                blocks.insert(
                    current_id,
                    DalvikBlock {
                        id: current_id,
                        instrs: current_instrs.clone(),
                        fall_through: if current_instrs
                            .last()
                            .is_some_and(|i| !i.is_unconditional_branch() && !i.is_return())
                        {
                            fall
                        } else {
                            None
                        },
                        branch_target: branch,
                    },
                );
                current_instrs.clear();
                current_id = instr.offset;
            }
            let is_term = instr.is_terminator();
            current_instrs.push(instr);
            if is_term {
                // Flush immediately.
                let fall = current_instrs
                    .last()
                    .map(|i| i.offset + u32::from(i.code_units) * 2);
                let branch = current_instrs.last().and_then(|i| {
                    i.branch_offset
                        .map(|off| (i64::from(i.offset) + i64::from(off)) as u32)
                });
                blocks.insert(
                    current_id,
                    DalvikBlock {
                        id: current_id,
                        instrs: current_instrs.clone(),
                        fall_through: if current_instrs
                            .last()
                            .is_some_and(|i| !i.is_unconditional_branch() && !i.is_return())
                        {
                            fall
                        } else {
                            None
                        },
                        branch_target: branch,
                    },
                );
                current_instrs.clear();
                current_id = current_instrs.last().map_or(0, |i| i.offset);
            }
        }
        // Flush final block.
        if !current_instrs.is_empty() {
            blocks.insert(
                current_id,
                DalvikBlock {
                    id: current_id,
                    instrs: current_instrs,
                    fall_through: None,
                    branch_target: None,
                },
            );
        }

        blocks
    }

    /// Lower decoded instructions to the IR.
    fn lower_to_ir(&self, instrs: &[DalvikInstr]) -> Vec<IrInstr> {
        instrs.iter().map(lower_one).collect()
    }
}

impl Default for SmaliLifter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Instruction decoder
// ---------------------------------------------------------------------------

fn decode_one(
    op: DalvikOpcode,
    code: &[u8],
    pos: usize,
    strings: &[String],
    types: &[String],
    methods: &[String],
) -> (DalvikInstr, usize) {
    let b1 = u16::from(*code.get(pos + 1).unwrap_or(&0));
    let v_a = (b1 >> 4) & 0xF;
    let v_b_nibble = b1 & 0xF;

    let w1 = read_u16(code, pos + 2);
    let w2 = read_u16(code, pos + 4);

    macro_rules! instr {
        ($units:expr) => {
            DalvikInstr {
                offset: pos as u32,
                opcode: op,
                v_a: None,
                v_b: None,
                v_c: None,
                index: None,
                branch_offset: None,
                code_units: $units,
            }
        };
    }

    match op {
        DalvikOpcode::Nop => (instr!(1), 2),

        DalvikOpcode::Move | DalvikOpcode::MoveWide | DalvikOpcode::MoveObject => {
            let mut i = instr!(1);
            i.v_a = Some(v_a);
            i.v_b = Some(v_b_nibble);
            (i, 2)
        }

        DalvikOpcode::MoveFrom16
        | DalvikOpcode::MoveWideFrom16 => {
            let mut i = instr!(2);
            i.v_a = Some(b1);
            i.v_b = Some(w1);
            (i, 4)
        }

        DalvikOpcode::ReturnVoid => (instr!(1), 2),

        DalvikOpcode::Return
        | DalvikOpcode::ReturnWide
        | DalvikOpcode::ReturnObject => {
            let mut i = instr!(1);
            i.v_a = Some(b1);
            (i, 2)
        }

        DalvikOpcode::Const4 => {
            let mut i = instr!(1);
            i.v_a = Some(v_a);
            i.v_c = Some(i32::from(v_b_nibble as i8));
            (i, 2)
        }

        DalvikOpcode::Const16 | DalvikOpcode::ConstWide16 => {
            let mut i = instr!(2);
            i.v_a = Some(b1);
            i.v_c = Some(i32::from(w1 as i16));
            (i, 4)
        }

        DalvikOpcode::Const => {
            let mut i = instr!(3);
            i.v_a = Some(b1);
            i.v_c = Some(i32::from_le_bytes([
                code.get(pos + 2).copied().unwrap_or(0),
                code.get(pos + 3).copied().unwrap_or(0),
                code.get(pos + 4).copied().unwrap_or(0),
                code.get(pos + 5).copied().unwrap_or(0),
            ]));
            (i, 6)
        }

        DalvikOpcode::ConstString | DalvikOpcode::ConstClass => {
            let mut i = instr!(2);
            i.v_a = Some(b1);
            i.index = Some(u32::from(w1));
            (i, 4)
        }

        DalvikOpcode::Goto => {
            let mut i = instr!(1);
            i.branch_offset = Some(i32::from(b1 as i8));
            (i, 2)
        }

        DalvikOpcode::Goto16 => {
            let mut i = instr!(2);
            i.branch_offset = Some(i32::from(w1 as i16));
            (i, 4)
        }

        DalvikOpcode::Goto32 => {
            let w3 = read_u16(code, pos + 4);
            let val = (u32::from(w1) | (u32::from(w3) << 16)) as i32;
            let mut i = instr!(3);
            i.branch_offset = Some(val);
            (i, 6)
        }

        DalvikOpcode::IfEq
        | DalvikOpcode::IfNe
        | DalvikOpcode::IfLt
        | DalvikOpcode::IfGe
        | DalvikOpcode::IfGt
        | DalvikOpcode::IfLe => {
            let mut i = instr!(2);
            i.v_a = Some(v_a);
            i.v_b = Some(v_b_nibble);
            i.branch_offset = Some(i32::from(w1 as i16));
            (i, 4)
        }

        DalvikOpcode::IfEqz | DalvikOpcode::IfNez => {
            let mut i = instr!(2);
            i.v_a = Some(b1);
            i.branch_offset = Some(i32::from(w1 as i16));
            (i, 4)
        }

        DalvikOpcode::InvokeVirtual
        | DalvikOpcode::InvokeSuper
        | DalvikOpcode::InvokeDirect
        | DalvikOpcode::InvokeStatic
        | DalvikOpcode::InvokeInterface => {
            let _ = methods;
            let mut i = instr!(3);
            i.index = Some(u32::from(w1));
            (i, 6)
        }

        DalvikOpcode::IGet | DalvikOpcode::IPut | DalvikOpcode::SGet | DalvikOpcode::SPut => {
            let mut i = instr!(2);
            i.v_a = Some(v_a);
            i.v_b = Some(v_b_nibble);
            i.index = Some(u32::from(w1));
            (i, 4)
        }

        DalvikOpcode::NewInstance => {
            let mut i = instr!(2);
            i.v_a = Some(b1);
            i.index = Some(u32::from(w1));
            let type_name = types.get(u32::from(w1) as usize).cloned().unwrap_or_default();
            let _ = type_name;
            (i, 4)
        }

        DalvikOpcode::AddInt
        | DalvikOpcode::SubInt
        | DalvikOpcode::MulInt
        | DalvikOpcode::DivInt
        | DalvikOpcode::RemInt
        | DalvikOpcode::AndInt
        | DalvikOpcode::OrInt
        | DalvikOpcode::XorInt
        | DalvikOpcode::ShlInt
        | DalvikOpcode::ShrInt => {
            let mut i = instr!(2);
            i.v_a = Some(b1);
            i.v_b = Some(v_a);
            i.v_c = Some(i32::from(v_b_nibble) | (i32::from(w1) << 4));
            (i, 4)
        }

        _ => {
            let _ = (w1, w2, strings);
            (instr!(1), 2)
        }
    }
}

fn read_u16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn lower_one(instr: &DalvikInstr) -> IrInstr {
    let kind = match instr.opcode {
        DalvikOpcode::Move
        | DalvikOpcode::MoveWide
        | DalvikOpcode::MoveObject
        | DalvikOpcode::MoveFrom16
        | DalvikOpcode::MoveWideFrom16
        | DalvikOpcode::MoveResult
        | DalvikOpcode::MoveResultWide
        | DalvikOpcode::MoveResultObject => IrKind::Copy,

        DalvikOpcode::Const4
        | DalvikOpcode::Const16
        | DalvikOpcode::Const
        | DalvikOpcode::ConstHigh16
        | DalvikOpcode::ConstWide16 => IrKind::LoadConst,

        DalvikOpcode::ConstString => IrKind::LoadString,

        DalvikOpcode::AddInt => IrKind::BinOp(BinOp::Add),
        DalvikOpcode::SubInt => IrKind::BinOp(BinOp::Sub),
        DalvikOpcode::MulInt => IrKind::BinOp(BinOp::Mul),
        DalvikOpcode::DivInt => IrKind::BinOp(BinOp::Div),
        DalvikOpcode::RemInt => IrKind::BinOp(BinOp::Rem),
        DalvikOpcode::AndInt => IrKind::BinOp(BinOp::And),
        DalvikOpcode::OrInt => IrKind::BinOp(BinOp::Or),
        DalvikOpcode::XorInt => IrKind::BinOp(BinOp::Xor),
        DalvikOpcode::ShlInt => IrKind::BinOp(BinOp::Shl),
        DalvikOpcode::ShrInt => IrKind::BinOp(BinOp::Shr),

        DalvikOpcode::IGet | DalvikOpcode::SGet => IrKind::FieldGet {
            is_static: instr.opcode == DalvikOpcode::SGet,
        },
        DalvikOpcode::IPut | DalvikOpcode::SPut => IrKind::FieldPut {
            is_static: instr.opcode == DalvikOpcode::SPut,
        },

        DalvikOpcode::Aget => IrKind::ArrayGet,
        DalvikOpcode::Aput => IrKind::ArrayPut,

        DalvikOpcode::NewInstance => IrKind::NewObject,
        DalvikOpcode::NewArray | DalvikOpcode::FilledNewArray => IrKind::NewArray,

        DalvikOpcode::InvokeVirtual => IrKind::Invoke { kind: InvokeKind::Virtual },
        DalvikOpcode::InvokeSuper => IrKind::Invoke { kind: InvokeKind::Super },
        DalvikOpcode::InvokeDirect => IrKind::Invoke { kind: InvokeKind::Direct },
        DalvikOpcode::InvokeStatic => IrKind::Invoke { kind: InvokeKind::Static },
        DalvikOpcode::InvokeInterface => IrKind::Invoke { kind: InvokeKind::Interface },

        DalvikOpcode::Goto | DalvikOpcode::Goto16 | DalvikOpcode::Goto32 => {
            IrKind::Branch { cond: None }
        }
        DalvikOpcode::IfEq => IrKind::Branch { cond: Some(BranchCond::Eq) },
        DalvikOpcode::IfNe => IrKind::Branch { cond: Some(BranchCond::Ne) },
        DalvikOpcode::IfLt => IrKind::Branch { cond: Some(BranchCond::Lt) },
        DalvikOpcode::IfGe => IrKind::Branch { cond: Some(BranchCond::Ge) },
        DalvikOpcode::IfGt => IrKind::Branch { cond: Some(BranchCond::Gt) },
        DalvikOpcode::IfLe => IrKind::Branch { cond: Some(BranchCond::Le) },
        DalvikOpcode::IfEqz => IrKind::Branch { cond: Some(BranchCond::EqZ) },
        DalvikOpcode::IfNez => IrKind::Branch { cond: Some(BranchCond::NeZ) },

        DalvikOpcode::ReturnVoid
        | DalvikOpcode::Return
        | DalvikOpcode::ReturnWide
        | DalvikOpcode::ReturnObject => IrKind::Return,

        DalvikOpcode::Throw => IrKind::Throw,

        _ => IrKind::Other,
    };

    let operands = match &kind {
        IrKind::LoadConst => {
            if let Some(c) = instr.v_c {
                vec![IrValue::Const(i64::from(c))]
            } else {
                vec![]
            }
        }
        IrKind::Copy => {
            let mut ops = Vec::new();
            if let Some(b) = instr.v_b {
                ops.push(IrValue::Reg(b));
            }
            ops
        }
        IrKind::BinOp(_) => {
            let mut ops = Vec::new();
            if let Some(b) = instr.v_b {
                ops.push(IrValue::Reg(b));
            }
            ops
        }
        _ => vec![],
    };

    IrInstr {
        offset: instr.offset,
        kind,
        dest: instr.v_a,
        operands,
    }
}

// Suppress dead-code warning for `MoveObjectFrom16` which is referenced in decode_one match arm.
#[allow(dead_code)]
const _DALVIK_MOVE_OBJECT_FROM_16: DalvikOpcode = DalvikOpcode::MoveObject;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_from_byte_nop() {
        assert_eq!(DalvikOpcode::from_byte(0x00), DalvikOpcode::Nop);
    }

    #[test]
    fn test_opcode_from_byte_invoke_virtual() {
        assert_eq!(DalvikOpcode::from_byte(0x6E), DalvikOpcode::InvokeVirtual);
    }

    #[test]
    fn test_opcode_is_terminator_return() {
        assert!(DalvikOpcode::ReturnVoid.is_terminator());
    }

    #[test]
    fn test_opcode_is_terminator_goto() {
        assert!(DalvikOpcode::Goto.is_terminator());
    }

    #[test]
    fn test_opcode_not_terminator() {
        assert!(!DalvikOpcode::Move.is_terminator());
    }

    #[test]
    fn test_opcode_is_invoke() {
        assert!(DalvikOpcode::InvokeStatic.is_invoke());
        assert!(!DalvikOpcode::Move.is_invoke());
    }

    #[test]
    fn test_lift_nop_only() {
        let lifter = SmaliLifter::new();
        // code = [0x00, 0x00] = nop
        let code = [0x00u8, 0x00];
        let m = lifter.lift("Lcom/example/Foo;->bar()V", &code, 2, 1);
        assert!(!m.blocks.is_empty() || m.ir.is_empty()); // structural check
        assert_eq!(m.descriptor, "Lcom/example/Foo;->bar()V");
    }

    #[test]
    fn test_lift_return_void() {
        let lifter = SmaliLifter::new();
        // return-void = 0x0E, 0x00
        let code = [0x0Eu8, 0x00];
        let m = lifter.lift("test", &code, 1, 0);
        assert!(!m.ir.is_empty());
        assert!(m.ir.iter().any(|i| i.kind == IrKind::Return));
    }

    #[test]
    fn test_lift_const_4() {
        let lifter = SmaliLifter::new();
        // const/4 v0, #5 = 0x12 0x50
        let code = [0x12u8, 0x50];
        let m = lifter.lift("test", &code, 2, 0);
        assert!(m.ir.iter().any(|i| i.kind == IrKind::LoadConst));
    }

    #[test]
    fn test_lift_goto() {
        let lifter = SmaliLifter::new();
        // goto +0 = 0x28 0x00
        let code = [0x28u8, 0x00];
        let m = lifter.lift("test", &code, 1, 0);
        assert!(m
            .ir
            .iter()
            .any(|i| matches!(i.kind, IrKind::Branch { cond: None })));
    }

    #[test]
    fn test_lift_if_eqz() {
        let lifter = SmaliLifter::new();
        // if-eqz v0, +0 = 0x38 0x00 0x00 0x00
        let code = [0x38u8, 0x00, 0x00, 0x00];
        let m = lifter.lift("test", &code, 2, 0);
        assert!(m
            .ir
            .iter()
            .any(|i| matches!(i.kind, IrKind::Branch { cond: Some(BranchCond::EqZ) })));
    }

    #[test]
    fn test_invocations_empty() {
        let m = LiftedMethod {
            descriptor: "test".to_string(),
            blocks: HashMap::new(),
            entry: 0,
            register_count: 0,
            ins_count: 0,
            ir: vec![],
        };
        assert!(m.invocations().is_empty());
    }

    #[test]
    fn test_dalvik_block_is_exit() {
        let block = DalvikBlock {
            id: 0,
            instrs: vec![DalvikInstr {
                offset: 0,
                opcode: DalvikOpcode::ReturnVoid,
                v_a: None,
                v_b: None,
                v_c: None,
                index: None,
                branch_offset: None,
                code_units: 1,
            }],
            fall_through: None,
            branch_target: None,
        };
        assert!(block.is_exit());
    }

    #[test]
    fn test_dalvik_instr_is_return() {
        let i = DalvikInstr {
            offset: 0,
            opcode: DalvikOpcode::ReturnObject,
            v_a: None,
            v_b: None,
            v_c: None,
            index: None,
            branch_offset: None,
            code_units: 1,
        };
        assert!(i.is_return());
    }
}
