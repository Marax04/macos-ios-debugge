use anyhow::{Result, anyhow};

// ── WebAssembly opcodes ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum WasmOpcode {
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
    ReturnCall(u32),
    ReturnCallIndirect(u32, u32),
    Drop,
    Select,
    SelectTyped(Vec<ValType>),
    LocalGet(u32),
    LocalSet(u32),
    LocalTee(u32),
    GlobalGet(u32),
    GlobalSet(u32),
    TableGet(u32),
    TableSet(u32),
    I32Load(MemArg),
    I64Load(MemArg),
    F32Load(MemArg),
    F64Load(MemArg),
    I32Load8S(MemArg),
    I32Load8U(MemArg),
    I32Load16S(MemArg),
    I32Load16U(MemArg),
    I64Load8S(MemArg),
    I64Load8U(MemArg),
    I64Load16S(MemArg),
    I64Load16U(MemArg),
    I64Load32S(MemArg),
    I64Load32U(MemArg),
    I32Store(MemArg),
    I64Store(MemArg),
    F32Store(MemArg),
    F64Store(MemArg),
    I32Store8(MemArg),
    I32Store16(MemArg),
    I64Store8(MemArg),
    I64Store16(MemArg),
    I64Store32(MemArg),
    MemorySize(u32),
    MemoryGrow(u32),
    I32Const(i32),
    I64Const(i64),
    F32Const(f32),
    F64Const(f64),
    I32Eqz, I32Eq, I32Ne, I32LtS, I32LtU, I32GtS, I32GtU, I32LeS, I32LeU, I32GeS, I32GeU,
    I64Eqz, I64Eq, I64Ne, I64LtS, I64LtU, I64GtS, I64GtU, I64LeS, I64LeU, I64GeS, I64GeU,
    F32Eq, F32Ne, F32Lt, F32Gt, F32Le, F32Ge,
    F64Eq, F64Ne, F64Lt, F64Gt, F64Le, F64Ge,
    I32Clz, I32Ctz, I32Popcnt, I32Add, I32Sub, I32Mul, I32DivS, I32DivU, I32RemS, I32RemU,
    I32And, I32Or, I32Xor, I32Shl, I32ShrS, I32ShrU, I32Rotl, I32Rotr,
    I64Clz, I64Ctz, I64Popcnt, I64Add, I64Sub, I64Mul, I64DivS, I64DivU, I64RemS, I64RemU,
    I64And, I64Or, I64Xor, I64Shl, I64ShrS, I64ShrU, I64Rotl, I64Rotr,
    F32Abs, F32Neg, F32Ceil, F32Floor, F32Trunc, F32Nearest, F32Sqrt, F32Add, F32Sub, F32Mul, F32Div, F32Min, F32Max, F32Copysign,
    F64Abs, F64Neg, F64Ceil, F64Floor, F64Trunc, F64Nearest, F64Sqrt, F64Add, F64Sub, F64Mul, F64Div, F64Min, F64Max, F64Copysign,
    I32WrapI64, I32TruncF32S, I32TruncF32U, I32TruncF64S, I32TruncF64U,
    I64ExtendI32S, I64ExtendI32U, I64TruncF32S, I64TruncF32U, I64TruncF64S, I64TruncF64U,
    F32ConvertI32S, F32ConvertI32U, F32ConvertI64S, F32ConvertI64U, F32DemoteF64,
    F64ConvertI32S, F64ConvertI32U, F64ConvertI64S, F64ConvertI64U, F64PromoteF32,
    I32ReinterpretF32, I64ReinterpretF64, F32ReinterpretI32, F64ReinterpretI64,
    I32Extend8S, I32Extend16S, I64Extend8S, I64Extend16S, I64Extend32S,
    RefNull(RefType),
    RefIsNull,
    RefFunc(u32),
    MemoryCopy(u32, u32),
    MemoryFill(u32),
    TableInit(u32, u32),
    ElemDrop(u32),
    TableCopy(u32, u32),
    TableGrow(u32),
    TableSize(u32),
    TableFill(u32),
    Unknown(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockType {
    Empty,
    ValType(ValType),
    TypeIndex(i64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValType { I32, I64, F32, F64, V128, FuncRef, ExternRef }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefType { FuncRef, ExternRef }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemArg { pub align: u32, pub offset: u32 }

// ── Instruction with offset ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WasmInstr {
    pub offset: u32,
    pub opcode: WasmOpcode,
    pub size: u32,
}

impl WasmInstr {
    #[must_use] 
    pub const fn mnemonic(&self) -> &'static str {
        match &self.opcode {
            WasmOpcode::Unreachable => "unreachable",
            WasmOpcode::Nop => "nop",
            WasmOpcode::Block(_) => "block",
            WasmOpcode::Loop(_) => "loop",
            WasmOpcode::If(_) => "if",
            WasmOpcode::Else => "else",
            WasmOpcode::End => "end",
            WasmOpcode::Br(_) => "br",
            WasmOpcode::BrIf(_) => "br_if",
            WasmOpcode::BrTable(_, _) => "br_table",
            WasmOpcode::Return => "return",
            WasmOpcode::Call(_) => "call",
            WasmOpcode::CallIndirect(_, _) => "call_indirect",
            WasmOpcode::Drop => "drop",
            WasmOpcode::Select => "select",
            WasmOpcode::LocalGet(_) => "local.get",
            WasmOpcode::LocalSet(_) => "local.set",
            WasmOpcode::LocalTee(_) => "local.tee",
            WasmOpcode::GlobalGet(_) => "global.get",
            WasmOpcode::GlobalSet(_) => "global.set",
            WasmOpcode::I32Const(_) => "i32.const",
            WasmOpcode::I64Const(_) => "i64.const",
            WasmOpcode::F32Const(_) => "f32.const",
            WasmOpcode::F64Const(_) => "f64.const",
            WasmOpcode::I32Add => "i32.add",
            WasmOpcode::I32Sub => "i32.sub",
            WasmOpcode::I32Mul => "i32.mul",
            WasmOpcode::I32DivS => "i32.div_s",
            WasmOpcode::I32DivU => "i32.div_u",
            WasmOpcode::I32And => "i32.and",
            WasmOpcode::I32Or => "i32.or",
            WasmOpcode::I32Xor => "i32.xor",
            WasmOpcode::I32Shl => "i32.shl",
            WasmOpcode::I32ShrS => "i32.shr_s",
            WasmOpcode::I32ShrU => "i32.shr_u",
            WasmOpcode::I32Eq => "i32.eq",
            WasmOpcode::I32Ne => "i32.ne",
            WasmOpcode::I32LtS => "i32.lt_s",
            WasmOpcode::I32Eqz => "i32.eqz",
            WasmOpcode::I64Add => "i64.add",
            WasmOpcode::I64Mul => "i64.mul",
            WasmOpcode::MemorySize(_) => "memory.size",
            WasmOpcode::MemoryGrow(_) => "memory.grow",
            WasmOpcode::I32Load(_) => "i32.load",
            WasmOpcode::I64Load(_) => "i64.load",
            WasmOpcode::I32Store(_) => "i32.store",
            WasmOpcode::I64Store(_) => "i64.store",
            WasmOpcode::I32Load8U(_) => "i32.load8_u",
            WasmOpcode::I32Load8S(_) => "i32.load8_s",
            WasmOpcode::I32Load16U(_) => "i32.load16_u",
            WasmOpcode::I32Load16S(_) => "i32.load16_s",
            WasmOpcode::I32Store8(_) => "i32.store8",
            WasmOpcode::I32Store16(_) => "i32.store16",
            WasmOpcode::RefIsNull => "ref.is_null",
            WasmOpcode::RefNull(_) => "ref.null",
            WasmOpcode::RefFunc(_) => "ref.func",
            _ => "???",
        }
    }
}

// ── Disassembler ──────────────────────────────────────────────────────────────

pub struct WasmDisassembler<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> WasmDisassembler<'a> {
    #[must_use] 
    pub const fn new(data: &'a [u8]) -> Self { Self { data, pos: 0 } }

    #[must_use] 
    pub const fn at(data: &'a [u8], offset: usize) -> Self { Self { data, pos: offset } }

    fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() { return Err(anyhow!("eof")); }
        let b = self.data[self.pos]; self.pos += 1; Ok(b)
    }

    fn read_leb_u32(&mut self) -> Result<u32> {
        let mut result = 0u32; let mut shift = 0u32;
        loop {
            let b = self.read_u8()?;
            // Use wrapping_shl to avoid a panic in debug builds when the
            // low 7 bits of a continuation byte shift into or past bit 31.
            result |= u32::from(b & 0x7f).wrapping_shl(shift);
            if b & 0x80 == 0 { break; }
            shift += 7;
            if shift >= 35 { return Err(anyhow!("leb overflow")); }
        }
        Ok(result)
    }

    fn read_leb_i32(&mut self) -> Result<i32> {
        let mut result = 0i32; let mut shift = 0u32;
        loop {
            if shift >= 35 { return Err(anyhow!("leb overflow")); }
            let b = self.read_u8()?;
            // Use wrapping_shl to avoid signed left-shift overflow UB when the
            // shifted bits include the sign bit (e.g. shift == 28, b & 0x7f == 0x7F).
            result |= i32::from(b & 0x7f).wrapping_shl(shift);
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 32 && (b & 0x40) != 0 { result |= (!0i32).wrapping_shl(shift); }
                break;
            }
        }
        Ok(result)
    }

    fn read_leb_i64(&mut self) -> Result<i64> {
        let mut result = 0i64; let mut shift = 0u32;
        loop {
            if shift >= 70 { return Err(anyhow!("leb overflow")); }
            let b = self.read_u8()?;
            // Use wrapping_shl to avoid signed left-shift overflow UB when
            // shift approaches 63 (e.g. shift == 63, b & 0x7f != 0).
            result |= i64::from(b & 0x7f).wrapping_shl(shift);
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && (b & 0x40) != 0 { result |= (!0i64).wrapping_shl(shift); }
                break;
            }
        }
        Ok(result)
    }

    fn read_f32(&mut self) -> Result<f32> {
        if self.pos + 4 > self.data.len() { return Err(anyhow!("eof")); }
        let bytes: [u8; 4] = self.data[self.pos..self.pos+4].try_into().unwrap();
        self.pos += 4;
        Ok(f32::from_le_bytes(bytes))
    }

    fn read_f64(&mut self) -> Result<f64> {
        if self.pos + 8 > self.data.len() { return Err(anyhow!("eof")); }
        let bytes: [u8; 8] = self.data[self.pos..self.pos+8].try_into().unwrap();
        self.pos += 8;
        Ok(f64::from_le_bytes(bytes))
    }

    fn read_block_type(&mut self) -> Result<BlockType> {
        let b = self.read_u8()?;
        Ok(match b {
            0x40 => BlockType::Empty,
            0x7f => BlockType::ValType(ValType::I32),
            0x7e => BlockType::ValType(ValType::I64),
            0x7d => BlockType::ValType(ValType::F32),
            0x7c => BlockType::ValType(ValType::F64),
            _ => {
                self.pos -= 1;
                BlockType::TypeIndex(i64::from(self.read_leb_i32()?))
            }
        })
    }

    fn read_memarg(&mut self) -> Result<MemArg> {
        let align = self.read_leb_u32()?;
        let offset = self.read_leb_u32()?;
        Ok(MemArg { align, offset })
    }

    pub fn decode_one(&mut self) -> Result<WasmOpcode> {
        let b = self.read_u8()?;
        Ok(match b {
            0x00 => WasmOpcode::Unreachable,
            0x01 => WasmOpcode::Nop,
            0x02 => WasmOpcode::Block(self.read_block_type()?),
            0x03 => WasmOpcode::Loop(self.read_block_type()?),
            0x04 => WasmOpcode::If(self.read_block_type()?),
            0x05 => WasmOpcode::Else,
            0x0b => WasmOpcode::End,
            0x0c => WasmOpcode::Br(self.read_leb_u32()?),
            0x0d => WasmOpcode::BrIf(self.read_leb_u32()?),
            0x0e => {
                let n = self.read_leb_u32()?;
                let labels: Result<Vec<u32>> = (0..n).map(|_| self.read_leb_u32()).collect();
                let default = self.read_leb_u32()?;
                WasmOpcode::BrTable(labels?, default)
            }
            0x0f => WasmOpcode::Return,
            0x10 => WasmOpcode::Call(self.read_leb_u32()?),
            0x11 => { let t = self.read_leb_u32()?; let m = self.read_leb_u32()?; WasmOpcode::CallIndirect(t, m) }
            0x1a => WasmOpcode::Drop,
            0x1b => WasmOpcode::Select,
            0x20 => WasmOpcode::LocalGet(self.read_leb_u32()?),
            0x21 => WasmOpcode::LocalSet(self.read_leb_u32()?),
            0x22 => WasmOpcode::LocalTee(self.read_leb_u32()?),
            0x23 => WasmOpcode::GlobalGet(self.read_leb_u32()?),
            0x24 => WasmOpcode::GlobalSet(self.read_leb_u32()?),
            0x25 => WasmOpcode::TableGet(self.read_leb_u32()?),
            0x26 => WasmOpcode::TableSet(self.read_leb_u32()?),
            0x28 => WasmOpcode::I32Load(self.read_memarg()?),
            0x29 => WasmOpcode::I64Load(self.read_memarg()?),
            0x2a => WasmOpcode::F32Load(self.read_memarg()?),
            0x2b => WasmOpcode::F64Load(self.read_memarg()?),
            0x2c => WasmOpcode::I32Load8S(self.read_memarg()?),
            0x2d => WasmOpcode::I32Load8U(self.read_memarg()?),
            0x2e => WasmOpcode::I32Load16S(self.read_memarg()?),
            0x2f => WasmOpcode::I32Load16U(self.read_memarg()?),
            0x30 => WasmOpcode::I64Load8S(self.read_memarg()?),
            0x31 => WasmOpcode::I64Load8U(self.read_memarg()?),
            0x32 => WasmOpcode::I64Load16S(self.read_memarg()?),
            0x33 => WasmOpcode::I64Load16U(self.read_memarg()?),
            0x34 => WasmOpcode::I64Load32S(self.read_memarg()?),
            0x35 => WasmOpcode::I64Load32U(self.read_memarg()?),
            0x36 => WasmOpcode::I32Store(self.read_memarg()?),
            0x37 => WasmOpcode::I64Store(self.read_memarg()?),
            0x38 => WasmOpcode::F32Store(self.read_memarg()?),
            0x39 => WasmOpcode::F64Store(self.read_memarg()?),
            0x3a => WasmOpcode::I32Store8(self.read_memarg()?),
            0x3b => WasmOpcode::I32Store16(self.read_memarg()?),
            0x3c => WasmOpcode::I64Store8(self.read_memarg()?),
            0x3d => WasmOpcode::I64Store16(self.read_memarg()?),
            0x3e => WasmOpcode::I64Store32(self.read_memarg()?),
            0x3f => WasmOpcode::MemorySize(self.read_leb_u32()?),
            0x40 => WasmOpcode::MemoryGrow(self.read_leb_u32()?),
            0x41 => WasmOpcode::I32Const(self.read_leb_i32()?),
            0x42 => WasmOpcode::I64Const(self.read_leb_i64()?),
            0x43 => WasmOpcode::F32Const(self.read_f32()?),
            0x44 => WasmOpcode::F64Const(self.read_f64()?),
            0x45 => WasmOpcode::I32Eqz,
            0x46 => WasmOpcode::I32Eq,
            0x47 => WasmOpcode::I32Ne,
            0x48 => WasmOpcode::I32LtS,
            0x49 => WasmOpcode::I32LtU,
            0x4a => WasmOpcode::I32GtS,
            0x4b => WasmOpcode::I32GtU,
            0x4c => WasmOpcode::I32LeS,
            0x4d => WasmOpcode::I32LeU,
            0x4e => WasmOpcode::I32GeS,
            0x4f => WasmOpcode::I32GeU,
            0x50 => WasmOpcode::I64Eqz,
            0x51 => WasmOpcode::I64Eq,
            0x52 => WasmOpcode::I64Ne,
            0x6a => WasmOpcode::I32Add,
            0x6b => WasmOpcode::I32Sub,
            0x6c => WasmOpcode::I32Mul,
            0x6d => WasmOpcode::I32DivS,
            0x6e => WasmOpcode::I32DivU,
            0x6f => WasmOpcode::I32RemS,
            0x70 => WasmOpcode::I32RemU,
            0x71 => WasmOpcode::I32And,
            0x72 => WasmOpcode::I32Or,
            0x73 => WasmOpcode::I32Xor,
            0x74 => WasmOpcode::I32Shl,
            0x75 => WasmOpcode::I32ShrS,
            0x76 => WasmOpcode::I32ShrU,
            0x77 => WasmOpcode::I32Rotl,
            0x78 => WasmOpcode::I32Rotr,
            0x7c => WasmOpcode::I64Add,
            0x7d => WasmOpcode::I64Sub,
            0x7e => WasmOpcode::I64Mul,
            0x7f => WasmOpcode::I64DivS,
            0xa7 => WasmOpcode::I32WrapI64,
            0xac => WasmOpcode::I64ExtendI32S,
            0xad => WasmOpcode::I64ExtendI32U,
            0xd0 => { let rt = self.read_u8()?; WasmOpcode::RefNull(if rt == 0x70 { RefType::FuncRef } else { RefType::ExternRef }) }
            0xd1 => WasmOpcode::RefIsNull,
            0xd2 => WasmOpcode::RefFunc(self.read_leb_u32()?),
            _ => WasmOpcode::Unknown(b),
        })
    }

    pub fn disassemble_function(&mut self, end_offset: usize) -> Result<Vec<WasmInstr>> {
        let mut instrs = Vec::new();
        while self.pos < end_offset {
            let start = self.pos;
            let opcode = self.decode_one()?;
            let size = (self.pos - start) as u32;
            instrs.push(WasmInstr { offset: start as u32, opcode, size });
        }
        Ok(instrs)
    }

    #[must_use] 
    pub fn print_function(instrs: &[WasmInstr], func_idx: u32, indent_size: usize) -> String {
        let mut out = format!("func[{func_idx}]:\n");
        let mut depth = 0usize;
        for instr in instrs {
            let indent = " ".repeat(indent_size * depth);
            match &instr.opcode {
                WasmOpcode::End | WasmOpcode::Else => {
                    depth = depth.saturating_sub(1);
                    let i = " ".repeat(indent_size * depth);
                    out.push_str(&format!("  {:08x}  {}{}\n", instr.offset, i, instr.mnemonic()));
                }
                WasmOpcode::Block(_) | WasmOpcode::Loop(_) | WasmOpcode::If(_) => {
                    out.push_str(&format!("  {:08x}  {}{}\n", instr.offset, indent, instr.mnemonic()));
                    depth += 1;
                }
                WasmOpcode::I32Const(v) => out.push_str(&format!("  {:08x}  {}i32.const {}\n", instr.offset, indent, v)),
                WasmOpcode::I64Const(v) => out.push_str(&format!("  {:08x}  {}i64.const {}\n", instr.offset, indent, v)),
                WasmOpcode::LocalGet(i) => out.push_str(&format!("  {:08x}  {}local.get {}\n", instr.offset, indent, i)),
                WasmOpcode::LocalSet(i) => out.push_str(&format!("  {:08x}  {}local.set {}\n", instr.offset, indent, i)),
                WasmOpcode::Call(i) => out.push_str(&format!("  {:08x}  {}call func[{}]\n", instr.offset, indent, i)),
                WasmOpcode::Br(d) => out.push_str(&format!("  {:08x}  {}br depth={}\n", instr.offset, indent, d)),
                WasmOpcode::BrIf(d) => out.push_str(&format!("  {:08x}  {}br_if depth={}\n", instr.offset, indent, d)),
                _ => out.push_str(&format!("  {:08x}  {}{}\n", instr.offset, indent, instr.mnemonic())),
            }
        }
        out
    }
}

// ── Control flow analysis ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WasmBasicBlock {
    pub id: usize,
    pub start_offset: u32,
    pub end_offset: u32,
    pub instrs: Vec<WasmInstr>,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
    pub block_type: WasmBlockType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasmBlockType { Entry, Normal, Loop, If, Else, Block, Exit }

pub struct WasmCfgBuilder;

impl WasmCfgBuilder {
    #[must_use] 
    pub fn build(instrs: &[WasmInstr]) -> Vec<WasmBasicBlock> {
        let mut blocks: Vec<WasmBasicBlock> = Vec::new();
        let mut current_instrs: Vec<WasmInstr> = Vec::new();
        let mut current_start = instrs.first().map_or(0, |i| i.offset);
        let mut block_id = 0usize;
        for instr in instrs {
            let is_terminator = matches!(&instr.opcode,
                WasmOpcode::Br(_) | WasmOpcode::BrIf(_) | WasmOpcode::BrTable(_, _) |
                WasmOpcode::Return | WasmOpcode::Unreachable | WasmOpcode::End
            );
            let is_leader = matches!(&instr.opcode, WasmOpcode::Block(_) | WasmOpcode::Loop(_) | WasmOpcode::If(_) | WasmOpcode::Else);
            if is_leader && !current_instrs.is_empty() {
                let end = current_instrs.last().map_or(current_start, |i| i.offset + i.size);
                blocks.push(WasmBasicBlock { id: block_id, start_offset: current_start, end_offset: end, instrs: current_instrs.clone(), successors: vec![], predecessors: vec![], block_type: WasmBlockType::Normal });
                block_id += 1;
                current_instrs.clear();
                current_start = instr.offset;
            }
            current_instrs.push(instr.clone());
            if is_terminator && !current_instrs.is_empty() {
                let end = current_instrs.last().map_or(current_start, |i| i.offset + i.size);
                let btype = match &instr.opcode {
                    WasmOpcode::Return | WasmOpcode::Unreachable => WasmBlockType::Exit,
                    _ => WasmBlockType::Normal,
                };
                blocks.push(WasmBasicBlock { id: block_id, start_offset: current_start, end_offset: end, instrs: current_instrs.clone(), successors: vec![], predecessors: vec![], block_type: btype });
                block_id += 1;
                current_instrs.clear();
                if let Some(next) = instrs.iter().find(|i| i.offset > instr.offset) {
                    current_start = next.offset;
                }
            }
        }
        if !current_instrs.is_empty() {
            let end = current_instrs.last().map_or(current_start, |i| i.offset + i.size);
            blocks.push(WasmBasicBlock { id: block_id, start_offset: current_start, end_offset: end, instrs: current_instrs, successors: vec![], predecessors: vec![], block_type: WasmBlockType::Normal });
        }
        blocks
    }
}

// ── Stack type checker ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct TypeStack {
    pub stack: Vec<ValType>,
}

impl TypeStack {
    pub fn push(&mut self, t: ValType) { self.stack.push(t); }
    pub fn pop(&mut self) -> Option<ValType> { self.stack.pop() }
    #[must_use] 
    pub fn peek(&self) -> Option<&ValType> { self.stack.last() }
    #[must_use] 
    pub const fn depth(&self) -> usize { self.stack.len() }

    pub fn check_instr(&mut self, instr: &WasmOpcode) -> Result<()> {
        match instr {
            WasmOpcode::I32Const(_) => { self.push(ValType::I32); }
            WasmOpcode::I64Const(_) => { self.push(ValType::I64); }
            WasmOpcode::F32Const(_) => { self.push(ValType::F32); }
            WasmOpcode::F64Const(_) => { self.push(ValType::F64); }
            WasmOpcode::I32Add | WasmOpcode::I32Sub | WasmOpcode::I32Mul |
            WasmOpcode::I32And | WasmOpcode::I32Or | WasmOpcode::I32Xor => {
                self.pop(); self.pop(); self.push(ValType::I32);
            }
            WasmOpcode::I32Eqz => { self.pop(); self.push(ValType::I32); }
            WasmOpcode::I32Eq | WasmOpcode::I32Ne | WasmOpcode::I32LtS => {
                self.pop(); self.pop(); self.push(ValType::I32);
            }
            WasmOpcode::Drop => { self.pop(); }
            WasmOpcode::LocalGet(_) => { self.push(ValType::I32); }
            WasmOpcode::LocalSet(_) => { self.pop(); }
            _ => {}
        }
        Ok(())
    }
}
