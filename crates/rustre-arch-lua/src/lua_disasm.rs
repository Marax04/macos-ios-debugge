use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use anyhow::{Result, bail};
use std::fmt::Write;

// ── Lua bytecode disassembler (LuaJIT 2.1 + Lua 5.4) ─────────────────────────

/// Version selector for the disassembler.
///
/// This is a local enum rather than an alias for [`crate::LuaVersion`] because
/// this module additionally handles the **`LuaJIT` 2.1** bytecode format, which
/// uses a completely different instruction layout (little-endian ABC with a
/// separate opcode space) that the rest of the crate does not support.
/// Re-using `crate::LuaVersion` would require extending it with a JIT variant
/// that is meaningless to the standard Lua decoder path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LuaVersion { Lua51, Lua52, Lua53, Lua54, LuaJit21 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaInstruction {
    pub offset: usize,
    pub raw: u32,
    pub opcode: u8,
    pub mnemonic: String,
    pub operands: String,
    pub a: u8,
    pub b: u16,
    pub c: u16,
    pub bx: u32,
    pub sbx: i32,
    pub ax: u32,
    pub format: InsnFormat,
    pub category: InsnCategory,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InsnFormat { ABC, ABx, AsBx, Ax }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InsnCategory {
    Move, LoadK, LoadBool, LoadNil,
    GetUpval, SetUpval, GetTabUp, SetTabUp,
    GetTable, SetTable, GetField, SetField, GetI, SetI,
    NewTable, Self_, Add, Sub, Mul, Div, Mod, Pow, Idiv,
    Band, Bor, Bxor, Shl, Shr, Unm, Bnot, Not, Len,
    Concat, Jump, Test, TestSet, Call, TailCall, Return,
    ForLoop, ForPrep, TForCall, TForLoop, SetList, Closure,
    Vararg, Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaProto {
    pub name: String,
    pub first_line: i32,
    pub last_line: i32,
    pub num_upvalues: u8,
    pub num_params: u8,
    pub is_vararg: u8,
    pub max_stack: u8,
    pub instructions: Vec<LuaInstruction>,
    pub constants: Vec<LuaConstant>,
    pub upvalues: Vec<LuaUpvalue>,
    pub protos: Vec<Self>,
    pub locals: Vec<LuaLocal>,
    pub line_info: Vec<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LuaConstant {
    Nil,
    Boolean(bool),
    Integer(i64),
    Float(f64),
    String(String),
}

impl LuaConstant {
    #[must_use] 
    pub fn to_display(&self) -> String {
        match self {
            Self::Nil => "nil".to_string(),
            Self::Boolean(b) => b.to_string(),
            Self::Integer(n) => n.to_string(),
            Self::Float(f) => format!("{f:.6}"),
            Self::String(s) => format!("{s:?}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaUpvalue {
    pub name: String,
    pub instack: bool,
    pub idx: u8,
    pub kind: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaLocal {
    pub name: String,
    pub start_pc: u32,
    pub end_pc: u32,
}

pub struct Lua54Disassembler {
    data: Vec<u8>,
    pos: usize,
    string_cache: HashMap<usize, String>,
    /// Current proto nesting depth; prevents stack overflow on malicious input.
    proto_depth: usize,
}

/// Maximum nesting depth for nested Lua function prototypes.
/// Lua itself typically limits nesting to ~200; 256 is a generous safe ceiling.
const MAX_PROTO_DEPTH: usize = 256;

impl Lua54Disassembler {
    #[must_use] 
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0, string_cache: HashMap::new(), proto_depth: 0 }
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() { bail!("EOF reading byte"); }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_u32(&mut self) -> Result<u32> {
        if self.pos + 4 > self.data.len() { bail!("EOF reading u32"); }
        let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn read_u64(&mut self) -> Result<u64> {
        if self.pos + 8 > self.data.len() { bail!("EOF reading u64"); }
        let v = u64::from_le_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    fn read_i64(&mut self) -> Result<i64> {
        Ok(self.read_u64()?.cast_signed())
    }

    fn read_f64(&mut self) -> Result<f64> {
        let bits = self.read_u64()?;
        Ok(f64::from_bits(bits))
    }

    fn read_varint(&mut self) -> Result<usize> {
        let mut result = 0usize;
        let mut shift = 0u32;
        // Lua 5.4 varints are at most 9 bytes (64 bits / 7 bits per byte = 10,
        // but usize is at most 64 bits so 10 iterations is the ceiling).
        // Cap at usize::BITS / 7 + 1 to prevent unbounded loops on malformed
        // input and avoid undefined shift-count overflow.
        let max_iters = (usize::BITS / 7 + 2) as usize;
        for _ in 0..max_iters {
            let byte = self.read_byte()?;
            if shift < usize::BITS {
                result |= ((byte & 0x7F) as usize) << shift;
            }
            shift += 7;
            if byte & 0x80 != 0 { return Ok(result); }
        }
        bail!("varint too long (malformed input)")
    }

    fn read_string54(&mut self) -> Result<Option<String>> {
        let size = self.read_varint()?;
        if size == 0 { return Ok(None); }
        // size includes the length byte itself, so the body is (size - 1) bytes.
        // Use checked arithmetic to avoid overflow on a maliciously large size.
        let body_len = size - 1;
        let end = self.pos.checked_add(body_len).ok_or_else(|| anyhow::anyhow!("string size overflow"))?;
        if end > self.data.len() { bail!("EOF reading string"); }
        let start = self.pos;
        // Reuse a previously decoded string starting at the same offset to
        // avoid re-allocating identical UTF-8 buffers when callers re-parse
        // overlapping regions.
        if let Some(cached) = self.string_cache.get(&start) {
            self.pos = end;
            return Ok(Some(cached.clone()));
        }
        let bytes = self.data[start..end].to_vec();
        self.pos = end;
        let decoded = String::from_utf8_lossy(&bytes).to_string();
        self.string_cache.insert(start, decoded.clone());
        Ok(Some(decoded))
    }

    /// Number of distinct strings memoized by the string cache.
    ///
    /// Useful for tests and debugging — confirms that repeated `read_string54`
    /// calls at the same offset hit the cache.
    #[must_use]
    pub fn cached_string_count(&self) -> usize {
        self.string_cache.len()
    }

    #[must_use] 
    pub fn check_magic(&self) -> bool {
        self.data.starts_with(b"\x1bLua")
    }

    /// # Errors
    ///
    /// Returns an error when the input bytes are malformed, truncated, or
    /// otherwise cannot be decoded.
    pub fn parse_header54(&mut self) -> Result<()> {
        if !self.check_magic() { bail!("Not a Lua bytecode file"); }
        self.pos = 4; // skip magic
        let version = self.read_byte()?;
        if version != 0x54 { bail!("Not Lua 5.4 bytecode (version={version:#02x})"); }
        let _format = self.read_byte()?;
        // LUAC_DATA: "\x19\x93\r\n\x1a\n" — read byte-by-byte for bounds safety
        for _ in 0..6 { self.read_byte()?; }
        let _int_size = self.read_byte()?;
        let _sizet_size = self.read_byte()?;
        let _insn_size = self.read_byte()?;
        let _int_size2 = self.read_byte()?;
        let _number_size = self.read_byte()?;
        // LUAC_INT and LUAC_NUM — read byte-by-byte for bounds safety
        for _ in 0..16 { self.read_byte()?; }
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error when the input bytes are malformed, truncated, or
    /// otherwise cannot be decoded.
    pub fn parse_proto54(&mut self) -> Result<LuaProto> {
        if self.proto_depth >= MAX_PROTO_DEPTH {
            bail!("proto nesting too deep (max {MAX_PROTO_DEPTH})");
        }
        self.proto_depth += 1;
        let name = self.read_string54()?.unwrap_or_default();
        let first_line = i32::try_from(self.read_varint()?).unwrap_or(i32::MAX);
        let last_line = i32::try_from(self.read_varint()?).unwrap_or(i32::MAX);
        let num_params = self.read_byte()?;
        let is_vararg = self.read_byte()?;
        let max_stack = self.read_byte()?;

        // Instructions — cap the capacity hint to avoid OOM on malformed input;
        // each instruction is 4 bytes so the true max is data.len() / 4.
        let num_insns = self.read_varint()?;
        let insns_cap = num_insns.min(self.data.len() / 4);
        let mut instructions = Vec::with_capacity(insns_cap);
        for i in 0..num_insns {
            let raw = self.read_u32()?;
            // i * 4 can overflow if i is enormous; use saturating multiply.
            let insn = decode_lua54_instruction(raw, i.saturating_mul(4));
            instructions.push(insn);
        }

        // Constants
        let num_consts = self.read_varint()?;
        let consts_cap = num_consts.min(self.data.len());
        let mut constants = Vec::with_capacity(consts_cap);
        for _ in 0..num_consts {
            let tag = self.read_byte()?;
            let c = match tag {
                1 | 17 => LuaConstant::Boolean(self.read_byte()? != 0),
                3 => LuaConstant::Float(self.read_f64()?),
                19 => LuaConstant::Integer(self.read_i64()?),
                4 | 20 => {
                    let s = self.read_string54()?.unwrap_or_default();
                    LuaConstant::String(s)
                }
                _ => LuaConstant::Nil,
            };
            constants.push(c);
        }

        // Upvalues
        let num_upvals = self.read_varint()?;
        // Same cap as instructions/constants above: each upvalue record is
        // 3 bytes (instack, idx, kind), so the remaining input bounds the count.
        let mut upvalues =
            Vec::with_capacity(num_upvals.min(self.data.len().saturating_sub(self.pos) / 3));
        for _ in 0..num_upvals {
            let instack = self.read_byte()? != 0;
            let idx = self.read_byte()?;
            let kind = self.read_byte()?;
            upvalues.push(LuaUpvalue { name: String::new(), instack, idx, kind });
        }

        // Protos
        let num_protos = self.read_varint()?;
        // Each nested proto needs at least one byte; bound by what is left.
        let mut protos =
            Vec::with_capacity(num_protos.min(self.data.len().saturating_sub(self.pos)));
        for _ in 0..num_protos {
            protos.push(self.parse_proto54()?);
        }

        // Debug info: line table and local-variable records.
        let (line_info, locals) = self.parse_proto54_debug()?;

        // Update upvalue names
        let upval_names_count = self.read_varint()?;
        for i in 0..upval_names_count.min(upvalues.len()) {
            if let Some(name) = self.read_string54()? {
                upvalues[i].name = name;
            }
        }

        self.proto_depth -= 1;
        Ok(LuaProto {
            name,
            first_line,
            last_line,
            num_upvalues: u8::try_from(num_upvals.min(usize::from(u8::MAX))).unwrap_or(u8::MAX),
            num_params,
            is_vararg,
            max_stack,
            instructions,
            constants,
            upvalues,
            protos,
            locals,
            line_info,
        })
    }

    /// Parse the Lua 5.4 debug section: the line table and the local-variable
    /// records that follow the nested prototypes.
    ///
    /// # Errors
    ///
    /// Returns an error when the input bytes are malformed or truncated.
    fn parse_proto54_debug(&mut self) -> Result<(Vec<i32>, Vec<LuaLocal>)> {
        // Debug info
        let num_lines = self.read_varint()?;
        // Line entries are 1, 2 or 4 bytes; use the 1-byte minimum as the bound.
        let mut line_info =
            Vec::with_capacity(num_lines.min(self.data.len().saturating_sub(self.pos)));
        if num_lines > 0 {
            let lines_size = self.read_byte()?;
            for _ in 0..num_lines {
                let line = match lines_size {
                    1 => i32::from(self.read_byte()?),
                    2 => {
                        let lo = u16::from(self.read_byte()?);
                        let hi = u16::from(self.read_byte()?);
                        i32::from((hi << 8) | lo)
                    }
                    4 => self.read_u32()?.cast_signed(),
                    _ => 0,
                };
                line_info.push(line);
            }
        }

        let num_locals = self.read_varint()?;
        // Each local is a string plus two varints — at least 3 bytes.
        let mut locals =
            Vec::with_capacity(num_locals.min(self.data.len().saturating_sub(self.pos) / 3));
        for _ in 0..num_locals {
            let name = self.read_string54()?.unwrap_or_default();
            let start_pc = u32::try_from(self.read_varint()?).unwrap_or(u32::MAX);
            let end_pc = u32::try_from(self.read_varint()?).unwrap_or(u32::MAX);
            locals.push(LuaLocal { name, start_pc, end_pc });
        }
        Ok((line_info, locals))
    }
}

fn decode_lua54_instruction(raw: u32, offset: usize) -> LuaInstruction {
    // Lua 5.4 instruction format:
    // bits 0-6: opcode (7 bits)
    // bits 7-14: A (8 bits)
    // bits 15-22: B (8 bits) or Bx high part
    // bits 23-31: C (9 bits) or Bx low part
    let opcode = (raw & 0x7F) as u8;
    let a = ((raw >> 7) & 0xFF) as u8;
    let b = ((raw >> 16) & 0x1FF) as u16;
    let c = ((raw >> 25) & 0x7F) as u16;  // simplified
    let bx = (raw >> 15) & 0x1FFFF;
    let sbx = bx.cast_signed() - ((1 << 16) - 1);
    let ax = raw >> 7 ;

    let (mnemonic, format, category, operands) = decode_lua54_opcode(opcode, a, b, c, bx, sbx, ax);

    LuaInstruction {
        offset,
        raw,
        opcode,
        mnemonic: mnemonic.to_string(),
        operands,
        a,
        b,
        c,
        bx,
        sbx,
        ax,
        format,
        category,
        comment: None,
    }
}

fn decode_lua54_opcode(
    opcode: u8, a: u8, b: u16, c: u16, bx: u32, sbx: i32, ax: u32,
) -> (&'static str, InsnFormat, InsnCategory, String) {
    match opcode {
        0x00 => ("MOVE", InsnFormat::ABC, InsnCategory::Move, format!("R{a} := R{b}")),
        0x01 => ("LOADI", InsnFormat::AsBx, InsnCategory::LoadK, format!("R{a} := {sbx}")),
        0x02 => ("LOADF", InsnFormat::AsBx, InsnCategory::LoadK, format!("R{} := {:.1}", a, f64::from(sbx))),
        0x03 => ("LOADK", InsnFormat::ABx, InsnCategory::LoadK, format!("R{a} := K[{bx}]")),
        0x04 => ("LOADKX", InsnFormat::ABx, InsnCategory::LoadK, format!("R{a} := K[extra]")),
        0x05 => ("LOADFALSE", InsnFormat::ABC, InsnCategory::LoadBool, format!("R{a} := false")),
        0x06 => ("LFALSESKIP", InsnFormat::ABC, InsnCategory::LoadBool, format!("R{a} := false; skip")),
        0x07 => ("LOADTRUE", InsnFormat::ABC, InsnCategory::LoadBool, format!("R{a} := true")),
        0x08 => ("LOADNIL", InsnFormat::ABC, InsnCategory::LoadNil, format!("R[{}..{}] := nil", a, u16::from(a) + b)),
        0x09 => ("GETUPVAL", InsnFormat::ABC, InsnCategory::GetUpval, format!("R{a} := U[{b}]")),
        0x0A => ("SETUPVAL", InsnFormat::ABC, InsnCategory::SetUpval, format!("U[{b}] := R{a}")),
        0x0B => ("GETTABUP", InsnFormat::ABC, InsnCategory::GetTabUp, format!("R{a} := U[{b}][K[{c}]]")),
        0x0C => ("GETTABLE", InsnFormat::ABC, InsnCategory::GetTable, format!("R{a} := R{b}[R{c}]")),
        0x0D => ("GETI", InsnFormat::ABC, InsnCategory::GetI, format!("R{a} := R{b}[{c}]")),
        0x0E => ("GETFIELD", InsnFormat::ABC, InsnCategory::GetField, format!("R{a} := R{b}[K[{c}]]")),
        0x0F => ("SETTABUP", InsnFormat::ABC, InsnCategory::SetTabUp, format!("U[{a}][K[{b}]] := RK[{c}]")),
        0x10 => ("SETTABLE", InsnFormat::ABC, InsnCategory::SetTable, format!("R{a}[R{b}] := RK[{c}]")),
        0x11 => ("SETI", InsnFormat::ABC, InsnCategory::SetI, format!("R{a}[{b}] := RK[{c}]")),
        0x12 => ("SETFIELD", InsnFormat::ABC, InsnCategory::SetField, format!("R{a}[K[{b}]] := RK[{c}]")),
        0x13 => ("NEWTABLE", InsnFormat::ABC, InsnCategory::NewTable, format!("R{a} := {{}} (b={b},c={c})")),
        0x14 => ("SELF", InsnFormat::ABC, InsnCategory::Self_, format!("R{}:=R{}; R{}:=R{}[RK[{}]]", a+1, b, a, b, c)),
        0x15 => ("ADDI", InsnFormat::ABC, InsnCategory::Add, format!("R{} := R{} + {}", a, b, c.cast_signed())),
        0x16 => ("ADDK", InsnFormat::ABC, InsnCategory::Add, format!("R{a} := R{b} + K[{c}]")),
        0x17 => ("SUBK", InsnFormat::ABC, InsnCategory::Sub, format!("R{a} := R{b} - K[{c}]")),
        0x18 => ("MULK", InsnFormat::ABC, InsnCategory::Mul, format!("R{a} := R{b} * K[{c}]")),
        0x19 => ("MODK", InsnFormat::ABC, InsnCategory::Mod, format!("R{a} := R{b} %% K[{c}]")),
        0x1A => ("POWK", InsnFormat::ABC, InsnCategory::Pow, format!("R{a} := R{b} ^ K[{c}]")),
        0x1B => ("DIVK", InsnFormat::ABC, InsnCategory::Div, format!("R{a} := R{b} / K[{c}]")),
        0x1C => ("IDIVK", InsnFormat::ABC, InsnCategory::Idiv, format!("R{a} := R{b} // K[{c}]")),
        0x1D => ("BANDK", InsnFormat::ABC, InsnCategory::Band, format!("R{a} := R{b} & K[{c}]")),
        0x1E => ("BORK", InsnFormat::ABC, InsnCategory::Bor, format!("R{a} := R{b} | K[{c}]")),
        0x1F => ("BXORK", InsnFormat::ABC, InsnCategory::Bxor, format!("R{a} := R{b} ~ K[{c}]")),
        0x20 => ("SHRI", InsnFormat::ABC, InsnCategory::Shr, format!("R{} := R{} >> {}", a, b, c.cast_signed())),
        0x21 => ("SHLI", InsnFormat::ABC, InsnCategory::Shl, format!("R{a} := K[{c}] << R{b}")),
        0x22 => ("ADD", InsnFormat::ABC, InsnCategory::Add, format!("R{a} := R{b} + R{c}")),
        0x23 => ("SUB", InsnFormat::ABC, InsnCategory::Sub, format!("R{a} := R{b} - R{c}")),
        0x24 => ("MUL", InsnFormat::ABC, InsnCategory::Mul, format!("R{a} := R{b} * R{c}")),
        0x25 => ("MOD", InsnFormat::ABC, InsnCategory::Mod, format!("R{a} := R{b} %% R{c}")),
        0x26 => ("POW", InsnFormat::ABC, InsnCategory::Pow, format!("R{a} := R{b} ^ R{c}")),
        0x27 => ("DIV", InsnFormat::ABC, InsnCategory::Div, format!("R{a} := R{b} / R{c}")),
        0x28 => ("IDIV", InsnFormat::ABC, InsnCategory::Idiv, format!("R{a} := R{b} // R{c}")),
        0x29 => ("BAND", InsnFormat::ABC, InsnCategory::Band, format!("R{a} := R{b} & R{c}")),
        0x2A => ("BOR", InsnFormat::ABC, InsnCategory::Bor, format!("R{a} := R{b} | R{c}")),
        0x2B => ("BXOR", InsnFormat::ABC, InsnCategory::Bxor, format!("R{a} := R{b} ~ R{c}")),
        0x2C => ("SHL", InsnFormat::ABC, InsnCategory::Shl, format!("R{a} := R{b} << R{c}")),
        0x2D => ("SHR", InsnFormat::ABC, InsnCategory::Shr, format!("R{a} := R{b} >> R{c}")),
        0x2E => ("MMBIN", InsnFormat::ABC, InsnCategory::Unknown, format!("R{a} op R{b} (mm={c})")),
        0x2F => ("MMBINI", InsnFormat::ABC, InsnCategory::Unknown, format!("R{a} op {b} (mm={c})")),
        0x30 => ("MMBINK", InsnFormat::ABC, InsnCategory::Unknown, format!("R{a} op K[{b}] (mm={c})")),
        0x31 => ("UNM", InsnFormat::ABC, InsnCategory::Unm, format!("R{a} := -R{b}")),
        0x32 => ("BNOT", InsnFormat::ABC, InsnCategory::Bnot, format!("R{a} := ~R{b}")),
        0x33 => ("NOT", InsnFormat::ABC, InsnCategory::Not, format!("R{a} := not R{b}")),
        0x34 => ("LEN", InsnFormat::ABC, InsnCategory::Len, format!("R{a} := #R{b}")),
        0x35 => ("CONCAT", InsnFormat::ABC, InsnCategory::Concat, format!("R{} := R[{}..{}]", a, a+1, u16::from(a)+b)),
        0x36 => ("CLOSE", InsnFormat::ABC, InsnCategory::Unknown, format!("close upvalues [R{a}+]")),
        0x37 => ("TBC", InsnFormat::ABC, InsnCategory::Unknown, format!("mark R{a} TBC")),
        0x38 => ("JMP", InsnFormat::AsBx, InsnCategory::Jump, format!("pc += {sbx} (->{sbx})")),
        0x39 => ("EQ", InsnFormat::ABC, InsnCategory::Test, format!("if (R{a} == R{b}) == {c} then skip")),
        0x3A => ("LT", InsnFormat::ABC, InsnCategory::Test, format!("if (R{a} < R{b}) == {c} then skip")),
        0x3B => ("LE", InsnFormat::ABC, InsnCategory::Test, format!("if (R{a} <= R{b}) == {c} then skip")),
        0x3C => ("EQK", InsnFormat::ABC, InsnCategory::Test, format!("if (R{a} == K[{b}]) == {c} then skip")),
        0x3D => ("EQI", InsnFormat::ABC, InsnCategory::Test, format!("if (R{} == {}) == {} then skip", a, b.cast_signed(), c)),
        0x3E => ("LTI", InsnFormat::ABC, InsnCategory::Test, format!("if (R{} < {}) == {} then skip", a, b.cast_signed(), c)),
        0x3F => ("LEI", InsnFormat::ABC, InsnCategory::Test, format!("if (R{} <= {}) == {} then skip", a, b.cast_signed(), c)),
        0x40 => ("GTI", InsnFormat::ABC, InsnCategory::Test, format!("if (R{} > {}) == {} then skip", a, b.cast_signed(), c)),
        0x41 => ("GEI", InsnFormat::ABC, InsnCategory::Test, format!("if (R{} >= {}) == {} then skip", a, b.cast_signed(), c)),
        0x42 => ("TEST", InsnFormat::ABC, InsnCategory::Test, format!("if not (bool(R{a}) == {c}) then skip")),
        0x43 => ("TESTSET", InsnFormat::ABC, InsnCategory::TestSet, format!("if (bool(R{b}) == {c}) then R{a} := R{b}")),
        0x44 => ("CALL", InsnFormat::ABC, InsnCategory::Call, format!("R[{}..{}] := R{}(R[{}..{}])", a, u16::from(a)+c-2, a, a+1, u16::from(a)+b-1)),
        0x45 => ("TAILCALL", InsnFormat::ABC, InsnCategory::TailCall, format!("return R{}(R[{}..{}])", a, a+1, u16::from(a)+b-1)),
        0x46 => ("RETURN", InsnFormat::ABC, InsnCategory::Return, format!("return R[{}..{}]", a, u16::from(a)+b-2)),
        0x47 => ("RETURN0", InsnFormat::ABC, InsnCategory::Return, "return".to_string()),
        0x48 => ("RETURN1", InsnFormat::ABC, InsnCategory::Return, format!("return R{a}")),
        0x49 => ("FORLOOP", InsnFormat::AsBx, InsnCategory::ForLoop, format!("R{} += R{}; if R{} <?= R{} then pc += {}", a+2, a+1, a+2, a, sbx)),
        0x4A => ("FORPREP", InsnFormat::AsBx, InsnCategory::ForPrep, format!("R{} -= R{}; pc += {}", a+2, a+1, sbx)),
        0x4B => ("TFORPREP", InsnFormat::AsBx, InsnCategory::TForCall, format!("R{a} := closure; pc += {sbx}")),
        0x4C => ("TFORCALL", InsnFormat::ABC, InsnCategory::TForCall, format!("R[{}..{}] := R{}(R{},R{})", a+4, u16::from(a)+3+c, a, a+1, a+2)),
        0x4D => ("TFORLOOP", InsnFormat::AsBx, InsnCategory::TForLoop, format!("if R{} ~= nil then R{} := R{}; pc += {}", a+4, a+2, a+4, sbx)),
        0x4E => ("SETLIST", InsnFormat::ABC, InsnCategory::SetList, {
            let c32 = u32::from(c);
            format!("R{}[{}..{}] := R[{}..{}]", a, c32.saturating_sub(1)*50+1, c32*50, a+1, u16::from(a)+b)
        }),
        0x4F => ("CLOSURE", InsnFormat::ABx, InsnCategory::Closure, format!("R{a} := closure(proto[{bx}])")),
        0x50 => ("VARARG", InsnFormat::ABC, InsnCategory::Vararg, format!("R[{}..{}] := vararg", a, u32::from(a).saturating_add(u32::from(c)).saturating_sub(2))),
        0x51 => ("VARARGPREP", InsnFormat::ABC, InsnCategory::Vararg, format!("adjust vararg ({a}+)")),
        0x52 => ("EXTRAARG", InsnFormat::Ax, InsnCategory::Unknown, format!("extra = {ax}")),
        _ => ("???", InsnFormat::ABC, InsnCategory::Unknown, format!("raw={:#010x}", (u32::from(opcode) | (u32::from(a) << 7) | (u32::from(b) << 16)))),
    }
}

pub struct LuaDisasmPrinter;

impl LuaDisasmPrinter {
    #[must_use] 
    pub fn print_proto(proto: &LuaProto, depth: usize) -> String {
        let indent = "  ".repeat(depth);
        let mut out = String::new();
        let _ = writeln!(out, "{}; function {} lines [{}-{}]", indent, proto.name, proto.first_line, proto.last_line);
        let _ = writeln!(out, "{}; params={}, upvals={}, maxstack={}",
            indent, proto.num_params, proto.num_upvalues, proto.max_stack);

        if !proto.upvalues.is_empty() {
            let _ = writeln!(out, "{indent}; upvalues:");
            for (i, uv) in proto.upvalues.iter().enumerate() {
                let _ = writeln!(out, "{}; [{}] {} instack={} idx={}",
                    indent, i, uv.name, uv.instack, uv.idx);
            }
        }

        if !proto.constants.is_empty() {
            let _ = writeln!(out, "{}; constants ({}):", indent, proto.constants.len());
            for (i, c) in proto.constants.iter().enumerate() {
                let _ = writeln!(out, "{}; K[{}] = {}", indent, i, c.to_display());
            }
        }

        let _ = writeln!(out, "{}; bytecode ({} instructions):", indent, proto.instructions.len());
        for (i, insn) in proto.instructions.iter().enumerate() {
            let line = proto.line_info.get(i).copied().unwrap_or(0);
            let local_hint = if proto.locals.is_empty() { String::new() } else {
                proto.locals.iter()
                    .filter(|l| l.start_pc as usize <= i && (l.end_pc as usize) > i)
                    .fold(String::new(), |mut acc, l| {
                        if !acc.is_empty() { acc.push(','); }
                        acc.push_str(&l.name);
                        acc
                    })
            };

            let _ = write!(out, "{}{:4} [{:4}] {:>12}  {:<40}",
                indent, i, line, insn.mnemonic, insn.operands);
            if !local_hint.is_empty() {
                let _ = write!(out, "  ; locals: {local_hint}");
            }
            out.push('\n');
        }

        for (i, sub) in proto.protos.iter().enumerate() {
            let _ = writeln!(out, "\n{indent}; -- sub-proto {i} --");
            out.push_str(&Self::print_proto(sub, depth + 1));
        }

        out
    }

    #[must_use] 
    pub fn disasm_to_json(proto: &LuaProto) -> serde_json::Value {
        serde_json::json!({
            "name": proto.name,
            "lines": [proto.first_line, proto.last_line],
            "params": proto.num_params,
            "upvalues": proto.upvalues.len(),
            "max_stack": proto.max_stack,
            "instructions": proto.instructions.iter().map(|i| {
                serde_json::json!({
                    "offset": i.offset,
                    "mnemonic": i.mnemonic,
                    "operands": i.operands,
                    "raw": format!("{:#010x}", i.raw),
                })
            }).collect::<Vec<_>>(),
            "constants": proto.constants.iter().map(LuaConstant::to_display).collect::<Vec<_>>(),
            "sub_protos": proto.protos.len(),
        })
    }
}

/// # Errors
///
/// Returns an error when the input bytes are malformed, truncated, or
/// otherwise cannot be decoded.
pub fn disassemble_lua54_file(path: &std::path::Path) -> Result<String> {
    let data = std::fs::read(path)?;
    let mut disasm = Lua54Disassembler::new(data);
    disasm.parse_header54()?;
    let proto = disasm.parse_proto54()?;
    Ok(LuaDisasmPrinter::print_proto(&proto, 0))
}
