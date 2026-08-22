//! Lua 5.1 bytecode format.
//!
//! Handles magic `0x1b4c7561` + version `0x51`, decodes function prototypes,
//! constants, upvalues, sub-prototypes, and provides a disassembler.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{self, Cursor, Read};

// ─────────────────────────────────────────────────────────────────────────────
// Magic / version constants
// ─────────────────────────────────────────────────────────────────────────────

pub const LUA_MAGIC: &[u8; 4] = b"\x1bLua";
pub const LUA51_VERSION: u8 = 0x51;
pub const LUA52_VERSION: u8 = 0x52;
pub const LUA53_VERSION: u8 = 0x53;

// ─────────────────────────────────────────────────────────────────────────────
// Cursor helpers
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn read_u8(cur: &mut Cursor<&[u8]>) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    cur.read_exact(&mut buf)?;
    Ok(buf[0])
}

pub(crate) fn read_u32_le(cur: &mut Cursor<&[u8]>) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    cur.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

pub(crate) fn read_i32_le(cur: &mut Cursor<&[u8]>) -> io::Result<i32> {
    read_u32_le(cur).map(|n| n as i32)
}

pub(crate) fn read_f64_le(cur: &mut Cursor<&[u8]>) -> io::Result<f64> {
    let mut buf = [0u8; 8];
    cur.read_exact(&mut buf)?;
    Ok(f64::from_le_bytes(buf))
}

pub(crate) fn read_lua_string(cur: &mut Cursor<&[u8]>) -> io::Result<Option<String>> {
    let len_byte = read_u8(cur)?;
    if len_byte == 0 {
        return Ok(None);
    }
    let len = len_byte as usize;
    let mut buf = vec![0u8; len - 1]; // Lua includes NUL in count but not in data
    cur.read_exact(&mut buf)?;
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua 5.1 header
// ─────────────────────────────────────────────────────────────────────────────

/// The Lua 5.1 file header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lua51Header {
    /// Must be `LUA_MAGIC`.
    pub magic: [u8; 4],
    /// Must be `0x51`.
    pub version: u8,
    /// 0 = official format.
    pub format: u8,
    /// 1 = little-endian, 0 = big-endian.
    pub endian: u8,
    /// Size of `int` in bytes.
    pub int_size: u8,
    /// Size of `size_t` in bytes.
    pub size_t_size: u8,
    /// Size of instruction in bytes (always 4).
    pub instr_size: u8,
    /// Size of Lua number (`lua_Number`, usually double = 8).
    pub number_size: u8,
    /// 1 if numbers are integral.
    pub integral_flag: u8,
}

impl Lua51Header {
    pub fn parse(data: &[u8]) -> Result<(Self, usize), String> {
        if data.len() < 12 {
            return Err("header too short".into());
        }
        if &data[0..4] != LUA_MAGIC {
            return Err("invalid magic".into());
        }
        if data[4] != LUA51_VERSION {
            return Err(format!("not Lua 5.1 (version=0x{:02x})", data[4]));
        }
        Ok((
            Self {
                magic: [data[0], data[1], data[2], data[3]],
                version: data[4],
                format: data[5],
                endian: data[6],
                int_size: data[7],
                size_t_size: data[8],
                instr_size: data[9],
                number_size: data[10],
                integral_flag: data[11],
            },
            12,
        ))
    }

    pub const fn is_little_endian(&self) -> bool {
        self.endian == 1
    }
    pub const fn is_64bit(&self) -> bool {
        self.size_t_size == 8
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua 5.1 opcodes
// ─────────────────────────────────────────────────────────────────────────────

/// All Lua 5.1 opcodes (38 total).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Lua51Opcode {
    Move = 0,
    LoadK = 1,
    LoadBool = 2,
    LoadNil = 3,
    GetUpval = 4,
    GetGlobal = 5,
    GetTable = 6,
    SetGlobal = 7,
    SetUpval = 8,
    SetTable = 9,
    NewTable = 10,
    Self_ = 11,
    Add = 12,
    Sub = 13,
    Mul = 14,
    Div = 15,
    Mod = 16,
    Pow = 17,
    Unm = 18,
    Not = 19,
    Len = 20,
    Concat = 21,
    Jmp = 22,
    Eq = 23,
    Lt = 24,
    Le = 25,
    Test = 26,
    TestSet = 27,
    Call = 28,
    TailCall = 29,
    Return = 30,
    ForLoop = 31,
    ForPrep = 32,
    TForLoop = 33,
    SetList = 34,
    Close = 35,
    Closure = 36,
    VarArg = 37,
}

impl Lua51Opcode {
    pub const fn from_u8(n: u8) -> Option<Self> {
        Some(match n {
            0 => Self::Move,
            1 => Self::LoadK,
            2 => Self::LoadBool,
            3 => Self::LoadNil,
            4 => Self::GetUpval,
            5 => Self::GetGlobal,
            6 => Self::GetTable,
            7 => Self::SetGlobal,
            8 => Self::SetUpval,
            9 => Self::SetTable,
            10 => Self::NewTable,
            11 => Self::Self_,
            12 => Self::Add,
            13 => Self::Sub,
            14 => Self::Mul,
            15 => Self::Div,
            16 => Self::Mod,
            17 => Self::Pow,
            18 => Self::Unm,
            19 => Self::Not,
            20 => Self::Len,
            21 => Self::Concat,
            22 => Self::Jmp,
            23 => Self::Eq,
            24 => Self::Lt,
            25 => Self::Le,
            26 => Self::Test,
            27 => Self::TestSet,
            28 => Self::Call,
            29 => Self::TailCall,
            30 => Self::Return,
            31 => Self::ForLoop,
            32 => Self::ForPrep,
            33 => Self::TForLoop,
            34 => Self::SetList,
            35 => Self::Close,
            36 => Self::Closure,
            37 => Self::VarArg,
            _ => return None,
        })
    }

    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Move => "MOVE",
            Self::LoadK => "LOADK",
            Self::LoadBool => "LOADBOOL",
            Self::LoadNil => "LOADNIL",
            Self::GetUpval => "GETUPVAL",
            Self::GetGlobal => "GETGLOBAL",
            Self::GetTable => "GETTABLE",
            Self::SetGlobal => "SETGLOBAL",
            Self::SetUpval => "SETUPVAL",
            Self::SetTable => "SETTABLE",
            Self::NewTable => "NEWTABLE",
            Self::Self_ => "SELF",
            Self::Add => "ADD",
            Self::Sub => "SUB",
            Self::Mul => "MUL",
            Self::Div => "DIV",
            Self::Mod => "MOD",
            Self::Pow => "POW",
            Self::Unm => "UNM",
            Self::Not => "NOT",
            Self::Len => "LEN",
            Self::Concat => "CONCAT",
            Self::Jmp => "JMP",
            Self::Eq => "EQ",
            Self::Lt => "LT",
            Self::Le => "LE",
            Self::Test => "TEST",
            Self::TestSet => "TESTSET",
            Self::Call => "CALL",
            Self::TailCall => "TAILCALL",
            Self::Return => "RETURN",
            Self::ForLoop => "FORLOOP",
            Self::ForPrep => "FORPREP",
            Self::TForLoop => "TFORLOOP",
            Self::SetList => "SETLIST",
            Self::Close => "CLOSE",
            Self::Closure => "CLOSURE",
            Self::VarArg => "VARARG",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua51Instruction
// ─────────────────────────────────────────────────────────────────────────────

/// A decoded Lua 5.1 instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lua51Instruction {
    pub raw: u32,
    pub opcode: Option<Lua51Opcode>,
    /// Field A (bits 6..13).
    pub a: u8,
    /// Field B (bits 23..31).
    pub b: u16,
    /// Field C (bits 14..22).
    pub c: u16,
    /// Field Bx (bits 14..31).
    pub bx: u32,
    /// Field sBx = Bx - 131071.
    pub sbx: i32,
}

impl Lua51Instruction {
    pub const fn decode(raw: u32) -> Self {
        let opcode_byte = (raw & 0x3f) as u8;
        let a = ((raw >> 6) & 0xff) as u8;
        let c = ((raw >> 14) & 0x1ff) as u16;
        let b = ((raw >> 23) & 0x1ff) as u16;
        let bx = (raw >> 14) & 0x3ffff;
        let sbx = bx as i32 - 131_071;
        Self {
            raw,
            opcode: Lua51Opcode::from_u8(opcode_byte),
            a,
            b,
            c,
            bx,
            sbx,
        }
    }

    pub fn mnemonic(&self) -> &'static str {
        self.opcode.map_or("???", Lua51Opcode::mnemonic)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua51Constant
// ─────────────────────────────────────────────────────────────────────────────

/// A constant in the constant table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Lua51Constant {
    Nil,
    Boolean(bool),
    Number(f64),
    String(String),
}

impl fmt::Display for Lua51Constant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nil => f.write_str("nil"),
            Self::Boolean(b) => write!(f, "{b}"),
            Self::Number(n) => write!(f, "{n}"),
            Self::String(s) => write!(f, "{s:?}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua51LocalVar
// ─────────────────────────────────────────────────────────────────────────────

/// A local variable debug record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lua51LocalVar {
    pub name: String,
    pub start_pc: u32,
    pub end_pc: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua51Proto
// ─────────────────────────────────────────────────────────────────────────────

/// A function prototype as stored in Lua 5.1 bytecode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lua51Proto {
    pub source_name: Option<String>,
    pub line_defined: i32,
    pub last_line_defined: i32,
    pub num_upvalues: u8,
    pub num_params: u8,
    pub is_vararg: u8,
    pub max_stack_size: u8,
    pub code: Vec<u32>,
    pub constants: Vec<Lua51Constant>,
    pub protos: Vec<Self>,
    pub source_lines: Vec<i32>,
    pub locals: Vec<Lua51LocalVar>,
    pub upvalue_names: Vec<String>,
}

impl Lua51Proto {
    /// Number of instructions.
    pub const fn instr_count(&self) -> usize {
        self.code.len()
    }

    /// Decode all instructions.
    pub fn instructions(&self) -> Vec<Lua51Instruction> {
        self.code
            .iter()
            .map(|&r| Lua51Instruction::decode(r))
            .collect()
    }

    /// Number of nested prototypes.
    pub const fn sub_proto_count(&self) -> usize {
        self.protos.len()
    }

    /// Total instruction count across all nested protos.
    pub fn total_instr_count(&self) -> usize {
        self.instr_count()
            + self
                .protos
                .iter()
                .map(Self::total_instr_count)
                .sum::<usize>()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// decode_lua51_proto
// ─────────────────────────────────────────────────────────────────────────────

/// Decode a Lua 5.1 prototype from the cursor.
pub fn decode_lua51_proto(cur: &mut Cursor<&[u8]>) -> Result<Lua51Proto, String> {
    let source_name = read_lua_string(cur).map_err(|e| format!("source name: {e}"))?;
    let line_defined = read_i32_le(cur).map_err(|e| format!("line_defined: {e}"))?;
    let last_line_defined = read_i32_le(cur).map_err(|e| format!("last_line_defined: {e}"))?;
    let num_upvalues = read_u8(cur).map_err(|e| format!("num_upvalues: {e}"))?;
    let num_params = read_u8(cur).map_err(|e| format!("num_params: {e}"))?;
    let is_vararg = read_u8(cur).map_err(|e| format!("is_vararg: {e}"))?;
    let max_stack_size = read_u8(cur).map_err(|e| format!("max_stack: {e}"))?;

    // Code
    let n_code = read_u32_le(cur).map_err(|e| format!("n_code: {e}"))?;
    let mut code = Vec::with_capacity(n_code as usize);
    for _ in 0..n_code {
        code.push(read_u32_le(cur).map_err(|e| format!("instr: {e}"))?);
    }

    // Constants
    let n_const = read_u32_le(cur).map_err(|e| format!("n_const: {e}"))?;
    let mut constants = Vec::with_capacity(n_const as usize);
    for _ in 0..n_const {
        let tag = read_u8(cur).map_err(|e| format!("const tag: {e}"))?;
        let constant = match tag {
            0 => Lua51Constant::Nil,
            1 => {
                let b = read_u8(cur).map_err(|e| format!("bool const: {e}"))?;
                Lua51Constant::Boolean(b != 0)
            }
            3 => {
                let n = read_f64_le(cur).map_err(|e| format!("number const: {e}"))?;
                Lua51Constant::Number(n)
            }
            4 => {
                let s = read_lua_string(cur)
                    .map_err(|e| format!("string const: {e}"))?
                    .unwrap_or_default();
                Lua51Constant::String(s)
            }
            _ => return Err(format!("unknown constant tag: {tag}")),
        };
        constants.push(constant);
    }

    // Sub-prototypes
    let n_proto = read_u32_le(cur).map_err(|e| format!("n_proto: {e}"))?;
    let mut protos = Vec::with_capacity(n_proto as usize);
    for _ in 0..n_proto {
        protos.push(decode_lua51_proto(cur)?);
    }

    // Line info
    let n_lines = read_u32_le(cur).map_err(|e| format!("n_lines: {e}"))?;
    let mut source_lines = Vec::with_capacity(n_lines as usize);
    for _ in 0..n_lines {
        source_lines.push(read_i32_le(cur).map_err(|e| format!("line: {e}"))?);
    }

    // Locals
    let n_locals = read_u32_le(cur).map_err(|e| format!("n_locals: {e}"))?;
    let mut locals = Vec::with_capacity(n_locals as usize);
    for _ in 0..n_locals {
        let name = read_lua_string(cur)
            .map_err(|e| format!("local name: {e}"))?
            .unwrap_or_default();
        let start_pc = read_u32_le(cur).map_err(|e| format!("start_pc: {e}"))?;
        let end_pc = read_u32_le(cur).map_err(|e| format!("end_pc: {e}"))?;
        locals.push(Lua51LocalVar {
            name,
            start_pc,
            end_pc,
        });
    }

    // Upvalue names
    let n_upvals = read_u32_le(cur).map_err(|e| format!("n_upvals: {e}"))?;
    let mut upvalue_names = Vec::with_capacity(n_upvals as usize);
    for _ in 0..n_upvals {
        let name = read_lua_string(cur)
            .map_err(|e| format!("upval name: {e}"))?
            .unwrap_or_default();
        upvalue_names.push(name);
    }

    Ok(Lua51Proto {
        source_name,
        line_defined,
        last_line_defined,
        num_upvalues,
        num_params,
        is_vararg,
        max_stack_size,
        code,
        constants,
        protos,
        source_lines,
        locals,
        upvalue_names,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Lua51Disassembler
// ─────────────────────────────────────────────────────────────────────────────

/// Disassembles Lua 5.1 prototypes to text.
pub struct Lua51Disassembler {
    pub show_source_lines: bool,
    pub show_constants: bool,
}

impl Default for Lua51Disassembler {
    fn default() -> Self {
        Self {
            show_source_lines: true,
            show_constants: true,
        }
    }
}

impl Lua51Disassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Disassemble a single prototype to a string.
    pub fn disassemble(&self, proto: &Lua51Proto) -> String {
        let mut out = String::new();
        let name = proto.source_name.as_deref().unwrap_or("(anonymous)");
        out.push_str(&format!(
            "; function: {} [{}-{}] params={} upvals={}\n",
            name, proto.line_defined, proto.last_line_defined, proto.num_params, proto.num_upvalues
        ));
        let instrs = proto.instructions();
        for (i, instr) in instrs.iter().enumerate() {
            let line_info = if self.show_source_lines && i < proto.source_lines.len() {
                format!("[{:4}]", proto.source_lines[i])
            } else {
                "      ".to_string()
            };
            out.push_str(&format!(
                "  {:4}: {} {:<12} A={} B={} C={}\n",
                i,
                line_info,
                instr.mnemonic(),
                instr.a,
                instr.b,
                instr.c
            ));
        }
        if self.show_constants && !proto.constants.is_empty() {
            out.push_str("; constants:\n");
            for (i, c) in proto.constants.iter().enumerate() {
                out.push_str(&format!("  {i:4}: {c}\n"));
            }
        }
        out
    }

    /// Disassemble all protos recursively.
    pub fn disassemble_all(&self, proto: &Lua51Proto) -> String {
        let mut out = self.disassemble(proto);
        for sub in &proto.protos {
            out.push('\n');
            out.push_str(&self.disassemble_all(sub));
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- Lua51Header ---

    #[test]
    fn header_parse_invalid_magic() {
        let data = [0u8; 12];
        assert!(Lua51Header::parse(&data).is_err());
    }

    #[test]
    fn header_parse_wrong_version() {
        let mut data = [0u8; 12];
        data[0..4].copy_from_slice(LUA_MAGIC);
        data[4] = 0x52; // Lua 5.2
        assert!(Lua51Header::parse(&data).is_err());
    }

    #[test]
    fn header_parse_valid() {
        let mut data = [0u8; 12];
        data[0..4].copy_from_slice(LUA_MAGIC);
        data[4] = LUA51_VERSION;
        data[6] = 1; // little-endian
        data[7] = 4;
        data[8] = 4;
        data[9] = 4;
        data[10] = 8;
        data[11] = 0;
        let (hdr, n) = Lua51Header::parse(&data).unwrap();
        assert_eq!(n, 12);
        assert_eq!(hdr.version, LUA51_VERSION);
        assert!(hdr.is_little_endian());
    }

    #[test]
    fn header_too_short() {
        let data = [0u8; 5];
        assert!(Lua51Header::parse(&data).is_err());
    }

    // --- Lua51Opcode ---

    #[test]
    fn opcode_from_u8_move() {
        assert_eq!(Lua51Opcode::from_u8(0), Some(Lua51Opcode::Move));
    }

    #[test]
    fn opcode_from_u8_vararg() {
        assert_eq!(Lua51Opcode::from_u8(37), Some(Lua51Opcode::VarArg));
    }

    #[test]
    fn opcode_from_u8_out_of_range() {
        assert_eq!(Lua51Opcode::from_u8(38), None);
    }

    #[test]
    fn opcode_mnemonic_move() {
        assert_eq!(Lua51Opcode::Move.mnemonic(), "MOVE");
    }

    #[test]
    fn opcode_mnemonic_return() {
        assert_eq!(Lua51Opcode::Return.mnemonic(), "RETURN");
    }

    // --- Lua51Instruction ---

    #[test]
    fn instruction_decode_move() {
        // opcode=0 (MOVE), A=1, B=2, C=0
        let raw = (1 << 6) | (2 << 23);
        let instr = Lua51Instruction::decode(raw);
        assert_eq!(instr.opcode, Some(Lua51Opcode::Move));
        assert_eq!(instr.a, 1);
        assert_eq!(instr.b, 2);
    }

    #[test]
    fn instruction_mnemonic_unknown() {
        let instr = Lua51Instruction {
            raw: 0,
            opcode: None,
            a: 0,
            b: 0,
            c: 0,
            bx: 0,
            sbx: 0,
        };
        assert_eq!(instr.mnemonic(), "???");
    }

    #[test]
    fn instruction_sbx_offset() {
        // bx = 131_071 → sbx = 0
        let bx = 131_071_u32;
        let raw = 22 | (bx << 14); // JMP with bx = 131071
        let instr = Lua51Instruction::decode(raw);
        assert_eq!(instr.sbx, 0);
    }

    // --- Lua51Constant ---

    #[test]
    fn constant_display_nil() {
        assert_eq!(format!("{}", Lua51Constant::Nil), "nil");
    }

    #[test]
    fn constant_display_bool() {
        assert_eq!(format!("{}", Lua51Constant::Boolean(true)), "true");
    }

    #[test]
    fn constant_display_string() {
        let s = format!("{}", Lua51Constant::String("hello".into()));
        assert!(s.contains("hello"));
    }

    // --- Lua51Proto (constructed, not parsed) ---

    fn make_proto(code: Vec<u32>, consts: Vec<Lua51Constant>) -> Lua51Proto {
        Lua51Proto {
            source_name: Some("test".into()),
            line_defined: 1,
            last_line_defined: 10,
            num_upvalues: 0,
            num_params: 0,
            is_vararg: 0,
            max_stack_size: 4,
            code,
            constants: consts,
            protos: vec![],
            source_lines: vec![],
            locals: vec![],
            upvalue_names: vec![],
        }
    }

    #[test]
    fn proto_instr_count() {
        let p = make_proto(vec![0u32; 5], vec![]);
        assert_eq!(p.instr_count(), 5);
    }

    #[test]
    fn proto_total_instr_count_nested() {
        let child = make_proto(vec![0u32; 3], vec![]);
        let mut parent = make_proto(vec![0u32; 2], vec![]);
        parent.protos.push(child);
        assert_eq!(parent.total_instr_count(), 5);
    }

    #[test]
    fn proto_instructions_decode() {
        let raw = (2 << 6) | (3 << 23); // MOVE A=2, B=3
        let p = make_proto(vec![raw], vec![]);
        let instrs = p.instructions();
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].a, 2);
    }

    // --- Lua51Disassembler ---

    #[test]
    fn disassembler_output_contains_function_name() {
        let p = make_proto(vec![0u32], vec![]);
        let d = Lua51Disassembler::new();
        let out = d.disassemble(&p);
        assert!(out.contains("test"));
    }

    #[test]
    fn disassembler_output_contains_mnemonic() {
        let raw = 0; // MOVE
        let p = make_proto(vec![raw], vec![]);
        let d = Lua51Disassembler::new();
        let out = d.disassemble(&p);
        assert!(out.contains("MOVE"));
    }

    #[test]
    fn disassembler_constants_shown() {
        let p = make_proto(vec![], vec![Lua51Constant::Number(3.14_f64)]);
        let d = Lua51Disassembler::new();
        let out = d.disassemble(&p);
        assert!(out.contains("3.14"));
    }

    #[test]
    fn disassembler_all_recurses() {
        let child = make_proto(vec![0u32], vec![]);
        let mut parent = make_proto(vec![0u32], vec![]);
        parent.protos.push(child);
        let d = Lua51Disassembler::new();
        let out = d.disassemble_all(&parent);
        // Should contain function header twice
        assert_eq!(out.matches("; function:").count(), 2);
    }
}
