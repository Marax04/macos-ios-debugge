//! `rustre-loader-lua::lua50_format`
//!
//! Lua 5.0 bytecode format (historic, version byte 0x50).
//!
//! Lua 5.0 differs from 5.1 in several ways:
//! - Version byte is `0x50`.
//! - The header includes `sizeof(lua_Number)` and an integer flag.
//! - Instructions use a 6-bit opcode (same encoding as 5.1 but different opcode table).
//! - Some opcodes are absent from 5.1 (`TFORPREP`, `SETLISTO`, `POW`).
//! - Prototypes store upvalue names **before** inner protos.

use std::collections::HashMap;
use std::fmt;

// ─── Lua 5.0 constants ────────────────────────────────────────────────────────

/// Lua bytecode magic bytes.
pub const LUA50_MAGIC: &[u8; 4] = b"\x1bLua";

/// Lua 5.0 version byte.
pub const LUA50_VERSION: u8 = 0x50;

/// Lua 5.0 official format identifier.
pub const LUA50_FORMAT: u8 = 0;

// ─── Lua 5.0 opcodes ──────────────────────────────────────────────────────────

/// All Lua 5.0 opcodes in canonical order (opcode = array index).
pub static LUA50_OPCODES: &[&str] = &[
    "MOVE",      // 0  A B     R(A) := R(B)
    "LOADK",     // 1  A Bx    R(A) := Kst(Bx)
    "LOADBOOL",  // 2  A B C   R(A) := (Bool)B; if C then PC++
    "LOADNIL",   // 3  A B     R(A) := ... := R(B) := nil
    "GETUPVAL",  // 4  A B     R(A) := UpValue[B]
    "GETGLOBAL", // 5  A Bx    R(A) := Gbl[Kst(Bx)]
    "GETTABLE",  // 6  A B C   R(A) := R(B)[RK(C)]
    "SETGLOBAL", // 7  A Bx    Gbl[Kst(Bx)] := R(A)
    "SETUPVAL",  // 8  A B     UpValue[B] := R(A)
    "SETTABLE",  // 9  A B C   R(A)[RK(B)] := RK(C)
    "NEWTABLE",  // 10 A B C   R(A) := {} (size = B, C)
    "SELF",      // 11 A B C   R(A+1) := R(B); R(A) := R(B)[RK(C)]
    "ADD",       // 12 A B C   R(A) := RK(B) + RK(C)
    "SUB",       // 13 A B C   R(A) := RK(B) - RK(C)
    "MUL",       // 14 A B C   R(A) := RK(B) * RK(C)
    "DIV",       // 15 A B C   R(A) := RK(B) / RK(C)
    "POW",       // 16 A B C   R(A) := RK(B) ^ RK(C)
    "UNM",       // 17 A B     R(A) := -R(B)
    "NOT",       // 18 A B     R(A) := not R(B)
    "CONCAT",    // 19 A B C   R(A) := R(B)..…..R(C)
    "JMP",       // 20 sBx     PC += sBx
    "EQ",        // 21 A B C   if (RK(B) == RK(C)) ~= A then PC++
    "LT",        // 22 A B C   if (RK(B) <  RK(C)) ~= A then PC++
    "LE",        // 23 A B C   if (RK(B) <= RK(C)) ~= A then PC++
    "TEST",      // 24 A B C   if (R(B) <=> C) then R(A) := R(B) else PC++
    "CALL",      // 25 A B C   R(A), …, R(A+C-2) := R(A)(R(A+1),…,R(A+B-1))
    "TAILCALL",  // 26 A B C   return R(A)(R(A+1),…,R(A+B-1))
    "RETURN",    // 27 A B     return R(A), …, R(A+B-2) (see note)
    "FORLOOP",   // 28 A sBx   R(A) += R(A+2); if R(A) <= R(A+1) then { PC += sBx; R(A+3) = R(A) }
    "TFORLOOP", // 29 A C     R(A+2), …, R(A+2+C) := R(A)(R(A+1),R(A+2)); if R(A+2) ~= nil then R(A+1) := R(A+2) else PC++
    "TFORPREP", // 30 A sBx   if type(R(A)) == table then R(A+1) := R(A), R(A) := next; PC += sBx
    "SETLIST",  // 31 A Bx    R(A)[Bx-Bx%FPF+i] := R(A+i), 1 <= i <= Bx%FPF+1
    "SETLISTO", // 32 A Bx    (see note)
    "CLOSE",    // 33 A       close stack variables down to R(A)
    "CLOSURE",  // 34 A Bx    R(A) := closure(Proto[Bx], R(A),…,R(A+n))
];

/// Number of opcodes in Lua 5.0.
pub const LUA50_NUM_OPCODES: usize = LUA50_OPCODES.len();

/// Opcode indices for common instructions.
pub mod op {
    pub const MOVE: u8 = 0;
    pub const LOADK: u8 = 1;
    pub const LOADBOOL: u8 = 2;
    pub const LOADNIL: u8 = 3;
    pub const GETUPVAL: u8 = 4;
    pub const GETGLOBAL: u8 = 5;
    pub const GETTABLE: u8 = 6;
    pub const SETGLOBAL: u8 = 7;
    pub const SETUPVAL: u8 = 8;
    pub const SETTABLE: u8 = 9;
    pub const NEWTABLE: u8 = 10;
    pub const SELF: u8 = 11;
    pub const ADD: u8 = 12;
    pub const SUB: u8 = 13;
    pub const MUL: u8 = 14;
    pub const DIV: u8 = 15;
    pub const POW: u8 = 16;
    pub const UNM: u8 = 17;
    pub const NOT: u8 = 18;
    pub const CONCAT: u8 = 19;
    pub const JMP: u8 = 20;
    pub const EQ: u8 = 21;
    pub const LT: u8 = 22;
    pub const LE: u8 = 23;
    pub const TEST: u8 = 24;
    pub const CALL: u8 = 25;
    pub const TAILCALL: u8 = 26;
    pub const RETURN: u8 = 27;
    pub const FORLOOP: u8 = 28;
    pub const TFORLOOP: u8 = 29;
    pub const TFORPREP: u8 = 30;
    pub const SETLIST: u8 = 31;
    pub const SETLISTO: u8 = 32;
    pub const CLOSE: u8 = 33;
    pub const CLOSURE: u8 = 34;
}

/// Return the mnemonic for a Lua 5.0 opcode byte, or `"UNK"` if out of range.
#[must_use]
pub fn opcode_name_50(opcode: u8) -> &'static str {
    LUA50_OPCODES.get(opcode as usize).copied().unwrap_or("UNK")
}

// ─── Instruction encoding ─────────────────────────────────────────────────────

/// Instruction format used by Lua 5.0 (same encoding as 5.1):
///
/// bits  0– 5: opcode (6 bits)
/// bits  6–13: A      (8 bits)
/// bits 14–22: C      (9 bits)
/// bits 23–31: B      (9 bits)
/// Bx = B<<9|C (18 bits unsigned)
/// sBx = Bx - MAXARG_sBx  (MAXARG_sBx = (1<<17)-1 = 131071)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lua50Instr(pub u32);

impl Lua50Instr {
    /// Opcode (bits 0–5).
    #[must_use]
    pub fn opcode(self) -> u8 {
        (self.0 & 0x3F) as u8
    }

    /// A operand (bits 6–13).
    #[must_use]
    pub fn a(self) -> u8 {
        ((self.0 >> 6) & 0xFF) as u8
    }

    /// C operand (bits 14–22).
    #[must_use]
    pub fn c(self) -> u16 {
        ((self.0 >> 14) & 0x1FF) as u16
    }

    /// B operand (bits 23–31).
    #[must_use]
    pub fn b(self) -> u16 {
        ((self.0 >> 23) & 0x1FF) as u16
    }

    /// Bx = B<<9|C (unsigned 18-bit).
    #[must_use]
    pub fn bx(self) -> u32 {
        self.0 >> 14
    }

    /// sBx = Bx - 131071.
    #[must_use]
    pub fn sbx(self) -> i32 {
        self.bx() as i32 - 131_071
    }

    /// Mnemonic for this instruction.
    #[must_use]
    pub fn mnemonic(self) -> &'static str {
        opcode_name_50(self.opcode())
    }

    /// Return `true` if this is a jump instruction.
    #[must_use]
    pub fn is_jump(self) -> bool {
        matches!(
            self.opcode(),
            op::JMP | op::FORLOOP | op::TFORPREP | op::EQ | op::LT | op::LE | op::TEST
        )
    }

    /// Return `true` if this instruction uses the sBx format.
    #[must_use]
    pub fn uses_sbx(self) -> bool {
        matches!(self.opcode(), op::JMP | op::FORLOOP | op::TFORPREP)
    }

    /// Return `true` if this instruction uses the Bx format.
    #[must_use]
    pub fn uses_bx(self) -> bool {
        matches!(
            self.opcode(),
            op::LOADK | op::GETGLOBAL | op::SETGLOBAL | op::CLOSURE | op::SETLIST | op::SETLISTO
        )
    }
}

impl fmt::Display for Lua50Instr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let op = self.mnemonic();
        if self.uses_sbx() {
            write!(f, "{op:<12} A={} sBx={}", self.a(), self.sbx())
        } else if self.uses_bx() {
            write!(f, "{op:<12} A={} Bx={}", self.a(), self.bx())
        } else {
            write!(f, "{op:<12} A={} B={} C={}", self.a(), self.b(), self.c())
        }
    }
}

// ─── Lua 5.0 header ───────────────────────────────────────────────────────────

/// Parsed Lua 5.0 bytecode file header.
///
/// Layout:
/// ```text
/// bytes 0–3: magic "\x1bLua"
/// byte    4: version (0x50)
/// byte    5: endianness (0 = big-endian, 1 = little-endian)
/// byte    6: sizeof(int)
/// byte    7: sizeof(size_t)
/// byte    8: sizeof(Instruction) — should be 4
/// byte    9: sizeof(lua_Number)  — typically 8 (double)
/// byte   10: int flag            — 0 = floating point, 1 = integer
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lua50Header {
    /// Endianness: `true` = little-endian.
    pub little_endian: bool,
    /// `sizeof(int)`.
    pub int_size: u8,
    /// `sizeof(size_t)`.
    pub size_t_size: u8,
    /// `sizeof(Instruction)` — should be 4.
    pub instruction_size: u8,
    /// `sizeof(lua_Number)` — typically 8.
    pub number_size: u8,
    /// Integer number flag: `true` if numbers are stored as integers.
    pub is_integer_num: bool,
}

impl Lua50Header {
    /// Byte length of the Lua 5.0 header.
    pub const SIZE: usize = 11;

    /// Parse a header from `data`.
    ///
    /// # Errors
    /// Returns a description string on parse failure.
    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < Self::SIZE {
            return Err("data too short for Lua 5.0 header");
        }
        if &data[0..4] != LUA50_MAGIC {
            return Err("invalid Lua magic bytes");
        }
        if data[4] != LUA50_VERSION {
            return Err("not a Lua 5.0 bytecode file");
        }
        Ok(Self {
            little_endian: data[5] != 0,
            int_size: data[6],
            size_t_size: data[7],
            instruction_size: data[8],
            number_size: data[9],
            is_integer_num: data[10] != 0,
        })
    }

    /// Encode a valid header into a `Vec<u8>`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(Self::SIZE);
        v.extend_from_slice(LUA50_MAGIC);
        v.push(LUA50_VERSION);
        v.push(if self.little_endian { 1 } else { 0 });
        v.push(self.int_size);
        v.push(self.size_t_size);
        v.push(self.instruction_size);
        v.push(self.number_size);
        v.push(if self.is_integer_num { 1 } else { 0 });
        v
    }

    /// Create a standard little-endian, 32-bit header.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            little_endian: true,
            int_size: 4,
            size_t_size: 4,
            instruction_size: 4,
            number_size: 8,
            is_integer_num: false,
        }
    }
}

impl fmt::Display for Lua50Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Lua 5.0 {} int={} size_t={} inst={} num={}{}",
            if self.little_endian { "LE" } else { "BE" },
            self.int_size,
            self.size_t_size,
            self.instruction_size,
            self.number_size,
            if self.is_integer_num { " int-nums" } else { "" },
        )
    }
}

// ─── Lua 5.0 constant ─────────────────────────────────────────────────────────

/// A constant pool entry for Lua 5.0.
#[derive(Debug, Clone, PartialEq)]
pub enum Lua50Const {
    /// nil.
    Nil,
    /// Number (always stored as `double` in 5.0 unless integer flag is set).
    Number(f64),
    /// String constant.
    String(String),
}

impl Lua50Const {
    /// Tag byte for nil.
    pub const TAG_NIL: u8 = 0;
    /// Tag byte for number.
    pub const TAG_NUMBER: u8 = 1;
    /// Tag byte for string.
    pub const TAG_STRING: u8 = 2;

    /// Return `true` if this is a string.
    #[must_use]
    pub fn is_string(&self) -> bool {
        matches!(self, Self::String(_))
    }

    /// Return the string value if applicable.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

impl fmt::Display for Lua50Const {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nil => write!(f, "nil"),
            Self::Number(n) => write!(f, "{n}"),
            Self::String(s) => write!(f, "\"{s}\""),
        }
    }
}

// ─── Lua 5.0 local variable ───────────────────────────────────────────────────

/// A local variable descriptor in a Lua 5.0 prototype.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lua50Local {
    /// Variable name.
    pub name: String,
    /// First live instruction.
    pub start_pc: u32,
    /// Last live instruction.
    pub end_pc: u32,
}

impl fmt::Display for Lua50Local {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}-{}]", self.name, self.start_pc, self.end_pc)
    }
}

// ─── Lua 5.0 prototype ────────────────────────────────────────────────────────

/// A parsed Lua 5.0 function prototype.
#[derive(Debug, Clone)]
pub struct Lua50Proto {
    /// Source name.
    pub source: Option<String>,
    /// First defined line.
    pub line_defined: u32,
    /// Number of upvalues.
    pub num_upvalues: u8,
    /// Number of parameters.
    pub num_params: u8,
    /// Whether the function is vararg.
    pub is_vararg: bool,
    /// Maximum stack size.
    pub max_stack: u8,
    /// Instructions.
    pub code: Vec<Lua50Instr>,
    /// Constant pool.
    pub constants: Vec<Lua50Const>,
    /// Nested prototypes.
    pub protos: Vec<Lua50Proto>,
    /// Source-line mapping: instruction index → line number.
    pub line_info: Vec<u32>,
    /// Local variable debug info.
    pub locals: Vec<Lua50Local>,
    /// Upvalue names.
    pub upvalue_names: Vec<String>,
}

impl Lua50Proto {
    /// Build a minimal mock prototype for testing.
    #[must_use]
    pub fn mock() -> Self {
        Self {
            source: Some("@test50.lua".to_string()),
            line_defined: 0,
            num_upvalues: 1,
            num_params: 0,
            is_vararg: true,
            max_stack: 4,
            code: vec![Lua50Instr((op::RETURN as u32) | (1 << 23))],
            constants: vec![
                Lua50Const::String("hello".to_string()),
                Lua50Const::Number(3.14_f64),
                Lua50Const::Nil,
            ],
            protos: vec![],
            line_info: vec![1],
            locals: vec![Lua50Local {
                name: "x".to_string(),
                start_pc: 0,
                end_pc: 10,
            }],
            upvalue_names: vec!["_ENV".to_string()],
        }
    }

    /// Total number of instructions in this proto and all nested protos.
    #[must_use]
    pub fn total_instructions(&self) -> usize {
        self.code.len()
            + self
                .protos
                .iter()
                .map(|p| p.total_instructions())
                .sum::<usize>()
    }

    /// Collect all string constants recursively.
    #[must_use]
    pub fn all_strings(&self) -> Vec<&str> {
        let mut result: Vec<&str> = self.constants.iter().filter_map(|c| c.as_str()).collect();
        for p in &self.protos {
            result.extend(p.all_strings());
        }
        result
    }

    /// Return the source line for instruction at `pc`.
    #[must_use]
    pub fn source_line(&self, pc: usize) -> Option<u32> {
        self.line_info.get(pc).copied()
    }

    /// Count constants by type.
    #[must_use]
    pub fn constant_type_counts(&self) -> HashMap<&'static str, usize> {
        let mut m: HashMap<&'static str, usize> = HashMap::new();
        for c in &self.constants {
            let k = match c {
                Lua50Const::Nil => "nil",
                Lua50Const::Number(_) => "number",
                Lua50Const::String(_) => "string",
            };
            *m.entry(k).or_insert(0) += 1;
        }
        m
    }
}

impl fmt::Display for Lua50Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Lua50Proto '{}' params={} vararg={} instrs={} consts={} protos={}",
            self.source.as_deref().unwrap_or("?"),
            self.num_params,
            self.is_vararg,
            self.code.len(),
            self.constants.len(),
            self.protos.len(),
        )
    }
}

// ─── Byte-level reader ────────────────────────────────────────────────────────

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    little_endian: bool,
    int_size: u8,
    size_t_size: u8,
    number_size: u8,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], hdr: &Lua50Header) -> Self {
        Self {
            data,
            pos: 0,
            little_endian: hdr.little_endian,
            int_size: hdr.int_size,
            size_t_size: hdr.size_t_size,
            number_size: hdr.number_size,
        }
    }

    fn read_u8(&mut self) -> Option<u8> {
        if self.pos < self.data.len() {
            let b = self.data[self.pos];
            self.pos += 1;
            Some(b)
        } else {
            None
        }
    }

    fn read_u32(&mut self) -> Option<u32> {
        if self.pos + 4 > self.data.len() {
            return None;
        }
        let b: [u8; 4] = self.data[self.pos..self.pos + 4].try_into().ok()?;
        self.pos += 4;
        Some(if self.little_endian {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }

    fn read_int(&mut self) -> Option<u64> {
        match self.int_size {
            1 => self.read_u8().map(|b| b as u64),
            2 => {
                if self.pos + 2 > self.data.len() {
                    return None;
                }
                let b: [u8; 2] = self.data[self.pos..self.pos + 2].try_into().ok()?;
                self.pos += 2;
                Some(if self.little_endian {
                    u16::from_le_bytes(b)
                } else {
                    u16::from_be_bytes(b)
                } as u64)
            }
            4 => self.read_u32().map(|v| v as u64),
            8 => {
                if self.pos + 8 > self.data.len() {
                    return None;
                }
                let b: [u8; 8] = self.data[self.pos..self.pos + 8].try_into().ok()?;
                self.pos += 8;
                Some(if self.little_endian {
                    u64::from_le_bytes(b)
                } else {
                    u64::from_be_bytes(b)
                })
            }
            _ => None,
        }
    }

    fn read_size_t(&mut self) -> Option<usize> {
        let saved_int = self.int_size;
        self.int_size = self.size_t_size;
        let v = self.read_int();
        self.int_size = saved_int;
        v.map(|n| n as usize)
    }

    fn read_number(&mut self) -> Option<f64> {
        if self.number_size == 8 {
            if self.pos + 8 > self.data.len() {
                return None;
            }
            let b: [u8; 8] = self.data[self.pos..self.pos + 8].try_into().ok()?;
            self.pos += 8;
            Some(f64::from_bits(if self.little_endian {
                u64::from_le_bytes(b)
            } else {
                u64::from_be_bytes(b)
            }))
        } else if self.number_size == 4 {
            if self.pos + 4 > self.data.len() {
                return None;
            }
            let b: [u8; 4] = self.data[self.pos..self.pos + 4].try_into().ok()?;
            self.pos += 4;
            Some(f32::from_bits(if self.little_endian {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }) as f64)
        } else {
            None
        }
    }

    fn read_string(&mut self) -> Option<Option<String>> {
        let slen = self.read_size_t()?;
        if slen == 0 {
            return Some(None);
        }
        if self.pos + slen > self.data.len() {
            return None;
        }
        let raw = &self.data[self.pos..self.pos + slen];
        self.pos += slen;
        // Strip trailing NUL.
        let without_nul = if raw.ends_with(&[0]) {
            &raw[..raw.len() - 1]
        } else {
            raw
        };
        Some(Some(String::from_utf8_lossy(without_nul).into_owned()))
    }
}

// ─── Prototype parser ─────────────────────────────────────────────────────────

/// Parse a Lua 5.0 prototype from a `Reader`.
fn parse_proto_50_reader(r: &mut Reader<'_>) -> Option<Lua50Proto> {
    // Source name (string)
    let source = r.read_string()?;

    // line_defined, num_upvalues, num_params, is_vararg, max_stack
    let line_defined = r.read_int()? as u32;
    let num_upvalues = r.read_u8()?;
    let num_params = r.read_u8()?;
    let is_vararg = r.read_u8()? != 0;
    let max_stack = r.read_u8()?;

    // Code
    let code_size = r.read_int()? as usize;
    let mut code = Vec::with_capacity(code_size);
    for _ in 0..code_size {
        let w = r.read_u32()?;
        code.push(Lua50Instr(w));
    }

    // Constants
    let kst_count = r.read_int()? as usize;
    let mut constants = Vec::with_capacity(kst_count);
    for _ in 0..kst_count {
        let tag = r.read_u8()?;
        let kst = match tag {
            Lua50Const::TAG_NIL => Lua50Const::Nil,
            Lua50Const::TAG_NUMBER => Lua50Const::Number(r.read_number()?),
            Lua50Const::TAG_STRING => {
                let s = r.read_string()?.unwrap_or_default();
                Lua50Const::String(s)
            }
            _ => Lua50Const::Nil,
        };
        constants.push(kst);
    }

    // Source-line info
    let li_count = r.read_int()? as usize;
    let mut line_info = Vec::with_capacity(li_count);
    for _ in 0..li_count {
        line_info.push(r.read_int()? as u32);
    }

    // Locals
    let loc_count = r.read_int()? as usize;
    let mut locals = Vec::with_capacity(loc_count);
    for _ in 0..loc_count {
        let lname = r.read_string()?.unwrap_or_default();
        let start_pc = r.read_int()? as u32;
        let end_pc = r.read_int()? as u32;
        locals.push(Lua50Local {
            name: lname,
            start_pc,
            end_pc,
        });
    }

    // Upvalue names (before inner protos in 5.0)
    let uv_count = r.read_int()? as usize;
    let mut upvalue_names = Vec::with_capacity(uv_count);
    for _ in 0..uv_count {
        let name = r.read_string()?.unwrap_or_default();
        upvalue_names.push(name);
    }

    // Inner protos
    let proto_count = r.read_int()? as usize;
    let mut protos = Vec::with_capacity(proto_count);
    for _ in 0..proto_count {
        protos.push(parse_proto_50_reader(r)?);
    }

    Some(Lua50Proto {
        source,
        line_defined,
        num_upvalues,
        num_params,
        is_vararg,
        max_stack,
        code,
        constants,
        protos,
        line_info,
        locals,
        upvalue_names,
    })
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Decode a Lua 5.0 prototype from `data` starting at `*offset`.
///
/// The caller is responsible for verifying the Lua 5.0 header before calling
/// this function.  `*offset` is advanced past all consumed bytes.
///
/// # Errors
/// Returns `Err(&'static str)` if parsing fails due to truncated data.
pub fn decode_lua50_proto(
    data: &[u8],
    offset: &mut usize,
    hdr: &Lua50Header,
) -> Result<Lua50Proto, &'static str> {
    let mut r = Reader::new(&data[*offset..], hdr);
    let proto = parse_proto_50_reader(&mut r).ok_or("failed to parse Lua 5.0 prototype")?;
    *offset += r.pos;
    Ok(proto)
}

/// Parse a complete Lua 5.0 bytecode file.
///
/// Returns `(header, top_level_proto)`.
///
/// # Errors
/// Returns `Err(&'static str)` on any parse failure.
pub fn parse_lua50(data: &[u8]) -> Result<(Lua50Header, Lua50Proto), &'static str> {
    let hdr = Lua50Header::parse(data)?;
    let mut offset = Lua50Header::SIZE;
    let proto = decode_lua50_proto(data, &mut offset, &hdr)?;
    Ok((hdr, proto))
}

/// Disassemble a Lua 5.0 prototype into human-readable lines.
///
/// Each line has the format `NNNN: MNEMONIC  operands  ; line N`.
#[must_use]
pub fn disassemble_50(proto: &Lua50Proto) -> Vec<String> {
    let mut lines = Vec::with_capacity(proto.code.len());
    for (pc, &instr) in proto.code.iter().enumerate() {
        let line_comment = proto
            .source_line(pc)
            .map(|l| format!(" ; line {l}"))
            .unwrap_or_default();
        let instr_str = instr.to_string();
        lines.push(format!("{pc:04}: {instr_str:<30}{line_comment}"));
    }
    lines
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn _std_hdr() -> Lua50Header {
        Lua50Header::standard()
    }

    // ── Opcodes ───────────────────────────────────────────────────────────────

    #[test]
    fn opcode_count() {
        assert_eq!(LUA50_OPCODES.len(), 35);
    }

    #[test]
    fn opcode_names_spot_check() {
        assert_eq!(opcode_name_50(op::MOVE), "MOVE");
        assert_eq!(opcode_name_50(op::LOADK), "LOADK");
        assert_eq!(opcode_name_50(op::ADD), "ADD");
        assert_eq!(opcode_name_50(op::RETURN), "RETURN");
        assert_eq!(opcode_name_50(op::CLOSURE), "CLOSURE");
        assert_eq!(opcode_name_50(op::POW), "POW");
        assert_eq!(opcode_name_50(op::TFORPREP), "TFORPREP");
        assert_eq!(opcode_name_50(op::SETLISTO), "SETLISTO");
    }

    #[test]
    fn opcode_out_of_range() {
        assert_eq!(opcode_name_50(0xFF), "UNK");
    }

    #[test]
    fn all_named_opcodes_present() {
        for op in LUA50_OPCODES {
            assert!(!op.is_empty());
        }
    }

    // ── Lua50Instr ────────────────────────────────────────────────────────────

    #[test]
    fn instr_opcode_extraction() {
        // Encode RETURN (27) as opcode in bits 0-5.
        let raw = op::RETURN as u32;
        let instr = Lua50Instr(raw);
        assert_eq!(instr.opcode(), op::RETURN);
        assert_eq!(instr.mnemonic(), "RETURN");
    }

    #[test]
    fn instr_abc_fields() {
        // Build instruction: op=ADD, A=5, B=3, C=4
        let raw = (op::ADD as u32) | (5 << 6) | (4 << 14) | (3 << 23);
        let instr = Lua50Instr(raw);
        assert_eq!(instr.opcode(), op::ADD);
        assert_eq!(instr.a(), 5);
        assert_eq!(instr.b(), 3);
        assert_eq!(instr.c(), 4);
    }

    #[test]
    fn instr_bx() {
        // LOADK A=1 Bx=7
        let bx: u32 = 7;
        let raw = (op::LOADK as u32) | (1 << 6) | (bx << 14);
        let instr = Lua50Instr(raw);
        assert_eq!(instr.bx(), 7);
        assert!(instr.uses_bx());
    }

    #[test]
    fn instr_sbx_zero() {
        // JMP sBx=0  → Bx = 131_071
        let bx: u32 = 131_071;
        let raw = (op::JMP as u32) | (bx << 14);
        let instr = Lua50Instr(raw);
        assert_eq!(instr.sbx(), 0);
        assert!(instr.uses_sbx());
    }

    #[test]
    fn instr_sbx_positive() {
        // JMP sBx=5 → Bx = 131_071+5 = 131_076
        let bx: u32 = 131_076;
        let raw = (op::JMP as u32) | (bx << 14);
        let instr = Lua50Instr(raw);
        assert_eq!(instr.sbx(), 5);
    }

    #[test]
    fn instr_is_jump_jmp() {
        let instr = Lua50Instr(op::JMP as u32);
        assert!(instr.is_jump());
    }

    #[test]
    fn instr_is_jump_add_false() {
        let instr = Lua50Instr(op::ADD as u32);
        assert!(!instr.is_jump());
    }

    #[test]
    fn instr_display_abc() {
        let raw = (op::MOVE as u32) | (1 << 6) | (2 << 23);
        let s = Lua50Instr(raw).to_string();
        assert!(s.contains("MOVE"));
        assert!(s.contains("A=1"));
    }

    // ── Lua50Header ───────────────────────────────────────────────────────────

    #[test]
    fn header_parse_and_roundtrip() {
        let hdr = Lua50Header::standard();
        let bytes = hdr.encode();
        let parsed = Lua50Header::parse(&bytes).unwrap();
        assert_eq!(parsed, hdr);
    }

    #[test]
    fn header_parse_wrong_version() {
        let mut bytes = Lua50Header::standard().encode();
        bytes[4] = 0x51; // Lua 5.1
        let err = Lua50Header::parse(&bytes);
        assert!(err.is_err());
    }

    #[test]
    fn header_parse_wrong_magic() {
        let mut bytes = Lua50Header::standard().encode();
        bytes[0] = 0x00;
        let err = Lua50Header::parse(&bytes);
        assert!(err.is_err());
    }

    #[test]
    fn header_parse_too_short() {
        let err = Lua50Header::parse(&[0u8; 4]);
        assert!(err.is_err());
    }

    #[test]
    fn header_standard_values() {
        let h = Lua50Header::standard();
        assert!(h.little_endian);
        assert_eq!(h.int_size, 4);
        assert_eq!(h.number_size, 8);
        assert!(!h.is_integer_num);
    }

    #[test]
    fn header_display() {
        let h = Lua50Header::standard();
        let s = h.to_string();
        assert!(s.contains("Lua 5.0"));
        assert!(s.contains("LE"));
    }

    // ── Lua50Const ────────────────────────────────────────────────────────────

    #[test]
    fn const_nil_not_string() {
        assert!(!Lua50Const::Nil.is_string());
        assert!(Lua50Const::Nil.as_str().is_none());
    }

    #[test]
    fn const_string_is_string() {
        let c = Lua50Const::String("hello".to_string());
        assert!(c.is_string());
        assert_eq!(c.as_str(), Some("hello"));
    }

    #[test]
    fn const_display() {
        assert_eq!(Lua50Const::Nil.to_string(), "nil");
        assert_eq!(Lua50Const::Number(3.14_f64).to_string(), "3.14");
        assert_eq!(Lua50Const::String("x".to_string()).to_string(), "\"x\"");
    }

    // ── Lua50Proto (mock) ─────────────────────────────────────────────────────

    #[test]
    fn proto_mock_valid() {
        let p = Lua50Proto::mock();
        assert_eq!(p.num_params, 0);
        assert!(p.is_vararg);
        assert!(!p.code.is_empty());
        assert!(!p.constants.is_empty());
    }

    #[test]
    fn proto_all_strings() {
        let p = Lua50Proto::mock();
        let strings = p.all_strings();
        assert!(strings.contains(&"hello"));
    }

    #[test]
    fn proto_total_instructions_no_nested() {
        let p = Lua50Proto::mock();
        assert_eq!(p.total_instructions(), p.code.len());
    }

    #[test]
    fn proto_source_line() {
        let p = Lua50Proto::mock();
        assert!(p.source_line(0).is_some());
        assert!(p.source_line(9999).is_none());
    }

    #[test]
    fn proto_constant_type_counts() {
        let p = Lua50Proto::mock();
        let counts = p.constant_type_counts();
        assert!(counts.contains_key("string"));
        assert!(counts.contains_key("number"));
        assert!(counts.contains_key("nil"));
    }

    #[test]
    fn proto_display() {
        let p = Lua50Proto::mock();
        let s = p.to_string();
        assert!(s.contains("Lua50Proto"));
        assert!(s.contains("test50.lua"));
    }

    // ── parse_lua50 (round-trip) ──────────────────────────────────────────────

    fn build_minimal_lua50() -> Vec<u8> {
        let hdr = Lua50Header::standard();
        let mut v = hdr.encode();

        let write_int = |v: &mut Vec<u8>, n: u32| v.extend_from_slice(&n.to_le_bytes());
        let write_u8 = |v: &mut Vec<u8>, b: u8| v.push(b);
        let write_string_nul = |v: &mut Vec<u8>, s: &str| {
            let bytes = s.as_bytes();
            let len = (bytes.len() + 1) as u32;
            v.extend_from_slice(&len.to_le_bytes()); // size_t (4 bytes)
            v.extend_from_slice(bytes);
            v.push(0); // NUL
        };
        let _write_empty_string = |v: &mut Vec<u8>| {
            v.extend_from_slice(&0u32.to_le_bytes()); // size_t = 0 → nil
        };

        // source name
        write_string_nul(&mut v, "@test.lua");
        // line_defined
        write_int(&mut v, 0);
        // num_upvalues
        write_u8(&mut v, 0);
        // num_params
        write_u8(&mut v, 0);
        // is_vararg
        write_u8(&mut v, 1);
        // max_stack
        write_u8(&mut v, 2);
        // code: 1 instruction (RETURN)
        write_int(&mut v, 1);
        let ret_instr: u32 = op::RETURN as u32 | (1 << 23);
        v.extend_from_slice(&ret_instr.to_le_bytes());
        // constants: 0
        write_int(&mut v, 0);
        // line info: 1
        write_int(&mut v, 1);
        write_int(&mut v, 1); // line 1
        // locals: 0
        write_int(&mut v, 0);
        // upvalue names: 0
        write_int(&mut v, 0);
        // inner protos: 0
        write_int(&mut v, 0);

        v
    }

    #[test]
    fn parse_lua50_minimal_roundtrip() {
        let data = build_minimal_lua50();
        let (hdr, proto) = parse_lua50(&data).unwrap();
        assert_eq!(hdr.version(), LUA50_VERSION);
        assert_eq!(proto.code.len(), 1);
        assert_eq!(proto.code[0].mnemonic(), "RETURN");
    }

    #[test]
    fn parse_lua50_source_name() {
        let data = build_minimal_lua50();
        let (_hdr, proto) = parse_lua50(&data).unwrap();
        assert_eq!(proto.source.as_deref(), Some("@test.lua"));
    }

    #[test]
    fn parse_lua50_line_info() {
        let data = build_minimal_lua50();
        let (_hdr, proto) = parse_lua50(&data).unwrap();
        assert_eq!(proto.line_info, vec![1]);
    }

    // ── disassemble_50 ────────────────────────────────────────────────────────

    #[test]
    fn disassemble_50_basic() {
        let p = Lua50Proto::mock();
        let lines = disassemble_50(&p);
        assert_eq!(lines.len(), p.code.len());
        assert!(lines[0].contains("0000:"));
    }

    #[test]
    fn disassemble_50_line_annotation() {
        let p = Lua50Proto::mock();
        let lines = disassemble_50(&p);
        // The mock has line_info = [1], so first instruction should have "; line 1"
        assert!(lines[0].contains("line 1"));
    }
}

impl Lua50Header {
    /// Return the version byte (always `0x50`).
    #[must_use]
    pub fn version(&self) -> u8 {
        LUA50_VERSION
    }
}
