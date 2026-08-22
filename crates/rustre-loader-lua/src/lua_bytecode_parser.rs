//! `lua_bytecode_parser` — Binary parser for Lua 5.1/5.2/5.3/5.4 bytecode.
//!
//! Reads the file header, parses the top-level function prototype, and
//! recursively decodes all nested protos, yielding a complete [`LuaChunk`]
//! that represents the entire bytecode file.

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// LuaVersion
// ─────────────────────────────────────────────────────────────────────────────

/// Supported Lua bytecode versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LuaVersion {
    Lua51,
    Lua52,
    Lua53,
    Lua54,
}

impl LuaVersion {
    /// Parse from the version byte in the bytecode header.
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x51 => Some(Self::Lua51),
            0x52 => Some(Self::Lua52),
            0x53 => Some(Self::Lua53),
            0x54 => Some(Self::Lua54),
            _ => None,
        }
    }

    /// Human-readable version string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lua51 => "5.1",
            Self::Lua52 => "5.2",
            Self::Lua53 => "5.3",
            Self::Lua54 => "5.4",
        }
    }

    /// Whether integers in the bytecode file are encoded as 64-bit (5.3+).
    pub const fn uses_integer64(self) -> bool {
        matches!(self, Self::Lua53 | Self::Lua54)
    }

    /// Float constant tag used in constant encoding (`LUA_TNUMBER` / `LUA_TFLT`).
    /// Both old (5.1/5.2) and new (5.3/5.4) encodings use tag value 3 for floats.
    pub const fn float_tag(self) -> u8 {
        3 // LUA_TNUMBER for 5.1/5.2; LUA_TFLT (0x03) for 5.3/5.4 — same value
    }

    /// Integer constant tag used in constant encoding (Lua 5.3+ only: `LUA_TINT` = 0x13).
    /// Returns `None` for Lua 5.1/5.2 which have no native integer constant type.
    pub const fn integer_tag(self) -> Option<u8> {
        match self {
            Self::Lua53 | Self::Lua54 => Some(0x13),
            Self::Lua51 | Self::Lua52 => None,
        }
    }
}

impl fmt::Display for LuaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaConstant
// ─────────────────────────────────────────────────────────────────────────────

/// A constant value stored in a Lua function prototype.
#[derive(Debug, Clone, PartialEq)]
pub enum LuaConstant {
    Nil,
    Boolean(bool),
    /// 64-bit integer (Lua 5.3+ native integer).
    Integer(i64),
    /// Floating-point number.
    Float(f64),
    /// String constant.
    String(String),
    /// Short string (Lua 5.4 tag 0x04).
    ShortString(String),
}

impl LuaConstant {
    /// Returns `true` if this constant is a string of any kind.
    pub const fn is_string(&self) -> bool {
        matches!(self, Self::String(_) | Self::ShortString(_))
    }

    /// Extract the string value regardless of short/long tag.
    pub const fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) | Self::ShortString(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

impl fmt::Display for LuaConstant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nil => write!(f, "nil"),
            Self::Boolean(b) => write!(f, "{b}"),
            Self::Integer(n) => write!(f, "{n}"),
            Self::Float(n) => write!(f, "{n}"),
            Self::String(s) | Self::ShortString(s) => write!(f, "{s:?}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UpvalueDesc
// ─────────────────────────────────────────────────────────────────────────────

/// Descriptor for an upvalue in a Lua function prototype.
#[derive(Debug, Clone)]
pub struct UpvalueDesc {
    /// Upvalue name (from debug info; may be empty if stripped).
    pub name: String,
    /// `in_stack`: 1 if the upvalue is in the immediately enclosing function's
    /// register file, 0 if it is from an outer upvalue list (Lua 5.2+).
    pub in_stack: u8,
    /// Index within the register file or outer upvalue list.
    pub idx: u8,
    /// Upvalue kind (Lua 5.4 only; 0 = regular, 1 = `to_be_closed`).
    pub kind: u8,
}

impl UpvalueDesc {
    /// Construct a simple upvalue descriptor with only index info.
    pub const fn simple(in_stack: u8, idx: u8) -> Self {
        Self { name: String::new(), in_stack, idx, kind: 0 }
    }

    /// Returns `true` if this upvalue is a register-local capture.
    pub const fn is_local_capture(&self) -> bool {
        self.in_stack != 0
    }
}

impl fmt::Display for UpvalueDesc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = if self.name.is_empty() { "<anon>" } else { &self.name };
        write!(f, "{}[in_stack={} idx={}]", name, self.in_stack, self.idx)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LocalVar
// ─────────────────────────────────────────────────────────────────────────────

/// A local variable descriptor from the debug info section of a proto.
#[derive(Debug, Clone)]
pub struct LocalVar {
    /// Variable name.
    pub name: String,
    /// Instruction at which this local becomes live.
    pub start_pc: u32,
    /// Instruction at which this local becomes dead.
    pub end_pc: u32,
}

impl LocalVar {
    /// Returns `true` if `pc` is within the live range of this local.
    pub const fn is_live_at(&self, pc: u32) -> bool {
        pc >= self.start_pc && pc < self.end_pc
    }
}

impl fmt::Display for LocalVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}..{}]", self.name, self.start_pc, self.end_pc)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaProto
// ─────────────────────────────────────────────────────────────────────────────

/// A Lua function prototype, corresponding to a single function body in source.
#[derive(Debug, Clone)]
pub struct LuaProto {
    /// Source file name (may start with `@` for filenames or `=` for literals).
    pub source_name: String,
    /// First line in source where this function is defined.
    pub line_defined: u32,
    /// Last line in source where this function ends.
    pub last_line_defined: u32,
    /// Number of parameters.
    pub num_params: u8,
    /// Whether this function is variadic (`...`).
    pub is_vararg: bool,
    /// Maximum number of registers (stack slots) used.
    pub max_stack: u8,
    /// Raw instruction words.
    pub instructions: Vec<u32>,
    /// Constant pool.
    pub constants: Vec<LuaConstant>,
    /// Upvalue descriptors.
    pub upvalues: Vec<UpvalueDesc>,
    /// Nested function prototypes.
    pub protos: Vec<Self>,
    /// Per-instruction source-line mapping (debug info).
    pub line_info: Vec<u32>,
    /// Local variable descriptors (debug info).
    pub locals: Vec<LocalVar>,
    /// Upvalue names from debug info.
    pub upvalue_names: Vec<String>,
    /// Proto index within the parent (0-based).
    pub proto_index: u32,
}

impl LuaProto {
    /// Create an empty proto.
    pub const fn empty() -> Self {
        Self {
            source_name: String::new(),
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            is_vararg: false,
            max_stack: 2,
            instructions: Vec::new(),
            constants: Vec::new(),
            upvalues: Vec::new(),
            protos: Vec::new(),
            line_info: Vec::new(),
            locals: Vec::new(),
            upvalue_names: Vec::new(),
            proto_index: 0,
        }
    }

    /// Number of instructions.
    pub const fn insn_count(&self) -> usize {
        self.instructions.len()
    }

    /// Recursively count this proto plus all nested protos.
    pub fn total_proto_count(&self) -> usize {
        1 + self.protos.iter().map(Self::total_proto_count).sum::<usize>()
    }

    /// Collect all string constants (including nested protos).
    pub fn all_strings(&self) -> Vec<&str> {
        let mut result: Vec<&str> = self.constants.iter().filter_map(|c| c.as_str()).collect();
        for child in &self.protos {
            result.extend(child.all_strings());
        }
        result
    }

    /// Returns `true` if this proto has debug info (non-empty `line_info`).
    pub const fn has_debug_info(&self) -> bool {
        !self.line_info.is_empty()
    }

    /// Find locals alive at instruction index `pc`.
    pub fn locals_at(&self, pc: u32) -> Vec<&LocalVar> {
        self.locals.iter().filter(|l| l.is_live_at(pc)).collect()
    }

    /// Opcode of instruction at index `i` (bits 0–5 for Lua 5.1–5.3;
    /// bits 0–6 for Lua 5.4).
    pub fn opcode_at(&self, i: usize, version: LuaVersion) -> u8 {
        let insn = self.instructions[i];
        match version {
            LuaVersion::Lua54 => (insn & 0x7F) as u8,
            _ => (insn & 0x3F) as u8,
        }
    }
}

impl fmt::Display for LuaProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let src = if self.source_name.is_empty() { "?" } else { &self.source_name };
        write!(
            f,
            "Proto {}:{}-{} params={} vararg={} insns={} consts={} protos={}",
            src,
            self.line_defined,
            self.last_line_defined,
            self.num_params,
            self.is_vararg,
            self.insn_count(),
            self.constants.len(),
            self.protos.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaChunk (file header + root proto)
// ─────────────────────────────────────────────────────────────────────────────

/// Header of a compiled Lua bytecode file.
#[derive(Debug, Clone)]
pub struct LuaHeader {
    /// Lua version.
    pub version: LuaVersion,
    /// Format (0 = official).
    pub format: u8,
    /// Whether the file is big-endian.
    pub big_endian: bool,
    /// Size of `int` on the compiling platform (bytes).
    pub int_size: u8,
    /// Size of `size_t` on the compiling platform.
    pub size_t_size: u8,
    /// Size of a VM instruction word (always 4).
    pub insn_size: u8,
    /// Size of the Lua number type.
    pub number_size: u8,
    /// Whether the Lua number type is integral (0 = float, 1 = int).
    pub number_integral: bool,
}

impl LuaHeader {
    /// `LUAC_MAGIC` prefix: `\x1bLua`.
    pub const MAGIC: [u8; 4] = [0x1b, 0x4c, 0x75, 0x61];

    /// Validate the magic bytes.
    pub fn check_magic(bytes: &[u8]) -> bool {
        bytes.len() >= 4 && bytes[..4] == Self::MAGIC
    }
}

impl fmt::Display for LuaHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LuaHeader v{} fmt={} be={} int={}B size_t={}B",
            self.version, self.format, self.big_endian, self.int_size, self.size_t_size
        )
    }
}

/// Top-level container for a parsed Lua bytecode file.
#[derive(Debug, Clone)]
pub struct LuaChunk {
    /// File header.
    pub header: LuaHeader,
    /// Top-level (main chunk) function prototype.
    pub main_proto: LuaProto,
    /// Total number of function prototypes (all levels).
    pub total_protos: usize,
    /// Parse warnings accumulated during parsing.
    pub warnings: Vec<String>,
}

impl LuaChunk {
    /// Build a chunk from a header and main proto.
    pub fn new(header: LuaHeader, main_proto: LuaProto) -> Self {
        let total_protos = main_proto.total_proto_count();
        Self { header, main_proto, total_protos, warnings: Vec::new() }
    }

    /// Collect all string constants in the entire chunk.
    pub fn all_strings(&self) -> Vec<&str> {
        self.main_proto.all_strings()
    }
}

impl fmt::Display for LuaChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LuaChunk [{}] protos={} warnings={}",
            self.header,
            self.total_protos,
            self.warnings.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cursor — low-level byte reader
// ─────────────────────────────────────────────────────────────────────────────

/// A simple cursor over a byte slice with big/little endian awareness.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    big_endian: bool,
}

impl<'a> Cursor<'a> {
    const fn new(data: &'a [u8], big_endian: bool) -> Self {
        Cursor { data, pos: 0, big_endian }
    }

    const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, ParseError> {
        if self.pos >= self.data.len() {
            return Err(ParseError::Truncated);
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        // Use checked_add to prevent pos + n from wrapping around on overflow.
        let end = self.pos.checked_add(n).ok_or(ParseError::Truncated)?;
        if end > self.data.len() {
            return Err(ParseError::Truncated);
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn read_u32(&mut self) -> Result<u32, ParseError> {
        let b = self.read_bytes(4)?;
        if self.big_endian {
            Ok(u32::from_be_bytes(b.try_into().unwrap()))
        } else {
            Ok(u32::from_le_bytes(b.try_into().unwrap()))
        }
    }

    fn read_i32(&mut self) -> Result<i32, ParseError> {
        Ok(self.read_u32()? as i32)
    }

    fn read_u64(&mut self) -> Result<u64, ParseError> {
        let b = self.read_bytes(8)?;
        if self.big_endian {
            Ok(u64::from_be_bytes(b.try_into().unwrap()))
        } else {
            Ok(u64::from_le_bytes(b.try_into().unwrap()))
        }
    }

    fn read_i64(&mut self) -> Result<i64, ParseError> {
        Ok(self.read_u64()? as i64)
    }

    fn read_f64(&mut self) -> Result<f64, ParseError> {
        let bits = self.read_u64()?;
        Ok(f64::from_bits(bits))
    }

    fn read_f32(&mut self) -> Result<f64, ParseError> {
        let b = self.read_bytes(4)?;
        let bits = if self.big_endian {
            u32::from_be_bytes(b.try_into().unwrap())
        } else {
            u32::from_le_bytes(b.try_into().unwrap())
        };
        Ok(f32::from_bits(bits) as f64)
    }

    /// Read a size_t-sized integer (platform-specific).
    fn read_size_t(&mut self, size: u8) -> Result<usize, ParseError> {
        match size {
            4 => Ok(self.read_u32()? as usize),
            8 => Ok(self.read_u64()? as usize),
            _ => Err(ParseError::Unsupported(format!("size_t size {size}"))),
        }
    }

    /// Read a platform int (platform-specific).
    fn read_int(&mut self, size: u8) -> Result<i64, ParseError> {
        match size {
            4 => Ok(self.read_i32()? as i64),
            8 => Ok(self.read_i64()?),
            _ => Err(ParseError::Unsupported(format!("int size {size}"))),
        }
    }

    /// Read a Lua string: `size_t` length followed by bytes (or 0 for nil string).
    fn read_lua_string(&mut self, size_t: u8) -> Result<Option<String>, ParseError> {
        let len = self.read_size_t(size_t)?;
        if len == 0 {
            return Ok(None);
        }
        // Guard against adversarial lengths that exceed what remains in the buffer.
        let str_len = len - 1; // Lua strings include NUL in length count
        if str_len > self.remaining() {
            return Err(ParseError::Truncated);
        }
        let bytes = self.read_bytes(str_len)?;
        Ok(Some(String::from_utf8_lossy(bytes).into_owned()))
    }

    /// Read a Lua 5.4 short string: varint length.
    fn read_lua54_string(&mut self) -> Result<Option<String>, ParseError> {
        let b = self.read_u8()?;
        if b == 0 {
            return Ok(None);
        }
        let len = if b == 0xFF {
            let raw = self.read_u64()?;
            // Guard against absurd lengths that cannot fit in memory.
            if raw > 0x0FFF_FFFF {
                return Err(ParseError::Malformed(format!(
                    "Lua 5.4 string length too large: {raw}"
                )));
            }
            raw as usize
        } else {
            b as usize - 1
        };
        if len == 0 {
            return Ok(Some(String::new()));
        }
        let bytes = self.read_bytes(len)?;
        Ok(Some(String::from_utf8_lossy(bytes).into_owned()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ParseError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by [`LuaBytecodeParser`].
#[derive(Debug, Clone)]
pub enum ParseError {
    /// Input was truncated before all data could be read.
    Truncated,
    /// Magic bytes did not match `\x1bLua`.
    BadMagic,
    /// Version byte not recognised.
    UnknownVersion(u8),
    /// A feature is recognised but not yet implemented.
    Unsupported(String),
    /// Generic parse error.
    Malformed(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated data"),
            Self::BadMagic => write!(f, "invalid magic"),
            Self::UnknownVersion(v) => write!(f, "unknown version {v:#04x}"),
            Self::Unsupported(s) => write!(f, "unsupported: {s}"),
            Self::Malformed(s) => write!(f, "malformed: {s}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaBytecodeParser
// ─────────────────────────────────────────────────────────────────────────────

/// Parser for Lua 5.1–5.4 compiled bytecode files.
///
/// Call [`LuaBytecodeParser::parse`] with the raw file bytes.
pub struct LuaBytecodeParser {
    /// Accumulated warnings.
    pub warnings: Vec<String>,
    /// Number of unconsumed trailing bytes after the last `parse()` call.
    /// Useful for detecting malformed or appended-data files.
    pub trailing_bytes: usize,
}

impl LuaBytecodeParser {
    /// Create a new parser.
    pub const fn new() -> Self {
        Self { warnings: Vec::new(), trailing_bytes: 0 }
    }

    /// Number of unconsumed trailing bytes recorded by the last `parse()` call.
    #[must_use]
    pub const fn trailing_bytes(&self) -> usize {
        self.trailing_bytes
    }

    /// Parse `data` and return a [`LuaChunk`].
    pub fn parse(&mut self, data: &[u8]) -> Result<LuaChunk, ParseError> {
        if !LuaHeader::check_magic(data) {
            return Err(ParseError::BadMagic);
        }

        let version_byte = *data.get(4).ok_or(ParseError::Truncated)?;
        let version = LuaVersion::from_byte(version_byte)
            .ok_or(ParseError::UnknownVersion(version_byte))?;

        let header = self.parse_header(data, version)?;
        let big_endian = header.big_endian;
        let int_size = header.int_size;
        let size_t_size = header.size_t_size;
        let number_size = header.number_size;
        let number_integral = header.number_integral;

        // Determine header length.
        let header_len = match version {
            LuaVersion::Lua51 => 12,
            LuaVersion::Lua52 => 18, // includes LUAC_DATA
            LuaVersion::Lua53 => 18,
            LuaVersion::Lua54 => 32,
        };

        if data.len() < header_len {
            return Err(ParseError::Truncated);
        }

        let mut cur = Cursor::new(&data[header_len..], big_endian);

        // Lua 5.4: skip the upvalue count before main proto.
        if version == LuaVersion::Lua54 {
            cur.read_u8()?; // number of upvalues in main chunk
        }

        let main_proto = self.parse_proto(
            &mut cur,
            version,
            int_size,
            size_t_size,
            number_size,
            number_integral,
            0,
        )?;

        self.trailing_bytes = cur.remaining();
        if self.trailing_bytes != 0 {
            self.warnings
                .push(format!("{} trailing bytes after main chunk", self.trailing_bytes));
        }

        let mut chunk = LuaChunk::new(header, main_proto);
        chunk.warnings = self.warnings.clone();
        Ok(chunk)
    }

    fn parse_header(&mut self, data: &[u8], version: LuaVersion) -> Result<LuaHeader, ParseError> {
        // Byte layout (offsets from start):
        // [0..3]  magic
        // [4]     version
        // [5]     format
        // Lua 5.1/5.2/5.3: [6] endian, [7] int_size, [8] size_t, [9] insn_size,
        //                   [10] num_size, [11] num_integral
        // Lua 5.4 has a different layout (LUAC_DATA etc.)
        let get = |i: usize| -> Result<u8, ParseError> {
            data.get(i).copied().ok_or(ParseError::Truncated)
        };
        let format = get(5)?;
        match version {
            LuaVersion::Lua51 | LuaVersion::Lua52 | LuaVersion::Lua53 => {
                let big_endian = get(6)? == 0;
                let int_size = get(7)?;
                let size_t_size = get(8)?;
                let insn_size = get(9)?;
                let number_size = get(10)?;
                let number_integral = get(11)? != 0;
                Ok(LuaHeader {
                    version,
                    format,
                    big_endian,
                    int_size,
                    size_t_size,
                    insn_size,
                    number_size,
                    number_integral,
                })
            }
            LuaVersion::Lua54 => {
                // Lua 5.4: LUAC_DATA at bytes [6..12], then sizes
                // [12] int size, [13] size_t, [14] insn, [15] int type, [16] float type
                let int_size = get(12)?;
                let size_t_size = get(13)?;
                let insn_size = get(14)?;
                Ok(LuaHeader {
                    version,
                    format,
                    big_endian: false, // 5.4 is always LE
                    int_size,
                    size_t_size,
                    insn_size,
                    number_size: 8,
                    number_integral: false,
                })
            }
        }
    }

    fn parse_proto(
        &mut self,
        cur: &mut Cursor<'_>,
        ver: LuaVersion,
        int_size: u8,
        size_t: u8,
        num_size: u8,
        num_int: bool,
        depth: u32,
    ) -> Result<LuaProto, ParseError> {
        let mut proto = LuaProto::empty();
        proto.proto_index = depth;

        // Source name.
        proto.source_name = match ver {
            LuaVersion::Lua54 => cur.read_lua54_string()?.unwrap_or_default(),
            _ => cur.read_lua_string(size_t)?.unwrap_or_default(),
        };

        // Line info.
        proto.line_defined = cur.read_int(int_size)? as u32;
        proto.last_line_defined = cur.read_int(int_size)? as u32;

        // In 5.1 the parameter count byte comes before num_params.
        if ver == LuaVersion::Lua51 {
            let _num_upvalues = cur.read_u8()?; // upvalue count at proto level
        }

        proto.num_params = cur.read_u8()?;
        proto.is_vararg = cur.read_u8()? != 0;
        proto.max_stack = cur.read_u8()?;

        // Instructions.
        let insn_count = {
            let n = cur.read_int(int_size)?;
            if !(0..=0x00FF_FFFF).contains(&n) {
                return Err(ParseError::Malformed(format!("insn_count out of range: {n}")));
            }
            n as usize
        };
        proto.instructions = Vec::with_capacity(insn_count);
        for _ in 0..insn_count {
            proto.instructions.push(cur.read_u32()?);
        }

        // Constants.
        let const_count = {
            let n = cur.read_int(int_size)?;
            if !(0..=0x00FF_FFFF).contains(&n) {
                return Err(ParseError::Malformed(format!("const_count out of range: {n}")));
            }
            n as usize
        };
        proto.constants = Vec::with_capacity(const_count);
        for _ in 0..const_count {
            let c = self.parse_constant(cur, ver, num_size, num_int, size_t)?;
            proto.constants.push(c);
        }

        // Nested protos.
        let proto_count = {
            let n = cur.read_int(int_size)?;
            if !(0..=0x00FF_FFFF).contains(&n) {
                return Err(ParseError::Malformed(format!("proto_count out of range: {n}")));
            }
            n as usize
        };
        proto.protos = Vec::with_capacity(proto_count);
        for i in 0..proto_count {
            let child =
                self.parse_proto(cur, ver, int_size, size_t, num_size, num_int, i as u32)?;
            proto.protos.push(child);
        }

        // Upvalues (Lua 5.2+).
        let uv_count = if ver == LuaVersion::Lua51 {
            // Already read above; upvalue count was embedded.
            0usize
        } else {
            let n = cur.read_int(int_size)?;
            if !(0..=0x0000_FFFF).contains(&n) {
                return Err(ParseError::Malformed(format!("uv_count out of range: {n}")));
            }
            n as usize
        };
        proto.upvalues = Vec::with_capacity(uv_count);
        for _ in 0..uv_count {
            let in_stack = cur.read_u8()?;
            let idx = cur.read_u8()?;
            let kind = if ver == LuaVersion::Lua54 { cur.read_u8()? } else { 0 };
            proto.upvalues.push(UpvalueDesc { name: String::new(), in_stack, idx, kind });
        }

        // Debug info — line positions.
        let line_count = {
            let n = cur.read_int(int_size)?;
            if !(0..=0x00FF_FFFF).contains(&n) {
                return Err(ParseError::Malformed(format!("line_count out of range: {n}")));
            }
            n as usize
        };
        proto.line_info = Vec::with_capacity(line_count);
        for _ in 0..line_count {
            proto.line_info.push(cur.read_int(int_size)? as u32);
        }

        // Debug info — local variables.
        let local_count = {
            let n = cur.read_int(int_size)?;
            if !(0..=0x00FF_FFFF).contains(&n) {
                return Err(ParseError::Malformed(format!("local_count out of range: {n}")));
            }
            n as usize
        };
        proto.locals = Vec::with_capacity(local_count);
        for _ in 0..local_count {
            let name = match ver {
                LuaVersion::Lua54 => cur.read_lua54_string()?.unwrap_or_default(),
                _ => cur.read_lua_string(size_t)?.unwrap_or_default(),
            };
            let start_pc = cur.read_int(int_size)? as u32;
            let end_pc = cur.read_int(int_size)? as u32;
            proto.locals.push(LocalVar { name, start_pc, end_pc });
        }

        // Debug info — upvalue names.
        let uv_name_count = {
            let n = cur.read_int(int_size)?;
            if !(0..=0x0000_FFFF).contains(&n) {
                return Err(ParseError::Malformed(format!("uv_name_count out of range: {n}")));
            }
            n as usize
        };
        proto.upvalue_names = Vec::with_capacity(uv_name_count);
        for i in 0..uv_name_count {
            let name = match ver {
                LuaVersion::Lua54 => cur.read_lua54_string()?.unwrap_or_default(),
                _ => cur.read_lua_string(size_t)?.unwrap_or_default(),
            };
            if let Some(uv) = proto.upvalues.get_mut(i) {
                uv.name = name.clone();
            }
            proto.upvalue_names.push(name);
        }

        Ok(proto)
    }

    fn parse_constant(
        &mut self,
        cur: &mut Cursor<'_>,
        ver: LuaVersion,
        num_size: u8,
        num_int: bool,
        size_t: u8,
    ) -> Result<LuaConstant, ParseError> {
        let tag = cur.read_u8()?;
        match ver {
            LuaVersion::Lua51 | LuaVersion::Lua52 => {
                match tag {
                    0 => Ok(LuaConstant::Nil),
                    1 => Ok(LuaConstant::Boolean(cur.read_u8()? != 0)),
                    3 => {
                        // LUA_TNUMBER — float or integer depending on build.
                        let v = if num_int {
                            LuaConstant::Integer(cur.read_int(num_size)?)
                        } else if num_size == 4 {
                            LuaConstant::Float(cur.read_f32()?)
                        } else {
                            LuaConstant::Float(cur.read_f64()?)
                        };
                        Ok(v)
                    }
                    4 => {
                        let s = cur.read_lua_string(size_t)?.unwrap_or_default();
                        Ok(LuaConstant::String(s))
                    }
                    _ => {
                        self.warnings.push(format!("unknown constant tag {tag:#04x}"));
                        Ok(LuaConstant::Nil)
                    }
                }
            }
            LuaVersion::Lua53 => {
                match tag {
                    0 => Ok(LuaConstant::Nil),
                    1 => Ok(LuaConstant::Boolean(cur.read_u8()? != 0)),
                    3 => Ok(LuaConstant::Float(cur.read_f64()?)),
                    0x13 => Ok(LuaConstant::Integer(cur.read_i64()?)),
                    4 | 0x14 => {
                        let s = cur.read_lua_string(size_t)?.unwrap_or_default();
                        Ok(LuaConstant::String(s))
                    }
                    _ => {
                        self.warnings.push(format!("unknown 5.3 constant tag {tag:#04x}"));
                        Ok(LuaConstant::Nil)
                    }
                }
            }
            LuaVersion::Lua54 => {
                match tag {
                    0 => Ok(LuaConstant::Nil),
                    1 => Ok(LuaConstant::Boolean(false)),
                    17 => Ok(LuaConstant::Boolean(true)),
                    3 => Ok(LuaConstant::Float(cur.read_f64()?)),
                    0x13 => Ok(LuaConstant::Integer(cur.read_i64()?)),
                    4 => {
                        let s = cur.read_lua54_string()?.unwrap_or_default();
                        Ok(LuaConstant::ShortString(s))
                    }
                    0x14 => {
                        let s = cur.read_lua54_string()?.unwrap_or_default();
                        Ok(LuaConstant::String(s))
                    }
                    _ => {
                        self.warnings.push(format!("unknown 5.4 constant tag {tag:#04x}"));
                        Ok(LuaConstant::Nil)
                    }
                }
            }
        }
    }
}

impl Default for LuaBytecodeParser {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lua_version_from_byte() {
        assert_eq!(LuaVersion::from_byte(0x51), Some(LuaVersion::Lua51));
        assert_eq!(LuaVersion::from_byte(0x54), Some(LuaVersion::Lua54));
        assert_eq!(LuaVersion::from_byte(0x99), None);
    }

    #[test]
    fn test_lua_version_integer64() {
        assert!(!LuaVersion::Lua51.uses_integer64());
        assert!(LuaVersion::Lua53.uses_integer64());
        assert!(LuaVersion::Lua54.uses_integer64());
    }

    #[test]
    fn test_lua_constant_is_string() {
        assert!(LuaConstant::String("hi".into()).is_string());
        assert!(LuaConstant::ShortString("x".into()).is_string());
        assert!(!LuaConstant::Nil.is_string());
    }

    #[test]
    fn test_lua_constant_as_str() {
        let c = LuaConstant::String("hello".into());
        assert_eq!(c.as_str(), Some("hello"));
        assert_eq!(LuaConstant::Integer(42).as_str(), None);
    }

    #[test]
    fn test_upvalue_is_local_capture() {
        let uv = UpvalueDesc::simple(1, 3);
        assert!(uv.is_local_capture());
        let uv2 = UpvalueDesc::simple(0, 1);
        assert!(!uv2.is_local_capture());
    }

    #[test]
    fn test_local_var_live_at() {
        let l = LocalVar { name: "x".into(), start_pc: 2, end_pc: 10 };
        assert!(l.is_live_at(5));
        assert!(!l.is_live_at(10));
        assert!(!l.is_live_at(1));
    }

    #[test]
    fn test_proto_total_count() {
        let mut root = LuaProto::empty();
        let child = LuaProto::empty();
        root.protos.push(child);
        assert_eq!(root.total_proto_count(), 2);
    }

    #[test]
    fn test_proto_all_strings() {
        let mut proto = LuaProto::empty();
        proto.constants.push(LuaConstant::String("foo".into()));
        proto.constants.push(LuaConstant::Integer(1));
        proto.constants.push(LuaConstant::String("bar".into()));
        let strings = proto.all_strings();
        assert_eq!(strings, vec!["foo", "bar"]);
    }

    #[test]
    fn test_check_magic() {
        assert!(LuaHeader::check_magic(&[0x1b, 0x4c, 0x75, 0x61, 0x51]));
        assert!(!LuaHeader::check_magic(&[0x00, 0x4c, 0x75, 0x61]));
    }

    #[test]
    fn test_parse_bad_magic() {
        let mut parser = LuaBytecodeParser::new();
        let result = parser.parse(b"not lua");
        assert!(matches!(result, Err(ParseError::BadMagic)));
    }

    #[test]
    fn test_parse_unknown_version() {
        let mut data = vec![0x1b, 0x4c, 0x75, 0x61, 0x99];
        data.extend_from_slice(&[0u8; 20]);
        let mut parser = LuaBytecodeParser::new();
        let result = parser.parse(&data);
        assert!(matches!(result, Err(ParseError::UnknownVersion(0x99))));
    }
}
