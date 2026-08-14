// wasm_disassembler.rs — WebAssembly bytecode disassembler
// Decodes raw WASM function body bytes into human-readable text.
// Covers: MVP, sign-extension, bulk-memory, reference-types, SIMD (0xFD prefix).

use std::fmt::Write as FmtWrite;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum DisasmError {
    UnexpectedEof,
    Leb128Overflow,
    InvalidOpcode(u8),
    InvalidSIMDOpcode(u32),
    InvalidBulkOpcode(u32),
    InvalidRefOpcode(u32),
    InvalidMemArgAlign(u32),
    InvalidLaneIndex { lane: u8, max: u8 },
    Utf8Error,
}

impl std::fmt::Display for DisasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of function body"),
            Self::Leb128Overflow => write!(f, "LEB128 integer overflow"),
            Self::InvalidOpcode(b) => write!(f, "invalid opcode 0x{b:02x}"),
            Self::InvalidSIMDOpcode(n) => write!(f, "invalid SIMD sub-opcode {n}"),
            Self::InvalidBulkOpcode(n) => write!(f, "invalid bulk-memory sub-opcode {n}"),
            Self::InvalidRefOpcode(n) => write!(f, "invalid ref sub-opcode {n}"),
            Self::InvalidMemArgAlign(a) => write!(f, "memory arg alignment too large: {a}"),
            Self::InvalidLaneIndex { lane, max } => write!(f, "lane {lane} > max {max}"),
            Self::Utf8Error => write!(f, "invalid UTF-8 in name"),
        }
    }
}

type Res<T> = Result<T, DisasmError>;

// ---------------------------------------------------------------------------
// Cursor
// ---------------------------------------------------------------------------

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(data: &'a [u8]) -> Self { Self { data, pos: 0 } }
    const fn remaining(&self) -> usize { self.data.len() - self.pos }
    const fn is_empty(&self) -> bool { self.pos >= self.data.len() }
    const fn offset(&self) -> usize { self.pos }

    fn byte(&mut self) -> Res<u8> {
        if self.pos >= self.data.len() { return Err(DisasmError::UnexpectedEof); }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn bytes(&mut self, n: usize) -> Res<&'a [u8]> {
        if n > self.remaining() { return Err(DisasmError::UnexpectedEof); }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u32_leb(&mut self) -> Res<u32> {
        let mut result = 0u32;
        let mut shift = 0u32;
        loop {
            let b = self.byte()?;
            let lo = u32::from(b & 0x7F);
            if shift >= 32 { return Err(DisasmError::Leb128Overflow); }
            result |= lo << shift;
            shift += 7;
            if b & 0x80 == 0 { break; }
        }
        Ok(result)
    }

    fn i32_leb(&mut self) -> Res<i32> {
        let mut result = 0i32;
        let mut shift = 0i32;
        loop {
            let b = self.byte()?;
            let lo = i32::from(b & 0x7F);
            if shift >= 32 { return Err(DisasmError::Leb128Overflow); }
            result |= lo << shift;
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 32 && (b & 0x40) != 0 {
                    result |= (-1i32) << shift;
                }
                break;
            }
        }
        Ok(result)
    }

    fn i64_leb(&mut self) -> Res<i64> {
        let mut result = 0i64;
        let mut shift = 0i32;
        loop {
            let b = self.byte()?;
            let lo = i64::from(b & 0x7F);
            if shift >= 64 { return Err(DisasmError::Leb128Overflow); }
            result |= lo << shift;
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && (b & 0x40) != 0 {
                    result |= (-1i64) << shift;
                }
                break;
            }
        }
        Ok(result)
    }

    fn f32_raw(&mut self) -> Res<f32> {
        let b = self.bytes(4)?;
        let bits = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        Ok(f32::from_bits(bits))
    }

    fn f64_raw(&mut self) -> Res<f64> {
        let b = self.bytes(8)?;
        let bits = u64::from_le_bytes([b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]]);
        Ok(f64::from_bits(bits))
    }

    fn mem_arg(&mut self) -> Res<(u32, u32)> {
        let align = self.u32_leb()?;
        let offset = self.u32_leb()?;
        Ok((align, offset))
    }

    fn lane(&mut self) -> Res<u8> { self.byte() }
}

// ---------------------------------------------------------------------------
// Disassembled instruction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Instr {
    pub offset: usize,
    pub text: String,
    pub byte_len: usize,
}

// ---------------------------------------------------------------------------
// Disassembler state
// ---------------------------------------------------------------------------

pub struct Disassembler<'a> {
    data: &'a [u8],
    indent: usize,
    show_offsets: bool,
    show_raw_bytes: bool,
    name_resolver: Option<Box<dyn Fn(u32) -> Option<String> + 'a>>,
}

impl<'a> Disassembler<'a> {
    #[must_use] 
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            indent: 0,
            show_offsets: true,
            show_raw_bytes: false,
            name_resolver: None,
        }
    }

    #[must_use] 
    pub const fn with_offsets(mut self, v: bool) -> Self { self.show_offsets = v; self }
    #[must_use] 
    pub const fn with_raw_bytes(mut self, v: bool) -> Self { self.show_raw_bytes = v; self }
    /// Set the initial indentation level (in spaces) applied to the text
    /// rendering produced by [`Self::to_text`].
    #[must_use] 
    pub const fn with_indent(mut self, indent: usize) -> Self { self.indent = indent; self }
    /// Current initial indentation level.
    #[must_use]
    pub const fn indent(&self) -> usize { self.indent }
    pub fn with_name_resolver<F>(mut self, f: F) -> Self
    where F: Fn(u32) -> Option<String> + 'a
    { self.name_resolver = Some(Box::new(f)); self }

    fn resolve(&self, idx: u32) -> String {
        if let Some(ref nr) = self.name_resolver
            && let Some(name) = nr(idx) {
                return format!("{idx} (; {name} ;)");
            }
        idx.to_string()
    }

    pub fn disassemble(&mut self) -> Result<Vec<Instr>, DisasmError> {
        let mut cur = Cursor::new(self.data);
        let mut out = Vec::new();

        // Skip locals section: count groups, each group is (count:u32, type:u8)
        let local_groups = cur.u32_leb()?;
        for _ in 0..local_groups {
            let cnt = cur.u32_leb()?;
            let ty = cur.byte()?;
            let _ = (cnt, ty);
        }

        while !cur.is_empty() {
            let off = cur.offset();
            let instr = self.decode_one(&mut cur)?;
            let len = cur.offset() - off;
            out.push(Instr { offset: off, text: instr, byte_len: len });
        }
        Ok(out)
    }

    /// Disassemble without locals prefix (raw instruction stream).
    pub fn disassemble_body(&mut self) -> Result<Vec<Instr>, DisasmError> {
        let mut cur = Cursor::new(self.data);
        let mut out = Vec::new();
        while !cur.is_empty() {
            let off = cur.offset();
            let instr = self.decode_one(&mut cur)?;
            let len = cur.offset() - off;
            out.push(Instr { offset: off, text: instr, byte_len: len });
        }
        Ok(out)
    }

    pub fn to_text(&mut self) -> Result<String, DisasmError> {
        let instrs = self.disassemble()?;
        let mut s = String::new();
        let mut indent = self.indent;
        for instr in &instrs {
            let trimmed = instr.text.trim();
            if trimmed == "end" || trimmed == "else" { indent = indent.saturating_sub(2); }
            let prefix = if self.show_offsets {
                format!("{:06x}  ", instr.offset)
            } else { String::new() };
            let _ = writeln!(s, "{prefix}{:indent$}{}", "", trimmed, indent = indent);
            if trimmed.starts_with("block") || trimmed.starts_with("loop")
               || trimmed.starts_with("if") || trimmed == "else" {
                indent += 2;
            }
        }
        Ok(s)
    }

    fn decode_one(&self, cur: &mut Cursor) -> Res<String> {
        let op = cur.byte()?;
        match op {
            0x00 => Ok("unreachable".into()),
            0x01 => Ok("nop".into()),
            0x02 => {
                let bt = Self::block_type(cur)?;
                Ok(format!("block {bt}"))
            }
            0x03 => {
                let bt = Self::block_type(cur)?;
                Ok(format!("loop {bt}"))
            }
            0x04 => {
                let bt = Self::block_type(cur)?;
                Ok(format!("if {bt}"))
            }
            0x05 => Ok("else".into()),
            0x0B => Ok("end".into()),
            0x0C => {
                let l = cur.u32_leb()?;
                Ok(format!("br {l}"))
            }
            0x0D => {
                let l = cur.u32_leb()?;
                Ok(format!("br_if {l}"))
            }
            0x0E => {
                let cnt = cur.u32_leb()?;
                let mut targets = Vec::with_capacity((cnt as usize).min(cur.remaining()));
                for _ in 0..cnt { targets.push(cur.u32_leb()?); }
                let default = cur.u32_leb()?;
                let ts: Vec<_> = targets.iter().map(std::string::ToString::to_string).collect();
                Ok(format!("br_table {} {default}", ts.join(" ")))
            }
            0x0F => Ok("return".into()),
            0x10 => {
                let idx = cur.u32_leb()?;
                Ok(format!("call {}", self.resolve(idx)))
            }
            0x11 => {
                let ti = cur.u32_leb()?;
                let tb = cur.u32_leb()?;
                Ok(format!("call_indirect {ti} {tb}"))
            }
            0x1A => Ok("drop".into()),
            0x1B => Ok("select".into()),
            0x1C => {
                let cnt = cur.u32_leb()?;
                let mut types = Vec::with_capacity((cnt as usize).min(cur.remaining()));
                for _ in 0..cnt { types.push(Self::val_type_name(cur.byte()?)); }
                Ok(format!("select (result {})", types.join(" ")))
            }
            0x20 => { let i = cur.u32_leb()?; Ok(format!("local.get {i}")) }
            0x21 => { let i = cur.u32_leb()?; Ok(format!("local.set {i}")) }
            0x22 => { let i = cur.u32_leb()?; Ok(format!("local.tee {i}")) }
            0x23 => { let i = cur.u32_leb()?; Ok(format!("global.get {i}")) }
            0x24 => { let i = cur.u32_leb()?; Ok(format!("global.set {i}")) }
            0x25 => { let i = cur.u32_leb()?; Ok(format!("table.get {i}")) }
            0x26 => { let i = cur.u32_leb()?; Ok(format!("table.set {i}")) }
            0x28 => { let (a,o) = cur.mem_arg()?; Ok(format!("i32.load align={a} offset={o}")) }
            0x29 => { let (a,o) = cur.mem_arg()?; Ok(format!("i64.load align={a} offset={o}")) }
            0x2A => { let (a,o) = cur.mem_arg()?; Ok(format!("f32.load align={a} offset={o}")) }
            0x2B => { let (a,o) = cur.mem_arg()?; Ok(format!("f64.load align={a} offset={o}")) }
            0x2C => { let (a,o) = cur.mem_arg()?; Ok(format!("i32.load8_s align={a} offset={o}")) }
            0x2D => { let (a,o) = cur.mem_arg()?; Ok(format!("i32.load8_u align={a} offset={o}")) }
            0x2E => { let (a,o) = cur.mem_arg()?; Ok(format!("i32.load16_s align={a} offset={o}")) }
            0x2F => { let (a,o) = cur.mem_arg()?; Ok(format!("i32.load16_u align={a} offset={o}")) }
            0x30 => { let (a,o) = cur.mem_arg()?; Ok(format!("i64.load8_s align={a} offset={o}")) }
            0x31 => { let (a,o) = cur.mem_arg()?; Ok(format!("i64.load8_u align={a} offset={o}")) }
            0x32 => { let (a,o) = cur.mem_arg()?; Ok(format!("i64.load16_s align={a} offset={o}")) }
            0x33 => { let (a,o) = cur.mem_arg()?; Ok(format!("i64.load16_u align={a} offset={o}")) }
            0x34 => { let (a,o) = cur.mem_arg()?; Ok(format!("i64.load32_s align={a} offset={o}")) }
            0x35 => { let (a,o) = cur.mem_arg()?; Ok(format!("i64.load32_u align={a} offset={o}")) }
            0x36 => { let (a,o) = cur.mem_arg()?; Ok(format!("i32.store align={a} offset={o}")) }
            0x37 => { let (a,o) = cur.mem_arg()?; Ok(format!("i64.store align={a} offset={o}")) }
            0x38 => { let (a,o) = cur.mem_arg()?; Ok(format!("f32.store align={a} offset={o}")) }
            0x39 => { let (a,o) = cur.mem_arg()?; Ok(format!("f64.store align={a} offset={o}")) }
            0x3A => { let (a,o) = cur.mem_arg()?; Ok(format!("i32.store8 align={a} offset={o}")) }
            0x3B => { let (a,o) = cur.mem_arg()?; Ok(format!("i32.store16 align={a} offset={o}")) }
            0x3C => { let (a,o) = cur.mem_arg()?; Ok(format!("i64.store8 align={a} offset={o}")) }
            0x3D => { let (a,o) = cur.mem_arg()?; Ok(format!("i64.store16 align={a} offset={o}")) }
            0x3E => { let (a,o) = cur.mem_arg()?; Ok(format!("i64.store32 align={a} offset={o}")) }
            0x3F => { let _m = cur.byte()?; Ok("memory.size".into()) }
            0x40 => { let _m = cur.byte()?; Ok("memory.grow".into()) }
            0x41 => { let v = cur.i32_leb()?; Ok(format!("i32.const {v}")) }
            0x42 => { let v = cur.i64_leb()?; Ok(format!("i64.const {v}")) }
            0x43 => { let v = cur.f32_raw()?; Ok(format!("f32.const {v}")) }
            0x44 => { let v = cur.f64_raw()?; Ok(format!("f64.const {v}")) }
            0x45 => Ok("i32.eqz".into()),
            0x46 => Ok("i32.eq".into()),
            0x47 => Ok("i32.ne".into()),
            0x48 => Ok("i32.lt_s".into()),
            0x49 => Ok("i32.lt_u".into()),
            0x4A => Ok("i32.gt_s".into()),
            0x4B => Ok("i32.gt_u".into()),
            0x4C => Ok("i32.le_s".into()),
            0x4D => Ok("i32.le_u".into()),
            0x4E => Ok("i32.ge_s".into()),
            0x4F => Ok("i32.ge_u".into()),
            0x50 => Ok("i64.eqz".into()),
            0x51 => Ok("i64.eq".into()),
            0x52 => Ok("i64.ne".into()),
            0x53 => Ok("i64.lt_s".into()),
            0x54 => Ok("i64.lt_u".into()),
            0x55 => Ok("i64.gt_s".into()),
            0x56 => Ok("i64.gt_u".into()),
            0x57 => Ok("i64.le_s".into()),
            0x58 => Ok("i64.le_u".into()),
            0x59 => Ok("i64.ge_s".into()),
            0x5A => Ok("i64.ge_u".into()),
            0x5B => Ok("f32.eq".into()),
            0x5C => Ok("f32.ne".into()),
            0x5D => Ok("f32.lt".into()),
            0x5E => Ok("f32.gt".into()),
            0x5F => Ok("f32.le".into()),
            0x60 => Ok("f32.ge".into()),
            0x61 => Ok("f64.eq".into()),
            0x62 => Ok("f64.ne".into()),
            0x63 => Ok("f64.lt".into()),
            0x64 => Ok("f64.gt".into()),
            0x65 => Ok("f64.le".into()),
            0x66 => Ok("f64.ge".into()),
            0x67 => Ok("i32.clz".into()),
            0x68 => Ok("i32.ctz".into()),
            0x69 => Ok("i32.popcnt".into()),
            0x6A => Ok("i32.add".into()),
            0x6B => Ok("i32.sub".into()),
            0x6C => Ok("i32.mul".into()),
            0x6D => Ok("i32.div_s".into()),
            0x6E => Ok("i32.div_u".into()),
            0x6F => Ok("i32.rem_s".into()),
            0x70 => Ok("i32.rem_u".into()),
            0x71 => Ok("i32.and".into()),
            0x72 => Ok("i32.or".into()),
            0x73 => Ok("i32.xor".into()),
            0x74 => Ok("i32.shl".into()),
            0x75 => Ok("i32.shr_s".into()),
            0x76 => Ok("i32.shr_u".into()),
            0x77 => Ok("i32.rotl".into()),
            0x78 => Ok("i32.rotr".into()),
            0x79 => Ok("i64.clz".into()),
            0x7A => Ok("i64.ctz".into()),
            0x7B => Ok("i64.popcnt".into()),
            0x7C => Ok("i64.add".into()),
            0x7D => Ok("i64.sub".into()),
            0x7E => Ok("i64.mul".into()),
            0x7F => Ok("i64.div_s".into()),
            0x80 => Ok("i64.div_u".into()),
            0x81 => Ok("i64.rem_s".into()),
            0x82 => Ok("i64.rem_u".into()),
            0x83 => Ok("i64.and".into()),
            0x84 => Ok("i64.or".into()),
            0x85 => Ok("i64.xor".into()),
            0x86 => Ok("i64.shl".into()),
            0x87 => Ok("i64.shr_s".into()),
            0x88 => Ok("i64.shr_u".into()),
            0x89 => Ok("i64.rotl".into()),
            0x8A => Ok("i64.rotr".into()),
            0x8B => Ok("f32.abs".into()),
            0x8C => Ok("f32.neg".into()),
            0x8D => Ok("f32.ceil".into()),
            0x8E => Ok("f32.floor".into()),
            0x8F => Ok("f32.trunc".into()),
            0x90 => Ok("f32.nearest".into()),
            0x91 => Ok("f32.sqrt".into()),
            0x92 => Ok("f32.add".into()),
            0x93 => Ok("f32.sub".into()),
            0x94 => Ok("f32.mul".into()),
            0x95 => Ok("f32.div".into()),
            0x96 => Ok("f32.min".into()),
            0x97 => Ok("f32.max".into()),
            0x98 => Ok("f32.copysign".into()),
            0x99 => Ok("f64.abs".into()),
            0x9A => Ok("f64.neg".into()),
            0x9B => Ok("f64.ceil".into()),
            0x9C => Ok("f64.floor".into()),
            0x9D => Ok("f64.trunc".into()),
            0x9E => Ok("f64.nearest".into()),
            0x9F => Ok("f64.sqrt".into()),
            0xA0 => Ok("f64.add".into()),
            0xA1 => Ok("f64.sub".into()),
            0xA2 => Ok("f64.mul".into()),
            0xA3 => Ok("f64.div".into()),
            0xA4 => Ok("f64.min".into()),
            0xA5 => Ok("f64.max".into()),
            0xA6 => Ok("f64.copysign".into()),
            0xA7 => Ok("i32.wrap_i64".into()),
            0xA8 => Ok("i32.trunc_f32_s".into()),
            0xA9 => Ok("i32.trunc_f32_u".into()),
            0xAA => Ok("i32.trunc_f64_s".into()),
            0xAB => Ok("i32.trunc_f64_u".into()),
            0xAC => Ok("i64.extend_i32_s".into()),
            0xAD => Ok("i64.extend_i32_u".into()),
            0xAE => Ok("i64.trunc_f32_s".into()),
            0xAF => Ok("i64.trunc_f32_u".into()),
            0xB0 => Ok("i64.trunc_f64_s".into()),
            0xB1 => Ok("i64.trunc_f64_u".into()),
            0xB2 => Ok("f32.convert_i32_s".into()),
            0xB3 => Ok("f32.convert_i32_u".into()),
            0xB4 => Ok("f32.convert_i64_s".into()),
            0xB5 => Ok("f32.convert_i64_u".into()),
            0xB6 => Ok("f32.demote_f64".into()),
            0xB7 => Ok("f64.convert_i32_s".into()),
            0xB8 => Ok("f64.convert_i32_u".into()),
            0xB9 => Ok("f64.convert_i64_s".into()),
            0xBA => Ok("f64.convert_i64_u".into()),
            0xBB => Ok("f64.promote_f32".into()),
            0xBC => Ok("i32.reinterpret_f32".into()),
            0xBD => Ok("i64.reinterpret_f64".into()),
            0xBE => Ok("f32.reinterpret_i32".into()),
            0xBF => Ok("f64.reinterpret_i64".into()),
            // Sign extension
            0xC0 => Ok("i32.extend8_s".into()),
            0xC1 => Ok("i32.extend16_s".into()),
            0xC2 => Ok("i64.extend8_s".into()),
            0xC3 => Ok("i64.extend16_s".into()),
            0xC4 => Ok("i64.extend32_s".into()),
            // Reference types
            0xD0 => {
                let rt = cur.byte()?;
                Ok(format!("ref.null {}", Self::ref_type_name(rt)))
            }
            0xD1 => Ok("ref.is_null".into()),
            0xD2 => {
                let idx = cur.u32_leb()?;
                Ok(format!("ref.func {idx}"))
            }
            // Prefixed opcodes
            0xFC => self.decode_misc(cur),
            0xFD => self.decode_simd(cur),
            0xFE => self.decode_atomic(cur),
            other => Err(DisasmError::InvalidOpcode(other)),
        }
    }

    // 0xFC: miscellaneous bulk-memory / sat-trunc / ref operations
    fn decode_misc(&self, cur: &mut Cursor) -> Res<String> {
        let sub = cur.u32_leb()?;
        match sub {
            0  => Ok("i32.trunc_sat_f32_s".into()),
            1  => Ok("i32.trunc_sat_f32_u".into()),
            2  => Ok("i32.trunc_sat_f64_s".into()),
            3  => Ok("i32.trunc_sat_f64_u".into()),
            4  => Ok("i64.trunc_sat_f32_s".into()),
            5  => Ok("i64.trunc_sat_f32_u".into()),
            6  => Ok("i64.trunc_sat_f64_s".into()),
            7  => Ok("i64.trunc_sat_f64_u".into()),
            8  => { let si = cur.u32_leb()?; let mi = cur.u32_leb()?; Ok(format!("memory.init {si} {mi}")) }
            9  => { let si = cur.u32_leb()?; Ok(format!("data.drop {si}")) }
            10 => { let d = cur.u32_leb()?; let s = cur.u32_leb()?; Ok(format!("memory.copy {d} {s}")) }
            11 => { let mi = cur.u32_leb()?; Ok(format!("memory.fill {mi}")) }
            12 => { let ei = cur.u32_leb()?; let ti = cur.u32_leb()?; Ok(format!("table.init {ei} {ti}")) }
            13 => { let ei = cur.u32_leb()?; Ok(format!("elem.drop {ei}")) }
            14 => { let d = cur.u32_leb()?; let s = cur.u32_leb()?; Ok(format!("table.copy {d} {s}")) }
            15 => { let ti = cur.u32_leb()?; Ok(format!("table.grow {ti}")) }
            16 => { let ti = cur.u32_leb()?; Ok(format!("table.size {ti}")) }
            17 => { let ti = cur.u32_leb()?; Ok(format!("table.fill {ti}")) }
            other => Err(DisasmError::InvalidBulkOpcode(other)),
        }
    }

    // 0xFD: SIMD
    fn decode_simd(&self, cur: &mut Cursor) -> Res<String> {
        let sub = cur.u32_leb()?;
        match sub {
            0  => { let (a,o) = cur.mem_arg()?; Ok(format!("v128.load align={a} offset={o}")) }
            1  => { let (a,o) = cur.mem_arg()?; Ok(format!("v128.load8x8_s align={a} offset={o}")) }
            2  => { let (a,o) = cur.mem_arg()?; Ok(format!("v128.load8x8_u align={a} offset={o}")) }
            3  => { let (a,o) = cur.mem_arg()?; Ok(format!("v128.load16x4_s align={a} offset={o}")) }
            4  => { let (a,o) = cur.mem_arg()?; Ok(format!("v128.load16x4_u align={a} offset={o}")) }
            5  => { let (a,o) = cur.mem_arg()?; Ok(format!("v128.load32x2_s align={a} offset={o}")) }
            6  => { let (a,o) = cur.mem_arg()?; Ok(format!("v128.load32x2_u align={a} offset={o}")) }
            7  => { let (a,o) = cur.mem_arg()?; Ok(format!("v128.load8_splat align={a} offset={o}")) }
            8  => { let (a,o) = cur.mem_arg()?; Ok(format!("v128.load16_splat align={a} offset={o}")) }
            9  => { let (a,o) = cur.mem_arg()?; Ok(format!("v128.load32_splat align={a} offset={o}")) }
            10 => { let (a,o) = cur.mem_arg()?; Ok(format!("v128.load64_splat align={a} offset={o}")) }
            11 => { let (a,o) = cur.mem_arg()?; Ok(format!("v128.store align={a} offset={o}")) }
            12 => {
                let b = cur.bytes(16)?;
                Ok(format!("v128.const 0x{}", hex_bytes(b)))
            }
            13 => {
                let lanes: Vec<u8> = (0..16).map(|_| cur.byte().unwrap_or(0)).collect();
                let ls: Vec<_> = lanes.iter().map(std::string::ToString::to_string).collect();
                Ok(format!("i8x16.shuffle {}", ls.join(" ")))
            }
            14 => Ok("i8x16.swizzle".into()),
            15 => Ok("i8x16.splat".into()),
            16 => Ok("i16x8.splat".into()),
            17 => Ok("i32x4.splat".into()),
            18 => Ok("i64x2.splat".into()),
            19 => Ok("f32x4.splat".into()),
            20 => Ok("f64x2.splat".into()),
            21 => { let l = cur.lane()?; Ok(format!("i8x16.extract_lane_s {l}")) }
            22 => { let l = cur.lane()?; Ok(format!("i8x16.extract_lane_u {l}")) }
            23 => { let l = cur.lane()?; Ok(format!("i8x16.replace_lane {l}")) }
            24 => { let l = cur.lane()?; Ok(format!("i16x8.extract_lane_s {l}")) }
            25 => { let l = cur.lane()?; Ok(format!("i16x8.extract_lane_u {l}")) }
            26 => { let l = cur.lane()?; Ok(format!("i16x8.replace_lane {l}")) }
            27 => { let l = cur.lane()?; Ok(format!("i32x4.extract_lane {l}")) }
            28 => { let l = cur.lane()?; Ok(format!("i32x4.replace_lane {l}")) }
            29 => { let l = cur.lane()?; Ok(format!("i64x2.extract_lane {l}")) }
            30 => { let l = cur.lane()?; Ok(format!("i64x2.replace_lane {l}")) }
            31 => { let l = cur.lane()?; Ok(format!("f32x4.extract_lane {l}")) }
            32 => { let l = cur.lane()?; Ok(format!("f32x4.replace_lane {l}")) }
            33 => { let l = cur.lane()?; Ok(format!("f64x2.extract_lane {l}")) }
            34 => { let l = cur.lane()?; Ok(format!("f64x2.replace_lane {l}")) }
            35 => Ok("i8x16.eq".into()),    36 => Ok("i8x16.ne".into()),
            37 => Ok("i8x16.lt_s".into()),  38 => Ok("i8x16.lt_u".into()),
            39 => Ok("i8x16.gt_s".into()),  40 => Ok("i8x16.gt_u".into()),
            41 => Ok("i8x16.le_s".into()),  42 => Ok("i8x16.le_u".into()),
            43 => Ok("i8x16.ge_s".into()),  44 => Ok("i8x16.ge_u".into()),
            45 => Ok("i16x8.eq".into()),    46 => Ok("i16x8.ne".into()),
            47 => Ok("i16x8.lt_s".into()),  48 => Ok("i16x8.lt_u".into()),
            49 => Ok("i16x8.gt_s".into()),  50 => Ok("i16x8.gt_u".into()),
            51 => Ok("i16x8.le_s".into()),  52 => Ok("i16x8.le_u".into()),
            53 => Ok("i16x8.ge_s".into()),  54 => Ok("i16x8.ge_u".into()),
            55 => Ok("i32x4.eq".into()),    56 => Ok("i32x4.ne".into()),
            57 => Ok("i32x4.lt_s".into()),  58 => Ok("i32x4.lt_u".into()),
            59 => Ok("i32x4.gt_s".into()),  60 => Ok("i32x4.gt_u".into()),
            61 => Ok("i32x4.le_s".into()),  62 => Ok("i32x4.le_u".into()),
            63 => Ok("i32x4.ge_s".into()),  64 => Ok("i32x4.ge_u".into()),
            65 => Ok("f32x4.eq".into()),    66 => Ok("f32x4.ne".into()),
            67 => Ok("f32x4.lt".into()),    68 => Ok("f32x4.gt".into()),
            69 => Ok("f32x4.le".into()),    70 => Ok("f32x4.ge".into()),
            71 => Ok("f64x2.eq".into()),    72 => Ok("f64x2.ne".into()),
            73 => Ok("f64x2.lt".into()),    74 => Ok("f64x2.gt".into()),
            75 => Ok("f64x2.le".into()),    76 => Ok("f64x2.ge".into()),
            77 => Ok("v128.not".into()),
            78 => Ok("v128.and".into()),
            79 => Ok("v128.andnot".into()),
            80 => Ok("v128.or".into()),
            81 => Ok("v128.xor".into()),
            82 => Ok("v128.bitselect".into()),
            83 => Ok("v128.any_true".into()),
            84 => { let (a,o) = cur.mem_arg()?; let l = cur.lane()?; Ok(format!("v128.load8_lane align={a} offset={o} {l}")) }
            85 => { let (a,o) = cur.mem_arg()?; let l = cur.lane()?; Ok(format!("v128.load16_lane align={a} offset={o} {l}")) }
            86 => { let (a,o) = cur.mem_arg()?; let l = cur.lane()?; Ok(format!("v128.load32_lane align={a} offset={o} {l}")) }
            87 => { let (a,o) = cur.mem_arg()?; let l = cur.lane()?; Ok(format!("v128.load64_lane align={a} offset={o} {l}")) }
            88 => { let (a,o) = cur.mem_arg()?; let l = cur.lane()?; Ok(format!("v128.store8_lane align={a} offset={o} {l}")) }
            89 => { let (a,o) = cur.mem_arg()?; let l = cur.lane()?; Ok(format!("v128.store16_lane align={a} offset={o} {l}")) }
            90 => { let (a,o) = cur.mem_arg()?; let l = cur.lane()?; Ok(format!("v128.store32_lane align={a} offset={o} {l}")) }
            91 => { let (a,o) = cur.mem_arg()?; let l = cur.lane()?; Ok(format!("v128.store64_lane align={a} offset={o} {l}")) }
            92 => { let (a,o) = cur.mem_arg()?; Ok(format!("v128.load32_zero align={a} offset={o}")) }
            93 => { let (a,o) = cur.mem_arg()?; Ok(format!("v128.load64_zero align={a} offset={o}")) }
            94 => Ok("f32x4.demote_f64x2_zero".into()),
            95 => Ok("f64x2.promote_low_f32x4".into()),
            96 => Ok("i8x16.abs".into()),   97 => Ok("i8x16.neg".into()),
            98 => Ok("i8x16.popcnt".into()),99 => Ok("i8x16.all_true".into()),
            100 => Ok("i8x16.bitmask".into()),
            101 => Ok("i8x16.narrow_i16x8_s".into()),
            102 => Ok("i8x16.narrow_i16x8_u".into()),
            107 => Ok("i8x16.shl".into()),  108 => Ok("i8x16.shr_s".into()),
            109 => Ok("i8x16.shr_u".into()),110 => Ok("i8x16.add".into()),
            111 => Ok("i8x16.add_sat_s".into()), 112 => Ok("i8x16.add_sat_u".into()),
            113 => Ok("i8x16.sub".into()),
            114 => Ok("i8x16.sub_sat_s".into()), 115 => Ok("i8x16.sub_sat_u".into()),
            118 => Ok("i8x16.min_s".into()), 119 => Ok("i8x16.min_u".into()),
            120 => Ok("i8x16.max_s".into()), 121 => Ok("i8x16.max_u".into()),
            123 => Ok("i8x16.avgr_u".into()),
            124 => Ok("i16x8.extadd_pairwise_i8x16_s".into()),
            125 => Ok("i16x8.extadd_pairwise_i8x16_u".into()),
            128 => Ok("i16x8.abs".into()),  129 => Ok("i16x8.neg".into()),
            130 => Ok("i16x8.q15mulr_sat_s".into()),
            131 => Ok("i16x8.all_true".into()), 132 => Ok("i16x8.bitmask".into()),
            133 => Ok("i16x8.narrow_i32x4_s".into()),
            134 => Ok("i16x8.narrow_i32x4_u".into()),
            135 => Ok("i16x8.extend_low_i8x16_s".into()),
            136 => Ok("i16x8.extend_high_i8x16_s".into()),
            137 => Ok("i16x8.extend_low_i8x16_u".into()),
            138 => Ok("i16x8.extend_high_i8x16_u".into()),
            139 => Ok("i16x8.shl".into()),  140 => Ok("i16x8.shr_s".into()),
            141 => Ok("i16x8.shr_u".into()),142 => Ok("i16x8.add".into()),
            143 => Ok("i16x8.add_sat_s".into()), 144 => Ok("i16x8.add_sat_u".into()),
            145 => Ok("i16x8.sub".into()),
            146 => Ok("i16x8.sub_sat_s".into()), 147 => Ok("i16x8.sub_sat_u".into()),
            149 => Ok("i16x8.mul".into()),
            150 => Ok("i16x8.min_s".into()), 151 => Ok("i16x8.min_u".into()),
            152 => Ok("i16x8.max_s".into()), 153 => Ok("i16x8.max_u".into()),
            155 => Ok("i16x8.avgr_u".into()),
            156 => Ok("i16x8.extmul_low_i8x16_s".into()),
            157 => Ok("i16x8.extmul_high_i8x16_s".into()),
            158 => Ok("i16x8.extmul_low_i8x16_u".into()),
            159 => Ok("i16x8.extmul_high_i8x16_u".into()),
            160 => Ok("i32x4.extadd_pairwise_i16x8_s".into()),
            161 => Ok("i32x4.extadd_pairwise_i16x8_u".into()),
            162 => Ok("i32x4.abs".into()),  163 => Ok("i32x4.neg".into()),
            165 => Ok("i32x4.all_true".into()), 166 => Ok("i32x4.bitmask".into()),
            167 => Ok("i32x4.extend_low_i16x8_s".into()),
            168 => Ok("i32x4.extend_high_i16x8_s".into()),
            169 => Ok("i32x4.extend_low_i16x8_u".into()),
            170 => Ok("i32x4.extend_high_i16x8_u".into()),
            171 => Ok("i32x4.shl".into()),  172 => Ok("i32x4.shr_s".into()),
            173 => Ok("i32x4.shr_u".into()),174 => Ok("i32x4.add".into()),
            177 => Ok("i32x4.sub".into()),
            181 => Ok("i32x4.mul".into()),
            182 => Ok("i32x4.min_s".into()), 183 => Ok("i32x4.min_u".into()),
            184 => Ok("i32x4.max_s".into()), 185 => Ok("i32x4.max_u".into()),
            186 => Ok("i32x4.dot_i16x8_s".into()),
            188 => Ok("i32x4.extmul_low_i16x8_s".into()),
            189 => Ok("i32x4.extmul_high_i16x8_s".into()),
            190 => Ok("i32x4.extmul_low_i16x8_u".into()),
            191 => Ok("i32x4.extmul_high_i16x8_u".into()),
            192 => Ok("i64x2.abs".into()),  193 => Ok("i64x2.neg".into()),
            195 => Ok("i64x2.all_true".into()), 196 => Ok("i64x2.bitmask".into()),
            199 => Ok("i64x2.extend_low_i32x4_s".into()),
            200 => Ok("i64x2.extend_high_i32x4_s".into()),
            201 => Ok("i64x2.extend_low_i32x4_u".into()),
            202 => Ok("i64x2.extend_high_i32x4_u".into()),
            203 => Ok("i64x2.shl".into()),  204 => Ok("i64x2.shr_s".into()),
            205 => Ok("i64x2.shr_u".into()),206 => Ok("i64x2.add".into()),
            209 => Ok("i64x2.sub".into()),
            213 => Ok("i64x2.mul".into()),
            214 => Ok("i64x2.eq".into()),   215 => Ok("i64x2.ne".into()),
            216 => Ok("i64x2.lt_s".into()), 217 => Ok("i64x2.gt_s".into()),
            218 => Ok("i64x2.le_s".into()), 219 => Ok("i64x2.ge_s".into()),
            220 => Ok("i64x2.extmul_low_i32x4_s".into()),
            221 => Ok("i64x2.extmul_high_i32x4_s".into()),
            222 => Ok("i64x2.extmul_low_i32x4_u".into()),
            223 => Ok("i64x2.extmul_high_i32x4_u".into()),
            224 => Ok("f32x4.ceil".into()),  225 => Ok("f32x4.floor".into()),
            226 => Ok("f32x4.trunc".into()), 227 => Ok("f32x4.nearest".into()),
            228 => Ok("f64x2.ceil".into()),  229 => Ok("f64x2.floor".into()),
            230 => Ok("f64x2.trunc".into()), 231 => Ok("f64x2.nearest".into()),
            232 => Ok("f32x4.abs".into()),   233 => Ok("f32x4.neg".into()),
            235 => Ok("f32x4.sqrt".into()),  236 => Ok("f32x4.add".into()),
            237 => Ok("f32x4.sub".into()),   238 => Ok("f32x4.mul".into()),
            239 => Ok("f32x4.div".into()),   240 => Ok("f32x4.min".into()),
            241 => Ok("f32x4.max".into()),   242 => Ok("f32x4.pmin".into()),
            243 => Ok("f32x4.pmax".into()),
            244 => Ok("f64x2.abs".into()),   245 => Ok("f64x2.neg".into()),
            247 => Ok("f64x2.sqrt".into()),  248 => Ok("f64x2.add".into()),
            249 => Ok("f64x2.sub".into()),   250 => Ok("f64x2.mul".into()),
            251 => Ok("f64x2.div".into()),   252 => Ok("f64x2.min".into()),
            253 => Ok("f64x2.max".into()),   254 => Ok("f64x2.pmin".into()),
            255 => Ok("f64x2.pmax".into()),
            256 => Ok("i32x4.trunc_sat_f32x4_s".into()),
            257 => Ok("i32x4.trunc_sat_f32x4_u".into()),
            258 => Ok("f32x4.convert_i32x4_s".into()),
            259 => Ok("f32x4.convert_i32x4_u".into()),
            260 => Ok("i32x4.trunc_sat_f64x2_s_zero".into()),
            261 => Ok("i32x4.trunc_sat_f64x2_u_zero".into()),
            262 => Ok("f64x2.convert_low_i32x4_s".into()),
            263 => Ok("f64x2.convert_low_i32x4_u".into()),
            other => Err(DisasmError::InvalidSIMDOpcode(other)),
        }
    }

    // 0xFE: threads / atomic
    fn decode_atomic(&self, cur: &mut Cursor) -> Res<String> {
        let sub = cur.byte()?;
        let (a, o) = cur.mem_arg()?;
        let name = match sub {
            0x00 => "memory.atomic.notify",
            0x01 => "memory.atomic.wait32",
            0x02 => "memory.atomic.wait64",
            0x10 => "i32.atomic.load",
            0x11 => "i64.atomic.load",
            0x12 => "i32.atomic.load8_u",
            0x13 => "i32.atomic.load16_u",
            0x14 => "i64.atomic.load8_u",
            0x15 => "i64.atomic.load16_u",
            0x16 => "i64.atomic.load32_u",
            0x17 => "i32.atomic.store",
            0x18 => "i64.atomic.store",
            0x19 => "i32.atomic.store8",
            0x1A => "i32.atomic.store16",
            0x1B => "i64.atomic.store8",
            0x1C => "i64.atomic.store16",
            0x1D => "i64.atomic.store32",
            0x1E => "i32.atomic.rmw.add",
            0x1F => "i64.atomic.rmw.add",
            0x20 => "i32.atomic.rmw8.add_u",
            0x21 => "i32.atomic.rmw16.add_u",
            0x22 => "i64.atomic.rmw8.add_u",
            0x23 => "i64.atomic.rmw16.add_u",
            0x24 => "i64.atomic.rmw32.add_u",
            0x25 => "i32.atomic.rmw.sub",
            0x26 => "i64.atomic.rmw.sub",
            0x27 => "i32.atomic.rmw8.sub_u",
            0x28 => "i32.atomic.rmw16.sub_u",
            0x29 => "i64.atomic.rmw8.sub_u",
            0x2A => "i64.atomic.rmw16.sub_u",
            0x2B => "i64.atomic.rmw32.sub_u",
            0x2C => "i32.atomic.rmw.and",
            0x2D => "i64.atomic.rmw.and",
            0x2E => "i32.atomic.rmw8.and_u",
            0x2F => "i32.atomic.rmw16.and_u",
            0x30 => "i64.atomic.rmw8.and_u",
            0x31 => "i64.atomic.rmw16.and_u",
            0x32 => "i64.atomic.rmw32.and_u",
            0x33 => "i32.atomic.rmw.or",
            0x34 => "i64.atomic.rmw.or",
            0x35 => "i32.atomic.rmw8.or_u",
            0x36 => "i32.atomic.rmw16.or_u",
            0x37 => "i64.atomic.rmw8.or_u",
            0x38 => "i64.atomic.rmw16.or_u",
            0x39 => "i64.atomic.rmw32.or_u",
            0x3A => "i32.atomic.rmw.xor",
            0x3B => "i64.atomic.rmw.xor",
            0x3C => "i32.atomic.rmw8.xor_u",
            0x3D => "i32.atomic.rmw16.xor_u",
            0x3E => "i64.atomic.rmw8.xor_u",
            0x3F => "i64.atomic.rmw16.xor_u",
            0x40 => "i64.atomic.rmw32.xor_u",
            0x41 => "i32.atomic.rmw.xchg",
            0x42 => "i64.atomic.rmw.xchg",
            0x43 => "i32.atomic.rmw8.xchg_u",
            0x44 => "i32.atomic.rmw16.xchg_u",
            0x45 => "i64.atomic.rmw8.xchg_u",
            0x46 => "i64.atomic.rmw16.xchg_u",
            0x47 => "i64.atomic.rmw32.xchg_u",
            0x48 => "i32.atomic.rmw.cmpxchg",
            0x49 => "i64.atomic.rmw.cmpxchg",
            0x4A => "i32.atomic.rmw8.cmpxchg_u",
            0x4B => "i32.atomic.rmw16.cmpxchg_u",
            0x4C => "i64.atomic.rmw8.cmpxchg_u",
            0x4D => "i64.atomic.rmw16.cmpxchg_u",
            0x4E => "i64.atomic.rmw32.cmpxchg_u",
            _ => return Ok(format!("atomic.unknown 0x{sub:02x} align={a} offset={o}")),
        };
        Ok(format!("{name} align={a} offset={o}"))
    }

    fn block_type(cur: &mut Cursor) -> Res<String> {
        // Block type is a signed LEB128: 0x40 = void, negative = val type, positive = type index
        let raw = cur.byte()?;
        if raw == 0x40 { return Ok(String::new()); }
        if raw & 0x80 == 0 && raw >= 0x70 {
            return Ok(Self::val_type_name(raw).to_string());
        }
        // Multi-value: decode as s33 LEB128
        let mut result = i64::from(raw & 0x7F);
        if raw & 0x80 != 0 {
            let mut shift = 7i32;
            loop {
                let b = cur.byte()?;
                result |= i64::from(b & 0x7F) << shift;
                shift += 7;
                if b & 0x80 == 0 {
                    if shift < 64 && (b & 0x40) != 0 {
                        result |= (-1i64) << shift;
                    }
                    break;
                }
                if shift > 35 { return Err(DisasmError::Leb128Overflow); }
            }
        }
        if result >= 0 {
            Ok(format!("(type {result})"))
        } else {
            Ok(Self::val_type_name(raw).to_string())
        }
    }

    const fn val_type_name(b: u8) -> &'static str {
        match b {
            0x7F => "i32", 0x7E => "i64", 0x7D => "f32", 0x7C => "f64",
            0x7B => "v128", 0x70 => "funcref", 0x6F => "externref",
            _ => "unknown",
        }
    }

    const fn ref_type_name(b: u8) -> &'static str {
        match b { 0x70 => "func", 0x6F => "extern", _ => "unknown" }
    }
}

fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Convenience top-level functions
// ---------------------------------------------------------------------------

pub fn disassemble_function(data: &[u8]) -> Result<Vec<Instr>, DisasmError> {
    Disassembler::new(data).disassemble()
}

pub fn disassemble_to_text(data: &[u8]) -> Result<String, DisasmError> {
    Disassembler::new(data).to_text()
}

// ---------------------------------------------------------------------------
// DisasmStats — aggregate statistics
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct DisasmStats {
    pub total_instructions: usize,
    pub load_count: usize,
    pub store_count: usize,
    pub call_count: usize,
    pub call_indirect_count: usize,
    pub branch_count: usize,
    pub simd_count: usize,
    pub atomic_count: usize,
    pub memory_ops: usize,
    pub const_count: usize,
}

impl DisasmStats {
    #[must_use] 
    pub fn from_instrs(instrs: &[Instr]) -> Self {
        let mut s = Self::default();
        for i in instrs {
            s.total_instructions += 1;
            let t = &i.text;
            if t.contains(".load") { s.load_count += 1; }
            if t.contains(".store") { s.store_count += 1; }
            if t.starts_with("call_indirect") { s.call_indirect_count += 1; }
            else if t.starts_with("call ") { s.call_count += 1; }
            if t.starts_with("br") || t.starts_with("if") || t.starts_with("return") { s.branch_count += 1; }
            if t.starts_with("v128") || t.contains("x16") || t.contains("x8") || t.contains("x4") || t.contains("x2") { s.simd_count += 1; }
            if t.contains("atomic") { s.atomic_count += 1; }
            if t.starts_with("memory.") || t.starts_with("memory") { s.memory_ops += 1; }
            if t.ends_with(".const") || t.contains(".const ") { s.const_count += 1; }
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn add_body() -> Vec<u8> {
        // locals: 0 groups
        // local.get 0 / local.get 1 / i32.add / end
        vec![
            0x00, // 0 local groups
            0x20, 0x00, // local.get 0
            0x20, 0x01, // local.get 1
            0x6A,       // i32.add
            0x0B,       // end
        ]
    }

    #[test]
    fn test_disassemble_add() {
        let instrs = disassemble_function(&add_body()).unwrap();
        assert_eq!(instrs.len(), 4);
        assert_eq!(instrs[0].text, "local.get 0");
        assert_eq!(instrs[1].text, "local.get 1");
        assert_eq!(instrs[2].text, "i32.add");
        assert_eq!(instrs[3].text, "end");
    }

    #[test]
    fn test_to_text() {
        let text = disassemble_to_text(&add_body()).unwrap();
        assert!(text.contains("i32.add"));
        assert!(text.contains("local.get 0"));
    }

    #[test]
    fn test_stats() {
        let instrs = disassemble_function(&add_body()).unwrap();
        let stats = DisasmStats::from_instrs(&instrs);
        assert_eq!(stats.total_instructions, 4);
    }

    #[test]
    fn test_memory_size_grow() {
        let body = vec![
            0x00,       // 0 locals
            0x3F, 0x00, // memory.size
            0x40, 0x00, // memory.grow
            0x0B,       // end
        ];
        let instrs = disassemble_function(&body).unwrap();
        assert_eq!(instrs[0].text, "memory.size");
        assert_eq!(instrs[1].text, "memory.grow");
    }

    #[test]
    fn test_i32_const() {
        let body = vec![
            0x00,             // 0 locals
            0x41, 0x2A,       // i32.const 42
            0x0B,
        ];
        let instrs = disassemble_function(&body).unwrap();
        assert_eq!(instrs[0].text, "i32.const 42");
    }
}
