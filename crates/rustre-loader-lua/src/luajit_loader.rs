// luajit_loader.rs — LuaJIT 2.0/2.1 bytecode loader.
// Detects LuaJIT format (BCDUMP header), parses proto tree, constants,
// upvalues, debug info, and loads the result into a flat analysis structure.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

// ── Magic / Header constants ──────────────────────────────────────────────────

const BCDUMP_HEAD1: u8 = 0x1B; // ESC
const BCDUMP_HEAD2: u8 = b'L';
const BCDUMP_HEAD3: u8 = b'J';
const BCDUMP_VERSION_20: u8 = 1; // LuaJIT 2.0
const BCDUMP_VERSION_21: u8 = 2; // LuaJIT 2.1

// BCDUMP flags
const BCDUMP_F_BE: u8 = 0x01;     // big-endian
const BCDUMP_F_STRIP: u8 = 0x02;  // no debug info
const BCDUMP_F_FFI: u8 = 0x04;    // FFI use

// Proto flags
pub const PROTO_F_VARARG: u8 = 0x02;
pub const PROTO_F_FFI: u8 = 0x04;
pub const PROTO_F_NOJIT: u8 = 0x08;
pub const PROTO_F_ILOOP: u8 = 0x10;

/// Returns `true` if the proto flag byte indicates a JIT-blocked interpreter loop.
#[must_use]
pub fn proto_has_iloop(flags: u8) -> bool {
    flags & PROTO_F_ILOOP != 0
}

// KGC types
pub const KGC_CHILD: u8 = 0;
pub const KGC_TAB: u8 = 1;
pub const KGC_I64: u8 = 2;
pub const KGC_U64: u8 = 3;
pub const KGC_COMPLEX: u8 = 4;
pub const KGC_STR: u8 = 5; // and above

/// Returns a textual name for a KGC tag byte (used for diagnostics).
#[must_use]
pub fn kgc_tag_name(tag: u8) -> &'static str {
    match tag {
        KGC_CHILD => "child",
        KGC_TAB => "tab",
        KGC_I64 => "i64",
        KGC_U64 => "u64",
        KGC_COMPLEX => "complex",
        t if t >= KGC_STR => "str",
        _ => "unknown",
    }
}

// KTAB sub-types
pub const KTAB_NIL: u8 = 0;
pub const KTAB_FALSE: u8 = 1;
pub const KTAB_TRUE: u8 = 2;
pub const KTAB_INT: u8 = 3;
pub const KTAB_NUM: u8 = 4;
pub const KTAB_STR: u8 = 5;

/// Returns a textual name for a KTAB sub-type tag byte.
#[must_use]
pub fn ktab_tag_name(tag: u8) -> &'static str {
    match tag {
        KTAB_NIL => "nil",
        KTAB_FALSE => "false",
        KTAB_TRUE => "true",
        KTAB_INT => "int",
        KTAB_NUM => "num",
        KTAB_STR => "str",
        _ => "unknown",
    }
}

// ── LuaJIT version ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LuaJitVersion {
    V20,
    V21,
}

impl LuaJitVersion {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V20 => "LuaJIT 2.0",
            Self::V21 => "LuaJIT 2.1",
        }
    }
}

// ── Dump Header ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcDumpHeader {
    pub version: LuaJitVersion,
    pub flags: u8,
    pub is_big_endian: bool,
    pub is_stripped: bool,
    pub has_ffi: bool,
    pub chunk_name: Option<String>,
}

impl BcDumpHeader {
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 3 {
            bail!("Too short for BCDUMP header");
        }
        if data[0] != BCDUMP_HEAD1 || data[1] != BCDUMP_HEAD2 || data[2] != BCDUMP_HEAD3 {
            bail!(
                "Not a LuaJIT bytecode file: magic {:02X} {:02X} {:02X}",
                data[0],
                data[1],
                data[2]
            );
        }
        let version = match data.get(3).copied() {
            Some(BCDUMP_VERSION_20) => LuaJitVersion::V20,
            Some(BCDUMP_VERSION_21) => LuaJitVersion::V21,
            Some(v) => bail!("Unknown LuaJIT version byte: {}", v),
            None => bail!("Truncated BCDUMP header at version"),
        };
        let flags = data.get(4).copied().unwrap_or(0);
        let is_big_endian = (flags & BCDUMP_F_BE) != 0;
        let is_stripped = (flags & BCDUMP_F_STRIP) != 0;
        let has_ffi = (flags & BCDUMP_F_FFI) != 0;

        let mut pos = 5;
        let chunk_name = if !is_stripped {
            let name_len = read_uleb128(data, &mut pos)? as usize;
            if pos + name_len > data.len() {
                bail!("Chunk name truncated");
            }
            let name = std::str::from_utf8(&data[pos..pos + name_len])
                .unwrap_or("<invalid>")
                .to_owned();
            pos += name_len;
            Some(name)
        } else {
            None
        };

        Ok((
            BcDumpHeader {
                version,
                flags,
                is_big_endian,
                is_stripped,
                has_ffi,
                chunk_name,
            },
            pos,
        ))
    }
}

// ── LuaJIT Instructions ───────────────────────────────────────────────────────

/// A single LuaJIT instruction is 4 bytes: op(8) a(8) b(8)/cd(16)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct JitInstr {
    pub op: u8,
    pub a: u8,
    pub b: u8,
    pub c: u8,
    pub d: u16, // b<<8 | c (or cd as 16-bit)
    pub raw: u32,
}

impl JitInstr {
    fn from_u32_le(word: u32) -> Self {
        let op = (word & 0xFF) as u8;
        let a = ((word >> 8) & 0xFF) as u8;
        let d = ((word >> 16) & 0xFFFF) as u16;
        let c = (d & 0xFF) as u8;
        let b = ((d >> 8) & 0xFF) as u8;
        JitInstr { op, a, b, c, d, raw: word }
    }

    fn from_u32_be(word: u32) -> Self {
        let op = ((word >> 24) & 0xFF) as u8;
        let a = ((word >> 16) & 0xFF) as u8;
        let d = (word & 0xFFFF) as u16;
        let c = (d & 0xFF) as u8;
        let b = ((d >> 8) & 0xFF) as u8;
        JitInstr { op, a, b, c, d, raw: word }
    }

    /// Return the signed jump offset (d - BCBIAS_J).
    #[must_use]
    pub fn jump_offset(self) -> i32 {
        const BCBIAS_J: i32 = 0x8000;
        self.d as i32 - BCBIAS_J
    }
}

// ── GC Constants ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KgcConst {
    ChildProto(u32),  // index into proto array
    Table(Vec<KTabEntry>),
    Int64(i64),
    Uint64(u64),
    Complex { re: f64, im: f64 },
    Str(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KTabEntry {
    Nil,
    False,
    True,
    Int(i32),
    Num(f64),
    Str(String),
}

// ── Numeric Constants ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KNumConst {
    Int(i32),
    Num(f64),
}

// ── Proto (function prototype) ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitProto {
    pub id: u32,
    pub parent_id: Option<u32>,
    pub flags: u8,
    pub num_params: u8,
    pub frame_size: u8,
    pub num_upvalues: u8,
    pub num_kgc: u32,
    pub num_kn: u32,
    pub num_bc: u32,
    pub debug_size: u32,
    pub first_line: u32,
    pub num_lines: u32,
    pub instructions: Vec<JitInstr>,
    pub kgc: Vec<KgcConst>,
    pub knum: Vec<KNumConst>,
    pub upvalues: Vec<UpvalDescriptor>,
    pub debug_varnames: Vec<VarInfo>,
    pub debug_upval_names: Vec<String>,
    pub name: Option<String>, // from debug or chunk name
    pub children: Vec<u32>,   // child proto IDs
}

impl JitProto {
    #[must_use]
    pub fn is_vararg(&self) -> bool {
        self.flags & PROTO_F_VARARG != 0
    }

    #[must_use]
    pub fn has_ffi(&self) -> bool {
        self.flags & PROTO_F_FFI != 0
    }

    #[must_use]
    pub fn is_jit_disabled(&self) -> bool {
        self.flags & PROTO_F_NOJIT != 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpvalDescriptor {
    pub on_stack: bool,
    pub idx: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarInfo {
    pub name: String,
    pub start_pc: u32,
    pub end_pc: u32,
}

// ── Full dump ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitDump {
    pub header: BcDumpHeader,
    pub protos: Vec<JitProto>,
    pub root_proto_id: Option<u32>,
}

impl JitDump {
    #[must_use]
    pub fn root_proto(&self) -> Option<&JitProto> {
        self.root_proto_id
            .and_then(|id| self.protos.get(id as usize))
    }

    #[must_use]
    pub fn proto_by_id(&self, id: u32) -> Option<&JitProto> {
        self.protos.get(id as usize)
    }

    #[must_use]
    pub fn all_strings(&self) -> Vec<&str> {
        let mut strings = Vec::new();
        for proto in &self.protos {
            for kgc in &proto.kgc {
                if let KgcConst::Str(s) = kgc {
                    strings.push(s.as_str());
                }
            }
        }
        strings
    }

    #[must_use]
    pub fn stats(&self) -> JitDumpStats {
        let total_instructions: usize = self.protos.iter().map(|p| p.num_bc as usize).sum();
        let total_strings: usize = self
            .protos
            .iter()
            .flat_map(|p| p.kgc.iter())
            .filter(|k| matches!(k, KgcConst::Str(_)))
            .count();
        JitDumpStats {
            num_protos: self.protos.len(),
            total_instructions,
            total_strings,
            version: self.header.version,
            is_stripped: self.header.is_stripped,
            has_ffi: self.header.has_ffi,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitDumpStats {
    pub num_protos: usize,
    pub total_instructions: usize,
    pub total_strings: usize,
    pub version: LuaJitVersion,
    pub is_stripped: bool,
    pub has_ffi: bool,
}

// ── Parser ────────────────────────────────────────────────────────────────────

pub struct LuaJitLoader<'a> {
    data: &'a [u8],
    pos: usize,
    big_endian: bool,
    proto_counter: u32,
}

impl<'a> LuaJitLoader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            big_endian: false,
            proto_counter: 0,
        }
    }

    pub fn load(&mut self) -> Result<JitDump> {
        let (header, hdr_end) = BcDumpHeader::parse(self.data)?;
        self.pos = hdr_end;
        self.big_endian = header.is_big_endian;

        let mut protos: Vec<JitProto> = Vec::new();
        let stack: Vec<u32> = Vec::new(); // parent proto IDs

        loop {
            let len = read_uleb128(self.data, &mut self.pos)? as usize;
            if len == 0 {
                break; // sentinel
            }
            if self.pos + len > self.data.len() {
                bail!("Proto extends past end of file");
            }

            let proto_data = &self.data[self.pos..self.pos + len];
            let id = self.proto_counter;
            let parent_id = stack.last().copied();

            let proto = self.parse_proto(proto_data, id, parent_id, &header)?;

            // Track children relationship
            if let Some(pid) = parent_id {
                if let Some(parent) = protos.get_mut(pid as usize) {
                    parent.children.push(id);
                }
            }

            protos.push(proto);
            self.proto_counter += 1;
            self.pos += len;

            // For simplicity, treat each proto as standalone (no nested push)
            // In a full implementation, we'd push/pop based on FNEW instructions
        }

        let root_proto_id = protos
            .iter()
            .enumerate()
            .filter(|(_, p)| p.parent_id.is_none())
            .map(|(i, _)| i as u32)
            .last();

        Ok(JitDump { header, protos, root_proto_id })
    }

    fn parse_proto(
        &self,
        data: &[u8],
        id: u32,
        parent_id: Option<u32>,
        header: &BcDumpHeader,
    ) -> Result<JitProto> {
        let mut pos = 0;
        let flags = read_byte(data, &mut pos)?;
        let num_params = read_byte(data, &mut pos)?;
        let frame_size = read_byte(data, &mut pos)?;
        let num_upvalues = read_byte(data, &mut pos)?;
        let num_kgc = read_uleb128(data, &mut pos)? as u32;
        let num_kn = read_uleb128(data, &mut pos)? as u32;
        let num_bc = read_uleb128(data, &mut pos)? as u32;
        let debug_size = if !header.is_stripped {
            read_uleb128(data, &mut pos)? as u32
        } else {
            0
        };
        let first_line = if !header.is_stripped {
            read_uleb128(data, &mut pos)? as u32
        } else {
            0
        };
        let num_lines = if !header.is_stripped {
            read_uleb128(data, &mut pos)? as u32
        } else {
            0
        };

        // Instructions
        let mut instructions = Vec::with_capacity(num_bc as usize);
        for _ in 0..num_bc {
            if pos + 4 > data.len() {
                bail!("Instructions truncated");
            }
            let raw = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
            let instr = if self.big_endian {
                JitInstr::from_u32_be(raw.swap_bytes())
            } else {
                JitInstr::from_u32_le(raw)
            };
            instructions.push(instr);
            pos += 4;
        }

        // Upvalue descriptors (2 bytes each)
        let mut upvalues = Vec::with_capacity(num_upvalues as usize);
        for _ in 0..num_upvalues {
            if pos + 2 > data.len() {
                bail!("Upvalue descriptors truncated");
            }
            let uv_data = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
            pos += 2;
            upvalues.push(UpvalDescriptor {
                on_stack: (uv_data & 1) != 0,
                idx: ((uv_data >> 1) & 0xFF) as u8,
            });
        }

        // GC constants (in reverse order, innermost first)
        let mut kgc = Vec::with_capacity(num_kgc as usize);
        for _ in 0..num_kgc {
            kgc.push(self.parse_kgc(data, &mut pos)?);
        }
        kgc.reverse();

        // Numeric constants
        let mut knum = Vec::with_capacity(num_kn as usize);
        for _ in 0..num_kn {
            knum.push(self.parse_knum(data, &mut pos)?);
        }

        // Debug info
        let mut debug_varnames = Vec::new();
        let mut debug_upval_names = Vec::new();
        let mut name = None;

        if !header.is_stripped && debug_size > 0 {
            let debug_end = pos + debug_size as usize;
            // Line numbers: num_bc entries, either 1, 2 or 4 bytes each
            let linepck = if num_lines < 256 { 1usize } else if num_lines < 65536 { 2 } else { 4 };
            let line_bytes = (num_bc as usize).saturating_mul(linepck);
            if pos + line_bytes > debug_end {
                bail!("Debug line info exceeds debug section bounds");
            }
            pos += line_bytes; // skip line info

            // Variable names: "<name>\0<start_pc ULEB><end_pc ULEB>" repeated, empty name = end
            while pos < debug_end {
                let start = pos;
                while pos < debug_end && pos < data.len() && data[pos] != 0 {
                    pos += 1;
                }
                if pos >= debug_end { break; }
                let var_name = std::str::from_utf8(&data[start..pos]).unwrap_or("").to_owned();
                pos += 1; // consume NUL
                if var_name.is_empty() { break; }
                let start_pc = read_uleb128(data, &mut pos).unwrap_or(0) as u32;
                let end_pc = read_uleb128(data, &mut pos).unwrap_or(0) as u32;
                debug_varnames.push(VarInfo { name: var_name, start_pc, end_pc });
            }

            // Upvalue names
            for _ in 0..num_upvalues {
                if pos >= data.len() { break; }
                let start = pos;
                while pos < data.len() && data[pos] != 0 { pos += 1; }
                let uv_name = std::str::from_utf8(&data[start..pos]).unwrap_or("").to_owned();
                if pos < data.len() { pos += 1; }
                debug_upval_names.push(uv_name);
            }
        }

        // Try to get function name from first GGET/GSET or chunk name
        if let Some(KgcConst::Str(s)) = kgc.last() {
            name = Some(s.clone());
        }

        Ok(JitProto {
            id,
            parent_id,
            flags,
            num_params,
            frame_size,
            num_upvalues,
            num_kgc,
            num_kn,
            num_bc,
            debug_size,
            first_line,
            num_lines,
            instructions,
            kgc,
            knum,
            upvalues,
            debug_varnames,
            debug_upval_names,
            name,
            children: Vec::new(),
        })
    }

    fn parse_kgc(&self, data: &[u8], pos: &mut usize) -> Result<KgcConst> {
        let tp = read_uleb128(data, pos)? as u32;
        Ok(match tp {
            0 => KgcConst::ChildProto(0), // placeholder; real child resolution done via FNEW
            1 => KgcConst::Table(self.parse_ktab(data, pos)?),
            2 => {
                let lo = read_uleb128(data, pos)?;
                let hi = read_uleb128(data, pos)?;
                KgcConst::Int64(((hi << 32) | lo) as i64)
            }
            3 => {
                let lo = read_uleb128(data, pos)?;
                let hi = read_uleb128(data, pos)?;
                KgcConst::Uint64((hi << 32) | lo)
            }
            4 => {
                let re = self.parse_num_const(data, pos)?;
                let im = self.parse_num_const(data, pos)?;
                let re_f = if let KNumConst::Num(f) = re { f } else { 0.0 };
                let im_f = if let KNumConst::Num(f) = im { f } else { 0.0 };
                KgcConst::Complex { re: re_f, im: im_f }
            }
            _ => {
                // tp >= 5 means string, length = tp - 5
                let len = (tp - 5) as usize;
                if *pos + len > data.len() {
                    bail!("KGC string truncated");
                }
                let s = std::str::from_utf8(&data[*pos..*pos + len])
                    .unwrap_or("<invalid>")
                    .to_owned();
                *pos += len;
                KgcConst::Str(s)
            }
        })
    }

    fn parse_ktab(&self, data: &[u8], pos: &mut usize) -> Result<Vec<KTabEntry>> {
        let narray = read_uleb128(data, pos)? as usize;
        let nhash = read_uleb128(data, pos)? as usize;
        let mut entries = Vec::with_capacity(narray + nhash * 2);

        for _ in 0..narray {
            entries.push(self.parse_ktab_val(data, pos)?);
        }
        for _ in 0..nhash {
            let _key = self.parse_ktab_val(data, pos)?;
            entries.push(self.parse_ktab_val(data, pos)?);
        }
        Ok(entries)
    }

    fn parse_ktab_val(&self, data: &[u8], pos: &mut usize) -> Result<KTabEntry> {
        // Read the full u64 tag; truncating to u8 would alias e.g. 259 → 3 (KTAB_NUM).
        let tp_raw = read_uleb128(data, pos)?;
        Ok(match tp_raw {
            0 => KTabEntry::Nil,
            1 => KTabEntry::False,
            2 => KTabEntry::True,
            3 => {
                let v = read_uleb128(data, pos)? as i32;
                KTabEntry::Int(v)
            }
            4 => {
                let lo = read_uleb128(data, pos)?;
                let hi = read_uleb128(data, pos)?;
                let bits = (hi << 32) | lo;
                KTabEntry::Num(f64::from_bits(bits))
            }
            tp if tp >= 5 => {
                // tp >= 5 means string, length = tp - 5
                let len = (tp - 5) as usize;
                if *pos + len > data.len() {
                    bail!("KTab string truncated");
                }
                let s = std::str::from_utf8(&data[*pos..*pos + len])
                    .unwrap_or("<invalid>")
                    .to_owned();
                *pos += len;
                KTabEntry::Str(s)
            }
            _ => bail!("KTab unknown type tag"),
        })
    }

    fn parse_knum(&self, data: &[u8], pos: &mut usize) -> Result<KNumConst> {
        self.parse_num_const(data, pos)
    }

    fn parse_num_const(&self, data: &[u8], pos: &mut usize) -> Result<KNumConst> {
        let lo = read_uleb128(data, pos)?;
        if lo & 1 == 0 {
            // integer: lo >> 1
            Ok(KNumConst::Int((lo >> 1) as i32))
        } else {
            // float: hi follows
            let hi = read_uleb128(data, pos)?;
            let bits = ((hi << 32) | (lo >> 1)) as u64;
            Ok(KNumConst::Num(f64::from_bits(bits)))
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn read_uleb128(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() {
            bail!("ULEB128 truncated");
        }
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            bail!("ULEB128 overflow");
        }
    }
    Ok(result)
}

fn read_byte(data: &[u8], pos: &mut usize) -> Result<u8> {
    if *pos >= data.len() {
        bail!("read_byte OOB at {}", *pos);
    }
    let b = data[*pos];
    *pos += 1;
    Ok(b)
}

// ── Top-level entry point ─────────────────────────────────────────────────────

/// Detect whether `data` is a LuaJIT bytecode file.
#[must_use]
pub fn is_luajit_bytecode(data: &[u8]) -> bool {
    data.len() >= 4
        && data[0] == BCDUMP_HEAD1
        && data[1] == BCDUMP_HEAD2
        && data[2] == BCDUMP_HEAD3
        && (data[3] == BCDUMP_VERSION_20 || data[3] == BCDUMP_VERSION_21)
}

/// Load a LuaJIT bytecode file and return the parsed dump.
pub fn load_luajit(data: &[u8]) -> Result<JitDump> {
    let mut loader = LuaJitLoader::new(data);
    loader.load()
}

// ── Opcode names (LuaJIT 2.x) ────────────────────────────────────────────────

/// Return the mnemonic for a LuaJIT 2.x opcode, or "UNKNOWN".
#[must_use]
pub fn opcode_name(op: u8) -> &'static str {
    // LuaJIT 2.x opcodes (ordered by value 0..=92)
    const NAMES: &[&str] = &[
        "ISLT", "ISGE", "ISLE", "ISGT", "ISEQV", "ISNEV", "ISEQS", "ISNES",
        "ISEQN", "ISNEN", "ISEQP", "ISNEP",
        "ISTC", "ISFC", "IST", "ISF", "ISTYPE", "ISNUM",
        "MOV", "NOT", "UNM", "LEN",
        "ADDVN", "SUBVN", "MULVN", "DIVVN", "MODVN",
        "ADDNV", "SUBNV", "MULNV", "DIVNV", "MODNV",
        "ADDVV", "SUBVV", "MULVV", "DIVVV", "MODVV",
        "POW", "CAT",
        "KSTR", "KCDATA", "KSHORT", "KNUM", "KPRI", "KNIL",
        "UGET", "USETV", "USETS", "USETN", "USETP", "UCLO",
        "FNEW",
        "TNEW", "TDUP", "GGET", "GSET",
        "TGETV", "TGETS", "TGETB", "TGETR",
        "TSETV", "TSETS", "TSETB", "TSETM", "TSETR",
        "CALLM", "CALL", "CALLMT", "CALLT",
        "ITERC", "ITERN",
        "VARG",
        "ISNEXT",
        "RETM", "RET", "RET0", "RET1",
        "FORI", "JFORI", "FORL", "IFORL", "JFORL",
        "ITERL", "IITERL", "JITERL",
        "LOOP", "ILOOP", "JLOOP",
        "JMP",
        "FUNCF", "IFUNCF", "JFUNCF",
        "FUNCV", "IFUNCV", "JFUNCV",
        "FUNCC", "FUNCCW",
    ];
    NAMES.get(op as usize).copied().unwrap_or("UNKNOWN")
}

/// Check if an opcode is a call instruction.
#[must_use]
pub fn is_call_op(op: u8) -> bool {
    // CALLM=0x40 CALL=0x41 CALLMT=0x42 CALLT=0x43
    matches!(opcode_name(op), "CALLM" | "CALL" | "CALLMT" | "CALLT")
}

/// Check if an opcode is a return instruction.
#[must_use]
pub fn is_return_op(op: u8) -> bool {
    matches!(opcode_name(op), "RETM" | "RET" | "RET0" | "RET1")
}

/// Check if an opcode is a jump instruction.
#[must_use]
pub fn is_jump_op(op: u8) -> bool {
    matches!(
        opcode_name(op),
        "JMP" | "FORI" | "JFORI" | "FORL" | "IFORL" | "JFORL" |
        "ITERL" | "IITERL" | "JITERL" | "LOOP" | "ILOOP" | "JLOOP" |
        "ISNEXT"
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_not_luajit() {
        let data = b"\x1BLJ\x03something";
        assert!(!is_luajit_bytecode(data));
    }

    #[test]
    fn test_detect_luajit_20() {
        let data = [BCDUMP_HEAD1, BCDUMP_HEAD2, BCDUMP_HEAD3, BCDUMP_VERSION_20, 0x02];
        assert!(is_luajit_bytecode(&data));
    }

    #[test]
    fn test_detect_luajit_21() {
        let data = [BCDUMP_HEAD1, BCDUMP_HEAD2, BCDUMP_HEAD3, BCDUMP_VERSION_21, 0x00];
        assert!(is_luajit_bytecode(&data));
    }

    #[test]
    fn test_opcode_names() {
        assert_eq!(opcode_name(0), "ISLT");
        assert_eq!(opcode_name(255), "UNKNOWN");
    }

    #[test]
    fn test_instr_decode() {
        // op=0x41 (CALL), a=1, d=0x0002
        let raw: u32 = 0x0002_0141;
        let instr = JitInstr::from_u32_le(raw);
        assert_eq!(instr.op, 0x41);
        assert_eq!(instr.a, 1);
        assert_eq!(instr.d, 2);
    }

    #[test]
    fn test_is_call_op() {
        assert!(is_call_op(opcode_name_to_id("CALL").unwrap_or(0x41)));
    }

    #[test]
    fn test_header_bad_magic() {
        let data = b"ELF\x02";
        assert!(BcDumpHeader::parse(data).is_err());
    }

    fn opcode_name_to_id(name: &str) -> Option<u8> {
        (0u8..=255).find(|&i| opcode_name(i) == name)
    }
}
