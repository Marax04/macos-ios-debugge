//! Full WebAssembly binary format parser — all section types, LEB128, full module model.
//!
//! This module provides a standalone, zero-dependency WebAssembly 1.0 + extensions
//! binary parser that produces a rich `ParsedWasmModule` with all section data
//! decoded and cross-linked.

use std::collections::HashMap;

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("invalid magic bytes at offset {0}")]
    InvalidMagic(usize),
    #[error("unsupported version {0}")]
    UnsupportedVersion(u32),
    #[error("LEB128 overflow at offset {0}")]
    Leb128Overflow(usize),
    #[error("unexpected end of input at offset {0}")]
    UnexpectedEof(usize),
    #[error("invalid UTF-8 in name at offset {0}")]
    InvalidUtf8(usize),
    #[error("unknown section id {0} at offset {1}")]
    UnknownSection(u8, usize),
    #[error("section too large: {0} bytes")]
    SectionTooLarge(u32),
    #[error("invalid value type 0x{0:02X} at offset {1}")]
    InvalidValType(u8, usize),
    #[error("invalid import kind 0x{0:02X} at offset {1}")]
    InvalidImportKind(u8, usize),
    #[error("invalid export kind 0x{0:02X} at offset {1}")]
    InvalidExportKind(u8, usize),
}

const MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];
const VERSION: u32 = 1;
const MAX_SECTION: u32 = 512 * 1024 * 1024;

// ── LEB128 reader ─────────────────────────────────────────────────────────────

/// Cursor-based LEB128 / raw-byte reader over a byte slice.
pub struct Reader<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self { Self { data, pos: 0 } }
    #[must_use]
    pub const fn new_at(data: &'a [u8], pos: usize) -> Self { Self { data, pos } }
    #[must_use]
    pub const fn remaining(&self) -> usize { self.data.len().saturating_sub(self.pos) }
    #[must_use]
    pub const fn is_done(&self) -> bool { self.pos >= self.data.len() }

    pub fn byte(&mut self) -> Result<u8, ParseError> {
        self.data.get(self.pos).copied().ok_or(ParseError::UnexpectedEof(self.pos))
            .inspect(|_b| { self.pos += 1; })
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let end = self.pos.checked_add(n).ok_or(ParseError::UnexpectedEof(self.pos))?;
        if end > self.data.len() { return Err(ParseError::UnexpectedEof(self.pos)); }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn u32_leb(&mut self) -> Result<u32, ParseError> {
        let mut v = 0u32; let mut shift = 0u32;
        loop {
            let b = self.byte()?;
            v |= u32::from(b & 0x7F) << shift;
            if b & 0x80 == 0 { break; }
            shift += 7;
            if shift >= 35 { return Err(ParseError::Leb128Overflow(self.pos)); }
        }
        Ok(v)
    }

    pub fn i32_leb(&mut self) -> Result<i32, ParseError> {
        let mut v = 0i32; let mut shift = 0u32; let last;
        loop {
            let b = self.byte()?;
            v |= i32::from(b & 0x7F) << shift;
            shift += 7;
            if b & 0x80 == 0 { last = b; break; }
            if shift >= 35 { return Err(ParseError::Leb128Overflow(self.pos)); }
        }
        if shift < 32 && (last & 0x40) != 0 { v |= -(1i32 << shift); }
        Ok(v)
    }

    pub fn u64_leb(&mut self) -> Result<u64, ParseError> {
        let mut v = 0u64; let mut shift = 0u32;
        loop {
            let b = self.byte()?;
            v |= u64::from(b & 0x7F) << shift;
            if b & 0x80 == 0 { break; }
            shift += 7;
            if shift >= 70 { return Err(ParseError::Leb128Overflow(self.pos)); }
        }
        Ok(v)
    }

    pub fn i64_leb(&mut self) -> Result<i64, ParseError> {
        let mut v = 0i64; let mut shift = 0u32; let last;
        loop {
            let b = self.byte()?;
            v |= i64::from(b & 0x7F) << shift;
            shift += 7;
            if b & 0x80 == 0 { last = b; break; }
            if shift >= 70 { return Err(ParseError::Leb128Overflow(self.pos)); }
        }
        if shift < 64 && (last & 0x40) != 0 { v |= -(1i64 << shift); }
        Ok(v)
    }

    pub fn f32_raw(&mut self) -> Result<f32, ParseError> {
        let b = self.bytes(4)?;
        Ok(f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn f64_raw(&mut self) -> Result<f64, ParseError> {
        let b = self.bytes(8)?;
        Ok(f64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    pub fn name(&mut self) -> Result<String, ParseError> {
        let len = self.u32_leb()? as usize;
        let b = self.bytes(len)?;
        std::str::from_utf8(b).map(str::to_owned).map_err(|_| ParseError::InvalidUtf8(self.pos))
    }
}

// ── Value types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValType { I32, I64, F32, F64, V128, FuncRef, ExternRef }

impl ValType {
    pub const fn from_byte(b: u8, pos: usize) -> Result<Self, ParseError> {
        match b {
            0x7F => Ok(Self::I32), 0x7E => Ok(Self::I64),
            0x7D => Ok(Self::F32), 0x7C => Ok(Self::F64),
            0x7B => Ok(Self::V128), 0x70 => Ok(Self::FuncRef), 0x6F => Ok(Self::ExternRef),
            _ => Err(ParseError::InvalidValType(b, pos)),
        }
    }
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self { Self::I32 => "i32", Self::I64 => "i64", Self::F32 => "f32",
            Self::F64 => "f64", Self::V128 => "v128", Self::FuncRef => "funcref",
            Self::ExternRef => "externref" }
    }
    #[must_use]
    pub const fn byte_size(self) -> usize {
        match self { Self::I32 | Self::F32 => 4, Self::I64 | Self::F64 => 8,
            Self::V128 => 16, Self::FuncRef | Self::ExternRef => 0 }
    }
}

impl std::fmt::Display for ValType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.name()) }
}

// ── Limits / table / global types ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct Limits { pub min: u32, pub max: Option<u32> }

impl Limits {
    pub fn parse(r: &mut Reader<'_>) -> Result<Self, ParseError> {
        let flag = r.byte()?;
        let min = r.u32_leb()?;
        let max = if flag & 1 != 0 { Some(r.u32_leb()?) } else { None };
        Ok(Self { min, max })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TableType { pub elem_type: ValType, pub limits: Limits }
#[derive(Debug, Clone, Copy)]
pub struct MemType { pub limits: Limits }
#[derive(Debug, Clone, Copy)]
pub struct GlobalType { pub val_type: ValType, pub mutable: bool }

// ── Function type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FuncType { pub params: Vec<ValType>, pub results: Vec<ValType> }

impl std::fmt::Display for FuncType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(")?;
        for (i, p) in self.params.iter().enumerate() {
            if i > 0 { write!(f, ", ")?; }
            write!(f, "{p}")?;
        }
        write!(f, ") -> (")?;
        for (i, r) in self.results.iter().enumerate() {
            if i > 0 { write!(f, ", ")?; }
            write!(f, "{r}")?;
        }
        write!(f, ")")
    }
}

// ── Import / export ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ImportDesc { Func(u32), Table(TableType), Mem(MemType), Global(GlobalType) }

#[derive(Debug, Clone)]
pub struct Import { pub module: String, pub name: String, pub desc: ImportDesc }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportDesc { Func(u32), Table(u32), Mem(u32), Global(u32) }

#[derive(Debug, Clone)]
pub struct Export { pub name: String, pub desc: ExportDesc }

// ── Element segment ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ElemSegment {
    pub table_index: u32,
    pub offset_expr: Vec<u8>,
    pub func_indices: Vec<u32>,
}

// ── Code entry ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LocalDecl { pub count: u32, pub ty: ValType }

#[derive(Debug, Clone)]
pub struct CodeEntry {
    pub locals: Vec<LocalDecl>,
    pub code: Vec<u8>,
    pub file_offset: usize,
    pub body_size: usize,
}

impl CodeEntry {
    #[must_use]
    pub fn total_locals(&self) -> u32 {
        self.locals.iter().map(|l| l.count).fold(0, u32::saturating_add)
    }
}

// ── Data segment ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum DataSegmentMode {
    Active { memory_index: u32, offset_expr: Vec<u8> },
    Passive,
    ActiveWithMemory { memory_index: u32, offset_expr: Vec<u8> },
}

#[derive(Debug, Clone)]
pub struct DataSegment {
    pub mode: DataSegmentMode,
    pub data: Vec<u8>,
}

// ── Custom section ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CustomSection { pub name: String, pub data: Vec<u8> }

impl CustomSection {
    #[must_use] pub fn is_name(&self) -> bool { self.name == "name" }
    #[must_use] pub fn is_dwarf(&self) -> bool { self.name.starts_with(".debug_") }
    #[must_use] pub fn is_producers(&self) -> bool { self.name == "producers" }
}

// ── Section index ─────────────────────────────────────────────────────────────

/// Section kind with index for ordered traversal.
#[derive(Debug, Clone)]
pub struct SectionRecord {
    pub id: u8,
    pub file_offset: usize,
    pub payload_offset: usize,
    pub payload_size: usize,
}

// ── Parsed module ─────────────────────────────────────────────────────────────

/// Fully-parsed WebAssembly module.
#[derive(Debug)]
pub struct ParsedWasmModule {
    pub version: u32,
    pub types: Vec<FuncType>,
    pub imports: Vec<Import>,
    /// Type indices for defined functions (from function section).
    pub func_type_indices: Vec<u32>,
    pub tables: Vec<TableType>,
    pub mems: Vec<MemType>,
    pub globals: Vec<(GlobalType, Vec<u8>)>,
    pub exports: Vec<Export>,
    pub start: Option<u32>,
    pub elements: Vec<ElemSegment>,
    pub code: Vec<CodeEntry>,
    pub data: Vec<DataSegment>,
    pub data_count: Option<u32>,
    pub customs: Vec<CustomSection>,
    pub sections: Vec<SectionRecord>,
}

impl ParsedWasmModule {
    /// Number of imported functions.
    #[must_use]
    pub fn import_func_count(&self) -> u32 {
        self.imports.iter().filter(|i| matches!(i.desc, ImportDesc::Func(_))).count() as u32
    }

    /// Total function count (imports + defined).
    #[must_use]
    pub fn total_func_count(&self) -> u32 {
        self.import_func_count() + self.code.len() as u32
    }

    /// Export names for functions.
    #[must_use]
    pub fn exported_func_names(&self) -> Vec<&str> {
        self.exports.iter().filter(|e| matches!(e.desc, ExportDesc::Func(_))).map(|e| e.name.as_str()).collect()
    }

    /// Return the resolved type for a defined function (0-indexed within defined).
    #[must_use]
    pub fn func_type(&self, defined_idx: usize) -> Option<&FuncType> {
        self.func_type_indices.get(defined_idx).and_then(|&ti| self.types.get(ti as usize))
    }

    /// Build a name map: `func_index` → name (from name section or exports).
    #[must_use]
    pub fn build_name_map(&self) -> HashMap<u32, String> {
        let mut map = HashMap::new();
        for exp in &self.exports {
            if let ExportDesc::Func(idx) = exp.desc {
                map.entry(idx).or_insert_with(|| exp.name.clone());
            }
        }
        // Parse name section if present
        if let Some(ns) = self.customs.iter().find(|c| c.is_name()) {
            // The name section payload is binary (LEB128 counts + UTF-8 strings),
            // not pure UTF-8, so no UTF-8 pre-check is needed or correct here.
            let mut r2 = Reader::new(&ns.data);
            // Try to parse subsection 1 (function names)
            while !r2.is_done() {
                let Ok(sub_id) = r2.byte() else { break };
                let Ok(sub_size) = r2.u32_leb() else { break };
                let Ok(sub_data) = r2.bytes(sub_size as usize) else { break };
                if sub_id == 1 {
                    let mut sr = Reader::new(sub_data);
                    if let Ok(count) = sr.u32_leb() {
                        for _ in 0..count {
                            if let (Ok(idx), Ok(name)) = (sr.u32_leb(), sr.name()) {
                                map.insert(idx, name);
                            }
                        }
                    }
                }
            }
        }
        map
    }

    /// Find the code entry for a given function name (via export).
    #[must_use]
    pub fn find_func_by_name(&self, name: &str) -> Option<&CodeEntry> {
        let ifc = self.import_func_count();
        for exp in &self.exports {
            if exp.name == name
                && let ExportDesc::Func(idx) = exp.desc {
                    let local = idx.checked_sub(ifc)?;
                    return self.code.get(local as usize);
                }
        }
        None
    }

    /// Total code bytes across all defined functions.
    #[must_use]
    pub fn total_code_bytes(&self) -> usize {
        self.code.iter().map(|c| c.code.len()).sum()
    }

    /// Total data bytes across all data segments.
    #[must_use]
    pub fn total_data_bytes(&self) -> usize {
        self.data.iter().map(|d| d.data.len()).sum()
    }

    /// Whether the module declares linear memory.
    #[must_use]
    pub fn has_memory(&self) -> bool {
        !self.mems.is_empty()
            || self.imports.iter().any(|i| matches!(i.desc, ImportDesc::Mem(_)))
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parses a raw WebAssembly binary into a `ParsedWasmModule`.
pub struct BinaryParser;

impl BinaryParser {
    /// Parse `bytes` into a `ParsedWasmModule`.
    pub fn parse(bytes: &[u8]) -> Result<ParsedWasmModule, ParseError> {
        if bytes.len() < 8 { return Err(ParseError::InvalidMagic(0)); }
        if bytes[..4] != MAGIC { return Err(ParseError::InvalidMagic(0)); }
        let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if version != VERSION { return Err(ParseError::UnsupportedVersion(version)); }

        let mut m = ParsedWasmModule {
            version, types: Vec::new(), imports: Vec::new(),
            func_type_indices: Vec::new(), tables: Vec::new(),
            mems: Vec::new(), globals: Vec::new(), exports: Vec::new(),
            start: None, elements: Vec::new(), code: Vec::new(),
            data: Vec::new(), data_count: None, customs: Vec::new(),
            sections: Vec::new(),
        };

        let mut pos = 8usize;
        while pos < bytes.len() {
            let section_offset = pos;
            let id = bytes[pos];
            pos += 1;
            let (sec_len, consumed) = Self::read_u32_leb(bytes, pos)?;
            pos += consumed;
            if sec_len > MAX_SECTION { return Err(ParseError::SectionTooLarge(sec_len)); }
            let payload_off = pos;
            let payload_end = pos.checked_add(sec_len as usize)
                .ok_or(ParseError::UnexpectedEof(pos))?;
            if payload_end > bytes.len() { return Err(ParseError::UnexpectedEof(pos)); }
            let payload = &bytes[payload_off..payload_end];

            m.sections.push(SectionRecord { id, file_offset: section_offset, payload_offset: payload_off, payload_size: sec_len as usize });

            match id {
                0 => { m.customs.push(Self::parse_custom(payload)?); }
                1 => { m.types = Self::parse_types(payload)?; }
                2 => { m.imports = Self::parse_imports(payload)?; }
                3 => { m.func_type_indices = Self::parse_functions(payload)?; }
                4 => { m.tables = Self::parse_tables(payload)?; }
                5 => { m.mems = Self::parse_mems(payload)?; }
                6 => { m.globals = Self::parse_globals(payload)?; }
                7 => { m.exports = Self::parse_exports(payload)?; }
                8 => { m.start = Some(Reader::new(payload).u32_leb()?); }
                9 => { m.elements = Self::parse_elements(payload)?; }
                10 => { m.code = Self::parse_code(payload, payload_off)?; }
                11 => { m.data = Self::parse_data(payload)?; }
                12 => { let mut r = Reader::new(payload); m.data_count = Some(r.u32_leb()?); }
                _ => return Err(ParseError::UnknownSection(id, section_offset)),
            }
            pos = payload_end;
        }
        Ok(m)
    }

    fn parse_custom(data: &[u8]) -> Result<CustomSection, ParseError> {
        let mut r = Reader::new(data);
        let name = r.name()?;
        let rest = data[r.pos..].to_vec();
        Ok(CustomSection { name, data: rest })
    }

    fn parse_types(data: &[u8]) -> Result<Vec<FuncType>, ParseError> {
        let mut r = Reader::new(data);
        let n = r.u32_leb()?;
        let mut types = Vec::with_capacity((n as usize).min(r.remaining()));
        for _ in 0..n {
            let tag = r.byte()?;
            if tag != 0x60 { return Err(ParseError::InvalidValType(tag, r.pos)); }
            let pc = r.u32_leb()?;
            let mut params = Vec::with_capacity((pc as usize).min(r.remaining()));
            for _ in 0..pc { let b = r.byte()?; params.push(ValType::from_byte(b, r.pos)?); }
            let rc = r.u32_leb()?;
            let mut results = Vec::with_capacity((rc as usize).min(r.remaining()));
            for _ in 0..rc { let b = r.byte()?; results.push(ValType::from_byte(b, r.pos)?); }
            types.push(FuncType { params, results });
        }
        Ok(types)
    }

    fn parse_imports(data: &[u8]) -> Result<Vec<Import>, ParseError> {
        let mut r = Reader::new(data);
        let n = r.u32_leb()?;
        let mut imports = Vec::with_capacity((n as usize).min(r.remaining()));
        for _ in 0..n {
            let module = r.name()?;
            let name = r.name()?;
            let kind = r.byte()?;
            let desc = match kind {
                0x00 => ImportDesc::Func(r.u32_leb()?),
                0x01 => {
                    let et = r.byte()?;
                    let elem_type = ValType::from_byte(et, r.pos)?;
                    ImportDesc::Table(TableType { elem_type, limits: Limits::parse(&mut r)? })
                }
                0x02 => ImportDesc::Mem(MemType { limits: Limits::parse(&mut r)? }),
                0x03 => {
                    let vt = r.byte()?;
                    let val_type = ValType::from_byte(vt, r.pos)?;
                    let mutable = r.byte()? != 0;
                    ImportDesc::Global(GlobalType { val_type, mutable })
                }
                _ => return Err(ParseError::InvalidImportKind(kind, r.pos)),
            };
            imports.push(Import { module, name, desc });
        }
        Ok(imports)
    }

    fn parse_functions(data: &[u8]) -> Result<Vec<u32>, ParseError> {
        let mut r = Reader::new(data);
        let n = r.u32_leb()?;
        let mut indices = Vec::with_capacity((n as usize).min(r.remaining()));
        for _ in 0..n { indices.push(r.u32_leb()?); }
        Ok(indices)
    }

    fn parse_tables(data: &[u8]) -> Result<Vec<TableType>, ParseError> {
        let mut r = Reader::new(data);
        let n = r.u32_leb()?;
        let mut tables = Vec::with_capacity((n as usize).min(r.remaining()));
        for _ in 0..n {
            let et = r.byte()?;
            let elem_type = ValType::from_byte(et, r.pos)?;
            tables.push(TableType { elem_type, limits: Limits::parse(&mut r)? });
        }
        Ok(tables)
    }

    fn parse_mems(data: &[u8]) -> Result<Vec<MemType>, ParseError> {
        let mut r = Reader::new(data);
        let n = r.u32_leb()?;
        let mut mems = Vec::with_capacity((n as usize).min(r.remaining()));
        for _ in 0..n { mems.push(MemType { limits: Limits::parse(&mut r)? }); }
        Ok(mems)
    }

    fn parse_globals(data: &[u8]) -> Result<Vec<(GlobalType, Vec<u8>)>, ParseError> {
        let mut r = Reader::new(data);
        let n = r.u32_leb()?;
        let mut globals = Vec::with_capacity((n as usize).min(r.remaining()));
        for _ in 0..n {
            let vt = r.byte()?;
            let val_type = ValType::from_byte(vt, r.pos)?;
            let mutable = r.byte()? != 0;
            let init = Self::read_const_expr(&mut r)?;
            globals.push((GlobalType { val_type, mutable }, init));
        }
        Ok(globals)
    }

    fn parse_exports(data: &[u8]) -> Result<Vec<Export>, ParseError> {
        let mut r = Reader::new(data);
        let n = r.u32_leb()?;
        let mut exports = Vec::with_capacity((n as usize).min(r.remaining()));
        for _ in 0..n {
            let name = r.name()?;
            let kind = r.byte()?;
            let idx = r.u32_leb()?;
            let desc = match kind {
                0x00 => ExportDesc::Func(idx),
                0x01 => ExportDesc::Table(idx),
                0x02 => ExportDesc::Mem(idx),
                0x03 => ExportDesc::Global(idx),
                _ => return Err(ParseError::InvalidExportKind(kind, r.pos)),
            };
            exports.push(Export { name, desc });
        }
        Ok(exports)
    }

    fn parse_elements(data: &[u8]) -> Result<Vec<ElemSegment>, ParseError> {
        let mut r = Reader::new(data);
        let n = r.u32_leb()?;
        let mut elems = Vec::with_capacity((n as usize).min(r.remaining()));
        for _ in 0..n {
            // Wasm 1.0: table index, offset expr, func indices
            let table_index = r.u32_leb()?;
            let offset_expr = Self::read_const_expr(&mut r)?;
            let count = r.u32_leb()?;
            let mut func_indices = Vec::with_capacity((count as usize).min(r.remaining()));
            for _ in 0..count { func_indices.push(r.u32_leb()?); }
            elems.push(ElemSegment { table_index, offset_expr, func_indices });
        }
        Ok(elems)
    }

    fn parse_code(data: &[u8], payload_base: usize) -> Result<Vec<CodeEntry>, ParseError> {
        let mut r = Reader::new(data);
        let n = r.u32_leb()?;
        let mut entries = Vec::with_capacity((n as usize).min(r.remaining()));
        for _ in 0..n {
            let file_offset = payload_base + r.pos;
            let body_size = r.u32_leb()? as usize;
            let body = r.bytes(body_size)?;
            let mut br = Reader::new(body);
            let lc = br.u32_leb()?;
            let mut locals = Vec::with_capacity((lc as usize).min(br.remaining()));
            for _ in 0..lc {
                let count = br.u32_leb()?;
                let vt = br.byte()?;
                let ty = ValType::from_byte(vt, br.pos)?;
                locals.push(LocalDecl { count, ty });
            }
            let code = body[br.pos..].to_vec();
            entries.push(CodeEntry { locals, code, file_offset, body_size });
        }
        Ok(entries)
    }

    fn parse_data(data: &[u8]) -> Result<Vec<DataSegment>, ParseError> {
        let mut r = Reader::new(data);
        let n = r.u32_leb()?;
        let mut segs = Vec::with_capacity((n as usize).min(r.remaining()));
        for _ in 0..n {
            // Wasm 1.0: memory index + offset expr + data
            let memory_index = r.u32_leb()?;
            let offset_expr = Self::read_const_expr(&mut r)?;
            let len = r.u32_leb()? as usize;
            let d = r.bytes(len)?.to_vec();
            segs.push(DataSegment {
                mode: DataSegmentMode::Active { memory_index, offset_expr },
                data: d,
            });
        }
        Ok(segs)
    }

    fn read_const_expr(r: &mut Reader<'_>) -> Result<Vec<u8>, ParseError> {
        // A naive byte-scan for 0x0B is incorrect: a LEB128 immediate whose value
        // happens to equal 11 (0x0B) would terminate the scan prematurely, leaving
        // the stream misaligned for all subsequent parsing.  Instead, dispatch on
        // the leading opcode to consume its typed immediate, then require the `end`
        // opcode (0x0B) explicitly.
        let start = r.pos;
        let opcode = r.byte()?;
        match opcode {
            0x41 => { r.i32_leb()?; }  // i32.const
            0x42 => { r.u64_leb()?; }  // i64.const
            0x43 => { r.bytes(4)?; }   // f32.const
            0x44 => { r.bytes(8)?; }   // f64.const
            0x23 => { r.u32_leb()?; }  // global.get
            0xD0 => { r.byte()?; }     // ref.null
            0xD2 => { r.u32_leb()?; }  // ref.func
            // Unknown opcode: fall back to consuming raw bytes until 0x0B.
            // A malformed stream with no 0x0B will be caught by the EOF error from r.byte().
            _ => {
                loop {
                    let b = r.byte()?;
                    if b == 0x0B { break; }
                }
                return Ok(r.data[start..r.pos].to_vec());
            }
        }
        // Consume the mandatory `end` (0x0B) opcode.
        let end_byte = r.byte()?;
        if end_byte != 0x0B {
            return Err(ParseError::UnexpectedEof(r.pos));
        }
        Ok(r.data[start..r.pos].to_vec())
    }

    fn read_u32_leb(data: &[u8], pos: usize) -> Result<(u32, usize), ParseError> {
        let mut v = 0u32; let mut shift = 0u32; let mut i = pos;
        loop {
            let b = data.get(i).copied().ok_or(ParseError::UnexpectedEof(i))?;
            i += 1;
            v |= u32::from(b & 0x7F) << shift;
            if b & 0x80 == 0 { break; }
            shift += 7;
            if shift >= 35 { return Err(ParseError::Leb128Overflow(i)); }
        }
        Ok((v, i - pos))
    }
}

// ── Section info ──────────────────────────────────────────────────────────────

/// Human-readable name for a section id.
#[must_use]
pub const fn section_name(id: u8) -> &'static str {
    match id {
        0 => "custom", 1 => "type", 2 => "import", 3 => "function",
        4 => "table", 5 => "memory", 6 => "global", 7 => "export",
        8 => "start", 9 => "element", 10 => "code", 11 => "data",
        12 => "data_count", _ => "unknown",
    }
}

/// Minimal valid Wasm binary: magic + version + empty body.
#[must_use]
pub fn minimal_wasm() -> Vec<u8> {
    vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]
}

/// Build a minimal Wasm module with a single exported `add(i32,i32)->i32` function.
#[must_use]
pub fn simple_add_wasm() -> Vec<u8> {
    // Manually encoded minimal module:
    // (module (func $add (param i32 i32) (result i32) local.get 0 local.get 1 i32.add) (export "add" (func 0)))
    vec![
        0x00, 0x61, 0x73, 0x6D, // magic
        0x01, 0x00, 0x00, 0x00, // version
        // type section
        0x01, 0x07, 0x01, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,
        // function section
        0x03, 0x02, 0x01, 0x00,
        // export section
        0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
        // code section
        0x0A, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6A, 0x0B,
    ]
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_wasm() {
        let m = BinaryParser::parse(&minimal_wasm()).unwrap();
        assert_eq!(m.version, 1);
        assert_eq!(m.total_func_count(), 0);
    }

    #[test]
    fn parse_simple_add() {
        let wasm = simple_add_wasm();
        let m = BinaryParser::parse(&wasm).unwrap();
        assert_eq!(m.types.len(), 1);
        assert_eq!(m.code.len(), 1);
        assert_eq!(m.exports.len(), 1);
        assert_eq!(m.exports[0].name, "add");
        assert!(matches!(m.exports[0].desc, ExportDesc::Func(0)));
    }

    #[test]
    fn parse_func_type_display() {
        let ft = FuncType { params: vec![ValType::I32, ValType::I64], results: vec![ValType::F32] };
        let s = ft.to_string();
        assert!(s.contains("i32"));
        assert!(s.contains("i64"));
        assert!(s.contains("f32"));
    }

    #[test]
    fn reader_u32_leb_single_byte() {
        let mut r = Reader::new(&[42]);
        assert_eq!(r.u32_leb().unwrap(), 42);
    }

    #[test]
    fn reader_u32_leb_multi_byte() {
        // 300 = 0x12C → LEB128: 0xAC 0x02
        let mut r = Reader::new(&[0xAC, 0x02]);
        assert_eq!(r.u32_leb().unwrap(), 300);
    }

    #[test]
    fn reader_i32_leb_negative() {
        // -1 → 0x7F in sleb128
        let mut r = Reader::new(&[0x7F]);
        assert_eq!(r.i32_leb().unwrap(), -1);
    }

    #[test]
    fn reader_name() {
        // length-prefixed "hello"
        let data = [5u8, b'h', b'e', b'l', b'l', b'o'];
        let mut r = Reader::new(&data);
        assert_eq!(r.name().unwrap(), "hello");
    }

    #[test]
    fn invalid_magic() {
        assert!(matches!(BinaryParser::parse(&[0x00, 0x00, 0x00, 0x00]), Err(ParseError::InvalidMagic(_))));
    }

    #[test]
    fn unsupported_version() {
        let mut wasm = minimal_wasm();
        wasm[4] = 0x02; // version 2
        assert!(matches!(BinaryParser::parse(&wasm), Err(ParseError::UnsupportedVersion(2))));
    }

    #[test]
    fn val_type_names() {
        assert_eq!(ValType::I32.name(), "i32");
        assert_eq!(ValType::V128.name(), "v128");
        assert_eq!(ValType::FuncRef.name(), "funcref");
    }

    #[test]
    fn val_type_byte_sizes() {
        assert_eq!(ValType::I32.byte_size(), 4);
        assert_eq!(ValType::I64.byte_size(), 8);
        assert_eq!(ValType::V128.byte_size(), 16);
        assert_eq!(ValType::FuncRef.byte_size(), 0);
    }

    #[test]
    fn section_name_lookup() {
        assert_eq!(section_name(1), "type");
        assert_eq!(section_name(10), "code");
        assert_eq!(section_name(0), "custom");
        assert_eq!(section_name(255), "unknown");
    }

    #[test]
    fn module_has_memory_false() {
        let m = BinaryParser::parse(&minimal_wasm()).unwrap();
        assert!(!m.has_memory());
    }

    #[test]
    fn parse_section_records() {
        let wasm = simple_add_wasm();
        let m = BinaryParser::parse(&wasm).unwrap();
        // Should have type(1), function(3), export(7), code(10) sections
        let ids: Vec<u8> = m.sections.iter().map(|s| s.id).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&10));
    }
}
