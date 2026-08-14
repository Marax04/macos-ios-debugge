//! Full WASM module loader.
//!
//! Provides [`WasmLoader`], [`WasmLoadResult`], and [`WasmRelocator`].

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

pub use std::fmt;

// Re-use the error and LEB128 utilities already defined in lib.rs via a local re-export.
// We define a minimal set here so the file compiles standalone.

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LoaderError {
    #[error("invalid magic bytes")]
    InvalidMagic,
    #[error("unsupported wasm version {0}")]
    UnsupportedVersion(u32),
    #[error("unexpected end of file at offset {0}")]
    UnexpectedEof(usize),
    #[error("invalid section id {0} at offset {1}")]
    InvalidSectionId(u8, usize),
    #[error("malformed LEB128 at offset {0}")]
    MalformedLeb128(usize),
    #[error("malformed UTF-8 in name section")]
    MalformedUtf8,
    #[error("relocation out of range: target {0:#x}, size {1}")]
    RelocationOutOfRange(u64, usize),
    #[error("duplicate section id {0}")]
    DuplicateSection(u8),
}

const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];
const WASM_VERSION: u32 = 1;

// ─────────────────────────────────────────────────────────────────────────────
// LEB128 helpers
// ─────────────────────────────────────────────────────────────────────────────

fn read_leb128_u32(data: &[u8], offset: &mut usize) -> Result<u32, LoaderError> {
    let mut result = 0u32;
    let mut shift = 0u32;
    loop {
        if *offset >= data.len() {
            return Err(LoaderError::UnexpectedEof(*offset));
        }
        let b = data[*offset];
        *offset += 1;
        result |= u32::from(b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift >= 35 {
            return Err(LoaderError::MalformedLeb128(*offset));
        }
    }
    Ok(result)
}

pub fn read_leb128_u64(data: &[u8], offset: &mut usize) -> Result<u64, LoaderError> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        if *offset >= data.len() {
            return Err(LoaderError::UnexpectedEof(*offset));
        }
        let b = data[*offset];
        *offset += 1;
        result |= u64::from(b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift >= 70 {
            return Err(LoaderError::MalformedLeb128(*offset));
        }
    }
    Ok(result)
}

fn read_name(data: &[u8], offset: &mut usize) -> Result<String, LoaderError> {
    let len = read_leb128_u32(data, offset)? as usize;
    if *offset + len > data.len() {
        return Err(LoaderError::UnexpectedEof(*offset));
    }
    let s = std::str::from_utf8(&data[*offset..*offset + len])
        .map_err(|_| LoaderError::MalformedUtf8)?
        .to_owned();
    *offset += len;
    Ok(s)
}

fn read_u8(data: &[u8], offset: &mut usize) -> Result<u8, LoaderError> {
    if *offset >= data.len() {
        return Err(LoaderError::UnexpectedEof(*offset));
    }
    let b = data[*offset];
    *offset += 1;
    Ok(b)
}

pub fn read_u32_le(data: &[u8], offset: &mut usize) -> Result<u32, LoaderError> {
    if *offset + 4 > data.len() {
        return Err(LoaderError::UnexpectedEof(*offset));
    }
    let v = u32::from_le_bytes(data[*offset..*offset + 4].try_into().unwrap());
    *offset += 4;
    Ok(v)
}

pub fn read_f32(data: &[u8], offset: &mut usize) -> Result<f32, LoaderError> {
    let bits = read_u32_le(data, offset)?;
    Ok(f32::from_bits(bits))
}

pub fn read_f64(data: &[u8], offset: &mut usize) -> Result<f64, LoaderError> {
    if *offset + 8 > data.len() {
        return Err(LoaderError::UnexpectedEof(*offset));
    }
    let bits = u64::from_le_bytes(data[*offset..*offset + 8].try_into().unwrap());
    *offset += 8;
    Ok(f64::from_bits(bits))
}

// ─────────────────────────────────────────────────────────────────────────────
// WASM value/ref types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValType {
    I32,
    I64,
    F32,
    F64,
    V128,
    FuncRef,
    ExternRef,
}

const fn decode_valtype(b: u8) -> Option<ValType> {
    match b {
        0x7F => Some(ValType::I32),
        0x7E => Some(ValType::I64),
        0x7D => Some(ValType::F32),
        0x7C => Some(ValType::F64),
        0x7B => Some(ValType::V128),
        0x70 => Some(ValType::FuncRef),
        0x6F => Some(ValType::ExternRef),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Module types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuncType {
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableType {
    pub element: ValType,
    pub min: u32,
    pub max: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemType {
    pub min: u32,
    pub max: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalType {
    pub value_type: ValType,
    pub mutable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExternKind {
    Func,
    Table,
    Mem,
    Global,
}

/// WASM import entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub module: String,
    pub name: String,
    pub kind: ExternKind,
    pub index: u32, // type / table / mem / global index
}

/// WASM export entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    pub name: String,
    pub kind: ExternKind,
    pub index: u32,
}

/// A global variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Global {
    pub ty: GlobalType,
    pub init_expr: Vec<u8>, // raw init expression bytes
}

/// A data segment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSegment {
    pub memory_index: u32,
    pub offset_expr: Vec<u8>, // raw offset expression bytes
    pub data: Vec<u8>,
}

/// An element segment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElemSegment {
    pub table_index: u32,
    pub offset_expr: Vec<u8>,
    pub function_indices: Vec<u32>,
}

/// A function body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionBody {
    pub local_types: Vec<(u32, ValType)>,
    pub code: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// WasmLoadResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of loading a WASM module.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WasmLoadResult {
    /// Function type signatures.
    pub types: Vec<FuncType>,
    /// Imports.
    pub imports: Vec<Import>,
    /// Function type indices (for internal functions).
    pub functions: Vec<u32>,
    /// Table types.
    pub tables: Vec<TableType>,
    /// Memory types.
    pub memories: Vec<MemType>,
    /// Globals.
    pub globals: Vec<Global>,
    /// Exports.
    pub exports: Vec<Export>,
    /// Start function index (if present).
    pub start: Option<u32>,
    /// Element segments.
    pub elements: Vec<ElemSegment>,
    /// Function bodies.
    pub code: Vec<FunctionBody>,
    /// Data segments.
    pub data: Vec<DataSegment>,
    /// Custom section data (name → bytes).
    pub custom: HashMap<String, Vec<u8>>,
    /// Binary size.
    pub binary_size: usize,
}

impl WasmLoadResult {
    /// Total number of functions (imported + internal).
    #[must_use]
    pub fn total_function_count(&self) -> usize {
        let imported = self
            .imports
            .iter()
            .filter(|i| matches!(i.kind, ExternKind::Func))
            .count();
        imported + self.functions.len()
    }

    /// Return all exported function names.
    #[must_use]
    pub fn exported_functions(&self) -> Vec<&str> {
        self.exports
            .iter()
            .filter(|e| matches!(e.kind, ExternKind::Func))
            .map(|e| e.name.as_str())
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WasmLoader
// ─────────────────────────────────────────────────────────────────────────────

/// Loads a WASM binary, parsing all standard sections.
pub struct WasmLoader {
    /// Maximum section size to accept.
    max_section_size: u32,
}

impl WasmLoader {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_section_size: 256 * 1024 * 1024,
        }
    }

    /// Set maximum section body size.
    pub const fn set_max_section_size(&mut self, s: u32) {
        self.max_section_size = s;
    }

    /// Parse a WASM binary and return a [`WasmLoadResult`].
    ///
    /// # Errors
    /// Returns [`LoaderError`] if the binary is malformed.
    pub fn load(&self, data: &[u8]) -> Result<WasmLoadResult, LoaderError> {
        if data.len() < 8 {
            return Err(LoaderError::UnexpectedEof(0));
        }
        if data[0..4] != WASM_MAGIC {
            return Err(LoaderError::InvalidMagic);
        }
        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if version != WASM_VERSION {
            return Err(LoaderError::UnsupportedVersion(version));
        }

        let mut result = WasmLoadResult {
            binary_size: data.len(),
            ..WasmLoadResult::default()
        };
        let mut offset = 8usize;

        while offset < data.len() {
            let section_id = read_u8(data, &mut offset)?;
            let section_size = read_leb128_u32(data, &mut offset)? as usize;
            if section_size > self.max_section_size as usize {
                return Err(LoaderError::InvalidSectionId(section_id, offset));
            }
            if offset + section_size > data.len() {
                return Err(LoaderError::UnexpectedEof(offset));
            }
            let section_data = &data[offset..offset + section_size];
            offset += section_size;

            match section_id {
                0 => self.parse_custom(section_data, &mut result)?,
                1 => self.parse_type(section_data, &mut result)?,
                2 => self.parse_import(section_data, &mut result)?,
                3 => self.parse_function(section_data, &mut result)?,
                4 => self.parse_table(section_data, &mut result)?,
                5 => self.parse_memory(section_data, &mut result)?,
                6 => self.parse_global(section_data, &mut result)?,
                7 => self.parse_export(section_data, &mut result)?,
                8 => self.parse_start(section_data, &mut result)?,
                9 => self.parse_element(section_data, &mut result)?,
                10 => self.parse_code(section_data, &mut result)?,
                11 => self.parse_data(section_data, &mut result)?,
                other => {
                    // Skip unknown sections.
                    let _ = other;
                }
            }
        }

        Ok(result)
    }

    fn parse_custom(&self, data: &[u8], result: &mut WasmLoadResult) -> Result<(), LoaderError> {
        let mut off = 0;
        let name = read_name(data, &mut off)?;
        let payload = data[off..].to_vec();
        result.custom.insert(name, payload);
        Ok(())
    }

    fn parse_type(&self, data: &[u8], result: &mut WasmLoadResult) -> Result<(), LoaderError> {
        let mut off = 0;
        let count = read_leb128_u32(data, &mut off)?;
        for _ in 0..count {
            let tag = read_u8(data, &mut off)?;
            if tag != 0x60 {
                return Err(LoaderError::UnexpectedEof(off));
            }
            let param_count = read_leb128_u32(data, &mut off)? as usize;
            let mut params = Vec::with_capacity(param_count.min(data.len().saturating_sub(off)));
            for _ in 0..param_count {
                let b = read_u8(data, &mut off)?;
                params.push(decode_valtype(b).ok_or(LoaderError::UnexpectedEof(off))?);
            }
            let result_count = read_leb128_u32(data, &mut off)? as usize;
            let mut results = Vec::with_capacity(result_count.min(data.len().saturating_sub(off)));
            for _ in 0..result_count {
                let b = read_u8(data, &mut off)?;
                results.push(decode_valtype(b).ok_or(LoaderError::UnexpectedEof(off))?);
            }
            result.types.push(FuncType { params, results });
        }
        Ok(())
    }

    fn parse_import(&self, data: &[u8], result: &mut WasmLoadResult) -> Result<(), LoaderError> {
        let mut off = 0;
        let count = read_leb128_u32(data, &mut off)?;
        for _ in 0..count {
            let module = read_name(data, &mut off)?;
            let name = read_name(data, &mut off)?;
            let kind_byte = read_u8(data, &mut off)?;
            let (kind, index) = match kind_byte {
                0x00 => (ExternKind::Func, read_leb128_u32(data, &mut off)?),
                0x01 => {
                    let idx = read_leb128_u32(data, &mut off)?;
                    (ExternKind::Table, idx)
                }
                0x02 => {
                    let idx = read_leb128_u32(data, &mut off)?;
                    (ExternKind::Mem, idx)
                }
                0x03 => {
                    let idx = read_leb128_u32(data, &mut off)?;
                    (ExternKind::Global, idx)
                }
                _ => return Err(LoaderError::UnexpectedEof(off)),
            };
            result.imports.push(Import {
                module,
                name,
                kind,
                index,
            });
        }
        Ok(())
    }

    fn parse_function(&self, data: &[u8], result: &mut WasmLoadResult) -> Result<(), LoaderError> {
        let mut off = 0;
        let count = read_leb128_u32(data, &mut off)?;
        for _ in 0..count {
            result.functions.push(read_leb128_u32(data, &mut off)?);
        }
        Ok(())
    }

    fn parse_table(&self, data: &[u8], result: &mut WasmLoadResult) -> Result<(), LoaderError> {
        let mut off = 0;
        let count = read_leb128_u32(data, &mut off)?;
        for _ in 0..count {
            let elem_type = read_u8(data, &mut off)?;
            let element = decode_valtype(elem_type).ok_or(LoaderError::UnexpectedEof(off))?;
            let limit_kind = read_u8(data, &mut off)?;
            let min = read_leb128_u32(data, &mut off)?;
            let max = if limit_kind == 1 {
                Some(read_leb128_u32(data, &mut off)?)
            } else {
                None
            };
            result.tables.push(TableType { element, min, max });
        }
        Ok(())
    }

    fn parse_memory(&self, data: &[u8], result: &mut WasmLoadResult) -> Result<(), LoaderError> {
        let mut off = 0;
        let count = read_leb128_u32(data, &mut off)?;
        for _ in 0..count {
            let limit_kind = read_u8(data, &mut off)?;
            let min = read_leb128_u32(data, &mut off)?;
            let max = if limit_kind == 1 {
                Some(read_leb128_u32(data, &mut off)?)
            } else {
                None
            };
            result.memories.push(MemType { min, max });
        }
        Ok(())
    }

    fn parse_global(&self, data: &[u8], result: &mut WasmLoadResult) -> Result<(), LoaderError> {
        let mut off = 0;
        let count = read_leb128_u32(data, &mut off)?;
        for _ in 0..count {
            let vt_byte = read_u8(data, &mut off)?;
            let value_type = decode_valtype(vt_byte).unwrap_or(ValType::I32);
            let mutable = read_u8(data, &mut off)? == 1;
            // Scan init expression until 0x0B (end).
            let expr_start = off;
            while off < data.len() && data[off] != 0x0B {
                off += 1;
            }
            if off >= data.len() {
                return Err(LoaderError::UnexpectedEof(off));
            }
            let init_expr = data[expr_start..off].to_vec();
            off += 1; // consume end
            result.globals.push(Global {
                ty: GlobalType {
                    value_type,
                    mutable,
                },
                init_expr,
            });
        }
        Ok(())
    }

    fn parse_export(&self, data: &[u8], result: &mut WasmLoadResult) -> Result<(), LoaderError> {
        let mut off = 0;
        let count = read_leb128_u32(data, &mut off)?;
        for _ in 0..count {
            let name = read_name(data, &mut off)?;
            let kind_byte = read_u8(data, &mut off)?;
            let kind = match kind_byte {
                0 => ExternKind::Func,
                1 => ExternKind::Table,
                2 => ExternKind::Mem,
                3 => ExternKind::Global,
                _ => return Err(LoaderError::UnexpectedEof(off)),
            };
            let index = read_leb128_u32(data, &mut off)?;
            result.exports.push(Export { name, kind, index });
        }
        Ok(())
    }

    fn parse_start(&self, data: &[u8], result: &mut WasmLoadResult) -> Result<(), LoaderError> {
        let mut off = 0;
        result.start = Some(read_leb128_u32(data, &mut off)?);
        Ok(())
    }

    fn parse_element(&self, data: &[u8], result: &mut WasmLoadResult) -> Result<(), LoaderError> {
        let mut off = 0;
        let count = read_leb128_u32(data, &mut off)?;
        for _ in 0..count {
            let table_index = read_leb128_u32(data, &mut off)?;
            // offset expr until 0x0B
            let expr_start = off;
            while off < data.len() && data[off] != 0x0B {
                off += 1;
            }
            let offset_expr = data[expr_start..off].to_vec();
            if off < data.len() {
                off += 1;
            }
            let fn_count = read_leb128_u32(data, &mut off)? as usize;
            let mut function_indices = Vec::with_capacity(fn_count.min(data.len().saturating_sub(off)));
            for _ in 0..fn_count {
                function_indices.push(read_leb128_u32(data, &mut off)?);
            }
            result.elements.push(ElemSegment {
                table_index,
                offset_expr,
                function_indices,
            });
        }
        Ok(())
    }

    fn parse_code(&self, data: &[u8], result: &mut WasmLoadResult) -> Result<(), LoaderError> {
        let mut off = 0;
        let count = read_leb128_u32(data, &mut off)?;
        for _ in 0..count {
            let body_size = read_leb128_u32(data, &mut off)? as usize;
            if off + body_size > data.len() {
                return Err(LoaderError::UnexpectedEof(off));
            }
            let body_data = &data[off..off + body_size];
            off += body_size;
            let mut boff = 0;
            let local_count = read_leb128_u32(body_data, &mut boff)? as usize;
            let mut local_types = Vec::with_capacity(local_count.min(body_data.len().saturating_sub(boff)));
            for _ in 0..local_count {
                let n = read_leb128_u32(body_data, &mut boff)?;
                let vt_byte = read_u8(body_data, &mut boff)?;
                let vt = decode_valtype(vt_byte).unwrap_or(ValType::I32);
                local_types.push((n, vt));
            }
            let code = body_data[boff..].to_vec();
            result.code.push(FunctionBody { local_types, code });
        }
        Ok(())
    }

    fn parse_data(&self, data: &[u8], result: &mut WasmLoadResult) -> Result<(), LoaderError> {
        let mut off = 0;
        let count = read_leb128_u32(data, &mut off)?;
        for _ in 0..count {
            let memory_index = read_leb128_u32(data, &mut off)?;
            let expr_start = off;
            while off < data.len() && data[off] != 0x0B {
                off += 1;
            }
            let offset_expr = data[expr_start..off].to_vec();
            if off < data.len() {
                off += 1;
            }
            let data_size = read_leb128_u32(data, &mut off)? as usize;
            if off + data_size > data.len() {
                return Err(LoaderError::UnexpectedEof(off));
            }
            let segment_data = data[off..off + data_size].to_vec();
            off += data_size;
            result.data.push(DataSegment {
                memory_index,
                offset_expr,
                data: segment_data,
            });
        }
        Ok(())
    }
}

impl Default for WasmLoader {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WasmRelocator
// ─────────────────────────────────────────────────────────────────────────────

/// Applies address relocations to a loaded WASM module.
pub struct WasmRelocator {
    base: u64,
}

impl WasmRelocator {
    /// Create a relocator with the given base address.
    #[must_use]
    pub const fn new(base: u64) -> Self {
        Self { base }
    }

    /// Relocate an address (add base).
    #[must_use]
    pub const fn relocate(&self, addr: u64) -> u64 {
        match self.base.checked_add(addr) {
            Some(v) => v,
            None => panic!("relocation overflow"),
        }
    }

    /// Apply relocation to all export addresses.
    ///
    /// `index_to_address` maps function index → pre-relocation address.
    /// Returns a map of export name → relocated address.
    #[must_use]
    pub fn relocate_exports(
        &self,
        exports: &[Export],
        index_to_address: &HashMap<u32, u64>,
    ) -> HashMap<String, u64> {
        exports
            .iter()
            .filter(|e| matches!(e.kind, ExternKind::Func))
            .filter_map(|e| {
                index_to_address
                    .get(&e.index)
                    .map(|&addr| (e.name.clone(), self.relocate(addr)))
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WASM binary builder helper (for tests)
// ─────────────────────────────────────────────────────────────────────────────

pub struct WasmBuilder {
    data: Vec<u8>,
}

impl Default for WasmBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmBuilder {
    #[must_use] 
    pub fn new() -> Self {
        let mut data = WASM_MAGIC.to_vec();
        data.extend_from_slice(&1u32.to_le_bytes()); // version
        Self { data }
    }

    pub fn add_section(&mut self, id: u8, payload: &[u8]) {
        self.data.push(id);
        self.write_leb128(payload.len() as u32);
        self.data.extend_from_slice(payload);
    }

    fn write_leb128(&mut self, mut v: u32) {
        loop {
            let mut b = (v & 0x7F) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            self.data.push(b);
            if v == 0 {
                break;
            }
        }
    }

    fn write_str(buf: &mut Vec<u8>, s: &str) {
        let bytes = s.as_bytes();
        let mut tmp = Self { data: Vec::new() };
        tmp.write_leb128(bytes.len() as u32);
        buf.extend_from_slice(&tmp.data);
        buf.extend_from_slice(bytes);
    }

    #[must_use] 
    pub fn build(self) -> Vec<u8> {
        self.data
    }

    #[must_use] 
    pub fn build_minimal() -> Vec<u8> {
        // Minimal valid WASM: magic + version + empty type section.
        let mut b = Self::new();
        b.add_section(1, &[0x00]); // type section: 0 types
        b.build()
    }

    #[must_use] 
    pub fn build_with_export(name: &str) -> Vec<u8> {
        let mut b = Self::new();
        // type section: one function type () → ()
        b.add_section(1, &[0x01, 0x60, 0x00, 0x00]);
        // function section: one function of type 0
        b.add_section(3, &[0x01, 0x00]);
        // export section
        let mut exp = Vec::new();
        exp.push(0x01); // 1 export
        Self::write_str(&mut exp, name);
        exp.push(0x00); // kind = func
        exp.push(0x00); // index = 0
        b.add_section(7, &exp);
        // code section: one body
        b.add_section(10, &[0x01, 0x02, 0x00, 0x0B]); // 1 body, 2 bytes, no locals, end
        b.build()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn loader() -> WasmLoader {
        WasmLoader::new()
    }

    // -- Magic/version validation --------------------------------------------

    #[test]
    fn test_invalid_magic() {
        let data = [0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        assert!(matches!(
            loader().load(&data),
            Err(LoaderError::InvalidMagic)
        ));
    }

    #[test]
    fn test_unsupported_version() {
        let mut data = WASM_MAGIC.to_vec();
        data.extend_from_slice(&2u32.to_le_bytes());
        assert!(matches!(
            loader().load(&data),
            Err(LoaderError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn test_too_short() {
        assert!(loader().load(&[0x00]).is_err());
    }

    // -- Minimal module ------------------------------------------------------

    #[test]
    fn test_load_minimal() {
        let data = WasmBuilder::build_minimal();
        let r = loader().load(&data).unwrap();
        assert_eq!(r.types.len(), 0);
        assert_eq!(r.binary_size, data.len());
    }

    // -- Type section --------------------------------------------------------

    #[test]
    fn test_type_section() {
        let mut b = WasmBuilder::new();
        // one type: (i32, i32) -> i32
        b.add_section(1, &[0x01, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F]);
        let r = loader().load(&b.build()).unwrap();
        assert_eq!(r.types.len(), 1);
        assert_eq!(r.types[0].params.len(), 2);
        assert_eq!(r.types[0].results.len(), 1);
    }

    // -- Function section ----------------------------------------------------

    #[test]
    fn test_function_section() {
        let mut b = WasmBuilder::new();
        b.add_section(1, &[0x01, 0x60, 0x00, 0x00]);
        b.add_section(3, &[0x01, 0x00]); // 1 function, type 0
        let r = loader().load(&b.build()).unwrap();
        assert_eq!(r.functions.len(), 1);
        assert_eq!(r.functions[0], 0);
    }

    // -- Export section ------------------------------------------------------

    #[test]
    fn test_export_section() {
        let data = WasmBuilder::build_with_export("main");
        let r = loader().load(&data).unwrap();
        assert_eq!(r.exports.len(), 1);
        assert_eq!(r.exports[0].name, "main");
        assert!(matches!(r.exports[0].kind, ExternKind::Func));
    }

    #[test]
    fn test_exported_functions() {
        let data = WasmBuilder::build_with_export("_start");
        let r = loader().load(&data).unwrap();
        assert!(r.exported_functions().contains(&"_start"));
    }

    // -- Import section ------------------------------------------------------

    #[test]
    fn test_import_section() {
        let mut b = WasmBuilder::new();
        b.add_section(1, &[0x01, 0x60, 0x00, 0x00]); // type
        // import: "env"."memory", kind=mem, min=1
        let mut imp = Vec::new();
        imp.push(0x01); // count
        WasmBuilder::write_str(&mut imp, "env");
        WasmBuilder::write_str(&mut imp, "memory");
        imp.push(0x02); // kind = mem
        imp.push(0x00); // limit kind = min only
        imp.push(0x01); // min = 1
        b.add_section(2, &imp);
        let r = loader().load(&b.build()).unwrap();
        assert_eq!(r.imports.len(), 1);
        assert_eq!(r.imports[0].module, "env");
        assert_eq!(r.imports[0].name, "memory");
    }

    // -- Memory section ------------------------------------------------------

    #[test]
    fn test_memory_section() {
        let mut b = WasmBuilder::new();
        b.add_section(5, &[0x01, 0x00, 0x01]); // 1 memory, no max, min=1
        let r = loader().load(&b.build()).unwrap();
        assert_eq!(r.memories.len(), 1);
        assert_eq!(r.memories[0].min, 1);
        assert!(r.memories[0].max.is_none());
    }

    // -- Code section --------------------------------------------------------

    #[test]
    fn test_code_section() {
        let data = WasmBuilder::build_with_export("noop");
        let r = loader().load(&data).unwrap();
        assert_eq!(r.code.len(), 1);
        // The body should contain at least the end opcode.
        assert!(!r.code[0].code.is_empty());
    }

    // -- Custom section -------------------------------------------------------

    #[test]
    fn test_custom_section() {
        let mut b = WasmBuilder::new();
        let mut custom = Vec::new();
        WasmBuilder::write_str(&mut custom, "name");
        custom.extend_from_slice(&[0x01, 0x02]);
        b.add_section(0, &custom);
        let r = loader().load(&b.build()).unwrap();
        assert!(r.custom.contains_key("name"));
    }

    // -- Start section -------------------------------------------------------

    #[test]
    fn test_start_section() {
        let mut b = WasmBuilder::new();
        b.add_section(1, &[0x01, 0x60, 0x00, 0x00]);
        b.add_section(3, &[0x01, 0x00]);
        b.add_section(8, &[0x00]); // start function = 0
        b.add_section(10, &[0x01, 0x02, 0x00, 0x0B]);
        let r = loader().load(&b.build()).unwrap();
        assert_eq!(r.start, Some(0));
    }

    // -- total_function_count ------------------------------------------------

    #[test]
    fn test_total_function_count() {
        let data = WasmBuilder::build_with_export("f");
        let r = loader().load(&data).unwrap();
        assert_eq!(r.total_function_count(), 1);
    }

    // -- LEB128 edge cases ---------------------------------------------------

    #[test]
    fn test_leb128_multibyte() {
        let mut off = 0;
        let data = vec![0x80, 0x01]; // 128 in LEB128
        assert_eq!(read_leb128_u32(&data, &mut off).unwrap(), 128);
    }

    #[test]
    fn test_leb128_eof() {
        let mut off = 0;
        let data = vec![0x80]; // incomplete LEB128
        assert!(read_leb128_u32(&data, &mut off).is_err());
    }

    // -- WasmRelocator -------------------------------------------------------

    #[test]
    fn test_relocator_base() {
        let r = WasmRelocator::new(0x10000);
        assert_eq!(r.relocate(0x100), 0x10100);
    }

    #[test]
    fn test_relocator_exports() {
        let exports = vec![Export {
            name: "main".into(),
            kind: ExternKind::Func,
            index: 0,
        }];
        let mut map = HashMap::new();
        map.insert(0u32, 0x200u64);
        let r = WasmRelocator::new(0x400000);
        let relocated = r.relocate_exports(&exports, &map);
        assert_eq!(relocated.get("main"), Some(&0x400200));
    }
}
