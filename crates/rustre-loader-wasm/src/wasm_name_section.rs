//! WASM name custom section parser.
//!
//! Parses the "name" custom section as defined in the WebAssembly specification:
//! module name, function names, local names, label names, type names, table
//! names, and global names.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NameSectionError {
    #[error("unexpected end of data at offset {0}")]
    UnexpectedEof(usize),
    #[error("malformed LEB128 at offset {0}")]
    MalformedLeb128(usize),
    #[error("invalid UTF-8 string")]
    InvalidUtf8,
    #[error("unknown name subsection type {0}")]
    UnknownSubsection(u8),
    #[error("duplicate function name for index {0}")]
    DuplicateName(u32),
}

// ─────────────────────────────────────────────────────────────────────────────
// LEB128 / string helpers
// ─────────────────────────────────────────────────────────────────────────────

fn read_u32(data: &[u8], off: &mut usize) -> Result<u32, NameSectionError> {
    let mut result = 0u32;
    let mut shift = 0u32;
    loop {
        if *off >= data.len() {
            return Err(NameSectionError::UnexpectedEof(*off));
        }
        let b = data[*off];
        *off += 1;
        result |= u32::from(b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift >= 35 {
            return Err(NameSectionError::MalformedLeb128(*off));
        }
    }
    Ok(result)
}

fn read_str(data: &[u8], off: &mut usize) -> Result<String, NameSectionError> {
    let len = read_u32(data, off)? as usize;
    if *off + len > data.len() {
        return Err(NameSectionError::UnexpectedEof(*off));
    }
    let s = std::str::from_utf8(&data[*off..*off + len])
        .map_err(|_| NameSectionError::InvalidUtf8)?
        .to_owned();
    *off += len;
    Ok(s)
}

fn read_u8(data: &[u8], off: &mut usize) -> Result<u8, NameSectionError> {
    if *off >= data.len() {
        return Err(NameSectionError::UnexpectedEof(*off));
    }
    let b = data[*off];
    *off += 1;
    Ok(b)
}

// ─────────────────────────────────────────────────────────────────────────────
// NameMap — maps index to name
// ─────────────────────────────────────────────────────────────────────────────

/// A mapping from an integer index to a name string.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NameMap {
    pub entries: HashMap<u32, String>,
}

impl NameMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a name map from raw bytes.
    ///
    /// # Errors
    /// Returns [`NameSectionError`] on malformed input.
    pub fn parse(data: &[u8], off: &mut usize) -> Result<Self, NameSectionError> {
        let count = read_u32(data, off)? as usize;
        let mut map = Self::new();
        for _ in 0..count {
            let idx = read_u32(data, off)?;
            let name = read_str(data, off)?;
            map.entries.insert(idx, name);
        }
        Ok(map)
    }

    /// Look up a name by index.
    #[must_use]
    pub fn get(&self, idx: u32) -> Option<&str> {
        self.entries.get(&idx).map(std::string::String::as_str)
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IndirectNameMap — maps outer index → (inner index → name)
// ─────────────────────────────────────────────────────────────────────────────

/// A two-level name map: outer index (e.g. function) → `NameMap` (e.g. locals).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IndirectNameMap {
    pub entries: HashMap<u32, NameMap>,
}

impl IndirectNameMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse an indirect name map.
    ///
    /// # Errors
    /// Returns [`NameSectionError`] on malformed input.
    pub fn parse(data: &[u8], off: &mut usize) -> Result<Self, NameSectionError> {
        let outer_count = read_u32(data, off)? as usize;
        let mut map = Self::new();
        for _ in 0..outer_count {
            let outer_idx = read_u32(data, off)?;
            let inner = NameMap::parse(data, off)?;
            map.entries.insert(outer_idx, inner);
        }
        Ok(map)
    }

    /// Look up a name by outer and inner index.
    #[must_use]
    pub fn get(&self, outer: u32, inner: u32) -> Option<&str> {
        self.entries.get(&outer)?.get(inner)
    }

    /// Number of outer entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Subsection types
// ─────────────────────────────────────────────────────────────────────────────

/// Module name subsection (id = 0).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleNameSubsection {
    pub name: String,
}

impl ModuleNameSubsection {
    fn parse(data: &[u8], off: &mut usize) -> Result<Self, NameSectionError> {
        Ok(Self {
            name: read_str(data, off)?,
        })
    }
}

/// Function name subsection (id = 1).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionNameSubsection {
    pub names: NameMap,
}

impl FunctionNameSubsection {
    fn parse(data: &[u8], off: &mut usize) -> Result<Self, NameSectionError> {
        Ok(Self {
            names: NameMap::parse(data, off)?,
        })
    }

    /// Return the name of a function by index.
    #[must_use]
    pub fn get(&self, idx: u32) -> Option<&str> {
        self.names.get(idx)
    }
}

/// Local name subsection (id = 2).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalNameSubsection {
    pub names: IndirectNameMap,
}

impl LocalNameSubsection {
    fn parse(data: &[u8], off: &mut usize) -> Result<Self, NameSectionError> {
        Ok(Self {
            names: IndirectNameMap::parse(data, off)?,
        })
    }

    /// Return the name of local `local_idx` in function `func_idx`.
    #[must_use]
    pub fn get(&self, func_idx: u32, local_idx: u32) -> Option<&str> {
        self.names.get(func_idx, local_idx)
    }
}

/// Label name subsection (id = 3).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LabelNameSubsection {
    pub names: IndirectNameMap,
}

impl LabelNameSubsection {
    fn parse(data: &[u8], off: &mut usize) -> Result<Self, NameSectionError> {
        Ok(Self {
            names: IndirectNameMap::parse(data, off)?,
        })
    }
}

/// Type name subsection (id = 4).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypeNameSubsection {
    pub names: NameMap,
}

impl TypeNameSubsection {
    fn parse(data: &[u8], off: &mut usize) -> Result<Self, NameSectionError> {
        Ok(Self {
            names: NameMap::parse(data, off)?,
        })
    }
}

/// Table name subsection (id = 5).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TableNameSubsection {
    pub names: NameMap,
}

impl TableNameSubsection {
    fn parse(data: &[u8], off: &mut usize) -> Result<Self, NameSectionError> {
        Ok(Self {
            names: NameMap::parse(data, off)?,
        })
    }
}

/// Memory name subsection (id = 6, non-standard extension).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryNameSubsection {
    pub names: NameMap,
}

impl MemoryNameSubsection {
    fn parse(data: &[u8], off: &mut usize) -> Result<Self, NameSectionError> {
        Ok(Self {
            names: NameMap::parse(data, off)?,
        })
    }
}

/// Global name subsection (id = 7).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalNameSubsection {
    pub names: NameMap,
}

impl GlobalNameSubsection {
    fn parse(data: &[u8], off: &mut usize) -> Result<Self, NameSectionError> {
        Ok(Self {
            names: NameMap::parse(data, off)?,
        })
    }
}

/// Element segment name subsection (id = 8).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ElemNameSubsection {
    pub names: NameMap,
}

impl ElemNameSubsection {
    fn parse(data: &[u8], off: &mut usize) -> Result<Self, NameSectionError> {
        Ok(Self {
            names: NameMap::parse(data, off)?,
        })
    }
}

/// Data segment name subsection (id = 9).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DataNameSubsection {
    pub names: NameMap,
}

impl DataNameSubsection {
    fn parse(data: &[u8], off: &mut usize) -> Result<Self, NameSectionError> {
        Ok(Self {
            names: NameMap::parse(data, off)?,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NameSection — the top-level parsed section
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed WASM name custom section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NameSection {
    pub module_name: Option<ModuleNameSubsection>,
    pub function_names: Option<FunctionNameSubsection>,
    pub local_names: Option<LocalNameSubsection>,
    pub label_names: Option<LabelNameSubsection>,
    pub type_names: Option<TypeNameSubsection>,
    pub table_names: Option<TableNameSubsection>,
    pub memory_names: Option<MemoryNameSubsection>,
    pub global_names: Option<GlobalNameSubsection>,
    pub elem_names: Option<ElemNameSubsection>,
    pub data_names: Option<DataNameSubsection>,
    /// Unrecognised subsections (id → raw bytes).
    pub unknown: HashMap<u8, Vec<u8>>,
}

impl NameSection {
    /// Parse the name section from the payload bytes (after the "name" string).
    ///
    /// # Errors
    /// Returns [`NameSectionError`] if the payload is malformed.
    pub fn parse(payload: &[u8]) -> Result<Self, NameSectionError> {
        let mut section = Self::default();
        let mut off = 0;

        while off < payload.len() {
            let subsection_id = read_u8(payload, &mut off)?;
            let subsection_size = read_u32(payload, &mut off)? as usize;
            if off + subsection_size > payload.len() {
                return Err(NameSectionError::UnexpectedEof(off));
            }
            let sub_data = &payload[off..off + subsection_size];
            let mut sub_off = 0;
            off += subsection_size;

            match subsection_id {
                0 => {
                    section.module_name = Some(ModuleNameSubsection::parse(sub_data, &mut sub_off)?);
                }
                1 => {
                    section.function_names =
                        Some(FunctionNameSubsection::parse(sub_data, &mut sub_off)?);
                }
                2 => {
                    section.local_names = Some(LocalNameSubsection::parse(sub_data, &mut sub_off)?);
                }
                3 => {
                    section.label_names = Some(LabelNameSubsection::parse(sub_data, &mut sub_off)?);
                }
                4 => section.type_names = Some(TypeNameSubsection::parse(sub_data, &mut sub_off)?),
                5 => {
                    section.table_names = Some(TableNameSubsection::parse(sub_data, &mut sub_off)?);
                }
                6 => {
                    section.memory_names =
                        Some(MemoryNameSubsection::parse(sub_data, &mut sub_off)?);
                }
                7 => {
                    section.global_names =
                        Some(GlobalNameSubsection::parse(sub_data, &mut sub_off)?);
                }
                8 => section.elem_names = Some(ElemNameSubsection::parse(sub_data, &mut sub_off)?),
                9 => section.data_names = Some(DataNameSubsection::parse(sub_data, &mut sub_off)?),
                id => {
                    section.unknown.insert(id, sub_data.to_vec());
                }
            }
        }

        Ok(section)
    }

    /// Try to parse from a custom section payload (strips the leading "name" string if present).
    ///
    /// # Errors
    /// Returns [`NameSectionError`] if the payload is malformed.
    pub fn from_custom_payload(payload: &[u8]) -> Result<Self, NameSectionError> {
        // Payload already has the "name" string stripped when stored in WasmLoadResult.
        Self::parse(payload)
    }

    /// Look up a function name by index.
    #[must_use]
    pub fn function_name(&self, idx: u32) -> Option<&str> {
        self.function_names.as_ref()?.get(idx)
    }

    /// Look up a local variable name.
    #[must_use]
    pub fn local_name(&self, func_idx: u32, local_idx: u32) -> Option<&str> {
        self.local_names.as_ref()?.get(func_idx, local_idx)
    }

    /// Return the module name.
    #[must_use]
    pub fn module_name_str(&self) -> Option<&str> {
        self.module_name.as_ref().map(|m| m.name.as_str())
    }

    /// Return the total number of named symbols (module + functions + locals).
    #[must_use]
    pub fn total_named_symbols(&self) -> usize {
        let module = usize::from(self.module_name.is_some());
        let funcs = self
            .function_names
            .as_ref()
            .map_or(0, |f| f.names.len());
        let locals: usize = self
            .local_names
            .as_ref()
            .map_or(0, |ln| ln.names.entries.values().map(NameMap::len).sum());
        module + funcs + locals
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NameSectionBuilder — for tests
// ─────────────────────────────────────────────────────────────────────────────

/// Helper to build a name section payload byte-by-byte.
#[derive(Default)]
pub struct NameSectionBuilder {
    data: Vec<u8>,
}

impl NameSectionBuilder {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
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

    fn write_leb128_to(buf: &mut Vec<u8>, mut v: u32) {
        loop {
            let mut b = (v & 0x7F) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            buf.push(b);
            if v == 0 {
                break;
            }
        }
    }

    fn write_str_inline(buf: &mut Vec<u8>, s: &str) {
        let bytes = s.as_bytes();
        Self::write_leb128_to(buf, bytes.len() as u32);
        buf.extend_from_slice(bytes);
    }

    /// Add module name subsection.
    #[must_use] 
    pub fn module_name(mut self, name: &str) -> Self {
        let mut payload: Vec<u8> = Vec::with_capacity(5 + name.len());
        Self::write_str_inline(&mut payload, name);
        self.data.push(0); // subsection id 0
        self.write_leb128(payload.len() as u32);
        self.data.extend_from_slice(&payload);
        self
    }

    /// Add function names subsection.
    #[must_use] 
    pub fn function_names(mut self, names: &[(u32, &str)]) -> Self {
        // Pre-size: 5B count LEB + per-entry (5B idx + 5B strlen + str bytes)
        let est: usize = 5 + names.iter().map(|(_, n)| 10 + n.len()).sum::<usize>();
        let mut payload: Vec<u8> = Vec::with_capacity(est);
        Self::write_leb128_to(&mut payload, names.len() as u32);
        for &(idx, name) in names {
            Self::write_leb128_to(&mut payload, idx);
            Self::write_str_inline(&mut payload, name);
        }
        self.data.push(1); // subsection id 1
        self.write_leb128(payload.len() as u32);
        self.data.extend_from_slice(&payload);
        self
    }

    #[must_use] 
    pub fn build(self) -> Vec<u8> {
        self.data
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build_module_name(name: &str) -> Vec<u8> {
        NameSectionBuilder::new().module_name(name).build()
    }

    fn build_function_names(names: &[(u32, &str)]) -> Vec<u8> {
        NameSectionBuilder::new().function_names(names).build()
    }

    // -- NameMap -------------------------------------------------------------

    #[test]
    fn test_name_map_parse() {
        let names: &[(u32, &str)] = &[(0, "main"), (1, "helper")];
        let payload = build_function_names(names);
        // payload here is the whole name section (module_name or func_names subsection).
        let section = NameSection::parse(&payload).unwrap();
        assert!(section.function_names.is_some());
        let fn_sec = section.function_names.unwrap();
        assert_eq!(fn_sec.get(0), Some("main"));
        assert_eq!(fn_sec.get(1), Some("helper"));
    }

    #[test]
    fn test_name_map_get_missing() {
        let section = NameSection::default();
        assert_eq!(section.function_name(0), None);
    }

    // -- NameSection parse ---------------------------------------------------

    #[test]
    fn test_parse_module_name() {
        let payload = build_module_name("my_module");
        let section = NameSection::parse(&payload).unwrap();
        assert_eq!(section.module_name_str(), Some("my_module"));
    }

    #[test]
    fn test_parse_function_names() {
        let payload = build_function_names(&[(0, "add"), (1, "mul")]);
        let section = NameSection::parse(&payload).unwrap();
        assert_eq!(section.function_name(0), Some("add"));
        assert_eq!(section.function_name(1), Some("mul"));
        assert_eq!(section.function_name(2), None);
    }

    #[test]
    fn test_parse_combined() {
        let payload = NameSectionBuilder::new()
            .module_name("wasm_test")
            .function_names(&[(0, "main"), (1, "_start")])
            .build();
        let section = NameSection::parse(&payload).unwrap();
        assert_eq!(section.module_name_str(), Some("wasm_test"));
        assert_eq!(section.function_name(0), Some("main"));
    }

    #[test]
    fn test_parse_empty_payload() {
        let section = NameSection::parse(&[]).unwrap();
        assert!(section.module_name.is_none());
        assert!(section.function_names.is_none());
    }

    #[test]
    fn test_parse_unknown_subsection() {
        let payload = vec![0xFF, 0x02, 0xDE, 0xAD];
        let section = NameSection::parse(&payload).unwrap();
        assert!(section.unknown.contains_key(&0xFF));
        assert_eq!(section.unknown[&0xFF], vec![0xDE, 0xAD]);
    }

    #[test]
    fn test_total_named_symbols() {
        let payload = NameSectionBuilder::new()
            .module_name("mod")
            .function_names(&[(0, "f0"), (1, "f1"), (2, "f2")])
            .build();
        let section = NameSection::parse(&payload).unwrap();
        assert_eq!(section.total_named_symbols(), 4); // 1 module + 3 functions
    }

    #[test]
    fn test_unexpected_eof() {
        // Subsection says length=100 but only 2 bytes follow.
        let payload = vec![0x00, 100u8, 0x01, 0x02];
        assert!(matches!(
            NameSection::parse(&payload),
            Err(NameSectionError::UnexpectedEof(_))
        ));
    }

    // -- IndirectNameMap -----------------------------------------------------

    #[test]
    fn test_indirect_name_map_get_missing() {
        let m = IndirectNameMap::new();
        assert_eq!(m.get(0, 0), None);
    }

    #[test]
    fn test_indirect_name_map_len() {
        let m = IndirectNameMap::new();
        assert_eq!(m.len(), 0);
        assert!(m.is_empty());
    }

    // -- NameMap is_empty / len ----------------------------------------------

    #[test]
    fn test_name_map_is_empty() {
        let m = NameMap::new();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    // -- from_custom_payload -------------------------------------------------

    #[test]
    fn test_from_custom_payload() {
        let payload = build_function_names(&[(0, "main")]);
        let section = NameSection::from_custom_payload(&payload).unwrap();
        assert_eq!(section.function_name(0), Some("main"));
    }

    // -- module_name_str edge cases ------------------------------------------

    #[test]
    fn test_module_name_str_none() {
        let section = NameSection::default();
        assert!(section.module_name_str().is_none());
    }

    // -- LEB128 edge cases ---------------------------------------------------

    #[test]
    fn test_leb128_eof() {
        let data = vec![0x80]; // incomplete
        let mut off = 0;
        assert!(matches!(
            read_u32(&data, &mut off),
            Err(NameSectionError::UnexpectedEof(_))
        ));
    }

    #[test]
    fn test_leb128_multibyte() {
        let data = vec![0x80, 0x01]; // 128
        let mut off = 0;
        assert_eq!(read_u32(&data, &mut off).unwrap(), 128);
    }

    // -- invalid UTF-8 -------------------------------------------------------

    #[test]
    fn test_invalid_utf8() {
        // Module name subsection (id=0), payload_len=3, name_len=2, invalid UTF-8 bytes
        let payload = vec![0x00, 0x03, 0x02, 0xFF, 0xFE];
        assert!(NameSection::parse(&payload).is_err());
    }

    // -- Multiple function names sanity ----------------------------------------

    #[test]
    fn test_many_function_names() {
        let names: Vec<(u32, &str)> = (0..50).map(|i| (i as u32, "func")).collect();
        let payload =
            build_function_names(&names.iter().map(|(i, n)| (*i, *n)).collect::<Vec<_>>());
        let section = NameSection::parse(&payload).unwrap();
        assert_eq!(section.function_names.as_ref().unwrap().names.len(), 50);
    }

    // -- NameSection default -----------------------------------------------

    #[test]
    fn test_name_section_default_is_empty() {
        let s = NameSection::default();
        assert!(s.module_name.is_none());
        assert!(s.function_names.is_none());
        assert!(s.local_names.is_none());
        assert!(s.global_names.is_none());
        assert!(s.unknown.is_empty());
    }

    #[test]
    fn test_module_name_subsection_default() {
        let m = ModuleNameSubsection::default();
        assert!(m.name.is_empty());
    }

    #[test]
    fn test_function_name_subsection_default() {
        let f = FunctionNameSubsection::default();
        assert!(f.names.is_empty());
    }

    // -- LocalNameSubsection -------------------------------------------------

    #[test]
    fn test_local_name_subsection_default() {
        let l = LocalNameSubsection::default();
        assert!(l.names.is_empty());
        assert_eq!(l.get(0, 0), None);
    }

    // -- TypeNameSubsection --------------------------------------------------

    #[test]
    fn test_type_name_subsection_default() {
        let t = TypeNameSubsection::default();
        assert!(t.names.is_empty());
    }

    // -- TableNameSubsection -------------------------------------------------

    #[test]
    fn test_table_name_subsection_default() {
        let t = TableNameSubsection::default();
        assert!(t.names.is_empty());
    }

    // -- GlobalNameSubsection ------------------------------------------------

    #[test]
    fn test_global_name_subsection_default() {
        let g = GlobalNameSubsection::default();
        assert!(g.names.is_empty());
    }

    // -- NameSectionBuilder idempotency ------------------------------------

    #[test]
    fn test_builder_module_name_roundtrip() {
        let payload = NameSectionBuilder::new().module_name("hello").build();
        let section = NameSection::parse(&payload).unwrap();
        assert_eq!(section.module_name_str(), Some("hello"));
    }

    #[test]
    fn test_builder_empty_function_names() {
        let payload = NameSectionBuilder::new().function_names(&[]).build();
        let section = NameSection::parse(&payload).unwrap();
        assert_eq!(section.function_names.as_ref().unwrap().names.len(), 0);
    }

    // -- total_named_symbols edge cases ------------------------------------

    #[test]
    fn test_total_symbols_no_module_name() {
        let payload = NameSectionBuilder::new()
            .function_names(&[(0, "f0")])
            .build();
        let section = NameSection::parse(&payload).unwrap();
        assert_eq!(section.total_named_symbols(), 1); // 0 module + 1 function
    }

    #[test]
    fn test_total_symbols_empty() {
        let section = NameSection::default();
        assert_eq!(section.total_named_symbols(), 0);
    }

    // -- NameMap entry presence -------------------------------------------

    #[test]
    fn test_name_map_contains_entry() {
        let payload = build_function_names(&[(5, "myFunc")]);
        let section = NameSection::parse(&payload).unwrap();
        assert_eq!(section.function_name(5), Some("myFunc"));
        assert_eq!(section.function_name(6), None);
    }

    // -- Read helpers edge cases ------------------------------------------

    #[test]
    fn test_read_u8_eof() {
        let mut off = 0;
        assert!(matches!(
            read_u8(&[], &mut off),
            Err(NameSectionError::UnexpectedEof(0))
        ));
    }

    #[test]
    fn test_read_str_length_overflow() {
        // String length exceeds available data.
        let data = vec![0x0A]; // length = 10, but no bytes follow
        let mut off = 0;
        assert!(read_str(&data, &mut off).is_err());
    }

    // -- Subsection with zero entries -------------------------------------

    #[test]
    fn test_function_subsection_zero_entries() {
        let payload = NameSectionBuilder::new().function_names(&[]).build();
        let section = NameSection::parse(&payload).unwrap();
        let fn_sec = section.function_names.unwrap();
        assert_eq!(fn_sec.names.len(), 0);
    }
}
