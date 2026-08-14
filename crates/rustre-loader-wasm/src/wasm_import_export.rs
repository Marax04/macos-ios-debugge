//! WebAssembly import and export section parser.
//!
//! Provides a detailed view of all imports and exports in a WASM module:
//! module/name pairs, kinds (function, table, memory, global), type indices,
//! and helpers for working with them.
//!
//! The main types are [`WasmImportSection`], [`WasmExportSection`],
//! [`WasmImport`], [`WasmExport`], [`ImportKind`], and [`ExportKind`].

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Leb128Decoder, WasmError};
use crate::wasm_type_decoder::{WasmGlobalTypeFull, WasmMemType, WasmTableType};

// ---------------------------------------------------------------------------
// ImportKind / ExportKind
// ---------------------------------------------------------------------------

/// The kind of entity an import descriptor refers to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ImportKind {
    /// An imported function: carries a type-section index.
    Function,
    /// An imported table: carries a table type.
    Table,
    /// An imported memory: carries a memory type.
    Memory,
    /// An imported global: carries a global type.
    Global,
    /// Unknown/future import kind.
    Unknown(u8),
}

impl ImportKind {
    /// Parse from a raw import descriptor byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Function,
            0x01 => Self::Table,
            0x02 => Self::Memory,
            0x03 => Self::Global,
            other => Self::Unknown(other),
        }
    }

    /// Return the numeric byte value.
    #[must_use]
    pub const fn to_byte(&self) -> u8 {
        match self {
            Self::Function => 0x00,
            Self::Table => 0x01,
            Self::Memory => 0x02,
            Self::Global => 0x03,
            Self::Unknown(b) => *b,
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Function => "func",
            Self::Table => "table",
            Self::Memory => "memory",
            Self::Global => "global",
            Self::Unknown(_) => "unknown",
        }
    }
}

impl fmt::Display for ImportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(b) => write!(f, "unknown(0x{b:02x})"),
            _ => write!(f, "{}", self.name()),
        }
    }
}

/// The kind of entity an export descriptor refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExportKind {
    /// An exported function: carries a function index.
    Function,
    /// An exported table: carries a table index.
    Table,
    /// An exported memory: carries a memory index.
    Memory,
    /// An exported global: carries a global index.
    Global,
    /// Unknown/future export kind.
    Unknown(u8),
}

impl ExportKind {
    /// Parse from a raw export descriptor byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Function,
            0x01 => Self::Table,
            0x02 => Self::Memory,
            0x03 => Self::Global,
            other => Self::Unknown(other),
        }
    }

    /// Return the numeric byte value.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Function => 0x00,
            Self::Table => 0x01,
            Self::Memory => 0x02,
            Self::Global => 0x03,
            Self::Unknown(b) => b,
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Function => "func",
            Self::Table => "table",
            Self::Memory => "memory",
            Self::Global => "global",
            Self::Unknown(_) => "unknown",
        }
    }
}

impl fmt::Display for ExportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(b) => write!(f, "unknown(0x{b:02x})"),
            _ => write!(f, "{}", self.name()),
        }
    }
}

// ---------------------------------------------------------------------------
// ImportDesc / ExportDesc
// ---------------------------------------------------------------------------

/// The typed descriptor of an import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImportDesc {
    /// A function import: type-section index.
    Function(u32),
    /// A table import.
    Table(WasmTableType),
    /// A memory import.
    Memory(WasmMemType),
    /// A global import.
    Global(WasmGlobalTypeFull),
}

impl ImportDesc {
    /// Return the import kind.
    #[must_use]
    pub const fn kind(&self) -> ImportKind {
        match self {
            Self::Function(_) => ImportKind::Function,
            Self::Table(_) => ImportKind::Table,
            Self::Memory(_) => ImportKind::Memory,
            Self::Global(_) => ImportKind::Global,
        }
    }

    /// If this is a function import, return its type index.
    #[must_use]
    pub const fn as_function(&self) -> Option<u32> {
        match self {
            Self::Function(idx) => Some(*idx),
            _ => None,
        }
    }
}

impl fmt::Display for ImportDesc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Function(idx) => write!(f, "(func (type {idx}))"),
            Self::Table(t) => write!(f, "(table {t})"),
            Self::Memory(m) => write!(f, "(memory {m})"),
            Self::Global(g) => write!(f, "(global {g})"),
        }
    }
}

/// The typed descriptor of an export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportDesc {
    /// The kind of the exported entity.
    pub kind: ExportKind,
    /// The index of the exported entity in its respective index space.
    pub index: u32,
}

impl ExportDesc {
    /// Create a function export.
    #[must_use]
    pub const fn function(index: u32) -> Self {
        Self { kind: ExportKind::Function, index }
    }

    /// Create a table export.
    #[must_use]
    pub const fn table(index: u32) -> Self {
        Self { kind: ExportKind::Table, index }
    }

    /// Create a memory export.
    #[must_use]
    pub const fn memory(index: u32) -> Self {
        Self { kind: ExportKind::Memory, index }
    }

    /// Create a global export.
    #[must_use]
    pub const fn global(index: u32) -> Self {
        Self { kind: ExportKind::Global, index }
    }
}

impl fmt::Display for ExportDesc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({} {})", self.kind, self.index)
    }
}

// ---------------------------------------------------------------------------
// WasmImport
// ---------------------------------------------------------------------------

/// A single import entry parsed from the import section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmImport {
    /// The module name part of the import path (e.g. `"env"`).
    pub module: String,
    /// The field name within the module (e.g. `"malloc"`).
    pub name: String,
    /// Typed import descriptor.
    pub desc: ImportDesc,
    /// Position in the import section (0-based).
    pub index: u32,
}

impl WasmImport {
    /// Return the import kind.
    #[must_use]
    pub const fn kind(&self) -> ImportKind {
        self.desc.kind()
    }

    /// Return `true` if this is a function import.
    #[must_use]
    pub const fn is_function(&self) -> bool {
        matches!(self.desc, ImportDesc::Function(_))
    }

    /// Qualified name `module::name`.
    #[must_use]
    pub fn qualified_name(&self) -> String {
        format!("{}::{}", self.module, self.name)
    }
}

impl fmt::Display for WasmImport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(import \"{}\" \"{}\" {})", self.module, self.name, self.desc)
    }
}

// ---------------------------------------------------------------------------
// WasmExport
// ---------------------------------------------------------------------------

/// A single export entry parsed from the export section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmExport {
    /// The exported name visible to the host.
    pub name: String,
    /// Typed export descriptor.
    pub desc: ExportDesc,
    /// Position in the export section (0-based).
    pub index: u32,
}

impl WasmExport {
    /// Return the export kind.
    #[must_use]
    pub const fn kind(&self) -> ExportKind {
        self.desc.kind
    }

    /// Return `true` if this is a function export.
    #[must_use]
    pub const fn is_function(&self) -> bool {
        matches!(self.desc.kind, ExportKind::Function)
    }

    /// Return `true` if this is a memory export.
    #[must_use]
    pub const fn is_memory(&self) -> bool {
        matches!(self.desc.kind, ExportKind::Memory)
    }
}

impl fmt::Display for WasmExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(export \"{}\" {})", self.name, self.desc)
    }
}

// ---------------------------------------------------------------------------
// WasmImportSection
// ---------------------------------------------------------------------------

/// Fully decoded import section of a WebAssembly module.
#[derive(Debug, Clone, Default)]
pub struct WasmImportSection {
    /// All import entries in order.
    pub imports: Vec<WasmImport>,
}

impl WasmImportSection {
    /// Number of imports.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.imports.len()
    }

    /// Return `true` if there are no imports.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.imports.is_empty()
    }

    /// Return all function imports.
    #[must_use]
    pub fn functions(&self) -> Vec<&WasmImport> {
        self.imports.iter().filter(|i| i.is_function()).collect()
    }

    /// Number of imported functions (determines the function index offset).
    #[must_use]
    pub fn function_count(&self) -> u32 {
        self.imports.iter().filter(|i| i.is_function()).count() as u32
    }

    /// Find all imports from a given module.
    #[must_use]
    pub fn from_module(&self, module: &str) -> Vec<&WasmImport> {
        self.imports.iter().filter(|i| i.module == module).collect()
    }

    /// Return a map from qualified name → import index.
    #[must_use]
    pub fn name_map(&self) -> HashMap<String, u32> {
        self.imports
            .iter()
            .map(|i| (i.qualified_name(), i.index))
            .collect()
    }

    /// Return all unique module names.
    #[must_use]
    pub fn module_names(&self) -> Vec<&str> {
        let mut seen = std::collections::HashSet::new();
        let mut names = Vec::new();
        for i in &self.imports {
            if seen.insert(i.module.as_str()) {
                names.push(i.module.as_str());
            }
        }
        names
    }
}

// ---------------------------------------------------------------------------
// WasmExportSection
// ---------------------------------------------------------------------------

/// Fully decoded export section of a WebAssembly module.
#[derive(Debug, Clone, Default)]
pub struct WasmExportSection {
    /// All export entries in order.
    pub exports: Vec<WasmExport>,
}

impl WasmExportSection {
    /// Number of exports.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.exports.len()
    }

    /// Return `true` if there are no exports.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.exports.is_empty()
    }

    /// Return all function exports.
    #[must_use]
    pub fn functions(&self) -> Vec<&WasmExport> {
        self.exports.iter().filter(|e| e.is_function()).collect()
    }

    /// Return the export with the given name, if any.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&WasmExport> {
        self.exports.iter().find(|e| e.name == name)
    }

    /// Return a map from export name → function index (for function exports only).
    #[must_use]
    pub fn function_name_map(&self) -> HashMap<&str, u32> {
        self.exports
            .iter()
            .filter(|e| e.is_function())
            .map(|e| (e.name.as_str(), e.desc.index))
            .collect()
    }

    /// Check for duplicate export names.
    ///
    /// Returns a list of names that appear more than once.
    #[must_use]
    pub fn duplicate_names(&self) -> Vec<&str> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for e in &self.exports {
            *counts.entry(e.name.as_str()).or_insert(0) += 1;
        }
        counts
            .into_iter()
            .filter(|(_, c)| *c > 1)
            .map(|(n, _)| n)
            .collect()
    }

    /// Return all exported function indices.
    #[must_use]
    pub fn function_indices(&self) -> Vec<u32> {
        self.exports
            .iter()
            .filter(|e| e.is_function())
            .map(|e| e.desc.index)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// WasmImportExport — combined section parser
// ---------------------------------------------------------------------------

/// Combined parser for the import and export sections.
pub struct WasmImportExport;

impl WasmImportExport {
    /// Parse the import section payload.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] on malformed data.
    pub fn parse_imports(payload: &[u8]) -> Result<WasmImportSection, WasmError> {
        let mut dec = Leb128Decoder::new(payload);
        let count = dec.read_u32()?;
        let mut imports = Vec::with_capacity((count as usize).min(dec.remaining()));
        for idx in 0..count {
            let module = dec.read_name()?;
            let name = dec.read_name()?;
            let kind_byte = dec.read_u8()?;
            let desc = match kind_byte {
                0x00 => ImportDesc::Function(dec.read_u32()?),
                0x01 => {
                    use crate::wasm_type_decoder::WasmTypeDecoder;
                    ImportDesc::Table(WasmTypeDecoder::read_table_type(&mut dec)?)
                }
                0x02 => {
                    use crate::wasm_type_decoder::WasmTypeDecoder;
                    ImportDesc::Memory(WasmTypeDecoder::read_mem_type(&mut dec)?)
                }
                0x03 => {
                    use crate::wasm_type_decoder::WasmTypeDecoder;
                    ImportDesc::Global(WasmTypeDecoder::read_global_type(&mut dec)?)
                }
                other => return Err(WasmError::InvalidSection(other)),
            };
            imports.push(WasmImport {
                module,
                name,
                desc,
                index: idx,
            });
        }
        Ok(WasmImportSection { imports })
    }

    /// Parse the export section payload.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError`] on malformed data.
    pub fn parse_exports(payload: &[u8]) -> Result<WasmExportSection, WasmError> {
        let mut dec = Leb128Decoder::new(payload);
        let count = dec.read_u32()?;
        let mut exports = Vec::with_capacity((count as usize).min(dec.remaining()));
        for idx in 0..count {
            let name = dec.read_name()?;
            let kind_byte = dec.read_u8()?;
            let kind = ExportKind::from_byte(kind_byte);
            let index = dec.read_u32()?;
            exports.push(WasmExport {
                name,
                desc: ExportDesc { kind, index },
                index: idx,
            });
        }
        Ok(WasmExportSection { exports })
    }

    /// Encode an import section from a list of `(module, name, type_index)` tuples.
    #[must_use]
    pub fn encode_func_imports(items: &[(&str, &str, u32)]) -> Vec<u8> {
        let mut payload = Vec::new();
        write_leb128_u32(&mut payload, items.len() as u32);
        for (module, name, type_idx) in items {
            write_leb128_u32(&mut payload, module.len() as u32);
            payload.extend_from_slice(module.as_bytes());
            write_leb128_u32(&mut payload, name.len() as u32);
            payload.extend_from_slice(name.as_bytes());
            payload.push(0x00); // function kind
            write_leb128_u32(&mut payload, *type_idx);
        }
        // Prepend section id + length.
        let mut out = vec![0x02u8]; // section id = 2
        write_leb128_u32(&mut out, payload.len() as u32);
        out.extend_from_slice(&payload);
        out
    }

    /// Encode an export section from a list of `(name, kind, index)` tuples.
    #[must_use]
    pub fn encode_exports(items: &[(&str, ExportKind, u32)]) -> Vec<u8> {
        let mut payload = Vec::new();
        write_leb128_u32(&mut payload, items.len() as u32);
        for (name, kind, index) in items {
            write_leb128_u32(&mut payload, name.len() as u32);
            payload.extend_from_slice(name.as_bytes());
            payload.push(kind.to_byte());
            write_leb128_u32(&mut payload, *index);
        }
        let mut out = vec![0x07u8]; // section id = 7
        write_leb128_u32(&mut out, payload.len() as u32);
        out.extend_from_slice(&payload);
        out
    }
}

/// Encode a u32 as unsigned LEB128 and append to `out`.
fn write_leb128_u32(out: &mut Vec<u8>, mut v: u32) {
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_import_payload(module: &str, name: &str, type_idx: u32) -> Vec<u8> {
        let mut v = vec![0x01u8]; // count = 1
        push_name(&mut v, module);
        push_name(&mut v, name);
        v.push(0x00); // function
        v.push(type_idx as u8);
        v
    }

    fn push_name(v: &mut Vec<u8>, s: &str) {
        v.push(s.len() as u8);
        v.extend_from_slice(s.as_bytes());
    }

    fn encode_export_payload(name: &str, kind: u8, index: u32) -> Vec<u8> {
        let mut v = vec![0x01u8]; // count = 1
        push_name(&mut v, name);
        v.push(kind);
        v.push(index as u8);
        v
    }

    #[test]
    fn test_parse_func_import() {
        let payload = encode_import_payload("env", "malloc", 3);
        let sec = WasmImportExport::parse_imports(&payload).unwrap();
        assert_eq!(sec.len(), 1);
        let imp = &sec.imports[0];
        assert_eq!(imp.module, "env");
        assert_eq!(imp.name, "malloc");
        assert!(imp.is_function());
        assert_eq!(imp.desc.as_function(), Some(3));
    }

    #[test]
    fn test_parse_empty_imports() {
        let payload = vec![0x00u8];
        let sec = WasmImportExport::parse_imports(&payload).unwrap();
        assert!(sec.is_empty());
    }

    #[test]
    fn test_parse_func_export() {
        let payload = encode_export_payload("main", 0x00, 5);
        let sec = WasmImportExport::parse_exports(&payload).unwrap();
        assert_eq!(sec.len(), 1);
        let exp = &sec.exports[0];
        assert_eq!(exp.name, "main");
        assert!(exp.is_function());
        assert_eq!(exp.desc.index, 5);
    }

    #[test]
    fn test_parse_memory_export() {
        let payload = encode_export_payload("memory", 0x02, 0);
        let sec = WasmImportExport::parse_exports(&payload).unwrap();
        assert!(sec.exports[0].is_memory());
    }

    #[test]
    fn test_import_qualified_name() {
        let payload = encode_import_payload("wasi_snapshot_preview1", "fd_write", 0);
        let sec = WasmImportExport::parse_imports(&payload).unwrap();
        assert_eq!(
            sec.imports[0].qualified_name(),
            "wasi_snapshot_preview1::fd_write"
        );
    }

    #[test]
    fn test_from_module() {
        let mut v = vec![0x02u8]; // 2 imports
        let mut add = |module: &str, name: &str, type_idx: u8| {
            v.push(module.len() as u8);
            v.extend_from_slice(module.as_bytes());
            v.push(name.len() as u8);
            v.extend_from_slice(name.as_bytes());
            v.push(0x00);
            v.push(type_idx);
        };
        add("env", "foo", 0);
        add("wasi", "bar", 1);
        let sec = WasmImportExport::parse_imports(&v).unwrap();
        let env_imports = sec.from_module("env");
        assert_eq!(env_imports.len(), 1);
        assert_eq!(env_imports[0].name, "foo");
    }

    #[test]
    fn test_export_function_name_map() {
        let mut v = vec![0x02u8];
        let mut add = |name: &str, kind: u8, idx: u8| {
            v.push(name.len() as u8);
            v.extend_from_slice(name.as_bytes());
            v.push(kind);
            v.push(idx);
        };
        add("main", 0x00, 5);
        add("memory", 0x02, 0);
        let sec = WasmImportExport::parse_exports(&v).unwrap();
        let map = sec.function_name_map();
        assert_eq!(map.get("main"), Some(&5));
        assert!(!map.contains_key("memory"));
    }

    #[test]
    fn test_export_no_duplicates() {
        let payload = encode_export_payload("main", 0x00, 0);
        let sec = WasmImportExport::parse_exports(&payload).unwrap();
        assert!(sec.duplicate_names().is_empty());
    }

    #[test]
    fn test_import_kind_roundtrip() {
        for b in 0u8..=3 {
            let k = ImportKind::from_byte(b);
            assert_eq!(k.to_byte(), b);
        }
    }

    #[test]
    fn test_export_kind_roundtrip() {
        for b in 0u8..=3 {
            let k = ExportKind::from_byte(b);
            assert_eq!(k.to_byte(), b);
        }
    }

    #[test]
    fn test_import_kind_display() {
        assert_eq!(ImportKind::Function.to_string(), "func");
        assert_eq!(ImportKind::Table.to_string(), "table");
        assert_eq!(ImportKind::Unknown(9).to_string(), "unknown(0x09)");
    }

    #[test]
    fn test_export_kind_display() {
        assert_eq!(ExportKind::Memory.to_string(), "memory");
        assert_eq!(ExportKind::Unknown(9).to_string(), "unknown(0x09)");
    }

    #[test]
    fn test_encode_func_imports_roundtrip() {
        let items = vec![("env", "malloc", 0u32), ("env", "free", 1u32)];
        let section_bytes = WasmImportExport::encode_func_imports(&items);
        // Strip section header.
        let payload_start = 1 + leb_len(section_bytes.len() as u32 - 1);
        let payload = &section_bytes[payload_start..];
        let sec = WasmImportExport::parse_imports(payload).unwrap();
        assert_eq!(sec.len(), 2);
        assert_eq!(sec.imports[0].module, "env");
        assert_eq!(sec.imports[1].name, "free");
    }

    fn leb_len(mut v: u32) -> usize {
        let mut n = 1;
        v >>= 7;
        while v > 0 { n += 1; v >>= 7; }
        n
    }

    #[test]
    fn test_encode_exports_roundtrip() {
        let items = vec![("main", ExportKind::Function, 3u32)];
        let section_bytes = WasmImportExport::encode_exports(&items);
        let payload_start = 1 + leb_len(section_bytes.len() as u32 - 1);
        let payload = &section_bytes[payload_start..];
        let sec = WasmImportExport::parse_exports(payload).unwrap();
        assert_eq!(sec.len(), 1);
        assert_eq!(sec.exports[0].name, "main");
        assert_eq!(sec.exports[0].desc.index, 3);
    }

    #[test]
    fn test_module_names() {
        let mut v = vec![0x02u8];
        let mut add = |module: &str, name: &str, type_idx: u8| {
            v.push(module.len() as u8);
            v.extend_from_slice(module.as_bytes());
            v.push(name.len() as u8);
            v.extend_from_slice(name.as_bytes());
            v.push(0x00);
            v.push(type_idx);
        };
        add("env", "foo", 0);
        add("env", "bar", 1);
        let sec = WasmImportExport::parse_imports(&v).unwrap();
        let modules = sec.module_names();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0], "env");
    }

    #[test]
    fn test_export_desc_display() {
        let d = ExportDesc::function(7);
        assert_eq!(d.to_string(), "(func 7)");
    }

    #[test]
    fn test_import_display() {
        let imp = WasmImport {
            module: "env".into(),
            name: "puts".into(),
            desc: ImportDesc::Function(2),
            index: 0,
        };
        let s = imp.to_string();
        assert!(s.contains("import"));
        assert!(s.contains("env"));
        assert!(s.contains("puts"));
    }
}
