//! WASM Component Model support.
//!
//! Detects and parses the WebAssembly Component Model layer on top of a
//! standard WASM module.  Handles the `component-type` custom section,
//! `ComponentType` definitions, `CanonicalOption` lifting/lowering options,
//! and embedded `CoreModule` sections.
//!
//! Reference: <https://github.com/WebAssembly/component-model>

// ── Component Model magic / version ──────────────────────────────────────────

/// Standard WASM module magic.
pub const WASM_MAGIC: &[u8; 4] = b"\0asm";
/// WASM 1.0 version.
pub const WASM_VERSION: u32 = 0x0000_0001;
/// Component Model layer version in the second u32.
pub const COMPONENT_LAYER: u32 = 0x0000_000D;

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentError {
    /// Not enough bytes to read the requested value.
    Truncated(&'static str),
    /// Magic bytes do not match.
    BadMagic,
    /// Version field is not recognised as either core WASM or Component Model.
    UnknownVersion(u32),
    /// A LEB128 integer could not be decoded.
    BadLeb128,
    /// UTF-8 decoding failure.
    BadUtf8,
    /// Unknown section ID encountered.
    UnknownSection(u8),
}

impl std::fmt::Display for ComponentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated(s) => write!(f, "truncated: {s}"),
            Self::BadMagic => write!(f, "bad WASM magic"),
            Self::UnknownVersion(v) => write!(f, "unknown version 0x{v:08x}"),
            Self::BadLeb128 => write!(f, "bad LEB128 integer"),
            Self::BadUtf8 => write!(f, "bad UTF-8 in name"),
            Self::UnknownSection(id) => write!(f, "unknown section id {id}"),
        }
    }
}

impl std::error::Error for ComponentError {}

pub type ComponentResult<T> = Result<T, ComponentError>;

// ── LEB128 reader ─────────────────────────────────────────────────────────────

/// Decode an unsigned LEB128 integer from `data[pos..]`.
/// Returns `(value, new_pos)`.
fn read_uleb128(data: &[u8], mut pos: usize) -> ComponentResult<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if pos >= data.len() {
            return Err(ComponentError::Truncated("leb128"));
        }
        let byte = data[pos];
        pos += 1;
        result |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err(ComponentError::BadLeb128);
        }
    }
    Ok((result, pos))
}

fn read_name(data: &[u8], pos: usize) -> ComponentResult<(String, usize)> {
    let (len, pos) = read_uleb128(data, pos)?;
    let len = usize::try_from(len).map_err(|_| ComponentError::Truncated("name bytes"))?;
    let end = pos
        .checked_add(len)
        .ok_or(ComponentError::Truncated("name bytes"))?;
    if end > data.len() {
        return Err(ComponentError::Truncated("name bytes"));
    }
    let s = std::str::from_utf8(&data[pos..end])
        .map_err(|_| ComponentError::BadUtf8)?
        .to_string();
    Ok((s, end))
}

// ── Canonical options ─────────────────────────────────────────────────────────

/// Options used by `canon lift` and `canon lower` in the Component Model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalOption {
    /// Use UTF-8 strings.
    Utf8,
    /// Use UTF-16 strings.
    Utf16,
    /// Use compact UTF-16 (Latin-1 where possible).
    CompactUtf16,
    /// Memory index for linear memory access.
    Memory(u32),
    /// Realloc function index.
    Realloc(u32),
    /// Post-return function index.
    PostReturn(u32),
}

impl CanonicalOption {
    fn from_byte(b: u8, data: &[u8], pos: usize) -> ComponentResult<(Self, usize)> {
        match b {
            0x00 => Ok((Self::Utf8, pos)),
            0x01 => Ok((Self::Utf16, pos)),
            0x02 => Ok((Self::CompactUtf16, pos)),
            0x03 => {
                let (idx, pos) = read_uleb128(data, pos)?;
                Ok((Self::Memory(idx as u32), pos))
            }
            0x04 => {
                let (idx, pos) = read_uleb128(data, pos)?;
                Ok((Self::Realloc(idx as u32), pos))
            }
            0x05 => {
                let (idx, pos) = read_uleb128(data, pos)?;
                Ok((Self::PostReturn(idx as u32), pos))
            }
            _ => Err(ComponentError::UnknownSection(b)),
        }
    }
}

// ── Component types ───────────────────────────────────────────────────────────

/// A Component Model type definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentType {
    /// A component function type with parameter/result names.
    Func {
        params: Vec<(String, ValType)>,
        results: Vec<(String, ValType)>,
    },
    /// A nested component type.
    Component(Vec<ComponentImport>),
    /// A component instance type.
    Instance(Vec<(String, Self)>),
}

/// Simplified component value type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValType {
    Bool,
    S8,
    U8,
    S16,
    U16,
    S32,
    U32,
    S64,
    U64,
    Float32,
    Float64,
    Char,
    String,
    List,
    Record,
    Tuple,
    Variant,
    Enum,
    Option,
    Result,
    Flags,
    Own,
    Borrow,
}

impl ValType {
    #[must_use] 
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x7F => Some(Self::Bool),
            0x7E => Some(Self::S8),
            0x7D => Some(Self::U8),
            0x7C => Some(Self::S16),
            0x7B => Some(Self::U16),
            0x7A => Some(Self::S32),
            0x79 => Some(Self::U32),
            0x78 => Some(Self::S64),
            0x77 => Some(Self::U64),
            0x76 => Some(Self::Float32),
            0x75 => Some(Self::Float64),
            0x74 => Some(Self::Char),
            0x73 => Some(Self::String),
            0x6F => Some(Self::List),
            0x6E => Some(Self::Record),
            0x6D => Some(Self::Tuple),
            0x6C => Some(Self::Variant),
            0x6B => Some(Self::Enum),
            0x6A => Some(Self::Option),
            0x69 => Some(Self::Result),
            0x68 => Some(Self::Flags),
            0x67 => Some(Self::Own),
            0x66 => Some(Self::Borrow),
            _ => None,
        }
    }
}

// ── Component imports ─────────────────────────────────────────────────────────

/// A component import declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentImport {
    /// Interface name (e.g. `wasi:io/streams@0.2.0`).
    pub name: String,
    /// Kind of import.
    pub kind: ImportKind,
}

/// What kind of item is being imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportKind {
    Func(u32),   // type index
    Global(u32), // type index
    Memory,
    Table,
    Module(u32), // type index
    Component(u32),
    Instance(u32),
    Value(u32),
}

// ── Core module embedding ─────────────────────────────────────────────────────

/// An embedded core WebAssembly module within a component.
#[derive(Debug, Clone)]
pub struct CoreModule {
    /// Raw bytes of the embedded module (starts with `\0asm`).
    pub bytes: Vec<u8>,
    /// Optional name from a `name` custom section.
    pub name: Option<String>,
}

impl CoreModule {
    #[must_use] 
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, name: None }
    }

    #[must_use] 
    pub const fn with_name(bytes: Vec<u8>, name: String) -> Self {
        Self {
            bytes,
            name: Some(name),
        }
    }

    #[must_use] 
    pub fn is_valid_wasm(&self) -> bool {
        self.bytes.starts_with(b"\0asm")
    }
}

// ── Custom component-type section ────────────────────────────────────────────

/// A parsed `component-type` custom section.
#[derive(Debug, Clone, Default)]
pub struct ComponentSection {
    /// Raw section name (should be `"component-type"`).
    pub name: String,
    /// Raw payload bytes.
    pub payload: Vec<u8>,
    /// Parsed type definitions found in the section.
    pub types: Vec<ComponentType>,
    /// Imports declared in the section.
    pub imports: Vec<ComponentImport>,
    /// Canonical options present.
    pub canonical_options: Vec<CanonicalOption>,
}

impl ComponentSection {
    /// The well-known section name for the Component Model type section.
    pub const SECTION_NAME: &'static str = "component-type";

    #[must_use] 
    pub fn new(name: String, payload: Vec<u8>) -> Self {
        Self {
            name,
            payload,
            ..Default::default()
        }
    }

    /// Check whether this section carries Component Model metadata.
    #[must_use] 
    pub fn is_component_type(&self) -> bool {
        self.name == Self::SECTION_NAME
    }
}

// ── Top-level detector and parser ────────────────────────────────────────────

/// Result of `detect_component_model`.
#[derive(Debug, Clone)]
pub struct ComponentModelInfo {
    /// `true` when the file has the Component Model layer version.
    pub is_component: bool,
    /// WASM version field from the header.
    pub version: u32,
    /// All custom sections found.
    pub custom_sections: Vec<ComponentSection>,
    /// All embedded core modules found.
    pub core_modules: Vec<CoreModule>,
    /// Total number of sections in the binary.
    pub total_sections: usize,
}

impl ComponentModelInfo {
    #[must_use] 
    pub fn has_component_type_section(&self) -> bool {
        self.custom_sections.iter().any(ComponentSection::is_component_type)
    }

    #[must_use] 
    pub fn component_type_sections(&self) -> Vec<&ComponentSection> {
        self.custom_sections
            .iter()
            .filter(|s| s.is_component_type())
            .collect()
    }
}

/// Detect whether `data` is a WASM Component Model binary, and extract
/// high-level metadata.
pub fn detect_component_model(data: &[u8]) -> ComponentResult<ComponentModelInfo> {
    if data.len() < 8 {
        return Err(ComponentError::Truncated("wasm header"));
    }
    if &data[0..4] != WASM_MAGIC {
        return Err(ComponentError::BadMagic);
    }

    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let is_component = version == COMPONENT_LAYER;

    if version != WASM_VERSION && version != COMPONENT_LAYER {
        return Err(ComponentError::UnknownVersion(version));
    }

    let mut pos = 8;
    let mut custom_sections: Vec<ComponentSection> = Vec::new();
    let mut core_modules: Vec<CoreModule> = Vec::new();
    let mut total_sections = 0;

    while pos < data.len() {
        if pos + 1 > data.len() {
            break;
        }
        let section_id = data[pos];
        pos += 1;

        let (section_len, new_pos) = read_uleb128(data, pos)?;
        pos = new_pos;

        let section_len = usize::try_from(section_len)
            .map_err(|_| ComponentError::Truncated("section body"))?;
        let section_end = pos
            .checked_add(section_len)
            .ok_or(ComponentError::Truncated("section body"))?;
        if section_end > data.len() {
            return Err(ComponentError::Truncated("section body"));
        }

        let section_data = &data[pos..section_end];
        total_sections += 1;

        match section_id {
            0 => {
                // Custom section: name then payload
                if !section_data.is_empty() {
                    let (name, after_name) = read_name(section_data, 0)?;
                    let payload = section_data[after_name..].to_vec();
                    let mut sec = ComponentSection::new(name, payload);

                    // Attempt to parse canonical options from component-type sections.
                    if sec.is_component_type() {
                        let () = parse_canonical_options(&mut sec);
                    }
                    custom_sections.push(sec);
                }
            }
            // Core module embedding (Component Model layer, id=1 in component context)
            1 if is_component
                && section_data.starts_with(b"\0asm") => {
                    core_modules.push(CoreModule::new(section_data.to_vec()));
                }
            // All other sections: skip but count.
            _ => {}
        }

        pos = section_end;
    }

    Ok(ComponentModelInfo {
        is_component,
        version,
        custom_sections,
        core_modules,
        total_sections,
    })
}

/// Best-effort parse of `CanonicalOption` entries from a `component-type` section payload.
fn parse_canonical_options(sec: &mut ComponentSection) {
    let mut pos = 0;
    while pos < sec.payload.len() {
        let b = sec.payload[pos];
        pos += 1;
        match CanonicalOption::from_byte(b, &sec.payload, pos) {
            Ok((opt, new_pos)) => {
                pos = new_pos;
                sec.canonical_options.push(opt);
            }
            Err(_) => break,
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a minimal valid WASM module (header only).
#[must_use] 
pub fn minimal_wasm_module() -> Vec<u8> {
    let mut v = Vec::from(WASM_MAGIC as &[u8]);
    v.extend_from_slice(&WASM_VERSION.to_le_bytes());
    v
}

/// Build a minimal Component Model binary (header only).
#[must_use] 
pub fn minimal_component_binary() -> Vec<u8> {
    let mut v = Vec::from(WASM_MAGIC as &[u8]);
    v.extend_from_slice(&COMPONENT_LAYER.to_le_bytes());
    v
}

/// Append a raw custom section to a WASM/component binary.
pub fn append_custom_section(binary: &mut Vec<u8>, name: &str, payload: &[u8]) {
    // Build content: LEB128(name_len) + name_bytes + payload
    let name_bytes = name.as_bytes();
    let mut content: Vec<u8> = Vec::new();
    write_uleb128(&mut content, name_bytes.len() as u64);
    content.extend_from_slice(name_bytes);
    content.extend_from_slice(payload);

    // Section id = 0 (custom)
    binary.push(0);
    write_uleb128(binary, content.len() as u64);
    binary.extend_from_slice(&content);
}

fn write_uleb128(buf: &mut Vec<u8>, mut val: u64) {
    loop {
        let byte = (val & 0x7F) as u8;
        val >>= 7;
        if val == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bad_magic() {
        let r = detect_component_model(b"NOTASM\0\0");
        assert!(matches!(r, Err(ComponentError::BadMagic)));
    }

    #[test]
    fn test_too_short() {
        let r = detect_component_model(b"\0asm");
        assert!(matches!(r, Err(ComponentError::Truncated(_))));
    }

    #[test]
    fn test_core_wasm_not_component() {
        let bin = minimal_wasm_module();
        let info = detect_component_model(&bin).unwrap();
        assert!(!info.is_component);
        assert_eq!(info.version, WASM_VERSION);
    }

    #[test]
    fn test_component_binary_is_component() {
        let bin = minimal_component_binary();
        let info = detect_component_model(&bin).unwrap();
        assert!(info.is_component);
        assert_eq!(info.version, COMPONENT_LAYER);
    }

    #[test]
    fn test_unknown_version_error() {
        let mut bin = Vec::from(WASM_MAGIC as &[u8]);
        bin.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(matches!(
            detect_component_model(&bin),
            Err(ComponentError::UnknownVersion(_))
        ));
    }

    #[test]
    fn test_no_sections_initially() {
        let bin = minimal_wasm_module();
        let info = detect_component_model(&bin).unwrap();
        assert_eq!(info.total_sections, 0);
        assert!(info.custom_sections.is_empty());
    }

    #[test]
    fn test_custom_section_detected() {
        let mut bin = minimal_wasm_module();
        append_custom_section(&mut bin, "component-type", b"\x00\x01\x02");
        let info = detect_component_model(&bin).unwrap();
        assert_eq!(info.total_sections, 1);
        assert_eq!(info.custom_sections.len(), 1);
        assert_eq!(info.custom_sections[0].name, "component-type");
    }

    #[test]
    fn test_has_component_type_section() {
        let mut bin = minimal_wasm_module();
        append_custom_section(&mut bin, "component-type", &[]);
        let info = detect_component_model(&bin).unwrap();
        assert!(info.has_component_type_section());
    }

    #[test]
    fn test_non_component_type_custom_section() {
        let mut bin = minimal_wasm_module();
        append_custom_section(&mut bin, "name", b"\x00hello");
        let info = detect_component_model(&bin).unwrap();
        assert!(!info.has_component_type_section());
    }

    #[test]
    fn test_multiple_custom_sections() {
        let mut bin = minimal_wasm_module();
        append_custom_section(&mut bin, "component-type", &[]);
        append_custom_section(&mut bin, "build-info", b"rustc");
        let info = detect_component_model(&bin).unwrap();
        assert_eq!(info.custom_sections.len(), 2);
    }

    #[test]
    fn test_canonical_option_utf8() {
        let (opt, _) = CanonicalOption::from_byte(0x00, &[], 0).unwrap();
        assert_eq!(opt, CanonicalOption::Utf8);
    }

    #[test]
    fn test_canonical_option_memory() {
        let payload = [0x05u8]; // memory index 5
        let (opt, _) = CanonicalOption::from_byte(0x03, &payload, 0).unwrap();
        assert_eq!(opt, CanonicalOption::Memory(5));
    }

    #[test]
    fn test_canonical_option_realloc() {
        let payload = [0x02u8];
        let (opt, _) = CanonicalOption::from_byte(0x04, &payload, 0).unwrap();
        assert_eq!(opt, CanonicalOption::Realloc(2));
    }

    #[test]
    fn test_core_module_is_valid_wasm() {
        let m = CoreModule::new(minimal_wasm_module());
        assert!(m.is_valid_wasm());
    }

    #[test]
    fn test_core_module_invalid() {
        let m = CoreModule::new(b"garbage".to_vec());
        assert!(!m.is_valid_wasm());
    }

    #[test]
    fn test_val_type_roundtrip() {
        for &(b, expected) in &[
            (0x7Fu8, ValType::Bool),
            (0x7A, ValType::S32),
            (0x73, ValType::String),
        ] {
            assert_eq!(ValType::from_u8(b), Some(expected));
        }
    }

    #[test]
    fn test_component_section_is_component_type() {
        let sec = ComponentSection::new("component-type".into(), vec![]);
        assert!(sec.is_component_type());
        let other = ComponentSection::new("name".into(), vec![]);
        assert!(!other.is_component_type());
    }
}
