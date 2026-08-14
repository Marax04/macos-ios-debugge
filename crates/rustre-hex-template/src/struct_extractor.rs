//! Struct layout extractor for hex template matches.
//!
//! Given a `CompiledTemplate` match and raw bytes, interprets captured field
//! values as typed struct members, handles endianness, and produces a typed
//! `ExtractedStruct`.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ── Primitive types ───────────────────────────────────────────────────────────

/// Endianness for multi-byte fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endian {
    Little,
    Big,
}

impl Default for Endian {
    fn default() -> Self {
        Endian::Little
    }
}

/// Primitive field types recognised by the extractor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldType {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    /// Raw bytes (no numeric interpretation).
    Bytes(usize),
    /// Null-terminated ASCII string up to N bytes.
    CStr(usize),
    /// UTF-16 LE string of exactly N bytes.
    Utf16Le(usize),
}

impl FieldType {
    /// Returns the byte size of this field type.
    #[must_use]
    pub fn size(&self) -> usize {
        match self {
            FieldType::U8 | FieldType::I8 => 1,
            FieldType::U16 | FieldType::I16 => 2,
            FieldType::U32 | FieldType::I32 => 4,
            FieldType::U64 | FieldType::I64 => 8,
            FieldType::Bytes(n) | FieldType::CStr(n) | FieldType::Utf16Le(n) => *n,
        }
    }

    /// Infer a field type from byte length (defaults to Bytes for ambiguous lengths).
    #[must_use]
    pub fn from_size(size: usize) -> Self {
        match size {
            1 => FieldType::U8,
            2 => FieldType::U16,
            4 => FieldType::U32,
            8 => FieldType::U64,
            n => FieldType::Bytes(n),
        }
    }
}

// ── Field value ───────────────────────────────────────────────────────────────

/// A decoded field value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    Bytes(Vec<u8>),
    Str(String),
}

impl FieldValue {
    /// Attempt to interpret the value as a u64 (for integer types).
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            FieldValue::U8(v) => Some(*v as u64),
            FieldValue::U16(v) => Some(*v as u64),
            FieldValue::U32(v) => Some(*v as u64),
            FieldValue::U64(v) => Some(*v),
            FieldValue::I8(v) => Some(*v as i64 as u64),
            FieldValue::I16(v) => Some(*v as i64 as u64),
            FieldValue::I32(v) => Some(*v as i64 as u64),
            FieldValue::I64(v) => Some(*v as u64),
            _ => None,
        }
    }

    /// Attempt to interpret the value as an i64.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            FieldValue::I8(v) => Some(*v as i64),
            FieldValue::I16(v) => Some(*v as i64),
            FieldValue::I32(v) => Some(*v as i64),
            FieldValue::I64(v) => Some(*v),
            FieldValue::U8(v) => Some(*v as i64),
            FieldValue::U16(v) => Some(*v as i64),
            FieldValue::U32(v) => Some(*v as i64),
            FieldValue::U64(v) => Some(*v as i64),
            _ => None,
        }
    }

    /// Human-readable display string.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            FieldValue::U8(v) => format!("0x{v:02X}"),
            FieldValue::U16(v) => format!("0x{v:04X}"),
            FieldValue::U32(v) => format!("0x{v:08X}"),
            FieldValue::U64(v) => format!("0x{v:016X}"),
            FieldValue::I8(v) => format!("{v}"),
            FieldValue::I16(v) => format!("{v}"),
            FieldValue::I32(v) => format!("{v}"),
            FieldValue::I64(v) => format!("{v}"),
            FieldValue::Bytes(b) => {
                b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ")
            }
            FieldValue::Str(s) => format!("{s:?}"),
        }
    }
}

impl std::fmt::Display for FieldValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display())
    }
}

// ── Struct schema ─────────────────────────────────────────────────────────────

/// Describes one field within a struct schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDescriptor {
    /// Field name (must match the capture name in the template).
    pub name: String,
    /// Interpreted type.
    pub field_type: FieldType,
    /// Human-readable description.
    pub description: String,
}

impl FieldDescriptor {
    /// Create a new field descriptor.
    #[must_use]
    pub fn new(name: impl Into<String>, field_type: FieldType, description: impl Into<String>) -> Self {
        Self { name: name.into(), field_type, description: description.into() }
    }
}

/// A schema describing how to interpret a template match as a struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructSchema {
    /// Schema name (e.g. "DOS_HEADER", "ELF_EHDR").
    pub name: String,
    /// Ordered list of fields.
    pub fields: Vec<FieldDescriptor>,
    /// Default endianness for integer fields.
    pub endian: Endian,
}

impl StructSchema {
    /// Create a new schema.
    #[must_use]
    pub fn new(name: impl Into<String>, endian: Endian) -> Self {
        Self { name: name.into(), fields: Vec::new(), endian }
    }

    /// Add a field to the schema.
    #[must_use]
    pub fn with_field(mut self, field: FieldDescriptor) -> Self {
        self.fields.push(field);
        self
    }

    /// Look up a field descriptor by name.
    #[must_use]
    pub fn get_field(&self, name: &str) -> Option<&FieldDescriptor> {
        self.fields.iter().find(|f| f.name == name)
    }
}

// ── Built-in schemas ──────────────────────────────────────────────────────────

impl StructSchema {
    /// DOS (MZ) executable header schema.
    #[must_use]
    pub fn dos_header() -> Self {
        Self::new("DOS_HEADER", Endian::Little)
            .with_field(FieldDescriptor::new("e_magic", FieldType::U16, "Magic number MZ"))
            .with_field(FieldDescriptor::new("e_cblp", FieldType::U16, "Bytes on last page"))
            .with_field(FieldDescriptor::new("e_cp", FieldType::U16, "Pages in file"))
            .with_field(FieldDescriptor::new("e_crlc", FieldType::U16, "Relocations"))
            .with_field(FieldDescriptor::new("e_cparhdr", FieldType::U16, "Header size in paragraphs"))
            .with_field(FieldDescriptor::new("e_minalloc", FieldType::U16, "Minimum extra paragraphs"))
            .with_field(FieldDescriptor::new("e_maxalloc", FieldType::U16, "Maximum extra paragraphs"))
            .with_field(FieldDescriptor::new("e_ss", FieldType::U16, "Initial SS value"))
            .with_field(FieldDescriptor::new("e_sp", FieldType::U16, "Initial SP value"))
            .with_field(FieldDescriptor::new("e_csum", FieldType::U16, "Checksum"))
            .with_field(FieldDescriptor::new("e_ip", FieldType::U16, "Initial IP value"))
            .with_field(FieldDescriptor::new("e_cs", FieldType::U16, "Initial CS value"))
            .with_field(FieldDescriptor::new("e_lfarlc", FieldType::U16, "Relocation table offset"))
            .with_field(FieldDescriptor::new("e_ovno", FieldType::U16, "Overlay number"))
            .with_field(FieldDescriptor::new("e_lfanew", FieldType::U32, "PE header offset"))
    }

    /// PE optional header (partial) schema.
    #[must_use]
    pub fn pe_optional_header() -> Self {
        Self::new("PE_OPTIONAL_HEADER", Endian::Little)
            .with_field(FieldDescriptor::new("magic", FieldType::U16, "Optional header magic"))
            .with_field(FieldDescriptor::new("major_linker", FieldType::U8, "Major linker version"))
            .with_field(FieldDescriptor::new("minor_linker", FieldType::U8, "Minor linker version"))
            .with_field(FieldDescriptor::new("size_of_code", FieldType::U32, "Size of code section"))
            .with_field(FieldDescriptor::new("size_of_init_data", FieldType::U32, "Size of initialized data"))
            .with_field(FieldDescriptor::new("entry_point", FieldType::U32, "Address of entry point"))
            .with_field(FieldDescriptor::new("image_base", FieldType::U64, "Preferred load address"))
    }

    /// ELF32 header schema.
    #[must_use]
    pub fn elf32_header() -> Self {
        Self::new("ELF32_HEADER", Endian::Little)
            .with_field(FieldDescriptor::new("e_ident", FieldType::Bytes(16), "ELF identification"))
            .with_field(FieldDescriptor::new("e_type", FieldType::U16, "Object file type"))
            .with_field(FieldDescriptor::new("e_machine", FieldType::U16, "Architecture"))
            .with_field(FieldDescriptor::new("e_version", FieldType::U32, "Object file version"))
            .with_field(FieldDescriptor::new("e_entry", FieldType::U32, "Entry point"))
            .with_field(FieldDescriptor::new("e_phoff", FieldType::U32, "Program header offset"))
            .with_field(FieldDescriptor::new("e_shoff", FieldType::U32, "Section header offset"))
    }
}

// ── Extraction error ──────────────────────────────────────────────────────────

/// Error during struct extraction.
#[derive(Debug, Clone)]
pub enum ExtractionError {
    FieldNotFound(String),
    SizeMismatch { field: String, expected: usize, got: usize },
    InvalidUtf16,
    BufferTooShort { field: String },
}

impl std::fmt::Display for ExtractionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtractionError::FieldNotFound(n) => write!(f, "field '{n}' not found in match"),
            ExtractionError::SizeMismatch { field, expected, got } => {
                write!(f, "field '{field}': expected {expected} bytes, got {got}")
            }
            ExtractionError::InvalidUtf16 => write!(f, "invalid UTF-16 sequence"),
            ExtractionError::BufferTooShort { field } => {
                write!(f, "buffer too short for field '{field}'")
            }
        }
    }
}

// ── Extracted struct ──────────────────────────────────────────────────────────

/// A struct extracted from a pattern match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedStruct {
    /// Schema name.
    pub schema_name: String,
    /// Byte offset in the original buffer.
    pub offset: usize,
    /// Decoded fields in order.
    pub fields: Vec<(String, FieldValue)>,
    /// Quick lookup map.
    #[serde(skip)]
    pub field_map: HashMap<String, FieldValue>,
}

impl ExtractedStruct {
    /// Look up a field value by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&FieldValue> {
        self.field_map.get(name)
    }

    /// Get a field as u64.
    #[must_use]
    pub fn get_u64(&self, name: &str) -> Option<u64> {
        self.field_map.get(name)?.as_u64()
    }

    /// Render as a multi-line human-readable table.
    #[must_use]
    pub fn render_table(&self) -> String {
        let name_width = self.fields.iter().map(|(n, _)| n.len()).max().unwrap_or(8).max(8);
        let mut out = format!("=== {} @ 0x{:X} ===\n", self.schema_name, self.offset);
        for (name, val) in &self.fields {
            out.push_str(&format!("  {:<width$}  {}\n", name, val.display(), width = name_width));
        }
        out
    }
}

// ── Extractor ─────────────────────────────────────────────────────────────────

/// Extracts typed struct values from raw pattern-match captures.
#[derive(Debug, Default)]
pub struct StructExtractor;

impl StructExtractor {
    /// Create a new extractor.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Extract a struct from raw field bytes using a schema.
    ///
    /// `raw_fields` is the map returned by `CompiledTemplate::extract_fields`.
    /// `match_offset` is the byte offset in the original buffer.
    pub fn extract(
        &self,
        schema: &StructSchema,
        raw_fields: &HashMap<String, Vec<u8>>,
        match_offset: usize,
    ) -> Result<ExtractedStruct, ExtractionError> {
        let mut fields: Vec<(String, FieldValue)> = Vec::new();
        let mut field_map: HashMap<String, FieldValue> = HashMap::new();

        for descriptor in &schema.fields {
            let bytes = raw_fields
                .get(&descriptor.name)
                .ok_or_else(|| ExtractionError::FieldNotFound(descriptor.name.clone()))?;

            let expected = descriptor.field_type.size();
            if bytes.len() != expected {
                return Err(ExtractionError::SizeMismatch {
                    field: descriptor.name.clone(),
                    expected,
                    got: bytes.len(),
                });
            }

            let value = self.decode_field(bytes, &descriptor.field_type, schema.endian)?;
            field_map.insert(descriptor.name.clone(), value.clone());
            fields.push((descriptor.name.clone(), value));
        }

        Ok(ExtractedStruct {
            schema_name: schema.name.clone(),
            offset: match_offset,
            fields,
            field_map,
        })
    }

    fn decode_field(
        &self,
        bytes: &[u8],
        field_type: &FieldType,
        endian: Endian,
    ) -> Result<FieldValue, ExtractionError> {
        match field_type {
            FieldType::U8 => Ok(FieldValue::U8(bytes[0])),
            FieldType::I8 => Ok(FieldValue::I8(bytes[0] as i8)),
            FieldType::U16 => {
                let v = if endian == Endian::Little {
                    u16::from_le_bytes([bytes[0], bytes[1]])
                } else {
                    u16::from_be_bytes([bytes[0], bytes[1]])
                };
                Ok(FieldValue::U16(v))
            }
            FieldType::I16 => {
                let v = if endian == Endian::Little {
                    i16::from_le_bytes([bytes[0], bytes[1]])
                } else {
                    i16::from_be_bytes([bytes[0], bytes[1]])
                };
                Ok(FieldValue::I16(v))
            }
            FieldType::U32 => {
                let arr: [u8; 4] = bytes[..4].try_into().unwrap();
                let v = if endian == Endian::Little {
                    u32::from_le_bytes(arr)
                } else {
                    u32::from_be_bytes(arr)
                };
                Ok(FieldValue::U32(v))
            }
            FieldType::I32 => {
                let arr: [u8; 4] = bytes[..4].try_into().unwrap();
                let v = if endian == Endian::Little {
                    i32::from_le_bytes(arr)
                } else {
                    i32::from_be_bytes(arr)
                };
                Ok(FieldValue::I32(v))
            }
            FieldType::U64 => {
                let arr: [u8; 8] = bytes[..8].try_into().unwrap();
                let v = if endian == Endian::Little {
                    u64::from_le_bytes(arr)
                } else {
                    u64::from_be_bytes(arr)
                };
                Ok(FieldValue::U64(v))
            }
            FieldType::I64 => {
                let arr: [u8; 8] = bytes[..8].try_into().unwrap();
                let v = if endian == Endian::Little {
                    i64::from_le_bytes(arr)
                } else {
                    i64::from_be_bytes(arr)
                };
                Ok(FieldValue::I64(v))
            }
            FieldType::Bytes(_) => Ok(FieldValue::Bytes(bytes.to_vec())),
            FieldType::CStr(_) => {
                let s: Vec<u8> = bytes.iter().copied().take_while(|&b| b != 0).collect();
                Ok(FieldValue::Str(String::from_utf8_lossy(&s).into_owned()))
            }
            FieldType::Utf16Le(n) => {
                if bytes.len() < *n || n % 2 != 0 {
                    return Err(ExtractionError::InvalidUtf16);
                }
                let units: Vec<u16> = bytes[..*n]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let s = String::from_utf16(&units).map_err(|_| ExtractionError::InvalidUtf16)?;
                Ok(FieldValue::Str(s))
            }
        }
    }

    /// Extract a struct at a specific offset in a raw buffer, without a template.
    ///
    /// Reads fields sequentially from `buf[offset..]` according to the schema.
    pub fn extract_sequential(
        &self,
        schema: &StructSchema,
        buf: &[u8],
        offset: usize,
    ) -> Result<ExtractedStruct, ExtractionError> {
        let mut fields: Vec<(String, FieldValue)> = Vec::new();
        let mut field_map: HashMap<String, FieldValue> = HashMap::new();
        let mut pos = offset;

        for descriptor in &schema.fields {
            let size = descriptor.field_type.size();
            if pos + size > buf.len() {
                return Err(ExtractionError::BufferTooShort {
                    field: descriptor.name.clone(),
                });
            }
            let bytes = &buf[pos..pos + size];
            let value = self.decode_field(bytes, &descriptor.field_type, schema.endian)?;
            field_map.insert(descriptor.name.clone(), value.clone());
            fields.push((descriptor.name.clone(), value));
            pos += size;
        }

        Ok(ExtractedStruct {
            schema_name: schema.name.clone(),
            offset,
            fields,
            field_map,
        })
    }
}

// ── Convenience: extract from raw buffer ─────────────────────────────────────

/// Extract multiple struct instances by scanning `buf` for the pattern defined by
/// `raw_fields_list` (already found via template search) and applying `schema`.
pub fn extract_all_matches(
    schema: &StructSchema,
    raw_fields_list: &[(usize, HashMap<String, Vec<u8>>)],
) -> Vec<Result<ExtractedStruct, ExtractionError>> {
    let extractor = StructExtractor::new();
    raw_fields_list
        .iter()
        .map(|(offset, fields)| extractor.extract(schema, fields, *offset))
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn _mz_raw_fields() -> HashMap<String, Vec<u8>> {
        let mut m = HashMap::new();
        m.insert("e_magic".to_string(), vec![0x4D, 0x5A]);
        m.insert("e_lfanew".to_string(), vec![0x80, 0x00, 0x00, 0x00]);
        m
    }

    #[test]
    fn test_extract_u16() {
        let extractor = StructExtractor::new();
        let schema = StructSchema::new("test", Endian::Little)
            .with_field(FieldDescriptor::new("magic", FieldType::U16, ""));
        let mut raw = HashMap::new();
        raw.insert("magic".to_string(), vec![0x4D, 0x5A]);
        let s = extractor.extract(&schema, &raw, 0).unwrap();
        assert_eq!(s.get_u64("magic"), Some(0x5A4D));
    }

    #[test]
    fn test_extract_u32_le() {
        let extractor = StructExtractor::new();
        let schema = StructSchema::new("test", Endian::Little)
            .with_field(FieldDescriptor::new("val", FieldType::U32, ""));
        let mut raw = HashMap::new();
        raw.insert("val".to_string(), vec![0x01, 0x00, 0x00, 0x00]);
        let s = extractor.extract(&schema, &raw, 0).unwrap();
        assert_eq!(s.get_u64("val"), Some(1));
    }

    #[test]
    fn test_extract_u32_be() {
        let extractor = StructExtractor::new();
        let schema = StructSchema::new("test", Endian::Big)
            .with_field(FieldDescriptor::new("val", FieldType::U32, ""));
        let mut raw = HashMap::new();
        raw.insert("val".to_string(), vec![0x00, 0x00, 0x00, 0x01]);
        let s = extractor.extract(&schema, &raw, 0).unwrap();
        assert_eq!(s.get_u64("val"), Some(1));
    }

    #[test]
    fn test_extract_cstr() {
        let extractor = StructExtractor::new();
        let schema = StructSchema::new("test", Endian::Little)
            .with_field(FieldDescriptor::new("name", FieldType::CStr(8), ""));
        let mut raw = HashMap::new();
        raw.insert("name".to_string(), b"Hello\x00\x00\x00".to_vec());
        let s = extractor.extract(&schema, &raw, 0).unwrap();
        if let Some(FieldValue::Str(st)) = s.get("name") {
            assert_eq!(st, "Hello");
        } else {
            panic!("expected Str");
        }
    }

    #[test]
    fn test_size_mismatch_error() {
        let extractor = StructExtractor::new();
        let schema = StructSchema::new("test", Endian::Little)
            .with_field(FieldDescriptor::new("val", FieldType::U32, ""));
        let mut raw = HashMap::new();
        raw.insert("val".to_string(), vec![0x01, 0x02]); // too short
        let result = extractor.extract(&schema, &raw, 0);
        assert!(matches!(result, Err(ExtractionError::SizeMismatch { .. })));
    }

    #[test]
    fn test_field_not_found_error() {
        let extractor = StructExtractor::new();
        let schema = StructSchema::new("test", Endian::Little)
            .with_field(FieldDescriptor::new("missing", FieldType::U8, ""));
        let raw = HashMap::new();
        let result = extractor.extract(&schema, &raw, 0);
        assert!(matches!(result, Err(ExtractionError::FieldNotFound(_))));
    }

    #[test]
    fn test_sequential_extract() {
        let extractor = StructExtractor::new();
        let schema = StructSchema::new("two_bytes", Endian::Little)
            .with_field(FieldDescriptor::new("a", FieldType::U8, ""))
            .with_field(FieldDescriptor::new("b", FieldType::U8, ""));
        let buf = vec![0xAA, 0xBB];
        let s = extractor.extract_sequential(&schema, &buf, 0).unwrap();
        assert_eq!(s.get_u64("a"), Some(0xAA));
        assert_eq!(s.get_u64("b"), Some(0xBB));
    }

    #[test]
    fn test_sequential_buffer_too_short() {
        let extractor = StructExtractor::new();
        let schema = StructSchema::new("test", Endian::Little)
            .with_field(FieldDescriptor::new("val", FieldType::U32, ""));
        let buf = vec![0x01, 0x02];
        let result = extractor.extract_sequential(&schema, &buf, 0);
        assert!(matches!(result, Err(ExtractionError::BufferTooShort { .. })));
    }

    #[test]
    fn test_render_table_contains_schema_name() {
        let extractor = StructExtractor::new();
        let schema = StructSchema::new("MY_HDR", Endian::Little)
            .with_field(FieldDescriptor::new("v", FieldType::U8, ""));
        let mut raw = HashMap::new();
        raw.insert("v".to_string(), vec![0x42]);
        let s = extractor.extract(&schema, &raw, 0x1000).unwrap();
        let table = s.render_table();
        assert!(table.contains("MY_HDR"));
        assert!(table.contains("0x1000"));
    }

    #[test]
    fn test_dos_header_schema_fields() {
        let schema = StructSchema::dos_header();
        assert!(schema.get_field("e_magic").is_some());
        assert!(schema.get_field("e_lfanew").is_some());
        assert_eq!(schema.get_field("e_lfanew").unwrap().field_type.size(), 4);
    }

    #[test]
    fn test_field_type_from_size() {
        assert_eq!(FieldType::from_size(1), FieldType::U8);
        assert_eq!(FieldType::from_size(4), FieldType::U32);
        assert_eq!(FieldType::from_size(3), FieldType::Bytes(3));
    }

    #[test]
    fn test_field_value_display() {
        let v = FieldValue::U32(0xDEADBEEF);
        assert_eq!(v.display(), "0xDEADBEEF");
        let v2 = FieldValue::Bytes(vec![0x01, 0x02]);
        assert_eq!(v2.display(), "01 02");
    }

    #[test]
    fn test_utf16le_field() {
        let extractor = StructExtractor::new();
        let schema = StructSchema::new("test", Endian::Little)
            .with_field(FieldDescriptor::new("name", FieldType::Utf16Le(6), ""));
        let mut raw = HashMap::new();
        // "Hi" in UTF-16 LE = 48 00 69 00, then null terminator 00 00
        raw.insert("name".to_string(), vec![0x48, 0x00, 0x69, 0x00, 0x00, 0x00]);
        let s = extractor.extract(&schema, &raw, 0).unwrap();
        if let Some(FieldValue::Str(st)) = s.get("name") {
            assert!(st.starts_with("Hi"), "got: {st}");
        } else {
            panic!("expected Str");
        }
    }
}
